// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! A library for working with [Google Breakpad][breakpad]'s
//! text-format [symbol files][symbolfiles].
//!
//! See the [walker][] module for documentation on CFI evaluation.
//!
//! The highest-level API provided by this crate is to use the
//! [`Symbolizer`][symbolizer] struct.
//!
//! [breakpad]: https://chromium.googlesource.com/breakpad/breakpad/+/master/
//! [symbolfiles]: https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md
//! [symbolizer]: struct.Symbolizer.html
//!
//! # Examples
//!
//! ```
//! # std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
//! use breakpad_symbols::{SimpleSymbolSupplier, Symbolizer, SimpleFrame, SimpleModule};
//! use debugid::DebugId;
//! use std::path::PathBuf;
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let paths = vec!(PathBuf::from("../testdata/symbols/"));
//!     let supplier = SimpleSymbolSupplier::new(paths);
//!     let symbolizer = Symbolizer::new(supplier);
//!
//!     // Simple function name lookup with debug file, debug id, address.
//!     let debug_id = DebugId::from_str("5A9832E5287241C1838ED98914E9B7FF1").unwrap();
//!     assert_eq!(symbolizer.get_symbol_at_address("test_app.pdb", debug_id, 0x1010)
//!         .await
//!         .unwrap(),
//!         "vswprintf");
//! }
//! ```

use async_trait::async_trait;
use debugid::{CodeId, DebugId};
use log::{debug, trace, warn};
use reqwest::{Client, Url};
use tempfile::NamedTempFile;

use std::borrow::Cow;
use std::boxed::Box;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub use minidump_common::traits::Module;
pub use sym_file::walker;

pub use crate::sym_file::{CfiRules, SymbolFile};

mod sym_file;

// Re-exports for the purposes of the cfi_eval fuzzer. Not public API.
#[doc(hidden)]
#[cfg(feature = "fuzz")]
pub mod fuzzing_private_exports {
    pub use crate::sym_file::walker::{eval_win_expr_for_fuzzer, walk_with_stack_cfi};
    pub use crate::sym_file::{StackInfoWin, WinStackThing};
}

/// Statistics on the symbols of a module.
#[derive(Default, Debug)]
pub struct SymbolStats {
    /// If the module's symbols were downloaded, this is the url used.
    pub symbol_url: Option<String>,
    /// If the symbols were found and loaded into memory.
    pub loaded_symbols: bool,
    /// If we tried to parse the symbols, but failed.
    pub corrupt_symbols: bool,
}

/// A `Module` implementation that holds arbitrary data.
///
/// This can be useful for getting symbols for a module when you
/// have a debug id and filename but not an actual minidump. If you have a
/// minidump, you should be using [`MinidumpModule`][minidumpmodule].
///
/// [minidumpmodule]: ../minidump/struct.MinidumpModule.html
#[derive(Default)]
pub struct SimpleModule {
    pub base_address: Option<u64>,
    pub size: Option<u64>,
    pub code_file: Option<String>,
    pub code_identifier: Option<CodeId>,
    pub debug_file: Option<String>,
    pub debug_id: Option<DebugId>,
    pub version: Option<String>,
}

impl SimpleModule {
    /// Create a `SimpleModule` with the given `debug_file` and `debug_id`.
    ///
    /// Uses `default` for the remaining fields.
    pub fn new(debug_file: &str, debug_id: DebugId) -> SimpleModule {
        SimpleModule {
            debug_file: Some(String::from(debug_file)),
            debug_id: Some(debug_id),
            ..SimpleModule::default()
        }
    }
}

impl Module for SimpleModule {
    fn base_address(&self) -> u64 {
        self.base_address.unwrap_or(0)
    }
    fn size(&self) -> u64 {
        self.size.unwrap_or(0)
    }
    fn code_file(&self) -> Cow<str> {
        self.code_file
            .as_ref()
            .map_or(Cow::from(""), |s| Cow::Borrowed(&s[..]))
    }
    fn code_identifier(&self) -> CodeId {
        self.code_identifier
            .as_ref()
            .cloned()
            .unwrap_or_else(CodeId::nil)
    }
    fn debug_file(&self) -> Option<Cow<str>> {
        self.debug_file.as_ref().map(|s| Cow::Borrowed(&s[..]))
    }
    fn debug_identifier(&self) -> Option<DebugId> {
        self.debug_id
    }
    fn version(&self) -> Option<Cow<str>> {
        self.version.as_ref().map(|s| Cow::Borrowed(&s[..]))
    }
}

/// Like `PathBuf::file_name`, but try to work on Windows or POSIX-style paths.
fn leafname(path: &str) -> &str {
    path.rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(path)
}

/// If `filename` ends with `match_extension`, remove it. Append `new_extension` to the result.
fn replace_or_add_extension(filename: &str, match_extension: &str, new_extension: &str) -> String {
    let mut bits = filename.split('.').collect::<Vec<_>>();
    if bits.len() > 1
        && bits
            .last()
            .map_or(false, |e| e.to_lowercase() == match_extension)
    {
        bits.pop();
    }
    bits.push(new_extension);
    bits.join(".")
}

/// Get a relative symbol path at which to locate symbols for `module`.
///
/// Symbols are generally stored in the layout used by Microsoft's symbol
/// server and associated tools:
/// `<debug filename>/<debug identifier>/<debug filename>.sym`. If
/// `debug filename` ends with *.pdb* the leaf filename will have that
/// removed.
/// `extension` is the expected extension for the symbol filename, generally
/// *sym* if Breakpad text format symbols are expected.
///
/// The debug filename and debug identifier can be found in the
/// [first line][module_line] of the symbol file output by the dump_syms tool.
/// You can use [this script][packagesymbols] to run dump_syms and put the
/// resulting symbol files in the proper directory structure.
///
/// [module_line]: https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md#MODULE-records
/// [packagesymbols]: https://gist.github.com/luser/2ad32d290f224782fcfc#file-packagesymbols-py
pub fn relative_symbol_path(module: &(dyn Module + Sync), extension: &str) -> Option<String> {
    module.debug_file().and_then(|debug_file| {
        module.debug_identifier().map(|debug_id| {
            // Can't use PathBuf::file_name here, it doesn't handle
            // Windows file paths on non-Windows.
            let leaf = leafname(&debug_file);
            let filename = replace_or_add_extension(leaf, "pdb", extension);
            [leaf, &debug_id.breakpad().to_string(), &filename[..]].join("/")
        })
    })
}

/// Possible results of locating symbols for a module.
///
/// Because symbols may be found from different sources, symbol providers
/// are usually configured to "cascade" into the next one whenever they report
/// `NotFound`.
///
/// Cascading currently assumes that if any provider finds symbols for
/// a module, all other providers will find the same symbols (if any).
/// Therefore cascading will not be applied if a LoadError or ParseError
/// occurs (because presumably, all the other sources will also fail to
/// load/parse.)
///
/// In theory we could do some interesting things where we attempt to
/// be more robust and actually merge together the symbols from multiple
/// sources, but that would make it difficult to cache symbol files, and
/// would rarely actually improve results.
///
/// Since symbol files can be on the order of a gigabyte(!) and downloaded
/// from the network, aggressive caching is pretty important. The current
/// approach is a nice balance of simple and effective.
#[derive(Debug, thiserror::Error)]
pub enum SymbolError {
    /// Symbol file could not be found.
    ///
    /// In this case other symbol providers may still be able to find it!
    #[error("symbol file not found")]
    NotFound,
    /// Symbol file could not be loaded into memory.
    #[error("couldn't read input stream")]
    LoadError(#[from] std::io::Error),
    /// Symbol file was too corrupt to be parsed at all.
    ///
    /// Because symbol files are pretty modular, many corruptions/ambiguities
    /// can be either repaired or discarded at a fairly granular level
    /// (e.g. a bad STACK WIN line can be discarded without affecting anything
    /// else). But sometimes we can't make any sense of the symbol file, and
    /// you find yourself here.
    #[error("parse error: {0} at line {1}")]
    ParseError(&'static str, u64),
}

/// An error produced by fill_symbol.
#[derive(Debug)]
pub struct FillSymbolError {
    // We don't want to yield a full SymbolError for fill_symbol
// as this would involve cloning bulky Error strings every time
// someone requested symbols for a missing module.
//
// As it turns out there's currently no reason to care about *why*
// fill_symbol, so for now this is just a dummy type until we have
// something to put here.
//
// The only reason fill_symbol *can* produce an Err is so that
// the caller can distinguish between "we had symbols, but this address
// didn't map to a function name" and "we had no symbols for that module"
// (this is used as a heuristic for stack scanning).
}

impl PartialEq for SymbolError {
    fn eq(&self, other: &SymbolError) -> bool {
        matches!(
            (self, other),
            (SymbolError::NotFound, SymbolError::NotFound)
                | (SymbolError::LoadError(_), SymbolError::LoadError(_))
                | (SymbolError::ParseError(..), SymbolError::ParseError(..))
        )
    }
}

/// A trait for things that can locate symbols for a given module.
#[async_trait]
pub trait SymbolSupplier {
    /// Locate and load a symbol file for `module`.
    ///
    /// Implementations may use any strategy for locating and loading
    /// symbols.
    async fn locate_symbols(&self, module: &(dyn Module + Sync))
        -> Result<SymbolFile, SymbolError>;
}

/// An implementation of `SymbolSupplier` that loads Breakpad text-format symbols from local disk
/// paths.
///
/// See [`relative_symbol_path`] for details on how paths are searched.
///
/// [`relative_symbol_path`]: fn.relative_symbol_path.html
pub struct SimpleSymbolSupplier {
    /// Local disk paths in which to search for symbols.
    paths: Vec<PathBuf>,
}

impl SimpleSymbolSupplier {
    /// Instantiate a new `SimpleSymbolSupplier` that will search in `paths`.
    pub fn new(paths: Vec<PathBuf>) -> SimpleSymbolSupplier {
        SimpleSymbolSupplier { paths }
    }
}

#[async_trait]
impl SymbolSupplier for SimpleSymbolSupplier {
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<SymbolFile, SymbolError> {
        if let Some(rel_path) = relative_symbol_path(module, "sym") {
            for path in self.paths.iter() {
                let test_path = path.join(&rel_path);
                if fs::metadata(&test_path).ok().map_or(false, |m| m.is_file()) {
                    return SymbolFile::from_file(&test_path);
                }
            }
        }
        Err(SymbolError::NotFound)
    }
}

/// A SymbolSupplier that maps module names (code_files) to an in-memory string.
///
/// Intended for mocking symbol files in tests.
#[derive(Default, Debug, Clone)]
pub struct StringSymbolSupplier {
    modules: HashMap<String, String>,
}

impl StringSymbolSupplier {
    /// Make a new StringSymbolSupplier with no modules.
    pub fn new(modules: HashMap<String, String>) -> Self {
        Self { modules }
    }
}

#[async_trait]
impl SymbolSupplier for StringSymbolSupplier {
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<SymbolFile, SymbolError> {
        if let Some(symbols) = self.modules.get(&*module.code_file()) {
            return SymbolFile::from_bytes(symbols.as_bytes());
        }
        Err(SymbolError::NotFound)
    }
}

/// An implementation of `SymbolSupplier` that loads Breakpad text-format symbols from HTTP
/// URLs.
///
/// See [`relative_symbol_path`] for details on how paths are searched.
///
/// [`relative_symbol_path`]: fn.relative_symbol_path.html
pub struct HttpSymbolSupplier {
    /// HTTP Client to use for fetching symbols.
    client: Client,
    /// URLs to search for symbols.
    urls: Vec<Url>,
    /// A `SimpleSymbolSupplier` to use for local symbol paths.
    local: SimpleSymbolSupplier,
    /// A path at which to cache downloaded symbols.
    ///
    /// We recommend using a subdirectory of `std::env::temp_dir()`, as this
    /// will be your OS's intended location for tempory files. This should
    /// give you free garbage collection of the cache while still allowing it
    /// to function between runs.
    cache: PathBuf,
    /// A path to a temporary location where downloaded symbols can be written
    /// before being atomically swapped into the cache.
    ///
    /// We recommend using `std::env::temp_dir()`, as this will be your OS's
    /// intended location for temporary files.
    tmp: PathBuf,
}

impl HttpSymbolSupplier {
    /// Create a new `HttpSymbolSupplier`.
    ///
    /// Symbols will be searched for in each of `local_paths` and `cache` first, then via HTTP
    /// at each of `urls`. If a symbol file is found via HTTP it will be saved under `cache`.
    pub fn new(
        urls: Vec<String>,
        cache: PathBuf,
        tmp: PathBuf,
        mut local_paths: Vec<PathBuf>,
        timeout: Duration,
    ) -> HttpSymbolSupplier {
        let client = Client::builder().timeout(timeout).build().unwrap();
        let urls = urls
            .into_iter()
            .filter_map(|mut u| {
                if !u.ends_with('/') {
                    u.push('/');
                }
                Url::parse(&u).ok()
            })
            .collect();
        local_paths.push(cache.clone());
        let local = SimpleSymbolSupplier::new(local_paths);
        HttpSymbolSupplier {
            client,
            urls,
            local,
            cache,
            tmp,
        }
    }
}

fn create_cache_file(tmp_path: &Path, final_path: &Path) -> io::Result<NamedTempFile> {
    // Use tempfile to save things to our cache to ensure proper
    // atomicity of writes. We may want multiple instances of rust-minidump
    // to be sharing a cache, and we don't want one instance to see another
    // instance's partially written results.
    //
    // tempfile is designed explicitly for this purpose, and will handle all
    // the platform-specific details and do its best to cleanup if things
    // crash.

    // First ensure that the target directory in the cache exists
    let base = final_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Bad cache path: {:?}", final_path),
        )
    })?;
    fs::create_dir_all(&base)?;

    NamedTempFile::new_in(tmp_path)
}

fn commit_cache_file(mut temp: NamedTempFile, final_path: &Path, url: &Url) -> io::Result<()> {
    // Append any extra metadata we also want to be cached as "INFO" lines,
    // because this is an established format that parsers will ignore the
    // contents of by default.

    // INFO URL allows us to properly report the url we retrieved a symbol file
    // from, even when the file is loaded from our on-disk cache.
    let cache_metadata = format!("INFO URL {}\n", url);
    temp.write_all(cache_metadata.as_bytes())?;

    // If another process already wrote this entry, prefer their value to
    // avoid needless file system churn.
    temp.persist_noclobber(final_path)?;

    Ok(())
}

/// Fetch a symbol file from the URL made by combining `base_url` and `rel_path` using `client`,
/// save the file contents under `cache` + `rel_path` and also return them.
async fn fetch_symbol_file(
    client: &Client,
    base_url: &Url,
    rel_path: &str,
    cache: &Path,
    tmp: &Path,
) -> Result<SymbolFile, SymbolError> {
    // This function is a bit of a complicated mess because we want to write
    // the input to our symbol cache, but we're a streaming parser. So we
    // use the bare SymbolFile::parse to get access to the contents of
    // the input stream as it's downloaded+parsed to write it to disk.
    //
    // Note that caching is strictly "optional" because it's more important
    // to parse the symbols. So if at any point the caching i/o fails, we just
    // give up on caching but let the parse+download continue.

    // First try to GET the file from a server
    let url = base_url.join(rel_path).map_err(|_| SymbolError::NotFound)?;
    debug!("Trying {}", url);
    let res = client
        .get(url.clone())
        .send()
        .await
        .and_then(|res| res.error_for_status())
        .map_err(|_| SymbolError::NotFound)?;

    // Now try to create the temp cache file (not yet in the cache)
    let final_cache_path = cache.join(rel_path);
    let mut temp = create_cache_file(tmp, &final_cache_path)
        .map_err(|e| {
            warn!("Failed to save symbol file in local disk cache: {}", e);
        })
        .ok();

    // Now stream parse the file as it downloads.
    let mut symbol_file = SymbolFile::parse_async(res, |data| {
        // While we're downloading+parsing, save this data to the the disk cache too
        if let Some(file) = temp.as_mut() {
            if let Err(e) = file.write_all(data) {
                // Give up on caching this.
                warn!("Failed to save symbol file in local disk cache: {}", e);
                temp = None;
            }
        }
    })
    .await?;
    // Make note of what URL this symbol file was downloaded from.
    symbol_file.url = Some(url.to_string());

    // Try to finish the cache file and atomically swap it into the cache.
    if let Some(temp) = temp {
        let _ = commit_cache_file(temp, &final_cache_path, &url).map_err(|e| {
            warn!("Failed to save symbol file in local disk cache: {}", e);
        });
    }

    Ok(symbol_file)
}

#[async_trait]
impl SymbolSupplier for HttpSymbolSupplier {
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<SymbolFile, SymbolError> {
        // Check local paths first.
        let local_result = self.local.locate_symbols(module).await;
        if !matches!(local_result, Err(SymbolError::NotFound)) {
            // Everything but NotFound prevents cascading
            return local_result;
        }
        // Now try urls
        if let Some(rel_path) = relative_symbol_path(module, "sym") {
            for url in &self.urls {
                if let Ok(file) =
                    fetch_symbol_file(&self.client, url, &rel_path, &self.cache, &self.tmp).await
                {
                    return Ok(file);
                }
            }
        }
        // If we get this far, we have failed to find anything
        Err(SymbolError::NotFound)
    }
}

/// A trait for setting symbol information on something like a stack frame.
pub trait FrameSymbolizer {
    /// Get the program counter value for this frame.
    fn get_instruction(&self) -> u64;
    /// Set the name, base address, and paramter size of the function in
    // which this frame is executing.
    fn set_function(&mut self, name: &str, base: u64, parameter_size: u32);
    /// Set the source file and (1-based) line number this frame represents.
    fn set_source_file(&mut self, file: &str, line: u32, base: u64);
}

pub trait FrameWalker {
    /// Get the instruction address that we're trying to unwind from.
    fn get_instruction(&self) -> u64;
    /// Get the number of bytes the callee's callee's parameters take up
    /// on the stack (or 0 if unknown/invalid). This is needed for
    /// STACK WIN unwinding.
    fn get_grand_callee_parameter_size(&self) -> u32;
    /// Get a register-sized value stored at this address.
    fn get_register_at_address(&self, address: u64) -> Option<u64>;
    /// Get the value of a register from the callee's frame.
    fn get_callee_register(&self, name: &str) -> Option<u64>;
    /// Set the value of a register for the caller's frame.
    fn set_caller_register(&mut self, name: &str, val: u64) -> Option<()>;
    /// Explicitly mark one of the caller's registers as invalid.
    fn clear_caller_register(&mut self, name: &str);
    /// Set whatever registers in the caller should be set based on the cfa (e.g. rsp).
    fn set_cfa(&mut self, val: u64) -> Option<()>;
    /// Set whatever registers in the caller should be set based on the return address (e.g. rip).
    fn set_ra(&mut self, val: u64) -> Option<()>;
}

/// A simple implementation of `FrameSymbolizer` that just holds data.
#[derive(Debug, Default)]
pub struct SimpleFrame {
    /// The program counter value for this frame.
    pub instruction: u64,
    /// The name of the function in which the current instruction is executing.
    pub function: Option<String>,
    /// The offset of the start of `function` from the module base.
    pub function_base: Option<u64>,
    /// The size, in bytes, that this function's parameters take up on the stack.
    pub parameter_size: Option<u32>,
    /// The name of the source file in which the current instruction is executing.
    pub source_file: Option<String>,
    /// The 1-based index of the line number in `source_file` in which the current instruction is
    /// executing.
    pub source_line: Option<u32>,
    /// The offset of the start of `source_line` from the function base.
    pub source_line_base: Option<u64>,
}

impl SimpleFrame {
    /// Instantiate a `SimpleFrame` with instruction pointer `instruction`.
    pub fn with_instruction(instruction: u64) -> SimpleFrame {
        SimpleFrame {
            instruction,
            ..SimpleFrame::default()
        }
    }
}

impl FrameSymbolizer for SimpleFrame {
    fn get_instruction(&self) -> u64 {
        self.instruction
    }
    fn set_function(&mut self, name: &str, base: u64, parameter_size: u32) {
        self.function = Some(String::from(name));
        self.function_base = Some(base);
        self.parameter_size = Some(parameter_size);
    }
    fn set_source_file(&mut self, file: &str, line: u32, base: u64) {
        self.source_file = Some(String::from(file));
        self.source_line = Some(line);
        self.source_line_base = Some(base);
    }
}

// Can't make Module derive Hash, since then it can't be used as a trait
// object (because the hash method is generic), so this is a hacky workaround.
type ModuleKey = (String, String, Option<String>, Option<String>);

/// Helper for deriving a hash key from a `Module` for `Symbolizer`.
fn key(module: &(dyn Module + Sync)) -> ModuleKey {
    (
        module.code_file().to_string(),
        module.code_identifier().to_string(),
        module.debug_file().map(|s| s.to_string()),
        module.debug_identifier().map(|s| s.to_string()),
    )
}

/// Symbolicate stack frames.
///
/// A `Symbolizer` manages loading symbols and looking up symbols in them
/// including caching so that symbols for a given module are only loaded once.
///
/// Call [`Symbolizer::new`][new] to instantiate a `Symbolizer`. A Symbolizer
/// requires a [`SymbolSupplier`][supplier] to locate symbols. If you have
/// symbols on disk in the [customary directory layout][dirlayout], a
/// [`SimpleSymbolSupplier`][simple] will work.
///
/// Use [`get_symbol_at_address`][get_symbol] or [`fill_symbol`][fill_symbol] to
/// do symbol lookup.
///
/// [new]: struct.Symbolizer.html#method.new
/// [supplier]: trait.SymbolSupplier.html
/// [dirlayout]: fn.relative_symbol_path.html
/// [simple]: struct.SimpleSymbolSupplier.html
/// [get_symbol]: struct.Symbolizer.html#method.get_symbol_at_address
/// [fill_symbol]: struct.Symbolizer.html#method.fill_symbol
pub struct Symbolizer {
    /// Symbol supplier for locating symbols.
    supplier: Box<dyn SymbolSupplier + Send + Sync + 'static>,
    /// Cache of symbol locating results.
    // TODO?: use lru-cache: https://crates.io/crates/lru-cache/
    // note that using an lru-cache would mess up the fact that we currently
    // use this for statistics collection. Splitting out statistics would be
    // way messier but not impossible.
    symbols: Mutex<HashMap<ModuleKey, Result<SymbolFile, SymbolError>>>,
}

impl Symbolizer {
    /// Create a `Symbolizer` that uses `supplier` to locate symbols.
    pub fn new<T: SymbolSupplier + Send + Sync + 'static>(supplier: T) -> Symbolizer {
        Symbolizer {
            supplier: Box::new(supplier),
            symbols: Mutex::new(HashMap::new()),
        }
    }

    /// Helper method for non-minidump-using callers.
    ///
    /// Pass `debug_file` and `debug_id` describing a specific module,
    /// and `address`, a module-relative address, and get back
    /// a symbol in that module that covers that address, or `None`.
    ///
    /// See [the module-level documentation][module] for an example.
    ///
    /// [module]: index.html
    pub async fn get_symbol_at_address(
        &self,
        debug_file: &str,
        debug_id: DebugId,
        address: u64,
    ) -> Option<String> {
        let k = (debug_file, debug_id);
        let mut frame = SimpleFrame::with_instruction(address);
        self.fill_symbol(&k, &mut frame).await.ok()?;
        frame.function
    }

    /// Fill symbol information in `frame` using the instruction address
    /// from `frame`, and the module information from `module`. If you're not
    /// using a minidump module, you can use [`SimpleModule`][simplemodule] and
    /// [`SimpleFrame`][simpleframe].
    ///
    /// An Error indicates that no symbols could be found for the relevant
    /// module.
    ///
    /// # Examples
    ///
    /// ```
    /// # std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
    /// use std::str::FromStr;
    /// use debugid::DebugId;
    /// use breakpad_symbols::{SimpleSymbolSupplier,Symbolizer,SimpleFrame,SimpleModule};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     use std::path::PathBuf;
    ///     let paths = vec!(PathBuf::from("../testdata/symbols/"));
    ///     let supplier = SimpleSymbolSupplier::new(paths);
    ///     let symbolizer = Symbolizer::new(supplier);
    ///     let debug_id = DebugId::from_str("5A9832E5287241C1838ED98914E9B7FF1").unwrap();
    ///     let m = SimpleModule::new("test_app.pdb", debug_id);
    ///     let mut f = SimpleFrame::with_instruction(0x1010);
    ///     let _ = symbolizer.fill_symbol(&m, &mut f).await;
    ///     assert_eq!(f.function.unwrap(), "vswprintf");
    ///     assert_eq!(f.source_file.unwrap(),
    ///         r"c:\program files\microsoft visual studio 8\vc\include\swprintf.inl");
    ///     assert_eq!(f.source_line.unwrap(), 51);
    /// }
    /// ```
    ///
    /// [simplemodule]: struct.SimpleModule.html
    /// [simpleframe]: struct.SimpleFrame.html
    pub async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizer + Send),
    ) -> Result<(), FillSymbolError> {
        let k = key(module);
        self.ensure_module(module, &k).await;

        // Symbols will always contain an entry after ensure_module (though it may be an Err).
        self.symbols.lock().unwrap()[&k]
            .as_ref()
            .map(|sym| {
                sym.fill_symbol(module, frame);
            })
            .map_err(|_| FillSymbolError {})
    }

    /// Collect various statistics on the symbols.
    ///
    /// Keys are the file name of the module (code_file's file name).
    pub fn stats(&self) -> HashMap<String, SymbolStats> {
        self.symbols
            .lock()
            .unwrap()
            .iter()
            .map(|(k, res)| {
                let mut stats = SymbolStats::default();
                match res {
                    Ok(sym) => {
                        stats.symbol_url = sym.url.clone();
                        stats.loaded_symbols = true;
                        stats.corrupt_symbols = false;
                    }
                    Err(SymbolError::NotFound) => {
                        stats.loaded_symbols = false;
                    }
                    Err(SymbolError::LoadError(_)) => {
                        stats.loaded_symbols = false;
                    }
                    Err(SymbolError::ParseError(..)) => {
                        stats.loaded_symbols = true;
                        stats.corrupt_symbols = true;
                    }
                }
                (leafname(&k.0).to_string(), stats)
            })
            .collect()
    }

    /// Tries to use CFI to walk the stack frame of the FrameWalker
    /// using the symbols of the given Module. Output will be written
    /// using the FrameWalker's `set_caller_*` APIs.
    pub async fn walk_frame(
        &self,
        module: &(dyn Module + Sync),
        walker: &mut (dyn FrameWalker + Send),
    ) -> Option<()> {
        let k = key(module);
        self.ensure_module(module, &k).await;
        if let Some(Ok(ref sym)) = self.symbols.lock().unwrap().get(&k) {
            trace!("unwind: found symbols for address, searching for cfi entries");
            sym.walk_frame(module, walker)
        } else {
            trace!("unwind: couldn't find symbols for address, cannot use cfi");
            None
        }
    }

    /// Ensures there is an entry in the `symbols` map for the given key
    /// (although it may be an Error). Will not change the entry if it already
    /// exists (so if they first time we look is an Error, it always will be).
    async fn ensure_module(&self, module: &(dyn Module + Sync), k: &ModuleKey) {
        if !self.symbols.lock().unwrap().contains_key(k) {
            let res = self.supplier.locate_symbols(module).await;
            self.symbols.lock().unwrap().insert(k.clone(), res);
        }
    }
}

#[test]
fn test_leafname() {
    assert_eq!(leafname("c:\\foo\\bar\\test.pdb"), "test.pdb");
    assert_eq!(leafname("c:/foo/bar/test.pdb"), "test.pdb");
    assert_eq!(leafname("test.pdb"), "test.pdb");
    assert_eq!(leafname("test"), "test");
    assert_eq!(leafname("/path/to/test"), "test");
}

#[test]
fn test_replace_or_add_extension() {
    assert_eq!(
        replace_or_add_extension("test.pdb", "pdb", "sym"),
        "test.sym"
    );
    assert_eq!(
        replace_or_add_extension("TEST.PDB", "pdb", "sym"),
        "TEST.sym"
    );
    assert_eq!(replace_or_add_extension("test", "pdb", "sym"), "test.sym");
    assert_eq!(
        replace_or_add_extension("test.x", "pdb", "sym"),
        "test.x.sym"
    );
    assert_eq!(replace_or_add_extension("", "pdb", "sym"), ".sym");
    assert_eq!(replace_or_add_extension("test.x", "x", "y"), "test.y");
}

#[cfg(test)]
mod test {

    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_relative_symbol_path() {
        let debug_id = DebugId::from_str("abcd1234-abcd-1234-abcd-abcd12345678-a").unwrap();
        let m = SimpleModule::new("foo.pdb", debug_id);
        assert_eq!(
            &relative_symbol_path(&m, "sym").unwrap(),
            "foo.pdb/ABCD1234ABCD1234ABCDABCD12345678a/foo.sym"
        );

        let m2 = SimpleModule::new("foo.pdb", debug_id);
        assert_eq!(
            &relative_symbol_path(&m2, "bar").unwrap(),
            "foo.pdb/ABCD1234ABCD1234ABCDABCD12345678a/foo.bar"
        );

        let m3 = SimpleModule::new("foo.xyz", debug_id);
        assert_eq!(
            &relative_symbol_path(&m3, "sym").unwrap(),
            "foo.xyz/ABCD1234ABCD1234ABCDABCD12345678a/foo.xyz.sym"
        );

        let m4 = SimpleModule::new("foo.xyz", debug_id);
        assert_eq!(
            &relative_symbol_path(&m4, "bar").unwrap(),
            "foo.xyz/ABCD1234ABCD1234ABCDABCD12345678a/foo.xyz.bar"
        );

        let bad = SimpleModule::default();
        assert!(relative_symbol_path(&bad, "sym").is_none());

        let bad2 = SimpleModule {
            debug_file: Some("foo".to_string()),
            ..SimpleModule::default()
        };
        assert!(relative_symbol_path(&bad2, "sym").is_none());

        let bad3 = SimpleModule {
            debug_id: Some(debug_id),
            ..SimpleModule::default()
        };
        assert!(relative_symbol_path(&bad3, "sym").is_none());
    }

    #[tokio::test]
    async fn test_relative_symbol_path_abs_paths() {
        let debug_id = DebugId::from_str("abcd1234-abcd-1234-abcd-abcd12345678-a").unwrap();
        {
            let m = SimpleModule::new("/path/to/foo.bin", debug_id);
            assert_eq!(
                &relative_symbol_path(&m, "sym").unwrap(),
                "foo.bin/ABCD1234ABCD1234ABCDABCD12345678a/foo.bin.sym"
            );
        }

        {
            let m = SimpleModule::new("c:/path/to/foo.pdb", debug_id);
            assert_eq!(
                &relative_symbol_path(&m, "sym").unwrap(),
                "foo.pdb/ABCD1234ABCD1234ABCDABCD12345678a/foo.sym"
            );
        }

        {
            let m = SimpleModule::new("c:\\path\\to\\foo.pdb", debug_id);
            assert_eq!(
                &relative_symbol_path(&m, "sym").unwrap(),
                "foo.pdb/ABCD1234ABCD1234ABCDABCD12345678a/foo.sym"
            );
        }
    }

    fn mksubdirs(path: &Path, dirs: &[&str]) -> Vec<PathBuf> {
        dirs.iter()
            .map(|dir| {
                let new_path = path.join(dir);
                fs::create_dir(&new_path).unwrap();
                new_path
            })
            .collect()
    }

    fn write_symbol_file(path: &Path, contents: &[u8]) {
        let dir = path.parent().unwrap();
        if !fs::metadata(&dir).ok().map_or(false, |m| m.is_dir()) {
            fs::create_dir_all(&dir).unwrap();
        }
        let mut f = File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    fn write_good_symbol_file(path: &Path) {
        write_symbol_file(path, b"MODULE Linux x86 abcd1234 foo\n");
    }

    fn write_bad_symbol_file(path: &Path) {
        write_symbol_file(path, b"this is not a symbol file\n");
    }

    #[tokio::test]
    async fn test_simple_symbol_supplier() {
        let t = tempfile::tempdir().unwrap();
        let paths = mksubdirs(t.path(), &["one", "two"]);

        let supplier = SimpleSymbolSupplier::new(paths.clone());
        let bad = SimpleModule::default();
        assert_eq!(
            supplier.locate_symbols(&bad).await,
            Err(SymbolError::NotFound)
        );

        // Try loading symbols for each of two modules in each of the two
        // search paths.
        for &(path, file, id, sym) in [
            (
                &paths[0],
                "foo.pdb",
                DebugId::from_str("abcd1234-0000-0000-0000-abcd12345678-a").unwrap(),
                "foo.pdb/ABCD1234000000000000ABCD12345678a/foo.sym",
            ),
            (
                &paths[1],
                "bar.xyz",
                DebugId::from_str("ff990000-0000-0000-0000-abcd12345678-a").unwrap(),
                "bar.xyz/FF990000000000000000ABCD12345678a/bar.xyz.sym",
            ),
        ]
        .iter()
        {
            let m = SimpleModule::new(file, id);
            // No symbols present yet.
            assert_eq!(
                supplier.locate_symbols(&m).await,
                Err(SymbolError::NotFound)
            );
            write_good_symbol_file(&path.join(sym));
            // Should load OK now that it exists.
            assert!(
                matches!(supplier.locate_symbols(&m).await, Ok(_)),
                "{}",
                format!("Located symbols for {}", sym)
            );
        }

        // Write a malformed symbol file, verify that it's found but fails to load.
        let debug_id = DebugId::from_str("ffff0000-0000-0000-0000-abcd12345678-a").unwrap();
        let mal = SimpleModule::new("baz.pdb", debug_id);
        let sym = "baz.pdb/FFFF0000000000000000ABCD12345678a/baz.sym";
        assert_eq!(
            supplier.locate_symbols(&mal).await,
            Err(SymbolError::NotFound)
        );
        write_bad_symbol_file(&paths[0].join(sym));
        let res = supplier.locate_symbols(&mal).await;
        assert!(
            matches!(res, Err(SymbolError::ParseError(..))),
            "{}",
            format!("Correctly failed to parse {}, result: {:?}", sym, res)
        );
    }

    #[tokio::test]
    async fn test_symbolizer() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path();

        // TODO: This could really use a MockSupplier
        let supplier = SimpleSymbolSupplier::new(vec![PathBuf::from(path)]);
        let symbolizer = Symbolizer::new(supplier);
        let debug_id = DebugId::from_str("abcd1234-abcd-1234-abcd-abcd12345678-a").unwrap();
        let m1 = SimpleModule::new("foo.pdb", debug_id);
        write_symbol_file(
            &path.join("foo.pdb/ABCD1234ABCD1234ABCDABCD12345678a/foo.sym"),
            b"MODULE Linux x86 ABCD1234ABCD1234ABCDABCD12345678a foo
FILE 1 foo.c
FUNC 1000 30 10 some func
1000 30 100 1
",
        );
        let mut f1 = SimpleFrame::with_instruction(0x1010);
        symbolizer.fill_symbol(&m1, &mut f1).await.unwrap();
        assert_eq!(f1.function.unwrap(), "some func");
        assert_eq!(f1.function_base.unwrap(), 0x1000);
        assert_eq!(f1.source_file.unwrap(), "foo.c");
        assert_eq!(f1.source_line.unwrap(), 100);
        assert_eq!(f1.source_line_base.unwrap(), 0x1000);

        assert_eq!(
            symbolizer
                .get_symbol_at_address("foo.pdb", debug_id, 0x1010)
                .await
                .unwrap(),
            "some func"
        );

        let debug_id = DebugId::from_str("ffff0000-0000-0000-0000-abcd12345678-a").unwrap();
        let m2 = SimpleModule::new("bar.pdb", debug_id);
        let mut f2 = SimpleFrame::with_instruction(0x1010);
        // No symbols present, should not find anything.
        assert!(symbolizer.fill_symbol(&m2, &mut f2).await.is_err());
        assert!(f2.function.is_none());
        assert!(f2.function_base.is_none());
        assert!(f2.source_file.is_none());
        assert!(f2.source_line.is_none());
        // Results should be cached.
        write_symbol_file(
            &path.join("bar.pdb/ffff0000000000000000ABCD12345678a/bar.sym"),
            b"MODULE Linux x86 ffff0000000000000000ABCD12345678a bar
FILE 53 bar.c
FUNC 1000 30 10 another func
1000 30 7 53
",
        );
        assert!(symbolizer.fill_symbol(&m2, &mut f2).await.is_err());
        assert!(f2.function.is_none());
        assert!(f2.function_base.is_none());
        assert!(f2.source_file.is_none());
        assert!(f2.source_line.is_none());
        // This should also use cached results.
        assert!(symbolizer
            .get_symbol_at_address("bar.pdb", debug_id, 0x1010)
            .await
            .is_none());
    }
}
