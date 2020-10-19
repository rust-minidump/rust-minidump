// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! A library for working with [Google Breakpad][breakpad]'s
//! text-format [symbol files][symbolfiles].
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
//! use breakpad_symbols::{SimpleSymbolSupplier,Symbolizer,SimpleFrame,SimpleModule};
//! use std::path::PathBuf;
//! let paths = vec!(PathBuf::from("../testdata/symbols/"));
//! let supplier = SimpleSymbolSupplier::new(paths);
//! let symbolizer = Symbolizer::new(supplier);
//!
//! // Simple function name lookup with debug file, debug id, address.
//! assert_eq!(symbolizer.get_symbol_at_address("test_app.pdb",
//!                                             "5A9832E5287241C1838ED98914E9B7FF1",
//!                                             0x1010)
//!               .unwrap(),
//!               "vswprintf");
//! ```

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate minidump_common;
#[allow(unused_imports)]
#[macro_use]
extern crate nom;
extern crate range_map;
extern crate reqwest;
#[cfg(test)]
extern crate tempdir;

mod sym_file;

use failure::Error;
pub use minidump_common::traits::Module;
use reqwest::blocking::Client;
use reqwest::Url;
use std::borrow::Cow;
use std::boxed::Box;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
pub use sym_file::SymbolFile;

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
    pub code_identifier: Option<String>,
    pub debug_file: Option<String>,
    pub debug_id: Option<String>,
    pub version: Option<String>,
}

impl SimpleModule {
    /// Create a `SimpleModule` with the given `debug_file` and `debug_id`.
    ///
    /// Uses `default` for the remaining fields.
    pub fn new(debug_file: &str, debug_id: &str) -> SimpleModule {
        SimpleModule {
            debug_file: Some(String::from(debug_file)),
            debug_id: Some(String::from(debug_id)),
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
    fn code_identifier(&self) -> Cow<str> {
        self.code_identifier
            .as_ref()
            .map_or(Cow::from(""), |s| Cow::Borrowed(&s[..]))
    }
    fn debug_file(&self) -> Option<Cow<str>> {
        self.debug_file.as_ref().map(|s| Cow::Borrowed(&s[..]))
    }
    fn debug_identifier(&self) -> Option<Cow<str>> {
        self.debug_id.as_ref().map(|s| Cow::Borrowed(&s[..]))
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
pub fn relative_symbol_path(module: &dyn Module, extension: &str) -> Option<String> {
    module.debug_file().and_then(|debug_file| {
        module.debug_identifier().map(|debug_id| {
            // Can't use PathBuf::file_name here, it doesn't handle
            // Windows file paths on non-Windows.
            let leaf = leafname(&debug_file);
            let filename = replace_or_add_extension(leaf, "pdb", extension);
            [leaf, &debug_id[..], &filename[..]].join("/")
        })
    })
}

/// Possible results of locating symbols.
#[derive(Debug)]
pub enum SymbolResult {
    /// Symbols loaded successfully.
    Ok(SymbolFile),
    /// Symbol file could not be found.
    NotFound,
    /// Error loading symbol file.
    LoadError(Error),
}

impl PartialEq for SymbolResult {
    fn eq(&self, other: &SymbolResult) -> bool {
        match (self, other) {
            (&SymbolResult::Ok(ref a), &SymbolResult::Ok(ref b)) => a == b,
            (&SymbolResult::NotFound, &SymbolResult::NotFound) => true,
            (&SymbolResult::LoadError(_), &SymbolResult::LoadError(_)) => true,
            _ => false,
        }
    }
}

impl fmt::Display for SymbolResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SymbolResult::Ok(_) => write!(f, "Ok"),
            SymbolResult::NotFound => write!(f, "Not found"),
            SymbolResult::LoadError(ref e) => write!(f, "Load error: {}", e),
        }
    }
}

/// A trait for things that can locate symbols for a given module.
pub trait SymbolSupplier {
    /// Locate and load a symbol file for `module`.
    ///
    /// Implementations may use any strategy for locating and loading
    /// symbols.
    fn locate_symbols(&self, module: &dyn Module) -> SymbolResult;
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

impl SymbolSupplier for SimpleSymbolSupplier {
    fn locate_symbols(&self, module: &dyn Module) -> SymbolResult {
        if let Some(rel_path) = relative_symbol_path(module, "sym") {
            for ref path in self.paths.iter() {
                let test_path = path.join(&rel_path);
                if fs::metadata(&test_path).ok().map_or(false, |m| m.is_file()) {
                    return SymbolFile::from_file(&test_path)
                        .map(SymbolResult::Ok)
                        .unwrap_or_else(SymbolResult::LoadError);
                }
            }
        }
        SymbolResult::NotFound
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
    cache: PathBuf,
}

impl HttpSymbolSupplier {
    /// Create a new `HttpSymbolSupplier`.
    ///
    /// Symbols will be searched for in each of `local_paths` and `cache` first, then via HTTP
    /// at each of `urls`. If a symbol file is found via HTTP it will be saved under `cache`.
    pub fn new(
        urls: Vec<String>,
        cache: PathBuf,
        mut local_paths: Vec<PathBuf>,
    ) -> HttpSymbolSupplier {
        let client = Client::new();
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
        }
    }
}

/// Save the data in `contents` to `path`.
fn save_contents(contents: &[u8], path: &Path) -> io::Result<()> {
    let base = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, format!("Bad cache path: {:?}", path))
    })?;
    fs::create_dir_all(&base)?;
    let mut f = File::create(path)?;
    f.write_all(contents)?;
    Ok(())
}

/// Fetch a symbol file from the URL made by combining `base_url` and `rel_path` using `client`,
/// save the file contents under `cache` + `rel_path` and also return them.
fn fetch_symbol_file(
    client: &Client,
    base_url: &Url,
    rel_path: &str,
    cache: &Path,
) -> Result<Vec<u8>, Error> {
    let url = base_url.join(&rel_path)?;
    debug!("Trying {}", url);
    let mut res = client.get(url).send()?.error_for_status()?;
    let mut buf = vec![];
    res.read_to_end(&mut buf)?;
    let local = cache.join(rel_path);
    match save_contents(&buf, &local) {
        Ok(_) => {}
        Err(e) => warn!("Failed to save symbol file in local disk cache: {}", e),
    }
    Ok(buf)
}

impl SymbolSupplier for HttpSymbolSupplier {
    fn locate_symbols(&self, module: &dyn Module) -> SymbolResult {
        // Check local paths first.
        match self.local.locate_symbols(module) {
            res @ SymbolResult::Ok(_) | res @ SymbolResult::LoadError(_) => res,
            SymbolResult::NotFound => {
                if let Some(rel_path) = relative_symbol_path(module, "sym") {
                    for ref url in self.urls.iter() {
                        if let Ok(buf) =
                            fetch_symbol_file(&self.client, url, &rel_path, &self.cache)
                        {
                            return SymbolFile::from_bytes(&buf)
                                .map(SymbolResult::Ok)
                                .unwrap_or_else(SymbolResult::LoadError);
                        }
                    }
                }
                SymbolResult::NotFound
            }
        }
    }
}

/// A trait for setting symbol information on something like a stack frame.
pub trait FrameSymbolizer {
    /// Get the program counter value for this frame.
    fn get_instruction(&self) -> u64;
    /// Set the name and base address of the function in which this frame is executing.
    fn set_function(&mut self, name: &str, base: u64);
    /// Set the source file and (1-based) line number this frame represents.
    fn set_source_file(&mut self, file: &str, line: u32, base: u64);
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
    fn set_function(&mut self, name: &str, base: u64) {
        self.function = Some(String::from(name));
        self.function_base = Some(base);
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
fn key(module: &dyn Module) -> ModuleKey {
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
    supplier: Box<dyn SymbolSupplier + 'static>,
    /// Cache of symbol locating results.
    //TODO: use lru-cache: https://crates.io/crates/lru-cache/
    symbols: RefCell<HashMap<ModuleKey, SymbolResult>>,
}

impl Symbolizer {
    /// Create a `Symbolizer` that uses `supplier` to locate symbols.
    pub fn new<T: SymbolSupplier + 'static>(supplier: T) -> Symbolizer {
        Symbolizer {
            supplier: Box::new(supplier),
            symbols: RefCell::new(HashMap::new()),
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
    pub fn get_symbol_at_address(
        &self,
        debug_file: &str,
        debug_id: &str,
        address: u64,
    ) -> Option<String> {
        let k = (debug_file, debug_id);
        let mut frame = SimpleFrame::with_instruction(address);
        self.fill_symbol(&k, &mut frame);
        frame.function
    }

    /// Fill symbol information in `frame` using the instruction address
    /// from `frame`, and the module information from `module`. If you're not
    /// using a minidump module, you can use [`SimpleModule`][simplemodule] and
    /// [`SimpleFrame`][simpleframe].
    ///
    /// # Examples
    ///
    /// ```
    /// use breakpad_symbols::{SimpleSymbolSupplier,Symbolizer,SimpleFrame,SimpleModule};
    /// use std::path::PathBuf;
    /// let paths = vec!(PathBuf::from("../testdata/symbols/"));
    /// let supplier = SimpleSymbolSupplier::new(paths);
    /// let symbolizer = Symbolizer::new(supplier);
    /// let m = SimpleModule::new("test_app.pdb", "5A9832E5287241C1838ED98914E9B7FF1");
    /// let mut f = SimpleFrame::with_instruction(0x1010);
    /// symbolizer.fill_symbol(&m, &mut f);
    /// assert_eq!(f.function.unwrap(), "vswprintf");
    /// assert_eq!(f.source_file.unwrap(), r"c:\program files\microsoft visual studio 8\vc\include\swprintf.inl");
    /// assert_eq!(f.source_line.unwrap(), 51);
    /// ```
    ///
    /// [simplemodule]: struct.SimpleModule.html
    /// [simpleframe]: struct.SimpleFrame.html
    pub fn fill_symbol(&self, module: &dyn Module, frame: &mut dyn FrameSymbolizer) {
        let k = key(module);
        if !self.symbols.borrow().contains_key(&k) {
            let res = self.supplier.locate_symbols(module);
            debug!("locate_symbols for {}: {}", module.code_file(), res);
            self.symbols.borrow_mut().insert(k.clone(), res);
        }
        if let Some(res) = self.symbols.borrow().get(&k) {
            if let SymbolResult::Ok(ref sym) = *res {
                sym.fill_symbol(module, frame)
            }
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
    use tempdir::TempDir;

    #[test]
    fn test_relative_symbol_path() {
        let m = SimpleModule::new("foo.pdb", "abcd1234");
        assert_eq!(
            &relative_symbol_path(&m, "sym").unwrap(),
            "foo.pdb/abcd1234/foo.sym"
        );

        let m2 = SimpleModule::new("foo.pdb", "abcd1234");
        assert_eq!(
            &relative_symbol_path(&m2, "bar").unwrap(),
            "foo.pdb/abcd1234/foo.bar"
        );

        let m3 = SimpleModule::new("foo.xyz", "abcd1234");
        assert_eq!(
            &relative_symbol_path(&m3, "sym").unwrap(),
            "foo.xyz/abcd1234/foo.xyz.sym"
        );

        let m4 = SimpleModule::new("foo.xyz", "abcd1234");
        assert_eq!(
            &relative_symbol_path(&m4, "bar").unwrap(),
            "foo.xyz/abcd1234/foo.xyz.bar"
        );

        let bad = SimpleModule::default();
        assert!(relative_symbol_path(&bad, "sym").is_none());

        let bad2 = SimpleModule {
            debug_file: Some("foo".to_string()),
            ..SimpleModule::default()
        };
        assert!(relative_symbol_path(&bad2, "sym").is_none());

        let bad3 = SimpleModule {
            debug_id: Some("foo".to_string()),
            ..SimpleModule::default()
        };
        assert!(relative_symbol_path(&bad3, "sym").is_none());
    }

    #[test]
    fn test_relative_symbol_path_abs_paths() {
        {
            let m = SimpleModule::new("/path/to/foo.bin", "abcd1234");
            assert_eq!(
                &relative_symbol_path(&m, "sym").unwrap(),
                "foo.bin/abcd1234/foo.bin.sym"
            );
        }

        {
            let m = SimpleModule::new("c:/path/to/foo.pdb", "abcd1234");
            assert_eq!(
                &relative_symbol_path(&m, "sym").unwrap(),
                "foo.pdb/abcd1234/foo.sym"
            );
        }

        {
            let m = SimpleModule::new("c:\\path\\to\\foo.pdb", "abcd1234");
            assert_eq!(
                &relative_symbol_path(&m, "sym").unwrap(),
                "foo.pdb/abcd1234/foo.sym"
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

    #[test]
    fn test_simple_symbol_supplier() {
        let t = TempDir::new("symtest").unwrap();
        let paths = mksubdirs(t.path(), &["one", "two"]);

        let supplier = SimpleSymbolSupplier::new(paths.clone());
        let bad = SimpleModule::default();
        assert_eq!(supplier.locate_symbols(&bad), SymbolResult::NotFound);

        // Try loading symbols for each of two modules in each of the two
        // search paths.
        for &(path, file, id, sym) in [
            (&paths[0], "foo.pdb", "abcd1234", "foo.pdb/abcd1234/foo.sym"),
            (&paths[1], "bar.xyz", "ff9900", "bar.xyz/ff9900/bar.xyz.sym"),
        ]
        .iter()
        {
            let m = SimpleModule::new(file, id);
            // No symbols present yet.
            assert_eq!(supplier.locate_symbols(&m), SymbolResult::NotFound);
            write_good_symbol_file(&path.join(sym));
            // Should load OK now that it exists.
            assert!(
                matches!(supplier.locate_symbols(&m), SymbolResult::Ok(_)),
                format!("Located symbols for {}", sym)
            );
        }

        // Write a malformed symbol file, verify that it's found but fails to load.
        let mal = SimpleModule::new("baz.pdb", "ffff0000");
        let sym = "baz.pdb/ffff0000/baz.sym";
        assert_eq!(supplier.locate_symbols(&mal), SymbolResult::NotFound);
        write_bad_symbol_file(&paths[0].join(sym));
        let res = supplier.locate_symbols(&mal);
        assert!(
            matches!(res, SymbolResult::LoadError(_)),
            format!("Correctly failed to parse {}, result: {:?}", sym, res)
        );
    }

    #[test]
    fn test_symbolizer() {
        let t = TempDir::new("symtest").unwrap();
        let path = t.path();

        // TODO: This could really use a MockSupplier
        let supplier = SimpleSymbolSupplier::new(vec![PathBuf::from(path)]);
        let symbolizer = Symbolizer::new(supplier);
        let m1 = SimpleModule::new("foo.pdb", "abcd1234");
        write_symbol_file(
            &path.join("foo.pdb/abcd1234/foo.sym"),
            b"MODULE Linux x86 abcd1234 foo
FILE 1 foo.c
FUNC 1000 30 10 some func
1000 30 100 1
",
        );
        let mut f1 = SimpleFrame::with_instruction(0x1010);
        symbolizer.fill_symbol(&m1, &mut f1);
        assert_eq!(f1.function.unwrap(), "some func");
        assert_eq!(f1.function_base.unwrap(), 0x1000);
        assert_eq!(f1.source_file.unwrap(), "foo.c");
        assert_eq!(f1.source_line.unwrap(), 100);
        assert_eq!(f1.source_line_base.unwrap(), 0x1000);

        assert_eq!(
            symbolizer
                .get_symbol_at_address("foo.pdb", "abcd1234", 0x1010)
                .unwrap(),
            "some func"
        );

        let m2 = SimpleModule::new("bar.pdb", "ffff0000");
        let mut f2 = SimpleFrame::with_instruction(0x1010);
        // No symbols present, should not find anything.
        symbolizer.fill_symbol(&m2, &mut f2);
        assert!(f2.function.is_none());
        assert!(f2.function_base.is_none());
        assert!(f2.source_file.is_none());
        assert!(f2.source_line.is_none());
        // Results should be cached.
        write_symbol_file(
            &path.join("bar.pdb/ffff0000/bar.sym"),
            b"MODULE Linux x86 ffff0000 bar
FILE 53 bar.c
FUNC 1000 30 10 another func
1000 30 7 53
",
        );
        symbolizer.fill_symbol(&m2, &mut f2);
        assert!(f2.function.is_none());
        assert!(f2.function_base.is_none());
        assert!(f2.source_file.is_none());
        assert!(f2.source_line.is_none());
        // This should also use cached results.
        assert!(symbolizer
            .get_symbol_at_address("bar.pdb", "ffff0000", 0x1010)
            .is_none());
    }
}
