//! This module defines the interface between minidump-processor and its [Symbolizer][].
//!
//! There can only be one [Symbolizer][], and this is configured by minidump-processor's Cargo
//! feature flags. The currently defined Symbolizers are:
//!
//! * breakpad_symbols -- feature: breakpad-syms (currently the default)
//! * symbolic -- feature: symbolic-syms (not yet implemented, but compiles)
//!
//!
//! minidump-processor and the [Symbolizer][] communicate using a series of traits. The symbolizer
//! must provide implementations of these traits:
//!
//! * [SymbolProvider][] - provides symbolication, cfi evaluation, and debug statistics
//!     * Implemented by [Symbolizer][]
//!     * This actually doesn't need to be a trait in the current design, it exists to allow
//!       multiple symbolicators to be used together, via [MultiSymbolProvider][]. The other
//!       SymbolProviders have been removed, but I figured it would be a waste to throw out
//!       this minimally intrusive machinery.
//!
//! * [SymbolSupplier][] - maps a [Module][] to a [SymbolFile][]
//!     * minidump-processor does not directly use this, it's just there so the Symbolizer can
//!       generically handle different symbol fetching strategies (which minidump-processor
//!       selects and configures).
//!
//!
//!
//! While minidump-processor provides implementations of these traits:
//!
//! * [FrameSymbolizer][] - callbacks that symbolication uses to return its results.
//!     * Implemented by [StackFrame][crate::process_state::StackFrame]
//!     * Implemented by DummyFrame (private, for a stack scanning heuristic)
//! * [FrameWalker][] - callbacks that cfi eval uses to read callee state and write caller state.
//!     * Implemented by CfiStackWalker (private)
//!
//!
//!
//! The symbolizer is responsible for providing the following concrete functions, which
//! minidump-processor uses to select and configure the symbol fetching strategy:
//!
//! * [http_symbol_supplier][] - a [SymbolSupplier][] that can find symbols over HTTP (and cache).
//! * [simple_symbol_supplier][] - a [SymbolSupplier][] that can find symbols on disk.
//! * [string_symbol_supplier][] - a mock [SymbolSupplier][] for tests.
//!
//!
//!
//! And the following concrete types:
//!
//! * [Symbolizer][] - the main interface of the symbolizer, implementing [SymbolProvider][].
//!     * Wraps the [SymbolSupplier][] implementation that minidump-processor selects.
//!     * Queries the [SymbolSupplier] and manages the SymbolFiles however it pleases.
//! * [SymbolStats][] - debug statistic output.
//! * [SymbolFile][] - a payload that a [SymbolProvider][] returns to the Symbolizer.
//!     * Never handled by minidump-processor, public for the trait. (use this for whatever)
//! * [SymbolError][] - possible errors a [SymbolProvider][] can yield.
//!     * Never handled by minidump-processor, public for the trait. (use this for whatever)
//! * [FillSymbolError][] - possible errors for `fill_symbol`.
//!     * While this *is* handled by minidump-processor, it doesn't actually look at the value. It's
//!       just there to be An Error Type for the sake of API design.
//!
//!
//!
//! # Example
//!
//! ```rust
//! use minidump::Minidump;
//! use minidump_processor::{http_symbol_supplier, ProcessorOptions, Symbolizer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ()> {
//!     // Read the minidump
//!     let dump = Minidump::read_path("../testdata/test.dmp").map_err(|_| ())?;
//!
//!     // Configure the symbolizer and processor
//!     let symbols_urls = vec![String::from("https://symbols.totallyrealwebsite.org")];
//!     let symbols_paths = vec![];
//!     let mut symbols_cache = std::env::temp_dir();
//!     symbols_cache.push("minidump-cache");
//!     let symbols_tmp = std::env::temp_dir();
//!     let timeout = std::time::Duration::from_secs(1000);
//!
//!     let options = ProcessorOptions::default();
//!     let provider = Symbolizer::new(http_symbol_supplier(
//!         symbols_paths,
//!         symbols_urls,
//!         symbols_cache,
//!         symbols_tmp,
//!         timeout,
//!     ));
//!
//!     let state = minidump_processor::process_minidump_with_options(&dump, &provider, options)
//!         .await
//!         .map_err(|_| ())?;
//!     state.print(&mut std::io::stdout()).map_err(|_| ())?;
//!     Ok(())
//! }
//! ```
//!

use async_trait::async_trait;
use minidump::Module;
use std::{collections::HashMap, path::PathBuf};
pub use symbols_shim::*;

#[async_trait]
pub trait SymbolProvider {
    async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizer + Send),
    ) -> Result<(), FillSymbolError>;
    async fn walk_frame(
        &self,
        module: &(dyn Module + Sync),
        walker: &mut (dyn FrameWalker + Send),
    ) -> Option<()>;
    async fn get_file_path(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError>;
    fn stats(&self) -> HashMap<String, SymbolStats>;
}

#[derive(Default)]
pub struct MultiSymbolProvider {
    providers: Vec<Box<dyn SymbolProvider + Send + Sync>>,
}

impl MultiSymbolProvider {
    pub fn new() -> MultiSymbolProvider {
        Default::default()
    }

    pub fn add(&mut self, provider: Box<dyn SymbolProvider + Send + Sync>) {
        self.providers.push(provider);
    }
}

#[async_trait]
impl SymbolProvider for MultiSymbolProvider {
    async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizer + Send),
    ) -> Result<(), FillSymbolError> {
        // Return Ok if *any* symbol provider came back with Ok, so that the user can
        // distinguish between having no symbols at all and just not being able to
        // symbolize this particular frame.
        let mut best_result = Err(FillSymbolError {});
        for p in self.providers.iter() {
            let new_result = p.fill_symbol(module, frame).await;
            best_result = best_result.or(new_result);
        }
        best_result
    }

    async fn walk_frame(
        &self,
        module: &(dyn Module + Sync),
        walker: &mut (dyn FrameWalker + Send),
    ) -> Option<()> {
        for p in self.providers.iter() {
            let result = p.walk_frame(module, walker).await;
            if result.is_some() {
                return result;
            }
        }
        None
    }

    async fn get_file_path(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        // Return Ok if *any* symbol provider came back with Ok
        let mut best_result = Err(FileError::NotFound);
        for p in self.providers.iter() {
            let new_result = p.get_file_path(module, file_kind).await;
            best_result = best_result.or(new_result);
        }
        best_result
    }

    fn stats(&self) -> HashMap<String, SymbolStats> {
        let mut result = HashMap::new();
        for p in self.providers.iter() {
            // FIXME: do more intelligent merging of the stats
            // (currently doesn't matter as only one provider reports non-empty stats).
            result.extend(p.stats());
        }
        result
    }
}

#[cfg(feature = "breakpad-syms")]
mod symbols_shim {
    use super::SymbolProvider;
    use async_trait::async_trait;
    pub use breakpad_symbols::{
        FileError, FileKind, FillSymbolError, FrameSymbolizer, FrameWalker, SymbolError,
        SymbolFile, SymbolStats, SymbolSupplier, Symbolizer,
    };
    use minidump::Module;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[async_trait]
    impl SymbolProvider for Symbolizer {
        async fn fill_symbol(
            &self,
            module: &(dyn Module + Sync),
            frame: &mut (dyn FrameSymbolizer + Send),
        ) -> Result<(), FillSymbolError> {
            self.fill_symbol(module, frame).await
        }
        async fn walk_frame(
            &self,
            module: &(dyn Module + Sync),
            walker: &mut (dyn FrameWalker + Send),
        ) -> Option<()> {
            self.walk_frame(module, walker).await
        }
        async fn get_file_path(
            &self,
            module: &(dyn Module + Sync),
            file_kind: FileKind,
        ) -> Result<PathBuf, FileError> {
            self.get_file_path(module, file_kind).await
        }
        fn stats(&self) -> HashMap<String, SymbolStats> {
            self.stats()
        }
    }

    /// Gets a SymbolSupplier that looks up symbols by path or with urls.
    ///
    /// * `symbols_paths` is a list of paths to check for symbol files. Paths
    ///   are searched in order until one returns a payload. If none do, then
    ///   urls are used.
    ///
    /// * `symbols_urls` is a list of "base urls" that should all point to Tecken
    ///   servers. urls are queried in order until one returns a payload. If none
    ///   do, then it's an error.
    ///
    /// * `symbols_cache` is a directory where an on-disk cache should be located.
    ///   This should be assumed to be a "temp" directory that another process
    ///   you don't control is garbage-collecting old files from (to provide an LRU cache).
    ///   The cache is queried before paths and urls (otherwise it wouldn't be much of a cache).
    ///
    /// * `symbols_tmp` is a directory where symbol files should be downloaded to
    ///   before atomically swapping them into the cache. Has the same "temp"
    ///   assumptions as symbols_cache.
    ///
    /// * `timeout` a maximum time limit for a symbol file download. This
    ///   is primarily defined to avoid getting stuck on buggy infinite downloads.
    ///   As of this writing, minidump-stackwalk defaults this to 1000 seconds. In
    ///   the event of a timeout, the supplier may still try to parse the truncated
    ///   download.
    #[cfg(feature = "http")]
    pub fn http_symbol_supplier(
        symbol_paths: Vec<PathBuf>,
        symbol_urls: Vec<String>,
        symbols_cache: PathBuf,
        symbols_tmp: PathBuf,
        timeout: std::time::Duration,
    ) -> impl SymbolSupplier {
        breakpad_symbols::HttpSymbolSupplier::new(
            symbol_urls,
            symbols_cache,
            symbols_tmp,
            symbol_paths,
            timeout,
        )
    }

    /// Gets a SymbolSupplier that looks up symbols by path.
    ///
    /// Paths are queried in order until one returns a payload.
    pub fn simple_symbol_supplier(symbol_paths: Vec<PathBuf>) -> impl SymbolSupplier {
        breakpad_symbols::SimpleSymbolSupplier::new(symbol_paths)
    }

    /// Gets a mock SymbolSupplier that just maps module names
    /// to a string containing an entire breakpad .sym file, for tests.
    pub fn string_symbol_supplier(modules: HashMap<String, String>) -> impl SymbolSupplier {
        breakpad_symbols::StringSymbolSupplier::new(modules)
    }
}

#[cfg(all(feature = "symbolic-syms", not(feature = "breakpad-syms")))]
mod symbols_shim {
    #![allow(dead_code)]

    use super::SymbolProvider;
    use async_trait::async_trait;
    use minidump::Module;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    // Import symbolic here

    /// A trait for things that can locate symbols for a given module.
    #[async_trait]
    pub trait SymbolSupplier {
        /// Locate and load a symbol file for `module`.
        ///
        /// Implementations may use any strategy for locating and loading
        /// symbols.
        async fn locate_symbols(
            &mut self,
            module: &(dyn Module + Sync),
        ) -> Result<SymbolFile, SymbolError>;

        /// Locate a specific file associated with a `module`
        ///
        /// Implementations may use any strategy for locating and loading
        /// symbols.
        async fn locate_file(
            &self,
            module: &(dyn Module + Sync),
            file_kind: FileKind,
        ) -> Result<PathBuf, FileError>;
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
        supplier: Box<dyn SymbolSupplier + 'static + Send + Sync>,
    }

    impl Symbolizer {
        /// Create a `Symbolizer` that uses `supplier` to locate symbols.
        pub fn new<T: SymbolSupplier + 'static + Send + Sync>(supplier: T) -> Symbolizer {
            Symbolizer {
                supplier: Box::new(supplier),
            }
        }
    }

    #[async_trait]
    impl SymbolProvider for Symbolizer {
        async fn fill_symbol(
            &self,
            _module: &(dyn Module + Sync),
            _frame: &mut (dyn FrameSymbolizer + Send),
        ) -> Result<(), FillSymbolError> {
            unimplemented!()
        }
        async fn walk_frame(
            &self,
            _module: &(dyn Module + Sync),
            _walker: &mut (dyn FrameWalker + Send),
        ) -> Option<()> {
            unimplemented!()
        }
        fn stats(&self) -> HashMap<String, SymbolStats> {
            unimplemented!()
        }
        async fn get_file_path(
            &self,
            module: &(dyn Module + Sync),
            file_kind: FileKind,
        ) -> Result<PathBuf, FileError> {
            unimplemented!()
        }
    }

    /// Gets a SymbolSupplier that looks up symbols by path or with urls.
    ///
    /// * `symbols_paths` is a list of paths to check for symbol files. Paths
    ///   are searched in order until one returns a payload. If none do, then
    ///   urls are used.
    ///
    /// * `symbols_urls` is a list of "base urls" that should all point to Tecken
    ///   servers. urls are queried in order until one returns a payload. If none
    ///   do, then it's an error.
    ///
    /// * `symbols_cache` is a directory where an on-disk cache should be located.
    ///   This should be assumed to be a "temp" directory that another process
    ///   you don't control is garbage-collecting old files from (to provide an LRU cache).
    ///   The cache is queried before paths and urls (otherwise it wouldn't be much of a cache).
    ///
    /// * `symbols_tmp` is a directory where symbol files should be downloaded to
    ///   before atomically swapping them into the cache. Has the same "temp"
    ///   assumptions as symbols_cache.
    ///
    /// * `timeout` a maximum time limit (in seconds) for a symbol file download. This
    ///   is primarily defined to avoid getting stuck on buggy infinite downloads.
    ///   As of this writing, minidump-stackwalk defaults this to 1000 seconds. In
    ///   the event of a timeout, the supplier may still try to parse the truncated
    ///   download.
    pub fn http_symbol_supplier(
        _symbol_paths: Vec<PathBuf>,
        _symbol_urls: Vec<String>,
        _symbols_cache: PathBuf,
        _symbols_tmp: PathBuf,
        _timeout: Duration,
    ) -> impl SymbolSupplier {
        HttpSymbolSupplier {}
    }

    /// Gets a SymbolSupplier that looks up symbols by path.
    ///
    /// Paths are queried in order until one returns a payload.
    pub fn simple_symbol_supplier(_symbol_paths: Vec<PathBuf>) -> impl SymbolSupplier {
        SimpleSymbolSupplier {}
    }

    /// Gets a mock SymbolSupplier that just maps module names
    /// to a string containing an entire breakpad .sym file, for tests.
    pub fn string_symbol_supplier(_modules: HashMap<String, String>) -> impl SymbolSupplier {
        StringSymbolSupplier {}
    }

    /// A type of file related to a module that you might want downloaded.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum FileKind {
        /// A Breakpad symbol (.sym) file
        BreakpadSym,
        /// The native binary of a module ("code file") (.exe/.dll/.so/.dylib...)
        Binary,
        /// Extra debuginfo for a module ("debug file") (.pdb/...?)
        ExtraDebugInfo,
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
    #[derive(Debug)]
    pub enum SymbolError {
        /// Symbol file could not be found.
        ///
        /// In this case other symbol providers may still be able to find it!
        NotFound,
        /// Symbol file could not be loaded into memory.
        LoadError,
        /// Symbol file was too corrupt to be parsed at all.
        ///
        /// Because symbol files are pretty modular, many corruptions/ambiguities
        /// can be either repaired or discarded at a fairly granular level
        /// (e.g. a bad STACK WIN line can be discarded without affecting anything
        /// else). But sometimes we can't make any sense of the symbol file, and
        /// you find yourself here.
        ParseError,
    }

    #[derive(Clone, Debug, thiserror::Error)]
    pub enum FileError {
        #[error("file not found")]
        NotFound,
    }

    #[derive(Debug)]
    pub struct FillSymbolError {}

    // Whatever representation you want, rust-minidump won't look at it.
    pub struct SymbolFile {}

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

    // These suppliers are entriely private to the implementation, so do whatever you
    // want with them.

    struct HttpSymbolSupplier {}

    struct SimpleSymbolSupplier {}

    struct StringSymbolSupplier {}

    #[async_trait]
    impl SymbolSupplier for HttpSymbolSupplier {
        async fn locate_symbols(
            &mut self,
            _module: &(dyn Module + Sync),
        ) -> Result<SymbolFile, SymbolError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SymbolSupplier for SimpleSymbolSupplier {
        async fn locate_symbols(
            &mut self,
            _module: &(dyn Module + Sync),
        ) -> Result<SymbolFile, SymbolError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SymbolSupplier for StringSymbolSupplier {
        async fn locate_symbols(
            &mut self,
            _module: &(dyn Module + Sync),
        ) -> Result<SymbolFile, SymbolError> {
            unimplemented!()
        }
    }
}
