//! An interface for Symbol Clients used by rust-minidump.
//!
//! This is glue for [minidump-processor](https://docs.rs/minidump-processor/latest/minidump-processor/)
//! and [minidump-stackwalk](https://docs.rs/minidump-stackwalk/latest/minidump-stackwalk/) to be able to
//! have any symbolizer backend plugged in.
//!
//! The current primary implementation is [breakpad-symbols](https://docs.rs/breakpad-symbols/latest/breakpad-symbols/).
//! but ideally this will one day be replaced by something based on [symbolic](https://docs.rs/symbolic/latest/symbolic/).
//!
//! "All" you need to do to implement a new Symbol Client backend is provide
//! an implementation of the [SymbolClient][] trait.

use async_trait::async_trait;
pub use minidump_common::traits::Module;
use std::collections::HashMap;
use std::path::PathBuf;

/// A SymbolClient is the natural pairing to a [Symbol Server][] and helps find
/// symbols locally on your machine or on the internet. A client is expected to
/// provide a few different strategies that are essentially subsets of the "full"
/// [SymbolClient::http_client][] for more constrained environments or testing.
///
/// An implementation is essentially free to do whatever it wants
///
/// [Symbol Server]: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols
#[async_trait]
pub trait SymbolClient {
    /// Gets a "disabled" SymbolClient that looks up no symbols.
    fn no_client() -> Self;

    /// Gets a "test" SymbolClient that has a hardcoded set of symbols.
    fn string_client(args: StringClientArgs) -> Self;

    /// Gets a "minimal" SymbolClient that looks up local symbols by local path.
    fn local_client(args: LocalClientArgs) -> Self;

    /// Gets a "full" SymbolClient that looks up symbols by local path or with urls.
    fn http_client(args: HttpClientArgs) -> Self;

    /// Fill symbol information in `frame` using the instruction address
    /// from `frame`, and the module information from `module`.
    async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizerCallbacks + Send),
    ) -> Result<(), FillSymbolError>;

    /// Tries to use CFI to walk the stack frame of the `walker`
    /// using the symbols of the given Module. Output will be written
    /// using the walker's `set_caller_*` APIs.
    async fn walk_frame(
        &self,
        module: &(dyn Module + Sync),
        walker: &mut (dyn FrameWalkerCallbacks + Send),
    ) -> Option<()>;

    /// Gets the path to a file for a given module (or an Error).
    ///
    /// See [`FileKind`][] for the kinds of files.
    async fn get_file_path(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError>;

    /// Collect various statistics on the symbols.
    ///
    /// Keys are the file name of the module (code_file's file name).
    fn stats(&self) -> HashMap<String, SymbolStats>;
}

/// Arguments for [`SymbolClient::string_client`][].
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct StringClientArgs {
    /// Maps module names to a string containing an entire breakpad .sym file, for tests.
    ///
    /// Defaults to HashMap::new()
    pub breakpad_modules: HashMap<String, String>,
}

/// Arguments for [`SymbolClient::local_client`][].
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct LocalClientArgs {
    /// Paths that the client will check for symbols
    ///
    /// Defaults to Vec::new()
    pub symbol_paths: Vec<PathBuf>,
}

/// Arguments for [`SymbolClient::http_client`][].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct HttpClientArgs {
    /// A list of paths to check for symbol files. Paths are searched in order
    /// until one returns a payload. If none do, then urls are used.
    ///
    /// Defaults to Vec::new()
    pub symbol_paths: Vec<PathBuf>,

    /// A list of "base urls" that should all point to Tecken
    /// servers. urls are queried in order until one returns a payload.
    /// If none do, then it's an error.
    ///
    /// Defaults to Vec::new()
    pub symbol_urls: Vec<String>,

    /// A directory where an on-disk cache should be located.
    /// This should be assumed to be a "temp" directory that another process
    /// you don't control is garbage-collecting old files from (to provide an LRU cache).
    /// The cache is queried before paths and urls (otherwise it wouldn't be much of a cache).
    /// ///
    /// Defaults to `std::env::temp_dir()`
    pub symbol_cache: PathBuf,

    /// A directory where symbol files should be downloaded to
    /// before atomically swapping them into the cache.
    /// Has the same "temp" assumptions as symbols_cache.
    ///
    /// Defaults to `std::env::temp_dir()`
    pub symbol_tmp: PathBuf,

    /// A maximum time limit for a symbol file download. This
    /// is primarily defined to avoid getting stuck on buggy infinite downloads.
    ///
    /// In the event of a timeout, the supplier may still try to parse the truncated
    /// download.
    ///
    /// Defaults to 1000 seconds.
    pub timeout: std::time::Duration,

    /// The maximum number of connections the client should allow.
    pub max_connections: u64,
}

impl Default for HttpClientArgs {
    fn default() -> Self {
        Self {
            symbol_paths: Vec::new(),
            symbol_urls: Vec::new(),
            symbol_cache: std::env::temp_dir(),
            symbol_tmp: std::env::temp_dir(),
            timeout: std::time::Duration::from_secs(1000),
            max_connections: 40,
        }
    }
}

/// A trait for setting symbol information on something like a stack frame.
pub trait FrameSymbolizerCallbacks {
    /// Get the program counter value for this frame.
    fn get_instruction(&self) -> u64;
    /// Set the name, base address, and paramter size of the function in
    // which this frame is executing.
    fn set_function(&mut self, name: &str, base: u64, parameter_size: u32);
    /// Set the source file and (1-based) line number this frame represents.
    fn set_source_file(&mut self, file: &str, line: u32, base: u64);
}

pub trait FrameWalkerCallbacks {
    /// Get the instruction address that we're trying to unwind from.
    fn get_instruction(&self) -> u64;
    /// Check whether the callee has a callee of its own.
    fn has_grand_callee(&self) -> bool;
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

/// An error produced by get_file.
#[derive(Clone, Debug, thiserror::Error)]
pub enum FileError {
    /// The file couldn't be found (or downloaded)
    #[error("file not found")]
    NotFound,
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

/// Statistics on the symbols of a module.
#[derive(Default, Debug)]
#[non_exhaustive]
pub struct SymbolStats {
    /// If the module's symbols were downloaded, this is the url used.
    pub symbol_url: Option<String>,
    /// If the symbols were found and loaded into memory.
    pub loaded_symbols: bool,
    /// If we tried to parse the symbols, but failed.
    pub corrupt_symbols: bool,
}
