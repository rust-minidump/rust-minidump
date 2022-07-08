//! This module defines the interface between minidump-processor and its [Symbolizer][].
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
//!
//! And the following concrete types:
//!
//! * [Symbolizer][] - the main interface of the symbolizer, implementing [SymbolProvider][].
//!     * Wraps the [SymbolSupplier][] implementation that minidump-processor selects.
//!     * Queries the [SymbolSupplier] and manages the SymbolFiles however it pleases.
//! * [SymbolStats][] - debug statistic output.
//! * [FillSymbolError][] - possible errors for `fill_symbol`.
//!     * While this *is* handled by minidump-processor, it doesn't actually look at the value. It's
//!       just there to be An Error Type for the sake of API design.
//!
//!
//!
//! # Example
//!
//! ```rust
//! use breakpad_symbols::http_symbol_supplier;
//! use minidump::Minidump;
//! use minidump_processor::{ProcessorOptions, Symbolizer};
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

use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;
use minidump::Module;

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

/// A trait for setting symbol information on something like a stack frame.
pub trait FrameSymbolizer {
    /// Get the program counter value for this frame.
    fn get_instruction(&self) -> u64;
    /// Set the name, base address, and parameter size of the function in
    // which this frame is executing.
    fn set_function(&mut self, name: &str, base: u64, parameter_size: u32);
    /// Set the source file and (1-based) line number this frame represents.
    fn set_source_file(&mut self, file: &str, line: u32, base: u64);
}

pub trait FrameWalker {
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

#[derive(Clone, Debug, thiserror::Error)]
pub enum FileError {
    #[error("file not found")]
    NotFound,
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
