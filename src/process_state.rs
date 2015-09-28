//! The state of a process.

use std::io::prelude::*;
use std::io::Result;

use chrono::*;

/// The state of a process as recorded by a `Minidump`.
pub struct ProcessState {
    /// When the minidump was written.
    pub time : DateTime<UTC>,
    /// When the process started.
    pub process_create_time : DateTime<UTC>,
    /// `true` if the minidump was written in response to a process crash.
    pub crashed : bool,
    /// If the process crashed, a `String` describing the crash reason.
    ///
    /// This is OS- and possibly CPU-specific.
    /// For example, "EXCEPTION_ACCESS_VIOLATION" (Windows),
    /// "EXC_BAD_ACCESS / KERN_INVALID_ADDRESS" (Mac OS X), "SIGSEGV"
    /// (other Unix).
    pub crash_reason : Option<String>,
    /// The memory address implicated in the crash.
    ///
    /// If the process crashed, and if the crash reason implicates memory,
    /// this is the memory address that caused the crash. For data access
    /// errors this will be the data address that caused the fault. For code
    /// errors, this will be the address of the instruction that caused the
    /// fault.
    pub crash_address : Option<u64>,
    /// A string describing an assertion that was hit, if present.
    pub assertion : Option<String>,
    // TODO:
    // requesting_thread
    // threads
    // thread_memory_regions
    // system_info
    // modules
    // modules_without_symbols
    // modules_with_corrupt_symbols
    // exploitability
}

impl ProcessState {
    /// Write a human-readable description of the process state to `_f`.
    ///
    /// This is very verbose, it implements the output format used by
    /// minidump_stackwalk.
    pub fn print<T : Write>(&self, _f : &mut T) -> Result<()> {
        Ok(())
    }
}
