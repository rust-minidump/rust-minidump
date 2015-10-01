// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! The state of a process.

use std::io::prelude::*;
use std::io;

use chrono::*;
use system_info::SystemInfo;

/// The state of a process as recorded by a `Minidump`.
pub struct ProcessState {
    /// When the minidump was written.
    pub time : DateTime<UTC>,
    /// When the process started, if available
    pub process_create_time : Option<DateTime<UTC>>,
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
    /// Information about the system on which the minidump was written.
    pub system_info : SystemInfo,
    // modules
    // modules_without_symbols
    // modules_with_corrupt_symbols
    // exploitability
}

impl ProcessState {
    /// `true` if the minidump was written in response to a process crash.
    pub fn crashed(&self) -> bool {
        self.crash_reason.is_some() && self.crash_address.is_some()
    }
    /// Write a human-readable description of the process state to `f`.
    ///
    /// This is very verbose, it implements the output format used by
    /// minidump_stackwalk.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(writeln!(f, "Operating system: {}", self.system_info.os.long_name()));
        if let Some(ref ver) = self.system_info.os_version {
            try!(writeln!(f, "                  {}", ver));
        }
        try!(writeln!(f, "CPU: {}", self.system_info.cpu));
        if let Some(ref info) = self.system_info.cpu_info {
            try!(writeln!(f, "     {}", info));
        }
        try!(writeln!(f, "     {} CPU{}", self.system_info.cpu_count,
                      if self.system_info.cpu_count > 1 { "s" } else { "" }));
        if let (&Some(ref reason), &Some(ref address)) = (&self.crash_reason,
                                                          &self.crash_address) {
            try!(writeln!(f, "Crash reason: {}
Crash address: {:#x}
",
                          reason, address));
        } else {
            try!(writeln!(f, "No crash"));
        }
        if let Some(ref assertion) = self.assertion {
            try!(writeln!(f, "Assertion: {}", assertion));
        }
        if let Some(ref time) = self.process_create_time {
            let uptime = self.time - *time;
            try!(writeln!(f, "Process uptime: {} seconds",
                          uptime.num_seconds()));
        } else {
            try!(writeln!(f, "Process uptime: not available"));
        }
        Ok(())
    }
}
