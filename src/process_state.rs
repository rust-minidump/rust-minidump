// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! The state of a process.

use std::io::prelude::*;
use std::io;

use chrono::*;
use system_info::SystemInfo;

/// Indicates how well the instruction pointer derived during
/// stack walking is trusted. Since the stack walker can resort to
/// stack scanning, it can wind up with dubious frames.
pub enum FrameTrust {
    /// Unknown
    None,
    /// Scanned the stack, found this.
    Scan,
    /// Found while scanning stack using call frame info.
    CfiScan,
    /// Derived from frame pointer.
    FramePointer,
    /// Derived from call frame info.
    CallFrameInfo,
    /// Explicitly provided by some external stack walker.
    PreWalked,
    /// Given as instruction pointer in a context.
    Context,
}

/// A single stack frame produced from unwinding a thread's stack.
pub struct StackFrame {
    // The program counter location as an absolute virtual address.
    //
    // - For the innermost called frame in a stack, this will be an exact
    //   program counter or instruction pointer value.
    //
    // - For all other frames, this address is within the instruction that
    //   caused execution to branch to this frame's callee (although it may
    //   not point to the exact beginning of that instruction). This ensures
    //   that, when we look up the source code location for this frame, we
    //   get the source location of the call, not of the point at which
    //   control will resume when the call returns, which may be on the next
    //   line. (If the compiler knows the callee never returns, it may even
    //   place the call instruction at the very end of the caller's machine
    //   code, such that the "return address" (which will never be used)
    //   immediately after the call instruction is in an entirely different
    //   function, perhaps even from a different source file.)
    //
    // On some architectures, the return address as saved on the stack or in
    // a register is fine for looking up the point of the call. On others, it
    // requires adjustment. ReturnAddress returns the address as saved by the
    // machine.
    pub instruction : u64,

    // The module in which the instruction resides.
    //pub module : Option<Module>,

    /// The function name, may be omitted if debug symbols are not available.
    pub function_name : Option<String>,

    /// The start address of the function, may be omitted if debug symbols
    /// are not available.
    pub function_base : Option<u64>,

    /// The source file name, may be omitted if debug symbols are not available.
    pub source_file_name : Option<String>,

    /// The (1-based) source line number, may be omitted if debug symbols are
    /// not available.
    pub source_line : Option<usize>,

    /// The start address of the source line, may be omitted if debug symbols
    /// are not available.
    pub source_line_base : Option<u64>,

    /// Amount of trust the stack walker has in the instruction pointer
    /// of this frame.
    pub trust : FrameTrust,
}

/// A stack of `StackFrame`s produced as a result of unwinding a thread.
pub struct CallStack {
    /// The stack frames.
    /// By convention, the stack frame at index 0 is the innermost callee frame,
    /// and the frame at the highest index in a call stack is the outermost
    /// caller.
    pub frames : Vec<StackFrame>,
}

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
    /// The index of the thread that requested a dump be written.
    /// If a dump was produced as a result of a crash, this
    /// will point to the thread that crashed.  If the dump was produced as
    /// by user code without crashing, and the dump contains extended Breakpad
    /// information, this will point to the thread that requested the dump.
    /// If the dump was not produced as a result of an exception and no
    /// extended Breakpad information is present, this field will be
    /// `None`.
    pub requesting_thread : Option<usize>,
    /// Stacks for each thread (except possibly the exception handler
    /// thread) at the time of the crash.
    pub threads : Vec<CallStack>,
    // TODO:
    // thread_memory_regions
    /// Information about the system on which the minidump was written.
    pub system_info : SystemInfo,
    // modules
    // modules_without_symbols
    // modules_with_corrupt_symbols
    // exploitability
}

impl FrameTrust {
    /// Return a string describing how a stack frame was found
    /// by the stackwalker.
    pub fn description(&self) -> &'static str {
        match *self {
            FrameTrust::Context => "given as instruction pointer in context",
            FrameTrust::PreWalked => "recovered by external stack walker",
            FrameTrust::CallFrameInfo => "call frame info",
            FrameTrust::CfiScan => "call frame info with scanning",
            FrameTrust::FramePointer => "previous frame's frame pointer",
            FrameTrust::Scan => "stack scanning",
            FrameTrust::None => "unknown",
        }
    }
}

impl StackFrame {
    /// Return the actual return address, as saved on the stack or in a
    /// register. See the comments for `StackFrame::instruction` for details.
    pub fn return_address(&self) -> u64 {
        self.instruction
    }
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
