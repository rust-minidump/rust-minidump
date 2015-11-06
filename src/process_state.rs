// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! The state of a process.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::prelude::*;
use std::io;

use breakpad_symbols::FrameSymbolizer;
use chrono::*;
use minidump::*;
use system_info::SystemInfo;

/// Indicates how well the instruction pointer derived during
/// stack walking is trusted. Since the stack walker can resort to
/// stack scanning, it can wind up with dubious frames.
#[derive(Debug, PartialEq)]
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
    pub module : Option<MinidumpModule>,

    /// The function name, may be omitted if debug symbols are not available.
    pub function_name : Option<String>,

    /// The start address of the function, may be omitted if debug symbols
    /// are not available.
    pub function_base : Option<u64>,

    /// The source file name, may be omitted if debug symbols are not available.
    pub source_file_name : Option<String>,

    /// The (1-based) source line number, may be omitted if debug symbols are
    /// not available.
    pub source_line : Option<u32>,

    /// The start address of the source line, may be omitted if debug symbols
    /// are not available.
    pub source_line_base : Option<u64>,

    /// Amount of trust the stack walker has in the instruction pointer
    /// of this frame.
    pub trust : FrameTrust,

    /// The CPU context containing register state for this frame.
    pub context : MinidumpContext,
}

/// Information about the results of unwinding a thread's stack.
#[derive(Debug, PartialEq)]
pub enum CallStackInfo {
    /// Everything went great.
    Ok,
    /// No `MinidumpContext` was provided, couldn't do anything.
    MissingContext,
    /// No stack memory was provided, couldn't unwind past the top frame.
    MissingMemory,
    /// The CPU type is unsupported.
    UnsupportedCPU,
    /// This thread wrote the minidump, it was skipped.
    DumpThreadSkipped,
}

/// A stack of `StackFrame`s produced as a result of unwinding a thread.
pub struct CallStack {
    /// The stack frames.
    /// By convention, the stack frame at index 0 is the innermost callee frame,
    /// and the frame at the highest index in a call stack is the outermost
    /// caller.
    pub frames : Vec<StackFrame>,
    /// Information about this `CallStack`.
    pub info : CallStackInfo,
}

/// The state of a process as recorded by a `Minidump`.
pub struct ProcessState {
    /// When the minidump was written.
    pub time : DateTime<UTC>,
    /// When the process started, if available
    pub process_create_time : Option<DateTime<UTC>>,
    /// If the process crashed, a `CrashReason` describing the crash reason.
    pub crash_reason : Option<CrashReason>,
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
    /// The modules that were loaded into the process represented by the
    /// `ProcessState`.
    pub modules : MinidumpModuleList,
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
    /// Create a `StackFrame` from a `MinidumpContext`.
    pub fn from_context(context : MinidumpContext,
                        trust : FrameTrust) -> StackFrame {
        StackFrame {
            instruction: context.get_instruction_pointer(),
            module: None,
            function_name: None,
            function_base: None,
            source_file_name: None,
            source_line: None,
            source_line_base: None,
            trust: trust,
            context: context,
        }
    }

    /// Return the actual return address, as saved on the stack or in a
    /// register. See the comments for `StackFrame::instruction` for details.
    pub fn return_address(&self) -> u64 {
        self.instruction
    }
}

impl FrameSymbolizer for StackFrame {
    fn get_instruction(&self) -> u64 {
        self.module.as_ref().map(|m| self.instruction - m.base_address())
            .unwrap_or(self.instruction)
    }
    fn set_function(&mut self, name : &str, base : u64) {
        self.function_name = Some(String::from(name));
        self.function_base = Some(base);
    }
    fn set_source_file(&mut self, file : &str, line : u32) {
        self.source_file_name = Some(String::from(file));
        self.source_line = Some(line);
    }
}

fn basename(f : &str) -> &str {
    match f.rfind(|c| c == '/' || c == '\\') {
        None => f,
        Some(index) => &f[(index+1)..],
    }
}

fn print_registers<T : Write>(f : &mut T,
                              ctx : &MinidumpContext) -> io::Result<()> {
    let registers : Cow<HashSet<&str>> = match ctx.valid {
        MinidumpContextValidity::All => {
            let gpr = ctx.general_purpose_registers();
            let set : HashSet<&str>  = gpr.iter().cloned().collect();
            Cow::Owned(set)
        },
        MinidumpContextValidity::Some(ref which) => Cow::Borrowed(which),
    };

    // Iterate over registers in a known order.
    let mut output = String::new();
    for reg in ctx.general_purpose_registers() {
        if registers.contains(reg) {
            let reg_val = ctx.get_register(reg).and_then(|v| Some(format!("{:#010x}", v))).unwrap_or(String::from("??????????"));
            let next = format!("   {} = {}", reg, reg_val);
            if output.chars().count() + next.chars().count() > 80 {
                // Flush the buffer.
                try!(writeln!(f, " {}", output));
                output.truncate(0);
            }
            output.push_str(&next);
        }
    }
    if !output.is_empty() {
        try!(writeln!(f, " {}", output));
    }
    Ok(())
}

impl CallStack {
    /// Create a `CallStack` with `info` and no frames.
    pub fn with_info(info : CallStackInfo) -> CallStack {
        CallStack {
            info: info,
            frames: vec!(),
        }
    }

    /// Write a human-readable description of the call stack to `f`.
    ///
    /// This is very verbose, it implements the output format used by
    /// minidump_stackwalk.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        if self.frames.len() == 0 {
            try!(writeln!(f, "<no frames>"));
        }
        for (i, frame) in self.frames.iter().enumerate() {
            let addr = frame.return_address();
            try!(write!(f, "{:2}  ", i));
            if let Some(ref module) = frame.module {
                try!(write!(f, "{}", basename(&module.code_file())));
                if let (&Some(ref function),
                        &Some(ref function_base)) = (&frame.function_name,
                                                     &frame.function_base) {
                    try!(write!(f, "!{}", function));
                    if let (&Some(ref source_file),
                            &Some(ref source_line),
                            &Some(ref source_line_base)) = (&frame.source_file_name,
                                                            &frame.source_line,
                                                            &frame.source_line_base) {
                        try!(write!(f, " [{} : {} + {:#x}]",
                                    basename(&source_file),
                                    source_line,
                                    addr - source_line_base));
                    } else {
                        try!(write!(f, " + {:#x}", addr - function_base));
                    }
                } else {
                    try!(write!(f, " + {:#x}", addr - module.base_address()));
                }
            } else {
                try!(writeln!(f, "{:#x}", addr));
            }
            try!(writeln!(f, ""));
            try!(print_registers(f, &frame.context));
            try!(writeln!(f, "    Found by: {}", frame.trust.description()));
        }
        Ok(())
    }
}

fn eq_some<T : PartialEq>(opt : Option<T>, val : T) -> bool {
    match opt {
        Some(v) => v == val,
        None => false,
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
        try!(writeln!(f, ""));

        if let (&Some(ref reason), &Some(ref address)) = (&self.crash_reason,
                                                          &self.crash_address) {
            try!(write!(f, "Crash reason:  {}
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
        try!(writeln!(f, ""));

        if let Some(requesting_thread) = self.requesting_thread {
            try!(writeln!(f, "Thread {} ({})",
                          requesting_thread,
                          if self.crashed() { "crashed" } else { "requested dump, did not crash" }));
            try!(self.threads[requesting_thread].print(f));
            try!(writeln!(f, ""));
        }
        for (i, stack) in self.threads.iter().enumerate() {
            if eq_some(self.requesting_thread, i) {
                // Don't print the requesting thread again,
                continue;
            }
            if stack.info == CallStackInfo::DumpThreadSkipped {
                continue;
            }
            try!(writeln!(f, "Thread {}", i));
            try!(stack.print(f));
        }
        try!(write!(f, "
Loaded modules:
"));
        let main_address = self.modules.main_module().and_then(|m| Some(m.base_address()));
        for module in self.modules.by_addr() {
            // TODO: missing symbols, corrupt symbols
            try!(write!(f, "{:#010x} - {:#010x}  {}  {}",
                        module.base_address(),
                        module.base_address() + module.size() - 1,
                        basename(&module.code_file()),
                        module.version().unwrap_or(Cow::Borrowed("???"))));
            if eq_some(main_address, module.base_address()) {
                try!(write!(f, "  (main)"));
            }
            try!(writeln!(f, ""));
        }
        Ok(())
    }
}
