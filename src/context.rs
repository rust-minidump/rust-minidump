// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! CPU contexts.

use std::io::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::SeekFrom;
use std::mem;

use minidump_format as md;
use iostuff::*;

/// The CPU-specific context structure.
#[derive(Clone)]
pub enum MinidumpRawContext {
    X86(md::MDRawContextX86),
    PPC(md::MDRawContextPPC),
    PPC64(md::MDRawContextPPC64),
    AMD64(md::MDRawContextAMD64),
    SPARC(md::MDRawContextSPARC),
    ARM(md::MDRawContextARM),
    ARM64(md::MDRawContextARM64),
    MIPS(md::MDRawContextMIPS),
}

/// Information about which registers are valid in a `MinidumpContext`.
#[derive(Clone, Debug, PartialEq)]
pub enum MinidumpContextValidity {
    // All registers are valid.
    All,
    // The registers in this set are valid.
    Some(HashSet<&'static str>),
}


/// CPU context such as register states.
///
/// MinidumpContext carries a CPU-specific MDRawContext structure, which
/// contains CPU context such as register states.  Each thread has its
/// own context, and the exception record, if present, also has its own
/// context.  Note that if the exception record is present, the context it
/// refers to is probably what the user wants to use for the exception
/// thread, instead of that thread's own context.  The exception thread's
/// context (as opposed to the exception record's context) will contain
/// context for the exception handler (which performs minidump generation),
/// and not the context that caused the exception (which is probably what the
/// user wants).
#[derive(Clone)]
pub struct MinidumpContext {
    /// The raw CPU register state.
    pub raw : MinidumpRawContext,
    /// Which registers are valid in `raw`.
    pub valid : MinidumpContextValidity,
}

/// Errors encountered while reading a `MinidumpContext`.
pub enum ContextError {
    /// Failed to read data.
    ReadFailure,
    /// Encountered an unknown CPU context.
    UnknownCPUContext,
}

/// General-purpose registers for x86.
static X86_REGS : [&'static str; 10] =
    ["eip", "esp", "ebp", "ebx", "esi", "edi", "eax", "ecx", "edx", "efl"];

//======================================================
// Implementations

impl MinidumpContext {
    /// Return a MinidumpContext given a `MinidumpRawContext`.
    pub fn from_raw(raw : MinidumpRawContext) -> MinidumpContext {
        MinidumpContext {
            raw: raw,
            valid: MinidumpContextValidity::All,
        }
    }

    /// Read a `MinidumpContext` from a file.
    pub fn read(mut f : &File, location : &md::MDLocationDescriptor) -> Result<MinidumpContext, ContextError> {
        try!(f.seek(SeekFrom::Start(location.rva as u64)).or(Err(ContextError::ReadFailure)));
        let expected_size = location.data_size as usize;
        // Some contexts don't have a context flags word at the beginning,
        // so special-case them by size.
        if expected_size == mem::size_of::<md::MDRawContextAMD64>() {
            let ctx = try!(read::<md::MDRawContextAMD64>(f).or(Err(ContextError::ReadFailure)));
            if ctx.context_flags & md::MD_CONTEXT_CPU_MASK != md::MD_CONTEXT_AMD64 {
                return Err(ContextError::ReadFailure);
            } else {
                return Ok(MinidumpContext::from_raw(MinidumpRawContext::AMD64(ctx)));
            }
        } else if expected_size == mem::size_of::<md::MDRawContextPPC64>() {
            let ctx = try!(read::<md::MDRawContextPPC64>(f).or(Err(ContextError::ReadFailure)));
            if ctx.context_flags & (md::MD_CONTEXT_CPU_MASK as u64) != md::MD_CONTEXT_PPC64 as u64 {
                return Err(ContextError::ReadFailure);
            } else {
                return Ok(MinidumpContext::from_raw(MinidumpRawContext::PPC64(ctx)));
            }
        } else if expected_size == mem::size_of::<md::MDRawContextARM64>() {
            let ctx = try!(read::<md::MDRawContextARM64>(f).or(Err(ContextError::ReadFailure)));
            if ctx.context_flags & (md::MD_CONTEXT_CPU_MASK as u64) != md::MD_CONTEXT_ARM64 as u64 {
                return Err(ContextError::ReadFailure);
            } else {
                return Ok(MinidumpContext::from_raw(MinidumpRawContext::ARM64(ctx)));
            }
        } else {
            // For everything else, read the flags and determine context
            // type from that.
            // TODO: swap
            let flags = try!(read::<u32>(&f).or(Err(ContextError::ReadFailure)));
            try!(f.seek(SeekFrom::Current(-4)).or(Err(ContextError::ReadFailure)));
            let cpu_type = flags & md::MD_CONTEXT_CPU_MASK;
            // TODO: handle dumps with MD_CONTEXT_ARM_OLD
            if let Some(ctx) = match cpu_type {
                md::MD_CONTEXT_X86 => {
                    let ctx = try!(read::<md::MDRawContextX86>(&f).or(Err(ContextError::ReadFailure)));
                    Some(MinidumpRawContext::X86(ctx))
                },
                md::MD_CONTEXT_PPC => {
                    let ctx = try!(read::<md::MDRawContextPPC>(&f).or(Err(ContextError::ReadFailure)));
                    Some(MinidumpRawContext::PPC(ctx))
                },
                md::MD_CONTEXT_SPARC => {
                    let ctx = try!(read::<md::MDRawContextSPARC>(&f).or(Err(ContextError::ReadFailure)));
                    Some(MinidumpRawContext::SPARC(ctx))
                },
                md::MD_CONTEXT_ARM => {
                    let ctx = try!(read::<md::MDRawContextARM>(&f).or(Err(ContextError::ReadFailure)));
                    Some(MinidumpRawContext::ARM(ctx))
                },
                md::MD_CONTEXT_MIPS => {
                    let ctx = try!(read::<md::MDRawContextMIPS>(&f).or(Err(ContextError::ReadFailure)));
                    Some(MinidumpRawContext::MIPS(ctx))
                },
                _ => None,
            } {
                return Ok(MinidumpContext::from_raw(ctx));
            }
            return Err(ContextError::UnknownCPUContext)
        }
    }

    pub fn get_instruction_pointer(&self) -> u64 {
        match self.raw {
            MinidumpRawContext::AMD64(ctx) => ctx.rip,
            MinidumpRawContext::ARM(ctx) => ctx.iregs[md::MD_CONTEXT_ARM_REG_PC as usize] as u64,
            MinidumpRawContext::ARM64(ctx) => ctx.iregs[md::MD_CONTEXT_ARM64_REG_PC as usize],
            MinidumpRawContext::PPC(ctx) => ctx.srr0 as u64,
            MinidumpRawContext::PPC64(ctx) => ctx.srr0,
            MinidumpRawContext::SPARC(ctx) => ctx.pc,
            MinidumpRawContext::X86(ctx) => ctx.eip as u64,
            MinidumpRawContext::MIPS(ctx) => ctx.epc,
        }
    }

    pub fn get_stack_pointer(&self) -> u64 {
        match self.raw {
            MinidumpRawContext::AMD64(ctx) => ctx.rsp,
            MinidumpRawContext::ARM(ctx) => ctx.iregs[md::MD_CONTEXT_ARM_REG_SP as usize] as u64,
            MinidumpRawContext::ARM64(ctx) => ctx.iregs[md::MD_CONTEXT_ARM64_REG_SP as usize],
            MinidumpRawContext::PPC(ctx) => ctx.gpr[md::MD_CONTEXT_PPC_REG_SP as usize] as u64,
            MinidumpRawContext::PPC64(ctx) => ctx.gpr[md::MD_CONTEXT_PPC64_REG_SP as usize],
            MinidumpRawContext::SPARC(ctx) => ctx.g_r[md::MD_CONTEXT_SPARC_REG_SP as usize],
            MinidumpRawContext::X86(ctx) => ctx.esp as u64,
            MinidumpRawContext::MIPS(ctx) => ctx.iregs[md::MD_CONTEXT_MIPS_REG_SP as usize],
        }
    }

    //TODO: want an associated type to set register size per-context!
    pub fn get_register(&self, reg : &str) -> Option<u64> {
        if let MinidumpContextValidity::Some(ref which) = self.valid {
            if !which.contains(reg) {
                return None;
            }
        }
        match self.raw {
            MinidumpRawContext::AMD64(_) => unimplemented!(),
            MinidumpRawContext::ARM(_) => unimplemented!(),
            MinidumpRawContext::ARM64(_) => unimplemented!(),
            MinidumpRawContext::PPC(_) => unimplemented!(),
            MinidumpRawContext::PPC64(_) => unimplemented!(),
            MinidumpRawContext::SPARC(_) => unimplemented!(),
            MinidumpRawContext::X86(raw) => match reg {
                "eip" => Some(raw.eip),
                "esp" => Some(raw.esp),
                "ebp" => Some(raw.ebp),
                "ebx" => Some(raw.ebx),
                "esi" => Some(raw.esi),
                "edi" => Some(raw.edi),
                "eax" => Some(raw.eax),
                "ecx" => Some(raw.ecx),
                "edx" => Some(raw.edx),
                "efl" => Some(raw.eflags),
                _ => None
            }.and_then(|r| Some(r as u64)),
            MinidumpRawContext::MIPS(_) => unimplemented!(),
        }
    }

    pub fn general_purpose_registers(&self) -> &'static [&'static str] {
        match self.raw {
            MinidumpRawContext::AMD64(_) => unimplemented!(),
            MinidumpRawContext::ARM(_) => unimplemented!(),
            MinidumpRawContext::ARM64(_) => unimplemented!(),
            MinidumpRawContext::PPC(_) => unimplemented!(),
            MinidumpRawContext::PPC64(_) => unimplemented!(),
            MinidumpRawContext::SPARC(_) => unimplemented!(),
            MinidumpRawContext::X86(_) => &X86_REGS[..],
            MinidumpRawContext::MIPS(_) => unimplemented!(),
        }
    }


    /// Write a human-readable description of this `MinidumpContext` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        match self.raw {
            MinidumpRawContext::X86(raw) => {
                try!(write!(f, r#"MDRawContextX86
  context_flags                = {:#x}
  dr0                          = {:#x}
  dr1                          = {:#x}
  dr2                          = {:#x}
  dr3                          = {:#x}
  dr6                          = {:#x}
  dr7                          = {:#x}
  float_save.control_word      = {:#x}
  float_save.status_word       = {:#x}
  float_save.tag_word          = {:#x}
  float_save.error_offset      = {:#x}
  float_save.error_selector    = {:#x}
  float_save.data_offset       = {:#x}
  float_save.data_selector     = {:#x}
  float_save.register_area[{:2}] = 0x"#,
                            raw.context_flags,
                            raw.dr0,
                            raw.dr1,
                            raw.dr2,
                            raw.dr3,
                            raw.dr6,
                            raw.dr7,
                            raw.float_save.control_word,
                            raw.float_save.status_word,
                            raw.float_save.tag_word,
                            raw.float_save.error_offset,
                            raw.float_save.error_selector,
                            raw.float_save.data_offset,
                            raw.float_save.data_selector,
                            md::MD_FLOATINGSAVEAREA_X86_REGISTERAREA_SIZE,
                            ));
                try!(write_bytes(f, &raw.float_save.register_area));
                try!(write!(f, "\n"));
                try!(write!(f, r#"  float_save.cr0_npx_state     = {:#x}
  gs                           = {:#x}
  fs                           = {:#x}
  es                           = {:#x}
  ds                           = {:#x}
  edi                          = {:#x}
  esi                          = {:#x}
  ebx                          = {:#x}
  edx                          = {:#x}
  ecx                          = {:#x}
  eax                          = {:#x}
  ebp                          = {:#x}
  eip                          = {:#x}
  cs                           = {:#x}
  eflags                       = {:#x}
  esp                          = {:#x}
  ss                           = {:#x}
  extended_registers[{:3}]      = 0x"#,
                            raw.float_save.cr0_npx_state,
                            raw.gs,
                            raw.fs,
                            raw.es,
                            raw.ds,
                            raw.edi,
                            raw.esi,
                            raw.ebx,
                            raw.edx,
                            raw.ecx,
                            raw.eax,
                            raw.ebp,
                            raw.eip,
                            raw.cs,
                            raw.eflags,
                            raw.esp,
                            raw.ss,
                            md::MD_CONTEXT_X86_EXTENDED_REGISTERS_SIZE,
                            ));
                try!(write_bytes(f, &raw.extended_registers));
                try!(write!(f, "\n\n"));
            },
            MinidumpRawContext::PPC(_raw) => {
                unimplemented!();
            },
            MinidumpRawContext::PPC64(_raw) => {
                unimplemented!();
            },
            MinidumpRawContext::AMD64(raw) => {
                try!(write!(f, r#"MDRawContextAMD64
  p1_home       = {:#x}
  p2_home       = {:#x}
  p3_home       = {:#x}
  p4_home       = {:#x}
  p5_home       = {:#x}
  p6_home       = {:#x}
  context_flags = {:#x}
  mx_csr        = {:#x}
  cs            = {:#x}
  ds            = {:#x}
  es            = {:#x}
  fs            = {:#x}
  gs            = {:#x}
  ss            = {:#x}
  eflags        = {:#x}
  dr0           = {:#x}
  dr1           = {:#x}
  dr2           = {:#x}
  dr3           = {:#x}
  dr6           = {:#x}
  dr7           = {:#x}
  rax           = {:#x}
  rcx           = {:#x}
  rdx           = {:#x}
  rbx           = {:#x}
  rsp           = {:#x}
  rbp           = {:#x}
  rsi           = {:#x}
  rdi           = {:#x}
  r8            = {:#x}
  r9            = {:#x}
  r10           = {:#x}
  r11           = {:#x}
  r12           = {:#x}
  r13           = {:#x}
  r14           = {:#x}
  r15           = {:#x}
  rip           = {:#x}

"#,
                            raw.p1_home,
                            raw.p2_home,
                            raw.p3_home,
                            raw.p4_home,
                            raw.p5_home,
                            raw.p6_home,
                            raw.context_flags,
                            raw.mx_csr,
                            raw.cs,
                            raw.ds,
                            raw.es,
                            raw.fs,
                            raw.gs,
                            raw.ss,
                            raw.eflags,
                            raw.dr0,
                            raw.dr1,
                            raw.dr2,
                            raw.dr3,
                            raw.dr6,
                            raw.dr7,
                            raw.rax,
                            raw.rcx,
                            raw.rdx,
                            raw.rbx,
                            raw.rsp,
                            raw.rbp,
                            raw.rsi,
                            raw.rdi,
                            raw.r8,
                            raw.r9,
                            raw.r10,
                            raw.r11,
                            raw.r12,
                            raw.r13,
                            raw.r14,
                            raw.r15,
                            raw.rip,
                            ));
            },
            MinidumpRawContext::SPARC(_raw) => {
                unimplemented!();
            },
            MinidumpRawContext::ARM(raw) => {
                try!(write!(f, r#"MDRawContextARM
  context_flags       = {:#x}
"#, raw.context_flags));
                for (i, reg) in raw.iregs.iter().enumerate() {
                    try!(writeln!(f, "  iregs[{:2}]            = {:#x}", i, reg));
                }
                try!(write!(f, r#"  cpsr                = {:#x}
  float_save.fpscr     = {:#x}
"#,
                            raw.cpsr,
                            raw.float_save.fpscr));
                for (i, reg) in raw.float_save.regs.iter().enumerate() {
                    try!(writeln!(f, "  float_save.regs[{:2}] = {:#x}", i, reg));
                }
                for (i, reg) in raw.float_save.extra.iter().enumerate() {
                    try!(writeln!(f, "  float_save.extra[{:2}] = {:#x}", i, reg));
                }
            },
            MinidumpRawContext::ARM64(_raw) => {
                unimplemented!();
            },
            MinidumpRawContext::MIPS(_raw) => {
                unimplemented!();
            },
        }
        Ok(())
    }
}
