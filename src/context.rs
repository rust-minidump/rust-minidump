// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! CPU contexts.

use scroll::{self, Pread};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::mem;

use iostuff::*;
use minidump_common::format as md;
use minidump_common::format::ContextFlagsCpu;

/// The CPU-specific context structure.
#[derive(Clone)]
pub enum MinidumpRawContext {
    X86(md::CONTEXT_X86),
    PPC(md::CONTEXT_PPC),
    PPC64(md::CONTEXT_PPC64),
    AMD64(md::CONTEXT_AMD64),
    SPARC(md::CONTEXT_SPARC),
    ARM(md::CONTEXT_ARM),
    ARM64(md::CONTEXT_ARM64),
    OLDARM64(md::CONTEXT_ARM64_OLD),
    MIPS(md::CONTEXT_MIPS),
}

/// Generic over the specifics of a CPU context.
pub trait CPUContext {
    /// The word size of general-purpose registers in the context.
    type Register: fmt::LowerHex;

    /// Get a register value if it is valid.
    ///
    /// Get the value of the register named `reg` from this CPU context
    /// if `valid` indicates that it has a valid value, otherwise return
    /// `None`.
    fn get_register(&self, reg: &str, valid: &MinidumpContextValidity) -> Option<Self::Register> {
        if let &MinidumpContextValidity::Some(ref which) = valid {
            if !which.contains(reg) {
                return None;
            }
        }
        Some(self.get_register_always(reg))
    }

    /// Return a String containing the value of `reg` formatted to its natural width.
    fn format_register(&self, reg: &str) -> String {
        format!(
            "0x{:01$x}",
            self.get_register_always(reg),
            mem::size_of::<Self::Register>() * 2
        )
    }

    /// Get a register value regardless of whether it is valid.
    fn get_register_always(&self, reg: &str) -> Self::Register;
}

impl CPUContext for md::CONTEXT_X86 {
    type Register = u32;

    fn get_register_always(&self, reg: &str) -> u32 {
        match reg {
            "eip" => self.eip,
            "esp" => self.esp,
            "ebp" => self.ebp,
            "ebx" => self.ebx,
            "esi" => self.esi,
            "edi" => self.edi,
            "eax" => self.eax,
            "ecx" => self.ecx,
            "edx" => self.edx,
            "efl" => self.eflags,
            _ => unreachable!("Invalid x86 register!"),
        }
    }
}

impl CPUContext for md::CONTEXT_AMD64 {
    type Register = u64;

    fn get_register_always(&self, reg: &str) -> u64 {
        match reg {
            "rax" => self.rax,
            "rdx" => self.rdx,
            "rcx" => self.rcx,
            "rbx" => self.rbx,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "rbp" => self.rbp,
            "rsp" => self.rsp,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            "rip" => self.rip,
            _ => unreachable!("Invalid x86-64 register!"),
        }
    }
}

impl CPUContext for md::CONTEXT_ARM64_OLD {
    type Register = u64;

    fn get_register_always(&self, reg: &str) -> u64 {
        match reg {
            "x0" => self.iregs[0],
            "x1" => self.iregs[1],
            "x2" => self.iregs[2],
            "x3" => self.iregs[3],
            "x4" => self.iregs[4],
            "x5" => self.iregs[5],
            "x6" => self.iregs[6],
            "x7" => self.iregs[7],
            "x8" => self.iregs[8],
            "x9" => self.iregs[9],
            "x10" => self.iregs[10],
            "x11" => self.iregs[11],
            "x12" => self.iregs[12],
            "x13" => self.iregs[13],
            "x14" => self.iregs[14],
            "x15" => self.iregs[15],
            "x16" => self.iregs[16],
            "x17" => self.iregs[17],
            "x18" => self.iregs[18],
            "x19" => self.iregs[19],
            "x20" => self.iregs[20],
            "x21" => self.iregs[21],
            "x22" => self.iregs[22],
            "x23" => self.iregs[23],
            "x24" => self.iregs[24],
            "x25" => self.iregs[25],
            "x26" => self.iregs[26],
            "x27" => self.iregs[27],
            "x28" => self.iregs[28],
            "x29" => self.iregs[29],
            "x30" => self.iregs[30],
            "x31" => self.iregs[31],
            "pc" => self.pc,
            "fp" => self.iregs[md::Arm64RegisterNumbers::FramePointer as usize],
            "sp" => self.iregs[md::Arm64RegisterNumbers::StackPointer as usize],
            _ => unreachable!("Invalid aarch64 register!"),
        }
    }
}

impl CPUContext for md::CONTEXT_ARM64 {
    type Register = u64;

    fn get_register_always(&self, reg: &str) -> u64 {
        match reg {
            "x0" => self.iregs[0],
            "x1" => self.iregs[1],
            "x2" => self.iregs[2],
            "x3" => self.iregs[3],
            "x4" => self.iregs[4],
            "x5" => self.iregs[5],
            "x6" => self.iregs[6],
            "x7" => self.iregs[7],
            "x8" => self.iregs[8],
            "x9" => self.iregs[9],
            "x10" => self.iregs[10],
            "x11" => self.iregs[11],
            "x12" => self.iregs[12],
            "x13" => self.iregs[13],
            "x14" => self.iregs[14],
            "x15" => self.iregs[15],
            "x16" => self.iregs[16],
            "x17" => self.iregs[17],
            "x18" => self.iregs[18],
            "x19" => self.iregs[19],
            "x20" => self.iregs[20],
            "x21" => self.iregs[21],
            "x22" => self.iregs[22],
            "x23" => self.iregs[23],
            "x24" => self.iregs[24],
            "x25" => self.iregs[25],
            "x26" => self.iregs[26],
            "x27" => self.iregs[27],
            "x28" => self.iregs[28],
            "x29" => self.iregs[29],
            "x30" => self.iregs[30],
            "x31" => self.iregs[31],
            "pc" => self.pc,
            "fp" => self.iregs[md::Arm64RegisterNumbers::FramePointer as usize],
            "sp" => self.iregs[md::Arm64RegisterNumbers::StackPointer as usize],
            _ => unreachable!("Invalid aarch64 register!"),
        }
    }
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
    pub raw: MinidumpRawContext,
    /// Which registers are valid in `raw`.
    pub valid: MinidumpContextValidity,
}

/// Errors encountered while reading a `MinidumpContext`.
pub enum ContextError {
    /// Failed to read data.
    ReadFailure,
    /// Encountered an unknown CPU context.
    UnknownCPUContext,
}

/// General-purpose registers for x86.
static X86_REGS: [&str; 10] = [
    "eip", "esp", "ebp", "ebx", "esi", "edi", "eax", "ecx", "edx", "efl",
];

/// General-purpose registers for x86-64.
static X86_64_REGS: [&str; 17] = [
    "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "rip",
];

/// General-purpose registers for aarch64.
static ARM64_REGS: [&str; 33] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "x31", "pc",
];
//======================================================
// Implementations

impl MinidumpContext {
    /// Return a MinidumpContext given a `MinidumpRawContext`.
    pub fn from_raw(raw: MinidumpRawContext) -> MinidumpContext {
        MinidumpContext {
            raw,
            valid: MinidumpContextValidity::All,
        }
    }

    /// Read a `MinidumpContext` from `bytes`.
    pub fn read(bytes: &[u8], endian: scroll::Endian) -> Result<MinidumpContext, ContextError> {
        // Some contexts don't have a context flags word at the beginning,
        // so special-case them by size.
        let mut offset = 0;
        if bytes.len() == mem::size_of::<md::CONTEXT_AMD64>() {
            let ctx: md::CONTEXT_AMD64 = bytes
                .gread_with(&mut offset, endian)
                .or(Err(ContextError::ReadFailure))?;
            if ContextFlagsCpu::from_flags(ctx.context_flags) != ContextFlagsCpu::CONTEXT_AMD64 {
                return Err(ContextError::ReadFailure);
            } else {
                return Ok(MinidumpContext::from_raw(MinidumpRawContext::AMD64(ctx)));
            }
        } else if bytes.len() == mem::size_of::<md::CONTEXT_PPC64>() {
            let ctx: md::CONTEXT_PPC64 = bytes
                .gread_with(&mut offset, endian)
                .or(Err(ContextError::ReadFailure))?;
            if ContextFlagsCpu::from_flags(ctx.context_flags as u32)
                != ContextFlagsCpu::CONTEXT_PPC64
            {
                return Err(ContextError::ReadFailure);
            } else {
                return Ok(MinidumpContext::from_raw(MinidumpRawContext::PPC64(ctx)));
            }
        } else if bytes.len() == mem::size_of::<md::CONTEXT_ARM64_OLD>() {
            let ctx: md::CONTEXT_ARM64_OLD = bytes
                .gread_with(&mut offset, endian)
                .or(Err(ContextError::ReadFailure))?;
            if ContextFlagsCpu::from_flags(ctx.context_flags as u32)
                != ContextFlagsCpu::CONTEXT_ARM64_OLD
            {
                return Err(ContextError::ReadFailure);
            } else {
                return Ok(MinidumpContext::from_raw(MinidumpRawContext::OLDARM64(ctx)));
            }
        }

        // For everything else, read the flags and determine context
        // type from that.
        let flags: u32 = bytes
            .gread_with(&mut offset, endian)
            .or(Err(ContextError::ReadFailure))?;
        // Seek back, the flags are also part of the RawContext structs.
        offset = 0;
        // TODO: handle dumps with MD_CONTEXT_ARM_OLD
        match ContextFlagsCpu::from_flags(flags) {
            ContextFlagsCpu::CONTEXT_X86 => {
                let ctx: md::CONTEXT_X86 = bytes
                    .gread_with(&mut offset, endian)
                    .or(Err(ContextError::ReadFailure))?;
                Ok(MinidumpContext::from_raw(MinidumpRawContext::X86(ctx)))
            }
            ContextFlagsCpu::CONTEXT_PPC => {
                let ctx: md::CONTEXT_PPC = bytes
                    .gread_with(&mut offset, endian)
                    .or(Err(ContextError::ReadFailure))?;
                Ok(MinidumpContext::from_raw(MinidumpRawContext::PPC(ctx)))
            }
            ContextFlagsCpu::CONTEXT_SPARC => {
                let ctx: md::CONTEXT_SPARC = bytes
                    .gread_with(&mut offset, endian)
                    .or(Err(ContextError::ReadFailure))?;
                Ok(MinidumpContext::from_raw(MinidumpRawContext::SPARC(ctx)))
            }
            ContextFlagsCpu::CONTEXT_ARM => {
                let ctx: md::CONTEXT_ARM = bytes
                    .gread_with(&mut offset, endian)
                    .or(Err(ContextError::ReadFailure))?;
                Ok(MinidumpContext::from_raw(MinidumpRawContext::ARM(ctx)))
            }
            ContextFlagsCpu::CONTEXT_MIPS => {
                let ctx: md::CONTEXT_MIPS = bytes
                    .gread_with(&mut offset, endian)
                    .or(Err(ContextError::ReadFailure))?;
                Ok(MinidumpContext::from_raw(MinidumpRawContext::MIPS(ctx)))
            }
            ContextFlagsCpu::CONTEXT_ARM64 => {
                let ctx: md::CONTEXT_ARM64 = bytes
                    .gread_with(&mut offset, endian)
                    .or(Err(ContextError::ReadFailure))?;
                Ok(MinidumpContext::from_raw(MinidumpRawContext::ARM64(ctx)))
            }
            _ => Err(ContextError::UnknownCPUContext),
        }
    }

    pub fn get_instruction_pointer(&self) -> u64 {
        match self.raw {
            MinidumpRawContext::AMD64(ref ctx) => ctx.rip,
            MinidumpRawContext::ARM(ref ctx) => {
                ctx.iregs[md::ArmRegisterNumbers::ProgramCounter as usize] as u64
            }
            MinidumpRawContext::ARM64(ref ctx) => ctx.pc,
            MinidumpRawContext::OLDARM64(ref ctx) => ctx.pc,
            MinidumpRawContext::PPC(ref ctx) => ctx.srr0 as u64,
            MinidumpRawContext::PPC64(ref ctx) => ctx.srr0,
            MinidumpRawContext::SPARC(ref ctx) => ctx.pc,
            MinidumpRawContext::X86(ref ctx) => ctx.eip as u64,
            MinidumpRawContext::MIPS(ref ctx) => ctx.epc,
        }
    }

    pub fn get_stack_pointer(&self) -> u64 {
        match self.raw {
            MinidumpRawContext::AMD64(ref ctx) => ctx.rsp,
            MinidumpRawContext::ARM(ref ctx) => {
                ctx.iregs[md::ArmRegisterNumbers::StackPointer as usize] as u64
            }
            MinidumpRawContext::ARM64(ref ctx) => {
                ctx.iregs[md::Arm64RegisterNumbers::StackPointer as usize]
            }
            MinidumpRawContext::OLDARM64(ref ctx) => {
                ctx.iregs[md::Arm64RegisterNumbers::StackPointer as usize]
            }
            MinidumpRawContext::PPC(ref ctx) => {
                ctx.gpr[md::PpcRegisterNumbers::StackPointer as usize] as u64
            }
            MinidumpRawContext::PPC64(ref ctx) => {
                ctx.gpr[md::Ppc64RegisterNumbers::StackPointer as usize]
            }
            MinidumpRawContext::SPARC(ref ctx) => {
                ctx.g_r[md::SparcRegisterNumbers::StackPointer as usize]
            }
            MinidumpRawContext::X86(ref ctx) => ctx.esp as u64,
            MinidumpRawContext::MIPS(ref ctx) => {
                ctx.iregs[md::MipsRegisterNumbers::StackPointer as usize]
            }
        }
    }

    pub fn format_register(&self, reg: &str) -> String {
        match self.raw {
            MinidumpRawContext::AMD64(ref ctx) => ctx.format_register(reg),
            MinidumpRawContext::ARM(_) => unimplemented!(),
            MinidumpRawContext::ARM64(ref ctx) => ctx.format_register(reg),
            MinidumpRawContext::OLDARM64(ref ctx) => ctx.format_register(reg),
            MinidumpRawContext::PPC(_) => unimplemented!(),
            MinidumpRawContext::PPC64(_) => unimplemented!(),
            MinidumpRawContext::SPARC(_) => unimplemented!(),
            MinidumpRawContext::X86(ref ctx) => ctx.format_register(reg),
            MinidumpRawContext::MIPS(_) => unimplemented!(),
        }
    }

    pub fn general_purpose_registers(&self) -> &'static [&'static str] {
        match self.raw {
            MinidumpRawContext::AMD64(_) => &X86_64_REGS[..],
            MinidumpRawContext::ARM(_) => unimplemented!(),
            MinidumpRawContext::ARM64(_) => &ARM64_REGS[..],
            MinidumpRawContext::OLDARM64(_) => &ARM64_REGS[..],
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
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        match self.raw {
            MinidumpRawContext::X86(ref raw) => {
                write!(
                    f,
                    r#"CONTEXT_X86
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
                    raw.float_save.register_area.len(),
                )?;
                write_bytes(f, &raw.float_save.register_area)?;
                writeln!(f)?;
                write!(
                    f,
                    r#"  float_save.cr0_npx_state     = {:#x}
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
                    raw.extended_registers.len(),
                )?;
                write_bytes(f, &raw.extended_registers)?;
                write!(f, "\n\n")?;
            }
            MinidumpRawContext::PPC(_) => {
                unimplemented!();
            }
            MinidumpRawContext::PPC64(_) => {
                unimplemented!();
            }
            MinidumpRawContext::AMD64(ref raw) => {
                write!(
                    f,
                    r#"CONTEXT_AMD64
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
                )?;
            }
            MinidumpRawContext::SPARC(_) => {
                unimplemented!();
            }
            MinidumpRawContext::ARM(ref raw) => {
                write!(
                    f,
                    r#"CONTEXT_ARM
  context_flags       = {:#x}
"#,
                    raw.context_flags
                )?;
                for (i, reg) in raw.iregs.iter().enumerate() {
                    writeln!(f, "  iregs[{:2}]            = {:#x}", i, reg)?;
                }
                write!(
                    f,
                    r#"  cpsr                = {:#x}
  float_save.fpscr     = {:#x}
"#,
                    raw.cpsr, raw.float_save.fpscr
                )?;
                for (i, reg) in raw.float_save.regs.iter().enumerate() {
                    writeln!(f, "  float_save.regs[{:2}] = {:#x}", i, reg)?;
                }
                for (i, reg) in raw.float_save.extra.iter().enumerate() {
                    writeln!(f, "  float_save.extra[{:2}] = {:#x}", i, reg)?;
                }
            }
            MinidumpRawContext::ARM64(ref raw) => {
                write!(
                    f,
                    r#"CONTEXT_ARM64
  context_flags        = {:#x}
"#,
                    raw.context_flags
                )?;
                for (i, reg) in raw.iregs.iter().enumerate() {
                    writeln!(f, "  iregs[{:2}]            = {:#x}", i, reg)?;
                }
                writeln!(f, "  pc                   = {:#x}", raw.pc)?;
                write!(
                    f,
                    r#"  cpsr                 = {:#x}
  float_save.fpsr     = {:#x}
  float_save.fpcr     = {:#x}
"#,
                    raw.cpsr, raw.float_save.fpsr, raw.float_save.fpcr
                )?;
                for (i, reg) in raw.float_save.regs.iter().enumerate() {
                    writeln!(f, "  float_save.regs[{:2}] = {:#x}", i, reg)?;
                }
            }
            MinidumpRawContext::OLDARM64(ref raw) => {
                write!(
                    f,
                    r#"CONTEXT_ARM64
  context_flags        = {:#x}
"#,
                    { raw.context_flags }
                )?;
                for (i, reg) in { raw.iregs }.iter().enumerate() {
                    writeln!(f, "  iregs[{:2}]            = {:#x}", i, reg)?;
                }
                writeln!(f, "  pc                   = {:#x}", { raw.pc })?;
                write!(
                    f,
                    r#"  cpsr                 = {:#x}
  float_save.fpsr     = {:#x}
  float_save.fpcr     = {:#x}
"#,
                    { raw.cpsr },
                    { raw.float_save }.fpsr,
                    { raw.float_save }.fpcr
                )?;
                for (i, reg) in { raw.float_save }.regs.iter().enumerate() {
                    writeln!(f, "  float_save.regs[{:2}] = {:#x}", i, reg)?;
                }
            }
            MinidumpRawContext::MIPS(_) => {
                unimplemented!();
            }
        }
        Ok(())
    }
}
