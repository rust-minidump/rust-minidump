// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::io::prelude::*;
use chrono::NaiveDateTime;
use encoding::all::UTF_16LE;
use encoding::{Encoding, DecoderTrap};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::SeekFrom;
use std::mem;
use std::path::Path;
use std::ptr;

use minidump_format as md;
use range_map::RangeMap;
use process_state::ProcessState;

/// An index into the contents of a minidump.
///
/// The `Minidump` struct represents the parsed header and
/// indices contained at the start of a minidump file. It can be instantiated
/// by calling the [`Minidump::read`][read] or
/// [`Minidump::read_path`][read_path] methods.
///
/// # Examples
///
/// ```
/// use minidump_processor::Minidump;
/// use std::fs::File;
/// # use std::io;
///
/// # fn foo() -> io::Result<()> {
/// let file = try!(File::open("../testdata/test.dmp"));
/// let dump = Minidump::read(file);
/// # Ok(())
/// # }
/// ```
///
/// [read]: struct.Minidump.html#method.read
/// [read_path]: struct.Minidump.html#method.read_path
#[allow(dead_code)]
pub struct Minidump {
    file : File,
    header : md::MDRawHeader,
    streams : HashMap<u32, (u32, md::MDRawDirectory)>,
    swap : bool,
}

#[derive(Debug)]
pub enum Error {
    FileNotFound,
    MissingHeader,
    HeaderMismatch,
    SwapNotImplemented,
    VersionMismatch,
    MissingDirectory,
    StreamReadFailure,
    StreamSizeMismatch,
    StreamNotFound,
    ModuleReadFailure,
    DataError,
    CodeViewReadFailure,
    UnknownCPUContext,
}

#[derive(Debug)]
pub enum ProcessError {
    UnknownError,
}

/* TODO
pub struct MinidumpMemoryList;
pub struct MinidumpException;
pub struct MinidumpAssertion;
pub struct MinidumpMiscInfo;
pub struct MinidumpBreakpadInfo;
pub struct MinidumpMemoryInfoList;
*/

pub trait MinidumpStream {
    //TODO: associated_consts when that stabilizes.
    fn stream_type() -> u32;
    fn read(f : &File, expected_size : usize) -> Result<Self, Error>;
}

pub trait Module {
    fn base_address(&self) -> u64;
    fn size(&self) -> u64;
    fn code_file(&self) -> Cow<str>;
    fn code_identifier(&self) -> Option<Cow<str>>;
    fn debug_file(&self) -> Option<Cow<str>>;
    fn debug_identifier(&self) -> Option<Cow<str>>;
    fn version(&self) -> Option<Cow<str>>;
}

pub enum CodeViewPDBRaw {
    PDB20(md::MDCVInfoPDB20),
    PDB70(md::MDCVInfoPDB70),
}

pub enum CodeView {
    PDB { raw: CodeViewPDBRaw, file: String },
    Unknown { bytes: Vec<u8> },
}

pub struct MinidumpModule {
    pub raw : md::MDRawModule,
    name : String,
    pub codeview_info : Option<CodeView>,
    pub misc_info : Option<md::MDImageDebugMisc>,
}

pub struct MinidumpModuleList {
    pub modules : Vec<MinidumpModule>,
    // Map from address range to index in modules.
    modules_by_addr : RangeMap<usize>,
}

pub struct MinidumpThread {
    pub raw : md::MDRawThread,
    pub context : Option<MinidumpContext>,
    pub stack : Option<MinidumpMemory>,
}

pub struct MinidumpThreadList {
    pub threads : Vec<MinidumpThread>,
    thread_ids : HashMap<u32, usize>,
}

pub struct MinidumpSystemInfo {
    pub raw : md::MDRawSystemInfo,
}

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

pub struct MinidumpContext {
    pub raw : MinidumpRawContext,
}

pub struct MinidumpMemory {
    pub base_address : u64,
    pub size : u64,
    pub bytes : Vec<u8>,
}

//======================================================
// Implementations

fn read_bytes(f : &File, count : usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(count);
    try!(f.take(count as u64).read_to_end(&mut buf));
    Ok(buf)
}

fn read<T : Copy>(f : &File) -> io::Result<T> {
    let size = mem::size_of::<T>();
    let mut buf = try!(read_bytes(f, size));
    let bytes = &mut buf[..];
    Ok(unsafe {
        let mut val : T = mem::uninitialized();
        ptr::copy(bytes.as_mut_ptr(), &mut val as *mut T as *mut u8, size);
        val
    })
}

fn read_string_utf16(mut f : &File, offset : u64) -> Result<String, Error> {
    try!(f.seek(SeekFrom::Start(offset)).or(Err(Error::DataError)));
    let size = try!(read::<u32>(f).or(Err(Error::DataError))) as usize;
    // TODO: swap
    if size % 2 != 0 {
        return Err(Error::DataError);
    }
    let buf = try!(read_bytes(f, size).or(Err(Error::DataError)));
    let bytes = &buf[..];
    UTF_16LE.decode(bytes, DecoderTrap::Strict).or(Err(Error::DataError))
}

fn write_bytes<T : Write>(f : &mut T, bytes : &[u8]) -> io::Result<()> {
    for b in bytes {
        try!(write!(f, "{:02x}", b));
    }
    Ok(())
}

fn read_codeview_pdb(mut f : &File, signature : u32, mut size : usize) -> Result<CodeView, Error> {
    let raw = match signature {
        md::MD_CVINFOPDB70_SIGNATURE => {
            size = size - mem::size_of::<md::MDCVInfoPDB70>() + 1;
            CodeViewPDBRaw::PDB70(try!(read::<md::MDCVInfoPDB70>(f).or(Err(Error::CodeViewReadFailure))))
        },
        md::MD_CVINFOPDB20_SIGNATURE => {
            size = size -mem::size_of::<md::MDCVInfoPDB20>() + 1;
            CodeViewPDBRaw::PDB20(try!(read::<md::MDCVInfoPDB20>(f).or(Err(Error::CodeViewReadFailure))))
        },
        _ => return Err(Error::CodeViewReadFailure),
    };
    // Both structs define a variable-length string with a placeholder
    // 1-byte array at the end, so seek back one byte and read the remaining
    // data as the string.
    try!(f.seek(SeekFrom::Current(-1)).or(Err(Error::CodeViewReadFailure)));
    let bytes = try!(read_bytes(f, size).or(Err(Error::CodeViewReadFailure)));
    // The string should have at least one trailing NUL.
    let file = String::from(String::from_utf8(bytes).unwrap().trim_right_matches('\0'));
    Ok(CodeView::PDB { raw: raw, file: file})
}

fn read_codeview(mut f : &File, location : md::MDLocationDescriptor) -> Result<CodeView, Error> {
    let size = location.data_size as usize;
    try!(f.seek(SeekFrom::Start(location.rva as u64)).or(Err(Error::CodeViewReadFailure)));
    // The CodeView data can contain a variable-length string at the end
    // and also can be one of a few different formats. Try to read the
    // signature first to figure out what format the data is.
    // TODO: swap
    let signature = try!(read::<u32>(f).or(Err(Error::CodeViewReadFailure)));
    // Seek back because the signature is part of the CV data.
    try!(f.seek(SeekFrom::Start(location.rva as u64)).or(Err(Error::CodeViewReadFailure)));
    match signature {
        md::MD_CVINFOPDB70_SIGNATURE | md::MD_CVINFOPDB20_SIGNATURE => {
            read_codeview_pdb(f, signature, size)
        },
        _ =>
            // Other formats aren't handled, but save the raw bytes.
            Ok(CodeView::Unknown { bytes: try!(read_bytes(f, size).or(Err(Error::CodeViewReadFailure))) })
    }
}

impl MinidumpModule {
    pub fn read(f : &File, raw : md::MDRawModule) -> Result<MinidumpModule, Error> {
        let name = try!(read_string_utf16(f, raw.module_name_rva as u64));
        let cv = if raw.cv_record.data_size > 0 {
            Some(try!(read_codeview(f, raw.cv_record).or(Err(Error::CodeViewReadFailure))))
        } else {
            None
        };
        Ok(MinidumpModule {
            raw: raw,
            name: name,
            codeview_info: cv,
            misc_info: None,
        })
    }
}

impl Module for MinidumpModule {
    fn base_address(&self) -> u64 { self.raw.base_of_image }
    fn size(&self) -> u64 { self.raw.size_of_image as u64 }
    fn code_file(&self) -> Cow<str> { Cow::Borrowed(&self.name) }
    fn code_identifier(&self) -> Option<Cow<str>> {
        Some(Cow::Owned(format!("{0:08X}{1:x}", self.raw.time_date_stamp,
                                self.raw.size_of_image)))
    }
    fn debug_file(&self) -> Option<Cow<str>> {
        match self.codeview_info {
            Some(CodeView::PDB { raw: _, ref file }) => Some(Cow::Borrowed(&file)),
            // TODO: support misc record
            _ => None,
        }
    }
    fn debug_identifier(&self) -> Option<Cow<str>> {
        match self.codeview_info {
            Some(CodeView::PDB { raw: CodeViewPDBRaw::PDB70(ref raw), file: _ }) => {
                let id = format!("{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:x}",
                                 raw.signature.data1,
                                 raw.signature.data2,
                                 raw.signature.data3,
                                 raw.signature.data4[0],
                                 raw.signature.data4[1],
                                 raw.signature.data4[2],
                                 raw.signature.data4[3],
                                 raw.signature.data4[4],
                                 raw.signature.data4[5],
                                 raw.signature.data4[6],
                                 raw.signature.data4[7],
                                 raw.age);
                Some(Cow::Owned(id))
            },
            Some(CodeView::PDB { raw: CodeViewPDBRaw::PDB20(ref raw), file: _ }) => {
                let id = format!("{:08X}{:x}",
                                 raw.signature,
                                 raw.age);
                Some(Cow::Owned(id))
            },
            _ => None,
        }
    }
    fn version(&self) -> Option<Cow<str>> {
        if self.raw.version_info.signature == md::MD_VSFIXEDFILEINFO_SIGNATURE &&
            (self.raw.version_info.struct_version & md::MD_VSFIXEDFILEINFO_VERSION) == md::MD_VSFIXEDFILEINFO_VERSION {
                let ver =
                    format!("{}.{}.{}.{}",
                            self.raw.version_info.file_version_hi >> 16,
                            self.raw.version_info.file_version_hi & 0xffff,
                            self.raw.version_info.file_version_lo >> 16,
                            self.raw.version_info.file_version_lo & 0xffff);
                Some(Cow::Owned(ver))
            }
        else {
            None
        }
    }
}

fn read_stream_list<T : Copy>(f : &File, expected_size : usize) -> Result<Vec<T>, Error> {
    if expected_size < mem::size_of::<u32>() {
        return Err(Error::StreamSizeMismatch);
    }

    // TODO: swap
    let count = try!(read::<u32>(&f).or(Err(Error::StreamReadFailure))) as usize;
    match expected_size - (mem::size_of::<u32>() + count * mem::size_of::<T>()) {
        0 => {},
        4 => {
            // 4 bytes of padding.
            try!(read::<u32>(&f).or(Err(Error::StreamReadFailure)));
        },
        _ => return Err(Error::StreamSizeMismatch)
    };
    // read count T raw stream entries
    let mut raw_entries = Vec::with_capacity(count);
    for _ in 0..count {
        let raw = try!(read::<T>(f).or(Err(Error::StreamReadFailure)));
        raw_entries.push(raw);
    }
    Ok(raw_entries)
}

impl MinidumpModuleList {
    pub fn module_at_address(&self, addr : u64) -> Option<&MinidumpModule> {
        return if let Some(index) = self.modules_by_addr.lookup(addr) {
            Some(&self.modules[index])
        } else {
            None
        }
    }
}

impl MinidumpStream for MinidumpModuleList {
    fn stream_type() -> u32 { md::MD_MODULE_LIST_STREAM }
    fn read(f : &File, expected_size : usize) -> Result<MinidumpModuleList, Error> {
        let raw_modules = try!(read_stream_list::<md::MDRawModule>(f, expected_size));
        // read auxiliary data for each module
        let mut modules = Vec::with_capacity(raw_modules.len());
        let mut map = RangeMap::<usize>::new();
        for raw in raw_modules.into_iter() {
            // TODO: swap
            if raw.size_of_image == 0 || raw.size_of_image as u64 > (u64::max_value() - raw.base_of_image) {
                // Bad image size.
                //println!("image {}: bad image size: {}", i, raw.size_of_image);
                // TODO: just drop this module, keep the rest?
                return Err(Error::ModuleReadFailure);
            }
            if let Err(_) = map.insert((raw.base_of_image, raw.base_of_image + raw.size_of_image as u64), modules.len()) {
                // Better error? Module overlaps existing module.
                // TODO: just drop this module, keep the rest?
                return Err(Error::ModuleReadFailure);
            }
            modules.push(try!(MinidumpModule::read(f, raw)));
        }
        Ok(MinidumpModuleList { modules: modules, modules_by_addr: map })
    }
}

impl MinidumpContext {
    pub fn read(mut f : &File, location : &md::MDLocationDescriptor) -> Result<MinidumpContext, Error> {
        try!(f.seek(SeekFrom::Start(location.rva as u64)).or(Err(Error::StreamReadFailure)));
        let expected_size = location.data_size as usize;
        // Some contexts don't have a context flags word at the beginning,
        // so special-case them by size.
        if expected_size == mem::size_of::<md::MDRawContextAMD64>() {
            let ctx = try!(read::<md::MDRawContextAMD64>(f).or(Err(Error::StreamReadFailure)));
            if ctx.context_flags & md::MD_CONTEXT_CPU_MASK != md::MD_CONTEXT_AMD64 {
                return Err(Error::StreamReadFailure);
            } else {
                return Ok(MinidumpContext {
                    raw: MinidumpRawContext::AMD64(ctx)
                })
            }
        } else if expected_size == mem::size_of::<md::MDRawContextPPC64>() {
            let ctx = try!(read::<md::MDRawContextPPC64>(f).or(Err(Error::StreamReadFailure)));
            if ctx.context_flags & (md::MD_CONTEXT_CPU_MASK as u64) != md::MD_CONTEXT_PPC64 as u64 {
                return Err(Error::StreamReadFailure);
            } else {
                return Ok(MinidumpContext {
                    raw: MinidumpRawContext::PPC64(ctx)
                })
            }
        } else if expected_size == mem::size_of::<md::MDRawContextARM64>() {
            let ctx = try!(read::<md::MDRawContextARM64>(f).or(Err(Error::StreamReadFailure)));
            if ctx.context_flags & (md::MD_CONTEXT_CPU_MASK as u64) != md::MD_CONTEXT_ARM64 as u64 {
                return Err(Error::StreamReadFailure);
            } else {
                return Ok(MinidumpContext {
                    raw: MinidumpRawContext::ARM64(ctx)
                })
            }
        } else {
            // For everything else, read the flags and determine context
            // type from that.
            // TODO: swap
            let flags = try!(read::<u32>(&f).or(Err(Error::StreamReadFailure)));
            try!(f.seek(SeekFrom::Current(-4)).or(Err(Error::StreamReadFailure)));
            let cpu_type = flags & md::MD_CONTEXT_CPU_MASK;
            // TODO: handle dumps with MD_CONTEXT_ARM_OLD
            if let Some(ctx) = match cpu_type {
                md::MD_CONTEXT_X86 => {
                    let ctx = try!(read::<md::MDRawContextX86>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::X86(ctx))
                },
                md::MD_CONTEXT_PPC => {
                    let ctx = try!(read::<md::MDRawContextPPC>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::PPC(ctx))
                },
                md::MD_CONTEXT_SPARC => {
                    let ctx = try!(read::<md::MDRawContextSPARC>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::SPARC(ctx))
                },
                md::MD_CONTEXT_ARM => {
                    let ctx = try!(read::<md::MDRawContextARM>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::ARM(ctx))
                },
                md::MD_CONTEXT_MIPS => {
                    let ctx = try!(read::<md::MDRawContextMIPS>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::MIPS(ctx))
                },
                _ => None,
            } {
                return Ok(MinidumpContext { raw: ctx })
            }
            return Err(Error::UnknownCPUContext)
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

impl MinidumpMemory {
    pub fn read(mut f : &File, desc : &md::MDMemoryDescriptor) -> Result<MinidumpMemory, Error> {
        try!(f.seek(SeekFrom::Start(desc.memory.rva as u64)).or(Err(Error::StreamReadFailure)));
        let bytes = try!(read_bytes(f, desc.memory.data_size as usize).or(Err(Error::DataError)));
        Ok(MinidumpMemory {
            base_address: desc.start_of_memory_range,
            size: desc.memory.data_size as u64,
            bytes: bytes,
        })
    }

    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, "0x"));
        for byte in self.bytes.iter() {
            try!(write!(f, "{:02x}", byte));
        }
        try!(write!(f, "\n"));
        Ok(())
    }
}

impl MinidumpThread {
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, r#"MDRawThread
  thread_id                   = {:#x}
  suspend_count               = {}
  priority_class              = {:#x}
  priority                    = {:#x}
  teb                         = {:#x}
  stack.start_of_memory_range = {:#x}
  stack.memory.data_size      = {:#x}
  stack.memory.rva            = {:#x}
  thread_context.data_size    = {:#x}
  thread_context.rva          = {:#x}

"#,
                    self.raw.thread_id,
                    self.raw.suspend_count,
                    self.raw.priority_class,
                    self.raw.priority,
                    self.raw.teb,
                    self.raw.stack.start_of_memory_range,
                    self.raw.stack.memory.data_size,
                    self.raw.stack.memory.rva,
                    self.raw.thread_context.data_size,
                    self.raw.thread_context.rva,
                    ));
        if let Some(ref ctx) = self.context {
            try!(ctx.print(f));
        } else {
            try!(write!(f, "  (no context)\n\n"));
        }

        if let Some(ref stack) = self.stack {
            try!(writeln!(f, "Stack"));
            try!(stack.print(f));
        } else {
            try!(writeln!(f, "No stack"));
        }
        try!(write!(f, "\n"));
        Ok(())
    }
}

impl MinidumpStream for MinidumpThreadList {
    fn stream_type() -> u32 { md::MD_THREAD_LIST_STREAM }
    fn read(f : &File, expected_size : usize) -> Result<MinidumpThreadList, Error> {
        let raw_threads = try!(read_stream_list::<md::MDRawThread>(f, expected_size));
        let mut threads = Vec::with_capacity(raw_threads.len());
        let mut thread_ids = HashMap::with_capacity(raw_threads.len());
        for raw in raw_threads.into_iter() {
            // TODO: swap
            thread_ids.insert(raw.thread_id, threads.len());
            let context = MinidumpContext::read(f, &raw.thread_context).ok();
            // TODO: check memory region
            let stack = MinidumpMemory::read(f, &raw.stack).ok();
            threads.push(MinidumpThread {
                raw: raw,
                context: context,
                stack: stack,
            });
        }
        Ok(MinidumpThreadList { threads: threads, thread_ids: thread_ids })
    }
}

impl MinidumpThreadList {
    pub fn get_thread(&self, id : u32) -> Option<&MinidumpThread> {
        match self.thread_ids.get(&id) {
            None => None,
            Some(&index) => Some(&self.threads[index]),
        }
    }

    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, r#"MinidumpThreadList
  thread_count = {}

"#, self.threads.len()));

        for (i, thread) in self.threads.iter().enumerate() {
            try!(write!(f, "thread[{}]\n", i));
            try!(thread.print(f));
        }
        Ok(())
    }
}

impl MinidumpSystemInfo {
    pub fn os(&self) -> &'static str {
        match self.raw.platform_id {
            md::MD_OS_WIN32_NT | md::MD_OS_WIN32_WINDOWS => "windows",
            md::MD_OS_MAC_OS_X => "mac",
            md::MD_OS_IOS => "ios",
            md::MD_OS_LINUX => "linux",
            md::MD_OS_SOLARIS => "solaris",
            md::MD_OS_ANDROID => "android",
            md::MD_OS_PS3 => "ps3",
            md::MD_OS_NACL => "nacl",
            _ => "unknown",
        }
    }

    pub fn cpu(&self) -> &'static str {
        match self.raw.processor_architecture as u32 {
            md::MD_CPU_ARCHITECTURE_X86 | md::MD_CPU_ARCHITECTURE_X86_WIN64 => "x86",
            md::MD_CPU_ARCHITECTURE_AMD64 => "x86-64",
            md::MD_CPU_ARCHITECTURE_PPC => "ppc",
            md::MD_CPU_ARCHITECTURE_PPC64 => "ppc64",
            md::MD_CPU_ARCHITECTURE_SPARC => "sparc",
            md::MD_CPU_ARCHITECTURE_ARM => "arm",
            md::MD_CPU_ARCHITECTURE_ARM64 => "arm64",
            _ => "unknown",
        }
    }
}

impl MinidumpStream for MinidumpSystemInfo {
    fn stream_type() -> u32 { md::MD_SYSTEM_INFO_STREAM }
    fn read(f : &File, expected_size : usize) -> Result<MinidumpSystemInfo, Error> {
        assert_eq!(expected_size, mem::size_of::<md::MDRawSystemInfo>());
        let raw = try!(read::<md::MDRawSystemInfo>(f).or(Err(Error::StreamReadFailure)));
        Ok(MinidumpSystemInfo { raw: raw })
    }
}

impl Minidump {
    /// Read a `Minidump` from a `Path` to a file on disk.
    pub fn read_path(path : &Path) -> Result<Minidump, Error> {
        let f = try!(File::open(path).or(Err(Error::FileNotFound)));
        Minidump::read(f)
    }

    /// Read a `Minidump` from an open `File`.
    pub fn read(f : File) -> Result<Minidump, Error> {
        let header = try!(read::<md::MDRawHeader>(&f).or(Err(Error::MissingHeader)));
        let swap = false;
        if header.signature != md::MD_HEADER_SIGNATURE {
            if header.signature.swap_bytes() != md::MD_HEADER_SIGNATURE {
                return Err(Error::HeaderMismatch);
            }
            return Err(Error::SwapNotImplemented);
            // TODO: implement swapping
            //swap = true;
        }
        if (header.version & 0x0000ffff) != md::MD_HEADER_VERSION {
            return Err(Error::VersionMismatch);
        }
        let mut streams = HashMap::with_capacity(header.stream_count as usize);
        for i in 0..header.stream_count {
            let dir = try!(read::<md::MDRawDirectory>(&f).or(Err(Error::MissingDirectory)));
            streams.insert(dir.stream_type, (i, dir));
        }
        Ok(Minidump {
            file: f,
            header: header,
            streams: streams,
            swap: swap
        })
    }

    pub fn process(&mut self) -> Result<ProcessState, ProcessError> {
        Err(ProcessError::UnknownError)
    }

    /// Get a known stream of data from the minidump.
    ///
    /// For streams known to this module whose types implement the
    /// [`MinidumpStream`][stream] trait, this method allows reading
    /// the stream data as a specific type.
    ///
    /// [stream]: trait.MinidumpStream.html
    pub fn get_stream<T: MinidumpStream>(&mut self) -> Result<T, Error> {
        match self.streams.get_mut(&T::stream_type()) {
            None => Err(Error::StreamNotFound),
            Some(&mut (_, dir)) => {
                try!(self.file.seek(SeekFrom::Start(dir.location.rva as u64)).or(Err(Error::StreamReadFailure)));
                // TODO: cache result
                T::read(&self.file, dir.location.data_size as usize)
            }
        }
    }

    /// Write a verbose description of the `Minidump` to `f`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        fn get_stream_name(stream_type : u32) -> &'static str {
            match stream_type {
                md::MD_UNUSED_STREAM =>
                    "MD_UNUSED_STREAM",
                md::MD_RESERVED_STREAM_0 =>
                    "MD_RESERVED_STREAM_0",
                md::MD_RESERVED_STREAM_1 =>
                    "MD_RESERVED_STREAM_1",
                md::MD_THREAD_LIST_STREAM =>
                    "MD_THREAD_LIST_STREAM",
                md::MD_MODULE_LIST_STREAM =>
                    "MD_MODULE_LIST_STREAM",
                md::MD_MEMORY_LIST_STREAM =>
                    "MD_MEMORY_LIST_STREAM",
                md::MD_EXCEPTION_STREAM =>
                    "MD_EXCEPTION_STREAM",
                md::MD_SYSTEM_INFO_STREAM =>
                    "MD_SYSTEM_INFO_STREAM",
                md::MD_THREAD_EX_LIST_STREAM =>
                    "MD_THREAD_EX_LIST_STREAM",
                md::MD_MEMORY_64_LIST_STREAM =>
                    "MD_MEMORY_64_LIST_STREAM",
                md::MD_COMMENT_STREAM_A =>
                    "MD_COMMENT_STREAM_A",
                md::MD_COMMENT_STREAM_W =>
                    "MD_COMMENT_STREAM_W",
                md::MD_HANDLE_DATA_STREAM =>
                    "MD_HANDLE_DATA_STREAM",
                md::MD_FUNCTION_TABLE_STREAM =>
                    "MD_FUNCTION_TABLE_STREAM",
                md::MD_UNLOADED_MODULE_LIST_STREAM =>
                    "MD_UNLOADED_MODULE_LIST_STREAM",
                md::MD_MISC_INFO_STREAM =>
                    "MD_MISC_INFO_STREAM",
                md::MD_MEMORY_INFO_LIST_STREAM =>
                    "MD_MEMORY_INFO_LIST_STREAM",
                md::MD_THREAD_INFO_LIST_STREAM =>
                    "MD_THREAD_INFO_LIST_STREAM",
                md::MD_HANDLE_OPERATION_LIST_STREAM =>
                    "MD_HANDLE_OPERATION_LIST_STREAM",
                md::MD_LAST_RESERVED_STREAM =>
                    "MD_LAST_RESERVED_STREAM",
                md::MD_BREAKPAD_INFO_STREAM =>
                    "MD_BREAKPAD_INFO_STREAM",
                md::MD_ASSERTION_INFO_STREAM =>
                    "MD_ASSERTION_INFO_STREAM",
                md::MD_LINUX_CPU_INFO =>
                    "MD_LINUX_CPU_INFO",
                md::MD_LINUX_PROC_STATUS =>
                    "MD_LINUX_PROC_STATUS",
                md::MD_LINUX_LSB_RELEASE =>
                    "MD_LINUX_LSB_RELEASE",
                md::MD_LINUX_CMD_LINE =>
                    "MD_LINUX_CMD_LINE",
                md::MD_LINUX_ENVIRON =>
                    "MD_LINUX_ENVIRON",
                md::MD_LINUX_AUXV =>
                    "MD_LINUX_AUXV",
                md::MD_LINUX_MAPS =>
                    "MD_LINUX_MAPS",
                md::MD_LINUX_DSO_DEBUG =>
                    "MD_LINUX_DSO_DEBUG",
                _ => "unknown",
            }
        }

        let mut formatted_time = String::new();
        if let Some(datetime) =
            NaiveDateTime::from_timestamp_opt(self.header.time_date_stamp as i64, 0) {
                formatted_time = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
        }
        try!(write!(f, r#"MDRawHeader
  signature            = {:#x}
  version              = {:#x}
  stream_count         = {}
  stream_directory_rva = {:#x}
  checksum             = {:#x}
  time_date_stamp      = {:#x} {}
  flags                = {:#x}

"#,
                    self.header.signature,
                    self.header.version,
                    self.header.stream_count,
                    self.header.stream_directory_rva,
                    self.header.checksum,
                    self.header.time_date_stamp,
                    formatted_time,
                    self.header.flags,
                    ));
        let mut streams = self.streams.iter().collect::<Vec<_>>();
        streams.sort_by(|&(&_, &(a, _)), &(&_, &(b, _))| a.cmp(&b));
        for &(_, &(i, stream)) in streams.iter() {
            try!(write!(f, r#"mDirectory[{}]
MDRawDirectory
  stream_type        = {:#x} ({})
  location.data_size = {}
  location.rva       = {:#x}

"#,
                        i,
                        stream.stream_type,
                        get_stream_name(stream.stream_type),
                        stream.location.data_size,
                        stream.location.rva));
        }
        try!(write!(f, "Streams:\n"));
        streams.sort_by(|&(&a, &(_, _)), &(&b, &(_, _))| a.cmp(&b));
        for (_, &(i, stream)) in streams {
            try!(write!(f, "  stream type {:#x} ({}) at index {}\n",
                        stream.stream_type,
                        get_stream_name(stream.stream_type),
                        i));
        }
        try!(write!(f, "\n"));
        Ok(())
    }
}
