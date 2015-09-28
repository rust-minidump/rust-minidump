use std::io::prelude::*;
use std::borrow::Cow;
use std::fs::File;
use std::io::SeekFrom;
use std::mem;
use std::ptr;
use std::collections::HashMap;

extern crate libc;
extern crate encoding;

use encoding::{Encoding, DecoderTrap};
use encoding::all::UTF_16LE;

pub mod minidump_format;
use minidump_format as fmt;
mod range_map;
use range_map::RangeMap;

#[allow(dead_code)]
pub struct Minidump {
    file : File,
    header : fmt::MDRawHeader,
    streams : HashMap<u32, (u32, fmt::MDRawDirectory)>,
    swap : bool,
}

#[derive(Debug)]
pub enum Error {
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

pub struct MinidumpMemoryList;
pub struct MinidumpException;
pub struct MinidumpAssertion;
pub struct MinidumpMiscInfo;
pub struct MinidumpBreakpadInfo;
pub struct MinidumpMemoryInfoList;

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
    PDB20(fmt::MDCVInfoPDB20),
    PDB70(fmt::MDCVInfoPDB70),
}

pub enum CodeView {
    PDB { raw: CodeViewPDBRaw, file: String },
    Unknown { bytes: Vec<u8> },
}

pub struct MinidumpModule {
    pub raw : fmt::MDRawModule,
    name : String,
    pub codeview_info : Option<CodeView>,
    pub misc_info : Option<fmt::MDImageDebugMisc>,
}

pub struct MinidumpModuleList {
    pub modules : Vec<MinidumpModule>,
    // Map from address range to index in modules.
    modules_by_addr : RangeMap<usize>,
}

pub struct MinidumpThread {
    pub raw : fmt::MDRawThread,
    pub context : Option<MinidumpContext>,
}

pub struct MinidumpThreadList {
    pub threads : Vec<MinidumpThread>,
    thread_ids : HashMap<u32, usize>,
}

pub struct MinidumpSystemInfo {
    pub raw : fmt::MDRawSystemInfo,
}

pub enum MinidumpRawContext {
    X86(fmt::MDRawContextX86),
    PPC(fmt::MDRawContextPPC),
    PPC64(fmt::MDRawContextPPC64),
    AMD64(fmt::MDRawContextAMD64),
    SPARC(fmt::MDRawContextSPARC),
    ARM(fmt::MDRawContextARM),
    ARM64(fmt::MDRawContextARM64),
    MIPS(fmt::MDRawContextMIPS),
}

pub struct MinidumpContext {
    pub raw : MinidumpRawContext,
}

//======================================================
// Implementations

fn read_bytes(f : &File, count : usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(count);
    try!(f.take(count as u64).read_to_end(&mut buf));
    Ok(buf)
}

fn read<T : Copy>(f : &File) -> std::io::Result<T> {
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

fn write_bytes<T : Write>(f : &mut T, bytes : &[u8]) -> std::io::Result<()> {
    for b in bytes {
        try!(write!(f, "{:02x}", b));
    }
    Ok(())
}

fn read_codeview_pdb(mut f : &File, signature : u32, mut size : usize) -> Result<CodeView, Error> {
    let raw = match signature {
        fmt::MD_CVINFOPDB70_SIGNATURE => {
            size = size - mem::size_of::<fmt::MDCVInfoPDB70>() + 1;
            CodeViewPDBRaw::PDB70(try!(read::<fmt::MDCVInfoPDB70>(f).or(Err(Error::CodeViewReadFailure))))
        },
        fmt::MD_CVINFOPDB20_SIGNATURE => {
            size = size -mem::size_of::<fmt::MDCVInfoPDB20>() + 1;
            CodeViewPDBRaw::PDB20(try!(read::<fmt::MDCVInfoPDB20>(f).or(Err(Error::CodeViewReadFailure))))
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

fn read_codeview(mut f : &File, location : fmt::MDLocationDescriptor) -> Result<CodeView, Error> {
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
        fmt::MD_CVINFOPDB70_SIGNATURE | fmt::MD_CVINFOPDB20_SIGNATURE => {
            read_codeview_pdb(f, signature, size)
        },
        _ =>
            // Other formats aren't handled, but save the raw bytes.
            Ok(CodeView::Unknown { bytes: try!(read_bytes(f, size).or(Err(Error::CodeViewReadFailure))) })
    }
}

impl MinidumpModule {
    pub fn read(f : &File, raw : fmt::MDRawModule) -> Result<MinidumpModule, Error> {
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
        if self.raw.version_info.signature == fmt::MD_VSFIXEDFILEINFO_SIGNATURE &&
            (self.raw.version_info.struct_version & fmt::MD_VSFIXEDFILEINFO_VERSION) == fmt::MD_VSFIXEDFILEINFO_VERSION {
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
    fn stream_type() -> u32 { fmt::MD_MODULE_LIST_STREAM }
    fn read(f : &File, expected_size : usize) -> Result<MinidumpModuleList, Error> {
        let raw_modules = try!(read_stream_list::<fmt::MDRawModule>(f, expected_size));
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
    pub fn read(mut f : &File, location : &fmt::MDLocationDescriptor) -> Result<MinidumpContext, Error> {
        try!(f.seek(SeekFrom::Start(location.rva as u64)).or(Err(Error::StreamReadFailure)));
        let expected_size = location.data_size as usize;
        // Some contexts don't have a context flags word at the beginning,
        // so special-case them by size.
        if expected_size == mem::size_of::<fmt::MDRawContextAMD64>() {
            let ctx = try!(read::<fmt::MDRawContextAMD64>(f).or(Err(Error::StreamReadFailure)));
            if ctx.context_flags & fmt::MD_CONTEXT_CPU_MASK != fmt::MD_CONTEXT_AMD64 {
                return Err(Error::StreamReadFailure);
            } else {
                return Ok(MinidumpContext {
                    raw: MinidumpRawContext::AMD64(ctx)
                })
            }
        } else if expected_size == mem::size_of::<fmt::MDRawContextPPC64>() {
            let ctx = try!(read::<fmt::MDRawContextPPC64>(f).or(Err(Error::StreamReadFailure)));
            if ctx.context_flags & (fmt::MD_CONTEXT_CPU_MASK as u64) != fmt::MD_CONTEXT_PPC64 as u64 {
                return Err(Error::StreamReadFailure);
            } else {
                return Ok(MinidumpContext {
                    raw: MinidumpRawContext::PPC64(ctx)
                })
            }
        } else if expected_size == mem::size_of::<fmt::MDRawContextARM64>() {
            let ctx = try!(read::<fmt::MDRawContextARM64>(f).or(Err(Error::StreamReadFailure)));
            if ctx.context_flags & (fmt::MD_CONTEXT_CPU_MASK as u64) != fmt::MD_CONTEXT_ARM64 as u64 {
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
            let cpu_type = flags & fmt::MD_CONTEXT_CPU_MASK;
            // TODO: handle dumps with MD_CONTEXT_ARM_OLD
            if let Some(ctx) = match cpu_type {
                fmt::MD_CONTEXT_X86 => {
                    let ctx = try!(read::<fmt::MDRawContextX86>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::X86(ctx))
                },
                fmt::MD_CONTEXT_PPC => {
                    let ctx = try!(read::<fmt::MDRawContextPPC>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::PPC(ctx))
                },
                fmt::MD_CONTEXT_SPARC => {
                    let ctx = try!(read::<fmt::MDRawContextSPARC>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::SPARC(ctx))
                },
                fmt::MD_CONTEXT_ARM => {
                    let ctx = try!(read::<fmt::MDRawContextARM>(&f).or(Err(Error::StreamReadFailure)));
                    Some(MinidumpRawContext::ARM(ctx))
                },
                fmt::MD_CONTEXT_MIPS => {
                    let ctx = try!(read::<fmt::MDRawContextMIPS>(&f).or(Err(Error::StreamReadFailure)));
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
            MinidumpRawContext::ARM(ctx) => ctx.iregs[fmt::MD_CONTEXT_ARM_REG_PC as usize] as u64,
            MinidumpRawContext::ARM64(ctx) => ctx.iregs[fmt::MD_CONTEXT_ARM64_REG_PC as usize],
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
            MinidumpRawContext::ARM(ctx) => ctx.iregs[fmt::MD_CONTEXT_ARM_REG_SP as usize] as u64,
            MinidumpRawContext::ARM64(ctx) => ctx.iregs[fmt::MD_CONTEXT_ARM64_REG_SP as usize],
            MinidumpRawContext::PPC(ctx) => ctx.gpr[fmt::MD_CONTEXT_PPC_REG_SP as usize] as u64,
            MinidumpRawContext::PPC64(ctx) => ctx.gpr[fmt::MD_CONTEXT_PPC64_REG_SP as usize],
            MinidumpRawContext::SPARC(ctx) => ctx.g_r[fmt::MD_CONTEXT_SPARC_REG_SP as usize],
            MinidumpRawContext::X86(ctx) => ctx.esp as u64,
            MinidumpRawContext::MIPS(ctx) => ctx.iregs[fmt::MD_CONTEXT_MIPS_REG_SP as usize],
        }
    }

    pub fn print<T : Write>(&self, f : &mut T) -> std::io::Result<()> {
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
                            fmt::MD_FLOATINGSAVEAREA_X86_REGISTERAREA_SIZE,
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
                            fmt::MD_CONTEXT_X86_EXTENDED_REGISTERS_SIZE,
                            ));
                try!(write_bytes(f, &raw.extended_registers));
                try!(write!(f, "\n\n"));
            },
            MinidumpRawContext::PPC(raw) => {
                unimplemented!();
            },
            MinidumpRawContext::PPC64(raw) => {
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
            MinidumpRawContext::SPARC(raw) => {
                unimplemented!();
            },
            MinidumpRawContext::ARM(raw) => {
                unimplemented!();
            },
            MinidumpRawContext::ARM64(raw) => {
                unimplemented!();
            },
            MinidumpRawContext::MIPS(raw) => {
                unimplemented!();
            },
        }
        Ok(())
    }
}

impl MinidumpThread {
    pub fn print<T : Write>(&self, f : &mut T) -> std::io::Result<()> {
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
        Ok(())
    }
}

impl MinidumpStream for MinidumpThreadList {
    fn stream_type() -> u32 { fmt::MD_THREAD_LIST_STREAM }
    fn read(f : &File, expected_size : usize) -> Result<MinidumpThreadList, Error> {
        let raw_threads = try!(read_stream_list::<fmt::MDRawThread>(f, expected_size));
        let mut threads = Vec::with_capacity(raw_threads.len());
        let mut thread_ids = HashMap::with_capacity(raw_threads.len());
        for raw in raw_threads.into_iter() {
            // TODO: swap
            thread_ids.insert(raw.thread_id, threads.len());
            // TODO: check memory region
            // TODO: read thread context
            let context = MinidumpContext::read(f, &raw.thread_context).ok();
            threads.push(MinidumpThread { raw: raw, context: context });
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

    pub fn print<T : Write>(&self, f : &mut T) -> std::io::Result<()> {
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
            fmt::MD_OS_WIN32_NT | fmt::MD_OS_WIN32_WINDOWS => "windows",
            fmt::MD_OS_MAC_OS_X => "mac",
            fmt::MD_OS_IOS => "ios",
            fmt::MD_OS_LINUX => "linux",
            fmt::MD_OS_SOLARIS => "solaris",
            fmt::MD_OS_ANDROID => "android",
            fmt::MD_OS_PS3 => "ps3",
            fmt::MD_OS_NACL => "nacl",
            _ => "unknown",
        }
    }

    pub fn cpu(&self) -> &'static str {
        match self.raw.processor_architecture as u32 {
            fmt::MD_CPU_ARCHITECTURE_X86 | fmt::MD_CPU_ARCHITECTURE_X86_WIN64 => "x86",
            fmt::MD_CPU_ARCHITECTURE_AMD64 => "x86-64",
            fmt::MD_CPU_ARCHITECTURE_PPC => "ppc",
            fmt::MD_CPU_ARCHITECTURE_PPC64 => "ppc64",
            fmt::MD_CPU_ARCHITECTURE_SPARC => "sparc",
            fmt::MD_CPU_ARCHITECTURE_ARM => "arm",
            fmt::MD_CPU_ARCHITECTURE_ARM64 => "arm64",
            _ => "unknown",
        }
    }
}

impl MinidumpStream for MinidumpSystemInfo {
    fn stream_type() -> u32 { fmt::MD_SYSTEM_INFO_STREAM }
    fn read(f : &File, expected_size : usize) -> Result<MinidumpSystemInfo, Error> {
        assert_eq!(expected_size, mem::size_of::<fmt::MDRawSystemInfo>());
        let raw = try!(read::<fmt::MDRawSystemInfo>(f).or(Err(Error::StreamReadFailure)));
        Ok(MinidumpSystemInfo { raw: raw })
    }
}

impl Minidump {
    pub fn read(f : File) -> Result<Minidump, Error> {
        let header = try!(read::<fmt::MDRawHeader>(&f).or(Err(Error::MissingHeader)));
        let swap = false;
        if header.signature != fmt::MD_HEADER_SIGNATURE {
            if header.signature.swap_bytes() != fmt::MD_HEADER_SIGNATURE {
                return Err(Error::HeaderMismatch);
            }
            return Err(Error::SwapNotImplemented);
            // TODO: implement swapping
            //swap = true;
        }
        if (header.version & 0x0000ffff) != fmt::MD_HEADER_VERSION {
            return Err(Error::VersionMismatch);
        }
        let mut streams = HashMap::with_capacity(header.stream_count as usize);
        for i in 0..header.stream_count {
            let dir = try!(read::<fmt::MDRawDirectory>(&f).or(Err(Error::MissingDirectory)));
            if dir.stream_type != fmt::MD_UNUSED_STREAM {
                streams.insert(dir.stream_type, (i, dir));
            }
        }
        Ok(Minidump {
            file: f,
            header: header,
            streams: streams,
            swap: swap
        })
    }

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

    pub fn print<T : Write>(&self, f : &mut T) -> std::io::Result<()> {
        fn get_stream_name(stream_type : u32) -> &'static str {
            match stream_type {
                fmt::MD_UNUSED_STREAM =>
                    "MD_UNUSED_STREAM",
                fmt::MD_RESERVED_STREAM_0 =>
                    "MD_RESERVED_STREAM_0",
                fmt::MD_RESERVED_STREAM_1 =>
                    "MD_RESERVED_STREAM_1",
                fmt::MD_THREAD_LIST_STREAM =>
                    "MD_THREAD_LIST_STREAM",
                fmt::MD_MODULE_LIST_STREAM =>
                    "MD_MODULE_LIST_STREAM",
                fmt::MD_MEMORY_LIST_STREAM =>
                    "MD_MEMORY_LIST_STREAM",
                fmt::MD_EXCEPTION_STREAM =>
                    "MD_EXCEPTION_STREAM",
                fmt::MD_SYSTEM_INFO_STREAM =>
                    "MD_SYSTEM_INFO_STREAM",
                fmt::MD_THREAD_EX_LIST_STREAM =>
                    "MD_THREAD_EX_LIST_STREAM",
                fmt::MD_MEMORY_64_LIST_STREAM =>
                    "MD_MEMORY_64_LIST_STREAM",
                fmt::MD_COMMENT_STREAM_A =>
                    "MD_COMMENT_STREAM_A",
                fmt::MD_COMMENT_STREAM_W =>
                    "MD_COMMENT_STREAM_W",
                fmt::MD_HANDLE_DATA_STREAM =>
                    "MD_HANDLE_DATA_STREAM",
                fmt::MD_FUNCTION_TABLE_STREAM =>
                    "MD_FUNCTION_TABLE_STREAM",
                fmt::MD_UNLOADED_MODULE_LIST_STREAM =>
                    "MD_UNLOADED_MODULE_LIST_STREAM",
                fmt::MD_MISC_INFO_STREAM =>
                    "MD_MISC_INFO_STREAM",
                fmt::MD_MEMORY_INFO_LIST_STREAM =>
                    "MD_MEMORY_INFO_LIST_STREAM",
                fmt::MD_THREAD_INFO_LIST_STREAM =>
                    "MD_THREAD_INFO_LIST_STREAM",
                fmt::MD_HANDLE_OPERATION_LIST_STREAM =>
                    "MD_HANDLE_OPERATION_LIST_STREAM",
                fmt::MD_LAST_RESERVED_STREAM =>
                    "MD_LAST_RESERVED_STREAM",
                fmt::MD_BREAKPAD_INFO_STREAM =>
                    "MD_BREAKPAD_INFO_STREAM",
                fmt::MD_ASSERTION_INFO_STREAM =>
                    "MD_ASSERTION_INFO_STREAM",
                fmt::MD_LINUX_CPU_INFO =>
                    "MD_LINUX_CPU_INFO",
                fmt::MD_LINUX_PROC_STATUS =>
                    "MD_LINUX_PROC_STATUS",
                fmt::MD_LINUX_LSB_RELEASE =>
                    "MD_LINUX_LSB_RELEASE",
                fmt::MD_LINUX_CMD_LINE =>
                    "MD_LINUX_CMD_LINE",
                fmt::MD_LINUX_ENVIRON =>
                    "MD_LINUX_ENVIRON",
                fmt::MD_LINUX_AUXV =>
                    "MD_LINUX_AUXV",
                fmt::MD_LINUX_MAPS =>
                    "MD_LINUX_MAPS",
                fmt::MD_LINUX_DSO_DEBUG =>
                    "MD_LINUX_DSO_DEBUG",
                _ => "unknown",
            }
        }

        try!(write!(f, r#"MDRawHeader
  signature            = {:#x}
  version              = {:#x}
  stream_count         = {}
  stream_directory_rva = {:#x}
  checksum             = {:#x}
  time_date_stamp      = {:#x}
  flags                = {:#x}

"#,
                    self.header.signature,
                    self.header.version,
                    self.header.stream_count,
                    self.header.stream_directory_rva,
                    self.header.checksum,
                    self.header.time_date_stamp,
                    // TODO: strftime(self.header.time_date_stamp)
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::fs::File;
    use super::*;

    fn read_test_minidump() -> Result<Minidump, Error> {
        let mut path = PathBuf::from(file!());
        path.pop();
        path.push("testdata/test.dmp");
        let f = File::open(&path).ok().expect(&format!("failed to open file: {:?}", path));
        Minidump::read(f)
    }

    #[test]
    fn test_read_minidump() {
        let dump = read_test_minidump().unwrap();
        assert_eq!(dump.streams.len(), 7);
    }

    #[test]
    fn test_module_list() {
        let mut dump = read_test_minidump().unwrap();
        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        assert_eq!(module_list.module_at_address(0x400000).unwrap().code_file(),
                   "c:\\test_app.exe");
        let modules = module_list.modules;
        assert_eq!(modules.len(), 13);
        assert_eq!(modules[0].base_address(), 0x400000);
        assert_eq!(modules[0].size(), 0x2d000);
        assert_eq!(modules[0].code_file(), "c:\\test_app.exe");
        assert_eq!(modules[0].code_identifier().unwrap(), "45D35F6C2d000");
        assert_eq!(modules[0].debug_file().unwrap(), "c:\\test_app.pdb");
        assert_eq!(modules[0].debug_identifier().unwrap(),
                   "5A9832E5287241C1838ED98914E9B7FF1");
        assert!(modules[0].version().is_none());

        assert_eq!(modules[12].base_address(), 0x76bf0000);
        assert_eq!(modules[12].size(), 0xb000);
        assert_eq!(modules[12].code_file(), "C:\\WINDOWS\\system32\\psapi.dll");
        assert_eq!(modules[12].code_identifier().unwrap(), "411096CAb000");
        assert_eq!(modules[12].debug_file().unwrap(), "psapi.pdb");
        assert_eq!(modules[12].debug_identifier().unwrap(),
                   "A5C3A1F9689F43D8AD228A09293889702");
        assert_eq!(modules[12].version().unwrap(), "5.1.2600.2180");

    }

    #[test]
    fn test_system_info() {
        let mut dump = read_test_minidump().unwrap();
        let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        assert_eq!(system_info.os(), "windows");
        assert_eq!(system_info.cpu(), "x86");
    }

    #[test]
    fn test_thread_list() {
        let mut dump = read_test_minidump().unwrap();
        let thread_list = dump.get_stream::<MinidumpThreadList>().unwrap();
        let ref threads = thread_list.threads;
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0].raw.thread_id, 0xbf4);
        assert_eq!(threads[1].raw.thread_id, 0x11c0);
        let id = threads[1].raw.thread_id;
        assert_eq!(thread_list.get_thread(id).unwrap().raw.thread_id, id);
        if let Some(ref ctx) = threads[0].context {
            assert_eq!(ctx.get_instruction_pointer(), 0x7c90eb94);
            assert_eq!(ctx.get_stack_pointer(), 0x12f320);
            if let &MinidumpContext { raw: MinidumpRawContext::X86(raw) } = ctx {
                assert_eq!(raw.eip, 0x7c90eb94);
            } else {
                assert!(false, "Wrong context type");
            }
        } else {
            assert!(false, "Missing context");
        }
    }
}
