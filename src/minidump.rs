// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::io::prelude::*;
use chrono::*;
use std::borrow::Cow;
use std::boxed::Box;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::SeekFrom;
use std::mem;
use std::path::Path;

pub use context::*;
use iostuff::*;
use minidump_format as md;
use range_map;
use system_info::*;

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
/// use minidump::Minidump;
/// use std::fs::File;
/// # use std::io;
///
/// # fn foo() -> io::Result<()> {
/// let file = try!(File::open("../testdata/test.dmp"));
/// let dump = Minidump::read(file).unwrap();
/// # Ok(())
/// # }
/// ```
///
/// [read]: struct.Minidump.html#method.read
/// [read_path]: struct.Minidump.html#method.read_path
#[allow(dead_code)]
pub struct Minidump {
    reader : Box<Readable + 'static>,
    pub header : md::MDRawHeader,
    streams : HashMap<u32, (u32, md::MDRawDirectory)>,
    swap : bool,
}

/// Errors encountered while reading a `Minidump`.
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
}

/* TODO
pub struct MinidumpMemoryList;
pub struct MinidumpAssertion;
pub struct MinidumpMemoryInfoList;
*/

/// The fundamental unit of data in a `Minidump`.
pub trait MinidumpStream {
    //TODO: associated_consts when that stabilizes.
    /// The stream type constant used in the `md::MDRawDirectory` entry.
    fn stream_type() -> u32;
    /// Read this `MinidumpStream` type from `f`.
    fn read<T : Readable>(f : &mut T, expected_size : usize) -> Result<Self, Error>;
}

/// An executable or shared library loaded in a process.
pub trait Module {
    /// The base address of this code module as it was loaded by the process.
    fn base_address(&self) -> u64;
    /// The size of the code module.
    fn size(&self) -> u64;
    /// The path or file name that the code module was loaded from.
    fn code_file(&self) -> Cow<str>;
    /// An identifying string used to discriminate between multiple versions and
    /// builds of the same code module.  This may contain a uuid, timestamp,
    /// version number, or any combination of this or other information, in an
    /// implementation-defined format.
    fn code_identifier(&self) -> Cow<str>;
    /// The filename containing debugging information associated with the code
    /// module.  If debugging information is stored in a file separate from the
    /// code module itself (as is the case when .pdb or .dSYM files are used),
    /// this will be different from code_file.  If debugging information is
    /// stored in the code module itself (possibly prior to stripping), this
    /// will be the same as code_file.
    fn debug_file(&self) -> Option<Cow<str>>;
    /// An identifying string similar to code_identifier, but identifies a
    /// specific version and build of the associated debug file.  This may be
    /// the same as code_identifier when the debug_file and code_file are
    /// identical or when the same identifier is used to identify distinct
    /// debug and code files.
    fn debug_identifier(&self) -> Option<Cow<str>>;
    /// A human-readable representation of the code module's version.
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

/// An executable or shared library loaded in the process at the time the `Minidump` was written.
pub struct MinidumpModule {
    /// The `MDRawModule` direct from the minidump file.
    pub raw : md::MDRawModule,
    /// The module name. This is stored separately in the minidump.
    name : String,
    /// A `CodeView` record, if one is present.
    pub codeview_info : Option<CodeView>,
    /// A misc debug record, if one is present.
    pub misc_info : Option<md::MDImageDebugMisc>,
}

/// A list of `MinidumpModule`s contained in a `Minidump`.
pub struct MinidumpModuleList {
    /// The modules, in the order they were stored in the minidump.
    pub modules : Vec<MinidumpModule>,
    /// Map from address range to index in modules. Use `MinidumpModuleList::module_at_address`.
    modules_by_addr : range_map::RangeMap<usize>,
}

/// The state of a thread from the process when the minidump was written.
pub struct MinidumpThread {
    /// The `MDRawThread` direct from the minidump file.
    pub raw : md::MDRawThread,
    /// The CPU context for the thread, if present.
    pub context : Option<MinidumpContext>,
    /// The stack memory for the thread, if present.
    pub stack : Option<MinidumpMemory>,
}

/// A list of `MinidumpThread`s contained in a `Minidump`.
pub struct MinidumpThreadList {
    /// The threads, in the order they were present in the `Minidump`.
    pub threads : Vec<MinidumpThread>,
    /// A map of thread id to index in `threads`.
    thread_ids : HashMap<u32, usize>,
}

/// Information about the system that generated the minidump.
pub struct MinidumpSystemInfo {
    /// The `MDRawSystemInfo` direct from the minidump.
    pub raw : md::MDRawSystemInfo,
    /// The operating system that generated the minidump.
    pub os : OS,
    /// The CPU on which the minidump was generated.
    pub cpu : CPU,
}

/// A region of memory from the process that wrote the minidump.
pub struct MinidumpMemory {
    /// The starting address of this range of memory.
    pub base_address : u64,
    /// The length of this range of memory.
    pub size : u64,
    /// The contents of the memory.
    pub bytes : Vec<u8>,
}

/// Miscellaneous information about the process that wrote the minidump.
pub struct MinidumpMiscInfo {
    /// The `MDRawMiscInfo` struct direct from the minidump.
    pub raw : md::MDRawMiscInfo,
    /// When the process started, if available.
    pub process_create_time : Option<DateTime<UTC>>,
}

/// Additional information about process state.
///
/// MinidumpBreakpadInfo wraps MDRawBreakpadInfo, which is an optional stream
/// in a minidump that provides additional information about the process state
/// at the time the minidump was generated.
pub struct MinidumpBreakpadInfo {
    raw : md::MDRawBreakpadInfo,
    /// The thread that wrote the minidump.
    pub dump_thread_id : Option<u32>,
    /// The thread that requested that a minidump be written.
    pub requesting_thread_id : Option<u32>,
}

/// The reason for a process crash.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CrashReason {
    Unknown,
}

/// Information about the exception that caused the minidump to be generated.
///
/// MinidumpException wraps MDRawExceptionStream, which contains information
/// about the exception that caused the minidump to be generated, if the
/// minidump was generated in an exception handler called as a result of an
/// exception.  It also provides access to a MinidumpContext object, which
/// contains the CPU context for the exception thread at the time the exception
/// occurred.
pub struct MinidumpException {
    pub raw : md::MDRawExceptionStream,
    pub thread_id : u32,
    pub context : Option<MinidumpContext>,
}

//======================================================
// Implementations


fn format_time_t(t : u32) -> String {
    if let Some(datetime) = NaiveDateTime::from_timestamp_opt(t as i64, 0) {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        String::new()
    }
}

fn flag(bits : u32, flag : u32) -> bool {
    (bits & flag) == flag
}

fn read_codeview_pdb<T : Readable>(f : &mut T, signature : u32, mut size : usize) -> Result<CodeView, Error> {
    let raw = match signature {
        md::MD_CVINFOPDB70_SIGNATURE => {
            size = size - mem::size_of::<md::MDCVInfoPDB70>() + 1;
            // ::<md::MDCVInfoPDB70>
            CodeViewPDBRaw::PDB70(try!(read(f).or(Err(Error::CodeViewReadFailure))))
        },
        md::MD_CVINFOPDB20_SIGNATURE => {
            size = size -mem::size_of::<md::MDCVInfoPDB20>() + 1;
            // ::<md::MDCVInfoPDB20>
            CodeViewPDBRaw::PDB20(try!(read(f).or(Err(Error::CodeViewReadFailure))))
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

fn read_codeview<T : Readable>(f : &mut T, location : md::MDLocationDescriptor) -> Result<CodeView, Error> {
    let size = location.data_size as usize;
    try!(f.seek(SeekFrom::Start(location.rva as u64)).or(Err(Error::CodeViewReadFailure)));
    // The CodeView data can contain a variable-length string at the end
    // and also can be one of a few different formats. Try to read the
    // signature first to figure out what format the data is.
    // TODO: swap
    let signature : u32 = try!(read(f).or(Err(Error::CodeViewReadFailure)));
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
    /// Create a `MinidumpModule` with some basic info.
    ///
    /// Useful for testing.
    pub fn new(base : u64, size : u32, name : &str) -> MinidumpModule {
        MinidumpModule {
            raw: md::MDRawModule {
                base_of_image: base,
                size_of_image: size,
                .. md::MDRawModule::default()
            },
            name: String::from(name),
            codeview_info: None,
            misc_info: None,
        }
    }

    pub fn read<T: Readable>(f : &mut T, raw : md::MDRawModule) -> Result<MinidumpModule, Error> {
        let name = try!(read_string_utf16(f, raw.module_name_rva as u64)
                        .or(Err(Error::CodeViewReadFailure)));
        let cv = if raw.cv_record.data_size > 0 {
            Some(try!(read_codeview(f, raw.cv_record)
                      .or(Err(Error::CodeViewReadFailure))))
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

    /// Write a human-readable description of this `MinidumpModule` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, r#"MDRawModule
  base_of_image                   = {:#x}
  size_of_image                   = {:#x}
  checksum                        = {:#x}
  time_date_stamp                 = {:#x} {}
  module_name_rva                 = {:#x}
  version_info.signature          = {:#x}
  version_info.struct_version     = {:#x}
  version_info.file_version       = {:#x}:{:#x}
  version_info.product_version    = {:#x}:{:#x}
  version_info.file_flags_mask    = {:#x}
  version_info.file_flags         = {:#x}
  version_info.file_os            = {:#x}
  version_info.file_type          = {:#x}
  version_info.file_subtype       = {:#x}
  version_info.file_date          = {:#x}:{:#x}
  cv_record.data_size             = {}
  cv_record.rva                   = {:#x}
  misc_record.data_size           = {}
  misc_record.rva                 = {:#x}
  (code_file)                     = "{}"
  (code_identifier)               = "{}"
  (cv_record).cv_signature        = {:#x}
  (cv_record).signature           = {}
  (cv_record).age                 = {}
  (cv_record).pdb_file_name       = {}
  (misc_record)                   = {}
  (debug_file)                    = "{}"
  (debug_identifier)              = "{}"
  (version)                       = {}

"#,
                    self.raw.base_of_image,
                    self.raw.size_of_image,
                    self.raw.checksum,
                    self.raw.time_date_stamp,
                    format_time_t(self.raw.time_date_stamp),
                    self.raw.module_name_rva,
                    self.raw.version_info.signature,
                    self.raw.version_info.struct_version,
                    self.raw.version_info.file_version_hi,
                    self.raw.version_info.file_version_lo,
                    self.raw.version_info.product_version_hi,
                    self.raw.version_info.product_version_lo,
                    self.raw.version_info.file_flags_mask,
                    self.raw.version_info.file_flags,
                    self.raw.version_info.file_os,
                    self.raw.version_info.file_type,
                    self.raw.version_info.file_subtype,
                    self.raw.version_info.file_date_hi,
                    self.raw.version_info.file_date_lo,
                    self.raw.cv_record.data_size,
                    self.raw.cv_record.rva,
                    self.raw.misc_record.data_size,
                    self.raw.misc_record.rva,
                    self.code_file(),
                    self.code_identifier(),
                    0, //TODO: cv_record.cv_signature
                    "", //TODO: cv_record.signature
                    0, //TODO: cv_record.age
                    "", //TODO: cv_record.pdb_file_name
                    "", //TODO: misc_record
                    "", //TODO: debug_file
                    "", //TODO: debug_identifier
                    "", //TODO: version
                    ));
        Ok(())
    }
}

impl Clone for CodeViewPDBRaw {
    fn clone(&self) -> CodeViewPDBRaw {
        match self {
            &CodeViewPDBRaw::PDB20(raw) => CodeViewPDBRaw::PDB20(raw.clone()),
            &CodeViewPDBRaw::PDB70(raw) => CodeViewPDBRaw::PDB70(raw.clone()),
        }
    }
}

impl Clone for CodeView {
    fn clone(&self) -> CodeView {
        match self {
            &CodeView::PDB { ref raw, ref file } => CodeView::PDB { raw: raw.clone(), file: file.clone() },
            &CodeView::Unknown { ref bytes } => CodeView::Unknown { bytes: bytes.clone() },
        }
    }
}

impl Clone for MinidumpModule {
    fn clone(&self) -> MinidumpModule {
        MinidumpModule {
            raw: self.raw.clone(),
            name: self.name.clone(),
            codeview_info: self.codeview_info.clone(),
            misc_info: self.misc_info.clone(),
        }
    }
}

impl Module for MinidumpModule {
    fn base_address(&self) -> u64 { self.raw.base_of_image }
    fn size(&self) -> u64 { self.raw.size_of_image as u64 }
    fn code_file(&self) -> Cow<str> { Cow::Borrowed(&self.name) }
    fn code_identifier(&self) -> Cow<str> {
        // TODO: Breakpad stubs this out on non-Windows.
        Cow::Owned(format!("{0:08X}{1:x}", self.raw.time_date_stamp,
                           self.raw.size_of_image))
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
            flag(self.raw.version_info.struct_version, md::MD_VSFIXEDFILEINFO_VERSION) {
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

fn read_stream_list<T : Copy, U: Readable>(f : &mut U, expected_size : usize) -> Result<Vec<T>, Error> {
    if expected_size < mem::size_of::<u32>() {
        return Err(Error::StreamSizeMismatch);
    }

    // TODO: swap
    let u : u32 = try!(read(f).or(Err(Error::StreamReadFailure)));
    let count = u as usize;
    match expected_size - (mem::size_of::<u32>() + count * mem::size_of::<T>()) {
        0 => {},
        4 => {
            // 4 bytes of padding.
            let _pad = try!(read_bytes(f, 4).or(Err(Error::StreamReadFailure)));
        },
        _ => return Err(Error::StreamSizeMismatch)
    };
    // read count T raw stream entries
    let mut raw_entries = Vec::with_capacity(count);
    for _ in 0..count {
        let raw : T = try!(read(f).or(Err(Error::StreamReadFailure)));
        raw_entries.push(raw);
    }
    Ok(raw_entries)
}

impl MinidumpModuleList {
    /// Return an empty `MinidumpModuleList`.
    pub fn new() -> MinidumpModuleList {
        MinidumpModuleList {
            modules: vec!(),
            modules_by_addr: range_map::RangeMap::<usize>::new()
        }
    }
    /// Create a `MinidumpModuleList` from a list of `MinidumpModule`s.
    pub fn from_modules(modules : Vec<MinidumpModule>) -> MinidumpModuleList {
        let mut map = range_map::RangeMap::<usize>::new();
        for (i, module) in modules.iter().enumerate() {
            if let Err(_) = map.insert((module.base_address(), module.base_address() + module.size()), i) {
                //TODO: Ignoring errors here from overlapping modules.
            }
        }
        MinidumpModuleList { modules: modules, modules_by_addr: map }
    }

    /// Returns the module corresponding to the main executable.
    pub fn main_module(&self) -> Option<&MinidumpModule> {
        // The main code module is the first one present in a minidump file's
        // MDRawModuleList.
        if self.modules.len() > 0 {
            Some(&self.modules[0])
        } else {
            None
        }
    }

    /// Return a `MinidumpModule` whose address range covers `addr`.
    pub fn module_at_address(&self, addr : u64) -> Option<&MinidumpModule> {
        return if let Some(index) = self.modules_by_addr.lookup(addr) {
            Some(&self.modules[index])
        } else {
            None
        }
    }

    /// Return modules in order by memory address.
    pub fn by_addr(&self) -> Vec<&MinidumpModule> {
        // TODO: would be nice to return an iterator here, but the type
        // ergonomics are horrible.
        self.modules_by_addr.iter().map(|&((_, _), index)| &self.modules[index]).collect()
    }

    /// Write a human-readable description of this `MinidumpModuleList` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, "MinidumpModuleList
  module_count = {}

", self.modules.len()));
        for (i, module) in self.modules.iter().enumerate() {
            try!(writeln!(f, "module[{}]", i));
            try!(module.print(f));
        }
        Ok(())
    }
}

impl MinidumpStream for MinidumpModuleList {
    fn stream_type() -> u32 { md::MD_MODULE_LIST_STREAM }
    fn read<T: Readable>(f : &mut T, expected_size : usize) -> Result<MinidumpModuleList, Error> {
        let raw_modules : Vec<md::MDRawModule> = try!(read_stream_list(f, expected_size));
        // read auxiliary data for each module
        let mut modules = Vec::with_capacity(raw_modules.len());
        for raw in raw_modules.into_iter() {
            // TODO: swap
            if raw.size_of_image == 0 || raw.size_of_image as u64 > (u64::max_value() - raw.base_of_image) {
                // Bad image size.
                // TODO: just drop this module, keep the rest?
                return Err(Error::ModuleReadFailure);
            }
            modules.push(try!(MinidumpModule::read(f, raw)));
        }
        Ok(MinidumpModuleList::from_modules(modules))
    }
}

impl Clone for MinidumpModuleList {
    fn clone(&self) -> MinidumpModuleList {
        MinidumpModuleList {
            modules: self.modules.clone(),
            modules_by_addr: self.modules_by_addr.clone(),
        }
    }
}

impl MinidumpMemory {
    pub fn read<T : Readable>(f : &mut T, desc : &md::MDMemoryDescriptor) -> Result<MinidumpMemory, Error> {
        try!(f.seek(SeekFrom::Start(desc.memory.rva as u64)).or(Err(Error::StreamReadFailure)));
        let bytes = try!(read_bytes(f, desc.memory.data_size as usize).or(Err(Error::DataError)));
        Ok(MinidumpMemory {
            base_address: desc.start_of_memory_range,
            size: desc.memory.data_size as u64,
            bytes: bytes,
        })
    }

    /// Get `mem::size_of::<T>()` bytes of memory at `addr` from this region.
    ///
    /// Return `None` if the requested address range falls out of the bounds
    /// of this memory region.
    pub fn get_memory_at_address<T : Copy + Sized>(&self, addr : u64) -> Option<T> {
        let in_range = |a : u64| {
            a >= self.base_address && a < (self.base_address + self.size)
        };
        let size = mem::size_of::<T>();
        if !in_range(addr) || !in_range(addr + size as u64 - 1) {
            return None;
        }
        let start = (addr - self.base_address) as usize;
        let end = start + size;
        Some(transmogrify::<T>(&self.bytes[start..end]))
    }

    /// Write a human-readable description of this `MinidumpMemory` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
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
    /// Write a human-readable description of this `MinidumpThread` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
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
    fn read<T: Readable>(f : &mut T, expected_size : usize) -> Result<MinidumpThreadList, Error> {
        let raw_threads : Vec<md::MDRawThread> = try!(read_stream_list(f, expected_size));
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
    /// Get the thread with id `id` from this thread list if it exists.
    pub fn get_thread(&self, id : u32) -> Option<&MinidumpThread> {
        match self.thread_ids.get(&id) {
            None => None,
            Some(&index) => Some(&self.threads[index]),
        }
    }

    /// Write a human-readable description of this `MinidumpThreadList` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
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

impl MinidumpStream for MinidumpSystemInfo {
    fn stream_type() -> u32 { md::MD_SYSTEM_INFO_STREAM }
    fn read<T: Readable>(f : &mut T, expected_size : usize) -> Result<MinidumpSystemInfo, Error> {
        if expected_size != mem::size_of::<md::MDRawSystemInfo>() {
            return Err(Error::StreamReadFailure);
        }
        let raw : md::MDRawSystemInfo = try!(read(f).or(Err(Error::StreamReadFailure)));
        Ok(MinidumpSystemInfo {
            raw: raw,
            os: OS::from_u32(raw.platform_id),
            cpu: CPU::from_u32(raw.processor_architecture as u32),
        })
    }
}

impl MinidumpSystemInfo {
    /// Write a human-readable description of this `MinidumpSystemInfo` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, "MDRawSystemInfo
  processor_architecture                     = {:#x}
  processor_level                            = {}
  processor_revision                         = {:#x}
  number_of_processors                       = {}
  product_type                               = {}
  major_version                              = {}
  minor_version                              = {}
  build_number                               = {}
  platform_id                                = {:#x}
  csd_version_rva                            = {:#x}
  suite_mask                                 = {:#x}

",
                    self.raw.processor_architecture,
                    self.raw.processor_level,
                    self.raw.processor_revision,
                    self.raw.number_of_processors,
                    self.raw.product_type,
                    self.raw.major_version,
                    self.raw.minor_version,
                    self.raw.build_number,
                    self.raw.platform_id,
                    self.raw.csd_version_rva,
                    self.raw.suite_mask));
        // TODO: cpu info etc
        Ok(())
    }
}

impl MinidumpStream for MinidumpMiscInfo {
    fn stream_type() -> u32 { md::MD_MISC_INFO_STREAM }
    fn read<T: Readable>(f : &mut T, expected_size : usize) -> Result<MinidumpMiscInfo, Error> {
        // Breakpad uses a single MDRawMiscInfo to represent several structs
        // of progressively larger sizes which are supersets of the smaller
        // ones.
        let mut bytes = try!(read_bytes(f, expected_size).or(Err(Error::StreamReadFailure)));
        if bytes.len() < mem::size_of::<md::MDRawMiscInfo>() {
            let padding = vec![0; mem::size_of::<md::MDRawMiscInfo>() - bytes.len()];
            bytes.extend(padding.into_iter());
        }
        let raw = transmogrify::<md::MDRawMiscInfo>(&bytes[..]);
        let process_create_time = if flag(raw.flags1, md::MD_MISCINFO_FLAGS1_PROCESS_TIMES) {
            Some(UTC.timestamp(raw.process_create_time as i64, 0))
        } else {
            None
        };
        Ok(MinidumpMiscInfo {
            raw: raw,
            process_create_time: process_create_time
        })
    }
}

impl MinidumpMiscInfo {
    /// Write a human-readable description of this `MinidumpMiscInfo` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, "MDRawMiscInfo
  size_of_info                 = {}
  flags1                       = {:#x}
  process_id                   = ",
                    self.raw.size_of_info,
                    self.raw.flags1));
        if flag(self.raw.flags1, md::MD_MISCINFO_FLAGS1_PROCESS_ID) {
            try!(writeln!(f, "{}", self.raw.process_id));
        } else {
            try!(writeln!(f, "(invalid)"));
        }
        try!(write!(f, "  process_create_time          = "));
        if flag(self.raw.flags1, md::MD_MISCINFO_FLAGS1_PROCESS_TIMES) {
            try!(writeln!(f, "{:#x} {}",
                          self.raw.process_create_time,
                          format_time_t(self.raw.process_create_time),
                          ));
        } else {
            try!(writeln!(f, "(invalid)"));
        }
        try!(write!(f, "  process_user_time            = "));
        if flag(self.raw.flags1, md::MD_MISCINFO_FLAGS1_PROCESS_TIMES) {
            try!(writeln!(f, "{}", self.raw.process_user_time));
        } else {
            try!(writeln!(f, "(invalid)"));
        }
        try!(write!(f, "  process_kernel_time          = "));
        if flag(self.raw.flags1, md::MD_MISCINFO_FLAGS1_PROCESS_TIMES) {
            try!(writeln!(f, "{}", self.raw.process_kernel_time));
        } else {
            try!(writeln!(f, "(invalid)"));
        }
        // TODO: version 2-4 fields
        try!(writeln!(f, ""));
        Ok(())
    }
}

impl MinidumpStream for MinidumpBreakpadInfo {
    fn stream_type() -> u32 { md::MD_BREAKPAD_INFO_STREAM }
    fn read<T: Readable>(f : &mut T, expected_size : usize) -> Result<MinidumpBreakpadInfo, Error> {
        if expected_size != mem::size_of::<md::MDRawBreakpadInfo>() {
            return Err(Error::StreamReadFailure);
        }
        let raw : md::MDRawBreakpadInfo = try!(read(f).or(Err(Error::StreamReadFailure)));
        let dump_thread = if flag(raw.validity, md::MD_BREAKPAD_INFO_VALID_DUMP_THREAD_ID) {
            Some(raw.dump_thread_id)
        } else {
            None
        };
        let requesting_thread = if flag(raw.validity, md::MD_BREAKPAD_INFO_VALID_REQUESTING_THREAD_ID) {
            Some(raw.requesting_thread_id)
        } else {
            None
        };
        Ok(MinidumpBreakpadInfo {
            raw: raw,
            dump_thread_id: dump_thread,
            requesting_thread_id: requesting_thread,
        })
    }
}

fn option_or_invalid<T : fmt::LowerHex>(what : &Option<T>) -> Cow<str> {
    match *what {
        Some(ref val) => Cow::Owned(format!("{:#x}", val)),
        None => Cow::Borrowed("(invalid)"),
    }
}

impl MinidumpBreakpadInfo {
    /// Write a human-readable description of this `MinidumpBreakpadInfo` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, "MDRawBreakpadInfo
  validity             = {:#x}
  dump_thread_id       = {}
  requesting_thread_id = {}
",
                    self.raw.validity,
                    option_or_invalid(&self.dump_thread_id),
                    option_or_invalid(&self.requesting_thread_id),
                    ));
        Ok(())
    }
}

impl CrashReason {
    /// Get a `CrashReason` from a `MDRawExceptionStream` for a given `OS`.
    fn from_exception(_raw : &md::MDRawExceptionStream,
                      _os : OS) -> CrashReason {
        // TODO: flesh this out
        CrashReason::Unknown
    }
}

impl fmt::Display for CrashReason {
    /// A string describing the crash reason.
    ///
    /// This is OS- and possibly CPU-specific.
    /// For example, "EXCEPTION_ACCESS_VIOLATION" (Windows),
    /// "EXC_BAD_ACCESS / KERN_INVALID_ADDRESS" (Mac OS X), "SIGSEGV"
    /// (other Unix).
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match *self {
            CrashReason::Unknown => "unknown",
        })
    }
}

impl MinidumpStream for MinidumpException {
    fn stream_type() -> u32 { md::MD_EXCEPTION_STREAM }
    fn read<T: Readable>(f : &mut T, expected_size : usize) -> Result<MinidumpException, Error> {
        if expected_size != mem::size_of::<md::MDRawExceptionStream>() {
            return Err(Error::StreamReadFailure);
        }
        let raw : md::MDRawExceptionStream = try!(read(f).or(Err(Error::StreamReadFailure)));
        let context = MinidumpContext::read(f, &raw.thread_context).ok();
        Ok(MinidumpException {
            raw: raw,
            thread_id: raw.thread_id,
            context: context,
        })
    }
}

impl MinidumpException {
    /// Get the crash address for an exception.
    pub fn get_crash_address(&self, os : OS) -> u64 {
        let mut addr = self.raw.exception_record.exception_address;
        match os {
            OS::Windows => {
                if (self.raw.exception_record.exception_code == md::MD_EXCEPTION_CODE_WIN_ACCESS_VIOLATION || self.raw.exception_record.exception_code == md::MD_EXCEPTION_CODE_WIN_IN_PAGE_ERROR) && self.raw.exception_record.number_parameters >= 2 {
                    addr = self.raw.exception_record.exception_information[1];
                }
            },
            _ => {}
        }
        addr
    }
    /// Get the crash reason for an exception.
    pub fn get_crash_reason(&self, os : OS) -> CrashReason {
        CrashReason::from_exception(&self.raw, os)
    }

    /// Write a human-readable description of this `MinidumpException` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T : Write>(&self, f : &mut T) -> io::Result<()> {
        try!(write!(f, "MDException
  thread_id                                  = {:#x}
  exception_record.exception_code            = {:#x}
  exception_record.exception_flags           = {:#x}
  exception_record.exception_record          = {:#x}
  exception_record.exception_address         = {:#x}
  exception_record.number_parameters         = {}
",
                    self.thread_id,
                    self.raw.exception_record.exception_code,
                    self.raw.exception_record.exception_flags,
                    self.raw.exception_record.exception_record,
                    self.raw.exception_record.exception_address,
                    self.raw.exception_record.number_parameters,
                    ));
        for i in 0..self.raw.exception_record.number_parameters as usize {
            try!(writeln!(f, "  exception_record.exception_information[{:2}] = {:#x}",
                          i,
                          self.raw.exception_record.exception_information[i]));
        }
        try!(write!(f, "  thread_context.data_size                   = {}
  thread_context.rva                         = {:#x}
",
                    self.raw.thread_context.data_size,
                    self.raw.thread_context.rva));
        if let Some(ref context) = self.context {
            try!(writeln!(f, ""));
            try!(context.print(f));
        } else {
            try!(write!(f, "  (no context)

"));
        }
        Ok(())
    }
}

impl Minidump {
    /// Read a `Minidump` from a `Path` to a file on disk.
    pub fn read_path(path : &Path) -> Result<Minidump, Error> {
        let f = try!(File::open(path).or(Err(Error::FileNotFound)));
        Minidump::read(f)
    }

    /// Read a `Minidump` from a [`Readable`][readable].
    ///
    /// [readable]: trait.Readable.html
    pub fn read<T : Readable + 'static>(mut f : T) -> Result<Minidump, Error> {
        let header : md::MDRawHeader = try!(read(&mut f).or(Err(Error::MissingHeader)));
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
            let dir : md::MDRawDirectory = try!(read(&mut f).or(Err(Error::MissingDirectory)));
            streams.insert(dir.stream_type, (i, dir));
        }
        Ok(Minidump {
            reader: Box::new(f),
            header: header,
            streams: streams,
            swap: swap
        })
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
                try!(self.reader.seek(SeekFrom::Start(dir.location.rva as u64)).or(Err(Error::StreamReadFailure)));
                // TODO: cache result
                T::read(&mut self.reader, dir.location.data_size as usize)
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
                    format_time_t(self.header.time_date_stamp),
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
