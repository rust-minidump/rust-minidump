// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use chrono::prelude::*;
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, Encoding};
use failure::Fail;
use memmap::Mmap;
use num_traits::FromPrimitive;
use scroll::ctx::{SizeWith, TryFromCtx};
use scroll::{self, Pread, BE, LE};
use std::borrow::Cow;
use std::boxed::Box;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::iter;
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
use std::path::Path;
use std::str;

pub use crate::context::*;
use crate::system_info::{Cpu, Os};
use minidump_common::format as md;
use minidump_common::format::{CvSignature, MINIDUMP_STREAM_TYPE};
use minidump_common::traits::{IntoRangeMapSafe, Module};
use range_map::{Range, RangeMap};

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
///
/// # fn foo() -> Result<(), minidump::Error> {
/// let dump = Minidump::read_path("../testdata/test.dmp")?;
/// # Ok(())
/// # }
/// ```
///
/// [read]: struct.Minidump.html#method.read
/// [read_path]: struct.Minidump.html#method.read_path
#[derive(Debug)]
pub struct Minidump<'a, T>
where
    T: Deref<Target = [u8]> + 'a,
{
    data: T,
    /// The raw minidump header from the file.
    pub header: md::MINIDUMP_HEADER,
    streams: HashMap<u32, (u32, md::MINIDUMP_DIRECTORY)>,
    /// The endianness of this minidump file.
    pub endian: scroll::Endian,
    _phantom: PhantomData<&'a [u8]>,
}

/// Errors encountered while reading a `Minidump`.
#[derive(Debug, Fail, PartialEq)]
pub enum Error {
    #[fail(display = "File not found")]
    FileNotFound,
    #[fail(display = "I/O error")]
    IoError,
    #[fail(display = "Missing minidump header")]
    MissingHeader,
    #[fail(display = "Header mismatch")]
    HeaderMismatch,
    #[fail(display = "Minidump version mismatch")]
    VersionMismatch,
    #[fail(display = "Missing stream directory")]
    MissingDirectory,
    #[fail(display = "Error reading stream")]
    StreamReadFailure,
    #[fail(
        display = "Stream size mismatch: expected {} byes, found {} bytes",
        expected, actual
    )]
    StreamSizeMismatch { expected: usize, actual: usize },
    #[fail(display = "Stream not found")]
    StreamNotFound,
    #[fail(display = "Module read failure")]
    ModuleReadFailure,
    #[fail(display = "Memory read failure")]
    MemoryReadFailure,
    #[fail(display = "Data error")]
    DataError,
    #[fail(display = "Error reading CodeView data")]
    CodeViewReadFailure,
}

/* TODO
pub struct MinidumpMemoryInfoList;
*/

/// The fundamental unit of data in a `Minidump`.
pub trait MinidumpStream<'a>: Sized {
    /// The stream type constant used in the `md::MDRawDirectory` entry.
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE;
    /// Read this `MinidumpStream` type from `bytes`.
    ///
    /// `bytes` is the contents of this specific stream.
    /// `all` refers to the full contents of the minidump, for reading auxilliary data
    /// referred to with `MINIDUMP_LOCATION_DESCRIPTOR`s.
    fn read(bytes: &'a [u8], all: &'a [u8], endian: scroll::Endian) -> Result<Self, Error>;
}

/// CodeView data describes how to locate debug symbols
#[derive(Debug, Clone)]
pub enum CodeView {
    /// PDB 2.0 format data in a separate file
    Pdb20(md::CV_INFO_PDB20),
    /// PDB 7.0 format data in a separate file (most common)
    Pdb70(md::CV_INFO_PDB70),
    /// Indicates data is in an ELF binary with build ID `build_id`
    Elf(md::CV_INFO_ELF),
    /// An unknown format containing the raw bytes of data
    Unknown(Vec<u8>),
}

/// An executable or shared library loaded in the process at the time the `Minidump` was written.
#[derive(Debug, Clone)]
pub struct MinidumpModule {
    /// The `MINIDUMP_MODULE` direct from the minidump file.
    pub raw: md::MINIDUMP_MODULE,
    /// The module name. This is stored separately in the minidump.
    pub name: String,
    /// A `CodeView` record, if one is present.
    pub codeview_info: Option<CodeView>,
    /// A misc debug record, if one is present.
    pub misc_info: Option<md::IMAGE_DEBUG_MISC>,
}

/// A list of `MinidumpModule`s contained in a `Minidump`.
#[derive(Debug, Clone)]
pub struct MinidumpModuleList {
    /// The modules, in the order they were stored in the minidump.
    modules: Vec<MinidumpModule>,
    /// Map from address range to index in modules. Use `MinidumpModuleList::module_at_address`.
    modules_by_addr: RangeMap<u64, usize>,
}

/// The state of a thread from the process when the minidump was written.
#[derive(Debug)]
pub struct MinidumpThread<'a> {
    /// The `MINIDUMP_THREAD` direct from the minidump file.
    pub raw: md::MINIDUMP_THREAD,
    /// The CPU context for the thread, if present.
    pub context: Option<MinidumpContext>,
    /// The stack memory for the thread, if present.
    pub stack: Option<MinidumpMemory<'a>>,
}

/// A list of `MinidumpThread`s contained in a `Minidump`.
#[derive(Debug)]
pub struct MinidumpThreadList<'a> {
    /// The threads, in the order they were present in the `Minidump`.
    pub threads: Vec<MinidumpThread<'a>>,
    /// A map of thread id to index in `threads`.
    thread_ids: HashMap<u32, usize>,
}

/// Information about the system that generated the minidump.
#[derive(Debug)]
pub struct MinidumpSystemInfo {
    /// The `MINIDUMP_SYSTEM_INFO` direct from the minidump
    pub raw: md::MINIDUMP_SYSTEM_INFO,
    /// The operating system that generated the minidump
    pub os: Os,
    /// The CPU on which the minidump was generated
    pub cpu: Cpu,
}

/// A region of memory from the process that wrote the minidump.
#[derive(Debug)]
pub struct MinidumpMemory<'a> {
    /// The raw `MINIDUMP_MEMORY_DESCRIPTOR` from the minidump.
    pub desc: md::MINIDUMP_MEMORY_DESCRIPTOR,
    /// The starting address of this range of memory.
    pub base_address: u64,
    /// The length of this range of memory.
    pub size: u64,
    /// The contents of the memory.
    pub bytes: &'a [u8],
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum RawMiscInfo {
    MiscInfo(md::MINIDUMP_MISC_INFO),
    MiscInfo2(md::MINIDUMP_MISC_INFO_2),
    MiscInfo3(md::MINIDUMP_MISC_INFO_3),
    MiscInfo4(md::MINIDUMP_MISC_INFO_4),
    MiscInfo5(md::MINIDUMP_MISC_INFO_5),
}

/// Miscellaneous information about the process that wrote the minidump.
#[derive(Debug)]
pub struct MinidumpMiscInfo {
    /// The `MINIDUMP_MISC_INFO` struct direct from the minidump.
    pub raw: RawMiscInfo,
}

/// Additional information about process state.
///
/// MinidumpBreakpadInfo wraps MINIDUMP_BREAKPAD_INFO, which is an optional stream
/// in a minidump that provides additional information about the process state
/// at the time the minidump was generated.
#[derive(Debug)]
pub struct MinidumpBreakpadInfo {
    raw: md::MINIDUMP_BREAKPAD_INFO,
    /// The thread that wrote the minidump.
    pub dump_thread_id: Option<u32>,
    /// The thread that requested that a minidump be written.
    pub requesting_thread_id: Option<u32>,
}

/// The reason for a process crash.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CrashReason {
    Unknown,
}

/// Information about the exception that caused the minidump to be generated.
///
/// `MinidumpException` wraps `MINIDUMP_EXCEPTION_STREAM`, which contains information
/// about the exception that caused the minidump to be generated, if the
/// minidump was generated in an exception handler called as a result of an
/// exception.  It also provides access to a `MinidumpContext` object, which
/// contains the CPU context for the exception thread at the time the exception
/// occurred.
#[derive(Debug)]
pub struct MinidumpException {
    /// The raw exception information from the minidump stream.
    pub raw: md::MINIDUMP_EXCEPTION_STREAM,
    /// The thread that encountered this exception.
    pub thread_id: u32,
    /// If present, the CPU context from the time the thread encountered the exception.
    ///
    /// This should be used in place of the context contained within the thread with id
    /// `thread_id`, since it points to the code location where the exception happened,
    /// without any exception handling routines that are likely to be on the stack after
    /// that point.
    pub context: Option<MinidumpContext>,
}

/// A list of memory regions included in a minidump.
#[derive(Debug)]
pub struct MinidumpMemoryList<'a> {
    /// The memory regions, in the order they were stored in the minidump.
    regions: Vec<MinidumpMemory<'a>>,
    /// Map from address range to index in regions. Use `MinidumpMemoryList::memory_at_address`.
    regions_by_addr: RangeMap<u64, usize>,
}

/// Information about an assertion that caused a crash.
#[derive(Debug)]
pub struct MinidumpAssertion {
    pub raw: md::MINIDUMP_ASSERTION_INFO,
}

/// A typed annotation object.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum MinidumpAnnotation {
    /// An invalid annotation. Reserved for internal use.
    Invalid,
    /// A `NUL`-terminated C-string.
    String(String),
    /// Clients may declare their own custom types.
    UserDefined(md::MINIDUMP_ANNOTATION),
    /// An unsupported annotation from a future crashpad version.
    Unsupported(md::MINIDUMP_ANNOTATION),
}

impl PartialEq for MinidumpAnnotation {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Invalid, Self::Invalid) => true,
            (Self::String(a), Self::String(b)) => a == b,
            _ => false,
        }
    }
}

/// Additional Crashpad-specific information about a module carried within a minidump file.
#[derive(Debug)]
pub struct MinidumpModuleCrashpadInfo {
    /// The raw crashpad module extension information.
    pub raw: md::MINIDUMP_MODULE_CRASHPAD_INFO,
    /// Index of the corresponding module in the `MinidumpModuleList`.
    pub module_index: usize,
    pub list_annotations: Vec<String>,
    pub simple_annotations: BTreeMap<String, String>,
    pub annotation_objects: BTreeMap<String, MinidumpAnnotation>,
}

/// Additional Crashpad-specific information carried within a minidump file.
#[derive(Debug)]
pub struct MinidumpCrashpadInfo {
    pub raw: md::MINIDUMP_CRASHPAD_INFO,
    pub simple_annotations: BTreeMap<String, String>,
    pub module_list: Vec<MinidumpModuleCrashpadInfo>,
}

//======================================================
// Implementations

fn format_time_t(t: u32) -> String {
    if let Some(datetime) = NaiveDateTime::from_timestamp_opt(t as i64, 0) {
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        String::new()
    }
}

fn format_system_time(time: &md::SYSTEMTIME) -> String {
    // Note this drops the day_of_week field on the ground -- is that fine?
    if let Some(date) =
        NaiveDate::from_ymd_opt(time.year as i32, time.month as u32, time.day as u32)
    {
        let time = NaiveTime::from_hms_milli(
            time.hour as u32,
            time.minute as u32,
            time.second as u32,
            time.milliseconds as u32,
        );
        let datetime = NaiveDateTime::new(date, time);
        datetime.format("%Y-%m-%d %H:%M:%S:%f").to_string()
    } else {
        "<invalid date>".to_owned()
    }
}

/// Produce a slice of `bytes` corresponding to the offset and size in `loc`, or an
/// `Error` if the data is not fully contained within `bytes`.
fn location_slice<'a>(
    bytes: &'a [u8],
    loc: &md::MINIDUMP_LOCATION_DESCRIPTOR,
) -> Result<&'a [u8], Error> {
    let start = loc.rva as usize;
    start
        .checked_add(loc.data_size as usize)
        .and_then(|end| bytes.get(start..end))
        .ok_or(Error::StreamReadFailure)
}

/// Read a u32 length-prefixed UTF-16 string from `bytes` at `offset`.
fn read_string_utf16(
    offset: &mut usize,
    bytes: &[u8],
    endian: scroll::Endian,
) -> Result<String, ()> {
    let u: u32 = bytes.gread_with(offset, endian).or(Err(()))?;
    let size = u as usize;
    if size % 2 != 0 || (*offset + size) > bytes.len() {
        return Err(());
    }
    match UTF_16LE.decode(&bytes[*offset..*offset + size], DecoderTrap::Strict) {
        Ok(s) => {
            *offset += size;
            Ok(s)
        }
        Err(_) => Err(()),
    }
}

#[inline]
fn read_string_utf8_unterminated<'a>(
    offset: &mut usize,
    bytes: &'a [u8],
    endian: scroll::Endian,
) -> Result<&'a str, ()> {
    let length: u32 = bytes.gread_with(offset, endian).or(Err(()))?;
    let slice = bytes.gread_with(offset, length as usize).or(Err(()))?;
    std::str::from_utf8(slice).or(Err(()))
}

fn read_string_utf8<'a>(
    offset: &mut usize,
    bytes: &'a [u8],
    endian: scroll::Endian,
) -> Result<&'a str, ()> {
    let string = read_string_utf8_unterminated(offset, bytes, endian)?;
    match bytes.gread(offset) {
        Ok(0u8) => Ok(string),
        _ => Err(()),
    }
}

/// Convert `bytes` with trailing NUL characters to a string
fn string_from_bytes_nul(bytes: &[u8]) -> Option<Cow<'_, str>> {
    bytes
        .split(|&b| b == 0)
        .next()
        .map(|b| String::from_utf8_lossy(b))
}

/// Format `bytes` as a String of hex digits
fn bytes_to_hex(bytes: &[u8]) -> String {
    let hex_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    hex_bytes.join("")
}

/// Attempt to read a CodeView record from `data` at `location`
fn read_codeview(
    location: &md::MINIDUMP_LOCATION_DESCRIPTOR,
    data: &[u8],
    endian: scroll::Endian,
) -> Result<CodeView, failure::Error> {
    let bytes = location_slice(data, location)?;
    // The CodeView data can be one of a few different formats. Try to read the
    // signature first to figure out what format the data is.
    let signature: u32 = bytes.pread_with(0, endian)?;
    Ok(match CvSignature::from_u32(signature) {
        // PDB data has two known versions: the current 7.0 and the older 2.0 version.
        Some(CvSignature::Pdb70) => CodeView::Pdb70(bytes.pread_with(0, endian)?),
        Some(CvSignature::Pdb20) => CodeView::Pdb20(bytes.pread_with(0, endian)?),
        // Breakpad's ELF build ID format.
        Some(CvSignature::Elf) => CodeView::Elf(bytes.pread_with(0, endian)?),
        // Other formats aren't handled, but save the raw bytes.
        _ => CodeView::Unknown(bytes.to_owned()),
    })
}

impl MinidumpModule {
    /// Create a `MinidumpModule` with some basic info.
    ///
    /// Useful for testing.
    pub fn new(base: u64, size: u32, name: &str) -> MinidumpModule {
        MinidumpModule {
            raw: md::MINIDUMP_MODULE {
                base_of_image: base,
                size_of_image: size,
                ..md::MINIDUMP_MODULE::default()
            },
            name: String::from(name),
            codeview_info: None,
            misc_info: None,
        }
    }

    /// Read additional data to construct a `MinidumpModule` from `bytes` using the information
    /// from the module list in `raw`.
    pub fn read(
        raw: md::MINIDUMP_MODULE,
        bytes: &[u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpModule, Error> {
        let mut offset = raw.module_name_rva as usize;
        let name =
            read_string_utf16(&mut offset, bytes, endian).or(Err(Error::CodeViewReadFailure))?;
        let codeview_info = if raw.cv_record.data_size == 0 {
            None
        } else {
            Some(read_codeview(&raw.cv_record, bytes, endian).or(Err(Error::CodeViewReadFailure))?)
        };
        Ok(MinidumpModule {
            raw,
            name,
            codeview_info,
            misc_info: None,
        })
    }

    /// Write a human-readable description of this `MinidumpModule` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_MODULE
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
  (code_file)                     = \"{}\"
  (code_identifier)               = \"{}\"
",
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
        )?;
        // Print CodeView data.
        match self.codeview_info {
            Some(CodeView::Pdb70(ref raw)) => {
                let pdb_file_name =
                    string_from_bytes_nul(&raw.pdb_file_name).unwrap_or(Cow::Borrowed("(invalid)"));
                write!(f, "  (cv_record).cv_signature        = {:#x}
  (cv_record).signature           = {:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}
  (cv_record).age                 = {}
  (cv_record).pdb_file_name       = \"{}\"
",
                       raw.cv_signature,
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
                       raw.age,
                       pdb_file_name,
                )?;
            }
            Some(CodeView::Pdb20(ref raw)) => {
                let pdb_file_name =
                    string_from_bytes_nul(&raw.pdb_file_name).unwrap_or(Cow::Borrowed("(invalid)"));
                write!(
                    f,
                    "  (cv_record).cv_header.signature = {:#x}
  (cv_record).cv_header.offset    = {:#x}
  (cv_record).signature           = {:#x} {}
  (cv_record).age                 = {}
  (cv_record).pdb_file_name       = \"{}\"
",
                    raw.cv_signature,
                    raw.cv_offset,
                    raw.signature,
                    format_time_t(raw.signature),
                    raw.age,
                    pdb_file_name,
                )?;
            }
            Some(CodeView::Elf(ref raw)) => {
                // Fibbing about having cv_signature handy here.
                write!(
                    f,
                    "  (cv_record).cv_signature        = {:#x}
  (cv_record).build_id            = {}
",
                    raw.cv_signature,
                    bytes_to_hex(&raw.build_id),
                )?;
            }
            Some(CodeView::Unknown(ref bytes)) => {
                writeln!(
                    f,
                    "  (cv_record)                     = {}",
                    bytes_to_hex(bytes),
                )?;
            }
            None => {
                writeln!(f, "  (cv_record)                     = (null)")?;
            }
        }

        // Print misc record data.
        if let Some(ref _misc) = self.misc_info {
            //TODO, not terribly important.
            writeln!(f, "  (misc_record)                   = (unimplemented)")?;
        } else {
            writeln!(f, "  (misc_record)                   = (null)")?;
        }

        // Print remaining data.
        write!(
            f,
            r#"  (debug_file)                    = "{}"
  (debug_identifier)              = "{}"
  (version)                       = "{}"

"#,
            self.debug_file().unwrap_or(Cow::Borrowed("")),
            self.debug_identifier().unwrap_or(Cow::Borrowed("")),
            self.version().unwrap_or(Cow::Borrowed("")),
        )?;
        Ok(())
    }

    fn memory_range(&self) -> Range<u64> {
        Range::new(self.base_address(), self.base_address() + self.size() - 1)
    }
}

impl Module for MinidumpModule {
    fn base_address(&self) -> u64 {
        self.raw.base_of_image
    }
    fn size(&self) -> u64 {
        self.raw.size_of_image as u64
    }
    fn code_file(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
    fn code_identifier(&self) -> Cow<'_, str> {
        match self.codeview_info {
            Some(CodeView::Elf(ref raw)) => Cow::Owned(bytes_to_hex(&raw.build_id)),
            _ => {
                // TODO: Breakpad stubs this out on non-Windows.
                Cow::Owned(format!(
                    "{0:08X}{1:x}",
                    self.raw.time_date_stamp, self.raw.size_of_image
                ))
            }
        }
    }
    fn debug_file(&self) -> Option<Cow<'_, str>> {
        match self.codeview_info {
            Some(CodeView::Pdb70(ref raw)) => string_from_bytes_nul(&raw.pdb_file_name),
            Some(CodeView::Pdb20(ref raw)) => string_from_bytes_nul(&raw.pdb_file_name),
            Some(CodeView::Elf(_)) => Some(Cow::Borrowed(&self.name)),
            // TODO: support misc record? not really important.
            _ => None,
        }
    }
    fn debug_identifier(&self) -> Option<Cow<'_, str>> {
        match self.codeview_info {
            Some(CodeView::Pdb70(ref raw)) => {
                let id = format!("{:#}{:x}", raw.signature, raw.age,);
                Some(Cow::Owned(id))
            }
            Some(CodeView::Pdb20(ref raw)) => {
                let id = format!("{:08X}{:x}", raw.signature, raw.age);
                Some(Cow::Owned(id))
            }
            Some(CodeView::Elf(ref raw)) => {
                // For backwards-compat (Linux minidumps have historically
                // been written using PDB70 CodeView info), treat build_id
                // as if the first 16 bytes were a GUID.
                let guid_size = <md::GUID>::size_with(&LE);
                let guid = if raw.build_id.len() < guid_size {
                    // Pad with zeros.
                    let v: Vec<u8> = raw
                        .build_id
                        .iter()
                        .cloned()
                        .chain(iter::repeat(0))
                        .take(guid_size)
                        .collect();
                    v.pread_with::<md::GUID>(0, LE).ok()
                } else {
                    raw.build_id.pread_with::<md::GUID>(0, LE).ok()
                };
                guid.map(|g| Cow::Owned(format!("{:#}0", g)))
            }
            _ => None,
        }
    }
    fn version(&self) -> Option<Cow<'_, str>> {
        if self.raw.version_info.signature == md::VS_FFI_SIGNATURE
            && self.raw.version_info.struct_version == md::VS_FFI_STRUCVERSION
        {
            let ver = format!(
                "{}.{}.{}.{}",
                self.raw.version_info.file_version_hi >> 16,
                self.raw.version_info.file_version_hi & 0xffff,
                self.raw.version_info.file_version_lo >> 16,
                self.raw.version_info.file_version_lo & 0xffff
            );
            Some(Cow::Owned(ver))
        } else {
            None
        }
    }
}

fn read_stream_list<'a, T>(
    offset: &mut usize,
    bytes: &'a [u8],
    endian: scroll::Endian,
) -> Result<Vec<T>, Error>
where
    T: TryFromCtx<'a, scroll::Endian, [u8], Error = scroll::Error>,
    T: SizeWith<scroll::Endian>,
{
    let u: u32 = bytes
        .gread_with(offset, endian)
        .or(Err(Error::StreamReadFailure))?;
    let count = u as usize;
    let counted_size = match count
        .checked_mul(<T>::size_with(&endian))
        .and_then(|v| v.checked_add(mem::size_of::<u32>()))
    {
        Some(s) => s,
        None => return Err(Error::StreamReadFailure),
    };
    if bytes.len() < counted_size {
        return Err(Error::StreamSizeMismatch {
            expected: counted_size,
            actual: bytes.len(),
        });
    }
    match bytes.len() - counted_size {
        0 => {}
        4 => {
            // 4 bytes of padding.
            *offset += 4;
        }
        _ => {
            return Err(Error::StreamSizeMismatch {
                expected: counted_size,
                actual: bytes.len(),
            })
        }
    };
    // read count T raw stream entries
    let mut raw_entries = Vec::with_capacity(count);
    for _ in 0..count {
        let raw: T = bytes
            .gread_with(offset, endian)
            .or(Err(Error::StreamReadFailure))?;
        raw_entries.push(raw);
    }
    Ok(raw_entries)
}

/// An iterator over `MinidumpModule`s.
#[allow(missing_debug_implementations)]
pub struct Modules<'a> {
    iter: Box<dyn Iterator<Item = &'a MinidumpModule> + 'a>,
}

impl<'a> Iterator for Modules<'a> {
    type Item = &'a MinidumpModule;

    fn next(&mut self) -> Option<&'a MinidumpModule> {
        self.iter.next()
    }
}

impl MinidumpModuleList {
    /// Return an empty `MinidumpModuleList`.
    pub fn new() -> MinidumpModuleList {
        MinidumpModuleList {
            modules: vec![],
            modules_by_addr: RangeMap::new(),
        }
    }
    /// Create a `MinidumpModuleList` from a list of `MinidumpModule`s.
    pub fn from_modules(modules: Vec<MinidumpModule>) -> MinidumpModuleList {
        let modules_by_addr = modules
            .iter()
            .enumerate()
            .map(|(i, module)| (module.memory_range(), i))
            .into_rangemap_safe();
        MinidumpModuleList {
            modules,
            modules_by_addr,
        }
    }

    /// Returns the module corresponding to the main executable.
    pub fn main_module(&self) -> Option<&MinidumpModule> {
        // The main code module is the first one present in a minidump file's
        // MINIDUMP_MODULEList.
        if !self.modules.is_empty() {
            Some(&self.modules[0])
        } else {
            None
        }
    }

    /// Return a `MinidumpModule` whose address range covers `address`.
    pub fn module_at_address(&self, address: u64) -> Option<&MinidumpModule> {
        self.modules_by_addr
            .get(address)
            .map(|&index| &self.modules[index])
    }

    /// Iterate over the modules in arbitrary order.
    pub fn iter(&self) -> Modules<'_> {
        Modules {
            iter: Box::new(self.modules.iter()),
        }
    }

    /// Iterate over the modules in order by memory address.
    pub fn by_addr(&self) -> Modules<'_> {
        Modules {
            iter: Box::new(
                self.modules_by_addr
                    .ranges_values()
                    .map(move |&(_, index)| &self.modules[index]),
            ),
        }
    }

    /// Write a human-readable description of this `MinidumpModuleList` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MinidumpModuleList
  module_count = {}

",
            self.modules.len()
        )?;
        for (i, module) in self.modules.iter().enumerate() {
            writeln!(f, "module[{}]", i)?;
            module.print(f)?;
        }
        Ok(())
    }
}

impl Default for MinidumpModuleList {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> MinidumpStream<'a> for MinidumpModuleList {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::ModuleListStream;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpModuleList, Error> {
        let mut offset = 0;
        let raw_modules: Vec<md::MINIDUMP_MODULE> = read_stream_list(&mut offset, bytes, endian)?;
        // read auxiliary data for each module
        let mut modules = Vec::with_capacity(raw_modules.len());
        for raw in raw_modules.into_iter() {
            if raw.size_of_image == 0
                || raw.size_of_image as u64 > (u64::max_value() - raw.base_of_image)
            {
                // Bad image size.
                // TODO: just drop this module, keep the rest?
                return Err(Error::ModuleReadFailure);
            }
            modules.push(MinidumpModule::read(raw, all, endian)?);
        }
        Ok(MinidumpModuleList::from_modules(modules))
    }
}

impl<'a> MinidumpMemory<'a> {
    pub fn read(
        desc: &md::MINIDUMP_MEMORY_DESCRIPTOR,
        data: &'a [u8],
    ) -> Result<MinidumpMemory<'a>, Error> {
        if desc.memory.rva == 0 || desc.memory.data_size == 0 {
            // Windows will sometimes emit null stack RVAs, indicating that
            // we need to lookup the address in a memory region. It's ok to
            // emit an error for that here, the thread processing code will
            // catch it.
            return Err(Error::MemoryReadFailure);
        }
        let bytes = location_slice(data, &desc.memory).or(Err(Error::StreamReadFailure))?;
        Ok(MinidumpMemory {
            desc: *desc,
            base_address: desc.start_of_memory_range,
            size: desc.memory.data_size as u64,
            bytes,
        })
    }

    /// Get `mem::size_of::<T>()` bytes of memory at `addr` from this region.
    ///
    /// Return `None` if the requested address range falls out of the bounds
    /// of this memory region.
    pub fn get_memory_at_address<T>(&self, addr: u64) -> Option<T>
    where
        T: TryFromCtx<'a, scroll::Endian, [u8], Error = scroll::Error>,
        T: SizeWith<scroll::Endian>,
    {
        let in_range = |a: u64| a >= self.base_address && a < (self.base_address + self.size);
        let size = <T>::size_with(&LE);
        if !in_range(addr) || !in_range(addr + size as u64 - 1) {
            return None;
        }
        let start = (addr - self.base_address) as usize;
        self.bytes.pread_with::<T>(start, LE).ok()
    }

    /// Write a human-readable description of this `MinidumpMemory` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_MEMORY_DESCRIPTOR
  start_of_memory_range = {:#x}
  memory.data_size      = {:#x}
  memory.rva            = {:#x}
Memory
",
            self.desc.start_of_memory_range, self.desc.memory.data_size, self.desc.memory.rva,
        )?;
        self.print_contents(f)?;
        writeln!(f)
    }

    /// Write the contents of this `MinidumpMemory` to `f` as a hex string.
    pub fn print_contents<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(f, "0x")?;
        for byte in self.bytes.iter() {
            write!(f, "{:02x}", byte)?;
        }
        writeln!(f)?;
        Ok(())
    }

    fn memory_range(&self) -> Range<u64> {
        Range::new(self.base_address, self.base_address + self.size - 1)
    }
}

/// An iterator over `MinidumpMemory`s.
#[allow(missing_debug_implementations)]
pub struct MemoryRegions<'iter, 'data> {
    iter: Box<dyn Iterator<Item = &'iter MinidumpMemory<'data>> + 'iter>,
}

impl<'iter, 'data> Iterator for MemoryRegions<'iter, 'data>
where
    'data: 'iter,
{
    type Item = &'iter MinidumpMemory<'data>;

    fn next(&mut self) -> Option<&'iter MinidumpMemory<'data>> {
        self.iter.next()
    }
}

impl<'mdmp> MinidumpMemoryList<'mdmp> {
    /// Return an empty `MinidumpMemoryList`.
    pub fn new() -> MinidumpMemoryList<'mdmp> {
        MinidumpMemoryList {
            regions: vec![],
            regions_by_addr: RangeMap::new(),
        }
    }

    /// Create a `MinidumpMemoryList` from a list of `MinidumpMemory`s.
    pub fn from_regions(regions: Vec<MinidumpMemory<'mdmp>>) -> MinidumpMemoryList<'mdmp> {
        let regions_by_addr = regions
            .iter()
            .enumerate()
            .map(|(i, region)| (region.memory_range(), i))
            .into_rangemap_safe();
        MinidumpMemoryList {
            regions,
            regions_by_addr,
        }
    }

    /// Return a `MinidumpMemory` containing memory at `address`, if one exists.
    pub fn memory_at_address(&self, address: u64) -> Option<&MinidumpMemory<'mdmp>> {
        self.regions_by_addr
            .get(address)
            .map(|&index| &self.regions[index])
    }

    /// Iterate over the memory regions in the order contained in the minidump.
    ///
    /// The iterator returns items of [MinidumpMemory] as `&'slf MinidumpMemory<'mdmp>`.
    /// That is the lifetime of the item is bound to the lifetime of the iterator itself
    /// (`'slf`), while the slice inside [MinidumpMemory] pointing at the memory itself has
    /// the lifetime of the [Minidump] struct ('mdmp).
    pub fn iter<'slf>(&'slf self) -> MemoryRegions<'slf, 'mdmp> {
        MemoryRegions {
            iter: Box::new(self.regions.iter()),
        }
    }

    /// Iterate over the memory regions in order by memory address.
    pub fn by_addr<'slf>(&'slf self) -> MemoryRegions<'slf, 'mdmp> {
        MemoryRegions {
            iter: Box::new(
                self.regions_by_addr
                    .ranges_values()
                    .map(move |&(_, index)| &self.regions[index]),
            ),
        }
    }

    /// Write a human-readable description of this `MinidumpMemoryList` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MinidumpMemoryList
  region_count = {}

",
            self.regions.len()
        )?;
        for (i, region) in self.regions.iter().enumerate() {
            writeln!(f, "region[{}]", i)?;
            region.print(f)?;
        }
        Ok(())
    }
}

impl<'a> Default for MinidumpMemoryList<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> MinidumpStream<'a> for MinidumpMemoryList<'a> {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::MemoryListStream;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpMemoryList<'a>, Error> {
        let mut offset = 0;
        let descriptors: Vec<md::MINIDUMP_MEMORY_DESCRIPTOR> =
            read_stream_list(&mut offset, bytes, endian)?;
        // read memory contents for each region
        let mut regions = Vec::with_capacity(descriptors.len());
        for raw in descriptors.into_iter() {
            if let Ok(memory) = MinidumpMemory::read(&raw, all) {
                regions.push(memory);
            } else {
                // Just skip over corrupt entries and try to limp along.
                continue;
            }
        }
        Ok(MinidumpMemoryList::from_regions(regions))
    }
}

impl<'a> MinidumpThread<'a> {
    /// Write a human-readable description of this `MinidumpThread` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            r#"MINIDUMP_THREAD
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
        )?;
        if let Some(ref ctx) = self.context {
            ctx.print(f)?;
        } else {
            write!(f, "  (no context)\n\n")?;
        }

        if let Some(ref stack) = self.stack {
            writeln!(f, "Stack")?;
            stack.print_contents(f)?;
        } else {
            writeln!(f, "No stack")?;
        }
        writeln!(f)?;
        Ok(())
    }
}

impl<'a> MinidumpStream<'a> for MinidumpThreadList<'a> {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::ThreadListStream;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpThreadList<'a>, Error> {
        let mut offset = 0;
        let raw_threads: Vec<md::MINIDUMP_THREAD> = read_stream_list(&mut offset, bytes, endian)?;
        let mut threads = Vec::with_capacity(raw_threads.len());
        let mut thread_ids = HashMap::with_capacity(raw_threads.len());
        for raw in raw_threads.into_iter() {
            thread_ids.insert(raw.thread_id, threads.len());
            let context_data = location_slice(all, &raw.thread_context)?;
            let context = MinidumpContext::read(context_data, endian).ok();

            // If this fails, it's ok. That probably means the RVA was null
            // and we need to lookup the stack's memory by address in the
            // mapped memory regions (minidump-processor will handle this).
            let stack = MinidumpMemory::read(&raw.stack, all).ok();
            threads.push(MinidumpThread {
                raw,
                context,
                stack,
            });
        }
        Ok(MinidumpThreadList {
            threads,
            thread_ids,
        })
    }
}

impl<'a> MinidumpThreadList<'a> {
    /// Get the thread with id `id` from this thread list if it exists.
    pub fn get_thread(&self, id: u32) -> Option<&MinidumpThread<'a>> {
        self.thread_ids.get(&id).map(|&index| &self.threads[index])
    }

    /// Write a human-readable description of this `MinidumpThreadList` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            r#"MinidumpThreadList
  thread_count = {}

"#,
            self.threads.len()
        )?;

        for (i, thread) in self.threads.iter().enumerate() {
            writeln!(f, "thread[{}]", i)?;
            thread.print(f)?;
        }
        Ok(())
    }
}

impl<'a> MinidumpStream<'a> for MinidumpSystemInfo {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::SystemInfoStream;

    fn read(
        bytes: &[u8],
        _all: &[u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpSystemInfo, Error> {
        let raw: md::MINIDUMP_SYSTEM_INFO = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;
        let os = Os::from_platform_id(raw.platform_id);
        let cpu = Cpu::from_processor_architecture(raw.processor_architecture);
        Ok(MinidumpSystemInfo { raw, os, cpu })
    }
}

impl MinidumpSystemInfo {
    /// Write a human-readable description of this `MinidumpSystemInfo` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_SYSTEM_INFO
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
            self.raw.suite_mask
        )?;
        // TODO: cpu info etc
        Ok(())
    }
}

// Generates an accessor for a MISC_INFO field with two possible syntaxes:
//
// * VERSION_NUMBER: FIELD_NAME -> FIELD_TYPE
// * VERSION_NUMBER: FIELD_NAME if FLAG -> FIELD_TYPE
//
// With the following definitions:
//
// * VERSION_NUMBER: The MISC_INFO version this field was introduced in
// * FIELD_NAME: The name of the field to read
// * FLAG: A MiscInfoFlag that defines if this field contains valid data
// * FIELD_TYPE: The type of the field
macro_rules! misc_accessors {
    () => {};
    (@defnoflag $name:ident $t:ty [$($variant:ident)+]) => {
        #[allow(unreachable_patterns)]
        pub fn $name(&self) -> Option<&$t> {
            match self {
                $(
                    RawMiscInfo::$variant(ref raw) => Some(&raw.$name),
                )+
                _ => None,
            }
        }
    };
    (@def $name:ident $flag:ident $t:ty [$($variant:ident)+]) => {
        #[allow(unreachable_patterns)]
        pub fn $name(&self) -> Option<&$t> {
            match self {
                $(
                    RawMiscInfo::$variant(ref raw) => if md::MiscInfoFlags::from_bits_truncate(raw.flags1).contains(md::MiscInfoFlags::$flag) { Some(&raw.$name) } else { None },
                )+
                _ => None,
            }
        }
    };
    (1: $name:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@defnoflag $name $t [MiscInfo MiscInfo2 MiscInfo3 MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };
    (1: $name:ident if $flag:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@def $name $flag $t [MiscInfo MiscInfo2 MiscInfo3 MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };

    (2: $name:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@defnoflag $name $t [MiscInfo2 MiscInfo3 MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };
    (2: $name:ident if $flag:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@def $name $flag $t [MiscInfo2 MiscInfo3 MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };

    (3: $name:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@defnoflag $name $t [MiscInfo3 MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };
    (3: $name:ident if $flag:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@def $name $flag $t [MiscInfo3 MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };

    (4: $name:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@defnoflag $name $t [MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };
    (4: $name:ident if $flag:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@def $name $flag $t [MiscInfo4 MiscInfo5]);
        misc_accessors!($($rest)*);
    };

    (5: $name:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@defnoflag $name $t [MiscInfo5]);
        misc_accessors!($($rest)*);
    };
    (5: $name:ident if $flag:ident -> $t:ty, $($rest:tt)*) => {
        misc_accessors!(@def $name $flag $t [MiscInfo5]);
        misc_accessors!($($rest)*);
    };
}

impl RawMiscInfo {
    // Fields are grouped by the flag that guards them.
    misc_accessors!(
        1: size_of_info -> u32,
        1: flags1 -> u32,

        1: process_id if MINIDUMP_MISC1_PROCESS_ID -> u32,

        1: process_create_time if MINIDUMP_MISC1_PROCESS_TIMES -> u32,
        1: process_user_time if MINIDUMP_MISC1_PROCESS_TIMES -> u32,
        1: process_kernel_time if MINIDUMP_MISC1_PROCESS_TIMES -> u32,

        2: processor_max_mhz if MINIDUMP_MISC1_PROCESSOR_POWER_INFO -> u32,
        2: processor_current_mhz if MINIDUMP_MISC1_PROCESSOR_POWER_INFO -> u32,
        2: processor_mhz_limit if MINIDUMP_MISC1_PROCESSOR_POWER_INFO -> u32,
        2: processor_max_idle_state if MINIDUMP_MISC1_PROCESSOR_POWER_INFO -> u32,
        2: processor_current_idle_state if MINIDUMP_MISC1_PROCESSOR_POWER_INFO -> u32,

        3: process_integrity_level if MINIDUMP_MISC3_PROCESS_INTEGRITY -> u32,

        3: process_execute_flags if MINIDUMP_MISC3_PROCESS_EXECUTE_FLAGS -> u32,

        3: protected_process if MINIDUMP_MISC3_PROTECTED_PROCESS -> u32,

        3: time_zone_id if MINIDUMP_MISC3_TIMEZONE -> u32,
        3: time_zone if MINIDUMP_MISC3_TIMEZONE -> md::TIME_ZONE_INFORMATION,

        4: build_string if MINIDUMP_MISC4_BUILDSTRING -> [u16; 260],
        4: dbg_bld_str if MINIDUMP_MISC4_BUILDSTRING -> [u16; 40],

        5: xstate_data -> md::XSTATE_CONFIG_FEATURE_MSC_INFO,

        5: process_cookie if MINIDUMP_MISC5_PROCESS_COOKIE -> u32,
    );
}

impl<'a> MinidumpStream<'a> for MinidumpMiscInfo {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::MiscInfoStream;

    fn read(bytes: &[u8], _all: &[u8], endian: scroll::Endian) -> Result<MinidumpMiscInfo, Error> {
        // The misc info has gone through several revisions, so try to read the largest known
        // struct possible.
        macro_rules! do_read {
            ($(($t:ty, $variant:ident),)+) => {
                $(
                    if bytes.len() >= <$t>::size_with(&endian) {
                        return Ok(MinidumpMiscInfo {
                            raw: RawMiscInfo::$variant(bytes.pread_with(0, endian).or(Err(Error::StreamReadFailure))?),
                        });
                    }
                )+
            }
        }

        do_read!(
            (md::MINIDUMP_MISC_INFO_5, MiscInfo5),
            (md::MINIDUMP_MISC_INFO_4, MiscInfo4),
            (md::MINIDUMP_MISC_INFO_3, MiscInfo3),
            (md::MINIDUMP_MISC_INFO_2, MiscInfo2),
            (md::MINIDUMP_MISC_INFO, MiscInfo),
        );
        Err(Error::StreamReadFailure)
    }
}

impl MinidumpMiscInfo {
    pub fn process_create_time(&self) -> Option<DateTime<Utc>> {
        self.raw
            .process_create_time()
            .map(|t| Utc.timestamp(*t as i64, 0))
    }

    /// Write a human-readable description of this `MinidumpMiscInfo` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        macro_rules! write_simple_field {
            ($stream:ident, $field:ident, $format:literal) => {
                write!(f, "  {:29}= ", stringify!($field))?;
                match self.raw.$field() {
                    Some($field) => {
                        writeln!(f, $format, $field)?;
                    }
                    None => writeln!(f, "(invalid)")?,
                }
            };
            ($stream:ident, $field:ident) => {
                write_simple_field!($stream, $field, "{}");
            };
        }
        writeln!(f, "MINIDUMP_MISC_INFO")?;

        write_simple_field!(f, size_of_info);
        write_simple_field!(f, flags1, "{:x}");
        write_simple_field!(f, process_id);
        write!(f, "  process_create_time          = ")?;
        match self.raw.process_create_time() {
            Some(&process_create_time) => {
                writeln!(
                    f,
                    "{:#x} {}",
                    process_create_time,
                    format_time_t(process_create_time),
                )?;
            }
            None => writeln!(f, "(invalid)")?,
        }
        write_simple_field!(f, process_user_time);
        write_simple_field!(f, process_kernel_time);

        write_simple_field!(f, processor_max_mhz);
        write_simple_field!(f, processor_current_mhz);
        write_simple_field!(f, processor_mhz_limit);
        write_simple_field!(f, processor_max_idle_state);
        write_simple_field!(f, processor_current_idle_state);

        write_simple_field!(f, process_integrity_level);
        write_simple_field!(f, process_execute_flags, "{:x}");
        write_simple_field!(f, protected_process);
        write_simple_field!(f, time_zone_id);

        write!(f, "  time_zone                    = ")?;
        match self.raw.time_zone() {
            Some(time_zone) => {
                writeln!(f)?;
                writeln!(f, "    bias          = {}", time_zone.bias)?;
                writeln!(
                    f,
                    "    standard_name = {}",
                    utf16_to_string(&time_zone.standard_name[..])
                        .unwrap_or_else(|| String::from("(invalid)"))
                )?;
                writeln!(
                    f,
                    "    standard_date = {}",
                    format_system_time(&time_zone.standard_date)
                )?;
                writeln!(f, "    standard_bias = {}", time_zone.standard_bias)?;
                writeln!(
                    f,
                    "    daylight_name = {}",
                    utf16_to_string(&time_zone.daylight_name[..])
                        .unwrap_or_else(|| String::from("(invalid)"))
                )?;
                writeln!(
                    f,
                    "    daylight_date = {}",
                    format_system_time(&time_zone.daylight_date)
                )?;
                writeln!(f, "    daylight_bias = {}", time_zone.daylight_bias)?;
            }
            None => writeln!(f, "(invalid)")?,
        }

        write!(f, "  build_string                 = ")?;
        match self
            .raw
            .build_string()
            .and_then(|string| utf16_to_string(&string[..]))
        {
            Some(build_string) => writeln!(f, "{}", build_string)?,
            None => writeln!(f, "(invalid)")?,
        }
        write!(f, "  dbg_bld_str                  = ")?;
        match self
            .raw
            .dbg_bld_str()
            .and_then(|string| utf16_to_string(&string[..]))
        {
            Some(dbg_bld_str) => writeln!(f, "{}", dbg_bld_str)?,
            None => writeln!(f, "(invalid)")?,
        }

        write!(f, "  xstate_data                  = ")?;
        match self.raw.xstate_data() {
            Some(xstate_data) => {
                writeln!(f)?;
                for (i, feature) in xstate_data.iter() {
                    if let Some(feature) = md::XstateFeatureIndex::from_index(i) {
                        write!(f, "    feature {:2} - {:22}: ", i, format!("{:?}", feature))?;
                    } else {
                        write!(f, "    feature {:2} - (unknown)           : ", i)?;
                    }
                    writeln!(f, " offset {:4}, size {:4}", feature.offset, feature.size)?;
                    // TODO: load the XSAVE state and print it?
                }
            }
            None => writeln!(f, "(invalid)")?,
        }

        write_simple_field!(f, process_cookie);
        writeln!(f)?;
        Ok(())
    }
}

impl<'a> MinidumpStream<'a> for MinidumpBreakpadInfo {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::BreakpadInfoStream;

    fn read(
        bytes: &[u8],
        _all: &[u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpBreakpadInfo, Error> {
        let raw: md::MINIDUMP_BREAKPAD_INFO = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;
        let flags = md::BreakpadInfoValid::from_bits_truncate(raw.validity);
        let dump_thread_id = if flags.contains(md::BreakpadInfoValid::DumpThreadId) {
            Some(raw.dump_thread_id)
        } else {
            None
        };
        let requesting_thread_id = if flags.contains(md::BreakpadInfoValid::RequestingThreadId) {
            Some(raw.requesting_thread_id)
        } else {
            None
        };
        Ok(MinidumpBreakpadInfo {
            raw,
            dump_thread_id,
            requesting_thread_id,
        })
    }
}

fn option_or_invalid<T: fmt::LowerHex>(what: &Option<T>) -> Cow<'_, str> {
    match *what {
        Some(ref val) => Cow::Owned(format!("{:#x}", val)),
        None => Cow::Borrowed("(invalid)"),
    }
}

impl MinidumpBreakpadInfo {
    /// Write a human-readable description of this `MinidumpBreakpadInfo` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_BREAKPAD_INFO
  validity             = {:#x}
  dump_thread_id       = {}
  requesting_thread_id = {}

",
            self.raw.validity,
            option_or_invalid(&self.dump_thread_id),
            option_or_invalid(&self.requesting_thread_id),
        )?;
        Ok(())
    }
}

impl CrashReason {
    /// Get a `CrashReason` from a `MINIDUMP_EXCEPTION_STREAM` for a given `Os`.
    fn from_exception(_raw: &md::MINIDUMP_EXCEPTION_STREAM, _os: Os) -> CrashReason {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                CrashReason::Unknown => "unknown",
            }
        )
    }
}

impl<'a> MinidumpStream<'a> for MinidumpException {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::ExceptionStream;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpException, Error> {
        let raw: md::MINIDUMP_EXCEPTION_STREAM = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;
        let context_data = location_slice(all, &raw.thread_context)?;
        let context = MinidumpContext::read(context_data, endian).ok();
        let thread_id = raw.thread_id;
        Ok(MinidumpException {
            raw,
            thread_id,
            context,
        })
    }
}

impl MinidumpException {
    /// Get the crash address for an exception.
    pub fn get_crash_address(&self, os: Os) -> u64 {
        match (
            os,
            md::ExceptionCodeWindows::from_u32(self.raw.exception_record.exception_code),
        ) {
            (Os::Windows, Some(md::ExceptionCodeWindows::EXCEPTION_ACCESS_VIOLATION))
            | (Os::Windows, Some(md::ExceptionCodeWindows::EXCEPTION_IN_PAGE_ERROR))
                if self.raw.exception_record.number_parameters >= 2 =>
            {
                self.raw.exception_record.exception_information[1]
            }
            _ => self.raw.exception_record.exception_address,
        }
    }

    /// Get the crash reason for an exception.
    pub fn get_crash_reason(&self, os: Os) -> CrashReason {
        CrashReason::from_exception(&self.raw, os)
    }

    pub fn get_crashing_thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Write a human-readable description of this `MinidumpException` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_EXCEPTION
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
        )?;
        for i in 0..self.raw.exception_record.number_parameters as usize {
            writeln!(
                f,
                "  exception_record.exception_information[{:2}] = {:#x}",
                i, self.raw.exception_record.exception_information[i]
            )?;
        }
        write!(
            f,
            "  thread_context.data_size                   = {}
  thread_context.rva                         = {:#x}
",
            self.raw.thread_context.data_size, self.raw.thread_context.rva
        )?;
        if let Some(ref context) = self.context {
            writeln!(f)?;
            context.print(f)?;
        } else {
            write!(
                f,
                "  (no context)

"
            )?;
        }
        Ok(())
    }
}

impl<'a> MinidumpStream<'a> for MinidumpAssertion {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::AssertionInfoStream;

    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpAssertion, Error> {
        let raw: md::MINIDUMP_ASSERTION_INFO = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;
        Ok(MinidumpAssertion { raw })
    }
}

fn utf16_to_string(data: &[u16]) -> Option<String> {
    use std::slice;

    let len = data.iter().take_while(|c| **c != 0).count();
    let s16 = &data[..len];
    let bytes = unsafe { slice::from_raw_parts(s16.as_ptr() as *const u8, s16.len() * 2) };
    UTF_16LE.decode(bytes, DecoderTrap::Strict).ok()
}

impl MinidumpAssertion {
    /// Get the assertion expression as a `String` if one exists.
    pub fn expression(&self) -> Option<String> {
        utf16_to_string(&self.raw.expression)
    }
    /// Get the function name where the assertion happened as a `String` if it exists.
    pub fn function(&self) -> Option<String> {
        utf16_to_string(&self.raw.function)
    }
    /// Get the source file name where the assertion happened as a `String` if it exists.
    pub fn file(&self) -> Option<String> {
        utf16_to_string(&self.raw.file)
    }

    /// Write a human-readable description of this `MinidumpAssertion` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MDAssertion
  expression                                 = {}
  function                                   = {}
  file                                       = {}
  line                                       = {}
  type                                       = {}

",
            self.expression().unwrap_or_else(String::new),
            self.function().unwrap_or_else(String::new),
            self.file().unwrap_or_else(String::new),
            self.raw.line,
            self.raw._type,
        )?;
        Ok(())
    }
}

fn read_string_list(
    all: &[u8],
    location: &md::MINIDUMP_LOCATION_DESCRIPTOR,
    endian: scroll::Endian,
) -> Result<Vec<String>, Error> {
    let data = location_slice(all, location).or(Err(Error::StreamReadFailure))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut offset = 0;

    let count: u32 = data
        .gread_with(&mut offset, endian)
        .or(Err(Error::StreamReadFailure))?;

    let mut strings = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let rva: md::RVA = data
            .gread_with(&mut offset, endian)
            .or(Err(Error::StreamReadFailure))?;

        let string = read_string_utf8(&mut (rva as usize), all, endian)
            .or(Err(Error::StreamReadFailure))?
            .to_owned();

        strings.push(string);
    }

    Ok(strings)
}

fn read_simple_string_dictionary(
    all: &[u8],
    location: &md::MINIDUMP_LOCATION_DESCRIPTOR,
    endian: scroll::Endian,
) -> Result<BTreeMap<String, String>, Error> {
    let mut dictionary = BTreeMap::new();

    let data = location_slice(all, location).or(Err(Error::StreamReadFailure))?;
    if data.is_empty() {
        return Ok(dictionary);
    }

    let mut offset = 0;

    let count: u32 = data
        .gread_with(&mut offset, endian)
        .or(Err(Error::StreamReadFailure))?;

    for _ in 0..count {
        let entry: md::MINIDUMP_SIMPLE_STRING_DICTIONARY_ENTRY = data
            .gread_with(&mut offset, endian)
            .or(Err(Error::StreamReadFailure))?;

        let key = read_string_utf8(&mut (entry.key as usize), all, endian)
            .or(Err(Error::StreamReadFailure))?;
        let value = read_string_utf8(&mut (entry.value as usize), all, endian)
            .or(Err(Error::StreamReadFailure))?;

        dictionary.insert(key.to_owned(), value.to_owned());
    }

    Ok(dictionary)
}

fn read_annotation_objects(
    all: &[u8],
    location: &md::MINIDUMP_LOCATION_DESCRIPTOR,
    endian: scroll::Endian,
) -> Result<BTreeMap<String, MinidumpAnnotation>, Error> {
    let mut dictionary = BTreeMap::new();

    let data = location_slice(all, location).or(Err(Error::StreamReadFailure))?;
    if data.is_empty() {
        return Ok(dictionary);
    }

    let mut offset = 0;

    let count: u32 = data
        .gread_with(&mut offset, endian)
        .or(Err(Error::StreamReadFailure))?;

    for _ in 0..count {
        let raw: md::MINIDUMP_ANNOTATION = data
            .gread_with(&mut offset, endian)
            .or(Err(Error::StreamReadFailure))?;

        let key = read_string_utf8(&mut (raw.name as usize), all, endian)
            .or(Err(Error::StreamReadFailure))?;

        let value = match raw.ty {
            md::MINIDUMP_ANNOTATION::TYPE_INVALID => MinidumpAnnotation::Invalid,
            md::MINIDUMP_ANNOTATION::TYPE_STRING => {
                let string = read_string_utf8_unterminated(&mut (raw.value as usize), all, endian)
                    .or(Err(Error::StreamReadFailure))?
                    .to_owned();

                MinidumpAnnotation::String(string)
            }
            _ if raw.ty >= md::MINIDUMP_ANNOTATION::TYPE_USER_DEFINED => {
                MinidumpAnnotation::UserDefined(raw)
            }
            _ => MinidumpAnnotation::Unsupported(raw),
        };

        dictionary.insert(key.to_owned(), value);
    }

    Ok(dictionary)
}

impl MinidumpModuleCrashpadInfo {
    pub fn read(
        link: md::MINIDUMP_MODULE_CRASHPAD_INFO_LINK,
        all: &[u8],
        endian: scroll::Endian,
    ) -> Result<Self, Error> {
        let raw: md::MINIDUMP_MODULE_CRASHPAD_INFO = all
            .pread_with(link.location.rva as usize, endian)
            .or(Err(Error::StreamReadFailure))?;

        let list_annotations = read_string_list(all, &raw.list_annotations, endian)?;
        let simple_annotations =
            read_simple_string_dictionary(all, &raw.simple_annotations, endian)?;
        let annotation_objects = read_annotation_objects(all, &raw.annotation_objects, endian)?;

        Ok(Self {
            raw,
            module_index: link.minidump_module_list_index as usize,
            list_annotations,
            simple_annotations,
            annotation_objects,
        })
    }
}

fn read_crashpad_module_links(
    all: &[u8],
    location: &md::MINIDUMP_LOCATION_DESCRIPTOR,
    endian: scroll::Endian,
) -> Result<Vec<MinidumpModuleCrashpadInfo>, Error> {
    let data = location_slice(all, location).or(Err(Error::StreamReadFailure))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut offset = 0;

    let count: u32 = data
        .gread_with(&mut offset, endian)
        .or(Err(Error::StreamReadFailure))?;

    let mut module_links = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let link: md::MINIDUMP_MODULE_CRASHPAD_INFO_LINK = data
            .gread_with(&mut offset, endian)
            .or(Err(Error::StreamReadFailure))?;

        let info = MinidumpModuleCrashpadInfo::read(link, all, endian)?;
        module_links.push(info);
    }

    Ok(module_links)
}

impl<'a> MinidumpStream<'a> for MinidumpCrashpadInfo {
    const STREAM_TYPE: MINIDUMP_STREAM_TYPE = MINIDUMP_STREAM_TYPE::CrashpadInfoStream;

    fn read(bytes: &'a [u8], all: &'a [u8], endian: scroll::Endian) -> Result<Self, Error> {
        let raw: md::MINIDUMP_CRASHPAD_INFO = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;

        if raw.version == 0 {
            // 0 is an invalid version, but all future versions are compatible with v1.
            return Err(Error::VersionMismatch);
        }

        let simple_annotations =
            read_simple_string_dictionary(all, &raw.simple_annotations, endian)?;

        let module_list = read_crashpad_module_links(all, &raw.module_list, endian)?;

        Ok(Self {
            raw,
            simple_annotations,
            module_list,
        })
    }
}

impl MinidumpCrashpadInfo {
    /// Write a human-readable description of this `MinidumpCrashpadInfo` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MDRawCrashpadInfo
  version = {}
  report_id = {}
  client_id = {}
",
            self.raw.version, self.raw.report_id, self.raw.client_id,
        )?;

        for (name, value) in &self.simple_annotations {
            writeln!(f, "  simple_annotations[\"{}\"] = {}", name, value)?;
        }

        for (index, module) in self.module_list.iter().enumerate() {
            writeln!(
                f,
                "  module_list[{}].minidump_module_list_index = {}",
                index, module.module_index,
            )?;
            writeln!(
                f,
                "  module_list[{}].version = {}",
                index, module.raw.version,
            )?;

            for (annotation_index, annotation) in module.list_annotations.iter().enumerate() {
                writeln!(
                    f,
                    "  module_list[{}].list_annotations[{}] = {}",
                    index, annotation_index, annotation,
                )?;
            }

            for (name, value) in &module.simple_annotations {
                writeln!(
                    f,
                    "  module_list[{}].simple_annotations[\"{}\"] = {}",
                    index, name, value,
                )?;
            }

            for (name, value) in &module.annotation_objects {
                write!(
                    f,
                    "  module_list[{}].annotation_objects[\"{}\"] = ",
                    index, name,
                )?;

                match value {
                    MinidumpAnnotation::Invalid => writeln!(f, "<invalid>"),
                    MinidumpAnnotation::String(string) => writeln!(f, "{}", string),
                    MinidumpAnnotation::UserDefined(_) => writeln!(f, "<user defined>"),
                    MinidumpAnnotation::Unsupported(_) => writeln!(f, "<unsupported>"),
                }?;
            }
        }

        writeln!(f)?;

        Ok(())
    }
}

impl<'a> Minidump<'a, Mmap> {
    /// Read a `Minidump` from a `Path` to a file on disk.
    ///
    /// See [the type definition](Minidump.html) for an example.
    pub fn read_path<P>(path: P) -> Result<Minidump<'a, Mmap>, Error>
    where
        P: AsRef<Path>,
    {
        let f = File::open(path).or(Err(Error::FileNotFound))?;
        let mmap = unsafe { Mmap::map(&f).or(Err(Error::IoError))? };
        Minidump::read(mmap)
    }
}

impl<'a, T> Minidump<'a, T>
where
    T: Deref<Target = [u8]> + 'a,
{
    /// Read a `Minidump` from the provided `data`.
    ///
    /// Typically this will be a `Vec<u8>` or `&[u8]` with the full contents of the minidump,
    /// but you can also use something like `memmap::Mmap`.
    pub fn read(data: T) -> Result<Minidump<'a, T>, Error> {
        let mut offset = 0;
        let mut endian = LE;
        let mut header: md::MINIDUMP_HEADER = data
            .gread_with(&mut offset, endian)
            .or(Err(Error::MissingHeader))?;
        if header.signature != md::MINIDUMP_SIGNATURE {
            if header.signature.swap_bytes() != md::MINIDUMP_SIGNATURE {
                return Err(Error::HeaderMismatch);
            }
            // Try again with big-endian.
            endian = BE;
            offset = 0;
            header = data
                .gread_with(&mut offset, endian)
                .or(Err(Error::MissingHeader))?;
            if header.signature != md::MINIDUMP_SIGNATURE {
                return Err(Error::HeaderMismatch);
            }
        }
        if (header.version & 0x0000ffff) != md::MINIDUMP_VERSION {
            return Err(Error::VersionMismatch);
        }
        let mut streams = HashMap::with_capacity(header.stream_count as usize);
        offset = header.stream_directory_rva as usize;
        for i in 0..header.stream_count {
            let dir: md::MINIDUMP_DIRECTORY = data
                .gread_with(&mut offset, endian)
                .or(Err(Error::MissingDirectory))?;
            streams.insert(dir.stream_type, (i, dir));
        }
        Ok(Minidump {
            data,
            header,
            streams,
            endian,
            _phantom: PhantomData,
        })
    }

    /// Get a known stream of data from the minidump.
    ///
    /// For streams known to this module whose types implement the
    /// [`MinidumpStream`][stream] trait, this method allows reading
    /// the stream data as a specific type.
    ///
    /// Note that the lifetime of the returned stream is bound to the lifetime of the this
    /// `Minidump` struct itself and not to the lifetime of the data backing this minidump.
    /// This is a consequence of how this struct relies on [Deref] to access the data.
    ///
    /// [stream]: trait.MinidumpStream.html
    pub fn get_stream<S>(&'a self) -> Result<S, Error>
    where
        S: MinidumpStream<'a>,
    {
        match self.get_raw_stream(S::STREAM_TYPE) {
            Err(e) => Err(e),
            Ok(bytes) => {
                let all_bytes = self.data.deref();
                S::read(bytes, all_bytes, self.endian)
            }
        }
    }

    /// Get a stream of raw data from the minidump.
    ///
    /// This can be used to get the contents of arbitrary minidump streams.
    /// For streams of known types you almost certainly want to use
    /// [`get_stream`][get_stream] instead.
    ///
    /// Note that the lifetime of the returned stream is bound to the lifetime of the this
    /// `Minidump` struct itself and not to the lifetime of the data backing this minidump.
    /// This is a consequence of how this struct relies on [Deref] to access the data.
    ///
    /// [get_stream]: #get_stream
    pub fn get_raw_stream<S>(&'a self, stream_type: S) -> Result<&'a [u8], Error>
    where
        S: Into<u32>,
    {
        match self.streams.get(&stream_type.into()) {
            None => Err(Error::StreamNotFound),
            Some(&(_, ref dir)) => {
                let bytes = self.data.deref();
                location_slice(bytes, &dir.location)
            }
        }
    }

    /// Write a verbose description of the `Minidump` to `f`.
    pub fn print<W: Write>(&self, f: &mut W) -> io::Result<()> {
        fn get_stream_name(stream_type: u32) -> Cow<'static, str> {
            if let Some(stream) = MINIDUMP_STREAM_TYPE::from_u32(stream_type) {
                Cow::Owned(format!("{:?}", stream))
            } else {
                Cow::Borrowed("unknown")
            }
        }

        write!(
            f,
            r#"MDRawHeader
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
        )?;
        let mut streams = self.streams.iter().collect::<Vec<_>>();
        streams.sort_by(|&(&_, &(a, _)), &(&_, &(b, _))| a.cmp(&b));
        for &(_, &(i, ref stream)) in streams.iter() {
            write!(
                f,
                r#"mDirectory[{}]
MDRawDirectory
  stream_type        = {:#x} ({})
  location.data_size = {}
  location.rva       = {:#x}

"#,
                i,
                stream.stream_type,
                get_stream_name(stream.stream_type),
                stream.location.data_size,
                stream.location.rva
            )?;
        }
        writeln!(f, "Streams:")?;
        streams.sort_by(|&(&a, &(_, _)), &(&b, &(_, _))| a.cmp(&b));
        for (_, &(i, ref stream)) in streams {
            writeln!(
                f,
                "  stream type {:#x} ({}) at index {}",
                stream.stream_type,
                get_stream_name(stream.stream_type),
                i
            )?;
        }
        writeln!(f)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::synth_minidump::{
        self, AnnotationValue, CrashpadInfo, DumpString, Memory, MiscFieldsBuildString,
        MiscFieldsPowerInfo, MiscFieldsProcessTimes, MiscFieldsTimeZone, MiscInfo5Fields,
        MiscStream, Module as SynthModule, ModuleCrashpadInfo, SimpleStream, SynthMinidump, Thread,
        STOCK_VERSION_INFO,
    };
    use md::GUID;
    use std::mem;
    use test_assembler::*;

    fn read_synth_dump<'a>(dump: SynthMinidump) -> Result<Minidump<'a, Vec<u8>>, Error> {
        Minidump::read(dump.finish().unwrap())
    }

    #[test]
    fn test_simple_synth_dump() {
        const STREAM_TYPE: u32 = 0x11223344;
        let dump = SynthMinidump::with_endian(Endian::Little).add_stream(SimpleStream {
            stream_type: STREAM_TYPE,
            section: Section::with_endian(Endian::Little).D32(0x55667788),
        });
        let dump = read_synth_dump(dump).unwrap();
        assert_eq!(dump.endian, LE);
        assert_eq!(
            dump.get_raw_stream(STREAM_TYPE).unwrap(),
            &[0x88, 0x77, 0x66, 0x55]
        );

        assert_eq!(
            dump.get_raw_stream(0xaabbccddu32),
            Err(Error::StreamNotFound)
        );
    }

    #[test]
    fn test_simple_synth_dump_bigendian() {
        const STREAM_TYPE: u32 = 0x11223344;
        let dump = SynthMinidump::with_endian(Endian::Big).add_stream(SimpleStream {
            stream_type: STREAM_TYPE,
            section: Section::with_endian(Endian::Big).D32(0x55667788),
        });
        let dump = read_synth_dump(dump).unwrap();
        assert_eq!(dump.endian, BE);
        assert_eq!(
            dump.get_raw_stream(STREAM_TYPE).unwrap(),
            &[0x55, 0x66, 0x77, 0x88]
        );

        assert_eq!(
            dump.get_raw_stream(0xaabbccddu32),
            Err(Error::StreamNotFound)
        );
    }

    #[test]
    fn test_module_list() {
        let name = DumpString::new("single module", Endian::Little);
        let cv_record = Section::with_endian(Endian::Little)
            .D32(md::CvSignature::Pdb70 as u32) // signature
            // signature, a GUID
            .D32(0xabcd1234)
            .D16(0xf00d)
            .D16(0xbeef)
            .append_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08")
            .D32(1) // age
            .append_bytes(b"c:\\foo\\file.pdb\0"); // pdb_file_name
        let module = SynthModule::new(
            Endian::Little,
            0xa90206ca83eb2852,
            0xada542bd,
            &name,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_module(module)
            .add(name)
            .add(cv_record);
        let dump = read_synth_dump(dump).unwrap();
        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        let modules = module_list.iter().collect::<Vec<_>>();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].base_address(), 0xa90206ca83eb2852);
        assert_eq!(modules[0].size(), 0xada542bd);
        assert_eq!(modules[0].code_file(), "single module");
        // time_date_stamp and size_of_image concatenated
        assert_eq!(modules[0].code_identifier(), "B1054D2Aada542bd");
        assert_eq!(modules[0].debug_file().unwrap(), "c:\\foo\\file.pdb");
        assert_eq!(
            modules[0].debug_identifier().unwrap(),
            "ABCD1234F00DBEEF01020304050607081"
        );
    }

    #[test]
    fn test_module_list_overlap() {
        let name1 = DumpString::new("module 1", Endian::Little);
        let name2 = DumpString::new("module 2", Endian::Little);
        let name3 = DumpString::new("module 3", Endian::Little);
        let name4 = DumpString::new("module 4", Endian::Little);
        let name5 = DumpString::new("module 5", Endian::Little);
        let cv_record = Section::with_endian(Endian::Little)
            .D32(md::CvSignature::Pdb70 as u32) // signature
            // signature, a GUID
            .D32(0xabcd1234)
            .D16(0xf00d)
            .D16(0xbeef)
            .append_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08")
            .D32(1) // age
            .append_bytes(b"c:\\foo\\file.pdb\0"); // pdb_file_name
        let module1 = SynthModule::new(
            Endian::Little,
            0x100000000,
            0x4000,
            &name1,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record);
        // module2 overlaps module1 exactly
        let module2 = SynthModule::new(
            Endian::Little,
            0x100000000,
            0x4000,
            &name2,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record);
        // module3 overlaps module1 partially
        let module3 = SynthModule::new(
            Endian::Little,
            0x100000001,
            0x4000,
            &name3,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record);
        // module4 is fully contained within module1
        let module4 = SynthModule::new(
            Endian::Little,
            0x100000001,
            0x3000,
            &name4,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record);
        // module5 is cool, though.
        let module5 = SynthModule::new(
            Endian::Little,
            0x100004000,
            0x4000,
            &name5,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_module(module1)
            .add_module(module2)
            .add_module(module3)
            .add_module(module4)
            .add_module(module5)
            .add(name1)
            .add(name2)
            .add(name3)
            .add(name4)
            .add(name5)
            .add(cv_record);
        let dump = read_synth_dump(dump).unwrap();
        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        let modules = module_list.iter().collect::<Vec<_>>();
        assert_eq!(modules.len(), 5);
        assert_eq!(modules[0].base_address(), 0x100000000);
        assert_eq!(modules[0].size(), 0x4000);
        assert_eq!(modules[0].code_file(), "module 1");
        assert_eq!(modules[1].base_address(), 0x100000000);
        assert_eq!(modules[1].size(), 0x4000);
        assert_eq!(modules[1].code_file(), "module 2");
        assert_eq!(modules[2].base_address(), 0x100000001);
        assert_eq!(modules[2].size(), 0x4000);
        assert_eq!(modules[2].code_file(), "module 3");
        assert_eq!(modules[3].base_address(), 0x100000001);
        assert_eq!(modules[3].size(), 0x3000);
        assert_eq!(modules[3].code_file(), "module 4");
        assert_eq!(modules[4].base_address(), 0x100004000);
        assert_eq!(modules[4].size(), 0x4000);
        assert_eq!(modules[4].code_file(), "module 5");

        // module_at_address should discard overlapping modules.
        assert_eq!(module_list.by_addr().count(), 2);
        assert_eq!(
            module_list
                .module_at_address(0x100001000)
                .unwrap()
                .code_file(),
            "module 1"
        );
        assert_eq!(
            module_list
                .module_at_address(0x100005000)
                .unwrap()
                .code_file(),
            "module 5"
        );
    }

    #[test]
    fn test_memory_list() {
        const CONTENTS: &[u8] = b"memory_contents";
        let memory = Memory::with_section(
            Section::with_endian(Endian::Little).append_bytes(CONTENTS),
            0x309d68010bd21b2c,
        );
        let dump = SynthMinidump::with_endian(Endian::Little).add_memory(memory);
        let dump = read_synth_dump(dump).unwrap();
        let memory_list = dump.get_stream::<MinidumpMemoryList<'_>>().unwrap();
        let regions = memory_list.iter().collect::<Vec<_>>();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].base_address, 0x309d68010bd21b2c);
        assert_eq!(regions[0].size, CONTENTS.len() as u64);
        assert_eq!(&regions[0].bytes, &CONTENTS);
    }

    #[test]
    fn test_memory_list_lifetimes() {
        // A memory list should not own any of the minidump data.
        const CONTENTS: &[u8] = b"memory_contents";
        let memory = Memory::with_section(
            Section::with_endian(Endian::Little).append_bytes(CONTENTS),
            0x309d68010bd21b2c,
        );
        let dump = SynthMinidump::with_endian(Endian::Little).add_memory(memory);
        let dump = read_synth_dump(dump).unwrap();
        let mem_slices: Vec<&[u8]> = {
            let mem_list: MinidumpMemoryList<'_> = dump.get_stream().unwrap();
            mem_list.iter().map(|mem| mem.bytes).collect()
        };
        assert_eq!(mem_slices[0], CONTENTS);
    }

    #[test]
    fn test_memory_list_overlap() {
        let memory1 = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(0, 0x1000),
            0x1000,
        );
        // memory2 overlaps memory1 exactly
        let memory2 = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(1, 0x1000),
            0x1000,
        );
        // memory3 overlaps memory1 partially
        let memory3 = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(2, 0x1000),
            0x1001,
        );
        // memory4 is fully contained within memory1
        let memory4 = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(3, 0x100),
            0x1001,
        );
        // memory5 is cool, though.
        let memory5 = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(4, 0x1000),
            0x2000,
        );
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_memory(memory1)
            .add_memory(memory2)
            .add_memory(memory3)
            .add_memory(memory4)
            .add_memory(memory5);
        let dump = read_synth_dump(dump).unwrap();
        let memory_list = dump.get_stream::<MinidumpMemoryList<'_>>().unwrap();
        let regions = memory_list.iter().collect::<Vec<_>>();
        assert_eq!(regions.len(), 5);
        assert_eq!(regions[0].base_address, 0x1000);
        assert_eq!(regions[0].size, 0x1000);
        assert_eq!(regions[1].base_address, 0x1000);
        assert_eq!(regions[1].size, 0x1000);
        assert_eq!(regions[2].base_address, 0x1001);
        assert_eq!(regions[2].size, 0x1000);
        assert_eq!(regions[3].base_address, 0x1001);
        assert_eq!(regions[3].size, 0x100);
        assert_eq!(regions[4].base_address, 0x2000);
        assert_eq!(regions[4].size, 0x1000);

        // memory_at_address should discard overlapping regions.
        assert_eq!(memory_list.by_addr().count(), 2);
        let m1 = memory_list.memory_at_address(0x1a00).unwrap();
        assert_eq!(m1.base_address, 0x1000);
        assert_eq!(m1.size, 0x1000);
        assert_eq!(m1.bytes, &[0u8; 0x1000][..]);
        let m2 = memory_list.memory_at_address(0x2a00).unwrap();
        assert_eq!(m2.base_address, 0x2000);
        assert_eq!(m2.size, 0x1000);
        assert_eq!(m2.bytes, &[4u8; 0x1000][..]);
    }

    #[test]
    fn test_misc_info() {
        const PID: u32 = 0x1234abcd;
        const PROCESS_TIMES: MiscFieldsProcessTimes = MiscFieldsProcessTimes {
            process_create_time: 0xf0f0b0b0,
            process_user_time: 0xf030a020,
            process_kernel_time: 0xa010b420,
        };

        let mut misc = MiscStream::new(Endian::Little);
        misc.process_id = Some(PID);
        misc.process_times = Some(PROCESS_TIMES);
        let dump = SynthMinidump::with_endian(Endian::Little).add_stream(misc);
        let dump = read_synth_dump(dump).unwrap();
        let misc = dump.get_stream::<MinidumpMiscInfo>().unwrap();
        assert_eq!(misc.raw.process_id(), Some(&PID));
        assert_eq!(
            misc.process_create_time().unwrap(),
            Utc.timestamp(PROCESS_TIMES.process_create_time as i64, 0)
        );
        assert_eq!(
            *misc.raw.process_user_time().unwrap(),
            PROCESS_TIMES.process_user_time
        );
        assert_eq!(
            *misc.raw.process_kernel_time().unwrap(),
            PROCESS_TIMES.process_kernel_time
        );
    }

    #[test]
    fn test_misc_info_large() {
        const PID: u32 = 0x1234abcd;
        const PROCESS_TIMES: MiscFieldsProcessTimes = MiscFieldsProcessTimes {
            process_create_time: 0xf0f0b0b0,
            process_user_time: 0xf030a020,
            process_kernel_time: 0xa010b420,
        };
        let mut misc = MiscStream::new(Endian::Little);
        misc.process_id = Some(PID);
        misc.process_times = Some(PROCESS_TIMES);
        // Make it larger.
        misc.pad_to_size = Some(mem::size_of::<md::MINIDUMP_MISC_INFO>() + 32);
        let dump = SynthMinidump::with_endian(Endian::Little).add_stream(misc);
        let dump = read_synth_dump(dump).unwrap();
        let misc = dump.get_stream::<MinidumpMiscInfo>().unwrap();
        assert_eq!(misc.raw.process_id(), Some(&PID));
        assert_eq!(
            misc.process_create_time().unwrap(),
            Utc.timestamp(PROCESS_TIMES.process_create_time as i64, 0)
        );
        assert_eq!(
            *misc.raw.process_user_time().unwrap(),
            PROCESS_TIMES.process_user_time
        );
        assert_eq!(
            *misc.raw.process_kernel_time().unwrap(),
            PROCESS_TIMES.process_kernel_time
        );
    }

    fn ascii_string_to_utf16(input: &str) -> Vec<u16> {
        input.chars().map(|c| c as u16).collect()
    }

    #[test]
    fn test_misc_info_5() {
        // MISC_INFO fields
        const PID: u32 = 0x1234abcd;
        const PROCESS_TIMES: MiscFieldsProcessTimes = MiscFieldsProcessTimes {
            process_create_time: 0xf0f0b0b0,
            process_user_time: 0xf030a020,
            process_kernel_time: 0xa010b420,
        };

        // MISC_INFO_2 fields
        const POWER_INFO: MiscFieldsPowerInfo = MiscFieldsPowerInfo {
            processor_max_mhz: 0x45873234,
            processor_current_mhz: 0x2134018a,
            processor_mhz_limit: 0x3423aead,
            processor_max_idle_state: 0x123aef12,
            processor_current_idle_state: 0x1205af3a,
        };

        // MISC_INFO_3 fields
        const PROCESS_INTEGRITY_LEVEL: u32 = 0x35603403;
        const PROCESS_EXECUTE_FLAGS: u32 = 0xa4e09da1;
        const PROTECTED_PROCESS: u32 = 0x12345678;

        let mut standard_name = [0; 32];
        let mut daylight_name = [0; 32];
        let bare_standard_name = ascii_string_to_utf16("Pacific Standard Time");
        let bare_daylight_name = ascii_string_to_utf16("Pacific Daylight Time");
        standard_name[..bare_standard_name.len()].copy_from_slice(&bare_standard_name);
        daylight_name[..bare_daylight_name.len()].copy_from_slice(&bare_daylight_name);

        const TIME_ZONE_ID: u32 = 2;
        const BIAS: i32 = 2;
        const STANDARD_BIAS: i32 = 1;
        const DAYLIGHT_BIAS: i32 = -60;
        const STANDARD_DATE: md::SYSTEMTIME = md::SYSTEMTIME {
            year: 0,
            month: 11,
            day_of_week: 2,
            day: 1,
            hour: 2,
            minute: 33,
            second: 51,
            milliseconds: 123,
        };
        const DAYLIGHT_DATE: md::SYSTEMTIME = md::SYSTEMTIME {
            year: 0,
            month: 3,
            day_of_week: 4,
            day: 2,
            hour: 3,
            minute: 41,
            second: 19,
            milliseconds: 512,
        };

        let time_zone = MiscFieldsTimeZone {
            time_zone_id: TIME_ZONE_ID,
            time_zone: md::TIME_ZONE_INFORMATION {
                bias: BIAS,
                standard_bias: STANDARD_BIAS,
                daylight_bias: DAYLIGHT_BIAS,
                daylight_name,
                standard_name,
                standard_date: STANDARD_DATE.clone(),
                daylight_date: DAYLIGHT_DATE.clone(),
            },
        };

        // MISC_INFO_4 fields
        let mut build_string = [0; 260];
        let mut dbg_bld_str = [0; 40];
        let bare_build_string = ascii_string_to_utf16("hello");
        let bare_dbg_bld_str = ascii_string_to_utf16("world");
        build_string[..bare_build_string.len()].copy_from_slice(&bare_build_string);
        dbg_bld_str[..bare_dbg_bld_str.len()].copy_from_slice(&bare_dbg_bld_str);

        let build_strings = MiscFieldsBuildString {
            build_string,
            dbg_bld_str,
        };

        // MISC_INFO_5 fields
        const SIZE_OF_INFO: u32 = mem::size_of::<md::XSTATE_CONFIG_FEATURE_MSC_INFO>() as u32;
        const CONTEXT_SIZE: u32 = 0x1234523f;
        const PROCESS_COOKIE: u32 = 0x1234dfe0;
        const KNOWN_FEATURE_IDX: usize = md::XstateFeatureIndex::LEGACY_SSE as usize;
        const UNKNOWN_FEATURE_IDX: usize = 39;
        let mut enabled_features = 0;
        let mut features = [md::XSTATE_FEATURE::default(); 64];
        // One known feature and one unknown feature.
        enabled_features |= 1 << KNOWN_FEATURE_IDX;
        features[KNOWN_FEATURE_IDX] = md::XSTATE_FEATURE {
            offset: 0,
            size: 140,
        };
        enabled_features |= 1 << UNKNOWN_FEATURE_IDX;
        features[UNKNOWN_FEATURE_IDX] = md::XSTATE_FEATURE {
            offset: 320,
            size: 1100,
        };
        let misc_5 = MiscInfo5Fields {
            xstate_data: md::XSTATE_CONFIG_FEATURE_MSC_INFO {
                size_of_info: SIZE_OF_INFO,
                context_size: CONTEXT_SIZE,
                enabled_features,
                features,
            },
            process_cookie: Some(PROCESS_COOKIE),
        };

        let mut misc = MiscStream::new(Endian::Little);
        misc.process_id = Some(PID);
        misc.process_times = Some(PROCESS_TIMES);
        misc.power_info = Some(POWER_INFO);
        misc.process_integrity_level = Some(PROCESS_INTEGRITY_LEVEL);
        misc.protected_process = Some(PROTECTED_PROCESS);
        misc.process_execute_flags = Some(PROCESS_EXECUTE_FLAGS);
        misc.time_zone = Some(time_zone);
        misc.build_strings = Some(build_strings);
        misc.misc_5 = Some(misc_5);

        let dump = SynthMinidump::with_endian(Endian::Little).add_stream(misc);
        let dump = read_synth_dump(dump).unwrap();
        let misc = dump.get_stream::<MinidumpMiscInfo>().unwrap();

        // MISC_INFO fields
        assert_eq!(misc.raw.process_id(), Some(&PID));
        assert_eq!(
            misc.process_create_time().unwrap(),
            Utc.timestamp(PROCESS_TIMES.process_create_time as i64, 0)
        );
        assert_eq!(
            *misc.raw.process_user_time().unwrap(),
            PROCESS_TIMES.process_user_time
        );
        assert_eq!(
            *misc.raw.process_kernel_time().unwrap(),
            PROCESS_TIMES.process_kernel_time
        );

        // MISC_INFO_2 fields
        assert_eq!(
            *misc.raw.processor_max_mhz().unwrap(),
            POWER_INFO.processor_max_mhz,
        );
        assert_eq!(
            *misc.raw.processor_current_mhz().unwrap(),
            POWER_INFO.processor_current_mhz,
        );
        assert_eq!(
            *misc.raw.processor_mhz_limit().unwrap(),
            POWER_INFO.processor_mhz_limit,
        );
        assert_eq!(
            *misc.raw.processor_max_idle_state().unwrap(),
            POWER_INFO.processor_max_idle_state,
        );
        assert_eq!(
            *misc.raw.processor_current_idle_state().unwrap(),
            POWER_INFO.processor_current_idle_state,
        );

        // MISC_INFO_3 fields
        assert_eq!(*misc.raw.time_zone_id().unwrap(), TIME_ZONE_ID);
        let time_zone = misc.raw.time_zone().unwrap();
        assert_eq!(time_zone.bias, BIAS);
        assert_eq!(time_zone.standard_bias, STANDARD_BIAS);
        assert_eq!(time_zone.daylight_bias, DAYLIGHT_BIAS);
        assert_eq!(time_zone.standard_date, STANDARD_DATE);
        assert_eq!(time_zone.daylight_date, DAYLIGHT_DATE);
        assert_eq!(time_zone.standard_name, standard_name);
        assert_eq!(time_zone.daylight_name, daylight_name);

        // MISC_INFO_4 fields
        assert_eq!(*misc.raw.build_string().unwrap(), build_string,);
        assert_eq!(*misc.raw.dbg_bld_str().unwrap(), dbg_bld_str,);

        // MISC_INFO_5 fields
        assert_eq!(*misc.raw.process_cookie().unwrap(), PROCESS_COOKIE,);

        let xstate = misc.raw.xstate_data().unwrap();
        assert_eq!(xstate.size_of_info, SIZE_OF_INFO);
        assert_eq!(xstate.context_size, CONTEXT_SIZE);
        assert_eq!(xstate.enabled_features, enabled_features);
        assert_eq!(xstate.features, features);

        let mut xstate_iter = xstate.iter();
        assert_eq!(
            xstate_iter.next().unwrap(),
            (KNOWN_FEATURE_IDX, features[KNOWN_FEATURE_IDX]),
        );
        assert_eq!(
            xstate_iter.next().unwrap(),
            (UNKNOWN_FEATURE_IDX, features[UNKNOWN_FEATURE_IDX]),
        );
        assert_eq!(xstate_iter.next(), None);
        assert_eq!(xstate_iter.next(), None);
    }

    #[test]
    fn test_elf_build_id() {
        // Add a module with a long ELF build id
        let name1 = DumpString::new("module 1", Endian::Little);
        const MODULE1_BUILD_ID: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let cv_record1 = Section::with_endian(Endian::Little)
            .D32(md::CvSignature::Elf as u32) // signature
            .append_bytes(MODULE1_BUILD_ID);
        let module1 = SynthModule::new(
            Endian::Little,
            0x100000000,
            0x4000,
            &name1,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record1);
        // Add a module with a short ELF build id
        let name2 = DumpString::new("module 2", Endian::Little);
        const MODULE2_BUILD_ID: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let cv_record2 = Section::with_endian(Endian::Little)
            .D32(md::CvSignature::Elf as u32) // signature
            .append_bytes(MODULE2_BUILD_ID);
        let module2 = SynthModule::new(
            Endian::Little,
            0x200000000,
            0x4000,
            &name2,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record2);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_module(module1)
            .add_module(module2)
            .add(name1)
            .add(cv_record1)
            .add(name2)
            .add(cv_record2);
        let dump = read_synth_dump(dump).unwrap();
        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        let modules = module_list.iter().collect::<Vec<_>>();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].base_address(), 0x100000000);
        assert_eq!(modules[0].code_file(), "module 1");
        // The full build ID.
        assert_eq!(
            modules[0].code_identifier(),
            "000102030405060708090a0b0c0d0e0f1011121314151617"
        );
        assert_eq!(modules[0].debug_file().unwrap(), "module 1");
        // The first 16 bytes of the build ID interpreted as a GUID.
        assert_eq!(
            modules[0].debug_identifier().unwrap(),
            "030201000504070608090A0B0C0D0E0F0"
        );

        assert_eq!(modules[1].base_address(), 0x200000000);
        assert_eq!(modules[1].code_file(), "module 2");
        // The full build ID.
        assert_eq!(modules[1].code_identifier(), "0001020304050607");
        assert_eq!(modules[1].debug_file().unwrap(), "module 2");
        // The first 16 bytes of the build ID interpreted as a GUID, padded with
        // zeroes in this case.
        assert_eq!(
            modules[1].debug_identifier().unwrap(),
            "030201000504070600000000000000000"
        );
    }

    #[test]
    fn test_thread_list_x86() {
        let context = synth_minidump::x86_context(Endian::Little, 0xabcd1234, 0x1010);
        let stack = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(0, 0x1000),
            0x1000,
        );
        let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_thread(thread)
            .add(context)
            .add_memory(stack);
        let dump = read_synth_dump(dump).unwrap();
        let mut thread_list = dump.get_stream::<MinidumpThreadList<'_>>().unwrap();
        assert_eq!(thread_list.threads.len(), 1);
        let mut thread = thread_list.threads.pop().unwrap();
        assert_eq!(thread.raw.thread_id, 0x1234);
        let context = thread.context.expect("Should have a thread context");
        match context.raw {
            MinidumpRawContext::X86(raw) => {
                assert_eq!(raw.eip, 0xabcd1234);
                assert_eq!(raw.esp, 0x1010);
            }
            _ => panic!("Got unexpected raw context type!"),
        }
        let stack = thread.stack.take().expect("Should have stack memory");
        assert_eq!(stack.base_address, 0x1000);
        assert_eq!(stack.size, 0x1000);
    }

    #[test]
    fn test_thread_list_amd64() {
        let context =
            synth_minidump::amd64_context(Endian::Little, 0x1234abcd1234abcd, 0x1000000010000000);
        let stack = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(0, 0x1000),
            0x1000000010000000,
        );
        let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_thread(thread)
            .add(context)
            .add_memory(stack);
        let dump = read_synth_dump(dump).unwrap();
        let mut thread_list = dump.get_stream::<MinidumpThreadList<'_>>().unwrap();
        assert_eq!(thread_list.threads.len(), 1);
        let mut thread = thread_list.threads.pop().unwrap();
        assert_eq!(thread.raw.thread_id, 0x1234);
        let context = thread.context.expect("Should have a thread context");
        match context.raw {
            MinidumpRawContext::Amd64(raw) => {
                assert_eq!(raw.rip, 0x1234abcd1234abcd);
                assert_eq!(raw.rsp, 0x1000000010000000);
            }
            _ => panic!("Got unexpected raw context type!"),
        }
        let stack = thread.stack.take().expect("Should have stack memory");
        assert_eq!(stack.base_address, 0x1000000010000000);
        assert_eq!(stack.size, 0x1000);
    }

    #[test]
    fn test_crashpad_info_missing() {
        let dump = SynthMinidump::with_endian(Endian::Little);
        let dump = read_synth_dump(dump).unwrap();

        assert!(matches!(
            dump.get_stream::<MinidumpCrashpadInfo>(),
            Err(Error::StreamNotFound)
        ));
    }

    #[test]
    fn test_crashpad_info_ids() {
        let report_id = GUID {
            data1: 1,
            data2: 2,
            data3: 3,
            data4: [4, 5, 6, 7, 8, 9, 10, 11],
        };

        let client_id = GUID {
            data1: 11,
            data2: 10,
            data3: 9,
            data4: [8, 7, 6, 5, 4, 3, 2, 1],
        };

        let crashpad_info = CrashpadInfo::new(Endian::Little)
            .report_id(report_id)
            .client_id(client_id);

        let dump = SynthMinidump::with_endian(Endian::Little).add_crashpad_info(crashpad_info);
        let dump = read_synth_dump(dump).unwrap();

        let crashpad_info = dump.get_stream::<MinidumpCrashpadInfo>().unwrap();

        assert_eq!(crashpad_info.raw.report_id, report_id);
        assert_eq!(crashpad_info.raw.client_id, client_id);
    }

    #[test]
    fn test_crashpad_info_annotations() {
        let module = ModuleCrashpadInfo::new(42, Endian::Little)
            .add_list_annotation("annotation")
            .add_simple_annotation("simple", "module")
            .add_annotation_object("string", AnnotationValue::String("value".to_owned()))
            .add_annotation_object("invalid", AnnotationValue::Invalid)
            .add_annotation_object("custom", AnnotationValue::Custom(0x8001, vec![42]));

        let crashpad_info = CrashpadInfo::new(Endian::Little)
            .add_module(module)
            .add_simple_annotation("simple", "info");

        let dump = SynthMinidump::with_endian(Endian::Little).add_crashpad_info(crashpad_info);
        let dump = read_synth_dump(dump).unwrap();

        let crashpad_info = dump.get_stream::<MinidumpCrashpadInfo>().unwrap();
        let module = &crashpad_info.module_list[0];

        assert_eq!(crashpad_info.simple_annotations["simple"], "info");
        assert_eq!(module.module_index, 42);
        assert_eq!(module.list_annotations, vec!["annotation".to_owned()]);
        assert_eq!(module.simple_annotations["simple"], "module");
        assert_eq!(
            module.annotation_objects["string"],
            MinidumpAnnotation::String("value".to_owned())
        );
        assert_eq!(
            module.annotation_objects["invalid"],
            MinidumpAnnotation::Invalid
        );
    }
}
