// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use debugid::{CodeId, DebugId};
use encoding::all::{UTF_16BE, UTF_16LE};
use encoding::{DecoderTrap, Encoding};
use memmap2::Mmap;
use num_traits::FromPrimitive;
use scroll::ctx::{SizeWith, TryFromCtx};
use scroll::{self, Pread, BE, LE};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::TryInto;
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
use std::time::{Duration, SystemTime};
use tracing::warn;
use uuid::Uuid;

pub use crate::context::*;
use crate::strings::*;
use crate::system_info::{Cpu, Os, PointerWidth};
use minidump_common::errors::{self as err};
use minidump_common::format::{self as md};
use minidump_common::format::{CvSignature, MINIDUMP_STREAM_TYPE};
use minidump_common::traits::{IntoRangeMapSafe, Module};
use range_map::{Range, RangeMap};
use time::format_description::well_known::Rfc3339;

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
    system_info: Option<MinidumpSystemInfo>,
    /// The endianness of this minidump file.
    pub endian: scroll::Endian,
    _phantom: PhantomData<&'a [u8]>,
}

/// Errors encountered while reading a `Minidump`.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("File not found")]
    FileNotFound,
    #[error("I/O error")]
    IoError,
    #[error("Missing minidump header (empty minidump?)")]
    MissingHeader,
    #[error("Header mismatch")]
    HeaderMismatch,
    #[error("Minidump version mismatch")]
    VersionMismatch,
    #[error("Missing stream directory (heavily truncated minidump?)")]
    MissingDirectory,
    #[error("Error reading stream")]
    StreamReadFailure,
    #[error("Stream size mismatch: expected {expected} bytes, found {actual} bytes")]
    StreamSizeMismatch { expected: usize, actual: usize },
    #[error("Stream not found")]
    StreamNotFound,
    #[error("Module read failure")]
    ModuleReadFailure,
    #[error("Memory read failure")]
    MemoryReadFailure,
    #[error("Data error")]
    DataError,
    #[error("Error reading CodeView data")]
    CodeViewReadFailure,
}

impl Error {
    /// Returns just the name of the error, as a more human-friendly version of
    /// an error-code for error logging.
    pub fn name(&self) -> &'static str {
        match self {
            Error::FileNotFound => "FileNotFound",
            Error::IoError => "IoError",
            Error::MissingHeader => "MissingHeader",
            Error::HeaderMismatch => "HeaderMismatch",
            Error::VersionMismatch => "VersionMismatch",
            Error::MissingDirectory => "MissingDirectory",
            Error::StreamReadFailure => "StreamReadFailure",
            Error::StreamSizeMismatch { .. } => "StreamSizeMismatch",
            Error::StreamNotFound => "StreamNotFound",
            Error::ModuleReadFailure => "ModuleReadFailure",
            Error::MemoryReadFailure => "MemoryReadFailure",
            Error::DataError => "DataError",
            Error::CodeViewReadFailure => "CodeViewReadFailure",
        }
    }
}

/// The fundamental unit of data in a `Minidump`.
pub trait MinidumpStream<'a>: Sized {
    /// The stream type constant used in the `md::MDRawDirectory` entry.
    /// This is usually a [MINIDUMP_STREAM_TYPE][] but it's left as a u32
    /// to allow external projects to add support for their own custom streams.
    const STREAM_TYPE: u32;

    /// Read this `MinidumpStream` type from `bytes`.
    ///
    /// * `bytes` is the contents of this specific stream.
    /// * `all` refers to the full contents of the minidump, for reading auxilliary data
    ///   referred to with `MINIDUMP_LOCATION_DESCRIPTOR`s.
    /// * `system_info` is the preparsed SystemInfo stream, if it exists in the minidump.
    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<Self, Error>;
}

/// Provides a unified interface for getting metadata about the process's mapped memory regions
/// at the time of the crash.
///
/// Currently this is one of [`MinidumpMemoryInfoList`], available in Windows minidumps,
/// or [`MinidumpLinuxMaps`], available in Linux minidumps.
///
/// This allows you to e.g. check whether an address was executable or not without
/// worrying about which platform the crash occured on. If you need to do more
/// specific analysis, you can get the native formats with [`UnifiedMemoryInfoList::info`]
/// and [`UnifiedMemoryInfoList::maps`].
///
/// Currently an enum because there is no situation where you can have both,
/// but this may change if the format evolves. Prefer using this type's methods
/// over pattern matching.
#[derive(Debug, Clone)]
pub enum UnifiedMemoryInfoList<'a> {
    Maps(MinidumpLinuxMaps<'a>),
    Info(MinidumpMemoryInfoList<'a>),
}

#[derive(Debug, Copy, Clone)]
/// A [`UnifiedMemoryInfoList`] entry, providing metatadata on a region of
/// memory in the crashed process.
pub enum UnifiedMemoryInfo<'a> {
    Map(&'a MinidumpLinuxMapInfo<'a>),
    Info(&'a MinidumpMemoryInfo<'a>),
}

/// The contents of `/proc/self/maps` for the crashing process.
///
/// This is roughly equivalent in functionality to [`MinidumpMemoryInfoList`].
/// Use [`UnifiedMemoryInfoList`] to handle the two uniformly.
#[derive(Debug, Clone)]
pub struct MinidumpLinuxMaps<'a> {
    /// The memory regions, in the order they were stored in the minidump.
    regions: Vec<MinidumpLinuxMapInfo<'a>>,
    /// Map from address range to index in regions. Use
    /// [`MinidumpLinuxMaps::memory_info_at_address`].
    regions_by_addr: RangeMap<u64, usize>,
}

/// A memory mapping entry for the process we are analyzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinidumpLinuxMapInfo<'a> {
    /// The first address this metadata applies to
    pub base_address: u64,
    /// The last address this metadata applies to
    pub final_address: u64,

    /// The kind of mapping
    pub kind: MinidumpLinuxMapKind<'a>,

    // FIXME: These could be bitflags but I'm not worried about it right now
    /// Whether the memory region is readable.
    pub is_read: bool,
    /// Whether the memory region is writeable.
    pub is_write: bool,
    /// Whether the memory region is executable.
    pub is_exec: bool,
    /// Whether the memory region is shared.
    pub is_shared: bool,
    /// Whether the memory region is private (copy-on-write).
    pub is_private: bool,

    // Fields in the format we ignore (not yet useful)
    // * offset
    // * dev
    // * inode
    _phantom: PhantomData<&'a u8>,
}

/// A broad classification of the mapped memory described by a [`MinidumpLinuxMapInfo`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinidumpLinuxMapKind<'a> {
    /// This is the main thread's stack.
    MainThreadStack,
    /// This is the stack of a non-main thread with the given `tid`.
    Stack(u64),
    /// This is the process's heap.
    Heap,
    /// This is the "Virtual Dynamically-linked Shared Object".
    Vdso,
    /// This is an anonymous mmap.
    AnonymousMap,
    /// Some other special kind that we don't know/care about.
    UnknownSpecial(Cow<'a, LinuxOsStr>),
    /// This is a mapped file/device at the given path.
    File(Cow<'a, LinuxOsStr>),
    /// This is a mapped file/device at the given path, and that file was deleted.
    DeletedFile(Cow<'a, LinuxOsStr>),
}

#[derive(Debug, Clone)]
pub struct MinidumpMemoryInfoList<'a> {
    /// The memory regions, in the order they were stored in the minidump.
    regions: Vec<MinidumpMemoryInfo<'a>>,
    /// Map from address range to index in regions. Use
    /// [`MinidumpMemoryInfoList::memory_info_at_address`].
    regions_by_addr: RangeMap<u64, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Metadata about a region of memory (whether it is executable, freed, private, and so on).
pub struct MinidumpMemoryInfo<'a> {
    /// The raw value from the minidump.
    raw: md::MINIDUMP_MEMORY_INFO,
    /// The memory protection when the region was initially allocated.
    pub allocation_protection: md::MemoryProtection,
    /// The state of the pages in the region (whether it is freed or not).
    pub state: md::MemoryState,
    /// The access protection of the pages in the region.
    pub protection: md::MemoryProtection,
    /// What kind of memory mapping the pages in this region are.
    pub ty: md::MemoryType,
    _phantom: PhantomData<&'a u8>,
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
    os: Os,
    /// The parsed DebugId of the module, if one is present.
    debug_id: Option<DebugId>,
}

/// A list of `MinidumpModule`s contained in a `Minidump`.
#[derive(Debug, Clone)]
pub struct MinidumpModuleList {
    /// The modules, in the order they were stored in the minidump.
    modules: Vec<MinidumpModule>,
    /// Map from address range to index in modules. Use `MinidumpModuleList::module_at_address`.
    modules_by_addr: RangeMap<u64, usize>,
}

/// A mapping of thread ids to their names.
#[derive(Debug, Clone, Default)]
pub struct MinidumpThreadNames {
    names: HashMap<u32, String>,
}

/// An executable or shared library that was once loaded into the process, but was unloaded
/// by the time the `Minidump` was written.
#[derive(Debug, Clone)]
pub struct MinidumpUnloadedModule {
    /// The `MINIDUMP_UNLOADED_MODULE` direct from the minidump file.
    pub raw: md::MINIDUMP_UNLOADED_MODULE,
    /// The module name. This is stored separately in the minidump.
    pub name: String,
}

/// A list of `MinidumpUnloadedModule`s contained in a `Minidump`.
#[derive(Debug, Clone)]
pub struct MinidumpUnloadedModuleList {
    /// The modules, in the order they were stored in the minidump.
    modules: Vec<MinidumpUnloadedModule>,
    /// Map from address range to index in modules.
    /// Use `MinidumpUnloadedModuleList::modules_at_address`.
    modules_by_addr: Vec<(Range<u64>, usize)>,
}

/// The state of a thread from the process when the minidump was written.
#[derive(Debug)]
pub struct MinidumpThread<'a> {
    /// The `MINIDUMP_THREAD` direct from the minidump file.
    pub raw: md::MINIDUMP_THREAD,
    /// The CPU context for the thread, if present.
    context: Option<&'a [u8]>,
    /// The stack memory for the thread, if present.
    stack: Option<MinidumpMemory<'a>>,
    /// Saved endianess for lazy parsing.
    endian: scroll::Endian,
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
#[derive(Debug, Clone)]
pub struct MinidumpSystemInfo {
    /// The `MINIDUMP_SYSTEM_INFO` direct from the minidump
    pub raw: md::MINIDUMP_SYSTEM_INFO,
    /// The operating system that generated the minidump
    pub os: Os,
    /// The CPU on which the minidump was generated
    pub cpu: Cpu,
    /// A string that describes the latest Service Pack installed on the system.
    /// If no Service Pack has been installed, the string is empty.
    /// This is stored separately in the minidump.
    csd_version: Option<String>,
    /// An x86 (not x64!) CPU vendor name that is stored in `raw` but in a way
    /// that's
    cpu_info: Option<String>,
}

/// A region of memory from the process that wrote the minidump.
/// This is the underlying generic type for [MinidumpMemory] and [MinidumpMemory64].
#[derive(Clone, Debug)]
pub struct MinidumpMemoryBase<'a, Descriptor> {
    /// The raw `MINIDUMP_MEMORY_DESCRIPTOR` from the minidump.
    pub desc: Descriptor,
    /// The starting address of this range of memory.
    pub base_address: u64,
    /// The length of this range of memory.
    pub size: u64,
    /// The contents of the memory.
    pub bytes: &'a [u8],
}

/// A region of memory from the process that wrote the minidump.
pub type MinidumpMemory<'a> = MinidumpMemoryBase<'a, md::MINIDUMP_MEMORY_DESCRIPTOR>;

/// A large region of memory from the process that wrote the minidump (usually a full dump).
pub type MinidumpMemory64<'a> = MinidumpMemoryBase<'a, md::MINIDUMP_MEMORY_DESCRIPTOR64>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum RawMacCrashInfo {
    V1(
        md::MINIDUMP_MAC_CRASH_INFO_RECORD,
        md::MINIDUMP_MAC_CRASH_INFO_RECORD_STRINGS,
    ),
    V4(
        md::MINIDUMP_MAC_CRASH_INFO_RECORD_4,
        md::MINIDUMP_MAC_CRASH_INFO_RECORD_STRINGS_4,
    ),
    V5(
        md::MINIDUMP_MAC_CRASH_INFO_RECORD_5,
        md::MINIDUMP_MAC_CRASH_INFO_RECORD_STRINGS_5,
    ),
}

#[derive(Debug)]
pub struct MinidumpMacCrashInfo {
    /// The `MINIDUMP_MAC_CRASH_INFO_RECORD` and `MINIDUMP_MAC_CRASH_INFO_RECORD_STRINGS`.
    pub raw: Vec<RawMacCrashInfo>,
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

#[derive(Default, Debug)]
/// Interesting values extracted from /etc/lsb-release
pub struct MinidumpLinuxLsbRelease<'a> {
    data: &'a [u8],
}

/// Interesting values extracted from /proc/self/environ
#[derive(Default, Debug)]
pub struct MinidumpLinuxEnviron<'a> {
    data: &'a [u8],
}

/// Interesting values extracted from /proc/cpuinfo
#[derive(Default, Debug)]
pub struct MinidumpLinuxCpuInfo<'a> {
    data: &'a [u8],
}

/// Interesting values extracted from /proc/self/status
#[derive(Default, Debug)]
pub struct MinidumpLinuxProcStatus<'a> {
    data: &'a [u8],
}

/// The reason for a process crash.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CrashReason {
    /// A Mac/iOS error code with no other interesting details.
    MacGeneral(err::ExceptionCodeMac, u32),
    MacBadAccessKern(err::ExceptionCodeMacBadAccessKernType),
    MacBadAccessArm(err::ExceptionCodeMacBadAccessArmType),
    MacBadAccessPpc(err::ExceptionCodeMacBadAccessPpcType),
    MacBadAccessX86(err::ExceptionCodeMacBadAccessX86Type),
    MacBadInstructionArm(err::ExceptionCodeMacBadInstructionArmType),
    MacBadInstructionPpc(err::ExceptionCodeMacBadInstructionPpcType),
    MacBadInstructionX86(err::ExceptionCodeMacBadInstructionX86Type),
    MacArithmeticPpc(err::ExceptionCodeMacArithmeticPpcType),
    MacArithmeticX86(err::ExceptionCodeMacArithmeticX86Type),
    MacSoftware(err::ExceptionCodeMacSoftwareType),
    MacBreakpointArm(err::ExceptionCodeMacBreakpointArmType),
    MacBreakpointPpc(err::ExceptionCodeMacBreakpointPpcType),
    MacBreakpointX86(err::ExceptionCodeMacBreakpointX86Type),
    MacResource(err::ExceptionCodeMacResourceType, u64, u64),
    MacGuard(err::ExceptionCodeMacGuardType, u64, u64),

    /// A Linux/Android error code with no other interesting metadata.
    LinuxGeneral(err::ExceptionCodeLinux, u32),
    LinuxSigill(err::ExceptionCodeLinuxSigillKind),
    LinuxSigtrap(err::ExceptionCodeLinuxSigtrapKind),
    LinuxSigbus(err::ExceptionCodeLinuxSigbusKind),
    LinuxSigfpe(err::ExceptionCodeLinuxSigfpeKind),
    LinuxSigsegv(err::ExceptionCodeLinuxSigsegvKind),
    LinuxSigsys(err::ExceptionCodeLinuxSigsysKind),

    /// A Windows error code with no other interesting metadata.
    WindowsGeneral(err::ExceptionCodeWindows),
    /// A Windows error from winerror.h.
    WindowsWinError(err::WinErrorWindows),
    /// A Windows error from ntstatus.h
    WindowsNtStatus(err::NtStatusWindows),
    /// ExceptionCodeWindows::EXCEPTION_ACCESS_VIOLATION but with details on the kind of access.
    WindowsAccessViolation(err::ExceptionCodeWindowsAccessType),
    /// ExceptionCodeWindows::EXCEPTION_IN_PAGE_ERROR but with details on the kind of access.
    /// Second argument is a windows NTSTATUS value.
    WindowsInPageError(err::ExceptionCodeWindowsInPageErrorType, u64),
    /// ExceptionCodeWindows::EXCEPTION_STACK_BUFFER_OVERRUN with an accompanying
    /// windows FAST_FAIL value.
    WindowsStackBufferOverrun(u64),
    /// A Windows error with no known mapping.
    WindowsUnknown(u32),

    Unknown(u32, u32),
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
pub struct MinidumpException<'a> {
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
    context: Option<&'a [u8]>,
    /// Saved endianess for lazy parsing.
    endian: scroll::Endian,
}

/// A list of memory regions included in a minidump.
/// This is the underlying generic type for [MinidumpMemoryList] and [MinidumpMemory64List].
#[derive(Debug)]
pub struct MinidumpMemoryListBase<'a, Descriptor> {
    /// The memory regions, in the order they were stored in the  minidump.
    regions: Vec<MinidumpMemoryBase<'a, Descriptor>>,
    /// Map from address range to index in regions. Use `MinidumpMemoryList::memory_at_address`.
    regions_by_addr: RangeMap<u64, usize>,
}

/// A list of memory regions included in a minidump.
pub type MinidumpMemoryList<'a> = MinidumpMemoryListBase<'a, md::MINIDUMP_MEMORY_DESCRIPTOR>;

/// A list of large memory regions included in a minidump (usually a full dump).
pub type MinidumpMemory64List<'a> = MinidumpMemoryListBase<'a, md::MINIDUMP_MEMORY_DESCRIPTOR64>;

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
    time::OffsetDateTime::from_unix_timestamp(t as i64)
        .ok()
        .and_then(|datetime| datetime.format(&Rfc3339).ok())
        .unwrap_or_default()
}

fn format_system_time(time: &md::SYSTEMTIME) -> String {
    // Note this drops the day_of_week field on the ground -- is that fine?
    let format_date = || {
        use std::convert::TryFrom;
        let month = time::Month::try_from(time.month as u8).ok()?;
        let date = time::Date::from_calendar_date(time.year as i32, month, time.day as u8).ok()?;
        let datetime = date
            .with_hms_milli(
                time.hour as u8,
                time.minute as u8,
                time.second as u8,
                time.milliseconds,
            )
            .ok()?
            .assume_utc();
        datetime.format(&Rfc3339).ok()
    };
    format_date().unwrap_or_else(|| "<invalid date>".to_owned())
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
fn read_string_utf16(offset: &mut usize, bytes: &[u8], endian: scroll::Endian) -> Option<String> {
    let u: u32 = bytes.gread_with(offset, endian).ok()?;
    let size = u as usize;
    if size % 2 != 0 || (*offset + size) > bytes.len() {
        return None;
    }
    let encoding: &dyn Encoding = match endian {
        scroll::Endian::Little => UTF_16LE,
        scroll::Endian::Big => UTF_16BE,
    };
    let s = encoding
        .decode(&bytes[*offset..*offset + size], DecoderTrap::Strict)
        .ok()?;
    *offset += size;
    Some(s)
}

#[inline]
fn read_string_utf8_unterminated<'a>(
    offset: &mut usize,
    bytes: &'a [u8],
    endian: scroll::Endian,
) -> Option<&'a str> {
    let length: u32 = bytes.gread_with(offset, endian).ok()?;
    let slice = bytes.gread_with(offset, length as usize).ok()?;
    std::str::from_utf8(slice).ok()
}

fn read_string_utf8<'a>(
    offset: &mut usize,
    bytes: &'a [u8],
    endian: scroll::Endian,
) -> Option<&'a str> {
    let string = read_string_utf8_unterminated(offset, bytes, endian)?;
    match bytes.gread(offset) {
        Ok(0u8) => Some(string),
        _ => None,
    }
}

fn read_cstring_utf8(offset: &mut usize, bytes: &[u8]) -> Option<String> {
    let initial_offset = *offset;
    loop {
        let byte: u8 = bytes.gread(offset).ok()?;
        if byte == 0 {
            break;
        }
    }
    std::str::from_utf8(&bytes[initial_offset..*offset - 1])
        .map(String::from)
        .ok()
}

/// Convert `bytes` with trailing NUL characters to a string
fn string_from_bytes_nul(bytes: &[u8]) -> Option<Cow<'_, str>> {
    bytes.split(|&b| b == 0).next().map(String::from_utf8_lossy)
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
) -> Option<CodeView> {
    let bytes = location_slice(data, location).ok()?;
    // The CodeView data can be one of a few different formats. Try to read the
    // signature first to figure out what format the data is.
    let signature: u32 = bytes.pread_with(0, endian).ok()?;
    Some(match CvSignature::from_u32(signature) {
        // PDB data has two known versions: the current 7.0 and the older 2.0 version.
        Some(CvSignature::Pdb70) => CodeView::Pdb70(bytes.pread_with(0, endian).ok()?),
        Some(CvSignature::Pdb20) => CodeView::Pdb20(bytes.pread_with(0, endian).ok()?),
        // Breakpad's ELF build ID format.
        Some(CvSignature::Elf) => CodeView::Elf(bytes.pread_with(0, endian).ok()?),
        // Other formats aren't handled, but save the raw bytes.
        _ => CodeView::Unknown(bytes.to_owned()),
    })
}

fn read_debug_id(codeview_info: &CodeView, endian: scroll::Endian) -> Option<DebugId> {
    match codeview_info {
        CodeView::Pdb70(ref raw) => {
            // For macOS, this should be its code ID with the age (0)
            // appended to the end of it. This makes it identical to debug
            // IDs for Windows, and is why it doesn't have a special case
            // here.
            let uuid = Uuid::from_fields(
                raw.signature.data1,
                raw.signature.data2,
                raw.signature.data3,
                &raw.signature.data4,
            );
            (!uuid.is_nil()).then(|| DebugId::from_parts(uuid, raw.age))
        }
        CodeView::Pdb20(ref raw) => Some(DebugId::from_pdb20(raw.signature, raw.age)),
        CodeView::Elf(ref raw) => {
            // For empty or trivial `build_id`s, we don't want to return a `DebugId`.
            // This can happen for mapped files that aren't executable, like fonts or .jar files.
            if raw.build_id.iter().all(|byte| *byte == 0) {
                return None;
            }

            // For backwards-compat (Linux minidumps have historically
            // been written using PDB70 CodeView info), treat build_id
            // as if the first 16 bytes were a GUID.
            let guid_size = <md::GUID>::size_with(&endian);
            let guid = if raw.build_id.len() < guid_size {
                // Pad with zeros.
                let v: Vec<u8> = raw
                    .build_id
                    .iter()
                    .cloned()
                    .chain(iter::repeat(0))
                    .take(guid_size)
                    .collect();
                v.pread_with::<md::GUID>(0, endian).ok()
            } else {
                raw.build_id.pread_with::<md::GUID>(0, endian).ok()
            };
            guid.map(|g| Uuid::from_fields(g.data1, g.data2, g.data3, &g.data4))
                .map(DebugId::from_uuid)
        }
        _ => None,
    }
}

/// Checks that the buffer is large enough for the given number of items.
///
/// Essentially ensures that `buf.len() >= offset + (number_of_entries * size_of_entry)`.
/// Returns `(number_of_entries, expected_size)` on success.
fn ensure_count_in_bound(
    buf: &[u8],
    number_of_entries: usize,
    size_of_entry: usize,
    offset: usize,
) -> Result<(usize, usize), Error> {
    let expected_size = number_of_entries
        .checked_mul(size_of_entry)
        .and_then(|v| v.checked_add(offset))
        .ok_or(Error::StreamReadFailure)?;
    if buf.len() < expected_size {
        return Err(Error::StreamSizeMismatch {
            expected: expected_size,
            actual: buf.len(),
        });
    }
    Ok((number_of_entries, expected_size))
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
            os: Os::Unknown(0),
            debug_id: None,
        }
    }

    /// Read additional data to construct a `MinidumpModule` from `bytes` using the information
    /// from the module list in `raw`.
    pub fn read(
        raw: md::MINIDUMP_MODULE,
        bytes: &[u8],
        endian: scroll::Endian,
        system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpModule, Error> {
        let mut offset = raw.module_name_rva as usize;
        let name =
            read_string_utf16(&mut offset, bytes, endian).ok_or(Error::CodeViewReadFailure)?;
        let codeview_info = if raw.cv_record.data_size == 0 {
            None
        } else {
            Some(read_codeview(&raw.cv_record, bytes, endian).ok_or(Error::CodeViewReadFailure)?)
        };

        let os = system_info.map(|info| info.os).unwrap_or(Os::Unknown(0));

        let debug_id = codeview_info
            .as_ref()
            .and_then(|cv| read_debug_id(cv, endian));

        Ok(MinidumpModule {
            raw,
            name,
            codeview_info,
            misc_info: None,
            os,
            debug_id,
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
            self.code_identifier().unwrap_or_default(),
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
            self.debug_identifier().unwrap_or_default(),
            self.version().unwrap_or(Cow::Borrowed("")),
        )?;
        Ok(())
    }

    fn memory_range(&self) -> Option<Range<u64>> {
        if self.size() == 0 {
            return None;
        }
        Some(Range::new(
            self.base_address(),
            self.base_address().checked_add(self.size())? - 1,
        ))
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

    fn code_identifier(&self) -> Option<CodeId> {
        match self.codeview_info {
            Some(CodeView::Pdb70(ref raw)) if self.os == Os::MacOs => {
                // MacOs uses PDB70 instead of its own dedicated format.
                // See the following issue for a potential MacOs-specific format:
                // https://github.com/rust-minidump/rust-minidump/issues/455
                Some(CodeId::new(format!("{:#}", raw.signature)))
            }
            Some(CodeView::Pdb20(_)) | Some(CodeView::Pdb70(_)) => Some(CodeId::new(format!(
                "{0:08X}{1:x}",
                self.raw.time_date_stamp, self.raw.size_of_image
            ))),
            Some(CodeView::Elf(ref raw)) => {
                // Return None instead of sentinel CodeIds for empty
                // `build_id`s. Non-executable mapped files like fonts or .jar
                // files will usually fall under this case.
                if raw.build_id.iter().all(|byte| *byte == 0) {
                    None
                } else {
                    Some(CodeId::from_binary(&raw.build_id))
                }
            }
            None if self.os == Os::Windows => {
                // Fall back to the timestamp + size-based debug-id for Windows.
                // Some Module records from Windows have no codeview record, but
                // the CodeId generated here is valid and can be looked up on
                // the Microsoft symbol server.
                // One example might be `wow64cpu.dll` with code-id `378BC3CDa000`.
                // This can however lead to "false positive" code-ids for modules
                // that have no timestamp, in which case the code-id looks extremely
                // low-entropy. The same can happen though if they *do* have a
                // codeview record.
                Some(CodeId::new(format!(
                    "{0:08X}{1:x}",
                    self.raw.time_date_stamp, self.raw.size_of_image
                )))
            }
            // Occasionally things will make it into the module stream that
            // shouldn't be there, and so no meaningful CodeId can be found from
            // those. One of those things are SysV shared memory segments which
            // have no CodeView record.
            _ => None,
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
    fn debug_identifier(&self) -> Option<DebugId> {
        self.debug_id
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

impl MinidumpUnloadedModule {
    /// Create a `MinidumpUnloadedModule` with some basic info.
    ///
    /// Useful for testing.
    pub fn new(base: u64, size: u32, name: &str) -> MinidumpUnloadedModule {
        MinidumpUnloadedModule {
            raw: md::MINIDUMP_UNLOADED_MODULE {
                base_of_image: base,
                size_of_image: size,
                ..md::MINIDUMP_UNLOADED_MODULE::default()
            },
            name: String::from(name),
        }
    }

    /// Read additional data to construct a `MinidumpUnloadedModule` from `bytes` using the information
    /// from the module list in `raw`.
    pub fn read(
        raw: md::MINIDUMP_UNLOADED_MODULE,
        bytes: &[u8],
        endian: scroll::Endian,
    ) -> Result<MinidumpUnloadedModule, Error> {
        let mut offset = raw.module_name_rva as usize;
        let name = read_string_utf16(&mut offset, bytes, endian).ok_or(Error::DataError)?;
        Ok(MinidumpUnloadedModule { raw, name })
    }

    /// Write a human-readable description of this `MinidumpModule` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_UNLOADED_MODULE
  base_of_image                   = {:#x}
  size_of_image                   = {:#x}
  checksum                        = {:#x}
  time_date_stamp                 = {:#x} {}
  module_name_rva                 = {:#x}
  (code_file)                     = \"{}\"
  (code_identifier)               = \"{}\"
",
            self.raw.base_of_image,
            self.raw.size_of_image,
            self.raw.checksum,
            self.raw.time_date_stamp,
            format_time_t(self.raw.time_date_stamp),
            self.raw.module_name_rva,
            self.code_file(),
            self.code_identifier().unwrap_or_default(),
        )?;

        Ok(())
    }

    fn memory_range(&self) -> Option<Range<u64>> {
        if self.size() == 0 {
            return None;
        }
        Some(Range::new(
            self.base_address(),
            self.base_address().checked_add(self.size())? - 1,
        ))
    }
}

impl Module for MinidumpUnloadedModule {
    fn base_address(&self) -> u64 {
        self.raw.base_of_image
    }
    fn size(&self) -> u64 {
        self.raw.size_of_image as u64
    }
    fn code_file(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
    fn code_identifier(&self) -> Option<CodeId> {
        // TODO: This should be returning None if the unloaded module is coming
        // from a non-Windows minidump. We'll need info about the operating
        // system, ideally sourced from the SystemInfo to be able to do this.
        Some(CodeId::new(format!(
            "{0:08X}{1:x}",
            self.raw.time_date_stamp, self.raw.size_of_image
        )))
    }
    fn debug_file(&self) -> Option<Cow<'_, str>> {
        None
    }
    fn debug_identifier(&self) -> Option<DebugId> {
        None
    }
    fn version(&self) -> Option<Cow<'_, str>> {
        None
    }
}

/// Parses X:Y or X=Y lists, skipping any blank/unparseable lines
fn linux_list_iter(
    bytes: &[u8],
    separator: u8,
) -> impl Iterator<Item = (&LinuxOsStr, &LinuxOsStr)> {
    fn strip_quotes(input: &LinuxOsStr) -> &LinuxOsStr {
        // Remove any extra surrounding whitespace since formats are inconsistent on this.
        let input = input.trim_ascii_whitespace();

        // Convert `"MyValue"` into `MyValue`, or just return the trimmed input.
        let output = input
            .strip_prefix(b"\"")
            .and_then(|input| input.strip_suffix(b"\""))
            .unwrap_or(input);

        LinuxOsStr::from_bytes(output)
    }

    let input = LinuxOsStr::from_bytes(bytes);
    input.lines().filter_map(move |line| {
        line.split_once(separator)
            .map(|(label, val)| (strip_quotes(label), (strip_quotes(val))))
    })
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

    let (count, counted_size) = ensure_count_in_bound(
        bytes,
        u as usize,
        <T>::size_with(&endian),
        mem::size_of::<u32>(),
    )?;

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
            });
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

fn read_ex_stream_list<'a, T>(
    offset: &mut usize,
    bytes: &'a [u8],
    endian: scroll::Endian,
) -> Result<Vec<T>, Error>
where
    T: TryFromCtx<'a, scroll::Endian, [u8], Error = scroll::Error>,
    T: SizeWith<scroll::Endian>,
{
    // Some newer list streams have an extended header:
    //
    // size_of_header: u32,
    // size_of_entry: u32,
    // number_of_entries: u32,
    // ...entries

    // In theory this allows the format of the stream to be extended without
    // us knowing how to handle the new parts.

    let size_of_header: u32 = bytes
        .gread_with(offset, endian)
        .or(Err(Error::StreamReadFailure))?;

    let size_of_entry: u32 = bytes
        .gread_with(offset, endian)
        .or(Err(Error::StreamReadFailure))?;

    let number_of_entries: u32 = bytes
        .gread_with(offset, endian)
        .or(Err(Error::StreamReadFailure))?;

    let expected_size_of_entry = <T>::size_with(&endian);

    if size_of_entry as usize != expected_size_of_entry {
        // For now, conservatively bail out if entries don't have
        // the expected size. In theory we can assume entries are
        // always extended with new trailing fields, and this information
        // would let us walk over trailing fields we don't know about?
        // But without an example let's be safe.
        return Err(Error::StreamReadFailure);
    }

    let (number_of_entries, _) = ensure_count_in_bound(
        bytes,
        number_of_entries as usize,
        size_of_entry as usize,
        size_of_header as usize,
    )?;

    let header_padding = match (size_of_header as usize).checked_sub(*offset) {
        Some(s) => s,
        None => return Err(Error::StreamReadFailure),
    };
    *offset += header_padding;

    // read count T raw stream entries
    let mut raw_entries = Vec::with_capacity(number_of_entries as usize);
    for _ in 0..number_of_entries {
        let raw: T = bytes
            .gread_with(offset, endian)
            .or(Err(Error::StreamReadFailure))?;
        raw_entries.push(raw);
    }
    Ok(raw_entries)
}

impl<'a> MinidumpStream<'a> for MinidumpThreadNames {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::ThreadNamesStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<Self, Error> {
        let mut offset = 0;
        let raw_names: Vec<md::MINIDUMP_THREAD_NAME> =
            read_stream_list(&mut offset, bytes, endian)?;
        // read out the actual names
        let mut names = HashMap::with_capacity(raw_names.len());
        for raw_name in raw_names {
            let mut offset = raw_name.thread_name_rva as usize;
            // Better to just drop unreadable names individually than the whole stream.
            if let Some(name) = read_string_utf16(&mut offset, all, endian) {
                names.insert(raw_name.thread_id, name);
            } else {
                warn!(
                    "Couldn't read thread name for thread id {}",
                    raw_name.thread_id
                );
            }
        }
        Ok(MinidumpThreadNames { names })
    }
}

impl MinidumpThreadNames {
    pub fn get_name(&self, thread_id: u32) -> Option<Cow<str>> {
        self.names
            .get(&thread_id)
            .map(|name| Cow::Borrowed(&**name))
    }

    /// Write a human-readable description of this `MinidumpThreadNames` to `f`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MinidumpThreadNames
  thread_count = {}

",
            self.names.len()
        )?;
        for (i, (thread_id, name)) in self.names.iter().enumerate() {
            writeln!(
                f,
                "thread_name[{}]
MINIDUMP_THREAD_NAME
  thread_id = {:#x}
  name      = \"{}\"
",
                i, thread_id, name
            )?;
        }

        Ok(())
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
    pub fn iter(&self) -> impl Iterator<Item = &MinidumpModule> {
        self.modules.iter()
    }

    /// Iterate over the modules in order by memory address.
    pub fn by_addr(&self) -> impl DoubleEndedIterator<Item = &MinidumpModule> {
        self.modules_by_addr
            .ranges_values()
            .map(move |&(_, index)| &self.modules[index])
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
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::ModuleListStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpModuleList, Error> {
        let mut offset = 0;
        let raw_modules: Vec<md::MINIDUMP_MODULE> = read_stream_list(&mut offset, bytes, endian)?;
        // read auxiliary data for each module
        let mut modules = Vec::with_capacity(raw_modules.len());
        for raw in raw_modules.into_iter() {
            if raw.size_of_image == 0 || raw.size_of_image as u64 > (u64::MAX - raw.base_of_image) {
                // Bad image size.
                // TODO: just drop this module, keep the rest?
                return Err(Error::ModuleReadFailure);
            }
            modules.push(MinidumpModule::read(raw, all, endian, system_info)?);
        }
        Ok(MinidumpModuleList::from_modules(modules))
    }
}

impl MinidumpUnloadedModuleList {
    /// Return an empty `MinidumpModuleList`.
    pub fn new() -> MinidumpUnloadedModuleList {
        MinidumpUnloadedModuleList {
            modules: vec![],
            modules_by_addr: vec![],
        }
    }
    /// Create a `MinidumpModuleList` from a list of `MinidumpModule`s.
    pub fn from_modules(modules: Vec<MinidumpUnloadedModule>) -> MinidumpUnloadedModuleList {
        let mut modules_by_addr = (0..modules.len())
            .filter_map(|i| modules[i].memory_range().map(|r| (r, i)))
            .collect::<Vec<_>>();

        modules_by_addr.sort_by_key(|(range, _idx)| *range);

        MinidumpUnloadedModuleList {
            modules,
            modules_by_addr,
        }
    }

    /// Return an iterator of `MinidumpUnloadedModules` whose address range covers `address`.
    pub fn modules_at_address(
        &self,
        address: u64,
    ) -> impl Iterator<Item = &MinidumpUnloadedModule> {
        // We have all of our modules sorted by memory range (base address being the
        // high-order value), and we need to get the range of values that overlap
        // with our target address. I'm a bit too tired to work out the exact
        // combination of binary searches to do this, so let's just use `filter`
        // for now (unloaded_modules should be a bounded list anyway).
        self.modules_by_addr
            .iter()
            .filter(move |(range, _idx)| range.contains(address))
            .map(move |(_range, idx)| &self.modules[*idx])
    }

    /// Iterate over the modules in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &MinidumpUnloadedModule> {
        self.modules.iter()
    }

    /// Iterate over the modules in order by memory address.
    pub fn by_addr(&self) -> impl Iterator<Item = &MinidumpUnloadedModule> {
        self.modules_by_addr
            .iter()
            .map(move |&(_, index)| &self.modules[index])
    }

    /// Write a human-readable description of this `MinidumpModuleList` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MinidumpUnloadedModuleList
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

impl Default for MinidumpUnloadedModuleList {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> MinidumpStream<'a> for MinidumpUnloadedModuleList {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::UnloadedModuleListStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpUnloadedModuleList, Error> {
        let mut offset = 0;
        let raw_modules: Vec<md::MINIDUMP_UNLOADED_MODULE> =
            read_ex_stream_list(&mut offset, bytes, endian)?;
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
            modules.push(MinidumpUnloadedModule::read(raw, all, endian)?);
        }
        Ok(MinidumpUnloadedModuleList::from_modules(modules))
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
}

impl<'a> MinidumpMemory64<'a> {
    /// Write a human-readable description of this `MinidumpMemory64` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_MEMORY_DESCRIPTOR64
  start_of_memory_range = {:#x}
  memory.data_size      = {:#x}
Memory
",
            self.desc.start_of_memory_range, self.desc.data_size,
        )?;
        self.print_contents(f)?;
        writeln!(f)
    }
}

impl<'a, Descriptor> MinidumpMemoryBase<'a, Descriptor> {
    /// Get `mem::size_of::<T>()` bytes of memory at `addr` from this region.
    ///
    /// Return `None` if the requested address range falls out of the bounds
    /// of this memory region.
    pub fn get_memory_at_address<T>(&self, addr: u64) -> Option<T>
    where
        T: TryFromCtx<'a, scroll::Endian, [u8], Error = scroll::Error>,
        T: SizeWith<scroll::Endian>,
    {
        // XXX: Instead of checking the base+size validity on each access, maybe
        // move this check to a different place?
        let _end = self.base_address.checked_add(self.size)?;
        let start = addr.checked_sub(self.base_address)? as usize;

        self.bytes.pread_with::<T>(start, LE).ok()
    }

    /// Write the contents of this `MinidumpMemory` to `f` as a hex string.
    pub fn print_contents<T: Write>(&self, f: &mut T) -> io::Result<()> {
        const PARAGRAPH_SIZE: usize = 16;
        let mut offset = 0;
        for paragraph in self.bytes.chunks(PARAGRAPH_SIZE) {
            write!(f, "    {:08x}: ", offset)?;
            let mut byte_iter = paragraph.iter().fuse();
            for _ in 0..PARAGRAPH_SIZE {
                if let Some(byte) = byte_iter.next() {
                    write!(f, "{:02x} ", byte)?;
                } else {
                    write!(f, "   ")?;
                }
            }
            for &byte in paragraph.iter() {
                let ascii_char = if !byte.is_ascii() || byte.is_ascii_control() {
                    '.'
                } else {
                    char::from(byte)
                };

                write!(f, "{}", ascii_char)?;
            }
            writeln!(f)?;

            offset += PARAGRAPH_SIZE;
        }
        Ok(())
    }

    pub fn memory_range(&self) -> Option<Range<u64>> {
        if self.size == 0 {
            return None;
        }
        Some(Range::new(
            self.base_address,
            self.base_address.checked_add(self.size)? - 1,
        ))
    }
}

impl<'mdmp, Descriptor> MinidumpMemoryListBase<'mdmp, Descriptor> {
    /// Return an empty `MinidumpMemoryListBase`.
    pub fn new() -> MinidumpMemoryListBase<'mdmp, Descriptor> {
        MinidumpMemoryListBase {
            regions: vec![],
            regions_by_addr: RangeMap::new(),
        }
    }

    /// Create a `MinidumpMemoryListBase` from a list of `MinidumpMemoryBase`s.
    pub fn from_regions(
        regions: Vec<MinidumpMemoryBase<'mdmp, Descriptor>>,
    ) -> MinidumpMemoryListBase<'mdmp, Descriptor> {
        let regions_by_addr = regions
            .iter()
            .enumerate()
            .map(|(i, region)| (region.memory_range(), i))
            .into_rangemap_safe();
        MinidumpMemoryListBase {
            regions,
            regions_by_addr,
        }
    }

    /// Return a `MinidumpMemoryBase` containing memory at `address`, if one exists.
    pub fn memory_at_address(
        &self,
        address: u64,
    ) -> Option<&MinidumpMemoryBase<'mdmp, Descriptor>> {
        self.regions_by_addr
            .get(address)
            .map(|&index| &self.regions[index])
    }

    /// Iterate over the memory regions in the order contained in the minidump.
    ///
    /// The iterator returns items of [MinidumpMemoryBase] as `&'slf MinidumpMemoryBase<'mdmp, Descriptor>`.
    /// That is the lifetime of the item is bound to the lifetime of the iterator itself
    /// (`'slf`), while the slice inside [MinidumpMemoryBase] pointing at the memory itself has
    /// the lifetime of the [Minidump] struct ('mdmp).
    pub fn iter<'slf>(
        &'slf self,
    ) -> impl Iterator<Item = &'slf MinidumpMemoryBase<'mdmp, Descriptor>> {
        self.regions.iter()
    }

    /// Iterate over the memory regions in order by memory address.
    pub fn by_addr<'slf>(
        &'slf self,
    ) -> impl Iterator<Item = &'slf MinidumpMemoryBase<'mdmp, Descriptor>> {
        self.regions_by_addr
            .ranges_values()
            .map(move |&(_, index)| &self.regions[index])
    }
}

impl<'mdmp> MinidumpMemoryList<'mdmp> {
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

impl<'mdmp> MinidumpMemory64List<'mdmp> {
    /// Write a human-readable description of this `MinidumpMemory64List` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MinidumpMemory64List
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

impl<'a, Descriptor> Default for MinidumpMemoryListBase<'a, Descriptor> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> MinidumpStream<'a> for MinidumpMemoryList<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::MemoryListStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
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

impl<'a> MinidumpStream<'a> for MinidumpMemory64List<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::Memory64ListStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpMemory64List<'a>, Error> {
        let mut offset = 0;
        let u: u64 = bytes
            .gread_with(&mut offset, endian)
            .or(Err(Error::StreamReadFailure))?;

        let mut rva: u64 = bytes
            .gread_with(&mut offset, endian)
            .or(Err(Error::StreamReadFailure))?;

        let (count, counted_size) = ensure_count_in_bound(
            bytes,
            u.try_into().map_err(|_| Error::StreamReadFailure)?,
            md::MINIDUMP_MEMORY_DESCRIPTOR64::size_with(&endian),
            offset,
        )?;

        if bytes.len() != counted_size {
            return Err(Error::StreamSizeMismatch {
                expected: counted_size,
                actual: bytes.len(),
            });
        }

        let mut raw_entries = Vec::with_capacity(count);
        for _ in 0..count {
            let raw: md::MINIDUMP_MEMORY_DESCRIPTOR64 = bytes
                .gread_with(&mut offset, endian)
                .or(Err(Error::StreamReadFailure))?;
            raw_entries.push(raw);
        }

        let mut regions = Vec::with_capacity(raw_entries.len());
        for raw in raw_entries {
            let start = rva;
            let end = rva
                .checked_add(raw.data_size)
                .ok_or(Error::StreamReadFailure)?;
            let bytes = all
                .get(start as usize..end as usize)
                .ok_or(Error::StreamReadFailure)?;

            regions.push(MinidumpMemory64 {
                desc: raw,
                base_address: raw.start_of_memory_range,
                size: raw.data_size,
                bytes,
            });

            rva = end;
        }
        Ok(MinidumpMemory64List::from_regions(regions))
    }
}

impl<'a> MinidumpStream<'a> for MinidumpMemoryInfoList<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::MemoryInfoListStream as u32;

    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpMemoryInfoList<'a>, Error> {
        let mut offset = 0;
        let raw_regions: Vec<md::MINIDUMP_MEMORY_INFO> =
            read_ex_stream_list(&mut offset, bytes, endian)?;
        let regions = raw_regions
            .into_iter()
            .map(|raw| MinidumpMemoryInfo {
                allocation_protection: md::MemoryProtection::from_bits_truncate(
                    raw.allocation_protection,
                ),
                state: md::MemoryState::from_bits_truncate(raw.state),
                protection: md::MemoryProtection::from_bits_truncate(raw.protection),
                ty: md::MemoryType::from_bits_truncate(raw._type),
                raw,
                _phantom: PhantomData,
            })
            .collect();
        Ok(MinidumpMemoryInfoList::from_regions(regions))
    }
}

impl<'a> Default for MinidumpMemoryInfoList<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'mdmp> MinidumpMemoryInfoList<'mdmp> {
    /// Return an empty `MinidumpMemoryList`.
    pub fn new() -> MinidumpMemoryInfoList<'mdmp> {
        MinidumpMemoryInfoList {
            regions: vec![],
            regions_by_addr: RangeMap::new(),
        }
    }

    /// Create a `MinidumpMemoryList` from a list of `MinidumpMemory`s.
    pub fn from_regions(regions: Vec<MinidumpMemoryInfo<'mdmp>>) -> MinidumpMemoryInfoList<'mdmp> {
        let regions_by_addr = regions
            .iter()
            .enumerate()
            .map(|(i, region)| (region.memory_range(), i))
            .into_rangemap_safe();
        MinidumpMemoryInfoList {
            regions,
            regions_by_addr,
        }
    }

    /// Return a `MinidumpMemory` containing memory at `address`, if one exists.
    pub fn memory_info_at_address(&self, address: u64) -> Option<&MinidumpMemoryInfo<'mdmp>> {
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
    pub fn iter<'slf>(&'slf self) -> impl Iterator<Item = &'slf MinidumpMemoryInfo<'mdmp>> {
        self.regions.iter()
    }

    /// Iterate over the memory regions in order by memory address.
    pub fn by_addr<'slf>(&'slf self) -> impl Iterator<Item = &'slf MinidumpMemoryInfo<'mdmp>> {
        self.regions_by_addr
            .ranges_values()
            .map(move |&(_, index)| &self.regions[index])
    }

    /// Write a human-readable description.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MinidumpMemoryInfoList
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

impl<'a> MinidumpMemoryInfo<'a> {
    /// Write a human-readable description.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_MEMORY_INFO
  base_address          = {:#x}
  allocation_base       = {:#x}
  allocation_protection = {:#x}
  region_size           = {:#x}
  state                 = {:#x}
  protection            = {:#x}
  _type                 = {:#x}
",
            self.raw.base_address,
            self.raw.allocation_base,
            self.allocation_protection,
            self.raw.region_size,
            self.state,
            self.protection,
            self.ty,
        )?;
        writeln!(f)
    }

    pub fn memory_range(&self) -> Option<Range<u64>> {
        if self.raw.region_size == 0 {
            return None;
        }
        Some(Range::new(
            self.raw.base_address,
            self.raw.base_address.checked_add(self.raw.region_size)? - 1,
        ))
    }

    /// Whether this memory range was executable.
    pub fn is_executable(&self) -> bool {
        self.protection.intersects(
            md::MemoryProtection::PAGE_EXECUTE
                | md::MemoryProtection::PAGE_EXECUTE_READ
                | md::MemoryProtection::PAGE_EXECUTE_READWRITE
                | md::MemoryProtection::PAGE_EXECUTE_WRITECOPY,
        )
    }
}

impl<'a> MinidumpStream<'a> for MinidumpLinuxMaps<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::LinuxMaps as u32;

    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        _endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpLinuxMaps<'a>, Error> {
        let regions = LinuxOsStr::from_bytes(bytes)
            .lines()
            .map(MinidumpLinuxMapInfo::from_line)
            .filter_map(|x| x.ok())
            .collect::<Vec<_>>();

        Ok(MinidumpLinuxMaps::from_regions(regions))
    }
}

impl<'a> Default for MinidumpLinuxMaps<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'mdmp> MinidumpLinuxMaps<'mdmp> {
    /// Return an empty `MinidumpMemoryList`.
    pub fn new() -> Self {
        Self {
            regions: vec![],
            regions_by_addr: RangeMap::new(),
        }
    }

    /// Create a `MinidumpMemoryList` from a list of `MinidumpMemory`s.
    pub fn from_regions(regions: Vec<MinidumpLinuxMapInfo<'mdmp>>) -> Self {
        let regions_by_addr = regions
            .iter()
            .enumerate()
            .map(|(i, region)| (region.memory_range(), i))
            .into_rangemap_safe();
        Self {
            regions,
            regions_by_addr,
        }
    }

    /// Return a `MinidumpMemory` containing memory at `address`, if one exists.
    pub fn memory_info_at_address(&self, address: u64) -> Option<&MinidumpLinuxMapInfo<'mdmp>> {
        self.regions_by_addr
            .get(address)
            .map(|&index| &self.regions[index])
    }

    /// Iterate over the memory regions in the order contained in the minidump.
    pub fn iter<'slf>(&'slf self) -> impl Iterator<Item = &'slf MinidumpLinuxMapInfo<'mdmp>> {
        self.regions.iter()
    }

    /// Iterate over the memory regions in order by memory address.
    pub fn by_addr<'slf>(&'slf self) -> impl Iterator<Item = &'slf MinidumpLinuxMapInfo<'mdmp>> {
        self.regions_by_addr
            .ranges_values()
            .map(move |&(_, index)| &self.regions[index])
    }

    /// Write a human-readable description.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MinidumpLinuxMapInfo
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

impl<'a> MinidumpLinuxMapInfo<'a> {
    /// Parses a line from /proc/self/maps into a `[MinidumpLinuxMapInfo]`.
    pub fn from_line(line: &'a LinuxOsStr) -> Result<MinidumpLinuxMapInfo<'a>, Error> {
        // /proc/self/maps is a listing of all the mapped ranges of memory
        // in the (crashing) process. We can use it to find out what regions
        // were executable (and what file they mapped to), where stacks/heap
        // are mapped, and various other things.
        //
        // Format of each line (by examples):
        //
        // ```text
        //
        //        address        perms   offset   dev   inode       path/kind         deleted?
        // 7fca3a80c0-7fca3a81a0  r-xp  10bac9000 fd:05 1196511 /usr/lib64/libtdb.so  (deleted)
        // 7ffe2e7910-7ffe2e7b10  rw-p  000000000 00:00 0       [stack]
        //
        // ```
        //
        // * address: the start and end addresses (inclusive)
        // * perms: permissions the process had on the memory
        //   * r = read
        //   * w = write
        //   * x = execute
        //   * s = shared
        //   * p = private (copy on write)
        //   * - = <ignore> (just for formatting)
        // * offset: the offset this mapping has into the mapped file/device. (ignored)
        // * dev: the "device" (major:minor). (ignored)
        // * inode: the inode on the device, 0 means no inode (uninitialized memory?). (ignored)
        // * path/kind: either a path to the mapped file/device or a special `[kind]`:
        //   * `[stack]`       - the main thread's stack
        //   * `[stack:<tid>]` - the stack of the thread with this tid (e.g. `[stack:123]`)
        //   * `[heap]`        - the process's heap
        //   * `[vdso]`        - the Virtual Dynamically-linked Shared Object
        //   * `<blank>`       - an anonymous mmap
        //
        // A path has a few extra caveats:
        //  * If suffixed with `(deleted)` that indicates the mapped file was deleted.
        //  * If the path contains a newline (yikes), it will appear as \012. It is impossible
        //    to distinguish this from the path literally containing the string `\012`.
        //    (We aren't resolving these paths so don't worry about it.)

        let mut tokens = line.split_ascii_whitespace();

        let (base_address, final_address) = tokens
            .next()
            .and_then(|range| range.split_once(b'-'))
            .and_then(|(start, end)| {
                // Parsing numbers, so can require them to be utf8
                let start = start
                    .to_str()
                    .ok()
                    .and_then(|x| u64::from_str_radix(x, 16).ok());

                let end = end
                    .to_str()
                    .ok()
                    .and_then(|x| u64::from_str_radix(x, 16).ok());

                start.zip(end)
            })
            .ok_or(Error::DataError)?;

        let empty = LinuxOsStr::new();
        let perms = tokens.next().unwrap_or(empty);

        let mut is_read = false;
        let mut is_write = false;
        let mut is_exec = false;
        let mut is_shared = false;
        let mut is_private = false;

        // Although some of these are mutually exclusive and they come in a specific
        // order, I see no reason to mandate this in this parser.
        for c in perms.iter() {
            match &c {
                b'r' => is_read = true,
                b'w' => is_write = true,
                b'x' => is_exec = true,
                b's' => is_shared = true,
                b'p' => is_private = true,
                b'-' => {}
                _ => {
                    // This shouldn't happen. That said, there's no obvious reason
                    // to fail the entire parse if there's new info we don't know about,
                    // so I suppose it's fine?
                }
            }
        }

        // We don't care about these values
        let _offset = tokens.next();
        let _dev = tokens.next();
        let _inode = tokens.next();

        let kind = tokens.next();
        let kind = match kind.map(|x| x.as_bytes()) {
            Some(b"[stack]") => MinidumpLinuxMapKind::MainThreadStack,
            Some(b"[heap]") => MinidumpLinuxMapKind::Heap,
            Some(b"[vdso]") => MinidumpLinuxMapKind::Vdso,
            Some(b"") | None => MinidumpLinuxMapKind::AnonymousMap,
            Some(_) => {
                // Go back to the LinuxOsStr
                let kind = kind.unwrap();
                // Try to parse an arbitrary [<special>]
                if let Some(special) = kind
                    .to_str()
                    .ok()
                    .and_then(|x| x.strip_prefix('['))
                    .and_then(|x| x.strip_suffix(']'))
                {
                    // See if it's a [stack:<tid>] special entry
                    if let Some(tid) = special.strip_prefix("stack:") {
                        // As far as I know, this part *is* base 10!
                        let tid = str::parse(tid).map_err(|_| Error::DataError)?;
                        MinidumpLinuxMapKind::Stack(tid)
                    } else {
                        MinidumpLinuxMapKind::UnknownSpecial(Cow::Borrowed(kind))
                    }
                } else {
                    // Finally just assume it's a path. Use the fact that we're handling
                    // a subslice to retrieve the index of the full string (so we don't lose any whitespace).

                    let base = line.as_ptr() as usize;
                    let pos = kind.as_ptr() as usize;
                    let idx = pos - base;

                    let path = LinuxOsStr::from_bytes(&line[idx..]).trim_ascii_whitespace();

                    // Check if this path has the `(deleted)` suffix
                    path.rsplit_once(b' ')
                        .and_then(|(path, deleted)| {
                            if deleted.as_bytes() == b"(deleted)" {
                                // (extra trim in case there was extra space between them)
                                Some(MinidumpLinuxMapKind::DeletedFile(Cow::Borrowed(
                                    path.trim_ascii_whitespace(),
                                )))
                            } else {
                                None
                            }
                        })
                        .unwrap_or(MinidumpLinuxMapKind::File(Cow::Borrowed(path)))
                }
            }
        };

        Ok(MinidumpLinuxMapInfo {
            base_address,
            final_address,
            kind,
            is_read,
            is_write,
            is_exec,
            is_private,
            is_shared,
            _phantom: PhantomData,
        })
    }
    /// Write a human-readable description of this.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        write!(
            f,
            "MINIDUMP_LINUX_MAP_INFO
  base_address          = {:#x}
  final_address         = {:#x}
  kind                  = {:#?}
  permissions           =\x20
",
            self.base_address, self.final_address, self.kind,
        )?;

        if self.is_read {
            write!(f, "r")?;
        } else {
            write!(f, "-")?;
        }
        if self.is_write {
            write!(f, "w")?;
        } else {
            write!(f, "-")?;
        }
        if self.is_exec {
            write!(f, "r")?;
        } else {
            write!(f, "-")?;
        }
        if self.is_private {
            write!(f, "p")?;
        } else if self.is_shared {
            write!(f, "s")?;
        } else {
            write!(f, "-")?;
        }
        writeln!(f)
    }

    pub fn memory_range(&self) -> Option<Range<u64>> {
        // final address is inclusive afaik
        if self.base_address > self.final_address {
            return None;
        }
        Some(Range::new(self.base_address, self.final_address))
    }

    /// Whether this memory range was executable.
    pub fn is_executable(&self) -> bool {
        self.is_exec
    }
}

impl<'a> Default for UnifiedMemoryInfoList<'a> {
    fn default() -> Self {
        Self::Info(MinidumpMemoryInfoList::default())
    }
}

impl<'a> UnifiedMemoryInfoList<'a> {
    /// Take two potential memory info sources and create an interface that unifies them.
    ///
    /// Under normal circumstances a minidump should only contain one of these.
    /// If both are provided, one will be arbitrarily preferred to attempt to
    /// make progress.
    pub fn new(
        info: Option<MinidumpMemoryInfoList<'a>>,
        maps: Option<MinidumpLinuxMaps<'a>>,
    ) -> Option<Self> {
        match (info, maps) {
            (Some(info), Some(_maps)) => {
                warn!("UnifiedMemoryInfoList got both kinds of info! (using InfoList)");
                // Just pick one I guess?
                Some(Self::Info(info))
            }
            (Some(info), None) => Some(Self::Info(info)),
            (None, Some(maps)) => Some(Self::Maps(maps)),
            (None, None) => None,
        }
    }

    /// Return a `MinidumpMemory` containing memory at `address`, if one exists.
    pub fn memory_info_at_address(&self, address: u64) -> Option<UnifiedMemoryInfo> {
        match self {
            Self::Info(info) => info
                .memory_info_at_address(address)
                .map(UnifiedMemoryInfo::Info),
            Self::Maps(maps) => maps
                .memory_info_at_address(address)
                .map(UnifiedMemoryInfo::Map),
        }
    }

    /// Iterate over the memory regions in the order contained in the minidump.
    pub fn iter(&self) -> impl Iterator<Item = UnifiedMemoryInfo> {
        // Use `flat_map` and `chain` to create a unified stream of the two types
        // (only one of which will conatin any values). Note that we are using
        // the fact that `Option` can be iterated (producing 1 to 0 values).
        let info = self
            .info()
            .into_iter()
            .flat_map(|info| info.iter().map(UnifiedMemoryInfo::Info));
        let maps = self
            .maps()
            .into_iter()
            .flat_map(|maps| maps.iter().map(UnifiedMemoryInfo::Map));

        info.chain(maps)
    }

    /// Iterate over the memory regions in order by memory address.
    pub fn by_addr(&self) -> impl Iterator<Item = UnifiedMemoryInfo> {
        let info = self
            .info()
            .into_iter()
            .flat_map(|info| info.by_addr().map(UnifiedMemoryInfo::Info));
        let maps = self
            .maps()
            .into_iter()
            .flat_map(|maps| maps.by_addr().map(UnifiedMemoryInfo::Map));

        info.chain(maps)
    }

    /// Write a human-readable description of this `MinidumpMemoryList` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        match self {
            Self::Info(info) => info.print(f),
            Self::Maps(maps) => maps.print(f),
        }
    }

    /// Get the [`MinidumpLinuxMaps`] contained inside, if it exists.
    ///
    /// Potentially useful for doing a more refined analysis in specific places.
    pub fn maps(&self) -> Option<&MinidumpLinuxMaps<'a>> {
        match &self {
            Self::Maps(maps) => Some(maps),
            Self::Info(_) => None,
        }
    }

    /// Get the [`MinidumpMemoryInfoList`] contained inside, if it exists.
    ///
    /// Potentially useful for doing a more refined analysis in specific places.
    pub fn info(&self) -> Option<&MinidumpMemoryInfoList<'a>> {
        match &self {
            Self::Maps(_) => None,
            Self::Info(info) => Some(info),
        }
    }
}

impl<'a> UnifiedMemoryInfo<'a> {
    /// Write a human-readable description.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        match self {
            Self::Info(info) => info.print(f),
            Self::Map(map) => map.print(f),
        }
    }

    /// The range of memory this info applies to.
    pub fn memory_range(&self) -> Option<Range<u64>> {
        match self {
            Self::Info(info) => info.memory_range(),
            Self::Map(map) => map.memory_range(),
        }
    }

    /// Whether this memory range was executable.
    pub fn is_executable(&self) -> bool {
        match self {
            Self::Info(info) => info.is_executable(),
            Self::Map(map) => map.is_executable(),
        }
    }
}

impl<'a> MinidumpThread<'a> {
    pub fn context(
        &self,
        system_info: &MinidumpSystemInfo,
        misc: Option<&MinidumpMiscInfo>,
    ) -> Option<Cow<MinidumpContext>> {
        MinidumpContext::read(self.context?, self.endian, system_info, misc)
            .ok()
            .map(Cow::Owned)
    }

    pub fn stack_memory(
        &self,
        memory_list: &MinidumpMemoryList<'a>,
    ) -> Option<Cow<MinidumpMemory<'a>>> {
        self.stack.as_ref().map(Cow::Borrowed).or_else(|| {
            // Sometimes the raw.stack RVA is null/busted, but the start_of_memory_range
            // value is correct. So if the `read` fails, try resolving start_of_memory_range
            // with the MinidumpMemoryList. (This seems to specifically be a problem with
            // Windows minidumps.)
            let stack_addr = self.raw.stack.start_of_memory_range;
            let memory = memory_list.memory_at_address(stack_addr)?;
            Some(Cow::Owned(memory.clone()))
        })
    }

    /// Write a human-readable description of this `MinidumpThread` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(
        &self,
        f: &mut T,
        memory: Option<&MinidumpMemoryList<'a>>,
        system: Option<&MinidumpSystemInfo>,
        misc: Option<&MinidumpMiscInfo>,
    ) -> io::Result<()> {
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
        if let Some(system_info) = system {
            if let Some(ctx) = self.context(system_info, misc) {
                ctx.print(f)?;
            } else {
                write!(f, "  (no context)\n\n")?;
            }
        } else {
            write!(f, "  (no context)\n\n")?;
        }

        let pointer_width = system.map_or(PointerWidth::Unknown, |info| info.cpu.pointer_width());

        // We might not need any memory, so try to limp forward with an empty
        // MemoryList if we don't have one.
        let dummy_memory = MinidumpMemoryList::default();
        let memory = memory.unwrap_or(&dummy_memory);
        if let Some(ref stack) = self.stack_memory(memory) {
            writeln!(f, "Stack")?;

            // For printing purposes, we'll treat any unknown CPU type as 64-bit
            let chunk_size: usize = pointer_width.size_in_bytes().unwrap_or(8).into();
            let mut offset = 0;
            for chunk in stack.bytes.chunks_exact(chunk_size) {
                write!(f, "    0x{:08x}: 0x", offset)?;

                match pointer_width {
                    PointerWidth::Bits32 => {
                        let value = match self.endian {
                            scroll::Endian::Little => u32::from_le_bytes(chunk.try_into().unwrap()),
                            scroll::Endian::Big => u32::from_be_bytes(chunk.try_into().unwrap()),
                        };
                        write!(f, "{:08x}", value)?;
                    }
                    PointerWidth::Unknown | PointerWidth::Bits64 => {
                        let value = match self.endian {
                            scroll::Endian::Little => u64::from_le_bytes(chunk.try_into().unwrap()),
                            scroll::Endian::Big => u64::from_be_bytes(chunk.try_into().unwrap()),
                        };
                        write!(f, "{:016x}", value)?;
                    }
                }

                writeln!(f)?;

                offset += chunk_size;
            }
        } else {
            writeln!(f, "No stack")?;
        }
        writeln!(f)?;
        Ok(())
    }

    /// Gets the last error code the thread recorded, just like win32's GetLastError.
    ///
    /// The value is heuristically converted into a CrashReason because that's our
    /// general error code handling machinery, even though this may not actually be
    /// the reason for the crash!
    pub fn last_error(&self, cpu: Cpu, memory: &MinidumpMemoryList) -> Option<CrashReason> {
        // Early hacky implementation: rather than implementing all the TEB layouts,
        // just use the fact that we know the value we want is a 13-pointers offset
        // from the start of the TEB.
        let teb = self.raw.teb;
        let pointer_width = cpu.pointer_width().size_in_bytes()? as u64;
        let offset = pointer_width.checked_mul(13)?;
        let addr = teb.checked_add(offset)?;
        let val: u32 = memory
            .memory_at_address(addr)?
            .get_memory_at_address(addr)?;

        Some(CrashReason::from_windows_error(val))
    }
}

impl<'a> MinidumpStream<'a> for MinidumpThreadList<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::ThreadListStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpThreadList<'a>, Error> {
        let mut offset = 0;
        let raw_threads: Vec<md::MINIDUMP_THREAD> = read_stream_list(&mut offset, bytes, endian)?;
        let mut threads = Vec::with_capacity(raw_threads.len());
        let mut thread_ids = HashMap::with_capacity(raw_threads.len());
        for raw in raw_threads.into_iter() {
            thread_ids.insert(raw.thread_id, threads.len());

            // Defer parsing of this to the `context` method, where we will have access
            // to other streams that are required to parse a context properly.
            let context = location_slice(all, &raw.thread_context).ok();

            // Try to get the stack memory here, but the `stack_memory` method will
            // attempt a fallback method with access to other streams.
            let stack = MinidumpMemory::read(&raw.stack, all).ok();
            threads.push(MinidumpThread {
                raw,
                context,
                stack,
                endian,
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
    pub fn print<T: Write>(
        &self,
        f: &mut T,
        memory: Option<&MinidumpMemoryList<'a>>,
        system: Option<&MinidumpSystemInfo>,
        misc: Option<&MinidumpMiscInfo>,
    ) -> io::Result<()> {
        write!(
            f,
            r#"MinidumpThreadList
  thread_count = {}

"#,
            self.threads.len()
        )?;

        for (i, thread) in self.threads.iter().enumerate() {
            writeln!(f, "thread[{}]", i)?;
            thread.print(f, memory, system, misc)?;
        }
        Ok(())
    }
}

impl<'a> MinidumpStream<'a> for MinidumpSystemInfo {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::SystemInfoStream as u32;

    fn read(
        bytes: &[u8],
        all: &[u8],
        endian: scroll::Endian,
        system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpSystemInfo, Error> {
        if let Some(system_info) = system_info {
            return Ok(system_info.clone());
        }

        use std::fmt::Write;

        let raw: md::MINIDUMP_SYSTEM_INFO = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;
        let os = Os::from_platform_id(raw.platform_id);
        let cpu = Cpu::from_processor_architecture(raw.processor_architecture);

        let mut csd_offset = raw.csd_version_rva as usize;
        let csd_version = read_string_utf16(&mut csd_offset, all, endian);

        // self.raw.cpu.data is actually a union which we resolve here.
        let cpu_info = match cpu {
            Cpu::X86 | Cpu::X86_64 => {
                let mut cpu_info = String::new();

                if let Cpu::X86 = cpu {
                    // The vendor's ID is an ascii string but we need to flatten out the u32's into u8's
                    let x86_info: md::X86CpuInfo = raw
                        .cpu
                        .data
                        .pread_with(0, endian)
                        .or(Err(Error::StreamReadFailure))?;

                    cpu_info.extend(
                        x86_info
                            .vendor_id
                            .iter()
                            .flat_map(|i| IntoIterator::into_iter(i.to_le_bytes()))
                            .map(char::from),
                    );
                    cpu_info.push(' ');
                }

                write!(
                    &mut cpu_info,
                    "family {} model {} stepping {}",
                    raw.processor_level,
                    (raw.processor_revision >> 8) & 0xff,
                    raw.processor_revision & 0xff
                )
                .unwrap();

                Some(cpu_info)
            }
            Cpu::Arm => {
                let arm_info: md::ARMCpuInfo = raw
                    .cpu
                    .data
                    .pread_with(0, endian)
                    .or(Err(Error::StreamReadFailure))?;

                // There is no good list of implementer id values, but the following
                // pages provide some help:
                //   http://comments.gmane.org/gmane.linux.linaro.devel/6903
                //   http://forum.xda-developers.com/archive/index.php/t-480226.html
                let vendors = [
                    (0x41, "ARM"),
                    (0x51, "Qualcomm"),
                    (0x56, "Marvell"),
                    (0x69, "Intel/Marvell"),
                ];
                let parts = [
                    (0x4100c050, "Cortex-A5"),
                    (0x4100c080, "Cortex-A8"),
                    (0x4100c090, "Cortex-A9"),
                    (0x4100c0f0, "Cortex-A15"),
                    (0x4100c140, "Cortex-R4"),
                    (0x4100c150, "Cortex-R5"),
                    (0x4100b360, "ARM1136"),
                    (0x4100b560, "ARM1156"),
                    (0x4100b760, "ARM1176"),
                    (0x4100b020, "ARM11-MPCore"),
                    (0x41009260, "ARM926"),
                    (0x41009460, "ARM946"),
                    (0x41009660, "ARM966"),
                    (0x510006f0, "Krait"),
                    (0x510000f0, "Scorpion"),
                ];
                let features = [
                    (md::ArmElfHwCaps::HWCAP_SWP, "swp"),
                    (md::ArmElfHwCaps::HWCAP_HALF, "half"),
                    (md::ArmElfHwCaps::HWCAP_THUMB, "thumb"),
                    (md::ArmElfHwCaps::HWCAP_26BIT, "26bit"),
                    (md::ArmElfHwCaps::HWCAP_FAST_MULT, "fastmult"),
                    (md::ArmElfHwCaps::HWCAP_FPA, "fpa"),
                    (md::ArmElfHwCaps::HWCAP_VFP, "vfpv2"),
                    (md::ArmElfHwCaps::HWCAP_EDSP, "edsp"),
                    (md::ArmElfHwCaps::HWCAP_JAVA, "java"),
                    (md::ArmElfHwCaps::HWCAP_IWMMXT, "iwmmxt"),
                    (md::ArmElfHwCaps::HWCAP_CRUNCH, "crunch"),
                    (md::ArmElfHwCaps::HWCAP_THUMBEE, "thumbee"),
                    (md::ArmElfHwCaps::HWCAP_NEON, "neon"),
                    (md::ArmElfHwCaps::HWCAP_VFPv3, "vfpv3"),
                    (md::ArmElfHwCaps::HWCAP_VFPv3D16, "vfpv3d16"),
                    (md::ArmElfHwCaps::HWCAP_TLS, "tls"),
                    (md::ArmElfHwCaps::HWCAP_VFPv4, "vfpv4"),
                    (md::ArmElfHwCaps::HWCAP_IDIVA, "idiva"),
                    (md::ArmElfHwCaps::HWCAP_IDIVT, "idivt"),
                ];

                let mut cpu_info = format!("ARMv{}", raw.processor_level);

                // Try to extract out known vendor/part names from the cpuid,
                // falling back to just reporting the raw value.
                let cpuid = arm_info.cpuid;
                if cpuid != 0 {
                    let vendor_id = (cpuid >> 24) & 0xff;
                    let part_id = cpuid & 0xff00fff0;

                    if let Some(&(_, vendor)) = vendors.iter().find(|&&(id, _)| id == vendor_id) {
                        write!(&mut cpu_info, " {}", vendor).unwrap();
                    } else {
                        write!(&mut cpu_info, " vendor(0x{:x})", vendor_id).unwrap();
                    }

                    if let Some(&(_, part)) = parts.iter().find(|&&(id, _)| id == part_id) {
                        write!(&mut cpu_info, " {}", part).unwrap();
                    } else {
                        write!(&mut cpu_info, " part(0x{:x})", part_id).unwrap();
                    }
                }

                // Report all the known hardware features.
                let elf_hwcaps = md::ArmElfHwCaps::from_bits_truncate(arm_info.elf_hwcaps);
                if !elf_hwcaps.is_empty() {
                    cpu_info.push_str(" features: ");

                    // Iterator::intersperse is still unstable, so do it manually
                    let mut comma = "";
                    for &(_, feature) in features
                        .iter()
                        .filter(|&&(feature, _)| elf_hwcaps.contains(feature))
                    {
                        cpu_info.push_str(comma);
                        cpu_info.push_str(feature);
                        comma = ",";
                    }
                }

                Some(cpu_info)
            }
            _ => None,
        };

        Ok(MinidumpSystemInfo {
            raw,
            os,
            cpu,
            csd_version,
            cpu_info,
        })
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
  (version)                                  = {}.{}.{} {}
  (cpu_info)                                 = {}

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
            self.raw.suite_mask,
            self.raw.major_version,
            self.raw.minor_version,
            self.raw.build_number,
            self.csd_version().as_deref().unwrap_or(""),
            self.cpu_info().as_deref().unwrap_or(""),
        )?;
        // TODO: cpu info etc
        Ok(())
    }

    /// If the minidump was generated on:
    /// - Windows: Returns the the name of the Service Pack.
    /// - macOS: Returns the product build number.
    /// - Linux: Returns the contents of `uname -srvmo`.
    pub fn csd_version(&self) -> Option<Cow<str>> {
        self.csd_version.as_deref().map(Cow::Borrowed)
    }

    /// Returns a string describing the cpu's vendor and model.
    pub fn cpu_info(&self) -> Option<Cow<str>> {
        self.cpu_info.as_deref().map(Cow::Borrowed)
    }

    /// Strings identifying the version and build number of the operating
    /// system. Returns a tuple in the format of (version, build number). This
    /// may be useful to use if the minidump was created on a Linux machine and
    /// is an producing empty-ish version number (0.0.0).
    ///
    /// Tries to parse the version number from the build if it cannot be found
    /// in the version string. If the stream already contains a valid version
    /// number or parsing from the build string fails, this will return what's
    /// directly stored in the stream.
    pub fn os_parts(&self) -> (String, Option<String>) {
        let os_version = format!(
            "{}.{}.{}",
            self.raw.major_version, self.raw.minor_version, self.raw.build_number
        );

        let os_build = self
            .csd_version()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());

        if md::PlatformId::from_u32(self.raw.platform_id) != Some(md::PlatformId::Linux)
            || os_version != "0.0.0"
        {
            return (os_version, os_build);
        }

        // Try to parse the Linux build string. Breakpad and Crashpad run
        // `uname -srvmo` to generate it. The string follows this structure:
        // "Linux [version] [build...] [arch] Linux/GNU" where the Linux/GNU
        // bit may not always be present.
        let raw_build = self.csd_version().unwrap_or(Cow::Borrowed(""));
        let mut parts = raw_build.split(' ');
        let version = parts.nth(1).unwrap_or("0.0.0");
        let _arch_or_os = parts.next_back().unwrap_or_default();
        if _arch_or_os == "Linux/GNU" {
            let _arch = parts.next_back();
        }
        let build = parts.collect::<Vec<&str>>().join(" ");

        if version == "0.0.0" {
            (os_version, os_build)
        } else {
            (version.into(), Some(build))
        }
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
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::MiscInfoStream as u32;

    fn read(
        bytes: &[u8],
        _all: &[u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpMiscInfo, Error> {
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

// Generates an accessor for a MAC_CRASH_INFO field with two possible syntaxes:
//
// * VERSION_NUMBER: FIELD_NAME -> FIELD_TYPE
// * VERSION_NUMBER: string FIELD_NAME -> FIELD_TYPE
//
// With the following definitions:
//
// * VERSION_NUMBER: The MAC_CRASH_INFO version this field was introduced in
// * FIELD_NAME: The name of the field to read
// * FIELD_TYPE: The type of the field
//
// The "string" mode will retrieve the field from the variant's _RECORD_STRINGS
// struct, while the other mode will retrieve it from the variant's _RECORD
// struct.
//
// In both cases, None will be yielded if the value is null/empty.
macro_rules! mac_crash_accessors {
    () => {};
    (@deffixed $name:ident $t:ty [$($variant:ident)+]) => {
        #[allow(unreachable_patterns)]
        pub fn $name(&self) -> Option<&$t> {
            match self {
                $(
                    RawMacCrashInfo::$variant(ref fixed, _) => {
                        if fixed.$name == 0 {
                            None
                        } else {
                            Some(&fixed.$name)
                        }
                    },
                )+
                _ => None,
            }
        }
    };
    (@defstrings $name:ident $t:ty [$($variant:ident)+]) => {
        #[allow(unreachable_patterns)]
        pub fn $name(&self) -> Option<&$t> {
            match self {
                $(
                    RawMacCrashInfo::$variant(_, ref strings) => {
                        if strings.$name.is_empty() {
                            None
                        } else {
                            Some(&*strings.$name)
                        }
                    }
                )+
                _ => None,
            }
        }
    };
    (1: $name:ident -> $t:ty, $($rest:tt)*) => {
        mac_crash_accessors!(@deffixed $name $t [V1 V4 V5]);
        mac_crash_accessors!($($rest)*);
    };
    (1: string $name:ident -> $t:ty, $($rest:tt)*) => {
        mac_crash_accessors!(@defstrings $name $t [V1 V4 V5]);
        mac_crash_accessors!($($rest)*);
    };
    (4: $name:ident -> $t:ty, $($rest:tt)*) => {
        mac_crash_accessors!(@deffixed $name $t [V4 V5]);
        mac_crash_accessors!($($rest)*);
    };
    (4: string $name:ident -> $t:ty, $($rest:tt)*) => {
        mac_crash_accessors!(@defstrings $name $t [V4 V5]);
        mac_crash_accessors!($($rest)*);
    };
    (5: $name:ident -> $t:ty, $($rest:tt)*) => {
        mac_crash_accessors!(@deffixed $name $t [V5]);
        mac_crash_accessors!($($rest)*);
    };
    (5: string $name:ident -> $t:ty, $($rest:tt)*) => {
        mac_crash_accessors!(@defstrings $name $t [V5]);
        mac_crash_accessors!($($rest)*);
    };
}

impl RawMacCrashInfo {
    // Fields are grouped by the flag that guards them.
    mac_crash_accessors!(
        1: version -> u64,

        4: thread -> u64,
        4: dialog_mode -> u64,

        4: string module_path -> str,
        4: string message -> str,
        4: string signature_string -> str,
        4: string backtrace -> str,
        4: string message2 -> str,

        5: abort_cause -> u64,
    );
}

impl<'a> MinidumpStream<'a> for MinidumpMacCrashInfo {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::MozMacosCrashInfoStream as u32;

    fn read(
        bytes: &[u8],
        all: &[u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpMacCrashInfo, Error> {
        // Get the main header of the stream
        let header: md::MINIDUMP_MAC_CRASH_INFO = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;

        let strings_offset = header.record_start_size as usize;
        let mut prev_version = None;
        let mut infos = Vec::new();

        // We use `take` here to better handle a corrupt record_count that is larger than the
        // maximum supported size.
        let records = header.records.iter().take(header.record_count as usize);

        for record_location in records {
            // Peek the V1 version to get the `version` field
            let record_slice = location_slice(all, record_location)?;
            let base: md::MINIDUMP_MAC_CRASH_INFO_RECORD = record_slice
                .pread_with(0, endian)
                .or(Err(Error::StreamReadFailure))?;

            // The V1 version also includes the stream type again, but that's
            // not really important, so just warn about it and keep going.
            if base.stream_type != header.stream_type as u64 {
                warn!(
                    "MozMacosCrashInfoStream records don't have the right stream type? {}",
                    base.stream_type
                );
            }

            // Make sure every record has the same version, because they have to
            // share their strings_offset which make heterogeneous records impossible.
            if let Some(prev_version) = prev_version {
                if prev_version != base.version {
                    warn!(
                        "MozMacosCrashInfoStream had two different versions ({} != {})",
                        prev_version, base.version
                    );
                    return Err(Error::VersionMismatch);
                }
            }
            prev_version = Some(base.version);

            // Now actually read the full record and its strings for the version
            macro_rules! do_read {
                ($base_version:expr, $strings_offset:expr, $infos:ident,
                    $(($version:expr, $fixed:ty, $strings:ty, $variant:ident),)+) => {$(
                    if $base_version >= $version {
                        let offset = &mut 0;
                        let fixed: $fixed = record_slice
                            .gread_with(offset, endian)
                            .or(Err(Error::StreamReadFailure))?;

                        // Sanity check that we haven't blown past where the strings start.
                        if *offset > $strings_offset {
                            warn!("MozMacosCrashInfoStream's record_start_size was too small! ({})",
                                $strings_offset);
                            return Err(Error::StreamReadFailure);
                        }

                        // We could be handling a newer version of the format than we know
                        // how to support, so jump to where the strings start, potentially
                        // skipping over some unknown fields.
                        *offset = $strings_offset;
                        let num_strings = <$strings>::num_strings();
                        let mut strings = <$strings>::default();

                        // Read out all the strings we know about
                        for i in 0..num_strings {
                            let string = read_cstring_utf8(offset, record_slice)
                                .ok_or(Error::StreamReadFailure)?;
                            strings.set_string(i, string);
                        }
                        // If this is a newer version, there may be some extra variable length
                        // data in this record, but we don't know what it is, so don't try to parse it.

                        infos.push(RawMacCrashInfo::$variant(fixed, strings));
                        continue;
                    }
                )+}
            }

            do_read!(
                base.version,
                strings_offset,
                infos,
                (
                    5,
                    md::MINIDUMP_MAC_CRASH_INFO_RECORD_5,
                    md::MINIDUMP_MAC_CRASH_INFO_RECORD_STRINGS_5,
                    V5
                ),
                (
                    4,
                    md::MINIDUMP_MAC_CRASH_INFO_RECORD_4,
                    md::MINIDUMP_MAC_CRASH_INFO_RECORD_STRINGS_4,
                    V4
                ),
                (
                    1,
                    md::MINIDUMP_MAC_CRASH_INFO_RECORD,
                    md::MINIDUMP_MAC_CRASH_INFO_RECORD_STRINGS,
                    V1
                ),
            );
        }
        Ok(MinidumpMacCrashInfo { raw: infos })
    }
}

impl<'a> MinidumpStream<'a> for MinidumpLinuxLsbRelease<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::LinuxLsbRelease as u32;

    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        _endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpLinuxLsbRelease<'a>, Error> {
        Ok(Self { data: bytes })
    }
}

impl<'a> MinidumpStream<'a> for MinidumpLinuxEnviron<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::LinuxEnviron as u32;

    #[allow(clippy::single_match)]
    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        _endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpLinuxEnviron<'a>, Error> {
        Ok(Self { data: bytes })
    }
}

impl<'a> MinidumpStream<'a> for MinidumpLinuxProcStatus<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::LinuxProcStatus as u32;

    #[allow(clippy::single_match)]
    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        _endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpLinuxProcStatus<'a>, Error> {
        Ok(Self { data: bytes })
    }
}

impl<'a> MinidumpStream<'a> for MinidumpLinuxCpuInfo<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::LinuxCpuInfo as u32;

    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        _endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<MinidumpLinuxCpuInfo<'a>, Error> {
        Ok(Self { data: bytes })
    }
}

impl<'a> MinidumpLinuxCpuInfo<'a> {
    /// Get an iterator over the key-value pairs stored in the `/proc/cpuinfo` dump.
    ///
    /// Keys and values are `trim`ed of leading/trailing spaces, and if a key
    /// or value was surrounded by quotes ("like this"), the quotes will be
    /// stripped.
    pub fn iter(&self) -> impl Iterator<Item = (&'a LinuxOsStr, &'a LinuxOsStr)> {
        linux_list_iter(self.data, b':')
    }

    /// Get the raw bytes of the `/proc/cpuinfo` dump.
    pub fn raw_bytes(&self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self.data)
    }
}

impl<'a> MinidumpLinuxEnviron<'a> {
    /// Get an iterator over the key-value pairs stored in the `/proc/self/environ` dump.
    ///
    /// Keys and values are `trim`ed of leading/trailing spaces, and if a key
    /// or value was surrounded by quotes ("like this"), the quotes will be
    /// stripped.
    pub fn iter(&self) -> impl Iterator<Item = (&'a LinuxOsStr, &'a LinuxOsStr)> {
        linux_list_iter(self.data, b'=')
    }

    /// Get the raw bytes of the `/proc/self/environ` dump.
    pub fn raw_bytes(&self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self.data)
    }
}

impl<'a> MinidumpLinuxProcStatus<'a> {
    /// Get an iterator over the key-value pairs stored in the `/proc/self/status` dump.
    ///
    /// Keys and values are `trim`ed of leading/trailing spaces, and if a key
    /// or value was surrounded by quotes ("like this"), the quotes will be
    /// stripped.
    pub fn iter(&self) -> impl Iterator<Item = (&'a LinuxOsStr, &'a LinuxOsStr)> {
        linux_list_iter(self.data, b':')
    }

    /// Get the raw bytes of the `/proc/self/status` dump.
    pub fn raw_bytes(&self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self.data)
    }
}

impl<'a> MinidumpLinuxLsbRelease<'a> {
    /// Get an iterator over the key-value pairs stored in the `/etc/lsb-release` dump.
    ///
    /// Keys and values are `trim`ed of leading/trailing spaces, and if a key
    /// or value was surrounded by quotes ("like this"), the quotes will be
    /// stripped.
    pub fn iter(&self) -> impl Iterator<Item = (&'a LinuxOsStr, &'a LinuxOsStr)> {
        linux_list_iter(self.data, b'=')
    }

    /// Get the raw bytes of the `/etc/lsb-release` dump.
    pub fn raw_bytes(&self) -> Cow<'a, [u8]> {
        Cow::Borrowed(self.data)
    }
}

fn systemtime_from_timestamp(timestamp: u64) -> Option<SystemTime> {
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(timestamp))
}

impl MinidumpMiscInfo {
    pub fn process_create_time(&self) -> Option<SystemTime> {
        self.raw
            .process_create_time()
            .and_then(|t| systemtime_from_timestamp(*t as u64))
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
                        let feature_name = format!("{:?}", feature);
                        write!(f, "    feature {:2} - {:22}: ", i, feature_name)?;
                    } else {
                        write!(f, "    feature {:2} - (unknown)           : ", i)?;
                    }
                    writeln!(f, " offset {:4}, size {:4}", feature.offset, feature.size)?;
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
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::BreakpadInfoStream as u32;

    fn read(
        bytes: &[u8],
        _all: &[u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
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
    fn from_exception(raw: &md::MINIDUMP_EXCEPTION_STREAM, os: Os, cpu: Cpu) -> CrashReason {
        let record = &raw.exception_record;
        let exception_code = record.exception_code;
        let exception_flags = record.exception_flags;

        let reason = match os {
            Os::MacOs | Os::Ios => Self::from_mac_exception(raw, cpu),
            Os::Linux | Os::Android => Self::from_linux_exception(raw, cpu),
            Os::Windows => Self::from_windows_exception(raw, cpu),
            _ => None,
        };

        // Default to a totally generic unknown error
        reason.unwrap_or(CrashReason::Unknown(exception_code, exception_flags))
    }

    /// Heuristically identifies what kind of windows exception code this is.
    ///
    /// Augments [`CrashReason::from_windows_error`] by also including
    /// `ExceptionCodeWindows`. Appropriate for an actual crash reason.
    pub fn from_windows_code(exception_code: u32) -> CrashReason {
        if let Some(err) = err::ExceptionCodeWindows::from_u32(exception_code) {
            Self::WindowsGeneral(err)
        } else {
            Self::from_windows_error(exception_code)
        }
    }

    /// Heuristically identifies what kind of windows error code this is.
    ///
    /// Appropriate for things like LastErrorValue() which may be non-fatal.
    pub fn from_windows_error(error_code: u32) -> CrashReason {
        if let Some(err) = err::WinErrorWindows::from_u32(error_code) {
            Self::WindowsWinError(err)
        } else if let Some(err) = err::NtStatusWindows::from_u32(error_code) {
            Self::WindowsNtStatus(err)
        } else {
            Self::WindowsUnknown(error_code)
        }
    }

    pub fn from_windows_exception(
        raw: &md::MINIDUMP_EXCEPTION_STREAM,
        _cpu: Cpu,
    ) -> Option<CrashReason> {
        use err::ExceptionCodeWindows;

        let record = &raw.exception_record;
        let info = &record.exception_information;
        let exception_code = record.exception_code;

        let mut reason = CrashReason::from_windows_code(exception_code);

        // Refine the output for error codes that have more info
        match reason {
            CrashReason::WindowsGeneral(ExceptionCodeWindows::EXCEPTION_ACCESS_VIOLATION) => {
                // For EXCEPTION_ACCESS_VIOLATION, Windows puts the address that
                // caused the fault in exception_information[1].
                // exception_information[0] is 0 if the violation was caused by
                // an attempt to read data, 1 if it was an attempt to write data,
                // and 8 if this was a data execution violation.
                // This information is useful in addition to the code address, which
                // will be present in the crash thread's instruction field anyway.
                if record.number_parameters >= 1 {
                    // NOTE: address := info[1];
                    if let Some(ty) = err::ExceptionCodeWindowsAccessType::from_u64(info[0]) {
                        reason = CrashReason::WindowsAccessViolation(ty);
                    }
                }
            }
            CrashReason::WindowsGeneral(ExceptionCodeWindows::EXCEPTION_IN_PAGE_ERROR) => {
                // For EXCEPTION_IN_PAGE_ERROR, Windows puts the address that
                // caused the fault in exception_information[1].
                // exception_information[0] is 0 if the violation was caused by
                // an attempt to read data, 1 if it was an attempt to write data,
                // and 8 if this was a data execution violation.
                // exception_information[2] contains the underlying NTSTATUS code,
                // which is the explanation for why this error occured.
                // This information is useful in addition to the code address, which
                // will be present in the crash thread's instruction field anyway.
                if record.number_parameters >= 3 {
                    // NOTE: address := info[1];
                    let nt_status = info[2];
                    if let Some(ty) = err::ExceptionCodeWindowsInPageErrorType::from_u64(info[0]) {
                        reason = CrashReason::WindowsInPageError(ty, nt_status);
                    }
                }
            }
            CrashReason::WindowsNtStatus(err::NtStatusWindows::STATUS_STACK_BUFFER_OVERRUN) => {
                if record.number_parameters >= 1 {
                    let fast_fail = info[0];
                    reason = CrashReason::WindowsStackBufferOverrun(fast_fail);
                }
            }
            _ => {
                // Do nothing interesting
            }
        }

        Some(reason)
    }

    pub fn from_mac_exception(
        raw: &md::MINIDUMP_EXCEPTION_STREAM,
        cpu: Cpu,
    ) -> Option<CrashReason> {
        use err::ExceptionCodeMac;

        let record = &raw.exception_record;
        let info = &record.exception_information;
        let exception_code = record.exception_code;
        let exception_flags = record.exception_flags;

        // Default to just directly reporting this reason.
        let mac_reason = err::ExceptionCodeMac::from_u32(exception_code)?;
        let mut reason = CrashReason::MacGeneral(mac_reason, exception_flags);

        // Refine the output for error codes that have more info
        match mac_reason {
            ExceptionCodeMac::EXC_BAD_ACCESS => {
                if let Some(ty) = err::ExceptionCodeMacBadAccessKernType::from_u32(exception_flags)
                {
                    reason = CrashReason::MacBadAccessKern(ty);
                } else {
                    match cpu {
                        Cpu::Arm64 => {
                            if let Some(ty) =
                                err::ExceptionCodeMacBadAccessArmType::from_u32(exception_flags)
                            {
                                reason = CrashReason::MacBadAccessArm(ty);
                            }
                        }
                        Cpu::Ppc => {
                            if let Some(ty) =
                                err::ExceptionCodeMacBadAccessPpcType::from_u32(exception_flags)
                            {
                                reason = CrashReason::MacBadAccessPpc(ty);
                            }
                        }
                        Cpu::X86 | Cpu::X86_64 => {
                            if let Some(ty) =
                                err::ExceptionCodeMacBadAccessX86Type::from_u32(exception_flags)
                            {
                                reason = CrashReason::MacBadAccessX86(ty);
                            }
                        }
                        _ => {
                            // Do nothing
                        }
                    }
                }
            }
            ExceptionCodeMac::EXC_BAD_INSTRUCTION => match cpu {
                Cpu::Arm64 => {
                    if let Some(ty) =
                        err::ExceptionCodeMacBadInstructionArmType::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacBadInstructionArm(ty);
                    }
                }
                Cpu::Ppc => {
                    if let Some(ty) =
                        err::ExceptionCodeMacBadInstructionPpcType::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacBadInstructionPpc(ty);
                    }
                }
                Cpu::X86 | Cpu::X86_64 => {
                    if let Some(ty) =
                        err::ExceptionCodeMacBadInstructionX86Type::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacBadInstructionX86(ty);
                    }
                }
                _ => {
                    // Do nothing
                }
            },
            ExceptionCodeMac::EXC_ARITHMETIC => match cpu {
                Cpu::Ppc => {
                    if let Some(ty) =
                        err::ExceptionCodeMacArithmeticPpcType::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacArithmeticPpc(ty);
                    }
                }
                Cpu::X86 | Cpu::X86_64 => {
                    if let Some(ty) =
                        err::ExceptionCodeMacArithmeticX86Type::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacArithmeticX86(ty);
                    }
                }
                _ => {
                    // Do nothing
                }
            },
            ExceptionCodeMac::EXC_SOFTWARE => {
                if let Some(ty) = err::ExceptionCodeMacSoftwareType::from_u32(exception_flags) {
                    reason = CrashReason::MacSoftware(ty);
                }
            }
            ExceptionCodeMac::EXC_BREAKPOINT => match cpu {
                Cpu::Arm64 => {
                    if let Some(ty) =
                        err::ExceptionCodeMacBreakpointArmType::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacBreakpointArm(ty);
                    }
                }
                Cpu::Ppc => {
                    if let Some(ty) =
                        err::ExceptionCodeMacBreakpointPpcType::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacBreakpointPpc(ty);
                    }
                }
                Cpu::X86 | Cpu::X86_64 => {
                    if let Some(ty) =
                        err::ExceptionCodeMacBreakpointX86Type::from_u32(exception_flags)
                    {
                        reason = CrashReason::MacBreakpointX86(ty);
                    }
                }
                _ => {
                    // Do nothing
                }
            },
            ExceptionCodeMac::EXC_RESOURCE => {
                if let Some(ty) =
                    err::ExceptionCodeMacResourceType::from_u32((exception_flags >> 29) & 0x7)
                {
                    reason = CrashReason::MacResource(ty, info[1], info[2]);
                }
            }
            ExceptionCodeMac::EXC_GUARD => {
                if let Some(ty) =
                    err::ExceptionCodeMacGuardType::from_u32((exception_flags >> 29) & 0x7)
                {
                    reason = CrashReason::MacGuard(ty, info[1], info[2]);
                }
            }
            _ => {
                // Do nothing
            }
        }
        Some(reason)
    }

    pub fn from_linux_exception(
        raw: &md::MINIDUMP_EXCEPTION_STREAM,
        _cpu: Cpu,
    ) -> Option<CrashReason> {
        let record = &raw.exception_record;
        let exception_code = record.exception_code;
        let exception_flags = record.exception_flags;

        let linux_reason = err::ExceptionCodeLinux::from_u32(exception_code)?;
        let mut reason = CrashReason::LinuxGeneral(linux_reason, exception_flags);
        // Refine the output for error codes that have more info
        match linux_reason {
            err::ExceptionCodeLinux::SIGILL => {
                if let Some(ty) = err::ExceptionCodeLinuxSigillKind::from_u32(exception_flags) {
                    reason = CrashReason::LinuxSigill(ty);
                }
            }
            err::ExceptionCodeLinux::SIGTRAP => {
                if let Some(ty) = err::ExceptionCodeLinuxSigtrapKind::from_u32(exception_flags) {
                    reason = CrashReason::LinuxSigtrap(ty);
                }
            }
            err::ExceptionCodeLinux::SIGFPE => {
                if let Some(ty) = err::ExceptionCodeLinuxSigfpeKind::from_u32(exception_flags) {
                    reason = CrashReason::LinuxSigfpe(ty);
                }
            }
            err::ExceptionCodeLinux::SIGSEGV => {
                if let Some(ty) = err::ExceptionCodeLinuxSigsegvKind::from_u32(exception_flags) {
                    reason = CrashReason::LinuxSigsegv(ty);
                }
            }
            err::ExceptionCodeLinux::SIGBUS => {
                if let Some(ty) = err::ExceptionCodeLinuxSigbusKind::from_u32(exception_flags) {
                    reason = CrashReason::LinuxSigbus(ty);
                }
            }
            err::ExceptionCodeLinux::SIGSYS => {
                if let Some(ty) = err::ExceptionCodeLinuxSigsysKind::from_u32(exception_flags) {
                    reason = CrashReason::LinuxSigsys(ty);
                }
            }
            _ => {
                // No refinements
            }
        }
        Some(reason)
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
        use CrashReason::*;

        fn write_nt_status(f: &mut fmt::Formatter<'_>, raw_nt_status: u64) -> fmt::Result {
            let nt_status = err::NtStatusWindows::from_u64(raw_nt_status);
            if let Some(nt_status) = nt_status {
                write!(f, "{:?}", nt_status)
            } else {
                write!(f, "0x{:08}", raw_nt_status)
            }
        }

        fn write_fast_fail(f: &mut fmt::Formatter<'_>, raw_fast_fail: u64) -> fmt::Result {
            let fast_fail = err::FastFailCode::from_u64(raw_fast_fail);
            if let Some(fast_fail) = fast_fail {
                write!(f, "{:?}", fast_fail)
            } else {
                write!(f, "0x{:08}", raw_fast_fail)
            }
        }

        fn write_exc_resource(
            f: &mut fmt::Formatter<'_>,
            ex: err::ExceptionCodeMacResourceType,
            code: u64,
            subcode: u64,
        ) -> fmt::Result {
            let flavor = (code >> 58) & 0x7;
            write!(f, "EXC_RESOURCE / {:?} / ", ex)?;
            match ex {
                err::ExceptionCodeMacResourceType::RESOURCE_TYPE_CPU => {
                    if let Some(cpu_flavor) =
                        err::ExceptionCodeMacResourceCpuFlavor::from_u64(flavor)
                    {
                        let interval = (code >> 7) & 0x1ffffff;
                        let cpu_limit = code & 0x7;
                        let cpu_consumed = subcode & 0x7;
                        write!(
                            f,
                            "{:?} interval: {}s CPU limit: {}% CPU consumed: {}%",
                            cpu_flavor, interval, cpu_limit, cpu_consumed
                        )
                    } else {
                        write!(f, "0x{:016} / 0x{:016}", code, subcode)
                    }
                }
                err::ExceptionCodeMacResourceType::RESOURCE_TYPE_WAKEUPS => {
                    if let Some(wakeups_flavor) =
                        err::ExceptionCodeMacResourceWakeupsFlavor::from_u64(flavor)
                    {
                        let interval = (code >> 20) & 0xfffff;
                        let wakeups_permitted = code & 0xfff;
                        let wakeups_observed = subcode & 0xfff;
                        write!(
                            f,
                            "{:?} interval: {}s wakeups permitted: {} wakeups observed: {}",
                            wakeups_flavor, interval, wakeups_permitted, wakeups_observed
                        )
                    } else {
                        write!(f, "0x{:016} / 0x{:016}", code, subcode)
                    }
                }
                err::ExceptionCodeMacResourceType::RESOURCE_TYPE_MEMORY => {
                    if let Some(memory_flavor) =
                        err::ExceptionCodeMacResourceMemoryFlavor::from_u64(flavor)
                    {
                        let hwm_limit = code & 0x1fff;
                        write!(
                            f,
                            "{:?} high watermark limit: {}MiB",
                            memory_flavor, hwm_limit
                        )
                    } else {
                        write!(f, "0x{:016} / 0x{:016}", code, subcode)
                    }
                }
                err::ExceptionCodeMacResourceType::RESOURCE_TYPE_IO => {
                    if let Some(io_flavor) = err::ExceptionCodeMacResourceIOFlavor::from_u64(flavor)
                    {
                        let interval = (code >> 15) & 0x1ffff;
                        let io_limit = code & 0x7fff;
                        let io_observed = subcode & 0x7fff;
                        write!(
                            f,
                            "{:?} interval: {}s I/O limit: {}% I/O observed: {}%",
                            io_flavor, interval, io_limit, io_observed
                        )
                    } else {
                        write!(f, "0x{:016} / 0x{:016}", code, subcode)
                    }
                }
                err::ExceptionCodeMacResourceType::RESOURCE_TYPE_THREADS => {
                    if let Some(threads_flavor) =
                        err::ExceptionCodeMacResourceThreadsFlavor::from_u64(flavor)
                    {
                        let hwm_limit = code & 0x7fff;
                        write!(
                            f,
                            "{:?} high watermark limit: {}",
                            threads_flavor, hwm_limit
                        )
                    } else {
                        write!(f, "0x{:016} / 0x{:016}", code, subcode)
                    }
                }
            }
        }

        fn write_exc_guard(
            f: &mut fmt::Formatter<'_>,
            ex: err::ExceptionCodeMacGuardType,
            code: u64,
            subcode: u64,
        ) -> fmt::Result {
            let flavor = (code >> 32) & 0x1fffffff;
            write!(f, "EXC_GUARD / {:?}", ex)?;
            match ex {
                err::ExceptionCodeMacGuardType::GUARD_TYPE_NONE => {
                    write!(f, "")
                }
                err::ExceptionCodeMacGuardType::GUARD_TYPE_MACH_PORT => {
                    if let Some(mach_port_flavor) =
                        err::ExceptionCodeMacGuardMachPortFlavor::from_u64(flavor)
                    {
                        let port_name = code & 0xfffffff;
                        write!(
                            f,
                            " / {:?} port name: {} guard identifier: {}",
                            mach_port_flavor, port_name, subcode,
                        )
                    } else {
                        write!(f, " / 0x{:016} / 0x{:016}", code, subcode)
                    }
                }
                err::ExceptionCodeMacGuardType::GUARD_TYPE_FD => {
                    if let Some(fd_flavor) = err::ExceptionCodeMacGuardFDFlavor::from_u64(flavor) {
                        let fd = code & 0xfffffff;
                        write!(
                            f,
                            " / {:?} file descriptor: {} guard identifier: {}",
                            fd_flavor, fd, subcode,
                        )
                    } else {
                        write!(f, " / 0x{:016} / 0x{:016}", code, subcode)
                    }
                }
                err::ExceptionCodeMacGuardType::GUARD_TYPE_USER => {
                    let namespace = code & 0xffffffff;
                    write!(
                        f,
                        "/ namespace: {} guard identifier: {}",
                        namespace, subcode,
                    )
                }
                err::ExceptionCodeMacGuardType::GUARD_TYPE_VN => {
                    if let Some(vn_flavor) = err::ExceptionCodeMacGuardVNFlavor::from_u64(flavor) {
                        let pid = code & 0xfffffff;
                        write!(
                            f,
                            " / {:?} pid: {} guard identifier: {}",
                            vn_flavor, pid, subcode,
                        )
                    } else {
                        write!(f, " / 0x{:016} / 0x{:016}", code, subcode)
                    }
                }
                err::ExceptionCodeMacGuardType::GUARD_TYPE_VIRT_MEMORY => {
                    if let Some(virt_memory_flavor) =
                        err::ExceptionCodeMacGuardVirtMemoryFlavor::from_u64(flavor)
                    {
                        write!(f, " / {:?} offset: {}", virt_memory_flavor, subcode)
                    } else {
                        write!(f, " / 0x{:016} / 0x{:016}", code, subcode)
                    }
                }
            }
        }

        fn write_signal(
            f: &mut fmt::Formatter<'_>,
            ex: err::ExceptionCodeLinux,
            flags: u32,
        ) -> fmt::Result {
            if let Some(si_code) = err::ExceptionCodeLinuxSicode::from_u32(flags) {
                if si_code == err::ExceptionCodeLinuxSicode::SI_USER {
                    write!(f, "{:?}", ex)
                } else {
                    write!(f, "{:?} / {:?}", ex, si_code)
                }
            } else {
                write!(f, "{:?} / 0x{:08x}", ex, flags)
            }
        }

        // OK this is kinda a gross hack but I *really* don't want
        // to write out all these strings again, so let's just lean on Debug
        // repeating the name of the enum variant!
        match *self {
            // ======================== Mac/iOS ============================

            // These codes get special messages
            MacGeneral(err::ExceptionCodeMac::SIMULATED, _) => write!(f, "Simulated Exception"),

            // Thse codes just repeat their names
            MacGeneral(ex, flags) => write!(f, "{:?} / 0x{:08x}", ex, flags),
            MacBadAccessKern(ex) => write!(f, "EXC_BAD_ACCESS / {:?}", ex),
            MacBadAccessArm(ex) => write!(f, "EXC_BAD_ACCESS / {:?}", ex),
            MacBadAccessPpc(ex) => write!(f, "EXC_BAD_ACCESS / {:?}", ex),
            MacBadAccessX86(ex) => write!(f, "EXC_BAD_ACCESS / {:?}", ex),
            MacBadInstructionArm(ex) => write!(f, "EXC_BAD_INSTRUCTION / {:?}", ex),
            MacBadInstructionPpc(ex) => write!(f, "EXC_BAD_INSTRUCTION / {:?}", ex),
            MacBadInstructionX86(ex) => write!(f, "EXC_BAD_INSTRUCTION / {:?}", ex),
            MacArithmeticPpc(ex) => write!(f, "EXC_ARITHMETIC / {:?}", ex),
            MacArithmeticX86(ex) => write!(f, "EXC_ARITHMETIC / {:?}", ex),
            MacSoftware(ex) => write!(f, "EXC_SOFTWARE / {:?}", ex),
            MacBreakpointArm(ex) => write!(f, "EXC_BREAKPOINT / {:?}", ex),
            MacBreakpointPpc(ex) => write!(f, "EXC_BREAKPOINT / {:?}", ex),
            MacBreakpointX86(ex) => write!(f, "EXC_BREAKPOINT / {:?}", ex),
            MacResource(ex, code, subcode) => write_exc_resource(f, ex, code, subcode),
            MacGuard(ex, code, subcode) => write_exc_guard(f, ex, code, subcode),

            // ===================== Linux/Android =========================

            // These codes just repeat their names
            LinuxGeneral(ex, flags) => write_signal(f, ex, flags),
            LinuxSigill(ex) => write!(f, "SIGILL / {:?}", ex),
            LinuxSigtrap(ex) => write!(f, "SIGTRAP / {:?}", ex),
            LinuxSigbus(ex) => write!(f, "SIGBUS / {:?}", ex),
            LinuxSigfpe(ex) => write!(f, "SIGFPE / {:?}", ex),
            LinuxSigsegv(ex) => write!(f, "SIGSEGV / {:?}", ex),
            LinuxSigsys(ex) => write!(f, "SIGSYS / {:?}", ex),

            // ======================== Windows =============================

            // These codes get special messages
            WindowsGeneral(err::ExceptionCodeWindows::OUT_OF_MEMORY) => write!(f, "Out of Memory"),
            WindowsGeneral(err::ExceptionCodeWindows::UNHANDLED_CPP_EXCEPTION) => {
                write!(f, "Unhandled C++ Exception")
            }
            WindowsGeneral(err::ExceptionCodeWindows::SIMULATED) => {
                write!(f, "Simulated Exception")
            }
            // These codes just repeat their names
            WindowsGeneral(ex) => write!(f, "{:?}", ex),
            WindowsWinError(winerror) => write!(f, "{:?}", winerror),
            WindowsNtStatus(nt_status) => write_nt_status(f, nt_status as _),
            WindowsAccessViolation(ex) => write!(f, "EXCEPTION_ACCESS_VIOLATION_{:?}", ex),
            WindowsInPageError(ex, nt_status) => {
                write!(f, "EXCEPTION_IN_PAGE_ERROR_{:?} / ", ex)?;
                write_nt_status(f, nt_status)
            }
            WindowsStackBufferOverrun(fast_fail) => {
                write!(f, "EXCEPTION_STACK_BUFFER_OVERRUN / ")?;
                write_fast_fail(f, fast_fail)
            }
            WindowsUnknown(code) => write!(f, "unknown 0x{:08}", code),

            Unknown(code, flags) => write!(f, "unknown 0x{:08} / 0x{:08}", code, flags),
        }
    }
}

impl<'a> MinidumpStream<'a> for MinidumpException<'a> {
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::ExceptionStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<Self, Error> {
        let raw: md::MINIDUMP_EXCEPTION_STREAM = bytes
            .pread_with(0, endian)
            .or(Err(Error::StreamReadFailure))?;
        let context = location_slice(all, &raw.thread_context).ok();
        let thread_id = raw.thread_id;
        Ok(MinidumpException {
            raw,
            thread_id,
            context,
            endian,
        })
    }
}

impl<'a> MinidumpException<'a> {
    /// Get the cpu context of the crashing (or otherwise minidump-requesting) thread.
    ///
    /// CPU contexts are a platform-specific format, so SystemInfo is required
    /// to reliably parse them. We used to use heuristics to avoid this requirement,
    /// but this made us too brittle to otherwise-backwards-compatible additions
    /// to the format.
    ///
    /// MiscInfo can contain additional details on the cpu context's format, but
    /// is optional because those details can be safely ignored (at the cost of
    /// being unable to parse some very obscure cpu state).
    pub fn context(
        &self,
        system_info: &MinidumpSystemInfo,
        misc: Option<&MinidumpMiscInfo>,
    ) -> Option<Cow<MinidumpContext>> {
        MinidumpContext::read(self.context?, self.endian, system_info, misc)
            .ok()
            .map(Cow::Owned)
    }

    /// Get the address that "caused" the crash.
    ///
    /// The meaning of this value depends on the kind of crash this was.
    ///
    /// By default, it's the instruction pointer at the time of the crash.
    /// However, if the crash was caused by an illegal memory access, the
    /// the address would be the memory address.
    ///
    /// So for instance, if you crashed from dereferencing a null pointer,
    /// the crash_address will be 0 (or close to it, due to offsets).
    pub fn get_crash_address(&self, os: Os, cpu: Cpu) -> u64 {
        let addr = match (
            os,
            err::ExceptionCodeWindows::from_u32(self.raw.exception_record.exception_code),
        ) {
            (Os::Windows, Some(err::ExceptionCodeWindows::EXCEPTION_ACCESS_VIOLATION))
            | (Os::Windows, Some(err::ExceptionCodeWindows::EXCEPTION_IN_PAGE_ERROR))
                if self.raw.exception_record.number_parameters >= 2 =>
            {
                self.raw.exception_record.exception_information[1]
            }
            _ => self.raw.exception_record.exception_address,
        };

        // Sometimes on 32-bit these values can be incorrectly sign-extended,
        // so mask and zero-extend them here.
        match cpu.pointer_width() {
            PointerWidth::Bits32 => addr as u32 as u64,
            _ => addr,
        }
    }

    /// Get the crash reason for an exception.
    ///
    /// The returned value reflects our best attempt to recover a
    /// "native" error for the crashing system based on the OS and
    /// things like raw error codes.
    ///
    /// This is an imperfect process, because OSes may have overlapping
    /// error types (e.g. WinError and NTSTATUS overlap, so we have to
    /// pick one arbirarily).
    ///
    /// The raw error codes can be extracted from [MinidumpException::raw][].
    pub fn get_crash_reason(&self, os: Os, cpu: Cpu) -> CrashReason {
        CrashReason::from_exception(&self.raw, os, cpu)
    }

    /// The id of the thread that caused the crash (or otherwise requested
    /// the minidump, even if there wasn't actually a crash).
    pub fn get_crashing_thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Write a human-readable description of this `MinidumpException` to `f`.
    ///
    /// This is very verbose, it is the format used by `minidump_dump`.
    pub fn print<T: Write>(
        &self,
        f: &mut T,
        system: Option<&MinidumpSystemInfo>,
        misc: Option<&MinidumpMiscInfo>,
    ) -> io::Result<()> {
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
        if let Some(system_info) = system {
            if let Some(context) = self.context(system_info, misc) {
                writeln!(f)?;
                context.print(f)?;
            } else {
                write!(
                    f,
                    "  (no context)

    "
                )?;
            }
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
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::AssertionInfoStream as u32;

    fn read(
        bytes: &'a [u8],
        _all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
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
            self.expression().unwrap_or_default(),
            self.function().unwrap_or_default(),
            self.file().unwrap_or_default(),
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

    let (count, _) = ensure_count_in_bound(all, count as usize, <md::RVA>::size_with(&endian), 0)?;

    let mut strings = Vec::with_capacity(count);
    for _ in 0..count {
        let rva: md::RVA = data
            .gread_with(&mut offset, endian)
            .or(Err(Error::StreamReadFailure))?;

        let string = read_string_utf8(&mut (rva as usize), all, endian)
            .ok_or(Error::StreamReadFailure)?
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
            .ok_or(Error::StreamReadFailure)?;
        let value = read_string_utf8(&mut (entry.value as usize), all, endian)
            .ok_or(Error::StreamReadFailure)?;

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
            .ok_or(Error::StreamReadFailure)?;

        let value = match raw.ty {
            md::MINIDUMP_ANNOTATION::TYPE_INVALID => MinidumpAnnotation::Invalid,
            md::MINIDUMP_ANNOTATION::TYPE_STRING => {
                let string = read_string_utf8_unterminated(&mut (raw.value as usize), all, endian)
                    .ok_or(Error::StreamReadFailure)?
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

    let (count, _) = ensure_count_in_bound(
        all,
        count as usize,
        <md::MINIDUMP_MODULE_CRASHPAD_INFO_LINK>::size_with(&endian),
        0,
    )?;

    let mut module_links = Vec::with_capacity(count);
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
    const STREAM_TYPE: u32 = MINIDUMP_STREAM_TYPE::CrashpadInfoStream as u32;

    fn read(
        bytes: &'a [u8],
        all: &'a [u8],
        endian: scroll::Endian,
        _system_info: Option<&MinidumpSystemInfo>,
    ) -> Result<Self, Error> {
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

/// A stream in the minidump that this implementation can interpret,
#[derive(Debug)]
pub struct MinidumpImplementedStream {
    pub stream_type: MINIDUMP_STREAM_TYPE,
    pub location: md::MINIDUMP_LOCATION_DESCRIPTOR,
    pub vendor: &'static str,
}

/// A stream in the minidump that this implementation has no knowledge of.
#[derive(Debug)]
pub struct MinidumpUnknownStream {
    pub stream_type: u32,
    pub location: md::MINIDUMP_LOCATION_DESCRIPTOR,
    pub vendor: &'static str,
}

/// A stream in the minidump that this implementation is aware of but doesn't
/// yet support.
#[derive(Debug)]
pub struct MinidumpUnimplementedStream {
    pub stream_type: MINIDUMP_STREAM_TYPE,
    pub location: md::MINIDUMP_LOCATION_DESCRIPTOR,
    pub vendor: &'static str,
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

        offset = header.stream_directory_rva as usize;

        let (count, _) = ensure_count_in_bound(
            &data,
            header.stream_count as usize,
            <md::MINIDUMP_DIRECTORY>::size_with(&endian),
            offset,
        )?;

        let mut streams = HashMap::with_capacity(count);
        for i in 0..header.stream_count {
            let dir: md::MINIDUMP_DIRECTORY = data
                .gread_with(&mut offset, endian)
                .or(Err(Error::MissingDirectory))?;
            if let Some((old_idx, old_dir)) = streams.insert(dir.stream_type, (i, dir.clone())) {
                if let Some(known_stream_type) = MINIDUMP_STREAM_TYPE::from_u32(dir.stream_type) {
                    warn!("Minidump contains multiple streams of type {} ({:?}) at indices {} ({} bytes) and {} ({} bytes) (using {})",
                        dir.stream_type,
                        known_stream_type,
                        old_idx,
                        old_dir.location.data_size,
                        i,
                        dir.location.data_size,
                        i,
                    );
                } else {
                    warn!("Minidump contains multiple streams of unknown type {} at indices {} ({} bytes) and {} ({} bytes) (using {})",
                        dir.stream_type,
                        old_idx,
                        old_dir.location.data_size,
                        i,
                        dir.location.data_size,
                        i,
                    );
                }
            }
        }
        let system_info =
            streams
                .get(&MinidumpSystemInfo::STREAM_TYPE)
                .and_then(|&(_, ref dir)| {
                    location_slice(data.deref(), &dir.location)
                        .ok()
                        .and_then(|bytes| {
                            let all_bytes = data.deref();
                            MinidumpSystemInfo::read(bytes, all_bytes, endian, None).ok()
                        })
                });

        Ok(Minidump {
            data,
            header,
            streams,
            endian,
            system_info,
            _phantom: PhantomData,
        })
    }

    /// Read and parse the specified [`MinidumpStream`][] `S` from the Minidump, if it exists.
    ///
    /// Because Minidump Streams can have totally different formats and meanings, the only
    /// way to coherently access one is by specifying a static type that provides an
    /// interpretation and interface of that format.
    ///
    /// As such, typical usage of this interface is to just statically request every
    /// stream your care about. Depending on what analysis you're trying to perform, you may:
    ///
    /// * Consider it an error for a stream to be missing (using `?` or `unwrap`)
    /// * Branch on the presence of stream to conditionally refine your analysis
    /// * Use a stream's `Default` implementation to make progress (with `unwrap_or_default`)
    ///
    /// ```
    /// use minidump::*;
    ///
    /// fn main() -> Result<(), Error> {
    ///     // Read the minidump from a file
    ///     let mut dump = minidump::Minidump::read_path("../testdata/test.dmp")?;
    ///
    ///     // Statically request (and require) several streams we care about:
    ///     let system_info = dump.get_stream::<MinidumpSystemInfo>()?;
    ///     let exception = dump.get_stream::<MinidumpException>()?;
    ///
    ///     // Combine the contents of the streams to perform more refined analysis
    ///     let crash_reason = exception.get_crash_reason(system_info.os, system_info.cpu);
    ///
    ///     // Conditionally analyze a stream
    ///     if let Ok(threads) = dump.get_stream::<MinidumpThreadList>() {
    ///         // Use `Default` to try to make some progress when a stream is missing.
    ///         // This is especially natural for MinidumpMemoryList because
    ///         // everything needs to handle memory lookups failing anyway.
    ///         let mem = dump.get_stream::<MinidumpMemoryList>().unwrap_or_default();
    ///
    ///         for thread in &threads.threads {
    ///            let stack = thread.stack_memory(&mem);
    ///            // ...
    ///         }
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// Some streams are impossible to fully parse/interpret without the contents
    /// of other streams (for instance, many things require [`MinidumpSystemInfo`][] to interpret
    /// hardware-specific details). As a result, some parsing of the stream may be
    /// further deferred to methods on the Stream type where those dependencies can be provided
    /// (e.g. [`MinidumpException::get_crash_reason`][]).
    ///
    /// Note that the lifetime of the returned stream is bound to the lifetime of the
    /// `Minidump` struct itself and not to the lifetime of the data backing this minidump.
    /// This is a consequence of how this struct relies on [`Deref`][] to access the data.
    ///
    /// ## Currently Supported Streams
    ///
    /// * [`MinidumpAssertion`][]
    /// * [`MinidumpBreakpadInfo`][]
    /// * [`MinidumpCrashpadInfo`][]
    /// * [`MinidumpException`][]
    /// * [`MinidumpLinuxCpuInfo`][]
    /// * [`MinidumpLinuxEnviron`][]
    /// * [`MinidumpLinuxLsbRelease`][]
    /// * [`MinidumpLinuxMaps`][]
    /// * [`MinidumpLinuxProcStatus`][]
    /// * [`MinidumpMacCrashInfo`][]
    /// * [`MinidumpMemoryList`][]
    /// * [`MinidumpMemory64List`][]
    /// * [`MinidumpMemoryInfoList`][]
    /// * [`MinidumpMiscInfo`][]
    /// * [`MinidumpModuleList`][]
    /// * [`MinidumpSystemInfo`][]
    /// * [`MinidumpThreadList`][]
    /// * [`MinidumpThreadNames`][]
    /// * [`MinidumpUnloadedModuleList`][]
    ///
    pub fn get_stream<S>(&'a self) -> Result<S, Error>
    where
        S: MinidumpStream<'a>,
    {
        match self.get_raw_stream(S::STREAM_TYPE) {
            Err(e) => Err(e),
            Ok(bytes) => {
                let all_bytes = self.data.deref();
                S::read(bytes, all_bytes, self.endian, self.system_info.as_ref())
            }
        }
    }

    /// Get a stream of raw data from the minidump.
    ///
    /// This can be used to get the contents of arbitrary minidump streams.
    /// For streams of known types you almost certainly want to use
    /// [`Minidump::get_stream`][] instead.
    ///
    /// Note that the lifetime of the returned stream is bound to the lifetime of the this
    /// `Minidump` struct itself and not to the lifetime of the data backing this minidump.
    /// This is a consequence of how this struct relies on [Deref] to access the data.
    pub fn get_raw_stream(&'a self, stream_type: u32) -> Result<&'a [u8], Error> {
        match self.streams.get(&stream_type) {
            None => Err(Error::StreamNotFound),
            Some(&(_, ref dir)) => {
                let bytes = self.data.deref();
                location_slice(bytes, &dir.location)
            }
        }
    }

    /// A listing of all the streams in the Minidump that this library is *aware* of,
    /// but has no further analysis for.
    ///
    /// If there are multiple copies of the same stream type (which should not happen for
    /// well-formed Minidumps), then only one of them will be yielded, arbitrarily.
    pub fn unimplemented_streams(&self) -> impl Iterator<Item = MinidumpUnimplementedStream> + '_ {
        static UNIMPLEMENTED_STREAMS: [MINIDUMP_STREAM_TYPE; 32] = [
            // Presumably will never have an implementation:
            MINIDUMP_STREAM_TYPE::UnusedStream,
            MINIDUMP_STREAM_TYPE::ReservedStream0,
            MINIDUMP_STREAM_TYPE::ReservedStream1,
            MINIDUMP_STREAM_TYPE::LastReservedStream,
            // Presumably should be implemented:
            MINIDUMP_STREAM_TYPE::ThreadExListStream,
            MINIDUMP_STREAM_TYPE::CommentStreamA,
            MINIDUMP_STREAM_TYPE::CommentStreamW,
            MINIDUMP_STREAM_TYPE::HandleDataStream,
            MINIDUMP_STREAM_TYPE::FunctionTable,
            MINIDUMP_STREAM_TYPE::ThreadInfoListStream,
            MINIDUMP_STREAM_TYPE::HandleOperationListStream,
            MINIDUMP_STREAM_TYPE::TokenStream,
            MINIDUMP_STREAM_TYPE::JavaScriptDataStream,
            MINIDUMP_STREAM_TYPE::SystemMemoryInfoStream,
            MINIDUMP_STREAM_TYPE::ProcessVmCountersStream,
            MINIDUMP_STREAM_TYPE::IptTraceStream,
            // Windows CE streams, very unlikely to be found in the wild.
            // Their contents are documented here: https://docs.microsoft.com/en-us/previous-versions/windows/embedded/ms939618(v=msdn.10)
            MINIDUMP_STREAM_TYPE::ceStreamNull,
            MINIDUMP_STREAM_TYPE::ceStreamSystemInfo,
            MINIDUMP_STREAM_TYPE::ceStreamException,
            MINIDUMP_STREAM_TYPE::ceStreamModuleList,
            MINIDUMP_STREAM_TYPE::ceStreamProcessList,
            MINIDUMP_STREAM_TYPE::ceStreamThreadList,
            MINIDUMP_STREAM_TYPE::ceStreamThreadContextList,
            MINIDUMP_STREAM_TYPE::ceStreamThreadCallStackList,
            MINIDUMP_STREAM_TYPE::ceStreamMemoryVirtualList,
            MINIDUMP_STREAM_TYPE::ceStreamMemoryPhysicalList,
            MINIDUMP_STREAM_TYPE::ceStreamBucketParameters,
            MINIDUMP_STREAM_TYPE::ceStreamProcessModuleMap,
            MINIDUMP_STREAM_TYPE::ceStreamDiagnosisList,
            // non-standard streams (should also be implemented):
            MINIDUMP_STREAM_TYPE::LinuxCmdLine,
            MINIDUMP_STREAM_TYPE::LinuxAuxv,
            MINIDUMP_STREAM_TYPE::LinuxDsoDebug,
        ];
        self.streams.iter().filter_map(|(_, (_, stream))| {
            MINIDUMP_STREAM_TYPE::from_u32(stream.stream_type).and_then(|stream_type| {
                if UNIMPLEMENTED_STREAMS.contains(&stream_type) {
                    return Some(MinidumpUnimplementedStream {
                        stream_type,
                        location: stream.location,
                        vendor: stream_vendor(stream.stream_type),
                    });
                }
                None
            })
        })
    }

    /// A listing of all the streams in the Minidump that this library has no knowledge of.
    ///
    /// If there are multiple copies of the same stream (which should not happen for
    /// well-formed Minidumps), then only one of them will be yielded, arbitrarily.
    pub fn unknown_streams(&self) -> impl Iterator<Item = MinidumpUnknownStream> + '_ {
        self.streams.iter().filter_map(|(_, (_, stream))| {
            if MINIDUMP_STREAM_TYPE::from_u32(stream.stream_type).is_none() {
                return Some(MinidumpUnknownStream {
                    stream_type: stream.stream_type,
                    location: stream.location,
                    vendor: stream_vendor(stream.stream_type),
                });
            }
            None
        })
    }

    /// A listing of all the streams in the Minidump.
    ///
    /// If there are multiple copies of the same stream (which should not happen for
    /// well-formed Minidumps), then only one of them will be yielded, arbitrarily.
    pub fn all_streams(&self) -> impl Iterator<Item = &md::MINIDUMP_DIRECTORY> + '_ {
        self.streams.iter().map(|(_, (_, stream))| stream)
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

fn stream_vendor(stream_type: u32) -> &'static str {
    if stream_type <= MINIDUMP_STREAM_TYPE::LastReservedStream as u32 {
        "Official"
    } else {
        match stream_type & 0xFFFF0000 {
            0x4767_0000 => "Google Extension",
            0x4d7a_0000 => "Mozilla Extension",
            _ => "Unknown Extension",
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use md::GUID;
    use minidump_common::format::{PlatformId, ProcessorArchitecture};
    use minidump_synth::{
        self, AnnotationValue, CrashpadInfo, DumpString, Exception, Memory,
        MemoryInfo as SynthMemoryInfo, MiscFieldsBuildString, MiscFieldsPowerInfo,
        MiscFieldsProcessTimes, MiscFieldsTimeZone, MiscInfo5Fields, MiscStream,
        Module as SynthModule, ModuleCrashpadInfo, SimpleStream, SynthMinidump, SystemInfo, Thread,
        ThreadName, UnloadedModule as SynthUnloadedModule, STOCK_VERSION_INFO,
    };
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
    fn test_thread_names() {
        let good_thread_id = 17;
        let corrupt_thread_id = 123;

        let good_name = DumpString::new("MyCoolThread", Endian::Little);
        // No corrupt name, will dangle

        let good_thread_name_entry =
            ThreadName::new(Endian::Little, good_thread_id, Some(&good_name));
        let corrupt_thread_name_entry = ThreadName::new(Endian::Little, corrupt_thread_id, None);

        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_thread_name(good_thread_name_entry)
            .add_thread_name(corrupt_thread_name_entry)
            .add(good_name);

        let dump = read_synth_dump(dump).unwrap();
        let thread_names = dump.get_stream::<MinidumpThreadNames>().unwrap();
        assert_eq!(thread_names.names.len(), 1);
        assert_eq!(
            &*thread_names.get_name(good_thread_id).unwrap(),
            "MyCoolThread"
        );
        assert_eq!(thread_names.get_name(corrupt_thread_id), None);
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
        assert_eq!(
            modules[0].code_identifier().unwrap(),
            CodeId::new("B1054D2Aada542bd".to_string())
        );
        assert_eq!(modules[0].debug_file().unwrap(), "c:\\foo\\file.pdb");
        assert_eq!(
            modules[0].debug_identifier().unwrap(),
            DebugId::from_breakpad("ABCD1234F00DBEEF01020304050607081").unwrap()
        );
    }

    #[test]
    fn test_module_list_pdb20() {
        let name = DumpString::new("single module", Endian::Little);
        let cv_record = Section::with_endian(Endian::Little)
            .D32(md::CvSignature::Pdb20 as u32) // cv_signature
            .D32(0x0) // cv_offset
            .D32(0xabcd1234) // signature
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
        assert_eq!(
            modules[0].code_identifier().unwrap(),
            CodeId::new("B1054D2Aada542bd".to_string())
        );
        assert_eq!(modules[0].debug_file().unwrap(), "c:\\foo\\file.pdb");
        assert_eq!(
            modules[0].debug_identifier().unwrap(),
            DebugId::from_pdb20(0xabcd1234, 1)
        );
    }

    #[test]
    fn test_unloaded_module_list() {
        let name = DumpString::new("single module", Endian::Little);
        let module = SynthUnloadedModule::new(
            Endian::Little,
            0xa90206ca83eb2852,
            0xada542bd,
            &name,
            0xb1054d2a,
            0x34571371,
        );
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_unloaded_module(module)
            .add(name);
        let dump = read_synth_dump(dump).unwrap();
        let module_list = dump.get_stream::<MinidumpUnloadedModuleList>().unwrap();
        let modules = module_list.iter().collect::<Vec<_>>();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].base_address(), 0xa90206ca83eb2852);
        assert_eq!(modules[0].size(), 0xada542bd);
        assert_eq!(modules[0].code_file(), "single module");
        // time_date_stamp and size_of_image concatenated
        assert_eq!(
            modules[0].code_identifier().unwrap(),
            CodeId::new("B1054D2Aada542bd".to_string())
        );
    }

    #[test]
    fn test_memory_info() {
        let info1_alloc_protection = md::MemoryProtection::PAGE_GUARD;
        let info1_protection = md::MemoryProtection::PAGE_EXECUTE_READ;
        let info1_state = md::MemoryState::MEM_FREE;
        let info1_ty = md::MemoryType::MEM_MAPPED;
        let info1 = SynthMemoryInfo::new(
            Endian::Little,
            0xa90206ca83eb2852,
            0xa802064a83eb2752,
            info1_alloc_protection.bits(),
            0xf80e064a93eb2356,
            info1_state.bits(),
            info1_protection.bits(),
            info1_ty.bits(),
        );

        let info2_alloc_protection = md::MemoryProtection::PAGE_EXECUTE_READ;
        let info2_protection = md::MemoryProtection::PAGE_READONLY;
        let info2_state = md::MemoryState::MEM_COMMIT;
        let info2_ty = md::MemoryType::MEM_PRIVATE;
        let info2 = SynthMemoryInfo::new(
            Endian::Little,
            0xd70206ca83eb2852,
            0xb802064383eb2752,
            info2_alloc_protection.bits(),
            0xe80e064a93eb2356,
            info2_state.bits(),
            info2_protection.bits(),
            info2_ty.bits(),
        );
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_memory_info(info1)
            .add_memory_info(info2);

        let dump = read_synth_dump(dump).unwrap();

        // Read both kinds of info to test this path on UnifiedMemoryInfo
        let info_list = dump.get_stream::<MinidumpMemoryInfoList>().ok();
        let maps = dump.get_stream::<MinidumpLinuxMaps>().ok();
        assert!(info_list.is_some());
        assert!(maps.is_none());

        let unified_info = UnifiedMemoryInfoList::new(info_list, maps).unwrap();
        let info_list = unified_info.info().unwrap();
        assert!(unified_info.maps().is_none());

        // Assert that unified and the info_list agree
        for (info, unified) in info_list.iter().zip(unified_info.iter()) {
            if let UnifiedMemoryInfo::Info(info2) = unified {
                assert_eq!(info, info2);
            } else {
                unreachable!();
            }
        }

        let infos = info_list.iter().collect::<Vec<_>>();

        assert_eq!(infos.len(), 2);

        assert_eq!(infos[0].raw.base_address, 0xa90206ca83eb2852);
        assert_eq!(infos[0].raw.allocation_base, 0xa802064a83eb2752);
        assert_eq!(
            infos[0].raw.allocation_protection,
            info1_alloc_protection.bits()
        );
        assert_eq!(infos[0].raw.region_size, 0xf80e064a93eb2356);
        assert_eq!(infos[0].raw.state, info1_state.bits());
        assert_eq!(infos[0].raw.protection, info1_protection.bits());
        assert_eq!(infos[0].raw._type, info1_ty.bits());

        assert_eq!(infos[0].allocation_protection, info1_alloc_protection);
        assert_eq!(infos[0].protection, info1_protection);
        assert_eq!(infos[0].state, info1_state);
        assert_eq!(infos[0].ty, info1_ty);
        assert!(infos[0].is_executable());

        assert_eq!(infos[1].raw.base_address, 0xd70206ca83eb2852);
        assert_eq!(infos[1].raw.allocation_base, 0xb802064383eb2752);
        assert_eq!(
            infos[1].raw.allocation_protection,
            info2_alloc_protection.bits()
        );
        assert_eq!(infos[1].raw.region_size, 0xe80e064a93eb2356);
        assert_eq!(infos[1].raw.state, info2_state.bits());
        assert_eq!(infos[1].raw.protection, info2_protection.bits());
        assert_eq!(infos[1].raw._type, info2_ty.bits());

        assert_eq!(infos[1].allocation_protection, info2_alloc_protection);
        assert_eq!(infos[1].protection, info2_protection);
        assert_eq!(infos[1].state, info2_state);
        assert_eq!(infos[1].ty, info2_ty);
        assert!(!infos[1].is_executable());
    }

    #[test]
    fn test_linux_maps() {
        // Whitespace intentionally wonky to test robustness
        let input = b"

 a90206ca83eb2852-b90206ca83eb3852 r-xp  10bac9000 fd:05 1196511 /usr/lib64/libtdb1.so\x20\x20
c70206ca83eb2852-de0206ca83eb2852  -w-s  10bac9000 fd:05 1196511 /usr/lib64/libtdb2.so  (deleted)


";

        let dump = SynthMinidump::with_endian(Endian::Little).set_linux_maps(input);
        let dump = read_synth_dump(dump).unwrap();

        // Read both kinds of info to test this path on UnifiedMemoryInfo
        let info_list = dump.get_stream::<MinidumpMemoryInfoList>().ok();
        let maps = dump.get_stream::<MinidumpLinuxMaps>().ok();
        assert!(info_list.is_none());
        assert!(maps.is_some());

        let unified_info = UnifiedMemoryInfoList::new(info_list, maps).unwrap();
        let maps = unified_info.maps().unwrap();
        assert!(unified_info.info().is_none());

        // Assert that unified and the maps agree
        for (info, unified) in maps.iter().zip(unified_info.iter()) {
            if let UnifiedMemoryInfo::Map(info2) = unified {
                assert_eq!(info, info2);
            } else {
                unreachable!();
            }
        }

        let maps = maps.iter().collect::<Vec<_>>();
        assert_eq!(maps.len(), 2);

        assert_eq!(maps[0].base_address, 0xa90206ca83eb2852);
        assert_eq!(maps[0].final_address, 0xb90206ca83eb3852);
        assert_eq!(
            maps[0].kind,
            MinidumpLinuxMapKind::File(Cow::Borrowed(LinuxOsStr::from_bytes(
                b"/usr/lib64/libtdb1.so"
            )))
        );
        assert!(maps[0].is_read);
        assert!(!maps[0].is_write);
        assert!(maps[0].is_exec);
        assert!(maps[0].is_private);
        assert!(!maps[0].is_shared);
        assert!(maps[0].is_executable());

        assert_eq!(maps[1].base_address, 0xc70206ca83eb2852);
        assert_eq!(maps[1].final_address, 0xde0206ca83eb2852);
        assert_eq!(
            maps[1].kind,
            MinidumpLinuxMapKind::DeletedFile(Cow::Borrowed(LinuxOsStr::from_bytes(
                b"/usr/lib64/libtdb2.so"
            )))
        );
        assert!(!maps[1].is_read);
        assert!(maps[1].is_write);
        assert!(!maps[1].is_exec);
        assert!(!maps[1].is_private);
        assert!(maps[1].is_shared);
        assert!(!maps[1].is_executable());

        let mut unified_infos = unified_info.by_addr();

        assert!(matches!(unified_infos.next(), Some(UnifiedMemoryInfo::Map(m)) if m == maps[0]));
        assert!(matches!(unified_infos.next(), Some(UnifiedMemoryInfo::Map(m)) if m == maps[1]));
    }

    #[test]
    fn test_linux_map_parse() {
        use MinidumpLinuxMapKind::*;

        let parse = |input| {
            let string = LinuxOsStr::from_bytes(input);
            MinidumpLinuxMapInfo::from_line(string)
        };

        // Whitespace intentionally wonky to test parser robustness

        {
            // Normal file
            let map = parse(b"  10a00-10b00 r-xp  10bac9000 fd:05 1196511 /usr/lib64/libtdb1.so  ");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(
                map.kind,
                File(Cow::Borrowed(LinuxOsStr::from_bytes(
                    b"/usr/lib64/libtdb1.so"
                )))
            );

            assert!(map.is_read);
            assert!(!map.is_write);
            assert!(map.is_exec);
            assert!(map.is_executable());
            assert!(map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Deleted file (also some whitespace in the file name)
            let map = parse(b"ffffffffff600000-ffffffffff601000 -wxs  10bac9000 fd:05 1196511  /usr/lib64/ libtdb1.so   (deleted) ");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0xffffffffff600000);
            assert_eq!(map.final_address, 0xffffffffff601000);
            assert_eq!(
                map.memory_range(),
                Some(Range::new(0xffffffffff600000, 0xffffffffff601000))
            );
            assert_eq!(
                map.kind,
                DeletedFile(Cow::Borrowed(LinuxOsStr::from_bytes(
                    b"/usr/lib64/ libtdb1.so"
                )))
            );

            assert!(!map.is_read);
            assert!(map.is_write);
            assert!(map.is_exec);
            assert!(map.is_executable());
            assert!(!map.is_private);
            assert!(map.is_shared);
        }

        {
            // Stack
            let map = parse(b"10a00-10b00 -------  10bac9000 fd:05 1196511  [stack] ");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(map.kind, MainThreadStack);

            assert!(!map.is_read);
            assert!(!map.is_write);
            assert!(!map.is_exec);
            assert!(!map.is_executable());
            assert!(!map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Stack with tid
            let map = parse(b"10a00-10b00 -------  10bac9000 fd:05 1196511  [stack:1234567] ");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(map.kind, Stack(1234567));

            assert!(!map.is_read);
            assert!(!map.is_write);
            assert!(!map.is_exec);
            assert!(!map.is_executable());
            assert!(!map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Heap
            let map = parse(b"10a00-10b00 --  10bac9000 fd:05 1196511  [heap]");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(map.kind, Heap);

            assert!(!map.is_read);
            assert!(!map.is_write);
            assert!(!map.is_exec);
            assert!(!map.is_executable());
            assert!(!map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Vdso
            let map = parse(b"10a00-10b00 r-wx-  10bac9000 fd:05 1196511  [vdso]");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(map.kind, Vdso);

            assert!(map.is_read);
            assert!(map.is_write);
            assert!(map.is_exec);
            assert!(map.is_executable());
            assert!(!map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Unknown Special
            let map = parse(b"10a00-10b00 r-wx-  10bac9000 fd:05 1196511  [asdfasd]");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(
                map.kind,
                UnknownSpecial(Cow::Borrowed(LinuxOsStr::from_bytes(b"[asdfasd]")))
            );

            assert!(map.is_read);
            assert!(map.is_write);
            assert!(map.is_exec);
            assert!(map.is_executable());
            assert!(!map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Anonymous
            let map = parse(b"10a00-10b00 -r-  10bac9000 fd:05 1196511  ");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(map.kind, AnonymousMap);

            assert!(map.is_read);
            assert!(!map.is_write);
            assert!(!map.is_exec);
            assert!(!map.is_executable());
            assert!(!map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Truncated defaults to anonymous
            let map = parse(b"10a00-10b00");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0x10a00);
            assert_eq!(map.final_address, 0x10b00);
            assert_eq!(map.memory_range(), Some(Range::new(0x10a00, 0x10b00)));
            assert_eq!(map.kind, AnonymousMap);

            assert!(!map.is_read);
            assert!(!map.is_write);
            assert!(!map.is_exec);
            assert!(!map.is_executable());
            assert!(!map.is_private);
            assert!(!map.is_shared);
        }

        {
            // Reversed ranges result in None for memory_range()
            let map = parse(b"fffff-10000");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0xfffff);
            assert_eq!(map.final_address, 0x10000);
            assert_eq!(map.memory_range(), None);
        }

        {
            // Equal ranges are valid
            let map = parse(b"fffff-fffff");
            let map = map.unwrap();

            assert_eq!(map.base_address, 0xfffff);
            assert_eq!(map.final_address, 0xfffff);
            assert_eq!(map.memory_range(), Some(Range::new(0xfffff, 0xfffff)));
        }

        {
            // blank line
            let map = parse(b"");
            assert!(map.is_err());

            let map = parse(b"   ");
            assert!(map.is_err());
        }

        {
            // bad addresses
            let map = parse(b"  -10b00 r-xp  10bac9000 fd:05 1196511 /usr/lib64/libtdb1.so  ");
            assert!(map.is_err());

            let map = parse(b"  10b00- r-xp  10bac9000 fd:05 1196511 /usr/lib64/libtdb1.so  ");
            assert!(map.is_err());

            let map = parse(b"  10b00 r-xp  10bac9000 fd:05 1196511 /usr/lib64/libtdb1.so  ");
            assert!(map.is_err());
        }

        {
            // bad [stack:<tid>]
            let map = parse(b"  -10b00 r-xp  10bac9000 fd:05 1196511 [stack:] ");
            assert!(map.is_err());

            let map = parse(b"  -10b00 r-xp  10bac9000 fd:05 1196511 [stack:a10] ");
            assert!(map.is_err());
        }
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
    fn test_memory64_list() {
        const CONTENTS0: &[u8] = b"memory_contents";
        const CONTENTS1: &[u8] = b"another_block";
        let memory0 = Memory::with_section(
            Section::with_endian(Endian::Little).append_bytes(CONTENTS0),
            0x309d68010bd21b2c,
        );
        let memory1 = Memory::with_section(
            Section::with_endian(Endian::Little).append_bytes(CONTENTS1),
            0x1234,
        );
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_memory64(memory0)
            .add_memory64(memory1);
        let dump = read_synth_dump(dump).unwrap();
        let memory_list = dump.get_stream::<MinidumpMemory64List<'_>>().unwrap();
        let regions = memory_list.iter().collect::<Vec<_>>();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].base_address, 0x309d68010bd21b2c);
        assert_eq!(regions[0].size, CONTENTS0.len() as u64);
        assert_eq!(&regions[0].bytes, &CONTENTS0);

        assert_eq!(regions[1].base_address, 0x1234);
        assert_eq!(regions[1].size, CONTENTS1.len() as u64);
        assert_eq!(&regions[1].bytes, &CONTENTS1);
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
    fn test_memory_overflow() {
        let memory1 = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(0, 2),
            u64::MAX,
        );
        let dump = SynthMinidump::with_endian(Endian::Little).add_memory(memory1);
        let dump = read_synth_dump(dump).unwrap();
        let memory_list = dump.get_stream::<MinidumpMemoryList<'_>>().unwrap();
        let regions = memory_list.iter().collect::<Vec<_>>();
        assert_eq!(regions.len(), 1);
        assert!(regions[0].get_memory_at_address::<u8>(u64::MAX).is_none());
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
            systemtime_from_timestamp(PROCESS_TIMES.process_create_time as u64).unwrap()
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
            systemtime_from_timestamp(PROCESS_TIMES.process_create_time as u64).unwrap(),
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
            systemtime_from_timestamp(PROCESS_TIMES.process_create_time as u64).unwrap()
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
            modules[0].code_identifier().unwrap(),
            CodeId::new("000102030405060708090a0b0c0d0e0f1011121314151617".to_string())
        );
        assert_eq!(modules[0].debug_file().unwrap(), "module 1");
        // The first 16 bytes of the build ID interpreted as a GUID.
        assert_eq!(
            modules[0].debug_identifier().unwrap(),
            DebugId::from_breakpad("030201000504070608090A0B0C0D0E0F0").unwrap()
        );

        assert_eq!(modules[1].base_address(), 0x200000000);
        assert_eq!(modules[1].code_file(), "module 2");
        // The full build ID.
        assert_eq!(
            modules[1].code_identifier().unwrap(),
            CodeId::new("0001020304050607".to_string())
        );
        assert_eq!(modules[1].debug_file().unwrap(), "module 2");
        // The first 16 bytes of the build ID interpreted as a GUID, padded with
        // zeroes in this case.
        assert_eq!(
            modules[1].debug_identifier().unwrap(),
            DebugId::from_breakpad("030201000504070600000000000000000").unwrap()
        );
    }

    #[test]
    fn test_os() {
        let dump = SynthMinidump::with_endian(Endian::Little).add_system_info(
            SystemInfo::new(Endian::Little).set_platform_id(PlatformId::MacOs as u32),
        );

        let dump = read_synth_dump(dump).unwrap();
        let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        assert_eq!(system_info.os, Os::MacOs);
    }

    #[test]
    fn test_macos_ids() {
        let name = DumpString::new("macos module", Endian::Little);
        let cv_record = Section::with_endian(Endian::Little)
            // signature
            .D32(md::CvSignature::Pdb70 as u32)
            // signature, a GUID
            .D32(0xaabbccdd)
            .D16(0xeeff)
            .D16(0x0011)
            .append_bytes(b"\x22\x33\x44\x55\x66\x77\x88\x99")
            // age, breakpad writes 0
            .D32(0)
            // pdb_file_name
            .append_bytes(b"helpivecrashed.dylib\0");
        let module = SynthModule::new(
            Endian::Little,
            0x100000000,
            0x4000,
            &name,
            0xb1054d2a,
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        )
        .cv_record(&cv_record);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_system_info(
                SystemInfo::new(Endian::Little).set_platform_id(PlatformId::MacOs as u32),
            )
            .add_module(module)
            .add(name)
            .add(cv_record);
        let dump = read_synth_dump(dump).unwrap();
        let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        assert_eq!(system_info.os, Os::MacOs);

        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        let modules = module_list.iter().collect::<Vec<_>>();
        assert_eq!(modules.len(), 1);
        // should be the uuid stored in cv record
        assert_eq!(
            modules[0].code_identifier().unwrap(),
            CodeId::new("AABBCCDDEEFF00112233445566778899".to_owned())
        );
        // should match code identifier, but with the age appended to it
        assert_eq!(
            modules[0].debug_identifier().unwrap(),
            DebugId::from_breakpad("AABBCCDDEEFF001122334455667788990").unwrap()
        );
        assert_eq!(modules[0].code_file(), "macos module");
        assert_eq!(modules[0].debug_file().unwrap(), "helpivecrashed.dylib");
    }

    #[test]
    fn test_windows_code_id_no_cv() {
        let name = DumpString::new("windows module", Endian::Little);
        let module = SynthModule::new(
            Endian::Little,
            0x100000000,
            0x4000, // size of image
            &name,
            0xb105_4d2a, // datetime
            0x34571371,
            Some(&STOCK_VERSION_INFO),
        );
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_system_info(
                SystemInfo::new(Endian::Little)
                    .set_platform_id(PlatformId::VER_PLATFORM_WIN32_NT as u32),
            )
            .add_module(module)
            .add(name);
        let dump = read_synth_dump(dump).unwrap();
        let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        assert_eq!(system_info.os, Os::Windows);

        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        let modules = module_list.iter().collect::<Vec<_>>();
        assert_eq!(modules.len(), 1);
        // should match datetime + size of image
        assert_eq!(
            modules[0].code_identifier().unwrap(),
            CodeId::new("B1054D2A4000".to_owned())
        );
    }

    #[test]
    fn test_null_id() {
        // Add a module with an ELF build id of nothing but zeros
        let name1 = DumpString::new("module 1", Endian::Little);
        const MODULE1_BUILD_ID: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
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

        // Add a module with a PDB70 build id of nothing but zeros
        let name2 = DumpString::new("module 2", Endian::Little);
        let cv_record2 = Section::with_endian(Endian::Little)
            // signature
            .D32(md::CvSignature::Pdb70 as u32)
            // signature, a GUID
            .D32(0x0)
            .D16(0x0)
            .D16(0x0)
            .append_bytes(b"\0\0\0\0\0\0\0\0")
            // age, breakpad writes 0
            .D32(0)
            // pdb_file_name
            .append_bytes(b"\0");
        let module2 = SynthModule::new(
            Endian::Little,
            0x100000000,
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

        assert!(modules[0].debug_identifier().is_none());
        assert!(modules[1].debug_identifier().is_none());
    }

    #[test]
    fn test_thread_list_x86() {
        let context = minidump_synth::x86_context(Endian::Little, 0xabcd1234, 0x1010);
        let stack = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(0, 0x1000),
            0x1000,
        );
        let arch = md::ProcessorArchitecture::PROCESSOR_ARCHITECTURE_INTEL as u16;
        let system_info = SystemInfo::new(Endian::Little).set_processor_architecture(arch);
        let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_thread(thread)
            .add(context)
            .add_memory(stack)
            .add_system_info(system_info);
        let dump = read_synth_dump(dump).unwrap();
        let mut thread_list = dump.get_stream::<MinidumpThreadList<'_>>().unwrap();
        let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        let misc_info = dump.get_stream::<MinidumpMiscInfo>().ok();
        assert_eq!(thread_list.threads.len(), 1);
        let mut thread = thread_list.threads.pop().unwrap();
        assert_eq!(thread.raw.thread_id, 0x1234);
        let context = thread
            .context(&system_info, misc_info.as_ref())
            .expect("Should have a thread context");
        match &context.raw {
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
            minidump_synth::amd64_context(Endian::Little, 0x1234abcd1234abcd, 0x1000000010000000);
        let stack = Memory::with_section(
            Section::with_endian(Endian::Little).append_repeated(0, 0x1000),
            0x1000000010000000,
        );
        let arch = md::ProcessorArchitecture::PROCESSOR_ARCHITECTURE_AMD64 as u16;
        let system_info = SystemInfo::new(Endian::Little).set_processor_architecture(arch);
        let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_thread(thread)
            .add(context)
            .add_memory(stack)
            .add_system_info(system_info);
        let dump = read_synth_dump(dump).unwrap();
        let mut thread_list = dump.get_stream::<MinidumpThreadList<'_>>().unwrap();
        let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        let misc_info = dump.get_stream::<MinidumpMiscInfo>().ok();
        assert_eq!(thread_list.threads.len(), 1);
        let mut thread = thread_list.threads.pop().unwrap();
        assert_eq!(thread.raw.thread_id, 0x1234);
        let context = thread
            .context(&system_info, misc_info.as_ref())
            .expect("Should have a thread context");
        match &context.raw {
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

    #[test]
    fn test_exception_x86() {
        // Defaults to x86
        let system_info = SystemInfo::new(Endian::Little);

        let mut exception = Exception::new(Endian::Little);

        // Check that we clear the erroneous high bits for 32-bit
        exception.exception_record.exception_address = 0xf0e1_d2c3_b4a5_9687;
        // FIXME: test other fields too

        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_system_info(system_info)
            .add_exception(exception);

        let dump = read_synth_dump(dump).unwrap();

        let system_stream = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        let exception_stream = dump.get_stream::<MinidumpException>().unwrap();
        assert_eq!(
            exception_stream.get_crash_address(system_stream.os, system_stream.cpu),
            0xb4a5_9687
        );
    }

    #[test]
    fn test_exception_x64() {
        // Defaults to x86
        let system_info = SystemInfo::new(Endian::Little)
            .set_processor_architecture(ProcessorArchitecture::PROCESSOR_ARCHITECTURE_AMD64 as u16);

        let mut exception = Exception::new(Endian::Little);

        // Check that we don't truncate this on 64-bit
        exception.exception_record.exception_address = 0xf0e1_d2c3_b4a5_9687;
        // FIXME: test other fields too

        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_system_info(system_info)
            .add_exception(exception);

        let dump = read_synth_dump(dump).unwrap();

        let system_stream = dump.get_stream::<MinidumpSystemInfo>().unwrap();
        let exception_stream = dump.get_stream::<MinidumpException>().unwrap();
        assert_eq!(
            exception_stream.get_crash_address(system_stream.os, system_stream.cpu),
            0xf0e1_d2c3_b4a5_9687
        );
    }

    #[test]
    fn test_fuzzed_oom() {
        // https://github.com/rust-minidump/rust-minidump/issues/381
        let data = b"MDMP\x93\xa7\x00\x00\x00\xffffdYfffff@\n\nfp\n\xbb\xff\xff\xff\n\xff\n";
        assert!(Minidump::read(data.as_ref()).is_err());

        // https://github.com/getsentry/symbolic/issues/478
        let data = b"MDMP\x93\xa7\x00\x00\r\x00\x00\x00 \xff\xff\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(Minidump::read(data.as_ref()).is_err());
    }

    #[test]
    fn test_empty_module() {
        let name = DumpString::new("/SYSV00000000 (deleted)", Endian::Little);
        let module = SynthModule::new(
            Endian::Little,
            0x7f602915e000,
            0x26000,
            &name,
            0x0,
            0x0,
            // All of these are completely zeroed out in the wild.
            Some(&md::VS_FIXEDFILEINFO {
                signature: 0,
                struct_version: 0,
                file_version_hi: 0,
                file_version_lo: 0,
                product_version_hi: 0,
                product_version_lo: 0,
                file_flags_mask: 0,
                file_flags: 0,
                file_os: 0,
                file_type: 0,
                file_subtype: 0,
                file_date_hi: 0,
                file_date_lo: 0,
            }),
        );
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_module(module)
            .add(name);
        let dump = read_synth_dump(dump).unwrap();
        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        let modules = module_list.iter().collect::<Vec<_>>();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].code_identifier(), None);
        assert_eq!(modules[0].debug_identifier(), None);
        assert_eq!(modules[0].code_file(), "/SYSV00000000 (deleted)");
        assert_eq!(modules[0].debug_file(), None);
        assert_eq!(modules[0].raw.base_of_image, 0x7f602915e000);
        assert_eq!(modules[0].raw.size_of_image, 0x26000);
    }
}
