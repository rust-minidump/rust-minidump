//! Minidump structure definitions.
//!
//! Types defined here should match those defined in [Microsoft's headers][msdn]. Additionally
//! some [Breakpad][breakpad] and [Crashpad][crashpad] extension types are defined here and should
//! match the definitions from those projects.
//!
//! [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/
//! [breakpad]: https://chromium.googlesource.com/breakpad/breakpad/
//! [crashpad]: https://chromium.googlesource.com/crashpad/crashpad/+/master/README.md
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use scroll::{Endian, Pread};

/// An offset from the start of the minidump file.
pub type RVA = u32;

/// The 4-byte magic number at the start of a minidump file.
///
/// In little endian this spells 'MDMP'.
pub const MINIDUMP_SIGNATURE: u32 = 0x504d444d;

/// The version of the minidump format.
pub const MINIDUMP_VERSION: u32 = 42899;

/// The header at the start of a minidump file.
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_header
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_HEADER {
    /// This should be [`MINIDUMP_SIGNATURE`][signature].
    ///
    /// [signature]: constant.MINIDUMP_SIGNATURE.html
    pub signature: u32,
    /// This should be [`MINIDUMP_VERSION`][version].
    ///
    /// [version]: constant.MINIDUMP_VERSION.html
    pub version: u32,
    /// The number of streams contained in the stream directory.
    pub stream_count: u32,
    /// The offset to the stream directory within the minidump. This usually points
    /// to immediately after the header. The stream directory is an array containing
    /// `stream_count` [`MINIDUMP_DIRECTORY`][dir] entries.
    ///
    /// [dir]: struct.MINIDUMP_DIRECTORY.html
    pub stream_directory_rva: RVA,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub flags: u64,
}

/// A location within a minidump file comprised of an offset and a size.
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_location_descriptor
#[derive(Copy, Default, Clone, Pread, SizeWith)]
pub struct MINIDUMP_LOCATION_DESCRIPTOR {
    /// The size of this data.
    pub data_size: u32,
    /// The offset to this data within the minidump file.
    pub rva: RVA,
}

/// A range of memory contained within a minidump consisting of a base address and a
/// location descriptor.
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_memory_descriptor
#[derive(Copy, Clone, Default, Pread, SizeWith)]
pub struct MINIDUMP_MEMORY_DESCRIPTOR {
    /// The base address of this memory range from the process.
    pub start_of_memory_range: u64,
    /// The offset and size of the actual bytes of memory contained in this dump.
    pub memory: MINIDUMP_LOCATION_DESCRIPTOR,
}

/// Information about a data stream contained in a minidump file.
///
/// The minidump header contains a pointer to a list of these structs which allows locating
/// specific streams in the dump.
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_directory
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_DIRECTORY {
    /// This is usually one of the values in [`MINIDUMP_STREAM_TYPE`][ty] for known stream types,
    /// but user streams can have arbitrary values.
    ///
    /// [ty]: enum.MINIDUMP_STREAM_TYPE.html
    pub stream_type: u32,
    /// The location of the stream contents within the dump.
    pub location: MINIDUMP_LOCATION_DESCRIPTOR,
}

/// The types of known minidump data streams.
///
/// Most of these values are derived from the [Microsoft enum][msdn] of the same name, but
/// the values after `LastReservedStream` are Breakpad and Crashpad extensions.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ne-minidumpapiset-_minidump_stream_type
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum MINIDUMP_STREAM_TYPE {
    /// An unused stream directory entry
    UnusedStream = 0,
    ReservedStream0 = 1,
    ReservedStream1 = 2,
    /// The list of threads from the process
    ///
    /// See [`MINIDUMP_THREAD`](struct.MINIDUMP_THREAD.html).
    ///
    /// Microsoft declares a [`MINIDUMP_THREAD_LIST`][list] struct which is the actual format
    /// of this stream, but it is a variable-length struct so no matching definition is provided
    /// in this crate.
    ///
    /// [list]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_thread_list
    ThreadListStream = 3,
    /// The list of executable modules from the process
    ///
    /// See [`MINIDUMP_MODULE`](struct.MINIDUMP_MODULE.html).
    ///
    /// Microsoft declares a [`MINIDUMP_MODULE_LIST`][list] struct which is the actual format
    /// of this stream, but it is a variable-length struct so no matching definition is provided
    /// in this crate.
    ///
    /// [list]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_module_list
    ModuleListStream = 4,
    /// The list of memory regions from the process contained within this dump
    ///
    /// See [`MINIDUMP_MEMORY_DESCRIPTOR`](struct.MINIDUMP_MEMORY_DESCRIPTOR.html).
    ///
    /// Microsoft declares a [`MINIDUMP_MEMORY_LIST`][list] struct which is the actual format
    /// of this stream, but it is a variable-length struct so no matching definition is provided
    /// in this crate.
    ///
    /// [list]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_memory_list
    MemoryListStream = 5,
    /// Information about the exception that caused the process to exit
    ///
    /// See [`MINIDUMP_EXCEPTION_STREAM`](struct.MINIDUMP_EXCEPTION_STREAM.html).
    ExceptionStream = 6,
    /// System information
    ///
    /// See [`MINIDUMP_SYSTEM_INFO`](struct.MINIDUMP_SYSTEM_INFO.html).
    SystemInfoStream = 7,
    ThreadExListStream = 8,
    Memory64ListStream = 9,
    CommentStreamA = 10,
    CommentStreamW = 11,
    HandleDataStream = 12,
    FunctionTable = 13,
    UnloadedModuleListStream = 14,
    /// Miscellaneous process and system information
    ///
    /// See ['MINIDUMP_MISC_INFO'][struct.MINIDUMP_MISC_INFO.html).
    MiscInfoStream = 15,
    /// Information about memory regions from the process
    ///
    /// See ['MINIDUMP_MEMORY_INFO_LIST'][struct.MINIDUMP_MEMORY_INFO_LIST.html).
    MemoryInfoListStream = 16,
    ThreadInfoListStream = 17,
    HandleOperationListStream = 18,
    TokenStream = 19,
    JavaScriptDataStream = 20,
    SystemMemoryInfoStream = 21,
    ProcessVmCountersStream = 22,
    IptTraceStream = 23,
    ThreadNamesStream = 24,
    ceStreamNull = 25,
    ceStreamSystemInfo = 26,
    ceStreamException = 27,
    ceStreamModuleList = 28,
    ceStreamProcessList = 29,
    ceStreamThreadList = 30,
    ceStreamThreadContextList = 31,
    ceStreamThreadCallStackList = 32,
    ceStreamMemoryVirtualList = 33,
    ceStreamMemoryPhysicalList = 34,
    ceStreamBucketParameters = 35,
    ceStreamProcessModuleMap = 36,
    ceStreamDiagnosisList = 37,
    LastReservedStream = 0x0000ffff,
    /* Breakpad extension types.  0x4767 = "Gg" */
    /// Additional process information (Breakpad extension)
    ///
    /// See ['MINIDUMP_BREAKPAD_INFO'][struct.MINIDUMP_BREAKPAD_INFO.html).
    BreakpadInfoStream = 0x47670001,
    /// Assertion information (Breakpad extension)
    ///
    /// See ['MINIDUMP_ASSERTION_INFO'][struct.MINIDUMP_ASSERTION_INFO.html).
    AssertionInfoStream = 0x47670002,
    /* These are additional minidump stream values which are specific to
     * the linux breakpad implementation. */
    /// The contents of /proc/cpuinfo from a Linux system
    LinuxCpuInfo = 0x47670003,
    /// The contents of /proc/self/status from a Linux system
    LinuxProcStatus = 0x47670004,
    /// The contents of /etc/lsb-release from a Linux system
    LinuxLsbRelease = 0x47670005,
    /// The contents of /proc/self/cmdline from a Linux system
    LinuxCmdLine = 0x47670006,
    /// The contents of /proc/self/environ from a Linux system
    LinuxEnviron = 0x47670007,
    /// The contents of /proc/self/auxv from a Linux system
    LinuxAuxv = 0x47670008,
    /// The contents of /proc/self/maps from a Linux system
    LinuxMaps = 0x47670009,
    /// Information from the Linux dynamic linker useful for writing core dumps
    ///
    /// See ['DSO_DEBUG_64'](struct.DSO_DEBUG_64.html) and
    /// ['DSO_DEBUG_32'](struct.DSO_DEBUG_32.html).
    LinuxDsoDebug = 0x4767000A,
    /* Crashpad extension types. 0x4350 = "CP"
     * See Crashpad's minidump/minidump_extensions.h. */
    CrashpadInfoStream = 0x43500001,
}

impl Into<u32> for MINIDUMP_STREAM_TYPE {
    fn into(self) -> u32 {
        self as u32
    }
}

/// Information about a single module (executable or shared library) from a minidump
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_module
#[derive(Clone, Default, Pread, SizeWith)]
pub struct MINIDUMP_MODULE {
    /// The base address of the executable image in memory.
    pub base_of_image: u64,
    /// The size of the executable image in memory, in bytes.
    pub size_of_image: u32,
    /// The checksum value from the PE headers.
    pub checksum: u32,
    /// The timestamp value from the PE headers in `time_t` format.
    pub time_date_stamp: u32,
    /// An offset to a length-prefixed UTF-16LE string containing the name of the module.
    pub module_name_rva: RVA,
    /// Version information for this module.
    pub version_info: VS_FIXEDFILEINFO,
    /// The location of a CodeView record describing debug information for this module.
    ///
    /// This should be one of [`CV_INFO_PDB70`][pdb70], [`CV_INFO_PDB20`][pdb20], or
    /// [`CV_INFO_ELF`][elf]. `PDB70` is the most common in practice, describing a standalone PDB
    /// file by way of GUID, age, and PDB filename, and `ELF` is a Breakpad extension for
    /// describing ELF modules with Build IDs.
    ///
    /// See [Matching Debug Information][dbg] for more information.
    ///
    /// [dbg]: http://www.debuginfo.com/articles/debuginfomatch.html
    /// [pdb70]: struct.CV_INFO_PDB70.html
    /// [pdb20]: struct.CV_INFO_PDB20.html
    /// [elf]: struct.CV_INFO_ELF.html
    pub cv_record: MINIDUMP_LOCATION_DESCRIPTOR,
    /// The location of an `IMAGE_DEBUG_MISC` record describing debug information for this module.
    pub misc_record: MINIDUMP_LOCATION_DESCRIPTOR,
    pub reserved0: [u32; 2],
    pub reserved1: [u32; 2],
}

/// Version information for a file
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/verrsrc/ns-verrsrc-tagvs_fixedfileinfo
#[derive(Clone, Default, Pread, SizeWith)]
pub struct VS_FIXEDFILEINFO {
    /// Contains the value of `VS_FFI_SIGNATURE`
    pub signature: u32,
    /// Should contain the value of `VS_FFI_STRUCVERSION`
    pub struct_version: u32,
    pub file_version_hi: u32,
    pub file_version_lo: u32,
    pub product_version_hi: u32,
    pub product_version_lo: u32,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_hi: u32,
    pub file_date_lo: u32,
}

/// The expected value of `VS_FIXEDFILEINFO.signature`
pub const VS_FFI_SIGNATURE: u32 = 0xfeef04bd;

/// The expected value of `VS_FIXEDFILEINFO.struct_version`
pub const VS_FFI_STRUCVERSION: u32 = 0x00010000;

/// Known values for the `signature` field of CodeView records
///
/// In addition to the two CodeView record formats used for linking
/// to external pdb files it is possible for debugging data to be carried
/// directly in the CodeView record itself.  These signature values will
/// be found in the first 4 bytes of the CodeView record.  Additional values
/// not commonly experienced in the wild are given by ["Microsoft Symbol and
/// Type Information"][sym] section 7.2.  An in-depth description of the CodeView 4.1 format
/// is given by ["Undocumented Windows 2000 Secrets"][win2k], Windows 2000 Debugging Support/
/// Microsoft Symbol File Internals/CodeView Subsections.
///
/// [sym]: http://web.archive.org/web/20070915060650/http://www.x86.org/ftp/manuals/tools/sym.pdf
/// [win2k]: https://dl.acm.org/citation.cfm?id=375734
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum CvSignature {
    /// PDB 2.0 CodeView data: 'NB10': [`CV_INFO_PDB20`](struct.CV_INFO_PDB20.html)
    Pdb20 = 0x3031424e,
    /// PDB 7.0 CodeView data: 'RSDS': [`CV_INFO_PDB70`](struct.CV_INFO_PDB70.html)
    Pdb70 = 0x53445352,
    /// ELF Build ID, a Breakpad extension: 'BpEL': [`CV_INFO_ELF`](struct.CV_INFO_ELF.html)
    Elf = 0x4270454c,
    /// CodeView 4.10: 'NB09'
    Cv41 = 0x3930424e,
    /// CodeView 5.0: 'NB11'
    Cv50 = 0x3131424e,
}

/// CodeView debug information in the older PDB 2.0 ("NB10") format.
///
/// This struct is defined as variable-length in C with a trailing PDB filename member.
#[derive(Clone)]
pub struct CV_INFO_PDB20 {
    /// This field will always be [`CvSignature::Pdb20`](enum.CvSignature.html#variant.Pdb20).
    pub cv_signature: u32,
    pub cv_offset: u32,
    pub signature: u32,
    pub age: u32,
    /// The PDB filename as a zero-terminated byte string
    pub pdb_file_name: Vec<u8>,
}

impl<'a> scroll::ctx::TryFromCtx<'a, Endian> for CV_INFO_PDB20 {
    type Error = scroll::Error;

    fn try_from_ctx(src: &[u8], endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        Ok((CV_INFO_PDB20 {
            cv_signature: src.gread_with(offset, endian)?,
            cv_offset: src.gread_with(offset, endian)?,
            signature: src.gread_with(offset, endian)?,
            age: src.gread_with(offset, endian)?,
            pdb_file_name: {
                let size = src.len() - *offset;
                src.gread_with::<&[u8]>(offset, size)?.to_owned()
            }
        }, *offset))
    }
}

/// CodeView debug information in the current PDB 7.0 ("RSDS") format.
///
/// This struct is defined as variable-length in C with a trailing PDB filename member.
#[derive(Clone)]
pub struct CV_INFO_PDB70 {
    /// This will always be [`CvSignature::Pdb70`](enum.CvSignature.html#variant.Pdb70)
    pub cv_signature: u32,
    /// A unique identifer for a module created on first build.
    pub signature: GUID,
    /// A counter, incremented for each rebuild that updates the PDB file.
    pub age: u32,
    /// The PDB filename as a zero-terminated byte string
    pub pdb_file_name: Vec<u8>,
}

impl<'a> scroll::ctx::TryFromCtx<'a, Endian> for CV_INFO_PDB70 {
    type Error = scroll::Error;

    fn try_from_ctx(src: &[u8], endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        Ok((CV_INFO_PDB70 {
            cv_signature: src.gread_with(offset, endian)?,
            signature: src.gread_with(offset, endian)?,
            age: src.gread_with(offset, endian)?,
            pdb_file_name: {
                let size = src.len() - *offset;
                src.gread_with::<&[u8]>(offset, size)?.to_owned()
            }
        }, *offset))
    }
}

/// A GUID as specified in Rpcdce.h
///
/// Matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa373931(v=vs.85).aspx
#[derive(Clone, Pread, SizeWith)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// An ELF Build ID.
///
/// Modern ELF toolchains insert a "[build id][buildid]" into the ELF headers that typically
/// contains a hash of some ELF headers and sections to uniquely identify a binary. The Build ID
/// is allowed to be an arbitrary number of bytes however, and [GNU binutils allows creating
/// ELF binaries with Build IDs of various formats][binutils].
///
/// [buildid]: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/developer_guide/compiling-build-id
/// [binutils]: https://sourceware.org/binutils/docs-2.26/ld/Options.html#index-g_t_002d_002dbuild_002did-292
#[derive(Clone)]
pub struct CV_INFO_ELF {
    /// This will always be [`CvSignature::Elf`](enum.CvSignature.html#variant.Elf)
    pub cv_signature: u32,
    /// The build id, a variable number of bytes
    pub build_id: Vec<u8>,
}

impl<'a> scroll::ctx::TryFromCtx<'a, Endian> for CV_INFO_ELF {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        Ok((CV_INFO_ELF {
            cv_signature: src.gread_with(offset, endian)?,
            build_id: {
                let size = src.len() - *offset;
                src.gread_with::<&[u8]>(offset, size)?.to_owned()
            }
        }, *offset))
    }
}

/// Obsolete debug record type defined in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct IMAGE_DEBUG_MISC {
    pub data_type: u32,
    pub length: u32,
    pub unicode: u8,
    pub reserved: [u8; 3],
    pub data: [u8; 1],
}

/// Information about a single thread from a minidump
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_thread
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_THREAD {
    /// The identifier of this thread
    pub thread_id: u32,
    /// The suspend count for this thread
    ///
    /// If greater than zero, the thread is suspended.
    pub suspend_count: u32,
    /// The priority class of the thread
    ///
    /// See [Scheduling Priorities][msdn] on MSDN.
    ///
    /// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/ProcThread/scheduling-priorities
    pub priority_class: u32,
    /// The priority level of the thread
    pub priority: u32,
    /// The thread environment block
    pub teb: u64,
    /// The location and base address of this thread's stack memory
    pub stack: MINIDUMP_MEMORY_DESCRIPTOR,
    /// The location of a CPU-specific `CONTEXT_` struct for this thread's CPU context
    pub thread_context: MINIDUMP_LOCATION_DESCRIPTOR,
}

/// Information about the exception that caused the process to terminate.
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-minidump_exception_stream
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_EXCEPTION_STREAM {
    /// The identifier of the thread that encountered the exception.
    pub thread_id: u32,
    pub __align: u32,
    /// Detailed information about the exception encountered.
    pub exception_record: MINIDUMP_EXCEPTION,
    /// The offset of a CPU context record from the time the thread encountered the exception.
    ///
    /// The actual data will be one of the `CONTEXT_*` structs defined here.
    pub thread_context: MINIDUMP_LOCATION_DESCRIPTOR,
}

/// Detailed information about an exception.
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_exception
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_EXCEPTION {
    /// The reason the exception occurred.
    ///
    /// Possible values are in the `ExceptionCodeWindows`, `ExceptionCodeLinux`, and
    /// `ExceptionCodeMac` enums.
    pub exception_code: u32,
    /// Flags related to the exception.
    ///
    /// On Windows this is 1 for noncontinuable exceptions and 0 otherwise. For Breakpad-produced
    /// minidumps on macOS this field is used to store additional exception information.
    pub exception_flags: u32,
    /// The address of an associated `MINIDUMP_EXCEPTION` for a nested exception.
    ///
    /// This address is in the minidump producing host's memory.
    pub exception_record: u64,
    /// The address where the exception occurred.
    ///
    /// For Breakpad-produced minidumps on macOS this is the exception subcode, which is
    /// typically the address.
    pub exception_address: u64,
    /// The number of valid elements in `exception_information`.
    pub number_parameters: u32,
    pub __align: u32,
    /// An array of additional arguments that describe the exception.
    ///
    /// For most exception codes the array elements are undefined, but for access violations
    /// the array will contain two elements: a read/write flag in the first element and
    /// the virtual address whose access caused the exception in the second element.
    pub exception_information: [u64; 15], // EXCEPTION_MAXIMUM_PARAMETERS
}

/// Values for `MINIDUMP_EXCEPTION.exception_code` for crashes on Windows
///
/// These values primarily come from WinBase.h and WinNT.h, with a few additions.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeWindows {
    DBG_CONTROL_C = 0x40010005,
    EXCEPTION_GUARD_PAGE = 0x80000001,
    EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002,
    EXCEPTION_BREAKPOINT = 0x80000003,
    EXCEPTION_SINGLE_STEP = 0x80000004,
    EXCEPTION_ACCESS_VIOLATION = 0xc0000005,
    EXCEPTION_IN_PAGE_ERROR = 0xc0000006,
    EXCEPTION_INVALID_HANDLE = 0xc0000008,
    EXCEPTION_ILLEGAL_INSTRUCTION = 0xc000001d,
    EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xc0000025,
    EXCEPTION_INVALID_DISPOSITION = 0xc0000026,
    EXCEPTION_BOUNDS_EXCEEDED = 0xc000008c,
    EXCEPTION_FLT_DENORMAL_OPERAND = 0xc000008d,
    EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xc000008e,
    EXCEPTION_FLT_INEXACT_RESULT = 0xc000008f,
    EXCEPTION_FLT_INVALID_OPERATION = 0xc0000090,
    EXCEPTION_FLT_OVERFLOW = 0xc0000091,
    EXCEPTION_FLT_STACK_CHECK = 0xc0000092,
    EXCEPTION_FLT_UNDERFLOW = 0xc0000093,
    EXCEPTION_INT_DIVIDE_BY_ZERO = 0xc0000094,
    EXCEPTION_INT_OVERFLOW = 0xc0000095,
    EXCEPTION_PRIV_INSTRUCTION = 0xc0000096,
    EXCEPTION_STACK_OVERFLOW = 0xc00000fd,
    EXCEPTION_POSSIBLE_DEADLOCK = 0xc0000194,
    STATUS_STACK_BUFFER_OVERRUN = 0xc0000409,
    STATUS_HEAP_CORRUPTION = 0xc0000374,
    /// Exception thrown by Chromium allocators to indicate OOM
    ///
    /// See base/process/memory.h in Chromium for rationale.
    OUT_OF_MEMORY = 0xe0000008,
    /// Per http://support.microsoft.com/kb/185294, generated by Visual C++ compiler
    UNHANDLED_CPP_EXCEPTION = 0xe06d7363,
    /// Fake exception code used by Crashpad
    SIMULATED = 0x0517a7ed,
}

/// Values for `MINIDUMP_EXCEPTION.exception_code` for crashes on Linux
///
/// These are primarily signal numbers from bits/signum.h.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeLinux {
    /// Hangup (POSIX)
    SIGHUP = 0x1,
    /// Interrupt (ANSI)
    SIGINT = 0x2,
    /// Quit (POSIX)
    SIGQUIT = 0x3,
    /// Illegal instruction (ANSI)
    SIGILL = 0x4,
    /// Trace trap (POSIX)
    SIGTRAP = 0x5,
    /// Abort (ANSI)
    SIGABRT = 0x6,
    /// BUS error (4.2 BSD)
    SIGBUS = 0x7,
    /// Floating-point exception (ANSI)
    SIGFPE = 0x8,
    /// Kill, unblockable (POSIX)
    SIGKILL = 0x9,
    /// User-defined signal 1 (POSIX)
    SIGUSR1 = 0xa,
    /// Segmentation violation (ANSI)
    SIGSEGV = 0xb,
    /// User-defined signal 2 (POSIX)
    SIGUSR2 = 0xc,
    /// Broken pipe (POSIX)
    SIGPIPE = 0xd,
    /// Alarm clock (POSIX)
    SIGALRM = 0xe,
    /// Termination (ANSI)
    SIGTERM = 0xf,
    /// Stack fault
    SIGSTKFLT = 0x10,
    /// Child status has changed (POSIX)
    SIGCHLD = 0x11,
    /// Continue (POSIX)
    SIGCONT = 0x12,
    /// Stop, unblockable (POSIX)
    SIGSTOP = 0x13,
    /// Keyboard stop (POSIX)
    SIGTSTP = 0x14,
    /// Background read from tty (POSIX)
    SIGTTIN = 0x15,
    /// Background write to tty (POSIX)
    SIGTTOU = 0x16,
    /// Urgent condition on socket (4.2 BSD)
    SIGURG = 0x17,
    /// CPU limit exceeded (4.2 BSD)
    SIGXCPU = 0x18,
    /// File size limit exceeded (4.2 BSD)
    SIGXFSZ = 0x19,
    /// Virtual alarm clock (4.2 BSD)
    SIGVTALRM = 0x1a,
    /// Profiling alarm clock (4.2 BSD)
    SIGPROF = 0x1b,
    /// Window size change (4.3 BSD, Sun)
    SIGWINCH = 0x1c,
    /// I/O now possible (4.2 BSD)
    SIGIO = 0x1d,
    /// Power failure restart (System V)
    SIGPWR = 0x1e,
    /// Bad system call
    SIGSYS = 0x1f,
    /// No exception, dump requested
    DUMP_REQUESTED = 0xffffffff,
}

/// Values for `MINIDUMP_EXCEPTION.exception_code` for crashes on macOS
///
/// Based on Darwin/macOS' mach/exception_types.h. This is what macOS calls an "exception",
/// not a "code".
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMac {
    /// code can be a kern_return_t
    EXC_BAD_ACCESS = 1,
    /// code is CPU-specific
    EXC_BAD_INSTRUCTION = 2,
    /// code is CPU-specific
    EXC_ARITHMETIC = 3,
    /// code is CPU-specific
    EXC_EMULATION = 4,
    EXC_SOFTWARE = 5,
    /// code is CPU-specific
    EXC_BREAKPOINT = 6,
    EXC_SYSCALL = 7,
    EXC_MACH_SYSCALL = 8,
    EXC_RPC_ALERT = 9,
    /// Fake exception code used by Crashpad's SimulateCrash ('CPsx')
    SIMULATED = 0x43507378,
}

/// Valid bits in a `context_flags` for `ContextFlagsCpu`
pub const CONTEXT_CPU_MASK: u32 = 0xffffff00;

bitflags! {
    /// CPU type values in the `context_flags` member of `CONTEXT_` structs
    pub struct ContextFlagsCpu: u32 {
        const CONTEXT_IA64 = 0x80000;
        /// Super-H, includes SH3, from winnt.h in the Windows CE 5.0 SDK
        const CONTEXT_SHX = 0xc0;
        /// From winnt.h in the Windows CE 5.0 SDK, no longer used
        ///
        /// Originally used by Breakpad but changed after conflicts with other context
        /// flag bits.
        const CONTEXT_ARM_OLD = 0x40;
        /// Alpha, from winnt.h in the Windows CE 5.0 SDK
        const CONTEXT_ALPHA = 0x20000;
        const CONTEXT_AMD64 = 0x100000;
        const CONTEXT_ARM = 0x40000000;
        const CONTEXT_ARM64 = 0x400000;
        const CONTEXT_ARM64_OLD = 0x80000000;
        const CONTEXT_MIPS = 0x40000;
        const CONTEXT_MIPS64 = 0x80000;
        const CONTEXT_PPC = 0x20000000;
        const CONTEXT_PPC64 = 0x1000000;
        const CONTEXT_SPARC = 0x10000000;
        const CONTEXT_X86 = 0x10000;
    }
}

impl ContextFlagsCpu {
    /// Populate a `ContextFlagsCpu` with valid bits from `flags`
    pub fn from_flags(flags: u32) -> ContextFlagsCpu {
        ContextFlagsCpu::from_bits_truncate(flags & CONTEXT_CPU_MASK)
    }
}

/// Possible contents of `CONTEXT_AMD64.float_save`.
///
/// This struct matches the definition of the struct with the same name from WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct XMM_SAVE_AREA32 {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    pub reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved3: u16,
    pub mx_csr: u32,
    pub mx_csr_mask: u32,
    pub float_registers: [u128; 8],
    pub xmm_registers: [u128; 16],
    pub reserved4: [u8; 96],
}

/// Possible contents of `CONTEXT_AMD64.float_save`.
///
/// This is defined as an anonymous struct inside an anonymous union in
/// the x86-64 CONTEXT struct in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct SSE_REGISTERS {
    pub header: [u128; 2],
    pub legacy: [u128; 8],
    pub xmm0: u128,
    pub xmm1: u128,
    pub xmm2: u128,
    pub xmm3: u128,
    pub xmm4: u128,
    pub xmm5: u128,
    pub xmm6: u128,
    pub xmm7: u128,
    pub xmm8: u128,
    pub xmm9: u128,
    pub xmm10: u128,
    pub xmm11: u128,
    pub xmm12: u128,
    pub xmm13: u128,
    pub xmm14: u128,
    pub xmm15: u128,
}

/// An x86-64 (amd64) CPU context
///
/// This struct matches the definition of `CONTEXT` in WinNT.h for x86-64.
#[derive(Clone, Pread, SizeWith)]
pub struct CONTEXT_AMD64 {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    /// Floating point state
    ///
    /// This is defined as a union in the C headers, but also
    /// ` MAXIMUM_SUPPORTED_EXTENSION` is defined as 512 bytes.
    ///
    /// Callers that want to access the underlying data can use `Pread` to read either
    /// an `XMM_SAVE_AREA32` or `SSE_REGISTERS` struct from this raw data as appropriate.
    pub float_save: [u8; 512],
    pub vector_register: [u128; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

/// ARM floating point state
#[derive(Clone, Pread, SizeWith)]
pub struct FLOATING_SAVE_AREA_ARM {
    pub fpscr: u64,
    pub regs: [u64; 32],
    pub extra: [u32; 8],
}

/// An ARM CPU context
///
/// This is a Breakpad extension, and does not match the definition of `CONTEXT` for ARM
/// in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct CONTEXT_ARM {
    pub context_flags: u32,
    pub iregs: [u32; 16],
    pub cpsr: u32,
    pub float_save: FLOATING_SAVE_AREA_ARM,
}

/// Offsets into `CONTEXT_ARM.iregs` for registers with a dedicated or conventional purpose
#[repr(usize)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ArmRegisterNumbers {
    IosFramePointer = 7,
    FramePointer = 11,
    StackPointer = 13,
    LinkRegister = 14,
    ProgramCounter = 15,
}

/// aarch64 floating point state (old)
#[derive(Clone, Copy, Pread, SizeWith)]
pub struct FLOATING_SAVE_AREA_ARM64_OLD {
    pub fpsr: u32,
    pub fpcr: u32,
    pub regs: [u128; 32usize],
}

/// An old aarch64 (arm64) CPU context
///
/// This is a Breakpad extension.
#[derive(Clone, Copy, Pread, SizeWith)]
#[repr(packed)]
pub struct CONTEXT_ARM64_OLD {
    pub context_flags: u64,
    pub iregs: [u64; 32],
    pub pc: u64,
    pub cpsr: u32,
    pub float_save: FLOATING_SAVE_AREA_ARM64_OLD,
}

/// aarch64 floating point state
#[derive(Clone, Pread, SizeWith)]
pub struct FLOATING_SAVE_AREA_ARM64 {
    pub regs: [u128; 32usize],
    pub fpsr: u32,
    pub fpcr: u32,
}

/// An aarch64 (arm64) CPU context
///
/// This is a Breakpad extension, and does not match the definition of `CONTEXT` for aarch64
/// in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct CONTEXT_ARM64 {
    pub context_flags: u32,
    pub cpsr: u32,
    pub iregs: [u64; 32],
    pub pc: u64,
    pub float_save: FLOATING_SAVE_AREA_ARM64,
    pub bcr: [u32; 8],
    pub bvr: [u64; 8],
    pub wcr: [u32; 2],
    pub wvr: [u64; 2],
}

/// Offsets into `CONTEXT_ARM64.iregs` for registers with a dedicated or conventional purpose
#[repr(usize)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Arm64RegisterNumbers {
    FramePointer = 29,
    LinkRegister = 30,
    StackPointer = 31,
    ProgramCounter = 32,
}

/// MIPS floating point state
#[derive(Clone, Pread, SizeWith)]
pub struct FLOATING_SAVE_AREA_MIPS {
    pub regs: [u64; 32],
    pub fpcsr: u32,
    pub fir: u32,
}

/// A MIPS CPU context
///
/// This is a Breakpad extension, as there is no definition of `CONTEXT` for MIPS in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct CONTEXT_MIPS {
    pub context_flags: u32,
    pub _pad0: u32,
    pub iregs: [u64; 32],
    pub mdhi: u64,
    pub mdlo: u64,
    pub hi: [u32; 3],
    pub lo: [u32; 3],
    pub dsp_control: u32,
    pub _pad1: u32,
    pub epc: u64,
    pub badvaddr: u64,
    pub status: u32,
    pub cause: u32,
    pub float_save: FLOATING_SAVE_AREA_MIPS,
}

/// Offsets into `CONTEXT_MIPS.iregs` for registers with a dedicated or conventional purpose
#[repr(usize)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MipsRegisterNumbers {
    S0 = 16,
    S1 = 17,
    S2 = 18,
    S3 = 19,
    S4 = 20,
    S5 = 21,
    S6 = 22,
    S7 = 23,
    GlobalPointer = 28,
    StackPointer = 29,
    FramePointer = 30,
    ReturnAddress = 31,
}

/// PPC floating point state
#[derive(Clone, Pread, SizeWith)]
pub struct FLOATING_SAVE_AREA_PPC {
    pub fpregs: [u64; 32],
    pub fpscr_pad: u32,
    pub fpscr: u32,
}

/// PPC vector state
#[derive(Clone, Pread, SizeWith)]
pub struct VECTOR_SAVE_AREA_PPC {
    pub save_vr: [u128; 32],
    pub save_vscr: u128,
    pub save_pad5: [u32; 4],
    pub save_vrvalid: u32,
    pub save_pad6: [u32; 7],
}

/// A PPC CPU context
///
/// This is a Breakpad extension, as there is no definition of `CONTEXT` for PPC in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct CONTEXT_PPC {
    pub context_flags: u32,
    pub srr0: u32,
    pub srr1: u32,
    pub gpr: [u32; 32],
    pub cr: u32,
    pub xer: u32,
    pub lr: u32,
    pub ctr: u32,
    pub mq: u32,
    pub vrsave: u32,
    pub float_save: FLOATING_SAVE_AREA_PPC,
    pub vector_save: VECTOR_SAVE_AREA_PPC,
}

/// Offsets into `CONTEXT_PPC.gpr` for registers with a dedicated or conventional purpose
#[repr(usize)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum PpcRegisterNumbers {
    StackPointer = 1,
}

/// A PPC64 CPU context
///
/// This is a Breakpad extension, as there is no definition of `CONTEXT` for PPC64 in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct CONTEXT_PPC64 {
    pub context_flags: u64,
    pub srr0: u64,
    pub srr1: u64,
    pub gpr: [u64; 32],
    pub cr: u64,
    pub xer: u64,
    pub lr: u64,
    pub ctr: u64,
    pub vrsave: u64,
    pub float_save: FLOATING_SAVE_AREA_PPC,
    pub vector_save: VECTOR_SAVE_AREA_PPC,
}

/// Offsets into `CONTEXT_PPC64.gpr` for registers with a dedicated or conventional purpose
#[repr(usize)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Ppc64RegisterNumbers {
    StackPointer = 1,
}

/// SPARC floating point state
#[derive(Clone, Pread, SizeWith)]
pub struct FLOATING_SAVE_AREA_SPARC {
    pub regs: [u64; 32],
    pub filler: u64,
    pub fsr: u64,
}

/// A SPARC CPU context
///
/// This is a Breakpad extension, as there is no definition of `CONTEXT` for SPARC in WinNT.h.
#[derive(Clone, Pread, SizeWith)]
pub struct CONTEXT_SPARC {
    pub context_flags: u32,
    pub flag_pad: u32,
    pub g_r: [u64; 32],
    pub ccr: u64,
    pub pc: u64,
    pub npc: u64,
    pub y: u64,
    pub asi: u64,
    pub fprs: u64,
    pub float_save: FLOATING_SAVE_AREA_SPARC,
}

/// Offsets into `CONTEXT_SPARC.g_r` for registers with a dedicated or conventional purpose
#[repr(usize)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SparcRegisterNumbers {
    StackPointer = 14,
}

/// x86 floating point state
///
/// This struct matches the definition of the `FLOATING_SAVE_AREA` struct from WinNT.h.
#[derive(Clone, SmartDefault, Pread, SizeWith)]
pub struct FLOATING_SAVE_AREA_X86 {
    pub control_word: u32,
    pub status_word: u32,
    pub tag_word: u32,
    pub error_offset: u32,
    pub error_selector: u32,
    pub data_offset: u32,
    pub data_selector: u32,
    #[default = "[0; 80]"]
    pub register_area: [u8; 80], // SIZE_OF_80387_REGISTERS
    pub cr0_npx_state: u32,
}

/// An x86 CPU context
///
/// This struct matches the definition of `CONTEXT` in WinNT.h for x86.
#[derive(Clone, SmartDefault, Pread, SizeWith)]
pub struct CONTEXT_X86 {
    pub context_flags: u32,
    pub dr0: u32,
    pub dr1: u32,
    pub dr2: u32,
    pub dr3: u32,
    pub dr6: u32,
    pub dr7: u32,
    pub float_save: FLOATING_SAVE_AREA_X86,
    pub gs: u32,
    pub fs: u32,
    pub es: u32,
    pub ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub ebp: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub ss: u32,
    #[default = "[0; 512]"]
    pub extended_registers: [u8; 512], // MAXIMUM_SUPPORTED_EXTENSION
}

/// CPU information contained within the `MINIDUMP_SYSTEM_INFO` struct
///
/// This struct matches the definition of the `CPU_INFORMATION` union from minidumpapiset.h.
#[derive(Clone, Pread, SizeWith)]
pub struct CPU_INFORMATION {
    /// `data` is defined as a union in the Microsoft headers
    ///
    /// It is the union of `X86CpuInfo`, `ARMCpuInfo` (Breakpad-specific), and
    /// `OtherCpuInfo` defined below. It does not seem possible to safely derive `Pread`
    /// on an actual union, so we provide the raw data here and expect callers to use
    /// `Pread` to derive the specific union representation desired.
    pub data: [u8; 24],
}

/// x86-specific CPU information derived from the `cpuid` instruction
///
/// This struct matches the definition of the struct of the same name from minidumpapiset.h,
/// which is contained within the `CPU_INFORMATION` union.
#[derive(Clone, Pread, SizeWith)]
pub struct X86CpuInfo {
    pub vendor_id: [u32; 3],
    pub version_information: u32,
    pub feature_information: u32,
    pub amd_extended_cpu_features: u32,
}

/// Arm-specific CPU information (Breakpad extension)
#[derive(Clone, Pread, SizeWith)]
pub struct ARMCpuInfo {
    pub cpuid: u32,
    /// Hardware capabilities
    ///
    /// See [`ArmElfHwCaps`](struct.ArmElfHwCaps.html) for possible values.
    pub elf_hwcaps: u32,
}

/// CPU information for non-x86 CPUs
///
/// This struct matches the definition of the struct of the same name from minidumpapiset.h,
/// which is contained within the `CPU_INFORMATION` union.
#[derive(Clone, Pread, SizeWith)]
pub struct OtherCpuInfo {
    pub processor_features: [u64; 2],
}

bitflags! {
    /// Possible values of `ARMCpuInfo.elf_hwcaps`
    ///
    /// This matches the Linux kernel definitions from [<asm/hwcaps.h>](hwcap).
    ///
    /// [hwcap]: https://elixir.bootlin.com/linux/latest/source/arch/arm/include/uapi/asm/hwcap.h
    pub struct ArmElfHwCaps: u32 {
        const HWCAP_SWP       = (1 << 0);
        const HWCAP_HALF      = (1 << 1);
        const HWCAP_THUMB     = (1 << 2);
        const HWCAP_26BIT     = (1 << 3);
        const HWCAP_FAST_MULT = (1 << 4);
        const HWCAP_FPA       = (1 << 5);
        const HWCAP_VFP       = (1 << 6);
        const HWCAP_EDSP      = (1 << 7);
        const HWCAP_JAVA      = (1 << 8);
        const HWCAP_IWMMXT    = (1 << 9);
        const HWCAP_CRUNCH    = (1 << 10);
        const HWCAP_THUMBEE   = (1 << 11);
        const HWCAP_NEON      = (1 << 12);
        const HWCAP_VFPv3     = (1 << 13);
        const HWCAP_VFPv3D16  = (1 << 14);
        const HWCAP_TLS       = (1 << 15);
        const HWCAP_VFPv4     = (1 << 16);
        const HWCAP_IDIVA     = (1 << 17);
        const HWCAP_IDIVT     = (1 << 18);
        const HWCAP_VFPD32    = (1 << 19);
        const HWCAP_IDIV      = Self::HWCAP_IDIVA.bits | Self::HWCAP_IDIVT.bits;
        const HWCAP_LPAE      = (1 << 20);
        const HWCAP_EVTSTRM   = (1 << 21);
    }
}

/// Processor and operating system information
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_system_info
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_SYSTEM_INFO {
    /// The system's processor architecture
    ///
    /// Known values are defined in [`ProcessorArchitecture`](enum.ProcessorArchitecture.html).
    pub processor_architecture: u16,
    /// x86 (5 = 586, 6 = 686 ...) or ARM (6 = ARMv6, 7 = ARMv7 ...) CPU level
    pub processor_level: u16,
    /// For x86, 0xMMSS where MM=model, SS=stepping
    pub processor_revision: u16,
    pub number_of_processors: u8,
    pub product_type: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    /// The operating system platform
    ///
    /// Known values are defined in [`PlatformId`](enum.PlatformId.html).
    pub platform_id: u32,
    pub csd_version_rva: RVA,
    pub suite_mask: u16,
    pub reserved2: u16,
    pub cpu: CPU_INFORMATION,
}

/// Known values of `MINIDUMP_SYSTEM_INFO.processor_architecture`
///
/// Many of these are taken from definitions in WinNT.h, but several of them are
/// Breakpad extensions.
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ProcessorArchitecture {
    PROCESSOR_ARCHITECTURE_INTEL =  0,
    PROCESSOR_ARCHITECTURE_MIPS = 1,
    PROCESSOR_ARCHITECTURE_ALPHA =  2,
    PROCESSOR_ARCHITECTURE_PPC = 3,
    PROCESSOR_ARCHITECTURE_SHX = 4,
    PROCESSOR_ARCHITECTURE_ARM =  5,
    PROCESSOR_ARCHITECTURE_IA64 = 6,
    PROCESSOR_ARCHITECTURE_ALPHA64 = 7,
    /// Microsoft Intermediate Language
    PROCESSOR_ARCHITECTURE_MSIL = 8,
    PROCESSOR_ARCHITECTURE_AMD64 = 9,
    /// WoW64
    PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 = 10,
    PROCESSOR_ARCHITECTURE_ARM64 = 12,
    /// Breakpad-defined value for SPARC
    PROCESSOR_ARCHITECTURE_SPARC     = 0x8001,
    /// Breakpad-defined value for PPC64
    PROCESSOR_ARCHITECTURE_PPC64     = 0x8002,
    /// Breakpad-defined value for ARM64
    PROCESSOR_ARCHITECTURE_ARM64_OLD = 0x8003,
    /// Breakpad-defined value for MIPS64
    PROCESSOR_ARCHITECTURE_MIPS64    = 0x8004,
    PROCESSOR_ARCHITECTURE_UNKNOWN   = 0xffff,
}

/// Known values of `MINIDUMP_SYSTEM_INFO.platform_id`
///
/// The Windows values here are taken from defines in WinNT.h, but the rest are Breakpad
/// extensions.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum PlatformId {
    /// Windows 3.1
    VER_PLATFORM_WIN32s = 1,
    /// Windows 95-98-Me
    VER_PLATFORM_WIN32_WINDOWS = 2,
    /// Windows NT, 2000+
    VER_PLATFORM_WIN32_NT = 3,
    /// Windows CE, Windows Mobile
    VER_PLATFORM_WIN32_CE = 4,
    /// Generic Unix-ish (Breakpad extension)
    Unix = 0x8000,
    /// macOS/Darwin (Breakpad extension)
    MacOs = 0x8101,
    /// iOS (Breakpad extension)
    Ios = 0x8102,
    /// Linux (Breakpad extension)
    Linux = 0x8201,
    /// Solaris (Breakpad extension)
    Solaris = 0x8202,
    /// Android (Breakpad extension)
    Android = 0x8203,
    /// PlayStation 3 (Breakpad extension)
    Ps3 = 0x8204,
    /// Native Client (Breakpad extension)
    NaCl = 0x8205,
}

/// A date and time
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724950(v=vs.85).aspx
#[derive(Clone, Pread, SizeWith)]
pub struct SYSTEMTIME {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

/// Settings for a time zone
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/timezoneapi/ns-timezoneapi-_time_zone_information
#[derive(Clone, Pread, SizeWith)]
pub struct TIME_ZONE_INFORMATION {
    pub bias: i32,
    pub standard_name: [u16; 32],
    pub standard_date: SYSTEMTIME,
    pub standard_bias: i32,
    pub daylight_name: [u16; 32],
    pub daylight_date: SYSTEMTIME,
    pub daylight_bias: i32,
}

/*
 * There are multiple versions of the misc info struct, and each new version includes all
 * fields from the previous versions. We declare them with a macro to avoid repeating
 * the fields excessively.
 */
macro_rules! multi_structs {
    // With no trailing struct left, terminate.
    (@next { $($prev:tt)* }) => {};
    // Declare the next struct, including fields from previous structs.
    (@next { $($prev:tt)* } $(#[$attr:meta])* pub struct $name:ident { $($cur:tt)* } $($tail:tt)* ) => {
        // Prepend fields from previous structs to this struct.
        multi_structs!($(#[$attr])* pub struct $name { $($prev)* $($cur)* } $($tail)*);
    };
    // Declare a single struct.
    ($(#[$attr:meta])* pub struct $name:ident { $( pub $field:ident: $t:tt, )* } $($tail:tt)* ) => {
        $(#[$attr])*
        #[derive(Clone, Pread, SizeWith)]
        pub struct $name {
            $( pub $field: $t, )*
        }
        // Persist its fields down to the following structs.
        multi_structs!(@next { $( pub $field: $t, )* } $($tail)*);
    };
}

multi_structs! {
    /// Miscellaneous process information
    ///
    /// This struct matches the [Microsoft struct][msdn] of the same name.
    ///
    /// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_misc_info
    pub struct MINIDUMP_MISC_INFO {
        pub size_of_info: u32,
        pub flags1: u32,
        pub process_id: u32,
        pub process_create_time: u32,
        pub process_user_time: u32,
        pub process_kernel_time: u32,
    }
    // Includes fields from MINIDUMP_MISC_INFO
    /// Miscellaneous process and system information
    ///
    /// This struct matches the [Microsoft struct][msdn] of the same name.
    ///
    /// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_misc_info_2
    pub struct MINIDUMP_MISC_INFO2 {
        pub processor_max_mhz: u32,
        pub processor_current_mhz: u32,
        pub processor_mhz_limit: u32,
        pub processor_max_idle_state: u32,
        pub processor_current_idle_state: u32,
    }
    // Includes fields from MINIDUMP_MISC_INFO and MINIDUMP_MISC_INFO_2
    /// Miscellaneous process and system information
    ///
    /// This struct matches the struct of the same name from minidumpapiset.h.
    pub struct MINIDUMP_MISC_INFO3 {
        pub process_integrity_level: u32,
        pub process_execute_flags: u32,
        pub protected_process: u32,
        pub time_zone_id: u32,
        pub time_zone: TIME_ZONE_INFORMATION,
    }
    // Includes fields from MINIDUMP_MISC_INFO..3
    /// Miscellaneous process and system information
    ///
    /// This struct matches the struct of the same name from minidumpapiset.h.
    pub struct MINIDUMP_MISC_INFO4 {
        pub build_string: [u16; 260], // MAX_PATH
        pub dbg_bld_str: [u16; 40],
    }
}

//TODO: MINIDUMP_MISC_INFO_5
/*
typedef struct _MINIDUMP_MISC_INFO_5 {
    ULONG32 SizeOfInfo;
    ULONG32 Flags1;
    ULONG32 ProcessId;
    ULONG32 ProcessCreateTime;
    ULONG32 ProcessUserTime;
    ULONG32 ProcessKernelTime;
    ULONG32 ProcessorMaxMhz;
    ULONG32 ProcessorCurrentMhz;
    ULONG32 ProcessorMhzLimit;
    ULONG32 ProcessorMaxIdleState;
    ULONG32 ProcessorCurrentIdleState;
    ULONG32 ProcessIntegrityLevel;
    ULONG32 ProcessExecuteFlags;
    ULONG32 ProtectedProcess;
    ULONG32 TimeZoneId;
    TIME_ZONE_INFORMATION TimeZone;
    WCHAR   BuildString[MAX_PATH];
    WCHAR   DbgBldStr[40];
    XSTATE_CONFIG_FEATURE_MSC_INFO XStateData;
    ULONG32 ProcessCookie;
} MINIDUMP_MISC_INFO_5, *PMINIDUMP_MISC_INFO_5;
*/

bitflags! {
    /// Known flags for `MINIDUMP_MISC_INFO*.flags1`
    pub struct MiscInfoFlags: u32 {
        const MINIDUMP_MISC1_PROCESS_ID            = 0x00000001;
        const MINIDUMP_MISC1_PROCESS_TIMES         = 0x00000002;
        const MINIDUMP_MISC1_PROCESSOR_POWER_INFO  = 0x00000004;
        const MINIDUMP_MISC3_PROCESS_INTEGRITY     = 0x00000010;
        const MINIDUMP_MISC3_PROCESS_EXECUTE_FLAGS = 0x00000020;
        const MINIDUMP_MISC3_TIMEZONE              = 0x00000040;
        const MINIDUMP_MISC3_PROTECTED_PROCESS     = 0x00000080;
        const MINIDUMP_MISC4_BUILDSTRING           = 0x00000100;
        const MINIDUMP_MISC5_PROCESS_COOKIE        = 0x00000200;
    }
}

/// A list of memory regions in a minidump
///
/// This is the format of the `MemoryInfoListStream`. The individual `MINIDUMP_MEMORY_INFO`
/// entries follow this header in the stream.
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_memory_info_list
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_MEMORY_INFO_LIST {
    /// The size of this header
    pub size_of_header: u32,
    /// The size of each entry in the list
    pub size_of_entry: u32,
    /// The number of entries in the list
    pub number_of_entries: u64,
}

/// Information about a memory region in a minidump
///
/// This struct matches the [Microsoft struct][msdn] of the same name.
///
/// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/ns-minidumpapiset-_minidump_memory_info
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_MEMORY_INFO {
    /// The base address of the region of pages
    pub base_address: u64,
    /// The base address of a range of pages in this region
    pub allocation_base: u64,
    /// The memory protection when the region was initially allocated
    ///
    /// See [`MemoryProtection`](struct.MemoryProtection.html) for valid values.
    pub allocation_protection: u32,
    pub __alignment1: u32,
    /// The size of the region in which all pages have identical attributes, in bytes
    pub region_size: u64,
    /// The state of the pages in the region
    ///
    /// See [`MemoryState`](struct.MemoryState.html) for valid values.
    pub state: u32,
    /// The access protection of the pages in the region
    ///
    /// See [`MemoryProtection`](struct.MemoryProtection.html) for valid values.
    pub protection: u32,
    /// The type of pages in the region
    ///
    /// See [`MemoryType`](struct.MemoryType.html) for valid values.
    pub _type: u32,
    pub __alignment2: u32,
}

bitflags! {
    /// Potential values for `MINIDUMP_MEMORY_INFO.state`
    pub struct MemoryState: u32 {
        const MEM_COMMIT  = 0x01000;
        const MEM_FREE    = 0x10000;
        const MEM_RESERVE = 0x02000;
    }
}

bitflags! {
    /// Potential values for `MINIDUMP_MEMORY_INFO.protection` and `allocation_protection`
    ///
    /// See [Microsoft's documentation](msdn) for details.
    ///
    /// [msdn]: https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants
    pub struct MemoryProtection: u32 {
        const PAGE_NOACCESS           = 0x01;
        const PAGE_READONLY           = 0x02;
        const PAGE_READWRITE          = 0x04;
        const PAGE_WRITECOPY          = 0x08;
        const PAGE_EXECUTE            = 0x10;
        const PAGE_EXECUTE_READ       = 0x20;
        const PAGE_EXECUTE_READWRITE  = 0x40;
        const PAGE_EXECUTE_WRITECOPY  = 0x80;
        const ACCESS_MASK             = 0xff;
        const PAGE_GUARD              = 0x100;
        const PAGE_NOCACHE            = 0x200;
        const PAGE_WRITECOMBINE       = 0x400;
    }
}

bitflags! {
    /// Potential values for `MINIDUMP_MEMORY_INFO._type`
    pub struct MemoryType: u32 {
        const MEM_PRIVATE = 0x00020000;
        const MEM_MAPPED  = 0x00040000;
        const MEM_IMAGE   = 0x01000000;
    }
}

/// A Breakpad extension containing some additional process information
///
/// Taken from the definition in Breakpad's [minidump_format.h][fmt].
///
/// [fmt]: https://chromium.googlesource.com/breakpad/breakpad/+/88d8114fda3e4a7292654bd6ac0c34d6c88a8121/src/google_breakpad/common/minidump_format.h#962
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_BREAKPAD_INFO {
    pub validity: u32,
    /// The Thread ID of the handler thread
    pub dump_thread_id: u32,
    /// The Thread ID of the thread that requested the dump
    pub requesting_thread_id: u32,
}

bitflags! {
    /// Potential values for `MINIDUMP_BREAKPAD_INFO.validity`
    ///
    /// Taken from definitions in Breakpad's [minidump_format.h][fmt].
    ///
    /// [fmt]: https://chromium.googlesource.com/breakpad/breakpad/+/88d8114fda3e4a7292654bd6ac0c34d6c88a8121/src/google_breakpad/common/minidump_format.h#989
    pub struct BreakpadInfoValid: u32 {
        const DumpThreadId       = 1 << 0;
        const RequestingThreadId = 1 << 1;
    }
}

/// A Breakpad extension containing information about an assertion that terminated the process
///
/// Taken from the definition in Breakpad's [minidump_format.h][fmt].
///
/// [fmt]: https://chromium.googlesource.com/breakpad/breakpad/+/88d8114fda3e4a7292654bd6ac0c34d6c88a8121/src/google_breakpad/common/minidump_format.h#998
#[derive(Clone, Pread, SizeWith)]
pub struct MINIDUMP_ASSERTION_INFO {
    /// The assertion that failed, as a 0-terminated UTF16-LE string
    pub expression: [u16; 128],
    /// The function containing the assertion, as a 0-terminated UTF16-LE string
    pub function: [u16; 128],
    /// The source file containing the assertion, as a 0-terminated UTF16-LE string
    pub file: [u16; 128],
    /// The line number in `file` containing the assertion
    pub line: u32,
    /// The assertion type
    pub _type: u32,
}

/// Known values of `MINIDUMP_ASSERTION_INFO._type`
/// Taken from the definition in Breakpad's [minidump_format.h][fmt].
///
/// [fmt]: https://chromium.googlesource.com/breakpad/breakpad/+/88d8114fda3e4a7292654bd6ac0c34d6c88a8121/src/google_breakpad/common/minidump_format.h#1011
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum AssertionType {
    Unknown = 0,
    InvalidParameter = 1,
    PureVirtualCall = 2,
}

/// Dynamic linker information for a shared library on 32-bit Linux
///
/// This is functionally equivalent to the data in `struct link_map` defined in <link.h>.
#[derive(Clone, Pread, SizeWith)]
pub struct LINK_MAP_32 {
    pub addr: u32,
    /// The offset of a string containing the filename of this shared library
    pub name: RVA,
    pub ld: u32,
}

/// DSO debug data for 32-bit Linux minidumps
///
/// Used when converting minidumps to coredumps. This is functionally equivalent to the data
/// in `struct r_debug` defined in <link.h>.
#[derive(Clone, Pread, SizeWith)]
pub struct DSO_DEBUG_32 {
    /// The version number of this protocol, from `r_debug.r_version`
    pub version: u32,
    /// The offset of an array of `LINK_MAP_32` structs
    pub map: RVA,
    /// The number of `LINK_MAP_32` entries pointed to by `map`
    pub dso_count: u32,
    /// The address of a function internal to the run-time linker used by debuggers to
    /// set a breakpoint.
    pub brk: u32,
    /// Base address the linker is loaded at
    pub ldbase: u32,
    /// The address of the "dynamic structure"
    pub dynamic: u32,
}

/// Dynamic linker information for a shared library on 64-bit Linux
///
/// This is functionally equivalent to the data in `struct link_map` defined in <link.h>.
#[derive(Clone, Pread, SizeWith)]
pub struct LINK_MAP_64 {
    pub addr: u64,
    /// The offset of a string containing the filename of this shared library
    pub name: RVA,
    pub ld: u64,
}

/// DSO debug data for 64-bit Linux minidumps
///
/// Used when converting minidumps to coredumps. This is functionally equivalent to the data
/// in `struct r_debug` defined in <link.h>.
#[derive(Clone, Pread, SizeWith)]
pub struct DSO_DEBUG_64 {
    /// The version number of this protocol, from `r_debug.r_version`
    pub version: u32,
    /// The offset of an array of `LINK_MAP_64` structs
    pub map: RVA,
    /// The number of `LINK_MAP_64` entries pointed to by `map`
    pub dso_count: u32,
    /// The address of a function internal to the run-time linker used by debuggers to
    /// set a breakpoint.
    pub brk: u64,
    /// Base address the linker is loaded at
    pub ldbase: u64,
    /// The address of the "dynamic structure"
    pub dynamic: u64,
}
