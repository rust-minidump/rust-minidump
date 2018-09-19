//! Minidump structure definitions.
//!
//! This file was originally generated from Breakpad's [minidump_format.h][1]
//! using [rust-bindgen][2], but has since been manually edited.
//! [1]: https://chromium.googlesource.com/breakpad/breakpad/+/master/src/google_breakpad/common/minidump_format.h
//! [2]: https://github.com/servo/rust-bindgen
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub const MD_CONTEXT_IA64: ::libc::c_uint = 524288;
pub const MD_CONTEXT_SHX: ::libc::c_uint = 192;
pub const MD_CONTEXT_ALPHA: ::libc::c_uint = 131072;
pub const MD_CONTEXT_CPU_MASK: ::libc::c_uint = 4294967040;
pub const MD_CONTEXT_AMD64_VR_COUNT: ::libc::c_uint = 26;
pub const MD_CONTEXT_AMD64: ::libc::c_uint = 1048576;
pub const MD_FLOATINGSAVEAREA_ARM_FPR_COUNT: ::libc::c_uint = 32;
pub const MD_FLOATINGSAVEAREA_ARM_FPEXTRA_COUNT: ::libc::c_uint = 8;
pub const MD_CONTEXT_ARM_GPR_COUNT: ::libc::c_uint = 16;
pub const MD_CONTEXT_ARM_OLD: ::libc::c_uint = 64;
pub const MD_CONTEXT_ARM: ::libc::c_uint = 1073741824;
pub const MD_FLOATINGSAVEAREA_ARM64_FPR_COUNT: ::libc::c_uint = 32;
pub const MD_CONTEXT_ARM64_GPR_COUNT: ::libc::c_uint = 33;
pub const MD_CONTEXT_ARM64: ::libc::c_uint = 2147483648;
pub const MD_CONTEXT_MIPS_GPR_COUNT: ::libc::c_uint = 32;
pub const MD_FLOATINGSAVEAREA_MIPS_FPR_COUNT: ::libc::c_uint = 32;
pub const MD_CONTEXT_MIPS_DSP_COUNT: ::libc::c_uint = 3;
pub const MD_CONTEXT_MIPS: ::libc::c_uint = 262144;
pub const MD_CONTEXT_MIPS64: ::libc::c_uint = 524288;
pub const MD_FLOATINGSAVEAREA_PPC_FPR_COUNT: ::libc::c_uint = 32;
pub const MD_VECTORSAVEAREA_PPC_VR_COUNT: ::libc::c_uint = 32;
pub const MD_CONTEXT_PPC_GPR_COUNT: ::libc::c_uint = 32;
pub const MD_CONTEXT_PPC: ::libc::c_uint = 536870912;
pub const MD_CONTEXT_PPC64: ::libc::c_uint = 16777216;
pub const MD_FLOATINGSAVEAREA_SPARC_FPR_COUNT: ::libc::c_uint = 32;
pub const MD_CONTEXT_SPARC_GPR_COUNT: ::libc::c_uint = 32;
pub const MD_CONTEXT_SPARC: ::libc::c_uint = 268435456;
pub const MD_FLOATINGSAVEAREA_X86_REGISTERAREA_SIZE: ::libc::c_uint = 80;
pub const MD_CONTEXT_X86_EXTENDED_REGISTERS_SIZE: ::libc::c_uint = 512;
pub const MD_CONTEXT_X86: ::libc::c_uint = 65536;
pub const MD_VSFIXEDFILEINFO_SIGNATURE: ::libc::c_uint = 4277077181;
pub const MD_VSFIXEDFILEINFO_VERSION: ::libc::c_uint = 65536;
pub const MD_VSFIXEDFILEINFO_FILE_FLAGS_DEBUG: ::libc::c_uint = 1;
pub const MD_VSFIXEDFILEINFO_FILE_FLAGS_PRERELEASE: ::libc::c_uint = 2;
pub const MD_VSFIXEDFILEINFO_FILE_FLAGS_PATCHED: ::libc::c_uint = 4;
pub const MD_VSFIXEDFILEINFO_FILE_FLAGS_PRIVATEBUILD: ::libc::c_uint = 8;
pub const MD_VSFIXEDFILEINFO_FILE_FLAGS_INFOINFERRED: ::libc::c_uint = 16;
pub const MD_VSFIXEDFILEINFO_FILE_FLAGS_SPECIALBUILD: ::libc::c_uint = 32;
pub const MD_VSFIXEDFILEINFO_FILE_OS_UNKNOWN: ::libc::c_uint = 0;
pub const MD_VSFIXEDFILEINFO_FILE_OS_DOS: ::libc::c_uint = 1 << 16;
pub const MD_VSFIXEDFILEINFO_FILE_OS_OS216: ::libc::c_uint = 2 << 16;
pub const MD_VSFIXEDFILEINFO_FILE_OS_OS232: ::libc::c_uint = 3 << 16;
pub const MD_VSFIXEDFILEINFO_FILE_OS_NT: ::libc::c_uint = 4 << 16;
pub const MD_VSFIXEDFILEINFO_FILE_OS_WINCE: ::libc::c_uint = 5 << 16;
pub const MD_VSFIXEDFILEINFO_FILE_OS__BASE: ::libc::c_uint = 0;
pub const MD_VSFIXEDFILEINFO_FILE_OS__WINDOWS16: ::libc::c_uint = 1;
pub const MD_VSFIXEDFILEINFO_FILE_OS__PM16: ::libc::c_uint = 2;
pub const MD_VSFIXEDFILEINFO_FILE_OS__PM32: ::libc::c_uint = 3;
pub const MD_VSFIXEDFILEINFO_FILE_OS__WINDOWS32: ::libc::c_uint = 4;
pub const MD_VSFIXEDFILEINFO_FILE_TYPE_UNKNOWN: ::libc::c_uint = 0;
pub const MD_VSFIXEDFILEINFO_FILE_TYPE_APP: ::libc::c_uint = 1;
pub const MD_VSFIXEDFILEINFO_FILE_TYPE_DLL: ::libc::c_uint = 2;
pub const MD_VSFIXEDFILEINFO_FILE_TYPE_DRV: ::libc::c_uint = 3;
pub const MD_VSFIXEDFILEINFO_FILE_TYPE_FONT: ::libc::c_uint = 4;
pub const MD_VSFIXEDFILEINFO_FILE_TYPE_VXD: ::libc::c_uint = 5;
pub const MD_VSFIXEDFILEINFO_FILE_TYPE_STATIC_LIB: ::libc::c_uint = 7;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_UNKNOWN: ::libc::c_uint = 0;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_PRINTER: ::libc::c_uint = 1;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_KEYBOARD: ::libc::c_uint = 2;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_LANGUAGE: ::libc::c_uint = 3;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_DISPLAY: ::libc::c_uint = 4;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_MOUSE: ::libc::c_uint = 5;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_NETWORK: ::libc::c_uint = 6;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_SYSTEM: ::libc::c_uint = 7;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_INSTALLABLE: ::libc::c_uint = 8;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_SOUND: ::libc::c_uint = 9;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_COMM: ::libc::c_uint = 10;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_INPUTMETHOD: ::libc::c_uint = 11;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_DRV_VERSIONED_PRINTER: ::libc::c_uint = 12;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_FONT_RASTER: ::libc::c_uint = 1;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_FONT_VECTOR: ::libc::c_uint = 2;
pub const MD_VSFIXEDFILEINFO_FILE_SUBTYPE_FONT_TRUETYPE: ::libc::c_uint = 3;
pub const MD_HEADER_SIGNATURE: ::libc::c_uint = 1347241037;
pub const MD_HEADER_VERSION: ::libc::c_uint = 42899;
pub const MD_MODULE_SIZE: ::libc::c_uint = 108;
pub const MD_CVINFOPDB20_SIGNATURE: ::libc::c_uint = 808534606;
pub const MD_CVINFOPDB70_SIGNATURE: ::libc::c_uint = 1396986706;
pub const MD_CVINFOELF_SIGNATURE: ::libc::c_uint = 1114654028;
pub const MD_CVINFOCV41_SIGNATURE: ::libc::c_uint = 959464014;
pub const MD_CVINFOCV50_SIGNATURE: ::libc::c_uint = 825311822;
pub const MD_CVINFOUNKNOWN_SIGNATURE: ::libc::c_uint = 4294967295;
pub const MD_EXCEPTION_MAXIMUM_PARAMETERS: ::libc::c_uint = 15;
pub const MD_MAX_PATH: ::libc::c_uint = 260;

#[derive(Clone, Pread, SizeWith)]
pub struct MDGUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextBase {
    pub context_flags: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDXmmSaveArea32AMD64 {
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

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextAMD64 {
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
    /// This is defined as a union in the C headers, but also
    /// ` MAXIMUM_SUPPORTED_EXTENSION` is defined as 512 bytes.
    ///
    /// Callers that want to access the underlying data can use `Pread` to read either
    /// an `MDXmmSaveArea32AMD64` or `SSERegisters` struct from this raw data as appropriate.
    pub float_save: [u8; 512],
    pub vector_register: [u128; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

/// This is defined as an anonymous struct inside an anonymous union in
/// the x86-64 CONTEXT struct in winnt.h.
#[derive(Clone, Pread, SizeWith)]
pub struct SSERegisters {
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

#[derive(Clone, Pread, SizeWith)]
pub struct MDFloatingSaveAreaARM {
    pub fpscr: u64,
    pub regs: [u64; 32usize],
    pub extra: [u32; 8usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextARM {
    pub context_flags: u32,
    pub iregs: [u32; 16usize],
    pub cpsr: u32,
    pub float_save: MDFloatingSaveAreaARM,
}

pub type Enum_MDARMRegisterNumbers = ::libc::c_uint;
pub const MD_CONTEXT_ARM_REG_IOS_FP: ::libc::c_uint = 7;
pub const MD_CONTEXT_ARM_REG_FP: ::libc::c_uint = 11;
pub const MD_CONTEXT_ARM_REG_SP: ::libc::c_uint = 13;
pub const MD_CONTEXT_ARM_REG_LR: ::libc::c_uint = 14;
pub const MD_CONTEXT_ARM_REG_PC: ::libc::c_uint = 15;

#[derive(Clone, Pread, SizeWith)]
pub struct MDFloatingSaveAreaARM64 {
    pub fpsr: u32,
    pub fpcr: u32,
    pub regs: [u128; 32usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextARM64 {
    pub context_flags: u64,
    pub iregs: [u64; 33usize],
    pub cpsr: u32,
    pub float_save: MDFloatingSaveAreaARM64,
}

pub type Enum_MDARM64RegisterNumbers = ::libc::c_uint;
pub const MD_CONTEXT_ARM64_REG_FP: ::libc::c_uint = 29;
pub const MD_CONTEXT_ARM64_REG_LR: ::libc::c_uint = 30;
pub const MD_CONTEXT_ARM64_REG_SP: ::libc::c_uint = 31;
pub const MD_CONTEXT_ARM64_REG_PC: ::libc::c_uint = 32;

#[derive(Clone, Pread, SizeWith)]
pub struct MDFloatingSaveAreaMIPS {
    pub regs: [u64; 32usize],
    pub fpcsr: u32,
    pub fir: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextMIPS {
    pub context_flags: u32,
    pub _pad0: u32,
    pub iregs: [u64; 32usize],
    pub mdhi: u64,
    pub mdlo: u64,
    pub hi: [u32; 3usize],
    pub lo: [u32; 3usize],
    pub dsp_control: u32,
    pub _pad1: u32,
    pub epc: u64,
    pub badvaddr: u64,
    pub status: u32,
    pub cause: u32,
    pub float_save: MDFloatingSaveAreaMIPS,
}

pub type Enum_MDMIPSRegisterNumbers = ::libc::c_uint;
pub const MD_CONTEXT_MIPS_REG_S0: ::libc::c_uint = 16;
pub const MD_CONTEXT_MIPS_REG_S1: ::libc::c_uint = 17;
pub const MD_CONTEXT_MIPS_REG_S2: ::libc::c_uint = 18;
pub const MD_CONTEXT_MIPS_REG_S3: ::libc::c_uint = 19;
pub const MD_CONTEXT_MIPS_REG_S4: ::libc::c_uint = 20;
pub const MD_CONTEXT_MIPS_REG_S5: ::libc::c_uint = 21;
pub const MD_CONTEXT_MIPS_REG_S6: ::libc::c_uint = 22;
pub const MD_CONTEXT_MIPS_REG_S7: ::libc::c_uint = 23;
pub const MD_CONTEXT_MIPS_REG_GP: ::libc::c_uint = 28;
pub const MD_CONTEXT_MIPS_REG_SP: ::libc::c_uint = 29;
pub const MD_CONTEXT_MIPS_REG_FP: ::libc::c_uint = 30;
pub const MD_CONTEXT_MIPS_REG_RA: ::libc::c_uint = 31;

#[derive(Clone, Pread, SizeWith)]
pub struct MDFloatingSaveAreaPPC {
    pub fpregs: [u64; 32usize],
    pub fpscr_pad: u32,
    pub fpscr: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDVectorSaveAreaPPC {
    pub save_vr: [u128; 32usize],
    pub save_vscr: u128,
    pub save_pad5: [u32; 4usize],
    pub save_vrvalid: u32,
    pub save_pad6: [u32; 7usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextPPC {
    pub context_flags: u32,
    pub srr0: u32,
    pub srr1: u32,
    pub gpr: [u32; 32usize],
    pub cr: u32,
    pub xer: u32,
    pub lr: u32,
    pub ctr: u32,
    pub mq: u32,
    pub vrsave: u32,
    pub float_save: MDFloatingSaveAreaPPC,
    pub vector_save: MDVectorSaveAreaPPC,
}

pub type Enum_MDPPCRegisterNumbers = ::libc::c_uint;
pub const MD_CONTEXT_PPC_REG_SP: ::libc::c_uint = 1;
pub type MDFloatingSaveAreaPPC64 = MDFloatingSaveAreaPPC;
pub type MDVectorSaveAreaPPC64 = MDVectorSaveAreaPPC;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextPPC64 {
    pub context_flags: u64,
    pub srr0: u64,
    pub srr1: u64,
    pub gpr: [u64; 32usize],
    pub cr: u64,
    pub xer: u64,
    pub lr: u64,
    pub ctr: u64,
    pub vrsave: u64,
    pub float_save: MDFloatingSaveAreaPPC,
    pub vector_save: MDVectorSaveAreaPPC,
}

pub type Enum_MDPPC64RegisterNumbers = ::libc::c_uint;
pub const MD_CONTEXT_PPC64_REG_SP: ::libc::c_uint = 1;

#[derive(Clone, Pread, SizeWith)]
pub struct MDFloatingSaveAreaSPARC {
    pub regs: [u64; 32usize],
    pub filler: u64,
    pub fsr: u64,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawContextSPARC {
    pub context_flags: u32,
    pub flag_pad: u32,
    pub g_r: [u64; 32usize],
    pub ccr: u64,
    pub pc: u64,
    pub npc: u64,
    pub y: u64,
    pub asi: u64,
    pub fprs: u64,
    pub float_save: MDFloatingSaveAreaSPARC,
}

pub type Enum_MDSPARCRegisterNumbers = ::libc::c_uint;
pub const MD_CONTEXT_SPARC_REG_SP: ::libc::c_uint = 14;

#[derive(Clone, SmartDefault, Pread, SizeWith)]
pub struct MDFloatingSaveAreaX86 {
    pub control_word: u32,
    pub status_word: u32,
    pub tag_word: u32,
    pub error_offset: u32,
    pub error_selector: u32,
    pub data_offset: u32,
    pub data_selector: u32,
    #[default = "[0; 80]"]
    pub register_area: [u8; 80usize],
    pub cr0_npx_state: u32,
}

#[derive(Clone, SmartDefault, Pread, SizeWith)]
pub struct MDRawContextX86 {
    pub context_flags: u32,
    pub dr0: u32,
    pub dr1: u32,
    pub dr2: u32,
    pub dr3: u32,
    pub dr6: u32,
    pub dr7: u32,
    pub float_save: MDFloatingSaveAreaX86,
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
    pub extended_registers: [u8; 512usize],
}

#[derive(Clone, Default, Pread, SizeWith)]
pub struct MDVSFixedFileInfo {
    pub signature: u32,
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

pub type MDRVA = u32;

#[derive(Copy, Default, Clone, Pread, SizeWith)]
pub struct MDLocationDescriptor {
    pub data_size: u32,
    pub rva: MDRVA,
}

#[derive(Copy, Clone, Default, Pread, SizeWith)]
pub struct MDMemoryDescriptor {
    pub start_of_memory_range: u64,
    pub memory: MDLocationDescriptor,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawHeader {
    pub signature: u32,
    pub version: u32,
    pub stream_count: u32,
    pub stream_directory_rva: MDRVA,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub flags: u64,
}

pub type Enum_Unnamed26 = ::libc::c_uint;
pub const MD_NORMAL: ::libc::c_uint = 0;
pub const MD_WITH_DATA_SEGS: ::libc::c_uint = 1;
pub const MD_WITH_FULL_MEMORY: ::libc::c_uint = 2;
pub const MD_WITH_HANDLE_DATA: ::libc::c_uint = 4;
pub const MD_FILTER_MEMORY: ::libc::c_uint = 8;
pub const MD_SCAN_MEMORY: ::libc::c_uint = 16;
pub const MD_WITH_UNLOADED_MODULES: ::libc::c_uint = 32;
pub const MD_WITH_INDIRECTLY_REFERENCED_MEMORY: ::libc::c_uint = 64;
pub const MD_FILTER_MODULE_PATHS: ::libc::c_uint = 128;
pub const MD_WITH_PROCESS_THREAD_DATA: ::libc::c_uint = 256;
pub const MD_WITH_PRIVATE_READ_WRITE_MEMORY: ::libc::c_uint = 512;
pub const MD_WITHOUT_OPTIONAL_DATA: ::libc::c_uint = 1024;
pub const MD_WITH_FULL_MEMORY_INFO: ::libc::c_uint = 2048;
pub const MD_WITH_THREAD_INFO: ::libc::c_uint = 4096;
pub const MD_WITH_CODE_SEGS: ::libc::c_uint = 8192;
pub const MD_WITHOUT_AUXILLIARY_SEGS: ::libc::c_uint = 16384;
pub const MD_WITH_FULL_AUXILLIARY_STATE: ::libc::c_uint = 32768;
pub const MD_WITH_PRIVATE_WRITE_COPY_MEMORY: ::libc::c_uint = 65536;
pub const MD_IGNORE_INACCESSIBLE_MEMORY: ::libc::c_uint = 131072;
pub const MD_WITH_TOKEN_INFORMATION: ::libc::c_uint = 262144;
pub type MDType = Enum_Unnamed26;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawDirectory {
    pub stream_type: u32,
    pub location: MDLocationDescriptor,
}

pub type Enum_Unnamed28 = ::libc::c_uint;
pub const MD_UNUSED_STREAM: ::libc::c_uint = 0;
pub const MD_RESERVED_STREAM_0: ::libc::c_uint = 1;
pub const MD_RESERVED_STREAM_1: ::libc::c_uint = 2;
pub const MD_THREAD_LIST_STREAM: ::libc::c_uint = 3;
pub const MD_MODULE_LIST_STREAM: ::libc::c_uint = 4;
pub const MD_MEMORY_LIST_STREAM: ::libc::c_uint = 5;
pub const MD_EXCEPTION_STREAM: ::libc::c_uint = 6;
pub const MD_SYSTEM_INFO_STREAM: ::libc::c_uint = 7;
pub const MD_THREAD_EX_LIST_STREAM: ::libc::c_uint = 8;
pub const MD_MEMORY_64_LIST_STREAM: ::libc::c_uint = 9;
pub const MD_COMMENT_STREAM_A: ::libc::c_uint = 10;
pub const MD_COMMENT_STREAM_W: ::libc::c_uint = 11;
pub const MD_HANDLE_DATA_STREAM: ::libc::c_uint = 12;
pub const MD_FUNCTION_TABLE_STREAM: ::libc::c_uint = 13;
pub const MD_UNLOADED_MODULE_LIST_STREAM: ::libc::c_uint = 14;
pub const MD_MISC_INFO_STREAM: ::libc::c_uint = 15;
pub const MD_MEMORY_INFO_LIST_STREAM: ::libc::c_uint = 16;
pub const MD_THREAD_INFO_LIST_STREAM: ::libc::c_uint = 17;
pub const MD_HANDLE_OPERATION_LIST_STREAM: ::libc::c_uint = 18;
pub const MD_LAST_RESERVED_STREAM: ::libc::c_uint = 65535;
pub const MD_BREAKPAD_INFO_STREAM: ::libc::c_uint = 1197932545;
pub const MD_ASSERTION_INFO_STREAM: ::libc::c_uint = 1197932546;
pub const MD_LINUX_CPU_INFO: ::libc::c_uint = 1197932547;
pub const MD_LINUX_PROC_STATUS: ::libc::c_uint = 1197932548;
pub const MD_LINUX_LSB_RELEASE: ::libc::c_uint = 1197932549;
pub const MD_LINUX_CMD_LINE: ::libc::c_uint = 1197932550;
pub const MD_LINUX_ENVIRON: ::libc::c_uint = 1197932551;
pub const MD_LINUX_AUXV: ::libc::c_uint = 1197932552;
pub const MD_LINUX_MAPS: ::libc::c_uint = 1197932553;
pub const MD_LINUX_DSO_DEBUG: ::libc::c_uint = 1197932554;
pub type MDStreamType = Enum_Unnamed28;

#[derive(Clone, Pread, SizeWith)]
pub struct MDString {
    pub length: u32,
    pub buffer: [u16; 1usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawThread {
    pub thread_id: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64,
    pub stack: MDMemoryDescriptor,
    pub thread_context: MDLocationDescriptor,
}

#[derive(Clone, Default, Pread, SizeWith)]
pub struct MDRawModule {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub module_name_rva: MDRVA,
    pub version_info: MDVSFixedFileInfo,
    pub cv_record: MDLocationDescriptor,
    pub misc_record: MDLocationDescriptor,
    pub reserved0: [u32; 2usize],
    pub reserved1: [u32; 2usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDCVHeader {
    pub signature: u32,
    pub offset: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDCVInfoPDB20 {
    pub cv_header: MDCVHeader,
    pub signature: u32,
    pub age: u32,
    // This is a variable-length byte array.
    // pub pdb_file_name: [u8; 1usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDCVInfoPDB70 {
    pub cv_signature: u32,
    pub signature: MDGUID,
    pub age: u32,
    // This is a variable-length byte array.
    //pub pdb_file_name: [u8; 1usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDCVInfoELF {
    pub cv_signature: u32,
    // This is a variable-length byte array.
    //pub build_id: [u8; 1usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDImageDebugMisc {
    pub data_type: u32,
    pub length: u32,
    pub unicode: u8,
    pub reserved: [u8; 3usize],
    pub data: [u8; 1usize],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDException {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    pub __align: u32,
    pub exception_information: [u64; 15usize],
}

pub type Enum_Unnamed41 = ::libc::c_uint;
pub const MD_EXCEPTION_CODE_LIN_SIGHUP: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_LIN_SIGINT: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_LIN_SIGQUIT: ::libc::c_uint = 3;
pub const MD_EXCEPTION_CODE_LIN_SIGILL: ::libc::c_uint = 4;
pub const MD_EXCEPTION_CODE_LIN_SIGTRAP: ::libc::c_uint = 5;
pub const MD_EXCEPTION_CODE_LIN_SIGABRT: ::libc::c_uint = 6;
pub const MD_EXCEPTION_CODE_LIN_SIGBUS: ::libc::c_uint = 7;
pub const MD_EXCEPTION_CODE_LIN_SIGFPE: ::libc::c_uint = 8;
pub const MD_EXCEPTION_CODE_LIN_SIGKILL: ::libc::c_uint = 9;
pub const MD_EXCEPTION_CODE_LIN_SIGUSR1: ::libc::c_uint = 10;
pub const MD_EXCEPTION_CODE_LIN_SIGSEGV: ::libc::c_uint = 11;
pub const MD_EXCEPTION_CODE_LIN_SIGUSR2: ::libc::c_uint = 12;
pub const MD_EXCEPTION_CODE_LIN_SIGPIPE: ::libc::c_uint = 13;
pub const MD_EXCEPTION_CODE_LIN_SIGALRM: ::libc::c_uint = 14;
pub const MD_EXCEPTION_CODE_LIN_SIGTERM: ::libc::c_uint = 15;
pub const MD_EXCEPTION_CODE_LIN_SIGSTKFLT: ::libc::c_uint = 16;
pub const MD_EXCEPTION_CODE_LIN_SIGCHLD: ::libc::c_uint = 17;
pub const MD_EXCEPTION_CODE_LIN_SIGCONT: ::libc::c_uint = 18;
pub const MD_EXCEPTION_CODE_LIN_SIGSTOP: ::libc::c_uint = 19;
pub const MD_EXCEPTION_CODE_LIN_SIGTSTP: ::libc::c_uint = 20;
pub const MD_EXCEPTION_CODE_LIN_SIGTTIN: ::libc::c_uint = 21;
pub const MD_EXCEPTION_CODE_LIN_SIGTTOU: ::libc::c_uint = 22;
pub const MD_EXCEPTION_CODE_LIN_SIGURG: ::libc::c_uint = 23;
pub const MD_EXCEPTION_CODE_LIN_SIGXCPU: ::libc::c_uint = 24;
pub const MD_EXCEPTION_CODE_LIN_SIGXFSZ: ::libc::c_uint = 25;
pub const MD_EXCEPTION_CODE_LIN_SIGVTALRM: ::libc::c_uint = 26;
pub const MD_EXCEPTION_CODE_LIN_SIGPROF: ::libc::c_uint = 27;
pub const MD_EXCEPTION_CODE_LIN_SIGWINCH: ::libc::c_uint = 28;
pub const MD_EXCEPTION_CODE_LIN_SIGIO: ::libc::c_uint = 29;
pub const MD_EXCEPTION_CODE_LIN_SIGPWR: ::libc::c_uint = 30;
pub const MD_EXCEPTION_CODE_LIN_SIGSYS: ::libc::c_uint = 31;
pub const MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED: ::libc::c_uint = 4294967295;
pub type MDExceptionCodeLinux = Enum_Unnamed41;
pub type Enum_Unnamed42 = ::libc::c_uint;
pub const MD_EXCEPTION_MAC_BAD_ACCESS: ::libc::c_uint = 1;
pub const MD_EXCEPTION_MAC_BAD_INSTRUCTION: ::libc::c_uint = 2;
pub const MD_EXCEPTION_MAC_ARITHMETIC: ::libc::c_uint = 3;
pub const MD_EXCEPTION_MAC_EMULATION: ::libc::c_uint = 4;
pub const MD_EXCEPTION_MAC_SOFTWARE: ::libc::c_uint = 5;
pub const MD_EXCEPTION_MAC_BREAKPOINT: ::libc::c_uint = 6;
pub const MD_EXCEPTION_MAC_SYSCALL: ::libc::c_uint = 7;
pub const MD_EXCEPTION_MAC_MACH_SYSCALL: ::libc::c_uint = 8;
pub const MD_EXCEPTION_MAC_RPC_ALERT: ::libc::c_uint = 9;
pub type MDExceptionMac = Enum_Unnamed42;
pub type Enum_Unnamed43 = ::libc::c_uint;
pub const MD_EXCEPTION_CODE_MAC_INVALID_ADDRESS: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_PROTECTION_FAILURE: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_MAC_NO_ACCESS: ::libc::c_uint = 8;
pub const MD_EXCEPTION_CODE_MAC_MEMORY_FAILURE: ::libc::c_uint = 9;
pub const MD_EXCEPTION_CODE_MAC_MEMORY_ERROR: ::libc::c_uint = 10;
pub const MD_EXCEPTION_CODE_MAC_BAD_SYSCALL: ::libc::c_uint = 65536;
pub const MD_EXCEPTION_CODE_MAC_BAD_PIPE: ::libc::c_uint = 65537;
pub const MD_EXCEPTION_CODE_MAC_ABORT: ::libc::c_uint = 65538;
pub const MD_EXCEPTION_CODE_MAC_NS_EXCEPTION: ::libc::c_uint = 3735929054;
pub const MD_EXCEPTION_CODE_MAC_ARM_DA_ALIGN: ::libc::c_uint = 257;
pub const MD_EXCEPTION_CODE_MAC_ARM_DA_DEBUG: ::libc::c_uint = 258;
pub const MD_EXCEPTION_CODE_MAC_ARM_UNDEFINED: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_ARM_BREAKPOINT: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_PPC_VM_PROT_READ: ::libc::c_uint = 257;
pub const MD_EXCEPTION_CODE_MAC_PPC_BADSPACE: ::libc::c_uint = 258;
pub const MD_EXCEPTION_CODE_MAC_PPC_UNALIGNED: ::libc::c_uint = 259;
pub const MD_EXCEPTION_CODE_MAC_PPC_INVALID_SYSCALL: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_PPC_UNIMPLEMENTED_INSTRUCTION: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_MAC_PPC_PRIVILEGED_INSTRUCTION: ::libc::c_uint = 3;
pub const MD_EXCEPTION_CODE_MAC_PPC_PRIVILEGED_REGISTER: ::libc::c_uint = 4;
pub const MD_EXCEPTION_CODE_MAC_PPC_TRACE: ::libc::c_uint = 5;
pub const MD_EXCEPTION_CODE_MAC_PPC_PERFORMANCE_MONITOR: ::libc::c_uint = 6;
pub const MD_EXCEPTION_CODE_MAC_PPC_OVERFLOW: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_PPC_ZERO_DIVIDE: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_MAC_PPC_FLOAT_INEXACT: ::libc::c_uint = 3;
pub const MD_EXCEPTION_CODE_MAC_PPC_FLOAT_ZERO_DIVIDE: ::libc::c_uint = 4;
pub const MD_EXCEPTION_CODE_MAC_PPC_FLOAT_UNDERFLOW: ::libc::c_uint = 5;
pub const MD_EXCEPTION_CODE_MAC_PPC_FLOAT_OVERFLOW: ::libc::c_uint = 6;
pub const MD_EXCEPTION_CODE_MAC_PPC_FLOAT_NOT_A_NUMBER: ::libc::c_uint = 7;
pub const MD_EXCEPTION_CODE_MAC_PPC_NO_EMULATION: ::libc::c_uint = 8;
pub const MD_EXCEPTION_CODE_MAC_PPC_ALTIVEC_ASSIST: ::libc::c_uint = 9;
pub const MD_EXCEPTION_CODE_MAC_PPC_TRAP: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_PPC_MIGRATE: ::libc::c_uint = 65792;
pub const MD_EXCEPTION_CODE_MAC_PPC_BREAKPOINT: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_X86_INVALID_OPERATION: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_X86_DIV: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_X86_INTO: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_MAC_X86_NOEXT: ::libc::c_uint = 3;
pub const MD_EXCEPTION_CODE_MAC_X86_EXTOVR: ::libc::c_uint = 4;
pub const MD_EXCEPTION_CODE_MAC_X86_EXTERR: ::libc::c_uint = 5;
pub const MD_EXCEPTION_CODE_MAC_X86_EMERR: ::libc::c_uint = 6;
pub const MD_EXCEPTION_CODE_MAC_X86_BOUND: ::libc::c_uint = 7;
pub const MD_EXCEPTION_CODE_MAC_X86_SSEEXTERR: ::libc::c_uint = 8;
pub const MD_EXCEPTION_CODE_MAC_X86_SGL: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_MAC_X86_BPT: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_MAC_X86_INVALID_TASK_STATE_SEGMENT: ::libc::c_uint = 10;
pub const MD_EXCEPTION_CODE_MAC_X86_SEGMENT_NOT_PRESENT: ::libc::c_uint = 11;
pub const MD_EXCEPTION_CODE_MAC_X86_STACK_FAULT: ::libc::c_uint = 12;
pub const MD_EXCEPTION_CODE_MAC_X86_GENERAL_PROTECTION_FAULT: ::libc::c_uint = 13;
pub const MD_EXCEPTION_CODE_MAC_X86_ALIGNMENT_FAULT: ::libc::c_uint = 17;
pub type MDExceptionCodeMac = Enum_Unnamed43;
pub type Enum_Unnamed44 = ::libc::c_uint;
pub const MD_EXCEPTION_CODE_PS3_UNKNOWN: ::libc::c_uint = 0;
pub const MD_EXCEPTION_CODE_PS3_TRAP_EXCEP: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_PS3_PRIV_INSTR: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_PS3_ILLEGAL_INSTR: ::libc::c_uint = 3;
pub const MD_EXCEPTION_CODE_PS3_INSTR_STORAGE: ::libc::c_uint = 4;
pub const MD_EXCEPTION_CODE_PS3_INSTR_SEGMENT: ::libc::c_uint = 5;
pub const MD_EXCEPTION_CODE_PS3_DATA_STORAGE: ::libc::c_uint = 6;
pub const MD_EXCEPTION_CODE_PS3_DATA_SEGMENT: ::libc::c_uint = 7;
pub const MD_EXCEPTION_CODE_PS3_FLOAT_POINT: ::libc::c_uint = 8;
pub const MD_EXCEPTION_CODE_PS3_DABR_MATCH: ::libc::c_uint = 9;
pub const MD_EXCEPTION_CODE_PS3_ALIGN_EXCEP: ::libc::c_uint = 10;
pub const MD_EXCEPTION_CODE_PS3_MEMORY_ACCESS: ::libc::c_uint = 11;
pub const MD_EXCEPTION_CODE_PS3_COPRO_ALIGN: ::libc::c_uint = 12;
pub const MD_EXCEPTION_CODE_PS3_COPRO_INVALID_COM: ::libc::c_uint = 13;
pub const MD_EXCEPTION_CODE_PS3_COPRO_ERR: ::libc::c_uint = 14;
pub const MD_EXCEPTION_CODE_PS3_COPRO_FIR: ::libc::c_uint = 15;
pub const MD_EXCEPTION_CODE_PS3_COPRO_DATA_SEGMENT: ::libc::c_uint = 16;
pub const MD_EXCEPTION_CODE_PS3_COPRO_DATA_STORAGE: ::libc::c_uint = 17;
pub const MD_EXCEPTION_CODE_PS3_COPRO_STOP_INSTR: ::libc::c_uint = 18;
pub const MD_EXCEPTION_CODE_PS3_COPRO_HALT_INSTR: ::libc::c_uint = 19;
pub const MD_EXCEPTION_CODE_PS3_COPRO_HALTINST_UNKNOWN: ::libc::c_uint = 20;
pub const MD_EXCEPTION_CODE_PS3_COPRO_MEMORY_ACCESS: ::libc::c_uint = 21;
pub const MD_EXCEPTION_CODE_PS3_GRAPHIC: ::libc::c_uint = 22;
pub type MDExceptionCodePS3 = Enum_Unnamed44;
pub type Enum_Unnamed45 = ::libc::c_uint;
pub const MD_EXCEPTION_CODE_SOL_SIGHUP: ::libc::c_uint = 1;
pub const MD_EXCEPTION_CODE_SOL_SIGINT: ::libc::c_uint = 2;
pub const MD_EXCEPTION_CODE_SOL_SIGQUIT: ::libc::c_uint = 3;
pub const MD_EXCEPTION_CODE_SOL_SIGILL: ::libc::c_uint = 4;
pub const MD_EXCEPTION_CODE_SOL_SIGTRAP: ::libc::c_uint = 5;
pub const MD_EXCEPTION_CODE_SOL_SIGIOT: ::libc::c_uint = 6;
pub const MD_EXCEPTION_CODE_SOL_SIGABRT: ::libc::c_uint = 6;
pub const MD_EXCEPTION_CODE_SOL_SIGEMT: ::libc::c_uint = 7;
pub const MD_EXCEPTION_CODE_SOL_SIGFPE: ::libc::c_uint = 8;
pub const MD_EXCEPTION_CODE_SOL_SIGKILL: ::libc::c_uint = 9;
pub const MD_EXCEPTION_CODE_SOL_SIGBUS: ::libc::c_uint = 10;
pub const MD_EXCEPTION_CODE_SOL_SIGSEGV: ::libc::c_uint = 11;
pub const MD_EXCEPTION_CODE_SOL_SIGSYS: ::libc::c_uint = 12;
pub const MD_EXCEPTION_CODE_SOL_SIGPIPE: ::libc::c_uint = 13;
pub const MD_EXCEPTION_CODE_SOL_SIGALRM: ::libc::c_uint = 14;
pub const MD_EXCEPTION_CODE_SOL_SIGTERM: ::libc::c_uint = 15;
pub const MD_EXCEPTION_CODE_SOL_SIGUSR1: ::libc::c_uint = 16;
pub const MD_EXCEPTION_CODE_SOL_SIGUSR2: ::libc::c_uint = 17;
pub const MD_EXCEPTION_CODE_SOL_SIGCLD: ::libc::c_uint = 18;
pub const MD_EXCEPTION_CODE_SOL_SIGCHLD: ::libc::c_uint = 18;
pub const MD_EXCEPTION_CODE_SOL_SIGPWR: ::libc::c_uint = 19;
pub const MD_EXCEPTION_CODE_SOL_SIGWINCH: ::libc::c_uint = 20;
pub const MD_EXCEPTION_CODE_SOL_SIGURG: ::libc::c_uint = 21;
pub const MD_EXCEPTION_CODE_SOL_SIGPOLL: ::libc::c_uint = 22;
pub const MD_EXCEPTION_CODE_SOL_SIGIO: ::libc::c_uint = 22;
pub const MD_EXCEPTION_CODE_SOL_SIGSTOP: ::libc::c_uint = 23;
pub const MD_EXCEPTION_CODE_SOL_SIGTSTP: ::libc::c_uint = 24;
pub const MD_EXCEPTION_CODE_SOL_SIGCONT: ::libc::c_uint = 25;
pub const MD_EXCEPTION_CODE_SOL_SIGTTIN: ::libc::c_uint = 26;
pub const MD_EXCEPTION_CODE_SOL_SIGTTOU: ::libc::c_uint = 27;
pub const MD_EXCEPTION_CODE_SOL_SIGVTALRM: ::libc::c_uint = 28;
pub const MD_EXCEPTION_CODE_SOL_SIGPROF: ::libc::c_uint = 29;
pub const MD_EXCEPTION_CODE_SOL_SIGXCPU: ::libc::c_uint = 30;
pub const MD_EXCEPTION_CODE_SOL_SIGXFSZ: ::libc::c_uint = 31;
pub const MD_EXCEPTION_CODE_SOL_SIGWAITING: ::libc::c_uint = 32;
pub const MD_EXCEPTION_CODE_SOL_SIGLWP: ::libc::c_uint = 33;
pub const MD_EXCEPTION_CODE_SOL_SIGFREEZE: ::libc::c_uint = 34;
pub const MD_EXCEPTION_CODE_SOL_SIGTHAW: ::libc::c_uint = 35;
pub const MD_EXCEPTION_CODE_SOL_SIGCANCEL: ::libc::c_uint = 36;
pub const MD_EXCEPTION_CODE_SOL_SIGLOST: ::libc::c_uint = 37;
pub const MD_EXCEPTION_CODE_SOL_SIGXRES: ::libc::c_uint = 38;
pub const MD_EXCEPTION_CODE_SOL_SIGJVM1: ::libc::c_uint = 39;
pub const MD_EXCEPTION_CODE_SOL_SIGJVM2: ::libc::c_uint = 40;
pub type MDExceptionCodeSolaris = Enum_Unnamed45;
pub type Enum_Unnamed46 = ::libc::c_uint;
pub const MD_EXCEPTION_CODE_WIN_CONTROL_C: ::libc::c_uint = 1073807365;
pub const MD_EXCEPTION_CODE_WIN_GUARD_PAGE_VIOLATION: ::libc::c_uint = 2147483649;
pub const MD_EXCEPTION_CODE_WIN_DATATYPE_MISALIGNMENT: ::libc::c_uint = 2147483650;
pub const MD_EXCEPTION_CODE_WIN_BREAKPOINT: ::libc::c_uint = 2147483651;
pub const MD_EXCEPTION_CODE_WIN_SINGLE_STEP: ::libc::c_uint = 2147483652;
pub const MD_EXCEPTION_CODE_WIN_ACCESS_VIOLATION: ::libc::c_uint = 3221225477;
pub const MD_EXCEPTION_CODE_WIN_IN_PAGE_ERROR: ::libc::c_uint = 3221225478;
pub const MD_EXCEPTION_CODE_WIN_INVALID_HANDLE: ::libc::c_uint = 3221225480;
pub const MD_EXCEPTION_CODE_WIN_ILLEGAL_INSTRUCTION: ::libc::c_uint = 3221225501;
pub const MD_EXCEPTION_CODE_WIN_NONCONTINUABLE_EXCEPTION: ::libc::c_uint = 3221225509;
pub const MD_EXCEPTION_CODE_WIN_INVALID_DISPOSITION: ::libc::c_uint = 3221225510;
pub const MD_EXCEPTION_CODE_WIN_ARRAY_BOUNDS_EXCEEDED: ::libc::c_uint = 3221225612;
pub const MD_EXCEPTION_CODE_WIN_FLOAT_DENORMAL_OPERAND: ::libc::c_uint = 3221225613;
pub const MD_EXCEPTION_CODE_WIN_FLOAT_DIVIDE_BY_ZERO: ::libc::c_uint = 3221225614;
pub const MD_EXCEPTION_CODE_WIN_FLOAT_INEXACT_RESULT: ::libc::c_uint = 3221225615;
pub const MD_EXCEPTION_CODE_WIN_FLOAT_INVALID_OPERATION: ::libc::c_uint = 3221225616;
pub const MD_EXCEPTION_CODE_WIN_FLOAT_OVERFLOW: ::libc::c_uint = 3221225617;
pub const MD_EXCEPTION_CODE_WIN_FLOAT_STACK_CHECK: ::libc::c_uint = 3221225618;
pub const MD_EXCEPTION_CODE_WIN_FLOAT_UNDERFLOW: ::libc::c_uint = 3221225619;
pub const MD_EXCEPTION_CODE_WIN_INTEGER_DIVIDE_BY_ZERO: ::libc::c_uint = 3221225620;
pub const MD_EXCEPTION_CODE_WIN_INTEGER_OVERFLOW: ::libc::c_uint = 3221225621;
pub const MD_EXCEPTION_CODE_WIN_PRIVILEGED_INSTRUCTION: ::libc::c_uint = 3221225622;
pub const MD_EXCEPTION_CODE_WIN_STACK_OVERFLOW: ::libc::c_uint = 3221225725;
pub const MD_EXCEPTION_CODE_WIN_POSSIBLE_DEADLOCK: ::libc::c_uint = 3221225876;
pub const MD_EXCEPTION_CODE_WIN_STACK_BUFFER_OVERRUN: ::libc::c_uint = 3221226505;
pub const MD_EXCEPTION_CODE_WIN_HEAP_CORRUPTION: ::libc::c_uint = 3221226356;
pub const MD_EXCEPTION_CODE_WIN_UNHANDLED_CPP_EXCEPTION: ::libc::c_uint = 3765269347;
pub type MDExceptionCodeWin = Enum_Unnamed46;
pub type Enum_Unnamed47 = ::libc::c_uint;
pub const MD_NTSTATUS_WIN_STATUS_UNSUCCESSFUL: ::libc::c_uint = 3221225473;
pub const MD_NTSTATUS_WIN_STATUS_NOT_IMPLEMENTED: ::libc::c_uint = 3221225474;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_INFO_CLASS: ::libc::c_uint = 3221225475;
pub const MD_NTSTATUS_WIN_STATUS_INFO_LENGTH_MISMATCH: ::libc::c_uint = 3221225476;
pub const MD_NTSTATUS_WIN_STATUS_ACCESS_VIOLATION: ::libc::c_uint = 3221225477;
pub const MD_NTSTATUS_WIN_STATUS_IN_PAGE_ERROR: ::libc::c_uint = 3221225478;
pub const MD_NTSTATUS_WIN_STATUS_PAGEFILE_QUOTA: ::libc::c_uint = 3221225479;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_HANDLE: ::libc::c_uint = 3221225480;
pub const MD_NTSTATUS_WIN_STATUS_BAD_INITIAL_STACK: ::libc::c_uint = 3221225481;
pub const MD_NTSTATUS_WIN_STATUS_BAD_INITIAL_PC: ::libc::c_uint = 3221225482;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_CID: ::libc::c_uint = 3221225483;
pub const MD_NTSTATUS_WIN_STATUS_TIMER_NOT_CANCELED: ::libc::c_uint = 3221225484;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER: ::libc::c_uint = 3221225485;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_DEVICE: ::libc::c_uint = 3221225486;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_FILE: ::libc::c_uint = 3221225487;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_DEVICE_REQUEST: ::libc::c_uint = 3221225488;
pub const MD_NTSTATUS_WIN_STATUS_END_OF_FILE: ::libc::c_uint = 3221225489;
pub const MD_NTSTATUS_WIN_STATUS_WRONG_VOLUME: ::libc::c_uint = 3221225490;
pub const MD_NTSTATUS_WIN_STATUS_NO_MEDIA_IN_DEVICE: ::libc::c_uint = 3221225491;
pub const MD_NTSTATUS_WIN_STATUS_UNRECOGNIZED_MEDIA: ::libc::c_uint = 3221225492;
pub const MD_NTSTATUS_WIN_STATUS_NONEXISTENT_SECTOR: ::libc::c_uint = 3221225493;
pub const MD_NTSTATUS_WIN_STATUS_MORE_PROCESSING_REQUIRED: ::libc::c_uint = 3221225494;
pub const MD_NTSTATUS_WIN_STATUS_NO_MEMORY: ::libc::c_uint = 3221225495;
pub const MD_NTSTATUS_WIN_STATUS_CONFLICTING_ADDRESSES: ::libc::c_uint = 3221225496;
pub const MD_NTSTATUS_WIN_STATUS_NOT_MAPPED_VIEW: ::libc::c_uint = 3221225497;
pub const MD_NTSTATUS_WIN_STATUS_UNABLE_TO_FREE_VM: ::libc::c_uint = 3221225498;
pub const MD_NTSTATUS_WIN_STATUS_UNABLE_TO_DELETE_SECTION: ::libc::c_uint = 3221225499;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_SYSTEM_SERVICE: ::libc::c_uint = 3221225500;
pub const MD_NTSTATUS_WIN_STATUS_ILLEGAL_INSTRUCTION: ::libc::c_uint = 3221225501;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LOCK_SEQUENCE: ::libc::c_uint = 3221225502;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_VIEW_SIZE: ::libc::c_uint = 3221225503;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_FILE_FOR_SECTION: ::libc::c_uint = 3221225504;
pub const MD_NTSTATUS_WIN_STATUS_ALREADY_COMMITTED: ::libc::c_uint = 3221225505;
pub const MD_NTSTATUS_WIN_STATUS_ACCESS_DENIED: ::libc::c_uint = 3221225506;
pub const MD_NTSTATUS_WIN_STATUS_BUFFER_TOO_SMALL: ::libc::c_uint = 3221225507;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_TYPE_MISMATCH: ::libc::c_uint = 3221225508;
pub const MD_NTSTATUS_WIN_STATUS_NONCONTINUABLE_EXCEPTION: ::libc::c_uint = 3221225509;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_DISPOSITION: ::libc::c_uint = 3221225510;
pub const MD_NTSTATUS_WIN_STATUS_UNWIND: ::libc::c_uint = 3221225511;
pub const MD_NTSTATUS_WIN_STATUS_BAD_STACK: ::libc::c_uint = 3221225512;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_UNWIND_TARGET: ::libc::c_uint = 3221225513;
pub const MD_NTSTATUS_WIN_STATUS_NOT_LOCKED: ::libc::c_uint = 3221225514;
pub const MD_NTSTATUS_WIN_STATUS_PARITY_ERROR: ::libc::c_uint = 3221225515;
pub const MD_NTSTATUS_WIN_STATUS_UNABLE_TO_DECOMMIT_VM: ::libc::c_uint = 3221225516;
pub const MD_NTSTATUS_WIN_STATUS_NOT_COMMITTED: ::libc::c_uint = 3221225517;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PORT_ATTRIBUTES: ::libc::c_uint = 3221225518;
pub const MD_NTSTATUS_WIN_STATUS_PORT_MESSAGE_TOO_LONG: ::libc::c_uint = 3221225519;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_MIX: ::libc::c_uint = 3221225520;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_QUOTA_LOWER: ::libc::c_uint = 3221225521;
pub const MD_NTSTATUS_WIN_STATUS_DISK_CORRUPT_ERROR: ::libc::c_uint = 3221225522;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_NAME_INVALID: ::libc::c_uint = 3221225523;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_NAME_NOT_FOUND: ::libc::c_uint = 3221225524;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_NAME_COLLISION: ::libc::c_uint = 3221225525;
pub const MD_NTSTATUS_WIN_STATUS_PORT_DISCONNECTED: ::libc::c_uint = 3221225527;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_ALREADY_ATTACHED: ::libc::c_uint = 3221225528;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_PATH_INVALID: ::libc::c_uint = 3221225529;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_PATH_NOT_FOUND: ::libc::c_uint = 3221225530;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_PATH_SYNTAX_BAD: ::libc::c_uint = 3221225531;
pub const MD_NTSTATUS_WIN_STATUS_DATA_OVERRUN: ::libc::c_uint = 3221225532;
pub const MD_NTSTATUS_WIN_STATUS_DATA_LATE_ERROR: ::libc::c_uint = 3221225533;
pub const MD_NTSTATUS_WIN_STATUS_DATA_ERROR: ::libc::c_uint = 3221225534;
pub const MD_NTSTATUS_WIN_STATUS_CRC_ERROR: ::libc::c_uint = 3221225535;
pub const MD_NTSTATUS_WIN_STATUS_SECTION_TOO_BIG: ::libc::c_uint = 3221225536;
pub const MD_NTSTATUS_WIN_STATUS_PORT_CONNECTION_REFUSED: ::libc::c_uint = 3221225537;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PORT_HANDLE: ::libc::c_uint = 3221225538;
pub const MD_NTSTATUS_WIN_STATUS_SHARING_VIOLATION: ::libc::c_uint = 3221225539;
pub const MD_NTSTATUS_WIN_STATUS_QUOTA_EXCEEDED: ::libc::c_uint = 3221225540;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PAGE_PROTECTION: ::libc::c_uint = 3221225541;
pub const MD_NTSTATUS_WIN_STATUS_MUTANT_NOT_OWNED: ::libc::c_uint = 3221225542;
pub const MD_NTSTATUS_WIN_STATUS_SEMAPHORE_LIMIT_EXCEEDED: ::libc::c_uint = 3221225543;
pub const MD_NTSTATUS_WIN_STATUS_PORT_ALREADY_SET: ::libc::c_uint = 3221225544;
pub const MD_NTSTATUS_WIN_STATUS_SECTION_NOT_IMAGE: ::libc::c_uint = 3221225545;
pub const MD_NTSTATUS_WIN_STATUS_SUSPEND_COUNT_EXCEEDED: ::libc::c_uint = 3221225546;
pub const MD_NTSTATUS_WIN_STATUS_THREAD_IS_TERMINATING: ::libc::c_uint = 3221225547;
pub const MD_NTSTATUS_WIN_STATUS_BAD_WORKING_SET_LIMIT: ::libc::c_uint = 3221225548;
pub const MD_NTSTATUS_WIN_STATUS_INCOMPATIBLE_FILE_MAP: ::libc::c_uint = 3221225549;
pub const MD_NTSTATUS_WIN_STATUS_SECTION_PROTECTION: ::libc::c_uint = 3221225550;
pub const MD_NTSTATUS_WIN_STATUS_EAS_NOT_SUPPORTED: ::libc::c_uint = 3221225551;
pub const MD_NTSTATUS_WIN_STATUS_EA_TOO_LARGE: ::libc::c_uint = 3221225552;
pub const MD_NTSTATUS_WIN_STATUS_NONEXISTENT_EA_ENTRY: ::libc::c_uint = 3221225553;
pub const MD_NTSTATUS_WIN_STATUS_NO_EAS_ON_FILE: ::libc::c_uint = 3221225554;
pub const MD_NTSTATUS_WIN_STATUS_EA_CORRUPT_ERROR: ::libc::c_uint = 3221225555;
pub const MD_NTSTATUS_WIN_STATUS_FILE_LOCK_CONFLICT: ::libc::c_uint = 3221225556;
pub const MD_NTSTATUS_WIN_STATUS_LOCK_NOT_GRANTED: ::libc::c_uint = 3221225557;
pub const MD_NTSTATUS_WIN_STATUS_DELETE_PENDING: ::libc::c_uint = 3221225558;
pub const MD_NTSTATUS_WIN_STATUS_CTL_FILE_NOT_SUPPORTED: ::libc::c_uint = 3221225559;
pub const MD_NTSTATUS_WIN_STATUS_UNKNOWN_REVISION: ::libc::c_uint = 3221225560;
pub const MD_NTSTATUS_WIN_STATUS_REVISION_MISMATCH: ::libc::c_uint = 3221225561;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_OWNER: ::libc::c_uint = 3221225562;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PRIMARY_GROUP: ::libc::c_uint = 3221225563;
pub const MD_NTSTATUS_WIN_STATUS_NO_IMPERSONATION_TOKEN: ::libc::c_uint = 3221225564;
pub const MD_NTSTATUS_WIN_STATUS_CANT_DISABLE_MANDATORY: ::libc::c_uint = 3221225565;
pub const MD_NTSTATUS_WIN_STATUS_NO_LOGON_SERVERS: ::libc::c_uint = 3221225566;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_LOGON_SESSION: ::libc::c_uint = 3221225567;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_PRIVILEGE: ::libc::c_uint = 3221225568;
pub const MD_NTSTATUS_WIN_STATUS_PRIVILEGE_NOT_HELD: ::libc::c_uint = 3221225569;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_ACCOUNT_NAME: ::libc::c_uint = 3221225570;
pub const MD_NTSTATUS_WIN_STATUS_USER_EXISTS: ::libc::c_uint = 3221225571;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_USER: ::libc::c_uint = 3221225572;
pub const MD_NTSTATUS_WIN_STATUS_GROUP_EXISTS: ::libc::c_uint = 3221225573;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_GROUP: ::libc::c_uint = 3221225574;
pub const MD_NTSTATUS_WIN_STATUS_MEMBER_IN_GROUP: ::libc::c_uint = 3221225575;
pub const MD_NTSTATUS_WIN_STATUS_MEMBER_NOT_IN_GROUP: ::libc::c_uint = 3221225576;
pub const MD_NTSTATUS_WIN_STATUS_LAST_ADMIN: ::libc::c_uint = 3221225577;
pub const MD_NTSTATUS_WIN_STATUS_WRONG_PASSWORD: ::libc::c_uint = 3221225578;
pub const MD_NTSTATUS_WIN_STATUS_ILL_FORMED_PASSWORD: ::libc::c_uint = 3221225579;
pub const MD_NTSTATUS_WIN_STATUS_PASSWORD_RESTRICTION: ::libc::c_uint = 3221225580;
pub const MD_NTSTATUS_WIN_STATUS_LOGON_FAILURE: ::libc::c_uint = 3221225581;
pub const MD_NTSTATUS_WIN_STATUS_ACCOUNT_RESTRICTION: ::libc::c_uint = 3221225582;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LOGON_HOURS: ::libc::c_uint = 3221225583;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_WORKSTATION: ::libc::c_uint = 3221225584;
pub const MD_NTSTATUS_WIN_STATUS_PASSWORD_EXPIRED: ::libc::c_uint = 3221225585;
pub const MD_NTSTATUS_WIN_STATUS_ACCOUNT_DISABLED: ::libc::c_uint = 3221225586;
pub const MD_NTSTATUS_WIN_STATUS_NONE_MAPPED: ::libc::c_uint = 3221225587;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_LUIDS_REQUESTED: ::libc::c_uint = 3221225588;
pub const MD_NTSTATUS_WIN_STATUS_LUIDS_EXHAUSTED: ::libc::c_uint = 3221225589;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_SUB_AUTHORITY: ::libc::c_uint = 3221225590;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_ACL: ::libc::c_uint = 3221225591;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_SID: ::libc::c_uint = 3221225592;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_SECURITY_DESCR: ::libc::c_uint = 3221225593;
pub const MD_NTSTATUS_WIN_STATUS_PROCEDURE_NOT_FOUND: ::libc::c_uint = 3221225594;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_FORMAT: ::libc::c_uint = 3221225595;
pub const MD_NTSTATUS_WIN_STATUS_NO_TOKEN: ::libc::c_uint = 3221225596;
pub const MD_NTSTATUS_WIN_STATUS_BAD_INHERITANCE_ACL: ::libc::c_uint = 3221225597;
pub const MD_NTSTATUS_WIN_STATUS_RANGE_NOT_LOCKED: ::libc::c_uint = 3221225598;
pub const MD_NTSTATUS_WIN_STATUS_DISK_FULL: ::libc::c_uint = 3221225599;
pub const MD_NTSTATUS_WIN_STATUS_SERVER_DISABLED: ::libc::c_uint = 3221225600;
pub const MD_NTSTATUS_WIN_STATUS_SERVER_NOT_DISABLED: ::libc::c_uint = 3221225601;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_GUIDS_REQUESTED: ::libc::c_uint = 3221225602;
pub const MD_NTSTATUS_WIN_STATUS_GUIDS_EXHAUSTED: ::libc::c_uint = 3221225603;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_ID_AUTHORITY: ::libc::c_uint = 3221225604;
pub const MD_NTSTATUS_WIN_STATUS_AGENTS_EXHAUSTED: ::libc::c_uint = 3221225605;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_VOLUME_LABEL: ::libc::c_uint = 3221225606;
pub const MD_NTSTATUS_WIN_STATUS_SECTION_NOT_EXTENDED: ::libc::c_uint = 3221225607;
pub const MD_NTSTATUS_WIN_STATUS_NOT_MAPPED_DATA: ::libc::c_uint = 3221225608;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCE_DATA_NOT_FOUND: ::libc::c_uint = 3221225609;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCE_TYPE_NOT_FOUND: ::libc::c_uint = 3221225610;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCE_NAME_NOT_FOUND: ::libc::c_uint = 3221225611;
pub const MD_NTSTATUS_WIN_STATUS_ARRAY_BOUNDS_EXCEEDED: ::libc::c_uint = 3221225612;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_DENORMAL_OPERAND: ::libc::c_uint = 3221225613;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_DIVIDE_BY_ZERO: ::libc::c_uint = 3221225614;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_INEXACT_RESULT: ::libc::c_uint = 3221225615;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_INVALID_OPERATION: ::libc::c_uint = 3221225616;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_OVERFLOW: ::libc::c_uint = 3221225617;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_STACK_CHECK: ::libc::c_uint = 3221225618;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_UNDERFLOW: ::libc::c_uint = 3221225619;
pub const MD_NTSTATUS_WIN_STATUS_INTEGER_DIVIDE_BY_ZERO: ::libc::c_uint = 3221225620;
pub const MD_NTSTATUS_WIN_STATUS_INTEGER_OVERFLOW: ::libc::c_uint = 3221225621;
pub const MD_NTSTATUS_WIN_STATUS_PRIVILEGED_INSTRUCTION: ::libc::c_uint = 3221225622;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_PAGING_FILES: ::libc::c_uint = 3221225623;
pub const MD_NTSTATUS_WIN_STATUS_FILE_INVALID: ::libc::c_uint = 3221225624;
pub const MD_NTSTATUS_WIN_STATUS_ALLOTTED_SPACE_EXCEEDED: ::libc::c_uint = 3221225625;
pub const MD_NTSTATUS_WIN_STATUS_INSUFFICIENT_RESOURCES: ::libc::c_uint = 3221225626;
pub const MD_NTSTATUS_WIN_STATUS_DFS_EXIT_PATH_FOUND: ::libc::c_uint = 3221225627;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_DATA_ERROR: ::libc::c_uint = 3221225628;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_NOT_CONNECTED: ::libc::c_uint = 3221225629;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_POWER_FAILURE: ::libc::c_uint = 3221225630;
pub const MD_NTSTATUS_WIN_STATUS_FREE_VM_NOT_AT_BASE: ::libc::c_uint = 3221225631;
pub const MD_NTSTATUS_WIN_STATUS_MEMORY_NOT_ALLOCATED: ::libc::c_uint = 3221225632;
pub const MD_NTSTATUS_WIN_STATUS_WORKING_SET_QUOTA: ::libc::c_uint = 3221225633;
pub const MD_NTSTATUS_WIN_STATUS_MEDIA_WRITE_PROTECTED: ::libc::c_uint = 3221225634;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_NOT_READY: ::libc::c_uint = 3221225635;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_GROUP_ATTRIBUTES: ::libc::c_uint = 3221225636;
pub const MD_NTSTATUS_WIN_STATUS_BAD_IMPERSONATION_LEVEL: ::libc::c_uint = 3221225637;
pub const MD_NTSTATUS_WIN_STATUS_CANT_OPEN_ANONYMOUS: ::libc::c_uint = 3221225638;
pub const MD_NTSTATUS_WIN_STATUS_BAD_VALIDATION_CLASS: ::libc::c_uint = 3221225639;
pub const MD_NTSTATUS_WIN_STATUS_BAD_TOKEN_TYPE: ::libc::c_uint = 3221225640;
pub const MD_NTSTATUS_WIN_STATUS_BAD_MASTER_BOOT_RECORD: ::libc::c_uint = 3221225641;
pub const MD_NTSTATUS_WIN_STATUS_INSTRUCTION_MISALIGNMENT: ::libc::c_uint = 3221225642;
pub const MD_NTSTATUS_WIN_STATUS_INSTANCE_NOT_AVAILABLE: ::libc::c_uint = 3221225643;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_NOT_AVAILABLE: ::libc::c_uint = 3221225644;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PIPE_STATE: ::libc::c_uint = 3221225645;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_BUSY: ::libc::c_uint = 3221225646;
pub const MD_NTSTATUS_WIN_STATUS_ILLEGAL_FUNCTION: ::libc::c_uint = 3221225647;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_DISCONNECTED: ::libc::c_uint = 3221225648;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_CLOSING: ::libc::c_uint = 3221225649;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_CONNECTED: ::libc::c_uint = 3221225650;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_LISTENING: ::libc::c_uint = 3221225651;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_READ_MODE: ::libc::c_uint = 3221225652;
pub const MD_NTSTATUS_WIN_STATUS_IO_TIMEOUT: ::libc::c_uint = 3221225653;
pub const MD_NTSTATUS_WIN_STATUS_FILE_FORCED_CLOSED: ::libc::c_uint = 3221225654;
pub const MD_NTSTATUS_WIN_STATUS_PROFILING_NOT_STARTED: ::libc::c_uint = 3221225655;
pub const MD_NTSTATUS_WIN_STATUS_PROFILING_NOT_STOPPED: ::libc::c_uint = 3221225656;
pub const MD_NTSTATUS_WIN_STATUS_COULD_NOT_INTERPRET: ::libc::c_uint = 3221225657;
pub const MD_NTSTATUS_WIN_STATUS_FILE_IS_A_DIRECTORY: ::libc::c_uint = 3221225658;
pub const MD_NTSTATUS_WIN_STATUS_NOT_SUPPORTED: ::libc::c_uint = 3221225659;
pub const MD_NTSTATUS_WIN_STATUS_REMOTE_NOT_LISTENING: ::libc::c_uint = 3221225660;
pub const MD_NTSTATUS_WIN_STATUS_DUPLICATE_NAME: ::libc::c_uint = 3221225661;
pub const MD_NTSTATUS_WIN_STATUS_BAD_NETWORK_PATH: ::libc::c_uint = 3221225662;
pub const MD_NTSTATUS_WIN_STATUS_NETWORK_BUSY: ::libc::c_uint = 3221225663;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_DOES_NOT_EXIST: ::libc::c_uint = 3221225664;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_COMMANDS: ::libc::c_uint = 3221225665;
pub const MD_NTSTATUS_WIN_STATUS_ADAPTER_HARDWARE_ERROR: ::libc::c_uint = 3221225666;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_NETWORK_RESPONSE: ::libc::c_uint = 3221225667;
pub const MD_NTSTATUS_WIN_STATUS_UNEXPECTED_NETWORK_ERROR: ::libc::c_uint = 3221225668;
pub const MD_NTSTATUS_WIN_STATUS_BAD_REMOTE_ADAPTER: ::libc::c_uint = 3221225669;
pub const MD_NTSTATUS_WIN_STATUS_PRINT_QUEUE_FULL: ::libc::c_uint = 3221225670;
pub const MD_NTSTATUS_WIN_STATUS_NO_SPOOL_SPACE: ::libc::c_uint = 3221225671;
pub const MD_NTSTATUS_WIN_STATUS_PRINT_CANCELLED: ::libc::c_uint = 3221225672;
pub const MD_NTSTATUS_WIN_STATUS_NETWORK_NAME_DELETED: ::libc::c_uint = 3221225673;
pub const MD_NTSTATUS_WIN_STATUS_NETWORK_ACCESS_DENIED: ::libc::c_uint = 3221225674;
pub const MD_NTSTATUS_WIN_STATUS_BAD_DEVICE_TYPE: ::libc::c_uint = 3221225675;
pub const MD_NTSTATUS_WIN_STATUS_BAD_NETWORK_NAME: ::libc::c_uint = 3221225676;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_NAMES: ::libc::c_uint = 3221225677;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_SESSIONS: ::libc::c_uint = 3221225678;
pub const MD_NTSTATUS_WIN_STATUS_SHARING_PAUSED: ::libc::c_uint = 3221225679;
pub const MD_NTSTATUS_WIN_STATUS_REQUEST_NOT_ACCEPTED: ::libc::c_uint = 3221225680;
pub const MD_NTSTATUS_WIN_STATUS_REDIRECTOR_PAUSED: ::libc::c_uint = 3221225681;
pub const MD_NTSTATUS_WIN_STATUS_NET_WRITE_FAULT: ::libc::c_uint = 3221225682;
pub const MD_NTSTATUS_WIN_STATUS_PROFILING_AT_LIMIT: ::libc::c_uint = 3221225683;
pub const MD_NTSTATUS_WIN_STATUS_NOT_SAME_DEVICE: ::libc::c_uint = 3221225684;
pub const MD_NTSTATUS_WIN_STATUS_FILE_RENAMED: ::libc::c_uint = 3221225685;
pub const MD_NTSTATUS_WIN_STATUS_VIRTUAL_CIRCUIT_CLOSED: ::libc::c_uint = 3221225686;
pub const MD_NTSTATUS_WIN_STATUS_NO_SECURITY_ON_OBJECT: ::libc::c_uint = 3221225687;
pub const MD_NTSTATUS_WIN_STATUS_CANT_WAIT: ::libc::c_uint = 3221225688;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_EMPTY: ::libc::c_uint = 3221225689;
pub const MD_NTSTATUS_WIN_STATUS_CANT_ACCESS_DOMAIN_INFO: ::libc::c_uint = 3221225690;
pub const MD_NTSTATUS_WIN_STATUS_CANT_TERMINATE_SELF: ::libc::c_uint = 3221225691;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_SERVER_STATE: ::libc::c_uint = 3221225692;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_DOMAIN_STATE: ::libc::c_uint = 3221225693;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_DOMAIN_ROLE: ::libc::c_uint = 3221225694;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_DOMAIN: ::libc::c_uint = 3221225695;
pub const MD_NTSTATUS_WIN_STATUS_DOMAIN_EXISTS: ::libc::c_uint = 3221225696;
pub const MD_NTSTATUS_WIN_STATUS_DOMAIN_LIMIT_EXCEEDED: ::libc::c_uint = 3221225697;
pub const MD_NTSTATUS_WIN_STATUS_OPLOCK_NOT_GRANTED: ::libc::c_uint = 3221225698;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_OPLOCK_PROTOCOL: ::libc::c_uint = 3221225699;
pub const MD_NTSTATUS_WIN_STATUS_INTERNAL_DB_CORRUPTION: ::libc::c_uint = 3221225700;
pub const MD_NTSTATUS_WIN_STATUS_INTERNAL_ERROR: ::libc::c_uint = 3221225701;
pub const MD_NTSTATUS_WIN_STATUS_GENERIC_NOT_MAPPED: ::libc::c_uint = 3221225702;
pub const MD_NTSTATUS_WIN_STATUS_BAD_DESCRIPTOR_FORMAT: ::libc::c_uint = 3221225703;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_USER_BUFFER: ::libc::c_uint = 3221225704;
pub const MD_NTSTATUS_WIN_STATUS_UNEXPECTED_IO_ERROR: ::libc::c_uint = 3221225705;
pub const MD_NTSTATUS_WIN_STATUS_UNEXPECTED_MM_CREATE_ERR: ::libc::c_uint = 3221225706;
pub const MD_NTSTATUS_WIN_STATUS_UNEXPECTED_MM_MAP_ERROR: ::libc::c_uint = 3221225707;
pub const MD_NTSTATUS_WIN_STATUS_UNEXPECTED_MM_EXTEND_ERR: ::libc::c_uint = 3221225708;
pub const MD_NTSTATUS_WIN_STATUS_NOT_LOGON_PROCESS: ::libc::c_uint = 3221225709;
pub const MD_NTSTATUS_WIN_STATUS_LOGON_SESSION_EXISTS: ::libc::c_uint = 3221225710;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_1: ::libc::c_uint = 3221225711;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_2: ::libc::c_uint = 3221225712;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_3: ::libc::c_uint = 3221225713;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_4: ::libc::c_uint = 3221225714;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_5: ::libc::c_uint = 3221225715;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_6: ::libc::c_uint = 3221225716;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_7: ::libc::c_uint = 3221225717;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_8: ::libc::c_uint = 3221225718;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_9: ::libc::c_uint = 3221225719;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_10: ::libc::c_uint = 3221225720;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_11: ::libc::c_uint = 3221225721;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PARAMETER_12: ::libc::c_uint = 3221225722;
pub const MD_NTSTATUS_WIN_STATUS_REDIRECTOR_NOT_STARTED: ::libc::c_uint = 3221225723;
pub const MD_NTSTATUS_WIN_STATUS_REDIRECTOR_STARTED: ::libc::c_uint = 3221225724;
pub const MD_NTSTATUS_WIN_STATUS_STACK_OVERFLOW: ::libc::c_uint = 3221225725;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_PACKAGE: ::libc::c_uint = 3221225726;
pub const MD_NTSTATUS_WIN_STATUS_BAD_FUNCTION_TABLE: ::libc::c_uint = 3221225727;
pub const MD_NTSTATUS_WIN_STATUS_VARIABLE_NOT_FOUND: ::libc::c_uint = 3221225728;
pub const MD_NTSTATUS_WIN_STATUS_DIRECTORY_NOT_EMPTY: ::libc::c_uint = 3221225729;
pub const MD_NTSTATUS_WIN_STATUS_FILE_CORRUPT_ERROR: ::libc::c_uint = 3221225730;
pub const MD_NTSTATUS_WIN_STATUS_NOT_A_DIRECTORY: ::libc::c_uint = 3221225731;
pub const MD_NTSTATUS_WIN_STATUS_BAD_LOGON_SESSION_STATE: ::libc::c_uint = 3221225732;
pub const MD_NTSTATUS_WIN_STATUS_LOGON_SESSION_COLLISION: ::libc::c_uint = 3221225733;
pub const MD_NTSTATUS_WIN_STATUS_NAME_TOO_LONG: ::libc::c_uint = 3221225734;
pub const MD_NTSTATUS_WIN_STATUS_FILES_OPEN: ::libc::c_uint = 3221225735;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_IN_USE: ::libc::c_uint = 3221225736;
pub const MD_NTSTATUS_WIN_STATUS_MESSAGE_NOT_FOUND: ::libc::c_uint = 3221225737;
pub const MD_NTSTATUS_WIN_STATUS_PROCESS_IS_TERMINATING: ::libc::c_uint = 3221225738;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LOGON_TYPE: ::libc::c_uint = 3221225739;
pub const MD_NTSTATUS_WIN_STATUS_NO_GUID_TRANSLATION: ::libc::c_uint = 3221225740;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_IMPERSONATE: ::libc::c_uint = 3221225741;
pub const MD_NTSTATUS_WIN_STATUS_IMAGE_ALREADY_LOADED: ::libc::c_uint = 3221225742;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_NOT_PRESENT: ::libc::c_uint = 3221225743;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_LID_NOT_EXIST: ::libc::c_uint = 3221225744;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_LID_ALREADY_OWNED: ::libc::c_uint = 3221225745;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_NOT_LID_OWNER: ::libc::c_uint = 3221225746;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_INVALID_COMMAND: ::libc::c_uint = 3221225747;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_INVALID_LID: ::libc::c_uint = 3221225748;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE: ::libc::c_uint = 3221225749;
pub const MD_NTSTATUS_WIN_STATUS_ABIOS_INVALID_SELECTOR: ::libc::c_uint = 3221225750;
pub const MD_NTSTATUS_WIN_STATUS_NO_LDT: ::libc::c_uint = 3221225751;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LDT_SIZE: ::libc::c_uint = 3221225752;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LDT_OFFSET: ::libc::c_uint = 3221225753;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LDT_DESCRIPTOR: ::libc::c_uint = 3221225754;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_NE_FORMAT: ::libc::c_uint = 3221225755;
pub const MD_NTSTATUS_WIN_STATUS_RXACT_INVALID_STATE: ::libc::c_uint = 3221225756;
pub const MD_NTSTATUS_WIN_STATUS_RXACT_COMMIT_FAILURE: ::libc::c_uint = 3221225757;
pub const MD_NTSTATUS_WIN_STATUS_MAPPED_FILE_SIZE_ZERO: ::libc::c_uint = 3221225758;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_OPENED_FILES: ::libc::c_uint = 3221225759;
pub const MD_NTSTATUS_WIN_STATUS_CANCELLED: ::libc::c_uint = 3221225760;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_DELETE: ::libc::c_uint = 3221225761;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_COMPUTER_NAME: ::libc::c_uint = 3221225762;
pub const MD_NTSTATUS_WIN_STATUS_FILE_DELETED: ::libc::c_uint = 3221225763;
pub const MD_NTSTATUS_WIN_STATUS_SPECIAL_ACCOUNT: ::libc::c_uint = 3221225764;
pub const MD_NTSTATUS_WIN_STATUS_SPECIAL_GROUP: ::libc::c_uint = 3221225765;
pub const MD_NTSTATUS_WIN_STATUS_SPECIAL_USER: ::libc::c_uint = 3221225766;
pub const MD_NTSTATUS_WIN_STATUS_MEMBERS_PRIMARY_GROUP: ::libc::c_uint = 3221225767;
pub const MD_NTSTATUS_WIN_STATUS_FILE_CLOSED: ::libc::c_uint = 3221225768;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_THREADS: ::libc::c_uint = 3221225769;
pub const MD_NTSTATUS_WIN_STATUS_THREAD_NOT_IN_PROCESS: ::libc::c_uint = 3221225770;
pub const MD_NTSTATUS_WIN_STATUS_TOKEN_ALREADY_IN_USE: ::libc::c_uint = 3221225771;
pub const MD_NTSTATUS_WIN_STATUS_PAGEFILE_QUOTA_EXCEEDED: ::libc::c_uint = 3221225772;
pub const MD_NTSTATUS_WIN_STATUS_COMMITMENT_LIMIT: ::libc::c_uint = 3221225773;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_LE_FORMAT: ::libc::c_uint = 3221225774;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_NOT_MZ: ::libc::c_uint = 3221225775;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_PROTECT: ::libc::c_uint = 3221225776;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_WIN_16: ::libc::c_uint = 3221225777;
pub const MD_NTSTATUS_WIN_STATUS_LOGON_SERVER_CONFLICT: ::libc::c_uint = 3221225778;
pub const MD_NTSTATUS_WIN_STATUS_TIME_DIFFERENCE_AT_DC: ::libc::c_uint = 3221225779;
pub const MD_NTSTATUS_WIN_STATUS_SYNCHRONIZATION_REQUIRED: ::libc::c_uint = 3221225780;
pub const MD_NTSTATUS_WIN_STATUS_DLL_NOT_FOUND: ::libc::c_uint = 3221225781;
pub const MD_NTSTATUS_WIN_STATUS_OPEN_FAILED: ::libc::c_uint = 3221225782;
pub const MD_NTSTATUS_WIN_STATUS_IO_PRIVILEGE_FAILED: ::libc::c_uint = 3221225783;
pub const MD_NTSTATUS_WIN_STATUS_ORDINAL_NOT_FOUND: ::libc::c_uint = 3221225784;
pub const MD_NTSTATUS_WIN_STATUS_ENTRYPOINT_NOT_FOUND: ::libc::c_uint = 3221225785;
pub const MD_NTSTATUS_WIN_STATUS_CONTROL_C_EXIT: ::libc::c_uint = 3221225786;
pub const MD_NTSTATUS_WIN_STATUS_LOCAL_DISCONNECT: ::libc::c_uint = 3221225787;
pub const MD_NTSTATUS_WIN_STATUS_REMOTE_DISCONNECT: ::libc::c_uint = 3221225788;
pub const MD_NTSTATUS_WIN_STATUS_REMOTE_RESOURCES: ::libc::c_uint = 3221225789;
pub const MD_NTSTATUS_WIN_STATUS_LINK_FAILED: ::libc::c_uint = 3221225790;
pub const MD_NTSTATUS_WIN_STATUS_LINK_TIMEOUT: ::libc::c_uint = 3221225791;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_CONNECTION: ::libc::c_uint = 3221225792;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_ADDRESS: ::libc::c_uint = 3221225793;
pub const MD_NTSTATUS_WIN_STATUS_DLL_INIT_FAILED: ::libc::c_uint = 3221225794;
pub const MD_NTSTATUS_WIN_STATUS_MISSING_SYSTEMFILE: ::libc::c_uint = 3221225795;
pub const MD_NTSTATUS_WIN_STATUS_UNHANDLED_EXCEPTION: ::libc::c_uint = 3221225796;
pub const MD_NTSTATUS_WIN_STATUS_APP_INIT_FAILURE: ::libc::c_uint = 3221225797;
pub const MD_NTSTATUS_WIN_STATUS_PAGEFILE_CREATE_FAILED: ::libc::c_uint = 3221225798;
pub const MD_NTSTATUS_WIN_STATUS_NO_PAGEFILE: ::libc::c_uint = 3221225799;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LEVEL: ::libc::c_uint = 3221225800;
pub const MD_NTSTATUS_WIN_STATUS_WRONG_PASSWORD_CORE: ::libc::c_uint = 3221225801;
pub const MD_NTSTATUS_WIN_STATUS_ILLEGAL_FLOAT_CONTEXT: ::libc::c_uint = 3221225802;
pub const MD_NTSTATUS_WIN_STATUS_PIPE_BROKEN: ::libc::c_uint = 3221225803;
pub const MD_NTSTATUS_WIN_STATUS_REGISTRY_CORRUPT: ::libc::c_uint = 3221225804;
pub const MD_NTSTATUS_WIN_STATUS_REGISTRY_IO_FAILED: ::libc::c_uint = 3221225805;
pub const MD_NTSTATUS_WIN_STATUS_NO_EVENT_PAIR: ::libc::c_uint = 3221225806;
pub const MD_NTSTATUS_WIN_STATUS_UNRECOGNIZED_VOLUME: ::libc::c_uint = 3221225807;
pub const MD_NTSTATUS_WIN_STATUS_SERIAL_NO_DEVICE_INITED: ::libc::c_uint = 3221225808;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_ALIAS: ::libc::c_uint = 3221225809;
pub const MD_NTSTATUS_WIN_STATUS_MEMBER_NOT_IN_ALIAS: ::libc::c_uint = 3221225810;
pub const MD_NTSTATUS_WIN_STATUS_MEMBER_IN_ALIAS: ::libc::c_uint = 3221225811;
pub const MD_NTSTATUS_WIN_STATUS_ALIAS_EXISTS: ::libc::c_uint = 3221225812;
pub const MD_NTSTATUS_WIN_STATUS_LOGON_NOT_GRANTED: ::libc::c_uint = 3221225813;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_SECRETS: ::libc::c_uint = 3221225814;
pub const MD_NTSTATUS_WIN_STATUS_SECRET_TOO_LONG: ::libc::c_uint = 3221225815;
pub const MD_NTSTATUS_WIN_STATUS_INTERNAL_DB_ERROR: ::libc::c_uint = 3221225816;
pub const MD_NTSTATUS_WIN_STATUS_FULLSCREEN_MODE: ::libc::c_uint = 3221225817;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_CONTEXT_IDS: ::libc::c_uint = 3221225818;
pub const MD_NTSTATUS_WIN_STATUS_LOGON_TYPE_NOT_GRANTED: ::libc::c_uint = 3221225819;
pub const MD_NTSTATUS_WIN_STATUS_NOT_REGISTRY_FILE: ::libc::c_uint = 3221225820;
pub const MD_NTSTATUS_WIN_STATUS_NT_CROSS_ENCRYPTION_REQUIRED: ::libc::c_uint = 3221225821;
pub const MD_NTSTATUS_WIN_STATUS_DOMAIN_CTRLR_CONFIG_ERROR: ::libc::c_uint = 3221225822;
pub const MD_NTSTATUS_WIN_STATUS_FT_MISSING_MEMBER: ::libc::c_uint = 3221225823;
pub const MD_NTSTATUS_WIN_STATUS_ILL_FORMED_SERVICE_ENTRY: ::libc::c_uint = 3221225824;
pub const MD_NTSTATUS_WIN_STATUS_ILLEGAL_CHARACTER: ::libc::c_uint = 3221225825;
pub const MD_NTSTATUS_WIN_STATUS_UNMAPPABLE_CHARACTER: ::libc::c_uint = 3221225826;
pub const MD_NTSTATUS_WIN_STATUS_UNDEFINED_CHARACTER: ::libc::c_uint = 3221225827;
pub const MD_NTSTATUS_WIN_STATUS_FLOPPY_VOLUME: ::libc::c_uint = 3221225828;
pub const MD_NTSTATUS_WIN_STATUS_FLOPPY_ID_MARK_NOT_FOUND: ::libc::c_uint = 3221225829;
pub const MD_NTSTATUS_WIN_STATUS_FLOPPY_WRONG_CYLINDER: ::libc::c_uint = 3221225830;
pub const MD_NTSTATUS_WIN_STATUS_FLOPPY_UNKNOWN_ERROR: ::libc::c_uint = 3221225831;
pub const MD_NTSTATUS_WIN_STATUS_FLOPPY_BAD_REGISTERS: ::libc::c_uint = 3221225832;
pub const MD_NTSTATUS_WIN_STATUS_DISK_RECALIBRATE_FAILED: ::libc::c_uint = 3221225833;
pub const MD_NTSTATUS_WIN_STATUS_DISK_OPERATION_FAILED: ::libc::c_uint = 3221225834;
pub const MD_NTSTATUS_WIN_STATUS_DISK_RESET_FAILED: ::libc::c_uint = 3221225835;
pub const MD_NTSTATUS_WIN_STATUS_SHARED_IRQ_BUSY: ::libc::c_uint = 3221225836;
pub const MD_NTSTATUS_WIN_STATUS_FT_ORPHANING: ::libc::c_uint = 3221225837;
pub const MD_NTSTATUS_WIN_STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT: ::libc::c_uint = 3221225838;
pub const MD_NTSTATUS_WIN_STATUS_PARTITION_FAILURE: ::libc::c_uint = 3221225842;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_BLOCK_LENGTH: ::libc::c_uint = 3221225843;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_NOT_PARTITIONED: ::libc::c_uint = 3221225844;
pub const MD_NTSTATUS_WIN_STATUS_UNABLE_TO_LOCK_MEDIA: ::libc::c_uint = 3221225845;
pub const MD_NTSTATUS_WIN_STATUS_UNABLE_TO_UNLOAD_MEDIA: ::libc::c_uint = 3221225846;
pub const MD_NTSTATUS_WIN_STATUS_EOM_OVERFLOW: ::libc::c_uint = 3221225847;
pub const MD_NTSTATUS_WIN_STATUS_NO_MEDIA: ::libc::c_uint = 3221225848;
pub const MD_NTSTATUS_WIN_STATUS_NO_SUCH_MEMBER: ::libc::c_uint = 3221225850;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_MEMBER: ::libc::c_uint = 3221225851;
pub const MD_NTSTATUS_WIN_STATUS_KEY_DELETED: ::libc::c_uint = 3221225852;
pub const MD_NTSTATUS_WIN_STATUS_NO_LOG_SPACE: ::libc::c_uint = 3221225853;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_SIDS: ::libc::c_uint = 3221225854;
pub const MD_NTSTATUS_WIN_STATUS_LM_CROSS_ENCRYPTION_REQUIRED: ::libc::c_uint = 3221225855;
pub const MD_NTSTATUS_WIN_STATUS_KEY_HAS_CHILDREN: ::libc::c_uint = 3221225856;
pub const MD_NTSTATUS_WIN_STATUS_CHILD_MUST_BE_VOLATILE: ::libc::c_uint = 3221225857;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_CONFIGURATION_ERROR: ::libc::c_uint = 3221225858;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_INTERNAL_ERROR: ::libc::c_uint = 3221225859;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_DEVICE_STATE: ::libc::c_uint = 3221225860;
pub const MD_NTSTATUS_WIN_STATUS_IO_DEVICE_ERROR: ::libc::c_uint = 3221225861;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_PROTOCOL_ERROR: ::libc::c_uint = 3221225862;
pub const MD_NTSTATUS_WIN_STATUS_BACKUP_CONTROLLER: ::libc::c_uint = 3221225863;
pub const MD_NTSTATUS_WIN_STATUS_LOG_FILE_FULL: ::libc::c_uint = 3221225864;
pub const MD_NTSTATUS_WIN_STATUS_TOO_LATE: ::libc::c_uint = 3221225865;
pub const MD_NTSTATUS_WIN_STATUS_NO_TRUST_LSA_SECRET: ::libc::c_uint = 3221225866;
pub const MD_NTSTATUS_WIN_STATUS_NO_TRUST_SAM_ACCOUNT: ::libc::c_uint = 3221225867;
pub const MD_NTSTATUS_WIN_STATUS_TRUSTED_DOMAIN_FAILURE: ::libc::c_uint = 3221225868;
pub const MD_NTSTATUS_WIN_STATUS_TRUSTED_RELATIONSHIP_FAILURE: ::libc::c_uint = 3221225869;
pub const MD_NTSTATUS_WIN_STATUS_EVENTLOG_FILE_CORRUPT: ::libc::c_uint = 3221225870;
pub const MD_NTSTATUS_WIN_STATUS_EVENTLOG_CANT_START: ::libc::c_uint = 3221225871;
pub const MD_NTSTATUS_WIN_STATUS_TRUST_FAILURE: ::libc::c_uint = 3221225872;
pub const MD_NTSTATUS_WIN_STATUS_MUTANT_LIMIT_EXCEEDED: ::libc::c_uint = 3221225873;
pub const MD_NTSTATUS_WIN_STATUS_NETLOGON_NOT_STARTED: ::libc::c_uint = 3221225874;
pub const MD_NTSTATUS_WIN_STATUS_ACCOUNT_EXPIRED: ::libc::c_uint = 3221225875;
pub const MD_NTSTATUS_WIN_STATUS_POSSIBLE_DEADLOCK: ::libc::c_uint = 3221225876;
pub const MD_NTSTATUS_WIN_STATUS_NETWORK_CREDENTIAL_CONFLICT: ::libc::c_uint = 3221225877;
pub const MD_NTSTATUS_WIN_STATUS_REMOTE_SESSION_LIMIT: ::libc::c_uint = 3221225878;
pub const MD_NTSTATUS_WIN_STATUS_EVENTLOG_FILE_CHANGED: ::libc::c_uint = 3221225879;
pub const MD_NTSTATUS_WIN_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT: ::libc::c_uint = 3221225880;
pub const MD_NTSTATUS_WIN_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT: ::libc::c_uint = 3221225881;
pub const MD_NTSTATUS_WIN_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT: ::libc::c_uint = 3221225882;
pub const MD_NTSTATUS_WIN_STATUS_DOMAIN_TRUST_INCONSISTENT: ::libc::c_uint = 3221225883;
pub const MD_NTSTATUS_WIN_STATUS_FS_DRIVER_REQUIRED: ::libc::c_uint = 3221225884;
pub const MD_NTSTATUS_WIN_STATUS_IMAGE_ALREADY_LOADED_AS_DLL: ::libc::c_uint = 3221225885;
pub const MD_NTSTATUS_WIN_STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING:
          ::libc::c_uint =
    3221225886;
pub const MD_NTSTATUS_WIN_STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME: ::libc::c_uint = 3221225887;
pub const MD_NTSTATUS_WIN_STATUS_SECURITY_STREAM_IS_INCONSISTENT: ::libc::c_uint = 3221225888;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LOCK_RANGE: ::libc::c_uint = 3221225889;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_ACE_CONDITION: ::libc::c_uint = 3221225890;
pub const MD_NTSTATUS_WIN_STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT: ::libc::c_uint = 3221225891;
pub const MD_NTSTATUS_WIN_STATUS_NOTIFICATION_GUID_ALREADY_DEFINED: ::libc::c_uint = 3221225892;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_EXCEPTION_HANDLER: ::libc::c_uint = 3221225893;
pub const MD_NTSTATUS_WIN_STATUS_DUPLICATE_PRIVILEGES: ::libc::c_uint = 3221225894;
pub const MD_NTSTATUS_WIN_STATUS_NOT_ALLOWED_ON_SYSTEM_FILE: ::libc::c_uint = 3221225895;
pub const MD_NTSTATUS_WIN_STATUS_REPAIR_NEEDED: ::libc::c_uint = 3221225896;
pub const MD_NTSTATUS_WIN_STATUS_QUOTA_NOT_ENABLED: ::libc::c_uint = 3221225897;
pub const MD_NTSTATUS_WIN_STATUS_NO_APPLICATION_PACKAGE: ::libc::c_uint = 3221225898;
pub const MD_NTSTATUS_WIN_STATUS_NETWORK_OPEN_RESTRICTION: ::libc::c_uint = 3221225985;
pub const MD_NTSTATUS_WIN_STATUS_NO_USER_SESSION_KEY: ::libc::c_uint = 3221225986;
pub const MD_NTSTATUS_WIN_STATUS_USER_SESSION_DELETED: ::libc::c_uint = 3221225987;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCE_LANG_NOT_FOUND: ::libc::c_uint = 3221225988;
pub const MD_NTSTATUS_WIN_STATUS_INSUFF_SERVER_RESOURCES: ::libc::c_uint = 3221225989;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_BUFFER_SIZE: ::libc::c_uint = 3221225990;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_ADDRESS_COMPONENT: ::libc::c_uint = 3221225991;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_ADDRESS_WILDCARD: ::libc::c_uint = 3221225992;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_ADDRESSES: ::libc::c_uint = 3221225993;
pub const MD_NTSTATUS_WIN_STATUS_ADDRESS_ALREADY_EXISTS: ::libc::c_uint = 3221225994;
pub const MD_NTSTATUS_WIN_STATUS_ADDRESS_CLOSED: ::libc::c_uint = 3221225995;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_DISCONNECTED: ::libc::c_uint = 3221225996;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_RESET: ::libc::c_uint = 3221225997;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_NODES: ::libc::c_uint = 3221225998;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_ABORTED: ::libc::c_uint = 3221225999;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_TIMED_OUT: ::libc::c_uint = 3221226000;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NO_RELEASE: ::libc::c_uint = 3221226001;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NO_MATCH: ::libc::c_uint = 3221226002;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_RESPONDED: ::libc::c_uint = 3221226003;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_INVALID_ID: ::libc::c_uint = 3221226004;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_INVALID_TYPE: ::libc::c_uint = 3221226005;
pub const MD_NTSTATUS_WIN_STATUS_NOT_SERVER_SESSION: ::libc::c_uint = 3221226006;
pub const MD_NTSTATUS_WIN_STATUS_NOT_CLIENT_SESSION: ::libc::c_uint = 3221226007;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_LOAD_REGISTRY_FILE: ::libc::c_uint = 3221226008;
pub const MD_NTSTATUS_WIN_STATUS_DEBUG_ATTACH_FAILED: ::libc::c_uint = 3221226009;
pub const MD_NTSTATUS_WIN_STATUS_SYSTEM_PROCESS_TERMINATED: ::libc::c_uint = 3221226010;
pub const MD_NTSTATUS_WIN_STATUS_DATA_NOT_ACCEPTED: ::libc::c_uint = 3221226011;
pub const MD_NTSTATUS_WIN_STATUS_NO_BROWSER_SERVERS_FOUND: ::libc::c_uint = 3221226012;
pub const MD_NTSTATUS_WIN_STATUS_VDM_HARD_ERROR: ::libc::c_uint = 3221226013;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_CANCEL_TIMEOUT: ::libc::c_uint = 3221226014;
pub const MD_NTSTATUS_WIN_STATUS_REPLY_MESSAGE_MISMATCH: ::libc::c_uint = 3221226015;
pub const MD_NTSTATUS_WIN_STATUS_MAPPED_ALIGNMENT: ::libc::c_uint = 3221226016;
pub const MD_NTSTATUS_WIN_STATUS_IMAGE_CHECKSUM_MISMATCH: ::libc::c_uint = 3221226017;
pub const MD_NTSTATUS_WIN_STATUS_LOST_WRITEBEHIND_DATA: ::libc::c_uint = 3221226018;
pub const MD_NTSTATUS_WIN_STATUS_CLIENT_SERVER_PARAMETERS_INVALID: ::libc::c_uint = 3221226019;
pub const MD_NTSTATUS_WIN_STATUS_PASSWORD_MUST_CHANGE: ::libc::c_uint = 3221226020;
pub const MD_NTSTATUS_WIN_STATUS_NOT_FOUND: ::libc::c_uint = 3221226021;
pub const MD_NTSTATUS_WIN_STATUS_NOT_TINY_STREAM: ::libc::c_uint = 3221226022;
pub const MD_NTSTATUS_WIN_STATUS_RECOVERY_FAILURE: ::libc::c_uint = 3221226023;
pub const MD_NTSTATUS_WIN_STATUS_STACK_OVERFLOW_READ: ::libc::c_uint = 3221226024;
pub const MD_NTSTATUS_WIN_STATUS_FAIL_CHECK: ::libc::c_uint = 3221226025;
pub const MD_NTSTATUS_WIN_STATUS_DUPLICATE_OBJECTID: ::libc::c_uint = 3221226026;
pub const MD_NTSTATUS_WIN_STATUS_OBJECTID_EXISTS: ::libc::c_uint = 3221226027;
pub const MD_NTSTATUS_WIN_STATUS_CONVERT_TO_LARGE: ::libc::c_uint = 3221226028;
pub const MD_NTSTATUS_WIN_STATUS_RETRY: ::libc::c_uint = 3221226029;
pub const MD_NTSTATUS_WIN_STATUS_FOUND_OUT_OF_SCOPE: ::libc::c_uint = 3221226030;
pub const MD_NTSTATUS_WIN_STATUS_ALLOCATE_BUCKET: ::libc::c_uint = 3221226031;
pub const MD_NTSTATUS_WIN_STATUS_PROPSET_NOT_FOUND: ::libc::c_uint = 3221226032;
pub const MD_NTSTATUS_WIN_STATUS_MARSHALL_OVERFLOW: ::libc::c_uint = 3221226033;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_VARIANT: ::libc::c_uint = 3221226034;
pub const MD_NTSTATUS_WIN_STATUS_DOMAIN_CONTROLLER_NOT_FOUND: ::libc::c_uint = 3221226035;
pub const MD_NTSTATUS_WIN_STATUS_ACCOUNT_LOCKED_OUT: ::libc::c_uint = 3221226036;
pub const MD_NTSTATUS_WIN_STATUS_HANDLE_NOT_CLOSABLE: ::libc::c_uint = 3221226037;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_REFUSED: ::libc::c_uint = 3221226038;
pub const MD_NTSTATUS_WIN_STATUS_GRACEFUL_DISCONNECT: ::libc::c_uint = 3221226039;
pub const MD_NTSTATUS_WIN_STATUS_ADDRESS_ALREADY_ASSOCIATED: ::libc::c_uint = 3221226040;
pub const MD_NTSTATUS_WIN_STATUS_ADDRESS_NOT_ASSOCIATED: ::libc::c_uint = 3221226041;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_INVALID: ::libc::c_uint = 3221226042;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_ACTIVE: ::libc::c_uint = 3221226043;
pub const MD_NTSTATUS_WIN_STATUS_NETWORK_UNREACHABLE: ::libc::c_uint = 3221226044;
pub const MD_NTSTATUS_WIN_STATUS_HOST_UNREACHABLE: ::libc::c_uint = 3221226045;
pub const MD_NTSTATUS_WIN_STATUS_PROTOCOL_UNREACHABLE: ::libc::c_uint = 3221226046;
pub const MD_NTSTATUS_WIN_STATUS_PORT_UNREACHABLE: ::libc::c_uint = 3221226047;
pub const MD_NTSTATUS_WIN_STATUS_REQUEST_ABORTED: ::libc::c_uint = 3221226048;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_ABORTED: ::libc::c_uint = 3221226049;
pub const MD_NTSTATUS_WIN_STATUS_BAD_COMPRESSION_BUFFER: ::libc::c_uint = 3221226050;
pub const MD_NTSTATUS_WIN_STATUS_USER_MAPPED_FILE: ::libc::c_uint = 3221226051;
pub const MD_NTSTATUS_WIN_STATUS_AUDIT_FAILED: ::libc::c_uint = 3221226052;
pub const MD_NTSTATUS_WIN_STATUS_TIMER_RESOLUTION_NOT_SET: ::libc::c_uint = 3221226053;
pub const MD_NTSTATUS_WIN_STATUS_CONNECTION_COUNT_LIMIT: ::libc::c_uint = 3221226054;
pub const MD_NTSTATUS_WIN_STATUS_LOGIN_TIME_RESTRICTION: ::libc::c_uint = 3221226055;
pub const MD_NTSTATUS_WIN_STATUS_LOGIN_WKSTA_RESTRICTION: ::libc::c_uint = 3221226056;
pub const MD_NTSTATUS_WIN_STATUS_IMAGE_MP_UP_MISMATCH: ::libc::c_uint = 3221226057;
pub const MD_NTSTATUS_WIN_STATUS_INSUFFICIENT_LOGON_INFO: ::libc::c_uint = 3221226064;
pub const MD_NTSTATUS_WIN_STATUS_BAD_DLL_ENTRYPOINT: ::libc::c_uint = 3221226065;
pub const MD_NTSTATUS_WIN_STATUS_BAD_SERVICE_ENTRYPOINT: ::libc::c_uint = 3221226066;
pub const MD_NTSTATUS_WIN_STATUS_LPC_REPLY_LOST: ::libc::c_uint = 3221226067;
pub const MD_NTSTATUS_WIN_STATUS_IP_ADDRESS_CONFLICT1: ::libc::c_uint = 3221226068;
pub const MD_NTSTATUS_WIN_STATUS_IP_ADDRESS_CONFLICT2: ::libc::c_uint = 3221226069;
pub const MD_NTSTATUS_WIN_STATUS_REGISTRY_QUOTA_LIMIT: ::libc::c_uint = 3221226070;
pub const MD_NTSTATUS_WIN_STATUS_PATH_NOT_COVERED: ::libc::c_uint = 3221226071;
pub const MD_NTSTATUS_WIN_STATUS_NO_CALLBACK_ACTIVE: ::libc::c_uint = 3221226072;
pub const MD_NTSTATUS_WIN_STATUS_LICENSE_QUOTA_EXCEEDED: ::libc::c_uint = 3221226073;
pub const MD_NTSTATUS_WIN_STATUS_PWD_TOO_SHORT: ::libc::c_uint = 3221226074;
pub const MD_NTSTATUS_WIN_STATUS_PWD_TOO_RECENT: ::libc::c_uint = 3221226075;
pub const MD_NTSTATUS_WIN_STATUS_PWD_HISTORY_CONFLICT: ::libc::c_uint = 3221226076;
pub const MD_NTSTATUS_WIN_STATUS_PLUGPLAY_NO_DEVICE: ::libc::c_uint = 3221226078;
pub const MD_NTSTATUS_WIN_STATUS_UNSUPPORTED_COMPRESSION: ::libc::c_uint = 3221226079;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_HW_PROFILE: ::libc::c_uint = 3221226080;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PLUGPLAY_DEVICE_PATH: ::libc::c_uint = 3221226081;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_ORDINAL_NOT_FOUND: ::libc::c_uint = 3221226082;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND: ::libc::c_uint = 3221226083;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCE_NOT_OWNED: ::libc::c_uint = 3221226084;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_LINKS: ::libc::c_uint = 3221226085;
pub const MD_NTSTATUS_WIN_STATUS_QUOTA_LIST_INCONSISTENT: ::libc::c_uint = 3221226086;
pub const MD_NTSTATUS_WIN_STATUS_FILE_IS_OFFLINE: ::libc::c_uint = 3221226087;
pub const MD_NTSTATUS_WIN_STATUS_EVALUATION_EXPIRATION: ::libc::c_uint = 3221226088;
pub const MD_NTSTATUS_WIN_STATUS_ILLEGAL_DLL_RELOCATION: ::libc::c_uint = 3221226089;
pub const MD_NTSTATUS_WIN_STATUS_LICENSE_VIOLATION: ::libc::c_uint = 3221226090;
pub const MD_NTSTATUS_WIN_STATUS_DLL_INIT_FAILED_LOGOFF: ::libc::c_uint = 3221226091;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_UNABLE_TO_LOAD: ::libc::c_uint = 3221226092;
pub const MD_NTSTATUS_WIN_STATUS_DFS_UNAVAILABLE: ::libc::c_uint = 3221226093;
pub const MD_NTSTATUS_WIN_STATUS_VOLUME_DISMOUNTED: ::libc::c_uint = 3221226094;
pub const MD_NTSTATUS_WIN_STATUS_WX86_INTERNAL_ERROR: ::libc::c_uint = 3221226095;
pub const MD_NTSTATUS_WIN_STATUS_WX86_FLOAT_STACK_CHECK: ::libc::c_uint = 3221226096;
pub const MD_NTSTATUS_WIN_STATUS_VALIDATE_CONTINUE: ::libc::c_uint = 3221226097;
pub const MD_NTSTATUS_WIN_STATUS_NO_MATCH: ::libc::c_uint = 3221226098;
pub const MD_NTSTATUS_WIN_STATUS_NO_MORE_MATCHES: ::libc::c_uint = 3221226099;
pub const MD_NTSTATUS_WIN_STATUS_NOT_A_REPARSE_POINT: ::libc::c_uint = 3221226101;
pub const MD_NTSTATUS_WIN_STATUS_IO_REPARSE_TAG_INVALID: ::libc::c_uint = 3221226102;
pub const MD_NTSTATUS_WIN_STATUS_IO_REPARSE_TAG_MISMATCH: ::libc::c_uint = 3221226103;
pub const MD_NTSTATUS_WIN_STATUS_IO_REPARSE_DATA_INVALID: ::libc::c_uint = 3221226104;
pub const MD_NTSTATUS_WIN_STATUS_IO_REPARSE_TAG_NOT_HANDLED: ::libc::c_uint = 3221226105;
pub const MD_NTSTATUS_WIN_STATUS_PWD_TOO_LONG: ::libc::c_uint = 3221226106;
pub const MD_NTSTATUS_WIN_STATUS_STOWED_EXCEPTION: ::libc::c_uint = 3221226107;
pub const MD_NTSTATUS_WIN_STATUS_REPARSE_POINT_NOT_RESOLVED: ::libc::c_uint = 3221226112;
pub const MD_NTSTATUS_WIN_STATUS_DIRECTORY_IS_A_REPARSE_POINT: ::libc::c_uint = 3221226113;
pub const MD_NTSTATUS_WIN_STATUS_RANGE_LIST_CONFLICT: ::libc::c_uint = 3221226114;
pub const MD_NTSTATUS_WIN_STATUS_SOURCE_ELEMENT_EMPTY: ::libc::c_uint = 3221226115;
pub const MD_NTSTATUS_WIN_STATUS_DESTINATION_ELEMENT_FULL: ::libc::c_uint = 3221226116;
pub const MD_NTSTATUS_WIN_STATUS_ILLEGAL_ELEMENT_ADDRESS: ::libc::c_uint = 3221226117;
pub const MD_NTSTATUS_WIN_STATUS_MAGAZINE_NOT_PRESENT: ::libc::c_uint = 3221226118;
pub const MD_NTSTATUS_WIN_STATUS_REINITIALIZATION_NEEDED: ::libc::c_uint = 3221226119;
pub const MD_NTSTATUS_WIN_STATUS_ENCRYPTION_FAILED: ::libc::c_uint = 3221226122;
pub const MD_NTSTATUS_WIN_STATUS_DECRYPTION_FAILED: ::libc::c_uint = 3221226123;
pub const MD_NTSTATUS_WIN_STATUS_RANGE_NOT_FOUND: ::libc::c_uint = 3221226124;
pub const MD_NTSTATUS_WIN_STATUS_NO_RECOVERY_POLICY: ::libc::c_uint = 3221226125;
pub const MD_NTSTATUS_WIN_STATUS_NO_EFS: ::libc::c_uint = 3221226126;
pub const MD_NTSTATUS_WIN_STATUS_WRONG_EFS: ::libc::c_uint = 3221226127;
pub const MD_NTSTATUS_WIN_STATUS_NO_USER_KEYS: ::libc::c_uint = 3221226128;
pub const MD_NTSTATUS_WIN_STATUS_FILE_NOT_ENCRYPTED: ::libc::c_uint = 3221226129;
pub const MD_NTSTATUS_WIN_STATUS_NOT_EXPORT_FORMAT: ::libc::c_uint = 3221226130;
pub const MD_NTSTATUS_WIN_STATUS_FILE_ENCRYPTED: ::libc::c_uint = 3221226131;
pub const MD_NTSTATUS_WIN_STATUS_WMI_GUID_NOT_FOUND: ::libc::c_uint = 3221226133;
pub const MD_NTSTATUS_WIN_STATUS_WMI_INSTANCE_NOT_FOUND: ::libc::c_uint = 3221226134;
pub const MD_NTSTATUS_WIN_STATUS_WMI_ITEMID_NOT_FOUND: ::libc::c_uint = 3221226135;
pub const MD_NTSTATUS_WIN_STATUS_WMI_TRY_AGAIN: ::libc::c_uint = 3221226136;
pub const MD_NTSTATUS_WIN_STATUS_SHARED_POLICY: ::libc::c_uint = 3221226137;
pub const MD_NTSTATUS_WIN_STATUS_POLICY_OBJECT_NOT_FOUND: ::libc::c_uint = 3221226138;
pub const MD_NTSTATUS_WIN_STATUS_POLICY_ONLY_IN_DS: ::libc::c_uint = 3221226139;
pub const MD_NTSTATUS_WIN_STATUS_VOLUME_NOT_UPGRADED: ::libc::c_uint = 3221226140;
pub const MD_NTSTATUS_WIN_STATUS_REMOTE_STORAGE_NOT_ACTIVE: ::libc::c_uint = 3221226141;
pub const MD_NTSTATUS_WIN_STATUS_REMOTE_STORAGE_MEDIA_ERROR: ::libc::c_uint = 3221226142;
pub const MD_NTSTATUS_WIN_STATUS_NO_TRACKING_SERVICE: ::libc::c_uint = 3221226143;
pub const MD_NTSTATUS_WIN_STATUS_SERVER_SID_MISMATCH: ::libc::c_uint = 3221226144;
pub const MD_NTSTATUS_WIN_STATUS_DS_NO_ATTRIBUTE_OR_VALUE: ::libc::c_uint = 3221226145;
pub const MD_NTSTATUS_WIN_STATUS_DS_INVALID_ATTRIBUTE_SYNTAX: ::libc::c_uint = 3221226146;
pub const MD_NTSTATUS_WIN_STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED: ::libc::c_uint = 3221226147;
pub const MD_NTSTATUS_WIN_STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS: ::libc::c_uint = 3221226148;
pub const MD_NTSTATUS_WIN_STATUS_DS_BUSY: ::libc::c_uint = 3221226149;
pub const MD_NTSTATUS_WIN_STATUS_DS_UNAVAILABLE: ::libc::c_uint = 3221226150;
pub const MD_NTSTATUS_WIN_STATUS_DS_NO_RIDS_ALLOCATED: ::libc::c_uint = 3221226151;
pub const MD_NTSTATUS_WIN_STATUS_DS_NO_MORE_RIDS: ::libc::c_uint = 3221226152;
pub const MD_NTSTATUS_WIN_STATUS_DS_INCORRECT_ROLE_OWNER: ::libc::c_uint = 3221226153;
pub const MD_NTSTATUS_WIN_STATUS_DS_RIDMGR_INIT_ERROR: ::libc::c_uint = 3221226154;
pub const MD_NTSTATUS_WIN_STATUS_DS_OBJ_CLASS_VIOLATION: ::libc::c_uint = 3221226155;
pub const MD_NTSTATUS_WIN_STATUS_DS_CANT_ON_NON_LEAF: ::libc::c_uint = 3221226156;
pub const MD_NTSTATUS_WIN_STATUS_DS_CANT_ON_RDN: ::libc::c_uint = 3221226157;
pub const MD_NTSTATUS_WIN_STATUS_DS_CANT_MOD_OBJ_CLASS: ::libc::c_uint = 3221226158;
pub const MD_NTSTATUS_WIN_STATUS_DS_CROSS_DOM_MOVE_FAILED: ::libc::c_uint = 3221226159;
pub const MD_NTSTATUS_WIN_STATUS_DS_GC_NOT_AVAILABLE: ::libc::c_uint = 3221226160;
pub const MD_NTSTATUS_WIN_STATUS_DIRECTORY_SERVICE_REQUIRED: ::libc::c_uint = 3221226161;
pub const MD_NTSTATUS_WIN_STATUS_REPARSE_ATTRIBUTE_CONFLICT: ::libc::c_uint = 3221226162;
pub const MD_NTSTATUS_WIN_STATUS_CANT_ENABLE_DENY_ONLY: ::libc::c_uint = 3221226163;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_MULTIPLE_FAULTS: ::libc::c_uint = 3221226164;
pub const MD_NTSTATUS_WIN_STATUS_FLOAT_MULTIPLE_TRAPS: ::libc::c_uint = 3221226165;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_REMOVED: ::libc::c_uint = 3221226166;
pub const MD_NTSTATUS_WIN_STATUS_JOURNAL_DELETE_IN_PROGRESS: ::libc::c_uint = 3221226167;
pub const MD_NTSTATUS_WIN_STATUS_JOURNAL_NOT_ACTIVE: ::libc::c_uint = 3221226168;
pub const MD_NTSTATUS_WIN_STATUS_NOINTERFACE: ::libc::c_uint = 3221226169;
pub const MD_NTSTATUS_WIN_STATUS_DS_RIDMGR_DISABLED: ::libc::c_uint = 3221226170;
pub const MD_NTSTATUS_WIN_STATUS_DS_ADMIN_LIMIT_EXCEEDED: ::libc::c_uint = 3221226177;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_FAILED_SLEEP: ::libc::c_uint = 3221226178;
pub const MD_NTSTATUS_WIN_STATUS_MUTUAL_AUTHENTICATION_FAILED: ::libc::c_uint = 3221226179;
pub const MD_NTSTATUS_WIN_STATUS_CORRUPT_SYSTEM_FILE: ::libc::c_uint = 3221226180;
pub const MD_NTSTATUS_WIN_STATUS_DATATYPE_MISALIGNMENT_ERROR: ::libc::c_uint = 3221226181;
pub const MD_NTSTATUS_WIN_STATUS_WMI_READ_ONLY: ::libc::c_uint = 3221226182;
pub const MD_NTSTATUS_WIN_STATUS_WMI_SET_FAILURE: ::libc::c_uint = 3221226183;
pub const MD_NTSTATUS_WIN_STATUS_COMMITMENT_MINIMUM: ::libc::c_uint = 3221226184;
pub const MD_NTSTATUS_WIN_STATUS_REG_NAT_CONSUMPTION: ::libc::c_uint = 3221226185;
pub const MD_NTSTATUS_WIN_STATUS_TRANSPORT_FULL: ::libc::c_uint = 3221226186;
pub const MD_NTSTATUS_WIN_STATUS_DS_SAM_INIT_FAILURE: ::libc::c_uint = 3221226187;
pub const MD_NTSTATUS_WIN_STATUS_ONLY_IF_CONNECTED: ::libc::c_uint = 3221226188;
pub const MD_NTSTATUS_WIN_STATUS_DS_SENSITIVE_GROUP_VIOLATION: ::libc::c_uint = 3221226189;
pub const MD_NTSTATUS_WIN_STATUS_PNP_RESTART_ENUMERATION: ::libc::c_uint = 3221226190;
pub const MD_NTSTATUS_WIN_STATUS_JOURNAL_ENTRY_DELETED: ::libc::c_uint = 3221226191;
pub const MD_NTSTATUS_WIN_STATUS_DS_CANT_MOD_PRIMARYGROUPID: ::libc::c_uint = 3221226192;
pub const MD_NTSTATUS_WIN_STATUS_SYSTEM_IMAGE_BAD_SIGNATURE: ::libc::c_uint = 3221226193;
pub const MD_NTSTATUS_WIN_STATUS_PNP_REBOOT_REQUIRED: ::libc::c_uint = 3221226194;
pub const MD_NTSTATUS_WIN_STATUS_POWER_STATE_INVALID: ::libc::c_uint = 3221226195;
pub const MD_NTSTATUS_WIN_STATUS_DS_INVALID_GROUP_TYPE: ::libc::c_uint = 3221226196;
pub const MD_NTSTATUS_WIN_STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN: ::libc::c_uint = 3221226197;
pub const MD_NTSTATUS_WIN_STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN: ::libc::c_uint = 3221226198;
pub const MD_NTSTATUS_WIN_STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER: ::libc::c_uint = 3221226199;
pub const MD_NTSTATUS_WIN_STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER: ::libc::c_uint = 3221226200;
pub const MD_NTSTATUS_WIN_STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER: ::libc::c_uint = 3221226201;
pub const MD_NTSTATUS_WIN_STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER: ::libc::c_uint =
    3221226202;
pub const MD_NTSTATUS_WIN_STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER: ::libc::c_uint =
    3221226203;
pub const MD_NTSTATUS_WIN_STATUS_DS_HAVE_PRIMARY_MEMBERS: ::libc::c_uint = 3221226204;
pub const MD_NTSTATUS_WIN_STATUS_WMI_NOT_SUPPORTED: ::libc::c_uint = 3221226205;
pub const MD_NTSTATUS_WIN_STATUS_INSUFFICIENT_POWER: ::libc::c_uint = 3221226206;
pub const MD_NTSTATUS_WIN_STATUS_SAM_NEED_BOOTKEY_PASSWORD: ::libc::c_uint = 3221226207;
pub const MD_NTSTATUS_WIN_STATUS_SAM_NEED_BOOTKEY_FLOPPY: ::libc::c_uint = 3221226208;
pub const MD_NTSTATUS_WIN_STATUS_DS_CANT_START: ::libc::c_uint = 3221226209;
pub const MD_NTSTATUS_WIN_STATUS_DS_INIT_FAILURE: ::libc::c_uint = 3221226210;
pub const MD_NTSTATUS_WIN_STATUS_SAM_INIT_FAILURE: ::libc::c_uint = 3221226211;
pub const MD_NTSTATUS_WIN_STATUS_DS_GC_REQUIRED: ::libc::c_uint = 3221226212;
pub const MD_NTSTATUS_WIN_STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY: ::libc::c_uint = 3221226213;
pub const MD_NTSTATUS_WIN_STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS: ::libc::c_uint = 3221226214;
pub const MD_NTSTATUS_WIN_STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED: ::libc::c_uint = 3221226215;
pub const MD_NTSTATUS_WIN_STATUS_MULTIPLE_FAULT_VIOLATION: ::libc::c_uint = 3221226216;
pub const MD_NTSTATUS_WIN_STATUS_CURRENT_DOMAIN_NOT_ALLOWED: ::libc::c_uint = 3221226217;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_MAKE: ::libc::c_uint = 3221226218;
pub const MD_NTSTATUS_WIN_STATUS_SYSTEM_SHUTDOWN: ::libc::c_uint = 3221226219;
pub const MD_NTSTATUS_WIN_STATUS_DS_INIT_FAILURE_CONSOLE: ::libc::c_uint = 3221226220;
pub const MD_NTSTATUS_WIN_STATUS_DS_SAM_INIT_FAILURE_CONSOLE: ::libc::c_uint = 3221226221;
pub const MD_NTSTATUS_WIN_STATUS_UNFINISHED_CONTEXT_DELETED: ::libc::c_uint = 3221226222;
pub const MD_NTSTATUS_WIN_STATUS_NO_TGT_REPLY: ::libc::c_uint = 3221226223;
pub const MD_NTSTATUS_WIN_STATUS_OBJECTID_NOT_FOUND: ::libc::c_uint = 3221226224;
pub const MD_NTSTATUS_WIN_STATUS_NO_IP_ADDRESSES: ::libc::c_uint = 3221226225;
pub const MD_NTSTATUS_WIN_STATUS_WRONG_CREDENTIAL_HANDLE: ::libc::c_uint = 3221226226;
pub const MD_NTSTATUS_WIN_STATUS_CRYPTO_SYSTEM_INVALID: ::libc::c_uint = 3221226227;
pub const MD_NTSTATUS_WIN_STATUS_MAX_REFERRALS_EXCEEDED: ::libc::c_uint = 3221226228;
pub const MD_NTSTATUS_WIN_STATUS_MUST_BE_KDC: ::libc::c_uint = 3221226229;
pub const MD_NTSTATUS_WIN_STATUS_STRONG_CRYPTO_NOT_SUPPORTED: ::libc::c_uint = 3221226230;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_PRINCIPALS: ::libc::c_uint = 3221226231;
pub const MD_NTSTATUS_WIN_STATUS_NO_PA_DATA: ::libc::c_uint = 3221226232;
pub const MD_NTSTATUS_WIN_STATUS_PKINIT_NAME_MISMATCH: ::libc::c_uint = 3221226233;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_LOGON_REQUIRED: ::libc::c_uint = 3221226234;
pub const MD_NTSTATUS_WIN_STATUS_KDC_INVALID_REQUEST: ::libc::c_uint = 3221226235;
pub const MD_NTSTATUS_WIN_STATUS_KDC_UNABLE_TO_REFER: ::libc::c_uint = 3221226236;
pub const MD_NTSTATUS_WIN_STATUS_KDC_UNKNOWN_ETYPE: ::libc::c_uint = 3221226237;
pub const MD_NTSTATUS_WIN_STATUS_SHUTDOWN_IN_PROGRESS: ::libc::c_uint = 3221226238;
pub const MD_NTSTATUS_WIN_STATUS_SERVER_SHUTDOWN_IN_PROGRESS: ::libc::c_uint = 3221226239;
pub const MD_NTSTATUS_WIN_STATUS_NOT_SUPPORTED_ON_SBS: ::libc::c_uint = 3221226240;
pub const MD_NTSTATUS_WIN_STATUS_WMI_GUID_DISCONNECTED: ::libc::c_uint = 3221226241;
pub const MD_NTSTATUS_WIN_STATUS_WMI_ALREADY_DISABLED: ::libc::c_uint = 3221226242;
pub const MD_NTSTATUS_WIN_STATUS_WMI_ALREADY_ENABLED: ::libc::c_uint = 3221226243;
pub const MD_NTSTATUS_WIN_STATUS_MFT_TOO_FRAGMENTED: ::libc::c_uint = 3221226244;
pub const MD_NTSTATUS_WIN_STATUS_COPY_PROTECTION_FAILURE: ::libc::c_uint = 3221226245;
pub const MD_NTSTATUS_WIN_STATUS_CSS_AUTHENTICATION_FAILURE: ::libc::c_uint = 3221226246;
pub const MD_NTSTATUS_WIN_STATUS_CSS_KEY_NOT_PRESENT: ::libc::c_uint = 3221226247;
pub const MD_NTSTATUS_WIN_STATUS_CSS_KEY_NOT_ESTABLISHED: ::libc::c_uint = 3221226248;
pub const MD_NTSTATUS_WIN_STATUS_CSS_SCRAMBLED_SECTOR: ::libc::c_uint = 3221226249;
pub const MD_NTSTATUS_WIN_STATUS_CSS_REGION_MISMATCH: ::libc::c_uint = 3221226250;
pub const MD_NTSTATUS_WIN_STATUS_CSS_RESETS_EXHAUSTED: ::libc::c_uint = 3221226251;
pub const MD_NTSTATUS_WIN_STATUS_PASSWORD_CHANGE_REQUIRED: ::libc::c_uint = 3221226252;
pub const MD_NTSTATUS_WIN_STATUS_PKINIT_FAILURE: ::libc::c_uint = 3221226272;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_SUBSYSTEM_FAILURE: ::libc::c_uint = 3221226273;
pub const MD_NTSTATUS_WIN_STATUS_NO_KERB_KEY: ::libc::c_uint = 3221226274;
pub const MD_NTSTATUS_WIN_STATUS_HOST_DOWN: ::libc::c_uint = 3221226320;
pub const MD_NTSTATUS_WIN_STATUS_UNSUPPORTED_PREAUTH: ::libc::c_uint = 3221226321;
pub const MD_NTSTATUS_WIN_STATUS_EFS_ALG_BLOB_TOO_BIG: ::libc::c_uint = 3221226322;
pub const MD_NTSTATUS_WIN_STATUS_PORT_NOT_SET: ::libc::c_uint = 3221226323;
pub const MD_NTSTATUS_WIN_STATUS_DEBUGGER_INACTIVE: ::libc::c_uint = 3221226324;
pub const MD_NTSTATUS_WIN_STATUS_DS_VERSION_CHECK_FAILURE: ::libc::c_uint = 3221226325;
pub const MD_NTSTATUS_WIN_STATUS_AUDITING_DISABLED: ::libc::c_uint = 3221226326;
pub const MD_NTSTATUS_WIN_STATUS_PRENT4_MACHINE_ACCOUNT: ::libc::c_uint = 3221226327;
pub const MD_NTSTATUS_WIN_STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER: ::libc::c_uint = 3221226328;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_WIN_32: ::libc::c_uint = 3221226329;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_WIN_64: ::libc::c_uint = 3221226330;
pub const MD_NTSTATUS_WIN_STATUS_BAD_BINDINGS: ::libc::c_uint = 3221226331;
pub const MD_NTSTATUS_WIN_STATUS_NETWORK_SESSION_EXPIRED: ::libc::c_uint = 3221226332;
pub const MD_NTSTATUS_WIN_STATUS_APPHELP_BLOCK: ::libc::c_uint = 3221226333;
pub const MD_NTSTATUS_WIN_STATUS_ALL_SIDS_FILTERED: ::libc::c_uint = 3221226334;
pub const MD_NTSTATUS_WIN_STATUS_NOT_SAFE_MODE_DRIVER: ::libc::c_uint = 3221226335;
pub const MD_NTSTATUS_WIN_STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT: ::libc::c_uint = 3221226337;
pub const MD_NTSTATUS_WIN_STATUS_ACCESS_DISABLED_BY_POLICY_PATH: ::libc::c_uint = 3221226338;
pub const MD_NTSTATUS_WIN_STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER: ::libc::c_uint = 3221226339;
pub const MD_NTSTATUS_WIN_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER: ::libc::c_uint = 3221226340;
pub const MD_NTSTATUS_WIN_STATUS_FAILED_DRIVER_ENTRY: ::libc::c_uint = 3221226341;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_ENUMERATION_ERROR: ::libc::c_uint = 3221226342;
pub const MD_NTSTATUS_WIN_STATUS_MOUNT_POINT_NOT_RESOLVED: ::libc::c_uint = 3221226344;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_DEVICE_OBJECT_PARAMETER: ::libc::c_uint = 3221226345;
pub const MD_NTSTATUS_WIN_STATUS_MCA_OCCURED: ::libc::c_uint = 3221226346;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_BLOCKED_CRITICAL: ::libc::c_uint = 3221226347;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_BLOCKED: ::libc::c_uint = 3221226348;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_DATABASE_ERROR: ::libc::c_uint = 3221226349;
pub const MD_NTSTATUS_WIN_STATUS_SYSTEM_HIVE_TOO_LARGE: ::libc::c_uint = 3221226350;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMPORT_OF_NON_DLL: ::libc::c_uint = 3221226351;
pub const MD_NTSTATUS_WIN_STATUS_NO_SECRETS: ::libc::c_uint = 3221226353;
pub const MD_NTSTATUS_WIN_STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY: ::libc::c_uint = 3221226354;
pub const MD_NTSTATUS_WIN_STATUS_FAILED_STACK_SWITCH: ::libc::c_uint = 3221226355;
pub const MD_NTSTATUS_WIN_STATUS_HEAP_CORRUPTION: ::libc::c_uint = 3221226356;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_WRONG_PIN: ::libc::c_uint = 3221226368;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_CARD_BLOCKED: ::libc::c_uint = 3221226369;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED: ::libc::c_uint = 3221226370;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_NO_CARD: ::libc::c_uint = 3221226371;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_NO_KEY_CONTAINER: ::libc::c_uint = 3221226372;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_NO_CERTIFICATE: ::libc::c_uint = 3221226373;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_NO_KEYSET: ::libc::c_uint = 3221226374;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_IO_ERROR: ::libc::c_uint = 3221226375;
pub const MD_NTSTATUS_WIN_STATUS_DOWNGRADE_DETECTED: ::libc::c_uint = 3221226376;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_CERT_REVOKED: ::libc::c_uint = 3221226377;
pub const MD_NTSTATUS_WIN_STATUS_ISSUING_CA_UNTRUSTED: ::libc::c_uint = 3221226378;
pub const MD_NTSTATUS_WIN_STATUS_REVOCATION_OFFLINE_C: ::libc::c_uint = 3221226379;
pub const MD_NTSTATUS_WIN_STATUS_PKINIT_CLIENT_FAILURE: ::libc::c_uint = 3221226380;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_CERT_EXPIRED: ::libc::c_uint = 3221226381;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_FAILED_PRIOR_UNLOAD: ::libc::c_uint = 3221226382;
pub const MD_NTSTATUS_WIN_STATUS_SMARTCARD_SILENT_CONTEXT: ::libc::c_uint = 3221226383;
pub const MD_NTSTATUS_WIN_STATUS_PER_USER_TRUST_QUOTA_EXCEEDED: ::libc::c_uint = 3221226497;
pub const MD_NTSTATUS_WIN_STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED: ::libc::c_uint = 3221226498;
pub const MD_NTSTATUS_WIN_STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED: ::libc::c_uint = 3221226499;
pub const MD_NTSTATUS_WIN_STATUS_DS_NAME_NOT_UNIQUE: ::libc::c_uint = 3221226500;
pub const MD_NTSTATUS_WIN_STATUS_DS_DUPLICATE_ID_FOUND: ::libc::c_uint = 3221226501;
pub const MD_NTSTATUS_WIN_STATUS_DS_GROUP_CONVERSION_ERROR: ::libc::c_uint = 3221226502;
pub const MD_NTSTATUS_WIN_STATUS_VOLSNAP_PREPARE_HIBERNATE: ::libc::c_uint = 3221226503;
pub const MD_NTSTATUS_WIN_STATUS_USER2USER_REQUIRED: ::libc::c_uint = 3221226504;
pub const MD_NTSTATUS_WIN_STATUS_STACK_BUFFER_OVERRUN: ::libc::c_uint = 3221226505;
pub const MD_NTSTATUS_WIN_STATUS_NO_S4U_PROT_SUPPORT: ::libc::c_uint = 3221226506;
pub const MD_NTSTATUS_WIN_STATUS_CROSSREALM_DELEGATION_FAILURE: ::libc::c_uint = 3221226507;
pub const MD_NTSTATUS_WIN_STATUS_REVOCATION_OFFLINE_KDC: ::libc::c_uint = 3221226508;
pub const MD_NTSTATUS_WIN_STATUS_ISSUING_CA_UNTRUSTED_KDC: ::libc::c_uint = 3221226509;
pub const MD_NTSTATUS_WIN_STATUS_KDC_CERT_EXPIRED: ::libc::c_uint = 3221226510;
pub const MD_NTSTATUS_WIN_STATUS_KDC_CERT_REVOKED: ::libc::c_uint = 3221226511;
pub const MD_NTSTATUS_WIN_STATUS_PARAMETER_QUOTA_EXCEEDED: ::libc::c_uint = 3221226512;
pub const MD_NTSTATUS_WIN_STATUS_HIBERNATION_FAILURE: ::libc::c_uint = 3221226513;
pub const MD_NTSTATUS_WIN_STATUS_DELAY_LOAD_FAILED: ::libc::c_uint = 3221226514;
pub const MD_NTSTATUS_WIN_STATUS_AUTHENTICATION_FIREWALL_FAILED: ::libc::c_uint = 3221226515;
pub const MD_NTSTATUS_WIN_STATUS_VDM_DISALLOWED: ::libc::c_uint = 3221226516;
pub const MD_NTSTATUS_WIN_STATUS_HUNG_DISPLAY_DRIVER_THREAD: ::libc::c_uint = 3221226517;
pub const MD_NTSTATUS_WIN_STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE:
          ::libc::c_uint =
    3221226518;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_CRUNTIME_PARAMETER: ::libc::c_uint = 3221226519;
pub const MD_NTSTATUS_WIN_STATUS_NTLM_BLOCKED: ::libc::c_uint = 3221226520;
pub const MD_NTSTATUS_WIN_STATUS_DS_SRC_SID_EXISTS_IN_FOREST: ::libc::c_uint = 3221226521;
pub const MD_NTSTATUS_WIN_STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST: ::libc::c_uint = 3221226522;
pub const MD_NTSTATUS_WIN_STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST: ::libc::c_uint = 3221226523;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_USER_PRINCIPAL_NAME: ::libc::c_uint = 3221226524;
pub const MD_NTSTATUS_WIN_STATUS_FATAL_USER_CALLBACK_EXCEPTION: ::libc::c_uint = 3221226525;
pub const MD_NTSTATUS_WIN_STATUS_ASSERTION_FAILURE: ::libc::c_uint = 3221226528;
pub const MD_NTSTATUS_WIN_STATUS_VERIFIER_STOP: ::libc::c_uint = 3221226529;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_POP_STACK: ::libc::c_uint = 3221226531;
pub const MD_NTSTATUS_WIN_STATUS_INCOMPATIBLE_DRIVER_BLOCKED: ::libc::c_uint = 3221226532;
pub const MD_NTSTATUS_WIN_STATUS_HIVE_UNLOADED: ::libc::c_uint = 3221226533;
pub const MD_NTSTATUS_WIN_STATUS_COMPRESSION_DISABLED: ::libc::c_uint = 3221226534;
pub const MD_NTSTATUS_WIN_STATUS_FILE_SYSTEM_LIMITATION: ::libc::c_uint = 3221226535;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IMAGE_HASH: ::libc::c_uint = 3221226536;
pub const MD_NTSTATUS_WIN_STATUS_NOT_CAPABLE: ::libc::c_uint = 3221226537;
pub const MD_NTSTATUS_WIN_STATUS_REQUEST_OUT_OF_SEQUENCE: ::libc::c_uint = 3221226538;
pub const MD_NTSTATUS_WIN_STATUS_IMPLEMENTATION_LIMIT: ::libc::c_uint = 3221226539;
pub const MD_NTSTATUS_WIN_STATUS_ELEVATION_REQUIRED: ::libc::c_uint = 3221226540;
pub const MD_NTSTATUS_WIN_STATUS_NO_SECURITY_CONTEXT: ::libc::c_uint = 3221226541;
pub const MD_NTSTATUS_WIN_STATUS_PKU2U_CERT_FAILURE: ::libc::c_uint = 3221226543;
pub const MD_NTSTATUS_WIN_STATUS_BEYOND_VDL: ::libc::c_uint = 3221226546;
pub const MD_NTSTATUS_WIN_STATUS_ENCOUNTERED_WRITE_IN_PROGRESS: ::libc::c_uint = 3221226547;
pub const MD_NTSTATUS_WIN_STATUS_PTE_CHANGED: ::libc::c_uint = 3221226548;
pub const MD_NTSTATUS_WIN_STATUS_PURGE_FAILED: ::libc::c_uint = 3221226549;
pub const MD_NTSTATUS_WIN_STATUS_CRED_REQUIRES_CONFIRMATION: ::libc::c_uint = 3221226560;
pub const MD_NTSTATUS_WIN_STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE: ::libc::c_uint = 3221226561;
pub const MD_NTSTATUS_WIN_STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER: ::libc::c_uint = 3221226562;
pub const MD_NTSTATUS_WIN_STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE: ::libc::c_uint = 3221226563;
pub const MD_NTSTATUS_WIN_STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE: ::libc::c_uint = 3221226564;
pub const MD_NTSTATUS_WIN_STATUS_CS_ENCRYPTION_FILE_NOT_CSE: ::libc::c_uint = 3221226565;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_LABEL: ::libc::c_uint = 3221226566;
pub const MD_NTSTATUS_WIN_STATUS_DRIVER_PROCESS_TERMINATED: ::libc::c_uint = 3221226576;
pub const MD_NTSTATUS_WIN_STATUS_AMBIGUOUS_SYSTEM_DEVICE: ::libc::c_uint = 3221226577;
pub const MD_NTSTATUS_WIN_STATUS_SYSTEM_DEVICE_NOT_FOUND: ::libc::c_uint = 3221226578;
pub const MD_NTSTATUS_WIN_STATUS_RESTART_BOOT_APPLICATION: ::libc::c_uint = 3221226579;
pub const MD_NTSTATUS_WIN_STATUS_INSUFFICIENT_NVRAM_RESOURCES: ::libc::c_uint = 3221226580;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_SESSION: ::libc::c_uint = 3221226581;
pub const MD_NTSTATUS_WIN_STATUS_THREAD_ALREADY_IN_SESSION: ::libc::c_uint = 3221226582;
pub const MD_NTSTATUS_WIN_STATUS_THREAD_NOT_IN_SESSION: ::libc::c_uint = 3221226583;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_WEIGHT: ::libc::c_uint = 3221226584;
pub const MD_NTSTATUS_WIN_STATUS_REQUEST_PAUSED: ::libc::c_uint = 3221226585;
pub const MD_NTSTATUS_WIN_STATUS_NO_RANGES_PROCESSED: ::libc::c_uint = 3221226592;
pub const MD_NTSTATUS_WIN_STATUS_DISK_RESOURCES_EXHAUSTED: ::libc::c_uint = 3221226593;
pub const MD_NTSTATUS_WIN_STATUS_NEEDS_REMEDIATION: ::libc::c_uint = 3221226594;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_FEATURE_NOT_SUPPORTED: ::libc::c_uint = 3221226595;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_UNREACHABLE: ::libc::c_uint = 3221226596;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_TOKEN: ::libc::c_uint = 3221226597;
pub const MD_NTSTATUS_WIN_STATUS_SERVER_UNAVAILABLE: ::libc::c_uint = 3221226598;
pub const MD_NTSTATUS_WIN_STATUS_FILE_NOT_AVAILABLE: ::libc::c_uint = 3221226599;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_INSUFFICIENT_RESOURCES: ::libc::c_uint = 3221226600;
pub const MD_NTSTATUS_WIN_STATUS_PACKAGE_UPDATING: ::libc::c_uint = 3221226601;
pub const MD_NTSTATUS_WIN_STATUS_NOT_READ_FROM_COPY: ::libc::c_uint = 3221226602;
pub const MD_NTSTATUS_WIN_STATUS_FT_WRITE_FAILURE: ::libc::c_uint = 3221226603;
pub const MD_NTSTATUS_WIN_STATUS_FT_DI_SCAN_REQUIRED: ::libc::c_uint = 3221226604;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_NOT_EXTERNALLY_BACKED: ::libc::c_uint = 3221226605;
pub const MD_NTSTATUS_WIN_STATUS_EXTERNAL_BACKING_PROVIDER_UNKNOWN: ::libc::c_uint = 3221226606;
pub const MD_NTSTATUS_WIN_STATUS_DATA_CHECKSUM_ERROR: ::libc::c_uint = 3221226608;
pub const MD_NTSTATUS_WIN_STATUS_INTERMIXED_KERNEL_EA_OPERATION: ::libc::c_uint = 3221226609;
pub const MD_NTSTATUS_WIN_STATUS_TRIM_READ_ZERO_NOT_SUPPORTED: ::libc::c_uint = 3221226610;
pub const MD_NTSTATUS_WIN_STATUS_TOO_MANY_SEGMENT_DESCRIPTORS: ::libc::c_uint = 3221226611;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_OFFSET_ALIGNMENT: ::libc::c_uint = 3221226612;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_FIELD_IN_PARAMETER_LIST: ::libc::c_uint = 3221226613;
pub const MD_NTSTATUS_WIN_STATUS_OPERATION_IN_PROGRESS: ::libc::c_uint = 3221226614;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_INITIATOR_TARGET_PATH: ::libc::c_uint = 3221226615;
pub const MD_NTSTATUS_WIN_STATUS_SCRUB_DATA_DISABLED: ::libc::c_uint = 3221226616;
pub const MD_NTSTATUS_WIN_STATUS_NOT_REDUNDANT_STORAGE: ::libc::c_uint = 3221226617;
pub const MD_NTSTATUS_WIN_STATUS_RESIDENT_FILE_NOT_SUPPORTED: ::libc::c_uint = 3221226618;
pub const MD_NTSTATUS_WIN_STATUS_COMPRESSED_FILE_NOT_SUPPORTED: ::libc::c_uint = 3221226619;
pub const MD_NTSTATUS_WIN_STATUS_DIRECTORY_NOT_SUPPORTED: ::libc::c_uint = 3221226620;
pub const MD_NTSTATUS_WIN_STATUS_IO_OPERATION_TIMEOUT: ::libc::c_uint = 3221226621;
pub const MD_NTSTATUS_WIN_STATUS_SYSTEM_NEEDS_REMEDIATION: ::libc::c_uint = 3221226622;
pub const MD_NTSTATUS_WIN_STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN: ::libc::c_uint = 3221226623;
pub const MD_NTSTATUS_WIN_STATUS_SHARE_UNAVAILABLE: ::libc::c_uint = 3221226624;
pub const MD_NTSTATUS_WIN_STATUS_APISET_NOT_HOSTED: ::libc::c_uint = 3221226625;
pub const MD_NTSTATUS_WIN_STATUS_APISET_NOT_PRESENT: ::libc::c_uint = 3221226626;
pub const MD_NTSTATUS_WIN_STATUS_DEVICE_HARDWARE_ERROR: ::libc::c_uint = 3221226627;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_TASK_NAME: ::libc::c_uint = 3221226752;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_TASK_INDEX: ::libc::c_uint = 3221226753;
pub const MD_NTSTATUS_WIN_STATUS_THREAD_ALREADY_IN_TASK: ::libc::c_uint = 3221226754;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_BYPASS: ::libc::c_uint = 3221226755;
pub const MD_NTSTATUS_WIN_STATUS_UNDEFINED_SCOPE: ::libc::c_uint = 3221226756;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_CAP: ::libc::c_uint = 3221226757;
pub const MD_NTSTATUS_WIN_STATUS_NOT_GUI_PROCESS: ::libc::c_uint = 3221226758;
pub const MD_NTSTATUS_WIN_STATUS_FAIL_FAST_EXCEPTION: ::libc::c_uint = 3221227010;
pub const MD_NTSTATUS_WIN_STATUS_IMAGE_CERT_REVOKED: ::libc::c_uint = 3221227011;
pub const MD_NTSTATUS_WIN_STATUS_DYNAMIC_CODE_BLOCKED: ::libc::c_uint = 3221227012;
pub const MD_NTSTATUS_WIN_STATUS_PORT_CLOSED: ::libc::c_uint = 3221227264;
pub const MD_NTSTATUS_WIN_STATUS_MESSAGE_LOST: ::libc::c_uint = 3221227265;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_MESSAGE: ::libc::c_uint = 3221227266;
pub const MD_NTSTATUS_WIN_STATUS_REQUEST_CANCELED: ::libc::c_uint = 3221227267;
pub const MD_NTSTATUS_WIN_STATUS_RECURSIVE_DISPATCH: ::libc::c_uint = 3221227268;
pub const MD_NTSTATUS_WIN_STATUS_LPC_RECEIVE_BUFFER_EXPECTED: ::libc::c_uint = 3221227269;
pub const MD_NTSTATUS_WIN_STATUS_LPC_INVALID_CONNECTION_USAGE: ::libc::c_uint = 3221227270;
pub const MD_NTSTATUS_WIN_STATUS_LPC_REQUESTS_NOT_ALLOWED: ::libc::c_uint = 3221227271;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCE_IN_USE: ::libc::c_uint = 3221227272;
pub const MD_NTSTATUS_WIN_STATUS_HARDWARE_MEMORY_ERROR: ::libc::c_uint = 3221227273;
pub const MD_NTSTATUS_WIN_STATUS_THREADPOOL_HANDLE_EXCEPTION: ::libc::c_uint = 3221227274;
pub const MD_NTSTATUS_WIN_STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED: ::libc::c_uint =
    3221227275;
pub const MD_NTSTATUS_WIN_STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED: ::libc::c_uint =
    3221227276;
pub const MD_NTSTATUS_WIN_STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED: ::libc::c_uint =
    3221227277;
pub const MD_NTSTATUS_WIN_STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED: ::libc::c_uint =
    3221227278;
pub const MD_NTSTATUS_WIN_STATUS_THREADPOOL_RELEASED_DURING_OPERATION: ::libc::c_uint = 3221227279;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING: ::libc::c_uint = 3221227280;
pub const MD_NTSTATUS_WIN_STATUS_APC_RETURNED_WHILE_IMPERSONATING: ::libc::c_uint = 3221227281;
pub const MD_NTSTATUS_WIN_STATUS_PROCESS_IS_PROTECTED: ::libc::c_uint = 3221227282;
pub const MD_NTSTATUS_WIN_STATUS_MCA_EXCEPTION: ::libc::c_uint = 3221227283;
pub const MD_NTSTATUS_WIN_STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE: ::libc::c_uint = 3221227284;
pub const MD_NTSTATUS_WIN_STATUS_SYMLINK_CLASS_DISABLED: ::libc::c_uint = 3221227285;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_IDN_NORMALIZATION: ::libc::c_uint = 3221227286;
pub const MD_NTSTATUS_WIN_STATUS_NO_UNICODE_TRANSLATION: ::libc::c_uint = 3221227287;
pub const MD_NTSTATUS_WIN_STATUS_ALREADY_REGISTERED: ::libc::c_uint = 3221227288;
pub const MD_NTSTATUS_WIN_STATUS_CONTEXT_MISMATCH: ::libc::c_uint = 3221227289;
pub const MD_NTSTATUS_WIN_STATUS_PORT_ALREADY_HAS_COMPLETION_LIST: ::libc::c_uint = 3221227290;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_RETURNED_THREAD_PRIORITY: ::libc::c_uint = 3221227291;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_THREAD: ::libc::c_uint = 3221227292;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_RETURNED_TRANSACTION: ::libc::c_uint = 3221227293;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_RETURNED_LDR_LOCK: ::libc::c_uint = 3221227294;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_RETURNED_LANG: ::libc::c_uint = 3221227295;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_RETURNED_PRI_BACK: ::libc::c_uint = 3221227296;
pub const MD_NTSTATUS_WIN_STATUS_CALLBACK_RETURNED_THREAD_AFFINITY: ::libc::c_uint = 3221227297;
pub const MD_NTSTATUS_WIN_STATUS_DISK_REPAIR_DISABLED: ::libc::c_uint = 3221227520;
pub const MD_NTSTATUS_WIN_STATUS_DS_DOMAIN_RENAME_IN_PROGRESS: ::libc::c_uint = 3221227521;
pub const MD_NTSTATUS_WIN_STATUS_DISK_QUOTA_EXCEEDED: ::libc::c_uint = 3221227522;
pub const MD_NTSTATUS_WIN_STATUS_CONTENT_BLOCKED: ::libc::c_uint = 3221227524;
pub const MD_NTSTATUS_WIN_STATUS_BAD_CLUSTERS: ::libc::c_uint = 3221227525;
pub const MD_NTSTATUS_WIN_STATUS_VOLUME_DIRTY: ::libc::c_uint = 3221227526;
pub const MD_NTSTATUS_WIN_STATUS_DISK_REPAIR_UNSUCCESSFUL: ::libc::c_uint = 3221227528;
pub const MD_NTSTATUS_WIN_STATUS_CORRUPT_LOG_OVERFULL: ::libc::c_uint = 3221227529;
pub const MD_NTSTATUS_WIN_STATUS_CORRUPT_LOG_CORRUPTED: ::libc::c_uint = 3221227530;
pub const MD_NTSTATUS_WIN_STATUS_CORRUPT_LOG_UNAVAILABLE: ::libc::c_uint = 3221227531;
pub const MD_NTSTATUS_WIN_STATUS_CORRUPT_LOG_DELETED_FULL: ::libc::c_uint = 3221227532;
pub const MD_NTSTATUS_WIN_STATUS_CORRUPT_LOG_CLEARED: ::libc::c_uint = 3221227533;
pub const MD_NTSTATUS_WIN_STATUS_ORPHAN_NAME_EXHAUSTED: ::libc::c_uint = 3221227534;
pub const MD_NTSTATUS_WIN_STATUS_PROACTIVE_SCAN_IN_PROGRESS: ::libc::c_uint = 3221227535;
pub const MD_NTSTATUS_WIN_STATUS_ENCRYPTED_IO_NOT_POSSIBLE: ::libc::c_uint = 3221227536;
pub const MD_NTSTATUS_WIN_STATUS_CORRUPT_LOG_UPLEVEL_RECORDS: ::libc::c_uint = 3221227537;
pub const MD_NTSTATUS_WIN_STATUS_FILE_CHECKED_OUT: ::libc::c_uint = 3221227777;
pub const MD_NTSTATUS_WIN_STATUS_CHECKOUT_REQUIRED: ::libc::c_uint = 3221227778;
pub const MD_NTSTATUS_WIN_STATUS_BAD_FILE_TYPE: ::libc::c_uint = 3221227779;
pub const MD_NTSTATUS_WIN_STATUS_FILE_TOO_LARGE: ::libc::c_uint = 3221227780;
pub const MD_NTSTATUS_WIN_STATUS_FORMS_AUTH_REQUIRED: ::libc::c_uint = 3221227781;
pub const MD_NTSTATUS_WIN_STATUS_VIRUS_INFECTED: ::libc::c_uint = 3221227782;
pub const MD_NTSTATUS_WIN_STATUS_VIRUS_DELETED: ::libc::c_uint = 3221227783;
pub const MD_NTSTATUS_WIN_STATUS_BAD_MCFG_TABLE: ::libc::c_uint = 3221227784;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_BREAK_OPLOCK: ::libc::c_uint = 3221227785;
pub const MD_NTSTATUS_WIN_STATUS_BAD_KEY: ::libc::c_uint = 3221227786;
pub const MD_NTSTATUS_WIN_STATUS_BAD_DATA: ::libc::c_uint = 3221227787;
pub const MD_NTSTATUS_WIN_STATUS_NO_KEY: ::libc::c_uint = 3221227788;
pub const MD_NTSTATUS_WIN_STATUS_FILE_HANDLE_REVOKED: ::libc::c_uint = 3221227792;
pub const MD_NTSTATUS_WIN_STATUS_WOW_ASSERTION: ::libc::c_uint = 3221264536;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_SIGNATURE: ::libc::c_uint = 3221266432;
pub const MD_NTSTATUS_WIN_STATUS_HMAC_NOT_SUPPORTED: ::libc::c_uint = 3221266433;
pub const MD_NTSTATUS_WIN_STATUS_AUTH_TAG_MISMATCH: ::libc::c_uint = 3221266434;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_STATE_TRANSITION: ::libc::c_uint = 3221266435;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_KERNEL_INFO_VERSION: ::libc::c_uint = 3221266436;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PEP_INFO_VERSION: ::libc::c_uint = 3221266437;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_QUEUE_OVERFLOW: ::libc::c_uint = 3221266448;
pub const MD_NTSTATUS_WIN_STATUS_ND_QUEUE_OVERFLOW: ::libc::c_uint = 3221266449;
pub const MD_NTSTATUS_WIN_STATUS_HOPLIMIT_EXCEEDED: ::libc::c_uint = 3221266450;
pub const MD_NTSTATUS_WIN_STATUS_PROTOCOL_NOT_SUPPORTED: ::libc::c_uint = 3221266451;
pub const MD_NTSTATUS_WIN_STATUS_FASTPATH_REJECTED: ::libc::c_uint = 3221266452;
pub const MD_NTSTATUS_WIN_STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED: ::libc::c_uint =
    3221266560;
pub const MD_NTSTATUS_WIN_STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR: ::libc::c_uint =
    3221266561;
pub const MD_NTSTATUS_WIN_STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR: ::libc::c_uint =
    3221266562;
pub const MD_NTSTATUS_WIN_STATUS_XML_PARSE_ERROR: ::libc::c_uint = 3221266563;
pub const MD_NTSTATUS_WIN_STATUS_XMLDSIG_ERROR: ::libc::c_uint = 3221266564;
pub const MD_NTSTATUS_WIN_STATUS_WRONG_COMPARTMENT: ::libc::c_uint = 3221266565;
pub const MD_NTSTATUS_WIN_STATUS_AUTHIP_FAILURE: ::libc::c_uint = 3221266566;
pub const MD_NTSTATUS_WIN_STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS: ::libc::c_uint = 3221266567;
pub const MD_NTSTATUS_WIN_STATUS_DS_OID_NOT_FOUND: ::libc::c_uint = 3221266568;
pub const MD_NTSTATUS_WIN_STATUS_INCORRECT_ACCOUNT_TYPE: ::libc::c_uint = 3221266569;
pub const MD_NTSTATUS_WIN_STATUS_HASH_NOT_SUPPORTED: ::libc::c_uint = 3221266688;
pub const MD_NTSTATUS_WIN_STATUS_HASH_NOT_PRESENT: ::libc::c_uint = 3221266689;
pub const MD_NTSTATUS_WIN_STATUS_SECONDARY_IC_PROVIDER_NOT_REGISTERED: ::libc::c_uint = 3221266721;
pub const MD_NTSTATUS_WIN_STATUS_GPIO_CLIENT_INFORMATION_INVALID: ::libc::c_uint = 3221266722;
pub const MD_NTSTATUS_WIN_STATUS_GPIO_VERSION_NOT_SUPPORTED: ::libc::c_uint = 3221266723;
pub const MD_NTSTATUS_WIN_STATUS_GPIO_INVALID_REGISTRATION_PACKET: ::libc::c_uint = 3221266724;
pub const MD_NTSTATUS_WIN_STATUS_GPIO_OPERATION_DENIED: ::libc::c_uint = 3221266725;
pub const MD_NTSTATUS_WIN_STATUS_GPIO_INCOMPATIBLE_CONNECT_MODE: ::libc::c_uint = 3221266726;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_SWITCH_RUNLEVEL: ::libc::c_uint = 3221266753;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_RUNLEVEL_SETTING: ::libc::c_uint = 3221266754;
pub const MD_NTSTATUS_WIN_STATUS_RUNLEVEL_SWITCH_TIMEOUT: ::libc::c_uint = 3221266755;
pub const MD_NTSTATUS_WIN_STATUS_RUNLEVEL_SWITCH_AGENT_TIMEOUT: ::libc::c_uint = 3221266757;
pub const MD_NTSTATUS_WIN_STATUS_RUNLEVEL_SWITCH_IN_PROGRESS: ::libc::c_uint = 3221266758;
pub const MD_NTSTATUS_WIN_STATUS_NOT_APPCONTAINER: ::libc::c_uint = 3221266944;
pub const MD_NTSTATUS_WIN_STATUS_NOT_SUPPORTED_IN_APPCONTAINER: ::libc::c_uint = 3221266945;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_PACKAGE_SID_LENGTH: ::libc::c_uint = 3221266946;
pub const MD_NTSTATUS_WIN_STATUS_APP_DATA_NOT_FOUND: ::libc::c_uint = 3221267073;
pub const MD_NTSTATUS_WIN_STATUS_APP_DATA_EXPIRED: ::libc::c_uint = 3221267074;
pub const MD_NTSTATUS_WIN_STATUS_APP_DATA_CORRUPT: ::libc::c_uint = 3221267075;
pub const MD_NTSTATUS_WIN_STATUS_APP_DATA_LIMIT_EXCEEDED: ::libc::c_uint = 3221267076;
pub const MD_NTSTATUS_WIN_STATUS_APP_DATA_REBOOT_REQUIRED: ::libc::c_uint = 3221267077;
pub const MD_NTSTATUS_WIN_STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED: ::libc::c_uint = 3221267105;
pub const MD_NTSTATUS_WIN_STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED: ::libc::c_uint = 3221267106;
pub const MD_NTSTATUS_WIN_STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED: ::libc::c_uint = 3221267107;
pub const MD_NTSTATUS_WIN_STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED: ::libc::c_uint = 3221267108;
pub const MD_NTSTATUS_WIN_DBG_NO_STATE_CHANGE: ::libc::c_uint = 3221291009;
pub const MD_NTSTATUS_WIN_DBG_APP_NOT_IDLE: ::libc::c_uint = 3221291010;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_STRING_BINDING: ::libc::c_uint = 3221356545;
pub const MD_NTSTATUS_WIN_RPC_NT_WRONG_KIND_OF_BINDING: ::libc::c_uint = 3221356546;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_BINDING: ::libc::c_uint = 3221356547;
pub const MD_NTSTATUS_WIN_RPC_NT_PROTSEQ_NOT_SUPPORTED: ::libc::c_uint = 3221356548;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_RPC_PROTSEQ: ::libc::c_uint = 3221356549;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_STRING_UUID: ::libc::c_uint = 3221356550;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_ENDPOINT_FORMAT: ::libc::c_uint = 3221356551;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_NET_ADDR: ::libc::c_uint = 3221356552;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_ENDPOINT_FOUND: ::libc::c_uint = 3221356553;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_TIMEOUT: ::libc::c_uint = 3221356554;
pub const MD_NTSTATUS_WIN_RPC_NT_OBJECT_NOT_FOUND: ::libc::c_uint = 3221356555;
pub const MD_NTSTATUS_WIN_RPC_NT_ALREADY_REGISTERED: ::libc::c_uint = 3221356556;
pub const MD_NTSTATUS_WIN_RPC_NT_TYPE_ALREADY_REGISTERED: ::libc::c_uint = 3221356557;
pub const MD_NTSTATUS_WIN_RPC_NT_ALREADY_LISTENING: ::libc::c_uint = 3221356558;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_PROTSEQS_REGISTERED: ::libc::c_uint = 3221356559;
pub const MD_NTSTATUS_WIN_RPC_NT_NOT_LISTENING: ::libc::c_uint = 3221356560;
pub const MD_NTSTATUS_WIN_RPC_NT_UNKNOWN_MGR_TYPE: ::libc::c_uint = 3221356561;
pub const MD_NTSTATUS_WIN_RPC_NT_UNKNOWN_IF: ::libc::c_uint = 3221356562;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_BINDINGS: ::libc::c_uint = 3221356563;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_PROTSEQS: ::libc::c_uint = 3221356564;
pub const MD_NTSTATUS_WIN_RPC_NT_CANT_CREATE_ENDPOINT: ::libc::c_uint = 3221356565;
pub const MD_NTSTATUS_WIN_RPC_NT_OUT_OF_RESOURCES: ::libc::c_uint = 3221356566;
pub const MD_NTSTATUS_WIN_RPC_NT_SERVER_UNAVAILABLE: ::libc::c_uint = 3221356567;
pub const MD_NTSTATUS_WIN_RPC_NT_SERVER_TOO_BUSY: ::libc::c_uint = 3221356568;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_NETWORK_OPTIONS: ::libc::c_uint = 3221356569;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_CALL_ACTIVE: ::libc::c_uint = 3221356570;
pub const MD_NTSTATUS_WIN_RPC_NT_CALL_FAILED: ::libc::c_uint = 3221356571;
pub const MD_NTSTATUS_WIN_RPC_NT_CALL_FAILED_DNE: ::libc::c_uint = 3221356572;
pub const MD_NTSTATUS_WIN_RPC_NT_PROTOCOL_ERROR: ::libc::c_uint = 3221356573;
pub const MD_NTSTATUS_WIN_RPC_NT_UNSUPPORTED_TRANS_SYN: ::libc::c_uint = 3221356575;
pub const MD_NTSTATUS_WIN_RPC_NT_UNSUPPORTED_TYPE: ::libc::c_uint = 3221356577;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_TAG: ::libc::c_uint = 3221356578;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_BOUND: ::libc::c_uint = 3221356579;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_ENTRY_NAME: ::libc::c_uint = 3221356580;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_NAME_SYNTAX: ::libc::c_uint = 3221356581;
pub const MD_NTSTATUS_WIN_RPC_NT_UNSUPPORTED_NAME_SYNTAX: ::libc::c_uint = 3221356582;
pub const MD_NTSTATUS_WIN_RPC_NT_UUID_NO_ADDRESS: ::libc::c_uint = 3221356584;
pub const MD_NTSTATUS_WIN_RPC_NT_DUPLICATE_ENDPOINT: ::libc::c_uint = 3221356585;
pub const MD_NTSTATUS_WIN_RPC_NT_UNKNOWN_AUTHN_TYPE: ::libc::c_uint = 3221356586;
pub const MD_NTSTATUS_WIN_RPC_NT_MAX_CALLS_TOO_SMALL: ::libc::c_uint = 3221356587;
pub const MD_NTSTATUS_WIN_RPC_NT_STRING_TOO_LONG: ::libc::c_uint = 3221356588;
pub const MD_NTSTATUS_WIN_RPC_NT_PROTSEQ_NOT_FOUND: ::libc::c_uint = 3221356589;
pub const MD_NTSTATUS_WIN_RPC_NT_PROCNUM_OUT_OF_RANGE: ::libc::c_uint = 3221356590;
pub const MD_NTSTATUS_WIN_RPC_NT_BINDING_HAS_NO_AUTH: ::libc::c_uint = 3221356591;
pub const MD_NTSTATUS_WIN_RPC_NT_UNKNOWN_AUTHN_SERVICE: ::libc::c_uint = 3221356592;
pub const MD_NTSTATUS_WIN_RPC_NT_UNKNOWN_AUTHN_LEVEL: ::libc::c_uint = 3221356593;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_AUTH_IDENTITY: ::libc::c_uint = 3221356594;
pub const MD_NTSTATUS_WIN_RPC_NT_UNKNOWN_AUTHZ_SERVICE: ::libc::c_uint = 3221356595;
pub const MD_NTSTATUS_WIN_EPT_NT_INVALID_ENTRY: ::libc::c_uint = 3221356596;
pub const MD_NTSTATUS_WIN_EPT_NT_CANT_PERFORM_OP: ::libc::c_uint = 3221356597;
pub const MD_NTSTATUS_WIN_EPT_NT_NOT_REGISTERED: ::libc::c_uint = 3221356598;
pub const MD_NTSTATUS_WIN_RPC_NT_NOTHING_TO_EXPORT: ::libc::c_uint = 3221356599;
pub const MD_NTSTATUS_WIN_RPC_NT_INCOMPLETE_NAME: ::libc::c_uint = 3221356600;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_VERS_OPTION: ::libc::c_uint = 3221356601;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_MORE_MEMBERS: ::libc::c_uint = 3221356602;
pub const MD_NTSTATUS_WIN_RPC_NT_NOT_ALL_OBJS_UNEXPORTED: ::libc::c_uint = 3221356603;
pub const MD_NTSTATUS_WIN_RPC_NT_INTERFACE_NOT_FOUND: ::libc::c_uint = 3221356604;
pub const MD_NTSTATUS_WIN_RPC_NT_ENTRY_ALREADY_EXISTS: ::libc::c_uint = 3221356605;
pub const MD_NTSTATUS_WIN_RPC_NT_ENTRY_NOT_FOUND: ::libc::c_uint = 3221356606;
pub const MD_NTSTATUS_WIN_RPC_NT_NAME_SERVICE_UNAVAILABLE: ::libc::c_uint = 3221356607;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_NAF_ID: ::libc::c_uint = 3221356608;
pub const MD_NTSTATUS_WIN_RPC_NT_CANNOT_SUPPORT: ::libc::c_uint = 3221356609;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_CONTEXT_AVAILABLE: ::libc::c_uint = 3221356610;
pub const MD_NTSTATUS_WIN_RPC_NT_INTERNAL_ERROR: ::libc::c_uint = 3221356611;
pub const MD_NTSTATUS_WIN_RPC_NT_ZERO_DIVIDE: ::libc::c_uint = 3221356612;
pub const MD_NTSTATUS_WIN_RPC_NT_ADDRESS_ERROR: ::libc::c_uint = 3221356613;
pub const MD_NTSTATUS_WIN_RPC_NT_FP_DIV_ZERO: ::libc::c_uint = 3221356614;
pub const MD_NTSTATUS_WIN_RPC_NT_FP_UNDERFLOW: ::libc::c_uint = 3221356615;
pub const MD_NTSTATUS_WIN_RPC_NT_FP_OVERFLOW: ::libc::c_uint = 3221356616;
pub const MD_NTSTATUS_WIN_RPC_NT_CALL_IN_PROGRESS: ::libc::c_uint = 3221356617;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_MORE_BINDINGS: ::libc::c_uint = 3221356618;
pub const MD_NTSTATUS_WIN_RPC_NT_GROUP_MEMBER_NOT_FOUND: ::libc::c_uint = 3221356619;
pub const MD_NTSTATUS_WIN_EPT_NT_CANT_CREATE: ::libc::c_uint = 3221356620;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_OBJECT: ::libc::c_uint = 3221356621;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_INTERFACES: ::libc::c_uint = 3221356623;
pub const MD_NTSTATUS_WIN_RPC_NT_CALL_CANCELLED: ::libc::c_uint = 3221356624;
pub const MD_NTSTATUS_WIN_RPC_NT_BINDING_INCOMPLETE: ::libc::c_uint = 3221356625;
pub const MD_NTSTATUS_WIN_RPC_NT_COMM_FAILURE: ::libc::c_uint = 3221356626;
pub const MD_NTSTATUS_WIN_RPC_NT_UNSUPPORTED_AUTHN_LEVEL: ::libc::c_uint = 3221356627;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_PRINC_NAME: ::libc::c_uint = 3221356628;
pub const MD_NTSTATUS_WIN_RPC_NT_NOT_RPC_ERROR: ::libc::c_uint = 3221356629;
pub const MD_NTSTATUS_WIN_RPC_NT_SEC_PKG_ERROR: ::libc::c_uint = 3221356631;
pub const MD_NTSTATUS_WIN_RPC_NT_NOT_CANCELLED: ::libc::c_uint = 3221356632;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_ASYNC_HANDLE: ::libc::c_uint = 3221356642;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_ASYNC_CALL: ::libc::c_uint = 3221356643;
pub const MD_NTSTATUS_WIN_RPC_NT_PROXY_ACCESS_DENIED: ::libc::c_uint = 3221356644;
pub const MD_NTSTATUS_WIN_RPC_NT_COOKIE_AUTH_FAILED: ::libc::c_uint = 3221356645;
pub const MD_NTSTATUS_WIN_RPC_NT_NO_MORE_ENTRIES: ::libc::c_uint = 3221422081;
pub const MD_NTSTATUS_WIN_RPC_NT_SS_CHAR_TRANS_OPEN_FAIL: ::libc::c_uint = 3221422082;
pub const MD_NTSTATUS_WIN_RPC_NT_SS_CHAR_TRANS_SHORT_FILE: ::libc::c_uint = 3221422083;
pub const MD_NTSTATUS_WIN_RPC_NT_SS_IN_NULL_CONTEXT: ::libc::c_uint = 3221422084;
pub const MD_NTSTATUS_WIN_RPC_NT_SS_CONTEXT_MISMATCH: ::libc::c_uint = 3221422085;
pub const MD_NTSTATUS_WIN_RPC_NT_SS_CONTEXT_DAMAGED: ::libc::c_uint = 3221422086;
pub const MD_NTSTATUS_WIN_RPC_NT_SS_HANDLES_MISMATCH: ::libc::c_uint = 3221422087;
pub const MD_NTSTATUS_WIN_RPC_NT_SS_CANNOT_GET_CALL_HANDLE: ::libc::c_uint = 3221422088;
pub const MD_NTSTATUS_WIN_RPC_NT_NULL_REF_POINTER: ::libc::c_uint = 3221422089;
pub const MD_NTSTATUS_WIN_RPC_NT_ENUM_VALUE_OUT_OF_RANGE: ::libc::c_uint = 3221422090;
pub const MD_NTSTATUS_WIN_RPC_NT_BYTE_COUNT_TOO_SMALL: ::libc::c_uint = 3221422091;
pub const MD_NTSTATUS_WIN_RPC_NT_BAD_STUB_DATA: ::libc::c_uint = 3221422092;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_ES_ACTION: ::libc::c_uint = 3221422169;
pub const MD_NTSTATUS_WIN_RPC_NT_WRONG_ES_VERSION: ::libc::c_uint = 3221422170;
pub const MD_NTSTATUS_WIN_RPC_NT_WRONG_STUB_VERSION: ::libc::c_uint = 3221422171;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_PIPE_OBJECT: ::libc::c_uint = 3221422172;
pub const MD_NTSTATUS_WIN_RPC_NT_INVALID_PIPE_OPERATION: ::libc::c_uint = 3221422173;
pub const MD_NTSTATUS_WIN_RPC_NT_WRONG_PIPE_VERSION: ::libc::c_uint = 3221422174;
pub const MD_NTSTATUS_WIN_RPC_NT_PIPE_CLOSED: ::libc::c_uint = 3221422175;
pub const MD_NTSTATUS_WIN_RPC_NT_PIPE_DISCIPLINE_ERROR: ::libc::c_uint = 3221422176;
pub const MD_NTSTATUS_WIN_RPC_NT_PIPE_EMPTY: ::libc::c_uint = 3221422177;
pub const MD_NTSTATUS_WIN_STATUS_PNP_BAD_MPS_TABLE: ::libc::c_uint = 3221487669;
pub const MD_NTSTATUS_WIN_STATUS_PNP_TRANSLATION_FAILED: ::libc::c_uint = 3221487670;
pub const MD_NTSTATUS_WIN_STATUS_PNP_IRQ_TRANSLATION_FAILED: ::libc::c_uint = 3221487671;
pub const MD_NTSTATUS_WIN_STATUS_PNP_INVALID_ID: ::libc::c_uint = 3221487672;
pub const MD_NTSTATUS_WIN_STATUS_IO_REISSUE_AS_CACHED: ::libc::c_uint = 3221487673;
pub const MD_NTSTATUS_WIN_STATUS_CTX_WINSTATION_NAME_INVALID: ::libc::c_uint = 3221880833;
pub const MD_NTSTATUS_WIN_STATUS_CTX_INVALID_PD: ::libc::c_uint = 3221880834;
pub const MD_NTSTATUS_WIN_STATUS_CTX_PD_NOT_FOUND: ::libc::c_uint = 3221880835;
pub const MD_NTSTATUS_WIN_STATUS_CTX_CLOSE_PENDING: ::libc::c_uint = 3221880838;
pub const MD_NTSTATUS_WIN_STATUS_CTX_NO_OUTBUF: ::libc::c_uint = 3221880839;
pub const MD_NTSTATUS_WIN_STATUS_CTX_MODEM_INF_NOT_FOUND: ::libc::c_uint = 3221880840;
pub const MD_NTSTATUS_WIN_STATUS_CTX_INVALID_MODEMNAME: ::libc::c_uint = 3221880841;
pub const MD_NTSTATUS_WIN_STATUS_CTX_RESPONSE_ERROR: ::libc::c_uint = 3221880842;
pub const MD_NTSTATUS_WIN_STATUS_CTX_MODEM_RESPONSE_TIMEOUT: ::libc::c_uint = 3221880843;
pub const MD_NTSTATUS_WIN_STATUS_CTX_MODEM_RESPONSE_NO_CARRIER: ::libc::c_uint = 3221880844;
pub const MD_NTSTATUS_WIN_STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE: ::libc::c_uint = 3221880845;
pub const MD_NTSTATUS_WIN_STATUS_CTX_MODEM_RESPONSE_BUSY: ::libc::c_uint = 3221880846;
pub const MD_NTSTATUS_WIN_STATUS_CTX_MODEM_RESPONSE_VOICE: ::libc::c_uint = 3221880847;
pub const MD_NTSTATUS_WIN_STATUS_CTX_TD_ERROR: ::libc::c_uint = 3221880848;
pub const MD_NTSTATUS_WIN_STATUS_CTX_LICENSE_CLIENT_INVALID: ::libc::c_uint = 3221880850;
pub const MD_NTSTATUS_WIN_STATUS_CTX_LICENSE_NOT_AVAILABLE: ::libc::c_uint = 3221880851;
pub const MD_NTSTATUS_WIN_STATUS_CTX_LICENSE_EXPIRED: ::libc::c_uint = 3221880852;
pub const MD_NTSTATUS_WIN_STATUS_CTX_WINSTATION_NOT_FOUND: ::libc::c_uint = 3221880853;
pub const MD_NTSTATUS_WIN_STATUS_CTX_WINSTATION_NAME_COLLISION: ::libc::c_uint = 3221880854;
pub const MD_NTSTATUS_WIN_STATUS_CTX_WINSTATION_BUSY: ::libc::c_uint = 3221880855;
pub const MD_NTSTATUS_WIN_STATUS_CTX_BAD_VIDEO_MODE: ::libc::c_uint = 3221880856;
pub const MD_NTSTATUS_WIN_STATUS_CTX_GRAPHICS_INVALID: ::libc::c_uint = 3221880866;
pub const MD_NTSTATUS_WIN_STATUS_CTX_NOT_CONSOLE: ::libc::c_uint = 3221880868;
pub const MD_NTSTATUS_WIN_STATUS_CTX_CLIENT_QUERY_TIMEOUT: ::libc::c_uint = 3221880870;
pub const MD_NTSTATUS_WIN_STATUS_CTX_CONSOLE_DISCONNECT: ::libc::c_uint = 3221880871;
pub const MD_NTSTATUS_WIN_STATUS_CTX_CONSOLE_CONNECT: ::libc::c_uint = 3221880872;
pub const MD_NTSTATUS_WIN_STATUS_CTX_SHADOW_DENIED: ::libc::c_uint = 3221880874;
pub const MD_NTSTATUS_WIN_STATUS_CTX_WINSTATION_ACCESS_DENIED: ::libc::c_uint = 3221880875;
pub const MD_NTSTATUS_WIN_STATUS_CTX_INVALID_WD: ::libc::c_uint = 3221880878;
pub const MD_NTSTATUS_WIN_STATUS_CTX_WD_NOT_FOUND: ::libc::c_uint = 3221880879;
pub const MD_NTSTATUS_WIN_STATUS_CTX_SHADOW_INVALID: ::libc::c_uint = 3221880880;
pub const MD_NTSTATUS_WIN_STATUS_CTX_SHADOW_DISABLED: ::libc::c_uint = 3221880881;
pub const MD_NTSTATUS_WIN_STATUS_RDP_PROTOCOL_ERROR: ::libc::c_uint = 3221880882;
pub const MD_NTSTATUS_WIN_STATUS_CTX_CLIENT_LICENSE_NOT_SET: ::libc::c_uint = 3221880883;
pub const MD_NTSTATUS_WIN_STATUS_CTX_CLIENT_LICENSE_IN_USE: ::libc::c_uint = 3221880884;
pub const MD_NTSTATUS_WIN_STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE: ::libc::c_uint = 3221880885;
pub const MD_NTSTATUS_WIN_STATUS_CTX_SHADOW_NOT_RUNNING: ::libc::c_uint = 3221880886;
pub const MD_NTSTATUS_WIN_STATUS_CTX_LOGON_DISABLED: ::libc::c_uint = 3221880887;
pub const MD_NTSTATUS_WIN_STATUS_CTX_SECURITY_LAYER_ERROR: ::libc::c_uint = 3221880888;
pub const MD_NTSTATUS_WIN_STATUS_TS_INCOMPATIBLE_SESSIONS: ::libc::c_uint = 3221880889;
pub const MD_NTSTATUS_WIN_STATUS_TS_VIDEO_SUBSYSTEM_ERROR: ::libc::c_uint = 3221880890;
pub const MD_NTSTATUS_WIN_STATUS_MUI_FILE_NOT_FOUND: ::libc::c_uint = 3221946369;
pub const MD_NTSTATUS_WIN_STATUS_MUI_INVALID_FILE: ::libc::c_uint = 3221946370;
pub const MD_NTSTATUS_WIN_STATUS_MUI_INVALID_RC_CONFIG: ::libc::c_uint = 3221946371;
pub const MD_NTSTATUS_WIN_STATUS_MUI_INVALID_LOCALE_NAME: ::libc::c_uint = 3221946372;
pub const MD_NTSTATUS_WIN_STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME: ::libc::c_uint = 3221946373;
pub const MD_NTSTATUS_WIN_STATUS_MUI_FILE_NOT_LOADED: ::libc::c_uint = 3221946374;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCE_ENUM_USER_STOP: ::libc::c_uint = 3221946375;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_INVALID_NODE: ::libc::c_uint = 3222470657;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_EXISTS: ::libc::c_uint = 3222470658;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_JOIN_IN_PROGRESS: ::libc::c_uint = 3222470659;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_NOT_FOUND: ::libc::c_uint = 3222470660;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND: ::libc::c_uint = 3222470661;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NETWORK_EXISTS: ::libc::c_uint = 3222470662;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NETWORK_NOT_FOUND: ::libc::c_uint = 3222470663;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NETINTERFACE_EXISTS: ::libc::c_uint = 3222470664;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NETINTERFACE_NOT_FOUND: ::libc::c_uint = 3222470665;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_INVALID_REQUEST: ::libc::c_uint = 3222470666;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_INVALID_NETWORK_PROVIDER: ::libc::c_uint = 3222470667;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_DOWN: ::libc::c_uint = 3222470668;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_UNREACHABLE: ::libc::c_uint = 3222470669;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_NOT_MEMBER: ::libc::c_uint = 3222470670;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS: ::libc::c_uint = 3222470671;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_INVALID_NETWORK: ::libc::c_uint = 3222470672;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NO_NET_ADAPTERS: ::libc::c_uint = 3222470673;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_UP: ::libc::c_uint = 3222470674;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_PAUSED: ::libc::c_uint = 3222470675;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NODE_NOT_PAUSED: ::libc::c_uint = 3222470676;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NO_SECURITY_CONTEXT: ::libc::c_uint = 3222470677;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NETWORK_NOT_INTERNAL: ::libc::c_uint = 3222470678;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_POISONED: ::libc::c_uint = 3222470679;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_NON_CSV_PATH: ::libc::c_uint = 3222470680;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_VOLUME_NOT_LOCAL: ::libc::c_uint = 3222470681;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_READ_OPLOCK_BREAK_IN_PROGRESS: ::libc::c_uint =
    3222470688;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_AUTO_PAUSE_ERROR: ::libc::c_uint = 3222470689;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_REDIRECTED: ::libc::c_uint = 3222470690;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_NOT_REDIRECTED: ::libc::c_uint = 3222470691;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_VOLUME_DRAINING: ::libc::c_uint = 3222470692;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_SNAPSHOT_CREATION_IN_PROGRESS: ::libc::c_uint =
    3222470693;
pub const MD_NTSTATUS_WIN_STATUS_CLUSTER_CSV_VOLUME_DRAINING_SUCCEEDED_DOWNLEVEL: ::libc::c_uint =
    3222470694;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_OPCODE: ::libc::c_uint = 3222536193;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_STACK_OVERFLOW: ::libc::c_uint = 3222536194;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_ASSERT_FAILED: ::libc::c_uint = 3222536195;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_INDEX: ::libc::c_uint = 3222536196;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_ARGUMENT: ::libc::c_uint = 3222536197;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_FATAL: ::libc::c_uint = 3222536198;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_SUPERNAME: ::libc::c_uint = 3222536199;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_ARGTYPE: ::libc::c_uint = 3222536200;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_OBJTYPE: ::libc::c_uint = 3222536201;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_TARGETTYPE: ::libc::c_uint = 3222536202;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INCORRECT_ARGUMENT_COUNT: ::libc::c_uint = 3222536203;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_ADDRESS_NOT_MAPPED: ::libc::c_uint = 3222536204;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_EVENTTYPE: ::libc::c_uint = 3222536205;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_HANDLER_COLLISION: ::libc::c_uint = 3222536206;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_DATA: ::libc::c_uint = 3222536207;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_REGION: ::libc::c_uint = 3222536208;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_ACCESS_SIZE: ::libc::c_uint = 3222536209;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_ACQUIRE_GLOBAL_LOCK: ::libc::c_uint = 3222536210;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_ALREADY_INITIALIZED: ::libc::c_uint = 3222536211;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_NOT_INITIALIZED: ::libc::c_uint = 3222536212;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_MUTEX_LEVEL: ::libc::c_uint = 3222536213;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_MUTEX_NOT_OWNED: ::libc::c_uint = 3222536214;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_MUTEX_NOT_OWNER: ::libc::c_uint = 3222536215;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_RS_ACCESS: ::libc::c_uint = 3222536216;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_INVALID_TABLE: ::libc::c_uint = 3222536217;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_REG_HANDLER_FAILED: ::libc::c_uint = 3222536224;
pub const MD_NTSTATUS_WIN_STATUS_ACPI_POWER_REQUEST_FAILED: ::libc::c_uint = 3222536225;
pub const MD_NTSTATUS_WIN_STATUS_SXS_SECTION_NOT_FOUND: ::libc::c_uint = 3222601729;
pub const MD_NTSTATUS_WIN_STATUS_SXS_CANT_GEN_ACTCTX: ::libc::c_uint = 3222601730;
pub const MD_NTSTATUS_WIN_STATUS_SXS_INVALID_ACTCTXDATA_FORMAT: ::libc::c_uint = 3222601731;
pub const MD_NTSTATUS_WIN_STATUS_SXS_ASSEMBLY_NOT_FOUND: ::libc::c_uint = 3222601732;
pub const MD_NTSTATUS_WIN_STATUS_SXS_MANIFEST_FORMAT_ERROR: ::libc::c_uint = 3222601733;
pub const MD_NTSTATUS_WIN_STATUS_SXS_MANIFEST_PARSE_ERROR: ::libc::c_uint = 3222601734;
pub const MD_NTSTATUS_WIN_STATUS_SXS_ACTIVATION_CONTEXT_DISABLED: ::libc::c_uint = 3222601735;
pub const MD_NTSTATUS_WIN_STATUS_SXS_KEY_NOT_FOUND: ::libc::c_uint = 3222601736;
pub const MD_NTSTATUS_WIN_STATUS_SXS_VERSION_CONFLICT: ::libc::c_uint = 3222601737;
pub const MD_NTSTATUS_WIN_STATUS_SXS_WRONG_SECTION_TYPE: ::libc::c_uint = 3222601738;
pub const MD_NTSTATUS_WIN_STATUS_SXS_THREAD_QUERIES_DISABLED: ::libc::c_uint = 3222601739;
pub const MD_NTSTATUS_WIN_STATUS_SXS_ASSEMBLY_MISSING: ::libc::c_uint = 3222601740;
pub const MD_NTSTATUS_WIN_STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET: ::libc::c_uint = 3222601742;
pub const MD_NTSTATUS_WIN_STATUS_SXS_EARLY_DEACTIVATION: ::libc::c_uint = 3222601743;
pub const MD_NTSTATUS_WIN_STATUS_SXS_INVALID_DEACTIVATION: ::libc::c_uint = 3222601744;
pub const MD_NTSTATUS_WIN_STATUS_SXS_MULTIPLE_DEACTIVATION: ::libc::c_uint = 3222601745;
pub const MD_NTSTATUS_WIN_STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY: ::libc::c_uint =
    3222601746;
pub const MD_NTSTATUS_WIN_STATUS_SXS_PROCESS_TERMINATION_REQUESTED: ::libc::c_uint = 3222601747;
pub const MD_NTSTATUS_WIN_STATUS_SXS_CORRUPT_ACTIVATION_STACK: ::libc::c_uint = 3222601748;
pub const MD_NTSTATUS_WIN_STATUS_SXS_CORRUPTION: ::libc::c_uint = 3222601749;
pub const MD_NTSTATUS_WIN_STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE: ::libc::c_uint = 3222601750;
pub const MD_NTSTATUS_WIN_STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME: ::libc::c_uint = 3222601751;
pub const MD_NTSTATUS_WIN_STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE: ::libc::c_uint = 3222601752;
pub const MD_NTSTATUS_WIN_STATUS_SXS_IDENTITY_PARSE_ERROR: ::libc::c_uint = 3222601753;
pub const MD_NTSTATUS_WIN_STATUS_SXS_COMPONENT_STORE_CORRUPT: ::libc::c_uint = 3222601754;
pub const MD_NTSTATUS_WIN_STATUS_SXS_FILE_HASH_MISMATCH: ::libc::c_uint = 3222601755;
pub const MD_NTSTATUS_WIN_STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT: ::libc::c_uint =
    3222601756;
pub const MD_NTSTATUS_WIN_STATUS_SXS_IDENTITIES_DIFFERENT: ::libc::c_uint = 3222601757;
pub const MD_NTSTATUS_WIN_STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT: ::libc::c_uint = 3222601758;
pub const MD_NTSTATUS_WIN_STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY: ::libc::c_uint = 3222601759;
pub const MD_NTSTATUS_WIN_STATUS_ADVANCED_INSTALLER_FAILED: ::libc::c_uint = 3222601760;
pub const MD_NTSTATUS_WIN_STATUS_XML_ENCODING_MISMATCH: ::libc::c_uint = 3222601761;
pub const MD_NTSTATUS_WIN_STATUS_SXS_MANIFEST_TOO_BIG: ::libc::c_uint = 3222601762;
pub const MD_NTSTATUS_WIN_STATUS_SXS_SETTING_NOT_REGISTERED: ::libc::c_uint = 3222601763;
pub const MD_NTSTATUS_WIN_STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE: ::libc::c_uint = 3222601764;
pub const MD_NTSTATUS_WIN_STATUS_SMI_PRIMITIVE_INSTALLER_FAILED: ::libc::c_uint = 3222601765;
pub const MD_NTSTATUS_WIN_STATUS_GENERIC_COMMAND_FAILED: ::libc::c_uint = 3222601766;
pub const MD_NTSTATUS_WIN_STATUS_SXS_FILE_HASH_MISSING: ::libc::c_uint = 3222601767;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONAL_CONFLICT: ::libc::c_uint = 3222863873;
pub const MD_NTSTATUS_WIN_STATUS_INVALID_TRANSACTION: ::libc::c_uint = 3222863874;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NOT_ACTIVE: ::libc::c_uint = 3222863875;
pub const MD_NTSTATUS_WIN_STATUS_TM_INITIALIZATION_FAILED: ::libc::c_uint = 3222863876;
pub const MD_NTSTATUS_WIN_STATUS_RM_NOT_ACTIVE: ::libc::c_uint = 3222863877;
pub const MD_NTSTATUS_WIN_STATUS_RM_METADATA_CORRUPT: ::libc::c_uint = 3222863878;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NOT_JOINED: ::libc::c_uint = 3222863879;
pub const MD_NTSTATUS_WIN_STATUS_DIRECTORY_NOT_RM: ::libc::c_uint = 3222863880;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE: ::libc::c_uint = 3222863882;
pub const MD_NTSTATUS_WIN_STATUS_LOG_RESIZE_INVALID_SIZE: ::libc::c_uint = 3222863883;
pub const MD_NTSTATUS_WIN_STATUS_REMOTE_FILE_VERSION_MISMATCH: ::libc::c_uint = 3222863884;
pub const MD_NTSTATUS_WIN_STATUS_CRM_PROTOCOL_ALREADY_EXISTS: ::libc::c_uint = 3222863887;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_PROPAGATION_FAILED: ::libc::c_uint = 3222863888;
pub const MD_NTSTATUS_WIN_STATUS_CRM_PROTOCOL_NOT_FOUND: ::libc::c_uint = 3222863889;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_SUPERIOR_EXISTS: ::libc::c_uint = 3222863890;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_REQUEST_NOT_VALID: ::libc::c_uint = 3222863891;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NOT_REQUESTED: ::libc::c_uint = 3222863892;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_ALREADY_ABORTED: ::libc::c_uint = 3222863893;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_ALREADY_COMMITTED: ::libc::c_uint = 3222863894;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER: ::libc::c_uint = 3222863895;
pub const MD_NTSTATUS_WIN_STATUS_CURRENT_TRANSACTION_NOT_VALID: ::libc::c_uint = 3222863896;
pub const MD_NTSTATUS_WIN_STATUS_LOG_GROWTH_FAILED: ::libc::c_uint = 3222863897;
pub const MD_NTSTATUS_WIN_STATUS_OBJECT_NO_LONGER_EXISTS: ::libc::c_uint = 3222863905;
pub const MD_NTSTATUS_WIN_STATUS_STREAM_MINIVERSION_NOT_FOUND: ::libc::c_uint = 3222863906;
pub const MD_NTSTATUS_WIN_STATUS_STREAM_MINIVERSION_NOT_VALID: ::libc::c_uint = 3222863907;
pub const MD_NTSTATUS_WIN_STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION:
          ::libc::c_uint =
    3222863908;
pub const MD_NTSTATUS_WIN_STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT: ::libc::c_uint =
    3222863909;
pub const MD_NTSTATUS_WIN_STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS: ::libc::c_uint = 3222863910;
pub const MD_NTSTATUS_WIN_STATUS_HANDLE_NO_LONGER_VALID: ::libc::c_uint = 3222863912;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CORRUPTION_DETECTED: ::libc::c_uint = 3222863920;
pub const MD_NTSTATUS_WIN_STATUS_RM_DISCONNECTED: ::libc::c_uint = 3222863922;
pub const MD_NTSTATUS_WIN_STATUS_ENLISTMENT_NOT_SUPERIOR: ::libc::c_uint = 3222863923;
pub const MD_NTSTATUS_WIN_STATUS_FILE_IDENTITY_NOT_PERSISTENT: ::libc::c_uint = 3222863926;
pub const MD_NTSTATUS_WIN_STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY: ::libc::c_uint = 3222863927;
pub const MD_NTSTATUS_WIN_STATUS_CANT_CROSS_RM_BOUNDARY: ::libc::c_uint = 3222863928;
pub const MD_NTSTATUS_WIN_STATUS_TXF_DIR_NOT_EMPTY: ::libc::c_uint = 3222863929;
pub const MD_NTSTATUS_WIN_STATUS_INDOUBT_TRANSACTIONS_EXIST: ::libc::c_uint = 3222863930;
pub const MD_NTSTATUS_WIN_STATUS_TM_VOLATILE: ::libc::c_uint = 3222863931;
pub const MD_NTSTATUS_WIN_STATUS_ROLLBACK_TIMER_EXPIRED: ::libc::c_uint = 3222863932;
pub const MD_NTSTATUS_WIN_STATUS_TXF_ATTRIBUTE_CORRUPT: ::libc::c_uint = 3222863933;
pub const MD_NTSTATUS_WIN_STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION: ::libc::c_uint = 3222863934;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED: ::libc::c_uint = 3222863935;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE: ::libc::c_uint = 3222863936;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_REQUIRED_PROMOTION: ::libc::c_uint = 3222863939;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION: ::libc::c_uint = 3222863940;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONS_NOT_FROZEN: ::libc::c_uint = 3222863941;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_FREEZE_IN_PROGRESS: ::libc::c_uint = 3222863942;
pub const MD_NTSTATUS_WIN_STATUS_NOT_SNAPSHOT_VOLUME: ::libc::c_uint = 3222863943;
pub const MD_NTSTATUS_WIN_STATUS_NO_SAVEPOINT_WITH_OPEN_FILES: ::libc::c_uint = 3222863944;
pub const MD_NTSTATUS_WIN_STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION: ::libc::c_uint = 3222863945;
pub const MD_NTSTATUS_WIN_STATUS_TM_IDENTITY_MISMATCH: ::libc::c_uint = 3222863946;
pub const MD_NTSTATUS_WIN_STATUS_FLOATED_SECTION: ::libc::c_uint = 3222863947;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_ACCEPT_TRANSACTED_WORK: ::libc::c_uint = 3222863948;
pub const MD_NTSTATUS_WIN_STATUS_CANNOT_ABORT_TRANSACTIONS: ::libc::c_uint = 3222863949;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NOT_FOUND: ::libc::c_uint = 3222863950;
pub const MD_NTSTATUS_WIN_STATUS_RESOURCEMANAGER_NOT_FOUND: ::libc::c_uint = 3222863951;
pub const MD_NTSTATUS_WIN_STATUS_ENLISTMENT_NOT_FOUND: ::libc::c_uint = 3222863952;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONMANAGER_NOT_FOUND: ::libc::c_uint = 3222863953;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONMANAGER_NOT_ONLINE: ::libc::c_uint = 3222863954;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION: ::libc::c_uint =
    3222863955;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NOT_ROOT: ::libc::c_uint = 3222863956;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_OBJECT_EXPIRED: ::libc::c_uint = 3222863957;
pub const MD_NTSTATUS_WIN_STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION: ::libc::c_uint =
    3222863958;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED: ::libc::c_uint = 3222863959;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_RECORD_TOO_LONG: ::libc::c_uint = 3222863960;
pub const MD_NTSTATUS_WIN_STATUS_NO_LINK_TRACKING_IN_TRANSACTION: ::libc::c_uint = 3222863961;
pub const MD_NTSTATUS_WIN_STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION: ::libc::c_uint =
    3222863962;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_INTEGRITY_VIOLATED: ::libc::c_uint = 3222863963;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTIONMANAGER_IDENTITY_MISMATCH: ::libc::c_uint = 3222863964;
pub const MD_NTSTATUS_WIN_STATUS_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT: ::libc::c_uint = 3222863965;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_MUST_WRITETHROUGH: ::libc::c_uint = 3222863966;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NO_SUPERIOR: ::libc::c_uint = 3222863967;
pub const MD_NTSTATUS_WIN_STATUS_EXPIRED_HANDLE: ::libc::c_uint = 3222863968;
pub const MD_NTSTATUS_WIN_STATUS_TRANSACTION_NOT_ENLISTED: ::libc::c_uint = 3222863969;
pub const MD_NTSTATUS_WIN_STATUS_LOG_SECTOR_INVALID: ::libc::c_uint = 3222929409;
pub const MD_NTSTATUS_WIN_STATUS_LOG_SECTOR_PARITY_INVALID: ::libc::c_uint = 3222929410;
pub const MD_NTSTATUS_WIN_STATUS_LOG_SECTOR_REMAPPED: ::libc::c_uint = 3222929411;
pub const MD_NTSTATUS_WIN_STATUS_LOG_BLOCK_INCOMPLETE: ::libc::c_uint = 3222929412;
pub const MD_NTSTATUS_WIN_STATUS_LOG_INVALID_RANGE: ::libc::c_uint = 3222929413;
pub const MD_NTSTATUS_WIN_STATUS_LOG_BLOCKS_EXHAUSTED: ::libc::c_uint = 3222929414;
pub const MD_NTSTATUS_WIN_STATUS_LOG_READ_CONTEXT_INVALID: ::libc::c_uint = 3222929415;
pub const MD_NTSTATUS_WIN_STATUS_LOG_RESTART_INVALID: ::libc::c_uint = 3222929416;
pub const MD_NTSTATUS_WIN_STATUS_LOG_BLOCK_VERSION: ::libc::c_uint = 3222929417;
pub const MD_NTSTATUS_WIN_STATUS_LOG_BLOCK_INVALID: ::libc::c_uint = 3222929418;
pub const MD_NTSTATUS_WIN_STATUS_LOG_READ_MODE_INVALID: ::libc::c_uint = 3222929419;
pub const MD_NTSTATUS_WIN_STATUS_LOG_METADATA_CORRUPT: ::libc::c_uint = 3222929421;
pub const MD_NTSTATUS_WIN_STATUS_LOG_METADATA_INVALID: ::libc::c_uint = 3222929422;
pub const MD_NTSTATUS_WIN_STATUS_LOG_METADATA_INCONSISTENT: ::libc::c_uint = 3222929423;
pub const MD_NTSTATUS_WIN_STATUS_LOG_RESERVATION_INVALID: ::libc::c_uint = 3222929424;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CANT_DELETE: ::libc::c_uint = 3222929425;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CONTAINER_LIMIT_EXCEEDED: ::libc::c_uint = 3222929426;
pub const MD_NTSTATUS_WIN_STATUS_LOG_START_OF_LOG: ::libc::c_uint = 3222929427;
pub const MD_NTSTATUS_WIN_STATUS_LOG_POLICY_ALREADY_INSTALLED: ::libc::c_uint = 3222929428;
pub const MD_NTSTATUS_WIN_STATUS_LOG_POLICY_NOT_INSTALLED: ::libc::c_uint = 3222929429;
pub const MD_NTSTATUS_WIN_STATUS_LOG_POLICY_INVALID: ::libc::c_uint = 3222929430;
pub const MD_NTSTATUS_WIN_STATUS_LOG_POLICY_CONFLICT: ::libc::c_uint = 3222929431;
pub const MD_NTSTATUS_WIN_STATUS_LOG_PINNED_ARCHIVE_TAIL: ::libc::c_uint = 3222929432;
pub const MD_NTSTATUS_WIN_STATUS_LOG_RECORD_NONEXISTENT: ::libc::c_uint = 3222929433;
pub const MD_NTSTATUS_WIN_STATUS_LOG_RECORDS_RESERVED_INVALID: ::libc::c_uint = 3222929434;
pub const MD_NTSTATUS_WIN_STATUS_LOG_SPACE_RESERVED_INVALID: ::libc::c_uint = 3222929435;
pub const MD_NTSTATUS_WIN_STATUS_LOG_TAIL_INVALID: ::libc::c_uint = 3222929436;
pub const MD_NTSTATUS_WIN_STATUS_LOG_FULL: ::libc::c_uint = 3222929437;
pub const MD_NTSTATUS_WIN_STATUS_LOG_MULTIPLEXED: ::libc::c_uint = 3222929438;
pub const MD_NTSTATUS_WIN_STATUS_LOG_DEDICATED: ::libc::c_uint = 3222929439;
pub const MD_NTSTATUS_WIN_STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS: ::libc::c_uint = 3222929440;
pub const MD_NTSTATUS_WIN_STATUS_LOG_ARCHIVE_IN_PROGRESS: ::libc::c_uint = 3222929441;
pub const MD_NTSTATUS_WIN_STATUS_LOG_EPHEMERAL: ::libc::c_uint = 3222929442;
pub const MD_NTSTATUS_WIN_STATUS_LOG_NOT_ENOUGH_CONTAINERS: ::libc::c_uint = 3222929443;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CLIENT_ALREADY_REGISTERED: ::libc::c_uint = 3222929444;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CLIENT_NOT_REGISTERED: ::libc::c_uint = 3222929445;
pub const MD_NTSTATUS_WIN_STATUS_LOG_FULL_HANDLER_IN_PROGRESS: ::libc::c_uint = 3222929446;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CONTAINER_READ_FAILED: ::libc::c_uint = 3222929447;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CONTAINER_WRITE_FAILED: ::libc::c_uint = 3222929448;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CONTAINER_OPEN_FAILED: ::libc::c_uint = 3222929449;
pub const MD_NTSTATUS_WIN_STATUS_LOG_CONTAINER_STATE_INVALID: ::libc::c_uint = 3222929450;
pub const MD_NTSTATUS_WIN_STATUS_LOG_STATE_INVALID: ::libc::c_uint = 3222929451;
pub const MD_NTSTATUS_WIN_STATUS_LOG_PINNED: ::libc::c_uint = 3222929452;
pub const MD_NTSTATUS_WIN_STATUS_LOG_METADATA_FLUSH_FAILED: ::libc::c_uint = 3222929453;
pub const MD_NTSTATUS_WIN_STATUS_LOG_INCONSISTENT_SECURITY: ::libc::c_uint = 3222929454;
pub const MD_NTSTATUS_WIN_STATUS_LOG_APPENDED_FLUSH_FAILED: ::libc::c_uint = 3222929455;
pub const MD_NTSTATUS_WIN_STATUS_LOG_PINNED_RESERVATION: ::libc::c_uint = 3222929456;
pub const MD_NTSTATUS_WIN_STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD: ::libc::c_uint = 3222995178;
pub const MD_NTSTATUS_WIN_STATUS_FLT_NO_HANDLER_DEFINED: ::libc::c_uint = 3223060481;
pub const MD_NTSTATUS_WIN_STATUS_FLT_CONTEXT_ALREADY_DEFINED: ::libc::c_uint = 3223060482;
pub const MD_NTSTATUS_WIN_STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST: ::libc::c_uint = 3223060483;
pub const MD_NTSTATUS_WIN_STATUS_FLT_DISALLOW_FAST_IO: ::libc::c_uint = 3223060484;
pub const MD_NTSTATUS_WIN_STATUS_FLT_INVALID_NAME_REQUEST: ::libc::c_uint = 3223060485;
pub const MD_NTSTATUS_WIN_STATUS_FLT_NOT_SAFE_TO_POST_OPERATION: ::libc::c_uint = 3223060486;
pub const MD_NTSTATUS_WIN_STATUS_FLT_NOT_INITIALIZED: ::libc::c_uint = 3223060487;
pub const MD_NTSTATUS_WIN_STATUS_FLT_FILTER_NOT_READY: ::libc::c_uint = 3223060488;
pub const MD_NTSTATUS_WIN_STATUS_FLT_POST_OPERATION_CLEANUP: ::libc::c_uint = 3223060489;
pub const MD_NTSTATUS_WIN_STATUS_FLT_INTERNAL_ERROR: ::libc::c_uint = 3223060490;
pub const MD_NTSTATUS_WIN_STATUS_FLT_DELETING_OBJECT: ::libc::c_uint = 3223060491;
pub const MD_NTSTATUS_WIN_STATUS_FLT_MUST_BE_NONPAGED_POOL: ::libc::c_uint = 3223060492;
pub const MD_NTSTATUS_WIN_STATUS_FLT_DUPLICATE_ENTRY: ::libc::c_uint = 3223060493;
pub const MD_NTSTATUS_WIN_STATUS_FLT_CBDQ_DISABLED: ::libc::c_uint = 3223060494;
pub const MD_NTSTATUS_WIN_STATUS_FLT_DO_NOT_ATTACH: ::libc::c_uint = 3223060495;
pub const MD_NTSTATUS_WIN_STATUS_FLT_DO_NOT_DETACH: ::libc::c_uint = 3223060496;
pub const MD_NTSTATUS_WIN_STATUS_FLT_INSTANCE_ALTITUDE_COLLISION: ::libc::c_uint = 3223060497;
pub const MD_NTSTATUS_WIN_STATUS_FLT_INSTANCE_NAME_COLLISION: ::libc::c_uint = 3223060498;
pub const MD_NTSTATUS_WIN_STATUS_FLT_FILTER_NOT_FOUND: ::libc::c_uint = 3223060499;
pub const MD_NTSTATUS_WIN_STATUS_FLT_VOLUME_NOT_FOUND: ::libc::c_uint = 3223060500;
pub const MD_NTSTATUS_WIN_STATUS_FLT_INSTANCE_NOT_FOUND: ::libc::c_uint = 3223060501;
pub const MD_NTSTATUS_WIN_STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND: ::libc::c_uint = 3223060502;
pub const MD_NTSTATUS_WIN_STATUS_FLT_INVALID_CONTEXT_REGISTRATION: ::libc::c_uint = 3223060503;
pub const MD_NTSTATUS_WIN_STATUS_FLT_NAME_CACHE_MISS: ::libc::c_uint = 3223060504;
pub const MD_NTSTATUS_WIN_STATUS_FLT_NO_DEVICE_OBJECT: ::libc::c_uint = 3223060505;
pub const MD_NTSTATUS_WIN_STATUS_FLT_VOLUME_ALREADY_MOUNTED: ::libc::c_uint = 3223060506;
pub const MD_NTSTATUS_WIN_STATUS_FLT_ALREADY_ENLISTED: ::libc::c_uint = 3223060507;
pub const MD_NTSTATUS_WIN_STATUS_FLT_CONTEXT_ALREADY_LINKED: ::libc::c_uint = 3223060508;
pub const MD_NTSTATUS_WIN_STATUS_FLT_NO_WAITER_FOR_REPLY: ::libc::c_uint = 3223060512;
pub const MD_NTSTATUS_WIN_STATUS_FLT_REGISTRATION_BUSY: ::libc::c_uint = 3223060515;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_NO_DESCRIPTOR: ::libc::c_uint = 3223126017;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT: ::libc::c_uint = 3223126018;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM: ::libc::c_uint = 3223126019;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK: ::libc::c_uint = 3223126020;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED: ::libc::c_uint =
    3223126021;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK: ::libc::c_uint =
    3223126022;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK: ::libc::c_uint =
    3223126023;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA: ::libc::c_uint = 3223126024;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK: ::libc::c_uint = 3223126025;
pub const MD_NTSTATUS_WIN_STATUS_MONITOR_INVALID_MANUFACTURE_DATE: ::libc::c_uint = 3223126026;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER: ::libc::c_uint = 3223191552;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER: ::libc::c_uint = 3223191553;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER: ::libc::c_uint = 3223191554;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ADAPTER_WAS_RESET: ::libc::c_uint = 3223191555;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_DRIVER_MODEL: ::libc::c_uint = 3223191556;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PRESENT_MODE_CHANGED: ::libc::c_uint = 3223191557;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PRESENT_OCCLUDED: ::libc::c_uint = 3223191558;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PRESENT_DENIED: ::libc::c_uint = 3223191559;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CANNOTCOLORCONVERT: ::libc::c_uint = 3223191560;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DRIVER_MISMATCH: ::libc::c_uint = 3223191561;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED: ::libc::c_uint = 3223191563;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PRESENT_UNOCCLUDED: ::libc::c_uint = 3223191564;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_WINDOWDC_NOT_AVAILABLE: ::libc::c_uint = 3223191565;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_WINDOWLESS_PRESENT_DISABLED: ::libc::c_uint = 3223191566;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_VIDEO_MEMORY: ::libc::c_uint = 3223191808;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CANT_LOCK_MEMORY: ::libc::c_uint = 3223191809;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ALLOCATION_BUSY: ::libc::c_uint = 3223191810;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_TOO_MANY_REFERENCES: ::libc::c_uint = 3223191811;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_TRY_AGAIN_LATER: ::libc::c_uint = 3223191812;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_TRY_AGAIN_NOW: ::libc::c_uint = 3223191813;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ALLOCATION_INVALID: ::libc::c_uint = 3223191814;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE: ::libc::c_uint =
    3223191815;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED: ::libc::c_uint =
    3223191816;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION: ::libc::c_uint = 3223191817;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE: ::libc::c_uint = 3223191824;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION: ::libc::c_uint =
    3223191825;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ALLOCATION_CLOSED: ::libc::c_uint = 3223191826;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE: ::libc::c_uint = 3223191827;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE: ::libc::c_uint = 3223191828;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE: ::libc::c_uint = 3223191829;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST: ::libc::c_uint = 3223191830;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE: ::libc::c_uint = 3223192064;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY: ::libc::c_uint = 3223192320;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED: ::libc::c_uint = 3223192321;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED: ::libc::c_uint =
    3223192322;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDPN: ::libc::c_uint = 3223192323;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE: ::libc::c_uint = 3223192324;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET: ::libc::c_uint = 3223192325;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED: ::libc::c_uint = 3223192326;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET: ::libc::c_uint = 3223192328;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET: ::libc::c_uint = 3223192329;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_FREQUENCY: ::libc::c_uint = 3223192330;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_ACTIVE_REGION: ::libc::c_uint = 3223192331;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_TOTAL_REGION: ::libc::c_uint = 3223192332;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE: ::libc::c_uint =
    3223192336;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE: ::libc::c_uint =
    3223192337;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET: ::libc::c_uint =
    3223192338;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY: ::libc::c_uint = 3223192339;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET: ::libc::c_uint = 3223192340;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET: ::libc::c_uint =
    3223192341;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET: ::libc::c_uint =
    3223192342;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET: ::libc::c_uint = 3223192343;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_TARGET_ALREADY_IN_SET: ::libc::c_uint = 3223192344;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH: ::libc::c_uint = 3223192345;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY: ::libc::c_uint =
    3223192346;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET: ::libc::c_uint =
    3223192347;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE: ::libc::c_uint =
    3223192348;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET: ::libc::c_uint = 3223192349;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET: ::libc::c_uint =
    3223192351;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_STALE_MODESET: ::libc::c_uint = 3223192352;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET: ::libc::c_uint =
    3223192353;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE: ::libc::c_uint = 3223192354;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN: ::libc::c_uint =
    3223192355;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE: ::libc::c_uint = 3223192356;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION:
          ::libc::c_uint =
    3223192357;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES: ::libc::c_uint =
    3223192358;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY: ::libc::c_uint = 3223192359;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE: ::libc::c_uint =
    3223192360;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET: ::libc::c_uint =
    3223192361;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET: ::libc::c_uint = 3223192362;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR: ::libc::c_uint = 3223192363;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET: ::libc::c_uint = 3223192364;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET: ::libc::c_uint =
    3223192365;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE: ::libc::c_uint =
    3223192366;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE: ::libc::c_uint =
    3223192367;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_RESOURCES_NOT_RELATED: ::libc::c_uint = 3223192368;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE: ::libc::c_uint = 3223192369;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE: ::libc::c_uint = 3223192370;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET: ::libc::c_uint = 3223192371;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER:
          ::libc::c_uint =
    3223192372;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_VIDPNMGR: ::libc::c_uint = 3223192373;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_ACTIVE_VIDPN: ::libc::c_uint = 3223192374;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY: ::libc::c_uint = 3223192375;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MONITOR_NOT_CONNECTED: ::libc::c_uint = 3223192376;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY: ::libc::c_uint = 3223192377;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE: ::libc::c_uint = 3223192378;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE: ::libc::c_uint = 3223192379;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_STRIDE: ::libc::c_uint = 3223192380;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_PIXELFORMAT: ::libc::c_uint = 3223192381;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_COLORBASIS: ::libc::c_uint = 3223192382;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE: ::libc::c_uint = 3223192383;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY: ::libc::c_uint = 3223192384;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT: ::libc::c_uint =
    3223192385;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE: ::libc::c_uint = 3223192386;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN: ::libc::c_uint = 3223192387;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL: ::libc::c_uint =
    3223192388;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION:
          ::libc::c_uint =
    3223192389;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED:
          ::libc::c_uint =
    3223192390;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_GAMMA_RAMP: ::libc::c_uint = 3223192391;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED: ::libc::c_uint = 3223192392;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED: ::libc::c_uint = 3223192393;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MODE_NOT_IN_MODESET: ::libc::c_uint = 3223192394;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON:
          ::libc::c_uint =
    3223192397;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE: ::libc::c_uint = 3223192398;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE: ::libc::c_uint = 3223192399;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS: ::libc::c_uint =
    3223192400;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING: ::libc::c_uint = 3223192402;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED: ::libc::c_uint = 3223192403;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS: ::libc::c_uint =
    3223192404;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT: ::libc::c_uint = 3223192405;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM: ::libc::c_uint =
    3223192406;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN: ::libc::c_uint =
    3223192407;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT:
          ::libc::c_uint =
    3223192408;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED: ::libc::c_uint = 3223192409;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION: ::libc::c_uint =
    3223192410;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_CLIENT_TYPE: ::libc::c_uint = 3223192411;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET: ::libc::c_uint = 3223192412;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED: ::libc::c_uint =
    3223192576;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED: ::libc::c_uint =
    3223192577;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER: ::libc::c_uint = 3223192624;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED: ::libc::c_uint = 3223192625;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED: ::libc::c_uint = 3223192626;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY: ::libc::c_uint = 3223192627;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED: ::libc::c_uint = 3223192628;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON: ::libc::c_uint = 3223192629;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE: ::libc::c_uint =
    3223192630;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER: ::libc::c_uint = 3223192632;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED: ::libc::c_uint = 3223192635;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_NOT_SUPPORTED: ::libc::c_uint = 3223192832;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_COPP_NOT_SUPPORTED: ::libc::c_uint = 3223192833;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_UAB_NOT_SUPPORTED: ::libc::c_uint = 3223192834;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS: ::libc::c_uint =
    3223192835;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST: ::libc::c_uint =
    3223192837;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_INTERNAL_ERROR: ::libc::c_uint = 3223192843;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_INVALID_HANDLE: ::libc::c_uint = 3223192844;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH: ::libc::c_uint =
    3223192846;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED: ::libc::c_uint = 3223192847;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED: ::libc::c_uint = 3223192848;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PVP_HFS_FAILED: ::libc::c_uint = 3223192849;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_INVALID_SRM: ::libc::c_uint = 3223192850;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP: ::libc::c_uint =
    3223192851;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP: ::libc::c_uint =
    3223192852;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA: ::libc::c_uint =
    3223192853;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET: ::libc::c_uint = 3223192854;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH: ::libc::c_uint = 3223192855;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE: ::libc::c_uint =
    3223192856;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS: ::libc::c_uint =
    3223192858;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS:
          ::libc::c_uint =
    3223192860;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST: ::libc::c_uint =
    3223192861;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR: ::libc::c_uint = 3223192862;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS:
          ::libc::c_uint =
    3223192863;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED: ::libc::c_uint = 3223192864;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST: ::libc::c_uint =
    3223192865;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_I2C_NOT_SUPPORTED: ::libc::c_uint = 3223192960;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST: ::libc::c_uint = 3223192961;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA: ::libc::c_uint = 3223192962;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA: ::libc::c_uint = 3223192963;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED: ::libc::c_uint = 3223192964;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DDCCI_INVALID_DATA: ::libc::c_uint = 3223192965;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE:
          ::libc::c_uint =
    3223192966;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING: ::libc::c_uint =
    3223192967;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MCA_INTERNAL_ERROR: ::libc::c_uint = 3223192968;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND: ::libc::c_uint =
    3223192969;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH: ::libc::c_uint = 3223192970;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM: ::libc::c_uint =
    3223192971;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE: ::libc::c_uint =
    3223192972;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS: ::libc::c_uint = 3223192973;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED: ::libc::c_uint =
    3223193056;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME: ::libc::c_uint =
    3223193057;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP: ::libc::c_uint =
    3223193058;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED: ::libc::c_uint =
    3223193059;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INVALID_POINTER: ::libc::c_uint = 3223193060;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE: ::libc::c_uint =
    3223193061;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL: ::libc::c_uint = 3223193062;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_INTERNAL_ERROR: ::libc::c_uint = 3223193063;
pub const MD_NTSTATUS_WIN_STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS: ::libc::c_uint =
    3223193064;
pub const MD_NTSTATUS_WIN_STATUS_FVE_LOCKED_VOLUME: ::libc::c_uint = 3223388160;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NOT_ENCRYPTED: ::libc::c_uint = 3223388161;
pub const MD_NTSTATUS_WIN_STATUS_FVE_BAD_INFORMATION: ::libc::c_uint = 3223388162;
pub const MD_NTSTATUS_WIN_STATUS_FVE_TOO_SMALL: ::libc::c_uint = 3223388163;
pub const MD_NTSTATUS_WIN_STATUS_FVE_FAILED_WRONG_FS: ::libc::c_uint = 3223388164;
pub const MD_NTSTATUS_WIN_STATUS_FVE_BAD_PARTITION_SIZE: ::libc::c_uint = 3223388165;
pub const MD_NTSTATUS_WIN_STATUS_FVE_FS_NOT_EXTENDED: ::libc::c_uint = 3223388166;
pub const MD_NTSTATUS_WIN_STATUS_FVE_FS_MOUNTED: ::libc::c_uint = 3223388167;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NO_LICENSE: ::libc::c_uint = 3223388168;
pub const MD_NTSTATUS_WIN_STATUS_FVE_ACTION_NOT_ALLOWED: ::libc::c_uint = 3223388169;
pub const MD_NTSTATUS_WIN_STATUS_FVE_BAD_DATA: ::libc::c_uint = 3223388170;
pub const MD_NTSTATUS_WIN_STATUS_FVE_VOLUME_NOT_BOUND: ::libc::c_uint = 3223388171;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NOT_DATA_VOLUME: ::libc::c_uint = 3223388172;
pub const MD_NTSTATUS_WIN_STATUS_FVE_CONV_READ_ERROR: ::libc::c_uint = 3223388173;
pub const MD_NTSTATUS_WIN_STATUS_FVE_CONV_WRITE_ERROR: ::libc::c_uint = 3223388174;
pub const MD_NTSTATUS_WIN_STATUS_FVE_OVERLAPPED_UPDATE: ::libc::c_uint = 3223388175;
pub const MD_NTSTATUS_WIN_STATUS_FVE_FAILED_SECTOR_SIZE: ::libc::c_uint = 3223388176;
pub const MD_NTSTATUS_WIN_STATUS_FVE_FAILED_AUTHENTICATION: ::libc::c_uint = 3223388177;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NOT_OS_VOLUME: ::libc::c_uint = 3223388178;
pub const MD_NTSTATUS_WIN_STATUS_FVE_KEYFILE_NOT_FOUND: ::libc::c_uint = 3223388179;
pub const MD_NTSTATUS_WIN_STATUS_FVE_KEYFILE_INVALID: ::libc::c_uint = 3223388180;
pub const MD_NTSTATUS_WIN_STATUS_FVE_KEYFILE_NO_VMK: ::libc::c_uint = 3223388181;
pub const MD_NTSTATUS_WIN_STATUS_FVE_TPM_DISABLED: ::libc::c_uint = 3223388182;
pub const MD_NTSTATUS_WIN_STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO: ::libc::c_uint = 3223388183;
pub const MD_NTSTATUS_WIN_STATUS_FVE_TPM_INVALID_PCR: ::libc::c_uint = 3223388184;
pub const MD_NTSTATUS_WIN_STATUS_FVE_TPM_NO_VMK: ::libc::c_uint = 3223388185;
pub const MD_NTSTATUS_WIN_STATUS_FVE_PIN_INVALID: ::libc::c_uint = 3223388186;
pub const MD_NTSTATUS_WIN_STATUS_FVE_AUTH_INVALID_APPLICATION: ::libc::c_uint = 3223388187;
pub const MD_NTSTATUS_WIN_STATUS_FVE_AUTH_INVALID_CONFIG: ::libc::c_uint = 3223388188;
pub const MD_NTSTATUS_WIN_STATUS_FVE_DEBUGGER_ENABLED: ::libc::c_uint = 3223388189;
pub const MD_NTSTATUS_WIN_STATUS_FVE_DRY_RUN_FAILED: ::libc::c_uint = 3223388190;
pub const MD_NTSTATUS_WIN_STATUS_FVE_BAD_METADATA_POINTER: ::libc::c_uint = 3223388191;
pub const MD_NTSTATUS_WIN_STATUS_FVE_OLD_METADATA_COPY: ::libc::c_uint = 3223388192;
pub const MD_NTSTATUS_WIN_STATUS_FVE_REBOOT_REQUIRED: ::libc::c_uint = 3223388193;
pub const MD_NTSTATUS_WIN_STATUS_FVE_RAW_ACCESS: ::libc::c_uint = 3223388194;
pub const MD_NTSTATUS_WIN_STATUS_FVE_RAW_BLOCKED: ::libc::c_uint = 3223388195;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NO_AUTOUNLOCK_MASTER_KEY: ::libc::c_uint = 3223388196;
pub const MD_NTSTATUS_WIN_STATUS_FVE_MOR_FAILED: ::libc::c_uint = 3223388197;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NO_FEATURE_LICENSE: ::libc::c_uint = 3223388198;
pub const MD_NTSTATUS_WIN_STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED: ::libc::c_uint =
    3223388199;
pub const MD_NTSTATUS_WIN_STATUS_FVE_CONV_RECOVERY_FAILED: ::libc::c_uint = 3223388200;
pub const MD_NTSTATUS_WIN_STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG: ::libc::c_uint = 3223388201;
pub const MD_NTSTATUS_WIN_STATUS_FVE_INVALID_DATUM_TYPE: ::libc::c_uint = 3223388202;
pub const MD_NTSTATUS_WIN_STATUS_FVE_VOLUME_TOO_SMALL: ::libc::c_uint = 3223388208;
pub const MD_NTSTATUS_WIN_STATUS_FVE_ENH_PIN_INVALID: ::libc::c_uint = 3223388209;
pub const MD_NTSTATUS_WIN_STATUS_FVE_FULL_ENCRYPTION_NOT_ALLOWED_ON_TP_STORAGE: ::libc::c_uint =
    3223388210;
pub const MD_NTSTATUS_WIN_STATUS_FVE_WIPE_NOT_ALLOWED_ON_TP_STORAGE: ::libc::c_uint = 3223388211;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NOT_ALLOWED_ON_CSV_STACK: ::libc::c_uint = 3223388212;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NOT_ALLOWED_ON_CLUSTER: ::libc::c_uint = 3223388213;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NOT_ALLOWED_TO_UPGRADE_WHILE_CONVERTING: ::libc::c_uint =
    3223388214;
pub const MD_NTSTATUS_WIN_STATUS_FVE_WIPE_CANCEL_NOT_APPLICABLE: ::libc::c_uint = 3223388215;
pub const MD_NTSTATUS_WIN_STATUS_FVE_EDRIVE_DRY_RUN_FAILED: ::libc::c_uint = 3223388216;
pub const MD_NTSTATUS_WIN_STATUS_FVE_SECUREBOOT_DISABLED: ::libc::c_uint = 3223388217;
pub const MD_NTSTATUS_WIN_STATUS_FVE_SECUREBOOT_CONFIG_CHANGE: ::libc::c_uint = 3223388218;
pub const MD_NTSTATUS_WIN_STATUS_FVE_DEVICE_LOCKEDOUT: ::libc::c_uint = 3223388219;
pub const MD_NTSTATUS_WIN_STATUS_FVE_VOLUME_EXTEND_PREVENTS_EOW_DECRYPT: ::libc::c_uint =
    3223388220;
pub const MD_NTSTATUS_WIN_STATUS_FVE_NOT_DE_VOLUME: ::libc::c_uint = 3223388221;
pub const MD_NTSTATUS_WIN_STATUS_FVE_PROTECTION_DISABLED: ::libc::c_uint = 3223388222;
pub const MD_NTSTATUS_WIN_STATUS_FVE_PROTECTION_CANNOT_BE_DISABLED: ::libc::c_uint = 3223388223;
pub const MD_NTSTATUS_WIN_STATUS_FWP_CALLOUT_NOT_FOUND: ::libc::c_uint = 3223453697;
pub const MD_NTSTATUS_WIN_STATUS_FWP_CONDITION_NOT_FOUND: ::libc::c_uint = 3223453698;
pub const MD_NTSTATUS_WIN_STATUS_FWP_FILTER_NOT_FOUND: ::libc::c_uint = 3223453699;
pub const MD_NTSTATUS_WIN_STATUS_FWP_LAYER_NOT_FOUND: ::libc::c_uint = 3223453700;
pub const MD_NTSTATUS_WIN_STATUS_FWP_PROVIDER_NOT_FOUND: ::libc::c_uint = 3223453701;
pub const MD_NTSTATUS_WIN_STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND: ::libc::c_uint = 3223453702;
pub const MD_NTSTATUS_WIN_STATUS_FWP_SUBLAYER_NOT_FOUND: ::libc::c_uint = 3223453703;
pub const MD_NTSTATUS_WIN_STATUS_FWP_NOT_FOUND: ::libc::c_uint = 3223453704;
pub const MD_NTSTATUS_WIN_STATUS_FWP_ALREADY_EXISTS: ::libc::c_uint = 3223453705;
pub const MD_NTSTATUS_WIN_STATUS_FWP_IN_USE: ::libc::c_uint = 3223453706;
pub const MD_NTSTATUS_WIN_STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS: ::libc::c_uint = 3223453707;
pub const MD_NTSTATUS_WIN_STATUS_FWP_WRONG_SESSION: ::libc::c_uint = 3223453708;
pub const MD_NTSTATUS_WIN_STATUS_FWP_NO_TXN_IN_PROGRESS: ::libc::c_uint = 3223453709;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TXN_IN_PROGRESS: ::libc::c_uint = 3223453710;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TXN_ABORTED: ::libc::c_uint = 3223453711;
pub const MD_NTSTATUS_WIN_STATUS_FWP_SESSION_ABORTED: ::libc::c_uint = 3223453712;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INCOMPATIBLE_TXN: ::libc::c_uint = 3223453713;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TIMEOUT: ::libc::c_uint = 3223453714;
pub const MD_NTSTATUS_WIN_STATUS_FWP_NET_EVENTS_DISABLED: ::libc::c_uint = 3223453715;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INCOMPATIBLE_LAYER: ::libc::c_uint = 3223453716;
pub const MD_NTSTATUS_WIN_STATUS_FWP_KM_CLIENTS_ONLY: ::libc::c_uint = 3223453717;
pub const MD_NTSTATUS_WIN_STATUS_FWP_LIFETIME_MISMATCH: ::libc::c_uint = 3223453718;
pub const MD_NTSTATUS_WIN_STATUS_FWP_BUILTIN_OBJECT: ::libc::c_uint = 3223453719;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TOO_MANY_CALLOUTS: ::libc::c_uint = 3223453720;
pub const MD_NTSTATUS_WIN_STATUS_FWP_NOTIFICATION_DROPPED: ::libc::c_uint = 3223453721;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TRAFFIC_MISMATCH: ::libc::c_uint = 3223453722;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INCOMPATIBLE_SA_STATE: ::libc::c_uint = 3223453723;
pub const MD_NTSTATUS_WIN_STATUS_FWP_NULL_POINTER: ::libc::c_uint = 3223453724;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_ENUMERATOR: ::libc::c_uint = 3223453725;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_FLAGS: ::libc::c_uint = 3223453726;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_NET_MASK: ::libc::c_uint = 3223453727;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_RANGE: ::libc::c_uint = 3223453728;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_INTERVAL: ::libc::c_uint = 3223453729;
pub const MD_NTSTATUS_WIN_STATUS_FWP_ZERO_LENGTH_ARRAY: ::libc::c_uint = 3223453730;
pub const MD_NTSTATUS_WIN_STATUS_FWP_NULL_DISPLAY_NAME: ::libc::c_uint = 3223453731;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_ACTION_TYPE: ::libc::c_uint = 3223453732;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_WEIGHT: ::libc::c_uint = 3223453733;
pub const MD_NTSTATUS_WIN_STATUS_FWP_MATCH_TYPE_MISMATCH: ::libc::c_uint = 3223453734;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TYPE_MISMATCH: ::libc::c_uint = 3223453735;
pub const MD_NTSTATUS_WIN_STATUS_FWP_OUT_OF_BOUNDS: ::libc::c_uint = 3223453736;
pub const MD_NTSTATUS_WIN_STATUS_FWP_RESERVED: ::libc::c_uint = 3223453737;
pub const MD_NTSTATUS_WIN_STATUS_FWP_DUPLICATE_CONDITION: ::libc::c_uint = 3223453738;
pub const MD_NTSTATUS_WIN_STATUS_FWP_DUPLICATE_KEYMOD: ::libc::c_uint = 3223453739;
pub const MD_NTSTATUS_WIN_STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER: ::libc::c_uint = 3223453740;
pub const MD_NTSTATUS_WIN_STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER: ::libc::c_uint = 3223453741;
pub const MD_NTSTATUS_WIN_STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER: ::libc::c_uint = 3223453742;
pub const MD_NTSTATUS_WIN_STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT: ::libc::c_uint = 3223453743;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INCOMPATIBLE_AUTH_METHOD: ::libc::c_uint = 3223453744;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INCOMPATIBLE_DH_GROUP: ::libc::c_uint = 3223453745;
pub const MD_NTSTATUS_WIN_STATUS_FWP_EM_NOT_SUPPORTED: ::libc::c_uint = 3223453746;
pub const MD_NTSTATUS_WIN_STATUS_FWP_NEVER_MATCH: ::libc::c_uint = 3223453747;
pub const MD_NTSTATUS_WIN_STATUS_FWP_PROVIDER_CONTEXT_MISMATCH: ::libc::c_uint = 3223453748;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_PARAMETER: ::libc::c_uint = 3223453749;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TOO_MANY_SUBLAYERS: ::libc::c_uint = 3223453750;
pub const MD_NTSTATUS_WIN_STATUS_FWP_CALLOUT_NOTIFICATION_FAILED: ::libc::c_uint = 3223453751;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_AUTH_TRANSFORM: ::libc::c_uint = 3223453752;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_CIPHER_TRANSFORM: ::libc::c_uint = 3223453753;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INCOMPATIBLE_CIPHER_TRANSFORM: ::libc::c_uint = 3223453754;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_TRANSFORM_COMBINATION: ::libc::c_uint = 3223453755;
pub const MD_NTSTATUS_WIN_STATUS_FWP_DUPLICATE_AUTH_METHOD: ::libc::c_uint = 3223453756;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_TUNNEL_ENDPOINT: ::libc::c_uint = 3223453757;
pub const MD_NTSTATUS_WIN_STATUS_FWP_L2_DRIVER_NOT_READY: ::libc::c_uint = 3223453758;
pub const MD_NTSTATUS_WIN_STATUS_FWP_KEY_DICTATOR_ALREADY_REGISTERED: ::libc::c_uint = 3223453759;
pub const MD_NTSTATUS_WIN_STATUS_FWP_KEY_DICTATION_INVALID_KEYING_MATERIAL: ::libc::c_uint =
    3223453760;
pub const MD_NTSTATUS_WIN_STATUS_FWP_CONNECTIONS_DISABLED: ::libc::c_uint = 3223453761;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INVALID_DNS_NAME: ::libc::c_uint = 3223453762;
pub const MD_NTSTATUS_WIN_STATUS_FWP_STILL_ON: ::libc::c_uint = 3223453763;
pub const MD_NTSTATUS_WIN_STATUS_FWP_IKEEXT_NOT_RUNNING: ::libc::c_uint = 3223453764;
pub const MD_NTSTATUS_WIN_STATUS_FWP_TCPIP_NOT_READY: ::libc::c_uint = 3223453952;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INJECT_HANDLE_CLOSING: ::libc::c_uint = 3223453953;
pub const MD_NTSTATUS_WIN_STATUS_FWP_INJECT_HANDLE_STALE: ::libc::c_uint = 3223453954;
pub const MD_NTSTATUS_WIN_STATUS_FWP_CANNOT_PEND: ::libc::c_uint = 3223453955;
pub const MD_NTSTATUS_WIN_STATUS_FWP_DROP_NOICMP: ::libc::c_uint = 3223453956;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_CLOSING: ::libc::c_uint = 3223519234;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_BAD_VERSION: ::libc::c_uint = 3223519236;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_BAD_CHARACTERISTICS: ::libc::c_uint = 3223519237;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_ADAPTER_NOT_FOUND: ::libc::c_uint = 3223519238;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_OPEN_FAILED: ::libc::c_uint = 3223519239;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_DEVICE_FAILED: ::libc::c_uint = 3223519240;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_MULTICAST_FULL: ::libc::c_uint = 3223519241;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_MULTICAST_EXISTS: ::libc::c_uint = 3223519242;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_MULTICAST_NOT_FOUND: ::libc::c_uint = 3223519243;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_REQUEST_ABORTED: ::libc::c_uint = 3223519244;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_RESET_IN_PROGRESS: ::libc::c_uint = 3223519245;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_PACKET: ::libc::c_uint = 3223519247;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_DEVICE_REQUEST: ::libc::c_uint = 3223519248;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_ADAPTER_NOT_READY: ::libc::c_uint = 3223519249;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_LENGTH: ::libc::c_uint = 3223519252;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_DATA: ::libc::c_uint = 3223519253;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_BUFFER_TOO_SHORT: ::libc::c_uint = 3223519254;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_OID: ::libc::c_uint = 3223519255;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_ADAPTER_REMOVED: ::libc::c_uint = 3223519256;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_UNSUPPORTED_MEDIA: ::libc::c_uint = 3223519257;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_GROUP_ADDRESS_IN_USE: ::libc::c_uint = 3223519258;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_FILE_NOT_FOUND: ::libc::c_uint = 3223519259;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_ERROR_READING_FILE: ::libc::c_uint = 3223519260;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_ALREADY_MAPPED: ::libc::c_uint = 3223519261;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_RESOURCE_CONFLICT: ::libc::c_uint = 3223519262;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_MEDIA_DISCONNECTED: ::libc::c_uint = 3223519263;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_ADDRESS: ::libc::c_uint = 3223519266;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_PAUSED: ::libc::c_uint = 3223519274;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INTERFACE_NOT_FOUND: ::libc::c_uint = 3223519275;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_UNSUPPORTED_REVISION: ::libc::c_uint = 3223519276;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_PORT: ::libc::c_uint = 3223519277;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_INVALID_PORT_STATE: ::libc::c_uint = 3223519278;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_LOW_POWER_STATE: ::libc::c_uint = 3223519279;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_REINIT_REQUIRED: ::libc::c_uint = 3223519280;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_NOT_SUPPORTED: ::libc::c_uint = 3223519419;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_OFFLOAD_POLICY: ::libc::c_uint = 3223523343;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED: ::libc::c_uint = 3223523346;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_OFFLOAD_PATH_REJECTED: ::libc::c_uint = 3223523347;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED: ::libc::c_uint = 3223527424;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_DOT11_MEDIA_IN_USE: ::libc::c_uint = 3223527425;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_DOT11_POWER_STATE_INVALID: ::libc::c_uint = 3223527426;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL: ::libc::c_uint = 3223527427;
pub const MD_NTSTATUS_WIN_STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL: ::libc::c_uint = 3223527428;
pub const MD_NTSTATUS_WIN_STATUS_TPM_ERROR_MASK: ::libc::c_uint = 3223912448;
pub const MD_NTSTATUS_WIN_STATUS_TPM_AUTHFAIL: ::libc::c_uint = 3223912449;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BADINDEX: ::libc::c_uint = 3223912450;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_PARAMETER: ::libc::c_uint = 3223912451;
pub const MD_NTSTATUS_WIN_STATUS_TPM_AUDITFAILURE: ::libc::c_uint = 3223912452;
pub const MD_NTSTATUS_WIN_STATUS_TPM_CLEAR_DISABLED: ::libc::c_uint = 3223912453;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DEACTIVATED: ::libc::c_uint = 3223912454;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DISABLED: ::libc::c_uint = 3223912455;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DISABLED_CMD: ::libc::c_uint = 3223912456;
pub const MD_NTSTATUS_WIN_STATUS_TPM_FAIL: ::libc::c_uint = 3223912457;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_ORDINAL: ::libc::c_uint = 3223912458;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INSTALL_DISABLED: ::libc::c_uint = 3223912459;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_KEYHANDLE: ::libc::c_uint = 3223912460;
pub const MD_NTSTATUS_WIN_STATUS_TPM_KEYNOTFOUND: ::libc::c_uint = 3223912461;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INAPPROPRIATE_ENC: ::libc::c_uint = 3223912462;
pub const MD_NTSTATUS_WIN_STATUS_TPM_MIGRATEFAIL: ::libc::c_uint = 3223912463;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_PCR_INFO: ::libc::c_uint = 3223912464;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOSPACE: ::libc::c_uint = 3223912465;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOSRK: ::libc::c_uint = 3223912466;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOTSEALED_BLOB: ::libc::c_uint = 3223912467;
pub const MD_NTSTATUS_WIN_STATUS_TPM_OWNER_SET: ::libc::c_uint = 3223912468;
pub const MD_NTSTATUS_WIN_STATUS_TPM_RESOURCES: ::libc::c_uint = 3223912469;
pub const MD_NTSTATUS_WIN_STATUS_TPM_SHORTRANDOM: ::libc::c_uint = 3223912470;
pub const MD_NTSTATUS_WIN_STATUS_TPM_SIZE: ::libc::c_uint = 3223912471;
pub const MD_NTSTATUS_WIN_STATUS_TPM_WRONGPCRVAL: ::libc::c_uint = 3223912472;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_PARAM_SIZE: ::libc::c_uint = 3223912473;
pub const MD_NTSTATUS_WIN_STATUS_TPM_SHA_THREAD: ::libc::c_uint = 3223912474;
pub const MD_NTSTATUS_WIN_STATUS_TPM_SHA_ERROR: ::libc::c_uint = 3223912475;
pub const MD_NTSTATUS_WIN_STATUS_TPM_FAILEDSELFTEST: ::libc::c_uint = 3223912476;
pub const MD_NTSTATUS_WIN_STATUS_TPM_AUTH2FAIL: ::libc::c_uint = 3223912477;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BADTAG: ::libc::c_uint = 3223912478;
pub const MD_NTSTATUS_WIN_STATUS_TPM_IOERROR: ::libc::c_uint = 3223912479;
pub const MD_NTSTATUS_WIN_STATUS_TPM_ENCRYPT_ERROR: ::libc::c_uint = 3223912480;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DECRYPT_ERROR: ::libc::c_uint = 3223912481;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_AUTHHANDLE: ::libc::c_uint = 3223912482;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NO_ENDORSEMENT: ::libc::c_uint = 3223912483;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_KEYUSAGE: ::libc::c_uint = 3223912484;
pub const MD_NTSTATUS_WIN_STATUS_TPM_WRONG_ENTITYTYPE: ::libc::c_uint = 3223912485;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_POSTINIT: ::libc::c_uint = 3223912486;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INAPPROPRIATE_SIG: ::libc::c_uint = 3223912487;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_KEY_PROPERTY: ::libc::c_uint = 3223912488;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_MIGRATION: ::libc::c_uint = 3223912489;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_SCHEME: ::libc::c_uint = 3223912490;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_DATASIZE: ::libc::c_uint = 3223912491;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_MODE: ::libc::c_uint = 3223912492;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_PRESENCE: ::libc::c_uint = 3223912493;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_VERSION: ::libc::c_uint = 3223912494;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NO_WRAP_TRANSPORT: ::libc::c_uint = 3223912495;
pub const MD_NTSTATUS_WIN_STATUS_TPM_AUDITFAIL_UNSUCCESSFUL: ::libc::c_uint = 3223912496;
pub const MD_NTSTATUS_WIN_STATUS_TPM_AUDITFAIL_SUCCESSFUL: ::libc::c_uint = 3223912497;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOTRESETABLE: ::libc::c_uint = 3223912498;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOTLOCAL: ::libc::c_uint = 3223912499;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_TYPE: ::libc::c_uint = 3223912500;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_RESOURCE: ::libc::c_uint = 3223912501;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOTFIPS: ::libc::c_uint = 3223912502;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_FAMILY: ::libc::c_uint = 3223912503;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NO_NV_PERMISSION: ::libc::c_uint = 3223912504;
pub const MD_NTSTATUS_WIN_STATUS_TPM_REQUIRES_SIGN: ::libc::c_uint = 3223912505;
pub const MD_NTSTATUS_WIN_STATUS_TPM_KEY_NOTSUPPORTED: ::libc::c_uint = 3223912506;
pub const MD_NTSTATUS_WIN_STATUS_TPM_AUTH_CONFLICT: ::libc::c_uint = 3223912507;
pub const MD_NTSTATUS_WIN_STATUS_TPM_AREA_LOCKED: ::libc::c_uint = 3223912508;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_LOCALITY: ::libc::c_uint = 3223912509;
pub const MD_NTSTATUS_WIN_STATUS_TPM_READ_ONLY: ::libc::c_uint = 3223912510;
pub const MD_NTSTATUS_WIN_STATUS_TPM_PER_NOWRITE: ::libc::c_uint = 3223912511;
pub const MD_NTSTATUS_WIN_STATUS_TPM_FAMILYCOUNT: ::libc::c_uint = 3223912512;
pub const MD_NTSTATUS_WIN_STATUS_TPM_WRITE_LOCKED: ::libc::c_uint = 3223912513;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_ATTRIBUTES: ::libc::c_uint = 3223912514;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_STRUCTURE: ::libc::c_uint = 3223912515;
pub const MD_NTSTATUS_WIN_STATUS_TPM_KEY_OWNER_CONTROL: ::libc::c_uint = 3223912516;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_COUNTER: ::libc::c_uint = 3223912517;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOT_FULLWRITE: ::libc::c_uint = 3223912518;
pub const MD_NTSTATUS_WIN_STATUS_TPM_CONTEXT_GAP: ::libc::c_uint = 3223912519;
pub const MD_NTSTATUS_WIN_STATUS_TPM_MAXNVWRITES: ::libc::c_uint = 3223912520;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOOPERATOR: ::libc::c_uint = 3223912521;
pub const MD_NTSTATUS_WIN_STATUS_TPM_RESOURCEMISSING: ::libc::c_uint = 3223912522;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DELEGATE_LOCK: ::libc::c_uint = 3223912523;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DELEGATE_FAMILY: ::libc::c_uint = 3223912524;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DELEGATE_ADMIN: ::libc::c_uint = 3223912525;
pub const MD_NTSTATUS_WIN_STATUS_TPM_TRANSPORT_NOTEXCLUSIVE: ::libc::c_uint = 3223912526;
pub const MD_NTSTATUS_WIN_STATUS_TPM_OWNER_CONTROL: ::libc::c_uint = 3223912527;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_RESOURCES: ::libc::c_uint = 3223912528;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_INPUT_DATA0: ::libc::c_uint = 3223912529;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_INPUT_DATA1: ::libc::c_uint = 3223912530;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_ISSUER_SETTINGS: ::libc::c_uint = 3223912531;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_TPM_SETTINGS: ::libc::c_uint = 3223912532;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_STAGE: ::libc::c_uint = 3223912533;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_ISSUER_VALIDITY: ::libc::c_uint = 3223912534;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DAA_WRONG_W: ::libc::c_uint = 3223912535;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_HANDLE: ::libc::c_uint = 3223912536;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_DELEGATE: ::libc::c_uint = 3223912537;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BADCONTEXT: ::libc::c_uint = 3223912538;
pub const MD_NTSTATUS_WIN_STATUS_TPM_TOOMANYCONTEXTS: ::libc::c_uint = 3223912539;
pub const MD_NTSTATUS_WIN_STATUS_TPM_MA_TICKET_SIGNATURE: ::libc::c_uint = 3223912540;
pub const MD_NTSTATUS_WIN_STATUS_TPM_MA_DESTINATION: ::libc::c_uint = 3223912541;
pub const MD_NTSTATUS_WIN_STATUS_TPM_MA_SOURCE: ::libc::c_uint = 3223912542;
pub const MD_NTSTATUS_WIN_STATUS_TPM_MA_AUTHORITY: ::libc::c_uint = 3223912543;
pub const MD_NTSTATUS_WIN_STATUS_TPM_PERMANENTEK: ::libc::c_uint = 3223912545;
pub const MD_NTSTATUS_WIN_STATUS_TPM_BAD_SIGNATURE: ::libc::c_uint = 3223912546;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOCONTEXTSPACE: ::libc::c_uint = 3223912547;
pub const MD_NTSTATUS_WIN_STATUS_TPM_COMMAND_BLOCKED: ::libc::c_uint = 3223913472;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INVALID_HANDLE: ::libc::c_uint = 3223913473;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DUPLICATE_VHANDLE: ::libc::c_uint = 3223913474;
pub const MD_NTSTATUS_WIN_STATUS_TPM_EMBEDDED_COMMAND_BLOCKED: ::libc::c_uint = 3223913475;
pub const MD_NTSTATUS_WIN_STATUS_TPM_EMBEDDED_COMMAND_UNSUPPORTED: ::libc::c_uint = 3223913476;
pub const MD_NTSTATUS_WIN_STATUS_TPM_RETRY: ::libc::c_uint = 3223914496;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NEEDS_SELFTEST: ::libc::c_uint = 3223914497;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DOING_SELFTEST: ::libc::c_uint = 3223914498;
pub const MD_NTSTATUS_WIN_STATUS_TPM_DEFEND_LOCK_RUNNING: ::libc::c_uint = 3223914499;
pub const MD_NTSTATUS_WIN_STATUS_TPM_COMMAND_CANCELED: ::libc::c_uint = 3223916545;
pub const MD_NTSTATUS_WIN_STATUS_TPM_TOO_MANY_CONTEXTS: ::libc::c_uint = 3223916546;
pub const MD_NTSTATUS_WIN_STATUS_TPM_NOT_FOUND: ::libc::c_uint = 3223916547;
pub const MD_NTSTATUS_WIN_STATUS_TPM_ACCESS_DENIED: ::libc::c_uint = 3223916548;
pub const MD_NTSTATUS_WIN_STATUS_TPM_INSUFFICIENT_BUFFER: ::libc::c_uint = 3223916549;
pub const MD_NTSTATUS_WIN_STATUS_TPM_PPI_FUNCTION_UNSUPPORTED: ::libc::c_uint = 3223916550;
pub const MD_NTSTATUS_WIN_STATUS_PCP_ERROR_MASK: ::libc::c_uint = 3223920640;
pub const MD_NTSTATUS_WIN_STATUS_PCP_DEVICE_NOT_READY: ::libc::c_uint = 3223920641;
pub const MD_NTSTATUS_WIN_STATUS_PCP_INVALID_HANDLE: ::libc::c_uint = 3223920642;
pub const MD_NTSTATUS_WIN_STATUS_PCP_INVALID_PARAMETER: ::libc::c_uint = 3223920643;
pub const MD_NTSTATUS_WIN_STATUS_PCP_FLAG_NOT_SUPPORTED: ::libc::c_uint = 3223920644;
pub const MD_NTSTATUS_WIN_STATUS_PCP_NOT_SUPPORTED: ::libc::c_uint = 3223920645;
pub const MD_NTSTATUS_WIN_STATUS_PCP_BUFFER_TOO_SMALL: ::libc::c_uint = 3223920646;
pub const MD_NTSTATUS_WIN_STATUS_PCP_INTERNAL_ERROR: ::libc::c_uint = 3223920647;
pub const MD_NTSTATUS_WIN_STATUS_PCP_AUTHENTICATION_FAILED: ::libc::c_uint = 3223920648;
pub const MD_NTSTATUS_WIN_STATUS_PCP_AUTHENTICATION_IGNORED: ::libc::c_uint = 3223920649;
pub const MD_NTSTATUS_WIN_STATUS_PCP_POLICY_NOT_FOUND: ::libc::c_uint = 3223920650;
pub const MD_NTSTATUS_WIN_STATUS_PCP_PROFILE_NOT_FOUND: ::libc::c_uint = 3223920651;
pub const MD_NTSTATUS_WIN_STATUS_PCP_VALIDATION_FAILED: ::libc::c_uint = 3223920652;
pub const MD_NTSTATUS_WIN_STATUS_PCP_DEVICE_NOT_FOUND: ::libc::c_uint = 3223920653;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_HYPERCALL_CODE: ::libc::c_uint = 3224698882;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_HYPERCALL_INPUT: ::libc::c_uint = 3224698883;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_ALIGNMENT: ::libc::c_uint = 3224698884;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_PARAMETER: ::libc::c_uint = 3224698885;
pub const MD_NTSTATUS_WIN_STATUS_HV_ACCESS_DENIED: ::libc::c_uint = 3224698886;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_PARTITION_STATE: ::libc::c_uint = 3224698887;
pub const MD_NTSTATUS_WIN_STATUS_HV_OPERATION_DENIED: ::libc::c_uint = 3224698888;
pub const MD_NTSTATUS_WIN_STATUS_HV_UNKNOWN_PROPERTY: ::libc::c_uint = 3224698889;
pub const MD_NTSTATUS_WIN_STATUS_HV_PROPERTY_VALUE_OUT_OF_RANGE: ::libc::c_uint = 3224698890;
pub const MD_NTSTATUS_WIN_STATUS_HV_INSUFFICIENT_MEMORY: ::libc::c_uint = 3224698891;
pub const MD_NTSTATUS_WIN_STATUS_HV_PARTITION_TOO_DEEP: ::libc::c_uint = 3224698892;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_PARTITION_ID: ::libc::c_uint = 3224698893;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_VP_INDEX: ::libc::c_uint = 3224698894;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_PORT_ID: ::libc::c_uint = 3224698897;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_CONNECTION_ID: ::libc::c_uint = 3224698898;
pub const MD_NTSTATUS_WIN_STATUS_HV_INSUFFICIENT_BUFFERS: ::libc::c_uint = 3224698899;
pub const MD_NTSTATUS_WIN_STATUS_HV_NOT_ACKNOWLEDGED: ::libc::c_uint = 3224698900;
pub const MD_NTSTATUS_WIN_STATUS_HV_ACKNOWLEDGED: ::libc::c_uint = 3224698902;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_SAVE_RESTORE_STATE: ::libc::c_uint = 3224698903;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_SYNIC_STATE: ::libc::c_uint = 3224698904;
pub const MD_NTSTATUS_WIN_STATUS_HV_OBJECT_IN_USE: ::libc::c_uint = 3224698905;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_PROXIMITY_DOMAIN_INFO: ::libc::c_uint = 3224698906;
pub const MD_NTSTATUS_WIN_STATUS_HV_NO_DATA: ::libc::c_uint = 3224698907;
pub const MD_NTSTATUS_WIN_STATUS_HV_INACTIVE: ::libc::c_uint = 3224698908;
pub const MD_NTSTATUS_WIN_STATUS_HV_NO_RESOURCES: ::libc::c_uint = 3224698909;
pub const MD_NTSTATUS_WIN_STATUS_HV_FEATURE_UNAVAILABLE: ::libc::c_uint = 3224698910;
pub const MD_NTSTATUS_WIN_STATUS_HV_INSUFFICIENT_BUFFER: ::libc::c_uint = 3224698931;
pub const MD_NTSTATUS_WIN_STATUS_HV_INSUFFICIENT_DEVICE_DOMAINS: ::libc::c_uint = 3224698936;
pub const MD_NTSTATUS_WIN_STATUS_HV_INVALID_LP_INDEX: ::libc::c_uint = 3224698945;
pub const MD_NTSTATUS_WIN_STATUS_HV_NOT_PRESENT: ::libc::c_uint = 3224702976;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_BAD_SPI: ::libc::c_uint = 3224764417;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_SA_LIFETIME_EXPIRED: ::libc::c_uint = 3224764418;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_WRONG_SA: ::libc::c_uint = 3224764419;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_REPLAY_CHECK_FAILED: ::libc::c_uint = 3224764420;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_INVALID_PACKET: ::libc::c_uint = 3224764421;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_INTEGRITY_CHECK_FAILED: ::libc::c_uint = 3224764422;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_CLEAR_TEXT_DROP: ::libc::c_uint = 3224764423;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_AUTH_FIREWALL_DROP: ::libc::c_uint = 3224764424;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_THROTTLE_DROP: ::libc::c_uint = 3224764425;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_DOSP_BLOCK: ::libc::c_uint = 3224797184;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_DOSP_RECEIVED_MULTICAST: ::libc::c_uint = 3224797185;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_DOSP_INVALID_PACKET: ::libc::c_uint = 3224797186;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED: ::libc::c_uint = 3224797187;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_DOSP_MAX_ENTRIES: ::libc::c_uint = 3224797188;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED: ::libc::c_uint = 3224797189;
pub const MD_NTSTATUS_WIN_STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES: ::libc::c_uint =
    3224797190;
pub const MD_NTSTATUS_WIN_STATUS_VID_DUPLICATE_HANDLER: ::libc::c_uint = 3224829953;
pub const MD_NTSTATUS_WIN_STATUS_VID_TOO_MANY_HANDLERS: ::libc::c_uint = 3224829954;
pub const MD_NTSTATUS_WIN_STATUS_VID_QUEUE_FULL: ::libc::c_uint = 3224829955;
pub const MD_NTSTATUS_WIN_STATUS_VID_HANDLER_NOT_PRESENT: ::libc::c_uint = 3224829956;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_OBJECT_NAME: ::libc::c_uint = 3224829957;
pub const MD_NTSTATUS_WIN_STATUS_VID_PARTITION_NAME_TOO_LONG: ::libc::c_uint = 3224829958;
pub const MD_NTSTATUS_WIN_STATUS_VID_MESSAGE_QUEUE_NAME_TOO_LONG: ::libc::c_uint = 3224829959;
pub const MD_NTSTATUS_WIN_STATUS_VID_PARTITION_ALREADY_EXISTS: ::libc::c_uint = 3224829960;
pub const MD_NTSTATUS_WIN_STATUS_VID_PARTITION_DOES_NOT_EXIST: ::libc::c_uint = 3224829961;
pub const MD_NTSTATUS_WIN_STATUS_VID_PARTITION_NAME_NOT_FOUND: ::libc::c_uint = 3224829962;
pub const MD_NTSTATUS_WIN_STATUS_VID_MESSAGE_QUEUE_ALREADY_EXISTS: ::libc::c_uint = 3224829963;
pub const MD_NTSTATUS_WIN_STATUS_VID_EXCEEDED_MBP_ENTRY_MAP_LIMIT: ::libc::c_uint = 3224829964;
pub const MD_NTSTATUS_WIN_STATUS_VID_MB_STILL_REFERENCED: ::libc::c_uint = 3224829965;
pub const MD_NTSTATUS_WIN_STATUS_VID_CHILD_GPA_PAGE_SET_CORRUPTED: ::libc::c_uint = 3224829966;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_NUMA_SETTINGS: ::libc::c_uint = 3224829967;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_NUMA_NODE_INDEX: ::libc::c_uint = 3224829968;
pub const MD_NTSTATUS_WIN_STATUS_VID_NOTIFICATION_QUEUE_ALREADY_ASSOCIATED: ::libc::c_uint =
    3224829969;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_MEMORY_BLOCK_HANDLE: ::libc::c_uint = 3224829970;
pub const MD_NTSTATUS_WIN_STATUS_VID_PAGE_RANGE_OVERFLOW: ::libc::c_uint = 3224829971;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_MESSAGE_QUEUE_HANDLE: ::libc::c_uint = 3224829972;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_GPA_RANGE_HANDLE: ::libc::c_uint = 3224829973;
pub const MD_NTSTATUS_WIN_STATUS_VID_NO_MEMORY_BLOCK_NOTIFICATION_QUEUE: ::libc::c_uint =
    3224829974;
pub const MD_NTSTATUS_WIN_STATUS_VID_MEMORY_BLOCK_LOCK_COUNT_EXCEEDED: ::libc::c_uint = 3224829975;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_PPM_HANDLE: ::libc::c_uint = 3224829976;
pub const MD_NTSTATUS_WIN_STATUS_VID_MBPS_ARE_LOCKED: ::libc::c_uint = 3224829977;
pub const MD_NTSTATUS_WIN_STATUS_VID_MESSAGE_QUEUE_CLOSED: ::libc::c_uint = 3224829978;
pub const MD_NTSTATUS_WIN_STATUS_VID_VIRTUAL_PROCESSOR_LIMIT_EXCEEDED: ::libc::c_uint = 3224829979;
pub const MD_NTSTATUS_WIN_STATUS_VID_STOP_PENDING: ::libc::c_uint = 3224829980;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_PROCESSOR_STATE: ::libc::c_uint = 3224829981;
pub const MD_NTSTATUS_WIN_STATUS_VID_EXCEEDED_KM_CONTEXT_COUNT_LIMIT: ::libc::c_uint = 3224829982;
pub const MD_NTSTATUS_WIN_STATUS_VID_KM_INTERFACE_ALREADY_INITIALIZED: ::libc::c_uint = 3224829983;
pub const MD_NTSTATUS_WIN_STATUS_VID_MB_PROPERTY_ALREADY_SET_RESET: ::libc::c_uint = 3224829984;
pub const MD_NTSTATUS_WIN_STATUS_VID_MMIO_RANGE_DESTROYED: ::libc::c_uint = 3224829985;
pub const MD_NTSTATUS_WIN_STATUS_VID_INVALID_CHILD_GPA_PAGE_SET: ::libc::c_uint = 3224829986;
pub const MD_NTSTATUS_WIN_STATUS_VID_RESERVE_PAGE_SET_IS_BEING_USED: ::libc::c_uint = 3224829987;
pub const MD_NTSTATUS_WIN_STATUS_VID_RESERVE_PAGE_SET_TOO_SMALL: ::libc::c_uint = 3224829988;
pub const MD_NTSTATUS_WIN_STATUS_VID_MBP_ALREADY_LOCKED_USING_RESERVED_PAGE: ::libc::c_uint =
    3224829989;
pub const MD_NTSTATUS_WIN_STATUS_VID_MBP_COUNT_EXCEEDED_LIMIT: ::libc::c_uint = 3224829990;
pub const MD_NTSTATUS_WIN_STATUS_VID_SAVED_STATE_CORRUPT: ::libc::c_uint = 3224829991;
pub const MD_NTSTATUS_WIN_STATUS_VID_SAVED_STATE_UNRECOGNIZED_ITEM: ::libc::c_uint = 3224829992;
pub const MD_NTSTATUS_WIN_STATUS_VID_SAVED_STATE_INCOMPATIBLE: ::libc::c_uint = 3224829993;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DATABASE_FULL: ::libc::c_uint = 3224895489;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_CONFIGURATION_CORRUPTED: ::libc::c_uint = 3224895490;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_CONFIGURATION_NOT_IN_SYNC: ::libc::c_uint = 3224895491;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_CONFIG_UPDATE_FAILED: ::libc::c_uint = 3224895492;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_CONTAINS_NON_SIMPLE_VOLUME: ::libc::c_uint =
    3224895493;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_DUPLICATE: ::libc::c_uint = 3224895494;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_DYNAMIC: ::libc::c_uint = 3224895495;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_ID_INVALID: ::libc::c_uint = 3224895496;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_INVALID: ::libc::c_uint = 3224895497;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_LAST_VOTER: ::libc::c_uint = 3224895498;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_LAYOUT_INVALID: ::libc::c_uint = 3224895499;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_LAYOUT_NON_BASIC_BETWEEN_BASIC_PARTITIONS:
          ::libc::c_uint =
    3224895500;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_LAYOUT_NOT_CYLINDER_ALIGNED: ::libc::c_uint =
    3224895501;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_LAYOUT_PARTITIONS_TOO_SMALL: ::libc::c_uint =
    3224895502;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_LAYOUT_PRIMARY_BETWEEN_LOGICAL_PARTITIONS:
          ::libc::c_uint =
    3224895503;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_LAYOUT_TOO_MANY_PARTITIONS: ::libc::c_uint =
    3224895504;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_MISSING: ::libc::c_uint = 3224895505;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_NOT_EMPTY: ::libc::c_uint = 3224895506;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_NOT_ENOUGH_SPACE: ::libc::c_uint = 3224895507;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_REVECTORING_FAILED: ::libc::c_uint = 3224895508;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_SECTOR_SIZE_INVALID: ::libc::c_uint = 3224895509;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_SET_NOT_CONTAINED: ::libc::c_uint = 3224895510;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_MEMBERS: ::libc::c_uint = 3224895511;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DISK_USED_BY_MULTIPLE_PLEXES: ::libc::c_uint = 3224895512;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DYNAMIC_DISK_NOT_SUPPORTED: ::libc::c_uint = 3224895513;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_EXTENT_ALREADY_USED: ::libc::c_uint = 3224895514;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_EXTENT_NOT_CONTIGUOUS: ::libc::c_uint = 3224895515;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_EXTENT_NOT_IN_PUBLIC_REGION: ::libc::c_uint = 3224895516;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_EXTENT_NOT_SECTOR_ALIGNED: ::libc::c_uint = 3224895517;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_EXTENT_OVERLAPS_EBR_PARTITION: ::libc::c_uint = 3224895518;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_EXTENT_VOLUME_LENGTHS_DO_NOT_MATCH: ::libc::c_uint =
    3224895519;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_FAULT_TOLERANT_NOT_SUPPORTED: ::libc::c_uint = 3224895520;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_INTERLEAVE_LENGTH_INVALID: ::libc::c_uint = 3224895521;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MAXIMUM_REGISTERED_USERS: ::libc::c_uint = 3224895522;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MEMBER_IN_SYNC: ::libc::c_uint = 3224895523;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MEMBER_INDEX_DUPLICATE: ::libc::c_uint = 3224895524;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MEMBER_INDEX_INVALID: ::libc::c_uint = 3224895525;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MEMBER_MISSING: ::libc::c_uint = 3224895526;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MEMBER_NOT_DETACHED: ::libc::c_uint = 3224895527;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MEMBER_REGENERATING: ::libc::c_uint = 3224895528;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_ALL_DISKS_FAILED: ::libc::c_uint = 3224895529;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NO_REGISTERED_USERS: ::libc::c_uint = 3224895530;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NO_SUCH_USER: ::libc::c_uint = 3224895531;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NOTIFICATION_RESET: ::libc::c_uint = 3224895532;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NUMBER_OF_MEMBERS_INVALID: ::libc::c_uint = 3224895533;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NUMBER_OF_PLEXES_INVALID: ::libc::c_uint = 3224895534;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_DUPLICATE: ::libc::c_uint = 3224895535;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_ID_INVALID: ::libc::c_uint = 3224895536;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_INVALID: ::libc::c_uint = 3224895537;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_NAME_INVALID: ::libc::c_uint = 3224895538;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_OFFLINE: ::libc::c_uint = 3224895539;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_HAS_QUORUM: ::libc::c_uint = 3224895540;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_WITHOUT_QUORUM: ::libc::c_uint = 3224895541;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PARTITION_STYLE_INVALID: ::libc::c_uint = 3224895542;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PARTITION_UPDATE_FAILED: ::libc::c_uint = 3224895543;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_IN_SYNC: ::libc::c_uint = 3224895544;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_INDEX_DUPLICATE: ::libc::c_uint = 3224895545;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_INDEX_INVALID: ::libc::c_uint = 3224895546;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_LAST_ACTIVE: ::libc::c_uint = 3224895547;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_MISSING: ::libc::c_uint = 3224895548;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_REGENERATING: ::libc::c_uint = 3224895549;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_TYPE_INVALID: ::libc::c_uint = 3224895550;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_NOT_RAID5: ::libc::c_uint = 3224895551;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_NOT_SIMPLE: ::libc::c_uint = 3224895552;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_STRUCTURE_SIZE_INVALID: ::libc::c_uint = 3224895553;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_TOO_MANY_NOTIFICATION_REQUESTS: ::libc::c_uint = 3224895554;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_TRANSACTION_IN_PROGRESS: ::libc::c_uint = 3224895555;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_UNEXPECTED_DISK_LAYOUT_CHANGE: ::libc::c_uint = 3224895556;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_CONTAINS_MISSING_DISK: ::libc::c_uint = 3224895557;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_ID_INVALID: ::libc::c_uint = 3224895558;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_LENGTH_INVALID: ::libc::c_uint = 3224895559;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_LENGTH_NOT_SECTOR_SIZE_MULTIPLE: ::libc::c_uint =
    3224895560;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_NOT_MIRRORED: ::libc::c_uint = 3224895561;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_NOT_RETAINED: ::libc::c_uint = 3224895562;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_OFFLINE: ::libc::c_uint = 3224895563;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_RETAINED: ::libc::c_uint = 3224895564;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NUMBER_OF_EXTENTS_INVALID: ::libc::c_uint = 3224895565;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_DIFFERENT_SECTOR_SIZE: ::libc::c_uint = 3224895566;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_BAD_BOOT_DISK: ::libc::c_uint = 3224895567;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_CONFIG_OFFLINE: ::libc::c_uint = 3224895568;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_CONFIG_ONLINE: ::libc::c_uint = 3224895569;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NOT_PRIMARY_PACK: ::libc::c_uint = 3224895570;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PACK_LOG_UPDATE_FAILED: ::libc::c_uint = 3224895571;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NUMBER_OF_DISKS_IN_PLEX_INVALID: ::libc::c_uint =
    3224895572;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NUMBER_OF_DISKS_IN_MEMBER_INVALID: ::libc::c_uint =
    3224895573;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_VOLUME_MIRRORED: ::libc::c_uint = 3224895574;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PLEX_NOT_SIMPLE_SPANNED: ::libc::c_uint = 3224895575;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NO_VALID_LOG_COPIES: ::libc::c_uint = 3224895576;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_PRIMARY_PACK_PRESENT: ::libc::c_uint = 3224895577;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_NUMBER_OF_DISKS_INVALID: ::libc::c_uint = 3224895578;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_MIRROR_NOT_SUPPORTED: ::libc::c_uint = 3224895579;
pub const MD_NTSTATUS_WIN_STATUS_VOLMGR_RAID5_NOT_SUPPORTED: ::libc::c_uint = 3224895580;
pub const MD_NTSTATUS_WIN_STATUS_BCD_TOO_MANY_ELEMENTS: ::libc::c_uint = 3224961026;
pub const MD_NTSTATUS_WIN_STATUS_VHD_DRIVE_FOOTER_MISSING: ::libc::c_uint = 3225026561;
pub const MD_NTSTATUS_WIN_STATUS_VHD_DRIVE_FOOTER_CHECKSUM_MISMATCH: ::libc::c_uint = 3225026562;
pub const MD_NTSTATUS_WIN_STATUS_VHD_DRIVE_FOOTER_CORRUPT: ::libc::c_uint = 3225026563;
pub const MD_NTSTATUS_WIN_STATUS_VHD_FORMAT_UNKNOWN: ::libc::c_uint = 3225026564;
pub const MD_NTSTATUS_WIN_STATUS_VHD_FORMAT_UNSUPPORTED_VERSION: ::libc::c_uint = 3225026565;
pub const MD_NTSTATUS_WIN_STATUS_VHD_SPARSE_HEADER_CHECKSUM_MISMATCH: ::libc::c_uint = 3225026566;
pub const MD_NTSTATUS_WIN_STATUS_VHD_SPARSE_HEADER_UNSUPPORTED_VERSION: ::libc::c_uint = 3225026567;
pub const MD_NTSTATUS_WIN_STATUS_VHD_SPARSE_HEADER_CORRUPT: ::libc::c_uint = 3225026568;
pub const MD_NTSTATUS_WIN_STATUS_VHD_BLOCK_ALLOCATION_FAILURE: ::libc::c_uint = 3225026569;
pub const MD_NTSTATUS_WIN_STATUS_VHD_BLOCK_ALLOCATION_TABLE_CORRUPT: ::libc::c_uint = 3225026570;
pub const MD_NTSTATUS_WIN_STATUS_VHD_INVALID_BLOCK_SIZE: ::libc::c_uint = 3225026571;
pub const MD_NTSTATUS_WIN_STATUS_VHD_BITMAP_MISMATCH: ::libc::c_uint = 3225026572;
pub const MD_NTSTATUS_WIN_STATUS_VHD_PARENT_VHD_NOT_FOUND: ::libc::c_uint = 3225026573;
pub const MD_NTSTATUS_WIN_STATUS_VHD_CHILD_PARENT_ID_MISMATCH: ::libc::c_uint = 3225026574;
pub const MD_NTSTATUS_WIN_STATUS_VHD_CHILD_PARENT_TIMESTAMP_MISMATCH: ::libc::c_uint = 3225026575;
pub const MD_NTSTATUS_WIN_STATUS_VHD_METADATA_READ_FAILURE: ::libc::c_uint = 3225026576;
pub const MD_NTSTATUS_WIN_STATUS_VHD_METADATA_WRITE_FAILURE: ::libc::c_uint = 3225026577;
pub const MD_NTSTATUS_WIN_STATUS_VHD_INVALID_SIZE: ::libc::c_uint = 3225026578;
pub const MD_NTSTATUS_WIN_STATUS_VHD_INVALID_FILE_SIZE: ::libc::c_uint = 3225026579;
pub const MD_NTSTATUS_WIN_STATUS_VIRTDISK_PROVIDER_NOT_FOUND: ::libc::c_uint = 3225026580;
pub const MD_NTSTATUS_WIN_STATUS_VIRTDISK_NOT_VIRTUAL_DISK: ::libc::c_uint = 3225026581;
pub const MD_NTSTATUS_WIN_STATUS_VHD_PARENT_VHD_ACCESS_DENIED: ::libc::c_uint = 3225026582;
pub const MD_NTSTATUS_WIN_STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH: ::libc::c_uint = 3225026583;
pub const MD_NTSTATUS_WIN_STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED: ::libc::c_uint = 3225026584;
pub const MD_NTSTATUS_WIN_STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT: ::libc::c_uint =
    3225026585;
pub const MD_NTSTATUS_WIN_STATUS_VIRTUAL_DISK_LIMITATION: ::libc::c_uint = 3225026586;
pub const MD_NTSTATUS_WIN_STATUS_VHD_INVALID_TYPE: ::libc::c_uint = 3225026587;
pub const MD_NTSTATUS_WIN_STATUS_VHD_INVALID_STATE: ::libc::c_uint = 3225026588;
pub const MD_NTSTATUS_WIN_STATUS_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE: ::libc::c_uint = 3225026589;
pub const MD_NTSTATUS_WIN_STATUS_VIRTDISK_DISK_ALREADY_OWNED: ::libc::c_uint = 3225026590;
pub const MD_NTSTATUS_WIN_STATUS_VIRTDISK_DISK_ONLINE_AND_WRITABLE: ::libc::c_uint = 3225026591;
pub const MD_NTSTATUS_WIN_STATUS_CTLOG_TRACKING_NOT_INITIALIZED: ::libc::c_uint = 3225026592;
pub const MD_NTSTATUS_WIN_STATUS_CTLOG_LOGFILE_SIZE_EXCEEDED_MAXSIZE: ::libc::c_uint = 3225026593;
pub const MD_NTSTATUS_WIN_STATUS_CTLOG_VHD_CHANGED_OFFLINE: ::libc::c_uint = 3225026594;
pub const MD_NTSTATUS_WIN_STATUS_CTLOG_INVALID_TRACKING_STATE: ::libc::c_uint = 3225026595;
pub const MD_NTSTATUS_WIN_STATUS_CTLOG_INCONSISTENT_TRACKING_FILE: ::libc::c_uint = 3225026596;
pub const MD_NTSTATUS_WIN_STATUS_VHD_METADATA_FULL: ::libc::c_uint = 3225026600;
pub const MD_NTSTATUS_WIN_STATUS_RKF_KEY_NOT_FOUND: ::libc::c_uint = 3225419777;
pub const MD_NTSTATUS_WIN_STATUS_RKF_DUPLICATE_KEY: ::libc::c_uint = 3225419778;
pub const MD_NTSTATUS_WIN_STATUS_RKF_BLOB_FULL: ::libc::c_uint = 3225419779;
pub const MD_NTSTATUS_WIN_STATUS_RKF_STORE_FULL: ::libc::c_uint = 3225419780;
pub const MD_NTSTATUS_WIN_STATUS_RKF_FILE_BLOCKED: ::libc::c_uint = 3225419781;
pub const MD_NTSTATUS_WIN_STATUS_RKF_ACTIVE_KEY: ::libc::c_uint = 3225419782;
pub const MD_NTSTATUS_WIN_STATUS_RDBSS_RESTART_OPERATION: ::libc::c_uint = 3225485313;
pub const MD_NTSTATUS_WIN_STATUS_RDBSS_CONTINUE_OPERATION: ::libc::c_uint = 3225485314;
pub const MD_NTSTATUS_WIN_STATUS_RDBSS_POST_OPERATION: ::libc::c_uint = 3225485315;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INVALID_HANDLE: ::libc::c_uint = 3225550849;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_READ_NOT_PERMITTED: ::libc::c_uint = 3225550850;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_WRITE_NOT_PERMITTED: ::libc::c_uint = 3225550851;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INVALID_PDU: ::libc::c_uint = 3225550852;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INSUFFICIENT_AUTHENTICATION: ::libc::c_uint = 3225550853;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_REQUEST_NOT_SUPPORTED: ::libc::c_uint = 3225550854;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INVALID_OFFSET: ::libc::c_uint = 3225550855;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INSUFFICIENT_AUTHORIZATION: ::libc::c_uint = 3225550856;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_PREPARE_QUEUE_FULL: ::libc::c_uint = 3225550857;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_ATTRIBUTE_NOT_FOUND: ::libc::c_uint = 3225550858;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_ATTRIBUTE_NOT_LONG: ::libc::c_uint = 3225550859;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE: ::libc::c_uint =
    3225550860;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INVALID_ATTRIBUTE_VALUE_LENGTH: ::libc::c_uint =
    3225550861;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_UNLIKELY: ::libc::c_uint = 3225550862;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INSUFFICIENT_ENCRYPTION: ::libc::c_uint = 3225550863;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_UNSUPPORTED_GROUP_TYPE: ::libc::c_uint = 3225550864;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_INSUFFICIENT_RESOURCES: ::libc::c_uint = 3225550865;
pub const MD_NTSTATUS_WIN_STATUS_BTH_ATT_UNKNOWN_ERROR: ::libc::c_uint = 3225554944;
pub const MD_NTSTATUS_WIN_STATUS_SECUREBOOT_ROLLBACK_DETECTED: ::libc::c_uint = 3225616385;
pub const MD_NTSTATUS_WIN_STATUS_SECUREBOOT_POLICY_VIOLATION: ::libc::c_uint = 3225616386;
pub const MD_NTSTATUS_WIN_STATUS_SECUREBOOT_INVALID_POLICY: ::libc::c_uint = 3225616387;
pub const MD_NTSTATUS_WIN_STATUS_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND: ::libc::c_uint = 3225616388;
pub const MD_NTSTATUS_WIN_STATUS_SECUREBOOT_POLICY_NOT_SIGNED: ::libc::c_uint = 3225616389;
pub const MD_NTSTATUS_WIN_STATUS_SECUREBOOT_FILE_REPLACED: ::libc::c_uint = 3225616391;
pub const MD_NTSTATUS_WIN_STATUS_AUDIO_ENGINE_NODE_NOT_FOUND: ::libc::c_uint = 3225681921;
pub const MD_NTSTATUS_WIN_STATUS_HDAUDIO_EMPTY_CONNECTION_LIST: ::libc::c_uint = 3225681922;
pub const MD_NTSTATUS_WIN_STATUS_HDAUDIO_CONNECTION_LIST_NOT_SUPPORTED: ::libc::c_uint = 3225681923;
pub const MD_NTSTATUS_WIN_STATUS_HDAUDIO_NO_LOGICAL_DEVICES_CREATED: ::libc::c_uint = 3225681924;
pub const MD_NTSTATUS_WIN_STATUS_HDAUDIO_NULL_LINKED_LIST_ENTRY: ::libc::c_uint = 3225681925;
pub const MD_NTSTATUS_WIN_STATUS_VOLSNAP_BOOTFILE_NOT_VALID: ::libc::c_uint = 3226468355;
pub const MD_NTSTATUS_WIN_STATUS_IO_PREEMPTED: ::libc::c_uint = 3226533889;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_ERROR_STORED: ::libc::c_uint = 3227254784;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_ERROR_NOT_AVAILABLE: ::libc::c_uint = 3227320064;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_UNIT_ATTENTION_AVAILABLE: ::libc::c_uint = 3227320065;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_UNIT_ATTENTION_CAPACITY_DATA_CHANGED: ::libc::c_uint =
    3227320066;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_PREEMPTED: ::libc::c_uint =
    3227320067;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_UNIT_ATTENTION_RESERVATIONS_RELEASED: ::libc::c_uint =
    3227320068;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_UNIT_ATTENTION_REGISTRATIONS_PREEMPTED: ::libc::c_uint =
    3227320069;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_UNIT_ATTENTION_OPERATING_DEFINITION_CHANGED: ::libc::c_uint =
    3227320070;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_RESERVATION_CONFLICT: ::libc::c_uint = 3227320071;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_WRONG_FILE_TYPE: ::libc::c_uint = 3227320072;
pub const MD_NTSTATUS_WIN_STATUS_SVHDX_VERSION_MISMATCH: ::libc::c_uint = 3227320073;
pub const MD_NTSTATUS_WIN_STATUS_VHD_SHARED: ::libc::c_uint = 3227320074;
pub const MD_NTSTATUS_WIN_STATUS_SPACES_RESILIENCY_TYPE_INVALID: ::libc::c_uint = 3236364291;
pub const MD_NTSTATUS_WIN_STATUS_SPACES_DRIVE_SECTOR_SIZE_INVALID: ::libc::c_uint = 3236364292;
pub const MD_NTSTATUS_WIN_STATUS_SPACES_INTERLEAVE_LENGTH_INVALID: ::libc::c_uint = 3236364297;
pub const MD_NTSTATUS_WIN_STATUS_SPACES_NUMBER_OF_COLUMNS_INVALID: ::libc::c_uint = 3236364298;
pub const MD_NTSTATUS_WIN_STATUS_SPACES_NOT_ENOUGH_DRIVES: ::libc::c_uint = 3236364299;
pub type MDNTStatusCodeWin = Enum_Unnamed47;
pub type Enum_Unnamed48 = ::libc::c_uint;
pub const MD_ACCESS_VIOLATION_WIN_READ: ::libc::c_uint = 0;
pub const MD_ACCESS_VIOLATION_WIN_WRITE: ::libc::c_uint = 1;
pub const MD_ACCESS_VIOLATION_WIN_EXEC: ::libc::c_uint = 8;
pub type MDAccessViolationTypeWin = Enum_Unnamed48;
pub type Enum_Unnamed49 = ::libc::c_uint;
pub const MD_IN_PAGE_ERROR_WIN_READ: ::libc::c_uint = 0;
pub const MD_IN_PAGE_ERROR_WIN_WRITE: ::libc::c_uint = 1;
pub const MD_IN_PAGE_ERROR_WIN_EXEC: ::libc::c_uint = 8;
pub type MDInPageErrorTypeWin = Enum_Unnamed49;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawExceptionStream {
    pub thread_id: u32,
    pub __align: u32,
    pub exception_record: MDException,
    pub thread_context: MDLocationDescriptor,
}

/// `CPU_INFORMATION` from minidumpapiset.h.
#[derive(Clone, Pread, SizeWith)]
pub struct MDCPUInformation {
    /// `data` is defined as a union in the Microsoft headers.
    ///
    /// It is the union of `MDX86CpuInfo`, `MDARMCpuInfo` (Breakpad-specific), and
    /// `OtherCpuInfo` defined below. It does not seem possible to safely derive `Pread`
    /// on an actual union, so we provide the raw data here and expect callers to use
    /// `Pread` to derive the specific union representation desired.
    pub data: [u8; 24],
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDX86CpuInfo {
    pub vendor_id: [u32; 3],
    pub version_information: u32,
    pub feature_information: u32,
    pub amd_extended_cpu_features: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDARMCpuInfo {
    pub cpuid: u32,
    pub elf_hwcaps: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct OtherCpuInfo {
    pub processor_features: [u64; 2],
}

pub type Enum_Unnamed55 = ::libc::c_uint;
pub const MD_CPU_ARM_ELF_HWCAP_SWP: ::libc::c_uint = 1;
pub const MD_CPU_ARM_ELF_HWCAP_HALF: ::libc::c_uint = 2;
pub const MD_CPU_ARM_ELF_HWCAP_THUMB: ::libc::c_uint = 4;
pub const MD_CPU_ARM_ELF_HWCAP_26BIT: ::libc::c_uint = 8;
pub const MD_CPU_ARM_ELF_HWCAP_FAST_MULT: ::libc::c_uint = 16;
pub const MD_CPU_ARM_ELF_HWCAP_FPA: ::libc::c_uint = 32;
pub const MD_CPU_ARM_ELF_HWCAP_VFP: ::libc::c_uint = 64;
pub const MD_CPU_ARM_ELF_HWCAP_EDSP: ::libc::c_uint = 128;
pub const MD_CPU_ARM_ELF_HWCAP_JAVA: ::libc::c_uint = 256;
pub const MD_CPU_ARM_ELF_HWCAP_IWMMXT: ::libc::c_uint = 512;
pub const MD_CPU_ARM_ELF_HWCAP_CRUNCH: ::libc::c_uint = 1024;
pub const MD_CPU_ARM_ELF_HWCAP_THUMBEE: ::libc::c_uint = 2048;
pub const MD_CPU_ARM_ELF_HWCAP_NEON: ::libc::c_uint = 4096;
pub const MD_CPU_ARM_ELF_HWCAP_VFPv3: ::libc::c_uint = 8192;
pub const MD_CPU_ARM_ELF_HWCAP_VFPv3D16: ::libc::c_uint = 16384;
pub const MD_CPU_ARM_ELF_HWCAP_TLS: ::libc::c_uint = 32768;
pub const MD_CPU_ARM_ELF_HWCAP_VFPv4: ::libc::c_uint = 65536;
pub const MD_CPU_ARM_ELF_HWCAP_IDIVA: ::libc::c_uint = 131072;
pub const MD_CPU_ARM_ELF_HWCAP_IDIVT: ::libc::c_uint = 262144;
pub type MDCPUInformationARMElfHwCaps = Enum_Unnamed55;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawSystemInfo {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub number_of_processors: u8,
    pub product_type: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version_rva: MDRVA,
    pub suite_mask: u16,
    pub reserved2: u16,
    pub cpu: MDCPUInformation,
}

pub type Enum_Unnamed57 = ::libc::c_uint;
pub const MD_CPU_ARCHITECTURE_X86: ::libc::c_uint = 0;
pub const MD_CPU_ARCHITECTURE_MIPS: ::libc::c_uint = 1;
pub const MD_CPU_ARCHITECTURE_ALPHA: ::libc::c_uint = 2;
pub const MD_CPU_ARCHITECTURE_PPC: ::libc::c_uint = 3;
pub const MD_CPU_ARCHITECTURE_SHX: ::libc::c_uint = 4;
pub const MD_CPU_ARCHITECTURE_ARM: ::libc::c_uint = 5;
pub const MD_CPU_ARCHITECTURE_IA64: ::libc::c_uint = 6;
pub const MD_CPU_ARCHITECTURE_ALPHA64: ::libc::c_uint = 7;
pub const MD_CPU_ARCHITECTURE_MSIL: ::libc::c_uint = 8;
pub const MD_CPU_ARCHITECTURE_AMD64: ::libc::c_uint = 9;
pub const MD_CPU_ARCHITECTURE_X86_WIN64: ::libc::c_uint = 10;
pub const MD_CPU_ARCHITECTURE_SPARC: ::libc::c_uint = 32769;
pub const MD_CPU_ARCHITECTURE_PPC64: ::libc::c_uint = 32770;
pub const MD_CPU_ARCHITECTURE_ARM64: ::libc::c_uint = 32771;
pub const MD_CPU_ARCHITECTURE_MIPS64: ::libc::c_uint = 32772;
pub const MD_CPU_ARCHITECTURE_UNKNOWN: ::libc::c_uint = 65535;
pub type MDCPUArchitecture = Enum_Unnamed57;
pub type Enum_Unnamed58 = ::libc::c_uint;
pub const MD_OS_WIN32S: ::libc::c_uint = 0;
pub const MD_OS_WIN32_WINDOWS: ::libc::c_uint = 1;
pub const MD_OS_WIN32_NT: ::libc::c_uint = 2;
pub const MD_OS_WIN32_CE: ::libc::c_uint = 3;
pub const MD_OS_UNIX: ::libc::c_uint = 32768;
pub const MD_OS_MAC_OS_X: ::libc::c_uint = 33025;
pub const MD_OS_IOS: ::libc::c_uint = 33026;
pub const MD_OS_LINUX: ::libc::c_uint = 33281;
pub const MD_OS_SOLARIS: ::libc::c_uint = 33282;
pub const MD_OS_ANDROID: ::libc::c_uint = 33283;
pub const MD_OS_PS3: ::libc::c_uint = 33284;
pub const MD_OS_NACL: ::libc::c_uint = 33285;
pub type MDOSPlatform = Enum_Unnamed58;

#[derive(Clone, Pread, SizeWith)]
pub struct MDSystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDTimeZoneInformation {
    pub bias: i32,
    pub standard_name: [u16; 32usize],
    pub standard_date: MDSystemTime,
    pub standard_bias: i32,
    pub daylight_name: [u16; 32usize],
    pub daylight_date: MDSystemTime,
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
    ($(#[$attr:meta])* pub struct $name:ident { $( pub $field:ident: $t:ty, )* } $($tail:tt)* ) => {
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
    /// MINIDUMP_MISC_INFO
    pub struct MDRawMiscInfo {
        pub size_of_info: u32,
        pub flags1: u32,
        pub process_id: u32,
        pub process_create_time: u32,
        pub process_user_time: u32,
        pub process_kernel_time: u32,
    }
    // Includes fields from MDRawMiscInfo
    /// MINIDUMP_MISC_INFO2
    pub struct MDRawMiscInfo2 {
        pub processor_max_mhz: u32,
        pub processor_current_mhz: u32,
        pub processor_mhz_limit: u32,
        pub processor_max_idle_state: u32,
        pub processor_current_idle_state: u32,
    }
    // Includes fields from MDRawMiscInfo and MDRawMiscInfo2
    /// MINIDUMP_MISC_INFO3
    pub struct MDRawMiscInfo3 {
        pub process_integrity_level: u32,
        pub process_execute_flags: u32,
        pub protected_process: u32,
        pub time_zone_id: u32,
        pub time_zone: MDTimeZoneInformation,
    }
    // Includes fields from MDRawMiscInfo..3
    /// MINIDUMP_MISC_INFO_4
    pub struct MDRawMiscInfo4 {
        pub build_string: [u16; 260usize],
        pub dbg_bld_str: [u16; 40usize],
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

pub type Enum_Unnamed62 = ::libc::c_uint;
pub const MD_MISCINFO_FLAGS1_PROCESS_ID: ::libc::c_uint = 1;
pub const MD_MISCINFO_FLAGS1_PROCESS_TIMES: ::libc::c_uint = 2;
pub const MD_MISCINFO_FLAGS1_PROCESSOR_POWER_INFO: ::libc::c_uint = 4;
pub const MD_MISCINFO_FLAGS1_PROCESS_INTEGRITY: ::libc::c_uint = 16;
pub const MD_MISCINFO_FLAGS1_PROCESS_EXECUTE_FLAGS: ::libc::c_uint = 32;
pub const MD_MISCINFO_FLAGS1_TIMEZONE: ::libc::c_uint = 64;
pub const MD_MISCINFO_FLAGS1_PROTECTED_PROCESS: ::libc::c_uint = 128;
pub const MD_MISCINFO_FLAGS1_BUILDSTRING: ::libc::c_uint = 256;
pub type MDMiscInfoFlags1 = Enum_Unnamed62;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawMemoryInfoList {
    pub size_of_header: u32,
    pub size_of_entry: u32,
    pub number_of_entries: u64,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawMemoryInfo {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protection: u32,
    pub __alignment1: u32,
    pub region_size: u64,
    pub state: u32,
    pub protection: u32,
    pub _type: u32,
    pub __alignment2: u32,
}

pub type Enum_Unnamed65 = ::libc::c_uint;
pub const MD_MEMORY_STATE_COMMIT: ::libc::c_uint = 4096;
pub const MD_MEMORY_STATE_RESERVE: ::libc::c_uint = 8192;
pub const MD_MEMORY_STATE_FREE: ::libc::c_uint = 65536;
pub type MDMemoryState = Enum_Unnamed65;
pub type Enum_Unnamed66 = ::libc::c_uint;
pub const MD_MEMORY_PROTECT_NOACCESS: ::libc::c_uint = 1;
pub const MD_MEMORY_PROTECT_READONLY: ::libc::c_uint = 2;
pub const MD_MEMORY_PROTECT_READWRITE: ::libc::c_uint = 4;
pub const MD_MEMORY_PROTECT_WRITECOPY: ::libc::c_uint = 8;
pub const MD_MEMORY_PROTECT_EXECUTE: ::libc::c_uint = 16;
pub const MD_MEMORY_PROTECT_EXECUTE_READ: ::libc::c_uint = 32;
pub const MD_MEMORY_PROTECT_EXECUTE_READWRITE: ::libc::c_uint = 64;
pub const MD_MEMORY_PROTECT_EXECUTE_WRITECOPY: ::libc::c_uint = 128;
pub const MD_MEMORY_PROTECT_GUARD: ::libc::c_uint = 256;
pub const MD_MEMORY_PROTECT_NOCACHE: ::libc::c_uint = 512;
pub const MD_MEMORY_PROTECT_WRITECOMBINE: ::libc::c_uint = 1024;
pub type MDMemoryProtection = Enum_Unnamed66;
pub type Enum_Unnamed67 = ::libc::c_uint;
pub const MD_MEMORY_TYPE_PRIVATE: ::libc::c_uint = 131072;
pub const MD_MEMORY_TYPE_MAPPED: ::libc::c_uint = 262144;
pub const MD_MEMORY_TYPE_IMAGE: ::libc::c_uint = 16777216;
pub type MDMemoryType = Enum_Unnamed67;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawBreakpadInfo {
    pub validity: u32,
    pub dump_thread_id: u32,
    pub requesting_thread_id: u32,
}

pub type Enum_Unnamed69 = ::libc::c_uint;
pub const MD_BREAKPAD_INFO_VALID_DUMP_THREAD_ID: ::libc::c_uint = 1;
pub const MD_BREAKPAD_INFO_VALID_REQUESTING_THREAD_ID: ::libc::c_uint = 2;
pub type MDBreakpadInfoValidity = Enum_Unnamed69;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawAssertionInfo {
    pub expression: [u16; 128usize],
    pub function: [u16; 128usize],
    pub file: [u16; 128usize],
    pub line: u32,
    pub _type: u32,
}

pub type Enum_Unnamed71 = ::libc::c_uint;
pub const MD_ASSERTION_INFO_TYPE_UNKNOWN: ::libc::c_uint = 0;
pub const MD_ASSERTION_INFO_TYPE_INVALID_PARAMETER: ::libc::c_uint = 1;
pub const MD_ASSERTION_INFO_TYPE_PURE_VIRTUAL_CALL: ::libc::c_uint = 2;
pub type MDAssertionInfoData = Enum_Unnamed71;

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawLinkMap32 {
    pub addr: u32,
    pub name: MDRVA,
    pub ld: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawDebug32 {
    pub version: u32,
    pub map: MDRVA,
    pub dso_count: u32,
    pub brk: u32,
    pub ldbase: u32,
    pub dynamic: u32,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawLinkMap64 {
    pub addr: u64,
    pub name: MDRVA,
    pub ld: u64,
}

#[derive(Clone, Pread, SizeWith)]
pub struct MDRawDebug64 {
    pub version: u32,
    pub map: MDRVA,
    pub dso_count: u32,
    pub brk: u64,
    pub ldbase: u64,
    pub dynamic: u64,
}

extern "C" {
    pub static MD_MEMORY_PROTECTION_ACCESS_MASK: u32;
}
