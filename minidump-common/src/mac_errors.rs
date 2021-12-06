#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::upper_case_acronyms)]

use enum_primitive_derive::Primitive;

/// Values for [`MINIDUMP_EXCEPTION::exception_code`] for crashes on macOS
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
    EXC_RESOURCE = 11,
    /// Fake exception code used by Crashpad's SimulateCrash ('CPsx')
    SIMULATED = 0x43507378,
}

// These error codes are based on
// * mach/ppc/exception.h
// * mach/i386/exception.h

/// Mac/iOS Kernel Bad Access Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBadAccessKernType {
    // These are relevant kern_return_t values from mach/kern_return.h
    KERN_INVALID_ADDRESS = 1,
    KERN_PROTECTION_FAILURE = 2,
    KERN_NO_ACCESS = 8,
    KERN_MEMORY_FAILURE = 9,
    KERN_MEMORY_ERROR = 10,
    KERN_CODESIGN_ERROR = 50,
}

/// Mac/iOS Arm Userland Bad Accesses Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBadAccessArmType {
    EXC_ARM_DA_ALIGN = 0x0101,
    EXC_ARM_DA_DEBUG = 0x0102,
}

/// Mac/iOS Ppc Userland Bad Access Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBadAccessPpcType {
    EXC_PPC_VM_PROT_READ = 0x0101,
    EXC_PPC_BADSPACE = 0x0102,
    EXC_PPC_UNALIGNED = 0x0103,
}

/// Mac/iOS x86 Userland Bad Access Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBadAccessX86Type {
    EXC_I386_GPFLT = 13,
}

/// Mac/iOS Arm Bad Instruction Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBadInstructionArmType {
    EXC_ARM_UNDEFINED = 1,
}

/// Mac/iOS Ppc Bad Instruction Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBadInstructionPpcType {
    EXC_PPC_INVALID_SYSCALL = 1,
    EXC_PPC_UNIPL_INST = 2,
    EXC_PPC_PRIVINST = 3,
    EXC_PPC_PRIVREG = 4,
    EXC_PPC_TRACE = 5,
    EXC_PPC_PERFMON = 6,
}

/// Mac/iOS x86 Bad Instruction Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBadInstructionX86Type {
    /// Invalid Operation
    EXC_I386_INVOP = 1,

    // The rest of these are raw x86 interrupt codes.
    /// Invalid Task State Segment
    EXC_I386_INVTSSFLT = 10,
    /// Segment Not Present
    EXC_I386_SEGNPFLT = 11,
    /// Stack Fault
    EXC_I386_STKFLT = 12,
    /// General Protection Fault
    EXC_I386_GPFLT = 13,
    /// Alignment Fault
    EXC_I386_ALIGNFLT = 17,
    // For sake of completeness, here's the interrupt codes that won't show up here (and why):

    // EXC_I386_DIVERR    =  0: mapped to EXC_ARITHMETIC/EXC_I386_DIV
    // EXC_I386_SGLSTP    =  1: mapped to EXC_BREAKPOINT/EXC_I386_SGL
    // EXC_I386_NMIFLT    =  2: should not occur in user space
    // EXC_I386_BPTFLT    =  3: mapped to EXC_BREAKPOINT/EXC_I386_BPT
    // EXC_I386_INTOFLT   =  4: mapped to EXC_ARITHMETIC/EXC_I386_INTO
    // EXC_I386_BOUNDFLT  =  5: mapped to EXC_ARITHMETIC/EXC_I386_BOUND
    // EXC_I386_INVOPFLT  =  6: mapped to EXC_BAD_INSTRUCTION/EXC_I386_INVOP
    // EXC_I386_NOEXTFLT  =  7: should be handled by the kernel
    // EXC_I386_DBLFLT    =  8: should be handled (if possible) by the kernel
    // EXC_I386_EXTOVRFLT =  9: mapped to EXC_BAD_ACCESS/(PROT_READ|PROT_EXEC)
    // EXC_I386_PGFLT     = 14: should not occur in user space
    // EXC_I386_EXTERRFLT = 16: mapped to EXC_ARITHMETIC/EXC_I386_EXTERR
    // EXC_I386_ENOEXTFLT = 32: should be handled by the kernel
    // EXC_I386_ENDPERR   = 33: should not occur
}

/// Mac/iOS Ppc Arithmetic Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacArithmeticPpcType {
    /// Integer ovrflow
    EXC_PPC_OVERFLOW = 1,
    /// Integer Divide-By-Zero
    EXC_PPC_ZERO_DIVIDE = 2,
    /// Float Inexact
    EXC_FLT_INEXACT = 3,
    /// Float Divide-By-Zero
    EXC_PPC_FLT_ZERO_DIVIDE = 4,
    /// Float Underflow
    EXC_PPC_FLT_UNDERFLOW = 5,
    /// Float Overflow
    EXC_PPC_FLT_OVERFLOW = 6,
    /// Float Not A Number
    EXC_PPC_FLT_NOT_A_NUMBER = 7,

    // NOTE: comments in breakpad suggest these two are actually supposed to be
    // for ExceptionCodeMac::EXC_EMULATION, but for now let's duplicate breakpad.
    EXC_PPC_NOEMULATION = 8,
    EXC_PPC_ALTIVECASSIST = 9,
}

/// Mac/iOS x86 Arithmetic Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacArithmeticX86Type {
    EXC_I386_DIV = 1,
    EXC_I386_INTO = 2,
    EXC_I386_NOEXT = 3,
    EXC_I386_EXTOVR = 4,
    EXC_I386_EXTERR = 5,
    EXC_I386_EMERR = 6,
    EXC_I386_BOUND = 7,
    EXC_I386_SSEEXTERR = 8,
}

/// Mac/iOS "Software" Exceptions
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacSoftwareType {
    SIGABRT = 0x00010002u32,
    UNCAUGHT_NS_EXCEPTION = 0xDEADC0DE,
    EXC_PPC_TRAP = 0x00000001,
    EXC_PPC_MIGRATE = 0x00010100,
    // Breakpad also defines these doesn't use them for Software crashes
    // SIGSYS  = 0x00010000,
    // SIGPIPE = 0x00010001,
}

/// Mac/iOS Arm Breakpoint Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBreakpointArmType {
    EXC_ARM_DA_ALIGN = 0x0101,
    EXC_ARM_DA_DEBUG = 0x0102,
    EXC_ARM_BREAKPOINT = 1,
}

/// Mac/iOS Ppc Breakpoint Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBreakpointPpcType {
    EXC_PPC_BREAKPOINT = 1,
}

/// Mac/iOS x86 Breakpoint Exceptions
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacBreakpointX86Type {
    EXC_I386_SGL = 1,
    EXC_I386_BPT = 2,
}

/// Mac/iOS Resource exception types
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacResourceType {
    RESOURCE_TYPE_CPU = 1,
    RESOURCE_TYPE_WAKEUPS = 2,
    RESOURCE_TYPE_MEMORY = 3,
    RESOURCE_TYPE_IO = 4,
    RESOURCE_TYPE_THREADS = 5,
}

/// Mac/iOS CPU resource exception flavors
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacResourceCpuFlavor {
    FLAVOR_CPU_MONITOR = 1,
    FLAVOR_CPU_MONITOR_FATAL = 2,
}

/// Mac/iOS wakeups resource exception flavors
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacResourceWakeupsFlavor {
    FLAVOR_WAKEUPS_MONITOR = 1,
}

/// Mac/iOS memory resource exception flavors
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacResourceMemoryFlavor {
    FLAVOR_HIGH_WATERMARK = 1,
}

/// Mac/iOS I/O resource exception flavors
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacResourceIOFlavor {
    FLAVOR_IO_PHYSICAL_WRITES = 1,
    FLAVOR_IO_LOGICAL_WRITES = 2,
}

/// Mac/iOS threads resource exception flavors
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeMacResourceThreadsFlavor {
    FLAVOR_THREADS_HIGH_WATERMARK = 1,
}
