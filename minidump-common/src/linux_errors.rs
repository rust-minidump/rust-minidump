#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::upper_case_acronyms)]

use enum_primitive_derive::Primitive;

/// Values for [`MINIDUMP_EXCEPTION::exception_code`] for crashes on Linux
///
/// These are primarily signal numbers from bits/signum.h.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeLinux {
    /// Hangup (POSIX)
    SIGHUP = 0x1u32,
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

// These values come from asm-generic/siginfo.h
#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeLinuxSigillKind {
    SI_USER = 0,
    ILL_ILLOPC = 1,
    ILL_ILLOPN = 2,
    ILL_ILLADR = 3,
    ILL_ILLTRP = 4,
    ILL_PRVOPC = 5,
    ILL_PRVREG = 6,
    ILL_COPROC = 7,
    ILL_BADSTK = 8,
    SI_KERNEL = 0x80,
}

#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeLinuxSigfpeKind {
    SI_USER = 0,
    FPE_INTDIV = 1,
    FPE_INTOVF = 2,
    FPE_FLTDIV = 3,
    FPE_FLTOVF = 4,
    FPE_FLTUND = 5,
    FPE_FLTRES = 6,
    FPE_FLTINV = 7,
    FPE_FLTSUB = 8,
    SI_KERNEL = 0x80,
}

#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeLinuxSigsegvKind {
    SI_USER = 0,
    SEGV_MAPERR = 1,
    SEGV_ACCERR = 2,
    SEGV_BNDERR = 3,
    SEGV_PKUERR = 4,
    SI_KERNEL = 0x80,
}

#[derive(Copy, Clone, PartialEq, Debug, Primitive)]
pub enum ExceptionCodeLinuxSigbusKind {
    SI_USER = 0,
    BUS_ADRALN = 1,
    BUS_ADRERR = 2,
    BUS_OBJERR = 3,
    BUS_MCEERR_AR = 4,
    BUS_MCEERR_AO = 5,
    SI_KERNEL = 0x80,
}
