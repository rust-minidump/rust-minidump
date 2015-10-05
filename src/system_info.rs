// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! Information about the system that produced a `Minidump`.

use std::borrow::Cow;
use std::fmt;

use minidump_format as md;

/// Derive an enum value from a primitive.
pub trait EnumFromPrimitive {
    /// Given a primitive value `u`, produce an enum value.
    fn from_u32(u : u32) -> Self;
}

/// Known operating systems.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OS {
    Windows,
    MacOSX,
    Ios,
    Linux,
    Solaris,
    Android,
    Ps3,
    NaCl,
    Unknown(u32),
}

/// Known CPU types.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CPU {
    X86,
    X86_64,
    PPC,
    PPC64,
    Sparc,
    ARM,
    ARM64,
    Unknown(u32),
}

/// Information about the system that produced a `Minidump`.
pub struct SystemInfo {
    /// The operating system that produced the minidump.
    pub os : OS,
    /// A string identifying the version of the operating system, such as
    /// "5.1.2600 Service Pack 2" or "10.4.8 8L2127", if present.
    pub os_version : Option<String>,
    /// The CPU on which the dump was produced.
    pub cpu : CPU,
    /// A string further identifying the specific CPU, such as
    /// "GenuineIntel level 6 model 13 stepping 8", if present.
    pub cpu_info : Option<String>,
    /// The number of processors in the system. Will be greater than one for
    /// multi-core systems.
    pub cpu_count : usize,
}

impl OS {
    /// Get a human-readable friendly name for an `OS`.
    pub fn long_name(&self) -> Cow<str> {
        match *self {
            OS::Windows => Cow::Borrowed("Windows"),
            OS::MacOSX => Cow::Borrowed("Mac OS X"),
            OS::Ios => Cow::Borrowed("iOS"),
            OS::Linux => Cow::Borrowed("Linux"),
            OS::Solaris => Cow::Borrowed("Solaris"),
            OS::Android => Cow::Borrowed("Android"),
            OS::Ps3 => Cow::Borrowed("PS3"),
            OS::NaCl => Cow::Borrowed("NaCl"),
            OS::Unknown(val) => Cow::Owned(format!("{:#08x}", val)),
        }
    }
}

impl EnumFromPrimitive for OS {
    fn from_u32(u : u32) -> OS {
        match u {
            md::MD_OS_WIN32_NT | md::MD_OS_WIN32_WINDOWS => OS::Windows,
            md::MD_OS_MAC_OS_X => OS::MacOSX,
            md::MD_OS_IOS => OS::Ios,
            md::MD_OS_LINUX => OS::Linux,
            md::MD_OS_SOLARIS => OS::Solaris,
            md::MD_OS_ANDROID => OS::Android,
            md::MD_OS_PS3 => OS::Ps3,
            md::MD_OS_NACL => OS::NaCl,
            _ => OS::Unknown(u),
        }
    }
}

impl fmt::Display for OS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match *self {
            OS::Windows => "windows",
            OS::MacOSX => "mac",
            OS::Ios => "ios",
            OS::Linux => "linux",
            OS::Solaris => "solaris",
            OS::Android => "android",
            OS::Ps3 => "ps3",
            OS::NaCl => "nacl",
            OS::Unknown(_) => "unknown",
        })
    }
}

impl EnumFromPrimitive for CPU {
    fn from_u32(u : u32) -> CPU {
        match u {
            md::MD_CPU_ARCHITECTURE_X86 | md::MD_CPU_ARCHITECTURE_X86_WIN64 => CPU::X86,
            md::MD_CPU_ARCHITECTURE_AMD64 => CPU::X86_64,
            md::MD_CPU_ARCHITECTURE_PPC => CPU::PPC,
            md::MD_CPU_ARCHITECTURE_PPC64 => CPU::PPC64,
            md::MD_CPU_ARCHITECTURE_SPARC => CPU::Sparc,
            md::MD_CPU_ARCHITECTURE_ARM => CPU::ARM,
            md::MD_CPU_ARCHITECTURE_ARM64 => CPU::ARM64,
            _ => CPU::Unknown(u),
        }
    }
}

impl fmt::Display for CPU {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match *self {
            CPU::X86 => "x86",
            CPU::X86_64 => "x86-64",
            CPU::PPC => "ppc",
            CPU::PPC64 => "ppc64",
            CPU::Sparc => "sparc",
            CPU::ARM => "arm",
            CPU::ARM64 => "arm64",
            CPU::Unknown(_) => "unknown",
        })
    }
}
