//! Definitions for Windows OS structures, based on public headers and reverse-engineering.
//!
//! These values can be read through [MINIDUMP_THREAD::teb](crate::format::MINIDUMP_THREAD::teb).
//!
//! Although officially these structures are allowed to change and evolve, they are extremely
//! part of Windows ABI (and Microsoft peeks into these when processing minidumps!) so they're
//! actually extremely stable and reasonable for us to dig through.
//!
//! By default these types match the Windows headers, but we can't actually use them because:
//!
//! * We need to add reverse-engineered fields
//! * We need the definitions to be platform agnostic
//!     * pointers need to be u32/u64
//!     * pointers need to be fed to our minidump datastructures to be "dereferenced"
//!     * unlike MINIDUMP types, these aren't as careful with padding, so we must add our own

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::upper_case_acronyms)]

use std::marker::PhantomData;

use scroll::{Pread, SizeWith};

/// An address in process memory (use [MINIDUMP_MEMORY_LIST](crate::format::MINIDUMP_MEMORY_LIST]).
pub type OpaqueAddr64 = u64;

/// An address in process memory (use [MINIDUMP_MEMORY_LIST](crate::format::MINIDUMP_MEMORY_LIST]).
#[derive(Copy, Clone, Debug)]
pub struct Addr64<T> {
    pub addr: u64,
    pub _phantom: PhantomData<T>,
}

impl<'a, T: 'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for Addr64<T> {
    type Error = scroll::Error;
    fn try_from_ctx(this: &'a [u8], le: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let (addr, amt) = u64::try_from_ctx(this, le)?;
        Ok((
            Addr64 {
                addr,
                _phantom: PhantomData,
            },
            amt,
        ))
    }
}

impl<T> scroll::ctx::SizeWith<scroll::Endian> for Addr64<T> {
    fn size_with(ctx: &scroll::Endian) -> usize {
        u64::size_with(ctx)
    }
}

impl<T> Addr64<T> {
    pub fn from(addr: u64) -> Self {
        Self {
            addr,
            _phantom: PhantomData,
        }
    }
}

/// x64 Windows Thread Environment Block
#[derive(Copy, Clone, Debug, Pread, SizeWith)]
pub struct TEB_X64 {
    pub _reserved: [OpaqueAddr64; 12],
    pub process_environment_block: Addr64<PEB_X64>,
    /// The GetLastError() value
    ///
    /// This field is reverse-engineered and not part of Windows headers.
    pub last_error_value: u32,
    // last_error_value is in reserved_2 but isn't pointer-sized,
    // so the next two fields are reserved2 but broken up to fix this.
    pub _reserved2_1: [u8; 4],
    pub _reserved2_2: [OpaqueAddr64; 398],
    pub _reserved3: [u8; 1952],
    pub tls_slots: [OpaqueAddr64; 64],
    pub _reserved4: [u8; 8],
    pub _reserved5: [OpaqueAddr64; 26],
    pub _reserved_for_ole: OpaqueAddr64,
    pub _reserved6: [OpaqueAddr64; 4],
    pub tls_expansion_slots: OpaqueAddr64,
}

/// x64 Windows Process Environment Block
#[derive(Copy, Clone, Debug, Pread, SizeWith)]
pub struct PEB_X64 {
    pub _reserved1: [u8; 2],
    pub being_debugged: u8,
    pub _reserved2: [u8; 1],
    pub _padding1: [u8; 4],
    pub _reserved3: [OpaqueAddr64; 2],
    pub ldr: Addr64<PEB_LDR_DATA_X64>,
    pub process_parameters: Addr64<RTL_USER_PROCESS_PARAMETERS_X64>,
    pub _reserved4: [OpaqueAddr64; 3],
    pub atl_thunk_s_list_ptr: OpaqueAddr64,
    pub _reserved5: OpaqueAddr64,
    pub _reserved6: u32,
    pub _padding2: [u8; 4],
    pub _reserved7: OpaqueAddr64,
    pub _reserved8: u32,
    pub atl_thunk_s_list_ptr_32: u32,
    pub _reserved9: [OpaqueAddr64; 45],
    pub _reserved10: [u8; 96],
    pub post_process_init_routine: PPS_POST_PROCESS_INIT_ROUTINE_X64,
    pub _reserved11: [u8; 128],
    pub _reserved12: [OpaqueAddr64; 1],
    pub session_id: u32,
    pub _padding3: [u8; 4],
}

/// x64 Windows User Process Paramaters
#[derive(Copy, Clone, Debug, Pread, SizeWith)]
pub struct RTL_USER_PROCESS_PARAMETERS_X64 {
    pub _reserved1: [u8; 16],
    pub _reserved2: [OpaqueAddr64; 10],
    pub image_path_name: UNICODE_STRING,
    pub command_line: UNICODE_STRING,
}

#[derive(Copy, Clone, Debug, Pread, SizeWith)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub _padding: [u8; 4],
    pub buffer: PWSTR,
}

pub type PWSTR = Addr64<u16>;

/// A function pointer, not useful to us.
pub type PPS_POST_PROCESS_INIT_ROUTINE_X64 = OpaqueAddr64;

#[derive(Copy, Clone, Debug, Pread, SizeWith)]
pub struct PEB_LDR_DATA_X64 {
    pub _reserved1: [u8; 8],
    pub _reserved2: [OpaqueAddr64; 3],
    pub in_memory_order_module_list: LIST_ENTRY_X64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, SizeWith)]
pub struct LIST_ENTRY_X64 {
    pub f_link: Addr64<LIST_ENTRY_X64>,
    pub b_link: Addr64<LIST_ENTRY_X64>,
}
