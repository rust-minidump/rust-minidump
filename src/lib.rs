// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! A parser for the minidump file format.
//!
//! The `minidump_processor` module provides a parser for the
//! [minidump][minidump] file format as produced by Microsoft's
//! [`MinidumpWriteDump`][minidumpwritedump] API and the
//! [Google Breakpad][breakpad] library.
//!
//! The primary API for this module is the [`Minidump`][struct_minidump]
//! struct, which can be instantiated by calling the [`Minidump::read`][read] or
//! [`Minidump::read_path`][read_path] methods.
//!
//! [minidump]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680369%28v=vs.85%29.aspx
//! [minidumpwritedump]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680360%28v=vs.85%29.aspx
//! [breakpad]: https://code.google.com/p/google-breakpad/
//! [struct_minidump]: struct.Minidump.html
//! [read]: struct.Minidump.html#method.read
//! [read_path]: struct.Minidump.html#method.read_path

extern crate chrono;
extern crate encoding;
extern crate libc;

pub mod minidump_format;
mod minidump;
mod processor;
mod process_state;
mod range_map;
mod system_info;

// Stable Rust has a bug where `pub use minidump::*;` doesn't work.
pub use minidump::Minidump;
pub use minidump::Error;
pub use minidump::Module;
pub use minidump::MinidumpMiscInfo;
pub use minidump::MinidumpModule;
pub use minidump::MinidumpModuleList;
pub use minidump::MinidumpThread;
pub use minidump::MinidumpThreadList;
pub use minidump::MinidumpSystemInfo;
pub use minidump::MinidumpRawContext;
pub use minidump::MinidumpContext;
pub use minidump::MinidumpMemory;
pub use processor::process_minidump;
pub use processor::ProcessError;
pub use process_state::ProcessState;
pub use system_info::CPU;
pub use system_info::OS;
pub use system_info::SystemInfo;
