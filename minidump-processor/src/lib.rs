//! A library for producing stack traces and other useful information from minidump files.
//!
//! You can use the [minidump](https://crates.io/minidump) crate to parse a minidump file, and then
//! use the [`process_minidump`] function to produce stack traces. If you provide paths to
//! Breakpad-format .sym files, the stack traces will include function and source line information.
//!
//! [`process_minidump`]: fn.process_minidump.html

extern crate breakpad_symbols;
extern crate chrono;
extern crate minidump;
#[cfg(test)]
extern crate test_assembler;

mod processor;
mod process_state;
mod stackwalker;
mod system_info;

pub use processor::*;
pub use process_state::*;
pub use stackwalker::*;
pub use system_info::*;
