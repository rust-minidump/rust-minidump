//! This crate defines [structs for the on-disk minidump format](format/index.html) as well as
//! [some common traits](traits/index.html) used by related crates.
//!
//! You probably don't want to use this crate directly, the [minidump][minidump] crate provides
//! the actual functionality of reading minidumps using the structs defined in this crate.
//!
//! [minidump]: https://crates.io/crates/minidump
#[macro_use]
extern crate enum_primitive_derive;
#[macro_use]
extern crate bitflags;
extern crate libc;
#[macro_use]
extern crate log;
extern crate num_traits;
extern crate range_map;
#[macro_use]
extern crate scroll;
#[macro_use]
extern crate smart_default;

pub mod format;
pub mod traits;
