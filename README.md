![Rust CI](https://github.com/luser/rust-minidump/workflows/Rust%20CI/badge.svg?branch=master) [![crates.io](https://img.shields.io/crates/v/minidump.svg)](https://crates.io/crates/minidump) [![](https://docs.rs/minidump/badge.svg)](https://docs.rs/minidump)

# Overview

This Rust crate implements a parser for the [minidump](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680369%28v=vs.85%29.aspx) file format.

It's fairly heavily modeled after the [Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/) library, and much of it was written as a means to learn Rust, so there are some rough edges, but it implements most of the functionality necessary to work with minidumps.

# Examples

Print the raw details of the exception stream from a minidump:

```rust
use minidump::{Error, Minidump, MinidumpException, MinidumpStream};
use std::io::{self, Write};

fn work() -> Result<(), Error> {
  let mut dump = minidump::Minidump::read_path("testdata/test.dmp")?;
  let exception: MinidumpException = dump.get_stream()?;
  drop(exception.print(&mut io::stdout()));
  Ok(())
}

fn main() {
    work().unwrap();
}
```

If you want to extract stack traces you should use [minidump-processor](https://crates.io/crates/minidump-processor).

# Sub-crates

The functionality here has been broken out into several sub-crates:
* [minidump-common](https://github.com/luser/rust-minidump/tree/master/minidump-common) [![crates.io](https://img.shields.io/crates/v/minidump-common.svg)](https://crates.io/crates/minidump-common) [![](https://docs.rs/minidump-common/badge.svg)](https://docs.rs/minidump-common) contains the definitions of basic minidump structs, and traits that are shared among several crates.
* [breakpad-symbols](https://github.com/luser/rust-minidump/tree/master/breakpad-symbols) [![crates.io](https://img.shields.io/crates/v/breakpad-symbols.svg)](https://crates.io/crates/breakpad-symbols) [![](https://docs.rs/breakpad-symbols/badge.svg)](https://docs.rs/breakpad-symbols) contains a parser for Breakpad's [text format .sym files](https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md) and interfaces for resolving functions and source line info by address from symbol files.
* [minidump-processor](https://github.com/luser/rust-minidump/tree/master/minidump-processor) [![crates.io](https://img.shields.io/crates/v/minidump-processor.svg)](https://crates.io/crates/minidump-processor) [![](https://docs.rs/minidump-processor/badge.svg)](https://docs.rs/minidump-processor) contains the pieces necessary to generate symbolicated stack traces from a minidump. It provides a `minidump_stackwalk` binary which should function similarly to the one provided in Breakpad.

# License

This software is provided under the MIT license. See [LICENSE](LICENSE).
