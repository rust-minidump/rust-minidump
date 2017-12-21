[![Build Status](https://travis-ci.org/luser/rust-minidump.svg?branch=master)](https://travis-ci.org/luser/rust-minidump)

# Overview

This Rust crate implements a parser for the [minidump](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680369%28v=vs.85%29.aspx) file format.

It's fairly heavily modeled after the [Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/) library, and much of it was written as a means to learn Rust, so there are some rough edges, but it implements most of the functionality necessary to work with minidumps.

[Documentation](http://luser.github.io/rust-project-docs/minidump/minidump/)

# Examples

Print the raw details of the exception stream from a minidump:

```rust
extern crate minidump;

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

# Sub-crates

The functionality here has been broken out into several sub-crates:
* [minidump-core](https://github.com/luser/rust-minidump/tree/master/minidump-core) contains the definitions of basic minidump structs, and traits that are shared among several crates.
* [breakpad-symbols](https://github.com/luser/rust-minidump/tree/master/breakpad-symbols) [![crates.io](https://img.shields.io/crates/v/breakpad-symbols.svg)](https://crates.io/crates/breakpad-symbols) [![](https://docs.rs/breakpad-symbols/badge.svg)](https://docs.rs/breakpad-symbols) contains a parser for Breakpad's [text format .sym files](https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md) and interfaces for resolving functions and source line info by address from symbol files.
* [minidump-processor](https://github.com/luser/rust-minidump/tree/master/minidump-processor) contains the pieces necessary to generate symbolicated stack traces from a minidump. It provides a `minidump_stackwalk` binary which should function similarly to the one provided in Breakpad.

# License

This software is provided under the MIT license. See [LICENSE](LICENSE).
