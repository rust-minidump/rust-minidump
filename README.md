![Rust CI](https://github.com/luser/rust-minidump/workflows/Rust%20CI/badge.svg?branch=master)

# Overview

This Rust crate implements a parser for the [minidump](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680369%28v=vs.85%29.aspx) file format.

It's fairly heavily modeled after the [Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/) library for historical reasons, but there is no fundamental interoperability requirement between the two beyond the fact that they fundamentally handle the same inputs.

This project has no "main" crate. It is a collection of crates that are developed together. What crate you should use depends on how "low-level" in the minidump format you want to get. By default you'll
probably want to use `minidump-processor` (library) or `minidump-stackwalk` (application), which provide the richest analysis.



# Examples

Print the raw details of the exception stream from a minidump:

```rust
use minidump::{Error, Minidump, MinidumpMiscInfo, MinidumpSystemInfo, MinidumpException, MinidumpStream};
use std::io::{self, Write};

fn work() -> Result<(), Error> {
  let mut dump = minidump::Minidump::read_path("../testdata/test.dmp")?;
  let system_info: Option<MinidumpSystemInfo> = dump.get_stream().ok();
  let misc_info: Option<MinidumpMiscInfo> = dump.get_stream().ok();
  let exception: MinidumpException = dump.get_stream()?;
  drop(exception.print(&mut io::stdout(), system_info.as_ref(), misc_info.as_ref()));
  Ok(())
}

fn main() {
    work().unwrap();
}
```

If you want to extract stack traces you should use [minidump-processor](https://crates.io/crates/minidump-processor).

If you just want to inspect a minidump, use minidump-stackwalk:

```text
> cargo install minidump-stackwalk
> minidump-stackwalk --human path/to/minidump.dmp
```




# Libraries


## [minidump-common](minidump-common) [![crates.io](https://img.shields.io/crates/v/minidump-common.svg)](https://crates.io/crates/minidump-common) [![](https://docs.rs/minidump-common/badge.svg)](https://docs.rs/minidump-common)

Basically "minidump-sys" -- minidump types and traits that are shared among several crates.

Most notably [format.rs](minidump-common/src/format.rs) is basically a giant native rust header for [minidumpapiset.h](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/) (with extra useful things added in like error code enums and breakpad extensions).




## [minidump](minidump) [![crates.io](https://img.shields.io/crates/v/minidump.svg)](https://crates.io/crates/minidump) [![](https://docs.rs/minidump/badge.svg)](https://docs.rs/minidump)

Basic parsing of the minidump format.

Minidump provides an interface for lazily enumerating and querying the "streams" of a minidump. It does its best to parse out values without additional context (like debuginfo). Properly parsing some values (such as the cpu contexts of each thread) may depend on multiple streams, in such a situation the method to get a
value will from a stream will request its dependencies.

If you want richer analysis of the minidump (such as stackwalking and symbolication), use minidump-processor.




## [minidump-processor](minidump-processor) [![crates.io](https://img.shields.io/crates/v/minidump-processor.svg)](https://crates.io/crates/minidump-processor) [![](https://docs.rs/minidump-processor/badge.svg)](https://docs.rs/minidump-processor)

High-level minidump analysis.

Builds on top of the `minidump` crate to provide a complete digest of the information in the minidump. Also provides machine-readable (JSON) and human-readable printing of these digests. If you don't actually care about how the minidump format works, this library will take care of all the details for you.

The biggest feature of minidump-processor is that it does stackwalking (computes a backtrace for every thread). Its analysis can be enhanced by providing it with symbols (i.e. using `breakpad-symbols`), producing more precise backtraces and symbolication (function names, source lines, etc.).

It also knows all of the "quirks" of minidumps, and can smooth over details that are impractical for the minidump crate to handle.





## [breakpad-symbols](breakpad-symbols) [![crates.io](https://img.shields.io/crates/v/breakpad-symbols.svg)](https://crates.io/crates/breakpad-symbols) [![](https://docs.rs/breakpad-symbols/badge.svg)](https://docs.rs/breakpad-symbols)

Fetching, parsing, and evaluation of Breakpad's [text format .sym files](https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md).

Fetches breakpad symbol files from disk or [a server](https://tecken.readthedocs.io/en/latest/download.html), and provides an on-disk temp symbol file cache.

Permissively parses breakpad symbol files to smooth over the unfortunately-very-common situation of corrupt debuginfo. Will generally try to recover the parse by discarding corrupt lines or arbitrarily picking one value when conflicts are found.

Provides an API for resolving functions and source line info by address from symbol files.

Provides an API for evaluating breakpad CFI (and WIN) expressions.

This is primarily designed for use by minidump-processor.





## [synth-minidump](synth-minidump)

(currently private to this project)

Provides a simple interface for mocking minidumps for unit tests.





# Applications


## [minidump-stackwalk](minidump-stackwalk) [![crates.io](https://img.shields.io/crates/v/minidump-stackwalk.svg)](https://crates.io/crates/minidump-stackwalk) [![](https://docs.rs/minidump-stackwalk/badge.svg)](https://docs.rs/minidump-stackwalk))

A CLI frontend for `minidump-processor`, providing both machine-readable and human-readable
digests of a minidump with backtraces and symbolication.

See the [README](minidump-stackwalk/README.md) for details.




## [minidump-dump](minidump/src/bin/minidump_dump.rs)

(currently private to this project)

A CLI dumper of the minidump's raw contents.

Although minidump-stackwalk is generally much better and more useful, minidump-dump can help debug strange minidumps, as it more explicitly exposes raw values and the stream directory's layout. This is *mostly* only really useful for developing rust-minidump itself.





# License

This software is provided under the MIT license. See [LICENSE](LICENSE).


# Release Notes

See [RELEASES.md](RELEASES.md) for release notes, commits, and details on the upcoming release.
