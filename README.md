![Rust CI](https://github.com/rust-minidump/rust-minidump/workflows/Rust%20CI/badge.svg?branch=master)

# Overview

This project provides type definitions, parsing, and analysis for the [minidump](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680369%28v=vs.85%29.aspx) file format.

It's fairly heavily modeled after [Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/) for historical reasons, but there is no fundamental interoperability requirement between the two beyond the fact that they fundamentally handle the same inputs.

This project has no "main" crate. It is a collection of crates that are developed together. What crate you should use depends on how "low-level" in the minidump format you want to get. By default you'll probably want to use [minidump-processor](https://crates.io/crates/minidump-processor) (library) or [minidump-stackwalk](https://crates.io/crates/minidump-stackwalk) (application), which provide the richest analysis.



# Examples

Parse a minidump with [minidump](https://crates.io/crates/minidump):

```rust
use minidump::*;

fn main() -> Result<(), Error> {
    // Read the minidump from a file
    let mut dump = minidump::Minidump::read_path("../testdata/test.dmp")?;

    // Statically request (and require) several streams we care about:
    let system_info = dump.get_stream::<MinidumpSystemInfo>()?;
    let exception = dump.get_stream::<MinidumpException>()?;

    // Combine the contents of the streams to perform more refined analysis
    let crash_reason = exception.get_crash_reason(system_info.os, system_info.cpu);

    // Conditionally analyze a stream
    if let Ok(threads) = dump.get_stream::<MinidumpThreadList>() {
        // Use `Default` to try to make progress when a stream is missing.
        // This is especially natural for MinidumpMemoryList because
        // everything needs to handle memory lookups failing anyway.
        let mem = dump.get_memory().unwrap_or_default();

        for thread in &threads.threads {
            let stack = thread.stack_memory(&mem);
            // ...
        }
    }
    Ok(())
}
```


Analyze a minidump with [minidump-processor](https://crates.io/crates/minidump-processor):

```rust
use minidump::Minidump;
use minidump_processor::{http_symbol_supplier, ProcessorOptions, Symbolizer};
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), ()> {
    // Read the minidump
    let dump = Minidump::read_path("../testdata/test.dmp").map_err(|_| ())?;
 
    // Configure the symbolizer and processor
    let symbols_urls = vec![String::from("https://symbols.totallyrealwebsite.org")];
    let symbols_paths = vec![];
    let mut symbols_cache = std::env::temp_dir();
    symbols_cache.push("minidump-cache");
    let symbols_tmp = std::env::temp_dir();
    let timeout = std::time::Duration::from_secs(1000);
 
    // Use ProcessorOptions for detailed configuration
    let options = ProcessorOptions::default();

    // Specify a symbol supplier (here we're using the most powerful one, the http supplier)
    let provider = Symbolizer::new(http_symbol_supplier(
        symbols_paths,
        symbols_urls,
        symbols_cache,
        symbols_tmp,
        timeout,
    ));
 
    let state = minidump_processor::process_minidump_with_options(&dump, &provider, options)
        .await
        .map_err(|_| ())?;

    // Write the JSON output to an arbitrary writer (here, a Vec).
    // This is currently preferred because this output is more stable 
    // than the contents of ProcessState.
    let mut json_output = Vec::new();
    state.print_json(&mut json_output, false).map_err(|_| ())?;

    // Now parse it (here parsed into an arbitrary JSON Object for max flexibility).
    let json: Value = serde_json::from_slice(&json_output).map_err(|_| ())?;

    // Now read whatever values you want out of it
    if let Some(Value::Number(pid)) = json.get("pid") {
        println!("pid: {}", pid);
    }

    Ok(())
}
```


Analyze a (Firefox) minidump with [minidump-stackwalk](https://crates.io/crates/minidump-stackwalk):

```text
> cargo install minidump-stackwalk
> minidump-stackwalk --symbols-url=https://symbols.mozilla.org/ /path/to/minidump.dmp

Operating system: Linux
                  0.0.0 Linux 5.13.4-201.fc35.x86_64 #1 SMP Wed Nov 24 12:56:51 UTC 2021 x86_64
CPU: amd64
     family 6 model 94 stepping 1
     8 CPUs

Crash reason:  SIGSEGV / SEGV_MAPERR
Crash address: 0x0
Process uptime: not available

Thread 0  (crashed)
 0  libxul.so!mozilla::dom::PlacesObservers::NotifyListeners(mozilla::dom::Sequence<mozilla::OwningNonNull<mozilla::dom::PlacesEvent> > const&) [PlacesObservers.cpp:d03f875556391582e06abbf647835af8ca59f94b : 280 + 0x11]
    rax = 0x00007fa5003b9af7   rdx = 0x0000000000000001
    rcx = 0x0000561011e9d4a8   rbx = 0x00007fa4b76db4a0
    rsi = 0x0000000000000000   rdi = 0x00007fffe0a39ee0
    rbp = 0x00007ffae0a3aea0   rsp = 0x00007ffaea3a9e30
     r8 = 0x0000000000000004    r9 = 0x00007f45075000e8
    r10 = 0xb4a62ad906997b2b   r11 = 0x00007a4507500b00
    r12 = 0x00007affe0a3a070   r13 = 0x00007fa5007abc60
    r14 = 0x00007ffae0a39ee0   r15 = 0x00007fa5001a7e90
    rip = 0x00007f44ff0caed1
    Found by: given as instruction pointer in context
 1  libxul.so!mozilla::places::NotifyRankingChanged::Run() [NotifyRankingChanged.h:d03f875556391582e06abbf647835af8ca59f94b : 32 + 0x7]
    rbx = 0x00007a44b76db4f0   rbp = 0x00007fffe0a3af10
    rsp = 0x00007ffae0a3aee0   r12 = 0x00007ffae0a3a0a0
    r13 = 0x00007f4500afbc60   r14 = 0x00007fffe0a39ee0
    r15 = 0x00007fa5001a7a90   rip = 0x00007fa4ff7a96eb
    Found by: call frame info
 2  libxul.so!mozilla::TaskController::DoExecuteNextTaskOnlyMainThreadInternal(mozilla::detail::BaseAutoLock<mozilla::Mutex&> const&) [TaskController.cpp:d03f875556391582e06abbf647835af8ca59f94b : 771 + 0x4]
    rbx = 0x000000000000001c   rbp = 0x00007fafe0a3a5a0
    rsp = 0x00007fffa0a39f20   r12 = 0x00007ffae0aaa070
    r13 = 0x00007f45007fba60   r14 = 0x00007fa502ad4270
    r15 = 0x00007fa49b04a480   rip = 0x00007f44fe142872
    Found by: call frame info
 ...
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





## [minidump-synth](minidump-synth)

Provides a simple interface for mocking minidumps for unit tests.

This is basically an internal dev-dependency of rust-minidump that we're publishing only so that `cargo publish` doesn't complain about it. I guess you could use it but we don't recommend it?





# Applications


## [minidump-stackwalk](minidump-stackwalk) [![crates.io](https://img.shields.io/crates/v/minidump-stackwalk.svg)](https://crates.io/crates/minidump-stackwalk) [![](https://docs.rs/minidump-stackwalk/badge.svg)](https://docs.rs/minidump-stackwalk)

A CLI frontend for `minidump-processor`, providing both machine-readable and human-readable
digests of a minidump with backtraces and symbolication.

Also includes the functionality of the old minidump_dump tool (see the --dump flag).

See the [README](minidump-stackwalk/README.md) for details.





# License

This software is provided under the MIT license. See [LICENSE](LICENSE).


# Release Notes

See [RELEASES.md](RELEASES.md) for release notes, commits, and details on the upcoming release.


# Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for what is expected of patches, and detailed discussion of testing/documenting rust-minidump.