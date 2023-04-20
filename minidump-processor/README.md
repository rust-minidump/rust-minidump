# minidump-processor

[![crates.io](https://img.shields.io/crates/v/minidump-processor.svg)](https://crates.io/crates/minidump-processor) [![](https://docs.rs/minidump-processor/badge.svg)](https://docs.rs/minidump-processor)

A library for producing stack traces and other useful information from minidump files. This crate
provides APIs for producing symbolicated stack traces for the threads in a minidump, as well as
a `minidump_stackwalk` tool that is intended to function very similarly to the one in the
[Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/+/master/) project.

The JSON Schema is stable and [documented here](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md).

If you want lower-level access to the minidump's contents, use the [minidump](https://crates.io/crates/minidump) crate.

For a CLI application that wraps this library, see [minidump-stackwalk](https://crates.io/crates/minidump-stackwalk). **This is the primary and stable interface for minidump-processor, which we recommend for most production users.**

For a GUI application that wraps this library, see [minidump-debugger](https://github.com/Gankra/minidump-debugger). **This is an experimental external project.**

If you do need to use minidump-processor as a library, we still recommend using the stabilized JSON output. The native APIs work fine and contain all the same information, we just haven't stabilized them yet, so updates are more likely to result in breakage. Here is a minimal example which gets the JSON output (and parses it with serde_json):

```rust
use minidump::Minidump;
use minidump_processor::ProcessorOptions;
use minidump_unwind::{http_symbol_supplier, Symbolizer};
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
