# minidump-processor

[![crates.io](https://img.shields.io/crates/v/minidump-processor.svg)](https://crates.io/crates/minidump-processor) [![](https://docs.rs/minidump-processor/badge.svg)](https://docs.rs/minidump-processor)

A library for producing stack traces and other useful information from minidump files. This crate
provides APIs for producing symbolicated stack traces for the threads in a minidump, as well as
a `minidump_stackwalk` tool that is intended to function very similarly to the one in the
[Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/+/master/) project.

The JSON Schema is stable and [documented here](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md).

If you want lower-level access to the minidump's contents, use the [minidump](https://crates.io/crates/minidump) crate.

For a CLI application that wraps this library, see [minidump-stackwalk](https://crates.io/crates/minidump-stackwalk). **This is the primary and stable interface for minidump-processor, which we recommend for most production users.**

If you do need to use minidump-processor as a library, we still recommend using the stabilized JSON output. The native APIs work fine and contain all the same information, we just haven't stabilized them yet, so updates are more likely to result in breakage. Here is a minimal example which gets the JSON output (and parses it with serde_json):

```rust
use minidump::Minidump;
use minidump_processor::ProcessorOptions;
use serde_json::Value;
use breakpad_symbols::{BreakpadSymbolClient, HttpClientArgs};
 
#[tokio::main]
async fn main() -> Result<(), ()> {
    // Read the minidump
    let dump = Minidump::read_path("../testdata/test.dmp").map_err(|_| ())?;
 
    // Configure the symbol client
    let mut client_args = HttpClientArgs::default();
    client_args.symbol_urls = vec![String::from("https://symbols.totallyrealwebsite.org")];
    client_args.symbols_cache = std::env::temp_dir().join("minidump-cache");
 
    // Use ProcessorOptions for detailed processor configuration
    let options = ProcessorOptions::default();
 
    // Specify a symbol supplier (here we're using the most powerful one, the http supplier)
    let symbol_client = BreakpadSymbolClient::http_client(client_args);
 
    let state = minidump_processor::process_minidump_with_options(&dump, &symbol_client, options)
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