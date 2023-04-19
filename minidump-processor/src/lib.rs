//! A library for producing stack traces and other useful information from minidump files.
//!
//! The JSON Schema is stable and documented in the next section.
//!
//! You can use the [minidump](https://crates.io/minidump) crate to parse a minidump file, and then
//! use the [`process_minidump`] function to produce stack traces. If you provide paths to
//! Breakpad-format .sym files, the stack traces will include function and source line information.
//!  
//! For a CLI application that wraps this library, see [minidump-stackwalk][].
//! **This is the primary and stable interface for minidump-processor, which
//! we recommend for most production users.**
//!  
//! If you do need to use minidump-processor as a library, we still recommend using
//! the stabilized JSON output. The native APIs work fine and contain all the same
//! information, we just haven't stabilized them yet, so updates are more likely
//! to result in breakage. Here is a minimal example which gets the JSON output
//! (and parses it with serde_json):
//!  
#![cfg_attr(
    feature = "http",
    doc = r##"
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
"##
)]
//!
//!
//!
//! [`process_minidump`]: fn.process_minidump.html
//! [minidump-stackwalk]: https://crates.io/crates/minidump-stackwalk
//!
#![doc = include_str!("../json-schema.md")]

#[cfg(all(doctest, feature = "http"))]
doc_comment::doctest!("../README.md");

mod arg_recovery;
mod evil;
mod op_analysis;
mod process_state;
mod processor;

pub use crate::process_state::*;
pub use crate::processor::*;
