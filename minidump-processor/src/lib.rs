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
//! ```rust
//! use minidump::Minidump;
//! use minidump_processor::ProcessorOptions;
//! use serde_json::Value;
//! use breakpad_symbols::{BreakpadSymbolClient, HttpClientArgs};
//!  
//! #[tokio::main]
//! async fn main() -> Result<(), ()> {
//!     // Read the minidump
//!     let dump = Minidump::read_path("../testdata/test.dmp").map_err(|_| ())?;
//!  
//!     // Configure the symbol client
//!     let mut client_args = HttpClientArgs::default();
//!     client_args.symbol_urls = vec![String::from("https://symbols.totallyrealwebsite.org")];
//!     client_args.symbols_cache = std::env::temp_dir().join("minidump-cache");
//!  
//!     // Use ProcessorOptions for detailed processor configuration
//!     let options = ProcessorOptions::default();
//!  
//!     // Specify a symbol supplier (here we're using the most powerful one, the http supplier)
//!     let symbol_client = BreakpadSymbolClient::http_client(client_args);
//!  
//!     let state = minidump_processor::process_minidump_with_options(&dump, &symbol_client, options)
//!         .await
//!         .map_err(|_| ())?;
//!  
//!     // Write the JSON output to an arbitrary writer (here, a Vec).
//!     let mut json_output = Vec::new();
//!     state.print_json(&mut json_output, false).map_err(|_| ())?;
//!  
//!     // Now parse it (here parsed into an arbitrary JSON Object for max flexibility).
//!     let json: Value = serde_json::from_slice(&json_output).map_err(|_| ())?;
//!  
//!     // Now read whatever values you want out of it
//!     if let Some(Value::Number(pid)) = json.get("pid") {
//!         println!("pid: {}", pid);
//!     }
//!  
//!     Ok(())
//! }
//! ```
//!
//!
//!
//! [`process_minidump`]: fn.process_minidump.html
//! [minidump-stackwalk]: https://crates.io/crates/minidump-stackwalk
//!
#![doc = include_str!("../json-schema.md")]

#[cfg(doctest)]
doc_comment::doctest!("../README.md");

mod arg_recovery;
mod evil;
mod process_state;
mod processor;
mod stackwalker;
mod system_info;

pub use crate::process_state::*;
pub use crate::processor::*;
pub use crate::stackwalker::*;
pub use crate::system_info::*;
pub use minidump_symbol_client::*;

#[cfg(test)]
pub type SymbolClientImpl = breakpad_symbols::BreakpadSymbolClient;
