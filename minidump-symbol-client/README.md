# minidump-symbol-client

[![crates.io](https://img.shields.io/crates/v/minidump-symbol-client.svg)](https://crates.io/crates/minidump-symbol-client) [![](https://docs.rs/minidump-symbol-client/badge.svg)](https://docs.rs/minidump-symbol-client)

An interface for symbol clients used by rust-minidump.

This is glue for [minidump-processor](https://docs.rs/minidump-processor/latest/minidump-processor/)/[minidump-stackwalk](https://docs.rs/minidump-stackwalk/latest/minidump-stackwalk/) to be able to have any symbolizer backend plugged in. The current primary implementation is [breakpad-symbols](https://docs.rs/breakpad-symbols/latest/breakpad-symbols/), but ideally this will one day be replaced by something based on [symbolic](https://docs.rs/symbolic/latest/symbolic/).