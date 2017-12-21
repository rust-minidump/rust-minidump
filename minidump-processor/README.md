[![crates.io](https://img.shields.io/crates/v/minidump-processor.svg)](https://crates.io/crates/minidump-processor) [![](https://docs.rs/minidump-processor/badge.svg)](https://docs.rs/minidump-processor)

A library for producing stack traces and other useful information from minidump files. This crate
provides APIs for producing symbolicated stack traces for the threads in a minidump, as well as
a `minidump_stackwalk` tool that is intended to function very similarly to the one in the
[Google Breakpad](https://chromium.googlesource.com/breakpad/breakpad/+/master/) project.
