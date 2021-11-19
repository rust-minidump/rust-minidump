# minidump

[![crates.io](https://img.shields.io/crates/v/minidump.svg)](https://crates.io/crates/minidump) [![](https://docs.rs/minidump/badge.svg)](https://docs.rs/minidump)

Basic parsing of the minidump format.

Minidump provides an interface for lazily enumerating and querying the "streams" of a minidump. It does its best to parse out values without additional context (like debuginfo). Properly parsing some values (such as the cpu contexts of each thread) may depend on multiple streams, in such a situation the method to get a
value will from a stream will request its dependencies.

If you want richer analysis of the minidump (such as stackwalking and symbolication), use [minidump-processor](https://crates.io/crates/minidump-processor).

