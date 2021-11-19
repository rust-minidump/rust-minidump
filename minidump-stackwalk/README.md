# minidump-stackwalk

[![crates.io](https://img.shields.io/crates/v/minidump-stackwalk.svg)](https://crates.io/crates/minidump-stackwalk) [![](https://docs.rs/minidump-stackwalk/badge.svg)](https://docs.rs/minidump-stackwalk)

A CLI frontend for [minidump-processor](https://crates.io/crates/minidump-processor), providing both machine-readable and human-readable digests of a minidump with backtraces and symbolication.

This is specifically designed to provide a compatible interface to [mozilla's minidump-stackwalk](https://github.com/mozilla-services/minidump-stackwalk) which is itself similar to [google-breakpad's minidump-stackwalk](https://github.com/google/breakpad/blob/main/src/processor/minidump_stackwalk.cc).

(If you need to distinguish them, call this one "rust-minidump-stackwalk")

The easiest way to use this is by `cargo install`ing it:

```text
> cargo install minidump-stackwalk
> minidump-stackwalk --human path/to/minidump.dmp
```

`minidump-stackwalk --help` will give you a listing of command line arguments.




# Output Formats

minidump-stackwalk defaults to outputting machine-readable JSON in a [format](https://github.com/mozilla-services/minidump-stackwalk#json-output) expected by Mozilla's servers. For the sake of tooling compatibility, we generally try to only add fields, and not remove them.

If you pass the --human flag, minidump-stackwalk will instead output a report in a more human-friendly format with no particular structure.

(Either way we recommend using the --output-file argument to write the results to a file, or piping this through `more` -- minidumps contain a lot of information!)




# Getting Symbols

minidump-stackwalk can operate without any symbols, but if you provide them you will get richer output in two ways:

* More precise backtraces (using mechanisms like Dwarf CFI or PE32 Unwinding Tables)
* Symbolicated stackframes (backtraces will have proper function names and line numbers)

minidump-stackwalk gets its symbols from [google-breakpad symbol files](https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md). Symbol files are a plain-text format intended to unify the contents of various platform-specific debuginfo/unwinding formats like PE32 Unwinding Tables, Dwarf CFI, Macho Compact Unwinding Info, etc.

To generate those files from your build artifacts, use either [Mozilla's dump_syms](https://github.com/mozilla/dump_syms/) (recommended) or [google-breakpad's dump_syms](https://github.com/google/breakpad/blob/main/src/tools/linux/dump_syms/dump_syms.cc).

You can then either provide those symbol files directly with the `--symbols-path` flag, or indirectly by setting up a symbol server that conforms to mozilla's [Tecken protocol](https://tecken.readthedocs.io/en/latest/download.html) and passing a URL to that server with the `--symbols-url` flag.




# Analyzing Firefox Minidumps

If you're trying to analyze firefox minidumps, you'll want to point minidump-stackwalk to [Mozilla's Tecken server](https://symbols.mozilla.org/).

```
> minidump-stackwalk --symbols-url=https://symbols.mozilla.org/ /path/to/minidump.dmp
```
