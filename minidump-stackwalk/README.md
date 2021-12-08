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

minidump-stackwalk defaults to outputting machine-readable JSON in a [format](https://github.com/luser/rust-minidump/blob/master/minidump-processor/json-schema.md) expected by Mozilla's servers. For the sake of tooling compatibility, we generally try to only add fields, and not remove them.

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













# minidump-stackwalk CLI manual

> This manual can be regenerated with `minidump-stackwalk --help-markdown please`

Version: `minidump-stackwalk 0.9.6`

Analyzes minidumps and produces a report (either human-readable or JSON).

# USAGE
minidump-stackwalk [FLAGS] [OPTIONS] <minidump> [--] [symbols-path]...

# FLAGS
### `--json`
Emit a machine-readable JSON report.

The schema for this output is officially documented here:
https://github.com/luser/rust-minidump/blob/master/minidump-processor/json-schema.md

### `--human`
Emit a human-readable report (the default).

The human-readable report does not have a specified format, and may not have as many details as the JSON
format. It is intended for quickly inspecting a crash or debugging rust-minidump itself.

### `--pretty`
Pretty-print --json output.

### `--brief`
Provide a briefer --human report.

Only provides the top-level summary and a backtrace of the crashing thread.
### `-h, --help`
Prints help information

### `-V, --version`
Prints version information


# OPTIONS
### `--cyborg <cyborg>`
Combine --human and --json

Because this creates two output streams, you must specify a path to write the --json
output to. The --human output will be the 'primary' output and default to stdout, which
can be configured with --output-file as normal.

### `--output-file <output-file>`
Where to write the output to (if unspecified, stdout is used)

### `--log-file <log-file>`
Where to write logs to (if unspecified, stderr is used)

### `--verbose <verbose>`
Set the logging level.

The unwinder has been heavily instrumented with `trace` logging, so if you want to debug why an unwind
happened the way it did, --verbose=trace is very useful (all unwinder logging will be prefixed with
`unwind:`).


\[default: error]  [possible values: off, error, warn, info, debug, trace]
### `--raw-json <raw-json>`
An input JSON file with the extra information.

This is a gross hack for some legacy side-channel information that mozilla uses. It will hopefully be phased
out and deprecated in favour of just using custom streams in the minidump itself.

### `--symbols-url <symbols-url>...`
base URL from which URLs to symbol files can be constructed.

If multiple symbols-url values are provided, they will each be tried in order until one resolves.

The server the base URL points to is expected to conform to the Tecken symbol server protocol. For more
details, see the Tecken docs:

https://tecken.readthedocs.io/en/latest/

Example symbols-url value: https://symbols.mozilla.org/

### `--symbols-cache <symbols-cache>`
A directory in which downloaded symbols can be stored.

Symbol files can be very large, so we recommend placing cached files in your system's temp directory so that
it can garbage collect unused ones for you. To this end, the default value for this flag is a `rust-
minidump-cache` subdirectory of `std::env::temp_dir()` (usually /tmp/rust-minidump-cache on linux).

symbols-cache must be on the same filesystem as symbols-tmp (if that doesn't mean anything to you, don't
worry about it, you're probably not doing something that will run afoul of it).

### `--symbols-tmp <symbols-tmp>`
A directory to use as temp space for downloading symbols.

A temp dir is necessary to allow for multiple rust-minidump instances to share a cache without race
conditions. Files to be added to the cache will be constructed in this location before being atomically
moved to the cache.

If no path is specified, `std::env::temp_dir()` will be used to improve portability. See the rust
documentation for how to set that value if you wish to use something other than your system's default temp
directory.

symbols-tmp must be on the same filesystem as symbols-cache (if that doesn't mean anything to you, don't
worry about it, you're probably not doing something that will run afoul of it).

### `--symbol-download-timeout-secs <symbol-download-timeout-secs>`
The maximum amount of time (in seconds) a symbol file download is allowed to take.

This is necessary to enforce forward progress on misbehaving http responses.

\[default: 1000]

# ARGS
### `<minidump>`
Path to the minidump file to analyze.

### `<symbols-path>...`
Path to a symbol file.

If multiple symbols-path values are provided, all symbol files will be merged into minidump-stackwalk's
symbol database.



# NOTES

## Purpose of Symbols

Symbols are used for two purposes:

1. To fill in more information about each frame of the backtraces. (function names, lines, etc.)

2. To do produce a more *accurate* backtrace. This is primarily accomplished with call frame information (CFI), but
just knowing what parts of a module maps to actual code is also useful!



## Supported Symbol Formats

Currently only breakpad text symbol files are supported, although we hope to eventually support native formats like
PDB and DWARF as well.



## Breakpad Symbol Files

Breakpad symbol files are basically a simplified version of the information found in native debuginfo formats. We
recommend using a version of dump_syms to generate them.

See:
* symbol file docs: https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md
* mozilla's dump_syms (co-developed with this program): https://github.com/mozilla/dump_syms
