# minidump-stackwalk

[![crates.io](https://img.shields.io/crates/v/minidump-stackwalk.svg)](https://crates.io/crates/minidump-stackwalk)
[![docs.rs](https://docs.rs/minidump-stackwalk/badge.svg)](https://docs.rs/minidump-stackwalk)

A CLI frontend for [minidump-processor](https://crates.io/crates/minidump-processor), providing both machine-readable and human-readable digests of a minidump, with backtraces and symbolication.

(If you would like a GUI frontend, see [minidump-debugger](https://github.com/Gankra/minidump-debugger). **This is an experimental external project.**)

This is specifically designed to provide a compatible interface to [mozilla's minidump-stackwalk](https://github.com/mozilla-services/minidump-stackwalk) which is itself similar to [google-breakpad's minidump-stackwalk](https://github.com/google/breakpad/blob/main/src/processor/minidump_stackwalk.cc).

(If you need to distinguish them, call this one "rust-minidump-stackwalk")

The easiest way to use this is by `cargo install`ing it:

```text
> cargo install minidump-stackwalk
> minidump-stackwalk path/to/minidump.dmp
```

Full documentation of the CLI can be found in the "minidump-stackwalk CLI manual" section below
(`--help` will produce the same output).

## Enabling Extra Analysis

The [--features](#--features-features) flag can be used to blindly opt into "more analysis". See that entry in the CLI docs for more details on choosing an appropriate value, but the tl;dr is that you can turn everything on and checkout "what's new" with `--features=unstable-all`.

## Output Formats

Quick Reference:

- `--human` (default) - human friendly output, modified by `--brief`
- `--json` - machine friendly output, modified by `--pretty`
- `--cyborg=some/file/for/machine/output.json` - both human and machine!
- `--dump` - "raw" output of the minidump's contents (for debugging)

minidump-stackwalk defaults to outputting human-readable reports because this is a nicer default for casual use, but the machine-readable output is considered the "main" output format.

If you pass **the --json flag** you will get machine-readable (JSON) output. As of version 0.9.6 this format _should_ be stable, [and has a fully documented schema](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md)! (--pretty will make this output easier for a human to read.)

If you pass **the --human flag**, minidump-stackwalk will output a report in a more human-friendly format with no particular structure. (--brief will make this output less verbose.)

By default, output is written to stdout, but `--output-file=some/file/name.txt` allows you to specify a file to write the output to instead. We will create and completely overwrite the specified file. If there is a fatal error, we will try to avoid writing anything to the output,
which may result in `--output-file` not being created/cleared at all.

Similarly, errors and warnings are written to stderr by default, which can be configured with `--log-file=...`. `--verbose=...` can be used to set the log level (defaults to "error").

If pass **the --cyborg flag** you will get both --human and --json output in one execution (saving lots of duplicated work), specifically you must pass `--cyborg=some/file/for/machine/output.json`. When cyborg mode is enabled, human output will still be the "primary" output that goes to stdout and can still be configured with `--output-file`.

Finally, **the --dump flag** will get you "raw" output of the minidump, for debugging its contents. The precise meaning of this is purposefully vague; the output will contain whatever we find useful to include for debugging. Most other flags will be fairly irrelevant in this mode, because `minidump_processor` will not be invoked (we only use the `minidump` crate for basic parsing of each stream). This is equivalent to the old minidump_dump tool.

## Getting Symbols

minidump-stackwalk can operate without any symbols, but if you provide them you will get richer output in two ways:

- More precise backtraces (using mechanisms like Dwarf CFI or PE32 Unwinding Tables)
- Symbolicated stackframes (backtraces will have proper function names and line numbers)

minidump-stackwalk gets its symbols from [google-breakpad symbol files](https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md). Symbol files are a plain-text format intended to unify the contents of various platform-specific debuginfo/unwinding formats like PE32 Unwinding Tables, Dwarf CFI, Macho Compact Unwinding Info, etc.

To generate those files from your build artifacts, use either [Mozilla's dump_syms](https://github.com/mozilla/dump_syms/) (recommended) or [google-breakpad's dump_syms](https://github.com/google/breakpad/blob/main/src/tools/linux/dump_syms/dump_syms.cc).

You can then either provide those symbol files directly as `symbols-path` values (passed positionally, see the cli manual below), or indirectly by setting up a symbol server that conforms to mozilla's [Tecken protocol](https://tecken.readthedocs.io/en/latest/download.html) and passing a URL to that server with the `--symbols-url` flag. (The protocol is basically a static file server with a specific path format.)

## Analyzing Firefox Minidumps

If you're trying to analyze firefox minidumps, you'll want to point minidump-stackwalk to [Mozilla's Tecken server](https://symbols.mozilla.org/).

```sh
minidump-stackwalk --symbols-url=https://symbols.mozilla.org/ /path/to/minidump.dmp
```

Alternatively, if you want to locally reprocess a crash report on <https://crash-stats.mozilla.org> (socorro), you may want to use [socc-pair](https://github.com/Gankra/socc-pair), which automates this process (and diffs the local result with the one that server had).

## Debugging Stackwalking

rust-minidump includes detailed trace-logging of its stackwalker, which you can enabled with `--verbose=trace` (we recommend against running this mode in production, it's _really_ verbose, and degenerate inputs may produce enormous logs).

Some tips on reading these logs:

- All stackwalking lines will start with `[TRACE] unwind` (other logs may get interspersed).
- Each thread's unwind will:
  - start with "starting stack unwind"
  - end with "finished stack unwind"
- Each frame's unwind will:
  - start with "unwinding \<name\>"
  - end with "\<unwinding method\> seems valid"
  - include the final instruction pointer and stack pointer values at the end
- The methods used to unwind are tried in order (decreasing in quality)
  - cfi
  - frame pointer
  - scan

If you see "trying scan" or "trying framepointer", this means the previous
unwinding method failed. Sometimes the reason for failure will be logged,
but other times the failure is in a weird place we don't have any logging for.
If that happens, you can still potentially infer what went wrong based on what
usually comes after that step.

For instance, a cfi trace typically looks like:

```text
[TRACE] unwind: unwinding NtGetContextThread
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
```

If you instead see:

```text
[TRACE] unwind: unwinding NtGetContextThread
[TRACE] unwind: trying cfi
[TRACE] unwind: trying frame pointer
```

This suggests the cfi analysis couldn't _even_ get to "found symbols for address". So,
presumably, it _couldn't_ find symbols for the current instruction pointer. This may
be because it didn't map to a known module, or because there were no symbols for that module.

Here is an example stackwalking trace:

```text
[TRACE] unwind: starting stack unwind
[TRACE] unwind: unwinding NtGetContextThread
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
[TRACE] unwind: trying STACK CFI exprs
[TRACE] unwind:   .cfa: $rsp 8 + .ra: .cfa 8 - ^
[TRACE] unwind:   .cfa: $rsp 8 +
[TRACE] unwind: STACK CFI parse successful
[TRACE] unwind: STACK CFI seems reasonable, evaluating
[TRACE] unwind: successfully evaluated .cfa (frame address)
[TRACE] unwind: successfully evaluated .ra (return address)
[TRACE] unwind: cfi evaluation was successful -- caller_ip: 0x000000ec00000000, caller_sp: 0x000000ec7fbfd790
[TRACE] unwind: cfi result seems valid
[TRACE] unwind: unwinding 1013612281855
[TRACE] unwind: trying cfi
[TRACE] unwind: trying frame pointer
[TRACE] unwind: trying scan
[TRACE] unwind: scan seems valid -- caller_ip: 0x7ffd172c2a24, caller_sp: 0xec7fbfd7f8
[TRACE] unwind: unwinding <unknown in ntdll.dll>
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
[TRACE] unwind: trying frame pointer
[TRACE] unwind: trying scan
[TRACE] unwind: scan seems valid -- caller_ip: 0x7ffd162b7034, caller_sp: 0xec7fbfd828
[TRACE] unwind: unwinding BaseThreadInitThunk
[TRACE] unwind: trying cfi
[TRACE] unwind: found symbols for address, searching for cfi entries
[TRACE] unwind: trying STACK CFI exprs
[TRACE] unwind:   .cfa: $rsp 8 + .ra: .cfa 8 - ^
[TRACE] unwind:   .cfa: $rsp 48 +
[TRACE] unwind: STACK CFI parse successful
[TRACE] unwind: STACK CFI seems reasonable, evaluating
[TRACE] unwind: successfully evaluated .cfa (frame address)
[TRACE] unwind: successfully evaluated .ra (return address)
[TRACE] unwind: cfi evaluation was successful -- caller_ip: 0x0000000000000000, caller_sp: 0x000000ec7fbfd858
[TRACE] unwind: cfi result seems valid
[TRACE] unwind: instruction pointer was nullish, assuming unwind complete
[TRACE] unwind: finished stack unwind
```

(This is a particularly nasty/useless stack to unwind, but it shows the two extreme cases of CFI unwinding in a known function and scan unwinding in a totally unknown function.)

<!-- markdownlint-disable -->

# minidump-stackwalk CLI manual

> This manual can be regenerated with `minidump-stackwalk --help-markdown`

Version: `minidump-stackwalk 0.14.0`

Analyzes minidumps and produces a report (either human-readable or JSON)

### USAGE

```
minidump-stackwalk [FLAGS] [OPTIONS] <minidump> [--] [symbols-path]...
```

### ARGS

#### `<MINIDUMP>`

Path to the minidump file to analyze

#### `<SYMBOLS_PATH_LEGACY>...`

Path to a symbol file. (Passed positionally)

If multiple symbols-path-legacy values are provided, all symbol files will be merged
into minidump-stackwalk's symbol database.

### OPTIONS

#### `--human`

Emit a human-readable report (the default)

The human-readable report does not have a specified format, and may not have as many
details as the JSON format. It is intended for quickly inspecting a crash or debugging
rust-minidump itself.

Can be simplified with --brief

#### `--json`

Emit a machine-readable JSON report

The schema for this output is officially documented here:

#### `<https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md>`

Can be pretty-printed with --pretty

#### `--cyborg <CYBORG>`

Combine --human and --json

Because this creates two output streams, you must specify a path to write the --json
output to. The --human output will be the 'primary' output and default to stdout, which
can be configured with --output-file as normal.

#### `--dump`

Dump the 'raw' contents of the minidump

This is an implementation of the functionality of the old minidump_dump tool. It
minimally parses and interprets the minidump in an attempt to produce a fairly 'raw'
dump of the minidump's contents. This is most useful for debugging minidump-stackwalk
itself, or a misbehaving minidump generator.

Can be simplified with --brief

#### `--features <FEATURES>`

Specify at a high-level how much analysis to perform

This flag provides a way to more blindly opt into Extra Analysis without having
to know about the specific features of minidump-stackwalk. This is equivalent to
ProcessorOptions in minidump-processor. The current supported values are:

- stable-basic (default): give me solid detailed analysis that most people would want
- stable-all: turn on extra detailed analysis.
- unstable-all: turn on the weird and experimental stuff.

stable-all enables: nothing (currently identical to stable-basic)

unstable-all enables: `--recover-function-args`

minidump-stackwalk wants to be a reliable and stable tool, but we also want to be able
to introduce new features which may be experimental or expensive. To balance these two
concerns, new features will usually be disabled by default and given a specific flag,
but still more easily 'discovered' by anyone who uses this flag.

Anyone using minidump-stackwalk who is _really_ worried about the output being stable
should probably not use this flag in production, but its use is recommended for casual
human usage or for checking "what's new".

Features under unstable-all may be deprecated and become noops. Features which require
additional input (such as `--evil-json`) cannot be affected by this, and must still be
manually 'discovered'.

\[default: stable-basic]  
\[possible values: stable-basic, stable-all, unstable-all]

#### `--verbose <VERBOSE>`

How verbose logging should be (log level)

The unwinder has been heavily instrumented with `trace` logging, so if you want to debug
why an unwind happened the way it did, --verbose=trace is very useful (all unwinder
logging will be prefixed with `unwind:`).

\[default: error]  
\[possible values: off, error, warn, info, debug, trace]

#### `--output-file <OUTPUT_FILE>`

Where to write the output to (if unspecified, stdout is used)

#### `--log-file <LOG_FILE>`

Where to write logs to (if unspecified, stderr is used)

#### `--no-color`

Prevent the output/logging from using ANSI coloring

Output written to a file via --log-file, --output-file, or --cyborg is always

#### `--no-color, so this just forces stdout/stderr printing.`

#### `--pretty`

Pretty-print --json output

#### `--brief`

Provide a briefer --human or --dump report

For human: Only provides the top-level summary and a backtrace of the crashing thread.

For dump: Omits all memory hexdumps.

#### `--no-interactive`

Disable all interactive progress feedback

We'll generally try to auto-detect when this should be disabled, but this is here in
case we mess up and you need it to go away.

#### `--evil-json <EVIL_JSON>`

**UNSTABLE** An input JSON file with the extra information.

This is a gross hack for some legacy side-channel information that mozilla uses. It will
hopefully be phased out and deprecated in favour of just using custom streams in the
minidump itself.

#### `--recover-function-args`

**UNSTABLE** Heuristically recover function arguments

This is an experimental feature, which currently only shows up in --human output.

#### `--use-local-debuginfo`

Use debug information from local files referred to by the minidump, if present.

#### `--symbols-url <SYMBOLS_URL>`

base URL from which URLs to symbol files can be constructed

If multiple symbols-url values are provided, they will each be tried in order until
one resolves.

The server the base URL points to is expected to conform to the Tecken
symbol server protocol. For more details, see the Tecken docs:

#### `<https://tecken.readthedocs.io/en/latest/>`

Example symbols-url values:

- microsoft's symbol-server: <https://msdl.microsoft.com/download/symbols/>
- mozilla's symbols-server: <https://symbols.mozilla.org/>

#### `--symbols-cache <SYMBOLS_CACHE>`

A directory in which downloaded symbols can be stored

Symbol files can be very large, so we recommend placing cached files in your system's
temp directory so that it can garbage collect unused ones for you. To this end, the
default value for this flag is a `rust-minidump-cache` subdirectory of
`std::env::temp_dir()` (usually /tmp/rust-minidump-cache on linux).

symbols-cache must be on the same filesystem as symbols-tmp (if that doesn't mean
anything to you, don't worry about it, you're probably not doing something that will run
afoul of it).

#### `--symbols-tmp <SYMBOLS_TMP>`

A directory to use as temp space for downloading symbols.

A temp dir is necessary to allow for multiple rust-minidump instances to share a cache
without race conditions. Files to be added to the cache will be constructed in this
location before being atomically moved to the cache.

If no path is specified, `std::env::temp_dir()` will be used to improve portability. See
the rust documentation for how to set that value if you wish to use something other than
your system's default temp directory.

symbols-tmp must be on the same filesystem as symbols-cache (if that doesn't mean
anything to you, don't worry about it, you're probably not doing something that will run
afoul of it).

#### `--symbols-download-timeout-secs <SYMBOLS_DOWNLOAD_TIMEOUT_SECS>`

The maximum amount of time (in seconds) a symbol file download is allowed to take

This is necessary to enforce forward progress on misbehaving http responses.

\[default: 1000]

#### `--symbols-path <SYMBOLS_PATH>`

Path to a symbol file.

If multiple symbols-path values are provided, all symbol files will be merged into
minidump-stackwalk's symbol database.

#### `-h, --help`

Print help information

#### `-V, --version`

Print version information
