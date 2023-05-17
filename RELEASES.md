<!-- next-header -->
# Next Version

# Version 0.17.0 (2023-05-17)

* Stack-walking using native debug information was somewhat buggy, after more
  thorough testing it should be now on-par with breakpad symbol file-based
  stack-walking.

## New minidump-unwind crate

The stack walking machinery has been extracted from the minidump-processor
crate and put in a separate one. This crate has significantly less dependencies
than the minidump-processor crate which makes it easier to vendor it in
projects that only care about stack walking.

## Guard-page detection

While analyzing a crash minidump-stackwalk will check if the crashing address
hit a potential guard page. Guard pages are usually introduced by the memory
allocator around larger allocation and have no permissions set. If the crash
address hit one of these pages the `memory_accesses` filed in the JSON output
will contain the `is_likely_guard_page: true` field.

# Version 0.16.0 (2023-04-05)

* Make all `minidump-common::format` structs writable with `scroll`.
* Don't fail reading the entire module list if one module has an invalid size.
* All crates now explicitly include the MIT license
* The stack walker will now fetch the CPU microcode value from the evil JSON
  payload when it's not present in the minidump
* CPU microcode value in the JSON output changed types from u32 to hexstring
* Crashes with jmp/call/ret instruction to non-canonical addresses now show the
  real address we jumped to instead of 0x0000000000000000 or 0xffffffffffffffff
* Updated several dependencies further decreasing the total number of crates
  it depends upon.

## NULL-pointer crash detection

The `minidump-processor` crate will use the disassembly of the current
instruction to check whether the crash involved a NULL-pointer access. Crashes
caused by accessing NULL pointers often exhibit near-NULL address making it less
clear what the underlying problem was. When using `minidump-stackwalk` the JSON
output will contain an `adjusted_address` field holding the reason for the
adjustment (`null-pointer`) as well as the offest from NULL.

## Potential bit-flip detection

The `minidump-processor` crate contains new logic that detects crashes that have
been potentially caused by a bit-flip in the user's machine memory. This
detection is driven by a heuristic as it is impossible to completely tell apart
software crashes from ones induced by flaky hardware. The tests we conducted on
real crash data showed this heuristic to be very effective in telling apart such
crashes. When using `minidump-stackwalk` this information will be added to the
JSON output under the `possible_bit_flips` field.

## Stack walking using native debug information

The stack walker now supports using native debug information available on the
host in addition to Breakpad .sym files. This functionality is enabled by
passing the `--use-local-debuginfo` flag to `minidump-stackwalk` when processing
a crash.

# Version 0.15.2 (2022-12-07)

* Updated the num-range crate, further reducing the number of dependencies
  required when vendoring this crate

# Version 0.15.1 (2022-12-06)

* Updated yaxpeax for improved performance when disassembling instructions
* Removed the tracing crate from the dependencies of the minidump-common crate

# Version 0.15.0 (2022-11-30)

* More Windows errors are now handled correctly
* Small improvements when handling macOS exceptions
* Hexadecimal values are now printed with consistent width and prefixes
* Several crates were updated
* Fixed some links in the documentation

## Support for instruction disassembly

The stackwalker is now capable of disassembling the crashing instruction,
printing it out as well as its memory operands. This functionality is used to
improve crash analysis: we implemented the ability to extract the real crashing
address for global protection fault exceptions on x86-64. These were usually
the result of an access to a non-canonical memory location and were reported as
either 0x0000000000000000 or 0xffffffffffffffff depending on the platform,
irrespective of the actual address.

# Version 0.14.0 (2022-08-03)

Commit: [f9933c36c5f48bf806a428b06399242e1b170020](https://github.com/rust-minidump/rust-minidump/commit/f9933c36c5f48bf806a428b06399242e1b170020)

* fixed an error in the json schema for the `registers` field
* we now emit frames based on inlinee info!!! (see below)

## Inlinee info

We now can read the new "inlinee" info that dump_syms can add to .sym files. This allows us to
report all the inlined functions for a given address in the binary, improving the quality of
backtraces. For machine-readable outputs we prefer to emit these as "fake" frames nested under
the pre-existing "real" frames. This means you will need to update your infra to make use of
the new info (unless using human output), but better reflects the reality that these frames
don't really exist at runtime, only in debuginfo.

* `minidump_processor::StackFrame` now has a new `inlines` field containing this info
* The JSON schema now has `threads.N.frames.N.inlines` (see the schema document for details)
* The human output will now include these frames as if they were real, but with "Found by: inlined"
  and no recovered registers/args

For anyone using breakpad-symbols directly: note that it emits inlines in the reverse order
from minidump-processor because the debuginfo is kind of inherently structured that way. minidump-processor immediately reverses them to put them in the same order as the "real" frames.

(Note that this functionality in dump_syms itself is experimental, and needs to be enabled with
--inlines, and may not work on all platforms. At this precise moment Windows notably does not have
inline info. As such the builtin support for running dump_syms inside breakpad_symbols does not
currently attempt to enable it.)

# Version 0.13.0 (2022-07-26)

Commit: [9fcb3b5108f4e0583548f163eb7b18dae63d1ebe](https://github.com/rust-minidump/rust-minidump/commit/9fcb3b5108f4e0583548f163eb7b18dae63d1ebe)

* Fixed `code_identifier` on iOS.
* Stackwalk threads concurrently. Consequently, `SymbolProvider` now needs to perform request coalescing and take care of internal synchronization.
* minidump-processor's ProcessorOptions now allows you to enable interactive statistics gathering for user interfaces that want immediate feedback 

# Version 0.12.0 (2022-07-14)

Commit: [b5fe86a8f3c1ab8a55f9a6c6e1be72d531af80ee](https://github.com/rust-minidump/rust-minidump/commit/b5fe86a8f3c1ab8a55f9a6c6e1be72d531af80ee)

Lots of fixes and experiments. This change is largely backcompat but we changed a lot of
dependencies and have significantly changed ARM/ARM64 stackwalking results (mostly for the better,
but in some specific situations you may get worse results, see below).


## ARM/ARM64 Stackwalker fixes

All 3 ARM stackwalkers (ARM, ARM64, ARM64_OLD) had completely nonsensical understandings of how lr/fp works.
These issues were inherited from breakpad, and still persist in that codebase. We also now ptr_auth_strip in
more places and more precisely, improving CFI unwinding.

The old code treated lr as always containing the current return address, and a *pushed* lr to be a callee-saved version of the caller's lr. This is just completely wrong. 

lr is mostly a general purpose register that can contain anything, because it's automatically overwritten whenever you make a call -- the callee simply cannot save it! Most functions will immediately push lr on startup, but thiss is pushing *their* lr, and therefore their return address. It's more accurate to think of this as saving the caller's pc.

This is a much simpler situation, so the fix was mostly just to rip out a ton of bad code and add/fix tests.

However this fix may cause a regression in some situations for the *first* frame of the stackwalk. This frame may have a valid lr register value, and if the frame is a proper leaf function (or crashed in the prologue), that lr won't be available on the stack. Without CFI/unwind-tables, we aren't aware of any way to detect that we're in this situation, so we simply assume it's not happening. 

If it *does* happen, then we will effectively end up unwinding our caller instead of ourselves -- but correctly. As a result, the caller will be skipped over, but the rest of the backtrace will behave as normal. Previously we would always assume lr was valid, so we would always handle this situation correctly (but mishandle the much more common non-leaf case).

In the future we may refine our heuristics for the top frame if we determine there's reasonably reliable ways to do that.


## Support for MIPS unwinding!

minidump-processor/minidump-stackwalk now have minimal support for unwinding MIPS (32-bit and 64-bit)!

The current implementation only supports Scanning and CFI, because frame pointers seem to be too unreliable
(at least for the examples we have).

This should be enabled by default and run automatically, although we don't have a lot of tests or experience,
so there's a reasonable chance there's a lot of bugs. symbolic and dump_syms are working on improving the quality
of MIPS CFI as well.


## Compatibility with inline-ful breakpad .sym files

breakpad-symbols is now compatible with the new [`INLINE`](https://github.com/google/breakpad/blob/main/docs/symbol_files.md#inline-records) and [`INLINE_ORIGIN`](https://github.com/google/breakpad/blob/main/docs/symbol_files.md#inline_origin-records) record types in the breakpad .sym format. The current implementation preserves existing rust-minidump behaviour and does not emit any inline frames yet. Instead, as before, symbolicated minidumps will only contain one symbolicated stack frame per "real" stack frame, with the name of the "outer function" at the frame's address, along with the file and line information for the outer function.

We are planning to make use of the new information in a future release.


## Experimental native debuginfo support!

breakpad-symbols/minidump-processor/minidump-stackwalk now have new **disabled-by-default** features

* `dump_syms` feature
    * enables fetching binaries from --symbols-url assuming it is a Microsoft Symbol Server.
        the binaries will still be processed into native .sym files, and those will be cached.
    * this will make `--symbols-url=https://msdl.microsoft.com/download/symbols/` work
    * because this increases the number of urls we query and we are currently very serial in our http
        queries, this may significantly increase runtime!
    * this implies the `http` feature (disabled by default unless you're using minidump-stackwalk)

* `mozilla_cab_symbols` feature
    * enables the dump_syms feature to also check additional paths that mozilla uses for CABed binaries.
        If it would check for `firefox.exe`, it will now also check for `firefox.ex_`

More generally, breakpad-symbols now has machinery for explicitly requesting binaries. this isn't fully
built out but may be useful in the future for implementingthings like bitflip/integrity checks.

## Breakpad-symbols has finally migrated from nom **1.2.2** to nom 7.

This came with a nice ~20% reduction in overall runtime, not necessarily because of the migration itself,
but because the author took the time to clean up some inefficiencies along the way.

RIP to the funniest old code in the project, thanks mstange!

## Migrated to `tracing` over `log`

We not emit more structured logs, making it a little harder to read but easier to grep specific tasks

## Added more windows-specific error codes from Windows SDK version 10.0.22621.0

You may get some better error pretty-printing





# Version 0.11.0 (2022-05-19)

Commit: [4a60e95fd1fceda67aa61cef85461d65457ab046](https://github.com/rust-minidump/rust-minidump/commit/4a60e95fd1fceda67aa61cef85461d65457ab046)

* Update `debugid` and `uuid` dependencies to `0.8.0` and `1.0.0` respectively.
* Make retrieval from http source an optional feature of `breakpad-symbols`.
















# Version 0.10.4 (2022-04-29)

Commit: [7811838a0fb6ddac0663fe07026c526bb9012825](https://github.com/rust-minidump/rust-minidump/commit/7811838a0fb6ddac0663fe07026c526bb9012825)

* Added trace logging to symbol resolution.
* Make `SymbolFile` parsing more robust towards enormous symbols.
* Improvements to stack memory pretty printing.
* Add more write implementations for minidump structures.
* Allow unwinding exception contexts that reference different memory regions than the stack memory.















# Version 0.10.3 (2022-04-01)

Commit: [7cd02d5824bebf92ba395e3368136ddcff9b9f2c](https://github.com/rust-minidump/rust-minidump/commit/7cd02d5824bebf92ba395e3368136ddcff9b9f2c)

Just a bugfix, pulling a previous change that was only applied to ARM64 to ARM64_OLD as well (they should have identical behaviour).
















# Version 0.10.2 (2022-03-24)

Commit: [77b30fc564c8fe23b5ba4dd1663be799d580d290](https://github.com/rust-minidump/rust-minidump/commit/77b30fc564c8fe23b5ba4dd1663be799d580d290)

Some random cleanups and fixes.

# minidump-common

* All the platform-specific errorcode enums have been pulled out to an `errors` module
to keep them out of the way of the actual minidump format's definitions.

# minidump

* MinidumpStream::STREAM_TYPE is now a u32 instead of an enum. This reflects the fact that minidumps allow for custom streams, and makes it easier for third-parties to add implementations of their own streams for their projects.
* Use the more common `eflags` register name instead of `efl`.
* Add `Mips/64` to `system_info::Cpu`, and the enum was made `#[non_exhaustive]`.
* Better support big-endian minidumps. This includes fixes for big-endian UTF16 string parsing, and endian aware parsing of debug-ids.
* The CodeId will always use timestamp + sizeof on Windows, even if no CodeView Record is available.




















# Version 0.10.1 (2022-03-17)

Commit: [b0af5b4ce2e8b5fb680ef006f415744f4a536d8a](https://github.com/rust-minidump/rust-minidump/commit/b0af5b4ce2e8b5fb680ef006f415744f4a536d8a)

Work on making minidump-common more useful for minidump *clients* (generators), as well as general improvements.



# minidump-common

* CONTEXT_ARM64 / CONTEXT_ARM64_OLD have been modified
    * Neither type is packed anymore (didn't effect serialize/deserialize, just made the type less safe)
    * Arm64RegisterNumbers now only has fp/lr, as those are the only actual "x" register puns
    * `sp` has been pulled from the `iregs` array to its own field like pc (layout works either way, this is just more honest).
    * FLOATING_SAVE_AREA_ARM64 has fixed the order of fpcr/fpsr (was just wrong)
    * ContextFlagsArm64 and ContextFlagsArm64Old have been added


# minidump

* MinidumpStream now takes an extra `Option<&MinidumpSystemInfo>` argument so that every stream can have this critical information available while parsing. We will eagerly try to parse this info when you create a Minidump, so if there's any SystemInfo at all (which should always be true, but minidumps are evil), then your stream should have it available for its own parsing. We are currently working on migrating existing streams that need/want it.

* macOS codeids are now properly handled thanks to the above SystemInfo work.


# synth-minidump / minidump-synth

synth-minidump has been renamed to minidump-synth and is now published on crates.io. There's no good reason to do this or use it, but I flaw in `cargo publish` requires the dev-dependencies of binaries (minidump-stackwalk) to be published, so, ok it is!

The rename was done to keep our public naming scheme consistent.























# Version 0.10.0 (2022-03-10)

Commit: [a8a4a2228af05b73ee671ae5b8a445b804368ef6](https://github.com/rust-minidump/rust-minidump/commit/a8a4a2228af05b73ee671ae5b8a445b804368ef6) (there was some Cargo.lock messiness, release is smeared between this one and the previous)

This release is a mix of substantial quality improvements, one major breaking change (making some things async), and several smaller changes to APIs. It's a bit of a big release because some major experimentation was going on and we didn't want to release something that we might immediately revert.





## **Major Breaking Change: Symbolication Is Now `async`(!)**

Making rust-minidump async is in some sense pointless, because it's a single-threaded design that is architected to scale by deploying multiple *processes*. The primary bottleneck on minidump processing is loading and parsing *symbol files*, which rust-minidump already maintains a system-global temporary cache for. This cache is designed specifically for the multi-process workflow.

The motivation for introducing `async` is more of an interoperation concern. For instance, compiling to wasm generally requires I/O to be converted to `async`. Users of `minidump-stackwalk` should be unaffected.

Because symbolication is core functionality for `minidump-processor`, this infects its entire API and means anyone using it will need to run in an async executor. If this proves to be too unpleasant to our users, we may look into making this async-ness configurable with a feature flag (but that would be a lot of work and have a very nasty maintenance burden, so that option isn't to be taken lightly).

---

If you are building an application, making it work with `async` may be as simple as adding the following to your Cargo.toml:

```
tokio =  { version = "*", features = ["full"] }
```

changing `main` to the following:

```
#[tokio::main]
async fn main() {
    ...
```

and adding `.await` to the end of your `process_minidump` call.

---

If you are building a library, the upgrade story is more complicated: you can either expose the `async`-ness in your own APIs, or try to hide it with APIs like `block_on`. Alternatively, you can depend on the `minidump-stackwalk` binary which behaves the same as it did before.




## Major Performance Improvements!

For minidump-stackwalk workloads that make use of large (200MB+) symbol files (e.g. Firefox), 
peak memory usage has been reduced by about 50%, and runtime decreased by up to 10%!
Memory usage wins are consistent whether loading from network or disk. Runtime numbers
depend heavily on how much of a bottleneck symbol file I/O is.





## Major Reliability Improvements! (Fuzzing!)

Thanks to @5225225, rust-minidump has had a ton of fuzzing infrastructure added. The fuzzers found many subtle bugs in the code *and* @5225225 fixed most of them too! Thank you so much!! 😭

To the best of our knowledge, none of the bugs found were security issues more serious than: 

* denial of service through long loops.
* denial of service through large allocations. 
* denial of service through crashes (tripping safe assertions).
* heuristic analyses producing worse results.
* validation steps accidentally discarding valid values.

Thanks to their work, rust-minidump is significantly more robust to "absurd" inputs that could result from either a malicious attacker or random memory corruption (which a crashreporting tool is of course obligated to deal with).

The primary strategy for taming "denial of service" inputs is to realize that although *in principle* a minidump can specify enormous amounts of work to do or enormous amounts of memory to allocate, a *well-formed* input will be linearly bounded by the size of the minidump itself. **This allows the user of rust-minidump to limit resource usage by setting file-size limits on the inputs they will accept.**

For instance, if a minidump reports "I have a list of 10 billion threads" but the minidump itself is only 2MB, we can reject this list length based on our knowledge of how large an entry is in that list (either by rejecting the stream entirely, or by truncating to the maximum possible value for the minidump's size).

Similarly, our stackwalkers have strict "forward progress of the stack pointer" requirements. Although *in principle* the "language" of stackwalking can tell us to go backwards or loop infinitely in place, we terminate stackwalking whenever this happens. CFI (call frame information) evaluation is similarly bounded by supporting no control flow mechanisms, guaranteeing linear forward progress.

Hardening rust-minidump in this manner is an ongoing project.

(Note however that debuginfo is orders of magnitude larger than a minidump (~2MB vs ~200MB), **so it's still quite easy to DOS a rust-minidump instance by just having a stackwalk traverse through a ton of different modules**, necessitating an enormous amount of debuginfo to be downloaded, loaded into memory, and parsed -- if a symbol server is made available to rust-minidump. There is no obvious solution to this at the moment.)





Detailed Changes:


# minidump

## Unloaded Modules Changes (Technically Fixes, but also Breaking)

* **BREAKING CHANGE**: `UnloadedModulesList::module_at_address` is now `modules_at_address`, and returns an Iterator
    * This properly reflects that many modules can overlap with that address
    * Order of iterator is currently unspecified.
* **BREAKING CHANGE**: `UnloadedModules::by_addr` now does not deduplicate or discard overlaps (as is correct)
    * This still needs some reworking, so precise order of duplicates is unspecfied.


## Crash Address Fix

get_crash_address will now mask out the high bits of the return value on 32-bit platforms.
We were seeing some minidumps where the pointer (which is always stored in a 64-bit location)
was incorrectly sign-extended. Now you will always get a value that only ever has the low 32 bits set.


## LinuxMaps Now Properly Implements Address Queries

The initial implementation had a reversed comparison, so valid memory ranges were discarded, and invalid ranges accepted (tripping an assertion later in the code). This has been fixed and better tests to cover this were added.

This didn't affect minidump-processor/minidump-stackwalk because we don't currently have analyses based on MemoryInfo or LinuxMaps (which tell you things like "what memory was executable?").


## Better Codeid and Debugid handling

Codeids/Debugids are the "primary keys" for looking up binaries and symbols for different modules. There is a fair amount of complexity in handling this because over the years microsoft has introduced new versions of the format, and breakpad has hacked in variants for other platforms.

We now use the debugid crate and strongly type these ids to better handle the various corner cases.
As a result, we should more reliably handle the various types of id for each platform, especially for MacOS.


## Improved General Purpose Register Handling

rust-minidump supports many architectures to various levels of usefulness. One very baseline level of support is understanding the CpuContext (CONTEXT_X86, CONTEXT_ARM64, CONTEXT_SPARC, ...). With this release, this baseline support is now significantly improved. CpuContext now includes:

* An associated `REGISTERS` constant, containing the canonical names of a platform's general purpose registers (use memoize_register to canonicalize your register names when there are aliases!).

* A `valid_registers` iterator which yields the value of every known-valid general purpose register.

* A `registers` iterator which yields the value of every geneeral purpose register *regardless of whether they contain unknown garbage*.

In addition, all known `CONTEXT_*` types now implement this trait and are supported by operations which work on contexts. Newly implemented:

* CONTEXT_SPARC
* CONTEXT_MIPS
* CONTEXT_PPC
* CONTEXT_PPC64

MinidumpContext has similarly been extended and had some long-standing `unimplemented!()` paths filled in!


## Input Validation Hardening

As discussed in the top-level notes, allocations are generally bounded by the size of the minidump now, so a rogue list length shouldn't cause you to instantly OOM and die. Allocations and runtime should generally be linearly bounded by the size of the minidump. (But minidump-processor can be made to do a lot more work than this when given a symbol server.)



# minidump-stackwalk/minidump-processor

## Feature families (and --recover-function-args)

You can now opt into enabling extra families of features with
ProcessorOptions (minidump-processor) or `--features` (minidump-stackwalk).

This allows us to introduce new/experimental things without messing up
anyone with harder stability requirements.

The major families are:

* stable-basic (default)
* stable-all (extra stuff)
* unstable-all (experimental stuff)

A new --recover-function-args (recover_function_args) feature has been
added under the unstable-all category, which tries to guess the ABI
and recover function arguments. This is currently very limited and only
kind of works for x86 minidumps where the ABIs tend to be simpler and
pass things on the stack.



## minidump_dump is now minidump-stackwalk --dump

The old minidump_dump binary that was hidden away in the `minidump` crate has
had its functionality merged into minidump-stackwalk with a new output format,
--dump. This simplifies many workflows, because more detailed investigation isn't
"oh so there's this other tool you need...".

This provides a more "raw" dump of the minidump's contents, which is useful for
debugging unexpected or strange results. This is a fairly separate
path that doesn't really use minidump-processor at all, so many flags of
minidump-stackwalk are useless in this mode.

Technically a **BREAKING CHANGE** because `cargo install minidump` would actually
install minidump_dump but this was more of an accident than an intentional
feature of the crate.



## Unloaded Modules

* `process_state::StackFrame` now includes an `unloaded_modules` field that contains all
  the overlapping unloaded modules and their offsets.
* human output has better function signatures that only map to unloaded modules: 
    * typical: `0x1f0800 (unloaded xul.dll@0x12)`
    * most general: `0x1f0800 (unloaded hacker.dll@0xa080|0x10) | (unloaded xul.dll@0x12)
* json output will now pretend the first overlapping unloaded module is loaded for the
  purposes of module name and module offset
  * This will probably be deprecated in favour of a more principled approach later,
    but it accurately reproduces current behaviour.
  * It's possible this won't even ship in this version, but mozilla needed it to 
    get things done for now.


## Better Stackwalking

* We now handle noreturn callees properly in the stack scanning heuristics
    * When you call a noreturn function you are not obligated to have any code following the CALL instruction, so the implicitly pushed return pointer may be "one-past-the-end" of the function's code. Subtracting 1 from the return pointer is sufficient to handle this.
* We no longer \~infinite loop when the stackpointer doesn't change on ARM64
    * Same issue we had on ARM but we forgot to port the fix to the ARM64 backend
* Many fixed overflows that were \~benign but would assert and crash debug builds


## More information in ProcessState

* **BREAKING CHANGE**:`SystemInfo::os_version` has been split into two fields.
    * `os_version`: "5.1.2600"
    * `os_build`: "Service Pack 2"
    * system_info.os_ver in the JSON schema still contains the combined value.
    * The combined value can be obtained with `SystemInfo::format_os_version`

* Threads (CallStacks) now include their original thread_id


## Better Errors

* More detailed formatting of OS-specific errors 
    * macOS EXC_GUARD
    * macOS KERN_FAILURE
    * Better handling of Linux si_code values

* Errors now use `thiserror` instead of `failure`, making the interop with std better.

* We no longer panic when the crashing thread has 0 frames (we instead omit it from the output).

* Fatal error messages are now prefixed with the "type" of error.
    * This can be useful for aggregating and correlating failures, and also gives you a starting point if you want to check the docs/code for that error type.

Examples of new fatal errors:

```text
[ERROR] HeaderMismatch - Error reading dump: Header mismatch
[ERROR] MissingThreadList - Error processing dump: The thread list stream was not found
[ERROR] Panic - A panic occurred at minidump-stackwalk\src\main.rs:305: oh no a panic message!!
```


## Snapshot Tests

minidump-stackwalk now has a suite of snapshot tests, so we can detect and document
any change to output. If you have a specific configuration/input you want to be
monitored, we may be able to include it in our codebase.

See: https://github.com/rust-minidump/rust-minidump/blob/master/minidump-stackwalk/tests/test-minidump-stackwalk.rs


## --raw-json is now --evil-json

**BREAKING CHANGE (TO AN UNSTABLE FEATURE)**

Mozilla's --raw-json flag has been renamed to --evil-json for consistency. It has now also been properly marked as unstable.


# breakpad-symbols

The symbol file parser is now streaming, so we do not need to materialize the entire
file in memory, and we can parse+save the file as we download it or read it from disk.
This reduces peak minidump-stackwalk memory usage by about 50% for large symbol files.
Performance is also improved, but by how much depends on how much I/O dominates your
runtime. I/O time should be about the same, but CPU time should be reduced.





























# Version 0.9.6 (2021-12-08)

Commit: [564ece47dd3b46dd928318fea7ca5f4254dd99c3](https://github.com/rust-minidump/rust-minidump/commit/564ece47dd3b46dd928318fea7ca5f4254dd99c3)

Breaking changes to fix integration issues found during deployment.

More docs.


Changes:


## minidump-stackwalk/minidump-processor

**BREAKING CHANGE**: json schema's `crashing_thread.thread_index` renamed to `crashing_thread.threads_index`

This was always supposed to be the name, we just typo'd it before publishing and didn't notice.


**BREAKING CHANGE**: minidump-stackwalk has changed its default output format from --json
to --human. Note that the --json flag was added in the previous version, so you can just
unconditionally pass --json for both versions to smooth migration.

This change was made to reflect the fact that most users of other flavours of minidump-stackwalk expect the breakpad human-based output more than mozilla's json-based output, minimizing workflow breakage. It's also just the more reasonable output for "casual" usage.









# Version 0.9.5 (2021-12-01)

Commit: [445431ce2bfe55fd85b990bb2a5c01867d2a8150](https://github.com/rust-minidump/rust-minidump/commit/445431ce2bfe55fd85b990bb2a5c01867d2a8150)

The JSON schema and minidump-stackwalk CLI are now stabilized. They are now
reasonable to rely on in production (only reason we would break them is if
we ran into a nasty bug).

This release also adds a ton of documentation! (But there can always be more...)



Changes:

## rust-minidump

Lots more documentation.

## minidump-stackwalk/minidump-processor


Breaking changes:

* Fixed symbols-paths to actually be positional (wasn't supposed to be named)
* Fixed the fact that --symbols-url accepted multiple values per instance
    * You can still pass multiple --symbols-url flags to set multiple http sources, but each one can only have one value
    * This prevents --symbols-url from accidentally greedily parsing the minidump path as one of its arguments
* Legacy truncation fields have been removed from the JSON Schema
    * `frames_truncated` removed because it was always `false`
    * `total_frames` removed because it was always the same as `frame_count`
    * Both were for a misfeature of a previous incarnation of minidump-stackwalk that we won't implement


New features:

* Cleaned up CLI help messages
* Added "--cyborg=path/to/output/json" output option (producing both --json and --human)
* Added --brief flag for shorter --human output
    * Also introduces ProcessState::print_brief
* Added dummy --json flag to hang docs off of (and to let you be explicit if you want)
* Better feedback for corrupt minidumps
* Added JSON Schema document: https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md
    * JSON Schema is now stabilized








# Version 0.9.4 (2021-11-19)

Commit: [8308577df997bae72cf952ddbfaeb901a992d950](https://github.com/rust-minidump/rust-minidump/commit/8308577df997bae72cf952ddbfaeb901a992d950)

Removing derelict experiments, and one bugfix.

Changes:

## ARM Bugfix

minidump-processor's ARM stackwalker should no longer infinitely loop on misbehaving inputs.


## Removed Code

The experimental native DWARF debuginfo symbolizer has been removed from minidump-processor. This code was still technically functional, but it was using very old libraries and not being hooked into new features of minidump-processor. Not worth the maintenance burden until we have a clearer plan for it.

The private minidump-tools subcrate has been completely removed from the project. This has no affect on users using the crates published on crates.io, as it wasn't published. It was a collection of random experiments and tools that are more work to maintain than they're worth now that minidump-processor and minidump-dump work as well as they do. Also it just had some really ancient dependencies -- removing it massively reduces the amount of work needed to compile the workspace.







# Version 0.9.3 (2021-11-18)

Commit: [1e7cc1a18399e32b5589d95575447e5f159d275d](https://github.com/rust-minidump/rust-minidump/commit/1e7cc1a18399e32b5589d95575447e5f159d275d)

New features added to make symbol downloading more reliable.

Changes:

* vendored-openssl feature added to minidump-stackwalk
    * Allows you to statically link openssl (useful for docker)
* `--symbol-download-timeout-secs` flag added to minidump-stackwalk
    * Sets a timeout for downloading symbol files
    * Forces forward progress for misbehaving http response bodies
    * Default is 1000 seconds for one file

This is a breaking change for the constructor of HttpSymbolSupplier, as it now requires the timeout.








# Version 0.9.2 (2021-11-10)

Commit: [4d96a5c49a5e36cf8905cefd5ad8a5041c0d2e72](https://github.com/rust-minidump/rust-minidump/commit/4d96a5c49a5e36cf8905cefd5ad8a5041c0d2e72)

Tentative parity with mozilla/minidump-stackwalk (and all the breakpad features it uses)! 🎉

All that remains before a potential 1.0 release is testing/documenting/cleanup.


Changes:


## minidump

New features:

* GetLastError
    * MinidumpThread now has a method to retrieve the thread's GetLastError value
    * We now parse more Windows error codes

* MemoryInfo:
    * MemoryInfoListStream has been implemented (as `MinidumpMemoryInfoList`)
        * Provides metadata on the mapped memory regions like "was executable" or "was it freed"
    * LinuxMapsStream has been implemented (as `MinidumpLinuxMaps`)
        * Linux version of `MemoryInfoListStream` (using a dump of `/proc/self/maps`)
    * New `UnifiedMemoryInfoList` type
        * Takes both `MemoryInfoList` and `LinuxMaps` provides a unified memory metadata interface

* Linux Streams:
    * New Linux strings types (`LinuxOsString` and `LinuxOsStr`) to represent the fact that some values contain things like raw linux paths (and therefore may not be utf8).
    * Various simple Linux streams have minimal implementations that are exposed as a key-value pair iterator (and also just let you get the raw bytes of the dumped section).
        * LinuxCpuInfoStream (as `MinidumpLinuxCpuInfo`)
            * A dump of `/proc/cpuinfo`
        * LinuxProcStatus (as `MinidumpLinuxProcStatus`) 
            * A dump of `/proc/self/status`
        * LinuxEnviron (as `MinidumpLinuxEnviron`)
            * A dump of `/proc/self/environ`
        * LinuxLsbRelease (as `MinidumpLinuxLsbRelease`)
            * A dump of `/etc/lsb-release`
    * Because these streams are just giant bags of random info, it's hard to reasonably pick out specific values to expose. The iterator API at least makes it so you can get whatever you want easily.


Improvements:

* Contexts with XSTATE are now properly parsed.
    * (although we still ignore the XSTATE data, but previously we would have returned an error)
* minidump_dump now properly handles bad stack RVAs properly.
* MinidumpSystemInfo::csd_version now works
    * Was reading its value from the wrong array *shrug*
    * This also improves minidump processor's `os_ver` string (now at parity with breakpad)
* More docs and tests backfilled (including synth-minidump framework).
* More misbehaving logging removed
* synth-minidump has been pulled out into a separate crate so the other crates can use it for testing.


Breaking changes:

* `MinidumpThread` and `MinidumpException` now lazily parse their `context` value (and `stack` for
`MinidumpThread`).
    * This is because these values cannot be reliable parsed without access to other streams.
    * These fields have been private, in favour of accessors which require the other streams
    necessary to properly parse them.
    * `print` functionality for them (and `MinidumpThreadList`) now also takes those values.
    * For most users this won't be a big deal since you'll want all the dependent streams anyway.
* Some explicitly typed iterators have been replaced with `impl Iterator`
    * These were always supposed to be like that, this code just pre-existed the feature
    * Comes with minor efficiency win because they were internally boxed and dynamically dispatched(!) to simulate `impl Iterator`.
 * LinuxLsbRelease has had all its parsed out values removed in favour of the new iterator API. The logic that parsed out specific fields has been moved to minidump-processor.
 * LinuxLsbRelease (and some others?) now borrow the Minidump.



## minidump-stack/minidump-processor/breakpad-symbols

Thread names:

* Now can retrieve thread names from the evil_json (if this means nothing to you, don't worry about it.)


Symbol cache:

* Now writes (and reads back) an `INFO URL` line to the symbol file
    * This allows `modules[].symbol_url` in the json schema to be populated even on cache hit


Json schema:

* Now properly populates the `thread.last_error_value` field
* Now properly populates the `system_info.cpu_microcode` field (using `LinuxCpuInfoStream`)
* `system_info.os_ver` now includes the contents of `MinidumpSystemInfo::csd_version` (as intended)


Breaking changes:

* `process_minidump_with_evil` has been replaced with the more general `process_minidump_with_options`



## minidump-common

* More Windows error type definitions
* CONTEXT_HAS_XSTATE value added
* doc cleanups









# Version 0.9.1 (2021-10-27)

Commit: [15d73f888c019517411329213c2671d59335f957](https://github.com/rust-minidump/rust-minidump/commit/15d73f888c019517411329213c2671d59335f957)

Iterating closer to parity with mozilla's minidump-stackwalk!

Changes:


## minidump-stackwalk

json schema:

* "exploitability" is now `null` instead of "TODO"
* modules now have more debug stats:
    * "missing_symbols"
    * "loaded_symbols"
    * "corrupt_symbols"
    * "symbol_url"
* modules now have "filename" actually be the filename and not full path
* modules now have "cert_subject" indicating the module was code signed
* new top level field "modules_contains_cert_info" (indicating whether
  we have any known-signed modules.)

cli:
* cli has just been massively cleaned up, now has much more documentation
* --symbols-tmp is now implemented
    * Symbols that are downloaded are now downloaded to this location and
      atomically swapped into the cache, allowing multiple processes to
      share the cache safely.
* --symbols-tmp and --symbols-cache now default to using std::env::temp_dir()
  to improve portability/ergonomics
* new flags for writing output to specific files
    * --output-file
    * --log-file
* --raw-json flag is now implemented
    * feeds into the certificate info in the json schema
    * please don't use this unless you're mozilla
        * if you are mozilla please stop using this too
* logging should be a bit less noisy


## breakpad-symbols/minidump-processor

* Symbolizers now have a `stats` method for getting stats on the symbols
    * See minidump-stackwalk's new "debug stats"
* Symbolizing now has tweaked error types
    * Can now distinguish between
        * "had symbols but address had no entry" and "had no symbols"
        * this is used to refine stack scanning in the unwinder
    * Can now distinguish between "failed to load" and "failed to parse"
        * Surfaced in "corrupt_symbols" statistic
* Symbolizer now truncates PUBLIC entries if there is a FUNC record in the way
    * Reduces the rate of false-positive symbolications
* Unwinding quality has been massively improved
* Unwinders now handle STACK WIN cfi
* Unwinders now more intelligently select how hard they validate output frames
    * "better" techniques like CFI and Frame Pointers get less validation
    * This means we will happily unwind into a frame we don't have symbols for
      with CFI and Frame Pointers, which makes subsequent Scan and Frame Pointer
      unwinds more reliable (since they're starting from a more accurate position).
* Unwinders now handle ARM64 pointer auth (high bits masked off)


## rust-minidump/minidump-common/minidump-tools

* Should be largely unchanged. Any changes are incidental to refactors.


## misc

* removed some excessive logging
* fixed some panics (an overflow and over-permissive parser)





# Previous Versions

No previous versions have release notes (too early in development to worry about it).
