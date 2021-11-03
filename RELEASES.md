# Pending Release (TBD)

Commit: TBD

Polishing and bugfixing to reach final feature parity with mozilla's minidump-stackwalk.

Changes:


## minidump

New features:

* MemoryInfoListStream has been implemented (as `MinidumpMemoryInfoList`)
    * Provides metadata on the mapped memory regions like "was executable" or "was it freed"
* LinuxMapsStream has been implemented (as `MinidumpLinuxMaps`)
    * Linux version of `MemoryInfoListStream` (using a dump of `/proc/self/maps`)
    * Currently sloppily requires paths reported by the metadata to be uft8 (will be fixed)
* New `UnifiedMemoryInfoList` type
    * Takes both `MemoryInfoList` and `LinuxMaps` provides a unified memory metadata interface
* Various simple Linux streams have had their implementations stubbed out
    * The streams are:
        * LinuxCpuInfoStream (as `MinidumpLinuxCpuInfo`)
            * A dump of `/proc/cpuinfo`
        * LinuxProcStatus (as `MinidumpLinuxProcStatus`) 
            * A dump of `/proc/self/status`
        * LinuxEnviron (as `MinidumpLinuxEnviron`)
            * A dump of `/proc/self/environ`
    * Right now these are \~useless as they don't actually expose any of the data (except for one field from `LinuxCpuInfo` for minidump-stackwalk's use).
    * Right now these are sloppy with respect to string encoding (will be fixed)
        * If the streams contain non-utf8 the stream will fail to decode, reporting an empty stream
        * This is possible because the files contain linux file paths, which may be arbitrary bytes


Improvements:

* More docs and tests backfilled (including synth-minidump framework).


Breaking changes:

* Some explicitly typed iterators have been replaced with `impl Iterator`
    * These were always supposed to be like that, this code just pre-existed the feature
    * Comes with minor efficiency win because they were internally boxed and dynamically dispatched(!) to simulate `impl Iterator`.



## minidump-stack/minidump-processor/breakpad-symbols

Symbol cache:

* Now writes (and reads back) an `INFO URL` line to the symbol file
    * This allows `modules[].symbol_url` in the json schema to be populated even on cache hit


Json schema:

* Now properly populates the `system_info.cpu_microcode` field (using `LinuxCpuInfoStream`)



## minidump-common/minidump-tools

No changes









# Version 0.9.1 (2021-10-27)

Commit: [15d73f888c019517411329213c2671d59335f957](https://github.com/luser/rust-minidump/commit/15d73f888c019517411329213c2671d59335f957)

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