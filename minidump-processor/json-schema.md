# rust-minidump JSON Schema

This document details the current JSON Schema for minidump-processor's and minidump-stackwalk's JSON output.

**As of the publishing of this document, the schema is stable**, but will have backwards compatible additions in the future. Stability guarantees only apply to crates.io releases, so if you build an unpublished version of rust-minidump, it may include things that can be removed before the next release. At the moment minidump-processor and minidump-stackwalk are versioned and published in lockstep (even when only one of them has been modified), so when this document refers to a particular "version" of the schema, it's the published version of these two crates.

**The Most Important Rule Of This Schema:** *Assume all fields are optional, and can be null or absent.* This includes top-level Objects which define subfields (like "modules" or "threads"). Minidumps are inherently "best-effort" and very modular &mdash; Information that we would *like* to use may be corrupt or missing, and rust-minidump has to do the best with what it has. Some information may also be platform-specific (e.g. `mac_crash_info`), so we may omit it when it doesn't make sense.

In the current implementation some data is always required and some fields always get populated, but we'd prefer to not specify this because in principle rust-minidump should always be trying to produce whatever it can whenever it can, which means making *more* things optional.

So when we say the schema is "stable" we are really just saying that we aren't going to rename fields or change their type (int, string, object...) or semantics. And of course we'll always do our best to populate an existing field when the required data is available! While we can *technically* deprecate a field and stop emitting it completely under this definition of "stable", we will try to avoid doing this unless there is some significant issue with the field (or it never contained a useful value anyway).

# Optional Analyses

As we add more experimental and unreliable analyses (like trying to recover function args, trying to detect bitflips, trying to detect exploitable crashes, etc.) they may be hidden behind flags in minidump-stackwalk or [ProcessorOptions](https://docs.rs/minidump-processor/latest/minidump_processor/struct.ProcessorOptions.html).

The default configuration will be fairly conservative, and our strictest stability guarantees can only be given for that configuation. If you opt into a feature that's marked **\[UNSTABLE\]**, its presence and representation in the schema is also unstable. These fields will be marked as `[UNSTABLE:my_feature_name]` in the schema, where `my_feature_name` is the name of the option in ProcessorOptions, and `--my-feature-name` is the name of the feature in minidump-stackwalk.

Features are grouped under three families which can be used for bulk enabling:

* stable_basic (`--features=stable-basic`): the default configuration, guaranteed stable, always there. All fields in the schema are stable_basic unless otherwise stated (In the future some stable-basic features may be made optional, but they will still be enabled by default.)

* stable_all (`--features=stable-all`): also guaranteed stable, but disabled by default.

* unstable_all (`--features=unstable-all`): unstable, may change or be removed.


# Types

Standard JSON types apply, which we will use as follows:

* `<u32>` (unsigned 32-bit integer)
* `<f32>` (IEEE 32-bit floating-point)
* `<bool>`
* `<string>`
* `<array>`
* `<object>`

**All of these can also be `null`, see "The Most Important Rule Of This Schema" above.**

(Arrays and objects will just be represented by the appropriate kind of braces.)

By default, strings are *opaque* to this schema, meaning they can contain anything (including the empty string). This usually means we are just passing the string through from a symbol file or the minidump itself. There may be an underlying structure from the source, but we aren't going to try to guarantee or specify it.

Some strings do however have more structure:

* `<hexstring>` - a string containing a hexadecimal integer that will fit into a `u64` (ex: "0x000af123"). These are usually pointers. We serialize these values as strings instead of json integers for a few reasons:
  * Although *on paper* JSON supports infinite precision integers, this is dubious because JavaScript itself (and many other languages) are built around Doubles which do not support that full range
  * Although this format is for machine-use first and foremost, humans often have reasons to read it, and this makes those values easier to read/scan for notable details. For similar reasons we also *try* to 0-pad hexstring values to the crashing platform's native width.
  * Feeding the JSON into indexing/sorting/reporting infrastructure is easier, because at every step the values are represented in the format that humans prefer for pointers.

* `"ENUM" | "Variants" | "like" | "these!"` - When there are only a limited number of values a field can contain, we will try to list them all off. However, because this schema is *descriptive* of the contents of a minidump, new features may necessitate new variants (for instance, new kinds of hardware and operating systems can happen). **Do not assume enums are exhaustive.**




# Schema

NOTE 1: Ordering of the fields is generally arbitrary, but they are roughly ordered in decreasing
importance/reliability. So e.g. `crash_info`, `system_info`, and `threads` contain the most
important information, and it would be very surprising if they were ever null.

NOTE 2: If the current implementation *supports* emitting a field but doesn't have the data
necessary to populate it, it will generally prefer emitting an explicit `null` over omitting the
field. Although sometimes the empty string is also used for this purpose (we may
try to tighten that up in future releases if it's an issue).

NOTE 3: Minidumps can be generated regardless of if there's an actual crash, but for simplicity
these notes will assume that a crash happened by default, since that's the important case.

NOTE 4: This schema isn't completely "normalized" and includes some information that *technically*
you could compute from the other data in the schema. To make it clear that these fields aren't
trying to capture any special situation, it will often be indicated that they're "redundant".
Redundant data is included to make the format more human-friendly and to try to reduce the
need for post-processing &mdash; especially when rust-minidump needs to compute that information
anyway.

<!-- weirdly rust syntax highlighting handles this fake-json best? -->
```rust,ignore
{
  // Either OK or an Error we encountered while trying to generate this report.
  //
  // Currently unused by rust-minidump, as we prefer to generate no output
  // when there's an error. Error messages will be sent to the logs. Very
  // few things will cause a processing error -- it generally only happens
  // for empty or heavily truncated minidumps which contain literally no
  // information about the crash.
  //
  // If we do ever use this, then generally any value other than "OK" will
  // imply the absence of all other fields.
  "status": "OK",

  // Crashing Process' id
  "pid": <u32>,







  // Top-level information about what caused the crash
  "crash_info": {
    // A platform-specific error type that caused the crash. e.g.:
    // * "EXCEPTION_ACCESS_VIOLATION" (Windows),
    // * "EXC_BAD_ACCESS / KERN_INVALID_ADDRESS" (MacOS)
    // * "SIGSEGV" (Linux)
    // * "0xa12ef56" (unknown error code)
    //
    // Note that some error codes have overlapping values, so we're making
    // a best guess at the type here.
    "type": <string>,

    // The memory address implicated in the crash.
    //
    // If the process crashed, and if the crash reason implicates memory,
    // this is the memory address that caused the crash. For data access
    // errors this will be the data address that caused the fault. For code
    // errors, this will be the address of the instruction that caused the
    // fault.
    "address": <hexstring>,

    // In certain circumstances, the previous `address` member may report a sub-optimal value
    // for debugging purposes. If instruction analysis is able to successfully determine a
    // more helpful value, it will be reported here.
    "adjusted_address": {
      "kind": <string>,
      // The original access was an Amd64 "non-canonical" address; actual address is provided here.
      // (Present when kind == "non-canonical")
      "address": <hexstring>,
      // The base pointer was null; offset from base is provided here.
      // (Present when kind == "null-pointer")
      "offset": <hexstring>
    },

    /// A string representing the crashing instruction (if available)
    "instruction": <string>,

    /// A list of memory accesses performed by crashing instruction (if available)
    "memory_accesses": [
      {
        "address": <hexstring>,
        "size": <u32>,
        /// Whether the address falls in a likely guard page (typically indicating buffer overflow).
        /// This field may only be present when the value is `true`.
        "is_likely_guard_page": <bool>
      }
    ],

    /// A list of addresses that could have been the actual address the program
    /// wanted to access, but which were changed by a bit-flip.
    "possible_bit_flips": [
      {
        "address": <hexstring>,
        /// Flags related to the calculation of confidence in a bit-flip.
        "details": {
           /// Whether the original address was non-canonical.
           "was_non_canonical": <bool>,
           /// Whether the bit-flipped address is null.
           "is_null": <bool>,
           /// Whether the original address was fairly low.
           /// This is only set if `is_null` is true, and may indicate that a
           /// bit flip didn't occur (low values could be the result of many
           /// things).
           "was_low": <bool>,
           /// Whether any poison register values were found.
           "poison_registers": <bool>,
           /// How many registers containing values near the bit-flip-corrected address.
           /// This is only set for corrected addresses which are sufficiently
           /// high to avoid false positives with (likely) low values.
           "nearby_registers": <u32>
        },
        /// The calculated confidence value in the bit-flip-corrected address.
        "confidence": <f32>
      }
    ],

    // The thread id of the thread that caused the crash (or requested the minidump).
    "crashing_thread": <u32>,

    // A message describing a tripped assertion (which presumably caused the crash).
    "assertion": <string>,
  }, // crash_info







  // Info about the hardware and OS that the crash occurred on.
  "system_info": {
    // The flavor of operating system
    "os": "Windows NT"
      | "Mac OS X"  // This is also used for MacOS 11+
      | "iOS"
      | "Linux"
      | "Solaris"
      | "Android"
      | "PS3"
      | "NaCl"
      | <hexstring>, // (unknown, here's the raw OS code)

    // Version of the OS
    // Generally "<major>.<minor>.<build_number>", e.g. "10.0.19043"
    "os_ver": <string>,

    // The flavor of CPU
    "cpu_arch": "x86"
      | "amd64"
      | "ppc"
      | "ppc64"
      | "sparc"
      | "arm"
      | "arm64"
      | "unknown",

    // A string describing the cpu's vendor and model
    // e.g. "family 6 model 60 stepping 3"
    "cpu_info": <string>,

    // Number of cpus (high level core count, probably?)
    "cpu_count": <u32>,

    // The version number of the microcode running on the CPU
    "cpu_microcode_version": <hexstring>,
  }, // system_info








  // How many threads there are (redundant array length).
  "thread_count": <u32>,

  "threads": [
    {
      // Name of the the thread.
      "thread_name": <string>,

      // The windows GetLastError() value for this thread.
      //
      // This roughly contains the status of the last system API call this
      // thread made before the crash, although its value is not reliably
      // updated (similar to errno on linux). Has the same kinds of strings
      // you will get from `crash_info.type` on Windows (mostly NTSTATUS
      // and WinError values).
      "last_error_value": <string>,

      // How many stack frames there are (redundant array length).
      "frame_count": <u32>,

      // The stack frames of the thread, from top (the code that was currently
      // executing) to bottom (start of the thread's execution).
      //
      // Stack frames are heuristically recovered. These values may be wrong,
      // especially if the "trust" is worse than "cfi" or "frame_pointer".
      // Quality of output relies heavily on symbol files providing debuginfo.
      //
      // Each stack frame is a specific location in the code (including dynamic
      // libraries) that was executing, optionally including mappings back to
      // the source files (.h, .c, .rs, ...).
      "frames": [
        {
          // The index of the frame in this array (redundant).
          "frame": <u32>,

          // The technique used to recover this stack frame (enum variants
          // ordered in decreasing level of trustworthiness).
          "trust": "context"   // State explicitly saved by minidump (should be perfect)
            | "cfi"            // Used debuginfo to unwind (very reliable)
            | "frame_pointer"  // Used frame pointers to unwind (often reliable)
            | "scan",          // Searched the callee's stack memory (SKETCHY!)

          // The values the general purpose registers contained.
          //
          // In the default configuration, this field will only show up in
          // frame 0 of the crashing_thread copy of this backtrace. In the
          // future, this may be more configurable and appear in different
          // frames.
          //
          // The contents of this <object> are platform-specific,
          // but it's always a mapping from register names to <hexstring>s.
          //
          // e.g. "rip": "0x000000010bbc852e"
          "registers": {
            "some_register_name": <hexstring>,
          }

          // The address (instruction) this frame is executing.
          //
          // For the top first frame (0), this is precise (e.g. it's the value of $rip),
          // but for all other frames the value is more heuristically computed from the
          // callee's return address. This is because we only *have* the return address,
          // and that goes to the *next* instruction in this function, not the one we're
          // currently executing.
          //
          // This is a bit more complicated to compute than you might imagine. For
          // instance, `objc_msgSend` does some magic to erase itself from the stack,
          // muddying the relationship between the return address and "current"
          // address.
          "offset": <hexstring>

          // The name of the module (library/binary) the `offset` maps to
          // (so the library/binary it's executing). (redundant)
          //
          // e.g.
          // * "libgtk-3.so.0"
          // * "kernel32.dll"
          // * "firefox.exe"
          "module": <string>,

          // `offset` but translated to be relative to the `module`s start
          // (so what instruction in the library/binary is being executed`).
          // (redundant)
          "module_offset": <hexstring>,

          // All of the unloaded modules that overlapped with this frame's `offset`.
          //
          // Currently only populated if `module` is null, but this may change
          // if there is significant demand for this value to always be present.
          //
          // This is sorted by module name to keep the order stable.
          "unloaded_modules": [
            {
              // The name of the unloaded module (see "module" above).
              "module": <string>,

              // Equivalent to "module_offset" above, but has multiple values because
              // a module that has been unloaded (and reloaded) multiple times
              // may have many overlapping locations.
              //
              // Modules *often* get reloaded in the same location,
              // so this will usually only contain one value.
              //
              // This will never be empty, will never contain duplicates,
              // and is sorted to keep the order stable.
              //
              // If there is desire for a more raw log of the offsets
              // (reflecting the raw values of the top level "unloaded_modules"),
              // then we will introduce a "raw_offsets" field.
              "offsets": [<hexstring>],
            }
          ]

          // The following fields all require symbol files to populate:

          // Pseudo-frames for functions that were inlined into this one.
          // 
          // We prefer emitting these as "subframes" because these frames
          // don't exist at runtime in the stack, and are only known because
          // compilers shove this information in debuginfo. As a result,
          // most of the info for these frames is identical to the parent
          // "real" frame or don't make sense at all. For instance they
          // have the same "registers", "offset", "module", and "module_offset".
          // 
          // Inlined frames are in the same ordering that normal frames are,
          // and logically come "before" the real frame in the backtrace.
          // So if displaying the frames you should do roughly:
          // 
          // ```
          // let mut frame_num = 0;
          // for frame in &thread.frames {
          //     for inline in &frame.inlines {
          //         print_inline(frame_num, frame, inline);
          //         frame_num += 1;
          //     }
          //     print_frame(frame_num, frame);
          //     frame_num += 1;
          // }
          // ```
          // 
          // (But remember the golden rule: all fields are optional, check for null!)
          "inlines": [
            {
                // All of these have the same meaning/format as the ones in "real" frames
                "function": <string>,
                "file": <string>,
                "line": <u32>,
            }
          ]


          // The name of the function being executed.
          //
          // e.g.
          // * "g_thread_proxy"
          // * "nsAppShell::EventProcessorCallback(_GIOChannel*, GIOCondition, void*)"
          // * "-[NSView removeFromSuperview]"
          // * "<unknown in textinputframework.dll>"
          // * "`anonymous namespace'::InterposedNtCreateFile(void**, unsigned long)"
          // * "{virtual override thunk({offset(-16)}, mozilla::Http2Session::SanityCheck())}"
          // * "std::panicking::begin_panic_handler::{{closure}}"
          "function": <string>,

          // `offset` but translated to be relative to the `function`s first
          // instruction in the binary/library.
          "function_offset": <hexstring>,

          // The name of the source file the function is defined in.
          //
          // e.g.
          // * "/home/john/my_project/src/main.h"
          // * "glib/gthread.c"
          // * "hg:hg.mozilla.org/mozilla-central:mozglue/misc/ConditionVariable_windows.cpp:524df7136a1f401f317d472f7945e6a284bd66f5"
          "file": <string>,

          // The line in the source file that is roughly executing.
          "line": <u32>,

          // Whether we had symbols for this frame (currently redundant with `function`).
          "missing_symbols": <bool>,
        }
      ], // frames
    }
  ], // threads




  // The thread that crashed (mostly copied from `threads`), with some additional details.
  "crashing_thread": {

    // Index into the `threads` array that this thread has.
    "threads_index": <u32>,

    // The rest of the fields are the same as they are in `threads` (redundant).

    "thread_name": <string>,
    "last_error_value": <string>,
    "frame_count": <u32>,
    "frames": [
      {
        "frame": <u32>,
        "trust": "context" | "cfi" | "frame_pointer" | "scan",
        "registers": {
          "some_register_name": <hexstring>,
        },
        "offset": <hexstring>
        "module": <string>,
        "module_offset": <hexstring>,
        "unloaded_modules": [
          {
            "module": <string>,
            "offsets": [<hexstring>],
          }
        ]
        "function": <string>,
        "function_offset": <hexstring>,
        "file": <string>,
        "line": <u32>,
        "missing_symbols": <bool>,
      }
    ], // frames
  } // crashing_thread





  // The index of the "main" module (i.e. the executable).
  "main_module": <u32>,

  // Whether any modules have code signing information (redundant).
  [UNSTABLE:evil_json] "modules_contains_cert_info": <bool>,

  // All the known modules that are currently mapped into the process.
  //
  // Modules roughly map to libraries (both static and dynamic) and
  // executables. However on some platforms you can get Weird Things
  // like memory-mapped fds or fonts.
  //
  // There is no specific significance to the ordering rust-minidump
  // emits here. It may change in the future if we decide we prefer
  // to e.g. sort by address or name to make human reading better.
  "modules": [
    {
      // The first address that maps to this module (inclusive).
      "base_addr": <hexstring>

      // The last address that maps to this module (exclusive).
      "end_addr": <hexstring>

      // The name of the file containing debuginfo for this module
      // e.g.
      // * "Kernel.Appcore.pdb"
      // * "firefox" (binary contains its own debuginfo)
      // * "libLAPACK.dylib" (dylib contains its own debuginfo)
      // * "libasound.so.2" (so contains its own debuginfo)
      "debug_file": <string>,

      // A string uniquely identifying the build.
      //
      // Combining this with `debug_file` gives you a very good
      // Primary Key for looking up symbol files (which is exactly what we
      // do for http symbol lookup).
      //
      // e.g. "6DEB321BD0ED5E6F4262367CCA2D26BF1"
      "debug_id": <string>,

      // The "name" of the module.
      //
      // Depending on the platform, this can be some very weird stuff...
      //
      // e.g.
      // * "firefox.exe"
      // * "kernel.appcore.dll"
      // * "libLAPACK.dylib"
      // * "libasound.so.2"
      // * "memfd:pulseaudio (deleted)"
      // * "VeraBd.ttf"
      // * "uBlock0@raymondhill.net.xpi"
      "filename": <string>,

      // The Code id. No I don't know either.
      //
      // e.g. "F75275E226000"
      "code_id": <string>,

      // The official version of the module.
      //
      // e.g.
      // "10.0.19041.546"
      "version": <string>,

      // If non-null, indicates that this module is known to be signed by
      // the given party (useful for detecting unofficial DLL injection).
      //
      // e.g.
      // * "Microsoft Windows"
      // * "Mozilla Corporation"
      [UNSTABLE:evil_json] "cert_subject": <string>,



      // These are all just metrics for debugging minidump-processor

      // If we looked for a symbol file for this module and couldn't find one.
      "missing_symbols": <bool>,
      // If we managed to load a symbol file for this module.
      "loaded_symbols": <bool>,
      // If the symbol file was too corrupt to use.
      "corrupt_symbols": <bool>,
      // The URL we downloaded the symbol file from.
      "symbol_url": <string>,
    }
  ], // modules




  // This is the same as `modules`, but specifically for modules that were no
  // longer mapped into the process' address space when the minidump was generated.
  //
  // Fields are a subset of `modules`.
  //
  // Because modules can be loaded and unloaded repeatedly, `unloaded_modules`
  // is more of a *log* of unload *events* and not a clean mapping of addresses to
  // modules. This means:
  //
  // * Entries may have overlapping address ranges
  // * A module may show up repeatedly, potentially at different addresses.
  //
  // Due to the way this "logging" is implemented in the minidump generator,
  // some unload events may be lost (you wouldn't want to use up all of a
  // system's memory just remembering that a DLL was loaded and unloaded a
  // million times).
  //
  // Events are *probably* incidentally in chronological order, but this
  // isn't guaranteed by the minidump format or its generators. We do however
  // preserve the minidump's ordering in case that contains some useful signal.
  "unloaded_modules": [
    {
      "base_addr": <hexstring>,
      "end_addr": <hexstring>,
      "code_id": <string>,
      "filename": <string>,
      [UNSTABLE:evil_json] "cert_subject": <string>,
    }
  ], // unloaded_modules






  // Linux Standard Base information (Linux-specific extended system_info)
  //
  // All of these are raw dumps of specific keys in `/etc/lsb-release`.
  // Because the same information may show up under different names on
  // different systems (I guess?), some of these values may source their
  // values from multiple keys. If both are present, one is chosen arbitrarily.
  //
  // TODO(?): properly document the semantics of these values. Unclear how
  // consistently they're used across distros.
  "lsb_release": {
    // DISTRIB_ID or ID
    "id": <string>,

    // DISTRIB_RELEASE or VERSION_ID
    "release": <string>,

    // DISTRIB_CODENAME or VERSION_CODENAME
    "codename": <string>,

    // DISTRIB_DESCRIPTION or PRETTY_NAME
    "description": <string>,
  }, // lsb_release






  // MacOS-specific extended crash_info
  //
  // This is a dump of the contents of a Mach-O `__DATA,__crash_info` section.
  //
  // TODO(?): properly document the semantics of these values. Are they even
  // documented by Apple, or did we just reverse-engineer these?
  "mac_crash_info": {
    // The number of entries in `records` (redundant).
    "num_records": <u32>,
    "records": [
      {
        "thread": <hexstring>,
        "dialog_mode": <hexstring>,
        "abort_cause": <hexstring>,
        "module": <string>
        "message": <string>,
        "signature_string": <string>,
        "backtrace": <string>,
        "message2": <string>,
      }
    ] // records
  }, // mac_crash_info






  // MacOS-specific kernel boot args
  "mac_boot_args": <string>,

}
```




# Schema Change Notes





## 0.9.6

**BREAKING CHANGE** (really? right after claiming it's stable?)

`crashing_thread.thread_index` renamed to `crashing_thread.threads_index`

This was actually always supposed to be the name, we just typoed it and didn't notice before publishing. It's soon enough that we'd rather just fix it rather than eternally have two copies of the field. Sorry!


## 0.10.0

### sensitive and exploitability fully removed

The top level `sensitive` field and its child `exploitability` field have been removed from the schema since they were already optional and never contained any real output. These features were never implemented, but they were stubbed out and made it into the schema simply because we were emitting these dummy fields.

While the idea of a "sensitive" section that can be stripped for data-security purposes is appealing, in reality it isn't really useful because *lots* of information in this report potentially contains sensitive user information. It's up to your organization to decide who can see which fields.

### evil-json now used uniformly and properly indicated as unstable

The evil_json feature has always been an "ideally temporary" hack for Mozilla's workflow, and has therefore always been defacto unstable, but we didn't have the terminology to refer to this. Now it's properly marked as unstable. Mozilla is free to mess with it however it wants.

The codebase also interchangeably referred to the evil_json feature as both evil_json and raw_json. It is now always evil_json to properly express that this is an evil feature that you should not use unless you are mozilla (and if you are mozilla, you should also stop using it).

This changes the `--raw-json` flag of minidump-stackwalk to `--evil-json`

## code_id casing

`modules[N].code_id` and `unloaded_modules[N].code_id` are now uniformly output as lowercase, as this format is expected by some case-sensitive tools. Previously, the casing would be a seemingly arbitrary casing, because code_id's were getting fed through the machinery for formatting debug_ids (which often contain two values, which are distinguished by UPPERlower).

### Unloaded Modules

Stack frames (`threads.N.frames.N` and `crashing_thread.frames.N`) now have
an "unloaded_modules" field, which provides all the unloaded modules that intersect
with that address, and the offsets (equivalent to "module_offset").

Offsets are an array because a module may be unloaded (and reloaded) many times,
which can result in an unloaded module having several known locations. Absent
a mechanism to pick the "right" one, we just list them all.

That said, modules *often* reload in the same location, so usually "unloaded_modules"
will just contain one module with one offset (we deduplicate the offsets).

Currently "unloaded_modules" is only populated if "module" is `null` (indicating
the frame's address didn't match any known loaded module). This is because
the "module" signal is to be preferred (and unconditionally computing these
values would be expensive and noisy). **In the future we may change this, if
we find there is a significant desire for unloaded_module info even when a
known loaded module is available.**

Also note that the information we have on unloaded modules
is fairly limited, so we can't validate them against certificates or use
them for symbolication. All we can tell you is that a module with the given
name was at a particular location. Whether it was a fake DLL from a hacker,
who could say?

# 0.14.0 (not yet released)

* Fixed some typos in the `registers` schema, the actual implementation is unchanged
* `threads.N.frames.N.inlines` added for inlined frames!
