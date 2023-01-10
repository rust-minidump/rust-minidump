# Contributing to rust-minidump

The top-level [README.md](README.md) documents the structure of the project. Each crate's README should further discuss itself and how to use it.

This document discusses how to actually make changes and properly test/document them.

TL;DR

* Document/Comment your code
* Test your code
* List your change in the upcoming release in RELEASES.md (optional)
* cargo fmt (in project root)
* cargo clippy (in project root)
* (maybe) cargo insta review
    * may also involve updating minidump-stackwalk's README which contains generated docs



# Document Folklore

Minidumps are basically a fractal of corner cases and situations that only happen on certain platforms. If you're introducing some special handling for these kinds of things, it's good to include a comment in the code.

This helps maintain and propagate the "folklore" of our field so more people know about the issue in the future.

Specifically, it's ideal to:

* describe the situation and why it's a problem
* provide a concrete example where this occurs
* describe what is needed to handle it

(Also of course, check in a test that covers exactly this situation!)

Here's an example comment in the current `instruction_seemd_valid_by_symbols` impl:

```rust
// Our input is a candidate return address, but we *really* want to validate the address
// of the call instruction *before* the return address. In theory this symbol-based
// analysis shouldn't *care* whether we're looking at the call or the instruction
// after it, but there is one corner case where the return address can be invalid
// but the instruction before it isn't: noreturn.
//
// If the *callee* is noreturn, then the caller has no obligation to have any instructions
// after the call! So e.g. on x86 if you CALL a noreturn function, the return address
// that's implicitly pushed *could* be one-past-the-end of the "function".
//
// This has been observed in practice with `+[NSThread exit]`!
//
// We don't otherwise need the instruction pointer to be terribly precise, so
// subtracting 1 from the address should be sufficient to handle this corner case.
let instruction = instruction.saturating_sub(1);
```


# Adding a Minidump Stream

The minidump crate is designed in a very modular way, because minidumps themselves are very modular. To help users navigate this modularity, there are several places where we redundantly list and document what the crate knows about and implements.

If you ever introduce a new stream, you should consider adjusting the following.

Core Functionality / Testing:

* [minidump's stream fuzzing tests](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/minidump/fuzz/fuzz_targets/parse.rs#L13)
* [minidump-synth's stream generator](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-synth/src/lib.rs#L31) (make it so that we can test the stream)
    * This will require filling in quite a bit of code!
* [minidump-stackwalk's raw stream dumper](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-stackwalk/src/main.rs#L516) (make it so we can debug the stream)
    * This generally requires implementing a "print" function for it

Documentation / Reporting:

* [unimplemented_streams](https://github.com/rust-minidump/rust-minidump/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/master/minidump/src/minidump.rs#L4582) (remove it)
* [stream_vendor](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/minidump/src/minidump.rs#L4726) (if this stream has a new custom vendor)
* [get_stream's listing of implemented streams](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/minidump/src/minidump.rs#L4520)
* [minidump's listing of implemented streams](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/minidump/src/lib.rs#L71)
* [minidump's listing of stream families](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/minidump/src/lib.rs#L276) (optional, but nice)

Wow that's a lot!

Since streams are rarely perfectly unique, you can usually fill in this stuff by basing it (read: copy-pasting) the code for similar streams. For instance, if you're implementing something similar to MemoryList, then CTRL+Fing for "memory_list" in minidump-synth will generally show you what needs to be added.


# Adding a New Analysis to minidump-processor/minidump-stackwalk

Many potential analyses of minidumps can be done fairly modularly (e.g. argument recovery, exploitability estimation, disassembling the crash address, ...). For these kinds of analyses, there is some established infrastructure for adding them.

New features should be added to minidump-processor (minidump-stackwalk) as unstable_all (--unstable-all) features, and the code should be given its own module. Places to modify:


* Add [a module for the feature to lib.rs](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/src/lib.rs#L80)
* Add [the feature to ProcessorOptions](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/src/processor.rs#L58)
* Fill in the values for [all of ProcessorOptions's ctors](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/src/processor.rs#L82) (disabled for everything but unstable_all) 
* Add fields for the data [to ProcessState](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/src/process_state.rs#L211) (or one of its subfields)
* Run your analysis in [process_minidump_with_options](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/src/processor.rs#L353-L356) (if the flag is set in `options`) and populate its ProcessState fields.
* Add synthetic tests for your feature [in test_processor](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/tests/test_processor.rs)
* (Please) List your new feature in the pending release [in RELEASES.md](https://github.com/rust-minidump/rust-minidump/blob/master/RELEASES.md)

* (Optional) Add support for this data to [ProcessState::print_internal](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/src/process_state.rs#L527) (--human output)
* (Optional) Add support for this data to [ProcessState::print_json](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-processor/src/process_state.rs#L734) (--json output)
  * Update [the JSON Schema](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md)
* If added to either output, then add [a flag to minidump-stackwalk](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-stackwalk/src/main.rs#L25)
  * List it under the [--features flag](https://github.com/rust-minidump/rust-minidump/blob/a8a4a2228af05b73ee671ae5b8a445b804368ef6/minidump-stackwalk/src/main.rs#L98)
  * Update [the CLI docs in minidump-stackwalk's README.md](https://github.com/rust-minidump/rust-minidump/tree/master/minidump-stackwalk#minidump-stackwalk-cli-manual) with the output of --help-markdown
  * Ensure your feature is tested [in test-minidump-stackwalk](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-stackwalk/tests/test-minidump-stackwalk.rs) (may be picked up automatically)
  * See the section below on `insta` for how to update the snapshots of these tests

It's ok to not have *everything* here ready to go in your initial PR if you're concerned we might not want the feature at all. But if we do accept the feature, all of this should ideally be filled out.



# Testing

Whether you're adding a new feature or fixing a bug, **you should always add a test to verify your change works as you expect.** Our code generally tries to be robust in the face of messed up stuff, so **it's very easy to write a test that you think checks for the issue but is actually handled by some other guards elsewhere.** If you're doing some kind of bugfix, it's highly recommended that you run the test both with and without your change to verify that it went from passing to failing!

Major locations for tests include:

* [minidump parsing unit tests](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/minidump/src/minidump.rs#L4739) (see the `minidump-synth` section)
* [minidump-processor integration tests](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/tests/test_processor.rs) (see the `minidump-synth` section)
* [minidump-stackwalk integration tests](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-stackwalk/tests/test-minidump-stackwalk.rs) (see the `insta` section)
* [breakpad-symbols symbol file parser tests](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/breakpad-symbols/src/lib.rs#L819)
* [breakpad-symbols cfi interpreter tests](https://github.com/rust-minidump/rust-minidump/blob/master/breakpad-symbols/src/sym_file/walker.rs#L1032)

minidump-processor stackwalker tests (see `test_assembler` section):

* [x86_unittest.rs](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/src/stackwalker/x86_unittest.rs)
* [amd64_unittest.rs](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/src/stackwalker/amd64_unittest.rs)
* [arm_unittest.rs](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/src/stackwalker/arm_unittest.rs)
* [arm64_unittest.rs](https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/src/stackwalker/arm64_unittest.rs)

fuzzing tests (see the `cargo fuzz` section):

* [minidump fuzz_targets](https://github.com/rust-minidump/rust-minidump/tree/master/minidump/fuzz/fuzz_targets)
* [minidump-processor fuzz targets](https://github.com/rust-minidump/rust-minidump/tree/master/minidump-processor/fuzz/fuzz_targets)
* [breakpad-symbols fuzz targets](https://github.com/rust-minidump/rust-minidump/tree/master/breakpad-symbols/fuzz/fuzz_targets)



## minidump-synth: Synthetic Minidumps for Tests

rust-minidump includes a [synthetic minidump generator](minidump-synth) which lets you come up with a high-level description of the contents of a minidump, and then produces an actual minidump binary that we can feed into the full parser.

This is used throughout the codebase. Being able to use minidump-synth and add things to it is very important! This can in turn involve the test_assembler crate, which we discuss in the next section. Thankfully you don't need to master these systems: there's usually already code/tests for something *similar* which you can copy-paste and tweak. 

Most streams in the minidump format are "some kind of list", and there are a few common formats for those lists. minidump-synth makes it relatively easy to add streams like that. See: ListStream, ExListStream, and SimpleStream.

If your stream is more complicated you might instead want to model your code off of the more adhoc streams like SystemInfo, Exception, or MiscStream.

It's hard for me to know what exactly to say here... the copy-paste method really is super effective here, so I don't really think about the high-level design of this stuff!

------

Example test using minidump-synth (from the minidump crate's unit tests):

```rust ,ignore
#[test]
fn test_crashpad_info_annotations() {
    // Build a synth minidump
    let module = ModuleCrashpadInfo::new(42, Endian::Little)
        .add_list_annotation("annotation")
        .add_simple_annotation("simple", "module")
        .add_annotation_object("string", AnnotationValue::String("value".to_owned()))
        .add_annotation_object("invalid", AnnotationValue::Invalid)
        .add_annotation_object("custom", AnnotationValue::Custom(0x8001, vec![42]));

    let crashpad_info = CrashpadInfo::new(Endian::Little)
        .add_module(module)
        .add_simple_annotation("simple", "info");

    let dump = SynthMinidump::with_endian(Endian::Little).add_crashpad_info(crashpad_info);
    let dump = read_synth_dump(dump).unwrap();


    // Actual tests
    let crashpad_info = dump.get_stream::<MinidumpCrashpadInfo>().unwrap();
    let module = &crashpad_info.module_list[0];

    assert_eq!(crashpad_info.simple_annotations["simple"], "info");
    assert_eq!(module.module_index, 42);
    assert_eq!(module.list_annotations, vec!["annotation".to_owned()]);
    assert_eq!(module.simple_annotations["simple"], "module");
    assert_eq!(
        module.annotation_objects["string"],
        MinidumpAnnotation::String("value".to_owned())
    );
    assert_eq!(
        module.annotation_objects["invalid"],
        MinidumpAnnotation::Invalid
    );
}
```


## test_assembler: building binaries

One of the major pieces of testing infra we rely on is [test_assembler](https://github.com/luser/rust-test-assembler), which allows us to construct artificial binaries with a combination of the builder pattern and *labels* which essentially represent variables which will have their values filled in later. The primary purpose of labels is that they let us refer to offsets in the binary we're writing, *even in the binary itself*, **even when those offsets aren't defined yet**.

The place where you'll see this most is in our stackwalker tests, where we artificially construct the memory of a stack we want to walk. Things like frame pointers are *precisely* pointers to later parts of the stack. Here's an [example frame pointery stack in the amd64 tests](https://github.com/rust-minidump/rust-minidump/blob/2001547fcf4aa0f28f52b8b1ab5da9bd99c8ac87/minidump-processor/src/stackwalker/amd64_unittest.rs#L82-L116):

```rust ,ignore
// Functions typically push their %rbp upon entry and set %rbp pointing
// there.  If stackwalking finds a plausible address for the next frame's
// %rbp directly below the return address, assume that it is indeed the
// next frame's %rbp.
let mut f = TestFixture::new();

// test_assembler lets you connect up many Sections, but here we only need one.
let mut stack = Section::new();           
let stack_start = 0x8000000080000000;
let return_address = 0x00007500b0000110;

// The `start` constant is the address this section should claim to start at.
// This affects the addresses that Labels will report when we query offsets
// in the binary. In this way we can easily test corner cases and get exact
// addresses when we want to test overflow/underflow/truncation bugs.
stack.start().set_const(stack_start);

// We will be querying these 3 offsets in the binary.
let frame0_rbp = Label::new();
let frame1_sp = Label::new();
let frame1_rbp = Label::new();

// Now we build the actual stack binary. Key methods:
//
// * D64(val): push a 64-bit value (may be a label!)
// * append_repeated(val, count): push `count` bytes that contain `val`
// * mark(label): write the current offset to the given label
//
// Note that we `D64(&frame1_rbp)` **before** we `mark(&frame1_rbp)`!
// This is allowed! test_assembler will record that the location of
// the D64 must contain whatever value is written to the label. This
// is done ~magically, and you really don't need to worry about how
// this works. If you mess it up, test_assembler will panic.
stack = stack
    // frame 0
    .append_repeated(0, 16)  // space (16 bytes, all 0)
    .D64(0x00007400b0000000) // junk that's not
    .D64(0x00007500b0000000) // a return address
    .D64(0x00007400c0001000) // a couple of plausible addresses
    .D64(0x00007500b000aaaa) // that are not within functions
    .mark(&frame0_rbp)
    .D64(&frame1_rbp)        // caller-pushed %rbp
    .D64(return_address)     // actual return address
    // frame 1
    .mark(&frame1_sp)
    .append_repeated(0, 32)  // body of frame1
    .mark(&frame1_rbp)       // end of stack
    .D64(0);

f.raw.rip = 0x00007400c0000200;
f.raw.rbp = frame0_rbp.value().unwrap();    // can read the label's value
f.raw.rsp = stack.start().value().unwrap();

let s = f.walk_stack(stack).await; // process the binary
```

**TEST_ASSEMBLER IS VERY "DO WHAT I MEAN" AND HAS SOME FOOTGUNS!** Most operations are generic over all the integer types, which means it will happily widen and truncate an integer to fit the operation you requested. This in turn means Rust can happily infer integers to be the wrong width and you will get very nasty to debug issues.

It's advisable to be extra explicit about integer types and the exact values you want when using test_assembler!



## insta: Snapshot Testing

[Insta](https://github.com/mitsuhiko/insta) is a tool for writing snapshot tests. What are snapshot tests? Well basically we write a test which produces some output and ask insta "hey, is this value the same as last time?". If it's not, insta will fail the test and spit out a diff.

We have [integration tests for the minidump-stackwalk CLI application that snapshot its output](https://github.com/rust-minidump/rust-minidump/blob/40c3390f5705890f932f78b7db4fc02866e012b8/minidump-stackwalk/tests/test-minidump-stackwalk.rs) to confirm that we never *accidentally* change the results. This also lets everyone see exactly what your changes look like in practice!

Now of course, this raises two questions:

* How does it know what the old value was?
* What do I do when the value changes?

When we ask insta about a snapshot, we give it a name like "json-pretty-evil-symbols". Insta maintains [a directory of files containing snapshots](https://github.com/rust-minidump/rust-minidump/tree/master/minidump-stackwalk/tests/snapshots) and will lookup the checked in snapshot with that name.

Whenever a snapshot *doesn't* match (including when insta has no record of that snapshot name at all), it will write out some temporary files to disk recording the diffs. You can then review and accept/reject those diffs with [cargo-insta](https://insta.rs/docs/cli/), a CLI-application you should be able to easily install and run:

```text
cargo install cargo-insta
cargo insta review

<some fancy terminal ui will show up>

<mash "A" a bunch of times if you like all the changes>
```

If the snapshot is totally new, be sure to `git add` the file. Otherwise, git will take care of the rest like any other changes.

Here's what one of the snapshot tests looks like:

```rust ,ignore
#[test]
fn test_evil_json() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--json")
        .arg("--pretty")
        .arg("--evil-json")
        .arg("../testdata/evil.json")
        .arg("../testdata/test.dmp")
        .arg("../testdata/symbols/")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    assert_eq!(stderr, "");

    // Hey insta, did the result change?
    insta::assert_snapshot!("json-pretty-evil-symbols", stdout);
}
```

Part of the motivation for this is to ensure we don't break the the JSON output, which has [very detailed schema document](https://github.com/rust-minidump/rust-minidump/blob/40c3390f5705890f932f78b7db4fc02866e012b8/minidump-processor/json-schema.md), which we're trying to keep stable so people can actually rely on it while the actual implementation details are still in flux.

Yes, [minidump-stackwalk](https://github.com/rust-minidump/rust-minidump/tree/master/minidump-stackwalk) is supposed to be stable and reasonable to use in production!

Oh also if **test_minidump_stackwalk__markdown-help.snap changes, use the new contents to update minidump-stackwalk's README.md**.




## cargo fuzz: Fuzzing The Project

Many of the crates have fuzzing tests. These tests aren't run in CI, but CI does check that they continue to compile. As of this writing, the fuzzer used does not work on Windows (sorry!).

You can run each fuzzer with `cargo fuzz`, but sadly this command is not workspace aware, so you will have to `cd` into the particular project you want to fuzz.

See [the Rust Fuzz Book](https://rust-fuzz.github.io/book/introduction.html) for more details on using `cargo fuzz`.

(Not much to say otherwise, this stuff Just Works, but has to run overnight to get interesting results.)





## socc-pair: A Dedicated Production Diffing, Simulating, and Debugging Tool

This tooling is optimized for testing how changes affect Mozilla's crash-reporting infras, but you might find it useful too.

Because minidumps are so horribly fractal and corner-casey, we spent *a lot* of time terrified of subtle issues that would become huge disasters if we ever actually tried to deploy to production, so we made [socc-pair](https://github.com/Gankra/socc-pair/) which takes the id of a crash report from Mozilla's [crash reporting system](https://crash-stats.mozilla.org/) and pulls down the minidump, the old breakpad-based implementation's output, and extra metadata.

It then runs a local rust-minidump (minidump-stackwalk) implementation on the minidump and does a domain-specific diff over the two inputs. The most substantial part of this is a fuzzy diff on the stackwalks that tries to better handle situations like when one implementation adds an extra frame but the two otherwise agree. It also uses the reported techniques each implementation used to try to identify whose output is more trustworthy when they totally diverge.

It also includes a bunch of mocking and benchmarking functionality.

The tool *can* be made to work without mozilla's servers, **but that workflow needs more work**.

It also enables the [really detailed trace-logging for the stackwalker](https://github.com/rust-minidump/rust-minidump/tree/master/minidump-stackwalk#debugging-stackwalking), making it easier to do a post-mortem debug on the stackwalk and the decisions it made.

Here's a trimmed down version of the kind of report socc-pair would produce:

```diff
comparing json...

 : {
   crash_info: {
     address: 0x7fff1760aca0
     crashing_thread: 8
     type: EXCEPTION_BREAKPOINT
   }
   crashing_thread: {
     frames: [
       0: {
         file: hg:hg.mozilla.org/mozilla-central:mozglue/static/rust/wrappers.cpp:1750da2d7f9db490b9d15b3ee696e89e6aa68cb7
         frame: 0
         function: RustMozCrash(char const*, int, char const*)
         function_offset: 0x00000010
-        did not match
+        line: 17
-        line: 20
         module: xul.dll

.....
.....
.....

   unloaded_modules: [
     0: {
       base_addr: 0x7fff48290000
-      local val was null instead of:
       code_id: 68798D2F9000
       end_addr: 0x7fff48299000
       filename: KBDUS.DLL
     }
     1: {
       base_addr: 0x7fff56020000
       code_id: DFD6E84B14000
       end_addr: 0x7fff56034000
       filename: resourcepolicyclient.dll
     }
   ]
~  ignoring field write_combine_size: "0"
 }
 
 - Total errors: 288, warnings: 39

benchmark results (ms):
  2388, 1986, 2268, 1989, 2353, 
average runtime: 00m:02s:196ms (2196ms)
median runtime: 00m:02s:268ms (2268ms)
min runtime: 00m:01s:986ms (1986ms)
max runtime: 00m:02s:388ms (2388ms)

max memory (rss) results (bytes):
  267755520, 261152768, 272441344, 276131840, 279134208, 
average max-memory: 258MB (271323136 bytes)
median max-memory: 259MB (272441344 bytes)
min max-memory: 249MB (261152768 bytes)
max max-memory: 266MB (279134208 bytes)

Output Files: 
  * (download) Minidump: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.dmp
  * (download) Socorro Processed Crash: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.json
  * (download) Raw JSON: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.raw.json
  * Local minidump-stackwalk --json Output: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.local.json
  * Local minidump-stackwalk Logs: C:\Users\gankra\AppData\Local\Temp\socc-pair\dumps\b4f58e9f-49be-4ba5-a203-8ef160211027.log.txt

``` 

