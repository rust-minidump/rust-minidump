// These tests largely just check that basic CLI configs still work,
// and show you how you've changed the output. Yes, a lot of these
// will randomly churn (especially the help message ones, which
// contain the latest version), but this is good for two reasons:
//
// * You can easily see exactly what you changed
// * You get a reminder to copy the new --help-markdown output to
//   minidump-stackwalk's README.md
//
// `cargo insta` automates reviewing and updating these snapshots.
// You can install `cargo insta` with:
//
// > cargo install cargo-insta
//
// Also note that `cargo test` for an application adds our binary to
// the env as `CARGO_BIN_EXE_<name>`.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use synth_minidump::*;
use test_assembler::*;

// Some tests need to write files (and read them back).
// To keep this tidy and hidden, we make a new directory
// in `target`.
const TEST_TMP: &str = "../target/testdata/";

fn test_output(file_name: &str) -> PathBuf {
    let mut res = PathBuf::from(TEST_TMP);
    // Ensure the directory exists.
    // Ignore failures because we don't care if the dir already exists.
    let _ = std::fs::create_dir(&res);
    // Now create the path
    res.push(file_name);
    res
}

#[test]
fn test_json() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--json")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("json", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_json_pretty() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--json")
        .arg("--pretty")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("json-pretty", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_json_symbols() {
    // For a while this didn't parse right
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--json")
        .arg("--pretty")
        .arg("../testdata/test.dmp")
        .arg("../testdata/symbols/")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("json-pretty-symbols", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_evil_json() {
    // For a while this didn't parse right
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--json")
        .arg("--pretty")
        .arg("--raw-json")
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
    insta::assert_snapshot!("json-pretty-evil-symbols", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_human() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_human_symbols() {
    // For a while this didn't parse right
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("../testdata/test.dmp")
        .arg("../testdata/symbols/")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human-symbols", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_human_symbols_garbo_url() {
    // For a while this didn't parse right
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg(r#"--symbols-url="garbage.realwebsite""#)
        .arg("../testdata/test.dmp")
        .arg("../testdata/symbols/")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human-symbols", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_human_brief() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("--brief")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human-brief", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_default() {
    // Should be the same as --human
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_cyborg() {
    let cyborg_out_path = test_output("mdsw-test-cyborg-out.json");
    // Should be the same as --human and --json
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--cyborg")
        .arg(&cyborg_out_path)
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    let json_file = File::open(cyborg_out_path).unwrap();
    let mut json_bytes = vec![];
    BufReader::new(json_file)
        .read_to_end(&mut json_bytes)
        .unwrap();
    let json_out = String::from_utf8(json_bytes).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human", stdout);
    insta::assert_snapshot!("json", json_out);
    assert_eq!(stderr, "");
}

#[test]
fn test_trace() {
    // Should be the same as --human and --json
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("--verbose=trace")
        .arg("../testdata/test.dmp")
        .env("NO_COLOR", "1") // disable coloured output for logs
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human", stdout);
    insta::assert_snapshot!("trace", stderr);
}

#[test]
fn test_output_files() {
    let out_path = test_output("mdsw-test-ouput-files-out.txt");
    let log_path = test_output("mdsw-test-output-files-log.txt");
    // Should be the same as --human and --json
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("--verbose=trace")
        .arg("--output-file")
        .arg(&out_path)
        .arg("--log-file")
        .arg(&log_path)
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    let out_file = File::open(out_path).unwrap();
    let mut out_bytes = vec![];
    BufReader::new(out_file)
        .read_to_end(&mut out_bytes)
        .unwrap();
    let out = String::from_utf8(out_bytes).unwrap();

    let log_file = File::open(log_path).unwrap();
    let mut log_bytes = vec![];
    BufReader::new(log_file)
        .read_to_end(&mut log_bytes)
        .unwrap();
    let log = String::from_utf8(log_bytes).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human", out);
    insta::assert_snapshot!("trace", log);
    assert_eq!(stdout, "");
    assert_eq!(stderr, "");
}

#[test]
fn test_version() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("-V")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    assert_eq!(stderr, "");

    let (name, ver) = stdout.split_once(' ').unwrap();
    assert_eq!(name, "minidump-stackwalk");
    let mut ver_parts = ver.trim().split('.');
    ver_parts.next().unwrap().parse::<u8>().unwrap();
    ver_parts.next().unwrap().parse::<u8>().unwrap();
    ver_parts.next().unwrap().parse::<u8>().unwrap();
    assert!(ver_parts.next().is_none());
}

#[test]
fn test_long_help() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("long-help", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_short_help() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("-h")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("short-help", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_markdown_help() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--help-markdown")
        .arg("please")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("markdown-help", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_ambiguous_parse() {
    // For a while this didn't parse right
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("--symbols-url")
        .arg("garbage-url.realwebsite")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_no_minidump() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!output.status.success());
    assert_eq!(stdout, "");
    assert!(!stderr.is_empty());
}

#[test]
fn test_bad_minidump() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("not_a_real_minidump.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!output.status.success());
    assert_eq!(stdout, "");
    assert!(!stderr.is_empty());
}

#[test]
fn test_multiple_outputs_conflict() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--json")
        .arg("--human")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!output.status.success());
    assert_eq!(stdout, "");
    assert!(!stderr.is_empty());
}

#[test]
fn test_pretty_humans() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("--pretty")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!output.status.success());
    assert_eq!(stdout, "");
    assert!(!stderr.is_empty());
}

#[test]
fn test_brief_robots() {
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("--pretty")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(!output.status.success());
    assert_eq!(stdout, "");
    assert!(!stderr.is_empty());
}

fn minimal_minidump() -> SynthMinidump {
    let context = synth_minidump::x86_context(Endian::Little, 0xf00800, 0x1010);
    let stack = Memory::with_section(
        Section::with_endian(Endian::Little).append_repeated(0, 0x1000),
        0x1000,
    );
    let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
    let system_info = SystemInfo::new(Endian::Little);
    SynthMinidump::with_endian(Endian::Little)
        .add_thread(thread)
        .add_system_info(system_info)
        .add(context)
        .add_memory(stack)
}

fn unloaded_minidump() -> PathBuf {
    // Testing how we handle a stack frame having no module mapping, but many
    // "hits" with unloaded modules.
    let synth_path = test_output("unloaded-minidump.dmp");

    let mod1_name = DumpString::new("many.dll", Endian::Little);
    let mod2_name = DumpString::new("solo.dll", Endian::Little);
    let mod3_name = DumpString::new("unused.dll", Endian::Little);

    // All of these should "hit", but this one will be hacked into JSON
    let mod1_1 = UnloadedModule::new(
        Endian::Little,
        0xf00000,
        0x1000,
        &mod1_name,
        0xb1054d2a,
        0x34571371,
    );
    let mod1_2 = UnloadedModule::new(
        Endian::Little,
        0xf00100,
        0x1000,
        &mod1_name,
        0xb1054d2a,
        0x34571371,
    );
    let mod1_3 = UnloadedModule::new(
        Endian::Little,
        0xf003a0,
        0x1000,
        &mod1_name,
        0xb1054d2a,
        0x34571371,
    );
    // Same as mod1_1, to check deduping
    let mod1_4 = UnloadedModule::new(
        Endian::Little,
        0xf00000,
        0x1000,
        &mod1_name,
        0xb1054d2a,
        0x34571371,
    );
    // This one should hit
    let mod2_1 = UnloadedModule::new(
        Endian::Little,
        0xf00220,
        0x2000,
        &mod2_name,
        0xb1054d2a,
        0x34571371,
    );
    // This one should miss
    let mod2_2 = UnloadedModule::new(
        Endian::Little,
        0xaf00220,
        0x2000,
        &mod2_name,
        0xb1054d2a,
        0x34571371,
    );
    // Same as mod 2_1, to check deduping
    let mod2_3 = UnloadedModule::new(
        Endian::Little,
        0xaf00220,
        0x2000,
        &mod2_name,
        0xb1054d2a,
        0x34571371,
    );
    // This one should miss
    let mod3 = UnloadedModule::new(
        Endian::Little,
        0xa003a0,
        0x1000,
        &mod3_name,
        0xb1054d2a,
        0x34571371,
    );

    // Vaguely randomize the module order
    let minidump = minimal_minidump()
        .add_unloaded_module(mod3)
        .add_unloaded_module(mod1_1)
        .add_unloaded_module(mod2_2)
        .add_unloaded_module(mod1_2)
        .add_unloaded_module(mod1_3)
        .add_unloaded_module(mod2_1)
        .add_unloaded_module(mod2_3)
        .add_unloaded_module(mod1_4)
        .add(mod1_name)
        .add(mod2_name)
        .add(mod3_name)
        .finish()
        .unwrap();

    // Write the synth minidump to disk
    {
        let mut file = File::create(&synth_path).unwrap();
        file.write_all(&minidump).unwrap();
    }

    synth_path
}

#[test]
fn test_unloaded_json() {
    let synth_path = unloaded_minidump();

    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--json")
        .arg("--pretty")
        .arg(synth_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("json-pretty-unloaded", stdout);
    assert_eq!(stderr, "");
}

#[test]
fn test_unloaded_human() {
    let synth_path = unloaded_minidump();

    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg(synth_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!("human-unloaded", stdout);
    assert_eq!(stderr, "");
}
