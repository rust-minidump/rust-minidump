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
use std::io::{BufReader, Read};
use std::process::{Command, Stdio};

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
    // Should be the same as --human and --json
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--cyborg=../target/mdsw-cyborg-temp.json")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    let json_file = File::open("../target/mdsw-cyborg-temp.json").unwrap();
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
    // Should be the same as --human and --json
    let bin = env!("CARGO_BIN_EXE_minidump-stackwalk");
    let output = Command::new(bin)
        .arg("--human")
        .arg("--verbose=trace")
        .arg("--output-file=../target/mdsw-human-out.txt")
        .arg("--log-file=../target/mdsw-log-out.txt")
        .arg("../testdata/test.dmp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    let out_file = File::open("../target/mdsw-human-out.txt").unwrap();
    let mut out_bytes = vec![];
    BufReader::new(out_file)
        .read_to_end(&mut out_bytes)
        .unwrap();
    let out = String::from_utf8(out_bytes).unwrap();

    let log_file = File::open("../target/mdsw-log-out.txt").unwrap();
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
