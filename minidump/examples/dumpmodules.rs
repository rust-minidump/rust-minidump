// Copyright 2016 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::env;
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;

use minidump::*;
use scroll::Pwrite;

const USAGE: &str = "Usage: dumpmodules [-v] <minidump>
Print full paths of modules from a minidump that were loaded in the crashed
process.

Options:
  -v  Also print debug IDs";

#[derive(PartialEq)]
enum Verbose {
    Yes,
    No,
}

fn print_minidump_modules<T: AsRef<Path>>(path: T, _verbose: Verbose) {
    let dump =  Minidump::read_path(path.as_ref()).unwrap();
    let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
    let raw_system_info = dump.get_raw_stream(MinidumpSystemInfo::STREAM_TYPE).unwrap();
    let mut output = vec![0; 10000];
    output.pwrite(&system_info.raw, 0).unwrap();
    assert_eq!(&output[..raw_system_info.len()], raw_system_info);
}

#[cfg_attr(test, allow(dead_code))]
fn main() {
    let mut verbose = Verbose::No;
    let mut stderr = std::io::stderr();
    for arg in env::args_os().skip(1) {
        if arg == OsStr::new("-v") {
            verbose = Verbose::Yes;
        } else if arg.to_str().map(|s| s.starts_with('-')).unwrap_or(false) {
            writeln!(&mut stderr, "Unknown argument {:?}", arg).unwrap();
            break;
        } else {
            return print_minidump_modules(arg, verbose);
        }
    }
    writeln!(&mut stderr, "{}", USAGE).unwrap();
}
