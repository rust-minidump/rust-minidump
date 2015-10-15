// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::env;
use std::path::Path;
use std::io::Write;

extern crate minidump;

use minidump::*;

const USAGE : &'static str = "Usage: minidump_dump <minidump>";

fn print_minidump_dump(path : &Path) {
    match Minidump::read_path(path) {
        Ok(mut dump) => {
            let stdout = &mut std::io::stdout();
            dump.print(stdout).unwrap();
            if let Ok(thread_list) = dump.get_stream::<MinidumpThreadList>() {
                thread_list.print(stdout).unwrap();
            }
            if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
                module_list.print(stdout).unwrap();
            }
            // TODO: MemoryList
            if let Ok(exception) = dump.get_stream::<MinidumpException>() {
                exception.print(stdout).unwrap();
            }
            // TODO: Assertion
            if let Ok(system_info) = dump.get_stream::<MinidumpSystemInfo>() {
                system_info.print(stdout).unwrap();
            }
            if let Ok(misc_info) = dump.get_stream::<MinidumpMiscInfo>() {
                misc_info.print(stdout).unwrap();
            }
            if let Ok(breakpad_info) = dump.get_stream::<MinidumpBreakpadInfo>() {
                breakpad_info.print(stdout).unwrap();
            }
            // TODO: MemoryInfoList
            // TODO: raw Linux streams
        },
        Err(err) => {
            let mut stderr = std::io::stderr();
            writeln!(&mut stderr, "Error reading dump: {:?}", err).unwrap();
        }
    }
}

#[cfg_attr(test, allow(dead_code))]
fn main() {
    if let Some(dump_arg) = env::args().nth(1) {
        let path = Path::new(&dump_arg);
        print_minidump_dump(&path);
    } else {
        let mut stderr = std::io::stderr();
        writeln!(&mut stderr, "{}", USAGE).unwrap();
    }
}
