// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::str;

extern crate minidump;
extern crate minidump_common;

use minidump::*;

const USAGE: &'static str = "Usage: minidump_dump <minidump>";

macro_rules! streams {
    ( $( $x:ident ),* ) => {
        &[$( ( minidump_common::format::MINIDUMP_STREAM_TYPE::$x, stringify!($x) ) ),*]
    };
}

fn print_raw_stream<T: Write>(name: &str, contents: &[u8], out: &mut T) -> io::Result<()> {
    writeln!(out, "Stream {}:", name)?;
    let s = contents
        .split(|&v| v == 0)
        .map(|s| String::from_utf8_lossy(s))
        .collect::<Vec<_>>()
        .join("\\0\n");
    write!(out, "{}\n\n", s)
}

fn print_minidump_dump(path: &Path) {
    match Minidump::read_path(path) {
        Ok(dump) => {
            let stdout = &mut std::io::stdout();
            dump.print(stdout).unwrap();
            if let Ok(thread_list) = dump.get_stream::<MinidumpThreadList>() {
                thread_list.print(stdout).unwrap();
            }
            if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
                module_list.print(stdout).unwrap();
            }
            if let Ok(memory_list) = dump.get_stream::<MinidumpMemoryList>() {
                memory_list.print(stdout).unwrap();
            }
            // TODO: MemoryList
            if let Ok(exception) = dump.get_stream::<MinidumpException>() {
                exception.print(stdout).unwrap();
            }
            if let Ok(assertion) = dump.get_stream::<MinidumpAssertion>() {
                assertion.print(stdout).unwrap();
            }
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
            for &(stream, name) in streams!(
                LinuxCmdLine,
                LinuxEnviron,
                LinuxLsbRelease,
                LinuxProcStatus,
                LinuxCpuInfo,
                LinuxMaps
            ) {
                if let Ok(contents) = dump.get_raw_stream(stream) {
                    print_raw_stream(name, contents, stdout).unwrap();
                }
            }
        }
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
