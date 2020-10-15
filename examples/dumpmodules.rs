// Copyright 2016 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::env;
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;

extern crate minidump;
extern crate minidump_common;

use minidump::*;
use minidump_common::traits::Module;

const USAGE: &'static str = "Usage: dumpmodules [-v] <minidump>
Print full paths of modules from a minidump that were loaded in the crashed
process.

Options:
  -v  Also print debug IDs";

#[derive(PartialEq)]
enum Verbose {
    Yes,
    No,
}

fn print_minidump_modules<T: AsRef<Path>>(path: T, verbose: Verbose) {
    match Minidump::read_path(path.as_ref()) {
        Ok(dump) => {
            if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
                for module in module_list.iter() {
                    print!("{}", module.code_file());
                    if verbose == Verbose::Yes {
                        print!("\t");
                        if let Some(debug_id) = module.debug_identifier() {
                            print!("{}", debug_id);
                        }
                    }
                    println!("");
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
    let mut verbose = Verbose::No;
    let mut stderr = std::io::stderr();
    for arg in env::args_os().skip(1) {
        if arg == OsStr::new("-v") {
            verbose = Verbose::Yes;
        } else if arg.to_str().map(|s| s.starts_with("-")).unwrap_or(false) {
            writeln!(&mut stderr, "Unknown argument {:?}", arg).unwrap();
            break;
        } else {
            return print_minidump_modules(arg, verbose);
        }
    }
    writeln!(&mut stderr, "{}", USAGE).unwrap();
}
