use std::env;
use std::fs::File;
use std::io::Write;

extern crate minidump_processor;

use minidump_processor::*;

fn print_minidump_dump(path : &str) {
    let f = File::open(&path).ok().expect(&format!("failed to open file: {:?}", path));
    if let Ok(mut dump) = Minidump::read(f) {
        let stdout = &mut std::io::stdout();
        dump.print(stdout).unwrap();
        if let Ok(thread_list) = dump.get_stream::<MinidumpThreadList>() {
            thread_list.print(stdout).unwrap();
        }
    } else {
        let mut stderr = std::io::stderr();
        writeln!(&mut stderr, "Error reading dump").unwrap();
    }
}

fn main() {
    if let Some(path) = env::args().nth(1) {
        print_minidump_dump(&path);
    } else {
        let mut stderr = std::io::stderr();
        writeln!(&mut stderr, "Usage: minidump_dump <minidump>").unwrap();
    }
}
