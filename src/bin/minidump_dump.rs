use std::env;
use std::path::Path;
use std::io::Write;

extern crate minidump_processor;

use minidump_processor::*;

const USAGE : &'static str = "Usage: minidump_dump <minidump>";

fn print_minidump_dump(path : &Path) {
    match Minidump::read_path(path) {
        Ok(mut dump) => {
            let stdout = &mut std::io::stdout();
            dump.print(stdout).unwrap();
            if let Ok(thread_list) = dump.get_stream::<MinidumpThreadList>() {
                thread_list.print(stdout).unwrap();
            }
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
