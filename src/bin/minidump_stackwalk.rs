use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::io::Write;

extern crate minidump_processor;

use minidump_processor::*;

const USAGE : &'static str =
    "usage: minidump_stackwalk <minidump-file> [symbol-path ...]";

fn print_minidump_process(path : &Path, _symbol_paths : Vec<PathBuf>) {
    let mut stderr = std::io::stderr();
    if let Ok(mut dump) = Minidump::read_path(path) {
        match dump.process() {
            Ok(state) => {
                let mut stdout = std::io::stdout();
                state.print(&mut stdout).unwrap();
            },
            Err(err) => {
                writeln!(&mut stderr, "Error processing dump: {:?}", err).unwrap();
            }
        }
    } else {
        writeln!(&mut stderr, "Error reading dump").unwrap();
    }
}

#[cfg_attr(test, allow(dead_code))]
fn main() {
    if let Some(arg) = env::args().nth(1) {
        let path = Path::new(&arg);
        let symbol_paths = env::args().skip(2).map(|a| PathBuf::from(&a)).collect();
        print_minidump_process(&path, symbol_paths);
    } else {
        let mut stderr = std::io::stderr();
        writeln!(&mut stderr, "{}", USAGE).unwrap();
    }
}
