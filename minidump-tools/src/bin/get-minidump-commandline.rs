extern crate minidump_tools;

use std::process;

fn main() {
    match minidump_tools::get_minidump_commandline() {
        Ok(_) => {},
        Err(e) => {
            println!("Error: {}", e);
            process::exit(1);
        }
    }
}
