extern crate minidump_tools;

use std::process;

fn main() {
    match minidump_tools::get_minidump_instructions() {
        Ok(_) => {}
        Err(e) => {
            println!("Error: {}", e);
            process::exit(1);
        }
    }
}
