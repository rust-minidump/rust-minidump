use std::process;

fn main() {
    match minidump_tools::dump_minidump_stack() {
        Ok(_) => {}
        Err(e) => {
            println!("Error: {}", e);
            process::exit(1);
        }
    }
}
