//! Tests in this file are never run by default, they are just entrypoints for creating minidumps.

#[test]
#[ignore]
fn basic_entry() {
    loop {
        std::thread::park();
    }
}
