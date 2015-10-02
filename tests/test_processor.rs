extern crate minidump_processor;

use std::path::PathBuf;
use minidump_processor::*;

fn read_test_minidump() -> Result<Minidump, Error> {
    let mut path = PathBuf::from(file!());
    path.pop();
    path.pop();
    path.push("testdata/test.dmp");
    Minidump::read_path(&path)
}

#[test]
fn test_processor() {
    let mut dump = read_test_minidump().unwrap();
    let state = process_minidump(&mut dump).unwrap();
    assert_eq!(state.system_info.os, OS::Windows);
    // TODO
    // assert_eq!(state.system_info.os_version.unwrap(),
    // "5.1.2600 Service Pack 2");
    assert_eq!(state.system_info.cpu, CPU::X86);
    // TODO:
    // assert_eq!(state.system_info.cpu_info.unwrap(),
    // "GenuineIntel family 6 model 13 stepping 8");
    assert_eq!(state.threads.len(), 2);
}
