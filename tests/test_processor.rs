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
    assert_eq!(state.threads[0].info, CallStackInfo::Ok);
    // TODO: should be 4 when we actually unwind
    assert_eq!(state.threads[0].frames.len(), 1);
    // TODO: this should work when we use the exception context
    //let m1 = state.threads[0].frames[0].module.as_ref().unwrap();
    //assert_eq!(m1.code_file(), "c:\\test_app.exe");
    assert_eq!(state.threads[1].info, CallStackInfo::DumpThreadSkipped);
    assert_eq!(state.threads[1].frames.len(), 0);
}
