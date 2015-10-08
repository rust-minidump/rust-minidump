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
    assert_eq!(state.crash_address.unwrap(), 0x45);
    assert_eq!(state.threads.len(), 2);
    assert_eq!(state.requesting_thread.unwrap(), 0);

    // Check thread 0.
    assert_eq!(state.threads[0].info, CallStackInfo::Ok);
    assert_eq!(state.threads[0].frames.len(), 4);
    // Check thread 0, frame 0.
    let f0 = &state.threads[0].frames[0];
    let m1 = f0.module.as_ref().unwrap();
    assert_eq!(m1.code_file(), "c:\\test_app.exe");
    assert_eq!(f0.trust, FrameTrust::Context);
    assert_eq!(f0.context.get_instruction_pointer(), 0x0040429e);
    assert_eq!(f0.context.get_stack_pointer(), 0x0012fe84);
    if let MinidumpContext { raw: MinidumpRawContext::X86(raw),
                             ref valid } = f0.context {
        assert_eq!(raw.eip, 0x0040429e);
        assert_eq!(*valid, MinidumpContextValidity::All);
    } else {
        assert!(false, "Wrong context type");
    }

    // Check thread 0, frame 3.
    let f3 = &state.threads[0].frames[3];
    let m2 = f3.module.as_ref().unwrap();
    assert_eq!(m2.code_file(), "C:\\WINDOWS\\system32\\kernel32.dll");
    assert_eq!(f3.trust, FrameTrust::FramePointer);
    assert_eq!(f3.context.get_instruction_pointer(), 0x7c816fd7);
    assert_eq!(f3.context.get_stack_pointer(), 0x0012ffc8);
    if let MinidumpContext { raw: MinidumpRawContext::X86(raw),
                             ref valid } = f3.context {
        assert_eq!(raw.eip, 0x7c816fd7);
        match valid {
            &MinidumpContextValidity::All => assert!(false, "Should not have all registers valid"),
            &MinidumpContextValidity::Some(ref which) => {
                assert!(which.contains("eip"));
                assert!(which.contains("esp"));
                assert!(which.contains("ebp"));
            }
        }
    } else {
        assert!(false, "Wrong context type");
    }

    // The dump thread should have been skipped.
    assert_eq!(state.threads[1].info, CallStackInfo::DumpThreadSkipped);
    assert_eq!(state.threads[1].frames.len(), 0);
}
