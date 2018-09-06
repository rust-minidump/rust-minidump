// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

extern crate breakpad_symbols;
extern crate failure;
extern crate minidump;
extern crate minidump_processor;

use breakpad_symbols::{SimpleSymbolSupplier, Symbolizer};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use minidump::*;
use minidump::system_info::{CPU, OS};
use minidump_processor::{CallStackInfo, FrameTrust};

fn locate_testdata() -> PathBuf {
    // This is a little weird because while cargo will always build this code by running rustc
    // from the crate root, if you run `cargo test --all` from the workspace root, then the test
    // binary will be run from the crate root, so relative paths from `file!` won't work.
    let paths = &[
        // First, try relative to the current directory for if we're being run from the workspace.
        Path::new("testdata"),
        // If that doesn't work, try looking in the parent directory.
        Path::new("../testdata"),
    ];
    for path in paths {
        if path.is_dir() {
            return path.to_path_buf();
        }
    }

    panic!("Couldn't find testdata directory! Tried: {:?}", paths);
}

fn read_test_minidump() -> Result<Minidump<Cursor<Vec<u8>>>, failure::Error> {
    let path = locate_testdata().join("test.dmp");
    println!("minidump: {:?}", path);
    Minidump::read_path(&path)
}

fn testdata_symbol_path() -> PathBuf {
    let path = locate_testdata().join("symbols");
    println!("symbol path: {:?}", path);
    path
}

#[test]
fn test_processor() {
    let mut dump = read_test_minidump().unwrap();
    let state = minidump_processor::process_minidump(
        &mut dump,
        &Symbolizer::new(SimpleSymbolSupplier::new(vec![])),
    ).unwrap();
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
    if let MinidumpContext {
        raw: MinidumpRawContext::X86(ref raw),
        ref valid,
    } = f0.context
    {
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
    if let MinidumpContext {
        raw: MinidumpRawContext::X86(ref raw),
        ref valid,
    } = f3.context
    {
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

#[test]
fn test_processor_symbols() {
    let mut dump = read_test_minidump().unwrap();
    let path = testdata_symbol_path();
    println!("symbol path: {:?}", path);
    let state = minidump_processor::process_minidump(
        &mut dump,
        &Symbolizer::new(SimpleSymbolSupplier::new(vec![path])),
    ).unwrap();
    let f0 = &state.threads[0].frames[0];
    assert_eq!(
        f0.function_name.as_ref().map(|s| s.as_str()),
        Some("`anonymous namespace'::CrashFunction")
    );
}
