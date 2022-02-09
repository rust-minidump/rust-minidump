// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use minidump::system_info::{Cpu, Os};
use minidump::{
    Error, Minidump, MinidumpContext, MinidumpContextValidity, MinidumpRawContext, Module,
};
use minidump_processor::{
    simple_symbol_supplier, CallStackInfo, FrameTrust, LinuxStandardBase, ProcessState, Symbolizer,
};
use std::path::{Path, PathBuf};

use synth_minidump::*;
use test_assembler::*;

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

fn read_macos_test_minidump() -> Result<Minidump<'static, memmap2::Mmap>, Error> {
    let path = locate_testdata().join("macos-mini.dmp");
    println!("minidump: {:?}", path);
    Minidump::read_path(&path)
}

fn read_linux_test_minidump() -> Result<Minidump<'static, memmap2::Mmap>, Error> {
    let path = locate_testdata().join("linux-mini.dmp");
    println!("minidump: {:?}", path);
    Minidump::read_path(&path)
}

fn read_windows_test_minidump() -> Result<Minidump<'static, memmap2::Mmap>, Error> {
    let path = locate_testdata().join("windows-mini.dmp");
    println!("minidump: {:?}", path);
    Minidump::read_path(&path)
}

fn read_test_minidump() -> Result<Minidump<'static, memmap2::Mmap>, Error> {
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
fn test_linux_minidump() {
    let dump = read_linux_test_minidump().unwrap();
    let state = minidump_processor::process_minidump(
        &dump,
        &Symbolizer::new(simple_symbol_supplier(vec![])),
    )
    .unwrap();
    let mut module_list = state.modules.iter();

    let module = module_list.next().unwrap();
    assert_eq!(
        module.debug_identifier().unwrap().into_owned(),
        "C0BCC3F19827FE653058404B2831D9E60",
        "debug identifier"
    );
    assert_eq!(
        module.code_identifier().into_owned(),
        "f1c3bcc0279865fe3058404b2831d9e64135386c",
        "code identifier"
    );

    let module = module_list.next().unwrap();
    assert_eq!(
        module.debug_identifier().unwrap().into_owned(),
        "E45DB8DFAF2D09FD640C8FE377D572DE0",
        "debug identifier"
    );
    assert_eq!(
        module.code_identifier().into_owned(),
        "dfb85de42daffd09640c8fe377d572de3e168920",
        "code identifier"
    );
}

#[test]
fn test_macos_minidump() {
    let dump = read_macos_test_minidump().unwrap();
    let state = minidump_processor::process_minidump(
        &dump,
        &Symbolizer::new(simple_symbol_supplier(vec![])),
    )
    .unwrap();
    let mut module_list = state.modules.iter();

    let module = module_list.next().unwrap();
    assert_eq!(
        module.debug_identifier().unwrap(),
        "67E9247C814E392BA027DBDE6748FCBF0",
        "debug identifier"
    );
    assert_eq!(
        module.code_identifier(),
        "67E9247C814E392BA027DBDE6748FCBF0",
        "code identifier"
    );

    let module = module_list.next().unwrap();
    assert_eq!(
        module.debug_identifier().unwrap(),
        "36385A3A60D332DBBF55C6D8931A7AA60",
        "debug identifier"
    );
    assert_eq!(
        module.code_identifier(),
        "36385A3A60D332DBBF55C6D8931A7AA60",
        "code identifier"
    );
}

#[test]
fn test_windows_minidump() {
    let dump = read_windows_test_minidump().unwrap();
    let state = minidump_processor::process_minidump(
        &dump,
        &Symbolizer::new(simple_symbol_supplier(vec![])),
    )
    .unwrap();
    let mut module_list = state.modules.iter();

    let module = module_list.next().unwrap();
    assert_eq!(
        module.debug_identifier().unwrap(),
        "3249D99D0C4049318610F4E4FB0B69361",
        "debug identifier"
    );
    assert_eq!(module.code_identifier(), "5AB380779000", "code identifier");

    let module = module_list.next().unwrap();
    assert_eq!(
        module.debug_identifier().unwrap(),
        "971F98E5CE6041FFB2D7235BBEB345781",
        "debug identifier"
    );
    assert_eq!(
        module.code_identifier(),
        "59B0D8F3183000",
        "code identifier"
    );
}

#[tokio::test]
async fn test_processor() {
    let dump = read_test_minidump().unwrap();
    let state = minidump_processor::process_minidump(
        &dump,
        &Symbolizer::new(simple_symbol_supplier(vec![])),
    )
    .await
    .unwrap();
    assert_eq!(state.system_info.os, Os::Windows);
    assert_eq!(state.system_info.os_version.unwrap(), "5.1.2600");
    assert_eq!(state.system_info.os_build.unwrap(), "Service Pack 2");
    assert_eq!(state.system_info.cpu, Cpu::X86);
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
        panic!("Wrong context type");
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
        match *valid {
            MinidumpContextValidity::All => panic!("Should not have all registers valid"),
            MinidumpContextValidity::Some(ref which) => {
                assert!(which.contains("eip"));
                assert!(which.contains("esp"));
                assert!(which.contains("ebp"));
            }
        }
    } else {
        panic!("Wrong context type");
    }

    // The dump thread should have been skipped.
    assert_eq!(state.threads[1].info, CallStackInfo::DumpThreadSkipped);
    assert_eq!(state.threads[1].frames.len(), 0);
}

#[tokio::test]
async fn test_processor_symbols() {
    let dump = read_test_minidump().unwrap();
    let path = testdata_symbol_path();
    println!("symbol path: {:?}", path);
    let state = minidump_processor::process_minidump(
        &dump,
        &Symbolizer::new(simple_symbol_supplier(vec![path])),
    )
    .await
    .unwrap();
    let f0 = &state.threads[0].frames[0];
    assert_eq!(
        f0.function_name.as_deref(),
        Some("`anonymous namespace'::CrashFunction")
    );
}

fn minimal_minidump() -> SynthMinidump {
    let context = synth_minidump::x86_context(Endian::Little, 0xabcd1234, 0x1010);
    let stack = Memory::with_section(
        Section::with_endian(Endian::Little).append_repeated(0, 0x1000),
        0x1000,
    );
    let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
    let system_info = SystemInfo::new(Endian::Little);
    SynthMinidump::with_endian(Endian::Little)
        .add_thread(thread)
        .add_system_info(system_info)
        .add(context)
        .add_memory(stack)
}

async fn read_synth_dump(dump: SynthMinidump) -> ProcessState {
    let dump = Minidump::read(dump.finish().unwrap()).unwrap();
    minidump_processor::process_minidump(&dump, &Symbolizer::new(simple_symbol_supplier(vec![])))
        .await
        .unwrap()
}

#[tokio::test]
async fn test_linux_cpu_info() {
    // Whitespace intentionally wonky to test robustness

    let input = b"
microcode : 0x1e34a6789
";

    let dump = minimal_minidump().set_linux_cpu_info(input);
    let state = read_synth_dump(dump).await;

    assert_eq!(state.system_info.cpu_microcode_version, Some(0x1e34a6789));
}

#[tokio::test]
async fn test_linux_lsb_release() {
    // Whitespace intentionally wonky to test robustness
    {
        let input = br#"
DISTRIB_ID="hello"
"DISTRIB_RELEASE"  =there
"DISTRIB_CODENAME" =   "very long string"
DISTRIB_DESCRIPTION= wow long string!!!
"#;
        let dump = minimal_minidump().set_linux_lsb_release(input);
        let state = read_synth_dump(dump).await;

        let LinuxStandardBase {
            id,
            release,
            codename,
            description,
        } = state.linux_standard_base.unwrap();

        assert_eq!(id, "hello");
        assert_eq!(release, "there");
        assert_eq!(codename, "very long string");
        assert_eq!(description, "wow long string!!!");
    }

    {
        let input = br#"
ID="hello"
"VERSION_ID"  =there
"VERSION_CODENAME" =   "very long string"
PRETTY_NAME= wow long string!!!
"#;
        let dump = minimal_minidump().set_linux_lsb_release(input);
        let state = read_synth_dump(dump).await;

        let LinuxStandardBase {
            id,
            release,
            codename,
            description,
        } = state.linux_standard_base.unwrap();

        assert_eq!(id, "hello");
        assert_eq!(release, "there");
        assert_eq!(codename, "very long string");
        assert_eq!(description, "wow long string!!!");
    }
}

#[tokio::test]
async fn test_linux_environ() {
    // Whitespace intentionally wonky to test robustness

    // TODO: add tests for values we care about
    let input = b"";

    let dump = minimal_minidump().set_linux_environ(input);
    let _state = read_synth_dump(dump).await;
}

#[tokio::test]
async fn test_linux_proc_status() {
    // Whitespace intentionally wonky to test robustness

    // TODO: add tests for values we care about
    let input = b"";

    let dump = minimal_minidump().set_linux_proc_status(input);
    let _state = read_synth_dump(dump).await;
}
