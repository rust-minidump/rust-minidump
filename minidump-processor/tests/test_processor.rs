// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use minidump::system_info::{Cpu, Os};
use minidump::{
    Error, Minidump, MinidumpContext, MinidumpContextValidity, MinidumpRawContext, Module,
};
use minidump_common::format::MemoryProtection;
use minidump_processor::{LinuxStandardBase, ProcessState};
use minidump_unwind::{simple_symbol_supplier, CallStackInfo, FrameTrust, Symbolizer};
use std::path::{Path, PathBuf};

use minidump_synth::*;
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

fn read_test_minidump() -> Result<Minidump<'static, memmap2::Mmap>, Error> {
    let path = locate_testdata().join("test.dmp");
    println!("minidump: {path:?}");
    Minidump::read_path(&path)
}

fn testdata_symbol_path() -> PathBuf {
    let path = locate_testdata().join("symbols");
    println!("symbol path: {path:?}");
    path
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
    assert_eq!(state.exception_info.unwrap().address.0, 0x45);
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
    println!("symbol path: {path:?}");
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
    let context = minidump_synth::x86_context(Endian::Little, 0xabcd1234, 0x1010);
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

#[tokio::test]
async fn test_no_frames() {
    let context = minidump_synth::x86_context(Endian::Little, 0, 0);

    let stack = Memory::with_section(Section::with_endian(Endian::Little), 0);

    let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
    let system_info = SystemInfo::new(Endian::Little);

    let mut ex = Exception::new(Endian::Little);
    ex.thread_id = 0x1234;

    let dump = SynthMinidump::with_endian(Endian::Little)
        .add_thread(thread)
        .add_exception(ex)
        .add_system_info(system_info)
        .add(context)
        .add_memory(stack);

    let mut state = read_synth_dump(dump).await;

    // I'm not sure if this is really a valid move in a test.
    // But I can't figure out *how* to get the frames to be clear in a valid dump.
    state.threads[0].frames.clear();

    state.print_json(&mut std::io::sink(), true).unwrap();
}

#[tokio::test]
async fn test_bit_flip() {
    let context = minidump_synth::amd64_context(Endian::Little, 0, 0);

    let stack = Memory::with_section(Section::with_endian(Endian::Little), 0);
    let heap_info = MemoryInfo::new(Endian::Little, 0x80000, 0x80000, 0, 8, 0, 0, 0);

    let thread = Thread::new(Endian::Little, 1, &stack, &context);
    let system_info = SystemInfo::new(Endian::Little).set_processor_architecture(
        minidump_common::format::ProcessorArchitecture::PROCESSOR_ARCHITECTURE_AMD64 as u16,
    );

    let mut ex = Exception::new(Endian::Little);
    ex.thread_id = 1;
    ex.exception_record.exception_address = 0x80400;

    let dump = SynthMinidump::with_endian(Endian::Little)
        .add_thread(thread)
        .add_exception(ex)
        .add_system_info(system_info)
        .add(context)
        .add_memory(stack)
        .add_memory_info(heap_info);

    let state = read_synth_dump(dump).await;

    let bit_flips = state
        .exception_info
        .expect("missing exception info")
        .possible_bit_flips;

    assert_eq!(bit_flips.len(), 1);
    let bf = bit_flips.into_iter().next().unwrap();
    assert_eq!(bf.address.0, 0x80000);
    assert_eq!(bf.details, Default::default());
}

#[tokio::test]
async fn test_no_bit_flip_32bit() {
    let context = minidump_synth::x86_context(Endian::Little, 0, 0);

    let stack = Memory::with_section(Section::with_endian(Endian::Little), 0);
    let heap_info = MemoryInfo::new(Endian::Little, 0x80000, 0x80000, 0, 8, 0, 0, 0);

    let thread = Thread::new(Endian::Little, 1, &stack, &context);
    let system_info = SystemInfo::new(Endian::Little);

    let mut ex = Exception::new(Endian::Little);
    ex.thread_id = 1;
    ex.exception_record.exception_address = 0x80400;

    let dump = SynthMinidump::with_endian(Endian::Little)
        .add_thread(thread)
        .add_exception(ex)
        .add_system_info(system_info)
        .add(context)
        .add_memory(stack)
        .add_memory_info(heap_info);

    let state = read_synth_dump(dump).await;

    assert!(state
        .exception_info
        .expect("missing exception info")
        .possible_bit_flips
        .is_empty());
}

#[tokio::test]
async fn test_guard_pages() {
    let context = minidump_synth::amd64_context(Endian::Little, 0x2000, 0x81000);

    // The bytes here are the opcode `mov al, [rsp]`. We use rsp only because it's convenient to
    // set using the `amd64_context` function.
    let memory = Memory::with_section(
        Section::with_endian(Endian::Little).append_bytes(&[0x8a, 0x04, 0x24]),
        0x2000,
    );
    let stack = Memory::with_section(Section::with_endian(Endian::Little), 0x1000);
    let heap_info = MemoryInfo::new(
        Endian::Little,
        0x80000,
        0x80000,
        0,
        4096,
        0,
        MemoryProtection::PAGE_EXECUTE_READWRITE.bits(),
        0,
    );
    let guard_page_info = MemoryInfo::new(
        Endian::Little,
        0x81000,
        0x81000,
        0,
        4096,
        0,
        MemoryProtection::PAGE_NOACCESS.bits(),
        0,
    );

    let thread = Thread::new(Endian::Little, 1, &stack, &context);
    let system_info = SystemInfo::new(Endian::Little).set_processor_architecture(
        minidump_common::format::ProcessorArchitecture::PROCESSOR_ARCHITECTURE_AMD64 as u16,
    );

    let context_label = context.file_offset();
    let context_size = context.file_size();

    let dump = SynthMinidump::with_endian(Endian::Little).add(context);

    let mut ex = Exception::new(Endian::Little);
    ex.thread_id = 1;
    ex.exception_record.exception_address = 0x81000;
    // Point the exception context at the main exception context.
    // This is (size, offset).
    ex.thread_context = (
        context_size.value().unwrap() as u32,
        context_label.value().unwrap() as u32,
    );

    let dump = dump
        .add_thread(thread)
        .add_exception(ex)
        .add_system_info(system_info)
        .add_memory(memory)
        .add_memory(stack)
        .add_memory_info(heap_info)
        .add_memory_info(guard_page_info);

    let state = read_synth_dump(dump).await;

    let accesses = state
        .exception_info
        .expect("missing exception info")
        .memory_accesses
        .expect("no memory accesses");

    assert_eq!(accesses.len(), 1);
    assert_eq!(accesses[0].address, 0x81000);
    assert!(accesses[0].is_likely_guard_page);
}
