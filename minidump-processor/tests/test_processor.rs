// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use minidump::system_info::{Cpu, Os};
use minidump::{
    Error, Minidump, MinidumpContext, MinidumpContextValidity, MinidumpRawContext, MmapMinidump,
    Module,
};
use minidump_common::format::MemoryProtection;
use minidump_processor::{BitFlipDetails, Limit, LinuxStandardBase, PossibleBitFlip, ProcessState};
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

fn read_test_minidump() -> Result<MmapMinidump, Error> {
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

/// `mov rax, [rsp]`: an eight-byte read.
const MOV_RAX_RSP: &[u8] = &[0x48, 0x8b, 0x04, 0x24];

/// `mov al, [rsp]`: a one-byte read.
const MOV_AL_RSP: &[u8] = &[0x8a, 0x04, 0x24];

/// Where `Amd64Crash::code` is mapped, and so the value of rip.
const CODE_ADDRESS: u64 = 0x2000;

/// An entry of the memory info list.
struct Region {
    base: u64,
    size: u64,
    protection: MemoryProtection,
}

/// A single-threaded amd64 crash.
struct Amd64Crash<'a> {
    rsp: u64,
    instruction: &'a [u8],
    fault_address: u64,
    mapped_regions: &'a [Region],
}

/// Create a dump for a simple crash with a faulting address.
async fn amd64_fault_dump(crash: Amd64Crash<'_>) -> ProcessState {
    let context = minidump_synth::amd64_context(Endian::Little, CODE_ADDRESS, crash.rsp);
    let stack = Memory::with_section(Section::with_endian(Endian::Little), 0x1000);
    let thread = Thread::new(Endian::Little, 1, &stack, &context);

    // Adding the context to the dump is what resolves these labels.
    let context_size = context.file_size();
    let context_label = context.file_offset();
    let dump = SynthMinidump::with_endian(Endian::Little).add(context);

    let mut ex = Exception::new(Endian::Little);
    ex.thread_id = 1;
    ex.exception_record.exception_address = crash.fault_address;
    ex.thread_context = (
        context_size.value().unwrap() as u32,
        context_label.value().unwrap() as u32,
    );

    let mut dump = dump
        .add_thread(thread)
        .add_exception(ex)
        .add_system_info(SystemInfo::new(Endian::Little).set_processor_architecture(
            minidump_common::format::ProcessorArchitecture::PROCESSOR_ARCHITECTURE_AMD64 as u16,
        ))
        .add_memory(Memory::with_section(
            Section::with_endian(Endian::Little).append_bytes(crash.instruction),
            CODE_ADDRESS,
        ))
        .add_memory(stack);
    for region in crash.mapped_regions {
        dump = dump.add_memory_info(MemoryInfo::new(
            Endian::Little,
            region.base,
            region.base,
            /* allocation_protection */ 0,
            region.size,
            /* state */ 0,
            region.protection.bits(),
            /* ty */ 0,
        ));
    }
    read_synth_dump(dump).await
}

fn bit_flips(state: ProcessState) -> Vec<PossibleBitFlip> {
    state
        .exception_info
        .expect("missing exception info")
        .possible_bit_flips
}

const RWX: MemoryProtection = MemoryProtection::PAGE_EXECUTE_READWRITE;
const NO_ACCESS: MemoryProtection = MemoryProtection::PAGE_NOACCESS;

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
async fn test_linux_cpu_pid() {
    let input = b"
Pid:	3747
";

    let dump = minimal_minidump().set_linux_proc_status(input);
    let state = read_synth_dump(dump).await;

    assert_eq!(state.process_id, Some(3747));
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
async fn test_linux_proc_limits() {
    // Whitespace intentionally wonky to test robustness

    // TODO: add tests for values we care about
    let input = b"
Limit                     Soft Limit           Hard Limit           Units     
Max cpu time              unlimited            unlimited            seconds   
Max file size             unlimited            unlimited            bytes     
Max data size             unlimited            unlimited            bytes     
Max stack size            8388608              unlimited            bytes     
Max core file size        0                    unlimited            bytes     
Max resident set          unlimited            unlimited            bytes     
Max processes             111064               111064               processes 
Max open files            1048576              1048576              files     
Max locked memory         3653476352           3653476352           bytes     
Max address space         unlimited            unlimited            bytes     
Max file locks            unlimited            unlimited            locks     
Max pending signals       111064               111064               signals   
Max msgqueue size         819200               819200               bytes     
Max nice priority         0                    0                    
Max realtime priority     0                    0                    
Max realtime timeout      unlimited            unlimited            us        
";

    let dump = minimal_minidump().set_linux_proc_limits(input);
    let _state = read_synth_dump(dump).await;

    if let Some(limits) = _state.linux_proc_limits {
        let max_open_files = limits.limits["Max open files"].clone();
        assert_eq!(max_open_files.soft, Limit::Limited(1048576));
        assert_eq!(max_open_files.hard, Limit::Limited(1048576));
        assert_eq!(max_open_files.unit, "files");

        let max_stack_size = limits.limits["Max stack size"].clone();
        assert_eq!(max_stack_size.soft, Limit::Limited(8388608));
        assert_eq!(max_stack_size.hard, Limit::Unlimited);
        assert_eq!(max_stack_size.unit, "bytes");

        let max_nice_priority = limits.limits["Max nice priority"].clone();
        assert_eq!(max_nice_priority.soft, Limit::Limited(0));
        assert_eq!(max_nice_priority.hard, Limit::Limited(0));
        assert_eq!(max_nice_priority.unit, "n/a");

        let max_realtime_timeout = limits.limits["Max realtime timeout"].clone();
        assert_eq!(max_realtime_timeout.soft, Limit::Unlimited);
        assert_eq!(max_realtime_timeout.hard, Limit::Unlimited);
        assert_eq!(max_realtime_timeout.unit, "us");
    } else {
        panic!("No /proc/PID/limits")
    }
}

const SOFT_ERRORS_INPUT: &str = r#"[
    {"InitErrors": [
        {"StopProcessFailed": {"Stop": "EPERM"}}
    ]},
    {"SuspendThreadsErrors": [{"PtraceAttachError": [1234, "EPERM"]}]}
]"#;

#[tokio::test]
async fn test_soft_errors() {
    let dump = minimal_minidump().set_soft_errors(SOFT_ERRORS_INPUT);
    let state = read_synth_dump(dump).await;
    let soft_errors = state.soft_errors.expect("missing soft error stream");
    let arr = soft_errors.as_array().expect("expected array");
    let s = arr
        .first()
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("InitErrors"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("StopProcessFailed"))
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("Stop"))
        .and_then(|v| v.as_str())
        .expect("expected InitErrors.StopProcessFailed.Stop == EPERM");
    assert_eq!(s, "EPERM");
    let attach_error = arr
        .get(1)
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("SuspendThreadsErrors"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("PtraceAttachError"))
        .and_then(|v| v.as_array())
        .expect("expected SuspendThreadsErrors.PtraceAttachError is array");
    assert_eq!(attach_error[0].as_u64(), Some(1234));
    assert_eq!(attach_error[1].as_str(), Some("EPERM"));
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

    let bit_flips = bit_flips(state);

    assert_eq!(bit_flips.len(), 1);
    let bf = bit_flips.into_iter().next().unwrap();
    assert_eq!(bf.address.0, 0x80000);
    // The faulting address sits past the region, so its distance is recorded. The access size is
    // unknown here (no disassembly), so the off-by-one detractor stays inert and no other
    // heuristic fires.
    assert_eq!(
        bf.details,
        BitFlipDetails {
            distance_to_closest_mapping: Some(1017),
            ..Default::default()
        }
    );
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

    assert!(bit_flips(state).is_empty());
}

// Remove this once issue #863 is fixed.
#[tokio::test]
async fn test_bit_flip_arm64() {
    let context = minidump_synth::arm64_context(Endian::Little, 0, 0);

    let stack = Memory::with_section(Section::with_endian(Endian::Little), 0);

    let thread = Thread::new(Endian::Little, 1, &stack, &context);
    let system_info = SystemInfo::new(Endian::Little).set_processor_architecture(
        minidump_common::format::ProcessorArchitecture::PROCESSOR_ARCHITECTURE_ARM64 as u16,
    );

    let mut ex = Exception::new(Endian::Little);
    ex.thread_id = 1;
    ex.exception_record.exception_address = 0x400;

    let dump = SynthMinidump::with_endian(Endian::Little)
        .add_thread(thread)
        .add_exception(ex)
        .add_system_info(system_info)
        .add(context)
        .add_memory(stack);

    let state = read_synth_dump(dump).await;

    assert!(bit_flips(state).is_empty());
}

#[cfg_attr(not(feature = "disasm_amd64"), ignore = "requires disassembly")]
#[tokio::test]
async fn test_guard_pages() {
    let state = amd64_fault_dump(Amd64Crash {
        rsp: 0x81000,
        instruction: MOV_AL_RSP,
        fault_address: 0x81000,
        mapped_regions: &[
            Region {
                base: 0x80000,
                size: 4096,
                protection: RWX,
            },
            Region {
                base: 0x81000,
                size: 4096,
                protection: NO_ACCESS,
            },
        ],
    })
    .await;

    let exception_info = state.exception_info.expect("missing exception info");

    // The crashing address itself is in the guard page, and so is the access the instruction
    // performs through `rsp`.
    assert!(exception_info.fault_in_guard_page);

    let access_list = exception_info
        .memory_access_list
        .expect("no memory accesses");

    assert_eq!(access_list.accesses.len(), 1);
    assert_eq!(access_list.accesses[0].address_info.address, 0x81000);
    assert!(access_list.accesses[0].address_info.is_likely_guard_page);
}

// Test cross-page boundary access: base address is valid but access crosses into invalid page.
// With the new code that uses the actual access address from memory operations,
// bitflip detection correctly identifies this as a non-bitflip (boundary crossing) crash.
#[cfg_attr(
    not(feature = "disasm_amd64"),
    ignore = "requires disassembly for access size"
)]
#[tokio::test]
async fn test_no_bit_flip_cross_page_boundary() {
    // The access base 0xfff9 is valid; the eight-byte read crosses out of the region at 0x10000.
    let state = amd64_fault_dump(Amd64Crash {
        rsp: 0xfff9,
        instruction: MOV_RAX_RSP,
        fault_address: 0x10000,
        mapped_regions: &[Region {
            base: 0x0,
            size: 0x10000,
            protection: RWX,
        }],
    })
    .await;

    // No bitflips should be detected because the access address (0xfff9) is valid. The segfault is
    // from crossing a page boundary, not a bitflip.
    assert!(
        bit_flips(state).is_empty(),
        "expected no bit flips for valid access address crossing page boundary"
    );
}

// Test an obvious off-by-one: the faulting access lands just past the end of a valid mapping,
// closer than the size of the access itself. It should not produce any possible bitflip.
#[cfg_attr(
    not(feature = "disasm_amd64"),
    ignore = "requires disassembly for access size"
)]
#[tokio::test]
async fn test_no_bit_flip_obvious_off_by_one() {
    // The region's inclusive end is 0x8ffff, so the access at 0x90001 is only two bytes past the
    // mapping, well within the eight-byte access size.
    let state = amd64_fault_dump(Amd64Crash {
        rsp: 0x90001,
        instruction: MOV_RAX_RSP,
        fault_address: 0x90001,
        mapped_regions: &[Region {
            base: 0x80000,
            size: 0x10000,
            protection: RWX,
        }],
    })
    .await;

    assert!(bit_flips(state).is_empty());
}

// A crash that lands a few access-widths past the end of an allocation looks more like an
// off-by-one than a bit flip, so the bit-flip confidence is reduced (towards zero) the closer the
// fault is to the allocation, measured in units of the access size.
#[cfg_attr(
    not(feature = "disasm_amd64"),
    ignore = "requires disassembly for access size"
)]
#[tokio::test]
async fn test_bit_flip_off_by_one_detractor() {
    // rsp sits 65 bytes (a bit over eight 8-byte elements) past the end of the region, and a single
    // flipped bit (bit 16) corrects it back into it (0x90040 ^ 0x10000 == 0x80040).
    let state = amd64_fault_dump(Amd64Crash {
        rsp: 0x90040,
        instruction: MOV_RAX_RSP,
        fault_address: 0x90040,
        mapped_regions: &[Region {
            base: 0x80000,
            size: 0x10000,
            protection: RWX,
        }],
    })
    .await;
    let bit_flips = bit_flips(state);

    assert!(!bit_flips.is_empty());
    let corrected = bit_flips
        .iter()
        .find(|bf| bf.address.0 == 0x80040)
        .expect("expected a bit-flip candidate correcting to 0x80040");
    assert_eq!(corrected.details.memory_access_size, Some(8));
    // 0x90040 - 0x8ffff == 65 bytes past the end of the heap region.
    assert_eq!(corrected.details.distance_to_closest_mapping, Some(65));

    // The off-by-one detractor reduces the baseline confidence following a square-root falloff,
    // with the distance measured in access-size units ("elements"):
    // baseline (0.25) * sqrt((elements - 1) / (OFF_BY_ONE_ELEMENTS - 1)), elements = distance/size.
    let expected = 0.25_f32 * ((65.0_f32 / 8.0 - 1.0) / (64.0 - 1.0)).sqrt();
    let confidence = corrected.confidence.expect("missing confidence");
    assert!(confidence > 0.0, "confidence should be reduced but nonzero");
    assert!(
        confidence < 0.25,
        "confidence {} should be below the baseline",
        confidence
    );
    assert!(
        (confidence - expected).abs() < 1e-5,
        "confidence {} != expected {}",
        confidence,
        expected
    );
}
