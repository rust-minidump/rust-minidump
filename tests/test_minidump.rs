// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

extern crate minidump;
extern crate minidump_common;
extern crate chrono;

use chrono::*;
use std::fs::File;
use std::path::PathBuf;
use minidump::*;
use minidump::system_info::{OS, CPU};
use minidump_common::traits::Module;

fn get_test_minidump_path() -> PathBuf {
    let mut path = PathBuf::from(file!());
    path.pop();
    path.pop();
    path.push("testdata/test.dmp");
    path
}

fn read_test_minidump() -> Result<Minidump, Error> {
    let path = get_test_minidump_path();
    Minidump::read_path(&path)
}

#[test]
fn test_minidump_read_path() {
    read_test_minidump().unwrap();
}

#[test]
fn test_minidump_read() {
    let path = get_test_minidump_path();
    let f = File::open(path).unwrap();
    let _dump = Minidump::read(f).unwrap();
}

#[test]
fn test_module_list() {
    let mut dump = read_test_minidump().unwrap();
    let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
    assert_eq!(module_list.module_at_address(0x400000).unwrap().code_file(),
               "c:\\test_app.exe");
    let modules = module_list.iter().collect::<Vec<_>>();
    let module_files = modules.iter().map(|m| m.code_file()).collect::<Vec<_>>();
    assert_eq!(modules.len(), 13);
    assert_eq!(modules[0].base_address(), 0x400000);
    assert_eq!(modules[0].size(), 0x2d000);
    assert_eq!(modules[0].code_file(), "c:\\test_app.exe");
    assert_eq!(modules[0].code_identifier(), "45D35F6C2d000");
    assert_eq!(modules[0].debug_file().unwrap(), "c:\\test_app.pdb");
    assert_eq!(modules[0].debug_identifier().unwrap(),
               "5A9832E5287241C1838ED98914E9B7FF1");
    assert!(modules[0].version().is_none());

    assert_eq!(modules[12].base_address(), 0x76bf0000);
    assert_eq!(modules[12].size(), 0xb000);
    assert_eq!(modules[12].code_file(), "C:\\WINDOWS\\system32\\psapi.dll");
    assert_eq!(modules[12].code_identifier(), "411096CAb000");
    assert_eq!(modules[12].debug_file().unwrap(), "psapi.pdb");
    assert_eq!(modules[12].debug_identifier().unwrap(),
               "A5C3A1F9689F43D8AD228A09293889702");
    assert_eq!(modules[12].version().unwrap(), "5.1.2600.2180");

    assert_eq!(module_files,
               vec![
                   r"c:\test_app.exe",
                   r"C:\WINDOWS\system32\ntdll.dll",
                   r"C:\WINDOWS\system32\kernel32.dll",
                   r"C:\WINDOWS\system32\ole32.dll",
                   r"C:\WINDOWS\system32\advapi32.dll",
                   r"C:\WINDOWS\system32\rpcrt4.dll",
                   r"C:\WINDOWS\system32\gdi32.dll",
                   r"C:\WINDOWS\system32\user32.dll",
                   r"C:\WINDOWS\system32\msvcrt.dll",
                   r"C:\WINDOWS\system32\imm32.dll",
                   r"C:\WINDOWS\system32\dbghelp.dll",
                   r"C:\WINDOWS\system32\version.dll",
                   r"C:\WINDOWS\system32\psapi.dll",
                   ]);

    assert_eq!(module_list.by_addr().map(|m| m.code_file()).collect::<Vec<_>>(),
               vec![
                   r"c:\test_app.exe",
                   r"C:\WINDOWS\system32\dbghelp.dll",
                   r"C:\WINDOWS\system32\imm32.dll",
                   r"C:\WINDOWS\system32\psapi.dll",
                   r"C:\WINDOWS\system32\ole32.dll",
                   r"C:\WINDOWS\system32\version.dll",
                   r"C:\WINDOWS\system32\msvcrt.dll",
                   r"C:\WINDOWS\system32\user32.dll",
                   r"C:\WINDOWS\system32\advapi32.dll",
                   r"C:\WINDOWS\system32\rpcrt4.dll",
                   r"C:\WINDOWS\system32\gdi32.dll",
                   r"C:\WINDOWS\system32\kernel32.dll",
                   r"C:\WINDOWS\system32\ntdll.dll",
                   ]);
}

#[test]
fn test_system_info() {
    let mut dump = read_test_minidump().unwrap();
    let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
    assert_eq!(system_info.os, OS::Windows);
    assert_eq!(system_info.cpu, CPU::X86);
}

#[test]
fn test_misc_info() {
    let mut dump = read_test_minidump().unwrap();
    let misc_info = dump.get_stream::<MinidumpMiscInfo>().unwrap();
    assert_eq!(misc_info.raw.process_id, 3932);
    assert_eq!(misc_info.raw.process_create_time, 0x45d35f73);
    assert_eq!(misc_info.process_create_time.unwrap(),
               UTC.ymd(2007, 02, 14).and_hms(19, 13, 55));
}

#[test]
fn test_breakpad_info() {
    let mut dump = read_test_minidump().unwrap();
    let breakpad_info = dump.get_stream::<MinidumpBreakpadInfo>().unwrap();
    assert_eq!(breakpad_info.dump_thread_id.unwrap(), 0x11c0);
    assert_eq!(breakpad_info.requesting_thread_id.unwrap(), 0xbf4);
}

#[test]
fn test_exception() {
    let mut dump = read_test_minidump().unwrap();
    let exception = dump.get_stream::<MinidumpException>().unwrap();
    assert_eq!(exception.thread_id, 0xbf4);
    assert_eq!(exception.raw.exception_record.exception_code,
               0xc0000005);
    if let Some(ref ctx) = exception.context {
        assert_eq!(ctx.get_instruction_pointer(), 0x40429e);
        assert_eq!(ctx.get_stack_pointer(), 0x12fe84);
        if let &MinidumpContext { raw: MinidumpRawContext::X86(raw),
                                  ref valid} = ctx {
            assert_eq!(raw.eip, 0x40429e);
            assert_eq!(*valid, MinidumpContextValidity::All);
        } else {
            assert!(false, "Wrong context type");
        }
    } else {
        assert!(false, "Missing context");
    }
}

#[test]
fn test_thread_list() {
    let mut dump = read_test_minidump().unwrap();
    let thread_list = dump.get_stream::<MinidumpThreadList>().unwrap();
    let ref threads = thread_list.threads;
    assert_eq!(threads.len(), 2);
    assert_eq!(threads[0].raw.thread_id, 0xbf4);
    assert_eq!(threads[1].raw.thread_id, 0x11c0);
    let id = threads[1].raw.thread_id;
    assert_eq!(thread_list.get_thread(id).unwrap().raw.thread_id, id);
    if let Some(ref ctx) = threads[0].context {
        assert_eq!(ctx.get_instruction_pointer(), 0x7c90eb94);
        assert_eq!(ctx.get_stack_pointer(), 0x12f320);
        if let &MinidumpContext { raw: MinidumpRawContext::X86(raw),
                                  ref valid } = ctx {
            assert_eq!(raw.eip, 0x7c90eb94);
            assert_eq!(*valid, MinidumpContextValidity::All);
        } else {
            assert!(false, "Wrong context type");
        }
    } else {
        assert!(false, "Missing context");
    }
    if let Some(ref stack) = threads[0].stack {
        // Try the beginning
        assert_eq!(stack.get_memory_at_address::<u8>(0x12f31c).unwrap(), 0);
        assert_eq!(stack.get_memory_at_address::<u16>(0x12f31c).unwrap(), 0);
        assert_eq!(stack.get_memory_at_address::<u32>(0x12f31c).unwrap(), 0);
        assert_eq!(stack.get_memory_at_address::<u64>(0x12f31c).unwrap(),
                   0x7c90e9c000000000);
        // And the end
        assert_eq!(stack.get_memory_at_address::<u8>(0x12ffff).unwrap(), 0);
        assert_eq!(stack.get_memory_at_address::<u16>(0x12fffe).unwrap(), 0);
        assert_eq!(stack.get_memory_at_address::<u32>(0x12fffc).unwrap(), 0);
        assert_eq!(stack.get_memory_at_address::<u64>(0x12fff8).unwrap(),
                   0x405443);
    } else {
        assert!(false, "Missing stack memory");
    }
}
