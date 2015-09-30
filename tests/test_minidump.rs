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
fn test_read_minidump() {
    read_test_minidump().unwrap();
}

#[test]
fn test_module_list() {
    let mut dump = read_test_minidump().unwrap();
    let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
    assert_eq!(module_list.module_at_address(0x400000).unwrap().code_file(),
               "c:\\test_app.exe");
    let modules = module_list.modules;
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

}

#[test]
fn test_system_info() {
    let mut dump = read_test_minidump().unwrap();
    let system_info = dump.get_stream::<MinidumpSystemInfo>().unwrap();
    assert_eq!(system_info.os.unwrap(), OS::Windows);
    assert_eq!(system_info.cpu.unwrap(), CPU::X86);
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
        if let &MinidumpContext { raw: MinidumpRawContext::X86(raw) } = ctx {
            assert_eq!(raw.eip, 0x7c90eb94);
        } else {
            assert!(false, "Wrong context type");
        }
    } else {
        assert!(false, "Missing context");
    }
}
