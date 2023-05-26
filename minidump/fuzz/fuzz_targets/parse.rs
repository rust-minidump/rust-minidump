#![no_main]
use libfuzzer_sys::fuzz_target;

use minidump::{
    MinidumpAssertion, MinidumpBreakpadInfo, MinidumpCrashpadInfo, MinidumpException,
    MinidumpLinuxCpuInfo, MinidumpLinuxEnviron, MinidumpLinuxLsbRelease, MinidumpLinuxMaps,
    MinidumpLinuxProcStatus, MinidumpMacCrashInfo, MinidumpMacBootargs, MinidumpMemory64List,
    MinidumpMemoryInfoList, MinidumpMemoryList, MinidumpMiscInfo, MinidumpModuleList,
    MinidumpSystemInfo, MinidumpThreadList, MinidumpThreadNames, MinidumpUnloadedModuleList,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(dump) = minidump::Minidump::read(data) {
        let _ = dump.get_stream::<MinidumpAssertion>();
        let _ = dump.get_stream::<MinidumpBreakpadInfo>();
        let _ = dump.get_stream::<MinidumpCrashpadInfo>();
        let _ = dump.get_stream::<MinidumpException>();
        let _ = dump.get_stream::<MinidumpLinuxCpuInfo>();
        let _ = dump.get_stream::<MinidumpLinuxEnviron>();
        let _ = dump.get_stream::<MinidumpLinuxLsbRelease>();
        let _ = dump.get_stream::<MinidumpLinuxMaps>();
        let _ = dump.get_stream::<MinidumpLinuxProcStatus>();
        let _ = dump.get_stream::<MinidumpMacCrashInfo>();
        let _ = dump.get_stream::<MinidumpMacBootargs>();
        let _ = dump.get_stream::<MinidumpMemory64List>();
        let _ = dump.get_stream::<MinidumpMemoryInfoList>();
        let _ = dump.get_stream::<MinidumpMemoryList>();
        let _ = dump.get_stream::<MinidumpMiscInfo>();
        let _ = dump.get_stream::<MinidumpModuleList>();
        let _ = dump.get_stream::<MinidumpSystemInfo>();
        let _ = dump.get_stream::<MinidumpThreadNames>();
        let _ = dump.get_stream::<MinidumpThreadList>();
        let _ = dump.get_stream::<MinidumpUnloadedModuleList>();
    }
});
