#![no_main]
use libfuzzer_sys::fuzz_target;

use minidump::system_info::{Cpu, Os};
use minidump::{MinidumpContext, MinidumpContextValidity, MinidumpMemory, UnifiedMemory};
use minidump::{MinidumpModule, MinidumpModuleList};
use minidump_unwind::{string_symbol_supplier, walk_stack, CallStack, Symbolizer, SystemInfo};
use std::collections::HashMap;
use test_assembler::Section;

struct TestFixture {
    pub raw: minidump::MinidumpRawContext,
    pub modules: MinidumpModuleList,
    pub symbols: HashMap<String, String>,
}

impl TestFixture {
    pub fn new(raw: minidump::MinidumpRawContext) -> TestFixture {
        TestFixture {
            raw,
            // Give the two modules reasonable standard locations and names
            // for tests to play with.
            modules: MinidumpModuleList::from_modules(vec![
                MinidumpModule::new(0x40000000, 0x10000, "module1"),
                MinidumpModule::new(0x50000000, 0x10000, "module2"),
            ]),
            symbols: HashMap::new(),
        }
    }

    pub async fn walk_stack(self, stack: Section) -> Option<CallStack> {
        let context = MinidumpContext {
            raw: self.raw,
            valid: MinidumpContextValidity::All,
        };

        let base = stack.start().value().unwrap();
        let size = stack.size();
        let stack = stack.get_contents().unwrap();
        let stack_memory = MinidumpMemory {
            desc: Default::default(),
            base_address: base,
            size,
            bytes: &stack,
            endian: minidump::Endian::Little,
        };
        let system_info = SystemInfo {
            os: Os::Windows,
            os_version: None,
            os_build: None,
            cpu: Cpu::X86_64,
            cpu_info: None,
            cpu_microcode_version: None,
            cpu_count: 1,
        };

        let symbolizer = Symbolizer::new(string_symbol_supplier(self.symbols.clone()));
        let mut stack = CallStack::with_context(context);

        walk_stack(
            (),
            &mut stack,
            Some(UnifiedMemory::Memory(&stack_memory)),
            &self.modules,
            &system_info,
            &symbolizer,
        )
        .await;

        Some(stack)
    }
}

fuzz_target!(|data: (&[u8], minidump::MinidumpRawContext)| {
    let f = TestFixture::new(data.1);
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);
    stack = stack.append_bytes(data.0);
    minidump_unwind_fuzz::fuzzing_block_on(f.walk_stack(stack));
});
