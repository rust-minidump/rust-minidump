#![no_main]
use libfuzzer_sys::fuzz_target;

use minidump::format::CONTEXT_X86;
use minidump::{MinidumpContext, MinidumpContextValidity, MinidumpMemory, MinidumpRawContext};
use minidump::{MinidumpModule, MinidumpModuleList};
use minidump_processor::walk_stack;
use minidump_processor::{string_symbol_supplier, CallStack, Symbolizer};
use std::collections::HashMap;
use test_assembler::Section;

struct TestFixture {
    pub raw: CONTEXT_X86,
    pub modules: MinidumpModuleList,
    pub symbols: HashMap<String, String>,
}

impl TestFixture {
    pub fn new() -> TestFixture {
        TestFixture {
            raw: CONTEXT_X86::default(),
            // Give the two modules reasonable standard locations and names
            // for tests to play with.
            modules: MinidumpModuleList::from_modules(vec![
                MinidumpModule::new(0x40000000, 0x10000, "module1"),
                MinidumpModule::new(0x50000000, 0x10000, "module2"),
            ]),
            symbols: HashMap::new(),
        }
    }

    pub fn walk_stack(&self, stack: Section) -> Option<CallStack> {
        let context = MinidumpContext {
            raw: MinidumpRawContext::X86(self.raw.clone()),
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
        };

        let symbolizer = Symbolizer::new(string_symbol_supplier(self.symbols.clone()));

        Some(walk_stack(
            &Some(&context),
            Some(&stack_memory),
            &self.modules,
            &symbolizer,
        ))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);
    stack = stack.append_bytes(data);
    f.raw.eip = 0x40000200;
    f.raw.ebp = 0x80000000;
    f.walk_stack(stack);
});
