#![cfg(test)]

use minidump::*;
use minidump_format::MDRawContextX86;
use process_state::*;
use stackwalker::walk_stack;
use test_assembler::*;

struct TestFixture {
    pub raw: MDRawContextX86,
    pub modules: MinidumpModuleList,
}

impl TestFixture {
    pub fn new() -> TestFixture {
        TestFixture {
            raw: MDRawContextX86::default(),
            // Give the two modules reasonable standard locations and names
            // for tests to play with.
            modules: MinidumpModuleList::from_modules(
                vec![
                    MinidumpModule::new(0x40000000, 0x10000, "module1"),
                    MinidumpModule::new(0x50000000, 0x10000, "module2"),
                    ]
                ),
        }
    }

    pub fn walk_stack(&self, stack : Section) -> CallStack {
        let context = MinidumpContext {
            raw: MinidumpRawContext::X86(self.raw),
            valid: MinidumpContextValidity::All,
        };
        let base = stack.start().value().unwrap();
        let size = stack.size();
        let stack_memory = MinidumpMemory {
            base_address: base,
            size: size,
            bytes: stack.get_contents().unwrap(),
        };
        walk_stack(&Some(&context), &Some(stack_memory), &self.modules)
    }
}

#[test]
fn test_simple() {
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);
    stack = stack.D32(0).D32(0); // end-of-stack marker
    f.raw.eip = 0x40000200;
    f.raw.ebp = 0x80000000;
    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 1);
    let f = &s.frames[0];
    let m = f.module.as_ref().unwrap();
    assert_eq!(m.code_file(), "module1");
}

// Walk a traditional frame. A traditional frame saves the caller's
// %ebp just below the return address, and has its own %ebp pointing
// at the saved %ebp.
#[test]
fn test_traditional() {
    let mut f = TestFixture::new();
    let frame0_ebp = Label::new();
    let frame1_ebp = Label::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);
    stack = stack
        .append_repeated(12, 0)         // frame 0: space
        .mark(&frame0_ebp)              // frame 0 %ebp points here
        .D32(&frame1_ebp)               // frame 0: saved %ebp
        .D32(0x40008679)                // frame 0: return address
        .append_repeated(8, 0)          // frame 1: space
        .mark(&frame1_ebp)              // frame 1 %ebp points here
        .D32(0)                         // frame 1: saved %ebp (stack end)
        .D32(0);                        // frame 1: return address (stack end)
    f.raw.eip = 0x4000c7a5;
    f.raw.esp = stack.start().value().unwrap() as u32;
    f.raw.ebp = frame0_ebp.value().unwrap() as u32;
    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 2);
    {
        let f0 = &s.frames[0];
        assert_eq!(f0.trust, FrameTrust::Context);
        assert_eq!(f0.context.valid, MinidumpContextValidity::All);
        assert_eq!(f0.instruction, 0x4000c7a5);
        // eip
        // ebp
    }
    {
        let f1 = &s.frames[1];
        assert_eq!(f1.trust, FrameTrust::FramePointer);
        // ContextValidity
        //FIXME: should be +1!
        assert_eq!(f1.instruction, 0x40008679);
        // eip
        // ebp
    }
}
