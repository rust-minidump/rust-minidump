// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use crate::process_state::*;
use crate::stackwalker::walk_stack;
use crate::{string_symbol_supplier, Symbolizer};
use minidump::format::CONTEXT_X86;
use minidump::*;
use std::collections::HashMap;
use test_assembler::*;

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

    pub fn walk_stack(&self, stack: Section) -> CallStack {
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
        walk_stack(
            &Some(&context),
            Some(&stack_memory),
            &self.modules,
            &symbolizer,
        )
    }

    pub fn add_symbols(&mut self, name: String, symbols: String) {
        self.symbols.insert(name, symbols);
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
        .append_repeated(12, 0) // frame 0: space
        .mark(&frame0_ebp) // frame 0 %ebp points here
        .D32(&frame1_ebp) // frame 0: saved %ebp
        .D32(0x40008679) // frame 0: return address
        .append_repeated(8, 0) // frame 1: space
        .mark(&frame1_ebp) // frame 1 %ebp points here
        .D32(0) // frame 1: saved %ebp (stack end)
        .D32(0); // frame 1: return address (stack end)
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
        assert_eq!(f1.instruction, 0x40008678);
        // eip
        // ebp
    }
}

// Walk a traditional frame, but use a bogus %ebp value, forcing a scan
// of the stack for something that looks like a return address.
#[test]
fn test_traditional_scan() {
    let mut f = TestFixture::new();
    let frame1_esp = Label::new();
    let frame1_ebp = Label::new();
    let mut stack = Section::new();
    let stack_start = 0x80000000;
    stack.start().set_const(stack_start);
    stack = stack
        // frame 0
        .D32(0xf065dc76) // locals area:
        .D32(0x46ee2167) // garbage that doesn't look like
        .D32(0xbab023ec) // a return address
        .D32(&frame1_ebp) // saved %ebp (%ebp fails to point here, forcing scan)
        .D32(0x4000129d) // return address
        // frame 1
        .mark(&frame1_esp)
        .append_repeated(8, 0) // space
        .mark(&frame1_ebp) // %ebp points here
        .D32(0) // saved %ebp (stack end)
        .D32(0); // return address (stack end)

    f.raw.eip = 0x4000f49d;
    f.raw.esp = stack.start().value().unwrap() as u32;
    // Make the frame pointer bogus, to make the stackwalker scan the stack
    // for something that looks like a return address.
    f.raw.ebp = 0xd43eed6e;

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 2);

    {
        // To avoid reusing locals by mistake
        let f0 = &s.frames[0];
        assert_eq!(f0.trust, FrameTrust::Context);
        assert_eq!(f0.context.valid, MinidumpContextValidity::All);
        assert_eq!(f0.instruction, 0x4000f49d);

        if let MinidumpRawContext::X86(ctx) = &f0.context.raw {
            assert_eq!(ctx.eip, 0x4000f49d);
            assert_eq!(ctx.esp, stack_start as u32);
            assert_eq!(ctx.ebp, 0xd43eed6e);
        } else {
            unreachable!();
        }
    }

    {
        // To avoid reusing locals by mistake
        let f1 = &s.frames[1];
        assert_eq!(f1.trust, FrameTrust::Scan);
        if let MinidumpContextValidity::Some(ref which) = f1.context.valid {
            assert!(which.contains("eip"));
            assert!(which.contains("esp"));
            assert!(which.contains("ebp"));
        } else {
            unreachable!();
        }
        assert_eq!(f1.instruction + 1, 0x4000129d);

        if let MinidumpRawContext::X86(ctx) = &f1.context.raw {
            assert_eq!(ctx.eip, 0x4000129d);
            assert_eq!(ctx.esp, frame1_esp.value().unwrap() as u32);
            assert_eq!(ctx.ebp, frame1_ebp.value().unwrap() as u32);
        } else {
            unreachable!();
        }
    }
}

// Force scanning for a return address a long way down the stack
#[test]
fn test_traditional_scan_long_way() {
    let mut f = TestFixture::new();
    let frame1_esp = Label::new();
    let frame1_ebp = Label::new();
    let mut stack = Section::new();
    let stack_start = 0x80000000;
    stack.start().set_const(stack_start);

    stack = stack
        // frame 0
        .D32(0xf065dc76) // locals area:
        .D32(0x46ee2167) // garbage that doesn't look like
        .D32(0xbab023ec) // a return address
        .append_repeated(20 * 4, 0) // a bunch of space
        .D32(&frame1_ebp) // saved %ebp (%ebp fails to point here, forcing scan)
        .D32(0x4000129d) // return address
        // frame 1
        .mark(&frame1_esp)
        .append_repeated(8, 0) // space
        .mark(&frame1_ebp) // %ebp points here
        .D32(0) // saved %ebp (stack end)
        .D32(0); // return address (stack end)

    f.raw.eip = 0x4000f49d;
    f.raw.esp = stack.start().value().unwrap() as u32;
    // Make the frame pointer bogus, to make the stackwalker scan the stack
    // for something that looks like a return address.
    f.raw.ebp = 0xd43eed6e;

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 2);

    {
        // To avoid reusing locals by mistake
        let f0 = &s.frames[0];
        assert_eq!(f0.trust, FrameTrust::Context);
        assert_eq!(f0.context.valid, MinidumpContextValidity::All);
        assert_eq!(f0.instruction, 0x4000f49d);

        if let MinidumpRawContext::X86(ctx) = &f0.context.raw {
            assert_eq!(ctx.eip, 0x4000f49d);
            assert_eq!(ctx.esp, stack_start as u32);
            assert_eq!(ctx.ebp, 0xd43eed6e);
        } else {
            unreachable!();
        }
    }

    {
        // To avoid reusing locals by mistake
        let f1 = &s.frames[1];
        assert_eq!(f1.trust, FrameTrust::Scan);
        if let MinidumpContextValidity::Some(ref which) = f1.context.valid {
            assert!(which.contains("eip"));
            assert!(which.contains("esp"));
            assert!(which.contains("ebp"));
        } else {
            unreachable!();
        }
        assert_eq!(f1.instruction + 1, 0x4000129d);

        if let MinidumpRawContext::X86(ctx) = &f1.context.raw {
            assert_eq!(ctx.eip, 0x4000129d);
            assert_eq!(ctx.esp, frame1_esp.value().unwrap() as u32);
            assert_eq!(ctx.ebp, frame1_ebp.value().unwrap() as u32);
        } else {
            unreachable!();
        }
    }
}

const CALLEE_SAVE_REGS: &[&str] = &["eip", "esp", "ebp", "ebx", "edi", "esi"];

fn init_cfi_state() -> (TestFixture, Section, CONTEXT_X86, MinidumpContextValidity) {
    let mut f = TestFixture::new();
    let symbols = [
        // The youngest frame's function.
        "FUNC 4000 1000 10 enchiridion\n",
        // Initially, just a return address.
        "STACK CFI INIT 4000 100 .cfa: $esp 4 + .ra: .cfa 4 - ^\n",
        // Push %ebx.
        "STACK CFI 4001 .cfa: $esp 8 + $ebx: .cfa 8 - ^\n",
        // Move %esi into %ebx.  Weird, but permitted.
        "STACK CFI 4002 $esi: $ebx\n",
        // Allocate frame space, and save %edi.
        "STACK CFI 4003 .cfa: $esp 20 + $edi: .cfa 16 - ^\n",
        // Put the return address in %edi.
        "STACK CFI 4005 .ra: $edi\n",
        // Save %ebp, and use it as a frame pointer.
        "STACK CFI 4006 .cfa: $ebp 8 + $ebp: .cfa 12 - ^\n",
        // The calling function.
        "FUNC 5000 1000 10 epictetus\n",
        // Mark it as end of stack.
        "STACK CFI INIT 5000 1000 .cfa: $esp .ra 0\n",
    ];
    f.add_symbols(String::from("module1"), symbols.concat());

    f.raw.set_register("esp", 0x80000000);
    f.raw.set_register("eip", 0x40005510);
    f.raw.set_register("ebp", 0xc0d4aab9);
    f.raw.set_register("ebx", 0x60f20ce6);
    f.raw.set_register("esi", 0x53d1379d);
    f.raw.set_register("edi", 0xafbae234);

    let raw_valid = MinidumpContextValidity::All;

    let expected = f.raw.clone();
    let expected_regs = CALLEE_SAVE_REGS;
    let expected_valid = MinidumpContextValidity::Some(expected_regs.iter().copied().collect());

    let stack = Section::new();
    stack
        .start()
        .set_const(f.raw.get_register("esp", &raw_valid).unwrap() as u64);

    (f, stack, expected, expected_valid)
}

fn check_cfi(
    f: TestFixture,
    stack: Section,
    expected: CONTEXT_X86,
    expected_valid: MinidumpContextValidity,
) {
    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 2);

    {
        // Frame 0
        let frame = &s.frames[0];
        assert_eq!(frame.trust, FrameTrust::Context);
        assert_eq!(frame.context.valid, MinidumpContextValidity::All);
    }

    {
        // Frame 1
        if let MinidumpContextValidity::Some(ref expected_regs) = expected_valid {
            let frame = &s.frames[1];
            let valid = &frame.context.valid;
            assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
            if let MinidumpContextValidity::Some(ref which) = valid {
                assert_eq!(which.len(), expected_regs.len());
            } else {
                unreachable!();
            }

            if let MinidumpRawContext::X86(ctx) = &frame.context.raw {
                for reg in expected_regs {
                    assert_eq!(
                        ctx.get_register(reg, valid),
                        expected.get_register(reg, &expected_valid),
                        "{} registers didn't match!",
                        reg
                    );
                }
                return;
            }
        }
    }
    unreachable!();
}

#[test]
fn test_cfi_at_4000() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_rsp = Label::new();
    stack = stack
        .D32(0x40005510) // return address
        .mark(&frame1_rsp)
        .append_repeated(0, 1000);

    expected.set_register("esp", frame1_rsp.value().unwrap() as u32);
    f.raw.set_register("eip", 0x40004000);

    check_cfi(f, stack, expected, expected_valid);
}

#[test]
fn test_cfi_at_4001() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_rsp = Label::new();
    stack = stack
        .D32(0x60f20ce6) // saved %ebx
        .D32(0x40005510) // return address
        .mark(&frame1_rsp)
        .append_repeated(0, 1000);

    expected.set_register("esp", frame1_rsp.value().unwrap() as u32);
    f.raw.set_register("eip", 0x40004001);
    f.raw.set_register("ebx", 0x91aa9a8b);

    check_cfi(f, stack, expected, expected_valid);
}

#[test]
fn test_cfi_at_4002() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_rsp = Label::new();
    stack = stack
        .D32(0x60f20ce6) // saved %ebx
        .D32(0x40005510) // return address
        .mark(&frame1_rsp)
        .append_repeated(0, 1000);

    expected.set_register("esp", frame1_rsp.value().unwrap() as u32);
    f.raw.set_register("eip", 0x40004002);
    f.raw.set_register("ebx", 0x53d1379d);
    f.raw.set_register("esi", 0xa5c790ed);

    check_cfi(f, stack, expected, expected_valid);
}

#[test]
fn test_cfi_at_4003() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_rsp = Label::new();
    stack = stack
        .D32(0x56ec3db7) // garbage
        .D32(0xafbae234) // saved %edi
        .D32(0x53d67131) // garbage
        .D32(0x60f20ce6) // saved %ebx
        .D32(0x40005510) // return address
        .mark(&frame1_rsp)
        .append_repeated(0, 1000);

    expected.set_register("esp", frame1_rsp.value().unwrap() as u32);
    f.raw.set_register("eip", 0x40004003);
    f.raw.set_register("ebx", 0x53d1379d);
    f.raw.set_register("esi", 0xa97f229d);
    f.raw.set_register("edi", 0xb05cc997);

    check_cfi(f, stack, expected, expected_valid);
}

#[test]
fn test_cfi_at_4004() {
    // Should be the same as 4003
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_rsp = Label::new();
    stack = stack
        .D32(0x56ec3db7) // garbage
        .D32(0xafbae234) // saved %edi
        .D32(0x53d67131) // garbage
        .D32(0x60f20ce6) // saved %ebx
        .D32(0x40005510) // return address
        .mark(&frame1_rsp)
        .append_repeated(0, 1000);

    expected.set_register("esp", frame1_rsp.value().unwrap() as u32);
    f.raw.set_register("eip", 0x40004004);
    f.raw.set_register("ebx", 0x53d1379d);
    f.raw.set_register("esi", 0xa97f229d);
    f.raw.set_register("edi", 0xb05cc997);

    check_cfi(f, stack, expected, expected_valid);
}

#[test]
fn test_cfi_at_4005() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_rsp = Label::new();
    stack = stack
        .D32(0xe29782c2) // garbage
        .D32(0xafbae234) // saved %edi
        .D32(0x5ba29ce9) // garbage
        .D32(0x60f20ce6) // saved %ebx
        .D32(0x8036cc02) // garbage
        .mark(&frame1_rsp)
        .append_repeated(0, 1000);

    expected.set_register("esp", frame1_rsp.value().unwrap() as u32);
    f.raw.set_register("eip", 0x40004005);
    f.raw.set_register("ebx", 0x53d1379d);
    f.raw.set_register("esi", 0x0fb7dc4e);
    f.raw.set_register("edi", 0x40005510);

    check_cfi(f, stack, expected, expected_valid);
}

#[test]
fn test_cfi_at_4006() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame0_ebp = Label::new();
    let frame1_rsp = Label::new();
    stack = stack
        .D32(0xdcdd25cd) // garbage
        .D32(0xafbae234) // saved %edi
        .D32(0xc0d4aab9) // saved %ebp
        .mark(&frame0_ebp) // frame pointer points here
        .D32(0x60f20ce6) // saved %ebx
        .D32(0x8036cc02) // garbage
        .mark(&frame1_rsp)
        .append_repeated(0, 1000);

    expected.set_register("esp", frame1_rsp.value().unwrap() as u32);
    f.raw
        .set_register("ebp", frame0_ebp.value().unwrap() as u32);
    f.raw.set_register("eip", 0x40004006);
    f.raw.set_register("ebx", 0x53d1379d);
    f.raw.set_register("esi", 0x743833c9);
    f.raw.set_register("edi", 0x40005510);

    check_cfi(f, stack, expected, expected_valid);
}
