// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

// NOTE: we don't bother testing arm64_old, it should have identical code at
// all times!

use crate::process_state::*;
use crate::stackwalker::walk_stack;
use breakpad_symbols::{SimpleSymbolSupplier, Symbolizer};
use minidump::format::CONTEXT_ARM;
use minidump::*;
use test_assembler::*;

struct TestFixture {
    pub raw: CONTEXT_ARM,
    pub modules: MinidumpModuleList,
    pub symbolizer: Symbolizer,
}

impl TestFixture {
    pub fn new() -> TestFixture {
        TestFixture {
            raw: CONTEXT_ARM::default(),
            // Give the two modules reasonable standard locations and names
            // for tests to play with.
            modules: MinidumpModuleList::from_modules(vec![
                MinidumpModule::new(0x40000000, 0x10000, "module1"),
                MinidumpModule::new(0x50000000, 0x10000, "module2"),
            ]),
            symbolizer: Symbolizer::new(SimpleSymbolSupplier::new(vec![])),
        }
    }

    pub fn walk_stack(&self, stack: Section) -> CallStack {
        let context = MinidumpContext {
            raw: MinidumpRawContext::Arm(self.raw.clone()),
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
        walk_stack(
            &Some(&context),
            Some(&stack_memory),
            &self.modules,
            &self.symbolizer,
        )
    }
}

#[test]
fn test_simple() {
    let mut f = TestFixture::new();
    let stack = Section::new();
    stack.start().set_const(0x80000000);
    // There should be no references to the stack in this walk: we don't
    // provide any call frame information, so trying to reconstruct the
    // context frame's caller should fail. So there's no need for us to
    // provide stack contents.
    f.raw.set_register("pc", 0x4000c020);
    f.raw.set_register("fp", 0x80000000);

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 1);
    let f = &s.frames[0];
    let m = f.module.as_ref().unwrap();
    assert_eq!(m.code_file(), "module1");
}

#[test]
fn test_scan_without_symbols() {
    // Scanning should work without any symbols
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let return_address1 = 0x50000100u32;
    let return_address2 = 0x50000900u32;
    let frame1_sp = Label::new();
    let frame2_sp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(0, 16) // space
        .D32(0x40090000) // junk that's not
        .D32(0x60000000) // a return address
        .D32(return_address1) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(0, 16) // space
        .D32(0xF0000000) // more junk
        .D32(0x0000000D)
        .D32(return_address2) // actual return address
        // frame 2
        .mark(&frame2_sp)
        .append_repeated(0, 32); // end of stack

    f.raw.set_register("pc", 0x40005510);
    f.raw
        .set_register("sp", stack.start().value().unwrap() as u32);

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 3);

    {
        // Frame 0
        let frame = &s.frames[0];
        assert_eq!(frame.trust, FrameTrust::Context);
        assert_eq!(frame.context.valid, MinidumpContextValidity::All);
    }

    {
        // Frame 1
        let frame = &s.frames[1];
        let valid = &frame.context.valid;
        assert_eq!(frame.trust, FrameTrust::Scan);
        if let MinidumpContextValidity::Some(ref which) = valid {
            assert_eq!(which.len(), 2);
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Arm(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame1_sp.value().unwrap() as u32
            );
        } else {
            unreachable!();
        }
    }

    {
        // Frame 2
        let frame = &s.frames[2];
        let valid = &frame.context.valid;
        assert_eq!(frame.trust, FrameTrust::Scan);
        if let MinidumpContextValidity::Some(ref which) = valid {
            assert_eq!(which.len(), 2);
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Arm(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address2);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame2_sp.value().unwrap() as u32
            );
        } else {
            unreachable!();
        }
    }
}

#[test]
fn test_scan_first_frame() {
    // The first (context) frame gets extra long scans, this test checks that.
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let return_address1 = 0x50000100u32;
    let return_address2 = 0x50000900u32;
    let frame1_sp = Label::new();
    let frame2_sp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(0, 16) // space
        .D32(0x40090000) // junk that's not
        .D32(0x60000000) // a return address
        .append_repeated(0, 96) // more space
        .D32(return_address1) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(0, 32) // space
        .D32(0xF0000000) // more junk
        .D32(0x0000000D)
        .append_repeated(0, 336) // more space
        .D32(return_address2) // actual return address (won't be found)
        // frame 2
        .mark(&frame2_sp)
        .append_repeated(0, 64); // end of stack

    f.raw.set_register("pc", 0x40005510);
    f.raw
        .set_register("sp", stack.start().value().unwrap() as u32);

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
        let frame = &s.frames[1];
        let valid = &frame.context.valid;
        assert_eq!(frame.trust, FrameTrust::Scan);
        if let MinidumpContextValidity::Some(ref which) = valid {
            assert_eq!(which.len(), 2);
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Arm(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame1_sp.value().unwrap() as u32
            );
        } else {
            unreachable!();
        }
    }
}

#[test]
fn test_frame_pointer() {
    // Frame-pointer-based unwinding
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let return_address1 = 0x50000100u32;
    let return_address2 = 0x50000900u32;
    let frame1_sp = Label::new();
    let frame2_sp = Label::new();
    let frame1_fp = Label::new();
    let frame2_fp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(0, 32) // space
        .D32(0x0000000D) // junk that's not
        .D32(0xF0000000) // a return address
        .mark(&frame1_fp) // next fp will point to the next value
        .D32(&frame2_fp) // save current frame pointer
        .D32(return_address2) // save current link register
        .mark(&frame1_sp)
        // frame 1
        .append_repeated(0, 32) // space
        .D32(0x0000000D) // junk that's not
        .D32(0xF0000000) // a return address
        .mark(&frame2_fp)
        .D32(0)
        .D32(0)
        .mark(&frame2_sp)
        // frame 2
        .append_repeated(0, 32) // Whatever values on the stack.
        .D32(0x0000000D) // junk that's not
        .D32(0xF0000000); // a return address.

    f.raw.set_register("pc", 0x40005510);
    f.raw.set_register("lr", return_address1);
    f.raw.set_register("fp", frame1_fp.value().unwrap() as u32);
    f.raw
        .set_register("sp", stack.start().value().unwrap() as u32);

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 3);

    {
        // Frame 0
        let frame = &s.frames[0];
        assert_eq!(frame.trust, FrameTrust::Context);
        assert_eq!(frame.context.valid, MinidumpContextValidity::All);
    }

    {
        // Frame 1
        let frame = &s.frames[1];
        let valid = &frame.context.valid;
        assert_eq!(frame.trust, FrameTrust::FramePointer);
        if let MinidumpContextValidity::Some(ref which) = valid {
            assert_eq!(which.len(), 4);
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Arm(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(ctx.get_register("lr", valid).unwrap(), return_address2);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame1_sp.value().unwrap() as u32
            );
            assert_eq!(
                ctx.get_register("fp", valid).unwrap(),
                frame2_fp.value().unwrap() as u32
            );
        } else {
            unreachable!();
        }
    }

    {
        // Frame 2
        let frame = &s.frames[2];
        let valid = &frame.context.valid;
        assert_eq!(frame.trust, FrameTrust::FramePointer);
        if let MinidumpContextValidity::Some(ref which) = valid {
            assert_eq!(which.len(), 4);
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Arm(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address2);
            assert_eq!(ctx.get_register("lr", valid).unwrap(), 0);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame2_sp.value().unwrap() as u32
            );
            assert_eq!(ctx.get_register("fp", valid).unwrap(), 0);
        } else {
            unreachable!();
        }
    }
}
