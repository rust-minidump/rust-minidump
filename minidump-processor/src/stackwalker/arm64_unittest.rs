// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

// NOTE: we don't bother testing arm64_old, it should have identical code at
// all times!

use crate::process_state::*;
use crate::stackwalker::walk_stack;
use breakpad_symbols::{StringSymbolSupplier, Symbolizer};
use minidump::*;
use test_assembler::*;

type Context = minidump::format::CONTEXT_ARM64;

struct TestFixture {
    pub raw: Context,
    pub modules: MinidumpModuleList,
    pub symbols: StringSymbolSupplier,
}

impl TestFixture {
    pub fn new() -> TestFixture {
        TestFixture {
            raw: Context::default(),
            // Give the two modules reasonable standard locations and names
            // for tests to play with.
            modules: MinidumpModuleList::from_modules(vec![
                MinidumpModule::new(0x40000000, 0x10000, "module1"),
                MinidumpModule::new(0x50000000, 0x10000, "module2"),
            ]),
            symbols: StringSymbolSupplier::new(),
        }
    }

    pub fn walk_stack(&self, stack: Section) -> CallStack {
        let context = MinidumpContext {
            raw: MinidumpRawContext::Arm64(self.raw.clone()),
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
        let symbolizer = Symbolizer::new(self.symbols.clone());
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

    pub fn init_cfi_state(&mut self) {
        let symbols = [
            // The youngest frame's function.
            "FUNC 4000 1000 10 enchiridion\n",
            // Initially, nothing has been pushed on the stack,
            // and the return address is still in the link
            // register (x30).
            "STACK CFI INIT 4000 100 .cfa: sp 0 + .ra: x30\n",
            // Push x19, x20, the frame pointer and the link register.
            "STACK CFI 4001 .cfa: sp 32 + .ra: .cfa -8 + ^",
            " x19: .cfa -32 + ^ x20: .cfa -24 + ^ ",
            " x29: .cfa -16 + ^\n",
            // Save x19..x22 in x0..x3: verify that we populate
            // the youngest frame with all the values we have.
            "STACK CFI 4002 x19: x0 x20: x1 x21: x2 x22: x3\n",
            // Restore x19..x22. Save the non-callee-saves register x1.
            "STACK CFI 4003 .cfa: sp 40 + x1: .cfa 40 - ^",
            " x19: x19 x20: x20 x21: x21 x22: x22\n",
            // Move the .cfa back eight bytes, to point at the return
            // address, and restore the sp explicitly.
            "STACK CFI 4005 .cfa: sp 32 + x1: .cfa 32 - ^",
            " x29: .cfa 8 - ^ .ra: .cfa ^ sp: .cfa 8 +\n",
            // Recover the PC explicitly from a new stack slot;
            // provide garbage for the .ra.
            "STACK CFI 4006 .cfa: sp 40 + pc: .cfa 40 - ^\n",
            // The calling function.
            "FUNC 5000 1000 10 epictetus\n",
            // Mark it as end of stack.
            "STACK CFI INIT 5000 1000 .cfa: 0 .ra: 0\n",
            // A function whose CFI makes the stack pointer
            // go backwards.
            "FUNC 6000 1000 20 palinal\n",
            "STACK CFI INIT 6000 1000 .cfa: sp 8 - .ra: x30\n",
            // A function with CFI expressions that can't be
            // evaluated.
            "FUNC 7000 1000 20 rhetorical\n",
            "STACK CFI INIT 7000 1000 .cfa: moot .ra: ambiguous\n",
        ];
        self.add_symbols(String::from("module1"), symbols.concat());

        self.raw.set_register("pc", 0x0000000040005510);
        self.raw.set_register("sp", 0x0000000080000000);
        self.raw.set_register("fp", 0xe11081128112e110);
        self.raw.set_register("x19", 0x5e68b5d5b5d55e68);
        self.raw.set_register("x20", 0x34f3ebd1ebd134f3);
        self.raw.set_register("x21", 0x74bca31ea31e74bc);
        self.raw.set_register("x22", 0x16b32dcb2dcb16b3);
        self.raw.set_register("x23", 0x21372ada2ada2137);
        self.raw.set_register("x24", 0x557dbbbbbbbb557d);
        self.raw.set_register("x25", 0x8ca748bf48bf8ca7);
        self.raw.set_register("x26", 0x21f0ab46ab4621f0);
        self.raw.set_register("x27", 0x146732b732b71467);
        self.raw.set_register("x28", 0xa673645fa673645f);
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

    let return_address1 = 0x50000100u64;
    let return_address2 = 0x50000900u64;
    let frame1_sp = Label::new();
    let frame2_sp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(0, 16) // space
        .D64(0x40090000) // junk that's not
        .D64(0x60000000) // a return address
        .D64(return_address1) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(0, 16) // space
        .D64(0xF0000000) // more junk
        .D64(0x0000000D)
        .D64(return_address2) // actual return address
        // frame 2
        .mark(&frame2_sp)
        .append_repeated(0, 64); // end of stack

    f.raw.set_register("pc", 0x40005510);
    f.raw.set_register("sp", stack.start().value().unwrap());

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

        if let MinidumpRawContext::Arm64(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame1_sp.value().unwrap()
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

        if let MinidumpRawContext::Arm64(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address2);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame2_sp.value().unwrap()
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

    let return_address1 = 0x50000100u64;
    let return_address2 = 0x50000900u64;
    let frame1_sp = Label::new();
    let frame2_sp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(0, 16) // space
        .D64(0x40090000) // junk that's not
        .D64(0x60000000) // a return address
        .append_repeated(0, 96) // more space
        .D64(return_address1) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(0, 32) // space
        .D64(0xF0000000) // more junk
        .D64(0x0000000D)
        .append_repeated(0, 336) // more space
        .D64(return_address2) // actual return address (won't be found)
        // frame 2
        .mark(&frame2_sp)
        .append_repeated(0, 64); // end of stack

    f.raw.set_register("pc", 0x40005510);
    f.raw.set_register("sp", stack.start().value().unwrap());

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

        if let MinidumpRawContext::Arm64(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame1_sp.value().unwrap()
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

    let return_address1 = 0x50000100u64;
    let return_address2 = 0x50000900u64;
    let frame1_sp = Label::new();
    let frame2_sp = Label::new();
    let frame1_fp = Label::new();
    let frame2_fp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(0, 64) // space
        .D64(0x0000000D) // junk that's not
        .D64(0xF0000000) // a return address
        .mark(&frame1_fp) // next fp will point to the next value
        .D64(&frame2_fp) // save current frame pointer
        .D64(return_address2) // save current link register
        .mark(&frame1_sp)
        // frame 1
        .append_repeated(0, 64) // space
        .D64(0x0000000D) // junk that's not
        .D64(0xF0000000) // a return address
        .mark(&frame2_fp)
        .D64(0)
        .D64(0)
        .mark(&frame2_sp)
        // frame 2
        .append_repeated(0, 64) // Whatever values on the stack.
        .D64(0x0000000D) // junk that's not
        .D64(0xF0000000); // a return address.

    f.raw.set_register("pc", 0x40005510);
    f.raw.set_register("lr", return_address1);
    f.raw.set_register("fp", frame1_fp.value().unwrap());
    f.raw.set_register("sp", stack.start().value().unwrap());

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

        if let MinidumpRawContext::Arm64(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(ctx.get_register("lr", valid).unwrap(), return_address2);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame1_sp.value().unwrap()
            );
            assert_eq!(
                ctx.get_register("fp", valid).unwrap(),
                frame2_fp.value().unwrap()
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

        if let MinidumpRawContext::Arm64(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address2);
            assert_eq!(ctx.get_register("lr", valid).unwrap(), 0);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame2_sp.value().unwrap()
            );
            assert_eq!(ctx.get_register("fp", valid).unwrap(), 0);
        } else {
            unreachable!();
        }
    }
}

// const CALLEE_SAVE_REGS: [&str; 13] = ["pc", "sp", "fp", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"];

#[test]
fn test_cfi_at_4000() {
    let mut f = TestFixture::new();
    f.init_cfi_state();
    let raw_valid = MinidumpContextValidity::All;

    let expected = f.raw.clone();
    let expected_regs = ["pc", "sp"];
    let expected_valid =
        MinidumpContextValidity::Some(std::array::IntoIter::new(expected_regs).collect());

    let mut stack = Section::new();
    stack = stack.append_repeated(0, 120);
    stack
        .start()
        .set_const(f.raw.get_register("sp", &raw_valid).unwrap());

    f.raw.set_register("pc", 0x0000000040004000);
    f.raw.set_register("lr", 0x0000000040005510);

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
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        if let MinidumpContextValidity::Some(ref which) = valid {
            assert_eq!(which.len(), expected_regs.len());
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Arm64(ctx) = &frame.context.raw {
            for reg in &expected_regs {
                assert_eq!(
                    ctx.get_register(reg, valid),
                    expected.get_register(reg, &expected_valid),
                    "{} registers didn't match!",
                    reg
                );
            }
        } else {
            unreachable!();
        }
    }
}
