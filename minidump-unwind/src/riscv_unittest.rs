use crate::*;
use minidump::system_info::{Cpu, Os};
use std::collections::HashMap;
use test_assembler::*;

type Context = minidump::format::CONTEXT_RISCV;
type Context64 = minidump::format::CONTEXT_RISCV64;

struct TestFixture {
    pub raw: Context,
    pub valid: MinidumpContextValidity,
    pub modules: MinidumpModuleList,
    pub symbols: HashMap<String, String>,
}

impl TestFixture {
    pub fn new() -> TestFixture {
        TestFixture {
            raw: Context::default(),
            valid: MinidumpContextValidity::All,
            // Give the two modules reasonable standard locations and names
            // for tests to play with.
            modules: MinidumpModuleList::from_modules(vec![
                MinidumpModule::new(0x40000000, 0x10000, "module1"),
                MinidumpModule::new(0x50000000, 0x10000, "module2"),
            ]),
            symbols: HashMap::new(),
        }
    }

    pub async fn walk_stack(&self, stack: Section) -> CallStack {
        let context = MinidumpContext {
            raw: MinidumpRawContext::Riscv(self.raw.clone()),
            valid: self.valid.clone(),
        };
        let base = stack.start().value().unwrap();
        let size = stack.size();
        let stack = stack.get_contents().unwrap();
        let stack_memory = MinidumpMemory {
            desc: Default::default(),
            base_address: base,
            size,
            bytes: &stack,
            endian: scroll::LE,
        };
        let system_info = SystemInfo {
            os: Os::Linux,
            os_version: None,
            os_build: None,
            cpu: Cpu::Riscv,
            cpu_info: None,
            cpu_microcode_version: None,
            cpu_count: 1,
        };
        let symbolizer = Symbolizer::new(string_symbol_supplier(self.symbols.clone()));
        let mut stack = CallStack::with_context(context);

        walk_stack(
            0,
            (),
            &mut stack,
            Some(UnifiedMemory::Memory(&stack_memory)),
            &self.modules,
            &system_info,
            &symbolizer,
        )
        .await;

        stack
    }

    pub fn add_symbols(&mut self, name: String, symbols: String) {
        self.symbols.insert(name, symbols);
    }
}

#[tokio::test]
async fn test_simple() {
    let mut f = TestFixture::new();
    let stack = Section::new();
    stack.start().set_const(0x80000000);
    // There should be no references to the stack in this walk: we don't
    // provide any call frame information, so trying to reconstruct the
    // context frame's caller should fail. So there's no need for us to
    // provide stack contents.
    f.raw.set_register("pc", 0x4000c020);
    f.raw.set_register("ra", 0x4000c01a);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 1);
    let f = &s.frames[0];
    let m = f.module.as_ref().unwrap();
    assert_eq!(m.code_file(), "module1");
}

#[tokio::test]
async fn test_scan_without_symbols() {
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
        .append_repeated(0, 8) // space
        .D32(0x40090000) // junk that's not
        .D32(0x60000000) // a return address
        .D32(return_address1) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(0, 8) // space
        .D32(0xF0000000) // more junk
        .D32(0x0000000D)
        .D32(return_address2) // actual return address
        // frame 2
        .mark(&frame2_sp)
        .append_repeated(0, 32); // end of stack

    f.raw.set_register("pc", 0x4000c020);
    f.raw
        .set_register("sp", stack.start().value().unwrap() as u32);

    let s = f.walk_stack(stack).await;
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

        if let MinidumpRawContext::Riscv(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(
                u64::from(ctx.get_register("sp", valid).unwrap()),
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

        if let MinidumpRawContext::Riscv(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address2);
            assert_eq!(
                u64::from(ctx.get_register("sp", valid).unwrap()),
                frame2_sp.value().unwrap()
            );
        } else {
            unreachable!();
        }
    }
}

#[tokio::test]
async fn test_scan_with_symbols() {
    // Test that we can refine our scanning using symbols. Specifically we
    // should be able to reject pointers that are in modules but don't map to
    // any code.
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let return_address = 0x50000200u32;
    let frame1_sp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(0, 8) // space
        .D32(0x40090000) // junk that's not
        .D32(0x60000000) // a return address
        .D32(0x40001000) // a couple of plausible addresses
        .D32(0x5000F000) // that are not within functions
        .D32(return_address) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(0, 32); // end of stack

    f.raw.set_register("pc", 0x40000200);
    f.raw
        .set_register("sp", stack.start().value().unwrap() as u32);

    f.add_symbols(
        String::from("module1"),
        // The youngest frame's function.
        String::from("FUNC 100 400 10 monotreme\n"),
    );
    f.add_symbols(
        String::from("module2"),
        // The calling frame's function.
        String::from("FUNC 100 400 10 marsupial\n"),
    );

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 2);

    {
        // Frame 0
        let frame = &s.frames[0];
        assert_eq!(frame.trust, FrameTrust::Context);
        assert_eq!(frame.context.valid, MinidumpContextValidity::All);
        assert_eq!(frame.function_name.as_deref(), Some("monotreme"));
        assert_eq!(frame.function_base, Some(0x40000100));
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

        if let MinidumpRawContext::Riscv(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address);
            assert_eq!(
                u64::from(ctx.get_register("sp", valid).unwrap()),
                frame1_sp.value().unwrap()
            );
        } else {
            unreachable!();
        }
        assert_eq!(frame.function_name.as_deref(), Some("marsupial"));
        assert_eq!(frame.function_base, Some(0x50000100));
    }
}

#[tokio::test]
async fn test_scan_first_frame() {
    // The first (context) frame gets extra long scans, this test checks that.
    // The second return address is beyond the default scan window of the
    // scan-recovered frame, so it must not be found.
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
        .append_repeated(0, 48) // more space
        .D32(return_address1) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(0, 16) // space
        .D32(0xF0000000) // more junk
        .D32(0x0000000D)
        .append_repeated(0, 168) // more space
        .D32(return_address2) // actual return address (won't be found)
        // frame 2
        .mark(&frame2_sp)
        .append_repeated(0, 32); // end of stack

    f.raw.set_register("pc", 0x4000c020);
    f.raw
        .set_register("sp", stack.start().value().unwrap() as u32);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 2);

    {
        // Frame 0
        let frame = &s.frames[0];
        assert_eq!(frame.trust, FrameTrust::Context);
    }

    {
        // Frame 1
        let frame = &s.frames[1];
        let valid = &frame.context.valid;
        assert_eq!(frame.trust, FrameTrust::Scan);
        if let MinidumpRawContext::Riscv(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), return_address1);
            assert_eq!(
                u64::from(ctx.get_register("sp", valid).unwrap()),
                frame1_sp.value().unwrap()
            );
        } else {
            unreachable!();
        }
    }
}

const CALLEE_SAVE_REGS: &[&str] = &[
    "pc", "sp", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
];

fn init_cfi_state() -> (TestFixture, Section, Context, MinidumpContextValidity) {
    let mut f = TestFixture::new();
    let symbols = [
        // The youngest frame's function.
        "FUNC 4000 1000 10 enchiridion\n",
        // Initially, nothing has been pushed on the stack,
        // and the return address is still in the return
        // address register (ra).
        "STACK CFI INIT 4000 100 .cfa: sp 0 + .ra: ra\n",
        // Push s1, s2, the frame pointer (s0) and the
        // return address register.
        "STACK CFI 4001 .cfa: sp 16 + .ra: .cfa -4 + ^",
        " s1: .cfa -16 + ^ s2: .cfa -12 + ^ ",
        " s0: .cfa -8 + ^\n",
        // Save s1..s4 in a1..a4: verify that we populate
        // the youngest frame with all the values we have.
        "STACK CFI 4002 s1: a1 s2: a2 s3: a3 s4: a4\n",
        // Restore s1..s4. Save the non-callee-saves register a2.
        "STACK CFI 4003 .cfa: sp 20 + a2: .cfa 20 - ^",
        " s1: s1 s2: s2 s3: s3 s4: s4\n",
        // Move the .cfa back four bytes, to point at the return
        // address, and restore the sp explicitly.
        "STACK CFI 4005 .cfa: sp 16 + a2: .cfa 16 - ^",
        " s0: .cfa 4 - ^ .ra: .cfa ^ sp: .cfa 4 +\n",
        // Recover the PC explicitly from a new stack slot;
        // provide garbage for the .ra.
        "STACK CFI 4006 .cfa: sp 20 + pc: .cfa 20 - ^\n",
        // The calling function.
        "FUNC 5000 1000 10 epictetus\n",
        // Mark it as end of stack.
        "STACK CFI INIT 5000 1000 .cfa: 0 .ra: 0\n",
        // A function whose CFI makes the stack pointer
        // go backwards.
        "FUNC 6000 1000 20 palinal\n",
        "STACK CFI INIT 6000 1000 .cfa: sp 4 - .ra: ra\n",
        // A function with CFI expressions that can't be
        // evaluated.
        "FUNC 7000 1000 20 rhetorical\n",
        "STACK CFI INIT 7000 1000 .cfa: moot .ra: ambiguous\n",
    ];
    f.add_symbols(String::from("module1"), symbols.concat());

    // The caller's expected register values; by default the youngest
    // frame carries them too, and each test overrides what it needs.
    f.raw.set_register("pc", 0x40005510);
    f.raw.set_register("sp", 0x80000000);
    f.raw.set_register("ra", 0x40005510);
    f.raw.set_register("s0", 0x8112e110);
    f.raw.set_register("s1", 0xb5d55e68);
    f.raw.set_register("s2", 0xebd134f3);
    f.raw.set_register("s3", 0xa31e74bc);
    f.raw.set_register("s4", 0x2dcb16b3);
    f.raw.set_register("s5", 0x2ada2137);
    f.raw.set_register("s6", 0xbbbb557d);
    f.raw.set_register("s7", 0x48bf8ca7);
    f.raw.set_register("s8", 0xab4621f0);
    f.raw.set_register("s9", 0x32b71467);
    f.raw.set_register("s10", 0xa673645f);
    f.raw.set_register("s11", 0xa673645f);

    let raw_valid = MinidumpContextValidity::All;

    let expected = f.raw.clone();
    let expected_regs = CALLEE_SAVE_REGS;
    let expected_valid = MinidumpContextValidity::Some(expected_regs.iter().copied().collect());

    let stack = Section::new();
    stack
        .start()
        .set_const(u64::from(f.raw.get_register("sp", &raw_valid).unwrap()));

    (f, stack, expected, expected_valid)
}

async fn check_cfi(
    f: TestFixture,
    stack: Section,
    expected: Context,
    expected_valid: MinidumpContextValidity,
) {
    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 2);

    {
        // Frame 0
        let frame = &s.frames[0];
        assert_eq!(frame.trust, FrameTrust::Context);
        assert_eq!(frame.context.valid, f.valid);
        assert_eq!(frame.function_name.as_deref(), Some("enchiridion"));
        assert_eq!(frame.function_base, Some(0x40004000));
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

            // The caller's instruction is its return address stepped back
            // onto the call (see the compressed-call test).
            assert_eq!(
                frame.instruction,
                u64::from(expected.get_register("pc", &expected_valid).unwrap()).wrapping_sub(2)
            );
            assert_eq!(frame.function_name.as_deref(), Some("epictetus"));

            if let MinidumpRawContext::Riscv(ctx) = &frame.context.raw {
                for reg in expected_regs {
                    assert_eq!(
                        ctx.get_register(reg, valid),
                        expected.get_register(reg, &expected_valid),
                        "{reg} registers didn't match!"
                    );
                }
                return;
            } else {
                unreachable!()
            }
        }
    }
    unreachable!();
}

#[tokio::test]
async fn test_cfi_at_4000() {
    let (mut f, mut stack, expected, expected_valid) = init_cfi_state();

    stack = stack.append_repeated(0, 120);

    f.raw.set_register("pc", 0x40004000);
    f.raw.set_register("ra", 0x40005510);

    check_cfi(f, stack, expected, expected_valid).await;
}

#[tokio::test]
async fn test_cfi_at_4001() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_sp = Label::new();
    stack = stack
        .D32(0xb5d55e68) // saved s1
        .D32(0xebd134f3) // saved s2
        .D32(0x8112e110) // saved s0
        .D32(0x40005510) // return address
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    expected.set_register("sp", frame1_sp.value().unwrap() as u32);
    f.raw.set_register("pc", 0x40004001);
    // distinct callee s1, s2 and s0
    f.raw.set_register("s1", 0xa635adc9);
    f.raw.set_register("s2", 0x35ac6231);
    f.raw.set_register("s0", 0xbe145fc4);

    check_cfi(f, stack, expected, expected_valid).await;
}

// As above, but unwind from a context that has only the PC and SP.
#[tokio::test]
async fn test_cfi_at_4001_limited_validity() {
    let (mut f, mut stack, mut expected, _) = init_cfi_state();

    let frame1_sp = Label::new();
    stack = stack
        .D32(0xb5d55e68) // saved s1
        .D32(0xebd134f3) // saved s2
        .D32(0x8112e110) // saved s0
        .D32(0x40005510) // return address
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    f.valid = MinidumpContextValidity::Some(["pc", "sp"].iter().copied().collect());
    f.raw.set_register("pc", 0x40004001);
    f.raw.set_register("s0", 0xbe145fc4);

    // Only the registers the CFI rules recover are valid in the caller:
    // everything else was invalid in the callee, so nothing forwards.
    expected.set_register("sp", frame1_sp.value().unwrap() as u32);
    let expected_valid =
        MinidumpContextValidity::Some(["pc", "sp", "s0", "s1", "s2"].iter().copied().collect());

    check_cfi(f, stack, expected, expected_valid).await;
}

#[tokio::test]
async fn test_cfi_at_4002() {
    let (mut f, mut stack, mut expected, expected_valid) = init_cfi_state();

    let frame1_sp = Label::new();
    stack = stack
        .D32(0xfb81ff3d) // no longer saved s1
        .D32(0xebd134f3) // no longer saved s2
        .D32(0x8112e110) // saved s0
        .D32(0x40005510) // return address
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    expected.set_register("sp", frame1_sp.value().unwrap() as u32);
    f.raw.set_register("pc", 0x40004002);
    f.raw.set_register("a1", 0xb5d55e68); // saved a1
    f.raw.set_register("a2", 0xebd134f3); // saved a2
    f.raw.set_register("a3", 0xa31e74bc); // saved a3
    f.raw.set_register("a4", 0x2dcb16b3); // saved a4
    f.raw.set_register("s1", 0xa635adc9); // distinct callee s1
    f.raw.set_register("s2", 0x35ac6231); // distinct callee s2
    f.raw.set_register("s3", 0x4356ac45); // distinct callee s3
    f.raw.set_register("s4", 0x562f2561); // distinct callee s4
    f.raw.set_register("s0", 0xbe145fc4); // distinct callee s0

    check_cfi(f, stack, expected, expected_valid).await;
}

#[tokio::test]
async fn test_cfi_at_4003() {
    let (mut f, mut stack, mut expected, mut expected_valid) = init_cfi_state();

    let frame1_sp = Label::new();
    stack = stack
        .D32(0x48c8dd5a) // saved a2 (even though it's not callee-saves)
        .D32(0xfb81ff3d) // no longer saved s1
        .D32(0xebd134f3) // no longer saved s2
        .D32(0x8112e110) // saved s0
        .D32(0x40005510) // return address
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    expected.set_register("sp", frame1_sp.value().unwrap() as u32);
    f.raw.set_register("pc", 0x40004003);
    f.raw.set_register("a2", 0xfb756319); // distinct callee a2
    f.raw.set_register("s0", 0xbe145fc4); // distinct callee s0
    expected.set_register("a2", 0x48c8dd5a); // caller's a2
    if let MinidumpContextValidity::Some(ref mut which) = expected_valid {
        which.insert("a2");
    }

    check_cfi(f, stack, expected, expected_valid).await;
}

// We have no new rule at module offset 0x4004, so the results here should
// be the same as those at module offset 0x4003.
#[tokio::test]
async fn test_cfi_at_4004() {
    let (mut f, mut stack, mut expected, mut expected_valid) = init_cfi_state();

    let frame1_sp = Label::new();
    stack = stack
        .D32(0x48c8dd5a) // saved a2 (even though it's not callee-saves)
        .D32(0xfb81ff3d) // no longer saved s1
        .D32(0xebd134f3) // no longer saved s2
        .D32(0x8112e110) // saved s0
        .D32(0x40005510) // return address
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    expected.set_register("sp", frame1_sp.value().unwrap() as u32);
    f.raw.set_register("pc", 0x40004004);
    f.raw.set_register("a2", 0xfb756319); // distinct callee a2
    f.raw.set_register("s0", 0xbe145fc4); // distinct callee s0
    expected.set_register("a2", 0x48c8dd5a); // caller's a2
    if let MinidumpContextValidity::Some(ref mut which) = expected_valid {
        which.insert("a2");
    }

    check_cfi(f, stack, expected, expected_valid).await;
}

// Here we move the .cfa, but provide an explicit rule to recover the SP,
// so again there should be no change in the registers recovered.
#[tokio::test]
async fn test_cfi_at_4005() {
    let (mut f, mut stack, mut expected, mut expected_valid) = init_cfi_state();

    let frame1_sp = Label::new();
    stack = stack
        .D32(0x48c8dd5a) // saved a2 (even though it's not callee-saves)
        .D32(0xfb81ff3d) // no longer saved s1
        .D32(0xebd134f3) // no longer saved s2
        .D32(0x8112e110) // saved s0
        .D32(0x40005510) // return address
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    expected.set_register("sp", frame1_sp.value().unwrap() as u32);
    f.raw.set_register("pc", 0x40004005);
    f.raw.set_register("a2", 0xfb756319); // distinct callee a2
    expected.set_register("a2", 0x48c8dd5a); // caller's a2
    if let MinidumpContextValidity::Some(ref mut which) = expected_valid {
        which.insert("a2");
    }

    check_cfi(f, stack, expected, expected_valid).await;
}

// Here we provide an explicit rule for the PC, and have the saved .ra be
// bogus.
#[tokio::test]
async fn test_cfi_at_4006() {
    let (mut f, mut stack, mut expected, mut expected_valid) = init_cfi_state();

    let frame1_sp = Label::new();
    stack = stack
        .D32(0x40005510) // saved pc
        .D32(0x48c8dd5a) // saved a2 (even though it's not callee-saves)
        .D32(0xfb81ff3d) // no longer saved s1
        .D32(0xebd134f3) // no longer saved s2
        .D32(0x8112e110) // saved s0
        .D32(0x5783f8d1) // .ra rule recovers this, which is garbage
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    expected.set_register("sp", frame1_sp.value().unwrap() as u32);
    f.raw.set_register("pc", 0x40004006);
    f.raw.set_register("a2", 0xfb756319); // distinct callee a2
    expected.set_register("a2", 0x48c8dd5a); // caller's a2
    if let MinidumpContextValidity::Some(ref mut which) = expected_valid {
        which.insert("a2");
    }

    check_cfi(f, stack, expected, expected_valid).await;
}

// A return address two bytes past a compressed call must look up its CFI
// rows at the call site: stepping back four bytes (as breakpad's original
// RISC-V walkers did, assuming a uniform 4-byte encoding) would land on
// the poison row that starts this function and end the walk early.
#[tokio::test]
async fn test_cfi_compressed_call() {
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let symbols = [
        // The youngest frame's function: nothing pushed, the return
        // address is still in ra.
        "FUNC 4000 1000 10 trapped\n",
        "STACK CFI INIT 4000 100 .cfa: sp 0 + .ra: ra\n",
        // The calling function. A 2-byte compressed call (`c.jal` on
        // RV32) sits at offset 0x5002, so a return address of 0x5004
        // must select the rows from 0x5002 on. The initial rules
        // covering [0x5000, 0x5002) are poison.
        "FUNC 5000 1000 10 caller\n",
        "STACK CFI INIT 5000 1000 .cfa: 0 .ra: 0\n",
        "STACK CFI 5002 .cfa: sp 8 + .ra: .cfa -4 + ^ s0: .cfa -8 + ^\n",
        // The caller's caller.
        "FUNC 6000 1000 10 outer\n",
        "STACK CFI INIT 6000 1000 .cfa: 0 .ra: 0\n",
    ];
    f.add_symbols(String::from("module1"), symbols.concat());

    // The youngest frame's ra points just past the 2-byte call.
    f.raw.set_register("pc", 0x40004000);
    f.raw.set_register("sp", 0x80000000);
    f.raw.set_register("ra", 0x40005004);

    let frame2_sp = Label::new();
    stack = stack
        .D32(0x22ab9f19) // saved s0
        .D32(0x40006010) // return address of `caller` (into `outer`)
        .mark(&frame2_sp)
        .append_repeated(0, 120);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 3);

    {
        // Frame 1: the caller. Its instruction must land on the 2-byte
        // call at 0x5002, not 4 bytes before it (where the poison row
        // would end the walk).
        let frame = &s.frames[1];
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        assert_eq!(frame.instruction, 0x40005002);
        assert_eq!(frame.function_name.as_deref(), Some("caller"));
    }

    {
        // Frame 2: recovered through the row the call site selected.
        let frame = &s.frames[2];
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        let valid = &frame.context.valid;
        if let MinidumpRawContext::Riscv(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), 0x40006010);
            assert_eq!(
                u64::from(ctx.get_register("sp", valid).unwrap()),
                frame2_sp.value().unwrap()
            );
            assert_eq!(ctx.get_register("s0", valid).unwrap(), 0x22ab9f19);
        } else {
            unreachable!();
        }
        assert_eq!(frame.function_name.as_deref(), Some("outer"));
    }
}

// A bare-metal image can be linked at 0: a softcore whose RAM starts
// there has its whole text below the first page boundary, so the
// null-page heuristic must not cut a walk whose frames live in it.
// Every code address in this walk is under 4096, and the walk still
// has to run to its natural end.
#[tokio::test]
async fn test_cfi_module_at_zero() {
    let mut f = TestFixture::new();
    f.modules =
        MinidumpModuleList::from_modules(vec![MinidumpModule::new(0x0, 0x10000, "lowmodule")]);
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let symbols = [
        // The youngest frame's function: nothing pushed, the return
        // address is still in ra.
        "FUNC 10 80 10 trapped\n",
        "STACK CFI INIT 10 80 .cfa: sp 0 + .ra: ra\n",
        // The calling function. A 2-byte compressed call sits at
        // offset 0x102, so a return address of 0x104 must select the
        // rows from 0x102 on. The initial rules covering [0x100,
        // 0x102) are poison.
        "FUNC 100 100 10 caller\n",
        "STACK CFI INIT 100 100 .cfa: 0 .ra: 0\n",
        "STACK CFI 102 .cfa: sp 8 + .ra: .cfa -4 + ^ s0: .cfa -8 + ^\n",
        // The caller's caller. Its poison rows recover a null pc, and
        // null is null even inside a module at 0, so the walk ends.
        "FUNC 200 100 10 outer\n",
        "STACK CFI INIT 200 100 .cfa: 0 .ra: 0\n",
    ];
    f.add_symbols(String::from("lowmodule"), symbols.concat());

    // The youngest frame's ra points just past the 2-byte call.
    f.raw.set_register("pc", 0x10);
    f.raw.set_register("sp", 0x80000000);
    f.raw.set_register("ra", 0x104);

    let frame2_sp = Label::new();
    stack = stack
        .D32(0x22ab9f19) // saved s0
        .D32(0x210) // return address of `caller` (into `outer`)
        .mark(&frame2_sp)
        .append_repeated(0, 120);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 3);

    {
        // Frame 1: the caller. Its address is below 4096 but inside
        // the module, so it is code, not null.
        let frame = &s.frames[1];
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        assert_eq!(frame.instruction, 0x102);
        assert_eq!(frame.function_name.as_deref(), Some("caller"));
    }

    {
        // Frame 2: recovered through the low-address rows.
        let frame = &s.frames[2];
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        let valid = &frame.context.valid;
        if let MinidumpRawContext::Riscv(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), 0x210);
            assert_eq!(
                u64::from(ctx.get_register("sp", valid).unwrap()),
                frame2_sp.value().unwrap()
            );
            assert_eq!(ctx.get_register("s0", valid).unwrap(), 0x22ab9f19);
        } else {
            unreachable!();
        }
        assert_eq!(frame.function_name.as_deref(), Some("outer"));
    }
}

// Check that we reject rules that would cause the stack pointer to
// move in the wrong direction.
#[tokio::test]
async fn test_cfi_reject_backwards() {
    let (mut f, stack, _expected, _expected_valid) = init_cfi_state();

    f.raw.set_register("pc", 0x40006000);
    f.raw.set_register("sp", 0x80000000);
    f.raw.set_register("ra", 0x40005510);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 1);
}

// Check that we reject rules whose expressions' evaluation fails.
#[tokio::test]
async fn test_cfi_reject_bad_expressions() {
    let (mut f, stack, _expected, _expected_valid) = init_cfi_state();

    f.raw.set_register("pc", 0x40007000);
    f.raw.set_register("sp", 0x80000000);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 1);
}

struct TestFixture64 {
    pub raw: Context64,
    pub valid: MinidumpContextValidity,
    pub modules: MinidumpModuleList,
    pub symbols: HashMap<String, String>,
}

impl TestFixture64 {
    pub fn new() -> TestFixture64 {
        TestFixture64 {
            raw: Context64::default(),
            valid: MinidumpContextValidity::All,
            modules: MinidumpModuleList::from_modules(vec![
                MinidumpModule::new(0x40000000, 0x10000, "module1"),
                MinidumpModule::new(0x50000000, 0x10000, "module2"),
            ]),
            symbols: HashMap::new(),
        }
    }

    pub async fn walk_stack(&self, stack: Section) -> CallStack {
        let context = MinidumpContext {
            raw: MinidumpRawContext::Riscv64(self.raw.clone()),
            valid: self.valid.clone(),
        };
        let base = stack.start().value().unwrap();
        let size = stack.size();
        let stack = stack.get_contents().unwrap();
        let stack_memory = MinidumpMemory {
            desc: Default::default(),
            base_address: base,
            size,
            bytes: &stack,
            endian: scroll::LE,
        };
        let system_info = SystemInfo {
            os: Os::Linux,
            os_version: None,
            os_build: None,
            cpu: Cpu::Riscv64,
            cpu_info: None,
            cpu_microcode_version: None,
            cpu_count: 1,
        };
        let symbolizer = Symbolizer::new(string_symbol_supplier(self.symbols.clone()));
        let mut stack = CallStack::with_context(context);

        walk_stack(
            0,
            (),
            &mut stack,
            Some(UnifiedMemory::Memory(&stack_memory)),
            &self.modules,
            &system_info,
            &symbolizer,
        )
        .await;

        stack
    }

    pub fn add_symbols(&mut self, name: String, symbols: String) {
        self.symbols.insert(name, symbols);
    }
}

#[tokio::test]
async fn test_simple64() {
    let mut f = TestFixture64::new();
    let stack = Section::new();
    stack.start().set_const(0x80000000);
    f.raw.set_register("pc", 0x4000c020);
    f.raw.set_register("ra", 0x4000c01a);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 1);
    let f = &s.frames[0];
    let m = f.module.as_ref().unwrap();
    assert_eq!(m.code_file(), "module1");
}

#[tokio::test]
async fn test_scan_without_symbols64() {
    // Scanning should work without any symbols
    let mut f = TestFixture64::new();
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

    f.raw.set_register("pc", 0x4000c020);
    f.raw.set_register("sp", stack.start().value().unwrap());

    let s = f.walk_stack(stack).await;
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
        if let MinidumpRawContext::Riscv64(ctx) = &frame.context.raw {
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
        if let MinidumpRawContext::Riscv64(ctx) = &frame.context.raw {
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

#[tokio::test]
async fn test_cfi_at_4001_64() {
    let mut f = TestFixture64::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let symbols = [
        // The youngest frame's function.
        "FUNC 4000 1000 10 enchiridion\n",
        // Initially, nothing has been pushed on the stack,
        // and the return address is still in the return
        // address register (ra).
        "STACK CFI INIT 4000 100 .cfa: sp 0 + .ra: ra\n",
        // Push s1, s2, the frame pointer (s0) and the
        // return address register.
        "STACK CFI 4001 .cfa: sp 32 + .ra: .cfa -8 + ^",
        " s1: .cfa -32 + ^ s2: .cfa -24 + ^ ",
        " s0: .cfa -16 + ^\n",
        // The calling function.
        "FUNC 5000 1000 10 epictetus\n",
        // Mark it as end of stack.
        "STACK CFI INIT 5000 1000 .cfa: 0 .ra: 0\n",
    ];
    f.add_symbols(String::from("module1"), symbols.concat());

    f.raw.set_register("pc", 0x40004001);
    f.raw.set_register("sp", 0x80000000);
    f.raw.set_register("ra", 0x40005510);
    // distinct callee s1, s2 and s0
    f.raw.set_register("s1", 0xadc9f635a635adc9);
    f.raw.set_register("s2", 0x623135ac35ac6231);
    f.raw.set_register("s0", 0x5fc4be14be145fc4);

    let frame1_sp = Label::new();
    stack = stack
        .D64(0xb5d55e68b5d55e68) // saved s1
        .D64(0x34f3ebd1ebd134f3) // saved s2
        .D64(0x0000_00a2_8112_e110) // saved s0
        .D64(0x0000_0000_4000_5510) // return address
        .mark(&frame1_sp)
        .append_repeated(0, 120);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 2);

    {
        // Frame 0
        let frame = &s.frames[0];
        assert_eq!(frame.trust, FrameTrust::Context);
    }

    {
        // Frame 1
        let frame = &s.frames[1];
        let valid = &frame.context.valid;
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        // The step back from the return address lands on the call.
        assert_eq!(frame.instruction, 0x4000550e);
        if let MinidumpRawContext::Riscv64(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), 0x40005510);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame1_sp.value().unwrap()
            );
            assert_eq!(
                ctx.get_register("s0", valid).unwrap(),
                0x0000_00a2_8112_e110
            );
            assert_eq!(ctx.get_register("s1", valid).unwrap(), 0xb5d55e68b5d55e68);
            assert_eq!(ctx.get_register("s2", valid).unwrap(), 0x34f3ebd1ebd134f3);
        } else {
            unreachable!();
        }
    }
}

// The rv64 twin of `test_cfi_compressed_call`: the C extension compresses
// calls on RV64 just as it does on RV32.
#[tokio::test]
async fn test_cfi_compressed_call64() {
    let mut f = TestFixture64::new();
    let mut stack = Section::new();
    stack.start().set_const(0x80000000);

    let symbols = [
        // The youngest frame's function: nothing pushed, the return
        // address is still in ra.
        "FUNC 4000 1000 10 trapped\n",
        "STACK CFI INIT 4000 100 .cfa: sp 0 + .ra: ra\n",
        // The calling function. A 2-byte compressed call (`c.jalr` on
        // RV64) sits at offset 0x5002, so a return address of 0x5004
        // must select the rows from 0x5002 on. The initial rules
        // covering [0x5000, 0x5002) are poison.
        "FUNC 5000 1000 10 caller\n",
        "STACK CFI INIT 5000 1000 .cfa: 0 .ra: 0\n",
        "STACK CFI 5002 .cfa: sp 16 + .ra: .cfa -8 + ^ s0: .cfa -16 + ^\n",
        // The caller's caller.
        "FUNC 6000 1000 10 outer\n",
        "STACK CFI INIT 6000 1000 .cfa: 0 .ra: 0\n",
    ];
    f.add_symbols(String::from("module1"), symbols.concat());

    // The youngest frame's ra points just past the 2-byte call.
    f.raw.set_register("pc", 0x40004000);
    f.raw.set_register("sp", 0x80000000);
    f.raw.set_register("ra", 0x40005004);

    let frame2_sp = Label::new();
    stack = stack
        .D64(0x22ab9f1922ab9f19) // saved s0
        .D64(0x40006010) // return address of `caller` (into `outer`)
        .mark(&frame2_sp)
        .append_repeated(0, 120);

    let s = f.walk_stack(stack).await;
    assert_eq!(s.frames.len(), 3);

    {
        // Frame 1: the caller. Its instruction must land on the 2-byte
        // call at 0x5002, not 4 bytes before it (where the poison row
        // would end the walk).
        let frame = &s.frames[1];
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        assert_eq!(frame.instruction, 0x40005002);
        assert_eq!(frame.function_name.as_deref(), Some("caller"));
    }

    {
        // Frame 2: recovered through the row the call site selected.
        let frame = &s.frames[2];
        assert_eq!(frame.trust, FrameTrust::CallFrameInfo);
        let valid = &frame.context.valid;
        if let MinidumpRawContext::Riscv64(ctx) = &frame.context.raw {
            assert_eq!(ctx.get_register("pc", valid).unwrap(), 0x40006010);
            assert_eq!(
                ctx.get_register("sp", valid).unwrap(),
                frame2_sp.value().unwrap()
            );
            assert_eq!(ctx.get_register("s0", valid).unwrap(), 0x22ab9f1922ab9f19);
        } else {
            unreachable!();
        }
        assert_eq!(frame.function_name.as_deref(), Some("outer"));
    }
}
