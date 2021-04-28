// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use crate::process_state::*;
use crate::stackwalker::walk_stack;
use breakpad_symbols::{SimpleSymbolSupplier, Symbolizer};
use minidump::format::CONTEXT_AMD64;
use minidump::*;
use test_assembler::*;

struct TestFixture {
    pub raw: CONTEXT_AMD64,
    pub modules: MinidumpModuleList,
    pub symbolizer: Symbolizer,
}

impl TestFixture {
    pub fn new() -> TestFixture {
        TestFixture {
            raw: CONTEXT_AMD64::default(),
            // Give the two modules reasonable standard locations and names
            // for tests to play with.
            modules: MinidumpModuleList::from_modules(vec![
                MinidumpModule::new(0x00007400c0000000, 0x10000, "module1"),
                MinidumpModule::new(0x00007500b0000000, 0x10000, "module2"),
            ]),
            symbolizer: Symbolizer::new(SimpleSymbolSupplier::new(vec![])),
        }
    }

    pub fn walk_stack(&self, stack: Section) -> CallStack {
        let context = MinidumpContext {
            raw: MinidumpRawContext::Amd64(self.raw.clone()),
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
            &Some(stack_memory),
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
    f.raw.rip = 0x00007400c0000200;
    f.raw.rbp = 0x8000000080000000;

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 1);
    let f = &s.frames[0];
    let m = f.module.as_ref().unwrap();
    assert_eq!(m.code_file(), "module1");
}

#[test]
fn test_caller_pushed_rbp() {
    // Functions typically push their %rbp upon entry and set %rbp pointing
    // there.  If stackwalking finds a plausible address for the next frame's
    // %rbp directly below the return address, assume that it is indeed the
    // next frame's %rbp.
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    let stack_start = 0x8000000080000000;
    let return_address = 0x00007500b0000110;
    stack.start().set_const(stack_start);

    let frame0_rbp = Label::new();
    let frame1_sp = Label::new();
    let frame1_rbp = Label::new();

    stack = stack
        // frame 0
        .append_repeated(16, 0) // space
        .D64(0x00007400b0000000) // junk that's not
        .D64(0x00007500b0000000) // a return address
        .D64(0x00007400c0001000) // a couple of plausible addresses
        .D64(0x00007500b000aaaa) // that are not within functions
        .mark(&frame0_rbp)
        .D64(&frame1_rbp) // caller-pushed %rbp
        .D64(return_address) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(32, 0) // body of frame1
        .mark(&frame1_rbp) // end of stack
        .D64(0);

    f.raw.rip = 0x00007400c0000200;
    f.raw.rbp = frame0_rbp.value().unwrap();
    f.raw.rsp = stack.start().value().unwrap();

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 2);

    {
        // To avoid reusing locals by mistake
        let f0 = &s.frames[0];
        assert_eq!(f0.trust, FrameTrust::Context);
        assert_eq!(f0.context.valid, MinidumpContextValidity::All);
        if let MinidumpRawContext::Amd64(ctx) = &f0.context.raw {
            assert_eq!(ctx.rbp, frame0_rbp.value().unwrap());
        } else {
            unreachable!();
        }
    }

    {
        // To avoid reusing locals by mistake
        let f1 = &s.frames[1];
        assert_eq!(f1.trust, FrameTrust::FramePointer);
        if let MinidumpContextValidity::Some(ref which) = f1.context.valid {
            assert!(which.contains("rip"));
            assert!(which.contains("rsp"));
            assert!(which.contains("rbp"));
        } else {
            unreachable!();
        }
        if let MinidumpRawContext::Amd64(ctx) = &f1.context.raw {
            assert_eq!(ctx.rip, return_address);
            assert_eq!(ctx.rsp, frame1_sp.value().unwrap());
            assert_eq!(ctx.rbp, frame1_rbp.value().unwrap());
        } else {
            unreachable!();
        }
    }
}

#[test]
fn test_scan_without_symbols() {
    // When the stack walker resorts to scanning the stack,
    // only addresses located within loaded modules are
    // considered valid return addresses.
    // Force scanning through three frames to ensure that the
    // stack pointer is set properly in scan-recovered frames.
    let mut f = TestFixture::new();
    let mut stack = Section::new();
    let stack_start = 0x8000000080000000;
    stack.start().set_const(stack_start);

    let return_address1 = 0x00007500b0000100;
    let return_address2 = 0x00007500b0000900;

    let frame1_sp = Label::new();
    let frame2_sp = Label::new();
    let frame1_rbp = Label::new();
    stack = stack
        // frame 0
        .append_repeated(16, 0) // space
        .D64(0x00007400b0000000) // junk that's not
        .D64(0x00007500d0000000) // a return address
        .D64(return_address1) // actual return address
        // frame 1
        .mark(&frame1_sp)
        .append_repeated(16, 0) // space
        .D64(0x00007400b0000000) // more junk
        .D64(0x00007500d0000000)
        .mark(&frame1_rbp)
        .D64(stack_start) // This is in the right place to be
        // a saved rbp, but it's bogus, so
        // we shouldn't report it.
        .D64(return_address2) // actual return address
        // frame 2
        .mark(&frame2_sp)
        .append_repeated(32, 0); // end of stack

    f.raw.rip = 0x00007400c0000200;
    f.raw.rbp = frame1_rbp.value().unwrap();
    f.raw.rsp = stack.start().value().unwrap();

    let s = f.walk_stack(stack);
    assert_eq!(s.frames.len(), 3);

    {
        // To avoid reusing locals by mistake
        let f0 = &s.frames[0];
        assert_eq!(f0.trust, FrameTrust::Context);
        assert_eq!(f0.context.valid, MinidumpContextValidity::All);
    }

    {
        // To avoid reusing locals by mistake
        let f1 = &s.frames[1];
        assert_eq!(f1.trust, FrameTrust::Scan);
        if let MinidumpContextValidity::Some(ref which) = f1.context.valid {
            assert!(which.contains("rip"));
            assert!(which.contains("rsp"));
            assert!(which.contains("rbp"));
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Amd64(ctx) = &f1.context.raw {
            assert_eq!(ctx.rip, return_address1);
            assert_eq!(ctx.rsp, frame1_sp.value().unwrap());
            assert_eq!(ctx.rbp, frame1_rbp.value().unwrap());
        } else {
            unreachable!();
        }
    }

    {
        // To avoid reusing locals by mistake
        let f2 = &s.frames[2];
        assert_eq!(f2.trust, FrameTrust::Scan);
        if let MinidumpContextValidity::Some(ref which) = f2.context.valid {
            assert!(which.contains("rip"));
            assert!(which.contains("rsp"));
        } else {
            unreachable!();
        }

        if let MinidumpRawContext::Amd64(ctx) = &f2.context.raw {
            assert_eq!(ctx.rip, return_address2);
            assert_eq!(ctx.rsp, frame2_sp.value().unwrap());
        } else {
            unreachable!();
        }
    }
}

/*
// Walk a traditional frame. A traditional frame saves the caller's
// %ebp just below the return address, and has its own %ebp pointing
// at the saved %ebp.
#[test]
fn test_traditional() {
    let mut f = TestFixture::new();
   let frame0_rbp = Label::new();
   let frame1_rbp = Label::new();
   let mut stack = Section::new();
   let stack_start = 0x80000000;
    stack.start().set_const(stack_start);

  stack = stack
    .append_repeated(12, 0)                      // frame 0: space
    .mark(&frame0_ebp)                  // frame 0 %ebp points here
    .D32(&frame1_ebp)                    // frame 0: saved %ebp
    .D32(0x40008679)                    // frame 0: return address
    .append_repeated(8, 0)                       // frame 1: space
    .mark(&frame1_ebp)                  // frame 1 %ebp points here
    .D32(0)                             // frame 1: saved %ebp (stack end)
    .D32(0);                            // frame 1: return address (stack end)

  f.raw.eip = 0x4000c7a5;
  f.raw.esp = stack.start().value().unwrap();
  f.raw.ebp = frame0_ebp.value().unwrap();

  let s = f.walk_stack(stack);
  assert_eq!(s.frames.len(), 2);


  {  // To avoid reusing locals by mistake
    let f0 = &s.frames[0];
            let f0 = &s.frames[0];
        assert_eq!(f0.trust, FrameTrust::Context);
        assert_eq!(f0.context.valid, MinidumpContextValidity::All);
        assert_eq!(f0.instruction, 0x4000c7a5);
        if let MinidumpRawContext::AMD64(ctx) = &f0.context.raw {
            assert_eq!(ctx.rip, 0x4000c7a5);
            assert_eq!(ctx.rsp, stack_start as u32);
            assert_eq!(ctx.rbp, frame0_rbp.value().unwrap());
        } else {
            unreachable!();
        }
  }

  {  // To avoid reusing locals by mistake
    let f1 = &s.frames[1];
    assert_eq!(f1.trust, FrameTrust::FramePointer);
    if let MinidumpContextValidity::Some(ref which) = f1.context.valid {
        assert!(which.contains("rip"));
        assert!(which.contains("rsp"));
        assert!(which.contains("rbp"));
    } else {
        unreachable!();
    }
    assert_eq!(f1.instruction + 1, 0x40008679);

    if let MinidumpRawContext::AMD64(ctx) = &f1.context.raw {
        assert_eq!(ctx.rip, 0x40008679);
        assert_eq!(ctx.rbp, frame1_rbp.value().unwrap());
    } else {
        unreachable!();
    }
  }
}
*/
