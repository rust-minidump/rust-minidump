// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use minidump::format::CONTEXT_X86;
use minidump::{MinidumpContext, MinidumpContextValidity, MinidumpMemory, MinidumpRawContext};
use process_state::{FrameTrust, StackFrame};
use stackwalker::unwind::Unwind;
use std::collections::HashSet;

fn get_caller_by_frame_pointer(
    ctx: &CONTEXT_X86,
    valid: &MinidumpContextValidity,
    stack_memory: &MinidumpMemory,
) -> Option<StackFrame> {
    match *valid {
        MinidumpContextValidity::All => {}
        MinidumpContextValidity::Some(ref which) => {
            if !which.contains("ebp") {
                return None;
            }
        }
    }

    let last_ebp = ctx.ebp;
    // Assume that the standard %ebp-using x86 calling convention is in
    // use.
    //
    // The typical x86 calling convention, when frame pointers are present,
    // is for the calling procedure to use CALL, which pushes the return
    // address onto the stack and sets the instruction pointer (%eip) to
    // the entry point of the called routine.  The called routine then
    // PUSHes the calling routine's frame pointer (%ebp) onto the stack
    // before copying the stack pointer (%esp) to the frame pointer (%ebp).
    // Therefore, the calling procedure's frame pointer is always available
    // by dereferencing the called procedure's frame pointer, and the return
    // address is always available at the memory location immediately above
    // the address pointed to by the called procedure's frame pointer.  The
    // calling procedure's stack pointer (%esp) is 8 higher than the value
    // of the called procedure's frame pointer at the time the calling
    // procedure made the CALL: 4 bytes for the return address pushed by the
    // CALL itself, and 4 bytes for the callee's PUSH of the caller's frame
    // pointer.
    //
    // %eip_new = *(%ebp_old + 4)
    // %esp_new = %ebp_old + 8
    // %ebp_new = *(%ebp_old)
    if let (Some(caller_eip), Some(caller_ebp)) = (
        stack_memory.get_memory_at_address(last_ebp as u64 + 4),
        stack_memory.get_memory_at_address(last_ebp as u64),
    ) {
        let caller_esp = last_ebp + 8;
        let caller_ctx = CONTEXT_X86 {
            eip: caller_eip,
            esp: caller_esp,
            ebp: caller_ebp,
            ..CONTEXT_X86::default()
        };
        let mut valid = HashSet::new();
        valid.insert("eip");
        valid.insert("esp");
        valid.insert("ebp");
        let context = MinidumpContext {
            raw: MinidumpRawContext::X86(caller_ctx),
            valid: MinidumpContextValidity::Some(valid),
        };
        let mut frame = StackFrame::from_context(context, FrameTrust::FramePointer);
        // caller_eip is the return address, which is the instruction
        // after the CALL that caused us to arrive at the callee. Set
        // new_frame->instruction to one less than that, so it points within the
        // CALL instruction.
        if caller_eip > 0 {
            frame.instruction = (caller_eip as u64) - 1;
        }
        Some(frame)
    } else {
        // TODO: try stack scanning
        None
    }
}

impl Unwind for CONTEXT_X86 {
    fn get_caller_frame(
        &self,
        valid: &MinidumpContextValidity,
        stack_memory: &Option<MinidumpMemory>,
    ) -> Option<StackFrame> {
        stack_memory.as_ref().and_then(|stack| {
            get_caller_by_frame_pointer(self, valid, stack).and_then(|frame| {
                // Treat an instruction address of 0 as end-of-stack.
                if frame.context.get_instruction_pointer() == 0 {
                    return None;
                }
                // If the new stack pointer is at a lower address than the old,
                // then that's clearly incorrect. Treat this as end-of-stack to
                // enforce progress and avoid infinite loops.
                if frame.context.get_stack_pointer() as u32 <= self.esp {
                    return None;
                }
                Some(frame)
            })
        })
    }
}
