// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

// Note since x86 and Amd64 have basically the same ABI, this implementation
// is written to largely erase the details of the two wherever possible,
// so that it can be copied between the two with minimal changes. It's not
// worth the effort to *actually* unify the implementations.

use crate::process_state::{FrameTrust, StackFrame};
use crate::stackwalker::unwind::Unwind;
use crate::stackwalker::CfiStackWalker;
use crate::SymbolProvider;
use log::trace;
use minidump::format::CONTEXT_X86;
use minidump::{
    MinidumpContext, MinidumpContextValidity, MinidumpMemory, MinidumpModuleList,
    MinidumpRawContext,
};
use std::collections::HashSet;

type Pointer = u32;
const POINTER_WIDTH: Pointer = 4;
const INSTRUCTION_REGISTER: &str = "eip";
const STACK_POINTER_REGISTER: &str = "esp";
const FRAME_POINTER_REGISTER: &str = "ebp";

fn get_caller_by_frame_pointer(
    ctx: &CONTEXT_X86,
    valid: &MinidumpContextValidity,
    _trust: FrameTrust,
    stack_memory: &MinidumpMemory,
    _modules: &MinidumpModuleList,
) -> Option<StackFrame> {
    if let MinidumpContextValidity::Some(ref which) = valid {
        if !which.contains(FRAME_POINTER_REGISTER) {
            return None;
        }
    }

    let last_bp = ctx.ebp;
    // Assume that the standard %bp-using x86 calling convention is in
    // use.
    //
    // The typical x86 calling convention, when frame pointers are present,
    // is for the calling procedure to use CALL, which pushes the return
    // address onto the stack and sets the instruction pointer (%ip) to
    // the entry point of the called routine.  The called routine then
    // PUSHes the calling routine's frame pointer (%bp) onto the stack
    // before copying the stack pointer (%sp) to the frame pointer (%bp).
    // Therefore, the calling procedure's frame pointer is always available
    // by dereferencing the called procedure's frame pointer, and the return
    // address is always available at the memory location immediately above
    // the address pointed to by the called procedure's frame pointer.  The
    // calling procedure's stack pointer (%sp) is 2 pointers higher than the
    // value of the called procedure's frame pointer at the time the calling
    // procedure made the CALL: 1 pointer for the return address pushed by the
    // CALL itself, and 1 pointer for the callee's PUSH of the caller's frame
    // pointer.
    //
    // %ip_new = *(%bp_old + ptr)
    // %sp_new = %bp_old + ptr
    // %bp_new = *(%bp_old)

    let caller_ip = stack_memory.get_memory_at_address(last_bp as u64 + POINTER_WIDTH as u64)?;
    let caller_bp = stack_memory.get_memory_at_address(last_bp as u64)?;
    let caller_sp = last_bp + POINTER_WIDTH * 2;

    // NOTE: minor divergence from x64 impl here: doing extra validation on the
    // value of `caller_sp` and `caller_bp` here encourages the stack scanner
    // to kick in and start outputting extra frames for `/testdata/test.dmp`.
    // Since breakpad also doesn't output those frames, let's assume that's
    // desirable.

    let caller_ctx = CONTEXT_X86 {
        eip: caller_ip,
        esp: caller_sp,
        ebp: caller_bp,
        ..CONTEXT_X86::default()
    };
    let mut valid = HashSet::new();
    valid.insert(INSTRUCTION_REGISTER);
    valid.insert(STACK_POINTER_REGISTER);
    valid.insert(FRAME_POINTER_REGISTER);
    let context = MinidumpContext {
        raw: MinidumpRawContext::X86(caller_ctx),
        valid: MinidumpContextValidity::Some(valid),
    };
    let mut frame = StackFrame::from_context(context, FrameTrust::FramePointer);
    adjust_instruction(&mut frame, caller_ip);
    Some(frame)
}

fn get_caller_by_cfi<P>(
    ctx: &CONTEXT_X86,
    valid: &MinidumpContextValidity,
    _trust: FrameTrust,
    stack_memory: &MinidumpMemory,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider,
{
    trace!("trying to get frame by cfi");
    if let MinidumpContextValidity::Some(ref which) = valid {
        if !which.contains(INSTRUCTION_REGISTER) {
            return None;
        }
    }

    trace!("  ...context was good");

    let instruction = ctx.eip;
    let module = modules.module_at_address(instruction as u64)?;

    let mut stack_walker = CfiStackWalker {
        instruction: instruction as u64,

        callee_ctx: ctx,
        callee_validity: valid,

        caller_ctx: CONTEXT_X86::default(),
        caller_validity: HashSet::new(),

        stack_memory,
    };

    symbol_provider.walk_frame(module, &mut stack_walker)?;
    let ip = stack_walker.caller_ctx.eip;

    let context = MinidumpContext {
        raw: MinidumpRawContext::X86(stack_walker.caller_ctx),
        valid: MinidumpContextValidity::Some(stack_walker.caller_validity),
    };
    let mut frame = StackFrame::from_context(context, FrameTrust::CallFrameInfo);
    adjust_instruction(&mut frame, ip);
    Some(frame)
}
fn get_caller_by_scan(
    ctx: &CONTEXT_X86,
    valid: &MinidumpContextValidity,
    trust: FrameTrust,
    stack_memory: &MinidumpMemory,
    modules: &MinidumpModuleList,
) -> Option<StackFrame> {
    // Stack scanning is just walking from the end of the frame until we encounter
    // a value on the stack that looks like a pointer into some code (it's an address
    // in a range covered by one of our modules). If we find such an instruction,
    // we assume it's a ip value that was pushed by the CALL instruction that created
    // the current frame. The next frame is then assumed to end just before that
    // ip value.
    let last_bp = match valid {
        MinidumpContextValidity::All => Some(ctx.ebp),
        MinidumpContextValidity::Some(ref which) => {
            if !which.contains(STACK_POINTER_REGISTER) {
                return None;
            }
            if which.contains(FRAME_POINTER_REGISTER) {
                Some(ctx.ebp)
            } else {
                None
            }
        }
    };
    // TODO: pointer-align this..? Does CALL push aligned ip values? Is sp aligned?
    let last_sp = ctx.esp;

    // Number of pointer-sized values to scan through in our search.
    let default_scan_range = 40;
    let extended_scan_range = default_scan_range * 4;

    // Breakpad devs found that the first frame of an unwind can be really messed up,
    // and therefore benefits from a longer scan. Let's do it too.
    let scan_range = if let FrameTrust::Context = trust {
        extended_scan_range
    } else {
        default_scan_range
    };

    for i in 0..scan_range {
        let address_of_ip = last_sp + i * POINTER_WIDTH;
        let caller_ip = stack_memory.get_memory_at_address(address_of_ip as u64)?;
        if instruction_seems_valid(caller_ip, modules) {
            // ip is pushed by CALL, so sp is just address_of_ip + ptr
            let caller_sp = address_of_ip + POINTER_WIDTH;

            // Try to restore bp as well. This can be possible in two cases:
            //
            // 1. This function has the standard prologue that pushes bp and
            //    sets bp = sp. If this is the case, then the current bp should be
            //    immediately after (before in memory) address_of_ip.
            //
            // 2. This function does not use bp, and has just preserved it
            //    from the caller. If this is the case, bp should be before
            //    (after in memory) address_of_ip.
            //
            // We then try our best to eliminate bogus-looking bp's with some
            // simple heuristics like "is a valid stack address".
            let mut caller_bp = None;

            // Max reasonable size for a single x86 frame is 128 KB.  This value is used in
            // a heuristic for recovering of the EBP chain after a scan for return address.
            // This value is based on a stack frame size histogram built for a set of
            // popular third party libraries which suggests that 99.5% of all frames are
            // smaller than 128 KB.
            const MAX_REASONABLE_GAP_BETWEEN_FRAMES: Pointer = 128 * 1024;

            let address_of_bp = address_of_ip - POINTER_WIDTH;
            let bp = stack_memory.get_memory_at_address(address_of_bp as u64)?;
            if bp > address_of_ip && bp - address_of_bp <= MAX_REASONABLE_GAP_BETWEEN_FRAMES {
                // Sanity check that resulting bp is still inside stack memory.
                if stack_memory
                    .get_memory_at_address::<Pointer>(bp as u64)
                    .is_some()
                {
                    caller_bp = Some(bp);
                }
            } else if let Some(last_bp) = last_bp {
                if last_bp >= address_of_ip + POINTER_WIDTH {
                    // Sanity check that resulting bp is still inside stack memory.
                    if stack_memory
                        .get_memory_at_address::<Pointer>(last_bp as u64)
                        .is_some()
                    {
                        caller_bp = Some(last_bp);
                    }
                }
            }

            let caller_ctx = CONTEXT_X86 {
                eip: caller_ip,
                esp: caller_sp,
                ebp: caller_bp.unwrap_or(0),
                ..CONTEXT_X86::default()
            };
            let mut valid = HashSet::new();
            valid.insert(INSTRUCTION_REGISTER);
            valid.insert(STACK_POINTER_REGISTER);
            if caller_bp.is_some() {
                valid.insert(FRAME_POINTER_REGISTER);
            }
            let context = MinidumpContext {
                raw: MinidumpRawContext::X86(caller_ctx),
                valid: MinidumpContextValidity::Some(valid),
            };
            let mut frame = StackFrame::from_context(context, FrameTrust::Scan);
            adjust_instruction(&mut frame, caller_ip);
            return Some(frame);
        }
    }

    None
}

#[allow(clippy::match_like_matches_macro)]
fn instruction_seems_valid(instruction: Pointer, modules: &MinidumpModuleList) -> bool {
    if let Some(_module) = modules.module_at_address(instruction as u64) {
        // TODO: if mapped, check if this instruction actually maps to a function line
        true
    } else {
        false
    }
}

fn adjust_instruction(frame: &mut StackFrame, caller_ip: Pointer) {
    // A caller's ip is the return address, which is the instruction
    // after the CALL that caused us to arrive at the callee. Set
    // the value to one less than that, so it points within the
    // CALL instruction.
    if caller_ip > 0 {
        frame.instruction = caller_ip as u64 - 1;
    }
}

impl Unwind for CONTEXT_X86 {
    fn get_caller_frame<P>(
        &self,
        valid: &MinidumpContextValidity,
        trust: FrameTrust,
        stack_memory: Option<&MinidumpMemory>,
        modules: &MinidumpModuleList,
        symbol_provider: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider,
    {
        stack_memory
            .as_ref()
            .and_then(|stack| {
                get_caller_by_cfi(self, valid, trust, stack, modules, symbol_provider)
                    .or_else(|| get_caller_by_frame_pointer(self, valid, trust, stack, modules))
                    .or_else(|| get_caller_by_scan(self, valid, trust, stack, modules))
            })
            .and_then(|frame| {
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
    }
}
