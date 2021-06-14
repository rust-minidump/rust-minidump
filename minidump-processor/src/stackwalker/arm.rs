// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

// NOTE: arm64_old.rs and arm64.rs should be identical except for the names of
// their context types.

use crate::process_state::{FrameTrust, StackFrame};
use crate::stackwalker::unwind::Unwind;
use crate::stackwalker::CfiStackWalker;
use crate::SymbolProvider;
use log::trace;
use minidump::{
    CpuContext, MinidumpContext, MinidumpContextValidity, MinidumpMemory, MinidumpModuleList,
    MinidumpRawContext,
};
use std::collections::HashSet;

type ArmContext = minidump::format::CONTEXT_ARM;
type Pointer = <ArmContext as CpuContext>::Register;
type Registers = minidump::format::ArmRegisterNumbers;

const POINTER_WIDTH: Pointer = std::mem::size_of::<Pointer>() as Pointer;
const FRAME_POINTER: &str = Registers::FramePointer.name();
const STACK_POINTER: &str = Registers::StackPointer.name();
const PROGRAM_COUNTER: &str = Registers::ProgramCounter.name();
const LINK_REGISTER: &str = Registers::LinkRegister.name();
const CALLEE_SAVED_REGS: &[&str] = &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"];

fn get_caller_by_frame_pointer<P>(
    ctx: &ArmContext,
    valid: &MinidumpContextValidity,
    _trust: FrameTrust,
    stack_memory: &MinidumpMemory,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider,
{
    // Assume that the standard %fp-using ARM calling convention is in use.
    // The main quirk of this ABI is that the return address doesn't need to
    // be restored from the stack -- it's already in the link register (lr).
    // But that means we need to save/restore lr itself so that the *caller's*
    // return address can be recovered.
    //
    // In the standard calling convention, the following happens:
    //
    // PUSH fp, lr    (save fp and lr to the stack -- ARM pushes in pairs)
    // fp := sp       (update the frame pointer to the current stack pointer)
    // lr := pc       (save the return address in the link register)
    //
    // So to restore the caller's registers, we have:
    //
    // pc := lr
    // sp := fp + ptr*2
    // lr := *(fp + ptr)
    // fp := *fp
    let last_fp = ctx.get_register(FRAME_POINTER, valid)?;
    let last_sp = ctx.get_register(STACK_POINTER, valid)?;
    // Unlike ARM64, we don't bother trying really hard to restore lr
    let last_lr = ctx.get_register(LINK_REGISTER, valid)?;

    let caller_fp = stack_memory.get_memory_at_address(last_fp as u64)?;
    let caller_lr = stack_memory.get_memory_at_address(last_fp as u64 + POINTER_WIDTH as u64)?;
    let caller_pc = last_lr;

    // TODO: why does breakpad do this? how can fp be null by here?
    let caller_sp = if last_fp == 0 {
        last_sp
    } else {
        last_fp + POINTER_WIDTH * 2
    };

    // If the recovered pc is not a canonical address it can't be
    // the return address, so fp must not have been a frame pointer.

    // Breakpad doesn't validate that the fp seems reasonable

    // Don't accept obviously wrong instruction pointers.
    if !instruction_seems_valid(caller_pc, modules, symbol_provider) {
        return None;
    }
    // Don't accept obviously wrong stack pointers.
    if !stack_seems_valid(caller_sp, last_sp, stack_memory) {
        return None;
    }

    let mut caller_ctx = ArmContext::default();
    caller_ctx.set_register(PROGRAM_COUNTER, caller_pc);
    caller_ctx.set_register(LINK_REGISTER, caller_lr);
    caller_ctx.set_register(FRAME_POINTER, caller_fp);
    caller_ctx.set_register(STACK_POINTER, caller_sp);

    let mut valid = HashSet::new();
    valid.insert(PROGRAM_COUNTER);
    valid.insert(LINK_REGISTER);
    valid.insert(FRAME_POINTER);
    valid.insert(STACK_POINTER);

    let context = MinidumpContext {
        raw: MinidumpRawContext::Arm(caller_ctx),
        valid: MinidumpContextValidity::Some(valid),
    };
    let mut frame = StackFrame::from_context(context, FrameTrust::FramePointer);
    adjust_instruction(&mut frame, caller_pc);
    Some(frame)
}

fn get_caller_by_cfi<P>(
    ctx: &ArmContext,
    valid: &MinidumpContextValidity,
    _trust: FrameTrust,
    stack_memory: &MinidumpMemory,
    grand_callee_frame: Option<&StackFrame>,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider,
{
    trace!("trying to get frame by cfi");

    let last_sp = ctx.get_register(STACK_POINTER, valid)?;
    let last_pc = ctx.get_register(PROGRAM_COUNTER, valid)?;

    trace!("  ...context was good");

    let module = modules.module_at_address(last_pc as u64)?;
    trace!("  ...found module");

    let grand_callee_parameter_size = grand_callee_frame
        .and_then(|f| f.parameter_size)
        .unwrap_or(0);

    let mut stack_walker = CfiStackWalker {
        instruction: last_pc as u64,
        grand_callee_parameter_size,

        callee_ctx: ctx,
        callee_validity: valid,

        // Default to forwarding all callee-saved regs verbatim.
        // The CFI evaluator may clear or overwrite these values.
        // The stack pointer and instruction pointer are not included.
        caller_ctx: ctx.clone(),
        caller_validity: callee_forwarded_regs(valid),

        stack_memory,
    };

    symbol_provider.walk_frame(module, &mut stack_walker)?;
    let caller_pc = stack_walker.caller_ctx.get_register_always(PROGRAM_COUNTER);
    let caller_sp = stack_walker.caller_ctx.get_register_always(STACK_POINTER);

    // Don't accept obviously wrong instruction pointers.
    if !instruction_seems_valid(caller_pc, modules, symbol_provider) {
        return None;
    }
    // Don't accept obviously wrong stack pointers.
    if !stack_seems_valid(caller_sp, last_sp, stack_memory) {
        return None;
    }

    let context = MinidumpContext {
        raw: MinidumpRawContext::Arm(stack_walker.caller_ctx),
        valid: MinidumpContextValidity::Some(stack_walker.caller_validity),
    };
    let mut frame = StackFrame::from_context(context, FrameTrust::CallFrameInfo);
    adjust_instruction(&mut frame, caller_pc);
    Some(frame)
}

fn callee_forwarded_regs(valid: &MinidumpContextValidity) -> HashSet<&'static str> {
    match valid {
        MinidumpContextValidity::All => CALLEE_SAVED_REGS.iter().copied().collect(),
        MinidumpContextValidity::Some(ref which) => CALLEE_SAVED_REGS
            .iter()
            .filter(|&reg| which.contains(reg))
            .copied()
            .collect(),
    }
}

fn get_caller_by_scan<P>(
    ctx: &ArmContext,
    valid: &MinidumpContextValidity,
    trust: FrameTrust,
    stack_memory: &MinidumpMemory,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider,
{
    // Stack scanning is just walking from the end of the frame until we encounter
    // a value on the stack that looks like a pointer into some code (it's an address
    // in a range covered by one of our modules). If we find such an instruction,
    // we assume it's an pc value that was pushed by the CALL instruction that created
    // the current frame. The next frame is then assumed to end just before that
    // pc value.
    let last_sp = ctx.get_register(STACK_POINTER, valid)?;

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
        let address_of_pc = last_sp + i * POINTER_WIDTH;
        let caller_pc = stack_memory.get_memory_at_address(address_of_pc as u64)?;
        if instruction_seems_valid(caller_pc, modules, symbol_provider) {
            // pc is pushed by CALL, so sp is just address_of_pc + ptr
            let caller_sp = address_of_pc + POINTER_WIDTH;

            // Don't do any more validation, and don't try to restore fp
            // (that's what breakpad does!)

            let mut caller_ctx = ArmContext::default();
            caller_ctx.set_register(PROGRAM_COUNTER, caller_pc);
            caller_ctx.set_register(STACK_POINTER, caller_sp);

            let mut valid = HashSet::new();
            valid.insert(PROGRAM_COUNTER);
            valid.insert(STACK_POINTER);

            let context = MinidumpContext {
                raw: MinidumpRawContext::Arm(caller_ctx),
                valid: MinidumpContextValidity::Some(valid),
            };
            let mut frame = StackFrame::from_context(context, FrameTrust::Scan);
            adjust_instruction(&mut frame, caller_pc);
            return Some(frame);
        }
    }

    None
}

#[allow(clippy::match_like_matches_macro)]
fn instruction_seems_valid<P>(
    instruction: Pointer,
    modules: &MinidumpModuleList,
    _symbol_provider: &P,
) -> bool
where
    P: SymbolProvider,
{
    if let Some(_module) = modules.module_at_address(instruction as u64) {
        // TODO: if mapped, check if this instruction actually maps to a function line
        true
    } else {
        false
    }
}

fn stack_seems_valid(
    caller_sp: Pointer,
    callee_sp: Pointer,
    stack_memory: &MinidumpMemory,
) -> bool {
    // The stack shouldn't *grow* when we unwind
    if caller_sp < callee_sp {
        return false;
    }

    // The stack pointer should be in the stack
    stack_memory
        .get_memory_at_address::<Pointer>(caller_sp as u64)
        .is_some()
}

fn adjust_instruction(frame: &mut StackFrame, caller_pc: Pointer) {
    // A caller's pc is the return address, which is the instruction
    // after the CALL that caused us to arrive at the callee. Set
    // the value to one less than that, so it points within the
    // CALL instruction.
    if caller_pc > 0 {
        frame.instruction = caller_pc as u64 - 1;
    }
}

impl Unwind for ArmContext {
    fn get_caller_frame<P>(
        &self,
        valid: &MinidumpContextValidity,
        trust: FrameTrust,
        stack_memory: Option<&MinidumpMemory>,
        grand_callee_frame: Option<&StackFrame>,
        modules: &MinidumpModuleList,
        syms: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider,
    {
        stack_memory
            .as_ref()
            .and_then(|stack| {
                get_caller_by_cfi(self, valid, trust, stack, grand_callee_frame, modules, syms)
                    .or_else(|| {
                        get_caller_by_frame_pointer(self, valid, trust, stack, modules, syms)
                    })
                    .or_else(|| get_caller_by_scan(self, valid, trust, stack, modules, syms))
            })
            .and_then(|frame| {
                // Treat an instruction address of 0 as end-of-stack.
                if frame.context.get_instruction_pointer() == 0 {
                    return None;
                }
                // If the new stack pointer is at a lower address than the old,
                // then that's clearly incorrect. Treat this as end-of-stack to
                // enforce progress and avoid infinite loops.
                if frame.context.get_stack_pointer() < self.get_register_always("sp") as u64 {
                    return None;
                }
                Some(frame)
            })
    }
}
