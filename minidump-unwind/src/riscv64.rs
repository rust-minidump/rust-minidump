// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use super::impl_prelude::*;
use crate::{SymbolProvider, SystemInfo};
use minidump::{
    CpuContext, MinidumpContext, MinidumpContextValidity, MinidumpModuleList, MinidumpRawContext,
    UnifiedMemory,
};
use std::collections::HashSet;
use tracing::trace;

type RiscvContext = minidump::format::CONTEXT_RISCV64;
type Pointer = <RiscvContext as CpuContext>::Register;

const POINTER_WIDTH: Pointer = std::mem::size_of::<Pointer>() as Pointer;
const FRAME_POINTER: &str = "s0";
const LINK_REGISTER: &str = "ra";
const STACK_POINTER: &str = "sp";
const PROGRAM_COUNTER: &str = "pc";
const CALLEE_SAVED_REGS: &[&str] = &[
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "sp",
];

async fn get_caller_by_cfi<P>(
    ctx: &RiscvContext,
    callee: &StackFrame,
    grand_callee: Option<&StackFrame>,
    stack_memory: UnifiedMemory<'_, '_>,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    trace!("trying cfi");

    let valid = &callee.context.valid;
    let _last_sp = ctx.get_register(STACK_POINTER, valid)?;
    let module = modules.module_at_address(callee.instruction)?;
    let grand_callee_parameter_size = grand_callee.and_then(|f| f.parameter_size).unwrap_or(0);
    let has_grand_callee = grand_callee.is_some();

    let mut stack_walker = CfiStackWalker {
        instruction: callee.instruction,
        has_grand_callee,
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

    symbol_provider
        .walk_frame(module, &mut stack_walker)
        .await?;

    let caller_pc = stack_walker.caller_ctx.get_register_always(PROGRAM_COUNTER);
    let caller_sp = stack_walker.caller_ctx.get_register_always(STACK_POINTER);

    trace!(
        "cfi evaluation was successful -- caller_pc: 0x{:016x}, caller_sp: 0x{:016x}",
        caller_pc,
        caller_sp,
    );

    // Do absolutely NO validation! Yep! As long as CFI evaluation succeeds
    // (which does include pc and sp resolving), just blindly assume the
    // values are correct. I Don't Like This, but it's what breakpad does and
    // we should start with a baseline of parity.

    let context = MinidumpContext {
        raw: MinidumpRawContext::Riscv64(stack_walker.caller_ctx),
        valid: MinidumpContextValidity::Some(stack_walker.caller_validity),
    };
    Some(StackFrame::from_context(context, FrameTrust::CallFrameInfo))
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

fn get_caller_by_frame_pointer<P>(
    ctx: &RiscvContext,
    callee: &StackFrame,
    _grand_callee: Option<&StackFrame>,
    stack_memory: UnifiedMemory<'_, '_>,
    _modules: &MinidumpModuleList,
    _symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    trace!("trying frame pointer");

    let valid = &callee.context.valid;
    let last_fp = ctx.get_register(FRAME_POINTER, valid)?;
    let last_sp = ctx.get_register(STACK_POINTER, valid)?;
    let last_ra = ctx.get_register(LINK_REGISTER, valid)?;

    trace!(
        "found -- last_fp: 0x{:016x}, last_sp: 0x{:016x}, last_ra: 0x{:016x}",
        last_fp,
        last_sp,
        last_ra,
    );

    if last_fp >= u64::MAX - POINTER_WIDTH * 2 {
        // Although this code generally works fine if the pointer math overflows,
        // debug builds will still panic, and this guard protects against it without
        // drowning the rest of the code in checked_add.
        return None;
    }

    let (caller_fp, caller_pc, caller_sp, caller_ra) = if last_fp == 0 {
        // In this case we want unwinding to stop. One of the termination conditions in get_caller_frame
        // is that caller_sp <= last_sp. Therefore we can force termination by setting caller_sp = last_sp.
        (0, last_ra, last_sp, 0)
    } else {
        (
            stack_memory.get_memory_at_address(last_fp)?,
            last_ra,
            last_fp + POINTER_WIDTH * 2,
            stack_memory.get_memory_at_address(last_fp + POINTER_WIDTH)?,
        )
    };

    trace!(
        "frame pointer seems valid -- caller_pc: 0x{:016x}, caller_sp: 0x{:016x}",
        caller_pc,
        caller_sp,
    );

    let mut caller_ctx = RiscvContext::default();
    caller_ctx.set_register(PROGRAM_COUNTER, caller_pc);
    caller_ctx.set_register(FRAME_POINTER, caller_fp);
    caller_ctx.set_register(STACK_POINTER, caller_sp);
    caller_ctx.set_register(LINK_REGISTER, caller_ra);

    let mut valid = HashSet::new();
    valid.insert(PROGRAM_COUNTER);
    valid.insert(FRAME_POINTER);
    valid.insert(STACK_POINTER);
    valid.insert(LINK_REGISTER);

    let context = MinidumpContext {
        raw: MinidumpRawContext::Riscv64(caller_ctx),
        valid: MinidumpContextValidity::Some(valid),
    };
    Some(StackFrame::from_context(context, FrameTrust::FramePointer))
}

async fn get_caller_by_scan<P>(
    ctx: &RiscvContext,
    callee: &StackFrame,
    stack_memory: UnifiedMemory<'_, '_>,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    trace!("trying scan");
    // Stack scanning is just walking from the end of the frame until we encounter
    // a value on the stack that looks like a pointer into some code (it's an address
    // in a range covered by one of our modules). If we find such an instruction,
    // we assume it's an pc value that was pushed by the CALL instruction that created
    // the current frame. The next frame is then assumed to end just before that
    // pc value.
    let valid = &callee.context.valid;
    let last_sp = ctx.get_register(STACK_POINTER, valid)?;

    // Number of pointer-sized values to scan through in our search.
    let default_scan_range = 40;
    let extended_scan_range = default_scan_range * 4;

    // Breakpad devs found that the first frame of an unwind can be really messed up,
    // and therefore benefits from a longer scan. Let's do it too.
    let scan_range = if let FrameTrust::Context = callee.trust {
        extended_scan_range
    } else {
        default_scan_range
    };

    for i in 0..scan_range {
        let address_of_pc = last_sp.checked_add(i * POINTER_WIDTH)?;
        let caller_pc = stack_memory.get_memory_at_address(address_of_pc)?;
        if instruction_seems_valid(caller_pc, modules, symbol_provider).await {
            // pc is pushed by CALL, so sp is just address_of_pc + ptr
            let caller_sp = address_of_pc.checked_add(POINTER_WIDTH)?;

            trace!(
                "scan seems valid -- caller_pc: 0x{:08x}, caller_sp: 0x{:08x}",
                caller_pc,
                caller_sp,
            );

            let mut caller_ctx = RiscvContext::default();
            caller_ctx.set_register(PROGRAM_COUNTER, caller_pc);
            caller_ctx.set_register(STACK_POINTER, caller_sp);

            let mut valid = HashSet::new();
            valid.insert(PROGRAM_COUNTER);
            valid.insert(STACK_POINTER);

            let context = MinidumpContext {
                raw: MinidumpRawContext::Riscv64(caller_ctx),
                valid: MinidumpContextValidity::Some(valid),
            };
            return Some(StackFrame::from_context(context, FrameTrust::Scan));
        }
    }

    None
}

async fn instruction_seems_valid<P>(
    instruction: Pointer,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> bool
where
    P: SymbolProvider + Sync,
{
    super::instruction_seems_valid_by_symbols(instruction, modules, symbol_provider).await
}

#[async_trait::async_trait]
impl Unwind for RiscvContext {
    async fn get_caller_frame<P>(
        &self,
        callee: &StackFrame,
        grand_callee: Option<&StackFrame>,
        stack_memory: Option<UnifiedMemory<'_, '_>>,
        modules: &MinidumpModuleList,
        _system_info: &SystemInfo,
        syms: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider + Sync,
    {
        let stack = stack_memory?;

        // .await doesn't like closures, so don't use Option chaining
        let mut frame = None;
        if frame.is_none() {
            frame = get_caller_by_cfi(self, callee, grand_callee, stack, modules, syms).await;
        }
        if frame.is_none() {
            frame = get_caller_by_frame_pointer(self, callee, grand_callee, stack, modules, syms);
        }
        if frame.is_none() {
            frame = get_caller_by_scan(self, callee, stack, modules, syms).await;
        }
        let mut frame = frame?;

        // We now check the frame to see if it looks like unwinding is complete,
        // based on the frame we computed having a nonsense value. Returning
        // None signals to the unwinder to stop unwinding.

        // if the instruction is within the first ~page of memory, it's basically
        // null, and we can assume unwinding is complete.
        if frame.context.get_instruction_pointer() < 4096 {
            trace!("instruction pointer was nullish, assuming unwind complete");
            return None;
        }

        // If the new stack pointer is at a lower address than the old,
        // then that's clearly incorrect. Treat this as end-of-stack to
        // enforce progress and avoid infinite loops.

        let sp = frame.context.get_stack_pointer();
        let last_sp = self.get_register_always("sp");
        if sp <= last_sp {
            // Arm leaf functions may not actually touch the stack (thanks
            // to the link register allowing you to "push" the return address
            // to a register), so we need to permit the stack pointer to not
            // change for the first frame of the unwind. After that we need
            // more strict validation to avoid infinite loops.
            let is_leaf = callee.trust == FrameTrust::Context && sp == last_sp;
            if !is_leaf {
                trace!("stack pointer went backwards, assuming unwind complete");
                return None;
            }
        }

        // Ok, the frame now seems well and truly valid, do final cleanup.

        // A caller's ip is the return address, which is the instruction
        // *after* the CALL that caused us to arrive at the callee. Set
        // the value to 4 less than that, so it points to the CALL instruction
        // (arm64 instructions are all 4 bytes wide). This is important because
        // we use this value to lookup the CFI we need to unwind the next frame.
        let ip = frame.context.get_instruction_pointer();
        frame.instruction = ip - 4;

        Some(frame)
    }
}
