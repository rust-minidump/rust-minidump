// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

// NOTE: arm64_old.rs and arm64.rs should be identical except for the names of
// their context types.

use crate::process_state::{FrameTrust, StackFrame};
use crate::stackwalker::unwind::Unwind;
use crate::stackwalker::CfiStackWalker;
use crate::{SymbolProvider, SystemInfo};
use log::trace;
use minidump::{
    CpuContext, MinidumpContext, MinidumpContextValidity, MinidumpMemory, MinidumpModuleList,
    MinidumpRawContext, Module,
};
use std::collections::HashSet;

type ArmContext = minidump::format::CONTEXT_ARM64;
type Pointer = <ArmContext as CpuContext>::Register;
type Registers = minidump::format::Arm64RegisterNumbers;

const POINTER_WIDTH: Pointer = std::mem::size_of::<Pointer>() as Pointer;
const FRAME_POINTER: &str = Registers::FramePointer.name();
const STACK_POINTER: &str = Registers::StackPointer.name();
const LINK_REGISTER: &str = Registers::LinkRegister.name();
const PROGRAM_COUNTER: &str = Registers::ProgramCounter.name();
const CALLEE_SAVED_REGS: &[&str] = &[
    "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "fp",
];

async fn get_caller_by_cfi<P>(
    ctx: &ArmContext,
    callee: &StackFrame,
    grand_callee: Option<&StackFrame>,
    stack_memory: &MinidumpMemory<'_>,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    trace!("unwind: trying cfi");

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
        "unwind: cfi evaluation was successful -- caller_pc: 0x{:016x}, caller_sp: 0x{:016x}",
        caller_pc,
        caller_sp,
    );

    // Do absolutely NO validation! Yep! As long as CFI evaluation succeeds
    // (which does include pc and sp resolving), just blindly assume the
    // values are correct. I Don't Like This, but it's what breakpad does and
    // we should start with a baseline of parity.

    // FIXME?: for whatever reason breakpad actually does block on the address
    // being canonical *ONLY* for arm64, which actually rejects null pc early!
    // Let's not do that to keep our code more uniform.

    let context = MinidumpContext {
        raw: MinidumpRawContext::Arm64(stack_walker.caller_ctx),
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
    ctx: &ArmContext,
    callee: &StackFrame,
    grand_callee: Option<&StackFrame>,
    stack_memory: &MinidumpMemory<'_>,
    modules: &MinidumpModuleList,
    _symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    trace!("unwind: trying frame pointer");
    // Assume that the standard %fp-using ARM64 calling convention is in use.
    // The main quirk of this ABI is that the return address doesn't need to
    // be restored from the stack -- it's already in the link register (lr).
    // But that means we need to save/restore lr itself so that the *caller's*
    // return address can be recovered.
    //
    // In the standard calling convention, the following happens:
    //
    // PUSH fp, lr    (save fp and lr to the stack -- ARM64 pushes in pairs)
    // fp := sp       (update the frame pointer to the current stack pointer)
    // lr := pc       (save the return address in the link register)
    //
    // So to restore the caller's registers, we have:
    //
    // pc := lr
    // sp := fp + ptr*2
    // lr := *(fp + ptr)
    // fp := *fp
    let valid = &callee.context.valid;
    let last_fp = ctx.get_register(FRAME_POINTER, valid)?;
    let last_sp = ctx.get_register(STACK_POINTER, valid)?;
    let last_lr = match ctx.get_register(LINK_REGISTER, valid) {
        Some(lr) => ptr_auth_strip(modules, lr),
        None => {
            // FIXME: it would be good to write this back to the callee's ctx/validity
            get_link_register_by_frame_pointer(ctx, valid, stack_memory, grand_callee, modules)?
        }
    };

    if last_fp as u64 >= u64::MAX - POINTER_WIDTH as u64 * 2 {
        // Although this code generally works fine if the pointer math overflows,
        // debug builds will still panic, and this guard protects against it without
        // drowning the rest of the code in checked_add.
        return None;
    }

    let (caller_fp, caller_lr, caller_sp) = if last_fp == 0 {
        // In this case we want unwinding to stop. One of the termination conditions in get_caller_frame
        // is that caller_sp <= last_sp. Therefore we can force termination by setting caller_sp = last_sp.
        (0, 0, last_sp)
    } else {
        (
            stack_memory.get_memory_at_address(last_fp as u64)?,
            stack_memory.get_memory_at_address(last_fp + POINTER_WIDTH as u64)?,
            last_fp + POINTER_WIDTH * 2,
        )
    };
    let caller_lr = ptr_auth_strip(modules, caller_lr);
    let caller_pc = last_lr;

    // TODO: restore all the other callee-save registers that weren't touched.
    // unclear: does this mean we need to be aware of ".undef" entries at this point?

    // Breakpad's tests don't like it we validate the frame pointer's value,
    // so we don't check that.

    // Don't accept obviously wrong instruction pointers.
    if is_non_canonical(caller_pc) {
        trace!("unwind: rejecting frame pointer result for unreasonable instruction pointer");
        return None;
    }

    // Don't actually validate that the stack makes sense (duplicating breakpad behaviour).

    trace!(
        "unwind: frame pointer seems valid -- caller_pc: 0x{:016x}, caller_sp: 0x{:016x}",
        caller_pc,
        caller_sp,
    );

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
        raw: MinidumpRawContext::Arm64(caller_ctx),
        valid: MinidumpContextValidity::Some(valid),
    };
    Some(StackFrame::from_context(context, FrameTrust::FramePointer))
}

/// Restores the callee's link register from the stack.
fn get_link_register_by_frame_pointer(
    ctx: &ArmContext,
    valid: &MinidumpContextValidity,
    stack_memory: &MinidumpMemory<'_>,
    grand_callee: Option<&StackFrame>,
    modules: &MinidumpModuleList,
) -> Option<Pointer> {
    // It may happen that whatever unwinding strategy we're using managed to
    // restore %fp but didn't restore %lr. Frame-pointer-based unwinding requires
    // %lr because it contains the return address (the caller's %pc).
    //
    // In the standard ARM64 calling convention %fp and %lr are pushed together,
    // so if the grand-callee appears to have been called with that convention
    // then we can recover %lr using its %fp.

    // We need the grand_callee's frame pointer
    let grand_callee = grand_callee?;
    let last_last_fp = if let MinidumpRawContext::Arm64(ref ctx) = grand_callee.context.raw {
        ctx.get_register(FRAME_POINTER, &grand_callee.context.valid)?
    } else {
        return None;
    };
    let presumed_last_fp: Pointer = stack_memory.get_memory_at_address(last_last_fp as u64)?;

    // Make sure fp and sp aren't obviously garbage (are well-ordered)
    let last_fp = ctx.get_register(FRAME_POINTER, valid)?;
    let last_sp = ctx.get_register(STACK_POINTER, valid)?;
    if last_fp <= last_sp {
        return None;
    }

    // Make sure the grand-callee and callee agree on the value of fp
    if presumed_last_fp != last_fp {
        return None;
    }

    // Now that we're pretty confident that frame pointers are valid, restore
    // the callee's %lr, which should be right next to where its %fp is saved.
    let last_lr = stack_memory.get_memory_at_address(last_last_fp + POINTER_WIDTH)?;

    Some(ptr_auth_strip(modules, last_lr))
}

fn ptr_auth_strip(modules: &MinidumpModuleList, ptr: Pointer) -> Pointer {
    // ARMv8.3 introduced a code hardening system called "Pointer Authentication"
    // which is used on Apple platforms. It adds some extra high bits to the
    // several pointers when they get pushed to memory. Interestingly
    // this doesn't seem to affect return addresses pushed by a function call,
    // but it does affect lr/fp registers that get pushed to the stack.
    //
    // Rather than actually thinking about how to recover the key and properly
    // decode this, let's apply a simple heuristic. We get the maximum address
    // that's contained in a module we know about, which will have some highest
    // bit that is set. We can then safely mask out any bit that's higher than
    // that one, which will hopefully mask out all the weird security stuff
    // in the high bits.
    if let Some(last_module) = modules.by_addr().next_back() {
        // Get the highest mappable address
        let mut mask = last_module.base_address() + last_module.size();
        // Repeatedly OR this value with its shifted self to "smear" its
        // highest set bit down to all lower bits. This will get us a
        // mask we can use to AND out any bits that are higher.
        mask |= mask >> 1;
        mask |= mask >> 1;
        mask |= mask >> 2;
        mask |= mask >> 4;
        mask |= mask >> 8;
        mask |= mask >> 16;
        mask |= mask >> 32;
        let stripped = ptr & mask;

        // Only actually use this stripped value if it ended up pointing in
        // a module so we don't start corrupting normal pointers that are just
        // in modules we don't know about.
        if modules.module_at_address(stripped).is_some() {
            // trace!("unwind: stripped pointer {:016x} -> {:016x}", ptr, stripped);
            return stripped;
        }
    }

    ptr
}

async fn get_caller_by_scan<P>(
    ctx: &ArmContext,
    callee: &StackFrame,
    stack_memory: &MinidumpMemory<'_>,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    trace!("unwind: trying scan");
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
        let caller_pc = stack_memory.get_memory_at_address(address_of_pc as u64)?;
        if instruction_seems_valid(caller_pc, modules, symbol_provider).await {
            // pc is pushed by CALL, so sp is just address_of_pc + ptr
            let caller_sp = address_of_pc.checked_add(POINTER_WIDTH)?;

            // Don't do any more validation, and don't try to restore fp
            // (that's what breakpad does!)

            trace!(
                "unwind: scan seems valid -- caller_pc: 0x{:08x}, caller_sp: 0x{:08x}",
                caller_pc,
                caller_sp,
            );

            let mut caller_ctx = ArmContext::default();
            caller_ctx.set_register(PROGRAM_COUNTER, caller_pc);
            caller_ctx.set_register(STACK_POINTER, caller_sp);

            let mut valid = HashSet::new();
            valid.insert(PROGRAM_COUNTER);
            valid.insert(STACK_POINTER);

            let context = MinidumpContext {
                raw: MinidumpRawContext::Arm64(caller_ctx),
                valid: MinidumpContextValidity::Some(valid),
            };
            return Some(StackFrame::from_context(context, FrameTrust::Scan));
        }
    }

    None
}

/// The most strict validation we have for instruction pointers.
///
/// This is only used for stack-scanning, because it's explicitly
/// trying to distinguish between total garbage and correct values.
/// cfi and frame_pointer approaches do not use this validation
/// because by default they're working with plausible/trustworthy
/// data.
///
/// Specifically, not using this validation allows cfi/fp methods
/// to unwind through frames we don't have mapped modules for (such as
/// OS APIs). This may seem confusing since we obviously don't have cfi
/// for unmapped modules!
///
/// The way this works is that we will use cfi to unwind some frame we
/// know about and *end up* in a function we know nothing about, but with
/// all the right register values. At this point, frame pointers will
/// often do the correct thing even though we don't know what code we're
/// in -- until we get back into code we do know about and cfi kicks back in.
/// At worst, this sets scanning up in a better position for success!
///
/// If we applied this more rigorous validation to cfi/fp methods, we
/// would just discard the correct register values from the known frame
/// and immediately start doing unreliable scans.
async fn instruction_seems_valid<P>(
    instruction: Pointer,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> bool
where
    P: SymbolProvider + Sync,
{
    if is_non_canonical(instruction) || instruction == 0 {
        return false;
    }

    super::instruction_seems_valid_by_symbols(instruction as u64, modules, symbol_provider).await
}

fn is_non_canonical(instruction: Pointer) -> bool {
    // Reject instructions in the first page or above the user-space threshold.
    !(0x1000..=0x000fffffffffffff).contains(&instruction)
}

/*
// ARM64 is currently hyper-permissive, so we don't use this,
// but here it is in case we change our minds!
fn stack_seems_valid(
    caller_sp: Pointer,
    callee_sp: Pointer,
    stack_memory: &MinidumpMemory<'_>,
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
*/

#[async_trait::async_trait]
impl Unwind for ArmContext {
    async fn get_caller_frame<P>(
        &self,
        callee: &StackFrame,
        grand_callee: Option<&StackFrame>,
        stack_memory: Option<&MinidumpMemory<'_>>,
        modules: &MinidumpModuleList,
        _system_info: &SystemInfo,
        syms: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider + Sync,
    {
        let stack = stack_memory.as_ref()?;

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
            trace!("unwind: instruction pointer was nullish, assuming unwind complete");
            return None;
        }

        // If the new stack pointer is at a lower address than the old,
        // then that's clearly incorrect. Treat this as end-of-stack to
        // enforce progress and avoid infinite loops.

        let sp = frame.context.get_stack_pointer();
        let last_sp = self.get_register_always("sp") as u64;
        if sp <= last_sp {
            // Arm leaf functions may not actually touch the stack (thanks
            // to the link register allowing you to "push" the return address
            // to a register), so we need to permit the stack pointer to not
            // change for the first frame of the unwind. After that we need
            // more strict validation to avoid infinite loops.
            let is_leaf = callee.trust == FrameTrust::Context && sp == last_sp;
            if !is_leaf {
                trace!("unwind: stack pointer went backwards, assuming unwind complete");
                return None;
            }
        }

        // Ok, the frame now seems well and truly valid, do final cleanup.

        // A caller's ip is the return address, which is the instruction
        // *after* the CALL that caused us to arrive at the callee. Set
        // the value to 4 less than that, so it points to the CALL instruction
        // (arm64 instructions are all 4 bytes wide). This is important because
        // we use this value to lookup the CFI we need to unwind the next frame.
        let ip = frame.context.get_instruction_pointer() as u64;
        frame.instruction = ip - 4;

        Some(frame)
    }
}
