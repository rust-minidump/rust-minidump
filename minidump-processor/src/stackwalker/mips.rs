use std::collections::HashSet;

use log::trace;
use minidump::{
    CpuContext, MinidumpContext, MinidumpContextValidity, MinidumpMemory, MinidumpModuleList,
    MinidumpRawContext,
};

use crate::stackwalker::unwind::Unwind;
use crate::stackwalker::CfiStackWalker;
use crate::{FrameTrust, StackFrame, SymbolProvider, SystemInfo};

type MipsContext = minidump::format::CONTEXT_MIPS;
type Pointer = <MipsContext as CpuContext>::Register;
type Registers = minidump::format::MipsRegisterNumbers;

const POINTER_WIDTH: Pointer = std::mem::size_of::<Pointer>() as Pointer;
const FRAME_POINTER: &str = Registers::FramePointer.name();
const STACK_POINTER: &str = "sp";
const PROGRAM_COUNTER: &str = "pc";
const RETURN_ADDR: &str = "ra";
const CALLEE_SAVED_REGS: &[&str] = &[
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "gp", "sp", "fp",
];

/*"$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$to", "$t1",
"$t2",   "$t3", "$t4", "$t5", "$t6", "$t7", "$s0", "$s1", "$s2", "$s3",
"$s4",   "$s5", "$s6", "$s7", "$t8", "$t9", "$k0", "$k1", "$gp", "$sp",
"$fp",   "$ra",*/

async fn get_caller_by_cfi<P>(
    ctx: &MipsContext,
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
    let caller_ra = stack_walker.caller_ctx.get_register_always(RETURN_ADDR);
    let caller_sp = stack_walker.caller_ctx.get_register_always(STACK_POINTER);

    if instruction_seems_valid(caller_ra, modules, symbol_provider).await {
        stack_walker
            .caller_ctx
            .set_register(PROGRAM_COUNTER, caller_ra - 2 * POINTER_WIDTH);
    }

    trace!(
        "unwind: cfi evaluation was successful -- caller_ra: {caller_ra:#016x}, caller_sp: {caller_sp:#016x}"
    );

    // Do absolutely NO validation! Yep! As long as CFI evaluation succeeds
    // (which does include pc and sp resolving), just blindly assume the
    // values are correct. I Don't Like This, but it's what breakpad does and
    // we should start with a baseline of parity.

    let context = MinidumpContext {
        raw: MinidumpRawContext::Mips(stack_walker.caller_ctx),
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

async fn get_caller_for_leaf<P>(
    ctx: &MipsContext,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    trace!("unwind: trying leaf function context");

    let return_addr = ctx.get_register_always(RETURN_ADDR);
    if instruction_seems_valid(return_addr, modules, symbol_provider).await {
        let mut caller_ctx = ctx.clone();
        caller_ctx.set_register(PROGRAM_COUNTER, return_addr - 8);

        let mut valid = HashSet::new();
        valid.insert(PROGRAM_COUNTER);
        valid.insert(STACK_POINTER);

        let context = MinidumpContext {
            raw: MinidumpRawContext::Mips(caller_ctx),
            valid: MinidumpContextValidity::Some(valid),
        };
        return Some(StackFrame::from_context(context, FrameTrust::FramePointer));
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
    if instruction < 0x1000 {
        return false;
    }

    super::instruction_seems_valid_by_symbols(instruction as u64, modules, symbol_provider).await
}

#[async_trait::async_trait]
impl Unwind for MipsContext {
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
        // if we are at the context frame, we try to take the RA directly from the registers
        // if frame.is_none() && grand_callee.is_none() {
        //     frame = get_caller_for_leaf(self, modules, syms).await;
        // }
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
        let last_sp = self.get_register_always(STACK_POINTER) as u64;
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

        let ip = frame.context.get_instruction_pointer() as u64;
        frame.instruction = ip - 8;

        Some(frame)
    }
}
