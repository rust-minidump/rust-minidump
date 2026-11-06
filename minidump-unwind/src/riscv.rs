use super::impl_prelude::*;
use minidump::{
    CpuContext, Endian, MinidumpContext, MinidumpContextValidity, MinidumpModuleList,
    MinidumpRawContext,
};
use scroll::ctx::{SizeWith, TryFromCtx};
use std::collections::HashSet;
use std::convert::TryFrom;
use tracing::trace;

type RiscvContext = minidump::format::CONTEXT_RISCV;
type Riscv64Context = minidump::format::CONTEXT_RISCV64;

const STACK_POINTER: &str = "sp";
const PROGRAM_COUNTER: &str = "pc";
const CALLEE_SAVED_REGS: &[&str] = &[
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
];

/// How far to step back from a return address to land on the call that
/// produced it.
///
/// A return address points just past the call instruction, and the next
/// frame's CFI rows are looked up at the call site, so the step back has
/// to land inside the calling instruction. Breakpad's original RISC-V
/// walkers subtract 4 here, on the assumption that RISC-V instructions
/// are uniformly 4 bytes. The C extension breaks that assumption: it
/// compresses calls to 2 bytes (`c.jal` on RV32, `c.jalr` on both
/// widths), so a 4-byte step can land in the instruction before the
/// call, or in the previous function, and select the wrong CFI rows.
/// Two is the largest step that stays inside the call for every
/// encoding. The compressed-call test pins this.
const CALL_SITE_ADJUSTMENT: u64 = 2;

async fn get_caller_by_cfi<'a, C, P>(
    ctx: &'a C,
    args: &'a GetCallerFrameArgs<'a, P>,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
    // all these bounds are essentially duplicated from `CfiStackWalker` :-(
    C: CpuContext + IntoRawContext + Clone + Send + Sync,
    C::Register: TryFrom<u64>,
    u64: TryFrom<C::Register>,
    C::Register: TryFromCtx<'a, Endian, [u8], Error = scroll::Error> + SizeWith<Endian>,
{
    trace!("trying cfi");

    let _last_sp = ctx.get_register(STACK_POINTER, args.valid())?;

    let mut stack_walker = CfiStackWalker::from_ctx_and_args(ctx, args, callee_forwarded_regs)?;

    args.symbol_provider
        .walk_frame(stack_walker.module, &mut stack_walker)
        .await?;
    let caller_pc = stack_walker.caller_ctx.get_register_always(PROGRAM_COUNTER);
    let caller_sp = stack_walker.caller_ctx.get_register_always(STACK_POINTER);

    trace!(
        "cfi evaluation was successful -- caller_pc: 0x{caller_pc:016x}, caller_sp: 0x{caller_sp:016x}"
    );

    // Do absolutely NO validation! Yep! As long as CFI evaluation succeeds
    // (which does include pc and sp resolving), just blindly assume the
    // values are correct. I Don't Like This, but it's what breakpad does and
    // we should start with a baseline of parity.

    let context = MinidumpContext {
        raw: stack_walker.caller_ctx.into_ctx(),
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

async fn get_caller_by_scan<'a, C, P>(
    ctx: &'a C,
    args: &'a GetCallerFrameArgs<'a, P>,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
    C: CpuContext + IntoRawContext + Default,
    C::Register: TryFrom<u64>,
    u64: TryFrom<C::Register>,
    C::Register: TryFromCtx<'a, Endian, [u8], Error = scroll::Error> + SizeWith<Endian>,
{
    trace!("trying scan");
    // Stack scanning is just walking from the end of the frame until we encounter
    // a value on the stack that looks like a pointer into some code (it's an address
    // in a range covered by one of our modules). If we find such a value, we assume
    // it's a return address that was saved on the stack by the callee in its
    // function prologue, following a call instruction of the caller. The next
    // frame is then assumed to end just past that return address.
    let last_sp = u64::try_from(ctx.get_register(STACK_POINTER, args.valid())?).ok()?;

    let pointer_width = std::mem::size_of::<C::Register>() as u64;

    // Number of pointer-sized values to scan through in our search.
    let default_scan_range: u64 = 40;
    let extended_scan_range = default_scan_range * 4;

    // Breakpad devs found that the first frame of an unwind can be really messed up,
    // and therefore benefits from a longer scan. Let's do it too.
    // Additionally, especially with JIT code, using an extended scan range when coming
    // from a trusted source allows skipping over undetectable JIT frames.
    let scan_range =
        if let FrameTrust::Context | FrameTrust::CallFrameInfo = args.callee_frame.trust {
            extended_scan_range
        } else {
            default_scan_range
        };

    for i in 0..scan_range {
        let address_of_pc = last_sp.checked_add(i * pointer_width)?;
        let caller_pc: C::Register = args.stack_memory.get_memory_at_address(address_of_pc)?;
        let caller_pc_u64 = u64::try_from(caller_pc).ok()?;
        if instruction_seems_valid(caller_pc_u64, args.modules, args.symbol_provider).await {
            // The return address is usually saved directly at the bottom of
            // the callee's frame, so sp is just address_of_pc + ptr
            let caller_sp = address_of_pc.checked_add(pointer_width)?;

            // Don't do any more validation (that's what breakpad does!)

            trace!(
                "scan seems valid -- caller_pc: 0x{caller_pc_u64:08x}, caller_sp: 0x{caller_sp:08x}"
            );

            let mut caller_ctx = C::default();
            caller_ctx.set_register(PROGRAM_COUNTER, C::Register::try_from(caller_pc_u64).ok()?)?;
            caller_ctx.set_register(STACK_POINTER, C::Register::try_from(caller_sp).ok()?)?;

            let mut valid = HashSet::new();
            valid.insert(PROGRAM_COUNTER);
            valid.insert(STACK_POINTER);

            let context = MinidumpContext {
                raw: caller_ctx.into_ctx(),
                valid: MinidumpContextValidity::Some(valid),
            };
            return Some(StackFrame::from_context(context, FrameTrust::Scan));
        }
    }

    None
}

async fn instruction_seems_valid<P>(
    instruction: u64,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> bool
where
    P: SymbolProvider + Sync,
{
    // Reject addresses in the first page: they are effectively null.
    // Bare-metal images can be linked at 0 (a softcore whose RAM starts
    // there has its whole text in the first page), so only reject an
    // address that no module covers. The null values themselves are
    // still rejected by `instruction_seems_valid_by_symbols`.
    if instruction < 0x1000 && modules.module_at_address(instruction).is_none() {
        return false;
    }

    super::instruction_seems_valid_by_symbols(instruction, modules, symbol_provider).await
}

async fn get_caller_frame_impl<'a, C, P>(
    ctx: &'a C,
    args: &'a GetCallerFrameArgs<'a, P>,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
    C: CpuContext + IntoRawContext + Default + Clone + Send + Sync,
    C::Register: TryFrom<u64>,
    u64: TryFrom<C::Register>,
    C::Register: TryFromCtx<'a, Endian, [u8], Error = scroll::Error> + SizeWith<Endian>,
{
    // .await doesn't like closures, so don't use Option chaining
    let mut frame = None;
    if frame.is_none() {
        frame = get_caller_by_cfi(ctx, args).await;
    }
    if frame.is_none() {
        frame = get_caller_by_scan(ctx, args).await;
    }
    let mut frame = frame?;

    // We now check the frame to see if it looks like unwinding is complete,
    // based on the frame we computed having a nonsense value. Returning
    // None signals to the unwinder to stop unwinding.

    // If the instruction is within the first ~page of memory, it's basically
    // null, and we can assume unwinding is complete -- unless a module is
    // actually linked that low, which bare-metal images do (a softcore
    // whose RAM starts at 0 has its whole text in that page). Addresses 0
    // and 1 are null no matter what: the shortest call encoding is two
    // bytes, so no return address can be smaller than 2.
    let caller_pc = frame.context.get_instruction_pointer();
    let outside_modules = args.modules.module_at_address(caller_pc).is_none();
    if caller_pc < 2 || (caller_pc < 4096 && outside_modules) {
        trace!("instruction pointer was nullish, assuming unwind complete");
        return None;
    }

    // If the new stack pointer is at a lower address than the old,
    // then that's clearly incorrect. Treat this as end-of-stack to
    // enforce progress and avoid infinite loops.

    let sp = frame.context.get_stack_pointer();
    let last_sp = u64::try_from(ctx.get_register_always(STACK_POINTER)).ok()?;
    if sp <= last_sp {
        // RISC-V leaf functions may not actually touch the stack (the
        // return address travels in `ra`, not memory), so we need to permit
        // the stack pointer to not change for the first frame of the unwind.
        // After that we need more strict validation to avoid infinite loops.
        let is_leaf = args.callee_frame.trust == FrameTrust::Context && sp == last_sp;
        if !is_leaf {
            trace!("stack pointer went backwards, assuming unwind complete");
            return None;
        }
    }

    // Ok, the frame now seems well and truly valid, do final cleanup.

    let ip = frame.context.get_instruction_pointer();
    frame.instruction = ip - CALL_SITE_ADJUSTMENT;

    Some(frame)
}

pub async fn get_caller_frame<P>(
    ctx: &RiscvContext,
    args: &GetCallerFrameArgs<'_, P>,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    get_caller_frame_impl(ctx, args).await
}

pub async fn get_caller_frame64<P>(
    ctx: &Riscv64Context,
    args: &GetCallerFrameArgs<'_, P>,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    get_caller_frame_impl(ctx, args).await
}

trait IntoRawContext {
    fn into_ctx(self) -> MinidumpRawContext;
}

impl IntoRawContext for RiscvContext {
    fn into_ctx(self) -> MinidumpRawContext {
        MinidumpRawContext::Riscv(self)
    }
}

impl IntoRawContext for Riscv64Context {
    fn into_ctx(self) -> MinidumpRawContext {
        MinidumpRawContext::Riscv64(self)
    }
}
