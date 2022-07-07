// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! Unwind stack frames for a thread.

mod amd64;
mod arm;
mod arm64;
mod arm64_old;
mod mips;
mod unwind;
mod x86;

use crate::process_state::*;
use crate::{FrameWalker, SymbolProvider, SystemInfo};
use minidump::*;
use scroll::ctx::{SizeWith, TryFromCtx};
use tracing::trace;

use self::unwind::Unwind;
use std::collections::HashSet;
use std::convert::TryFrom;

struct CfiStackWalker<'a, C: CpuContext> {
    instruction: u64,
    has_grand_callee: bool,
    grand_callee_parameter_size: u32,

    callee_ctx: &'a C,
    callee_validity: &'a MinidumpContextValidity,

    caller_ctx: C,
    caller_validity: HashSet<&'static str>,

    stack_memory: &'a MinidumpMemory<'a>,
}

impl<'a, C> FrameWalker for CfiStackWalker<'a, C>
where
    C: CpuContext,
    C::Register: TryFrom<u64>,
    u64: TryFrom<C::Register>,
    C::Register: TryFromCtx<'a, Endian, [u8], Error = scroll::Error> + SizeWith<Endian>,
{
    fn get_instruction(&self) -> u64 {
        self.instruction
    }
    fn has_grand_callee(&self) -> bool {
        self.has_grand_callee
    }
    fn get_grand_callee_parameter_size(&self) -> u32 {
        self.grand_callee_parameter_size
    }
    fn get_register_at_address(&self, address: u64) -> Option<u64> {
        let result: Option<C::Register> = self.stack_memory.get_memory_at_address(address);
        result.and_then(|val| u64::try_from(val).ok())
    }
    fn get_callee_register(&self, name: &str) -> Option<u64> {
        self.callee_ctx
            .get_register(name, self.callee_validity)
            .and_then(|val| u64::try_from(val).ok())
    }
    fn set_caller_register(&mut self, name: &str, val: u64) -> Option<()> {
        let memoized = self.caller_ctx.memoize_register(name)?;
        let val = C::Register::try_from(val).ok()?;
        self.caller_validity.insert(memoized);
        self.caller_ctx.set_register(name, val)
    }
    fn clear_caller_register(&mut self, name: &str) {
        self.caller_validity.remove(name);
    }
    fn set_cfa(&mut self, val: u64) -> Option<()> {
        // NOTE: some things have alluded to architectures where this isn't
        // how the CFA should be handled, but we apparently don't support them yet?
        let stack_pointer_reg = self.caller_ctx.stack_pointer_register_name();
        let val = C::Register::try_from(val).ok()?;
        self.caller_validity.insert(stack_pointer_reg);
        self.caller_ctx.set_register(stack_pointer_reg, val)
    }
    fn set_ra(&mut self, val: u64) -> Option<()> {
        let instruction_pointer_reg = self.caller_ctx.instruction_pointer_register_name();
        let val = C::Register::try_from(val).ok()?;
        self.caller_validity.insert(instruction_pointer_reg);
        self.caller_ctx.set_register(instruction_pointer_reg, val)
    }
}

async fn get_caller_frame<P>(
    callee_frame: &StackFrame,
    grand_callee_frame: Option<&StackFrame>,
    stack_memory: Option<&MinidumpMemory<'_>>,
    modules: &MinidumpModuleList,
    system_info: &SystemInfo,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider + Sync,
{
    match callee_frame.context.raw {
        /*
        MinidumpRawContext::PPC(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::PPC64(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::SPARC(ctx) => ctx.get_caller_frame(stack_memory),
         */
        MinidumpRawContext::Arm(ref ctx) => {
            ctx.get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                system_info,
                symbol_provider,
            )
            .await
        }
        MinidumpRawContext::Arm64(ref ctx) => {
            ctx.get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                system_info,
                symbol_provider,
            )
            .await
        }
        MinidumpRawContext::OldArm64(ref ctx) => {
            ctx.get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                system_info,
                symbol_provider,
            )
            .await
        }
        MinidumpRawContext::Amd64(ref ctx) => {
            ctx.get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                system_info,
                symbol_provider,
            )
            .await
        }
        MinidumpRawContext::X86(ref ctx) => {
            ctx.get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                system_info,
                symbol_provider,
            )
            .await
        }
        MinidumpRawContext::Mips(ref ctx) => {
            ctx.get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                system_info,
                symbol_provider,
            )
            .await
        }
        _ => None,
    }
}

async fn fill_source_line_info<P>(
    frame: &mut StackFrame,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) where
    P: SymbolProvider + Sync,
{
    // Find the module whose address range covers this frame's instruction.
    if let Some(module) = modules.module_at_address(frame.instruction) {
        // FIXME: this shouldn't need to clone, we should be able to use
        // the same lifetime as the module list that's passed in.
        frame.module = Some(module.clone());

        // This is best effort, so ignore any errors.
        let _ = symbol_provider.fill_symbol(module, frame).await;
    }
}

#[tracing::instrument(name = "unwind", level = "trace", skip_all, fields(tid = thread_id, name = thread_name.unwrap_or("")))]
pub async fn walk_stack<P>(
    thread_id: u32,
    thread_name: Option<&str>,
    maybe_context: &Option<&MinidumpContext>,
    stack_memory: Option<&MinidumpMemory<'_>>,
    modules: &MinidumpModuleList,
    system_info: &SystemInfo,
    symbol_provider: &P,
) -> CallStack
where
    P: SymbolProvider + Sync,
{
    // Begin with the context frame, and keep getting callers until there are
    // no more.
    let mut frames = vec![];
    let mut info = CallStackInfo::Ok;
    if let Some(context) = *maybe_context {
        trace!(
            "starting stack unwind of thread {} {}",
            thread_id,
            thread_name.unwrap_or("")
        );
        let ctx = context.clone();
        let mut maybe_frame = Some(StackFrame::from_context(ctx, FrameTrust::Context));
        while let Some(mut frame) = maybe_frame {
            fill_source_line_info(&mut frame, modules, symbol_provider).await;
            match frame.function_name.as_ref() {
                Some(name) => trace!("unwinding {}", name),
                None => trace!("unwinding 0x{:016x}", frame.instruction),
            }
            frames.push(frame);
            let callee_frame = &frames.last().unwrap();
            let grand_callee_frame = frames.len().checked_sub(2).and_then(|idx| frames.get(idx));
            maybe_frame = get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                system_info,
                symbol_provider,
            )
            .await;
        }
        trace!(
            "finished stack unwind of thread {} {}\n",
            thread_id,
            thread_name.unwrap_or("")
        );
    } else {
        info = CallStackInfo::MissingContext;
    }

    CallStack {
        frames,
        info,
        thread_id: 0,
        thread_name: None,
        last_error_value: None,
    }
}

/// Checks if we can dismiss the validity of an instruction based on our symbols,
/// to refine the quality of each unwinder's instruction_seems_valid implementation.
async fn instruction_seems_valid_by_symbols<P>(
    instruction: u64,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> bool
where
    P: SymbolProvider + Sync,
{
    // Our input is a candidate return address, but we *really* want to validate the address
    // of the call instruction *before* the return address. In theory this symbol-based
    // analysis shouldn't *care* whether we're looking at the call or the instruction
    // after it, but there is one corner case where the return address can be invalid
    // but the instruction before it isn't: noreturn.
    //
    // If the *callee* is noreturn, then the caller has no obligation to have any instructions
    // after the call! So e.g. on x86 if you CALL a noreturn function, the return address
    // that's implicitly pushed *could* be one-past-the-end of the "function".
    //
    // This has been observed in practice with `+[NSThread exit]`!
    //
    // We don't otherwise need the instruction pointer to be terribly precise, so
    // subtracting 1 from the address should be sufficient to handle this corner case.
    let instruction = instruction.saturating_sub(1);

    // NULL pointer is definitely not valid
    if instruction == 0 {
        return false;
    }

    if let Some(module) = modules.module_at_address(instruction as u64) {
        // Create a dummy frame symbolizing implementation to feed into
        // our symbol provider with the address we're interested in. If
        // it tries to set a non-empty function name, then we can reasonably
        // assume the instruction address is valid.
        use crate::FrameSymbolizer;

        struct DummyFrame {
            instruction: u64,
            has_name: bool,
        }
        impl FrameSymbolizer for DummyFrame {
            fn get_instruction(&self) -> u64 {
                self.instruction
            }
            fn set_function(&mut self, name: &str, _base: u64, _parameter_size: u32) {
                self.has_name = !name.is_empty();
            }
            fn set_source_file(&mut self, _file: &str, _line: u32, _base: u64) {
                // Do nothing
            }
        }

        let mut frame = DummyFrame {
            instruction: instruction as u64,
            has_name: false,
        };

        if symbol_provider
            .fill_symbol(module, &mut frame)
            .await
            .is_ok()
        {
            frame.has_name
        } else {
            // If the symbol provider returns an Error, this means that we
            // didn't have any symbols for the *module*. Just assume the
            // instruction is valid in this case so that scanning works
            // when we have no symbols.
            true
        }
    } else {
        // We couldn't even map this address to a module. Reject the pointer
        // so that we have *some* way to distinguish "normal" pointers
        // from instruction address.
        //
        // FIXME: this will reject any pointer into JITed code which otherwise
        // isn't part of a normal well-defined module. We can potentially use
        // MemoryInfoListStream (windows) and /proc/self/maps (linux) to refine
        // this analysis and allow scans to walk through JITed code.
        false
    }
}

#[cfg(test)]
mod amd64_unittest;
#[cfg(test)]
mod arm64_unittest;
#[cfg(test)]
mod arm_unittest;
#[cfg(test)]
mod x86_unittest;
