// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! Unwind stack frames for a thread.

mod amd64;
mod arm;
mod arm64;
mod arm64_old;
mod unwind;
mod x86;

use crate::process_state::*;
use crate::{FrameWalker, SymbolProvider};
use minidump::*;
use scroll::ctx::{SizeWith, TryFromCtx};

use self::unwind::Unwind;
use std::collections::HashSet;
use std::convert::TryFrom;

struct CfiStackWalker<'a, C: CpuContext> {
    instruction: u64,
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
        // TODO: some things have alluded to architectures where this isn't
        // how the CFA should be handled, but I don't know what they are.
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

fn get_caller_frame<P>(
    callee_frame: &StackFrame,
    grand_callee_frame: Option<&StackFrame>,
    stack_memory: Option<&MinidumpMemory>,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> Option<StackFrame>
where
    P: SymbolProvider,
{
    match callee_frame.context.raw {
        /*
        MinidumpRawContext::PPC(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::PPC64(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::SPARC(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::MIPS(ctx) => ctx.get_caller_frame(stack_memory),
         */
        MinidumpRawContext::Arm(ref ctx) => ctx.get_caller_frame(
            &callee_frame.context.valid,
            callee_frame.trust,
            stack_memory,
            grand_callee_frame,
            modules,
            symbol_provider,
        ),
        MinidumpRawContext::Arm64(ref ctx) => ctx.get_caller_frame(
            &callee_frame.context.valid,
            callee_frame.trust,
            stack_memory,
            grand_callee_frame,
            modules,
            symbol_provider,
        ),
        MinidumpRawContext::OldArm64(ref ctx) => ctx.get_caller_frame(
            &callee_frame.context.valid,
            callee_frame.trust,
            stack_memory,
            grand_callee_frame,
            modules,
            symbol_provider,
        ),
        MinidumpRawContext::Amd64(ref ctx) => ctx.get_caller_frame(
            &callee_frame.context.valid,
            callee_frame.trust,
            stack_memory,
            grand_callee_frame,
            modules,
            symbol_provider,
        ),
        MinidumpRawContext::X86(ref ctx) => ctx.get_caller_frame(
            &callee_frame.context.valid,
            callee_frame.trust,
            stack_memory,
            grand_callee_frame,
            modules,
            symbol_provider,
        ),
        _ => None,
    }
}

fn fill_source_line_info<P>(
    frame: &mut StackFrame,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) where
    P: SymbolProvider,
{
    // Find the module whose address range covers this frame's instruction.
    if let Some(module) = modules.module_at_address(frame.instruction) {
        // FIXME: this shouldn't need to clone, we should be able to use
        // the same lifetime as the module list that's passed in.
        frame.module = Some(module.clone());
        symbol_provider.fill_symbol(module, frame);
    }
}

pub fn walk_stack<P>(
    maybe_context: &Option<&MinidumpContext>,
    stack_memory: Option<&MinidumpMemory>,
    modules: &MinidumpModuleList,
    symbol_provider: &P,
) -> CallStack
where
    P: SymbolProvider,
{
    // Begin with the context frame, and keep getting callers until there are
    // no more.
    let mut frames = vec![];
    let mut info = CallStackInfo::Ok;
    if let Some(context) = *maybe_context {
        let ctx = context.clone();
        let mut maybe_frame = Some(StackFrame::from_context(ctx, FrameTrust::Context));
        while let Some(mut frame) = maybe_frame {
            fill_source_line_info(&mut frame, modules, symbol_provider);
            frames.push(frame);
            let callee_frame = &frames.last().unwrap();
            let grand_callee_frame = frames.len().checked_sub(2).and_then(|idx| frames.get(idx));
            maybe_frame = get_caller_frame(
                callee_frame,
                grand_callee_frame,
                stack_memory,
                modules,
                symbol_provider,
            );
        }
    } else {
        info = CallStackInfo::MissingContext;
    }
    CallStack {
        frames,
        info,
        thread_name: None,
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
