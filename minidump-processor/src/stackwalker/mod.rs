// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! Unwind stack frames for a thread.

mod unwind;
mod x86;

use minidump::*;
use crate::process_state::*;
use crate::SymbolProvider;

use self::unwind::Unwind;

fn get_caller_frame(
    frame: &StackFrame,
    stack_memory: &Option<MinidumpMemory>,
) -> Option<StackFrame> {
    match frame.context.raw {
        /*
        MinidumpRawContext::AMD64(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::ARM(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::ARM64(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::PPC(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::PPC64(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::SPARC(ctx) => ctx.get_caller_frame(stack_memory),
        MinidumpRawContext::MIPS(ctx) => ctx.get_caller_frame(stack_memory),
         */
        MinidumpRawContext::X86(ref ctx) => {
            ctx.get_caller_frame(&frame.context.valid, stack_memory)
        }
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
    stack_memory: &Option<MinidumpMemory>,
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
            let last_frame = &frames.last().unwrap();
            maybe_frame = get_caller_frame(last_frame, stack_memory);
        }
    } else {
        info = CallStackInfo::MissingContext;
    }
    CallStack { frames, info }
}

#[cfg(test)]
mod x86_unittest;
