// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! Unwind stack frames for a thread.

use minidump::*;
use process_state::StackFrame;

fn get_context_frame() -> Option<StackFrame> {
    None
}

fn get_caller_frame(frame : &StackFrame) -> Option<StackFrame> {
    None
}

fn fill_source_line_info(frame : &mut StackFrame,
                         module_list : &Option<MinidumpModuleList>) {
    if let &Some(ref modules) = module_list {
        // get module at frame instruction
        if let &Some(module) = &modules.module_at_address(frame.instruction) {
            frame.module = Some(module.clone());
            // see if we have symbols for this module
            // - if not, see if we can find symbols for this module
            // -- if so, load them
            // - fill in info using symbols
        }
    }
}

pub fn walk_stack(context : &Option<MinidumpContext>,
                  stack : &Option<MinidumpMemory>,
                  modules : &Option<MinidumpModuleList>) -> Vec<StackFrame> {
    // context, memory, modules, symbolizer
    // Begin with the context frame, and keep getting callers until there are
    // no more.
    let mut frames = vec!();
    let mut maybe_frame = get_context_frame();
    while let Some(mut frame) = maybe_frame {
        // TODO: provide a SourceLineResolver trait?
        fill_source_line_info(&mut frame, modules);
        frames.push(frame);
        maybe_frame = get_caller_frame(&frames.last().unwrap());
    }
    frames
}
