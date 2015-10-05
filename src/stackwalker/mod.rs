// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! Unwind stack frames for a thread.

use minidump::*;
use process_state::{CallStack,CallStackInfo,StackFrame};

// TODO: this probably needs to be on a trait so we can have per-CPU
// implementations.
fn get_caller_frame(_frame : &StackFrame,
                    _stack_memory : &Option<MinidumpMemory>) -> Option<StackFrame> {
    None
}

fn fill_source_line_info(frame : &mut StackFrame,
                         modules : &MinidumpModuleList) {
    // get module at frame instruction
    if let &Some(module) = &modules.module_at_address(frame.instruction) {
        // FIXME: this shouldn't need to clone, we should be able to use
        // the same lifetime as the module list that's passed in.
        frame.module = Some(module.clone());
        // see if we have symbols for this module
        // - if not, see if we can find symbols for this module
        // -- if so, load them
        // - fill in info using symbols
    }
}

pub fn walk_stack(maybe_context : &Option<&MinidumpContext>,
                  stack_memory : &Option<MinidumpMemory>,
                  modules : &MinidumpModuleList) -> CallStack {
    // context, memory, modules, symbolizer
    // Begin with the context frame, and keep getting callers until there are
    // no more.
    let mut frames = vec!();
    let mut info = CallStackInfo::Ok;
    if let &Some(ref context) = maybe_context {
        let mut maybe_frame = Some(StackFrame::from_context(&context));
        while let Some(mut frame) = maybe_frame {
            // TODO: provide a SourceLineResolver trait?
            fill_source_line_info(&mut frame, modules);
            frames.push(frame);
            maybe_frame = get_caller_frame(&frames.last().unwrap(),
                                           stack_memory);
        }
    } else {
        info = CallStackInfo::MissingContext;
    }
    CallStack { frames: frames, info: info }
}
