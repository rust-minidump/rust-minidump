// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use crate::process_state::StackFrame;
use crate::SymbolProvider;
use minidump::{MinidumpMemory, MinidumpModuleList};

/// A trait for things that can unwind to a caller.
pub trait Unwind {
    /// Get the caller frame of this frame.
    fn get_caller_frame<P>(
        &self,
        callee: &StackFrame,
        grand_callee: Option<&StackFrame>,
        stack_memory: Option<&MinidumpMemory>,
        modules: &MinidumpModuleList,
        symbol_provider: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider;
}
