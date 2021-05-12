// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use crate::process_state::{FrameTrust, StackFrame};
use crate::SymbolProvider;
use minidump::{MinidumpContextValidity, MinidumpMemory, MinidumpModuleList};

/// A trait for things that can unwind to a caller.
pub trait Unwind {
    /// Get the caller frame of this frame.
    fn get_caller_frame<P>(
        &self,
        valid: &MinidumpContextValidity,
        trust: FrameTrust,
        stack_memory: Option<&MinidumpMemory>,
        grand_callee_frame: Option<&StackFrame>,
        modules: &MinidumpModuleList,
        symbol_provider: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider;
}
