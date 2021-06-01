// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use crate::process_state::{FrameTrust, StackFrame};
use crate::SymbolProvider;
use minidump::{MinidumpContextValidity, MinidumpMemory, MinidumpModuleList};

use async_trait::async_trait;

/// A trait for things that can unwind to a caller.
#[async_trait(?Send)]
pub trait Unwind {
    /// Get the caller frame of this frame.
    async fn get_caller_frame<P>(
        &self,
        valid: &MinidumpContextValidity,
        trust: FrameTrust,
        stack_memory: Option<&MinidumpMemory<'_>>,
        grand_callee_frame: Option<&StackFrame>,
        modules: &MinidumpModuleList,
        symbol_provider: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider;
}
