// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use crate::process_state::StackFrame;
use crate::{SymbolProvider, SystemInfo};
use minidump::{MinidumpMemory, MinidumpModuleList};

/// A trait for things that can unwind to a caller.
#[async_trait::async_trait]
pub trait Unwind {
    /// Get the caller frame of this frame.
    async fn get_caller_frame<P>(
        &self,
        callee: &StackFrame,
        grand_callee: Option<&StackFrame>,
        stack_memory: Option<&MinidumpMemory<'_>>,
        modules: &MinidumpModuleList,
        system_info: &SystemInfo,
        symbol_provider: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider + Sync;
}
