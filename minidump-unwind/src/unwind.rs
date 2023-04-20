// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use super::{StackFrame, SymbolProvider, SystemInfo};
use minidump::{MinidumpModuleList, UnifiedMemory};

/// A trait for things that can unwind to a caller.
#[async_trait::async_trait]
pub trait Unwind {
    /// Get the caller frame of this frame.
    async fn get_caller_frame<P>(
        &self,
        callee: &StackFrame,
        grand_callee: Option<&StackFrame>,
        stack_memory: Option<UnifiedMemory<'_, '_>>,
        modules: &MinidumpModuleList,
        system_info: &SystemInfo,
        symbol_provider: &P,
    ) -> Option<StackFrame>
    where
        P: SymbolProvider + Sync;
}
