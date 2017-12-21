// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use minidump::{MinidumpContextValidity,MinidumpMemory};
use process_state::StackFrame;

/// A trait for things that can unwind to a caller.
pub trait Unwind {
    /// Get the caller frame of this frame.
    fn get_caller_frame(&self,
                        valid : &MinidumpContextValidity,
                        stack_memory : &Option<MinidumpMemory>) -> Option<StackFrame>;
}
