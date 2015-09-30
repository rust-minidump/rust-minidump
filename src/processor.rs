// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use chrono::{TimeZone,UTC};
use minidump::*;
use process_state::ProcessState;

/// An error encountered during minidump processing.
#[derive(Debug)]
pub enum ProcessError {
    /// An unknown error.
    UnknownError,
}

/// Unwind all threads in `dump` and return a `ProcessState`.
pub fn process_minidump(mut dump : &Minidump) -> Result<ProcessState, ProcessError> {
    // Get process create time
    let process_create_time = 0;
    // Get CPU info
    // Get OS info
    // Get Breakpad info
    // - Get dump thread ID
    // - Get requesting thread ID
    // Get exception
    let crashed = false;
    // - Get crashing thread
    // - Get crash reason
    let crash_reason = None;
    let crash_address = None;
    // Get assertion
    let assertion = None;
    // Get module list
    // Get memory list
    // Get thread list
    // for each thread:
    // - if dump thread, skip
    // - if requesting thread and have exception, use exception context,
    //   else use thread context
    // - walk stack using stackwalker
    // - save call stack
    // if exploitability enabled, run exploitability analysis
    if true {
        return Err(ProcessError::UnknownError);
    }
    Ok(ProcessState {
        time: UTC.timestamp(dump.header.time_date_stamp as i64, 0),
        process_create_time: UTC.timestamp(process_create_time as i64, 0),
        crashed: crashed,
        crash_reason: crash_reason,
        crash_address: crash_address,
        assertion: assertion,
    })
}
