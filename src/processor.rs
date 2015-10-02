// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use chrono::{TimeZone,UTC};
use minidump::*;
use process_state::ProcessState;
use system_info::SystemInfo;

/// An error encountered during minidump processing.
#[derive(Debug)]
pub enum ProcessError {
    /// An unknown error.
    UnknownError,
    /// Missing system info stream.
    MissingSystemInfo,
}

/// Unwind all threads in `dump` and return a `ProcessState`.
pub fn process_minidump(dump : &mut Minidump) -> Result<ProcessState, ProcessError> {
    let process_create_time = if let Ok(misc_info) = dump.get_stream::<MinidumpMiscInfo>() {
        misc_info.process_create_time
    } else {
        None
    };
    let dump_system_info = try!(dump.get_stream::<MinidumpSystemInfo>().or(Err(ProcessError::MissingSystemInfo)));
    let system_info = SystemInfo {
        os: dump_system_info.os,
        // TODO
        os_version: None,
        cpu: dump_system_info.cpu,
        // TODO
        cpu_info: None,
        cpu_count: dump_system_info.raw.number_of_processors as usize,
    };
    // Get CPU info
    // Get OS info
    // Get Breakpad info
    // - Get dump thread ID
    // - Get requesting thread ID
    // Get exception
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
    Ok(ProcessState {
        time: UTC.timestamp(dump.header.time_date_stamp as i64, 0),
        process_create_time: process_create_time,
        crash_reason: crash_reason,
        crash_address: crash_address,
        assertion: assertion,
        system_info: system_info,
    })
}
