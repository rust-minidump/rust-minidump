// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use chrono::{TimeZone,UTC};
use minidump::*;
use process_state::{CallStack,CallStackInfo,ProcessState};
use stackwalker;
use system_info::SystemInfo;

/// An error encountered during minidump processing.
#[derive(Debug)]
pub enum ProcessError {
    /// An unknown error.
    UnknownError,
    /// Missing system info stream.
    MissingSystemInfo,
    /// Missing thread list stream.
    MissingThreadList,
}

/// Unwind all threads in `dump` and return a `ProcessState`.
///
/// # Examples
///
/// ```
/// use minidump_processor::{Minidump,process_minidump};
/// use std::fs::File;
/// # use std::io;
///
/// # fn foo() -> io::Result<()> {
/// let file = try!(File::open("../testdata/test.dmp"));
/// let mut dump = Minidump::read(file).unwrap();
/// let state = process_minidump(&mut dump).unwrap();
/// println!("Processed {} threads", state.threads.len());
/// # Ok(())
/// # }
/// ```
pub fn process_minidump(dump : &mut Minidump) -> Result<ProcessState, ProcessError> {
    // Thread list is required for processing.
    let thread_list = try!(dump.get_stream::<MinidumpThreadList>().or(Err(ProcessError::MissingThreadList)));
    // System info is required for processing.
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
    // Process create time is optional.
    let process_create_time = if let Ok(misc_info) = dump.get_stream::<MinidumpMiscInfo>() {
        misc_info.process_create_time
    } else {
        None
    };
    // If Breakpad info exists in dump, get dump and requesting thread ids.
    let breakpad_info = dump.get_stream::<MinidumpBreakpadInfo>();
    let (dump_thread_id, requesting_thread_id) = if let Ok(info) = breakpad_info {
        (info.dump_thread_id, info.requesting_thread_id)
    } else {
        (None, None)
    };
    // Get exception
    // - Get crashing thread
    // - Get crash reason
    // - Get exception context
    let crash_reason = None;
    let crash_address = None;
    // Get assertion
    let assertion = None;
    let modules = if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
        module_list.clone()
    } else {
        // Just give an empty list, simplifies things.
        MinidumpModuleList::new()
    };
    // Get memory list
    let mut threads = vec!();
    for thread in thread_list.threads {
        // If this is the thread that wrote the dump, skip processing it.
        if dump_thread_id.is_some() && dump_thread_id.unwrap() == thread.raw.thread_id {
            threads.push(CallStack::with_info(CallStackInfo::DumpThreadSkipped));
            continue;
        }
        // - if requesting thread and have exception, use exception context,
        //   else use thread context
        let stack = stackwalker::walk_stack(&thread.context,
                                            &thread.stack,
                                            &modules);
        threads.push(stack);
    }
    // if exploitability enabled, run exploitability analysis
    Ok(ProcessState {
        time: UTC.timestamp(dump.header.time_date_stamp as i64, 0),
        process_create_time: process_create_time,
        crash_reason: crash_reason,
        crash_address: crash_address,
        assertion: assertion,
        // TODO: fill this once we have a threads vector
        requesting_thread: None,
        system_info: system_info,
        threads: threads,
        modules: modules,
    })
}
