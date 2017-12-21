// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use breakpad_symbols::{FrameSymbolizer, Symbolizer};
use chrono::{TimeZone,UTC};
use minidump::*;
use process_state::{CallStack,CallStackInfo,ProcessState};
use stackwalker;
use std::boxed::Box;
use system_info::SystemInfo;

pub trait SymbolProvider {
    fn fill_symbol(&self,
                   module: &Module,
                   frame: &mut FrameSymbolizer);
}

impl SymbolProvider for Symbolizer {
    fn fill_symbol(&self,
                   module: &Module,
                   frame: &mut FrameSymbolizer) {
        self.fill_symbol(module, frame);
    }
}

#[derive(Default)]
pub struct MultiSymbolProvider {
    providers: Vec<Box<SymbolProvider>>,
}

impl MultiSymbolProvider {
    pub fn new() -> MultiSymbolProvider {
        Default::default()
    }

    pub fn add(&mut self, provider: Box<SymbolProvider>) {
        self.providers.push(provider);
    }
}

impl SymbolProvider for MultiSymbolProvider {
    fn fill_symbol(&self,
                   module: &Module,
                   frame: &mut FrameSymbolizer) {
        for p in self.providers.iter() {
            p.fill_symbol(module, frame);
        }
    }
}

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
/// extern crate breakpad_symbols;
/// extern crate minidump;
/// extern crate minidump_processor;
/// use minidump::Minidump;
/// use breakpad_symbols::{Symbolizer, SimpleSymbolSupplier};
/// use std::fs::File;
/// use std::path::PathBuf;
/// # use std::io;
///
/// # fn foo() -> io::Result<()> {
/// let file = File::open("../testdata/test.dmp")?;
/// let mut dump = Minidump::read(file).unwrap();
/// let supplier = SimpleSymbolSupplier::new(vec!(PathBuf::from("../testdata/symbols")));
/// let symbolizer = Symbolizer::new(supplier);
/// let state = minidump_processor::process_minidump(&mut dump, &symbolizer).unwrap();
/// assert_eq!(state.threads.len(), 2);
/// println!("Processed {} threads", state.threads.len());
/// # Ok(())
/// # }
/// # fn main() { foo().unwrap() }
/// ```
pub fn process_minidump<P>(dump: &mut Minidump,
                           symbol_provider: &P)
                           -> Result<ProcessState, ProcessError>
    where P: SymbolProvider,
{
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
    // Get exception info if it exists.
    let exception_stream = dump.get_stream::<MinidumpException>().ok();
    let exception_ref = exception_stream.as_ref();
    let (crash_reason,
         crash_address) = if let Some(exception) = exception_ref {
        (Some(exception.get_crash_reason(system_info.os)),
         Some(exception.get_crash_address(system_info.os)))
    } else {
        (None, None)
    };
    let exception_context = exception_ref.and_then(|e| e.context.as_ref());
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
    let mut requesting_thread = None;
    for (i, thread) in thread_list.threads.iter().enumerate() {
        // If this is the thread that wrote the dump, skip processing it.
        if dump_thread_id.is_some() && dump_thread_id.unwrap() == thread.raw.thread_id {
            threads.push(CallStack::with_info(CallStackInfo::DumpThreadSkipped));
            continue;
        }
        // If this thread requested the dump then try to use the exception
        // context if it exists.
        let context = if requesting_thread_id.is_some() && requesting_thread_id.unwrap() == thread.raw.thread_id {
            requesting_thread = Some(i);
            exception_context.or(thread.context.as_ref())
        } else {
            thread.context.as_ref()
        };
        let stack = stackwalker::walk_stack(&context,
                                            &thread.stack,
                                            &modules,
                                            symbol_provider);
        threads.push(stack);
    }
    // if exploitability enabled, run exploitability analysis
    Ok(ProcessState {
        time: UTC.timestamp(dump.header.time_date_stamp as i64, 0),
        process_create_time: process_create_time,
        crash_reason: crash_reason,
        crash_address: crash_address,
        assertion: assertion,
        requesting_thread: requesting_thread,
        system_info: system_info,
        threads: threads,
        modules: modules,
    })
}
