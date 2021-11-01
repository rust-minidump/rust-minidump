// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use chrono::{TimeZone, Utc};
use failure::Fail;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::ops::Deref;
use std::path::Path;

use minidump::{self, *};

use crate::process_state::{CallStack, CallStackInfo, ProcessState};
use crate::stackwalker;
use crate::symbols::*;
use crate::system_info::SystemInfo;

/// An error encountered during minidump processing.
#[derive(Debug, Fail)]
pub enum ProcessError {
    #[fail(display = "Failed to read minidump")]
    MinidumpReadError(minidump::Error),
    #[fail(display = "An unknown error occurred")]
    UnknownError,
    #[fail(display = "The system information stream was not found")]
    MissingSystemInfo,
    #[fail(display = "The thread list stream was not found")]
    MissingThreadList,
}

impl From<minidump::Error> for ProcessError {
    fn from(err: minidump::Error) -> ProcessError {
        ProcessError::MinidumpReadError(err)
    }
}

/// Unwind all threads in `dump` and return a `ProcessState`.
///
/// # Examples
///
/// ```
/// use minidump::Minidump;
/// use std::path::PathBuf;
/// use breakpad_symbols::{Symbolizer, SimpleSymbolSupplier};
///
/// # std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
/// # fn foo() -> Result<(), minidump_processor::ProcessError> {
/// let mut dump = Minidump::read_path("../testdata/test.dmp")?;
/// let supplier = SimpleSymbolSupplier::new(vec!(PathBuf::from("../testdata/symbols")));
/// let symbolizer = Symbolizer::new(supplier);
/// let state = minidump_processor::process_minidump(&mut dump, &symbolizer)?;
/// assert_eq!(state.threads.len(), 2);
/// println!("Processed {} threads", state.threads.len());
/// # Ok(())
/// # }
/// # fn main() { foo().unwrap() }
/// ```
pub fn process_minidump<'a, T, P>(
    dump: &Minidump<'a, T>,
    symbol_provider: &P,
) -> Result<ProcessState, ProcessError>
where
    T: Deref<Target = [u8]> + 'a,
    P: SymbolProvider,
{
    // No Evil JSON Here!
    process_minidump_with_evil(dump, symbol_provider, None)
}

/// The same as `process_minidump` but with an extra evil little json file.
///
/// This is a hack to support mozilla's legacy workflow, just use `process_minidump`.
pub fn process_minidump_with_evil<'a, T, P>(
    dump: &Minidump<'a, T>,
    symbol_provider: &P,
    evil_json: Option<&Path>,
) -> Result<ProcessState, ProcessError>
where
    T: Deref<Target = [u8]> + 'a,
    P: SymbolProvider,
{
    // Thread list is required for processing.
    let thread_list = dump
        .get_stream::<MinidumpThreadList>()
        .or(Err(ProcessError::MissingThreadList))?;
    // Try to get thread names, but it's only a nice-to-have.
    let thread_names = dump
        .get_stream::<MinidumpThreadNames>()
        .unwrap_or_else(|_| MinidumpThreadNames::default());

    // System info is required for processing.
    let dump_system_info = dump
        .get_stream::<MinidumpSystemInfo>()
        .or(Err(ProcessError::MissingSystemInfo))?;

    let mut os_version = format!(
        "{}.{}.{}",
        dump_system_info.raw.major_version,
        dump_system_info.raw.minor_version,
        dump_system_info.raw.build_number
    );
    if let Some(csd_version) = dump_system_info.csd_version() {
        os_version.push(' ');
        os_version.push_str(&csd_version);
    }

    let cpu_info = dump_system_info
        .cpu_info()
        .map(|string| string.into_owned());

    let system_info = SystemInfo {
        os: dump_system_info.os,
        os_version: Some(os_version),
        cpu: dump_system_info.cpu,
        cpu_info,
        cpu_count: dump_system_info.raw.number_of_processors as usize,
    };
    let linux_standard_base = dump.get_stream::<MinidumpLinuxLsbRelease>().ok();
    let mac_crash_info = dump
        .get_stream::<MinidumpMacCrashInfo>()
        .ok()
        .map(|info| info.raw);
    // Process create time is optional.
    let (process_id, process_create_time) =
        if let Ok(misc_info) = dump.get_stream::<MinidumpMiscInfo>() {
            (
                misc_info.raw.process_id().cloned(),
                misc_info.process_create_time(),
            )
        } else {
            (None, None)
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
    let (crash_reason, crash_address, crashing_thread_id) = if let Some(exception) = exception_ref {
        (
            Some(exception.get_crash_reason(system_info.os, system_info.cpu)),
            Some(exception.get_crash_address(system_info.os)),
            Some(exception.get_crashing_thread_id()),
        )
    } else {
        (None, None, None)
    };
    let exception_context = exception_ref.and_then(|e| e.context.as_ref());
    // Get assertion
    let assertion = None;
    let modules = match dump.get_stream::<MinidumpModuleList>() {
        Ok(module_list) => module_list,
        // Just give an empty list, simplifies things.
        Err(_) => MinidumpModuleList::new(),
    };
    let unloaded_modules = match dump.get_stream::<MinidumpUnloadedModuleList>() {
        Ok(module_list) => module_list,
        // Just give an empty list, simplifies things.
        Err(_) => MinidumpUnloadedModuleList::new(),
    };
    let memory_list = dump.get_stream::<MinidumpMemoryList>().unwrap_or_default();
    let _memory_info_list = dump
        .get_stream::<MinidumpMemoryInfoList>()
        .unwrap_or_default();

    // Get memory list
    let mut threads = vec![];
    let mut requesting_thread = None;
    for (i, thread) in thread_list.threads.iter().enumerate() {
        // If this is the thread that wrote the dump, skip processing it.
        if dump_thread_id.is_some() && dump_thread_id.unwrap() == thread.raw.thread_id {
            threads.push(CallStack::with_info(CallStackInfo::DumpThreadSkipped));
            continue;
        }
        // If this thread requested the dump then try to use the exception
        // context if it exists. (prefer the exception stream's thread id over
        // the breakpad info stream's thread id.)
        let context = if crashing_thread_id
            .or(requesting_thread_id)
            .map(|id| id == thread.raw.thread_id)
            .unwrap_or(false)
        {
            requesting_thread = Some(i);
            exception_context.or_else(|| thread.context.as_ref())
        } else {
            thread.context.as_ref()
        };

        let stack = thread.stack.as_ref().or_else(|| {
            // Windows probably gave us null RVAs for our stack memory descriptors.
            // If this happens, then we need to look up the memory region by address.
            let stack_addr = thread.raw.stack.start_of_memory_range;
            memory_list.memory_at_address(stack_addr)
        });

        let mut stack = stackwalker::walk_stack(&context, stack, &modules, symbol_provider);

        let name = thread_names
            .get_name(thread.raw.thread_id)
            .map(|cow| cow.into_owned());
        stack.thread_name = name;

        threads.push(stack);
    }

    // Collect up info on unimplemented/unknown modules
    let unknown_streams = dump.unknown_streams().collect();
    let unimplemented_streams = dump.unimplemented_streams().collect();

    // Get symbol stats from the symbolizer
    let symbol_stats = symbol_provider.stats();

    // Finally, handle the evil JSON file (get module signing certs)
    let cert_info = evil_json.and_then(handle_evil).unwrap_or_else(HashMap::new);

    Ok(ProcessState {
        process_id,
        time: Utc.timestamp(dump.header.time_date_stamp as i64, 0),
        process_create_time,
        cert_info,
        crash_reason,
        crash_address,
        assertion,
        requesting_thread,
        system_info,
        linux_standard_base,
        mac_crash_info,
        threads,
        modules,
        unloaded_modules,
        unknown_streams,
        unimplemented_streams,
        symbol_stats,
    })
}

fn handle_evil(evil_path: &Path) -> Option<HashMap<String, String>> {
    use log::{error, warn};
    use serde_json::Value::{self, *};

    // Get the evil json
    let evil_json = File::open(evil_path)
        .map_err(|e| {
            error!("Could not load Extra JSON at {:?}", evil_path);
            e
        })
        .ok()?;

    let buf = BufReader::new(evil_json);
    let json: Value = serde_json::from_reader(buf)
        .map_err(|e| {
            error!("Could not parse Extra JSON (was not valid JSON)");
            e
        })
        .ok()?;

    // Get module signing info
    let temp_obj;
    let certs = match json.get("ModuleSignatureInfo") {
        Some(Object(obj)) => obj,
        Some(String(string)) => {
            // Possible the signature info was wrapped in a string by mistake,
            // So try to parse that string as an object.
            temp_obj = serde_json::from_str(string)
                .map_err(|e| {
                    error!("Could not parse Extra JSON's ModuleSignatureInfo (not an object)");
                    error!("ModuleSignatureInfo: {}", string);
                    e
                })
                .ok()?;
            &temp_obj
        }
        _ => {
            error!("Could not parse Extra JSON's ModuleSignatureInfo (not an object)");
            return None;
        }
    };

    // Each certificate lists the modules it applies to, but we want the
    // reverse mapping -- module names to certificates. Invert the map.
    let mut cert_map = HashMap::new();
    for (cert, modules) in certs {
        if let Array(modules) = modules {
            for module in modules {
                if let String(module) = module {
                    cert_map.insert(module.clone(), cert.clone());
                }
            }
        } else {
            warn!(
                "Extra JSON had corrupt entry -- \"{}\": {:?}",
                cert, modules
            );
        }
    }

    Some(cert_map)
}
