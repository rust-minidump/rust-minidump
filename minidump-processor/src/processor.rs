// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::path::Path;
use std::time::{Duration, SystemTime};

use minidump::{self, *};

use crate::arg_recovery;
use crate::evil;
use crate::process_state::{CallStack, CallStackInfo, LinuxStandardBase, ProcessState};
use crate::stackwalker;
use crate::symbols::*;
use crate::system_info::SystemInfo;

/// Configuration of the processor's exact behaviour.
///
/// This can be used to either:
///
/// * enable extra features that are disabled by default
/// * lock in the features you want enabled to minimize future changes
///
/// All fields are `pub`, but the type is `non_exhaustive`.
/// Recommended usage is to call one of the constructors to get a baseline
/// set of features, and then manually set any values you particularly care about.
///
/// If we decide an unstable feature exposed by these flags is a bad idea,
/// we may remove its functionality and turn it into a noop, but the flag
/// will remain to avoid breaking code. Similarly, if a feature seems to be
/// too bloated, its implementation may be hidden behind a cargo feature
/// flag, producing a similar result if that feature is statically disabled.
///
/// In either of these cases, a `warn` diagnostic will be emitted if you
/// try to use request a feature whose implementation does not exist.
///
/// [`process_minidump`][] uses [`ProcessorOptions::stable_basic`][], which
/// is also exposed as [`Default::default`].
///
/// ## Example:
///
/// ```
/// use minidump_processor::ProcessorOptions;
///
/// // Happy with the default-enabled features
/// let mut options = ProcessorOptions::stable_basic();
/// // But specifically want this cool unstable feature
/// options.recover_function_args = true;
/// ```
///
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProcessorOptions<'a> {
    /// **\[UNSTABLE\]** The evil "raw json" mozilla's legacy infrastructure relies on.
    ///
    /// Please don't use this. If you have to use this, you know who you are.
    pub evil_json: Option<&'a Path>,

    /// **\[UNSTABLE\]** Whether to try to heuristically recover function arguments in backtraces.
    ///
    /// Currently this only work for x86, and assumes everything is either cdecl or thiscall
    /// (inferred from whether the symbol name looks like a static function or a method).
    pub recover_function_args: bool,
}

impl ProcessorOptions<'_> {
    /// "Do the normal stuff everyone should want"
    ///
    /// * `evil_json: None`
    /// * `recover_function_args: false`
    ///
    /// Unlike stable_all, you shouldn't expect this to change its results much.
    ///
    /// It will specifically always try to:
    ///
    /// * Perform full backtraces and symbolication of every thread.
    /// * Produce detailed system info (OS, Cpu, Versions...)
    /// * Produce detailed crash info (Crashing thread, crash address, formatted error...)
    /// * List loaded and unloaded modules
    pub fn stable_basic() -> Self {
        ProcessorOptions {
            evil_json: None,
            recover_function_args: false,
        }
    }

    /// "Turn all the stable features on"
    ///
    /// * `evil_json: None`
    /// * `recover_function_args: false`
    ///
    /// (At this precise moment this is identical to stable_basic, but may diverge
    /// as we introduce more features.)
    ///
    /// Everything included by stable_basic, but willing to enable more interesting
    /// features and spend extra time trying to find extra insights. This is the default
    /// place that unstable features will "graduate" to when they're deemed good enough.
    pub fn stable_all() -> Self {
        ProcessorOptions {
            evil_json: None,
            recover_function_args: false,
        }
    }

    /// "Turn EVERYTHING on, even the experimental stuff!"
    ///
    /// * `evil_json: None`
    /// * `recover_function_args: true`
    ///
    /// (evil_json is still "disabled" because you need to give it needs a path.)
    ///
    /// Some of this stuff can be really jank, use at your own risk!
    pub fn unstable_all() -> Self {
        ProcessorOptions {
            evil_json: None,
            recover_function_args: true,
        }
    }

    /// Check if any of the enabled features are deprecated or disabled
    /// and emit warnings if they are.
    fn check_deprecated_and_disabled(&self) {
        // Currently nothing is deprecated / disableable, but here's the template.

        /*
        use log::warn;

        if self.my_bad_feature {
            warn!("Deprecated ProcessorOption my_bad_feature has been removed and does nothing.")
        }

        if !cfg!(feature = "my-optional-feature") && self.my_optional_feature {
            warn!("Disabled ProcessorOption my_optional_feature must be enabled via cargo.")
        }
        */
    }
}

impl Default for ProcessorOptions<'_> {
    fn default() -> Self {
        Self::stable_basic()
    }
}

/// An error encountered during minidump processing.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("Failed to read minidump")]
    MinidumpReadError(#[from] minidump::Error),
    #[error("An unknown error occurred")]
    UnknownError,
    #[error("The system information stream was not found")]
    MissingSystemInfo,
    #[error("The thread list stream was not found")]
    MissingThreadList,
}

/// Unwind all threads in `dump` and return a report as a `ProcessState`.
///
/// This is equivalent to [`process_minidump_with_options`] with
/// [`ProcessorOptions::stable_basic`][].
///
/// # Examples
///
/// ```
/// use minidump::Minidump;
/// use std::path::PathBuf;
/// use breakpad_symbols::{Symbolizer, SimpleSymbolSupplier};
/// use minidump_processor::ProcessError;
///
/// #[tokio::main]
/// async fn main() -> Result<(), ProcessError> {
///     # std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
///     let mut dump = Minidump::read_path("../testdata/test.dmp")?;
///     let supplier = SimpleSymbolSupplier::new(vec!(PathBuf::from("../testdata/symbols")));
///     let symbolizer = Symbolizer::new(supplier);
///     let state = minidump_processor::process_minidump(&mut dump, &symbolizer).await?;
///     assert_eq!(state.threads.len(), 2);
///     println!("Processed {} threads", state.threads.len());
///     Ok(())
/// }
/// ```
pub async fn process_minidump<'a, T, P>(
    dump: &Minidump<'a, T>,
    symbol_provider: &P,
) -> Result<ProcessState, ProcessError>
where
    T: Deref<Target = [u8]> + 'a,
    P: SymbolProvider + Sync,
{
    // No Evil JSON Here!
    process_minidump_with_options(dump, symbol_provider, ProcessorOptions::default()).await
}

/// Process `dump` with the given options and return a report as a `ProcessState`.
///
/// See [`ProcessorOptions`][] for details on the specific features that can be
/// enabled and how to choose them.
pub async fn process_minidump_with_options<'a, T, P>(
    dump: &Minidump<'a, T>,
    symbol_provider: &P,
    options: ProcessorOptions<'_>,
) -> Result<ProcessState, ProcessError>
where
    T: Deref<Target = [u8]> + 'a,
    P: SymbolProvider + Sync,
{
    options.check_deprecated_and_disabled();

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

    let (os_version, os_build) = dump_system_info.os_parts();

    let linux_standard_base = dump.get_stream::<MinidumpLinuxLsbRelease>().ok();
    let linux_cpu_info = dump
        .get_stream::<MinidumpLinuxCpuInfo>()
        .unwrap_or_default();
    let _linux_environ = dump.get_stream::<MinidumpLinuxEnviron>().ok();
    let _linux_proc_status = dump.get_stream::<MinidumpLinuxProcStatus>().ok();

    // Extract everything we care about from linux streams here.
    // We don't eagerly process them in the minidump crate because there's just
    // tons of random information in there and it's not obvious what anyone
    // would care about. So just providing an iterator and letting minidump-processor
    // pull out the things it cares about is simple and effective.

    let mut cpu_microcode_version = None;
    for (key, val) in linux_cpu_info.iter() {
        if key.as_bytes() == b"microcode" {
            cpu_microcode_version = val
                .to_str()
                .ok()
                .and_then(|val| val.strip_prefix("0x"))
                .and_then(|val| u64::from_str_radix(val, 16).ok());
            break;
        }
    }

    let linux_standard_base = linux_standard_base.map(|linux_standard_base| {
        let mut lsb = LinuxStandardBase::default();
        for (key, val) in linux_standard_base.iter() {
            match key.as_bytes() {
                b"DISTRIB_ID" | b"ID" => lsb.id = val.to_string_lossy().into_owned(),
                b"DISTRIB_RELEASE" | b"VERSION_ID" => {
                    lsb.release = val.to_string_lossy().into_owned()
                }
                b"DISTRIB_CODENAME" | b"VERSION_CODENAME" => {
                    lsb.codename = val.to_string_lossy().into_owned()
                }
                b"DISTRIB_DESCRIPTION" | b"PRETTY_NAME" => {
                    lsb.description = val.to_string_lossy().into_owned()
                }
                _ => {}
            }
        }
        lsb
    });

    let cpu_info = dump_system_info
        .cpu_info()
        .map(|string| string.into_owned());

    let system_info = SystemInfo {
        os: dump_system_info.os,
        os_version: Some(os_version),
        os_build,
        cpu: dump_system_info.cpu,
        cpu_info,
        cpu_microcode_version,
        cpu_count: dump_system_info.raw.number_of_processors as usize,
    };

    let mac_crash_info = dump
        .get_stream::<MinidumpMacCrashInfo>()
        .ok()
        .map(|info| info.raw);

    let misc_info = dump.get_stream::<MinidumpMiscInfo>().ok();
    // Process create time is optional.
    let (process_id, process_create_time) = if let Some(misc_info) = misc_info.as_ref() {
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
            Some(exception.get_crash_address(system_info.os, system_info.cpu)),
            Some(exception.get_crashing_thread_id()),
        )
    } else {
        (None, None, None)
    };
    let exception_context =
        exception_ref.and_then(|e| e.context(&dump_system_info, misc_info.as_ref()));
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
    let memory_info_list = dump.get_stream::<MinidumpMemoryInfoList>().ok();
    let linux_maps = dump.get_stream::<MinidumpLinuxMaps>().ok();
    let _memory_info = UnifiedMemoryInfoList::new(memory_info_list, linux_maps).unwrap_or_default();

    // Get the evil JSON file (thread names and module certificates)
    let evil = options
        .evil_json
        .and_then(evil::handle_evil)
        .unwrap_or_default();

    let mut threads = vec![];
    let mut requesting_thread = None;
    for (i, thread) in thread_list.threads.iter().enumerate() {
        let id = thread.raw.thread_id;

        // If this is the thread that wrote the dump, skip processing it.
        if dump_thread_id.is_some() && dump_thread_id.unwrap() == id {
            threads.push(CallStack::with_info(id, CallStackInfo::DumpThreadSkipped));
            continue;
        }

        let thread_context = thread.context(&dump_system_info, misc_info.as_ref());
        // If this thread requested the dump then try to use the exception
        // context if it exists. (prefer the exception stream's thread id over
        // the breakpad info stream's thread id.)
        let context = if crashing_thread_id
            .or(requesting_thread_id)
            .map(|id| id == thread.raw.thread_id)
            .unwrap_or(false)
        {
            requesting_thread = Some(i);
            exception_context.as_deref().or(thread_context.as_deref())
        } else {
            thread_context.as_deref()
        };

        let stack_memory = thread.stack_memory(&memory_list);

        let mut stack =
            stackwalker::walk_stack(&context, stack_memory.as_deref(), &modules, symbol_provider)
                .await;
        stack.thread_id = id;
        for frame in &mut stack.frames {
            // If the frame doesn't have a loaded module, try to find an unloaded module
            // that overlaps with its address range. The may be multiple, so record all
            // of them and the offsets this frame has in them.
            if frame.module.is_none() {
                let mut offsets = BTreeMap::new();
                for unloaded in unloaded_modules.modules_at_address(frame.instruction) {
                    let offset = frame.instruction - unloaded.raw.base_of_image;
                    offsets
                        .entry(unloaded.name.clone())
                        .or_insert_with(BTreeSet::new)
                        .insert(offset);
                }

                frame.unloaded_modules = offsets;
            }
        }

        let name = thread_names
            .get_name(thread.raw.thread_id)
            .map(|cow| cow.into_owned())
            .or_else(|| evil.thread_names.get(&thread.raw.thread_id).cloned());
        stack.thread_name = name;

        stack.last_error_value = thread.last_error(system_info.cpu, &memory_list);

        if options.recover_function_args {
            arg_recovery::fill_arguments(&mut stack, stack_memory.as_deref());
        }

        threads.push(stack);
    }

    // Collect up info on unimplemented/unknown modules
    let unknown_streams = dump.unknown_streams().collect();
    let unimplemented_streams = dump.unimplemented_streams().collect();

    // Get symbol stats from the symbolizer
    let symbol_stats = symbol_provider.stats();

    Ok(ProcessState {
        process_id,
        time: SystemTime::UNIX_EPOCH + Duration::from_secs(dump.header.time_date_stamp as u64),
        process_create_time,
        cert_info: evil.certs,
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
