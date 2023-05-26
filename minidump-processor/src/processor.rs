// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, RangeInclusive};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use minidump::system_info::PointerWidth;
use minidump::{self, *};
use minidump_unwind::{
    walk_stack, CallStack, CallStackInfo, FrameTrust, StackFrame, SymbolProvider, SystemInfo,
};

use crate::op_analysis::MemoryAccess;
use crate::process_state::{LinuxStandardBase, ProcessState};
use crate::{arg_recovery, evil, AdjustedAddress};

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

    /// Set this value to subscribe to live statistics during the processing.
    ///
    /// See [`PendingProcessorStats`] and [`PendingProcessorStatSubscriptions`].
    pub stat_reporter: Option<&'a PendingProcessorStats>,
}

/// A subscription to various live updates during minidump processing.
///
/// Construct it with [`PendingProcessorStats::new`] and pass it into
/// [`ProcessorOptions::stat_reporter`]. The type internally handles
/// concurrency and can be safely sent or shared between threads.
///
/// The type can't be cloned just because we don't want to guarantee
/// how the atomics are implemented. Wrap it in an Arc if you want
/// shared access for yourself.
#[derive(Debug)]
pub struct PendingProcessorStats {
    /// The stats we will track
    subscriptions: PendingProcessorStatSubscriptions,
    /// The actual computed stats
    stats: Arc<Mutex<PendingProcessorStatsInner>>,
}

/// An implementation detail of PendingProcessorStats, where all the
/// actual stats are recorded. Can be changed without anything caring.
#[derive(Default, Debug, Clone)]
struct PendingProcessorStatsInner {
    /// How many threads have been processed
    num_threads_processed: u64,
    /// How many threads there are in total (redundant, but convenient)
    total_threads: u64,
    /// The number of frames that have been walked
    num_frames_processed: u64,
    /// Frames that have been walked since you last queried this stat
    new_walked_frames: Vec<WalkedFrame>,
    /// The partial ProcessState, before stackwalking
    unwalked_result: Option<ProcessState>,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Live updates you want to subscribe to during the processing.
///
/// Pass this into [`PendingProcessorStats::new`] to configure it.
pub struct PendingProcessorStatSubscriptions {
    /// Subscribe to stats on how many threads have been processed.
    ///
    /// This can be used to give a progress estimate.
    ///
    /// The values can be read with [`PendingProcessorStats::get_thread_count`].
    pub thread_count: bool,
    /// Subscribe to stats on how many frames have been processed.
    ///
    /// This can be used to give a progress estimate.
    ///
    /// The value can be read with [`PendingProcessorStats::get_frame_count`].
    pub frame_count: bool,
    /// Subscribe to a copy of the ProcessState before stackwalking (or symbolication).
    ///
    /// This can be used to provide the quick and easy results while the expensive
    /// stackwalker has to go off and start doing file or network i/o for symbols.
    ///
    /// The values can be read with [`PendingProcessorStats::take_unwalked_result`].
    pub unwalked_result: bool,
    /// Subscribe to live StackFrame results.
    ///
    /// This can be used to update [`PendingProcessorStatSubscriptions::unwalked_result`]
    /// as the stackwalker makes progress. How useful/smooth this is depends on the input.
    /// If the biggest symbol file is the first frame of the stack, the walker may hang at 0%
    /// progress for a long time and then suddenly jump to 100% instantly, as the
    /// first dependency gets resolved last.
    ///
    /// The values can be read with [`PendingProcessorStats::drain_new_frames`].
    pub live_frames: bool,
}

/// A StackFrame that has been walked, with metadata on which thread it's part of,
/// and which frame of that thread it is.
///
/// This is the payload for [`PendingProcessorStatSubscriptions::live_frames`].
#[derive(Debug, Clone)]
pub struct WalkedFrame {
    /// The thread that this was, the index corresponds to [`ProcessState::threads`].
    pub thread_idx: usize,
    /// The frame that this was, the index corresponds to [`CallStack::frames`].
    pub frame_idx: usize,
    /// The actual walked and symbolicated StackFrame. Some post-processing analysis
    /// may be missing, so these results should be discarded once you have the
    /// final [`ProcessState`].
    pub frame: StackFrame,
}

impl PendingProcessorStats {
    /// Subscribe to the given stats.
    ///
    /// Pass this into [`ProcessorOptions::stat_reporter`] to use it.
    pub fn new(subscriptions: PendingProcessorStatSubscriptions) -> Self {
        Self {
            subscriptions,
            stats: Default::default(),
        }
    }

    /// Gets (processed_thread_count, total_thread_count).
    ///
    /// This will panic if you didn't subscribe to
    /// [`PendingProcessorStatSubscriptions::thread_count`].
    pub fn get_thread_count(&self) -> (u64, u64) {
        assert!(
            self.subscriptions.thread_count,
            "tried to get thread count stats, but wasn't subscribed!"
        );
        let stats = self.stats.lock().unwrap();
        (stats.num_threads_processed, stats.total_threads)
    }

    /// Get count of walked frames.
    ///
    /// This will panic if you didn't subscribe to
    /// [`PendingProcessorStatSubscriptions::frame_count`].
    pub fn get_frame_count(&self) -> u64 {
        assert!(
            self.subscriptions.frame_count,
            "tried to get frame count stats, but wasn't subscribed!"
        );
        let stats = self.stats.lock().unwrap();
        stats.num_frames_processed
    }

    /// Get all the new walked frames since this method was last called.
    ///
    /// This operates via callback to allow implementation flexibility.
    ///
    /// This will panic if you didn't subscribe to
    /// [`PendingProcessorStatSubscriptions::live_frames`].
    pub fn drain_new_frames(&self, mut callback: impl FnMut(WalkedFrame)) {
        assert!(
            self.subscriptions.live_frames,
            "tried to get new frames, but wasn't subscribed!"
        );
        let mut stats = self.stats.lock().unwrap();
        for frame in stats.new_walked_frames.drain(..) {
            callback(frame);
        }
    }

    /// Get the unwalked [`ProcessState`], if it has been computed.
    ///
    /// This will yield `Some` exactly once.
    ///
    /// This will panic if you didn't subscribe to
    /// [`PendingProcessorStatSubscriptions::unwalked_result`].
    pub fn take_unwalked_result(&self) -> Option<ProcessState> {
        assert!(
            self.subscriptions.unwalked_result,
            "tried to get unwalked result, but wasn't subscribed!"
        );
        let mut stats = self.stats.lock().unwrap();
        stats.unwalked_result.take()
    }

    /// Record how many threads there are in total.
    pub(crate) fn set_total_threads(&self, total_threads: u64) {
        // Only bother doing this if the user cares
        if self.subscriptions.thread_count {
            let mut stats = self.stats.lock().unwrap();
            stats.total_threads = total_threads;
        }
    }

    /// Record that a thread has been processed.
    pub(crate) fn inc_processed_threads(&self) {
        // Only bother doing this if the user cares
        if self.subscriptions.thread_count {
            let mut stats = self.stats.lock().unwrap();
            stats.num_threads_processed += 1;
        }
    }

    /// Record that this frame has been walked.
    pub(crate) fn add_walked_frame(&self, thread_idx: usize, frame_idx: usize, frame: &StackFrame) {
        // Only bother doing this if the user cares
        if self.subscriptions.live_frames || self.subscriptions.frame_count {
            let mut stats = self.stats.lock().unwrap();
            // Once we're in here it's easier to update this then check if they care
            stats.num_frames_processed += 1;
            // But this one is worth rechecking
            if self.subscriptions.live_frames {
                stats.new_walked_frames.push(WalkedFrame {
                    thread_idx,
                    frame_idx,
                    frame: frame.clone(),
                });
            }
        }
    }

    /// Record this unwalked [`ProcessState`].
    pub(crate) fn add_unwalked_result(&self, state: &ProcessState) {
        // Only bother doing this if the user cares
        if self.subscriptions.unwalked_result {
            let mut stats = self.stats.lock().unwrap();
            stats.unwalked_result = Some(state.clone());
        }
    }
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
            stat_reporter: None,
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
            stat_reporter: None,
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
            stat_reporter: None,
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
#[derive(Clone, Debug, thiserror::Error)]
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

impl ProcessError {
    /// Returns just the name of the error, as a more human-friendly version of
    /// an error-code for error logging.
    pub fn name(&self) -> &'static str {
        match self {
            ProcessError::MinidumpReadError(_) => "MinidumpReadError",
            ProcessError::UnknownError => "UnknownError",
            ProcessError::MissingSystemInfo => "MissingSystemInfo",
            ProcessError::MissingThreadList => "MissingThreadList",
        }
    }
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

/// Get the microcode version from linux cpu info and evil options.
fn get_microcode_version(linux_cpu_info: &MinidumpLinuxCpuInfo, evil: &evil::Evil) -> Option<u64> {
    linux_cpu_info
        .iter()
        .find_map(|(key, val)| {
            if key.as_bytes() == b"microcode" {
                val.to_str().ok()
            } else {
                None
            }
        })
        .or(evil.cpu_microcode_version.as_deref())
        .and_then(|val| val.strip_prefix("0x"))
        .and_then(|val| u64::from_str_radix(val, 16).ok())
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
    let info = MinidumpInfo::new(dump, options)?;

    let mut exception_details = info.get_exception_details();

    if let Some(details) = &mut exception_details {
        info.check_for_bitflips(details);
        info.check_for_guard_pages(details);
    }
    info.into_process_state(dump, symbol_provider, exception_details)
        .await
}

struct MinidumpInfo<'a> {
    options: ProcessorOptions<'a>,
    evil: crate::evil::Evil,
    thread_list: MinidumpThreadList<'a>,
    thread_names: MinidumpThreadNames,
    dump_system_info: MinidumpSystemInfo,
    linux_standard_base: Option<LinuxStandardBase>,
    system_info: SystemInfo,
    mac_crash_info: Option<Vec<RawMacCrashInfo>>,
    mac_boot_args: Option<MinidumpMacBootargs>,
    misc_info: Option<MinidumpMiscInfo>,
    dump_thread_id: Option<u32>,
    requesting_thread_id: Option<u32>,
    modules: MinidumpModuleList,
    unloaded_modules: MinidumpUnloadedModuleList,
    memory_list: UnifiedMemoryList<'a>,
    /*
    memory_info_list: Option<MinidumpMemoryInfoList<'a>>,
    linux_maps: Option<MinidumpLinuxMaps<'a>>,
    */
    memory_info: UnifiedMemoryInfoList<'a>,
    exception: Option<MinidumpException<'a>>,
    //exception_details: Option<ExceptionDetails<'a>>,
}

impl<'a> MinidumpInfo<'a> {
    pub fn new<T: Deref<Target = [u8]> + 'a>(
        dump: &'a Minidump<'a, T>,
        options: ProcessorOptions<'a>,
    ) -> Result<Self, ProcessError> {
        options.check_deprecated_and_disabled();

        // Get the evil JSON file (thread names, module certificates, etc)
        let evil = options
            .evil_json
            .and_then(evil::handle_evil)
            .unwrap_or_default();

        // Thread list is required for processing.
        let thread_list = dump
            .get_stream::<MinidumpThreadList>()
            .or(Err(ProcessError::MissingThreadList))?;

        let num_threads = thread_list.threads.len() as u64;
        if let Some(reporter) = options.stat_reporter {
            reporter.set_total_threads(num_threads);
        }

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

        let cpu_microcode_version = get_microcode_version(&linux_cpu_info, &evil);

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

        let mac_boot_args = dump.get_stream::<MinidumpMacBootargs>().ok();

        let misc_info = dump.get_stream::<MinidumpMiscInfo>().ok();
        // If Breakpad info exists in dump, get dump and requesting thread ids.
        let breakpad_info = dump.get_stream::<MinidumpBreakpadInfo>();
        let (dump_thread_id, requesting_thread_id) = if let Ok(info) = breakpad_info {
            (info.dump_thread_id, info.requesting_thread_id)
        } else {
            (None, None)
        };
        // Get assertion
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
        let memory_list = dump.get_memory().unwrap_or_default();
        let memory_info_list = dump.get_stream::<MinidumpMemoryInfoList>().ok();
        let linux_maps = dump.get_stream::<MinidumpLinuxMaps>().ok();
        let memory_info =
            UnifiedMemoryInfoList::new(memory_info_list, linux_maps).unwrap_or_default();

        // Get exception info if it exists.
        let exception = dump.get_stream::<MinidumpException>().ok();

        Ok(MinidumpInfo {
            options,
            evil,
            thread_list,
            thread_names,
            dump_system_info,
            linux_standard_base,
            system_info,
            mac_crash_info,
            mac_boot_args,
            misc_info,
            dump_thread_id,
            requesting_thread_id,
            modules,
            unloaded_modules,
            memory_list,
            /*
            memory_info_list: Option<MinidumpMemoryInfoList<'a>>,
            linux_maps: Option<MinidumpLinuxMaps<'a>>,
            */
            memory_info,
            exception,
            //exception_details: None,
        })
    }

    /// Get details about the minidump exception, if available.
    pub fn get_exception_details(&self) -> Option<ExceptionDetails<'a>> {
        let exception = self.exception.as_ref()?;

        let reason = exception.get_crash_reason(self.system_info.os, self.system_info.cpu);
        let address = exception.get_crash_address(self.system_info.os, self.system_info.cpu);

        let stack_memory_ref = self
            .thread_list
            .get_thread(exception.get_crashing_thread_id())
            .and_then(|thread| thread.stack_memory(&self.memory_list));

        let context = exception.context(&self.dump_system_info, self.misc_info.as_ref());

        let mut exception_info: Option<crate::ExceptionInfo> = None;
        let mut instruction_registers: BTreeSet<&'static str> = Default::default();

        // If we have a context, we can attempt to analyze the crashing thread's instructions
        if let Some(context) = context.as_ref() {
            match crate::op_analysis::analyze_thread_context(
                context,
                &self.memory_list,
                stack_memory_ref,
            ) {
                Ok(op_analysis) => {
                    let memory_accesses = op_analysis.memory_accesses.as_deref();

                    let adjusted_address = try_detect_null_pointer_in_disguise(memory_accesses)
                        .map(|offset| AdjustedAddress::NullPointerWithOffset(offset.into()))
                        .or_else(|| {
                            try_get_non_canonical_crash_address(
                                &self.system_info,
                                memory_accesses,
                                reason,
                                address,
                            )
                            .map(|addr| AdjustedAddress::NonCanonical(addr.into()))
                        });

                    exception_info = Some(crate::ExceptionInfo {
                        reason,
                        address: address.into(),
                        adjusted_address,
                        instruction_str: Some(op_analysis.instruction_str),
                        memory_accesses: op_analysis.memory_accesses,
                        possible_bit_flips: Default::default(),
                    });
                    instruction_registers = op_analysis.registers;
                }
                Err(e) => {
                    tracing::warn!("failed to analyze the thread context: {e}");
                }
            }
        }

        let info = exception_info.unwrap_or_else(|| crate::ExceptionInfo {
            reason,
            address: address.into(),
            adjusted_address: None,
            instruction_str: None,
            memory_accesses: None,
            possible_bit_flips: Default::default(),
        });

        Some(ExceptionDetails {
            info,
            context,
            instruction_registers,
        })
    }

    /// Check for bit-flips of the exception address/instruction.
    ///
    /// Additional bit flip information will be added to `exception_details`.
    pub fn check_for_bitflips(&self, exception_details: &mut ExceptionDetails<'a>) {
        // Only check for bit-flips on 64-bit systems, as the large memory space makes
        // false-positives less likely.
        if self.system_info.cpu.pointer_width() != PointerWidth::Bits64 {
            return;
        }

        let info = &mut exception_details.info;

        use bitflip::BitRange;
        let bit_flip_address = match &info.adjusted_address {
            // Use the non canonical address if present.
            Some(AdjustedAddress::NonCanonical(v)) => Some((v.0, BitRange::Amd64NonCanonical)),
            // If we think the address is a null pointer with an offset, don't try bit flips.
            Some(AdjustedAddress::NullPointerWithOffset(_)) => None,
            // Try the crashing address if no adjustments have been made.
            None => Some((
                info.address.0,
                if self.system_info.cpu != system_info::Cpu::X86_64 {
                    BitRange::All
                } else {
                    BitRange::Amd64Canononical
                },
            )),
        };
        if let Some((address, bit_range)) = bit_flip_address {
            let memory_op = bitflip::MemoryOperation::from_crash_reason(&info.reason);
            info.possible_bit_flips = bitflip::try_bit_flips(
                address,
                None,
                bit_range,
                exception_details.context.as_deref(),
                &self.memory_info,
                memory_op,
            );

            // If we have an exception context, we can check the registers involved in the
            // crashing instruction.
            if let Some(context) = exception_details.context.as_deref() {
                for reg in &exception_details.instruction_registers {
                    if let Some(address) = context.get_register(reg) {
                        info.possible_bit_flips.extend(bitflip::try_bit_flips(
                            address,
                            Some(reg),
                            bit_range,
                            Some(context),
                            &self.memory_info,
                            // We assume that a register that is causing a crash due to a flipped
                            // bit has the same memory operation as the crash (i.e. we assume that
                            // the base address, possibly combined with some offset, is still in
                            // the same memory region).
                            memory_op,
                        ));
                    }
                }
            }
        }
    }

    /// Check whether memory accesses are accessing likely guard pages.
    pub fn check_for_guard_pages(&self, exception_details: &mut ExceptionDetails<'a>) {
        const GUARD_MEMORY_MAX_SIZE: u64 = 2 << 14;

        if let Some(accesses) = &mut exception_details.info.memory_accesses {
            for access in accesses {
                let Some(info) = self.memory_info.memory_info_at_address(access.address) else { continue; };
                let Some(range) = info.memory_range() else { continue; };

                fn is_accessible(range: &UnifiedMemoryInfo) -> bool {
                    range.is_readable() || range.is_writable() || range.is_executable()
                }

                let is_adjacent_to_accessible_memory = || {
                    for region in self.memory_info.by_addr() {
                        let Some(other_range) = region.memory_range() else { continue; };
                        if other_range.end + 1 == range.start && is_accessible(&region) {
                            return true;
                        }
                        if range.end + 1 == other_range.start {
                            // At this point we won't encounter any other relevant regions as we're
                            // iterating by address, so return.
                            return is_accessible(&region);
                        }
                    }
                    false
                };

                // As a heuristic, we consider any mapped memory to be a guard page if it:
                // * has no permissions,
                // * is less than `GUARD_MEMORY_MAX_SIZE`, and
                // * is adjacent to a region with permissions.
                if !is_accessible(&info)
                    && range.end - range.start < GUARD_MEMORY_MAX_SIZE
                    && is_adjacent_to_accessible_memory()
                {
                    access.is_likely_guard_page = true;
                }
            }
        }
    }

    pub async fn into_process_state<P, T>(
        self,
        dump: &Minidump<'a, T>,
        symbol_provider: &P,
        exception_details: Option<ExceptionDetails<'a>>,
    ) -> Result<ProcessState, ProcessError>
    where
        T: Deref<Target = [u8]> + 'a,
        P: SymbolProvider + Sync,
    {
        let crashing_thread_id = self.exception.as_ref().map(|e| e.get_crashing_thread_id());

        let (exception_info, exception_context) = match exception_details {
            Some(details) => (Some(details.info), details.context),
            None => (None, None),
        };

        let mut requesting_thread = None;

        let threads = self
            .thread_list
            .threads
            .iter()
            .enumerate()
            .map(|(i, thread)| {
                let id = thread.raw.thread_id;

                // If this is the thread that wrote the dump, skip processing it.
                if self.dump_thread_id == Some(id) {
                    return CallStack::with_info(id, CallStackInfo::DumpThreadSkipped);
                }

                let thread_context =
                    thread.context(&self.dump_system_info, self.misc_info.as_ref());
                // If this thread requested the dump then try to use the exception
                // context if it exists. (prefer the exception stream's thread id over
                // the breakpad info stream's thread id.)
                let context = if crashing_thread_id.or(self.requesting_thread_id) == Some(id) {
                    requesting_thread = Some(i);
                    exception_context.as_deref().or(thread_context.as_deref())
                } else {
                    thread_context.as_deref()
                };

                let name = self
                    .thread_names
                    .get_name(thread.raw.thread_id)
                    .map(|cow| cow.into_owned())
                    .or_else(|| self.evil.thread_names.get(&thread.raw.thread_id).cloned());

                let (info, frames) = if let Some(context) = context {
                    let ctx = context.clone();
                    (
                        CallStackInfo::Ok,
                        vec![StackFrame::from_context(ctx, FrameTrust::Context)],
                    )
                } else {
                    (CallStackInfo::MissingContext, vec![])
                };

                CallStack {
                    frames,
                    info,
                    thread_id: id,
                    thread_name: name,
                    last_error_value: thread.last_error(self.system_info.cpu, &self.memory_list),
                }
            })
            .collect();

        // Collect up info on unimplemented/unknown modules
        let unknown_streams = dump.unknown_streams().collect();
        let unimplemented_streams = dump.unimplemented_streams().collect();

        // Get symbol stats from the symbolizer
        let symbol_stats = symbol_provider.stats();

        // Process create time is optional.
        let (process_id, process_create_time) = if let Some(misc_info) = self.misc_info.as_ref() {
            (
                misc_info.raw.process_id().cloned(),
                misc_info.process_create_time(),
            )
        } else {
            (None, None)
        };

        let mut state = ProcessState {
            process_id,
            time: SystemTime::UNIX_EPOCH + Duration::from_secs(dump.header.time_date_stamp as u64),
            process_create_time,
            cert_info: self.evil.certs,
            exception_info,
            assertion: None,
            requesting_thread,
            system_info: self.system_info,
            linux_standard_base: self.linux_standard_base,
            mac_crash_info: self.mac_crash_info,
            mac_boot_args: self.mac_boot_args,
            threads,
            modules: self.modules,
            unloaded_modules: self.unloaded_modules,
            unknown_streams,
            unimplemented_streams,
            symbol_stats,
        };

        // Report the unwalked result
        if let Some(reporter) = self.options.stat_reporter {
            reporter.add_unwalked_result(&state);
        }

        {
            let memory_list = &self.memory_list;
            let modules = &state.modules;
            let system_info = &state.system_info;
            let unloaded_modules = &state.unloaded_modules;
            let options = &self.options;

            futures_util::future::join_all(
                state
                    .threads
                    .iter_mut()
                    .zip(self.thread_list.threads.iter())
                    .enumerate()
                    .map(|(i, (stack, thread))| async move {
                        let mut stack_memory = thread.stack_memory(memory_list);
                        // Always choose the memory region that is referenced by the context,
                        // as the `exception_context` may refer to a different memory region than
                        // the `thread_context`, which in turn would fail to stack walk.
                        let stack_ptr = stack
                            .frames
                            .get(0)
                            .map(|ctx_frame| ctx_frame.context.get_stack_pointer());
                        if let Some(stack_ptr) = stack_ptr {
                            let contains_stack_ptr = stack_memory
                                .as_ref()
                                .and_then(|memory| memory.get_memory_at_address::<u64>(stack_ptr))
                                .is_some();
                            if !contains_stack_ptr {
                                stack_memory =
                                    memory_list.memory_at_address(stack_ptr).or(stack_memory);
                            }
                        }

                        walk_stack(
                            |frame_idx: usize, frame: &StackFrame| {
                                if let Some(reporter) = options.stat_reporter {
                                    reporter.add_walked_frame(i, frame_idx, frame);
                                }
                            },
                            stack,
                            stack_memory,
                            modules,
                            system_info,
                            symbol_provider,
                        )
                        .await;

                        for frame in &mut stack.frames {
                            // If the frame doesn't have a loaded module, try to find an unloaded module
                            // that overlaps with its address range. The may be multiple, so record all
                            // of them and the offsets this frame has in them.
                            if frame.module.is_none() {
                                let mut offsets = BTreeMap::new();
                                for unloaded in
                                    unloaded_modules.modules_at_address(frame.instruction)
                                {
                                    let offset = frame.instruction - unloaded.raw.base_of_image;
                                    offsets
                                        .entry(unloaded.name.clone())
                                        .or_insert_with(BTreeSet::new)
                                        .insert(offset);
                                }

                                frame.unloaded_modules = offsets;
                            }
                        }

                        if options.recover_function_args {
                            arg_recovery::fill_arguments(stack, stack_memory);
                        }

                        // Report the unwalked result
                        if let Some(reporter) = options.stat_reporter {
                            reporter.inc_processed_threads();
                        }

                        stack
                    }),
            )
            .await
        };

        let symbol_stats = symbol_provider.stats();
        state.symbol_stats = symbol_stats;

        Ok(state)
    }
}

struct ExceptionDetails<'a> {
    info: crate::ExceptionInfo,
    context: Option<std::borrow::Cow<'a, MinidumpContext>>,
    instruction_registers: BTreeSet<&'static str>,
}

/// If a non-canonical access caused a crash, return the real address
///
/// Amd64 has the concept of a "canonical addressing", which requires that the upper 16 bits of
/// an address contain the same binary digit as bit 47. A violation of this rule triggers a
/// General Protection Fault instead of the usual Page Fault, which unfortunately means that the
/// OS has no idea what memory address actually caused the issue
///
/// If `exception_info` contains the markers of a non-canonical exception, and it also contains
/// memory access info from analyzing the CPU instruction with `op_analysis`, this module will
/// attempt to determine what address the CPU was instructed to access when the GPF occurred
///
/// # Return
///
/// `Some(address)` if the crash was caused by a non-canonical access and the real address was
/// determined, `None` otherwise
fn try_get_non_canonical_crash_address(
    system_info: &SystemInfo,
    memory_accesses: Option<&[MemoryAccess]>,
    reason: CrashReason,
    address: u64,
) -> Option<u64> {
    use system_info::Cpu;

    // The range of non-canonical addresses in the current 48-bit implementation
    // See: https://en.wikipedia.org/wiki/X86-64#Virtual_address_space_details
    const NON_CANONICAL_RANGE: RangeInclusive<u64> = 0x0000_8000_0000_0000..=0xffff_7fff_ffff_ffff;

    // Only Amd64 has non-canonical addresses
    if system_info.cpu != Cpu::X86_64 {
        return None;
    }

    if !is_non_canonical_exception(system_info.os, reason, address) {
        return None;
    }

    // If we weren't able to determine the memory accessed by the instruction, we can't do this analysis
    if memory_accesses.is_none() {
        tracing::warn!(
            "lack of instruction analysis prevented determination of non-canonical address"
        );
        return None;
    }

    // If any of the instructions operands were within the non-canonical range, we have our culprit
    for access in memory_accesses.unwrap().iter() {
        if NON_CANONICAL_RANGE.contains(&access.address) {
            return Some(access.address);
        }
    }

    tracing::warn!("somehow got a non-canonical address exception in an instruction that doesn't appear to access one");

    None
}

/// Report whether the given exception represents a non-canonical access on the given OS
///
/// Different operating systems have different ways of reporting non-canonical address accesses
/// This function will return whether the given `exception_info` object represents such an access
/// on the given OS
fn is_non_canonical_exception(os: system_info::Os, reason: CrashReason, address: u64) -> bool {
    use minidump_common::errors as minidump_errors;
    use system_info::Os;

    // This is needed because match arms don't allow casting
    const SI_KERNEL_U32: u32 = minidump_errors::ExceptionCodeLinuxSicode::SI_KERNEL as u32;

    match (os, reason, address) {
        // Windows reports it as EXCEPTION_ACCESS_VIOLATION_READ, address 0xffffffffffffffff
        (
            Os::Windows,
            CrashReason::WindowsAccessViolation(
                minidump_errors::ExceptionCodeWindowsAccessType::READ,
            ),
            u64::MAX,
        ) => true,
        (Os::Windows, _, _) => false,
        // macOS reports it as EXC_BAD_ACCESS / EXC_I386_GPFLT, address 0x0000000000000000
        (
            Os::MacOs,
            CrashReason::MacBadAccessX86(
                minidump_errors::ExceptionCodeMacBadAccessX86Type::EXC_I386_GPFLT,
            ),
            0,
        ) => true,
        (Os::MacOs, _, _) => false,
        // Linux reports it as either "SIGBUS / SI_KERNEL" or "SIGSEGV / SI_KERNEL", address 0x0000000000000000
        (
            Os::Linux,
            CrashReason::LinuxGeneral(minidump_errors::ExceptionCodeLinux::SIGSEGV, SI_KERNEL_U32),
            0,
        ) => true,
        (
            Os::Linux,
            CrashReason::LinuxGeneral(minidump_errors::ExceptionCodeLinux::SIGBUS, SI_KERNEL_U32),
            0,
        ) => true,
        (Os::Linux, _, _) => false,
        (_, _, _) => {
            tracing::warn!("we don't currently support non-canonical analysis for your OS");
            false
        }
    }
}

/// Try to detect a "null pointer in disguise"
///
/// This function will search though all the memory accessses for the instruction and see if any
/// of them were flagged by `op_analysis` as being a disguised nullptr. If so, we return that
/// address as an "offset" from the null pointer value
fn try_detect_null_pointer_in_disguise(memory_accesses: Option<&[MemoryAccess]>) -> Option<u64> {
    if let Some(memory_accesses) = memory_accesses {
        for access in memory_accesses.iter() {
            if access.is_likely_null_pointer_dereference {
                return Some(access.address);
            }
        }
    }
    None
}

/// Bit-flip detection.
mod bitflip {
    use super::*;
    use crate::PossibleBitFlip;

    /// The memory operation occurring when a crash occurred.
    #[derive(Default, PartialEq, Eq, Clone, Copy)]
    pub enum MemoryOperation {
        #[default]
        Unknown,
        Read,
        Write,
        Execute,
    }

    impl MemoryOperation {
        pub fn from_crash_reason(reason: &CrashReason) -> Self {
            // TODO: it may be possible to derive the read/write/exec when disassembling the faulting
            // instruction, though this may be fairly verbose to implement.
            use minidump_common::errors::ExceptionCodeWindowsAccessType as WinAccess;
            match reason {
                CrashReason::WindowsAccessViolation(WinAccess::READ) => MemoryOperation::Read,
                CrashReason::WindowsAccessViolation(WinAccess::WRITE) => MemoryOperation::Write,
                CrashReason::WindowsAccessViolation(WinAccess::EXEC) => MemoryOperation::Execute,
                _ => Self::default(),
            }
        }

        /// Return whether this memory operation is allowed in the given memory region.
        pub fn allowed_for(&self, memory_info: &UnifiedMemoryInfo) -> bool {
            match self {
                Self::Unknown => true,
                Self::Read => memory_info.is_readable(),
                Self::Write => memory_info.is_writable(),
                Self::Execute => memory_info.is_executable(),
            }
        }
    }

    /// The bit range over which to check bit flips.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BitRange {
        Amd64Canononical,
        Amd64NonCanonical,
        All,
    }

    impl BitRange {
        pub fn range(&self) -> std::ops::Range<u32> {
            match self {
                Self::All => 0..u64::BITS,
                Self::Amd64Canononical => 0..48,
                Self::Amd64NonCanonical => 48..u64::BITS,
            }
        }
    }

    /// Try to determine whether an address was the result of a flipped bit.
    ///
    /// `memory_operation` represents the memory operation that was occurring at the crashing address
    /// (read/write/exec). If left as `Unknown`, all memory operations are considered allowed.
    /// Otherwise, specify one of the operations that was occurring.
    pub fn try_bit_flips(
        address: u64,
        source_register: Option<&'static str>,
        bit_range: BitRange,
        exception_context: Option<&MinidumpContext>,
        memory_info: &UnifiedMemoryInfoList,
        memory_operation: MemoryOperation,
    ) -> Vec<PossibleBitFlip> {
        let mut addresses = Vec::new();
        // If the address maps to valid memory, don't do anything else.
        if let Some(mi) = memory_info.memory_info_at_address(address) {
            if memory_operation.allowed_for(&mi) {
                return addresses;
            }
        }

        let create_possible_address = |new_address: u64| {
            let mut ret = PossibleBitFlip::new(new_address, source_register);
            ret.calculate_heuristics(
                address,
                bit_range == BitRange::Amd64NonCanonical,
                exception_context,
            );
            ret
        };

        for i in bit_range.range() {
            let possible_address = address ^ (1 << i);
            // If the possible address is NULL, we assume that this was the originally intended address
            // and some logic error has occurred (e.g. a NULL check went the wrong way).
            if possible_address == 0 {
                addresses.push(create_possible_address(possible_address));
            }
            if let Some(mi) = memory_info.memory_info_at_address(possible_address) {
                if memory_operation.allowed_for(&mi) {
                    addresses.push(create_possible_address(possible_address));
                }
            }
        }

        addresses
    }
}
