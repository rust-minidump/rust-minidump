// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! The state of a process.

use std::borrow::{Borrow, Cow};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::io::prelude::*;
use std::time::SystemTime;

use crate::op_analysis::MemoryAccess;
use minidump::system_info::PointerWidth;
use minidump::*;
use minidump_common::utils::basename;
use minidump_unwind::{CallStack, CallStackInfo, SymbolStats, SystemInfo};
use serde_json::json;

#[derive(Default)]
struct SerializationContext {
    pub pointer_width: Option<PointerWidth>,
}

std::thread_local! {
    static SERIALIZATION_CONTEXT: RefCell<SerializationContext> = Default::default();
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(into = "String")]
pub struct Address(pub u64);

impl From<u64> for Address {
    fn from(v: u64) -> Self {
        Address(v)
    }
}

impl From<Address> for u64 {
    fn from(a: Address) -> Self {
        a.0
    }
}

impl From<Address> for String {
    fn from(a: Address) -> Self {
        a.to_string()
    }
}

impl std::ops::Deref for Address {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Address {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let pointer_width = SERIALIZATION_CONTEXT
            .with(|ctx| ctx.borrow().pointer_width.unwrap_or(PointerWidth::Unknown));
        match pointer_width {
            PointerWidth::Bits32 => write!(f, "{:#010x}", self.0),
            _ => write!(f, "{:#018x}", self.0),
        }
    }
}

pub type AddressOffset = Address;

#[derive(Debug, Clone, Default)]
pub struct LinuxStandardBase {
    pub id: String,
    pub release: String,
    pub codename: String,
    pub description: String,
}

/// Info about an exception that may have occurred
///
/// May not be available if the minidump wasn't triggered by an exception, or if required
/// info about the exception is missing
#[derive(Debug, Clone)]
pub struct ExceptionInfo {
    /// a `CrashReason` describing the crash reason.
    pub reason: CrashReason,
    /// The memory address implicated in the crash.
    ///
    /// If the crash reason implicates memory, this is the memory address that
    /// caused the crash. For data access errors this will be the data address
    /// that caused the fault. For code errors, this will be the address of the
    /// instruction that caused the fault.
    pub address: Address,
    /// In certain circumstances, the previous `address` member may report a sub-optimal value
    /// for debugging purposes. If instruction analysis is able to successfully determine a
    /// more helpful value, it will be reported here.
    pub adjusted_address: Option<AdjustedAddress>,
    /// A string representing the crashing instruction (if available)
    pub instruction_str: Option<String>,
    /// A list of memory accesses performed by crashing instruction (if available)
    pub memory_accesses: Option<Vec<MemoryAccess>>,
    /// Possible valid addresses which are one flipped bit away from the crashing address or adjusted address.
    ///
    /// The original address was possibly the result of faulty hardware, alpha particles, etc.
    pub possible_bit_flips: Vec<PossibleBitFlip>,
}

/// Info about a memory address that was adjusted from its reported value
///
/// There will be situations where the memory address reported by the OS is sub-optimal for
/// debugging purposes, such as when an array is accidently indexed into with a null pointer base,
/// at which point the address might read something like `0x00001000` when the more-useful address
/// would just be zero.
///
/// If such a correction was made, this will be included in `ExceptionInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjustedAddress {
    /// The original access was an Amd64 "non-canonical" address; actual address is provided here.
    NonCanonical(Address),
    /// The base pointer was null; offset from base is provided here.
    NullPointerWithOffset(AddressOffset),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BitFlipDetails {
    /// The bit flip caused a non-canonical address access.
    pub was_non_canonical: bool,
    /// The corrected address is null.
    pub is_null: bool,
    /// The original address was fairly low.
    ///
    /// This is only populated if `is_null` is true, and may indicate that a bit flip didn't occur
    /// (and the original value was merely a small value which is more likely to be produced by
    /// booleans, iteration, etc).
    pub was_low: bool,
    /// The number of registers near the corrected address.
    ///
    /// This will only be populated for sufficiently high addresses (to avoid high false positive
    /// rates).
    pub nearby_registers: u32,
    /// There are poison patterns in one or more registers.
    ///
    /// This may indicate that a bit flip _didn't_ occur, and instead there was a UAF.
    pub poison_registers: bool,
}

mod confidence {
    /* The hat from which these numbers are drawn.
           .~~~~`\~~\
          ;       ~~ \
          |           ;
      ,--------,______|---.
     /          \-----`    \
     `.__________`-_______-'
    */

    const HIGH: f32 = 0.90;
    const MEDIUM: f32 = 0.50;
    const LOW: f32 = 0.25;

    pub fn combine(values: &[f32]) -> f32 {
        1.0f32 - values.iter().map(|v| 1.0f32 - v).product::<f32>()
    }

    // TODO: do we want this at all, vs Option<f32> for confidence?
    // The only problem is there may not be a good way to display this (i.e. omitting a confidence
    // would potentially make those seem _stronger_).
    pub const BASELINE: f32 = LOW;

    pub const NON_CANONICAL: f32 = HIGH;
    pub const NULL: f32 = MEDIUM;
    pub const NEARBY_REGISTER: [f32; 4] = [MEDIUM, MEDIUM + 0.05, MEDIUM + 0.1, MEDIUM + 0.15];

    // Detractors
    pub const POISON: f32 = MEDIUM;
    pub const ORIGINAL_LOW: f32 = MEDIUM;
}

impl BitFlipDetails {
    /// Calculate a confidence level between 0 and 1 pertaining to the bit flip likelihood.
    pub fn confidence(&self) -> f32 {
        use confidence::*;
        let mut values = Vec::with_capacity(4);
        values.push(BASELINE);

        if self.was_non_canonical {
            values.push(NON_CANONICAL);
        }

        if self.is_null {
            let mut val = NULL;
            if self.was_low {
                val *= ORIGINAL_LOW;
            }
            values.push(val);
        }

        if self.nearby_registers > 0 {
            let nearby = std::cmp::min(self.nearby_registers as usize, NEARBY_REGISTER.len()) - 1;
            values.push(NEARBY_REGISTER[nearby]);
        }

        let mut ret = combine(&values);

        if self.poison_registers {
            ret *= POISON;
        }
        ret
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PossibleBitFlip {
    /// The un-bit-flipped (potentially correct) address.
    pub address: Address,
    /// The register which held the bit-flipped address, if from a register at all.
    pub source_register: Option<&'static str>,
    /// Heuristics related to the determination of the bit flip.
    pub details: BitFlipDetails,
    /// A confidence level for the bit flip, derived from the details.
    pub confidence: Option<f32>,
}

/// The maximum distance between addresses to consider them "nearby" when calculating bit flip
/// heuristics with regard to register contents.
const NEARBY_REGISTER_DISTANCE: u64 = 1 << 12;

/// The cutoff for addresses considered "low".
const LOW_ADDRESS_CUTOFF: u64 = NEARBY_REGISTER_DISTANCE * 2;

impl PossibleBitFlip {
    pub fn new(address: u64, source_register: Option<&'static str>) -> Self {
        PossibleBitFlip {
            address: address.into(),
            source_register,
            details: Default::default(),
            confidence: None,
        }
    }

    pub fn calculate_heuristics(
        &mut self,
        original_address: u64,
        was_non_canonical: bool,
        context: Option<&MinidumpContext>,
    ) {
        self.details.is_null = self.address.0 == 0;
        self.details.was_low = self.details.is_null && original_address <= LOW_ADDRESS_CUTOFF;
        self.details.was_non_canonical = was_non_canonical;

        self.details.nearby_registers = 0;
        self.details.poison_registers = false;
        if let Some(context) = context {
            let register_size = context.register_size();

            let is_repeated = match register_size {
                2 => |addr: u64| addr == (addr & 0xff) * 0x0101,
                4 => |addr: u64| addr == (addr & 0xff) * 0x01010101,
                8 => |addr: u64| addr == (addr & 0xff) * 0x0101010101010101,
                other => {
                    tracing::warn!("unsupported register size: {other}");
                    |_| false
                }
            };

            // Don't calculate nearby registers for low addresses, there will be a high false
            // positive rate.
            let should_calculate_nearby_registers = self.address.0 > LOW_ADDRESS_CUTOFF;

            for (_, addr) in context.valid_registers() {
                if should_calculate_nearby_registers
                    && self.address.0.abs_diff(addr) <= NEARBY_REGISTER_DISTANCE
                {
                    self.details.nearby_registers += 1;
                }

                if !self.details.poison_registers && is_repeated(addr) {
                    // Poison patterns from
                    // https://searchfox.org/mozilla-central/rev/3002762e41363de8ee9ca80196d55e79651bcb6b/js/src/util/Poison.h#52
                    //
                    // 0xa5 from xmalloc/jemalloc
                    // 0xe5 from mozilla jemalloc
                    // (https://searchfox.org/mozilla-central/source/memory/build/mozjemalloc.cpp#1412)
                    match (addr & 0xff) as u8 {
                        0x2b | 0x2d | 0x2f | 0x49 | 0x4b | 0x4d | 0x4f | 0x6b | 0x8b | 0x9b
                        | 0x9f | 0xa5 | 0xbb | 0xcc | 0xcd | 0xce | 0xdb | 0xe5 => {
                            self.details.poison_registers = true;
                        }
                        _ => (),
                    }
                }
            }
        }

        self.confidence = Some(self.details.confidence());
    }
}

/// The state of a process as recorded by a `Minidump`.
#[derive(Debug, Clone)]
pub struct ProcessState {
    /// The PID of the process.
    pub process_id: Option<u32>,
    /// When the minidump was written.
    pub time: SystemTime,
    /// When the process started, if available
    pub process_create_time: Option<SystemTime>,
    /// Known code signing certificates (module name => cert name)
    pub cert_info: HashMap<String, String>,
    /// Info about the exception that triggered the dump (if one did)
    pub exception_info: Option<ExceptionInfo>,
    /// A string describing an assertion that was hit, if present.
    pub assertion: Option<String>,
    /// The index of the thread that requested a dump be written.
    /// If a dump was produced as a result of a crash, this
    /// will point to the thread that crashed.  If the dump was produced as
    /// by user code without crashing, and the dump contains extended Breakpad
    /// information, this will point to the thread that requested the dump.
    /// If the dump was not produced as a result of an exception and no
    /// extended Breakpad information is present, this field will be
    /// `None`.
    pub requesting_thread: Option<usize>,
    /// Stacks for each thread (except possibly the exception handler
    /// thread) at the time of the crash.
    pub threads: Vec<CallStack>,
    // TODO:
    // thread_memory_regions
    /// Information about the system on which the minidump was written.
    pub system_info: SystemInfo,
    /// Linux Standard Base Info
    pub linux_standard_base: Option<LinuxStandardBase>,
    pub mac_crash_info: Option<Vec<RawMacCrashInfo>>,
    pub mac_boot_args: Option<MinidumpMacBootargs>,
    /// The modules that were loaded into the process represented by the
    /// `ProcessState`.
    pub modules: MinidumpModuleList,
    pub unloaded_modules: MinidumpUnloadedModuleList,
    // modules_without_symbols
    // modules_with_corrupt_symbols
    // exploitability
    pub unknown_streams: Vec<MinidumpUnknownStream>,
    pub unimplemented_streams: Vec<MinidumpUnimplementedStream>,
    pub symbol_stats: HashMap<String, SymbolStats>,
}

fn json_registers(ctx: &MinidumpContext) -> serde_json::Value {
    let registers: Cow<HashSet<&str>> = match ctx.valid {
        MinidumpContextValidity::All => {
            let gpr = ctx.general_purpose_registers();
            let set: HashSet<&str> = gpr.iter().cloned().collect();
            Cow::Owned(set)
        }
        MinidumpContextValidity::Some(ref which) => Cow::Borrowed(which),
    };

    let mut output = serde_json::Map::new();
    for &reg in ctx.general_purpose_registers() {
        if registers.contains(reg) {
            let reg_val = ctx.format_register(reg);
            output.insert(String::from(reg), json!(reg_val));
        }
    }
    json!(output)
}

fn eq_some<T: PartialEq>(opt: Option<T>, val: T) -> bool {
    match opt {
        Some(v) => v == val,
        None => false,
    }
}

impl ProcessState {
    /// `true` if the minidump was written in response to a process crash.
    pub fn crashed(&self) -> bool {
        self.exception_info.is_some()
    }
    /// Write a human-readable description of the process state to `f`.
    ///
    /// This is very verbose, it implements the output format used by
    /// minidump_stackwalk.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        self.print_internal(f, false)
    }

    /// Write a brief human-readable description of the process state to `f`.
    ///
    /// Only includes the summary at the top and a backtrace of the crashing thread.
    pub fn print_brief<T: Write>(&self, f: &mut T) -> io::Result<()> {
        self.print_internal(f, true)
    }

    fn print_internal<T: Write>(&self, f: &mut T, brief: bool) -> io::Result<()> {
        self.set_print_context();

        writeln!(f, "Operating system: {}", self.system_info.os.long_name())?;
        if let Some(ref ver) = self.system_info.format_os_version() {
            writeln!(f, "                  {ver}")?;
        }
        writeln!(f, "CPU: {}", self.system_info.cpu)?;
        if let Some(ref info) = self.system_info.cpu_info {
            writeln!(f, "     {info}")?;
        }
        writeln!(
            f,
            "     {} CPU{}",
            self.system_info.cpu_count,
            if self.system_info.cpu_count > 1 {
                "s"
            } else {
                ""
            }
        )?;
        if let Some(ref lsb) = self.linux_standard_base {
            writeln!(
                f,
                "Linux {} {} - {} ({})",
                lsb.id, lsb.release, lsb.codename, lsb.description
            )?;
        }
        writeln!(f)?;

        if let Some(ref crash_info) = self.exception_info {
            writeln!(f, "Crash reason:  {}", crash_info.reason)?;

            if let Some(adjusted_address) = &crash_info.adjusted_address {
                writeln!(f, "Crash address: {} **", crash_info.address)?;
                match adjusted_address {
                    AdjustedAddress::NonCanonical(address) => {
                        writeln!(f, "    ** Non-canonical address detected: {address}")?
                    }
                    AdjustedAddress::NullPointerWithOffset(offset) => {
                        writeln!(f, "    ** Null pointer detected with offset: {offset}")?
                    }
                }
            } else {
                writeln!(f, "Crash address: {}", crash_info.address)?;
            }

            if let Some(ref crashing_instruction_str) = crash_info.instruction_str {
                writeln!(f, "Crashing instruction: `{crashing_instruction_str}`")?;
            }

            if let Some(ref memory_accesses) = crash_info.memory_accesses {
                if !memory_accesses.is_empty() {
                    writeln!(f, "Memory accessed by instruction:")?;
                    for (idx, access) in memory_accesses.iter().enumerate() {
                        writeln!(f, "  {idx}. Address: {}", Address(access.address))?;
                        if let Some(size) = access.size {
                            writeln!(f, "     Size: {size}")?;
                        } else {
                            writeln!(f, "     Size: Unknown")?;
                        }
                        if access.is_likely_guard_page {
                            writeln!(f, "     This address falls in a likely guard page.")?;
                        }
                    }
                } else {
                    writeln!(f, "No memory accessed by instruction")?;
                }
            }

            if !crash_info.possible_bit_flips.is_empty() {
                writeln!(f, "Crashing address may be the result of a flipped bit:")?;
                let mut bit_flips_with_confidence = crash_info
                    .possible_bit_flips
                    .iter()
                    .map(|b| (b.confidence.unwrap_or_default(), b))
                    .collect::<Vec<_>>();
                // Sort by confidence (descending), then address (ascending).
                bit_flips_with_confidence.sort_unstable_by(|(conf_a, bf_a), (conf_b, bf_b)| {
                    conf_a
                        .total_cmp(conf_b)
                        .reverse()
                        .then_with(|| bf_a.address.cmp(&bf_b.address))
                });
                for (idx, (confidence, b)) in bit_flips_with_confidence.iter().enumerate() {
                    writeln!(
                        f,
                        "  {idx}. Valid address: {register}{addr} ({confidence:.3})",
                        addr = b.address,
                        register = match b.source_register {
                            None => Default::default(),
                            Some(name) => format!("{name}="),
                        }
                    )?;
                }
            }
        } else {
            writeln!(f, "No crash")?;
        }

        if let Some(ref assertion) = self.assertion {
            writeln!(f, "Assertion: {assertion}")?;
        }
        if let Some(ref info) = self.mac_crash_info {
            writeln!(f, "Mac Crash Info:")?;
            for (idx, record) in info.iter().enumerate() {
                writeln!(f, "  Record {idx}")?;
                if let Some(val) = record.thread() {
                    writeln!(f, "    thread: 0x{val}")?;
                }
                if let Some(val) = record.dialog_mode() {
                    writeln!(f, "    dialog mode: 0x{val}")?;
                }
                if let Some(val) = record.abort_cause() {
                    writeln!(f, "    abort_cause: 0x{val}")?;
                }

                if let Some(val) = record.module_path() {
                    writeln!(f, "    module: {val}")?;
                }
                if let Some(val) = record.message() {
                    writeln!(f, "    message: {val}")?;
                }
                if let Some(val) = record.signature_string() {
                    writeln!(f, "    signature string: {val}")?;
                }
                if let Some(val) = record.backtrace() {
                    writeln!(f, "    backtrace: {val}")?;
                }
                if let Some(val) = record.message2() {
                    writeln!(f, "    message2: {val}")?;
                }
            }
            writeln!(f)?;
        }
        if let Some(ref info) = self.mac_boot_args {
            writeln!(
                f,
                "Mac Boot Args: {}",
                info.bootargs.as_deref().unwrap_or("")
            )?;
            writeln!(f)?;
        }
        if let Some(ref time) = self.process_create_time {
            let uptime = self.time.duration_since(*time).unwrap_or_default();
            writeln!(f, "Process uptime: {} seconds", uptime.as_secs())?;
        } else {
            writeln!(f, "Process uptime: not available")?;
        }
        writeln!(f)?;

        if let Some(requesting_thread) = self.requesting_thread {
            let stack = &self.threads[requesting_thread];
            writeln!(
                f,
                "Thread {} {} ({})",
                requesting_thread,
                stack.thread_name.as_deref().unwrap_or(""),
                if self.crashed() {
                    "crashed"
                } else {
                    "requested dump, did not crash"
                }
            )?;
            stack.print(f)?;
            writeln!(f)?;
        }

        // We're done if this is a brief report!
        if brief {
            return Ok(());
        }

        for (i, stack) in self.threads.iter().enumerate() {
            if eq_some(self.requesting_thread, i) {
                // Don't print the requesting thread again,
                continue;
            }
            if stack.info == CallStackInfo::DumpThreadSkipped {
                continue;
            }
            writeln!(
                f,
                "Thread {} {}",
                i,
                stack.thread_name.as_deref().unwrap_or("")
            )?;
            stack.print(f)?;
        }
        write!(
            f,
            "
Loaded modules:
"
        )?;
        let main_address = self.modules.main_module().map(|m| m.base_address());
        for module in self.modules.by_addr() {
            // TODO: missing symbols, corrupt symbols
            let full_name = module.code_file();
            let name = basename(&full_name);
            write!(
                f,
                "{:#010x} - {:#010x}  {}  {}",
                module.base_address(),
                module.base_address() + module.size() - 1,
                name,
                module.version().unwrap_or(Cow::Borrowed("???"))
            )?;
            if eq_some(main_address, module.base_address()) {
                write!(f, "  (main)")?;
            }
            if let Some(cert) = self.cert_info.get(name) {
                write!(f, " ({cert})")?;
            }
            writeln!(f)?;
        }
        write!(
            f,
            "
Unloaded modules:
"
        )?;
        for module in self.unloaded_modules.by_addr() {
            let full_name = module.code_file();
            let name = basename(&full_name);
            write!(
                f,
                "{:#010x} - {:#010x}  {}",
                module.base_address(),
                module.base_address() + module.size() - 1,
                basename(&module.code_file()),
            )?;
            if let Some(cert) = self.cert_info.get(name) {
                write!(f, " ({cert})")?;
            }
            writeln!(f)?;
        }
        if !self.unimplemented_streams.is_empty() {
            write!(
                f,
                "
Unimplemented streams encountered:
"
            )?;
            for stream in &self.unimplemented_streams {
                writeln!(
                    f,
                    "Stream 0x{:08x} {:?} ({}) @ 0x{:08x}",
                    stream.stream_type as u32,
                    stream.stream_type,
                    stream.vendor,
                    stream.location.rva,
                )?;
            }
        }
        if !self.unknown_streams.is_empty() {
            write!(
                f,
                "
Unknown streams encountered:
"
            )?;
            for stream in &self.unknown_streams {
                writeln!(
                    f,
                    "Stream 0x{:08x} ({}) @ 0x{:08x}",
                    stream.stream_type, stream.vendor, stream.location.rva,
                )?;
            }
        }
        Ok(())
    }

    /// Outputs json in a schema compatible with mozilla's Socorro crash reporting servers.
    ///
    /// See the top level documentation of this library for the stable JSON schema.
    pub fn print_json<T: Write>(&self, f: &mut T, pretty: bool) -> Result<(), serde_json::Error> {
        // See ../json-schema.md for details on this format.

        self.set_print_context();

        let sys = &self.system_info;

        fn json_hex(address: u64) -> String {
            Address(address).to_string()
        }

        let mut output = json!({
            // Currently unused, we either produce no output or successful output.
            // OK | ERROR_* | SYMBOL_SUPPLIER_INTERRUPTED
            "status": "OK",
            "system_info": {
                // Linux | Windows NT | Mac OS X
                "os": sys.os.long_name(),
                "os_ver": sys.format_os_version(),
                // x86 | amd64 | arm | ppc | sparc
                "cpu_arch": sys.cpu.to_string(),
                "cpu_info": sys.cpu_info,
                "cpu_count": sys.cpu_count,
                // optional, print as hex string
                "cpu_microcode_version": sys.cpu_microcode_version.map(|num| format!("{num:#x}")),
            },
            "crash_info": {
                "type": self.exception_info.as_ref().map(|info| info.reason).map(|reason| reason.to_string()),
                "address": self.exception_info.as_ref().map(|info| info.address),
                "adjusted_address": self.exception_info.as_ref().map(|info| {
                    info.adjusted_address.as_ref().map(|adjusted| match adjusted {
                        AdjustedAddress::NonCanonical(address) => json!({
                            "kind": "non-canonical",
                            "address": address,
                        }),
                        AdjustedAddress::NullPointerWithOffset(offset) => json!({
                            "kind": "null-pointer",
                            "offset": offset,
                        }),
                    })
                }),
                "instruction": self.exception_info.as_ref().map(|info| info.instruction_str.as_ref()),
                "memory_accesses": self.exception_info.as_ref().and_then(|info| {
                    info.memory_accesses.as_ref().map(|accesses| {
                        accesses.iter().map(|access| {
                            let mut map = json!({
                                "address": json_hex(access.address),
                                "size": access.size,
                            });
                            // Only add the `is_likely_guard_page` field when it is affirmative.
                            if access.is_likely_guard_page {
                                map["is_likely_guard_page"] = true.into();
                            }
                            map
                        }).collect::<Vec<_>>()
                    })
                }),
                "possible_bit_flips": self.exception_info.as_ref().and_then(|info| {
                    (!info.possible_bit_flips.is_empty()).then_some(&info.possible_bit_flips)
                }),
                // thread index | null
                "crashing_thread": self.requesting_thread,
                "assertion": self.assertion,
            },
            // optional
            "lsb_release": self.linux_standard_base.as_ref().map(|lsb| json!({
                "id": lsb.id,
                "release": lsb.release,
                "codename": lsb.codename,
                "description": lsb.description,
            })),
            // optional
            "mac_crash_info": self.mac_crash_info.as_ref().map(|info| json!({
                "num_records": info.len(),
                // All of these fields are optional
                "records": info.iter().map(|record| json!({
                    "thread": record.thread().copied().map(json_hex),
                    "dialog_mode": record.dialog_mode().copied().map(json_hex),
                    "abort_cause": record.abort_cause().copied().map(json_hex),

                    "module": record.module_path(),
                    "message": record.message(),
                    "signature_string": record.signature_string(),
                    "backtrace": record.backtrace(),
                    "message2": record.message2(),
                })).collect::<Vec<_>>()
            })),
            // optional
            "mac_boot_args": self.mac_boot_args.as_ref().map(|info| info.bootargs.as_ref()),

            // the first module is always the main one
            "main_module": 0,
            // [UNSTABLE:evil_json]
            "modules_contains_cert_info": !self.cert_info.is_empty(),
            "modules": self.modules.iter().map(|module| {
                let full_name = module.code_file();
                let name = basename(&full_name);

                // Gather statistics on the module's symbols
                let stats = self.symbol_stats.get(name);
                let had_stats = stats.is_some();
                let default = SymbolStats::default();
                let stats = stats.unwrap_or(&default);
                // Only consider the symbols "missing" if the symbolizer
                // actually has statistics on them (implying it *tried* to
                // get the symbols but failed.)
                let missing_symbols = had_stats && !stats.loaded_symbols;
                json!({
                    "base_addr": json_hex(module.raw.base_of_image),
                    // filename | empty string
                    "debug_file": basename(module.debug_file().unwrap_or(Cow::Borrowed("")).borrow()),
                    // [[:xdigit:]]{33} | empty string
                    "debug_id": module.debug_identifier().unwrap_or_default().breakpad().to_string(),
                    "end_addr": json_hex(module.raw.base_of_image + module.raw.size_of_image as u64),
                    "filename": &name,
                    "code_id": module.code_identifier().unwrap_or_default().as_str(),
                    "version": module.version(),
                    // [UNSTABLE:evil_json]
                    "cert_subject": self.cert_info.get(name),

                    // These are all just metrics for debugging minidump-processor's execution

                    // optional, if mdsw looked for the file and it doesn't exist
                    "missing_symbols": missing_symbols,
                    // optional, if mdsw looked for the file and it does exist
                    "loaded_symbols": stats.loaded_symbols,
                    // optional, if mdsw found a file that has parse errors
                    "corrupt_symbols": stats.corrupt_symbols,
                    // optional, url of symbol file
                    "symbol_url": stats.symbol_url,
                })
            }).collect::<Vec<_>>(),
            "pid": self.process_id,
            "thread_count": self.threads.len(),
            "threads": self.threads.iter().map(|thread| json!({
                "frame_count": thread.frames.len(),
                // optional
                "last_error_value": thread.last_error_value.map(|error| error.to_string()),
                // optional
                "thread_name": thread.thread_name,
                "frames": thread.frames.iter().enumerate().map(|(idx, frame)| json!({
                    "frame": idx,
                    // optional
                    "module": frame.module.as_ref().map(|module| basename(&module.name)),
                    // optional
                    "function": frame.function_name,
                    // optional
                    "file": frame.source_file_name,
                    // optional
                    "line": frame.source_line,
                    "offset": json_hex(frame.instruction),
                    // optional
                    "inlines": if !frame.inlines.is_empty() {
                        Some(frame.inlines.iter().map(|frame| {
                            json!({
                                "function": frame.function_name,
                                "file": frame.source_file_name,
                                "line": frame.source_line,
                            })
                        }).collect::<Vec<_>>())
                    } else {
                        None
                    },
                    // optional
                    "module_offset": frame
                        .module
                        .as_ref()
                        .map(|module| frame.instruction - module.raw.base_of_image)
                        .map(json_hex),
                    // optional
                    "unloaded_modules": if frame.unloaded_modules.is_empty() {
                        None
                    } else {
                        Some(frame.unloaded_modules.iter().map(|(module, offsets)| json!({
                            "module": module,
                            "offsets": offsets.iter().copied().map(json_hex).collect::<Vec<_>>(),
                        })).collect::<Vec<_>>())
                    },
                    // optional
                    "function_offset": frame
                        .function_base
                        .map(|func_base| frame.instruction - func_base)
                        .map(json_hex),
                    "missing_symbols": frame.function_name.is_none(),
                    // none | scan | cfi_scan | frame_pointer | cfi | context | prewalked
                    "trust": frame.trust.as_str()
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),

            "unloaded_modules": self.unloaded_modules.iter().map(|module| json!({
                "base_addr": json_hex(module.raw.base_of_image),
                "code_id": module.code_identifier().unwrap_or_default().as_str(),
                "end_addr": json_hex(module.raw.base_of_image + module.raw.size_of_image as u64),
                "filename": module.name,
                "cert_subject": self.cert_info.get(&module.name),
            })).collect::<Vec<_>>(),
        });

        if let Some(requesting_thread) = self.requesting_thread {
            // Copy the crashing thread into a top-level "crashing_thread" field and:
            // * Add a "threads_index" field to indicate which thread it was
            // * Add a "registers" field to its first frame
            //
            // Note that we currently make crashing_thread a strict superset
            // of a normal "threads" entry, while the original schema strips
            // many of the fields here. We don't to keep things more uniform.

            // We can't do any of this work if we don't have at least one frame.
            if let Some(f) = self.threads[requesting_thread].frames.get(0) {
                let registers = json_registers(&f.context);

                // Yuck, spidering through json...
                let mut thread = output.get_mut("threads").unwrap().as_array().unwrap()
                    [requesting_thread]
                    .clone();
                let thread_obj = thread.as_object_mut().unwrap();
                let frames = thread_obj
                    .get_mut("frames")
                    .unwrap()
                    .as_array_mut()
                    .unwrap();
                let frame = frames[0].as_object_mut().unwrap();

                frame.insert(String::from("registers"), registers);
                thread_obj.insert(String::from("threads_index"), json!(requesting_thread));

                output
                    .as_object_mut()
                    .unwrap()
                    .insert(String::from("crashing_thread"), thread);
            }
        }

        if pretty {
            serde_json::to_writer_pretty(f, &output)
        } else {
            serde_json::to_writer(f, &output)
        }
    }

    fn set_print_context(&self) {
        SERIALIZATION_CONTEXT.with(|ctx| {
            ctx.borrow_mut().pointer_width = Some(self.system_info.cpu.pointer_width());
        });
    }
}
