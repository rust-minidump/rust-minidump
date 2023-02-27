use anyhow::Context;
use clap::Parser;
use futures_util::future;
use minidump::{
    Minidump, MinidumpException, MinidumpMemoryList, MinidumpMiscInfo, MinidumpModule,
    MinidumpModuleList, MinidumpSystemInfo, MinidumpThread, MinidumpThreadList, Module,
    UnifiedMemoryList,
};
use minidump_processor::{
    symbols::debuginfo::DebugInfoSymbolProvider, walk_stack, CallStack, CallStackInfo, FrameTrust,
    ProcessorOptions, SystemInfo,
};
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

/// Analyze a minidump file to augment a corresponding .extra file with stack trace information.
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Generate all stacks, rather than just those of the crashing thread.
    #[arg(long = "full")]
    all_stacks: bool,

    /// The minidump file to analyze.
    minidump: PathBuf,
}

impl Args {
    /// Get the extra file.
    ///
    /// This file is derived from the minidump file path.
    pub fn extra_file(&self) -> PathBuf {
        let mut ret = self.minidump.clone();
        ret.set_extension("extra");
        ret
    }
}

mod processor {
    use super::*;

    pub struct Processor<'a> {
        rt: tokio::runtime::Runtime,
        // We create a Context abstraction to easily spawn tokio tasks (which must be 'static).
        context: Arc<Ctx<'a>>,
    }

    struct Ctx<'a> {
        processor_options: ProcessorOptions<'a>,
        module_list: MinidumpModuleList,
        memory_list: UnifiedMemoryList<'a>,
        system_info: MinidumpSystemInfo,
        processor_system_info: SystemInfo,
        misc_info: Option<MinidumpMiscInfo>,
        symbol_provider: DebugInfoSymbolProvider,
    }

    impl<'a> Processor<'a> {
        pub fn new<T>(
            processor_options: ProcessorOptions<'a>,
            minidump: &'a Minidump<T>,
        ) -> anyhow::Result<Self>
        where
            T: std::ops::Deref<Target = [u8]>,
        {
            let system_info = minidump.get_stream::<MinidumpSystemInfo>()?;
            let misc_info = minidump.get_stream::<MinidumpMiscInfo>().ok();
            let module_list = minidump
                .get_stream::<MinidumpModuleList>()
                .unwrap_or_default();
            let memory_list = minidump
                .get_stream::<MinidumpMemoryList>()
                .unwrap_or_default();

            // TODO Something like SystemInfo::current() to get the active system's info?
            let processor_system_info = SystemInfo {
                os: system_info.os,
                os_version: None,
                os_build: None,
                cpu: system_info.cpu,
                cpu_info: None,
                cpu_microcode_version: None,
                cpu_count: 1,
            };

            let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            Ok(Processor {
                rt: tokio_runtime,
                context: Arc::new(Ctx {
                    processor_options,
                    module_list,
                    memory_list: UnifiedMemoryList::Memory(memory_list),
                    system_info,
                    processor_system_info,
                    misc_info,
                    symbol_provider: Default::default(),
                }),
            })
        }

        /// Get the minidump system info.
        pub fn system_info(&self) -> &MinidumpSystemInfo {
            &self.context.system_info
        }

        /// Get call stacks for the given threads.
        ///
        /// Call stacks will be concurrently calculated.
        pub fn thread_call_stacks<'b>(
            &self,
            threads: impl IntoIterator<Item = &'b MinidumpThread<'b>>,
        ) -> anyhow::Result<Vec<CallStack>> {
            self.rt
                .block_on(async move {
                    future::join_all(
                        threads.into_iter().enumerate().map(|(thread_idx, thread)| {
                            // # Safety
                            // We block on these spawned tasks immediately, so we lie about the lifetimes
                            // because we know they will be valid.
                            // Unfortunately there's no more ergonomic interface for this.
                            let context = unsafe {
                                std::mem::transmute::<Arc<Ctx>, Arc<Ctx<'static>>>(
                                    self.context.clone(),
                                )
                            };
                            let thread = unsafe {
                                std::mem::transmute::<
                                    &MinidumpThread,
                                    &'static MinidumpThread<'static>,
                                >(thread)
                            };
                            tokio::spawn(async move {
                                context.thread_call_stack(thread_idx, thread).await
                            })
                        }),
                    )
                    .await
                })
                .into_iter()
                .collect::<Result<_, _>>()
                .context("while spawning tasks")
        }

        /// Get all modules, ordered by address.
        pub fn modules(&self) -> impl Iterator<Item = &MinidumpModule> {
            self.context.module_list.by_addr()
        }

        /// Get the index of the given module in the iterator returned by `modules`.
        pub fn module_index(&self, module: &MinidumpModule) -> Option<usize> {
            self.modules()
                .position(|o| module.base_address() == o.base_address())
        }

        /// Get the index of the main module.
        ///
        /// Returns `None` when no main module exists (only when there are modules).
        pub fn main_module_index(&self) -> Option<usize> {
            self.context
                .module_list
                .main_module()
                .and_then(|m| self.module_index(m))
        }

        /// Convert a call stack to json (in a form appropriate for the extra json file).
        pub fn call_stack_to_json(&self, call_stack: &CallStack) -> json::JsonValue {
            json::object! {
                "frames": call_stack.frames.iter().map(|frame| {
                    json::object! {
                        "ip": frame.instruction,
                        "module_index": frame.module.as_ref().and_then(|m| self.module_index(m)),
                        "trust": frame.trust.json_name(),
                    }
                }).collect::<Vec<_>>()
            }
        }

        /// Get the json representation of module signature information.
        pub fn module_signature_info(&self) -> json::JsonValue {
            // TODO { binary_org_name: [code_file filename] }
            // authenticode_parser uses system openssl, which may be undesirable. In that case, we may
            // want to directly use `winapi`.
            json::JsonValue::Null
        }
    }

    impl Ctx<'_> {
        /// Compute the call stack for a single thread.
        pub async fn thread_call_stack(
            &self,
            thread_idx: usize,
            thread: &MinidumpThread<'_>,
        ) -> CallStack {
            let context = thread
                .context(&self.system_info, self.misc_info.as_ref())
                .map(|c| c.into_owned());
            let stack_memory = thread.stack_memory(&self.memory_list);
            let Some(mut call_stack) = context.map(CallStack::with_context) else {
                return CallStack::with_info(thread.raw.thread_id, CallStackInfo::MissingContext);
            };

            walk_stack(
                thread_idx,
                &self.processor_options,
                &mut call_stack,
                stack_memory,
                &self.module_list,
                &self.processor_system_info,
                &self.symbol_provider,
            )
            .await;

            call_stack
        }
    }
}

use processor::Processor;

pub fn main() {
    env_logger::init();

    if let Err(e) = try_main() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn try_main() -> anyhow::Result<()> {
    let args = Args::parse();
    let extra_file = args.extra_file();

    log::info!("minidump file path: {}", args.minidump.display());
    log::info!("extra file path: {}", extra_file.display());

    let minidump = Minidump::read_path(&args.minidump).context("while reading minidump")?;

    let mut extra_json = {
        let mut extra_file_content = String::new();
        File::open(&extra_file)
            .context("while opening extra file")?
            .read_to_string(&mut extra_file_content)
            .context("while reading extra file")?;

        json::parse(&extra_file_content).context("while parsing extra file JSON")?
    };

    let mut processor_options = ProcessorOptions::stable_all();
    processor_options.evil_json = Some(extra_file.as_path());

    // Read relevant information from the minidump.
    let proc = Processor::new(processor_options, &minidump)?;
    let exception = minidump.get_stream::<MinidumpException>()?;
    let thread_list = minidump.get_stream::<MinidumpThreadList>()?;

    // Derive additional arguments used in stack walking.
    let crashing_thread = thread_list
        .get_thread(exception.get_crashing_thread_id())
        .ok_or(anyhow::anyhow!(
            "exception thread id missing in thread list"
        ))?;

    let (crashing_thread_idx, call_stacks) = if args.all_stacks {
        (
            thread_list
                .threads
                .iter()
                .position(|t| t.raw.thread_id == crashing_thread.raw.thread_id)
                .expect("get_thread() returned a thread that doesn't exist"),
            proc.thread_call_stacks(&thread_list.threads)?,
        )
    } else {
        (0, proc.thread_call_stacks([crashing_thread])?)
    };

    let crash_type = exception
        .get_crash_reason(proc.system_info().os, proc.system_info().cpu)
        .to_string();
    let crash_address = exception.get_crash_address(proc.system_info().os, proc.system_info().cpu);

    extra_json["StackTraces"] = json::object! {
        "status": call_stack_status(&call_stacks),
        "crash_info": {
            "type": crash_type,
            "address": format!("{crash_address:#x}"),
            "crashing_thread": crashing_thread_idx
            // TODO: "assertion" when there's no crash indicator
        },
        "main_module": proc.main_module_index(),
        "modules": proc.modules().map(|module| {
            json::object! {
                "base_addr": format!("{:#x}", module.base_address()),
                "end_addr": format!("{:#x}", module.base_address() + module.size()),
                "filename": module.code_file().as_ref(),
                "code_id": module.code_identifier().as_ref().map(|id| id.as_str()),
                "debug_file": module.debug_file().as_deref(),
                "debug_id": module.debug_identifier().map(|debug| debug.breakpad().to_string()),
                "version": module.version().as_deref()
            }
        }).collect::<Vec<_>>(),
        // TODO "unloaded_modules"
        "threads": call_stacks.iter().map(|call_stack| proc.call_stack_to_json(call_stack)).collect::<Vec<_>>()
    };

    extra_json["ModuleSignatureInfo"] = proc.module_signature_info();

    let mut output = File::create(&extra_file).context("while truncating extra file")?;
    extra_json
        .write(&mut output)
        .context("while writing modified extra file")?;

    Ok(())
}

fn call_stack_status(stacks: &[CallStack]) -> json::JsonValue {
    use std::fmt::Write;

    /// Add a separator if a string is non-empty.
    fn add_separator(s: &mut String) {
        if !s.is_empty() {
            s.push_str(", ");
        }
    }

    let mut error_string = String::new();

    for (i, s) in stacks.iter().enumerate() {
        match s.info {
            CallStackInfo::Ok | CallStackInfo::DumpThreadSkipped => (),
            CallStackInfo::UnsupportedCpu => {
                // If the CPU is unsupported, it ought to be the same error for every thread.
                error_string = "unsupported cpu".into();
                break;
            }
            CallStackInfo::MissingContext => {
                add_separator(&mut error_string);
                write!(&mut error_string, "frame {i} missing context").unwrap();
            }
            CallStackInfo::MissingMemory => {
                add_separator(&mut error_string);
                write!(&mut error_string, "frame {i} missing stack memory").unwrap();
            }
        }
    }
    if error_string.is_empty() {
        "OK".into()
    } else {
        error_string.into()
    }
}
