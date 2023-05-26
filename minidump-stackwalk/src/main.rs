// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::fs::File;
use std::io::Write;
use std::ops::Deref;
use std::panic;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{boxed::Box, path::PathBuf};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use minidump::*;
use minidump_processor::{
    PendingProcessorStatSubscriptions, PendingProcessorStats, ProcessorOptions,
};
use minidump_unwind::{
    debuginfo::DebugInfoSymbolProvider, http_symbol_supplier, simple_symbol_supplier,
    MultiSymbolProvider, SymbolProvider, Symbolizer,
};

use clap::{
    builder::{PossibleValuesParser, TypedValueParser},
    ArgGroup, CommandFactory, Parser,
};
use tracing::error;
use tracing::level_filters::LevelFilter;

/// Analyzes minidumps and produces a report (either human-readable or JSON)
///
/// NOTES:
///
/// Purpose of Symbols:
///
/// Symbols are used for two purposes:
///
///  1. To fill in more information about each frame of the backtraces. (function names, lines, etc.)
///  2. To produce a more *accurate* backtrace. This is primarily accomplished with call frame
///     information (CFI), but just knowing what parts of a module maps to actual code is also
///     useful!
///
/// Supported Symbol Formats:
///
/// Currently only breakpad text symbol files are supported, although we hope to eventually
/// support native formats like PDB and DWARF as well.
///
/// Breakpad Symbol Files:
///
/// Breakpad symbol files are basically a simplified version of the information found in
/// native debuginfo formats. We recommend using a version of dump_syms to generate them.
///
/// See:
/// * <https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md>
/// * mozilla's dump_syms (co-developed with this program): <https://github.com/mozilla/dump_syms>
#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[clap(propagate_version = true)]
#[clap(group(ArgGroup::new("output-format").args(&[
    "json",
    "human",
    "cyborg",
    "dump",
    "help_markdown",
])))]
#[clap(override_usage("minidump-stackwalk [FLAGS] [OPTIONS] <minidump> [--] [symbols-path]..."))]
#[clap(verbatim_doc_comment)]
struct Cli {
    /// Emit a human-readable report (the default)
    ///
    /// The human-readable report does not have a specified format, and may not have as
    /// many details as the JSON format. It is intended for quickly inspecting
    /// a crash or debugging rust-minidump itself.
    ///
    /// Can be simplified with --brief
    #[arg(long)]
    human: bool,

    /// Emit a machine-readable JSON report
    ///
    /// The schema for this output is officially documented here:
    /// <https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md>
    ///
    /// Can be pretty-printed with --pretty
    #[arg(long)]
    json: bool,

    /// Combine --human and --json
    ///
    /// Because this creates two output streams, you must specify a path to write the --json
    /// output to. The --human output will be the 'primary' output and default to stdout, which
    /// can be configured with --output-file as normal.
    #[arg(long)]
    cyborg: Option<PathBuf>,

    /// Dump the 'raw' contents of the minidump
    ///
    /// This is an implementation of the functionality of the old minidump_dump tool.
    /// It minimally parses and interprets the minidump in an attempt to produce a
    /// fairly 'raw' dump of the minidump's contents. This is most useful for debugging
    /// minidump-stackwalk itself, or a misbehaving minidump generator.
    ///
    /// Can be simplified with --brief
    #[arg(long)]
    dump: bool,

    /// Print --help but formatted as markdown (used for generating docs)
    #[arg(long, hide = true)]
    help_markdown: bool,

    /// Specify at a high-level how much analysis to perform
    ///
    /// This flag provides a way to more blindly opt into Extra Analysis without having
    /// to know about the specific features of minidump-stackwalk. This is equivalent to
    /// ProcessorOptions in minidump-processor. The current supported values are:
    ///  
    /// * stable-basic (default): give me solid detailed analysis that most people would want
    /// * stable-all: turn on extra detailed analysis.
    /// * unstable-all: turn on the weird and experimental stuff.
    ///  
    /// stable-all enables: nothing (currently identical to stable-basic)
    ///  
    /// unstable-all enables: `--recover-function-args`
    ///  
    /// minidump-stackwalk wants to be a reliable and stable tool, but we also want to be able
    /// to introduce new features which may be experimental or expensive. To balance these two
    /// concerns, new features will usually be disabled by default and given a specific flag,
    /// but still more easily 'discovered' by anyone who uses this flag.
    ///  
    /// Anyone using minidump-stackwalk who is *really* worried about the output being stable
    /// should probably not use this flag in production, but its use is recommended for casual
    /// human usage or for checking "what's new".
    ///  
    /// Features under unstable-all may be deprecated and become noops. Features which require
    /// additional input (such as `--evil-json`) cannot be affected by this, and must still be
    /// manually 'discovered'.
    #[arg(long, default_value = "stable-basic")]
    #[arg(value_parser = ["stable-basic", "stable-all", "unstable-all"])]
    #[arg(verbatim_doc_comment)]
    features: String,

    /// How verbose logging should be (log level)
    ///
    /// The unwinder has been heavily instrumented with `trace` logging, so if you want to
    /// debug why an unwind happened the way it did, --verbose=trace is very useful
    /// (all unwinder logging will be prefixed with `unwind:`).
    #[arg(long)]
    #[arg(default_value = "error")]
    #[arg(value_parser = PossibleValuesParser::new(["off", "error", "warn", "info", "debug", "trace"]).map(|v| LevelFilter::from_str(&v).unwrap()))]
    verbose: LevelFilter,

    /// Where to write the output to (if unspecified, stdout is used)
    #[arg(long)]
    output_file: Option<PathBuf>,

    /// Where to write logs to (if unspecified, stderr is used)
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Prevent the output/logging from using ANSI coloring
    ///
    /// Output written to a file via --log-file, --output-file, or --cyborg
    /// is always --no-color, so this just forces stdout/stderr printing.
    #[arg(long)]
    no_color: bool,

    /// Pretty-print --json output
    #[arg(long)]
    pretty: bool,

    /// Provide a briefer --human or --dump report
    ///
    /// For human: Only provides the top-level summary and a backtrace of the crashing thread.
    ///
    /// For dump: Omits all memory hexdumps.
    #[arg(long)]
    brief: bool,

    /// Disable all interactive progress feedback
    ///
    /// We'll generally try to auto-detect when this should be disabled, but this is here in
    /// case we mess up and you need it to go away.
    #[arg(long)]
    no_interactive: bool,

    /// **UNSTABLE** An input JSON file with the extra information.
    ///
    /// This is a gross hack for some legacy side-channel information that mozilla uses.
    /// It will hopefully be phased out and deprecated in favour of just using custom
    /// streams in the minidump itself.
    #[arg(long)]
    evil_json: Option<PathBuf>,

    /// **UNSTABLE** Heuristically recover function arguments
    ///
    /// This is an experimental feature, which currently only shows up in --human output.
    #[arg(long)]
    recover_function_args: bool,

    /// Use debug information from local files referred to by the minidump, if present.
    #[arg(long)]
    use_local_debuginfo: bool,

    /// base URL from which URLs to symbol files can be constructed
    ///
    /// If multiple symbols-url values are provided, they will each be tried in order until
    /// one resolves.
    ///
    /// The server the base URL points to is expected to conform to the Tecken
    /// symbol server protocol. For more details, see the Tecken docs:
    ///
    /// <https://tecken.readthedocs.io/en/latest/>
    ///
    /// Example symbols-url values:
    /// * microsoft's symbol-server: <https://msdl.microsoft.com/download/symbols/>
    /// * mozilla's symbols-server: <https://symbols.mozilla.org/>
    #[arg(long)]
    #[arg(verbatim_doc_comment)]
    symbols_url: Vec<String>,

    /// A directory in which downloaded symbols can be stored
    ///
    /// Symbol files can be very large, so we recommend placing cached files in your
    /// system's temp directory so that it can garbage collect unused ones for you.
    /// To this end, the default value for this flag is a `rust-minidump-cache`
    /// subdirectory of `std::env::temp_dir()` (usually /tmp/rust-minidump-cache on linux).
    ///
    /// symbols-cache must be on the same filesystem as symbols-tmp (if that doesn't
    /// mean anything to you, don't worry about it, you're probably not doing something
    /// that will run afoul of it).
    #[arg(long)]
    symbols_cache: Option<PathBuf>,

    /// A directory to use as temp space for downloading symbols.
    ///
    /// A temp dir is necessary to allow for multiple rust-minidump instances to share a
    /// cache without race conditions. Files to be added to the cache will be constructed
    /// in this location before being atomically moved to the cache.
    ///
    /// If no path is specified, `std::env::temp_dir()` will be used to improve portability.
    /// See the rust documentation for how to set that value if you wish to use something
    /// other than your system's default temp directory.
    ///
    /// symbols-tmp must be on the same filesystem as symbols-cache (if that doesn't
    /// mean anything to you, don't worry about it, you're probably not doing something
    /// that will run afoul of it).
    #[arg(long)]
    symbols_tmp: Option<PathBuf>,

    /// The maximum amount of time (in seconds) a symbol file download is allowed to take
    ///
    /// This is necessary to enforce forward progress on misbehaving http responses.
    #[arg(long, default_value_t = 1000)]
    symbols_download_timeout_secs: u64,

    /// Path to the minidump file to analyze
    minidump: PathBuf,

    /// Path to a symbol file.
    ///
    /// If multiple symbols-path values are provided, all symbol files will be merged
    /// into minidump-stackwalk's symbol database.
    #[arg(long)]
    symbols_path: Vec<PathBuf>,

    /// Path to a symbol file. (Passed positionally)
    ///
    /// If multiple symbols-path-legacy values are provided, all symbol files will be merged
    /// into minidump-stackwalk's symbol database.
    symbols_path_legacy: Vec<PathBuf>,
}

#[tokio::main]
async fn main() {
    if let Err(e) = main_result().await {
        // Ignore broken pipe errors, they will only occur from stdio, typically when a user is
        // piping into another program but that program doesn't read all input.
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg_attr(test, allow(dead_code))]
async fn main_result() -> std::io::Result<()> {
    let cli = Cli::parse();

    // Init the logger (and make trace logging less noisy)
    if let Some(log_path) = &cli.log_file {
        let log_file = File::create(log_path)?;
        tracing_subscriber::fmt::fmt()
            .with_max_level(cli.verbose)
            .with_target(false)
            .without_time()
            .with_ansi(false)
            .with_writer(log_file)
            .init();
    } else {
        tracing_subscriber::fmt::fmt()
            .with_max_level(cli.verbose)
            .with_target(false)
            .without_time()
            .with_ansi(!cli.no_color)
            .with_writer(std::io::stderr)
            .init();
    }

    // Set a panic hook to redirect to the logger
    panic::set_hook(Box::new(|panic_info| {
        let (filename, line) = panic_info
            .location()
            .map(|loc| (loc.file(), loc.line()))
            .unwrap_or(("<unknown>", 0));
        let cause = panic_info
            .payload()
            .downcast_ref::<String>()
            .map(String::deref)
            .unwrap_or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<&str>()
                    .copied()
                    .unwrap_or("<cause unknown>")
            });
        error!(
            "Panic - A panic occurred at {}:{}: {}",
            filename, line, cause
        );
    }));

    // This is a little hack to generate a markdown version of the --help message,
    // to be used by rust-minidump devs to regenerate docs. Not officially part
    // of our public API.
    if cli.help_markdown {
        print_help_markdown(&mut std::io::stdout()).expect("help-markdown failed");
        return Ok(());
    }

    let temp_dir = std::env::temp_dir();

    let mut symbols_paths = cli.symbols_path;
    symbols_paths.extend(cli.symbols_path_legacy);

    // Default to env::temp_dir()/rust-minidump-cache
    let symbols_cache = cli
        .symbols_cache
        .unwrap_or_else(|| temp_dir.join("rust-minidump-cache"));

    // Default to env::temp_dir()
    let symbols_tmp = cli.symbols_tmp.unwrap_or(temp_dir);

    let timeout = Duration::from_secs(cli.symbols_download_timeout_secs);

    // Determine the kind of output we're producing -- dump, json, human, or cyborg (both).
    // Although we have a --human argument it's mostly just there to make the documentation
    // more clear. human output is enabled by default, and --json disables it.
    // Mutual exclusion is enforced by an ArgGroup, but it doesn't understand that "human"
    // is the implicit default, so we have to do some munging here.
    // Human is just enabled if nothing else is
    let raw_dump = cli.dump;
    let mut json = cli.json;
    let mut human = !json && !raw_dump;
    // Cyborg is just "desugarred" to --json --human
    if cli.cyborg.is_some() {
        human = true;
        json = true;
    }

    // Now check if arguments that tweak the output are valid. We can't use
    // Arg::requires because clap doesn't understand --json being implicitly enabled.
    if cli.pretty && !json {
        error!("Humans must be hideous! (The --pretty and --human flags cannot both be set)");
        std::process::exit(1);
    }

    if cli.brief && !(human || raw_dump) {
        error!("Robots cannot be brief! (The --brief flag is only valid for --human, --cyborg, and --dump)");
        std::process::exit(1);
    }

    // Pick the default options
    let mut options = match &*cli.features {
        "stable-basic" => ProcessorOptions::stable_basic(),
        "stable-all" => ProcessorOptions::stable_all(),
        "unstable-all" => ProcessorOptions::unstable_all(),
        _ => unimplemented!("unknown --features value"),
    };

    // Now overload the defaults
    options.evil_json = cli.evil_json.as_deref();
    options.recover_function_args = cli.recover_function_args;

    // Register for instractive updates, if we want them
    let interactive_enabled = !json && !cli.no_interactive && cli.output_file.is_none();
    let mut processor_stats = None;
    if interactive_enabled {
        let mut subscriptions = PendingProcessorStatSubscriptions::default();
        subscriptions.frame_count = true;
        subscriptions.thread_count = true;
        processor_stats = Some(PendingProcessorStats::new(subscriptions));
        options.stat_reporter = processor_stats.as_ref();
    }

    // Ok now let's do the thing!!!!

    match Minidump::read_path(cli.minidump) {
        Ok(dump) => {
            let mut stdout;
            let mut output_f;
            let cyborg_output_f = cli.cyborg.map(File::create).transpose()?;

            let mut output: &mut dyn Write = if let Some(output_path) = cli.output_file {
                output_f = File::create(output_path)?;
                &mut output_f
            } else {
                stdout = std::io::stdout();
                &mut stdout
            };

            // minidump_dump mode
            if raw_dump {
                return print_minidump_dump(&dump, &mut output, cli.brief);
            }

            let mut provider = MultiSymbolProvider::new();

            if cli.use_local_debuginfo {
                provider.add(Box::<DebugInfoSymbolProvider>::default());
            }

            if !cli.symbols_url.is_empty() {
                provider.add(Box::new(Symbolizer::new(http_symbol_supplier(
                    symbols_paths,
                    cli.symbols_url,
                    symbols_cache,
                    symbols_tmp,
                    timeout,
                ))));
            } else if !symbols_paths.is_empty() {
                provider.add(Box::new(Symbolizer::new(simple_symbol_supplier(
                    symbols_paths,
                ))));
            }

            let interactive_ui = processor_stats
                .as_ref()
                .map(|processor_stats| InterativeUi {
                    all: MultiProgress::new(),
                    symbol_progress: ProgressBar::hidden(),
                    thread_progress: ProgressBar::hidden(),
                    frame_progress: ProgressBar::hidden(),
                    total_progress: ProgressBar::hidden(),
                    needed_stats: AtomicBool::new(false),
                    symbol_stats: &provider,
                    processor_stats,
                });

            let update_state = || async {
                // Do an initial sleep to avoid reporting things for fast ops
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                loop {
                    if let Some(interactive_ui) = &interactive_ui {
                        update_status(interactive_ui, false);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            };

            let result = tokio::select! {
                result = minidump_processor::process_minidump_with_options(&dump, &provider, options) => result,
                _ = update_state() => unreachable!(),
            };

            // Do one final sync stat update
            if let Some(interactive_ui) = &interactive_ui {
                update_status(interactive_ui, true);
            }

            match result {
                Ok(state) => {
                    // Print the human output if requested (always uses the "real" output).
                    if human {
                        if cli.brief {
                            state.print_brief(&mut output)?;
                        } else {
                            state.print(&mut output)?;
                        }
                    }

                    // Print the json output if requested (using "cyborg" output if available).
                    if json {
                        if let Some(mut cyborg_output_f) = cyborg_output_f {
                            state.print_json(&mut cyborg_output_f, cli.pretty)?;
                        } else {
                            state.print_json(&mut output, cli.pretty)?;
                        }
                    }
                    Ok(())
                }
                Err(err) => {
                    error!("{} - Error processing dump: {}", err.name(), err);
                    std::process::exit(1);
                }
            }
        }
        Err(err) => {
            error!("{} - Error reading dump: {}", err.name(), err);
            std::process::exit(1);
        }
    }
}

fn print_help_markdown(out: &mut dyn Write) -> std::io::Result<()> {
    let app_name = "minidump-stackwalk";
    let pretty_app_name = "minidump-stackwalk";
    // Make a new App to get the help message this time.

    writeln!(out, "# {pretty_app_name} CLI manual")?;
    writeln!(out)?;
    writeln!(
        out,
        "> This manual can be regenerated with `{pretty_app_name} --help-markdown please`"
    )?;
    writeln!(out)?;

    let mut cli = Cli::command().term_width(0);
    let full_command = &mut cli;
    full_command.build();
    let mut todo = vec![full_command];
    let mut is_full_command = true;

    while let Some(command) = todo.pop() {
        let mut help_buf = Vec::new();
        command.write_long_help(&mut help_buf)?;
        let help = String::from_utf8(help_buf).unwrap();

        // First line is --version
        let lines = help.lines();
        // let version_line = lines.next().unwrap();
        let subcommand_name = command.get_name();

        if is_full_command {
            // writeln!(out, "Version: `{version_line}`")?;
            // writeln!(out)?;
        } else {
            // Give subcommands some breathing room
            writeln!(out, "<br><br><br>")?;
            writeln!(out, "## {pretty_app_name} {subcommand_name}")?;
        }

        let mut in_subcommands_listing = false;
        let mut in_global_options = false;
        for line in lines {
            if let Some(usage) = line.strip_prefix("Usage: ") {
                writeln!(out, "### Usage:")?;
                writeln!(out)?;
                writeln!(out, "```")?;
                writeln!(out, "{usage}")?;
                writeln!(out, "```")?;
                continue;
            }

            // Use a trailing colon to indicate a heading
            if let Some(heading) = line.strip_suffix(':') {
                if !line.starts_with(' ') {
                    in_subcommands_listing = heading == "Subcommands";

                    in_global_options = heading == "GLOBAL OPTIONS";

                    writeln!(out, "### {heading}")?;

                    if in_global_options && !is_full_command {
                        writeln!(
                            out,
                            "This subcommand accepts all the [global options](#global-options)"
                        )?;
                    }
                    continue;
                }
            }

            if in_global_options && !is_full_command {
                // Skip global options for non-primary commands
                continue;
            }

            if in_subcommands_listing && !line.starts_with("     ") {
                // subcommand names are list items
                let own_subcommand_name = line.trim();
                if !own_subcommand_name.is_empty() {
                    write!(
                        out,
                        "* [{own_subcommand_name}](#{app_name}-{own_subcommand_name}): "
                    )?;
                    continue;
                }
            }
            // The rest is indented, get rid of that
            let line = line.trim();

            // argument names are subheadings
            if line.starts_with('-') || line.starts_with('<') {
                writeln!(out, "#### `{line}`")?;
                continue;
            }
            if line == "[SYMBOLS_PATH_LEGACY]..." {
                writeln!(out, "#### `{line}`")?;
                continue;
            }

            // escape default/value strings
            if line.starts_with('[') {
                writeln!(out, "\\{line}  ")?;
                continue;
            }

            // Normal paragraph text
            writeln!(out, "{line}")?;
        }
        writeln!(out)?;

        // The todo list is a stack, and processed in reverse-order, append
        // these commands to the end in reverse-order so the first command is
        // processed first (i.e. at the end of the list).
        todo.extend(
            command
                .get_subcommands_mut()
                .filter(|cmd| !cmd.is_hide_set())
                .collect::<Vec<_>>()
                .into_iter()
                .rev(),
        );
        is_full_command = false;
    }

    Ok(())
}

fn print_minidump_dump<'a, T, W>(
    dump: &Minidump<'a, T>,
    output: &mut W,
    brief: bool,
) -> std::io::Result<()>
where
    T: Deref<Target = [u8]> + 'a,
    W: Write,
{
    dump.print(output)?;

    // Other streams depend on these, so load them upfront.
    let system_info = dump.get_stream::<MinidumpSystemInfo>().ok();
    let mut memory_list = dump.get_stream::<MinidumpMemoryList<'_>>().ok();
    let mut memory64_list = dump.get_stream::<MinidumpMemory64List<'_>>().ok();
    let misc_info = dump.get_stream::<MinidumpMiscInfo>().ok();

    let unified_memory = memory64_list
        .take()
        .map(UnifiedMemoryList::Memory64)
        .or_else(|| memory_list.take().map(UnifiedMemoryList::Memory));
    if let Ok(thread_list) = dump.get_stream::<MinidumpThreadList<'_>>() {
        thread_list.print(
            output,
            unified_memory.as_ref(),
            system_info.as_ref(),
            misc_info.as_ref(),
            brief,
        )?;
    }
    if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
        module_list.print(output)?;
    }
    if let Ok(module_list) = dump.get_stream::<MinidumpUnloadedModuleList>() {
        module_list.print(output)?;
    }
    if let Some(memory_list) = unified_memory {
        memory_list.print(output, brief)?;
    }
    if let Some(memory_list) = memory_list {
        memory_list.print(output, brief)?;
    }
    if let Some(memory64_list) = memory64_list {
        memory64_list.print(output, brief)?;
    }
    if let Ok(memory_info_list) = dump.get_stream::<MinidumpMemoryInfoList<'_>>() {
        memory_info_list.print(output)?;
    }
    if let Ok(exception) = dump.get_stream::<MinidumpException>() {
        exception.print(output, system_info.as_ref(), misc_info.as_ref())?;
    }
    if let Ok(assertion) = dump.get_stream::<MinidumpAssertion>() {
        assertion.print(output)?;
    }
    if let Some(system_info) = system_info {
        system_info.print(output)?;
    }
    if let Some(misc_info) = misc_info {
        misc_info.print(output)?;
    }
    if let Ok(thread_names) = dump.get_stream::<MinidumpThreadNames>() {
        thread_names.print(output)?;
    }
    if let Ok(breakpad_info) = dump.get_stream::<MinidumpBreakpadInfo>() {
        breakpad_info.print(output)?;
    }
    match dump.get_stream::<MinidumpCrashpadInfo>() {
        Ok(crashpad_info) => crashpad_info.print(output)?,
        Err(Error::StreamNotFound) => (),
        Err(_) => write!(output, "MinidumpCrashpadInfo cannot print invalid data")?,
    }
    if let Ok(mac_info) = dump.get_stream::<MinidumpMacCrashInfo>() {
        mac_info.print(output)?;
    }
    if let Ok(mac_bootargs) = dump.get_stream::<MinidumpMacBootargs>() {
        mac_bootargs.print(output)?;
    }

    // Handle Linux streams that are just a dump of some system "file".
    macro_rules! streams {
        ( $( $x:ident ),* ) => {
            &[$( ( minidump_common::format::MINIDUMP_STREAM_TYPE::$x, stringify!($x) ) ),*]
        };
    }
    fn print_raw_stream<T: Write>(name: &str, contents: &[u8], out: &mut T) -> std::io::Result<()> {
        writeln!(out, "Stream {name}:")?;
        let s = contents
            .split(|&v| v == 0)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join("\\0\n");
        write!(out, "{s}\n\n")
    }

    for &(stream, name) in streams!(
        LinuxCmdLine,
        LinuxEnviron,
        LinuxLsbRelease,
        LinuxProcStatus,
        LinuxCpuInfo,
        LinuxMaps
    ) {
        if let Ok(contents) = dump.get_raw_stream(stream as u32) {
            print_raw_stream(name, contents, output)?;
        }
    }

    Ok(())
}

struct InterativeUi<'a> {
    all: MultiProgress,
    symbol_progress: ProgressBar,
    thread_progress: ProgressBar,
    frame_progress: ProgressBar,
    total_progress: ProgressBar,

    needed_stats: AtomicBool,
    symbol_stats: &'a MultiSymbolProvider,
    processor_stats: &'a PendingProcessorStats,
}

fn update_status(ui: &InterativeUi, finished: bool) {
    // Don't do anything if we're finishing up but we never started!
    if finished && !ui.needed_stats.load(Ordering::Relaxed) {
        return;
    }

    let symbol_stats = ui.symbol_stats.pending_stats();
    let (t_done, t_pending) = ui.processor_stats.get_thread_count();
    let frames_walked = ui.processor_stats.get_frame_count();

    let progress = if finished {
        100
    } else if t_pending == 0 {
        0
    } else {
        let estimated_frames_per_thread = 20;
        let estimate = 100 * frames_walked / (estimated_frames_per_thread * t_pending);
        estimate.min(80)
    };

    ui.symbol_progress
        .set_length(symbol_stats.symbols_requested);
    ui.symbol_progress
        .set_position(symbol_stats.symbols_processed);

    ui.thread_progress.set_length(t_pending);
    ui.thread_progress.set_position(t_done);

    ui.frame_progress.set_length(frames_walked);

    ui.total_progress.set_position(progress);

    // Make the UI visible for the first time
    if !ui.needed_stats.load(Ordering::Relaxed) {
        ui.thread_progress
            .set_style(ProgressStyle::with_template("{msg:>17} {pos}/{len}").unwrap());
        ui.symbol_progress
            .set_style(ProgressStyle::with_template("{msg:>17} {pos}/{len}").unwrap());
        ui.frame_progress
            .set_style(ProgressStyle::with_template("{msg:>17} {len}").unwrap());
        ui.total_progress
            .set_style(ProgressStyle::with_template("{msg:>17} {pos:>3}% {wide_bar} ").unwrap());

        ui.total_progress.set_length(100);
        ui.symbol_progress.set_message("symbols fetched");
        ui.thread_progress.set_message("threads processed");
        ui.frame_progress.set_message("frames walked");
        ui.total_progress.set_message("processing...");

        ui.all.add(ui.frame_progress.clone());
        ui.all.add(ui.symbol_progress.clone());
        ui.all.add(ui.thread_progress.clone());
        ui.all.add(ui.total_progress.clone());
        ui.needed_stats.store(true, Ordering::Relaxed);
    }

    if finished {
        ui.symbol_progress.finish();
        ui.thread_progress.finish();
        ui.frame_progress.finish();
        ui.total_progress.finish();
    }
}
