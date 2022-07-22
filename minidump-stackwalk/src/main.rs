// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::fs::File;
use std::io::Write;
use std::ops::Deref;
use std::panic;
use std::time::Duration;
use std::{boxed::Box, path::PathBuf};

use minidump::*;
use minidump_processor::{
    http_symbol_supplier, simple_symbol_supplier, MultiSymbolProvider, PendingStats,
    ProcessorOptions, SymbolProvider, Symbolizer,
};

use clap::{AppSettings, ArgGroup, CommandFactory, Parser};
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
///  2. To do produce a more *accurate* backtrace. This is primarily accomplished with
///     call frame information (CFI), but just knowing what parts of a module maps to actual
///     code is also useful!
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
    "help-markdown",
])))]
#[clap(override_usage("minidump-stackwalk [FLAGS] [OPTIONS] <minidump> [--] [symbols-path]..."))]
#[clap(setting(AppSettings::DeriveDisplayOrder))]
#[clap(verbatim_doc_comment)]
struct Cli {
    /// Emit a human-readable report (the default)
    ///
    /// The human-readable report does not have a specified format, and may not have as
    /// many details as the JSON format. It is intended for quickly inspecting
    /// a crash or debugging rust-minidump itself.
    ///
    /// Can be simplified with --brief
    #[clap(long)]
    human: bool,

    /// Emit a machine-readable JSON report
    ///
    /// The schema for this output is officially documented here:
    /// <https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md>
    ///
    /// Can be pretty-printed with --pretty
    #[clap(long)]
    json: bool,

    /// Combine --human and --json
    ///
    /// Because this creates two output streams, you must specify a path to write the --json
    /// output to. The --human output will be the 'primary' output and default to stdout, which
    /// can be configured with --output-file as normal.
    #[clap(long)]
    cyborg: Option<PathBuf>,

    /// Dump the 'raw' contents of the minidump
    ///
    /// This is an implementation of the functionality of the old minidump_dump tool.
    /// It minimally parses and interprets the minidump in an attempt to produce a
    /// fairly 'raw' dump of the minidump's contents. This is most useful for debugging
    /// minidump-stackwalk itself, or a misbehaving minidump generator.
    ///
    /// Can be simplified with --brief
    #[clap(long)]
    dump: bool,

    /// Print --help but formatted as markdown (used for generating docs)
    #[clap(long, hide = true)]
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
    #[clap(long, default_value = "stable-basic")]
    #[clap(possible_values = ["stable-basic", "stable-all", "unstable-all"])]
    #[clap(verbatim_doc_comment)]
    features: String,

    /// How verbose logging should be (log level)
    ///
    /// The unwinder has been heavily instrumented with `trace` logging, so if you want to
    /// debug why an unwind happened the way it did, --verbose=trace is very useful
    /// (all unwinder logging will be prefixed with `unwind:`).
    #[clap(long)]
    #[clap(default_value = "error")]
    #[clap(possible_values = ["off", "error", "warn", "info", "debug", "trace"])]
    verbose: LevelFilter,

    /// Where to write the output to (if unspecified, stdout is used)
    #[clap(long)]
    output_file: Option<PathBuf>,

    /// Where to write logs to (if unspecified, stderr is used)
    #[clap(long)]
    log_file: Option<PathBuf>,

    /// Prevent the output/logging from using ANSI coloring
    ///
    /// Output written to a file via --log-file, --output-file, or --cyborg
    /// is always --no-color, so this just forces stdout/stderr printing.
    #[clap(long)]
    no_color: bool,

    /// Pretty-print --json output
    #[clap(long)]
    pretty: bool,

    /// Provide a briefer --human or --dump report
    ///
    /// For human: Only provides the top-level summary and a backtrace of the crashing thread.
    ///
    /// For dump: Omits all memory hexdumps.
    #[clap(long)]
    brief: bool,

    /// **UNSTABLE** An input JSON file with the extra information.
    ///
    /// This is a gross hack for some legacy side-channel information that mozilla uses.
    /// It will hopefully be phased out and deprecated in favour of just using custom
    /// streams in the minidump itself.
    #[clap(long)]
    evil_json: Option<PathBuf>,

    /// **UNSTABLE** Heuristically recover function arguments
    ///
    /// This is an experimental feature, which currently only shows up in --human output.
    #[clap(long)]
    recover_function_args: bool,

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
    #[clap(long)]
    #[clap(verbatim_doc_comment)]
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
    #[clap(long)]
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
    #[clap(long)]
    symbols_tmp: Option<PathBuf>,

    /// The maximum amount of time (in seconds) a symbol file download is allowed to take
    ///
    /// This is necessary to enforce forward progress on misbehaving http responses.
    #[clap(long, default_value_t = 1000)]
    symbols_download_timeout_secs: u64,

    /// Path to the minidump file to analyze
    minidump: PathBuf,

    /// Path to a symbol file.
    ///
    /// If multiple symbols-path values are provided, all symbol files will be merged
    /// into minidump-stackwalk's symbol database.
    #[clap(long)]
    symbols_path: Vec<PathBuf>,

    /// Path to a symbol file. (Passed positionally)
    ///
    /// If multiple symbols-path-legacy values are provided, all symbol files will be merged
    /// into minidump-stackwalk's symbol database.
    symbols_path_legacy: Vec<PathBuf>,
}

#[cfg_attr(test, allow(dead_code))]
#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Init the logger (and make trace logging less noisy)
    if let Some(log_path) = &cli.log_file {
        let log_file = File::create(log_path).unwrap();
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
        return;
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
    options.frame_stat_reporter = Some(Default::default());
    options.thread_stat_reporter = Some(Default::default());
    let frame_stat_reporter = options.frame_stat_reporter.clone().unwrap();
    let thread_stat_reporter = options.thread_stat_reporter.clone().unwrap();

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

    // Ok now let's do the thing!!!!

    match Minidump::read_path(cli.minidump) {
        Ok(dump) => {
            let mut stdout;
            let mut output_f;
            let cyborg_output_f = cli.cyborg.map(|path| File::create(path).unwrap());

            let mut output: &mut dyn Write = if let Some(output_path) = cli.output_file {
                output_f = File::create(output_path).unwrap();
                &mut output_f
            } else {
                stdout = std::io::stdout();
                &mut stdout
            };

            // minidump_dump mode
            if raw_dump {
                return print_minidump_dump(&dump, &mut output, cli.brief).unwrap();
            }

            let mut provider = MultiSymbolProvider::new();

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

            fn update_status(
                symbol_stats: &PendingStats,
                t_done: u64,
                t_pending: u64,
                frames_walked: u64,
            ) {
                // TODO: proper progress bars
                eprintln!("processing threads: {}/{}", t_done, t_pending);
                eprintln!(
                    "fetching symbols: {}/{}",
                    symbol_stats.symbols_processed, symbol_stats.symbols_requested
                );
                eprintln!("frames walked: {}", frames_walked)
            }

            let needed_stats = std::sync::atomic::AtomicBool::new(false);
            let update_state = || async {
                // Do an initial sleep to avoid reporting things for fast ops
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                loop {
                    if !json {
                        needed_stats.store(true, std::sync::atomic::Ordering::Relaxed);
                        let symbol_stats = provider.pending_stats();
                        let (t_done, t_pending) = *thread_stat_reporter.lock().unwrap();
                        let frames_walked = *frame_stat_reporter.lock().unwrap();
                        // TODO: proper progress bars
                        update_status(&symbol_stats, t_done, t_pending, frames_walked);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            };

            let result = tokio::select! {
                result = minidump_processor::process_minidump_with_options(&dump, &provider, options) => result,
                _ = update_state() => unreachable!(),
            };

            // Do one final sync stat update
            if needed_stats.load(std::sync::atomic::Ordering::Relaxed) {
                let symbol_stats = provider.pending_stats();
                let (t_done, t_pending) = *thread_stat_reporter.lock().unwrap();
                let frames_walked = *frame_stat_reporter.lock().unwrap();

                update_status(&symbol_stats, t_done, t_pending, frames_walked);
            }

            match result {
                Ok(state) => {
                    // Print the human output if requested (always uses the "real" output).
                    if human {
                        if cli.brief {
                            state.print_brief(&mut output).unwrap();
                        } else {
                            state.print(&mut output).unwrap();
                        }
                    }

                    // Print the json output if requested (using "cyborg" output if available).
                    if json {
                        if let Some(mut cyborg_output_f) = cyborg_output_f {
                            state.print_json(&mut cyborg_output_f, cli.pretty).unwrap();
                        } else {
                            state.print_json(&mut output, cli.pretty).unwrap();
                        }
                    }
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

fn print_help_markdown(out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    let app_name = "minidump-stackwalk";
    let pretty_app_name = "minidump-stackwalk";
    // Make a new App to get the help message this time.

    writeln!(out, "# {pretty_app_name} CLI manual")?;
    writeln!(out)?;
    writeln!(
        out,
        "> This manual can be regenerated with `{pretty_app_name} --help-markdown`"
    )?;
    writeln!(out)?;

    let mut cli = Cli::command();
    let full_command = &mut cli;
    full_command.build();
    let mut todo = vec![full_command];
    let mut is_full_command = true;

    while let Some(command) = todo.pop() {
        let mut help_buf = Vec::new();
        command.write_long_help(&mut help_buf).unwrap();
        let help = String::from_utf8(help_buf).unwrap();

        // First line is --version
        let mut lines = help.lines();
        let version_line = lines.next().unwrap();
        let subcommand_name = command.get_name();
        let pretty_subcommand_name;

        if is_full_command {
            pretty_subcommand_name = String::new();
            writeln!(out, "Version: `{version_line}`")?;
            writeln!(out)?;
        } else {
            pretty_subcommand_name = format!("{pretty_app_name} {subcommand_name} ");
            // Give subcommands some breathing room
            writeln!(out, "<br><br><br>")?;
            writeln!(out, "## {pretty_subcommand_name}")?;
        }

        let mut in_subcommands_listing = false;
        let mut in_usage = false;
        for line in lines {
            // Use a trailing colon to indicate a heading
            if let Some(heading) = line.strip_suffix(':') {
                if !line.starts_with(' ') {
                    // SCREAMING headers are Main headings
                    if heading.to_ascii_uppercase() == heading {
                        in_subcommands_listing = heading == "SUBCOMMANDS";
                        in_usage = heading == "USAGE";

                        writeln!(out, "### {pretty_subcommand_name}{heading}")?;
                    } else {
                        writeln!(out, "### {heading}")?;
                    }
                    continue;
                }
            }

            if in_subcommands_listing && !line.starts_with("     ") {
                // subcommand names are list items
                let own_subcommand_name = line.trim();
                write!(
                    out,
                    "* [{own_subcommand_name}](#{app_name}-{own_subcommand_name}): "
                )?;
                continue;
            }
            // The rest is indented, get rid of that
            let line = line.trim();

            // Usage strings get wrapped in full code blocks
            if in_usage && line.starts_with(pretty_app_name) {
                writeln!(out, "```")?;
                writeln!(out, "{line}")?;
                writeln!(out, "```")?;
                continue;
            }

            // argument names are subheadings
            if line.starts_with('-') || line.starts_with('<') {
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

        todo.extend(command.get_subcommands_mut());
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
    let memory_list = dump.get_stream::<MinidumpMemoryList<'_>>().ok();
    let memory64_list = dump.get_stream::<MinidumpMemory64List<'_>>().ok();
    let misc_info = dump.get_stream::<MinidumpMiscInfo>().ok();

    if let Ok(thread_list) = dump.get_stream::<MinidumpThreadList<'_>>() {
        thread_list.print(
            output,
            memory_list.as_ref(),
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
    if let Ok(breakpad_info) = dump.get_stream::<MinidumpBreakpadInfo>() {
        breakpad_info.print(output)?;
    }
    if let Ok(thread_names) = dump.get_stream::<MinidumpThreadNames>() {
        thread_names.print(output)?;
    }
    match dump.get_stream::<MinidumpCrashpadInfo>() {
        Ok(crashpad_info) => crashpad_info.print(output)?,
        Err(Error::StreamNotFound) => (),
        Err(_) => write!(output, "MinidumpCrashpadInfo cannot print invalid data")?,
    }

    // Handle Linux streams that are just a dump of some system "file".
    macro_rules! streams {
        ( $( $x:ident ),* ) => {
            &[$( ( minidump_common::format::MINIDUMP_STREAM_TYPE::$x, stringify!($x) ) ),*]
        };
    }
    fn print_raw_stream<T: Write>(name: &str, contents: &[u8], out: &mut T) -> std::io::Result<()> {
        writeln!(out, "Stream {}:", name)?;
        let s = contents
            .split(|&v| v == 0)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join("\\0\n");
        write!(out, "{}\n\n", s)
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
