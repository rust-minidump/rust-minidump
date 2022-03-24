// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::boxed::Box;
use std::env;
use std::fs::File;
use std::io::Write;
use std::ops::Deref;
use std::panic;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use minidump::*;
use minidump_processor::{
    http_symbol_supplier, simple_symbol_supplier, MultiSymbolProvider, ProcessorOptions, Symbolizer,
};

use clap::{AppSettings, Arg, ArgGroup, Command};
use log::error;
use simplelog::{
    ColorChoice, ConfigBuilder, Level, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

fn make_app() -> Command<'static> {
    Command::new("minidump-stackwalk")
        .version(clap::crate_version!())
        .about("Analyzes minidumps and produces a report (either human-readable or JSON).")
        .next_line_help(true)
        .setting(AppSettings::DeriveDisplayOrder)
        .override_usage("minidump-stackwalk [FLAGS] [OPTIONS] <minidump> [--] [symbols-path]...")
        .arg(Arg::new("json").long("json").long_help(
            "Emit a machine-readable JSON report.

The schema for this output is officially documented here:
https://github.com/rust-minidump/rust-minidump/blob/master/minidump-processor/json-schema.md",
        ))
        .arg(Arg::new("human").long("human").long_help(
            "Emit a human-readable report (the default).

The human-readable report does not have a specified format, and may not have as \
many details as the JSON format. It is intended for quickly inspecting \
a crash or debugging rust-minidump itself.",
        ))
        .arg(
            Arg::new("cyborg")
                .long("cyborg")
                .takes_value(true)
                .allow_invalid_utf8(true)
                .long_help(
                    "Combine --human and --json

Because this creates two output streams, you must specify a path to write the --json \
output to. The --human output will be the 'primary' output and default to stdout, which \
can be configured with --output-file as normal.",
                ),
        )
        .arg(Arg::new("dump").long("dump").long_help(
            "Dump the 'raw' contents of the minidump.

This is an implementation of the functionality of the old minidump_dump tool. \
It minimally parses and interprets the minidump in an attempt to produce a \
fairly 'raw' dump of the minidump's contents. This is most useful for debugging \
minidump-stackwalk itself, or a misbehaving minidump generator.",
        ))
        .arg(
            Arg::new("help-markdown")
                .long("help-markdown")
                .long_help("Print --help but formatted as markdown (used for generating docs)")
                .hide(true),
        )
        .group(ArgGroup::new("output-format").args(&[
            "json",
            "human",
            "cyborg",
            "dump",
            "help-markdown",
        ]))
        .arg(
            Arg::new("features")
                .long("features")
                .possible_values(&["stable-basic", "stable-all", "unstable-all"])
                .default_value("stable-basic")
                .takes_value(true)
                .long_help(
                    "Specify at a high-level how much analysis to perform.

This flag provides a way to more blindly opt into Extra Analysis without having to know about \
the specific features of minidump-stackwalk. This is equivalent to ProcessorOptions in \
minidump-processor. The current supported values are:

* stable-basic (default): give me solid detailed analysis that most people would want
* stable-all: turn on extra detailed analysis.
* unstable-all: turn on the weird and experimental stuff.

stable-all enables: nothing (currently identical to stable-basic)

unstable-all enables: `--recover-function-args`

minidump-stackwalk wants to be a reliable and stable tool, but we also want to be able to \
introduce new features which may be experimental or expensive. To balance these two concerns, \
new features will usually be disabled by default and given a specific flag, but still more \
easily 'discovered' by anyone who uses this flag.

Anyone using minidump-stackwalk who is *really* worried about the output being stable \
should probably not use this flag in production, but its use is recommended for casual
human usage or for checking \"what's new\".

Features under unstable-all may be deprecated and become noops. Features which require \
additional input (such as `--evil-json`) cannot be affected by this, and must still be \
manually 'discovered'.",
                ),
        )
        .arg(
            Arg::new("output-file")
                .long("output-file")
                .takes_value(true)
                .allow_invalid_utf8(true)
                .help("Where to write the output to (if unspecified, stdout is used)"),
        )
        .arg(
            Arg::new("log-file")
                .long("log-file")
                .takes_value(true)
                .allow_invalid_utf8(true)
                .help("Where to write logs to (if unspecified, stderr is used)"),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .possible_values(&["off", "error", "warn", "info", "debug", "trace"])
                .default_value("error")
                .takes_value(true)
                .long_help(
                    "Set the logging level.

The unwinder has been heavily instrumented with `trace` logging, so if you want to debug why \
an unwind happened the way it did, --verbose=trace is very useful (all unwinder logging will \
be prefixed with `unwind:`).",
                ),
        )
        .arg(
            Arg::new("pretty")
                .long("pretty")
                .help("Pretty-print --json output."),
        )
        .arg(Arg::new("brief").long("brief").help(
            "Provide a briefer --human report.

Only provides the top-level summary and a backtrace of the crashing thread.",
        ))
        .arg(
            Arg::new("evil-json")
                .long("evil-json")
                .takes_value(true)
                .allow_invalid_utf8(true)
                .long_help(
                    "**[UNSTABLE]** An input JSON file with the extra information.

This is a gross hack for some legacy side-channel information that mozilla uses. It will \
hopefully be phased out and deprecated in favour of just using custom streams in the \
minidump itself.",
                ),
        )
        .arg(
            Arg::new("recover-function-args")
                .long("recover-function-args")
                .help(
                    "**[UNSTABLE]** Heuristically recover function arguments

This is an experimental feature, which currently only shows up in --human output.",
                ),
        )
        .arg(
            Arg::new("symbols-url")
                .long("symbols-url")
                .multiple_occurrences(true)
                .takes_value(true)
                .long_help(
                    "base URL from which URLs to symbol files can be constructed.

If multiple symbols-url values are provided, they will each be tried in order until \
one resolves.

The server the base URL points to is expected to conform to the Tecken \
symbol server protocol. For more details, see the Tecken docs:

https://tecken.readthedocs.io/en/latest/

Example symbols-url value: https://symbols.mozilla.org/",
                ),
        )
        .arg(
            Arg::new("symbols-cache")
                .long("symbols-cache")
                .takes_value(true)
                .allow_invalid_utf8(true)
                .long_help(
                    "A directory in which downloaded symbols can be stored.
                    
Symbol files can be very large, so we recommend placing cached files in your \
system's temp directory so that it can garbage collect unused ones for you. \
To this end, the default value for this flag is a `rust-minidump-cache` \
subdirectory of `std::env::temp_dir()` (usually /tmp/rust-minidump-cache on linux).

symbols-cache must be on the same filesystem as symbols-tmp (if that doesn't mean anything to \
you, don't worry about it, you're probably not doing something that will run afoul of it).",
                ),
        )
        .arg(
            Arg::new("symbols-tmp")
                .long("symbols-tmp")
                .takes_value(true)
                .allow_invalid_utf8(true)
                .long_help(
                    "A directory to use as temp space for downloading symbols.

A temp dir is necessary to allow for multiple rust-minidump instances to share a cache without \
race conditions. Files to be added to the cache will be constructed in this location before \
being atomically moved to the cache.

If no path is specified, `std::env::temp_dir()` will be used to improve portability. \
See the rust documentation for how to set that value if you wish to use something other than \
your system's default temp directory.

symbols-tmp must be on the same filesystem as symbols-cache (if that doesn't mean anything to \
you, don't worry about it, you're probably not doing something that will run afoul of it).",
                ),
        )
        .arg(
            Arg::new("symbol-download-timeout-secs")
                .long("symbol-download-timeout-secs")
                .default_value("1000")
                .takes_value(true)
                .help(
                    "The maximum amount of time (in seconds) a symbol file download is allowed \
to take.

This is necessary to enforce forward progress on misbehaving http responses.",
                ),
        )
        .arg(
            Arg::new("minidump")
                .required_unless_present("help-markdown")
                .takes_value(true)
                .allow_invalid_utf8(true)
                .help("Path to the minidump file to analyze."),
        )
        .arg(
            Arg::new("symbols-path")
                .long("symbols-path")
                .multiple_occurrences(true)
                .takes_value(true)
                .allow_invalid_utf8(true)
                .long_help(
                    "Path to a symbol file.

If multiple symbols-path values are provided, all symbol files will be merged \
into minidump-stackwalk's symbol database.",
                ),
        )
        .arg(
            Arg::new("symbols-path-legacy")
                .multiple_values(true)
                .takes_value(true)
                .allow_invalid_utf8(true)
                .long_help(
                    "Path to a symbol file. (Passed positionally)

If multiple symbols-path-legacy values are provided, all symbol files will be merged \
into minidump-stackwalk's symbol database.",
                ),
        )
        .after_help(
            "
NOTES:

Purpose of Symbols:

  Symbols are used for two purposes:

  1. To fill in more information about each frame of the backtraces. (function names, lines, etc.)

  2. To do produce a more *accurate* backtrace. This is primarily accomplished with \
call frame information (CFI), but just knowing what parts of a module maps to actual \
code is also useful!

Supported Symbol Formats:

  Currently only breakpad text symbol files are supported, although we hope to eventually \
support native formats like PDB and DWARF as well.

Breakpad Symbol Files:

  Breakpad symbol files are basically a simplified version of the information found in \
native debuginfo formats. We recommend using a version of dump_syms to generate them.

  See:
    * https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md
    * mozilla's dump_syms (co-developed with this program): https://github.com/mozilla/dump_syms

",
        )
}

#[cfg_attr(test, allow(dead_code))]
#[tokio::main]
async fn main() {
    let matches = make_app().get_matches();

    // This is a little hack to generate a markdown version of the --help message,
    // to be used by rust-minidump devs to regenerate docs. Not officially part
    // of our public API.
    if matches.is_present("help-markdown") {
        print_help_markdown();
        return;
    }

    let output_file = matches
        .value_of_os("output-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let log_file = matches
        .value_of_os("log-file")
        .map(|os_str| Path::new(os_str).to_owned());

    let verbosity = match matches.value_of("verbose").unwrap() {
        "off" => LevelFilter::Off,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Error,
    };

    // Init the logger (and make trace logging less noisy)
    if let Some(log_path) = log_file {
        let log_file = File::create(log_path).unwrap();
        let _ = WriteLogger::init(
            verbosity,
            ConfigBuilder::new()
                .set_location_level(LevelFilter::Off)
                .set_time_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .build(),
            log_file,
        )
        .unwrap();
    } else {
        let _ = TermLogger::init(
            verbosity,
            ConfigBuilder::new()
                .set_location_level(LevelFilter::Off)
                .set_time_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .set_level_color(Level::Trace, None)
                .build(),
            TerminalMode::Stderr,
            ColorChoice::Auto,
        );
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

    // Pick the default options
    let mut options = match matches.value_of("features").unwrap() {
        "stable-basic" => ProcessorOptions::stable_basic(),
        "stable-all" => ProcessorOptions::stable_all(),
        "unstable-all" => ProcessorOptions::unstable_all(),
        _ => unimplemented!("unknown --features value"),
    };

    // Now overload the defaults
    options.evil_json = matches.value_of_os("evil-json").map(Path::new);
    if matches.is_present("recover-function-args") {
        options.recover_function_args = true;
    }

    let temp_dir = std::env::temp_dir();

    let mut symbols_paths = matches
        .values_of_os("symbols-path")
        .map(|v| {
            v.map(|os_str| Path::new(os_str).to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::new);
    let symbols_paths_legacy = matches
        .values_of_os("symbols-path-legacy")
        .map(|v| {
            v.map(|os_str| Path::new(os_str).to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::new);
    symbols_paths.extend(symbols_paths_legacy);

    // Default to env::temp_dir()/rust-minidump-cache
    let symbols_cache = matches
        .value_of_os("symbols-cache")
        .map(|os_str| Path::new(os_str).to_owned())
        .unwrap_or_else(|| temp_dir.join("rust-minidump-cache"));

    // Default to env::temp_dir()
    let symbols_tmp = matches
        .value_of_os("symbols-tmp")
        .map(|os_str| Path::new(os_str).to_owned())
        .unwrap_or(temp_dir);

    let symbols_urls = matches
        .values_of("symbols-url")
        .map(|v| v.map(String::from).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);

    let timeout = matches
        .value_of("symbol-download-timeout-secs")
        .and_then(|x| u64::from_str(x).ok())
        .map(Duration::from_secs)
        .unwrap();

    let minidump_path = matches.value_of_os("minidump").map(Path::new).unwrap();

    // Determine the kind of output we're producing -- dump, json, human, or cyborg (both).
    // Although we have a --human argument it's mostly just there to make the documentation
    // more clear. human output is enabled by default, and --json disables it.
    // Mutual exclusion is enforced by an ArgGroup, but it doesn't understand that "human"
    // is the implicit default, so we have to do some munging here.
    let raw_dump = matches.is_present("dump");
    let mut json = matches.is_present("json");
    // Human is just enabled if nothing else is
    let mut human = !json && !raw_dump;
    // Cyborg is just "desugarred" to --json --human
    let cyborg = matches.value_of_os("cyborg").map(Path::new);

    if cyborg.is_some() {
        human = true;
        json = true;
    }

    // Now check if arguments that tweak the output are valid. We can't use
    // Arg::requires because clap doesn't understand --json being implicitly enabled.
    let pretty = matches.is_present("pretty");
    let brief = matches.is_present("brief");

    if pretty && !json {
        error!("Humans must be hideous! (The --pretty and --human flags cannot both be set)");
        std::process::exit(1);
    }

    if brief && !human {
        error!("Robots cannot be brief! (The --brief flag is only valid for --human output (or --cyborg)");
        std::process::exit(1);
    }

    // Ok now let's do the thing!!!!

    match Minidump::read_path(minidump_path) {
        Ok(dump) => {
            let mut stdout;
            let mut output_f;
            let cyborg_output_f = cyborg.map(|path| File::create(path).unwrap());

            let mut output: &mut dyn Write = if let Some(output_path) = output_file {
                output_f = File::create(output_path).unwrap();
                &mut output_f
            } else {
                stdout = std::io::stdout();
                &mut stdout
            };

            // minidump_dump mode
            if raw_dump {
                return print_minidump_dump(&dump, &mut output).unwrap();
            }

            let mut provider = MultiSymbolProvider::new();

            if !symbols_urls.is_empty() {
                provider.add(Box::new(Symbolizer::new(http_symbol_supplier(
                    symbols_paths,
                    symbols_urls,
                    symbols_cache,
                    symbols_tmp,
                    timeout,
                ))));
            } else if !symbols_paths.is_empty() {
                provider.add(Box::new(Symbolizer::new(simple_symbol_supplier(
                    symbols_paths,
                ))));
            }

            match minidump_processor::process_minidump_with_options(&dump, &provider, options).await
            {
                Ok(state) => {
                    // Print the human output if requested (always uses the "real" output).
                    if human {
                        if brief {
                            state.print_brief(&mut output).unwrap();
                        } else {
                            state.print(&mut output).unwrap();
                        }
                    }

                    // Print the json output if requested (using "cyborg" output if available).
                    if json {
                        if let Some(mut cyborg_output_f) = cyborg_output_f {
                            state.print_json(&mut cyborg_output_f, pretty).unwrap();
                        } else {
                            state.print_json(&mut output, pretty).unwrap();
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

fn print_help_markdown() {
    let mut help_buf = Vec::new();

    // Make a new App to get the help message this time.
    make_app().write_long_help(&mut help_buf).unwrap();
    let help = String::from_utf8(help_buf).unwrap();

    println!("# minidump-stackwalk CLI manual");
    println!();
    println!("> This manual can be regenerated with `minidump-stackwalk --help-markdown please`");
    println!();

    // First line is --version
    let mut lines = help.lines();
    println!("Version: `{}`", lines.next().unwrap());
    println!();

    for line in lines {
        // Use a trailing colon to indicate a heading
        if let Some(heading) = line.strip_suffix(':') {
            if !line.starts_with(' ') {
                // SCREAMING headers are Main headings
                if heading.to_ascii_uppercase() == heading {
                    println!("# {}", heading);
                } else {
                    println!("## {}", heading);
                }
                continue;
            }
        }

        // Usage strings get wrapped in full code blocks
        if line.starts_with("minidump-stackwalk ") {
            println!("```");
            println!("{}", line);
            println!("```");
            continue;
        }

        // The rest is indented, get rid of that
        let line = line.trim();

        // argument names are subheadings
        if line.starts_with('-') || line.starts_with('<') {
            println!("### `{}`", line);
            continue;
        }

        // escape default/value strings
        if line.starts_with('[') {
            println!("\\{}", line);
            continue;
        }

        // Normal paragraph text
        println!("{}", line);
    }
}

fn print_minidump_dump<'a, T, W>(dump: &Minidump<'a, T>, output: &mut W) -> std::io::Result<()>
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
        )?;
    }
    if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
        module_list.print(output)?;
    }
    if let Ok(module_list) = dump.get_stream::<MinidumpUnloadedModuleList>() {
        module_list.print(output)?;
    }
    if let Some(memory_list) = memory_list {
        memory_list.print(output)?;
    }
    if let Some(memory64_list) = memory64_list {
        memory64_list.print(output)?;
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
