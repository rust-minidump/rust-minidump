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

use clap::{crate_version, App, AppSettings, Arg, ArgGroup};
use log::error;
use simplelog::{
    ColorChoice, ConfigBuilder, Level, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};

#[cfg_attr(test, allow(dead_code))]
fn main() {
    let matches = App::new("minidump-stackwalk")
        .version(crate_version!())
        .about("Analyzes minidumps and produces a report (either human-readable or JSON).")
        .setting(AppSettings::NextLineHelp)
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::DeriveDisplayOrder)
        .usage("minidump-stackwalk [FLAGS] [OPTIONS] <minidump> [--] [symbols-path]...")
        .arg(
            Arg::with_name("json")
                .long("json")
                .long_help("Emit a machine-readable JSON report (the default).

Official schema TBD, but the output *is* stabilized. That said, sometimes values can't be computed \
(e.g. because the minidump doesn't contain that information), so nearly every value \
*can* be null. And of course, we reserve the right to introduce new fields/values \
for new features.

In general we try to emit an explicit `null` for a field that *can* appear in the JSON but \
doesn't, so every JSON report is *kind of* reporting the current schema (but of course, \
missing the possible values and their meanings).\n\n\n")
        )
        .arg(
            Arg::with_name("human")
                .long("human")
                .long_help("Emit a human-readable report.

The human-readable report does not have a specified format, and may not have as \
many details as the default JSON format. It is intended for quickly inspecting \
a crash or debugging rust-minidump itself.\n\n\n")
        )
        .arg(
            Arg::with_name("cyborg")
                .long("cyborg")
                .takes_value(true)
                .long_help("Combine --human and --json

Because this creates two output streams, you must specify a path to write the --json
output to. The --human output will be the 'primary' output and default to stdout, which
can be configured with --output-file as normal.\n\n\n")
        )
        .group(ArgGroup::with_name("output-format")
            .args(&["json", "human", "cyborg"])
        )
        .arg(
            Arg::with_name("output-file")
                .long("output-file")
                .takes_value(true)
                .help("Where to write the output to (if unspecified, stdout is used)")
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .takes_value(true)
                .help("Where to write logs to (if unspecified, stderr is used)")
        )
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .possible_values(&["off", "error", "warn", "info", "debug", "trace"])
                .default_value("error")
                .takes_value(true)
                .long_help("Set the logging level.

The unwinder has been heavily instrumented with `trace` logging, so if you want to debug why \
an unwind happened the way it did, --verbose=trace is very useful (all unwinder logging will \
be prefixed with `unwind:`).\n\n\n")
        )
        .arg(
            Arg::with_name("pretty")
                .long("pretty")
                .help("Pretty-print --json output.")
        )
        .arg(
            Arg::with_name("brief")
                .long("brief")
                .help("Provide a briefer --human report.

Only provides the top-level summary and a backtrace of the crashing thread.")
        )
        .arg(
            Arg::with_name("raw-json")
                .long("raw-json")
                .takes_value(true)
                .long_help("An input JSON file with the extra information.

This is a gross hack for some legacy side-channel information that mozilla uses. It will \
hopefully be phased out and deprecated in favour of just using custom streams in the \
minidump itself.\n\n\n")
        )
        .arg(
            Arg::with_name("symbols-url")
                .long("symbols-url")
                .multiple(true)
                .takes_value(true)
                .long_help("base URL from which URLs to symbol files can be constructed.

If multiple symbols-url values are provided, they will each be tried in order until \
one resolves.

The server the base URL points to is expected to conform to the Tecken \
symbol server protocol. For more details, see the Tecken docs:

https://tecken.readthedocs.io/en/latest/

Example symbols-url value: https://symbols.mozilla.org/\n\n\n")
        )
        .arg(
            Arg::with_name("symbols-cache")
                .long("symbols-cache")
                .takes_value(true)
                .long_help("A directory in which downloaded symbols can be stored.
                    
Symbol files can be very large, so we recommend placing cached files in your \
system's temp directory so that it can garbage collect unused ones for you. \
To this end, the default value for this flag is a `rust-minidump-cache` \
subdirectory of `std::env::temp_dir()` (usually /tmp/rust-minidump-cache on linux).

symbols-cache must be on the same filesystem as symbols-tmp (if that doesn't mean anything to \
you, don't worry about it, you're probably not doing something that will run afoul of it).\n\n\n")
        )
        .arg(
            Arg::with_name("symbols-tmp")
                .long("symbols-tmp")
                .takes_value(true)
                .long_help("A directory to use as temp space for downloading symbols.

A temp dir is necessary to allow for multiple rust-minidump instances to share a cache without \
race conditions. Files to be added to the cache will be constructed in this location before \
being atomically moved to the cache.

If no path is specified, `std::env::temp_dir()` will be used to improve portability. \
See the rust documentation for how to set that value if you wish to use something other than \
your system's default temp directory.

symbols-tmp must be on the same filesystem as symbols-cache (if that doesn't mean anything to \
you, don't worry about it, you're probably not doing something that will run afoul of it).\n\n\n")
        )
        .arg(
            Arg::with_name("symbol-download-timeout-secs")
                .long("symbol-download-timeout-secs")
                .default_value("1000")
                .takes_value(true)
                .help("The maximum amount of time (in seconds) a symbol file download is allowed \
to take.

This is necessary to enforce forward progress on misbehaving http responses.\n\n")
        )
        .arg(
            Arg::with_name("minidump")
                .required(true)
                .takes_value(true)
                .help("Path to the minidump file to analyze.")
        )
        .arg(
            Arg::with_name("symbols-path")
                .multiple(true)
                .takes_value(true)
                .long_help("Path to a symbol file.

If multiple symbols-path values are provided, all symbol files will be merged \
into minidump-stackwalk's symbol database.\n\n\n")   
        )
        .after_help("

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
    * symbol file docs: https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md
    * mozilla's dump_syms (co-developed with this program): https://github.com/mozilla/dump_syms

")
        .get_matches();

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
        error!("A panic occurred at {}:{}: {}", filename, line, cause);
    }));

    let mut options = ProcessorOptions::default();

    options.evil_json = matches.value_of_os("raw-json").map(Path::new);

    let temp_dir = std::env::temp_dir();

    let symbols_paths = matches
        .values_of_os("symbols-path")
        .map(|v| {
            v.map(|os_str| Path::new(os_str).to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::new);

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

    // Determine the kind of output we're producing -- json, human, or cyborg (both).
    // Although we have a --json argument it's mostly just there to make the documentation
    // more clear. json output is enabled by default, and --human disables it.
    // Mutual exclusion is enforced by an ArgGroup.
    let mut human = matches.is_present("human");
    let mut json = !human;
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

            match minidump_processor::process_minidump_with_options(&dump, &provider, options) {
                Ok(state) => {
                    let mut stdout;
                    let mut output_f;

                    let mut output: &mut dyn Write = if let Some(output_path) = output_file {
                        output_f = File::create(output_path).unwrap();
                        &mut output_f
                    } else {
                        stdout = std::io::stdout();
                        &mut stdout
                    };

                    if human {
                        state.print(&mut output).unwrap();
                    } else {
                        state.print_json(&mut output, pretty).unwrap();
                    }
                }
                Err(err) => {
                    error!("Error processing dump: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Err(err) => {
            error!("Error reading dump: {}", err);
            std::process::exit(1);
        }
    }
}
