// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::boxed::Box;
use std::env;
use std::ops::Deref;
use std::panic;
use std::path::Path;
use std::path::PathBuf;

use breakpad_symbols::{HttpSymbolSupplier, SimpleSymbolSupplier, Symbolizer};
use minidump::*;
use minidump_processor::{DwarfSymbolizer, MultiSymbolProvider};

use clap::{crate_authors, crate_version, App, Arg};
use log::error;
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};

fn print_minidump_process(
    path: &Path,
    symbol_paths: Vec<PathBuf>,
    symbol_urls: Vec<String>,
    symbols_cache: Option<PathBuf>,
    human: bool,
    pretty: bool,
) {
    if let Ok(dump) = Minidump::read_path(path) {
        let mut provider = MultiSymbolProvider::new();

        if let Some(symbols_cache) = symbols_cache {
            provider.add(Box::new(Symbolizer::new(HttpSymbolSupplier::new(
                symbol_urls,
                symbols_cache,
                symbol_paths,
            ))));
        } else if !symbol_paths.is_empty() {
            provider.add(Box::new(Symbolizer::new(SimpleSymbolSupplier::new(
                symbol_paths,
            ))));
        }
        provider.add(Box::new(DwarfSymbolizer::new()));

        match minidump_processor::process_minidump(&dump, &provider) {
            Ok(state) => {
                let mut stdout = std::io::stdout();
                if human {
                    state.print(&mut stdout).unwrap();
                } else {
                    state.print_json(&mut stdout, pretty).unwrap();
                }
            }
            Err(err) => {
                eprintln!("Error processing dump: {:?}", err);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Error reading dump");
        std::process::exit(1);
    }
}

#[cfg_attr(test, allow(dead_code))]
fn main() {
    let matches = App::new("minidump_stackwalk")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about("Analyzes minidumps and produces a machine-readable JSON report")
        .arg(
            Arg::with_name("human")
                .help("Emit a human-readable report instead")
                .long("human")
        )
        .arg(
            Arg::with_name("pretty")
                .help("Pretty-print JSON output.")
                .long("pretty")
        )
        .arg(
            Arg::with_name("pipe-dump")
                .help("Produce pipe-delimited output in addition to JSON output")
                .long("pipe-dump")
        )
        .arg(
            Arg::with_name("verbose")
                .help("Set the level of verbosity (off, error (default), warn, info, debug, trace)")
                .long("verbose")
                .default_value("error")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("raw-json")
                .help("An input file with the raw annotations as JSON")
                .long("raw-json")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("symbols-url")
                .help("A base URL from which URLs to symbol files can be constructed")
                .multiple(true)
                .long("symbols-url")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("symbols-cache")
                .help("A directory in which downloaded symbols can be stored")
                .long("symbols-cache")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("symbols-tmp")
                .help("A directory to use as temp space for downloading symbols. Must be on the same filesystem as symbols-cache.")
                .long("symbols-tmp")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("minidump")
                .help("Path to minidump file")
                .required(true)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("symbols-path")
                .help("Path to symbol file")
                .multiple(true)
                .takes_value(true)
        )
        .get_matches();

    let verbosity = match matches.value_of("verbose").unwrap() {
        "off" => LevelFilter::Off,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Error,
    };

    // Init the logger
    let _ = TermLogger::init(verbosity, Config::default(), TerminalMode::Stderr);

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

    // All options the original minidump-stackwalk has, stubbed out for when we need them:
    let _pipe = matches.is_present("pipe-dump");
    let _json_path = matches.value_of_os("raw-json").map(Path::new);
    let symbols_cache = matches
        .value_of_os("symbols-cache")
        .map(|os_str| Path::new(os_str).to_owned());
    let _symbols_tmp = matches.value_of_os("symbols-tmp").map(Path::new);
    let symbols_urls = matches
        .values_of("symbols-url")
        .map(|v| v.map(String::from).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);

    let pretty = matches.is_present("pretty");
    let human = matches.is_present("human");

    let minidump_path = matches.value_of_os("minidump").map(Path::new).unwrap();
    let symbols_paths = matches
        .values_of_os("symbols-path")
        .map(|v| {
            v.map(|os_str| Path::new(os_str).to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(Vec::new);

    if symbols_urls.is_empty() != symbols_cache.is_none() {
        eprintln!("You must specify both --symbols-url and --symbols-cache when using one of these options");
        std::process::exit(1);
    }

    print_minidump_process(
        minidump_path,
        symbols_paths,
        symbols_urls,
        symbols_cache,
        human,
        pretty,
    );
}
