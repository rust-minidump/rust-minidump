//! Contains HTTP symbol retrieval specific functionality

use crate::*;
use reqwest::{Client, Url};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;
use tracing::{debug, trace, warn};

/// A key that uniquely identifies a File associated with a module
type FileKey = (ModuleKey, FileKind);

/// Various options for [`HttpSymbolSupplier`]
///
/// # Recipes
///
/// ## Mozilla HTTP Symbol Files
///
/// This is the "standard" configuration for someone fully bought into the
/// breakpad/rust-minidump ecosystem. Substitute in the URL for your own
/// symbol server.
///
/// ```
/// # use breakpad_symbols::HttpSymbolSupplierOptions;
/// let mut opts = HttpSymbolSupplierOptions::default();
///
/// opts.urls = vec!["https://symbols.mozilla.org/".to_owned()];
/// opts.cache = Some(std::env::temp_dir().join("minidump-symbols"));
/// opts.tmp = Some(std::env::temp_dir());
/// ```
///
///
/// ## Microsoft HTTP Native Symbols
///
/// This is the configuration that emulates the experience of using official
/// Microsoft minidump tooling like windbg.
///
/// ```
/// # use breakpad_symbols::HttpSymbolSupplierOptions;
/// let mut opts = HttpSymbolSupplierOptions::default();
///
/// opts.urls = vec!["https://msdl.microsoft.com/download/symbols/".to_owned()];
/// opts.cache = Some(std::env::temp_dir().join("minidump-symbols"));
/// opts.tmp = Some(std::env::temp_dir());
/// opts.fetch_syms = false;
/// opts.fetch_native_binaries = true;
/// ```
///
///
/// ## Local Development
///
/// This configuration works when analyzing minidumps on the same machine
/// the crash was produced on. Should work especially well if the crashed
/// program was invoked with `cargo run`.
///
/// ```
/// # use breakpad_symbols::HttpSymbolSupplierOptions;
/// let mut opts = HttpSymbolSupplierOptions::default();
///
/// opts.cache = Some(std::env::temp_dir().join("minidump-symbols"));
/// opts.tmp = Some(std::env::temp_dir());
/// opts.use_minidump_paths = true;
/// ```
///
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpSymbolSupplierOptions {
    /// URLs to symbol servers, to try in order.
    ///
    /// Defaults to `vec![]`, meaning now URLs will be queried.
    ///
    /// When looking for symbols for a module, we will first look for breakpad symbols,
    /// and then native symbols (codefile and debugfile). These queries may be launched
    /// in parallel, but the if multiple URLs come back with a response, the tie will
    /// be broken by order.
    ///
    /// We may also append some `?` parameters to the end of a url to help the symbol server
    /// log symbols that it was missing in a way that can be acted upon, since the e.g.
    /// a `sym` query doesn't provide necessary info about the codefile.
    ///
    /// Many of these details are configurable by other options in this struct.
    ///
    /// The path schema is as follows (see also the example queries below):
    ///
    /// * For syms: `DEBUG_FILE/DEBUG_ID/DEBUG_FILE.sym`
    /// * For codefiles: `CODE_FILE/CODE_ID/CODE_FILE`
    /// * For debugfiles: `DEBUG_FILE/DEBUG_ID/DEBUG_FILE`
    ///
    /// Example input URLs:
    ///
    /// * `https://symbols.mozilla.org/`
    /// * `https://msdl.microsoft.com/download/symbols/`
    ///
    /// Example queries:
    ///
    /// * sym: `https://symbols.mozilla.org/DWrite.pdb/c10250ffba478e770798871932c7d8c51/DWrite.sym`
    /// * debugfile: `https://msdl.microsoft.com/download/symbols/DWrite.pdb/c10250ffba478e770798871932c7d8c51/DWrite.pdb`
    /// * codefile: `https://msdl.microsoft.com/download/symbols/DWrite.dll/29a9e8ad27f000/DWrite.dll`
    pub urls: Vec<String>,
    /// A base path to build a local symbol cache in.
    ///
    /// Defaults to `None`, but we highly recommend setting it!
    ///
    /// If this is None, we will only ever store loaded/computed symbols in memory
    /// (to the best of our ability, unfortunately every feature that relies on
    /// the `dump_syms` feature currently hard-requires the cache. We will emit
    /// warnings if you disable cache/tmp with those features enabled.)
    ///
    /// If this is Some, then we will download symbols to an anonymous file
    /// in the directory specified by the `tmp` option, and then "atomically"
    /// rename them into their final location in the cache.
    ///
    /// The directory structure of the cache is identical to the one used for
    /// `urls`, (so if you hosted the cache with a static file server and passed
    /// it to `urls`, that would work).
    ///
    /// `cache` is queried before `urls`, so if we ever get something weird from
    /// a url, it may stick around for all eternity, until the cache entry is removed.
    ///
    /// We don't ever garbage-collect our cache, and
    /// just assume a monitor program handles this for us (which is ideally how
    /// system temp dirs should automatically work if you're running out of space).
    pub cache: Option<PathBuf>,
    /// A directory for any temporary files that we need when downloading/computing
    /// symbols. If this isn't set and we still need it, we will panic.
    ///
    /// Defaults to `Some(std::env::temp_dir())`.
    ///
    /// If you set `cache` we recommend setting this as well, as cache relies on
    /// renaming files from this directory, and that doesn't work if they're on
    /// different file systems (and some systems put /tmp/ on a separate filesystem)!
    pub tmp: Option<PathBuf>,
    /// Local paths to search for .sym files.
    ///
    /// Defaults to `vec![]`, meaning no paths will be queried.
    ///
    /// The structure of these dirs should be the same as `cache`.
    /// Local results will be preferred over all other results,
    /// and if there are multiple local results, the first one will be preferred.
    pub local_paths: Vec<PathBuf>,
    /// A timeout to use for http requests.
    ///
    /// Defaults to 1000 seconds.
    pub timeout: Duration,
    /// Whether to query urls for .sym files.
    ///
    /// Defaults to `true`.
    ///
    /// This mode works with "fake" Microsoft Symbol Servers like Tecken,
    /// and is the mode that breakpad-symbols was designed for. These files
    /// are generally significantly smaller than a codefile or debugfile,
    /// where symbols natively reside.
    pub fetch_syms: bool,
    /// Whether to query urls for native codefiles and debugfiles.
    ///
    /// Currently defaults to `cfg!(feature = dump_syms)` (experimental).
    ///
    /// Setting this to `true` will do nothing if the `dump_syms` feature isn't also enabled.
    ///
    /// This mode works with "real" Microsoft Symbol Servers, and is experimental.
    pub fetch_native_binaries: bool,
    /// Whether to try to get symbols from the *actual* codefile and debugfile paths
    /// on the current system.
    ///
    /// Currently defaults to `false` (experimental).
    ///
    /// Setting this to `true` will do nothing if the `dump_syms` feature isn't also enabled.
    ///
    /// The actual codefile and debugfile entries in a minidump are actually complete paths
    /// from either the machine where the program was running, or the machine where the build
    /// was performed. Either way, this means processing a minidump on the same machine
    /// that the crash occured on can yield some symbols at those paths. This works especially
    /// well for local development where "build machine" and "run machine" are the same, and
    /// the executable is still in the build dir with ALL the debuginfo the compiler emitted!
    ///
    /// If `cache` is set, we *may* place a `sym` in it to optimize subsequent runs.
    pub use_minidump_paths: bool,
    /// Whether to append extra `?` parameters to http requests to symbol servers.
    ///
    /// Defaults to `true`.
    ///
    /// Current enabling this makes us append `?code_file=...&code_id=...` to
    /// `.sym` queries. Native binary queries are unaffected, but this may change in
    /// the future if anyone has a compelling reason to add them.
    ///
    /// The extra parameters can help the symbol server log and backfill failed symbol
    /// queries, but aren't part of the official symbol server protocol. Microsoft's
    /// servers don't care if they're there even for native queries, but you can disable
    /// them if you really want.
    pub append_debug_query_params: bool,
}

impl Default for HttpSymbolSupplierOptions {
    fn default() -> Self {
        Self {
            urls: vec![],
            cache: None,
            tmp: Some(std::env::temp_dir()),
            local_paths: vec![],
            timeout: Duration::from_secs(1000),
            fetch_syms: true,
            fetch_native_binaries: cfg!(feature = "dump_syms"),
            use_minidump_paths: false,
            append_debug_query_params: true,
        }
    }
}

/// An implementation of `SymbolSupplier` that loads Breakpad text-format
/// symbols from HTTP URLs.
///
/// See [`crate::breakpad_sym_lookup`] for details on how paths are searched.
///
/// See [`HttpSymbolSupplierOptions`][] for various options and details on how urls are queried.
pub struct HttpSymbolSupplier {
    /// File paths that are known to be in the cache
    #[allow(clippy::type_complexity)]
    cached_file_paths: Mutex<HashMap<FileKey, CachedOperation<(PathBuf, Option<Url>), FileError>>>,
    /// HTTP Client to use for fetching symbols.
    client: Client,
    /// URLs to search for symbols.
    urls: Vec<Url>,
    /// A `SimpleSymbolSupplier` to use for local symbol paths.
    local: SimpleSymbolSupplier,
    /// A path at which to cache downloaded symbols.
    cache: Option<PathBuf>,
    /// A path to a temporary location where downloaded symbols can be written
    /// before being atomically swapped into the cache.
    tmp: Option<PathBuf>,
    /// Whether to fetch .sym files over http.
    fetch_syms: bool,
    /// Whether to fetch native binaries over http.
    fetch_native_binaries: bool,
    /// Whether to try to use the full paths for codefiles/debugfiles in the minidump.
    use_minidump_paths: bool,
    /// Whether to append extra debugging arguments as `?query` params to URLs.
    append_debug_query_params: bool,
}

impl HttpSymbolSupplier {
    /// Create a new `HttpSymbolSupplier`.
    ///
    /// Symbols will be searched for in each of `local_paths` and `cache` first,
    /// then via HTTP at each of `urls`. If a symbol file is found via HTTP it
    /// will be saved under `cache`.
    pub fn new(options: HttpSymbolSupplierOptions) -> HttpSymbolSupplier {
        let client = Client::builder().timeout(options.timeout).build().unwrap();
        let urls = options
            .urls
            .into_iter()
            .filter_map(|mut u| {
                if !u.ends_with('/') {
                    u.push('/');
                }
                Url::parse(&u).ok()
            })
            .collect();
        let mut local_paths = options.local_paths;
        if let Some(cache) = options.cache.clone() {
            local_paths.push(cache);
        }
        let local = SimpleSymbolSupplier::new(local_paths);
        let cached_file_paths = Mutex::default();

        if !cfg!(feature = "dump_syms") {
            if options.fetch_native_binaries {
                warn!("fetch_native_binaries is enabled, but the dump_syms feature is cfg'd off!");
            }
            if options.use_minidump_paths {
                warn!("use_minidump_paths is enabled, but the dump_syms feature is cfg'd off!");
            }
        }
        HttpSymbolSupplier {
            client,
            cached_file_paths,
            urls,
            local,
            cache: options.cache,
            tmp: options.tmp,
            fetch_native_binaries: options.fetch_native_binaries,
            fetch_syms: options.fetch_syms,
            use_minidump_paths: options.use_minidump_paths,
            append_debug_query_params: options.append_debug_query_params,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, module), fields(module = crate::basename(&*module.code_file())))]
    pub async fn locate_file_internal(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<(PathBuf, Option<Url>), FileError> {
        let k = file_key(module, file_kind);
        let file_once = self
            .cached_file_paths
            .lock()
            .unwrap()
            .entry(k)
            .or_default()
            .clone();
        file_once
            .get_or_init(|| async {
                // First look for the file in the cache
                if let Ok(path) = self.local.locate_file(module, file_kind).await {
                    return Ok((path, None));
                }

                // Then try to download the file
                // FIXME: if we try to parallelize this with `join` then if we have multiple hits
                // we'll end up downloading all of them at once and having them race to write into
                // the cache... is that ok? Maybe? Since only one will ever win the swap, and it's
                // unlikely to get multiple hits... this might actually be ok!
                if let Some(lookup) = lookup(module, file_kind) {
                    for url in &self.urls {
                        let fetch = fetch_lookup(
                            &self.client,
                            url,
                            &lookup,
                            self.cache.as_deref(),
                            self.tmp.as_deref(),
                        )
                        .await;

                        if let Ok((path, url)) = fetch {
                            return Ok((path, url));
                        }
                    }

                    // If we're allowed to look for mozilla's special CAB paths, do that
                    if cfg!(feature = "mozilla_cab_symbols") {
                        for url in &self.urls {
                            let fetch = fetch_cab_lookup(
                                &self.client,
                                url,
                                &lookup,
                                self.cache.as_deref(),
                                self.tmp.as_deref(),
                            )
                            .await;

                            if let Ok((path, url)) = fetch {
                                return Ok((path, url));
                            }
                        }
                    }
                }
                Err(FileError::NotFound)
            })
            .await
            .clone()
    }
}

fn file_key(module: &(dyn Module + Sync), file_kind: FileKind) -> FileKey {
    (module_key(module), file_kind)
}

fn create_cache_file(tmp_path: &Path, final_path: &Path) -> io::Result<NamedTempFile> {
    // Use tempfile to save things to our cache to ensure proper
    // atomicity of writes. We may want multiple instances of rust-minidump
    // to be sharing a cache, and we don't want one instance to see another
    // instance's partially written results.
    //
    // tempfile is designed explicitly for this purpose, and will handle all
    // the platform-specific details and do its best to cleanup if things
    // crash.

    // First ensure that the target directory in the cache exists
    let base = final_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Bad cache path: {:?}", final_path),
        )
    })?;
    fs::create_dir_all(&base)?;

    NamedTempFile::new_in(tmp_path)
}

fn commit_cache_file(mut temp: NamedTempFile, final_path: &Path, url: &Url) -> io::Result<()> {
    // Append any extra metadata we also want to be cached as "INFO" lines,
    // because this is an established format that parsers will ignore the
    // contents of by default.

    // INFO URL allows us to properly report the url we retrieved a symbol file
    // from, even when the file is loaded from our on-disk cache.
    let cache_metadata = format!("INFO URL {}\n", url);
    temp.write_all(cache_metadata.as_bytes())?;

    // TODO: don't do this
    if final_path.exists() {
        fs::remove_file(final_path)?;
    }

    // If another process already wrote this entry, prefer their value to
    // avoid needless file system churn.
    temp.persist_noclobber(final_path)?;

    Ok(())
}

/// Fetch a symbol file from the URL made by combining `base_url` and `rel_path` using `client`,
/// save the file contents under `cache` + `rel_path` and also return them.
async fn fetch_symbol_file(
    client: &Client,
    base_url: &Url,
    module: &(dyn Module + Sync),
    cache: Option<&Path>,
    tmp: Option<&Path>,
    append_debug_query_params: bool,
) -> Result<SymbolFile, SymbolError> {
    trace!("HttpSymbolSupplier trying symbol server {}", base_url);
    // This function is a bit of a complicated mess because we want to write
    // the input to our symbol cache, but we're a streaming parser. So we
    // use the bare SymbolFile::parse to get access to the contents of
    // the input stream as it's downloaded+parsed to write it to disk.
    //
    // Note that caching is strictly "optional" because it's more important
    // to parse the symbols. So if at any point the caching i/o fails, we just
    // give up on caching but let the parse+download continue.

    // First try to GET the file from a server
    let sym_lookup = breakpad_sym_lookup(module).ok_or(SymbolError::MissingDebugFileOrId)?;
    let mut url = base_url
        .join(&sym_lookup.server_rel)
        .map_err(|_| SymbolError::NotFound)?;

    if append_debug_query_params {
        let code_id = module.code_identifier().unwrap_or_default();
        url.query_pairs_mut()
            .append_pair("code_file", crate::basename(&module.code_file()))
            .append_pair("code_id", code_id.as_str());
    }
    debug!("Trying {}", url);
    let res = client
        .get(url.clone())
        .send()
        .await
        .and_then(|res| res.error_for_status())
        .map_err(|_| SymbolError::NotFound)?;

    // Now try to create the temp cache file (not yet in the cache)

    let mut temp = cache.and_then(|cache| {
        let final_cache_path = cache.join(sym_lookup.cache_rel);
        let tmp = tmp.expect("set cache but unset tmp?!");
        let file = create_cache_file(tmp, &final_cache_path)
            .map_err(|e| {
                warn!("Failed to save symbol file in local disk cache: {}", e);
            })
            .ok()?;
        Some((file, final_cache_path))
    });

    // Now stream parse the file as it downloads.
    let mut symbol_file = SymbolFile::parse_async(res, |data| {
        // While we're downloading+parsing, save this data to the the disk cache too
        if let Some((file, _path)) = temp.as_mut() {
            if let Err(e) = file.write_all(data) {
                // Give up on caching this.
                warn!("Failed to save symbol file in local disk cache: {}", e);
                temp = None;
            }
        }
    })
    .await?;
    // Make note of what URL this symbol file was downloaded from.
    symbol_file.url = Some(url.to_string());

    // Try to finish the cache file and atomically swap it into the cache.
    if let Some((temp, final_cache_path)) = temp {
        let _ = commit_cache_file(temp, &final_cache_path, &url).map_err(|e| {
            warn!("Failed to save symbol file in local disk cache: {}", e);
        });
    }

    Ok(symbol_file)
}

/// Like fetch_symbol_file but instead of parsing the file live, we just download it opaquely based
/// on the given Lookup.
///
/// The returned value is the path to the downloaded file and the url it was downloaded from.
async fn fetch_lookup(
    client: &Client,
    base_url: &Url,
    lookup: &FileLookup,
    cache: Option<&Path>,
    tmp: Option<&Path>,
) -> Result<(PathBuf, Option<Url>), SymbolError> {
    let (cache, tmp) = if let (Some(cache), Some(tmp)) = (cache, tmp) {
        (cache, tmp)
    } else {
        warn!("Fetching native binaries currently requires both cache and tmp!");
        return Err(SymbolError::NotFound);
    };
    // First try to GET the file from a server
    let url = base_url
        .join(&lookup.server_rel)
        .map_err(|_| SymbolError::NotFound)?;
    debug!("Trying {}", url);
    let mut res = client
        .get(url.clone())
        .send()
        .await
        .and_then(|res| res.error_for_status())
        .map_err(|_| SymbolError::NotFound)?;

    // Now try to create the temp cache file (not yet in the cache)
    let final_cache_path = cache.join(&lookup.cache_rel);
    let mut temp = create_cache_file(tmp, &final_cache_path)?;

    // Now stream the contents to our file
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    {
        temp.write_all(&chunk[..])?;
    }

    // And swap it into the cache
    temp.persist_noclobber(&final_cache_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    trace!("symbols: fetched native binary: {}", lookup.cache_rel);

    Ok((final_cache_path, Some(url)))
}

#[cfg(feature = "mozilla_cab_symbols")]
async fn fetch_cab_lookup(
    client: &Client,
    base_url: &Url,
    lookup: &FileLookup,
    cache: Option<&Path>,
    tmp: Option<&Path>,
) -> Result<(PathBuf, Option<Url>), FileError> {
    let (cache, tmp) = if let (Some(cache), Some(tmp)) = (cache, tmp) {
        (cache, tmp)
    } else {
        warn!("Fetching native binaries currently requires both cache and tmp!");
        return Err(FileError::NotFound);
    };

    let cab_lookup = moz_lookup(lookup.clone());
    // First try to GET the file from a server
    let url = base_url
        .join(&cab_lookup.server_rel)
        .map_err(|_| FileError::NotFound)?;
    debug!("Trying {}", url);
    let res = client
        .get(url.clone())
        .send()
        .await
        .and_then(|res| res.error_for_status())
        .map_err(|_| FileError::NotFound)?;

    let cab_bytes = res.bytes().await.map_err(|_| FileError::NotFound)?;
    let final_cache_path =
        unpack_cabinet_file(&cab_bytes, lookup, cache, tmp).map_err(|_| FileError::NotFound)?;

    trace!("Fetched native binary: {}", lookup.cache_rel);

    Ok((final_cache_path, Some(url)))
}

#[cfg(not(feature = "mozilla_cab_symbols"))]
async fn fetch_cab_lookup(
    _client: &Client,
    _base_url: &Url,
    _lookup: &FileLookup,
    _cache: Option<&Path>,
    _tmp: Option<&Path>,
) -> Result<(PathBuf, Option<Url>), FileError> {
    Err(FileError::NotFound)
}

#[cfg(feature = "mozilla_cab_symbols")]
pub fn unpack_cabinet_file(
    buf: &[u8],
    lookup: &FileLookup,
    cache: &Path,
    tmp: &Path,
) -> Result<PathBuf, std::io::Error> {
    trace!("Unpacking CAB file: {}", lookup.cache_rel);
    // try to find a file in a cabinet archive and unpack it to the destination
    use cab::Cabinet;
    use std::io::Cursor;
    fn get_cabinet_file(
        cab: &Cabinet<Cursor<&[u8]>>,
        file_name: &str,
    ) -> Result<String, std::io::Error> {
        for folder in cab.folder_entries() {
            for file in folder.file_entries() {
                let cab_file_name = file.name();
                if cab_file_name.ends_with(file_name) {
                    return Ok(cab_file_name.to_string());
                }
            }
        }
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    }
    let final_cache_path = cache.join(&lookup.cache_rel);

    let cursor = Cursor::new(buf);
    let mut cab = Cabinet::new(cursor)?;
    let file_name = final_cache_path.file_name().unwrap().to_string_lossy();
    let cab_file = get_cabinet_file(&cab, &file_name)?;
    let mut reader = cab.read_file(&cab_file)?;

    // Now try to create the temp cache file (not yet in the cache)
    let mut temp = create_cache_file(tmp, &final_cache_path)?;
    std::io::copy(&mut reader, &mut temp)?;

    // And swap it into the cache
    temp.persist_noclobber(&final_cache_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(final_cache_path)
}

/// Try to lookup native binaries in the cache and by querying the symbol server

/// Runs dump_syms on the given inputs and produces a .sym file at the give output.
///
/// This function has to work around some technical limitations in dump_syms, and
/// requires some delicate handling:
///
/// * All inputs should be in the same directory and have their "natural names"
///   so that they can be automatically discovered and format-detected.
///
/// * Inputs should be ordered in "increasing preference", and debuginfo (pdb)
///   files should be preferred over executable (exe/dll) files.
///
/// This can take a while to run, and is *ideally* just a transient hack while
/// we teach rust-minidump to handle native debuginfo directly.
#[cfg(feature = "dump_syms")]
async fn dump_syms(
    inputs: &[Result<(PathBuf, Option<Url>), FileError>],
    output: &Path,
) -> Result<(), SymbolError> {
    use dump_syms::dumper;

    if !inputs.iter().any(|input| input.is_ok()) {
        return Err(SymbolError::NotFound);
    }

    trace!("Found native symbols!");

    let mut source_file = None;
    let mut urls = vec![];
    for (input_path, input_url) in inputs.iter().flatten() {
        // If we know where we got this from, record it.
        if let Some(url) = input_url {
            urls.push(url.to_string());
            trace!("  Native binary: {} from {}", input_path.display(), url);
        } else {
            trace!("  Native binary: {}", input_path.display());
        }
        // dump_syms only wants one input, and will derive the others
        // from that one input by looking in the directory. If we have
        // multiple sources, we want the last one (caller knows the right priority).
        source_file = Some(input_path);
    }

    trace!("Running dump_syms on {}...", source_file.unwrap().display());

    if let Err(e) = dumper::single_file(
        &dumper::Config {
            output: dumper::Output::File(output.to_string_lossy()[..].into()),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: "unknown",
            file_type: dump_syms::common::FileType::Pdb,
            num_jobs: 2, // default this
            check_cfi: false,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
        },
        &source_file.unwrap().to_string_lossy()[..],
    ) {
        debug!("dump_syms failed: {}", e);
        Err(std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }

    {
        // Write extra metadata to the file
        let mut temp = std::fs::File::options().append(true).open(output)?;
        let mut cache_metadata = String::new();
        for url in urls {
            cache_metadata.push_str(&format!("INFO URL {}\n", url));
        }
        temp.write_all(cache_metadata.as_bytes())?;
    }

    Ok(())
}

#[cfg(not(feature = "dump_syms"))]
async fn dump_syms(
    _inputs: &[Result<(PathBuf, Option<Url>), FileError>],
    _output: &Path,
) -> Result<(), SymbolError> {
    Err(SymbolError::NotFound)
}

#[async_trait]
impl SymbolSupplier for HttpSymbolSupplier {
    #[tracing::instrument(name = "symbols", level = "trace", skip_all, fields(file = crate::basename(&*module.code_file())))]
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<SymbolFile, SymbolError> {
        // First: try local paths for sym files
        let local_result = self.local.locate_symbols(module).await;
        if !matches!(local_result, Err(SymbolError::NotFound)) {
            // Everything but NotFound prevents cascading
            return local_result;
        }
        trace!("HttpSymbolSupplier search (SimpleSymbolSupplier found nothing)");

        // Second: try to directly download sym files
        if self.fetch_syms {
            for url in &self.urls {
                // First, try to get a breakpad .sym file from the symbol server
                let sym = fetch_symbol_file(
                    &self.client,
                    url,
                    module,
                    self.cache.as_deref(),
                    self.tmp.as_deref(),
                    self.append_debug_query_params,
                )
                .await;
                match sym {
                    Ok(file) => {
                        trace!("HttpSymbolSupplier parsed file!");
                        return Ok(file);
                    }
                    Err(e) => {
                        trace!("HttpSymbolSupplier failed: {}", e);
                    }
                }
            }
        }

        // Third: try to generate a symfile from native symbols
        if cfg!(feature = "dump_syms") && self.fetch_native_binaries {
            if let (Some(cache), Some(_tmp)) = (self.cache.as_ref(), self.tmp.as_ref()) {
                trace!("symbols: trying to fetch native symbols");
                // Find native files
                let mut native_artifacts = vec![];
                native_artifacts.push(self.locate_file_internal(module, FileKind::Binary).await);
                native_artifacts.push(
                    self.locate_file_internal(module, FileKind::ExtraDebugInfo)
                        .await,
                );

                // Now try to run dump_syms to produce a .sym
                let sym_lookup =
                    breakpad_sym_lookup(module).ok_or(SymbolError::MissingDebugFileOrId)?;
                let output = cache.join(sym_lookup.cache_rel);
                if dump_syms(&native_artifacts, &output).await.is_ok() {
                    trace!("symbols: dump_syms successful! using local result");
                    // We want dump_syms to leave us in a state "as if" we had downloaded
                    // the symbol file, so as a guard against that diverging, we now use
                    // the proper cache-lookup path to read the file dump_syms just wrote.
                    if let Ok(local_result) = self.local.locate_symbols(module).await {
                        return Ok(local_result);
                    } else {
                        warn!("dump_syms succeeded, but there was no symbol file in the cache?");
                    }
                }
            } else {
                warn!("Unfortunately the current dump_syms impl requires both a cache and tmp!")
            };
        }

        // Fourth: try minidump paths
        if cfg!(feature = "dump_syms") && self.use_minidump_paths {
            if let (Some(cache), Some(_tmp)) = (self.cache.as_ref(), self.tmp.as_ref()) {
                let mut native_artifacts = vec![];
                {
                    let path = PathBuf::from(&*module.code_file());
                    if path.exists() {
                        native_artifacts.push(Ok((path, None)));
                    }
                }
                if let Some(path) = module.debug_file() {
                    let path = PathBuf::from(&*path);
                    if path.exists() {
                        native_artifacts.push(Ok((path, None)));
                    }
                }
                // Now try to run dump_syms to produce a .sym
                let sym_lookup =
                    breakpad_sym_lookup(module).ok_or(SymbolError::MissingDebugFileOrId)?;
                let output = cache.join(sym_lookup.cache_rel);
                if dump_syms(&native_artifacts, &output).await.is_ok() {
                    trace!("symbols: dump_syms successful! using local result");
                    // We want dump_syms to leave us in a state "as if" we had downloaded
                    // the symbol file, so as a guard against that diverging, we now use
                    // the proper cache-lookup path to read the file dump_syms just wrote.
                    if let Ok(local_result) = self.local.locate_symbols(module).await {
                        return Ok(local_result);
                    } else {
                        warn!("dump_syms succeeded, but there was no symbol file in the cache?");
                    }
                }
            } else {
                panic!("Unfortunately the current dump_syms impl requires both a cache and tmp!")
            };
        }

        // If we get this far, we have failed to find anything
        Err(SymbolError::NotFound)
    }

    async fn locate_file(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        self.locate_file_internal(module, file_kind)
            .await
            .map(|(path, _url)| path)
    }
}
