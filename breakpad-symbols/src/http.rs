//! Contains HTTP symbol retrieval specific functionality

use crate::*;
use cachemap2::CacheMap;
use reqwest::{Client, Url};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;
use tracing::{debug, trace, warn};

/// A key that uniquely identifies a File associated with a module
type FileKey = (ModuleKey, FileKind);

/// An implementation of `SymbolSupplier` that loads Breakpad text-format
/// symbols from HTTP URLs.
///
/// See [`crate::breakpad_sym_lookup`] for details on how paths are searched.
pub struct HttpSymbolSupplier {
    /// File paths that are known to be in the cache
    #[allow(clippy::type_complexity)]
    cached_file_paths: CacheMap<FileKey, CachedAsyncResult<(PathBuf, Option<Url>), FileError>>,
    /// HTTP Client to use for fetching symbols.
    client: Client,
    /// URLs to search for symbols.
    urls: Vec<Url>,
    /// A `SimpleSymbolSupplier` to use for local symbol paths.
    local: SimpleSymbolSupplier,
    /// A path at which to cache downloaded symbols.
    ///
    /// We recommend using a subdirectory of `std::env::temp_dir()`, as this
    /// will be your OS's intended location for tempory files. This should
    /// give you free garbage collection of the cache while still allowing it
    /// to function between runs.
    cache: PathBuf,
    /// A path to a temporary location where downloaded symbols can be written
    /// before being atomically swapped into the cache.
    ///
    /// We recommend using `std::env::temp_dir()`, as this will be your OS's
    /// intended location for temporary files.
    tmp: PathBuf,
}

impl HttpSymbolSupplier {
    /// Create a new `HttpSymbolSupplier`.
    ///
    /// Symbols will be searched for in each of `local_paths` and `cache` first,
    /// then via HTTP at each of `urls`. If a symbol file is found via HTTP it
    /// will be saved under `cache`.
    pub fn new(
        urls: Vec<String>,
        cache: PathBuf,
        tmp: PathBuf,
        mut local_paths: Vec<PathBuf>,
        timeout: Duration,
    ) -> HttpSymbolSupplier {
        let client = Client::builder().timeout(timeout).build().unwrap();
        let urls = urls
            .into_iter()
            .filter_map(|mut u| {
                if !u.ends_with('/') {
                    u.push('/');
                }
                Url::parse(&u).ok()
            })
            .collect();
        local_paths.push(cache.clone());
        let local = SimpleSymbolSupplier::new(local_paths);
        let cached_file_paths = Default::default();
        HttpSymbolSupplier {
            client,
            cached_file_paths,
            urls,
            local,
            cache,
            tmp,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, module), fields(module = crate::basename(&module.code_file())))]
    pub async fn locate_file_internal(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<(PathBuf, Option<Url>), FileError> {
        self.cached_file_paths
            .cache_default(file_key(module, file_kind))
            .get(|| async {
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
                        let fetch =
                            fetch_lookup(&self.client, url, &lookup, &self.cache, &self.tmp).await;

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
                                &self.cache,
                                &self.tmp,
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
            .as_ref()
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
            format!("Bad cache path: {final_path:?}"),
        )
    })?;
    fs::create_dir_all(base)?;

    NamedTempFile::new_in(tmp_path)
}

fn commit_cache_file(mut temp: NamedTempFile, final_path: &Path, url: &Url) -> io::Result<()> {
    // Append any extra metadata we also want to be cached as "INFO" lines,
    // because this is an established format that parsers will ignore the
    // contents of by default.

    // INFO URL allows us to properly report the url we retrieved a symbol file
    // from, even when the file is loaded from our on-disk cache.
    let cache_metadata = format!("INFO URL {url}\n");
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
    cache: &Path,
    tmp: &Path,
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
    let code_id = module.code_identifier().unwrap_or_default();
    url.query_pairs_mut()
        .append_pair("code_file", crate::basename(&module.code_file()))
        .append_pair("code_id", code_id.as_str());
    debug!("Trying {}", url);
    let res = client
        .get(url.clone())
        .send()
        .await
        .and_then(|res| res.error_for_status())
        .map_err(|_| SymbolError::NotFound)?;

    // Now try to create the temp cache file (not yet in the cache)
    let final_cache_path = cache.join(sym_lookup.cache_rel);
    let mut temp = create_cache_file(tmp, &final_cache_path)
        .map_err(|e| {
            warn!("Failed to save symbol file in local disk cache: {}", e);
        })
        .ok();

    // Now stream parse the file as it downloads.
    let mut symbol_file = SymbolFile::parse_async(res, |data| {
        // While we're downloading+parsing, save this data to the the disk cache too
        if let Some(file) = temp.as_mut() {
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
    if let Some(temp) = temp {
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
    cache: &Path,
    tmp: &Path,
) -> Result<(PathBuf, Option<Url>), SymbolError> {
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
    cache: &Path,
    tmp: &Path,
) -> Result<(PathBuf, Option<Url>), FileError> {
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

    trace!("symbols: fetched native binary: {}", lookup.cache_rel);

    Ok((final_cache_path, Some(url)))
}

#[cfg(not(feature = "mozilla_cab_symbols"))]
async fn fetch_cab_lookup(
    _client: &Client,
    _base_url: &Url,
    _lookup: &FileLookup,
    _cache: &Path,
    _tmp: &Path,
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
    trace!("symbols: unpacking CAB file: {}", lookup.cache_rel);
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

    trace!("symbols: found native symbols! running dump_syms...");

    let mut source_file = None;
    let mut urls = vec![];
    for (input_path, input_url) in inputs.iter().flatten() {
        // If we know where we got this from, record it.
        if let Some(url) = input_url {
            urls.push(url.to_string());
        }
        // dump_syms only wants one input, and will derive the others
        // from that one input by looking in the directory. If we have
        // multiple sources, we want the last one (caller knows the right priority).
        source_file = Some(input_path);
    }

    if let Err(e) = dumper::single_file(
        &dumper::Config {
            output: dumper::Output::File(output.to_string_lossy()[..].into()),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: "unknown",
            num_jobs: 2, // default this
            check_cfi: false,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            emit_inlines: true,
        },
        &source_file.unwrap().to_string_lossy()[..],
    ) {
        debug!("symbols: dump_syms failed: {}", e);
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
    Ok(())
}

#[async_trait]
impl SymbolSupplier for HttpSymbolSupplier {
    #[tracing::instrument(name = "symbols", level = "trace", skip_all, fields(file = crate::basename(&module.code_file())))]
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
        for url in &self.urls {
            // First, try to get a breakpad .sym file from the symbol server
            let sym = fetch_symbol_file(&self.client, url, module, &self.cache, &self.tmp).await;
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

        // Third: try to generate a symfile from native symbols
        if cfg!(feature = "dump_syms") {
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
            let output = self.cache.join(sym_lookup.cache_rel);
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
