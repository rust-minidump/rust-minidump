//! Contains HTTP symbol retrieval specific functionality

use crate::*;
use reqwest::{Client, Url};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;
use tracing::{debug, trace, warn};

/// An implementation of `SymbolSupplier` that loads Breakpad text-format
/// symbols from HTTP URLs.
///
/// See [`crate::relative_symbol_path`] for details on how paths are searched.
pub struct HttpSymbolSupplier {
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
        HttpSymbolSupplier {
            client,
            urls,
            local,
            cache,
            tmp,
        }
    }
}

/// A lookup we would like to perform for some native binary (exe, pdb, dll, ...)
pub struct BinaryLookup {
    cache_rel: String,
    server_rel: String,
}

/// Returns a lookup for this module's debuginfo (pdb)
pub fn debuginfo_lookup(module: &(dyn Module + Sync)) -> Option<BinaryLookup> {
    let debug_file = module.debug_file()?;
    let debug_id = module.debug_identifier()?;

    let leaf = leafname(&debug_file);
    let rel_path = [leaf, &debug_id.breakpad().to_string(), leaf].join("/");
    Some(BinaryLookup {
        cache_rel: rel_path.clone(),
        server_rel: rel_path,
    })
}

/// Returns a lookup for this module's executable (exe, dll, ...)
pub fn executable_lookup(module: &(dyn Module + Sync)) -> Option<BinaryLookup> {
    // NOTE: to make dump_syms happy we're currently moving the bin
    // to be next to the pdb. This changes where we would naively put it,
    // hence the two different paths!

    let code_file = module.code_file();
    let code_id = module.code_identifier()?;
    let debug_file = module.debug_file()?;
    let debug_id = module.debug_identifier()?;

    let bin_leaf = leafname(&code_file);
    let debug_leaf = leafname(&debug_file);

    Some(BinaryLookup {
        cache_rel: [debug_leaf, &debug_id.breakpad().to_string(), bin_leaf].join("/"),
        server_rel: [bin_leaf, &code_id.to_string(), bin_leaf].join("/"),
    })
}

/// Mangles a lookup to mozilla's format where the last char is replaced by an underscore
/// (and the file is wrapped in a CAB, but dump_syms handles that transparently).
pub fn moz_lookup(mut lookup: BinaryLookup) -> BinaryLookup {
    lookup.server_rel.pop().unwrap();
    lookup.server_rel.push('_');
    lookup
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

/// Query a Lookup from the cache.
///
/// The returned value is the path to the cache file and the url it was downloaded from if known.
fn get_cached_lookup(
    lookup: &BinaryLookup,
    cache: &Path,
) -> Result<(PathBuf, Option<Url>), SymbolError> {
    // All we have to do is check if the path exists, sadly we don't know the URL at this point.
    let final_cache_path = cache.join(&lookup.cache_rel);
    if final_cache_path.exists() {
        Ok((final_cache_path, None))
    } else {
        Err(SymbolError::NotFound)
    }
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
    let rel_path = relative_symbol_path(module, "sym").ok_or(SymbolError::MissingDebugFileOrId)?;
    let mut url = base_url
        .join(&rel_path)
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
    let final_cache_path = cache.join(rel_path);
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
    lookup: &BinaryLookup,
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

/// Try to lookup native binaries in the cache and by querying the symbol server
async fn lookup(
    client: &Client,
    base_url: &Url,
    lookup: Option<&BinaryLookup>,
    cache: &Path,
    tmp: &Path,
) -> Result<(PathBuf, Option<Url>), SymbolError> {
    if let Some(lookup) = lookup {
        if let Ok(res) = get_cached_lookup(lookup, cache) {
            Ok(res)
        } else {
            fetch_lookup(client, base_url, lookup, cache, tmp).await
        }
    } else {
        Err(SymbolError::NotFound)
    }
}

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
    inputs: &[Result<(PathBuf, Option<Url>), SymbolError>],
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
    _inputs: &[Result<(PathBuf, Option<Url>), SymbolError>],
    _output: &Path,
) -> Result<(), SymbolError> {
    Ok(())
}

#[async_trait]
impl SymbolSupplier for HttpSymbolSupplier {
    #[tracing::instrument(name = "symbols", level = "trace", skip_all, fields(file = crate::basename(&*module.code_file())))]
    async fn locate_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> Result<SymbolFile, SymbolError> {
        // Check local paths first.
        let local_result = self.local.locate_symbols(module).await;
        if !matches!(local_result, Err(SymbolError::NotFound)) {
            // Everything but NotFound prevents cascading
            return local_result;
        }
        trace!("HttpSymbolSupplier search (SimpleSymbolSupplier found nothing)");
        // Now try urls
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

            if cfg!(feature = "dump_syms") {
                trace!("symbols: trying to fetch native symbols");
                // If that didn't work, try to request a native pdb/dll from the symbol server
                let exe_lookup = executable_lookup(module);
                let pdb_lookup = debuginfo_lookup(module);

                // NOTE: pdb must come after bin, as this indicates that we should prefer
                // the pdb over the bin when they're both available (dump_syms doesn't like
                // when you pass it both, and just wants to infer one from the other).
                //
                // All of this logic handles lots of Options and Results to keep all the
                // error handling in one place instead of smeared around in here.
                let mut native_artifacts = vec![];
                native_artifacts.push(
                    lookup(
                        &self.client,
                        url,
                        exe_lookup.as_ref(),
                        &self.cache,
                        &self.tmp,
                    )
                    .await,
                );
                native_artifacts.push(
                    lookup(
                        &self.client,
                        url,
                        pdb_lookup.as_ref(),
                        &self.cache,
                        &self.tmp,
                    )
                    .await,
                );

                // Query mozilla's quirky alternate names
                // TODO: make this a separate feature?
                if true {
                    let moz_exe_lookup = exe_lookup.map(moz_lookup);
                    let moz_pdb_lookup = pdb_lookup.map(moz_lookup);
                    native_artifacts.push(
                        lookup(
                            &self.client,
                            url,
                            moz_exe_lookup.as_ref(),
                            &self.cache,
                            &self.tmp,
                        )
                        .await,
                    );
                    native_artifacts.push(
                        lookup(
                            &self.client,
                            url,
                            moz_pdb_lookup.as_ref(),
                            &self.cache,
                            &self.tmp,
                        )
                        .await,
                    );
                }

                // Now try to run the user's local dump_syms binary on the inputs to produce a .sym
                let out =
                    relative_symbol_path(module, "sym").ok_or(SymbolError::MissingDebugFileOrId)?;
                let output = self.cache.join(out);

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
        }
        // If we get this far, we have failed to find anything
        Err(SymbolError::NotFound)
    }
}
