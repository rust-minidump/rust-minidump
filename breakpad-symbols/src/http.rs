//! Contains HTTP symbol retrieval specific functionality

use crate::*;
use log::{debug, trace, warn};
use reqwest::{Client, Url};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;

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
    trace!(
        "symbols: HttpSymbolSupplier trying symbol server {}",
        base_url
    );
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

#[async_trait]
impl SymbolSupplier for HttpSymbolSupplier {
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
        trace!("symbols: HttpSymbolSupplier search (SimpleSymbolSupplier found nothing)");
        // Now try urls
        for url in &self.urls {
            let file = fetch_symbol_file(&self.client, url, module, &self.cache, &self.tmp).await;
            match file {
                Ok(file) => {
                    trace!("symbols: HttpSymbolSupplier parsed file!");
                    return Ok(file);
                }
                Err(e) => {
                    trace!("symbols: HttpSymbolSupplier failed: {}", e);
                }
            }
        }
        // If we get this far, we have failed to find anything
        Err(SymbolError::NotFound)
    }
}
