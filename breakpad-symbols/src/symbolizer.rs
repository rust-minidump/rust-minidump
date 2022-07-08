use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use debugid::DebugId;
use minidump_common::traits::Module;
use minidump_processor::{
    FileError, FileKind, FillSymbolError, FrameSymbolizer, FrameWalker, SymbolProvider, SymbolStats,
};
use tracing::trace;

use crate::{
    leafname, module_key, CachedOperation, ModuleKey, SimpleFrame, SymbolError, SymbolFile,
    SymbolSupplier,
};

/// Symbolicate stack frames.
///
/// A `Symbolizer` manages loading symbols and looking up symbols in them
/// including caching so that symbols for a given module are only loaded once.
///
/// Call [`Symbolizer::new`][new] to instantiate a `Symbolizer`. A Symbolizer
/// requires a [`SymbolSupplier`][supplier] to locate symbols. If you have
/// symbols on disk in the [customary directory layout][breakpad_sym_lookup], a
/// [`SimpleSymbolSupplier`][simple] will work.
///
/// Use [`get_symbol_at_address`][get_symbol] or [`fill_symbol`][fill_symbol] to
/// do symbol lookup.
///
/// [new]: struct.Symbolizer.html#method.new
/// [supplier]: trait.SymbolSupplier.html
/// [simple]: struct.SimpleSymbolSupplier.html
/// [get_symbol]: struct.Symbolizer.html#method.get_symbol_at_address
/// [fill_symbol]: struct.Symbolizer.html#method.fill_symbol
pub struct Symbolizer {
    /// Symbol supplier for locating symbols.
    supplier: Box<dyn SymbolSupplier + Send + Sync + 'static>,
    /// Cache of symbol locating results.
    // TODO?: use lru-cache: https://crates.io/crates/lru-cache/
    // note that using an lru-cache would mess up the fact that we currently
    // use this for statistics collection. Splitting out statistics would be
    // way messier but not impossible.
    symbols: Mutex<HashMap<ModuleKey, CachedOperation<SymbolFile, SymbolError>>>,
}

impl Symbolizer {
    /// Create a `Symbolizer` that uses `supplier` to locate symbols.
    pub fn new<T: SymbolSupplier + Send + Sync + 'static>(supplier: T) -> Symbolizer {
        Symbolizer {
            supplier: Box::new(supplier),
            symbols: Mutex::new(HashMap::new()),
        }
    }

    /// Helper method for non-minidump-using callers.
    ///
    /// Pass `debug_file` and `debug_id` describing a specific module,
    /// and `address`, a module-relative address, and get back
    /// a symbol in that module that covers that address, or `None`.
    ///
    /// See [the module-level documentation][module] for an example.
    ///
    /// [module]: index.html
    pub async fn get_symbol_at_address(
        &self,
        debug_file: &str,
        debug_id: DebugId,
        address: u64,
    ) -> Option<String> {
        let k = (debug_file, debug_id);
        let mut frame = SimpleFrame::with_instruction(address);
        self.fill_symbol(&k, &mut frame).await.ok()?;
        frame.function
    }

    /// Fill symbol information in `frame` using the instruction address
    /// from `frame`, and the module information from `module`. If you're not
    /// using a minidump module, you can use [`SimpleModule`][simplemodule] and
    /// [`SimpleFrame`][simpleframe].
    ///
    /// An Error indicates that no symbols could be found for the relevant
    /// module.
    ///
    /// # Examples
    ///
    /// ```
    /// # std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
    /// use std::str::FromStr;
    /// use debugid::DebugId;
    /// use breakpad_symbols::{SimpleSymbolSupplier,Symbolizer,SimpleFrame,SimpleModule};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     use std::path::PathBuf;
    ///     let paths = vec!(PathBuf::from("../testdata/symbols/"));
    ///     let supplier = SimpleSymbolSupplier::new(paths);
    ///     let symbolizer = Symbolizer::new(supplier);
    ///     let debug_id = DebugId::from_str("5A9832E5287241C1838ED98914E9B7FF1").unwrap();
    ///     let m = SimpleModule::new("test_app.pdb", debug_id);
    ///     let mut f = SimpleFrame::with_instruction(0x1010);
    ///     let _ = symbolizer.fill_symbol(&m, &mut f).await;
    ///     assert_eq!(f.function.unwrap(), "vswprintf");
    ///     assert_eq!(f.source_file.unwrap(),
    ///         r"c:\program files\microsoft visual studio 8\vc\include\swprintf.inl");
    ///     assert_eq!(f.source_line.unwrap(), 51);
    /// }
    /// ```
    ///
    /// [simplemodule]: struct.SimpleModule.html
    /// [simpleframe]: struct.SimpleFrame.html
    pub async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizer + Send),
    ) -> Result<(), FillSymbolError> {
        let cached_sym = self.get_symbols(module).await;
        let sym = cached_sym
            .get()
            .unwrap()
            .as_ref()
            .map_err(|_| FillSymbolError {})?;
        sym.fill_symbol(module, frame);
        Ok(())
    }

    /// Collect various statistics on the symbols.
    ///
    /// Keys are the file name of the module (code_file's file name).
    pub fn stats(&self) -> HashMap<String, SymbolStats> {
        self.symbols
            .lock()
            .unwrap()
            .iter()
            .map(|(k, res)| {
                let res = res.get().expect("Had uninitialized SymbolFile entry?");
                let mut stats = SymbolStats::default();
                match res {
                    Ok(sym) => {
                        stats.symbol_url = sym.url.clone();
                        stats.loaded_symbols = true;
                        stats.corrupt_symbols = false;
                    }
                    Err(SymbolError::NotFound) => {
                        stats.loaded_symbols = false;
                    }
                    Err(SymbolError::MissingDebugFileOrId) => {
                        stats.loaded_symbols = false;
                    }
                    Err(SymbolError::LoadError(_)) => {
                        stats.loaded_symbols = false;
                    }
                    Err(SymbolError::ParseError(..)) => {
                        stats.loaded_symbols = true;
                        stats.corrupt_symbols = true;
                    }
                }
                (leafname(&k.0).to_string(), stats)
            })
            .collect()
    }

    /// Tries to use CFI to walk the stack frame of the FrameWalker
    /// using the symbols of the given Module. Output will be written
    /// using the FrameWalker's `set_caller_*` APIs.
    pub async fn walk_frame(
        &self,
        module: &(dyn Module + Sync),
        walker: &mut (dyn FrameWalker + Send),
    ) -> Option<()> {
        let cached_sym = self.get_symbols(module).await;
        let sym = cached_sym.get().unwrap().as_ref();
        if let Ok(sym) = sym {
            trace!("found symbols for address, searching for cfi entries");
            sym.walk_frame(module, walker)
        } else {
            trace!("couldn't find symbols for address, cannot use cfi");
            None
        }
    }

    /// Gets the fully parsed SymbolFile for a given module (or an Error).
    ///
    /// This returns a CachedOperation which is guaranteed to already be resolved (lifetime stuff).
    async fn get_symbols(
        &self,
        module: &(dyn Module + Sync),
    ) -> CachedOperation<SymbolFile, SymbolError> {
        // This clones an Arc<Once> that we will use to only do this operation once
        let k = module_key(module);
        let symbol_once = self.symbols.lock().unwrap().entry(k).or_default().clone();
        symbol_once
            .get_or_init(|| async {
                trace!("locating symbols for module {}", module.code_file());
                self.supplier.locate_symbols(module).await
            })
            .await;
        symbol_once
    }

    /// Gets the path to a file for a given module (or an Error).
    ///
    /// This returns a CachedOperation which is guaranteed to already be resolved (lifetime stuff).
    pub async fn get_file_path(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        self.supplier.locate_file(module, file_kind).await
    }
}

#[async_trait]
impl SymbolProvider for Symbolizer {
    async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizer + Send),
    ) -> Result<(), FillSymbolError> {
        self.fill_symbol(module, frame).await
    }
    async fn walk_frame(
        &self,
        module: &(dyn Module + Sync),
        walker: &mut (dyn FrameWalker + Send),
    ) -> Option<()> {
        self.walk_frame(module, walker).await
    }
    async fn get_file_path(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        self.get_file_path(module, file_kind).await
    }
    fn stats(&self) -> HashMap<String, SymbolStats> {
        self.stats()
    }
}
