use minidump::Module;
pub use symbols_shim::*;

pub trait SymbolProvider {
    fn fill_symbol(&self, module: &dyn Module, frame: &mut dyn FrameSymbolizer);
    fn walk_frame(&self, module: &dyn Module, walker: &mut dyn FrameWalker) -> Option<()>;
}

#[derive(Default)]
pub struct MultiSymbolProvider {
    providers: Vec<Box<dyn SymbolProvider>>,
}

impl MultiSymbolProvider {
    pub fn new() -> MultiSymbolProvider {
        Default::default()
    }

    pub fn add(&mut self, provider: Box<dyn SymbolProvider>) {
        self.providers.push(provider);
    }
}

impl SymbolProvider for MultiSymbolProvider {
    fn fill_symbol(&self, module: &dyn Module, frame: &mut dyn FrameSymbolizer) {
        for p in self.providers.iter() {
            p.fill_symbol(module, frame);
        }
    }

    fn walk_frame(&self, module: &dyn Module, walker: &mut dyn FrameWalker) -> Option<()> {
        for p in self.providers.iter() {
            let result = p.walk_frame(module, walker);
            if result.is_some() {
                return result;
            }
        }
        None
    }
}

#[cfg(feature = "breakpad-syms")]
mod symbols_shim {
    use super::SymbolProvider;
    use minidump::Module;
    use std::collections::HashMap;
    use std::path::PathBuf;

    pub use breakpad_symbols::{FrameSymbolizer, FrameWalker, SymbolSupplier, Symbolizer};

    impl SymbolProvider for Symbolizer {
        fn fill_symbol(&self, module: &dyn Module, frame: &mut dyn FrameSymbolizer) {
            self.fill_symbol(module, frame);
        }
        fn walk_frame(&self, module: &dyn Module, walker: &mut dyn FrameWalker) -> Option<()> {
            self.walk_frame(module, walker)
        }
    }

    /// Gets a SymbolSupplier that looks up symbols by path or with urls.
    ///
    /// May use the `symbols_cache` path to store downloads.
    pub fn http_symbol_supplier(
        symbol_paths: Vec<PathBuf>,
        symbol_urls: Vec<String>,
        symbols_cache: PathBuf,
    ) -> impl SymbolSupplier {
        breakpad_symbols::HttpSymbolSupplier::new(symbol_urls, symbols_cache, symbol_paths)
    }

    /// Gets a SymbolSupplier that looks up symbols by path.
    pub fn simple_symbol_supplier(symbol_paths: Vec<PathBuf>) -> impl SymbolSupplier {
        breakpad_symbols::SimpleSymbolSupplier::new(symbol_paths)
    }

    /// Gets a mock SymbolSupplier that just maps module names
    /// to a string containing an entire breakpad .sym file, for tests.
    pub fn string_symbol_supplier(modules: HashMap<String, String>) -> impl SymbolSupplier {
        breakpad_symbols::StringSymbolSupplier::new(modules)
    }
}

#[cfg(feature = "symbolic-syms")]
mod symbols_shim {
    #![allow(dead_code)]

    use super::SymbolProvider;
    use minidump::Module;
    use std::collections::HashMap;
    use std::path::PathBuf;

    // Import symbolic here

    /// A trait for things that can locate symbols for a given module.
    pub trait SymbolSupplier {
        /// Locate and load a symbol file for `module`.
        ///
        /// Implementations may use any strategy for locating and loading
        /// symbols.
        fn locate_symbols(&mut self, module: &dyn Module) -> SymbolResult;
    }

    /// A trait for setting symbol information on something like a stack frame.
    pub trait FrameSymbolizer {
        /// Get the program counter value for this frame.
        fn get_instruction(&self) -> u64;
        /// Set the name, base address, and paramter size of the function in
        // which this frame is executing.
        fn set_function(&mut self, name: &str, base: u64, parameter_size: u32);
        /// Set the source file and (1-based) line number this frame represents.
        fn set_source_file(&mut self, file: &str, line: u32, base: u64);
    }

    pub trait FrameWalker {
        /// Get the instruction address that we're trying to unwind from.
        fn get_instruction(&self) -> u64;
        /// Get the number of bytes the callee's callee's parameters take up
        /// on the stack (or 0 if unknown/invalid). This is needed for
        /// STACK WIN unwinding.
        fn get_grand_callee_parameter_size(&self) -> u32;
        /// Get a register-sized value stored at this address.
        fn get_register_at_address(&self, address: u64) -> Option<u64>;
        /// Get the value of a register from the callee's frame.
        fn get_callee_register(&self, name: &str) -> Option<u64>;
        /// Set the value of a register for the caller's frame.
        fn set_caller_register(&mut self, name: &str, val: u64) -> Option<()>;
        /// Explicitly mark one of the caller's registers as invalid.
        fn clear_caller_register(&mut self, name: &str);
        /// Set whatever registers in the caller should be set based on the cfa (e.g. rsp).
        fn set_cfa(&mut self, val: u64) -> Option<()>;
        /// Set whatever registers in the caller should be set based on the return address (e.g. rip).
        fn set_ra(&mut self, val: u64) -> Option<()>;
    }

    /// Possible results of locating symbols. (can be opaque, not used externally)
    #[derive(Debug)]
    pub struct SymbolResult;

    /// Symbolicate stack frames.
    ///
    /// A `Symbolizer` manages loading symbols and looking up symbols in them
    /// including caching so that symbols for a given module are only loaded once.
    ///
    /// Call [`Symbolizer::new`][new] to instantiate a `Symbolizer`. A Symbolizer
    /// requires a [`SymbolSupplier`][supplier] to locate symbols. If you have
    /// symbols on disk in the [customary directory layout][dirlayout], a
    /// [`SimpleSymbolSupplier`][simple] will work.
    ///
    /// Use [`get_symbol_at_address`][get_symbol] or [`fill_symbol`][fill_symbol] to
    /// do symbol lookup.
    ///
    /// [new]: struct.Symbolizer.html#method.new
    /// [supplier]: trait.SymbolSupplier.html
    /// [dirlayout]: fn.relative_symbol_path.html
    /// [simple]: struct.SimpleSymbolSupplier.html
    /// [get_symbol]: struct.Symbolizer.html#method.get_symbol_at_address
    /// [fill_symbol]: struct.Symbolizer.html#method.fill_symbol
    pub struct Symbolizer {
        /// Symbol supplier for locating symbols.
        supplier: Box<dyn SymbolSupplier + 'static>,
    }

    impl Symbolizer {
        /// Create a `Symbolizer` that uses `supplier` to locate symbols.
        pub fn new<T: SymbolSupplier + 'static>(supplier: T) -> Symbolizer {
            Symbolizer {
                supplier: Box::new(supplier),
            }
        }
    }

    impl SymbolProvider for Symbolizer {
        fn fill_symbol(&self, _module: &dyn Module, _frame: &mut dyn FrameSymbolizer) {
            unimplemented!()
        }
        fn walk_frame(&self, _module: &dyn Module, _walker: &mut dyn FrameWalker) -> Option<()> {
            unimplemented!()
        }
    }

    pub struct HttpSymbolSupplier {}

    pub struct SimpleSymbolSupplier {}

    pub struct StringSymbolSupplier {}

    impl SymbolSupplier for HttpSymbolSupplier {
        fn locate_symbols(&self, _module: &dyn Module) -> SymbolResult {
            unimplemented!()
        }
    }

    impl SymbolSupplier for SimpleSymbolSupplier {
        fn locate_symbols(&self, _module: &dyn Module) -> SymbolResult {
            unimplemented!()
        }
    }

    impl SymbolSupplier for StringSymbolSupplier {
        fn locate_symbols(&self, _module: &dyn Module) -> SymbolResult {
            unimplemented!()
        }
    }

    /// Gets a SymbolSupplier that looks up symbols by path or with urls.
    ///
    /// May use the `symbols_cache` path to store downloads.
    pub fn http_symbol_supplier(
        _symbol_paths: Vec<PathBuf>,
        _symbol_urls: Vec<String>,
        _symbols_cache: PathBuf,
    ) -> impl SymbolSupplier {
        HttpSymbolSupplier {}
    }

    /// Gets a SymbolSupplier that looks up symbols by path.
    pub fn simple_symbol_supplier(_symbol_paths: Vec<PathBuf>) -> impl SymbolSupplier {
        SimpleSymbolSupplier {}
    }

    /// Gets a mock SymbolSupplier that just maps module names
    /// to a string containing an entire breakpad .sym file, for tests.
    pub fn string_symbol_supplier(_modules: HashMap<String, String>) -> impl SymbolSupplier {
        StringSymbolSupplier {}
    }
}
