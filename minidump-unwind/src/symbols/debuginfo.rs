//! This module provides a `SymbolProvider` which uses local binary debuginfo.

use super::{async_trait, FileError, FileKind, FillSymbolError, FrameSymbolizer, FrameWalker};
use cachemap2::CacheMap;
use framehop::Unwinder;
use futures_util::lock::Mutex;
use memmap2::Mmap;
use minidump::{MinidumpModuleList, Module};
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use wholesym::{SymbolManager, SymbolManagerConfig, SymbolMap};

type ModuleData = std::borrow::Cow<'static, [u8]>;

/// A symbol provider which gets information from the minidump modules on the local system.
pub struct DebugInfoSymbolProvider {
    unwinder: framehop::x86_64::UnwinderX86_64<ModuleData>,
    unwind_cache: PerThread<framehop::x86_64::CacheX86_64<ModuleData>>,
    /// Indexed by module base address.
    symbols: HashMap<ModuleKey, Mutex<SymbolMap>>,
    symbol_manager: SymbolManager,
    /// The caches and unwinder operate on the memory held by the mapped modules, so this field
    /// must not be dropped until after they are dropped.
    _mapped_modules: Box<[Mmap]>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ModuleKey(u64);

impl ModuleKey {
    /// Create a module key for the given module.
    pub fn for_module(module: &dyn Module) -> Self {
        ModuleKey(module.base_address())
    }
}

impl From<&dyn Module> for ModuleKey {
    fn from(module: &dyn Module) -> Self {
        Self::for_module(module)
    }
}

impl From<&minidump::MinidumpModule> for ModuleKey {
    fn from(module: &minidump::MinidumpModule) -> Self {
        Self::for_module(module)
    }
}

struct PerThread<T> {
    inner: CacheMap<std::thread::ThreadId, UnsafeCell<T>>,
}

impl<T> Default for PerThread<T> {
    fn default() -> Self {
        PerThread {
            inner: Default::default(),
        }
    }
}

impl<T: Default> PerThread<T> {
    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        // # Safety
        // We guarantee unique access to the mutable reference because the values are indexed by
        // thread id: each thread gets its own value which it can freely mutate. We prevent
        // multiple mutable aliases from being created by requiring a callback function.
        f(unsafe { &mut *self.inner.cache_default(std::thread::current().id()).get() })
    }
}

/// Get the file path with debug information for the given module.
///
/// If `unwind_info` is true, returns the path that should contain unwind information.
fn effective_debug_file(module: &dyn Module, unwind_info: bool) -> PathBuf {
    // Windows x86_64 always stores the unwind info _only_ in the binary.
    let ignore_debug_file = unwind_info && cfg!(all(windows, target_arch = "x86_64"));

    let code_file = module.code_file();
    let code_file_path: &Path = code_file.as_ref().as_ref();

    if !ignore_debug_file {
        if let Some(file) = module.debug_file() {
            let file_path: &Path = file.as_ref().as_ref();
            // Anchor relative paths in the code file parent.
            if file_path.is_relative() {
                if let Some(parent) = code_file_path.parent() {
                    let path = parent.join(file_path);
                    if path.exists() {
                        return path;
                    }
                }
            }
            if file_path.exists() {
                return file_path.to_owned();
            }
        }
        // else fall back to code file below
    }

    code_file_path.to_owned()
}

fn load_unwind_module(module: &dyn Module) -> Option<(Mmap, framehop::Module<ModuleData>)> {
    let path = effective_debug_file(module, true);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!("failed to open {} for debug info: {e}", path.display());
            return None;
        }
    };
    // # Safety
    // The file is presumably read-only (being some binary or debug info file).
    let mapped = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("failed to map {} for debug info: {e}", path.display());
            return None;
        }
    };

    let objfile = match object::read::File::parse(
        // # Safety
        // We broaden the lifetime to static, but ensure that the Mmap which provides the data
        // outlives all references.
        unsafe { std::mem::transmute::<_, &'static [u8]>(mapped.as_ref()) },
    ) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("failed to parse object file {}: {e}", path.display());
            return None;
        }
    };

    let base = module.base_address();
    let end = base + module.size();
    let fhmodule = framehop::Module::new(path.display().to_string(), base..end, base, &objfile);

    Some((mapped, fhmodule))
}

impl DebugInfoSymbolProvider {
    pub async fn new(modules: &MinidumpModuleList) -> Self {
        let mut mapped_modules = Vec::new();
        let mut symbols = HashMap::new();
        let mut unwinder = framehop::x86_64::UnwinderX86_64::default();
        let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::new());
        for module in modules.iter() {
            if let Some((mapped, fhmodule)) = load_unwind_module(module) {
                mapped_modules.push(mapped);
                unwinder.add_module(fhmodule);
            }

            let path = effective_debug_file(module, false);
            if let Ok(sm) = symbol_manager
                .load_symbol_map_for_binary_at_path(&path, None)
                .await
            {
                symbols.insert(module.into(), Mutex::new(sm));
            }
        }
        DebugInfoSymbolProvider {
            unwinder,
            unwind_cache: Default::default(),
            symbols,
            symbol_manager,
            _mapped_modules: mapped_modules.into(),
        }
    }
}

#[async_trait]
impl super::SymbolProvider for DebugInfoSymbolProvider {
    async fn fill_symbol(
        &self,
        module: &(dyn Module + Sync),
        frame: &mut (dyn FrameSymbolizer + Send),
    ) -> Result<(), FillSymbolError> {
        let key = ModuleKey::for_module(module);
        let symbol_map = self.symbols.get(&key).ok_or(FillSymbolError {})?;

        use std::convert::TryInto;
        let addr = match (frame.get_instruction() - module.base_address()).try_into() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("failed to downcast relative address offset: {e}");
                return Ok(());
            }
        };

        let (address_info, origin) = {
            let guard = symbol_map.lock().await;
            let address_info = guard.lookup_relative_address(addr);
            let origin = guard.symbol_file_origin();
            (address_info, origin)
        };

        if let Some(address_info) = address_info {
            frame.set_function(
                &address_info.symbol.name,
                module.base_address() + address_info.symbol.address as u64,
                0,
            );
            use wholesym::FramesLookupResult::*;
            let frames = match address_info.frames {
                Available(frames) => Some(frames),
                External(ext) => self.symbol_manager.lookup_external(&origin, &ext).await,
                Unavailable => None,
            };

            if let Some(frames) = frames {
                let mut iter = frames.into_iter().rev();
                if let Some(f) = iter.next() {
                    if let Some(path) = f.file_path {
                        frame.set_source_file(
                            path.raw_path(),
                            f.line_number.unwrap_or(0),
                            module.base_address() + address_info.symbol.address as u64,
                        );
                    }
                }
                for f in iter {
                    frame.add_inline_frame(
                        f.function.as_deref().unwrap_or(""),
                        f.file_path.as_ref().map(|p| p.raw_path()),
                        f.line_number,
                    );
                }
            }
        }
        Ok(())
    }

    async fn walk_frame(
        &self,
        _module: &(dyn Module + Sync),
        walker: &mut (dyn FrameWalker + Send),
    ) -> Option<()> {
        let sp = walker.get_callee_register("rsp")?;
        let bp = walker.get_callee_register("rbp")?;
        let ip = walker.get_callee_register("rip")?;
        let mut regs = framehop::x86_64::UnwindRegsX86_64::new(ip, sp, bp);
        let result = self.unwind_cache.with(|cache| {
            self.unwinder.unwind_frame(
                if walker.has_grand_callee() {
                    framehop::FrameAddress::from_return_address(ip).unwrap()
                } else {
                    framehop::FrameAddress::from_instruction_pointer(ip)
                },
                &mut regs,
                cache,
                &mut |addr| walker.get_register_at_address(addr).ok_or(()),
            )
        });
        let ra = match result {
            Ok(ra) => ra,
            Err(e) => {
                tracing::error!("failed to unwind frame: {e}");
                return None;
            }
        };
        tracing::error!("ra = {:?}", ra);
        if let Some(ra) = ra {
            walker.set_ra(ra)?;
        }
        walker.set_cfa(regs.sp())?;
        walker.set_caller_register("rbp", regs.bp())?;

        Some(())
    }

    async fn get_file_path(
        &self,
        module: &(dyn Module + Sync),
        file_kind: FileKind,
    ) -> Result<PathBuf, FileError> {
        let path = match file_kind {
            FileKind::BreakpadSym => None,
            FileKind::Binary => Some(PathBuf::from(module.code_file().as_ref())),
            FileKind::ExtraDebugInfo => module.debug_file().map(|p| PathBuf::from(p.as_ref())),
        };
        match path {
            Some(path) if path.exists() => Ok(path),
            _ => Err(FileError::NotFound),
        }
    }
}
