use SymbolProvider;
use addr2line::{Mapping, Options};
use breakpad_symbols::FrameSymbolizer;
use failure::Error;
use memmap;
use minidump::Module;
use object::{self, Object};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;

#[derive(Default)]
pub struct DwarfSymbolizer {
    /// A mapping of lookups of symbol files, where the key is the path to the binary.
    known_modules: RefCell<HashMap<String, Option<Mapping>>>,
}

fn locate_symbols(path: &str) -> Result<Mapping, Error> {
    let f = File::open(path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };
    let obj = object::File::parse(&*buf).map_err(|_| format_err!("Failed to parse {}", path))?;
    if obj.has_debug_symbols() {
        let mapping = Options::default()
            .with_functions()
            .build(path)
            .map_err(|_| format_err!("Failed to load debug symbols for {}", path))?;
        Ok(mapping)
    } else {
        //TODO: use moria
        bail!("No debug symbols in {}", path)
    }
}

impl DwarfSymbolizer {
    pub fn new() -> DwarfSymbolizer {
        Default::default()
    }
}

impl SymbolProvider for DwarfSymbolizer {
    fn fill_symbol(&self, module: &Module, frame: &mut FrameSymbolizer) {
        let path = module.code_file();
        let k = path.as_ref();
        if !self.known_modules.borrow().contains_key(k) {
            self.known_modules
                .borrow_mut()
                .insert(path.clone().into_owned(), locate_symbols(&path).ok());
        }
        if let Some(&mut Some(ref mut map)) = self.known_modules.borrow_mut().get_mut(k) {
            let addr = frame.get_instruction();
            if let Ok(Some((source_file, line, func))) = map.locate(addr) {
                //TODO: get base address for line
                frame.set_source_file(&source_file.to_string_lossy(), line.unwrap_or(0) as u32, 0);
                if let Some(ref func) = func {
                    //TODO: get base address for function
                    frame.set_function(&func, 0);
                }
            }
        }
    }
}
