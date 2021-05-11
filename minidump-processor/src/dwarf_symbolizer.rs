use addr2line::{Context, Frame, Location};
use failure::{bail, format_err, Error};
use gimli::{EndianRcSlice, RunTimeEndian};
use object::{self, Object};

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;

use breakpad_symbols::{FrameSymbolizer, FrameWalker};
use minidump::Module;

use crate::SymbolProvider;

#[derive(Default)]
pub struct DwarfSymbolizer {
    /// A mapping of lookups of symbol files, where the key is the path to the binary.
    known_modules: RefCell<HashMap<String, Option<Context<EndianRcSlice<RunTimeEndian>>>>>,
}

fn locate_symbols(path: &str) -> Result<Context<EndianRcSlice<RunTimeEndian>>, Error> {
    let f = File::open(path)?;
    let buf = unsafe { memmap::Mmap::map(&f)? };
    let obj = object::File::parse(&*buf).map_err(|_| format_err!("Failed to parse {}", path))?;
    if obj.has_debug_symbols() {
        let context = Context::new(&obj)
            .map_err(|_| format_err!("Failed to load debug symbols for {}", path))?;
        Ok(context)
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
    fn fill_symbol(&self, module: &dyn Module, frame: &mut dyn FrameSymbolizer) {
        let path = module.code_file();
        let k = path.as_ref();
        if !self.known_modules.borrow().contains_key(k) {
            self.known_modules
                .borrow_mut()
                .insert(path.clone().into_owned(), locate_symbols(&path).ok());
        }
        if let Some(&mut Some(ref mut map)) = self.known_modules.borrow_mut().get_mut(k) {
            let addr = frame.get_instruction();
            if let Ok(mut iter) = map.find_frames(addr) {
                while let Ok(Some(Frame {
                    function: Some(func),
                    location:
                        Some(Location {
                            file: Some(source_file),
                            line,
                            ..
                        }),
                })) = iter.next()
                {
                    //TODO: get base address for line
                    frame.set_source_file(&source_file, line.unwrap_or(0) as u32, 0);
                    //TODO: get base address for function
                    if let Ok(name) = func.demangle() {
                        frame.set_function(&name, 0);
                        break;
                    }
                }
            }
        }
    }
    fn walk_frame(&self, _module: &dyn Module, _walker: &mut dyn FrameWalker) -> Option<()> {
        // unimplemented
        None
    }
}
