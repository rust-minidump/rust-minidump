// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

mod parser;
mod types;

use std::path::Path;

pub use sym_file::types::*;
use ::{Module,FrameSymbolizer};
use sym_file::parser::{parse_symbol_file,parse_symbol_bytes};

impl SymbolFile {
    /// Parse a `SymbolFile` from `path`.
    pub fn from_file(path : &Path) -> Result<SymbolFile, &'static str> {
        parse_symbol_file(path)
    }

    /// Parse an in-memory `SymbolFile` from `bytes`.
    pub fn from_bytes(bytes : &[u8]) -> Result<SymbolFile, &'static str> {
        parse_symbol_bytes(bytes)
    }

    /// Fill in as much source information for `frame` as possible.
    pub fn fill_symbol(&self,
                       module : &Module,
                       frame : &mut FrameSymbolizer) {
        // Look for a FUNC covering the address first.
        let addr = frame.get_instruction();
        if let Some(ref func) = self.functions.lookup(addr) {
            frame.set_function(&func.name,
                               func.address + module.base_address());
            // See if there's source line info as well.
            func.lines.lookup(addr).map(|ref line| {
                self.files.get(&line.file).map(|ref file| {
                    frame.set_source_file(file,
                                          line.line,
                                          line.address + module.base_address());
                })
            });
        } else if let Some(ref public) = self.find_nearest_public(addr) {
            // Settle for a PUBLIC.
            frame.set_function(&public.name,
                               public.address + module.base_address());
        }
    }

    /// Find the nearest `PublicSymbol` whose address is less than or equal to `addr`.
    pub fn find_nearest_public(&self, addr : u64) -> Option<&PublicSymbol> {
        for p in self.publics.iter().rev() {
            if p.address <= addr {
                return Some(p)
            }
        }

        return None;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;

    fn abs_file() -> PathBuf {
        let mut path = PathBuf::from(env!("PWD"));
        path.push(file!());
        path
    }

    #[test]
    fn test_symbolfile_from_file() {
        let mut path = abs_file();
        path.pop();
        path.pop();
        path.pop();
        path.push("testdata/symbols/test_app.pdb/5A9832E5287241C1838ED98914E9B7FF1/test_app.sym");
        let sym = SymbolFile::from_file(&path).unwrap();
        assert_eq!(sym.files.len(), 6661);
        assert_eq!(sym.publics.len(), 5);
        assert_eq!(sym.find_nearest_public(0x9b07).unwrap().name,
                   "_NLG_Return");
        assert_eq!(sym.find_nearest_public(0x142e7).unwrap().name,
                   "_NLG_Return");
        assert_eq!(sym.find_nearest_public(0x23b06).unwrap().name,
                   "__from_strstr_to_strchr");
        assert_eq!(sym.find_nearest_public(0xFFFFFFFF).unwrap().name,
                   "__from_strstr_to_strchr");
        assert_eq!(sym.functions.len(), 1065);
        assert_eq!(sym.functions.lookup(0x1000).unwrap().name, "vswprintf");
        assert_eq!(sym.functions.lookup(0x1012).unwrap().name, "vswprintf");
        assert!(sym.functions.lookup(0x1013).is_none());
        assert_eq!(sym.win_stack_info.len(), 1815);
        assert_eq!(sym.win_stack_info.lookup(0x41b0).unwrap().address,
                   0x41b0);
    }

    #[test]
    fn test_symbolfile_from_bytes() {
        let sym = SymbolFile::from_bytes(b"MODULE Linux x86 ffff0000 bar
FILE 53 bar.c
PUBLIC 1234 10 some public
FUNC 1000 30 10 another func
1000 30 7 53
").unwrap();
        assert_eq!(sym.files.len(), 1);
        assert_eq!(sym.publics.len(), 1);
        assert_eq!(sym.functions.len(), 1);
        assert_eq!(sym.functions.lookup(0x1000).unwrap().name, "another func");
        assert_eq!(sym.functions.lookup(0x1000).unwrap().lines.len(), 1);
    }
}
