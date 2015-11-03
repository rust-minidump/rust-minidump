// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

mod parser;
mod types;

use std::path::Path;

pub use sym_file::types::*;
use sym_file::parser::parse_symbol_file;

impl SymbolFile {
    /// Parse a `SymbolFile` from `path`.
    pub fn from_file(path : &Path) -> Result<SymbolFile, &'static str> {
        parse_symbol_file(path)
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

}
