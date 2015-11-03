// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

mod parser;
mod types;

use std::path::Path;

pub use sym_file::types::SymbolFile;
use sym_file::parser::parse_symbol_file;

impl SymbolFile {
    /// Parse a `SymbolFile` from `path`.
    pub fn from_file(path : &Path) -> Result<SymbolFile, &'static str> {
        parse_symbol_file(path)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_symbolfile_from_file() {
        let mut path = PathBuf::from(file!());
        path.pop();
        path.pop();
        path.pop();
        path.push("testdata/symbols/test_app.pdb/5A9832E5287241C1838ED98914E9B7FF1/test_app.sym");
        let sym = SymbolFile::from_file(&path).unwrap();
        assert_eq!(sym.files.len(), 6661);
        assert_eq!(sym.publics.len(), 5);
        assert_eq!(sym.functions.len(), 1065);
        assert_eq!(sym.win_stack_info.len(), 1815);
    }

}
