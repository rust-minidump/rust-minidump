// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use failure::Error;

use std::path::Path;

use crate::sym_file::parser::{parse_symbol_bytes, parse_symbol_file};
use crate::{FrameSymbolizer, FrameWalker, Module};

pub use crate::sym_file::types::*;

mod parser;
mod types;
mod walker;

impl SymbolFile {
    /// Parse a `SymbolFile` from `path`.
    pub fn from_file(path: &Path) -> Result<SymbolFile, Error> {
        parse_symbol_file(path)
    }

    /// Parse an in-memory `SymbolFile` from `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<SymbolFile, Error> {
        parse_symbol_bytes(bytes)
    }

    /// Fill in as much source information for `frame` as possible.
    pub fn fill_symbol(&self, module: &dyn Module, frame: &mut dyn FrameSymbolizer) {
        // Look for a FUNC covering the address first.
        if frame.get_instruction() < module.base_address() {
            return;
        }
        let addr = frame.get_instruction() - module.base_address();
        if let Some(func) = self.functions.get(addr) {
            // TODO: although FUNC records have a parameter size, it appears that
            // they aren't to be trusted? The STACK WIN records are more reliable
            // when available. This is important precisely because these values
            // are used to unwind subsequent STACK WIN frames (because certain
            // calling conventions have the caller push the callee's arguments,
            // which affects the the stack's size!).
            //
            // Need to spend more time thinking about if this is the right approach
            let parameter_size = if let Some(info) = self.win_stack_framedata_info.get(addr) {
                info.parameter_size
            } else if let Some(info) = self.win_stack_fpo_info.get(addr) {
                info.parameter_size
            } else {
                func.parameter_size
            };

            frame.set_function(
                &func.name,
                func.address + module.base_address(),
                parameter_size,
            );
            // See if there's source line info as well.
            func.lines.get(addr).map(|line| {
                self.files.get(&line.file).map(|file| {
                    frame.set_source_file(file, line.line, line.address + module.base_address());
                })
            });
        } else if let Some(public) = self.find_nearest_public(addr) {
            // Settle for a PUBLIC.
            frame.set_function(
                &public.name,
                public.address + module.base_address(),
                public.parameter_size,
            );
        }
    }

    pub fn walk_frame(&self, module: &dyn Module, walker: &mut dyn FrameWalker) -> Option<()> {
        if walker.get_instruction() < module.base_address() {
            return None;
        }
        let addr = walker.get_instruction() - module.base_address();

        // Preferentially use framedata over fpo, because if both are present,
        // the former tends to be more precise (breakpad heuristic).
        let win_stack_result = if let Some(info) = self.win_stack_framedata_info.get(addr) {
            walker::walk_with_stack_win_framedata(info, walker)
        } else if let Some(info) = self.win_stack_fpo_info.get(addr) {
            walker::walk_with_stack_win_fpo(info, walker)
        } else {
            None
        };

        // If STACK WIN failed, try STACK CFI
        win_stack_result.or_else(|| {
            if let Some(info) = self.cfi_stack_info.get(addr) {
                // Don't use add_rules that come after this address
                let mut count = 0;
                let len = info.add_rules.len();
                while count < len && info.add_rules[count].address <= addr {
                    count += 1;
                }

                walker::walk_with_stack_cfi(&info.init, &info.add_rules[0..count], walker)
            } else {
                None
            }
        })
    }

    /// Find the nearest `PublicSymbol` whose address is less than or equal to `addr`.
    pub fn find_nearest_public(&self, addr: u64) -> Option<&PublicSymbol> {
        for p in self.publics.iter().rev() {
            if p.address <= addr {
                return Some(p);
            }
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    fn test_symbolfile_from_file(rel_path: &str) {
        let mut path = PathBuf::from(env!("PWD"));
        if path.file_name() == Some(OsStr::new("rust-minidump")) {
            path.push("breakpad-symbols");
        }
        path.push(rel_path);
        let sym = SymbolFile::from_file(&path).unwrap();
        assert_eq!(sym.files.len(), 6661);
        assert_eq!(sym.publics.len(), 5);
        assert_eq!(sym.find_nearest_public(0x9b07).unwrap().name, "_NLG_Return");
        assert_eq!(
            sym.find_nearest_public(0x142e7).unwrap().name,
            "_NLG_Return"
        );
        assert_eq!(
            sym.find_nearest_public(0x23b06).unwrap().name,
            "__from_strstr_to_strchr"
        );
        assert_eq!(
            sym.find_nearest_public(0xFFFFFFFF).unwrap().name,
            "__from_strstr_to_strchr"
        );
        assert_eq!(sym.functions.ranges_values().count(), 1065);
        assert_eq!(sym.functions.get(0x1000).unwrap().name, "vswprintf");
        assert_eq!(sym.functions.get(0x1012).unwrap().name, "vswprintf");
        assert!(sym.functions.get(0x1013).is_none());
        // There are 1556 `STACK WIN 4` lines in the symbol file, but only 856
        // that don't overlap. However they all overlap in ways that we have
        // to handle in the wild.
        assert_eq!(sym.win_stack_framedata_info.ranges_values().count(), 1556);
        assert_eq!(sym.win_stack_fpo_info.ranges_values().count(), 259);
        assert_eq!(
            sym.win_stack_framedata_info.get(0x41b0).unwrap().address,
            0x41b0
        );
    }

    #[test]
    fn test_symbolfile_from_lf_file() {
        test_symbolfile_from_file(
            "testdata/symbols/test_app.pdb/5A9832E5287241C1838ED98914E9B7FF1/test_app.sym",
        );
    }

    #[test]
    fn test_symbolfile_from_crlf_file() {
        test_symbolfile_from_file(
            "testdata/symbols/test_app.pdb/6A9832E5287241C1838ED98914E9B7FF1/test_app.sym",
        );
    }

    fn test_symbolfile_from_bytes(symbolfile_bytes: &[u8]) {
        let sym = SymbolFile::from_bytes(symbolfile_bytes).unwrap();

        assert_eq!(sym.files.len(), 1);
        assert_eq!(sym.publics.len(), 1);
        assert_eq!(sym.functions.ranges_values().count(), 1);
        assert_eq!(sym.functions.get(0x1000).unwrap().name, "another func");
        assert_eq!(
            sym.functions
                .get(0x1000)
                .unwrap()
                .lines
                .ranges_values()
                .count(),
            1
        );
        // test fallback
        assert_eq!(sym.functions.get(0x1001).unwrap().name, "another func");
    }

    #[test]
    fn test_symbolfile_from_bytes_with_lf() {
        test_symbolfile_from_bytes(
            b"MODULE Linux x86 ffff0000 bar
FILE 53 bar.c
PUBLIC 1234 10 some public
FUNC 1000 30 10 another func
1000 30 7 53
",
        );
    }

    #[test]
    fn test_symbolfile_from_bytes_with_crlf() {
        test_symbolfile_from_bytes(
            b"MODULE Linux x86 ffff0000 bar
FILE 53 bar.c
PUBLIC 1234 10 some public
FUNC 1000 30 10 another func
1000 30 7 53
",
        );
    }
}
