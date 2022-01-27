// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.
use crate::{FrameSymbolizer, FrameWalker, Module, SymbolError};

pub use crate::sym_file::types::*;
pub use parser::SymbolParser;
use std::fs::File;
use std::io::Read;
use std::path::Path;

mod parser;
mod types;
pub mod walker;

impl SymbolFile {
    /// Parse a SymbolFile from the given Reader.
    ///
    /// Every time a chunk of the input is parsed, that chunk will
    /// be passed to `callback` to allow you to do something else
    /// with the data as it's streamed in (e.g. you can save the
    /// input to a cache).
    ///
    /// The reader is wrapped in a buffer reader so you shouldn't
    /// buffer the input yourself.
    pub fn parse<R: Read>(
        mut input_reader: R,
        mut callback: impl FnMut(&[u8]),
    ) -> Result<SymbolFile, SymbolError> {
        // This parse streams the input to avoid the need to materialize all of
        // it into memory at once (symbol files can be a gigabyte!). As a result,
        // we need to iteratively parse.
        //
        // We do this by repeatedly filling up a buffer with input and asking the
        // parser to parse it. The parser will return how much of the input it
        // consumed, which we can use to clear space in our buffer and to tell
        // if it successfully consumed the whole input when the Reader runs dry.

        // Having a fix-sized buffer has one fatal issue: if one atomic step
        // of the parser needs more than this amount of data, then we won't
        // be able to parse it.
        //
        // This can result in `buf` filling up and `buf.space()` becoming an
        // empty slice. This in turn will make the reader yield 0 bytes, and
        // we'll treat it like EOF and fail the parse. Bad error message UX,
        // but good enough. This is also our safety-valve against bugs in the
        // parser causing infinite loops.
        //
        // The "atom" of our parser is a line, and ~100kb is a pretty generous
        // limit to have on the length of a line. However we actually only have
        // *half* this value as our limit, as circular::Buffer will only
        // `shift` the buffer's contents if over half of its capacity has been
        // drained by `consume` -- and `space()` only grows when a `shift` happens.
        //
        // I have in fact seen 8kb function names (thanks generic combinators!), so we
        // need a buffer size that's at least 16kb. I went with 100kb to be safe.
        //
        // FIXME: investigate using `Buffer::grow` to be more adaptive here?
        let mut buf = circular::Buffer::with_capacity(100_000);
        let mut parser = SymbolParser::new();
        let mut fully_consumed = false;
        loop {
            // Read the data in, and tell the circular buffer about the new data
            let size = input_reader
                .read(buf.space())
                .map_err(SymbolError::LoadError)?;
            buf.fill(size);

            // If the reader returned nothing, then we're done. On the previous
            // iteration we submitted the last bytes of the input. If the parser
            // consumed all of those bytes, then the file perfectly parsed!
            if size == 0 {
                if fully_consumed {
                    return Ok(parser.finish());
                } else {
                    return Err(SymbolError::ParseError(format!("unexpected EOF during parsing of SymbolFile (or a line was too long?) at line {}", parser.lines)));
                }
            }

            // Ask the parser to parse more of the input
            let input = buf.data();
            let consumed = parser.parse_more(input)?;

            // Give the other consumer of this Reader a chance to use this data.
            callback(&input[..consumed]);

            // Remember for the next iteration if all the input was consumed.
            fully_consumed = input.len() == consumed;
            buf.consume(consumed);
        }
    }

    // Parse a SymbolFile from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<SymbolFile, SymbolError> {
        Self::parse(bytes, |_| ())
    }

    // Parse a SymbolFile from a file.
    pub fn from_file(path: &Path) -> Result<SymbolFile, SymbolError> {
        let file = File::open(path).map_err(SymbolError::LoadError)?;
        Self::parse(file, |_| ())
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
            // We couldn't find a valid FUNC record, but we could find a PUBLIC record.
            // Unfortauntely, PUBLIC records don't have end-points, so this could be
            // a random PUBLIC record from the start of the module that isn't at all
            // applicable. To try limit this problem, we can use the nearest FUNC
            // record that comes *before* the address we're trying to find a symbol for.
            //
            // It is reasonable to assume a PUBLIC record cannot extend *past* a FUNC,
            // so if the PUBLIC has a smaller base address than the nearest previous FUNC
            // to our target address, the PUBLIC must actually end before that FUNC and
            // therefore not actually apply to the target address.
            //
            // We get the nearest previous FUNC by getting the raw slice of ranges
            // and binary searching for our base address. Rust's builtin binary search
            // will fail to find the value since it uses strict equality *but* the Err
            // will helpfully contain the index in the slice where our value "should"
            // be inserted to preserve the sort. The element before this index is
            // therefore the nearest previous value!
            //
            // Case analysis for this -1 because binary search is an off-by-one minefield:
            //
            // * if the address we were looking for came *before* every FUNC, binary_search
            //   would yield "0" because that's where it should go to preserve the sort.
            //   The checked_sub will then fail and make us just assume the PUBLIC is reasonable,
            //   which is correct.
            //
            // * if we get 1, this saying we actually want element 0, so again -1 is
            //   correct. (This generalizes to all other "reasonable" values, but 1 is easiest
            //   to think about given the previous case's analysis.)
            //
            // * if the address we were looking for came *after* every FUNC, binary search
            //   would yield "slice.len()", and the nearest FUNC is indeed at `len-1`, so
            //   again correct.
            let funcs_slice = self.functions.ranges_values().as_slice();
            let prev_func = funcs_slice
                .binary_search_by_key(&addr, |(range, _)| range.start)
                .err()
                .and_then(|idx| idx.checked_sub(1))
                .and_then(|idx| funcs_slice.get(idx));

            if let Some(prev_func) = prev_func {
                if public.address <= prev_func.1.address {
                    // This PUBLIC is truncated by a FUNC before it gets to `addr`,
                    // so we shouldn't use it.
                    return;
                }
            }

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
    fn test_symbolfile_from_file(rel_path: &str) {
        let mut path = std::env::current_dir().unwrap();
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
