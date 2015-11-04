// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

#[macro_use]
extern crate nom;
extern crate range_map;
#[cfg(test)]
extern crate tempdir;

mod sym_file;

use std::borrow::Cow;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
pub use sym_file::SymbolFile;

/// An executable or shared library loaded in a process.
pub trait Module {
    /// The base address of this code module as it was loaded by the process.
    fn base_address(&self) -> u64;
    /// The size of the code module.
    fn size(&self) -> u64;
    /// The path or file name that the code module was loaded from.
    fn code_file(&self) -> Cow<str>;
    /// An identifying string used to discriminate between multiple versions and
    /// builds of the same code module.  This may contain a uuid, timestamp,
    /// version number, or any combination of this or other information, in an
    /// implementation-defined format.
    fn code_identifier(&self) -> Cow<str>;
    /// The filename containing debugging information associated with the code
    /// module.  If debugging information is stored in a file separate from the
    /// code module itself (as is the case when .pdb or .dSYM files are used),
    /// this will be different from code_file.  If debugging information is
    /// stored in the code module itself (possibly prior to stripping), this
    /// will be the same as code_file.
    fn debug_file(&self) -> Option<Cow<str>>;
    /// An identifying string similar to code_identifier, but identifies a
    /// specific version and build of the associated debug file.  This may be
    /// the same as code_identifier when the debug_file and code_file are
    /// identical or when the same identifier is used to identify distinct
    /// debug and code files.
    fn debug_identifier(&self) -> Option<Cow<str>>;
    /// A human-readable representation of the code module's version.
    fn version(&self) -> Option<Cow<str>>;
}

/// A `Module` implementation that holds arbitrary data.
///
/// This can be useful for getting symbols for a module when you
/// have a debug id and filename but not an actual minidump.
#[derive(Default)]
pub struct SimpleModule<'a> {
    pub base_address : Option<u64>,
    pub size : Option<u64>,
    pub code_file : Option<Cow<'a, str>>,
    pub code_identifier : Option<Cow<'a, str>>,
    pub debug_file : Option<Cow<'a, str>>,
    pub debug_id : Option<Cow<'a, str>>,
    pub version : Option<Cow<'a, str>>,
}

impl<'a> SimpleModule<'a> {
    /// Create a `SimpleModule` with the given `debug_file` and `debug_id`.
    ///
    /// Uses `default` for the remaining fields.
    pub fn new(debug_file : &'a str, debug_id : &'a str) -> SimpleModule<'a> {
        SimpleModule {
            debug_file: Some(Cow::Borrowed(debug_file)),
            debug_id: Some(Cow::Borrowed(debug_id)),
            ..SimpleModule::default()
        }
    }
}

impl<'a> Module for SimpleModule<'a> {
    fn base_address(&self) -> u64 { self.base_address.unwrap_or(0) }
    fn size(&self) -> u64 { self.size.unwrap_or(0) }
    fn code_file(&self) -> Cow<str> {
        self.code_file.as_ref().map_or(Cow::from(""), |s| s.clone())
    }
    fn code_identifier(&self) -> Cow<str> {
        self.code_identifier.as_ref().map_or(Cow::from(""), |s| s.clone())
    }
    fn debug_file(&self) -> Option<Cow<str>> {
        self.debug_file.as_ref().map(|s| s.clone())
    }
    fn debug_identifier(&self) -> Option<Cow<str>> {
        self.debug_id.as_ref().map(|s| s.clone())
    }
    fn version(&self) -> Option<Cow<str>> {
        self.version.as_ref().map(|s| s.clone())
    }
}


/// Get a relative symbol path at which to locate symbols for `module`.
///
/// Symbols are generally stored in the layout used by Microsoft's symbol
/// server and associated tools:
/// `<debug filename>/<debug identifier>/<debug filename>.sym`. If
/// `debug filename` ends with *.pdb* the leaf filename will have that
/// removed.
/// `extension` is the expected extension for the symbol filename, generally
/// *sym* if Breakpad text format symbols are expected.
pub fn relative_symbol_path(module : &Module, extension : &str)
                            -> Option<String> {
    module.debug_file().and_then(|debug_file| {
        module.debug_identifier().map(|debug_id| {
            let mut path = PathBuf::from(debug_file.deref());
            // For files ending in .pdb, swap it for the extension.
            let filename = if path.extension().map_or(false, |e| e.to_string_lossy().to_lowercase() == "pdb") {
                path.set_extension(extension);
                path.to_string_lossy()
            } else {
                // Just tack on the extension.
                Cow::from([debug_file.deref(), extension].join("."))
            };
            [debug_file, debug_id, filename].join("/")
        })
    })
}

/// Possible results of locating symbols.
#[derive(Debug, PartialEq)]
pub enum SymbolResult {
    /// Symbols loaded successfully.
    Ok(SymbolFile),
    /// Symbol file could not be found.
    NotFound,
    /// Error loading symbol file.
    LoadError(&'static str),
}

/// Locate symbols for a given module.
pub trait SymbolSupplier {
    /// Locate and load a symbol file for `module`.
    fn locate_symbols(&self, module : &Module) -> SymbolResult;
}

/// Locate symbols in local disk paths.
pub struct LocalSymbolSupplier {
    /// Local disk paths to search for symbols.
    paths : Vec<PathBuf>,
}

impl LocalSymbolSupplier {
    pub fn new(paths : Vec<PathBuf>) -> LocalSymbolSupplier {
        LocalSymbolSupplier { paths : paths }
    }
}

impl SymbolSupplier for LocalSymbolSupplier {
    fn locate_symbols(&self, module : &Module) -> SymbolResult {
        if let Some(rel_path) = relative_symbol_path(module, "sym") {
            for ref path in self.paths.iter() {
                let test_path = path.join(&rel_path);
                if fs::metadata(&test_path).ok()
                    .map_or(false, |m| m.is_file()) {
                    return SymbolFile::from_file(&test_path)
                        .and_then(|s| Ok(SymbolResult::Ok(s)))
                        .unwrap_or_else(|e| SymbolResult::LoadError(e))
                }
            }
        }
        SymbolResult::NotFound
    }
}

#[cfg(test)]
mod test {

use super::*;
use std::borrow::Cow;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path,PathBuf};
use tempdir::TempDir;

#[test]
fn test_relative_symbol_path() {
    let m = SimpleModule::new("foo.pdb", "abcd1234");
    assert_eq!(&relative_symbol_path(&m, "sym").unwrap(),
               "foo.pdb/abcd1234/foo.sym");

    let m2 = SimpleModule::new("foo.pdb", "abcd1234");
    assert_eq!(&relative_symbol_path(&m2, "bar").unwrap(),
               "foo.pdb/abcd1234/foo.bar");

    let m3 = SimpleModule::new("foo.xyz", "abcd1234");
    assert_eq!(&relative_symbol_path(&m3, "sym").unwrap(),
               "foo.xyz/abcd1234/foo.xyz.sym");

    let m4 = SimpleModule::new("foo.xyz", "abcd1234");
    assert_eq!(&relative_symbol_path(&m4, "bar").unwrap(),
               "foo.xyz/abcd1234/foo.xyz.bar");

    let bad = SimpleModule::default();
    assert!(relative_symbol_path(&bad, "sym").is_none());

    let bad2 = SimpleModule { debug_file: Some(Cow::Borrowed("foo")),
                              ..SimpleModule::default() };
    assert!(relative_symbol_path(&bad2, "sym").is_none());

    let bad3 = SimpleModule { debug_id: Some(Cow::Borrowed("foo")),
                              ..SimpleModule::default() };
    assert!(relative_symbol_path(&bad3, "sym").is_none());
}

fn mksubdirs(path : &Path, dirs : &[&str]) -> Vec<PathBuf> {
    dirs.iter().map(|dir| {
        let new_path = path.join(dir);
        fs::create_dir(&new_path).unwrap();
        new_path
    }).collect()
}

fn write_symbol_file(path : &Path, contents : &[u8]) {
    let dir = path.parent().unwrap();
    if !fs::metadata(&dir).ok().map_or(false, |m| m.is_dir()) {
        fs::create_dir_all(&dir).unwrap();
    }
    let mut f = File::create(path).unwrap();
    f.write_all(contents).unwrap();
}

fn write_good_symbol_file(path : &Path) {
    write_symbol_file(path, b"MODULE Linux x86 abcd1234 foo\n");
}

fn write_bad_symbol_file(path : &Path) {
    write_symbol_file(path, b"this is not a symbol file\n");
}

#[test]
fn test_local_symbol_supplier() {
    let t = TempDir::new("symtest").unwrap();
    let paths = mksubdirs(t.path(), &["one", "two"]);

    let supplier = LocalSymbolSupplier::new(paths.clone());
    let bad = SimpleModule::default();
    assert_eq!(supplier.locate_symbols(&bad), SymbolResult::NotFound);

    // Try loading symbols for each of two modules in each of the two
    // search paths.
    for &(path, file, id, sym) in [(&paths[0], "foo.pdb", "abcd1234",
                                    "foo.pdb/abcd1234/foo.sym"),
                                   (&paths[1], "bar.xyz", "ff9900",
                                    "bar.xyz/ff9900/bar.xyz.sym")].iter() {
        let m = SimpleModule::new(file, id);
        // No symbols present yet.
        assert_eq!(supplier.locate_symbols(&m), SymbolResult::NotFound);
        write_good_symbol_file(&path.join(sym));
        // Should load OK now that it exists.
        assert!(if let SymbolResult::Ok(_) = supplier.locate_symbols(&m) {
            true
        } else {
            false
        }, format!("Located symbols for {}", sym));
    }

    // Write a malformed symbol file, verify that it's found but fails to load.
    let mal = SimpleModule::new("baz.pdb", "ffff0000");
    let sym = "baz.pdb/ffff0000/baz.sym";
    assert_eq!(supplier.locate_symbols(&mal), SymbolResult::NotFound);
    write_bad_symbol_file(&paths[0].join(sym));
    let res = supplier.locate_symbols(&mal);
    assert!(if let SymbolResult::LoadError(_) = res {
            true
    } else {
            false
    }, format!("Correctly failed to parse {}, result: {:?}", sym, res));
}

}
