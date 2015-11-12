// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

#[macro_use]
extern crate nom;
extern crate range_map;
#[cfg(test)]
extern crate tempdir;

mod sym_file;

use std::borrow::Cow;
use std::boxed::Box;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
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
pub struct SimpleModule {
    pub base_address : Option<u64>,
    pub size : Option<u64>,
    pub code_file : Option<String>,
    pub code_identifier : Option<String>,
    pub debug_file : Option<String>,
    pub debug_id : Option<String>,
    pub version : Option<String>,
}

impl SimpleModule {
    /// Create a `SimpleModule` with the given `debug_file` and `debug_id`.
    ///
    /// Uses `default` for the remaining fields.
    pub fn new(debug_file : &str, debug_id : &str) -> SimpleModule {
        SimpleModule {
            debug_file: Some(String::from(debug_file)),
            debug_id: Some(String::from(debug_id)),
            ..SimpleModule::default()
        }
    }
}

impl Module for SimpleModule {
    fn base_address(&self) -> u64 { self.base_address.unwrap_or(0) }
    fn size(&self) -> u64 { self.size.unwrap_or(0) }
    fn code_file(&self) -> Cow<str> {
        self.code_file.as_ref().map_or(Cow::from(""), |s| Cow::Borrowed(&s[..]))
    }
    fn code_identifier(&self) -> Cow<str> {
        self.code_identifier.as_ref().map_or(Cow::from(""),
                                             |s| Cow::Borrowed(&s[..]))
    }
    fn debug_file(&self) -> Option<Cow<str>> {
        self.debug_file.as_ref().map(|s| Cow::Borrowed(&s[..]))
    }
    fn debug_identifier(&self) -> Option<Cow<str>> {
        self.debug_id.as_ref().map(|s| Cow::Borrowed(&s[..]))
    }
    fn version(&self) -> Option<Cow<str>> {
        self.version.as_ref().map(|s| Cow::Borrowed(&s[..]))
    }
}

/// Like `PathBuf::file_name`, but try to work on Windows or POSIX-style paths.
fn leafname(path : &str) -> &str {
    path.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(path)
}

/// If `filename` ends with `match_extension`, remove it. Append `new_extension` to the result.
fn replace_or_add_extension(filename : &str,
                            match_extension : &str,
                            new_extension : &str) -> String {
    let mut bits = filename.split('.').collect::<Vec<_>>();
    if bits.len() > 1 && bits.last().map_or(false, |e| e.to_lowercase() == match_extension) {
        bits.pop();
    }
    bits.push(new_extension);
    bits.join(".")
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
            // Can't use PathBuf::file_name here, it doesn't handle
            // Windows file paths on non-Windows.
            let leaf = leafname(&debug_file);
            let filename = replace_or_add_extension(leaf, "pdb", extension);
            [leaf, &debug_id[..], &filename[..]].join("/")
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

/// Locate Breakpad text-format symbols in local disk paths.
pub struct SimpleSymbolSupplier {
    /// Local disk paths to search for symbols.
    paths : Vec<PathBuf>,
}

impl SimpleSymbolSupplier {
    pub fn new(paths : Vec<PathBuf>) -> SimpleSymbolSupplier {
        SimpleSymbolSupplier { paths : paths }
    }
}

impl SymbolSupplier for SimpleSymbolSupplier {
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

pub trait FrameSymbolizer {
    /// Get the program counter value for this frame.
    fn get_instruction(&self) -> u64;
    /// Set the name and base address of the function in which this frame is executing.
    fn set_function(&mut self, name : &str, base : u64);
    /// Set the source file and (1-based) line number this frame represents.
    fn set_source_file(&mut self, file : &str, line : u32, base : u64);
}

#[derive(Default)]
pub struct SimpleFrame {
    pub instruction : u64,
    pub function : Option<String>,
    pub function_base : Option<u64>,
    pub source_file : Option<String>,
    pub source_line : Option<u32>,
    pub source_line_base : Option<u64>,
}

impl SimpleFrame {
    pub fn with_instruction(instruction : u64) -> SimpleFrame {
        SimpleFrame {
            instruction: instruction,
            ..SimpleFrame::default()
        }
    }
}

impl FrameSymbolizer for SimpleFrame {
    fn get_instruction(&self) -> u64 { self.instruction }
    fn set_function(&mut self, name : &str, base : u64) {
        self.function = Some(String::from(name));
        self.function_base = Some(base);
    }
    fn set_source_file(&mut self, file : &str, line : u32, base : u64) {
        self.source_file = Some(String::from(file));
        self.source_line = Some(line);
        self.source_line_base = Some(base);
    }
}

// Can't make Module derive Hash, since then it can't be used as a trait
// object (because the hash method is generic), so this is a hacky workaround.
type ModuleKey = (String, String, Option<String>, Option<String>);

/// Helper for deriving a hash key from a `Module` for `Symbolizer`.
fn key(module : &Module) -> ModuleKey {
    (module.code_file().to_string(),
     module.code_identifier().to_string(),
     module.debug_file().map(|s| s.to_string()),
     module.debug_identifier().map(|s| s.to_string()))
}

/// Symbolicate stack frames.
pub struct Symbolizer {
    /// Symbol supplier for locating symbols.
    supplier : Box<SymbolSupplier + 'static>,
    /// Cache of symbol locating results.
    symbols : RefCell<HashMap<ModuleKey, SymbolResult>>,
    /// A place to store `SimpleModule`s so callers don't have to create them.
    local_modules : RefCell<HashMap<(String, String), SimpleModule>>,
}

impl Symbolizer {
    /// Create a `Symbolizer` that uses `supplier` to locate symbols.
    pub fn new<T: SymbolSupplier + 'static>(supplier : T) -> Symbolizer {
        Symbolizer {
            supplier: Box::new(supplier),
            symbols: RefCell::new(HashMap::new()),
            local_modules : RefCell::new(HashMap::new()),
        }
    }

    /// Helper method for non-minidump-using callers.
    ///
    /// Pass `debug_file` and `debug_id` describing a specific module,
    /// and `address`, a module-relative address, and get back
    /// a symbol in that module that covers that address, or `None`.
    pub fn get_symbol_at_address(&self,
                                 debug_file : &str,
                                 debug_id : &str,
                                 address : u64) -> Option<String> {
        let k = (debug_file.to_string(), debug_id.to_string());
        if !self.local_modules.borrow().contains_key(&k) {
            let module = SimpleModule::new(debug_file,
                                           debug_id);
            self.local_modules.borrow_mut().insert(k.clone(), module);
        }
        self.local_modules.borrow().get(&k).and_then(|ref module| {
            let mut frame = SimpleFrame::with_instruction(address);
            self.fill_symbol(*module, &mut frame);
            frame.function
        })
    }

    pub fn fill_symbol(&self,
                       module : &Module,
                       frame : &mut FrameSymbolizer) {
        let k = key(module);
        if !self.symbols.borrow().contains_key(&k) {
            self.symbols
                .borrow_mut()
                .insert(k.clone(),
                        self.supplier.locate_symbols(module));
        }
        if let Some(res) = self.symbols.borrow().get(&k) {
            match res {
                &SymbolResult::Ok(ref sym) => sym.fill_symbol(module, frame),
                _ => {},
            }
        }
    }
}

#[test]
fn test_leafname() {
    assert_eq!(leafname("c:\\foo\\bar\\test.pdb"), "test.pdb");
    assert_eq!(leafname("c:/foo/bar/test.pdb"), "test.pdb");
    assert_eq!(leafname("test.pdb"), "test.pdb");
    assert_eq!(leafname("test"), "test");
    assert_eq!(leafname("/path/to/test"), "test");
}

#[test]
fn test_replace_or_add_extension() {
    assert_eq!(replace_or_add_extension("test.pdb", "pdb", "sym"), "test.sym");
    assert_eq!(replace_or_add_extension("TEST.PDB", "pdb", "sym"), "TEST.sym");
    assert_eq!(replace_or_add_extension("test", "pdb", "sym"), "test.sym");
    assert_eq!(replace_or_add_extension("test.x", "pdb", "sym"), "test.x.sym");
    assert_eq!(replace_or_add_extension("", "pdb", "sym"), ".sym");
    assert_eq!(replace_or_add_extension("test.x", "x", "y"), "test.y");
}

#[cfg(test)]
mod test {

use super::*;
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

    let bad2 = SimpleModule { debug_file: Some("foo".to_string()),
                              ..SimpleModule::default() };
    assert!(relative_symbol_path(&bad2, "sym").is_none());

    let bad3 = SimpleModule { debug_id: Some("foo".to_string()),
                              ..SimpleModule::default() };
    assert!(relative_symbol_path(&bad3, "sym").is_none());
}

#[test]
fn test_relative_symbol_path_abs_paths() {
    {
        let m = SimpleModule::new("/path/to/foo.bin", "abcd1234");
        assert_eq!(&relative_symbol_path(&m, "sym").unwrap(),
                   "foo.bin/abcd1234/foo.bin.sym");
    }

    {
        let m = SimpleModule::new("c:/path/to/foo.pdb", "abcd1234");
        assert_eq!(&relative_symbol_path(&m, "sym").unwrap(),
                   "foo.pdb/abcd1234/foo.sym");
    }

    {
        let m = SimpleModule::new("c:\\path\\to\\foo.pdb", "abcd1234");
        assert_eq!(&relative_symbol_path(&m, "sym").unwrap(),
                   "foo.pdb/abcd1234/foo.sym");
    }
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
fn test_simple_symbol_supplier() {
    let t = TempDir::new("symtest").unwrap();
    let paths = mksubdirs(t.path(), &["one", "two"]);

    let supplier = SimpleSymbolSupplier::new(paths.clone());
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

#[test]
fn test_symbolizer() {
    let t = TempDir::new("symtest").unwrap();
    let path = t.path();

    // TODO: This could really use a MockSupplier
    let supplier = SimpleSymbolSupplier::new(vec!(PathBuf::from(path)));
    let symbolizer = Symbolizer::new(supplier);
    let m1 = SimpleModule::new("foo.pdb", "abcd1234");
    write_symbol_file(&path.join("foo.pdb/abcd1234/foo.sym"),
                      b"MODULE Linux x86 abcd1234 foo
FILE 1 foo.c
FUNC 1000 30 10 some func
1000 30 100 1
");
    let mut f1 = SimpleFrame::with_instruction(0x1010);
    symbolizer.fill_symbol(&m1, &mut f1);
    assert_eq!(f1.function.unwrap(), "some func");
    assert_eq!(f1.function_base.unwrap(), 0x1000);
    assert_eq!(f1.source_file.unwrap(), "foo.c");
    assert_eq!(f1.source_line.unwrap(), 100);
    assert_eq!(f1.source_line_base.unwrap(), 0x1000);

    assert_eq!(symbolizer.get_symbol_at_address("foo.pdb", "abcd1234", 0x1010)
               .unwrap(),
               "some func");

    let m2 = SimpleModule::new("bar.pdb", "ffff0000");
    let mut f2 = SimpleFrame::with_instruction(0x1010);
    // No symbols present, should not find anything.
    symbolizer.fill_symbol(&m2, &mut f2);
    assert!(f2.function.is_none());
    assert!(f2.function_base.is_none());
    assert!(f2.source_file.is_none());
    assert!(f2.source_line.is_none());
    // Results should be cached.
    write_symbol_file(&path.join("bar.pdb/ffff0000/bar.sym"),
                      b"MODULE Linux x86 ffff0000 bar
FILE 53 bar.c
FUNC 1000 30 10 another func
1000 30 7 53
");
    symbolizer.fill_symbol(&m2, &mut f2);
    assert!(f2.function.is_none());
    assert!(f2.function_base.is_none());
    assert!(f2.source_file.is_none());
    assert!(f2.source_line.is_none());
    // This should also use cached results.
    assert!(symbolizer.get_symbol_at_address("bar.pdb", "ffff0000", 0x1010)
            .is_none());
}

}
