use std::borrow::Cow;

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

/// Implement Module for 2-tuples of &str for convenience.
/// `breakpad-symbols`' `Symbolizer::get_symbol_at_address` uses this.
impl<'a> Module for (&'a str, &'a str) {
    fn base_address(&self) -> u64 { 0 }
    fn size(&self) -> u64 { 0 }
    fn code_file(&self) -> Cow<str> { Cow::Borrowed("") }
    fn code_identifier(&self) -> Cow<str> { Cow::Borrowed("") }
    fn debug_file(&self) -> Option<Cow<str>> {
        let &(ref file, ref _id) = self;
        Some(Cow::Borrowed(file))
    }
    fn debug_identifier(&self) -> Option<Cow<str>> {
        let &(ref _file, ref id) = self;
        Some(Cow::Borrowed(id))
    }
    fn version(&self) -> Option<Cow<str>> { None }
}
