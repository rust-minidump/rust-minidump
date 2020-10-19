// Copyright 2016 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

// Some test_assembler types do not have Debug, so be a bit more lenient here.
#![allow(missing_debug_implementations)]

use encoding::all::UTF_16LE;
use encoding::{EncoderTrap, Encoding};
use minidump_common::format as md;
use scroll::ctx::SizeWith;
use scroll::LE;
use std::marker::PhantomData;
use std::mem;
use test_assembler::*;

/// A writer of synthetic minidumps.
pub struct SynthMinidump {
    /// The `Section` containing the minidump contents.
    section: Section,
    /// The minidump flags, for the header.
    flags: Label,
    /// The number of streams.
    stream_count: u32,
    /// The number of streams, as a label for the header.
    stream_count_label: Label,
    /// The directory's file offset, for the header.
    stream_directory_rva: Label,
    /// The contents of the stream directory.
    stream_directory: Section,
    /// List of modules in this minidump.
    module_list: Option<ListStream<Module>>,
    /// List of threads in this minidump.
    thread_list: Option<ListStream<Thread>>,
    /// List of memory regions in this minidump.
    memory_list: Option<ListStream<Section>>,
    /// Crashpad extension containing annotations.
    crashpad_info: Option<CrashpadInfo>,
}

/// A block of data contained in a minidump.
pub trait DumpSection {
    /// A label representing this `DumpSection`'s offset in bytes from the start of the minidump.
    fn file_offset(&self) -> Label;

    /// A label representing this `DumpSection`'s size in bytes within the minidump.
    fn file_size(&self) -> Label;
}

/// A list item with optional out-of-band data.
///
/// Items can be added to [`List`]. The main sections returned from [`ListItem::into_sections`] are
/// stored in a compact list, followed by all out-of-band data in implementation-defined order.
///
/// For convenience, `ListItem` is implemented for every type that implements `Into<Section>`, so
/// that it can be used directly for types that do not require out-of-band data. Prefer to implement
/// `Into<Section>` unless out-of-band data is explicitly required.
pub trait ListItem: DumpSection {
    /// Returns a pair of sections for in-band and out-of-band data.
    fn into_sections(self) -> (Section, Option<Section>);
}

impl<T> ListItem for T
where
    T: Into<Section> + DumpSection,
{
    fn into_sections(self) -> (Section, Option<Section>) {
        (self.into(), None)
    }
}

pub trait CiteLocation {
    /// Append an `MINIDUMP_LOCATION_DESCRIPTOR` to `section` referring to this section.
    fn cite_location_in(&self, section: Section) -> Section;
}

impl<T: DumpSection> CiteLocation for T {
    fn cite_location_in(&self, section: Section) -> Section {
        // An MINIDUMP_LOCATION_DESCRIPTOR is just a 32-bit size + 32-bit offset.
        section.D32(&self.file_size()).D32(&self.file_offset())
    }
}

impl CiteLocation for (Label, Label) {
    fn cite_location_in(&self, section: Section) -> Section {
        section.D32(&self.0).D32(&self.1)
    }
}

impl<T: CiteLocation> CiteLocation for Option<T> {
    fn cite_location_in(&self, section: Section) -> Section {
        match *self {
            Some(ref inner) => inner.cite_location_in(section),
            None => section.D32(0).D32(0),
        }
    }
}

/// Additional methods to make working with `Section`s simpler
pub trait SectionExtra {
    /// A chainable version of `CiteLocation::cite_location_in`
    fn cite_location<T: CiteLocation>(self, thing: &T) -> Self;
    /// A chainable version of `Memory::cite_memory_in`
    fn cite_memory(self, memory: &Memory) -> Self;
}

impl SectionExtra for Section {
    fn cite_location<T: CiteLocation>(self, thing: &T) -> Self {
        thing.cite_location_in(self)
    }
    fn cite_memory(self, memory: &Memory) -> Self {
        memory.cite_memory_in(self)
    }
}

/// A minidump stream.
pub trait Stream: DumpSection + Into<Section> {
    /// The stream type, used in the stream directory.
    fn stream_type(&self) -> u32;
    /// Append an `MDRawDirectory` referring to this stream to `section`.
    fn cite_stream_in(&self, section: Section) -> Section {
        section.D32(self.stream_type()).cite_location(self)
    }
}

impl SynthMinidump {
    /// Create a `SynthMinidump` with default endianness.
    pub fn new() -> SynthMinidump {
        SynthMinidump::with_endian(DEFAULT_ENDIAN)
    }

    /// Create a `SynthMinidump` with `endian` endianness.
    pub fn with_endian(endian: Endian) -> SynthMinidump {
        let flags = Label::new();
        let stream_count_label = Label::new();
        let stream_directory_rva = Label::new();
        let section = Section::with_endian(endian)
            .D32(md::MINIDUMP_SIGNATURE)
            .D32(md::MINIDUMP_VERSION)
            .D32(&stream_count_label)
            .D32(&stream_directory_rva)
            .D32(0)
            .D32(1262805309) // date_time_stamp, arbitrary
            .D64(&flags);
        section.start().set_const(0);
        assert_eq!(section.size(), mem::size_of::<md::MINIDUMP_HEADER>() as u64);

        SynthMinidump {
            section,
            flags,
            stream_count: 0,
            stream_count_label,
            stream_directory_rva,
            stream_directory: Section::with_endian(endian),
            module_list: Some(ListStream::new(
                md::MINIDUMP_STREAM_TYPE::ModuleListStream,
                endian,
            )),
            thread_list: Some(ListStream::new(
                md::MINIDUMP_STREAM_TYPE::ThreadListStream,
                endian,
            )),
            memory_list: Some(ListStream::new(
                md::MINIDUMP_STREAM_TYPE::MemoryListStream,
                endian,
            )),
            crashpad_info: None,
        }
    }

    /// Set the minidump flags to `flags`.
    pub fn flags(self, flags: u64) -> SynthMinidump {
        self.flags.set_const(flags);
        self
    }

    /// Append `section` to `self`, setting its location appropriately.
    // Perhaps should have been called .add_section().
    #[allow(clippy::should_implement_trait)]
    pub fn add<T>(mut self, section: T) -> SynthMinidump
    where
        T: DumpSection + Into<Section>,
    {
        let offset = section.file_offset();
        self.section = self.section.mark(&offset).append_section(section);
        self
    }

    /// Add `module` to `self`, adding it to the module list stream as well.
    pub fn add_module(mut self, module: Module) -> SynthMinidump {
        self.module_list = self
            .module_list
            .take()
            .map(|module_list| module_list.add(module));
        self
    }

    /// Add `memory` to `self`, adding it to the memory list stream as well.
    pub fn add_memory(mut self, memory: Memory) -> SynthMinidump {
        // The memory list contains `MINIDUMP_MEMORY_DESCRIPTOR`s, so create one here.
        let descriptor = memory.cite_memory_in(Section::with_endian(self.section.endian));
        // And append that descriptor to the memory list.
        self.memory_list = self
            .memory_list
            .take()
            .map(|memory_list| memory_list.add(descriptor));
        // Add the memory region itself.
        self.add(memory)
    }

    /// Add `thread` to `self`, adding it to the thread list stream as well.
    pub fn add_thread(mut self, thread: Thread) -> SynthMinidump {
        self.thread_list = self
            .thread_list
            .take()
            .map(|thread_list| thread_list.add(thread));
        self
    }

    /// Add crashpad module and annotation extension information.
    pub fn add_crashpad_info(mut self, crashpad_info: CrashpadInfo) -> Self {
        self.crashpad_info = Some(crashpad_info);
        self
    }

    /// Append `stream` to `self`, setting its location appropriately and adding it to the stream directory.
    pub fn add_stream<T: Stream>(mut self, stream: T) -> SynthMinidump {
        self.stream_directory = stream.cite_stream_in(self.stream_directory);
        self.stream_count += 1;
        self.add(stream)
    }

    fn finish_list<T: ListItem>(self, list: Option<ListStream<T>>) -> SynthMinidump {
        match list {
            Some(l) => {
                if !l.is_empty() {
                    self.add_stream(l)
                } else {
                    self
                }
            }
            None => self,
        }
    }

    /// Finish generating the minidump and return the contents.
    pub fn finish(mut self) -> Option<Vec<u8>> {
        // Add module list stream if any modules were added.
        let modules = self.module_list.take();
        self = self.finish_list(modules);
        // Add memory list stream if any memory regions were added.
        let memories = self.memory_list.take();
        self = self.finish_list(memories);
        // Add thread list stream if any threads were added.
        let threads = self.thread_list.take();
        self = self.finish_list(threads);
        // Add crashpad info stream if any.
        if let Some(crashpad_info) = self.crashpad_info.take() {
            self = self.add_stream(crashpad_info);
        }

        let SynthMinidump {
            section,
            flags,
            stream_count,
            stream_count_label,
            stream_directory_rva,
            stream_directory,
            ..
        } = self;
        if flags.value().is_none() {
            flags.set_const(0);
        }
        // Create the stream directory.
        stream_count_label.set_const(stream_count as u64);
        section
            .mark(&stream_directory_rva)
            .append_section(stream_directory)
            .get_contents()
    }
}

impl Default for SynthMinidump {
    fn default() -> Self {
        Self::new()
    }
}

impl DumpSection for Section {
    fn file_offset(&self) -> Label {
        self.start()
    }

    fn file_size(&self) -> Label {
        self.final_size()
    }
}

macro_rules! impl_dumpsection {
    ( $x:ty ) => {
        impl DumpSection for $x {
            fn file_offset(&self) -> Label {
                self.section.file_offset()
            }
            fn file_size(&self) -> Label {
                self.section.file_size()
            }
        }
    };
}

/// A stream of arbitrary data.
pub struct SimpleStream {
    /// The stream type.
    pub stream_type: u32,
    /// The stream's contents.
    pub section: Section,
}

impl From<SimpleStream> for Section {
    fn from(stream: SimpleStream) -> Self {
        stream.section
    }
}

impl_dumpsection!(SimpleStream);

impl Stream for SimpleStream {
    fn stream_type(&self) -> u32 {
        self.stream_type
    }
}

/// A stream containing a list of dump entries.
pub struct List<T: ListItem> {
    /// The stream's contents.
    section: Section,
    /// The number of entries.
    count: u32,
    /// The number of entries, as a `Label`.
    count_label: Label,
    /// Out-of-band data referenced by this stream's contents.
    out_of_band: Section,
    _type: PhantomData<T>,
}

impl<T: ListItem> List<T> {
    pub fn new(endian: Endian) -> Self {
        let count_label = Label::new();
        List {
            section: Section::with_endian(endian).D32(&count_label),
            count_label,
            count: 0,
            out_of_band: Section::with_endian(endian),
            _type: PhantomData,
        }
    }

    // Possibly name this .add_section().
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, entry: T) -> Self {
        self.count += 1;

        let (section, out_of_band_opt) = entry.into_sections();

        self.section = self
            .section
            .mark(&section.file_offset())
            .append_section(section);

        if let Some(out_of_band) = out_of_band_opt {
            self.out_of_band = self
                .out_of_band
                .mark(&out_of_band.file_offset())
                .append_section(out_of_band);
        }

        self
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl<T: ListItem> From<List<T>> for Section {
    fn from(list: List<T>) -> Self {
        // Finalize the entry count.
        list.count_label.set_const(list.count as u64);

        // Serialize all (transitive) out-of-band data after the dense list of entry records.
        list.section
            .mark(&list.out_of_band.file_offset())
            .append_section(list.out_of_band)
    }
}

impl<T: ListItem> DumpSection for List<T> {
    fn file_offset(&self) -> Label {
        self.section.file_offset()
    }

    fn file_size(&self) -> Label {
        self.section.file_size()
    }
}

pub struct ListStream<T: ListItem> {
    /// The stream type.
    stream_type: u32,
    /// The list containing items.
    list: List<T>,
}

impl<T: ListItem> ListStream<T> {
    pub fn new<S: Into<u32>>(stream_type: S, endian: Endian) -> Self {
        Self {
            stream_type: stream_type.into(),
            list: List::new(endian),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, entry: T) -> Self {
        self.list = self.list.add(entry);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

impl<T: ListItem> From<ListStream<T>> for Section {
    fn from(stream: ListStream<T>) -> Self {
        stream.list.into()
    }
}

impl<T: ListItem> DumpSection for ListStream<T> {
    fn file_offset(&self) -> Label {
        self.list.file_offset()
    }

    fn file_size(&self) -> Label {
        self.list.file_size()
    }
}

impl<T: ListItem> Stream for ListStream<T> {
    fn stream_type(&self) -> u32 {
        self.stream_type
    }
}

/// An `MINIDUMP_STRING`, a UTF-16 string preceded by a 4-byte length.
pub struct DumpString {
    section: Section,
}

impl DumpString {
    /// Create a new `DumpString` with `s` as its contents, using `endian` endianness.
    pub fn new(s: &str, endian: Endian) -> DumpString {
        let u16_s = UTF_16LE.encode(s, EncoderTrap::Strict).unwrap();
        let section = Section::with_endian(endian)
            .D32(u16_s.len() as u32)
            .append_bytes(&u16_s);
        DumpString { section }
    }
}

impl From<DumpString> for Section {
    fn from(string: DumpString) -> Self {
        string.section
    }
}

impl_dumpsection!(DumpString);

pub struct DumpUtf8String {
    section: Section,
}

impl DumpUtf8String {
    pub fn new(s: &str, endian: Endian) -> Self {
        let section = Section::with_endian(endian)
            .D32(s.len() as u32)
            .append_bytes(s.as_bytes())
            .D8(0);

        Self { section }
    }
}

impl From<DumpUtf8String> for Section {
    fn from(string: DumpUtf8String) -> Self {
        string.section
    }
}

impl_dumpsection!(DumpUtf8String);

/// A fixed set of version info to use for tests.
pub const STOCK_VERSION_INFO: md::VS_FIXEDFILEINFO = md::VS_FIXEDFILEINFO {
    signature: md::VS_FFI_SIGNATURE as u32,
    struct_version: md::VS_FFI_STRUCVERSION as u32,
    file_version_hi: 0x11111111,
    file_version_lo: 0x22222222,
    product_version_hi: 0x33333333,
    product_version_lo: 0x44444444,
    file_flags_mask: 1,
    file_flags: 1,
    file_os: 0x40004,
    file_type: 1,
    file_subtype: 0,
    file_date_hi: 0,
    file_date_lo: 0,
};

/// A minidump module.
pub struct Module {
    section: Section,
    cv_record: Option<(Label, Label)>,
    misc_record: Option<(Label, Label)>,
}

impl Module {
    pub fn new<'a, T: Into<Option<&'a md::VS_FIXEDFILEINFO>>>(
        endian: Endian,
        base_of_image: u64,
        size_of_image: u32,
        name: &DumpString,
        time_date_stamp: u32,
        checksum: u32,
        version_info: T,
    ) -> Module {
        let stock_version = &STOCK_VERSION_INFO;
        let version_info = version_info.into().unwrap_or(stock_version);
        let section = Section::with_endian(endian)
            .D64(base_of_image)
            .D32(size_of_image)
            .D32(checksum)
            .D32(time_date_stamp)
            .D32(name.file_offset())
            .D32(version_info.signature)
            .D32(version_info.struct_version)
            .D32(version_info.file_version_hi)
            .D32(version_info.file_version_lo)
            .D32(version_info.product_version_hi)
            .D32(version_info.product_version_lo)
            .D32(version_info.file_flags_mask)
            .D32(version_info.file_flags)
            .D32(version_info.file_os)
            .D32(version_info.file_type)
            .D32(version_info.file_subtype)
            .D32(version_info.file_date_hi)
            .D32(version_info.file_date_lo);
        Module {
            section,
            cv_record: None,
            misc_record: None,
        }
    }

    pub fn cv_record<T: DumpSection>(mut self, cv_record: &T) -> Module {
        self.cv_record = Some((cv_record.file_size(), cv_record.file_offset()));
        self
    }

    pub fn misc_record<T: DumpSection>(mut self, misc_record: &T) -> Module {
        self.misc_record = Some((misc_record.file_size(), misc_record.file_offset()));
        self
    }
}

impl_dumpsection!(Module);

impl From<Module> for Section {
    fn from(module: Module) -> Self {
        let Module {
            section,
            cv_record,
            misc_record,
        } = module;
        section
            .cite_location(&cv_record)
            .cite_location(&misc_record)
            // reserved0
            .D64(0)
            // reserved1
            .D64(0)
    }
}

/// A minidump thread.
pub struct Thread {
    section: Section,
}

impl Thread {
    pub fn new<T>(endian: Endian, id: u32, stack: &Memory, context: &T) -> Thread
    where
        T: DumpSection,
    {
        let section = Section::with_endian(endian)
            .D32(id)
            .D32(0) // suspend_count
            .D32(0) // priority_class
            .D32(0) // priority
            .D64(0) // teb
            .cite_memory(stack)
            .cite_location(context);
        Thread { section }
    }
}

impl_dumpsection!(Thread);

impl From<Thread> for Section {
    fn from(thread: Thread) -> Self {
        thread.section
    }
}

/// A range of memory contents.
pub struct Memory {
    section: Section,
    pub address: u64,
}

impl Memory {
    /// Create a new `Memory` object representing memory starting at `address`,
    /// containing the contents of `section`.
    pub fn with_section(section: Section, address: u64) -> Memory {
        Memory { section, address }
    }

    // Append an `MINIDUMP_MEMORY_DESCRIPTOR` referring to this memory range to `section`.
    pub fn cite_memory_in(&self, section: Section) -> Section {
        section.D64(self.address).cite_location(self)
    }
}

impl_dumpsection!(Memory);

impl From<Memory> for Section {
    fn from(memory: Memory) -> Self {
        memory.section
    }
}

/// MINIDUMP_MISC_INFO stream.
pub struct MiscStream {
    /// The stream's contents.
    section: Section,
    pub process_id: Option<u32>,
    pub process_create_time: Option<u32>,
    pub pad_to_size: Option<usize>,
}

impl MiscStream {
    pub fn new(endian: Endian) -> MiscStream {
        let section = Section::with_endian(endian);
        let size = section.final_size();
        MiscStream {
            section: section.D32(size),
            process_id: None,
            process_create_time: None,
            pad_to_size: None,
        }
    }
}

impl From<MiscStream> for Section {
    fn from(stream: MiscStream) -> Self {
        let MiscStream {
            section,
            process_id,
            process_create_time,
            pad_to_size,
        } = stream;
        let flags_label = Label::new();
        let section = section.D32(&flags_label);
        let mut flags = md::MiscInfoFlags::empty();
        let section = section.D32(if let Some(pid) = process_id {
            flags |= md::MiscInfoFlags::MINIDUMP_MISC1_PROCESS_ID;
            pid
        } else {
            0
        });
        let section = if let Some(time) = process_create_time {
            flags |= md::MiscInfoFlags::MINIDUMP_MISC1_PROCESS_TIMES;
            section
                .D32(time)
                // user_time
                .D32(0)
                // kernel_time
                .D32(0)
        } else {
            section.D32(0).D32(0).D32(0)
        };
        flags_label.set_const(flags.bits() as u64);
        // Pad to final size, if necessary.
        if let Some(size) = pad_to_size {
            let size = (size as u64 - section.size()) as usize;
            section.append_repeated(0, size)
        } else {
            section
        }
    }
}

impl_dumpsection!(MiscStream);

impl Stream for MiscStream {
    fn stream_type(&self) -> u32 {
        md::MINIDUMP_STREAM_TYPE::MiscInfoStream as u32
    }
}

/// Populate a `CONTEXT_X86` struct with the given `endian`, `eip`, and `esp`.
pub fn x86_context(endian: Endian, eip: u32, esp: u32) -> Section {
    let section = Section::with_endian(endian)
        .D32(0x1007f) // context_flags: CONTEXT_ALL
        .append_repeated(0, 4 * 6) // dr0,1,2,3,6,7, 4 bytes each
        .append_repeated(0, md::FLOATING_SAVE_AREA_X86::size_with(&LE)) // float_save
        .append_repeated(0, 4 * 11) // gs-ebp, 4 bytes each
        .D32(eip)
        .D32(0) // cs
        .D32(0) // eflags
        .D32(esp)
        .D32(0) // ss
        .append_repeated(0, 512); // extended_registers
    assert_eq!(section.size(), md::CONTEXT_X86::size_with(&LE) as u64);
    section
}

/// Populate a `CONTEXT_AMD64` struct with the given `endian`, `rip`, and `rsp`.
pub fn amd64_context(endian: Endian, rip: u64, rsp: u64) -> Section {
    let section = Section::with_endian(endian)
        .append_repeated(0, mem::size_of::<u64>() * 6) // p[1-6]_home
        .D32(0x10001f) // context_flags: CONTEXT_ALL
        .D32(0) // mx_csr
        .append_repeated(0, mem::size_of::<u16>() * 6) // cs,ds,es,fs,gs,ss
        .D32(0) // eflags
        .append_repeated(0, mem::size_of::<u64>() * 6) // dr0,1,2,3,6,7
        .append_repeated(0, mem::size_of::<u64>() * 4) // rax,rcx,rdx,rbx
        .D64(rsp)
        .append_repeated(0, mem::size_of::<u64>() * 11) // rbp-r15
        .D64(rip)
        .append_repeated(0, 512) // float_save
        .append_repeated(0, mem::size_of::<u128>() * 26) // vector_register
        .append_repeated(0, mem::size_of::<u64>() * 6); // trailing stuff
    assert_eq!(section.size(), md::CONTEXT_AMD64::size_with(&LE) as u64);
    section
}

pub struct SectionRef {
    section: Section,
    data_section: Section,
}

impl SectionRef {
    pub fn new(data_section: impl Into<Section>, endian: Endian) -> Self {
        let data_section = data_section.into();
        let section = Section::with_endian(endian).D32(data_section.file_offset());
        Self {
            section,
            data_section,
        }
    }
}

impl_dumpsection!(SectionRef);

impl ListItem for SectionRef {
    fn into_sections(self) -> (Section, Option<Section>) {
        (self.section, Some(self.data_section))
    }
}

pub struct SimpleStringDictionaryEntry {
    endian: Endian,
    section: Section,
    key: DumpUtf8String,
    value: DumpUtf8String,
}

impl SimpleStringDictionaryEntry {
    pub fn new(key: &str, value: &str, endian: Endian) -> Self {
        Self {
            endian,
            section: Section::with_endian(endian),
            key: DumpUtf8String::new(key, endian),
            value: DumpUtf8String::new(value, endian),
        }
    }
}

impl_dumpsection!(SimpleStringDictionaryEntry);

impl ListItem for SimpleStringDictionaryEntry {
    fn into_sections(self) -> (Section, Option<Section>) {
        let section = self
            .section
            .D32(self.key.file_offset())
            .D32(self.value.file_offset());

        let out_of_band = Section::with_endian(self.endian)
            .mark(&self.key.file_offset())
            .append_section(self.key)
            .mark(&self.value.file_offset())
            .append_section(self.value);

        (section, Some(out_of_band))
    }
}

pub type SimpleStringDictionary = List<SimpleStringDictionaryEntry>;

#[derive(Clone, Debug)]
pub enum AnnotationValue {
    Invalid,
    String(String),
    Custom(u16, Vec<u8>),
}

pub struct AnnotationObject {
    section: Section,
    out_of_band: Section,
}

impl AnnotationObject {
    pub fn new(name: &str, value: AnnotationValue, endian: Endian) -> Self {
        let name = DumpUtf8String::new(name, endian);

        let (ty, value) = match value {
            AnnotationValue::Invalid => (md::MINIDUMP_ANNOTATION::TYPE_INVALID, None),
            AnnotationValue::String(s) => (
                md::MINIDUMP_ANNOTATION::TYPE_STRING,
                Some(DumpUtf8String::new(&s, endian).into()),
            ),
            AnnotationValue::Custom(ty, bytes) => (ty, Some(Section::new().append_bytes(&bytes))),
        };

        let mut section = Section::with_endian(endian)
            .D32(name.file_offset())
            .D16(ty)
            .D16(0); // reserved, always 0

        section = match value {
            Some(ref value) => section.D32(value.file_offset()),
            None => section.D32(0),
        };

        let mut out_of_band = Section::with_endian(endian)
            .mark(&name.file_offset())
            .append_section(name);

        if let Some(value) = value {
            out_of_band = out_of_band.mark(&value.file_offset()).append_section(value);
        }

        Self {
            section,
            out_of_band,
        }
    }
}

impl_dumpsection!(AnnotationObject);

impl ListItem for AnnotationObject {
    fn into_sections(self) -> (Section, Option<Section>) {
        (self.section, Some(self.out_of_band))
    }
}

pub type AnnotationObjects = List<AnnotationObject>;

/// Link + Info
pub struct ModuleCrashpadInfo {
    endian: Endian,
    section: Section,
    list_annotations: List<SectionRef>,
    simple_annotations: SimpleStringDictionary,
    annotation_objects: AnnotationObjects,
}

impl ModuleCrashpadInfo {
    pub fn new(index: u32, endian: Endian) -> Self {
        Self {
            endian,
            section: Section::with_endian(endian).D32(index),
            list_annotations: List::new(endian),
            simple_annotations: SimpleStringDictionary::new(endian),
            annotation_objects: AnnotationObjects::new(endian),
        }
    }

    pub fn add_list_annotation(mut self, value: &str) -> Self {
        let section = SectionRef::new(DumpUtf8String::new(value, self.endian), self.endian);
        self.list_annotations = self.list_annotations.add(section);
        self
    }

    pub fn add_simple_annotation(mut self, key: &str, value: &str) -> Self {
        let entry = SimpleStringDictionaryEntry::new(key, value, self.endian);
        self.simple_annotations = self.simple_annotations.add(entry);
        self
    }

    pub fn add_annotation_object(mut self, key: &str, value: AnnotationValue) -> Self {
        let object = AnnotationObject::new(key, value, self.endian);
        self.annotation_objects = self.annotation_objects.add(object);
        self
    }
}

impl_dumpsection!(ModuleCrashpadInfo);

impl ListItem for ModuleCrashpadInfo {
    fn into_sections(self) -> (Section, Option<Section>) {
        let info = Section::with_endian(self.endian)
            .D32(md::MINIDUMP_MODULE_CRASHPAD_INFO::VERSION)
            .cite_location(&self.list_annotations)
            .cite_location(&self.simple_annotations)
            .cite_location(&self.annotation_objects)
            .mark(&self.list_annotations.file_offset())
            .append_section(self.list_annotations)
            .mark(&self.simple_annotations.file_offset())
            .append_section(self.simple_annotations)
            .mark(&self.annotation_objects.file_offset())
            .append_section(self.annotation_objects);

        let link = self.section.cite_location(&info);

        (link, Some(info))
    }
}

pub type ModuleCrashpadInfoList = List<ModuleCrashpadInfo>;

pub struct Guid {
    section: Section,
}

impl Guid {
    pub fn new(guid: md::GUID, endian: Endian) -> Self {
        let section = Section::with_endian(endian)
            .D32(guid.data1)
            .D16(guid.data2)
            .D16(guid.data3)
            .append_bytes(&guid.data4);

        Self { section }
    }

    pub fn empty(endian: Endian) -> Self {
        let guid = md::GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0, 0, 0, 0, 0, 0, 0, 0],
        };

        Self::new(guid, endian)
    }
}

// Guid does not impl DumpSections as it cannot be cited.

impl From<Guid> for Section {
    fn from(guid: Guid) -> Self {
        guid.section
    }
}

pub struct CrashpadInfo {
    endian: Endian,
    section: Section,
    report_id: Guid,
    client_id: Guid,
    simple_annotations: SimpleStringDictionary,
    module_list: ModuleCrashpadInfoList,
}

impl CrashpadInfo {
    pub fn new(endian: Endian) -> Self {
        Self {
            endian,
            section: Section::with_endian(endian),
            report_id: Guid::empty(endian),
            client_id: Guid::empty(endian),
            simple_annotations: SimpleStringDictionary::new(endian),
            module_list: ModuleCrashpadInfoList::new(endian),
        }
    }

    pub fn report_id(mut self, report_id: md::GUID) -> Self {
        self.report_id = Guid::new(report_id, self.endian);
        self
    }

    pub fn client_id(mut self, client_id: md::GUID) -> Self {
        self.client_id = Guid::new(client_id, self.endian);
        self
    }

    pub fn add_simple_annotation(mut self, key: &str, value: &str) -> Self {
        let entry = SimpleStringDictionaryEntry::new(key, value, self.endian);
        self.simple_annotations = self.simple_annotations.add(entry);
        self
    }

    pub fn add_module(mut self, info: ModuleCrashpadInfo) -> Self {
        self.module_list = self.module_list.add(info);
        self
    }
}

impl_dumpsection!(CrashpadInfo);

impl From<CrashpadInfo> for Section {
    fn from(info: CrashpadInfo) -> Self {
        info.section
            .D32(md::MINIDUMP_CRASHPAD_INFO::VERSION)
            .append_section(info.report_id)
            .append_section(info.client_id)
            .cite_location(&info.simple_annotations)
            .cite_location(&info.module_list)
            .mark(&info.simple_annotations.file_offset())
            .append_section(info.simple_annotations)
            .mark(&info.module_list.file_offset())
            .append_section(info.module_list)
    }
}

impl Stream for CrashpadInfo {
    fn stream_type(&self) -> u32 {
        md::MINIDUMP_STREAM_TYPE::CrashpadInfoStream.into()
    }
}

#[test]
fn test_dump_header() {
    let dump = SynthMinidump::with_endian(Endian::Little).flags(0x9f738b33685cc84c);
    assert_eq!(
        dump.finish().unwrap(),
        vec![
            0x4d, 0x44, 0x4d, 0x50, // signature
            0x93, 0xa7, 0x00, 0x00, // version
            0, 0, 0, 0, // stream count
            0x20, 0, 0, 0, // directory RVA
            0, 0, 0, 0, // checksum
            0x3d, 0xe1, 0x44, 0x4b, // time_date_stamp
            0x4c, 0xc8, 0x5c, 0x68, // flags
            0x33, 0x8b, 0x73, 0x9f,
        ]
    );
}

#[test]
fn test_dump_header_bigendian() {
    let dump = SynthMinidump::with_endian(Endian::Big).flags(0x9f738b33685cc84c);
    assert_eq!(
        dump.finish().unwrap(),
        vec![
            0x50, 0x4d, 0x44, 0x4d, // signature
            0x00, 0x00, 0xa7, 0x93, // version
            0, 0, 0, 0, // stream count
            0, 0, 0, 0x20, // directory RVA
            0, 0, 0, 0, // checksum
            0x4b, 0x44, 0xe1, 0x3d, // time_date_stamp
            0x9f, 0x73, 0x8b, 0x33, // flags
            0x68, 0x5c, 0xc8, 0x4c,
        ]
    );
}

#[test]
fn test_section_cite() {
    let s1 = Section::with_endian(Endian::Little).append_repeated(0, 0x0a);
    s1.start().set_const(0xff00ee11);
    let s2 = Section::with_endian(Endian::Little);
    let s2 = s1.cite_location_in(s2);
    s1.get_contents().unwrap();
    assert_eq!(
        s2.get_contents().unwrap(),
        vec![0x0a, 0, 0, 0, 0x11, 0xee, 0x00, 0xff]
    );
}

#[test]
fn test_dump_string() {
    let dump = SynthMinidump::with_endian(Endian::Little);
    let s = DumpString::new("hello", Endian::Little);
    let contents = dump.add(s).finish().unwrap();
    // Skip over the header
    assert_eq!(
        &contents[mem::size_of::<md::MINIDUMP_HEADER>()..],
        &[
            0xa, 0x0, 0x0, 0x0, // length
            b'h', 0x0, b'e', 0x0, b'l', 0x0, b'l', 0x0, b'o', 0x0
        ]
    );
}

#[test]
fn test_list_out_of_band() {
    let list = List::<SectionRef>::new(Endian::Little);
    assert_eq!(
        Into::<Section>::into(list).get_contents().unwrap(),
        vec![0, 0, 0, 0]
    );

    let a = SectionRef::new(DumpUtf8String::new("foo", Endian::Little), Endian::Little);
    let b = SectionRef::new(DumpUtf8String::new("bar", Endian::Little), Endian::Little);
    let section: Section = List::new(Endian::Little).add(a).add(b).into();
    assert_eq!(
        section.set_start_const(0).get_contents().unwrap(),
        vec![
            2, 0, 0, 0, // entry count
            12, 0, 0, 0, // first RVA
            20, 0, 0, 0, // second RVA
            3, 0, 0, 0, // "foo".len()
            102, 111, 111, 0, // "foo\0"
            3, 0, 0, 0, // "bar".len()
            98, 97, 114, 0 // "bar\0"
        ]
    );
}

#[test]
fn test_list_stream() {
    // Empty list
    let list = ListStream::<DumpString>::new(0x11223344u32, Endian::Little);
    assert_eq!(
        Into::<Section>::into(list).get_contents().unwrap(),
        vec![0, 0, 0, 0]
    );
    let list = ListStream::new(0x11223344u32, Endian::Little)
        .add(DumpString::new("a", Endian::Little))
        .add(DumpString::new("b", Endian::Little));
    assert_eq!(
        Into::<Section>::into(list).get_contents().unwrap(),
        vec![
            2, 0, 0, 0, // entry count
            // first entry
            0x2, 0x0, 0x0, 0x0, // length
            b'a', 0x0, // second entry
            0x2, 0x0, 0x0, 0x0, // length
            b'b', 0x0
        ]
    );
}

#[test]
fn test_simple_stream() {
    let section = Section::with_endian(Endian::Little).D32(0x55667788);
    let stream_rva = mem::size_of::<md::MINIDUMP_HEADER>() as u8;
    let directory_rva = stream_rva + section.size() as u8;
    let dump = SynthMinidump::with_endian(Endian::Little)
        .flags(0x9f738b33685cc84c)
        .add_stream(SimpleStream {
            stream_type: 0x11223344,
            section,
        });
    assert_eq!(
        dump.finish().unwrap(),
        vec![
            0x4d,
            0x44,
            0x4d,
            0x50, // signature
            0x93,
            0xa7,
            0x00,
            0x00, // version
            1,
            0,
            0,
            0, // stream count
            directory_rva,
            0,
            0,
            0, // directory RVA
            0,
            0,
            0,
            0, // checksum
            0x3d,
            0xe1,
            0x44,
            0x4b, // time_date_stamp
            0x4c,
            0xc8,
            0x5c,
            0x68, // flags
            0x33,
            0x8b,
            0x73,
            0x9f,
            // Stream contents
            0x88,
            0x77,
            0x66,
            0x55,
            // Stream directory
            0x44,
            0x33,
            0x22,
            0x11, // stream type
            4,
            0,
            0,
            0, // size
            stream_rva,
            0,
            0,
            0, // rva
        ]
    );
}

#[test]
fn test_simple_stream_bigendian() {
    let section = Section::with_endian(Endian::Big).D32(0x55667788);
    let stream_rva = mem::size_of::<md::MINIDUMP_HEADER>() as u8;
    let directory_rva = stream_rva + section.size() as u8;
    let dump = SynthMinidump::with_endian(Endian::Big)
        .flags(0x9f738b33685cc84c)
        .add_stream(SimpleStream {
            stream_type: 0x11223344,
            section,
        });
    assert_eq!(
        dump.finish().unwrap(),
        vec![
            0x50,
            0x4d,
            0x44,
            0x4d, // signature
            0x00,
            0x00,
            0xa7,
            0x93, // version
            0,
            0,
            0,
            1, // stream count
            0,
            0,
            0,
            directory_rva, // directory RVA
            0,
            0,
            0,
            0, // checksum
            0x4b,
            0x44,
            0xe1,
            0x3d, // time_date_stamp
            0x9f,
            0x73,
            0x8b,
            0x33, // flags
            0x68,
            0x5c,
            0xc8,
            0x4c,
            // Stream contents
            0x55,
            0x66,
            0x77,
            0x88,
            // Stream directory
            0x11,
            0x22,
            0x33,
            0x44, // stream type
            0,
            0,
            0,
            4, // size
            0,
            0,
            0,
            stream_rva, // rva
        ]
    );
}
