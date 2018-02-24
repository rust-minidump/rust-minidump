// Copyright 2016 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use encoding::all::UTF_16LE;
use encoding::{EncoderTrap, Encoding};
use minidump_common::format as md;
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
    module_list: Option<List<Module>>,
    /// List of memory regions in this minidump.
    memory_list: Option<List<Section>>,
}

/// A block of data contained in a minidump.
pub trait DumpSection: Into<Section> {
    /// A label representing this `DumpSection`'s offset in bytes from the start of the minidump.
    fn file_offset(&self) -> Label;
    /// A label representing this `DumpSection`'s size in bytes within the minidump.
    fn file_size(&self) -> Label;
}

trait CiteLocation {
    /// Append an `MDLocationDescriptor` to `section` referring to this section.
    fn cite_location_in(&self, section: Section) -> Section;
}

impl<T: DumpSection> CiteLocation for T {
    fn cite_location_in(&self, section: Section) -> Section {
        // An MDLocationDescriptor is just a 32-bit size + 32-bit offset.
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
        match self {
            &Some(ref inner) => inner.cite_location_in(section),
            &None => section.D32(0).D32(0),
        }
    }
}

/// A minidump stream.
pub trait Stream: DumpSection {
    /// The stream type, used in the stream directory.
    fn stream_type(&self) -> u32;
    /// Append an `MDRawDirectory` referring to this stream to `section`.
    fn cite_stream_in(&self, section: Section) -> Section {
        let section = section.D32(self.stream_type());
        self.cite_location_in(section)
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
            .D32(md::MD_HEADER_SIGNATURE)
            .D32(md::MD_HEADER_VERSION)
            .D32(&stream_count_label)
            .D32(&stream_directory_rva)
            .D32(0)
            .D32(1262805309) // date_time_stamp, arbitrary
            .D64(&flags);
        section.start().set_const(0);
        assert_eq!(section.size(), mem::size_of::<md::MDRawHeader>() as u64);

        SynthMinidump {
            section: section,
            flags: flags,
            stream_count: 0,
            stream_count_label: stream_count_label,
            stream_directory_rva: stream_directory_rva,
            stream_directory: Section::with_endian(endian),
            module_list: Some(List::new(md::MD_MODULE_LIST_STREAM, endian)),
            memory_list: Some(List::new(md::MD_MEMORY_LIST_STREAM, endian)),
        }
    }

    /// Set the minidump flags to `flags`.
    pub fn flags(self, flags: u64) -> SynthMinidump {
        self.flags.set_const(flags);
        self
    }

    /// Append `section` to `self`, setting its location appropriately.
    pub fn add<T: DumpSection>(mut self, section: T) -> SynthMinidump {
        let offset = section.file_offset();
        self.section = self.section.mark(&offset).append_section(section);
        self
    }

    /// Add `module` to `self`, adding it to the module list stream as well.
    pub fn add_module(mut self, module: Module) -> SynthMinidump {
        self.module_list = self.module_list
            .take()
            .map(|module_list| module_list.add(module));
        self
    }

    /// Add `memory` to `self`, adding it to the memory list stream as well.
    pub fn add_memory(mut self, memory: Memory) -> SynthMinidump {
        // The memory list contains `MDMemoryDescriptor`s, so create one here.
        let descriptor = memory.cite_memory_in(Section::with_endian(self.section.endian));
        // And append that descriptor to the memory list.
        self.memory_list = self.memory_list
            .take()
            .map(|memory_list| memory_list.add(descriptor));
        // Add the memory region itself.
        self.add(memory)
    }

    /// Append `stream` to `self`, setting its location appropriately and adding it to the stream directory.
    pub fn add_stream<T: Stream>(mut self, stream: T) -> SynthMinidump {
        self.stream_directory = stream.cite_stream_in(self.stream_directory);
        self.stream_count += 1;
        self.add(stream)
    }

    /// Finish generating the minidump and return the contents.
    pub fn finish(self) -> Option<Vec<u8>> {
        let mut this = self;
        // Add module list stream if any modules were added.
        let mut this = match this.module_list.take() {
            Some(module_list) => if !module_list.empty() {
                this.add_stream(module_list)
            } else {
                this
            },
            _ => this,
        };
        // Add memory list stream if any memory regions were added.
        let this = match this.memory_list.take() {
            Some(memory_list) => if !memory_list.empty() {
                this.add_stream(memory_list)
            } else {
                this
            },
            _ => this,
        };
        let SynthMinidump {
            section,
            flags,
            stream_count,
            stream_count_label,
            stream_directory_rva,
            stream_directory,
            ..
        } = this;
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

impl Into<Section> for SimpleStream {
    fn into(self) -> Section {
        self.section
    }
}

impl_dumpsection!(SimpleStream);

impl Stream for SimpleStream {
    fn stream_type(&self) -> u32 {
        self.stream_type
    }
}

/// A stream containing a list of dump entries.
pub struct List<T: DumpSection> {
    /// The stream type.
    stream_type: u32,
    /// The stream's contents.
    section: Section,
    /// The number of entries.
    count: u32,
    /// The number of entries, as a `Label`.
    count_label: Label,
    _type: PhantomData<T>,
}

impl<T: DumpSection> List<T> {
    pub fn new(stream_type: u32, endian: Endian) -> List<T> {
        let count_label = Label::new();
        List {
            stream_type: stream_type,
            section: Section::with_endian(endian).D32(&count_label),
            count_label: count_label,
            count: 0,
            _type: PhantomData,
        }
    }

    pub fn add(mut self, entry: T) -> List<T> {
        self.count += 1;
        self.section = self.section
            .mark(&entry.file_offset())
            .append_section(entry);
        self
    }

    pub fn empty(&self) -> bool {
        self.count == 0
    }
}

impl<T: DumpSection> Into<Section> for List<T> {
    fn into(self) -> Section {
        // Finalize the entry count.
        self.count_label.set_const(self.count as u64);
        self.section
    }
}

impl<T: DumpSection> DumpSection for List<T> {
    fn file_offset(&self) -> Label {
        self.section.file_offset()
    }
    fn file_size(&self) -> Label {
        self.section.file_size()
    }
}

impl<T: DumpSection> Stream for List<T> {
    fn stream_type(&self) -> u32 {
        self.stream_type
    }
}

/// An `MDString`, a UTF-16 string preceded by a 4-byte length.
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
        DumpString { section: section }
    }
}

impl Into<Section> for DumpString {
    fn into(self) -> Section {
        self.section
    }
}

impl_dumpsection!(DumpString);

/// A fixed set of version info to use for tests.
pub const STOCK_VERSION_INFO: md::MDVSFixedFileInfo = md::MDVSFixedFileInfo {
    signature: md::MD_VSFIXEDFILEINFO_SIGNATURE,
    struct_version: md::MD_VSFIXEDFILEINFO_VERSION,
    file_version_hi: 0x11111111,
    file_version_lo: 0x22222222,
    product_version_hi: 0x33333333,
    product_version_lo: 0x44444444,
    file_flags_mask: md::MD_VSFIXEDFILEINFO_FILE_FLAGS_DEBUG,
    file_flags: md::MD_VSFIXEDFILEINFO_FILE_FLAGS_DEBUG,
    file_os: md::MD_VSFIXEDFILEINFO_FILE_OS_NT | md::MD_VSFIXEDFILEINFO_FILE_OS__WINDOWS32,
    file_type: md::MD_VSFIXEDFILEINFO_FILE_TYPE_APP,
    file_subtype: md::MD_VSFIXEDFILEINFO_FILE_SUBTYPE_UNKNOWN,
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
    pub fn new<'a, T: Into<Option<&'a md::MDVSFixedFileInfo>>>(
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
            section: section,
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

impl Into<Section> for Module {
    fn into(self) -> Section {
        let Module {
            section,
            cv_record,
            misc_record,
        } = self;
        let section = cv_record.cite_location_in(section);
        let section = misc_record.cite_location_in(section);
        section
            // reserved0
            .D64(0)
            // reserved1
            .D64(0)
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
        Memory {
            section: section,
            address: address,
        }
    }

    // Append an `MDMemoryDescriptor` referring to this memory range to `section`.
    pub fn cite_memory_in(&self, section: Section) -> Section {
        let section = section.D64(self.address);
        self.cite_location_in(section)
    }
}

impl_dumpsection!(Memory);

impl Into<Section> for Memory {
    fn into(self) -> Section {
        self.section
    }
}

/// MDRawMiscInfo stream.
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

impl Into<Section> for MiscStream {
    fn into(self) -> Section {
        let MiscStream {
            section,
            process_id,
            process_create_time,
            pad_to_size,
        } = self;
        let flags_label = Label::new();
        let section = section.D32(&flags_label);
        let mut flags = 0;
        let section = section.D32(if let Some(pid) = process_id {
            flags = flags | md::MD_MISCINFO_FLAGS1_PROCESS_ID;
            pid
        } else {
            0
        });
        let section = if let Some(time) = process_create_time {
            flags = flags | md::MD_MISCINFO_FLAGS1_PROCESS_TIMES;
            section.D32(time)
                // user_time
                .D32(0)
                // kernel_time
                .D32(0)
        } else {
            section.D32(0).D32(0).D32(0)
        };
        flags_label.set_const(flags as u64);
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
        md::MD_MISC_INFO_STREAM
    }
}

#[test]
fn test_dump_header() {
    let dump = SynthMinidump::with_endian(Endian::Little).flags(0x9f738b33685cc84c);
    assert_eq!(
        dump.finish().unwrap(),
        vec![0x4d, 0x44, 0x4d, 0x50, // signature
                    0x93, 0xa7, 0x00, 0x00, // version
                    0, 0, 0, 0,             // stream count
                    0x20, 0, 0, 0,          // directory RVA
                    0, 0, 0, 0,             // checksum
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
        vec![0x50, 0x4d, 0x44, 0x4d, // signature
                    0x00, 0x00, 0xa7, 0x93, // version
                    0, 0, 0, 0,             // stream count
                    0, 0, 0, 0x20,          // directory RVA
                    0, 0, 0, 0,             // checksum
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
        &contents[mem::size_of::<md::MDRawHeader>()..],
        &[0xa, 0x0, 0x0, 0x0, // length
                 b'h', 0x0, b'e', 0x0, b'l', 0x0, b'l', 0x0, b'o', 0x0]
    );
}

#[test]
fn test_list() {
    // Empty list
    let list = List::<DumpString>::new(0x11223344, Endian::Little);
    assert_eq!(
        Into::<Section>::into(list).get_contents().unwrap(),
        vec![0, 0, 0, 0]
    );
    let list = List::new(0x11223344, Endian::Little)
        .add(DumpString::new("a", Endian::Little))
        .add(DumpString::new("b", Endian::Little));
    assert_eq!(
        Into::<Section>::into(list).get_contents().unwrap(),
        vec![2, 0, 0, 0, // entry count
                    // first entry
                    0x2, 0x0, 0x0, 0x0, // length
                    b'a', 0x0,
                    // second entry
                    0x2, 0x0, 0x0, 0x0, // length
                    b'b', 0x0]
    );
}

#[test]
fn test_simple_stream() {
    let section = Section::with_endian(Endian::Little).D32(0x55667788);
    let stream_rva = mem::size_of::<md::MDRawHeader>() as u8;
    let directory_rva = stream_rva + section.size() as u8;
    let dump = SynthMinidump::with_endian(Endian::Little)
        .flags(0x9f738b33685cc84c)
        .add_stream(SimpleStream {
            stream_type: 0x11223344,
            section: section,
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
    let stream_rva = mem::size_of::<md::MDRawHeader>() as u8;
    let directory_rva = stream_rva + section.size() as u8;
    let dump = SynthMinidump::with_endian(Endian::Big)
        .flags(0x9f738b33685cc84c)
        .add_stream(SimpleStream {
            stream_type: 0x11223344,
            section: section,
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
