use std::io::prelude::*;
use std::fs::File;
use std::io::SeekFrom;
use std::mem;
use std::ptr;
use std::collections::HashMap;

extern crate libc;
extern crate encoding;

use encoding::{Encoding, DecoderTrap};
use encoding::all::UTF_16LE;

pub mod minidump_format;
use minidump_format as fmt;

#[allow(dead_code)]
pub struct Minidump {
    file : File,
    header : fmt::MDRawHeader,
    streams : HashMap<u32, fmt::MDRawDirectory>,
    swap : bool,
}

#[derive(Debug)]
pub enum Error {
    MissingHeader,
    HeaderMismatch,
    SwapNotImplemented,
    VersionMismatch,
    MissingDirectory,
    StreamReadFailure,
    StreamSizeMismatch,
    StreamNotFound,
    ModuleReadFailure,
    DataError,
}

pub struct MinidumpThreadList;
pub struct MinidumpMemoryList;
pub struct MinidumpException;
pub struct MinidumpAssertion;
pub struct MinidumpSystemInfo;
pub struct MinidumpMiscInfo;
pub struct MinidumpBreakpadInfo;
pub struct MinidumpMemoryInfoList;

pub trait MinidumpStream {
    //TODO: associated_consts when that stabilizes.
    fn stream_type() -> u32;
    fn read(f : &File, expected_size : usize) -> Result<Self, Error>;
}

pub trait Module {
    fn base_address(&self) -> u64;
    fn size(&self) -> u64;
}

pub struct MinidumpModule {
    pub raw : fmt::MDRawModule,
    pub name : String,
}

pub struct MinidumpModuleList {
    pub modules : Vec<MinidumpModule>,
}

//======================================================
// Implementations

fn read<T : Copy>(mut f : &File) -> std::io::Result<T> {
    let size = mem::size_of::<T>();
    let mut buf = vec!(0; size);
    let bytes = &mut buf[..];
    try!(f.read(bytes));
    Ok(unsafe {
        let mut val : T = mem::uninitialized();
        ptr::copy(bytes.as_mut_ptr(), &mut val as *mut T as *mut u8, size);
        val
    })
}

fn read_string(mut f : &File, offset : u64) -> Result<String, Error> {
    try!(f.seek(SeekFrom::Start(offset)).or(Err(Error::DataError)));
    let size = try!(read::<u32>(f).or(Err(Error::DataError))) as usize;
    // TODO: swap
    if size % 2 != 0 {
        return Err(Error::DataError);
    }
    let mut buf = vec!(0; size);
    let bytes = &mut buf[..];
    try!(f.read(bytes).or(Err(Error::DataError)));
    UTF_16LE.decode(bytes, DecoderTrap::Strict).or(Err(Error::DataError))
}

impl MinidumpModule {
    pub fn read(f : &File, raw : fmt::MDRawModule) -> Result<MinidumpModule, Error> {
        let name = try!(read_string(f, raw.module_name_rva as u64));
        // TODO: read debug info
        Ok(MinidumpModule { raw: raw, name: name})
    }
}

impl Module for MinidumpModule {
    fn base_address(&self) -> u64 { self.raw.base_of_image }
    fn size(&self) -> u64 { self.raw.size_of_image as u64 }
}

impl MinidumpStream for MinidumpModuleList {
    fn stream_type() -> u32 { fmt::MD_MODULE_LIST_STREAM }
    fn read(f : &File, expected_size : usize) -> Result<MinidumpModuleList, Error> {
        if expected_size < mem::size_of::<u32>() {
            return Err(Error::StreamSizeMismatch);
        }
        // TODO: swap
        let count = try!(read::<u32>(&f).or(Err(Error::StreamReadFailure))) as usize;
        match expected_size - (mem::size_of::<u32>() + count * fmt::MD_MODULE_SIZE as usize) {
            0 => {},
            4 => {
                // 4 bytes of padding.
                try!(read::<u32>(&f).or(Err(Error::StreamReadFailure)));
            },
            _ => return Err(Error::StreamSizeMismatch)
        };
        // read count MDRawModule
        let mut raw_modules = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = try!(read::<fmt::MDRawModule>(f).or(Err(Error::ModuleReadFailure)));
            // TODO: swap
            if raw.size_of_image == 0 || raw.size_of_image as u64 > (u64::max_value() - raw.base_of_image) {
                // Bad image size.
                //println!("image {}: bad image size: {}", i, raw.size_of_image);
                // TODO: just drop this module, keep the rest?
                return Err(Error::ModuleReadFailure);
            }
            raw_modules.push(raw);
        }
        // read auxiliary data for each module
        let mut modules = Vec::with_capacity(count);
        for raw in raw_modules.into_iter() {
            modules.push(try!(MinidumpModule::read(f, raw)));
        }
        // store modules by address (interval?)
        Ok(MinidumpModuleList { modules: modules })
    }
}

impl Minidump {
    pub fn read(f : File) -> Result<Minidump, Error> {
        let header = try!(read::<fmt::MDRawHeader>(&f).or(Err(Error::MissingHeader)));
        let swap = false;
        if header.signature != fmt::MD_HEADER_SIGNATURE {
            if header.signature.swap_bytes() != fmt::MD_HEADER_SIGNATURE {
                return Err(Error::HeaderMismatch);
            }
            return Err(Error::SwapNotImplemented);
            // TODO: implement swapping
            //swap = true;
        }
        if (header.version & 0x0000ffff) != fmt::MD_HEADER_VERSION {
            return Err(Error::VersionMismatch);
        }
        let mut streams = HashMap::with_capacity(header.stream_count as usize);
        if header.stream_count != 0 {
            for _ in 0..header.stream_count {
                let dir = try!(read::<fmt::MDRawDirectory>(&f).or(Err(Error::MissingDirectory)));
                if dir.stream_type != fmt::MD_UNUSED_STREAM {
                    streams.insert(dir.stream_type, dir);
                }
            }
        }
        Ok(Minidump {
            file: f,
            header: header,
            streams: streams,
            swap: swap
        })
    }

    pub fn get_stream<T: MinidumpStream>(&mut self) -> Result<T, Error> {
        match self.streams.get_mut(&T::stream_type()) {
            None => Err(Error::StreamNotFound),
            Some(dir) => {
                try!(self.file.seek(SeekFrom::Start(dir.location.rva as u64)).or(Err(Error::StreamReadFailure)));
                // TODO: cache result
                T::read(&self.file, dir.location.data_size as usize)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::fs::File;
    use super::*;

    #[test]
    fn test_read_minidump() {
        let mut path = PathBuf::from(file!());
        path.pop();
        path.push("testdata/test.dmp");
        let f = File::open(&path).ok().expect(&format!("failed to open file: {:?}", path));
        let mut dump = Minidump::read(f).unwrap();
        assert_eq!(dump.streams.len(), 7);

        let module_list = dump.get_stream::<MinidumpModuleList>().unwrap();
        let modules = module_list.modules;
        assert_eq!(modules.len(), 13);
        assert_eq!(modules[0].name, "c:\\test_app.exe");
        assert_eq!(modules[0].base_address(), 0x400000);
        assert_eq!(modules[0].size(), 0x2d000);
        assert_eq!(modules[12].name, "C:\\WINDOWS\\system32\\psapi.dll");
        assert_eq!(modules[12].base_address(), 0x76bf0000);
        assert_eq!(modules[12].size(), 0xb000);
    }
}
