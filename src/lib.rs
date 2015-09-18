use std::io::prelude::*;
use std::fs::File;
use std::mem;
use std::ptr;
use std::collections::HashMap;

extern crate libc;

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
}

fn read<T>(mut f : &File) -> std::io::Result<T> {
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
        let dump = Minidump::read(f).unwrap();
        assert_eq!(dump.streams.len(), 7);
    }
}
