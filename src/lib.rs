use std::io::prelude::*;
use std::fs::File;
use std::mem;
use std::ptr;

pub mod minidump_format;
use minidump_format as fmt;

#[allow(dead_code)]
pub struct Minidump {
    file : File,
    header : fmt::MDRawHeader,
    swap : bool,
}

#[derive(Debug)]
pub enum Error {
    MissingHeader,
    HeaderMismatch,
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
        let mut swap = false;
        if header.signature != fmt::MD_HEADER_SIGNATURE {
            if header.signature.swap_bytes() != fmt::MD_HEADER_SIGNATURE {
                return Err(Error::HeaderMismatch);
            }
            swap = true;
        }
        Ok(Minidump { file: f, header: header, swap: swap })
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
        Minidump::read(f).unwrap();
    }
}
