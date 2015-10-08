// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! General-purpose I/O routines.

use encoding::all::UTF_16LE;
use encoding::{Encoding, DecoderTrap};
use std::io::prelude::*;
use std::fs::File;
use std::io;
use std::io::SeekFrom;
use std::mem;
use std::ptr;

/// Read `count` bytes from `f` and return a `Vec<u8>` of them.
pub fn read_bytes(f : &File, count : usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(count);
    try!(f.take(count as u64).read_to_end(&mut buf));
    Ok(buf)
}

/// Convert `bytes` into `T`.
//FIXME: this should be replaced with something based on serialize.
pub fn transmogrify<T : Copy + Sized>(bytes : &[u8]) -> T {
    assert_eq!(mem::size_of::<T>(), bytes.len());
    unsafe {
        let mut val : T = mem::uninitialized();
        ptr::copy(bytes.as_ptr(), &mut val as *mut T as *mut u8, bytes.len());
        val
    }
}

/// Read a `T` from `f`.
pub fn read<T : Copy + Sized>(f : &File) -> io::Result<T> {
    let size = mem::size_of::<T>();
    let buf = try!(read_bytes(f, size));
    Ok(transmogrify::<T>(&buf[..]))
}

/// Read a UTF-16 string from `f` at `offset`.
pub fn read_string_utf16(mut f : &File, offset : u64) -> io::Result<String> {
    try!(f.seek(SeekFrom::Start(offset)));
    let size = try!(read::<u32>(f)) as usize;
    // TODO: swap
    if size % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
                                  "Invalid UTF-16 string length"));
    }
    let buf = try!(read_bytes(f, size));
    let bytes = &buf[..];
    UTF_16LE.decode(bytes, DecoderTrap::Strict)
        .or(Err(io::Error::new(io::ErrorKind::InvalidData,
                               "Invalid UTF-16 string")))
}

/// Format `bytes` to `f` as a hex string.
pub fn write_bytes<T : Write>(f : &mut T, bytes : &[u8]) -> io::Result<()> {
    for b in bytes {
        try!(write!(f, "{:02x}", b));
    }
    Ok(())
}
