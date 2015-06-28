pub const MD_HEADER_SIGNATURE : u32 = 0x504d444d;

pub type MDRVA = u32;

#[derive(Copy, Clone)]
#[repr(C)]
#[packed]
#[allow(dead_code)]
pub struct MDRawHeader {
  pub signature            : u32,
  pub version              : u32,
  pub stream_count         : u32,
  pub stream_directory_rva : MDRVA,  /* A |stream_count|-sized array of
                                      * MDRawDirectory structures. */
  pub checksum             : u32,    /* Can be 0.  In fact, that's all that's
                                      * been found in minidump files. */
  pub time_date_stamp      : u32,    /* time_t */
  pub flags                : u64
}
