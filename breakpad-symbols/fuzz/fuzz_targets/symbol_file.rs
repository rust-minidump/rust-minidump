#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = breakpad_symbols::SymbolFile::from_bytes(data);
});
