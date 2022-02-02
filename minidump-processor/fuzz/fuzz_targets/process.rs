#![no_main]
use libfuzzer_sys::fuzz_target;

struct StaticSymbolSupplier {
    file: Vec<u8>,
}

impl minidump_processor::SymbolSupplier for StaticSymbolSupplier {
    fn locate_symbols(
        &self,
        _module: &dyn minidump_common::traits::Module,
    ) -> Result<minidump_processor::SymbolFile, minidump_processor::SymbolError> {
        minidump_processor::SymbolFile::from_bytes(&self.file)
    }
}

fuzz_target!(|data: (&[u8], &[u8])| {
    if let Ok(dump) = minidump::Minidump::read(data.0) {
        let supplier = StaticSymbolSupplier {
            file: data.1.to_vec(),
        };

        let provider = minidump_processor::Symbolizer::new(supplier);
        let _ = minidump_processor::process_minidump(&dump, &provider);
    }
});
