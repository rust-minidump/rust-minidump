use std::fs::File;
use std::io::{Seek, SeekFrom};

use crate::{BitFlip, BitFlips, FileKind, Integrity, SymbolProvider};
use breakpad_symbols::Module;
use minidump::{MinidumpMemory, MinidumpMemoryList, MinidumpModuleList};

pub async fn check_integrity(
    memory_list: &MinidumpMemoryList<'_>,
    modules: &MinidumpModuleList,
    symbols: &(impl SymbolProvider + Sync),
) -> Integrity {
    let bit_flips = check_flips(memory_list, modules, symbols).await;
    Integrity { bit_flips }
}

pub async fn check_flips(
    memory_list: &MinidumpMemoryList<'_>,
    modules: &MinidumpModuleList,
    symbols: &(impl SymbolProvider + Sync),
) -> BitFlips {
    let mut failures = vec![];

    for memory in memory_list.iter() {
        if let Ok(Some(val)) = check_memory_for_flip(memory, modules, symbols).await {
            failures.push(val);
        }
    }
    BitFlips {
        checked: true,
        failures,
    }
}

pub async fn check_memory_for_flip(
    memory: &MinidumpMemory<'_>,
    modules: &MinidumpModuleList,
    symbols: &(impl SymbolProvider + Sync),
) -> Result<Option<BitFlip>, std::io::Error> {
    let base_addr = memory.base_address;
    let memory_size = memory.size;
    if let Some(module) = modules.module_at_address(base_addr) {
        let offset = base_addr - module.base_address();
        if let Ok(path) = symbols.get_file_path(module, FileKind::Binary).await {
            let mut binary = File::open(&path)?;
            let in_binary = vec![0; memory_size as usize];
            binary.seek(SeekFrom::Start(offset))?;
            if in_binary != memory.bytes {
                return Ok(Some(BitFlip {
                    module: module.clone(),
                    offset,
                    in_dump: memory.bytes.to_owned(),
                    in_binary,
                }));
            }
        }
    }
    Ok(None)
}
