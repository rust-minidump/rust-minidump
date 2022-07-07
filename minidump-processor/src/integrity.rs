use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

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
            let mut in_binary = vec![0; memory_size as usize];
            binary.seek(SeekFrom::Start(offset))?;
            binary.read_exact(&mut in_binary[..])?;

            let mut first_flip = 0;
            let mut last_flip = 0;
            let mut flip_count = 0u64;
            for (idx, (a, b)) in in_binary.iter().zip(memory.bytes.iter()).enumerate() {
                if a != b {
                    if flip_count == 0 {
                        first_flip = idx;
                    }
                    last_flip = idx;
                    flip_count += 1;
                }
            }

            if flip_count != 0 {
                return Ok(Some(BitFlip {
                    flip_offset: first_flip as u64,
                    flip_count,
                    flip_in_dump: memory.bytes[first_flip..=last_flip].to_owned(),
                    flip_in_binary: in_binary[first_flip..=last_flip].to_owned(),
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
