//! Module for analyzing CPU instructions
//!
//! When analyzing a minidump, it is often useful to know information about what instructions
//! were being run by various CPU threads (especially the crashing thread during a crash).
//!
//! This module attempts to provide a toolbox of instruction analysis tools that can be used to
//! provide such information.
//!
//! Support for different architectures can be enabled through features on the crate. Below is
//! a list of currently available architectures and enabling features:
//!
//! - `disasm_amd64`: enable analysis of Amd64 instructions (on by default)
//!
//! The functions in this module will generally return `OpAnalysisError::UnsupportedCpuArch` if
//! support for the target CPU is not available.

#![deny(missing_docs)]

use minidump::{MinidumpContext, MinidumpRawContext};

/// Error type for the functions in this module
#[derive(Debug, thiserror::Error)]
pub enum OpAnalysisError {
    /// CPU architecture not available (or not enabled by current feature set)
    #[error("unsupported CPU architecture")]
    UnsupportedCpuArch,
    /// Failed to read the memory at the instruction pointer
    #[error("failed to read memory at instruction pointer")]
    ReadThreadInstructionFailed,
    /// A byte slice was too short and therefore contained a truncated instruction
    #[error("byte slice contained truncated instruction")]
    InstructionTruncated,
    /// Failed to decode an instruction
    #[error("failed to decode instruction")]
    DecodeFailed(#[source] Box<dyn std::error::Error>),
    /// An instruction accesses memory using a register with invalid contents
    #[error("a register used by the instruction had an invalid value")]
    RegisterInvalid,
}

/// Details about a memory access performed by an instruction
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MemoryAccess {
    /// The address of the memory access
    pub address: u64,
    /// The size of the memory access
    ///
    /// Note that this is optional, as there are weird instructions that do not know the size
    /// of their memory accesses without more complex context.
    pub size: Option<u8>,
}

/// Determine the memory accesses that would occur with the given instruction and context
///
/// Architectures like x86 allow for complex arithmetic involving multiple registers to be
/// used to determine a target memory address, and allow for single operations involving
/// multiple memory locations (bit blitting, vector ops).
///
/// If the given `instruction_bytes` contain a valid instruction, and the given `context` contains
/// valid values for all the registers used for address calculation, this function will return a
/// (possibly-empty) list of all the memory accesses for the instruction.
///
/// ⚠ NOTE ⚠ - Certain instructions like "PUSH reg" are not considered to access memory, even
/// though they do technically write to the stack (the "PUSH [mem]" instruction will still
/// report the memory access for the operand, but not the implicit stack write). Generally this
/// shouldn't be of much concern, but there may be some situations where this detail matters.
///
/// # Errors
///
/// May fail if the given bytes are too short to form an instruction, don't represent a valid
/// instruction encoding, registers needed to calculate the address are invalid, or if the
/// given CPU architecture is not supported or enabled by the current feature set.
pub fn get_instruction_memory_access(
    context: &MinidumpContext,
    instruction_bytes: &[u8],
) -> Result<Vec<MemoryAccess>, OpAnalysisError> {
    match context.raw {
        #[cfg(feature = "disasm_amd64")]
        MinidumpRawContext::Amd64(_) => {
            self::amd64::get_instruction_memory_access(context, instruction_bytes)
        }
        _ => Err(OpAnalysisError::UnsupportedCpuArch),
    }
}

/// Pretty print the given instruction bytes
///
/// Interpret the given `instruction_bytes` as instructions for the CPU architecture given by
/// `context`, and pretty-print the instruction as a string.
///
/// # Errors
///
/// May fail if the given bytes are too short to form an instruction, don't represent a valid
/// instruction encoding, or if the given CPU architecture is not supported or enabled by the
/// current feature set.
pub fn pretty_print_instruction_bytes(
    context: &MinidumpContext,
    instruction_bytes: &[u8],
) -> Result<String, OpAnalysisError> {
    match context.raw {
        #[cfg(feature = "disasm_amd64")]
        MinidumpRawContext::Amd64(_) => {
            self::amd64::pretty_print_instruction_bytes(instruction_bytes)
        }
        _ => Err(OpAnalysisError::UnsupportedCpuArch),
    }
}

/// Determine the memory accesses that the given thread was performing
///
/// This function is just a convenience wrapper that reads the instruction bytes from the
/// given memory list and analyzes them with `get_instruction_memory_access`
///
/// # Errors
///
/// This may fail if there are no bytes at the instruction pointer, or if
/// `get_instruction_memory_access` fails
pub fn get_thread_memory_access<'a, Descriptor>(
    context: &MinidumpContext,
    memory_list: &minidump::MinidumpMemoryListBase<'a, Descriptor>,
) -> Result<Vec<MemoryAccess>, OpAnalysisError> {
    let instruction_bytes = get_thread_instruction_bytes(context, memory_list)?;
    get_instruction_memory_access(context, instruction_bytes)
}

/// Pretty-print the instruction that the given thread was running
///
/// This function is just a convenience wrapper that reads the instruction bytes from the
/// given memory list and pretty-prints them with `pretty_print_instruction_bytes`
///
/// # Errors
///
/// This may fail if there are no bytes at the instruction pointer, or if
/// `pretty_print_instruction_bytes` fails
pub fn pretty_print_thread_instruction<'a, Descriptor>(
    context: &MinidumpContext,
    memory_list: &minidump::MinidumpMemoryListBase<'a, Descriptor>,
) -> Result<String, OpAnalysisError> {
    let instruction_bytes = get_thread_instruction_bytes(context, memory_list)?;
    pretty_print_instruction_bytes(context, instruction_bytes)
}

/// Helper to read the instruction bytes that were being run by the given thread
///
/// Use the given `context` to attempt to read `1 <= n <= MAX_INSTRUCTION_LENGTH`
/// bytes at the instruction pointer from the given memory list
///
/// # Errors
///
/// This may fail if there are no bytes at the instruction pointer
fn get_thread_instruction_bytes<'a, Descriptor>(
    context: &MinidumpContext,
    memory_list: &'a minidump::MinidumpMemoryListBase<'a, Descriptor>,
) -> Result<&'a [u8], OpAnalysisError> {
    let instruction_pointer = context.get_instruction_pointer();

    memory_list
        .memory_at_address(instruction_pointer)
        .map(|memory| {
            let offset = (instruction_pointer - memory.base_address) as usize;
            &memory.bytes[offset..]
        })
        .ok_or(OpAnalysisError::ReadThreadInstructionFailed)
}

/// Analysis tools for the Amd64 architecture
#[cfg(feature = "disasm_amd64")]
mod amd64 {
    use super::*;

    /// Amd64-specific `get_instruction_memory_access`. See docs for general function
    pub fn get_instruction_memory_access(
        context: &MinidumpContext,
        bytes: &[u8],
    ) -> Result<Vec<MemoryAccess>, OpAnalysisError> {
        use yaxpeax_x86::amd64::{DecodeError, InstDecoder, Operand, RegSpec};

        let calculate_address = |base_reg: Option<RegSpec>,
                                 index_reg: Option<RegSpec>,
                                 scale: Option<u8>,
                                 disp: Option<i32>|
         -> Result<u64, OpAnalysisError> {
            let get_reg = |reg: RegSpec| -> Result<u64, OpAnalysisError> {
                context
                    .get_register(reg.name())
                    .ok_or(OpAnalysisError::RegisterInvalid)
            };

            let base = match base_reg {
                Some(reg) => get_reg(reg)?,
                None => 0,
            };

            let scaled_index = match index_reg {
                Some(reg) => {
                    let index = get_reg(reg)?;
                    let scale = scale.unwrap_or(1);
                    index.wrapping_mul(scale.into())
                }
                None => 0,
            };

            let disp = i64::from(disp.unwrap_or(0)) as u64;

            Ok(base.wrapping_add(scaled_index).wrapping_add(disp))
        };

        let decoder = InstDecoder::default();
        let decoded_instruction = decoder.decode_slice(bytes).map_err(|error| match error {
            DecodeError::ExhaustedInput => OpAnalysisError::InstructionTruncated,
            e => OpAnalysisError::DecodeFailed(e.into()),
        })?;

        let mut memory_accesses = Vec::new();

        // Shortcut -- If the instruction doesn't access memory, just return an empty list
        let mem_size = match decoded_instruction.mem_size() {
            Some(access) => access.bytes_size(),
            None => return Ok(memory_accesses),
        };

        for idx in 0..decoded_instruction.operand_count() {
            let operand = decoded_instruction.operand(idx);

            let maybe_address = match operand {
                Operand::DisplacementU32(disp) => Some(disp.into()),
                Operand::DisplacementU64(disp) => Some(disp),
                Operand::RegDeref(base) => Some(calculate_address(Some(base), None, None, None)?),
                Operand::RegDisp(base, disp) => {
                    Some(calculate_address(Some(base), None, None, Some(disp))?)
                }
                Operand::RegScale(index, scale) => {
                    Some(calculate_address(None, Some(index), Some(scale), None)?)
                }
                Operand::RegIndexBase(base, index) => {
                    Some(calculate_address(Some(base), Some(index), None, None)?)
                }
                Operand::RegIndexBaseDisp(base, index, disp) => Some(calculate_address(
                    Some(base),
                    Some(index),
                    None,
                    Some(disp),
                )?),
                Operand::RegScaleDisp(index, scale, disp) => Some(calculate_address(
                    None,
                    Some(index),
                    Some(scale),
                    Some(disp),
                )?),
                Operand::RegIndexBaseScale(base, index, scale) => Some(calculate_address(
                    Some(base),
                    Some(index),
                    Some(scale),
                    None,
                )?),
                Operand::RegIndexBaseScaleDisp(base, index, scale, disp) => Some(
                    calculate_address(Some(base), Some(index), Some(scale), Some(disp))?,
                ),
                _ => None,
            };

            if let Some(address) = maybe_address {
                memory_accesses.push(MemoryAccess {
                    address,
                    size: mem_size,
                });
            }
        }

        Ok(memory_accesses)
    }

    /// Amd64-specific `pretty_print_instruction_bytes`. See docs for general function
    pub fn pretty_print_instruction_bytes(bytes: &[u8]) -> Result<String, OpAnalysisError> {
        use yaxpeax_x86::amd64::{DecodeError, InstDecoder};

        let decoder = InstDecoder::default();
        let decoded_instruction = decoder.decode_slice(bytes).map_err(|error| match error {
            DecodeError::ExhaustedInput => OpAnalysisError::InstructionTruncated,
            e => OpAnalysisError::DecodeFailed(e.into()),
        })?;

        Ok(decoded_instruction.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use minidump::MinidumpRawContext;

    #[cfg(feature = "disasm_amd64")]
    mod amd64 {
        use super::*;

        use minidump::{format::CONTEXT_AMD64, CpuContext};

        struct AccessTestData<'a> {
            bytes: &'a [u8],
            regs: &'a [(&'a str, u64)],
            expected_size: u8,
            expected_addresses: &'a [u64],
        }

        fn access_test(data: &AccessTestData) {
            let mut context_raw = CONTEXT_AMD64::default();

            for &(name, value) in data.regs.iter() {
                assert_ne!(name, "rip", "you may not specify a value for 'rip'");
                context_raw.set_register(name, value).unwrap();
            }

            let context = MinidumpContext::from_raw(MinidumpRawContext::Amd64(context_raw));
            let memory_accesses = get_instruction_memory_access(&context, data.bytes).unwrap();

            let mut expected_set: std::collections::HashSet<u64> =
                data.expected_addresses.iter().cloned().collect();

            for access in memory_accesses.iter() {
                if access.size.unwrap() != data.expected_size {
                    panic!(
                        "expected memory access size {}, got {}",
                        data.expected_size,
                        access.size.unwrap()
                    );
                }
                if !expected_set.remove(&access.address) {
                    panic!(
                        "unexpected memory address found in instruction:\n{}\nexpected:\n{:?}\n",
                        access.address, expected_set
                    );
                }
            }

            if !expected_set.is_empty() {
                panic!(
                    "expected memory addresses not found in instruction:\n{:?}\n",
                    expected_set
                );
            }
        }

        #[test]
        fn test_reg_deref() {
            // mov al, [rbx]
            let mut data = AccessTestData {
                bytes: &[0x8a, 0x03],
                regs: &[("rbx", 0xbadc0ffebadc0ffe)],
                expected_size: 1,
                expected_addresses: &[0xbadc0ffebadc0ffe],
            };
            access_test(&data);

            // mov ax, [rbx]
            data.bytes = &[0x66, 0x8b, 0x03];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [rbx]
            data.bytes = &[0x8b, 0x03];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [rbx]
            data.bytes = &[0x48, 0x8b, 0x03];
            data.expected_size = 8;
            access_test(&data);
        }

        #[test]
        fn test_base_disp() {
            // mov al, [rbp + 0x800]
            let mut data = AccessTestData {
                bytes: &[0x8a, 0x85, 0x00, 0x08, 0x00, 0x00],
                regs: &[("rbp", 0x1000)],
                expected_size: 1,
                expected_addresses: &[0x1800],
            };
            access_test(&data);

            // mov ax, [rbp + 0x800]
            data.bytes = &[0x66, 0x8b, 0x85, 0x00, 0x08, 0x00, 0x00];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [rbp + 0x800]
            data.bytes = &[0x8b, 0x85, 0x00, 0x08, 0x00, 0x00];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [rbp + 0x800]
            data.bytes = &[0x48, 0x8b, 0x85, 0x00, 0x08, 0x00, 0x00];
            data.expected_size = 8;
            access_test(&data);

            // mov rax, [rbp - 0x800]
            data.bytes = &[0x48, 0x8b, 0x85, 0x00, 0xf8, 0xff, 0xff];
            data.expected_addresses = &[0x800];
            access_test(&data);
        }

        #[test]
        fn test_index_scale() {
            // mov al, [rsi * 4] + 0x00000000
            let mut data = AccessTestData {
                bytes: &[0x8a, 0x04, 0xb5, 0x00, 0x00, 0x00, 0x00],
                regs: &[("rsi", 0x1000)],
                expected_size: 1,
                expected_addresses: &[0x4000],
            };
            access_test(&data);

            // mov ax, [rsi * 4] + 0x00000000
            data.bytes = &[0x66, 0x8b, 0x04, 0xb5, 0x00, 0x00, 0x00, 0x00];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [rsi * 4] + 0x00000000
            data.bytes = &[0x8b, 0x04, 0xb5, 0x00, 0x00, 0x00, 0x00];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [rsi * 4] + 0x00000000
            data.bytes = &[0x48, 0x8b, 0x04, 0xb5, 0x00, 0x00, 0x00, 0x00];
            data.expected_size = 8;
            access_test(&data);
        }

        #[test]
        fn test_base_index() {
            // mov al, [rbx + rcx]
            let mut data = AccessTestData {
                bytes: &[0x8a, 0x04, 0x0b],
                regs: &[("rbx", 0x1000), ("rcx", 0x234)],
                expected_size: 1,
                expected_addresses: &[0x1234],
            };
            access_test(&data);

            // mov ax, [rbx + rcx]
            data.bytes = &[0x66, 0x8b, 0x04, 0x0b];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [rbx + rcx]
            data.bytes = &[0x8b, 0x04, 0x0b];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [rbx + rcx]
            data.bytes = &[0x48, 0x8b, 0x04, 0x0b];
            data.expected_size = 8;
            access_test(&data);
        }

        #[test]
        fn test_base_index_disp() {
            // mov al, [rcx + r9 + 16]
            let mut data = AccessTestData {
                bytes: &[0x42, 0x8a, 0x44, 0x09, 0x10],
                regs: &[("rcx", 0x4000), ("r9", 0x2000)],
                expected_size: 1,
                expected_addresses: &[0x6010],
            };
            access_test(&data);

            // mov ax, [rcx + r9 + 16]
            data.bytes = &[0x66, 0x42, 0x8b, 0x44, 0x09, 0x10];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [rcx + r9 + 16]
            data.bytes = &[0x42, 0x8b, 0x44, 0x09, 0x10];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [rcx + r9 + 16]
            data.bytes = &[0x4a, 0x8b, 0x44, 0x09, 0x10];
            data.expected_size = 8;
            access_test(&data);

            // mov rax, [rcx + r9 - 16]
            data.bytes = &[0x4a, 0x8b, 0x44, 0x09, 0xf0];
            data.expected_size = 8;
            data.expected_addresses = &[0x5ff0];
            access_test(&data);
        }

        #[test]
        fn test_index_scale_disp() {
            // mov al, [r13 * 8 + 0x100000]
            let mut data = AccessTestData {
                bytes: &[0x42, 0x8a, 0x04, 0xed, 0x00, 0x00, 0x10, 0x00],
                regs: &[("r13", 0x1000)],
                expected_size: 1,
                expected_addresses: &[0x108000],
            };
            access_test(&data);

            // mov ax, [r13 * 8 + 0x100000]
            data.bytes = &[0x66, 0x42, 0x8b, 0x04, 0xed, 0x00, 0x00, 0x10, 0x00];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [r13 * 8 + 0x100000]
            data.bytes = &[0x42, 0x8b, 0x04, 0xed, 0x00, 0x00, 0x10, 0x00];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [r13 * 8 + 0x100000]
            data.bytes = &[0x4a, 0x8b, 0x04, 0xed, 0x00, 0x00, 0x10, 0x00];
            data.expected_size = 8;
            access_test(&data);

            // mov rax, [r13 * 8 - 0x100000]
            data.bytes = &[0x4a, 0x8b, 0x04, 0xed, 0x00, 0x00, 0xf0, 0xff];
            data.expected_size = 8;
            data.expected_addresses = &[0xfffffffffff08000];
            access_test(&data);
        }

        #[test]
        fn test_base_index_scale() {
            // mov al, [r12 + r14 * 2]
            let mut data = AccessTestData {
                bytes: &[0x43, 0x8a, 0x04, 0x74],
                regs: &[("r12", 0x8000), ("r14", 0x10000)],
                expected_size: 1,
                expected_addresses: &[0x28000],
            };
            access_test(&data);

            // mov ax, [r12 + r14 * 2]
            data.bytes = &[0x66, 0x43, 0x8b, 0x04, 0x74];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [r12 + r14 * 2]
            data.bytes = &[0x43, 0x8b, 0x04, 0x74];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [r12 + r14 * 2]
            data.bytes = &[0x4b, 0x8b, 0x04, 0x74];
            data.expected_size = 8;
            access_test(&data);
        }

        #[test]
        fn test_base_index_scale_disp() {
            // mov al, [r9 + rbx * 8 + 0x7fffffff]
            let mut data = AccessTestData {
                bytes: &[0x41, 0x8a, 0x84, 0xd9, 0xff, 0xff, 0xff, 0x7f],
                regs: &[("r9", 0x100001), ("rbx", 0x1000)],
                expected_size: 1,
                expected_addresses: &[0x80108000],
            };
            access_test(&data);

            // mov ax, [r9 + rbx * 8 + 0x7fffffff]
            data.bytes = &[0x66, 0x41, 0x8b, 0x84, 0xd9, 0xff, 0xff, 0xff, 0x7f];
            data.expected_size = 2;
            access_test(&data);

            // mov eax, [r9 + rbx * 8 + 0x7fffffff]
            data.bytes = &[0x41, 0x8b, 0x84, 0xd9, 0xff, 0xff, 0xff, 0x7f];
            data.expected_size = 4;
            access_test(&data);

            // mov rax, [r9 + rbx * 8 + 0x7fffffff]
            data.bytes = &[0x49, 0x8b, 0x84, 0xd9, 0xff, 0xff, 0xff, 0x7f];
            data.expected_size = 8;
            access_test(&data);

            // mov rax, [r9 + rbx * 8 - 0x7fffffff]
            data.bytes = &[0x49, 0x8b, 0x84, 0xd9, 0x01, 0x00, 0x00, 0x80];
            data.expected_size = 8;
            data.expected_addresses = &[0xffffffff80108002];
            access_test(&data);
        }

        #[test]
        fn test_string_copy() {
            // movsb
            let mut data = AccessTestData {
                bytes: &[0xa4],
                regs: &[("rsi", 0x1000), ("rdi", 0x2000), ("rcx", 10)],
                expected_size: 1,
                expected_addresses: &[0x2000, 0x1000],
            };
            access_test(&data);

            // movsw
            data.bytes = &[0x66, 0xa5];
            data.expected_size = 2;
            access_test(&data);

            // movsd
            data.bytes = &[0xa5];
            data.expected_size = 4;
            access_test(&data);

            // movsq
            data.bytes = &[0x48, 0xa5];
            data.expected_size = 8;
            access_test(&data);

            // rep movsb
            data.bytes = &[0xf3, 0xa4];
            data.expected_size = 1;
            access_test(&data);
        }
    }
}
