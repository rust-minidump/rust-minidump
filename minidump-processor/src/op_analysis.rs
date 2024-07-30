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

use minidump::{MinidumpContext, MinidumpRawContext, UnifiedMemory};
use std::collections::BTreeSet;

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

/// The results of analyzing a CPU instruction
///
/// Many fields of this structure are optional, as it's possible that some kinds of analysis
/// will work where others will fail (for example, if some-but-not-all of the memory or registers
/// are invalid, some things might still work fine).
#[derive(Debug)]
pub struct OpAnalysis {
    /// A string representation of the instruction for humans to read
    pub instruction_str: String,
    /// A list of booleans representing whether this instruction could have caused
    /// a particular type of crash
    pub possible_crash_info: PossibleCrashInfo,
    /// A list of all the memory accesses performed by the instruction
    ///
    /// Note that an empty vector and `None` don't mean the same thing -- `None` means
    /// that access could not be determined, `Some(Vec<len==0>)` means it was successfully
    /// determined that the instruction doesn't access memory.
    pub memory_accesses: Option<Vec<MemoryAccess>>,
    /// Whether the instruction pointer is being updated by the instruction
    pub instruction_pointer_update: Option<InstructionPointerUpdate>,
    /// A list of all registers which were used by this instruction.
    pub registers: BTreeSet<&'static str>,
}

/// A list of booleans representing whether this instruction could have caused
/// a particular type of crash
/// Note that memory access crashses are checked through `memory_accesses`
// TODO: remove `is_common_memory_crash_instruction` field once `yaxpeax` provides access types
// for operands of all instructions
#[derive(Clone, Debug)]
pub struct PossibleCrashInfo {
    pub is_common_memory_crash_instruction: bool,
    pub int_division_by_zero: bool,
    pub priv_instruction: bool,
}

/// Details about a memory access performed by an instruction
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MemoryAccess {
    // Information
    pub address_info: MemoryAddressInfo,
    /// The size of the memory access
    ///
    /// Note that this is optional, as there are weird instructions that do not know the size
    /// of their memory accesses without more complex context.
    pub size: Option<u8>,
    /// The type of the memory access
    pub access_type: MemoryAccessType,
}

/// Details about update of instruction pointer performed by an instruction
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InstructionPointerUpdate {
    /// Information about the address that instruciton pointer is being updated to
    pub address_info: MemoryAddressInfo,
}

/// Details about a memory address of a memory access or an instruction pointer update
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MemoryAddressInfo {
    /// The address
    pub address: u64,
    /// Whether or not this memory address is likely the result of a null-pointer dereference
    pub is_likely_null_pointer_dereference: bool,
    /// Whether or not this memory address was part of a likely guard page.
    pub is_likely_guard_page: bool,
}

/// The direction of a memory access
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryAccessType {
    Read,
    Write,
    ReadWrite,

    // TODO: Remove this variant once `yaxpeax` is used to derive access type of every operand
    UncommonInstructionAccess,
}

impl MemoryAccessType {
    pub fn is_read_or_write(&self) -> bool {
        !matches!(self, Self::UncommonInstructionAccess)
    }
}

impl std::fmt::Display for MemoryAccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => f.write_str("Read"),
            Self::Write => f.write_str("Write"),
            Self::ReadWrite => f.write_str("ReadWrite"),
            Self::UncommonInstructionAccess => f.write_str("Uncommon Instruction Access"),
        }
    }
}

/// Analyze the instructions being run by the given thread
///
/// Using the passed-in `context` of the thread's execution and the memory contained in
/// `memory_list`, this function will use a disassembler to analyze the instructions the thread
/// was running and determine information that may be useful for people who need to analyze crash
/// dumps.
///
/// Note that most things in this function are heuristic, and so both false positives and
/// false negatives are expected.
///
/// # Errors
///
/// An error may be returned for a number of reasons, mainly: if disassembly of the target CPU
/// architecture is not supported, if the memory pointed to by the instruction pointer is missing
/// from the memory dump, or if the crashing instruction could not be disassembled.
///
/// Note that even if this function doesn't return an error, individual pieces of information
/// may still be missing from the returned `OpAnalysis` structure.
pub fn analyze_thread_context(
    context: &MinidumpContext,
    memory_list: &minidump::UnifiedMemoryList,
    stack_memory: Option<UnifiedMemory>,
) -> Result<OpAnalysis, OpAnalysisError> {
    let instruction_bytes = get_thread_instruction_bytes(context, memory_list)?;

    match context.raw {
        #[cfg(feature = "disasm_amd64")]
        MinidumpRawContext::Amd64(_) => self::amd64::analyze_instruction(
            context,
            instruction_bytes,
            Some(memory_list),
            stack_memory,
        ),
        _ => Err(OpAnalysisError::UnsupportedCpuArch),
    }
}

/// Helper to read the instruction bytes that were being run by the given thread
///
/// Use the given `context` to attempt to read `1 <= n <= MAX_INSTRUCTION_LENGTH`
/// bytes at the instruction pointer from the given memory list.
///
/// # Errors
///
/// This may fail if there are no bytes at the instruction pointer.
fn get_thread_instruction_bytes<'a>(
    context: &MinidumpContext,
    memory_list: &'a minidump::UnifiedMemoryList<'a>,
) -> Result<&'a [u8], OpAnalysisError> {
    let instruction_pointer = context.get_instruction_pointer();

    memory_list
        .memory_at_address(instruction_pointer)
        .map(|memory| {
            let offset = (instruction_pointer - memory.base_address()) as usize;
            &memory.bytes()[offset..]
        })
        .ok_or(OpAnalysisError::ReadThreadInstructionFailed)
}

/// Analysis tools for the Amd64 architecture
#[cfg(feature = "disasm_amd64")]
mod amd64 {
    use super::*;
    use yaxpeax_x86::amd64::{Instruction, Opcode, Operand, RegSpec};

    /// Amd64-specific instruction analysis
    ///
    /// Uses yaxpeax-x86 to disassemble the given `instruction_bytes`, and then uses the registers
    /// contained in `context` to determine useful information about the given instruction.
    pub fn analyze_instruction(
        context: &MinidumpContext,
        instruction_bytes: &[u8],
        memory_list: Option<&minidump::UnifiedMemoryList>,
        stack_memory: Option<minidump::UnifiedMemory>,
    ) -> Result<OpAnalysis, OpAnalysisError> {
        let decoded_instruction = decode_instruction(instruction_bytes)?;

        let instruction_str = decoded_instruction.to_string();

        let possible_crash_info = PossibleCrashInfo::from_instruction(decoded_instruction);

        let memory_accesses = MemoryAccess::from_instruction(decoded_instruction, context)
            .map_err(|e| tracing::warn!("failed to determine instruction memory access: {}", e))
            .ok();

        let instruction_pointer_update = InstructionPointerUpdate::from_instruction(
            decoded_instruction,
            context,
            memory_list,
            stack_memory,
        )
        .map_err(|e| tracing::warn!("failed to determine instruction pointer updates: {}", e))
        .ok()
        .flatten();

        let registers = get_registers(decoded_instruction);

        Ok(OpAnalysis {
            instruction_str,
            possible_crash_info,
            memory_accesses,
            instruction_pointer_update,
            registers,
        })
    }

    /// Decode the given Amd64 instruction using yaxpeax-x86
    ///
    /// # Errors
    ///
    /// Will return an error if the instruction could not be decoded (possibly because the
    /// given bytes represent an invalid x86 instruction), or because the given byte buffer is
    /// not long enough and the given instruction is therefore truncated.
    fn decode_instruction(bytes: &[u8]) -> Result<Instruction, OpAnalysisError> {
        use yaxpeax_x86::amd64::{DecodeError, InstDecoder};
        let decoder = InstDecoder::default();
        decoder.decode_slice(bytes).map_err(|error| match error {
            DecodeError::ExhaustedInput => OpAnalysisError::InstructionTruncated,
            e => OpAnalysisError::DecodeFailed(e.into()),
        })
    }

    impl PossibleCrashInfo {
        fn from_instruction(instruction: Instruction) -> Self {
            PossibleCrashInfo {
                is_common_memory_crash_instruction: CommonOpcode::is_common(instruction.opcode()),
                int_division_by_zero: PossibleCrashInfo::int_division_by_zero_possible(instruction),
                priv_instruction: PossibleCrashInfo::priv_instruction_possible(instruction),
            }
        }

        fn int_division_by_zero_possible(instruction: Instruction) -> bool {
            // TODO: check if the divisor is zero
            matches!(instruction.opcode(), Opcode::DIV | Opcode::IDIV)
        }

        // TODO: Use `yaxpeax` to check for all possible privileged instructions
        fn priv_instruction_possible(instruction: Instruction) -> bool {
            matches!(
                instruction.opcode(),
                Opcode::CLI
                    | Opcode::CLTS
                    | Opcode::HLT
                    | Opcode::IN
                    | Opcode::INS
                    | Opcode::INT
                    | Opcode::INTO
                    | Opcode::INVD
                    | Opcode::INVEPT
                    | Opcode::INVLPG
                    | Opcode::INVVPID
                    | Opcode::IRET
                    | Opcode::IRETD
                    | Opcode::IRETQ
                    | Opcode::LGDT
                    | Opcode::LIDT
                    | Opcode::LLDT
                    | Opcode::LMSW
                    | Opcode::LTR
                    | Opcode::MONITOR
                    | Opcode::MOV
                    | Opcode::MWAIT
                    | Opcode::OUT
                    | Opcode::OUTS
                    | Opcode::RDMSR
                    | Opcode::RDPMC
                    | Opcode::RDTSC
                    | Opcode::RDTSCP
                    | Opcode::RETF
                    | Opcode::STI
                    | Opcode::SWAPGS
                    | Opcode::SYSEXIT
                    | Opcode::SYSRET
                    | Opcode::VMCALL
                    | Opcode::VMCLEAR
                    | Opcode::VMLAUNCH
                    | Opcode::VMPTRLD
                    | Opcode::VMPTRST
                    | Opcode::VMREAD
                    | Opcode::VMRESUME
                    | Opcode::VMWRITE
                    | Opcode::VMXOFF
                    | Opcode::VMXON
                    | Opcode::WBINVD
                    | Opcode::WRMSR
                    | Opcode::XSETBV
            )
        }
    }

    impl MemoryAccess {
        /// Determine the memory accesses implied by the given instruction and context
        ///
        /// # Errors
        ///
        /// The most likely cause of an error is that a register named by the given instruction
        /// is invalid.
        fn from_instruction(
            instruction: Instruction,
            context: &MinidumpContext,
        ) -> Result<Vec<Self>, OpAnalysisError> {
            let mut accesses = Vec::new();
            if let Some(opcode) = CommonOpcode::from_amd64_opcode(instruction.opcode()) {
                Self::add_common_opcode_accesses(&mut accesses, opcode, instruction, context)?;
            } else {
                Self::add_uncommon_opcode_accesses(&mut accesses, instruction, context)?;
            }
            Ok(accesses)
        }

        fn add_common_opcode_accesses(
            accesses: &mut Vec<MemoryAccess>,
            opcode: CommonOpcode,
            instruction: Instruction,
            context: &MinidumpContext,
        ) -> Result<(), OpAnalysisError> {
            // Shortcut -- If the instruction doesn't access memory, just return
            let mem_size = match instruction.mem_size() {
                Some(access) => access.bytes_size(),
                None => return Ok(()),
            };

            for idx in 0..instruction.operand_count() {
                Self::add_common_opcode_explicit_access(
                    accesses,
                    opcode,
                    instruction.operand(idx),
                    idx,
                    mem_size,
                    context,
                )?;
            }

            Self::add_common_opcode_implicit_access(accesses, opcode, mem_size, context)?;
            Ok(())
        }

        fn add_common_opcode_explicit_access(
            accesses: &mut Vec<MemoryAccess>,
            opcode: CommonOpcode,
            operand: Operand,
            idx: u8,
            mem_size: Option<u8>,
            context: &MinidumpContext,
        ) -> Result<(), OpAnalysisError> {
            if !operand.is_memory() {
                return Ok(());
            }

            let access_type = match (opcode, idx) {
                (CommonOpcode::ADD | CommonOpcode::SUB, 0) => MemoryAccessType::ReadWrite,
                (CommonOpcode::ADD | CommonOpcode::SUB, 1) => MemoryAccessType::ReadWrite,
                (
                    CommonOpcode::CALL
                    | CommonOpcode::JMP
                    | CommonOpcode::JMPF
                    | CommonOpcode::PUSH,
                    0,
                ) => MemoryAccessType::Read,
                (CommonOpcode::CMP, 0 | 1) => MemoryAccessType::Read,
                (CommonOpcode::DEC | CommonOpcode::INC, 0) => MemoryAccessType::ReadWrite,
                (CommonOpcode::MOV | CommonOpcode::MOVAPS | CommonOpcode::MOVUPS, 0) => {
                    MemoryAccessType::Write
                }
                (CommonOpcode::MOV | CommonOpcode::MOVAPS | CommonOpcode::MOVUPS, 1) => {
                    MemoryAccessType::Read
                }
                (CommonOpcode::LEA, 0 | 1) => return Ok(()),
                _ => {
                    tracing::warn!("instruction had unexpected memory operand");
                    return Ok(());
                }
            };

            if let Some(op_info) = MemoryOperandInfo::try_from_operand(operand) {
                let address_info = MemoryAddressInfo::from_memory_operand_info(op_info, context)?;
                accesses.push(MemoryAccess {
                    address_info,
                    size: mem_size,
                    access_type,
                });
            }

            Ok(())
        }

        fn add_common_opcode_implicit_access(
            accesses: &mut Vec<MemoryAccess>,
            opcode: CommonOpcode,
            mem_size: Option<u8>,
            context: &MinidumpContext,
        ) -> Result<(), OpAnalysisError> {
            let mut push_implicit_access = |address, access_type| {
                let address_info = MemoryAddressInfo {
                    address,
                    is_likely_null_pointer_dereference: address == 0,
                    is_likely_guard_page: false,
                };
                accesses.push(MemoryAccess {
                    address_info,
                    size: mem_size,
                    access_type,
                });
            };

            match opcode {
                CommonOpcode::CALL | CommonOpcode::PUSH => {
                    if let Ok(rsp) = context.get_regspec(RegSpec::rsp()) {
                        push_implicit_access(rsp, MemoryAccessType::Write);
                    }
                }
                CommonOpcode::IRET
                | CommonOpcode::IRETD
                | CommonOpcode::IRETQ
                | CommonOpcode::POP
                | CommonOpcode::RETF
                | CommonOpcode::RETURN => {
                    if let Ok(rsp) = context.get_regspec(RegSpec::rsp()) {
                        push_implicit_access(rsp, MemoryAccessType::Read);
                    }
                }
                _ => (),
            }
            Ok(())
        }

        fn add_uncommon_opcode_accesses(
            accesses: &mut Vec<MemoryAccess>,
            instruction: Instruction,
            context: &MinidumpContext,
        ) -> Result<(), OpAnalysisError> {
            // Shortcut -- If the instruction doesn't access memory, just return
            let mem_size = match instruction.mem_size() {
                Some(access) => access.bytes_size(),
                None => return Ok(()),
            };

            for idx in 0..instruction.operand_count() {
                Self::add_uncommon_opcode_explicit_access(
                    accesses,
                    instruction.operand(idx),
                    mem_size,
                    context,
                )?;
            }

            Ok(())
        }
        fn add_uncommon_opcode_explicit_access(
            accesses: &mut Vec<MemoryAccess>,
            operand: Operand,
            mem_size: Option<u8>,
            context: &MinidumpContext,
        ) -> Result<(), OpAnalysisError> {
            if !operand.is_memory() {
                return Ok(());
            }

            if let Some(op_info) = MemoryOperandInfo::try_from_operand(operand) {
                let address_info = MemoryAddressInfo::from_memory_operand_info(op_info, context)?;
                accesses.push(MemoryAccess {
                    address_info,
                    size: mem_size,
                    access_type: MemoryAccessType::UncommonInstructionAccess,
                });
            }

            Ok(())
        }
    }

    impl InstructionPointerUpdate {
        fn from_instruction(
            instruction: Instruction,
            context: &MinidumpContext,
            memory_list: Option<&minidump::UnifiedMemoryList>,
            stack_memory: Option<minidump::UnifiedMemory>,
        ) -> Result<Option<Self>, OpAnalysisError> {
            let rip_update = |address| {
                Some(InstructionPointerUpdate {
                    address_info: MemoryAddressInfo {
                        address,
                        is_likely_null_pointer_dereference: address == 0,
                        is_likely_guard_page: false,
                    },
                })
            };

            match instruction.opcode() {
                Opcode::CALL | Opcode::CALLF | Opcode::JMP | Opcode::JMPF | Opcode::JMPE => {
                    if instruction.operand_count() != 1 {
                        tracing::warn!("call/jmp instruction had incorrect operand count");
                        return Ok(None);
                    }
                    // We assume that relative offsets (for CALL, JMP) and absolute values (CALLF,
                    // JMPF) will be valid, so we don't check immediate operands, only registers.
                    match instruction.operand(0) {
                        Operand::Register(reg) => return Ok(rip_update(context.get_regspec(reg)?)),
                        other_operand => {
                            // If the operand was some sort of register dereference, try to get the
                            // _actual_ address from the memory list.
                            if let Some(op_info) =
                                MemoryOperandInfo::try_from_operand(other_operand)
                            {
                                let memory_address =
                                    MemoryAddressInfo::from_memory_operand_info(op_info, context)?
                                        .address;
                                if let Some(address) = memory_list
                                    .and_then(|ml| ml.memory_at_address(memory_address))
                                    .and_then(|mem| {
                                        mem.get_memory_at_address::<u64>(memory_address)
                                    })
                                {
                                    return Ok(rip_update(address));
                                }
                            }
                        }
                    }
                }
                Opcode::RETURN | Opcode::RETF | Opcode::IRET | Opcode::IRETD | Opcode::IRETQ => {
                    // Use the return address (from the stack)
                    if let (Ok(rsp), Some(stack)) =
                        (context.get_regspec(RegSpec::rsp()), &stack_memory)
                    {
                        if let Some(address) = stack.get_memory_at_address::<u64>(rsp) {
                            return Ok(rip_update(address));
                        }
                    }
                }
                _ => (),
            }
            Ok(None)
        }
    }

    #[derive(Copy, Clone)]
    #[allow(clippy::upper_case_acronyms)]
    enum CommonOpcode {
        ADD,
        CALL,
        CMP,
        DEC,
        IRET,
        IRETD,
        IRETQ,
        INC,
        JMP,
        JMPF,
        LEA,
        MOV,
        MOVAPS,
        MOVUPS,
        POP,
        PUSH,
        RETF,
        RETURN,
        SUB,
    }

    impl CommonOpcode {
        fn from_amd64_opcode(opcode: Opcode) -> Option<Self> {
            match opcode {
                Opcode::ADD => Some(Self::ADD),
                Opcode::CALL => Some(Self::CALL),
                Opcode::CMP => Some(Self::CMP),
                Opcode::DEC => Some(Self::DEC),
                Opcode::IRET => Some(Self::IRET),
                Opcode::IRETD => Some(Self::IRETD),
                Opcode::IRETQ => Some(Self::IRETQ),
                Opcode::INC => Some(Self::INC),
                Opcode::JMP => Some(Self::JMP),
                Opcode::JMPF => Some(Self::JMPF),
                Opcode::LEA => Some(Self::LEA),
                Opcode::MOV => Some(Self::MOV),
                Opcode::MOVAPS => Some(Self::MOVAPS),
                Opcode::MOVUPS => Some(Self::MOVUPS),
                Opcode::POP => Some(Self::POP),
                Opcode::PUSH => Some(Self::PUSH),
                Opcode::RETF => Some(Self::RETF),
                Opcode::RETURN => Some(Self::RETURN),
                Opcode::SUB => Some(Self::SUB),
                _ => None,
            }
        }

        fn is_common(opcode: Opcode) -> bool {
            Self::from_amd64_opcode(opcode).is_some()
        }
    }

    #[derive(Default)]
    struct MemoryOperandInfo {
        pub base_reg: Option<RegSpec>,
        pub index_reg: Option<RegSpec>,
        pub scale: Option<u8>,
        // Reg operands disp are i32, Displacement operands are i64
        pub disp: Option<i64>,
    }

    impl MemoryOperandInfo {
        pub fn try_from_operand(op: Operand) -> Option<Self> {
            let mut info = MemoryOperandInfo::default();
            match op {
                Operand::DisplacementU32(disp) => info.disp = Some(disp as i32 as i64),
                Operand::DisplacementU64(disp) => info.disp = Some(disp as i64),
                Operand::RegDeref(base) => {
                    info.base_reg = Some(base);
                }
                Operand::RegDisp(base, disp) => {
                    info.base_reg = Some(base);
                    info.disp = Some(disp.into());
                }
                Operand::RegScale(index, scale) => {
                    info.index_reg = Some(index);
                    info.scale = Some(scale);
                }
                Operand::RegIndexBase(base, index) => {
                    info.base_reg = Some(base);
                    info.index_reg = Some(index);
                }
                Operand::RegIndexBaseDisp(base, index, disp) => {
                    info.base_reg = Some(base);
                    info.index_reg = Some(index);
                    info.disp = Some(disp.into());
                }
                Operand::RegScaleDisp(index, scale, disp) => {
                    info.index_reg = Some(index);
                    info.scale = Some(scale);
                    info.disp = Some(disp.into());
                }
                Operand::RegIndexBaseScale(base, index, scale) => {
                    info.base_reg = Some(base);
                    info.index_reg = Some(index);
                    info.scale = Some(scale);
                }
                Operand::RegIndexBaseScaleDisp(base, index, scale, disp) => {
                    info.base_reg = Some(base);
                    info.index_reg = Some(index);
                    info.scale = Some(scale);
                    info.disp = Some(disp.into());
                }
                _ => return None,
            }
            Some(info)
        }
    }

    impl MemoryAddressInfo {
        fn from_memory_operand_info(
            register_operand_info: MemoryOperandInfo,
            context: &MinidumpContext,
        ) -> Result<MemoryAddressInfo, OpAnalysisError> {
            let mut address_info = MemoryAddressInfo {
                address: 0,
                is_likely_null_pointer_dereference: false,
                is_likely_guard_page: false,
            };

            if let Some(reg) = register_operand_info.base_reg {
                let base = context.get_regspec(reg)?;
                address_info.address = base;
                // If the base contains zero, this is very likely a dereference of a null pointer
                // plus an offset
                if base == 0 {
                    address_info.is_likely_null_pointer_dereference = true;
                }
            }

            if let Some(reg) = register_operand_info.index_reg {
                let index = context.get_regspec(reg)?;
                let scale = register_operand_info.scale.unwrap_or(1);
                let scaled_index = index.wrapping_mul(scale.into());
                address_info.address = address_info.address.wrapping_add(scaled_index);
            }

            let disp = register_operand_info.disp.unwrap_or(0) as u64;
            address_info.address = address_info.address.wrapping_add(disp);

            Ok(address_info)
        }
    }

    trait ContextExt {
        fn get_regspec(&self, regspec: RegSpec) -> Result<u64, OpAnalysisError>;
    }

    impl ContextExt for MinidumpContext {
        fn get_regspec(&self, regspec: RegSpec) -> Result<u64, OpAnalysisError> {
            self.get_register(regspec.name())
                .ok_or(OpAnalysisError::RegisterInvalid)
        }
    }

    fn get_registers(i: Instruction) -> BTreeSet<&'static str> {
        let mut ret = BTreeSet::new();
        for op in 0..i.operand_count() {
            if let Some(reginfo) = MemoryOperandInfo::try_from_operand(i.operand(op)) {
                if let Some(reg) = reginfo.base_reg {
                    ret.insert(reg.name());
                }
                if let Some(reg) = reginfo.index_reg {
                    ret.insert(reg.name());
                }
            }
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "disasm_amd64")]
    mod amd64 {
        use minidump::{format::CONTEXT_AMD64, CpuContext, MinidumpContext, MinidumpRawContext};

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

            let op_analysis =
                crate::op_analysis::amd64::analyze_instruction(&context, data.bytes, None, None)
                    .unwrap();

            let memory_accesses = op_analysis.memory_accesses.unwrap();

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
                if !expected_set.remove(&access.address_info.address) {
                    panic!(
                        "unexpected memory address found in instruction:\n{}\nexpected:\n{:?}\n",
                        access.address_info.address, expected_set
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
