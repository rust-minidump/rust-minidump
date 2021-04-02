// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use range_map::{Range, RangeMap};
use std::cmp::Ordering;
use std::collections::HashMap;

/// A publicly visible linker symbol.
#[derive(Debug, Eq, PartialEq)]
pub struct PublicSymbol {
    /// The symbol's address relative to the module's load address.
    pub address: u64,
    /// The size of parameters passed to the function.
    pub parameter_size: u32,
    /// The name of the symbol.
    pub name: String,
}

impl Ord for PublicSymbol {
    fn cmp(&self, other: &PublicSymbol) -> Ordering {
        let o = self.address.cmp(&other.address);
        if o != Ordering::Equal {
            o
        } else {
            // Fall back to sorting by name if addresses are equal.
            let nameo = self.name.cmp(&other.name);
            if nameo != Ordering::Equal {
                nameo
            } else {
                // Compare parameter size just for sanity.
                self.parameter_size.cmp(&other.parameter_size)
            }
        }
    }
}

impl PartialOrd for PublicSymbol {
    fn partial_cmp(&self, other: &PublicSymbol) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A mapping from machine code bytes to source line and file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLine {
    /// The start address relative to the module's load address.
    pub address: u64,
    /// The size of this range of instructions in bytes.
    pub size: u32,
    /// The source file name that generated this machine code.
    ///
    /// This is an index into `SymbolFile::files`.
    pub file: u32,
    /// The line number in `file` that generated this machine code.
    pub line: u32,
}

/// A source-language function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// The function's start address relative to the module's load address.
    pub address: u64,
    /// The size of the function in bytes.
    pub size: u32,
    /// The size of parameters passed to the function.
    pub parameter_size: u32,
    /// The name of the function as declared in the source.
    pub name: String,
    /// Source line information for this function.
    pub lines: RangeMap<u64, SourceLine>,
}

impl Function {
    pub fn memory_range(&self) -> Range<u64> {
        Range::new(self.address, self.address + self.size as u64 - 1)
    }
}

/// DWARF CFI rules for recovering registers at a specific address.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CfiRules {
    /// The address in question.
    pub address: u64,
    /// Postfix expressions to evaluate to recover register values.
    pub rules: String,
}

/// Information used for unwinding stack frames using DWARF CFI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackInfoCfi {
    /// The initial rules for this address range.
    pub init: CfiRules,
    /// The size of this entire address range.
    pub size: u32,
    /// Additional rules to use at specified addresses.
    pub add_rules: Vec<CfiRules>,
}

impl StackInfoCfi {
    pub fn memory_range(&self) -> Range<u64> {
        Range::new(self.init.address, self.init.address + self.size as u64 - 1)
    }
}

/// Specific details about whether the frame uses a base pointer or has a program string to
/// evaluate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WinFrameType {
    /// This frame uses FPO-style data.
    Fpo(StackInfoWin),
    /// This frame uses new-style frame data, has a program string.
    FrameData(StackInfoWin),
    /// Some other type of frame.
    Unhandled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WinStackThing {
    ProgramString(String),
    AllocatesBasePointer(bool),
}

/// Information used for unwinding stack frames using Windows frame info.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackInfoWin {
    /// The address in question.
    pub address: u64,
    /// The size of the address range covered.
    pub size: u32,
    /// The size of the function's prologue.
    pub prologue_size: u32,
    /// The size of the function's epilogue.
    pub epilogue_size: u32,
    /// The size of arguments passed to this function.
    pub parameter_size: u32,
    /// The number of bytes in the stack frame for callee-saves registers.
    pub saved_register_size: u32,
    /// The number of bytes in the stack frame for local variables.
    pub local_size: u32,
    /// The maximum number of bytes pushed onto the stack by this frame.
    pub max_stack_size: u32,
    /// A program string or boolean regarding a base pointer.
    pub program_string_or_base_pointer: WinStackThing,
}

impl StackInfoWin {
    pub fn memory_range(&self) -> Range<u64> {
        Range::new(self.address, self.address + self.size as u64 - 1)
    }
}

/// A parsed .sym file containing debug symbols.
#[derive(Debug, PartialEq)]
pub struct SymbolFile {
    /// The set of source files involved in compilation.
    pub files: HashMap<u32, String>,
    /// Publicly visible symbols.
    pub publics: Vec<PublicSymbol>,
    /// Functions.
    pub functions: RangeMap<u64, Function>,
    /// DWARF CFI unwind information.
    pub cfi_stack_info: RangeMap<u64, StackInfoCfi>,
    /// Windows unwind information (frame data).
    pub win_stack_framedata_info: RangeMap<u64, StackInfoWin>,
    /// Windows unwind information (FPO data).
    pub win_stack_fpo_info: RangeMap<u64, StackInfoWin>,
}
