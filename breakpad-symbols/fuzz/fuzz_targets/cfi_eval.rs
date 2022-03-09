#![no_main]
use libfuzzer_sys::fuzz_target;

use breakpad_symbols::fuzzing_private_exports::{
    eval_win_expr_for_fuzzer, StackInfoWin, WinStackThing,
};
use breakpad_symbols::FrameWalker;
use std::collections::HashMap;

fuzz_target!(|data: ([u32; 14], &str)| {
    test_stack_win_doc_example(data.0, data.1);
});

// Eugh, need this to memoize register names to static
static STATIC_REGS: [&str; 14] = [
    "cfa", "ra", "esp", "eip", "ebp", "eax", "ebx", "rsp", "rip", "rbp", "rax", "rbx", "x11", "x12",
];

struct TestFrameWalker<Reg> {
    instruction: Reg,
    has_grand_callee: bool,
    grand_callee_param_size: u32,
    callee_regs: HashMap<&'static str, Reg>,
    caller_regs: HashMap<&'static str, Reg>,
    stack: Vec<u8>,
}

trait Int {
    const BYTES: usize;
    fn from_bytes(bytes: &[u8]) -> Self;
    fn into_u64(self) -> u64;
    fn from_u64(val: u64) -> Self;
}
impl Int for u32 {
    const BYTES: usize = 4;
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0; Self::BYTES];
        buf.copy_from_slice(bytes);
        u32::from_le_bytes(buf)
    }
    fn into_u64(self) -> u64 {
        self as u64
    }
    fn from_u64(val: u64) -> Self {
        val as u32
    }
}
impl Int for u64 {
    const BYTES: usize = 8;
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0; Self::BYTES];
        buf.copy_from_slice(bytes);
        u64::from_le_bytes(buf)
    }
    fn into_u64(self) -> u64 {
        self
    }
    fn from_u64(val: u64) -> Self {
        val
    }
}

impl<Reg: Int + Copy> FrameWalker for TestFrameWalker<Reg> {
    fn get_instruction(&self) -> u64 {
        self.instruction.into_u64()
    }
    fn has_grand_callee(&self) -> bool {
        self.has_grand_callee
    }
    fn get_grand_callee_parameter_size(&self) -> u32 {
        self.grand_callee_param_size
    }
    /// Get a register-sized value stored at this address.
    fn get_register_at_address(&self, address: u64) -> Option<u64> {
        let addr = address as usize;
        self.stack
            .get(addr..addr + Reg::BYTES)
            .map(|slice| Reg::from_bytes(slice).into_u64())
    }
    /// Get the value of a register from the callee's frame.
    fn get_callee_register(&self, name: &str) -> Option<u64> {
        self.callee_regs.get(name).map(|val| val.into_u64())
    }
    /// Set the value of a register for the caller's frame.
    fn set_caller_register(&mut self, name: &str, val: u64) -> Option<()> {
        STATIC_REGS.iter().position(|&reg| reg == name).map(|idx| {
            let memoized_reg = STATIC_REGS[idx];
            self.caller_regs.insert(memoized_reg, Reg::from_u64(val));
        })
    }
    fn clear_caller_register(&mut self, name: &str) {
        self.caller_regs.remove(name);
    }
    /// Set whatever registers in the caller should be set based on the cfa (e.g. rsp).
    fn set_cfa(&mut self, val: u64) -> Option<()> {
        self.caller_regs.insert("cfa", Reg::from_u64(val));
        Some(())
    }
    /// Set whatever registers in the caller should be set based on the return address (e.g. rip).
    fn set_ra(&mut self, val: u64) -> Option<()> {
        self.caller_regs.insert("ra", Reg::from_u64(val));
        Some(())
    }
}

impl<Reg: Int + Copy> TestFrameWalker<Reg> {
    fn new(stack: Vec<u8>, callee_regs: HashMap<&'static str, Reg>) -> Self {
        TestFrameWalker {
            stack,
            callee_regs,
            caller_regs: HashMap::new(),

            // Arbitrary values
            instruction: Reg::from_u64(0xF1CEFA32),
            has_grand_callee: true,
            grand_callee_param_size: 4,
        }
    }
}

/// Arbitrary default values in case needed.
fn whatever_win_info() -> StackInfoWin {
    StackInfoWin {
        address: 0xFEA4A123,
        size: 16,
        prologue_size: 4,
        epilogue_size: 8,
        parameter_size: 16,
        saved_register_size: 12,
        local_size: 24,
        max_stack_size: 64,
        program_string_or_base_pointer: WinStackThing::AllocatesBasePointer(false),
    }
}

fn test_stack_win_doc_example(regs: [u32; 14], expr: &str) {
    let input = STATIC_REGS
        .iter()
        .zip(regs)
        .map(|(&reg, val)| (reg, val))
        .collect();
    let mut stack = vec![0; 1600];

    const FINAL_EBP: u32 = 0xFA1EF2E6;
    const FINAL_EIP: u32 = 0xB3EF04CE;

    stack[16..20].copy_from_slice(&FINAL_EBP.to_le_bytes());
    stack[20..24].copy_from_slice(&FINAL_EIP.to_le_bytes());

    let mut walker = TestFrameWalker::new(stack, input);
    let info = whatever_win_info();

    eval_win_expr_for_fuzzer(expr, &info, &mut walker);
}
