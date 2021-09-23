// This file implements support for breakpad's text-based STACK CFI and STACK WIN
// unwinding instructions. These instructions are provided in "lines" corresponding
// to all the instructions for restoring the registers at a given address in the
// module.
//
// See also [the upstream breakpad docs](https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/symbol_files.md).
//
//
//
// # STACK CFI
//
// STACK CFI lines comes in two forms:
//
// `STACK CFI INIT instruction_address num_bytes registers`
//
// `STACK CFI instruction_address registers`
//
//
// A `STACK CFI INIT` line specifies how to restore registers for the given
// range of addresses.
//
// Example: `STACK CFI INIT 804c4b0 40 .cfa: $esp 4 + $eip: .cfa 4 - ^`
//
// Arguments:
//   * instruction_address (hex u64) is the first address in the module this line applies to
//   * num_bytes (hex u64) is the number of bytes it (and its child STACK CFI lines) covers
//   * registers (string) is the register restoring instructions (see the next section)
//
//
// A `STACK CFI` line always follows a "parent" `STACK CFI INIT` line. It
// updates the instructions on how to restore registers for anything within
// the parent STACK CFI INIT's range after the given address (inclusive).
// It only specifies rules for registers that have new instructions.
//
// To get the final rules for a given address, start with its `STACK CFI INIT`
// and then apply all the applicable `STACK CFI` "diffs" in order.
//
// Example: `STACK CFI 804c4b1 .cfa: $esp 8 + $ebp: .cfa 8 - ^`
//
// Arguments:
//   * instruction_address (hex u64) is the first address to apply these instructions
//   * registers (string) is the new register restoring instructions (see the next section)
//
//
//
// ## STACK CFI registers
//
// A line's STACK CFI registers are of the form
//
// `REG: EXPR REG: EXPR REG: EXPR...`
//
// Where REG is .cfa, .ra, or $<any alphanumerics>
// And EXPR is <anything but ":"> (see next section for details)
//
// Each `REG: EXPR` pair specifies how to compute the register REG for the
// caller. There are three kinds of registers:
//
// * $XXX refers to an actual general-purpose register. In REG position it
//   refers to the caller, in an EXPR it refers to the callee.
//
// * .cfa is the "canonical frame address" (CFA), as used in DWARF CFI. It
//   abstractly represents the base address of the frame. On x86, x64, and
//   ARM64 the CFA is the caller's stack pointer from *before* the call. As
//   such on those platforms you will never see instructions to restore the
//   frame pointer -- it must be implicitly restored from the cfa. .cfa
//   always refers to the caller, and therefore must be computed without
//   use of itself.
//
// * .ra is the "return address", which just abstractly refers to the
//   instruction pointer/program counter. It only ever appears in REG
//   position.
//
// .cfa and .ra must always have defined rules, or the STACK CFI is malformed.
//
// The CFA is special because its computed value can be used by every other EXPR.
// As such it should always be computed first so that its value is available.
// The purpose of the CFA is to cleanly handle the very common case of registers
// saved to the stack. Every register saved this way lives at a fixed offset
// from the start of the frame. So we can specify their rules once, and just
// update the CFA.
//
// For example:
//
// ```text
// STACK CFI INIT 0x10 16 .cfa: $rsp 8 + .ra: .cfa -8 + ^
// STACK CFI 0x11 .cfa: $rsp 16 + $rax: .cfa -16 + ^
// STACK CFI 0x12 .cfa: $rsp 24 +
// ```
//
// Can be understood as (pseudo-rust):
//
// ```rust,ignore
// let mut cfa = 0;
// let mut ra = None;
// let mut caller_rax = None;
//
//
// // STACK CFI INIT 0x10's original state
// cfa = callee_rsp + 8;
// ra = Some(|| { *(cfa - 8) });            // Defer evaluation
//
//
// // STACK CFI 0x11's diff
// if address >= 0x11 {
//   cfa = callee_rsp + 16;
//   caller_rax = Some(|| { *(cfa - 16) }); // Defer evaluation
// }
//
//
// // STACK CFI 0x12's diff
// if address >= 0x12 {
//   cfa = callee_rsp + 24;
// }
//
// caller.stack_pointer = cfa;
//
// // Finally evaluate all other registers using the current cfa
// caller.instruction_pointer = ra.unwrap()();
// caller.rax = caller_rax.map(|func| func());
// ```
//
//
//
// ## STACK CFI expressions
//
// STACK CFI expressions are in postfix (Reverse Polish) notation with tokens
// separated by whitespace. e.g.
//
//   .cfa $rsp 3 + * ^
//
// Is the postfix form of
//
//   ^(.cfa * ($rsp + 3))
//
// The benefit of postfix notation is that it can be evaluated while
// processing the input left-to-right without needing to maintain any
// kind of parse tree.
//
// The only state a postfix evaluator needs to maintain is a stack of
// computed values. When a value (see below) is encountered, it is pushed
// onto the stack. When an operator (see below) is encountered, it can be
// evaluated immediately by popping its inputs off the stack and pushing
// its output onto the stack.
//
// If the postfix expression is valid, then at the end of the token
// stream the stack should contain a single value, which is the result.
//
// For binary operators the right-hand-side (rhs) will be the first
// value popped from the stack.
//
// Supported operations are:
//
// * `+`: Binary Add
// * `-`: Binary Subtract
// * `*`: Binary Multiply
// * `/`: Binary Divide
// * `%`: Binary Remainder
// * `@`: Binary Align (truncate lhs to be a multiple of rhs)
// * `^`: Unary Dereference (load from stack memory)
//
// Supported values are:
//
// * .cfa: read the CFA
// * .undef: terminate execution, the output is explicitly unknown
// * $<anything>: read a general purpose register from the callee's frame
// * <a signed decimal integer>: read this integer constant (limited to i64 precision)
//
//
//
//
//
// # STACK WIN
//
// STACK WIN lines try to encode the more complex unwinding rules produced by
// x86 Windows toolchains.
//
// TODO: flesh this out
//
// ```text
// STACK WIN type rva code_size prologue_size epilogue_size parameter_size
//           saved_register_size local_size max_stack_size has_program_string
//           program_string_OR_allocates_base_pointer
// ```
//
// ```
// grand_callee_parameter_size = frame.callee.parameter_size
// frame_size = local_size + saved_register_size + grand_callee_parameter_size
// ```
//
//
//
// # STACK WIN frame pointer mode ("fpo")
//
// TODO: fill this in
//
// This is an older mode that just assumes a standard calling convention
// and a known frame size. Restore eip from the stack, restore ebp from
// the stack if necessary (allocates_base_pointer), add the frame size to
// get the new esp.
//
//
//
// # STACK WIN expression mode ("framedata")
//
// STACK WIN expressions use many of the same concepts as STACK CFI, but rather
// than using `REG: EXPR` pairs to specify outputs, it maintains a map of variables
// whose values can be read and written by each expression.
//
// I personally find this easiest to understand as an extension to the STACK CFI
// expressions, so I'll describe it in those terms:
//
// The supported operations add one binary operation:
//
// * `=`: Binary Assign (assign the rhs's integer to the lhs's variable)
//
// This operation requires us to have a distinction between *integers* and
// *variables*, which the postfix evaluator's stack must hold.
//
// All other operators operate only on integers. If a variable is passed where
// an integer is expected, that means the current value of the variable should
// be used.
//
// "values" then become:
//
// * .<anything>: a variable containing some initial constants (see below)
// * $<anything>: a variable representing a general purpose register or temporary
// * .undef: delete the variable if this is assigned to it (like Option::None) (TODO: ?)
// * <a signed decimal integer>: read this integer constant (limited to i64 precision)
//
//
// Before evaluating a STACK WIN expression:
//
// * The variables `$ebp` and `$esp` should be initialized from the callee's
//   values for those registers (error out if those are unknown). Breakpad
//   also initializes `$ebx` if it's available, since some things want it.
//
// * The following constant variables should be set accordingly:
//   * `.cbParams = parameter_size`
//   * `.cbCalleeParams = grand_callee_parameter_size` (only for breakpad-generated exprs)
//   * `.cbSavedRegs = saved_register_size`
//   * `.cbLocals = local_size`
//
// * The variables `.raSearch` and `.raSearchStart` should be set to the address
//   on the stack to begin scanning for a return address. This roughly corresponds
//   to the STACK CFI's `.cfa`. Breakpad computes this with a ton of messy heuristics,
//   but as a starting point `$esp + frame_size` is a good value.
//
//
// After evaluating a STACK WIN expression:
//
// The caller's registers are stored in `$eip`, `$esp`, `$ebp`, `$ebx`, `$esi`,
// and `$edi`. If those variables are undefined, then their values in the caller
// are unknown.
//
// TODO: do we need to track if ebp/esp/ebx were re-written, or is it fine to
// consider them defined if they weren't explicitly set to .undef?
//
// TODO: should it be an error if the stack isn't empty at the end? It's
// arguably malformed input but also it doesn't matter since the output is
// in the variables.
//
//
//
// ## Example STACK WIN framedata evaluation
//
// Here is an example of framedata for a function with the standard prologue.
// Given the input:
//
// ```
// $T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + =
// ```
//
// and initial state:
//
// ```
// ebp: 16, esp: 1600
// ```
//
// Then evaluation proceeds as follows:
//
// ```
//   Token  |    Stack     |                       Vars
// ---------+--------------+----------------------------------------------------
//          |              | $ebp: 16,      $esp: 1600,
//   $T0    | $T0          | $ebp: 16,      $esp: 1600,
//   $ebp   | $T0 $ebp     | $ebp: 16,      $esp: 1600,
//   =      |              | $ebp: 16,      $esp: 1600,   $T0: 16,
//   $eip   | $eip         | $ebp: 16,      $esp: 1600,   $T0: 16,
//   $T0    | $eip $T0     | $ebp: 16,      $esp: 1600,   $T0: 16,
//   4      | $eip $T0 4   | $ebp: 16,      $esp: 1600,   $T0: 16,
//   +      | $eip 20      | $ebp: 16,      $esp: 1600,   $T0: 16,
//   ^      | $eip (*20)   | $ebp: 16,      $esp: 1600,   $T0: 16,
//   =      |              | $ebp: 16,      $esp: 1600,   $T0: 16,   $eip: (*20)
//   $ebp   | $ebp         | $ebp: 16,      $esp: 1600,   $T0: 16,   $eip: (*20)
//   $T0    | $ebp $T0     | $ebp: 16,      $esp: 1600,   $T0: 16,   $eip: (*20)
//   ^      | $ebp (*16)   | $ebp: 16,      $esp: 1600,   $T0: 16,   $eip: (*20)
//   =      |              | $ebp: (*16),   $esp: 1600,   $T0: 16,   $eip: (*20)
//   $esp   | $esp         | $ebp: (*16),   $esp: 1600,   $T0: 16,   $eip: (*20)
//   $T0    | $esp $T0     | $ebp: (*16),   $esp: 1600,   $T0: 16,   $eip: (*20)
//   8      | $esp $T0 8   | $ebp: (*16),   $esp: 1600,   $T0: 16,   $eip: (*20)
//   +      | $esp 24      | $ebp: (*16),   $esp: 1600,   $T0: 16,   $eip: (*20)
//   =      |              | $ebp: (*16),   $esp: 24,     $T0: 16,   $eip: (*20)
// ```
//
// Giving a final output of `ebp=(*16)`, `esp=24`, `eip=(*20)`.

use super::{CfiRules, StackInfoWin, WinStackThing};
use crate::FrameWalker;
use log::{debug, trace};
use std::collections::HashMap;
use std::str::FromStr;

pub fn walk_with_stack_cfi(
    init: &CfiRules,
    additional: &[CfiRules],
    walker: &mut dyn FrameWalker,
) -> Option<()> {
    trace!("  ...got cfi");
    trace!("    {}", init.rules);
    for line in additional {
        trace!("    {}", line.rules);
    }

    // First we must collect up all the `REG: EXPR` pairs in these lines.
    // If a REG occurs twice, we prefer the one that comes later. This allows
    // STACK CFI records to apply incremental updates to the instructions.
    let mut exprs = HashMap::new();
    parse_cfi_exprs(&init.rules, &mut exprs)?;
    for line in additional {
        parse_cfi_exprs(&line.rules, &mut exprs)?;
    }
    trace!("  ...parsed exprs");
    trace!("    {:?}", exprs);

    // These two are special and *must* always be present
    let cfa_expr = exprs.remove(&CfiReg::Cfa)?;
    let ra_expr = exprs.remove(&CfiReg::Ra)?;
    trace!("  ...had cfa and ra");

    // Evaluating the CFA cannot itself use the CFA
    let cfa = eval_cfi_expr(cfa_expr, walker, None)?;
    let ra = eval_cfi_expr(ra_expr, walker, Some(cfa))?;
    trace!("  ...eval'd cfa and ra");

    walker.set_cfa(cfa)?;
    walker.set_ra(ra)?;

    for (reg, expr) in exprs {
        if let CfiReg::Other(reg) = reg {
            // If this eval fails, just don't emit this particular register
            // and keep going on. It's fine to lose some general purpose regs,
            // but make sure to clear it in case it would have been implicitly
            // forwarded from the callee.
            match eval_cfi_expr(expr, walker, Some(cfa)) {
                Some(val) => {
                    walker.set_caller_register(reg, val);
                }
                None => {
                    walker.clear_caller_register(reg);
                }
            }
        } else {
            // All special registers should already have been removed??
            unreachable!()
        }
    }
    trace!("  ...eval'd all regs");
    trace!("  ...success!");

    Some(())
}

fn parse_cfi_exprs<'a>(input: &'a str, output: &mut HashMap<CfiReg<'a>, &'a str>) -> Option<()> {
    // Note this is an ascii format so we can think chars == bytes!

    let base_addr = input.as_ptr() as usize;
    let mut cur_reg = None;
    let mut expr_first: Option<&str> = None;
    let mut expr_last: Option<&str> = None;
    for token in input.split_ascii_whitespace() {
        if let Some(token) = token.strip_suffix(':') {
            // This token is a "REG:", indicating the end of the previous EXPR
            // and start of the next. If we already have an active register,
            // then now is the time to commit it to our output.
            if let Some(reg) = cur_reg {
                // We compute the the expr substring by just abusing the fact that rust substrings
                // point into the original string, so we can use map addresses in the substrings
                // back into indices into the original string.
                let min_addr = expr_first?.as_ptr() as usize;
                let max_addr = expr_last?.as_ptr() as usize + expr_last?.len();
                let expr = &input[min_addr - base_addr..max_addr - base_addr];

                // Intentionally overwrite any pre-existing entries for this register,
                // because that's how CFI records work.
                output.insert(reg, expr);

                expr_first = None;
                expr_last = None;
            }

            cur_reg = if token == ".cfa" {
                Some(CfiReg::Cfa)
            } else if token == ".ra" {
                Some(CfiReg::Ra)
            } else if let Some(token) = token.strip_prefix('$') {
                // x86-style $rax register
                Some(CfiReg::Other(token))
            } else {
                // arm-style x11 register
                Some(CfiReg::Other(token))
            };
        } else {
            // First token *must* be a register!
            cur_reg.as_ref()?;

            // This is just another part of the current EXPR, update first/last accordingly.
            if expr_first.is_none() {
                expr_first = Some(token);
            }
            expr_last = Some(token);
        }
    }

    // Process the final rule (there must be a defined reg!)
    let min_addr = expr_first?.as_ptr() as usize;
    let max_addr = expr_last?.as_ptr() as usize + expr_last?.len();
    let expr = &input[min_addr - base_addr..max_addr - base_addr];

    output.insert(cur_reg?, expr);

    Some(())
}

fn eval_cfi_expr(expr: &str, walker: &mut dyn FrameWalker, cfa: Option<u64>) -> Option<u64> {
    // TODO: this should be an ArrayVec or something, most exprs are simple.
    let mut stack: Vec<u64> = Vec::new();
    for token in expr.split_ascii_whitespace() {
        match token {
            // TODO: not sure what overflow/sign semantics are
            "+" => {
                // Add
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                stack.push(lhs.wrapping_add(rhs));
            }
            "-" => {
                // Subtract
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                stack.push(lhs.wrapping_sub(rhs));
            }
            "*" => {
                // Multiply
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                stack.push(lhs.wrapping_mul(rhs));
            }
            "/" => {
                // Divide
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                if rhs == 0 {
                    // Div by 0
                    return None;
                }
                stack.push(lhs.wrapping_div(rhs));
            }
            "%" => {
                // Remainder
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                if rhs == 0 {
                    // Div by 0
                    return None;
                }
                stack.push(lhs.wrapping_rem(rhs));
            }
            "@" => {
                // Align (truncate)
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;

                if rhs == 0 || !rhs.is_power_of_two() {
                    return None;
                }

                // ~Bit Magic Corner~
                //
                // A power of two has only one bit set (e.g. 4 is 0b100), and
                // subtracting 1 from that gets you all 1's below that bit (e.g. 0b011).
                // -1 is all 1's.
                //
                // So XORing -1 with (power_of_2 - 1) gets you all ones except
                // for the bits lower than the power of 2. ANDing that value
                // to a number consequently makes it a multiple of that power
                // of two (all the bits smaller than the power are cleared).
                stack.push(lhs & (-1i64 as u64 ^ (rhs - 1)))
            }
            "^" => {
                // Deref the value
                let ptr = stack.pop()?;
                stack.push(walker.get_register_at_address(ptr)?);
            }
            ".cfa" => {
                // Push the CFA. Note the CFA shouldn't be used to compute
                // itself, so this returns None if that happens.
                stack.push(cfa?);
            }
            ".undef" => {
                // This register is explicitly undefined!
                return None;
            }
            _ => {
                // More complex cases
                if let Some((_, reg)) = token.split_once('$') {
                    // Push a register
                    stack.push(walker.get_callee_register(reg)?);
                } else if let Ok(value) = i64::from_str(token) {
                    // Push a constant
                    // TODO: We do everything in wrapping arithmetic, so it's fine to squash
                    // i64's into u64's?
                    stack.push(value as u64)
                } else if let Some(reg) = walker.get_callee_register(token) {
                    // Maybe the register just didn't have a $ prefix?
                    // (seems to be how ARM syntax works).
                    stack.push(reg);
                } else {
                    // Unknown expr
                    debug!(
                        "STACK CFI expression eval failed - unknown token: {}",
                        token
                    );
                    return None;
                }
            }
        }
    }

    if stack.len() == 1 {
        stack.pop()
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CfiReg<'a> {
    Cfa,
    Ra,
    Other(&'a str),
}

fn eval_win_expr(expr: &str, info: &StackInfoWin, walker: &mut dyn FrameWalker) -> Option<()> {
    // TODO: do a bunch of heuristics to make this more robust.

    let mut vars = HashMap::new();

    let callee_esp = walker.get_callee_register("esp")? as u32;
    let callee_ebp = walker.get_callee_register("ebp")? as u32;
    let grand_callee_param_size = walker.get_grand_callee_parameter_size();
    let frame_size = win_frame_size(info, grand_callee_param_size);

    // First setup the initial variables
    vars.insert("$esp", callee_esp);
    vars.insert("$ebp", callee_ebp);
    if let Some(callee_ebx) = walker.get_callee_register("ebx") {
        vars.insert("$ebx", callee_ebx as u32);
    }

    let search_start = callee_esp + frame_size;

    trace!(
        "    raSearchStart: 0x{:08x} (0x{:08x}, 0x{:08x}, 0x{:08x})",
        search_start,
        grand_callee_param_size,
        info.local_size,
        info.saved_register_size
    );

    // Magic names from breakpad
    vars.insert(".cbParams", info.parameter_size);
    vars.insert(".cbCalleeParams", grand_callee_param_size);
    vars.insert(".cbSavedRegs", info.saved_register_size);
    vars.insert(".cbLocals", info.local_size);
    vars.insert(".raSearch", search_start);
    vars.insert(".raSearchStart", search_start);

    // TODO: this should be an ArrayVec or something..?
    let mut stack: Vec<WinVal> = Vec::new();

    // TODO: handle the bug where "= NEXT_TOKEN" is sometimes "=NEXT_TOKEN"
    // for some windows toolchains.

    // Evaluate the expressions
    for token in expr.split_ascii_whitespace() {
        trace!("    ...token: {}", token);
        match token {
            // TODO: not sure what overflow/sign semantics are
            "+" => {
                // Add
                let rhs = stack.pop()?.into_int(&vars)?;
                let lhs = stack.pop()?.into_int(&vars)?;
                stack.push(WinVal::Int(lhs.wrapping_add(rhs)));
            }
            "-" => {
                // Subtract
                let rhs = stack.pop()?.into_int(&vars)?;
                let lhs = stack.pop()?.into_int(&vars)?;
                stack.push(WinVal::Int(lhs.wrapping_sub(rhs)));
            }
            "*" => {
                // Multiply
                let rhs = stack.pop()?.into_int(&vars)?;
                let lhs = stack.pop()?.into_int(&vars)?;
                stack.push(WinVal::Int(lhs.wrapping_mul(rhs)));
            }
            "/" => {
                // Divide
                let rhs = stack.pop()?.into_int(&vars)?;
                let lhs = stack.pop()?.into_int(&vars)?;
                if rhs == 0 {
                    // Div by 0
                    return None;
                }
                stack.push(WinVal::Int(lhs.wrapping_div(rhs)));
            }
            "%" => {
                // Remainder
                let rhs = stack.pop()?.into_int(&vars)?;
                let lhs = stack.pop()?.into_int(&vars)?;
                if rhs == 0 {
                    // Div by 0
                    return None;
                }
                stack.push(WinVal::Int(lhs.wrapping_rem(rhs)));
            }
            "@" => {
                // Align (truncate)
                let rhs = stack.pop()?.into_int(&vars)?;
                let lhs = stack.pop()?.into_int(&vars)?;

                if rhs == 0 || !rhs.is_power_of_two() {
                    return None;
                }

                // ~Bit Magic Corner~
                //
                // A power of two has only one bit set (e.g. 4 is 0b100), and
                // subtracting 1 from that gets you all 1's below that bit (e.g. 0b011).
                // -1 is all 1's.
                //
                // So XORing -1 with (power_of_2 - 1) gets you all ones except
                // for the bits lower than the power of 2. ANDing that value
                // to a number consequently makes it a multiple of that power
                // of two (all the bits smaller than the power are cleared).
                stack.push(WinVal::Int(lhs & (-1i32 as u32 ^ (rhs - 1))));
            }
            "=" => {
                // Assign lhs = rhs
                let rhs = stack.pop()?;
                let lhs = stack.pop()?.into_var()?;

                if let WinVal::Undef = rhs {
                    vars.remove(&lhs);
                } else {
                    vars.insert(lhs, rhs.into_int(&vars)?);
                }
            }
            "^" => {
                // Deref the value
                let ptr = stack.pop()?.into_int(&vars)?;
                stack.push(WinVal::Int(
                    walker.get_register_at_address(ptr as u64)? as u32
                ));
            }
            ".undef" => {
                // This register is explicitly undefined!
                stack.push(WinVal::Undef);
            }
            _ => {
                // More complex cases
                if token == ".undef" {
                    stack.push(WinVal::Undef);
                } else if token.starts_with('$') || token.starts_with('.') {
                    // Push a register
                    stack.push(WinVal::Var(token));
                } else if let Ok(value) = i32::from_str(token) {
                    // Push a constant
                    // TODO: We do everything in wrapping arithmetic, so it's fine to squash
                    // i32's into u32's?
                    stack.push(WinVal::Int(value as u32));
                } else {
                    // Unknown expr
                    debug!(
                        "STACK CFI expression eval failed - unknown token: {}",
                        token
                    );
                    return None;
                }
            }
        }
    }

    trace!("  ...eval'd expr");
    // panic!();

    let output_regs = ["$eip", "$esp", "$ebp", "$ebx", "$esi", "$edi"];
    for reg in &output_regs {
        if let Some(&val) = vars.get(reg) {
            walker.set_caller_register(&reg[1..], val as u64)?;
        }
    }

    trace!("  ...success!");

    Some(())
}

fn win_frame_size(info: &StackInfoWin, grand_callee_param_size: u32) -> u32 {
    info.local_size + info.saved_register_size + grand_callee_param_size
}

enum WinVal<'a> {
    Var(&'a str),
    Int(u32),
    Undef,
}

impl<'a> WinVal<'a> {
    fn into_var(self) -> Option<&'a str> {
        if let WinVal::Var(var) = self {
            Some(var)
        } else {
            None
        }
    }
    fn into_int(self, map: &HashMap<&'a str, u32>) -> Option<u32> {
        match self {
            WinVal::Var(var) => map.get(&var).cloned(),
            WinVal::Int(int) => Some(int),
            WinVal::Undef => None,
        }
    }
}

pub fn walk_with_stack_win_framedata(
    info: &StackInfoWin,
    walker: &mut dyn FrameWalker,
) -> Option<()> {
    if let WinStackThing::ProgramString(ref expr) = info.program_string_or_base_pointer {
        trace!("   ...using stack win framedata: {}", expr);
        eval_win_expr(expr, info, walker)
    } else {
        unreachable!()
    }
}

pub fn walk_with_stack_win_fpo(info: &StackInfoWin, walker: &mut dyn FrameWalker) -> Option<()> {
    if let WinStackThing::AllocatesBasePointer(allocates_base_pointer) =
        info.program_string_or_base_pointer
    {
        // TODO: do a bunch of heuristics to make this more robust.

        trace!("  ...using stack win fpo");
        let grand_callee_param_size = walker.get_grand_callee_parameter_size();
        let frame_size = win_frame_size(info, grand_callee_param_size) as u64;

        let callee_esp = walker.get_callee_register("esp")?;
        trace!("  ...got callee esp");

        let eip_address = callee_esp + frame_size;
        let caller_eip = walker.get_register_at_address(eip_address)?;
        let caller_esp = callee_esp + frame_size + 4;

        trace!("  ...computed caller eip/esp");

        let caller_ebp = if allocates_base_pointer {
            let ebp_address =
                callee_esp + grand_callee_param_size as u64 + info.saved_register_size as u64 - 8;
            walker.get_register_at_address(ebp_address)?
        } else {
            // Per Breakpad: We also propagate %ebx through, as it is commonly unmodifed after
            // calling simple forwarding functions in ntdll (that are this non-EBP
            // using type). It's not clear that this is always correct, but it is
            // important for some functions to get a correct walk.
            if let Some(callee_ebx) = walker.get_callee_register("ebx") {
                walker.set_caller_register("ebx", callee_ebx)?;
            }

            walker.get_callee_register("ebp")?
        };
        trace!("  ...computed caller ebp");

        walker.set_caller_register("eip", caller_eip)?;
        walker.set_caller_register("esp", caller_esp)?;
        walker.set_caller_register("ebp", caller_ebp)?;

        trace!("  ...success!");
        Some(())
    } else {
        unreachable!()
    }
}

#[cfg(test)]
mod test {
    use super::super::types::{CfiRules, StackInfoWin, WinStackThing};
    use super::{eval_win_expr, walk_with_stack_cfi};
    use crate::FrameWalker;
    use std::collections::HashMap;

    // Eugh, need this to memoize register names to static
    static STATIC_REGS: [&str; 14] = [
        "cfa", "ra", "esp", "eip", "ebp", "eax", "ebx", "rsp", "rip", "rbp", "rax", "rbx", "x11",
        "x12",
    ];

    struct TestFrameWalker<Reg> {
        instruction: Reg,
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

    fn build_cfi_rules(init: &str, additional: &[&str]) -> (CfiRules, Vec<CfiRules>) {
        let init = CfiRules {
            address: 0,
            rules: init.to_string(),
        };
        let additional = additional
            .iter()
            .enumerate()
            .map(|(idx, rules)| CfiRules {
                address: idx as u64 + 1,
                rules: rules.to_string(),
            })
            .collect::<Vec<_>>();

        (init, additional)
    }

    #[test]
    fn test_stack_win_doc_example() {
        // Final output of `ebp=(*16)`, `esp=24`, `eip=(*20)`.
        let expr = "$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + =";
        let input = vec![("ebp", 16u32), ("esp", 1600)].into_iter().collect();
        let mut stack = vec![0; 1600];

        const FINAL_EBP: u32 = 0xFA1EF2E6;
        const FINAL_EIP: u32 = 0xB3EF04CE;

        stack[16..20].copy_from_slice(&FINAL_EBP.to_le_bytes());
        stack[20..24].copy_from_slice(&FINAL_EIP.to_le_bytes());

        let mut walker = TestFrameWalker::new(stack, input);
        let info = whatever_win_info();

        eval_win_expr(expr, &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 3);
        assert_eq!(walker.caller_regs["esp"], 24);
        assert_eq!(walker.caller_regs["ebp"], FINAL_EBP);
        assert_eq!(walker.caller_regs["eip"], FINAL_EIP);
    }

    #[test]
    fn test_stack_win_ops() {
        // Making sure all the operators do what they should.
        let input = vec![("esp", 32u32), ("ebp", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);
        let info = whatever_win_info();

        // Addition!
        walker.caller_regs.clear();
        eval_win_expr("$esp 1 2 + = $ebp -4 0 + =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 3);
        assert_eq!(walker.caller_regs["ebp"], -4i32 as u32);

        // Subtraction!
        walker.caller_regs.clear();
        eval_win_expr("$esp 5 3 - = $ebp -4 2 - =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 2);
        assert_eq!(walker.caller_regs["ebp"], -6i32 as u32);

        // Multiplication!
        walker.caller_regs.clear();
        eval_win_expr("$esp 5 3 * = $ebp -4 2 * =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 15);
        assert_eq!(walker.caller_regs["ebp"], -8i32 as u32);

        // Division!
        walker.caller_regs.clear();
        eval_win_expr("$esp 5 3 / = $ebp -4 2 / =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 1);
        // TODO: oh no this fails, u64/u32 mismatches ARE a problem...
        // assert_eq!(walker.caller_regs["ebp"], -2i32 as u32);

        // Modulo!
        walker.caller_regs.clear();
        eval_win_expr("$esp  5 3 %  = $ebp -1 2 % = ", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 2);
        assert_eq!(walker.caller_regs["ebp"], 1);

        // Align!
        walker.caller_regs.clear();
        eval_win_expr("$esp  8 16 @ = $ebp 161 8 @ = ", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 0);
        assert_eq!(walker.caller_regs["ebp"], 160);

        // Operator Errors - Missing Inputs

        // + missing args
        assert!(eval_win_expr("1 + ", &info, &mut walker).is_none());

        // - missing args
        assert!(eval_win_expr("1 -", &info, &mut walker).is_none());

        // * missing args
        assert!(eval_win_expr("1 *", &info, &mut walker).is_none());

        // / missing args
        assert!(eval_win_expr("1 /", &info, &mut walker).is_none());

        // % missing args
        assert!(eval_win_expr("1 %", &info, &mut walker).is_none());

        // @ missing args
        assert!(eval_win_expr("1 @", &info, &mut walker).is_none());

        // ^ missing arg
        assert!(eval_win_expr("^", &info, &mut walker).is_none());

        // Operator Errors - Invalid Inputs

        // / by 0
        assert!(eval_win_expr("$esp 1 0 / = $ebp 1 =", &info, &mut walker).is_none());

        // % by 0
        assert!(eval_win_expr("$esp 1 0 % = $ebp 1 =", &info, &mut walker).is_none());

        // @ by 0
        assert!(eval_win_expr("$esp 1 0 @ = $ebp 1 =", &info, &mut walker).is_none());

        // @ not power of 2
        assert!(eval_win_expr("$esp 1 3 @ = $ebp 1 =", &info, &mut walker).is_none());
    }

    #[test]
    fn test_stack_win_corners() {
        // Making sure all the operators do what they should.
        let input = vec![("esp", 32u32), ("ebp", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);
        let info = whatever_win_info();

        // Empty expression is ok, just forward through registers
        walker.caller_regs.clear();
        eval_win_expr("", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 32);
        assert_eq!(walker.caller_regs["ebp"], 1600);

        // Undef works
        walker.caller_regs.clear();
        eval_win_expr("$esp .undef = $ebp .undef =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 0);

        // Idempotent works
        walker.caller_regs.clear();
        eval_win_expr("$esp $esp = $ebp $ebp =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 32);
        assert_eq!(walker.caller_regs["ebp"], 1600);

        // Trailing garbage in the stack is ok
        walker.caller_regs.clear();
        eval_win_expr("$esp 1 = $ebp 2 = 3 4 5", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 1);
        assert_eq!(walker.caller_regs["ebp"], 2);

        // Trailing garbage in the stack is ok (with variables)
        walker.caller_regs.clear();
        eval_win_expr("$esp 1 = $ebp 2 = 3 4 5 $esp $eax", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 1);
        assert_eq!(walker.caller_regs["ebp"], 2);

        // Temporaries don't get assigned to output
        walker.caller_regs.clear();
        eval_win_expr("$t0 1 = $esp $t0 5 + = $ebp 2 =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 6);
        assert_eq!(walker.caller_regs["ebp"], 2);

        // Variables can be assigned after they are pushed
        walker.caller_regs.clear();
        eval_win_expr("$esp  $T0 $T0 2 = = $ebp 3 =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 2);
        assert_eq!(walker.caller_regs["ebp"], 3);
    }

    #[test]
    fn test_stack_win_errors() {
        // Making sure all the operators do what they should.
        let input = vec![("esp", 32u32), ("ebp", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);
        let info = whatever_win_info();

        // Deref out of bounds
        assert!(eval_win_expr("$esp 2000 ^ =", &info, &mut walker).is_none());

        // Reading undefined value
        assert!(eval_win_expr("$esp $kitties =", &info, &mut walker).is_none());

        // Reading value before defined
        assert!(eval_win_expr("$esp $kitties = $kitties 1 =", &info, &mut walker).is_none());

        // Reading deleted value
        assert!(eval_win_expr("$esp .undef = $ebp $esp =", &info, &mut walker).is_none());

        // Assigning value to value
        assert!(eval_win_expr("0 2 =", &info, &mut walker).is_none());

        // Assigning variable to value
        assert!(eval_win_expr("0 $esp =", &info, &mut walker).is_none());

        // Variables must start with $ or .
        assert!(eval_win_expr("esp 2 = ebp 3 =", &info, &mut walker).is_none());
    }

    #[test]
    #[ignore]
    fn test_stack_win_equal_fixup() {
        // Bug in old windows toolchains that sometimes cause = to lose
        // its trailing space. Although we would ideally reject this, we're
        // at the mercy of what toolchains emit :(

        // TODO: this test currently fails! (hence the #[ignore])

        let input = vec![("esp", 32u32), ("ebp", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);
        let info = whatever_win_info();

        eval_win_expr("$esp 1 =$ebp 2 =", &info, &mut walker).unwrap();
        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 1);
        assert_eq!(walker.caller_regs["ebp"], 2);
    }

    #[test]
    #[ignore]
    fn test_stack_win_negative_division() {
        // Negative division issues

        // TODO: this test currently fails! (hence the #[ignore])

        let input = vec![("esp", 32u32), ("ebp", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);
        let info = whatever_win_info();

        // Division!
        walker.caller_regs.clear();
        eval_win_expr("$esp 5 3 / = $ebp -4 2 / =", &info, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["esp"], 1);
        assert_eq!(walker.caller_regs["ebp"], -2i32 as u32);
    }

    #[test]
    fn test_stack_cfi_doc_example() {
        // Final output of:
        //
        // cfa = callee_rsp + 24
        // ra = *(cfa - 8)
        // rax = *(cfa - 16)

        let init = ".cfa: $rsp 8 + .ra: .cfa -8 + ^";
        let additional = &[".cfa: $rsp 16 + $rax: .cfa -16 + ^", ".cfa: $rsp 24 +"];
        let input = vec![("rsp", 32u64), ("rip", 1600)].into_iter().collect();
        let mut stack = vec![0; 1600];

        const FINAL_CFA: usize = 32 + 24;
        const FINAL_RA: u64 = 0xFA1E_F2E6_A2DF_2B68;
        const FINAL_RAX: u64 = 0xB3EF_04CE_4321_FE2A;

        stack[FINAL_CFA - 8..FINAL_CFA].copy_from_slice(&FINAL_RA.to_le_bytes());
        stack[FINAL_CFA - 16..FINAL_CFA - 8].copy_from_slice(&FINAL_RAX.to_le_bytes());

        let mut walker = TestFrameWalker::new(stack, input);
        let (init, additional) = build_cfi_rules(init, additional);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 3);
        assert_eq!(walker.caller_regs["cfa"], FINAL_CFA as u64);
        assert_eq!(walker.caller_regs["ra"], FINAL_RA);
        assert_eq!(walker.caller_regs["rax"], FINAL_RAX);
    }

    #[test]
    fn test_stack_cfi_ops() {
        // Making sure all the operators do what they should, using 32-bit
        // to stress truncation issues from u64 <-> u32 mapping of the
        // abstraction.
        let input = vec![("esp", 32u32), ("eip", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);

        // Addition!
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 1 2 + .ra: -4 0 +", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 3);
        assert_eq!(walker.caller_regs["ra"], -4i32 as u32);

        // Subtraction!
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 5 3 - .ra: -4 2 -", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 2);
        assert_eq!(walker.caller_regs["ra"], -6i32 as u32);

        // Multiplication!
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 5 3 * .ra: -4 2 *", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 15);
        assert_eq!(walker.caller_regs["ra"], -8i32 as u32);

        // Division!
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 5 3 / .ra: -4 2 /", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 1);
        assert_eq!(walker.caller_regs["ra"], -2i32 as u32);

        // Modulo!
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 5 3 % .ra: -1 2 %", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 2);
        assert_eq!(walker.caller_regs["ra"], 1);

        // Align!
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 8 16 @ .ra: 161 8 @", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 0);
        assert_eq!(walker.caller_regs["ra"], 160);

        // Operator Errors - Missing Inputs

        // + missing args
        let (init, additional) = build_cfi_rules(".cfa: 1 + .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // - missing args
        let (init, additional) = build_cfi_rules(".cfa: 1 - .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // * missing args
        let (init, additional) = build_cfi_rules(".cfa: 1 * .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // / missing args
        let (init, additional) = build_cfi_rules(".cfa: 1 / .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // % missing args
        let (init, additional) = build_cfi_rules(".cfa: 1 % .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // @ missing args
        let (init, additional) = build_cfi_rules(".cfa: 1 @ .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // ^ missing arg
        let (init, additional) = build_cfi_rules(".cfa: ^ .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Operator Errors - Invalid Inputs

        // / by 0
        let (init, additional) = build_cfi_rules(".cfa: 1 0 / .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // % by 0
        let (init, additional) = build_cfi_rules(".cfa: 1 0 % .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // @ by 0
        let (init, additional) = build_cfi_rules(".cfa: 1 0 @ .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // @ not power of 2
        let (init, additional) = build_cfi_rules(".cfa: 1 3 @ .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());
    }

    #[test]
    fn test_stack_cfi_errors() {
        // Checking various issues that we should bail on
        let input = vec![("rsp", 32u64), ("rip", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);

        // Basic syntax

        // Missing .ra
        let (init, additional) = build_cfi_rules(".cfa: 8 16 +", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Missing .cfa
        let (init, additional) = build_cfi_rules(".ra: 8 16 *", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // No : at all
        let (init, additional) = build_cfi_rules(".cfa 8 16 *", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Doesn't start with a REG
        let (init, additional) = build_cfi_rules(".esp 8 16 * .cfa: 16 .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // .cfa has extra junk on stack
        let (init, additional) = build_cfi_rules(".cfa: 8 12 .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // REG has empty expr (trailing)
        let (init, additional) = build_cfi_rules(".cfa: 12 .ra: 8 $rax:", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // REG has empty expr (trailing with space)
        let (init, additional) = build_cfi_rules(".cfa: 12 .ra: 8 $rax: ", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // REG has empty expr (middle)
        let (init, additional) = build_cfi_rules(".cfa: 12 .ra: 8 $rax: $rbx: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Make sure = operator isn't supported in this implementation
        let (init, additional) = build_cfi_rules(".cfa: 12 .ra: $rsp $rip =", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // .cfa is undef
        let (init, additional) = build_cfi_rules(".cfa: .undef .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // .ra is undef
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: .undef", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Reading out of bounds
        let (init, additional) = build_cfi_rules(".cfa: 2000 ^ .ra: 8", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Reading fake $reg
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: $kitties", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Reading real but still undefined $reg
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: $rax", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Reading .cfa for .cfa's own value
        let (init, additional) = build_cfi_rules(".cfa: .cfa .ra: 2", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Reading .ra for .cfa's value
        let (init, additional) = build_cfi_rules(".cfa: .ra .ra: 2", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Reading .ra for .ra's value
        let (init, additional) = build_cfi_rules(".cfa: 1 .ra: .ra", &[]);
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());

        // Malformed doc example shouldn't work (found while typoing docs)
        // Note the first .cfa in the additional lines has no `:`!
        let (init, additional) = build_cfi_rules(
            ".cfa: $rsp 8 + .ra: .cfa -8 + ^",
            &[".cfa $rsp 16 + $rax: .cfa -16 + ^", ".cfa $rsp 24 +"],
        );
        assert!(walk_with_stack_cfi(&init, &additional, &mut walker).is_none());
    }

    #[test]
    fn test_stack_cfi_corners() {
        // Checking various issues that we should bail on
        let input = vec![("rsp", 32u64), ("rip", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);

        // Just a value for each reg (no ops to execute)
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: 12 $rax: 16", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 3);
        assert_eq!(walker.caller_regs["cfa"], 8);
        assert_eq!(walker.caller_regs["ra"], 12);
        assert_eq!(walker.caller_regs["rax"], 16);

        // Undef $REGs are ok, Undef in the middle of expr ok
        walker.caller_regs.clear();
        let (init, additional) =
            build_cfi_rules(".cfa: 8 .ra: 12 $rax: .undef $rbx: 1 .undef +", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 8);
        assert_eq!(walker.caller_regs["ra"], 12);

        // Unknown $reg output is ok; evaluated but value discarded
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: 12 $kitties: 16", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 8);
        assert_eq!(walker.caller_regs["ra"], 12);

        // Smooshed regs are garbage but we don't validate the string so it should work
        // the same as an unknown reg (dubious behaviour but hey let's be aware of it).
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 12 .ra: 8 $rax:$rbx: 8", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 12);
        assert_eq!(walker.caller_regs["ra"], 8);

        // Evaluation errors for $reg output ok; value is discarded
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 1 .ra: 8 $rax: 1 0 /", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 1);
        assert_eq!(walker.caller_regs["ra"], 8);

        // Duplicate records are ok (use the later one)
        walker.caller_regs.clear();
        let (init, additional) =
            build_cfi_rules(".cfa: 1 .cfa: 2 .ra: 3 .ra: 4 $rax: 5 $rax: 6", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 3);
        assert_eq!(walker.caller_regs["cfa"], 2);
        assert_eq!(walker.caller_regs["ra"], 4);
        assert_eq!(walker.caller_regs["rax"], 6);

        // Using .cfa works fine
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 7 .ra: .cfa 1 + $rax: .cfa 2 -", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 3);
        assert_eq!(walker.caller_regs["cfa"], 7);
        assert_eq!(walker.caller_regs["ra"], 8);
        assert_eq!(walker.caller_regs["rax"], 5);

        // Reading .ra for $REG's value is ok; value is discarded
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 1 .ra: 2 $rax: .ra", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 1);
        assert_eq!(walker.caller_regs["ra"], 2);

        // Undefined destination .reg is assumed to be an ARM-style register, is dropped
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: 12 .kitties: 16", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();
        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 8);
        assert_eq!(walker.caller_regs["ra"], 12);

        // Trying to write to .undef is assumed to be an ARM-style register, is dropped
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: 12 .undef: 16", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();
        assert_eq!(walker.caller_regs.len(), 2);
        assert_eq!(walker.caller_regs["cfa"], 8);
        assert_eq!(walker.caller_regs["ra"], 12);
    }

    #[test]
    fn test_stack_cfi_arm() {
        // ARM doesn't prefix registers with $
        // Checking various issues that we should bail on
        let input = vec![("pc", 32u64), ("x11", 1600)].into_iter().collect();
        let stack = vec![0; 1600];

        let mut walker = TestFrameWalker::new(stack, input);

        // Just a value for each reg (no ops to execute)
        walker.caller_regs.clear();
        let (init, additional) = build_cfi_rules(".cfa: 8 .ra: 12 x11: 16 x12: x11 .cfa +", &[]);
        walk_with_stack_cfi(&init, &additional, &mut walker).unwrap();

        assert_eq!(walker.caller_regs.len(), 4);
        assert_eq!(walker.caller_regs["cfa"], 8);
        assert_eq!(walker.caller_regs["ra"], 12);
        assert_eq!(walker.caller_regs["x11"], 16);
        assert_eq!(walker.caller_regs["x12"], 1608);
    }
}
