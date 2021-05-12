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
// STACK CFI 0x11 .cfa $rsp 16 + $rax: .cfa -16 + ^
// STACK CFI 0x12 .cfa $rsp 24 +
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
            // and keep going on. It's fine to lose some general purpose regs.
            eval_cfi_expr(expr, walker, Some(cfa))
                .and_then(|val| walker.set_caller_register(reg, val));
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
        if token.ends_with(':') {
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

            cur_reg = if token == ".cfa:" {
                Some(CfiReg::Cfa)
            } else if token == ".ra:" {
                Some(CfiReg::Ra)
            } else if token.starts_with('$') {
                Some(CfiReg::Other(&token[1..token.len() - 1]))
            } else {
                // Malformed register
                debug!(
                    "STACK CFI expression parsing failed - invalid register: {}",
                    token
                );
                return None;
            };
        } else {
            // This is just another part of the current EXPR, update first/last accordingly.
            if expr_first.is_none() {
                expr_first = Some(token);
            }
            expr_last = Some(token);
        }
    }

    // Process the final rule
    if let Some(reg) = cur_reg {
        let min_addr = expr_first?.as_ptr() as usize;
        let max_addr = expr_last?.as_ptr() as usize + expr_last?.len();
        let expr = &input[min_addr - base_addr..max_addr - base_addr];

        output.insert(reg, expr);
    }

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

                // NOTE: breakpad assumes rhs is a power of 2 and does
                // lhs & (-1 ^ (rhs - 1))
                stack.push(lhs.wrapping_div(rhs).wrapping_mul(rhs))
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

    trace!(
        "  ...got callee registers (frame_size: {}, raSearch: {})",
        frame_size,
        callee_esp + frame_size
    );

    // First setup the initial variables
    vars.insert("$esp", callee_esp);
    vars.insert("$ebp", callee_ebp);
    if let Some(callee_ebx) = walker.get_callee_register("ebx") {
        vars.insert("$ebx", callee_ebx as u32);
    }

    let search_start = callee_esp + frame_size;

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

                // NOTE: breakpad assumes rhs is a power of 2 and does
                // lhs & (-1 ^ (rhs - 1))
                stack.push(WinVal::Int(lhs.wrapping_div(rhs).wrapping_mul(rhs)));
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

#[allow(unused_variables, unreachable_code)]
pub fn walk_with_stack_win_framedata(
    info: &StackInfoWin,
    walker: &mut dyn FrameWalker,
) -> Option<()> {
    // Temporarily disabled while I iterate on this
    return None;

    if let WinStackThing::ProgramString(ref expr) = info.program_string_or_base_pointer {
        trace!("   ...using stack win framedata: {}", expr);
        eval_win_expr(expr, info, walker)
    } else {
        unreachable!()
    }
}

#[allow(unused_variables, unreachable_code)]
pub fn walk_with_stack_win_fpo(info: &StackInfoWin, walker: &mut dyn FrameWalker) -> Option<()> {
    // Temporarily disabled while I iterate on this
    return None;

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
