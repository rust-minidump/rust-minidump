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
    // Parsing out "REG: EXPR REG: EXPR REG: EXPR..."
    //
    // Where REG is .cfa, .ra, or $<any alphanumerics>
    // And EXPR is <anything but ":">
    //
    // Also note this is an ascii format so we can think chars == bytes!

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
    // CFI expressions are in postfix (Reverse Polish) notation with tokens
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
    // STACK WIN may use a more complex extension of this that involves a map
    // of variables that can be assigned to with a "=" operator, but that
    // shouldn't happen with STACK CFI, so that isn't implemented here (yet).

    // TODO: this should be an ArrayVec or something, most exprs are simple.
    let mut stack: Vec<u64> = Vec::new();
    for token in expr.split_ascii_whitespace() {
        match token {
            // TODO: not sure what the supported set of binary ops are,
            // and what the overflow/sign semantics are.
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

pub fn walk_with_stack_win_framedata(
    info: &StackInfoWin,
    _walker: &mut dyn FrameWalker,
) -> Option<()> {
    // TODO: implement this? I haven't found anything that uses this.
    if let WinStackThing::ProgramString(ref string) = info.program_string_or_base_pointer {
        debug!("STACK WIN framedata: {}", string);
    } else {
        unreachable!()
    }
    None
}

pub fn walk_with_stack_win_fpo(info: &StackInfoWin, _walker: &mut dyn FrameWalker) -> Option<()> {
    // TODO: implement this? I haven't found anything that uses this.
    if let WinStackThing::AllocatesBasePointer(allocates_base_pointer) =
        info.program_string_or_base_pointer
    {
        debug!(
            "STACK WIN fpo: allocates_base_pointer: {}",
            allocates_base_pointer
        );
    } else {
        unreachable!()
    }
    None
}
