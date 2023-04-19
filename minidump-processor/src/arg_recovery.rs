use minidump::{CpuContext, MinidumpRawContext, UnifiedMemory};
use minidump_unwind::{CallStack, CallingConvention, FunctionArg, FunctionArgs};

// # Recovering x86 function arguments
//
// This approach is very hacky and very likely to produce incorrect values
// in many situations. But sometimes it will be right, and that's useful, right?
//
// x86 has two common calling conventions which are very friendly to recovering
// function arguments: cdecl and thiscall.
//
// In both conventions, arguments are unconditionally pushed to the
// stack in reverse order, so in theory all we need to do is jump to the
// top of the caller's stack frame and just start reading the values off!
//
// (thiscall requires some special handling for the implicit "this" arg, see below.)
//
// This leaves us with several problems to solve:
//
// 1. determining the calling convention
// 2. determining the number (and name) of arguments
// 3. determining the size of arguments
//
//
//
// ## Determining the calling convention
//
// We don't have the kind of debuginfo that would tell use what the calling
// convention was, but we can make an educated guess based on the name of
// the function:
//
// * If the function name contains a ::, it's probably a C++ member function,
//   in which case it's thiscall
// * Otherwise, assume it's cdecl
//
// It's a blunt heuristic that will misclassify static functions and always
// mishandle anything that's manually defined to be fastcall or whatever else,
// but it should do the right thing for *most* functions!
//
//
//
// ## Determining the number of arguments
//
// We assume a function name includes its argument list if it contains
// both an open-paren "(" and close-paren ")" in the right order. Everything
// between the first open-paren and last close-paren is assumed to be the
// argument list.
//
// The number of arguments is then just "the number of commas in the argument list".
// However C++ templates introduce "fake" commas. This can be easily handled by
// tracking the nesting level of `<` and `>` and only considering a comma "real"
// if the nesting level is 0. We similarly handle `(` and `)` to try to handle
// function pointer types.
//
// thiscall functions have an implicit first argument "this". Windows (Visual C++)
// toolchains will pass "this" via $eax instead of on the stack. Other (gcc)
// toolchains will pass "this" just like any other argument (so it will be at
// the top of the stack frame).
//
//
//
// # Determining the size of arguments
//
// Rather than attempting to parse and resolve C++ types (*laughs and cries at the same time*),
// we just unconditionally assume all arguments are pointer-sized. This is intuitively true
// most of the time. The major exceptions are `bool` and `uint64_t`. Maybe those
// are worth carving out special cases for, but until then: it's all pointers!

/// Try to recover function arguments
pub fn fill_arguments(call_stack: &mut CallStack, stack_memory: Option<UnifiedMemory>) {
    // Collect up all the results at once to avoid borrowing issues.
    let args = call_stack
        .frames
        .iter()
        .enumerate()
        .map(|(frame_idx, frame)| {
            // Only x86 is implemented because it has friendly calling conventions.
            // and we need the function name to make any guesses at what the arguments are.
            if let (Some(mem), Some(func_name), MinidumpRawContext::X86(ctx)) =
                (stack_memory, &frame.function_name, &frame.context.raw)
            {
                const POINTER_WIDTH: u64 = 4;

                if let Some((calling_convention, argument_list)) = parse_x86_arg_list(func_name) {
                    // We're assuming this is either cdecl or thiscall. In either case,
                    // all the arguments are saved at the top of the caller's stackframe
                    // in reverse order (which in fact means we can start at the top
                    // of the frame and read them off *in order*).

                    // The stack grows down, so the maximum address in the stack
                    // is actually the base of the stack. Since we're walking down
                    // the stack, the base of the stack is a good upper-bound
                    // (and default value) for any stack/frame pointer.
                    let stack_base = mem.base_address().saturating_add(mem.size());

                    let caller_stack_pointer = call_stack
                        .frames
                        .get(frame_idx + 1)
                        .map(|f| f.context.get_stack_pointer())
                        .unwrap_or(stack_base);
                    let caller_frame_pointer = call_stack
                        .frames
                        .get(frame_idx + 2)
                        .map(|f| f.context.get_stack_pointer())
                        .unwrap_or(stack_base);

                    let mut read_head = caller_stack_pointer;
                    let mut pop_value = || {
                        if read_head < caller_frame_pointer {
                            let val = mem.get_memory_at_address::<u32>(read_head);
                            read_head += POINTER_WIDTH;
                            val.map(|val| val as u64)
                        } else {
                            None
                        }
                    };

                    let mut args = Vec::new();

                    // Handle the first argument of thiscall
                    match calling_convention {
                        CallingConvention::WindowsThisCall => {
                            // On windows, "this" is passed in eax
                            let value = ctx
                                .get_register("eax", &frame.context.valid)
                                .map(|x| x as u64);
                            args.push(FunctionArg {
                                name: String::from("this"),
                                value,
                            });
                        }
                        CallingConvention::OtherThisCall => {
                            // Everywhere else, "this" is passed like a normal value
                            let value = pop_value();
                            args.push(FunctionArg {
                                name: String::from("this"),
                                value,
                            });
                        }
                        CallingConvention::Cdecl => {
                            // Nothing to do
                        }
                    }

                    // Now handle the rest
                    args.extend(argument_list.iter().map(|&arg_name| {
                        let value = pop_value();
                        FunctionArg {
                            name: String::from(arg_name),
                            value,
                        }
                    }));

                    return Some(FunctionArgs {
                        calling_convention,
                        args,
                    });
                }
            }
            None
        })
        .collect::<Vec<_>>();

    // Now write the values back to the call stack
    for (frame, args) in call_stack.frames.iter_mut().zip(args) {
        frame.arguments = args;
    }
}

fn parse_x86_arg_list(func_name: &str) -> Option<(CallingConvention, Vec<&str>)> {
    if let Some((func_name, arg_list)) = func_name.split_once('(') {
        if let Some((arg_list, _junk)) = arg_list.rsplit_once(')') {
            let calling_convention = if func_name.contains("::") {
                // Assume this is a C++ method (thiscall)
                let windows = true; // TODO
                if windows {
                    CallingConvention::WindowsThisCall
                } else {
                    CallingConvention::OtherThisCall
                }
            } else {
                CallingConvention::Cdecl
                // Assume this is a static function (cdecl)
            };

            let mut args = Vec::new();

            // Now parse the arguments out
            let mut arg_start = 0;
            let mut template_depth = 0;
            let mut paren_depth = 0;

            // Only consider a comma a "real" argument separator if we aren't
            // currently nested inside of templates (`<>`) or parens (`()`).
            for (idx, c) in arg_list.bytes().enumerate() {
                match c as char {
                    '<' => template_depth += 1,
                    '>' => {
                        if template_depth > 0 {
                            template_depth -= 1;
                        } else {
                            // Parser is lost
                            return None;
                        }
                    }
                    '(' => paren_depth += 1,
                    ')' => {
                        if paren_depth > 0 {
                            paren_depth -= 1;
                        } else {
                            // Parser is lost
                            return None;
                        }
                    }
                    ',' => {
                        if template_depth == 0 && paren_depth == 0 {
                            args.push(arg_list[arg_start..idx].trim());
                            arg_start = idx + 1;
                        }
                    }
                    _ => {}
                }
            }

            // Whole function name parsed, the remainder is the last argument.
            args.push(arg_list[arg_start..].trim());

            // Only accept the result if all nesting was balanced
            if template_depth == 0 && paren_depth == 0 {
                return Some((calling_convention, args));
            }
        }
    }
    None
}
