// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use failure::Error;
use nom::*;
use nom::IResult::*;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str;
use std::str::FromStr;

use sym_file::types::*;
use range_map::Range;
#[cfg(test)]
use range_map::RangeMap;

enum Line<'a> {
    Info,
    File(u32, &'a str),
    Public(PublicSymbol),
    Function(Function),
    StackWin(WinFrameType),
    StackCFI(StackInfoCFI),
}

// Nom's `eol` doesn't use complete! so it will return Incomplete.
named!(my_eol<char>, alt!(complete!(crlf) | newline));

/// Match a hex string, parse it to a u64.
named!(hex_str_u64<&[u8], u64>,
       map_res!(map_res!(hex_digit, str::from_utf8), |s| u64::from_str_radix(s, 16)));

/// Match a decimal string, parse it to a u32.
named!(decimal_u32<&[u8], u32>, map_res!(map_res!(digit, str::from_utf8), FromStr::from_str));

/// Matches a MODULE record.
named!(module_line<&[u8], ()>,
  chain!(
    tag!("MODULE") ~
          space     ~
          // os
    alphanumeric ~
          space ~
          // cpu
    take_until!(" ") ~
          space ~
          // debug id
    hex_digit ~
          space ~
          // filename
    not_line_ending ~
    my_eol ,
    || {}
));

/// Matches an INFO record.
named!(
    info_line,
    chain!(
    tag!("INFO") ~
    space ~
    x: not_line_ending ~
    my_eol,
      ||{ x }
)
);

/// Matches a FILE record.
named!(file_line<&[u8], (u32, &str)>,
  chain!(
    tag!("FILE") ~
    space ~
    id: decimal_u32 ~
    space ~
    filename: map_res!(not_line_ending, str::from_utf8) ~
    my_eol ,
      ||{ (id, filename) }
));

/// Matches a PUBLIC record.
named!(public_line<&[u8], PublicSymbol>,
  chain!(
    tag!("PUBLIC") ~
    space ~
    address: hex_str_u64 ~
    space ~
    parameter_size: hex_u32 ~
    space ~
    name: map_res!(not_line_ending, str::from_utf8) ~
    my_eol ,
      || {
          PublicSymbol {
              address: address,
              parameter_size: parameter_size,
              name: name.to_string()
          }
      }
));

/// Matches line data after a FUNC record.
named!(func_line_data<&[u8], SourceLine>,
  chain!(
    address: hex_str_u64 ~
    space ~
    size: hex_u32 ~
    space ~
    line: decimal_u32 ~
    space ~
    filenum: decimal_u32 ~
    my_eol ,
      || {
          SourceLine {
              address: address,
              size: size,
              file: filenum,
              line: line,
          }
      }
));

/// Matches a FUNC record and any following line records.
named!(func_lines<&[u8], Function>,
  chain!(
    tag!("FUNC") ~
    preceded!(space, tag!("m"))? ~
    space ~
    address: hex_str_u64 ~
    space ~
    size: hex_u32 ~
    space ~
    parameter_size: hex_u32 ~
    space ~
    name: map_res!(not_line_ending, str::from_utf8) ~
    my_eol ~
    lines: many0!(func_line_data) ,
      || {
          Function {
              address: address,
              size: size,
              parameter_size: parameter_size,
              name: name.to_string(),
              lines: lines.into_iter()
                  .filter_map(|l| {
                      // Line data from PDB files often has a zero-size line entry, so just
                      // filter those out.
                      if l.size > 0 {
                          Some((Range::new(l.address, l.address + l.size as u64 - 1), l))
                      } else {
                          None
                      }
                  })
                  .collect(),
          }
      }
      ));

/// Matches a STACK WIN record.
named!(stack_win_line<&[u8], WinFrameType>,
  chain!(
    tag!("STACK WIN") ~
    space ~
    // Frame type, currently ignored.
    ty: hex_digit ~
    space ~
    address: hex_str_u64 ~
    space ~
    code_size: hex_u32 ~
    space ~
    prologue_size: hex_u32 ~
    space ~
    epilogue_size: hex_u32 ~
    space ~
    parameter_size: hex_u32 ~
    space ~
    saved_register_size: hex_u32 ~
    space ~
    local_size: hex_u32 ~
    space ~
    max_stack_size: hex_u32 ~
    space ~
    has_program_string: map_res!(map_res!(digit, str::from_utf8), |s| -> Result<bool,()> { Ok(s == "1") }) ~
    space ~
    rest: map_res!(not_line_ending, str::from_utf8) ~
    my_eol ,
      || {
          let program_string_or_base_pointer = if has_program_string {
              WinStackThing::ProgramString(rest.to_string())
          } else {
              WinStackThing::AllocatesBasePointer(rest == "1")
          };
          let info = StackInfoWin {
              address: address,
              size: code_size,
              prologue_size: prologue_size,
              epilogue_size: epilogue_size,
              parameter_size: parameter_size,
              saved_register_size: saved_register_size,
              local_size: local_size,
              max_stack_size: max_stack_size,
              program_string_or_base_pointer,
          };
          match ty {
              b"4" => WinFrameType::FrameData(info),
              b"0" => WinFrameType::FPO(info),
              _ => WinFrameType::Unhandled,
          }
      }
));

/// Matches a STACK CFI record.
named!(stack_cfi<&[u8], CFIRules>,
       chain!(
           tag!("STACK CFI") ~
               space ~
               address: hex_str_u64 ~
               space ~
               rules: map_res!(not_line_ending, str::from_utf8) ~
               my_eol ,
           || {
               CFIRules {
                   address: address,
                   rules: rules.to_string(),
               }
           }
           ));

/// Matches a STACK CFI INIT record.
named!(stack_cfi_init<&[u8], (CFIRules, u32)>,
  chain!(
    tag!("STACK CFI INIT") ~
    space ~
    address: hex_str_u64 ~
    space ~
    size: hex_u32 ~
    space ~
    rules: map_res!(not_line_ending, str::from_utf8) ~
    my_eol ,
      || {
          (CFIRules {
              address: address,
              rules: rules.to_string(),
          },
           size)
      }
));

/// Match a STACK CFI INIT record followed by zero or more STACK CFI records.
named!(stack_cfi_lines<&[u8], StackInfoCFI>,
  chain!(
    init: stack_cfi_init ~
    mut add_rules: many0!(stack_cfi) ,
      move || {
          let (init_rules, size) = init;
          add_rules.sort();
          StackInfoCFI {
              init: init_rules,
              size: size,
              add_rules: add_rules,
          }
      }
));

/// Parse any of the line data that can occur in the body of a symbol file.
named!(line<&[u8], Line>,
  alt!(
    info_line => { |_| Line::Info } |
    file_line => { |(i,f)| Line::File(i, f) } |
    public_line => { |p| Line::Public(p) } |
    func_lines => { |f| Line::Function(f) } |
    stack_win_line => { |s| Line::StackWin(s) } |
    stack_cfi_lines => { |s| Line::StackCFI(s) }
));

/// Return a `SymbolFile` given a vec of `Line` data.
fn symbol_file_from_lines<'a>(lines: Vec<Line<'a>>) -> SymbolFile {
    let mut files = HashMap::new();
    let mut publics = vec![];
    let mut funcs = vec![];
    let mut stack_cfi = vec![];
    let mut stack_win_framedata: Vec<StackInfoWin> = vec![];
    let mut stack_win_fpo: Vec<StackInfoWin> = vec![];
    for line in lines {
        match line {
            Line::Info => {}
            Line::File(id, filename) => {
                files.insert(id, filename.to_string());
            }
            Line::Public(p) => {
                publics.push(p);
            }
            Line::Function(f) => {
                funcs.push(f);
            }
            Line::StackWin(frame_type) => {
                // PDB files contain lots of overlapping unwind info, so we have to filter
                // some of it out.
                fn insert_win_stack_info(stack_win: &mut Vec<StackInfoWin>, info: StackInfoWin) {
                    if let Some(last) = stack_win.last() {
                        if last.memory_range().intersects(&info.memory_range()) {
                            return;
                        }
                    }
                    stack_win.push(info);
                }
                match frame_type {
                    WinFrameType::FrameData(s) => {
                        insert_win_stack_info(&mut stack_win_framedata, s);
                    }
                    WinFrameType::FPO(s) => {
                        insert_win_stack_info(&mut stack_win_fpo, s);
                    }
                    // Just ignore other types.
                    _ => {}
                }
            }
            Line::StackCFI(s) => {
                stack_cfi.push(s);
            }
        }
    }
    publics.sort();
    SymbolFile {
        files: files,
        publics: publics,
        functions: funcs.into_iter().map(|f| (f.memory_range(), f)).collect(),
        cfi_stack_info: stack_cfi
            .into_iter()
            .map(|s| (s.memory_range(), s))
            .collect(),
        win_stack_framedata_info: stack_win_framedata
            .into_iter()
            .map(|s| (s.memory_range(), s))
            .collect(),
        win_stack_fpo_info: stack_win_fpo
            .into_iter()
            .map(|s| (s.memory_range(), s))
            .collect(),
    }
}

/// Matches an entire symbol file.
named!(symbol_file<&[u8], SymbolFile>,
  chain!(
    module_line? ~
    lines: many0!(line) ,
    || { symbol_file_from_lines(lines) })
);

/// Parse a `SymbolFile` from `bytes`.
pub fn parse_symbol_bytes(bytes: &[u8]) -> Result<SymbolFile, Error> {
    match symbol_file(&bytes) {
        Done(rest, symfile) => {
            if rest == b"" {
                Ok(symfile)
            } else {
                // Junk left over, or maybe didn't parse anything.
                let next_line = rest.split(|b| *b == b'\r').next()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .unwrap_or(Cow::Borrowed(""));
                Err(format_err!("Failed to parse file, next line was: `{}`", next_line))
            }
        }
        Error(e) => Err(format_err!("Failed to parse file: {}", e)),
        Incomplete(_) => Err(format_err!("Failed to parse file: incomplete data")),
    }
}

/// Parse a `SymbolFile` from `path`.
pub fn parse_symbol_file(path: &Path) -> Result<SymbolFile, Error> {
    let mut f = File::open(path)?;
    let mut bytes = vec![];
    f.read_to_end(&mut bytes)?;
    parse_symbol_bytes(&bytes)
}

#[test]
fn test_module_line() {
    let line = b"MODULE Linux x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin\n";
    let rest = &b""[..];
    assert_eq!(module_line(line), Done(rest, ()));
}

#[test]
fn test_module_line_filename_spaces() {
    let line = b"MODULE Windows x86_64 D3096ED481217FD4C16B29CD9BC208BA0 firefox x y z\n";
    let rest = &b""[..];
    assert_eq!(module_line(line), Done(rest, ()));
}

#[test]
fn test_info_line() {
    let line = b"INFO blah blah blah\n";
    let bits = &b"blah blah blah"[..];
    let rest = &b""[..];
    assert_eq!(info_line(line), Done(rest, bits));
}

#[test]
fn test_info_line2() {
    let line = b"INFO   CODE_ID   abc xyz\n";
    let bits = &b"CODE_ID   abc xyz"[..];
    let rest = &b""[..];
    assert_eq!(info_line(line), Done(rest, bits));
}

#[test]
fn test_file_line() {
    let line = b"FILE 1 foo.c\n";
    let rest = &b""[..];
    assert_eq!(file_line(line), Done(rest, (1, "foo.c")));
}

#[test]
fn test_file_line_spaces() {
    let line = b"FILE  1234  foo bar.xyz\n";
    let rest = &b""[..];
    assert_eq!(file_line(line), Done(rest, (1234, "foo bar.xyz")));
}

#[test]
fn test_public_line() {
    let line = b"PUBLIC f00d d00d some func\n";
    let rest = &b""[..];
    assert_eq!(
        public_line(line),
        Done(
            rest,
            PublicSymbol {
                address: 0xf00d,
                parameter_size: 0xd00d,
                name: "some func".to_string(),
            }
        )
    );
}

#[test]
fn test_func_lines_no_lines() {
    let line = b"FUNC c184 30 0 nsQueryInterfaceWithError::operator()(nsID const&, void**) const\n";
    let rest = &b""[..];
    assert_eq!(
        func_lines(line),
        Done(
            rest,
            Function {
                address: 0xc184,
                size: 0x30,
                parameter_size: 0,
                name: "nsQueryInterfaceWithError::operator()(nsID const&, void**) const"
                    .to_string(),
                lines: RangeMap::new(),
            }
        )
    );
}

#[test]
fn test_func_lines_and_lines() {
    let data = b"FUNC 1000 30 10 some func
1000 10 42 7
1010 10 52 8
1020 10 62 15
";
    if let Done(rest, f) = func_lines(data) {
        assert_eq!(rest, &b""[..]);
        assert_eq!(f.address, 0x1000);
        assert_eq!(f.size, 0x30);
        assert_eq!(f.parameter_size, 0x10);
        assert_eq!(f.name, "some func".to_string());
        assert_eq!(
            f.lines.get(0x1000).unwrap(),
            &SourceLine {
                address: 0x1000,
                size: 0x10,
                file: 7,
                line: 42,
            }
        );
        assert_eq!(
            f.lines.ranges_values().collect::<Vec<_>>(),
            vec![
                &(
                    Range::<u64>::new(0x1000, 0x100F),
                    SourceLine {
                        address: 0x1000,
                        size: 0x10,
                        file: 7,
                        line: 42,
                    },
                ),
                &(
                    Range::<u64>::new(0x1010, 0x101F),
                    SourceLine {
                        address: 0x1010,
                        size: 0x10,
                        file: 8,
                        line: 52,
                    },
                ),
                &(
                    Range::<u64>::new(0x1020, 0x102F),
                    SourceLine {
                        address: 0x1020,
                        size: 0x10,
                        file: 15,
                        line: 62,
                    },
                ),
            ]
        );
    } else {
        assert!(false, "Failed to parse!");
    }
}

#[test]
fn test_func_with_m() {
    let data = b"FUNC m 1000 30 10 some func
1000 10 42 7
1010 10 52 8
1020 10 62 15
";
    if let Done(rest, _) = func_lines(data) {
        assert_eq!(rest, &b""[..]);
    } else {
        assert!(false, "Failed to parse!");
    }
}

#[test]
fn test_stack_win_line_program_string() {
    let line =
        b"STACK WIN 4 2170 14 a1 b2 c3 d4 e5 f6 1 $eip 4 + ^ = $esp $ebp 8 + = $ebp $ebp ^ =\n";
    match stack_win_line(line) {
        Done(rest, WinFrameType::FrameData(stack)) => {
            assert_eq!(rest, &b""[..]);
            assert_eq!(stack.address, 0x2170);
            assert_eq!(stack.size, 0x14);
            assert_eq!(stack.prologue_size, 0xa1);
            assert_eq!(stack.epilogue_size, 0xb2);
            assert_eq!(stack.parameter_size, 0xc3);
            assert_eq!(stack.saved_register_size, 0xd4);
            assert_eq!(stack.local_size, 0xe5);
            assert_eq!(stack.max_stack_size, 0xf6);
            assert_eq!(
                stack.program_string_or_base_pointer,
                WinStackThing::ProgramString(
                    "$eip 4 + ^ = $esp $ebp 8 + = $ebp $ebp ^ =".to_string()
                )
            );
        }
        Error(e) => {
            assert!(false, format!("Parse error: {:?}", e));
        }
        Incomplete(_) => {
            assert!(false, "Incomplete parse!");
        }
        _ => assert!(false, "Something bad happened"),
    }
}

#[test]
fn test_stack_win_line_frame_data() {
    let line = b"STACK WIN 0 1000 30 a1 b2 c3 d4 e5 f6 0 1\n";
    match stack_win_line(line) {
        Done(rest, WinFrameType::FPO(stack)) => {
            assert_eq!(rest, &b""[..]);
            assert_eq!(stack.address, 0x1000);
            assert_eq!(stack.size, 0x30);
            assert_eq!(stack.prologue_size, 0xa1);
            assert_eq!(stack.epilogue_size, 0xb2);
            assert_eq!(stack.parameter_size, 0xc3);
            assert_eq!(stack.saved_register_size, 0xd4);
            assert_eq!(stack.local_size, 0xe5);
            assert_eq!(stack.max_stack_size, 0xf6);
            assert_eq!(
                stack.program_string_or_base_pointer,
                WinStackThing::AllocatesBasePointer(true)
            );
        }
        Error(e) => {
            assert!(false, format!("Parse error: {:?}", e));
        }
        Incomplete(_) => {
            assert!(false, "Incomplete parse!");
        }
        _ => assert!(false, "Something bad happened"),
    }
}

#[test]
fn test_stack_cfi() {
    let line = b"STACK CFI deadf00d some rules\n";
    let rest = &b""[..];
    assert_eq!(
        stack_cfi(line),
        Done(
            rest,
            CFIRules {
                address: 0xdeadf00d,
                rules: "some rules".to_string(),
            }
        )
    );
}

#[test]
fn test_stack_cfi_init() {
    let line = b"STACK CFI INIT badf00d abc init rules\n";
    let rest = &b""[..];
    assert_eq!(
        stack_cfi_init(line),
        Done(
            rest,
            (
                CFIRules {
                    address: 0xbadf00d,
                    rules: "init rules".to_string(),
                },
                0xabc
            )
        )
    );
}

#[test]
fn test_stack_cfi_lines() {
    let data = b"STACK CFI INIT badf00d abc init rules
STACK CFI deadf00d some rules
STACK CFI deadbeef more rules
";
    let rest = &b""[..];
    assert_eq!(
        stack_cfi_lines(data),
        Done(
            rest,
            StackInfoCFI {
                init: CFIRules {
                    address: 0xbadf00d,
                    rules: "init rules".to_string(),
                },
                size: 0xabc,
                add_rules: vec![
                    CFIRules {
                        address: 0xdeadbeef,
                        rules: "more rules".to_string(),
                    },
                    CFIRules {
                        address: 0xdeadf00d,
                        rules: "some rules".to_string(),
                    },
                ],
            }
        )
    );
}

#[test]
fn test_parse_symbol_bytes() {
    let bytes = &b"MODULE Linux x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin
INFO blah blah blah
FILE 0 foo.c
FILE 100 bar.c
PUBLIC abcd 10 func 1
PUBLIC ff00 3 func 2
FUNC 900 30 10 some other func
FUNC 1000 30 10 some func
1000 10 42 7
1010 10 52 8
1020 10 62 15
FUNC 1100 30 10 a third func
STACK WIN 4 900 30 a1 b2 c3 d4 e5 f6 1 prog string
STACK WIN 0 1000 30 a1 b2 c3 d4 e5 f6 0 1
STACK CFI INIT badf00d abc init rules
STACK CFI deadf00d some rules
STACK CFI deadbeef more rules
STACK CFI INIT f00f f0 more init rules
"[..];
    let sym = parse_symbol_bytes(bytes).unwrap();
    assert_eq!(sym.files.len(), 2);
    assert_eq!(sym.files.get(&0).unwrap(), "foo.c");
    assert_eq!(sym.files.get(&100).unwrap(), "bar.c");
    assert_eq!(sym.publics.len(), 2);
    {
        let p = &sym.publics[0];
        assert_eq!(p.address, 0xabcd);
        assert_eq!(p.parameter_size, 0x10);
        assert_eq!(p.name, "func 1".to_string());
    }
    {
        let p = &sym.publics[1];
        assert_eq!(p.address, 0xff00);
        assert_eq!(p.parameter_size, 0x3);
        assert_eq!(p.name, "func 2".to_string());
    }
    assert_eq!(sym.functions.ranges_values().count(), 3);
    let funcs = sym.functions
        .ranges_values()
        .map(|&(_, ref f)| f)
        .collect::<Vec<_>>();
    {
        let f = &funcs[0];
        assert_eq!(f.address, 0x900);
        assert_eq!(f.size, 0x30);
        assert_eq!(f.parameter_size, 0x10);
        assert_eq!(f.name, "some other func".to_string());
        assert_eq!(f.lines.ranges_values().count(), 0);
    }
    {
        let f = &funcs[1];
        assert_eq!(f.address, 0x1000);
        assert_eq!(f.size, 0x30);
        assert_eq!(f.parameter_size, 0x10);
        assert_eq!(f.name, "some func".to_string());
        assert_eq!(
            f.lines.ranges_values().collect::<Vec<_>>(),
            vec![
                &(
                    Range::new(0x1000, 0x100F),
                    SourceLine {
                        address: 0x1000,
                        size: 0x10,
                        file: 7,
                        line: 42,
                    },
                ),
                &(
                    Range::new(0x1010, 0x101F),
                    SourceLine {
                        address: 0x1010,
                        size: 0x10,
                        file: 8,
                        line: 52,
                    },
                ),
                &(
                    Range::new(0x1020, 0x102F),
                    SourceLine {
                        address: 0x1020,
                        size: 0x10,
                        file: 15,
                        line: 62,
                    },
                ),
            ]
        );
    }
    {
        let f = &funcs[2];
        assert_eq!(f.address, 0x1100);
        assert_eq!(f.size, 0x30);
        assert_eq!(f.parameter_size, 0x10);
        assert_eq!(f.name, "a third func".to_string());
        assert_eq!(f.lines.ranges_values().count(), 0);
    }
    assert_eq!(sym.win_stack_framedata_info.ranges_values().count(), 1);
    let ws = sym.win_stack_framedata_info
        .ranges_values()
        .map(|&(_, ref s)| s)
        .collect::<Vec<_>>();
    {
        let stack = &ws[0];
        assert_eq!(stack.address, 0x900);
        assert_eq!(stack.size, 0x30);
        assert_eq!(stack.prologue_size, 0xa1);
        assert_eq!(stack.epilogue_size, 0xb2);
        assert_eq!(stack.parameter_size, 0xc3);
        assert_eq!(stack.saved_register_size, 0xd4);
        assert_eq!(stack.local_size, 0xe5);
        assert_eq!(stack.max_stack_size, 0xf6);
        assert_eq!(
            stack.program_string_or_base_pointer,
            WinStackThing::ProgramString("prog string".to_string())
        );
    }
    assert_eq!(sym.win_stack_fpo_info.ranges_values().count(), 1);
    let ws = sym.win_stack_fpo_info
        .ranges_values()
        .map(|&(_, ref s)| s)
        .collect::<Vec<_>>();
    {
        let stack = &ws[0];
        assert_eq!(stack.address, 0x1000);
        assert_eq!(stack.size, 0x30);
        assert_eq!(stack.prologue_size, 0xa1);
        assert_eq!(stack.epilogue_size, 0xb2);
        assert_eq!(stack.parameter_size, 0xc3);
        assert_eq!(stack.saved_register_size, 0xd4);
        assert_eq!(stack.local_size, 0xe5);
        assert_eq!(stack.max_stack_size, 0xf6);
        assert_eq!(
            stack.program_string_or_base_pointer,
            WinStackThing::AllocatesBasePointer(true)
        );
    }
    assert_eq!(sym.cfi_stack_info.ranges_values().count(), 2);
    let cs = sym.cfi_stack_info
        .ranges_values()
        .map(|&(_, ref s)| s.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        cs[0],
        StackInfoCFI {
            init: CFIRules {
                address: 0xf00f,
                rules: "more init rules".to_string(),
            },
            size: 0xf0,
            add_rules: vec![],
        }
    );
    assert_eq!(
        cs[1],
        StackInfoCFI {
            init: CFIRules {
                address: 0xbadf00d,
                rules: "init rules".to_string(),
            },
            size: 0xabc,
            add_rules: vec![
                CFIRules {
                    address: 0xdeadbeef,
                    rules: "more rules".to_string(),
                },
                CFIRules {
                    address: 0xdeadf00d,
                    rules: "some rules".to_string(),
                },
            ],
        }
    );
}

#[test]
fn test_parse_symbol_bytes_malformed() {
    assert!(
        parse_symbol_bytes(&b"this is not a symbol file\n"[..]).is_err(),
        "Should fail to parse junk"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 xxxxxx
FILE 0 foo.c
"[..]
        ).is_err(),
        "Should fail to parse malformed MODULE line"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FILE x foo.c
"[..]
        ).is_err(),
        "Should fail to parse malformed FILE line"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FUNC xx 1 2 foo
"[..]
        ).is_err(),
        "Should fail to parse malformed FUNC line"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
this is some junk
"[..]
        ).is_err(),
        "Should fail to parse malformed file"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FILE 0 foo.c
FILE"[..]
        ).is_err(),
        "Should fail to parse truncated file"
    );

    assert!(
        parse_symbol_bytes(&b""[..]).is_err(),
        "Should fail to parse empty file"
    );
}
