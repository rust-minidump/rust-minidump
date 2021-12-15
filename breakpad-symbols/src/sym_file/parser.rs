// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use failure::format_err;
use log::warn;
use nom::IResult::*;
use nom::*;
use range_map::Range;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str;
use std::str::FromStr;

use minidump_common::traits::IntoRangeMapSafe;

use crate::sym_file::types::*;
use crate::SymbolError;

enum Line<'a> {
    Info(Info),
    File(u32, &'a str),
    Public(PublicSymbol),
    Function(Function),
    StackWin(WinFrameType),
    StackCfi(StackInfoCfi),
}

// Nom's `eol` doesn't use complete! so it will return Incomplete.
named!(
    my_eol<char>,
    complete!(preceded!(many0!(char!('\r')), char!('\n')))
);

// Match a hex string, parse it to a u64.
named!(hex_str_u64<&[u8], u64>,
       map_res!(map_res!(hex_digit, str::from_utf8), |s| u64::from_str_radix(s, 16)));

// Match a decimal string, parse it to a u32.
named!(decimal_u32<&[u8], u32>, map_res!(map_res!(digit, str::from_utf8), FromStr::from_str));

// Matches a MODULE record.
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

// Matches an INFO URL record.
named!(
    info_url<&[u8], Info>,
    chain!(
        tag!("INFO URL") ~
        space ~
        url: map_res!(not_line_ending, str::from_utf8) ~
        my_eol,
          ||{ Info::Url(url.to_string()) }
    )
);

// Matches other INFO records.
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

// Matches a FILE record.
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

// Matches a PUBLIC record.
named!(public_line<&[u8], PublicSymbol>,
  chain!(
    tag!("PUBLIC") ~
    preceded!(space, tag!("m"))? ~
    space ~
    address: hex_str_u64 ~
    space ~
    parameter_size: hex_u32 ~
    space ~
    name: map_res!(not_line_ending, str::from_utf8) ~
    my_eol ,
      || {
          PublicSymbol {
              address,
              parameter_size,
              name: name.to_string()
          }
      }
));

// Matches line data after a FUNC record.
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
              address,
              size,
              file: filenum,
              line,
          }
      }
));

// Matches a FUNC record and any following line records.
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
            address,
            size,
            parameter_size,
            name: name.to_string(),
            lines: lines.into_iter()
                .map(|l| {
                    // Line data from PDB files often has a zero-size line entry, so just
                    // filter those out.
                    if l.size > 0 {
                        (Some(Range::new(l.address, l.address + l.size as u64 - 1)), l)
                    } else {
                        (None, l)
                    }
                })
                .into_rangemap_safe(),
        }
    }
    ));

// Matches a STACK WIN record.
named!(stack_win_line<&[u8], WinFrameType>,
  chain!(
    // Use this for debugging the parser:
    // line: peek!(map_res!(not_line_ending, str::from_utf8)) ~
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
          // Sometimes has_program_string is just wrong. We could try to infer which one is right
          // but this is rare enough that it's better to just play it safe and discard the input.
          let really_has_program_string = ty == b"4";
          if really_has_program_string != has_program_string {
            let kind = match ty {
              b"4" => "FrameData",
              b"0" => "Fpo",
              _ => "Unknown Type!",
            };
            warn!("STACK WIN entry had inconsistent values for type and has_program_string, discarding corrupt entry");
            // warn!("  {}", &line);
            warn!("  type: {} ({}), has_program_string: {}, final_arg: {}", str::from_utf8(ty).unwrap_or(""), kind, has_program_string, rest);

            return WinFrameType::Unhandled;
          }

          let program_string_or_base_pointer = if really_has_program_string {
              WinStackThing::ProgramString(rest.to_string())
          } else {
              WinStackThing::AllocatesBasePointer(rest == "1")
          };
          let info = StackInfoWin {
              address,
              size: code_size,
              prologue_size,
              epilogue_size,
              parameter_size,
              saved_register_size,
              local_size,
              max_stack_size,
              program_string_or_base_pointer,
          };
          match ty {
              b"4" => WinFrameType::FrameData(info),
              b"0" => WinFrameType::Fpo(info),
              _ => WinFrameType::Unhandled,
          }
      }
));

// Matches a STACK CFI record.
named!(stack_cfi<&[u8], CfiRules>,
chain!(
    tag!("STACK CFI") ~
        space ~
        address: hex_str_u64 ~
        space ~
        rules: map_res!(not_line_ending, str::from_utf8) ~
        my_eol ,
    || {
        CfiRules {
            address,
            rules: rules.to_string(),
        }
    }
    ));

// Matches a STACK CFI INIT record.
named!(stack_cfi_init<&[u8], (CfiRules, u32)>,
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
          (CfiRules {
              address,
              rules: rules.to_string(),
          },
           size)
      }
));

// Match a STACK CFI INIT record followed by zero or more STACK CFI records.
named!(stack_cfi_lines<&[u8], StackInfoCfi>,
  chain!(
    init: stack_cfi_init ~
    mut add_rules: many0!(stack_cfi) ,
      move || {
          let (init_rules, size) = init;
          add_rules.sort();
          StackInfoCfi {
              init: init_rules,
              size,
              add_rules,
          }
      }
));

// Parse any of the line data that can occur in the body of a symbol file.
named!(line<&[u8], Line>,
  alt!(
    info_url => { Line::Info } |
    info_line => { |_| Line::Info(Info::Unknown) } |
    file_line => { |(i,f)| Line::File(i, f) } |
    public_line => { Line::Public } |
    func_lines => { Line::Function } |
    stack_win_line => { Line::StackWin } |
    stack_cfi_lines => { Line::StackCfi }
));

// Return a `SymbolFile` given a vec of `Line` data.
fn symbol_file_from_lines(lines: Vec<Line<'_>>) -> SymbolFile {
    let mut files = HashMap::new();
    let mut publics = vec![];
    let mut funcs = vec![];
    let mut stack_cfi = vec![];
    let mut stack_win_framedata: Vec<StackInfoWin> = vec![];
    let mut stack_win_fpo: Vec<StackInfoWin> = vec![];
    let mut url = None;
    for line in lines {
        match line {
            Line::Info(Info::Url(cached_url)) => {
                url = Some(cached_url);
            }
            Line::Info(Info::Unknown) => {
                // Don't care
            }
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
                    if let Some(memory_range) = info.memory_range() {
                        if let Some(last) = stack_win.last_mut() {
                            if last.memory_range().unwrap().intersects(&memory_range) {
                                if info.address > last.address {
                                    // Sometimes we get STACK WIN directives where each line
                                    // has an accurate starting point, but the length just
                                    // covers the entire function, like so:
                                    //
                                    // addr: 0, len: 10
                                    // addr: 1, len: 9
                                    // addr: 4, len: 6
                                    //
                                    // In this case, the next instruction is the one that
                                    // really defines the length of the previous one. So
                                    // we need to fixup the lengths like so:
                                    //
                                    // addr: 0, len: 1
                                    // addr: 1, len: 2
                                    // addr: 4, len: 6
                                    last.size = (info.address - last.address) as u32;
                                } else if last.memory_range().unwrap() != memory_range {
                                    // We silently drop identical ranges because sometimes
                                    // duplicates happen, but we complain for non-trivial duplicates.
                                    warn!(
                                        "STACK WIN entry had bad intersections, dropping it {:?}",
                                        info
                                    );
                                    return;
                                }
                            }
                        }
                        stack_win.push(info);
                    } else {
                        warn!("STACK WIN entry had invalid range, dropping it {:?}", info);
                    }
                }
                match frame_type {
                    WinFrameType::FrameData(s) => {
                        insert_win_stack_info(&mut stack_win_framedata, s);
                    }
                    WinFrameType::Fpo(s) => {
                        insert_win_stack_info(&mut stack_win_fpo, s);
                    }
                    // Just ignore other types.
                    _ => {}
                }
            }
            Line::StackCfi(s) => {
                stack_cfi.push(s);
            }
        }
    }
    publics.sort();
    SymbolFile {
        files,
        publics,
        functions: funcs
            .into_iter()
            .map(|f| (f.memory_range(), f))
            .into_rangemap_safe(),
        cfi_stack_info: stack_cfi
            .into_iter()
            .map(|s| (s.memory_range(), s))
            .into_rangemap_safe(),
        win_stack_framedata_info: stack_win_framedata
            .into_iter()
            .map(|s| (s.memory_range(), s))
            .into_rangemap_safe(),
        win_stack_fpo_info: stack_win_fpo
            .into_iter()
            .map(|s| (s.memory_range(), s))
            .into_rangemap_safe(),
        // Will get filled in by the caller
        url,
        // TODO
        ambiguities_repaired: 0,
        // TODO
        ambiguities_discarded: 0,
        // TODO
        corruptions_discarded: 0,
        // TODO
        cfi_eval_corruptions: 0,
    }
}

// Matches an entire symbol file.
named!(symbol_file<&[u8], SymbolFile>,
  chain!(
    module_line? ~
    lines: many0!(line) ,
    || { symbol_file_from_lines(lines) })
);

/// Parse a `SymbolFile` from `bytes`.
pub fn parse_symbol_bytes(bytes: &[u8]) -> Result<SymbolFile, SymbolError> {
    match symbol_file(bytes) {
        Done(rest, symfile) => {
            if rest == b"" {
                Ok(symfile)
            } else {
                // Junk left over, or maybe didn't parse anything.
                let next_line = rest
                    .split(|b| *b == b'\r')
                    .next()
                    .map(String::from_utf8_lossy)
                    .unwrap_or(Cow::Borrowed(""));
                Err(format_err!(
                    "Failed to parse file, next line was: `{}`",
                    next_line
                ))
            }
        }
        Error(e) => Err(format_err!("Failed to parse file: {}", e)),
        Incomplete(_) => Err(format_err!("Failed to parse file: incomplete data")),
    }
    .map_err(SymbolError::ParseError)
}

/// Parse a `SymbolFile` from `path`.
pub fn parse_symbol_file(path: &Path) -> Result<SymbolFile, SymbolError> {
    let mut f = File::open(path)
        .map_err(|e| SymbolError::LoadError(format_err!("Failed to open file: {}", e)))?;
    let mut bytes = vec![];
    f.read_to_end(&mut bytes)
        .map_err(|e| SymbolError::LoadError(format_err!("Failed to read file: {}", e)))?;
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

/// Sometimes dump_syms on Windows does weird things and produces multiple carriage returns
/// before the line feed.
#[test]
fn test_module_line_crcrlf() {
    let line = b"MODULE Windows x86_64 D3096ED481217FD4C16B29CD9BC208BA0 firefox\r\r\n";
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
fn test_info_url() {
    let line = b"INFO URL https://www.example.com\n";
    let url = "https://www.example.com".to_string();
    let rest = &b""[..];
    assert_eq!(info_url(line), Done(rest, Info::Url(url)));
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
fn test_public_with_m() {
    let line = b"PUBLIC m f00d d00d some func\n";
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
    use range_map::RangeMap;
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
        panic!("Failed to parse!");
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
        panic!("Failed to parse!");
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
        Error(e) => panic!("{}", format!("Parse error: {:?}", e)),
        Incomplete(_) => panic!("Incomplete parse!"),
        _ => panic!("Something bad happened"),
    }
}

#[test]
fn test_stack_win_line_frame_data() {
    let line = b"STACK WIN 0 1000 30 a1 b2 c3 d4 e5 f6 0 1\n";
    match stack_win_line(line) {
        Done(rest, WinFrameType::Fpo(stack)) => {
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
        Error(e) => panic!("{}", format!("Parse error: {:?}", e)),
        Incomplete(_) => panic!("Incomplete parse!"),
        _ => panic!("Something bad happened"),
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
            CfiRules {
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
                CfiRules {
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
            StackInfoCfi {
                init: CfiRules {
                    address: 0xbadf00d,
                    rules: "init rules".to_string(),
                },
                size: 0xabc,
                add_rules: vec![
                    CfiRules {
                        address: 0xdeadbeef,
                        rules: "more rules".to_string(),
                    },
                    CfiRules {
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
    let funcs = sym
        .functions
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
    let ws = sym
        .win_stack_framedata_info
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
    let ws = sym
        .win_stack_fpo_info
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
    let cs = sym
        .cfi_stack_info
        .ranges_values()
        .map(|&(_, ref s)| s.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        cs[0],
        StackInfoCfi {
            init: CfiRules {
                address: 0xf00f,
                rules: "more init rules".to_string(),
            },
            size: 0xf0,
            add_rules: vec![],
        }
    );
    assert_eq!(
        cs[1],
        StackInfoCfi {
            init: CfiRules {
                address: 0xbadf00d,
                rules: "init rules".to_string(),
            },
            size: 0xabc,
            add_rules: vec![
                CfiRules {
                    address: 0xdeadbeef,
                    rules: "more rules".to_string(),
                },
                CfiRules {
                    address: 0xdeadf00d,
                    rules: "some rules".to_string(),
                },
            ],
        }
    );
}

/// Test that parsing a symbol file with overlapping FUNC/line data works.
#[test]
fn test_parse_with_overlap() {
    //TODO: deal with duplicate PUBLIC records? Not as important since they don't go
    // into a RangeMap.
    let bytes = b"MODULE Linux x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin
FILE 0 foo.c
PUBLIC abcd 10 func 1
PUBLIC ff00 3 func 2
FUNC 1000 30 10 some func
1000 10 42 0
1000 10 43 0
1001 10 44 0
1001 5 45 0
1010 10 52 0
FUNC 1000 30 10 some func overlap exact
FUNC 1001 30 10 some func overlap end
FUNC 1001 10 10 some func overlap contained
";
    let sym = parse_symbol_bytes(&bytes[..]).unwrap();
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
    assert_eq!(sym.functions.ranges_values().count(), 1);
    let funcs = sym
        .functions
        .ranges_values()
        .map(|&(_, ref f)| f)
        .collect::<Vec<_>>();
    {
        let f = &funcs[0];
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
                        file: 0,
                        line: 42,
                    },
                ),
                &(
                    Range::new(0x1010, 0x101F),
                    SourceLine {
                        address: 0x1010,
                        size: 0x10,
                        file: 0,
                        line: 52,
                    },
                ),
            ]
        );
    }
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
        )
        .is_err(),
        "Should fail to parse malformed MODULE line"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FILE x foo.c
"[..]
        )
        .is_err(),
        "Should fail to parse malformed FILE line"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FUNC xx 1 2 foo
"[..]
        )
        .is_err(),
        "Should fail to parse malformed FUNC line"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
this is some junk
"[..]
        )
        .is_err(),
        "Should fail to parse malformed file"
    );

    assert!(
        parse_symbol_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FILE 0 foo.c
FILE"[..]
        )
        .is_err(),
        "Should fail to parse truncated file"
    );

    assert!(
        parse_symbol_bytes(&b""[..]).is_err(),
        "Should fail to parse empty file"
    );
}

#[test]
fn test_parse_stack_win_inconsistent() {
    // Various cases where the has_program_string value is inconsistent
    // with the type of the STACK WIN entry.
    //
    // type=0 (FPO) should go with has_program_string==0 (false)
    // type=4 (FrameData) should go with has_program_string==1 (true)
    //
    // Only 4d93e and 8d93e are totally valid.
    //
    // Current policy is to discard all the other ones, but all the cases
    // are here in case we decide on a more sophisticated heuristic.

    let bytes = b"MODULE Windows x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin
FILE 0 foo.c
STACK WIN 0 1d93e 4 4 0 0 10 0 0 1 1
STACK WIN 0 2d93e 4 4 0 0 10 0 0 1 0
STACK WIN 0 3d93e 4 4 0 0 10 0 0 1 prog string
STACK WIN 0 4d93e 4 4 0 0 10 0 0 0 1
STACK WIN 4 5d93e 4 4 0 0 10 0 0 0 1
STACK WIN 4 6d93e 4 4 0 0 10 0 0 0 0
STACK WIN 4 7d93e 4 4 0 0 10 0 0 0 prog string
STACK WIN 4 8d93e 4 4 0 0 10 0 0 1 prog string
";
    let sym = parse_symbol_bytes(&bytes[..]).unwrap();

    assert_eq!(sym.win_stack_framedata_info.ranges_values().count(), 1);
    let ws = sym
        .win_stack_framedata_info
        .ranges_values()
        .map(|&(_, ref s)| s)
        .collect::<Vec<_>>();
    {
        let stack = &ws[0];
        assert_eq!(stack.address, 0x8d93e);
        assert_eq!(stack.size, 0x4);
        assert_eq!(stack.prologue_size, 0x4);
        assert_eq!(stack.epilogue_size, 0);
        assert_eq!(stack.parameter_size, 0);
        assert_eq!(stack.saved_register_size, 0x10);
        assert_eq!(stack.local_size, 0);
        assert_eq!(stack.max_stack_size, 0);
        assert_eq!(
            stack.program_string_or_base_pointer,
            WinStackThing::ProgramString("prog string".to_string())
        );
    }
    assert_eq!(sym.win_stack_fpo_info.ranges_values().count(), 1);
    let ws = sym
        .win_stack_fpo_info
        .ranges_values()
        .map(|&(_, ref s)| s)
        .collect::<Vec<_>>();
    {
        let stack = &ws[0];
        assert_eq!(stack.address, 0x4d93e);
        assert_eq!(stack.size, 0x4);
        assert_eq!(stack.prologue_size, 0x4);
        assert_eq!(stack.epilogue_size, 0);
        assert_eq!(stack.parameter_size, 0);
        assert_eq!(stack.saved_register_size, 0x10);
        assert_eq!(stack.local_size, 0);
        assert_eq!(stack.max_stack_size, 0);
        assert_eq!(
            stack.program_string_or_base_pointer,
            WinStackThing::AllocatesBasePointer(true)
        );
    }
}
