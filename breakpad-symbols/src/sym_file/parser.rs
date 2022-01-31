// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use log::warn;
use nom::IResult::*;
use nom::*;
use range_map::{Range, RangeMap};

use std::collections::HashMap;
use std::fmt::Debug;
use std::str;
use std::str::FromStr;

use minidump_common::traits::IntoRangeMapSafe;

use crate::sym_file::types::*;
use crate::SymbolError;

#[derive(Debug)]
enum Line {
    Module,
    Info(Info),
    File(u32, String),
    Public(PublicSymbol),
    Function(Function, Vec<SourceLine>),
    StackWin(WinFrameType),
    StackCfi(StackInfoCfi),
}

// Nom's `eol` doesn't use complete! so it will return Incomplete.
named!(
    my_eol<char>,
    complete!(preceded!(many0!(char!('\r')), char!('\n')))
);

// Match a hex string, parse it t)o a u64.
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
named!(file_line<&[u8], (u32, String)>,
  chain!(
    tag!("FILE") ~
    space ~
    id: decimal_u32 ~
    space ~
    filename: map_res!(not_line_ending, str::from_utf8) ~
    my_eol ,
      ||{ (id, filename.to_string()) }
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

// Matches a FUNC record.
named!(func_line<&[u8], Function>,
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
  my_eol ,
    || {
        Function {
            address,
            size,
            parameter_size,
            name: name.to_string(),
            lines: RangeMap::new(),
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
named!(stack_cfi_init<&[u8], StackInfoCfi>,
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
          StackInfoCfi {
              init: CfiRules {
                  address,
                  rules: rules.to_string(),
              },
              size,
              add_rules: Default::default(),
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
    func_line => { |f| Line::Function(f, Vec::new()) } |
    stack_win_line => { Line::StackWin } |
    stack_cfi_init => { Line::StackCfi } |
    module_line => { |_| Line::Module }
));

/// A parser for SymbolFiles.
///
/// This is basically just a SymbolFile but with some extra state
/// to handle streaming parsing.
///
/// Use this by repeatedly calling [`parse_more`][] until the
/// whole input is consumed. Then call [`finish`][].
#[derive(Debug, Default)]
pub struct SymbolParser {
    files: HashMap<u32, String>,
    publics: Vec<PublicSymbol>,

    // When building a RangeMap when need to sort an array of this
    // format anyway, so we might as well construct it directly and
    // save a giant allocation+copy.
    functions: Vec<(Range<u64>, Function)>,
    cfi_stack_info: Vec<(Range<u64>, StackInfoCfi)>,
    win_stack_framedata_info: Vec<(Range<u64>, StackInfoWin)>,
    win_stack_fpo_info: Vec<(Range<u64>, StackInfoWin)>,
    url: Option<String>,
    pub lines: u64,
    cur_item: Option<Line>,
}

impl SymbolParser {
    /// Creates a new SymbolParser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses as much of the input as it can, and then returns
    /// how many bytes of the input was used. The *unused* portion of the
    /// input must be resubmitted on subsequent calls to parse_more
    /// (along with more data so we can make progress on the parse).
    pub fn parse_more(&mut self, mut input: &[u8]) -> Result<usize, SymbolError> {
        // We parse the input line-by-line, so trim away any part of the input
        // that comes after the last newline (this is necessary for streaming
        // parsing, as it can otherwise be impossible to tell if a line is
        // truncated.)
        input = if let Some(idx) = input.iter().rposition(|&x| x == b'\n') {
            &input[..idx + 1]
        } else {
            // If there's no newline, then we can't process anything!
            return Ok(0);
        };
        // Remember the (truncated) input so that we can tell how many bytes
        // we've consumed.
        let orig_input = input;

        loop {
            // If there's no more input, then we've consumed all of it
            // (except for the partial line we trimmed away).
            if input.is_empty() {
                return Ok(orig_input.len());
            }

            // First check if we're currently processing sublines of a
            // multi-line item like `FUNC` and `STACK CFI INIT`.
            // If we are, parse the next line as its subline format.
            //
            // If we encounter an error, this probably means we've
            // reached a new item (which ends this one). To handle this,
            // we can just finish off the current item and resubmit this
            // line to the top-level parser (below). If the line is
            // genuinely corrupt, then the top-level parser will also
            // fail to read it.
            //
            // We `take` and then reconstitute the item for borrowing/move
            // reasons.
            match self.cur_item.take() {
                Some(Line::Function(cur, mut lines)) => match func_line_data(input) {
                    Done(new_input, line) => {
                        lines.push(line);
                        input = new_input;
                        self.cur_item = Some(Line::Function(cur, lines));
                        self.lines += 1;
                        continue;
                    }
                    Error(_) | Incomplete(_) => {
                        self.finish_item(Line::Function(cur, lines));
                        continue;
                    }
                },
                Some(Line::StackCfi(mut cur)) => match stack_cfi(input) {
                    Done(new_input, line) => {
                        cur.add_rules.push(line);
                        input = new_input;
                        self.cur_item = Some(Line::StackCfi(cur));
                        self.lines += 1;
                        continue;
                    }
                    Error(_) | Incomplete(_) => {
                        self.finish_item(Line::StackCfi(cur));
                        continue;
                    }
                },
                _ => {
                    // We're not parsing sublines, move on to top level parser!
                }
            }

            // Parse a top-level item, and first handle the Result
            let line = match line(input) {
                Done(new_input, line) => {
                    // Success! Advance the input.
                    input = new_input;
                    line
                }
                Error(_) => {
                    // The file has a completely corrupt line,
                    // conservatively reject the entire parse.
                    return Err(SymbolError::ParseError("failed to parse file", self.lines));
                }
                Incomplete(_) => {
                    // One of our sub-parsers wants more input, which normally
                    // would be fine for a streaming parser, bust the newline
                    // preprocessing we do means this should never happen.
                    // So Incomplete input is just another kind of parsing Error.
                    return Err(SymbolError::ParseError("line was incomplete!", self.lines));
                }
            };

            // Now store the item in our partial SymbolFile (or make it the cur_item
            // if it has potential sublines we need to parse first).
            match line {
                Line::Module => {
                    // We don't use this but it MUST be the first line
                    if self.lines != 0 {
                        return Err(SymbolError::ParseError(
                            "MODULE line found after the start of the file",
                            self.lines,
                        ));
                    }
                }
                Line::Info(Info::Url(cached_url)) => {
                    self.url = Some(cached_url);
                }
                Line::Info(Info::Unknown) => {
                    // Don't care
                }
                Line::File(id, filename) => {
                    self.files.insert(id, filename.to_string());
                }
                Line::Public(p) => {
                    self.publics.push(p);
                }
                Line::StackWin(frame_type) => {
                    // PDB files contain lots of overlapping unwind info, so we have to filter
                    // some of it out.
                    fn insert_win_stack_info(
                        stack_win: &mut Vec<(Range<u64>, StackInfoWin)>,
                        info: StackInfoWin,
                    ) {
                        if let Some(memory_range) = info.memory_range() {
                            if let Some((last_range, last_info)) = stack_win.last_mut() {
                                if last_range.intersects(&memory_range) {
                                    if info.address > last_info.address {
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
                                        last_info.size = (info.address - last_info.address) as u32;
                                        *last_range = last_info.memory_range().unwrap();
                                    } else if *last_range != memory_range {
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
                            stack_win.push((memory_range, info));
                        } else {
                            warn!("STACK WIN entry had invalid range, dropping it {:?}", info);
                        }
                    }
                    match frame_type {
                        WinFrameType::FrameData(s) => {
                            insert_win_stack_info(&mut self.win_stack_framedata_info, s);
                        }
                        WinFrameType::Fpo(s) => {
                            insert_win_stack_info(&mut self.win_stack_fpo_info, s);
                        }
                        // Just ignore other types.
                        _ => {}
                    }
                }
                item @ Line::Function(_, _) => {
                    // More sublines to parse
                    self.cur_item = Some(item);
                }
                item @ Line::StackCfi(_) => {
                    // More sublines to parse
                    self.cur_item = Some(item);
                }
            }

            // Make note that we've consumed a line of input.
            self.lines += 1;
        }
    }

    /// Finish processing an item (cur_item) which had sublines.
    /// We now have all the sublines, so it's complete.
    fn finish_item(&mut self, item: Line) {
        match item {
            Line::Function(mut cur, lines) => {
                cur.lines = lines
                    .into_iter()
                    .map(|l| {
                        // Line data from PDB files often has a zero-size line entry, so just
                        // filter those out.
                        if l.size > 0 {
                            if let Some(end) = l.address.checked_add(l.size as u64 - 1) {
                                (Some(Range::new(l.address, end)), l)
                            } else {
                                (None, l)
                            }
                        } else {
                            (None, l)
                        }
                    })
                    .into_rangemap_safe();

                if let Some(range) = cur.memory_range() {
                    self.functions.push((range, cur));
                }
            }
            Line::StackCfi(mut cur) => {
                cur.add_rules.sort();
                if let Some(range) = cur.memory_range() {
                    self.cfi_stack_info.push((range, cur));
                }
            }
            _ => {
                unreachable!()
            }
        }
    }

    /// Finish the parse and create the final SymbolFile.
    ///
    /// Call this when the parser has consumed all the input.
    pub fn finish(mut self) -> SymbolFile {
        // If there's a pending multiline item, finish it now.
        if let Some(item) = self.cur_item.take() {
            self.finish_item(item);
        }

        // Now sort everything and bundle it up in its final format.
        self.publics.sort();

        SymbolFile {
            files: self.files,
            publics: self.publics,
            functions: into_rangemap_safe(self.functions),
            cfi_stack_info: into_rangemap_safe(self.cfi_stack_info),
            win_stack_framedata_info: into_rangemap_safe(self.win_stack_framedata_info),
            win_stack_fpo_info: into_rangemap_safe(self.win_stack_fpo_info),
            // Will get filled in by the caller
            url: self.url,
            ambiguities_repaired: 0,
            ambiguities_discarded: 0,
            corruptions_discarded: 0,
            cfi_eval_corruptions: 0,
        }
    }
}

// Copied from minidump-common, because we've preconstructed the array to sort.
fn into_rangemap_safe<V: Clone + Eq + Debug>(mut input: Vec<(Range<u64>, V)>) -> RangeMap<u64, V> {
    input.sort_by_key(|x| x.0);
    let mut vec: Vec<(Range<u64>, V)> = Vec::with_capacity(input.len());
    for (range, val) in input {
        if let Some((last_range, last_val)) = vec.last_mut() {
            if range.start <= last_range.end && val != *last_val {
                continue;
            }

            if range.start <= last_range.end.saturating_add(1) && &val == last_val {
                last_range.end = std::cmp::max(range.end, last_range.end);
                continue;
            }
        }
        vec.push((range, val));
    }
    RangeMap::from_sorted_vec(vec)
}

#[cfg(test)]
fn parse_symbol_bytes(data: &[u8]) -> Result<SymbolFile, SymbolError> {
    SymbolFile::parse(data, |_| ())
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
    assert_eq!(file_line(line), Done(rest, (1, String::from("foo.c"))));
}

#[test]
fn test_file_line_spaces() {
    let line = b"FILE  1234  foo bar.xyz\n";
    let rest = &b""[..];
    assert_eq!(
        file_line(line),
        Done(rest, (1234, String::from("foo bar.xyz")))
    );
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
        func_line(line),
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
    let file = SymbolFile::from_bytes(data).expect("failed to parse!");
    let (_, f) = file.functions.ranges_values().next().unwrap();
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
}

#[test]
fn test_func_with_m() {
    let data = b"FUNC m 1000 30 10 some func
1000 10 42 7
1010 10 52 8
1020 10 62 15
";
    let file = SymbolFile::from_bytes(data).expect("failed to parse!");
    let (_, _f) = file.functions.ranges_values().next().unwrap();
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
            StackInfoCfi {
                init: CfiRules {
                    address: 0xbadf00d,
                    rules: "init rules".to_string(),
                },
                size: 0xabc,
                add_rules: vec![],
            }
        )
    );
}

#[test]
fn test_stack_cfi_lines() {
    let data = b"STACK CFI INIT badf00d abc init rules
STACK CFI deadf00d some rules
STACK CFI deadbeef more rules
";
    let file = SymbolFile::from_bytes(data).expect("failed to parse!");
    let (_, cfi) = file.cfi_stack_info.ranges_values().next().unwrap();
    assert_eq!(
        cfi,
        &StackInfoCfi {
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

#[test]
fn address_size_overflow() {
    let bytes = b"FUNC 1 2 3 x\nffffffffffffffff 2 0 0\n";
    let sym = parse_symbol_bytes(bytes.as_slice()).unwrap();
    let fun = sym.functions.get(1).unwrap();
    assert!(fun.lines.is_empty());
    assert!(fun.name == "x");
}
