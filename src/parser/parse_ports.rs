// Port of snort3 src/parser/parse_ports.cc + parse_ports.h
// (POParser state machine + PortObjectParseString).
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//           Copyright (C) 2005-2013 Sourcefire, Inc.
//
// The C char-by-char state machine (POParserInit/POPGetChar/POPGetChar2/
// POPUnGetChar/POPPeekChar/POPSkipSpace with pos/slen bookkeeping) is ported
// over an owned byte vector with identical accept/reject and errflag
// behavior: '$' var lookup via PortVarTable (add_if_not_found = true),
// recursive '[' lists via _POFindMatchingBraces plus the pointer-equality
// cursor jump, '!' negate-flag-only toggling (applied by normalize), and
// strtoul port reading INCLUDING the C `(int)` cast wrap: strtoul saturates
// to ULONG_MAX on ERANGE and (int) wraps, so "100:4294967396" parses as
// 100:100 while 21+ digit inputs hit POPERR_BOUNDS. Parity is enforced
// against ground-truth vectors generated from the original sources
// (tools/cpp_harness; see tests/ports_parity_test.rs).

#![allow(dead_code)]

use crate::ports::port_object::PortObject;
use crate::ports::port_var_table::PortVarTable;

pub const POPERR_NO_NAME: i32 = 1;
pub const POPERR_NO_ENDLIST_BRACKET: i32 = 2;
pub const POPERR_NOT_A_NUMBER: i32 = 3;
pub const POPERR_EXTRA_BRACKET: i32 = 4;
pub const POPERR_NO_DATA: i32 = 5;
pub const POPERR_ADDITEM_FAILED: i32 = 6;
pub const POPERR_MALLOC_FAILED: i32 = 7;
pub const POPERR_INVALID_RANGE: i32 = 8;
pub const POPERR_DUPLICATE_ENTRY: i32 = 9;
pub const POPERR_BOUNDS: i32 = 10;
pub const POPERR_BAD_VARIABLE: i32 = 11;

pub const POP_MAX_BUFFER_SIZE: usize = 256;

fn c_isspace(c: u8) -> bool {
    // C isspace in the "C" locale
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

pub struct POParser<'tbl> {
    s: Vec<u8>, // owned copy; C++ pop->s == &s[i0]
    i0: usize,
    slen: usize,
    pos: usize,
    token: Vec<u8>, // token[POP_MAX_BUFFER_SIZE+4]
    errflag_: i32,
    pv_table: Option<&'tbl mut PortVarTable>,
    dump_rule_info: bool,
}

impl<'tbl> POParser<'tbl> {
    pub fn errflag(&self) -> i32 {
        self.errflag_
    }

    /// POParserInit: memset 0 then set pos/s/slen/errflag/pvTable
    fn init(s: &str, pv_table: Option<&'tbl mut PortVarTable>, dump_rule_info: bool) -> Self {
        POParser {
            s: s.as_bytes().to_vec(),
            i0: 0,
            slen: s.len(),
            pos: 0,
            token: Vec::new(),
            errflag_: 0,
            pv_table,
            dump_rule_info,
        }
    }

    /// POPGetChar (0 == end sentinel; snort port strings carry no NULs)
    fn pop_get_char(&mut self) -> u8 {
        if self.slen > 0 {
            let c = self.s[self.i0];
            self.slen -= 1;
            self.i0 += 1;
            self.pos += 1;
            c
        } else {
            0
        }
    }

    /// POPGetChar2: skip whitespace and commas
    fn pop_get_char2(&mut self) -> u8 {
        loop {
            let c = self.pop_get_char();
            if c == 0 {
                return 0;
            }
            if c_isspace(c) || c == b',' {
                continue;
            }
            return c;
        }
    }

    /// POPUnGetChar
    fn pop_unget_char(&mut self) {
        if self.pos > 0 {
            self.slen += 1;
            self.i0 -= 1;
            self.pos -= 1;
        }
    }

    /// POPPeekChar
    fn pop_peek_char(&self) -> u8 {
        if self.slen > 0 {
            self.s[self.i0]
        } else {
            0
        }
    }

    /// POPSkipSpace
    fn pop_skip_space(&mut self) -> u8 {
        loop {
            let c = self.pop_peek_char();
            if c == 0 {
                return 0;
            }
            if !c_isspace(c) && c != b',' {
                return c;
            }
            self.pop_get_char();
        }
    }

    /// POParserName(): exact loop order of the C
    /// `for (c = POPGetChar; c != 0 && k < POP_MAX_BUFFER_SIZE; c = POPGetChar)`
    /// — the char driving the k-bound check is already consumed.
    fn poparser_name(&mut self) -> Option<String> {
        if self.i0 >= self.s.len() || self.s[self.i0] == 0 {
            return None; // !pop->s || !*(pop->s)
        }
        let mut c = self.pop_get_char2();
        if c == 0 {
            return None;
        }
        if c == b'$' {
            // skip leading '$' - old Var indicator
            c = self.pop_get_char2();
            if c == 0 {
                return None;
            }
        }
        self.token.clear();
        if c.is_ascii_alphanumeric() {
            self.token.push(c);
        } else {
            self.pop_unget_char();
            return None; // not a name
        }
        loop {
            c = self.pop_get_char();
            if c == 0 || self.token.len() >= POP_MAX_BUFFER_SIZE {
                break;
            }
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' {
                self.token.push(c);
            } else {
                self.pop_unget_char();
                break;
            }
        }
        Some(String::from_utf8_lossy(&self.token).into_owned())
    }

    /// POParserGetShort(): strtoul(buffer, &pend, 10) semantics — ERANGE
    /// saturates to ULONG_MAX — followed by the C `(int)` cast wrap and the
    /// `c > 65535 || c < 0` bounds check on the WRAPPED value.
    fn poparser_get_short(&mut self) -> u16 {
        self.pop_skip_space();
        self.token.clear(); // C: pop->token[0]=0 happens in _POParsePort,
                            // but GetShort uses a local char buffer[32]; the
                            // cap is 31 digits ("thats all that fits").
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            let c = self.pop_get_char();
            if c == 0 {
                break;
            }
            if c.is_ascii_digit() {
                buffer.push(c);
                if buffer.len() == 31 {
                    break; // sizeof(buffer)-1
                }
            } else {
                if !(c == b':' || c == b' ' || c == b']' || c == b',' || c == b'\t' || c == b'\n') {
                    self.errflag_ = POPERR_NOT_A_NUMBER;
                    return 0; // char stays consumed, exactly like the C return
                }
                self.pop_unget_char();
                break;
            }
        }

        // strtoul (64-bit unsigned long on this platform) + (int) cast.
        let mut val: u64 = 0;
        let mut erange = false;
        for &d in buffer.iter() {
            match val.checked_mul(10).and_then(|x| x.checked_add((d - b'0') as u64)) {
                Some(v) => val = v,
                None => {
                    val = u64::MAX; // ERANGE: strtoul returns ULONG_MAX
                    erange = true;
                }
            }
        }
        let _ = erange;
        let c = val as i32; // C's (int) cast wraps
        if !(0..=65535).contains(&c) {
            self.errflag_ = POPERR_BOUNDS;
            return 0;
        }
        c as u16
    }

    /// _POParseVar(): PortVarTableFind(pvTable, name, true) then Dup.
    fn pop_parse_var(&mut self) -> Option<PortObject> {
        let name = match self.poparser_name() {
            Some(n) => n,
            None => {
                self.pos += 1; // C quirk: pop->pos++ before the error
                self.errflag_ = POPERR_NO_NAME;
                return None;
            }
        };
        let found = match self.pv_table.as_mut() {
            Some(t) => t.find(&name, true, self.dump_rule_info),
            None => None, // PortVarTableFind(nullptr, ...) -> nullptr
        };
        match found {
            Some(pox) => Some(
                pox, // PortObjectDup of the found entry
            ),
            None => {
                self.errflag_ = POPERR_BAD_VARIABLE;
                None
            }
        }
    }

    /// _POParsePort()
    fn pop_parse_port(&mut self) -> Option<PortObject> {
        let mut po = PortObject::new();
        self.token.clear(); // pop->token[0] = 0

        let lport = self.poparser_get_short();
        if self.errflag_ != 0 {
            return None;
        }

        let mut c = self.pop_peek_char();
        if c == b':' {
            // half open range
            self.pop_get_char();
            c = self.pop_peek_char();
            if (c == 0 && self.slen == 0) || c == b',' {
                // Open ended range, highport is 65k
                po.add_range(lport as i32, 65535);
                return Some(po);
            }
            if !c.is_ascii_digit() {
                self.errflag_ = POPERR_NOT_A_NUMBER;
                return None;
            }
            let hport = self.poparser_get_short();
            if self.errflag_ != 0 {
                return None;
            }
            if lport > hport {
                self.errflag_ = POPERR_INVALID_RANGE;
                return None;
            }
            po.add_range(lport as i32, hport as i32);
        } else {
            po.add_port(lport as i32);
        }
        Some(po)
    }

    /// _POFindMatchingBraces(s): returns the absolute index in self.s of the
    /// matching ']', scanning from `from` (pop->s); C ++s++ do-while over NUL.
    fn po_find_matching_braces(&self, from: usize) -> Option<usize> {
        let mut depth: u32 = 0;
        let mut k = from;
        loop {
            match self.s.get(k) {
                None | Some(0) => {
                    // *s == 0 terminates the do-while
                    return None;
                }
                Some(&c) => {
                    if c == b'[' {
                        depth += 1;
                    } else if c == b']' {
                        if depth == 0 {
                            return Some(k);
                        }
                        depth -= 1;
                    }
                    k += 1;
                }
            }
        }
    }

    /// _POParseString()
    fn pop_parse_string(&mut self) -> Option<PortObject> {
        let mut po = PortObject::new();
        let mut local_neg = false;
        let mut list_count = 0i32;

        while {
            let c = self.pop_get_char2();
            c != 0
        } {
            let c = self.s[self.i0 - 1]; // the char just returned
            let potmp: PortObject;
            if c == b'!' {
                local_neg = true;
                continue;
            }
            if c == b'$' {
                // Don't dup this again - the returned PortObject has already
                // been dup'ed
                potmp = self.pop_parse_var()?;
            } else if c == b'[' {
                // Start of a list. Tokenize list and recurse on it.
                list_count += 1;
                let end = match self.po_find_matching_braces(self.i0) {
                    Some(e) => e,
                    None => {
                        self.errflag_ = POPERR_NO_ENDLIST_BRACKET;
                        return None;
                    }
                };
                // tok = snort_strndup(pop->s, end - pop->s); child shares the
                // var table (pop->pvTable) exactly as in C.
                let tok: Vec<u8> = self.s[self.i0..end].to_vec();
                let tok_str = String::from_utf8_lossy(&tok).into_owned();
                let table = self.pv_table.take();
                let mut child = POParser {
                    s: tok_str.into_bytes(),
                    i0: 0,
                    slen: 0,
                    pos: 0,
                    token: Vec::new(),
                    errflag_: 0,
                    pv_table: table,
                    dump_rule_info: self.dump_rule_info,
                };
                child.slen = child.s.len();
                let child_res = child.pop_parse_string();
                let cerr = child.errflag_;
                self.pv_table = child.pv_table.take();
                potmp = match child_res {
                    Some(p) => p,
                    None => {
                        self.errflag_ = cerr;
                        return None;
                    }
                };
                // Advance "cursor" to end of this list:
                //   while (c && pop->s != end) c = POPGetChar(pop);
                let mut cc = c;
                while cc != 0 && self.i0 < end {
                    cc = self.pop_get_char();
                }
            } else if c == b']' {
                list_count -= 1;
                if list_count < 0 {
                    self.errflag_ = POPERR_EXTRA_BRACKET;
                    return None;
                }
                continue;
            } else {
                self.pop_unget_char();
                potmp = self.pop_parse_port()?;
            }

            let mut potmp = potmp;
            if local_neg {
                // intentionally only sets the negation flag! The actual
                // negation takes place when normalization is called.
                potmp.toggle();
                local_neg = false;
            }

            let mut err = 0i32;
            if po.add_port_object(&potmp, &mut err) != 0 {
                self.errflag_ = err.max(self.errflag_);
                return None;
            }
        }

        // Check for mis-matched brackets
        if list_count != 0 {
            if list_count > 0 {
                self.errflag_ = POPERR_NO_ENDLIST_BRACKET;
            } else {
                self.errflag_ = POPERR_EXTRA_BRACKET;
            }
            return None;
        }
        Some(po)
    }

    /// PortObjectParseError()
    pub fn error_string(&self) -> &'static str {
        match self.errflag_ {
            POPERR_NO_NAME => "no name",
            POPERR_NO_ENDLIST_BRACKET => {
                "no end of list bracket. Elements must be comma separated, and no spaces may appear between brackets."
            }
            POPERR_NOT_A_NUMBER => "not a number",
            POPERR_EXTRA_BRACKET => "extra list bracket",
            POPERR_NO_DATA => "no data",
            POPERR_ADDITEM_FAILED => "add item failed",
            POPERR_MALLOC_FAILED => "mem alloc failed",
            POPERR_INVALID_RANGE => "invalid port range",
            POPERR_DUPLICATE_ENTRY => "duplicate ports in list",
            POPERR_BOUNDS => "value out of bounds for a port",
            POPERR_BAD_VARIABLE => "unrecognized variable",
            _ => "unknown POParse error",
        }
    }
}

/// PortObject* PortObjectParseString(pvTable, pop, name, s, nameflag):
/// Ok(po) mirrors non-null; Err carries (errflag, message). name is borrowed;
/// C strdup'd it ("noname" when null).
pub fn port_object_parse_string(
    pv_table: Option<&mut PortVarTable>,
    name: Option<&str>,
    s: &str,
    nameflag: bool,
    dump_rule_info: bool,
) -> Result<PortObject, (i32, &'static str)> {
    port_object_parse_string_with_pos(pv_table, name, s, nameflag, dump_rule_info)
        .map_err(|(e, m, _)| (e, m))
}

/// Same as port_object_parse_string but also surfaces pop->pos at the point
/// of failure (parser/vars.cc ParsePortVar feeds it into the ParseAbort
/// caret message ">>%*s").
pub fn port_object_parse_string_with_pos(
    pv_table: Option<&mut PortVarTable>,
    name: Option<&str>,
    s: &str,
    nameflag: bool,
    dump_rule_info: bool,
) -> Result<PortObject, (i32, &'static str, usize)> {
    let mut pop = POParser::init(s, pv_table, dump_rule_info);

    let po_name = if nameflag {
        match pop.poparser_name() {
            Some(n) => Some(n),
            None => {
                pop.errflag_ = POPERR_NO_NAME;
                return Err((pop.errflag(), pop.error_string(), pop.pos));
            }
        }
    } else {
        Some(name.unwrap_or("noname").to_string())
    };

    let mut potmp = match pop.pop_parse_string() {
        Some(p) => p,
        None => return Err((pop.errflag(), pop.error_string(), pop.pos)),
    };

    potmp.normalize();

    // Catches !:65535
    if potmp.items.is_empty() {
        pop.errflag_ = POPERR_INVALID_RANGE;
        return Err((pop.errflag(), pop.error_string(), pop.pos));
    }

    let mut po = PortObject::new();
    po.name = po_name;
    let mut err = 0i32;
    if po.add_port_object(&potmp, &mut err) != 0 {
        return Err((pop.errflag(), pop.error_string(), pop.pos));
    }
    Ok(po)
}
