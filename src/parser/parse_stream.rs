//! parse_stream.{h,cc} — the rules tokenizer FSM, literal transcription of
//! /opt/data/snort3-src/src/parser/parse_stream.cc @ fe29cbe7403a.
//! Ground truth: tools/rules_harness (REAL parse_stream.cc compiled into
//! the probe; stream-block vectors S1/S2/S3 + FATAL_DEMO=3
//! abort-through-FSM).
//!
//! Plumbing note (argument split, NOT behavior): C's parse_stream reaches
//! parse_conf state through file-scope statics (inc_parse_position,
//! parse_include). The Rust port threads ParseConf into get_token for
//! inc_parse_position. FSM_INC routes through the ParseConf include seam
//! (the seam receives pc and re-enters the stream): C's parse_include ->
//! parse_rules_file -> parse_stream recursion lives entirely on the
//! ParseConf side, so parse_stream itself never calls ParseConf include
//! helpers. The bytes an ifstream would yield ride the seam's `data`
//! parameter (C ifstream <-> Rust std::fs::read; see parse_conf).
//!
//! C-fidelity points pinned by / exercised by the harness:
//!  * get_token's `static int prev = EOF; static int pos = 0;` live for the
//!    stream lifetime: the probe drives TWO parse_rules_string calls and
//!    they share both statics (a "prev" token is never re-read by the next
//!    call). Rust keeps them in a StreamCtx the driver owns across calls.
//!  * Counter statics: `lines = 1`, everything else 0.
//!  * punct tables: C's `if (s->punct)` keeps nullptr rows from updating
//!    the table while "" rows (non-null) DO update it (clearing it).
//!    Modeled as Option<&str>: None = keep, Some(t) = set ("" = clear).
//!  * `#begin` latches only at pos == 6; `#end` unlatches via a
//!    case-insensitive compare at EVERY append (lengths 1-3 can't match a
//!    4-char NUL compare; kept literal, no extra gate).
//!  * get_state: LINEAR first-match scan of fsm[] — table ORDER is
//!    semantics (row 0 num 0 is the "include" KEY row; the generic ACT
//!    row follows it). Miss -> ParseError("syntax error") and the walk
//!    continues with fsm[0] (action ERR, next 0, punct "" -> CLEARS).
//!  * exec fall-throughs are real C flow: FSM_SPX runs ports("any") THEN
//!    FSM_DIR with the same token; FSM_DPX runs ports("any") THEN opens
//!    (FSM_SOB body); FSM_EOB re-runs FSM_END first when rps.tbd (the
//!    option never saw ';').
//!  * FSM_KEY gates option_begin on tok != "include" only; rps.key latches
//!    either way, so get_escape() sees "include" (esc 1) afterwards.
//!  * rules++ counts every FSM_EOB, latched or not. In C the counter is
//!    file-static and unprinted; Rust parks it on RuleCoreState.stats_rules
//!    for future pinning.
//!  * trailing `if (num) ParseError("incomplete rule")`: num is the state
//!    AFTER the last transition; unclosed body EOFs at num 11 -> fires
//!    ("sid:13; rev:1" vector); clean rules EOF at num 0 -> silent.
//!  * ParseAbort inside the stream (header $port on an undefined var)
//!    terminates the process in C: the Rust port propagates
//!    Err(Fatal::Quitting) out of parse_stream via the ? on every
//!    parse_rule_ports call (pinned: FATAL_DEMO=3 rc=1, same diagnostics
//!    as the direct-drive fatal vectors).
//!  * opt_end with rps.otn null: C only lands there if parse_rule_open
//!    returned null (s_ignore) between SO and OPT/END tokens — C's
//!    unconditional deref would SEGV, but in that exact path option_end's
//!    very first C statement is the s_ignore guard (s_ignore still set),
//!    so upstream is safe-and-silent. Rust skips the call whenever the
//!    slot is null — identical observable behavior (documented).

use crate::detection::parse_rule::{
    parse_rule_close, parse_rule_dir, parse_rule_nets, parse_rule_open, parse_rule_opt_begin,
    parse_rule_opt_end, parse_rule_opt_set, parse_rule_ports, parse_rule_proto, parse_rule_type,
    RuleCoreState,
};
use crate::log::messages::Fatal;
use crate::detection::treenodes::{OtnHandle, RuleTreeNode};
use crate::log::messages::WARN_RULES;
use crate::parser::config_file::ConfFiles;
use crate::utils::cfmt::Arg;
use crate::parser::parse_conf::{ParseConf, SnortConfig};
use crate::parser::vars::VarContext;

// ---------------------------------------------------------------- token types
// enum TokenType { TT_NONE, TT_PUNCT, TT_STRING, TT_LIST, TT_LITERAL, TT_MAX };
const TT_NONE: u8 = 0;
const TT_PUNCT: u8 = 1;
const TT_STRING: u8 = 2;
const TT_LIST: u8 = 3;
const TT_LITERAL: u8 = 4;

// ---------------------------------------------------------------- fsm actions
// enum FsmAction (C declaration order):
const FSM_ACT: u8 = 0;
const FSM_PRO: u8 = 1;
const FSM_HDR: u8 = 2;
const FSM_SIP: u8 = 3;
const FSM_SP: u8 = 4;
const FSM_SPX: u8 = 5;
const FSM_DIR: u8 = 6;
const FSM_DIP: u8 = 7;
const FSM_DP: u8 = 8;
const FSM_DPX: u8 = 9;
const FSM_SOB: u8 = 10;
const FSM_STB: u8 = 11;
const FSM_EOB: u8 = 12;
const FSM_KEY: u8 = 13;
const FSM_OPT: u8 = 14;
const FSM_VAL: u8 = 15;
const FSM_SET: u8 = 16;
const FSM_ADD: u8 = 17;
const FSM_INC: u8 = 18;
const FSM_END: u8 = 19;
const FSM_NOP: u8 = 20;
const FSM_ERR: u8 = 21;

/// struct State { int num; int next; TokenType type; FsmAction action;
///                const char* match; const char* punct; }
/// match "" == C nullptr (wildcard via !s->match). ttype 0: the C
/// "!s->type" test is only ever TRUE for this zero slot AND for TT_NONE
/// tokens; TT_NONE rows in the table (num 14 SET/ADD) carry type
/// TT_NONE(0) — identical semantics to C's "!s->type || type == s->type".
/// punct: None = C nullptr (keep previous table), Some(t) = C table
/// ("" = clear).
struct State {
    num: i32,
    next: i32,
    ttype: u8,
    action: u8,
    r#match: &'static str, // C: match (reserved in Rust)
    punct: Option<&'static str>,
}

/// fsm[] verbatim (declaration order = first-match-wins).
/// (num, next, tt, act, match, punct) — C spacing collapsed; the two
/// literal-match rows with punct "" (num 11/12 EOB ")") carry Some("")
/// exactly like the C source ("\",        \"\"      }").
static FSM: &[State] = &[
    State { num: -1, next: 0, ttype: TT_NONE, action: FSM_ERR, r#match: "", punct: Some("") },
    State { num: 0, next: 15, ttype: TT_LITERAL, action: FSM_KEY, r#match: "include", punct: Some("") },
    State { num: 0, next: 1, ttype: TT_LITERAL, action: FSM_ACT, r#match: "", punct: Some("(") },
    State { num: 1, next: 8, ttype: TT_PUNCT, action: FSM_STB, r#match: "(", punct: Some("(:,;)") },
    State { num: 1, next: 2, ttype: TT_LITERAL, action: FSM_PRO, r#match: "", punct: Some("(") },
    State { num: 2, next: 8, ttype: TT_PUNCT, action: FSM_HDR, r#match: "(", punct: Some("(:,;)") },
    State { num: 2, next: 3, ttype: TT_LIST, action: FSM_SIP, r#match: "", punct: Some("") },
    State { num: 2, next: 3, ttype: TT_LITERAL, action: FSM_SIP, r#match: "", punct: Some("") },
    State { num: 3, next: 5, ttype: TT_LITERAL, action: FSM_SPX, r#match: "->", punct: None },
    State { num: 3, next: 5, ttype: TT_LITERAL, action: FSM_SPX, r#match: "<>", punct: None },
    State { num: 3, next: 4, ttype: TT_LIST, action: FSM_SP, r#match: "", punct: None },
    State { num: 3, next: 4, ttype: TT_LITERAL, action: FSM_SP, r#match: "", punct: None },
    State { num: 4, next: 5, ttype: TT_LITERAL, action: FSM_DIR, r#match: "", punct: None },
    State { num: 5, next: 6, ttype: TT_LIST, action: FSM_DIP, r#match: "", punct: Some("(") },
    State { num: 5, next: 6, ttype: TT_LITERAL, action: FSM_DIP, r#match: "", punct: Some("(") },
    State { num: 6, next: 8, ttype: TT_PUNCT, action: FSM_DPX, r#match: "(", punct: Some("(:,;)") },
    State { num: 6, next: 7, ttype: TT_LIST, action: FSM_DP, r#match: "", punct: Some("(:,;)") },
    State { num: 6, next: 7, ttype: TT_LITERAL, action: FSM_DP, r#match: "", punct: Some("(:,;)") },
    State { num: 7, next: 8, ttype: TT_PUNCT, action: FSM_SOB, r#match: "(", punct: None },
    State { num: 8, next: 0, ttype: TT_PUNCT, action: FSM_EOB, r#match: ")", punct: None },
    State { num: 8, next: 13, ttype: TT_LITERAL, action: FSM_KEY, r#match: "metadata", punct: None },
    State { num: 8, next: 16, ttype: TT_LITERAL, action: FSM_KEY, r#match: "reference", punct: Some(":;") },
    State { num: 8, next: 9, ttype: TT_LITERAL, action: FSM_KEY, r#match: "", punct: None },
    State { num: 9, next: 8, ttype: TT_PUNCT, action: FSM_END, r#match: ";", punct: None },
    State { num: 9, next: 10, ttype: TT_PUNCT, action: FSM_NOP, r#match: ":", punct: None },
    // we can't allow this because the syntax is squiffy
    // would prefer to require a ; after the last option
    // (and delete all the other cases like this too)
    // {  9,  0, TT_PUNCT,   FSM_EOB, ")",        ""      },
    State { num: 10, next: 12, ttype: TT_STRING, action: FSM_OPT, r#match: "", punct: None },
    State { num: 10, next: 11, ttype: TT_LITERAL, action: FSM_OPT, r#match: "", punct: None },
    State { num: 11, next: 12, ttype: TT_STRING, action: FSM_VAL, r#match: "", punct: None },
    State { num: 11, next: 12, ttype: TT_LITERAL, action: FSM_VAL, r#match: "", punct: None },
    State { num: 11, next: 8, ttype: TT_PUNCT, action: FSM_END, r#match: ";", punct: None },
    State { num: 11, next: 0, ttype: TT_PUNCT, action: FSM_EOB, r#match: ")", punct: Some("") },
    State { num: 11, next: 10, ttype: TT_PUNCT, action: FSM_SET, r#match: ",", punct: None },
    State { num: 12, next: 8, ttype: TT_PUNCT, action: FSM_END, r#match: ";", punct: None },
    State { num: 12, next: 0, ttype: TT_PUNCT, action: FSM_EOB, r#match: ")", punct: Some("") },
    State { num: 12, next: 10, ttype: TT_PUNCT, action: FSM_SET, r#match: ",", punct: None },
    State { num: 13, next: 14, ttype: TT_PUNCT, action: FSM_NOP, r#match: ":", punct: None },
    State { num: 14, next: 8, ttype: TT_PUNCT, action: FSM_END, r#match: ";", punct: Some("(:,;)") },
    State { num: 14, next: 14, ttype: TT_NONE, action: FSM_SET, r#match: ",", punct: None },
    State { num: 14, next: 14, ttype: TT_NONE, action: FSM_ADD, r#match: "", punct: None },
    State { num: 15, next: 0, ttype: TT_LITERAL, action: FSM_INC, r#match: "", punct: None },
    State { num: 16, next: 14, ttype: TT_PUNCT, action: FSM_NOP, r#match: ":", punct: Some(";") },
];

fn unescape(c: u8) -> u8 {
    // C switch in source order; default returns c.
    match c {
        b'a' => 0x07,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'n' => 0x0a,
        b'r' => 0x0d,
        b't' => 0x09,
        b'v' => 0x0b,
        _ => c,
    }
}

fn to_hex(c: u8) -> u8 {
    // C: isdigit ? c-'0' : isupper ? 10+c-'A' : 10+c-'a'. Callers gate on
    // isxdigit; the non-hex else-branch is unreachable but literal.
    if c.is_ascii_digit() {
        c - b'0'
    } else if c.is_ascii_uppercase() {
        10 + c - b'A'
    } else {
        10 + c - b'a'
    }
}

/// The parse_stream.cc file-static counters. C's printf lines that read
/// them are commented out upstream; carried so a future transcript can
/// pin them (and get_token formats warning line numbers from them).
#[derive(Debug, Clone, Copy)]
pub struct StreamStats {
    pub chars: u32,
    pub tokens: u32,
    pub lines: u32,
    pub comments: u32,
    pub keys: u32,
    pub rules: u32,
    pub lists: u32,
    pub strings: u32,
}

impl Default for StreamStats {
    fn default() -> Self {
        // static unsigned chars = 0, tokens = 0;
        // static unsigned lines = 1, comments = 0;
        // static unsigned keys = 0, rules = 0;
        // static unsigned lists = 0, strings = 0;
        StreamStats {
            chars: 0,
            tokens: 0,
            lines: 1,
            comments: 0,
            keys: 0,
            rules: 0,
            lists: 0,
            strings: 0,
        }
    }
}

/// get_token's two function-statics + the counters. C keeps them for the
/// whole process; the driver owns ONE StreamCtx spanning every parse_stream
/// call (the probe's sequential parse_rules_string runs share prev/pos).
#[derive(Debug)]
pub struct StreamCtx {
    prev: i32, // static int prev = EOF (EOF pins -1)
    pos: i32,  // static int pos = 0
    pub stats: StreamStats,
}

impl Default for StreamCtx {
    fn default() -> Self {
        StreamCtx { prev: -1, pos: 0, stats: StreamStats::default() }
    }
}

/// ByteCursor stands for std::istream& (is.get() -> int, EOF at end).
struct ByteCursor<'a> {
    data: &'a [u8],
    i: usize,
}

impl<'a> ByteCursor<'a> {
    fn get(&mut self) -> i32 {
        if self.i < self.data.len() {
            let c = self.data[self.i];
            self.i += 1;
            c as i32
        } else {
            -1 // EOF
        }
    }
}

const SRC: bool = true;
const DST: bool = false;

/// static TokenType get_token(istream& is, string& s, const char* punct,
/// int esc). Returns the TokenType; `s` receives the token.
#[allow(clippy::too_many_arguments)]
fn get_token(
    sc: &mut RuleCoreState,
    pc: &mut ParseConf,
    is: &mut ByteCursor,
    s: &mut String,
    punct: Option<&str>,
    esc: i32,
    ctx: &mut StreamCtx,
) -> u8 {
    let mut list: i32 = 0;
    let mut state: i32 = 0;
    s.clear();
    let mut inc = true;
    let mut hex: u8 = 0;

    let mut c: i32;
    if ctx.prev != -1 {
        c = ctx.prev;
        ctx.prev = -1;
        inc = c != 0x0a; // inc = ( c != '\n' )
    } else {
        c = is.get();
        ctx.stats.chars += 1;
    }

    let has_punct = |c: i32| -> bool {
        match punct {
            Some(t) => t.bytes().any(|b| b as i32 == c),
            None => false, // C never calls strchr(nullptr, ..): the parse
                           // loop below only assigns punct from non-null
                           // tables; Some("") has no members anyway.
        }
    };

    while c != -1 {
        if c == 0x0a {
            ctx.stats.lines += 1;
            ctx.pos = 0;
            if inc {
                pc.inc_parse_position(&mut sc.log); // parse_conf.cc static
            } else {
                inc = true;
            }
        } else {
            ctx.pos += 1;
        }
        let pos = ctx.pos;

        match state {
            0 => {
                // idle
                if has_punct(c) {
                    s.push(c as u8 as char);
                    return TT_PUNCT;
                } else if c == b'#' as i32 {
                    s.push('#');
                    ctx.stats.comments += 1;
                    state = 1;
                } else if c == b'/' as i32 {
                    s.push('/');
                    state = 10;
                } else if c == b'[' as i32 {
                    s.push('[');
                    ctx.stats.lists += 1;
                    list = 1;
                    state = 2;
                } else if c == b'"' as i32 {
                    s.push('"');
                    ctx.stats.strings += 1;
                    state = 3;
                } else if c == b'!' as i32 {
                    s.push('!');
                    state = 7;
                } else if c == b'\\' as i32 {
                    state = 5;
                } else if !(c as u8).is_ascii_whitespace() {
                    s.push(c as u8 as char);
                    ctx.stats.keys += 1;
                    state = 6;
                }
            }
            1 => {
                // comment
                if c == 0x0a {
                    s.clear();
                    state = 0;
                } else if s.len() < 6 {
                    s.push(c as u8 as char);
                    // C: pos == 6 && !strcasecmp(s, "#begin"). C's
                    // strcasecmp NUL-terminates so only the exact 6-char
                    // "#begin" matches at len 6 -- exactly this compare.
                    if pos == 6 && s.eq_ignore_ascii_case("#begin") {
                        state = 8;
                    }
                }
            }
            2 => {
                // list
                s.push(c as u8 as char);
                if c == b'[' as i32 {
                    list += 1;
                }
                if c == b']' as i32 {
                    list -= 1;
                }
                if list == 0 {
                    return TT_LIST;
                }
            }
            3 => {
                // string
                if esc != 0 && c == b'"' as i32 {
                    s.push('"');
                    return TT_STRING;
                }
                if esc == 0 && c == b';' as i32 {
                    ctx.prev = c;
                    return TT_STRING;
                } else if c == b'\\' as i32 {
                    state = if esc > 0 { 4 } else { 16 };
                } else if c == 0x0a {
                    sc.log.parse_warning(
                        WARN_RULES,
                        "line break in string on line %u\n",
                        &[Arg::U((ctx.stats.lines - 1) as u64)],
                    );
                } else {
                    s.push(c as u8 as char);
                }
            }
            4 => {
                // quoted escape
                if c == b'x' as i32 {
                    state = 14;
                } else {
                    s.push(unescape(c as u8) as char);
                    state = 3;
                }
            }
            5 => {
                // unquoted escape
                if c != 0x0a && c != 0x0d {
                    sc.log.parse_warning(
                        WARN_RULES,
                        "invalid escape on line %u\n",
                        &[Arg::U(ctx.stats.lines as u64)],
                    );
                }
                state = 0;
            }
            6 => {
                // token
                if esc != 0 && c == b'\\' as i32 {
                    state = 9;
                } else if (c as u8).is_ascii_whitespace() || has_punct(c) {
                    ctx.prev = c;
                    return TT_LITERAL;
                } else {
                    s.push(c as u8 as char);
                }
            }
            7 => {
                // not string
                if c == b'"' as i32 {
                    s.push('"');
                    ctx.stats.strings += 1;
                    state = 3;
                } else if (c as u8).is_ascii_whitespace() || has_punct(c) {
                    ctx.prev = c;
                    return TT_LITERAL;
                } else {
                    s.push(c as u8 as char);
                    state = 6;
                }
            }
            8 => {
                // #begin block
                if c == 0x0a {
                    s.clear();
                } else if s.len() < 4 {
                    s.push(c as u8 as char);
                    // C re-runs strcasecmp(s, "#end") at EVERY append;
                    // NUL-terminated compare means only the exact 4-char
                    // "#end" matches -- identical to this compare.
                    if s.eq_ignore_ascii_case("#end") {
                        state = 1;
                    }
                }
            }
            9 => {
                // token escape
                s.push(c as u8 as char);
                state = 6;
            }
            10 => {
                // start of comment?
                if c == b'*' as i32 {
                    s.clear();
                    state = 11;
                } else {
                    ctx.stats.keys += 1;
                    // now as if state == 6
                    if esc != 0 && c == b'\\' as i32 {
                        state = 9;
                    } else if (c as u8).is_ascii_whitespace() || has_punct(c) {
                        ctx.prev = c;
                        return TT_LITERAL;
                    } else {
                        s.push(c as u8 as char);
                        state = 6;
                    }
                }
            }
            11 => {
                // /* comment */
                if c == b'*' as i32 {
                    state = 12;
                } else if c == b'"' as i32 {
                    state = 13;
                }
            }
            12 => {
                // end of comment?
                if c == b'/' as i32 {
                    ctx.stats.comments += 1;
                    state = 0;
                }
            }
            13 => {
                // quoted string in comment
                if c == b'"' as i32 {
                    state = 11;
                } else if c == 0x0a {
                    sc.log.parse_warning(
                        WARN_RULES,
                        "line break in commented string on line %u\n",
                        &[Arg::U((ctx.stats.lines - 1) as u64)],
                    );
                    state = 11;
                }
            }
            14 => {
                // escaped hex in string - first digit
                if (c as u8).is_ascii_hexdigit() {
                    hex = to_hex(c as u8);
                    state = 15;
                } else {
                    sc.log.parse_warning(
                        WARN_RULES,
                        "\\x used with no following hex digits on line %u\n",
                        &[Arg::U((ctx.stats.lines - 1) as u64)],
                    );
                    s.push(c as u8 as char);
                    state = 3;
                }
            }
            15 => {
                // escaped hex in string - second digit
                if (c as u8).is_ascii_hexdigit() {
                    hex <<= 4;
                    hex |= to_hex(c as u8);
                    s.push(hex as char);
                    state = 3;
                } else {
                    s.push(hex as char);
                    s.push(c as u8 as char);
                    state = 3;
                }
            }
            16 => {
                // string we don't unescape
                s.push('\\');
                s.push(c as u8 as char);
                state = 3;
            }
            _ => {}
        }
        c = is.get();
        ctx.stats.chars += 1;
    }
    TT_NONE
}

/// static const State* get_state(int num, TokenType type, const string& tok)
fn get_state(sc: &mut RuleCoreState, num: i32, ttype: u8, tok: &str) -> &'static State {
    // C `sizeof(fsm)/sizeof(fsm[0])` linear scan; first match wins.
    for s in FSM {
        if num == s.num
            && (s.ttype == 0 || ttype == s.ttype) // !s->type || type == s->type
            && (s.r#match.is_empty() || tok == s.r#match)
        {
            return s;
        }
    }
    sc.parse_error("syntax error", &[]);
    &FSM[0]
}

/// static int get_escape(const string& s)
/// FIXIT-L escaping should not be by option name (verbatim).
fn get_escape(s: &str) -> i32 {
    if s == "pcre" {
        0 // no escape, option goes to ;
    } else if s == "regex" || s == "sd_pattern" {
        -1 // no escape, option goes to "
    } else {
        1 // escape, option goes to "
    }
}

/// struct RuleParseState { RuleTreeNode rtn; OptTreeNode* otn; string key,
/// opt, val; bool tbd; }
struct RuleParseState {
    rtn: RuleTreeNode,
    otn: Option<OtnHandle>,
    key: String,
    opt: String,
    val: String,
    tbd: bool,
}

/// static bool exec(FsmAction act, string& tok, RuleParseState& rps, sc).
/// True == STOP the loop (the "END" word). ParseAbort propagates as
/// Err(Fatal::Quitting) through the ? on parse_rule_ports.
// C's exec takes (act, tok, rps, sc); the port threads the parse_conf
// pair + StreamCtx needed by the include chain -- argument plumbing only.
#[allow(clippy::too_many_arguments)]
fn exec(
    sc: &mut RuleCoreState,
    pc: &mut ParseConf,
    conf: &SnortConfig,
    conf_files: &ConfFiles,
    ctx: &mut StreamCtx,
    act: u8,
    tok: &str,
    rps: &mut RuleParseState,
) -> Result<bool, Fatal> {
    match act {
        FSM_ACT => {
            // FIXIT-L if non-rule tok != "END", parsing goes bad
            // (need ctl-D to terminate)
            if tok == "END" {
                return Ok(true);
            }
            parse_rule_type(sc, Some(tok), &mut rps.rtn);
        }
        FSM_PRO => parse_rule_proto(sc, tok, &mut rps.rtn, false),
        FSM_HDR => {
            parse_rule_nets(sc, "any", SRC, &mut rps.rtn, true);
            parse_rule_ports(sc, "any", SRC, &mut rps.rtn, true)?;
            parse_rule_dir(sc, "->", &mut rps.rtn, true);
            parse_rule_nets(sc, "any", DST, &mut rps.rtn, true);
            parse_rule_ports(sc, "any", DST, &mut rps.rtn, true)?;
            rps.otn = parse_rule_open(sc, &mut rps.rtn, false);
        }
        FSM_SIP => parse_rule_nets(sc, tok, SRC, &mut rps.rtn, false),
        FSM_SP => parse_rule_ports(sc, tok, SRC, &mut rps.rtn, false)?,
        FSM_SPX => {
            // fall thru ...
            parse_rule_ports(sc, "any", SRC, &mut rps.rtn, true)?;
            parse_rule_dir(sc, tok, &mut rps.rtn, false);
        }
        FSM_DIR => parse_rule_dir(sc, tok, &mut rps.rtn, false),
        FSM_DIP => parse_rule_nets(sc, tok, DST, &mut rps.rtn, false),
        FSM_DP => parse_rule_ports(sc, tok, DST, &mut rps.rtn, false)?,
        FSM_DPX => {
            // fall thru ...
            parse_rule_ports(sc, "any", DST, &mut rps.rtn, true)?;
            rps.otn = parse_rule_open(sc, &mut rps.rtn, false);
        }
        FSM_SOB => rps.otn = parse_rule_open(sc, &mut rps.rtn, false),
        FSM_STB => rps.otn = parse_rule_open(sc, &mut rps.rtn, true),
        FSM_EOB => {
            if rps.tbd {
                // C recursive call: exec(FSM_END, tok, rps, sc)
                exec(sc, pc, conf, conf_files, ctx, FSM_END, tok, rps)?;
            }
            parse_rule_close(sc, &mut rps.rtn, &rps.otn)?;
            rps.otn = None;
            // rules++ (parse_stream.cc file static; C never prints it in
            // this scope -- parked for future pinning)
            sc.stats_rules += 1;
        }
        FSM_KEY => {
            if tok != "include" {
                parse_rule_opt_begin(sc, tok);
            }
            rps.key = tok.to_string();
            rps.opt.clear();
            rps.val.clear();
            rps.tbd = true;
        }
        FSM_OPT => {
            rps.opt = tok.to_string();
            rps.val.clear();
            rps.tbd = true;
        }
        FSM_VAL => {
            rps.val = tok.to_string();
            rps.tbd = true;
        }
        FSM_SET => {
            parse_rule_opt_set(sc, &rps.key, &rps.opt, &rps.val);
            rps.opt.clear();
            rps.val.clear();
            rps.tbd = false;
        }
        FSM_END => {
            if !rps.opt.is_empty() {
                parse_rule_opt_set(sc, &rps.key, &rps.opt, &rps.val);
            }
            if let Some(o) = rps.otn.as_ref() {
                parse_rule_opt_end(sc, &rps.key, &mut o.borrow_mut());
            }
            rps.opt.clear();
            rps.val.clear();
            rps.tbd = false;
        }
        FSM_ADD => {
            // adding another state would eliminate this if
            if rps.opt.is_empty() {
                rps.opt.push_str(tok);
            } else {
                if !rps.val.is_empty() {
                    rps.val.push(' ');
                }
                rps.val.push_str(tok);
            }
            rps.tbd = true;
        }
        FSM_INC => parse_include(sc, pc, conf, conf_files, ctx, tok)?,
        FSM_NOP => {}
        // C: case FSM_ERR: break; (the -1 sentinel row never executes
        // through the table walk). _ mirrors C's no-default switch:
        // FSM_MAX and the FSM_INC case (handled by the caller on
        // s->action before exec) fall here silently.
        FSM_ERR => {}
        _ => {}
    }
    Ok(false)
}

/// The include channel (C exec FSM_INC -> parse_conf.cc parse_include +
/// parse_rules_file -> parse_stream recursion). Fused into this module so
/// the re-entry can hand parse_stream the live sc/pc pair (C reaches them
/// through globals; the Rust port threads them). Pinning surface: S3 --
/// get_config_file miss -> ParseError "can't open %s\n" and NO loc push
/// (depth stays 0; inc_parse_position then no-ops forever).
fn parse_include(
    sc: &mut RuleCoreState,
    pc: &mut ParseConf,
    conf: &SnortConfig,
    conf_files: &ConfFiles,
    ctx: &mut StreamCtx,
    arg: &str,
) -> Result<(), Fatal> {
    // std::string conf = ExpandVars(arg); (C abort terminates the process)
    let conf_str = {
        let slot = sc.ips_policy_slot;
        let pol = &mut sc.policies[slot];
        let mut vctx = VarContext::new(&mut pol.ip_vartable, &mut pol.port_var_table);
        crate::parser::vars::expand_vars(&mut vctx, arg)
    };
    let conf_str = match conf_str {
        Ok(v) => v,
        Err(pa) => {
            sc.log.parse_abort("%s", &[Arg::S(Some(pa.0.clone().into()))]);
            return Err(Fatal::Quitting);
        }
    };

    // seed selection (parse_include 208-215): depth -> get_parse_file();
    // else s_ips_policy -> policy includer; else
    // parser_get_special_includer() (RuleCoreState.s_special_includer in
    // the port). Cloned out before the &mut borrows below.
    let seed: String = if pc.depth() != 0 {
        pc.get_parse_file(conf_files).to_string()
    } else if pc.ips_policy_flag() {
        let slot = sc.ips_policy_slot;
        sc.policies[slot].includer.clone()
    } else {
        sc.s_special_includer.clone()
    };
    let mut file_buf: Vec<u8> = seed.into_bytes();

    let code = match pc.get_config_file(&conf_str, &mut file_buf, conf, conf_files) {
        None => {
            sc.log
                .parse_error("can't open %s\n", &[Arg::S(Some(conf_str.clone().into()))]);
            return Ok(()); // C returns; location NOT pushed
        }
        Some(c) => c,
    };
    let file = String::from_utf8_lossy(&file_buf).into_owned();
    pc.push_parse_location(
        Some(code),
        Some(file.as_str()),
        Some(&conf_str),
        1,
        conf,
        &mut sc.log,
    );

    // parse_rules_file(sc, file.c_str()): ifstream binary + depth bump +
    // stream re-entry. stat() passed in get_config_file, so a failed read
    // is the race path; ENOENT pins the glibc strerror text the
    // text_log/streams milestones carry.
    match std::fs::read(file.as_str()) {
        Err(e) => {
            let msg = if e.kind() == std::io::ErrorKind::NotFound {
                "No such file or directory".to_string()
            } else {
                e.to_string()
            };
            sc.log.parse_error(
                "unable to open rules file '%s': %s",
                &[Arg::S(Some(file.clone().into())), Arg::S(Some(msg.into()))],
            );
        }
        Ok(data) => {
            pc.bump_rules_file_depth(1);
            pc.stream_reads += 1; // parse_rules_file reaches parse_stream
            parse_stream(sc, pc, conf, conf_files, &data, ctx)?;
            pc.bump_rules_file_depth(-1);
        }
    }

    pc.pop_parse_location(conf, &mut sc.log);
    Ok(())
}

/// void parse_stream(istream& is, SnortConfig* sc). `data` stands for the
/// istream content (stringstream string or ifstream); conf/conf_files are
/// the parse_conf surface the include chain needs (C globals; the driver
/// owns them and hands references here -- their mutation lives in the
/// parse_conf layer, never in the stream itself).
pub fn parse_stream(
    sc: &mut RuleCoreState,
    pc: &mut ParseConf,
    conf: &SnortConfig,
    conf_files: &ConfFiles,
    data: &[u8],
    ctx: &mut StreamCtx,
) -> Result<(), Fatal> {
    let mut cur = ByteCursor { data, i: 0 };
    let mut rps = RuleParseState {
        rtn: RuleTreeNode::new(),
        otn: None,
        key: String::new(),
        opt: String::new(),
        val: String::new(),
        tbd: false,
    };

    let mut tok = String::new();
    let mut esc: i32 = 1;
    let mut num: i32 = 0;
    let mut punct: Option<&str> = FSM[0].punct; // C: punct = fsm[0].punct

    loop {
        let t = get_token(sc, pc, &mut cur, &mut tok, punct, esc, ctx);
        if t == TT_NONE {
            break;
        }
        ctx.stats.tokens += 1;
        let s: &'static State = get_state(sc, num, t, &tok);
        if exec(sc, pc, conf, conf_files, ctx, s.action, &tok, &mut rps)? {
            break;
        }
        num = s.next;
        esc = get_escape(&rps.key);
        if s.punct.is_some() {
            // C `if ( s->punct ) punct = s->punct;` -- "" is non-null and
            // DOES update (clearing the table).
            punct = s.punct;
        }
    }

    if num != 0 {
        sc.parse_error("incomplete rule", &[]);
    }
    Ok(())
}
