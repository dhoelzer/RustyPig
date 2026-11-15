//! Port map of snort3 parser/parse_so_rule.cc — the so_rule stub FSM for
//! --dump-dynamic-rules. Zero runtime deps upstream; this file is a
//! literal transcription of the 9-state FSM including its quirks:
//!
//! - `prev` tracks the last space only for the STUB accumulation, but C's
//!   guard is a *string content* comparison (*accum == stub) — so when the
//!   option accumulator's content happens to equal the stub's, prev is
//!   updated from the option side too. Reproduced at Target::Opt.
//! - state 2's else-arm appends '/' and continues WITHOUT ++in (the
//!   current char is re-processed in state `next`): "/ *alert()*/" keeps
//!   "/ *alert()" (vector-pinned).
//! - the newline collapse (state<7 && c=='\n' -> ' ') happens after the
//!   switch, before the append gate.
//! - the non-stub ';' branch appends opt + ';' straight to opts,
//!   consumes c itself (opts += *in++; continue) — but accum/state were
//!   ALREADY reset to stub/5 before the if/else.
//! - trim() leading check reads stub[0]; on an empty std::string that is
//!   the defined '\0', not a space (guarded here).
//!
//! Ground truth: tools/sorule_harness — the ORIGINAL parse_so_rule.cc
//! compiled twice: once through the upstream Catch2 tables (syntax/basic/
//! stub_tests, all three TEST_CASEs) as a gate, and once merged with a
//! probe that replays every table input plus extras through both channels
//! (stub AND opts). tests/sorule_parity_test.rs replays vectors.txt.

const STUB_OPTS: [&str; 12] = [
    "classtype", "flowbits", "gid", "metadata", "msg", "priority", "reference", "rem", "rev",
    "service", "sid", "soid",
];

/// parse_so_rule.cc:53 is_stub_option — name = opt up to the first of " :;".
fn is_stub_option(opt: &str) -> bool {
    let name = match opt.find([' ', ':', ';']) {
        Some(n) => &opt[..n],
        None => opt,
    };
    STUB_OPTS.contains(&name)
}

/// C std::isspace in the "C" locale over a (non-negative) char value.
#[inline]
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// parse_so_rule.cc:219 trim. C reads stub[0] unguarded; for an empty
/// std::string operator[](0) yields '\0' which is not a space, so the
/// loop just doesn't run — guarded equivalently here.
fn trim(stub: &mut String) {
    while stub.as_bytes().first().is_some_and(|b| is_space(*b)) {
        stub.remove(0);
    }

    if let Some(mut n) = stub.rfind(';') {
        n += 1;
        if n < stub.len() && is_space(stub.as_bytes()[n]) {
            n += 1;
            while n < stub.len() && is_space(stub.as_bytes()[n]) {
                stub.remove(n);
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum Target {
    Stub,
    Opt,
}

/// parse_so_rule.cc:70 parse_so_rule (SoRuleParser::parse_so_rule).
/// in, stub, opts map to &str / &mut String; returns whether the rule
/// body close ')' was reached.
pub fn parse_so_rule(r#in: &str, stub: &mut String, opts: &mut String) -> bool {
    let bytes = r#in.as_bytes();
    let mut i = 0usize;

    let mut state: u32 = 0;
    let mut next: u32 = 0;

    let mut prev: u8 = 0;
    let mut drop = false;

    let mut opt = String::new();
    let mut accum = Target::Stub;

    'scan: while i < bytes.len() {
        let mut c = bytes[i];

        match state {
            0 => {
                // in rule header
                if c == b'#' {
                    state = 1;
                    next = 0;
                    drop = true;
                } else if c == b'(' {
                    state = 5;
                } else if c == b'/' {
                    state = 2;
                    next = 0;
                    drop = true;
                }
            }
            1 => {
                // in bash-style comment
                if c == b'\n' {
                    state = next;
                    drop = false;
                    c = b' ';
                }
            }
            2 => {
                // in C-style comment begin
                if c == b'*' {
                    state = 3;
                } else {
                    // C appends the literal '/' that opened state 2 (the
                    // real one was dropped), then repeats the current
                    // char in state `next` WITHOUT ++in.
                    match accum {
                        Target::Stub => stub.push('/'),
                        Target::Opt => opt.push('/'),
                    }
                    state = next;
                    drop = false;
                    // repeat the same char in the new state (no ++in)
                    continue 'scan;
                }
            }
            3 => {
                // in C-style comment
                if c == b'*' {
                    state = 4;
                }
            }
            4 => {
                // in C-style comment end
                if c == b'/' {
                    state = next;
                    drop = false;
                    c = b' ';
                } else {
                    state = 3;
                }
            }
            5 => {
                // in rule ( body )
                if c == b'#' {
                    state = 1;
                    next = 5;
                    drop = true;
                } else if c == b'/' {
                    state = 2;
                    next = 5;
                    drop = true;
                } else if c == b')' {
                    // accum is Stub whenever state 5 is entered
                    stub.push(c as char);
                    trim(stub);
                    return true;
                } else if !is_space(c) {
                    opt.clear();
                    accum = Target::Opt;
                    state = 6;
                }
            }
            6 => {
                // in rule option
                if c == b'/' {
                    state = 2;
                    next = 6;
                    drop = true;
                } else if c == b'"' {
                    state = 7;
                } else if c == b';' {
                    accum = Target::Stub;
                    state = 5;

                    if is_stub_option(&opt) {
                        stub.push_str(&opt);
                        // falls through: the ';' is appended normally
                    } else {
                        opts.push_str(&opt);
                        opts.push(c as char);
                        i += 1; // opts += *in++; continue;
                        continue 'scan;
                    }
                }
            }
            7 => {
                // in "string"
                if c == b'\\' {
                    state = 8;
                } else if c == b'"' {
                    state = 6;
                }
            }
            8 => {
                // in escape
                state = 7;
            }
            _ => {}
        }

        if state < 7 && c == b'\n' {
            c = b' ';
        }

        // collapse runs of spaces in the stub (option accumulation keeps
        // everything verbatim); prev was the last byte appended to stub.
        if (!drop && (!is_space(c) || !is_space(prev))) || state >= 6 {
            match accum {
                Target::Stub => stub.push(c as char),
                Target::Opt => opt.push(c as char),
            }
            // C: if (*accum == stub) prev = c; — pointer-accum to the same
            // object is trivially equal; the Opt side compares CONTENTS.
            let equal = accum == Target::Stub || opt == *stub;
            if equal {
                prev = c;
            }
        }

        i += 1;
    }

    false
}

/// parse_so_rule.cc:238 get_so_stub (the only exported entry).
pub fn get_so_stub(r#in: &str, stub: &mut String) -> bool {
    let mut opts = String::new();
    parse_so_rule(r#in, stub, &mut opts)
}
