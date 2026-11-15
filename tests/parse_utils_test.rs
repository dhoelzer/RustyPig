//! Port of embedded Catch2 "parse_int" sections in parser/parse_utils.cc
//! (6 SECTIONs) plus replay of tools/parse_utils_harness/vectors.txt — the
//! original parse_byte_code has no upstream tests, so state-machine edges
//! (dangling hex run, interior quotes, `|` toggling, bad xdigit position)
//! are pinned against the compiled C source.

use snort3::parser::parse_utils::{ERANGE, parse_byte_code, parse_int};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// TEST_CASE("parse_int", "[ParseUtils]")
// ---------------------------------------------------------------------------

#[test]
fn parse_int_invalid_format() {
    let r = parse_int(b"10  ", "test", -65535, 65535);
    assert_eq!(r.value, 10); // quirk: value returned despite format error
    assert_eq!(r.errors, vec!["invalid 'test' format."]);
}

#[test]
fn parse_int_not_a_number() {
    let r = parse_int(b"test", "test", -65535, 65535);
    assert_eq!(r.value, 0);
}

#[test]
fn parse_int_overflow() {
    let d = b"99999999999999999999999999999999999999999999999999";
    let r = parse_int(d, "test", -65535, 65535);
    assert_eq!(r.value, 65535);
    assert_eq!(r.errno, ERANGE);
}

#[test]
fn parse_int_underflow() {
    let d = b"-9999999999999999999999999999999999999999999999999";
    let r = parse_int(d, "test", -65535, 65535);
    assert_eq!(r.value, -65535);
    assert_eq!(r.errno, ERANGE);
}

#[test]
fn parse_int_below_limit() {
    let r = parse_int(b"1", "test", 2, 3);
    assert_eq!(r.value, 2);
}

#[test]
fn parse_int_above_limit() {
    let r = parse_int(b"4", "test", 2, 3);
    assert_eq!(r.value, 3);
}

// ---------------------------------------------------------------------------
// Vector replay (BCIN/BCOUT parse_byte_code, PIIN/PIOUT parse_int): error
// text lines appear between the IN and OUT lines, matching the C probe's
// interleaved stdout.
// ---------------------------------------------------------------------------

fn vectors() -> Vec<String> {
    include_str!("../tools/parse_utils_harness/vectors.txt")
        .lines()
        .map(|l| l.to_string())
        .collect()
}

#[test]
fn vector_replay() {
    let vs = vectors();
    let mut i = 0;
    let mut bc_cases = 0;
    let mut pi_cases = 0;

    let errors_before = |i: &mut usize| -> Vec<String> {
        let mut e = Vec::new();
        while *i < vs.len() && vs[*i].starts_with("ERR ") {
            e.push(vs[*i][4..].to_string());
            *i += 1;
        }
        e
    };

    while i < vs.len() {
        let line = &vs[i];
        if let Some(rest) = line.strip_prefix("BCIN ") {
            let input = hex(rest);
            i += 1;
            let errs = errors_before(&mut i);
            assert!(vs[i].starts_with("BCOUT "), "{}", vs[i]);
            let parts: Vec<&str> = vs[i][6..].splitn(3, ' ').collect();
            let ok = parts[0] == "1";
            let neg = parts[1] == "1";
            let out = hex(parts[2].trim());
            i += 1;
            bc_cases += 1;

            let r = parse_byte_code(&input);
            assert_eq!(r.ok, ok, "{line}");
            assert_eq!(r.negate, neg, "{line}");
            assert_eq!(r.out, out, "{line}");
            assert_eq!(r.errors, errs, "{line}");
        } else if let Some(rest) = line.strip_prefix("PIIN ") {
            // PIIN <hex input> <low> <high>
            let mut it = rest.split(' ');
            let input = hex(it.next().unwrap());
            let low: i32 = it.next().unwrap().parse().unwrap();
            let high: i32 = it.next().unwrap().parse().unwrap();
            i += 1;
            let errs = errors_before(&mut i);
            assert!(vs[i].starts_with("PIOUT "), "{}", vs[i]);
            let body = &vs[i][6..]; // "<value> errno=N"
            let (vstr, estr) = body.rsplit_once(" errno=").unwrap();
            let value: i32 = vstr.parse().unwrap();
            let errno: i32 = estr.parse().unwrap();
            i += 1;
            pi_cases += 1;

            let r = parse_int(&input, "test", low, high);
            assert_eq!(r.value, value, "{line}");
            assert_eq!(r.errno, errno, "{line}");
            assert_eq!(r.errors, errs, "{line}");
        } else {
            panic!("unknown vector line: {line}");
        }
    }
    assert!(bc_cases == 18 && pi_cases == 11, "{bc_cases}/{pi_cases}");
}
