//! Port of the embedded Catch2 unit tests in framework/range.cc ("dflt op",
//! "=", "!", "!=", "<", "<=", ">", ">=", "<>", "<=>", "parsing",
//! "validate") plus replay of tools/range_harness/vectors.txt (probe over the
//! original range.cc) which pins hash() values that upstream tests omit.

use snort3::framework::range::{RangeCheck, RcOp};

fn rc(s: &str) -> Option<RangeCheck> {
    let mut r = RangeCheck::default();
    if r.parse(s.as_bytes()) {
        Some(r)
    } else {
        None
    }
}

/// TEST_CASE("dflt op"): bare "5" -> EQ with min=0/max=5 (the hi-swap quirk).
#[test]
fn dflt_op() {
    let r = rc("5").unwrap();
    assert_eq!(r.op, RcOp::Eq);
    assert_eq!(r.max, 5);
    assert!(r.eval(5));
    assert!(!r.eval(4));
    assert!(!r.eval(6));
}

#[test]
fn eq_sign() {
    let r = rc("=+0x5").unwrap();
    assert_eq!(r.op, RcOp::Eq);
    assert_eq!(r.max, 5);
    assert!(r.eval(5));
    assert!(!r.eval(4));
    assert!(!r.eval(6));
}

#[test]
fn not_neg() {
    let r = rc("!-5").unwrap();
    assert_eq!(r.op, RcOp::Not);
    assert_eq!(r.max, -5);
    assert!(r.eval(-4));
    assert!(r.eval(-6));
    assert!(!r.eval(-5));
}

#[test]
fn not_equal() {
    let r = rc("!=5").unwrap();
    assert_eq!(r.op, RcOp::Not);
    assert_eq!(r.max, 5);
    assert!(r.eval(4));
    assert!(r.eval(6));
    assert!(!r.eval(5));
}

#[test]
fn lt() {
    let r = rc("<5").unwrap();
    assert_eq!(r.op, RcOp::Lt);
    assert_eq!(r.max, 5);
    assert!(r.eval(4));
    assert!(r.eval(-1));
    assert!(!r.eval(5));
    assert!(!r.eval(6));
}

#[test]
fn le() {
    let r = rc("<=5").unwrap();
    assert_eq!(r.op, RcOp::Le);
    assert_eq!(r.max, 5);
    assert!(r.eval(5));
    assert!(r.eval(-1));
    assert!(!r.eval(6));
    assert!(!r.eval(1000));
}

#[test]
fn gt() {
    let r = rc(">5").unwrap();
    assert_eq!(r.op, RcOp::Gt);
    assert_eq!(r.min, 5);
    assert!(r.eval(6));
    assert!(r.eval(10));
    assert!(!r.eval(5));
    assert!(!r.eval(-1));
}

#[test]
fn ge() {
    let r = rc(">=5").unwrap();
    assert_eq!(r.op, RcOp::Ge);
    assert_eq!(r.min, 5);
    assert!(r.eval(5));
    assert!(r.eval(10));
    assert!(!r.eval(4));
    assert!(!r.eval(-4));
}

#[test]
fn lg_strict() {
    let r = rc("0<>5").unwrap();
    assert_eq!(r.op, RcOp::Lg);
    assert_eq!(r.min, 0);
    assert_eq!(r.max, 5);
    assert!(r.eval(1));
    assert!(r.eval(4));
    assert!(!r.eval(-1));
    assert!(!r.eval(0));
    assert!(!r.eval(5));
    assert!(!r.eval(6));
}

#[test]
fn leg_inclusive() {
    let r = rc("0<=>5").unwrap();
    assert_eq!(r.op, RcOp::Leg);
    assert_eq!(r.max, 5);
    assert!(r.eval(0));
    assert!(r.eval(1));
    assert!(r.eval(4));
    assert!(r.eval(5));
    assert!(!r.eval(-1));
    assert!(!r.eval(6));
}

#[test]
fn parsing_valid() {
    let r = rc("5").unwrap();
    assert_eq!(r.op, RcOp::Eq);
    assert_eq!(r.max, 5);

    let r = rc(" 5 ").unwrap();
    assert_eq!(r.op, RcOp::Eq);
    assert_eq!(r.max, 5);

    let r = rc(" ! 5 ").unwrap();
    assert_eq!(r.op, RcOp::Not);
    assert_eq!(r.max, 5);

    let r = rc(" != 5 ").unwrap();
    assert_eq!(r.op, RcOp::Not);
    assert_eq!(r.max, 5);

    let r = rc(" < 5 ").unwrap();
    assert_eq!(r.op, RcOp::Lt);
    assert_eq!(r.max, 5);

    let r = rc(" > 5 ").unwrap();
    assert_eq!(r.op, RcOp::Gt);
    assert_eq!(r.min, 5);

    let r = rc(" <= 5 ").unwrap();
    assert_eq!(r.op, RcOp::Le);
    assert_eq!(r.max, 5);

    let r = rc(" >= 5 ").unwrap();
    assert_eq!(r.op, RcOp::Ge);
    assert_eq!(r.min, 5);

    let r = rc(" 10 <> 50 ").unwrap();
    assert_eq!(r.op, RcOp::Lg);
    assert_eq!(r.min, 10);
    assert_eq!(r.max, 50);

    let r = rc(" 0x10 <=> 0x50 ").unwrap();
    assert_eq!(r.op, RcOp::Leg);
    assert_eq!(r.min, 0x10);
    assert_eq!(r.max, 0x50);

    let r = rc(" -0123 <=> 0x123 ").unwrap();
    assert_eq!(r.op, RcOp::Leg);
    assert_eq!(r.min, -83); // octal 0123 = 83, negated
    assert_eq!(r.max, 291); // hex 0x123
}

#[test]
fn parsing_invalid() {
    // spacey operators
    for s in [
        " ! = 5 ",
        " < = 5 ",
        " > = 5 ",
        " 1 < > 5 ",
        " 1 < = > 5 ",
        " < > 5 ",
        " < = > 5 ",
    ] {
        assert!(rc(s).is_none(), "should fail: {s}");
    }
    // other invalids
    for s in [
        "5x",
        "5.0",
        "5-0",
        "*5",
        "=$5",
        "=5x",
        "<<0",
        "+9223372036854775808",
        "-9223372036854775809",
        "4<>2",
        "24<=>16",
    ] {
        assert!(rc(s).is_none(), "should fail: {s}");
    }
    // backwards
    for s in [
        " 5 = ", " 5 ! ", " 5 != ", " 5 < ", " 5 <= ", " 5 > ", " 5 >= ",
    ] {
        assert!(rc(s).is_none(), "should fail: {s}");
    }
    // missing bound
    for s in [" 1 <> ", " <> 5 ", " 1 <=> ", " <=> 5 "] {
        assert!(rc(s).is_none(), "should fail: {s}");
    }
}

#[test]
fn validate_cases() {
    let mut r = RangeCheck::default();
    assert!(r.validate(b"2<>4", Some(b"0:10")));
    assert_eq!(r.min, 2);
    assert_eq!(r.max, 4);

    // #
    assert!(r.validate(b"2<>4", Some(b"0")));
    // #:
    assert!(r.validate(b"2<>4", Some(b"1:")));
    // :#
    assert!(r.validate(b"2<>4", Some(b":8")));
    // in hex
    assert!(r.validate(b"2<>4", Some(b"0x1:0x0A")));

    // invalid low
    assert!(!r.validate(b"2<>4", Some(b"3:")));
    // invalid hi
    assert!(!r.validate(b"2<>4", Some(b"1:3")));
    // invalid low and hi
    assert!(!r.validate(b"200<>400", Some(b"3:10")));
}

// ---------------------------------------------------------------------------
// Replay tools/range_harness/vectors.txt: parse state + hash() values that
// the upstream Catch cases don't cover (hash equality of "5"/"=5"/"5 ",
// octal-ish "08" failure, LLONG_MIN boundary, -0, x15, 0x).
// ---------------------------------------------------------------------------
fn vectors() -> Vec<String> {
    let body = include_str!("../tools/range_harness/vectors.txt");
    body.lines().map(|l| l.to_string()).collect()
}

#[test]
fn vector_replay() {
    let mut rc_rows = 0;
    let mut va_rows = 0;
    for line in vectors() {
        if let Some(rest) = line.strip_prefix("RC ") {
            rc_rows += 1;
            let parts: Vec<&str> = rest.split('|').collect();
            let src = parts[1].as_bytes();
            if parts[2] == "fail" {
                assert!(rc(std::str::from_utf8(src).unwrap()).is_none(), "{line}");
                continue;
            }
            let mut r = RangeCheck::default();
            assert!(r.parse(src), "{line}");
            assert_eq!(op_code_of(r.op).to_string(), parts[2], "{line}");
            assert_eq!(r.min.to_string(), parts[3], "{line}");
            assert_eq!(r.max.to_string(), parts[4], "{line}");
            assert_eq!(r.hash().to_string(), parts[5], "{line}");
        } else if let Some(rest) = line.strip_prefix("VA ") {
            va_rows += 1;
            let parts: Vec<&str> = rest.split('|').collect();
            let rng = if parts[2] == "(null)" {
                None
            } else {
                Some(parts[2].as_bytes())
            };
            let mut r = RangeCheck::default();
            let ok = r.validate(parts[1].as_bytes(), rng);
            assert_eq!((if ok { 1 } else { 0 }).to_string(), parts[3], "{line}");
            assert_eq!(r.min.to_string(), parts[4], "{line}");
            assert_eq!(r.max.to_string(), parts[5], "{line}");
            assert_eq!(
                op_code_of(r.op).to_string(),
                parts[6],
                "{line}"
            );
        } else {
            panic!("unknown vector line: {line}");
        }
    }
    assert!(rc_rows >= 29 && va_rows >= 11, "{rc_rows}/{va_rows}");
}

fn op_code_of(op: snort3::framework::range::RcOp) -> u32 {
    snort3::framework::range::op_code(op)
}
