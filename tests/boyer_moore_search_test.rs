//! Port of helpers/test/boyer_moore_search_test.cc (CppUTest group
//! boyer_moore_test_group). NOCASE mirrors the C Tester: the pattern is
//! uppercased on the way in (::toupper over the pattern string).
use snort3::helpers::boyer_moore_search::*;

#[derive(Clone, Copy, PartialEq)]
enum TestType {
    Case,
    NoCase,
}

struct Tester<'a> {
    pat: Vec<u8>,
    buf: &'a [u8],
    r#type: TestType,
    index: i32,
}

impl<'a> Tester<'a> {
    fn new(pat: &str, buf: &'a str, typ: TestType, index: i32) -> Self {
        let mut p = pat.as_bytes().to_vec();
        if typ == TestType::NoCase {
            // C: transform(pat.begin(), pat.end(), pat.begin(), ::toupper)
            for b in p.iter_mut() {
                *b = if b.is_ascii_lowercase() {
                    *b - b'a' + b'A'
                } else {
                    *b
                };
            }
        }
        Tester {
            pat: p,
            buf: buf.as_bytes(),
            r#type: typ,
            index,
        }
    }

    fn run(&self) -> bool {
        let pos = match self.r#type {
            TestType::NoCase => BoyerMooreSearchNoCase::new(&self.pat).search(self.buf),
            TestType::Case => BoyerMooreSearchCase::new(&self.pat).search(self.buf),
        };
        pos == self.index
    }
}

#[test]
fn binary() {
    let pat: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let buf: Vec<u8> = vec![
        0x00, 0x01, 0x02, 0x03, 0x72, 0x01, 0x3F, 0x2B, 0x1F, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02,
        0x03,
    ];
    let pos = BoyerMooreSearchCase::new(&pat).search(&buf);
    assert_eq!(pos, 9);
}

#[test]
fn empty() {
    assert!(Tester::new("abc", "", TestType::Case, -1).run());
}

#[test]
fn start() {
    assert!(Tester::new("abc", "abc", TestType::Case, 0).run());
}

#[test]
fn start_nocase() {
    assert!(Tester::new("abc", "aBc", TestType::NoCase, 0).run());
}

#[test]
fn found1() {
    assert!(Tester::new("d", "abcdefg", TestType::Case, 3).run());
}

#[test]
fn found2() {
    assert!(Tester::new("nan", "banana", TestType::Case, 2).run());
}

#[test]
fn found3() {
    assert!(Tester::new("pan", "anpanman", TestType::Case, 2).run());
}

#[test]
fn found4() {
    assert!(Tester::new("bcd", "abcd", TestType::Case, 1).run());
}

#[test]
fn found5() {
    assert!(Tester::new("aa", "aaa", TestType::Case, 0).run());
}

#[test]
fn found6() {
    assert!(Tester::new(
        "that",
        "which finally halts at tHaT point",
        TestType::NoCase,
        23
    )
    .run());
}

#[test]
fn not_found1() {
    assert!(Tester::new("nnaaman", "anpanmanam", TestType::Case, -1).run());
}

#[test]
fn not_found2() {
    assert!(Tester::new("abcd", "abc", TestType::Case, -1).run());
}

#[test]
fn not_found3() {
    assert!(Tester::new("abcd", "bcd", TestType::Case, -1).run());
}

#[test]
fn not_found4() {
    assert!(Tester::new("baa", "aaaaa", TestType::Case, -1).run());
}
