// Port of snort3 helpers/literal_search.h + helpers/boyer_moore_search.{h,cc}.
//
// Original: Copyright (C) 2020-2026 Cisco and/or its affiliates.
//
// LiteralSearch is the abstract single-pattern matcher; instantiate() in C
// selects HyperSearch when hyperscan is compiled in / configured, else
// BoyerMoore{Case,NoCase}. No hyperscan here -> the BM engine is the only
// backend (see KNOWN DEVIATIONS.md).

#![allow(dead_code)]

/// C LiteralSearch interface trait. Handle (hyperscan scratch) is dropped:
/// with no hyperscan it is always nullptr in C (nullptr_t equivalent).
pub trait LiteralSearch {
    fn search(&self, buffer: &[u8]) -> i32;
}

/// skip table shared by both flavors (make_skip).
/// skip[c] is the distance between the pattern's last character and the
/// rightmost occurrence of c in pattern[..last]; pattern_len if absent.
pub struct BoyerMooreSearch {
    // pattern is NOT owned: C borrows the caller's bytes for the object's
    // lifetime. We copy to keep the port safe; bytes are identical.
    pub(crate) pattern: Vec<u8>,
    pub(crate) last: usize,
    pub(crate) skip: [usize; 256],
}

impl BoyerMooreSearch {
    pub(crate) fn new(pattern: &[u8]) -> Self {
        assert!(!pattern.is_empty(), "C assert(pattern_len > 0)");
        let last = pattern.len() - 1;
        let mut skip = [pattern.len(); 256];
        for i in 0..last {
            skip[pattern[i] as usize] = last - i;
        }
        BoyerMooreSearch {
            pattern: pattern.to_vec(),
            last,
            skip,
        }
    }
}

/// C BoyerMooreSearchCase.
pub struct BoyerMooreSearchCase {
    bm: BoyerMooreSearch,
}

impl BoyerMooreSearchCase {
    pub fn new(pattern: &[u8]) -> Self {
        BoyerMooreSearchCase {
            bm: BoyerMooreSearch::new(pattern),
        }
    }
}

impl LiteralSearch for BoyerMooreSearchCase {
    fn search(&self, buffer: &[u8]) -> i32 {
        let pattern = &self.bm.pattern;
        let plen = pattern.len();
        let last = self.bm.last;
        let start = buffer.as_ptr() as usize;
        let mut buffer = buffer;

        while buffer.len() >= plen {
            let mut pos = last;
            loop {
                if buffer[pos] != pattern[pos] {
                    break;
                }
                if pos == 0 {
                    return (buffer.as_ptr() as usize - start) as i32;
                }
                pos -= 1;
            }
            let s = self.bm.skip[buffer[last] as usize];
            buffer = &buffer[s..]; // C UB-would occur if s > len; skip[] <=
            // plen <= len here keeps it in-bounds like C's pointer bump
        }
        -1
    }
}

/// C BoyerMooreSearchNoCase. Like C, the pattern must ALREADY be uppercased
/// by the caller (the C tester and LiteralSearch callers uppercase it); the
/// buffer is ASCII-uppercased on the fly with C toupper semantics.
pub struct BoyerMooreSearchNoCase {
    bm: BoyerMooreSearch,
}

impl BoyerMooreSearchNoCase {
    pub fn new(pattern: &[u8]) -> Self {
        BoyerMooreSearchNoCase {
            bm: BoyerMooreSearch::new(pattern),
        }
    }
}

/// C toupper on unsigned char in the "C" locale.
#[inline]
fn c_toupper(b: u8) -> u8 {
    if b.is_ascii_lowercase() {
        b - b'a' + b'A'
    } else {
        b
    }
}

impl LiteralSearch for BoyerMooreSearchNoCase {
    fn search(&self, buffer: &[u8]) -> i32 {
        let pattern = &self.bm.pattern;
        let plen = pattern.len();
        let last = self.bm.last;
        let start = buffer.as_ptr() as usize;
        let mut buffer = buffer;

        while buffer.len() >= plen {
            let mut pos = last;
            loop {
                if c_toupper(buffer[pos]) != pattern[pos] {
                    break;
                }
                if pos == 0 {
                    return (buffer.as_ptr() as usize - start) as i32;
                }
                pos -= 1;
            }
            let s = self.bm.skip[c_toupper(buffer[last]) as usize];
            buffer = &buffer[s..];
        }
        -1
    }
}

/// C LiteralSearch::instantiate(h, pattern, len, no_case, false) without
/// hyperscan: returns the BM backend matching the flags. (hs=true /
/// hyperscan_literals config path omitted — no hyperscan backend; the
/// returned engine is observably identical for literal matching, see
/// KNOWN DEVIATIONS.md.)
pub enum LiteralSearchImpl {
    Case(BoyerMooreSearchCase),
    NoCase(BoyerMooreSearchNoCase),
}

pub fn instantiate(pattern: &[u8], no_case: bool) -> LiteralSearchImpl {
    if no_case {
        LiteralSearchImpl::NoCase(BoyerMooreSearchNoCase::new(pattern))
    } else {
        LiteralSearchImpl::Case(BoyerMooreSearchCase::new(pattern))
    }
}

impl LiteralSearch for LiteralSearchImpl {
    fn search(&self, buffer: &[u8]) -> i32 {
        match self {
            LiteralSearchImpl::Case(c) => c.search(buffer),
            LiteralSearchImpl::NoCase(c) => c.search(buffer),
        }
    }
}
