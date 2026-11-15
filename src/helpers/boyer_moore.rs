// Port of snort3 src/helpers/boyer_moore.{h,cc} (BoyerMoore pattern matching).
//
// Original: Copyright (C) 2019-2026 Cisco and/or its affiliates.
// Semantics preserved exactly:
//   - skip[c] = distance from last pattern char to rightmost occurrence of c in
//     pattern[0..last]; skip[c] = pattern_len if c does not occur there.
//   - search() compares pattern as given; search_nocase() uppercases the buffer
//     (C `::toupper`, ASCII locale) and expects an already-uppercased pattern.
//   - Return byte offset of first match or -1.

pub struct BoyerMoore {
    pattern: Vec<u8>,
    pattern_len: usize,
    last: usize,
    skip: [usize; 256],
}

/// C `::toupper` on a uint8_t in the "C" locale.
fn c_toupper(b: u8) -> u8 {
    if b.is_ascii_lowercase() {
        b - b'a' + b'A'
    } else {
        b
    }
}

impl BoyerMoore {
    /// Mirrors `BoyerMoore(const uint8_t* pattern, unsigned pattern_len)`.
    /// Panics on empty pattern (original asserts pattern_len > 0).
    pub fn new(pattern: &[u8]) -> Self {
        assert!(!pattern.is_empty(), "pattern_len > 0");
        let pattern_len = pattern.len();
        let last = pattern_len - 1;
        let mut bm = BoyerMoore {
            pattern: pattern.to_vec(),
            pattern_len,
            last,
            skip: [0usize; 256],
        };
        bm.make_skip();
        bm
    }

    fn make_skip(&mut self) {
        for i in 0..256 {
            self.skip[i] = self.pattern_len;
        }
        for i in 0..self.last {
            self.skip[self.pattern[i] as usize] = self.last - i;
        }
    }

    pub fn search(&self, buffer: &[u8]) -> i64 {
        self.search_impl(buffer, false)
    }

    pub fn search_nocase(&self, buffer: &[u8]) -> i64 {
        self.search_impl(buffer, true)
    }

    fn search_impl(&self, buffer: &[u8], nocase: bool) -> i64 {
        // `off` tracks the C `buffer - start` pointer difference.
        let mut off = 0usize;
        let mut buffer_len = buffer.len();
        let mut buf = buffer;

        while buffer_len >= self.pattern_len {
            // for (pos = last; buffer[pos] == pattern[pos]; pos--) if (pos == 0) return buffer - start;
            let mut pos = self.last;
            loop {
                let b = if nocase { c_toupper(buf[pos]) } else { buf[pos] };
                if b != self.pattern[pos] {
                    break;
                }
                if pos == 0 {
                    return off as i64;
                }
                pos -= 1;
            }

            let last_b = if nocase { c_toupper(buf[self.last]) } else { buf[self.last] };
            let skip = self.skip[last_b as usize];
            buffer_len -= skip;
            buf = &buf[skip..];
            off += skip;
        }

        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from src/helpers/test/boyer_moore_test.cc (CppUTest cases 1:1).
    fn run(pat: &str, buf: &str, nocase: bool, idx: i64) -> bool {
        let pat = if nocase {
            pat.to_uppercase()
        } else {
            pat.to_string()
        };
        let bm = BoyerMoore::new(pat.as_bytes());
        let pos = if nocase {
            bm.search_nocase(buf.as_bytes())
        } else {
            bm.search(buf.as_bytes())
        };
        pos == idx
    }

    #[test]
    fn binary() {
        let pat: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
        let buf: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03,
            0x72, 0x01, 0x3F, 0x2B,
            0x1F, 0xCA, 0xFE, 0xBA,
            0xBE, 0x01, 0x02, 0x03,
        ];
        let bm = BoyerMoore::new(&pat);
        assert_eq!(bm.search(&buf), 9);
    }

    #[test]
    fn empty() {
        assert!(run("abc", "", false, -1));
    }

    #[test]
    fn start() {
        assert!(run("abc", "abc", false, 0));
    }

    #[test]
    fn start_nocase() {
        assert!(run("abc", "aBc", true, 0));
    }

    #[test]
    fn found1() {
        assert!(run("d", "abcdefg", false, 3));
    }

    #[test]
    fn found2() {
        assert!(run("nan", "banana", false, 2));
    }

    #[test]
    fn found3() {
        assert!(run("pan", "anpanman", false, 2));
    }

    #[test]
    fn found4() {
        assert!(run("bcd", "abcd", false, 1));
    }

    #[test]
    fn found5() {
        assert!(run("aa", "aaa", false, 0));
    }

    #[test]
    fn found6() {
        assert!(run("that", "which finally halts at tHaT point", true, 23));
    }

    #[test]
    fn not_found1() {
        assert!(run("nnaaman", "anpanmanam", false, -1));
    }

    #[test]
    fn not_found2() {
        assert!(run("abcd", "abc", false, -1));
    }

    #[test]
    fn not_found3() {
        assert!(run("abcd", "bcd", false, -1));
    }

    #[test]
    fn not_found4() {
        assert!(run("baa", "aaaaa", false, -1));
    }
}
