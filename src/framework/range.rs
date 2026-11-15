// Port of snort3 framework/range.{h,cc}: RangeCheck — the op/min/max range
// helper shared by IpsOptions like dsize and icode.
//
// Quirks from range.h's header comment kept verbatim: `<>` is icode-style
// strict-exclusive, `<=>` is dsize-style inclusive, and a bare number like
// "5" sets min = 0, max = 5 (the EQ-from-hi swap).
#![allow(dead_code)]

use crate::hash::{finalize, mix};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcOp {
    Eq,
    Not,
    Lt,
    Le,
    Gt,
    Ge,
    Lg,
    Leg,
    Max,
}

// C enum Op discriminants EQ..MAX = 0..8 are load-bearing for hash():
// `uint32_t a = op;`.
pub fn op_code(op: RcOp) -> u32 {
    match op {
        RcOp::Eq => 0,
        RcOp::Not => 1,
        RcOp::Lt => 2,
        RcOp::Le => 3,
        RcOp::Gt => 4,
        RcOp::Ge => 5,
        RcOp::Lg => 6,
        RcOp::Leg => 7,
        RcOp::Max => 8,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeCheck {
    pub op: RcOp,
    pub min: i64,
    pub max: i64,
}

impl Default for RangeCheck {
    fn default() -> Self {
        RangeCheck {
            op: RcOp::Max,
            min: 0,
            max: 0,
        }
    }
}

// get_tokens state machine: verbatim port. Inputs are bytes (C works on
// char*; the rule parser feeds ASCII).
fn get_tokens(s: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut low: Vec<u8> = Vec::new();
    let mut ops: Vec<u8> = Vec::new();
    let mut hi: Vec<u8> = Vec::new();
    let mut state = 0u32;

    let isxdigit = |c: u8| c.is_ascii_hexdigit();
    let strp = |c: u8, set: &[u8]| set.contains(&c);

    for &ch in s {
        match state {
            0 => {
                // looking for low or ops
                if strp(ch, b"+-x") || isxdigit(ch) {
                    low.push(ch);
                    state = 1;
                } else if strp(ch, b"=!<>") {
                    ops.push(ch);
                    state = 2;
                } else if ch != b' ' {
                    return None;
                }
            }
            1 => {
                // accumulating low
                if ch == b'x' || isxdigit(ch) {
                    low.push(ch);
                } else if strp(ch, b"=!<>") {
                    ops.push(ch);
                    state = 2;
                } else if ch != b' ' {
                    return None;
                }
            }
            2 => {
                // accumulating ops
                if strp(ch, b"+-x") || isxdigit(ch) {
                    hi.push(ch);
                    state = 4;
                } else if strp(ch, b"=!<>") {
                    ops.push(ch);
                } else if ch == b' ' {
                    state = 3;
                } else {
                    return None;
                }
            }
            3 => {
                // looking for hi
                if strp(ch, b"+-x") || isxdigit(ch) {
                    hi.push(ch);
                    state = 4;
                } else {
                    return None;
                }
            }
            4 => {
                // accumulating hi
                if ch == b'x' || isxdigit(ch) {
                    hi.push(ch);
                } else if ch != b' ' {
                    return None;
                }
            }
            _ => unreachable!(),
        }
    }
    Some((low, ops, hi))
}

fn get_op(s: &[u8]) -> Option<RcOp> {
    let op = if s.is_empty() || s == b"=" {
        RcOp::Eq
    } else if s == b"!" {
        RcOp::Not
    } else if s == b"<" {
        RcOp::Lt
    } else if s == b">" {
        RcOp::Gt
    } else if s == b"!=" {
        RcOp::Not
    } else if s == b"<=" {
        RcOp::Le
    } else if s == b">=" {
        RcOp::Ge
    } else if s == b"<>" {
        RcOp::Lg
    } else if s == b"<=>" {
        RcOp::Leg
    } else {
        return None;
    };
    Some(op)
}

/// C get_num uses strtoll base 0 and fails on errno (ERANGE incl.) or an
/// unconsumed tail. C++ strtoll saturates at LLONG_MIN/MAX and sets errno on
/// overflow, so "out of range" -> errno != 0 -> parse fails.
fn c_strtoll(s: &[u8]) -> Option<i64> {
    if s.is_empty() {
        return Some(0); // C get_num empty case
    }
    // parse base-0: optional sign, 0x hex, leading-0 octal, else decimal
    let mut i = 0usize;
    let neg = match s.get(i) {
        Some(b'+') => {
            i += 1;
            false
        }
        Some(b'-') => {
            i += 1;
            true
        }
        _ => false,
    };
    if i >= s.len() {
        return None; // no digits: strtoll returns 0 with end==s -> *end != 0? No: end==s and C only checks !*end and errno. For "5=" style, get_tokens never yields an empty-digit token; strtoll("") can't arrive here. Still model strtoll: no digits -> end == s; then `!*end` fails unless s empty
    }
    let (radix, i) = if s[i] == b'0' && matches!(s.get(i + 1), Some(b'x') | Some(b'X')) {
        (16u32, i + 2)
    } else if s[i] == b'0' {
        (8u32, i)
    } else {
        (10u32, i)
    };
    let mut value: u64 = 0;
    let mut overflow = false;
    let mut j = i;
    // strtoll semantics: accumulate with saturation at LLONG_MAX/LLONG_MIN and
    // set ERANGE on overflow.
    let limit: u64 = if neg {
        (i64::MAX as u64) + 1
    } else {
        i64::MAX as u64
    };
    while j < s.len() {
        let d = digit_of(s[j], radix);
        match d {
            Some(dv) => {
                let dv = dv as u64;
                match value.checked_mul(radix as u64) {
                    Some(m) => match m.checked_add(dv) {
                        Some(v) if v <= limit => value = v,
                        _ => {
                            value = limit;
                            overflow = true;
                            // consume the rest of the digits (C strtoll does)
                        }
                    },
                    _ => {
                        value = limit;
                        overflow = true;
                    }
                }
                j += 1;
            }
            None => break,
        }
    }
    // C strtoll: no digits consumed at all leaves end == nptr, and trailing
    // junk stops it early; get_num requires *end == 0 in both cases, so the
    // whole token must be consumed, digits included.
    if j == i {
        return None; // sign-only, "0x" with no hex digits, "x15", etc.
    }
    if overflow {
        return None; // errno (ERANGE) set
    }
    if j != s.len() {
        return None; // *end != 0: trailing junk (e.g. "08" parsed as octal)
    }
    if neg && value == (i64::MAX as u64) + 1 {
        return Some(i64::MIN);
    }
    if neg {
        Some(-(value as i64))
    } else {
        Some(value as i64)
    }
}

impl RangeCheck {
    pub fn init(&mut self) {
        self.op = RcOp::Max;
        self.min = 0;
        self.max = 0;
    }

    pub fn is_set(&self) -> bool {
        self.op != RcOp::Max
    }

    pub fn parse(&mut self, s: &[u8]) -> bool {
        let (low, ops, hi) = match get_tokens(s) {
            Some(t) => t,
            None => return false,
        };
        let op = match get_op(&ops) {
            Some(o) => o,
            None => return false,
        };
        let min = match c_strtoll(&low) {
            Some(n) => n,
            None => return false,
        };
        let max = match c_strtoll(&hi) {
            Some(n) => n,
            None => return false,
        };
        if !valid(op, !low.is_empty(), !hi.is_empty()) {
            return false;
        }

        self.op = op;
        self.min = min;
        self.max = max;

        if self.op == RcOp::Eq && hi.is_empty() {
            if !ops.is_empty() {
                return false;
            }
            self.max = self.min;
            self.min = 0;
        } else if self.op == RcOp::Gt || self.op == RcOp::Ge {
            self.min = self.max;
            self.max = 0;
        }

        !((self.op == RcOp::Lg || self.op == RcOp::Leg) && self.min > self.max)
    }

    pub fn eval(&self, c: i64) -> bool {
        match self.op {
            RcOp::Eq => c == self.max,
            RcOp::Not => c != self.max,
            RcOp::Lt => c < self.max,
            RcOp::Le => c <= self.max,
            RcOp::Gt => c > self.min,
            RcOp::Ge => c >= self.min,
            RcOp::Lg => self.min < c && c < self.max,
            RcOp::Leg => self.min <= c && c <= self.max,
            RcOp::Max => false,
        }
    }

    /// C validate(s, r): parse then bound-check against a "#: | :# | #: # | #"
    /// range string (r may be null -> just parse).
    pub fn validate(&mut self, s: &[u8], r: Option<&[u8]>) -> bool {
        if !self.parse(s) {
            return false;
        }
        let r = match r {
            None => return true,
            Some(r) => r,
        };

        // check that min and max are within r
        let (v_min, v_max) = match self.op {
            RcOp::Lg | RcOp::Leg => (self.min, self.max),
            RcOp::Gt | RcOp::Ge => (self.min, self.min),
            _ => (self.max, self.max),
        };

        if r.first().copied() != Some(b':') {
            // C strtoll(r, nullptr, 0): leading number, junk-tolerant.
            match c_strtoll_prefix(r) {
                Some(low) if v_min < low => return false,
                _ => {}
            }

        }

        if let Some(pos) = r.iter().position(|&c| c == b':') {
            let t = &r[pos + 1..];
            if !t.is_empty() {
                match c_strtoll_prefix(t) {
                    Some(hi) if v_max > hi => return false,
                    _ => {}
                }
            }
        }
        true
    }

    /// C hash(): jenkins mix+finalize over (op, min, max) as uint32s.
    pub fn hash(&self) -> u32 {
        let mut a = op_code(self.op);
        let mut b = (self.min as i32) as u32; // C narrows int64_t -> uint32_t
        let mut c = (self.max as i32) as u32;
        mix(&mut a, &mut b, &mut c);
        finalize(&mut a, &mut b, &mut c);
        a
    }
}

/// strtoll with a C caller that ignores end and errno except on empty input:
/// parse leading number; on overflow saturate (no errno check in caller).
fn c_strtoll_prefix(s: &[u8]) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    let mut i = 0usize;
    let neg = match s.get(i) {
        Some(b'+') => {
            i += 1;
            false
        }
        Some(b'-') => {
            i += 1;
            true
        }
        _ => false,
    };
    let (radix, i) = if s.get(i) == Some(&b'0') && matches!(s.get(i + 1), Some(b'x') | Some(b'X')) {
        (16u32, i + 2)
    } else if s.get(i) == Some(&b'0') {
        (8u32, i)
    } else {
        (10u32, i)
    };
    let limit: u64 = if neg {
        (i64::MAX as u64) + 1
    } else {
        i64::MAX as u64
    };
    let mut value: u64 = 0;
    let mut j = i;
    let mut consumed = false;
    while j < s.len() {
        match digit_of(s[j], radix) {
            Some(dv) => {
                consumed = true;
                value = match value.checked_mul(radix as u64) {
                    Some(m) => match m.checked_add(dv as u64) {
                        Some(v) if v <= limit => v,
                        _ => limit,
                    },
                    _ => limit,
                };
                j += 1;
            }
            None => break,
        }
    }
    if !consumed {
        return Some(0); // strtoll returns 0 with end==nptr (caller ignores)
    }
    Some(if neg {
        value.wrapping_neg() as i64 // saturating wrap: value <= limit
    } else {
        value as i64
    })
}

fn digit_of(b: u8, radix: u32) -> Option<u32> {
    let d = match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'a'..=b'f' => (b - b'a' + 10) as u32,
        b'A'..=b'F' => (b - b'A' + 10) as u32,
        _ => return None,
    };
    if d < radix {
        Some(d)
    } else {
        None
    }
}

fn valid(op: RcOp, low: bool, hi: bool) -> bool {
    if op == RcOp::Eq {
        (low && !hi) || (hi && !low)
    } else if op == RcOp::Lg || op == RcOp::Leg {
        low && hi
    } else {
        !low && hi
    }
}
