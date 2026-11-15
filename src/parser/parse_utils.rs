// Port of snort3 parser/parse_utils.{h,cc}: parse_byte_code (quoted text +
// |hex| byte-code strings) and parse_int (strtol + range clamp with C errno
// side effects).
//
// Quirks preserved verbatim:
//   * C state 0 fall-through into state 1 (only `!` handled at state 0);
//   * the closing-quote detection is `c == '"' && in[len-1] == '"'`, so an
//     interior quote in e.g. `"ab"c` enters hex mode and the tail is text;
//   * parse_byte_code does NOT close the hex run at end-of-input: a dangling
//     "|41" without a closing `|` never flushes hex;
//   * parse_int returns the clamped value even after an invalid-format
//     error ("10  " -> 10 with an error logged);
//   * ERANGE (34 on Linux) is left in errno by the overflow path and
//     observable.
#![allow(clippy::upper_case_acronyms)]

pub const ERANGE: i32 = 34;

#[derive(Debug, Default)]
pub struct ByteCodeResult {
    pub ok: bool,
    pub negate: bool,
    pub out: Vec<u8>,
    pub errors: Vec<String>,
}

// C isdigit/isspace/isxdigit/isupper are called on char values; the rule
// parser feeds ASCII. glibc would return 0 for the negative (>127) signed
// chars, which is what these predicates give too (see deviations).
fn c_isdigit(c: u8) -> bool {
    c.is_ascii_digit()
}
fn c_isupper(c: u8) -> bool {
    c.is_ascii_uppercase()
}
fn c_isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}
fn c_isxdigit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn xton(c: u8) -> u8 {
    if c_isdigit(c) {
        c - b'0'
    } else if c_isupper(c) {
        c - b'A' + 10
    } else {
        c - b'a' + 10
    }
}

pub fn parse_byte_code(input: &[u8]) -> ByteCodeResult {
    let mut r = ByteCodeResult::default();
    let mut state = 0u32;
    let mut idx: usize = 0;
    let mut len = input.len();
    r.negate = false;

    let mut hex: u8 = 0;
    let mut nx: u32 = 0;
    r.ok = true;

    while r.ok && (idx < len) {
        let c = input[idx];
        idx += 1;

        match state {
            0 => {
                if c == b'!' {
                    r.negate = true;
                    state = 1;
                    continue; // C `break`, not fall-through
                }
                // C falls through to case 1 here
                // loop invariant idx < len keeps len > 0 here, matching C
                // in[len-1] / --len.
                if c == b'"' && input[len - 1] == b'"' {
                    len -= 1;
                    state = 2;
                } else if !c_isspace(c) {
                    r.ok = false;
                }
            }
            1 => {
                if c == b'"' && input[len - 1] == b'"' {
                    len -= 1;
                    state = 2;
                } else if !c_isspace(c) {
                    r.ok = false;
                }
            }
            2 => {
                if c == b'|' {
                    hex = 0;
                    nx = 0;
                    state = 4;
                } else {
                    r.out.push(c);
                }
            }
            4 => {
                if c == b'|' {
                    if nx != 0 {
                        r.out.push(hex);
                    }
                    state = 2;
                } else if c_isxdigit(c) {
                    if nx >= 2 {
                        r.out.push(hex);
                        hex = 0;
                        nx = 0;
                    }
                    hex = hex.wrapping_shl(4) + xton(c);
                    nx += 1;
                } else if c_isspace(c) && nx != 0 {
                    r.out.push(hex);
                    hex = 0;
                    nx = 0;
                } else if !c_isspace(c) {
                    r.ok = false;
                }
            }
            _ => unreachable!(), // C assert(false)
        }
    }
    if !r.ok {
        r.errors.push(format!("invalid byte code at {idx}"));
    }
    r
}

/// C strtol base 10 faithful model: parse sign + decimal digits, stop at
/// first non-digit, saturate with ERANGE. Returns (value, end_offset,
/// erange).
fn c_strtol(s: &[u8]) -> (i64, usize, bool) {
    let mut i = 0usize;
    let neg = match s.first() {
        Some(b'+') => {
            i = 1;
            false
        }
        Some(b'-') => {
            i = 1;
            true
        }
        _ => false,
    };
    let start = i;
    let mut value: i64 = 0;
    let mut erange = false;
    while i < s.len() && s[i].is_ascii_digit() {
        let d = (s[i] - b'0') as i64;
        if !erange {
            match value.checked_mul(10).and_then(|v| v.checked_add(d)) {
                Some(v) => value = v,
                None => {
                    value = if neg { i64::MIN } else { i64::MAX };
                    erange = true;
                }
            }
        }
        i += 1;
    }
    if erange {
        // glibc saturates: negative -> LONG_MIN, positive -> LONG_MAX
        value = if neg { i64::MIN } else { i64::MAX };
    } else if neg {
        value = -value;
    }
    let _ = start;
    (value, i, erange)
}

#[derive(Debug)]
pub struct ParseIntResult {
    pub value: i32,
    pub errno: i32, // 0 or ERANGE; models errno after SnortStrtol + parse_int
    pub errors: Vec<String>,
}

pub fn parse_int(data: &[u8], tag: &str, low: i32, high: i32) -> ParseIntResult {
    debug_assert!(low <= high); // C assert(low <= high)

    let (value, end, erange) = c_strtol(data);
    let mut errors = Vec::new();
    let mut errno = if erange { ERANGE } else { 0 };

    if end < data.len() {
        // *endptr nonzero: invalid format; value NOT clamped on this path
        errors.push(format!("invalid '{tag}' format."));
        return ParseIntResult {
            value: value as i32,
            errno,
            errors,
        };
    }

    if errno == ERANGE || value > i64::from(i32::MAX) || value < i64::from(i32::MIN) {
        errors.push(format!("range problem on '{tag}' value."));
        errno = ERANGE;
    } else if value > i64::from(high) || value < i64::from(low) {
        errors.push(format!("'{tag}' must be in {low}:{high}, inclusive"));
    }

    let v = if value > i64::from(high) {
        high
    } else if value < i64::from(low) {
        low
    } else {
        value as i32
    };
    ParseIntResult {
        value: v,
        errno,
        errors,
    }
}
