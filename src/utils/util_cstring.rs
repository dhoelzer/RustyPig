//! Port of snort3 src/utils/util_cstring.{h,cc}.
//!
//! Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//!           Copyright (C) 2002-2013 Sourcefire, Inc.;
//!           Copyright (C) 2002 Martin Roesch.
//!
//! The C++ original operates on possibly-unterminated C buffers. The Rust port
//! keeps that model over byte slices: buffer + explicit length, with NUL
//! termination treated as just another byte value (this is what the original
//! "safe" helpers check for). All search helpers return a byte offset (isize)
//! mirroring the C returned pointer (as offset from s), or -1 for null.

pub const SNORT_SNPRINTF_SUCCESS: i32 = 0;
pub const SNORT_SNPRINTF_TRUNCATION: i32 = 1;
pub const SNORT_SNPRINTF_ERROR: i32 = -1;

pub const SNORT_STRNCPY_SUCCESS: i32 = 0;
pub const SNORT_STRNCPY_TRUNCATION: i32 = 1;
pub const SNORT_STRNCPY_ERROR: i32 = -1;
pub const SNORT_STRNLEN_ERROR: i32 = -1;

/// Mirrors `int SnortStrnlen(const char* buf, int buf_size)`.
/// Returns string length if NUL-terminated within buf_size, else SNORT_STRNLEN_ERROR.
pub fn snort_strnlen(buf: &[u8], buf_size: i32) -> i32 {
    if buf.is_empty() || buf_size <= 0 {
        return SNORT_STRNLEN_ERROR;
    }
    let mut i = 0i32;
    while i < buf_size {
        if buf[i as usize] == 0 {
            break;
        }
        i += 1;
    }
    if i == buf_size {
        return SNORT_STRNLEN_ERROR;
    }
    i
}

/// Mirrors `int SnortStrncpy(char* dst, const char* src, size_t dst_size)`.
/// `dst` is mutated in place and always NUL-terminated. dst_size includes NUL.
pub fn snort_strncpy(dst: &mut [u8], src: &[u8], dst_size: usize) -> i32 {
    if dst_size == 0 || dst.len() < dst_size {
        return SNORT_STRNCPY_ERROR;
    }
    dst[dst_size - 1] = 0;

    // strncpy semantics: copy min(strlen(src)+1, dst_size) bytes, padding with NUL
    let src_len = src.iter().position(|&b| b == 0).map_or(src.len(), |p| p);
    let n = src_len.min(dst_size - 1);
    dst[..n].copy_from_slice(&src[..n]);
    for b in &mut dst[n..dst_size] {
        *b = 0;
    }

    if src_len >= dst_size {
        // result was truncated (note: dst[last] stays 0, matching original check
        // where truncation is detected when src had no NUL within dst_size)
        return SNORT_STRNCPY_TRUNCATION;
    }
    SNORT_STRNCPY_SUCCESS
}

/// Mirrors `const char* SnortStrnPbrk(const char* s, int slen, const char* accept)`.
/// Returns offset of first byte of s[..slen] appearing in accept, or -1.
/// C semantics detail: strchr(accept, ch) matches ch==0 against accept's own NUL
/// terminator, so any NUL byte in s (after position 0, which the `!*s` guard
/// rejects) is a match even when not literally in accept.
pub fn snort_strn_pbrk(s: &[u8], slen: i32, accept: &[u8]) -> isize {
    if slen == 0 || s.is_empty() || s[0] == 0 {
        return -1;
    }
    // accept as a C string: effective set excludes bytes from its NUL terminator on
    let acc_end = accept.iter().position(|&b| b == 0).unwrap_or(accept.len());
    let s_end = (slen as usize).min(s.len());
    for i in 0..s_end {
        let ch = s[i];
        if ch == 0 || accept[..acc_end].contains(&ch) {
            return i as isize;
        }
    }
    -1
}

/// Mirrors `const char* SnortStrnStr(const char* s, int slen, const char* searchstr)`.
/// Search for searchstr within s[..slen]; stops at first NUL in s. Returns offset or -1.
pub fn snort_strn_str(s: &[u8], slen: i32, searchstr: &[u8]) -> isize {
    if slen == 0 || s.is_empty() || s[0] == 0 {
        return -1;
    }
    // searchstr is a C string: strip its NUL terminator if present
    let pat: &[u8] = match searchstr.iter().position(|&b| b == 0) {
        Some(p) => &searchstr[..p],
        None => searchstr,
    };
    if pat.is_empty() {
        return 0; // C: empty searchstr returns s
    }
    let ch = pat[0];
    let len = pat.len() - 1; // strlen(searchstr+1)
    let mut i = 0usize;
    let mut slen = slen;
    loop {
        // inner scan for first char
        loop {
            if i >= s.len() {
                return -1;
            }
            let nc = s[i];
            i += 1;
            slen -= 1;
            if nc == 0 {
                return -1;
            }
            if slen == 0 {
                return -1;
            }
            if nc == ch {
                break;
            }
        }
        if slen - (len as i32) < 0 {
            return -1;
        }
        if i + len > s.len() || s[i..i + len] != pat[1..] {
            continue;
        }
        return (i - 1) as isize; // C `s--`
    }
}

/// Mirrors `const char* SnortStrcasestr(const char* s, int slen, const char* substr)`.
/// Case-insensitive (C-locale tolower) variant of SnortStrnStr. Returns offset or -1.
pub fn snort_strcasestr(s: &[u8], slen: i32, substr: &[u8]) -> isize {
    if slen == 0 || s.is_empty() || s[0] == 0 {
        return -1;
    }
    let sub: &[u8] = match substr.iter().position(|&b| b == 0) {
        Some(p) => &substr[..p],
        None => substr,
    };
    if sub.is_empty() {
        return 0;
    }
    let ch = c_tolower(sub[0]);
    let len = sub.len() - 1;
    let mut i = 0usize;
    let mut slen = slen;
    loop {
        loop {
            if i >= s.len() {
                return -1;
            }
            let nc = s[i];
            i += 1;
            slen -= 1;
            if nc == 0 {
                return -1;
            }
            if slen == 0 {
                return -1;
            }
            if c_tolower(nc) == ch {
                break;
            }
        }
        if slen - (len as i32) < 0 {
            return -1;
        }
        if i + len > s.len() {
            continue;
        }
        if s[i..i + len]
            .iter()
            .zip(&sub[1..])
            .any(|(&a, &b)| c_tolower(a) != c_tolower(b))
        {
            continue;
        }
        return (i - 1) as isize; // C `s--`
    }
}

/// C `tolower((uint8_t)c)` in the "C" locale.
fn c_tolower(c: u8) -> u8 {
    if c.is_ascii_uppercase() {
        c - b'A' + b'a'
    } else {
        c
    }
}

/// Mirrors `inline int SnortStrToU32(const char* buffer, char** endptr, uint32_t* value, int base)`.
/// Returns (rc, value, end_index, erange) where rc -1 == error (mirrors C -1),
/// end_index mirrors *endptr as an offset (also carries the EINVAL/"nothing to
/// convert" check), and erange replicates the errno=ERANGE contract when the
/// value exceeded u32::MAX (clamped, success returned, exactly like the C++).
pub struct StrToU32 {
    pub rc: i32,
    pub value: u32,
    pub end: usize,
    pub erange: bool,
}

fn c_isspace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

pub fn snort_str_to_u32(buffer: &[u8], base: u32) -> StrToU32 {
    // skip isspace
    let mut i = 0usize;
    while i < buffer.len() && c_isspace(buffer[i]) {
        i += 1;
    }
    if i >= buffer.len() || buffer[i] == b'\0' || buffer[i] == b'-' {
        // all spaces / empty / negative sign
        return StrToU32 { rc: -1, value: 0, end: i, erange: false };
    }
    // strtoul accepts optional '+'
    let num_start = if buffer[i] == b'+' { i + 1 } else { i };

    // manual strtoul parse in `base`
    let mut acc: u64 = 0;
    let mut overflow = false;
    let mut j = num_start;
    let base = if base == 0 {
        // C strtoul base 0: 0x/0X -> 16, leading 0 -> 8, else 10
        if j + 1 < buffer.len() && buffer[j] == b'0' && (buffer[j + 1] == b'x' || buffer[j + 1] == b'X') {
            j += 2;
            16
        } else if j < buffer.len() && buffer[j] == b'0' {
            8
        } else {
            10
        }
    } else {
        base
    };
    let mut digits = 0usize;
    while j < buffer.len() {
        let d = match buffer[j] {
            b'0'..=b'9' => (buffer[j] - b'0') as u32,
            b'a'..=b'z' => (buffer[j] - b'a' + 10) as u32,
            b'A'..=b'Z' => (buffer[j] - b'A' + 10) as u32,
            _ => u32::MAX,
        };
        if d >= base {
            break;
        }
        match acc.checked_mul(base as u64).and_then(|x| x.checked_add(d as u64)) {
            Some(v) => acc = v,
            None => {
                overflow = true;
                acc = u64::MAX;
            }
        }
        digits += 1;
        j += 1;
    }

    if digits == 0 && j == i {
        // nothing to convert (C: *endptr == buffer)
        return StrToU32 { rc: -1, value: 0, end: num_start, erange: false };
    }
    // NOTE: like glibc strtoul, "+" alone parses as 0 (endptr != buffer -> success).

    let mut erange = overflow;
    if acc > u32::MAX as u64 {
        acc = u32::MAX as u64;
        erange = true;
    }
    StrToU32 { rc: 0, value: acc as u32, end: j, erange }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strnlen_null_terminated() {
        assert_eq!(snort_strnlen(b"abcd\0", 5), 4); // NUL at index 4 within 5
        assert_eq!(snort_strnlen(b"abcd", 4), -1); // no NUL
        assert_eq!(snort_strnlen(b"", 0), -1);
    }

    #[test]
    fn strncpy_success_and_truncation() {
        let mut dst = [0x58u8; 8];
        assert_eq!(snort_strncpy(&mut dst, b"abc\0", 8), SNORT_STRNCPY_SUCCESS);
        assert_eq!(&dst[..4], b"abc\0");

        let mut dst = [0x58u8; 4];
        // src longer than dst_size: strncpy writes exactly dst_size bytes, no NUL
        // from src; original sets dst[last]=0 first and detects via that staying 0
        // only when strncpy overwrote it... strncpy leaves last byte = 'd' ->
        // original returns TRUNCATION and forces NUL.
        assert_eq!(snort_strncpy(&mut dst, b"abcdef\0", 4), SNORT_STRNCPY_TRUNCATION);
        assert_eq!(&dst, b"abc\0");
    }

    #[test]
    fn strn_pbrk_finds_first_accept_char() {
        assert_eq!(snort_strn_pbrk(b"hello world\0", 11, b" ow\0"), 4); // 'o' at 4
        assert_eq!(snort_strn_pbrk(b"hello world\0", 4, b" ow\0"), -1); // 'o' at 4 is beyond slen=4
        assert_eq!(snort_strn_pbrk(b"abc\0", 0, b"c\0"), -1);
        // NUL inside slen matches via strchr(accept, 0) hitting accept's terminator
        assert_eq!(snort_strn_pbrk(b"ab\0", 3, b"c"), 2);
    }

    #[test]
    fn strn_str_basic() {
        assert_eq!(snort_strn_str(b"foobarbaz\0", 9, b"bar\0"), 3);
        // slen=6: scan f,o,o,b (slen 5->2), slen-len=2-2=0, memcmp at [3] fits:
        assert_eq!(snort_strn_str(b"foobarbaz\0", 6, b"bar\0"), 3);
        // slen=5: after b (slen 4->1), 1-2 < 0 -> null; next b consumes past slen -> null
        assert_eq!(snort_strn_str(b"foobarbaz\0", 5, b"bar\0"), -1);
        assert_eq!(snort_strn_str(b"abc\0", 4, b"abc\0"), 0); // C: returns s
        assert_eq!(snort_strn_str(b"abc\0", 4, b"\0"), 0); // empty pattern (C returns s)
        // the delimiter scanning used by parse_ports:
        assert_eq!(snort_strn_str(b"ab;cd;\0", 7, b";\0"), 2);
    }

    #[test]
    fn strcasestr_basic() {
        assert_eq!(snort_strcasestr(b"Get POSTed\0", 10, b"post\0"), 4);
        assert_eq!(snort_strcasestr(b"Get POSTed\0", 6, b"post\0"), -1);
    }

    #[test]
    fn strtou32_cases() {
        // reject: all spaces, negative, garbage
        assert_eq!(snort_str_to_u32(b"    \0", 10).rc, -1);
        assert_eq!(snort_str_to_u32(b"-5\0", 10).rc, -1);
        assert_eq!(snort_str_to_u32(b"xyz\0", 10).rc, -1);

        let r = snort_str_to_u32(b" 123abc\0", 10);
        assert_eq!(r.rc, 0);
        assert_eq!(r.value, 123);
        assert_eq!(r.end, 4); // *endptr at 'a' (0-based offset)

        let r = snort_str_to_u32(b"0x1f4\0", 0); // auto base like strtoul(base 0)
        // NOTE: original callers pass explicit bases; base 0 means "auto" in C.
        // Our port keeps C base-0 semantics:
        assert_eq!(r.rc, 0);
        assert_eq!(r.value, 500);

        let r = snort_str_to_u32(b"4294967296\0", 10); // 2^32: clamp + ERANGE, still success
        assert_eq!(r.rc, 0);
        assert_eq!(r.value, u32::MAX);
        assert!(r.erange);
    }
}
