// Port of snort3 utils/util.{h,cc}.
// Pure-logic members are verbatim; filesystem members map to std::fs;
// ts_print's SnortConfig dependency becomes an explicit TimeCfg param
// (see KNOWN DEVIATIONS.md).
#![allow(clippy::too_many_arguments)]

use std::fs;

pub const TIMEBUF_SIZE: usize = 27;
pub const SECONDS_PER_DAY: i64 = 86400; // number of seconds in a day

pub fn get_random_seed() -> u32 {
    // C: std::random_device{}() with clock fallback.
    use std::io::Read;
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = u32::MAX;
    let mut buf = [0u8; 4];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            seed = u32::from_le_bytes(buf);
        }
    } else {
        seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32 ^ d.subsec_nanos())
            .unwrap_or(0);
    }
    seed
}

pub fn get_file_size(path: &str) -> Option<usize> {
    // C: stat; reject non-regular and negative size
    let md = fs::metadata(path).ok()?;
    if !md.is_file() {
        return None;
    }
    let sz = md.len(); // metadata never reports negative
    Some(sz as usize)
}

pub fn is_directory_path(path: &str) -> bool {
    match fs::metadata(path) {
        Ok(md) => md.is_dir(),
        Err(_) => false,
    }
}

/// C memrchr: last occurrence of byte c in s[0..n], search from the end.
pub fn snort_memrchr(s: &[u8], c: u8) -> Option<usize> {
    let mut p = s.len();
    while p != 0 {
        p -= 1;
        if s[p] == c {
            return Some(p);
        }
    }
    None
}

/// Subset of SnortConfig fields consumed by ts_print.
#[derive(Clone, Copy, Default)]
// Default = all-zero mirrors C SnortConfig defaults (thiszone=0, flags off)
pub struct TimeCfg {
    pub thiszone: i64,
    pub output_use_utc: bool,
    pub output_include_year: bool,
}

/// Days-from-civil (Howard Hinnant's algorithm), matching gmtime_r for
/// the proleptic Gregorian range C's gmtime_r supports.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0,399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0,365]
    let mp = (5 * doy + 2) / 153; // [0,11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1,31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1,12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// ts_print: C takes (tv_sec, tv_usec); config selects the format.
/// Returns a NUL-free formatted string (buffer is TIMEBUF_SIZE in C).
pub fn ts_print(cfg: &TimeCfg, tv_sec: i64, tv_usec: u32) -> String {
    let mut localzone = cfg.thiszone;
    if cfg.output_use_utc {
        localzone = 0;
    }

    // C int arithmetic wraps at i32 for s: keep i64 (see deviations)
    let s = (tv_sec + localzone).rem_euclid(SECONDS_PER_DAY);
    let time = (tv_sec + localzone) - s;

    let (year, mon, mday) = civil_from_days(time / 86400);
    // C struct tm: tm_year = year - 1900
    let tm_year = year - 1900;

    if cfg.output_include_year {
        // C: int year = (lt->tm_year >= 100) ? (lt->tm_year - 100) : lt->tm_year;
        let yr = if tm_year >= 100 { tm_year - 100 } else { tm_year };
        format!(
            "{:02}/{:02}/{:02}-{:02}:{:02}:{:02}.{:06}",
            yr,
            mon,
            mday,
            s / 3600,
            (s % 3600) / 60,
            s % 60,
            tv_usec
        )
    } else {
        // yyyymmdd form (C takes a bool at the callsite)
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
            year,
            mon,
            mday,
            s / 3600,
            (s % 3600) / 60,
            s % 60,
            tv_usec
        )
    }
}

/// yyyymmdd=false C form: "%02d/%02d-%02d:%02d:%02d.%06u" (no year).
pub fn ts_print_mmdd(cfg: &TimeCfg, tv_sec: i64, tv_usec: u32) -> String {
    let mut localzone = cfg.thiszone;
    if cfg.output_use_utc {
        localzone = 0;
    }
    let s = (tv_sec + localzone).rem_euclid(SECONDS_PER_DAY);
    let time = (tv_sec + localzone) - s;
    let (_, mon, mday) = civil_from_days(time / 86400);
    // C printf %02d of tm_mon+1 etc (mon already 1..12)
    format!(
        "{:02}/{:02}-{:02}:{:02}:{:02}.{:06}",
        mon,
        mday,
        s / 3600,
        (s % 3600) / 60,
        s % 60,
        tv_usec
    )
}

/// uint8_to_printable_str: printable 0x20..0x7E as chars, others as
/// "%.2x " bracketed by |hex-state| runs.
pub fn uint8_to_printable_str(buff: &[u8]) -> String {
    let mut print_str = String::new();
    let mut hex_state = false;
    for b in buff {
        if *b >= 0x20 && *b <= 0x7E {
            if hex_state {
                hex_state = false;
                print_str.push('|');
            }
            print_str.push(*b as char);
        } else {
            if !hex_state {
                hex_state = true;
                print_str.push('|');
            }
            print_str.push_str(&format!("{b:02x} "));
        }
    }
    if hex_state {
        print_str.push('|');
    }
    print_str
}

/// str_to_int_vector: split on delim, std::stoul each item.
/// C++ std::stoul throws on an unparseable/empty item; Rust mirrors with
/// a panic (same observable crash, see KNOWN DEVIATIONS.md).
pub fn str_to_int_vector(s: &str, delim: u8) -> Vec<u32> {
    let mut elems = Vec::new();
    for item in s.as_bytes().split(|c| *c == delim) {
        elems.push(stoul(item).expect("stoul: no conversion (C++ std::stoul throws)"));
    }
    elems
}

/// C++ std::stoul prefix parse (base 10): leading ws, optional sign,
/// digits; Err on no digits (throws in C++).
fn stoul(item: &[u8]) -> Result<u32, ()> {
    let mut i = 0;
    while i < item.len() && (item[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    let neg = if i < item.len() && (item[i] == b'-' || item[i] == b'+') {
        item[i] == b'-'
    } else {
        false
    };
    if i < item.len() && (item[i] == b'-' || item[i] == b'+') {
        i += 1;
    }
    let start = i;
    let mut v: u64 = 0;
    while i < item.len() && item[i].is_ascii_digit() {
        v = v
            .saturating_mul(10)
            .saturating_add((item[i] - b'0') as u64);
        i += 1;
    }
    if i == start {
        return Err(());
    }
    // C ul = wraps unsigned long; 32-bit target: mod 2^32; sign applied
    // at conversion to signed? stoul returns unsigned long; negative
    // literals are negation of the parsed ul (gcc: wraps).
    Ok(if neg {
        0u32.wrapping_sub(v as u32)
    } else {
        v as u32
    })
}

/// int_vector_to_str: join with delim; empty vector prints "none".
pub fn int_vector_to_str(elems: &[u32], delim: char) -> String {
    if elems.is_empty() {
        return "none".to_string();
    }
    elems
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(&delim.to_string())
}

/// check_file_size
pub fn check_file_size(path: &str, max_file_size: u64) -> bool {
    match fs::metadata(path) {
        Ok(md) => md.len() >= max_file_size,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    // embedded UNIT_TEST Catch2 cases from utils/util.cc
    use super::*;

    #[test]
    fn uint8_to_printable_str_go_over_all_options() {
        let pattern: &[u8] = &[0, b'a', b'(', b'd', b')', 1, b'\r', 2, b'\n', b'n'];
        let print_str = uint8_to_printable_str(pattern);
        assert_eq!(print_str, "|00 |a(d)|01 0d 02 0a |n");
    }

    #[test]
    fn uint8_to_printable_str_empty_buffer() {
        let print_str = uint8_to_printable_str(&[]);
        assert_eq!(print_str, "");
    }

    #[test]
    fn uint8_to_printable_str_end_with_pipe() {
        let pattern: &[u8] = &[b'a', 0];
        let print_str = uint8_to_printable_str(pattern);
        assert_eq!(print_str, "a|00 |");
    }

    #[test]
    fn int_vector_roundtrip() {
        // str_to_int_vector/int_vector_to_str: no upstream tests; pinned per
        // C++ semantics (stoul prefix parse, "none" for empty)
        let v = str_to_int_vector("1,22,333", b',');
        assert_eq!(v, vec![1, 22, 333]);
        assert_eq!(int_vector_to_str(&v, ','), "1,22,333");
        assert_eq!(int_vector_to_str(&[], ','), "none");
        // empty items (trailing delim) -> stoul throws in C++; same here
        assert!(std::panic::catch_unwind(|| str_to_int_vector("1,", b',')).is_err());
    }

    #[test]
    fn memrchr_finds_last() {
        assert_eq!(snort_memrchr(b"abacada", b'a'), Some(6));
        assert_eq!(snort_memrchr(b"abacada", b'z'), None);
        assert_eq!(snort_memrchr(b"", b'a'), None);
    }

    #[test]
    fn ts_print_formats() {
        // 2026-11-15 12:34:56.000789 UTC epoch 1794746096
        let cfg = TimeCfg { thiszone: 0, output_use_utc: true, output_include_year: false };
        assert_eq!(
            ts_print(&cfg, 1794746096, 789),
            "2026-11-15 12:34:56.000789"
        );
        let cfg2 = TimeCfg { thiszone: 0, output_use_utc: true, output_include_year: true };
        assert_eq!(ts_print(&cfg2, 1794746096, 789), "26/11/15-12:34:56.000789");
        assert_eq!(ts_print_mmdd(&cfg, 1794746096, 789), "11/15-12:34:56.000789");
    }
}
