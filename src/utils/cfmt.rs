// Minimal C-printf engine standing in for glibc vsnprintf/printf for the
// log layer port (zero external deps). Covers the conversion set used by
// snort3's log/messages.cc, ConfigLogger, Dumper and log_text call sites:
//   conv: d i u o x X c s f e g p %
//   flags: - + ' ' 0 #
//   width/precision: digits or '*' (pulled from the next arg, like varargs)
//   length mods consumed (hh h l ll z j t L); integer masking applied for
//     hh -> i8/u8, h -> i16/u16 (matching the probe's promotion contract)
// glibc behaviors pinned by tools/log_harness vectors:
//   * null %s prints "(null)"
//   * negative width == '-' flag; negative precision == no precision
//   * '0' flag suppressed when '-' present or precision present (%d/%u/...)
//   * "%*.0s" with width W prints W spaces (precision empties the text,
//     width still pads) — this is how ConfigLogger::log_list indents
//     continuation lines
//   * %g: precision 0 means 1 sig digit; fixed iff -4 <= expX < P; then
//     strip trailing zeros unless '#'
//   * %e/%g exponent: at least 2 digits with sign
//   * inf/nan: "inf"/"-inf"/"nan" for f/e/g
//   * octal '#': leading '0' only when value != 0 and not prec-0-empty...
//     (glibc: '#' forces leading 0 for octal even for value 0)

use std::borrow::Cow;

#[derive(Clone, Debug)]
pub enum Arg<'a> {
    S(Option<Cow<'a, str>>),
    I(i64),
    U(u64),
    F(f64),
}

fn got_int(a: &Arg<'_>) -> i64 {
    match a {
        Arg::I(v) => *v,
        Arg::U(v) => *v as i64,
        Arg::S(_) | Arg::F(_) => 0,
    }
}
fn got_uint(a: &Arg<'_>) -> u64 {
    match a {
        Arg::U(v) => *v,
        Arg::I(v) => *v as u64,
        Arg::S(_) | Arg::F(_) => 0,
    }
}
fn got_float(a: &Arg<'_>) -> f64 {
    match a {
        Arg::F(v) => *v,
        _ => 0.0,
    }
}


fn mask_i(v: i64, lm: [u8; 2]) -> i64 {
    if lm[0] == b'h' && lm[1] == b'h' {
        ((v as u8) as i8) as i64
    } else if lm[0] == b'h' {
        ((v as u16) as i16) as i64
    } else if lm[0] == 0 {
        // bare %d reads an int slot: the low 32 bits sign-extended
        ((v as u32) as i32) as i64
    } else {
        v // l/ll/z/j/t: the full 64-bit slot
    }
}

fn mask_u(v: u64, lm: [u8; 2]) -> u64 {
    if lm[0] == b'h' && lm[1] == b'h' {
        (v as u8) as u64
    } else if lm[0] == b'h' {
        (v as u16) as u64
    } else if lm[0] == 0 {
        // bare %u reads an unsigned-int slot
        (v as u32) as u64
    } else {
        v
    }
}

fn c_exp(e: i32) -> String {
    format!("e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs())
}

fn strip_z(s: String) -> String {
    let mut t = s;
    if t.contains('.') {
        while t.ends_with('0') {
            t.pop();
        }
        if t.ends_with('.') {
            t.pop();
        }
    }
    t
}

fn fmt_f(v: f64, prec: usize) -> String {
    if !v.is_finite() {
        return inf_name(v);
    }
    format!("{:.*}", prec, v.abs())
}

fn fmt_e(v: f64, prec: usize) -> String {
    if !v.is_finite() {
        return inf_name(v);
    }
    let a = v.abs();
    let core = format!("{:.*e}", prec, a);
    let (m, e) = core.split_once('e').unwrap();
    let m = if prec == 0 { m.replace('.', "") } else { m.to_string() };
    let e: i32 = e.parse().unwrap();
    format!("{m}{}", c_exp(e))
}

fn fmt_g(v: f64, prec: Option<i64>, alt: bool) -> String {
    if !v.is_finite() {
        return inf_name(v);
    }
    let p = match prec {
        None => 6,
        Some(0) => 1,
        Some(n) => n as usize,
    };
    if v == 0.0 {
        let s = format!("{:.*}", p.saturating_sub(1), 0.0);
        let t = strip_z(s);
        return if alt && !t.contains('.') { format!("{t}.") } else { t };
    }
    // C99: round to P significant digits; style-E exponent e. e-style iff
    // e < -4 || e >= P; else fixed with P-1-e decimals. Trailing zeros
    // only survive with '#'. (e is the style-E exponent — NOT 0.ddd*10^X.)
    let rounded = format!("{:.*e}", p - 1, v.abs());
    let (m, ex) = rounded.split_once('e').unwrap();
    let e: i32 = ex.parse().unwrap();
    if e < -4 || e >= p as i32 {
        // style-E mantissa is already d.dddd; strip zeros within it
        let mant = if alt { m.to_string() } else { strip_z(m.to_string()) };
        let mant = if mant.is_empty() { "0".to_string() } else { mant };
        format!("{mant}{}", c_exp(e))
    } else {
        let dec = (p as i64 - 1 - e as i64).max(0) as usize;
        let s = format!("{:.*}", dec, v.abs());
        let t = strip_z(s);
        if alt && !t.contains('.') { format!("{t}.") } else { t }
    }
}

fn inf_name(v: f64) -> String {
    // sign comes from the caller's `neg` (sign_negative && !nan), which
    // matches glibc: -inf prints "-inf", -nan prints "nan" (vector q:nan)
    if v.is_nan() { "nan".to_string() } else { "inf".to_string() }
}

/// Format `fmt` with `args`; returns the full converted string (no
/// vsnprintf truncation — callers that need STD_BUF semantics clip in the
/// Port layer exactly as the C does).
pub fn cfmt(fmt: &str, args: &[Arg]) -> String {
    let f = fmt.as_bytes();
    let mut ai = 0usize;
    const ZERO: Arg<'static> = Arg::I(0);
    let take = |ai: &mut usize| -> &Arg<'_> {
        let a: &Arg<'_> = args.get(*ai).unwrap_or(&ZERO);
        *ai += 1;
        a
    };
    let mut out = String::new();
    let mut i = 0usize;
    while i < f.len() {
        if f[i] != b'%' {
            out.push(f[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i < f.len() && f[i] == b'%' {
            out.push('%');
            i += 1;
            continue;
        }
        let (mut left, mut plus, mut space, mut zero, mut alt) =
            (false, false, false, false, false);
        while i < f.len() && matches!(f[i], b'-' | b'+' | b' ' | b'0' | b'#') {
            match f[i] {
                b'-' => left = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'0' => zero = true,
                b'#' => alt = true,
                _ => {}
            }
            i += 1;
        }
        let mut width: i64 = 0;
        if i < f.len() && f[i] == b'*' {
            width = got_int(take(&mut ai));
            i += 1;
        } else {
            let st = i;
            while i < f.len() && f[i].is_ascii_digit() {
                i += 1;
            }
            if i > st {
                width = fmt[st..i].parse().unwrap();
            }
        }
        if width < 0 {
            left = true;
            width = -width;
        }
        let mut prec: Option<i64> = None;
        if i < f.len() && f[i] == b'.' {
            i += 1;
            let mut p: i64 = 0;
            if i < f.len() && f[i] == b'*' {
                p = got_int(take(&mut ai));
                i += 1;
            } else {
                let st = i;
                while i < f.len() && f[i].is_ascii_digit() {
                    i += 1;
                }
                if i > st {
                    p = fmt[st..i].parse().unwrap();
                }
            }
            prec = if p < 0 { None } else { Some(p) };
        }
        let mut lm = [0u8; 2];
        let mut lmi = 0usize;
        while i < f.len() && matches!(f[i], b'h' | b'l' | b'z' | b'j' | b't' | b'L') {
            if lmi < 2 {
                lm[lmi] = f[i];
                lmi += 1;
            }
            i += 1;
        }
        let conv = *f.get(i).unwrap_or(&b'?');
        i += 1;

        let body = match conv {
            b'd' | b'i' => {
                let v = mask_i(got_int(take(&mut ai)), lm);
                let neg = v < 0;
                let mut ds = v.unsigned_abs().to_string();
                if let Some(p) = prec {
                    zero = false;
                    ds = format!("{ds:0>p$}", p = p as usize);
                }
                let sign = if neg {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                pad_body(sign, ds, width, left, zero)
            }
            b'u' | b'x' | b'X' | b'o' => {
                let v = mask_u(got_uint(take(&mut ai)), lm);
                let mut ds = match conv {
                    b'u' => format!("{v}"),
                    b'x' => format!("{v:x}"),
                    b'X' => format!("{v:X}"),
                    _ => format!("{v:o}"),
                };
                if let Some(p) = prec {
                    zero = false;
                    let empty = p == 0;
                    ds = if empty { String::new() } else { format!("{ds:0>p$}", p = p as usize) };
                }
                // '#' prefixes hex (when nonzero); glibc octal '#' forces a
                // leading zero only if digits don't already start with one
                let prefix = if alt {
                    match conv {
                        b'x' if v != 0 => "0x",
                        b'X' if v != 0 => "0X",
                        b'o' if !ds.is_empty() && !ds.starts_with('0') => "0",
                        _ => "",
                    }
                } else {
                    ""
                };
                pad_body2(prefix, ds, width, left, zero, plus || space)
            }
            b'c' => {
                let c = got_uint(take(&mut ai)) as u32 & 0xff;
                let s = char::from_u32(c).map(|ch| ch.to_string()).unwrap_or_default();
                pad_body2("", s, width, left, false, false)
            }
            b's' => {
                let raw: Option<&str> = match take(&mut ai) {
                    Arg::S(c) => c.as_ref().map(|c| &**c),
                    _ => None,
                };
                let raw = raw.unwrap_or("(null)");
                let s: String = match prec {
                    Some(p) => raw.chars().take(p as usize).collect(),
                    None => raw.to_string(),
                };
                pad_body2("", s, width, left, false, false)
            }
            b'f' | b'e' | b'E' | b'g' | b'G' => {
                let v = got_float(take(&mut ai));
                let p = prec.unwrap_or(6) as usize;
                let core = match conv {
                    b'f' => fmt_f(v, p),
                    b'e' => fmt_e(v, p),
                    b'E' => fmt_e(v, p).replace('e', "E"),
                    b'g' => fmt_g(v, prec, alt),
                    _ /* G */ => fmt_g(v, prec, alt).replace('e', "E"),
                };
                let (inf, neg) = (!v.is_finite(), v.is_sign_negative() && !v.is_nan());
                if inf {
                    let sign = if neg {
                        "-"
                    } else if plus {
                        "+"
                    } else if space {
                        " "
                    } else {
                        ""
                    };
                    pad_body(sign, core, width, left, false)
                } else {
                    let sign = if neg {
                        "-"
                    } else if plus {
                        "+"
                    } else if space {
                        " "
                    } else {
                        ""
                    };
                    // unlike %d, the '0' flag is NOT suppressed by
                    // precision for %f/%e/%g (vector zerof:0001.500)
                    pad_body(sign, core, width, left, zero)
                }
            }
            b'p' => {
                let v = got_uint(take(&mut ai));
                let core = if v == 0 { "(nil)".to_string() } else { format!("{v:#x}") };
                pad_body2("", core, width, left, false, false)
            }
            other => format!("%{}", other as char),
        };
        out.push_str(&body);
    }
    out
}

// %d-family padding: sign goes before zero-padding
fn pad_body(sign: &str, ds: String, width: i64, left: bool, zero: bool) -> String {
    let w = (width as usize).saturating_sub(sign.len() + ds.len());
    if left {
        format!("{sign}{ds}{}", " ".repeat(w))
    } else if zero {
        format!("{sign}{}{ds}", "0".repeat(w))
    } else {
        format!("{}{sign}{ds}", " ".repeat(w))
    }
}

// %s/%u-family: prefix glued to text before padding
fn pad_body2(prefix: &str, ds: String, width: i64, left: bool, zero: bool, _signed: bool) -> String {
    let head = format!("{prefix}{ds}");
    let w = (width as usize).saturating_sub(head.len());
    if left {
        format!("{head}{}", " ".repeat(w))
    } else if zero && prefix.is_empty() {
        format!("{}{head}", "0".repeat(w))
    } else {
        format!("{}{head}", " ".repeat(w))
    }
}
