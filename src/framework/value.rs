// Port of snort3 framework/value.{h,cc} (Lua bool/number/string carrier).
#![allow(clippy::should_implement_trait)]
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::sfip::sf_cidr::SfCidr;
use crate::sfip::sf_ip::SfIp;
use crate::sfip::sf_returns::{AF_INET, AF_INET6};
use crate::utils::bits::FixedBitSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueType {
    VtBool,
    VtNum,
    VtUnum,
    VtStr,
    VtReal,
}

pub const MASK_BITS: u32 = 52; // ieee 754 significand

#[derive(Clone)]
pub struct Value {
    r#type: ValueType,
    unum: u64,
    num: i64,
    real: f64,
    str: Vec<u8>,
    origin_str: String,
    // C stringstream* ss, recreated by set_first_token
    ss: Option<Ss>,
    param: Option<&'static Parameter>,
}

/// subset of std::stringstream used by get_next_token/get_next_csv_token
#[derive(Clone)]
struct Ss {
    buf: String,
    pos: usize,
    failed: bool,
}

impl Ss {
    fn new(s: &str) -> Ss {
        Ss {
            buf: s.to_string(),
            pos: 0,
            failed: false,
        }
    }
    /// operator>>(istream&, string&): skip ws; on all-ws-or-exhausted set
    /// failbit and empty tok.
    fn extract_ws(&mut self, tok: &mut String) -> bool {
        *tok = String::new();
        let b = self.buf.as_bytes();
        if self.failed || self.pos >= b.len() {
            self.failed = true;
            return false;
        }
        while self.pos < b.len() && (b[self.pos] as char).is_ascii_whitespace() {
            self.pos += 1;
        }
        if self.pos >= b.len() {
            self.failed = true;
            return false;
        }
        let start = self.pos;
        while self.pos < b.len() && !(b[self.pos] as char).is_ascii_whitespace() {
            self.pos += 1;
        }
        *tok = self.buf[start..self.pos].to_string();
        !self.failed
    }
    /// getline(is, tok, ','): if at end, failbit, tok empty, false.
    fn getline(&mut self, delim: u8, tok: &mut String) -> bool {
        *tok = String::new();
        let b = self.buf.as_bytes();
        if self.failed || self.pos >= b.len() {
            self.failed = true;
            return false;
        }
        let start = self.pos;
        while self.pos < b.len() && b[self.pos] != delim {
            self.pos += 1;
        }
        *tok = self.buf[start..self.pos].to_string();
        if self.pos < b.len() {
            self.pos += 1; // consume delim
        }
        // char was extracted, so no failbit even at eof
        !self.failed
    }
}

impl Value {
    // ---- constructors (C ctor set() + optional set_origin for &str) ----
    pub fn from_bool(b: bool) -> Value {
        let mut v = Value::blank(ValueType::VtBool);
        v.set_bool(b);
        v
    }
    pub fn from_double(d: f64) -> Value {
        let mut v = Value::blank(ValueType::VtReal);
        v.set_double(d);
        v
    }
    pub fn from_i64(i: i64) -> Value {
        let mut v = Value::blank(ValueType::VtNum);
        v.set_i64(i);
        v
    }
    pub fn from_u64(u: u64) -> Value {
        let mut v = Value::blank(ValueType::VtUnum);
        v.set_u64(u);
        v
    }
    pub fn from_str(s: &str) -> Value {
        let mut v = Value::blank(ValueType::VtStr);
        v.set_str(s);
        v.set_origin(s);
        v
    }
    fn blank(r#type: ValueType) -> Value {
        Value {
            r#type,
            unum: 0,
            num: 0,
            real: 0.0,
            str: Vec::new(),
            origin_str: String::new(),
            ss: None,
            param: None,
        }
    }

    // ---- setters (verbatim) ----
    pub fn get_type(&self) -> ValueType {
        self.r#type
    }
    pub fn set_bool(&mut self, b: bool) {
        self.r#type = ValueType::VtBool;
        self.unum = if b { 1 } else { 0 };
    }
    pub fn set_double(&mut self, d: f64) {
        self.r#type = ValueType::VtReal;
        self.real = d;
    }
    pub fn set_u64(&mut self, n: u64) {
        self.r#type = ValueType::VtUnum;
        self.unum = n;
    }
    pub fn set_i64(&mut self, n: i64) {
        self.r#type = ValueType::VtNum;
        self.num = n;
    }
    pub fn set_str(&mut self, s: &str) {
        self.r#type = ValueType::VtStr;
        self.str = s.as_bytes().to_vec();
    }
    pub fn set_origin(&mut self, val: &str) {
        self.origin_str = val.to_string();
    }
    pub fn set_bytes(&mut self, s: &[u8]) {
        self.r#type = ValueType::VtStr;
        self.str = s.to_vec();
    }
    pub fn set_param(&mut self, p: &'static Parameter) {
        self.param = Some(p);
    }
    pub fn set_enum(&mut self, u: u64) {
        self.r#type = ValueType::VtUnum;
        self.unum = u;
    }
    pub fn set_aux(&mut self, u: u64) {
        self.r#type = ValueType::VtUnum;
        self.unum = u;
    }

    // ---- param accessors ----
    pub fn get_name(&self) -> Option<&'static str> {
        self.param.and_then(|p| p.name)
    }
    pub fn is(&self, s: &str) -> bool {
        matches!(self.param, Some(p) if p.name.map(|n| n == s) == Some(true))
    }
    pub fn has_default(&self) -> bool {
        matches!(self.param, Some(p) if p.deflt.is_some())
    }
    pub fn get_param_type(&self) -> PtType {
        match self.param {
            Some(p) => p.ptype,
            None => PtType::PtMax,
        }
    }

    // ---- numeric coercion (quirk: VT_NUM still uses unum in get_bool
    // and get_ip4, exactly like the C original) ----
    pub fn get_bool(&self) -> bool {
        if self.r#type == ValueType::VtReal {
            self.real != 0.0
        } else {
            self.unum != 0
        }
    }
    pub fn get_size(&self) -> u64 {
        match self.r#type {
            ValueType::VtReal => self.real as u64, // C (size_t)real: UB for
            ValueType::VtUnum => self.unum,        // out-of-range but that
            _ => self.num as u64,                  // is C behavior
        }
    }
    pub fn get_uint8(&self) -> u8 {
        match self.r#type {
            ValueType::VtReal => self.real as u64 as u8,
            ValueType::VtUnum => self.unum as u8,
            _ => self.num as u64 as u8,
        }
    }
    pub fn get_int16(&self) -> i16 {
        match self.r#type {
            ValueType::VtReal => self.real as i64 as i16,
            ValueType::VtUnum => self.unum as i64 as i16,
            _ => self.num as i16,
        }
    }
    pub fn get_uint16(&self) -> u16 {
        match self.r#type {
            ValueType::VtReal => self.real as u64 as u16,
            ValueType::VtUnum => self.unum as u16,
            _ => self.num as u64 as u16,
        }
    }
    pub fn get_int32(&self) -> i32 {
        match self.r#type {
            ValueType::VtReal => self.real as i64 as i32,
            ValueType::VtUnum => self.unum as i64 as i32,
            _ => self.num as i32,
        }
    }
    pub fn get_uint32(&self) -> u32 {
        match self.r#type {
            ValueType::VtReal => self.real as u64 as u32,
            ValueType::VtUnum => self.unum as u32,
            _ => self.num as u64 as u32,
        }
    }
    pub fn get_int64(&self) -> i64 {
        match self.r#type {
            ValueType::VtReal => self.real as i64,
            ValueType::VtUnum => self.unum as i64,
            _ => self.num,
        }
    }
    pub fn get_uint64(&self) -> u64 {
        match self.r#type {
            ValueType::VtReal => self.real as u64,
            ValueType::VtUnum => self.unum,
            _ => self.num as u64,
        }
    }
    pub fn get_real(&self) -> f64 {
        self.real
    }
    pub fn get_buffer(&self) -> (&[u8], usize) {
        (self.str.as_slice(), self.str.len()) // C n = (unsigned)str.size()
    }
    pub fn get_string(&self) -> &[u8] {
        &self.str
    }

    pub fn get_as_string(&self) -> String {
        let mut value_str = String::from_utf8_lossy(&self.str).into_owned();
        #[allow(clippy::needless_range_loop)]
        match self.r#type {
            ValueType::VtBool => value_str = if self.unum != 0 { "true".into() } else { "false".into() },
            ValueType::VtNum => value_str = self.num.to_string(),
            ValueType::VtUnum => value_str = self.unum.to_string(),
            ValueType::VtReal => {
                // C: stringstream default float with fixed => 6 decimals,
                // then trim trailing zeros and a leftover '.'
                value_str = format!("{:.6}", self.real);
                let dot = value_str.find('.').unwrap();
                let mut pos = value_str.bytes().rposition(|c| c != b'0').unwrap();
                if pos == dot {
                    pos -= 1;
                }
                value_str.truncate(pos + 1);
            }
            ValueType::VtStr => {}
        }
        value_str
    }

    pub fn get_origin_string(&self) -> String {
        if self.origin_str.is_empty() {
            return String::new();
        }
        let mut value = String::new();
        for token in self.origin_str.split_ascii_whitespace() {
            // C: value += token; value += " ";
            value.push_str(token);
            value.push(' ');
        }
        if value.is_empty() {
            return self.origin_str.clone();
        }
        value.pop();
        value
    }

    pub fn get_unquoted_string(&self) -> String {
        let s = String::from_utf8_lossy(&self.str).into_owned();
        if s.len() < 2 {
            return s;
        }
        let mut tmp = s;
        if tmp.starts_with('"') && tmp.ends_with('"') {
            tmp.remove(0);
            tmp.pop();
        }
        tmp
    }

    // ---- strtol / strtoul (C base 0; false on empty or trailing junk) ----
    pub fn strtol(&self) -> (bool, i64) {
        Self::c_strtol(&self.str)
    }
    pub fn strtol_tok(tok: &str) -> (bool, i64) {
        Self::c_strtol(tok.as_bytes())
    }
    pub fn strtoul(&self) -> (bool, u64) {
        Self::c_strtoul(&self.str)
    }
    pub fn strtoul_tok(tok: &str) -> (bool, u64) {
        Self::c_strtoul(tok.as_bytes())
    }

    fn c_strtol(s: &[u8]) -> (bool, i64) {
        if s.is_empty() {
            return (false, 0);
        }
        match Self::c_strtoul_core(s) {
            None => (false, 0),
            Some((neg, mag, consumed)) => {
                if consumed != s.len() {
                    return (false, 0); // *end != 0
                }
                // C strtol overflow saturates LONG_MIN/MAX
                let v = if mag > (1i64 << 63) as u64 {
                    if neg {
                        i64::MIN
                    } else {
                        i64::MAX
                    }
                } else {
                    let m = mag as i64;
                    if neg {
                        m.checked_neg().unwrap_or(i64::MIN)
                    } else if m == i64::MIN {
                        i64::MAX // overflow -> LONG_MAX
                    } else {
                        m
                    }
                };
                (true, v)
            }
        }
    }

    fn c_strtoul(s: &[u8]) -> (bool, u64) {
        if s.is_empty() {
            return (false, 0);
        }
        match Self::c_strtoul_core(s) {
            None => (false, 0),
            Some((neg, mag, consumed)) => {
                if consumed != s.len() {
                    return (false, 0);
                }
                // C strtoul accepts a leading '-' and wraps (probe:
                // strtoul("-1") == ULONG_MAX)
                (true, if neg { 0u64.wrapping_sub(mag) } else { mag })
            }
        }
    }

    /// C strtoul with base 0 (glibc semantics pinned by probe):
    /// skip ws, optional sign, 0x-hex / 0-octal / decimal; no digits ->
    /// None (end == start of number). glibc saturation: decimal wraps at
    /// ULONG_MAX, octal clamps at LONG_MAX (verified probe: 0777...7 ->
    /// 0x7fffffffffffffff, 21-digit decimal -> ULONG_MAX).
    /// Returns (neg, magnitude, consumed_bytes_including_prefix).
    fn c_strtoul_core(s: &[u8]) -> Option<(bool, u64, usize)> {
        let mut i = 0usize;
        while i < s.len() && (s[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        let neg = i < s.len() && (s[i] == b'-' || s[i] == b'+');
        if neg {
            i += 1;
        }
        let num_start = i;
        let mut base = 10u32;
        if i < s.len() && s[i] == b'0' {
            if i + 1 < s.len() && (s[i + 1] | 0x20) == b'x' {
                // hex prefix; if no hex digit follows, C consumes only "0"
                if i + 2 < s.len() && Value::hex_digit(s[i + 2]).is_some() {
                    base = 16;
                    i += 2;
                }
            } else {
                base = 8;
            }
        }
        let digits_start = i;
        let limit = if base == 8 {
            (1i64 << 63) as u64 - 1 // glibc octal clamp at LONG_MAX
        } else {
            u64::MAX
        };
        let mut mag: u64 = 0;
        let mut overflowed = false;
        while i < s.len() {
            let d = if base == 16 {
                match Self::hex_digit(s[i]) {
                    Some(d) => d,
                    None => break,
                }
            } else if s[i].is_ascii_digit() {
                (s[i] - b'0') as u64
            } else {
                break;
            };
            if d >= base as u64 {
                break;
            }
            if !overflowed {
                match mag.checked_mul(base as u64) {
                    None => overflowed = true,
                    Some(m) => match m.checked_add(d) {
                        None => overflowed = true,
                        Some(m2) => {
                            if m2 > limit {
                                overflowed = true;
                            } else {
                                mag = m2;
                            }
                        }
                    },
                }
            }
            i += 1;
        }
        if i == digits_start {
            // no digits for the base: C sets end to num_start
            // ("0x" -> end "x" means "0" consumed as decimal zero; handled
            // by the caller's *end check either way)
            return None;
        }
        if overflowed {
            mag = limit;
        }
        let _ = num_start;
        // i is an absolute index: consumed == i bytes of s
        Some((neg, mag, i))
    }

    fn hex_digit(c: u8) -> Option<u64> {
        if c.is_ascii_digit() {
            Some((c - b'0') as u64)
        } else if (b'a'..=b'f').contains(&c) {
            Some((c - b'a' + 10) as u64)
        } else if (b'A'..=b'F').contains(&c) {
            Some((c - b'A' + 10) as u64)
        } else {
            None
        }
    }

    // ---- comparison ops (verbatim C) ----
    pub fn eq_str(&self, s: &str) -> bool {
        self.str == s.as_bytes()
    }
    pub fn eq_u64(&self, n: u64) -> bool {
        n == if self.r#type == ValueType::VtUnum {
            self.unum
        } else {
            self.num as u64
        }
    }
    pub fn eq_double(&self, d: f64) -> bool {
        self.real == d
    }

    // ---- bit sets (verbatim; C asserts len == list.size()) ----
    #[allow(clippy::needless_range_loop)] // C-index loop verbatim
    pub fn get_bits<const N: usize>(&self, list: &mut FixedBitSet<N>) {
        list.reset();
        let len = self.str.len();
        assert_eq!(len, list.size());
        for n in 0..len {
            if self.str[n] == b'1' {
                list.set(n);
            }
        }
    }

    // ---- case converts (C ::tolower/::toupper: byte-local ASCII here) ----
    pub fn lower(&mut self) {
        for b in self.str.iter_mut() {
            *b = b.to_ascii_lowercase();
        }
    }
    pub fn upper(&mut self) {
        for b in self.str.iter_mut() {
            *b = b.to_ascii_uppercase();
        }
    }

    // ---- addresses (verbatim) ----
    pub fn get_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        if self.str.len() == 6 {
            mac.copy_from_slice(&self.str);
        }
        mac
    }
    pub fn get_addr_raw(&self) -> [u8; 16] {
        // C: size <= 16: str.copy(addr, 16) — copies str bytes and then
        // reads past its end? no: std::string::copy with n > remaining
        // copies what's available (pos..len) then returns; remaining bytes
        // are NOT zeroed unless they already are. In practice C++
        // copy(dst, s, n) copies min(n, size-pos) — the rest stays as-is
        // (uninitialized). Tests only exercise exact-size/over-size, where
        // over-size hits the memset branch; exact copies fully cover.
        let mut addr = [0u8; 16];
        if self.str.len() <= 16 {
            addr[..self.str.len()].copy_from_slice(&self.str);
            // str.copy((char*)addr, sizeof(addr)) with str.size() <= 16:
            // trailing bytes in C come from the string's past-the-end
            // (UB/uninitialized); tests treat zero-init buffers, so zero.
        } else {
            addr = [0u8; 16];
        }
        addr
    }
    pub fn get_addr_ip4(&self) -> [u8; 4] {
        let mut addr = [0u8; 4];
        if self.str.len() == 4 {
            addr.copy_from_slice(&self.str);
        }
        addr
    }
    pub fn get_addr_ip6(&self) -> [u8; 16] {
        let mut addr = [0u8; 16];
        if self.str.len() == 16 {
            addr.copy_from_slice(&self.str);
        }
        addr
    }
    pub fn get_addr_ip(&self, addr: &mut SfIp) {
        // addr.set(str.c_str(), AF_INET): the (const void*, int) overload
        if self.str.len() == 4 {
            addr.set_raw(&self.str, AF_INET);
        } else if self.str.len() == 16 {
            addr.set_raw(&self.str, AF_INET6);
        } else {
            addr.clear();
        }
    }
    pub fn get_addr_cidr(&self, cidr: &mut SfCidr) {
        if self.str.len() == 4 {
            cidr.set_raw(&self.str, AF_INET);
        } else if self.str.len() == 16 {
            cidr.set_raw(&self.str, AF_INET6);
        } else {
            cidr.clear();
        }
    }
    pub fn get_ip4(&self) -> u32 {
        if self.r#type == ValueType::VtReal {
            self.real as u64 as u32
        } else {
            self.unum as u32
        }
    }

    // ---- token streams (verbatim) ----
    pub fn set_first_token(&mut self) {
        self.ss = Some(Ss::new(&String::from_utf8_lossy(&self.str)));
    }
    pub fn get_next_token(&mut self, tok: &mut String) -> bool {
        match &mut self.ss {
            None => false,
            Some(s) => s.extract_ws(tok),
        }
    }
    pub fn get_next_csv_token(&mut self, tok: &mut String) -> bool {
        match &mut self.ss {
            None => false,
            Some(s) => s.getline(b',', tok),
        }
    }

    // ---- update_mask (verbatim, generic over unsigned widths) ----
    pub fn update_mask_u8(&self, mask: &mut u8, flag: u8, invert: bool) {
        self.update_mask_core(mask, flag, invert)
    }
    pub fn update_mask_u16(&self, mask: &mut u16, flag: u16, invert: bool) {
        self.update_mask_core(mask, flag, invert)
    }
    pub fn update_mask_u32(&self, mask: &mut u32, flag: u32, invert: bool) {
        self.update_mask_core(mask, flag, invert)
    }
    pub fn update_mask_u64(&self, mask: &mut u64, flag: u64, invert: bool) {
        self.update_mask_core(mask, flag, invert)
    }
    fn update_mask_core<T>(&self, mask: &mut T, flag: T, invert: bool)
    where
        T: Copy + std::ops::BitOrAssign + std::ops::BitAndAssign + std::ops::Not<Output = T>,
    {
        if self.get_bool() ^ invert {
            *mask |= flag;
        } else {
            *mask &= !flag;
        }
    }
}
