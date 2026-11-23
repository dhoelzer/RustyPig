// Port of snort3 src/sfip/sf_ip.{h,cc} — the v4/v6 address type.
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//           Copyright (C) 1998-2013 Sourcefire, Inc.
//
// Layout note: the C++ version stores a 16-byte union + packed int16 family.
// We store the same 16 raw bytes (network byte order, big-endian semantics for
// IPv6; IPv4 lives in the last 4 bytes with ::ffff: prefix, exactly like the
// original on Linux/glibc) and an i16 family. Raw-u32 comparisons that the
// original performs on little-endian hosts are replicated with from_le_bytes
// views so fast_lt6/gt6 ordering semantics match the x86 original bit-for-bit.

// Index-carrying loops mirror the C original's pointer walks verbatim.
#![allow(clippy::needless_range_loop)]
use super::sf_returns::*;

pub const INET6_ADDRSTRLEN: usize = 46;
pub const INET_ADDRSTRLEN: usize = 16;
pub const MAX_INET6_STRLEN_NO_IPV4_MAP: usize = 40;

/// glibc-compatible inet_pton, AF_INET (strict: no leading zeros) and AF_INET6
/// (one '::', optional trailing dotted quad). Writes network-order bytes.
pub fn inet_pton(fam: i16, ip: &str, dst: &mut [u8]) -> i32 {
    match fam {
        AF_INET => {
            if dst.len() < 4 {
                return -1;
            }
            let b = ip.as_bytes();
            let mut i = 0usize;
            let mut out = [0u8; 4];
            for o in 0..4 {
                if o > 0 {
                    if i >= b.len() || b[i] != b'.' {
                        return 0;
                    }
                    i += 1;
                }
                let start = i;
                let mut val: u32 = 0;
                while i < b.len() && b[i].is_ascii_digit() {
                    if i - start >= 3 {
                        return 0; // octet longer than 3 digits
                    }
                    if i == start && b[i] == b'0' && i + 1 < b.len() && b[i + 1].is_ascii_digit()
                    {
                        return 0; // leading zero (glibc rejects)
                    }
                    val = val * 10 + (b[i] - b'0') as u32;
                    i += 1;
                }
                if i == start || val > 255 {
                    return 0;
                }
                out[o] = val as u8;
            }
            if i != b.len() {
                return 0; // trailing garbage
            }
            dst[..4].copy_from_slice(&out);
            1
        }
        AF_INET6 => {
            if dst.len() < 16 {
                return -1;
            }
            for x in dst[..16].iter_mut() {
                *x = 0;
            }
            let b = ip.as_bytes();
            let mut words = [0u16; 8];
            let mut n = 0usize;
            let mut compress_at = usize::MAX; // where '::' expands
            let mut i = 0usize;

            if i < b.len() && b[i] == b':' {
                if i + 1 >= b.len() || b[i + 1] != b':' {
                    return 0;
                }
                i += 2;
                compress_at = 0;
            }
            while i < b.len() {
                if n >= 8 {
                    return 0;
                }
                if b[i] == b':' {
                    if compress_at != usize::MAX {
                        return 0; // second '::'
                    }
                    i += 1;
                    if i < b.len() && b[i] == b':' {
                        return 0; // ':::'
                    }
                    compress_at = n;
                    continue;
                }
                // group: 1-4 hex, or trailing dotted quad
                let start = i;
                let mut val: u32 = 0;
                let mut digits = 0;
                while i < b.len() && b[i].is_ascii_hexdigit() {
                    if digits == 4 {
                        return 0;
                    }
                    val = val * 16 + (b[i] as char).to_digit(16).unwrap();
                    digits += 1;
                    i += 1;
                }
                if digits == 0 {
                    return 0;
                }
                // dotted quad tail?
                if i < b.len() && b[i] == b'.' {
                    if n > 6 {
                        return 0;
                    }
                    // rewind the first decimal group and parse full v4 tail
                    let quad = &b[start..];
                    let mut qb = [0u8; 4];
                    let mut qi = 0usize;
                    let mut ok = true;
                    for qo in 0..4 {
                        if qo > 0 {
                            if qi >= quad.len() || quad[qi] != b'.' {
                                ok = false;
                                break;
                            }
                            qi += 1;
                        }
                        let qs = qi;
                        let mut qv: u32 = 0;
                        while qi < quad.len() && quad[qi].is_ascii_digit() {
                            if qi - qs >= 3 {
                                ok = false;
                                break;
                            }
                            if qi == qs && quad[qi] == b'0' && qi + 1 < quad.len()
                                && quad[qi + 1].is_ascii_digit()
                            {
                                ok = false;
                                break;
                            }
                            qv = qv * 10 + (quad[qi] - b'0') as u32;
                            qi += 1;
                        }
                        if qi == qs || qv > 255 {
                            ok = false;
                            break;
                        }
                        qb[qo] = qv as u8;
                    }
                    if !ok || qi != quad.len() {
                        return 0;
                    }
                    words[n] = ((qb[0] as u16) << 8) | qb[1] as u16;
                    words[n + 1] = ((qb[2] as u16) << 8) | qb[3] as u16;
                    n += 2;
                    break;
                }
                if b.get(i) == Some(&b':') {
                    // group followed by colon: normal
                } else if i != b.len() {
                    return 0; // bad char after group
                }
                words[n] = val as u16;
                n += 1;
                if i < b.len() {
                    if b[i] != b':' {
                        return 0;
                    }
                    i += 1;
                    if i == b.len() {
                        return 0; // trailing single ':'
                    }
                }
            }
            let final_n = if compress_at != usize::MAX {
                if n > 7 {
                    return 0;
                }
                let mut out = [0u16; 8];
                let tail = n - compress_at;
                out[..compress_at].copy_from_slice(&words[..compress_at]);
                out[8 - tail..].copy_from_slice(&words[compress_at..n]);
                out
            } else {
                if n != 8 {
                    return 0;
                }
                words
            };
            for k in 0..8 {
                dst[2 * k] = (final_n[k] >> 8) as u8;
                dst[2 * k + 1] = (final_n[k] & 0xff) as u8;
            }
            1
        }
        _ => -1,
    }
}

/// snort_inet_ntop (sf_ip.cc), both test_features modes:
///
/// false: standard (glibc-style) formatting; true: "%04x" full expansion,
/// no compression. IPv6 always needs bufsize >= INET6_ADDRSTRLEN,
/// IPv4 >= INET_ADDRSTRLEN.
pub fn snort_inet_ntop_raw(fam: i16, ip_raw: &[u8], test_features: bool) -> Option<String> {
    if fam == AF_INET {
        if ip_raw.len() < 4 {
            return None;
        }
        Some(format!("{}.{}.{}.{}", ip_raw[0], ip_raw[1], ip_raw[2], ip_raw[3]))
    } else if fam == AF_INET6 {
        if ip_raw.len() < 16 {
            return None;
        }
        if test_features {
            let mut parts = Vec::with_capacity(8);
            for p in 0..8 {
                parts.push(format!(
                    "{:04x}",
                    ((ip_raw[2 * p] as u16) << 8) | ip_raw[2 * p + 1] as u16
                ));
            }
            return Some(parts.join(":"));
        }
        // glibc: lowercase, compress the longest run of >=2 zero words
        let mut ws = [0u16; 8];
        for p in 0..8 {
            ws[p] = ((ip_raw[2 * p] as u16) << 8) | ip_raw[2 * p + 1] as u16;
        }
        let (mut best_s, mut best_l, mut cs, mut cl) = (usize::MAX, 0usize, usize::MAX, 0usize);
        for p in 0..8 {
            if ws[p] == 0 {
                if cs == usize::MAX {
                    cs = p;
                    cl = 1;
                } else {
                    cl += 1;
                }
            } else {
                if cl > best_l {
                    best_s = cs;
                    best_l = cl;
                }
                cs = usize::MAX;
                cl = 0;
            }
        }
        if cl > best_l {
            best_s = cs;
            best_l = cl;
        }
        if best_l < 2 {
            best_s = usize::MAX;
        }
        let mut s = String::new();
        let mut p = 0usize;
        while p < 8 {
            if p == best_s {
                // row 22b alignment rider: the collapsed run emits "::" at
                // its position EXACTLY like inet_ntop (leading `::`, mid
                // `2001:db8::cafe`, trailing `fe80::`); the pre-rider face
                // emitted a single ':' for non-leading runs (glibc-drift —
                // ZERO landed caller exercises this arm: every prior ntop
                // face rides ntop(true); the trace row's v6 ntuple strings
                // require the C byte face).
                s.push_str("::");
                p += best_l;
                if p == 8 {
                    break;
                }
            } else {
                if !s.is_empty() && !s.ends_with(':') {
                    s.push(':');
                }
                s.push_str(&format!("{:x}", ws[p]));
                p += 1;
            }
        }
        Some(s)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SfIp {
    /// 16 bytes, network order (IPv4 in the last 4, with ::ffff: v4-mapped prefix)
    pub ip8: [u8; 16],
    pub family: i16,
}

impl Default for SfIp {
    fn default() -> Self {
        Self::new()
    }
}

impl SfIp {
    pub fn new() -> Self {
        SfIp { ip8: [0; 16], family: AF_UNSPEC }
    }

    pub fn clear(&mut self) {
        self.family = AF_UNSPEC;
        self.ip8 = [0; 16];
    }

    // ---- raw views, mirroring the C union (LE-host words as on x86) ----
    #[inline]
    fn ip32_raw(&self, k: usize) -> u32 {
        u32::from_le_bytes([self.ip8[4 * k], self.ip8[4 * k + 1], self.ip8[4 * k + 2], self.ip8[4 * k + 3]])
    }
    #[inline]
    fn set_ip32_raw(&mut self, k: usize, v: u32) {
        self.ip8[4 * k..4 * k + 4].copy_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn ip16_raw(&self, k: usize) -> u16 {
        u16::from_le_bytes([self.ip8[2 * k], self.ip8[2 * k + 1]])
    }
    #[inline]
    fn set_ip16_raw(&mut self, k: usize, v: u16) {
        self.ip8[2 * k..2 * k + 2].copy_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn ip64_raw(&self, k: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.ip8[8 * k..8 * k + 8]);
        u64::from_le_bytes(b)
    }
    /// network-order numeric value of word k (== C ntohl(ip32[k]) on LE hosts)
    #[inline]
    fn net32(&self, k: usize) -> u32 {
        u32::from_be_bytes([self.ip8[4 * k], self.ip8[4 * k + 1], self.ip8[4 * k + 2], self.ip8[4 * k + 3]])
    }
    #[inline]
    fn set_net32(&mut self, k: usize, v: u32) {
        self.ip8[4 * k..4 * k + 4].copy_from_slice(&v.to_be_bytes());
    }

    // ---- accessors ----
    pub fn get_family(&self) -> u16 {
        self.family as u16
    }
    pub fn get_ip4_value(&self) -> u32 {
        self.ip32_raw(3)
    }
    pub fn is_set(&self) -> bool {
        (self.family == AF_INET && self.ip32_raw(3) != 0)
            || (self.family == AF_INET6
                && (self.ip32_raw(0) != 0
                    || self.ip32_raw(1) != 0
                    || self.ip32_raw(3) != 0
                    || self.ip16_raw(4) != 0
                    || (self.ip16_raw(5) != 0 && self.ip16_raw(5) != 0xffff)))
    }
    pub fn is_ip6(&self) -> bool {
        self.family == AF_INET6
    }
    pub fn is_ip4(&self) -> bool {
        self.family == AF_INET
    }

    pub fn is_loopback(&self) -> bool {
        if self.ip32_raw(0) != 0 || self.ip32_raw(1) != 0 || self.ip16_raw(4) != 0 {
            return false;
        }
        if self.ip16_raw(5) == 0xffff {
            return self.ip8[12] == 0x7f;
        }
        if self.ip16_raw(5) == 0 {
            return self.net32(3) == 1 || self.ip8[12] == 0x7f;
        }
        false
    }

    pub fn is_private(&self) -> bool {
        if self.ip32_raw(0) != 0 || self.ip32_raw(1) != 0 || self.ip16_raw(4) != 0 {
            return false;
        }
        if self.ip16_raw(5) == 0xffff {
            return (self.ip8[12] == 10)
                || ((self.ip8[12] == 172) && ((self.ip8[13] & 0xf0) == 16))
                || ((self.ip8[12] == 192) && (self.ip8[13] == 168));
        }
        if self.ip16_raw(5) == 0 {
            return (self.ip8[12] == 10)
                || ((self.ip8[12] == 172) && ((self.ip8[13] & 0xf0) == 16))
                || ((self.ip8[12] == 192) && (self.ip8[13] == 168))
                || (self.net32(3) == 1);
        }
        false
    }

    pub fn is_mapped(&self) -> bool {
        !(self.ip32_raw(0) != 0
            || self.ip32_raw(1) != 0
            || self.ip16_raw(4) != 0
            || (self.ip16_raw(5) != 0xffff && self.ip16_raw(5) != 0))
    }

    // ---- comparisons ----
    fn _is_equals(&self, rhs: &SfIp) -> bool {
        if self.is_ip4() {
            rhs.is_ip4() && self.ip32_raw(3) == rhs.ip32_raw(3)
        } else if self.is_ip6() {
            (0..4).all(|k| self.ip32_raw(k) == rhs.ip32_raw(k))
        } else {
            false
        }
    }

    fn _is_lesser(&self, rhs: &SfIp) -> bool {
        if self.is_ip4() && rhs.is_ip4() {
            return self.net32(3) < rhs.net32(3);
        }
        for k in 0..4 {
            let (a, b) = (self.net32(k), rhs.net32(k));
            if a != b {
                return a < b;
            }
        }
        false
    }

    pub fn equals(&self, rhs: &SfIp, match_unset: bool) -> bool {
        if !self.is_set() || !rhs.is_set() {
            return match_unset;
        }
        self._is_equals(rhs)
    }

    pub fn less_than(&self, rhs: &SfIp) -> bool {
        if !self.is_set() || !rhs.is_set() {
            return false;
        }
        self._is_lesser(rhs)
    }

    pub fn greater_than(&self, rhs: &SfIp) -> bool {
        if !self.is_set() || !rhs.is_set() {
            return false;
        }
        rhs._is_lesser(self)
    }

    fn _ip4_cmp(ip1: u32, ip2: u32) -> SfIpRet {
        let hip1 = ip1.swap_bytes(); // C htonl on LE host
        let hip2 = ip2.swap_bytes();
        if hip1 < hip2 {
            SfIpRet::Lesser
        } else if hip1 > hip2 {
            SfIpRet::Greater
        } else {
            SfIpRet::Equal
        }
    }

    fn _ip6_cmp(&self, ip2: &SfIp) -> SfIpRet {
        for k in 0..4 {
            let ret = Self::_ip4_cmp(self.ip32_raw(k), ip2.ip32_raw(k));
            if ret != SfIpRet::Equal {
                return ret;
            }
        }
        SfIpRet::Equal
    }

    pub fn compare(&self, ip2: &SfIp, match_unset: bool) -> SfIpRet {
        if !self.is_set() || !ip2.is_set() {
            return if match_unset { SfIpRet::Equal } else { SfIpRet::Failure };
        }
        if self.is_ip4() && ip2.is_ip4() {
            return Self::_ip4_cmp(self.get_ip4_value(), ip2.get_ip4_value());
        }
        self._ip6_cmp(ip2)
    }

    pub fn fast_eq4(&self, ip2: &SfIp) -> bool {
        self.get_ip4_value() == ip2.get_ip4_value()
    }

    pub fn fast_lt6(&self, ip2: &SfIp) -> bool {
        for k in 0..4 {
            if self.ip32_raw(k) < ip2.ip32_raw(k) {
                return true;
            } else if self.ip32_raw(k) > ip2.ip32_raw(k) {
                return false;
            }
        }
        false
    }

    pub fn fast_gt6(&self, ip2: &SfIp) -> bool {
        for k in 0..4 {
            if self.ip32_raw(k) > ip2.ip32_raw(k) {
                return true;
            } else if self.ip32_raw(k) < ip2.ip32_raw(k) {
                return false;
            }
        }
        false
    }

    pub fn fast_eq6(&self, ip2: &SfIp) -> bool {
        self.ip64_raw(0) == ip2.ip64_raw(0) && self.ip64_raw(1) == ip2.ip64_raw(1)
    }

    pub fn fast_equals_raw(&self, ip2: &SfIp) -> bool {
        if self.family == AF_INET {
            ip2.family == AF_INET && self.fast_eq4(ip2)
        } else if self.family == AF_INET6 {
            ip2.family == AF_INET6 && self.fast_eq6(ip2)
        } else {
            false
        }
    }

    // ---- setters ----
    /// pton: strict pre-check for IPv4 leading zeros (C++ comment: inet_pton is
    /// inconsistent across platforms), then strict parse.
    pub fn pton(&mut self, fam: i16, ip: &str) -> SfIpRet {
        if fam == AF_INET {
            let b = ip.as_bytes();
            let mut new_octet = true;
            let mut i = 0usize;
            while i < b.len() {
                let chr = b[i];
                i += 1;
                if new_octet && chr == b'0' && i < b.len() && b[i].is_ascii_digit() {
                    return SfIpRet::InetParseErr;
                }
                new_octet = chr == b'.';
            }
            self.ip8 = [0; 16];
            self.set_ip16_raw(5, 0xffff);
            let mut ok = false;
            let mut tmp = [0u8; 4];
            if inet_pton(AF_INET, ip, &mut tmp) == 1 {
                self.ip8[12..16].copy_from_slice(&tmp);
                ok = true;
            }
            if !ok {
                return SfIpRet::InetParseErr;
            }
        } else {
            // parse into a temp; commit only on success (glibc inet_pton does
            // not partially write on failure)
            let mut tmp = [0u8; 16];
            if inet_pton(fam, ip, &mut tmp) < 1 {
                return SfIpRet::InetParseErr;
            }
            self.ip8 = tmp;
        }
        self.family = fam;
        SfIpRet::Success
    }

    fn cidr_mask(&mut self, val: i32) -> SfIpRet {
        if !(0..=128).contains(&val) {
            return SfIpRet::ArgErr;
        }
        if val == 128 {
            return SfIpRet::Success;
        }
        let index = ((val as f64 / 32.0).ceil() as i32) - 1;
        let bits = 32 - (val - index * 32);
        if bits != 0 {
            let mask: u32 = (!0u32 >> bits) << bits;
            // C: ip32[index] &= htonl(mask) on LE host == per-byte AND
            // equivalent to net-word AND with mask's byte order preserved:
            let masked = self.net32(index as usize) & mask;
            self.set_net32(index as usize, masked);
        }
        let mut index = index + 1;
        while index < 4 {
            self.set_ip32_raw(index as usize, 0);
            index += 1;
        }
        SfIpRet::Success
    }

    /// Mirrors `set(const void* src, int fam)`; src is raw 4 (v4) or 16 (v6) bytes.
    pub fn set_raw(&mut self, src: &[u8], fam: i16) -> SfIpRet {
        self.family = fam;
        if fam == AF_INET {
            self.ip8 = [0; 16];
            self.set_ip16_raw(5, 0xffff);
            self.ip8[12..16].copy_from_slice(&src[..4]);
            SfIpRet::Success
        } else if fam == AF_INET6 {
            self.ip8.copy_from_slice(&src[..16]);
            SfIpRet::Success
        } else {
            SfIpRet::ArgErr
        }
    }

    /// Mirrors `set(const void* src)` (128-bit v6, collapsing v4-mapped).
    pub fn set_mapped_raw(&mut self, src: &[u8]) -> SfIpRet {
        let w0 = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
        let w1 = u32::from_le_bytes([src[4], src[5], src[6], src[7]]);
        let h4 = u16::from_le_bytes([src[8], src[9]]);
        let h5 = u16::from_le_bytes([src[10], src[11]]);
        if w0 == 0 && w1 == 0 && h4 == 0 && h5 == 0xffff {
            return self.set_raw(&src[12..16], AF_INET);
        }
        self.set_raw(src, AF_INET6)
    }

    /// Mirrors `SfIpRet set(const char* src, uint16_t* srcBits)`; returns
    /// (ret, bits) — bits is the *out value only on Success, mirroring *srcBits.
    pub fn set_addr_str(&mut self, src: &str) -> (SfIpRet, u16) {
        let mut ob = false;
        let family = sfip_str_to_fam(src);
        // work on a mutable byte model, mirroring the in-place str mutations
        let mut buf: Vec<u8> = src.bytes().collect();
        let mut ip_start = 0usize;
        while ip_start < buf.len()
            && (c_isspace(buf[ip_start]) || {
                if buf[ip_start] == b'[' {
                    ob = true;
                    true
                } else {
                    false
                }
            })
        {
            ip_start += 1;
        }
        if ob
            && let Some(cb) = buf[ip_start..].iter().rposition(|&c| c == b']') {
                buf[ip_start + cb] = 0;
            }
        // find '/' within ip (NUL-terminated slice)
        let ip_slice_end = buf[ip_start..].iter().position(|&c| c == 0).map_or(buf.len(), |p| ip_start + p);
        let mut bits: i32;
        if let Some(sl) = buf[ip_start..ip_slice_end].iter().position(|&c| c == b'/') {
            let slash = ip_start + sl;
            let mut mask = slash + 1;
            let mut end = slash;
            while end > ip_start && c_isspace(buf[end - 1]) {
                end -= 1;
            }
            buf[end] = 0;
            while mask < buf.len() && c_isspace(buf[mask]) {
                mask += 1;
            }
            let mch = buf.get(mask).copied().unwrap_or(0);
            if (family == AF_INET6 && !mch.is_ascii_hexdigit())
                || (family == AF_INET && !mch.is_ascii_digit())
            {
                return (SfIpRet::CidrErr, 0);
            }
            let mask_str = take_cstr(&buf, mask);
            if mask_str.contains('.') || mask_str.contains(':') {
                bits = netmask_str_to_bit_count(&mask_str, sfip_str_to_fam(&mask_str));
            } else {
                bits = c_atoi(&mask_str);
            }
        } else if let Some(col) = (family == AF_INET)
            .then(|| buf[ip_start..ip_slice_end].iter().position(|&c| c == b':'))
            .flatten()
            .map(|p| ip_start + p)
            .or_else(|| buf[ip_start..ip_slice_end].iter().position(|&c| c == b' ').map(|p| ip_start + p))
        {
            // ':' (v4 netmask form) or ' ' delimiter
            let mut mask = col + 1;
            let mut end = col;
            while end > ip_start && c_isspace(buf[end - 1]) {
                end -= 1;
            }
            buf[end] = 0;
            while mask < buf.len() && c_isspace(buf[mask]) {
                mask += 1;
            }
            let mch = buf.get(mask).copied().unwrap_or(0);
            if (family == AF_INET && mch.is_ascii_digit())
                || (family == AF_INET6 && (mch.is_ascii_hexdigit() || mch == b':'))
            {
                let mask_str = take_cstr(&buf, mask);
                bits = netmask_str_to_bit_count(&mask_str, sfip_str_to_fam(&mask_str));
            } else {
                bits = if family == AF_INET { 32 } else { 128 };
            }
        } else {
            bits = if family == AF_INET { 32 } else { 128 };
        }

        let ip_str = take_cstr(&buf, ip_start);
        self.family = family;
        if self.pton(family, &ip_str) != SfIpRet::Success {
            return (SfIpRet::InetParseErr, 0);
        }

        bits += if family == AF_INET && bits >= 0 { 96 } else { 0 };
        if self.cidr_mask(bits) != SfIpRet::Success {
            return (SfIpRet::InvalidMask, 0);
        }
        (SfIpRet::Success, bits as u16)
    }

    pub fn set_str(&mut self, src: &str) -> SfIpRet {
        let (ret, bits) = self.set_addr_str(src);
        if ret != SfIpRet::Success {
            return ret;
        }
        // C++: with srcBits == nullptr, a non-/128 result is an error
        // (the address keeps its masked value, but the call fails).
        if bits != 128 {
            return SfIpRet::InetParseErr;
        }
        SfIpRet::Success
    }

    #[allow(dead_code)] // ported for parity with C sf_ip.cc
    fn zero_ip6_ptr(&self) -> [u8; 16] {
        self.ip8
    }

    pub fn obfuscate(&mut self, ob: &super::sf_cidr::SfCidr) {
        let family = self.family;
        let _ = family;
        let ob_p = ob.get_addr_bytes();
        let obits = ob.get_bits() as i32;
        let index = ((obits as f64 / 32.0).ceil() as i32) - 1;
        let mut mask: u32 = 0;
        for _ in 0..(32 - (obits - index * 32)) {
            mask = (mask << 1) + 1;
        }
        // C: ip32[index] = htonl(ntohl(ip32[index]) & mask)
        let masked = self.net32(index as usize) & mask;
        self.set_net32(index as usize, masked);
        let mut index = index;
        while index > 0 {
            index -= 1;
            self.set_ip32_raw(index as usize, 0);
        }
        for k in 0..4 {
            let mut ob_w = [0u8; 4];
            ob_w.copy_from_slice(&ob_p[4 * k..4 * k + 4]);
            let v = self.net32(k) | u32::from_be_bytes(ob_w);
            self.set_net32(k, v);
        }
    }

    pub fn ntop(&self, test_features: bool) -> Option<String> {
        let (off, len) = if self.is_ip4() { (12, 4) } else { (0, 16) };
        snort_inet_ntop_raw(self.family, &self.ip8[off..off + len], test_features)
    }
}

/// get_ptr() for v4-mapped layout: v4 reads 4 bytes at offset 12.
pub fn sfip_ntop_raw_bytes(ip: &SfIp) -> &[u8] {
    if ip.is_ip4() {
        &ip.ip8[12..16]
    } else {
        &ip.ip8
    }
}

/// sfip_str_to_fam: two or more ':' => v6; any '.' => v4; else AF_UNSPEC.
pub fn sfip_str_to_fam(str: &str) -> i16 {
    if let Some(s) = str.find(':')
        && str[s + 1..].contains(':') {
            return AF_INET6;
        }
    if str.contains('.') {
        return AF_INET;
    }
    AF_UNSPEC
}

fn take_cstr(buf: &[u8], start: usize) -> String {
    let rest = &buf[start..];
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

fn c_isspace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// C atoi: optional leading space/sign, digits until non-digit; no overflow trap.
pub fn c_atoi(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && c_isspace(b[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut val: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        val = val * 10 + (b[i] - b'0') as i64;
        if val > i32::MAX as i64 + 1 {
            val = i32::MAX as i64 + 1; // saturate; C is UB, we clamp
        }
        i += 1;
    }
    ((if neg { -val } else { val }) as i32).wrapping_add(0)
}

fn _count_bits(mut val: u32) -> u32 {
    let mut count = 0;
    while val != 0 {
        val &= val - 1;
        count += 1;
    }
    count
}

/// _netmask_str_to_bit_count: parse mask string as address, require contiguity.
pub fn netmask_str_to_bit_count(mask: &str, family: i16) -> i32 {
    let mut buf = [0u8; 16];
    let n = if family == AF_INET { 4 } else { 16 };
    if inet_pton(family, mask, &mut buf) < 1 {
        return -1;
    }
    // popcount over the word views (endian-agnostic for popcount sum)
    let mut bits = _count_bits(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]));
    if family == AF_INET6 {
        for k in 1..4 {
            bits += _count_bits(u32::from_le_bytes([
                buf[4 * k], buf[4 * k + 1], buf[4 * k + 2], buf[4 * k + 3],
            ]));
        }
    }
    // contiguity over network-order bytes
    let mut nbits = bits as i32;
    for i in 0..n {
        if nbits >= 8 {
            if buf[i] != 0xff {
                return -1;
            }
            nbits -= 8;
        } else if nbits == 0 {
            if buf[i] != 0x00 {
                return -1;
            }
        } else {
            if buf[i] != ((0xff00u32 >> nbits) & 0xff) as u8 {
                return -1;
            }
            nbits = 0;
        }
    }
    bits as i32
}

/// parse_ip_from_uri (sf_ip.h)
pub fn parse_ip_from_uri(ip_str: &str, ip: &mut SfIp) -> bool {
    let mut host_start = match ip_str.find("://") {
        Some(h) => {
            let h = h + 3;
            if h >= ip_str.len() {
                return false;
            }
            h
        }
        None => 0,
    };
    let mut host_end = host_start;
    let family = sfip_str_to_fam(&ip_str[host_start..]);

    if family == AF_INET {
        while host_end < ip_str.len()
            && ip_str.as_bytes()[host_end] != b':'
            && ip_str.as_bytes()[host_end] != b'/'
        {
            host_end += 1;
        }
    } else if family == AF_INET6 {
        if ip_str.as_bytes()[host_start] == b'[' {
            host_start += 1;
            host_end += 1;
        }
        while host_end < ip_str.len()
            && ip_str.as_bytes()[host_end] != b']'
            && ip_str.as_bytes()[host_end] != b'/'
        {
            host_end += 1;
        }
    } else {
        return false;
    }

    if host_end <= host_start
        || (host_end - host_start) > MAX_INET6_STRLEN_NO_IPV4_MAP
    {
        return false;
    }

    let (hstart, hend) = (host_start, host_end);
    if hstart != 0 || hend != ip_str.len() {
        let host_str = &ip_str[hstart..hend];
        ip.set_str(host_str) == SfIpRet::Success
    } else {
        ip.set_str(ip_str) == SfIpRet::Success
    }
}
