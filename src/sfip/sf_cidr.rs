// Port of snort3 src/sfip/sf_cidr.{h,cc}.
#![allow(dead_code)]

use super::sf_ip::SfIp;
use super::sf_returns::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SfCidr {
    pub addr: SfIp,
    pub bits: u16,
}

impl Default for SfCidr {
    fn default() -> Self {
        Self::new()
    }
}

impl SfCidr {
    pub fn new() -> Self {
        SfCidr { addr: SfIp::new(), bits: 0 }
    }

    pub fn clear(&mut self) {
        self.addr.clear();
        self.bits = 0;
    }

    pub fn set_str(&mut self, src: &str) -> SfIpRet {
        let (ret, outbits) = self.addr.set_addr_str(src);
        self.bits = outbits;
        ret
    }

    pub fn set_ip(&mut self, src: &SfIp) {
        self.addr = *src;
        self.bits = 128;
    }

    pub fn set_raw(&mut self, src: &[u8], fam: i16) -> SfIpRet {
        let ret = self.addr.set_raw(src, fam);
        if ret != SfIpRet::Success {
            return ret;
        }
        self.bits = 128;
        SfIpRet::Success
    }

    pub fn set_bits(&mut self, new_bits: u16) {
        if new_bits > 128 {
            return;
        }
        self.bits = new_bits;
    }

    pub fn get_addr(&self) -> &SfIp {
        &self.addr
    }

    pub fn get_addr_bytes(&self) -> [u8; 16] {
        self.addr.ip8
    }

    pub fn get_family(&self) -> u16 {
        self.addr.get_family()
    }

    pub fn get_bits(&self) -> u16 {
        self.bits
    }

    pub fn is_set(&self) -> bool {
        (self.addr.is_set()
            || ((self.addr.get_family() as i16 == AF_INET
                || self.addr.get_family() as i16 == AF_INET6)
                && self.bits != 128))
    }

    fn ip32_raw(ip: &SfIp, k: usize) -> u32 {
        u32::from_le_bytes([ip.ip8[4 * k], ip.ip8[4 * k + 1], ip.ip8[4 * k + 2], ip.ip8[4 * k + 3]])
    }
    fn net32(ip: &SfIp, k: usize) -> u32 {
        u32::from_be_bytes([ip.ip8[4 * k], ip.ip8[4 * k + 1], ip.ip8[4 * k + 2], ip.ip8[4 * k + 3]])
    }

    pub fn fast_cont4(&self, ip: &SfIp) -> bool {
        let shift = (128 - self.bits) as u32;
        let needle = Self::net32(ip, 3);
        let haystack = Self::net32(&self.addr, 3);

        if haystack == 0 {
            return true;
        }

        let needle = (needle >> shift) << shift;
        haystack == needle
    }

    pub fn fast_cont6(&self, ip: &SfIp) -> bool {
        let words = (self.bits / 32) as usize;
        for i in 0..words {
            if Self::ip32_raw(&self.addr, i) != Self::ip32_raw(ip, i) {
                return false;
            }
        }
        let shift = 32 - (self.bits % 32) as u32;
        if shift == 32 {
            return true;
        }
        let mut needle = Self::net32(ip, words);
        needle = (needle >> shift) << shift;
        Self::net32(&self.addr, words) == needle
    }

    /// contains(): `Some(ip)` mirrors SfIp*, None mirrors the C nullptr special case.
    pub fn contains(&self, ip: Option<&SfIp>) -> SfIpRet {
        let ip = match ip {
            None => return SfIpRet::Contains,
            Some(i) => i,
        };
        let bits = self.bits as usize;
        let full_words = bits / 32;
        for i in 0..full_words {
            if Self::ip32_raw(&self.addr, i) != Self::ip32_raw(ip, i) {
                return SfIpRet::NotContains;
            }
        }
        let mask = (32 - (bits - 32 * full_words)) as u32;
        if mask == 32 {
            return SfIpRet::Contains;
        }
        let mut temp = Self::net32(ip, full_words);
        temp = (temp >> mask) << mask;
        if Self::net32(&self.addr, full_words) == temp {
            return SfIpRet::Contains;
        }
        SfIpRet::NotContains
    }

    pub fn ntop(&self, test_features: bool) -> Option<String> {
        self.addr.ntop(test_features)
    }

    pub fn compare(&self, cidr2: &SfCidr) -> SfIpRet {
        let ret = self.addr.compare(cidr2.get_addr(), true);
        if ret == SfIpRet::Equal {
            if self.bits < cidr2.get_bits() {
                return SfIpRet::Lesser;
            }
            if self.bits > cidr2.get_bits() {
                return SfIpRet::Greater;
            }
        }
        ret
    }
}
