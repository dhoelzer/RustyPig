// Port of snort3 src/ports/port_item.{h,cc}.
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//           Copyright (C) 2005-2013 Sourcefire, Inc.
#![allow(dead_code)]

pub const SFPO_MAX_LPORTS: usize = 500;
pub const SFPO_MAX_PORTS: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PortObjectItem {
    pub negate: bool,
    pub hport: u16, // hi port (field order preserved from C struct)
    pub lport: u16, // lo port
}

impl PortObjectItem {
    pub fn new() -> Self {
        PortObjectItem::default()
    }

    pub fn any(&self) -> bool {
        !self.negate && self.lport == 0 && self.hport == ((SFPO_MAX_PORTS - 1) as u16)
    }

    pub fn one(&self) -> bool {
        self.lport == self.hport
    }

    pub fn items_equal(a: &PortObjectItem, b: &PortObjectItem) -> bool {
        a.lport == b.lport && a.hport == b.hport
    }

    /// PortObjectItemPrint: appends " [!]<any|%hu|%hu:%hu>" semantics.
    pub fn print_append(&self, buf: &mut String) {
        buf.push(' ');
        if self.negate {
            buf.push('!');
        }
        if self.any() {
            buf.push_str("any");
        } else if self.one() {
            buf.push_str(&self.lport.to_string());
        } else {
            buf.push_str(&format!("{}:{}", self.lport, self.hport));
        }
    }

    /// unsigned PortObjectItemHash(poi, hash, scale)
    pub fn hash(&self, mut hash: u32, scale: u32) -> u32 {
        if self.any() {
            return 0;
        }
        hash = hash.wrapping_mul(scale);
        hash = hash.wrapping_add((self.lport & 0xff) as u32);
        hash = hash.wrapping_mul(scale);
        hash = hash.wrapping_add(((self.lport >> 8) & 0xff) as u32);
        hash = hash.wrapping_mul(scale);
        hash = hash.wrapping_add((self.hport & 0xff) as u32);
        hash = hash.wrapping_mul(scale);
        hash = hash.wrapping_add(((self.hport >> 8) & 0xff) as u32);
        hash
    }
}
