// Port of snort3 src/ports/port_utils.cc bitset conversions (PortBitSet is
// std::bitset<MAX_PORTS> in the C++ headers).
#![allow(dead_code)]

use super::port_item::{PortObjectItem, SFPO_MAX_PORTS};
use super::port_object::PortObject;

const WORDS: usize = SFPO_MAX_PORTS / 64; // 1024

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortBitSet {
    words: [u64; WORDS],
}

impl Default for PortBitSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PortBitSet {
    pub fn new() -> Self {
        PortBitSet { words: [0; WORDS] }
    }

    pub fn set_all(&mut self) {
        for w in self.words.iter_mut() {
            *w = !0;
        }
    }

    pub fn test(&self, i: usize) -> bool {
        (self.words[i / 64] >> (i % 64)) & 1 != 0
    }

    pub fn set_bit(&mut self, i: usize) {
        self.words[i / 64] |= 1u64 << (i % 64);
    }

    pub fn clear_bit(&mut self, i: usize) {
        self.words[i / 64] &= !(1u64 << (i % 64));
    }

    pub fn and_not(&mut self, other: &PortBitSet) {
        for k in 0..WORDS {
            self.words[k] &= !other.words[k];
        }
    }

    pub fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }
}

/// int PortObjectBits(PortBitSet& parray, const PortObject* po)
/// Returns unique port count (0 if ANY).
pub fn port_object_bits(parray: &mut PortBitSet, po: &PortObject) -> i32 {
    if po.has_any() != 0 {
        return 0; // ANY = 64K
    }

    let mut cnt = 0i32;
    let mut not_cnt = 0usize;

    for poi in &po.items {
        if poi.negate {
            not_cnt += 1;
            continue;
        }
        if poi.any() {
            continue;
        }
        for i in poi.lport as usize..=poi.hport as usize {
            if !parray.test(i) {
                cnt += 1;
            }
            parray.set_bit(i);
        }
    }

    // remove NOT'd ports possibly added above
    for poi in &po.items {
        if !poi.negate {
            continue;
        }
        if poi.any() {
            continue;
        }
        for i in poi.lport as usize..=poi.hport as usize {
            if parray.test(i) {
                cnt -= 1;
            }
            parray.clear_bit(i);
        }
    }

    // pure Not list
    if po.items.len() == not_cnt {
        parray.set_all();
        cnt += parray.count() as i32;
        for poi in &po.items {
            if !poi.negate {
                continue; // should not happen
            }
            if poi.any() {
                continue;
            }
            for i in poi.lport as usize..=poi.hport as usize {
                if parray.test(i) {
                    cnt -= 1;
                }
                parray.clear_bit(i);
            }
        }
    }

    cnt
}

/// SF_LIST* PortObjectItemListFromBits(const PortBitSet& parray, int n)
pub fn port_object_item_list_from_bits(parray: &PortBitSet, n: usize) -> Vec<PortObjectItem> {
    let mut plist = Vec::new();
    let mut nports = parray.count();

    let mut i = 0usize;
    while i < n && nports > 0 {
        if !parray.test(i) {
            i += 1;
            continue;
        }
        let lport = i;
        let mut hport = i;
        nports -= 1;

        i += 1;
        while i < n {
            if parray.test(i) {
                hport = i;
                nports -= 1;
                i += 1;
                continue;
            }
            break;
        }
        let mut poi = PortObjectItem::new();
        poi.lport = lport as u16;
        poi.hport = hport as u16;
        plist.push(poi);
    }
    plist
}
