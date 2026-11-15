// Port of snort3 src/ports/port_object.{h,cc}.
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//           Copyright (C) 2005-2013 Sourcefire, Inc.
//
// RuleGroup (C++) is out of scope at this layer; `group` is omitted
// (documented deviation). The duplicate-port ParseWarning in add_item fires
// in C++ but produces stdout-free behavior; the port keeps the same 0 return.
#![allow(dead_code)]

use super::port_item::{PortObjectItem, SFPO_MAX_PORTS};
use super::port_utils::{port_object_bits, port_object_item_list_from_bits, PortBitSet};

#[derive(Clone, Debug, Default)]
pub struct PortObject {
    pub name: Option<String>,
    pub id: i32,
    pub hash: u32,                  // mutable hash cache (C++ mutable member)
    pub items: Vec<PortObjectItem>, // item_list (tail-append order)
    pub rules: Vec<i32>,            // rule_list
}

impl PortObject {
    pub fn new() -> Self {
        PortObject::default()
    }

    /// int PortObjectSetName(po, name)
    pub fn set_name(&mut self, name: &str) -> i32 {
        self.name = Some(name.to_string());
        0
    }

    /// int PortObjectAddItem(po, poi, errflag): C++ scans for an exact
    /// lport/hport duplicate (fires ParseWarning, no error), then ALWAYS
    /// tail-appends. Never returns nonzero.
    pub fn add_item(&mut self, poi: PortObjectItem) -> i32 {
        let dup = self
            .items
            .iter()
            .any(|p| p.lport == poi.lport && p.hport == poi.hport);
        let _ = dup; // ParseWarning(WARN_RULES, "duplicate ports in list")
        self.items.push(poi);
        0
    }

    /// int PortObjectAddPortObject(podst, posrc, errflag)
    pub fn add_port_object(&mut self, src: &PortObject, errflag: &mut i32) -> i32 {
        *errflag = 0;
        let mut ret = 0;
        for poi in src.items.iter() {
            let poi = *poi; // PortObjectItemDup
            ret = self.add_item(poi);
            if ret != 0 {
                return ret;
            }
        }
        ret
    }

    pub fn add_port(&mut self, port: i32) -> i32 {
        self.add_range(port, port)
    }

    /// int PortObjectAddRange: C++ casts (unsigned short) in both directions.
    pub fn add_range(&mut self, lport: i32, hport: i32) -> i32 {
        let mut poi = PortObjectItem::new();
        poi.lport = lport as u16;
        poi.hport = hport as u16;
        self.items.push(poi);
        0
    }

    /// int PortObjectAddRule(po, rule): stores boxed int in rule_list.
    pub fn add_rule(&mut self, rule: i32) -> i32 {
        self.rules.push(rule);
        0
    }

    /// int PortObjectAddPortAny(po): sets name "any" if unnamed.
    pub fn add_port_any(&mut self) -> i32 {
        if self.name.is_none() {
            self.name = Some("any".to_string());
        }
        self.add_range(0, SFPO_MAX_PORTS as i32 - 1)
    }

    /// PortObject* PortObjectDup(po): items + rules + name; missing name ->
    /// "dup"; hash cache starts fresh (0).
    pub fn dup(&self) -> PortObject {
        let mut ponew = PortObject::new();
        ponew.name = Some(self.name.clone().unwrap_or_else(|| "dup".to_string()));
        for poi in self.items.iter() {
            ponew.add_item(*poi); // PortObjectItemDup + PortObjectAddItem
        }
        ponew.rules = self.rules.clone();
        ponew
    }

    /// PortObject* PortObjectDupPorts(po): items + name only.
    pub fn dup_ports(&self) -> PortObject {
        let mut ponew = PortObject::new();
        ponew.name = Some(self.name.clone().unwrap_or_else(|| "dup".to_string()));
        for poi in self.items.iter() {
            ponew.add_item(*poi);
        }
        ponew
    }

    /// int PortObjectNormalize(po)
    pub fn normalize(&mut self) -> i32 {
        if self.has_any() != 0 {
            return 0; // ANY = 64K
        }
        let mut parray = PortBitSet::new();
        let nports = port_object_bits(&mut parray, self);
        self.items = port_object_item_list_from_bits(&parray, SFPO_MAX_PORTS);
        nports
    }

    /// bool PortObjectEqual(a, b): count, then pairwise ItemsEqual
    /// (ItemsEqual ignores the negate flag).
    pub fn equal(a: &PortObject, b: &PortObject) -> bool {
        if a.items.len() != b.items.len() {
            return false;
        }
        a.items
            .iter()
            .zip(b.items.iter())
            .all(|(pa, pb)| PortObjectItem::items_equal(pa, pb))
    }

    /// int PortObjectPortCount(po): any item = -1; 0 = none; negative
    /// accumulations (pure-not pre-normalization) get 64K added back.
    pub fn port_count(&self) -> i32 {
        let mut cnt = 0i32;
        for poi in &self.items {
            if poi.any() {
                return -1;
            }
            let nports = poi.hport as i32 - poi.lport as i32 + 1;
            if poi.negate {
                cnt -= nports;
            } else {
                cnt += nports;
            }
        }
        if cnt < 0 {
            cnt += SFPO_MAX_PORTS as i32;
        }
        cnt
    }

    /// int PortObjectHasPort(po, port): NOTE C++ quirk: an ANY item returns
    /// 0 (not found), and a negate item returns 1 if not earlier matched.
    pub fn has_port(&self, port: i32) -> i32 {
        for poi in &self.items {
            if poi.any() {
                return 0;
            }
            let p = port as u16;
            if p >= poi.lport && p <= poi.hport {
                return 1;
            }
            if poi.negate {
                return 1;
            }
        }
        0
    }

    /// void PortObjectToggle(po)
    pub fn toggle(&mut self) {
        for poi in self.items.iter_mut() {
            poi.negate = !poi.negate;
        }
    }

    /// int PortObjectIsPureNot(po)
    pub fn is_pure_not(&self) -> i32 {
        if self.items.is_empty() {
            return 0;
        }
        if self.items.iter().any(|poi| !poi.negate) {
            return 0;
        }
        1
    }

    /// int PortObjectHasAny(po)
    pub fn has_any(&self) -> i32 {
        for poi in self.items.iter() {
            if poi.any() {
                return 1;
            }
        }
        0
    }

    /// int PortObjectRemovePorts(a, b): A = A - B via bitsets.
    pub fn remove_ports(&mut self, b: &PortObject) -> i32 {
        let mut pa = PortBitSet::new();
        let mut pb = PortBitSet::new();
        port_object_bits(&mut pa, self);
        port_object_bits(&mut pb, b);
        pa.and_not(&pb);
        self.items = port_object_item_list_from_bits(&pa, SFPO_MAX_PORTS);
        0
    }

    /// PortObject* PortObjectAppend(poa, pob): dups pob items onto poa tail.
    pub fn append(&mut self, pob: &PortObject) {
        for poib in &pob.items {
            self.items.push(*poib); // PortObjectItemDup + add_tail
        }
    }

    /// PortObjectPrintPortsRaw-style rendering (returned instead of logged).
    pub fn print_ports_raw(&self) -> String {
        let mut buf = String::from(" [");
        for poi in &self.items {
            poi.print_append(&mut buf);
        }
        buf.push(']');
        buf
    }

    /// unsigned PortObjectHash(po, hash, scale, hardener): cached in
    /// po->hash (non-debug C++ short-circuits when nonzero).
    pub fn hash(&mut self, mut hash: u32, scale: u32, hardener: u32) -> u32 {
        if self.hash != 0 {
            return self.hash;
        }
        for poi in self.items.iter() {
            hash = poi.hash(hash, scale);
        }
        self.hash = hash ^ hardener;
        self.hash
    }
}
