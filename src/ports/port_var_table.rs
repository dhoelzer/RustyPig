// Port of snort3 src/ports/port_var_table.{h,cc}.
//
// C++ PortVarTable is a snort::GHash keyed by name; find() returns a BORROWED
// pointer into the table (callers in parse_ports immediately PortObjectDup it,
// which is why find() hands back an owned clone here — same observable
// effect). GHash internals (LRU, primetable sizing) are out of scope at this
// layer (documented deviation).
#![allow(dead_code)]

use std::collections::HashMap;

use super::port_object::PortObject;

pub struct PortVarTable {
    map: HashMap<String, PortObject>,
}

impl PortVarTable {
    /// PortVarTableCreate(): GHash(1000), then the default ANY entry
    /// (PortObjectNew + PortObjectAddPortAny -> name "any").
    pub fn create() -> Self {
        let mut t = PortVarTable { map: HashMap::new() };
        let mut po = PortObject::new();
        po.add_port_any();
        t.add(po);
        t
    }

    /// int PortVarTableAdd(h, po): -1 error, 0 added, 1 already in table.
    pub fn add(&mut self, po: PortObject) -> i32 {
        let name = po.name.clone().unwrap_or_default();
        if self.map.contains_key(&name) {
            return 1; // HASH_INTABLE
        }
        self.map.insert(name, po);
        0 // HASH_OK
    }

    /// PortObject* PortVarTableFind(h, name, add_if_not_found): the C++
    /// add-if-missing path requires conf->dump_rule_info and is gated by the
    /// dump_rule_info flag (matches snort only when that option is set).
    pub fn find(&mut self, name: &str, add_if_not_found: bool, dump_rule_info: bool) -> Option<PortObject> {
        if let Some(po) = self.map.get(name) {
            return Some(po.clone()); // dup by the only caller in C++
        }
        if dump_rule_info && add_if_not_found {
            let mut po = PortObject::new();
            po.name = Some(name.to_string());
            self.map.insert(name.to_string(), po.clone());
            return Some(po);
        }
        None
    }
}
