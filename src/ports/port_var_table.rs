// Port of snort3 src/ports/port_var_table.{h,cc}.
//
// C++ PortVarTable is a snort::GHash keyed by name; find() returns a BORROWED
// pointer into the table (callers in parse_ports immediately PortObjectDup it,
// which is why find() hands back an owned clone here — same observable
// effect). GHash internals (LRU, primetable sizing) are out of scope at this
// layer (documented deviation).
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::port_object::PortObject;

pub type PoHandle = Rc<RefCell<PortObject>>;

#[derive(Debug, Default)]
pub struct PortVarTable {
    map: HashMap<String, PortObject>,
    // Identity handles consumed by the rule layer: C PortVarTableFind hands
    // the *table pointer* to rtn->{src,dst}_portobject, so the rule core
    // needs shared handles (ptr-identity is what same_headers compares when
    // strict reduction is off). Kept parallel to `map`; the borrowing find()
    // below is unchanged for the parse_ports layer.
    handles: HashMap<String, PoHandle>,
}

impl PortVarTable {
    /// PortVarTableCreate(): GHash(1000), then the default ANY entry
    /// (PortObjectNew + PortObjectAddPortAny -> name "any").
    pub fn create() -> Self {
        let mut t = PortVarTable { map: HashMap::new(), handles: HashMap::new() };
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
        self.handles.insert(name.clone(), Rc::new(RefCell::new(po.clone())));
        self.map.insert(name, po);
        0 // HASH_OK
    }

    /// Identity-preserving lookup used by the rule tree (rtn portobject
    /// pointers must alias the table entry, not clone it).
    pub fn find_handle(&self, name: &str) -> Option<PoHandle> {
        self.handles.get(name).cloned()
    }

    /// add() for a rule-layer caller that already holds a PoHandle: keeps
    /// `handles` and `map` in sync (C PortVarTableAdd stores the one node
    /// both sides then point at; the Rust table stores value + shared handle).
    pub fn add_handle(&mut self, h: &PoHandle) -> i32 {
        let name = h.borrow().name.clone().unwrap_or_default();
        if self.map.contains_key(&name) {
            return 1; // HASH_INTABLE
        }
        self.handles.insert(name.clone(), Rc::clone(h));
        self.map.insert(name, h.borrow().clone());
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
            self.handles.insert(name.to_string(), Rc::new(RefCell::new(po.clone())));
            self.map.insert(name.to_string(), po.clone());
            return Some(po);
        }
        None
    }

    /// Identity-preserving Find+add used by the rule layer (ParsePortList
    /// '$' arm): PortVarTableFind(h, name, true) gated by
    /// SnortConfig::get_conf()->dump_rule_info() (port_var_table.cc).
    pub fn find_or_add(&mut self, name: &str, add_if_not_found: bool, dump_rule_info: bool) -> Option<PoHandle> {
        if let Some(h) = self.handles.get(name) {
            return Some(Rc::clone(h));
        }
        if dump_rule_info && add_if_not_found {
            let mut po = PortObject::new();
            po.name = Some(name.to_string());
            let h = Rc::new(RefCell::new(po.clone()));
            self.handles.insert(name.to_string(), Rc::clone(&h));
            self.map.insert(name.to_string(), po);
            return Some(h);
        }
        None
    }
}

// Default derived
