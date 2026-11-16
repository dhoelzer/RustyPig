// Port of snort3 src/ports/port_table.{h,cc}. The rule-tree layer consumes
// the INPUT-list half: PortTableNew, PortTableFindInputPortObjectPorts,
// PortTableAddObject (identity-preserving handles, because C hands the
// table's own PortObject pointer back and the rule layer aliases it).
// The merged-port compile path (PortTableCompile/Finalize/GHASH) belongs
// to the detection-compile layer and is deferred — documented deviation.
//
// Also ports ports/rule_port_tables.{h,cc}: PortProto tables +
// RulePortTables { svc_any } per protocol spine.
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use super::port_object::PortObject;
use super::port_var_table::PoHandle;

pub const PTCNT_ANY: usize = 0;
pub const PTCNT_SRC: usize = 1;
pub const PTCNT_DST: usize = 2;
pub const PTCNT_BOTH: usize = 3;
pub const PTCNT_NFP: usize = 4;
pub const PTCNT_MAXLISTS: usize = 5;

pub const PL_SINGLE_RULE_GROUP: usize = 0;
pub const PL_BLEEDOVER: usize = 1;
pub const PL_MAX_PLISTS: usize = 2;

pub const PTBL_LRC_DEFAULT: i32 = 10;

#[derive(Debug)]
pub struct PortTable {
    pub pt_optimize: i32,
    pub pt_polist: Vec<PoHandle>, // input port object list
    pub pt_poid: i32,             // port object id (compile path; unused here)
    pub pt_lrc: i32,              // large rule count
}

impl PortTable {
    /// PortTableNew()
    pub fn new() -> PortTable {
        PortTable {
            pt_optimize: 1,
            pt_polist: Vec::new(),
            pt_poid: 0,
            pt_lrc: PTBL_LRC_DEFAULT,
        }
    }

    /// PortTableFindInputPortObjectPorts: linear PortObjectEqual scan over
    /// the input list; the FIRST equal entry is handed out (identity).
    pub fn find_input(&self, po: &PortObject) -> Option<PoHandle> {
        for e in self.pt_polist.iter() {
            if PortObject::equal(&e.borrow(), po) {
                return Some(Rc::clone(e));
            }
        }
        None
    }

    /// int PortTableAddObject(ptbl, po)
    pub fn add_object(&mut self, po: PoHandle) -> i32 {
        self.pt_polist.push(po);
        0
    }
}

impl Default for PortTable {
    fn default() -> Self {
        PortTable::new()
    }
}

/// rule_port_tables.h PortProto
pub struct PortProto {
    pub src: PortTable,
    pub dst: PortTable,
    pub any: PoHandle,
    pub nfp: PoHandle,
}

impl PortProto {
    /// PortProto ctor: PortTableNew x2, PortObjectNew x2, pt_lrc overridden
    /// to DEFAULT_LARGE_RULE_GROUP (9) on both tables, any-ports on both
    /// objects.
    pub fn new() -> PortProto {
        let mut src = PortTable::new();
        let mut dst = PortTable::new();
        src.pt_lrc = 9; // DEFAULT_LARGE_RULE_GROUP (rule_port_tables.cc:33)
        dst.pt_lrc = 9;
        let mut any = PortObject::new();
        any.add_port_any();
        let mut nfp = PortObject::new();
        nfp.add_port_any();
        PortProto {
            src,
            dst,
            any: Rc::new(RefCell::new(any)),
            nfp: Rc::new(RefCell::new(nfp)),
        }
    }
}

impl Default for PortProto {
    fn default() -> Self {
        PortProto::new()
    }
}

/// rule_port_tables.h RulePortTables
pub struct RulePortTables {
    pub ip: PortProto,
    pub icmp: PortProto,
    pub tcp: PortProto,
    pub udp: PortProto,
    pub svc_any: PoHandle,
}

impl Default for RulePortTables {
    fn default() -> Self { Self::new() }
}

impl RulePortTables {
    /// PortTablesNew(): default-constructs the protocol spines, then
    /// svc_any = PortObjectNew + PortObjectAddPortAny.
    pub fn new() -> Self {
        let mut svc_any = PortObject::new();
        svc_any.add_port_any();
        Self {
            ip: PortProto::new(),
            icmp: PortProto::new(),
            tcp: PortProto::new(),
            udp: PortProto::new(),
            svc_any: Rc::new(RefCell::new(svc_any)),
        }
    }
}
