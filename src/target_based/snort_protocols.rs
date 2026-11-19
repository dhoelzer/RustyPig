// Port of snort3 src/target_based/snort_protocols.{h,cc}: the ProtocolReference
// name<->id table plus the fixed protocol enum. Literal transcription:
// ids are allocated by insertion order (protocol_number++ starting at 0),
// init seeds ["unknown","ip","icmp","tcp","udp","file"] so UNKNOWN=0 and
// SNORT_PROTO_* land at 1..5; add() returns UNKNOWN for null name and
// otherwise get-or-insert. The enum-inline predicates (is_network_protocol
// etc.) depend on declaration order exactly as upstream. Ground truth:
// ORIGINAL snort_protocols.cc compiled in tools/rules_harness (vectors pin
// spid = 3 for tcp rules, 6/7/8 for first-name service allocations).
#![allow(dead_code)]

use std::collections::HashMap;

pub type SnortProtocolId = u16;

// enum SnortProtocols : SnortProtocolId (declaration order pins values).
pub const SNORT_PROTO_IP: SnortProtocolId = 1;
pub const SNORT_PROTO_ICMP: SnortProtocolId = 2;
pub const SNORT_PROTO_TCP: SnortProtocolId = 3;
pub const SNORT_PROTO_UDP: SnortProtocolId = 4;
pub const SNORT_PROTO_FILE: SnortProtocolId = 5;
pub const SNORT_PROTO_MAX: SnortProtocolId = 6;

pub const UNKNOWN_PROTOCOL_ID: SnortProtocolId = 0;
pub const INVALID_PROTOCOL_ID: SnortProtocolId = 0xffff;

/// Row 17y: the literal the FileService proto arms look up —
/// file_service.cc:143 / :167 `proto_ref->find("file_id")` (the ctor
/// adds "file" at 5, so a probe-seeded add("file_id") lands 6 — the
/// fsvc V1 `spid=6` pin through the REAL find body).
pub const FILE_ID_PROTO_NAME: &str = "file_id";

// The is_*_protocol functions depend on the order of these enums.
pub fn is_network_protocol(proto: SnortProtocolId) -> bool {
    (SNORT_PROTO_IP..=SNORT_PROTO_UDP).contains(&proto)
}

pub fn is_builtin_protocol(proto: SnortProtocolId) -> bool {
    proto < SNORT_PROTO_MAX
}

pub fn is_service_protocol(proto: SnortProtocolId) -> bool {
    proto > SNORT_PROTO_UDP
}

/// class ProtocolReference
pub struct ProtocolReference {
    id_map: Vec<String>,
    ind_map: Vec<SnortProtocolId>,
    ref_table: HashMap<String, SnortProtocolId>,

    protocol_number: SnortProtocolId,

    // C get_name() hands back the interned `const char*` from
    // SnortConfig::get_static_name; Rust owns the String instead (the
    // pointer-identity deviation is irrelevant to callers: every harness
    // and probe path compares through the name text).
}

impl ProtocolReference {
    /// void init(old_proto_ref)
    fn init(&mut self, old: Option<&ProtocolReference>) {
        match old {
            None => {
                // add() return-value chain feeds `ok`; failures abort via
                // the upstream assert(ok). Rust assert mirrors it.
                let mut ok = self.add("unknown") == UNKNOWN_PROTOCOL_ID;
                ok = (self.add("ip") == SNORT_PROTO_IP) && ok;
                ok = (self.add("icmp") == SNORT_PROTO_ICMP) && ok;
                ok = (self.add("tcp") == SNORT_PROTO_TCP) && ok;
                ok = (self.add("udp") == SNORT_PROTO_UDP) && ok;
                ok = (self.add("file") == SNORT_PROTO_FILE) && ok;
                assert!(ok);
            }
            Some(old_ref) => {
                let count = old_ref.get_count();
                for id in 0..count {
                    // C: add(old->get_name(id)). get_name clamps id >= id_map
                    // .size() to 0; ids below count are always in id_map.
                    let name = old_ref.get_name(id).to_string();
                    self.add(&name);
                }
            }
        }
    }

    /// ProtocolReference::ProtocolReference()
    pub fn new() -> ProtocolReference {
        let mut pr = ProtocolReference {
            id_map: Vec::new(),
            ind_map: Vec::new(),
            ref_table: HashMap::new(),
            protocol_number: 0,
        };
        pr.init(None);
        pr
    }

    /// ProtocolReference::ProtocolReference(ProtocolReference* old)
    pub fn with_old(old: &ProtocolReference) -> ProtocolReference {
        let mut pr = ProtocolReference {
            id_map: Vec::new(),
            ind_map: Vec::new(),
            ref_table: HashMap::new(),
            protocol_number: 0,
        };
        pr.init(Some(old));
        pr
    }

    /// SnortProtocolId get_count() const { return protocol_number; }
    pub fn get_count(&self) -> SnortProtocolId {
        self.protocol_number
    }

    /// const char* get_name(id) const: id >= id_map.size() clamps to 0.
    pub fn get_name(&self, id: SnortProtocolId) -> &str {
        let mut id = id as usize;
        if id >= self.id_map.len() {
            id = 0;
        }
        &self.id_map[id]
    }

    /// SnortProtocolId add(protocol): null -> UNKNOWN; else get-or-insert
    /// with protocol_number++ (post-increment: first insert takes 0).
    pub fn add(&mut self, protocol: &str) -> SnortProtocolId {
        if let Some(&id) = self.ref_table.get(protocol) {
            return id;
        }
        let snort_protocol_id = self.protocol_number;
        self.protocol_number = self.protocol_number.wrapping_add(1);
        self.id_map.push(protocol.to_string());
        self.ref_table.insert(protocol.to_string(), snort_protocol_id);
        snort_protocol_id
    }

    /// add(nullptr) channel: C early-returns UNKNOWN without touching state.
    pub fn add_opt(&mut self, protocol: Option<&str>) -> SnortProtocolId {
        match protocol {
            None => UNKNOWN_PROTOCOL_ID,
            Some(p) => self.add(p),
        }
    }

    /// SnortProtocolId find(protocol) const: miss -> UNKNOWN.
    pub fn find(&self, protocol: &str) -> SnortProtocolId {
        match self.ref_table.get(protocol) {
            Some(&id) => id,
            None => UNKNOWN_PROTOCOL_ID,
        }
    }
}

impl Default for ProtocolReference {
    fn default() -> Self {
        ProtocolReference::new()
    }
}
