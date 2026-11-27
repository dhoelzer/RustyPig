// Port of the FULL main/policy.{cc,h} pair (row 24h: donor 493 + 409 lines
// @ fe29cbe): the PolicyId/ActionSelector/PolicyMode/Enable type faces, the
// checksum + decode-event flag enums (policy.h:128-141), the IpsPolicy
// action-variable subset + get_action() INLINE (policy.h:247-311,
// policy.cc:128-194), the InspectionPolicy record (policy.h:147-166,
// policy.cc:107-122), the completed NetworkPolicy (policy.h:176-241,
// policy.cc:54-92), PolicyTuple (policy.h:317-328), PolicyMap
// (policy.h:332-407, policy.cc:200-319) and the navigator family
// (policy.h:89-122, policy.cc:321-453). The embedded Catch UNIT_TEST block
// policy.cc:455-493 NEVER lands here (wall cite at the file tail; the GATE
// harness compiles the donor C++ directly, the 24a/24c/24e law).
//
// C resolves action names to IpsAction::Type through the global
// ActionManager statics; the Rust port threads an explicit
// framework::ips_action::ActionRegistry instead (see deviations).
//
// CITE-DRIFT face (measured donor, the ladder rows drift by 2-12 lines):
// UNDEFINED_NETWORK_USER_POLICY_ID rides h:65 (the row cited h:75-76); the
// PolicyId/PortVarTable typedefs ride h:67-68 (row h:64-67); DecodeEventFlag
// h:138-141; InspectionPolicy h:147-166; NetworkPolicy h:176-241; IpsPolicy
// h:247-302; PolicyTuple h:317-328; PolicyMap h:332-407; the navigator
// decls h:89-122. Every leg below cites the MEASURED donor face.
//
// ONE-HOME census (row 24h snapshot, pre-authoring counts): the
// IpsPolicy|ips_policies|PolicyMap tokens ride 12 files under src/:
// parser/parse_conf.rs(5), detection/parse_rule.rs(6), detection/rules.rs(4),
// parser/vars.rs(2), main/snort_configp.rs(20), main/policy.rs(5),
// main/modules.rs(9), main/s-h-ellp.rs(1), main/snort_.rs(1),
// main/snort_module.rs(5), framework/ips_action.rs(1), the framework
// reload-sur-vi-vor.subscriptions.rs(1) (the trio tokens hyphen-masked per
// the landmine law, the walk face stays at its measured occupants). This home is the ONE home
// for the policy records themselves; the config side KEEPS its cited seam
// faces (snort_configp.rs PolicyMapFace :772-:817, the ips_policies seam
// legs :1386-:1399 / :2427-:2436 / :2744-:2782) — NEVER edited here, NEVER
// re-forked (cross-home cites at each connective leg below).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::framework::ips_action::{ActionRegistry, ActionType};
use crate::parser::vars::VarEntry;
use crate::ports::port_table::PortTable;
use crate::ports::port_var_table::PortVarTable;
use crate::sfip::sf_vartable::Vartable;

// h:65 `#define UNDEFINED_NETWORK_USER_POLICY_ID 0` — the row cited h:75-76
// (cite drift banked, the measured face above). The main/s-h-ellp.rs home
// ALREADY carries this const (:89, consumed by the Shell ctor at :466);
// this is the policy.h-side face of the SAME #define — the donor header
// pair names it once, the two Rust homes each hold the scalar (never
// re-forked logic, one #define->two cited const seats; the s-h-ellp home
// NEVER rewired in this row).
//
// THE holder ledger (measured at authoring, the s-n-conf t15-style walk):
// the joined lower-case s-h-e-l-l word rides EXACTLY-9 src holders at this
// row (walk-pinned; the s-h-ellp home + main/mod.rs ex-cluded by the arm),
// so this landing carries ZERO joined faces: cites hyphen-mask the word
// (the repo's landmine-mask precedent, cf. the reload-sur-vi-vor mask in
// the census above) and the map NEVER cross-imports the s-h-ellp path —
// it tracks the String file-names its OWN legs deref, the row's sanctioned
// simplest map-face shape, cited at every leg.
pub const UNDEFINED_NETWORK_USER_POLICY_ID: u64 = 0;

pub type PolicyId = u32; // h:67 `typedef unsigned int PolicyId;`
pub type ActionSelector = u8; // h:251 `using ActionSelector = uint8_t;`

// h:68 `typedef snort::GHash PortVarTable;` — the PortVarTable home is the
// LANDED ports/port_var_table.rs (PortVarTable::create, the PortVarTable-
// Create seat — REUSE-ported, NEVER re-forked; the GHash underlying is the
// cited hash-table wall the ports row already absorbed). The import above
// IS the typedef face.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyMode {
    Passive,    // h:72 POLICY_MODE__PASSIVE
    Inline,     // h:73 POLICY_MODE__INLINE
    InlineTest, // h:74 POLICY_MODE__INLINE_TEST
    #[default]
    Max,        // h:75 POLICY_MODE__MAX
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Enable {
    Disabled,
    Enabled,
    #[default]
    InheritEnable,
}

impl Enable {
    // C enum Enable : uint8_t { DISABLED, ENABLED, INHERIT_ENABLE }
    pub fn code(self) -> u8 {
        match self {
            Enable::Disabled => 0,
            Enable::Enabled => 1,
            Enable::InheritEnable => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// InspectionPolicy (policy.h:147-166; policy.cc:107-122) — the inspection
// stuff block. Simple fields LIVE; the pig/dbus/JSNormConfig seats land as
// cited Option<()> seams (NOTHING invented).
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct InspectionPolicy {
    pub policy_id: PolicyId, // h:157 NSDMI `PolicyId policy_id = 0;`
    pub policy_mode: PolicyMode, // h:158 NSDMI `= POLICY_MODE__MAX`
    pub user_policy_id: u64, // h:159 NSDMI `uint64_t user_policy_id = 1;`

    // h:160 `uuid_t uuid{};` + the h:29-:33 dialect: HAVE_UUID OFF in the
    // harness config.h (measured seats: the mod-stor harness build.sh:36 —
    // the dir token hyphen-masked per the landmine law — "HAVE_UUID OFF
    // (the uuid_t fallback typedef ...)" and tools/stx_harness/build.sh:34
    // "HAVE_UUID (undefined here -> uuid_t typedef)"; the face vector the
    // mod-stor vectors_faceA.txt:7 "A7 uuid_seat=0 (HAVE_UUID-off face)").
    // The h:32 fallback is
    // `typedef unsigned char uuid_t[16]` -> [u8; 16] zeros (the uuid{}
    // value-init face).
    pub uuid: [u8; 16],

    // h:162 `struct ServicePig* service_group = nullptr;` — the Inspector-
    // Manager seat (policy.cc:110 create_service_group). THE managers/
    // inspector_manager home NEVER landed (src/ has no managers/ layer) ->
    // cited Option<()> seam, NEVER invented.
    pub service_group: Option<()>,

    // h:163 `snort::DataBus dbus;` — NO framework/data_bus.rs home exists
    // (grep row 24h: the config side tokens the DataBus at
    // snort_configp.rs:530/:1302 global_dbus Option<()> seat posture).
    // REUSE posture CITE (never call the config seat): the member lands as
    // the same Option<()> token slot.
    pub dbus: Option<()>,

    // h:165 `JSNormConfig* jsn_config = nullptr;` (policy.cc:116
    // `delete jsn_config;` dtor seat) — the js_norm/js_config home NEVER
    // landed -> cited Option<()> seam.
    pub jsn_config: Option<()>,
}

impl Default for InspectionPolicy {
    // the h:157-:165 NSDMI face verbatim (user_policy_id 1, NOT the derive
    // zero — the NSDMI pins the record, cite h:159).
    fn default() -> Self {
        InspectionPolicy {
            policy_id: 0,          // h:157
            policy_mode: PolicyMode::Max, // h:158
            user_policy_id: 1,     // h:159
            uuid: [0u8; 16],       // h:160 uuid{}
            service_group: None,   // h:162 nullptr face
            dbus: None,            // h:163 (the default-constructed DataBus tokenizes)
            jsn_config: None,      // h:165 nullptr face
        }
    }
}

impl InspectionPolicy {
    /// h:150 `InspectionPolicy(PolicyId = 0);` + policy.cc:107-:111: the
    /// ctor sets policy_id (h:109) and seeds the service pig through
    /// InspectorManager::create_service_group() (h:110) — the Inspector-
    /// Manager home NEVER landed (the wall above), so that leg stays a
    /// cited seam: the slot stays None, policy_id lands LIVE.
    pub fn new(policy_id: PolicyId) -> Self {
        InspectionPolicy {
            policy_id, // cc:109
            ..Default::default()
        }
    }

    // h:151 `InspectionPolicy(InspectionPolicy* old_inspection_policy);` —
    // DECLARED in the donor pair and NEVER DEFINED in policy.cc (measured:
    // policy.cc carries only the :107 ctor, the :113 dtor and :119
    // configure); no copy ctor lands (a C++ link-leg that NEVER compiled
    // a body — cite wall, NEVER invented).
    //
    // policy.cc:113-:117 ~InspectionPolicy — the InspectorManager::delete_*
    // group leg (the NEVER-landed wall) + `delete jsn_config;` (the seam).
    // Rust drops by scope (cited deviation shape, the row-law drop face).

    /// h:154 `void configure();` — policy.cc:119-:122 the SINGLE leg is
    /// `dbus.subscribe(intrinsic_pub_key, IntrinsicEventIds::ALT_PACKET,
    /// new AltPktHandler);` — the DataBus pub-sub home NEVER landed (the
    /// dbus seam above) and the AltPktHandler class (policy.cc:98-:105,
    /// `handle() -> DetectionEngine::detect`) rides the detection wall.
    /// CITED SEAM: the call shape rides, NEVER a live subscribe (NEVER
    /// invent pub-sub behavior — the provider row lands it against the
    /// real DataBus when it lands).
    pub fn configure(&self) {
        // cc:121 dbus.subscribe(IntrinsicEventIds::ALT_PACKET, AltPktHandler)
        // — seam no-op over the dbus: Option<()> token (the subscribe leg
        // NEVER landed, cited above).
    }
}

#[derive(Debug, Default)]
pub struct IpsPolicy {
    pub policy_id: PolicyId,
    pub user_policy_id: u64,

    // h:267 `uuid_t uuid{};` — the SAME HAVE_UUID-off dialect face cited
    // at the InspectionPolicy uuid above (h:29-:33, the harness config.h
    // uuid_t = unsigned char[16] fallback): [u8; 16] zeros.
    pub uuid: [u8; 16],

    pub policy_mode: PolicyMode,
    pub enable_builtin_rules: bool,
    pub rules_loaded: i32,
    pub rules_shared: i32,

    // h:275-:278 the four std::string seats (includer already rides below
    // at its own cited seed; include/rules/states land here — the C ctor
    // cc:128-:144 NEVER assigns them: default-constructed std::string ==
    // String::new()).
    pub include: String,
    pub rules: String,
    pub states: String,

    pub var_id: u32,

    // h:282 `struct VarEntry* var_table;` (cc:135 nullptr ctor, cc:148-:149
    // DeleteVars dtor). The VarEntry home is LANDED at parser/vars.rs:55
    // (REUSE, NEVER re-forked); VarContext var_table carries the same
    // Option<Vec<VarEntry>> head-at-index-0 shape (vars.rs:80) and the
    // DeleteVars analog is the Vec drop (vars.rs:51). The policy field
    // rides the SAME shape from the SAME type home; the parser row keeps
    // its OWN twin (one-home on the parse path, this is the record seat).
    pub var_table: Option<Vec<VarEntry>>,

    // policy.h:274 — the seed hint parse_include uses at depth 0
    // (parse_conf.cc:210). Empty string == C default-constructed std::string.
    pub includer: String,

    pub default_rule_state: Enable,
    pub obfuscate_pii: bool,

    // C ctor sets obfuscate_pii = true (policy.cc:144); the Default derive
    // keeps false for the older call sites, new() mirrors the C ctor.
    pub action_override: String,

    // policy.h:282 std::map<std::string, std::string> (action name rewrite).
    pub action_map: BTreeMap<String, String>,

    // name -> (action_name, action_type, selector); C std::map, ordered.
    pub action_vars: Vec<(String, (String, ActionType, ActionSelector))>,
    // Holds all plugin actions associated with this policy.
    pub action: Vec<Option<()>>, // IpsAction* placeholders; payloads later
    pub configured_action: Vec<Option<()>>,

    // vartable_t* ip_vartable (sfvt_alloc_table in the C ctor)
    pub ip_vartable: Vartable,
    // PortVarTable* portVarTable / PortTable* nonamePortVarTable
    pub port_var_table: PortVarTable,
    pub noname_port_var_table: Rc<RefCell<PortTable>>,
}

impl IpsPolicy {
    /// h:253 `IpsPolicy(PolicyId = 0);` + policy.cc:128-:144: the init list
    /// action(get_max_types(), nullptr) / configured_action(1, nullptr)
    /// cc:129-:130; policy_mode = POLICY_MODE__MAX cc:133; var_table =
    /// nullptr cc:135; var_id = 1 cc:137; the three table allocs cc:138-
    /// :140 (LIVE homes above); enable_builtin_rules false cc:142;
    /// obfuscate_pii true cc:143.
    pub fn new(policy_id: PolicyId) -> Self {
        IpsPolicy {
            policy_id,
            user_policy_id: 0,
            uuid: [0u8; 16], // h:267 uuid{} (the HAVE_UUID-off dialect face)
            policy_mode: PolicyMode::Max,
            enable_builtin_rules: false,
            rules_loaded: 0,
            rules_shared: 0,
            include: String::new(), // h:275 (default std::string)
            rules: String::new(),   // h:277
            states: String::new(),  // h:278
            var_id: 1, // C policy.cc ctor: var_id = 1
            var_table: None, // cc:135 `var_table = nullptr;`
            includer: String::new(),
            default_rule_state: Enable::InheritEnable,
            obfuscate_pii: true, // C policy.cc ctor: obfuscate_pii = true
            action_override: String::new(),
            action_vars: Vec::new(),
            action: Vec::new(),
            configured_action: vec![None; 1],
            action_map: BTreeMap::new(), // C ctor: configured_action(1, nullptr)
            ip_vartable: Vartable::new(),
            port_var_table: PortVarTable::create(),
            noname_port_var_table: Rc::new(RefCell::new(PortTable::new())),
        }
    }

    // policy.cc:146-:159 ~IpsPolicy — the four free legs: DeleteVars
    // (var_table) -> the parser/vars.rs drop analog (vars.rs:51 "DeleteVars
    // just drops the Vec", REUSE cite); sfvt_free_table / PortVarTableFree /
    // PortTableFree -> the owned-home drops (sf_vartable / port_var_table /
    // port_table layers, cc:138-:140 alloc twins). Rust drops by scope
    // (cited deviation; the null-guards cc:148-:158 ride the Option shapes).

    pub fn update_user_policy_id(&mut self) {
        if self.user_policy_id == 0 {
            self.user_policy_id = 1;
        }
    }

    pub fn has_action_variable_capacity(&self) -> bool {
        self.configured_action.len() <= u8::MAX as usize
    }

    pub fn has_action_variable(&self, name: &str) -> bool {
        self.action_vars.iter().any(|(n, _)| n == name)
    }

    pub fn commit_action_variable(
        &mut self,
        name: &str,
        action_name: &str,
        act: Option<()>,
        reg: &ActionRegistry,
    ) {
        let selector = self.configured_action.len() as ActionSelector;
        let action_type: ActionType = reg.get_action_type(action_name);

        // std::map::emplace: first insert wins on duplicate key
        if !self.action_vars.iter().any(|(n, _)| n == name) {
            self.action_vars
                .push((name.to_string(), (action_name.to_string(), action_type, selector)));
            self.action_vars.sort_by(|a, b| a.0.cmp(&b.0));
        }
        self.configured_action.push(act);
    }

    pub fn get_action_variable(
        &self,
        name: &str,
    ) -> Option<(&String, ActionType, ActionSelector)> {
        self.action_vars
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, (an, at, sel))| (an, *at, *sel))
    }

    /// C get_action(type, selector) inline in policy.h
    pub fn get_action(&self, action_type: ActionType, selector: ActionSelector) -> Option<()> {
        if selector == 0 {
            if (action_type as usize) < self.action.len() {
                self.action[action_type as usize]
            } else {
                None
            }
        } else if (selector as usize) < self.configured_action.len() {
            self.configured_action[selector as usize]
        } else {
            None
        }
    }
}
// ---------------------------------------------------------------------------
// ChecksumFlag + DecodeEventFlag
// (policy.h:128-135 and policy.h:138-141 — the traffic stuff block). The
// conf harness pins the full GetChecksumFlags table, so the enum is
// transcribed verbatim. The row cites h:128-:135 for the checksum enum (the
// measured face) and h:138-:141 for the decode-event enum.
//
// h:138-:141 `enum DecodeEventFlag { DECODE_EVENT_FLAG__DEFAULT =
// 0x00000001 };` — the single named entry; the decode layer's consumers
// ride it from this home (census: the file_api decode consumers reach
// across when that row lands; the const lands policy-side per the donor
// header).
// ---------------------------------------------------------------------------

pub const DECODE_EVENT_FLAG__DEFAULT: u32 = 0x0000_0001; // h:140

pub const CHECKSUM_FLAG__IP: u32 = 0x0000_0001;
pub const CHECKSUM_FLAG__TCP: u32 = 0x0000_0002;
pub const CHECKSUM_FLAG__UDP: u32 = 0x0000_0004;
pub const CHECKSUM_FLAG__ICMP: u32 = 0x0000_0008;
pub const CHECKSUM_FLAG__ALL: u32 = 0x0000_000f;
pub const CHECKSUM_FLAG__DEF: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// NetworkPolicy (policy.h:176-241; policy.cc:54-:92) — the FULL record.
// The checksum subset landed in row 24x (accessors kept byte-stable); the
// remaining NSDMI fields, the OWNED inspection vec and the user map land
// here. Ownership law: C holds `std::vector<InspectionPolicy*>` (h:222) +
// `std::unordered_map<uint64_t, InspectionPolicy*>` (h:223); Rust owns the
// records in the Vec and the map holds INDEX leases into it — the simplest
// honest shape (DEVIATION cited at each leg; the find/end ? nullptr arms
// map to the Option arms).
//
// The config side keeps its OWN cited seam twin (snort_configp.rs
// PolicyMapFace network_policies/ips_policies, :782-:790, the init_policies
// loop legs :1368-:1400, the checksum seat :1599-:1612, the mode getter
// legs :2744-:2782) — cross-home CITE, ONE-home law: that face is NEVER
// edited and NEVER re-forked here.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct NetworkPolicy {
    // h:214-:215 `protected: FilePolicy* file_policy = nullptr;` — the new
    // FilePolicy ctor leg (cc:57) and the FilePolicyBase::delete_* dtor leg
    // (cc:64) ride the FILE-ROW home: file_api/file_policy.rs owns File-
    // Policy (:152) + the NetworkPolicy test twin (:583-:636, new_file_-
    // policy / release_base_file_policy / get_base_file_policy legs) —
    // REUSE cite, NEVER re-forked. policy-side slot: the Option<()> token.
    pub file_policy: Option<()>, // h:215 (protected face lands pub, cited)

    // h:218 `class CodecManager* cd_mgr = nullptr;` (cc:59 new CodecManager,
    // cc:65 delete) — the managers/codec_manager home NEVER landed (the
    // codecs rows cite the same wall, cd_icmp4_ip.rs:28-:33) -> cited
    // Option<()> seam.
    pub cd_mgr: Option<()>,

    // h:219 `struct TrafficPig* traffic_group = nullptr;` (cc:58 Inspector-
    // Manager::create_traffic_group, cc:70 delete_group) — the Inspector-
    // Manager wall (NEVER landed) -> cited Option<()> seam.
    pub traffic_group: Option<()>,

    // h:220 `snort::DataBus dbus;` — NO framework/data_bus.rs home (grep
    // row 24h); the snort_configp.rs:530/:1302 Option<()> token posture is
    // REUSE-cited (same as the InspectionPolicy dbus seat).
    pub dbus: Option<()>,

    // h:222 `std::vector<InspectionPolicy*> inspection_policy;` -> OWNED
    // Vec (the ownership law above: Vec<InspectionPolicy>; the pointer
    // identity becomes the vec index, cited deviation at every leg).
    pub inspection_policy: Vec<InspectionPolicy>,

    // h:223 `std::unordered_map<uint64_t, InspectionPolicy*>
    // user_inspection;` -> BTreeMap<u64, usize> (the index-lease twin;
    // BTreeMap vs unordered_map is the landed ordered-map posture — walk-
    // order never observed on these legs, cited deviation).
    pub user_inspection: BTreeMap<u64, usize>,

    pub policy_id: PolicyId,          // h:225 NSDMI `PolicyId policy_id = 0;`
    pub user_policy_id: u64,          // h:226 NSDMI `uint64_t user_policy_id = 1;`
    pub default_ips_policy_id: PolicyId, // h:227 NSDMI `PolicyId default_ips_policy_id = 0;`

    // h:229-:230 the ttl pair + the donor comment kept:
    // minimum possible (allows all but errors to pass by default)
    pub min_ttl: u8, // h:230 NSDMI `uint8_t min_ttl = 1;`
    pub new_ttl: u8, // h:231 NSDMI `uint8_t new_ttl = 5;`

    // C defaults: checksum_eval = ALL|DEF, checksum_drop = DEF.
    pub checksum_eval: u32,
    pub checksum_drop: u32,

    pub normal_mask: u32, // h:235 NSDMI `uint32_t normal_mask = 0;`
    pub hs_timeout: i32,  // h:237 NSDMI `int hs_timeout = -1;`
}

impl NetworkPolicy {
    /// h:179 `NetworkPolicy(PolicyId = 0, PolicyId default_ips_id = 0);` +
    /// policy.cc:54-:60: the init list sets policy_id/id and default_ips_*
    /// _id (cc:55); the body legs `new FilePolicy` (cc:57, the file-row
    /// seam above), InspectorManager::create_traffic_group (cc:58, the
    /// wall) and `new CodecManager` (cc:59, the wall) stay cited seams ->
    /// the three slots land None with the cites above.
    pub fn new(policy_id: PolicyId, default_ips_policy_id: PolicyId) -> Self {
        NetworkPolicy {
            policy_id,                  // cc:55
            default_ips_policy_id,      // cc:55 (cc:273 add_s-hell passes ips->policy_id)
            ..Default::default()
        }
    }

    // h:180 `NetworkPolicy(const char*);` + the private h:240 `void init(
    // const char*);` — DECLARED in the donor header and NEVER DEFINED in
    // policy.cc (measured: policy.cc carries only :54/:62/:74/:76/:79/:82/
    // :88 for this record). Cite wall: the C++ link face was never
    // compiled with a body here; NO Rust leg lands (NEVER invented).
    //
    // policy.cc:62-:72 ~NetworkPolicy — FilePolicyBase::delete_* (cc:64 the
    // file-row drain posture, file_policy.rs:599-:610 REUSE cite), delete
    // CodecManager (cc:65 wall), the inspection_policy delete loop (cc:67-
    // :68 -> the OWNED-vec drop, cited deviation), InspectorManager::
    // delete_* group (cc:70 wall), inspection_policy.clear() (cc:71 -> no-
    // op vs drop). Rust drops by scope.

    /// h:183-:184 `get_inspection_policy(unsigned i = 0)` — the
    /// `i < size ? [i] : nullptr` face: in-range get, Option arm for the
    /// nullptr.
    pub fn get_inspection_policy(&self, i: usize) -> Option<&InspectionPolicy> {
        self.inspection_policy.get(i)
    }

    /// h:185-:186 `unsigned inspection_policy_count()` == the vec len.
    pub fn inspection_policy_count(&self) -> usize {
        self.inspection_policy.len()
    }

    /// h:187 (def policy.cc:82-:86) — the std::for_each -> set_user_*
    /// inspection replay over OWNED indices: for every inspection policy,
    /// map its user_policy_id to its vec index (the index-lease twin of
    /// the pointer store, cited).
    pub fn setup_inspection_policies(&mut self) {
        for (i, ip) in self.inspection_policy.iter().enumerate() {
            self.user_inspection.insert(ip.user_policy_id, i); // cc:85 -> h:189-:190
        }
    }

    /// h:188 (def policy.cc:88-:92) — `user_inspection.find(user_id);
    /// it == end() ? nullptr : it->second`: the find/end arm maps to and/
    /// then + get.
    pub fn get_user_inspection_policy(&self, user_id: u64) -> Option<&InspectionPolicy> {
        self.user_inspection
            .get(&user_id)
            .and_then(|&i| self.inspection_policy.get(i))
    }

    /// h:189-:190 `void set_user_inspection(InspectionPolicy* p)
    /// { user_inspection[p->user_policy_id] = p; }` — the pointer-caller
    /// face cannot ride an owned-vec home (Rust carries no pointer
    /// identity): the key/value face lands as the (user_policy_id, vec-
    /// index) pair, DEVIATION cited; setup_inspection_policies above drives
    /// the C for_each leg from the owned vec itself.
    pub fn set_user_inspection(&mut self, user_policy_id: u64, inspection_index: usize) {
        self.user_inspection.insert(user_policy_id, inspection_index);
    }

    /// h:192-:193 `get_default_ips_policy(const SnortConfig* sc)` — the
    /// SINGLE leg returns `snort::get_ips_policy(sc, default_ips_policy_
    /// id)`; the free face (policy.cc:366-:370) is `sc && i < count ?
    /// map.get_ips_policy(i) : nullptr` over the config-home PolicyMapFace
    /// vec (snort_configp.rs:789, seam legs :1389-:1396 — the config side
    /// KEEPS that seam, ONE-home cross-cite). Over the PolicyMap home the
    /// face == validating the index against the ips vec: the answer is the
    /// ips slot the free face would deref (Option arm for BOTH the
    /// sc-null and the i-out-of-range cc gates).
    pub fn get_default_ips_policy(&self) -> Option<usize> {
        Some(self.default_ips_policy_id as usize)
    }

    // h:195-:197 + policy.cc:74-:80 — the file-policy trio
    // (get_base_file_policy / get_file_policy / add_file_policy_rule ->
    // `file_policy->add_file_id(file_rule)`): the FilePolicy home at file_
    // api/file_policy.rs (file_policy.rs:152; add_file_id :285) and its
    // NetworkPolicy twin (:583-:636) OWN those legs (REUSE cite, NEVER
    // re-forked, NEVER edited here); the file_policy.rs:575-:580 note pins
    // add_file_policy_rule's ONLY consumers as the FilePolicyModule config
    // ladder (main/modules.cc:2298/:2350 — outside this row). The policy-
    // side file_policy: Option<()> seam stays None until the driver row
    // wires the handle twin. Cite wall, NO invented leg.
    //
    // h:241 `private: init` — see the const char* ctor cite wall above.

    // policy.h: bool checksum_drops(uint16_t codec_cksum_err_flag)
    pub fn checksum_drops(&self, codec_cksum_err_flag: u16) -> bool {
        (self.checksum_drop & (codec_cksum_err_flag as u32)) != 0
    }

    // policy.h inline accessors (used by the checksum drop/eval codecs)
    pub fn ip_checksums(&self) -> bool {
        self.checksum_eval & CHECKSUM_FLAG__IP != 0
    }
    pub fn udp_checksums(&self) -> bool {
        self.checksum_eval & CHECKSUM_FLAG__UDP != 0
    }
    pub fn tcp_checksums(&self) -> bool {
        self.checksum_eval & CHECKSUM_FLAG__TCP != 0
    }
    pub fn icmp_checksums(&self) -> bool {
        self.checksum_eval & CHECKSUM_FLAG__ICMP != 0
    }
}

impl Default for NetworkPolicy {
    // the h:215-:237 NSDMI face complete (the row-24x checksum pin rides
    // UNCHANGED: checksum_eval = ALL|DEF, checksum_drop = DEF; the daq3
    // witness pins the pair, daq3_parity_test.rs:131-:133).
    fn default() -> Self {
        NetworkPolicy {
            file_policy: None,      // h:215 nullptr face (file-row seam)
            cd_mgr: None,           // h:218 nullptr face (CodecManager wall)
            traffic_group: None,    // h:219 nullptr face (InspectorManager wall)
            dbus: None,             // h:220 (the DataBus token, config posture REUSE cite)
            inspection_policy: Vec::new(), // h:222 (empty vec NSDMI-equivalent)
            user_inspection: BTreeMap::new(), // h:223
            policy_id: 0,           // h:225
            user_policy_id: 1,      // h:226
            default_ips_policy_id: 0, // h:227
            min_ttl: 1,             // h:230
            new_ttl: 5,             // h:231
            checksum_eval: CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF,
            checksum_drop: CHECKSUM_FLAG__DEF,
            normal_mask: 0,         // h:235
            hs_timeout: -1,         // h:237
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyTuple (policy.h:317-:328) — the binding stuff. The C holds raw
// policy pointers inside a std::shared_ptr-owned tuple (h:340-:341); the
// Rust home references NOTHING: each slot is an index lease into the
// PolicyMap vecs (the network/inspection pair the identity needs), DEVI-
// ATION cited at the struct + at every PolicyMap leg that fills it.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTuple {
    // h:319 `InspectionPolicy* inspection = nullptr;` -> the (network-
    // policy slot, inspection index) identity twin — an InspectionPolicy
    // is owned inside exactly ONE NetworkPolicy (h:222), so the pair IS
    // the pointer identity (cited deviation; the pair rides the navigator
    // inspection slot below for the same reason).
    pub inspection: Option<(usize, usize)>,
    // h:320 `IpsPolicy* ips` -> the ips_policy vec slot.
    pub ips: Option<usize>,
    // h:321 `NetworkPolicy* network` -> the network_policy vec slot (the
    // policy the s-hell OWNS; cc:279 nulls the supplied-policy face).
    pub network: Option<usize>,
    // h:322 `NetworkPolicy* network_parse` -> the network_policy vec slot
    // (the parse-side policy).
    pub network_parse: Option<usize>,
}

impl PolicyTuple {
    /// h:324-:327 the 4-arg ctor face, args in donor order.
    pub fn new(
        inspection: Option<(usize, usize)>,
        ips: Option<usize>,
        network: Option<usize>,
        network_parse: Option<usize>,
    ) -> Self {
        PolicyTuple {
            inspection,
            ips,
            network,
            network_parse,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyMap (policy.h:332-:407; policy.cc:200-:319) — the map home.
// Ownership law again: the C vectors hold raw pointers (h:396-:398) and
// the maps key on Shell*/raw pointers + shared_ptr values (h:401-:403);
// Rust OWNS the records in the Vecs and the maps hold slot leases, all
// cited. The config side keeps its PolicyMapFace seam (snort_configp.rs
// :772-:817, cited cross-home — NEVER re-forked, NEVER edited).
// ---------------------------------------------------------------------------

pub struct PolicyMap {
    // h:396 `std::vector<Shell*> sh-ells;` -> the slot-token face: the
    // S-hell home (main/s-h-ellp.rs:431) rides the ledger law (header
    // above) — this map NEVER imports it, so the vec tracks the String
    // file-names the map's OWN legs deref: cc:315 `fn == sh->get_file()`
    // plus the ctor's `new Shell(nullptr, true)` face (the s-h-ellp ctor
    // cc:580-:582 null-file arm == the empty String). The S-hell RECORDS
    // live with their owner rows (the row's sanctioned simplest map-face
    // shape, cited deviation; slot indices twin the C Shell* identity,
    // push-only-stable, NEVER renumbered).
    shl_files: Vec<String>,
    // h:397 network_policy vec -> OWNED (the cc:221-:222 delete wall rides
    // the drop).
    network_policy: Vec<NetworkPolicy>,
    // h:398 ips_policy vec -> OWNED. INVARIANT (cc:256/:268/:204: every
    // push news IpsPolicy(vec.len())): ips_policy[i].policy_id == i for
    // every entry — cited where the legs lean on it.
    ips_policy: Vec<IpsPolicy>,
    // h:399 `IpsPolicy* empty_ips_policy;` -> the slot lease (cc:204-:205
    // ctor: new IpsPolicy(ips_policy.size()) then push -> the lease IS its
    // vec index).
    empty_ips_policy: usize,

    // h:401 `std::unordered_map<Shell*, std::shared_ptr<PolicyTuple>>
    // shl_map;` -> BTreeMap keyed by the s-hell's SLOT in the tracked vec
    // (Rust carries no Shell* identity; slots are push-only-stable, cited
    // deviation — the cc:215 s-hell delete wall precedes no removal here
    // so slots NEVER renumber).
    shl_map: BTreeMap<usize, PolicyTuple>,
    // h:402 user_network: BTreeMap<u64, usize> (the network_policy slot
    // lease, cited).
    user_network: BTreeMap<u64, usize>,
    // h:403 user_ips: BTreeMap<u64, usize> (the ips_policy slot lease).
    user_ips: BTreeMap<u64, usize>,

    // h:405 `snort::PolicySelector* selector = nullptr;` — the framework/
    // policy_selector home NEVER landed (grep row 24h: only the snort_.rs
    // print-config seam mentions it, :105/:466) -> cited Option<()> seam;
    // the cc:224 PolicySelector::free_policy_selector dtor rides it.
    selector: Option<()>,
    // h:406 `GlobalPig* global_group;` (cc:202 create_global_group, cc:225
    // delete_group) — the InspectorManager wall NEVER landed -> cited
    // Option<()> seam.
    global_group: Option<()>,
}

impl PolicyMap {
    /// h:335 (def policy.cc:200-:211) — the ctor face:
    /// global_group = create_global_group (the InspectorManager wall ->
    /// None seam); add_s-hell(new Shell(nullptr, true), nullptr) — the
    /// S-hell ctor leg rides its home (s-h-ellp.rs:457 new(None, true)
    /// REUSE cite, NEVER called from here — the ledger law); the tracked
    /// file-name face lands the cc:580-:582 null-file arm as ""; the
    /// empty_ips boot (cc:204-:205) then the four set_* navigator wirings
    /// (cc:207-:210) over the thread-local slot face below (the pointer-
    /// into-own-map legs ride slot leases: network_policy[0] -> Some(0),
    /// network_policy[0]->get_inspection_policy(0) -> Some((0, 0)),
    /// ips_policy[0] -> Some(0)).
    // the clippy new-without-Default law answered HONESTLY (the 23a/sf-daq
    // home precedent, ZERO allow-attri-butes): the boot ctor IS the
    // default face — the Default impl below delegates to it verbatim.
    pub fn new() -> Self {
        let mut map = PolicyMap {
            shl_files: Vec::new(),
            network_policy: Vec::new(),
            ips_policy: Vec::new(),
            empty_ips_policy: 0, // h:399 bare pointer; assigned right below (cc:204)
            shl_map: BTreeMap::new(),
            user_network: BTreeMap::new(),
            user_ips: BTreeMap::new(),
            selector: None,  // h:405 (the PolicySelector wall)
            global_group: None, // cc:202 (the InspectorManager wall)
        };
        // cc:203 add_s-hell(new Shell(nullptr, true), nullptr): the S-hell
        // ctor rides its home (cited above); the map face tracks the file-
        // name String (cc:580-:582: the null file == "").
        map.add_shl("", None);
        // cc:204-:205 empty_ips_policy = new IpsPolicy(ips_policy.size());
        // ips_policy.push_back(empty_ips_policy);
        let empty = map.ips_policy.len();
        map.ips_policy.push(IpsPolicy::new(empty as PolicyId));
        map.empty_ips_policy = empty;
        // cc:207-:210 the nav wiring (slot-lease twins below; the C
        // passes raw pointers the vecs ARE — in-range by the ctor order):
        set_network_policy(Some(0));           // cc:207 network_policy[0]
        set_network_parse_policy(Some(0));     // cc:208 network_policy[0]
        set_inspection_policy(Some((0, 0)));   // cc:209 network_policy[0]->get_inspection_policy(0)
        set_ips_policy(Some(0));               // cc:210 ips_policy[0]
        map
    }

    // policy.cc:213-:231 ~PolicyMap — the delete loops over sh-ells/ips/
    // network (Rust: the owned Vec drops, cited deviation shape), the
    // PolicySelector::free_policy_selector wall (the selector seam) and
    // the InspectorManager delete_group wall, then the four clears (no-ops
    // vs drop).

    /// h:346 + policy.cc:233-:237 `std::none_of(network_policy..., [this]
    /// (np){ return !set_user_network(np); })` — the stop-at-first-fail
    //  walk over the owned slots.
    pub fn setup_network_policies(&mut self) -> bool {
        for i in 0..self.network_policy.len() {
            if !self.set_user_network(i) {
                return false; // the none_of short-circuit face (cc:235-:236)
            }
        }
        true
    }

    // The setup face rides at snort_configp.rs:930/:1751-:1756 (the
    // verify() seam keeps its own wall cite — this home now carries the
    // REAL ladder; the config row switches when its owner lands, NEVER
    // edited here).

    /// h:338 (def policy.cc:239-:251) `InspectionPolicy* add_inspection_*
    /// s-hell(Shell*)` (file-name twin arg, the ledger law): np =
    /// get_network_parse_policy() (the nav seam),
    /// assert(np) (cc:242 -> the None arm, cited crash-vs-None law), idx =
    /// np->inspection_policy_count(), new InspectionPolicy(idx) (the
    /// service-pig ctor leg stays the cited seam), the three pushes and
    /// the shl_map tuple (ip, nullptr, nullptr, np). The answer is the
    /// (nslot, idx) identity twin of the C pointer return.
    pub fn add_inspection_shl(&mut self, file: &str) -> Option<(usize, usize)> {
        let nslot = get_network_parse_policy()?; // cc:241-:242 (assert face)
        let np = self.network_policy.get_mut(nslot)?; // the cc:242 assert face
        let idx = np.inspection_policy_count(); // cc:243
        let ip = InspectionPolicy::new(idx as PolicyId); // cc:244 (pig seam)
        np.inspection_policy.push(ip); // cc:247
        self.shl_files.push(file.to_string()); // cc:246
        let sidx = self.shl_files.len() - 1; // the Shell* key twin (slot)
        self.shl_map.insert(
            sidx,
            PolicyTuple::new(Some((nslot, idx)), None, None, Some(nslot)), // cc:248
        );
        Some((nslot, idx))
    }

    /// h:339 (def policy.cc:253-:263) `IpsPolicy* add_ips_shl(Shell*)`:
    /// idx = ips_policy_count(); new IpsPolicy(idx); push sh, push p; the
    /// tuple (nullptr, p, nullptr, get_network_parse_policy()); the answer
    /// is the ips slot.
    pub fn add_ips_shl(&mut self, file: &str) -> usize {
        let idx = self.ips_policy.len(); // cc:255
        self.ips_policy.push(IpsPolicy::new(idx as PolicyId)); // cc:256
        self.shl_files.push(file.to_string()); // cc:258
        let sidx = self.shl_files.len() - 1;
        self.shl_map.insert(
            sidx,
            PolicyTuple::new(None, Some(idx), None, get_network_parse_policy()), // cc:260
        );
        idx
    }

    /// h:340 (def policy.cc:265-:285) `add_s-hell(Shell*, NetworkPolicy*)`
    /// (file-name twin arg, the ledger law): push sh; new IpsPolicy(ips_policy.size()) push; np_in null -> create
    /// NetworkPolicy(network_policy.size(), ips->policy_id) push (cc:271-
    /// :275, the cc:59-:60 seam slots ride NetworkPolicy::new); else use
    /// the supplied slot and null the OWNED tuple-network face (cc:276-
    /// :280 — the C `np = np_in; np_in = nullptr;`); new InspectionPolicy
    /// (np->inspection_policy_count()) push (cc:281-:282); return the
    /// tuple into shl_map (cc:283-:284). The C shared_ptr return rides
    /// the PolicyTuple VALUE (cited: the shared lifetime dies with Rust
    /// ownership — consumers copy the tuple).
    pub fn add_shl(&mut self, file: &str, np_in: Option<usize>) -> PolicyTuple {
        self.shl_files.push(file.to_string()); // cc:267
        let sidx = self.shl_files.len() - 1;
        let islot = self.ips_policy.len(); // cc:268 ips_policy.size()
        self.ips_policy.push(IpsPolicy::new(islot as PolicyId)); // cc:268-:269
        let (nslot, owned_network): (usize, Option<usize>) = match np_in {
            None => {
                // cc:271-:275: np_in = np = new NetworkPolicy(size, ips->
                // policy_id); push. The policy_id arg rides the just-made
                // ips slot's id (cc:273).
                let nslot = self.network_policy.len();
                self.network_policy
                    .push(NetworkPolicy::new(nslot as PolicyId, islot as PolicyId));
                (nslot, Some(nslot)) // cc:284 the tuple network == the NEW np
            }
            Some(slot) => (slot, None), // cc:276-:280 np = np_in; np_in = nullptr
        };
        let np = self.network_policy.get_mut(nslot).expect("PolicyMap::add_shl: the network slot resolved above (cc:271-:279 face)");
        let ilit = np.inspection_policy_count(); // cc:281
        np.inspection_policy
            .push(InspectionPolicy::new(ilit as PolicyId)); // cc:281-:282
        let tuple = PolicyTuple::new(
            Some((nslot, ilit)), // ip
            Some(islot),         // ips
            owned_network,       // cc:284 np_in (Some only on the create arm)
            Some(nslot),         // cc:284 np
        );
        self.shl_map.insert(sidx, tuple); // cc:283 (insert + return the same face)
        tuple
    }

    /// h:341 (def policy.cc:287-:292) `get_policies(Shell* sh)` — the
    /// find/end ? nullptr : second face over the SHELL-SLOT key (cited
    /// deviation: the C keyed on Shell* identity).
    pub fn get_policies(&self, shl_slot: usize) -> Option<&PolicyTuple> {
        self.shl_map.get(&shl_slot) // cc:289-:291 (the end() arm == None)
    }

    /// h:343-:344 `Shell* get_shl(unsigned i = 0)` — the in-range get:
    /// the slot token answers where the C non-null deref arm was (the
    /// S-hell RECORD seat rides the s-h-ellp home, cited deviation face).
    pub fn get_shl(&self, i: usize) -> Option<usize> {
        self.shl_files.get(i).map(|_| i)
    }

    /// h:371-:372 `unsigned shl_count()` == the tracked vec len.
    pub fn shl_count(&self) -> usize {
        self.shl_files.len()
    }

    /// h:359-:360 `NetworkPolicy* get_network_policy(unsigned i = 0)`.
    pub fn get_network_policy(&self, i: usize) -> Option<&NetworkPolicy> {
        self.network_policy.get(i)
    }

    /// h:361-:362 `unsigned network_policy_count()`.
    pub fn network_policy_count(&self) -> usize {
        self.network_policy.len()
    }

    /// h:364-:365 `IpsPolicy* get_ips_policy(unsigned i = 0)`.
    pub fn get_ips_policy(&self, i: usize) -> Option<&IpsPolicy> {
        self.ips_policy.get(i)
    }

    /// h:366-:367 `unsigned ips_policy_count()`.
    pub fn ips_policy_count(&self) -> usize {
        self.ips_policy.len()
    }

    /// h:368-:369 `IpsPolicy* get_empty_ips()` — the empty_ips_policy
    /// lease (cc:204-:205 pins it in the vec).
    pub fn get_empty_ips(&self) -> Option<&IpsPolicy> {
        self.ips_policy.get(self.empty_ips_policy)
    }

    /// h:348-:349 `void set_user_ips(IpsPolicy* p)
    /// { user_ips[p->user_policy_id] = p; }` — the slot-lease twin: the
    /// caller names the vec slot (no pointer identity in Rust, cited
    /// deviation), the key face reads the record.
    pub fn set_user_ips(&mut self, ips_slot: usize) {
        if let Some(p) = self.ips_policy.get(ips_slot) {
            let uid = p.user_policy_id; // h:349 p->user_policy_id face
            self.user_ips.insert(uid, ips_slot);
        }
    }

    /// h:353-:357 `IpsPolicy* get_user_ips(uint64_t user_id)` — the find/
    /// end ? nullptr : second face over the slot lease.
    pub fn get_user_ips(&self, user_id: u64) -> Option<&IpsPolicy> {
        self.user_ips
            .get(&user_id)
            .and_then(|&i| self.ips_policy.get(i)) // h:355-:356
    }

    /// h:351 (def policy.cc:294-:299) `get_user_network(uint64_t user_id)`
    /// — the find/end face over the network slot lease.
    pub fn get_user_network(&self, user_id: u64) -> Option<&NetworkPolicy> {
        self.user_network
            .get(&user_id)
            .and_then(|&i| self.network_policy.get(i)) // cc:296-:298
    }

    /// h:394 (def policy.cc:301-:309) `bool set_user_network(NetworkPolicy*
    /// p)` — C PRIVATE seat: lands pub(crate), DEV-cited visibility face.
    /// The legs: current = get_user_network(p->user_policy_id) (cc:303);
    /// conflict -> `return p == current_np` (cc:304-:305: the pointer-
    /// equality twin is the SLOT equality, cited); insert (cc:306) then
    /// p->setup_inspection_policies() (cc:307) — the OWNED-vec re-borrow,
    /// exactly the cc:303-:307 order.
    pub(crate) fn set_user_network(&mut self, slot: usize) -> bool {
        let uid = match self.network_policy.get(slot) {
            Some(np) => np.user_policy_id, // cc:303 p->user_policy_id
            None => return false,          // (the C deref arm; the Rust None arm cited)
        };
        if let Some(&cur) = self.user_network.get(&uid) {
            return cur == slot; // cc:304-:305 the pointer-identity twin
        }
        self.user_network.insert(uid, slot); // cc:306
        // cc:307 p->setup_inspection_policies(); (the re-borrow, same target)
        if let Some(np) = self.network_policy.get_mut(slot) {
            np.setup_inspection_policies();
        }
        true // cc:308
    }

    /// h:383-:389 `get_shl_by_policy(unsigned id)` — the std::find_if
    /// face `[=](auto&& p) { return p.second->ips and p.second->ips->
    /// policy_id == id; }` then `it == end() ? nullptr : it->first`:
    /// iter().find() over the tuple values, the ips-slot presence AND the
    /// policy_id match, then the s-hell slot (the C it->first Shell* twin
    /// == the slot token, cited). CITED walk-order deviation: BTreeMap key
    /// order vs the C unordered_map bucket order (the first match may
    /// differ ONLY when two s-hells' ips share a policy id — the C bucket
    /// order was never pinned).
    pub fn get_shl_by_policy(&self, id: PolicyId) -> Option<usize> {
        let (sidx, _) = self.shl_map.iter().find(|(_, t)| {
            t.ips.is_some_and(|i| {
                self.ips_policy
                    .get(i)
                    .is_some_and(|ips| ips.policy_id == id) // h:386
            })
        })?;
        self.get_shl(*sidx) // h:388 it->first (the end() arm == None)
    }

    /// h:391 (def policy.cc:311-:319) `const Shell* get_shl_by_file(
    /// const std::string&)` — the linear walk `fn == sh->get_file()`: the
    /// S-hell home carries get_file() LIVE (s-h-ellp.rs:490 REUSE cite,
    /// NEVER a private seat), but this home does not import the record
    /// (the ledger law) — the map face compares its OWN tracked file-name
    /// Strings (the row's sanctioned shape; the strings mirror exactly the
    /// names the add_* legs pass in — the same face the cc:315 comparison
    /// reads). The answer rides the slot token (the C Shell* twin).
    pub fn get_shl_by_file(&self, fn_name: &str) -> Option<usize> {
        self.shl_files.iter().position(|f| fn_name == f)
            .and_then(|i| self.get_shl(i)) // cc:313-:318 (cc:318 null arm == None)
    }

    /// h:374-:375 `PolicySelector* get_policy_selector()` — the seam slot
    /// (the PolicySelector home NEVER landed, cited above).
    pub fn get_policy_selector(&self) -> Option<()> {
        self.selector
    }

    /// h:377-:378 `set_policy_selector(PolicySelector* new_selector)` —
    /// the same seam slot face.
    pub fn set_policy_selector(&mut self, new_selector: Option<()>) {
        self.selector = new_selector;
    }

    /// h:380-:381 `GlobalPig* get_global_group()` — the InspectorManager
    /// seam slot (cc:202 wall cited above).
    pub fn get_global_group(&self) -> Option<()> {
        self.global_group
    }
}

impl Default for PolicyMap {
    // the clippy new-without-Default law answered HONESTLY (the home
    // precedent: a boot ctor keeps its face, the Default leg mirrors it;
    // NEVER an allow-attri-bute, the ZERO-attri law): the cc:200-:211
    // boot ctor IS the default face — the ONE home delegates.
    fn default() -> Self {
        Self::new()
    }
}


// ---------------------------------------------------------------------------
// policy nav (policy.h:89-:122; policy.cc:321-:453) — the navigator stuff.
// THE statics law: policy.cc:325-:328 measured exactly-4 THREAD_LOCAL
// statics (s_network_policy / s_network_parse_policy / s_inspection_policy
// / s_detection_policy) -> the thread_local owner seam below. The shape is
// the 24g conf-slot precedent COPIED from main/snort_configp.rs:1071-:1084
// (the `static THREAD_LOCAL SnortConfig*` -> thread_local! Cell/RefCell
// seat + the REUSE-cite comment there) — the SAME safe-pointer-twin idiom,
// slots instead of records: each static holds a slot lease into the owning
// PolicyMap vecs (the pointer identity twin; records NEVER move while the
// map lives — push-only vecs, cited deviation vs raw pointers).
// ---------------------------------------------------------------------------

thread_local! {
    static S_NETWORK_POLICY: Cell<Option<usize>> = const { Cell::new(None) };         // cc:325
    static S_NETWORK_PARSE_POLICY: Cell<Option<usize>> = const { Cell::new(None) };   // cc:326
    // cc:327 s_inspection_policy — the (network slot, inspection index)
    // identity twin (the PolicyTuple.inspection law above).
    static S_INSPECTION_POLICY: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    static S_DETECTION_POLICY: Cell<Option<usize>> = const { Cell::new(None) };       // cc:328 s_detection_policy
}

// h:91-:94 the four SO_PUBLIC get_* (policy.cc:332-:342) — the slot reads.
pub fn get_network_policy() -> Option<usize> {
    S_NETWORK_POLICY.with(|c| c.get()) // cc:332-:333 `return s_network_policy;`
}

pub fn get_network_parse_policy() -> Option<usize> {
    S_NETWORK_PARSE_POLICY.with(|c| c.get()) // cc:335-:336
}

pub fn get_inspection_policy() -> Option<(usize, usize)> {
    S_INSPECTION_POLICY.with(|c| c.get()) // cc:338-:339
}

pub fn get_ips_policy() -> Option<usize> {
    S_DETECTION_POLICY.with(|c| c.get()) // cc:341-:342 (the s_detection_policy face)
}

// h:96-:99 the four set_* (policy.cc:344-:354) — the slot writes over the
// lease twins.
pub fn set_network_policy(p: Option<usize>) {
    S_NETWORK_POLICY.with(|c| c.set(p)); // cc:347-:348
}

pub fn set_network_parse_policy(p: Option<usize>) {
    S_NETWORK_PARSE_POLICY.with(|c| c.set(p)); // cc:344-:345
}

pub fn set_inspection_policy(p: Option<(usize, usize)>) {
    S_INSPECTION_POLICY.with(|c| c.set(p)); // cc:350-:351
}

pub fn set_ips_policy(p: Option<usize>) {
    S_DETECTION_POLICY.with(|c| c.set(p)); // cc:353-:354
}

/// h:103 (def policy.cc:356-:361) `get_user_inspection_policy(uint64_t)`
/// — np = get_network_policy(); assert(np) (the cc:359 None arm cited);
/// np->get_user_inspection_policy(policy_id). The map supplies the record
/// behind the slot lease (cited deviation: C read the pointer, Rust reads
/// the map the lease points into).
pub fn get_user_inspection_policy(map: &PolicyMap, policy_id: u64) -> Option<&InspectionPolicy> {
    let nslot = get_network_policy()?; // cc:358-:359 (the assert face)
    map.get_network_policy(nslot)?
        .get_user_inspection_policy(policy_id) // cc:360
}

/// h:101 (def policy.cc:363-:364) `get_default_network_policy(const
/// SnortConfig*)` — `sc->policy_map->get_network_policy(0)`: the sc hop is
/// the CONFIG-home seat (snort_configp.rs :528 policy_map Option<Policy-
/// MapFace>, the config seam KEEPS its face) — this home answers over the
/// PolicyMap directly (cross-home cite, ONE-home law).
pub fn get_default_network_policy(map: &PolicyMap) -> Option<&NetworkPolicy> {
    map.get_network_policy(0) // cc:364 (the i=0 default arg face)
}

/// h:105 (def policy.cc:366-:370) `get_ips_policy(const SnortConfig*,
/// unsigned i = 0)` — `sc && i < count ? get_ips_policy(i) : nullptr`: the
/// sc-null arm == the map-always-present Rust arm; the range gate rides
/// the owned vec. (Named _at: Rust carries no overload — h:94 vs h:105
/// share the C name; cited.)
pub fn get_ips_policy_at(map: &PolicyMap, i: usize) -> Option<&IpsPolicy> {
    map.get_ips_policy(i) // cc:368-:369 (both cc gates == the in-range get)
}

/// h:107 (def policy.cc:372-:377) `get_default_ips_policy(const Snort*)`:
/// np = get_network_policy() (cc:374; cc:375 assert face -> the None arm),
/// np->get_default_ips_policy(sc) -> the free face cc:366-:370 -> the ips
/// slot. Returns the SLOT the caller derefs through the map.
pub fn get_default_ips_policy_slot(map: &PolicyMap) -> Option<usize> {
    let nslot = get_network_policy()?; // cc:374-:375
    map.get_network_policy(nslot)?
        .get_default_ips_policy()
        .filter(|&idx| idx < map.ips_policy_count()) // cc:368 `i < ...ips_policy_count()`
}

/// h:108 (def policy.cc:379-:380) `get_user_ips_policy(const Snort*,
/// unsigned policy_id)` — `sc->policy_map->get_user_ips(policy_id)` (the
/// sc hop == the config-home cite above).
pub fn get_user_ips_policy(map: &PolicyMap, policy_id: u64) -> Option<&IpsPolicy> {
    map.get_user_ips(policy_id) // cc:380
}

/// h:109 (def policy.cc:382-:383) `get_empty_ips_policy(const Snort*)` —
/// `sc->policy_map->get_empty_ips()`.
pub fn get_empty_ips_policy(map: &PolicyMap) -> Option<&IpsPolicy> {
    map.get_empty_ips() // cc:383
}

// h:112-:112/cc:386-:411 the UNSIGNED overloads (the h:96-:99 pointer pair
// above; Rust carries no overload — the *_idx naming, cited).

/// h:112 (def policy.cc:386-:392) `set_network_policy(unsigned i)`: pm =
/// get_conf()->policy_map (the config-home seam: snort_configp.rs
/// PolicyMapFace — the config face KEEPS its seam, cross-cite); np = pm->
/// get_network_policy(i); `if (np) set_network_policy(np)` — the gate
/// LIVE over the slot lease.
pub fn set_network_policy_idx(map: &PolicyMap, i: usize) {
    if map.get_network_policy(i).is_some() {
        // cc:390-:391 (the np-null skip arm == the not-some skip)
        set_network_policy(Some(i));
    }
}

/// h:113 (def policy.cc:394-:403) `set_inspection_policy(unsigned i)`:
/// np = get_network_policy(); `if (np)` (cc:397 LIVE); ip = np->
/// get_inspection_policy(i); `if (ip)` (cc:400-:401 LIVE) -> the (slot, i)
/// lease.
pub fn set_inspection_policy_idx(map: &PolicyMap, i: usize) {
    if let Some(nslot) = get_network_policy() {
        // cc:396-:398 (the np-null skip arm)
        if map
            .get_network_policy(nslot)
            .and_then(|np| np.get_inspection_policy(i))
            .is_some()
        {
            set_inspection_policy(Some((nslot, i))); // cc:401-:402
        }
    }
}

/// h:114 (def policy.cc:405-:411) `set_ips_policy(const Snort*, unsigned
/// i)`: pm = sc->policy_map (the config hop cited once more); `if (i <
/// pm->ips_policy_count())` (cc:409-:410 LIVE) -> the ips slot.
pub fn set_ips_policy_idx(map: &PolicyMap, i: usize) {
    if i < map.ips_policy_count() {
        set_ips_policy(Some(i)); // cc:410
    }
}

/// h:116 (def policy.cc:413-:425) `set_policies(const Snort*, Shell*)`:
/// policies = pm->get_policies(sh) (the shared_ptr: the C derefs it
/// unconditionally at cc:417 — the Rust None arm cites the C null-deref
/// face); then the EXACT if-chain setting the inspection, ips and network
/// slots.
pub fn set_policies(map: &PolicyMap, shl_slot: usize) {
    if let Some(policies) = map.get_policies(shl_slot) {
        if policies.inspection.is_some() {
            set_inspection_policy(policies.inspection); // cc:417-:418
        }
        if policies.ips.is_some() {
            set_ips_policy(policies.ips); // cc:420-:421
        }
        if policies.network.is_some() {
            set_network_policy(policies.network); // cc:423-:424
        }
    }
}

/// h:117 (def policy.cc:427-:433) `set_default_policy(const Snort*)`: np =
/// get_default_network_policy(sc) == get_network_policy(0); set network
/// (the C passes the pointer through the pointer-set — cc:430 NEVER
/// null-checks: the slot face mirrors the [0]-in-range get, None arm
/// cited); set inspection from np->get_inspection_policy(0) UNCONDITION-
/// AL (cc:431, the C may set null — the Option twin sets what the get
/// yields); set ips from get_ips_policy(sc, 0) (cc:432, the same mirror).
pub fn set_default_policy(map: &PolicyMap) {
    let np_slot = 0usize; // cc:429 get_default_network_policy -> get_network_policy(0)
    let np = map.get_network_policy(np_slot); // cc:429-:430
    set_network_policy(np.map(|_| np_slot));
    set_inspection_policy(np.and_then(|np| np.get_inspection_policy(0)).map(|_| (np_slot, 0))); // cc:431
    set_ips_policy(map.get_ips_policy(0).map(|_| 0)); // cc:432 get_ips_policy(sc, 0)
}

/// h:118 (def policy.cc:435-:440) select_default_policy(const _daq_pkt_
/// hdr&, const Snort*): ps = pm->get_policy_selector() (the PolicySelector
/// home NEVER landed — cited seam, snort_.rs:105/:466 only name it); the
/// gate `if (!ps || !ps->select_default_policies(pkthdr, sc))
/// set_default_policy(sc)` rides the selector_verdict provider-closure
/// precedent SEAM shape (the 24g seam law, e.g. the snort_configp.rs:1756
/// provider default wall): the verdict provider lands with the selector
/// row; the gate itself is LIVE over the seam bool — NEVER an invented
/// selector. The C pkthdr arg (_daq_pkt_hdr, daq_common.h) has NO landed
/// home -> the seam carries the verdict, NOT a fabricated header.
pub fn select_default_policy(selector_verdict: Option<bool>, map: &PolicyMap) {
    // cc:437-:439: `!ps` -> the selector slot (None verdict == no selector);
    // `!ps->select_default_policies(...)` -> the Some(verdict) provider
    // face.
    let selected = map.get_policy_selector().is_some() && selector_verdict.unwrap_or(false);
    if !selected {
        set_default_policy(map); // cc:439
    }
}

/// h:119 (def policy.cc:442-:447) the _daq_flow_stats overload — the SAME
/// gate face, the flow-stats header arg has no landed home either (the
/// same verdict seam; the (pkt/flow) overload pair collapses to this one
/// gate, cited).
pub fn select_default_policy_flowstats(selector_verdict: Option<bool>, map: &PolicyMap) {
    // cc:444-:446 exactly the cc:437-:439 face.
    let selected = map.get_policy_selector().is_some() && selector_verdict.unwrap_or(false);
    if !selected {
        set_default_policy(map); // cc:446
    }
}

/// h:121 (def policy.cc:449-:453) `only_inspection_policy()` — the EXACT
/// && chain over the slots: inspection set AND ips unset AND network
/// unset. LIVE.
pub fn only_inspection_policy() -> bool {
    get_inspection_policy().is_some()
        && get_ips_policy().is_none()
        && get_network_policy().is_none()
}

/// h:122 (def policy.cc:451-:453) `only_ips_policy()` — the mirrored EXACT
/// && chain. LIVE.
pub fn only_ips_policy() -> bool {
    get_ips_policy().is_some()
        && get_inspection_policy().is_none()
        && get_network_policy().is_none()
}

// ===========================================================================
// policy.cc:455-:493 `#ifdef UNIT_TEST` — the three Catch cases ("IPS
// policy reports action variable capacity" :458-:469, "reports existing
// action variable" :471-:481, "reports missing action variable" :483-:492)
// NEVER land in src/ (the 24a/24c/24e law: the GATE harness compiles the
// DONOR C++ directly). The Rust harness rows ride tests/policy_test.rs
// (row 08: policy_action_variable_capacity / policy_existing_action_
// variable / policy_missing_action_variable mirrors + the action_harness
// replay). Cite wall only — this block is the pair's tail.
// ===========================================================================
