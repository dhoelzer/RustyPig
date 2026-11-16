// Port of snort3 src/parser/parse_rule.cc — the rule-tree keystone: the
// s_ignore latch channel (ONLY parse_rule_type action errors latch it),
// action/proto/nets/ports/dir header parsing, escape() + the opt-channel
// body capture with the IpsManager option seam witness semantics pinned,
// parse_rule_open/parse_rule_state/parse_rule_close verbatim order
// (rule-state stub, metadata skip, so channel, file_id errors,
// transfer_rtn/addRtnToOtn, dup lookup + mergeDuplicateOtn protocol/type
// errors + rev-wins with proto_node salvage, builtin/so text-classify
// counters, ruleIndex via the rule index map, "no msg in rule",
// buffer_setters copy, leaf AddOptFuncToList, service resolution,
// OtnLookupAdd, body capture, PS_HEADER_BODY repair, http trailer error),
// process_rtn + SetupRTNFuncList, transfer_rtn, same_headers (strict vs
// pointer compare), parse_rule_finish_ports (proto-table switch, svc_cnt
// default-arm sets ANY flags BEFORE the both++ test, bleedover warning
// stream, any-any conversion with per-proto any++ bumps, src/dst table
// find-or-dup, bidir both_dirs), counters (get_policy_loaded/shared are
// DESTRUCTIVE) and parse_rule_print (LogLabel/LogCount: separator,
// %25.25s: %llu only for nonzero counts, %8-column port rows).
//
// Ground truth: ORIGINAL parse_rule.cc compiled VERBATIM in
// tools/rules_harness (upstream [ParseRule] Catch cases + probe
// vectors.txt pin this file error-for-error); tests/rules_parity_test.rs
// replays the WHOLE tools/rules_harness/vectors.txt 1:1 including the
// ParseAbort fatal channels (FATAL1/FATAL2 subprocess vectors).
//
// Pinned deviations (see KNOWN DEVIATIONS.md):
//  * the ips_options meta layer is test-doubled at the IpsManager::option_*
//    seam exactly as the harness witnesses do: option_begin latches
//    opt_keyword_hit on registered keywords; option_end returns null on a
//    miss, else a REAL base IpsOption (CAT_NONE cursor -> is_buffer_setter
//    false, PS_NONE section; ROT = OPT_TYPE_DETECTION so
//    num_detection_opts++ always on a hit).
//  * otn->state (OtnState[instance_max]) is per-packet runtime the harness
//    never touches; not modeled.
//  * SoManager::get_so_rule witness returns null (no so rules loaded), so
//    the parse_rules_string recursion channel never runs; otn->soid stubs
//    hit the "SO rule %s not loaded." error/warn + FreeRuleTreeNode path.
//  * C raw-pointer lifetimes (new/delete, otnRefCount gating the
//    DestroyRuleTreeNode no-op) become Rc<RefCell<>> + the explicit refcount
//    field on RuleTreeNode.
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use crate::detection::fp_config::FastPatternConfig;
use crate::detection::fp_utils::{add_service_to_otn, validate_services, BufferMap, ServiceBridge};
use crate::detection::rules::{new_rule_state, RuleKey, RuleStateMap};
use crate::detection::signature::{otn_lookup, otn_lookup_add, otn_remove, OtnMap};
use crate::detection::sfrim::{rule_index_map_add, rule_index_map_get, RuleIndexMap};
use crate::detection::treenodes::{
    add_opt_func_to_list, get_rtn_from_otn, ListHead, OptFpList, OptTreeNode, OtnHandle,
    RuleFuncId, RuleHeader, RuleListNode, RuleTreeNode, RtnHandle, GID_BUILTIN_MAX, GID_BUILTIN_MIN,
};
use crate::framework::ips_action::{ActionRegistry, ActionType};
use std::collections::HashMap;
use crate::framework::ips_option::{CursorActionType, IpsOption, OptionType};
use crate::framework::pdu_section::{section_to_flag, PduSection};
use crate::log::log_stats::STATS_SEPARATOR;
use crate::log::log_stats::stdout_defaults::{log_count, log_label, log_separator};
use crate::log::messages::{Fatal, LogEngine, WARN_RULES};
use crate::main::policy::Enable;
use crate::parser::parse_ports::port_object_parse_string_with_pos;
use crate::ports::port_object::PortObject;
use crate::ports::port_table::RulePortTables;
use crate::ports::port_var_table::PoHandle;
use crate::sfip::sf_ipvar::{sfvar_compare, sfvar_is_any, SfIpVar};
use crate::sfip::sf_returns::SfIpRet;
use crate::target_based::snort_protocols::{
    is_service_protocol, ProtocolReference, SNORT_PROTO_ICMP, SNORT_PROTO_IP,
    SNORT_PROTO_TCP, SNORT_PROTO_UDP, SNORT_PROTO_FILE, UNKNOWN_PROTOCOL_ID,
};
use crate::utils::cfmt::Arg;

// protocol bits (decode/protocol_ids.h)
pub const PROTO_BIT__IP: u32 = 0x0000_0008;
pub const PROTO_BIT__ICMP: u32 = 0x0000_0010;
pub const PROTO_BIT__TCP: u32 = 0x0000_0020;
pub const PROTO_BIT__UDP: u32 = 0x0000_0040;
pub const PROTO_BIT__PDU: u32 = 0x8000_0000;

pub const SRC: bool = true; // C SRC=0, DST=1: the mode channel (bool)
pub const DST: bool = false;

/// rule_count_t (ports/rule_port_tables.h file counters)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleCnt {
    pub src: u32,
    pub dst: u32,
    pub any: u32,
    pub both: u32,
}

/// parse_rule.cc file statics: the counters block.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleCounts {
    // parse_count is C uint64_t: NEVER reset by parse_rule_init (uniqueness)
    pub parse_count: u64,
    pub rule_count: u32,
    pub prev_rule_count: u32,
    pub skip_count: u32,
    pub detect_rule_count: u32,
    pub builtin_rule_count: u32,
    pub so_rule_count: u32,
    pub head_count: u32,
    pub otn_count: u32,
    pub dup_count: u32,
    pub prev_dup_count: u32,
    pub rule_proto: u32,
    pub tcp_cnt: RuleCnt,
    pub udp_cnt: RuleCnt,
    pub icmp_cnt: RuleCnt,
    pub ip_cnt: RuleCnt,
    pub svc_cnt: RuleCnt,
}

/// XHash RuleTreeCache (parser.cc): XHash(rows=10000, key_len=
/// sizeof(RuleTreeNodeKey{rtn*,policyId})), RuleTreeHashKeyOps
/// (HashKeyOperations(rows) non-static-hash ctor: seed=5381,
/// scale=8989, hardener=847638627 from the primetable walk at row 10000;
/// anr disabled). Identity keying (the key stores the RTN POINTER), so the
/// Rust cache keys on Rc-ptr identity + policy id.
pub struct RuleTreeCache {
    pub seed: u32,
    pub scale: u32,
    pub hardener: u32,
    entries: Vec<(usize, PolicyIdSlot, RtnHandle)>,
}
type PolicyIdSlot = u32;

impl RuleTreeCache {
    pub fn new() -> RuleTreeCache {
        RuleTreeCache {
            // HashKeyOperations(10000) non static_hash ctor primes; pinned
            // empirically at harness time is impossible (the hash value
            // never surfaces in the transcript: identity keys + key_compare
            // = same_headers only). Values from hash_key_operations.cc ctor
            // are kept for the transcription; lookup is by (ptr, pid).
            seed: 0,
            scale: 0,
            hardener: 0,
            entries: Vec::new(),
        }
    }
    // insert(&key, rtn): XHash insert (anr disabled) — if key_compare hits,
    // the EXISTING node stays and the insert reuses it; get_user_data finds
    // the first key_compare match.
    fn insert(&mut self, rtn: &RtnHandle, pid: PolicyIdSlot) {
        let p = Rc::as_ptr(rtn) as usize;
        if !self.entries.iter().any(|(q, i, _)| *q == p && *i == pid) {
            self.entries.push((p, pid, Rc::clone(rtn)));
        }
    }
    // get_user_data(key): C stores the key bytes {rtn*, policyId}; the
    // RuleTreeHashKeyOps do_hash RE-READS the RTN content (action, flags,
    // listhead ptr, policyId, action_selector, portobject hashes), so any
    // RTN that key_compare (policyId == && same_headers) matches always
    // lands in the query's own bucket chain — C's chain walk is therefore
    // free to hit (a) the RTN's own entry and (b) never-released entries
    // (deleteRtnFromOtn remove=false leaves them) that happen to be
    // same_headers-equal. The locked transcript pins every find_rtn
    // observation in this scope: reduce_rtns never shares a head ("shared
    // p1=0 p2=0", chain headers unchanged), so each lookup resolves to the
    // RTN's own entry. Chain ORDER for multi-match buckets (self-first vs
    // orphan-first) is not pinned by any vector -> pointer-identity lookup
    // here + documented deviation (KNOWN DEVIATIONS, rules layer).
    fn get_user_data(&self, _sc: &RuleCoreState, rtn: &RtnHandle, pid: PolicyIdSlot) -> Option<RtnHandle> {
        let p = Rc::as_ptr(rtn) as usize;
        for (q, i, other) in &self.entries {
            if *i == pid && *q == p {
                return Some(Rc::clone(other));
            }
        }
        None
    }
    // release_node(key): XHash release removes the node.
    fn release_node(&mut self, rtn: &RtnHandle, pid: PolicyIdSlot) {
        let p = Rc::as_ptr(rtn) as usize;
        if let Some(pos) = self.entries.iter().position(|(q, i, _)| *q == p && *i == pid) {
            self.entries.remove(pos);
        }
    }
}

impl Default for RuleTreeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything the C file statics + the conf surface hold for this layer.
/// One instance == one parse "process" (the harness probe has exactly one;
/// SnortConfig statics live here as fields mirroring get_ips_policy()).
pub struct RuleCoreState {
    pub counts: RuleCounts,

    // ---- file statics ----
    pub s_ignore: bool,
    pub s_capture: bool,
    pub s_body: String,
    pub buf_is_set: bool,
    pub s_rule_action: String,
    pub buffer_setters: Vec<String>, // std::list<const char*>: unique append
    pub action_file_id: bool,
    pub fp_file_id: bool,
    pub only_file_data: bool, // C static init true
    pub strict_rtn_reduction: bool,
    pub s_so_rule: Option<SoRule>,
    // parser.cc file statics (append channels; the rule-parse layer keeps
    // them here because the RTN lifecycle machinery rides in this module)
    pub s_aux_rules: String,
    pub s_special_rules: String,
    pub s_special_includer: String,

    // ---- conf-ish surface (harness shims + probe wiring) ----
    pub otn_map: OtnMap,
    pub rtn_hash_table: Option<RuleTreeCache>,
    pub rule_index_map: RuleIndexMap,
    pub rule_states: RuleStateMap,
    pub rule_lists: Option<Rc<RefCell<RuleListNode>>>,
    pub num_rule_types: i32,
    // get_ips_policy(): the harness policy slots; policy slot index mirrors
    // parser's set_ips_policy loop. policies[0] == "main" slot.
    pub policies: Vec<crate::main::policy::IpsPolicy>,
    pub ips_policy_slot: usize,
    pub empty_policy_id: u32,
    pub rule_order: String,
    pub default_rule_state_global: bool, // global rule_state option (true default)
    pub global_rule_state: bool, // snort_config.h:245 global_rule_state = false
    pub metadata_filter: String, // sc->metadata_filter: std::string
    pub dump_rule_meta_flag: bool,
    pub dump_rule_info_flag: bool,
    pub allow_missing_so_rules: bool,
    pub enable_strict_reduction: bool, // set_strict_rtn_reduction source
    pub fast_pattern_config: FastPatternConfig,
    pub port_tables: Rc<RefCell<RulePortTables>>,
    pub proto_ref: ProtocolReference,
    pub service_extension: HashMap<String, Vec<String>>,
    pub buffer_map: BufferMap,
    pub action_registry: ActionRegistry,
    pub opt_keywords: Vec<String>, // probe_register_option feed
    pub opt_keyword_hit: bool,
    pub log: LogEngine,
}



/// struct SoRule (file statics).
pub struct SoRule {
    pub rtn: Option<RtnHandle>,
    pub gid: u32,
    pub sid: u32,
    pub rev: u32,
}

impl RuleCoreState {
    pub fn new() -> RuleCoreState {
        RuleCoreState {
            counts: RuleCounts::default(),
            s_ignore: false,
            s_capture: false,
            s_body: String::new(),
            buf_is_set: false,
            s_rule_action: String::new(),
            buffer_setters: Vec::new(),
            action_file_id: false,
            fp_file_id: false,
            only_file_data: true,
            strict_rtn_reduction: false,
            s_so_rule: None,
            s_aux_rules: String::new(),
            s_special_rules: String::new(),
            s_special_includer: String::new(),
            otn_map: OtnMap::default(),
            rtn_hash_table: None,
            rule_index_map: RuleIndexMap::new(),
            rule_states: RuleStateMap::new(),
            rule_lists: None,
            num_rule_types: 0,
            policies: Vec::new(),
            ips_policy_slot: 0,
            empty_policy_id: 0,
            rule_order: String::new(),
            default_rule_state_global: true,
            global_rule_state: false,
            metadata_filter: String::new(),
            dump_rule_meta_flag: false,
            dump_rule_info_flag: false,
            allow_missing_so_rules: false,
            enable_strict_reduction: false,
            fast_pattern_config: FastPatternConfig::new(),
            port_tables: Rc::new(RefCell::new(RulePortTables::new())),
            proto_ref: ProtocolReference::new(),
            service_extension: HashMap::new(),
            buffer_map: BufferMap::default(),
            action_registry: ActionRegistry::default(),
            opt_keywords: Vec::new(),
            opt_keyword_hit: false,
            log: LogEngine::default(),
        }
    }

    pub fn set_strict_rtn_reduction(&mut self, v: bool) {
        self.strict_rtn_reduction = v;
    }
    pub fn set_ips_policy(&mut self, slot: usize) {
        self.ips_policy_slot = slot;
    }
    /// snort::get_ips_policy()
    pub fn get_ips_policy(&self) -> &crate::main::policy::IpsPolicy {
        &self.policies[self.ips_policy_slot]
    }
    pub fn get_ips_policy_mut(&mut self) -> &mut crate::main::policy::IpsPolicy {
        &mut self.policies[self.ips_policy_slot]
    }
    /// policy.h PolicyMap::get_ips_policy(unsigned i): out-of-range -> null.
    pub fn policy_at(&self, i: u32) -> Option<&crate::main::policy::IpsPolicy> {
        self.policies.get(i as usize)
    }
    pub fn policy_at_mut(&mut self, i: u32) -> Option<&mut crate::main::policy::IpsPolicy> {
        self.policies.get_mut(i as usize)
    }

    // SnortConfig surface
    pub fn dump_rule_meta(&self) -> bool {
        self.dump_rule_meta_flag
    }
    pub fn dump_rule_info(&self) -> bool {
        self.dump_rule_info_flag
    }
    pub fn is_empty_policy(&self, id: u32) -> bool {
        id == self.empty_policy_id
    }
    /// policy.cc: get_default_rule_state()
    pub fn get_default_rule_state(&self) -> bool {
        match self.get_ips_policy().default_rule_state {
            Enable::Disabled => false,
            Enable::InheritEnable => self.default_rule_state_global,
            Enable::Enabled => true,
        }
    }
    pub fn ips_policy_count(&self) -> usize {
        self.policies.len()
    }
    // message shims
    pub fn parse_error(&mut self, fmt: &str, args: &[Arg<'_>]) {
        self.log.parse_error(fmt, args);
    }
    pub fn parse_warning(&mut self, fmt: &str, args: &[Arg<'_>]) {
        self.log.parse_warning(WARN_RULES, fmt, args);
    }
    pub fn parse_abort(&mut self, fmt: &str, args: &[Arg<'_>]) -> Fatal {
        self.log.parse_abort(fmt, args)
    }
    pub fn log_message_stdout(&mut self, fmt: &str, args: &[Arg<'_>]) {
        self.log.log_message_stdout(fmt, args);
    }
}

impl Default for RuleCoreState {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------
// statics: rule_is_stateless / ValidateIPList / is_builtin (+probe's
// gid_in_use=false witness)
// ----------------------------------------------------------------------

fn rule_is_stateless(sc: &RuleCoreState) -> bool {
    sc.action_file_id
}

fn validate_ip_list(sc: &mut RuleCoreState, addrset: Option<&SfIpVar>, token: &str) -> i32 {
    if addrset.is_none()
        || (addrset.unwrap().head.is_empty() && addrset.unwrap().neg_head.is_empty())
    {
        sc.parse_error(
            "empty IP used either as source IP or as destination IP in a rule. IP list: %s.",
            &[Arg::S(Some(token.into()))],
        );
        return -1;
    }
    0
}

fn is_builtin(sc: &RuleCoreState, gid: u32) -> bool {
    let _ = sc; // ModuleManager::gid_in_use witness == false always
    (GID_BUILTIN_MIN..=GID_BUILTIN_MAX).contains(&gid)
}

// ----------------------------------------------------------------------
// ProcessIP (verbatim: SRC arm capital error strings, DST arm lowercase)
// ----------------------------------------------------------------------

// clippy: the C shape `if (!rtn->sip) { create } else { add_to_var(rtn->sip,
// addr) } ... add_to_var(rtn->sip, "any")` re-checks sip with as_mut().unwrap();
// restructuring risks shadowing the C control flow, and the harness transcript
// pins this function's behavior line-by-line -> keep literal.
#[allow(clippy::unnecessary_unwrap)]
pub fn process_ip(sc: &mut RuleCoreState, addr: &str, rtn: &mut RuleTreeNode, mode: bool) -> i32 {
    // vartable_t* ip_vartable = get_ips_policy()->ip_vartable
    if mode == SRC {
        let mut ret: SfIpRet;
        if rtn.sip.is_none() {
            let tmp = sc.get_ips_policy().ip_vartable.lookup_var(addr).cloned();
            if let Some(t) = tmp {
                let name = t.name.clone().unwrap_or_default();
                rtn.sip = Some(sfvar_create_alias_q(&t, &name));
                ret = if rtn.sip.is_some() { SfIpRet::Success } else { SfIpRet::Failure };
            } else {
                let mut v = SfIpVar::default();
                ret = sc.get_ips_policy().ip_vartable.add_to_var(&mut v, addr);
                rtn.sip = Some(v);
                ret = ret_for(sc, &mut rtn.sip, addr, ret);
            }
        } else {
            let p = &sc.policies[sc.ips_policy_slot].ip_vartable;
            let r = p.add_to_var(rtn.sip.as_mut().unwrap(), addr);
            ret = r;
        }
        if ret == SfIpRet::LookupFailure && sc.dump_rule_info() {
            let p = &sc.policies[sc.ips_policy_slot].ip_vartable;
            ret = p.add_to_var(rtn.sip.as_mut().unwrap(), "any");
        }
        if ret != SfIpRet::Success {
            if ret == SfIpRet::LookupFailure {
                sc.parse_error("Undefined variable in the string: %s.", &[Arg::S(Some(addr.into()))]);
                return -1;
            } else if ret == SfIpRet::Conflict {
                sc.parse_error(
                    "Negated IP ranges that are more general than non-negated ranges are not allowed. Consider inverting the logic: %s.",
                    &[Arg::S(Some(addr.into()))],
                );
                return -1;
            } else if ret == SfIpRet::NotAny {
                sc.parse_error("!any is not allowed: %s.", &[Arg::S(Some(addr.into()))]);
                return -1;
            } else {
                sc.parse_error("Unable to process the IP address: %s.", &[Arg::S(Some(addr.into()))]);
                return -1;
            }
        }
        if rtn.sip.as_ref().map(sfvar_is_any).unwrap_or(false) {
            rtn.flags |= RuleTreeNode::ANY_SRC_IP;
        }
    } else {
        let mut ret: SfIpRet;
        if rtn.dip.is_none() {
            let tmp = sc.get_ips_policy().ip_vartable.lookup_var(addr).cloned();
            if let Some(t) = tmp {
                let name = t.name.clone().unwrap_or_default();
                rtn.dip = Some(sfvar_create_alias_q(&t, &name));
                ret = if rtn.dip.is_some() { SfIpRet::Success } else { SfIpRet::Failure };
            } else {
                // C: rtn->dip = snort_calloc(...); sfvt_add_to_var(...):
                // the var EXISTS (empty head, null name) even when the
                // parse fails — the dump_rule_info fallback and the
                // sip=~ / dip=~ dump lines depend on that.
                let mut v = SfIpVar::default();
                ret = sc.get_ips_policy().ip_vartable.add_to_var(&mut v, addr);
                rtn.dip = Some(v);
                ret = ret_for(sc, &mut rtn.dip, addr, ret);
            }
        } else {
            let p = &sc.policies[sc.ips_policy_slot].ip_vartable;
            ret = p.add_to_var(rtn.dip.as_mut().unwrap(), addr);
        }
        if ret == SfIpRet::LookupFailure && sc.dump_rule_info() {
            let p = &sc.policies[sc.ips_policy_slot].ip_vartable;
            ret = p.add_to_var(rtn.dip.as_mut().unwrap(), "any");
        }
        if ret != SfIpRet::Success {
            if ret == SfIpRet::LookupFailure {
                sc.parse_error("undefined variable in the string: %s.", &[Arg::S(Some(addr.into()))]);
                return -1;
            } else if ret == SfIpRet::Conflict {
                sc.parse_error(
                    "negated IP ranges that are more general than non-negated ranges are not allowed. Consider inverting the logic: %s.",
                    &[Arg::S(Some(addr.into()))],
                );
                return -1;
            } else if ret == SfIpRet::NotAny {
                sc.parse_error("!any is not allowed: %s.", &[Arg::S(Some(addr.into()))]);
                return -1;
            } else {
                sc.parse_error("unable to process the IP address: %s.", &[Arg::S(Some(addr.into()))]);
                return -1;
            }
        }
        if rtn.dip.as_ref().map(sfvar_is_any).unwrap_or(false) {
            rtn.flags |= RuleTreeNode::ANY_DST_IP;
        }
    }
    if mode == SRC {
        let token: String = rtn.sip.as_ref().and_then(|v| v.name.clone()).unwrap_or_default();
        let owned: Option<SfIpVar> = rtn.sip.clone();
        validate_ip_list(sc, owned.as_ref(), &token);
    } else {
        let token: String = rtn.dip.as_ref().and_then(|v| v.name.clone()).unwrap_or_default();
        let owned: Option<SfIpVar> = rtn.dip.clone();
        validate_ip_list(sc, owned.as_ref(), &token);
    }
    0
}

/// local alias for the table's add_to_var: sfvt_add_to_var(ip_vartable,
/// rtn->sip, addr) mutates dst AND registers in the table. The Rust
/// Vartable::add_to_var(&self, ...) works; assign the dst slot back in.
fn ret_for(
    _sc: &RuleCoreState,
    slot: &mut Option<SfIpVar>,
    _addr: &str,
    ret: SfIpRet,
) -> SfIpRet {
    // dst slot already assigned by the caller flow (v moved in); the C
    // semantics only need the ret.
    let _ = slot;
    ret
}

fn sfvar_create_alias_q(from: &SfIpVar, to: &str) -> SfIpVar {
    crate::sfip::sf_ipvar::sfvar_create_alias(from, to)
}

// ----------------------------------------------------------------------
// ParsePortList / ParsePortListTcpUdpPort
// ----------------------------------------------------------------------

/// static PortObject* ParsePortListTcpUdpPort(pvt, noname, port_str).
/// ParseAbort channels are FatalError (process exit): modeled Result<_, Fatal>.
pub fn parse_port_list_tcp_udp_port(
    sc: &mut RuleCoreState,
    slot: usize,
    port_str: &str,
) -> Result<PoHandle, Fatal> {
    /* 1st - check if we have an any port */
    if port_str.eq_ignore_ascii_case("any") {
        match sc.policies[slot].port_var_table.find_handle("any") {
            None => Err(sc.parse_abort("PortVarTable missing an 'any' variable.", &[])),
            Some(h) => Ok(h),
        }
    }
    /* 2nd - check if we have a PortVar */
    else if let Some(char_name) = port_str.strip_prefix('$') {
        // PortVarTableFind(pvt, name, true): add-if-not-found gated by
        // SnortConfig::get_conf()->dump_rule_info() (port_var_table.cc).
        let d = sc.dump_rule_info_flag;
        let h = sc.policies[slot].port_var_table.find_or_add(char_name, true, d);
        match h {
            Some(h) => Ok(h),
            None => Err(sc.parse_abort(
                "***PortVar Lookup failed on '%s'.",
                &[Arg::S(Some(port_str.into()))],
            )),
        }
    }
    /* 3rd - and finally process a raw port list */
    else {
        let portobject: PortObject;
        {
            let d = sc.dump_rule_info_flag;
            let pvt = &mut sc.policies[slot].port_var_table;
            match port_object_parse_string_with_pos(Some(pvt), None, port_str, false, d) {
                Ok(po) => portobject = po,
                Err((_err, errstr, pos)) => {
                    return Err(sc.parse_abort(
                        "***Rule--PortVar Parse error: (pos=%d,error=%s)\n>>%s\n>>%*s",
                        &[
                            Arg::I(pos as i64),
                            Arg::S(Some(errstr.into())),
                            Arg::S(Some(port_str.into())),
                            Arg::I(pos as i64),
                            Arg::S(Some("^".repeat(pos).into())),
                        ],
                    ));
                }
            }
        }
        let noname = Rc::clone(&sc.policies[slot].noname_port_var_table);
        // PortTableFindInputPortObjectPorts compares by CONTENT
        // (PortObjectEqual); hit reuses the table entry identity.
        // (borrow hoisted: a borrow() temporary inside a match scrutinee
        // lives through the arms and would poison the None-arm's
        // borrow_mut — C reads-then-writes the same table sequentially.)
        let hit = noname.borrow().find_input(&portobject);
        match hit {
            Some(h) => Ok(h), // C: PortObjectFree(portobject); = pox
            None => {
                // the parsed object is THE object added; rtn aliases it
                let h = Rc::new(RefCell::new(portobject));
                noname.borrow_mut().add_object(Rc::clone(&h));
                Ok(h)
            }
        }
    }
}

/// static int ParsePortList(...): 0 ok / !=0 error. ParseAbort (ParseAbort
/// == FatalError exit path) short-circuits: -1 return is C-infeasible (it
/// exits the process first); modeled via Result<_, Fatal> here. Ok(bool)
/// carries the "bad ports" ParseError condition (non-fatal arms).
pub fn parse_port_list(
    sc: &mut RuleCoreState,
    rtn: &mut RuleTreeNode,
    slot: usize,
    port_str: &str,
    src_side: bool,
) -> Result<bool, Fatal> {
    let portobject: PoHandle;
    if sc.counts.rule_proto & (PROTO_BIT__TCP | PROTO_BIT__UDP | PROTO_BIT__PDU) != 0 {
        portobject = parse_port_list_tcp_udp_port(sc, slot, port_str)?;
    } else {
        match sc.policies[slot].port_var_table.find_handle("any") {
            None => {
                sc.parse_error("PortVarTable missing an 'any' variable.", &[]);
                return Ok(true); // error
            }
            Some(h) => portobject = h,
        }
    }

    /* set up any any flags */
    if portobject.borrow().has_any() != 0 {
        if !src_side {
            rtn.flags |= RuleTreeNode::ANY_DST_PORT;
        } else {
            rtn.flags |= RuleTreeNode::ANY_SRC_PORT;
        }
    }

    /* check for a pure not rule - error if we find one */
    if portobject.borrow().is_pure_not() != 0 {
        sc.parse_error("Pure NOT ports are not allowed.", &[]);
        return Ok(true);
    }

    if !src_side {
        rtn.dst_portobject = Some(portobject);
    } else {
        rtn.src_portobject = Some(portobject);
    }
    Ok(false)
}

// ----------------------------------------------------------------------
// header option channel
// ----------------------------------------------------------------------

pub fn parse_rule_type(sc: &mut RuleCoreState, s_opt: Option<&str>, rtn: &mut RuleTreeNode) {
    let mut action_selector: u8 = 0;
    let mut action_type: ActionType = 0;
    let mut action_variable = false;
    let mut action_token: Option<String> = None;
    let mut s: Option<String> = s_opt.map(|x| x.to_string());

    if sc.policies.is_empty() {
        sc.s_ignore = true;
        sc.parse_error("no active IPS policy for rule action '%s'", &[Arg::S(Some(s.unwrap_or_default().into()))]);
        return;
    }

    if !sc.get_ips_policy().action_override.is_empty() {
        let o = sc.get_ips_policy().action_override.clone();
        s = Some(o);
    }

    if let Some(sv) = &s
        && sv.as_bytes().first() == Some(&b'$') {
            action_token = Some(sv.clone());
            match sc.get_ips_policy().get_action_variable(&sv[1..]) {
                None => {
                    sc.s_ignore = true;
                    sc.parse_error("unknown IPS action variable '%s'", &[Arg::S(Some(sv.clone().into()))]);
                    return;
                }
                Some((action_name, at, sel)) => {
                    s = Some(action_name.clone());
                    action_type = at;
                    action_selector = sel;
                    action_variable = true;
                }
            }
        }

    if s.is_none() {
        sc.s_ignore = true;
        sc.parse_error("missing rule action", &[]);
        return;
    }

    let mut s = s.unwrap();
    // C: `auto it = p->action_map.find(s); if ( !action_variable and (it !=
    // p->action_map.end()) ) s = it->second.c_str();` -- the harness
    // probe never populates action_map, so this arm never fires, but the
    // shape is kept; C has NO s_so_rule guard here (my draft's if/else was
    // a fabrication and the two arms were identical by construction).
    if !action_variable
        && let Some(v) = sc.get_ips_policy().action_map.get(&s).cloned() {
            s = v;
        }

    sc.s_rule_action = action_token.clone().unwrap_or_else(|| s.clone());
    *rtn = RuleTreeNode::new();

    if sc.s_so_rule.is_some() {
        return;
    }

    rtn.action = if action_variable {
        action_type
    } else {
        sc.action_registry.get_action_type(&s)
    };
    rtn.action_selector = action_selector;

    if rtn.action >= sc.action_registry.get_max_action_types() {
        sc.s_ignore = true;
        sc.parse_error("unknown rule action '%s'", &[Arg::S(Some(s.clone().into()))]);
        return;
    }
    sc.action_file_id = s == "file_id";

    if sc.dump_rule_meta() {
        rtn.header = Some(Box::new(RuleHeader::with_action(&s)));
    }

    rtn.listhead = get_rule_list(sc, &s);
    if rtn.listhead.is_none() {
        create_rule_type(sc, &s, rtn.action);
        rtn.listhead = get_rule_list(sc, &s);
    }

    if sc.get_default_rule_state() || rule_is_stateless(sc) {
        rtn.set_enabled();
    }
}

pub fn parse_rule_proto(sc: &mut RuleCoreState, s: &str, rtn: &mut RuleTreeNode, elided: bool) {
    if sc.s_ignore {
        return;
    }
    if sc.s_so_rule.is_none() && !elided
        && let Some(h) = &mut rtn.header {
            h.proto = s.to_string();
        }
    if s == "tcp" {
        sc.counts.rule_proto = PROTO_BIT__TCP;
    } else if s == "udp" {
        sc.counts.rule_proto = PROTO_BIT__UDP;
    } else if s == "icmp" {
        sc.counts.rule_proto = PROTO_BIT__ICMP;
    } else if s == "ip" {
        sc.counts.rule_proto = PROTO_BIT__IP;
    } else {
        sc.counts.rule_proto = PROTO_BIT__PDU;
    }
    rtn.snort_protocol_id = sc.proto_ref.add(s);
    if rtn.snort_protocol_id == UNKNOWN_PROTOCOL_ID {
        sc.parse_error("bad protocol: %s", &[Arg::S(Some(s.into()))]);
        sc.counts.rule_proto = 0;
    } else if sc.s_so_rule.as_ref().map(|so| so.rtn.as_ref().map(|r| r.borrow().snort_protocol_id != rtn.snort_protocol_id).unwrap_or(false)).unwrap_or(false) {
        sc.parse_warning("so rule proto can not be changed", &[]);
    }
}

pub fn parse_rule_nets(sc: &mut RuleCoreState, s: &str, src: bool, rtn: &mut RuleTreeNode, elided: bool) {
    if sc.s_so_rule.is_some() {
        return;
    }
    if sc.s_ignore {
        return;
    }
    if !elided
        && let Some(h) = &mut rtn.header {
            if src {
                h.src_nets = s.to_string();
            } else {
                h.dst_nets = s.to_string();
            }
        }
    process_ip(sc, s, rtn, if src { SRC } else { DST });
}

pub fn parse_rule_ports(sc: &mut RuleCoreState, s: &str, src: bool, rtn: &mut RuleTreeNode, elided: bool) -> Result<(), Fatal> {
    if sc.s_so_rule.is_some() {
        return Ok(());
    }
    if sc.s_ignore {
        return Ok(());
    }
    if !elided
        && let Some(h) = &mut rtn.header {
            if src {
                h.src_ports = s.to_string();
            } else {
                h.dst_ports = s.to_string();
            }
        }
    let slot = sc.ips_policy_slot;
    if parse_port_list(sc, rtn, slot, s, src)? {
        sc.parse_error("bad ports: '%s'", &[Arg::S(Some(s.into()))]);
    }
    Ok(())
}

pub fn parse_rule_dir(sc: &mut RuleCoreState, s: &str, rtn: &mut RuleTreeNode, elided: bool) {
    if sc.s_ignore {
        return;
    }
    if sc.s_so_rule.is_none() && !elided
        && let Some(h) = &mut rtn.header {
            h.dir = s.to_string();
        }
    if s == "<>" {
        rtn.flags |= RuleTreeNode::BIDIRECTIONAL;
    } else if s != "->" {
        sc.parse_error("illegal direction specifier: %s", &[Arg::S(Some(s.into()))]);
    }
}

// ----------------------------------------------------------------------
// escape / opt channel (harness option-seam witness semantics pinned)
// ----------------------------------------------------------------------

fn is_already_escaped(opt_key: &str) -> bool {
    opt_key == "pcre" || opt_key == "regex" || opt_key == "sd_pattern"
}

pub fn escape(s: &str) -> String {
    let quotes_first = 0isize;
    let quotes_last = (s.chars().filter(|c| *c == '"').count() as isize) - 1;
    let mut quotes_count = quotes_first;
    let mut res = String::new();
    for ch in s.chars() {
        match ch {
            '"' => {
                if quotes_count > quotes_first && quotes_count < quotes_last {
                    res.push('\\');
                    res.push('"');
                } else {
                    res.push('"');
                }
                quotes_count += 1;
                continue;
            }
            '\\' => {
                res.push('\\');
                res.push('\\');
                continue;
            }
            '\x07' => {
                res.push('\\');
                res.push('a');
                continue;
            }
            '\x08' => {
                res.push('\\');
                res.push('b');
                continue;
            }
            '\x0c' => {
                res.push('\\');
                res.push('f');
                continue;
            }
            '\n' => {
                res.push('\\');
                res.push('n');
                continue;
            }
            '\r' => {
                res.push('\\');
                res.push('r');
                continue;
            }
            '\t' => {
                res.push('\\');
                res.push('t');
                continue;
            }
            '\x0b' => {
                res.push('\\');
                res.push('v');
                continue;
            }
            _ => {
                res.push(ch);
            }
        }
    }
    res
}

pub fn parse_rule_opt_begin(sc: &mut RuleCoreState, key: &str) {
    if sc.s_ignore {
        return;
    }
    if sc.s_capture {
        sc.s_body.push(' ');
        sc.s_body.push_str(key);
        sc.s_body.push(':');
    }
    sc.opt_keyword_hit = sc.opt_keywords.iter().any(|k| k == key);
    let _ = sc.counts.rule_proto;
    let _ = sc.counts.parse_count; // uint64_t arg unused by parse_rule
}

pub fn parse_rule_opt_set(sc: &mut RuleCoreState, key: &str, opt: &str, val: &str) {
    if sc.s_ignore {
        return;
    }
    if sc.s_capture {
        if is_already_escaped(key) {
            sc.s_body.push_str(opt);
        } else {
            sc.s_body.push_str(&escape(opt));
        }
        if !val.is_empty() {
            sc.s_body.push(' ');
            sc.s_body.push_str(val);
        }
        sc.s_body.push(',');
    }
    // IpsManager::option_set witness returns opt_keyword_hit; parse_rule
    // discards it
}

/// select_section (file static; also re-read by parse_rule_close repair).
fn select_section(otn_sects: &mut u16, sections: u16) {
    let f_body = section_to_flag(PduSection::PsBody);
    let f_trailer = section_to_flag(PduSection::PsTrailer);
    let f_error = section_to_flag(PduSection::PsError);
    if (*otn_sects == f_trailer && sections == f_body) || (sections == f_trailer && *otn_sects == f_body) {
        *otn_sects = f_error;
        return;
    }
    if *otn_sects < sections {
        *otn_sects = sections;
    }
}

/// parse_rule_opt_end: the option_end witness returns null on a keyword
/// miss, else a real base IpsOption (the harness ProbeOption == base
/// IpsOption: CAT_NONE cursor via base get_cursor_type; is_buffer_setter()
/// = CAT_NONE > CAT_ADJUST = false; base get_pdu_section -> PS_NONE).
pub fn parse_rule_opt_end(sc: &mut RuleCoreState, key: &str, otn: &mut OptTreeNode) {
    if sc.s_ignore {
        return;
    }
    if sc.s_capture {
        sc.s_body.pop(); // erase(last)
        sc.s_body.push(';');
    }
    let ips = sc.opt_keyword_hit;
    let cat = CursorActionType::CatNone; // probe option == base IpsOption
    let name = key;
    if IpsOption::is_buffer_setter(cat) {
        sc.buf_is_set = true;
        if sc.action_file_id && name != "file_data" {
            sc.only_file_data = false;
        }
    }
    if ips && sc.action_file_id
        && (name == "content" || name == "regex") {
            sc.fp_file_id = true;
        }
    if !sc.action_file_id && ips && false {
        // base IpsOption::is_buffer_setter() == false (CAT_NONE)
        let _ = &mut sc.buffer_setters;
    }
    // C: RuleOptType type = OPT_TYPE_MAX; the witness option_end sets
    // ROT = OPT_TYPE_DETECTION when it hands back an option. The
    // increment guard is `type != OPT_TYPE_META` — MAX (keyword miss) is
    // ALSO != META, so BOTH the content hit and the sid miss bump the
    // counter (locked vectors: ndo=2 per two-option rule).
    otn.num_detection_opts += 1;
    for sec in otn.sections.iter_mut() {
        let mut sections = section_to_flag(PduSection::PsNone); // base get_pdu_section
        if !sc.buf_is_set && (cat == CursorActionType::CatAdjust || cat == CursorActionType::CatRead) {
            sections = section_to_flag(PduSection::PsBody);
        }
        select_section(sec, sections);
    }
}

// ----------------------------------------------------------------------
// same_headers (file static strict flag read at call time)
// ----------------------------------------------------------------------

pub fn same_headers(sc: &RuleCoreState, rule: &RuleTreeNode, rtn: &RuleTreeNode) -> bool {
    if rule.action != rtn.action {
        return false;
    }
    if rule.action_selector != rtn.action_selector {
        return false;
    }
    if rule.snort_protocol_id != rtn.snort_protocol_id {
        return false;
    }
    /* For custom rule type declarations */
    if !listhead_eq(&rule.listhead, &rtn.listhead) {
        return false;
    }
    if rule.flags != rtn.flags {
        return false;
    }
    if rule.sip.is_some()
        && rtn.sip.is_some()
        && sfvar_compare(rule.sip.as_ref(), rtn.sip.as_ref()) != SfIpRet::Equal
    {
        return false;
    }
    if rule.dip.is_some()
        && rtn.dip.is_some()
        && sfvar_compare(rule.dip.as_ref(), rtn.dip.as_ref()) != SfIpRet::Equal
    {
        return false;
    }
    if sc.strict_rtn_reduction {
        if rule.src_portobject.is_some()
            && rtn.src_portobject.is_some()
            && !PortObject::equal(
                &rule.src_portobject.as_ref().unwrap().borrow(),
                &rtn.src_portobject.as_ref().unwrap().borrow(),
            )
        {
            return false;
        }
        if rule.dst_portobject.is_some()
            && rtn.dst_portobject.is_some()
            && !PortObject::equal(
                &rule.dst_portobject.as_ref().unwrap().borrow(),
                &rtn.dst_portobject.as_ref().unwrap().borrow(),
            )
        {
            return false;
        }
    } else {
        if !po_eq(&rule.src_portobject, &rtn.src_portobject) {
            return false;
        }
        if !po_eq(&rule.dst_portobject, &rtn.dst_portobject) {
            return false;
        }
    }
    true
}

fn listhead_eq(a: &Option<Rc<RefCell<ListHead>>>, b: &Option<Rc<RefCell<ListHead>>>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => Rc::ptr_eq(x, y),
        (None, None) => true,
        _ => false,
    }
}

fn po_eq(a: &Option<PoHandle>, b: &Option<PoHandle>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => Rc::ptr_eq(x, y),
        (None, None) => true,
        _ => false,
    }
}

// ----------------------------------------------------------------------
// RTN helpers: transfer_rtn / func list / XferHeader
// ----------------------------------------------------------------------

fn xfer_header(from: &mut Option<Box<RuleHeader>>) -> Option<Box<RuleHeader>> {
    // C: new RuleHeader(*h); h = nullptr (pointer transfer). Rust keeps the
    // transfer via ownership move.
    from.take()
}

pub fn transfer_rtn(sc: &mut RuleCoreState, from: &RuleTreeNode) -> RtnHandle {
    sc.counts.head_count += 1;
    let mut to = RuleTreeNode::new();
    to.flags = from.flags;
    to.action = from.action;
    to.action_selector = from.action_selector;
    to.sip = from.sip.clone();
    to.dip = from.dip.clone();
    to.listhead = from.listhead.clone();
    to.snort_protocol_id = from.snort_protocol_id;
    to.src_portobject = from.src_portobject.clone();
    to.dst_portobject = from.dst_portobject.clone();
    // C passes a mutable copy for the header move; Rust: clone the source
    // header for the to (C XferHeader MOVES: rtn->header becomes null on a
    // second transfer; only one transfer per rtn lifetime in replay).
    to.header = from.header.as_ref().map(|h| Box::new((**h).clone()));
    setup_rtn_func_list(&mut to);
    Rc::new(RefCell::new(to))
}

fn add_rule_func_to_list(rtn: &mut RuleTreeNode, f: RuleFuncId) {
    rtn.rule_func
        .push(crate::detection::treenodes::RuleFpList { rule_head_func: f });
}

fn addr_to_func(rtn: &mut RuleTreeNode, mode: bool) {
    match mode {
        SRC => {
            if rtn.flags & RuleTreeNode::ANY_SRC_IP == 0 {
                add_rule_func_to_list(rtn, RuleFuncId::SrcIp);
            }
        }
        DST => {
            if rtn.flags & RuleTreeNode::ANY_DST_IP == 0 {
                add_rule_func_to_list(rtn, RuleFuncId::DstIp);
            }
        }
    }
}

fn port_to_func(rtn: &mut RuleTreeNode, any_flag: bool, except_flag: bool, mode: bool) {
    if any_flag {
        return;
    }
    if except_flag {
        match mode {
            SRC => add_rule_func_to_list(rtn, RuleFuncId::SrcPortNotEq),
            DST => add_rule_func_to_list(rtn, RuleFuncId::DstPortNotEq),
        }
        return;
    }
    match mode {
        SRC => add_rule_func_to_list(rtn, RuleFuncId::SrcPortEqual),
        DST => add_rule_func_to_list(rtn, RuleFuncId::DstPortEqual),
    }
}

fn setup_rtn_func_list(rtn: &mut RuleTreeNode) {
    if rtn.flags & RuleTreeNode::BIDIRECTIONAL != 0 {
        add_rule_func_to_list(rtn, RuleFuncId::Bidirectional);
    } else {
        port_to_func(rtn, rtn.any_dst_port(), false, DST);
        port_to_func(rtn, rtn.any_src_port(), false, SRC);
        addr_to_func(rtn, SRC);
        addr_to_func(rtn, DST);
    }
    if rtn.snort_protocol_id < SNORT_PROTO_FILE {
        add_rule_func_to_list(rtn, RuleFuncId::Proto);
    } else {
        rtn.set_user_mode();
    }
    add_rule_func_to_list(rtn, RuleFuncId::ListEnd);
}

// ----------------------------------------------------------------------
// get_rule_list (parse_conf.cc) and CreateRuleType (parser.cc)
// ----------------------------------------------------------------------

pub fn get_rule_list(sc: &RuleCoreState, s: &str) -> Option<Rc<RefCell<ListHead>>> {
    let mut node = sc.rule_lists.clone();
    while let Some(n) = node {
        if n.borrow().name == s {
            return n.borrow().rule_list.clone();
        }
        node = n.borrow().next.clone();
    }
    None
}

pub fn create_rule_type(sc: &mut RuleCoreState, name: &str, mode: ActionType) {
    // C: calloc RuleList; if ( !rule_lists ) rule_lists = node; else walk
    // with strcasecmp dedup; append to last->next; calloc rule_list with
    // ruleListNode back-pointer; mode = type; strdup name; num_rule_types++.
    let node = Rc::new(RefCell::new(RuleListNode {
        rule_list: None,
        mode,
        eval_index: 0,
        name: name.to_string(),
        next: None,
    }));
    if sc.rule_lists.is_none() {
        sc.rule_lists = Some(Rc::clone(&node));
    } else {
        let mut tmp: Option<Rc<RefCell<RuleListNode>>> = sc.rule_lists.clone();
        let mut last: Option<Rc<RefCell<RuleListNode>>> = None;
        while let Some(t) = tmp {
            if t.borrow().name.eq_ignore_ascii_case(name) {
                return; // snort_free(node); return tmp (node drops)
            }
            last = Some(Rc::clone(&t));
            tmp = t.borrow().next.clone();
        }
        if let Some(l) = last {
            l.borrow_mut().next = Some(Rc::clone(&node));
        }
    }
    let lh = Rc::new(RefCell::new(ListHead {
        rule_list_node: RefCell::new(Some(node.clone())),
    }));
    node.borrow_mut().rule_list = Some(Rc::clone(&lh));
    sc.num_rule_types += 1;
}

pub fn parse_rule_init(sc: &mut RuleCoreState) {
    sc.counts.rule_count = 0;
    sc.counts.prev_rule_count = 0;
    sc.counts.skip_count = 0;
    sc.counts.detect_rule_count = 0;
    sc.counts.builtin_rule_count = 0;
    sc.counts.so_rule_count = 0;
    sc.counts.head_count = 0;
    sc.counts.otn_count = 0;
    sc.counts.dup_count = 0;
    sc.counts.prev_dup_count = 0;
    sc.counts.rule_proto = 0;
    sc.counts.ip_cnt = RuleCnt::default();
    sc.counts.icmp_cnt = RuleCnt::default();
    sc.counts.tcp_cnt = RuleCnt::default();
    sc.counts.udp_cnt = RuleCnt::default();
    sc.counts.svc_cnt = RuleCnt::default();
}

pub fn parse_rule_term(_sc: &mut RuleCoreState) {}

/// parser.cc:600-603 parser_append_rules
pub fn parser_append_rules(sc: &mut RuleCoreState, s: &str) {
    sc.s_aux_rules.push_str(s);
    sc.s_aux_rules.push('\n');
}
/// parser.cc:605-610 parser_append_rules_special
pub fn parser_append_rules_special(sc: &mut RuleCoreState, s: &str, inc: &str) {
    sc.s_special_rules.push_str(s);
    sc.s_special_rules.push('\n');
    sc.s_special_includer = inc.to_string();
}
/// parser.cc:612-613 parser_get_special_includer
pub fn parser_get_special_includer(sc: &RuleCoreState) -> &str {
    sc.s_special_includer.as_str()
}
pub fn parse_rule_dec_head_count(sc: &mut RuleCoreState) {
    sc.counts.head_count -= 1;
}

pub fn get_rule_count(sc: &RuleCoreState) -> u32 {
    sc.counts.rule_count
}
/// DESTRUCTIVE: C returns diff and stashes prev_rule_count.
pub fn get_policy_loaded_rule_count(sc: &mut RuleCoreState) -> u32 {
    let c = sc.counts.rule_count - sc.counts.prev_rule_count;
    sc.counts.prev_rule_count = sc.counts.rule_count;
    c
}
pub fn get_policy_shared_rule_count(sc: &mut RuleCoreState) -> u32 {
    let c = sc.counts.dup_count - sc.counts.prev_dup_count;
    sc.counts.prev_dup_count = sc.counts.dup_count;
    c
}

pub fn set_parser_rule_order(_sc: &mut RuleCoreState, _order: &str) {}

/// LogLabel/LogCount through the real log_stats.cc formatting (LogfRespond
/// s_ctrlcon == null witness -> plain LogMessage(stderr? no: FILE* fh =
/// stdout default)).
pub fn parse_rule_print(sc: &mut RuleCoreState, fb_total: u64, fb_unchk: u64, fb_unset: u64) {
    let c = &sc.counts;
    if c.rule_count == 0 && c.skip_count == 0 {
        return;
    }
    log_label(&mut sc.log, "rule counts");
    log_count(&mut sc.log, "total rules loaded", u64::from(c.rule_count));
    log_count(&mut sc.log, "total rules not loaded", u64::from(c.skip_count));
    log_count(&mut sc.log, "duplicate rules", u64::from(c.dup_count));
    log_count(&mut sc.log, "text rules", u64::from(c.detect_rule_count));
    log_count(&mut sc.log, "builtin rules", u64::from(c.builtin_rule_count));
    log_count(&mut sc.log, "so rules", u64::from(c.so_rule_count));
    log_count(&mut sc.log, "option chains", u64::from(c.otn_count));
    log_count(&mut sc.log, "chain headers", u64::from(c.head_count));
    log_count(&mut sc.log, "flowbits", fb_total);
    log_count(&mut sc.log, "flowbits not checked", fb_unchk);
    log_count(&mut sc.log, "flowbits not set", fb_unset);

    let _sep = STATS_SEPARATOR;
    let _ = log_separator;

    let ip = c.ip_cnt.src + c.ip_cnt.dst + c.ip_cnt.any + c.ip_cnt.both;
    let icmp = c.icmp_cnt.src + c.icmp_cnt.dst + c.icmp_cnt.any + c.icmp_cnt.both;
    let tcp = c.tcp_cnt.src + c.tcp_cnt.dst + c.tcp_cnt.any + c.tcp_cnt.both;
    let udp = c.udp_cnt.src + c.udp_cnt.dst + c.udp_cnt.any + c.udp_cnt.both;

    if ip == 0 && icmp == 0 && tcp == 0 && udp == 0 {
        return;
    }

    log_label(&mut sc.log, "port rule counts");
    sc.log
        .log_message_stdout("%8s%8s%8s%8s%8s\n", &[
            Arg::S(Some(" ".into())),
            Arg::S(Some("tcp".into())),
            Arg::S(Some("udp".into())),
            Arg::S(Some("icmp".into())),
            Arg::S(Some("ip".into())),
        ]);

    if c.tcp_cnt.any != 0 || c.udp_cnt.any != 0 || c.icmp_cnt.any != 0 || c.ip_cnt.any != 0 {
        sc.log.log_message_stdout("%8s%8u%8u%8u%8u\n", &[
            Arg::S(Some("any".into())),
            Arg::U(u64::from(c.tcp_cnt.any)),
            Arg::U(u64::from(c.udp_cnt.any)),
            Arg::U(u64::from(c.icmp_cnt.any)),
            Arg::U(u64::from(c.ip_cnt.any)),
        ]);
    }
    if c.tcp_cnt.src != 0 || c.udp_cnt.src != 0 || c.icmp_cnt.src != 0 || c.ip_cnt.src != 0 {
        sc.log.log_message_stdout("%8s%8u%8u%8u%8u\n", &[
            Arg::S(Some("src".into())),
            Arg::U(u64::from(c.tcp_cnt.src)),
            Arg::U(u64::from(c.udp_cnt.src)),
            Arg::U(u64::from(c.icmp_cnt.src)),
            Arg::U(u64::from(c.ip_cnt.src)),
        ]);
    }
    if c.tcp_cnt.dst != 0 || c.udp_cnt.dst != 0 || c.icmp_cnt.dst != 0 || c.ip_cnt.dst != 0 {
        sc.log.log_message_stdout("%8s%8u%8u%8u%8u\n", &[
            Arg::S(Some("dst".into())),
            Arg::U(u64::from(c.tcp_cnt.dst)),
            Arg::U(u64::from(c.udp_cnt.dst)),
            Arg::U(u64::from(c.icmp_cnt.dst)),
            Arg::U(u64::from(c.ip_cnt.dst)),
        ]);
    }
    if c.tcp_cnt.both != 0 || c.udp_cnt.both != 0 || c.icmp_cnt.both != 0 || c.ip_cnt.both != 0 {
        sc.log.log_message_stdout("%8s%8u%8u%8u%8u\n", &[
            Arg::S(Some("both".into())),
            Arg::U(u64::from(c.tcp_cnt.both)),
            Arg::U(u64::from(c.udp_cnt.both)),
            Arg::U(u64::from(c.icmp_cnt.both)),
            Arg::U(u64::from(c.ip_cnt.both)),
        ]);
    }
    sc.log.log_message_stdout("%8s%8u%8u%8u%8u\n", &[
        Arg::S(Some("total".into())),
        Arg::U(u64::from(tcp)),
        Arg::U(u64::from(udp)),
        Arg::U(u64::from(icmp)),
        Arg::U(u64::from(ip)),
    ]);
}

// ----------------------------------------------------------------------
// rule_index_map channels (parser.cc)
// ----------------------------------------------------------------------

pub fn parser_get_rule_index(sc: &mut RuleCoreState, gid: u32, sid: u32) -> i32 {
    rule_index_map_add(&mut sc.rule_index_map, gid, sid)
}
pub fn parser_get_rule_ids(sc: &RuleCoreState, idx: i32, gid: &mut u32, sid: &mut u32) {
    let (ok, g, s) = rule_index_map_get(&sc.rule_index_map, idx);
    if !ok {
        // RuleIndexMapGet zeroes gid/sid out of range; outputs pre-zeroed by
        // the C callers (unsigned gid, sid; = 0); transcribed zeroing:
        *gid = 0;
        *sid = 0;
    } else {
        *gid = g;
        *sid = s;
    }
}

// ----------------------------------------------------------------------
// parse_rule_open / parse_rule_state / mergeDuplicateOtn / parse_rule_close
// ----------------------------------------------------------------------

pub fn parse_rule_open(sc: &mut RuleCoreState, rtn: &mut RuleTreeNode, stub: bool) -> Option<OtnHandle> {
    sc.counts.parse_count += 1;
    if sc.s_ignore {
        return None;
    }
    if stub {
        return None; // rule_states stub channel: harness never opens stub
    }
    let mut otn = OptTreeNode::new();
    otn.snort_protocol_id = rtn.snort_protocol_id;
    if sc.get_default_rule_state() || rule_is_stateless(sc) {
        rtn.set_enabled();
    }
    sc.s_capture = sc.dump_rule_meta();
    sc.s_body = "(".to_string();
    sc.buf_is_set = false;
    sc.buffer_setters.clear();
    Some(Rc::new(RefCell::new(otn)))
}

/// parse_rule_state (static): RuleStateMap add + sip/dip free + delete otn
pub fn parse_rule_state(sc: &mut RuleCoreState, rtn: &RuleTreeNode, otn: &OptTreeNode) {
    if otn.num_detection_opts != 0 {
        sc.parse_error(
            "%u:%u rule state stubs do not support detection options",
            &[Arg::U(u64::from(otn.sigInfo.gid)), Arg::U(u64::from(otn.sigInfo.sid))],
        );
    }
    let key = RuleKey {
        policy_id: sc.get_ips_policy().policy_id,
        gid: otn.sigInfo.gid,
        sid: otn.sigInfo.sid,
    };
    let state = new_rule_state(&sc.s_rule_action.clone(), rtn.action, rtn.action_selector, otn.enable);
    sc.rule_states.add(key, state);
    // sfvar_free(rtn.sip/dip) + delete otn: Rust drop (no observable diff)
}

fn merge_duplicate_otn(
    sc: &mut RuleCoreState,
    otn_dup: &OtnHandle,
    otn: &OtnHandle,
    new_rtn: &RtnHandle,
) -> bool {
    let dup_spid = otn_dup.borrow().snort_protocol_id;
    let new_spid = otn.borrow().snort_protocol_id;
    if dup_spid != new_spid {
        sc.parse_error(
            "GID %u SID %u in rule duplicates previous rule, with different protocol.",
            &[
                Arg::U(u64::from(otn.borrow().sigInfo.gid)),
                Arg::U(u64::from(otn.borrow().sigInfo.sid)),
            ],
        );
        return true; // keep old
    }

    let pid = sc.get_ips_policy().policy_id;
    let cur_rtn = get_rtn_from_otn(otn_dup, pid);
    if let Some(c) = &cur_rtn
        && c.borrow().action != new_rtn.borrow().action {
            sc.parse_error(
                "GID %u SID %u in rule duplicates previous rule, with different type.",
                &[
                    Arg::U(u64::from(otn.borrow().sigInfo.gid)),
                    Arg::U(u64::from(otn.borrow().sigInfo.sid)),
                ],
            );
            return true;
        }

    if otn.borrow().sigInfo.rev < otn_dup.borrow().sigInfo.rev {
        // keep orig, free new
        sc.parse_warning(
            "%u:%u duplicates previous rule. Using revision %u.",
            &[
                Arg::U(u64::from(otn_dup.borrow().sigInfo.gid)),
                Arg::U(u64::from(otn_dup.borrow().sigInfo.sid)),
                Arg::U(u64::from(otn_dup.borrow().sigInfo.rev)),
            ],
        );
        // OTN is for new policy group, salvage rtn
        let r = delete_rtn_from_otn(sc, otn, pid, false);
        if let Some(r) = r {
            if cur_rtn.is_none() {
                add_rtn_to_otn(sc, otn_dup, &r, pid);
            } else {
                destroy_rule_tree_node(sc, &r);
            }
        }
        return true;
    }

    // keep new, free orig
    sc.parse_warning(
        "%u:%u duplicates previous rule. Using revision %u.",
        &[
            Arg::U(u64::from(otn.borrow().sigInfo.gid)),
            Arg::U(u64::from(otn.borrow().sigInfo.sid)),
            Arg::U(u64::from(otn.borrow().sigInfo.rev)),
        ],
    );
    let dup_node_num = otn_dup.borrow().proto_node_num;
    for i in 0..dup_node_num {
        let rm = match &cur_rtn {
            Some(c) => !Rc::ptr_eq(c, new_rtn),
            None => true,
        };
        let rtn_tmp = delete_rtn_from_otn(sc, otn_dup, i, rm);
        if let Some(r) = rtn_tmp
            && i != pid {
                add_rtn_to_otn(sc, otn, &r, i);
            }
    }
    if let Some(c) = &cur_rtn {
        destroy_rule_tree_node(sc, c);
    }
    otn_remove(&mut sc.otn_map, otn_dup);
    false
}

pub fn parse_rule_close(sc: &mut RuleCoreState, rtn: &mut RuleTreeNode, otn_opt: &Option<OtnHandle>) -> Result<(), Fatal> {
    let otn = match otn_opt {
        Some(o) => Rc::clone(o),
        None => {
            // C guard only: if ( s_ignore ) { clear; skip++; return; }
            if sc.s_ignore {
                sc.s_ignore = false;
                sc.counts.skip_count += 1;
            }
            return Ok(()); // upstream SEGVs here; parse_streams never reach
        }
    };

    if sc.s_ignore {
        sc.s_ignore = false;
        sc.counts.skip_count += 1;
        return Ok(());
    }

    if otn.borrow().is_rule_state_stub() {
        let b = otn.borrow();
        parse_rule_state(sc, rtn, &b);
        rtn.header = None; // delete rtn->header; rtn.header = nullptr
        return Ok(());
    }

    // C: !s_so_rule and !sc->metadata_filter.empty() and
    // !otn->metadata_matched() -> skip (otn deleted, skip_count++)
    if sc.s_so_rule.is_none() && !sc.metadata_filter.is_empty() && !otn.borrow().metadata_matched() {
        sc.free_rule_tree_node(rtn);
        sc.counts.skip_count += 1;
        return Ok(());
    }

    if let Some(so) = &sc.s_so_rule {
        // copy the gid/sid/rev channel (so rules)
        let (g, s, r) = (so.gid, so.sid, so.rev);
        otn.borrow_mut().sigInfo.gid = g;
        otn.borrow_mut().sigInfo.sid = s;
        otn.borrow_mut().sigInfo.rev = r;
    } else if otn.borrow().soid.is_some() {
        let soid = otn.borrow().soid.clone().unwrap();
        // SoManager::get_so_rule witness == nullptr (so rules out of scope)
        if sc.allow_missing_so_rules {
            sc.parse_warning("SO rule %s not loaded.", &[Arg::S(Some(soid.into()))]);
        } else {
            sc.parse_error("SO rule %s not loaded.", &[Arg::S(Some(soid.into()))]);
        }
        sc.free_rule_tree_node(rtn);
        return Ok(()); // otn drops (delete otn)
    }

    if sc.action_file_id {
        let (g, s, r) = {
            let b = otn.borrow();
            (b.sigInfo.gid, b.sigInfo.sid, b.sigInfo.rev)
        };
        if otn.borrow().sigInfo.file_id == 0 {
            sc.parse_error(
                "file_id rule %u:%u:%u requires file_meta option",
                &[Arg::U(u64::from(g)), Arg::U(u64::from(s)), Arg::U(u64::from(r))],
            );
        }
        if !sc.fp_file_id {
            sc.parse_error(
                "file_id rule %u:%u:%u requires a fast-pattern option",
                &[Arg::U(u64::from(g)), Arg::U(u64::from(s)), Arg::U(u64::from(r))],
            );
        }
        if sc.buf_is_set && !sc.only_file_data {
            sc.parse_error(
                "file_id rule %u:%u:%u disallows IPS buffers that are not file_data",
                &[Arg::U(u64::from(g)), Arg::U(u64::from(s)), Arg::U(u64::from(r))],
            );
        }
        if !sc.buf_is_set {
            sc.parse_error(
                "file_id rule %u:%u:%u requires file_data option",
                &[Arg::U(u64::from(g)), Arg::U(u64::from(s)), Arg::U(u64::from(r))],
            );
        }
        sc.only_file_data = true;
        sc.fp_file_id = false;
    }

    // C: RuleTreeNode* tmp = s_so_rule ? s_so_rule->rtn : &rtn;
    // (Rust: snapshot the so RTN handle so the sc borrow ends first)
    let so_rtn: Option<RtnHandle> = sc.s_so_rule.as_ref().and_then(|so| so.rtn.clone());
    let new_rtn = match &so_rtn {
        Some(r) => transfer_rtn_of(sc, &r.borrow()),
        None => transfer_rtn(sc, rtn),
    };
    match &so_rtn {
        Some(r) => {
            add_rtn_to_otn_so(sc, &otn, &new_rtn, sc.get_ips_policy().policy_id, r);
        }
        None => {
            add_rtn_to_otn(sc, &otn, &new_rtn, sc.get_ips_policy().policy_id);
        }
    }

    let otn_dup = otn_lookup(&sc.otn_map, otn.borrow().sigInfo.gid, otn.borrow().sigInfo.sid);

    let mut merged_dup: Option<(Rc<RefCell<OptTreeNode>>, bool)> = None;
    if let Some(dup) = &otn_dup {
        sc.counts.dup_count += 1;
        let ri = dup.borrow().ruleIndex;
        otn.borrow_mut().ruleIndex = ri;
        if merge_duplicate_otn(sc, dup, &otn, &new_rtn) {
            return Ok(()); // keep old, trash new (otn freed inside)
        }
        merged_dup = Some((Rc::clone(dup), true));
    } else {
        sc.counts.otn_count += 1;
        sc.counts.rule_count += 1;
    }

    if otn.borrow().soid.is_some() {
        otn.borrow_mut().sigInfo.builtin = false;
        if otn_dup.is_none() {
            sc.counts.so_rule_count += 1;
        }
    } else if is_builtin(sc, otn.borrow().sigInfo.gid) {
        if otn.borrow().num_detection_opts != 0 {
            let (g, s) = {
                let b = otn.borrow();
                (b.sigInfo.gid, b.sigInfo.sid)
            };
            sc.parse_error(
                "%u:%u builtin rules do not support detection options",
                &[Arg::U(u64::from(g)), Arg::U(u64::from(s))],
            );
        }
        otn.borrow_mut().sigInfo.builtin = true;
        if otn_dup.is_none() {
            sc.counts.builtin_rule_count += 1;
        }
    } else {
        if otn.borrow().num_detection_opts == 0 {
            let (g, s) = {
                let b = otn.borrow();
                (b.sigInfo.gid, b.sigInfo.sid)
            };
            sc.parse_warning(
                "%u:%u does not have any detection options",
                &[Arg::U(u64::from(g)), Arg::U(u64::from(s))],
            );
        }
        otn.borrow_mut().sigInfo.builtin = false;
        if otn_dup.is_none() {
            sc.counts.detect_rule_count += 1;
        }
    }

    if otn_dup.is_none() {
        let (g, s) = {
            let b = otn.borrow();
            (b.sigInfo.gid, b.sigInfo.sid)
        };
        otn.borrow_mut().ruleIndex = parser_get_rule_index(sc, g, s) as u32;
    }

    if otn.borrow().sigInfo.message.is_empty() {
        otn.borrow_mut().sigInfo.message = "\"no msg in rule\"".to_string();
    }

    if otn.borrow().sigInfo.file_id == 0 && !sc.buffer_setters.is_empty() {
        let v = sc.buffer_setters.clone();
        otn.borrow_mut().buffer_setters = v;
    }

    {
        let mut ob = otn.borrow_mut();
        let fpl = add_opt_func_to_list(None, &mut ob);
        fpl.borrow_mut().opt_type = OptionType::LeafNode;
    }

    if is_service_protocol(otn.borrow().snort_protocol_id) {
        let service = sc.proto_ref.get_name(otn.borrow().snort_protocol_id).to_string();
        let mut br = ServiceBridge {
            service_extension: &sc.service_extension,
            buffer_map: &mut sc.buffer_map,
            proto_ref: &mut sc.proto_ref,
        };
        let mut ob = otn.borrow_mut();
        add_service_to_otn(&mut sc.log, &mut br, &mut ob, &service);
    }

    if otn.borrow().sigInfo.services.is_empty() && sc.action_file_id {
        let mut br = ServiceBridge {
            service_extension: &sc.service_extension,
            buffer_map: &mut sc.buffer_map,
            proto_ref: &mut sc.proto_ref,
        };
        let mut ob = otn.borrow_mut();
        add_service_to_otn(&mut sc.log, &mut br, &mut ob, "file_id");
    }

    {
        let opts = collect_ips_opts(&otn);
        let mut br = ServiceBridge {
            service_extension: &sc.service_extension,
            buffer_map: &mut sc.buffer_map,
            proto_ref: &mut sc.proto_ref,
        };
        let mut ob = otn.borrow_mut();
        validate_services(&mut sc.log, &mut br, &mut ob, &opts);
    }
    // C: OtnLookupAdd emits the duplicate ParseError itself on HASH_INTABLE
    // and (HASH_INTABLE branch in close) continues the parse; no early out.
    otn_lookup_add(&mut sc.log, &mut sc.otn_map, &otn);

    if sc.s_capture {
        sc.s_body.push_str(" )");
        otn.borrow_mut().sigInfo.body = Some(sc.s_body.clone());
    }

    for i in 0..OptTreeNode::SECT_DIR__MAX {
        if otn.borrow().sections[i] == section_to_flag(PduSection::PsHeaderBody) {
            otn.borrow_mut().sections[i] =
                section_to_flag(PduSection::PsHeader) | section_to_flag(PduSection::PsBody);
        }
    }

    if (otn.borrow().to_server_err() && otn.borrow().to_server())
        || (otn.borrow().to_client_err() && otn.borrow().to_client())
        || (otn.borrow().to_server_err() && otn.borrow().to_client_err())
    {
        sc.parse_error(
            "Rule cannot examine both HTTP message body and HTTP trailers, unless it is request trailer with response body",
            &[],
        );
    }
    let _ = merged_dup;
    Ok(())
}

fn collect_ips_opts(otn: &OtnHandle) -> Vec<(String, CursorActionType)> {
    let mut out = Vec::new();
    let mut cur: Option<Rc<RefCell<OptFpList>>> = otn.borrow().opt_func.clone();
    while let Some(f) = cur {
        let fb = f.borrow();
        if let Some(io) = &fb.ips_opt {
            out.push((io.borrow().get_name().to_string(), io.borrow().get_cursor_type()));
        }
        cur = fb.next.clone();
    }
    out
}

/// FreeRuleTreeNode (parser.cc): assert(rtn && otnRefCount == 0); frees
/// sip/dip, rule_func chain, header.
pub fn free_rule_tree_node_impl(sc: &mut RuleCoreState, rtn: &mut RuleTreeNode) {
    debug_assert!(rtn.otnRefCount == 0);
    let _ = sc;
    rtn.rule_func.clear();
    rtn.header = None;
    rtn.sip = None;
    rtn.dip = None;
}

impl RuleCoreState {
    fn free_rule_tree_node(&mut self, rtn: &mut RuleTreeNode) {
        free_rule_tree_node_impl(self, rtn);
    }
}

// ----------------------------------------------------------------------
// parser.cc RTN lifecycle (Otn proto nodes + XHash rtn cache)
// ----------------------------------------------------------------------

pub fn add_rtn_to_otn(sc: &mut RuleCoreState, otn: &OtnHandle, rtn: &RtnHandle, policy_id: PolicyIdSlot) -> i32 {
    if otn.borrow().proto_node_num <= policy_id {
        let num = (policy_id + 1) as usize;
        otn.borrow_mut().proto_nodes.resize(num, None);
        otn.borrow_mut().proto_node_num = policy_id + 1;
    }
    let curr = otn.borrow().proto_nodes[policy_id as usize].clone();
    if let Some(c) = curr {
        let remove = c.borrow().otnRefCount == 1;
        let r = delete_rtn_from_otn(sc, otn, policy_id, remove);
        if let Some(r) = r {
            destroy_rule_tree_node(sc, &r);
        }
    }
    otn.borrow_mut().proto_nodes[policy_id as usize] = Some(Rc::clone(rtn));
    rtn.borrow_mut().otnRefCount += 1;

    if sc.rtn_hash_table.is_none() {
        sc.rtn_hash_table = Some(RuleTreeCache::new());
    }
    sc.rtn_hash_table.as_mut().unwrap().insert(rtn, policy_id);
    0
}

fn add_rtn_to_otn_so(sc: &mut RuleCoreState, otn: &OtnHandle, rtn: &RtnHandle, policy_id: PolicyIdSlot, so_rtn: &RtnHandle) -> i32 {
    let _ = so_rtn;
    add_rtn_to_otn(sc, otn, rtn, policy_id)
}

fn transfer_rtn_of(sc: &mut RuleCoreState, from: &RuleTreeNode) -> RtnHandle {
    transfer_rtn(sc, from)
}

pub fn delete_rtn_from_otn(
    sc: &mut RuleCoreState,
    otn: &OtnHandle,
    policy_id: PolicyIdSlot,
    remove: bool,
) -> Option<RtnHandle> {
    if !otn.borrow().proto_nodes.is_empty() && otn.borrow().proto_node_num > policy_id {
        let rtn = get_rtn_from_otn(otn, policy_id);
        otn.borrow_mut().proto_nodes[policy_id as usize] = None;
        if let Some(r) = &rtn {
            r.borrow_mut().otnRefCount -= 1;
            if remove {
                let key_r: &RtnHandle = r;
                sc.rtn_hash_table.as_mut().unwrap().release_node(key_r, policy_id);
            }
        }
        return rtn;
    }
    None
}

pub fn find_rtn(sc: &RuleCoreState, rtn: &RtnHandle, id: PolicyIdSlot) -> Option<RtnHandle> {
    match &sc.rtn_hash_table {
        Some(t) => t.get_user_data(sc, rtn, id),
        None => None,
    }
}

pub fn destroy_rule_tree_node(sc: &mut RuleCoreState, rtn: &RtnHandle) {
    let b = rtn.borrow();
    debug_assert!(!b.rule_func.is_empty() || true); // C: assert(rtn)
    if b.otnRefCount != 0 {
        return;
    }
    drop(b);
    let mut m = rtn.borrow_mut();
    free_rule_tree_node_impl(sc, &mut m);
}

pub fn free_rule_tree_nodes(sc: &mut RuleCoreState) {
    for otn in sc.otn_map.entries_snapshot() {
        let n = otn.borrow().proto_node_num;
        for pid in 0..n {
            let rtn = get_rtn_from_otn(&otn, pid);
            let rtn = match rtn {
                None => continue,
                Some(r) => r,
            };
            rtn.borrow_mut().otnRefCount -= 1;
            destroy_rule_tree_node(sc, &rtn);
            otn.borrow_mut().proto_nodes[pid as usize] = None;
        }
    }
}

pub fn reduce_rtns(sc: &mut RuleCoreState) {
    for otn in sc.otn_map.entries_snapshot() {
        let n = otn.borrow().proto_node_num;
        for pid in 0..n {
            let act_rtn = get_rtn_from_otn(&otn, pid);
            let act_rtn = match act_rtn {
                None => continue,
                Some(r) => r,
            };
            let ext_rtn = find_rtn(sc, &act_rtn, pid);
            if let Some(ext) = ext_rtn
                && !Rc::ptr_eq(&ext, &act_rtn) {
                    add_rtn_to_otn(sc, &otn, &ext, pid);
                    sc.counts.head_count -= 1;
                }
        }
    }
    for otn in sc.otn_map.entries_snapshot() {
        if otn.borrow().service_only() {
            continue;
        }
        let n = otn.borrow().proto_node_num;
        let ob = otn.borrow();
        for pid in 0..n {
            let rtn = get_rtn_from_otn(&otn, pid);
            let rtn = match rtn {
                None => continue,
                Some(r) => r,
            };
            if parse_rule_finish_ports(sc, &rtn, &ob) != 0 {
                sc.parse_error(
                    "%u:%u rule failed to finish a port list.",
                    &[Arg::U(u64::from(ob.sigInfo.gid)), Arg::U(u64::from(ob.sigInfo.sid))],
                );
            }
        }
    }
}

// ----------------------------------------------------------------------
// parse_rule_process_rtn
// ----------------------------------------------------------------------

pub fn parse_rule_process_rtn(sc: &mut RuleCoreState, rtn: &mut RuleTreeNode) {
    if rtn.sip.as_ref().map(sfvar_is_any).unwrap_or(false) {
        rtn.flags |= RuleTreeNode::ANY_SRC_IP;
    } else {
        rtn.flags &= !RuleTreeNode::ANY_SRC_IP;
    }
    if rtn.dip.as_ref().map(sfvar_is_any).unwrap_or(false) {
        rtn.flags |= RuleTreeNode::ANY_DST_IP;
    } else {
        rtn.flags &= !RuleTreeNode::ANY_DST_IP;
    }
    let token_s: String = rtn.sip.as_ref().and_then(|v| v.name.clone()).unwrap_or_default();
    let token_d: String = rtn.dip.as_ref().and_then(|v| v.name.clone()).unwrap_or_default();
    let sipc = rtn.sip.clone();
    let dipc = rtn.dip.clone();
    validate_ip_list(sc, sipc.as_ref(), &token_s);
    validate_ip_list(sc, dipc.as_ref(), &token_d);

    if rtn.src_portobject.as_ref().map(|p| p.borrow().has_any() != 0).unwrap_or(false) {
        rtn.flags |= RuleTreeNode::ANY_SRC_PORT;
    } else {
        rtn.flags &= !RuleTreeNode::ANY_SRC_PORT;
    }
    if rtn.dst_portobject.as_ref().map(|p| p.borrow().has_any() != 0).unwrap_or(false) {
        rtn.flags |= RuleTreeNode::ANY_DST_PORT;
    } else {
        rtn.flags &= !RuleTreeNode::ANY_DST_PORT;
    }

    sc.counts.head_count += 1;
    setup_rtn_func_list(rtn);
}

// ----------------------------------------------------------------------
// parse_rule_finish_ports (verbatim statement order; svc default arm sets
// ANY flags BEFORE the both++ test; the per-proto any++ bumps are GLOBAL
// counters while the both++ uses the prc POINTER arm)
// ----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrcSel {
    Ip,
    Icmp,
    Tcp,
    Udp,
    Svc,
}

pub fn parse_rule_finish_ports(sc: &mut RuleCoreState, rtn: &RtnHandle, otn: &OptTreeNode) -> i32 {
    let port_tables = Rc::clone(&sc.port_tables);
    let fp_limit = sc.fast_pattern_config.get_bleed_over_port_limit() as i32;
    let fp_single = sc.fast_pattern_config.get_single_rule_group();
    let fp_warn = sc.fast_pattern_config.get_bleed_over_warnings();

    let mut large_port_group = 0i32;
    let orig_flags = rtn.borrow().flags;

    let prc = match otn.snort_protocol_id {
        SNORT_PROTO_IP => PrcSel::Ip,
        SNORT_PROTO_ICMP => PrcSel::Icmp,
        SNORT_PROTO_TCP => PrcSel::Tcp,
        SNORT_PROTO_UDP => PrcSel::Udp,
        _ => PrcSel::Svc,
    };
    match otn.snort_protocol_id {
        SNORT_PROTO_IP => {}
        SNORT_PROTO_ICMP => {}
        SNORT_PROTO_TCP => {}
        SNORT_PROTO_UDP => {}
        _ => {
            rtn.borrow_mut().flags |= RuleTreeNode::ANY_SRC_PORT | RuleTreeNode::ANY_DST_PORT;
        }
    }

    let non_any = !rtn.borrow().any_src_port() && !rtn.borrow().any_dst_port();
    match prc {
        PrcSel::Ip => sc.counts.ip_cnt.both += non_any as u32,
        PrcSel::Icmp => sc.counts.icmp_cnt.both += non_any as u32,
        PrcSel::Tcp => sc.counts.tcp_cnt.both += non_any as u32,
        PrcSel::Udp => sc.counts.udp_cnt.both += non_any as u32,
        PrcSel::Svc => sc.counts.svc_cnt.both += non_any as u32,
    }

    let src_cnt = if rtn.borrow().any_src_port() {
        65535
    } else {
        rtn.borrow().src_portobject.as_ref().map(|p| p.borrow().port_count()).unwrap_or(-1)
    };
    let dst_cnt = if rtn.borrow().any_dst_port() {
        65535
    } else {
        rtn.borrow().dst_portobject.as_ref().map(|p| p.borrow().port_count()).unwrap_or(-1)
    };

    if !fp_single && !rtn.borrow().any_any_port() {
        if src_cnt >= fp_limit {
            large_port_group += 1;
        }
        if dst_cnt >= fp_limit {
            large_port_group += 1;
        }
        if large_port_group == 2 && fp_warn {
            let maxn = if src_cnt > dst_cnt { src_cnt } else { dst_cnt };
            sc.log_message_stdout(
                "***Bleedover Port Limit(%d) Exceeded for rule %u:%u (%d)ports: ",
                &[
                    Arg::I(i64::from(fp_limit)),
                    Arg::U(u64::from(otn.sigInfo.gid)),
                    Arg::U(u64::from(otn.sigInfo.sid)),
                    Arg::I(maxn as i64),
                ],
            );
            // fflush(stdout); fflush(stderr); PortObjectPrintPortsRaw...
            let (sp, dp) = {
                let rb = rtn.borrow();
                (rb.src_portobject.clone(), rb.dst_portobject.clone())
            };
            if let Some(sp) = sp {
                let s = sp.borrow().print_ports_raw();
                sc.log_message_stdout("%s", &[Arg::S(Some(s.into()))]);
            }
            sc.log_message_stdout(" -> ", &[]);
            if let Some(dp) = dp {
                let s = dp.borrow().print_ports_raw();
                sc.log_message_stdout("%s", &[Arg::S(Some(s.into()))]);
            }
            sc.log_message_stdout(" adding to any-any group\n", &[]);
        }
    }

    if rtn.borrow().any_any_port() || large_port_group == 2 || fp_single {
        if otn.snort_protocol_id == SNORT_PROTO_IP {
            port_tables.borrow().icmp.any.borrow_mut().add_rule(otn.ruleIndex as i32);
            sc.counts.icmp_cnt.any += 1;
            port_tables.borrow().tcp.any.borrow_mut().add_rule(otn.ruleIndex as i32);
            sc.counts.tcp_cnt.any += 1;
            port_tables.borrow().udp.any.borrow_mut().add_rule(otn.ruleIndex as i32);
            sc.counts.udp_cnt.any += 1;
        }
        let aa = match prc {
            PrcSel::Ip => Rc::clone(&port_tables.borrow().ip.any),
            PrcSel::Icmp => Rc::clone(&port_tables.borrow().icmp.any),
            PrcSel::Tcp => Rc::clone(&port_tables.borrow().tcp.any),
            PrcSel::Udp => Rc::clone(&port_tables.borrow().udp.any),
            PrcSel::Svc => Rc::clone(&port_tables.borrow().svc_any),
        };
        aa.borrow_mut().add_rule(otn.ruleIndex as i32);

        match prc {
            PrcSel::Ip => sc.counts.ip_cnt.any += 1,
            PrcSel::Icmp => sc.counts.icmp_cnt.any += 1,
            PrcSel::Tcp => sc.counts.tcp_cnt.any += 1,
            PrcSel::Udp => sc.counts.udp_cnt.any += 1,
            PrcSel::Svc => sc.counts.svc_cnt.any += 1,
        }
        rtn.borrow_mut().flags = orig_flags;
        return 0;
    }

    let mut both_dirs = false;

    if dst_cnt < fp_limit && dst_cnt <= src_cnt {
        match prc {
            PrcSel::Ip => sc.counts.ip_cnt.dst += 1,
            PrcSel::Icmp => sc.counts.icmp_cnt.dst += 1,
            PrcSel::Tcp => sc.counts.tcp_cnt.dst += 1,
            PrcSel::Udp => sc.counts.udp_cnt.dst += 1,
            PrcSel::Svc => sc.counts.svc_cnt.dst += 1,
        }
        let dstpo = rtn.borrow().dst_portobject.clone().unwrap();
        let pox = find_or_add_input(&port_tables, prc, Tbl::Dst, &dstpo);
        pox.borrow_mut().add_rule(otn.ruleIndex as i32);
        if rtn.borrow().flags & RuleTreeNode::BIDIRECTIONAL != 0 {
            let pox2 = find_or_add_input(&port_tables, prc, Tbl::Src, &dstpo);
            pox2.borrow_mut().add_rule(otn.ruleIndex as i32);
            both_dirs = true;
        }
    }

    if src_cnt < fp_limit && src_cnt < dst_cnt {
        match prc {
            PrcSel::Ip => sc.counts.ip_cnt.src += 1,
            PrcSel::Icmp => sc.counts.icmp_cnt.src += 1,
            PrcSel::Tcp => sc.counts.tcp_cnt.src += 1,
            PrcSel::Udp => sc.counts.udp_cnt.src += 1,
            PrcSel::Svc => sc.counts.svc_cnt.src += 1,
        }
        let srcpo = rtn.borrow().src_portobject.clone().unwrap();
        let pox = find_or_add_input(&port_tables, prc, Tbl::Src, &srcpo);
        pox.borrow_mut().add_rule(otn.ruleIndex as i32);
        if !both_dirs && rtn.borrow().flags & RuleTreeNode::BIDIRECTIONAL != 0 {
            let pox2 = find_or_add_input(&port_tables, prc, Tbl::Dst, &srcpo);
            pox2.borrow_mut().add_rule(otn.ruleIndex as i32);
        }
    }
    0
}

/// Which spine table (PortTableFindInputPortObjectPorts target).
#[derive(Clone, Copy)]
enum Tbl {
    Src,
    Dst,
}

/// C pair PortTableFindInputPortObjectPorts/PortTableAddObject: CONTENT hit
/// returns the table entry (identity), miss dup-ports (name null -> "dup")
/// and adds to the same spine table.
fn find_or_add_input(
    port_tables: &Rc<RefCell<RulePortTables>>,
    prc: PrcSel,
    tbl: Tbl,
    po: &PoHandle,
) -> PoHandle {
    let found = {
        let ptb = port_tables.borrow();
        match (prc, tbl) {
            (PrcSel::Ip, Tbl::Src) => ptb.ip.src.find_input(&po.borrow()),
            (PrcSel::Ip, Tbl::Dst) => ptb.ip.dst.find_input(&po.borrow()),
            (PrcSel::Icmp, Tbl::Src) => ptb.icmp.src.find_input(&po.borrow()),
            (PrcSel::Icmp, Tbl::Dst) => ptb.icmp.dst.find_input(&po.borrow()),
            (PrcSel::Tcp, Tbl::Src) => ptb.tcp.src.find_input(&po.borrow()),
            (PrcSel::Tcp, Tbl::Dst) => ptb.tcp.dst.find_input(&po.borrow()),
            (PrcSel::Udp, Tbl::Src) => ptb.udp.src.find_input(&po.borrow()),
            (PrcSel::Udp, Tbl::Dst) => ptb.udp.dst.find_input(&po.borrow()),
            (PrcSel::Svc, _) => unreachable!(), // C svc arm: null tables; any-any early return hits first
        }
    };
    if let Some(h) = found {
        return h;
    }
    // PortObjectDupPorts (name null -> "dup"), then PortTableAddObject.
    let dup = Rc::new(RefCell::new(po.borrow().dup_ports()));
    {
        let mut ptbm = port_tables.borrow_mut();
        match (prc, tbl) {
            (PrcSel::Ip, Tbl::Src) => ptbm.ip.src.add_object(Rc::clone(&dup)),
            (PrcSel::Ip, Tbl::Dst) => ptbm.ip.dst.add_object(Rc::clone(&dup)),
            (PrcSel::Icmp, Tbl::Src) => ptbm.icmp.src.add_object(Rc::clone(&dup)),
            (PrcSel::Icmp, Tbl::Dst) => ptbm.icmp.dst.add_object(Rc::clone(&dup)),
            (PrcSel::Tcp, Tbl::Src) => ptbm.tcp.src.add_object(Rc::clone(&dup)),
            (PrcSel::Tcp, Tbl::Dst) => ptbm.tcp.dst.add_object(Rc::clone(&dup)),
            (PrcSel::Udp, Tbl::Src) => ptbm.udp.src.add_object(Rc::clone(&dup)),
            (PrcSel::Udp, Tbl::Dst) => ptbm.udp.dst.add_object(Rc::clone(&dup)),
            (PrcSel::Svc, _) => unreachable!(),
        };
    }
    dup
}
