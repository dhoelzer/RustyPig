// Port of snort3 src/detection/rules.{h,cc}: RuleKey / RuleState /
// RuleStateMap. Literal transcription of operator< map ordering (NOT
// plain tuple order: the sid<sid arm is gated on the policy_id-equal
// block), map[key]=state overwrite, the two-phase apply (global_rule_state
// fan-out over ips_policy() skipping the empty-policy id; else the direct
// key.policy_id), the private apply() slot-fallback chain (policy_id slot,
// else slot 0 clone), dup_rtn vartable/portobject rebind with the
// name-restore quirk and the "any rebinding happened -> rebuild
// rule_func via parse_rule_process_rtn" branch, and update_rtn's
// $action-variable rules (null-policy error, "in IPS policy <user_policy_id>"
// error), enable/clear switch, listhead swap, header action rewrite.
// Ground truth: ORIGINAL rules.cc compiled in tools/rules_harness; the
// upstream [RuleStateMap] Catch cases run against it; the Rust replay
// (tests/rules_parity_test.rs) pins STATE/OTN/RTN lines 1:1.
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use crate::detection::parse_rule::{add_rtn_to_otn, destroy_rule_tree_node, get_rule_list, parse_rule_process_rtn, RuleCoreState};
use crate::detection::signature::otn_lookup;
use crate::detection::treenodes::{get_rtn_from_otn, OtnHandle, RuleTreeNode, RtnHandle};
use crate::log::messages::WARN_RULES;
use crate::main::policy::{ActionSelector, Enable, IpsPolicy, PolicyId};
use crate::sfip::sf_ipvar::{sfvar_create_alias, sfvar_deep_copy};
use crate::utils::cfmt::Arg;

/// rules.h GID_SESSION / EventIsInternal
pub const GID_SESSION: u32 = 135;
pub fn event_is_internal(gid: u32) -> bool {
    gid == GID_SESSION
}

/// rules.h RuleKey
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleKey {
    pub policy_id: PolicyId,
    pub gid: u32,
    pub sid: u32,
}

/// rules.cc operator< verbatim.
pub fn rule_key_lt(lhs: &RuleKey, rhs: &RuleKey) -> bool {
    if lhs.policy_id < rhs.policy_id {
        return true;
    }
    if lhs.policy_id == rhs.policy_id {
        if lhs.gid < rhs.gid {
            return true;
        }
        if lhs.gid == rhs.gid && lhs.sid < rhs.sid {
            return true;
        }
    }
    false
}

/// rules.h RuleState
#[derive(Clone, Debug)]
pub struct RuleState {
    pub rule_action: String,
    pub action: u8,
    pub action_selector: ActionSelector,
    pub enable: Enable,
}

pub fn new_rule_state(
    rule_action: &str,
    action: u8,
    action_selector: ActionSelector,
    enable: Enable,
) -> RuleState {
    RuleState {
        rule_action: rule_action.to_string(),
        action,
        action_selector,
        enable,
    }
}

/// rules.h class RuleStateMap (std::map<RuleKey, RuleState>). The Vec is
/// kept in operator< order (std::map scan order for apply()).
#[derive(Default)]
pub struct RuleStateMap {
    map: Vec<(RuleKey, RuleState)>,
}

/// driver entry: C `sc->rule_states->apply(sc)` (pointer call; no aliasing
/// issue). Rust field access forces the map out of sc for the duration.
pub fn rule_state_apply(sc: &mut RuleCoreState) {
    let map = std::mem::take(&mut sc.rule_states);
    map.apply(sc);
    sc.rule_states = map;
}

impl RuleStateMap {
    pub fn new() -> RuleStateMap {
        RuleStateMap::default()
    }

    /// void add(const RuleKey& key, const RuleState& state) { map[key] = state; }
    pub fn add(&mut self, key: RuleKey, state: RuleState) {
        if let Some((_, v)) = self.map.iter_mut().find(|(k, _)| *k == key) {
            *v = state; // operator[] hit: overwrite
            return;
        }
        let pos = self.map.partition_point(|(k, _)| rule_key_lt(k, &key));
        self.map.insert(pos, (key, state));
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// void apply(SnortConfig* sc)
    pub fn apply(&self, sc: &mut RuleCoreState) {
        for (k, state) in self.map.iter() {
            let otn = otn_lookup(&sc.otn_map, k.gid, k.sid);
            let otn = match otn {
                None => {
                    sc.log.parse_warning(
                        WARN_RULES,
                        "Rule state specified for unknown rule %u:%u",
                        &[Arg::U(k.gid as u64), Arg::U(k.sid as u64)],
                    );
                    continue;
                }
                Some(o) => o,
            };
            if sc.global_rule_state {
                let count = sc.policies.len() as u32;
                for i in 0..count {
                    // C: policy && policy->policy_id != empty_ips_id
                    match sc.policy_at(i) {
                        Some(p) if p.policy_id != sc.empty_policy_id => apply_one(sc, &otn, i, state),
                        _ => {}
                    }
                }
            } else {
                apply_one(sc, &otn, k.policy_id, state);
            }
        }
    }
}

/// private static void apply(sc, OptTreeNode* otn, unsigned ips_num,
/// const RuleState& s)
fn apply_one(sc: &mut RuleCoreState, otn: &OtnHandle, ips_num: PolicyId, s: &RuleState) {
    let (b_rtn, clone_slot) = match get_rtn_from_otn(otn, ips_num) {
        Some(r) => (Some(r), None),
        None => {
            if ips_num != 0 {
                match get_rtn_from_otn(otn, 0) {
                    Some(r) => (Some(r), Some(ips_num)),
                    None => (None, None),
                }
            } else {
                (None, None)
            }
        }
    };
    let b_rtn = match b_rtn {
        None => return,
        Some(r) => r,
    };

    let t_rtn = dup_rtn(sc, &b_rtn, clone_slot);

    if !update_rtn(sc, ips_num, &t_rtn, s) {
        // DestroyRuleTreeNode(t_rtn); return;
        destroy_rule_tree_node(sc, &t_rtn);
        return;
    }

    if let Some(cs) = clone_slot {
        // clone_policy->rules_shared++
        if let Some(p) = sc.policy_at_mut(cs) {
            p.rules_shared += 1;
        }
    }

    add_rtn_to_otn(sc, otn, &t_rtn, ips_num);
}

/// private static RuleTreeNode* dup_rtn(RuleTreeNode* rtn, IpsPolicy* policy)
/// (policy == the clone slot's policy, else nullptr)
fn dup_rtn(sc: &mut RuleCoreState, src: &RtnHandle, clone_slot: Option<PolicyId>) -> RtnHandle {
    let rebind_policy: Option<&IpsPolicy> = match clone_slot {
        Some(i) => sc.policy_at(i),
        None => None,
    };

    let mut ret = {
        let sb = src.borrow();
        RuleTreeNode {
            rule_func: sb.rule_func.clone(),
            flags: sb.flags,
            action: sb.action,
            snort_protocol_id: sb.snort_protocol_id,
            listhead: sb.listhead.clone(),
            header: sb.header.clone(),
            sip: sb.sip.clone(),
            dip: sb.dip.clone(),
            src_portobject: sb.src_portobject.clone(),
            dst_portobject: sb.dst_portobject.clone(),
            otnRefCount: 0,
            action_selector: sb.action_selector,
        }
    };

    // C: sfvt_lookup_var(ipvt, rtn->sip->name) — the ORIGINAL name (before
    // any rebind), so capture names first.
    let sip_name = ret.sip.as_ref().and_then(|v| v.name.clone());
    let dip_name = ret.dip.as_ref().and_then(|v| v.name.clone());
    let spo_name = ret
        .src_portobject
        .as_ref()
        .and_then(|p| p.borrow().name.clone());
    let dpo_name = ret
        .dst_portobject
        .as_ref()
        .and_then(|p| p.borrow().name.clone());

    let sip_alias = match (&rebind_policy, &sip_name) {
        (Some(p), Some(n)) => p.ip_vartable.lookup_var(n).cloned(),
        _ => None,
    };
    let dip_alias = match (&rebind_policy, &dip_name) {
        (Some(p), Some(n)) => p.ip_vartable.lookup_var(n).cloned(),
        _ => None,
    };

    if let Some(orig) = ret.sip.clone() {
        ret.sip = Some(match &sip_alias {
            Some(a) => sfvar_create_alias(a, a.name.as_deref().unwrap_or("")),
            None => {
                let mut d = sfvar_deep_copy(&orig);
                if orig.name.is_some() {
                    d.name = orig.name.clone(); // snort_strdup(rtn->sip->name)
                }
                d
            }
        });
    }
    if let Some(orig) = ret.dip.clone() {
        ret.dip = Some(match &dip_alias {
            Some(a) => sfvar_create_alias(a, a.name.as_deref().unwrap_or("")),
            None => {
                let mut d = sfvar_deep_copy(&orig);
                if orig.name.is_some() {
                    d.name = orig.name.clone();
                }
                d
            }
        });
    }

    let (spo, dpo) = match rebind_policy {
        Some(p) => (
            spo_name.as_deref().and_then(|n| p.port_var_table.find_handle(n)),
            dpo_name.as_deref().and_then(|n| p.port_var_table.find_handle(n)),
        ),
        None => (None, None),
    };
    if spo.is_some() {
        ret.src_portobject = spo.clone();
    }
    if dpo.is_some() {
        ret.dst_portobject = dpo.clone();
    }
    ret.otnRefCount = 0;

    if sip_alias.is_some() || dip_alias.is_some() || spo.is_some() || dpo.is_some() {
        // C: ret->rule_func = nullptr; parse_rule_process_rtn(ret)
        ret.rule_func.clear();
        let h = Rc::new(RefCell::new(ret));
        parse_rule_process_rtn(sc, &mut h.borrow_mut());
        return h;
    }

    // else: the rule_func list copy is the verbatim clone above
    Rc::new(RefCell::new(ret))
}

/// private static bool update_rtn(SnortConfig* sc, IpsPolicy* policy,
/// RuleTreeNode* rtn, const RuleState& s). `policy` is
/// sc->policy_map->get_ips_policy(ips_num) (nullptr if out of range).
fn update_rtn(sc: &mut RuleCoreState, ips_num: PolicyId, rtn: &RtnHandle, s: &RuleState) -> bool {
    let mut rule_action = s.rule_action.clone();
    let mut action = s.action;
    let mut action_selector = s.action_selector;

    if !rule_action.is_empty() && rule_action.as_bytes()[0] == b'$' {
        let slot_valid = sc.policy_at(ips_num).is_some();
        if !slot_valid {
            sc.log.parse_error(
                "unknown IPS action variable '%s'",
                &[Arg::S(Some(rule_action.clone().into()))],
            );
            return false;
        }
        let got = sc.policies[ips_num as usize].get_action_variable(&rule_action[1..]);
        match got {
            Some((aname, atype, sel)) => {
                action = atype;
                action_selector = sel;
                rule_action = aname.clone();
            }
            None => {
                let upid = sc.policies[ips_num as usize].user_policy_id;
                sc.log.parse_error(
                    "unknown IPS action variable '%s' in IPS policy %llu",
                    &[Arg::S(Some(rule_action.clone().into())), Arg::U(upid)],
                );
                return false;
            }
        }
    }

    let new_listhead = get_rule_list(sc, &rule_action);
    {
        let mut rb = rtn.borrow_mut();
        match s.enable {
            Enable::Disabled => rb.clear_enabled(),
            Enable::Enabled => rb.set_enabled(),
            Enable::InheritEnable => {}
        }
        if new_listhead.is_some() && !listhead_ptr_eq(&rb.listhead, &new_listhead) {
            rb.listhead = new_listhead;
        }
        rb.action = action;
        rb.action_selector = action_selector;
        if let Some(h) = &mut rb.header {
            h.action = rule_action;
        }
    }
    true
}

fn listhead_ptr_eq(
    a: &Option<Rc<RefCell<crate::detection::treenodes::ListHead>>>,
    b: &Option<Rc<RefCell<crate::detection::treenodes::ListHead>>>,
) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => Rc::ptr_eq(x, y),
        (None, None) => true,
        _ => false,
    }
}


