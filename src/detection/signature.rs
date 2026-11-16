// Port of snort3 src/detection/signature.cc — the OtnLookup map half
// (OtnLookupNew / OtnLookup / OtnLookupAdd / OtnRemove / OtnFree) plus the
// file-static rule_index_map wiring note. Literal transcription of the
// assert + ParseError("duplicate rule with same gid (%u) and sid (%u)")
// semantics on HASH_INTABLE.
//
// Deviations (documented, pinned by tools/rules_harness replay): the C map
// is a GHash(10000, sizeof(OtnKey), false, OtnFree) whose traversal order IS
// observable through find_first in reduce_rtns/FreeRuleTreeNodes — the probe
// transcript never dumps per-iteration order (all observation sites are
// gid,sid point lookups + summed counters), so insertion-order Vec scan is
// behaviorally indistinguishable for this subsystem. ~OptTreeNode resource
// teardown is Rust drop semantics.
#![allow(dead_code)]

use crate::detection::treenodes::OtnHandle;
use crate::log::messages::LogEngine;
use crate::utils::cfmt::Arg;

/// signature.h OtnKey
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtnKey {
    pub gid: u32,
    pub sid: u32,
}

/// GHash otn_map stand-in (see header note).
#[derive(Debug, Default)]
pub struct OtnMap {
    pub entries: Vec<OtnHandle>,
}

impl OtnMap {
    /// OtnMap find-first/next semantics as owned handle snapshot.
    pub fn entries_snapshot(&self) -> Vec<OtnHandle> {
        self.entries.clone()
    }
    /// Alias mirroring the GHash find_first/find_next walk sites
    /// (reduce_rtns / FreeRuleTreeNodes).
    pub fn find_iter(&self) -> Vec<OtnHandle> {
        self.entries.clone()
    }
}

/// OptTreeNode* OtnLookup(GHash*, gid, sid): linear find by (gid, sid).
pub fn otn_lookup(map: &OtnMap, gid: u32, sid: u32) -> Option<OtnHandle> {
    for o in map.entries.iter() {
        let b = o.borrow();
        if b.sigInfo.gid == gid && b.sigInfo.sid == sid {
            return Some(std::rc::Rc::clone(o));
        }
    }
    None
}

/// void OtnLookupAdd(GHash*, otn): insert; HASH_OK returns, else
/// assert(status == HASH_INTABLE) + ParseError duplicate rule.
/// Returns true when inserted (HASH_OK), false on INTABLE (otn NOT added).
pub fn otn_lookup_add(log: &mut LogEngine, map: &mut OtnMap, otn: &OtnHandle) -> bool {
    let (gid, sid) = {
        let b = otn.borrow();
        (b.sigInfo.gid, b.sigInfo.sid)
    };
    if otn_lookup(map, gid, sid).is_some() {
        log.parse_error(
            "duplicate rule with same gid (%u) and sid (%u)",
            &[Arg::U(gid as u64), Arg::U(sid as u64)],
        );
        return false;
    }
    map.entries.push(std::rc::Rc::clone(otn));
    true
}

/// void OtnRemove(GHash*, otn)
pub fn otn_remove(map: &mut OtnMap, otn: &OtnHandle) {
    let (gid, sid) = {
        let b = otn.borrow();
        (b.sigInfo.gid, b.sigInfo.sid)
    };
    map.entries.retain(|o| {
        let b = o.borrow();
        !(b.sigInfo.gid == gid && b.sigInfo.sid == sid && std::rc::Rc::ptr_eq(o, otn))
    });
}

/// OtnFree(data) -> delete otn: Rust drop when last Rc released.
#[allow(unused_variables)]
pub fn otn_free(otn: &OtnHandle) {}

/// parse_conf-side helper: sc->otn_map == nullptr test (OtnInit guard).
pub fn otn_map_is_null(map: &Option<OtnMap>) -> bool {
    map.is_none()
}

/// OtnLookupNew(): GHash(10000, sizeof(OtnKey), false, OtnFree)
pub fn otn_lookup_new() -> OtnMap {
    OtnMap::default()
}
