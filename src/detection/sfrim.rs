// Port of snort3 src/detection/sfrim.{h,cc}: the ordinal rule-index map
// (gid,sid -> insertion index; index -> gid,sid). Literal transcription:
// RuleIndexMapAdd always appends (duplicates get distinct indices), index
// = pre-insert size; RuleIndexMapGet zeroes both outputs on out-of-range
// and returns false. Upstream ships a [RuleIndexMap] Catch table (1 case);
// the rules_harness Catch gate runs the ORIGINAL (tools/rules_harness).
#![allow(dead_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleNumber {
    pub gid: u32,
    pub sid: u32,
}

/// struct rule_index_map_t { std::vector<rule_number_t> map; }
#[derive(Default)]
pub struct RuleIndexMap {
    map: Vec<RuleNumber>,
}

/// rule_index_map_t* RuleIndexMapCreate()
impl RuleIndexMap {
    pub fn new() -> RuleIndexMap {
        rule_index_map_create()
    }
}

pub fn rule_index_map_create() -> RuleIndexMap {
    RuleIndexMap::default()
}

/// int RuleIndexMapAdd(rim, gid, sid): emplace_back, return pre-size index.
pub fn rule_index_map_add(rim: &mut RuleIndexMap, gid: u32, sid: u32) -> i32 {
    let index = rim.map.len() as i32;
    rim.map.push(RuleNumber { gid, sid });
    index
}

/// bool RuleIndexMapGet(rim, index, gid, sid): in-range copy + true;
/// else gid = sid = 0, false. C `(unsigned)index < size` means a negative
/// index wraps to a huge unsigned and fails — mirrored via index cast.
pub fn rule_index_map_get(rim: &RuleIndexMap, index: i32) -> (bool, u32, u32) {
    if rim.map.len() > (index as u32) as usize {
        let rn = rim.map[index as usize];
        return (true, rn.gid, rn.sid);
    }
    (false, 0, 0)
}

/// void RuleIndexMapFree(rim): assert(rim); delete rim. Rust drop models
/// the non-null assert (Option deref) — caller hands ownership over.
pub fn rule_index_map_free(_rim: RuleIndexMap) {
    // C: assert(rim); delete rim; -> drop is the deletion.
}
