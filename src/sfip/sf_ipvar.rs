// Port of snort3 src/sfip/sf_ipvar.{h,cc}.
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//           Copyright (C) 1998-2013 Sourcefire, Inc.
//
// The C singly-linked node lists (sfip_node_t head/next splices, frees,
// insertion sorts) are ported as Vec<SfIpNode>; the separate *_count fields
// are kept and mutated exactly as C does (they can diverge from Vec::len in
// the single-node overlap branch — preserved quirk). Ownership: C's
// free-or-insert pointer semantics map to consuming the passed node.
// See KNOWN DEVIATIONS.md.

#![allow(dead_code)]

use super::sf_cidr::SfCidr;
use super::sf_ip::SfIp;
use super::sf_returns::{AF_INET, AF_INET6, SfIpRet};

/* Flags */
pub const SFIP_NEGATED: u32 = 1;
pub const SFIP_ANY: u32 = 2;

const LIST_OPEN: u8 = b'[';
const LIST_CLOSE: u8 = b']';

fn c_isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SfIpNode {
    pub ip: SfCidr,
    pub flags: u32,
    pub addr_flags: u32,
}

pub type SfIpNodeList = Vec<SfIpNode>;

/// IP variable object (sfip_var_t). The C `next` linkage for the table
/// lives in the Vartable vector instead (documented deviation).
#[derive(Clone, Debug, Default)]
pub struct SfIpVar {
    pub head: SfIpNodeList,
    pub neg_head: SfIpNodeList,
    pub head_count: u32,
    pub neg_head_count: u32,
    pub id: u32,
    pub name: Option<String>,
    pub value: Option<String>,
}

/// sfipnode_alloc(): (Some(node), Success) or (None, status).
pub fn sfipnode_alloc(str: &str) -> (Option<SfIpNode>, SfIpRet) {
    let bytes = str.as_bytes();
    let mut k = 0usize;
    let mut flags = 0u32;

    /* Check if this string starts with a '!', if so, negate */
    if k < bytes.len() && bytes[k] == b'!' {
        k += 1;
        flags |= SFIP_NEGATED;
    }
    while k < bytes.len() && c_isspace(bytes[k]) {
        k += 1;
    }

    /* Check if this is an "any" (C: !strncasecmp(str, "any", 3) — matches
     * ANY string whose first 3 chars are a-n-y insensitively) */
    if str.len() - k >= 3 && str[k..k + 3].eq_ignore_ascii_case("any") {
        /* Make sure they're not doing !any, which is meaningless */
        if flags & SFIP_NEGATED != 0 {
            return (None, SfIpRet::ArgErr);
        }
        let mut ip = SfCidr::new();
        let rc = ip.set_str("0.0.0.0");
        if rc != SfIpRet::Success {
            return (None, rc);
        }
        let node = SfIpNode { ip, flags: flags | SFIP_ANY, addr_flags: 0 };
        /* Check if this is a negated, zeroed IP (equivalent of a "!any") */
        if !node.ip.is_set() && node.flags & SFIP_NEGATED != 0 {
            return (None, SfIpRet::NotAny);
        }
        return (Some(node), SfIpRet::Success);
    }

    let mut ip = SfCidr::new();
    let rc = ip.set_str(&str[k..]);
    if rc != SfIpRet::Success {
        return (None, rc);
    }
    let node = SfIpNode { ip, flags, addr_flags: 0 };

    if !node.ip.is_set() && node.flags & SFIP_NEGATED != 0 {
        return (None, SfIpRet::NotAny);
    }
    (Some(node), SfIpRet::Success)
}

/// Deep copy that owns its own data (sfvar_deep_copy); id/name/value start
/// unset exactly like C's calloc + node-list copy only.
pub fn sfvar_deep_copy(var: &SfIpVar) -> SfIpVar {
    SfIpVar {
        head: var.head.clone(),
        neg_head: var.neg_head.clone(),
        head_count: var.head_count,
        neg_head_count: var.neg_head_count,
        id: 0,
        name: None,
        value: None,
    }
}

/// New variable aliasing another, deep-copied (sfvar_create_alias).
pub fn sfvar_create_alias(alias_from: &SfIpVar, alias_to: &str) -> SfIpVar {
    let mut ret = sfvar_deep_copy(alias_from);
    ret.name = Some(alias_to.to_string());
    ret.id = alias_from.id;
    ret
}

fn sfvar_is_alias(one: &SfIpVar, two: &SfIpVar) -> bool {
    one.id != 0 && one.id == two.id
}

/// C loop stops at the shorter list yet still returns SFIP_EQUAL (the count
/// equality is enforced by sfvar_compare before this runs).
fn sfvar_list_compare(list1: &SfIpNodeList, list2: &SfIpNodeList) -> SfIpRet {
    for (n1, n2) in list1.iter().zip(list2.iter()) {
        if n1.ip.compare(&n2.ip) != SfIpRet::Equal {
            return SfIpRet::Failure;
        }
    }
    SfIpRet::Equal
}

/// Check's if two variables have the same nodes (sfvar_compare).
pub fn sfvar_compare(one: Option<&SfIpVar>, two: Option<&SfIpVar>) -> SfIpRet {
    match (one, two) {
        (None, None) => SfIpRet::Equal,
        (Some(_), None) | (None, Some(_)) => SfIpRet::Failure,
        (Some(a), Some(b)) => {
            if sfvar_is_alias(a, b) {
                return SfIpRet::Equal;
            }
            if a.head_count != b.head_count {
                return SfIpRet::Failure;
            }
            if a.neg_head_count != b.neg_head_count {
                return SfIpRet::Failure;
            }
            if sfvar_list_compare(&a.head, &b.head) == SfIpRet::Failure {
                return SfIpRet::Failure;
            }
            if sfvar_list_compare(&a.neg_head, &b.neg_head) == SfIpRet::Failure {
                return SfIpRet::Failure;
            }
            SfIpRet::Equal
        }
    }
}

enum ContainsOutcome {
    /// node consumed: absorbed by a list entry, or swapped in as the sole
    /// node replacing a single-node list (C `return true` paths)
    Consumed,
    /// node survives; a list entry it contained was deleted (C `return false`
    /// after removing an overlap)
    OverlapRemoved,
    /// nothing matched (C `return false` with no change)
    NoMatch,
}

/// list_contains_node(): true iff the node is contained by a network in the
/// sorted list (node deleted/consumed). False keeps the node but deletes any
/// network the node contains so the caller can insert without overlap.
/// C's tail out-param is implicit with Vec.
fn list_contains_node(list: &mut SfIpNodeList, count: &mut u32, node: &SfIpNode) -> ContainsOutcome {
    let fam = node.ip.get_family();
    let mut sel: Option<usize> = None;
    let mut consumed = false;

    let af = if fam == AF_INET as u16 {
        AF_INET as u16
    } else if fam == AF_INET6 as u16 {
        AF_INET6 as u16
    } else {
        0
    };

    if af != 0 {
        for (i, cur) in list.iter().enumerate() {
            if !cur.ip.is_set() || cur.ip.get_family() != af {
                continue;
            }
            let hit = if af == AF_INET as u16 {
                node.ip.fast_cont4(cur.ip.get_addr())
            } else {
                node.ip.fast_cont6(cur.ip.get_addr())
            };
            if hit {
                sel = Some(i); // list entry is contained by node: remove it
                break;
            }
            let hit2 = if af == AF_INET as u16 {
                cur.ip.fast_cont4(node.ip.get_addr())
            } else {
                cur.ip.fast_cont6(node.ip.get_addr())
            };
            if hit2 {
                consumed = true; // node is contained by list entry: node dies
                break;
            }
        }
    }

    if consumed {
        return ContainsOutcome::Consumed;
    }

    if let Some(c) = sel {
        if c > 0 {
            // prev exists: prev->next = cur->next (tail fix implicit in Vec)
            list.remove(c);
            *count -= 1;
        } else if list.len() > 1 {
            // head = cur->next
            list.remove(0);
            *count -= 1;
        } else {
            // only one node: head = tail = node; count UNCHANGED (C quirk)
            *list = vec![node.clone()];
            return ContainsOutcome::Consumed;
        }
        return ContainsOutcome::OverlapRemoved;
    }
    ContainsOutcome::NoMatch
}

/// merge_lists(): both lists sorted; head "any" short-circuits by freeing
/// the other list. Returns (merged head list, merge_len).
/// C quirk preserved: in the trailing append loops, listN_len is NOT
/// decremented for nodes consumed before the surviving one, so the final
/// merge_len can over-count in those (rare) cases.
fn merge_lists(
    list1: SfIpNodeList,
    list2: SfIpNodeList,
    list1_len: u32,
    list2_len: u32,
) -> (SfIpNodeList, u32) {
    if list1.is_empty() && list2.is_empty() {
        return (Vec::new(), 0);
    }
    if list1.is_empty() {
        return (list2, list2_len);
    }
    if list2.is_empty() {
        return (list1, list1_len);
    }

    if list1[0].flags & SFIP_ANY != 0 {
        return (list1, list1_len); // list2 freed
    }
    if list2[0].flags & SFIP_ANY != 0 {
        return (list2, list2_len); // list1 freed
    }

    // C works by splicing nodes out of the input chains; Vec + cursors keeps
    // the identical decisions without mutation of the source lists.
    let mut l1 = list1;
    let mut l2 = list2;
    let mut merge_list = SfIpNodeList::new();
    let mut ia = 0usize;
    let mut ib = 0usize;
    let mut l1_len = list1_len;
    let mut l2_len = list2_len;
    let mut num_nodes = 0u32;

    while ia < l1.len() && ib < l2.len() {
        if num_nodes != 0 {
            if matches!(list_contains_node(&mut merge_list, &mut num_nodes, &l1[ia]), ContainsOutcome::Consumed) {
                ia += 1;
                l1_len -= 1;
                continue;
            }
            if matches!(list_contains_node(&mut merge_list, &mut num_nodes, &l2[ib]), ContainsOutcome::Consumed) {
                ib += 1;
                l2_len -= 1;
                continue;
            }
        }

        let ret = l1[ia].ip.compare(&l2[ib].ip);
        let node = match ret {
            SfIpRet::Lesser => {
                let n = l1[ia].clone();
                ia += 1;
                l1_len -= 1;
                n
            }
            SfIpRet::Greater => {
                let n = l2[ib].clone();
                ib += 1;
                l2_len -= 1;
                n
            }
            SfIpRet::Equal => {
                // keep list1 node; free the duplicate node from list2
                let n = l1[ia].clone();
                ia += 1;
                ib += 1;
                l1_len -= 1;
                l2_len -= 1;
                n
            }
            _ => break, // SFIP_FAILURE
        };

        merge_list.push(node);
        num_nodes += 1;
    }

    /* list2 exhausted: append list1's remaining chain */
    while ia < l1.len() {
        let out = list_contains_node(&mut merge_list, &mut num_nodes, &l1[ia]);
        if !matches!(out, ContainsOutcome::Consumed) && !merge_list.is_empty() {
            let rest = l1.split_off(ia);
            num_nodes += l1_len;
            merge_list.extend(rest);
            break;
        }
        ia += 1; // no length decrement in the C tail loop (quirk)
    }

    /* list1 exhausted: append list2's remaining chain */
    while ib < l2.len() {
        let out = list_contains_node(&mut merge_list, &mut num_nodes, &l2[ib]);
        if !matches!(out, ContainsOutcome::Consumed) && !merge_list.is_empty() {
            let rest = l2.split_off(ib);
            num_nodes += l2_len;
            merge_list.extend(rest);
            break;
        }
        ib += 1;
    }

    (merge_list, num_nodes)
}

/// Deep copy of src added to dst (sfvar_add).
pub fn sfvar_add(dst: &mut SfIpVar, src: &SfIpVar) -> SfIpRet {
    let a = std::mem::take(&mut dst.head);
    let ac = std::mem::replace(&mut dst.head_count, 0);
    let (m, mc) = merge_lists(a, src.head.clone(), ac, src.head_count);
    dst.head = m;
    dst.head_count = mc;

    let a = std::mem::take(&mut dst.neg_head);
    let ac = std::mem::replace(&mut dst.neg_head_count, 0);
    let (m, mc) = merge_lists(a, src.neg_head.clone(), ac, src.neg_head_count);
    dst.neg_head = m;
    dst.neg_head_count = mc;

    SfIpRet::Success
}

/// Adds the node to the variable in sorted position (sfvar_add_node).
/// Takes ownership exactly like C's free-or-insert pointer arg.
pub fn sfvar_add_node(var: &mut SfIpVar, node: SfIpNode, negated: bool) -> SfIpRet {
    let (list, count) = if negated {
        (&mut var.neg_head, &mut var.neg_head_count)
    } else {
        (&mut var.head, &mut var.head_count)
    };

    if list.is_empty() {
        list.push(node);
        *count += 1;
        return SfIpRet::Success;
    }

    /* If head node is any, do not add anything else */
    if list[0].flags & SFIP_ANY != 0 {
        return SfIpRet::Success; // node freed
    }

    /* "Anys" should always be inserted first */
    if node.flags & SFIP_ANY != 0 {
        // Free the list when adding any
        *list = vec![node];
        *count = 1;
        return SfIpRet::Success;
    }

    if matches!(list_contains_node(list, count, &node), ContainsOutcome::Consumed) {
        return SfIpRet::Success;
    }

    /* To insert the new node, first check if this IP is less than the head */
    let node_cmp_ret = node.ip.compare(&list[0].ip);
    if node_cmp_ret == SfIpRet::Equal {
        return SfIpRet::Success; // node freed
    } else if node_cmp_ret == SfIpRet::Lesser {
        list.insert(0, node);
        *count += 1;
        return SfIpRet::Success;
    }

    /* Here the head was lesser than the new node */
    if list.len() == 1 {
        list.push(node);
        *count += 1;
        return SfIpRet::Success;
    }

    /* Insertion sort */
    for p in 0..list.len() - 1 {
        let node_cmp_ret = node.ip.compare(&list[p + 1].ip);
        if node_cmp_ret == SfIpRet::Equal {
            return SfIpRet::Success; // node freed
        } else if node_cmp_ret == SfIpRet::Lesser {
            list.insert(p + 1, node);
            *count += 1;
            return SfIpRet::Success;
        }
    }

    list.push(node);
    *count += 1;
    SfIpRet::Success
}

/// sfvar_parse_iplist support: bracket matching (can't strchr because of the
/// [a, [b], c] case, can't strrchr because of [a, [b], [c]]).
fn _find_end_token(s: &[u8]) -> Option<usize> {
    let mut stack: i32 = 0;
    for (k, &c) in s.iter().enumerate() {
        if c == LIST_OPEN {
            stack += 1;
        } else if c == LIST_CLOSE {
            stack -= 1;
        }
        if stack == 0 {
            return Some(k);
        }
    }
    None
}

/// sfvar_parse_iplist support: negates a node (C: SFIP_NEGATED == 1).
fn _negate_node(node: &mut SfIpNode) {
    if node.addr_flags & SFIP_NEGATED != 0 {
        node.addr_flags &= !SFIP_NEGATED;
        node.flags &= !SFIP_NEGATED;
    } else {
        node.addr_flags |= SFIP_NEGATED;
        node.flags |= SFIP_NEGATED;
    }
}

/// sfvar_parse_iplist support: negates a variable, swapping lists.
fn _negate_lists(var: &mut SfIpVar) {
    for node in var.head.iter_mut() {
        _negate_node(node);
    }
    for node in var.neg_head.iter_mut() {
        _negate_node(node);
    }
    std::mem::swap(&mut var.head, &mut var.neg_head);
    std::mem::swap(&mut var.head_count, &mut var.neg_head_count);
}

/// Parses an IP list described by 'str' and merges results into 'var'
/// (sfvar_parse_iplist). `table` backs $variable lookups; None mirrors
/// nullptr -> SFIP_LOOKUP_UNAVAILABLE.
pub fn sfvar_parse_iplist(
    table: Option<&super::sf_vartable::Vartable>,
    var: &mut SfIpVar,
    str: &str,
    negation: bool,
) -> SfIpRet {
    let b = str.as_bytes();
    let mut s = 0usize; // C `str` cursor

    while s < b.len() {
        /* Skip whitespace and leading commas */
        if c_isspace(b[s]) || b[s] == b',' {
            s += 1;
            continue;
        }

        let mut neg_ip = false;

        /* Handle multiple negations (also skips spaces) */
        while s < b.len() && (b[s] == b'!' || c_isspace(b[s])) {
            if b[s] == b'!' {
                neg_ip = !neg_ip;
            }
            s += 1;
        }

        if s >= b.len() {
            return SfIpRet::ArgErr;
        }

        /* Find end of this token: start from s+1 */
        let mut e = s + 1;
        while e < b.len() && !c_isspace(b[e]) && b[e] != LIST_CLOSE && b[e] != b',' {
            e += 1;
        }
        let tok = &str[s..e];

        if b[s] == LIST_OPEN {
            /* Find end of this list */
            let end_rel = match _find_end_token(&b[s..]) {
                Some(x) => s + x,
                None => return SfIpRet::UnmatchedBracket,
            };
            // list_tok = strndup(str+1, end - str - 1)
            let inner = &str[s + 1..end_rel];
            let ret = sfvar_parse_iplist(table, var, inner, negation != neg_ip);
            if ret != SfIpRet::Success {
                return ret;
            }
        } else if b[s] == b'$' {
            let table = match table {
                None => return SfIpRet::LookupUnavailable,
                Some(t) => t,
            };
            let tmp_var = match table.lookup_var(tok) {
                None => return SfIpRet::LookupFailure,
                Some(v) => v,
            };
            let mut copy_var = sfvar_deep_copy(tmp_var);

            /* Apply the negation */
            if negation != neg_ip {
                /* Check for a negated "any" */
                if let Some(h) = copy_var.head.first()
                    && h.flags & SFIP_ANY != 0 {
                        return SfIpRet::NotAny;
                    }
                /* Negated, zeroed IP == "!any" */
                if let Some(h) = copy_var.head.first()
                    && !h.ip.is_set() {
                        return SfIpRet::NotAny;
                    }
                _negate_lists(&mut copy_var);
            }

            sfvar_add(var, &copy_var);
        } else if b[s] == LIST_CLOSE {
            /* This should be the last character... */
            if s + 1 >= b.len() {
                return SfIpRet::Success;
            }
            return SfIpRet::UnmatchedBracket;
        } else {
            /* Check for a negated "any" */
            if (negation != neg_ip) && tok.eq_ignore_ascii_case("any") {
                return SfIpRet::NotAny;
            }

            let (node, ret) = sfipnode_alloc(tok);
            let mut node = match node {
                None => return ret,
                Some(n) => n,
            };

            if negation != neg_ip {
                _negate_node(&mut node);
            }

            /* Negated, zeroed IP equivalent of "!any" */
            if !node.ip.is_set() && node.flags & SFIP_NEGATED != 0 {
                return SfIpRet::NotAny;
            }

            let ret = sfvar_add_node(var, node, negation != neg_ip);
            if ret != SfIpRet::Success {
                return ret;
            }
        }

        if e < b.len() {
            s = e + 1;
        } else {
            break;
        }
    }

    SfIpRet::Success
}

/// Makes sure there are no IP address conflicts (sfvar_validate).
pub fn sfvar_validate(var: &SfIpVar) -> SfIpRet {
    if var.head.is_empty() || var.neg_head.is_empty() {
        return SfIpRet::Success;
    }
    for idx in &var.head {
        for neg_idx in &var.neg_head {
            /* A smaller netmask means "less specific" */
            if neg_idx.ip.get_bits() <= idx.ip.get_bits()
                /* Verify they overlap */
                && neg_idx.ip.contains(Some(idx.ip.get_addr())) == SfIpRet::Contains
            {
                return SfIpRet::Conflict;
            }
        }
    }
    SfIpRet::Success
}

/// Allocates and returns a new variable described by "variable"
/// (sfvar_alloc). Borrow-only over the table (alias lookup).
pub fn sfvar_alloc(table: &super::sf_vartable::Vartable, variable: &str) -> (Option<SfIpVar>, SfIpRet) {
    if variable.is_empty() {
        return (None, SfIpRet::ArgErr);
    }
    let b = variable.as_bytes();

    /* Extract and save the variable's name: skip leading whitespace or
       line continuations '\' */
    let mut s = 0usize;
    while s < b.len() && (c_isspace(b[s]) || b[s] == b'\\') {
        s += 1;
    }
    if s >= b.len() {
        return (None, SfIpRet::ArgErr); // Didn't get anything
    }

    /* Find the end of the name */
    let mut e = s;
    while e < b.len() && !c_isspace(b[e]) && b[e] != b'\\' {
        e += 1;
    }

    if !(b[s] as char).is_ascii_alphanumeric() && b[s] != b'$' && b[s] != b'!' {
        return (None, SfIpRet::ArgErr);
    }

    let name = &variable[s..e];

    /* Skip past the name and any whitespace / line continuations */
    s = e;
    while s < b.len() && (c_isspace(b[s]) || b[s] == b'\\') {
        s += 1;
    }
    if s >= b.len() {
        return (None, SfIpRet::ArgErr); // Didn't get anything
    }

    /* Trim whitespace and line continuations off the end of the string */
    let mut end2 = b.len() - 1;
    while end2 > s && (c_isspace(b[end2]) || b[end2] == b'\\') {
        end2 -= 1;
    }
    end2 += 1;

    /* See if this is just an alias */
    let tmp = &variable[s..end2];
    if let Some(tmpvar) = table.lookup_var(tmp) {
        let aliased = sfvar_create_alias(tmpvar, name);
        return (Some(aliased), SfIpRet::Success);
    }

    let mut ret = SfIpVar {
        name: Some(name.to_string()),
        ..Default::default()
    };

    /* Everything is treated as a list, even one unbracketed element */
    let stat = sfvar_parse_iplist(Some(table), &mut ret, &variable[s..end2], false);
    if stat != SfIpRet::Success {
        return (None, stat);
    }

    if let Some(h) = ret.head.first()
        && h.flags & SFIP_ANY != 0 && h.flags & SFIP_NEGATED != 0 {
            return (None, SfIpRet::NotAny);
        }

    if sfvar_validate(&ret) == SfIpRet::Conflict {
        return (None, SfIpRet::Conflict);
    }

    (Some(ret), SfIpRet::Success)
}

/// sfvar_ip_in4 / sfvar_ip_in6 / sfvar_ip_in.
pub fn sfvar_ip_in(var: &SfIpVar, ip: &SfIp) -> bool {
    if ip.get_family() == AF_INET as u16 {
        sfvar_ip_in_n(var, ip, AF_INET as u16)
    } else {
        sfvar_ip_in_n(var, ip, AF_INET6 as u16)
    }
}

fn sfvar_ip_in_n(var: &SfIpVar, ip: &SfIp, af: u16) -> bool {
    let mut match_ = false;
    let mut pi = 0usize;
    let mut ni = 0usize;

    if var.head.is_empty() {
        while ni < var.neg_head.len() {
            let n = &var.neg_head[ni];
            ni += 1;
            if n.ip.get_addr().get_family() != af {
                continue;
            }
            let hit = if af == AF_INET as u16 {
                n.ip.fast_cont4(ip)
            } else {
                n.ip.fast_cont6(ip)
            };
            if hit {
                return false;
            }
        }
        return true;
    }

    while pi < var.head.len() {
        if ni < var.neg_head.len() {
            let n = &var.neg_head[ni];
            let hit = n.ip.get_addr().get_family() == af
                && (if af == AF_INET as u16 {
                    n.ip.fast_cont4(ip)
                } else {
                    n.ip.fast_cont6(ip)
                });
            if hit {
                return false;
            }
            ni += 1;
        }
        /* No more potential negations: check if we've already matched. */
        else if match_ {
            return true;
        }

        if !match_ {
            let p = &var.head[pi];
            if p.ip.is_set() {
                let hit = p.ip.get_addr().get_family() == af
                    && (if af == AF_INET as u16 {
                        p.ip.fast_cont4(ip)
                    } else {
                        p.ip.fast_cont6(ip)
                    });
                if hit {
                    match_ = true;
                } else {
                    pi += 1;
                }
            } else {
                // zeroed entry matches everything (sfvar sorts these first)
                match_ = true;
            }
        }
    }

    false
}
