//! Behavior tests for parser/parse_ip.rs (C++ parse_ip.cc has no unit
//! suite; expected codes come from reading sfvt_add_to_var +
//! sfvar_parse_iplist + sfvar_validate paths and from the sf_ipvar
//! Catch2 sections that cover the same engine).
use snort3::parser::parse_ip::sfip_var_from_string;
use snort3::sfip::sf_ipvar::*;
use snort3::sfip::sf_returns::SfIpRet;

#[test]
fn plain_list_ok() {
    let (v, rc) = sfip_var_from_string("[ 192.168.1.1, 10.0.0.0/8 ]");
    assert_eq!(rc, SfIpRet::Success);
    assert_eq!(v.head_count, 2);
    assert_eq!(print(&v.head), "10.0.0.0,192.168.1.1");
}

#[test]
fn any_list_ok() {
    let (v, rc) = sfip_var_from_string("any");
    assert_eq!(rc, SfIpRet::Success);
    assert_eq!(v.head_count, 1);
    assert_ne!(v.head[0].flags & SFIP_ANY, 0);
}

#[test]
fn variable_reference_unavailable_without_table() {
    let (_, rc) = sfip_var_from_string("[ $EXTERNAL_NET, 1.2.3.4 ]");
    assert_eq!(rc, SfIpRet::LookupUnavailable);
}

#[test]
fn conflict_negated_more_specific() {
    // negated range == non-negated range -> SFIP_CONFLICT (sfvar_validate)
    let (_, rc) = sfip_var_from_string("[ 1.2.3.4, !1.2.3.4 ]");
    assert_eq!(rc, SfIpRet::Conflict);
}

#[test]
fn garbage_fails() {
    // C sfvar_parse_iplist: unmatched '[' -> UNMATCHED_BRACKET; a lone
    // trailing ']' is accepted as SUCCESS (C quirk at parse-list end);
    // ']' followed by more -> UNMATCHED_BRACKET; empty "[]" inner list
    // also SUCCESS (C quirk); junk names -> FAILURE.
    assert_eq!(sfip_var_from_string("[").1, SfIpRet::UnmatchedBracket);
    assert_eq!(sfip_var_from_string("]").1, SfIpRet::Success);
    assert_eq!(sfip_var_from_string("] x").1, SfIpRet::UnmatchedBracket);
    assert_eq!(sfip_var_from_string("[]").1, SfIpRet::Success);
    for bad in ["sdfg", "1.2.3.4.5"] {
        let (_, rc) = sfip_var_from_string(bad);
        // C sfipnode_alloc -> SfCidr::set() -> SFIP_INET_PARSE_ERR,
        // propagated through sfvar_parse_iplist (sfvt_add_str would
        // squash to FAILURE, but sfip_var_from_string does not).
        assert_eq!(rc, SfIpRet::InetParseErr, "input {bad:?}");
    }
}

fn print(list: &SfIpNodeList) -> String {
    list.iter()
        .map(|n| n.ip.ntop(true).unwrap())
        .collect::<Vec<_>>()
        .join(",")
}
