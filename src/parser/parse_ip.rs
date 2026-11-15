// Port of snort3 src/parser/parse_ip.{h,cc}.
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates.
//
// C's sfip_var_from_string() allocates a fresh unnamed var and parses the
// list with NO var table (rule-header $VARs are resolved earlier by the
// parser pre-pass; see KNOWN DEVIATIONS.md). The ParseError() side effects
// map to returned SfIpRet codes here; the framework text-output layer is
// not ported yet, so callers render the messages.

#![allow(dead_code)]

use crate::sfip::sf_ipvar::SfIpVar;
use crate::sfip::sf_returns::SfIpRet;

/// C++ sfip_var_from_string(addr, caller).
/// Returns the (possibly partially built) var plus the status code; the
/// caller is responsible for the matching ParseError wording:
///   LookupFailure       -> "Undefined variable in the IP list"
///   Conflict            -> "Negated IP ranges equal to or more-specific ..."
///   LookupUnavailable   -> "Snort variables are only permitted in rule headers ..."
///   anything else != Success -> "Unable to process IP list"
pub fn sfip_var_from_string(addr: &str) -> (SfIpVar, SfIpRet) {
    let mut ret = SfIpVar::default();
    let ret_code = crate::sfip::sf_vartable::Vartable::none_add_to_var(&mut ret, addr);
    (ret, ret_code)
}
