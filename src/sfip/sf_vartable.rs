// Port of snort3 src/sfip/sf_vartable.{h,cc}.
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates;
//           Copyright (C) 1998-2013 Sourcefire, Inc.
//
// The var table is a sorted (by strcmp, C locale = byte order) singly
// linked list in C++; ported as a sorted Vec<SfIpVar> with C's insertion
// sort + redefine (SFIP_DUPLICATE) semantics. Lookup borrows &'a SfIpVar.
// sfvt_print is a debug dump not needed by any upstream test; omitted.
// See KNOWN DEVIATIONS.md.

#![allow(dead_code)]

use super::sf_ipvar::*;
use super::sf_returns::SfIpRet;

#[derive(Debug, Default)]
pub struct Vartable {
    pub vars: Vec<SfIpVar>, // sorted by name (strcmp ascending)
    /// ID for recognition of variables with different name but same content.
    /// Start at 1; 0 means unset.
    pub id: u32,
}

impl Vartable {
    /// sfvt_alloc_table()
    pub fn new() -> Self {
        Vartable { vars: Vec::new(), id: 1 }
    }

    /// sfvt_lookup_var(): strip a leading '$', cut the name at the first
    /// space / '\\' / ']', then exact-length compare against the sorted list.
    pub fn lookup_var(&self, name: &str) -> Option<&SfIpVar> {
        let name = name.strip_prefix('$').unwrap_or(name);
        let nb = name.as_bytes();
        let end = nb
            .iter()
            .position(|&c| {
                matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b'\\' | b']')
            })
            .unwrap_or(nb.len());
        let len = end; // bytes (names are ASCII in practice)
        for v in &self.vars {
            let vname = v.name.clone().unwrap_or_default();
            if vname.len() == len && vname.as_bytes()[..len] == nb[..len] {
                return Some(v);
            }
        }
        None
    }

    /// sfvt_add_str() + sfvar_alloc(). On Ok, the new/replace var is stored
    /// in the table; SFIP_DUPLICATE means it replaced an existing entry.
    /// Returns code + (index into vars when added).
    pub fn add_str(&mut self, str: &str) -> (SfIpRet, Option<usize>) {
        let (mut var, status) = sfvar_alloc(self, str);
        // If the alias is not available, return SFIP_LOOKUP_FAILURE to
        // resolve the variable later
        if status == SfIpRet::LookupFailure {
            return (status, None);
        }
        let var = match var.take() {
            None => return (SfIpRet::Failure, None),
            Some(v) => v,
        };

        /* If this is an alias of another var, id will be set */
        let mut var = var;
        if var.id == 0 {
            var.id = self.id;
            self.id += 1;
        }

        /* Insertion sort by name (C strcmp: byte order) */
        let name = var.name.clone().unwrap_or_default();
        let pos = self
            .vars
            .iter()
            .position(|v| name.as_bytes() <= v.name.as_deref().unwrap_or("").as_bytes());
        match pos {
            None => {
                self.vars.push(var);
                (SfIpRet::Success, Some(self.vars.len() - 1))
            }
            Some(p) => {
                if self.vars[p].name.as_deref().unwrap_or("") == name.as_str() {
                    // Redefinition: replace
                    self.vars[p] = var;
                    (SfIpRet::Duplicate, Some(p))
                } else {
                    self.vars.insert(p, var);
                    (SfIpRet::Success, Some(p))
                }
            }
        }
    }

    /// sfvt_add_to_var(): parse src into dst; validate the merged var.
    pub fn add_to_var(&self, dst: &mut SfIpVar, src: &str) -> SfIpRet {
        let ret = sfvar_parse_iplist(Some(self), dst, src, false);
        if ret == SfIpRet::Success {
            return sfvar_validate(dst);
        }
        ret
    }

    /// sfvt_add_to_var(nullptr, ...): same path, no var table (rule bodies
    /// cannot reference $Vars -> SFIP_LOOKUP_UNAVAILABLE for any $ref).
    pub fn none_add_to_var(dst: &mut SfIpVar, src: &str) -> SfIpRet {
        let ret = sfvar_parse_iplist(None, dst, src, false);
        if ret == SfIpRet::Success {
            return sfvar_validate(dst);
        }
        ret
    }

    /// sfvt_define(): add the variable, then store its expanded value form
    /// (sfvt_expand_value) when add succeeded or redefined it.
    pub fn define(&mut self, name: &str, value: &str) -> SfIpRet {
        let combined = format!("{name} {value}");
        let (ret, idx) = self.add_str(&combined);
        if ret == SfIpRet::Success || ret == SfIpRet::Duplicate {
            if let Some(i) = idx {
                let expanded = sfvt_expand_value(self, name, value);
                self.vars[i].value = expanded;
            }
        }
        ret
    }
}

/// sfvt_expand_value(): expand $var / $(var) references in `value` using the
/// table's stored `value` strings. Needs a table snapshot without the row
/// being defined (C defines before expanding, so self-lookup yields the
/// row's old NULL value -> literal kept); emulate by consulting all vars.
fn sfvt_expand_value(table: &Vartable, _name: &str, value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let vb = value.as_bytes();
    let mut p = 0usize;
    let mut e = vb.len();
    while p < e && (vb[p] as char).is_ascii_whitespace() {
        p += 1;
    }
    while e > p && (vb[e - 1] as char).is_ascii_whitespace() {
        e -= 1;
    }
    if p == e {
        return None;
    }
    let tmp = &value[p..e];

    let mut ret = String::new();
    let tb = tmp.as_bytes();
    let mut ptr = 0usize;
    let end = tb.len();
    let mut escaped = false;

    while ptr < end {
        if !escaped && tb[ptr] == b'$' {
            ptr += 1;
            if ptr >= end {
                return None; // goto error
            }
            let mut parens = false;
            if tb[ptr] == b'(' {
                ptr += 1;
                parens = true;
            }
            let varstart = ptr;
            while ptr < end {
                if parens {
                    if tb[ptr] == b')' {
                        break;
                    }
                } else if !(tb[ptr].is_ascii_alphanumeric() || tb[ptr] == b'_') {
                    break;
                }
                ptr += 1;
            }
            if varstart == ptr {
                return None; // goto error
            }
            let vartmp = &tmp[varstart..ptr];
            let ipvar = match table.lookup_var(vartmp) {
                None => return None, // goto error
                Some(v) => v,
            };
            if let Some(iv) = &ipvar.value {
                ret.push_str(iv);
            }
            if parens {
                ptr += 1;
            }
            continue;
        }

        escaped = tb[ptr] == b'\\';
        ret.push(tb[ptr] as char);
        ptr += 1;
    }
    Some(ret)
}
