// Port of the Value-facing subset of snort3 framework/parameter.{h,cc}.
// validate()/range parsing deferred to the option-parsing layer.
#![allow(dead_code)]

pub type PtMax = u32;

/// Parameter::Type
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Type {
    PtTable = 0,  // range is Parameter*, no default
    PtList,       // range is Parameter*, no default
    PtDynamic,    // range is RangeQuery*
    PtBool,       // if you are reading this, get more coffee
    PtInt,        // signed 53 bits or less determined by range
    PtInterval,   // string that defines an interval, bounds within range
    PtReal,       // double
    PtPort,       // 0 to 64K-1 unless specified otherwise
    PtString,     // any string less than len chars
    PtSelect,     // any string appearing in range
    PtMulti,      // one or more strings appearing in range
    PtEnum,       // string converted to unsigned by range sequence
    PtMac,        // 6-byte mac address
    PtIp4,        // inet_addr() compatible
    PtAddr,       // ip4 or ip6 CIDR
    PtBitList,    // string that converts to bitset
    PtIntList,    // string that contains ints
    PtAddrList,   // Snort 2 ip list in [ ]
    PtImplied,    // rule option args w/o values eg relative
    PtStrList,    // string that contains strings
    PtDynamics,   // multiple from range which is RangeQuery*
    PtMax,        // PT_MAX
}

#[derive(Clone, Copy, Debug)]
pub struct Parameter {
    pub name: Option<&'static str>,
    pub ptype: Type,
    pub deflt: Option<&'static str>,
    // range omitted here (char*/RangeQuery*/Parameter* variants) until the
    // option-validating layer needs it
}

impl Parameter {
    pub fn is_positional(&self) -> bool {
        matches!(self.name, Some(n) if n.starts_with('~'))
    }

    pub fn is_wild_card(&self) -> bool {
        matches!(self.name, Some(n) if n.starts_with('*'))
    }

    pub fn is_table(&self) -> bool {
        self.ptype == Type::PtTable || self.ptype == Type::PtList
    }

    pub fn is_quoted(&self) -> bool {
        (self.ptype as u32) > (Type::PtPort as u32)
    }

    // ---- Parameter::index (parameter.cc:44-77) ----

    /// 0-based; -1 if not found; list is | delimited
    pub fn index(list: &str, key: &str) -> i32 {
        match find(list, key) {
            None => -1,
            // char offsets: byte index of match within list
            Some(t) => get_index(list, t) as i32,
        }
    }

    /// C Parameter::find: first Parameter in null-terminated array whose
    /// name equals s (used by options layer; here a slice version).
    pub fn find_param<'a>(list: &[&'a Parameter], s: &str) -> Option<&'a Parameter> {
        list.iter().copied().find(|p| matches!(p.name, Some(n) if n == s))
    }
}

fn is_sep(c: u8) -> bool {
    c == 0 || c == b'|' // C: !c || c == '|'
}

/// static const char* find(const char* r, const char* s)
/// whole-token match inside '|'-separated list r; returns byte index.
fn find(r: &str, s: &str) -> Option<usize> {
    let rb = r.as_bytes();
    let sb = s.as_bytes();
    let n = sb.len();
    if n == 0 {
        return None;
    }
    let mut from = 0usize;
    while let Some(rel) = r[from..].find(s) {
        let t = from + rel;
        let before_ok = t == 0 || is_sep(rb[t - 1]);
        // C reads t[n] which may be the NUL terminator (== list end)
        let at = if t + n < rb.len() { rb[t + n] } else { 0 };
        if before_ok && is_sep(at) {
            return Some(t);
        }
        from = t + n;
    }
    None
}

/// static unsigned get_index(const char* r, const char* t)
fn get_index(r: &str, t: usize) -> u32 {
    let mut idx = 0u32;
    let mut p = r.find('|');
    while let Some(pos) = p {
        if pos >= t {
            break;
        }
        idx += 1;
        p = r[pos + 1..].find('|').map(|q| q + pos + 1);
    }
    idx
}
