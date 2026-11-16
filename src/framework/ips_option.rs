// Port of snort3 framework/ips_option.{h,cc} core — the IpsOption base
// class identity layer (name, type, hash, ==) plus the enums. The
// instantiator statics (set_* on IpsInfo) and the Packet/Cursor eval
// hooks are deferred until the detection/rule-parse layers exist; see
// PORTING_PLAN.md.
use crate::framework::pdu_section::{section_to_flag, PduSection, SectionFlags};
use crate::hash::{finalize, mix_str};

/// detection/rule_option_types.h
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum OptionType {
    LeafNode,  // RULE_OPTION_TYPE_LEAF_NODE
    Content,   // RULE_OPTION_TYPE_CONTENT
    Flowbit,   // RULE_OPTION_TYPE_FLOWBIT
    Other,     // RULE_OPTION_TYPE_OTHER
}

/// framework/ips_option.h CursorActionType
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u32)]
pub enum CursorActionType {
    CatNone,
    CatRead,
    CatAdjust,
    CatSetOther,
    CatSetRaw,
    CatSetFastPattern,
    CatSetSubSection,
}

/// framework/ips_option.h RuleDirection
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum RuleDirection {
    RuleFromClient,
    RuleFromServer,
    RuleWoDir,
}

/// IpsOption::EvalStatus
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvalStatus {
    NoMatch,
    Match,
    NoAlert,
    FailedBit,
}

/// IPSAPI_VERSION ((BASE_API_VERSION << 16) | 4). BASE_API_VERSION is 29
/// in framework/base_api.h at this source commit.
pub const IPSAPI_VERSION: u32 = (29 << 16) | 4;

/// The IpsOption base class. Rust models it as a base *struct* plus trait
/// hooks in the detection layer; here we keep identity + hashing exactly.
#[derive(Clone, Debug)]
pub struct IpsOption {
    name: &'static str,
    r#type: OptionType,
}

impl IpsOption {
    /// protected: IpsOption(const char* s, option_type_t t = OTHER)
    pub fn new(name: &'static str, r#type: OptionType) -> IpsOption {
        IpsOption { name, r#type }
    }

    pub fn get_name(&self) -> &'static str {
        self.name
    }
    pub fn get_type(&self) -> OptionType {
        self.r#type
    }

    /// virtual uint32_t hash() const {
    ///     uint32_t a=0,b=0,c=0; mix_str(a,b,c,get_name()); finalize(a,b,c);
    ///     return c;
    /// }
    /// Note: C names this member hash() but a name clash with std::hash is
    /// not an issue in Rust; keeping the name for parity.
    pub fn hash(&self) -> u32 {
        let (mut a, mut b, mut c) = (0u32, 0u32, 0u32);
        mix_str(&mut a, &mut b, &mut c, self.name.as_bytes(), 0);
        finalize(&mut a, &mut b, &mut c);
        c
    }

    /// virtual bool operator==(const IpsOption& ips) const
    /// { return !strcmp(get_name(), ips.get_name()); }
    pub fn option_eq(&self, other: &IpsOption) -> bool {
        self.name == other.name
    }

    /// virtual CursorActionType get_cursor_type() const { return CAT_NONE; }
    /// (base; ProbeOption == base => CAT_NONE in the harness seam)
    pub fn get_cursor_type(&self) -> CursorActionType {
        CursorActionType::CatNone
    }

    /// virtual section_flags get_pdu_section(bool) const — base returns PS_NONE
    /// flags (same as default_pdu_section()).
    pub fn get_pdu_section(&self, _to_server: bool) -> crate::framework::pdu_section::SectionFlags {
        Self::default_pdu_section()
    }

    /// bool is_buffer_setter() const { return get_cursor_type() > CAT_ADJUST; }
    pub fn is_buffer_setter(cursor_type: CursorActionType) -> bool {
        cursor_type > CursorActionType::CatAdjust
    }

    /// virtual section_flags get_pdu_section(bool) const { return
    /// section_to_flag(PS_NONE); }
    pub fn default_pdu_section() -> SectionFlags {
        section_to_flag(PduSection::PsNone)
    }
}
