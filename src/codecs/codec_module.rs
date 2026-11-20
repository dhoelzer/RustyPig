//! Port of `src/codecs/codec_module.{h,cc}` (269+71 = 340 L) — row
//! 18d. THE vocabulary header every later codec row includes (NEXT.md
//! 18d scoping): the DECODE_* event enum home (the :203 `// = 450` /
//! :209 `// = 456` anchors 18c's deviations lean on) + the codecs-
//! module parameter face + `BaseCodecModule` / `CodecModule`.
//! Ground: snort3-src @ fe29cbe, md5 `3f3bd92752ba46b8732f831724d3b279`
//! (h) + `27ca93d786e8532b7f9679efafc57726` (cc) — eth PLAN §0.
//!
//! This is the header's FIRST real link (`codec_module.cc` links as
//! the row's own .o at 18d — the 18c rule "do not link it" expired by
//! design, eth PLAN §1). Its vectors arms (tools/eth_harness/
//! vectors.txt, IMmutABLE):
//!   vec:3  `EV 116 424` DECODE_ETH_HDR_TRUNC (enum WALK, h:171-:177)
//!   vec:13 `EV 116 109` DECODE_ARP_TRUNCATED (LITERAL, h:73)
//!   vec:15 `MOD rules=8 gid=116 help=general decoder rules
//!          trace=null` (codec_module.cc:55-:67 8-row table walked +
//!          h:38 GID_DECODE 116 + cc:30-:31 help + cc:45-:53 the
//!          `#ifndef DEBUG_MSGS` null-trace-options arm: the harness
//!          compiles WITHOUT DEBUG_MSGS, so `trace=null` is the pinned
//!          face — the 18a TraceOption graft seam serves it, eth
//!          PLAN §3).

use crate::framework::parameter::Parameter;
use crate::framework::parameter::Type as PtType;

// codec_module.h:38 `constexpr int GID_DECODE = 116;` — the landed
// home stays framework/codec.rs:23 (row 4); cite-only re-pin lives in
// the parity test (vectors:15 `gid=116`). No duplicate const here.

/// codec_module.h:34 `extern THREAD_LOCAL const snort::Trace*
/// decode_trace;` + codec_module.cc:35 `THREAD_LOCAL const Trace*
/// decode_trace = nullptr;` — THE definition home lands HERE (the
/// 18a file_trace posture, file_module.rs:102-:129: no landed Trace
/// type — the row-observable face is the slot's nullness ONLY, so the
/// slot models as a data-free token; deviation row 18a carried).
pub struct TraceToken;

std::thread_local! {
    pub static DECODE_TRACE: std::cell::Cell<Option<&'static TraceToken>> =
        const { std::cell::Cell::new(None) };
}

// ==================================================================
// The full CodecSid enum — every value from the comment-stripped
// mechanical walk of codec_module.h:44-:234 (eth PLAN §3 enum-WALK
// discipline; the extraction asserts 170 entries and every `// = N`
// comment anchor matches, pinned in tests/eth_parity_test.rs).
// ==================================================================

/// The ENTIRE `enum CodecSid : uint32_t` (codec_module.h:44-:234) —
/// 170 enumerators, the FULL literal walk from the C header
/// (comment-stripped mechanical extraction, eth PLAN §3 enum-WALK
/// discipline): every explicit `= N` and every trailing `// = N`
/// comment lands on its const; the rest carry the walked value. The
/// comment-anchor pins (// = 430 / // = 440 / // = 450 / // = 460 /
/// // = 470 @ :183/:193/:203/:213/:223) ALL match the walk — asserted
/// in tests/eth_parity_test.rs codec_sid_walk_vs_header. DECODE-
/// ETH_HDR_TRUNC = 424 by WALK (418 @ :171 + six (:172-:176) ->
/// :177); DECODE_ARP_TRUNCATED = 109 by LITERAL (:73) — the
/// double-pin pair vectors:3 `EV 116 424` / vectors:13 `EV 116 109`.
#[allow(dead_code)] // the vocabulary serves every LATER row's arms
// The C enumerator spellings stay VERBATIM (skill rule: a literal
// C-table-to-Rust-table transcription keeps the C names so the
// header-vs-consts header audit stays row-by-row diffable; renaming
// breaks the walk-pin audit). File-level allow, 17-series precedent.
#[allow(non_camel_case_types)]
#[repr(u32)] // mirrors the C `enum CodecSid : uint32_t` width
pub enum CodecSid {
    DECODE_NOT_IPV4_DGRAM = 1,  // h:46
    DECODE_IPV4_INVALID_HEADER_LEN = 2,  // h:47
    DECODE_IPV4_DGRAM_LT_IPHDR = 3,  // h:48
    DECODE_IPV4OPT_BADLEN = 4,  // h:49
    DECODE_IPV4OPT_TRUNCATED = 5,  // h:50
    DECODE_IPV4_DGRAM_GT_CAPLEN = 6,  // h:51
    DECODE_TCP_DGRAM_LT_TCPHDR = 45,  // h:53
    DECODE_TCP_INVALID_OFFSET = 46,  // h:54
    DECODE_TCP_LARGE_OFFSET = 47,  // h:55
    DECODE_TCPOPT_BADLEN = 54,  // h:57
    DECODE_TCPOPT_TRUNCATED = 55,  // h:58
    DECODE_TCPOPT_TTCP = 56,  // h:59
    DECODE_TCPOPT_OBSOLETE = 57,  // h:60
    DECODE_TCPOPT_EXPERIMENTAL = 58,  // h:61
    DECODE_TCPOPT_WSCALE_INVALID = 59,  // h:62
    DECODE_UDP_DGRAM_LT_UDPHDR = 95,  // h:64
    DECODE_UDP_DGRAM_INVALID_LENGTH = 96,  // h:65
    DECODE_UDP_DGRAM_SHORT_PACKET = 97,  // h:66
    DECODE_UDP_DGRAM_LONG_PACKET = 98,  // h:67
    DECODE_ICMP_DGRAM_LT_ICMPHDR = 105,  // h:69
    DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR = 106,  // h:70
    DECODE_ICMP_DGRAM_LT_ADDRHDR = 107,  // h:71
    DECODE_ARP_TRUNCATED = 109,  // h:73
    DECODE_EAPOL_TRUNCATED = 110,  // h:74
    DECODE_EAPKEY_TRUNCATED = 111,  // h:75
    DECODE_EAP_TRUNCATED = 112,  // h:76
    DECODE_BAD_PPPOE_DISC = 120,  // h:78
    DECODE_BAD_VLAN = 130,  // h:79
    DECODE_BAD_LLC_HEADER = 131,  // h:80
    DECODE_BAD_LLC_OTHER = 132,  // h:81
    DECODE_BAD_80211_ETHLLC = 133,  // h:82
    DECODE_BAD_80211_OTHER = 134,  // h:83
    DECODE_BAD_TRH = 140,  // h:85
    DECODE_BAD_TR_ETHLLC = 141,  // h:86
    DECODE_BAD_TR_MR_LEN = 142,  // h:87
    DECODE_BAD_TRHMR = 143,  // h:88
    DECODE_BAD_TRAFFIC_LOOPBACK = 150,  // h:90
    DECODE_BAD_TRAFFIC_SAME_SRCDST = 151,  // h:91
    DECODE_GRE_DGRAM_LT_GREHDR = 160,  // h:93
    DECODE_GRE_MULTIPLE_ENCAPSULATION = 161,  // h:94
    DECODE_GRE_INVALID_VERSION = 162,  // h:95
    DECODE_GRE_INVALID_HEADER = 163,  // h:96
    DECODE_GRE_V1_INVALID_HEADER = 164,  // h:97
    DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR = 165,  // h:98
    DECODE_BAD_MPLS = 170,  // h:100
    DECODE_BAD_MPLS_LABEL0 = 171,  // h:101
    DECODE_BAD_MPLS_LABEL1 = 172,  // h:102
    DECODE_BAD_MPLS_LABEL2 = 173,  // h:103
    DECODE_BAD_MPLS_LABEL3 = 174,  // h:104
    DECODE_MPLS_RESERVED_LABEL = 175,  // h:105
    DECODE_MPLS_LABEL_STACK = 176,  // h:106
    DECODE_GENEVE_DGRAM_LT_GENEVE_HDR = 180,  // h:108
    DECODE_GENEVE_INVALID_VERSION = 181,  // h:109
    DECODE_GENEVE_INVALID_HEADER = 182,  // h:110
    DECODE_GENEVE_INVALID_FLAGS = 183,  // h:111
    DECODE_GENEVE_INVALID_OPTIONS = 184,  // h:112
    DECODE_ICMP_ORIG_IP_TRUNCATED = 250,  // h:114
    DECODE_ICMP_ORIG_IP_VER_MISMATCH = 251,  // h:115
    DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP = 252,  // h:116
    DECODE_ICMP_ORIG_PAYLOAD_LT_64 = 253,  // h:117
    DECODE_ICMP_ORIG_PAYLOAD_GT_576 = 254,  // h:118
    DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET = 255,  // h:119
    DECODE_IPV6_MIN_TTL = 270,  // h:121
    DECODE_IPV6_IS_NOT = 271,  // h:122
    DECODE_IPV6_TRUNCATED_EXT = 272,  // h:123
    DECODE_IPV6_TRUNCATED = 273,  // h:124
    DECODE_IPV6_DGRAM_LT_IPHDR = 274,  // h:125
    DECODE_IPV6_DGRAM_GT_CAPLEN = 275,  // h:126
    DECODE_IPV6_DST_ZERO = 276,  // h:127
    DECODE_IPV6_SRC_MULTICAST = 277,  // h:128
    DECODE_IPV6_DST_RESERVED_MULTICAST = 278,  // h:129
    DECODE_IPV6_BAD_OPT_TYPE = 279,  // h:130
    DECODE_IPV6_BAD_MULTICAST_SCOPE = 280,  // h:131
    DECODE_IPV6_BAD_NEXT_HEADER = 281,  // h:132
    DECODE_IPV6_ROUTE_AND_HOPBYHOP = 282,  // h:133
    DECODE_IPV6_TWO_ROUTE_HEADERS = 283,  // h:134
    DECODE_ICMPV6_TOO_BIG_BAD_MTU = 285,  // h:136
    DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE = 286,  // h:137
    DECODE_ICMPV6_SOLICITATION_BAD_CODE = 287,  // h:138
    DECODE_ICMPV6_ADVERT_BAD_CODE = 288,  // h:139
    DECODE_ICMPV6_SOLICITATION_BAD_RESERVED = 289,  // h:140
    DECODE_ICMPV6_ADVERT_BAD_REACHABLE = 290,  // h:141
    DECODE_IPV6_TUNNELED_IPV4_TRUNCATED = 291,  // h:143
    DECODE_IPV6_DSTOPTS_WITH_ROUTING = 292,  // h:144
    DECODE_IP_MULTIPLE_ENCAPSULATION = 293,  // h:145
    DECODE_ESP_HEADER_TRUNC = 294,  // h:147
    DECODE_IPV6_BAD_OPT_LEN = 295,  // h:148
    DECODE_IPV6_UNORDERED_EXTENSIONS = 296,  // h:149
    DECODE_GTP_MULTIPLE_ENCAPSULATION = 297,  // h:151
    DECODE_GTP_BAD_LEN = 298,  // h:152
    DECODE_TCP_XMAS = 400,  // h:154
    DECODE_TCP_NMAP_XMAS = 401,  // h:155
    DECODE_DOS_NAPTHA = 402,  // h:156
    DECODE_SYN_TO_MULTICAST = 403,  // h:157
    DECODE_ZERO_TTL = 404,  // h:158
    DECODE_BAD_FRAGBITS = 405,  // h:159
    DECODE_UDP_IPV6_ZERO_CHECKSUM = 406,  // h:160
    DECODE_IP4_LEN_OFFSET = 407,  // h:161
    DECODE_IP4_SRC_THIS_NET = 408,  // h:162
    DECODE_IP4_DST_THIS_NET = 409,  // h:163
    DECODE_IP4_SRC_MULTICAST = 410,  // h:164
    DECODE_IP4_SRC_RESERVED = 411,  // h:165
    DECODE_IP4_DST_RESERVED = 412,  // h:166
    DECODE_IP4_SRC_BROADCAST = 413,  // h:167
    DECODE_IP4_DST_BROADCAST = 414,  // h:168
    DECODE_ICMP4_DST_MULTICAST = 415,  // h:169
    DECODE_ICMP4_DST_BROADCAST = 416,  // h:170
    DECODE_ICMP4_TYPE_OTHER = 418,  // h:171
    DECODE_TCP_BAD_URP = 419,  // h:172
    DECODE_TCP_SYN_FIN = 420,  // h:173
    DECODE_TCP_SYN_RST = 421,  // h:174
    DECODE_TCP_MUST_ACK = 422,  // h:175
    DECODE_TCP_NO_SYN_ACK_RST = 423,  // h:176
    DECODE_ETH_HDR_TRUNC = 424,  // h:177
    DECODE_IP4_HDR_TRUNC = 425,  // h:178
    DECODE_ICMP4_HDR_TRUNC = 426,  // h:179
    DECODE_ICMP6_HDR_TRUNC = 427,  // h:180
    DECODE_IP4_MIN_TTL = 428,  // h:181
    DECODE_IP6_ZERO_HOP_LIMIT = 429,  // h:182
    DECODE_IP4_DF_OFFSET = 430,  // h:183  // = 430
    DECODE_ICMP6_TYPE_OTHER = 431,  // h:184
    DECODE_ICMP6_DST_MULTICAST = 432,  // h:185
    DECODE_TCP_SHAFT_SYNFLOOD = 433,  // h:186
    DECODE_ICMP_PING_NMAP = 434,  // h:187
    DECODE_ICMP_ICMPENUM = 435,  // h:188
    DECODE_ICMP_REDIRECT_HOST = 436,  // h:189
    DECODE_ICMP_REDIRECT_NET = 437,  // h:190
    DECODE_ICMP_TRACEROUTE_IPOPTS = 438,  // h:191
    DECODE_ICMP_SOURCE_QUENCH = 439,  // h:192
    DECODE_ICMP_BROADSCAN_SMURF_SCANNER = 440,  // h:193  // = 440
    DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED = 441,  // h:194
    DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED = 442,  // h:195
    DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED = 443,  // h:196
    DECODE_IP_OPTION_SET = 444,  // h:197
    DECODE_UDP_LARGE_PACKET = 445,  // h:198
    DECODE_TCP_PORT_ZERO = 446,  // h:199
    DECODE_UDP_PORT_ZERO = 447,  // h:200
    DECODE_IP_RESERVED_FRAG_BIT = 448,  // h:201
    DECODE_IP_UNASSIGNED_PROTO = 449,  // h:202
    DECODE_IP_BAD_PROTO = 450,  // h:203  // = 450
    DECODE_ICMP_PATH_MTU_DOS = 451,  // h:204
    DECODE_ICMP_DOS_ATTEMPT = 452,  // h:205
    DECODE_IPV6_ISATAP_SPOOF = 453,  // h:206
    DECODE_PGM_NAK_OVERFLOW = 454,  // h:207
    DECODE_IGMP_OPTIONS_DOS = 455,  // h:208
    DECODE_IP6_EXCESS_EXT_HDR = 456,  // h:209
    DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE = 457,  // h:210
    DECODE_IPV6_BAD_FRAG_PKT = 458,  // h:211
    DECODE_ZERO_LENGTH_FRAG = 459,  // h:212
    DECODE_ICMPV6_NODE_INFO_BAD_CODE = 460,  // h:213  // = 460
    DECODE_IPV6_ROUTE_ZERO = 461,  // h:214
    DECODE_ERSPAN_HDR_VERSION_MISMATCH = 462,  // h:215
    DECODE_ERSPAN2_DGRAM_LT_HDR = 463,  // h:216
    DECODE_ERSPAN3_DGRAM_LT_HDR = 464,  // h:217
    DECODE_AUTH_HDR_TRUNC = 465,  // h:218
    DECODE_AUTH_HDR_BAD_LEN = 466,  // h:219
    DECODE_FPATH_HDR_TRUNC = 467,  // h:220
    DECODE_CISCO_META_HDR_TRUNC = 468,  // h:221
    DECODE_CISCO_META_HDR_OPT_LEN = 469,  // h:222
    DECODE_CISCO_META_HDR_OPT_TYPE = 470,  // h:223  // = 470
    DECODE_CISCO_META_HDR_SGT = 471,  // h:224
    DECODE_TOO_MANY_LAYERS = 472,  // h:225
    DECODE_BAD_ETHER_TYPE = 473,  // h:226
    DECODE_ICMP6_NOT_IP6 = 474,  // h:227
    DECODE_MIPV6_BAD_PAYLOAD_PROTO = 475,  // h:228
    DECODE_IPV6_SRC_RESERVED = 476,  // h:229
    DECODE_IPV6_DST_RESERVED = 477,  // h:230
    DECODE_ICMP6_OPT_ZERO_LENGTH = 478,  // h:231
    DECODE_BAD_PPPOE_SESS = 479,  // h:232
    DECODE_INDEX_MAX = 480,  // h:233
}

/// The enum head comment kept beside the walk (h:41-:42):
/// "remember to add rules to preproc_rules/decoder.rules / add the
/// new decoder rules to the following enum."

// ==================================================================
// RuleMap (framework/module.h:77-:81 `struct RuleMap { unsigned sid;
// const char* msg; }`) — the landed literal shape (18a FMOD_RULES
// used tuples; this row lands the STRUCT because the C++-facing .cc
// tables read BOTH fields and the walk stops on sid == 0 BEFORE
// reading msg — the terminator's msg stays Option None, never read).
// ==================================================================
#[derive(Debug, PartialEq, Eq)]
pub struct RuleMap {
    pub sid: u32,      // module.h:79 `unsigned sid`
    pub msg: Option<&'static str>, // module.h:80 `const char* msg`
}

/// The C table-walk idiom `while (rm[n].sid) n++;` — the probe's
/// rule-count face (vectors:15 `rules=8`: the 8 entries before the
/// `{ 0, nullptr }` terminator at cc:66).
pub fn rule_count(rules: &[RuleMap]) -> usize {
    let mut n = 0;
    while rules[n].sid != 0 {
        n += 1;
    }
    n
}

// ==================================================================
// module.h:216 `enum Usage { GLOBAL, CONTEXT, INSPECT, DETECT };` —
// unscoped order pins (file_module.rs:306 C_USAGE_GLOBAL precedent).
// ==================================================================
pub const C_USAGE_GLOBAL: u32 = 0;
pub const C_USAGE_CONTEXT: u32 = 1;
#[allow(dead_code)]
pub const C_USAGE_INSPECT: u32 = 2;
#[allow(dead_code)]
pub const C_USAGE_DETECT: u32 = 3;

// ==================================================================
// codec_module.h:240-:255 `class BaseCodecModule : public Module`
// ==================================================================

/// h:243-:247 the two ctors (2-arg `Module(s, h)` + 3-arg
/// `Module(s, h, p, is_list = false)`) + h:249-:250 `get_gid() ->
/// GID_DECODE` + h:253-:254 `get_usage() -> CONTEXT` (the
/// cppcheck-suppressed uselessOverride KEPT: the comment says the
/// override is retained to document the derived interface contract).
/// No Rust Module base fork (17z/18a posture); the (name, help,
/// params, is_list) triple lands as this type's fields.
#[derive(Debug)]
pub struct BaseCodecModule {
    pub name: &'static str,
    pub help: &'static str,
    /// h:246 the `const Parameter*` head (nullptr-terminated table);
    /// Rust carries `Option<&'static [Parameter]>` — None models the
    /// 2-arg ctor's unset base slot ONLY where C leaves it unset; the
    /// C default is_list = false lands explicit (deviation row 18d).
    pub params: Option<&'static [Parameter]>,
    pub is_list: bool,
}

impl BaseCodecModule {
    /// h:243 `BaseCodecModule(const char* s, const char* h) :
    /// Module(s, h)` — params slot untouched (C Module ctor leaves it
    /// null, module.cc).
    pub fn new(s: &'static str, h: &'static str) -> BaseCodecModule {
        BaseCodecModule { name: s, help: h, params: None, is_list: false }
    }

    /// h:246-:247 `BaseCodecModule(const char* s, const char* h,
    /// const Parameter* p, bool is_list = false)` — CodecModule's
    /// ctor call lands `is_list: false` EXPLICIT (the C default).
    pub fn new_with_params(
        s: &'static str,
        h: &'static str,
        p: &'static [Parameter],
    ) -> BaseCodecModule {
        BaseCodecModule { name: s, help: h, params: Some(p), is_list: false }
    }

    /// h:249-:250 `unsigned get_gid() const override { return
    /// GID_DECODE; }` — vectors:15 `gid=116`.
    #[inline]
    pub fn get_gid(&self) -> u32 {
        crate::framework::codec::GID_DECODE
    }

    /// h:253-:254 `Usage get_usage() const override { return
    /// CONTEXT; }` == 1 (module.h:216 order).
    #[inline]
    pub fn get_usage(&self) -> u32 {
        C_USAGE_CONTEXT
    }
}

// ==================================================================
// codec_module.h:257-:266 `class SO_PUBLIC CodecModule : public
// BaseCodecModule` + codec_module.cc's face.
// ==================================================================

/// cc:33 `#define s_name "decode"` (the CodecModule module name —
/// NOT the same string as the CD_* codec names).
pub const S_NAME: &str = "decode";
/// cc:30-:31 `#define codec_module_help "general decoder rules"` —
/// vectors:15 `help=general decoder rules`.
pub const CODEC_MODULE_HELP: &str = "general decoder rules";

/// cc:37 `static const Parameter s_params[] = {{ nullptr,
/// Parameter::PT_MAX, nullptr, nullptr, nullptr }};` — the ONE
/// entry terminator table (Parameter 5-field ctor, parameter.h:74;
/// the landed Rust Parameter struct keeps name/ptype/deflt and omits
/// the range+help slots, parameter.rs:36-:41 — carried deviation,
/// both nullptr here).
pub const S_PARAMS: [Parameter; 1] = [Parameter {
    name: None,                 // cc:37 1st field
    ptype: PtType::PtMax,       // Parameter::PT_MAX (parameter.h:66)
    deflt: None,                // 4th field (deflt)
}];

/// cc:39-:40 `CodecModule::CodecModule() : BaseCodecModule(s_name,
/// codec_module_help, s_params) { }` — the 3-arg arm lands
/// is_list=false via the C default.
#[derive(Debug)]
pub struct CodecModule {
    pub base: BaseCodecModule,
}

impl CodecModule {
    pub fn new() -> CodecModule {
        CodecModule {
            base: BaseCodecModule::new_with_params(S_NAME, CODEC_MODULE_HELP, &S_PARAMS),
        }
    }

    /// cc:42-:43 `set_trace(const Trace* trace) const { decode_trace
    /// = trace; }` — writes THIS TU's THREAD_LOCAL definition (the
    /// 18a file_trace twin posture, data-free token slot).
    pub fn set_trace(&self, trace: Option<&'static TraceToken>) {
        DECODE_TRACE.with(|t| t.set(trace));
    }

    /// the current-slot readback (the probe's face for the def home).
    pub fn decode_trace_armed() -> bool {
        DECODE_TRACE.with(|t| t.get().is_some())
    }

    /// cc:45-:53 `get_trace_options()` — `#ifndef DEBUG_MSGS` the
    /// function returns nullptr (vectors:15 `trace=null` — the
    /// harness compiles WITHOUT DEBUG_MSGS, eth PLAN §3), and only
    /// the `#else` arm builds the function-local `static const
    /// TraceOption codec_trace_options(nullptr, 0, nullptr)`.
    /// DEBUG_MSGS is an autotools build flag, NOT a cargo debug/
    /// release concept, so the seam is NOT cfg'd: the port models
    /// the PINNED nullptr arm unconditionally and keeps the
    /// DEBUG_MSGS face as this cited comment (deviations row 18d
    /// "DEBUG_MSGS seam"; the flipped face would be the all-null
    /// TraceOptionFace below either way).
    pub fn get_trace_options(&self) -> Option<TraceOptionFace> {
        None // cc:48 `return nullptr;` — the pinned vectors:15 face
    }

    /// cc:69-:70 `get_rules() { return general_decode_rules; }`
    pub fn get_rules(&self) -> &'static [RuleMap; 9] {
        &GENERAL_DECODE_RULES
    }

    /// h:249-:250 gid + the help/name readbacks the probe walks
    /// (vectors:15 `gid=116 help=general decoder rules`).
    pub fn get_gid(&self) -> u32 {
        self.base.get_gid()
    }
    pub fn get_help(&self) -> &'static str {
        self.base.help
    }
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

impl Default for CodecModule {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:45-:53 the DEBUG_MSGS-face TraceOption triple (name=nullptr,
/// id=0, help=nullptr, trace.h TraceOption ctor — the 18a fmod
/// TraceOption graft face).
#[derive(Debug, PartialEq, Eq)]
pub struct TraceOptionFace {
    pub name: Option<&'static str>,
    pub id: u32,
    pub help: Option<&'static str>,
}

/// cc:55-:67 `static const RuleMap general_decode_rules[]` — EIGHT
/// rows + the `{ 0, nullptr }` terminator (cc:66). Vectors:15's
/// `rules=8` walks exactly these eight before stopping (cc:57-:65
/// order VERBATIM; msg strings byte-exact from the C source, the
/// two-line cc:58-:59 entry lands as one string). The sids reference
/// the CodecSid variants (as u32) — the walk values, never typed.
pub const GENERAL_DECODE_RULES: [RuleMap; 9] = [
    RuleMap { sid: CodecSid::DECODE_IP_BAD_PROTO as u32, msg: Some("bad IP protocol") }, // cc:57 (h:203 `// = 450` comment pin)
    RuleMap { sid: CodecSid::DECODE_IP_MULTIPLE_ENCAPSULATION as u32, msg: Some("two or more IP (v4 and/or v6) encapsulation layers present") }, // cc:58-:59 (h:145 = 293)
    RuleMap { sid: CodecSid::DECODE_ZERO_LENGTH_FRAG as u32, msg: Some("fragment with zero length") }, // cc:60 (h:212 walk = 459)
    RuleMap { sid: CodecSid::DECODE_BAD_TRAFFIC_LOOPBACK as u32, msg: Some("loopback IP") }, // cc:61 (h:90 = 150)
    RuleMap { sid: CodecSid::DECODE_BAD_TRAFFIC_SAME_SRCDST as u32, msg: Some("same src/dst IP") }, // cc:62 (h:91 = 151)
    RuleMap { sid: CodecSid::DECODE_IP_UNASSIGNED_PROTO as u32, msg: Some("unassigned/reserved IP protocol") }, // cc:63 (h:202 walk = 449)
    RuleMap { sid: CodecSid::DECODE_TOO_MANY_LAYERS as u32, msg: Some("too many protocols present") }, // cc:64 (h:225 walk = 472)
    RuleMap { sid: CodecSid::DECODE_BAD_ETHER_TYPE as u32, msg: Some("ether type out of range") }, // cc:65 (h:226 walk = 473)
    RuleMap { sid: 0, msg: None }, // cc:66 `{ 0, nullptr }`
];

/// cc:69-:70 — the module-side twin (kept next to the table; the
/// CodecModule::get_rules method routes here).
pub fn general_decode_rules() -> &'static [RuleMap; 9] {
    &GENERAL_DECODE_RULES
}
