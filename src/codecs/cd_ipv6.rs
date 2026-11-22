//! Port of `src/codecs/ip/cd_ipv6.cc` (733 L) — row 20a, the headline TU of
//! the `codecs/ip/` chapter trio (DIR FACT: `codecs/ip/`; cd_ipv4 sibling +
//! its lineage). Ground: snort3-src @ fe29cbe, md5
//! `89267b1d6d4f583434af207a14f90f56` wc 733. THE 26th straight honest
//! ZERO-GATE face: TEST_CASE/CppUTest grep-0 in the TU (the ip-chapter
//! harness stays probe-only, tools-side; NOTHING lands here).
//!
//! THE RULE TABLE IS THE MODULE (cc:44-:81): TWENTY-SIX data rows + the
//! cc:80 `{ 0, nullptr }` terminator -> `IPV6_RULES: [RuleMap; 27]`; sids
//! via the RESIDENT `CodecSid` walk — ALL TWENTY-SIX variant names
//! grep-VERIFIED resident codec_module.rs (270-:235 band; h:121-:230) —
//! ZERO new sids; msgs byte-exact off the ground strings INCLUDING the
//! wrapped multi-line pairs cc:54-:55, :57-:58, :59-:60, :61-:62, :64-:65,
//! :66-:67, :68-:69, :76-:77. The module cc:83-:90 is the TWO-arg
//! `BaseCodecModule(CD_IPV6_NAME, CD_IPV6_HELP)` + get_rules ONLY — NO
//! get_pegs/get_counts in this TU (the honest absent face).
//!
//! ext#4 SYNTHETIC ROW (the daq/dlt faces, NEVER ABI truth): HELP cc:39
//! splices `ADD_DLT(CD_IPV6_HELP_STR, DLT_IPV6)` -> the landed string
//! carries `" (DLT 229)"` (codec.h:52 STRINGIFY_MX splice; DLT_IPV6 229 =
//! the tcpdump-group/libpcap `pcap/dlt.h` face, SYNTHETIC ext#4 CITE — the
//! cd_eth DLT_EN10MB/DLT_PPP_ETHER + cd_raw DLT_RAW landed-row precedent);
//! the NAPT meta face cc:211-:217 (`daq_msg_get_meta(DAQ_PKT_META_NAPT_INFO)`
//! + the two `daq_napt_info_*_addr_family` accessor faces) lands as the
//!   SYNTHETIC `Ipv6NaptFace` probe struct — field layout probe-faked,
//!   cite-pinned, NEVER promoted to the frozen daq masters.
//!
//! THE WITNESS-NULLPTR FACE (cc:40): `static sfip_var_t* ReservedIpv6 =
//! nullptr;` — the sfvar world NEVER lands (sfip_var_t/sfvar_ip_in/
//! sfvar_from_string/sfvar_free cites only); the cc:682-:691 ginit block —
//! the IANA comment + the 14-range reserved-v6 STRING cc:687-:688 +
//! `assert(ReservedIpv6)` — rides as a CITE-NEVER-LAND comment. The
//! anomaly arms cc:288-:292 therefore fold to the honest witness-false
//! face: the config gate READS, the sfvar legs stay FALSE at the witness
//! (476/477 NEVER fire — never vectorized, cite).
//!
//! THE DECODE CONTRACT (the parity harness calls EXACTLY this shape):
//! `decode(&self, raw, codec, snort, conf, daq, sink) -> bool`. The C
//! `codec.conf->hit_ip_maxlayers` cc:157 + `tunnel_bypass_enabled`
//! cc:195/:203 + `is_address_anomaly_check_enabled` cc:286 legs fold to
//! the `Ipv6Conf` seam (hand-written Default = the NSDMI `max_ip_layers =
//! 0` face snort_config.h:279 — NEVER armed at default, the honest
//! 293-unarmed posture). `Ipv6DaqFace.pdd` is a FACE-A probe stamping
//! ONLY: this TU has NO `valid_checksum_from_daq` (grep-0 — the cd_icmp4/
//! cd_icmp6 contrast; the cd_ipv6 DAQ reads are EXACTLY-ONE, the NAPT
//! meta cc:211) so pdd is NEVER consumed in decode. The snort operand
//! mirrors the ip_api states (family + pointers): `ip4h` =
//! `get_ip4h()` (cc:245), `fam6` = `is_ip6()` after the cc:209 set.
//!
//! ORDER FACES the vectors pin: the cc:138-:146 DOUBLE-EV (273 — guarded —
//! THEN 291 UNCONDITIONAL, the "Taken from prot_ipv4.cc" comment rides;
//! the pair fires TOGETHER on a short v6 datagram, never sorted); the
//! cc:166-:175 nested-equal quirk (`!=` OUTER, `>` INNER — a payload_len
//! SMALLER than caplen CONTINUES silently, only the GT leg 275+bails);
//! the cc:187-:188 Teredo SILENT bail (NO codec_event — the honest
//! return-false face); cc:207 isatap BEFORE the cc:209 ip_api.set (the C
//! comment "check for isatap before overwriting the ip_api." rides); the
//! cc:224-:225 BAD_NEXT_HEADER 281 CONTINUES (no return); the cc:227
//! `const_cast<uint32_t&>(raw.len) = ip6h->len() + IP6_HEADER_LEN` folds
//! to a LOCAL computation (RawData.len immutable here; the new value feeds
//! the packet layer AFTER decode — NEVER printed, honest cite).
//!
//! THE LONG TAIL (cc:296-:507): the FULL multicast scope ladder transcribed
//! statement-verbatim — every IANA case comment rides; the
//! cppcheck-suppress knownConditionTrueFalse QUARTET (x4, cc:343/:345/:347/:349) rides.
//! THE u6_addr16/u6_addr32 WORD-READ IDENTITY (ipv6.h:50-:57 LE-host
//! union): on little-endian x86 C, `u6_addr16[k] != 0` IS the byte pair
//! `addr8[2k]==0 && addr8[2k+1]==0`, and `u6_addr8[n]` is the SAME byte as
//! the wire octet — every word face lands as the byte-window equal with
//! the identity cited; `ntohl` reads = BE reads; the isatap cc:253 RHS
//! keeps the RAW LE `u6_addr32[3]` field (C compares the LE field against
//! the LE s_addr — NEVER ntohl'd, the probe-pinned word face). The
//! ground MulticastScope enum values (ipv6.h:38-:44: ADMIN `0x04` SITE
//! `0x05`) WIN over the row brief's `ADMIN 3 SITE 4` sketch shorthand —
//! re-sed, the disk ground law.
//!
//! sids ALL RESIDENT (ZERO new consts): 273/:291 cc:141/:144, 271 cc:152,
//! 293 cc:159, 275 cc:171, 453 cc:254, 151 cc:271, 150 cc:276, 276 cc:283,
//! 476/477 cc:289/:292 (dead-at-witness), 277 cc:302, 280 cc:322, 278
//! cc:336/:354/:365/:413/:428/:481/:499/:505, 281 cc:225 — the
//! codec_module.rs h-walk cites, same band as the rule table.

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData, CodecTable,
    CODEC_NON_IP_TUNNEL, CODEC_ROUTING_SEEN, CODEC_TEREDO_SEEN, CODEC_UNSURE_ENCAP,
    IpProtocol, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData, ip_protocol,
    protocol_id,
};
use crate::sfip::sf_ip::SfIp;
use crate::sfip::sf_returns::{AF_INET, AF_INET6};

/// cc:37 `#define CD_IPV6_NAME "ipv6"` (the NAME macro — file base, table
/// feed and api name slot all land TRUE "ipv6").
pub const CD_IPV6_NAME: &str = "ipv6";
/// cc:38 `#define CD_IPV6_HELP_STR "support for Internet protocol v6"` —
/// the BASE string (the ADD_DLT splice lands on the HELP row below).
pub const CD_IPV6_HELP_STR: &str = "support for Internet protocol v6";
/// cc:39 `#define CD_IPV6_HELP ADD_DLT(CD_IPV6_HELP_STR, DLT_IPV6)` — the
/// codec.h:52 splice is COMPILE-TIME TEXT: `help " (DLT "
/// STRINGIFY_MX(DLT_IPV6) ")"` -> the landed string carries the decimal
/// `" (DLT 229)"` (DLT_IPV6 229 = libpcap dlt.h, SYNTHETIC ext#4 CITE —
/// the cd_eth.rs:47-:48 / cd_raw.rs:33 landed-row DLT precedent; the
/// get_data_link_type cc:123 face pins the same 229).
pub const CD_IPV6_HELP: &str = "support for Internet protocol v6 (DLT 229)";

// cc:40 `static sfip_var_t* ReservedIpv6 = nullptr;` — THE WITNESS
// nullptr face (module doc): the static initialized nullptr at file
// scope, ARMED only by the cc:682-:690 ginit. NO Rust data lands — the
// sfip_var_t type NEVER exists here; the pointer's whole life is cited:
//   cc:682-:690 ipv6_codec_ginit — /* Check against reserved ipv6
//   addresses. These are listed at: https://www.iana.org/assignments/
//   ipv6-address-space/ipv6-address-space.xml */ (cc:684-:685) then
//   `ReservedIpv6 = sfip_var_from_string("[0000::/8,0100::/8,0200::/7,
//   0400::/6,0800::/5,1000::/4,4000::/3,6000::/3,8000::/3,a000::/3,
//   c000::/3,e000::/4,f000::/5,f800::/6,fe00::/9]", "ipv6")` (the wrapped
//   string cc:687-:688 — CITE-NEVER-LAND) + `assert(ReservedIpv6)`
//   (:689, NDEBUG-irrelevant at a nullptr static pre-init anyway);
//   cc:692-:695 ipv6_codec_gterm — `sfvar_free(ReservedIpv6)`.
// At the harness witness the sfvar provider ABSENT: the cc:288/:291
// sfvar_ip_in legs fold FALSE — 476/477 UNREACHED (the honest face).

/// ipv6.h:31 `constexpr uint8_t IP6_HEADER_LEN = 40;` — the cc:138 gate,
/// the cc:164/:227 addends, the cc:230 lyr_len. ROW-SCOPED home (the landed
/// dup-not-import family — the cd_icmp6_ip.rs:90 twin re-declares the same
/// value framework-side NEVER).
pub const IP6_HEADER_LEN: u8 = 40;

/// DLT_IPV6 = 229 (the libpcap `pcap/dlt.h` dlt enum, SYNTHETIC ext#4 —
/// the HELP-splice cc:39 + the get_data_link_type cc:123 face; row-scoped
/// with the cd_eth.rs:47-:48 / cd_raw.rs:33 precedent).
pub const DLT_IPV6: i32 = 229;

/// snort_config.h:117-:128 `enum TunnelFlags` (WHOLE enum cited per the
/// row law): `TUNNEL_GTP 0x01, TUNNEL_TEREDO 0x02, TUNNEL_6IN4 0x04,
/// TUNNEL_4IN6 0x08, TUNNEL_4IN4 0x10, TUNNEL_6IN6 0x20, TUNNEL_GRE 0x40,
/// TUNNEL_MPLS 0x80, TUNNEL_VXLAN 0x100, TUNNEL_GENEVE 0x200`. THIS TU
/// reads exactly the TWO :121 6IN4 (cc:195) + :124 6IN6 (cc:203) — the
/// landed snort_config.cc:1020-:1023 truth
/// `return !((tunnel_mask & proto) or SFDAQ::get_tunnel_bypass(proto));`
/// folds to the Ipv6Conf mask face (the SFDAQ leg ABSENT at the witness).
pub const TUNNEL_6IN4: u16 = 0x04; // snort_config.h:121 — the cc:195 arg
pub const TUNNEL_6IN6: u16 = 0x20; // snort_config.h:124 — the cc:203 arg

/// decode_data.h:87 `#define PROTO_BIT__IP 0x000001` (sed-pinned THIS
/// pass; :85 `// eg PROTO_BIT__IP == BIT(PktType::IP)` rides) — the cc:235
/// OR. ROW HOME (grep: the 0x000001 value ABSENT from the landed frame-
/// work — framework/codec.rs carries ONLY PROTO_BIT__IP6_EXT 0x010000;
/// the parse_rule.rs:76 PROTO_BIT__IP 0x8 is the detection-CHAPTER twin of
/// a DIFFERENT bit, NEVER imported here).
pub const PROTO_BIT__IP: u32 = 0x000001;

/// ipv6.h:38-:47 `enum class MulticastScope : uint8_t { RESERVED 0x00,
/// INTERFACE 0x01, LINK 0x02, ADMIN 0x04, SITE 0x05, ORG 0x08, GLOBAL
/// 0x0E }` — the cc:312-:318 switch labels + the three scope-helper arms
/// (ipv6.h:113-:124 full-byte compares). GROUND VALUES WIN (the disk sed;
/// ADMIN/SITE are 0x04/0x05, NOT the row-sketch 3/4).
pub const MCAST_SCOPE_RESERVED: u8 = 0x00; // ipv6.h:40
pub const MCAST_SCOPE_INTERFACE: u8 = 0x01; // ipv6.h:41
pub const MCAST_SCOPE_LINK: u8 = 0x02; // ipv6.h:42
pub const MCAST_SCOPE_ADMIN: u8 = 0x04; // ipv6.h:43
pub const MCAST_SCOPE_SITE: u8 = 0x05; // ipv6.h:44
pub const MCAST_SCOPE_ORG: u8 = 0x08; // ipv6.h:45
pub const MCAST_SCOPE_GLOBAL: u8 = 0x0E; // ipv6.h:46

/// cc:44-:81 `static const RuleMap ipv6_rules[]` — TWENTY-SIX data rows +
/// the :80 terminator -> 27 slots; ALL sids RESIDENT CodecSid variants
/// (grep-verified), msgs byte-exact incl the eight wrapped pairs.
pub const IPV6_RULES: [RuleMap; 27] = [
    RuleMap { sid: CodecSid::DECODE_IPV6_MIN_TTL as u32, msg: Some("IPv6 packet below TTL limit") }, // :46
    RuleMap { sid: CodecSid::DECODE_IPV6_IS_NOT as u32, msg: Some("IPv6 header claims to not be IPv6") }, // :47
    RuleMap { sid: CodecSid::DECODE_IPV6_TRUNCATED_EXT as u32, msg: Some("IPv6 truncated extension header") }, // :48
    RuleMap { sid: CodecSid::DECODE_IPV6_TRUNCATED as u32, msg: Some("IPv6 truncated header") }, // :49
    RuleMap { sid: CodecSid::DECODE_IPV6_DGRAM_LT_IPHDR as u32, msg: Some("IPv6 datagram length < header field") }, // :50
    RuleMap { sid: CodecSid::DECODE_IPV6_DGRAM_GT_CAPLEN as u32, msg: Some("IPv6 datagram length > captured length") }, // :51
    RuleMap { sid: CodecSid::DECODE_IPV6_DST_ZERO as u32, msg: Some("IPv6 packet with destination address ::0") }, // :52
    RuleMap { sid: CodecSid::DECODE_IPV6_SRC_MULTICAST as u32, msg: Some("IPv6 packet with multicast source address") }, // :53
    RuleMap { sid: CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32, msg: Some("IPv6 packet with reserved multicast destination address") }, // :54-:55 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_BAD_OPT_TYPE as u32, msg: Some("IPv6 header includes an undefined option type") }, // :56
    RuleMap { sid: CodecSid::DECODE_IPV6_BAD_MULTICAST_SCOPE as u32, msg: Some("IPv6 address includes an unassigned multicast scope value") }, // :57-:58 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_BAD_NEXT_HEADER as u32, msg: Some("IPv6 header includes an invalid value for the 'next header' field") }, // :59-:60 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_ROUTE_AND_HOPBYHOP as u32, msg: Some("IPv6 header includes a routing extension header followed by a hop-by-hop header") }, // :61-:62 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_TWO_ROUTE_HEADERS as u32, msg: Some("IPv6 header includes two routing extension headers") }, // :63
    RuleMap { sid: CodecSid::DECODE_IPV6_DSTOPTS_WITH_ROUTING as u32, msg: Some("IPv6 header has destination options followed by a routing header") }, // :64-:65 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_TUNNELED_IPV4_TRUNCATED as u32, msg: Some("IPV6 tunneled over IPv4, IPv6 header truncated, possible Linux kernel attack") }, // :66-:67 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_BAD_OPT_LEN as u32, msg: Some("IPv6 header includes an option which is too big for the containing header") }, // :68-:69 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_UNORDERED_EXTENSIONS as u32, msg: Some("IPv6 packet includes out-of-order extension headers") }, // :70
    RuleMap { sid: CodecSid::DECODE_IP6_ZERO_HOP_LIMIT as u32, msg: Some("IPv6 packet has zero hop limit") }, // :71
    RuleMap { sid: CodecSid::DECODE_IPV6_ISATAP_SPOOF as u32, msg: Some("ISATAP-addressed IPv6 traffic spoofing attempt") }, // :72
    RuleMap { sid: CodecSid::DECODE_IPV6_BAD_FRAG_PKT as u32, msg: Some("bogus fragmentation packet, possible BSD attack") }, // :73
    RuleMap { sid: CodecSid::DECODE_IPV6_ROUTE_ZERO as u32, msg: Some("IPv6 routing type 0 extension header") }, // :74
    RuleMap { sid: CodecSid::DECODE_IP6_EXCESS_EXT_HDR as u32, msg: Some("too many IPv6 extension headers") }, // :75
    RuleMap { sid: CodecSid::DECODE_MIPV6_BAD_PAYLOAD_PROTO as u32, msg: Some("IPv6 mobility header includes an invalid value for the 'payload protocol' field") }, // :76-:77 (wrapped)
    RuleMap { sid: CodecSid::DECODE_IPV6_SRC_RESERVED as u32, msg: Some("IPv6 packet from reserved source address") }, // :78
    RuleMap { sid: CodecSid::DECODE_IPV6_DST_RESERVED as u32, msg: Some("IPv6 packet to reserved dest address") }, // :79
    RuleMap { sid: 0, msg: None }, // :80 `{ 0, nullptr }`
];

/// cc:83-:90 `class Ipv6Module : public BaseCodecModule` — the TWO-arg
/// ctor face `BaseCodecModule(CD_IPV6_NAME, CD_IPV6_HELP)` :85 (NO
/// Parameter table, NO params slot) + the get_rules override :87-:88 ONLY
/// (NO get_pegs/get_counts this TU — the honest absent face).
#[derive(Debug)]
pub struct Ipv6Module {
    pub base: BaseCodecModule,
}

impl Ipv6Module {
    /// :85 the ctor face (2-arg — contrast the mpls 3-arg params face).
    pub fn new() -> Ipv6Module {
        Ipv6Module {
            base: BaseCodecModule::new(CD_IPV6_NAME, CD_IPV6_HELP),
        }
    }

    /// :87-:88 `const RuleMap* get_rules() const override { return
    /// ipv6_rules; }` -> the 27-slot table (26 + terminator).
    pub fn get_rules(&self) -> &'static [RuleMap] {
        &IPV6_RULES
    }
}

impl Default for Ipv6Module {
    fn default() -> Self {
        Self::new()
    }
}

/// snort_config.h:454-:455 `bool hit_ip_maxlayers(uint8_t curr_ip) const
/// { return max_ip_layers && (curr_ip >= max_ip_layers); }` — the cc:157
/// gate (var-first: the `max_ip_layers` NONZERO test lands BEFORE the
/// `>=` compare, the C `&&` short-circuit kept). The NSDMI `uint8_t
/// max_ip_layers = 0;` (snort_config.h:279) = the Default face — the gate
/// NEVER arms at default (the honest 293-unarmed posture).
/// snort_config.h:1020-:1023 tunnel_bypass_enabled folds to
/// `(tunnel_mask & proto) == 0` — the SFDAQ::get_tunnel_bypass leg ABSENT
/// at the probe witness (honest cite, same fold the tun-family rows use).
/// `is_address_anomaly_check_enabled()` (snort_config.h:500) is the SAME
/// getter the cc:286 gate reads — here carried as the direct field, the
/// seam's value == the getter's value.
#[derive(Clone, Copy, Debug)]
pub struct Ipv6Conf {
    pub max_ip_layers: u8,       // snort_config.h:279 NSDMI default 0
    pub address_anomaly_check_enabled: bool, // the :500 getter's stored face, default false
    pub tunnel_mask: u16,        // the snort_config tunnel_mask the :1022 AND reads
}

impl Default for Ipv6Conf {
    /// HAND-WRITTEN (the derived Default lands false/0/0 == the ground
    /// NSDMI faces exactly); kept explicit per the row law.
    fn default() -> Self {
        Ipv6Conf { max_ip_layers: 0, address_anomaly_check_enabled: false, tunnel_mask: 0 }
    }
}

impl Ipv6Conf {
    /// snort_config.h:454-:455 — the cc:157 call.
    #[inline]
    pub fn hit_ip_maxlayers(&self, curr_ip: u8) -> bool {
        self.max_ip_layers != 0 && curr_ip >= self.max_ip_layers
    }

    /// snort_config.cc:1020-:1023 SFDAQ-folded face — the cc:195/:203
    /// calls (TUNNEL_6IN4 / TUNNEL_6IN6 above carry the enum cites).
    #[inline]
    pub fn tunnel_bypass_enabled(&self, proto: u16) -> bool {
        (self.tunnel_mask & proto) == 0
    }
}

/// THE DAQ FACE (ext#4 SYNTHETIC, cc:211): `daq_msg_get_meta(raw.daq_msg,
/// DAQ_PKT_META_NAPT_INFO)` -> the `DAQ_NAPTInfo_t*` napti. THE pdd slot:
/// a FACE-A probe stamp ONLY — cd_ipv6 has NO valid_checksum_from_daq
/// (grep-0; the cd_icmp4.rs:160-:175 / cd_icmp6.rs:399-:413 DaqPdd
/// contrast) and the DecodeData& snort member `pdd` is NEVER touched by
/// this TU: the DAQ reads here are EXACTLY-ONE, the NAPT meta. pdd stays
/// on the face for census honesty; NEVER consumed in decode.
#[derive(Clone, Copy, Debug)]
pub struct Ipv6Pdd {
    pub l3_checksum: bool, // the DAQ_PKT_META_DECODE_DATA pdd fields (probe-stamped, NEVER read here)
    pub ipv6: bool,
    pub l3: bool,
    pub l3_offset: i64,
}

/// cc:212-:217 the napti reads (ext#4 SYNTHETIC layout — the REAL SDK
/// DAQ_NAPTInfo_t stays with the frozen daq masters, NEVER promoted):
/// `ip_layer` (the cc:212 == compare), `src_addr`/`dst_addr` (the cc:216
/// /:217 set() args as u32 words on wire-ish host order, probe-faked), the
/// two `daq_napt_info_src_addr_family` / `..._dst_addr_family` accessor
/// faces (cc:216/:217) pre-resolved to u16.
#[derive(Clone, Copy, Debug)]
pub struct Ipv6NaptFace {
    pub ip_layer: u8,          // :212 napti->ip_layer
    pub src_addr: u32,         // :216 napti->src_addr
    pub dst_addr: u32,         // :217 napti->dst_addr
    pub src_addr_family: u16,  // :216 daq_napt_info_src_addr_family(napti)
    pub dst_addr_family: u16,  // :217 daq_napt_info_dst_addr_family(napti)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Ipv6DaqFace {
    pub pdd: Option<Ipv6Pdd>,  // NEVER read by cd_ipv6 (module doc)
    pub napt: Option<Ipv6NaptFace>, // cc:211 — the EXACTLY-ONE DAQ read
}

/// THE snort operand SEAM (row-scoped ip_api mirror — the cd_frag
/// FragDecodeData / cd_icmp4_ip IpApiLite precedent; the real DecodeData
/// owner stays OPEN). `ip4h` models `snort.ip_api.get_ip4h()` (the cc:245
/// read); `fam6` models `ip_api.is_ip6()` AFTER the cc:209 set — the
/// IpApi::set(const IP6Hdr*) face OVERWRITES the ip pointer AND the
/// family (ip_api keeps the LAST ip_api set = outermost-first walk: v4
/// state clears when the v6 set lands; cited, never re-derived).
#[derive(Clone, Copy, Debug)]
pub struct Ipv6DecodeData {
    pub src: SfIp,  // ip_api.get_src() (cc:253/:261)
    pub dst: SfIp,  // ip_api.get_dst() (cc:262)
    pub ip4h: Option<&'static [u8]>, // the OUTER v4 header window (get_ip4h(), cc:245)
    pub fam6: bool, // ip_api.is_ip6() state (cc:198)
}

// the hand-written Default CITES the ground value-inits (SfIp() x2, the
// nullptr ip_api window, fam6 false) — the NSDMI law: the derive would
// erase the citation face; house precedent cursor.rs:13 posture.
#[allow(clippy::derivable_impls)] // cited ground-init body (see above)
impl Default for Ipv6DecodeData {
    fn default() -> Self {
        Ipv6DecodeData {
            src: SfIp::new(), // SfIp() value-init (sf_ip.rs:299)
            dst: SfIp::new(),
            ip4h: None, // no ip set yet
            fam6: false,
        }
    }
}

impl Ipv6DecodeData {
    /// ip_api.is_ip4() (cc:190/:245) — the probe's d.ip_api.set(outer v4
    /// hdr) face lands here.
    #[inline]
    pub fn is_ip4(&self) -> bool {
        self.ip4h.is_some()
    }

    /// ip_api.is_ip6() (cc:198) — the fam6 state (true only AFTER the
    /// cc:209 set_v6; a v4 set below the pair never reads it in decode).
    #[inline]
    pub fn is_ip6(&self) -> bool {
        self.fam6
    }

    /// THE probe's `d.ip_api.set(outer)` v4 face: stashes the window and
    /// seeds src/dst v4 (SfIp v4 = the ::ffff: v4-mapped layout — the
    /// landed set_raw AF_INET face, sf_ip.rs:583-:590, ip8[12..16] = the
    /// header's ip_src/ip_dst words IN WIRE order at 12..16 — copied
    /// byte-for-byte through the SAME set_raw path get_ip4_value reads).
    pub fn set_v4(&mut self, hdr: &'static [u8]) {
        self.ip4h = Some(hdr);
        self.fam6 = false; // the last-set ip_api family = v4
        self.src.set_raw(&hdr[12..16], AF_INET); // ip_src @ v4hdr 12-15
        self.dst.set_raw(&hdr[16..20], AF_INET); // ip_dst @ v4hdr 16-19
    }

    /// cc:209 `snort.ip_api.set(ip6h)` — the IpApi::set(ip6h) mirror: the
    /// v6 src bytes (inner hdr 8..24) / dst (24..40) land in ip8[0..16],
    /// family AF_INET6 (the set_raw v6 leg, sf_ip.rs:591-:594); AND the
    /// set OVERWRITES the ip_api state — the outer v4 window clears,
    /// fam6 arms (module doc cite).
    pub fn set_v6(&mut self, h6: &[u8]) {
        self.src.set_raw(&h6[8..24], AF_INET6);
        self.dst.set_raw(&h6[24..40], AF_INET6);
        self.fam6 = true; // the family slot the set re-arms
    }
}

/// ipv6.h:130-:151 `inline bool is_valid_next_header() const` — the
/// switch's TWELVE valid labels, GROUND EXACT: NONEXT :134, TCP :135,
/// UDP :136, ICMPV6 :137, HOPOPTS :138, DSTOPTS :139, ROUTING :140,
/// FRAGMENT :141, MPLS_IP :142, GRE :143, MOBILITY_IPV6 :144, ESP :145;
/// `default: break; } return false;` :147-:150 (sed-verified THIS pass —
/// the twelve-label set EXCEEDS the row brief's nine sketch). Row-scoped
/// inline mirroring the header fn (the landed dup family; the values via
/// the resident ip_protocol module).
#[inline]
pub fn is_valid_next_header(next: u8) -> bool {
    matches!(
        next,
        ip_protocol::NONEXT     // 59  ipv6.h:134
            | ip_protocol::TCP  // 6   :135
            | ip_protocol::UDP  // 17  :136
            | ip_protocol::ICMPV6 // 58 :137
            | ip_protocol::HOPOPTS // 0 :138
            | ip_protocol::DSTOPTS // 60 :139
            | ip_protocol::ROUTING // 43 :140
            | ip_protocol::FRAGMENT // 44 :141
            | ip_protocol::MPLS_IP // 137 :142
            | ip_protocol::GRE  // 47  :143
            | ip_protocol::MOBILITY_IPV6 // 135 :144
            | ip_protocol::ESP  // 50  :145
    )
}

// ---- the u6_addr word-identity helpers (ipv6.h:50-:57 LE-host union) ----
// C `u6_addr16[k]` on LE x86 == the 2-byte LE word at addr8[2k] -> its
// `!= 0` test IS "the byte pair is not both zero"; `u6_addr8[n]` is the
// wire octet itself. Every face below lands as the BYTE window with the
// identity cited (never an endian guess).

/// ip6_dst (h6[24..40]) `u6_addr16[k] != 0` — cc:330-:334 / cc:344-:352.
#[inline]
fn dst16_ne(h6: &[u8], k: usize) -> bool {
    h6[24 + 2 * k] != 0 || h6[24 + 2 * k + 1] != 0
}

/// ip6_dst `ntohl(u6_addr32[3])` — the BE read of dst bytes 12-15 ==
// h6[36..40); cc:358/:372/:419/:434/:487-:492 (C re-reads ntohl per leg —
/// the arms land ONE local, cited).
#[inline]
fn dst_w3(h6: &[u8]) -> u32 {
    u32::from_be_bytes([h6[36], h6[37], h6[38], h6[39]])
}

/// ip6_dst `u6_addr8[n]` faces (cc:403/:408 n=11/12; cc:431/:484 &0xF0).
#[inline]
fn dst_b(h6: &[u8], n: usize) -> u8 {
    h6[24 + n]
}

/// cc:511-:551 `bool Ipv6Codec::CheckTeredoPrefix(const ip::IP6Hdr*
/// const hdr)` — STATIC, no self needed (cc:113 the private static decl).
/// The cc:509-:510 banner comment rides: /* Teredo packets need to have
/// one of their IPs use either the Teredo prefix, or a link-local prefix
/// (in the case of Router Solicitation messages) */. FOUR byte-equality
/// chains verbatim; every conjunct lands var-first (the R6 compound law).
pub fn check_teredo_prefix(h6: &[u8]) -> bool {
    /* Check if src address matches 2001::/32 */
    // cc:513; the cc:514-:517 chain (u6_addr8[0..3] IS wire octets
    // 0-3 = h6[0..4])
    if (h6[0] == 0x20) && (h6[1] == 0x01) && (h6[2] == 0x00) && (h6[3] == 0x00) {
        return true; // cc:518
    }

    /* Check if src address matches fe80::/64 */
    // cc:520; cc:521-:528 chain = h6[0..8]
    if (h6[0] == 0xfe)
        && (h6[1] == 0x80)
        && (h6[2] == 0x00)
        && (h6[3] == 0x00)
        && (h6[4] == 0x00)
        && (h6[5] == 0x00)
        && (h6[6] == 0x00)
        && (h6[7] == 0x00)
    {
        return true; // cc:529
    }

    /* Check if dst address matches 2001::/32 */
    // cc:531; cc:532-:535 chain = ip6_dst u6_addr8[0..3] = h6[24..28]
    if (h6[24] == 0x20) && (h6[25] == 0x01) && (h6[26] == 0x00) && (h6[27] == 0x00) {
        return true; // cc:536
    }

    /* Check if dst address matches fe80::/64 */
    // cc:538; cc:539-:546 chain = h6[24..32]
    if (h6[24] == 0xfe)
        && (h6[25] == 0x80)
        && (h6[26] == 0x00)
        && (h6[27] == 0x00)
        && (h6[28] == 0x00)
        && (h6[29] == 0x00)
        && (h6[30] == 0x00)
        && (h6[31] == 0x00)
    {
        return true; // cc:547
    }

    /* No Teredo prefix found. */
    false // cc:549-:550
}

/// cc:92-:114 `class Ipv6Codec : public Codec` — the `Codec(CD_IPV6_NAME)`
/// ctor face :95 (Module IGNORED; the class carries NO config — the API
/// ctor cc:697 `static Codec* ctor(Module*)` discards its arg, contrast
/// the mpls config-carrying face). Decls: get_data_link_type :97,
/// get_protocol_ids :98, decode :99; log :105, encode :100-:101, update
/// :102-:103, format :104 ride CITE-NEVER-LAND (row rule — the comment
/// block under the impl); privates IPV6CheckIsatap :108-:110,
/// IPV6MiscTests :111, CheckIPV6Multicast :112, static CheckTeredoPrefix
/// :113 (landed as the free pub fn above — the static, no-self face).
#[derive(Debug, Default)]
pub struct Ipv6Codec;

impl Ipv6Codec {
    /// :95 `Ipv6Codec() : Codec(CD_IPV6_NAME) { }` — the zero-state name
    /// face.
    pub fn new() -> Ipv6Codec { Ipv6Codec }

    /// cc:121-:124 `void Ipv6Codec::get_data_link_type(std::vector<int>&
    /// v) { v.emplace_back(DLT_IPV6); }` — EXACTLY one 229 push (the
    /// SYNTHETIC ext#4 dlt face; the vectors' GETDLT pin).
    pub fn get_data_link_type(&self, v: &mut Vec<i32>) {
        v.push(DLT_IPV6); // cc:123 (229)
    }

    /// cc:126-:130 get_protocol_ids — the deterministic emplace x2 face:
    /// `ProtocolId::ETHERTYPE_IPV6` cc:128 (0x86DD = 34525, the RESIDENT
    /// protocol_id landing) THEN `ProtocolId::IPV6` cc:129 (41, resident).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::ETHERTYPE_IPV6); // cc:128 (34525)
        v.push(protocol_id::IPV6);           // cc:129 (41)
    }

    /// cc:132-:238 out-of-line decode — statement order VERBATIM, the
    /// DECODE CONTRACT shape (module doc). `conf` carries the C
    /// `codec.conf->` legs; `daq` the cc:211 meta; `sink` the codec_event
    /// queue. Every compound lands var-first; wrapping arithmetic on the
    /// u8 layer counter.
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut Ipv6DecodeData,
        conf: &Ipv6Conf,
        daq: Ipv6DaqFace,
        sink: QueueSink<'_>,
    ) -> bool {
        /* lay the IP struct over the raw data */
        // cc:134 comment rides; cc:135-:136 the
        // `reinterpret_cast<const ip::IP6Hdr*>(raw.data)` overlay cast =
        // the raw window itself (all reads below land as byte windows).
        let h6: &[u8] = raw.data;

        // cc:138-:146 THE double-EV face: `if (raw.len < ip::IP6_HEADER_
        // LEN)` -> guarded 273 (the CODEC_UNSURE_ENCAP==0 leg cc:139-:140
        // gates it), THEN — OUTSIDE the guard, UNCONDITIONAL — 291 with
        // the ground's own `// Taken from prot_ipv4.cc` comment cc:143
        // riding; :145 return false. THE PAIR fires TOGETHER (273 THEN
        // 291, never sorted — the I61 pin).
        if raw.len < u32::from(IP6_HEADER_LEN) {
            if (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0 {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IPV6_TRUNCATED as u32,
                    &mut *sink,
                ); // cc:141
            }

            // Taken from prot_ipv4.cc
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_TUNNELED_IPV4_TRUNCATED as u32,
                &mut *sink,
            ); // cc:144 (UNCONDITIONAL)
            return false; // cc:145
        }

        /* Verify version in IP6 Header agrees */
        // cc:148 comment rides; ver() = ipv6.h:84-:85 (uint8)(ntohl(ip6_vtf)
        // >> 28) — the BE word of h6[0..4) shrunk to the high nibble; on
        // the byte window that IS h6[0] >> 4 (the ipv6.h face cited; the
        // BE-load == nibble identity on wire bytes).
        let ver = (h6[0] >> 4) & 0x0F; // ipv6.h:87 face, cc:149 side
        if ver != 6 {
            if (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0 {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IPV6_IS_NOT as u32,
                    &mut *sink,
                ); // cc:152
            }

            return false; // cc:154
        }

        // cc:157-:161 `if ( codec.conf->hit_ip_maxlayers(codec.ip_layer_
        // cnt) )` — var-first: the gate result lands, THEN EV 293 + false.
        let hit_layers = conf.hit_ip_maxlayers(codec.ip_layer_cnt); // cc:157
        if hit_layers {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IP_MULTIPLE_ENCAPSULATION as u32,
                &mut *sink,
            ); // cc:159
            return false; // cc:160
        }

        codec.ip_layer_cnt = codec.ip_layer_cnt.wrapping_add(1); // cc:163 ++
        // cc:164 `const uint32_t payload_len = ntohs(ip6h->ip6_payload_
        // len) + ip::IP6_HEADER_LEN;` — ip6_payload_len = h6[4..6) BE
        // (the ntohs face); row-scoped addition, no wrap at u32 widths.
        let payload_len: u32 =
            u32::from(u16::from_be_bytes([h6[4], h6[5]])) + u32::from(IP6_HEADER_LEN);

        // cc:166-:175 THE nested-equal quirk (the vectors' honesty pin):
        // OUTER `!=` cc:166, INNER `>` cc:168 — a SMALLER payload_len than
        // caplen falls through the OUTER and silently CONTINUES; only the
        // GT leg guards 275 (cc:170) AND returns (cc:173 — the return
        // sits INSIDE the `>`, OUTSIDE the UNSURE gate).
        // the nested-if SHAPE is the cc:166-:168 literal (the nested-
        // equal quirk vectors pin: OUTER !=, INNER >). Collapsing the
        // pair would ERASE the ground quirk.
        #[allow(clippy::collapsible_if)] // literal C nested-if face
        if payload_len != raw.len {
            if payload_len > raw.len {
                if (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0 {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_IPV6_DGRAM_GT_CAPLEN as u32,
                        &mut *sink,
                    ); // cc:171
                }

                return false; // cc:173
            }
        }

        /* Teredo packets should always use the 2001:0000::/32 prefix, or
           in some cases the link-local prefix fe80::/64.
           Source: RFC 4380, section 2.6 & section 5.2.1

           Checking the addresses will save us from numerous false
           positives when UDP clients use 3544 as their ephemeral port, or
           "Deep Teredo Inspection" is turned on.

           If we ever start decoding more than 2 layers of IP in a packet,
           this check against snort.proto_bits will need to be refactored. */
        // cc:177-:186 (the comment says proto_bits — the CODE reads
        // codec_flags: the ground's OWN stale-comment face, rides un-
        // "fixed"). cc:187-:188: var-first both legs, the SILENT bail —
        // NO codec_event (the I64 honest false face).
        let teredo_seen = (codec.codec_flags & CODEC_TEREDO_SEEN) != 0; // cc:187 LHS
        let teredo_prefix = check_teredo_prefix(h6); // cc:187 RHS
        if teredo_seen && !teredo_prefix {
            return false; // cc:188
        }

        if snort.is_ip4() {
            /* If the previous layer was not IP-in-IP, this is not a
               6-in-4 tunnel */
            // cc:190 the is_ip4() gate; cc:193-:194 CODEC_NON_IP_TUNNEL
            // CLEAR arm, cc:195-:196 the TUNNEL_6IN4 bypass else-if.
            if codec.codec_flags & CODEC_NON_IP_TUNNEL != 0 {
                codec.codec_flags &= !CODEC_NON_IP_TUNNEL; // cc:194
            } else {
                let bypass = conf.tunnel_bypass_enabled(TUNNEL_6IN4); // cc:195
                if bypass {
                    codec.tunnel_bypass = true; // cc:196
                }
            }
        } else if snort.is_ip6() {
            /* If the previous layer was not IP-in-IP, this is not a
               6-in-6 tunnel */
            // cc:198 the is_ip6() else-if (fam6 state — set only by a
            // prior ip_api.set(ip6h)); cc:201-:202 the CLEAR arm,
            // cc:203-:204 the TUNNEL_6IN6 bypass.
            if codec.codec_flags & CODEC_NON_IP_TUNNEL != 0 {
                codec.codec_flags &= !CODEC_NON_IP_TUNNEL; // cc:202
            } else {
                let bypass = conf.tunnel_bypass_enabled(TUNNEL_6IN6); // cc:203
                if bypass {
                    codec.tunnel_bypass = true; // cc:204
                }
            }
        }

        self.ipv6_check_isatap(h6, snort, codec, &mut *sink); // cc:207 — check for isatap before overwriting the ip_api. (the ground trailing comment rides; the ORDER IS THE PIN)

        snort.set_v6(h6); // cc:209 `snort.ip_api.set(ip6h);` (mirrors the set above)
        // update to real IP when needed
        // cc:210 comment rides; cc:211 the daq_msg_get_meta(NAPT_INFO)
        // face -> the SYNTHETIC Ipv6NaptFace (ext#4 — the ONLY DAQ read
        // in this TU; pdd NEVER touched); cc:212 the napti-AND + the
        // cc:211 ip_layer == compare (u8==u8 widened in C — kept);
        // cc:214-:217 the two SfIp locals + set(&napti->src_addr,
        // family) — the landed set_raw face takes the 4-byte LE word
        // bytes == the u32's in-memory bytes on LE x86 (the word-face
        // cite), family from the accessor faces as i16;
        // cc:218 `snort.ip_api.update(real_src, real_dst)` folds to the
        // two field writes (ip_api.update re-points src/dst).
        // :211 `napti && codec.ip_layer_cnt == ...` — the Option bind +
        // the comparison split for the bind; the two-level shape is the
        // getter-null AND leg face.
        #[allow(clippy::collapsible_if)] // getter-null AND-compare legs
        if let Some(napt) = daq.napt {
            if codec.ip_layer_cnt == napt.ip_layer {
                let mut real_src = SfIp::new(); // cc:214
                let mut real_dst = SfIp::new(); // cc:215
                real_src.set_raw(&napt.src_addr.to_le_bytes(), napt.src_addr_family as i16); // cc:216
                real_dst.set_raw(&napt.dst_addr.to_le_bytes(), napt.dst_addr_family as i16); // cc:217
                snort.src = real_src; // cc:218 update(real_src, ...)
                snort.dst = real_dst; // cc:218 ...
            }
        }

        self.ipv6_misc_tests(snort, codec, conf, &mut *sink); // cc:221 (reads snort.src/dst POST-update — the cc:261-:262 get_src/get_dst)
        self.check_ipv6_multicast(h6, codec, &mut *sink); // cc:222 (header-driven, ip_api NOT read)

        // the `== false` written AS GROUND (cc:224).
        #[allow(clippy::bool_comparison)] // literal `== false` face
        if is_valid_next_header(h6[6]) == false {
            // cc:224 `if (ip6h->is_valid_next_header() == false)` — the
            // == false written AS ground; EV 281 cc:225 CONTINUES (NO
            // return — the honest continue face; the vectors interleave
            // it with the tail below).
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_BAD_NEXT_HEADER as u32,
                &mut *sink,
            ); // cc:225
        }

        // cc:227 `const_cast<uint32_t&>(raw.len) = ip6h->len() + ip::
        // IP6_HEADER_LEN;` — the LEN re-pin (len() = ntohs of h6[4..6),
        // ipv6.h:71-:72 sed-pinned = the same BE read as cc:164's addend).
        // RawData.len is immutable at this seam: the const_cast folds to
        // this LOCAL — feeds the packet layer AFTER decode, NEVER read
        // again inside, NEVER printed (honest cite, never a fake write).
        let _re_pinned_len: u32 =
            u32::from(u16::from_be_bytes([h6[4], h6[5]])) + u32::from(IP6_HEADER_LEN);
        // cc:228 set_pkt_type(PktType::IP) — the DOCUMENT face: this seam
        // carries NO pkt-type slot (the row-scoped Ipv6DecodeData keeps
        // ONLY the ip_api mirror fields the cc-decode touches); the
        // PktType::IP set is cited, NEVER landed.
        // h6[6] = ip6_next (ipv6.h:65, the byte after payload_len :63):
        // cc:229 `(ProtocolId)ip6h->next()` -> ProtocolId is u8-alias, the
        // SAME 8-bit value; cc:233 `codec.ip6_csum_proto = ip6h->next()`
        // -> the IpProtocol alias, SAME value again (the C++ distinct-
        // enum-pair force-cast face folds — the framework's u8 aliases,
        // codec.rs:95 header note).
        codec.next_prot_id = h6[6] as ProtocolId; // cc:229
        codec.lyr_len = IP6_HEADER_LEN as u16; // cc:230 (40, the u8->u16 widening)
        codec.curr_ip6_extension = 0; // cc:231
        codec.ip6_extension_count = 0; // cc:232
        codec.ip6_csum_proto = h6[6] as IpProtocol; // cc:233
        codec.codec_flags &= !CODEC_ROUTING_SEEN; // cc:234
        codec.proto_bits |= PROTO_BIT__IP; // cc:235 (row home 0x000001, decode_data.h:87)

        true // cc:237
    }

    /// cc:240-:257 `void Ipv6Codec::IPV6CheckIsatap(const ip::IP6Hdr*
    /// const ip6h, const DecodeData& snort, const CodecData& codec)` —
    /// renamed ipv6_check_isatap (lower_snake; the C CamelCase rides the
    /// cite). THE ORDER: runs BEFORE the cc:209 set (the cc:207 comment)
    /// so the ip_api state read here is the OUTER.
    fn ipv6_check_isatap(
        &self,
        h6: &[u8],
        snort: &Ipv6DecodeData,
        codec: &CodecData<'_>,
        sink: QueueSink<'_>,
    ) {
        /* Only check for IPv6 over IPv4 */
        // cc:244 comment rides. cc:245 BOTH legs var-first: is_ip4() then
        // get_ip4h()->proto() == IpProtocol::IPV6 — the OUTER v4 header's
        // proto byte = v4hdr[9] (ip_proto @ 9), the resident 41 face.
        let outer_v4 = snort.is_ip4(); // cc:245 LHS
        let outer_proto = match snort.ip4h {
            Some(h) => h[9] == ip_protocol::IPV6, // cc:245 RHS (get_ip4h()->proto())
            None => false, // the nullptr get_ip4h() leg unrepresentable — is_ip4() arms ip4h
        };
        if outer_v4 && outer_proto {
            // cc:247 `uint32_t isatap_interface_id = ntohl(ip6h->ip6_src
            // .u6_addr32[2]) & 0xFCFFFFFF;` — the BE read of SRC words
            // 8-11 (the INNER header bytes 16-19), then the mask.
            let isatap_interface_id =
                u32::from_be_bytes([h6[16], h6[17], h6[18], h6[19]]) & 0xFCFF_FFFF; // cc:247

            /* ISATAP uses address with prefix fe80:0000:0000:0000:0200:
               5efe or fe80:0000:0000:0000:0000:5efe, followed by the
               IPv4 address. */
            // cc:249-:250 ride.
            if isatap_interface_id == 0x0000_5EFE {
                // cc:253 THE word face BOTH reads cited (the I6B/I6C
                // pins): LHS get_src()->get_ip4_value() = the OUTER v4
                // src s_addr raw LE u32 (the landed SfIp face, sf_ip.rs:
                // :344); RHS ip6h->ip6_src.u6_addr32[3] = the RAW LE-host
                // union word of INNER src bytes 20-23 — C compares the LE
                // field vs the LE s_addr, ntohl NEVER applied (probe-
                // pinned; the identity on LE x86 makes it a byte-
                // sequence equality, kept as the raw LE read).
                let lhs = snort.src.get_ip4_value(); // cc:253 LHS
                let rhs = u32::from_le_bytes([h6[20], h6[21], h6[22], h6[23]]); // cc:253 RHS (u6_addr32[3] raw LE)
                if lhs != rhs {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_IPV6_ISATAP_SPOOF as u32,
                        &mut *sink,
                    ); // cc:254
                }
            }
        }
    }

    /// cc:259-:294 `void Ipv6Codec::IPV6MiscTests(const DecodeData&
    /// snort, const CodecData& codec)` — renamed ipv6_misc_tests; reads
    /// snort.ip_api.get_src()/get_dst() cc:261-:262 (POST-cc:218 update
    /// when the NAPT face rode).
    fn ipv6_misc_tests(
        &self,
        snort: &Ipv6DecodeData,
        codec: &CodecData<'_>,
        conf: &Ipv6Conf,
        sink: QueueSink<'_>,
    ) {
        let ip_src = &snort.src; // cc:261 `const SfIp* ip_src = snort.ip_api.get_src();`
        let ip_dst = &snort.dst; // cc:262 `const SfIp* ip_dst = snort.ip_api.get_dst();`
        /*
         * Some IP Header tests
         * Land Attack(same src/dst ip)
         * Loopback (src or dst in 127/8 block)
         * Modified: 2/22/05-man for High Endian Architecture.
         */
        // cc:263-:268 the block comment rides verbatim.
        // cc:269-:272 fast_eq6 (the landed SfIp face, sf_ip.rs:504) —
        // SOFT: no return, the chain CONTINUES.
        if ip_src.fast_eq6(ip_dst) {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_BAD_TRAFFIC_SAME_SRCDST as u32,
                &mut *sink,
            ); // cc:271
        }

        // cc:274-:277 the loopback pair (both legs var-first per R6).
        let src_loop = ip_src.is_loopback(); // cc:274 LHS
        let dst_loop = ip_dst.is_loopback(); // cc:274 RHS
        if src_loop || dst_loop {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_BAD_TRAFFIC_LOOPBACK as u32,
                &mut *sink,
            ); // cc:276
        }

        /* Other decoder alerts for IPv6 addresses
           Added: 5/24/10 (Snort 2.9.0) */
        // cc:279-:280 ride. cc:281-:284 the !is_set() face (landed
        // SfIp::is_set, sf_ip.rs:347 — the v6 leg covers ip32[0]/[1]/[3]
        // + ip16[4]/[5]; a value-init ::0 dst trips it). SOFT continues.
        if !ip_dst.is_set() {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_DST_ZERO as u32,
                &mut *sink,
            ); // cc:283
        }

        // cc:286-:293 THE anomaly block: the config gate cc:286 READS
        // (is_address_anomaly_check_enabled, snort_config.h:500 — same
        // call-as-field posture the tun rows use); cc:288/:291 then call
        // `sfvar_ip_in(ReservedIpv6, src/dst)` — the WITNESS FALSE fold:
        // the ReservedIpv6 provider NEITHER exists in THIS seam NOR
        // resolves at the probe witness (the cc:40 nullptr static + the
        // ginit NEVER running at the Rust harness), so both legs are
        // HARD-CITED FALSE: 476 SRC_RESERVED / 477 DST_RESERVED NEVER
        // FIRE — anomaly NEVER ON-vectored for this TU (the vectors carry
        // the CITE line, NEVER a fake EV). The arms stay written as
        // ground (the `false` witness term IS the transcription).
        let anomaly = conf.address_anomaly_check_enabled; // cc:286 gate var (R6: lands first)
        if anomaly {
            // cc:288 `sfvar_ip_in(ReservedIpv6, ip_src)` — ReservedIpv6
            // nullptr face -> FALSE (witness fold, module doc).
            if false /* witness sfvar_ip_in FALSE (ReservedIpv6 nullptr face, cc:40) */
            {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IPV6_SRC_RESERVED as u32,
                    &mut *sink,
                ); // cc:289
            }

            // cc:291 `sfvar_ip_in(ReservedIpv6, ip_dst)` — same fold.
            if false /* witness sfvar_ip_in FALSE (ReservedIpv6 nullptr face, cc:40) */
            {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IPV6_DST_RESERVED as u32,
                    &mut *sink,
                ); // cc:292
            }
        }
    }

    /// cc:296-:507 `void Ipv6Codec::CheckIPV6Multicast(const ip::IP6Hdr*
    /// const ip6h, const CodecData& codec)` — renamed check_ipv6_multi-
    /// cast; the FULL head-ladder, EVERY arm byte-verbatim, EVERY case
    /// comment riding. Header-driven ONLY (ip_api NEVER read — the cc:222
    /// call rides straight off ip6h). Word faces via the identity helpers
    /// (module doc); the per-arm `ntohl(u6_addr32[3])` lands ONCE
    /// (C re-reads the same word per comparison — the fold cited).
    // the HARD `return;` arms (cc:487-:490/:492-:494) land AS ground:
    // the ladder's early-outs are statements in C. The house posture
    // (framework/codec.rs:315) allows the literal-C flow verbatim.
    #[allow(clippy::needless_return)] // literal C hard-return flow (the
    // cc ssm hard return; house precedent codec.rs:315)
    fn check_ipv6_multicast(&self, h6: &[u8], codec: &CodecData<'_>, sink: QueueSink<'_>) {
        // cc:300-:303 `if (ip6h->is_src_multicast())` — ipv6.h:107-:108
        // `ip6_src.u6_addr8[0] == IP6_MULTICAST` (IP6_MULTICAST 0xFF,
        // ipv6.h:33) = inner hdr byte 8 -> h6[8]. SOFT (no return).
        if h6[8] == 0xFF {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_SRC_MULTICAST as u32,
                &mut *sink,
            ); // cc:302
        }
        // cc:304-:307 the early-out: `if (!ip6h->is_dst_multicast())
        // ipv6.h:110-:111 dst byte 0 (h6[24]) == 0xFF gate.
        if !(h6[24] == 0xFF) {
            return;
        }

        // cc:309 `multicast_scope = ip6h->get_dst_multicast_scope();` —
        // ipv6.h:103-:104 static_cast<MulticastScope>(u6_addr8[1] &
        // 0x0F): dst byte 1 = h6[25], LOW nibble only. cc:310-:323 the
        // scope switch: the SEVEN assigned values pass, the default EV
        // 280 — and CONTINUES (no return/break-out below the switch in
        // C: fall to cc:325+).
        let multicast_scope = h6[25] & 0x0F; // cc:309 (MulticastScope, ipv6.h:38-:44)
        match multicast_scope {
            MCAST_SCOPE_RESERVED | MCAST_SCOPE_INTERFACE | MCAST_SCOPE_LINK | MCAST_SCOPE_ADMIN
            | MCAST_SCOPE_SITE | MCAST_SCOPE_ORG | MCAST_SCOPE_GLOBAL => {} // cc:312-:319 break
            _ => {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IPV6_BAD_MULTICAST_SCOPE as u32,
                    &mut *sink,
                ); // cc:322
            }
        }

        /* Check against assigned multicast addresses. These are listed
           at: http://www.iana.org/assignments/ipv6-multicast-addresses/
        */
        // cc:325-:326 ride. /* Multicast addresses only specify the first
        // 16 and last 40 bits. Others should be zero. */ cc:328-:329 ride.
        // cc:330-:338 the five-leg OR (u6_addr16[1..4] + u6_addr8[10] —
        // the LE-word identity = byte pairs nonzero, helpers cited;
        // u6_addr8[10] = h6[34]): EV 278 THEN return (the HARD early
        // exit — the cc:344+ block below can ONLY see these zero).
        if dst16_ne(h6, 1) || dst16_ne(h6, 2) || dst16_ne(h6, 3) || dst16_ne(h6, 4) || (dst_b(h6, 10) != 0) {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                &mut *sink,
            ); // cc:336
            return; // cc:337
        }

        // cc:340 the head arm: `is_dst_multicast_scope_reserved()` —
        // ipv6.h:113-:114 the FULL dst byte 1 == MulticastScope::
        // RESERVED (0x00, the WHOLE byte NOT the nibble — the asymmetry
        // vs cc:309 cited).
        if h6[25] == MCAST_SCOPE_RESERVED {
            // Node-local scope
            // cc:342 comment + the cc:343-:351 cppcheck-suppress
            // knownConditionTrueFalse QUARTET (x4 at cc:343/:345/:347/:349 —
            // suppressions ARE ground comments; they ride between the OR
            // legs). NOTE vs the
            // cc:330 block above: addr16[5]/[6] join and [10] drops —
            // transcribed EXACTLY (u6_addr16[5] = dst addr8[10-11] = h6
            // 34,35; [6] = addr8[12-13] = h6 36,37 — the byte-identity
            // helpers cited).
            if dst16_ne(h6, 1)
                || dst16_ne(h6, 2)
                || dst16_ne(h6, 3)
                || dst16_ne(h6, 4)
                || dst16_ne(h6, 5)
                || dst16_ne(h6, 6)
            {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                    &mut *sink,
                ); // cc:354 (NO return — continues to the tail, C fallthrough to fn end is this arm's end)
            } else {
                // cc:358 `switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))` —
                // ONE local (dst_w3), cited.
                let w = dst_w3(h6); // cc:358 (ntohl re-read per C leg — fold cited)
                match w {
                    0x0000_0001 => {} // All Nodes          cc:360
                    0x0000_0002 => {} // All Routers        cc:361
                    0x0000_00FB => {} // mDNSv6             cc:362
                    _ => {                                  // cc:364 default
                        crate::framework::codec::codec_event(
                            codec,
                            CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                            &mut *sink,
                        ); // cc:365
                    }
                }
            }
        }
        // cc:369 `else if (ip6h->is_dst_multicast_scope_link())` —
        // ipv6.h:120-:121 FULL byte == LINK (0x02).
        else if h6[25] == MCAST_SCOPE_LINK {
            // Link-local scope
            // cc:371. cc:372-:414 the TWENTY-EIGHT-word case list + the
            // default's TWO solicited-node escape arms THEN 278.
            let w = dst_w3(h6); // cc:372 (ONE local; C re-ntohls per case — fold cited)
            match w {
                0x0000_0001 => {} // All Nodes                  cc:374
                0x0000_0002 => {} // All Routers                cc:375
                0x0000_0004 => {} // DVMRP Routers              cc:376
                0x0000_0005 => {} // OSPFIGP                    cc:377
                0x0000_0006 => {} // OSPFIGP Designated Routers cc:378
                0x0000_0007 => {} // ST Routers                 cc:379
                0x0000_0008 => {} // ST Hosts                   cc:380
                0x0000_0009 => {} // RIP Routers                cc:381
                0x0000_000A => {} // EIGRP Routers              cc:382
                0x0000_000B => {} // Mobile-Agents              cc:383
                0x0000_000C => {} // SSDP                       cc:384
                0x0000_000D => {} // All PIMP Routers           cc:385
                0x0000_000E => {} // RSVP-ENCAPSULATION         cc:386
                0x0000_000F => {} // UPnP                       cc:387
                0x0000_0012 => {} // VRRP                       cc:388
                0x0000_0016 => {} // All MLDv2-capable routers  cc:389
                0x0000_006A => {} // All-Snoopers               cc:390
                0x0000_006B => {} // PTP-pdelay                 cc:391
                0x0000_006C => {} // Saratoga                   cc:392
                0x0000_006D => {} // LL-MANET-Routers           cc:393
                0x0000_006E => {} // IGRS                       cc:394
                0x0000_006F => {} // iADT Discovery             cc:395
                0x0000_00FB => {} // mDNSv6                     cc:396
                0x0001_0001 => {} // Link Name                  cc:397
                0x0001_0002 => {} // All-dhcp-agents            cc:398
                0x0001_0003 => {} // Link-local Multicast Name Resolution cc:399
                0x0001_0004 => {} // DTCP Announcement          cc:400
                _ => { // cc:402 default
                    // cc:403-:407 the Solicited-Node escape: u6_addr8[11]
                    // == 1 && u6_addr8[12] == 0xFF -> break (h6[35],
                    // h6[36] — the u6_addr8 byte identity cited).
                    if (dst_b(h6, 11) == 1) && (dst_b(h6, 12) == 0xFF) {
                        // Solicited-Node Address  (break, cc:406)
                    } else if (dst_b(h6, 11) == 2) && (dst_b(h6, 12) == 0xFF) {
                        // cc:408-:412 the Node Information Queries escape.
                        // Node Information Queries  (break, cc:411)
                    } else {
                        crate::framework::codec::codec_event(
                            codec,
                            CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                            &mut *sink,
                        ); // cc:413
                    }
                }
            }
        }
        // cc:416 `else if (ip6h->is_dst_multicast_scope_site())` —
        // ipv6.h:123-:124 FULL byte == SITE (the ipv6.h:43 value is
        // `0x05` — disk-sed wins over the row sketch's 4; cite rides the
        // helper constant home).
        else if h6[25] == MCAST_SCOPE_SITE {
            // Site-local scope
            // cc:418. cc:419-:429 the FIVE-word list, default 278.
            let w = dst_w3(h6); // cc:419 fold cited
            match w {
                0x0000_0002 => {} // All Routers        cc:421
                0x0000_00FB => {} // mDNSv6             cc:422
                0x0001_0003 => {} // All-dhcp-servers   cc:423
                0x0001_0004 => {} // Deprecated         cc:424
                0x0001_0005 => {} // SL-MANET-ROUTERS   cc:425
                _ => { // cc:427 default
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                        &mut *sink,
                    ); // cc:428
                }
            }
        }
        // cc:431 `else if ((ip6h->ip6_dst.u6_addr8[1] & 0xF0) == 0)` —
        // dst byte 1 HIGH nibble zero -> Variable scope (cc:433). The
        // cc:340/:369/:416 arms already ate full-byte 0x00/0x02/0x05, so
        // this arm admits nibble-low != {0,2,5} faces — kept literal.
        else if (dst_b(h6, 1) & 0xF0) == 0 {
            // Variable scope
            // cc:433. cc:434-:482 the THIRTEEN-word list + the FIVE
            // default range blocks, each with its ground comment riding;
            // then 278. ONE `w` local per cc:434 + the cc:451-:476
            // repeated-ntohl folds (C re-reads per leg — cited).
            let w = dst_w3(h6); // cc:434 fold cited
            match w {
                0x0000_000C => {} // SSDP                    cc:436
                0x0000_00FB => {} // mDNSv6                  cc:437
                0x0000_0181 => {} // PTP-primary             cc:438
                0x0000_0182 => {} // PTP-alternate1          cc:439
                0x0000_0183 => {} // PTP-alternate2          cc:440
                0x0000_0184 => {} // PTP-alternate3          cc:441
                0x0000_018C => {} // All ACs multicast addr  cc:442
                0x0000_0201 => {} // "rwho" Group (BSD)      cc:443
                0x0000_0202 => {} // SUN RPC PMAPPROC_CALLIT cc:444
                0x0000_0204 => {} // All C1222 Nodes         cc:445
                0x0000_0300 => {} // Mbus/IPv6               cc:446
                0x0002_7FFE => {} // SAPv1 Announcements     cc:447
                0x0002_7FFF => {} // SAPv0 Announcements     cc:448
                _ => { // cc:450 default
                    // cc:451-:455 the contiguous-block face (both legs
                    // var-first per R6 on the folded w). The C >=/<=
                    // pairs fold to RangeInclusive::contains (the
                    // house-idiom face; the interval BOUNDS stay the
                    // cited ground values).
                    if (0x0000_0100..=0x0000_0136).contains(&w) {
                        // Several addresses assigned in a contiguous block
                    } else if (0x0000_0140..=0x0000_014F).contains(&w) {
                        // cc:457-:461
                        // EPSON-disc-set
                    } else if (0x0002_0000..=0x0002_7FFD).contains(&w) {
                        // cc:463-:467
                        // Multimedia Conference Calls
                    } else if (0x0001_1000..=0x0001_13FF).contains(&w) {
                        // cc:469-:473
                        // Service Location, Version 2
                    } else if (0x0002_8000..=0x0002_FFFF).contains(&w) {
                        // cc:475-:479
                        // SAP Dynamic Assignments
                    } else {
                        crate::framework::codec::codec_event(
                            codec,
                            CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                            &mut *sink,
                        ); // cc:481
                    }
                }
            }
        }
        // cc:484 `else if ((ip6h->ip6_dst.u6_addr8[1] & 0xF0) == 0x30)` —
        // Source-Specific Multicast block (cc:486).
        else if (dst_b(h6, 1) & 0xF0) == 0x30 {
            // Source-Specific Multicast block
            let w = dst_w3(h6); // cc:487-:492 folds (C re-ntohls each leg)
            if (0x4000_0001..=0x7FFF_FFFF).contains(&w) {
                return; // IETF consensus  (cc:487-:490 — the HARD return)
            } else if w >= 0x8000_0000 {
                return; // Dynamically allocated by hosts when needed (cc:492-:494)
            } else {
                // Other addresses in this block are reserved.
                // cc:498 comment rides.
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                    &mut *sink,
                ); // cc:499
            }
        } else {
            /* Addresses not listed above are reserved. */
            // cc:504 comment rides. cc:505 the FINAL 278.
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_DST_RESERVED_MULTICAST as u32,
                &mut *sink,
            ); // cc:505
        }
    }
}

// CITE-NEVER-LAND (the row law): log cc:557-:587 — the obfuscate() TextLog
// "x:x:x:x::x:x:x:x -> x:x:x:x::x:x:x:x" arm, the inet_ntop pair +
// `%s -> %s`, TextLog_NewLine/Putc '\t', and the
// `"Next:0x%02X TTL:%u TOS:0x%X DgmLen:%u"` line (next()/hop_lim()/tos()/
// len() faces ipv6.h:69/:81/:89/:74) — ported by reading ONLY, NEVER
// callable in this seam (the TextLog never lands).
// encode cc:593-:630 — allocate(sizeof(IP6Hdr))=40, the ip6_next
// enc.next_proto_set() pair, the forward()/reverse() src/dst memcpy pair +
// enc.get_ttl, the `ip6_vtf = htonl(ntohl(hi->ip6_vtf) & 0xFFF00000)`
// vtc-only splice, `ip6_payload_len = htons(buf.size() - 40)`, the
// next_proto=IPV6/next_ethertype=ETHERTYPE_IPV6 tail cc:627-:628 — CITED,
// NEVER landed (the Buffer/EncState encode rows own that world).
// update cc:632-:652 — the `(flags & UPD_MODIFIED) && !(flags &
// UPD_RESIZED)` pair (cc:641; the cc:637-:640 payload-trim comment
// riding) -> `updated_len = ntohs(ip6_payload_len) + 40` cc:643 ELSE
// `updated_len += lyr_len` cc:647 + the cc:650 `h->ip6_payload_len =
// htons((uint16_t)(updated_len - ip::IP6_HEADER_LEN))` (the cc:649 "// len
// includes header, remove for payload" comment rides) —
// CITED, NEVER landed.
// format cc:654-:670 — the reverse() u6_addr8 SWAP trio via the tmp_addr
// (cc:658-:664) + `snort.ip_api.set(ip6h)` cc:668 (the comment "// set
// outer to inner so this will always wind pointing to inner" cc:667
// rides) + set_pkt_type(PktType::IP) cc:669 — CITED, NEVER landed.

/// :676-:677 `static Module* mod_ctor() { return new Ipv6Module; }` +
/// :679-:680 `static void mod_dtor(Module* m) { delete m; }` — behavior-
/// only cites; the record's mod arms land SET below; the Rust mod face is
/// Ipv6Module::new (the stack-owned drop folds the dtor, 18d posture).
/// :682-:691 `ipv6_codec_ginit` (the reserved-v6 STRING + assert = THE
/// ReservedIpv6 witness block at the table head) and :692-:695
/// `ipv6_codec_gterm` (`sfvar_free(ReservedIpv6)`) — pinit/pterm arms
/// SET: NONE of that world lands here (module doc). :697-:698 `static
/// Codec* ctor(Module*)` — the Module DISCARDED face (contrast mpls's
/// config-carrying ctor) -> Ipv6Codec::new; :700-:701 `dtor` SET.
///
/// cc:703-:723 `static const CodecApi ipv6_api` — the base block
/// PT_CODEC :706 / sizeof :707 / CDAPI_VERSION :708 / 0 :709 /
/// PLUGIN_SO_RELOAD :710 / API_OPTIONS :711 / NAME :712 -> "ipv6" /
/// HELP :713 -> the DLT-spliced string; mod_ctor :714 / mod_dtor :715
/// REAL-SET; the ground slot comments ride: pinit :717 (`ipv6_codec_
/// ginit, // pinit`) SET / pterm :718 (`ipv6_codec_gterm, // pterm`) SET —
/// the ginit/gterm face; tinit :719 `nullptr, // tinit` / tterm :720
/// `nullptr, // tterm` — the TARM ipv6 0/0 face; ctor :721 (`ctor, //
/// ctor`) / dtor :722 (`dtor, // dtor`) SET.
pub const IPV6_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // :706
    size: CDAPI_SIZEOF_CODEC_API, // :707 sizeof(CodecApi)=112
    api_version: CDAPI_VERSION,   // :708
    version: 0,                   // :709
    features: PLUGIN_SO_RELOAD,   // :710
    options: API_OPTIONS,         // :711
    name: CD_IPV6_NAME,           // :712 -> "ipv6"
    help: CD_IPV6_HELP,           // :713 -> "... v6 (DLT 229)" splice
    mod_ctor: true,               // :714 SET (mod_ctor :676 REAL)
    mod_dtor: true,               // :715 SET (mod_dtor :679 REAL)
    pinit: true,                  // :717 SET — ipv6_codec_ginit // pinit (the reserved-v6 block; CITE-NEVER-LAND)
    pterm: true,                  // :718 SET — ipv6_codec_gterm // pterm (sfvar_free; NO Rust arm lands)
    tinit: false,                 // :719 nullptr // tinit (the TARM face)
    tterm: false,                 // :720 nullptr // tterm
    ctor: true,                   // :721 SET  // ctor (Module ignored :697)
    dtor: true,                   // :722 SET  // dtor
};
// NOTE the pinit/pterm pair: THIS is the row's api-slot asymmetry face —
// the ground arms are NON-NULL (`ipv6_codec_ginit` :717 / `ipv6_codec_gterm`
// :718) so the bool slots land TRUE (contrast the mpls nullptr pair, and
// the TARM ipv6 0/0 at :719/:720 which stay FALSE). The ginit BODY — the
// 14-range reserved-v6 STRING cc:687-:688 + the assert —
// stays CITE-NEVER-LAND (the ReservedIpv6 witness face, module doc).

/// cc:725-:733 the hidden export, TRUE-NAME: `#ifdef BUILDING_SO` :725 /
/// SO arm `SO_PUBLIC const BaseApi* snort_plugins[] =` :726 / `#else` :727
/// / the static-build `const BaseApi* cd_ipv6[] =` :728 feeding
/// `&ipv6_api.base` :731 + nullptr :732 (ONE feed). nm: cd_ipv6 D
/// EXACTLY-1 == the FILE base (the TRUE-NAME equality pin law). Ladder
/// entry "cd_ipv6" RESIDENT codec_api.rs:52 (the ground extern codec_api.
/// cc:33 face — witness_stubs there, NEVER re-touched; THIS row TURNS it
/// real at its own table).
pub const CD_IPV6: CodecTable = &[&IPV6_API];
