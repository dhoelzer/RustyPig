//! Port of `src/codecs/ip/cd_icmp6.cc` (518 L) — row 18i, the THIRD arm of
//! the `tools/daq3_harness` ZERO-gate probe-only DAQ trio (ip/cd_udp.cc 660
//! \+ cd_icmp4.cc 645 + cd_icmp6.cc 518 = 1,823 L). Ground: snort3-src @
//! fe29cbe, md5 `778157526e26f194e8ca832290ce164e`, wc 518 (every build).
//! DIR FACT: `codecs/ip/`; the TU includes <daq.h> (cc:25) + codec_module/
//! codec/text_log/snort_config/icmp6.h/icmp4.h/util/checksum (cc:27-:35) —
//! THE ROW'S CROSS-RIDER FACT: `#include "protocols/icmp4.h"` rides at
//! cc:32 (sed-pin) and the ONLY icmp4.h struct dependence is the
//! `sizeof(ICMPHdr::icmp_hun.idseq)` gate operand at cc:224 — the pair of
//! u16 slots id/seq (icmp4.h:131-:135) = 4 bytes, nothing else from
//! icmp4.h (the log/format faces are icmp6's own).
//!
//! THE NAME-DRIFT HEADLINE (the row's rider, the 18h cd_auth precedent
//! RE-RIDDEN with the drift on the API-STRUCT slot instead of the table):
//!   file base      `cd_icmp6`   (cd_icmp6.cc — the Rust file base stays
//!                                TRUE, cd_icmp6.rs; mod.rs already
//!                                declares it)
//!   TABLE name     `cd_icmp6[]` cc:513 (REAL BUILDING_SO arms :510-:518)
//!   extern         `cd_icmp6`   ladder entry codec_api.rs:114 (RESIDENT,
//!                                NEVER touched; the dormant STATIC census)
//!   NAME macro     `CD_ICMP6_NAME "icmp6"` cc:39 -> `LOAD icmp6`
//!                                (vectors_faceA:3) / `API icmp6 ...
//!                                name=icmp6` (:11) / RULES `name=icmp6`
//!                                (vectors:93)
//!   api struct     `ipv6_api`   cc:488  <-- THE DRIFT: the C record
//!                                identifier is `ipv6_api` while the file
//!                                is cd_icmp6.cc, the table is cd_icmp6
//!                                and the NAME slot carries "icmp6". The
//!                                table feeds `&ipv6_api.base` (cc:516).
//! Following the cd_auth.rs precedent (file base TRUE: AH_API carries the C
//! STRUCT name ah_api), the Rust record const lands as `IPV6_API` — THE
//! C STRUCT NAME LANDS. NO Rust identifier with the file-base-plus-api
//! spelling ("icmp6" + the api suffix, the token the src/ grep tripwires)
//! exists ANYWHERE and ground-side that grep is a 0-HIT (grep -rn verified
//! THIS pass @ fe29cbe = 0 matches): the drift is FALSE-CLEAN to that grep
//! — the tripwire keys on the `ipv6_api` <-> `cd_icmp6` <-> "icmp6" TRIPLE
//! (build.sh keeps `drift_ipv6_api_face.txt` EMPTY by grepping the whole
//! src/ for that forbidden spelling — the token must NEVER appear ANYWHERE
//! in this file either, doc prose INCLUDED, the 18h drift-extern face). The probe prints the table/NAME face
//! ONLY — `// the ipv6_api :488 struct name DOES NOT APPEAR in any
//! printout -- table cd_icmp6 NAME icmp6 face, the drift rider ride`
//! (probe_dec.cc:179-:181): vectors:93 `ICMP6RULES 13 sid0=427
//! name=icmp6` + ICMP6 faceA `API icmp6 type=0 size=112 ver=1900547
//! name=icmp6` + HELP `support for Internet control message protocol v6`
//! (cc:40).
//!
//! THE DAQ GRAFT SEAM (the trio's first-ever daq_msg witnesses; SYNTHETIC,
//! the 17d left-open seam — plan row 20 = real DAQ): ground
//! valid_checksum_from_daq (cc:123-:138, inline static) reads
//! `daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA)` (cc:125-:126)
//! \+ `daq_msg_get_data` (cc:132) off the graft copy/daq.h (md5
//! 73fdbc3983ca45246b554c46efdf1ad1, SYNTHETIC; `DAQ_PKT_DECODE_OFFSET_
//! INVALID (-1)` graft :15; `struct _daq_msg;` fwd = framework/codec.h :38
//! face). Gate site cc:197 `snort::get_network_policy()->icmp_checksums()
//! && !valid_checksum_from_daq(raw)` — the NetworkPolicy::icmp_checksums
//! param + DaqFace bundle ride the cd_icmp4.rs shape EXACTLY (the trio
//! parity rule: identical seam faces across the three files). The ICMP6
//! guard face cc:127 reads l4_checksum/icmp/l4 — the `.udp` bit exists on
//! the graft face and is NEVER read by this TU (the udp twin reads it; the
//! field stays for graft fidelity). The `raw.data - data` compare (cc:133)
//! folds to the DaqFace.payload_delta param (probe-faked pointer quantity;
//! NEVER ABI truth, R1).
//!
//! PEGS cite-never-land (the cc:44-:57 PegInfo/Stats/THREAD_LOCAL blocks +
//! the get_pegs/get_counts overrides cc:93-:97): the rows ride THIS
//! comment — CountType::SUM `bad_icmp6_checksum` "nonzero icmp6 checksums"
//! (cc:46) / SUM `checksum_bypassed` "checksum calculations bypassed"
//! (cc:47) / END terminator (cc:48); Stats { bad_ip6_cksum, cksum_bypassed
//! } cc:51-:55 over `static THREAD_LOCAL Stats stats` cc:57. The
//! `stats.bad_ip6_cksum++` (cc:211) and `stats.cksum_bypassed++` (cc:136)
//! increments are CITE-NEVER-LAND (NO Rust counters; the counters never
//! surface in any vectors line — vectors:69 `ICMP6 cksumbad-daqvalid -> 1
//! dflags=0 lyr=8` prints only the observable faces; the small4 pgm
//! tri-state precedent, R2 cite-never-vectorize).
//!
//! ROW CENSUS (14-unique-event vs 13-rule-row, the cc:59-:82 contrast):
//! icmp6_rules carries 13 rows + `{ 0, nullptr }` (cc:82) — vectors:93
//! `ICMP6RULES 13 sid0=427 first-name row TRUNC 427` — while the probe
//! arms fire FOURTEEN unique event names: the thirteen rule sids PLUS
//! DECODE_ICMP_DGRAM_LT_ICMPHDR 105, which the switch short-dgram arms
//! fire NINE times (cc:233/:251/:274/:295/:316/:331/:346/:360/:377) but
//! which has NO icmp6_rules row. The probe comment "daq face + 14 unique
//! names" (probe_dec.cc:179) pins the census.
//!
//! THE 21-TYPE RECOGNIZE-NO-EVENT LIST (cc:382 comment "recognize these so
//! we don't alert but no further checking (yet)" + the 21 bare cases
//! cc:383-:403, all break-no-event): MULTICAST_LISTENER_QUERY/REPORT/DONE,
//! INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION/ADVERTISEMENT,
//! VERSION_2_MULTICAST_LISTENER_REPORT, HOME_AGENT_ADDRESS_DISCOVERY_
//! REQUEST/REPLY, MOBILE_PREFIX_SOLICITATION/ADVERTISEMENT,
//! CERTIFICATION_PATH_SOLICITATION/ADVERTISEMENT, MULTICAST_ROUTER_
//! ADVERTISEMENT/SOLICITATION/TERMINATION, FMIPV6, RPL_CONTROL,
//! ILNPV6_LOCATOR_UPDATE, DUPLICATE_ADDRESS_REQUEST/CONFIRMATION,
//! MPL_CONTROL — exactly 21 enum values (h:52-:54 + h:62-:79); with the
//! 13 checked arms they cover all 34 Icmp6Types enumerators exactly once.
//!
//! VECTORS ANCHORS (tools/daq3_harness/vectors.txt :64-:93, the ICMP6
//! block; the arms are the probe faces probe_dec.cc:179-:235 — mirror
//! statement order/semantics exactly): :64-:65 `EV 116 427` + `short3 ->
//! 0` (cc:183 MIN_LEN 4 gate); :66-:67 `EV 116 474` + `noip6 -> 0`
//! (cc:189-:191 the get_ip6h() None face); :68 `cksumbad-daqoff -> 0
//! dflags=8` (DAQ-OFF fold-invalid -> DECODE_ERR_CKSUM_ICMP, the gate
//! rides NetworkPolicy::default(), policy.h :211-:212 + :233); :69
//! `cksumbad-daqvalid -> 1 dflags=0 lyr=8` (same packet, pdd-valid -> the
//! checksum leg SKIPPED, cksum_bypassed PEG cite-only); :70-:71 `EV 116
//! 432` + `mcast -> 1` (ip6 dst byte0 0xFF, ipv6.h:33/:111); :72-:73
//! `EV 116 285` + `toobig1024 -> 1 lyr=8 next=260` (0x0104 = 260,
//! protocol_ids.h:131); :74-:75 `EV 116 286` unreach code==2; :76-:77
//! `EV 116 457` code 7 > 6; :78-:80 `EV 116 287` + `EV 116 289` rs-bad
//! (code!=0 then reserved!=0 — BOTH events on one packet, order kept);
//! :81-:83 `EV 116 288` + `EV 116 290` ra-bad (reachable_time 0xFFFFFFFF
//! \> 3600000); :84-:85 `EV 116 478` ra-zerolen (NDP walk cc:171-:175);
//! :86-:87 `EV 116 460` nodeinfo3; :88-:89 `EV 116 105` + `toobig6 -> 0`
//! (dsize 2 < sizeof(ICMP6TooBig)=8); :90-:91 `EV 116 431` type200
//! default; :92 `ICMP6PID 58 n=1`. faceA :3 `LOAD icmp6` / :11 API / :13
//! `icmp6 mod_ctor=1 mod_dtor=1` (all four ctor slots SET, cc:499/:500/
//! :506/:507 record faces; pinit/pterm/tinit/tterm nullptr cc:502-:505).

use crate::codecs::checksum::{icmp_cksum_v6, Pseudoheader6};
use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecData, CodecTable, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    EncodeFlags, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData, ip_protocol,
    protocol_id, UPD_COOKED, UPD_REBUILT_FRAG,
};
use crate::main::policy::NetworkPolicy;

/// cc:39 `#define CD_ICMP6_NAME "icmp6"` — THE NAME side of the drift
/// triple (module doc): printed/API name everywhere the walk looks.
pub const CD_ICMP6_NAME: &str = "icmp6";
/// cc:40 `#define CD_ICMP6_HELP "support for Internet control message
/// protocol v6"` (faceA :12 HELP line).
pub const CD_ICMP6_HELP: &str = "support for Internet control message protocol v6";

// ============================================================================
// Row-scoped numerics (the cd_gre PROTOCOL_ID_ETHERTYPE_PPP / cd_teredo
// PROTOCOL_ID_TEREDO precedent; framework files byte-UNTOUCHED). Every
// value grep-pinned THIS pass against the ground headers @ fe29cbe.
// ============================================================================

/// icmp6.h:29 `constexpr uint16_t ICMP6_HEADER_MIN_LEN = 4` — the cc:183
/// trunc gate, the cc:217 dsize delta and the cc:144 walk base.
pub const ICMP6_HEADER_MIN_LEN: u16 = 4;
/// icmp6.h:30 `constexpr uint16_t ICMP6_HEADER_NORMAL_LEN = 8` — the
/// ECHO/PACKET_TOO_BIG/embedded arms' `len =` writes (cc:226/:246/:269);
/// the vectors:69 `lyr=8` + :73 `lyr=8` face.
pub const ICMP6_HEADER_NORMAL_LEN: u16 = 8;

/// icmp6.h:32 `#define ICMPv6_NS_MIN_LEN 24` (the cc:322 dsize delta
/// 24-4=20 and the cc:327 min_len arg).
pub const ICMPV6_NS_MIN_LEN: u16 = 24;  // rustc naming face of the C macro (doc lines keep the C spelling)
/// icmp6.h:33 `#define ICMPv6_NA_MIN_LEN 24` (cc:337 delta, cc:342 arg).
pub const ICMPV6_NA_MIN_LEN: u16 = 24;
/// icmp6.h:34 `#define ICMPv6_RS_MIN_LEN 8` (cc:280 delta 8-4=4, cc:291
/// arg; the walk's option_field_not_exists face for the 8-byte RS,
/// vectors:78-:80).
pub const ICMPV6_RS_MIN_LEN: u16 = 8;
/// icmp6.h:35 `#define ICMPv6_RA_MIN_LEN 16` (cc:301 delta 16-4=12,
/// cc:312 arg — the ra-zerolen walk base, vectors:84-:85).
pub const ICMPV6_RA_MIN_LEN: u16 = 16;
/// icmp6.h:36 `#define ICMPv6_RD_MIN_LEN 40` (cc:352 delta 40-4=36,
/// cc:356 arg).
pub const ICMPV6_RD_MIN_LEN: u16 = 40;

/// Sizes of the two sizeof-driven switch gates, read off the icmp6.h
/// struct layouts: `sizeof(icmp::ICMP6TooBig)` = 8 (h:109-:115, 1+1+2+4,
/// align 4 — the probe comment "sizeof(ICMP6TooBig)=8" probe_dec.cc:203;
/// the cc:239 gate) and `sizeof(icmp::ICMP6NodeInfo)` = 16 (h:147-:155,
/// 1+1+2+2+2 with u64 nonce @8, align 8 — the cc:367 gate 16-4=12).
pub const ICMP6_TOO_BIG_SIZE: u16 = 8;
pub const ICMP6_NODE_INFO_SIZE: u16 = 16;

/// THE CROSS-RIDER SIZE FACE (module doc; the ONLY icmp4.h struct
/// dependence in the TU): `sizeof(ICMPHdr::icmp_hun.idseq)` = 4 — the
/// pair of u16 slots id/seq, icmp4.h:131-:135 — the cc:224 ECHO gate
/// `dsize >= 4`.
pub const ICMP4_IDSEQ_SIZE: u16 = 4;

/// protocol_ids.h:131 `IP_EMBEDDED_IN_ICMP6 = 0x0104` (== 260) — the
/// PACKET_TOO_BIG cc:247 and embedded-group cc:270 next_prot_id writes;
/// vectors:73 `next=260`. Row-scoped const per the cd_grep cd_gre.rs
/// PROTOCOL_ID_* precedent (the landed protocol_id mod has NO slot for
/// it — cd_icmp4.rs keeps IP_EMBEDDED_IN_ICMP4 row-scoped the same way).
pub const PROTOCOL_ID_IP_EMBEDDED_ICMP6: ProtocolId = 0x0104;

/// decode_data.h:90 `#define PROTO_BIT__ICMP 0x000008` — the cc:412 tail
/// proto_bits write.
pub const PROTO_BIT__ICMP: u32 = 0x000008;

/// decode_data.h:134 `DECODE_ERR_CKSUM_ICMP = 0x00000008` — the cc:212
/// `snort.decode_flags |=` write; vectors:68 `dflags=8`.
pub const DECODE_ERR_CKSUM_ICMP: u64 = 0x00000008;

/// decode_data.h:45-:48 `enum class PktType : uint8_t { NONE, IP, TCP,
/// UDP, ICMP, ... }` — ICMP is the 4th enumerator (0-based -> 4); the
/// cc:414/:469 `set_pkt_type(PktType::ICMP)` face (the cd_icmp4.rs
/// PKT_TYPE__ICMP twin — trio seam parity).
pub const PKT_TYPE__ICMP: u8 = 4;

/// ipv6.h:33 `constexpr uint8_t IP6_MULTICAST = 0xFF; // first/most
/// significant octet` — the is_dst_multicast test octet (ipv6.h:111
/// `ip6_dst.u6_addr8[0] == IP6_MULTICAST` via get_dst(), :99-:101); the
/// cc:228-:229 arm, vectors:70-:71 `EV 116 432`.
pub const IP6_MULTICAST: u8 = 0xFF;

/// icmp6.h:44-:80 `enum Icmp6Types : std::uint8_t` — ALL THIRTY-FOUR
/// enumerators land as u8 consts (NOT a Rust enum — the C enum is plain
/// and the switch discriminates raw; the cd_icmp4.rs icmp_type mod
/// precedent). COUNT PINNED THIS PASS: grep of the enumerator lines
/// h:46-:79 = THIRTY-FOUR declarations (4 + 10 + 11 + 9 — the enum skips
/// 138 and 150; the sheet-side "35" is a miscount, the measured truth is
/// 34). The cc:220 switch discriminates 13 (ECHO pair, PACKET_TOO_BIG,
/// the TIME_EXCEEDED6/PARAMETER_PROBLEM/DESTINATION_UNREACHABLE trio,
/// RS/RA/NS/NA/RD, the NODE_INFO pair); the cc:383-:403 recognize block
/// carries the remaining 21 as bare no-event breaks — 13 + 21 = 34:
/// EVERY enumerator is touched exactly once; every value grep-pinned at
/// h:46-:79.
pub mod icmp6_type {
    pub const DESTINATION_UNREACHABLE: u8 = 1; // h:46
    pub const PACKET_TOO_BIG: u8 = 2;          // h:47
    pub const TIME_EXCEEDED6: u8 = 3;          // h:48
    pub const PARAMETER_PROBLEM: u8 = 4;       // h:49
    pub const ECHO_REQUEST: u8 = 128;          // h:50  (cc:222 case)
    pub const ECHO_REPLY: u8 = 129;            // h:51  (cc:223 case)
    pub const MULTICAST_LISTENER_QUERY: u8 = 130;        // h:52 (cc:383)
    pub const MULTICAST_LISTENER_REPORT: u8 = 131;       // h:53 (cc:384)
    pub const MULTICAST_LISTENER_DONE: u8 = 132;         // h:54 (cc:385)
    pub const ROUTER_SOLICITATION: u8 = 133;             // h:55 (cc:279)
    pub const ROUTER_ADVERTISEMENT: u8 = 134;            // h:56 (cc:300)
    pub const NEIGHBOR_SOLICITATION: u8 = 135;           // h:57 (cc:321)
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;          // h:58 (cc:336)
    pub const REDIRECT6: u8 = 137;                       // h:59 (cc:351)
    pub const NODE_INFORMATION_QUERY: u8 = 139;          // h:60 (cc:365)
    pub const NODE_INFORMATION_RESPONSE: u8 = 140;       // h:61 (cc:366)
    pub const INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION: u8 = 141;    // h:62 (cc:386)
    pub const INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT: u8 = 142;   // h:63 (cc:387)
    pub const VERSION_2_MULTICAST_LISTENER_REPORT: u8 = 143;        // h:64 (cc:388)
    pub const HOME_AGENT_ADDRESS_DISCOVERY_REQUEST: u8 = 144;       // h:65 (cc:389)
    pub const HOME_AGENT_ADDRESS_DISCOVERY_REPLY: u8 = 145;         // h:66 (cc:390)
    pub const MOBILE_PREFIX_SOLICITATION: u8 = 146;                 // h:67 (cc:391)
    pub const MOBILE_PREFIX_ADVERTISEMENT: u8 = 147;                // h:68 (cc:392)
    pub const CERTIFICATION_PATH_SOLICITATION: u8 = 148;            // h:69 (cc:393)
    pub const CERTIFICATION_PATH_ADVERTISEMENT: u8 = 149;           // h:70 (cc:394)
    pub const MULTICAST_ROUTER_ADVERTISEMENT: u8 = 151;             // h:71 (cc:395)
    pub const MULTICAST_ROUTER_SOLICITATION: u8 = 152;              // h:72 (cc:396)
    pub const MULTICAST_ROUTER_TERMINATION: u8 = 153;               // h:73 (cc:397)
    pub const FMIPV6: u8 = 154;                                     // h:74 (cc:398)
    pub const RPL_CONTROL: u8 = 155;                                // h:75 (cc:399)
    pub const ILNPV6_LOCATOR_UPDATE: u8 = 156;                      // h:76 (cc:400)
    pub const DUPLICATE_ADDRESS_REQUEST: u8 = 157;                  // h:77 (cc:401)
    pub const DUPLICATE_ADDRESS_CONFIRMATION: u8 = 158;             // h:78 (cc:402)
    pub const MPL_CONTROL: u8 = 159;                                // h:79 (cc:403)
}

/// icmp6.h:82-:93 `enum class Icmp6Code : uint8_t` — the TWO codes this
/// TU reads land here (the rest of the enumerators, UNREACH_NET 0x00,
/// UNREACH_FILTER_PROHIB 0x01, UNREACH_HOST 0x03, UNREACH_PORT 0x04
/// (h:85-:89), are NEVER read by the TU — the code slot is compared
/// numerically at cc:266/:285/:306/:370). UNREACH_INVALID 0x02 (h:87 —
/// the ground in-code comment `// UNREACH_INVALID == 2` at cc:263 rides);
/// ADVERTISEMENT 0X00 (h:92, the cc:306 RA compare).
pub mod icmp6_code {
    pub const UNREACH_NET: u8 = 0x00;             // h:85 (never read)
    pub const UNREACH_FILTER_PROHIB: u8 = 0x01;   // h:86 (never read)
    pub const UNREACH_INVALID: u8 = 0x02;         // h:87 (cc:263)
    pub const UNREACH_HOST: u8 = 0x03;            // h:88 (never read)
    pub const UNREACH_PORT: u8 = 0x04;            // h:89 (never read)
    pub const ADVERTISEMENT: u8 = 0x00;           // h:92 (cc:306)
}

/// cc:59-:83 `static const RuleMap icmp6_rules[]` — 13 rows VERBATIM
/// (multi-line C strings joined) + the `{ 0, nullptr }` terminator cc:82
/// -> [RuleMap; 14]. The vectors:93 census face `ICMP6RULES 13 sid0=427
/// name=icmp6`. All sids resident codec_module.rs (ZERO new): 427 :185,
/// 431 :189, 432 :190, 285-:290 :145-:150, 457 :215, 460 :218, 474 :232,
/// 478 :236.
pub const ICMP6_RULES: [RuleMap; 14] = [
    RuleMap {
        sid: CodecSid::DECODE_ICMP6_HDR_TRUNC as u32, // 427 (h:180, cc:61)
        msg: Some("truncated ICMPv6 header"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP6_TYPE_OTHER as u32, // 431 (h:184, cc:62)
        msg: Some("ICMPv6 type not decoded"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP6_DST_MULTICAST as u32, // 432 (h:185, cc:63)
        msg: Some("ICMPv6 packet to multicast address"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_TOO_BIG_BAD_MTU as u32, // 285 (h:136)
        // cc:64-:65:
        msg: Some("ICMPv6 packet of type 2 (message too big) with MTU field < 1280"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE as u32, // 286
        // cc:66-:67:
        msg: Some("ICMPv6 packet of type 1 (destination unreachable) with non-RFC 2463 code"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_SOLICITATION_BAD_CODE as u32, // 287 (h:138)
        // cc:68-:69:
        msg: Some("ICMPv6 router solicitation packet with a code not equal to 0"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_ADVERT_BAD_CODE as u32, // 288 (h:139)
        // cc:70-:71:
        msg: Some("ICMPv6 router advertisement packet with a code not equal to 0"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_SOLICITATION_BAD_RESERVED as u32, // 289 (h:140)
        // cc:72-:73:
        msg: Some("ICMPv6 router solicitation packet with the reserved field not equal to 0"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_ADVERT_BAD_REACHABLE as u32, // 290 (h:141)
        // cc:74-:75 ("set > 1 hour" verbatim — the 3600000 at cc:309 is
        // the numeric face, NOT the rule string):
        msg: Some("ICMPv6 router advertisement packet with the reachable time field set > 1 hour"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE as u32, // 457 (h:210)
        // cc:76-:77:
        msg: Some("ICMPv6 packet of type 1 (destination unreachable) with non-RFC 4443 code"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMPV6_NODE_INFO_BAD_CODE as u32, // 460 (h:213)
        // cc:78-:79:
        msg: Some("ICMPv6 node info query/response packet with a code greater than 2"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP6_NOT_IP6 as u32, // 474 (h:227, cc:80)
        msg: Some("ICMPv6 not encapsulated in IPv6"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP6_OPT_ZERO_LENGTH as u32, // 478 (h:231, cc:81)
        msg: Some("ICMPv6 option length field is set to 0"),
    },
    RuleMap { sid: 0, msg: None }, // cc:82 `{ 0, nullptr }` terminator
];

/// cc:85-:98 `class Icmp6Module : public BaseCodecModule` — the 2-arg
/// ctor cc:88 (cheat sheet: the plain-2-arg shape, NO params — the
/// contrast vs the udp CONFIG codec). get_rules cc:90-:91 returns the
/// table; get_pegs cc:93-:94 + get_counts cc:96-:97 are the PEG CITE
/// face (module doc) — NO Rust landing. The vectors:93 walk prints
/// sid0=427, 13 rows, NAME "icmp6" (m->get_name() = CD_ICMP6_NAME — the
/// drift ride prints icmp6 NEVER ipv6).
#[derive(Debug)]
pub struct Icmp6Module {
    pub base: BaseCodecModule,
}

impl Icmp6Module {
    /// cc:88 the 2-arg BaseCodecModule ctor face.
    pub fn new() -> Icmp6Module {
        Icmp6Module {
            base: BaseCodecModule::new(CD_ICMP6_NAME, CD_ICMP6_HELP),
        }
    }

    /// cc:90-:91 `{ return icmp6_rules; }`.
    pub fn get_rules() -> &'static [RuleMap] {
        &ICMP6_RULES
    }

    /// Module::get_name face — vectors:93 `name=icmp6`.
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

impl Default for Icmp6Module {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// THE DAQ seam (row 18i) — the cd_icmp4.rs shape kept IDENTICAL across the
// trio (the graft copy/daq.h md5 73fdbc39 is SYNTHETIC; 17d left-open;
// real DAQ lands row 20 and MUST re-cite the SDK header; NEVER ABI truth,
// PLAN §9 R1). Only the DECODE_DATA meta exists here — the NAPT_INFO face
// is the udp twin's (cd_udp.cc:420); this TU's single get_meta call is
// DAQ_PKT_META_DECODE_DATA (cc:126), so NO DaqNapt lands.
// ============================================================================

/// graft daq.h:15 `#define DAQ_PKT_DECODE_OFFSET_INVALID (-1)` — the
/// cc:130 compare (C int32 slot; compared pdd.l4_offset != -1).
pub const DAQ_PKT_DECODE_OFFSET_INVALID: i64 = -1;

/// graft daq.h:16-:22 `DAQ_PktDecodeData_t` — the flags.bits bitfield
/// group {l4_checksum, udp, icmp, l4} (graft `unsigned x : 1` face, order
/// SYNTHETIC, NEVER ABI) + `int32_t l4_offset`. THE ICMP6 GUARD FACE
/// cc:127: `!pdd || !bits.l4_checksum || !bits.icmp || !bits.l4` — the
/// `.udp` bit EXISTS on the face but this TU never reads it (contrast the
/// udp twin reading `.udp`); the field rides for graft fidelity.
#[derive(Copy, Clone, Default)]
pub struct DaqPdd {
    pub l4_checksum: bool,
    pub udp: bool, // face-only — never read by the cc:127 guard
    pub icmp: bool,
    pub l4: bool,
    pub l4_offset: i64, // the grafted int32_t slot
}

/// The decode-call DAQ parameter bundle (the cd_icmp4.rs trio shape):
/// the two valid_checksum_from_daq legs — the meta handle and the
/// probe-faked `raw.data - daq_msg_get_data()` delta (cc:133) — ride as
/// one Copy parameter (keeps decode inside the arg-count gate).
#[derive(Copy, Clone, Default)]
pub struct DaqFace {
    pub pdd: Option<DaqPdd>,
    pub payload_delta: i64, // cc:133 pointer-difference face (probe-faked)
}

/// The row-scoped DecodeData seam (the 18h AuthDecodeData::is_ip6 face RE-
/// CUT to the ground read): cc:189 `!snort.ip_api.get_ip6h()` — the
/// get_ip6h() None face IS the NOT_IP6 gate, so the seam is the
/// Option<&'static [u8]> header window itself: None <-> `474 + false`
/// (vectors:66-:67 `ICMP6 noip6 -> 0`, probe arm probe_dec.cc:186 with NO
/// set_ip6 call), Some(window) doubles as the cc:200-:202 get_src()/
/// get_dst() pseudoheader words and the cc:228 is_dst_multicast octet
/// (the 40-byte wire face, probe set_ip6 = bytes 8-23 src / 24-39 dst).
/// decode_flags is the cc:212 write face (vectors:68 dflags=8) fresh at 0
/// per call; the cc:414 set_pkt_type lands as the landed pkt_type slot
/// (PKT_TYPE__ICMP); the cc:413 `snort.icmph = reinterpret_cast<const
/// icmp::ICMPHdr*>(icmp6h)` pointer stash is the LEFT-OPEN pointer face —
/// the alias IS the raw byte window, no Rust slot lands (document pin,
/// the cd_icmp4.rs posture; probe never prints it).
#[derive(Copy, Clone, Default)]
pub struct Icmp6DecodeData {
    pub decode_flags: u64, // cc:212 write
    pub ip6h: Option<&'static [u8]>, // cc:189 get_ip6h() face
    pub pkt_type: u8,
}

/// ipv6.h:56 (`uint32_t u6_addr32[4]`) + :97-:98 get_src() — the address
/// bytes 8-23 as four u32 words as stored (the COPY4 cc:201 word-identity
/// face); :99-:101 get_dst() — bytes 24-39 (cc:202). Row-scoped fns, the
/// cd_udp.rs ip_addr face (per-TU private; trio wording kept).
#[inline]
fn ip6_sip_words(h: &[u8]) -> [u32; 4] {
    ip6_addr_words(h, 8)
}
/// cc:202 — the get_dst() u6_addr32 words (bytes 24-39).
#[inline]
fn ip6_dip_words(h: &[u8]) -> [u32; 4] {
    ip6_addr_words(h, 24)
}

/// the cc:201-:202 COPY4 (u6_addr32) / cc:457-:458 memcpy (get_ip6_ptr,
/// sfip/sf_ip.h:72/:159 — the 16 address bytes) faces: `off` is the
/// address start in the ip6 wire header (8 src / 24 dst); four u32 words
/// AS STORED (LE-host copy identity — the bytes round-trip unchanged;
/// the memcpy-vs-COPY4 pair lands the SAME bytes, identity kept).
fn ip6_addr_words(h: &[u8], off: usize) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (i, slot) in w.iter_mut().enumerate() {
        *slot = u32::from_le_bytes([
            *h.get(off + 4 * i).unwrap_or(&0),
            *h.get(off + 4 * i + 1).unwrap_or(&0),
            *h.get(off + 4 * i + 2).unwrap_or(&0),
            *h.get(off + 4 * i + 3).unwrap_or(&0),
        ]);
    }
    w
}

/// The update-path LEFT-OPEN ip::IpApi read seam (module doc + the
/// cd_gtp.rs/cd_udp.rs UdpApiLite lineage ruling, cleaner branch): the C
/// operand `const ip::IpApi& api` cc:446 IS READ here (the contrast vs
/// the never-read gtp/gre/icmp4 arms): cc:457-:458 `api.get_src()/
/// get_dst()->get_ip6_ptr()` = the 16 address bytes each (the
/// `sizeof(ps6.hdr.sip)` memcpy span). WHO feeds it stays OPEN (the ip
/// codec rows); the observable quantity is pinned as raw 16-byte address
/// pairs — NOT an IpApi port, NEVER ABI.
#[derive(Copy, Clone, Default)]
pub struct Icmp6ApiFace {
    pub src_ip6: [u8; 16], // cc:457 get_src()->get_ip6_ptr() bytes
    pub dst_ip6: [u8; 16], // cc:458 get_dst()->get_ip6_ptr() bytes
}

// The wire-offset overlay readers (the gre.h overlay posture, icmp6.h
// struct layouts): type @0 / code @1 / csum @2-3 ride every struct face
// (Icmp6Hdr h:95-:107; each NDPOption-target struct repeats them).

#[inline]
fn u32_be_at(b: &[u8], off: usize) -> u32 {
    // the C ntohl faces (cc:243/:288/:309): wire-BE loads, get-or-0.
    u32::from_be_bytes([
        *b.get(off).unwrap_or(&0),
        *b.get(off + 1).unwrap_or(&0),
        *b.get(off + 2).unwrap_or(&0),
        *b.get(off + 3).unwrap_or(&0),
    ])
}

/// The nine codec_event sites + the walk's one (cc:233/:251/:274/:295/
/// :316/:331/:346/:360/:377/:173) ride the LANDED framework/codec.rs
/// codec_event (GID_DECODE 116 -> the vectors `EV 116 <sid>` family) —
/// file-private wrapper, the gre/icmp4 codec_event_* pattern verbatim.
#[inline]
fn codec_event_icmp6(codec: &CodecData, sid: u32, sink: QueueSink) {
    crate::framework::codec::codec_event(codec, sid, sink);
}

/// cc:100-:117 `class Icmp6Codec : public Codec` — the method map:
/// get_protocol_ids cc:105 -> `get_protocol_ids`, decode cc:106 ->
/// `decode`, update cc:107-:108 -> `update`, format cc:109 -> `format`,
/// log cc:110 -> `log`; the PRIVATES valid_checksum_from_daq cc:113 and
/// the templated validate_ndp_option cc:114-:116 (the OptionType
/// template folds to the option_start-offset arg — see the walk doc).
/// ctor cc:103 `Icmp6Codec() : Codec(CD_ICMP6_NAME)` — the Codec base
/// name is the MACRO "icmp6" (drift triple side two).
#[derive(Default)]
pub struct Icmp6Codec;

impl Icmp6Codec {
    /// cc:103 `Icmp6Codec() : Codec(CD_ICMP6_NAME) { }`.
    pub fn new() -> Icmp6Codec {
        Icmp6Codec
    }

    /// cc:120-:121 out-of-line def — one emplace_back; vectors:92
    /// `ICMP6PID 58 n=1` (protocol_id::ICMPV6 = 58, the landed home).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::ICMPV6); // cc:121
    }

    /// cc:123-:138 `valid_checksum_from_daq` — THE VERBATIM DAQ face
    /// (module doc rules the seam): cc:125-:126 the get_meta
    /// (DAQ_PKT_META_DECODE_DATA) read folds to the DaqFace.pdd Option
    /// (the witness nullptr arm = None, witness_daq.cc `meta_enabled`);
    /// cc:127-:128 the guard reads l4_checksum/icmp/l4; cc:129 the
    /// "Sanity check to make sure we're talking about the same thing if
    /// offset is available" comment rides; cc:130-:135 the offset arm
    /// (l4_offset != -1 -> the cc:133 `raw.data - data` compare, folded
    /// to DaqFace.payload_delta — the probe-pinned quantity, NEVER ABI);
    /// cc:136 the cksum_bypassed PEG bump — cite-never-land, NO Rust
    /// counter; cc:137 true.
    pub fn valid_checksum_from_daq(daq: DaqFace) -> bool {
        let pdd = match daq.pdd {
            // cc:127 `!pdd || !bits.l4_checksum || !bits.icmp || !bits.l4`
            Some(p) if p.l4_checksum && p.icmp && p.l4 => p,
            _ => return false, // cc:128
        };
        if pdd.l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID {
            // cc:132-:134 the same-thing sanity compare (the
            // daq_msg_get_data leg folded into DaqFace.payload_delta):
            if daq.payload_delta != pdd.l4_offset {
                return false; // cc:134
            }
        }
        // cc:136 stats.cksum_bypassed++ — PEG cite-never-land (module
        // doc pegs block; vectors:69 prints only ret/dflags/lyr — the
        // counter never surfaces).
        true // cc:137
    }

    /// cc:114-:116 decl + cc:140-:179 out-of-line body —
    /// `validate_ndp_option<OptionType>`. THE TEMPLATE FOLD: the C
    /// template argument never changes the body — the only OptionType
    /// touch is `&icmp_pkt->options_start` (cc:155), whose value is the
    /// MEMBER OFFSET of options_start in each struct (icmp6.h layouts):
    /// RS h:138-:145 -> 8, RA h:125-:136 -> 16, NS h:157-:166 -> 24,
    /// NA h:168-:177 -> 24, RD h:179-:190 -> 40 — EXACTLY the
    /// ICMPv6_*_MIN_LEN macros (h:32-:36), so the walk arg pair is the
    /// (window, opt_off == min_len, min_len, dsize) face — generic-free.
    /// Port statement-for-statement over the raw window with the offset
    /// walk (curr_option_ptr - icmp_pkt_ptr = an offset counter):
    /// cc:144 real_size = dsize + MIN_LEN(4); cc:145-:147
    /// option_field_not_exists (real_size == min_len) -> return (the
    /// rs-bad arm, vectors:78-:80: real 8 == 8, NO walk event);
    /// cc:149 `assert(real_size > min_len - MIN_LEN)` + cc:150-:151 the
    /// RFC2461 "option field depends on version" comment + cc:152
    /// `assert(type >= 133 && type <= 137)` — debug_assert-FREE CITES
    /// (the lineage posture: asserts never land as Rust asserts);
    /// cc:154-:155 the two pointer bases fold to offsets 0 and opt_off;
    /// cc:157 while real_size > off; cc:159 assert off > 0 CITEd;
    /// cc:160-:162 field_incomplete (real_size == off + 1) -> return
    /// (cc:162 comment `// FIXIT-L good candidate for new builtin rule`
    /// rides); cc:164-:165 the NDPOptionFormatBasic overlay (h:117-:123,
    /// type @0 length @1) over the window at off — the get-or-0 posture;
    /// cc:167 the RFC4861 comment + cc:168-:169 `type == 0 || type > 5`
    /// -> return (the `// FIXIT-L good candidate for non-supported
    /// option field` comment rides, cc:169); cc:171-:175 length == 0 ->
    /// codec_event(DECODE_ICMP6_OPT_ZERO_LENGTH 478) + return (the walk's
    /// ONLY event arm — vectors:84-:85 `EV 116 478` ra-zerolen: option
    /// @16 type1 length0); cc:177 `curr_option_ptr += length * 8` (the
    /// length slot is u8, *8 = 8-byte units, icmp6.h:120 — the C
    /// uint8_t-then-int-math face kept as u16 wrapping ops).
    fn validate_ndp_option(
        codec: &CodecData,
        window: &[u8],
        opt_off: u16, // &icmp_pkt->options_start (the member-offset face)
        min_len: u16,
        dsize: u16,
        sink: QueueSink,
    ) {
        // cc:144:
        let real_size: u16 = dsize.wrapping_add(ICMP6_HEADER_MIN_LEN);
        // cc:145-:147 `bool option_field_not_exists = real_size ==
        // min_len; if (...) return;`:
        if real_size == min_len {
            return;
        }

        // cc:149 assert(real_size > min_len - MIN_LEN) — CITE ONLY;
        // cc:152 assert(icmp_pkt->type >= 133 && icmp_pkt->type <= 137)
        // — CITE ONLY: the caller arms are 133/134/135/136/137 by
        // construction (the switch cases), so the assert cannot fire.

        // cc:154-:155: icmp_pkt_ptr folds to 0 (the window base); the
        // walk cursor is the offset face:
        let mut off: u16 = opt_off;

        // cc:157 `while (real_size > curr_option_ptr - icmp_pkt_ptr)`:
        while real_size > off {
            // cc:159 assert(curr_option_ptr > icmp_pkt_ptr) — CITE ONLY
            // (opt_off >= 8 > 0 at every call site):
            // cc:160-:162 `bool field_incomplete = real_size == off + 1;
            // if (...) return;` (the lone-byte remnant — never-armed in
            // replay):
            if real_size == off.wrapping_add(1) {
                return;
            }

            // cc:164-:165 the NDPOptionFormatBasic overlay read at off
            // (type h:119 @0, length h:120 @1):
            let opt_type = *window.get(off as usize).unwrap_or(&0);
            let opt_len = *window.get(off as usize + 1).unwrap_or(&0);

            // cc:168-:169 `if (type == 0 || type > 5) return;` (the
            // RFC4861 comment rides):
            if opt_type == 0 || opt_type > 5 {
                return;
            }

            // cc:171-:175 `if (length == 0) { codec_event(
            // DECODE_ICMP6_OPT_ZERO_LENGTH); return; }` — vectors:84-:85
            // (off 16 hits exactly: real_size 24 > 16, off+1 = 17 != 24,
            // type 1 passes, length 0 fires 478):
            if opt_len == 0 {
                codec_event_icmp6(codec, CodecSid::DECODE_ICMP6_OPT_ZERO_LENGTH as u32, sink); // cc:173
                return; // cc:174
            }

            // cc:177 `curr_option_ptr += curr_option->length * 8;`:
            off = off.wrapping_add((opt_len as u16) * 8);
        }
    }

    /// cc:181-:416 out-of-line decode, statement order VERBATIM (the
    /// eval-order posture: never reorder an event vs a mutation). The
    /// netpol param carries the cc:197 `snort::get_network_policy()->
    /// icmp_checksums()` read (policy.h:211-:212; the NetworkPolicy::
    /// default = CHECKSUM_FLAG__ALL|DEF, policy.h:233-:234 — the gate is
    /// TRUE at the vectors:68-:69 dual-face pair); daq carries the
    /// cc:125-:133 legs; the icmph overlay cc:195 = the raw window
    /// itself.
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut Icmp6DecodeData,
        netpol: &NetworkPolicy, // cc:197 get_network_policy() seam
        daq: DaqFace,          // cc:125-:133 meta faces
        sink: QueueSink,
    ) -> bool {
        // cc:183-:187: raw.len < icmp::ICMP6_HEADER_MIN_LEN (4) -> 427 +
        // false. vectors:64-:65 `EV 116 427` + `ICMP6 short3 -> 0`.
        if raw.len < u32::from(ICMP6_HEADER_MIN_LEN) {
            codec_event_icmp6(codec, CodecSid::DECODE_ICMP6_HDR_TRUNC as u32, sink); // cc:185
            return false; // cc:186
        }

        // cc:189-:193: `!snort.ip_api.get_ip6h()` (the `/* FIXIT-L &&
        // verify prior layer == ip6 */` comment rides) -> 474 + false.
        // THE is_ip6 SEAM (the cd_auth.rs AuthDecodeData precedent RE-
        // CUT to the get_ip6h() None face, module doc): vectors:66-:67
        // `EV 116 474` + `ICMP6 noip6 -> 0` — a fresh DecodeData, probe
        // arm probe_dec.cc:186 SKIPS the set_ip6 call.
        let ip6h: &[u8] = match snort.ip6h {
            Some(h) => h,
            None => {
                codec_event_icmp6(codec, CodecSid::DECODE_ICMP6_NOT_IP6 as u32, sink); // cc:191
                return false; // cc:192
            }
        };

        // cc:195 the Icmp6Hdr overlay (h:95-:107: type @0, code @1,
        // csum @2-3, union @4-7): the alias IS the raw window:
        let icmp6h = raw.data;
        let typ = *icmp6h.first().unwrap_or(&0); // icmp6h->type h:97
        let code = *icmp6h.get(1).unwrap_or(&0); // icmp6h->code h:98

        // cc:197-:215 THE CHECKSUM GATE: icmp_checksums() && !daq-valid.
        if netpol.icmp_checksums() && !Self::valid_checksum_from_daq(daq) {
            // cc:199-:205 the Pseudoheader6 fill on the LANDED
            // checksum.rs field shapes (sip/dip [u32;4], zero, protocol,
            // len — network-order bits per the checksum.rs pin):
            let ph6 = Pseudoheader6 {
                sip: ip6_sip_words(ip6h),           // cc:201 COPY4 get_src()->u6_addr32
                dip: ip6_dip_words(ip6h),           // cc:202 COPY4 get_dst()->u6_addr32
                zero: 0,                            // cc:203
                protocol: codec.ip6_csum_proto,     // cc:204 (the CodecData read)
                len: u16::to_be(raw.len as u16),    // cc:205 htons((uint16_t)raw.len)
            };

            // cc:207 THE 3-ARG v6 face: C `checksum::icmp_cksum(icmp6h,
            // raw.len, ph6)` landed as `checksum::icmp_cksum_v6`
            // (checksum.rs:354 — the name the landed file actually
            // EXPORTS for the Pseudoheader6 overload, verified by
            // reading THIS pass):
            let csum = icmp_cksum_v6(icmp6h, raw.len as usize, ph6);

            // cc:209-:214: `if (csum && !codec.is_cooked())` — the VALID
            // face posture (nonzero csum = bad, the cd_icmp4:167 twin,
            // NOT the udp `!valid` inversion):
            if csum != 0 && !codec.is_cooked() {
                // cc:211 stats.bad_ip6_cksum++ — PEG cite-never-land:
                snort.decode_flags |= DECODE_ERR_CKSUM_ICMP; // cc:212
                return false; // cc:213 — vectors:68 dflags=8
            }
        }

        // cc:217-:218: dsize = raw.len - 4 (uint16_t, trunc face kept);
        // len starts at MIN_LEN (the lyr=8 faces ride the NORMAL writes).
        let dsize: u16 = (raw.len as u16).wrapping_sub(ICMP6_HEADER_MIN_LEN);
        let mut len: u16 = ICMP6_HEADER_MIN_LEN;

        // cc:220 `switch (icmp6h->type)` — arms in C order:
        match typ {
            // cc:222-:223 fall-throw ECHO pair:
            icmp6_type::ECHO_REQUEST | icmp6_type::ECHO_REPLY => {
                // cc:224-:236 THE idseq gate (the cross-rider const):
                if dsize >= ICMP4_IDSEQ_SIZE {
                    len = ICMP6_HEADER_NORMAL_LEN; // cc:226

                    // cc:228-:229: is_dst_multicast() — ipv6.h:111 the
                    // dst address byte0 (window byte 24) == IP6_MULTICAST
                    // 0xFF (h:33); vectors:70-:71 `EV 116 432`:
                    if *ip6h.get(24).unwrap_or(&0) == IP6_MULTICAST {
                        codec_event_icmp6(codec, CodecSid::DECODE_ICMP6_DST_MULTICAST as u32, sink);
                    }
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:233
                    return false; // cc:234
                }
            }

            // cc:238-:254:
            icmp6_type::PACKET_TOO_BIG => {
                // gate dsize >= sizeof(ICMP6TooBig) = 8 (h:109-:115):
                if dsize >= ICMP6_TOO_BIG_SIZE {
                    // cc:241-:243 the ICMP6TooBig overlay (mtu u32 @4,
                    // h:114) — vectors:72-:73 mtu BE 1024 < 1280 -> 285:
                    if u32_be_at(icmp6h, 4) < 1280 {
                        codec_event_icmp6(codec, CodecSid::DECODE_ICMPV6_TOO_BIG_BAD_MTU as u32, sink);
                    }

                    len = ICMP6_HEADER_NORMAL_LEN; // cc:246
                    codec.next_prot_id = PROTOCOL_ID_IP_EMBEDDED_ICMP6; // cc:247 -> 260
                } else {
                    // toobig6 (dsize 2 < 8): vectors:88-:89 `EV 116 105`:
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:251
                    return false; // cc:252
                }
            }

            // cc:256-:258 fall-through trio:
            icmp6_type::TIME_EXCEEDED6
            | icmp6_type::PARAMETER_PROBLEM
            | icmp6_type::DESTINATION_UNREACHABLE => {
                // cc:259 `if (dsize >= 4)`:
                if dsize >= 4 {
                    // cc:261-:268 the inner re-test (NOT a separate
                    // case — statement order kept):
                    if typ == icmp6_type::DESTINATION_UNREACHABLE {
                        // cc:263-:264 `code == UNREACH_INVALID` (== 2,
                        // the ground in-code comment) — vectors:74-:75 286:
                        if code == icmp6_code::UNREACH_INVALID {
                            codec_event_icmp6(
                                codec,
                                CodecSid::DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE as u32,
                                sink,
                            );
                        }
                        // cc:266-:267 `static_cast<uint8_t>(code) > 6`
                        // — vectors:76-:77 code 7 -> 457:
                        else if code > 6 {
                            codec_event_icmp6(
                                codec,
                                CodecSid::DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE as u32,
                                sink,
                            );
                        }
                    }
                    len = ICMP6_HEADER_NORMAL_LEN; // cc:269
                    codec.next_prot_id = PROTOCOL_ID_IP_EMBEDDED_ICMP6; // cc:270
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:274
                    return false; // cc:275
                }
            }

            // cc:279-:298: gate dsize >= (RS_MIN 8 - 4) = 4:
            icmp6_type::ROUTER_SOLICITATION => {
                if dsize >= (ICMPV6_RS_MIN_LEN - ICMP6_HEADER_MIN_LEN) {
                    // cc:282-:287 the ICMP6RouterSolicitation overlay
                    // (h:138-:145: code @1 — re-read off the struct face,
                    // operand identity kept — reserved u32 @4): both
                    // events on ONE packet, rs-bad code1 + reserved BE
                    // 0..1 — vectors:78-:80 `EV 287` THEN `EV 289`:
                    if *icmp6h.get(1).unwrap_or(&0) != 0 {
                        codec_event_icmp6(codec, CodecSid::DECODE_ICMPV6_SOLICITATION_BAD_CODE as u32, sink); // cc:286
                    }

                    if u32_be_at(icmp6h, 4) != 0 {
                        codec_event_icmp6(codec, CodecSid::DECODE_ICMPV6_SOLICITATION_BAD_RESERVED as u32, sink); // cc:289
                    }

                    Self::validate_ndp_option(codec, icmp6h, ICMPV6_RS_MIN_LEN, ICMPV6_RS_MIN_LEN, dsize, sink); // cc:291
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:295
                    return false; // cc:296
                }
            }

            // cc:300-:319: gate dsize >= (RA_MIN 16 - 4) = 12:
            icmp6_type::ROUTER_ADVERTISEMENT => {
                if dsize >= (ICMPV6_RA_MIN_LEN - ICMP6_HEADER_MIN_LEN) {
                    // cc:303-:307: the code face re-read off icmp6h (the
                    // C reads icmp6h->code, NOT ra->code — operand
                    // identity per arm kept, BOTH read @1 the same slot):
                    if code != icmp6_code::ADVERTISEMENT {
                        codec_event_icmp6(codec, CodecSid::DECODE_ICMPV6_ADVERT_BAD_CODE as u32, sink); // cc:307
                    }

                    // cc:309-:310: reachable_time u32 @8 (h:133 — RA
                    // layout num_addrs@4, addr_entry@5, lifetime@6,
                    // reachable@8), BE compare > 3600000; vectors:81-:83
                    // 0xFFFFFFFF -> 290:
                    if u32_be_at(icmp6h, 8) > 3600000 {
                        codec_event_icmp6(codec, CodecSid::DECODE_ICMPV6_ADVERT_BAD_REACHABLE as u32, sink);
                    }

                    Self::validate_ndp_option(codec, icmp6h, ICMPV6_RA_MIN_LEN, ICMPV6_RA_MIN_LEN, dsize, sink); // cc:312 — vectors:84-:85 -> 478
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:316
                    return false; // cc:317
                }
            }

            // cc:321-:334: gate dsize >= (NS_MIN 24 - 4) = 20 — the
            // WALK-ONLY arm (no checks before validate, cc:324-:327):
            icmp6_type::NEIGHBOR_SOLICITATION => {
                if dsize >= (ICMPV6_NS_MIN_LEN - ICMP6_HEADER_MIN_LEN) {
                    Self::validate_ndp_option(codec, icmp6h, ICMPV6_NS_MIN_LEN, ICMPV6_NS_MIN_LEN, dsize, sink); // cc:327
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:331
                    return false; // cc:332
                }
            }

            // cc:336-:349: gate dsize >= (NA_MIN 24 - 4) = 20 — walk-
            // only (the na overlay cc:339 is cast and NEVER read):
            icmp6_type::NEIGHBOR_ADVERTISEMENT => {
                if dsize >= (ICMPV6_NA_MIN_LEN - ICMP6_HEADER_MIN_LEN) {
                    Self::validate_ndp_option(codec, icmp6h, ICMPV6_NA_MIN_LEN, ICMPV6_NA_MIN_LEN, dsize, sink); // cc:342
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:346
                    return false; // cc:347
                }
            }

            // cc:351-:363: gate dsize >= (RD_MIN 40 - 4) = 36 — walk-
            // only (the rd overlay cc:354 cast, never read):
            icmp6_type::REDIRECT6 => {
                if dsize >= (ICMPV6_RD_MIN_LEN - ICMP6_HEADER_MIN_LEN) {
                    Self::validate_ndp_option(codec, icmp6h, ICMPV6_RD_MIN_LEN, ICMPV6_RD_MIN_LEN, dsize, sink); // cc:356
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:360
                    return false; // cc:361
                }
            }

            // cc:365-:380: gate dsize >= sizeof(ICMP6NodeInfo) (16,
            // h:147-:155) - 4 = 12:
            icmp6_type::NODE_INFORMATION_QUERY | icmp6_type::NODE_INFORMATION_RESPONSE => {
                if dsize >= (ICMP6_NODE_INFO_SIZE - ICMP6_HEADER_MIN_LEN) {
                    // cc:369-:371: the ni->code read = the code slot @1
                    // (h:150) — nodeinfo3: vectors:86-:87 code 3 > 2 ->
                    // 460:
                    if *icmp6h.get(1).unwrap_or(&0) > 2 {
                        codec_event_icmp6(codec, CodecSid::DECODE_ICMPV6_NODE_INFO_BAD_CODE as u32, sink);
                    }

                    // cc:373 the FIXIT-L comment (`// FIXIT-L add alert
                    // for INFO Response, code == 1 || code == 2) with
                    // data`) rides as a cite — NO event (the never-done
                    // arm):
                } else {
                    codec_event_icmp6(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, sink); // cc:377
                    return false; // cc:378
                }
            }

            // cc:382 `// recognize these so we don't alert but no
            // further checking (yet)` + the 21 bare cases cc:383-:403 —
            // NO event, NO len change, break only (the 21-TYPE list,
            // module doc; every name a h:52-:79 enumerator):
            icmp6_type::MULTICAST_LISTENER_QUERY
            | icmp6_type::MULTICAST_LISTENER_REPORT
            | icmp6_type::MULTICAST_LISTENER_DONE
            | icmp6_type::INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION
            | icmp6_type::INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT
            | icmp6_type::VERSION_2_MULTICAST_LISTENER_REPORT
            | icmp6_type::HOME_AGENT_ADDRESS_DISCOVERY_REQUEST
            | icmp6_type::HOME_AGENT_ADDRESS_DISCOVERY_REPLY
            | icmp6_type::MOBILE_PREFIX_SOLICITATION
            | icmp6_type::MOBILE_PREFIX_ADVERTISEMENT
            | icmp6_type::CERTIFICATION_PATH_SOLICITATION
            | icmp6_type::CERTIFICATION_PATH_ADVERTISEMENT
            | icmp6_type::MULTICAST_ROUTER_ADVERTISEMENT
            | icmp6_type::MULTICAST_ROUTER_SOLICITATION
            | icmp6_type::MULTICAST_ROUTER_TERMINATION
            | icmp6_type::FMIPV6
            | icmp6_type::RPL_CONTROL
            | icmp6_type::ILNPV6_LOCATOR_UPDATE
            | icmp6_type::DUPLICATE_ADDRESS_REQUEST
            | icmp6_type::DUPLICATE_ADDRESS_CONFIRMATION
            | icmp6_type::MPL_CONTROL => {} // cc:383-:404 bare break

            // cc:406-:408: vectors:90-:91 type200 -> 431:
            _ => {
                codec_event_icmp6(codec, CodecSid::DECODE_ICMP6_TYPE_OTHER as u32, sink); // cc:407
            }
        }

        // cc:411-:415 the tail writes, statement order:
        codec.lyr_len = len; // cc:411 (vectors:69/:73 lyr=8)
        codec.proto_bits |= PROTO_BIT__ICMP; // cc:412
        // cc:413 `snort.icmph = reinterpret_cast<const icmp::ICMPHdr*>
        // (icmp6h)` — LEFT-OPEN pointer stash DOCUMENT pin (the alias IS
        // the raw window; the cd_icmp4.rs posture, no slot):
        snort.pkt_type = PKT_TYPE__ICMP; // cc:414 (decode_data.h:45-:48 ICMP=4)
        true // cc:415
    }

    /// cc:422-:427 out-of-line log (the "L O G G E R" banner cc:418-:420
    /// rides) — NEVER vectorized (NO probe line calls log(); the cited-
    /// never-vectorized posture, 18d eth / 18g gre / 18h frag precedent):
    /// cc:425 the Icmp6Hdr overlay + cc:426 the ONE TextLog_Print,
    /// format `"sType:%d  Code:%d  "` (TWO spaces between fields and TWO
    /// trailing spaces verbatim; %d decimal both — the code slot
    /// `static_cast<uint8_t>` so the enum prints decimal), lyr_len
    /// UNNAMED (cc:423 `const uint16_t /*lyr_len*/`).
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        // cc:425 the overlay: type @0, code @1 (h:97-:98):
        sink(format!(
            "sType:{}  Code:{}  ",
            *raw_pkt.first().unwrap_or(&0),      // cc:426 icmph->type
            *raw_pkt.get(1).unwrap_or(&0),      // cc:426 static_cast<uint8_t>(icmph->code) — the
            // u8 slot already prints decimal (the C cast is a NO-OP face on
            // the Rust overlay read, cited not re-cast)
        )); // cc:426
    }
}

// cc:429-431 the "E N C O D E R" banner rides. cc:433-:444 the anon-
// namespace `struct IcmpHdr { uint8_t type; uint8_t code; uint16_t
// cksum; uint32_t unused; }` — the TWO cppcheck-suppress
// unusedStructMember pins (cc:438/:441) ride; NO Rust struct lands: the
// update overlay reads the SAME wire offsets (@0 type, @1 code, @2-3
// cksum) — @2-3 is the Icmp6Hdr csum same slot (icmp6.h:99 — a
// document-cite, never a second face).

impl Icmp6Codec {
    /// cc:446-:464 out-of-line update, statement order VERBATIM. THE
    /// LEFT-OPEN api seam (the trio/gtp ruling, module doc): C operand
    /// `const ip::IpApi& api` cc:446 IS READ at cc:457-:458 (the
    /// get_*_ptr() memcpys — the contrast vs the never-read `&()` faces
    /// of update cd_gtp.rs:417 / cd_icmp4.rs update), so the operand
    /// lands as Icmp6ApiFace (the 16 address bytes the IpApi hands; WHO
    /// feeds stays QUEUED). The EncodeFlags carrier landed u64; the
    /// uint32 accumulate wrapping (every C unsigned pair).
    pub fn update(
        &self,
        api: &Icmp6ApiFace, // cc:446 the read face (module doc)
        flags: EncodeFlags, // cc:447 const EncodeFlags
        raw_pkt: &mut [u8], // cc:447-:448 uint8_t* raw_pkt
        lyr_len: u16,       // cc:448 uint16_t lyr_len
        updated_len: &mut u32, // cc:448 uint32_t& reference param
    ) {
        // cc:449 the IcmpHdr overlay (fields ride the wire offsets @0/@1/
        // @2-3); cc:450 `updated_len += lyr_len;` — BEFORE any field
        // work, and the cc:462 cksum window is `updated_len` bytes (NOT
        // lyr_len) — operand identity per arm kept:
        *updated_len = updated_len.wrapping_add(u32::from(lyr_len));

        // cc:452 `if ( !(flags & UPD_COOKED) || (flags &
        // UPD_REBUILT_FRAG) )` — the OR shape kept (landed codec.rs:85/
        // :88 consts; the trio-parity cast posture):
        if (flags & u64::from(UPD_COOKED)) == 0 || (flags & u64::from(UPD_REBUILT_FRAG)) != 0 {
            // cc:454-455 `h->cksum = 0;` — the uint16 LE face on the
            // pinned LE host (bytes 2-3 cleared, same-window operand):
            raw_pkt[2] = 0;
            raw_pkt[3] = 0;

            // cc:457-:461 the Pseudoheader6 fill: the two memcpys over
            // get_*()->get_ip6_ptr() (16 bytes each, the address-bytes
            // seam) into the as-stored word slots (the ip6_addr_words
            // copy identity), zero cc:459, protocol =
            // IpProtocol::ICMPV6 cc:460 (ip_protocol::ICMPV6 = 58, the
            // FIXED protocol here — the contrast vs decode cc:204's
            // codec.ip6_csum_proto read, operand identity kept), len =
            // htons((uint16_t)updated_len) cc:461 (the FRESH value, the
            // udp sibling's operand pin):
            let ps6 = Pseudoheader6 {
                sip: ip6_addr_words(&api.src_ip6, 0),      // cc:457
                dip: ip6_addr_words(&api.dst_ip6, 0),      // cc:458
                zero: 0,                                   // cc:459
                protocol: ip_protocol::ICMPV6,             // cc:460
                len: u16::to_be(*updated_len as u16),      // cc:461 htons
            };

            // cc:462 `h->cksum = checksum::icmp_cksum(h, updated_len,
            // ps6);` — the LANDED 3-arg v6 face (checksum.rs:354, same
            // call shape as decode cc:207); the u16 write-back lands LE
            // (the cd_icmp4 update pair):
            let value = icmp_cksum_v6(raw_pkt, *updated_len as usize, ps6);
            raw_pkt[2..4].copy_from_slice(&value.to_le_bytes()); // cc:462 raw slot
        }
        // cc:463-:464 `}` closes update — void, no return.
    }

    /// cc:466-:470 out-of-line format — NEVER vectorized, literal: the
    /// reverse operand COMMENTED-out named (cc:466 `bool /*reverse*/`) =
    /// the never-read face; NO raw_pkt mutation happens (no reverse arm
    /// — the contrast vs the udp format swap). cc:468 the `snort.icmph =
    /// reinterpret_cast<ICMPHdr*>(raw_pkt)` stash is the LEFT-OPEN
    /// pointer document pin (same ruling as decode cc:413 — the _raw_pkt
    /// param keeps the call-site shape); cc:469 set_pkt_type:
    pub fn format(&self, _reverse: bool, _raw_pkt: &mut [u8], snort: &mut Icmp6DecodeData) {
        snort.pkt_type = PKT_TYPE__ICMP; // cc:469
    }
}

// cc:472-:474 the "api" separator comment rides.
// cc:476-:477 `static Module* mod_ctor() { return new Icmp6Module; }` +
// cc:479-:480 `static void mod_dtor(Module* m) { delete m; }` — the mod
// pair SET (faceA :13 `icmp6 mod_ctor=1 mod_dtor=1` — the trio uniform
// x3 print); the Rust mod_ctor() face is Icmp6Module::new (stack-owned
// drop, 18d posture). cc:482-:483 `static Codec* ctor(Module*)` /
// cc:485-:486 `static void dtor(Codec* cd)` — the codec pair, the C
// `(Module*)` arg unused (Icmp6Codec is config-free — the contrast vs
// the udp ctor cc:618-:625).

/// cc:488-:508 `static const CodecApi ipv6_api` — THE DRIFT-SITE record
/// (module doc headline): the C identifier is `ipv6_api` (cc:488 — NOT
/// the file-base spelling + api suffix) while the file is cd_icmp6.cc, the
/// table is cd_icmp6 (cc:513) and the NAME slot carries "icmp6"
/// (CD_ICMP6_NAME cc:39 -> cc:497). Following cd_auth.rs (AH_API carries
/// the C struct name ah_api), the Rust const carries the C STRUCT NAME:
/// IPV6_API. The forbidden file-base+api token NEVER appears (ground grep
/// = 0 hits FALSE-CLEAN face; build.sh arms the src/ grep EVERY build).
/// ALL FOUR ctor/dtor slots SET: mod_ctor
/// cc:499 + mod_dtor cc:500 (cc:476/:479 fns), ctor cc:506 + dtor
/// cc:507 (cc:482/:485); cc:502-:505 the four nullptr pinit/pterm/
/// tinit/tterm. faceA :11 `API icmp6 type=0 size=112 ver=1900547
/// name=icmp6`.
pub const IPV6_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:491
    size: CDAPI_SIZEOF_CODEC_API, // cc:492 sizeof(CodecApi) = 112
    api_version: CDAPI_VERSION,   // cc:493 1900547
    version: 0,                   // cc:494
    features: PLUGIN_SO_RELOAD,   // cc:495
    options: API_OPTIONS,         // cc:496
    name: CD_ICMP6_NAME,          // cc:497 -> "icmp6" (the NAME side)
    help: CD_ICMP6_HELP,          // cc:498
    mod_ctor: true,               // cc:499 SET
    mod_dtor: true,               // cc:500 SET
    pinit: false,                 // cc:502 nullptr
    pterm: false,                 // cc:503 nullptr
    tinit: false,                 // cc:504 nullptr
    tterm: false,                 // cc:505 nullptr
    ctor: true,                   // cc:506 SET
    dtor: true,                   // cc:507 SET
};

/// cc:510-:518 the export — THE DRIFT FACE RIDE: `#ifdef BUILDING_SO`
/// `SO_PUBLIC const BaseApi* snort_plugins[]` (cc:510-:511) `#else`
/// `const BaseApi* cd_icmp6[]` (cc:513) `{ &ipv6_api.base, nullptr }`
/// (cc:516-:517) — the REAL non-BUILDING_SO arm feeds `&ipv6_api.base`,
/// the record whose NAME word is "icmp6". The Rust table const names
/// the TABLE: CD_ICMP6 (codec_api.rs:114 ladder entry "cd_icmp6",
/// RESIDENT — the census tripwire pins the file-base `cd_icmp6` <->
/// ladder `cd_icmp6` <-> struct `IPV6_API` TRIPLE; there is no
/// file-base-vs-extern flip on this row, the drift lives on the api
/// struct slot alone — the 18h cd_auth table-side contrast).
pub const CD_ICMP6: CodecTable = &[&IPV6_API];
