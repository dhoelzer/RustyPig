//! Port of `src/codecs/ip/cd_icmp4.cc` (645 L) — row 18i, the _tools/
//! daq3_harness_ ZERO-gate probe-only DAQ trio (udp 660 / icmp4 645 /
//! icmp6 518). Ground: snort3-src @ fe29cbe, md5
//! `12c1935ede670171715aeb970da42cc5` + wc 645 (re-measured THIS pass,
//! matches the pinned trio md5 in the row cheat sheet). DIR FACT:
//! `codecs/ip/` (same dir as the gre/auth lineage — NEVER misc/).
//!
//! THE GRAFT SEAM — DAQ, LEFT-OPEN (row 18i cheat sheet R1; plan row 20
//! = real DAQ): cc:130-:145 `valid_checksum_from_daq` reads
//! `daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA)` off the C
//! 17d-forward-declared `_daq_msg` (framework/codec.h :38 face ONLY —
//! the `daq.h` header EXISTS NOWHERE in ground: find whole tree = 0 real
//! hits; the ONLY face is the SYNTHETIC graft tools/daq3_harness/
//! copy/daq.h, md5 `73fdbc3983ca45246b554c46efdf1ad1`, 33 L, shapes
//! drawn MEASURED from cd_udp.cc:263-:270/:420, cd_icmp4.cc:132-:139 and
//! cd_icmp6.cc:125-:132 ONLY — NEVER ABI truth). The witness bodies live
//! in tools/daq3_harness/witness_daq.cc (54 L, ZERO-fn-witness precedent,
//! SYNTHETIC by design: null-meta fallback arm vs the probe-faked valid
//! pdd). THE GATE FACE: cc:159 `snort::get_network_policy()
//! ->icmp_checksums() && !valid_checksum_from_daq(raw)` rides the landed
//! `crate::main::policy::NetworkPolicy` (Default = checksum_eval
//! ALL|DEF, the policy.h :233 NSDMI the witness hand-seeds); the three
//! ground gate sites are cd_udp.cc:367 / cd_icmp4.cc:159 /
//! cd_icmp6.cc:197. DUAL FACE, ONE PACKET (vectors:26 `ICMP4
//! cksumbad-daqoff -> 0 dflags=8` vs vectors:28 `cksumbad-daqvalid -> 1
//! dflags=0`, probe_dec.cc:118-:125): dflags=8 = DECODE_ERR_CKSUM_ICMP
//! (decode_data.h:134, row-scoped const below); offset-mismatch fallback
//! (l4_offset vs raw.data-data, cc:137-:141) keeps the compared delta as
//! a PARAMETER — pointer math is probe-faked (witness
//! `daq_msg_get_data` returns &fake_payload[0]; a stack-window raw.data
//! can never sit at fake_payload, so l4_offset=0 mis-fires the FALSE arm
//! exactly as the udp twin face vectors:11 pins).
//!
//! PEG FACE — CITE, NEVER LAND (cheat sheet R2; small4 pgm tri-state
//! precedent, cd_gtp/cd_geneve PegInfo-comment posture): cc:42-:47
//! `PegInfo pegs[] = { {SUM,"bad_checksum","non-zero icmp checksums"},
//! {SUM,"checksum_bypassed","checksum calculations bypassed"},
//! {END,nullptr,nullptr} }`; cc:49-:53 `struct Stats { PegCount
//! bad_ip4_cksum; PegCount cksum_bypassed; }`; cc:55 `static
//! THREAD_LOCAL Stats stats`; the module get_pegs cc:101-:102 +
//! get_counts cc:104-:105 reinterpret-cast face; the increments
//! `stats.cksum_bypassed++` cc:143 + `stats.bad_ip4_cksum++` cc:166 and
//! the probe comment's "checksum_bypassed PEG face, NOT the
//! tunnel_bypass hook" (probe_dec.cc:10-:11, the 18h peg-vs-hook
//! correction; nm census 0 tunnel_bypass x3). NO Rust PegInfo machinery
//! lands anywhere in this file; the counters are never printed.
//!
//! THE 25-ROW RULES FACE vs THE 18-EVENT CENSUS CONTRAST: cc:57-:91
//! carries TWENTY-FIVE RuleMap rows (25 rows cc:59-:89 + `{ 0, nullptr }`
//! cc:90) — vectors:63 `ICMP4RULES 25 sid0=105 name=icmp4` (the NAME
//! face "icmp4", probe_dec.cc:176-:177 walk). But the decode face RAISES
//! ONLY 18 codec_event sites: cc:151/:188/:197/:206/:212/:235/:268/:282/
//! :291/:295/:299/:303/:307/:311/:317/:321/:325/:329 (sed census, ALL
//! distinct names). SEVEN table rows are TABLE-ONLY in this TU —
//! DECODE_ICMP_ORIG_IP_TRUNCATED/VER_MISMATCH/ORIG_DGRAM_LT_ORIG_IP/
//! PAYLOAD_LT_64/PAYLOAD_GT_576/WITH_FRAGOFFSET (the icmp4_ip embed
//! family, misc/cd_icmp4_ip.cc's later row) + DECODE_ICMP_DOS_ATTEMPT
//! (grep: zero call sites in 645 L). The gre MULTIPLE_ENCAPSULATION
//! table-only posture, x7 here. Arm-dense vectors face: 19 arms
//! vectors:23-:61 cover ALL 18 unique event names (probe_dec.cc:109
//! header), the shared-105 rider riding the extra arm.
//!
//! NAME FACE (lean-word rider): the NAME macro is `CD_ICMP4_NAME
//! "icmp4"` cc:37 while the C struct identifier is `icmp4_api` cc:615 —
//! lineage posture (cd_auth.rs AH_API = the C struct name): the Rust
//! api-record const lands as ICMP4_API, the table const as CD_ICMP4
//! (cc:640, REAL BUILDING_SO/SO_PUBLIC arms :637-:644; ladder entry
//! "cd_icmp4" RESIDENT codec_api.rs — NEVER re-touched). No file-vs-
//! table drift tripwire needed (grep-verified: table name == file base).
//!
//! ROW-SCOPED VOCAB (framework files byte-UNTOUCHED; 18e/18g posture):
//! protocol_ids.h / decode_data.h / ipv4.h / decode_data.h-PktType
//! numerics this TU touches land HERE with their h: cites; the sids all
//! ride the RESIDENT CodecSid walk (25/25 grep-verified
//! src/codecs/codec_module.rs:88-:210 — ZERO new sid constants).
//! eval-order posture: every codec_event rides its ground statement
//! slot (AddrTests fires BEFORE len+=4, MiscTests AFTER both switches,
//! the bcast/mcast pair BEFORE the smurf rider — vectors:34-:39 show
//! `EV 116 416`/`EV 116 440` and `EV 116 415`/`EV 116 440` in that
//! ground order, never sorted).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CODEC_IPOPT_RR_SEEN, CodecApiRecord, CodecData, CodecTable,
    CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, EncodeFlags, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId,
    QueueSink, RawData, protocol_id, UPD_COOKED, UPD_REBUILT_FRAG,
};
use crate::main::policy::NetworkPolicy;

/// cc:37 `#define CD_ICMP4_NAME "icmp4"` — the NAME side of the
/// lean-word pair (module doc): NAME "icmp4" vs the C struct `icmp4_api`
/// cc:615. vectors:63 + the FACE-A walk print this word.
pub const CD_ICMP4_NAME: &str = "icmp4";
/// cc:38 `#define CD_ICMP4_HELP "support for Internet control message
/// protocol v4"`
pub const CD_ICMP4_HELP: &str = "support for Internet control message protocol v4";

/// icmp4.h:30 `constexpr uint32_t ICMP_BASE_LEN = 4;` — the cc:149 short
/// guard (vectors:22-:23 `ICMP4 short3 -> 0`, raw.len 3 < 4 -> EV 426)
/// and the cc:216 len seed. (icmp4.h:31 `ICMP_UNREACH_DATA_LEN = 8` is
/// NOT touched by this TU — grep cd_icmp4.cc = 0 hits — it stays in the
/// header, no Rust landing.)
pub const ICMP_BASE_LEN: u32 = 4;

/// protocol_ids.h:130 `IP_EMBEDDED_IN_ICMP4 = 0x0103` (== 259, the
/// vectors:47 `ICMP4 sq8 -> 1 next=259` + vectors:61 `pmtu512 -> 1
/// next=259` faces) — the cc:246 next_prot_id write. ROW-SCOPED home
/// (framework/codec.rs byte-UNTOUCHED this row; the 18g
/// PROTOCOL_ID_ETHERTYPE_PPP precedent).
pub const PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4: ProtocolId = 0x0103;

/// decode_data.h:90 `#define PROTO_BIT__ICMP 0x000008` — the cc:257
/// proto_bits OR. Row-scoped home like the landed PROTO_BIT__GTP/TEREDO/
/// GENEVE trio (grep row files).
pub const PROTO_BIT__ICMP: u32 = 0x000008;

/// decode_data.h:134 `DECODE_ERR_CKSUM_ICMP = 0x00000008` (enum
/// DecodeFlags :129-:145 face) — the cc:167 `snort.decode_flags |=`
/// write; vectors:26 `dflags=8` is THIS number (the udp twin 4 is
/// decode_data.h:133, never touched here). u64 rides the landed
/// FragDecodeData.decode_flags shape.
pub const DECODE_ERR_CKSUM_ICMP: u64 = 0x00000008;

/// ipv4.h:37 `constexpr uint32_t IP4_BROADCAST = 0xffffffff;` — the
/// cc:267 dst compare ("check all 32 bits; all set so byte order is
/// irrelevant", the C comment rides): the vectors:34-:36 `bcast` arm is
/// the probe's w[16..19] = FF FF FF FF face (probe_dec.cc:135).
pub const IP4_BROADCAST: u32 = 0xffffffff;

/// ipv4.h:40 `constexpr uint8_t IP4_MULTICAST = 0x0E;  // ms nibble` —
/// the cc:281 msb compare: the vectors:37-:39 `mcast` arm is the
/// probe's w[16]=0xE0 face (probe_dec.cc:139) read LE-host.
pub const IP4_MULTICAST: u8 = 0x0E;

/// decode_data.h:45-:48 `enum class PktType : uint8_t { NONE, IP, TCP,
/// UDP, ICMP, ... }` — ICMP is the 4th enumerator = 4; cc:255 + cc:596
/// `snort.set_pkt_type(PktType::ICMP)` (the writer face is
/// decode_data.h:192) into the row-scoped seam field below. No PktType
/// vocabulary is landed framework-wide — this TU touches ONLY the ICMP
/// enumerator, so ONLY it lands.
pub const PKT_TYPE__ICMP: u8 = 4;

// ---- the cc:130-:145 DAQ face (row 18i graft seam, module doc) ----

/// graft copy/daq.h `#define DAQ_PKT_DECODE_OFFSET_INVALID (-1)` — the
/// cc:137 sentinel compare `pdd->l4_offset != DAQ_PKT_DECODE_OFFSET_
/// INVALID`. SYNTHETIC graft face (md5 73fdbc39... measured THIS pass),
/// NEVER ABI truth (plan row 20 re-cites the real SDK header).
pub const DAQ_PKT_DECODE_OFFSET_INVALID: i64 = -1;

/// The cc:132-:137 field face mirror of the graft `DAQ_PktDecodeData_t`
/// bitfield struct: `flags.bits.l4_checksum / .udp / .icmp / .l4` +
/// `int32_t l4_offset` (graft copy/daq.h shapes, MEASURED from the C use
/// sites, NOT ABI). THE ICMP4 GUARD HONESTY: cc:134 reads ONLY
/// l4_checksum, icmp, l4 — the `.udp` bit EXISTS in the face but this TU
/// never reads it (contrast the udp twin reading `.udp`); the field is
/// kept on the mirror, the guard keeps its ground shape (cheat sheet
/// "the udp flag bit is .icmp" — the read face here is .icmp).
#[derive(Copy, Clone, Default)]
pub struct DaqPdd {
    pub l4_checksum: bool,
    pub udp: bool, // face-only — never read by the cc:134 icmp4 guard
    pub icmp: bool,
    pub l4: bool,
    pub l4_offset: i64,
}

/// The decode-call DAQ parameter bundle (cheat sheet-sanctioned "or a
/// small struct" shape): the two valid_checksum_from_daq legs — the
/// meta handle and the probe-faked `raw.data - get_data()` delta — ride
/// as one Copy parameter (keeps decode at 7 args, inside the clippy
/// gate; no allowance needed).
#[derive(Copy, Clone, Default)]
pub struct DaqFace {
    pub pdd: Option<DaqPdd>,
    pub payload_delta: i64,
}

/// The row-scoped DecodeData seam (18h frag shape, row-scoped per the
/// 18e IpApiLite precedent): THIS TU reads/writes exactly three pieces
/// of `DecodeData` — `decode_flags` (cc:167 |=), the dst address via
/// `snort.ip_api.get_dst()->get_ip4_value()` (cc:264 — the ip_api
/// operand stays LEFT-OPEN, this field carries ONLY what cc:264 reads:
/// the dst `s_addr`-order u32; the probe set_ip4 arms feed it from the
/// 20-byte header window bytes 16-19, probe_dec.cc:32/:135/:139), and
/// `set_pkt_type` (cc:255/:596). The cc:256 `snort.icmph = icmph`
/// header-pointer stash is the LEFT-OPEN pointer face: the alias is the
/// raw byte window itself, no Rust slot lands (the probe never prints
/// it).
#[derive(Copy, Clone, Default)]
pub struct Icmp4DecodeData {
    pub decode_flags: u64,
    pub dst_ip4: u32, // network-order s_addr face (cc:264)
    pub pkt_type: u8,
}

/// The cc:173-:197 `union` field face + the cc:272-:283 `icmp_dun` face
/// as BYTE-OFFSET overlay reads of the header window (the gre cd_gre.rs
/// gre.h posture; icmp4.h:114-:198). Wire offsets: type @0 (h:116),
/// code @1 (h:117), csum @2-3 (h:118); `icmp_hun` @4-7: param.pptr @4
/// (h:124), gwaddr @4-7 (h:129), idseq.id @4-5 + idseq.seq @6-7
/// (h:131-:135), pmtu.nextmtu @6-7 (h:139-:143), rtradv.num_addrs @4 /
/// .wpa @5 / .lifetime @6-7 (h:145-:150); `icmp_dun` : ts.otime @8-11 /
/// rtime @12-15 / ttime @16-19 (h:167-:172), mask @8-11 (h:187).
/// `sizeof(ICMPHdr::icmp_hun.idseq)` = 4 (h:131-:135) is the cc:228
/// `len +=` operand.
///
/// The IcmpType vocabulary, icmp4.h IcmpType enum h:37-:55 as u8 consts
/// (NOT a Rust enum — the C enum is plain `enum IcmpType : uint8_t` and
/// its sibling aliases discriminants; also the ground header comment
/// h:33-:35 "do NOT add 'ICMP_' ... dnet macros" rides). ALL fifteen
/// enumerators are touched by this TU (switch-1 labels cc:175-:185/
/// :193-:194/:202-:203 + the full log switch cc:346-:557), so all
/// fifteen land — each with its h: line.
pub mod icmp_type {
    pub const ECHOREPLY: u8 = 0;         // h:39
    pub const DEST_UNREACH: u8 = 3;      // h:40
    pub const SOURCE_QUENCH: u8 = 4;     // h:41
    pub const REDIRECT: u8 = 5;          // h:42
    pub const ECHO_4: u8 = 8;            // h:43
    pub const ROUTER_ADVERTISE: u8 = 9;  // h:44
    pub const ROUTER_SOLICIT: u8 = 10;   // h:45
    pub const TIME_EXCEEDED: u8 = 11;    // h:46
    pub const PARAMETERPROB: u8 = 12;    // h:47
    pub const TIMESTAMP: u8 = 13;        // h:48
    pub const TIMESTAMPREPLY: u8 = 14;   // h:49
    pub const INFO_REQUEST: u8 = 15;     // h:50
    pub const INFO_REPLY: u8 = 16;       // h:51
    pub const ADDRESS: u8 = 17;          // h:52
    pub const ADDRESSREPLY: u8 = 18;     // h:53
    // h:54 `// NR_ICMP_TYPES = 18` is COMMENTED-OUT in the enum face —
    // nothing lands (the free constant NR_ICMP_TYPES h:226 is not
    // touched by this TU, grep = 0).
}

/// The IcmpCode vocabulary, icmp4.h IcmpCode enum h:58-:98 as u8 consts
/// — THE C ALIASED-DISCRIMINANT FACE: five enumerators share 0
/// (NET_UNREACH h:61 / SOURCE_QUENCH_CODE h:79 / REDIR_NET h:82 /
/// ECHO_CODE h:88 / TIMEOUT_TRANSIT h:91 / PARAM_BADIPHDR h:95) and
/// 1 recurs (REDIR_HOST h:83 / TIMEOUT_REASSY h:92 / PARAM_OPTMISSING
/// h:96) — a Rust enum CANNOT spell that, the const-module shape is
/// forced (the codec.rs "newtypes to keep C's aliased enumerators"
/// posture verbatim). Which enumerators land: exactly those THIS TU
/// touches — the EIGHT decode/misc code reads (FRAG_NEEDED cc:232,
/// REDIR_HOST cc:298, REDIR_NET cc:302, SOURCE_QUENCH_CODE cc:310,
/// ECHO_CODE cc:316, PKT_FILTERED_HOST cc:324, PKT_FILTERED cc:320,
/// PKT_FILTERED_NET cc:328) plus the log-switch enumerators (the whole
//  UNREACHABLE block cc:358-:422 + REDIR cc:438-:452 + TIMEOUT
//  cc:484-:490 + PARAM cc:502-:513) = ALL 26 ground enumerators land;
//  each cites its h: line.
pub mod icmp_code {
    /* Codes for ICMP UNREACHABLES (3) — h:60 comment rides */
    pub const NET_UNREACH: u8 = 0;       // h:61
    pub const HOST_UNREACH: u8 = 1;      // h:62
    pub const PROT_UNREACH: u8 = 2;      // h:63
    pub const PORT_UNREACH: u8 = 3;      // h:64
    pub const FRAG_NEEDED: u8 = 4;       // h:65  (cc:232 pmtu guard)
    pub const SR_FAILED: u8 = 5;         // h:66
    pub const NET_UNKNOWN: u8 = 6;       // h:67
    pub const HOST_UNKNOWN: u8 = 7;      // h:68
    pub const HOST_ISOLATED: u8 = 8;     // h:69
    pub const PKT_FILTERED_NET: u8 = 9;  // h:70  (cc:328)
    pub const PKT_FILTERED_HOST: u8 = 10; // h:71 (cc:324)
    pub const NET_UNR_TOS: u8 = 11;      // h:72
    pub const HOST_UNR_TOS: u8 = 12;     // h:73
    pub const PKT_FILTERED: u8 = 13;     // h:74  (cc:320)
    pub const PREC_VIOLATION: u8 = 14;   // h:75
    pub const PREC_CUTOFF: u8 = 15;      // h:76

    /* Code for ICMP Source Quench (4) — h:78 comment rides */
    pub const SOURCE_QUENCH_CODE: u8 = 0; // h:79 (= NET_UNREACH)

    /* Codes for an ICMP Redirect (5) — h:81 comment rides */
    pub const REDIR_NET: u8 = 0;         // h:82  (cc:302)
    pub const REDIR_HOST: u8 = 1;        // h:83  (cc:298)
    pub const REDIR_TOS_NET: u8 = 2;     // h:84
    pub const REDIR_TOS_HOST: u8 = 3;    // h:85

    /* Codes for ICMP Echo (8) — h:87 comment rides */
    pub const ECHO_CODE: u8 = 0;         // h:88  (cc:316 smurf)

    /* Codes for ICMP time exceeded (11) — h:90 comment rides */
    pub const TIMEOUT_TRANSIT: u8 = 0;   // h:91
    pub const TIMEOUT_REASSY: u8 = 1;    // h:92

    /* code for ICMP Parameter Problem (12) — h:94 comment rides */
    pub const PARAM_BADIPHDR: u8 = 0;    // h:95
    pub const PARAM_OPTMISSING: u8 = 1;  // h:96
    pub const PARAM_BAD_LENGTH: u8 = 2;  // h:97
}

/// cc:57-:91 `static const RuleMap icmp4_rules[]` — THE 25-ROW TABLE +
/// the `{ 0, nullptr }` terminator cc:90 (26 entries: `[RuleMap; 26]`).
/// ALL 25 sids are RESIDENT CodecSid enumerators (grep census THIS pass
/// src/codecs/codec_module.rs: DECODE_ICMP_DGRAM_LT_ICMPHDR :88 =105
/// (h:69), LT_TIMESTAMPHDR :89 =106 (h:70), LT_ADDRHDR :90 =107 (h:71),
/// ORIG_IP_* :125-:130 =250-255 (h:114-:119), DST_MULTICAST :174 =415
/// (h:169), DST_BROADCAST :175 =416 (h:170), TYPE_OTHER :176 =418
/// (h:171), PING_NMAP :192 =434 (h:187), ICMPENUM :193 =435 (h:188),
/// REDIRECT_HOST :194 =436, REDIRECT_NET :195 =437, TRACEROUTE_IPOPTS
/// :196 =438, SOURCE_QUENCH :197 =439, BROADSCAN_SMURF_SCANNER :198
/// =440, DST_UNREACH_ADMIN_PROHIBITED :199 =441, DST_HOST_PROHIBITED
/// :200 =442, DST_NET_PROHIBITED :201 =443, PATH_MTU_DOS :209 =451
/// (h:204), DOS_ATTEMPT :210 =452 (h:205), HDR_TRUNC :184 =426 (h:179))
/// — ZERO new constants. vectors:63 `ICMP4RULES 25 sid0=105 name=icmp4`
/// (sid0 = TRUNC-side 105 FIRST row, the cc:59 slot) . The module doc
/// carries the 25-vs-18 site census. Multi-line C string concats
/// (cc:64-:65, cc:79-:86) land as ONE Rust string each (cd_frag/cd_auth
/// precedent).
pub const ICMP4_RULES: [RuleMap; 26] = [
    RuleMap {
        sid: CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, // 105
        msg: Some("ICMP header truncated"), // cc:59 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR as u32, // 106
        msg: Some("ICMP timestamp header truncated"), // cc:60 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_DGRAM_LT_ADDRHDR as u32, // 107
        msg: Some("ICMP address header truncated"), // cc:61 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_ORIG_IP_TRUNCATED as u32, // 250 (TABLE-ONLY)
        msg: Some("ICMP original IP header truncated"), // cc:62 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_ORIG_IP_VER_MISMATCH as u32, // 251 (TABLE-ONLY)
        msg: Some("ICMP version and original IP header versions differ"), // cc:63
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP as u32, // 252 (TABLE-ONLY)
        // cc:64-:65 the TWO-LITERAL concat lands as ONE string:
        msg: Some("ICMP original datagram length < original IP header length"),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_ORIG_PAYLOAD_LT_64 as u32, // 253 (TABLE-ONLY)
        msg: Some("ICMP original IP payload < 64 bits"), // cc:66 verbatim
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_ORIG_PAYLOAD_GT_576 as u32, // 254 (TABLE-ONLY)
        msg: Some("ICMP original IP payload > 576 bytes"), // cc:67
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET as u32, // 255 (TABLE-ONLY)
        msg: Some("ICMP original IP fragmented and offset not 0"), // cc:68
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP4_DST_MULTICAST as u32, // 415
        msg: Some("ICMP4 packet to multicast dest address"), // cc:69
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP4_DST_BROADCAST as u32, // 416
        msg: Some("ICMP4 packet to broadcast dest address"), // cc:70
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP4_TYPE_OTHER as u32, // 418
        msg: Some("ICMP4 type other"), // cc:71
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_PING_NMAP as u32, // 434
        msg: Some("ICMP ping Nmap"), // cc:72
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_ICMPENUM as u32, // 435
        msg: Some("ICMP icmpenum v1.1.1"), // cc:73
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_REDIRECT_HOST as u32, // 436
        msg: Some("ICMP redirect host"), // cc:74
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_REDIRECT_NET as u32, // 437
        msg: Some("ICMP redirect net"), // cc:75
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_TRACEROUTE_IPOPTS as u32, // 438
        msg: Some("ICMP traceroute ipopts"), // cc:76
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_SOURCE_QUENCH as u32, // 439
        msg: Some("ICMP source quench"), // cc:77
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_BROADSCAN_SMURF_SCANNER as u32, // 440
        msg: Some("broadscan smurf scanner"), // cc:78
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED as u32, // 441
        msg: Some(
            "ICMP destination unreachable communication administratively prohibited",
        ), // cc:79-:80
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED as u32, // 442
        // cc:81-:83 the THREE-LITERAL concat ("...host is " "administratively
        // prohibited") lands as ONE string:
        msg: Some(
            "ICMP destination unreachable communication with destination host is \
             administratively prohibited",
        ),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED as u32, // 443
        // cc:84-:86 the THREE-LITERAL concat, same face:
        msg: Some(
            "ICMP destination unreachable communication with destination network is \
             administratively prohibited",
        ),
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_PATH_MTU_DOS as u32, // 451
        msg: Some("ICMP path MTU denial of service attempt"), // cc:87
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP_DOS_ATTEMPT as u32, // 452 (TABLE-ONLY)
        msg: Some("Linux ICMP header DOS attempt"), // cc:88
    },
    RuleMap {
        sid: CodecSid::DECODE_ICMP4_HDR_TRUNC as u32, // 426
        msg: Some("truncated ICMP4 header"), // cc:89
    },
    RuleMap { sid: 0, msg: None }, // cc:90 terminator
];

/// cc:93-:106 `class Icmp4Module : public BaseCodecModule` — the plain
/// 2-ARG ctor face cc:96 `BaseCodecModule(CD_ICMP4_NAME, CD_ICMP4_HELP)`
/// (contrast the 18i udp twin: udp has params cc:62, icmp4 has NONE —
/// cheat sheet "plain 2-arg BaseCodecModule, NO params"). get_rules
/// override cc:98-:99 returns the table. get_pegs cc:101-:102 +
/// get_counts cc:104-:105 are the PEG CITE face (module doc) — NO Rust
/// landing. vectors:63 walks this module: sid0=105, 25 rows, NAME
/// "icmp4" (m->get_name() = CD_ICMP4_NAME).
#[derive(Debug)]
pub struct Icmp4Module {
    pub base: BaseCodecModule,
}

impl Icmp4Module {
    /// cc:96 the 2-arg BaseCodecModule ctor face.
    pub fn new() -> Icmp4Module {
        Icmp4Module {
            base: BaseCodecModule::new(CD_ICMP4_NAME, CD_ICMP4_HELP),
        }
    }

    /// cc:98-:99 `{ return icmp4_rules; }`.
    pub fn get_rules() -> &'static [RuleMap] {
        &ICMP4_RULES
    }

    /// Module::get_name face — vectors:63 `name=icmp4` (the NAME word
    /// on the RULES print, riding the lean-word record).
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

impl Default for Icmp4Module {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:108-:124 `class Icmp4Codec : public Codec` — the private/public
/// method map: get_protocol_ids cc:113 -> `get_protocol_ids`, decode
/// cc:114 -> `decode`, update cc:115-:116 -> `update`, format
/// cc:117 -> `format`, log cc:118 -> `log`; the PRIVATES
/// valid_checksum_from_daq cc:121 -> `valid_checksum_from_daq`
/// (inline static, def cc:130-:145), ICMP4AddrTests cc:122 ->
/// `icmp4_addr_tests` (cc:262-:283), ICMP4MiscTests cc:123 ->
/// `icmp4_misc_tests` (cc:285-:330). The Codec base name is
/// CD_ICMP4_NAME cc:111.
#[derive(Default)]
pub struct Icmp4Codec;

impl Icmp4Codec {
    /// cc:111 `Icmp4Codec() : Codec(CD_ICMP4_NAME) { }`
    pub fn new() -> Icmp4Codec {
        Icmp4Codec
    }

    /// cc:113 decl / cc:127-:128 def: `v.emplace_back(ProtocolId::ICMPV4)`
    /// — the LANDED protocol_id::ICMPV4 = 1 (codec.rs:131,
    /// protocol_ids.h walk) — reused, no new const. vectors:62
    /// `ICMP4PID 1 n=1` (probe_dec.cc:175).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::ICMPV4); // cc:128
    }

    /// cc:130-:145 `inline bool Icmp4Codec::valid_checksum_from_daq
    /// (const RawData&)` — VERBATIM shape on the graft seam (module
    /// doc): `daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA)`
    /// cc:132-:133 lands as the `pdd: Option<DaqPdd>` parameter (None =
    /// the witness null-meta fallback arm); the cc:134 guard
    /// `!pdd->flags.bits.l4_checksum || !pdd->flags.bits.icmp ||
    /// !pdd->flags.bits.l4` reads the .icmp bit (NOT .udp — the
    /// DaqPdd doc); the cc:136 comment "Sanity check to make sure we're
    /// talking about the same thing if offset is available" rides; the
    /// cc:137-:141 offset arm compares `daq_payload_delta` =
    /// `raw.data - daq_msg_get_data(raw.daq_msg)` — the C pointer delta
    /// is probe-faked (witness body returns the static fake_payload), so
    /// the delta rides as a parameter (cheat sheet: "the Rust arm
    /// carries the compared offset as a field/param and compares").
    /// cc:143 `stats.cksum_bypassed++` = the PEG cite (module doc).
    #[inline]
    fn valid_checksum_from_daq(pdd: Option<DaqPdd>, daq_payload_delta: i64) -> bool {
        // cc:134 the four-way truth guard (`!pdd ||` = the None arm):
        let pdd = match pdd {
            Some(p) if p.l4_checksum && p.icmp && p.l4 => p,
            _ => return false, // cc:135
        };
        // cc:137-:142:
        if pdd.l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID && daq_payload_delta != pdd.l4_offset
        {
            return false; // cc:141
        }
        // cc:143 stats.cksum_bypassed++ (PEG, cite)
        true // cc:144
    }

    /// cc:147-:260 out-of-line decode, statement order VERBATIM. The
    /// `netpol` operand carries the cc:159 `snort::get_network_policy()`
    /// read (the landed NetworkPolicy; vectors:26 vs :28 dual face);
    /// `daq` carries the cc:159 `!valid_checksum_from_daq(raw)` leg
    /// (DaqFace: pdd + payload_delta); `snort` is the row-scoped
    /// DecodeData seam. The 18 codec_event sites ride the local
    /// `codec_event_icmp4` wrapper (the gre codec_event_gre pattern).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut Icmp4DecodeData,
        netpol: &NetworkPolicy,
        daq: DaqFace,
        sink: QueueSink,
    ) -> bool {
        // cc:149-:153: raw.len < ICMP_BASE_LEN (4) -> 426 + false.
        // vectors:22-:23 `ICMP4 short3 -> 0` (the z[3] all-zero face —
        // the cksum gate sits AFTER this guard, probe_dec.cc:112 note
        // "all-zero dgram: cksum_add fold = ~0 = 0 -> gate passes"
        // rides as the why the vectors line carries no dflags).
        if raw.len < ICMP_BASE_LEN {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP4_HDR_TRUNC as u32, &mut *sink); // cc:151
            return false; // cc:152
        }

        // cc:155-:156 "/* set the header ptr first */" — the ICMPHdr
        // overlay (field face = byte offsets, the gre posture above).
        let icmph = raw.data;
        let typ = *icmph.first().unwrap_or(&0);    // icmph->type h:116
        let code = *icmph.get(1).unwrap_or(&0);    // icmph->code h:117

        // cc:157 `uint16_t len = 0;` — the 0 initializer is DEAD in
        // ground: the only write before any read is cc:216 `len =
        // icmp::ICMP_BASE_LEN` (sed census: cc:216 lands before the
        // first read in every switch path). Documented dead-face pin
        // (the 18g GRE_V1_HEADER_LEN precedent: dead-in-C face kept
        // cited, not coded); the Rust binding starts at the first
        // LIVE write.
        let mut len: u16;

        // cc:159 THE GATE: icmp_checksums() && !valid_from_daq (the
        // three-site twin udp:367 / icmp4:159 / icmp6:197).
        if netpol.icmp_checksums()
            && !Self::valid_checksum_from_daq(daq.pdd, daq.payload_delta)
        {
            // cc:161 `uint16_t csum = checksum::cksum_add(icmph,
            // raw.len);` — the LANDED 18b public 2-arg fold
            // (checksum.rs:434, the gre cksum_add consumer ride).
            let csum = crate::codecs::checksum::cksum_add(icmph, raw.len as usize);

            // cc:163 the cppcheck-suppress comment "zero is the valid
            // packet checksum result" rides. THE DISTINCT COOKED
            // GUARD — cc:164 is ONE ground if-statement `if (csum &&
            // !codec.is_cooked())` (the VALID face, contrast the udp
            // `!valid &&` shape + inner if cc:414-:419 — cheat sheet
            // "keep each distinct"): the && short-circuit keeps the C
            // operand order exactly.
            if csum != 0 && !codec.is_cooked() {
                // cc:166 stats.bad_ip4_cksum++ (PEG, cite)
                snort.decode_flags |= DECODE_ERR_CKSUM_ICMP; // cc:167
                return false; // cc:168 — vectors:26 dflags=8 face
            }
        }

        // cc:172-:214 THE FIRST TYPE SWITCH: three minimum-length
        // groups + default (the group arms EVENT+RETURN; the default
        // EVENTS and BREAKS — decode continues). Or-pattern arms spell
        // the C fall-through label stacks; the const-module names ride
        // as const-path patterns.
        match typ {
            // cc:174 "fall through ..." — the ELEVEN-label case
            // (SOURCE_QUENCH :175, DEST_UNREACH :176, REDIRECT :177,
            // TIME_EXCEEDED :178, PARAMETERPROB :179, ECHOREPLY :180,
            // ECHO_4 :181, ROUTER_ADVERTISE :182, ROUTER_SOLICIT :183,
            // INFO_REQUEST :184, INFO_REPLY :185): the 8-byte guard.
            icmp_type::SOURCE_QUENCH
            | icmp_type::DEST_UNREACH
            | icmp_type::REDIRECT
            | icmp_type::TIME_EXCEEDED
            | icmp_type::PARAMETERPROB
            | icmp_type::ECHOREPLY
            | icmp_type::ECHO_4
            | icmp_type::ROUTER_ADVERTISE
            | icmp_type::ROUTER_SOLICIT
            | icmp_type::INFO_REQUEST
            | icmp_type::INFO_REPLY => {
                if raw.len < 8 {
                    codec_event_icmp4(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ICMPHDR as u32, &mut *sink); // cc:188
                    return false; // cc:189 — vectors:24-:25 the type3 4-byte face
                }
                // cc:191 break
            }

            // cc:193-:194 the TIMESTAMP pair, the 20-byte guard:
            icmp_type::TIMESTAMP | icmp_type::TIMESTAMPREPLY => {
                if raw.len < 20 {
                    codec_event_icmp4(codec, CodecSid::DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR as u32, &mut *sink); // cc:197
                    return false; // cc:198 — vectors:40-:41 tstamp8
                }
                // cc:200 break
            }

            // cc:202-:203 the ADDRESS (mask) pair, the 12-byte guard:
            icmp_type::ADDRESS | icmp_type::ADDRESSREPLY => {
                if raw.len < 12 {
                    codec_event_icmp4(codec, CodecSid::DECODE_ICMP_DGRAM_LT_ADDRHDR as u32, &mut *sink); // cc:206
                    return false; // cc:207 — vectors:42-:43 addr8
                }
                // cc:209 break
            }

            // cc:211-:213 default: EVENT + break (NO return — the
            // vectors:44-:45 `type99 -> 1` face proves decode proceeds
            // on an unknown type; EV 418 fired first).
            _ => {
                codec_event_icmp4(codec, CodecSid::DECODE_ICMP4_TYPE_OTHER as u32, &mut *sink); // cc:212
            }
        }

        // cc:216 `len = icmp::ICMP_BASE_LEN;`
        len = ICMP_BASE_LEN as u16;

        // cc:218-:251 THE SECOND TYPE SWITCH — TWO FALL-THROUGH FACES:
        // (1) cc:220-:222 the 8: case ECHO_4 calls ICMP4AddrTests THEN
        // falls into case ECHOREPLY (cc:224) whose body is the idseq
        // size bump; (2) cc:231-:238 case DEST_UNREACH runs the pmtu
        // guard (EVENT, no return) THEN falls into the four-label
        // block cc:240-:243. Rust has no C fall-through: the shared
        // tails land DUPLICATED inside the arms, statement-verbatim
        // (the cd_gtp update_gtp_length fall-through posture) — same
        // observable semantics, cited per line.
        match typ {
            // cc:220-:229: AddrTests FIRST (eval order: the bcast EV
            // 416 / mcast EV 415 ride BEFORE any len bookkeeping), then
            // the cc:222 "fall through" into the cc:224-:228 body —
            // the "/* setup the pkt id and seq numbers */" + "/* add
            // the size of the echo ext ... */" comments cc:226-:227
            // cite the idseq slot:
            icmp_type::ECHO_4 => {
                Self::icmp4_addr_tests(snort, codec, &mut *sink); // cc:221
                len = len.wrapping_add(4);
                // cc:228 `len += sizeof(ICMPHdr::icmp_hun.idseq)` == 4
                // (h:131-:135 idseq{u16 id; u16 seq;}).
            }

            icmp_type::ECHOREPLY => {
                // cc:224-:228 (the fall-into target, cc:221's tail
                // duplicated above):
                len = len.wrapping_add(4); // cc:228
            }

            // cc:231-:247: the DEST_UNREACH pmtu guard then the
            // cc:238 "/* Fall through */" into the four-label extra-4
            // block (the tail duplicated):
            icmp_type::DEST_UNREACH => {
                // cc:232-:236 `(code == FRAG_NEEDED) && (ntohs(nextmtu)
                // < 576)` -> EV 451 (no return): the && operand order
                // kept — the nextmtu read fires ONLY once code matches
                // (gre short-circuit posture). The pmtu512 face
                // p[6..8]={2,0} = BE 512 < 576 (probe_dec.cc:172-:174,
                // vectors:60-:61 `EV 116 451` + `next=259`).
                if code == icmp_code::FRAG_NEEDED
                    && Self::ntoh16(icmph, 6) < 576 // s_icmp_nextmtu @6-7 (h:139-:143 + h:159), memcpy+ntohs == BE read
                {
                    codec_event_icmp4(codec, CodecSid::DECODE_ICMP_PATH_MTU_DOS as u32, &mut *sink); // cc:235
                }
                // cc:238 fall-through ↓ (cc:240-:247 body duplicated):
                len = len.wrapping_add(4);                         // cc:245
                codec.next_prot_id = PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4; // cc:246
            }

            // cc:240-:247 SOURCE_QUENCH :240, REDIRECT :241,
            // TIME_EXCEEDED :242, PARAMETERPROB :243 — the "/* account
            // for extra 4 bytes in header */" cc:244 comment rides: the
            // sq8 face (vectors:46-:47 `EV 116 439` before, `next=259`
            // after) and every embed-carrier.
            icmp_type::SOURCE_QUENCH
            | icmp_type::REDIRECT
            | icmp_type::TIME_EXCEEDED
            | icmp_type::PARAMETERPROB => {
                len = len.wrapping_add(4);                         // cc:245
                codec.next_prot_id = PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4; // cc:246
            }

            // cc:249-:250 default: break (no write — e.g. the ECHO
            // pair, timestamp/address pair, type99 keep next at init).
            _ => {}
        }

        // cc:253 `ICMP4MiscTests(icmph, codec, (uint16_t)raw.len - len)`
        // — the u16 trunc-then-subtract face kept wrapping:
        Self::icmp4_misc_tests(icmph, codec, (raw.len as u16).wrapping_sub(len), &mut *sink);

        // cc:255 `snort.set_pkt_type(PktType::ICMP)`:
        snort.pkt_type = PKT_TYPE__ICMP;
        // cc:256 `snort.icmph = icmph` — the LEFT-OPEN pointer stash
        // (the Icmp4DecodeData doc: the alias is the byte window).
        // cc:257-:258 the success pair (vectors lyr/next faces):
        codec.proto_bits |= PROTO_BIT__ICMP; // cc:257
        codec.lyr_len = len;                 // cc:258 (u16 field direct)
        true                                 // cc:259
    }

    /// cc:262-:283 `void Icmp4Codec::ICMP4AddrTests(const DecodeData&
    /// snort, const CodecData& codec)` — THE LEAN POSTURE: cc:270-:271
    /// "don't use htonl for speed reasons - s_addr is always in network
    /// order" rides; cc:272-:276 THE WORDS_BIGENDIAN PAIR —
    /// `#ifdef WORDS_BIGENDIAN` cc:273 `msb_dst = (uint8_t)(dst >> 24)`
    /// is CITED NOT PORTED (the harness host is pinned LE — grep
    /// WORDS_BIGENDIAN = 0 across the lineage ports); the cc:275 `#else`
    /// arm `msb_dst = (uint8_t)(dst & 0xff)` lands. cc:279 `msb_dst >>=
    /// 4` then the 0x0E compare ("check the 'msn'" comment cc:278).
    /// vectors:34-:39 the bcast (dst all-FF -> 416 only, msn 0xF) and
    /// mcast (w[16]=0xE0 LE-host -> msb 0xE0>>4 = 0xE -> 415) faces
    /// probe_dec.cc:133-:140.
    fn icmp4_addr_tests(snort: &Icmp4DecodeData, codec: &CodecData, sink: QueueSink) {
        // cc:264 `uint32_t dst = snort.ip_api.get_dst()->get_ip4_value()`
        // — the seam field (network-order s_addr u32).
        let dst = snort.dst_ip4;

        // cc:266 "check all 32 bits; all set so byte order is
        // irrelevant ..." rides as the why the == works on any host:
        if dst == IP4_BROADCAST {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP4_DST_BROADCAST as u32, &mut *sink); // cc:268
        }

        // cc:275 (the #else LE arm; the #ifdef BE arm cc:273 cited
        // above, never ported):
        let mut msb_dst: u8 = (dst & 0xff) as u8;

        // cc:278-:279 "check the 'msn' (most significant nibble) ...":
        msb_dst >>= 4;

        if msb_dst == IP4_MULTICAST {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP4_DST_MULTICAST as u32, &mut *sink); // cc:282
        }
    }

    /// cc:285-:330 `void Icmp4Codec::ICMP4MiscTests(const ICMPHdr*
    /// const, const CodecData&, const uint16_t dsize)` — ALL TEN ground
    /// if-statements VERBATIM (measured count: ten ifs at cc:289, :293,
    /// :297, :301, :305, :309, :313, :319, :323, :327 — the cheat
    /// sheet's "eleven" is CORRECTED by the sed census; twenty
    /// conjuncts total, the smurf check cc:313-:316 carrying FOUR),
    /// never sorted: events fire ONLY in this source order (the
    /// enum666 face EV 434 THEN 435, vectors:29-:31; the bcast/mcast
    /// pair riding 440 AFTER the AddrTests word, vectors:34-:39). Only
    /// `s_icmp_seq` joins the byte-face reads: @6-7 HOST-ORDER load
    /// (h:134 + h:156) — ground cc:294 / cc:315 compare the RAW struct
    /// member with NO ntohs (the probe's wire bytes 9A 02 are 666
    /// host-order, probe_dec.cc:127, the vectors enum666 EV 435 proof;
    /// the gre ntohs-collapse does NOT apply at this site — operand
    /// identity, the LE-host pin as everywhere).
    fn icmp4_misc_tests(icmph: &[u8], codec: &CodecData, dsize: u16, sink: QueueSink) {
        let typ = *icmph.first().unwrap_or(&0);
        let code = *icmph.get(1).unwrap_or(&0);
        // s_icmp_seq h:134 host-order load (doc above):
        let seq = u16::from_le_bytes([*icmph.get(6).unwrap_or(&0), *icmph.get(7).unwrap_or(&0)]);

        // cc:289-:291 the zero-payload echo (the vectors enum666 arm
        // fires THIS then the ICMPENUM below, probe_dec.cc:127-:129):
        if dsize == 0 && typ == icmp_type::ECHO_4 {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP_PING_NMAP as u32, &mut *sink); // cc:291
        }

        // cc:293-:295 seq 666 = icmpenum v1.1.1 (host-order compare,
        // doc above):
        if dsize == 0 && seq == 666 {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP_ICMPENUM as u32, &mut *sink); // cc:295
        }

        // cc:297-:299 redirect host (code1 face vectors:48-:49):
        if typ == icmp_type::REDIRECT && code == icmp_code::REDIR_HOST {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP_REDIRECT_HOST as u32, &mut *sink); // cc:299
        }

        // cc:301-:303 redirect net (code0 face vectors:50-:51):
        if typ == icmp_type::REDIRECT && code == icmp_code::REDIR_NET {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP_REDIRECT_NET as u32, &mut *sink); // cc:303
        }

        // cc:305-:307 the traceroute face: ECHOREPLY + CODEC_IPOPT_RR_SEEN
        // (0x0010, the LANDED codec.rs:46 face — the vectors:52-:53
        // arm pre-sets c.codec_flags |= 0x0010, probe_dec.cc:161):
        if typ == icmp_type::ECHOREPLY && (codec.codec_flags & CODEC_IPOPT_RR_SEEN) != 0 {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP_TRACEROUTE_IPOPTS as u32, &mut *sink); // cc:307
        }

        // cc:309-:311 source quench code 0 (the sq8 face, vectors:46-:47):
        if typ == icmp_type::SOURCE_QUENCH && code == icmp_code::SOURCE_QUENCH_CODE {
            codec_event_icmp4(codec, CodecSid::DECODE_ICMP_SOURCE_QUENCH as u32, &mut *sink); // cc:311
        }

        // cc:313-:317 the FOUR-conjunct smurf face (dsize 4, echo, seq
        // 0, code 0 — vectors:32-:33 + the 415/416 riders' shared EV
        // 440, vectors:34-:39):
        if dsize == 4
            && typ == icmp_type::ECHO_4
            && seq == 0
            && code == icmp_code::ECHO_CODE
        {
            codec_event_icmp4(
                codec,
                CodecSid::DECODE_ICMP_BROADSCAN_SMURF_SCANNER as u32,
                &mut *sink,
            ); // cc:317
        }

        // cc:319-:321 unreach code 13 (vectors:54-:55):
        if typ == icmp_type::DEST_UNREACH && code == icmp_code::PKT_FILTERED {
            codec_event_icmp4(
                codec,
                CodecSid::DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED as u32,
                &mut *sink,
            ); // cc:321
        }

        // cc:323-:325 unreach code 10 (vectors:56-:57):
        if typ == icmp_type::DEST_UNREACH && code == icmp_code::PKT_FILTERED_HOST {
            codec_event_icmp4(
                codec,
                CodecSid::DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED as u32,
                &mut *sink,
            ); // cc:325
        }

        // cc:327-:329 unreach code 9 (vectors:58-:59):
        if typ == icmp_type::DEST_UNREACH && code == icmp_code::PKT_FILTERED_NET {
            codec_event_icmp4(
                codec,
                CodecSid::DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED as u32,
                &mut *sink,
            ); // cc:329
        }
    }

    /// cc:336-:559 out-of-line log — the BIGGER logger block of the row
    /// (the whole cc:332-:334 "L O G G E R" banner rides as this
    /// doc). CITED-NEVER-VECTORIZED (the probe never calls log() — no
    /// vectors line has one; the 18d eth / 18g gre / 18h frag posture):
    /// every TextLog_Print lands as one ordered sink(format!) with the
    /// GROUND format string verbatim (`%d`/`%u` = decimal, `0x%08X` =
    /// upper-hex), every TextLog_Puts as one plain sink. The head pair
    /// cc:343-:344 fires for EVERY type before the switch. The FOUR
    /// nested code switches (DEST_UNREACH cc:356-:427, REDIRECT
    /// cc:436-:456, TIME_EXCEEDED cc:482-:494, PARAMETERPROB
    /// cc:500-:517) port statement-for-statement. THE LEFT-OPEN SEAM:
    /// cc:458-:459 `snort_inet_ntop(AF_INET, &icmph->s_icmp_gwaddr
    /// .s_addr, buf, sizeof(buf))` — NEVER libc: the dotted quad is
    /// hand-formatted from the four gwaddr bytes @4-7 (h:129, LE-host
    /// octet order = wire order, exactly what inet_ntop prints); the cc
    /// :341-:342 buffer comment "32 digits plus 7 colons and a null
    /// byte" + `char buf[8*4 + 7 + 1]` are pin-only (the only consumer
    /// is this one ntop arm). The IGNORED third C param (cc:337
    /// `const uint16_t` UNNAMED) is the never-read posture — no Rust
    /// slot.
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        // cc:339 the ICMPHdr overlay:
        let icmph = raw_pkt;
        let typ = *icmph.first().unwrap_or(&0);
        let code = *icmph.get(1).unwrap_or(&0);

        // cc:343 TextLog_Print "Type:%d  Code:%d  " (TWO trailing
        // spaces kept exact):
        sink(format!("Type:{}  Code:{}  ", typ, code));
        // cc:344 TextLog_Puts "\n\t":
        sink("\n\t".to_string());

        match typ {
            // cc:348-:352 ECHOREPLY:
            icmp_type::ECHOREPLY => {
                sink(format!(
                    "ID:{}  Seq:{}  ",
                    Self::ntoh16(icmph, 4), // cc:349 ntohs s_icmp_id @4-5
                    Self::ntoh16(icmph, 6), // cc:350 ntohs s_icmp_seq @6-7
                )); // cc:349 "ID:%d  Seq:%d  "
                sink("ECHO REPLY".to_string()); // cc:351
            }

            // cc:354-:428 DEST_UNREACH + the nested code switch
            // cc:356-:427 (sixteen arms + UNKNOWN default):
            icmp_type::DEST_UNREACH => {
                sink("DESTINATION UNREACHABLE: ".to_string()); // cc:355 (trailing space)
                match code {
                    icmp_code::NET_UNREACH => sink("NET UNREACHABLE".to_string()),   // cc:359
                    icmp_code::HOST_UNREACH => sink("HOST UNREACHABLE".to_string()), // cc:363
                    icmp_code::PROT_UNREACH => sink("PROTOCOL UNREACHABLE".to_string()), // cc:367
                    icmp_code::PORT_UNREACH => sink("PORT UNREACHABLE".to_string()), // cc:371
                    icmp_code::FRAG_NEEDED => {
                        // cc:375-:377 the TWO-literal concat lands as
                        // ONE: "FRAGMENTATION NEEDED, DF SET, NEXT LINK
                        // MTU: %u" — ntohs(s_icmp_nextmtu) @6-7:
                        sink(format!(
                            "FRAGMENTATION NEEDED, DF SET, NEXT LINK MTU: {}",
                            Self::ntoh16(icmph, 6), // cc:377
                        ));
                    }
                    icmp_code::SR_FAILED => sink("SOURCE ROUTE FAILED".to_string()),   // cc:381
                    icmp_code::NET_UNKNOWN => sink("NET UNKNOWN".to_string()),         // cc:385
                    icmp_code::HOST_UNKNOWN => sink("HOST UNKNOWN".to_string()),       // cc:389
                    icmp_code::HOST_ISOLATED => sink("HOST ISOLATED".to_string()),     // cc:393
                    icmp_code::PKT_FILTERED_NET => {
                        // cc:397 verbatim:
                        sink("ADMINISTRATIVELY PROHIBITED NETWORK FILTERED".to_string());
                    }
                    icmp_code::PKT_FILTERED_HOST => {
                        // cc:401 verbatim:
                        sink("ADMINISTRATIVELY PROHIBITED HOST FILTERED".to_string());
                    }
                    icmp_code::NET_UNR_TOS => sink("NET UNREACHABLE FOR TOS".to_string()),  // cc:405
                    icmp_code::HOST_UNR_TOS => sink("HOST UNREACHABLE FOR TOS".to_string()), // cc:409
                    icmp_code::PKT_FILTERED => {
                        // cc:413 verbatim (the COMMA kept):
                        sink("ADMINISTRATIVELY PROHIBITED, PACKET FILTERED".to_string());
                    }
                    icmp_code::PREC_VIOLATION => sink("PREC VIOLATION".to_string()), // cc:417
                    icmp_code::PREC_CUTOFF => sink("PREC CUTOFF".to_string()),       // cc:421
                    _ => sink("UNKNOWN".to_string()),                                // cc:425
                }
            }

            // cc:430-432 SOURCE_QUENCH:
            icmp_type::SOURCE_QUENCH => {
                sink("SOURCE QUENCH".to_string()); // cc:431
            }

            // cc:434-:461 REDIRECT + the nested code switch
            // cc:436-:456 (leading-SPACE strings kept verbatim!), then
            // the hand-formatted gwaddr pair cc:458-:460:
            icmp_type::REDIRECT => {
                sink("REDIRECT".to_string()); // cc:435
                match code {
                    icmp_code::REDIR_NET => sink(" NET".to_string()),       // cc:439
                    icmp_code::REDIR_HOST => sink(" HOST".to_string()),     // cc:443
                    icmp_code::REDIR_TOS_NET => sink(" TOS NET".to_string()),  // cc:447
                    icmp_code::REDIR_TOS_HOST => sink(" TOS HOST".to_string()), // cc:451
                    _ => {}                                                  // cc:454-:455 default
                }
                // cc:458-:459 the snort_inet_ntop seam, hand-format
                // face (doc above): s_icmp_gwaddr four octets @4-7:
                let gw = format!(
                    "{}.{}.{}.{}",
                    *icmph.get(4).unwrap_or(&0),
                    *icmph.get(5).unwrap_or(&0),
                    *icmph.get(6).unwrap_or(&0),
                    *icmph.get(7).unwrap_or(&0),
                );
                sink(format!(" NEW GW: {}", gw)); // cc:460 (leading space)
            }

            // cc:463-:467 ECHO ("ID:%d   Seq:%d  " — THREE spaces
            // between ID and Seq, kept, unlike the ECHOREPLY pair):
            icmp_type::ECHO_4 => {
                sink(format!(
                    "ID:{}   Seq:{}  ",
                    Self::ntoh16(icmph, 4), // cc:464
                    Self::ntoh16(icmph, 6), // cc:465
                )); // cc:464 "ID:%d   Seq:%d  "
                sink("ECHO".to_string()); // cc:466
            }

            // cc:469-:474 ROUTER_ADVERTISE: the cc:470-:471 concat —
            // "ROUTER ADVERTISEMENT: Num addrs: %d Addr entry size: %d
            // Lifetime: %u"; num_addrs @4 / wpa @5 raw %d, lifetime
            // @6-7 ntohs %u (h:145-:150):
            icmp_type::ROUTER_ADVERTISE => {
                sink(format!(
                    "ROUTER ADVERTISEMENT: Num addrs: {} Addr entry size: {} Lifetime: {}",
                    *icmph.get(4).unwrap_or(&0),  // cc:472 s_icmp_num_addrs
                    *icmph.get(5).unwrap_or(&0),  // cc:472 s_icmp_wpa
                    Self::ntoh16(icmph, 6),       // cc:473 s_icmp_lifetime
                )); // cc:470-:471
            }

            // cc:476-:478 ROUTER_SOLICIT:
            icmp_type::ROUTER_SOLICIT => {
                sink("ROUTER SOLICITATION".to_string()); // cc:477
            }

            // cc:480-:496 TIME_EXCEEDED + the nested code switch
            // cc:482-:494 (leading-SPACE strings kept):
            icmp_type::TIME_EXCEEDED => {
                sink("TTL EXCEEDED".to_string()); // cc:481 (the type word vs the strings differs from ground verbatim)
                match code {
                    icmp_code::TIMEOUT_TRANSIT => sink(" IN TRANSIT".to_string()), // cc:485
                    icmp_code::TIMEOUT_REASSY => {
                        // cc:489 verbatim:
                        sink(" TIME EXCEEDED IN FRAG REASSEMBLY".to_string());
                    }
                    _ => {} // cc:492-:493 default
                }
            }

            // cc:498-:519 PARAMETERPROB + the nested code switch
            // cc:500-:517:
            icmp_type::PARAMETERPROB => {
                sink("PARAMETER PROBLEM".to_string()); // cc:499
                match code {
                    icmp_code::PARAM_BADIPHDR => {
                        // cc:503-:504 ": BAD IP HEADER BYTE %u" over
                        // s_icmp_pptr @4 (h:124):
                        sink(format!(
                            ": BAD IP HEADER BYTE {}",
                            *icmph.get(4).unwrap_or(&0), // cc:504
                        ));
                    }
                    icmp_code::PARAM_OPTMISSING => sink(": OPTION MISSING".to_string()), // cc:508
                    icmp_code::PARAM_BAD_LENGTH => sink(": BAD LENGTH".to_string()),     // cc:512
                    _ => {} // cc:515-:516 default
                }
            }

            // cc:521-:524 TIMESTAMP ("ID: %u  Seq: %u  TIMESTAMP
            // REQUEST" — a SPACE after "ID:"/"Seq:", the "ID:%d" faces
            // above have NONE; kept both ways):
            icmp_type::TIMESTAMP => {
                sink(format!(
                    "ID: {}  Seq: {}  TIMESTAMP REQUEST",
                    Self::ntoh16(icmph, 4), // cc:523
                    Self::ntoh16(icmph, 6), // cc:523
                )); // cc:522
            }

            // cc:526-:532 TIMESTAMPREPLY: the cc:527-:528 concat
            // "ID: %u  Seq: %u  TIMESTAMP REPLY: Orig: %u Rtime: %u  Ttime: %u"
            // — id/seq ntohs, the THREE timestamp u32s read HOST-ORDER
            // (NO ntohl at the call cc:530-:531 — LE-host loads, cited
            // posture): otime @8-11 / rtime @12-15 / ttime @16-19
            // (h:167-:172). NOTE the ONE space "Orig: %u Rtime" vs the
            // TWO spaces "Rtime: %u  Ttime": kept.
            icmp_type::TIMESTAMPREPLY => {
                sink(format!(
                    "ID: {}  Seq: {}  TIMESTAMP REPLY: Orig: {} Rtime: {}  Ttime: {}",
                    Self::ntoh16(icmph, 4),  // cc:529
                    Self::ntoh16(icmph, 6),  // cc:529
                    Self::host_u32(icmph, 8),  // cc:530 s_icmp_otime
                    Self::host_u32(icmph, 12), // cc:530 s_icmp_rtime
                    Self::host_u32(icmph, 16), // cc:531 s_icmp_ttime
                )); // cc:527-:528
            }

            // cc:534-:537 INFO_REQUEST:
            icmp_type::INFO_REQUEST => {
                sink(format!(
                    "ID: {}  Seq: {}  INFO REQUEST",
                    Self::ntoh16(icmph, 4), // cc:536
                    Self::ntoh16(icmph, 6), // cc:536
                )); // cc:535
            }

            // cc:539-:542 INFO_REPLY:
            icmp_type::INFO_REPLY => {
                sink(format!(
                    "ID: {}  Seq: {}  INFO REPLY",
                    Self::ntoh16(icmph, 4), // cc:541
                    Self::ntoh16(icmph, 6), // cc:541
                )); // cc:540
            }

            // cc:544-:547 ADDRESS (mask request):
            icmp_type::ADDRESS => {
                sink(format!(
                    "ID: {}  Seq: {}  ADDRESS REQUEST",
                    Self::ntoh16(icmph, 4), // cc:546
                    Self::ntoh16(icmph, 6), // cc:546
                )); // cc:545
            }

            // cc:549-:553 ADDRESSREPLY: "ID: %u  Seq: %u  ADDRESS
            // REPLY: 0x%08X" over ntohl(s_icmp_mask) = the @8-11 BE
            // read (h:187), UPPER-hex 8-wide:
            icmp_type::ADDRESSREPLY => {
                sink(format!(
                    "ID: {}  Seq: {}  ADDRESS REPLY: 0x{:08X}",
                    Self::ntoh16(icmph, 4),   // cc:551
                    Self::ntoh16(icmph, 6),   // cc:551
                    Self::ntoh32(icmph, 8),   // cc:552 ntohl s_icmp_mask
                )); // cc:550
            }

            // cc:555-:557 default:
            _ => sink("UNKNOWN".to_string()), // cc:556
        }
    }

    /// The memcpy+ntohs collapse over a u16 slot (the gre gre_proto
    /// posture): BIG-endian read of bytes off..off+1 (get-or-0 = the
    /// never-armed short-window face, the landed checks posture).
    #[inline]
    fn ntoh16(b: &[u8], off: usize) -> u16 {
        u16::from_be_bytes([*b.get(off).unwrap_or(&0), *b.get(off + 1).unwrap_or(&0)])
    }

    /// The memcpy+ntohl collapse over a u32 slot (BE read).
    #[inline]
    fn ntoh32(b: &[u8], off: usize) -> u32 {
        u32::from_be_bytes([
            *b.get(off).unwrap_or(&0),
            *b.get(off + 1).unwrap_or(&0),
            *b.get(off + 2).unwrap_or(&0),
            *b.get(off + 3).unwrap_or(&0),
        ])
    }

    /// HOST-ORDER u32 load (the ground reads with NO ntohl — cc:530-
    /// :531 direct struct reads): on the pinned LE probe host that is
    /// the LE read; cited posture, the BE arm never exists port-side
    /// (the WORDS_BIGENDIAN cite in icmp4_addr_tests).
    #[inline]
    fn host_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([
            *b.get(off).unwrap_or(&0),
            *b.get(off + 1).unwrap_or(&0),
            *b.get(off + 2).unwrap_or(&0),
            *b.get(off + 3).unwrap_or(&0),
        ])
    }

    /// cc:579-:590 out-of-line update, statement order VERBATIM. The
    /// `ip::IpApi&` operand is UNNAMED (cc:579) — the never-read lineage
    /// posture -> `&()` (the cd_gref/cd_gtp update signature mirror).
    /// The uint32 accumulate is wrapping (every C unsigned pair, skill
    /// rule — the gre/gtp update shape).
    /// `h->cksum = 0;` cc:587 is the uint16 LE face on the pinned LE
    /// host (bytes 2-3 cleared, the gre raw_pkt[4]/[5] precedent);
    /// `h->cksum = checksum::icmp_cksum(h, updated_len);` cc:588 rides
    /// the LANDED 2-arg `checksum::icmp_cksum(buf, len)` (checksum.rs:
    /// 361-:367, checksum.h:218-:221 — checksum.rs itself pre-names the
    /// cd_icmp4 :588 consume in its own doc; the u16 write-back lands
    /// LE per the gre pair). The cc:585 guard `!(flags & UPD_COOKED) ||
    /// (flags & UPD_REBUILT_FRAG)` keeps its OR shape (the UPD_* consts
    /// are the landed codec.rs:85/:88 values; the C EncodeFlags carrier
    /// is the u64).
    pub fn update(
        &self,
        _api: &(),
        flags: EncodeFlags,
        raw_pkt: &mut [u8],
        lyr_len: u16,
        updated_len: &mut u32,
    ) {
        // cc:582 the IcmpHdr overlay (field reads ride the wire offsets).
        // cc:583 `updated_len += lyr_len;` — BEFORE any field work, and
        // the cc:588 cksum window is `updated_len` bytes (NOT lyr_len) —
        // operand identity per arm kept (the gre update cite).
        *updated_len = updated_len.wrapping_add(u32::from(lyr_len));

        if (flags & u64::from(UPD_COOKED)) == 0 || (flags & u64::from(UPD_REBUILT_FRAG)) != 0 {
            raw_pkt[2] = 0; // cc:587 (a uint16 LE clear zeroes both
            raw_pkt[3] = 0; // bytes — same-window operand kept)
            // cc:588 the 2-arg ICMP cksum over the updated_len window
            // (the declared-len == window pin rides checksum.rs like
            // the gre cite — never exercised by the pinned arms; a
            // declared len past the real buffer is the C OOB-walk face,
            // Rust index-panic posture, gre deviations cite).
            let value = crate::codecs::checksum::icmp_cksum(raw_pkt, *updated_len as usize);
            // cc:588 the u16 LE write-back (memcpy face):
            raw_pkt[2..4].copy_from_slice(&value.to_le_bytes());
        }
        // cc:589-:590 `}` closes update — void, no return.
    }

    /// cc:592-:597 out-of-line format. The reverse operand is
    /// COMMENTED-out named (cc:592 `bool /*reverse*/`) — the never-read
    /// face. cc:594 the "FIXIT-L handle nested icmp4 layers" comment
    /// rides. cc:595 the `snort.icmph = reinterpret_cast<ICMPHdr*>(
    /// raw_pkt)` stash is the LEFT-OPEN pointer face (the
    /// Icmp4DecodeData doc: the reinterpret_cast produces ONLY an alias
    /// — the byte window itself IS the face, no Rust slot lands; the
    /// _raw_pkt param keeps the call-site shape). cc:596
    /// `snort.set_pkt_type(PktType::ICMP)`:
    pub fn format(
        &self,
        _reverse: bool,
        _raw_pkt: &mut [u8],
        snort: &mut Icmp4DecodeData,
    ) {
        snort.pkt_type = PKT_TYPE__ICMP; // cc:596
    }
}

// cc:561-:563 the "E N C O D E R" banner rides. cc:565-:577 the anon-
// namespace `struct IcmpHdr { uint8_t type; uint8_t code; uint16_t
// cksum; uint32_t unused; }` — "These fields preserve the ICMP wire
// layout; icmp_cksum consumes the complete header bytes" (the cc:569
// comment) + the two cppcheck-suppress unusedStructMember pins; NO Rust
// struct lands: the update overlay reads the SAME wire offsets (@0
// type, @1 code, @2-3 cksum) — the cksum pair @2-3 is the h:118 same
// slot (a doc-cite, never a second face).

/// The 18 codec_event sites ride the LANDED framework/codec.rs
/// codec_event (GID_DECODE 116 -> the vectors `EV 116 <sid>` family) —
/// file-private wrapper, the gre codec_event_gre pattern verbatim.
#[inline]
fn codec_event_icmp4(codec: &CodecData, sid: u32, sink: QueueSink) {
    crate::framework::codec::codec_event(codec, sid, &mut *sink);
}
// cc:599-:601 the "api" separator comment rides.
// cc:603-:604 `static Module* mod_ctor() { return new Icmp4Module; }` +
// cc:606-:607 `static void mod_dtor(Module* m) { delete m; }` — the mod
// pair SET (contrast the 18h frag nullptr R2 face; the FACE-A uniform
// mod_ctor=1 x3 print); the Rust mod_ctor() face is Icmp4Module::new
// (stack-owned drop, 18d posture). cc:609-:610 `static Codec*
// ctor(Module*)` / cc:612-:613 `static void dtor(Codec* cd)` — the
// codec pair, the C `(Module*)` arg unused.

/// cc:615-:635 `static const CodecApi icmp4_api` — THE lean-word record
/// (module doc): C identifier `icmp4_api` while the NAME slot carries
/// "icmp4" cc:624-:625. ALL FOUR ctor/dtor slots SET: mod_ctor cc:626 +
/// mod_dtor cc:627, ctor cc:633 + dtor cc:634; cc:629-:632 the four
/// `nullptr` arms (pinit/pterm/tinit/tterm) = false. vectors:62-:63
/// exercise the ctor + the mod walk end-to-end.
pub const ICMP4_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:618
    size: CDAPI_SIZEOF_CODEC_API, // cc:619 sizeof(CodecApi)=112
    api_version: CDAPI_VERSION,   // cc:620 1900547
    version: 0,                   // cc:621
    features: PLUGIN_SO_RELOAD,   // cc:622
    options: API_OPTIONS,         // cc:623
    name: CD_ICMP4_NAME,          // cc:624 -> "icmp4"
    help: CD_ICMP4_HELP,          // cc:625
    mod_ctor: true,               // cc:626 SET
    mod_dtor: true,               // cc:627 SET
    pinit: false,                 // cc:629 nullptr
    pterm: false,                 // cc:630 nullptr
    tinit: false,                 // cc:631 nullptr
    tterm: false,                 // cc:632 nullptr
    ctor: true,                   // cc:633 SET
    dtor: true,                   // cc:634 SET
};

/// cc:637-:645 the table face: the REAL BUILDING_SO/SO_PUBLIC `snort_
/// plugins[]` arm :637-:638 vs the static-build `const BaseApi*
/// cd_icmp4[] = { &icmp4_api.base, nullptr }` face cc:640-:645 — the
/// table name == the file base (NO cd_auth/cd_frag drift rider here;
/// grep-verified face, the gre TRUE-NAME FACT posture). The ladder
/// entry "cd_icmp4" is already RESIDENT (codec_api.rs STATIC_CODEC_
/// EXTERN_NAMES) — NEVER re-touched; the dormant extern stays a record,
/// not a link edge.
pub const CD_ICMP4: CodecTable = &[&ICMP4_API];
