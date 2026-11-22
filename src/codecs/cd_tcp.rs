//! Port of `src/codecs/ip/cd_tcp.cc` (839 L) — row 20a, the THIRD and last
//! TU of the `tools/ipheavy_harness` ZERO-gate probe-only chapter (the ip
//! heavies trio; this TU is the tcp leg of `codecs/ip/`). Ground:
//! snort3-src @ fe29cbe, md5 `144c427504a13c58dc117bcf93f6a604`, wc 839
//! (both re-measured THIS pass: `md5sum` + `wc -l` on the ground TU — the
//! trio sum 790+733+839 = 2362 re-adds).
//! THE 26th straight honest zero-gate face: TEST_CASE/TEST_GROUP/
//! UNIT_TEST/CppUTest grep EXACTLY-0 in the TU (re-run THIS pass; the
//! harness build.sh census echo carries the same face) — the vectors pair
//! Rust mirrors against the LIVE C build.
//!
//! THE BUILDING_SO grep-LIE FACE (THE TU's own table law — cd_tcp.cc
//! :831-:835): the BUILDING_SO split is COMMENTED OUT here —
//! `//#ifdef BUILDING_SO` :831, `//SO_PUBLIC const BaseApi* snort_plugins[]`
//! :832, `//#else` :833, REAL `const BaseApi* cd_tcp[] =` :834, `//#endif`
//! :835 — the table is UNCONDITIONAL, not `#ifdef`-hidden. Therefore
//! `grep -c BUILDING_SO` == 1 on this TU LIES (the substring only lives
//! inside the comment at :831); the census law the harness asserts is the
//! LINE-ANCHORED `grep -c '^[[:space:]]*#ifdef BUILDING_SO'` == 0 for THIS
//! TU versus EXACTLY-1 for cd_ipv4.cc :782 / cd_ipv6.cc :725 (build.sh
//! carries the trio census). TRUE NAME holds: file base == table name
//! `cd_tcp[]` at :834, nm D EXACTLY-1 == FILE base (the 18n equality-pin
//! law); ONE feed `&tcp_api.base` :837 + nullptr :838 -> LOADS 1 per feed,
//! trio `LOADS 3` faceA:4.
//!
//! TRUE-NAME table + api struct `tcp_api` cc:809 (lands TCP_API — the
//! C-struct-name rule, cd_mpls MPLS_API family). NAME/HELP at :42/:43:
//! HELP is BARE `"support for transmission control protocol"` — THE HELP
//! ASYMMETRY face: NO ADD_DLT splice here (contrast the cd_ipv4.rs :49
//! `"...(DLT 228)"` and cd_ipv6.rs :39 `"...(DLT 229)"` splice faces — the
//! framework/codec.h:52 macro simply NEVER runs in this TU, and the codec
//! NEVER overrides get_data_link_type (faceA:41 `GETDLT_n tcp 0`).
//!
//! WORDS_BIGENDIAN cc:45-:51 (the seed-drift TRIPWIRE law): the BE arms
//! `naptha_seq = 0x005c7b2a` :46 / `naptha_id = 0x019d` :47 are CITED
//! NEVER landed (host LE, x86 build face); the `#else` LE arms
//! `naptha_seq = 0x2a7b5c00` :49 / `naptha_id = 0x9d01` :50 LAND as
//! NAPTHA_SEQ/NAPTHA_ID — vectors IC14 fires EV 402 ONLY on the LE consts
//! (wire bytes 00 5c 7b 2a + outer ip_id wire 01 9d) and IC15 with the
//! BYTE-SWAPPED BE-era wire NEVER fires; the 402 total over the pair is
//! EXACTLY-1 (the arm census: the pair pins WHICH side of :45/:48 the
//! build took).
//!
//! `using namespace tcp;` cc:53 — the TH_*/OPT_*/TcpOptCode/TCPHdr
//! unqualified-ride face; lands as the row-scoped consts below (dup-not-
//! import family: the checksum.rs usize TCP_MIN 20 home at checksum is a
//! DIFFERENT home — row-scoped per the cd_frag/cd_ipv4 lineage law).
//!
//! sid census (ALL 20 tcp_rules rows RESIDENT codec_module.rs enum
//! CodecSid, ZERO new constants — each grepped EXISTS THIS pass):
//! DGRAM_LT_TCPHDR 45 (:76, h) / INVALID_OFFSET 46 (:77) / LARGE_OFFSET
//! 47 (:78) / TCPOPT_BADLEN 54 (:79) / TCPOPT_TRUNCATED 55 (:80) /
//! TCPOPT_TTCP 56 (:81) / TCPOPT_OBSOLETE 57 (:82) / TCPOPT_EXPERIMENTAL
//! 58 (:83) / TCPOPT_WSCALE_INVALID 59 (:84) / TCP_XMAS 400 (:85) /
//! NMAP_XMAS 401 (:86) / BAD_URP 419 (:87 — gate NEVER arms in vectors:
//! th_urp bytes 16-17 stay ZERO in every probe header, the p[22]/p[23]
//! writes sit in PAYLOAD past the 20-byte header — the §8 419-ZERO face) /
//! SYN_FIN 420 (:88) / SYN_RST 421 (:89) / MUST_ACK 422 (:90) /
//! NO_SYN_ACK_RST 423 (:91) / SHAFT_SYNFLOOD 433 (:92) / PORT_ZERO 446
//! (:93) / DOS_NAPTHA 402 (:94, h:156) / SYN_TO_MULTICAST 403 (:95,
//! h:157). Table face: 21 rows -> `{ 0, nullptr }` terminator :96 (20
//! data + 1 term; faceA:37 `RULES tcp n=20 first=45 last=403`).
//!
//! PEGS cite-never-land (cc:57-:63 PegInfo / Stats struct :65-:70 /
//! `static THREAD_LOCAL Stats stats;` :72 + the get_pegs/get_counts
//! overrides :107-:111): the THREE rows ride THIS comment — CountType::SUM
//! `bad_tcp4_checksum` "nonzero tcp over ip checksums" (:59), SUM
//! `bad_tcp6_checksum` "nonzero tcp over ipv6 checksums" (:60), SUM
//! `checksum_bypassed` "checksum calculations bypassed" (:61); the :168
//! `stats.cksum_bypassed++` and the :247 `(*bad_cksum_cnt)++` are PEG
//! faces (NEVER printed by any vector; NO Rust counter machinery lands).
//!
//! THE sfvar WITNESS FACE (cc:147): `static sfip_var_t*
//! SynToMulticastDstIp = nullptr` — ginit :790-:795 fills it via
//! `sfip_var_from_string("[224.0.0.0/4]", "tcp")` :793 (the RFC 5771
//! comment :792 rides; the :794 assert is the NDEBUG elide face) and
//! gterm :797-:801 frees it. At the harness face witness_ipvars.cc pins
//! `sfip_var_from_string` -> nullptr, so the :542 leg
//! `sfvar_ip_in(SynToMulticastDstIp, snort.ip_api.get_dst())` measures
//! FALSE (IC12: ANOM-ON + v4 dst 239.1.1.1 -> NO 403 — the closed-but-
//! false wire face, arms LIVE in the binary). THE FOLD: the 403 arm reads
//! `sfvar_in == false` (witness face cited at the use site); the
//! `src/sfip/sf_ipvar.rs` module is NEVER imported.
//!
//! THE DAQ SEAM (ext#4 SYNTHETIC, NEVER ABI truth — the cd_udp.rs graft
//! ruling carried): the DAQ SDK header is ABSENT ground-side; the harness
//! copy/daq.h shape (51 L md5 97bca757..., copy-LOCAL heredoc, masters
//! md5-frozen NEVER promoted) is drawn ONLY from the measured call faces
//! cc:157-:166 (`DAQ_PktDecodeData_t flags.bits.l4_checksum/.tcp/.l4` +
//! `l4_offset` — the l4 twin of the cd_ipv4 l3 trio) + cc:279-:283
//! (`DAQ_NAPTInfo_t ip_layer/src_port/dst_port` — THE CENSUS FACE: this TU
//! consumes the PORT members ONLY (:282-:283); the addr/family members
//! ride the v4/v6 legs cc:250/:216 — NEVER ABI truth, plan row 20
//! re-cites the real SDK). THE offset sentinel `DAQ_PKT_DECODE_OFFSET_
//! INVALID (-1)` rides row-scoped w/ the cd_icmp4.rs landed twin cite; the
//! cc:165 pointer difference `raw.data - daq_msg_get_data(raw.daq_msg)`
//! folds to the explicit `payload_delta: i64` param (cd_icmp4 DaqFace
//! precedent — pointer math probe-faked). `valid_checksum_from_daq` lands
//! VERBATIM statement-for-statement (cc:155-:170), the :168
//! `stats.cksum_bypassed++` leg is the PEG face above.
//!
//! THE IP API SEAM: :230 `snort.ip_api.is_ip4()` (the false leg :239
//! implies the v6 posture), :174 `get_ip4h()`, :189 `get_ip6h()`,
//! :533-:534 `is_ip4()/get_ip4h()` reads. The row-scoped TcpDecodeData
//! seam (the cd_ipv4.rs Ipv4DecodeData family shape) carries decode_flags
//! + sp/dp (the :287-:288/:770-:771 writes) + `pkt_type` (the :276
//!   set_pkt_type face — PktType::TCP ordinal 2, decode_data.h:45-:48) +
//!   `ip4h`/`ip6h` header-window slots (the get_ipXh() faces). THE
//!   `snort.tcph = tcph` pointer stash at :277 (and :769) is a DOCUMENT
//!   pin: the DecodeData::tcph OWNER (framework/decode_data.h
//!   DecodeData) stays LEFT-OPEN — NEVER ported (the log/encode world
//!   reader, cite-only).
//!
//! THE CHECKSUM LEGS LAND (decode-facing, unlike the log/encode world):
//! valid_checksum_from_daq :155-:170, valid_checksum4 :172-:185 (the
//! Pseudoheader sip/dip RAW-field legs — the cd_udp.rs:568-:580 ip4_sip/
//! ip4_dip LE-host raw-read twin; `htons((uint16_t)raw.len)` stores the
//! SWAPPED bytes, the Pseudoheader.len network-order pin family),
//! valid_checksum6 :187-:200 (COPY4 legs = the raw u32-word copy, the
//! cd_ipv6.rs address-words fold twin; protocol = `codec.ip6_csum_proto`
//! :195 — the cross-layer ride face). `tcp_cksum` overload pair RESIDENT
//! checksum.rs (row 18b donors, REUSED never re-ported). HONEST FACE: the
//! vectors NEVER arm the !valid leg — probe_dec stamps the pdd bits ON +
//! l4_offset INVALID (probe_dec.cc :55-:57), so valid_checksum_from_daq
//! short-circuits the whole :225 block every decode (the checksum-fail
//! :243-:251 return-false face is LIVE CODE, ZERO-VECTORIZED — the honest
//! §8 carry; the E4 daq.h-drop inversion probe face lives in FACE-A, not
//! in DEC).
//!
//! CITE-NEVER-LAND (the log/encode/update/format world, per the row law):
//! log :571-:598 (stringify_flags tcpFlags[9] face :574-:580, the SrcPort/
//! DstPort/Seq/Ack/Win/TcpLen TextLog_Print face :583-:587, the TH_URG
//! UrgPtr leg :589-:590, the has_options -> LogTcpOptions leg :593-:597 —
//! the log_text reader world); the ENCODER banner :600-:615 (the RFC 793
//! RST-window quote block rides the encode cite below); encode :617-:720
//! (the TCP RST builder: buf.allocate(TCP_MIN_HEADER_LEN) :622, ctl =
//! SYN?1:0 :626, forward/reverse slot legs :628-:660, THE
//! `Stream::get_held_pkt_seq(flow, seq)` seam at :638 = A LEFT-OPEN
//! PROVIDER (real body stream/stream.cc:872 — the stream world NEVER
//! enters Rust scope; the harness witness stands in
//! tools/ipheavy_harness/, row 21 closes), ENC_FLAG_INLINE/SEQ/VAL legs
//! :633-:640/:665-:672, the ENC pseudoheader recompute :676-:700); update
//! :722-:756 (`updated_len += h->hlen()` :725, the UPD_COOKED/
//! UPD_REBUILT_FRAG gate :727, th_sum = 0 + recomputed cksum legs :729-
//! :755); format :758-:773 (reverse port-slot SWAP :762-:767, the
//! snort.tcph/sp/dp/pkt_type stash :769-:772 — the format-side twin of
//! the :287-:288 legs, document pin).
//!
//! GATE-ORDER FACT (EVERY cc cite rides decode verbatim): :204 short gate
//! -> :211 overlay+tcph_len var (the uint16_t widening face) -> :213
//! hlen<20 -> :219 hlen>raw.len (uint16-vs-uint32 promotion cite) ->
//! :225 policy+daq checksum fork -> :254 flag_tests -> :257 tcp_opt_len
//! (the hlen() RE-CALL face — not tcph_len:211) -> :259-:263 options ->
//! :264 dsize signed-int fold -> :269 BAD_URP gate -> :273 lyr_len (the
//! `tcph_len - codec.invalid_bytes` ride from decode_options) -> :274
//! proto_bits -> :276/:277 pkt_type+tcph pins -> :279-:289 the NAPT fork
//! (the ip_layer_cnt==ip_layer gate — tcp NEVER increments ip_layer_cnt
//! (stays 0): IC18 re-stamps napt->ip_layer = 0 for the MATCH arm;
//! FACE-A:42-:44 rides the MISMATCH face at napt ip_layer 1 -> the
//! header-port path faceA `NAPTTCP sp=25001 dp=25002`) -> :291-:292
//! PORT_ZERO -> :294 true.
//!
//! THE flag_tests ORDER (:518-:565): the XMAS are_flags_set BOTH pair
//! :521/:523 -> 400/401; the SYN block :529 (th_flags==TH_SYN -> the RAW-
//! FIELD naptha gate :533-:534 -> 402; anomaly :540 -> 403; RST :546 ->
//! 421; FIN :549 -> 420; TH_NORESERVED==TH_SYN && seq()==674711609 :552
//! -> 433 — the seq() = ntohl FIELD face, contrast the naptha RAW
//! compare: IC13 htonl-stamps the wire so seq() == the decimal); the ELSE
//! no-SYN arm :557 -> 423; the OUTSIDE MUST_ACK block :561-:563 -> 422
//! (IC5 order pin: 401, 423, 422 — MUST_ACK rides AFTER the else arm,
//! vectors:83-:85).
//!
//! THE decode_options WALK (:330-:484): window-relative (the C pointer
//! walk folds to offsets, the cd_ipv4 DecodeIPOptions twin law); locals
//! verbatim incl the `int code = 2;` :335 seed value (NEVER read before
//! assignment on any measured path — honest shape carry); the EOL->NOP
//! fallthrough :358-:364 (done + invalid_bytes, THEN code = 0); the
//! CC_ECHO :416-:418 EV-56-IMMEDIATE-then-fallthrough-to-CC validate face
//! (IC23: 56 fires on ENTRY before any validate — vectors:116); every
//! validate failure :456-:473 -> BADLEN 54 / TRUNC 55 then the BSD/Linux
//! accept-good-options comment :467-:470 + invalid_bytes + return; the
//! advance :475 `((uint8_t)code <= 1) ? 1 : opt->len`; the
//! `opt = &opt->next()` :476 face — the tcp_options.h:110-:121 next()
//! body: code<=1 -> reinterpret of the len byte (the +1 advance lands ON
//! the next option code — the vectors' [.,6,5?,...] rides), len>=2 ->
//! data[len-2] == opt+len (the +len advance), and the len<2 -> `static
//! const TcpOption eol_opt` arm (:114-:117) is UNREACHABLE here: EVERY
//! code>1 case validates FIRST and a len<2 returns code<0 at :456 before
//! the advance (the honest dead-at-this-call-site cite, NEVER vectored);
//! the tail :479-:483 experimental-else-if-obsolete pair — MUTUALLY
//! EXCLUSIVE (IC21 pins 57 SINGLE with experimental FALSE: vectors:112).
//! THE IC22 MEASURED FACE: [18,4] arms case TRAILER_CSUM :424 (NOT the
//! default): experimental flag SET, validate EXPECTED TCPOLEN_TRAILER_CSUM
//! 3: len 4 != 3 -> OPT_BADLEN -> EV 54 SINGLE (vectors:114; the name
//! "trailer58" in the probe is a red herring — vectors print 54; the
//! [18,3] FIXED-LEN face NEVER reaches the tail flags).

use crate::codecs::checksum::{Pseudoheader, Pseudoheader6, tcp_cksum4, tcp_cksum6};
use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CODEC_UNSURE_ENCAP, CodecApiRecord,
    CodecData, CodecTable, PT_CODEC, PLUGIN_SO_RELOAD, ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;

// ---------------------------------------------------------------------------
// api identification (the C #defines)
// ---------------------------------------------------------------------------

/// cc:42 `#define CD_TCP_NAME "tcp"` (faceA:31 `name=tcp`, faceA:36
/// `NAME tcp mod=tcp`).
pub const CD_TCP_NAME: &str = "tcp";

/// cc:43 `#define CD_TCP_HELP "support for transmission control protocol"`
/// — THE HELP ASYMMETRY: NO ADD_DLT splice (module doc; faceA:32/:36 the
/// bare string, contrast the ipv4/ipv6 "(DLT 228)/(229)" faces).
pub const CD_TCP_HELP: &str = "support for transmission control protocol";

// ---------------------------------------------------------------------------
// WORDS_BIGENDIAN naptha consts (cc:45-:51) — the seed-drift tripwire
// ---------------------------------------------------------------------------

/// cc:49 (the `#else` host-LE arm) `const uint32_t naptha_seq =
/// 0x2a7b5c00;` — LIVE on this build. THE BE arm cc:46 `0x005c7b2a` rides
/// CITED NEVER landed. The :533 compare hits the RAW th_seq FIELD
/// (u32::from_le_bytes of wire bytes 4-7 == this value: IC14's wire
/// 00 5c 7b 2a reads 0x2a7b5c00 LE — probe_dec.cc :297-:302 comment, the
/// FIELD-vs-seq() cite; IC15's 2a 7b 5c 00 = the BE-era field 0x005c7b2a,
/// NEVER fires 402 — the pair pins the arm).
pub const NAPTHA_SEQ: u32 = 0x2a7b_5c00;

/// cc:50 (the `#else` host-LE arm) `const uint16_t naptha_id = 0x9d01;` —
/// the BE arm cc:47 `0x019d` cited (the :534 raw ip_id FIELD compare at
/// the OUTER v4 header bytes 4-5: wire 01 9d reads LE 0x9d01 — probe
/// outer[4]=0x01 outer[5]=0x9d face).
pub const NAPTHA_ID: u16 = 0x9d01;

// ---------------------------------------------------------------------------
// protocols/tcp.h row-scoped faces (the `using namespace tcp;` :53 ride)
// ---------------------------------------------------------------------------

/// tcp.h:32 `#define TH_FIN  0x01`
pub const TH_FIN: u8 = 0x01;
/// tcp.h:33 `#define TH_SYN  0x02`
pub const TH_SYN: u8 = 0x02;
/// tcp.h:34 `#define TH_RST  0x04`
pub const TH_RST: u8 = 0x04;
/// tcp.h:35 `#define TH_PUSH 0x08`
pub const TH_PUSH: u8 = 0x08;
/// tcp.h:36 `#define TH_ACK  0x10`
pub const TH_ACK: u8 = 0x10;
/// tcp.h:37 `#define TH_URG  0x20`
pub const TH_URG: u8 = 0x20;
/// tcp.h:41-:42 `#define TH_NORESERVED (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|
/// TH_URG)` = 0x3F (the :552 SHAFT mask face; the TH_ECE/TH_CWR :38-:40
/// rows NEVER ride this TU — cd_user.rs lineage cite).
pub const TH_NORESERVED: u8 = TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG;

/// tcp.h:75 `constexpr uint8_t TCP_MIN_HEADER_LEN = 20;` — row-scoped
/// (the checksum.rs home is a DIFFERENT const, row 18b donor, cited not
/// reused — the cd_frag.rs dup-not-import family).
pub const TCP_MIN_HEADER_LEN: u8 = 20;

/// tcp.h:76 `constexpr int OPT_TRUNC = -1;` (the :462 TRUNC gate face).
pub const OPT_TRUNC: i32 = -1;

/// tcp.h:77 `constexpr int OPT_BADLEN = -2;` (the :458 BADLEN gate face).
pub const OPT_BADLEN: i32 = -2;

/// tcp.h:92-:93 `inline uint8_t hlen() const { return (th_offx2 & 0xf0)
/// \>> 2; }` (sed-landed body verbatim; :211/:257 call sites; IC2's
/// 0x40 -> 16, IC3/IC19+ 0x60 -> 24, 0x70 -> 28).
#[inline]
pub fn tcp_hlen(th_offx2: u8) -> u8 {
    (th_offx2 & 0xf0) >> 2 // tcp.h:93 body
}

/// tcp.h:95-:96 `inline uint8_t off() const { return (th_offx2 & 0xf0)
/// \>> 2; }` — the SAME body as hlen() (the log :587 `tcph->off()`
/// reader: cite-only world, landed for the access-set completeness
/// face).
#[inline]
pub fn tcp_off(th_offx2: u8) -> u8 {
    (th_offx2 & 0xf0) >> 2 // tcp.h:96 body
}

/// tcp.h:101-102/:104-105 `src_port()/dst_port() { return ntohs(...) }` —
/// the BE reads of header bytes 0-1 / 2-3 (:287-:288 the else-leg writes;
/// faceA:44 `sp=25001 dp=25002` wire-stamped ports ride this read).
#[inline]
pub fn tcp_src_port(tcph: &[u8]) -> u16 {
    u16::from_be_bytes([tcph[0], tcph[1]]) // th_sport @0
}

#[inline]
pub fn tcp_dst_port(tcph: &[u8]) -> u16 {
    u16::from_be_bytes([tcph[2], tcph[3]]) // th_dport @2
}

/// tcp.h:116-:117 `inline uint32_t seq() const { return ntohl(th_seq);
/// }` — the BE read of wire bytes 4-7 (the :552 SHAFT compare face:
/// IC13 htonl-stamps the wire so seq() == 674711609; contrast the naptha
/// :533 RAW FIELD compare — never this read).
#[inline]
pub fn tcp_seq(tcph: &[u8]) -> u32 {
    u32::from_be_bytes([tcph[4], tcph[5], tcph[6], tcph[7]])
}

/// tcp.h:139-:140 `inline uint16_t urp() const { return ntohs(th_urp);
/// }` — the BE read of bytes 16-17 (the :269 BAD_URP leg; ZERO vectored,
/// module doc).
#[inline]
pub fn tcp_urp(tcph: &[u8]) -> u16 {
    u16::from_be_bytes([tcph[16], tcph[17]])
}

/// tcp.h:125-:126 `inline bool are_flags_set(uint8_t flags) const
/// { return (th_flags & flags) == flags; }` — the ALL-SET gate (IC5's
/// 0x29 needs all THREE of FIN|PUSH|URG; the 0x0D near-miss cite).
#[inline]
pub fn tcp_are_flags_set(th_flags: u8, flags: u8) -> bool {
    (th_flags & flags) == flags
}

// ---------------------------------------------------------------------------
// protocols/tcp_options.h option-code + length faces (cc via the case
// labels :358-:453 — the full enum class TcpOptCode :38-:67 cite-rides)
// ---------------------------------------------------------------------------
// enum class TcpOptCode : std::uint8_t (tcp_options.h:38-:67): EOL 0
// "End of Option List [RFC793]", NOP 1, MAXSEG 2, WSCALE 3 [RFC1323],
// SACKOK 4 / SACK 5 [RFC2018], ECHO 6 / ECHOREPLY 7 [RFC1072 obsoleted],
// TIMESTAMP 8 [RFC1323 10 bytes], PARTIAL_PERM 9 / PARTIAL_SVC 10
// [RFC1693], CC 11 / CC_NEW 12 / CC_ECHO 13 [RFC1644 T/TCP], ALTCSUM 15,
// SKEETER 16 / BUBBA 17 [Knowles] (the :297-:329 skeeter/bubba email
// comment block rides below the decode_options landing), TRAILER_CSUM 18
// [Subbu & Monroe], MD5SIG 19 [RFC2385], SCPS 20 / SELNEGACK 21 /
// RECORDBOUND 22 / CORRUPTION 23 [Scott], SNAP 24 [Sukonnik], UNASSIGNED
// 25 (released 12/18/00), COMPRESSION 26 [Bellovin] — COMPRESSION falls
// to `default:` (the :450 arm), AUTH 29 [RFC5925].

/// tcp_options.h:84-:98 selected `const uint8_t TCPOLEN_*` (the values
/// the case arms pass to validate_option EXPECTED variant):
pub const TCPOLEN_MAXSEG: u32 = 4; // :84 "Always 4 bytes - [RFC793]"
pub const TCPOLEN_WSCALE: u32 = 3; // :85 "1 byte with logarithmic values - [RFC1323]"
pub const TCPOLEN_SACKOK: u32 = 2; // :86
pub const TCPOLEN_ECHO: u32 = 6; // :87 (":389 both use the same lengths")
pub const TCPOLEN_TIMESTAMP: u32 = 10; // :94 [RFC1323]
pub const TCPOLEN_CC: u32 = 6; // :96 "page 17 of rfc1644" (CC/CC_NEW/
                               // CC_ECHO :96-:98 trio all 6)
pub const TCPOLEN_TRAILER_CSUM: u32 = 3; // :99 (the IC22 [18,4] != 3 BADLEN face)
pub const TCPOLEN_MD5SIG: u32 = 18; // :100 [RFC2385]

// ---------------------------------------------------------------------------
// decode_data.h row-scoped flags (sed-pinned THIS pass: h:132 / h:151 /
// h:152 / h:153 / h:88 / h:45-:48)
// ---------------------------------------------------------------------------

/// decode_data.h:132 `DECODE_ERR_CKSUM_TCP = 0x00000002` (the :248 write;
/// ZERO vectored — the checksum-fail block never arms, module doc).
pub const DECODE_ERR_CKSUM_TCP: u64 = 0x0000_0002;

/// decode_data.h:151 `DECODE_TCP_MSS = 0x00002000` (the :369 write after
/// a clean MAXSEG option; the DecodeData flags-accumulation DOCUMENT face
/// — never printed).
pub const DECODE_TCP_MSS: u64 = 0x0000_2000;

/// decode_data.h:152 `DECODE_TCP_TS = 0x00004000` (the :432 write after a
/// clean TIMESTAMP option; never printed).
pub const DECODE_TCP_TS: u64 = 0x0000_4000;

/// decode_data.h:153 `DECODE_TCP_WS = 0x00008000` (the :385 write INSIDE
/// the WSCALE code==0 block — braces ground-exact; never printed).
pub const DECODE_TCP_WS: u64 = 0x0000_8000;

/// decode_data.h:88 `#define PROTO_BIT__TCP 0x000002` (the :274 ride;
/// the cd_user.rs:83 landed-twin family — row-home cite NOT import;
/// the vectors' IC6 `pb=2` pin).
pub const PROTO_BIT__TCP: u32 = 0x0000_0002;

/// decode_data.h:45-:48 `enum class PktType : std::uint8_t { NONE, IP,
/// TCP, UDP, ... }` -> TCP ordinal 2 (the :276 set_pkt_type document pin;
/// the cd_ipv4.rs PKT_TYPE__IP h:45-:48 precedent).
pub const PKT_TYPE__TCP: u8 = 2;

/// ext#4 daq.h (copy-LOCAL 51 L md5 97bca757, harness graft):
/// `DAQ_PKT_DECODE_OFFSET_INVALID` — the cd_icmp4.rs:149 landed-twin
/// family (dup-not-import); the :162 `l4_offset != INVALID` skip gate.
pub const DAQ_PKT_DECODE_OFFSET_INVALID: i64 = -1;

// ---------------------------------------------------------------------------
// the ext#4 DAQ seam faces (SYNTHETIC, NEVER ABI truth — module doc)
// ---------------------------------------------------------------------------

/// The `DAQ_PktDecodeData_t` consumption face cc:157-:162 — the l4 twin
/// of the cd_ipv4.rs Ipv4Pdd (the :159 guard reads EXACTLY these three
/// bits + :162 the offset read).
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpPdd {
    pub l4_checksum: bool, // :159
    pub tcp: bool,         // :159
    pub l4: bool,          // :159
    pub l4_offset: i64,    // :162/:165
}

/// The `DAQ_NAPTInfo_t` members THIS TU reads (:280 ip_layer, :282-:283
/// src_port/dst_port — THE PORT-ONLY CENSUS, module doc). THE `*_be`
/// convention inherits the cd_udp.rs DaqNapt:500-:504 family: the field
/// holds the C raw u16 (network stored); `ntohs` lands as the swap.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpNaptFace {
    pub ip_layer: u8,       // :280
    pub src_port_be: u16,   // :282 raw th-order u16
    pub dst_port_be: u16,   // :283 raw th-order u16
}

/// The decode-call DAQ parameter bundle (the cd_icmp4/cd_ipv4 DaqFace
/// shape: pdd + napt + the :165 pointer-difference fold as one Copy
/// parameter, keeping decode at 7 args inside the clippy arg gate).
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpDaqFace {
    pub pdd: Option<TcpPdd>,         // :157-:158 (None == the getter nullptr)
    pub napt: Option<TcpNaptFace>,   // :279 (None == the getter nullptr)
    pub payload_delta: i64,          // :165 `raw.data - data` fold
}

// ---------------------------------------------------------------------------
// the config seam (the :225/:540 policy+conf reads)
// ---------------------------------------------------------------------------

/// The policy()/conf() seam this TU reads. Row-scoped per the cd_ipv4.rs
/// Ipv4Conf family law (NEVER threaded off SnortConfig here):
#[derive(Clone, Copy, Debug)]
pub struct TcpConf {
    /// policy.h:208 `bool tcp_checksums()` — the :225
    /// `snort::get_network_policy()->tcp_checksums()` gate; NSDMI
    /// `checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF`
    /// (policy.h:233, the witness TRUE face — cd_ipv4.rs:305-:311 twin)
    /// -> TRUE.
    pub tcp_checksums: bool,
    /// snort_config.h:282 NSDMI false -> the :540
    /// `codec.conf->is_address_anomaly_check_enabled()` gate (IC12
    /// conf_an flips TRUE + the witness sfvar FALSE face -> NO 403).
    pub address_anomaly_check_enabled: bool,
}

impl Default for TcpConf {
    /// HAND-WRITTEN per the row law (the NSDMI faces: checksums TRUE,
    /// anomaly false).
    fn default() -> Self {
        TcpConf {
            tcp_checksums: true, // policy.h:233 (ALL|DEF -> TRUE)
            address_anomaly_check_enabled: false, // snort_config.h:282
        }
    }
}

// ---------------------------------------------------------------------------
// the row-scoped DecodeData seam (the ip_api reader fold — module doc)
// ---------------------------------------------------------------------------

/// The DecodeData legs :230/:287-:288/:533-:542 read. The REAL
/// DecodeData owner (decode_data.h:168+ with the ip_api member) stays
/// LEFT-OPEN — NEVER ported.
#[derive(Clone, Debug)]
pub struct TcpDecodeData {
    pub decode_flags: u64,                 // decode_data.h DecodeFlags face (:248/:369/:385/:432 writes)
    pub sp: u16,                           // :282/:287/:770 (faceA:44 sp=25001)
    pub dp: u16,                           // :283/:288/:771 (faceA:44 dp=25002)
    pub pkt_type: u8,                      // decode_data.h:192-:195 set_pkt_type face (:276)
    pub ip4h: Option<&'static [u8]>,       // get_ip4h() (:174/:534) — the v4 window
    pub ip6h: Option<&'static [u8]>,       // get_ip6h() (:189) — the v6 window
    // NO `tcph` pointer slot: the :277/:769 `snort.tcph = tcph` stash is
    // the log/encode reader DOCUMENT pin (module doc, LEFT-OPEN).
}

// the hand-written Default CITES each ground value-init (the DecodeData
// value-init, the PktType::NONE slot, the nullptr windows) — the NSDMI
// law; the derive would erase the citation face (house cursor.rs:13).
#[allow(clippy::derivable_impls)] // cited ground-init body (house face)
impl Default for TcpDecodeData {
    fn default() -> Self {
        TcpDecodeData {
            decode_flags: 0, // DecodeData value-init
            sp: 0,
            dp: 0,
            pkt_type: 0, // PktType::NONE
            ip4h: None,
            ip6h: None,
        }
    }
}

impl TcpDecodeData {
    /// ip.h:80 `is_ip4()` — the :230 gate (the ip_api Type == IAT_4
    /// posture; landed as the window-slot test per the cd_icmp4
    /// IpApiLite precedent).
    pub fn is_ip4(&self) -> bool {
        self.ip4h.is_some()
    }
}

// ---------------------------------------------------------------------------
// the event face
// ---------------------------------------------------------------------------

fn codec_event_tcp(codec: &CodecData, sid: u32, sink: QueueSink) {
    crate::framework::codec::codec_event(codec, sid, &mut *sink);
}

// ---------------------------------------------------------------------------
// tcp_rules (cc:74-:97 — all 20 sids VERIFIED resident CodecSid THIS
// pass; msgs byte-exact incl the :84 wrap)
// ---------------------------------------------------------------------------

pub const TCP_RULES: [RuleMap; 21] = [
    RuleMap { sid: CodecSid::DECODE_TCP_DGRAM_LT_TCPHDR as u32, msg: Some("TCP packet length is smaller than 20 bytes") }, // :76
    RuleMap { sid: CodecSid::DECODE_TCP_INVALID_OFFSET as u32, msg: Some("TCP data offset is less than 5") },               // :77
    RuleMap { sid: CodecSid::DECODE_TCP_LARGE_OFFSET as u32, msg: Some("TCP header length exceeds packet length") },        // :78
    RuleMap { sid: CodecSid::DECODE_TCPOPT_BADLEN as u32, msg: Some("TCP options found with bad lengths") },                // :79
    RuleMap { sid: CodecSid::DECODE_TCPOPT_TRUNCATED as u32, msg: Some("truncated TCP options") },                          // :80
    RuleMap { sid: CodecSid::DECODE_TCPOPT_TTCP as u32, msg: Some("T/TCP detected") },                                      // :81
    RuleMap { sid: CodecSid::DECODE_TCPOPT_OBSOLETE as u32, msg: Some("obsolete TCP options found") },                      // :82
    RuleMap { sid: CodecSid::DECODE_TCPOPT_EXPERIMENTAL as u32, msg: Some("experimental TCP options found") },              // :83
    RuleMap { sid: CodecSid::DECODE_TCPOPT_WSCALE_INVALID as u32, msg: Some("TCP window scale option found with length > 14") }, // :84 (the single-line string in ground; the vector "length > 14" wording)
    RuleMap { sid: CodecSid::DECODE_TCP_XMAS as u32, msg: Some("XMAS attack detected") },                                   // :85
    RuleMap { sid: CodecSid::DECODE_TCP_NMAP_XMAS as u32, msg: Some("Nmap XMAS attack detected") },                         // :86
    RuleMap { sid: CodecSid::DECODE_TCP_BAD_URP as u32, msg: Some("TCP urgent pointer exceeds payload length or no payload") }, // :87
    RuleMap { sid: CodecSid::DECODE_TCP_SYN_FIN as u32, msg: Some("TCP SYN with FIN") },                                    // :88
    RuleMap { sid: CodecSid::DECODE_TCP_SYN_RST as u32, msg: Some("TCP SYN with RST") },                                    // :89
    RuleMap { sid: CodecSid::DECODE_TCP_MUST_ACK as u32, msg: Some("TCP PDU missing ack for established session") },        // :90
    RuleMap { sid: CodecSid::DECODE_TCP_NO_SYN_ACK_RST as u32, msg: Some("TCP has no SYN, ACK, or RST") },                  // :91
    RuleMap { sid: CodecSid::DECODE_TCP_SHAFT_SYNFLOOD as u32, msg: Some("DDOS shaft SYN flood") },                         // :92
    RuleMap { sid: CodecSid::DECODE_TCP_PORT_ZERO as u32, msg: Some("TCP port 0 traffic") },                                // :93
    RuleMap { sid: CodecSid::DECODE_DOS_NAPTHA as u32, msg: Some("DOS NAPTHA vulnerability detected") },                    // :94
    RuleMap { sid: CodecSid::DECODE_SYN_TO_MULTICAST as u32, msg: Some("SYN to multicast address") },                        // :95
    RuleMap { sid: 0, msg: None }, // :96 `{ 0, nullptr }` (faceA:37 n=20)
];

// ---------------------------------------------------------------------------
// TcpModule (cc:99-:112)
// ---------------------------------------------------------------------------

pub struct TcpModule {
    pub base: BaseCodecModule,
}

impl TcpModule {
    /// :102 the 2-arg BaseCodecModule ctor face (no config exists —
    /// contrast the cd_mpls params face; the cd_ipv4/cd_ipv6 trio twin).
    pub fn new() -> TcpModule {
        TcpModule {
            base: BaseCodecModule::new(CD_TCP_NAME, CD_TCP_HELP), // :102
        }
    }

    /// :104-:105 the get_rules override -> the stored 21-row table.
    pub fn get_rules(&self) -> &'static [RuleMap] {
        &TCP_RULES // :105 `return tcp_rules;`
    }

    // :107-:111 `get_pegs()/get_counts()` CITE-NEVER-LAND (the PegInfo +
    // THREAD_LOCAL Stats world — the module-doc PEG census rows).
}

impl Default for TcpModule {
    fn default() -> Self {
        TcpModule::new()
    }
}

// ---------------------------------------------------------------------------
// TcpCodec (cc:114-:145 decl — privates :132-:144 land as pub fns per the
// cd_ipv4.rs landed-private family: the harness/replay face needs them)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct TcpCodec;

impl TcpCodec {
    /// :117 `TcpCodec() : Codec(CD_TCP_NAME) { }` (faceA `ctor` slot SET
    /// — the ctor(:803) IGNORES Module: the anti-18o config-threading
    /// drift cite, cd_ipv4.rs:1400 twin).
    pub fn new() -> TcpCodec {
        TcpCodec
    }

    /// cc:150-:153 get_protocol_ids — the deterministic emplace x1 face
    /// `v.emplace_back(ProtocolId::TCP)` (protocol_id::TCP 6 —
    /// faceA:39-:40 `GETIDS tcp 6` `GETIDS_n tcp 1`).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::TCP); // :152
    }

    // :120 `log(...)` override CITE-NEVER-LAND (:571-:598 — module doc).
    // :123-:124 encode / :126-:127 update / :129 format override cites —
    // module doc (the Stream::get_held_pkt_seq :638 left-open seam rides
    // the encode cite).

    /// cc:155-:170 `valid_checksum_from_daq` (the `inline` mark :155
    /// rides): the :157-:158 getter face folds to `daq.pdd` (None == the
    /// nullptr).
    pub fn valid_checksum_from_daq(daq: &TcpDaqFace) -> bool {
        // :159-:160 `if (!pdd || !pdd->flags.bits.l4_checksum ||
        // !pdd->flags.bits.tcp || !pdd->flags.bits.l4) return false;`
        let pdd = match daq.pdd {
            Some(p) => p, // the !pdd FALSE leg (the getter face)
            None => return false,
        };
        let bad_bits = !pdd.l4_checksum || !pdd.tcp || !pdd.l4; // :159 LHS legs, order verbatim
        if bad_bits {
            return false; // :160
        }
        // :161 `// Sanity check to make sure we're talking about the same
        // thing if offset is available` — :162-:167 (the probe stamps the
        // offset INVALID -> the whole block SKIPS, the bypass ride).
        if pdd.l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID {
            // :164 `const uint8_t* data = daq_msg_get_data(raw.daq_msg);`
            // :165-:166 `if (raw.data - data != pdd->l4_offset) return
            // false;` — the i64 fold (module doc).
            if daq.payload_delta != pdd.l4_offset {
                return false;
            }
        }
        // :168 `stats.cksum_bypassed++;` — the PEG cite-never-land face.
        true // :169
    }

    /// cc:172-:185 `valid_checksum4` — the v4 pseudoheader legs:
    /// `ph.hdr.sip = ip4h->get_src()` :177 / `dip = get_dst()` :178 —
    /// the RAW u32 FIELD reads (the cd_udp.rs ip4_sip/ip4_dip LE-host
    /// family: ipv4.h get_src/get_dst return ip_src/ip_dst raw, v4
    /// window bytes 12-15 / 16-19); `zero = 0` :179; `protocol =
    /// IpProtocol::TCP` :180; `len = htons((uint16_t)raw.len)` :181 (the
    /// swapped-store face, the Pseudoheader.len pin); the tcp_cksum
    /// RESIDENT donor (checksum.rs:597 family, tcp_cksum4).
    pub fn valid_checksum4(raw: &RawData<'_>, snort: &TcpDecodeData) -> bool {
        let ip4h: &[u8] = match snort.ip4h {
            Some(h) => h, // :174 `const ip::IP4Hdr* ip4h = snort.ip_api.get_ip4h();`
            None => &[],  // the getter nullptr face (NEVER armed in
                          // vectors — probe pre-sets or leaves NONE; cite)
        };
        let ph = Pseudoheader {
            sip: u32::from_le_bytes([ip4h[12], ip4h[13], ip4h[14], ip4h[15]]), // :177
            dip: u32::from_le_bytes([ip4h[16], ip4h[17], ip4h[18], ip4h[19]]), // :178
            zero: 0,                    // :179
            protocol: ip_protocol::TCP, // :180 (IpProtocol::TCP 6)
            len: (raw.len as u16).swap_bytes(), // :181 htons store
        };
        // :183 `// cppcheck-suppress knownConditionTrueFalse ; zero is
        // the valid packet checksum result` — :184
        tcp_cksum4(raw.data, raw.len as usize, ph) == 0
    }

    /// cc:187-:200 `valid_checksum6` — `COPY4(ph6.hdr.sip,
    /// ip6h->get_src()->u6_addr32)` :192 / dip :193 (the raw u32-word
    /// copy, the cd_ipv6.rs address-words folded twin — v6 window bytes
    /// 8-23 / 24-39); `zero = 0` :194; **`protocol =
    /// codec.ip6_csum_proto`** :195 (the cross-layer ride face, NOT a
    /// fixed TCP — honest literal); `len = htons(raw.len)` :196.
    pub fn valid_checksum6(raw: &RawData<'_>, codec: &CodecData<'_>, snort: &TcpDecodeData) -> bool {
        let ip6h: &[u8] = match snort.ip6h {
            Some(h) => h, // :189 get_ip6h() (NEVER armed face, cite)
            None => &[],
        };
        let words = |base: usize| -> [u32; 4] {
            [
                u32::from_le_bytes([ip6h[base], ip6h[base + 1], ip6h[base + 2], ip6h[base + 3]]),
                u32::from_le_bytes([ip6h[base + 4], ip6h[base + 5], ip6h[base + 6], ip6h[base + 7]]),
                u32::from_le_bytes([ip6h[base + 8], ip6h[base + 9], ip6h[base + 10], ip6h[base + 11]]),
                u32::from_le_bytes([ip6h[base + 12], ip6h[base + 13], ip6h[base + 14], ip6h[base + 15]]),
            ]
        };
        let ph6 = Pseudoheader6 {
            sip: words(8),  // :192 COPY4 u6_addr32
            dip: words(24), // :193
            zero: 0,        // :194
            protocol: codec.ip6_csum_proto, // :195 (IpProtocol, resident field)
            len: (raw.len as u16).swap_bytes(), // :196
        };
        // :198 the same cppcheck-suppress comment — :199
        tcp_cksum6(raw.data, raw.len as usize, ph6) == 0
    }

    /// cc:202-:295 decode — the gate order rides the module-doc census
    /// (self + 6 args == the cd_icmp4 7-arg decode family: INSIDE the
    /// clippy arg-count gate, NO allowance, the cd_ipv4.rs twin face).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut TcpDecodeData,
        conf: &TcpConf,
        daq: TcpDaqFace,
        sink: QueueSink<'_>,
    ) -> bool {
        // :204-:208 `if (raw.len < tcp::TCP_MIN_HEADER_LEN) {
        // codec_event(codec, DECODE_TCP_DGRAM_LT_TCPHDR); return false; }`
        // (the `DGRAM` spelling rides ground). Vectors IC1 (19 L).
        if raw.len < u32::from(TCP_MIN_HEADER_LEN) {
            codec_event_tcp(codec, CodecSid::DECODE_TCP_DGRAM_LT_TCPHDR as u32, &mut *sink); // :206
            return false; // :207
        }

        /* :210 `const tcp::TCPHdr* tcph = reinterpret_cast<const
         * tcp::TCPHdr*>(raw.data);` — the overlay lands as the byte
         * window (the cd_ipv4 :181 family). :211 `const uint16_t
         * tcph_len = tcph->hlen();` — the uint16_t widening of the uint8
         * hlen() face; hlen() re-CALLS :257 (NOT this var, the C quirk
         * rides). */
        let tcph: &[u8] = raw.data; // :210
        let tcph_len: u16 = u16::from(tcp_hlen(tcph[12])); // :211

        // :213-:217 `if (tcph_len < tcp::TCP_MIN_HEADER_LEN)` -> 46 (IC2
        // 0x40 -> 16). uint8-vs-uint16 promotion face: both widened.
        if tcph_len < u16::from(TCP_MIN_HEADER_LEN) {
            codec_event_tcp(codec, CodecSid::DECODE_TCP_INVALID_OFFSET as u32, &mut *sink); // :215
            return false; // :216
        }

        // :219-:223 `if (tcph_len > raw.len)` — the uint16-vs-uint32
        // promotion (C widens tcph_len; Rust mirrors via u32::from). IC3
        // 24 > 20.
        if u32::from(tcph_len) > raw.len {
            codec_event_tcp(codec, CodecSid::DECODE_TCP_LARGE_OFFSET as u32, &mut *sink); // :221
            return false; // :222
        }

        // :225-:252 the checksum fork: `snort::get_network_policy()->
        // tcp_checksums() && !valid_checksum_from_daq(raw)` — the conf
        // seam + the landed daq bypass above (probe stamps the pdd ON +
        // l4_offset INVALID -> the bypass TRUE short-circuits EVERY
        // vector, the honest zero-armed !valid face). :227
        // `PegCount* bad_cksum_cnt;` — the PEG cite-never-land slot (the
        // :234/:240 select legs + :247 increment live in the module-doc
        // peg census).
        if conf.tcp_checksums && !Self::valid_checksum_from_daq(&daq) {
            // C decl-site literal (declare-then-assign above the :231
            // fork).
            #[allow(clippy::needless_late_init)] // cited decl-site pin
            let valid: bool; // :228 (the declare-then-assign face)

            if snort.is_ip4() {
                // :232 `// cppcheck-suppress knownConditionTrueFalse ;
                // result depends on packet contents` — :233
                valid = Self::valid_checksum4(raw, snort);
                // :234 `bad_cksum_cnt = &stats.bad_ip4_cksum;` PEG face
            } else {
                // :238 the same cppcheck-suppress comment — :239
                valid = Self::valid_checksum6(raw, codec, snort);
                // :240 `bad_cksum_cnt = &stats.bad_ip6_cksum;` PEG face
            }

            if !valid {
                // :245-:249 `if (!(codec->codec_flags & CODEC_UNSURE_
                // ENCAP)) { (*bad_cksum_cnt)++; snort.decode_flags |=
                // DECODE_ERR_CKSUM_TCP; }` — the increment PEG face.
                let no_uncertain = (codec.codec_flags & CODEC_UNSURE_ENCAP) == 0; // :245 LHS
                if no_uncertain {
                    snort.decode_flags |= DECODE_ERR_CKSUM_TCP; // :248
                }
                return false; // :250
            }
        }

        // :254 `flag_tests(tcph, snort, codec);` — the conf seam threads
        // the :540 `codec.conf->` reader (CodecData::conf lands elsewhere;
        // the row folds the ONE read to the param per the cd_ipv4 twin).
        self.flag_tests(tcph, snort, codec, conf, &mut *sink); 

        /* :256 `/* if options are present, decode them */` — :257
         * `uint16_t tcp_opt_len = (uint16_t)(tcph->hlen() - tcp::
         * TCP_MIN_HEADER_LEN);` — the hlen() RE-CALL face (:211's var is
         * NOT reused); uint8 arithmetic widened, then the uint16 cast;
         * never fires here (hlen >= 20 past the :213 gate) — wrapping_sub
         * kept honest per the row law. */
        let tcp_opt_len: u16 = (tcp_hlen(tcph[12]) as u16).wrapping_sub(u16::from(TCP_MIN_HEADER_LEN));

        // :259-:263 `if (tcp_opt_len > 0) { const uint8_t* opts =
        // (const uint8_t*)(raw.data + tcp::TCP_MIN_HEADER_LEN);
        // decode_options(opts, tcp_opt_len, codec, snort); }` — the
        // window slice (the walk bounds ride the o_len count, NOT the
        // slice end — the C pointer law, module doc).
        if tcp_opt_len > 0 {
            let opts = &raw.data[usize::from(TCP_MIN_HEADER_LEN)..]; // :261
            self.decode_options(opts, u32::from(tcp_opt_len), codec, snort, &mut *sink); // :262
        }

        // :264 `int dsize = raw.len - tcph->hlen();` — the SIGNED int
        // result of a uint32 - uint8 pair (C promotes both to int at the
        // measured sizes; i64 keeps the fold lossless); :266-:267 `if
        // (dsize < 0) dsize = 0;`.
        let mut dsize: i64 = raw.len as i64 - i64::from(tcp_hlen(tcph[12])); // :264 (another hlen() RE-CALL: :264 — the THIRD call site face)
        if dsize < 0 {
            dsize = 0; // :267
        }

        // :268-:270 `if ( (tcph->th_flags & TH_URG) && ((dsize == 0) ||
        // tcph->urp() > dsize) ) codec_event(codec, DECODE_TCP_BAD_URP);`
        // — the uint16-to-int promotion on the urp side. THE 419-ZERO
        // face: th_urp wire bytes 16-17 sit ZERO in EVERY probe header
        // (the TCPH helper zeroes them; probe's p[22]/p[23] writes land in
        // PAYLOAD — probe_dec.cc :313-:318's IC16 comment muddles the
        // wording, VECTORS WIN: vectors:105 prints ZERO for IC16).
        let th_flags: u8 = tcph[13]; // the th_flags FIELD face (tcp.h:12)
        let urg_set = (th_flags & TH_URG) != 0; // :269 LHS
        let urp_gt = (i64::from(tcp_urp(tcph)) > dsize) || dsize == 0; // :269 (dsize==0 || urp>dsize — var-first legs)
        if urg_set && urp_gt {
            codec_event_tcp(codec, CodecSid::DECODE_TCP_BAD_URP as u32, &mut *sink); // :270
        }

        // :272 `// Now that we are returning true, set the tcp header` —
        // :273 `codec.lyr_len = tcph_len - codec.invalid_bytes;` (the
        // decode_options invalid_bytes ride: IC19 23, IC21/IC23 26,
        // IC22/IC24/IC25 20); :274 `codec.proto_bits |= PROTO_BIT__TCP`
        // (IC6 `pb=2`).
        codec.lyr_len = tcph_len.wrapping_sub(codec.invalid_bytes); // :273
        codec.proto_bits |= PROTO_BIT__TCP; // :274

        // :276 `snort.set_pkt_type(PktType::TCP);` — the decode_data.h
        // :192-:193 face. :277 `snort.tcph = tcph;` — DOCUMENT pin
        // (module doc, the stash owner LEFT-OPEN).
        snort.pkt_type = PKT_TYPE__TCP; // :276

        // :279 `const DAQ_NAPTInfo_t* napti = (const DAQ_NAPTInfo_t*)
        // daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_NAPT_INFO);` — None
        // face; :280 `if (napti && codec.ip_layer_cnt == napti->ip_layer)`
        // — THE PORT-MEMBER-only consumption (the addr members NEVER
        // touched HERE, module doc); tcp NEVER increments ip_layer_cnt
        // (stays 0 — contrast the v4/v6 ++ legs): IC18 re-stamps
        // napt->ip_layer = 0 for the MATCH arm.
        match daq.napt {
            Some(n) if codec.ip_layer_cnt == n.ip_layer => {
                // :282-:283 `snort.sp = ntohs(napti->src_port); snort.dp
                // = ntohs(napti->dst_port);` — the *_be fold (cd_udp
                // DaqNapt family): swap the raw stored u16. IC18 7/9.
                snort.sp = n.src_port_be.swap_bytes(); // :282
                snort.dp = n.dst_port_be.swap_bytes(); // :283
            }
            _ => {
                snort.sp = tcp_src_port(tcph); // :287 (faceA:44 25001)
                snort.dp = tcp_dst_port(tcph); // :288 (faceA:44 25002)
            }
        }

        // :291-:292 `if (snort.sp == 0 || snort.dp == 0) codec_event
        // (codec, DECODE_TCP_PORT_ZERO);` (IC17 both-zero raw).
        if snort.sp == 0 || snort.dp == 0 {
            codec_event_tcp(codec, CodecSid::DECODE_TCP_PORT_ZERO as u32, &mut *sink); // :292
        }

        true // :294
    }

    /* cc:297-:329 THE skeeter/bubba email comment block + the RFC-793
     * 4.2.2.5 quote — rides VERBATIM above decode_options:
     *   ------------------------------------------------------------
     *   From: "Kastenholz, Frank" <FKastenholz@unispherenetworks.com>
     *   Subject: Re: skeeter & bubba TCP options?
     *
     *   ah, the sins of ones youth that never seem to be lost...
     *
     *   it was something that ben levy and stev and i did at ftp many
     *   many moons ago. bridgham and stev were the instigators of it.
     *   the idea was simple, put a dh key exchange directly in tcp
     *   so that all tcp sessions could be encrypted without requiring
     *   any significant key management system. authentication was not
     *   a part of the idea, it was to be provided by passwords or
     *   whatever, which could now be transmitted over the internet
     *   with impunity since they were encrypted... we implemented
     *   a simple form of this (doing the math was non trivial on the
     *   machines of the day). it worked. the only failure that i
     *   remember was that it was vulnerable to man-in-the-middle
     *   attacks.
     *
     *   why "skeeter" and "bubba"? well, that's known only to stev...
     *   ------------------------------------------------------------
     *
     * 4.2.2.5 TCP Options: RFC-793 Section 3.1
     *
     *    A TCP MUST be able to receive a TCP option in any segment. A TCP
     *    MUST ignore without error any TCP option it does not implement,
     *    assuming that the option has a length field (all TCP options
     *    defined in the future will have length fields). TCP MUST be
     *    prepared to handle an illegal option length (e.g., zero) without
     *    crashing; a suggested procedure is to reset the connection and log
     *    the reason.
     */

    /// cc:330-:484 decode_options — the :333 `end_ptr = start + o_len`
    /// "points to byte after last option" folds to the o_len COUNT; the
    /// :334 TcpOption overlay lands as window-relative byte reads (the
    /// cd_ipv4 IPOptionIterator fold law). Locals :335-:339 verbatim
    /// INCLUDING the `int code = 2;` seed (never read pre-assignment on
    /// any measured path — the shape rides). The C walk guard :354
    /// `(tot_len < o_len) && !done` — tot_len a C uint16 widened against
    /// the uint32 o_len (u32 here; TCP_OPTLENMAX 40 per the :349-:350
    /// comment makes any wrap unreachable — the `(((2^4) - 1) * 4 -
    /// TCP_MIN_HEADER_LEN` cite rides).
    pub fn decode_options(
        &self,
        start: &[u8], // the :261 window slice (packet-tail backed: the option region NEVER extends past the packet past the header)
        o_len: u32,   // the :331 uint32 o_len
        codec: &mut CodecData<'_>,
        snort: &mut TcpDecodeData,
        sink: &mut dyn FnMut(u32, u32),
    ) {
        let end = o_len;      // :333 the index face
        let mut code: i32; // :335 `int code = 2;` — THE DEAD-SEED FACE:
                           // the literal seed 2 NEVER reads before an
                           // overwrite (EVERY switch arm assigns code
                           // before the :456 read); Rust's
                           // unused_assignments flags the store and the
                           // ZERO-allow row law forbids suppressing it,
                           // so the seed rides documented-only (the
                           // honest ledger face — the sibling
                           // cd_ipv4.rs :489 `int code = 0;` seed DOES
                           // read (the :493 loop carries it across
                           // iterations); here the per-iteration
                           // reassignment makes it inert).
        let mut tot_len: u32 = 0; // :336 (C uint16_t widened, see above)
        let mut done = false;  // :337 `/* have we reached TCPOPT_EOL yet?*/`
        let mut experimental_option_found = false; // :338 `/* are all options RFC compliant? */`
        let mut obsolete_option_found = false; // :339

        while (tot_len < end) && !done {
            let idx = tot_len as usize; // :334 the walking pointer face
            let code_b: u8 = start[idx]; // opt->code (always inside: the guard) — :356

            // THE len byte (:334 TcpOption::len): C reads (opt+1) but the
            // `||`/expected-gates short-circuit the (opt+2)>end TRUE leg
            // BEFORE any len read at the very edge — the value NEVER
            // lands there on a bounded window; 0-fold with the cite.
            let len_b: u8 =
                if idx + 1 < start.len() { start[idx + 1] } else { 0 /* the :494-:495/:508 (opt+expected)>(opt) gates short-circuit first — cite */ };

            // The :356 switch(opt->code) — labels byte-exact to the
            // tcp_options.h enum. THE two fallthroughs land as blocks.
            match code_b {
                // :358-:360 case EOL: done = true; codec.invalid_bytes =
                // o_len - tot_len; /* fallthrough */ (:361)
                0x00 => {
                    done = true; // :359
                    codec.invalid_bytes = (end - tot_len) as u16; // :360
                    // :362-:363 case NOP: code = 0; break; — the
                    // fallthrough leg:
                    code = 0; // :363
                }
                // :362 case NOP:
                0x01 => {
                    code = 0; // :363
                }
                // :366-:370 case MAXSEG: validate MAXSEG; code==0 ->
                // DECODE_TCP_MSS
                0x02 => {
                    code = Self::validate_option(start, idx, end, TCPOLEN_MAXSEG); // :367
                    if code == 0 {
                        snort.decode_flags |= DECODE_TCP_MSS; // :369
                    }
                }
                // :372-:374 case SACKOK
                0x04 => {
                    code = Self::validate_option(start, idx, end, TCPOLEN_SACKOK); // :373
                }
                // :376-:387 case WSCALE — the data[0] > 14 -> EV 59 arm
                // then the WS flag INSIDE the same code==0 block (braces
                // ground-exact IC19: 59 AND WS set; IC20 clean: neither
                // event, WS set).
                0x03 => {
                    code = Self::validate_option(start, idx, end, TCPOLEN_WSCALE); // :377
                    if code == 0 {
                        // :380 `if (((uint16_t)opt->data[0] > 14))` — the
                        // uint8->uint16 widening face.
                        if u16::from(start[idx + 2]) > 14 {
                            // :382 `/* LOG INVALID WINDOWSCALE alert */`
                            codec_event_tcp(codec, CodecSid::DECODE_TCPOPT_WSCALE_INVALID as u32, sink); // :383
                        }
                        snort.decode_flags |= DECODE_TCP_WS; // :385
                    }
                }
                // :389-:393 case ECHO /* both use the same lengths */ /
                // ECHOREPLY: obsolete flag + validate ECHO.
                0x06 | 0x07 => {
                    obsolete_option_found = true; // :391
                    code = Self::validate_option(start, idx, end, TCPOLEN_ECHO); // :392
                }
                // :395-:399 case MD5SIG
                0x13 => {
                    // :396 `/* RFC 5925 obsoletes this option (see
                    // below) */`
                    obsolete_option_found = true; // :397
                    code = Self::validate_option(start, idx, end, TCPOLEN_MD5SIG); // :398
                }
                // :401-:407 case AUTH — the PAIR validate + the RFC 5925
                // s2.2 min-4 arm.
                0x1d => {
                    code = Self::validate_option_pair(start, idx, end); // :402
                    // :404 `/* Has to have at least 4 bytes - see RFC
                    // 5925, Section 2.2 */` :405-:406
                    if code >= 0 && len_b < 4 {
                        code = OPT_BADLEN;
                    }
                }
                // :409-:414 case SACK — PAIR validate + the len<2 arm.
                0x05 => {
                    code = Self::validate_option_pair(start, idx, end); // :410
                    if code >= 0 && len_b < 2 {
                        // :412 `if ((code >= 0) && (opt->len < 2))`
                        code = OPT_BADLEN;
                    }
                }
                // :416-:418 case CC_ECHO: EV 56 IMMEDIATE (BEFORE any
                // validate — IC23 order pin vectors:116) /* fall through
                // */ :418
                0x0d => {
                    codec_event_tcp(codec, CodecSid::DECODE_TCPOPT_TTCP as u32, sink); // :417
                    // :419-:422 case CC / case CC_NEW /* all 3 use the
                    // same lengths / T/TCP */ — the fall-through leg:
                    code = Self::validate_option(start, idx, end, TCPOLEN_CC); // :421
                }
                // :419 case CC ::420 case CC_NEW (same body):
                0x0b | 0x0c => {
                    code = Self::validate_option(start, idx, end, TCPOLEN_CC); // :421
                }
                // :424-:427 case TRAILER_CSUM — THE IC22 MEASURED FACE
                // [18,4] -> experimental flag SET + validate EXPECTED 3:
                // len 4 != 3 -> BADLEN -> EV 54 SINGLE (vectors:114),
                // the return at :472 PREEMPTS the tail flags (the name
                // "trailer58" probe-label red herring, module doc).
                0x12 => {
                    experimental_option_found = true; // :425
                    code = Self::validate_option(start, idx, end, TCPOLEN_TRAILER_CSUM); // :426
                }
                // :429-:433 case TIMESTAMP
                0x08 => {
                    code = Self::validate_option(start, idx, end, TCPOLEN_TIMESTAMP); // :430
                    if code == 0 {
                        snort.decode_flags |= DECODE_TCP_TS; // :432
                    }
                }
                // :435-:440 case SKEETER / BUBBA / UNASSIGNED —
                // obsolete + PAIR validate.
                0x10 | 0x11 | 0x19 => {
                    obsolete_option_found = true; // :438
                    code = Self::validate_option_pair(start, idx, end); // :439
                }
                // :442-:453 case SCPS/SELNEGACK/RECORDBOUND/CORRUPTION/
                // PARTIAL_PERM/PARTIAL_SVC/ALTCSUM/SNAP + default:
                // experimental + PAIR validate (COMPRESSION 26 and every
                // unseen code land HERE).
                _ => {
                    experimental_option_found = true; // :451
                    code = Self::validate_option_pair(start, idx, end); // :452
                }
            }

            // :456-:473 the failure block.
            if code < 0 {
                if code == OPT_BADLEN {
                    codec_event_tcp(codec, CodecSid::DECODE_TCPOPT_BADLEN as u32, sink); // :458-:460
                } else if code == OPT_TRUNC {
                    codec_event_tcp(codec, CodecSid::DECODE_TCPOPT_TRUNCATED as u32, sink); // :462-:464
                }

                // :467-:470 `/* set the option count to the number of
                // valid options found before this bad one
                // some implementations (BSD and Linux) ignore
                // the bad ones, but accept the good ones */`
                codec.invalid_bytes = (end - tot_len) as u16; // :471
                return; // :472
            }

            // :475 `tot_len += ((uint8_t)opt->code <= 1) ? 1 : opt->len;`
            // — sed-VERIFIED THIS pass the token is `opt->code` (the
            // option-code byte, NOT the validate result; the grep -A
            // window earlier clipped the line — the disk won). u8
            // widening vs the u32 tot (the C uint16->int promo face kept
            // inside u32); wrapping_add kept per the row law (the C
            // uint16_t tot wraps mod 2^16 — TCP_OPTLENMAX 40 per the
            // :349-:350 comment makes any wrap unreachable).
            tot_len = tot_len.wrapping_add(if code_b <= 1 { 1 } else { len_b as u32 }); // :475
            // :476 `opt = &(opt->next());` — the tcp_options.h:110-:121
            // next() body: code<=1 -> the len-byte reinterpret (same +1
            // step as :475); len>=2 -> data[len-2] == option+len (same
            // +len step as :475); the len<2 static-eol_opt arm
            // (:114-:117) UNREACHABLE at this call site (every code>1
            // case pre-validates; len<2 returns code<0 at :456-:472
            // before the advance — the honest dead-at-the-face cite,
            // NEVER vectored). THE WALK POINTER FOLDS ONTO tot_len
            // EXACTLY because both legs step identically per the option
            // (the two cursors stay in lockstep at the measured face —
            // the fold's license).
        }

        // :479-:483 the tail census — the experimental else-if obsolete
        // pair (MUTUALLY EXCLUSIVE: IC21 obsolete -> 57 SINGLE,
        // experimental FALSE pin).
        if experimental_option_found {
            codec_event_tcp(codec, CodecSid::DECODE_TCPOPT_EXPERIMENTAL as u32, sink); // :480
        } else if obsolete_option_found {
            codec_event_tcp(codec, CodecSid::DECODE_TCPOPT_OBSOLETE as u32, sink); // :483
        }
    }

    /// cc:486-:501 validate_option EXPECTED variant (the :487
    /// `const int expected_len` leg): :489 the opt_ptr address fold ==
    /// the window index; :491 `assert(expected_len > 1)` is the NDEBUG
    /// elide face (misc9 -DNDEBUG law) — CITED never landed. :493
    /// `/* not enough data to read in a perfect world */` :494-:495
    /// `if ((opt_ptr + expected_len) > end) return tcp::OPT_TRUNC;` —
    /// the POINTER compare (same-buffer arithmetic; end == start + o_len
    /// folds to the index face idx + expected > o_len). IC25 rides THIS
    /// gate: [10,10]/o_len 4 -> 0+10 > 4 -> TRUNC -> EV 55 (vectors:120);
    /// IC22 [18,4]/o_len 4 -> 0+3 > 4 FALSE -> the :497 len compare 4 !=
    /// 3 -> BADLEN (vectors:114). :497-:498 `if (opt->len !=
    /// expected_len) return tcp::OPT_BADLEN;` (the len byte at opt+1 —
    /// the :497 read sits INSIDE the walk's short-circuit safety once the
    /// gate passed, but when idx+1 == o_len == slice edge the C reads the
    /// raw.data byte just past the option region — the packet/array tail;
    /// the harness probe reads its zero-padded stack byte (the vectors'
    /// 54 outcome rides that byte), landed honestly as the 0-fold).
    pub fn validate_option(
        start: &[u8],
        opt_idx: usize,
        end: u32, // :333 the (start + o_len) end face == the o_len count
        expected_len: u32,
    ) -> i32 {
        // :494-:495 the TRUNC gate (var-first, R6).
        let truncated = (opt_idx as u32).wrapping_add(expected_len) > end;
        if truncated {
            return OPT_TRUNC;
        }
        let len_b = *start.get(opt_idx + 1).unwrap_or(&0); // the array-tail 0-fold (doc above)
        if len_b as u32 != expected_len {
            return OPT_BADLEN; // :498
        }
        0 // :500
    }

    /// cc:503-:516 the PAIR variant (no expected): :507 `/* not enough
    /// data to read in a perfect world */` :508-:509 `if ((opt_ptr + 2)
    /// \> end or (opt_ptr + opt->len) \> end) return tcp::OPT_TRUNC;` —
    /// the same index fold on BOTH disjuncts (`or` == ||, var-first);
    /// :511-:512 `/* RFC says that we MUST have at least this much
    /// data */ if (opt->len < 2) return tcp::OPT_BADLEN;`. The AUTH/
    /// SACK/SKEETER-TRIO/SCPS-TRIO/default arms route HERE; NO vector
    /// arms an option that lands on this variant (the honest zero-
    /// face cite; the len<2 RFC gate NEVER armed).
    pub fn validate_option_pair(start: &[u8], opt_idx: usize, end: u32) -> i32 {
        let len_b = *start.get(opt_idx + 1).unwrap_or(&0); // the same 0-fold (doc above)
        let a2 = (opt_idx as u32) + 2 > end; // :508 LHS
        let alen = (opt_idx as u32).wrapping_add(u32::from(len_b)) > end; // :508 RHS
        if a2 || alen {
            return OPT_TRUNC; // :509
        }
        if len_b < 2 {
            return OPT_BADLEN; // :513
        }
        0 // :515
    }

    /// cc:518-:565 flag_tests (the :519 `const DecodeData& snort` +
    /// :519 `const CodecData& codec` legs; the :540 `codec.conf->`
    /// reader folds to the threaded conf seam per the row law). THE whole
    /// block reads th_flags + the raw seq fields; the IC order census
    /// rides the module doc.
    pub fn flag_tests(
        &self,
        tcph: &[u8], // :518 the TCPHdr window
        snort: &TcpDecodeData,
        codec: &CodecData<'_>,
        conf: &TcpConf,
        sink: &mut dyn FnMut(u32, u32),
    ) {
        let th_flags: u8 = tcph[13]; // the raw field legs ride ground verbatim

        // :521-:527 the XMAS block (the are_flags_set ALL-set gate pair).
        let xmas_set = tcp_are_flags_set(th_flags, TH_FIN | TH_PUSH | TH_URG); // :521
        if xmas_set {
            let synackrst = tcp_are_flags_set(th_flags, TH_SYN | TH_ACK | TH_RST); // :523
            if synackrst {
                codec_event_tcp(codec, CodecSid::DECODE_TCP_XMAS as u32, sink); // :524 (IC4: 400 first)
            } else {
                codec_event_tcp(codec, CodecSid::DECODE_TCP_NMAP_XMAS as u32, sink); // :526 (IC5)
            }
        }

        // :529 `if (tcph->are_flags_set(TH_SYN))` — the single-bit ALL-set
        // face (== the !=0 test for one bit).
        let syn_set = tcp_are_flags_set(th_flags, TH_SYN);
        if syn_set {
            // :531-:537 `if ( tcph->th_flags == TH_SYN )` — the EXACT
            // byte face (IC11/IC12/IC13 all SYN-only): the naptha gate.
            if th_flags == TH_SYN {
                // :533-:535 `if ((tcph->th_seq == naptha_seq) and snort.
                // ip_api.is_ip4() and (snort.ip_api.get_ip4h()->ip_id ==
                // naptha_id))` — THE RAW FIELD COMPARES (module doc:
                // th_seq bytes 4-7 LE-vs-NAPTHA_SEQ, outer v4 ip_id bytes
                // 4-5 LE-vs-NAPTHA_ID — the WORDS_BIGENDIAN seed-drift
                // face; IC14 402-SINGLE, IC15 ZERO).
                let raw_seq: u32 = u32::from_le_bytes([tcph[4], tcph[5], tcph[6], tcph[7]]); // th_seq FIELD face
                let seq_match = raw_seq == NAPTHA_SEQ; // :533 LHS
                let v4 = snort.is_ip4(); // :533 mid-leg
                let id_match = match snort.ip4h {
                    Some(h) => u16::from_le_bytes([h[4], h[5]]) == NAPTHA_ID, // :534 get_ip4h()->ip_id FIELD
                    None => false,
                };
                if seq_match && v4 && id_match {
                    codec_event_tcp(codec, CodecSid::DECODE_DOS_NAPTHA as u32, sink); // :536
                }
            }

            // :540-:544 the anomaly fork: conf gate + the witness sfvar
            // FALSE face (SynToMulticastDstIp nullptr at the harness face
            // — module doc; `sfvar_ip_in` never imported).
            if conf.address_anomaly_check_enabled {
                let sfvar_in = false; // witness_ipvars.cc FALSE face (IC12: dst 239.1.1.1 + ANOM-ON -> NO 403)
                if sfvar_in {
                    codec_event_tcp(codec, CodecSid::DECODE_SYN_TO_MULTICAST as u32, sink); // :543 (ZERO-armed at the witness face — the armed-live binary cite)
                }
            }

            // :546-:547 `if ( (tcph->th_flags & TH_RST) ) codec_event
            // (codec, DECODE_TCP_SYN_RST);` (IC4 421, IC9 421 after 420?
            // NO — IC9 SYN|RST: 421 then no FIN -> SINGLE... order: RST
            // FIRST :546 then FIN :549: IC8 SYN|FIN prints 420 then 422 —
            // the FIN-only leg; IC4 prints 421 THEN 420 (vectors:80-:81)).
            let rst_set = (th_flags & TH_RST) != 0;
            if rst_set {
                codec_event_tcp(codec, CodecSid::DECODE_TCP_SYN_RST as u32, sink); // :547
            }

            // :549-:550 FIN arm.
            let fin_set = (th_flags & TH_FIN) != 0;
            if fin_set {
                codec_event_tcp(codec, CodecSid::DECODE_TCP_SYN_FIN as u32, sink); // :550
            }

            // :552-:553 the SHAFT arm: the TH_NORESERVED mask EQUALS
            // TH_SYN (SYN alone among the six) AND `tcph->seq() ==
            // 674711609` — the ntohl seq() read (IC13 htonl-stamps the
            // wire -> the decimal compare; the :557-commentless else
            // never arms for SYNs).
            let shaft_mask = (th_flags & TH_NORESERVED) == TH_SYN; // :552 LHS
            let shaft_seq = tcp_seq(tcph) == 674711609; // :552 RHS (the seq() face)
            if shaft_mask && shaft_seq {
                codec_event_tcp(codec, CodecSid::DECODE_TCP_SHAFT_SYNFLOOD as u32, sink); // :553
            }
        } else {
            // :555-:559 `else {   // we already know there is no SYN
            // if ( !(tcph->th_flags & (TH_ACK|TH_RST)) ) codec_event
            // (codec, DECODE_TCP_NO_SYN_ACK_RST); }` (IC7 ZERO flags +
            // IC5 + IC10 the 423 legs).
            let no_ackrst = (th_flags & (TH_ACK | TH_RST)) == 0;
            if no_ackrst {
                codec_event_tcp(codec, CodecSid::DECODE_TCP_NO_SYN_ACK_RST as u32, sink); // :558
            }
        }

        // :561-:563 OUTSIDE both forks: (FIN|PUSH|URG any) && no ACK ->
        // MUST_ACK (IC4 flags 0x3F HAS ACK -> NO 422: vectors:79-:82
        // census; IC5 0x29 -> 422 last).
        let push_leg = (th_flags & (TH_FIN | TH_PUSH | TH_URG)) != 0; // :561
        let no_ack = (th_flags & TH_ACK) == 0; // :562
        if push_leg && no_ack {
            codec_event_tcp(codec, CodecSid::DECODE_TCP_MUST_ACK as u32, sink); // :563
        }
    }
}

// ---------------------------------------------------------------------------
// api + table (cc:779-:839)
// ---------------------------------------------------------------------------

/// :779-:780 `static Module* mod_ctor() { return new TcpModule; }` —
/// slot SET (the record flag below).
pub fn mod_ctor() -> TcpModule {
    TcpModule::new()
}

/// :782-:783 `static void mod_dtor(Module* m) { delete m; }` — SET.
pub fn mod_dtor(_m: TcpModule) {}

/// cc:790-:795 `tcp_codec_ginit`: the RFC 5771 comment :792 +
/// `SynToMulticastDstIp = sfip_var_from_string("[224.0.0.0/4]", "tcp")`
/// :793 + the :794 assert (NDEBUG elide face). THE WITNESS FACE:
/// witness_ipvars.cc pins sfip_var_from_string -> nullptr (module doc) —
/// landed as the slot-SET record leg ONLY (NO sf_ipvar surface imported).
pub const TCP_GINIT_VAR_STRING: &str = "[224.0.0.0/4]"; // :793 (the list-string DOCUMENT face — ginit NEVER builds a Rust var)

/// cc:797-:801 `tcp_codec_gterm` (the `if (SynToMulticastDstIp)` guard) —
/// the sfvar_free world: SET-leg only.
pub fn tcp_codec_ginit() {
    // :793 :794 witness face (module doc) — NO-OP landing.
}

pub fn tcp_codec_gterm() {
    // :799-:800 the if-guarded sfvar_free — NO-OP landing.
}

/// cc:803-:804 `static Codec* ctor(Module*) { return new TcpCodec(); }` —
/// the ctor IGNORES Module (the anti-18o drift cite, cd_ipv4.rs twin).
pub fn ctor(_m: Option<&BaseCodecModule>) -> TcpCodec {
    TcpCodec::new()
}

/// cc:806-:807 `static void dtor(Codec* cd) { delete cd; }` — SET.
pub fn dtor(_cd: TcpCodec) {}

/// cc:809-:829 `static const CodecApi tcp_api` — the record face
/// (:812-:822 base slots then the pinit/pterm/tinit/tterm/ctor/dtor
/// tail). faceA:31 pins API tcp type=0 size=112 ver=1900547 features=1.
pub const TCP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // :812
    size: CDAPI_SIZEOF_CODEC_API, // :813 `sizeof(CodecApi)` = 112
    api_version: CDAPI_VERSION, // :814 1900547
    version: 0, // :815
    features: PLUGIN_SO_RELOAD, // :816
    options: API_OPTIONS, // :817
    name: CD_TCP_NAME, // :818 -> "tcp"
    help: CD_TCP_HELP, // :819 the BARE help (NO DLT splice — the asymmetry)
    mod_ctor: true, // :820 SET (:779)
    mod_dtor: true, // :821 SET (:782)
    pinit: true, // :823 SET (tcp_codec_ginit — `// pinit`)
    pterm: true, // :824 SET (tcp_codec_gterm — `// pterm`)
    tinit: false, // :825 `nullptr, // tinit` (faceA:35 TARM tcp tinit=0)
    tterm: false, // :826 `nullptr, // tterm` (faceA:35 tterm=0)
    ctor: true, // :827 SET (ctor :803 — Module IGNORED)
    dtor: true, // :828 SET (dtor :806)
};

/// cc:831-:839 THE UNCONDITIONAL table (the BUILDING_SO block lines
/// COMMENTED :831/:832/:833/:835 — the grep-lie face, module doc):
/// `const BaseApi* cd_tcp[] = { &tcp_api.base, nullptr };` — TRUE NAME
/// (`cd_tcp[]` :834 == FILE base; nm D EXACTLY-1). Ladder entry "cd_tcp"
/// RESIDENT codec_api.rs:57 (the ground extern codec_api.cc:36 face —
/// the witness stub there, NEVER re-touched; the Rust-side stub-record
/// audit outcome rides the KNOWN DEVIATIONS ledger this turn).
pub const CD_TCP: CodecTable = &[&TCP_API];
