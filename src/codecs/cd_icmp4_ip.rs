//! Port of `src/codecs/misc/cd_icmp4_ip.cc` (345 L) — row 18j, the misc
//! icmp _ip PAIR half one (`tools/miscip_harness`, ZERO-gate probe-only).
//! Ground: snort3-src @ fe29cbe, md5 `c0744dc1d4d38b3b66c3293acae1c04d`
//! wc 345 (miscip build.sh md5/wc pins every build). DIR FACT: `codecs/
//! misc/` (the pair finally lands in the misc dir — the 18h-pass "region
//! drift ip->misc for the _ip pair" face, honored at the row).
//!
//! THE HIDDEN-TABLE FACE (the row's census headline, miscip PLAN §2/§4 —
//! the FIRST BUILDING_SO-table row in the lineage): the export rides
//! `#ifdef BUILDING_SO` cc:336-:344 — the `snort_plugins[]` SO arm is
//! cc:337, the REAL table `const BaseApi* cd_icmp4_ip[] =` cc:339 feeds
//! `&icmp4_ip_api.base` cc:342; BUILDING_SO is NEVER defined anywhere
//! the harness builds, so `cd_icmp4_ip[]` EXISTS in every .o (nm table
//! symbol EXACTLY-1, PLAN §4). The string `cd_icmp4_ip[]` NEVER exists
//! in any .so face. Rust face = the landed-row pattern (cd_icmp4.rs
//! cc:637-:645 precedent, grep-verified ZERO `#[no_mangle]` in src): the
//! ifdef arms are doc-CITED, and the table lands as `pub const
//! CD_ICMP4_IP: CodecTable` — a record, not a link edge. TRUE NAME holds:
//! file base == table base == NAME "icmp4_ip" (cc:37 macro) x2 contrast
//! the cd_auth drift family (build.sh NAME/HELP macro sed pins).
//!
//! THE WITNESS HEADLINE (PLAN §0/§6, MEASURED): log() calls
//! `PacketManager::get_proto_name(ip4h->proto())` at cc:179 + cc:297 —
//! `IpHdr::proto()` returns **IpProtocol** (ip.h:116), so the pair objs
//! reference EXACTLY ONE new symbol (nm mangled census -eq 1, L1
//! undefined-EXACTLY-1; the NEXT "+2" prediction MEASURED DOWN, R2).
//! The ground def `protocols/packet_manager.cc:1004-:1008` walks
//! CodecManager::s_proto_map — that TU was NEVER compiled into any donor
//! (find tools = 0; 1,047 L). The Rust side NEVER invents the C++
//! PacketManager call: this row models the face with the harness
//! witness's OBSERVABLE body (witness_miscip.cc:25-:26 fixed
//! "witness_proto", the cited-minimal route after the real-body attempt
//! rc1: managers/codec_manager.h never cp'd) — the real CodecManager
//! walk home is queued (row 20 lands the 34-name load face). Log OUTPUT is
//! cite-never-vectorize: NO probe ever calls log() (vectors carry ZERO
//! log lines).
//!
//! SIX-EVENT DECODE FACE (the row's DEC ladder + the PYPIN sid census):
//! TRUNCATED cc:58 (gate :56), VER_MISMATCH cc:71 (gate :69 COMPOUND
//! `(ver!=4) && !snort.ip_api.is_ip6()` — the is_ip6 RIDER pair arms:
//! ver!=4+ip4-api DIES / ver!=4+ip6-api CONTINUES, vectors:5 survives
//! pb=16384), DGRAM_LT_ORIG_IP cc:79 (gate :77 raw.len<hlen),
//! PAYLOAD_LT_64 cc:91, PAYLOAD_GT_576 cc:99 — **event-THEN-CONTINUE,
//! NO return** (vectors:10 `gt576 -> 1 pb=8192 lyr=20`), IP_WITH_FRAGOFFSET
//! cc:105 via the off()!=0 else arm cc:102 (the RFC comment :104 rides).
//! ALL SIX sids RESIDENT (codec_module.rs:125-:130, ZERO new constants —
//! the cd_icmp4.rs:55 module doc pre-named THIS row: "the icmp4_ip embed
//! family, misc/cd_icmp4_ip.cc's later row"). ZERO RuleMap rows in this
//! TU (grep RuleMap|codec_rule 0/0, PLAN §3) — the pair carries no rules
//! table face at all.
//!
//! EMBED SWITCH cc:109-:125 (4 arms, `switch (ip4h->proto())`):
//! TCP -> PROTO_BIT__TCP_EMBED_ICMP 4096 / UDP -> _UDP_EMBED_ICMP 8192 /
//! ICMPV4 -> _ICMP_EMBED_ICMP 16384 / default -> _ICMP_EMBED_OTHER
//! 32768 (decode_data.h :99-:102 sed-pinned; ZERO landed Rust face for
//! the family -> row-scoped homes, the PROTO_BIT__UDP_TUNNELED
//! cd_udp.rs:158 precedent). lyr_len = hlen cc:129 — the TRUTH face:
//! the LYR len is the embedded IP header length, NOT a TCP data-offset.
//! The cc:127-:128 comment "If you change this, change the buffer and
//! memcpy length in encode() below !!" cites a GROUND-STALE reference:
//! this TU has NO encode() (`::encode(` grep 0) — transcribed, NEVER
//! "fixed".
//!
//! SEAMS (row-scoped, left-open per 18e IpApiLite lineage):
//! Icmp4IpDecodeData{is_ip6 (cc:69), dgram_len (cc:97 — the ip.cc:247-
//! :251 face reads the ip_api SET header (IAT_4: IP4Hdr::len(); IAT_6:
//! len+40), NEVER the embedded raw window — the probe's b4/b6 windows).
//! The log obfuscate read cc:154 `SnortConfig::get_conf()->obfuscate()`
//! has NO landed Rust SnortConfig home (grep obfuscate parse_conf.rs =
//! 0) -> a `obfuscate: bool` PARAM seam, producing layer queued. C++
//! anon statics (ctor/cc:308, dtor/cc:311, the api struct cc:314) ride
//! behavior-only cites: the record flags carry the face.
//!
//! tcp.h is the PAIR's ONLY fresh header cp (miscip E4 wall: tcp.h strip
//! -> ONLY this TU dies at its :30 include); the ONLY functional
//! tcp.h consumer in this row is the LOG TCP arm cc:223-:230 (TCPHdr
//! th_sport/th_dport/th_seq/th_ack/th_win/off() — tcp.h:80-:96 wire
//! cites), NEVER vectorized by the probe. udp.h rider cc:31: the UDP log
//! arm reuses the LANDED cd_udp.rs:116 UDP_HEADER_LEN (call-target
//! reuse, ext-row posture). The cc:133-:140 `struct ip4_addr` union is
//! the alias face — dotted-quad reads the SAME wire octets, no Rust
//! struct lands. The cc:198-:205 `#if 0` LogIpOptions block is DEAD
//! ground code — NOT ported (cd_frag #if 0 precedent).

use crate::codecs::cd_udp::UDP_HEADER_LEN;
use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecTable, CodecData, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData, ip_protocol,
};

/// cc:37 `#define ICMP4_IP_NAME "icmp4_ip"` — TRUE-NAME side (module
/// doc): file base == table base == this NAME (the no-drift census).
pub const CD_ICMP4_IP_NAME: &str = "icmp4_ip";
/// cc:38 `#define ICMP4_IP_HELP "support for IP in ICMPv4"` — the HELP
/// face, vectors_faceA:5 `HELP icmp4_ip support for IP in ICMPv4`.
pub const CD_ICMP4_IP_HELP: &str = "support for IP in ICMPv4";

/// ipv4.h:38 `constexpr uint8_t IP4_HEADER_LEN = 20` — the cc:56 trunc
/// gate (vectors:1 short19 -> EV 250). Row-scoped home (zero landed).
pub const IP4_HEADER_LEN: u8 = 20;

/// protocol_ids.h:130 `IP_EMBEDDED_IN_ICMP4 = 0x0103` (== 259, the face
/// vectors_faceA:7 `GETIDS icmp4_ip 259`) — the cc:52 emplace_back.
/// ROW-SCOPED DUPLICATE per the cd_icmp6.rs:179-:183 ruling that was
/// ALREADY banked pre-row ("cd_icmp4.rs keeps IP_EMBEDDED_IN_ICMP4
/// row-scoped the same way") — miscip PLAN §0 confirms duplicate, NOT
/// import (the cd_gre PROTOCOL_ID_* precedent family).
pub const PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4: ProtocolId = 0x0103;

/// decode_data.h:99 `#define PROTO_BIT__TCP_EMBED_ICMP 0x001000` — the
/// cc:112 OR (vectors:11 embed-tcp pb=4096). Row-scoped home.
pub const PROTO_BIT__TCP_EMBED_ICMP: u32 = 0x001000;
/// decode_data.h:100 `#define PROTO_BIT__UDP_EMBED_ICMP 0x002000` — the
/// cc:116 OR (vectors:10 gt576 pb=8192). Row-scoped home.
pub const PROTO_BIT__UDP_EMBED_ICMP: u32 = 0x002000;
/// decode_data.h:101 `#define PROTO_BIT__ICMP_EMBED_ICMP 0x004000` —
/// the cc:120 OR (vectors:5 rider + vectors:12 embed-icmp 16384).
pub const PROTO_BIT__ICMP_EMBED_ICMP: u32 = 0x004000;
/// decode_data.h:102 `#define PROTO_BIT__ICMP_EMBED_OTHER 0x008000` —
/// the cc:123 default OR (vectors:13 embed-other 32768). Row-scoped
/// home; the decode_data.h :116-:118 OR-group macro is cite material
/// ONLY (grep landed face: ZERO consumers, never ported).
pub const PROTO_BIT__ICMP_EMBED_OTHER: u32 = 0x008000;

/// cc:35-:49 the anon-namespace `class Icmp4IpCodec : public Codec` —
/// THREE overrides (get_protocol_ids / decode / log — the pair-class
/// asymmetry vs the mate's TWO). Rust posture: stack-owned codec
/// (18d rule); the C `Codec(ICMP4_IP_NAME)` ctor name face cc:43 rides
/// the api record.
#[derive(Default)]
pub struct Icmp4IpCodec;

/// The row-scoped DecodeData seam (module doc): cc:69 `snort.ip_api
/// .is_ip6()` + cc:97 `snort.ip_api.dgram_len()` (ip.cc:247-:251:
/// IAT_4 -> embedded-context SET header IP4Hdr::len(), IAT_6 -> len +
/// IP6_HEADER_LEN). NOT a full IpApi port; the cc:63 IP4Hdr
/// reinterpret_cast is the alias face (the byte window IS the face — no
/// pointer slot lands, the cd_icmp4.rs posture).
#[derive(Copy, Clone, Default)]
pub struct Icmp4IpDecodeData {
    pub is_ip6: bool,    // cc:69 rider read
    pub dgram_len: u16,  // cc:97 read face (ip.cc:247 IAT_4/IAT_6)
}

impl Icmp4IpCodec {
    /// cc:43 `Icmp4IpCodec() : Codec(ICMP4_IP_NAME) { }` — the base name
    /// is the macro word.
    pub fn new() -> Icmp4IpCodec {
        Icmp4IpCodec
    }

    /// cc:51-:52 out-of-line def — one emplace_back, vectors_faceA:7
    /// `GETIDS icmp4_ip 259` (0x0103 decimal face, all-decimal hygiene).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(PROTOCOL_ID_IP_EMBEDDED_IN_ICMP4); // cc:52
    }

    /// cc:54-:131 out-of-line decode, statement order VERBATIM (R6
    /// eval-order: every event fires in its ground statement slot, the
    /// gt576 arm does NOT return — the vectors:10 CONTINUE face).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &Icmp4IpDecodeData,
        sink: QueueSink,
    ) -> bool {
        // cc:56-:60: raw.len < IP4_HEADER_LEN (20) -> 250 + false
        // (vectors:1-2 `EV 116 250` + `IP4 short19 -> 0`).
        if raw.len < u32::from(IP4_HEADER_LEN) {
            crate::framework::codec::codec_event(codec, IP_TRUNCATED_SID, sink); // cc:58
            return false;
        }

        // cc:62-:63 "lay the IP struct over the raw data" — the alias
        // face (doc above); the reads below ride the wire offsets.

        // cc:65-:73: the DLT_RAW comment rides + the COMPOUND gate
        // `(ver != 4) && !is_ip6()` -> 251 + false, eval order kept.
        // RIDER PAIR armed both faces (PLAN R5): vectors:3-4 ver6 +
        // ip4-api DIES; vectors:5 ver6 + ip6-api CONTINUES.
        let ver = (raw.data[0]) >> 4; // ipv4.h:61 `ip_verhl >> 4`
        if (ver != 4) && !snort.is_ip6 {
            crate::framework::codec::codec_event(codec, VER_MISMATCH_SID, sink); // cc:71
            return false;
        }

        // cc:75: hlen = (ip_verhl & 0x0f) << 2 (ipv4.h:59-:60).
        let hlen = u32::from((raw.data[0] & 0x0f) << 2);

        // cc:77-:81: raw.len < hlen -> 252 + false (vectors:6-7
        // hlen24-22: IHL 6 -> 24 > 22).
        if raw.len < hlen {
            crate::framework::codec::codec_event(codec, DGRAM_LT_ORIG_IP_SID, sink); // cc:79
            return false;
        }

        // cc:83-:107: the off()==0 gate (ipv4.h:91-:92
        // (ntohs(ip_off) & 0x1FFF) << 3, bytes 6-7 BE).
        let off_w_flags = u16::from_be_bytes([raw.data[6], raw.data[7]]); // ipv4.h:77-:78
        if ((off_w_flags & 0x1FFF) << 3) == 0 {
            // cc:84-:100: ip_len = raw.len - hlen.
            let ip_len = raw.len - hlen;
            if ip_len < 8 {
                crate::framework::codec::codec_event(codec, PAYLOAD_LT_64_SID, sink); // cc:91
                return false;
            } else if snort.dgram_len > 576 {
                // cc:97-:99: EVENT-THEN-CONTINUE (NO return — the
                // "could contain as much as possible but not exceed
                // 576" comment rides; vectors:9-10 pin the face).
                crate::framework::codec::codec_event(codec, PAYLOAD_GT_576_SID, sink);
            }
        } else {
            // cc:102-:107: "RFC states that only first frag will get an
            // ICMP response" (the :104 comment) -> 255 + false.
            crate::framework::codec::codec_event(codec, WITH_FRAGOFFSET_SID, sink); // cc:105
            return false;
        }

        // cc:109-:125: the embed switch (4 arms, values DECIMAL in the
        // vectors: 4096/8192/16384/32768).
        let proto = raw.data[9]; // ipv4.h:74-:75 `proto()` -> IpProtocol
        match proto {
            // cc:111-:113 "decode the interesting part of the header":
            ip_protocol::TCP => codec.proto_bits |= PROTO_BIT__TCP_EMBED_ICMP,
            // cc:115-:117:
            ip_protocol::UDP => codec.proto_bits |= PROTO_BIT__UDP_EMBED_ICMP,
            // cc:119-:121:
            ip_protocol::ICMPV4 => codec.proto_bits |= PROTO_BIT__ICMP_EMBED_ICMP,
            // cc:122-:124:
            _ => codec.proto_bits |= PROTO_BIT__ICMP_EMBED_OTHER,
        }

        // cc:127-:129: the comment cites an encode() that DOES NOT
        // EXIST in this TU (ground-stale, doc pin) — the write stands:
        // lyr_len = hlen (the embedded IP header length).
        codec.lyr_len = hlen as u16;
        true // cc:130
    }

    /// cc:142-:302 out-of-line log — the FULL embedded re-walk, ported
    /// statement-for-statement, CITE-NEVER-VECTORIZED (the probes NEVER
    /// call log(); ZERO log lines in the pinned transcripts). The C
    /// `const uint16_t /*lyr_len*/` UNNAMED third param = never-read
    /// posture. `obfuscate` is the cc:154 conf seam (module doc). Every
    /// TextLog_* call lands as ONE sink line, ground call order.
    pub fn log(
        &self,
        sink: &mut dyn FnMut(String),
        raw_pkt: &[u8],
        _lyr_len: u16,
        obfuscate: bool, // cc:154 get_conf()->obfuscate() seam
    ) {
        // cc:145 the IP4Hdr overlay (alias face); cc:146-:148 the
        // ORIGINAL DATAGRAM DUMP banner pair + the IPv4 tag:
        sink("\n\t**** ORIGINAL DATAGRAM DUMP: ****".to_string()); // cc:146 Puts
        sink("\n".to_string()); // cc:147 TextLog_NewLine
        sink("\tIPv4\n\t\t".to_string()); // cc:148 Puts

        // cc:150-:151 "COPIED DIRECTLY FROM ipv4 CODEC. This is
        // specifically replicated since the two are not necessarily the
        // same." + cc:153 "FIXIT-RC this does NOT obfuscate correctly" —
        // the ground comment pair rides.
        if obfuscate {
            // cc:154-:157:
            sink("xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx".to_string());
        } else {
            // cc:158-:169: the ip4_addr union face — src.addr32 /
            // dst.addr32 read the wire slots (ipv4.h:127-:130 get_src/
            // get_dst raw slots = bytes 12-15 / 16-19; addr8[] octets on
            // the LE host == wire octet order = inet dotted order), the
            // "%d.%d.%d.%d -> %d.%d.%d.%d" print:
            sink(format!(
                "{}.{}.{}.{} -> {}.{}.{}.{}",
                raw_pkt[12], raw_pkt[13], raw_pkt[14], raw_pkt[15],
                raw_pkt[16], raw_pkt[17], raw_pkt[18], raw_pkt[19],
            )); // cc:164-:168
        }

        sink("\n".to_string()); // cc:171 NewLine
        sink("\t\t".to_string()); // cc:172 Puts

        // cc:174-:176 the three locals: hlen, len = ip4h->len()
        // (ntohs bytes 2-3, ipv4.h:63-:64), frag_off = off_w_flags().
        let hlen = u16::from((raw_pkt[0] & 0x0f) << 2);
        let len = u16::from_be_bytes([raw_pkt[2], raw_pkt[3]]); // ipv4.h:63
        let frag_off = u16::from_be_bytes([raw_pkt[6], raw_pkt[7]]); // ipv4.h:77

        // cc:178-:181 the Next line — NOTE the ground arg pairing:
        // "IpLen:%u" gets **hlen**, "DgmLen:%u" gets **len** (the
        // ground's own labeling; transcribed with operand identity).
        // The %s is the get_proto_name seam (module doc: NEVER the real
        // C++ PacketManager call — the witness mirror face).
        sink(format!(
            "Next:{}({:02X}) TTL:{} TOS:0x{:X} ID:{} IpLen:{} DgmLen:{}",
            get_proto_name(raw_pkt[9]),          // cc:179 seam
            raw_pkt[9],                          // cc:180 static_cast<uint8_t>
            raw_pkt[8],                          // cc:180 ipv4.h:68 ttl()
            raw_pkt[1],                          // cc:180 ipv4.h:62 tos() 0x%X
            u16::from_be_bytes([raw_pkt[4], raw_pkt[5]]), // cc:181 id() :97-:98
            hlen,                                // cc:181 IpLen <- hlen (!)
            len,                                 // cc:181 DgmLen <- len
        ));

        // cc:183-:185 "print the reserved bit if it's set":
        if frag_off & 0x8000 != 0 {
            sink(" RB".to_string());
        }
        // cc:187-:189 "printf more frags/don't frag bits":
        if frag_off & 0x4000 != 0 {
            sink(" DF".to_string());
        }
        // cc:191-:196 MF (the ground `bool mf` local feeds cc:207):
        let mf = frag_off & 0x2000 != 0;
        if mf {
            sink(" MF".to_string());
        }

        // cc:198-:205 `#if 0` LogIpOptions block — DEAD ground code
        // ("FIXIT-L more ip options fixits") — NOT ported (the cd_frag
        // #if 0 DECODE_RF precedent, deviations row 18j cites it).

        // cc:207-:213: the compound line. C UNSIGNED face: `len - hlen`
        // wraps when hlen > len, making `> 0` TRUE — the wrapping is
        // TRANSCRIBED (wrapping_sub), NEVER silently "fixed".
        if mf && (frag_off & 0x1FFF) != 0 && len.wrapping_sub(hlen) > 0 {
            sink("\n".to_string());          // cc:209 NewLine
            sink("\t\t".to_string());        // cc:210 Puts
            sink(format!(
                "Frag Offset: 0x{:04X}   Frag Size: 0x{:04X}",
                frag_off & 0x1FFF,
                len.wrapping_sub(hlen),
            )); // cc:211-:212 (THREE spaces between the fields, kept)
        }

        sink("\n".to_string());       // cc:215 NewLine
        sink("\t".to_string());       // cc:216 TextLog_Putc '\t'

        // cc:218-:301 the EMBEDDED PROTOCOL switch — re-reads the SAME
        // proto byte (cc:219, the second switch over ip4h->proto()).
        match raw_pkt[9] {
            // cc:221-:233 the TCP arm — the ONLY functional tcp.h
            // consumer in the row (tcp.h:80-:96 layout; `raw_pkt +
            // hlen` overlay):
            ip_protocol::TCP => {
                let t = &raw_pkt[hlen as usize..];
                sink("TCP\n\t\t".to_string()); // cc:225
                sink(format!(
                    "SrcPort:{}  DstPort:{}  Seq: 0x{:X}  Ack: 0x{:X}  Win: 0x{:X}  TcpLen: {}",
                    u16::from_be_bytes([t[0], t[1]]), // cc:227 th_sport
                    u16::from_be_bytes([t[2], t[3]]), // cc:227-:228 th_dport
                    u32::from_be_bytes([t[4], t[5], t[6], t[7]]), // cc:228 th_seq ntohl %lX
                    u32::from_be_bytes([t[8], t[9], t[10], t[11]]), // cc:229 th_ack
                    u16::from_be_bytes([t[14], t[15]]), // cc:230 th_win %X
                    (t[12] & 0xf0) >> 2, // cc:230 TCPHdr::off() tcp.h:95-:96
                )); // cc:226-:230
            }
            // cc:235-:244 the UDP arm (udp.h rider; Len = uh_len -
            // UDP_HEADER_LEN %d, udp.h:44-:46):
            ip_protocol::UDP => {
                let u = &raw_pkt[hlen as usize..];
                sink("UDP\n\t\t".to_string()); // cc:239
                sink(format!(
                    "SourcePort:{} DestPort:{} Len:{}",
                    u16::from_be_bytes([u[0], u[1]]), // cc:241 uh_sport
                    u16::from_be_bytes([u[2], u[3]]), // cc:241 uh_dport
                    i32::from(u16::from_be_bytes([u[4], u[5]]))
                        - i32::from(UDP_HEADER_LEN), // cc:242 (cd_udp.rs:116 reuse)
                )); // cc:240-:242
            }
            // cc:246-:293 the ICMPv4 arm:
            ip_protocol::ICMPV4 => {
                let i = &raw_pkt[hlen as usize..];
                sink("ICMPv4\n\t\t".to_string()); // cc:251
                sink(format!(
                    "Type:{}  Code:{}  Csum:{}",
                    i[0], // cc:253 icmph->type (icmp4.h:114-:115)
                    i[1], // cc:253 icmph->code
                    u16::from_be_bytes([i[2], i[3]]), // cc:253 csum icmp4.h:116
                )); // cc:252-:253
                // cc:255-:291 the inner type switch:
                match i[0] {
                    // cc:257-:260 DEST_UNREACH / TIME_EXCEEDED /
                    // SOURCE_QUENCH: NO-OP break arms:
                    ICMP_TYPE_DEST_UNREACH | ICMP_TYPE_TIME_EXCEEDED | ICMP_TYPE_SOURCE_QUENCH => {}
                    // cc:262-:265 PARAMETERPROB: code==0 prints the
                    // Ptr (s_icmp_pptr = icmp_hun.param.pptr @4,
                    // icmp4.h:153):
                    ICMP_TYPE_PARAMETERPROB => {
                        if i[1] == 0 {
                            sink(format!("  Ptr: {}", i[4])); // cc:264
                        }
                    }
                    // cc:267-:269: the ground `case ICMP_REDIRECT:` is
                    // the BARE constant (icmp4.h:210-:211 `#ifndef
                    // ICMP_REDIRECT constexpr uint8_t ICMP_REDIRECT = 5`
                    // — the enum-namespace asymmetry face, transcribed)
                    // + the FIXIT-L not-implemented comment:
                    ICMP_REDIRECT => {}
                    // cc:271-:281 the echo/timestamp/info/address
                    // family: Id/Seq @4-5/@6-7 (icmp4.h:155-:156):
                    ICMP_TYPE_ECHO_4
                    | ICMP_TYPE_ECHOREPLY
                    | ICMP_TYPE_TIMESTAMP
                    | ICMP_TYPE_TIMESTAMPREPLY
                    | ICMP_TYPE_INFO_REQUEST
                    | ICMP_TYPE_INFO_REPLY
                    | ICMP_TYPE_ADDRESS
                    | ICMP_TYPE_ADDRESSREPLY => {
                        sink(format!(
                            "  Id: {}  SeqNo: {}",
                            u16::from_be_bytes([i[4], i[5]]), // cc:280 s_icmp_id
                            u16::from_be_bytes([i[6], i[7]]), // cc:280 s_icmp_seq
                        )); // cc:279-:280
                    }
                    // cc:283-:287 ROUTER_ADVERTISE: num_addrs/wpa raw,
                    // lifetime ntohs (icmp4.h:160-:162):
                    ICMP_TYPE_ROUTER_ADVERTISE => {
                        sink(format!(
                            "  Addrs: {}  Size: {}  Lifetime: {}",
                            i[4],                           // cc:284 s_icmp_num_addrs
                            i[5],                           // cc:285 s_icmp_wpa
                            u16::from_be_bytes([i[6], i[7]]), // cc:286 s_icmp_lifetime
                        )); // cc:284-:286
                    }
                    // cc:289-:290 default: NO-OP:
                    _ => {}
                }
            }
            // cc:294-:300 the default arm — the SECOND get_proto_name
            // call site (cc:297, the witness census rides BOTH sites
            // sharing ONE symbol):
            _ => {
                sink(format!(
                    "Protocol:{}({:02X})",
                    get_proto_name(raw_pkt[9]), // cc:297 seam
                    raw_pkt[9],                 // cc:298
                ));
            }
        }
    }
}

/// cc:257/:258/:259 the three no-op switch arms' values (IcmpType
/// enumerators, icmp4.h h:40/:46/:41 — the SAME numerics the landed
/// cd_icmp4.rs:215-:230 icmp_type family carries; row-scoped local
/// consts keep this TU self-contained per the lineage posture).
const ICMP_TYPE_DEST_UNREACH: u8 = 3;
const ICMP_TYPE_SOURCE_QUENCH: u8 = 4;
const ICMP_REDIRECT: u8 = 5; // the BARE non-enum ground case (see above)
const ICMP_TYPE_ECHO_4: u8 = 8;
const ICMP_TYPE_ROUTER_ADVERTISE: u8 = 9;
const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;
const ICMP_TYPE_PARAMETERPROB: u8 = 12;
const ICMP_TYPE_TIMESTAMP: u8 = 13;
const ICMP_TYPE_TIMESTAMPREPLY: u8 = 14;
const ICMP_TYPE_INFO_REQUEST: u8 = 15;
const ICMP_TYPE_INFO_REPLY: u8 = 16;
const ICMP_TYPE_ADDRESS: u8 = 17;
const ICMP_TYPE_ADDRESSREPLY: u8 = 18;
const ICMP_TYPE_ECHOREPLY: u8 = 0;

/// The get_proto_name seam face (module doc headline): NEVER the real
/// C++ `PacketManager::get_proto_name` (packet_manager.h:123/:126 decls;
/// the :1004-:1008 CodecManager-walk def TU was NEVER compiled into any
/// donor — find tools 0). The OBSERVABLE face this row proves end-to-end
/// is the harness witness (witness_miscip.cc:25-:26, fixed "witness_proto"
/// after the real-body rc1, PLAN R1) — the mirror body exists so the
/// transcribed log arms COMPILE and the LINK face is honest; the log
/// OUTPUT is cite-never-vectorize. The real provider home is queued
/// (row 20, the 34-name load face).
pub fn get_proto_name(_protocol: u8) -> &'static str {
    "witness_proto"
}

/// resident sids (codec_module.rs:125-:130 h:114-:119 walk cites — the
/// SIX-event family, ZERO new constants).
const IP_TRUNCATED_SID: u32 = CodecSid::DECODE_ICMP_ORIG_IP_TRUNCATED as u32;      // 250
const VER_MISMATCH_SID: u32 = CodecSid::DECODE_ICMP_ORIG_IP_VER_MISMATCH as u32;   // 251
const DGRAM_LT_ORIG_IP_SID: u32 = CodecSid::DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP as u32; // 252
const PAYLOAD_LT_64_SID: u32 = CodecSid::DECODE_ICMP_ORIG_PAYLOAD_LT_64 as u32;    // 253
const PAYLOAD_GT_576_SID: u32 = CodecSid::DECODE_ICMP_ORIG_PAYLOAD_GT_576 as u32;  // 254
const WITH_FRAGOFFSET_SID: u32 = CodecSid::DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET as u32; // 255

// cc:304-:306 the "api" separator banner rides. cc:308-:309 `static
// Codec* ctor(Module*)` + cc:311-:312 `static void dtor(Codec*)` — the
// C++ anon statics ride behavior-only cites: the record flags below
// carry the ctor/dtor = SET face (the pair's REAL codec ctor is
// Icmp4IpCodec::new, stack-owned drop, 18d posture).

/// cc:314-:334 `static const CodecApi icmp4_ip_api` — THE
/// asymmetry-record (CDAPI census): mod_ctor cc:325 + mod_dtor cc:326
/// BOTH `nullptr` (// module constructor + // module destructor) ->
/// `false` x2 (vectors_faceA:6/:10 `mod_ctor=0 mod_dtor=0` — THE row
/// asymmetry pin vs daq3's uniform 1/1 x3 and small4's 1/0/1/1);
/// g_ctor/g_dtor/t_ctor/t_dtor nullptr cc:328-:331 = false x4;
/// ctor/dtor cc:332-:333 SET. The module doc NAME/HELP slots cc:323-:324.
pub const ICMP4_IP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:317
    size: CDAPI_SIZEOF_CODEC_API, // cc:318 sizeof(CodecApi)=112 (faceA:4)
    api_version: CDAPI_VERSION,   // cc:319 1900547
    version: 0,                   // cc:320
    features: PLUGIN_SO_RELOAD,   // cc:321
    options: API_OPTIONS,         // cc:322
    name: CD_ICMP4_IP_NAME,       // cc:323 -> "icmp4_ip"
    help: CD_ICMP4_IP_HELP,       // cc:324
    mod_ctor: false,              // cc:325 nullptr (THE asymmetry pin)
    mod_dtor: false,              // cc:326 nullptr (THE asymmetry pin)
    pinit: false,                 // cc:328 nullptr (g_ctor)
    pterm: false,                 // cc:329 nullptr (g_dtor)
    tinit: false,                 // cc:330 nullptr (t_ctor)
    tterm: false,                 // cc:331 nullptr (t_dtor)
    ctor: true,                   // cc:332 SET
    dtor: true,                   // cc:333 SET
};

/// cc:336-:344 the hidden export — THE BUILDING_SO census face (module
/// doc): `#ifdef BUILDING_SO` cc:336 / the SO arm `SO_PUBLIC const
/// BaseApi* snort_plugins[] =` cc:337 / the static-build arm `const
/// BaseApi* cd_icmp4_ip[] =` cc:339 feeding `&icmp4_ip_api.base` cc:342
/// plus nullptr cc:343. The harness compiles the STATIC arm
///     (BUILDING_SO never defined) — nm table symbol EXACTLY-1 (PLAN §4
///     sed/nm census). Rust face = the landed-row doc-cite + record
///     pattern (cd_icmp4.rs precedent; ZERO `#[no_mangle]` in src —
///     grep face). Table name == file base (TRUE NAME, no drift); the
///     ladder entry "cd_icmp4_ip" is ALREADY RESIDENT (codec_api.rs:113)
///     — NEVER re-touched.
pub const CD_ICMP4_IP: CodecTable = &[&ICMP4_IP_API];
