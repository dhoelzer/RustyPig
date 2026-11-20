//! Port of `src/codecs/ip/cd_frag.cc` (190 L) — row 18h (the small four,
//! `tools/small4_harness`, ZERO-gate probe-only row).
//! Ground: snort3-src @ fe29cbe, md5 `2832f4fdf4bb93a88507c354049d4a47`
//! wc 190 (small4 build.sh :36-:41 every build). DIR FACT: `codecs/ip/`;
//! includes only the FOUR resident headers PLUS log/text_log.h (cc:26),
//! residency proven by the stripped-tree flipped-assert (drop
//! log/text_log.h -> ONLY cd_frag dies, `E4_notextlog_frag.txt`; frag is
//! the FIRST rider of the text_log residency the tun lineage paid).
//!
//! NAME FACE (PLAN §3, the second drift rider of the row): file base ==
//! table name here (`cd_frag[]` :184, REAL BUILDING_SO arms :181-:185,
//! sed-pins at build.sh), BUT the api struct is `ipv6_frag_api` :159 and
//! the NAME macro is `CD_IPV6_FRAG_NAME "ipv6_frag"` :31 while HELP says
//! "IPv6 fragment decoding" — the FACE-A walk prints `LOAD ipv6_frag` /
//! `API frag ... name=ipv6_frag` (table symbol vs printed name). The
//! tripwire pins file-vs-name pairs; the ladder entry stays "cd_frag"
//! codec_api.rs:108 (NEVER re-touched).
//!
//! THE R2 FACE — NO module, NO RuleMap, NO Parameter: the api's
//! mod_ctor/mod_dtor slots are nullptr (cc:170-:171) — vectors_faceA
//! `frag mod_ctor=0 mod_dtor=0` + vectors:23 `FRAG api mod_ctor=0
//! mod_dtor=0`. A port that "helpfully" adds a params table drifts FROM
//! ground (small4 PLAN R2): the honest absent face IS the pin. There is
//! NO get_rules/Parameter landing anywhere in this file.
//!
//! THE ORDER-DENSE FACE: the frag decode is the lineage's most
//! arm-dense ordering face — FOUR events + THREE flags across ONE
//! decode (cc:54/:60/:69/:91 + DECODE_DF-clear :74, DECODE_MF :77,
//! DECODE_FRAG :89), and TWO order checks (cc:102 FRAGMENT, cc:111
//! ip6f_nxt when offset==0). The cc:65-:71 ZERO_LENGTH_FRAG arm does
//! NOT return (the FIXIT-L comment "identical to DEFRAG_ANOMALY_ZERO.
//! Commenting 'return false'…" rides verbatim); vectors:12-:17 show the
//! interleaving EXACTLY in ground call order (459 head THEN 458, never
//! sorted). `#if 0` reserved-flag block cc:79-:83 stays dead — the
//! DECODE_RF face NEVER lands (measured: no vectors line carries 0x100).
//!
//! DECODE-DATA SEAM left-open (18e IpApiLite precedent, row-scoped):
//! the DecodeData operand reads/writes only decode_flags here —
//! `FragDecodeData` carries it; the C ip6f_nxt order-check arg reads the
//! header bytes, NOT ip_api (unlike esp/auth, frag never calls
//! is_ip6() — the ip6 block is UNCONDITIONAL here: cc:48-:127 has NO
//! is_ip6 guard, the codec is reached ONLY as an IPv6 extension in
//! production, so the Rust port keeps that unconditional shape verbatim).
//! Row-scoped VOCAB (framework files UNTOUCHED): DECODE_MF h:142 0x80,
//! DECODE_FRAG h:141 0x40 land here with cites; vectors:16 `dflags=192`
//! is MF|FRAG, :20 `dflags=64` FRAG-only (both decomposition-pinned in
//! build.sh python BOTH ends).
//!
//! sizeof(ip::IP6Frag) = 8 = ip::MIN_EXT_LEN: the cc:52 guard uses
//! MIN_EXT_LEN (ipv6.h:32, landed fw `ip::MIN_EXT_LEN`), the cc:65
//! equality and cc:93 lyr_len use the header size 8 (the same number,
//! DIFFERENT source lines — kept distinct, small4 PLAN §8).
//!
//! sids resident, zero new: 272 (:133), 456 (:214), 458 (:216),
//! 459 (:217 — cc:60 h:212 walk: the codec_module.rs RuleMap already
//! cites it for the module vocabulary), 296 via the landed order check.
//! The cc:98-:99 FIXIT-RC comments ("it looks like it's called (twice)
//! before setting it") ride the port unchanged: the order calls DO
//! precede the next_prot_id write cc:120/:124 — statement order kept.

use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecTable, CodecData, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    CODEC_DF, DECODE_IP6_EXCESS_EXT_HDR, DECODE_IPV6_TRUNCATED_EXT, PLUGIN_SO_RELOAD,
    PROTO_BIT__IP6_EXT, PT_CODEC, ProtocolId, QueueSink, RawData, ip, ip_protocol, protocol_id,
};

/// resident sids via the CodecSid walk (zero new constants;
/// codec_module.rs:216/:217 h:211/:212)
const IPV6_BAD_FRAG_PKT_SID: u32 = CodecSid::DECODE_IPV6_BAD_FRAG_PKT as u32;
const ZERO_LENGTH_FRAG_SID: u32 = CodecSid::DECODE_ZERO_LENGTH_FRAG as u32;

/// cc:31 `#define CD_IPV6_FRAG_NAME "ipv6_frag"` — the PRINTED name
/// (drift rider, module doc). vectors_faceA `LOAD ipv6_frag`.
pub const CD_IPV6_FRAG_NAME: &str = "ipv6_frag";
/// cc:32 `#define CD_IPV6_FRAG_HELP "support for IPv6 fragment decoding"`
pub const CD_IPV6_FRAG_HELP: &str = "support for IPv6 fragment decoding";

/// decode_data.h:141 `DECODE_FRAG = 0x00000040` (row-scoped home).
pub const DECODE_FRAG: u64 = 0x0040;
/// decode_data.h:142 `DECODE_MF = 0x00000080` (row-scoped home).
pub const DECODE_MF: u64 = 0x0080;

/// The row-scoped DecodeData seam (module doc): decode_flags only.
#[derive(Copy, Clone, Default)]
pub struct FragDecodeData {
    pub decode_flags: u64,
}

#[derive(Default)]
pub struct Ipv6FragCodec;

impl Ipv6FragCodec {
    /// cc:39 `Ipv6FragCodec() : Codec(CD_IPV6_FRAG_NAME) { }`
    pub fn new() -> Ipv6FragCodec {
        Ipv6FragCodec
    }

    /// cc:130-:131 out-of-line def — vectors:22 `FRAGPID 44 n=1`
    /// (ProtocolId::FRAGMENT = 44, grep-pin in build.sh).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::FRAGMENT); // cc:131
    }

    /// cc:48-:128 out-of-line decode, statement order VERBATIM (the
    /// order-dense face, module doc). The cc:50 reinterpret_cast to
    /// `const ip::IP6Frag*` reads bytes 0..8 once the cc:52 guard
    /// passes; the .get posture only keeps hostile short inputs
    /// panic-free and NEVER fires in replay (cd_hop_opts carry).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut FragDecodeData,
        sink: QueueSink,
    ) -> bool {
        // cc:52-:56: raw.len < ip::MIN_EXT_LEN (8) -> 272 + false.
        // vectors:12/:13 `EV 116 272` + `FRAG short7 -> 0`.
        if raw.len < ip::MIN_EXT_LEN {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, sink);
            return false;
        }

        // cc:58-:62 the maxopts latch -> 456 + false (vectors:14/:15;
        // ip6_extension_count arm — the probe sets count=1/max=1; conf
        // rides the landed Option<&SnortConfig> seam 18c posture).
        let hit = codec
            .conf
            .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
            .unwrap_or(false);
        if hit {
            crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, sink);
            return false;
        }

        // cc:64-:71 "// already checked for short packet above":
        // raw.len == sizeof(IP6Frag) (8) -> DECODE_ZERO_LENGTH_FRAG,
        // the COMMENTED-OUT `// return false;` (FIXIT-L) rides: decode
        // CONTINUES. vectors:12 area: EV 459 fires INSIDE the zero8 arm
        // that returns TRUE (`FRAG zero8 -> 1`).
        if raw.len == 8 {
            crate::framework::codec::codec_event(codec, ZERO_LENGTH_FRAG_SID, sink);
            // cc:70 `//        return false;` — COMMENT DEAD, no return.
        }

        // cc:73-:74 "If this is an IP Fragment, set some data...":
        // clear CODEC_DF (cc:74 &= ~CODEC_DF).
        codec.codec_flags &= !CODEC_DF;

        // cc:76-:77 ip6frag_hdr->mf() (ipv6.h:217 ntohs(offlg) &
        // IP6F_MF_MASK 0x0001, h:35) -> DECODE_MF. The wire face: C's
        // uint16 field + ntohs == the BE read of bytes 2-3 on any host
        // (one face, no double-swap; the probe arms f[3]=0x01/0x08).
        let offlg = u16::from_be_bytes([
            *raw.data.get(2).unwrap_or(&0),
            *raw.data.get(3).unwrap_or(&0),
        ]);
        let mf: u16 = offlg & 0x0001; // IP6F_MF_MASK h:35
        if mf != 0 {
            snort.decode_flags |= DECODE_MF;
        }

        // cc:79-:83 `#if 0` reserved-flag block: DEAD in ground, NEVER
        // lands here (no DECODE_RF write anywhere — dead face pinned).

        // cc:85-:91 frag_offset = off() = ntohs & 0xFFF8; then the
        // offset||MF fork: DECODE_FRAG ELSE event 458 (NO return).
        let frag_offset: u16 = offlg & 0xFFF8;
        if frag_offset != 0 || (snort.decode_flags & DECODE_MF) != 0 {
            snort.decode_flags |= DECODE_FRAG; // cc:89
        } else {
            crate::framework::codec::codec_event(codec, IPV6_BAD_FRAG_PKT_SID, sink); // cc:91
        }

        // cc:93-:96 the four writes, ground order kept: lyr_len (= 8),
        // ip6_csum_proto = ip6f_nxt (byte 0), bits |= PROTO_BIT__IP6_EXT,
        // ip6_extension_count++.
        codec.lyr_len = 8; // cc:93 sizeof(ip::IP6Frag)
        let ip6f_nxt = *raw.data.first().unwrap_or(&0); // cc:94 ip6f_nxt
        codec.ip6_csum_proto = ip6f_nxt;
        codec.proto_bits |= PROTO_BIT__IP6_EXT; // cc:95
        codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1); // cc:96

        // cc:98-:99 the FIXIT-RC comment (order called TWICE BEFORE the
        // next_prot_id write) + cc:102 first order check FRAGMENT:
        crate::framework::codec::check_ipv6_extension_order(codec, ip_protocol::FRAGMENT, sink);

        // cc:104-:111 second order check iff frag_offset == 0 (the
        // "ensure the next layer is correctly ordered now" face; the
        // vectors:17-:19 `FRAG ooo2` arm rides it — HOPOPTS order 1 <=
        // curr 4 -> EV 296 SECOND order line).
        if frag_offset == 0 {
            crate::framework::codec::check_ipv6_extension_order(codec, ip6f_nxt, sink);
        }

        // cc:113-:125 the DECODE_FRAG fork: FINISHED_DECODE (256) vs the
        // raw ip6f_nxt (vectors:16/:19/:21 next=256/next=0/next=256).
        if snort.decode_flags & DECODE_FRAG != 0 {
            codec.next_prot_id = protocol_id::FINISHED_DECODE;
        } else {
            codec.next_prot_id = ip6f_nxt as ProtocolId; // cc:124
        }

        true // cc:127
    }

    /// cc:133-:147 out-of-line log: TextLog_Print format cc:139-:140
    /// `"Next:0x%02X Off:%u ID:%u"` (Next/ID decimal-vs-hex MIX kept
    /// literal: %02X upper-hex, Off decimal, ID %u decimal) + the
    /// " MF" / " RB" TextLog_Puts arms (cc:142-:146, rb =
    /// ntohs(offlg) & IP6F_RES_MASK 0x0006, h:36). NEVER vectorized:
    /// NO probe line calls log() — the cited-never-vectorized posture
    /// (18d eth / 18g gre precedent); the format lands at the ordered
    /// sink for later rows.
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        let offlg = u16::from_be_bytes([
            *raw_pkt.get(2).unwrap_or(&0),
            *raw_pkt.get(3).unwrap_or(&0),
        ]);
        sink(format!(
            "Next:0x{:02X} Off:{} ID:{}",
            *raw_pkt.first().unwrap_or(&0), // cc:140 static_cast<uint8_t>(ip6f_nxt)
            offlg & 0xFFF8,                 // cc:137 offlg = off()
            u32::from_be_bytes([
                *raw_pkt.get(4).unwrap_or(&0),
                *raw_pkt.get(5).unwrap_or(&0),
                *raw_pkt.get(6).unwrap_or(&0),
                *raw_pkt.get(7).unwrap_or(&0),
            ]), // cc:140 fragh->id() = ntohl(ip6f_ident)
        )); // cc:139
        if offlg & 0x0001 != 0 {
            sink(" MF".to_string()); // cc:143
        }
        if offlg & 0x0006 != 0 {
            sink(" RB".to_string()); // cc:146
        }
    }
}

// cc:153-:157 `static Codec* ctor(Module*)` / `static void dtor(Codec*)`
// — the codec pair SET; the MODULE pair does NOT exist in this file
// (R2 face). Record slots below carry the asymmetry.

/// cc:159-:179 `static const CodecApi ipv6_frag_api` — NOTE the name
/// (module doc) and the cc:170-:171 nullptr mod_ctor/mod_dtor pair:
/// the ONLY zero-mod-slot record of the four (vectors_faceA
/// `frag mod_ctor=0 mod_dtor=0`).
pub const IPV6_FRAG_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:162
    size: CDAPI_SIZEOF_CODEC_API, // cc:163 (112 probe pin)
    api_version: CDAPI_VERSION, // cc:164 (1900547)
    version: 0,      // cc:165
    features: PLUGIN_SO_RELOAD, // cc:166
    options: API_OPTIONS, // cc:167
    name: CD_IPV6_FRAG_NAME, // cc:168
    help: CD_IPV6_FRAG_HELP, // cc:169
    mod_ctor: false, // cc:170 nullptr — THE R2 FACE
    mod_dtor: false, // cc:171 nullptr — THE R2 FACE
    pinit: false,    // cc:173
    pterm: false,    // cc:174
    tinit: false,    // cc:175
    tterm: false,    // cc:176
    ctor: true,      // cc:177 SET
    dtor: true,      // cc:178 SET
};

/// cc:181-:189 the export — REAL BUILDING_SO arms (:181-:185 sed-pins),
/// table `cd_frag[]` at :184 feeding `&ipv6_frag_api.base`.
pub const CD_FRAG: CodecTable = &[&IPV6_FRAG_API];
