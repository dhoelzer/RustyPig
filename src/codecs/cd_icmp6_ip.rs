//! Port of `src/codecs/misc/cd_icmp6_ip.cc` (162 L) — row 18j, the misc
//! icmp _ip PAIR half two (`tools/miscip_harness`, ZERO-gate probe-only).
//! Ground: snort3-src @ fe29cbe, md5 `60723a7c04827eb877ae229015b9247c`
//! wc 162 + the 345+162=507 SUM (miscip build.sh pins every build). DIR
//! FACT: `codecs/misc/`. Include closure = THREE resident headers ONLY
//! (cc:24 codec_module.h, cc:25 framework/codec.h, + the :21 config.h
//! guard face): ZERO fresh cps of its own — the pair's fresh-cp budget
//! (tcp.h) rides the MATE ONLY (miscip E4: tcp.h strip kills ONLY
//! cd_icmp4_ip; this TU SURVIVES, measured).
//!
//! THE NAME-MACRO FACE (a NAME-vs-MODULE doc cite, NOT drift, PLAN §2):
//! the ICMS macro wraps in `#ifndef ICMP6_IP_NAME` cc:33-:35 carrying
//! the ground comment cc:29 + cc:31-:32 ("yes, macros are necessary..."
//! / "this macros is defined in the module to ensure identical names.
//! However, if you don't want a module, define the name here.") — the
//! icmp4 mate carries NO #ifndef (asymmetry transcribed). TRUE names
//! hold x2: file base == table base == NAME "icmp6_ip" (HELP cc:37
//! "support for IP in ICMPv6", vectors_faceA:9).
//!
//! THE HIDDEN-TABLE FACE (the pair census headline): the export rides
//! `#ifdef BUILDING_SO` cc:154-:161 — `snort_plugins[]` SO arm cc:155,
//! the REAL static arm `const BaseApi* cd_icmp6_ip[] =` cc:157 feeds
//! `&icmp6_ip_api.base` cc:160. Same Rust pattern as the mate (doc-cite
//!     plus `pub const CD_ICMP6_IP: CodecTable`, NO #[no_mangle], the
//!     landed rows' face); ladder entry "cd_icmp6_ip" RESIDENT
//!     codec_api.rs:115, NEVER re-touched.
//!
//! THE WITNESS CONTRAST (the row's honest half): nm -C census says this
//! TU references ZERO get_proto_name (the pair's EXACTLY-+1 witness
//! delta is icmp4_ip-ONLY, PLAN §6) — this class ships NO log override
//! (`::log(` grep 0 — the class-face asymmetry: THREE methods vs TWO,
//! cc:41-:48). decode's DecodeData& param is UNNAMED (cc:54) = the
//! never-read posture (the small4 pgm precedent — NO seam struct lands
//! for this TU).
//!
//! THE GROUND-DEAD SECOND GATE (the DEC-face honesty headline, PLAN §7):
//! cc:77-:82 re-checks `raw.len < IP6_HEADER_LEN` — SAME condition as
//! the FIRST gate cc:61 — with the ground's OWN `// cppcheck-suppress
//! knownConditionTrueFalse ; embedded packet length depends on captured
//! traffic` at cc:77. First gate guarantees raw.len>=40 => the second
//! can NEVER fire: the 252 arm is UNARMED. The vectors carry the honest
//! CITE line `IP6 252-unarmed cc:78-fixed-true` — NEVER a fake EV
//! (cite-never-guess). The transcription keeps the dead gate literal.
//! THREE event sites (250 cc:63, 251 cc:73, 252 cc:80 DEAD) ride the
//! SAME resident family as the mate (codec_module.rs:125-:130, ZERO new
//! sids; the 6/3-unique event-name census pinned by the harness PYPIN).
//!
//! THE next() SWITCH cc:97-:114 + its FIXIT block: the cc:84-:85
//! commented-out orig_frag_offset lines + cc:87 "FIXIT-L NOT YET
//! IMPLEMENTED - fragments inside ICMP payload" + the cc:89-:94 comment
//! ("...I can't set the next_prot_id in this case because I don't want
//! this going to the TCP, UDP, or ICMP codec. Therefore, doing a minor
//! decode here." — the row's own design note, the reason the embed ids
//! land at GETIDS) + cc:96 "FIXIT-M will fail to decode Ipv6 options"
//!     plus cc:107 "FIXIT-M do we need to handle ICMPV6 here?" ALL ride. THE
//! SWITCH-ARM ODDITY transcribed EXACTLY: cc:108 is `case
//! IpProtocol::ICMPV4:` (NOT ICMPV6 — the ground's own bug-shaped arm,
//! guarded only by the comment; NEVER "fixed"), and the SAME four
//! PROTO_BIT homes as the mate. lyr_len = IP6_HEADER_LEN cc:118 (ipv6.h
//! :31 = 40 — NOT hlen-driven like the mate; vectors:17/:19 lyr=40) +
//! the cc:116-:117 encode() comment rides (ground-stale AGAIN: no
//! encode() in this TU either — grep 0).
//!
//! SEAM: Icmp6IpDecodeData does NOT exist (the unnamed cc:54 param). Log
//! face: absent. The cc:59 IP6Hdr reinterpret_cast = the alias face
//! (window reads @0 ver nibble, @6 next, ipv6.h:78-:79). C++ anon
//! statics cc:126-:130 + api cc:132 behavior-only cites; the record
//! carries the pair-same asymmetry face mod_ctor=0/mod_dtor=0 (cc:143-
//! :144 nullptr, vectors_faceA:10).

use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecTable, CodecData, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData, ip_protocol,
};

/// cc:29-:37 the macro block (module doc: the #ifndef-wrapped NAME +
/// its ground comment pair ride there): `#define ICMP6_IP_NAME
/// "icmp6_ip"` cc:34 (inside `#ifndef ICMP6_IP_NAME` cc:33 — unlike
/// the mate). TRUE-NAME side x2.
pub const CD_ICMP6_IP_NAME: &str = "icmp6_ip";
/// cc:37 `#define ICMP6_IP_HELP "support for IP in ICMPv6"` — the HELP
/// face, vectors_faceA:9.
pub const CD_ICMP6_IP_HELP: &str = "support for IP in ICMPv6";

/// ipv6.h:31 `constexpr uint8_t IP6_HEADER_LEN = 40` — the cc:61 gate
/// (vectors:14 short39 -> EV 250), the cc:78 GROUND-DEAD repeat-gate
/// face, AND the cc:118 lyr_len write (vectors:17/:19 lyr=40 — the
/// probe's sed cite face). Row-scoped home.
pub const IP6_HEADER_LEN: u8 = 40;

/// protocol_ids.h:131 `IP_EMBEDDED_IN_ICMP6 = 0x0104` (== 260, the face
/// vectors_faceA:11 `GETIDS icmp6_ip 260`) — the cc:52 emplace_back.
/// ROW-SCOPED DUPLICATE (the cd_icmp6.rs:179-:183 pre-banked ruling the
/// PLAN §0 confirms — import-vs-duplicate ruled AGAINST that cite, not
/// air).
pub const PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6: ProtocolId = 0x0104;

/// decode_data.h :99-:102 — the four embed bits, the SAME family the
/// mate lands (the C source ORs the SAME macros; Rust row-scoped consts
/// per TU keep the lineage's per-file homes, the cd_udp.rs:158
/// precedent). Cites ride the mate's docs; DECIMAL vectors faces:
/// 4096/8192/16384/32768.
pub const PROTO_BIT__TCP_EMBED_ICMP: u32 = 0x001000; // cc:100 (vectors:17)
pub const PROTO_BIT__UDP_EMBED_ICMP: u32 = 0x002000; // (no DEC arm rides here)
pub const PROTO_BIT__ICMP_EMBED_ICMP: u32 = 0x004000; // cc:109 (the ICMPV4-arm oddity)
pub const PROTO_BIT__ICMP_EMBED_OTHER: u32 = 0x008000; // cc:112 (vectors:19)

/// cc:39-:49 the anon-namespace `class Icmp6IpCodec : public Codec` —
/// TWO overrides ONLY (get_protocol_ids + decode; NO log — the class
/// asymmetry vs the mate's THREE, witness headline half two).
#[derive(Default)]
pub struct Icmp6IpCodec;

impl Icmp6IpCodec {
    /// cc:44 `Icmp6IpCodec() : Codec(ICMP6_IP_NAME) { }`.
    pub fn new() -> Icmp6IpCodec {
        Icmp6IpCodec
    }

    /// cc:51-:52 out-of-line def — one emplace_back, vectors_faceA:11
    /// `GETIDS icmp6_ip 260` (0x0104 decimal face).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(PROTOCOL_ID_IP_EMBEDDED_IN_ICMP6); // cc:52
    }

    /// cc:54-:120 out-of-line decode — note the UNNAMED `DecodeData&`
    /// (never-read: NO seam param lands, the pgm precedent). Statement
    /// order VERBATIM incl the GROUND-DEAD second gate (module doc).
    /// The `// uint16_t orig_frag_offset;` cc:56 commented decl rides.
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: QueueSink,
    ) -> bool {
        // cc:58-:59 "lay the IP struct over the raw data" — the alias
        // face; reads ride the wire bytes (no pointer slot lands).

        // cc:61-:65 FIRST gate: raw.len < 40 -> 250 + false
        // (vectors:14-15 `EV 116 250` + `IP6 short39 -> 0`).
        if raw.len < u32::from(IP6_HEADER_LEN) {
            crate::framework::codec::codec_event(codec, IP_TRUNCATED_SID, sink); // cc:63
            return false;
        }

        // cc:67-:75: the DLT_RAW comment rides; ver nibble @0
        // (0x60 -> 6). vectors:16-17 ver4 (0x45) -> 251 + false.
        let ver = raw.data[0] >> 4;
        if ver != 6 {
            crate::framework::codec::codec_event(codec, VER_MISMATCH_SID, sink); // cc:73
            return false;
        }

        // cc:77-:82 THE GROUND-DEAD GATE (headline face, module doc):
        // the cppcheck-suppress comment cc:77 rides; the condition is
        // TRUE-FIXED given the first gate — the 252 arm can NEVER fire,
        // the vectors carry the honest cite line, NEVER a fake EV. The
        // transcription keeps the dead gate LITERAL.
        // (cppcheck-suppress knownConditionTrueFalse ; embedded packet
        // length depends on captured traffic)  <- cc:77 verbatim cite
        if raw.len < u32::from(IP6_HEADER_LEN) {
            crate::framework::codec::codec_event(codec, DGRAM_LT_ORIG_IP_SID, sink); // cc:80 (UNARMED)
            return false;
        }

        // cc:84-:96: the commented orig_frag_offset pair + FIXIT-L
        // fragments comment + the cc:89-:94 "minor decode here" design
        // comment + cc:96 FIXIT-M options comment — ALL ride (module
        // doc); the cc:97 switch reads ip6_next @6 (ipv6.h:78-:79
        // `next()`).

        // cc:97-:114: the next() switch — arms DECIMAL in vectors:17/:19
        // (4096 / 32768). The cc:107 "FIXIT-M do we need to handle
        // ICMPV6 here?" comment + cc:108's GROUND ICMPV4 arm (NOT
        // ICMPV6 — transcribed as-is, NEVER fixed) pin the oddity.
        let next = raw.data[6]; // ipv6.h:76-:79 next()
        match next {
            // cc:99-:101 "decode the interesting part of the header":
            ip_protocol::TCP => codec.proto_bits |= PROTO_BIT__TCP_EMBED_ICMP,
            // cc:103-:105:
            ip_protocol::UDP => codec.proto_bits |= PROTO_BIT__UDP_EMBED_ICMP,
            // cc:106-:110 (the FIXIT-M comment rides; ICMPV4 per GROUND):
            ip_protocol::ICMPV4 => codec.proto_bits |= PROTO_BIT__ICMP_EMBED_ICMP,
            // cc:111-:113:
            _ => codec.proto_bits |= PROTO_BIT__ICMP_EMBED_OTHER,
        }

        // cc:116-:118: the encode() comment rides (ground-stale: NO
        // encode() in this TU — grep 0, same face as the mate); the
        // write stands: FIXED 40, NOT hlen-driven (the mate contrast).
        codec.lyr_len = u16::from(IP6_HEADER_LEN);
        true // cc:119
    }
}

/// resident sids (codec_module.rs:125-:130 — the THREE-name family, 2
/// LIVE + the DEAD 252 site; ZERO new constants, the 6/3-unique census
/// rides the harness PYPIN).
const IP_TRUNCATED_SID: u32 = CodecSid::DECODE_ICMP_ORIG_IP_TRUNCATED as u32;      // 250
const VER_MISMATCH_SID: u32 = CodecSid::DECODE_ICMP_ORIG_IP_VER_MISMATCH as u32;   // 251
const DGRAM_LT_ORIG_IP_SID: u32 = CodecSid::DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP as u32; // 252 (UNARMED)

// cc:122-:124 the "api" separator banner rides. cc:126-:127 `static
// Codec* ctor(Module*)` + cc:129-:130 `static void dtor(Codec*)` — the
// C++ anon statics ride behavior-only cites (record flags = the ctor/
// dtor SET face; the Rust codec is Icmp6IpCodec::new, 18d posture).

/// cc:132-:152 `static const CodecApi icmp6_ip_api` — the pair-same
/// asymmetry record: mod_ctor cc:143 + mod_dtor cc:144 BOTH nullptr
/// (// module constructor/destructor) -> false x2 (vectors_faceA:10);
/// NAME/HELP cc:141-:142; g/t ctor-dtor nullptr cc:146-:149 = false x4;
/// ctor/dtor cc:150-:151 SET.
pub const ICMP6_IP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:135
    size: CDAPI_SIZEOF_CODEC_API, // cc:136 sizeof(CodecApi)=112 (faceA:8)
    api_version: CDAPI_VERSION,   // cc:137 1900547
    version: 0,                   // cc:138
    features: PLUGIN_SO_RELOAD,   // cc:139
    options: API_OPTIONS,         // cc:140
    name: CD_ICMP6_IP_NAME,       // cc:141 -> "icmp6_ip"
    help: CD_ICMP6_IP_HELP,       // cc:142
    mod_ctor: false,              // cc:143 nullptr (the pair asymmetry)
    mod_dtor: false,              // cc:144 nullptr (the pair asymmetry)
    pinit: false,                 // cc:146 nullptr (g_ctor)
    pterm: false,                 // cc:147 nullptr (g_dtor)
    tinit: false,                 // cc:148 nullptr (t_ctor)
    tterm: false,                 // cc:149 nullptr (t_dtor)
    ctor: true,                   // cc:150 SET
    dtor: true,                   // cc:151 SET
};

/// cc:154-:162 the hidden export (module doc headline): `#ifdef
/// BUILDING_SO` cc:154 / `SO_PUBLIC const BaseApi* snort_plugins[] =`
/// cc:155 / the static-build `const BaseApi* cd_icmp6_ip[] =` cc:157
/// feeding `&icmp6_ip_api.base` cc:160 + nullptr cc:161. nm table
/// symbol EXACTLY-1 (the STATIC arm IS the harness face, PLAN §4).
/// Rust = doc-cite + table record (the landed-row pattern, grep face:
/// ZERO #[no_mangle] in src). Table name == file base (TRUE x2); the
/// ladder entry "cd_icmp6_ip" RESIDENT (codec_api.rs:115) NEVER touched.
pub const CD_ICMP6_IP: CodecTable = &[&ICMP6_IP_API];
