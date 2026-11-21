//! Port of `src/codecs/link/cd_trans_bridge.cc` (158 L) — row 18l, the
//! codecs/link CHEAP SUB-TRIO half three (`tools/erspan_harness`, ZERO-gate
//! probe-only, 19th straight). Ground: snort3-src @ fe29cbe, md5
//! `20a6a8b0ee1b4c1f9b66e10fe7c00db9` wc 158 (the 450 SUM asserted every
//! build). DIR FACT: `codecs/link/`. THE sub-trio's THIRD TU + the pair
//! story's other end: the erspan2 happy arm hands the NEXT id 0x6558 HERE
//! (cc:94 -> this codec), and the probe's TB happy fixture puts an erspan2
//! ethertype 0x88BE INSIDE a trans-bridge frame (vectors:16 `next=35006`)
//! — the sibling-pair handshake, decimal-only.
//!
//! THE TRUE-NAME DRIFT headline (the row's name-pin story, PLAN §1/:17):
//! the file base is `cd_trans_bridge` but the static table is
//! `const BaseApi* cd_transbridge[]` at cc:152 feeding `&transbridge_api
//! .base` cc:155 — the ONLY drift name INSIDE this row's three TUs (the
//! cd_pppoepkt double-NAME — arms `CD_PPPOEPKT_DISC_NAME :115` +
//! `CD_PPPOEPKT_SESS_NAME :139`, table :236 — lives in cd_pppoe.cc, a 18m
//! face this row NEVER touches; the briefing's "cd_pppoepkt live in the
//! erspan TUs" face is WRONG on disk, grep-refused every build). The Rust
//! landing files use the FILE base names (PLAN §3/§5 discipline: a future
//! grep-vs-file confusion trips LOUD at the harness table pins, never at a
//! file). Ladder entry "cd_transbridge" (the DRIFT spelling) RESIDENT
//! codec_api.rs:127 (ground extern codec_api.cc :69, load :114) NEVER
//! re-walked.
//!
//! THE ANON-NAMESPACE NAME/HELP enclosure (the §55 pin NO earlier row ever
//! carried): the two #defines CD_TRANSBRIDGE_NAME :33 + CD_TRANSBRIDGE_
//! HELP :34 sit INSIDE `namespace {` :31-:32 (close `} // anonymous
//! namespace` :47) — build.sh sed-pins :31/:32/:33/:34/:47 every build.
//! The NAME string itself is `"trans_bridge"` (underscore): the LOAD face
//! vectors_faceA:3 prints the NAME through the DRIFT table — `LOAD
//! trans_bridge` (drift name carries honest NAME, the probe pin).
//!
//! THE mod-pair ZERO side of the trio 1/1/0 census: NO Module subclass
//! exists HERE at all (the class cc:36-:46 is a bare Codec), and the
//! BaseApi slots cc:138/:139 carry the EXPLICIT `nullptr,` / `nullptr`
//! pair (NO comment — the contrast vs misc3 cd_user's commented pair):
//! vectors_faceA:17 `trans_bridge mod_ctor=0 mod_dtor=0`. No Rust *Module
//! type lands (honest absence, NOT a carried face); ctor/dtor SET cc:121/
//! :124 -> slots cc:145/:146.
//!
//! GRE adjacency CITE-NEVER-LAND (the PLAN §3 ruling, the trio's ONE GRE
//! token): the sid NAME `DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR` (165, RESIDENT
//! codec_module.rs:112, ZERO new const) is the ONLY gre-family touch —
//! cc:56 sed-pinned every build; GRE_HDR/gre_api/tunnel grep 0 in all
//! three TUs, TUNNEL_ERSPAN 0 tree-WIDE, the hook seam lives at cd_mpls.cc
//! :205-:206 (a b3 hand-off). ZERO coupling to cd_gre.rs.
//!
//! THE eth-face REUSE axis (PLAN §3 "the real reuse axis"): decode/log/
//! encode mirror the landed cd_eth shape — this TU's two EXTRA includes
//! (log/log_text.h :26, protocols/eth.h :27) are the pair's ONLY closure
//! delta (the E4 nologt/noeth walls kill ONLY this TU, the erspair
//! survive, every build). PROTO_BIT__ETH 0x000800 + CODEC_ETHER_NEXT +
//! protocol_id::ETHERTYPE_MINIMUM are framework IMPORT faces (landed,
//! NEVER re-authored); `eth::ETH_HEADER_LEN` 14 lands row-scoped with the
//! cd_eth.rs:51 twin cite (parity-pinned EQUAL, the dup-vs-import ruling
//! cd_icmp6.rs:179-:183). The LogEthAddrs call cc:79 is the FROZEN-WITNESS
//! STAND-IN REUSE face (log_text.cc:112 body drags the Packet/appid world;
//! eth build.sh :454 + tun_harness :179 precedents; the harness witness
//! body rides the witness_conf.cc heredoc; NEVER a new backbone pin — the
//! backbone STAYS 10).
//!
//! THE encode face: cited, NEVER called (vectors:18 cite line; EncState
//! pulls ip::IpApi — the eth_harness NEVER called encode either, ZERO
//! encode arms). Ported-by-reading with cc-line cites ONLY (the cc:92/
//! :98/:100-:109/:111-:112 face list the harness greps); the log face
//! cc:83-:86 (<= ETHERTYPE_MINIMUM -> "  len:0x%04X" else "  type:
//! 0x%04X") is cited-never-vectorized (vectors:17) — mirrored BELOW as
//! code, NEVER printed by the vectors.

use crate::framework::codec::{
    API_OPTIONS, CODEC_ETHER_NEXT, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord,
    CodecData, CodecTable, EncState, PLUGIN_SO_RELOAD, PROTO_BIT__ETH, PT_CODEC, ProtocolId,
    QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;
use crate::framework::codec::Buffer;

/// cc:33 `#define CD_TRANSBRIDGE_NAME "trans_bridge"` — NOTE the macro
/// NAME rides the DRIFT spelling (TRANSBRIDGE, no underscore) while the
/// string carries the underscore; the #define sits INSIDE the anon
/// namespace :31-:32/:47 (module doc headline, sed-enclosure pins).
pub const CD_TRANSBRIDGE_NAME: &str = "trans_bridge";
/// cc:34 `#define CD_TRANSBRIDGE_HELP "support for trans-bridging"` —
/// also INSIDE the anon namespace (vectors_faceA:16).
pub const CD_TRANSBRIDGE_HELP: &str = "support for trans-bridging";

/// protocol_ids.h:147 `ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558` (= 25944,
/// GETIDS faceA:19) — the cc:50 get_protocol_ids push. ROW home of the id
/// (the erspan2/erspan3 twins cite THIS file; the landed dup-not-import
/// family, parity-pinned EQUAL).
pub const ETHERTYPE_TRANS_ETHER_BRIDGING: ProtocolId = 0x6558;

/// eth.h:37 `constexpr uint16_t ETH_HEADER_LEN = 14;` — the cc:54 len
/// gate + cc:67 lyr_len write (vectors:15 len13 -> EV 165 / vectors:16
/// lyr=14). Row-scoped twin of cd_eth.rs:51 (the same C constexpr; the
/// dup-not-import ruling cd_icmp6.rs:179-:183 family — parity-pinned
/// EQUAL in the row's parity test).
pub const ETH_HEADER_LEN: u16 = 14;

/// eth.h:46-:47 `ProtocolId ethertype() const { return (ProtocolId)
/// ntohs(ether_type); }` over the EtherHdr window (dst @0..6, src @6..12,
/// type @12..14) — the same landed cd_eth rs:109-:111 face the mirror
/// re-uses (this TU's own copy, cited; cc:68 + cc:81 + cc:95 encode).
#[inline]
pub fn eth_hdr_ethertype(pkt: &[u8]) -> ProtocolId {
    u16::from_be_bytes([pkt[12], pkt[13]])
}

/// cc:36-:46 `class TransbridgeCodec : public Codec` — FOUR overrides
/// (get_protocol_ids :41 / decode :42 / log :43 / encode :44-:45 — the
/// trio's ONLY encode surface). NO Module subclass exists (the drift +
/// zero-mod-pair module doc headline): the C `Codec(CD_TRANSBRIDGE_NAME)`
/// ctor name face cc:39 rides the api record. decode's third C param
/// UNNAMED (cc:52) = never-read (pgm precedent). encode's `Flow*` is
/// UNNAMED (cc:45) = dropped like the other never-read pointer operands.
#[derive(Default)]
pub struct TransbridgeCodec;

impl TransbridgeCodec {
    /// cc:39 `TransbridgeCodec() : Codec(CD_TRANSBRIDGE_NAME) { }`
    pub fn new() -> TransbridgeCodec {
        TransbridgeCodec
    }

    /// cc:49-:50 `v.emplace_back(ProtocolId::ETHERTYPE_TRANS_ETHER_
    /// BRIDGING)` — vectors_faceA:19 GETIDS 25944 DECIMAL.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_TRANS_ETHER_BRIDGING); // cc:50
    }

    /// cc:52-:72 out-of-line decode, statement order VERBATIM
    /// (cc:66 proto_bits -> cc:67 lyr -> cc:68 next -> cc:69 flags).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink<'_>) -> bool {
        // cc:54-:58: `raw.len < eth::ETH_HEADER_LEN` (14) -> codec_event
        // DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR 165 (cc:56 — THE one GRE
        // token in the trio = the SID NAME ONLY, sed pin :56; 165
        // RESIDENT codec_module.rs:112). vectors:14 `EV 116 165`,
        // vectors:15 `TB len13 -> 0`.
        if raw.len < ETH_HEADER_LEN as u32 {
            crate::framework::codec::codec_event(
                codec,
                crate::codecs::codec_module::CodecSid::DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:60-:64 the EtherHdr reinterpret_cast face + the ground
        // comment `/* The Packet struct's ethernet header will now point
        // to the inner ethernet header of the packet */` rides here.
        codec.proto_bits |= PROTO_BIT__ETH;   // cc:66 (0x000800 = 2048, vectors:16 pb)
        codec.lyr_len = ETH_HEADER_LEN;       // cc:67 (14)
        codec.next_prot_id = eth_hdr_ethertype(raw.data); // cc:68 (eh->ethertype() — OUR bytes: 0x88BE fixture -> 35006, the pair story)
        codec.codec_flags |= CODEC_ETHER_NEXT; // cc:69 (0x1000 = 4096, vectors:16 flags)

        true // cc:71
    }

    /// cc:74-:87 out-of-line log (cited-never-vectorized — vectors:17
    /// cite line; the harness NEVER calls log). The `/*len*/` unnamed
    /// third param face kept. Mirrors the landed cd_eth log shape: the
    /// LogEthAddrs seam is the frozen-witness STAND-IN silent step
    /// (module doc; eth rs:181-:186 posture), the TextLog_Print format
    /// strings land literal (cc:84 `"  len:0x%04X"` / cc:86 `"  type:
    /// 0x%04X"`, the TWO leading spaces byte-exact, %04X upper-case).
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8], _len: u16) {
        // cc:77 the EtherHdr overlay + cc:79 `LogEthAddrs(text_log, eh);`
        // — stand-in: NO fragment under this face (the reuse pin, NEVER a
        // new backbone symbol).
        let _ = raw_pkt;

        // cc:81 `const ProtocolId prot_id = eh->ethertype();`
        let prot_id = eth_hdr_ethertype(raw_pkt);

        // cc:83-:86 the SAME <= ETHERTYPE_MINIMUM test as cd_eth (IMPORT
        // face protocol_id::ETHERTYPE_MINIMUM, to_utype both sides — the
        // landed rs:193-:198 posture), different arms:
        if (prot_id as u32) <= (protocol_id::ETHERTYPE_MINIMUM as u32) {
            sink(format!("  len:0x{prot_id:04X}")); // cc:84
        } else {
            sink(format!("  type:0x{prot_id:04X}")); // cc:86
        }
    }

    /// cc:89-:115 out-of-line encode — cited, NEVER called (vectors:18;
    /// the EncState-IpApi seam, eth_harness NEVER-called-encode
    /// precedent). Ported-by-reading, EVERY move cc-cited; the statement
    /// order rides verbatim: allocate cc:92 -> ethertype-select cc:98 ->
    /// forward keep-vs-swap cc:100-:109 -> NOT_SET resets cc:111-:112.
    /// The `raw_len` name IS used HERE (cc:92 allocate(raw_len)) — unlike
    /// cd_eth, no unused face.
    #[allow(clippy::needless_return)] // literal C flow kept readable
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // cc:92-:93 `if ( !buf.allocate(raw_len) ) return false;`
        if !buf.allocate(u32::from(raw_len)) {
            return false;
        }

        // cc:95-:96 the hi/ho EtherHdr overlays (hi = raw_in window; ho =
        // the freshly allocated head — data() is valid right after a
        // SUCCESSFUL allocate, the landed Buffer posture).
        let ho = buf.data_mut().expect("allocate(raw_len) just made size != 0");

        // cc:98 `ho->ether_type = enc.ethertype_set() ? htons(to_utype(
        // enc.next_ethertype)) : hi->ether_type;` — var-first (the row's
        // EVERY-compound rule): the select lands as a var before the
        // 12..14 store. htons(next_ethertype) writes the WIRE order ->
        // to_be_bytes; the else arm copies hi's wire bytes.
        let ethertype_bytes = if enc.ethertype_set() {
            enc.next_ethertype.to_be_bytes() // cc:98 TRUE arm
        } else {
            [raw_in[12], raw_in[13]] // cc:98 FALSE arm (hi->ether_type copy)
        };
        ho[12..14].copy_from_slice(&ethertype_bytes); // cc:98 store

        // cc:100-:109 `if ( enc.forward() )` keep-vs-swap MAC copies
        // (EtherHdr dst @0..6 / src @6..12; the sizeof copy faces ride
        // the 6-byte windows).
        if enc.forward() {
            ho[0..6].copy_from_slice(&raw_in[0..6]);  // cc:102 dst<-dst
            ho[6..12].copy_from_slice(&raw_in[6..12]); // cc:103 src<-src
        } else {
            ho[0..6].copy_from_slice(&raw_in[6..12]);  // cc:107 dst<-SRC
            ho[6..12].copy_from_slice(&raw_in[0..6]);  // cc:108 src<-DST
        }

        // cc:111-:112 the NOT_SET resets (both slots, every call):
        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET; // cc:111
        enc.next_proto = ip_protocol::PROTO_NOT_SET;         // cc:112

        true // cc:114
    }
}

// cc:117-:119 the "api" separator banner rides. cc:121-:125 `static
// Codec* ctor(Module*)` + `static void dtor(Codec*)` ride behavior-only
// cites (record SET flags; the Rust codec face is TransbridgeCodec::new).
// NO mod pair EXISTS here — the BaseApi slots take the bare nullptr pair.

/// cc:127-:147 `static const CodecApi transbridge_api` (the api VAR also
/// carries the drift spelling): name/help slots cc:136/:137 land the
/// inside-ns macro faces; mod_ctor cc:138 + mod_dtor cc:139 the EXPLICIT
/// `nullptr, nullptr` pair (no comment, §15 faceA pin 0/0); pinit/pterm/
/// tinit/tterm nullptr cc:141-:144 = false x4; ctor/dtor SET cc:145/:146.
pub const TRANSBRIDGE_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:130
    size: CDAPI_SIZEOF_CODEC_API, // cc:131 sizeof(CodecApi)=112 (faceA:15)
    api_version: CDAPI_VERSION,   // cc:132 1900547
    version: 0,                   // cc:133
    features: PLUGIN_SO_RELOAD,   // cc:134
    options: API_OPTIONS,         // cc:135
    name: CD_TRANSBRIDGE_NAME,    // cc:136 -> "trans_bridge"
    help: CD_TRANSBRIDGE_HELP,    // cc:137
    mod_ctor: false,              // cc:138 nullptr (the 1/1/0 ZERO side)
    mod_dtor: false,              // cc:139 nullptr
    pinit: false,                 // cc:141 nullptr
    pterm: false,                 // cc:142 nullptr
    tinit: false,                 // cc:143 nullptr
    tterm: false,                 // cc:144 nullptr
    ctor: true,                   // cc:145 SET
    dtor: true,                   // cc:146 SET
};

/// cc:149-:157 the hidden export with THE drift name: `#ifdef BUILDING_SO`
/// cc:149 / SO arm cc:150 / the static-build `const BaseApi*
/// cd_transbridge[] =` cc:152 feeding `&transbridge_api.base` cc:155 +
/// nullptr cc:156. nm: the .o defines cd_transbridge, EXACTLY-0 occurrences
/// of cd_trans_bridge (the drift refusal, every build; §5 tripwire: Rust
/// landing files use the FILE base name `cd_trans_bridge.rs` — grep-vs-
/// file confusion trips at the harness sed pins :152/:155). Ladder entry
/// "cd_transbridge" RESIDENT codec_api.rs:127 NEVER re-touched (ground
/// extern codec_api.cc :69, load :114).
pub const CD_TRANSBRIDGE: CodecTable = &[&TRANSBRIDGE_API];
