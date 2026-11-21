//! Port of `src/codecs/misc/cd_vxlan.cc` (133 L) — row 18k, the codecs/misc
//! LEFTOVER TRIO half two (`tools/misc3_harness`, ZERO-gate probe-only).
//! Ground: snort3-src @ fe29cbe, md5 `c8479a2aa67ee6af89c22ecc8f763b7d`
//! wc 133 (misc3 build.sh md5/wc + the 498 SUM pins every build). DIR
//! FACT: `codecs/misc/`. Include closure rides the donor RESIDENT face
//! PLUS the active.h rider (E4 wall: strip packet_io/active.h -> ONLY
//! cd_vxlan dies at cc:27 — MEASURED every build; codec_module.h strip
//! kills ONLY the llc mate).
//!
//! THE tunnel_bypass HOOK seam (THE central check, PLAN §2): cc:73-:74
//! `if ( codec.conf->tunnel_bypass_enabled(TUNNEL_VXLAN) ) codec.
//! tunnel_bypass = true;` — the HOOK, NOT a checksum peg (the 18h peg-vs-
//! hook correction; pin the CALLEE: decl main/snort_config.h:777, body
//! main/snort_config.cc:1022 `!((tunnel_mask & proto) or SFDAQ::
//! get_tunnel_bypass(proto))`). The Rust face is the landed LEFT-OPEN
//! bypass hook param — the cd_teredo.rs :219-:221 / cd_gtp :326 /
//! cd_geneve :300 precedent family, replayed the 18f witness_18f body
//! face (`!((tun_mask & proto) != 0)`, tun_witness_set_mask(0x100) ->
//! FALSE / set_mask(0) -> TRUE, vectors:11/:12 both arms DUAL-FACE).
//! The tunnel_bypass FIELD lands in the landed CodecData (framework/
//! codec.rs :236). U-census of the row .o: llc 0 / vxlan 1 / user 0 —
//! witness_18f CARRIED, EXACTLY-ZERO new bypass witness this row.
//! EVAL ORDER (the vectors:10 cite line): the HOOK read cc:73 runs
//! BEFORE the lyr/proto_bits/next/flags sets cc:76-:79 — transcribed in
//! statement order VERBATIM.
//!
//! NOT a tunnel_decap/encap row (grep 'decap|encap' over the TU = 0
//! MEASURED every build): the dport-4789 VXLAN_U_PORT face lives in
//! cd_udp.cc (landed cd_udp.rs :123) — NEVER imported here (this TU
//! never references it ground-side).
//!
//! REUSE cites (PLAN §3): CODEC_NON_IP_TUNNEL 0x0200 IMPORTED from the
//! landed framework/codec.rs :51; ETHERNET_802_3 0x0105 IMPORTED from
//! the landed protocol_id face (framework/codec.rs :164-:166,
//! protocol_ids.h:132; vectors:11/:12 next=261 — the 802_3 face HERE is
//! the decode next_prot_id WRITE, verified this row as the cd_eth
//! vectors:9 print face already landed; cd_geneve.rs imports the SAME
//! const — the family face). ROW-SCOPED DUPLICATE per the cd_icmp6.rs:
//! 179-:183 ruling (the 18j embed-id family): PROTOCOL_ID_VXLAN 0x0108
//! (protocol_ids.h:135 — the cd_udp.rs :147 twin lives in ITS module
//! scope, same cite posture, no collision; vectors_faceA:14 GETIDS vxlan
//! 264 DECIMAL). NEW row-scoped PROTO_BIT__VXLAN 0x040000 with the
//! decode_data.h:105 cite — ZERO prior landed face (grep src == 0
//! re-measured; the PYPIN in build.sh re-derives 262144 ground-side
//! every build). TUNNEL_VXLAN 0x100 row-scoped (snort_config.h:127, the
//! cd_teredo.rs TUNNEL_TEREDO sibling precedent).
//!
//! THE mod-pair ZERO face (the 1/0/0 asymmetry, half two): cc:113/:114
//! plain `nullptr,` X2 (no inline comment — the user mate's EXPLICIT
//! `// mod_ctor` comments are the contrast face), vectors_faceA:12
//! `vxlan mod_ctor=0 mod_dtor=0`; pinit/pterm/tinit/tterm carry the
//! ground's own `// pinit ...` slot comments cc:116-:119 (transcribed).

use crate::framework::codec::{
    API_OPTIONS, CODEC_NON_IP_TUNNEL, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord,
    CodecData, CodecTable, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, RawData, protocol_id,
};

/// cc:31 `#define CD_VXLAN_NAME "vxlan"` — TRUE-NAME side.
pub const CD_VXLAN_NAME: &str = "vxlan";
/// cc:32 `#define CD_VXLAN_HELP "support for Virtual Extensible LAN"`
/// (vectors_faceA:11).
pub const CD_VXLAN_HELP: &str = "support for Virtual Extensible LAN";

/// cc:55 `constexpr uint16_t VXLAN_MIN_HDR_LEN = 8` — the cc:65 len gate,
/// the cc:76 lyr_len write, AND the VNI read bounds (the harness sed-pins
/// the constexpr line ground-side every build).
pub const VXLAN_MIN_HDR_LEN: u16 = 8;

/// decode_data.h:105 `#define PROTO_BIT__VXLAN 0x040000` (= 262144) — the
/// cc:77 proto_bits OR; vectors:11/:12 pb=262144. ZERO landed Rust face
/// pre-row (module doc; the harness PYPIN re-derives from the ground
/// header every build) — row-scoped home.
pub const PROTO_BIT__VXLAN: u32 = 0x040000;

/// snort_config.h:127 `TUNNEL_VXLAN = 0x100` (= 256, enum TunnelFlags
/// :119-:128 — the 18f witness mask face, sed-pinned every build) — the
/// cc:73 bypass-call argument; the vector LABEL `mask256` rides the
/// decimal (harness PYPIN).
pub const TUNNEL_VXLAN: u16 = 0x100;

/// protocol_ids.h:135 `VXLAN = 0x0108` (== 264) — the cc:60
/// get_protocol_ids push + the probe's CodecData init face. ROW-SCOPED
/// DUPLICATE per the cd_icmp6.rs:179-:183 / 18j embed-id ruling: the
/// cd_udp.rs :147 PROTOCOL_ID_VXLAN twin (the cc:458 decode arm there)
/// lives in ITS module scope — same value, same cite, no collision (the
/// cd_teredo/cd_udp PROTOCOL_ID_TEREDO twin family the same way).
pub const PROTOCOL_ID_VXLAN: ProtocolId = 0x0108;

/// cc:46-:54 `struct VXLANHdr` — the wire layout the window reads mirror:
/// flags @0; `reserved_1[3]` @1..3 (the ground's own `// cppcheck-suppress
/// unusedStructMember` rides — never materialized, unread face);
/// vni[3] @4..6 (`//VXLAN network id` comment rides); `reserved_2` @7
/// (cppcheck-suppress again). sizeof = 8 = VXLAN_MIN_HDR_LEN.
pub const VXLAN_HDR_FLAGS_OFF: usize = 0;
pub const VXLAN_HDR_VNI_OFF: usize = 4;

/// cc:88 the VNI read `( hdr->vni[0] << 16 ) | ( hdr->vni[1] << 8 ) |
/// hdr->vni[2]` — u32 accumulator over the WINDOW bytes @4..6 (the log
/// face; big-endian 24-bit network id).
#[inline]
pub fn vxlan_vni(raw: &[u8]) -> u32 {
    (u32::from(raw[VXLAN_HDR_VNI_OFF]) << 16)
        | (u32::from(raw[VXLAN_HDR_VNI_OFF + 1]) << 8)
        | u32::from(raw[VXLAN_HDR_VNI_OFF + 2])
}

/// cc:36-:44 `class VxlanCodec : public Codec` — THREE overrides
/// (get_protocol_ids / decode / log). Stack-owned Rust posture (18d);
/// the C `Codec(CD_VXLAN_NAME)` ctor name face cc:39 rides the record.
/// decode's third C param UNNAMED (`DecodeData&`, cc:63) = never-read
/// (pgm precedent — ZERO seam struct).
#[derive(Default)]
pub struct VxlanCodec;

impl VxlanCodec {
    /// cc:39 `VxlanCodec() : Codec(CD_VXLAN_NAME) { }`
    pub fn new() -> VxlanCodec {
        VxlanCodec
    }

    /// cc:58-:61 `v.push_back(ProtocolId::VXLAN)` — vectors_faceA:14
    /// GETIDS vxlan 264 DECIMAL.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(PROTOCOL_ID_VXLAN); // cc:60
    }

    /// cc:63-:82 out-of-line decode, statement order VERBATIM — zero-
    /// event asymmetry (the two gates return false with NO codec_event;
    /// the llc mate is the trio's only event TU): NO sink param (the
    /// cd_teredo zero-event signature precedent). `bypass` is the
    /// left-open hook for the cc:73 conf->tunnel_bypass_enabled read
    /// (module doc; the 18f witness replay closure shape).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        bypass: &mut dyn FnMut(u16) -> bool,
    ) -> bool {
        // cc:65-:66 `if ( raw.len < VXLAN_MIN_HDR_LEN ) return false;` —
        // vectors:8 `VX len7 -> 0` (NO event).
        if raw.len < u32::from(VXLAN_MIN_HDR_LEN) {
            return false;
        }

        // cc:68 the VXLANHdr reinterpret_cast face: flags window @0.
        // cc:70-:71 `if ( hdr->flags != 0x08 ) return false;` — literal
        // 0x08 rides (the I-bit; vectors:9 flags-neq8 -> 0, NO event).
        if raw.data[VXLAN_HDR_FLAGS_OFF] != 0x08 {
            return false;
        }

        // cc:73-:74 the BYPASS arm — eval-order pin: this read rides
        // BEFORE every set below (:76-:79); the mask256 FALSE arm (bypass
        // still 0 BELOW) proves the hook ran first without mutation.
        if bypass(TUNNEL_VXLAN) {
            codec.tunnel_bypass = true; // cc:74
        }

        // cc:76-:79 the four sets (vectors:11/:12 lyr=8 pb=262144
        // next=261 flags=512) — next via the LANDED protocol_id IMPORT
        // (module doc; 0x0105 ETHERNET_802_3 inner ethernet).
        codec.lyr_len = VXLAN_MIN_HDR_LEN;                              // cc:76
        codec.proto_bits |= PROTO_BIT__VXLAN;                           // cc:77
        codec.next_prot_id = protocol_id::ETHERNET_802_3;               // cc:78
        codec.codec_flags |= CODEC_NON_IP_TUNNEL;                       // cc:79

        true // cc:81
    }

    /// cc:84-:90 out-of-line log (ported-by-reading, cite-never-
    /// vectorized: ZERO log lines in either vectors face). TextLog_Print
    /// seam = the landed String-sink closure (cd_eth:187 shape); the
    /// `%u` decimal VNI face (NOT %X — all-decimal hygiene matches the
    /// ground format).
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8], _lyr_len: u16) {
        // cc:88-:89 `uint32_t vni = ...; TextLog_Print(text_log,
        // "network identifier: %u", vni)`.
        sink(format!("network identifier: {}", vxlan_vni(raw_pkt)));
    }
}

// cc:92-:94 the "api" separator banner rides. cc:96-:100 `static Codec*
// ctor(Module*)` / `static void dtor(Codec*)` ride behavior-only cites
// (record flags SET); Rust codec face = VxlanCodec::new (18d posture).

/// cc:102-:122 `static const CodecApi vxlan_api` — the mod-pair ZERO
/// face: nullptr X2 cc:113/:114 (vectors_faceA:12 mod_ctor=0 — the 1/0/0
/// trio asymmetry, module doc headline); the four g/t nullptr slots carry
/// the ground's own `// pinit`-style comments cc:116-:119; ctor/dtor SET
/// cc:120-:121 (the `// ctor` / `// dtor` comment pins transcribed).
pub const VXLAN_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:105
    size: CDAPI_SIZEOF_CODEC_API, // cc:106 sizeof(CodecApi)=112 (faceA:10)
    api_version: CDAPI_VERSION,   // cc:107 1900547
    version: 0,                   // cc:108
    features: PLUGIN_SO_RELOAD,   // cc:109
    options: API_OPTIONS,         // cc:110
    name: CD_VXLAN_NAME,          // cc:111 -> "vxlan"
    help: CD_VXLAN_HELP,          // cc:112
    mod_ctor: false,              // cc:113 nullptr (plain, no comment)
    mod_dtor: false,              // cc:114 nullptr (plain, no comment)
    pinit: false,                 // cc:116 nullptr  // pinit
    pterm: false,                 // cc:117 nullptr  // pterm
    tinit: false,                 // cc:118 nullptr  // tinit
    tterm: false,                 // cc:119 nullptr  // tterm
    ctor: true,                   // cc:120 SET      // ctor
    dtor: true,                   // cc:121 SET      // dtor
};

/// cc:124-:133 the hidden export (trio BUILDING_SO census, PLAN §1):
/// `#ifdef BUILDING_SO` cc:124 / `SO_PUBLIC const BaseApi* snort_plugins[]= `
/// cc:125 / the static-build `const BaseApi* cd_vxlan[] =` cc:127 feeding
/// `&vxlan_api.base` cc:130 + nullptr cc:131; nm table symbol EXACTLY-1
/// (the STATIC arm IS the harness face). Table name == file base == NAME
/// (TRUE x3). Ladder entry "cd_vxlan" RESIDENT codec_api.rs :131 NEVER
/// re-touched (extern codec_api.cc :73, load :118).
pub const CD_VXLAN: CodecTable = &[&VXLAN_API];
