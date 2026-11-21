//! Port of `src/codecs/link/cd_erspan3.cc` (147 L) — row 18l, the codecs/
//! link CHEAP SUB-TRIO half two (`tools/erspan_harness`, ZERO-gate probe-
//! only, 19th straight). Ground: snort3-src @ fe29cbe, md5
//! `8ba0422c85300be2f799c6e24b4b8086` wc 147 (the 450 SUM asserted every
//! build). DIR FACT: `codecs/link/`. SIBLING of cd_erspan2.rs (diff = 120
//! lines on 145/147, PLAN §0): same NAME/HELP-outside-ns shape (cc:29/:30),
//! same REAL mod pair, same hidden static arm (`cd_erspan3[]` cc:141 feeds
//! `&erspan3_api.base` cc:144), same SHARED 462 version-mismatch sid +
//! the SAME RuleMap-order-vs-event twist below.
//!
//! THE sizeof-20 DISK FACE (the §9 CORRECTION-HONESTY pin): the seed-pass
//! PLAN label "ERSpanType3Hdr 16B" was WRONG on disk — the fields
//! ver_vlan(2), flags_spanId(2), timestamp(4), pad0(2), pad1(2), pad2(4),
//! pad3(4) at cc:60-:66 sum to **20** (sizeof, cc:58-:70). The 16-B seed
//! arms MISFIRED EV 464 x3 (scratch build_run6/7 caught it BY the vectors,
//! fixed); the landed vectors carry len19 / 20-B payload arms and lyr=20.
//! The harness PYPIN re-derives `lyr=20` from ground every build.
//!
//! THE mod-pair face: REAL like the sibling — `mod_ctor()` cc:104-:105 +
//! `mod_dtor()` cc:107-:108 into the BaseApi slots cc:127/:128 (FACE-A
//! vectors_faceA:12 `erspan3 mod_ctor=1 mod_dtor=1` — the trio census
//! 1/1/0, do NOT carry any prior row's face). ctor/dtor SET cc:110/:113 ->
//! slots cc:134/:135.
//!
//! THE ground TYPO honesty pin (transcribed, NEVER silently fixed): the
//! id line protocol_ids.h:146 reads `ETHERTYPE_ERSPAN_TYPE3 = 0X22EB,` —
//! a CAPITAL-X hex literal, the ground's own typo face, sed-pinned by the
//! harness PYPIN (`"0X22EB" in protocol_ids.h` asserted every build) and
//! mirrored VERBATIM in the const cite below. Value = 0x22EB = 8939
//! decimal (GETIDS faceA:14).
//!
//! THE RuleMap/464 face: erspan3's table carries EXACTLY ONE data row
//! (464 "captured < ERSpan type3 header length", cc:36) + terminator
//! cc:37 — the SHARED 462 fires HERE (cc:91) WITHOUT its own RuleMap row;
//! the sibling's table carries 462 first (cc:36). A sibling-pair asymmetry
//! the diff hides in 120 lines — pinned by the tables below.
//! sids 464/462 RESIDENT codec_module.rs:222/:220 (ZERO new consts).
//!
//! GRE adjacency CITE-NEVER-LAND (PLAN §3): GRE/tunnel tokens grep 0 in
//! this TU (build.sh census `grep -c GRE cd_erspan3.cc == 0` every build);
//! the header is PRIVATE, ZERO struct shared with cd_gre.rs. Session-id
//! face (cc:60-:61 ver_vlan + flags_spanId) cited-never-ported beyond the
//! >>12 mask (PLAN §8; vectors:10 cite line).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData, CodecTable,
    PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};

/// cc:29 `#define CD_ERSPAN3_NAME "erspan3"` — TRUE-NAME side.
pub const CD_ERSPAN3_NAME: &str = "erspan3";
/// cc:30 `#define CD_ERSPAN3_HELP "support for encapsulated remote
/// switched port analyzer - type 3"` (vectors_faceA:11).
pub const CD_ERSPAN3_HELP: &str = "support for encapsulated remote switched port analyzer - type 3";

/// protocol_ids.h:146 `ETHERTYPE_ERSPAN_TYPE3 = 0X22EB` — NOTE the GROUND
/// TYPO: a CAPITAL X in the hex literal (`0X22EB`), transcribed VERBATIM
/// per the §9 honesty pin (the harness PYPIN asserts the typo face in the
/// ground header EVERY build; NEVER silently fixed here or there). Value
/// = 8939 decimal (GETIDS faceA:14, python-derived). The cc:75
/// get_protocol_ids push. Row-scoped home (ZERO prior landed face).
pub const ETHERTYPE_ERSPAN_TYPE3: ProtocolId = 0x22EB; // ground literal `0X22EB` (typo face pinned)

/// protocol_ids.h:147 `ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558` (= 25944)
/// — the cc:95 next_prot_id WRITE. File-local twin of the cd_trans_bridge
///.rs home / the cd_erspan2.rs twin (the file-local code-scope dup family
/// with cites; parity-pinned EQUAL in the row's parity test).
pub const ETHERTYPE_TRANS_ETHER_BRIDGING: ProtocolId = 0x6558;

/// cc:58-:70 `struct ERSpanType3Hdr` — THE sizeof-20 DISK face (module doc
/// headline correction): fields ver_vlan @0..1, flags_spanId @2..3,
/// timestamp @4..7, pad0 @8..9, pad1 @10..11, pad2 @12..15, pad3 @16..19;
/// sizeof = 20 for this layout (u32 members keep the sum at 20) = the
/// cc:82 len gate AND the cc:96 lyr_len write (vectors:8 len19 -> EV 464;
/// vectors:11 lyr=20). The 6 pad fields ride unread (the ground's own
/// dead-ish padding, cited, NEVER a Rust symbol beyond the size).
pub const ERSPAN3_HDR_SIZE: u32 = 20;

/// cc:68-:69 `inline uint16_t version() const` returning
/// `ntohs(ver_vlan) >> 12` — the `inline` keyword face (the erspan2
/// sibling omits it — one of the 120 diff lines). Session-id face cited-
/// never-ported (the ONLY extracted field is version(); vectors:10).
#[inline]
pub fn erspan3_version(raw: &[u8]) -> u16 {
    u16::from_be_bytes([raw[0], raw[1]]) >> 12
}

/// cc:34-:38 `static const RuleMap erspan3_rules[]` — EXACTLY ONE data row
/// plus the terminator (the sibling-pair table asymmetry, module doc):
///   cc:36 464, cc:37 `{ 0, nullptr }`. NO 462 row HERE despite the SHARED
///   sid firing at cc:91 (the sibling cc:36 DOES carry it) — byte-exact
///   message face: captured < ERSpan type3 header length. sids REUSE the landed enum
/// (codec_module.rs :222/:220 — ZERO new constants).
pub const ERSPAN3_RULES: [RuleMap; 2] = [
    RuleMap { sid: CodecSid::DECODE_ERSPAN3_DGRAM_LT_HDR as u32, msg: Some("captured < ERSpan type3 header length") }, // cc:36
    RuleMap { sid: 0, msg: None }, // cc:37
];

/// cc:40-:47 `class Erspan3Module : public BaseCodecModule` — the REAL
/// module (the 1/1 side of the trio 1/1/0 census): 2-arg base ctor cc:43,
/// get_rules override cc:45-:46. The Rust face of real `mod_ctor()` cc:104.
#[derive(Debug)]
pub struct Erspan3Module {
    pub base: BaseCodecModule,
}

impl Erspan3Module {
    /// cc:43 the 2-arg ctor face.
    pub fn new() -> Erspan3Module {
        Erspan3Module { base: BaseCodecModule::new(CD_ERSPAN3_NAME, CD_ERSPAN3_HELP) }
    }

    /// cc:45-:46 `get_rules()` override -> erspan3_rules.
    pub fn get_rules() -> &'static [RuleMap] {
        &ERSPAN3_RULES
    }
}

impl Default for Erspan3Module {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:49-:56 `class Erspan3Codec : public Codec` — TWO overrides
/// (get_protocol_ids / decode), same shape as the sibling. decode's third
/// C param UNNAMED (cc:77) = never-read (pgm precedent).
#[derive(Default)]
pub struct Erspan3Codec;

impl Erspan3Codec {
    /// cc:52 `Erspan3Codec() : Codec(CD_ERSPAN3_NAME) { }`
    pub fn new() -> Erspan3Codec {
        Erspan3Codec
    }

    /// cc:74-:75 `v.emplace_back(ProtocolId::ETHERTYPE_ERSPAN_TYPE3)` —
    /// vectors_faceA:14 `GETIDS erspan3 8939` DECIMAL (the 0X22EB-typo
    /// ground face, python-derived).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_ERSPAN_TYPE3); // cc:75
    }

    /// cc:77-:98 out-of-line decode, statement order VERBATIM. THE
    /// ORDER-SITE FACE (the vectors:11 cite line + §8): the happy arm
    /// writes next_prot_id FIRST (cc:95) THEN lyr_len (cc:96) — the
    /// INVERSE of the erspan2 sibling (:93 lyr before :94 next). Both
    /// fields land either way (both arms return true); the ORDER still
    /// transcribes (the row's eval-order discipline).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink<'_>) -> bool {
        // cc:79-:80 the ERSpanType3Hdr reinterpret_cast face (window
        // overlay, no materialization). cc:82-:86: `raw.len <
        // sizeof(ERSpanType3Hdr)` (= 20, module doc) -> codec_event
        // DECODE_ERSPAN3_DGRAM_LT_HDR (cc:84, vectors:7 `EV 116 464`) +
        // false (vectors:8 `E3 len19 -> 0 lyr=0` — fail NEVER sets lyr).
        if raw.len < ERSPAN3_HDR_SIZE {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_ERSPAN3_DGRAM_LT_HDR as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:88-:93 the version gate (`// Check that this is in fact
        // ERSpan Type 3.` cc:88, `/* Type 3 == version 0x02 */` cc:89;
        // var-first: version() lands as a VAR before the compare).
        let version = erspan3_version(raw.data); // cc:89 LHS
        if version != 0x02 {
            // cc:91 the SHARED 462 (the (a1) pin: vectors:5 `EV 116 462`
            // = the EXACTLY-2 faceA-shared-462 vectors census across the
            // sibling pair).
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_ERSPAN_HDR_VERSION_MISMATCH as u32,
                sink,
            );
            return false;
        }

        codec.next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING; // cc:95 (NEXT FIRST — the order face, 25944)
        codec.lyr_len = ERSPAN3_HDR_SIZE as u16; // cc:96 (lyr SECOND; = 20 the sizeof DISK face, vectors:11)
        true // cc:97; codec_flags STAYS 0 (vectors:11 flags=0 — exactly
             // TWO flags=0 arms across the DEC face, the harness PYPIN)
    }
    // session-id cite (cc:60-:61 ver_vlan + flags_spanId — the SAME field
    // names as the sibling's cc:61-:62): cited-NEVER-ported beyond the
    // >>12 version mask (PLAN §8; the vectors:10 cite line).

    // NO log / encode / get_data_link_type overrides (TWO only, cc:54-:55;
    // GETDLT ZERO faceA census).
}

// cc:100-:102 the "api" separator banner rides. cc:104-:108 the REAL mod
// pair (Erspan3Module::new IS the Rust mod_ctor face); cc:110-:114 the
// Codec ctor/dtor pair ride behavior-only cites (record SET flags).

/// cc:116-:136 `static const CodecApi erspan3_api` — the record: mod pair
/// TRUE cc:127/:128 (REAL cc:104/:107); name/help slots cc:125/:126;
/// pinit/pterm/tinit/tterm nullptr cc:130-:133 = false x4; ctor/dtor SET
/// cc:134/:135.
pub const ERSPAN3_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:119
    size: CDAPI_SIZEOF_CODEC_API, // cc:120 sizeof(CodecApi)=112 (faceA:10)
    api_version: CDAPI_VERSION,   // cc:121 1900547
    version: 0,                   // cc:122
    features: PLUGIN_SO_RELOAD,   // cc:123
    options: API_OPTIONS,         // cc:124
    name: CD_ERSPAN3_NAME,        // cc:125 -> "erspan3"
    help: CD_ERSPAN3_HELP,        // cc:126
    mod_ctor: true,               // cc:127 REAL (the trio 1/1/0 side)
    mod_dtor: true,               // cc:128 REAL
    pinit: false,                 // cc:130 nullptr
    pterm: false,                 // cc:131 nullptr
    tinit: false,                 // cc:132 nullptr
    tterm: false,                 // cc:133 nullptr
    ctor: true,                   // cc:134 SET
    dtor: true,                   // cc:135 SET
};

/// cc:138-:146 the hidden export: `#ifdef BUILDING_SO` cc:138 / SO arm
/// cc:139 / the static-build `const BaseApi* cd_erspan3[] =` cc:141
/// feeding `&erspan3_api.base` cc:144 + nullptr cc:145. nm table D
/// EXACTLY-1. TRUE NAME holds x3 (drift name lives in the TB mate ONLY).
/// Ladder entry "cd_erspan3" RESIDENT codec_api.rs:104 NEVER re-touched
/// (ground extern codec_api.cc :46, load :91).
pub const CD_ERSPAN3: CodecTable = &[&ERSPAN3_API];
