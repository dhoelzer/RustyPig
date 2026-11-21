//! Port of `src/codecs/link/cd_erspan2.cc` (145 L) — row 18l, the codecs/
//! link CHEAP SUB-TRIO half one (`tools/erspan_harness`, ZERO-gate probe-
//! only, the 19th straight honest zero-gate face: find src/codecs/link
//! -type d -name test = 0). Ground: snort3-src @ fe29cbe, md5
//! `fee3934f71fe1c77cf3c0aef120e7eec` wc 145 (the 145+147+158 = 450 SUM
//! re-measured and asserted EVERY build by tools/erspan_harness/build.sh,
//! PLAN §0). DIR FACT: `codecs/link/`. SIBLING-PAIR face: diff vs
//! cd_erspan3.cc = 120 diff lines on 145/147-L files (measured, PLAN §0 —
//! the richest vectors-per-byte story, the (a1) rationale).
//!
//! THE mod-pair ASYMMETRY 1/1/0 (the row census headline, PLAN §1: do NOT
//! carry misc3's 1/0/0, daq3's 1/1/1 or miscip's 0/0/0): erspan2 carries a
//! REAL module — `static Module* mod_ctor()` cc:102-:103 + `static void
//! mod_dtor(Module*)` cc:105-:106 feed the BaseApi slots cc:125/:126
//! (FACE-A vectors_faceA:7 `erspan2 mod_ctor=1 mod_dtor=1`). The Rust
//! mod_ctor face is `Erspan2Module::new` (the landed UdpModule::new 18i /
//! LlcModule::new 18k posture: the C++ heap `new` folds onto stack-owned
//! Rust); the record carries mod_ctor/mod_dtor TRUE (the harness + FACE-A
//! pin). ctor/dtor (CodecApi slots) non-null cc:108/:111 (slots cc:132/
//! :133) — the faceA `ctor=1 dtor=1` face.
//!
//! THE hidden-TABLE face (the family census HOLDS x3, PLAN §1): the export
//! rides `#ifdef BUILDING_SO` cc:136 — SO arm cc:137, the REAL static arm
//! `const BaseApi* cd_erspan2[] =` cc:139 feeds `&erspan2_api.base` cc:142;
//! the nm table symbol D EXACTLY-1 (the static arm IS the harness face,
//! sed-verbatim every build). The Rust face = the landed-row pattern (ZERO
//! no_mangle attribute sites in src, grep-verified): doc-cite + `pub const
//! CD_ERSPAN2: CodecTable`. TRUE NAME holds x3: file base == table base ==
//! NAME "erspan2" (cc:29 macro, sed-pinned every build; the drift headline
//! name `cd_transbridge[]` lives in the trans_bridge mate, §1). Ladder
//! entry "cd_erspan2" RESIDENT codec_api.rs:103 (ground extern codec_api.cc
//! :45, load :90) NEVER re-walked.
//!
//! SIBLING-PAIR story (the (a1) pick, PLAN §3): the SHARED sid
//! DECODE_ERSPAN_HDR_VERSION_MISMATCH (462) is loaded by BOTH siblings —
//! this TU's RuleMap row cc:36 + the decode event cc:89; the version-check
//! literals are 0x01 HERE (cc:87) vs 0x02 in the erspan3 mate (cc:89).
//! sids 463/462 RESIDENT codec_module.rs:221/:220 (codec_module.h walk;
//! ZERO new consts, PLAN §4 — NEVER re-walked, the import face).
//!
//! GRE adjacency is CITE-NEVER-LAND (the PLAN §3 ruling re-measured):
//! GRE/gre_api/GRE_HDR/ tunnel tokens grep 0 HERE and 0 in both mates
//! (build.sh census every build — the briefing's tunnel face was WRONG on
//! disk, §1); the erspan header is PRIVATE `ERSpanType2Hdr` (cc:59-:67),
//! ZERO struct shared with cd_gre.rs. Reuse axis = the landed framework
//! faces ONLY (protocol_id family, CodecData, codec_event/QueueSink seam,
//! BaseCodecModule).
//!
//! Session-id honesty (PLAN §8, vectors:6 cite line): the ver_vlan low-12
//! vlan bits + flags_spanId (cc:61-:62) are NEVER ported beyond the
//! `>> 12` version mask — the ONLY extracted field is version(), EXACTLY
//! as the ground itself Extracts (cc:65-:66); ZERO mask-constant lands
//! with this file pinning the never-ported face.

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData, CodecTable,
    PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};

/// cc:29 `#define CD_ERSPAN2_NAME "erspan2"` — TRUE-NAME side (the trio's
/// NAME lives OUTSIDE the anon namespace, the trans_bridge contrast face).
pub const CD_ERSPAN2_NAME: &str = "erspan2";
/// cc:30 `#define CD_ERSPAN2_HELP "support for encapsulated remote
/// switched port analyzer - type 2"` (vectors_faceA:6).
pub const CD_ERSPAN2_HELP: &str = "support for encapsulated remote switched port analyzer - type 2";

/// protocol_ids.h:159 `ETHERTYPE_ERSPAN_TYPE2 = 0x88BE` (= 35006, the
/// DECIMAL GETIDS faceA:9) — the cc:72 get_protocol_ids push. Row-scoped
/// home per the landed dup-not-import rule (ZERO prior landed Rust face
/// MEASURED grep src; the harness PYPIN re-derives from the ground header
/// every build).
pub const ETHERTYPE_ERSPAN_TYPE2: ProtocolId = 0x88BE;

/// protocol_ids.h:147 `ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558` (= 25944)
/// — the cc:94 next_prot_id WRITE. File-local twin of the cd_trans_bridge
///.rs home (its GETIDS id cc:50): the cd_user/cd_udp PROTO_BIT twin-family
/// precedent (file-local code-scope dupes with cites; NEVER framework-
/// imported, the framework-owned family rule), parity-pinned EQUAL.
pub const ETHERTYPE_TRANS_ETHER_BRIDGING: ProtocolId = 0x6558;

/// cc:59-:67 `struct ERSpanType2Hdr` — window layout: ver_vlan @0..1,
/// flags_spanId @2..3, pad @4..7; sizeof = 8 = the cc:79 len gate AND the
/// cc:93 lyr_len write (vectors:2/:5 lyr=8 face; the harness PYPIN
/// sed-pins `codec.lyr_len = sizeof(ERSpanType2Hdr);`). No struct
/// materialization (the landed reinterpret_cast/window posture).
pub const ERSPAN2_HDR_SIZE: u32 = 8;

/// cc:65-:66 `uint16_t version() const { return ntohs(ver_vlan) >> 12; }`
/// — the ONLY extracted struct field (session-id face cited-never-ported,
/// module doc; vectors:6). Big-endian wire read (ntohs).
#[inline]
pub fn erspan2_version(raw: &[u8]) -> u16 {
    u16::from_be_bytes([raw[0], raw[1]]) >> 12
}

/// cc:34-:39 `static const RuleMap erspan2_rules[]` — TWO data rows +
/// terminator, order VERBATIM: cc:36 the SHARED 462 row FIRST, cc:37 463,
/// cc:38 `{ 0, nullptr }`. sids REUSE the landed enum (codec_module.rs
/// :220/:221 — ZERO new constants; the messages land byte-exact:
/// "ERSpan header version mismatch" / "captured length < ERSpan type2
/// header length").
pub const ERSPAN2_RULES: [RuleMap; 3] = [
    RuleMap { sid: CodecSid::DECODE_ERSPAN_HDR_VERSION_MISMATCH as u32, msg: Some("ERSpan header version mismatch") }, // cc:36
    RuleMap { sid: CodecSid::DECODE_ERSPAN2_DGRAM_LT_HDR as u32, msg: Some("captured length < ERSpan type2 header length") }, // cc:37
    RuleMap { sid: 0, msg: None }, // cc:38
];

/// cc:41-:48 `class Erspan2Module : public BaseCodecModule` — the REAL
/// module side of the 1/1/0 asymmetry (module doc headline): 2-arg base
/// ctor cc:44 `BaseCodecModule(CD_ERSPAN2_NAME, CD_ERSPAN2_HELP)`,
/// get_rules override cc:46-:47. This type IS the Rust face of the real
/// `mod_ctor()` cc:102 (the dtor folds onto the stack-owned drop, 18d).
#[derive(Debug)]
pub struct Erspan2Module {
    pub base: BaseCodecModule,
}

impl Erspan2Module {
    /// cc:44 the 2-arg ctor face.
    pub fn new() -> Erspan2Module {
        Erspan2Module { base: BaseCodecModule::new(CD_ERSPAN2_NAME, CD_ERSPAN2_HELP) }
    }

    /// cc:46-:47 `get_rules()` override -> erspan2_rules.
    pub fn get_rules() -> &'static [RuleMap] {
        &ERSPAN2_RULES
    }
}

impl Default for Erspan2Module {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:50-:57 `class Erspan2Codec : public Codec` — TWO overrides
/// (get_protocol_ids / decode). Stack-owned Rust posture (18d); the C
/// `Codec(CD_ERSPAN2_NAME)` ctor name face cc:53 rides the api record.
/// decode's third C param is UNNAMED (`DecodeData&`, cc:74) = the never-
/// read posture (the pgm precedent — ZERO seam struct lands).
#[derive(Default)]
pub struct Erspan2Codec;

impl Erspan2Codec {
    /// cc:53 `Erspan2Codec() : Codec(CD_ERSPAN2_NAME) { }`
    pub fn new() -> Erspan2Codec {
        Erspan2Codec
    }

    /// cc:71-:72 `v.emplace_back(ProtocolId::ETHERTYPE_ERSPAN_TYPE2)` —
    /// vectors_faceA:9 `GETIDS erspan2 35006` DECIMAL (0x88BE, the PYPIN
    // ground-walk face of protocol_ids.h :159).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_ERSPAN_TYPE2); // cc:72
    }

    /// cc:74-:96 out-of-line decode, statement order VERBATIM. TWO event
    /// arms ride the RESIDENT sid family (463 codec_module.rs :221, the
    /// SHARED 462 :220 — NEVER re-walked). EVAL ORDER (the row's var-
    /// first rule + the vectors:13 order-site cite): the lyr_len write
    /// cc:93 lands BEFORE the next_prot_id write cc:94 (the erspan3 mate
    /// flips its pair — next :95 before lyr :96 — the order-site face).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink<'_>) -> bool {
        // cc:76-:77 the ERSpanType2Hdr reinterpret_cast face: the window
        // overlay, NO struct materialization (landed posture).
        // cc:79-:83: `raw.len < sizeof(ERSpanType2Hdr)` (= 8) -> codec_event
        // DECODE_ERSPAN2_DGRAM_LT_HDR (cc:81, vectors:1 `EV 116 463`) +
        // false (vectors:2 `E2 len7 -> 0 lyr=0` — the fail path NEVER
        // touches lyr_len, the return :82 face).
        if raw.len < ERSPAN2_HDR_SIZE {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_ERSPAN2_DGRAM_LT_HDR as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:85-:91 the version gate (var-first: version() lands as a VAR
        // before the compare, the row's EVERY-compound rule). The comment
        // `/* Check that this is in fact ERSpan Type 2. */` cc:85-:86 +
        // `/* Type 2 == version 0x01 */` cc:87 ride verbatim in this cite.
        let version = erspan2_version(raw.data); // cc:87 LHS
        if version != 0x01 {
            // cc:89 the SHARED sid (the (a1) pin, vectors:3 `EV 116 462`:
            // both siblings fire this SAME event EXACTLY-2 across the
            // pair — the parity census).
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_ERSPAN_HDR_VERSION_MISMATCH as u32,
                sink,
            );
            return false;
        }

        codec.lyr_len = ERSPAN2_HDR_SIZE as u16; // cc:93 (LYR BEFORE next — vectors:5 lyr=8)
        codec.next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING; // cc:94 (25944)
        true // cc:95; codec_flags STAYS 0 on this TU's happy arm
              // (vectors:5 flags=0 — the contrast vs the TB mate's 4096)
    }
    // session-id cite (cc:61-:62 ver_vlan low-12 vlan bits + flags_spanId,
    // cc:60-:61 in the mate): cited-NEVER-ported beyond the >>12 version
    // mask — the ONLY extracted field is version() (PLAN §8; the vectors:6
    // cite line; ZERO mask-constant here).

    // NO log, NO encode, NO get_data_link_type overrides (cc:55-:56 the
    // class declares TWO only — the probe's GETDLT ZERO census face).
}

// cc:98-:100 the "api" separator banner rides. cc:102-:106 the REAL mod
// pair (module doc headline: Erspan2Module::new IS the Rust mod_ctor face);
// cc:108-:112 `static Codec* ctor(Module*)` + `static void dtor(Codec*)`
// ride behavior-only cites (record flags = the ctor/dtor SET face; the
// Rust codec face is Erspan2Codec::new).

/// cc:114-:134 `static const CodecApi erspan2_api` — the 1/1 record side:
/// mod_ctor TRUE cc:125 + mod_dtor TRUE cc:126 (the REAL functions cc:102/
/// :105 — the trio's FIRST 1-side mod pair); pinit/pterm/tinit/tterm
/// nullptr cc:128-:131 = false x4; ctor/dtor SET cc:132/:133. name/help
/// slots cc:123/:124 land the cc:29/:30 macro faces.
pub const ERSPAN2_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:117
    size: CDAPI_SIZEOF_CODEC_API, // cc:118 sizeof(CodecApi)=112 (faceA:5)
    api_version: CDAPI_VERSION,   // cc:119 1900547
    version: 0,                   // cc:120
    features: PLUGIN_SO_RELOAD,   // cc:121
    options: API_OPTIONS,         // cc:122
    name: CD_ERSPAN2_NAME,        // cc:123 -> "erspan2"
    help: CD_ERSPAN2_HELP,        // cc:124
    mod_ctor: true,               // cc:125 REAL (the 1/1/0 asymmetry pin)
    mod_dtor: true,               // cc:126 REAL
    pinit: false,                 // cc:128 nullptr
    pterm: false,                 // cc:129 nullptr
    tinit: false,                 // cc:130 nullptr
    tterm: false,                 // cc:131 nullptr
    ctor: true,                   // cc:132 SET
    dtor: true,                   // cc:133 SET
};

/// cc:136-:144 the hidden export (module doc headline): `#ifdef
/// BUILDING_SO` cc:136 / `SO_PUBLIC const BaseApi* snort_plugins[] =`
/// cc:137 / the static-build `const BaseApi* cd_erspan2[] =` cc:139
/// feeding `&erspan2_api.base` cc:142 + nullptr cc:143. nm table symbol
/// EXACTLY-1 (the harness face, PLAN §1). Table name == file base == NAME
/// (TRUE x3 — the trio's drift name lives in the trans_bridge mate).
/// Ladder entry "cd_erspan2" RESIDENT codec_api.rs:103 NEVER re-touched
/// (load codec_api.cc :90, extern :45).
pub const CD_ERSPAN2: CodecTable = &[&ERSPAN2_API];
