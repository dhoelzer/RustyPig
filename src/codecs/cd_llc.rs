//! Port of `src/codecs/misc/cd_llc.cc` (198 L) — row 18k, the codecs/misc
//! LEFTOVER TRIO half one (`tools/misc3_harness`, ZERO-gate probe-only, the
//! 18th straight honest face). Ground: snort3-src @ fe29cbe, md5
//! `df63cf75b1bf7642ca80b6a215a0f28c` wc 198 (the 198+133+167 = 498 SUM
//! re-measured and asserted EVERY build by tools/misc3_harness/build.sh).
//! DIR FACT: `codecs/misc/` — this half + the mates CLOSE the misc tail
//! (ls misc/ after 18k = the 6 landed .cc + test/ only).
//!
//! THE REAL-MODULE FACE (the trio's asymmetry headline, census 1/0/0): llc
//! is the ONLY trio TU with a REAL module — `class LlcModule : public
//! BaseCodecModule` cc:42-:49 (2-arg base ctor cc:45, get_rules override
//! cc:47-:48) + `static Module* mod_ctor()` cc:156-:157 / `static void
//! mod_dtor(Module*)` cc:159-:160 feeding the BaseApi slots cc:179/:180.
//! FACE-A MEASURED the asymmetry through the tables: `llc mod_ctor=1
//! mod_dtor=1` (vectors_faceA:7) vs `vxlan mod_ctor=0` (vxlan nullptr pair
//! :113/:114) and `user mod_ctor=0` (EXPLICIT `nullptr,  // mod_ctor`
//! comments cc:147/:148) — contrast daq3's uniform 1/1/1 + miscip's 0/0.
//! The Rust mod_ctor face is `LlcModule::new` (the landed UdpModule::new
//! 18i posture: C++ heap `new LlcModule` folds onto stack-owned Rust);
//! the record carries mod_ctor/mod_dtor TRUE (the harness + FACE-A pin).
//!
//! THE HIDDEN-TABLE FACE (the trio census, PLAN §1): the export rides
//! `#ifdef BUILDING_SO` cc:190-:197 — SO arm cc:191, the REAL static arm
//! `const BaseApi* cd_llc[] =` cc:193 feeds `&llc_api.base` cc:196; nm
//! table symbol EXACTLY-1 (the STATIC arm IS the harness face). The Rust
//! face = landed-row pattern (ZERO no_mangle attribute sites in src,
//! grep-verified): doc-cite + `pub const CD_LLC: CodecTable`. TRUE NAME
//! holds: file base ==
//! table base == NAME "llc" (cc:30 macro, sed-pinned by build.sh every
//! build); ladder entry "cd_llc" RESIDENT codec_api.rs :117 (extern
//! codec_api.cc :59, load :104) NEVER re-touched.
//!
//! REUSE cites (PLAN §3, ZERO new vocab where landed): sids
//! DECODE_BAD_LLC_HEADER 131 / DECODE_BAD_LLC_OTHER 132 ALREADY landed
//! codec_module.rs :97-:98 (codec_module.h :80-:81) — NEVER re-walked, the
//! import face; ETHERNET_LLC 0x0107 IMPORTED from the landed framework
//! protocol_id (codec.rs :167-:169, protocol_ids.h :134, vectors:9 DEC 263
//! GETIDS face); CODEC_ETHER_NEXT 0x1000 IMPORTED (codec.rs :54). The llc
//! RuleMap 2 rows + terminator cc:35-:39 are the trio's ONLY rule table
//! (vxlan/user RuleMap 0/0) — `rule_count` reuse (18d shape).
//!
//! THE SIX DEAD DEFINES (the ground's own dead-code face, harness census
//! grep-count 1 x6 EVERY build): the four DSAP/SSAP SNA+STP #defines
//! 0x08/0x00/0x42/0x42 at cc:80-:83 + the two ETH_ORG_CODE_* #defines
//! 0x000000/0x00000c at cc:87/:88 — ZERO use sites ANYWHERE (the SNAP org
//! gate rides LITERAL 0 :117-:119; the two USED names ETH_DSAP_IP/ETH_SSA
//! P_IP :84/:85 ride :105/:106 + :139/:140). Six names transcribe cite-
//! NEVER-land — the tokens NEVER land ANYWHERE in this file, symbol OR
//! comment (the 18i forbidden-token prose discipline: the build.sh PYPIN
//! re-asserts token-zero Rust-side; the cd_gre dead-init discipline); the
//! two used names land as consts.
//!
//! FIXIT-L pins that ride: cc:98 `// FIXIT-L need a better alert for llc
//! len` (the vectors:2 short2 arm raises the bare 131).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CODEC_ETHER_NEXT, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord,
    CodecData, CodecTable, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData, protocol_id,
};

/// cc:30 `#define LLC_NAME "llc"` — TRUE-NAME side (module doc).
pub const LLC_NAME: &str = "llc";
/// cc:31 `#define LLC_HELP "support for logical link control"` (vectors_faceA:6).
pub const LLC_HELP: &str = "support for logical link control";

/// cc:84 `#define ETH_DSAP_IP  0xaa` — USED :105 + :139 (grep-count 3 with
/// the #define; the harness asserts 3 EVERY build).
pub const ETH_DSAP_IP: u8 = 0xaa;
/// cc:85 `#define ETH_SSAP_IP  0xaa` — USED :106 + :140.
pub const ETH_SSAP_IP: u8 = 0xaa;

// THE SIX DEAD DEFINES — cite-NEVER-land (module doc census; ZERO tokens
// here, ZERO Rust symbols): the four DSAP/SSAP SNA + STP #defines (0x08 /
// 0x00 / 0x42 / 0x42, cc:80-:83) + the two ETH_ORG_CODE #defines (0x000000
// encapsulated-ethernet / 0x00000c cisco-discovery, cc:87/:88). The SNAP
// org arms read LITERAL zero bytes (cc:117-:119), NOT these names; the
// build.sh PYPIN re-asserts the token-zero face Rust-side EVERY build.

/// cc:61-:66 `struct EthLlc` — three u8 fields: dsap @0 / ssap @1 / ctrl
/// @2 (sizeof 3 = the cc:96 outer gate `raw.len < sizeof(EthLlc)` face —
/// vectors:2 short2 2<3, vectors:3 len 3 PASSES the outer gate). The Rust
/// port reads the SAME window offsets (the landed reinterpret_cast face,
/// cd_gre gre.h posture) — no struct materialization needed.
pub const ETH_LLC_SIZE: u32 = 3;
/// cc:68-:78 `struct EthLlcOther` — org_code[3] @3..5 (window offsets past
/// EthLlc) + proto_id[2] @6..7 (sizeof 5). The cc:108 inner gate is
/// `raw.len < sizeof(EthLlc) + sizeof(EthLlcOther)` = 8; the cc:121
/// lyr_len write is the SAME 3+5 sum.
pub const ETH_LLC_OTHER_SIZE: u32 = 5;

/// cc:73-:77 `EthLlcOther::proto()` — `(proto_id[0] << 8) | proto_id[1]`
/// big-endian over the WINDOW bytes @6..7 (the cc:122 next_prot_id write;
/// vectors:6 next=2048 = the 0x0800 fixture, vectors_faceA never prints
/// this face).
#[inline]
pub fn eth_llc_other_proto(raw: &[u8]) -> ProtocolId {
    (u16::from(raw[6]) << 8) | u16::from(raw[7])
}

/// cc:35-:40 `static const RuleMap llc_rules[]` — the trio's ONLY rule
/// table, TWO data rows + terminator (residual whitespace face kept: cc:38
/// `"bad extra LLC info"},` closes without the space). sids REUSE the
/// landed CodecSid enum (codec_module.rs :97-:98, codec_module.h :80-:81 —
/// ZERO new constants).
pub const LLC_RULES: [RuleMap; 3] = [
    RuleMap { sid: CodecSid::DECODE_BAD_LLC_HEADER as u32, msg: Some("bad LLC header") }, // cc:37
    RuleMap { sid: CodecSid::DECODE_BAD_LLC_OTHER as u32, msg: Some("bad extra LLC info") }, // cc:38
    RuleMap { sid: 0, msg: None }, // cc:39 `{ 0, nullptr }`
];

/// cc:42-:49 `class LlcModule : public BaseCodecModule` — the trio's ONLY
/// real module (module doc headline). The 2-arg base ctor cc:45
/// `BaseCodecModule(LLC_NAME, LLC_HELP)` lands as the landed
/// BaseCodecModule::new(s, h) face (codec_module.rs, C params slot
/// untouched); get_rules cc:47-:48 -> LLC_RULES. This type IS the Rust
/// face of the real `mod_ctor()` cc:156 (18i UdpModule::new posture).
#[derive(Debug)]
pub struct LlcModule {
    pub base: BaseCodecModule,
}

impl LlcModule {
    /// cc:45 the 2-arg ctor face.
    pub fn new() -> LlcModule {
        LlcModule { base: BaseCodecModule::new(LLC_NAME, LLC_HELP) }
    }

    /// cc:47-:48 `get_rules()` override -> llc_rules.
    pub fn get_rules() -> &'static [RuleMap] {
        &LLC_RULES
    }
}

impl Default for LlcModule {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:51-:59 `class LlcCodec : public Codec` — THREE overrides
/// (decode / log / get_protocol_ids). Rust posture: stack-owned codec
/// (18d rule); the C `Codec(LLC_NAME)` ctor name face cc:54 rides the
/// api record. decode's third C param is UNNAMED (`DecodeData&`, cc:94) =
/// the never-read posture (the pgm precedent — ZERO seam struct lands).
#[derive(Default)]
pub struct LlcCodec;

impl LlcCodec {
    /// cc:54 `LlcCodec() : Codec(LLC_NAME) { }`
    pub fn new() -> LlcCodec {
        LlcCodec
    }

    /// cc:91-:92 `v.emplace_back(ProtocolId::ETHERNET_LLC)` — the landed
    /// protocol_id IMPORT face (framework/codec.rs :167-:169,
    /// protocol_ids.h :134); vectors_faceA:9 GETIDS llc 263 DECIMAL.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::ETHERNET_LLC); // cc:92
    }

    /// cc:94-:128 out-of-line decode, statement order VERBATIM. TWO event
    /// arms ride the RESIDENT sid family (131 codec_module.rs :97, 132
    /// :98 — NEVER re-walked). EVAL ORDER (harness §8 pin): the cc:105-
    /// :106 dsap&&ssap AND-pair evaluates FIRST (probe arm vectors:3
    /// aa/00: operand 1 FALSE -> NO event, NO SNAP, decode TRUE); the
    /// inner len gate rides INSIDE the pair (7<8 fires 132, vectors:4/:5).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink<'_>) -> bool {
        // cc:96-:101: `raw.len < sizeof(EthLlc)` (= 3) -> codec_event
        // DECODE_BAD_LLC_HEADER (cc:99, the FIXIT-L cc:98 pin; the
        // "better alert" is a GROUND debt, cite-never-fix) + false.
        // vectors:1/:2 `EV 116 131` / `LLC short2 -> 0`.
        if raw.len < ETH_LLC_SIZE {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_BAD_LLC_HEADER as u32,
                &mut *sink,
            );
            return false;
        }

        // cc:103 the EthLlc reinterpret_cast face: window reads @0/@1.
        let dsap = raw.data[0];
        let ssap = raw.data[1];

        // cc:105-:106 the AND-pair — var-first discipline (R6): both
        // operands land as vars BEFORE the join (the dsap-aa-ssap-00 arm
        // vectors:3 proves the FIRST-operand FALSE short, eval-order cite).
        let dsap_hit = dsap == ETH_DSAP_IP; // cc:105
        let ssap_hit = ssap == ETH_SSAP_IP; // cc:106
        if dsap_hit && ssap_hit {
            // cc:108-:112 the inner gate: raw.len < 3+5 -> codec_event
            // DECODE_BAD_LLC_OTHER (cc:110) + false (vectors:4/:5 snap7).
            if raw.len < ETH_LLC_SIZE + ETH_LLC_OTHER_SIZE {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_BAD_LLC_OTHER as u32,
                    sink,
                );
                return false;
            }

            // cc:114-:115 the EthLlcOther reinterpret_cast face: org_code
            // window @3..5 (the `raw.data + sizeof(EthLlc)` pointer write).
            let g0 = raw.data[3] == 0; // cc:117 (literal-zero org gate, var-first)
            let g1 = raw.data[4] == 0; // cc:118
            let g2 = raw.data[5] == 0; // cc:119
            if g0 && g1 && g2 {
                // cc:121-:123 the SNAP happy arm (vectors:6): lyr 3+5,
                // next = EthLlcOther::proto() (@6..7 BE), ETHER_NEXT flag.
                codec.lyr_len = (ETH_LLC_SIZE + ETH_LLC_OTHER_SIZE) as u16; // cc:121
                codec.next_prot_id = eth_llc_other_proto(raw.data); // cc:122
                codec.codec_flags |= CODEC_ETHER_NEXT;              // cc:123
            }
            // org-gate FALSE face (cc:117-:119 fail): TRUE with lyr 0 —
            // vectors:7 snap-org-nonzero (the 0x0c CDP fixture byte rides
            // the harness, NOT the dead cisco-discovery org-code define).
        }

        true // cc:127
    }

    /// cc:130-:149 out-of-line log (ported-by-reading, cite-never-
    /// vectorized: the probes NEVER call log — ZERO log lines in either
    /// vectors file). The `/*lyr_len*/` unnamed third param face kept.
    /// TextLog_Print seam = the landed String-sink closure (cd_eth:187
    /// shape); the `%X`/`%02X`/`%04X` spec map is verbatim.
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8], _lyr_len: u16) {
        // cc:135-:136 `DSAP:0x%X SSAP:0x%X CTRL:0x%X` (uint8 promotions).
        sink(format!(
            "DSAP:0x{:X} SSAP:0x{:X} CTRL:0x{:X}",
            raw_pkt[0], raw_pkt[1], raw_pkt[2]
        ));

        // cc:138-:148 "Assuming that if these three conditions are met,
        // this is SNAP." (the ground comment rides; SAME pair test again
        // :139-:140 — the log-side re-read of the window).
        if raw_pkt[0] == ETH_DSAP_IP && raw_pkt[1] == ETH_SSAP_IP {
            // cc:145-:147 `" ORG:0x%02X%02X%02X PROTO:0x%04X"` with the
            // org bytes @3..5 + static_cast<uint16_t>(proto()) @6..7.
            sink(format!(
                " ORG:0x{:02X}{:02X}{:02X} PROTO:0x{:04X}",
                raw_pkt[3],
                raw_pkt[4],
                raw_pkt[5],
                eth_llc_other_proto(raw_pkt) as u16
            ));
        }
    }
}

// cc:151-:153 the "api" separator banner rides. cc:156-:160 the REAL mod
// pair (module doc headline: LlcModule::new IS the Rust mod_ctor face, the
// dtor folds onto the stack-owned drop, 18d posture); cc:162-:166 `static
// Codec* ctor(Module*)` + `static void dtor(Codec*)` ride behavior-only
// cites (record flags = the ctor/dtor SET face; the Rust codec face is
// LlcCodec::new).

/// cc:168-:188 `static const CodecApi llc_api` — THE asymmetry record:
/// mod_ctor TRUE cc:179 + mod_dtor TRUE cc:180 (the REAL functions cc:156/
/// :159 — the trio's only 1-side mod pair, vectors_faceA:7 `mod_ctor=1
/// mod_dtor=1`); pinit/pterm/tinit/tterm nullptr (:182-:185) = false x4;
/// ctor/dtor SET (:186-:187).
pub const LLC_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:171
    size: CDAPI_SIZEOF_CODEC_API, // cc:172 sizeof(CodecApi)=112 (faceA:5)
    api_version: CDAPI_VERSION,   // cc:173 1900547
    version: 0,                   // cc:174
    features: PLUGIN_SO_RELOAD,   // cc:175
    options: API_OPTIONS,         // cc:176
    name: LLC_NAME,               // cc:177 -> "llc"
    help: LLC_HELP,               // cc:178
    mod_ctor: true,               // cc:179 REAL (the 1/0/0 asymmetry pin)
    mod_dtor: true,               // cc:180 REAL
    pinit: false,                 // cc:182 nullptr
    pterm: false,                 // cc:183 nullptr
    tinit: false,                 // cc:184 nullptr
    tterm: false,                 // cc:185 nullptr
    ctor: true,                   // cc:186 SET
    dtor: true,                   // cc:187 SET
};

/// cc:190-:198 the hidden export (module doc headline): `#ifdef
/// BUILDING_SO` cc:190 / `SO_PUBLIC const BaseApi* snort_plugins[] =`
/// cc:191 / the static-build `const BaseApi* cd_llc[] =` cc:193 feeding
/// `&llc_api.base` cc:196 + nullptr cc:197. nm table symbol EXACTLY-1
/// (the harness face, PLAN §1). Table name == file base == NAME (TRUE x3,
/// no drift face). Ladder entry "cd_llc" RESIDENT codec_api.rs :117 NEVER
/// re-touched (load codec_api.cc :104, extern :59).
pub const CD_LLC: CodecTable = &[&LLC_API];
