//! Port of `src/codecs/ip/cd_pgm.cc` (211 L) — row 18h (the small four,
//! `tools/small4_harness`, ZERO-gate probe-only row).
//! Ground: snort3-src @ fe29cbe, md5 `6b476f5cec30acdfc6fe172bed53b657`
//! wc 211 (small4 build.sh :36-:41 every build). DIR FACT: `codecs/ip/`;
//! includes the four resident headers PLUS same-dir `checksum.h`
//! (cc:28) — pgm is the SECOND rider of the checksum residency the gre
//! row paid first (stripped-tree flipped-assert: drop checksum.h -> ONLY
//! cd_pgm dies, `E4_nochecksum_pgm.txt`; copy md5 b43628f3 re-pinned
//! every build).
//!
//! THE CHECKSUM CROSS-CHECK RIDER (the 18g two-way parity face
//! EXTENDED): cc:137 `checksum::cksum_add(raw.data, raw.len)` inside
//! pgm_nak_detect is a SECOND C consumer of the all-inline 18b lib —
//! the Rust row reuses the landed `crate::codecs::checksum::cksum_add`
//! (row 18b), zero new primitives. The expensive-checksum guard
//! (cc:134-:141 comment "checksum is expensive... do that only if the
//! length is bad") is the vectors arm `PGM cksum-guard -> 1` with NO
//! EV: header->checksum != 0 folds nonzero -> PGM_NAK_ERR (cc:139-:140).
//!
//! TRUE NAME holds: file base == table `cd_pgm[]` :206 (REAL
//! BUILDING_SO arms :203-:207, sed-pins build.sh), extern cd_pgm
//! codec_api.cc :63 + load :108, ladder resident codec_api.rs:121
//! (NEVER re-touched).
//!
//! THE ALWAYS-TRUE DECODE FACE: cc:153-:158 — pgm_nak_detect's tri-state
//! (statics PGM_NAK_ERR/OK/VULN cc:61-:63, the ONLY event site cc:156
//! fires on VULN) and decode returns TRUE UNCONDITIONALLY (vectors
//! `PGM len44 -> 1` even on the ERR arms). The statics are
//! file-scope internals (R3: not exported, invisible to the nm global
//! census) — the Rust arms land as the same tri-state consts here.
//!
//! PGM struct trio cc:65-:104: PGM_NAK_OPT / PGM_NAK / PgmHeader —
//! transcribed as byte-offset reads over raw.data, NOT repr(C) structs:
//! the decode touches exactly FIVE offsets — header->type @4 (cc:120),
//! header->nak.opt.type @36 (cc:123), header->nak.opt.len @37 (cc:132),
//! header->checksum @6-7 (cc:135, memcmp-face != 0) — and sizeof-
//! dependent face `raw.len <= sizeof(PgmHeader)` = 44 (cc:112, the
//! layout sums 4+4+2+8+2+24 = 44, grep-pinned by the probe arm
//! `PGM len44 -> 1`). The cppcheck-suppress members stay unread (the
//! probe never pokes them, R3).
//!
//! sids resident, zero new: DECODE_PGM_NAK_OVERFLOW h:207 -> 454
//! (codec_module.rs:212). vectors:19 `EV 116 454` + :20 `PGM nak-vuln
//! -> 1` (the ONLY pgm event site) + :15 rules census
//! `PGMRULES 1 sid0=454 name=pgm` + :14 `PGMPID 113 n=1`.

use crate::codecs::checksum::cksum_add;
use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecTable, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData,
    PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData, protocol_id,
};

/// cc:34 `#define CD_PGM_NAME "pgm"`
pub const CD_PGM_NAME: &str = "pgm";
/// cc:35 `#define CD_PGM_HELP "support for pragmatic general multicast"`
/// — FACE-A HELP line (ground define sed-pinned in build.sh).
pub const CD_PGM_HELP: &str = "support for pragmatic general multicast";

/// cc:61-:63 the pgm_nak_detect tri-state (`PGM_NAK_ERR = -1`,
/// `PGM_NAK_OK = 0`, `PGM_NAK_VULN = 1`).
pub const PGM_NAK_ERR: i32 = -1;
pub const PGM_NAK_OK: i32 = 0;
pub const PGM_NAK_VULN: i32 = 1;

/// sizeof(PgmHeader) face (cc:112 `raw.len <= sizeof(PgmHeader)`, 44):
/// ports 4 + type/opt 2 + checksum 2 + gsd 6 + length 2 + PGM_NAK 28
/// (nak 24 + PGM_NAK_OPT 8). Kept as the cc:94-:104 layout cite, never
/// a size_of call (the probe arm `PGM len44 -> 1` is the pin).
pub const PGM_HEADER_SIZE: u32 = 44;

/// cc:37-:41 `static const RuleMap pgm_rules[]` — ONE entry + the
/// terminator (the 1-entry ground census is build.sh-side). vectors:15
/// `PGMRULES 1 sid0=454 name=pgm`.
pub const PGM_RULES: [RuleMap; 2] = [
    RuleMap {
        sid: CodecSid::DECODE_PGM_NAK_OVERFLOW as u32, // 454 (h:207)
        msg: Some("PGM nak list overflow attempt"), // cc:39 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:40 terminator
];

/// cc:43-:50 `class PgmModule : public BaseCodecModule` — the TWO-arg
/// ctor (NO params table: `BaseCodecModule(CD_PGM_NAME, CD_PGM_HELP)`
/// cc:46) + get_rules() override cc:48-:49.
#[derive(Debug)]
pub struct PgmModule {
    pub base: BaseCodecModule,
}

impl PgmModule {
    pub fn new() -> PgmModule {
        PgmModule {
            base: BaseCodecModule::new(CD_PGM_NAME, CD_PGM_HELP), // cc:46 2-arg arm
        }
    }

    pub fn get_rules() -> &'static [RuleMap] {
        &PGM_RULES
    }
}

impl Default for PgmModule {
    fn default() -> Self {
        Self::new()
    }
}

/// cc:107-:147 `static inline int pgm_nak_detect(const RawData& raw)` —
/// ground comment cc:107 "This PGM NAK function started off as an SO
/// rule, sid 8351." rides the port. The five field reads ride the
/// header-offset map above; the checksum arm calls the LANDED 18b
/// `checksum::cksum_add` (cc:137 — the two-way parity face).
pub fn pgm_nak_detect(raw: &RawData<'_>) -> i32 {
    // cc:110-:115: "request must be bigger than 44 bytes to cause vuln,
    // and length must be divisible by 4" -> ERR. `or` == Rust `||`
    // (cc:112 digraph kept). vectors:16-:17 `PGM len44 -> 1` /
    // `PGM len45 -> 1` (decode true, NO EV — the ERR face).
    if raw.len <= PGM_HEADER_SIZE || (raw.len & 0x03) != 0 {
        return PGM_NAK_ERR;
    }

    // cc:120-:121 header->type @4 (cc:98) != 8 -> ERR. vectors:18
    // `PGM type9 -> 1` (p[4]=9).
    if *raw.data.get(4).unwrap_or(&0) != 8 {
        return PGM_NAK_ERR;
    }

    // cc:123-:124 header->nak.opt.type @36 (the PGM_NAK at @20, opt at
    // @36; PGM_NAK_OPT::type cc:67 `02 = vuln`) != 2 -> ERR.
    if *raw.data.get(36).unwrap_or(&0) != 2 {
        return PGM_NAK_ERR;
    }

    // cc:130-:132: data_left = raw.len - 36 (>0 — the len>44 guard ran);
    // opt.len @37 (cc:68).
    let data_left: u32 = raw.len - 36;
    if data_left > (*raw.data.get(37).unwrap_or(&0) as u32) {
        // cc:134-:141 the cheap guard: header->checksum (bytes 6-7,
        // cc:100) == 0 skips the cksum (the nak-vuln vectors arm);
        // nonzero -> cksum_add MUST be nonzero -> ERR (the cksum-guard
        // face: fold of 0x01 + 0x08... != 0 -> NO EV). The .get posture
        // mirrors the post-guard C read (raw.len > 44 => in-bounds).
        if *raw.data.get(6).unwrap_or(&0) != 0 || *raw.data.get(7).unwrap_or(&0) != 0 {
            // cc:137 checksum::cksum_add(raw.data, raw.len) — the 18b
            // landed face (buf.len==raw.len at every probe arm).
            let checksum = cksum_add(raw.data, raw.len as usize);
            if checksum != 0 {
                return PGM_NAK_ERR; // cc:139-:140
            }
        }
        return PGM_NAK_VULN; // cc:143 -> the ONLY EV (cc:156, sid 454)
    }

    PGM_NAK_OK // cc:146 (the optlen-ok vectors arm: opt.len 200)
}

#[derive(Default)]
pub struct PgmCodec;

impl PgmCodec {
    /// cc:55 `PgmCodec() : Codec(CD_PGM_NAME) { }`
    pub fn new() -> PgmCodec {
        PgmCodec
    }

    /// cc:160-:163 out-of-line def — vectors:14 `PGMPID 113 n=1`
    /// (ProtocolId::PGM = 113, protocol_ids.h grep-pin in build.sh).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::PGM); // cc:162
    }

    /// cc:153-:158 out-of-line decode: the tri-state gates the ONLY
    /// event; `return true` UNCONDITIONAL (module doc). The
    /// `DecodeData&` operand is UNNAMED in ground (cc:153 trailing `)`)
    /// — never read: the 18g/18c unnamed-param posture, NO seam param.
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink) -> bool {
        if pgm_nak_detect(raw) == PGM_NAK_VULN {
            crate::framework::codec::codec_event(codec, PGM_NAK_OVERFLOW_SID, sink); // cc:156
        }
        true // cc:157 — every arm decodes "successfully"
    }
}

/// resident sid (codec_module.rs:212 `DECODE_PGM_NAK_OVERFLOW = 454  // h:207`)
const PGM_NAK_OVERFLOW_SID: u32 = CodecSid::DECODE_PGM_NAK_OVERFLOW as u32;

// cc:169-:179 static mod_ctor/mod_dtor + ctor/dtor — ALL FOUR slots
// live at pgm (vectors_faceA `pgm mod_ctor=1 mod_dtor=1`).

/// cc:181-:201 `static const CodecApi pgm_api`.
pub const PGM_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:184
    size: CDAPI_SIZEOF_CODEC_API, // cc:185 (112 probe pin)
    api_version: CDAPI_VERSION, // cc:186 (1900547)
    version: 0,      // cc:187
    features: PLUGIN_SO_RELOAD, // cc:188
    options: API_OPTIONS, // cc:189
    name: CD_PGM_NAME, // cc:190
    help: CD_PGM_HELP, // cc:191
    mod_ctor: true,  // cc:192 SET
    mod_dtor: true,  // cc:193 SET
    pinit: false,    // cc:195
    pterm: false,    // cc:196
    tinit: false,    // cc:197
    tterm: false,    // cc:198
    ctor: true,      // cc:199
    dtor: true,      // cc:200
};

/// cc:203-:211 the export — REAL BUILDING_SO arms (:203-:207 sed-pins),
/// table `cd_pgm[]` at :206.
pub const CD_PGM: CodecTable = &[&PGM_API];
