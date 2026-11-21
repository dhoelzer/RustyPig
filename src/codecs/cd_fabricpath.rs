//! Port of `src/codecs/link/cd_fabricpath.cc` (187 L) — row 18n, the
//! codecs/link chapter-tail vlan TRIO half three (the FREE-RIDE member:
//! ZERO fresh cps — the PRE-CP `-fsyntax-only` rc0 on the donor tree ALONE
//! IS its closure face, receipt E_pre_cd_fabricpath.txt EMPTY, VERIFIED
//! MEASURED PLAN §1; the leanest include face of the trio: :24 codec_module.h
//! with :25 framework/codec.h ONLY — the E4 text_log-strip arm KILLS vlan +
//! cisco while this TU SURVIVES, every build). Ground: snort3-src @ fe29cbe,
//! md5 `f3fee8d9caf01be7686c9d1907e8f18b` wc 187 (the 236+235+187 = 658 SUM
//! asserted EVERY build by tools/link4_harness/build.sh; THIS landing file
//! is cd_fabricpath.rs). DIR FACT:
//! `codecs/link/`. Trio mates: cd_vlan.rs (graft-v3 headline) +
//! cd_ciscometadata.rs (the 468-471 ladder).
//!
//! THE ZERO-machinery RIDE (the §7 cost table face): no daq.h, no protocol
//! header, no text_log — TWO resident includes. nm_U 21 = the 18m §1 face
//! EXACT re-pin; tunnel-U 0 (the bypass hook NEVER crosses here — that seam
//! lives at the deferred-TU hook cite :205-:206 (q4 row). NO graft token of
//! ANY kind lands in this TU (the graft rides the vlan member ONLY).
//!
//! THE R6 ORDER-CLONE face (the vectors' F pair): the happy arm writes
//! `codec.next_prot_id = ProtocolId::ETHERNET_802_3` :84 BEFORE `codec.lyr_len
//! = FABRICPATH_HEADER_LEN` :85 — MEASURED both lines (probe_dec.cc's print
//! order `F len16 -> 1 next=261 lyr=16`); the cite line `F order-site
//! next:84-before-lyr:85 cite` pins the order-site (the cd_no_next/erspan3
//! NEXT-FIRST lineage clone — the trio's ONLY order-site besides the vlan
//! ext pair and the cisco ladder chain).
//!
//! TRUE-NAME face: the table symbol `const BaseApi* cd_fabricpath[]` :181 ==
//! the FILE base (BUILDING_SO arm :178, feed &fabricpath_api.base :184) —
//! the nm D-face EQUALITY pin rides build.sh (the 18m drift CONTRAST, no
//! refusal greps needed). Ladder entry "cd_fabricpath" RESIDENT
//! codec_api.rs:107 (ground extern codec_api.cc :49, load :94) NEVER
//! re-walked; THIS row TURNS it loaded. mod arms ALL REAL (PLAN §8 the
//! nullptr-free tail face): mod_ctor :144 / mod_dtor :147 -> api arms
//! :167/:168 => faceA `fabricpath mod_ctor=1 mod_dtor=1`; CodecApi ctor :150
//! / dtor :153 SET (faceA `ctor=1 dtor=1`) — the ctor(:150) DISCARDS its
//! Module* (:150 `ctor(Module*)`) = never-read (the ciscometadata twin face).
//!
//! GETIDS :73-:74 = ONE emplace, ETHERTYPE_FPATH (protocol_ids.h :160
//! 0x8903 = 35075 — framework const ALREADY landed at codec face
//! `protocol_id::ETHERTYPE_FPATH`, NEVER re-authored) => faceA `GETIDS
//! fabricpath 35075`. sids: DECODE_FPATH_HDR_TRUNC = 467 RESIDENT
//! codec_module.rs :225 — NEVER re-walked, ZERO new consts (the sids_tokens
//! census: 2 tokens / 1 distinct). RuleMap :34-:38 ONE row + terminator,
//! msg byte-exact. The deferred-TU NEVER-land law: this file carries ZERO
//! hook token ANYWHERE (the q4 deferred-row law; the negative census rides
//! the parity test — grep-0 BOTH the Rust trio AND the probes).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData,
    CodecTable, ENC_FLAG_RAW, EncState, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::protocol_id;

/// :29 `#define CD_FABRICPATH_NAME "fabricpath"` (faceA LOAD/API/HELP name).
pub const CD_FABRICPATH_NAME: &str = "fabricpath";
/// :30 `#define CD_FABRICPATH_HELP "support for fabricpath"` (faceA HELP
/// line verbatim).
pub const CD_FABRICPATH_HELP: &str = "support for fabricpath";

/// :70 `constexpr uint8_t FABRICPATH_HEADER_LEN = 16;` — the :78 len gate
/// (`F len15` dies / `F len16` lands) AND the :85 lyr write AND the :105
/// encode allocate. Ground sed-verbatim pin rides build.sh.
pub const FABRICPATH_HEADER_LEN: u16 = 16;

/// :34-:38 `static const RuleMap fabricpath_rules[]` — ONE data row +
/// terminator; sid RESIDENT DECODE_FPATH_HDR_TRUNC = 467 (codec_module.rs
/// :225, h:220, NEVER re-walked), msg byte-exact.
pub const FABRICPATH_RULES: [RuleMap; 2] = [
    RuleMap { sid: CodecSid::DECODE_FPATH_HDR_TRUNC as u32, msg: Some("truncated FabricPath header") }, // :36
    RuleMap { sid: 0, msg: None }, // :37 `{ 0, nullptr }`
];

/// :40-:47 `class FabricPathModule : public BaseCodecModule` — the :43 TWO-
/// arg ctor face (NO params table — the BaseCodecModule::new 2-arg arm, the
/// params slot stays None: this module has NO Parameter table at all, the
/// trio's leanest module face) + :45-:46 get_rules override. NO set().
#[derive(Debug)]
pub struct FabricPathModule {
    pub base: BaseCodecModule,
}

impl FabricPathModule {
    /// :43 `FabricPathModule() : BaseCodecModule(CD_FABRICPATH_NAME,
    /// CD_FABRICPATH_HELP) { }` — the 2-arg arm (params slot untouched,
    /// C Module ctor leaves it null — the landed codec_module.rs:307 face).
    pub fn new() -> FabricPathModule {
        FabricPathModule {
            base: BaseCodecModule::new(CD_FABRICPATH_NAME, CD_FABRICPATH_HELP),
        }
    }

    /// :45-:46 the get_rules override -> the stored table.
    pub fn get_rules(&self) -> &'static [RuleMap] {
        &FABRICPATH_RULES
    }
}

impl Default for FabricPathModule {
    fn default() -> Self {
        Self::new()
    }
}

/// :61-:68 `struct FPathHdr` — the wire layout: fpath_dst[6] :63,
/// fpath_src[6] :64, fpath_type u16 :65, fptag_extra u16 :67 (`/* 10-bit
/// FTag + 6-bit TTL */`, the cppcheck-suppress :66 rides — face-only member,
/// ZERO read anywhere in the TU). Byte offsets: dst @0..6, src @6..12,
/// type @12..14, tag @14..16 (sizeof == 16 == FABRICPATH_HEADER_LEN).
/// Rust-side, the encode/format arms ride BYTE-SLICE windows over the
/// 16-byte header (the cd_eth overlay posture) — no struct fork needed;
/// the offsets land at every use-site cite below.
pub struct FPathHdr; // presence pin only — the field layout rides the
                     // slice windows at the :111-:120 / :131-:136 sites.
pub const FPATH_DST_OFF: usize = 0;   // :63 fpath_dst[6]
pub const FPATH_SRC_OFF: usize = 6;   // :64 fpath_src[6]
pub const FPATH_TYPE_OFF: usize = 12; // :65 fpath_type (u16)
pub const FPATH_TAG_OFF: usize = 14;  // :67 fptag_extra (unusedStructMember)

/// :49-:59 `class FabricPathCodec : public Codec` — get_protocol_ids :54 /
/// decode :55 / encode :56-:57 / format :58 overrides + the
/// `Codec(CD_FABRICPATH_NAME)` ctor face :52. NO log override (the leanest
/// trio face). Stack-owned Rust posture (18d).
#[derive(Default)]
pub struct FabricPathCodec;

impl FabricPathCodec {
    /// :52 the base-ctor name face.
    pub fn new() -> FabricPathCodec {
        FabricPathCodec
    }

    /// :73-:74 `v.emplace_back(ProtocolId::ETHERTYPE_FPATH)` — faceA `GETIDS
    /// fabricpath 35075` DECIMAL (0x8903, protocol_ids.h :160; the landed
    /// framework const `protocol_id::ETHERTYPE_FPATH` IMPORTED, NEVER
    /// re-authored — the framework-OWNED face).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::ETHERTYPE_FPATH); // :74
    }

    /// :76-:87 out-of-line decode — the soft gate + THE NEXT-FIRST order
    /// clone (module doc). The third C param UNNAMED (:76 `DecodeData&`) =
    /// never-read (the pgm precedent).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink<'_>) -> bool {
        // :78-:82 `raw.len < FABRICPATH_HEADER_LEN` (16) -> codec_event
        // DECODE_FPATH_HDR_TRUNC (:80 — sid 467 RESIDENT) + return false
        // (:81) — the fail path NEVER touches lyr / next (vectors `F len15
        // -> 0 lyr=0`).
        if raw.len < u32::from(FABRICPATH_HEADER_LEN) {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_FPATH_HDR_TRUNC as u32,
                &mut *sink,
            );
            return false; // :81
        }

        // :84 `codec.next_prot_id = ProtocolId::ETHERNET_802_3;` — FIRST
        // (framework import, the landed 261 = 0x0105 face);
        // :85 `codec.lyr_len = FABRICPATH_HEADER_LEN;` — SECOND. THE
        // order-site clone of the NEXT-FIRST lineage (vectors `F order-site
        // next:84-before-lyr:85 cite`; both writes observable in the print
        // `F len16 -> 1 next=261 lyr=16`).
        codec.next_prot_id = protocol_id::ETHERNET_802_3; // :84
        codec.lyr_len = FABRICPATH_HEADER_LEN; // :85
        true // :86
    }

    /// :89-:125 out-of-line encode — cited-NEVER-called (the vectors' `F
    /// encode cc:89-:125 ... cited-never-called` line; Buffer/enc.flags
    /// face), ported-by-reading, statement order VERBATIM: the :92-:93 raw-
    /// ip gate (`bool raw = (enc.flags & ENC_FLAG_RAW)` — VAR first, the
    /// R6 rule), the :95 `if (!raw)` block, the :97-:100 zero-size arm
    /// (`buf.size() == 0` -> `buf.off = 0;  // for alignment` — the landed
    /// Buffer's PUBLIC off field, the C alignment face kept), the :105-:106
    /// allocate-FAILS->`return true` oddity (TRUE on failure — the ground's
    /// honest face, NEVER "fixed"), the :108-:109 in/out overlays, the
    /// :111 fpath_type copy, the :112-:121 forward-vs-reverse src/dst pair
    /// (the forward() face = enc flags & ENC_FLAG_FWD) — FORWARD copies src
    /// ->src dst->dst; REVERSE SWAPS src<->dst), and the :124 `return true`
    /// OUTSIDE everything (the raw-ip and zero-size arms BOTH true too).
    /// The `raw_len` param UNNAMED (:90) = never-read (the allocate size is
    /// the CONSTANT 16 — the honest face vectors-pinned by the cite only);
    /// the `Flow*` UNNAMED (:90) = dropped.
    pub fn encode(
        &self,
        raw_in: &[u8],
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // :92-:93 `bool raw = ( enc.flags & ENC_FLAG_RAW );` — the landed
        // framework const (codec.rs:73) read VAR-first.
        let raw = (enc.flags & ENC_FLAG_RAW) != 0; // :93

        if !raw {
            if buf.size() == 0 {
                // :97-:100 the zero-size arm (`buf.off = 0;  // for
                // alignment` — the comment rides).
                buf.off = 0; // :99
            } else {
                // :103-:104 the ground comment (`outer-most layer when not
                // raw ip` + `any encapsulated ethernet layer`) rides.
                // :105-:106 `if ( !buf.allocate(FABRICPATH_HEADER_LEN) )
                // return true;` — TRUE on allocate failure (honest ground
                // face, vectors cite only, NEVER fixed).
                if !buf.allocate(u32::from(FABRICPATH_HEADER_LEN)) {
                    return true; // :106
                }

                // :108-:109 the FPathHdr overlays (hi read-only over
                // raw_in, ho the fresh allocate head). :111 the TYPE copy:
                // `ho->fpath_type = hi->fpath_type` — u16 @12 (h layout
                // above, the network-order bit-transport face: memcpy-
                // shaped 2 bytes, NO host swap in the ground).
                let head = buf.data_mut().expect("allocate(16) just succeeded");
                head[FPATH_TYPE_OFF..FPATH_TYPE_OFF + 2]
                    .copy_from_slice(&raw_in[FPATH_TYPE_OFF..FPATH_TYPE_OFF + 2]); // :111

                if enc.forward() {
                    // :112-:116 the FORWARD pair: src -> src, dst -> dst.
                    head[FPATH_SRC_OFF..FPATH_SRC_OFF + 6]
                        .copy_from_slice(&raw_in[FPATH_SRC_OFF..FPATH_SRC_OFF + 6]); // :114
                    head[FPATH_DST_OFF..FPATH_DST_OFF + 6]
                        .copy_from_slice(&raw_in[FPATH_DST_OFF..FPATH_DST_OFF + 6]); // :115
                } else {
                    // :117-:121 the REVERSE SWAP pair: hi's DST lands in
                    // ho's SRC, hi's SRC lands in ho's DST.
                    head[FPATH_SRC_OFF..FPATH_SRC_OFF + 6]
                        .copy_from_slice(&raw_in[FPATH_DST_OFF..FPATH_DST_OFF + 6]); // :119
                    head[FPATH_DST_OFF..FPATH_DST_OFF + 6]
                        .copy_from_slice(&raw_in[FPATH_SRC_OFF..FPATH_SRC_OFF + 6]); // :120
                }
            }
        }
        true // :124
    }

    /// :127-:138 out-of-line format — cited-NEVER-called (the vectors' `F
    /// ... F format cc:127-:137 cited-never-called` face; a mut-window
    /// reverse-swap like the landed cd_eth.rs:304 format — the ONLY prior
    /// format face), statement order VERBATIM: the :129 `if (reverse)`
    /// gate, the :131 ch overlay, the :132 `uint8_t tmp_addr[6]` temp, the
    /// :134-:136 THREE-memcpy swap (dst -> tmp -> ... the classic temp
    /// chain, order kept: tmp<-dst, dst<-src, src<-tmp); the third C param
    /// UNNAMED (:127) = never-read (pgm precedent). The fwd (non-reverse)
    /// arm touches NOTHING (the honest zero-write face).
    pub fn format(&self, reverse: bool, raw_pkt: &mut [u8]) {
        if reverse {
            // :132 the temp, :134-:136 the ground's temp-chain order
            // VERBATIM (tmp <- dst; dst <- src; src <- tmp).
            let mut tmp_addr = [0u8; 6]; // :132
            tmp_addr.copy_from_slice(&raw_pkt[FPATH_DST_OFF..FPATH_DST_OFF + 6]); // :134
            // the ground's THREE separate memcpy STATEMENTS need no temp
            // copies; the Rust slice form stages the src read into a stack
            // temp FIRST (the :135 operand value lands BEFORE :136 writes
            // — the three C statements read hi-side only; face-identical,
            // cited, NEVER a re-order of the write targets):
            let src_side = {
                let mut t = [0u8; 6];
                t.copy_from_slice(&raw_pkt[FPATH_SRC_OFF..FPATH_SRC_OFF + 6]); // :135 read
                t
            };
            raw_pkt[FPATH_DST_OFF..FPATH_DST_OFF + 6].copy_from_slice(&src_side); // :135 write
            raw_pkt[FPATH_SRC_OFF..FPATH_SRC_OFF + 6].copy_from_slice(&tmp_addr); // :136 write
        }
    }
}

// :140-:142 the "api" separator banner rides. :144-:145 `static Module*
// mod_ctor() { return new FabricPathModule; }` + :147-:148 `mod_dtor` ride
// behavior-only cites (record mod slots SET — faceA `fabricpath mod_ctor=1
// mod_dtor=1`; the Rust mod face is FabricPathModule::new; dtor folds onto
// the stack-owned drop, 18d posture). :150-:151 `static Codec*
// ctor(Module*)` — the Module* DISCARDED (never-read, the faceA ctor=1
// slot rides); :153-:154 `dtor` SET.

/// :156-:176 `static const CodecApi fabricpath_api` — NAME/HELP slots :165/
/// :166 land the :29/:30 macro faces; mod arms :167/:168 REAL (the mod_ctor
/// :144/mod_dtor :147 pair — trio nullptr-FREE face, contrast 18m NEVER
/// carried); pinit :170 / pterm :171 / tinit :172 / tterm :173 nullptr WITH
/// the ground `// pinit`-style slot comments; ctor :174 (`// ctor`) + dtor
/// :175 (`// dtor`) SET.
pub const FABRICPATH_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // :159
    size: CDAPI_SIZEOF_CODEC_API, // :160 sizeof(CodecApi)=112 (faceA size pin)
    api_version: CDAPI_VERSION,   // :161 1900547
    version: 0,                   // :162
    features: PLUGIN_SO_RELOAD,   // :163
    options: API_OPTIONS,         // :164
    name: CD_FABRICPATH_NAME,     // :165 -> "fabricpath"
    help: CD_FABRICPATH_HELP,     // :166
    mod_ctor: true,               // :167 SET (mod_ctor :144 REAL)
    mod_dtor: true,               // :168 SET (mod_dtor :147 REAL)
    pinit: false,                 // :170 nullptr // pinit
    pterm: false,                 // :171 nullptr // pterm
    tinit: false,                 // :172 nullptr // tinit
    tterm: false,                 // :173 nullptr // tterm
    ctor: true,                   // :174 SET  // ctor
    dtor: true,                   // :175 SET  // dtor
};

/// :178-:186 the hidden export, TRUE-NAME: `#ifdef BUILDING_SO` :178 / SO
/// arm :179 / the static-build `const BaseApi* cd_fabricpath[] =` :181
/// feeding `&fabricpath_api.base` :184 + nullptr :185 (ONE feed — faceA
/// `LOAD fabricpath` + `LOADS 1`). nm: cd_fabricpath D EXACTLY-1 == FILE
/// base (the TRUE-NAME EQUALITY pin — the 18m drift CONTRAST). Ladder entry
/// "cd_fabricpath" RESIDENT codec_api.rs:107 (ground extern codec_api.cc
/// :49, load :94) NEVER re-touched — THIS row TURNS it loaded.
pub const CD_FABRICPATH: CodecTable = &[&FABRICPATH_API];
