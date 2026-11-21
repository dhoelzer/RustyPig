//! Port of `src/codecs/link/cd_ciscometadata.cc` (235 L) — row 18n, the
//! codecs/link chapter-tail vlan TRIO half two (`tools/link4_harness`,
//! ZERO-gate probe-only, 21st straight). Ground: snort3-src @ fe29cbe, md5
//! `8cd594aa2a6576c56ea0136b1b2bdc05` wc 235 (the 236+235+187 = 658 SUM
//! asserted EVERY build by tools/link4_harness/build.sh; THIS landing file
//! is cd_ciscometadata.rs — the TRUE-NAME table face, see below). DIR FACT:
//! `codecs/link/`. Trio mates: cd_vlan.rs (the graft-v3 headline, 236 L
//! md5 fe9747e8...) + cd_fabricpath.rs (the zero-cp free-ride, 187 L md5
//! f3fee8d9...).
//!
//! THE 1-fresh-cp face (PLAN §1, MEASURED — "1 cp NOT 2" §9 verification):
//! :27 protocols/cisco_meta_data.h 43 L md5 f5f66631, the ARPA-ONLY header
//! (:23 `<arpa/inet.h>` its ONLY include — the header-symmetric duo with
//! vlan.h 50 L e68dcca9, PLAN §5's DISAGREEMENT (3) pairing face). The
//! struct `CiscoMetaDataHdr` h:29-:38: version u8 :31, length u8 :32,
//! opt_len_type u16 :33 (`3-bit length + 13-bit type`), sgt u16 :34
//! (`anything but 0xFFFF`), ether_type u16 :35 + sgt_val() ntohs h:37.
//! `sizeof` == **8** (1+1+2+2+2) — the DISK arms len 7/8 ride it
//! (`C len7 -> 0` dies). Post-cp syntax/-c/O2 rc0 x3 receipt E_cisco_cp.txt
//! EMPTY; nm_U 24 = the 18m §1 face EXACT; tunnel-U 0.
//!
//! THE 468-471 LADDER + THE STATS-ONLY SILENT-FAIL FACE (the row's EV
//! story): the decode chain cc:106-:162 fires FOUR sids — ALL RESIDENT
//! codec_module.rs :226-:229 (DECODE_CISCO_META_HDR_TRUNC 468 / OPT_LEN 469
//! / OPT_TYPE 470 / SGT 471; NEVER re-walked, ZERO new consts — the
//! sids_tokens census 8 rows / 4 distinct). BUT the ver/len arms (:116-
//! :120, :122-:126) bump THREAD_LOCAL stats ONLY and `return false` with
//! **NO codec_event** — the silent-fail census: the vectors print `C ver0
//! -> 0 lyr=0` + `C lenf0 -> 0 lyr=0` with NO EV line between (the ladder
//! census: 4 EV lines = 468+469+470+471, NOT six). THE SOFT-EVENT-THEN-
//! CONTINUES face: sgt == 0xFFFF (:149-:153) bumps stats + fires EV 471
//! (:152) then FALLS THROUGH — the inner frame is STILL decoded (ground
//! comment :148 `0xFFFF is a reserved tag, not a framing error`): vectors
//! `C sgtffff -> 1 lyr=8 next=2048 flags=4096 pb=131072` WITH EV 471.
//!
//! THE const ladder cc :93-:98 (sed-pinned build-side ground face):
//! CISCO_META_VALID_HDR_VER 1 / VALID_HDR_LEN 1 / VALID_OPT_LEN 0 /
//! OPT_LEN_SHIFT 13 / OPT_TYPE_SGT 1 / OPT_TYPE_MASK 0x1FFF (`mask
//! opt_len_type to get option type`). eval-order cite `C order-site
//! ver:116-len:122-opt:130-type:141-sgt:149-lyr:155 cite`: the `ntohs(cmdh
//! ->opt_len_type)` reads land in TWO local vars (:130 len >> 13, :131
//! type & MASK) BEFORE the comparisons (the R6 var-first rule EVERY
//! compound). The len/type arms' numeric arms: 0x2001 >> 13 == 1 > 0 ->
//! EV 469; 0x0002 & 0x1FFF == 2 != 1 -> EV 470.
//!
//! THE pegs cite-never-land face (the cd_udp.rs:385-:386 / cd_icmp4.rs:
//! 35-:45 lineage, vectors' cite line `C pegs cc:49-:59 CountType-END:53
//! cited-not-vectorized`): the PegInfo table :45-:54 (SIX SUM pegs + the
//! CountType::END :53 terminator — the 18m §P3 only-per-codec-stats face
//! re-cited), the CiscoMetaDataStats struct :56-:64 + THREAD_LOCAL :65 +
//! the get_pegs :75-:76 / get_counts :78-:79 overrides ALL ride as CITES
//! only — ZERO Rust-side counters land (the vectors NEVER print a count;
//! the six ground stats++ sites :108/:118/:124/:136/:143/:151 carry their
//! cite inside the corresponding arm BELOW).
//!
//! TRUE-NAME face: `const BaseApi* cd_ciscometadata[]` :230 == the FILE
//! base (BUILDING_SO :227, feed &ciscometadata_api.base :233) — the nm
//! D-face EQUALITY pin (the 18m drift CONTRAST). Ladder entry "cd_cisco-
//! metadata" RESIDENT codec_api.rs:101 (ground extern codec_api.cc :43,
//! load :88) NEVER re-walked; THIS row TURNS it loaded. mod arms ALL REAL:
//! mod_ctor :193 / mod_dtor :196 -> arms :216/:217 => faceA `ciscometadata
//! mod_ctor=1 mod_dtor=1`; CodecApi ctor :199 (the Module* DISCARDED —
//! never-read) / dtor :202 SET.
//!
//! GETIDS :101-:102 = ONE emplace, ETHERTYPE_CISCO_META (protocol_ids.h
//! :161 0x8909 = 35081) => faceA `GETIDS ciscometadata 35081`. The id is
//! ROW-SCOPE HOME (MEASURED ZERO prior landed Rust face — the landed dup-
//! not-import family; protocol_ids.h sed cite). C log cc :165-:173 + C
//! encode cc :175-:187 cited-NEVER-called (the format string `"Ver:%hhu
//! SGT:%hu EtherNext:0x%X"` :171 rides — the %hhu/%hu C-printf dialect,
//! unit-mirrored in the parity test); the :189-:191 api banner, ctor/dtor
//! cites land after the codec.

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CODEC_ETHER_NEXT, CodecApiRecord,
    CodecData, CodecTable, EncState, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;

/// :31 `#define CD_CISCOMETADATA_NAME "ciscometadata"` (faceA name face).
pub const CD_CISCOMETADATA_NAME: &str = "ciscometadata";
/// :32 `#define CD_CISCOMETADATA_HELP "support for cisco metadata"` (faceA
/// HELP line verbatim).
pub const CD_CISCOMETADATA_HELP: &str = "support for cisco metadata";

/// protocol_ids.h:161 `ETHERTYPE_CISCO_META = 0x8909` (= 35081, the GETIDS
/// face, the :102 push). ROW HOME (MEASURED ZERO prior landed Rust face;
/// the dup-not-import family).
pub const ETHERTYPE_CISCO_META: ProtocolId = 0x8909;

/// cisco_meta_data.h:29-:38 `struct CiscoMetaDataHdr` — `sizeof` == **8**
/// (u8+u8+u16+u16+u16, the :106 len gate; DISK arms `C len7` die / 8 pass).
/// Wire offsets: version @0, length @1, opt_len_type @2-3, sgt @4-5,
/// ether_type @6-7 (all multi-byte fields ntohs — the arpa/inet-only
/// header face).
pub const CISCO_META_HDR_SIZE: u16 = 8;

/// :93 `constexpr uint8_t CISCO_META_VALID_HDR_VER = 1;` — the :116 version
/// gate (`C ver0` dies with NO event — the stats-only arm).
pub const CISCO_META_VALID_HDR_VER: u8 = 1;
/// :94 `constexpr uint8_t CISCO_META_VALID_HDR_LEN = 1;` — the :122 length
/// gate (`C lenf0` dies stats-only).
pub const CISCO_META_VALID_HDR_LEN: u8 = 1;
/// :95 `constexpr uint16_t CISCO_META_VALID_OPT_LEN = 0;` — the :134 opt-
/// len gate (`0 indicates no additional options beyond SGT` :133).
pub const CISCO_META_VALID_OPT_LEN: u16 = 0;
/// :96 `constexpr uint8_t CISCO_META_OPT_LEN_SHIFT = 13;` — the :130 shift.
pub const CISCO_META_OPT_LEN_SHIFT: u32 = 13;
/// :97 `constexpr uint16_t CISCO_META_OPT_TYPE_SGT = 1;` — the :141 type
/// gate (`Bottom 13 bits (type) must be 1 to indicate SGT` :129).
pub const CISCO_META_OPT_TYPE_SGT: u16 = 1;
/// :98 `constexpr uint16_t CISCO_META_OPT_TYPE_MASK = 0x1FFF; // mask
/// opt_len_type to get option type` — the :131 mask.
pub const CISCO_META_OPT_TYPE_MASK: u16 = 0x1FFF;

/// decode_data.h:104 `#define PROTO_BIT__CISCO_META_DATA 0x020000` (=
/// 131072, the vectors' `pb=131072` face) — the :160 write. Row-scope home
/// (MEASURED ZERO prior landed Rust face for this bit; the landed dup-not-
/// import family — the PROTO_BIT__VLAN face rides framework, decode_data.h
/// :97 ALREADY landed at codec.rs:477-:484 census).
pub const PROTO_BIT__CISCO_META_DATA: u32 = 0x020000;

/// :36-:43 `static const RuleMap ciscometadata_rules[]` — FOUR data rows +
/// terminator, ALL sids RESIDENT codec_module.rs :226-:229 (ZERO new
/// consts), msgs byte-exact.
pub const CISCOMETADATA_RULES: [RuleMap; 5] = [
    RuleMap { sid: CodecSid::DECODE_CISCO_META_HDR_TRUNC as u32, msg: Some("truncated Cisco Metadata header") }, // :38
    RuleMap { sid: CodecSid::DECODE_CISCO_META_HDR_OPT_LEN as u32, msg: Some("invalid Cisco Metadata option length") }, // :39
    RuleMap { sid: CodecSid::DECODE_CISCO_META_HDR_OPT_TYPE as u32, msg: Some("invalid Cisco Metadata option type") }, // :40
    RuleMap { sid: CodecSid::DECODE_CISCO_META_HDR_SGT as u32, msg: Some("invalid Cisco Metadata security group tag") }, // :41
    RuleMap { sid: 0, msg: None }, // :42 `{ 0, nullptr }`
];

/// :67-:80 `class CiscoMetaDataModule : public BaseCodecModule` — :70 the
/// TWO-arg ctor face (NO params table) + :72-:73 get_rules + the get_pegs
/// :75-:76 / get_counts :78-:79 overrides = the PEG cite-never-land pair
/// (module doc: the PegInfo table cc:45-:54, the CiscoMetaDataStats struct
/// cc:56-:64 + THREAD_LOCAL cc:65 ride as CITES ONLY — ZERO counters land;
/// the 6-peg + CountType::END cc:53 table face cited, the vectors print
/// ZERO counts).
#[derive(Debug)]
pub struct CiscoMetaDataModule {
    pub base: BaseCodecModule,
}

impl CiscoMetaDataModule {
    /// :70 `CiscoMetaDataModule() : BaseCodecModule(CD_CISCOMETADATA_NAME,
    /// CD_CISCOMETADATA_HELP) { }` — the 2-arg arm.
    pub fn new() -> CiscoMetaDataModule {
        CiscoMetaDataModule {
            base: BaseCodecModule::new(CD_CISCOMETADATA_NAME, CD_CISCOMETADATA_HELP),
        }
    }

    /// :72-:73 the get_rules override -> the stored table.
    pub fn get_rules(&self) -> &'static [RuleMap] {
        &CISCOMETADATA_RULES
    }
    // get_pegs cc:75-:76 -> ciscometadata_pegs cc:45-:54 + get_counts
    // cc:78-:79 -> &ciscometadata_stats cc:65: the PEG cite-never-land
    // overrides (module doc; the cd_udp.rs:385-:386 lineage wording).
}

impl Default for CiscoMetaDataModule {
    fn default() -> Self {
        Self::new()
    }
}

/// :82-:91 `class CiscoMetaDataCodec : public Codec` — get_protocol_ids
/// :87 / decode :88 / log :89 / encode :90 overrides + the
/// `Codec(CD_CISCOMETADATA_NAME)` ctor face :85. Stack-owned (18d).
#[derive(Default)]
pub struct CiscoMetaDataCodec;

impl CiscoMetaDataCodec {
    /// :85 the base-ctor name face.
    pub fn new() -> CiscoMetaDataCodec {
        CiscoMetaDataCodec
    }

    /// :101-:102 `v.emplace_back(ProtocolId::ETHERTYPE_CISCO_META)` — faceA
    /// `GETIDS ciscometadata 35081` DECIMAL (0x8909, protocol_ids.h :161).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_CISCO_META); // :102
    }

    /// :104-:163 out-of-line decode — THE 468-471 ladder with the stats-
    /// only silent arms + the soft-then-continues sgt face (module doc).
    /// The third C param UNNAMED (:104 `DecodeData&`) = never-read (the pgm
    /// precedent). eval-order VAR-first EVERY compound (the :130/:131 len/
    /// type vars precede their gates; cite `ver:116-len:122-opt:130-type:
    /// 141-sgt:149-lyr:155`).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: QueueSink<'_>,
    ) -> bool {
        // :106-:111 `raw.len < sizeof(cisco_meta_data::CiscoMetaDataHdr)`
        // (8) -> stats.truncated_hdr++ (:108 — PEG cite-never-land, module
        // doc) + codec_event DECODE_CISCO_META_HDR_TRUNC (:109 — sid 468
        // RESIDENT) + return false (:110; vectors `EV 116 468` + `C len7
        // -> 0 lyr=0`).
        if raw.len < u32::from(CISCO_META_HDR_SIZE) {
            // cc:108 ciscometadata_stats.truncated_hdr++ (PEG, cite)
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_CISCO_META_HDR_TRUNC as u32,
                &mut *sink,
            ); // :109
            return false; // :110
        }

        // :113-:114 the CiscoMetaDataHdr overlay over raw.data — the Rust
        // face reads the wire windows BELOW (cd_eth overlay posture).
        // :116-:120 `if (cmdh->version != CISCO_META_VALID_HDR_VER)` ->
        // stats.invalid_hdr_ver++ (:118 — PEG cite) + return false (:119)
        // — THE SILENT-FAIL face: NO codec_event ANYWHERE (vectors `C ver0
        // -> 0 lyr=0` with NO EV line — the census-pinned ladder story).
        if raw.data[0] != CISCO_META_VALID_HDR_VER {
            // cc:118 ciscometadata_stats.invalid_hdr_ver++ (PEG, cite)
            return false; // :119
        }

        // :122-:126 `if (cmdh->length != CISCO_META_VALID_HDR_LEN)` ->
        // stats.invalid_hdr_len++ (:124 — PEG cite) + return false (:125)
        // — stats-only AGAIN (`C lenf0 -> 0 lyr=0` NO EV).
        if raw.data[1] != CISCO_META_VALID_HDR_LEN {
            // cc:124 ciscometadata_stats.invalid_hdr_len++ (PEG, cite)
            return false; // :125
        }

        // :128-:129 the ground comment (`Top 3 bits (length) must be equal
        // to 0` + `Bottom 13 bits (type) must be 1 to indicate SGT`) rides.
        // :130-:131 the TWO vars land FIRST (the R6 rule): `uint16_t len =
        // ntohs(cmdh->opt_len_type) >> CISCO_META_OPT_LEN_SHIFT;` +
        // `uint16_t type = ntohs(cmdh->opt_len_type) & CISCO_META_OPT_TYPE_
        // MASK;`.
        let opt_len_type = u16::from_be_bytes([raw.data[2], raw.data[3]]); // the two ntohs reads
        let len = opt_len_type >> CISCO_META_OPT_LEN_SHIFT; // :130
        let op_type = opt_len_type & CISCO_META_OPT_TYPE_MASK; // :131

        // :133 the ground comment (`0 indicates no additional options ...`)
        // rides. :134-:139 `if (len > CISCO_META_VALID_OPT_LEN)` -> stats
        // .invalid_opt_len++ (:136 — PEG cite) + EV 469 (:137) + return
        // false (:138; `C optlen1` on 0x2001).
        if len > CISCO_META_VALID_OPT_LEN {
            // cc:136 ciscometadata_stats.invalid_opt_len++ (PEG, cite)
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_CISCO_META_HDR_OPT_LEN as u32,
                &mut *sink,
            ); // :137
            return false; // :138
        }

        // :141-:146 `if (type != CISCO_META_OPT_TYPE_SGT)` -> stats
        // .invalid_opt_type++ (:143 — PEG cite) + EV 470 (:144) + return
        // false (:145; `C opttype2` on 0x0002).
        if op_type != CISCO_META_OPT_TYPE_SGT {
            // cc:143 ciscometadata_stats.invalid_opt_type++ (PEG, cite)
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_CISCO_META_HDR_OPT_TYPE as u32,
                &mut *sink,
            ); // :144
            return false; // :145
        }

        // :148 the ground comment (`0xFFFF is a reserved tag, not a
        // framing error, so the inner frame is still decoded`) rides — THE
        // SOFT-EVENT face: :149-:153 `if (cmdh->sgt == 0xFFFF)` -> stats
        // .invalid_sgt++ (:151 — PEG cite) + EV 471 (:152) — NO return:
        // control CONTINUES to the (:155-:160) tail (`C sgtffff -> 1` with
        // EV 471 AND the full happy tail face). The sgt window @4-5. The
        // 0xFFFF literal rides as the GROUND's (h:34 comment face), NEVER
        // a named const (the ground names NOTHING).
        let sgt = u16::from_be_bytes([raw.data[4], raw.data[5]]);
        if sgt == 0xFFFF {
            // cc:151 ciscometadata_stats.invalid_sgt++ (PEG, cite)
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_CISCO_META_HDR_SGT as u32,
                &mut *sink,
            ); // :152 (no return — the tail lands anyway)
        }

        // :155 `codec.lyr_len = sizeof(...)` :8; :157 `codec.next_prot_id =
        // static_cast<ProtocolId>(ntohs(cmdh->ether_type));` — the CAST
        // face @6-7 (2048 on the fixture — the cast rides, no enum); :159
        // `codec.codec_flags |= CODEC_ETHER_NEXT;` (4096, framework const
        // codec.rs:54); :160 `codec.proto_bits |= PROTO_BIT__CISCO_META_
        // DATA;` (131072, decode_data.h :104). Vars-first order VERBATIM :155
        // -> :157 -> :159 -> :160 (the order-site cite's tail).
        codec.lyr_len = CISCO_META_HDR_SIZE; // :155
        codec.next_prot_id = u16::from_be_bytes([raw.data[6], raw.data[7]]); // :157 cast face
        codec.codec_flags |= CODEC_ETHER_NEXT; // :159
        codec.proto_bits |= PROTO_BIT__CISCO_META_DATA; // :160
        true // :162
    }

    /// :165-:173 out-of-line log — cited-NEVER-called (the vectors' `C
    /// log cc:165-:173 cited-never-called` line; the cd_udp.rs:964 /
    /// cd_vxlan.rs:176 TextLog seam precedent), statement order VERBATIM:
    /// the :168-:169 overlay, ONE TextLog_Print :171-:172 format `"Ver:%hhu
    ///  SGT:%hu  EtherNext:0x%X"` (DOUBLE spaces verbatim; the C %hhu/
    /// %hu/%X dialect — sgt_val() = ntohs(sgt) h:37, ntohs(ether_type)).
    /// The :166 lyr_len operand UNNAMED — never-read posture.
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        sink(format!(
            "Ver:{}  SGT:{}  EtherNext:0x{:X}", // :171 (%hhu / %hu / %X)
            raw_pkt[0],                                              // :172 cmdh->version
            u16::from_be_bytes([raw_pkt[4], raw_pkt[5]]),            // :172 cmdh->sgt_val()
            u16::from_be_bytes([raw_pkt[6], raw_pkt[7]]),            // :172 ntohs(ether_type)
        ));
    }

    /// :175-:187 out-of-line encode — cited-NEVER-called (the vectors' `C
    /// encode cc:175-:187 ... cited-never-called` line), statement order
    /// VERBATIM: allocate :178-:179 -> memcpy :181 -> NOT_SET x2 :183-:184
    /// -> true :186. The `Flow*` UNNAMED (:176) = the landed never-read
    /// drop. THE cd_vlan encode twin face (byte-identical shape :176-:186
    /// vs vlan :176-:184 — the trio's two copy-only encodes vs the
    /// fabricpath swap encode).
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        if !buf.allocate(u32::from(raw_len)) {
            return false; // :178-:179
        }
        let n = usize::from(raw_len);
        let head = buf.data_mut().expect("allocate(raw_len) just made size != 0");
        head[..n].copy_from_slice(&raw_in[..n]); // :181 memcpy

        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET; // :183
        enc.next_proto = ip_protocol::PROTO_NOT_SET; // :184

        true // :186
    }
}

// :189-:191 the "api" separator banner rides. :193-:194 `static Module*
// mod_ctor() { return new CiscoMetaDataModule; }` + :196-:197 `mod_dtor`
// ride behavior-only cites (record mod slots SET — faceA `ciscometadata
// mod_ctor=1 mod_dtor=1`; the Rust mod face is CiscoMetaDataModule::new;
// the dtor folds onto the stack-owned drop, 18d posture). :199-:200
// `static Codec* ctor(Module*)` — the Module* DISCARDED (fabricpath twin
// face) — SET; :202-:203 `dtor` SET.

/// :205-:225 `static const CodecApi ciscometadata_api` — NAME/HELP slots
/// :214/:215 land the :31/:32 macro faces; mod arms :216/:217 REAL (the
/// mod_ctor :193/mod_dtor :196 pair); pinit :219 / pterm :220 / tinit :221
/// / tterm :222 nullptr WITH the ground `// pinit`-style comments; ctor
/// :223 (`// ctor`) + dtor :224 (`// dtor`) SET.
pub const CISCOMETADATA_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,                 // :208
    size: CDAPI_SIZEOF_CODEC_API,    // :209 sizeof(CodecApi)=112 (faceA pin)
    api_version: CDAPI_VERSION,      // :210 1900547
    version: 0,                      // :211
    features: PLUGIN_SO_RELOAD,      // :212
    options: API_OPTIONS,            // :213
    name: CD_CISCOMETADATA_NAME,     // :214 -> "ciscometadata"
    help: CD_CISCOMETADATA_HELP,     // :215
    mod_ctor: true,                  // :216 SET (mod_ctor :193 REAL)
    mod_dtor: true,                  // :217 SET (mod_dtor :196 REAL)
    pinit: false,                    // :219 nullptr // pinit
    pterm: false,                    // :220 nullptr // pterm
    tinit: false,                    // :221 nullptr // tinit
    tterm: false,                    // :222 nullptr // tterm
    ctor: true,                      // :223 SET  // ctor
    dtor: true,                      // :224 SET  // dtor
};

/// :227-:235 the hidden export, TRUE-NAME: `#ifdef BUILDING_SO` :227 / SO
/// arm :228 / the static-build `const BaseApi* cd_ciscometadata[] =` :230
/// feeding `&ciscometadata_api.base` :233 + nullptr :234 (ONE feed — faceA
/// `LOAD ciscometadata` + `LOADS 1`). nm: cd_ciscometadata D EXACTLY-1 ==
/// FILE base (the TRUE-NAME EQUALITY pin — the 18m drift CONTRAST). Ladder
/// entry "cd_ciscometadata" RESIDENT codec_api.rs:101 (ground extern
/// codec_api.cc :43, load :88) NEVER re-touched — THIS row TURNS it loaded.
pub const CD_CISCOMETADATA: CodecTable = &[&CISCOMETADATA_API];
