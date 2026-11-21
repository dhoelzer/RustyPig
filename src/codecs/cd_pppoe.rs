//! Port of `src/codecs/link/cd_pppoe.cc` (243 L) — row 18m, the codecs/
//! link PPP DRIFT PAIR half one (`tools/link6_harness`, ZERO-gate probe-
//! only, 20th straight honest zero-gate face: find src/codecs/link -type
//! d -name test = 0). Ground: snort3-src @ fe29cbe, md5
//! `65109bbd2bd8837140568f35bdf98eb5` wc 243 (the 243+174 = 417 SUM
//! re-measured and asserted EVERY build by tools/link6_harness/build.sh).
//! DIR FACT: `codecs/link/`. DRIFT-PAIR half one of two: the mate is
//! cd_ppp_encap.rs (174 L, md5 3a254d9eeb93298d8fc548f84ad6cad0).
//!
//! THE DOUBLE-NAME headline (the row's name-pin story, PLAN §5 — the ONLY
//! double-NAME/double-LOAD face in the backlog): ONE TU carries TWO
//! BaseCodecModule arms under TWO api structs (`pppoepkt_disc_api` cc:189
//! and `pppoepkt_sess_api` cc:211) feeding ONE TWO-entry table `const
//! BaseApi* cd_pppoepkt[]` cc:236 (`&pppoepkt_disc_api.base` cc:239 and
//! `&pppoepkt_sess_api.base` cc:240 and nullptr cc:241). The NAME
//! #defines `CD_PPPOEPKT_DISC_NAME "pppoe_disc"` cc:115 +
//! `CD_PPPOEPKT_SESS_NAME "pppoe_sess"` cc:139 sit INSIDE the SECOND
//! anon namespace cc:113-:165 (contrast the ppp_encap mate: NAME/HELP
//! cc:29/:30 OUTSIDE its ns :32-:49 — the enclosure faces sed-pinned
//! build-side). FACE-A vectors print `LOAD pppoe_disc` + `LOAD
//! pppoe_sess` = TWO LOAD lines from ONE table — the FIRST double-NAME
//! LOAD face in the port.
//!
//! THE TRUE-NAME DRIFT face (PLAN §1/:14 + §3): the FILE base is
//! `cd_pppoe` but the static table symbol is `cd_pppoepkt[]` cc:236 — the
//! Rust landing file keeps the FILE base (this file) while the hidden-
//! table const rides the TABLE spelling `CD_PPPOEPKT` (18l's
//! cd_trans_bridge.rs : cd_transbridge split PRECEDENT; the nm refusal
//! pins `cd_pppoe$` EXACTLY-0 in the .o every build — a grep-vs-file
//! confusion dies LOUD at the pins, never at a file). Ladder entry
//! "cd_pppoepkt" (the DRIFT spelling) RESIDENT codec_api.rs:123 (ground
//! extern codec_api.cc :65, load :110) NEVER re-walked; THIS row TURNS it
//! loaded.
//!
//! THE mod-arms face MEASURED, NEVER carried from 18l's 1/1/0: disc arms
//! `disc_mod_ctor` cc:171 -> slot cc:200 + `mod_dtor` cc:177 -> slot
//! cc:201; sess arms `sess_mod_ctor` cc:174 -> cc:222 + mod_dtor cc:223
//! => `pppoe_disc mod_ctor=1 mod_dtor=1` AND `pppoe_sess mod_ctor=1
//! mod_dtor=1` (vectors_faceA); ctor/dtor (CodecApi slots) SET x2 cc:207/
//! :208 + cc:229/:230. The PPPoEModule class cc:62-:73 is the tail's
//! THREE-arg shape (name, help, RuleMap* cc:65-:66, get_rules override
//! cc:68-:69) — ONE class, TWO instances (the double-NAME face again).
//!
//! THE GROUND FAMILY LINK (PLAN §1, the pair story): the sess decode
//! happy arm writes `codec.lyr_len = PPPOE_HEADER_LEN` cc:160 BEFORE
//! `codec.next_prot_id = ProtocolId::ETHERTYPE_PPP` cc:161 (THE PAIR-LINK
//! pin + the order-site cite) — the SAME ETHERTYPE_PPP (0x880B = 34827,
//! protocol_ids.h :152) that the cd_ppp_encap mate PUSHES in
//! get_protocol_ids cc:52: pppoe_sess -> ppp_encap is a REAL decode-chain
//! family, not name similarity (parity-pinned cross-file EQUAL; the
//! ETHERTYPE_PPP twin here cites the cd_ppp_encap.rs home — the
//! cd_user/cd_udp + erspan2/trans_bridge dup-not-import family).
//!
//! PADT NEVER-PULL RULING (PLAN §5d3, disk wins): `PADT` greps 0 in the
//! ground TU — the SESSION token is TRUE (session field cc:41, the
//! `pppoe_sess` NAME :139/:145), PADT NEVER EXISTS on disk => NO PADT arm
//! is ever ported, vectorized, or cited-as-present; build.sh re-asserts
//! PADT grep-0 BOTH sides (source + nm) EVERY build.
//!
//! sids 120/479 RESIDENT codec_module.rs :95/:237 (h:78/:232), NEVER
//! re-walked, ZERO new consts (PLAN §4). The disc HAPPY arm sets ZERO
//! lyr/next EVER (cc:136 bare return true — the honest zero-write face,
//! next rides the CodecData init ctor codec.h face; vectors
//! `PD len6 -> 1 lyr=0 next=34915`). encode cc:92-:105 is cited-NEVER-
//! called by the vectors (EncState-IpApi seam, the eth/tun/erspan ZERO-
//! encode-arms precedent) — ported-by-reading with cc-line cites, unit-
//! mirrored below like 18l's TB encode.

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData,
    CodecTable, EncState, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;

/// cc:115 `#define CD_PPPOEPKT_DISC_NAME "pppoe_disc"` — the FIRST of the
/// DOUBLE-NAME pair, INSIDE the second anon namespace cc:113-:165 (the
/// enclosure contrast vs the mate's OUTSIDE-ns :29/:30, sed-pinned).
pub const CD_PPPOEPKT_DISC_NAME: &str = "pppoe_disc";
/// cc:116 `#define CD_PPPOEPKT_DISC_HELP "support for point-to-point
/// discovery"` (vectors_faceA HELP line verbatim).
pub const CD_PPPOEPKT_DISC_HELP: &str = "support for point-to-point discovery";
/// cc:139 `#define CD_PPPOEPKT_SESS_NAME "pppoe_sess"` — the SECOND NAME
/// in ONE TU (the double-NAME headline; the NAME string is used at the
/// ctor cc:145 and mod ctor cc:175 faces).
pub const CD_PPPOEPKT_SESS_NAME: &str = "pppoe_sess";
/// cc:140 `#define CD_PPPOEPKT_SESS_HELP "support for point-to-point
/// session"` (vectors_faceA HELP line verbatim).
pub const CD_PPPOEPKT_SESS_HELP: &str = "support for point-to-point session";

/// protocol_ids.h:155 `ETHERTYPE_PPPOE_DISC = 0x8863` (= 34915, the
/// GETIDS face) — the cc:125 get_protocol_ids push.
pub const ETHERTYPE_PPPOE_DISC: ProtocolId = 0x8863;
/// protocol_ids.h:156 `ETHERTYPE_PPPOE_SESS = 0x8864` (= 34916, the
/// GETIDS face) — the cc:149 get_protocol_ids push.
pub const ETHERTYPE_PPPOE_SESS: ProtocolId = 0x8864;
/// protocol_ids.h:152 `ETHERTYPE_PPP = 0x880B` (= 34827) — the cc:161
/// next_prot_id WRITE: THE PAIR-LINK. File-local TWIN of the
/// cd_ppp_encap.rs home (its get_protocol_ids GETIDS id cc:52): the
/// landed dup-not-import family, parity-pinned EQUAL in the row's parity
/// test (the cross-file family assert: sess next == ppp_encap GETIDS).
pub const ETHERTYPE_PPP: ProtocolId = 0x880B;

/// cc:86 `constexpr uint16_t PPPOE_HEADER_LEN = 6;` — the cc:130/:154 len
/// gates AND the cc:160 lyr_len write (vectors `PS len6 -> 1 lyr=6`).
/// Ground-pinned by build.sh every build (`constexpr uint16_t
/// PPPOE_HEADER_LEN = 6;` sed-verbatim).
pub const PPPOE_HEADER_LEN: u16 = 6;

/// cc:50-:54 `static const RuleMap pppoe_disc_rules[]` — ONE data row +
/// terminator, msg byte-exact, sid RESIDENT 120 (codec_module.rs :95,
/// ZERO new consts).
pub const PPPOE_DISC_RULES: [RuleMap; 2] = [
    RuleMap { sid: CodecSid::DECODE_BAD_PPPOE_DISC as u32, msg: Some("bad PPPOE discovery frame detected") }, // cc:52
    RuleMap { sid: 0, msg: None }, // cc:53 `{ 0, nullptr }`
];

/// cc:56-:60 `static const RuleMap pppoe_sess_rules[]` — ONE data row +
/// terminator, sid RESIDENT 479 (codec_module.rs :237).
pub const PPPOE_SESS_RULES: [RuleMap; 2] = [
    RuleMap { sid: CodecSid::DECODE_BAD_PPPOE_SESS as u32, msg: Some("bad PPPOE session frame detected") }, // cc:58
    RuleMap { sid: 0, msg: None }, // cc:59
];

/// cc:62-:73 `class PPPoEModule : public BaseCodecModule` — the tail's
/// THREE-arg ctor shape cc:65-:66 `(name, help, const RuleMap* rm)` with
/// the get_rules override cc:68-:69: ONE class, TWO instances (disc via
/// `disc_mod_ctor` cc:171-:172, sess via `sess_mod_ctor` cc:174-:175 —
/// the double-NAME face at the module layer; the C++ heap `new` folds
/// onto stack-owned Rust like every landed row).
#[derive(Debug)]
pub struct PPPoEModule {
    pub base: BaseCodecModule,
    pub rules: &'static [RuleMap; 2],
}

impl PPPoEModule {
    /// cc:171-:172 `disc_mod_ctor()` — the Rust mod_ctor face: the disc
    /// NAME/HELP pair cc:115/:116 + `pppoe_disc_rules`.
    pub fn new_disc() -> PPPoEModule {
        PPPoEModule {
            base: BaseCodecModule::new(CD_PPPOEPKT_DISC_NAME, CD_PPPOEPKT_DISC_HELP),
            rules: &PPPOE_DISC_RULES,
        }
    }

    /// cc:174-:175 `sess_mod_ctor()` — the sess NAME/HELP pair cc:139/
    /// :140 + `pppoe_sess_rules`.
    pub fn new_sess() -> PPPoEModule {
        PPPoEModule {
            base: BaseCodecModule::new(CD_PPPOEPKT_SESS_NAME, CD_PPPOEPKT_SESS_HELP),
            rules: &PPPOE_SESS_RULES,
        }
    }

    /// cc:68-:69 `get_rules()` override -> the stored rules (the ONE
    /// class's field cc:72; disc/sess ride their own tables).
    pub fn get_rules(&self) -> &'static [RuleMap] {
        self.rules
    }
}

/// cc:75-:83 `class PPPoECodec : public Codec` — the SHARED base of the
/// double-NAME pair: encode FINAL cc:78-:79 + the protected name ctor
/// cc:82. Stack-owned Rust posture (18d); decode rides each derived
/// codec's own impl (the C single-inheritance fold, the landed pattern).
#[derive(Default)]
pub struct PPPoECodecBase;

impl PPPoECodecBase {
    /// cc:92-:105 `PPPoECodec::encode` (SHARED final) — cited-NEVER-
    /// CALLED by the vectors (vectors `PD encode cc:92-:105 cited-never-
    /// called EncState-IpApi face`), ported-by-reading with EVERY move
    /// cc-cited, statement order VERBATIM: allocate cc:95-:96 -> memcpy
    /// cc:98 -> `ppph->length = htons(buf.size() - raw_len)` cc:100 (the
    /// PPPoEHdr length slot @4..6, cc:42; allocate was JUST raw_len, so
    /// the C expression computes 0 — honest face copied, NEVER "simpli-
    /// fied" away) -> NOT_SET resets cc:102-:103 -> true cc:104. The
    /// `Flow*` operand UNNAMED (cc:93) = dropped like every landed never-
    /// read pointer.
    pub fn encode(
        raw_in: &[u8],
        raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
    ) -> bool {
        // cc:95-:96 `if (!buf.allocate(raw_len)) return false;`
        if !buf.allocate(u32::from(raw_len)) {
            return false;
        }

        // cc:98 `memcpy(buf.data(), raw_in, raw_len)` — the landed
        // Buffer posture copies the window explicitly.
        // cc:99-:100 the PPPoEHdr overlay + `ppph->length = htons(
        // (uint16_t)buf.size() - raw_len)` — length slot @4..6 (cc:42
        // uint16_t length), htons -> wire order to_be_bytes. buf.size()
        // == raw_len right after the allocate (the C face; the expression
        // computes 0 — honest, cited-never-invented; the size read lands
        // BEFORE the head borrow, the Rust-face clone of the C sequence).
        let len_field = (buf.size() - u32::from(raw_len)) as u16; // cc:100 buf.size() read
        let head = buf.data_mut().expect("allocate(raw_len) just made size != 0");
        let n = usize::from(raw_len);
        head[..n].copy_from_slice(&raw_in[..n]); // cc:98
        head[4..6].copy_from_slice(&len_field.to_be_bytes()); // cc:100 store

        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET; // cc:102
        enc.next_proto = ip_protocol::PROTO_NOT_SET;         // cc:103
        true // cc:104
    }
}

/// cc:118-:126 `class PPPoEDiscCodec : public PPPoECodec` — decode cc:122
/// and get_protocol_ids cc:124-:125. The `PPPoECodec(CD_PPPOEPKT_DISC_NAME)`
/// ctor-name face cc:121 rides the api record.
#[derive(Default)]
pub struct PppoeDiscCodec;

impl PppoeDiscCodec {
    /// cc:121 the base-ctor name face.
    pub fn new() -> PppoeDiscCodec {
        PppoeDiscCodec
    }

    /// cc:124-:125 `v.emplace_back(ProtocolId::ETHERTYPE_PPPOE_DISC)` —
    /// vectors_faceA `GETIDS pppoe_disc 34915` DECIMAL (0x8863 :155).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_PPPOE_DISC); // cc:125
    }

    /// cc:128-:137 out-of-line decode — the soft gate + the ZERO-write
    /// happy face. decode's third C param UNNAMED (cc:128 `DecodeData&`)
    /// = never-read (the pgm precedent).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink<'_>) -> bool {
        // cc:130-:134: `raw.len < PPPOE_HEADER_LEN` (6) -> codec_event
        // DECODE_BAD_PPPOE_DISC (cc:132 — sid 120 RESIDENT codec_module.
        // rs :95, NEVER re-walked) + return false (:133) — the fail path
        // NEVER touches lyr_len (vectors `EV 116 120` + `PD len5 -> 0
        // lyr=0`).
        if raw.len < u32::from(PPPOE_HEADER_LEN) {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_BAD_PPPOE_DISC as u32,
                &mut *sink,
            );
            return false; // cc:133
        }

        // cc:136 `return true;` — the HONEST zero face: lyr_len and
        // next_prot_id NEVER written on the disc happy arm (vectors
        // `PD len6 -> 1 lyr=0 next=34915` — next stays the CodecData
        // INIT prot, the codec.h init face; cited, never invented).
        true
    }
    // NO encode override in the derived class — encode is the SHARED
    // final base arm cc:78-:79 (PPPoECodecBase::encode above).
}

/// cc:142-:150 `class PPPoESessCodec : public PPPoECodec` — decode cc:146
/// and get_protocol_ids cc:148-:149 (the SESS id).
#[derive(Default)]
pub struct PppoeSessCodec;

impl PppoeSessCodec {
    /// cc:145 the base-ctor name face.
    pub fn new() -> PppoeSessCodec {
        PppoeSessCodec
    }

    /// cc:148-:149 `v.emplace_back(ProtocolId::ETHERTYPE_PPPOE_SESS)` —
    /// vectors_faceA `GETIDS pppoe_sess 34916` DECIMAL (0x8864 :156).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_PPPOE_SESS); // cc:149
    }

    /// cc:152-:163 out-of-line decode — THE PAIR-LINK. EVAL ORDER (the
    /// row's order-site cite `PS order-site lyr:160-before-next:161`):
    /// the lyr_len write cc:160 lands BEFORE the next_prot_id write
    /// cc:161, statement order VERBATIM.
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink<'_>) -> bool {
        // cc:154-:158: `raw.len < 6` -> codec_event DECODE_BAD_PPPOE_SESS
        // (cc:156, sid 479 RESIDENT codec_module.rs :237) + false
        // (:157) — vectors `EV 116 479` + `PS len5 -> 0 lyr=0`.
        if raw.len < u32::from(PPPOE_HEADER_LEN) {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_BAD_PPPOE_SESS as u32,
                &mut *sink,
            );
            return false; // cc:157
        }

        codec.lyr_len = PPPOE_HEADER_LEN;       // cc:160 (LYR FIRST — the order-site pin)
        codec.next_prot_id = ETHERTYPE_PPP;     // cc:161 (34827 == the ppp_encap GETIDS id — the ground decode-chain family)
        true // cc:162
    }
    // session-hdr honesty (vectors cite line): the PPPoEHdr cc:34-:44
    // fields — ver_type :37, code :39, SESSION id :41, length :42 — are
    // NEVER read by either decode arm (cc:128/:152 touch raw.len ONLY);
    // the :41 session field rides cited-never-ported. PADT: grep-0 in
    // the ground TU — NEVER-pull ruling (module doc headline; build.sh
    // asserts PADT 0 source + nm EVERY build).
}

// cc:167-:169 the "api" separator banner rides. cc:171-:187 the api
// function faces (disc_mod_ctor :171 / sess_mod_ctor :174 / mod_dtor :177
// / disc_ctor :180 / sess_ctor :183 / pppoe_dtor :186) ride behavior-only
// cites: the Rust mod_ctor faces ARE PPPoEModule::new_disc/new_sess, the
// Rust codec faces ARE PppoeDiscCodec::new/PppoeSessCodec::new, and the
// dtors fold onto the stack-owned drop (18d posture). The mod_dtor face
// cc:177-:178 is SHARED by both api records (ONE function, slots cc:201
// + cc:223 — the double-LOAD record face).

/// cc:189-:209 `static const CodecApi pppoepkt_disc_api` — the FIRST of
/// the TWO api structs in ONE TU: name/help slots cc:198/:199 land the
/// cc:115/:116 macro faces; mod_ctor cc:200 (`disc_mod_ctor` cc:171) +
/// mod_dtor cc:201 (`mod_dtor` cc:177) REAL; pinit/pterm/tinit/tterm
/// nullptr cc:203-:206 = false x4; ctor cc:207 (`disc_ctor`) + dtor
/// cc:208 (`pppoe_dtor`) SET.
pub const PPPOEPKT_DISC_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:192
    size: CDAPI_SIZEOF_CODEC_API, // cc:193 sizeof(CodecApi)=112 (faceA size pin)
    api_version: CDAPI_VERSION,   // cc:194 1900547
    version: 0,                   // cc:195
    features: PLUGIN_SO_RELOAD,   // cc:196
    options: API_OPTIONS,         // cc:197
    name: CD_PPPOEPKT_DISC_NAME,  // cc:198 -> "pppoe_disc"
    help: CD_PPPOEPKT_DISC_HELP,  // cc:199
    mod_ctor: true,               // cc:200 REAL (disc_mod_ctor cc:171)
    mod_dtor: true,               // cc:201 REAL (mod_dtor cc:177 — SHARED)
    pinit: false,                 // cc:203 nullptr
    pterm: false,                 // cc:204 nullptr
    tinit: false,                 // cc:205 nullptr
    tterm: false,                 // cc:206 nullptr
    ctor: true,                   // cc:207 SET (disc_ctor cc:180)
    dtor: true,                   // cc:208 SET (pppoe_dtor cc:186 — SHARED)
};

/// cc:211-:231 `static const CodecApi pppoepkt_sess_api` — the SECOND api
/// struct: name/help cc:220/:221 land cc:139/:140; mod_ctor cc:222
/// (`sess_mod_ctor` cc:174) + mod_dtor cc:223 (SHARED mod_dtor cc:177)
/// REAL; nullptr x4 cc:225-:228; ctor cc:229 + dtor cc:230 SET.
pub const PPPOEPKT_SESS_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // cc:214
    size: CDAPI_SIZEOF_CODEC_API, // cc:215
    api_version: CDAPI_VERSION,   // cc:216
    version: 0,                   // cc:217
    features: PLUGIN_SO_RELOAD,   // cc:218
    options: API_OPTIONS,         // cc:219
    name: CD_PPPOEPKT_SESS_NAME,  // cc:220 -> "pppoe_sess"
    help: CD_PPPOEPKT_SESS_HELP,  // cc:221
    mod_ctor: true,               // cc:222 REAL (sess_mod_ctor cc:174)
    mod_dtor: true,               // cc:223 REAL (mod_dtor cc:177 — SHARED)
    pinit: false,                 // cc:225 nullptr
    pterm: false,                 // cc:226 nullptr
    tinit: false,                 // cc:227 nullptr
    tterm: false,                 // cc:228 nullptr
    ctor: true,                   // cc:229 SET (sess_ctor cc:183)
    dtor: true,                   // cc:230 SET (pppoe_dtor cc:186 — SHARED)
};

/// cc:233-:242 the hidden export with THE drift name + THE double feed
/// (module doc headline): `#ifdef BUILDING_SO` cc:233 / SO arm cc:234 /
/// the static-build `const BaseApi* cd_pppoepkt[] =` cc:236 feeding TWO
/// bases `&pppoepkt_disc_api.base` cc:239 + `&pppoepkt_sess_api.base`
/// cc:240 + nullptr cc:241 — the FIRST TWO-entry table in the port (the
/// FACE-A double-LOAD face: `LOAD pppoe_disc` + `LOAD pppoe_sess`,
/// `LOADS 2`). nm: the .o defines cd_pppoepkt EXACTLY-1, `cd_pppoe$`
/// EXACTLY-0 (the build.sh drift refusal). The Rust const rides the
/// TABLE spelling (18l precedent); the FILE base stays cd_pppoe.rs.
/// Ladder entry "cd_pppoepkt" RESIDENT codec_api.rs:123 NEVER re-touched
/// (ground extern codec_api.cc :65, load :110) — THIS row TURNS it loaded.
pub const CD_PPPOEPKT: CodecTable = &[&PPPOEPKT_DISC_API, &PPPOEPKT_SESS_API];
