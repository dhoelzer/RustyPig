//! Port of `src/codecs/link/cd_mpls.cc` (390 L) — row 18o, the LAST TU of
//! the codecs/link chapter (`tools/mpls_harness`, ZERO-gate probe-only, the
//! 25th straight honest zero-gate face: link/test find-0 + add_cpputest 0 +
//! TEST_CASE/CppUTest grep-0 in the TU). Ground: snort3-src @ fe29cbe, md5
//! `e2911ad515d5f416415acd1ee9967379` wc 390 (the six-file chapter ledger
//! 390+236+235+187+207+210 = 1465 asserted HERE and EVERY build by
//! tools/mpls_harness/build.sh). DIR FACT: `codecs/link/`.
//!
//! THE HEAVIEST-CLOSURE ROW OF THE LINK CHAPTER (harness PLAN §2, the
//! headline cost): the TU drags SEVEN fresh cps at the 122-tree head —
//! flow/flow.h 637 L (md5 765663d4) + utils/safec.h 42 L (md5 4d366338) +
//! FIVE riders (flow_data/deferred_trust/flow_stash/ips_context_chain +
//! THE clock_defs rider — the 6-vs-7 docs CORRECTION lands MEASURED, PLAN
//! §2 step-6 fatal flow.h:51; the flowz/flow_data.h graft DECOY NEVER
//! satisfies the flow/-path include). Harness-side only: this Rust file
//! ships NONE of that world (the Flow ride lands as the cited left-open
//! seam below; the safec face lands as the memcpy semantics below).
//!
//! THE EXT#2 GRAD EXTENSION (the SECOND graft-extension row, PLAN §3): the
//! flow.h cp DEMANDS the MAX_DAQ_VERDICT enum face (flow.h :541; the NEVER-
//! land census grep-0 in ALL FOUR landed daq faces FLIPS POSITIVE at this
//! row's HARNESS ONLY) -> the 34 L copy-LOCAL heredoc md5 **9b603f8f** rides
//! copy/daq_common.h; the frozen masters 73fdbc39/f683749c + the INHERITED
//! link4 face fead0027 are md5-asserted ladder HEAD AND TAIL every build,
//! NEVER cp'd NEVER promoted (the 18n graft law re-armed; row 20 re-cites
//! the real SDK — SYNTHETIC enum face, NEVER ABI truth). graft-v3 daq.h
//! 0f7016a6 rides INHERITED and is NEVER consumed (grep-ci daq in the TU =
//! 0 — the daq.h-drop SURVIVES rc0 inversion vs 18n). NONE of this is Rust
//! surface: the enum NEVER lands here (ZERO daq symbols in this file).
//!
//! THE SAFEC STOCK-SHIM SEMANTIC FACE (PLAN §5, MEASURED not assumed): the
//! EXACTLY-1 memcpy_s use-site :267 rides the STOCK safec.h #else shim
//! (config.h HAVE_SAFEC grep-0 -> the 42-L verbatim cp defines memcpy_s ->
//! memcpy, safec.h :23+:33) — ZERO safe_*_lib grafts, ZERO shim authoring;
//! the strip arm moves the wall to the :30 include, NEVER :267 (C15
//! receipts). The Rust encode mirrors the shim AS A PLAIN COPY (the 18n
//! copy_from_slice posture) with the shim cite — ported BY READING.
//!
//! THE WITNESS/SEAM FACES (the §7 MEASURED, never pre-picked face): the
//! bypass hook U CLOSES against the INHERITED witness_18f (T ea1f79f3,
//! ZERO clone cost); OWN L1 census = EXACTLY-1 distinct undefined
//! snort::Flow::get_mpls_layer_per_dir(bool) -> witness_flow.cc 27 L
//! b76c809d own-new (miscip 27-L shape; backbone array STAYS EXACTLY 10 —
//! symbol-vs-array law). Rust twin: THE get_mpls_layer_per_dir SEAM lands
//! LEFT-OPEN (the row 18i R1 cheat sheet / vlan get_pkthdr precedent):
//! encode takes the per-dir Layer as an Option PARAM — the harness mirror
//! returns nullptr, so ground :255 `mpls_lyr && mpls_lyr->length` is FALSE
//! and the raw_in/raw_len defaults :249-:250 ride (the vectorized encode
//! face; the ONLY call site cd_mpls.cc :253). The REAL Flow provider stays
//! CITED-NEVER-INVENTED (flow.h :223 decl + flow.cc per-dir members + the
//! witness-mirror face); ZERO provider machinery lands in this row.
//!
//! PROTO_BIT__MPLS 0x000200 (vectors pb=512 / the M10 pb=0 TRUE CLEAR):
//! ALREADY RESIDENT at crate::detection::rtn_checks :34 (decode_data.h :96)
//! — REUSE-NEVER-REDECLARE (the row-scoped-NEW docs const face STALE, re-
//! grep THIS pass; the cite lands both homes). TUNNEL_MPLS 0x80 row-scoped
//! (snort_config.h :126 sed-pinned) w/ the cd_vxlan TUNNEL_VXLAN / cd_gtp
//! TUNNEL_GTP / cd_geneve TUNNEL_GENEVE sibling precedent; the hook itself
//! rides the landed LEFT-OPEN bypass closure seam (the 18k/18f/18g family),
//! NEVER an invented provider.
//!
//! sids 7/7 RESIDENT codec_module.rs :113-:119 (h :100-:106): DECODE_BAD_
//! MPLS 170 / LABEL0 171 / LABEL1 172 / LABEL2 173 / LABEL3 174 /
//! DECODE_MPLS_RESERVED_LABEL 175 / DECODE_MPLS_LABEL_STACK 176 — ZERO new
//! consts. THE sid band FIRES POSITIVE in ITS OWN vectors THE FIRST TIME
//! (the q4 NEVER-land census FLIPS AT its own row; the parity test re-
//! asserts the SAME band grep-0 in ALL FOUR landed predecessor vectors —
//! the flip NEVER leaks).
//!
//! TRUE-NAME face: `const BaseApi* cd_mpls[]` :385 == the FILE base (THE
//! 18n equality-pin law; BUILDING_SO split :382-:386, feed &mpls_api.base
//! :388, nm D-EXACTLY-1). Ladder entry "cd_mpls" RESIDENT codec_api.rs :119
//! (ground extern codec_api.cc :61 + load :106 — EXACTLY-2 hits) NEVER re-
//! walked; THIS row TURNS it loaded; the 39-extern census + [&str; 34]
//! UNDISTURBED. NAME/HELP at the DISK-corrected :34/:35 (the NEXT docs :33/
//! :34 face DISK-DEAD, re-sed; use-sites :80/:111/:369/:370). mod arms ALL
//! REAL (mod_ctor :341/mod_dtor :344 -> api :371/:372) + THE CONFIG-CARRYING
//! `ctor(Module* m)` :347 face (`if (m)` :349-:354 threads mod->get_data()
//! into MplsCodec — the config-threading pin the M10 vectors print).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, Buffer, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData,
    CodecTable, EncState, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, QueueSink, RawData,
};
use crate::framework::codec::ip_protocol;
use crate::framework::codec::protocol_id;
use crate::framework::value::Value;

/// :34 `#define CD_MPLS_NAME "mpls"` (vectors_faceA LOAD/API/HELP/NAME
/// name). THE :34 FACE IS THE DISK one — the docs ':33' cite is DISK-DEAD
/// (harness §1 re-sed; §9 risk (4) CONFIRMED at the row build).
pub const CD_MPLS_NAME: &str = "mpls";
/// :35 `#define CD_MPLS_HELP "support for multiprotocol label switching"`
/// (faceA `HELP mpls ...` line verbatim — the correction lands IN vectors).
pub const CD_MPLS_HELP: &str = "support for multiprotocol label switching";

/// :126 `constexpr int MPLS_HEADER_LEN = 4;` — the :169 short gate + the
/// :194 stride (the vectors' lyr 4/8/16/20 faces).
pub const MPLS_HEADER_LEN: u32 = 4;
/// :127 `constexpr int NUM_RESERVED_LABELS = 16;` — the :181 validate-range
/// gate (labels 0..=15; >= 16 NEVER reaches the switch).
pub const NUM_RESERVED_LABELS: u32 = 16;

/// :39-:46 `enum MplsPayloadType : uint8_t` — INDICES 0/1/2/3 (the :41
/// "Entries must align with payload_type enum parameter" comment IS the
/// transcription — the seed-draft eth=2/ip6=4 bound was DRIFT, the ground
/// enum order wins, §11(d)).
pub const MPLS_PAYLOADTYPE_AUTODETECT: u8 = 0; // :42
pub const MPLS_PAYLOADTYPE_ETHERNET: u8 = 1; // :43
pub const MPLS_PAYLOADTYPE_IPV4: u8 = 2; // :44
pub const MPLS_PAYLOADTYPE_IPV6: u8 = 3; // :45

/// protocol_ids.h:153 `ETHERTYPE_MPLS_UNICAST = 0x8847` (= 34887) — the
/// get_protocol_ids head :132 AND the probe's CodecData init_prot face (the
/// failure lines print next=34887, NEVER zeroed by a fail path). ROW HOME
/// (MEASURED zero prior landed Rust face; the landed dup-not-import family).
pub const ETHERTYPE_MPLS_UNICAST: ProtocolId = 0x8847;
/// protocol_ids.h:154 `ETHERTYPE_MPLS_MULTICAST = 0x8848` (= 34888) — the
/// :133 emplace. ROW HOME (same census).
pub const ETHERTYPE_MPLS_MULTICAST: ProtocolId = 0x8848;
// MPLS_IP = 137 (:134 emplace) LANDS as the RESIDENT `crate::framework::
// codec::protocol_id::MPLS_IP` face (framework/codec.rs :151 — landed since
// 17d; REUSE-NEVER-REDECLARE, the get_protocol_ids write cites it).
// PROTO_BIT__MPLS rides the RESIDENT crate::detection::rtn_checks :34
// 0x000200 (decode_data.h :96) — REUSE, NEVER a row-scoped re-declare.

/// protocol_ids.h:147 `ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558` (= 25944)
/// — the :220 forced-eth arm + the :238 auto-default arm. ROW HOME twin w/
/// the cd_trans_bridge.rs:88 / cd_erspan2.rs:80 landed twin precedent (the
/// landed dup-not-import family — protocol_id.rs NEVER carries it framework-
/// side; the vectors pin the DECIMAL 25944, never the name).
pub const ETHERTYPE_TRANS_ETHER_BRIDGING: ProtocolId = 0x6558;

/// snort_config.h:126 `TUNNEL_MPLS = 0x80` (enum TunnelFlags, sed-pinned) —
/// the :205 hook argument. vectors M16 mask80 -> bypass=0 / M17 mask00 ->
/// bypass=1 (the tun_harness witness_18f mask-pair observable the CARRIED
/// T face closes). Row-scoped home w/ the cd_vxlan.rs:80 / cd_gtp.rs:148 /
/// cd_geneve.rs:208 sibling precedent.
pub const TUNNEL_MPLS: u16 = 0x80;

/// :48-:57 `static const Parameter mpls_params[]` — TWO data rows + the
/// PT_MAX terminator (:56). The landed Parameter shape keeps name/ptype/
/// deflt (the range/help slots unported — the carried 16c/vlan/esp-slot
/// deviation re-cited); the ground range strings ride MPLS_PARAM_RANGES
/// ONLY so the faceA PARAM print lines have their cite-homed values (PT_INT
/// ordinal 4 / PT_ENUM ordinal 11 ride the landed Type enum — the same
/// parameter.h walk the misc9 null_params sentinel face used).
pub const MPLS_PARAMS: [crate::framework::parameter::Parameter; 3] = [
    crate::framework::parameter::Parameter {
        name: Some("max_stack_depth"), // :50 1st field
        ptype: crate::framework::parameter::Type::PtInt, // :50 PT_INT
        deflt: Some("-1"), // :50 4th field — the -1 SENTINEL (:196 gate-off face)
    },
    crate::framework::parameter::Parameter {
        name: Some("payload_type"), // :53 1st field
        ptype: crate::framework::parameter::Type::PtEnum, // :53 PT_ENUM
        deflt: Some("auto"), // :53 4th field
    },
    crate::framework::parameter::Parameter {
        name: None, // :56 1st field nullptr
        ptype: crate::framework::parameter::Type::PtMax, // :56 PT_MAX
        deflt: None, // :56
    },
];

/// The 3rd Parameter slot (range) text, pinned as strings because the
/// landed Parameter shape omits the slot (deviation above): :50
/// `"-1:255"` + :53 `"auto | eth | ip4 | ip6"` — the faceA PARAM lines
/// print them (probe inline raw-field walk, the misc9 precedent). Cites,
/// never re-derived.
pub const MPLS_PARAM_RANGES: [(&str, &str); 2] = [
    ("-1:255", "-1"), // :50 range + deflt
    ("auto | eth | ip4 | ip6", "auto"), // :53 range + deflt
];

/// :59-:69 `static const RuleMap mpls_rules[]` — SEVEN data rows + the :68
/// terminator; sids ALL RESIDENT codec_module.rs :113-:119 (ZERO new
/// consts), msgs byte-exact off the ground strings.
pub const MPLS_RULES: [RuleMap; 8] = [
    RuleMap { sid: CodecSid::DECODE_BAD_MPLS as u32, msg: Some("bad MPLS frame") }, // :61
    RuleMap { sid: CodecSid::DECODE_BAD_MPLS_LABEL0 as u32, msg: Some("MPLS label 0 appears in bottom header when not decoding as ip4") }, // :62
    RuleMap { sid: CodecSid::DECODE_BAD_MPLS_LABEL1 as u32, msg: Some("MPLS label 1 appears in bottom header") }, // :63
    RuleMap { sid: CodecSid::DECODE_BAD_MPLS_LABEL2 as u32, msg: Some("MPLS label 2 appears in bottom header when not decoding as ip6") }, // :64
    RuleMap { sid: CodecSid::DECODE_BAD_MPLS_LABEL3 as u32, msg: Some("MPLS label 3 appears in header") }, // :65
    RuleMap { sid: CodecSid::DECODE_MPLS_RESERVED_LABEL as u32, msg: Some("MPLS label 4, 5,.. or 15 appears in header") }, // :66
    RuleMap { sid: CodecSid::DECODE_MPLS_LABEL_STACK as u32, msg: Some("too many MPLS headers") }, // :67
    RuleMap { sid: 0, msg: None }, // :68 `{ 0, nullptr }`
];

/// :71-:75 `struct MplsCodecConfig { int stack_depth = -1; uint8_t
/// payload_type = MPLS_PAYLOADTYPE_AUTODETECT; }` — the NSDMI faces (the
/// `-1` sentinel = the ground PARAM deflt face; `begin` re-arms {} :87).
#[derive(Debug, Clone, Copy)]
pub struct MplsCodecConfig {
    pub stack_depth: i32, // :73 default -1
    pub payload_type: u8, // :74 default AUTODETECT(0)
}

/// THE NSDMI FACE (`int stack_depth = -1;` :73) — a DERIVED Default would
/// land 0 and ARM the :196 depth gate (the vectors' M2/M9 default-cfg PASS
/// faces prove the -1 sentinel); hand-written per the ground NSDMI.
impl Default for MplsCodecConfig {
    fn default() -> Self {
        MplsCodecConfig { stack_depth: -1, payload_type: MPLS_PAYLOADTYPE_AUTODETECT } // :73/:74
    }
}

/// decode_data.h:177 `snort::mpls::MplsHdr mplsHdr = {}` (protocols/mpls.h
/// :29-:35 FOUR fields label/tc/bos/ttl, value-init 0) — the row-scoped
/// DecodeData SEAM twin (the cd_frag.rs:84 FragDecodeData / cd_esp / cd_udp
/// precedent: the real DecodeData owner stays OPEN; the vectors print the
/// bo/lab/t/ttl faces straight off these fields).
#[derive(Debug, Default, Clone, Copy)]
pub struct MplsHdr {
    pub label: u32, // mpls.h:31
    pub tc: u8, // mpls.h:32
    pub bos: u8, // mpls.h:33
    pub ttl: u8, // mpls.h:34
}

/// :77-:106 `class MplsModule : public BaseCodecModule` — the :80 3-arg
/// ctor face (name/help/`mpls_params`); get_rules :82-:83; `begin` resets
/// the config {} :85-:89; the :91-:99 `set` reads `v.is(...)` — THE
/// BINDING-DRIVEN face (Value::is() compares the BOUND parameter, the
/// called-name arg rides IGNORED — the faceA `SET mpls ret=111` honest
/// ground face the probe census pins); `get_data()` :101-:102 feeds the
/// config-carrying ctor :352.
#[derive(Debug)]
pub struct MplsModule {
    pub base: BaseCodecModule,
    pub config: MplsCodecConfig,
}

impl MplsModule {
    /// :80 the ctor face: `BaseCodecModule(CD_MPLS_NAME, CD_MPLS_HELP,
    /// mpls_params)` + the :73/:74 NSDMI config face.
    pub fn new() -> MplsModule {
        MplsModule {
            base: BaseCodecModule::new_with_params(CD_MPLS_NAME, CD_MPLS_HELP, &MPLS_PARAMS),
            config: MplsCodecConfig::default(), // :73/:74 NSDMI (-1, AUTO)
        }
    }

    /// :82-:83 the get_rules override -> the stored 8-row table (7 + term).
    pub fn get_rules(&self) -> &'static [RuleMap] {
        &MPLS_RULES
    }

    /// :85-:89 `begin` — `config = { }` then true (the per-reload reset
    /// face; the begin-time config reset the SET ladder rides).
    pub fn begin(&mut self, _name: &str, _index: i32) -> bool {
        self.config = MplsCodecConfig::default(); // :87 `config = { }`
        true
    }

    /// :91-:99 the set ladder — `v.is("max_stack_depth")` ->
    /// `v.get_int16()` :94; else-if `v.is("payload_type")` ->
    /// `v.get_uint8()` :96; `return true` :98 UNCONDITIONAL (the silent
    /// arms — an unmatched Value STILL returns true, the ret=111 face
    /// incl the bogus-name binding arm). The const char* arg UNREAD (the
    /// `is()`-binding face — faceA honest note); the SnortConfig* param
    /// UNNAMED (never-read posture).
    pub fn set(&mut self, _name: &str, v: &mut Value) -> bool {
        if v.is("max_stack_depth") {
            // :94 `config.stack_depth = v.get_int16();` — i16 -> int
            // widening kept by cast.
            self.config.stack_depth = i32::from(v.get_int16());
        } else if v.is("payload_type") {
            self.config.payload_type = v.get_uint8(); // :96
        }
        true // :98
    }

    /// :101-:102 `const MplsCodecConfig& get_data()` — the ctor(m) feed.
    pub fn get_data(&self) -> MplsCodecConfig {
        self.config // :352 `mod->get_data()`
    }
}

impl Default for MplsModule {
    fn default() -> Self {
        Self::new()
    }
}

/// :108-:124 `class MplsCodec : public Codec` — get_protocol_ids :113 /
/// decode :114 / encode :115-:116 / log :117 overrides + the
/// `Codec(CD_MPLS_NAME)` ctor face :111 + stored config + the
/// validate_reserved_label PRIVATE helper :120. Stack-owned Rust posture
/// (18d).
#[derive(Debug, Default)]
pub struct MplsCodec {
    pub config: MplsCodecConfig,
}

/// :137-:157 `static inline void decode_mpls_entry(const uint32_t* entry,
/// uint32_t& label, uint8_t& tc, uint8_t& bos, uint8_t& ttl)` — THE rfc5462
/// bit layout (ground ASCII art :139-:149 rides the module cite: Label 20b
/// / TC 3b / S 1b / TTL 8b). ntohl face: the Rust BE-read lands the SAME
/// word. WRITE ORDER kept verbatim (:152 ttl :153 shift :154 bos :155 raw
/// tc :156 label): ttl = low byte; shift 8; bos = &1; tc = &0x0E RAW
/// UNNORMALIZED (the M2 `t=2` store face); label = (h>>4)&0xFFFFF ==
/// (w>>12)&0xFFFFF. Tuple return mirrors the C out-params.
#[inline]
pub fn decode_mpls_entry(w: u32) -> (u32, u8, u8, u8) {
    let ttl = (w & 0x0000_00FF) as u8; // :152
    let mpls_h = w >> 8; // :153
    let bos = (mpls_h & 0x0000_0001) as u8; // :154
    let tc = (mpls_h & 0x0000_000E) as u8; // :155
    let label = (mpls_h >> 4) & 0x000F_FFFF; // :156
    (label, tc, bos, ttl)
}

impl MplsCodec {
    /// :111 `MplsCodec(const MplsCodecConfig& config = { }) :
    /// Codec(CD_MPLS_NAME), config(config)` — the DEFAULT face (the
    /// probe's ctor(nullptr): depth -1 / plt AUTO) + the CONFIG-CARRYING
    /// :352 feed face (ctor(m) -> new_from).
    pub fn new(config: MplsCodecConfig) -> MplsCodec {
        MplsCodec { config }
    }

    /// :341-:355 `static Codec* ctor(Module* m)` — THE CONFIG-CARRYING
    /// face (the contrast to the link4 trio's Module*-ignored ctors,
    /// harness probe.cc:9-12): `if (m)` :349 -> static_cast + `new
    /// MplsCodec(mod->get_data())` :351-:352; else `new MplsCodec()`
    /// :354. None == the ctor(nullptr) default window (the DEC cc2 face).
    pub fn ctor(m: Option<&MplsModule>) -> MplsCodec {
        match m {
            Some(mod_) => MplsCodec::new(mod_.get_data()), // :351-:352
            None => MplsCodec::default(), // :354 `new MplsCodec()`
        }
    }

    /// :130-:135 out-of-line get_protocol_ids — the DETERMINISTIC std::
    /// vector emplace x3 face (probe.cc ORDER-PINNS the block positionally
    /// — contrast the vlan unordered-SET walk): UNICAST :132 / MULTICAST
    /// :133 / MPLS_IP :134 (137, the RESIDENT protocol_id landing).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(ETHERTYPE_MPLS_UNICAST); // :132 (34887)
        v.push(ETHERTYPE_MPLS_MULTICAST); // :133 (34888)
        v.push(protocol_id::MPLS_IP); // :134 (137, framework/codec.rs :151 RESIDENT)
    }

    /// :159-:244 out-of-line decode — statement order VERBATIM, THE
    /// label-stack walk. `snort` is the mplsHdr-seam operand (the third C
    /// param DecodeData&); `bypass` is the landed LEFT-OPEN hook seam (the
    /// cd_vxlan/cd_gtp/cd_geneve closure face for the :205 conf->
    /// tunnel_bypass_enabled read). R6 eval order EVERY compound: vars
    /// land BEFORE the comparisons; the :181 validate runs PER-ENTRY
    /// INSIDE the walk BEFORE any BoS capture (the M8 :181-before-:186
    /// eval-order receipt — entry 8 NEVER captured, pb NEVER set).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut MplsHdr,
        sink: QueueSink<'_>,
        bypass: &mut dyn FnMut(u16) -> bool,
    ) -> bool {
        let mut bos: u8 = 0; // :161
        let mut depth: u8 = 0; // :162 (C uint8_t — the wrap face kept via
                               // wrapping_add; the -1 sentinel gate NEVER
                               // lets ++depth free-run at sane depths)
        let mut stack_len: u32 = raw.len; // :163 (uint32_t)
        let mut off: usize = 0; // :165 `mpls_entry` cursor (advances :193)

        while bos == 0 {
            // :169-:172 `if (stack_len < MPLS_HEADER_LEN)` -> EV 170 +
            // return false — lyr NEVER set (:208 unreached), mplsHdr
            // NEVER touched (the M1 face; M15 re-fires it AT the drain,
            // the face a tail-count-only rule MISSES).
            if stack_len < MPLS_HEADER_LEN {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_BAD_MPLS as u32,
                    &mut *sink,
                ); // :171
                return false; // :172
            }

            // :165/:179 the uint32_t* overlay read (BE wire, ntohl face).
            let w = u32::from_be_bytes([
                raw.data[off],
                raw.data[off + 1],
                raw.data[off + 2],
                raw.data[off + 3],
            ]);
            let (label, tc, bos_v, ttl) = decode_mpls_entry(w); // :179 out-params
            bos = bos_v;

            // :181 THE per-entry reserved-label gate (THE eval-order
            // receipt): the RANGE var lands FIRST, the validate call
            // short-circuits FALSE for labels >= 16; `return false` :182
            // rides BEFORE any capture (M8: 175x7 THEN 174, mplsHdr stays
            // value-init lab=0, pb stays 0).
            let in_reserved_range = label < NUM_RESERVED_LABELS; // :181 LHS
            if in_reserved_range
                && !self.validate_reserved_label(codec, label, bos, &mut *sink)
            {
                return false; // :182
            }

            // :184-:192 BoS capture + the proto_bits SET (the ONLY pb
            // write besides the :200 depth CLEAR — M2 bo=1 proves 512).
            if bos != 0 {
                snort.label = label; // :186
                snort.tc = tc; // :187
                snort.bos = bos; // :188
                snort.ttl = ttl; // :189
                codec.proto_bits |= crate::detection::rtn_checks::PROTO_BIT__MPLS; // :191 (RESIDENT 0x000200)
            }

            off += MPLS_HEADER_LEN as usize; // :193 mpls_entry++
            stack_len -= MPLS_HEADER_LEN; // :194

            // :196-:202 THE depth gate — eval order PINNED: the `!= -1`
            // sentinel var rides FIRST (the default -1 config NEVER ++'s
            // depth — M9's five entries PASS on the default cfg), the
            // ++depth pre-increment lands ONLY on the armed arm, then the
            // compare (C int promotion of the uint8 depth kept via cast).
            // :198 EV 176, :200 the ONLY proto_bits CLEAR (pb &= ~512 —
            // the M10 512->0 TRUE-CLEAR proof: capture RODE at entry 5
            // BEFORE the gate), :201 return false; entry-6 (the bos word)
            // NEVER read, lyr NEVER set.
            let depth_gate = self.config.stack_depth != -1; // :196 LHS
            if depth_gate {
                depth = depth.wrapping_add(1); // :196 ++depth (only if armed)
                if i32::from(depth) > self.config.stack_depth {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_MPLS_LABEL_STACK as u32,
                        &mut *sink,
                    ); // :198
                    codec.proto_bits &= !crate::detection::rtn_checks::PROTO_BIT__MPLS; // :200
                    return false; // :201
                }
            }
        } // :203 the peel-off loop comment rides

        // :205-:206 the BYPASS arm — the landed LEFT-OPEN hook closure
        // (module doc; the CARRIED witness_18f mask observable rides the
        // vectors' mask pair). Reached ONLY on a COMPLETED walk (M1/M6/
        // M8/M10/M15 NEVER arm it).
        let bypass_on = bypass(TUNNEL_MPLS); // :205
        if bypass_on {
            codec.tunnel_bypass = true; // :206
        }

        // :208 lyr_len = the consumed window (C pointer diff; the uint16
        // field trunc face kept by cast).
        codec.lyr_len = off as u16; // :208

        // :210-:241 THE LABEL-FIRST next-prot ladder — eval order is the
        // vectors' pin set (:211 beats :213 beats both forced :215-:220
        // arms beats the :221-:241 auto nibble): M3/M4 label0 -> 2048
        // OVERRIDES nibble 0x11/0x61; M13 label0 rides OVER forced eth;
        // M14 label0 rides OVER forced ip6 34525; M7/M18 label2 -> 34525
        // rides OVER forced eth 25944. dplt reads FIRST per :210.
        let dplt = self.config.payload_type; // :210
        if snort.label == 0 {
            codec.next_prot_id = protocol_id::ETHERTYPE_IPV4; // :212 (2048)
        } else if snort.label == 2 {
            codec.next_prot_id = protocol_id::ETHERTYPE_IPV6; // :214 (34525)
        } else if dplt == MPLS_PAYLOADTYPE_IPV4 {
            codec.next_prot_id = protocol_id::ETHERTYPE_IPV4; // :216 (M12 forced-vs-auto pin)
        } else if dplt == MPLS_PAYLOADTYPE_IPV6 {
            codec.next_prot_id = protocol_id::ETHERTYPE_IPV6; // :218
        } else if dplt == MPLS_PAYLOADTYPE_ETHERNET {
            codec.next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING; // :220 (row twin w/ the trans_bridge.rs:88 / cdTransBridge cite, protocol_ids.h :147 0x6558 = 25944)
        } else {
            // :222-:240 the first-nibble AUTODETECT arm (the ground
            // :224-:225 corner-case comment rides). :226-:227: label-only
            // stack (lyr_len == raw.len) -> return FALSE (the empty-
            // payload face; C uint16-vs-uint32 compare widened).
            if u32::from(codec.lyr_len) == raw.len {
                return false; // :227
            }
            let first_nibble = (raw.data[usize::from(codec.lyr_len)] >> 4) & 0x0F; // :228
            match first_nibble {
                4 => codec.next_prot_id = protocol_id::ETHERTYPE_IPV4, // :232
                6 => codec.next_prot_id = protocol_id::ETHERTYPE_IPV6, // :235
                _ => codec.next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING, // :238
            }
        }

        true // :243
    }

    /// :246-:272 out-of-line encode — VECTORIZED on the mirror face (the
    /// harness encodes it live on the nullptr witness; the Rust mirror
    /// stays unit-mirrored like 18l-18n). THE get_mpls_layer_per_dir SEAM
    /// lands as the `pflow_layer` Option PARAM (module doc — the cited
    /// left-open mirror: the harness witness_flow b76c809d returns nullptr
    /// -> ground :251 TRUE (:253 runs) + :255 FALSE -> the :249-:250 raw
    /// defaults ride; the vectors NEVER carry a non-null Flow). `enc.
    /// forward()` is the landed EncState face (:310-:311) — read ONLY
    /// through the mirror, never re-authored. The `assert(hdr_start)`
    /// :259 arm is the NDEBUG elide face (the misc9 -DNDEBUG law re-armed;
    /// Rust: the mirror type makes a null-start layer unrepresentable —
    /// honest CITE, never an invented check).
    pub fn encode(
        &self,
        raw_in: &[u8],
        raw_len: u16,
        enc: &mut EncState,
        buf: &mut Buffer<'_>,
        pflow_layer: Option<&MplsLayer<'_>>,
    ) -> bool {
        // :249-:250 the raw defaults ride FIRST (the C init faces).
        let mut hdr_len: u16 = raw_len; // :249
        let mut hdr_start: &[u8] = raw_in; // :250

        if let Some(layer) = pflow_layer {
            // :253 pflow->get_mpls_layer_per_dir(enc.forward()) -> the
            // Option param above; :255 `mpls_lyr && mpls_lyr->length` —
            // the length var lands first (R6), the Some-with-length arm
            // re-points the window (:257-:258).
            if layer.length != 0 {
                hdr_len = layer.length; // :257
                hdr_start = layer.start; // :258
            }
        }

        // :264-:265 `if (!buf.allocate(hdr_len)) return false;` — the
        // zero-size Buffer face (ENC b0: allocate(4) > max_len 0 -> the
        // honest false print).
        if !buf.allocate(u32::from(hdr_len)) {
            return false;
        }

        // :267 `memcpy_s(buf.data(), hdr_len, hdr_start, hdr_len);` — the
        // EXACTLY-1 safec use-site rides the STOCK #else shim (safec.h :23
        // +:33: memcpy_s -> memcpy; HAVE_SAFEC grep-0 — plan §5 decision
        // face): the Rust mirror is a PLAIN WINDOW COPY, NO shim authoring,
        // NO header rewrite (the copy-only 18n posture).
        let n = usize::from(hdr_len);
        let head = buf.data_mut().expect("allocate(hdr_len) just made size != 0");
        head[..n].copy_from_slice(&hdr_start[..n]); // :267 (the shim face)

        // :268-:269 the NOT_SET pair (vectors `netype 0 npro 255`,
        // protocol_ids.h :91/:122 faces, both RESIDENT imports).
        enc.next_ethertype = protocol_id::ETHERTYPE_NOT_SET; // :268
        enc.next_proto = ip_protocol::PROTO_NOT_SET; // :269

        true // :271
    }

    /// :320-:335 out-of-line log — cited-NEVER-called (the U closes vs the
    /// donor REAL text_log.o, harness §4), ported-by-reading with EVERY
    /// move cc-cited (the TextLog_Print seam precedent): the SAME uint32_t
    /// overlay walk on decode_mpls_entry :331 UNTIL bos (:325), the
    /// TextLog_Print format :332 `"\n\tlabel:0x%05X tc:0x%hhX bos:0x
    /// %hhX ttl:0x%hhX"` — the literal leading newline+tab kept in the
    /// seam string. The lyr_len param UNNAMED (:321) = never-read. NO
    /// bounds check in C (the caller's lyr_len bounds it); the seam feeds
    /// bos-terminated windows ONLY (honest cite, same posture as the C).
    pub fn log(&self, sink: &mut dyn FnMut(String), raw_pkt: &[u8]) {
        let mut off: usize = 0; // :323
        let mut bos: u8 = 0; // :324
        while bos == 0 {
            let w = u32::from_be_bytes([
                raw_pkt[off],
                raw_pkt[off + 1],
                raw_pkt[off + 2],
                raw_pkt[off + 3],
            ]);
            let (label, tc, b, ttl) = decode_mpls_entry(w); // :331
            bos = b;
            // :332 format VERBATIM semantics: %05X pads, the %hhX trio is
            // RAW uppercase hex (NO zero-pad face — `tc:0x2` not `0x02`).
            sink(format!(
                "\n\tlabel:0x{label:05X} tc:0x{tc:X} bos:0x{b:X} ttl:0x{ttl:X}"
            ));
            off += MPLS_HEADER_LEN as usize; // :333
        }
    }

    /// :277-:318 the PRIVATE `validate_reserved_label` — THE reserved-label
    /// switch, called ONLY with label below 16 (the :181 range gate; the
    /// 16-and-above face NEVER lands here — the `default:` arm below IS the
    /// :311-:314 4..15 SOFT arm, labels 0-3 ride their own cases). THE
    /// asymmetry set (EVERY arm cited, R6 var-first):
    /// - case 0 :283-:288: gate `bos && plt && plt != IPV4` — the DEFAULT
    ///   cfg plt AUTO(0) SHORT-CIRCUITS (M3/M4/M16/M17 SILENT faces);
    ///   EV 171 is SOFT: break, NO return (true rides — M13/M14). The RFC
    ///   :284-:285 comment rides.
    /// - case 1 :290-:297: `if (bos)` ONLY -> EV 172 + return FALSE
    ///   (:294-:295); MID-stack bos FALSE continues SILENTLY (M5 entry 1).
    /// - case 2 :299-:304: `bos && plt && plt != IPV6` — auto SILENT
    ///   (M7); the FORCED arm is the ONLY 173 face (M18: eth trips too —
    ///   the gate reads IPV6, and M14 mirrors it label0-side via IPV4).
    /// - case 3 :306-:309: UNCONDITIONAL EV 174 + return FALSE (M8 at
    ///   entry 8 — never captured).
    /// - default :311-:314: SOFT EV 175, break, CONTINUES (the 26-fire
    ///   census workhorse; :312-:313 comment rides).
    ///
    /// `plt` reads at :279 — the arm order is the C switch order.
    fn validate_reserved_label(
        &self,
        codec: &CodecData,
        label: u32,
        bos: u8,
        sink: QueueSink,
    ) -> bool {
        let plt = self.config.payload_type; // :279

        match label {
            0 => {
                // :286 `if (bos && plt && plt != MPLS_PAYLOADTYPE_IPV4)` —
                // vars first, short-circuit order kept.
                let bos_on = bos != 0;
                let plt_forced = plt != 0;
                let plt_not_ip4 = plt != MPLS_PAYLOADTYPE_IPV4;
                if bos_on && plt_forced && plt_not_ip4 {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_BAD_MPLS_LABEL0 as u32,
                        &mut *sink,
                    ); // :287 (SOFT)
                }
            } // :288 break
            1 => {
                let bos_on = bos != 0; // :292 var first
                if bos_on {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_BAD_MPLS_LABEL1 as u32,
                        &mut *sink,
                    ); // :294
                    return false; // :295
                }
            } // :297 break (mid-stack label1 rides SILENT)
            2 => {
                // :302 — the IPV6 gate face (mirror image of case 0's
                // IPV4 read).
                let bos_on = bos != 0;
                let plt_forced = plt != 0;
                let plt_not_ip6 = plt != MPLS_PAYLOADTYPE_IPV6;
                if bos_on && plt_forced && plt_not_ip6 {
                    crate::framework::codec::codec_event(
                        codec,
                        CodecSid::DECODE_BAD_MPLS_LABEL2 as u32,
                        &mut *sink,
                    ); // :303 (SOFT)
                }
            } // :304 break
            3 => {
                // :308 UNCONDITIONAL — `label 3 ... should never actually
                // appear in a stack` (:307). FATAL.
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_BAD_MPLS_LABEL3 as u32,
                    &mut *sink,
                );
                return false; // :309
            }
            _ => {
                // :311-:314 the 4..15 SOFT arm (the :181 range gate keeps
                // >=16 out; `Labels 4-15 are reserved without any current
                // special meaning` :312).
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_MPLS_RESERVED_LABEL as u32,
                    &mut *sink,
                ); // :313 (SOFT CONTINUES)
            }
        }

        true // :317
    }
}

/// THE left-open Flow seam (module doc): the C `Flow* pflow` operand
/// :246-:247 reaches `pflow->get_mpls_layer_per_dir(enc.forward())` :253
/// (flow.h :223 decl; the per-dir client/server Layer* walk flows flow.cc —
/// CITED NEVER ported). The harness closes the U with witness_flow.cc 27 L
/// (b76c809d) returning nullptr — the ONLY observationally-safe mirror at
/// the sole call site (:255 falls to the raw path, the vectorized face).
/// The Rust twin is this Option-valued struct: None == the C nullptr (the
/// mirror face), None-with-length-0 keeps the `->length` sub-arm; the REAL
/// provider stays queued with the flow rows — NEVER invented here.
#[derive(Debug)]
pub struct MplsLayer<'a> {
    pub length: u16, // layer.h Layer::length (the :255/:257 read)
    pub start: &'a [u8], // layer.h Layer::start (the :258 read)
}

// :337-:339 the "api" separator banner rides. :341-:342 `static Module*
// mod_ctor() { return new MplsModule; }` + :344-:345 `mod_dtor` ride
// behavior-only cites (record mod slots SET — faceA `mpls mod_ctor=1
// mod_dtor=1`; the Rust mod face is MplsModule::new; the dtor folds onto
// the stack-owned drop, 18d posture). :347-:355 `static Codec* ctor
// (Module* m)` — THE config-carrying face lands above (MplsCodec::ctor:
// `if (m)` threads get_data(), else the NSDMI default); :357-:358 `static
// void dtor(Codec* cd)` SET.

/// :360-:380 `static const CodecApi mpls_api` — NAME/HELP slots :369/:370
/// land the :34/:35 macro faces; mod arms :371/:372 REAL (mod_ctor :341 /
/// mod_dtor :344 — the nullptr-FREE face); pinit :374 / pterm :375 / tinit
/// :376 / tterm :377 nullptr WITH the ground slot comments; ctor :378 (`//
/// ctor`) + dtor :379 (`// dtor`) SET — ctor being the config-carrying one.
pub const MPLS_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC,              // :363
    size: CDAPI_SIZEOF_CODEC_API, // :364 sizeof(CodecApi)=112 (faceA size pin)
    api_version: CDAPI_VERSION,   // :365 1900547
    version: 0,                   // :366
    features: PLUGIN_SO_RELOAD,   // :367
    options: API_OPTIONS,         // :368
    name: CD_MPLS_NAME,           // :369 -> "mpls"
    help: CD_MPLS_HELP,           // :370
    mod_ctor: true,               // :371 SET (mod_ctor :341 REAL)
    mod_dtor: true,               // :372 SET (mod_dtor :344 REAL)
    pinit: false,                 // :374 nullptr // pinit
    pterm: false,                 // :375 nullptr // pterm
    tinit: false,                 // :376 nullptr // tinit
    tterm: false,                 // :377 nullptr // tterm
    ctor: true,                   // :378 SET  // ctor (config-carrying :347)
    dtor: true,                   // :379 SET  // dtor
};

/// :382-:390 the hidden export, TRUE-NAME: `#ifdef BUILDING_SO` :382 / SO
/// arm snort_plugins[] :383 / `#else` :384 / the static-build
/// `const BaseApi* cd_mpls[] =` :385 feeding `&mpls_api.base` :388 +
/// nullptr :389 (ONE feed — faceA `LOAD mpls` + `LOADS 1`). nm: cd_mpls D EXACTLY-1 ==
/// FILE base (the 18n TRUE-NAME EQUALITY pin rides build.sh — NO drift
/// refusal needed at THIS row). Ladder entry "cd_mpls" RESIDENT
/// codec_api.rs :119 (ground extern codec_api.cc :61, load :106) NEVER
/// re-touched — THIS row TURNS it loaded.
pub const CD_MPLS: CodecTable = &[&MPLS_API];
