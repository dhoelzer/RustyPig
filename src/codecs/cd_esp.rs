//! Port of `src/codecs/ip/cd_esp.cc` (227 L) — row 18h (the small four,
//! harness `tools/small4_harness`, ZERO-gate probe-only row).
//! Ground: snort3-src @ fe29cbe, md5 `d9a20eae70244e652c54fc4c0281f7bd`
//! wc 227 (both asserted EVERY build by small4 build.sh :36-:41).
//! DIR FACT: `codecs/ip/` (includes.txt face: cc:22/:25/:26/:27 — ONLY
//! the four resident headers, ZERO fresh cps, DAQ-FREE).
//!
//! TRUE NAME holds this row: file base == table name `cd_esp[]` at
//! cc:221 with the REAL BUILDING_SO arms :218-:222 (sed-asserted every
//! build, build.sh :48-:49); extern cd_ah-family face does NOT apply
//! HERE — that drift owns the cd_auth row (see cd_auth.rs).
//!
//! CONFIG GATE — LEFT-OPEN SEAM (small4 PLAN §8, the 18e IpApiLite /
//! 18f TeredoPorts / 18g bypass-hook precedent): cc:100
//! `codec.conf->esp_decoding()` reads the C SnortConfig NSDMI
//! `enable_esp = false` (snort_config.h :281, grep-asserted at
//! build.sh). The production config provider stays QUEUED (config rows
//! land in the parse layer); the call site lands as the decode param
//! `decode_esp: bool` and the replay re-arms it per arm exactly where
//! probe_dec.cc writes conf.enable_esp. vectors:1 `ESP gate-off -> 0`
//! is the false arm (NO event, NO mutation); every later esp arm runs
//! with true.
//!
//! DECODE-DATA SEAM: C `snort.ip_api.is_ip6()` (cc:127) lands as the
//! row-scoped `EspDecodeData::is_ip6` read face (IpApiLite precedent);
//! the DECODE_PKT_TRUST write (cc:152/:170) rides the SAME struct's
//! decode_flags. Row-scoped VOCAB (18g posture: framework/codec.rs +
//! parse_conf.rs BYTE-UNTOUCHED): DECODE_PKT_TRUST 0x20 lands here
//! with the decode_data.h h:140 cite.
//!
//! C MUTATES raw.len through the cc:141-:142 const_cast ("FIXIT-L
//! shouldn't this be raw.len = guessed_len?" — the upstream TODO rides
//! the port unchanged): the Rust form keeps a LOCAL len copy; no
//! vectors line reads raw.len after decode, so the observable face is
//! identical (deviations row 18h). The cc:146 pad test compares
//! pad_length against the MUTATED len (len − 14), kept EXACT.
//!
//! UNCHECKED READS (the C reinterpret-pose): cc:122-:123 read
//! esp_payload[guessed_len] / [guessed_len+1] past nothing at the
//! pinned faces (len 24 -> indices 10/11 in-bounds); the .get-or-zero
//! form only keeps short hostile inputs panic-free, NEVER fires in
//! replay (the cd_hop_opts posture).
//!
//! sids ALL resident: DECODE_ESP_HEADER_TRUNC h:147->294,
//! DECODE_IP6_EXCESS_EXT_HDR h:209->456 (codec_module.rs:154/:214);
//! the row adds ZERO constants. vectors:2 `EV 116 294` +
//! vectors:6/7 `EV 116 456`+`ESP maxopts -> 0` + vectors:8/9 the
//! ORDER-rides-a-success interleave `EV 116 296` / `flags=1030`
//! (CODEC_ENCAP_LAYER 6 | CODEC_IP6_EXT_OOO 0x400, decomposition
//! python-pinned BOTH ends in build.sh).

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecTable, CODEC_ENCAP_LAYER, CodecData,
    CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, DECODE_IP6_EXCESS_EXT_HDR, PLUGIN_SO_RELOAD,
    PROTO_BIT__IP6_EXT, PT_CODEC, ProtocolId, QueueSink, RawData, ip_protocol, protocol_id,
};
use crate::framework::parameter::{Parameter, Type as PtType};

/// cc:31 `#define CD_ESP_NAME "esp"`
pub const CD_ESP_NAME: &str = "esp";
/// cc:32 `#define CD_ESP_HELP "support for encapsulating security payload"`
/// — FACE-A `HELP esp ...` line (build.sh sed-pins the define itself).
pub const CD_ESP_HELP: &str = "support for encapsulating security payload";

/// cc:79-:81 the ESP length trio (`ESP_HEADER_LEN = 8`,
/// `ESP_AUTH_DATA_LEN = 12`, `ESP_TRAILER_LEN = 2`) — the cc:105
/// short-dgram guard sums to 22.
pub const ESP_HEADER_LEN: u32 = 8;   // h:79
pub const ESP_AUTH_DATA_LEN: u32 = 12; // h:80
pub const ESP_TRAILER_LEN: u32 = 2;    // h:81

/// decode_data.h:140 `DECODE_PKT_TRUST = 0x00000020` — row-scoped home
/// (18g posture; framework files byte-UNTOUCHED this row). vectors:5
/// `dflags=32` is the pad-huge face.
pub const DECODE_PKT_TRUST: u64 = 0x0020;

/// cc:36-:40 `static const RuleMap esp_rules[]` — ONE entry + the
/// `{ 0, nullptr }` terminator (the 1-entry grep census lives in
/// build.sh). vectors:11 `ESPRULES 1 sid0=294 name=esp`.
pub const ESP_RULES: [RuleMap; 2] = [
    RuleMap {
        sid: CodecSid::DECODE_ESP_HEADER_TRUNC as u32, // 294 (h:147)
        msg: Some("truncated encapsulated security payload header"), // cc:38 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:39 terminator
];

/// cc:42-:48 `static const Parameter esp_params[]` — the ONE
/// `decode_esp` PT_BOOL row with default `"false"` (the cc:100 gate's
/// face; build.sh greps `"false",` in the ground file) + the PT_MAX
/// terminator. The landed Parameter keeps name/ptype/deflt (range +
/// help nullptr here, parameter.rs:36-:41 carry-face).
pub const ESP_PARAMS: [Parameter; 2] = [
    Parameter {
        name: Some("decode_esp"), // cc:44
        ptype: PtType::PtBool,    // cc:44 Parameter::PT_BOOL
        deflt: Some("false"),     // cc:44 the gate default
    },
    Parameter {
        name: None,               // cc:47 terminator
        ptype: PtType::PtMax,     // cc:47 Parameter::PT_MAX
        deflt: None,
    },
];

/// cc:50-:67 `class EspModule : public BaseCodecModule` — 3-arg ctor
/// (params table) + get_rules() override + set() cc:58-:66.
#[derive(Debug)]
pub struct EspModule {
    pub base: BaseCodecModule,
}

impl EspModule {
    /// cc:53 `EspModule() : BaseCodecModule(CD_ESP_NAME, CD_ESP_HELP,
    /// esp_params) { }`
    pub fn new() -> EspModule {
        EspModule {
            base: BaseCodecModule::new_with_params(CD_ESP_NAME, CD_ESP_HELP, &ESP_PARAMS),
        }
    }

    /// cc:55-:56 `get_rules()` override.
    pub fn get_rules() -> &'static [RuleMap] {
        &ESP_RULES
    }

    /// cc:58-:66 `set(const char*, Value& v, SnortConfig* sc)`:
    /// `v.is("decode_esp")` -> `sc->enable_esp = v.get_bool()`, else
    /// `return false`. The SnortConfig WRITE lands QUEUED (the config
    /// provider row); the face here is the name-match + bool read-back:
    /// Some(value) on match, None models the `return false` arm.
    pub fn set(&self, name: &str, value: bool) -> Option<bool> {
        if name == "decode_esp" {
            // cc:61 sc->enable_esp = v.get_bool() — QUEUED provider
            return Some(value);
        }
        None // cc:63 return false
    }
}

impl Default for EspModule {
    fn default() -> Self {
        Self::new()
    }
}

/// The row-scoped DecodeData seam (module doc): the cc:127 is_ip6()
/// read + the cc:152/:170 decode_flags writes. NOT a full IpApi port.
#[derive(Copy, Clone, Default)]
pub struct EspDecodeData {
    pub is_ip6: bool,      // cc:127 snort.ip_api.is_ip6()
    pub decode_flags: u64, // cc:152/:170 `snort.decode_flags |= DECODE_PKT_TRUST`
}

#[derive(Default)]
pub struct EspCodec;

impl EspCodec {
    /// cc:72 `EspCodec() : Codec(CD_ESP_NAME) { }`
    pub fn new() -> EspCodec {
        EspCodec
    }

    /// cc:84-:85 out-of-line def — one emplace_back, vectors:10
    /// `ESPPID 50 n=1` (ProtocolId::ESP = 50, protocol_ids.h grep-pin).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::ESP); // cc:85
    }

    /// cc:94-:178 out-of-line decode, statement order VERBATIM.
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &mut EspDecodeData,
        decode_esp: bool, // cc:100 codec.conf->esp_decoding() — QUEUED provider
        sink: QueueSink,
    ) -> bool {
        // cc:100-:101 the config gate, the FIRST statement: false ->
        // no event, no mutation. vectors:1 `ESP gate-off -> 0`.
        if !decode_esp {
            return false;
        }

        // cc:105-:110 raw.len < (8+12+2) -> TRUNC + false. vectors:2/:3
        // `EV 116 294` + `ESP short21 -> 0`.
        if raw.len < (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN) {
            crate::framework::codec::codec_event(codec, ESP_HEADER_TRUNC_SID, sink);
            return false;
        }

        // cc:118 guessed_len from the original len.
        let guessed_len = raw.len - (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);

        // cc:120-:124 lyr_len, then the two payload reads esp_payload =
        // raw.data + ESP_HEADER_LEN: pad_length at +guessed_len,
        // ip_proto at +guessed_len+1 (.get-or-0 posture, module doc).
        codec.lyr_len = ESP_HEADER_LEN as u16; // cc:120
        let pad_length = *raw
            .data
            .get((ESP_HEADER_LEN + guessed_len) as usize)
            .unwrap_or(&0); // cc:122
        let ip_proto = *raw
            .data
            .get((ESP_HEADER_LEN + guessed_len + 1) as usize)
            .unwrap_or(&0); // cc:123
        codec.next_prot_id = ip_proto as ProtocolId; // cc:124 (ProtocolId) cast

        // cc:127-:139 the ip6 block ("must be called AFTER setting
        // next_prot_id" comment kept). maxopts latch -> 456 + false
        // (vectors:6/:7); then the landed order check cc:135 (vectors:8
        // EV 296 rides the SUCCESS at cc:177).
        if snort.is_ip6 {
            let hit = codec
                .conf
                .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
                .unwrap_or(false);
            if hit {
                crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, sink);
                return false;
            }
            crate::framework::codec::check_ipv6_extension_order(codec, ip_protocol::ESP, sink);
            codec.proto_bits |= PROTO_BIT__IP6_EXT; // cc:136
            codec.ip6_csum_proto = ip_proto; // cc:137
            codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1); // cc:138
        }

        // cc:142 the const_cast mutation -> LOCAL len (module doc).
        let mut len = raw.len - (ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);

        // cc:146-:156 the pad arm against the MUTATED len: small pad ->
        // subtract it; else TRUST + FINISHED_DECODE + true (the
        // pad255 face: vectors:5 `next=256 dflags=32`).
        if (pad_length as u32) < len {
            len -= pad_length as u32; // cc:148
            let _ = len; // mutated C value is never read again (no vectors face)
        } else {
            snort.decode_flags |= DECODE_PKT_TRUST; // cc:152
            codec.lyr_len = ESP_HEADER_LEN as u16; // cc:153 re-write, kept EXACT
            codec.next_prot_id = protocol_id::FINISHED_DECODE; // cc:154
            return true; // cc:155
        }

        // cc:167-:175 the next_prot_id > 0xFF guard. C comment cc:163-:166
        // says the arm can NEVER fire off the uint8 origin (FIXIT-L) —
        // dead-but-literal, transcribed diff-evident; NO probe arm ever
        // reaches it (the cc:153 FINISHED face returned at cc:155).
        if (codec.next_prot_id as u32) > 0xFF {
            codec.next_prot_id = protocol_id::FINISHED_DECODE; // cc:169
            snort.decode_flags |= DECODE_PKT_TRUST; // cc:170 — dead-arm write, kept literal
        } else {
            codec.codec_flags |= CODEC_ENCAP_LAYER; // cc:174 = 6 (SAVE 4 | UNSURE 2)
        }

        true // cc:177
    }
}

/// the sid via the resident CodecSid walk (zero new constants;
/// codec_module.rs:154 `DECODE_ESP_HEADER_TRUNC = 294  // h:147`)
const ESP_HEADER_TRUNC_SID: u32 = CodecSid::DECODE_ESP_HEADER_TRUNC as u32;

// cc:184-:194 static ctor/dtor pairs (mod_ctor/mod_dtor + ctor/dtor —
// ALL FOUR slots live at esp: vectors_faceA `esp mod_ctor=1
// mod_dtor=1` + record ctor/dtor true).

/// cc:196-:216 `static const CodecApi esp_api` — mod_ctor/mod_dtor SET
/// (cc:207-:208), pinit..tterm nullptr (cc:210-:213), ctor/dtor SET.
pub const ESP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:199
    size: CDAPI_SIZEOF_CODEC_API, // cc:200 (112 probe pin)
    api_version: CDAPI_VERSION, // cc:201 (1900547)
    version: 0,      // cc:202
    features: PLUGIN_SO_RELOAD, // cc:203
    options: API_OPTIONS, // cc:204
    name: CD_ESP_NAME, // cc:205
    help: CD_ESP_HELP, // cc:206
    mod_ctor: true,  // cc:207 SET
    mod_dtor: true,  // cc:208 SET
    pinit: false,    // cc:210
    pterm: false,    // cc:211
    tinit: false,    // cc:212
    tterm: false,    // cc:213
    ctor: true,      // cc:214
    dtor: true,      // cc:215
};

/// cc:218-:226 the export — REAL BUILDING_SO arms (:218-:222 sed-pins),
/// table `cd_esp[]` at :221 (TRUE name, no drift this TU). Fold
/// identical to 18c-18g: the nullptr terminator rides the slice length.
pub const CD_ESP: CodecTable = &[&ESP_API];
