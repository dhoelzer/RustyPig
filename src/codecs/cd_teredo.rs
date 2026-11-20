//! Port of `src/codecs/misc/cd_teredo.cc` (161 L) — row 18f.
//! Ground: snort3-src @ fe29cbe, md5 `649dde0666ee14a9514cd02744815dd5`
//! (tun PLAN §0). DIR FACT: `codecs/misc/`.
//!
//! TRUE-NAME FACT (tun PLAN §0): file base == extern table name on this
//! row — `cd_teredo` at cc:155 (the BUILDING_SO ternary face :152-:160),
//! NO cd-hop_opts-style drift tripwire here.
//!
//! MODULE-PAIR ASYMMETRY (the 18f honest arm): the teredo_api record
//! carries nullptr mod_ctor/mod_dtor (cc:141-:142) — the ONLY tunnel TU
//! of the trio WITHOUT a Module pair (gtp cc:271-:272 and geneve
//! cc:263-:264 set theirs). Pinned twice: vectors_faceA.txt:7 `API
//! teredo mod_ctor=0` + vectors.txt:40 `TER mod_ctor=0 mod_dtor=0`,
//! and the nm census shows ZERO `Module::Module` U-lines for
//! cd_teredo.o vs 1 each for gtp/geneve (build.sh E2 asserts).
//!
//! ZERO-EVENT ASYMMETRY: TeredoCodec::decode raises NO codec_event on
//! any arm (the C TU emits no codec_event U-line at all — the ONLY one
//! of the trio; gtp/geneve carry exactly 1 each, build.sh E2). The
//! decode signature therefore carries NO QueueSink.
//!
//! THE BYPASS HOOK — LEFT-OPEN RULING (tun PLAN §4/§7, named in
//! deviations row 18f): cc:106 `codec.conf->tunnel_bypass_enabled(
//! TUNNEL_TEREDO)` is the ground conf read (def main/snort_config.cc
//! :1020-:1023 `!((tunnel_mask & proto) or SFDAQ::get_tunnel_bypass(
//! proto))`; tunnel_mask snort_config.h:393 NSDMI 0). The production
//! provider (the SnortConfig field + the SFDAQ arm, DAQ = plan row 20)
//! stays OPEN: this row lands the call site as an explicit hook
//! parameter `&mut dyn FnMut(u16) -> bool` (the landed QueueSink
//! callback precedent, framework/codec.rs) and the parity replay's
//! hook mirrors tools/tun_harness/witness_18f.cc byte-exactly
//! (observable table + ground-shaped return, daq arm pinned false).
//!
//! ROW-SCOPED VOCAB (15-path staging; deviations row 18f): the three
//! protocol_ids.h / decode_data.h / snort_config.h numerics this TU
//! touches, plus the teredo.h inline machinery, land HERE with the C
//! cites (framework/codec.rs and parse_conf.rs byte-UNTOUCHED this row
//! — the 18e posture; the tunnel_mask config-row homes are queued).
//!
//! THE PORTS SEAM (cc:109 reads snort.sp / snort.dp): the DecodeData
//! operand's two port reads ride the minimal read-only seam
//! `TeredoPorts` below (the 18e IpApiLite precedent) — who feeds
//! sp/dp per packet stays OPEN for the parser rows.

use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CodecTable, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION,
    CODEC_ENCAP_LAYER, CODEC_NON_IP_TUNNEL, CODEC_TEREDO_SEEN, CodecData, PLUGIN_SO_RELOAD,
    ProtocolId, RawData,
};

/// cc:33 `#define CD_TEREDO_NAME "teredo"`
pub const CD_TEREDO_NAME: &str = "teredo";
/// cc:34 `#define CD_TEREDO_HELP "support for teredo"` — vectors:6 face.
pub const CD_TEREDO_HELP: &str = "support for teredo";

// ---- protocols/teredo.h constexprs (row-scoped housing, cite per row) ----
/// teredo.h:29 `TEREDO_PORT = 3544`
pub const TEREDO_PORT: u16 = 3544;
/// teredo.h:30 `INDICATOR_ORIGIN = 0x00`
pub const INDICATOR_ORIGIN: u16 = 0x00;
/// teredo.h:31 `INDICATOR_ORIGIN_LEN = 8`
pub const INDICATOR_ORIGIN_LEN: u16 = 8;
/// teredo.h:32 `INDICATOR_AUTH = 0x01`
pub const INDICATOR_AUTH: u16 = 0x01;
/// teredo.h:33 `INDICATOR_AUTH_MIN_LEN = 13`
pub const INDICATOR_AUTH_MIN_LEN: u16 = 13;
/// teredo.h:34 `MIN_HDR_LEN = 2`
pub const MIN_HDR_LEN: u16 = 2;
/// teredo.h:35 `INDICATOR_LEN = MIN_HDR_LEN`
pub const INDICATOR_LEN: u16 = MIN_HDR_LEN; // C alias, kept verbatim
/// teredo.h:36 `IPV6_VERSION_FIELD_LEN = 1`
pub const IPV6_VERSION_FIELD_LEN: u16 = 1;

/// teredo.h:38-:39 `is_teredo_port(uint16_t port) { return port ==
/// TEREDO_PORT; }` — read at cc:109 twice (sp then dp).
#[inline]
pub fn is_teredo_port(port: u16) -> bool {
    port == TEREDO_PORT
}

/// decode_data.h:94 `#define PROTO_BIT__TEREDO 0x000080` — OR at
/// cc:103. vectors:10 `bits=128` (decimal face of 0x80).
pub const PROTO_BIT__TEREDO: u32 = 0x000080;

/// snort_config.h:120 `TUNNEL_TEREDO = 0x02` (enum TunnelFlags
/// :117-:128) — the argument of the cc:106 bypass call. DEC probe
/// face mask0002 (vectors:10 bypass=0) / mask0000 (vectors:9 1).
pub const TUNNEL_TEREDO: u16 = 0x02;

/// protocol_ids.h:128 `TEREDO = 0x0101` (== 257) — the
/// get_protocol_ids head (cc:50) AND the CodecData init proto the
/// probe hands (probe_dec.cc:23 `ProtocolId::TEREDO`). vectors:12
/// `TERPID 257 n=1`. Row-scoped until the protocol_ids table row
/// (deviations bullet: 15-path staging; named in
/// STATIC_CODEC_EXTERN_NAMES :126 "cd_teredo" — already resident).
pub const PROTOCOL_ID_TEREDO: ProtocolId = 0x0101;

/// THE ports seam (module doc): the read-only stand-in for the TWO
/// DecodeData port reads of cc:109 (named `snort` in C, cc:53 — kept
/// as the param name). NOT a DecodeData port — the producing layer
/// stays open. C fixture face (teredo_codec_test.cc:79-:80):
/// sp 3544 / dp 6666; the DEC probe face leaves both 0 (ports-off,
/// vectors:11 `flags=646` — the ENCAP arm FIRES).
#[derive(Copy, Clone, Default)]
pub struct TeredoPorts {
    pub sp: u16, // cc:109 snort.sp
    pub dp: u16, // cc:109 snort.dp
}

/// cc:38-:45 `class TeredoCodec : public Codec` — anonymous-namespace
/// class; name slot via Codec(CD_TEREDO_NAME) (cc:41) rides the record.
#[derive(Default)]
pub struct TeredoCodec;

impl TeredoCodec {
    /// cc:41 `TeredoCodec() : Codec(CD_TEREDO_NAME) { }`
    pub fn new() -> TeredoCodec {
        TeredoCodec
    }

    /// cc:48-:51 `v.emplace_back(ProtocolId::TEREDO)` — vectors:12
    /// `TERPID 257 n=1`.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(PROTOCOL_ID_TEREDO); // cc:50
    }

    /// cc:53-:118 out-of-line decode, statement order VERBATIM.
    /// No sink: the zero-event asymmetry (module doc). `bypass` is
    /// the left-open hook for the cc:106 conf read.
    #[allow(clippy::collapsible_if)] // literal C nesting kept (codec.rs:610 precedent)
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &TeredoPorts,
        bypass: &mut dyn FnMut(u16) -> bool,
    ) -> bool {
        // cc:55-:62: `const uint8_t* raw_pkt = raw.data; uint32_t
        // consumed = 0;` + the get_indicator lambda (`memcpy(&value,
        // p, 2); ntohs(value)` == big-endian u16 read).
        let mut raw_pkt: usize = 0;
        let mut consumed: u32 = 0; // cc:56
        let get_indicator = |p: usize| -> u16 {
            // C reads two bytes unchecked at the cursor; the get-or-0
            // posture stands where C would overrun (every probe arm
            // stays in bounds — the .get never substitutes 0 there).
            u16::from_be_bytes([
                *raw.data.get(p).unwrap_or(&0),
                *raw.data.get(p + 1).unwrap_or(&0),
            ])
        };

        // cc:64-:65 `if (raw.len < teredo::MIN_HDR_LEN) return false;`
        // vectors:7 `TER short1 -> 0` (len 1 < 2).
        if raw.len < u32::from(MIN_HDR_LEN) {
            return false;
        }

        // cc:67-:82 the AUTH indicator block ("Decode indicators. If
        // both are present, Auth always comes before Origin." cc:67).
        // vectors:8 the AUTH-seen-but-short face (`TER auth-shord`:
        // indicator 0x0001 at len 3 < 13).
        if get_indicator(raw_pkt) == INDICATOR_AUTH {
            // cc:70-:71 `if (raw.len < INDICATOR_AUTH_MIN_LEN) return false;`
            if raw.len < u32::from(INDICATOR_AUTH_MIN_LEN) {
                return false;
            }
            // cc:73-:74 the two length bytes AFTER the 2-byte indicator.
            #[allow(clippy::unwrap_or_default)] // bounds posture mirrors C unchecked read
            let client_id_length: u8 = *raw.data.get(raw_pkt + 2).unwrap_or(&0); // cc:73
            let auth_data_length: u8 = *raw.data.get(raw_pkt + 3).unwrap_or(&0); // cc:74
            // cc:76-:77 the total-length gate (uint32_t cast kept):
            let need = u32::from(INDICATOR_AUTH_MIN_LEN)
                + u32::from(client_id_length)
                + u32::from(auth_data_length);
            if raw.len < need {
                return false; // kept separate from the outer nesting: literal C shape
            }
            // cc:79-:81 consumed advance + lyr_len assignment (NOT +=:
            // the AUTH arm ASSIGNS).
            consumed = need;
            raw_pkt += consumed as usize;
            codec.lyr_len = consumed as u16; // cc:81 (C uint32 -> u16 trunc face)
        }

        // cc:84-:85 `if (raw.len < consumed + teredo::INDICATOR_LEN) return false;`
        if raw.len < consumed + u32::from(INDICATOR_LEN) {
            return false;
        }

        // cc:87-:95 the ORIGIN indicator block.
        if get_indicator(raw_pkt) == INDICATOR_ORIGIN {
            // cc:89-:90
            if raw.len < consumed + u32::from(INDICATOR_ORIGIN_LEN) {
                return false;
            }
            // cc:92-:94 the += pair (consumed AND lyr_len — the AUTH
            // arm assigns, this one accumulates: operand per-arm audit).
            raw_pkt += usize::from(INDICATOR_ORIGIN_LEN);
            consumed += u32::from(INDICATOR_ORIGIN_LEN);
            codec.lyr_len = codec.lyr_len.wrapping_add(INDICATOR_ORIGIN_LEN); // cc:94
        }

        // cc:97-:98 `if (raw.len < consumed + teredo::IPV6_VERSION_FIELD_LEN) return false;`
        if raw.len < consumed + u32::from(IPV6_VERSION_FIELD_LEN) {
            return false;
        }

        // cc:100-:101 `/* If this is an IPv6 datagram, the first 4
        // bits will be the number 6. */ if (((*raw_pkt & 0xF0) >> 4)
        // == 6)` — the deref is at the CURSOR (raw_pkt), the
        // get-or-0 posture stands (probe face: 0x60 @ index 8).
        if ((*raw.data.get(raw_pkt).unwrap_or(&0) & 0xF0) >> 4) == 6 {
            // cc:102-:114 the success block, operand identity per arm:
            codec.proto_bits |= PROTO_BIT__TEREDO; // cc:103
            codec.codec_flags |= CODEC_TEREDO_SEEN; // cc:104 `// for ipv6 codec`

            // cc:106-:107 the BYPASS arm — left-open hook (module doc):
            // ground conf->tunnel_bypass_enabled(TUNNEL_TEREDO).
            if bypass(TUNNEL_TEREDO) {
                codec.tunnel_bypass = true;
            }

            // cc:109-:110 `if ((!is_teredo_port(snort.sp)) && (!
            // is_teredo_port(snort.dp))) codec.codec_flags |=
            // CODEC_ENCAP_LAYER;` — short-circuit order kept; the
            // probe face ports 0/0 -> the arm FIRES (vectors:10/:11
            // flags=646 = 0x286 = TEREDO_SEEN|ENCAP|NON_IP_TUNNEL).
            if (!is_teredo_port(snort.sp)) && (!is_teredo_port(snort.dp)) {
                codec.codec_flags |= CODEC_ENCAP_LAYER;
            }

            codec.next_prot_id = crate::framework::codec::protocol_id::IPV6; // cc:112 (41 — vectors:10 next=41)
            codec.codec_flags |= CODEC_NON_IP_TUNNEL; // cc:113
            return true; // cc:114
        }

        // cc:117 the nibble-miss face (probe never arms it — literal).
        false
    }
}

// cc:124-:125 `static Codec* ctor(Module*) { return new TeredoCodec();
// }` + cc:127-:128 dtor — the ctor/dtor presence slots on the record
// below; no heap ownership on the Rust face (row-18d posture).
// NO mod_ctor/mod_dtor for this TU: cc:141-:142 the two base slots are
// the nullptr pair (the trio asymmetry, module doc).

/// cc:130-:150 `static const CodecApi teredo_api` — vectors:5 `API
/// teredo type=0 size=112 ver=1900547 name=teredo` + vectors:6 HELP.
/// The pinit/pterm/tinit/tterm quartet (cc:144-:147) + the
/// mod pair (cc:141-:142) ALL nullptr — the mod_ctor=0 honest arm
/// re-pinned by DEC vectors:40.
pub const TEREDO_API: CodecApiRecord = CodecApiRecord {
    ptype: crate::framework::codec::PT_CODEC, // cc:133
    size: CDAPI_SIZEOF_CODEC_API,             // cc:134 sizeof(CodecApi)=112
    api_version: CDAPI_VERSION,               // cc:135 1900547
    version: 0,                               // cc:136
    features: PLUGIN_SO_RELOAD,               // cc:137
    options: API_OPTIONS,                     // cc:138
    name: CD_TEREDO_NAME,                     // cc:139
    help: CD_TEREDO_HELP,                     // cc:140
    mod_ctor: false,                          // cc:141 nullptr — the ASYMMETRY face
    mod_dtor: false,                          // cc:142 nullptr
    pinit: false,                             // cc:144
    pterm: false,                             // cc:145
    tinit: false,                             // cc:146
    tterm: false,                             // cc:147
    ctor: true,                               // cc:148
    dtor: true,                               // cc:149
};

/// cc:152-:160 `#ifdef BUILDING_SO / SO_PUBLIC const BaseApi*
/// snort_plugins[] = #else const BaseApi* cd_teredo[] = #endif {
/// &teredo_api.base, nullptr }` — the non-SO face (the name the
/// STATIC_CODEC_EXTERN_NAMES census :126 carries).
pub const CD_TEREDO: CodecTable = &[&TEREDO_API];
