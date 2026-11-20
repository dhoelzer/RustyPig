//! Port of `src/codecs/ip/cd_bad_proto.cc` (98 L) — row 18c.
//! Ground: snort3-src @ fe29cbe, md5 `5b1624c2c3bf87f6652736db1119f440`.
//! DIR FACT (NEXT.md 18c scoping): this TU lives in `codecs/ip/`, not
//! `codecs/root/`.
//!
//! The "bad protocol id" codec: answers SWIPE(53)+SUN_ND(77) on
//! get_protocol_ids (cc:44-:48), and its decode raises the
//! DECODE_IP_BAD_PROTO event and returns TRUE (cc:50-:55) — a codec
//! that swallows the packet as an event instead of decoding it.
//!
//! cc:34 spells the class `BadProtocalCodec` (upstream typo, "Protocal")
//! — kept VERBATIM as the Rust type name so the C-to-Rust diff stays
//! row-by-row auditable (literal-preservation rule).
//!
//! The decode arm calls the 17d `codec_event` (framework/codec.cc:85,
//! real home; the harness links the REAL framework/codec.o — nm census
//! RESOLVED, vocab PLAN §2) via the QueueSink seam. vectors:9 pins
//! `EV 116 450`, vector 10 `DECODE bad_proto -> 1`.

use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData, DECODE_IP_BAD_PROTO,
    PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, protocol_id,
};

/// cc:29 `#define CD_BAD_PROTO_NAME "bad_proto"`
pub const CD_BAD_PROTO_NAME: &str = "bad_proto";
/// cc:30 `#define CD_BAD_PROTO_HELP "bad protocol id"` — plain help,
/// no ADD_DLT (the DLT-appending macro is cd_raw's, codec.h:52).
pub const CD_BAD_PROTO_HELP: &str = "bad protocol id";

/// cc:34-:41 `class BadProtocalCodec : public Codec` — upstream typo
/// kept (module doc). Out-of-line member defs at cc:44-:55.
#[derive(Default)]
pub struct BadProtocalCodec;

impl BadProtocalCodec {
    /// cc:37 `BadProtocalCodec() : Codec(CD_BAD_PROTO_NAME) { }`
    pub fn new() -> BadProtocalCodec {
        BadProtocalCodec
    }

    /// cc:44-:48 out-of-line def: SWIPE then SUN_ND, emplace_back order
    /// verbatim (vectors:6/:7 `PID 53` `PID 77`).
    pub fn get_protocol_ids(&self, proto_ids: &mut Vec<ProtocolId>) {
        proto_ids.push(protocol_id::SWIPE);
        proto_ids.push(protocol_id::SUN_ND);
    }

    /// cc:50-:55 out-of-line def — "// currently unsupported": raise
    /// DECODE_IP_BAD_PROTO, return true. The RawData/DecodeData params
    /// are unnamed in C (never read); the sink threads the 17d
    /// queue_event witness seam.
    pub fn decode(
        &self,
        codec: &CodecData,
        sink: crate::framework::codec::QueueSink,
    ) -> bool {
        // cc:53 `codec_event(codec, DECODE_IP_BAD_PROTO);`
        crate::framework::codec::codec_event(codec, DECODE_IP_BAD_PROTO, sink);
        // cc:54
        true
    }
}

/// cc:67-:87 `static const CodecApi bad_proto_api` — const-record pin
/// (vectors:5 `API bad_proto type=0 size=112 ver=1900547 features=1
/// name=bad_proto`): features=1 = PLUGIN_SO_RELOAD (cc:74) — cd_default
/// was the features=0 outlier.
pub const BAD_PROTO_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:70
    size: CDAPI_SIZEOF_CODEC_API, // cc:71
    api_version: CDAPI_VERSION, // cc:72
    version: 0,      // cc:73
    features: PLUGIN_SO_RELOAD, // cc:74 (vectors features=1)
    options: API_OPTIONS, // cc:75
    name: CD_BAD_PROTO_NAME, // cc:76
    help: CD_BAD_PROTO_HELP, // cc:77
    mod_ctor: false, // cc:78 nullptr
    mod_dtor: false, // cc:79 nullptr
    // cc:81-:86 nullptr pinit/pterm/tinit/tterm; ctor/dtor set
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true, // cc:85
    dtor: true, // cc:86
};

/// cc:89-:97 the export, non-BUILDING_SO face (the harness link, like
/// every ground static-codecs build):
/// `const BaseApi* cd_bad_proto[] = { &bad_proto_api.base, nullptr }`.
/// The `#ifdef BUILDING_SO ... snort_plugins[]` alternation is the DSO
/// face, NOT built at the pinned posture — deviation row 18c records
/// the folded branch. cd_bad_proto itself is NOT in codec_api.cc's
/// always-loaded five; it stands in the STATIC_CODECS ladder only
/// (cc:87), dormant (names pinned in codec_api.rs).
pub const CD_BAD_PROTO: crate::framework::codec::CodecTable = &[&BAD_PROTO_API];
