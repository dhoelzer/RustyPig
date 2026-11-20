//! Port of `src/codecs/misc/cd_default.cc` (83 L) — row 18c.
//! Ground: snort3-src @ fe29cbe, md5 `24af11828b3dc4d14ee646dda38524c2`.
//!
//! The omnipresent fallback codec ("unknown"): get_protocol_ids answers
//! FINISHED_DECODE, decode answers false (cc:38-:42). Its table
//! `cd_default` (cc:78-:82) is the ONLY table with no `BUILDING_SO`
//! alternation — cc:31's comment "static to ensure omnipresent" is why
//! codec_api.cc loads it unconditionally.
//!
//! C file-statics map 1:1: `DefaultCodec` (cc:33-:43, anonymous
//! namespace) -> `DefaultCodec`, `ctor`/`dtor` (cc:50-:54) -> the
//! `default_ctor`/`default_dtor` presence pins on the record,
//! `default_api` (cc:56-:76) -> `DEFAULT_API`.
//!
//! Codec-shape deviation (deviations row 18c, rides the 17d model): the
//! C vtable override pair becomes inherent methods on the Rust stand-
//! in; the vectors API line pins the record, the decode arms pin the
//! behavior — see tests/vocab_parity_test.rs (D1).

use crate::framework::codec::{
    API_OPTIONS, API_RESERVED, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, PT_CODEC,
    ProtocolId, protocol_id,
};

/// cc:28 `#define CD_DEFAULT_NAME "unknown"`
pub const CD_DEFAULT_NAME: &str = "unknown";
/// cc:29 `#define CD_DEFAULT_HELP "support for unknown protocols"`
pub const CD_DEFAULT_HELP: &str = "support for unknown protocols";

/// cc:33-:43 `class DefaultCodec : public Codec { ... }` — the
/// anonymous-namespace class. Its two overrides:
/// get_protocol_ids -> ProtocolId::FINISHED_DECODE (cc:38-:39),
/// decode -> false (cc:41-:42).
#[derive(Default)]
pub struct DefaultCodec;

impl DefaultCodec {
    /// cc:36 `DefaultCodec() : Codec(CD_DEFAULT_NAME) { }` — the base
    /// name slot (17d model: the record carries the name; the Rust
    /// ctor just builds the stand-in).
    pub fn new() -> DefaultCodec {
        DefaultCodec
    }

    /// cc:38-:39 `void get_protocol_ids(std::vector<ProtocolId>& v)
    /// override { v.emplace_back(ProtocolId::FINISHED_DECODE); }`
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::FINISHED_DECODE);
    }

    /// cc:41-:42 `bool decode(const RawData&, CodecData&, DecodeData&)
    /// override { return false; }` — the no-event, no-mutation posture
    /// (vectors:4 `DECODE unknown -> 0`).
    pub fn decode(&self) -> bool {
        false
    }
}

/// cc:50-:51 `static Codec* ctor(Module*) { return new DefaultCodec(); }`
/// and cc:53-:54 `dtor` — record slots live => presence pins true
/// (vectors never call through a null slot; 17w/17z precedent).
const DEFAULT_CTOR: bool = true;
const DEFAULT_DTOR: bool = true;

/// cc:56-:76 `static const CodecApi default_api` — const-record pin.
/// V1 replay line (vector 1): `API unknown type=0 size=112
/// ver=1900547 features=0 name=unknown` — size 112 = sizeof(CodecApi)
/// on the C++ layout (BaseApi 112 == CodecApi head; the probe printf
/// read api->base.size; PROBE_SIZEOF precedent, never size_of).
/// features 0 = API_RESERVED (cc:63 — cd_default is the ONE codec of
/// the four WITHOUT PLUGIN_SO_RELOAD: vectors features=0 vs 1).
pub const DEFAULT_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:59
    size: CDAPI_SIZEOF_CODEC_API, // cc:60 sizeof(CodecApi) -> 112 (probe pin)
    api_version: CDAPI_VERSION, // cc:61 == (29<<16)|3 == 1900547 (vectors ver=)
    version: 0,     // cc:62
    features: API_RESERVED, // cc:63
    options: API_OPTIONS, // cc:64
    name: CD_DEFAULT_NAME, // cc:65
    help: CD_DEFAULT_HELP, // cc:66
    mod_ctor: false, // cc:67 nullptr
    mod_dtor: false, // cc:68 nullptr
    // cc:70-:75 pinit/pterm/tinit/tterm nullptr, ctor/dtor set
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: DEFAULT_CTOR,
    dtor: DEFAULT_DTOR,
};

/// cc:78-:82 `const BaseApi* cd_default[] = { &default_api.base,
/// nullptr }` — the exported table (no BUILDING_SO alternation at this
/// TU: omnipresent). Null terminator folded away (deviation row 18c:
/// Rust slice length carries it; codec_api's load_codecs sinks x[0]).
pub const CD_DEFAULT: crate::framework::codec::CodecTable = &[&DEFAULT_API];

#[cfg(test)]
mod tests {
    use super::*;

    /// record-field readback against the vector-1 line of
    /// tools/vocab_harness/vectors.txt (in-crate convenience twin; the
    /// full ordered replay lives in tests/vocab_parity_test.rs).
    #[test]
    fn default_api_fields() {
        assert_eq!(DEFAULT_API.name, "unknown");
        assert_eq!(DEFAULT_API.help, "support for unknown protocols");
        assert_eq!(DEFAULT_API.ptype, PT_CODEC0);
        assert_eq!(DEFAULT_API.size, 112);
        assert_eq!(DEFAULT_API.api_version, (29 << 16) | 3);
        // cc:63: features 0 (NO PLUGIN_SO_RELOAD -- vectors features=0)
        assert_eq!(DEFAULT_API.features, 0);
        // vectors order: type=0 (PT_CODEC == 0, base_api.h:52)
        assert_eq!(API_RESERVED, 0);
        assert_eq!(API_OPTIONS, 0);
        assert_eq!(crate::framework::codec::BASE_API_VERSION, 29);
    }

    const PT_CODEC0: u32 = 0; // base_api.h:52 PT_CODEC is enum head

    #[test]
    fn decode_posture() {
        let c = DefaultCodec::new();
        assert!(!c.decode());
        let mut v = Vec::new();
        c.get_protocol_ids(&mut v);
        assert_eq!(v, vec![protocol_id::FINISHED_DECODE]); // vectors:2 PID 256
    }
}
