//! Port of `src/codecs/ip/cd_no_next.cc` (116 L) — row 18c.
//! Ground: snort3-src @ fe29cbe, md5 `5943bf61b79fe655c85f6fa6d08c4a10`.
//! DIR FACT (NEXT.md 18c scoping): `codecs/ip/`, not root/.
//!
//! The ipv6 "no next header" sentinel codec (name "ipv6_no_next").
//! decode (cc:45-:70) is the row's only conf-reading, state-mutating
//! arm; vectors pin all three faces:
//!   - short len (< MIN_EXT_LEN=8) -> false, silent (vec 14)
//!   - ok len 8, conf.max == 0 -> true, lyr=8,
//!     bits=PROTO_BIT__IP6_EXT, cnt=1 (vec 15)
//!   - conf.max == 2 && cnt == 2 (hit) -> EV 116 456, false
//!     (vec 16/:17)
//!
//! The C line cc:65 `const_cast<uint32_t&>(raw.len) = ip::MIN_EXT_LEN;`
//! mutates the const RawData through a const_cast. Rust deviation
//! (row 18c): RawData rides the 17d Copy model, so the port returns the
//! folded len through the result and the replay asserts it against the
//! C-observable face — the vectors never print raw.len back, so the
//! const_cast has NO observable in the pinned transcript; the port
//! drops the mutation and records the fact. The four cc:66-:68 mutations
//! on CodecData stay exactly.
//!
//! conf posture: C calls through codec.conf WITHOUT a null guard
//! (cc:52). The port models conf as Option<&SnortConfig> (the 17d
//! seam): a None conf never happens at the pinned posture (probe.cc:52
//! builds SnortConfig on the stack); the port treats None as max==0
//! (hit_ip6_maxopts false), mirroring what the C would read from a
//! zeroed conf, and never panics — deviation row 18c.

use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData,
    DECODE_IP6_EXCESS_EXT_HDR, PLUGIN_SO_RELOAD, PROTO_BIT__IP6_EXT, PT_CODEC, ProtocolId,
    RawData, ip, protocol_id,
};

/// cc:32 `#define CD_NO_NEXT_NAME "ipv6_no_next"`
pub const CD_NO_NEXT_NAME: &str = "ipv6_no_next";
/// cc:33 `#define CD_NO_NEXT_HELP "sentinel codec"`
pub const CD_NO_NEXT_HELP: &str = "sentinel codec";

/// cc:35-:42 `class Ipv6NoNextCodec : public Codec` (member defs land
/// out-of-line at cc:45+).
#[derive(Default)]
pub struct Ipv6NoNextCodec;

impl Ipv6NoNextCodec {
    /// cc:38 `Ipv6NoNextCodec() : Codec(CD_NO_NEXT_NAME) { }`
    pub fn new() -> Ipv6NoNextCodec {
        Ipv6NoNextCodec
    }

    /// cc:72-:73 `void Ipv6NoNextCodec::get_protocol_ids(...)
    /// { v.emplace_back(ProtocolId::NONEXT); }` — vectors:12 `PID 59`.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(protocol_id::NONEXT);
    }

    /// cc:45-:70 out-of-line def, statement order verbatim:
    /// 1. cc:49-:50 short-ext guard (raw.len < MIN_EXT_LEN -> false;
    ///    "// No need to check IPv6 extension order since this is
    ///    automatically the last extension." comment rides cc:47-:48)
    /// 2. cc:52-:56 the maxopts latch -> codec_event + false
    /// 3. cc:58-:61 the FIXIT-M comment block (no code — kept, never
    ///    paraphrased into invented alert logic)
    /// 4. cc:65-:68 the four writes (lyr_len, proto_bits |=, count++,
    ///    plus the const_cast face — see module doc deviation).
    ///    The unused-by-value params keep C names (RawData rides in
    ///    even though only .len is read; cc:65's const_cast arm folded,
    ///    module doc).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: crate::framework::codec::QueueSink,
    ) -> bool {
        // cc:49 `if (raw.len < ip::MIN_EXT_LEN) return false;`
        if raw.len < ip::MIN_EXT_LEN {
            return false;
        }

        // cc:52 `if ( codec.conf->hit_ip6_maxopts(codec.ip6_extension_count) )`
        // — conf is the landed Option seam (module doc for the None
        // ruling: None stands for the zeroed default => never hits).
        let hit = codec
            .conf
            .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
            .unwrap_or(false);
        if hit {
            // cc:54 `codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);`
            crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, sink);
            // cc:55
            return false;
        }

        // cc:65 `const_cast<uint32_t&>(raw.len) = ip::MIN_EXT_LEN;` —
        // folded deviation (module doc): no observable pin in vectors;
        // the pinned facts are cc:66-:68 below.

        // cc:66 `codec.lyr_len = ip::MIN_EXT_LEN;`
        codec.lyr_len = ip::MIN_EXT_LEN as u16;
        // cc:67 `codec.proto_bits |= PROTO_BIT__IP6_EXT;` — "// check
        // for any IP related rules"
        codec.proto_bits |= PROTO_BIT__IP6_EXT;
        // cc:68 `codec.ip6_extension_count++;` — C counter on u8;
        // wrapping per the C-unsigned-port rule (vectors cnt=1 never
        // wraps, the posture does).
        codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1);
        // cc:69
        true
    }
}

/// cc:85-:105 `static const CodecApi no_next_api` — vectors:11
/// `API ipv6_no_next ... features=1 name=ipv6_no_next` (cc:92
/// PLUGIN_SO_RELOAD). HELP "sentinel codec" at vector 13.
pub const NO_NEXT_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:88
    size: CDAPI_SIZEOF_CODEC_API, // cc:89
    api_version: CDAPI_VERSION, // cc:90
    version: 0,      // cc:91
    features: PLUGIN_SO_RELOAD, // cc:92
    options: API_OPTIONS, // cc:93
    name: CD_NO_NEXT_NAME, // cc:94
    help: CD_NO_NEXT_HELP, // cc:95
    mod_ctor: false, // cc:96
    mod_dtor: false, // cc:97
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true, // cc:103
    dtor: true, // cc:104
};

/// cc:107-:115 export (non-BUILDING_SO face; the BUILDING_SO
/// snort_plugins alternation is the folded DSO branch, row 18c
/// deviation). STATIC_CODECS-only ladder member (cc:107), not in the
/// always-loaded five.
pub const CD_NO_NEXT: crate::framework::codec::CodecTable = &[&NO_NEXT_API];
