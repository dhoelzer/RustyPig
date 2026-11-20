//! Port of `src/codecs/ip/cd_mobility.cc` (143 L) — row 18e.
//! Ground: snort3-src @ fe29cbe, md5 `a053ea4f83cb866e9267d610c1ed08d2`
//! (ext PLAN §0). DIR FACT: `codecs/ip/`.
//!
//! The IPv6 Mobility Header codec (RFC 6275; name "ipv6_mobility",
//! ProtocolId::MOBILITY_IPV6 = 135). Probe-pinned arms:
//!   vec:22/:23 `EV 116 475` + `MOB badpayl -> 1 next=60` — THE
//!           mob-quirk: payload_proto (m[0]) = 60 (DSTOPTS) !=
//!           NONEXT(59) raises DECODE_MIPV6_BAD_PAYLOAD_PROTO
//!           (cc:89-:90) and decode STILL RETURNS TRUE (cc:99) — the
//!           event never short-circuits the return. Pinned by the
//!           vectors, asserted again by a cited unit arm; NEVER
//!           "fixed" (recon §6.4).
//!   vec:24    `MOB_PID 135 n=1` (cc:58-:61 — defined BEFORE decode
//!           in C too, member order kept).
//!
//! LADDER SHAPE (never unified): mobility checks the MAXOPTS latch
//! FIRST (cc:66-:70, with return), THEN `raw.len < ip::MIN_EXT_LEN`
//! (cc:72-:76) — the exact inverse of hopopts' len-then-maxopts, and
//! routing's MIN-then-maxopts-then-sizeof is a third shape. lyr base =
//! ip::MIN_EXT_LEN (8) + (header_len << 3) (cc:78). Write order after
//! the lyr check: bits/cnt/nxt/csum with the badpayl event wedged
//! BETWEEN cnt++ and nxt (cc:86-:93) — one more per-file order to keep
//! verbatim.
//!
//! cc:28-:29 keeps the upstream "// yes, macros are necessary. The API
//! and class constructor require different strings." comment beside the
//! CD_MOBILE_NAME/CD_MOBILE_HELP pair — kept in place; the string pair
//! (name "ipv6_mobility", help "support for mobility") lands as the
//! two consts as everywhere else.
//!
//! struct MobileIPV6Header (cc:45-:56, RFC 6275): payload_proto(0),
//! header_len(1), mh_type(2), reserved(3), checksum(u16, 4-5);
//! sizeof 6. The cppcheck-suppress unusedStructMember comments on
//! mh_type/reserved/checksum ride their fields' comments — those three
//! are NEVER READ by decode (port keeps layout-comment posture, no
//! fake reads).
//!
//! The 456 maxopts arm: DEAD-at-probe-default ruling + Option<&conf>
//! seam (see cd_hop_opts.rs module doc — same 18c posture).
//! Export cc:134-:139: normal `#ifdef BUILDING_SO` alternation,
//! non-DSO face pinned (18c folded-branch deviation carries).

use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData,
    DECODE_IP6_EXCESS_EXT_HDR, DECODE_IPV6_TRUNCATED_EXT, PLUGIN_SO_RELOAD, PROTO_BIT__IP6_EXT,
    PT_CODEC, ProtocolId, RawData, ip, ip_protocol,
};

/// cc:30 `#define CD_MOBILE_NAME "ipv6_mobility"` (the "macros are
/// necessary" comment cc:28-:29 rides the module doc).
pub const CD_MOBILE_NAME: &str = "ipv6_mobility";
/// cc:31 `#define CD_MOBILE_HELP "support for mobility"` — vectors:8.
pub const CD_MOBILE_HELP: &str = "support for mobility";

#[derive(Default)]
pub struct MobilityCodec;

impl MobilityCodec {
    /// cc:36 `MobilityCodec() : Codec(CD_MOBILE_NAME) { }`
    pub fn new() -> MobilityCodec {
        MobilityCodec
    }

    /// cc:58-:61 — vectors:24 `MOB_PID 135 n=1`
    /// (ProtocolId::MOBILITY_IPV6 = 135).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(crate::framework::codec::protocol_id::MOBILITY_IPV6); // cc:60
    }

    /// cc:63-:100 out-of-line decode, statement order VERBATIM
    /// (maxopts FIRST, badpayl event mid-write-run, true ALWAYS
    /// at cc:99 — module doc).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: crate::framework::codec::QueueSink,
    ) -> bool {
        // cc:66-:70 maxopts FIRST (the hopopts inverse — never
        // unified) -> EXCESS + return. DEAD at probe default.
        let hit = codec
            .conf
            .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
            .unwrap_or(false);
        if hit {
            crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, &mut *sink);
            return false;
        }

        // cc:72-:76 `raw.len < ip::MIN_EXT_LEN` -> TRUNCATED + false.
        if raw.len < ip::MIN_EXT_LEN {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        let mip6_payload = *raw.data.first().unwrap_or(&0); // cc:46 payload_proto
        let mip6_hdrlen = *raw.data.get(1).unwrap_or(&0); // cc:47 header_len

        // cc:78 lyr_len = MIN_EXT_LEN + (header_len << 3); cc:80-:84
        // lyr>len -> TRUNCATED + false.
        codec.lyr_len = (ip::MIN_EXT_LEN + ((mip6_hdrlen as u32) << 3)) as u16;
        if (codec.lyr_len as u32) > raw.len {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        // cc:86-:87 bits/cnt (same grouping as routing/dstopts).
        codec.proto_bits |= PROTO_BIT__IP6_EXT; // cc:86
        codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1); // cc:87

        // cc:88-:90 `// RFC 6275, 6.1.1 and 9.2, payload protocol
        // must be IPPROTO_NONE (59 decimal)` — the badpayl event lands
        // HERE, between cnt++ and the nxt write; decode NEVER returns
        // false on it (the vectors-pinned quirk, vec:22/:23).
        if mip6_payload != ip_protocol::NONEXT {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_MIPV6_BAD_PAYLOAD_PROTO as u32,
                &mut *sink,
            );
        }

        // cc:92-:93 nxt/csum AFTER the event (vec:23 next=60 — the
        // bad payload_proto still lands in next_prot_id).
        codec.next_prot_id = mip6_payload as ProtocolId; // cc:92
        codec.ip6_csum_proto = mip6_payload; // cc:93

        // cc:95-:97 "// must be called AFTER setting next_prot_id /
        // Mobility Header must always be the last header in the
        // header chain of an IPv6 packet" — MOBILITY_IPV6 maps to
        // IPV6_ORDER_MAX (7, the order tables' `_` arm): the landed
        // check's unordered-extension latch faces ride 18d's code.
        crate::framework::codec::check_ipv6_extension_order(
            codec,
            ip_protocol::MOBILITY_IPV6,
            &mut *sink,
        );
        // cc:99 — unconditional true (the badpayl event above never
        // changes it — vec:23).
        true
    }
}

// cc:106-:110 ctor/dtor presence slots; no module pair (igmp-only).

/// cc:112-:132 `static const CodecApi mobility_api` — vectors:7
/// `API mobility type=0 size=112 ver=1900547 name=ipv6_mobility` +
/// vectors:8 HELP. NB the C record cc:126-:131 drops the trailing
// field comments (`nullptr, nullptr, nullptr, nullptr, ctor, dtor,`
// listed bare) — literal kept field-by-field, comments not invented.
pub const MOBILITY_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:114
    size: CDAPI_SIZEOF_CODEC_API, // cc:115
    api_version: CDAPI_VERSION, // cc:116
    version: 0,      // cc:117
    features: PLUGIN_SO_RELOAD, // cc:118
    options: API_OPTIONS, // cc:119
    name: CD_MOBILE_NAME, // cc:120
    help: CD_MOBILE_HELP, // cc:121
    mod_ctor: false, // cc:122
    mod_dtor: false, // cc:123
    pinit: false,    // cc:127
    pterm: false,    // cc:128
    tinit: false,    // cc:129
    tterm: false,    // cc:130
    ctor: true,      // cc:131
    dtor: true,      // cc:131
};

/// cc:134-:142 the export — non-DSO arm (`const BaseApi*
/// cd_mobility[]`, folded DSO branch = 18c deviation): the
/// STATIC_CODECS ladder name `cd_mobility` (codec_api.rs:118 tripwire
/// ALREADY names it — the 18e real record lands WITHOUT touching the
/// stub consts, ext PLAN §6).
pub const CD_MOBILITY: crate::framework::codec::CodecTable = &[&MOBILITY_API];
