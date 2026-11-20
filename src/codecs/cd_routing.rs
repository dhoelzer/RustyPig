//! Port of `src/codecs/ip/cd_routing.cc` (163 L) — row 18e.
//! Ground: snort3-src @ fe29cbe, md5 `811d85c5dbe45398a10c97efcdb0291f`
//! (ext PLAN §0). DIR FACT: `codecs/ip/`. Second copyright line
//! (Sourcefire 2002-2013, cc:3) kept in this provenance note.
//!
//! The IPv6 routing extension codec (name "ipv6_routing"). The probe
//! arms pin the type0 ladder line-for-line:
//!   vec:18/:19 `EV 116 461` + `EV 116 283` — q[0]=0x2b (nxt =
//!           ROUTING 43) + q[2]=0: TYPE-ZERO event 461 (cc:96-:97,
//!           the "evil creatures" comment cc:95) THEN the self-route
//!           event 283 (cc:102-:103; the HOPOPTS event 282 at
//!           cc:99-:100 does NOT fire — nxt != 0 — literal kept).
//!   vec:20    `ROUTE t0 -> 1 next=43 bits=65536` (return true,
//!           cc:119; lyr_len = MIN_EXT_LEN 8 + (len0 << 3) = 8 == len).
//!   vec:21    `ROUTE_PID 43 n=1` (cc:70-:71, ProtocolId::ROUTING).
//!
//! LADDER SHAPE (recon §6.4, never unified): routing is the ONLY 18e
//! unit with THREE len-style guards in sequence — MIN_EXT_LEN (cc:77),
//! maxopts-with-return (cc:83-:87), then `raw.len <
//! sizeof(IP6Route)` (cc:89-:93; sizeof = 4: nxt/len/type/seg_left,
//! cc:46-:52 — NOT 8). The three-event block (461/282/283) fires
//! BEFORE the lyr>len truncation re-check (cc:96-:103 precede
//! cc:105-:109). Write order = bits/cnt/nxt/csum (cc:112-:115, the
//! dstopts grouping, NOT hopopts').
//!
//! DEAD CODE, transcribed as dead (recon §6.5): cc:55-:67 `#if 0`
//! block holds the `IP6Route0` struct — "// Keeping this around for
//! future development" — with the `snort_in6_addr ip6rte0_addr[1]`
//! ("Up to 23 IP6 addresses") member. ZERO Rust surface: the block
//! stays below as a comment, never a type, never a fixture.
//!
//! The 456 maxopts arm rides the DEAD-at-probe-default ruling
//! (witness conf max_ip6_extensions = 0) + the 18c Option<&conf> seam
//! — same posture as cd_hop_opts.rs (module cite there).
//!
//! Export cc:154-:159: the normal `#ifdef BUILDING_SO` alternation;
//! pinned non-DSO face (18c folded-branch deviation carries).

use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData,
    DECODE_IP6_EXCESS_EXT_HDR, DECODE_IPV6_TRUNCATED_EXT, PLUGIN_SO_RELOAD, PROTO_BIT__IP6_EXT,
    PT_CODEC, ProtocolId, RawData, ip, ip_protocol,
};

/// cc:30 `#define CD_IPV6_ROUTING_NAME "ipv6_routing"` — NOTE the
/// macro-name prefix CD_IPV6_ROUTING_* (not CD_ROUTING_*), kept.
pub const CD_IPV6_ROUTING_NAME: &str = "ipv6_routing";
/// cc:31 `#define CD_IPV6_ROUTING_HELP "support for IPv6 routing extension"`
pub const CD_IPV6_ROUTING_HELP: &str = "support for IPv6 routing extension";

/// cc:46-:52 `struct IP6Route` — nxt/len/type/seg_left = sizeof 4
/// ("/* type specific data follows */"). The two guards read bytes 0
/// (nxt) and 2 (type); byte 1 is len. `ip6rte_seg_left` (byte 3) is
/// NEVER READ in the decode — kept as the layout comment only, no
/// Rust field (mirror of the 18d never-read-field posture).
#[derive(Default)]
pub struct Ipv6RoutingCodec;

impl Ipv6RoutingCodec {
    /// cc:38 `Ipv6RoutingCodec() : Codec(CD_IPV6_ROUTING_NAME) { }`
    pub fn new() -> Ipv6RoutingCodec {
        Ipv6RoutingCodec
    }

    /// cc:70-:71 `{ v.emplace_back(ProtocolId::ROUTING); }` —
    /// vectors:21 `ROUTE_PID 43 n=1`. NB the C file defines this
    /// BEFORE decode (cc:70 precedes cc:73) — member order kept in
    /// this impl too.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(crate::framework::codec::protocol_id::ROUTING); // cc:71
    }

    /// cc:73-:120 out-of-line decode, statement order VERBATIM
    /// (three guards, three events, dstopts-order writes).
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: crate::framework::codec::QueueSink,
    ) -> bool {
        // cc:77-:81 `raw.len < ip::MIN_EXT_LEN` (8) -> TRUNCATED +
        // false — routing measures against MIN_EXT_LEN here, NOT
        // sizeof like hopopts (ladder never unified).
        if raw.len < ip::MIN_EXT_LEN {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        // cc:83-:87 maxopts latch -> EXCESS + RETURN (contrast dstopts
        // cc:63-:64 no-return; DEAD at probe default).
        let hit = codec
            .conf
            .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
            .unwrap_or(false);
        if hit {
            crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, &mut *sink);
            return false;
        }

        // cc:89-:93 the SECOND len guard: `raw.len < sizeof(IP6Route)`
        // = 4. Between MIN_EXT_LEN(8) and 4 it is unreachable (8 > 4)
        // — the C keeps both, the port keeps both (dead-but-literal
        // transcription, no optimization).
        if raw.len < 4 {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        let rte_nxt = *raw.data.first().unwrap_or(&0); // cc:48 ip6rte_nxt
        let rte_len = *raw.data.get(1).unwrap_or(&0); // cc:49 ip6rte_len
        let rte_type = *raw.data.get(2).unwrap_or(&0); // cc:50 ip6rte_type

        // cc:95-:97 `/* Routing type 0 extension headers are evil
        // creatures. */ if (rte->ip6rte_type == 0)` -> ROUTE_ZERO 461.
        if rte_type == 0 {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_ROUTE_ZERO as u32,
                &mut *sink,
            );
        }
        // cc:99-:100 nxt == HOPOPTS -> 282 (does NOT fire on the
        // vec:18 face, nxt=43; literal kept for the unit face).
        if rte_nxt == ip_protocol::HOPOPTS {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_ROUTE_AND_HOPBYHOP as u32,
                &mut *sink,
            );
        }
        // cc:102-:103 nxt == ROUTING -> 283 TWO_ROUTE (fires, vec:19).
        if rte_nxt == ip_protocol::ROUTING {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_TWO_ROUTE_HEADERS as u32,
                &mut *sink,
            );
        }

        // cc:105-:109 lyr_len = MIN_EXT_LEN + (len << 3) — the base is
        // ip::MIN_EXT_LEN (8) HERE, not sizeof (the hopopts contrast).
        codec.lyr_len = (ip::MIN_EXT_LEN + ((rte_len as u32) << 3)) as u16;
        if (codec.lyr_len as u32) > raw.len {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        // cc:112-:115 "// check ip proto rules against this layer" —
        // bits/cnt/nxt/csum order (dstopts grouping).
        codec.proto_bits |= PROTO_BIT__IP6_EXT; // cc:112
        codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1); // cc:113
        codec.next_prot_id = rte_nxt as ProtocolId; // cc:114 — vec:20 next=43
        codec.ip6_csum_proto = rte_nxt; // cc:115

        // cc:117-:118 CheckIPv6ExtensionOrder(codec, ROUTING): the
        // landed check sets CODEC_ROUTING_SEEN (codec.rs :625-:626) —
        // the second-DSTOPTS exception's latch half, untouched by 18e.
        crate::framework::codec::check_ipv6_extension_order(
            codec,
            ip_protocol::ROUTING,
            &mut *sink,
        );
        // cc:119 unconditional true (NO CheckIPV6HopOptions call here
        // — routing never parses options; hopopts/dstopts-only arms).
        true
    }
}

// C cc:55-:67, transcribed as DEAD exactly (module doc):
//   #if 0
//   // Keeping this around for future development
//   struct IP6Route0 { ip6rte0_nxt/len/type/seg_left; ip6rte0_reserved;
//     ip6rte0_bitmap[3]; struct snort_in6_addr ip6rte0_addr[1];
//     /* Up to 23 IP6 addresses */ };
//   #endif
// Zero Rust surface. The LIVE struct is IP6Route (4 B) above.

// cc:126-:130 ctor/dtor presence slots; no module pair.

/// cc:132-:152 `static const CodecApi ipv6_routing_api` — vectors:5
/// `API routing type=0 size=112 ver=1900547 name=ipv6_routing` +
/// vectors:6 HELP.
pub const IPV6_ROUTING_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:134
    size: CDAPI_SIZEOF_CODEC_API, // cc:135
    api_version: CDAPI_VERSION, // cc:136
    version: 0,      // cc:137
    features: PLUGIN_SO_RELOAD, // cc:138
    options: API_OPTIONS, // cc:139
    name: CD_IPV6_ROUTING_NAME, // cc:140
    help: CD_IPV6_ROUTING_HELP, // cc:141
    mod_ctor: false, // cc:142 nullptr
    mod_dtor: false, // cc:143 nullptr
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true, // cc:149
    dtor: true, // cc:150
};

/// cc:154-:162 the export — non-DSO arm (folded DSO branch = the 18c
/// deviation, unchanged): `const BaseApi* cd_routing[] = {
/// &ipv6_routing_api.base, nullptr }`.
pub const CD_ROUTING: crate::framework::codec::CodecTable = &[&IPV6_ROUTING_API];
