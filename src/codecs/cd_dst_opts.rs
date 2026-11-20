//! Port of `src/codecs/ip/cd_dst_opts.cc` (134 L) — row 18e.
//! Ground: snort3-src @ fe29cbe, md5 `033def126e4e32c6db272629fe91dde7`
//! (ext PLAN §0). DIR FACT: `codecs/ip/`.
//!
//! The IPv6 destination-options extension codec (name "ipv6_dst_opts").
//! The probe arms for this unit are PIDS-ONLY (vectors:17 `DSTPID 60
//! n=1`, ProtocolId::DSTOPTS = 60) — the decode ladder (cc:53-:88)
//! lands as a literal transcription, cited line-by-line (the 18d
//! port-by-reading rule: no vectors line claimed, no fixture value
//! invented).
//!
//! THE LADDER QUIRK, pinned by the C itself (recon §6.4 — NEVER
//! unified with the four siblings): the cc:63-:64 maxopts arm raises
//! DECODE_IP6_EXCESS_EXT_HDR but does NOT return — unlike hopopts
//! (cc:67-:70) and routing/mobility, dstopts CONTINUES after the
//! EXCESS event (MEASURED grep return=0 inside cc:63-:65, ext PLAN
//! §3 DEC-face cite). The Rust port keeps the missing return EXACT.
//! Ordering contrast #2: dstopts touches proto_bits/cnt BEFORE
//! next_prot_id/ip6_csum_proto (cc:77-:80) — the inverse of hopopts
//! (cc:80-:83). Both orders kept verbatim per file.
//!
//! The 456 face rides the same DEAD-at-probe-default ruling as
//! cd_hop_opts.rs (witness conf keeps max_ip6_extensions = 0,
//! snort_config.h:278); the Rust arm mirrors the 18c Option seam.
//!
//! Export cc:125-:133 is the NORMAL `#ifdef BUILDING_SO` alternation
//! (NOT the comment-out oddity of cd_hop_opts — the 18c folded-DSO
//! branch deviation carries unchanged).

use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData,
    DECODE_IP6_EXCESS_EXT_HDR, DECODE_IPV6_TRUNCATED_EXT, PLUGIN_SO_RELOAD, PROTO_BIT__IP6_EXT,
    PT_CODEC, ProtocolId, RawData, ip_protocol,
};

/// cc:30 `#define CD_DSTOPTS_NAME "ipv6_dst_opts"`
pub const CD_DSTOPTS_NAME: &str = "ipv6_dst_opts";
/// cc:31 `#define CD_DSTOPTS_HELP "support for ipv6 destination options"`
/// — vectors:4 face, LOWERCASE "ipv6" (the cc:31 spelling kept; the
/// hopopts help caps IPv6 — the two literals never normalized).
pub const CD_DSTOPTS_HELP: &str = "support for ipv6 destination options";

/// cc:44-:49 `struct IP6Dest` — `ip6dest_nxt` (byte 0),
/// `ip6dest_len` (byte 1), `ip6dest_pad[6]`: sizeof = 8. Same
/// read-the-two-bytes-after-the-guard posture as cd_hop_opts.rs
/// (panic-free fallbacks, never fire at the pinned posture).
#[derive(Default)]
pub struct Ipv6DSTOptsCodec;

impl Ipv6DSTOptsCodec {
    /// cc:38 `Ipv6DSTOptsCodec() : Codec(CD_DSTOPTS_NAME) { }`
    pub fn new() -> Ipv6DSTOptsCodec {
        Ipv6DSTOptsCodec
    }

    /// cc:90-:91 `void Ipv6DSTOptsCodec::get_protocol_ids(...)
    /// { v.emplace_back(ProtocolId::DSTOPTS); }` — vectors:17
    /// `DSTPID 60 n=1`.
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(crate::framework::codec::protocol_id::DSTOPTS); // cc:91
    }

    /// cc:53-:88 out-of-line decode, statement order VERBATIM incl.
    /// the no-return EXCESS arm (module doc).
    // needless_bool allowed at function level: the cc:85-:87
    // if/return + tail `false` stays literal (lint spans the tail;
    // codec.rs needless_return precedent).
    #[allow(clippy::needless_bool)] // literal C flow kept readable
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: crate::framework::codec::QueueSink,
    ) -> bool {
        // cc:57-:61 short-ext guard -> TRUNCATED + false (sizeof
        // IP6Dest = 8).
        if raw.len < 8 {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        let dst_nxt = *raw.data.first().unwrap_or(&0); // cc:46 ip6dest_nxt
        let dst_len = *raw.data.get(1).unwrap_or(&0); // cc:47 ip6dest_len

        // cc:63-:64 `if (conf->hit_ip6_maxopts(...)) codec_event(..);`
        // — NO return, NO braces (module-doc quirk #1): the walk
        // CONTINUES after the EXCESS event. Kept exact.
        let hit = codec
            .conf
            .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
            .unwrap_or(false);
        if hit {
            crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, &mut *sink);
        }

        // cc:66-:67 `if (dsthdr->ip6dest_nxt == IpProtocol::ROUTING)`
        // -> DECODE_IPV6_DSTOPTS_WITH_ROUTING (292, codec_module.h:144
        // Literal; CodecSid landed 18d).
        if dst_nxt == ip_protocol::ROUTING {
            crate::framework::codec::codec_event(
                codec,
                CodecSid::DECODE_IPV6_DSTOPTS_WITH_ROUTING as u32,
                &mut *sink,
            );
        }

        // cc:69 lyr_len (same 8 + (len << 3) fold as hopopts);
        // cc:71-:75 lyr>len -> TRUNCATED + false.
        codec.lyr_len = (8u32 + ((dst_len as u32) << 3)) as u16;
        if (codec.lyr_len as u32) > raw.len {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        // cc:77-:80 the four writes — THIS file's order bits/cnt BEFORE
        // nxt/csum (the hopopts contrast, kept verbatim).
        codec.proto_bits |= PROTO_BIT__IP6_EXT; // cc:77
        codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1); // cc:78
        codec.next_prot_id = dst_nxt as ProtocolId; // cc:79
        codec.ip6_csum_proto = dst_nxt; // cc:80

        // cc:82-:83 "// must be called AFTER setting next_prot_id" —
        // DSTOPTS: the second-DSTOPTS exception arm (codec.rs landed
        // comment) lives INSIDE the landed check; this row adds no
        // order-table change (the 18d tables cover DSTOPTS = 2).
        crate::framework::codec::check_ipv6_extension_order(
            codec,
            ip_protocol::DSTOPTS,
            &mut *sink,
        );
        // cc:85-:87 `if ( CheckIPV6HopOptions(raw, codec)) return true;
        // return false;` — dstopts REUSES the hop-by-hop option walk
        // (the cc:24 hopopts comment "included in the binary" intent).
        // needless_bool suppressed: literal C tail flow kept
        // diff-evident (function-level allow on decode, codec.rs
        // needless_return precedent).
        if crate::framework::codec::check_ipv6_hop_options(raw, codec, &mut *sink) {
            return true;
        }
        false
    }
}

// cc:97-:101 `static Codec* ctor(Module*)` / `static void dtor(Codec*)`
// presence slots; mod_ctor/mod_dtor nullptr (igmp-only face, vectors:9).

/// cc:103-:123 `static const CodecApi ipv6_dstopts_api` — vectors:3
/// `API dstopts type=0 size=112 ver=1900547 name=ipv6_dst_opts` +
/// vectors:4 HELP.
pub const IPV6_DSTOPTS_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:105
    size: CDAPI_SIZEOF_CODEC_API, // cc:106
    api_version: CDAPI_VERSION, // cc:107
    version: 0,      // cc:108
    features: PLUGIN_SO_RELOAD, // cc:109
    options: API_OPTIONS, // cc:110
    name: CD_DSTOPTS_NAME, // cc:111
    help: CD_DSTOPTS_HELP, // cc:112
    mod_ctor: false, // cc:113 nullptr
    mod_dtor: false, // cc:114 nullptr
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true, // cc:120
    dtor: true, // cc:121
};

/// cc:125-:133 the export — NORMAL `#ifdef BUILDING_SO / SO_PUBLIC
/// snort_plugins[] / #else / const BaseApi* cd_dstopts[] / #endif`:
/// pinned face = the non-DSO arm (18c folded-branch deviation carries;
/// contrast cd_hop_opts.cc where those directives are COMMENTED OUT).
pub const CD_DSTOPTS: crate::framework::codec::CodecTable = &[&IPV6_DSTOPTS_API];
