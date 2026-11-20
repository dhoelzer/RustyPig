//! Port of `src/codecs/ip/cd_hop_opts.cc` (143 L) — row 18e.
//! Ground: snort3-src @ fe29cbe, md5 `ec3b0bed51c16c7eab9939aa484b0cb0`
//! (ext PLAN §0). DIR FACT: `codecs/ip/` (the C base name is
//! `cd_hop_opts` while the EXPORTED symbol is `cd_hopopts` — the
//! tripwire spelling split pinned by ext PLAN §6; the header comment
//! cc:17 even says "cd_hopopts.cc author", the file is cd_hop_opts.cc).
//!
//! The IPv6 hop-by-hops extension codec (name "ipv6_hop_opts"). The
//! decode ladder (cc:57-:91) is vectors-pinned line-for-line:
//!   vec:11/:12 `EV 116 272` + `HOP short7 -> 0` — cc:61-:64 the
//!           `raw.len < sizeof(IP6HopByHop)` (8 = 1+1+6, cc:44-:50)
//!           guard fires TRUNCATED BEFORE the maxopts arm
//!   vec:13    `HOP ok8 -> 1 next=6 lyr=8 bits=65536 cnt=1
//!              csumproto=6` — the full-write face + the
//!           CheckIPV6HopOptions true return (cc:87-:88)
//!   vec:14/:15 `EV 116 272` + `HOP lyr>len -> 0` — cc:74-:78 the
//!           lyr_len-vs-raw.len re-check (p[1]=1 -> lyr 16 > len 8)
//!   vec:16    `HOPPID 0 n=1` (ProtocolId::HOPOPTS == 0)
//!
//! NEVER unify the five 18e ladders (recon §6.4): hopopts checks
//! `raw.len < sizeof` FIRST, then maxopts — mobility is the inverse
//! (cd_mobility.rs module doc) and dstopts events EXCESS without
//! returning (cd_dst_opts.rs cc:63-:64). Each ladder rides its own
//! statement order verbatim.
//!
//! The 456 face: `DECODE_IP6_EXCESS_EXT_HDR` (cc:67-:71, the
//! hit_ip6_maxopts latch) is DEAD on the probe default face — the
//! witness SnortConfig keeps max_ip6_extensions = 0
//! (snort_config.h:278; ext recon §6.3), and NO vectors line claims a
//! 456 value. The Rust arm mirrors the landed Option<&SnortConfig>
//! seam (18c cd_no_next precedent: None stands for the zeroed default,
//! hit false, never panics); the mutated face is exercised ONLY by a
//! cited Rust unit arm in tests/ext_parity_test.rs, never pre-typed.
//!
//! The export face is the DEAD-COMMENT oddity of the five (cc:134-:138
//! — the `#ifdef BUILDING_SO` arms are COMMENTED OUT, `//#ifdef`
//! `//SO_PUBLIC` `//#else` `//#endif`): cd_hopopts[] is an unconditional
//! definition, the `/* This codec is static … */` comment cc:130-:132
//! states why (pulls CheckIPV6HopOptions/CheckIPv6ExtensionOrder into
//! the binary). Deviations row 18e records the always-static fold; the
//! 18a-INVERTED dup landmine (real cd_hopopts[] vs the frozen vocab
//! stub, ext PLAN §4) is harness-side, zero Rust surface change:
//! codec_api.rs:82-:85 stub records stay UNTOUCHED.

use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData,
    DECODE_IP6_EXCESS_EXT_HDR, DECODE_IPV6_TRUNCATED_EXT, PLUGIN_SO_RELOAD, PROTO_BIT__IP6_EXT,
    PT_CODEC, ProtocolId, RawData, ip_protocol,
};

/// cc:30 `#define CD_HOPOPTS_NAME "ipv6_hop_opts"`
pub const CD_HOPOPTS_NAME: &str = "ipv6_hop_opts";
/// cc:31 `#define CD_HOPOPTS_HELP "support for IPv6 hop options"` —
/// vectors:2 face (capital "IPv6", unlike dstopts' lowercase help).
pub const CD_HOPOPTS_HELP: &str = "support for IPv6 hop options";

/// cc:44-:50 `struct IP6HopByHop` — `ip6hbh_nxt` (IpProtocol, byte 0),
/// `ip6hbh_len` (byte 1), `ip6hbh_pad[6]` ("/* options follow */"):
/// sizeof = 8 (no packing needed: 1+1+6). The Rust port reads the two
/// leading bytes straight off `raw.data` (the C reinterpret_cast face);
/// the read sits AFTER the cc:61 len guard in statement order, so at
/// the pinned posture the .get-or-0 fallbacks never fire — they exist
/// only so short inputs stay panic-free instead of UB (the landed
/// check_ipv6_hop_options posture, codec.rs).
#[derive(Default)]
pub struct Ipv6HopOptsCodec;

impl Ipv6HopOptsCodec {
    /// cc:38 `Ipv6HopOptsCodec() : Codec(CD_HOPOPTS_NAME) { }`
    pub fn new() -> Ipv6HopOptsCodec {
        Ipv6HopOptsCodec
    }

    /// cc:93-:96 out-of-line def — one emplace_back, vectors:16
    /// `HOPPID 0 n=1` (ProtocolId::HOPOPTS = 0).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(crate::framework::codec::protocol_id::HOPOPTS); // cc:95
    }

    /// cc:57-:91 out-of-line decode, statement order VERBATIM (this
    /// file's ladder, never unified — module doc). DecodeData& is the
    /// unnamed never-read param (18c posture); the sink stands for the
    /// event raises exactly as in cd_bad_proto/cd_no_next.
    // needless_bool suppressed for the cc:87-:90 if/return + tail
    // shape (function-level allow: the lint spans the tail `false`
    // too): literal C flow kept diff-evident, codec.rs needless_return
    // precedent.
    #[allow(clippy::needless_bool)] // literal C flow kept readable
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        sink: crate::framework::codec::QueueSink,
    ) -> bool {
        // cc:61-:64 `if (raw.len < sizeof(IP6HopByHop))` — 8 bytes;
        // vectors:11/:12 `EV 116 272` + `HOP short7 -> 0`. THIS guard
        // runs BEFORE the maxopts arm (the mobility contrast, cc
        // ladder NEVER unified).
        if raw.len < 8 {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        // hbh_hdr fields (byte 0 nxt, byte 1 len) — in-bounds once the
        // cc:61 guard passed; unwrap_or keeps the read panic-free.
        let hbh_nxt = *raw.data.first().unwrap_or(&0); // cc:46 ip6hbh_nxt
        let hbh_len = *raw.data.get(1).unwrap_or(&0); // cc:47 ip6hbh_len

        // cc:67-:71 the maxopts latch -> EXCESS + false. DEAD at the
        // probe default face (max_ip6_extensions = 0, module doc); the
        // Rust face is the SAME latch over the landed
        // parse_conf::SnortConfig::hit_ip6_maxopts cell (18c).
        let hit = codec
            .conf
            .map(|c| c.hit_ip6_maxopts(codec.ip6_extension_count))
            .unwrap_or(false);
        if hit {
            crate::framework::codec::codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR, &mut *sink);
            return false;
        }

        // cc:73 `codec.lyr_len = sizeof(IP6HopByHop) + (hbh_hdr->ip6hbh_len << 3);`
        // (uint16_t assignment fold, same as the C int->u16 narrowing).
        codec.lyr_len = (8u32 + ((hbh_len as u32) << 3)) as u16;
        // cc:74-:78 lyr>len re-check — vectors:14/:15 (p[1]=1 -> lyr
        // 16 > 8): TRUNCATED AGAIN, false.
        if (codec.lyr_len as u32) > raw.len {
            crate::framework::codec::codec_event(codec, DECODE_IPV6_TRUNCATED_EXT, &mut *sink);
            return false;
        }

        // cc:80-:83 the four writes, this file's ORDER (nxt, csum,
        // cnt++, bits) — vectors:13 next=6 csumproto=6 cnt=1
        // bits=65536. count++ on u8 wraps per the C-unsigned rule
        // (cd_no_next carry).
        codec.next_prot_id = hbh_nxt as ProtocolId; // cc:80 (ProtocolId) cast = widening
        codec.ip6_csum_proto = hbh_nxt; // cc:81
        codec.ip6_extension_count = codec.ip6_extension_count.wrapping_add(1); // cc:82
        codec.proto_bits |= PROTO_BIT__IP6_EXT; // cc:83 (= 0x10000 = 65536)

        // cc:85-:86 "// must be called AFTER setting next_prot_id" —
        // the landed 18d check (framework/codec.rs): HOPOPTS order 1 >
        // curr 0 -> curr_ip6_extension = 1, zero events on the pinned
        // face (CheckIPv6ExtensionOrder never fires inside the replay).
        crate::framework::codec::check_ipv6_extension_order(
            codec,
            ip_protocol::HOPOPTS,
            &mut *sink,
        );
        // cc:87-:90 `if ( CheckIPV6HopOptions(raw, codec)) return true;
        // return false;` — the landed 17d walk (codec.rs; zero option
        // bytes at the vec:13 face -> true; the H6/H3/H4 latch history
        // there is UNTOUCHED by this row). Literal C tail flow:
        // needless_bool suppressed to keep the if/return shape
        // diff-evident against cc:87-:90 (codec.rs needless_return
        // precedent).
        #[allow(clippy::needless_bool)] // literal C flow kept readable
        if crate::framework::codec::check_ipv6_hop_options(raw, codec, &mut *sink) {
            return true;
        }
        false
    }
}

// cc:102-:106 `static Codec* ctor(Module*)` / `static void
// dtor(Codec*)` — presence-bool slots of the record below (the
// mod_ctor/mod_dtor pair stays nullptr here: hopopts has NO module —
// the vectors:9 `mod_ctor=1` face is igmp's ALONE, ext PLAN §3).

/// cc:108-:128 `static const CodecApi ipv6_hopopts_api` — vectors:1
/// `API hopopts type=0 size=112 ver=1900547 name=ipv6_hop_opts` +
/// vectors:2 HELP. features = PLUGIN_SO_RELOAD (cc:114) like the four
/// sibling 18e records (features=0 stays the cd_default outlier, 18c).
pub const IPV6_HOPOPTS_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:110
    size: CDAPI_SIZEOF_CODEC_API, // cc:111 (112 probe pin)
    api_version: CDAPI_VERSION, // cc:112 (1900547)
    version: 0,      // cc:113
    features: PLUGIN_SO_RELOAD, // cc:114
    options: API_OPTIONS, // cc:115
    name: CD_HOPOPTS_NAME, // cc:116
    help: CD_HOPOPTS_HELP, // cc:117
    mod_ctor: false, // cc:118 nullptr
    mod_dtor: false, // cc:119 nullptr
    // cc:121-:126 nullptr pinit/pterm/tinit/tterm; ctor/dtor SET
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true, // cc:125
    dtor: true, // cc:126
};

/// cc:130-:143 the export. THE ODDITY (module doc): the BUILDING_SO
/// arms are COMMENTED OUT (`//#ifdef` / `//SO_PUBLIC` / `//#else` /
/// `//#endif` at cc:134/:135/:136/:138) — cd_hopopts[] is the ONLY
/// unconditional export of the five (always static; the cc:130-:132
/// comment states the statics-pull intent). Rust fold identical to
/// 18c/18d: null-terminated `const BaseApi* cd_hopopts[]` -> 1-elem
/// CodecTable slice. Symbol-vs-file tripwire: extern name `cd_hopopts`
/// (codec_api.rs STATIC names list) vs this file's base `cd_hop_opts`.
pub const CD_HOP_OPTS: crate::framework::codec::CodecTable = &[&IPV6_HOPOPTS_API];
