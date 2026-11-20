//! Port of `src/codecs/link/cd_arp.cc` (128 L) — row 18d.
//! Ground: snort3-src @ fe29cbe, md5 `3520b36cf3cfd62b01528021c156f48c`
//! (eth PLAN §0). The ARP link codec: a length-gated decode (no
//! header parsing at all — cc:67-:79) + the exported `cd_arp[]` table
//! (cc:119-:127).
//!
//! vectors pins (tools/eth_harness/vectors.txt — the same 15 L, md5
//! 1bd98dbb57dd2f536104995bd76d9bad; arp block = vec:10-:14):
//!   vec:10 `API arp name=arp` (the probe's short face)
//!   vec:11 `HELPARP support for address resolution protocol` — NO
//!          DLT suffix (cc:32: CD_ARP_HELP is the PLAIN string; the
//!          CONTRAST arm pinning the ADD_DLT ladder as per-codec, eth
//!          PLAN §3)
//!   vec:12 `EV 116 109` DECODE_ARP_TRUNCATED — LITERAL at
//!          codec_module.h:73 (`= 109` in the enum itself; the walk
//!          needs NO work — double-pin discipline vs the 424 WALK)
//!   vec:13 `ARP short -> 0` (27 B < ETHERARP_HDR_LEN 28)
//!   vec:14 `ARP ok -> 1 lyr=28 bits=4194304` (PROTO_BIT__ARP
//!          0x400000 == 4194304 decimal, decode_data.h:109 — the
//!          all-decimal posture; vec:15 is the CodecModule MOD line).
//!
//! get_protocol_ids (cc:61-:65) pushes ETHERTYPE_ARP 0x0806 +
//! ETHERTYPE_REVARP 0x8035 (protocol_ids.h:145/:148): the probe NEVER
//! calls arp->get_protocol_ids (no PIDS line for arp — eth §3 arms),
//! so the pair rides as the literal port with cites, exercised by a
//! Rust-side unit arm in tests/eth_parity_test.rs.

use crate::codecs::codec_module::CodecSid;
use crate::framework::codec::{
    protocol_id, API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecApiRecord, CodecData,
    PLUGIN_SO_RELOAD, PT_CODEC, PROTO_BIT__ARP, QueueSink, RawData,
};

/// arp.h:50 `constexpr uint16_t ETHERARP_HDR_LEN = 28;` — with the C
/// comment kept: `/* sizeof EtherARP != 28 */` (the struct on paper is
/// 30 B; the constant is the pinned wire-length gate, never a size_of).
pub const ETHERARP_HDR_LEN: u16 = 28;

/// cc:31 `#define CD_ARP_NAME "arp"`
pub const CD_ARP_NAME: &str = "arp";
/// cc:32 `#define CD_ARP_HELP "support for address resolution
/// protocol"` — NO ADD_DLT wrapper (the contrast arm: vectors:12 has
/// no ` (DLT …)` suffix).
pub const CD_ARP_HELP: &str = "support for address resolution protocol";

/// cc:36-:40 `static const RuleMap arp_rules[]` — one row + the
/// `{ 0, nullptr }` terminator.
pub const ARP_RULES: [(u32, &str); 2] = [
    (CodecSid::DECODE_ARP_TRUNCATED as u32, "truncated ARP"), // cc:38 (h:73 LITERAL = 109)
    (0, ""),                                                  // cc:39
];

/// cc:42-:49 `class ArpModule : public BaseCodecModule` — ctor face
/// `BaseCodecModule(CD_ARP_NAME, CD_ARP_HELP)`; get_rules returns
/// arp_rules (cc:47-:48).
#[derive(Default)]
pub struct ArpModule;

impl ArpModule {
    pub fn new() -> ArpModule {
        ArpModule
    }
    pub fn get_rules() -> &'static [(u32, &'static str); 2] {
        &ARP_RULES
    }
}

/// cc:51-:58 `class ArpCodec : public Codec` — two overrides only.
#[derive(Default)]
pub struct ArpCodec;

impl ArpCodec {
    /// cc:54 `ArpCodec() : Codec(CD_ARP_NAME) { }`
    pub fn new() -> ArpCodec {
        ArpCodec
    }

    /// cc:61-:65 `get_protocol_ids`: emplace_back(ETHERTYPE_ARP) then
    /// emplace_back(ETHERTYPE_REVARP) — push order literal (0x0806 =
    /// 2054, 0x8035 = 32821; protocol_ids.h:145/:148).
    pub fn get_protocol_ids(&self, v: &mut Vec<u16>) {
        v.push(protocol_id::ETHERTYPE_ARP); // cc:63
        v.push(protocol_id::ETHERTYPE_REVARP); // cc:64
    }

    /// cc:67-:79 out-of-line decode. NO header parsing at all — the
    /// length gate is the only logic (the C DecodeData& operand is
    /// unnamed, cc:67 — never-read posture as 18c).
    pub fn decode(&self, raw: &RawData<'_>, codec: &mut CodecData<'_>, sink: QueueSink) -> bool {
        // cc:69-:73 `if (raw.len < arp::ETHERARP_HDR_LEN)` -> event +
        // false. vectors: `EV 116 109` then `ARP short -> 0`.
        // vectors:12 `EV 116 109` then vectors:13 `ARP short -> 0`.
        if raw.len < ETHERARP_HDR_LEN as u32 {
            crate::framework::codec::codec_event(codec, CodecSid::DECODE_ARP_TRUNCATED as u32, sink);
            return false;
        }

        // cc:75-:76 — the ONLY mutations: proto_bits |=
        // PROTO_BIT__ARP, lyr_len = ETHERARP_HDR_LEN. vectors:14
        // `ARP ok -> 1 lyr=28 bits=4194304` (next_prot_id STAYS the
        // probe's init ETHERTYPE_NOT_SET — no line prints it).
        codec.proto_bits |= PROTO_BIT__ARP; // cc:75
        codec.lyr_len = ETHERARP_HDR_LEN; // cc:76

        // cc:78
        true
    }
}

/// cc:85-:95 the four static ctor/dtor faces — presence-bool slots
/// (17w/18c posture); cc:107-:108 set the module pair EXACTLY like
/// cd_eth's cc:242-:243.
///
/// cc:97-:117 `static const CodecApi arp_api` — vectors:`API arp
/// name=arp` + `HELPARP support for address resolution protocol`.
pub const ARP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:100
    size: CDAPI_SIZEOF_CODEC_API, // cc:101 sizeof(CodecApi)
    api_version: CDAPI_VERSION, // cc:102 (== 1900547)
    version: 0,      // cc:103
    features: PLUGIN_SO_RELOAD, // cc:104
    options: API_OPTIONS, // cc:105
    name: CD_ARP_NAME, // cc:106
    help: CD_ARP_HELP, // cc:107 (no DLT splice — the contrast arm)
    mod_ctor: true,  // cc:108 SET (the EthModule/ArpModule news —
    mod_dtor: true,  // cc:109 contrast vs the four 18c no-op records
    //                       with nullptr module slots)
    pinit: false,    // cc:111 nullptr // pinit
    pterm: false,    // cc:112 nullptr // pterm
    tinit: false,    // cc:113 nullptr // tinit
    tterm: false,    // cc:114 nullptr // tterm
    ctor: true,      // cc:115 ctor — the probe's aa->ctor(nullptr)
    dtor: true,      // cc:116 dtor
};

/// cc:119-:127 export (non-BUILDING_SO face; alternation folded as
/// the four 18c TUs — deviations row 18c unchanged). eth PLAN §5
/// keeps this the collision-free face: the vocab witness set carries
/// NO cd_arp stub, so 18d's REAL cd_arp[] (nm `D cd_arp`,
/// cd_arp.cc:122) collides with nothing and NO stub retires here.
pub const CD_ARP: crate::framework::codec::CodecTable = &[&ARP_API];
