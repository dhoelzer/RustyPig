//! Port of `src/codecs/codec_api.h` (26 L) + `src/codecs/codec_api.cc`
//! (121 L) — row 18c.  Ground: snort3-src @ fe29cbe, md5
//! `df2bc9d1f74314408a3ced3be3e4d2ad` / `77b4bd8671720d1b6d1afbf33e024ee1`.
//!
//! codec_api.h is a 26-L header whose only content is the `void
//! load_codecs();` export (codec_api.h:23) — the C .h+.cc pair lands as
//! THIS one module; no separate header file.
//!
//! C `PluginManager::load_plugins(const BaseApi**)` (managers/
//! plugin_manager.h:59, the `managers/plugin_manager.cc` TU is NOT in
//! this row) is the load seam: the harness stands a witness body
//! (tools/vocab_harness/probe.cc:26-:30 prints `LOAD <table[0]->name>`);
//! the Rust twin threads a `LoadSink` so the replay (`tests/
//! vocab_parity_test.rs`) observes the identical 5-line ORDER
//! (vectors.txt:24-:28 + `LOADS 5` at :29).
//!
//! The four plugin tables codec_api.cc:32-:34/:36 externs for LATER
//! row-18 subrows (cd_ipv4/cd_ipv6/cd_tcp/cd_hopopts — the 18e/19
//! tail) stand here as WITNESS stub records mirroring tools/
//! vocab_harness/witness_stubs.cc:7-:14 VERBATIM (name pins
//! `cd_ipv4_stub` ... — the stub names, not the later real names, are
//! what the frozen 29-L vectors replay). R3 rule (vocab PLAN §4):
//! later rows swap the real tables IN HERE; they never link a second
//! table of that name.
//!
//! `#ifdef STATIC_CODECS` (cc:39-:74 extern block, cc:84-:119 the 34
//! load_plugins calls) is NOT defined in the ground/harness build —
//! the vectors pin `LOADS 5` (vectors.txt:29): the ladder lands as a
//! dormant name table (`STATIC_CODECS = false`), the 34 extern names
//! VERBATIM in cc order. Pin: the extern DECALARATION order
//! (cc:31-:36) is default, ipv4, ipv6, hopopts, tcp but the LOAD
//! order (cc:78-:82) is default, ipv4, ipv6, tcp, hopopts — the
//! hopopts/tcp SWAP between the two; the replay pins the load order.

use crate::framework::codec::{
    API_OPTIONS, API_RESERVED, CodecApiRecord, CodecTable, PT_CODEC,
};

// ---- the always-loaded five (externs cc:31-:36; loads cc:78-:82) ----
// cd_default is REAL (its TU is in this row); the other four tables
// are witness stubs standing for later rows (module doc above).
pub use crate::codecs::cd_default::CD_DEFAULT;

/// cc:32 `extern const BaseApi* cd_ipv4[];` stand-in for the 18e/19
/// tail — witness_stubs.cc:7 `{ PT_CODEC, 0,0,0,0,nullptr,
/// "cd_ipv4_stub",nullptr,nullptr,nullptr }`: BaseApi slots zeroed
/// (size 0, api_version 0, features 0; the C nullptr options/help land
/// as "" — the 17z stand-in precedent). NOT sizeof-pinned, and NOT a
/// real CodecApi record: the witness never reads those slots —
/// load_plugins prints table[0]->name only.
pub const CD_IPV4: CodecTable = &[&CD_IPV4_STUB];
/// cc:33 `extern const BaseApi* cd_ipv6[];` — witness_stubs.cc:8.
pub const CD_IPV6: CodecTable = &[&CD_IPV6_STUB];
/// cc:34 `extern const BaseApi* cd_hopopts[];` — witness_stubs.cc:10.
pub const CD_HOP_OPTS: CodecTable = &[&CD_HOP_OPTS_STUB];
/// cc:36 `extern const BaseApi* cd_tcp[];` — witness_stubs.cc:9.
pub const CD_TCP: CodecTable = &[&CD_TCP_STUB];

const fn stub(name: &'static str) -> CodecApiRecord {
    // the witness_stubs.cc brace order transcribed slot-for-slot:
    // { PT_CODEC, 0,0,0,0,nullptr, name, nullptr, nullptr, nullptr }
    CodecApiRecord {
        ptype: PT_CODEC,
        size: 0,
        api_version: 0,
        version: 0,
        features: API_RESERVED, // the 0 literal == API_RESERVED
        options: API_OPTIONS,   // the 0 literal == API_OPTIONS
        name,
        help: "",
        mod_ctor: false,
        mod_dtor: false,
        pinit: false,
        pterm: false,
        tinit: false,
        tterm: false,
        ctor: false,
        dtor: false,
    }
}

const CD_IPV4_STUB: CodecApiRecord = stub("cd_ipv4_stub");
const CD_IPV6_STUB: CodecApiRecord = stub("cd_ipv6_stub");
const CD_TCP_STUB: CodecApiRecord = stub("cd_tcp_stub");
const CD_HOP_OPTS_STUB: CodecApiRecord = stub("cd_hopopts_stub");

/// cc:39 `#ifdef STATIC_CODECS` — NOT defined at the build face the
/// vectors pin (`LOADS 5`, vectors.txt:29). Later rows that flip this
/// const swap the STATIC table slots below to their real records (R3).
#[allow(dead_code)] // the dormant arm's gate value; 18e/19 tail lands it
                   // (the vocab_parity tripwire test reads it back)
pub const STATIC_CODECS: bool = false;

/// codec_api.cc:40-:73 the 34 STATIC_CODECS externs, cc ORDER verbatim
/// (the :85-:118 load ladder re-loads the SAME 34 in the same order).
#[allow(dead_code)] // dormant until the STATIC_CODECS row (see STATIC_CODECS)
pub const STATIC_CODEC_EXTERN_NAMES: [&str; 34] = [
    "cd_ah",
    "cd_arp",
    "cd_bad_proto",
    "cd_ciscometadata",
    "cd_dstopts",
    "cd_erspan2",
    "cd_erspan3",
    "cd_esp",
    "cd_eth",
    "cd_fabricpath",
    "cd_frag",
    "cd_geneve",
    "cd_gre",
    "cd_gtp",
    "cd_icmp4",
    "cd_icmp4_ip",
    "cd_icmp6",
    "cd_icmp6_ip",
    "cd_igmp",
    "cd_llc",
    "cd_mobility",
    "cd_mpls",
    "cd_no_next",
    "cd_pgm",
    "cd_pppencap",
    "cd_pppoepkt",
    "cd_raw",
    "cd_routing",
    "cd_teredo",
    "cd_transbridge",
    "cd_udp",
    "cd_user",
    "cd_vlan",
    "cd_vxlan",
];

/// The plugin-manager load seam: twin of the probe's witness
/// PluginManager::load_plugins (probe.cc:26-:30 — the real
/// managers/plugin_manager.cc TU is NOT in this row's closure, the nm
/// census names it as the only codec_api.o residue, PLAN §2). The
/// sink observes one call per table with the table head; C derefs
/// plugins[0] unguarded, the null-terminated tables always carry a
/// live head.
pub type LoadSink<'a> = &'a mut dyn FnMut(&'static CodecApiRecord);

/// cc:76-:120 `void load_codecs()` — the five always-loaded tables in
/// the cc:78-:82 CALL order (NOT the cc:31-:36 declaration order —
/// the hopopts/tcp swap note above), then the dormant STATIC_CODECS
/// arm. `PluginManager::load_plugins(x)` statics map 1:1: one sink
/// call per load_plugins call.
#[allow(clippy::needless_return)] // literal C flow: the #ifdef arm is a compile-time branch
pub fn load_codecs(sink: LoadSink) {
    // cc:78-:82 verbatim call order
    PluginLoad::run(CD_DEFAULT, sink);
    PluginLoad::run(CD_IPV4, sink);
    PluginLoad::run(CD_IPV6, sink);
    PluginLoad::run(CD_TCP, sink);
    PluginLoad::run(CD_HOP_OPTS, sink);

    // cc:84-:119 `#ifdef STATIC_CODECS` ... `#endif` — compiled out at
    // the build face the frozen vectors pin (LOADS 5 == the five above
    // only). STATIC_CODEC_EXTERN_NAMES freezes the would-be 34 in cc
    // order; the row that flips STATIC_CODECS swaps real tables into
    // this call ladder exactly where the names sit (R3).
}

/// The C `PluginManager::load_plugins(plugins)` static-call shape kept
/// as a named seam (prints table[0]->name in the witness body; the
/// 17z witness-home rule: the port carries the sink, production wires
/// the real PluginManager row).
struct PluginLoad;
impl PluginLoad {
    #[inline]
    fn run(table: CodecTable, sink: LoadSink) {
        sink(table[0]);
    }
}
