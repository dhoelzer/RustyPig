//! Port of `src/codecs/ip/cd_igmp.cc` (138 L) — row 18e.
//! Ground: snort3-src @ fe29cbe, md5 `9dfbc89efc2a1eb7ea4861dca69fd826`
//! (ext PLAN §0). DIR FACT: `codecs/ip/`.
//!
//! THE include-closure finding (ext PLAN §0, NEXT.md CORRECTION):
//! cd_igmp.cc has THREE includes only — config.h cc:21,
//! framework/codec.h cc:24, codec_module.h cc:25 — and NO
//! main/snort_config.h: igmp rides `snort.ip_api` (DecodeData), not
//! SnortConfig. It is the ONLY 18e unit with NO conf touch: zero
//! hit_ip6_maxopts arms anywhere here.
//!
//! THE Module pair (first in the 18e five): `IgmpModule :
//! public BaseCodecModule` (cc:39-:47) + the one-row `igmp_rules`
//! RuleMap table (cc:34-:37) — vectors read the face:
//!   vec:26 `IGMP mod_ctor=1 mod_dtor=1` (the igmp_api cc:118-:119
//!           slots — the ONLY TRUE pair among all 18e records; the
//!           other four cc:118/:119-arms are nullptr)
//!   vec:27 `IGMP rules=1 sid0=455 name=igmp` — the `while
//!           (rmap[n].sid) n++` walk (probe) over { DECODE_IGMP_
//!           OPTIONS_DOS=455 (codec_module.h:208 Literal, landed 18d),
//!           { 0, nullptr } } + get_name(). RuleMap struct + the
//!           `rule_count` walker are the landed 18d homes
//!           (codec_module.rs — reused, not re-forked; the 17z/18a
//!           tuple precedent stays for FMOD, this row rides the struct
//!           precedent like GENERAL_DECODE_RULES).
//!   vec:25 `IGMP_PID 2 n=1` (cc:86-:89, ProtocolId::IGMP = 2).
//!
//! THE IpApi-LITE SEAM — LEFT-OPEN RULING (ext recon §6.6, named in
//! deviations row 18e): the decode's guard reads THREE DecodeData
//! fields through `snort.ip_api` (cc:61 is_ip4(), cc:63
//! get_ip_opt_data(), cc:67 get_ip_opt_len()). framework/codec.rs
//! header note: DecodeData has NO Rust ip_api twin (the C reference
//! members were dropped at 17d; pointers dropped). Rather than fork a
//! full IpApi, this row lands the MINIMAL read-only seam `IpApiLite`
//! ({is_ip4, opt_data: Option<&[u8]>, opt_len: u32}) — enough to
//! replay the four cc:61-:82 arms — and the REAL wiring (which layer
//! populates it per packet) stays OPEN for the parser rows: the tuple
//! (who feeds is_ip4 / opt_data / opt_len) is an OPEN seam, NOT a
//! resolved design. vectors never arm decode here (only the PIDS/
//! mod/rules faces are probed) — the decode arms land as literal
//! transcription with cited unit arms ONLY (18d port-by-reading rule;
//! every unit-arm value is derived from the C statement, never a
//! pinned vectors line).
//!
//! The flag pair: CODEC_IPOPT_RTRALT_SEEN 0x0020 + CODEC_IPOPT_
//! LEN_THREE 0x0040 landed 17d/18c (codec.rs :47/:48) — reused. The
//! cc:77-:82 second event arm fires the SAME sid 455 (no return) and
//! decode falls to the cc:83 `return true`.

use crate::codecs::codec_module::{BaseCodecModule, CodecSid, RuleMap};
use crate::framework::codec::{
    API_OPTIONS, CodecApiRecord, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CODEC_IPOPT_LEN_THREE,
    CODEC_IPOPT_RTRALT_SEEN, CodecData, PLUGIN_SO_RELOAD, PT_CODEC, ProtocolId, RawData,
};

/// cc:28 `#define CD_IGMP_NAME "igmp"`
pub const CD_IGMP_NAME: &str = "igmp";
/// cc:29 `#define CD_IGMP_HELP "support for Internet group management
/// protocol"` — vectors:10 face (full words, no abbreviation kept).
pub const CD_IGMP_HELP: &str = "support for Internet group management protocol";

/// cc:34-:37 `static const RuleMap igmp_rules[]` — the ONE-row table +
/// the `{ 0, nullptr }` terminator (msg stays Option None, never read
/// past the sid-0 stop — the landed 18d RuleMap posture).
pub const IGMP_RULES: [RuleMap; 2] = [
    RuleMap {
        sid: 455, // DECODE_IGMP_OPTIONS_DOS (codec_module.h:208, landed enum)
        msg: Some("DOS IGMP IP options validation attempt"), // cc:36 verbatim
    },
    RuleMap { sid: 0, msg: None }, // cc:37 terminator
];

/// cc:39-:47 `class IgmpModule : public BaseCodecModule` — the 2-arg
/// BaseCodecModule ctor (h:243, params slot untouched — the 18d
/// census face `trace=null`/no-params), get_rules() override cc:45-:46
/// returns the table head.
#[derive(Debug)]
pub struct IgmpModule {
    pub base: BaseCodecModule,
}

impl IgmpModule {
    /// cc:41 `IgmpModule() : BaseCodecModule(CD_IGMP_NAME, CD_IGMP_HELP) { }`
    pub fn new() -> IgmpModule {
        IgmpModule {
            base: BaseCodecModule::new(CD_IGMP_NAME, CD_IGMP_HELP),
        }
    }

    /// cc:45-:46 `{ return igmp_rules; }` — Rust hands the landed
    /// slice; the probe's `while (sid) n++` walk (vec:27 `rules=1`)
    /// rides the landed `rule_count` fn.
    pub fn get_rules() -> &'static [RuleMap] {
        &IGMP_RULES
    }

    /// mod-ctor name face: vectors:27 `name=igmp` (Module::get_name
    /// over the cc:41 name slot; gid/usage faces ride the landed
    /// BaseCodecModule: GID 116 h:249-:250, Usage CONTEXT h:253-:254).
    pub fn get_name(&self) -> &'static str {
        self.base.name
    }
}

// the landed CodecModule Default twin (codec_module.rs:421) — the
// mod_ctor() face constructs via new().
impl Default for IgmpModule {
    fn default() -> Self {
        Self::new()
    }
}

/// THE left-open seam (module doc): the read-only stand-in for the
/// three `snort.ip_api` reads of cc:61-:67. NOT a full IpApi port —
/// the producing layer stays open. Names mirror the C call sites:
/// is_ip4() / get_ip_opt_data() / get_ip_opt_len().
#[derive(Copy, Clone, Default)]
pub struct IpApiLite {
    pub is_ip4: bool,                // cc:61 snort.ip_api.is_ip4()
    pub opt_data: Option<&'static [u8]>, // cc:63 get_ip_opt_data() (nullptr face)
    pub opt_len: u32,                // cc:67 get_ip_opt_len()
}

#[derive(Default)]
pub struct IgmpCodec;

impl IgmpCodec {
    /// cc:52 `IgmpCodec() : Codec(CD_IGMP_NAME) { }`
    pub fn new() -> IgmpCodec {
        IgmpCodec
    }

    /// cc:86-:89 — vectors:25 `IGMP_PID 2 n=1` (ProtocolId::IGMP = 2).
    pub fn get_protocol_ids(&self, v: &mut Vec<ProtocolId>) {
        v.push(crate::framework::codec::protocol_id::IGMP); // cc:88
    }

    /// cc:59-:84 out-of-line decode — the ONLY 18e decode that reads
    /// the DecodeData operand (named `snort` in C, cc:59 — kept as
    /// the param name). Literal transcription (module doc: no vectors
    /// line arms this); every arm cited.
    pub fn decode(
        &self,
        raw: &RawData<'_>,
        codec: &mut CodecData<'_>,
        snort: &IpApiLite,
        sink: crate::framework::codec::QueueSink,
    ) -> bool {
        // cc:61 the three-operand guard, short-circuit order kept:
        // is_ip4 && raw.len >= 1 && data[0] == 0x11 (IGMP Membership
        // Query type). Rust && mirrors the C && (the .get posture
        // stands where the C UB-reads raw.data[0] — guarded HERE by
        // the len >= 1 operand anyway, so data[0] only reads in-bounds).
        if snort.is_ip4 && raw.len >= 1 && raw.data.first().copied() == Some(0x11u8) {
            // cc:63-:74 the ip-options DOS arm: opt_data non-null,
            // opt_len >= 2, first TWO opt bytes both 0 -> event +
            // RETURN FALSE (the only false return of this decode).
            // C's THREE nested ifs (cc:65 != nullptr / cc:67 >= 2 /
            // cc:69 the pair) kept literal — collapsible_if
            // suppressed for the diff-evident shape (codec.rs:610
            // precedent).
            #[allow(clippy::collapsible_if)] // literal C nesting kept
            if let Some(ip_opt_data) = snort.opt_data {
                #[allow(clippy::collapsible_if)] // literal C nesting kept
                if snort.opt_len >= 2 {
                    if ip_opt_data.first().copied() == Some(0)
                        && ip_opt_data.get(1).copied() == Some(0)
                    {
                        crate::framework::codec::codec_event(
                            codec,
                            CodecSid::DECODE_IGMP_OPTIONS_DOS as u32,
                            &mut *sink,
                        );
                        return false; // cc:72
                    }
                }
            }

            // cc:77-:81 `if ((!(codec_flags & CODEC_IPOPT_RTRALT_SEEN))
            // && (codec_flags & CODEC_IPOPT_LEN_THREE))` -> the SAME
            // event 455, NO return (event-then-fall-to-true).
            if (codec.codec_flags & CODEC_IPOPT_RTRALT_SEEN == 0)
                && (codec.codec_flags & CODEC_IPOPT_LEN_THREE != 0)
            {
                crate::framework::codec::codec_event(
                    codec,
                    CodecSid::DECODE_IGMP_OPTIONS_DOS as u32,
                    &mut *sink,
                );
            }
        }
        // cc:83 — unconditional true (the flag arm above never
        // short-circuits; only the ip_opt_data double-zero returns
        // false, cc:72).
        true
    }
}

// cc:95-:99 the MODULE pair — `static Module* mod_ctor() { return
// new IgmpModule; }` + `static void mod_dtor(Module* m) { delete m;
// }`. The Rust face is the IgmpModule::new above (no heap ownership:
// the record below lands mod_ctor/mod_dtor TRUE — the presence-bool
// census, vectors:26 `mod_ctor=1 mod_dtor=1`, the ONLY 18e record
// where the pair lands set; the 18d cd_eth/cd_arp TRUE census
// precedent extends with its module-pair meaning here).
// cc:101-:105 the CODEC ctor/dtor pair (presence below).

/// cc:107-:127 `static const CodecApi igmp_api` — vectors:9
/// `API igmp type=0 size=112 ver=1900547 name=igmp` (the probe_dec
/// api() line) + vectors:10 HELP + the mod pair readback vec:26.
pub const IGMP_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:109
    size: CDAPI_SIZEOF_CODEC_API, // cc:110
    api_version: CDAPI_VERSION, // cc:111
    version: 0,      // cc:112
    features: PLUGIN_SO_RELOAD, // cc:113
    options: API_OPTIONS, // cc:114
    name: CD_IGMP_NAME, // cc:115
    help: CD_IGMP_HELP, // cc:116
    mod_ctor: true,  // cc:118 SET — igmp is the only 18e module
    mod_dtor: true,  // cc:119 SET
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true, // cc:124
    dtor: true, // cc:125
};

/// cc:129-:137 the export — non-DSO arm `const BaseApi* cd_igmp[]`
/// (folded DSO branch = 18c deviation carries). The STATIC_CODECS
/// ladder name `cd_igmp` (codec_api.rs:116 tripwire) already pins
/// this table; stub consts untouched (ext PLAN §6).
pub const CD_IGMP: crate::framework::codec::CodecTable = &[&IGMP_API];
