//! Port of `src/codecs/root/cd_raw.cc` (105 L) — row 18c.
//! Ground: snort3-src @ fe29cbe, md5 `d34183a11307f2256eef6297f8005c86`.
//!
//! The raw-IP DLT codec: decode sniffs the IP version nibble of the
//! first byte and hands out ETHERTYPE_IPV4 / ETHERTYPE_IPV6 (cc:46-:58);
//! get_data_link_type answers DLT_RAW (cc:60-:63). vectors pin v4 ->
//! next=2048 (vec 21), v6 -> next=34525 (vec 22), 0x50 -> false (vec 23).
//!
//! cc:24 `#include <daq_dlt.h>` — the ONLY such include in codecs/ and
//! absent on ground + host (NNNEXT.md 18c scoping: find = 0 hits all
//! three). The harness grafts the header (vocab PLAN §1); THE CITE for
//! the one constant it defines, `DLT_RAW 12` — real libpcap
//! `pcap/dlt.h` (android.googlesource mirror, lines 112-:114): DLT_RAW
//! is **14** on BSD/OS builds and **12** on the libpcap/libdaq
//! convention Snort links. The vectors pin 12 twice: the HELP string
//! via ADD_DLT (cc:31-:32, vec 20 `support for raw IP (DLT 12)`) and
//! get_data_link_type's `v.emplace_back(DLT_RAW)` (cc:62, vec 19
//! `DLT 12`). The DAQ SDK itself lands at row 20 (the 17d/18c
//! RawData-drops-daq_msg seam closes there).
//!
//! ADD_DLT (framework/codec.h:52 `#define ADD_DLT(help, x) help " (DLT
//! " STRINGIFY_MX(x) ")") is a C compile-time string splice; the Rust
//! port spells the spliced literal ("support for raw IP (DLT 12)") and
//! the helper below pins the recipe — a format macro, never a runtime
//! concat inside decode.

use crate::framework::codec::{
    API_OPTIONS, CDAPI_SIZEOF_CODEC_API, CDAPI_VERSION, CodecData, CodecApiRecord, PLUGIN_SO_RELOAD,
    PT_CODEC, RawData, protocol_id,
};

/// daq_dlt.h graft value (module doc carries the libpcap cite).
pub const DLT_RAW: i32 = 12;

/// cc:30 `#define CD_RAW_NAME "raw"`
pub const CD_RAW_NAME: &str = "raw";
/// cc:31 `#define CD_RAW_HELP_STR "support for raw IP"`
pub const CD_RAW_HELP_STR: &str = "support for raw IP";
/// cc:32 `#define CD_RAW_HELP ADD_DLT(CD_RAW_HELP_STR, DLT_RAW)` — the
/// compile-time splice of codec.h:52 evaluated at the graft value 12:
/// vectors:20 `HELP support for raw IP (DLT 12)`.
pub const CD_RAW_HELP: &str = "support for raw IP (DLT 12)";

/// codec.h:52 ADD_DLT recipe spelled as a fn (pin for the literal
/// above: `"support for raw IP"` + `" (DLT "` + stringify(12) + `")"`;
/// vectors vec 20 asserts the composition so the literal can never
/// drift from the graft constant).
pub fn add_dlt(help: &str, dlt: i32) -> String {
    format!("{help} (DLT {dlt})")
}

/// cc:36-:43 `class RawCodec : public Codec` — the C member name
/// `get_data_link_type` (virtual over ride, cc:42). NO
/// get_protocol_ids override: the base returns an empty vector (the
/// vectors raw block prints no PID line — cc base posture).
#[derive(Default)]
pub struct RawCodec;

impl RawCodec {
    /// cc:39 `RawCodec() : Codec(CD_RAW_NAME) { }`
    pub fn new() -> RawCodec {
        RawCodec
    }

    /// cc:46-:58 out-of-line def: `(raw.data[0] & 0xf0)` — C reads
    /// data[0] unguarded (a decode is never called with an empty
    /// buffer; the probe cc:60-:66 arms all feed len>=1).
    /// 0x40 -> ETHERTYPE_IPV4; 0x60 -> ETHERTYPE_IPV6; else false with
    /// NO mutation of next_prot_id (vec 23: the bad arm returns 0; the
    //  CodecData keeps its init ETHERTYPE_NOT_SET — probe inits
    // ProtocolId::ETHERTYPE_NOT_SET, vec 23 prints no next= field).
    pub fn decode(&self, raw: &RawData<'_>, data: &mut CodecData<'_>) -> bool {
        let ipver = raw.data[0] & 0xf0;

        if ipver == 0x40 {
            // cc:51
            data.next_prot_id = protocol_id::ETHERTYPE_IPV4;
        } else if ipver == 0x60 {
            // cc:53
            data.next_prot_id = protocol_id::ETHERTYPE_IPV6;
        } else {
            // cc:55
            return false;
        }

        // cc:57
        true
    }

    /// cc:60-:63 `void RawCodec::get_data_link_type(std::vector<int>& v)
    /// { v.emplace_back(DLT_RAW); }` — vectors:19 `DLT 12`.
    pub fn get_data_link_type(&self, v: &mut Vec<i32>) {
        v.push(DLT_RAW);
    }
}

/// cc:75-:95 `static const CodecApi raw_api` — vectors:18 `API raw ...
/// features=1 name=raw` (cc:82 PLUGIN_SO_RELOAD); HELP at vec 20
/// carries the ADD_DLT splice.
pub const RAW_API: CodecApiRecord = CodecApiRecord {
    ptype: PT_CODEC, // cc:78
    size: CDAPI_SIZEOF_CODEC_API, // cc:79
    api_version: CDAPI_VERSION, // cc:80
    version: 0,      // cc:81
    features: PLUGIN_SO_RELOAD, // cc:82
    options: API_OPTIONS, // cc:83
    name: CD_RAW_NAME, // cc:84
    help: CD_RAW_HELP, // cc:85
    mod_ctor: false, // cc:86
    mod_dtor: false, // cc:87
    pinit: false,
    pterm: false,
    tinit: false,
    tterm: false,
    ctor: true, // cc:93
    dtor: true, // cc:94
};

/// cc:97-:105 export (non-BUILDING_SO face; BUILDING_SO alternation
/// folded, row 18c deviation). STATIC_CODECS-only ladder member
/// (cc:111), not in the always-loaded five.
pub const CD_RAW: crate::framework::codec::CodecTable = &[&RAW_API];
