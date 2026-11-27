//! Row 24i — the analyzer-command pair landing (chapter-21 NINTH body).
//!
//! Ground: main/analyzer-command .cc 583 L md5 2fe847d72cdac14b4b1f5a572d693646 +
//! main/analyzer-command .h 267 L md5 9e9ee8432e295ddecfb5673bed316cc9 @
//! fe29cbe (the 850 L ledger; MEASURED at this row: wc 583/267, the md5 faces
//! above re-verified). The mod wiring is the ONE line this row flips 12 -> 13
//! (the complete-flip law; the 24d/24e/24f/24g rows each added one wiring
//! line — this landing genuinely FIRES that row).
//!
//! THE STATIC CENSUS (grep-measured on the ground pair, the echo the twin
//! replays): the ground .cc carries EXACTLY-6 `^static` lines (:55
//! report-time, :56 report-period, :57 invalid-ip, :60 format-ip-addr, :74
//! tuner-next, :83 tuner-update) OVER the `static THREAD_LOCAL` face at :55 —
//! the THREAD_LOCAL count is EXACTLY-1 in the cc, EXACTLY-0 in the .h; the
//! .h carries EXACTLY-1 `^static` line (:104, the clear-counter string-map
//! vector — the ONE header ^static the census pins, h :104-:113). Census
//! echo: ^static 6 + 1 = 7; THREAD_LOCAL 1 + 0 = 1. The port rides them to
//! honest Rust seats: report-time lands as the ROW-OWNED thread-local Cell
//! below (the 24g sn-conf conf-slot PATTERN cite — the thread-local block at
//! that home :1077-:1086; different record, never that record);
//! report-period + invalid-ip land as consts; the string map lands as the
//! pub const [&str; 7] (h :104-:113 values VERBATIM); the two static helper
//! fns land pub-pure (the timeradd legs REUSE the an-zl home :269-:277 —
//! NEVER re-forked; the timercmp '>' macro face cc :88 lands as the row cmp
//! fn, the cppcheck-suppress comment kept).
//!
//! THE CITE / NEVER-LAND WALL (the 24d pattern re-ridden): the module
//! manager (managers/module-manager .cc :70/:1331/:1362/:1494/:1512), the
//! plug-in manager (managers/plug-in-manager .h :82), the swapper
//! (main/swapper .h :35/:43/:44/:46 + .cc :67/:83), the host-attributes
//! manager (target-based/host-attributes .cc :178/:188), the drop-stats
//! family (utils/stats .h :104-:108, utils/stats .cc :393), the packet-stats
//! family (protocols/packet-manager .h :63/:146/:147), the scratch-allocator
//! update virtual (helpers/scratch-allocator .h :44/:51) and the control-
//! conn class (control/control .h :69/:70/:71) ride cite-NEVER-land homes
//! over ONE provider seam trait ([`AnalyzerCommandWorld`], an
//! [`AnalyzerWorld`] super) plus the row object traits
//! ([`ControlConnFace`], [`ModuleFace`], [`ReloadTunerOps`],
//! [`ScratchUpdateFace`], [`SwapperFace`]). ZERO invented success past ANY
//! boundary: every default legs at the honest failure posture (the ioctl
//! defaults ride DAQ_ERROR from the landed 23a sf-daq home :63 — REUSE,
//! NEVER re-forked).
//!
//! THE ONE-HOME REUSE (landed homes RIDDEN, NEVER re-forked):
//! * the an-zl home (row 24d, the analysis-loop seat, main/an-zl .rs):
//!   [`AnalyzerCore`] is the execute target — start :879 / run :893 / stop
//!   :905 / pause :912 / resume :927 / rotate :950 / reload-daq :941 /
//!   get-state :542 / is-idling :550 / the id field :383 (h :153) — plus the
//!   STATE_PAUSED :91 + STATE_RUNNING :90 guards (the ACSwap state gate),
//!   [`Timeval`] :127, [`timeradd`] :269-:277 and the command-facility +
//!   refcount get/put law :638-:652 (the AF-i face the base mirrors at
//!   h :59-:60) all ride that home. The get-instance-id seat (main/thread
//!   .h :48 over the thread .cc :46 THREAD_LOCAL instance-id) NEVER ports:
//!   EVERY cc get-instance-id() call site (:76/:186/:326/:471/:568) rides
//!   the analyzer's OWN id field — the threaded-param law the thread home
//!   :1495 pins for that seat.
//! * the reload-tracker home (row 19a, LIVE landed struct):
//!   ReloadTracker::end (:214-:241) and end_default (:246-:248) are REUSED
//!   by the swap-swap / host-attributes-pair / scratch-update dtor ladders
//!   (cc :389/:402/:430). DEVIATION cite: that home pairs ctrlcon with its
//!   own Control-Conn-Tracker QUERY face (:80-:94, the current-command
//!   shape); THIS pair carries the respond/is-local face (control face
//!   :69-:71) with NO landed shape, so the dtor legs pass the NONE-conn
//!   face — the harness nullptr-control-conn precedent THAT home itself
//!   pins (:29-:33, "every call site passes nullptr"); its end-face
//!   debug-assert contract rides unchanged.
//! * the sn-conf home (row 24g, the config owner): SnortConfig :379 (the
//!   borrowed-conf arg of the scratch-update legs), the reload-tuner-face
//!   opaque SLOT token :349-:353 (cited, NEVER widened — the object face is
//!   the row trait), get-reload-resource-tuners :2521-:2523 +
//!   clear-reload-resource-tuner-list :2528-:2530 (REUSE cites the swapper
//!   face arms provider-side), and the main-broadcast-command seam that
//!   ALREADY lives there (the main-broadcast-ac-scratch-update leg :924-:927
//!   + update-scratch :1547-:1549) — CITED, NEVER moved or edited. This
//!     pair NEVER calls the broadcast seam (its call sites live in other TUs)
//!     so NO row trait leg re-models it (the 23i dialect law).
//! * the thread home (row 23b): ThreadConfig::get-instance-max :742-:747
//!   (the ROW-OWNED name law: the harness-side witness owns that name; this
//!   landing just CITES the home) sizes the three per-thread vectors (h
//!   :182/:229/:249); get-instance-tid :906-:911 arms the two report
//!   ladders (cc :448/:498), the cold -1 face rides through.
//! * the 23a sf-daq home: DAQ_SUCCESS :60 (cc :476/:574) + DAQ_ERROR :63 —
//!   imported, NEVER re-forked.
//! * the counts home (framework/counts .rs): PegCount :20, CountType
//!   :24-:36, PegInfo :44-:48 REUSE under the aggregation ladder (the REAL
//!   algorithm body lands below, framework/module .cc :109-:166 cited).
//! * the log home: LogEngine::log-message-stdout (log/messages .rs
//!   :353-:358, the quiet-gate + cfmt core REUSE cite) — the LogEngine
//!   rides as an explicit param (the reload-tracker home precedent :157,
//!   the C global-Log-Message legs threaded, NEVER re-stubbed).
//!
//! THE FLOAT FORMATTING LAW (the DEC heart, MEASURED at authoring): the
//! report ladders must byte-match glibc printf %.1f / %.3f. Probe receipt
//! (this host, gcc + rustc O0/O2 clean): a 200,000-line boundary-seeking
//! vector (LCG-seeded classes: .xxxxx5 seats at every decimal ladder, f32-
//! cpu-upcast faces, sum-times-1-0-div-count-div-1000 average faces, sign
//! arms) compared glibc printf("C %.1f|%.3f") against the landed cfmt core
//! (utils/cfmt .rs :159 + fmt-f :98-:103, the same core the Rust {:.1}
//! face uses) => EXACTLY-0 mismatched lines; plus a 16-value exact-binary
//! tie battery (0.125/0.375/... halves) and the 116-line f1/f3 battery,
//! EXACTLY-0. Naive scale-ROUND-divide helpers are REJECTED by double-
//! rounding drift (a probe caught the half-even-on-scaled face wrong); so
//! [`fmt_f1`]/[`fmt_f3`] land as honest cfmt-core WRAPPERS and the ladders
//! feed the ground format strings through cfmt — the render face the twin
//! replays BYTE-EQUAL. One formatting home, never re-forked.
//!
//! THE DIALECT FACES (MEASURED on the ground pair, the 23i law: measured
//! post-cited, NEVER invented live code): REG_TEST x1 in the .h (:261, the
//! main-unicast decl :262 inside the :261-:263 block) + x0 in the .cc —
//! REG_TEST is NEVER defined by this build system, so the main-unicast
//! decl lands as the CITED comment face at the file tail, NEVER a live
//! item. The enable-sh-ell token count is EXACTLY-0 in BOTH ground files
//! (grep-0 x2, MEASURED) — the sh-ell dial-ect is OFF and this pair carries
//! NO sh-ell leg. The main-broadcast decl h :264 already has its seam at
//! the sn-conf home (cites above) — cited, NEVER duplicated here.
//!
//! ZERO allow-attributes on THIS landing; ZERO un-safe surfaces (the prose
//! faces ride the split word); ZERO panics on port logic legs — the three
//! C out-of-bounds UB seats (the cc :327/:482/:580 unchecked-index writes)
//! land the honest port guard faces, cited per site. The cc :454/:555
//! tab-indent slips ride the ladder bodies (byte-irrelevant to output).

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;

use crate::framework::counts::{CountType, PegCount, PegInfo};
use crate::log::messages::LogEngine;
use crate::main::analyzer::{
    AnalyzerCore, AnalyzerWorld, Timeval, timeradd, STATE_PAUSED, STATE_RUNNING,
};
use crate::main::reload_tracker::ReloadTracker;
use crate::main::snort_configp::SnortConfig;
use crate::main::thread_config::ThreadConfig;
use crate::packet_io::sfdaq::{DAQ_ERROR, DAQ_SUCCESS};
use crate::utils::cfmt::{cfmt, Arg};

// ====================================================================
// the stats-output-format seat — ground main/stats-output-format .h
// :22-:26 (the enum class { Text :24, Json :25 }); the h :31 include
// arms it and the pair uses it at h :77 (the ctor default arg) + cc
// :298 (the Text-format gate). grep-0 across src/ at authoring: NO prior
// landing carries the type — the row-scoped seat lands HERE.
// ====================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatsOutputFormat {
    Text, // stats-output-format :24
    Json, // stats-output-format :25
}

// ====================================================================
// the clear-counter-type enum (h :88-:99, the typedef-enum face): the
// EXACT ordinals — TYPE_INVALID = -1 :90, TYPE_DAQ = 0 :91, then the
// walk to TYPE_ALL :98 (explicit vals at source, the ordinal law).
// The ground face is an UNSCOPED typedef-enum (h :88 `typedef enum
// clear_counter_type`): the nine enumerators are plain global names in
// C, so the faithful port seat is the i32 typedef + the SCREAMING
// enumerator consts (the family const-group pattern — the camel-case
// enum-variant rename NEVER touches the ground enumerator faces; the
// clippy-wash lands AT SOURCE, no attribute)
// ====================================================================

pub type ClearCounterType = i32;

pub const TYPE_INVALID: ClearCounterType = -1; // h :90
pub const TYPE_DAQ: ClearCounterType = 0;      // h :91
pub const TYPE_MODULE: ClearCounterType = 1;   // h :92
pub const TYPE_APPID: ClearCounterType = 2;    // h :93
pub const TYPE_FILE_ID: ClearCounterType = 3;  // h :94
pub const TYPE_SNORT: ClearCounterType = 4;    // h :95
pub const TYPE_HA: ClearCounterType = 5;       // h :96
pub const TYPE_MESSAGING: ClearCounterType = 6; // h :97
pub const TYPE_ALL: ClearCounterType = 7;      // h :98

// h :101-:103 the FIXIT-M comment kept VERBATIM: "Will replace this
// vector with an unordered map of <clear-counter-type, clear-counter-
// type-string-map> when will come up with more granular form of clearing
// module stats."
//
// THE .h's ONE ^static LINE (the header census seat, h :104: `static
// std::vector<const char*> clear_counter_type_string_map`) — the seven
// strings h :106-:112 VERBATIM (TYPE_INVALID and TYPE_ALL own NO string
// seat — the 7-arity face the map pins)
pub const CLEAR_COUNTER_TYPE_STRING_MAP: [&str; 7] = [
    "daq",               // h :106
    "module",            // h :107
    "appid",             // h :108
    "file_inspect",      // h :109
    "snort",             // h :110
    "high_availability", // h :111
    "mp_data_bus",       // h :112
];

const _: () = assert!(CLEAR_COUNTER_TYPE_STRING_MAP.len() == 7); // the h :104-:113 arity walk

// ====================================================================
// the SDK record + ordinal seats over api/daq-common .h (MEASURED
// against the lib-daq ground @ c8d4083): the DIOCTL enum head :406-:423
// (GET-DEVICE-INDEX = 1 :408 — the walk pins CPU-PROFILE :422 = 15 and
// SNORT-LATENCY :423 = 16); the landed sf-daq-instance home :168-:173
// carries ordinals 2/6/7/11 and NO seat for this pair's two (grep-0 at
// authoring) — the row-scoped consts land HERE, cited NEVER grafted
// ====================================================================

/// api/daq-common :422 the DIOCTL-get-cpu-profile-data ordinal (15; the
/// cc :473 cast face)
pub const DIOCTL_GET_CPU_PROFILE_DATA: u32 = 15;
/// api/daq-common :423 the DIOCTL-get-snort-latency-data ordinal (16; the
/// cc :570 cast face)
pub const DIOCTL_GET_SNORT_LATENCY_DATA: u32 = 16;

/// api/daq-common :663-:666 the latency-protocol enum (TCP :663, UDP
/// :664, OTHERS :665, MAX :666 = 3 — the cc :499 walk bound)
pub const DAQ_SNORT_LATENCY_PROTO_MAX: usize = 3;

const _: () = assert!(DIOCTL_GET_CPU_PROFILE_DATA == 15); // the :408 head walk
const _: () = assert!(DIOCTL_GET_SNORT_LATENCY_DATA == 16);

/// api/daq-common :644-:653 the get-cpu-profile-data record — the THREE
/// float members :650-:652 land f32 (the REAL record face; the cc
/// :483-:485 static-cast-to-double legs ride the cast at the COPY site,
/// NEVER at the record)
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DioctlGetCpuProfileData {
    pub cpu_usage_percent_30s: f32,  // :650
    pub cpu_usage_percent_120s: f32, // :651
    pub cpu_usage_percent_300s: f32, // :652
}

/// api/daq-common :669-:694 the snort-latency-data record (the h :255
/// vector element): the five u64 scalars :671-:675, the FOUR 16-byte ipv6
/// address seats :677-:684 (the 16-byte array twin — the format-ip-addr
/// fn reads the FIRST FOUR bytes for the v4 face, the cc :67-:68 memcpy
/// law), the four u16 port seats :680-:687, the four ipv6-flag 1-bit
/// fields :689-:693 (land u32 — the widen-face deviation, DEV-cited)
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DaqSnortLatencyData {
    pub max_pkt_time: u64,            // :671
    pub snort_up_max_pkt_time: u64,   // :672
    pub pkt_count: u64,               // :673
    pub sum_time: u64,                // :674
    pub conn_meta_null_counters: u64, // :675
    pub max_pkt_src_addr: [u8; 16],   // :677
    pub max_pkt_dst_addr: [u8; 16],   // :678
    pub max_pkt_src_port: u16,        // :680
    pub max_pkt_dst_port: u16,        // :681
    pub snort_up_max_pkt_src_addr: [u8; 16], // :683
    pub snort_up_max_pkt_dst_addr: [u8; 16], // :684
    pub snort_up_max_pkt_src_port: u16,      // :686
    pub snort_up_max_pkt_dst_port: u16,      // :687
    pub max_pkt_src_ipv6: u32,        // :689 (1-bit widened, DEV-cited)
    pub max_pkt_dst_ipv6: u32,        // :690
    pub snort_up_max_pkt_src_ipv6: u32,  // :692
    pub snort_up_max_pkt_dst_ipv6: u32,  // :693
}

/// api/daq-common :697-:699 the get-snort-latency-data record (the h :255
/// member-vector element + the cc :561 `= {}` zero-init face rides the
/// Default derive; the cc :581 whole-record copy is the Copy assign)
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DioctlGetSnortLatencyData {
    pub snort_latency_data: [DaqSnortLatencyData; DAQ_SNORT_LATENCY_PROTO_MAX], // :698
}

// ====================================================================
// THE ROW-OWNED THREAD-LOCAL SEAT (the statics law): cc :55 `static
// THREAD_LOCAL timeval report_time{};` — the pair's OWN THREAD_LOCAL
// definition seat (the census: THREAD_LOCAL x1 in the .cc, x0 in the .h;
// NEVER mirrored by ANY witness, the 24d family law). The seat lands as
// the thread-local Cell below OVER the 24g sn-conf conf-slot PATTERN
// (that home :1077-:1086 — the shape cited, NOT the record; different
// record, other row's owner). The cc :56/:57 siblings land as consts —
// the pair's OWN definitions, NEVER witness faces
// ====================================================================

thread_local! {
    /// cc :55 `static THREAD_LOCAL timeval report_time{};` — the `{}`
    /// zero-init rides the zero-tuple seat
    static REPORT_TIME: Cell<Timeval> = const { Cell::new((0, 0)) }; // cc :55
}

/// the cc :55 read seat (the twin's witness face)
pub fn report_time_get() -> Timeval {
    REPORT_TIME.with(|c| c.get())
}

/// the cc :80/:90 write seats (the timeradd-armed faces)
pub fn report_time_set(t: Timeval) {
    REPORT_TIME.with(|c| c.set(t));
}

/// cc :56 `static const timeval report_period = {10, 0};`
pub const REPORT_PERIOD: Timeval = (10, 0);

/// cc :57 `static const char* invalid_ip = "<invalid>";`
pub const INVALID_IP: &str = "<invalid>";

// ====================================================================
// the two cc :74-:93 static helper fn legs land pub-pure BELOW the
// tuner traits; the format-ip-addr legs (cc :60-:72) land as the pure
// fn over the 16-byte address + is-ipv6 flag
// ====================================================================

/// the timercmp(a, b, >) face (the sys/time macro seat, cc :88 — the
/// cppcheck-suppress syntax-error comment there cites the macro-argument
/// law; the port face is the plain tuple cmp)
pub fn timercmp_gt(a: Timeval, b: Timeval) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 > b.1)
}

/// cc :60-:72 the format-ip-addr face: the is-ipv6 gate :62, the inet-
/// ntop AF-INET-6 seat :63, and the IN4-addr memcpy :67-:68 + inet-ntop
/// AF-INET seat :69 legs OVER the 16-byte address + is-ipv6 flag (the
/// v4 seat IS the first four bytes of the array — the memcpy law :68);
/// the Option models the inet-ntop FAILURE faces whose strcpy legs (:64/
/// :70) land at [`format_ip_or_invalid`]. The glibc inet-ntop NEVER fails
/// on a well-formed address, so None is the unreachable-error posture in
/// practice — the Option keeps the failure leg HONEST (never invented)
pub fn format_ip_addr(addr: &[u8; 16], is_ipv6: bool) -> Option<String> {
    if is_ipv6 {
        inet_ntop_v6(addr) // cc :62-:63
    } else {
        // cc :67-:69: the v4-addr aggregate + the memcpy from the array
        // head + the AF-INET call
        inet_ntop_v4([addr[0], addr[1], addr[2], addr[3]])
    }
}

/// the cc :64/:70 `strcpy(buf, invalid_ip)` fallback legs folded over the
/// Option arm (the call-ladder face, cc :508-:511)
pub fn format_ip_or_invalid(addr: &[u8; 16], is_ipv6: bool) -> String {
    match format_ip_addr(addr, is_ipv6) {
        Some(s) => s,
        None => INVALID_IP.to_string(), // cc :64 / cc :70
    }
}

/// the inet-ntop AF-INET face (arpa/inet): the dotted-quad of the four
/// in-addr bytes (in_addr memory order, host-byte-order prints per the
/// 23i byte face)
fn inet_ntop_v4(b: [u8; 4]) -> Option<String> {
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

/// the inet-ntop AF-INET-6 face (arpa/inet): Glibc law — eight 16-bit
/// groups in lowercase hex with NO leading zeros; the LONGEST run of TWO
/// OR MORE zero groups collapses to the "::" seat (strictly-longest wins:
/// the first on TIES; a single zero group NEVER collapses; all-zero →
/// "::"). The failure posture (None) is the glibc EINVAL family — never
/// reached on a well-formed 16-byte seat
fn inet_ntop_v6(a: &[u8; 16]) -> Option<String> {
    let mut groups = [0u16; 8];
    for g in 0..8 {
        groups[g] = ((a[g * 2] as u16) << 8) | (a[g * 2 + 1] as u16);
    }
    // the longest-zero-run scan (the glibc law above)
    let mut best_start = 8usize;
    let mut best_len = 1usize;
    let mut i = 0usize;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            if i - start > best_len {
                best_start = start;
                best_len = i - start;
            }
        } else {
            i += 1;
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if best_len >= 2 {
        let head: Vec<String> = groups[..best_start]
            .iter()
            .map(|g| format!("{g:x}"))
            .collect();
        let tail: Vec<String> = groups[best_start + best_len..]
            .iter()
            .map(|g| format!("{g:x}"))
            .collect();
        // the collapse seat is EXACTLY "::" (glibc inet_ntop face — no
        // leading/trailing colon trimming: empty head -> "::tail", empty
        // tail -> "head::", all-zero -> "::")
        parts.push(head.join(":"));
        parts.push("::".to_string()); // the collapse seat
        parts.push(tail.join(":"));
        let mut out = String::new();
        out.push_str(parts.first().map(|s| s.as_str()).unwrap_or(""));
        out.push_str(parts.get(1).map(|s| s.as_str()).unwrap_or(""));
        out.push_str(parts.get(2).map(|s| s.as_str()).unwrap_or(""));
        Some(out)
    } else {
        for g in groups {
            parts.push(format!("{g:x}"));
        }
        Some(parts.join(":"))
    }
}

// ====================================================================
// the control-conn respond seam (control/control .h class :37; the faces
// THIS pair reaches: is-local :69 (the log-message-core gate, cc :97) +
// the respond legs :70/:71 (the va-list + varargs faces — the RENDERED
// text is what crosses the boundary; the ground respond does its OWN
// vsprintf, cited not re-done); the cc :99-:102 va-copy legs collapse —
// BOTH sinks feed the SAME rendered text). The Log-Respond macro
// (control :99-:100, the cn-then-Log-Message face) lands as
// [`AnalyzerCommand::log_respond`]. The landed Control-Conn-Tracker face
// (the reload-tracker home :80-:94, the QUERY face) is the SIBLING — its
// row owns it, NEVER widened here
// ====================================================================

pub trait ControlConnFace {
    /// control :69 the is-local face — the default legs at the honest
    /// boundary: an un-landed conn reports LOCAL (the respond leg NEVER
    /// fires un-invited); the provider sets the face
    fn is_local(&self) -> bool {
        true
    }
    /// control :70/:71 the respond face (the rendered-text law above);
    /// the default reports FAILURE (NO invented success past a boundary)
    fn respond(&mut self, _text: &str) -> bool {
        false
    }
}

// ====================================================================
// the reload-resource-tuner object seam (main/reload-tuner .h class :25-
// :51: the name :35 / tinit :38 / tune-packet-context :41 / tune-idle-
// context :42 / report-progress :45 virtuals; the work-limit consts :28/
// :30 CITED: RELOAD-MAX-WORK-PER-PACKET = 3 and WHEN-IDLE = 32767); the
// h :174 forward-decl seat. The sn-conf home's Reload-Resource-Tuner-
// Face opaque SLOT token (:349-:353) is cited, NEVER widened — THIS trait
// is the OBJECT face the ladder calls. The Arc handles mirror the C same-
// pointer double-hold law: the new-CONF owns the tuner objects, the per-
// thread list holds COPIES of the pointers (cc :332), and the cc :351
// pop-front / :363-:364 / :378-:379 list-delete legs drop the LIST,
// NEVER the tuner — the provider-side conf still holds; the Arc face
// makes that C ownership law EXPLICIT
// ====================================================================

pub trait ReloadTunerOps {
    /// reload-tuner :35
    fn name(&self) -> &'static str;
    /// reload-tuner :38 — true arms the tuner (the cc :336-:339
    /// erase-the-not-tinit'd arm)
    fn tinit(&mut self) -> bool;
    /// reload-tuner :41
    fn tune_packet_context(&mut self) -> bool;
    /// reload-tuner :42
    fn tune_idle_context(&mut self) -> bool;
    /// reload-tuner :45 — the default EMPTY body (the .h face IS an empty
    /// virtual); the cc :91 report-progress call leg
    fn report_progress(&mut self) {}
}

/// the reload-tuner work-limit CITE consts (reload-tuner :28/:30 — the
/// pair NEVER reads them; the provider body home owns the use, CITED)
pub const RELOAD_MAX_WORK_PER_PACKET: u32 = 3; // reload-tuner :28
pub const RELOAD_MAX_WORK_WHEN_IDLE: u32 = 32767; // reload-tuner :30

// ====================================================================
// the module object seam over framework/module .h (the legs cc :200-:275
// reaches): get-pegs :145 (the DEFAULT nullptr face lands the None arm)
// / prep-counts :151 / get-num-counts :159 / global-stats :173 / sum-
// stats :186 / collect-dump-stats-counts :196 / set-dump-stats-results
// :198. The std-mutex seats NEVER port (cc :222 the lock-guard over
// module-manager :102, cc :227): the ownership law the an-zl home pins
// (:82-:83, "mutex members NEVER port"); the RefCell handles carry the
// single-owner face (the DEV-cited posture, the observable legs intact)
// ====================================================================

pub trait ModuleFace {
    /// module :145 — the None arm IS the DEFAULT nullptr face
    fn get_pegs(&self) -> Option<Vec<PegInfo>>;
    /// module :151
    fn prep_counts(&mut self, dump_stats: bool);
    /// module :159
    fn get_num_counts(&self) -> i32;
    /// module :173
    fn global_stats(&self) -> bool;
    /// module :186
    fn sum_stats(&mut self, dump_stats: bool);
    /// module :196 (the out-reference face -> the out-param)
    fn collect_dump_stats_counts(&mut self, out: &mut Vec<PegCount>);
    /// module :198
    fn set_dump_stats_results(&mut self, results: &[PegCount]);
}

/// the scratch-allocator object seam (helpers/scratch-allocator .h :44-
/// :53): the UPDATE virtual :51 — the sn-conf home's Scratch-Allocator-
/// Face (:362-:372) carries setup/cleanup ONLY and NO update leg (CITED,
/// NEVER edited); the scratch-update ladder needs the :51 face, so THIS
/// row trait lands HERE (the cc :422 update call). The conf arg rides the
/// REUSED sn-conf record (:379) — the borrowed-conf face of the h :214
/// raw-pointer member, NEVER a new owner
pub trait ScratchUpdateFace {
    fn update_scratch(&mut self, sc: &mut SnortConfig);
}

/// the swapper object seam (main/swapper .h :35 class; the swap-pair
/// legs): apply :43 (the cc :321 call), the get-new-conf presence face
/// :46 (the cc :323-:325 null-pointer test arms the presence bool — the
/// Snort-Config* NEVER crosses the wall, DEV-cited), the tuner-copy face
/// the cc :332 leg rides (the sn-conf get-accessor REUSE cite :2521-:2523
/// arms it provider-side), and the clear face the dtor's cc :381-:385
/// gate rides (the sn-conf clear-list REUSE cite :2528-:2530 arms it
/// provider-side). Swapper-FINISH is the STATIC seat (swapper .cc :83,
/// the cc :365 call) — it rides the WORLD leg, NOT this trait
pub trait SwapperFace {
    fn apply_swapper(&mut self, a: &mut AnalyzerCore, w: &mut dyn AnalyzerCommandWorld);
    /// the cc :323-:325 presence test face
    fn get_new_conf_present(&mut self) -> bool;
    /// the cc :332 tuner-copy face (the get-CONF gate the caller holds)
    fn get_new_conf_tuners(&mut self) -> Vec<Arc<RefCell<dyn ReloadTunerOps>>>;
    /// the cc :381-:385 combined face (the get-CONF gate + the clear leg)
    fn clear_new_conf_tuner_list(&mut self);
}

// ====================================================================
// the provider seam for the NEVER-LAND walls THIS pair reaches (the 24d
// analyzer-world pattern re-ridden): every cite-NEVER-land home rides ONE
// trait leg; every default sits at the honest boundary. The two ioctl
// legs default DAQ-ERROR (the 23a home :63 REUSE import; the sf-daq-
// instance home :1122 ioctl shape, the cc :473/:569 call sites) — NEVER
// an invented success past a boundary
// ====================================================================

pub trait AnalyzerCommandWorld: AnalyzerWorld {
    /// plug-in-manager :82 the get-all-modules face (cc :176-:177); the
    /// Option arms model the cc :203-:204 / :244-:246 null-module faces
    fn get_all_modules(&mut self) -> Vec<Option<Arc<RefCell<dyn ModuleFace>>>> {
        Vec::new()
    }
    /// module-manager :70 is-dynamic-stats-module (cc :206)
    fn is_dynamic_stats_module(&self, _m: &Arc<RefCell<dyn ModuleFace>>) -> bool {
        false
    }
    /// module-manager :1512 the type-arg reset-stats overload (cc :306)
    fn reset_stats_leg(&mut self, _requested: ClearCounterType) {}
    /// module-manager :1331 (cc :250, the global-stats module arm)
    fn collect_global_dump_stats_leg(&mut self, _m: &Arc<RefCell<dyn ModuleFace>>) {}
    /// module-manager :1362 the accumulated-counts fallback (cc :265)
    fn get_accumulated_counts_leg(
        &mut self,
        _m: &Arc<RefCell<dyn ModuleFace>>,
        _thread_idx: usize,
        _out: &mut Vec<PegCount>,
    ) {
    }
    /// module-manager :1494 (cc :301)
    fn clear_global_active_counters_leg(&mut self) {}
    /// stats :104-:108 / stats .cc :393 the drop-stats family (cc :297);
    /// the conn-presence arg models the control-conn pointer arg face
    fn drop_stats_leg(
        &mut self,
        _ctrlcon_present: bool,
        _already_accumulated: bool,
        _display_stats: &[PegCount],
        _format: StatsOutputFormat,
    ) {
    }
    /// packet-manager :146 (cc :192): the Stats alias :63 (the fixed
    /// array face) lands Vec-PegCount sized provider-side — cited
    fn packet_get_thread_stats(&mut self) -> Vec<PegCount> {
        Vec::new()
    }
    /// packet-manager :147 (cc :279)
    fn packet_get_global_stats(&mut self) -> Vec<PegCount> {
        Vec::new()
    }
    /// host-attributes :178 (cc :395)
    fn host_attributes_initialize(&mut self) {}
    /// host-attributes :188 (cc :388/:401)
    fn host_attributes_swap_cleanup(&mut self) {}
    /// swapper .cc :83 the FINISH static (cc :365)
    fn swapper_finish(&mut self) {}
    /// the sf-daq-instance ioctl legs (home :1122; cc :473-:474): the
    /// DIOCTL-get-cpu-profile-data call carrying the cc :473 ordinal arg,
    /// the DAQ-ERROR default posture
    fn daq_ioctl_cpu_profile(
        &mut self,
        _cmd: u32, // the cc :473 cast-face arg
        _out: &mut DioctlGetCpuProfileData,
    ) -> i32 {
        DAQ_ERROR
    }
    /// the same home, the cc :569-:572 latency call face (the ordinal
    /// arg rides too, cc :570)
    fn daq_ioctl_snort_latency(
        &mut self,
        _cmd: u32,
        _out: &mut DioctlGetSnortLatencyData,
    ) -> i32 {
        DAQ_ERROR
    }
}

/// the landing's OWN cite-side world (the an-zl Null-World sibling face:
/// every default legs at the honest boundary)
#[derive(Default)]
pub struct NullCommandWorld;
impl AnalyzerWorld for NullCommandWorld {}
impl AnalyzerCommandWorld for NullCommandWorld {}

// ====================================================================
// the FLOAT REPORT HELPERS (the DEC face; see THE FLOAT FORMATTING LAW
// up top — the cfmt-core wrappers, proven BYTE-EQUAL vs glibc on the
// 200k boundary vector at authoring; pub so the twin can replay them)
// ====================================================================

/// the printf-%.1f face over the ONE cfmt core
pub fn fmt_f1(v: f64) -> String {
    cfmt("%.1f", &[Arg::F(v)])
}

/// the printf-%.3f face over the ONE cfmt core
pub fn fmt_f3(v: f64) -> String {
    cfmt("%.3f", &[Arg::F(v)])
}

// ====================================================================
// the aggregation algorithm (framework/module .cc :109-:166, the PAIR-
// VISIBLE static body the dtor ladder calls at cc :272-:273): the by-
// value overload :109-:124 collapses into the slice form below (the C
// vector-of-pointers marshalling :118-:121 == the cc :257-:270 legs);
// the REAL body :126-:166 lands VERBATIM: the pegs-null / num-counts <=
// 0 guard :132-:134 (the out-untouched face), the fill-zero seat :135,
// the size-mismatch skip :138-:140, and the CountType switch :144-:160
// (the END skip :146-:147, the SUM + NOW add :149-:152, the MAX-max :154-
// :157); the enum arms ride the counts-home CountType REUSE (End :26 /
// Sum :29 / Now :32 / Max :35 per that file)
// ====================================================================

pub fn aggregate_dump_stats_counts(
    pegs: &[PegInfo],
    num_counts: usize,
    per_thread_counts: &[Vec<PegCount>],
) -> Vec<PegCount> {
    if pegs.is_empty() || num_counts == 0 {
        return Vec::new(); // module :132-:134 (the out-UNTOUCHED C face;
        // the port returns the empty form — the call site NEVER reads the
        // untouched buffer, cited)
    }
    let mut out = vec![0 as PegCount; num_counts]; // module :135
    for counts in per_thread_counts {
        if counts.len() != num_counts {
            continue; // module :138-:140 (the null + size-mismatch skip)
        }
        for peg_ix in 0..num_counts {
            match pegs[peg_ix].peg_type {
                CountType::End => {} // module :146-:147
                CountType::Sum | CountType::Now => {
                    out[peg_ix] += counts[peg_ix]; // module :149-:152
                }
                CountType::Max => {
                    if counts[peg_ix] > out[peg_ix] {
                        out[peg_ix] = counts[peg_ix]; // module :154-:157
                    }
                }
            }
        }
    }
    out
}

// ====================================================================
// the analyzer-command base (h :45-:71): the ctor pair h :48-:49 (the
// nullptr-default + the conn-arg), the pure-virtual execute h :52 + the
// stringify h :57 + the need-update-reload-id DEFAULT-FALSE virtual
// h :54-:55 (the grep-0 override face in the pair, MEASURED), the h :59-
// :60 get/put inline ref legs (the AF-i law cites the an-zl :638-:652
// command-facility mirror), the h :66 conn member (the Option-face), the
// h :70 ref-count NSDMI-zero, the log-message trio cc :95-:121 (the
// private va-core h :69 / cc :95-:105, the static varargs h :63 / cc
// :107-:113, the member h :62 / cc :115-:121) + the get-daq-instance
// static h :64 / cc :433-:436
// ====================================================================

/// the virtual face (the execute-over-dyn-world / stringify / the need-
/// update default): the Log-Engine threads the C global Log-Message legs
/// (the reload-tracker home param precedent :157); the LogRespond legs
/// ride it too (the macro's else arm)
pub trait AnalyzerCommandVirtual {
    /// h :52 the pure virtual (the conn-less faces NEVER log — the `_log`
    /// postures cite that)
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool;
    /// h :54-:55 the default-false virtual (grep-0 override face across
    /// the pair, MEASURED — swap-pair / scratch-update ride the default)
    fn need_update_reload_id(&self) -> bool {
        false
    }
    /// h :57 (the Dev face is the NON-CONST virtual; all returns are
    /// compile-time literals so the port face is &self, DEV-cited)
    fn stringify(&self) -> &'static str;
}

#[derive(Default)]
pub struct AnalyzerCommand {
    /// h :66 `ControlConn* ctrlcon;` (the ctor pair h :48-:49: the
    /// nullptr-default + the conn-arg — the Option face is ONE shape)
    pub ctrlcon: Option<Box<dyn ControlConnFace>>,
    /// h :70 `unsigned ref_count = 0;` (the private seat)
    ref_count: u32,
}

impl AnalyzerCommand {
    /// the h :48-:49 ctor pair merged face (the NONE models the nullptr)
    pub fn new(ctrlcon: Option<Box<dyn ControlConnFace>>) -> Self {
        AnalyzerCommand {
            ctrlcon,
            ref_count: 0, // h :70 the NSDMI
        }
    }

    /// h :59 `get() { return ++ref_count; }` (the pre-increment face)
    pub fn get(&mut self) -> u32 {
        self.ref_count += 1;
        self.ref_count
    }

    /// h :60 `put() { return --ref_count; }` — CONSUMED at the an-zl
    /// reaper seat (:719, the zero-triggers-destroy law); the port-side
    /// saturation guard mirrors the an-zl finish-command if-arms (:619-
    /// :621): the C face NEVER wraps at zero
    pub fn put(&mut self) -> u32 {
        if self.ref_count == 0 {
            return 0;
        }
        self.ref_count -= 1;
        self.ref_count
    }

    /// the h :70 read face (the twin witness)
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// cc :95-:105 the PRIVATE core (h :69): the cc :97 gate
    /// `ctrlcon && !ctrlcon->is_local()` arms the respond leg (:101 — the
    /// va-copy :99-:102 legs collapse because the rendered text crosses
    /// BOTH sinks, the observable face identical), THEN the unconditional
    /// Log-Message :104 (the log-home REUSE cite)
    fn log_message_core(
        ctrlcon: Option<&mut dyn ControlConnFace>,
        log: &mut LogEngine,
        format: &str,
        args: &[Arg<'_>],
    ) {
        if let Some(conn) = ctrlcon
            && !conn.is_local()
        {
            // cc :101 — the ground respond does its OWN vsprintf
            // (control :70/:71); the rendered-text face rides cfmt
            conn.respond(&cfmt(format, args));
        }
        // cc :104 the Log-Message face (messages :353-:358: the quiet
        // gate + the CORE both live THERE)
        log.log_message_stdout(format, args);
    }

    /// cc :107-:113 the STATIC varargs leg (h :63) — the va-start/end
    /// :109-:112 legs collapse into the direct core call
    pub fn log_message_static(
        ctrlcon: Option<&mut dyn ControlConnFace>,
        log: &mut LogEngine,
        format: &str,
        args: &[Arg<'_>],
    ) {
        Self::log_message_core(ctrlcon, log, format, args);
    }

    /// cc :115-:121 the MEMBER leg (h :62) — rides the stored conn (the
    /// legs mirror the core body inline: the Box-borrow face NEVER
    /// escapes self, the family borrow-law posture)
    pub fn log_message(&mut self, log: &mut LogEngine, format: &str, args: &[Arg<'_>]) {
        if let Some(conn) = self.ctrlcon.as_mut()
            && !conn.is_local()
        {
            conn.respond(&cfmt(format, args)); // cc :101
        }
        log.log_message_stdout(format, args); // cc :104
    }

    /// the Log-Respond MACRO (control :99-:100) VERBATIM: `do { if (cn)
    /// cn->respond(__VA_ARGS__); else snort::LogMessage(__VA_ARGS__); }
    /// while(0)` — the macro is NOT a class member in the ground; it
    /// lands as the base helper the report ladders call (the ONLY
    /// pair-visible use face of the macro, cited per ladder). No is-
    /// local gate (the macro has NONE — the contrast with the trio above
    /// is the ground face)
    pub fn log_respond(&mut self, log: &mut LogEngine, format: &str, args: &[Arg<'_>]) {
        if let Some(conn) = self.ctrlcon.as_mut() {
            conn.respond(&cfmt(format, args)); // the macro's respond arm
        } else {
            log.log_message_stdout(format, args); // the macro's else arm
        }
    }

    /// cc :433-:436 the STATIC get-daq-instance (`return analyzer.get_
    /// daq_instance();`): the instance POINTER NEVER crosses the wall —
    /// the presence bool rides an-zl daq-present :178-:180; the cc :468 /
    /// cc :564 the-presence-gates call THIS
    pub fn get_daq_instance_present(w: &dyn AnalyzerCommandWorld) -> bool {
        w.daq_present()
    }
}

// ====================================================================
// the two tuner seat helpers (the cc :74-:93 static helper legs, pub-
// pure): the Log-Message legs ride the AnalyzerWorld log-face :136 (the
// id arg threads the get-instance-id seat law); the timeradd legs REUSE
// an-zl :269-:277; the report-period const is cc :56; the report-time
// TLS seat is cc :55 via the block above
// ====================================================================

/// cc :74-:81: the cc :76 echo (`ReloadResourceTuner[%u] running %s\n`
/// — the id + the tuner-name faces), the cc :78-:79 NOW seat (the
/// packet-get-time-of-day world leg, an-zl :194) and the cc :80 report-
/// time := timeradd(now, period) legs
pub fn tuner_next<W: AnalyzerWorld + ?Sized>(
    tuner: &Arc<RefCell<dyn ReloadTunerOps>>,
    instance_id: u32, // the id seat law (the cc :76 face)
    w: &mut W,
) {
    let name = tuner.borrow().name(); // cc :76 the name leg
    w.log_message(&format!("ReloadResourceTuner[{instance_id}] running {name}")); // :76
    let now = w.packet_gettimeofday(); // :79
    report_time_set(timeradd(now, REPORT_PERIOD)); // :80 over :56 + :55
}

/// cc :83-:93: the NOW seat :85-:86, the timercmp-'>' gate :88 and the
/// advance-then-report legs :90-:91 (the report-progress arms the reload-
/// tuner face :45 above — the DEFAULT empty-body legs live there)
pub fn tuner_update<W: AnalyzerWorld + ?Sized>(
    tuner: &Arc<RefCell<dyn ReloadTunerOps>>,
    w: &mut W,
) {
    let now = w.packet_gettimeofday(); // :86
    if timercmp_gt(now, report_time_get()) {
        // :88 the gate (the cppcheck-suppress comment cite lives at the
        // timercmp-fn seat above)
        report_time_set(timeradd(now, REPORT_PERIOD)); // :90
        tuner.borrow_mut().report_progress(); // :91
    }
}

// ====================================================================
// the plain lifecycle commands (the ONE-liner execute legs cc :123-:158
// over the an-zl command faces — each home cited, NEVER re-forked; the
// bases default-ctor the conn-less faces h :48)
// ====================================================================

/// h :160-:165 / cc :123-:127 (the an-zl start :879-:910 — wait the
/// :879 seat; cc :125 `analyzer.start()`)
#[derive(Default)]
pub struct ACStart {
    pub base: AnalyzerCommand, // the C base face (inheritance -> field)
}

impl ACStart {
    pub fn new() -> Self {
        Self::default()
    }
    /// cc :123-:127
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine, // NO logging legs (the pair face)
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        a.start(w); // cc :125 -> an-zl :879
        true // cc :126
    }
    pub fn stringify(&self) -> &'static str {
        "START"
    } // h :164
}

impl AnalyzerCommandVirtual for ACStart {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "START"
    }
}

/// h :149-:158 / cc :129-:134: the DELETED no-arg ctor h :152 (the
/// default face NEVER ships), the is-paused default-ARG ctor h :153,
/// the member NSDMI h :157 — the execute runs the an-zl run-seat (:893)
/// THEN the ONE-SHOT paused-clear (cc :132: the SECOND execute rides
/// false)
pub struct ACRun {
    pub base: AnalyzerCommand,
    paused: bool, // h :157
}

impl ACRun {
    /// h :153 (the default-arg face ships as the pair below; the no-arg
    /// ctor h :152 NEVER lands)
    pub fn new(paused: bool) -> Self {
        ACRun {
            base: AnalyzerCommand::default(), // the conn-less face
            paused,
        }
    }
    /// the h :153 `is_paused = false` default-arg face (the call-side
    /// twin of the deleted-default ctor law)
    pub fn new_default() -> Self {
        Self::new(false)
    }
    /// cc :129-:134
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        a.run(self.paused, w); // cc :131 -> an-zl :893
        self.paused = false; // cc :132 the one-shot CLEAR
        true // cc :133
    }
    pub fn stringify(&self) -> &'static str {
        "RUN"
    } // h :155
}

impl AnalyzerCommandVirtual for ACRun {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "RUN"
    }
}

/// h :167-:172 / cc :136-:140 (cc :138 `analyzer.stop()` -> an-zl :905)
#[derive(Default)]
pub struct ACStop {
    pub base: AnalyzerCommand,
}

impl ACStop {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        a.stop(w); // cc :138 -> an-zl :905-:908
        true // cc :139
    }
    pub fn stringify(&self) -> &'static str {
        "STOP"
    } // h :171
}

impl AnalyzerCommandVirtual for ACStop {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "STOP"
    }
}

/// h :125-:130 / cc :142-:146 (cc :144 `analyzer.pause()` -> an-zl
/// :912-:924: the RUNNING-guard + the "== [u] paused" echo + the state-
/// string error arm ALL live at that home, REUSE cite)
#[derive(Default)]
pub struct ACPause {
    pub base: AnalyzerCommand,
}

impl ACPause {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        a.pause(w); // cc :144 -> an-zl :912
        true // cc :145
    }
    pub fn stringify(&self) -> &'static str {
        "PAUSE"
    } // h :129
}

impl AnalyzerCommandVirtual for ACPause {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "PAUSE"
    }
}

/// h :132-:140 / cc :148-:152: the `ACResume(uint64-t msg-cnt)` ctor
/// h :135 + the member h :139 — the an-zl resume-seat (:927-:937, the
/// PAUSED-guard + the set-pause-after + the RUNNING arm REUSE cited)
pub struct ACResume {
    pub base: AnalyzerCommand,
    msg_cnt: u64, // h :139
}

impl ACResume {
    pub fn new(msg_cnt: u64) -> Self {
        ACResume {
            base: AnalyzerCommand::default(),
            msg_cnt,
        }
    }
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        a.resume(self.msg_cnt, w); // cc :150 -> an-zl :927
        true // cc :151
    }
    pub fn stringify(&self) -> &'static str {
        "RESUME"
    } // h :137
    /// the h :139 member read face (the twin witness)
    pub fn msg_cnt(&self) -> u64 {
        self.msg_cnt
    }
}

impl AnalyzerCommandVirtual for ACResume {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "RESUME"
    }
}

/// h :142-:147 / cc :154-:158 (cc :156 `analyzer.rotate()` -> an-zl
/// :950-:954: the THREAD-ROTATE publish seat + the Option-handoff face
/// REUSE cited THERE; the swap-window boundary legs are an-other row's,
/// cited)
#[derive(Default)]
pub struct ACRotate {
    pub base: AnalyzerCommand,
}

impl ACRotate {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        // the an-zl rotate handoff face (the live-bus Some-arm: the
        // swap-window None boundary NEVER fires HERE, the cite lives at
        // the home :947-:954); the dyn-cast arms the +?Sized bound
        let mut slot: Option<&mut dyn AnalyzerWorld> = Some(w);
        a.rotate(&mut slot); // cc :156 -> an-zl :950
        true // cc :157
    }
    pub fn stringify(&self) -> &'static str {
        "ROTATE"
    } // h :146
}

impl AnalyzerCommandVirtual for ACRotate {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "ROTATE"
    }
}

/// h :115-:123 / cc :304-:308 + the ctor cc :310-:311: the clear-
/// counter-type member h :122 (the value-carry face, the cc :310 ctor)
/// over the module-manager reset-stats wall (:1512, the type-arg
/// overload, cc :306)
pub struct ACResetStats {
    pub base: AnalyzerCommand,
    requested_type: ClearCounterType, // h :122
}

impl ACResetStats {
    pub fn new(requested_type: ClearCounterType) -> Self {
        ACResetStats {
            base: AnalyzerCommand::default(),
            requested_type, // cc :310-:311
        }
    }
    /// cc :304-:308
    pub fn execute(
        &mut self,
        _a: &mut AnalyzerCore, // the cc :304 unused (analyzer-ref) face
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        w.reset_stats_leg(self.requested_type); // cc :306 -> mm :1512
        true // cc :307
    }
    pub fn stringify(&self) -> &'static str {
        "RESET_STATS"
    } // h :120
    /// the h :122 member read face
    pub fn requested_type(&self) -> ClearCounterType {
        self.requested_type
    }
}

impl AnalyzerCommandVirtual for ACResetStats {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "RESET_STATS"
    }
}

// ====================================================================
// the stats-getter (h :74-:86): the State forward h :83 + the unique-
// ptr member h :84 (the cc :187 null-guard legs -> the Option face) +
// the format member h :85 (h :77 the Text DEFAULT-ARG ctor face). The
// ctor cc :173-:182, the execute snapshot cc :184-:235, the dtor
// AGGREGATION ladder cc :237-:302 (the explicit dtor method — the
// family dtor law, cited at the helper above)
// ====================================================================

/// cc :162-:167 the thread-snapshot seat: the pkt-stats-valid NSDMI
/// :164, the Packet-Manager Stats seat :165 (the packet-manager :63
/// fixed-array alias -> Vec-PegCount sized provider-side, cited), and
/// the module-dump-counts seat :166
#[derive(Clone, Default)]
pub struct GetStatsThreadSnapshot {
    pub pkt_stats_valid: bool, // cc :164 (`= false` NSDMI)
    pub pkt_stats: Vec<PegCount>, // cc :165 (the `{}` zero face -> empty)
    pub module_dump_counts: Vec<Vec<PegCount>>, // cc :166
}

/// cc :169-:170 the State seat (h :83 the forward): the module LIST +
/// the snapshot vector
pub struct GetStatsState {
    pub modules: Vec<Option<Arc<RefCell<dyn ModuleFace>>>>, // cc :169
    pub thread_snapshots: Vec<GetStatsThreadSnapshot>,      // cc :170
}

pub struct ACGetStats {
    pub base: AnalyzerCommand,
    state: Option<GetStatsState>, // h :84 / cc :174
    format: StatsOutputFormat,    // h :85
}

impl ACGetStats {
    /// cc :173-:182: the conn-leg + the State-make seat (:174) + the
    /// format seat (:174), the get-all-modules wall leg (:176-:177 — the
    /// assign face), the get-instance-max resize (:178, the thread-home
    /// :742 CITE — the row-OWNED name law says the witness owns that
    /// name, the landing rides the home), and the reserve ladder
    /// :180-:181
    pub fn new(
        conn: Option<Box<dyn ControlConnFace>>,
        output_format: StatsOutputFormat,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> Self {
        let mut st = GetStatsState {
            modules: w.get_all_modules(), // cc :176-:177
            thread_snapshots: Vec::new(),
        };
        let n = ThreadConfig::get_instance_max() as usize; // cc :178
        st.thread_snapshots
            .resize(n, GetStatsThreadSnapshot::default());
        let m = st.modules.len();
        for snap in &mut st.thread_snapshots {
            snap.module_dump_counts.reserve(m); // cc :180-:181
        }
        ACGetStats {
            base: AnalyzerCommand::new(conn), // cc :174
            state: Some(st),                  // cc :174
            format: output_format,            // cc :174
        }
    }
    /// the h :77 `StatsOutputFormat output-format = StatsOutputFormat::
    /// Text` DEFAULT-ARG face
    pub fn new_text(conn: Option<Box<dyn ControlConnFace>>, w: &mut dyn AnalyzerCommandWorld) -> Self {
        Self::new(conn, StatsOutputFormat::Text, w)
    }

    /// cc :184-:235 the per-thread SNAPSHOT legs: the double-guard
    /// VERBATIM (:187), the walk with the null skip (:203-:204), the
    /// dynamic-stats wall leg (:206), the GLOBAL gate (:207-:212, a
    /// global-stats module counts ONLY on the first-packet-thread :198),
    /// the need-lock OR (:214-:215), the reserve-on-lock arm (:217-:218),
    /// and the LOCKED / UNLOCKED legs (:220-:232): the std-mutex guard
    /// :222 NEVER ports (the ownership law, the mutex seat module-
    /// manager :102 CITED; the body legs run under the single-owner
    /// RefCell face — the observable legs identical, DEV-cited)
    pub fn execute(
        &mut self,
        a: &AnalyzerCore, // the cc :184 face; the id seat :186 rides the
        // analyzer's OWN id field (an-zl :383, h :153) — the thread-
        // local id NEVER ports (the threaded-param law)
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        let id = a.id as usize; // cc :186 (the port face, cite above)
        let st = match self.state.as_mut() {
            Some(st) => st,
            None => return true, // cc :187 the first guard arm
        };
        if id >= st.thread_snapshots.len() {
            return true; // cc :187 the bounds arm (the port-face honest
            // guard vs the C out-of-bounds UB — cited)
        }
        let mods = st.modules.clone();
        let snap = &mut st.thread_snapshots[id]; // cc :190

        snap.pkt_stats = w.packet_get_thread_stats(); // cc :192
        snap.pkt_stats_valid = true; // cc :193

        snap.module_dump_counts.clear(); // cc :195
        snap.module_dump_counts.resize(mods.len(), Vec::new()); // cc :196

        let is_first_packet_thread = id == 0; // cc :198

        for i in 0..mods.len() {
            let m = match mods[i].as_ref() {
                Some(m) => m.clone(),
                None => continue, // cc :203-:204
            };
            let is_dynamic_stats = w.is_dynamic_stats_module(&m); // cc :206
            let is_global_stats = m.borrow().global_stats(); // cc :207

            if is_global_stats && !is_first_packet_thread {
                continue; // cc :209-:212
            }

            let needs_lock = is_global_stats || is_dynamic_stats; // :214-:215

            if needs_lock && m.borrow().get_num_counts() > 0 {
                // the C reserve-on-counts arm (capacity face, :217-:218)
                snap.module_dump_counts[i].reserve(m.borrow().get_num_counts().max(0) as usize);
            }

            if needs_lock {
                // cc :222 the lock-guard seat NEVER ports (cite above);
                // the :223 / :225 / :226 legs run unlocked UNDER the
                // single-owner face
                let mut mb = m.borrow_mut();
                mb.prep_counts(true); // cc :223
                if is_dynamic_stats {
                    mb.sum_stats(true); // cc :225
                }
                mb.collect_dump_stats_counts(&mut snap.module_dump_counts[i]); // cc :226
            } else {
                let mut mb = m.borrow_mut();
                mb.prep_counts(true); // cc :230
                mb.collect_dump_stats_counts(&mut snap.module_dump_counts[i]); // cc :231
            }
        }
        true // cc :234
    }

    /// cc :237-:302 the dtor AGGREGATION ladder (the explicit dtor — the
    /// response-buf family law): the null-state early-out :239-:240; the
    /// per-module walk :242-:276 (the :245 triple-guard skip, the GLOBAL
    /// arm :248-:252 collect-global + CONTINUE, the per-thread ladder
    /// :257-:270 — the snapshot-miss arms the get-accumulated WALL leg
    /// (:263-:267), else the SNAPSHOT counts (:268-:269); the C pointer-
    /// vector face lands owned copies under the ownership law, the
    /// observable face identical); the REUSED aggregate fn (cc :272-:273
    /// over the module :126-:166 body cited up top); set-results :275;
    /// the display-sum legs :278-:295 (the global-before seat, the fill-
    /// zero thread-sum seat, the valid-only skip :286, the zero-roll :293-
    /// :295: display = global-before + thread-sum — the zip arms the C
    /// same-array index law); the drop-stats WALL leg :297 (the stats .cc
    /// :393 home; the conn-presence arg models the pointer-arg face, the
    /// already-accumulated TRUE face VERBATIM); the TEXT-format End-Of-
    /// stats marker :298-:299 (the EXACTLY-50 equal-signs line, MEASURED;
    /// the "Marking End of stats" comment kept; the Log-Respond face);
    /// and the clear-global-counters wall tail :301
    pub fn dtor(&mut self, log: &mut LogEngine, w: &mut dyn AnalyzerCommandWorld) {
        let st = match self.state.take() {
            Some(st) => st,
            None => return, // cc :239-:240
        };
        for i in 0..st.modules.len() {
            let m = match st.modules[i].as_ref() {
                Some(m) => m.clone(),
                None => continue, // cc :244-:246 (the module ref :244 +
                // the null-check :245)
            };
            let pegs = m.borrow().get_pegs(); // cc :245
            let n_i = m.borrow().get_num_counts(); // cc :245
            let n = match pegs {
                Some(_) if n_i > 0 => n_i as usize,
                _ => continue, // cc :245 the triple-guard face
            };

            if m.borrow().global_stats() {
                w.collect_global_dump_stats_leg(&m); // cc :250
                continue; // cc :251
            }

            // cc :257-:270 the per-thread pointers ladder (the pegs-already-
            // matched arm below owns the Some-face)
            let pegs = match pegs {
                Some(p) => p,
                None => continue, // already guarded above, the honest rider
            };
            let mut per_thread: Vec<Vec<PegCount>> =
                Vec::with_capacity(st.thread_snapshots.len());
            for (thread_idx, snap) in st.thread_snapshots.iter().enumerate() {
                if i >= snap.module_dump_counts.len() {
                    // cc :263-:267: the snapshot-miss FALLBACK arm
                    let mut fb: Vec<PegCount> = Vec::new();
                    w.get_accumulated_counts_leg(&m, thread_idx, &mut fb); // mm :1362
                    per_thread.push(fb); // :266 the push-arm face
                } else {
                    per_thread.push(snap.module_dump_counts[i].clone()); // :269
                }
            }

            let results = aggregate_dump_stats_counts(&pegs, n, &per_thread); // cc :272-:273
            m.borrow_mut().set_dump_stats_results(&results); // cc :275
        }

        let global_before = w.packet_get_global_stats(); // cc :278-:279
        let mut thread_sum = vec![0 as PegCount; global_before.len()]; // :281-:282
        for snap in &st.thread_snapshots {
            if !snap.pkt_stats_valid {
                continue; // cc :286
            }
            for idx in 0..thread_sum.len() {
                if idx < snap.pkt_stats.len() {
                    thread_sum[idx] += snap.pkt_stats[idx]; // cc :289-:290
                }
            }
        }
        let display_stats: Vec<PegCount> = global_before
            .iter()
            .zip(thread_sum.iter())
            .map(|(g, t)| g + t)
            .collect(); // cc :293-:295 VERBATIM (the display-zero + sum)

        w.drop_stats_leg(
            self.base.ctrlcon.is_some(), // the conn-pointer-arg face
            true,                        // cc :297 already-accumulated
            &display_stats,
            self.format,
        ); // cc :297 -> stats .cc :393

        if self.format == StatsOutputFormat::Text {
            // cc :298-:299 the marker (the 50-equals face MEASURED, the
            // "Marking End of stats" comment kept) — the LogRespond face
            self.base
                .log_respond(log, "==================================================\n", &[]);
        }

        w.clear_global_active_counters_leg(); // cc :301 -> mm :1494
    }

    pub fn stringify(&self) -> &'static str {
        "GET_STATS"
    } // h :79
}

impl AnalyzerCommandVirtual for ACGetStats {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "GET_STATS"
    }
}

// ====================================================================
// the swap-pair (h :176-:191): the DELETED no-arg ctor h :179, the pair-
// ctor h :180-:182 (conn + swapper; the reload-tuner-per-thread vector
// sized by the thread-home get-instance-max CITE h :182 — the row-OWNED
// name law: the harness witness owns that name, the landing rides the
// home :742-:747), the dtor h :183, the swapper member h :189 (the
// Option face models the cc :319 pointer test), the nullable-list vector
// h :190 (`std::vector<std::list<reload-tuner *> *>` -> the Option-of-
// VecDeque vector face — the nullptr list is None); the FULL reload-
// tuner ladder cc :313-:374 and the dtor cc :376-:391 sit below
// ====================================================================

// the per-thread nullable tuner-list seat type (h :190's `std::vector<
// std::list<reload-tuner *> *>` face: the outer vector pre-sized at the
// ctor, each seat a null-list -> None; the named seat keeps the member
// face readable, the family type-alias law)
pub type ReloadTunerSlot = VecDeque<Arc<RefCell<dyn ReloadTunerOps>>>;

pub struct ACSwap {
    pub base: AnalyzerCommand, // h :181 (the conn leg)
    ps: Option<Box<dyn SwapperFace>>, // h :189
    reload_tuners_by_thread: Vec<Option<ReloadTunerSlot>>, // h :190
}

impl ACSwap {
    /// h :180-:182 (the get-instance-max sizing leg CITES the thread
    /// home; the nullptr fill == the all-None start)
    pub fn new(ps: Box<dyn SwapperFace>, conn: Option<Box<dyn ControlConnFace>>) -> Self {
        ACSwap {
            base: AnalyzerCommand::new(conn), // h :181
            ps: Some(ps),
            reload_tuners_by_thread: vec![
                None;
                ThreadConfig::get_instance_max() as usize
            ], // h :182
        }
    }

    /// cc :313-:374 the FULL reload-tuner ladder: the state guard
    /// :315-:317 (the PAUSED / RUNNING pair over the an-zl get-state
    /// :542 + the STATE_PAUSED :91 / STATE_RUNNING :90 REUSE consts —
    /// the FALSE posture); the swapper presence test :319; the apply
    /// call :321; the get-new-conf guard :323-:325 (the presence face at
    /// the swapper face; the Snort-Config pointer NEVER crosses, DEV-
    /// cited); the id seat :326 (the analyzer-id law); the per-thread
    /// list FIRST-ARM face :329-:343 (the "start" echo :331 over the
    /// world log face — Log-Message faces, NOT conn faces; the tuner-
    /// copy ctor :332 the sn-conf get-accessor REUSE cite :2521-:2523
    /// arms provider-side; the tinit-erase WHILE ladder :333-:340 — the
    /// filter-collect face is the erase ladder's INVERSE with the order
    /// intact, the in-order-walk law cited); the WORK pass :345-:357
    /// (the front tuner, the idle-vs-packet CONTEXT pick :348 over the
    /// an-zl is-idling :550, the COMPLETE arm pop-fronts :351 + re-arms
    /// :352-:353, else the update leg :356); the done face :359-:367
    /// (the C comment "check for empty again and free list instance if
    /// we are done" KEPT at the leg, the "complete" echo :362, the
    /// list-delete seat :363-:364 -> None, the swapper-finish WALL leg
    /// :365 -> the swapper .cc :83 home, TRUE :366); the not-done FALSE
    /// :369; the no-swapper / no-conf tail TRUE :373. PORT-FACE CITE:
    /// the cc :327 unchecked `reload_tuners_by_thread[id]` write is C
    /// out-of-bounds UB past the ctor-sized length — the get-mut guard
    /// returns the tail TRUE (the honest port face, NEVER a UB replay)
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine, // the ladder echoes (:331/:362) are Log-
        // Message faces — they ride the world log leg, the param posture
        // cites that contrast
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        let state = a.get_state(); // cc :315 -> an-zl :542
        if state != STATE_PAUSED && state != STATE_RUNNING {
            return false; // cc :316-:317
        }

        if let Some(ps) = self.ps.as_mut() {
            ps.apply_swapper(a, w); // cc :321

            if ps.get_new_conf_present() {
                // cc :323-:325 (the presence face)
                let id = a.id as usize; // cc :326 (the id-seat law)
                if id >= self.reload_tuners_by_thread.len() {
                    return true; // the port guard face (cite above)
                }

                if self.reload_tuners_by_thread[id].is_none() {
                    // cc :331 the "start" echo (`ReloadResourceTuner[%u]
                    // start\n` — the id face)
                    w.log_message(&format!("ReloadResourceTuner[{id}] start"));
                    let tuners = ps.get_new_conf_tuners(); // cc :332
                    // cc :333-:340 the tinit/erase WHILE ladder (the
                    // filter-collect = the erase inverse, order intact)
                    let list: ReloadTunerSlot = tuners
                        .into_iter()
                        .filter(|t| t.borrow_mut().tinit())
                        .collect();
                    self.reload_tuners_by_thread[id] = Some(list); // :332
                    if let Some(front) = self.reload_tuners_by_thread[id]
                        .as_ref()
                        .and_then(|l| l.front().cloned())
                    {
                        // cc :341-:342 the not-empty guard + tuner-next
                        tuner_next(&front, id as u32, w);
                    }
                }

                if let Some(front) = self.reload_tuners_by_thread[id]
                    .as_ref()
                    .and_then(|l| l.front().cloned())
                {
                    // cc :345-:348 the work pass (the context pick over
                    // the an-zl is-idling :550)
                    let tuning_complete = if a.is_idling() {
                        front.borrow_mut().tune_idle_context() // cc :348
                    } else {
                        front.borrow_mut().tune_packet_context() // cc :348
                    };
                    if tuning_complete {
                        // cc :349-:354 pop-front + re-arm (the Arc-drop
                        // face keeps the TUNER alive — the conf still
                        // holds it: the C pop-never-deletes-the-tuner
                        // ownership law, cite)
                        if let Some(l) = self.reload_tuners_by_thread[id].as_mut() {
                            l.pop_front(); // cc :351
                            let next_front = l.front().cloned();
                            if let Some(t) = next_front {
                                tuner_next(&t, id as u32, w); // :352-:353
                            }
                        }
                    } else {
                        tuner_update(&front, w); // cc :356
                    }
                }

                // cc :359-:367 the done face (the "check for empty
                // again" comment kept at this leg)
                let done = self.reload_tuners_by_thread[id]
                    .as_ref()
                    .map(|l: &ReloadTunerSlot| l.is_empty())
                    .unwrap_or(false);
                if done {
                    w.log_message(&format!("ReloadResourceTuner[{id}] complete")); // :362
                    self.reload_tuners_by_thread[id] = None; // :363-:364
                    w.swapper_finish(); // :365 -> the swapper .cc :83 wall
                    return true; // :366
                }

                return false; // :369
            }
        }

        true // :373
    }

    /// cc :376-:391 the dtor (the explicit-dtor family law): the per-
    /// thread list-delete loop :378-:379 (`delete tuners` -> the None
    /// fill), the vector clear :380, the swapper gate + conf-clear legs
    /// :381-:386 (the get-new-conf gate + the clear combined at the
    /// swapper face leg — the sn-conf clear-reload-resource-tuner-list
    /// REUSE cite :2528-:2530 arms it provider-side), `delete ps` :387
    /// (the None face), the host-attributes swap-cleanup WALL leg :388
    /// (the target-based home :188 cited), the REUSED reload-tracker end
    /// :389 (the end_default face :246-:248 — the prompt-default h :35;
    /// the None conn face per the header deviation cite), and the "==
    /// reload complete" echo LAST :390 (the member log-message leg: the
    /// respond-if-remote + the Log-Message pair)
    pub fn dtor(
        &mut self,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
        tracker: &mut ReloadTracker, // the reload-tracker home REUSE
    ) {
        for slot in &mut self.reload_tuners_by_thread {
            *slot = None; // cc :378-:379
        }
        self.reload_tuners_by_thread.clear(); // cc :380

        if let Some(ps) = self.ps.as_mut() {
            ps.clear_new_conf_tuner_list(); // cc :381-:386
        }
        self.ps = None; // cc :387

        w.host_attributes_swap_cleanup(); // cc :388 -> the host-attr :188

        tracker.end_default(log, None); // cc :389

        self.base.log_message(log, "== reload complete\n", &[]); // cc :390
    }

    pub fn stringify(&self) -> &'static str {
        "SWAP"
    } // h :187
}

impl AnalyzerCommandVirtual for ACSwap {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "SWAP"
    }
}

// ====================================================================
// the host-attributes-swap pair (h :193-:201): the conn ctor h :196-:197
// (the base conn leg ONLY — no tuners vector), the execute h :198, the
// stringify h :199; the dtor h :200. The cc :393-:397 execute (the
// initialize WALL leg :395 -> the target-based home :178) + the dtor cc
// :399-:404 (the swap-cleanup :401, the REUSED reload-tracker end :402,
// the "== reload host attributes complete" echo :403 — the echo rides
// the LogRespond-else-LogMessage pair like the swap-pair tail :390)
// ====================================================================

pub struct ACHostAttributesSwap {
    pub base: AnalyzerCommand, // h :196 (the conn leg)
}

impl ACHostAttributesSwap {
    pub fn new(conn: Option<Box<dyn ControlConnFace>>) -> Self {
        ACHostAttributesSwap {
            base: AnalyzerCommand::new(conn),
        }
    }
    /// cc :393-:397
    pub fn execute(
        &mut self,
        _a: &mut AnalyzerCore, // the cc :393 unused face
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        w.host_attributes_initialize(); // cc :395 -> the host-attr :178
        true // cc :396
    }
    /// cc :399-:404 the explicit dtor (the same reload-tracker REUSE +
    /// the None-conn law as the swap-pair dtor, cite there)
    pub fn dtor(
        &mut self,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
        tracker: &mut ReloadTracker, // the reload-tracker home REUSE
    ) {
        w.host_attributes_swap_cleanup(); // cc :401
        tracker.end_default(log, None); // cc :402
        self.base
            .log_message(log, "== reload host attributes complete\n", &[]); // cc :403
    }
    pub fn stringify(&self) -> &'static str {
        "HOST_ATTRIBUTES_SWAP"
    } // h :199
}

impl AnalyzerCommandVirtual for ACHostAttributesSwap {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "HOST_ATTRIBUTES_SWAP"
    }
}

// ====================================================================
// the daq-swap pair (h :203-:209): the NO explicit ctor (the base h :48
// default face — no conn legs, the cc :414 echo NEVER touches one), the
// execute h :206, the stringify h :207, the dtor h :208. The cc :406-:410
// execute rides the an-zl reload-daq :941-:945 REUSE (the if-instance
// presence :942 lives at the home); the dtor cc :412-:415 is the bare
// LogMessage echo (NOT LogRespond, NOT the trio — the face VERBATIM)
// ====================================================================

#[derive(Default)]
pub struct ACDAQSwap {
    pub base: AnalyzerCommand,
}

impl ACDAQSwap {
    pub fn new() -> Self {
        Self::default() // the base default ctor (h :48)
    }
    /// cc :406-:410
    pub fn execute(
        &mut self,
        a: &mut AnalyzerCore,
        _log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        a.reload_daq(w); // cc :408 -> an-zl :941
        true // cc :409
    }
    /// cc :412-:415 (the echo via the log home, the pair carries NO conn)
    pub fn dtor(&mut self, log: &mut LogEngine) {
        log.log_message_stdout("== daq module reload complete\n", &[]); // cc :414
    }
    pub fn stringify(&self) -> &'static str {
        "DAQ_SWAP"
    } // h :207
}

impl AnalyzerCommandVirtual for ACDAQSwap {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "DAQ_SWAP"
    }
}

// ====================================================================
// the scratch-update pair (h :211-:223): the triple ctor h :214-:215
// (conf + handlers + conn), the members h :221-:222 (the conf raw
// pointer -> the shared handle borrowed face over the REUSED sn-conf
// record :379 — NEVER a new owner; the handlers REF vector -> the owned
// handle vector, the same-pointer double-hold law the sn-conf scratch-
// handlers seat :1074-:1092 pins, the slot twin REUSE cite), the
// execute h :217, the stringify h :218, the dtor h :219. The cc :417-:425
// execute (the null-skipping update ladder :419-:423, the update
// virtual arms — the scratch-allocator face :51) + the dtor cc :427-:431
// (THE ORDER pin: the "== scratch update complete" echo :429 FIRST,
// THEN the REUSED reload-tracker end with the TRUE prompt arm :430)
// ====================================================================

pub struct ACScratchUpdate {
    pub base: AnalyzerCommand, // h :215 (the conn leg)
    sc: Option<Rc<RefCell<SnortConfig>>>, // h :221 (the borrowed-conf
    // face; the call sites pass non-null — the None arm never fires in
    // the harness vector, cited posture)
    handlers: Vec<Option<Arc<RefCell<dyn ScratchUpdateFace>>>>, // h :222
    // (the cc :420-:421 null-skip legs ride the Option faces)
}

impl ACScratchUpdate {
    pub fn new(
        sc: Option<Rc<RefCell<SnortConfig>>>,
        handlers: Vec<Option<Arc<RefCell<dyn ScratchUpdateFace>>>>,
        conn: Option<Box<dyn ControlConnFace>>,
    ) -> Self {
        ACScratchUpdate {
            base: AnalyzerCommand::new(conn),
            sc,
            handlers,
        }
    }
    /// cc :417-:425: `for (auto * s : handlers) { if (s) s->update(sc);
    /// } return true;` VERBATIM (the null-skip :420-:421, the single
    // borrowed-conf owner across the ladder — the C same-pointer legs)
    pub fn execute(
        &mut self,
        _a: &mut AnalyzerCore, // the cc :417 unused face
        _log: &mut LogEngine,
        _w: &mut dyn AnalyzerCommandWorld, // the cc :417 face pair
    ) -> bool {
        if let Some(sc) = self.sc.clone() {
            let mut scb = sc.borrow_mut(); // the borrowed-conf face
            // cc :419-:423 the null-SKIP ladder (the None arms == the cc
            // :420 `if (s)` gate — the flatten face keeps the skip)
            for h in self.handlers.iter().flatten() {
                h.borrow_mut().update_scratch(&mut scb); // cc :422
            }
        }
        true // cc :424
    }
    /// cc :427-:431 the explicit dtor (THE ORDER: log echo :429 THEN the
    /// end TRUE-prompt arm :430 — the home end :214-:241 legs pin the
    /// "Reload ended" line before the prompt pull; the None conn face
    /// law rides the swap-pair dtor cite)
    pub fn dtor(&mut self, log: &mut LogEngine, tracker: &mut ReloadTracker) {
        self.base.log_message(log, "== scratch update complete\n", &[]); // :429
        tracker.end(log, None, true); // :430 (the prompt-TRUE face)
    }
    pub fn stringify(&self) -> &'static str {
        "SCRATCH_UPDATE"
    } // h :218
}

impl AnalyzerCommandVirtual for ACScratchUpdate {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "SCRATCH_UPDATE"
    }
}

// ====================================================================
// the cpu-report (h :225-:243): the conn ctor h :228-:230 (the cpu-usage
// vector sized by the thread-home get-instance-max CITE; the Cpu-Usage
// record h :236-:241 -> the f64 seats below — the cc :483-:485 static-
// cast legs arm the widening AT the copy, the record face stays f32),
// the execute h :231, the stringify h :232, the dtor h :233. The cc
// :463-:488 execute: the zero-init record :465, the instance-presence
// gate :467-:469 (the get-daq-instance static face cc :433-:436 -> the
// present leg — the SFDAQ pointer NEVER crosses, DEV-cited), the id seat
// :471, the ioctl fetch :473-:474 (the ordinal const above, the sf-daq-
// instance home :1122 shape), the NOT-SUCCESS arm :476-:480 (the "Fetch-
// ing profile data failed from DAQ instance %d" respond legs :478 VERBA-
// TIM, the TRUE posture :479), the cast copy legs :482-:485 (the port
// get-mut guard vs the cc :482 out-of-bounds UB seat — the honest port
// face, cited). The dtor cc :438-:461 the report ladder: the three sum
// seats :440-:442, the instance counter :443, the per-instance LINE
// `%-3d \t%-6d \t%.1f%% \t%.1f%% \t%.1f%%\n` :447-:449 VERBATIM through
// the cfmt core (the get-instance-tid leg the thread home :906-:911
// CITE arms — the cold -1 face rides the %-6d seat), the three accum
// legs :451-:453, the instance walk :454 (the cc :454 TAB-indent slip
// rides, byte-irrelevant), and the `if (instance)` DIVISION-GUARD :457
// (the zero-instance face NEVER divides NOR prints) over the "Summary"
// LINE :458-:460 (the leading-\n face, the sums divided by the instance
// COUNT — the guard legs the sums are safe)
// ====================================================================

/// h :236-:241: the Cpu-Usage record (the member names ride the C++
/// member spellings at the struct faces, the cite law)
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SnortCpuUsage {
    pub cpu_usage_30s: f64,  // h :238
    pub cpu_usage_120s: f64, // h :239
    pub cpu_usage_300s: f64, // h :240
}

pub struct ACShowSnortCPU {
    pub base: AnalyzerCommand,
    cpu_usage: Vec<SnortCpuUsage>, // h :242
}

impl ACShowSnortCPU {
    pub fn new(conn: Option<Box<dyn ControlConnFace>>) -> Self {
        ACShowSnortCPU {
            base: AnalyzerCommand::new(conn), // h :228
            cpu_usage: vec![
                SnortCpuUsage::default();
                ThreadConfig::get_instance_max() as usize
            ], // h :229 (the thread-home CITE)
        }
    }
    /// cc :463-:488 (every leg cited at the struct head above)
    pub fn execute(
        &mut self,
        a: &AnalyzerCore, // the cc :463 face; the id legs ride the
        // analyzer-id law
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        let mut get_data = DioctlGetCpuProfileData::default(); // cc :465

        if !AnalyzerCommand::get_daq_instance_present(w) {
            return true; // cc :467-:469 (`if (!instance) return true`)
        }

        let instance_id = a.id as i32; // cc :471 (the id-seat law)

        let status = w.daq_ioctl_cpu_profile(DIOCTL_GET_CPU_PROFILE_DATA, &mut get_data); // :473-:474

        if DAQ_SUCCESS != status {
            // cc :478 the respond legs VERBATIM (the %d id face; the
            // LogRespond pair arms — NO LogMessage when a conn lives,
            // the macro law cited at the base helper)
            self.base.log_respond(
                log,
                "Fetching profile data failed from DAQ instance %d\n",
                &[Arg::I(i64::from(instance_id))],
            ); // cc :478
            return true; // cc :479
        }

        if let Some(stat) = self.cpu_usage.get_mut(instance_id as usize) {
            // cc :482-:485 the cast copy legs (the f32 record -> the f64
            // seats, the static-cast faces)
            stat.cpu_usage_30s = f64::from(get_data.cpu_usage_percent_30s); // :483
            stat.cpu_usage_120s = f64::from(get_data.cpu_usage_percent_120s); // :484
            stat.cpu_usage_300s = f64::from(get_data.cpu_usage_percent_300s); // :485
        } // the port get-mut guard vs the cc :482 UB seat (cited)

        true // cc :487
    }
    /// cc :438-:461 the dtor report LADDER (every leg cited at the
    /// struct head above; the percent + tab + `%-3d` / `%-6d` faces
    /// ride the cfmt core byte-EQUAL — the DEC law header pins the
    /// probe receipt)
    pub fn dtor(&mut self, log: &mut LogEngine) {
        let mut cpu_usage_30s = 0_f64; // cc :440
        let mut cpu_usage_120s = 0_f64; // cc :441
        let mut cpu_usage_300s = 0_f64; // cc :442
        let mut instance: i32 = 0; // cc :443

        for cu in self.cpu_usage.iter().copied() {
            // cc :447-:449 the LINE VERBATIM (the tab seats + the %% +
            // the tid CITE seat)
            self.base.log_respond(
                log,
                "%-3d \t%-6d \t%.1f%% \t%.1f%% \t%.1f%%\n",
                &[
                    Arg::I(i64::from(instance)),
                    Arg::I(i64::from(ThreadConfig::get_instance_tid(instance))), // :448
                    Arg::F(cu.cpu_usage_30s),
                    Arg::F(cu.cpu_usage_120s),
                    Arg::F(cu.cpu_usage_300s),
                ],
            );

            cpu_usage_30s += cu.cpu_usage_30s; // cc :451
            cpu_usage_120s += cu.cpu_usage_120s; // cc :452
            cpu_usage_300s += cu.cpu_usage_300s; // cc :453
            instance += 1; // cc :454
        }

        if instance != 0 {
            // cc :457 the DIVISION-GUARD (the zero face NEVER divides)
            self.base.log_respond(
                log,
                "\nSummary \t%.1f%% \t%.1f%% \t%.1f%%\n", // :458 VERBATIM
                &[
                    Arg::F(cpu_usage_30s / f64::from(instance)),
                    Arg::F(cpu_usage_120s / f64::from(instance)),
                    Arg::F(cpu_usage_300s / f64::from(instance)), // :459-:460
                ],
            );
        }
    }
    pub fn stringify(&self) -> &'static str {
        "SHOW_SNORT_CPU"
    } // h :232
}

impl AnalyzerCommandVirtual for ACShowSnortCPU {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "SHOW_SNORT_CPU"
    }
}

// ====================================================================
// the latency-report (h :245-:256): the conn ctor h :248-:249 (the
// latency vector sized by the thread-home get-instance-max CITE; the h
// :255 element = the SDK record above), the execute h :251, the
// stringify h :252, the dtor h :253. The cc :559-:583 execute: the zero-
// init array :561, the presence gate :563-:567 (the "Fetching latency
// data failed from DAQ instance" echo :565 — the SAME text both
// failure arms, NO id face unlike the cpu arm — the face VERBATIM), the
// id seat :568, the ioctl :569-:572, the NOT-SUCCESS arm :574-:578 (the
// SAME echo :576, TRUE :577), the whole-record copy :580-:581 (the port
// get-mut guard vs the cc :580 UB seat, cited). The dtor cc :490-:557
// the banner/protocol ladder: the THREE-name row h... cc :492
// (`{ "TCP", "UDP", "Others" }` — the protocol-name seat VERBATIM, the
// SDK enum order cited at the latency-max const), the instance counter
// :493, the per-instance BANNER :498 (`\n================ Instance: %-3d
// ================\nThreadID: %d\n` VERBATIM, the tid CITE seat), the
// three-protocol walk :499-:553: the average leg :502-:503 (the sum-
// times-1-0-div-count-div-1000 zero-GUARDED face — the count-0 leg rides
// 0.0), the FOUR format-ip calls :508-:511 (the fallback legs the
// format-or-invalid fn arms), the bracket line :513, the SIX condi-
// tional respond legs :514-:531 (the non-zero gates + the two PRIu64
// divided-by-1000 faces + the null-conn-counters + the AVERAGE %.3f
// gated on the non-zero average :526-:528 + the max-latency :529-:531),
// the TWO 5-tuple gates :533-:551 (the C comment "Only print 5-tuple
// lines if any port is non-zero and if it has valid IPs" KEPT: the any-
// port-non-zero OR pair AND the two not-equal-invalid strcmp pairs — the
// strcmp legs land straight String compares vs the invalid const, the glibc
// faces identical), and the per-instance TAIL :554 (the EXACTLY-60
// minus-signs line, MEASURED). All respond lines ride the LogRespond
// pair (the conn-or-log macro)
// ====================================================================

/// cc :492 the protocol-name row (index == the SDK latency-protocol
/// enum face cited at the max const)
pub const LATENCY_PROTOCOL_NAMES: [&str; 3] = ["TCP", "UDP", "Others"];

pub struct ACShowSnortPacketLatencyData {
    pub base: AnalyzerCommand,
    latency_data: Vec<DioctlGetSnortLatencyData>, // h :255
}

impl ACShowSnortPacketLatencyData {
    pub fn new(conn: Option<Box<dyn ControlConnFace>>) -> Self {
        ACShowSnortPacketLatencyData {
            base: AnalyzerCommand::new(conn), // h :248
            latency_data: vec![
                DioctlGetSnortLatencyData::default();
                ThreadConfig::get_instance_max() as usize
            ], // h :249 (the thread-home CITE)
        }
    }
    /// cc :559-:583 (every leg cited at the struct head above)
    pub fn execute(
        &mut self,
        a: &AnalyzerCore, // the cc :559 face; the id seat law rides
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        let mut latency_data_array = DioctlGetSnortLatencyData::default(); // cc :561

        if !AnalyzerCommand::get_daq_instance_present(w) {
            // cc :565 (the SAME text BOTH arms — the face VERBATIM, no
            // id seat unlike the cpu ladder)
            self.base
                .log_respond(log, "Fetching latency data failed from DAQ instance\n", &[]);
            return true; // cc :566
        }
        let instance_id = a.id as usize; // cc :568 (the id-seat law)

        let status = w.daq_ioctl_snort_latency(DIOCTL_GET_SNORT_LATENCY_DATA, &mut latency_data_array); // :569-:572

        if DAQ_SUCCESS != status {
            self.base
                .log_respond(log, "Fetching latency data failed from DAQ instance\n", &[]); // :576
            return true; // :577
        }

        if let Some(stat) = self.latency_data.get_mut(instance_id) {
            *stat = latency_data_array; // :580-:581 (the whole-record
            // copy face; the port guard vs the cc :580 UB seat, cited)
        }
        true // :582
    }
    /// cc :490-:557 the dtor banner / protocol LADDER (every leg cited
    /// at the struct head above; the DEC faces ride the ONE cfmt core —
    /// the %.3f average + the six gated legs byte-match, the probe
    /// receipt in the header)
    pub fn dtor(&mut self, log: &mut LogEngine) {
        // cc :443/:493 the instance COUNTER seat (the zip face == the C
        // walk: the count NEVER gates the loop, it labels the lines and
        // arms the cpu summary guard — the i32 seat rides the tid call)
        for (instance, ld) in (0_i32..).zip(self.latency_data.iter().copied()) {
            // cc :498 the BANNER VERBATIM (the 16+16 equal-signs faces
            // — the run MEASURED at the format string)
            self.base.log_respond(
                log,
                "\n================ Instance: %-3d ================\nThreadID: %d\n",
                &[
                    Arg::I(i64::from(instance)),
                    Arg::I(i64::from(ThreadConfig::get_instance_tid(instance))), // :498
                ],
            );

            for (i, ld_proto) in
                ld.snort_latency_data.iter().copied().enumerate()
            {
                // cc :499 the three-walk bound (the SDK enum MAX cited)
                let ld = ld_proto; // :501 (the record alias, the C auto&
                // ref-seat face)
                let average_pkt_time = if ld.pkt_count > 0 {
                    // cc :502-:503 the average face VERBATIM (the times-
                    // one-double + the div-count + the div-1000; the
                    // zero-guard arms the count-0 leg)
                    (ld.sum_time as f64) * 1.0 / (ld.pkt_count as f64) / 1000.0
                } else {
                    0.0 // cc :503
                };

                // cc :505-511 the FOUR address buffers (the INET6-
                // ADDRSTRLEN face rides the String form)
                let max_pkt_src_ip = format_ip_or_invalid(&ld.max_pkt_src_addr, ld.max_pkt_src_ipv6 != 0); // :508
                let max_pkt_dst_ip = format_ip_or_invalid(&ld.max_pkt_dst_addr, ld.max_pkt_dst_ipv6 != 0); // :509
                let up_max_pkt_src_ip =
                    format_ip_or_invalid(&ld.snort_up_max_pkt_src_addr, ld.snort_up_max_pkt_src_ipv6 != 0); // :510
                let up_max_pkt_dst_ip =
                    format_ip_or_invalid(&ld.snort_up_max_pkt_dst_addr, ld.snort_up_max_pkt_dst_ipv6 != 0); // :511

                // cc :513 the bracket line
                self.base.log_respond(
                    log,
                    "  [%s]\n",
                    &[Arg::S(Some(LATENCY_PROTOCOL_NAMES[i].into()))],
                );

                // THE SIX conditional legs VERBATIM (cc :514-:531): the
                // two PRIu64 div-1000 faces, the null-conn-counters face
                // rides %lu -> the un-signed u64 arg (the PRIu64 macro
                // face, DEV-cited port law), the %.3f average gated on
                // the non-zero average, the max-latency div-1000 face
                if ld.snort_up_max_pkt_time != 0 {
                    self.base.log_respond(
                        log,
                        "    Max Latency (us, since restart): %lu\n", // :515
                        &[Arg::U(ld.snort_up_max_pkt_time / 1000)], // :516
                    );
                }
                if ld.pkt_count != 0 {
                    self.base.log_respond(
                        log,
                        "    Total Packet Count in last 5mins: %lu\n", // :518
                        &[Arg::U(ld.pkt_count)],
                    );
                }
                if ld.sum_time != 0 {
                    self.base.log_respond(
                        log,
                        "    Sum of Packet Latencies in last 5mins (us): %lu\n", // :521
                        &[Arg::U(ld.sum_time / 1000)], // :522
                    );
                }
                if ld.conn_meta_null_counters != 0 {
                    self.base.log_respond(
                        log,
                        "    Null ConnMeta Count in last 5mins: %lu\n", // :524
                        &[Arg::U(ld.conn_meta_null_counters)],
                    );
                }
                if average_pkt_time != 0.0 {
                    self.base.log_respond(
                        log,
                        "    Average Packet Latency in last 5mins (us): %.3f\n", // :527
                        &[Arg::F(average_pkt_time)], // :528
                    );
                }
                if ld.max_pkt_time != 0 {
                    self.base.log_respond(
                        log,
                        "    Maximum Observed Latency in last 5mins (us): %lu\n", // :530
                        &[Arg::U(ld.max_pkt_time / 1000)], // :531
                    );
                }

                // cc :533-:542 THE 5-tuple legs: the C comment KEPT
                // ("Only print 5-tuple lines if any port is non-zero
                // and if it has valid IPs"): the any-port OR pair AND
                // the two not-equal-invalid legs (the strcmp faces land
                // String compares — identical results, the invalid const
                // at the cc :535/:545 seats cited)
                if (ld.max_pkt_src_port != 0 || ld.max_pkt_dst_port != 0)
                    && max_pkt_src_ip != INVALID_IP
                    && max_pkt_dst_ip != INVALID_IP
                {
                    self.base.log_respond(
                        log,
                        "    5min Max Latency Packet 5-tuple: %s:%u -> %s:%u (%s)\n", // :537
                        &[
                            Arg::S(Some(max_pkt_src_ip.as_str().into())), // :538
                            Arg::U(u64::from(ld.max_pkt_src_port)),      // :539
                            Arg::S(Some(max_pkt_dst_ip.as_str().into())), // :540
                            Arg::U(u64::from(ld.max_pkt_dst_port)),      // :541
                            Arg::S(Some(LATENCY_PROTOCOL_NAMES[i].into())), // :542
                        ],
                    );
                }
                if (ld.snort_up_max_pkt_src_port != 0 || ld.snort_up_max_pkt_dst_port != 0)
                    && up_max_pkt_src_ip != INVALID_IP
                    && up_max_pkt_dst_ip != INVALID_IP
                {
                    self.base.log_respond(
                        log,
                        "    Max Latency Packet 5-tuple (us, since restart): %s:%u -> %s:%u (%s)\n", // :546
                        &[
                            Arg::S(Some(up_max_pkt_src_ip.as_str().into())), // :547
                            Arg::U(u64::from(ld.snort_up_max_pkt_src_port)), // :548
                            Arg::S(Some(up_max_pkt_dst_ip.as_str().into())), // :549
                            Arg::U(u64::from(ld.snort_up_max_pkt_dst_port)), // :550
                            Arg::S(Some(LATENCY_PROTOCOL_NAMES[i].into())),  // :551
                        ],
                    );
                }
            }
            // cc :554 the per-instance TAIL (the EXACTLY-60 minus-signs
            // line, MEASURED)
            self.base.log_respond(
                log,
                "------------------------------------------------------------\n",
                &[],
            );
            // cc :555 the walk advance (the zip binding IS the counter)
        }
    }
    pub fn stringify(&self) -> &'static str {
        "SHOW_SNORT_PACKET_LATENCY_DATA"
    } // h :252
}

impl AnalyzerCommandVirtual for ACShowSnortPacketLatencyData {
    fn execute_virtual(
        &mut self,
        a: &mut AnalyzerCore,
        log: &mut LogEngine,
        w: &mut dyn AnalyzerCommandWorld,
    ) -> bool {
        self.execute(a, log, w)
    }
    fn stringify(&self) -> &'static str {
        "SHOW_SNORT_PACKET_LATENCY_DATA"
    }
}

// ====================================================================
// THE TAIL CITE BLOCK (the 23i dialect law — measured post-cited, NEVER
// live): the h :258-:265 namespace block. h :261-:263 the REG_TEST block
// (`#if defined(REG_TEST) void main_unicast_command(AnalyzerCommand*,
// unsigned target, ControlConn* = nullptr); #endif`): REG_TEST x1 MEASURED
// h :261 (x0 cc), NEVER defined by this build system — the main-unicast
// decl NEVER lands, the CITED comment face is ALL it is. h :264 the main-
// broadcast decl (`SO_PUBLIC void main_broadcast_command(snort::Analyzer-
// Command*, ControlConn* = nullptr)` — from the snort-p .cc seat): the
// seam ALREADY lives at the sn-conf home (the main-broadcast-ac-scratch-
// update trait leg :924-:927 + the update-scratch method :1547-:1549, the
// ACScratchUpdate ctor :214-:215 above arms the object face) — CITED,
// NEVER moved, NEVER duplicated: this pair's OWN call sites carry NO
// broadcast leg (every broadcast call site in the ground lives in ANOTHER
// TU — grep-measured) so NO row trait leg re-models it
// ====================================================================
