//! Flat, cite-heavy literal port of `framework/reload_survivor_subscriptions.cc`
//! (ground truth @ fe29cbe: cc 631 L md5 `ff4b549236fce47b0ee899d6b793f87a`)
//! plus the public surface of `framework/reload_survivor_subscriptions_impl.h`
//! (156 L md5 `b437ba1cff967338b48b1b354743d64a`) = the 787-L row ledger the
//! tools/rsubs_harness/build.sh asserts EVERY build (row 21a, chapter-19 P2:
//! THE RELOAD-SURVIVOR-SUBSCRIPTIONS REGISTRY — the FIRST framework-registry
//! row of the port).
//!
//! PAIR-CLOSURE law (rsubs PLAN §1, MEASURED both ways harness-side): the cc
//! DIRECT-quotes the impl.h at cc :24 — the pair is ONE registry/pegs/enum/
//! flow-pin mechanism; dropping impl.h kills the cc (`fatal error:
//! reload_survivor_subscriptions_impl.h`), dropping flow/flow_data.h kills it
//! CHAINED via impl.h:32 (the flowz DECOY never satisfies the ground path).
//!
//! WITNESS/SEAM FACES (the EXACTLY-3 own-new mirrors the harness link closes,
//! rsubs witness_rsubs.cc — cite ALL, provider-queued, NEVER invented here):
//! * `DataBus::_subscribe(const PubKey&, unsigned, DataHandler*)` — the
//!   friend-unlock PRIVATE overload (data_bus.h :127 `friend class
//!   ReloadSurvivorSubscriptions` + :130 signature face; body-shape cite
//!   data_bus.cc :210). NO landed DataBus type exists in src/ (AUDIT: the only
//!   landed bus faces are the file_api name-level `DataBusSeam`/
//!   `DataBusIdSeam` traits, file_log.rs:543 / file_inspect.rs:129 — the
//!   PUBLIC subscribe shape, NEVER this overload; the pub_sub row NEVER
//!   lands: rsubs.o carries ZERO pub_sub symbols — PLAN §2). This port models
//!   the subscribe ladder against the cited [`DataBusSubscribeSeam`] trait with
//!   the same left-open discipline: mirror face cited, provider queued with the
//!   data_bus row (data_bus.cc, P3'/queue).
//! * `SnortConfig::get_reload_id()` (snort_config.h :775 `SO_PUBLIC static
//!   unsigned get_reload_id();` — the NOT-`const` member face) + the carried
//!   `SnortConfig::get_conf()` seam: NO landed SnortConfig type; the landed
//!   config-presence face is `LogEngine::conf_present` (messages.rs :102
//!   "Stands for SnortConfig::get_conf() != nullptr") which the [`RssConfigSeam`]
//!   mirrors for the cc :79-:80 ternary. The harness witness returns 7 — the
//!   T8c `reload id 7` vectors substring rides that face EXACTLY.
//! * `WarningMessage(const char*, ...)` (messages.h :58 variadic face): the
//!   landed Rust twin is `LogEngine::warning_message` (messages.rs :370) over
//!   the landed cfmt core (utils/cfmt.rs :159). Threading an engine instance
//!   through the registry internals would diverge from the C's implicit
//!   global, so the port lands the thin global bridge [`warning_message`]
//!   (same cfmt core, same call-site arity) with a provider-queued default sink
//!   (the pull-site-count-only posture, 19a show_prompt precedent); the harness
//!   capture mirror (witness_rsubs.cc wr_last_warn/wrwarn_calls) registers a
//!   sink in the parity replay, the production sink stays provider-queued.
//!
//! `SurvivorFlowData` (impl.h :138-:152 `class SurvivorFlowData : public
//! FlowData`) is a DECL-ONLY mirror face: DEFINED ONLY in
//! `survivor_flow_data.cc` 88 L (md5 4b1eedaf70469172153c22cd91b4a682, the
//! row-21b/P3 provider NOT landed); `nm rsubs.o | grep -c SurvivorFlowData`
//! = 0 (harness-proven NO link pull — the class rides the header as a decl).
//! The reachable arms of THIS row never touch it, so this rs lands the cited
//! decl face as documentation ONLY — ZERO type, ZERO stand-in (the
//! never-invent law; flow/flow_data.h's FlowData is its own unlanded row).
//!
//! `rss_stats.policy_resolution_failures`: the row cc NEVER bumps it
//! (build.sh grep-pin `policy_resolution_failures\.(fetch_add|store)` == 0 on
//! the cc); the ONLY production bumps are inspector_manager.cc :652/:681
//! (inspector_manager-owned CONSUMER row, cite-only) — NEVER invent a
//! provider; the field + slot exist, the bump sites do not.
//!
//! CLOCK SEAM (the UNIT_TEST arms; ground census cc 4 / impl.h 1 — build.sh
//! asserts EXACTLY 4/1, flip trips loud): forced_elapsed_ms (:57) + the
//! elapsed_ms read arm (:63-:64) + rss_reset_for_test's clear (:620) + the
//! rss_set_elapsed_for_test def @ :625 (impl.h :133-:135 pair; the NEXT.md
//! ':619-:624' region cite is DRIFTED — the :625 disk face wins, build.sh
//! sed-pins `void rss_set_elapsed_for_test(uint64_t ms)` @ :625). cargo cfg is
//! NOT the autotools -DUNIT_TEST flag (the 18d DEBUG_MSGS precedent): the seam
//! lands UNCONDITIONALLY in Rust; the production build NEVER calls it and
//! forced_elapsed_ms stays 0 = the real-clock arm (cc :56 "zero means use the
//! real clock").
//!
//! NDEBUG posture: the row cc carries ZERO runtime assert() arms (build.sh:
//! `^[[:space:]]*assert\(` == 0; the only 'assert' string hits are the :340
//! static_assert + the <cassert> include = EXACTLY 2) — the 50-face nm census
//! is NDEBUG-INVARIANT (0 __assert_fail pulls). The Rust port models nothing
//! special: ZERO assert!/debug_assert! arms land, honest NON-delta vs the 19a
//! module.cc :372 +1 face.
//!
//! THE static_assert (:340 `std::size(rss_pegs) == RssPeg::Count + 1`) ships
//! as the Rust `const _: () = assert!` compile-shape face (the harness proves
//! the .o exists = it held; NEVER a runtime arm). THE TRIPLE-coupling contract
//! (impl.h :42 "order must match RssStats and rss_pegs[] exactly"): RssPeg
//! enumeration order == RSS_PEGS row order == RssStats field order — pinned by
//! the harness PYPIN walk AND the parity test.

use crate::framework::counts::{CountType, PegCount, PegInfo};
use crate::hash::fnv1a; // the landed FNV-1a home (hash/fnv.rs, re-exported via hash/mod.rs `pub use fnv::*`)
use crate::utils::cfmt;
use crate::utils::cfmt::Arg;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

// ---------------------------------------------------------------------------
// C `constexpr uint64_t slow_wait_first_ms/second_ms/repeat_ms` (:51-:53,
// anon namespace) — "first warning at 5 s, the next at 1 min, every 5 min
// after that" (:50). Disk sed-pins (build.sh :66-:68 the :51/:52/:53 lines).
// ---------------------------------------------------------------------------
const SLOW_WAIT_FIRST_MS: u64 = 5000; // cc :51
const SLOW_WAIT_SECOND_MS: u64 = 60000; // cc :52
const SLOW_WAIT_REPEAT_MS: u64 = 300000; // cc :53

// ---------------------------------------------------------------------------
// THE clock seam (cc :55-:58 `#ifdef UNIT_TEST` `static std::atomic<uint64_t>
// forced_elapsed_ms{ 0 };` — "zero means use the real clock; absent from
// release builds"). Rust: landed unconditionally (cargo-cfg face above),
// NSDMI {0} rides the const ctor face.
// ---------------------------------------------------------------------------
static FORCED_ELAPSED_MS: AtomicU64 = AtomicU64::new(0); // cc :57

// cc :60-:69 `static uint64_t elapsed_ms(std::chrono::steady_clock::time_point since)`
// — Rust Instant for the steady_clock time_point (landed time/clock_defs.rs
// rides the same std anchor). The UNIT_TEST forced-read arm (:63-:64) lands
// unconditionally per the seam law above: `if ( const uint64_t forced =
// forced_elapsed_ms.load(std::memory_order_relaxed) ) return forced;` — the
// declaration-inside-the-condition face rides the let binding.
fn elapsed_ms(since: Instant) -> u64 {
    let forced = FORCED_ELAPSED_MS.load(Ordering::Relaxed); // cc :63 memory_order_relaxed
    if forced != 0 {
        return forced;
    }
    // cc :67-:68 `static_cast<uint64_t>(duration_cast<ms>(now() - since).count())`
    Instant::now().duration_since(since).as_millis() as u64
}

// cc :71-:77 `static bool warn_due(uint64_t elapsed, unsigned warns)`
// — eval-order var-first face: the SECOND return is the compound
// `slow_wait_second_ms + (warns - 1) * slow_wait_repeat_ms` — every
// sub-expression below is a plain const/param read, arithmetic WRAPS exactly
// like C unsigned (wrapping_ops on u64 args mirror C `unsigned warns` widened;
// the C computes in uint64_t: second + (warns-1)*repeat, all consts u64).
fn warn_due(elapsed: u64, warns: u32) -> bool {
    if warns == 0 {
        // cc :73-:74 `if ( !warns ) return elapsed >= slow_wait_first_ms;`
        return elapsed >= SLOW_WAIT_FIRST_MS;
    }
    let step = ((warns - 1) as u64)
        .wrapping_mul(SLOW_WAIT_REPEAT_MS)
        .wrapping_add(SLOW_WAIT_SECOND_MS);
    elapsed >= step // cc :76
}

// ---------------------------------------------------------------------------
// THE config seam (cc :79-:80 `static unsigned current_reload_id()`
// `{ return SnortConfig::get_conf() ? SnortConfig::get_reload_id() : 0; }`).
// get_conf() stands via the landed LogEngine::conf_present posture
// (messages.rs :102); get_reload_id() is the harness witness face
// (witness_rsubs.cc `unsigned SnortConfig::get_reload_id() { return 7; }`,
// snort_config.h :775 the NOT-const member face). Provider-queued: real
// reload-id bookkeeping lands with the config/reload rows.
// ---------------------------------------------------------------------------
pub struct RssConfigSeam {
    /// `SnortConfig::get_conf() != nullptr` (the cc :80 gate).
    pub conf_present: bool,
    /// `SnortConfig::get_reload_id()` (snort_config.h :775; the harness
    /// witness face = 7 — the T8c `reload id 7` vectors substring).
    pub reload_id: u32,
}

static RSS_CONFIG_SEAM: OnceLock<RssConfigSeam> = OnceLock::new();

/// Register the config seam (idempotent; the harness witness mirror sets
/// `{ conf_present: true, reload_id: 7 }`). Production wiring is
/// provider-queued (the config row) — NEVER invented here.
pub fn set_rss_config_seam(seam: RssConfigSeam) {
    let _ = RSS_CONFIG_SEAM.set(seam);
}

fn current_reload_id() -> u32 {
    // cc :80 verbatim ternary: conf ? reload_id : 0; an UNSET seam models
    // get_conf() == nullptr (the probe never hits this arm; the ternary does).
    match RSS_CONFIG_SEAM.get() {
        Some(s) if s.conf_present => s.reload_id,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// THE survivor seam: this row's cc reaches ONLY two Inspector faces —
// cc :82-:83 `survivor_name(Inspector* s) { return (s and s->get_api()) ?
// s->get_name() : "<unknown>"; }` and the pointer-IDENTITY key (the registry
// map, :241). `Inspector` (framework/inspector.h :107, the 175-L inspector.cc
// CONSUMER row) is NOT landed; the RSS entry points receive the survivor
// through this cited input face (the 19a ControlConnTracker posture):
//   * `get_api()` — inspector.h :161 (inline getter; the NULL arm at cc :83
//     yields the `'<unknown>'` label — harness T8c).
//   * `get_name()` — inspector.h :284 `return api->base.name;` INLINE (the nm
//     face: W-emitted in the row .o, ZERO witness pull).
// The provider (real Inspector) lands with the inspector row, NEVER forked
// here.
pub trait RssSurvivor {
    /// inspector.h :161 `get_api()` — presence face only (no InspectApi type
    /// in this row).
    fn get_api(&self) -> bool;
    /// inspector.h :284 `get_name() const` — reached ONLY when get_api() is
    /// non-null (cc :83).
    fn get_name(&self) -> &'static str;
}

// cc :82-:83 — the C takes `Inspector*` and guards both the pointer and the
// api; Rust carries the (already non-null) seam ref, so the pointer arm of
// the `s and` guard is the Option face.
fn survivor_name(survivor: Option<&dyn RssSurvivor>) -> &'static str {
    match survivor {
        Some(s) if s.get_api() => s.get_name(), // cc :83 `s and s->get_api()`
        _ => "<unknown>",                       // cc :83 the label arm (T8c)
    }
}

// ---------------------------------------------------------------------------
// THE bus/handler provider seams. DataBus/DataHandler/PubKey
// (framework/data_bus.h :44-:130) are UNLANDED rows: this port lands the
// mirror faces the row cc actually touches, provider-queued (NEVER a real
// bus). The file_api-landed `DataBusSeam`/`DataBusIdSeam` traits
// (file_log.rs:543 / file_inspect.rs:129) are the PUBLIC subscribe/get_id
// shapes by NAME — different arity, NEVER reused here, NEVER re-forked.
// ---------------------------------------------------------------------------

/// data_bus.h :44-:48 `struct PubKey { const char* publisher; unsigned
/// num_events; };` — the impl.h :40 front-decl + the cc :302/:366 refs. The
/// file_log deviation face (file_log.rs:101-:106, PubKey TU-local by name)
/// lives in THAT row; the rsubs row reads pub.publisher (strcmp face) and
/// carries num_events inertly, so the full two-field shape lands.
#[derive(Clone, Copy, Debug)]
pub struct PubKey {
    pub publisher: &'static str, // C `const char* publisher`
    pub num_events: u32,         // C `unsigned num_events` (inert here)
}

/// data_bus.h :50 `class DataEvent` — the bare marker face (the row cc only
/// forwards `DataEvent&` and never inspects it; the probe drives
/// BareDataEvent, data_bus.h :99-:104 `class BareDataEvent final : public
/// DataEvent`). Provider-queued with the data_bus row, NEVER invented.
pub trait DataEvent: Send + Sync {}

/// data_bus.h :99-:104 the probe's event face.
pub struct BareDataEvent;
impl DataEvent for BareDataEvent {}

/// data_bus.h :78-:95 `class DataHandler` — the base face the row cc touches:
/// the protected ctor `DataHandler(const char* mod_name)` (:93),
/// `module_name` (:84), `order` (:88, "1 = first, 0 = last"), the
/// `std::atomic<bool> live{true}` NSDMI (:90 "retired handlers clear this"),
/// and `virtual void handle(DataEvent&, Flow*)` (:82). The C `Flow*` param is
/// inert on EVERY arm reachable here (inner->handle just forwards it; the
/// harness handlers ignore it); the unlanded flow row owns Flow, so the
/// ported param rides a thin `*const ()` carry — NEVER derefed, no unsafe.
pub trait DataHandler: Send + Sync {
    /// data_bus.h :82 `virtual void handle(DataEvent& e, Flow* f)`.
    fn handle(&self, event: &dyn DataEvent, flow: *const ());
    /// data_bus.h :84 `const char* module_name`.
    fn module_name(&self) -> &str;
    /// data_bus.h :88 `unsigned order = 0;` — NSDMI 0 face.
    fn order(&self) -> u32 {
        0
    }
    /// data_bus.h :90 `std::atomic<bool> live{true}` — the cell the base
    /// class owns (retire() writes it, cc :205).
    fn live(&self) -> &AtomicBool;
}

/// The friend-unlock PRIVATE overload provider seam:
/// `DataBus::_subscribe(const PubKey&, unsigned evt_id, DataHandler* h)`
/// (data_bus.h :127 `friend class ReloadSurvivorSubscriptions;` + :130
/// `void _subscribe(const PubKey&, unsigned evt_id, DataHandler*);`;
/// body-shape cite data_bus.cc :210; the call site is cc :420
/// `ip.dbus._subscribe(pub, eid, leased);` — THE friend-unlock site the
/// harness sed-pins). The harness closes the C link with exactly ONE mirror
/// body (witness_rsubs.cc, the +3 own-new census); the Rust provider is
/// queued with the data_bus row — NEVER a real pub_sub world here (rsubs.o
/// carries ZERO pub_sub symbols, PLAN §2).
///
/// The leased pointer hand-off is modelled by Arc (the ownership-face
/// deviation note below): C hands the bus a RAW `RssLeaseHandler*`.
/// `bus_id` stands for the DataBus identity stored per HandlerEntry
/// (cc :424 `&ip.dbus` = the bus-teardown compare key, cc :557).
pub trait DataBusSubscribeSeam: Send + Sync {
    /// data_bus.h :130 / cc :420 — the private friend-unlock overload. The
    /// leading-underscore C identity rides this cite; the Rust arm is
    /// rss_subscribe (a leading-underscore method would mask the param-name
    /// convention).
    fn rss_subscribe(&self, pub_key: &PubKey, eid: u32, leased: &Arc<RssLeaseHandler>);
    /// The `const DataBus*` identity face (cc :424/:557 `&ip.dbus`).
    fn bus_id(&self) -> usize;
}

/// policy.h :152-:177 `class InspectionPolicy` — the ctor/entry-point face
/// THIS row reaches: `user_policy_id` (policy.h :159 NSDMI `= 1` — the T5
/// `ipid=1` vectors face) and the BY-VALUE `snort::DataBus dbus;` member
/// (policy.h :163 — the `ip.dbus` handle at cc :420). The RESIDENT landed
/// face is `main::policy::IpsPolicy` (policy.rs, the public policy member
/// audit: it carries NO dbus member and no DataBus row landed into it —
/// NEVER patched over or re-forked this row): the rsubs ctor therefore rides
/// this cited seam struct, provider-queued with the policy/data_bus rows.
pub struct RssInspectionPolicy {
    pub user_policy_id: u64, // policy.h :159 (NSDMI 1)
    // the `InspectionPolicy*` key face (cc :389 `&ip`, :478 e.target_ip) rides
    // the struct ADDRESS (policy_seam_id below) — same face as the C pointer,
    // no second id field to drift.
    pub bus: &'static dyn DataBusSubscribeSeam, // policy.h :163 `snort::DataBus dbus` (by-value member -> the seam ref face)
}

/// policy.h :183-:227 `class NetworkPolicy` — same face: `user_policy_id`
/// (policy.h :226 NSDMI `= 1` — the T5 `npid=1`) + the id key. (The resident
/// `main::policy::NetworkPolicy` likewise carries neither the id NSDMI nor a
/// dbus — cited, never touched; the rsubs ctor rides this seam.)
pub struct RssNetworkPolicy {
    pub user_policy_id: u64, // policy.h :226 (NSDMI 1); cc :418 reads it via the ref face
}

// ---------------------------------------------------------------------------
// cc :85-:91 `struct HandlerEntry { InspectionPolicy* target_ip; const
// DataBus* bus; std::string key; DataHandler* handler; };` — the pointer
// fields ride the id faces above (deviation note: C raw-pointer identity ->
// Rust id usize / Arc strong handle; the vectors NEVER print identities).
// ---------------------------------------------------------------------------
struct HandlerEntry {
    target_ip: usize,               // cc :87 `InspectionPolicy* target_ip`
    bus: usize,                     // cc :88 `const DataBus* bus`
    key: String,                    // cc :89
    handler: Arc<RssLeaseHandler>,  // cc :90 `DataHandler* handler`
}

// cc :93-:106 `struct SurvivorState` — NSDMI law: every `= 0`/`false` rides
// the hand-written Default below; `std::chrono::steady_clock::time_point
// reconcile_started;` default-constructs in C and is READ ONLY behind
// `reconciling` (opened at :586 re-stamps it), so Instant::now() at state
// construction is face-equivalent (deviation cited here).
struct SurvivorState {
    handlers: Vec<HandlerEntry>,          // cc :95
    np_user_id: u64,                      // cc :96
    ip_user_id: u64,                      // cc :97
    ids_initialized: bool,                // cc :98
    reconciling: bool,                    // cc :100
    reconcile_started: Instant,           // cc :102
    reconcile_reload_id: u32,             // cc :103
    reconcile_deferrals: u64,             // cc :104
    reconcile_warns: u32,                 // cc :105
}

// CITED point-site allow (the 20a derivable_impls precedent): the hand-
// written default keeps the cc :96-:105 NSDMI `= 0` / `= false` face
// STATEMENT-VERBATIM (a derived Default would erase the per-field cites).
#[allow(clippy::derivable_impls)]
impl Default for SurvivorState {
    fn default() -> Self {
        SurvivorState {
            handlers: Vec::new(),
            np_user_id: 0,
            ip_user_id: 0,
            ids_initialized: false,
            reconciling: false,
            reconcile_started: Instant::now(), // the default time_point face (above)
            reconcile_reload_id: 0,
            reconcile_deferrals: 0,
            reconcile_warns: 0,
        }
    }
}

// cc :108-:116 `struct DedupKey { Inspector* survivor; InspectionPolicy*
// target_ip; std::string key; bool operator==(...) }` — identity == the id
// faces; `==` derives to the same three-field compare cc :115.
#[derive(Clone, PartialEq, Eq)]
struct DedupKey {
    survivor: usize,   // cc :110 `Inspector* survivor`
    target_ip: usize,  // cc :111 `InspectionPolicy* target_ip`
    key: String,       // cc :112
}

// cc :115 `survivor == o.survivor and target_ip == o.target_ip and key == o.key`
// ordering face (short-circuit order preserved via the derived tuple compare).

// cc :118-:127 `struct DedupKeyHash { size_t operator()(const DedupKey& k) }`
// — THE golden-ratio mix: the constant 0x9e3779b97f4a7c15 appears EXACTLY
// twice (cc :123/:124, build.sh grep-pins == 2; the parity tripwire re-asserts
// the same census on this rs). libstdc++ `std::hash<void*>` is the IDENTITY
// (scratch-verified posture; cited deviation); `std::hash<std::string>` for the
// key face rides the LANDED fnv1a (hash/fnv.rs — REUSED, never re-ported).
// The composite lands as a fn and streams as one pre-mixed u64 through the
// BuildHasherDefault plumbing (bucket order NEVER vectors-observable).
const GOLDEN_RATIO_MIX: u64 = 0x9e3779b97f4a7c15; // the cc :123/:124 constant face

// cc :122-:125 statement-verbatim; wrapping arithmetic law (C size_t ops):
//   h = hash<void*>{}(k.survivor);
//   h ^= hash<void*>{}(k.target_ip) + 0x9e.. + (h << 6) + (h >> 2);
//   h ^= hash<std::string>{}(k.key)   + 0x9e.. + (h << 6) + (h >> 2);
// eval-order var-first: every RHS is bound BEFORE the ^-assign.
fn dedup_key_hash(k: &DedupKey) -> u64 {
    let mut h = k.survivor as u64; // cc :122 `size_t h = std::hash<void*>{}(k.survivor);`
    let mix_ip = (k.target_ip as u64)
        .wrapping_add(GOLDEN_RATIO_MIX)
        .wrapping_add(h << 6)
        .wrapping_add(h >> 2);
    h ^= mix_ip; // cc :123
    let mix_key = fnv1a(k.key.as_bytes())
        .wrapping_add(GOLDEN_RATIO_MIX)
        .wrapping_add(h << 6)
        .wrapping_add(h >> 2);
    h ^= mix_key; // cc :124
    h
}

#[derive(Default)]
struct RssHasher {
    h: u64,
}
impl Hasher for RssHasher {
    fn finish(&self) -> u64 {
        self.h
    }
    fn write(&mut self, bytes: &[u8]) {
        // the u64 fast path below carries the whole composite; a byte stream
        // would only fold a raw passthrough (never exercised by DedupKey).
        for b in bytes {
            self.h ^= *b as u64;
        }
    }
    fn write_u64(&mut self, v: u64) {
        self.h = v;
    }
}
impl Hash for DedupKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(dedup_key_hash(self));
    }
}
type RssBuildHasher = BuildHasherDefault<RssHasher>;

// cc :129-:130 `using DedupEntry = std::pair<const char*, unsigned>;` —
// "original (publisher, event) a repeated key is checked against; see
// classify_dedup()".
type DedupEntry = (&'static str, u32);

// ---------------------------------------------------------------------------
// cc :132-:236 `class RssLeaseHandler : public DataHandler` — "in-flight
// dispatch lease around every RSS handler". Anon-namespace identity: the C
// lease family is LOCAL t-only (nm census: ZERO ABI exposure, harness
// receipts); the Rust seam plumbing (Arc hand-off through the provider trait)
// forces the pub face — cited deviation, identity stays module-internal by
// convention.
// ---------------------------------------------------------------------------
pub struct RssLeaseHandler {
    key: String,                    // cc :224 `const std::string key`
    survivor: usize,                // cc :225 `Inspector* const survivor` (id face)
    survivor_label: String,         // cc :226 `const std::string survivor_label`
    np_user_id: u64,                // cc :227 `const uint64_t np_user_id`
    ip_user_id: u64,                // cc :228 `const uint64_t ip_user_id`
    inflight: AtomicU32,            // cc :230 `std::atomic<unsigned> inflight { 0 }` NSDMI 0
    // cc :232-:235 private: `DataHandler* const inner` (sole owner — the
    // non-copyable law :176-:178 keeps a stray value-copy from double-delete;
    // Rust: the Box is the sole owner, Drop IS the delete face),
    // `const std::string module_label`, `std::atomic<unsigned> borrows { 0 }`.
    inner: Box<dyn DataHandler>,
    module_label: String,
    borrows: AtomicU32,
    order: u32, // cc :142 `order = inner_->order;` (the base DataHandler::order copy)
    live: AtomicBool, // the DataHandler-base live cell (data_bus.h :90) the wrapper owns
}

impl RssLeaseHandler {
    /// ctor cc :136-:142 —
    /// `RssLeaseHandler(DataHandler* inner_, const std::string& key_, Inspector* survivor_,
    ///  uint64_t np_id, uint64_t ip_id) :
    ///   DataHandler(inner_->module_name), key(key_), survivor(survivor_),
    ///   survivor_label(survivor_name(survivor_)), np_user_id(np_id), ip_user_id(ip_id),
    ///   inner(inner_),
    ///   module_label(inner_->module_name ? inner_->module_name : "")`
    /// `{ order = inner_->order; module_name = module_label.c_str(); }`
    /// The `module_name = module_label.c_str()` re-point (base slot -> own
    /// owned-label copy) has no Rust slot to repoint; the wrapper's
    /// module_name answers through module_label (cc :219 prints
    /// `module_name` — same string face).
    pub fn new(inner: Box<dyn DataHandler>, key: &str, survivor: Option<&dyn RssSurvivor>, np_id: u64, ip_id: u64) -> RssLeaseHandler {
        let module_label = if inner.module_name().is_empty() { String::new() } else { inner.module_name().to_string() }; // cc :141 ternary face
        let ord = inner.order(); // cc :142 `order = inner_->order;` (read BEFORE the Box moves — var-first law)
        RssLeaseHandler {
            key: key.to_string(),          // cc :138 `key(key_)` (dk.key)
            survivor: survivor.map_or(0, survivor_id), // cc :139 `survivor(survivor_)`
            survivor_label: survivor_name(survivor).to_string(), // cc :139 survivor_name label
            np_user_id: np_id,             // cc :139 (np.user_policy_id face, call :418)
            ip_user_id: ip_id,             // cc :139 (ip.user_policy_id)
            inflight: AtomicU32::new(0),   // cc :230 NSDMI { 0 }
            inner,                         // cc :140 `inner(inner_)` (sole owner)
            module_label,                  // cc :141
            borrows: AtomicU32::new(0),    // cc :235 NSDMI { 0 }
            order: ord,                    // cc :142 base DataHandler::order copy
            live: AtomicBool::new(true),   // DataHandler base live{true} NSDMI (data_bus.h :90)
        }
    }
}

impl RssLeaseHandler {
    /// cc :144-:174 `~RssLeaseHandler()` — "waits out any borrow() still held
    /// by a drain() outside the registry lock". Rust Drop = the delete/
    /// destruction face (the Arc's last strong ref); `delete inner` (cc :173)
    /// folds into the Box drop at the end of this body.
    fn drain_borrows(&self) {
        // cc :147-:148 `const auto started = ...now(); unsigned warns = 0;`
        let started = Instant::now();
        let mut warns: u32 = 0;
        loop {
            // cc :152 `const unsigned held = borrows.load(std::memory_order_seq_cst);`
            let held = self.borrows.load(Ordering::SeqCst);
            if held == 0 {
                break; // cc :154-:155 `if ( !held ) break;`
            }
            // cc :157 `const uint64_t elapsed = elapsed_ms(started);` (R6 var-
            // first state read)
            let elapsed = elapsed_ms(started);
            // cc :159-:168 the warn_due arm
            if warn_due(elapsed, warns) {
                if warns == 0 {
                    // cc :161-:162 `if ( !warns ) rss_stats.slow_drains.fetch_add(1, relaxed);`
                    RSS_STATS.slow_drains.fetch_add(1, Ordering::Relaxed);
                }
                warns += 1; // cc :164
                // cc :166-:167 `warn_slow_wait("wrapper destruction", elapsed,
                // inflight.load(relaxed), held);` — the inline-load arg face rides
                // the var-first let (R6) in the call below.
                let in_flight = self.inflight.load(Ordering::Relaxed);
                self.warn_slow_wait("wrapper destruction", elapsed, in_flight, held);
            }
            std::thread::yield_now(); // cc :170 std::this_thread::yield()
        }
    }

    // cc :176-:178 non-copyable law — Rust: Box + Arc plumbing, no Copy/Clone
    // derives exist on the wrapper (the strays cannot compile). Cited.

    /// cc :180-:182 `void borrow()` — "pins this object alive; pair with
    /// unborrow() around any use outside the registry lock".
    pub fn borrow(&self) {
        self.borrows.fetch_add(1, Ordering::SeqCst);
    }

    /// cc :184-:185 `void unborrow()`.
    pub fn unborrow(&self) {
        self.borrows.fetch_sub(1, Ordering::SeqCst);
    }

    /// cc :187-:197 `void handle(DataEvent& e, Flow* f) override` — the live
    /// gate + the dead-skip peg (the T9 arms face).
    pub fn handle(&self, e: &dyn DataEvent, f: *const ()) {
        // cc :189 `inflight.fetch_add(1, std::memory_order_seq_cst);`
        self.inflight.fetch_add(1, Ordering::SeqCst);
        // cc :191-:194 `if ( live.load(seq_cst) ) inner->handle(e, f); else
        // rss_stats.dead_handler_skips.fetch_add(1, relaxed);`
        if self.live.load(Ordering::SeqCst) {
            self.inner.handle(e, f);
        } else {
            RSS_STATS.dead_handler_skips.fetch_add(1, Ordering::Relaxed);
        }
        // cc :196 `inflight.fetch_sub(1, std::memory_order_seq_cst);`
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }

    /// cc :199-:206 `retire()` — the seq_cst store-buffer pairing comment rides
    /// verbatim: "seq_cst: this live-store pairs with drain()'s inflight-load
    /// and handle()'s fetch_add + live-load (store-buffer). inner->live is the
    /// wrapped handler's own flag, off that path, so release suffices."
    pub fn retire(&self) {
        self.live.store(false, Ordering::SeqCst); // cc :204 seq_cst
        self.inner.live().store(false, Ordering::Release); // cc :205 release
    }

    /// cc :208-:209 `unsigned borrow_count() const`.
    pub fn borrow_count(&self) -> u32 {
        self.borrows.load(Ordering::Relaxed)
    }

    /// cc :211-:222 `void warn_slow_wait(const char* phase, uint64_t elapsed,
    /// unsigned in_flight, unsigned held) const` — THE warn-string face the
    /// T8c capture substrings ride (`'<unknown>'`, `key 'k5'`, `reload id 7`).
    /// STDu64 = snort_types.h :32 `#define STDu64 "%" PRIu64` -> the "%lu"
    /// glibc x86-64 face the landed cfmt consumes (length-mod `l`). Every arg
    /// lands as a VAR before the call (R6 eval-order law).
    pub fn warn_slow_wait(&self, phase: &str, elapsed: u64, in_flight: u32, held: u32) {
        // cc :220 `live.load(relaxed) ? "live" : "retired"` (inline arg face ->
        // var-first)
        let live_label = if self.live.load(Ordering::Relaxed) { "live" } else { "retired" };
        // cc :221 `current_reload_id()` (inline arg face -> var-first)
        let rid = current_reload_id();
        let args: [Arg<'_>; 12] = [
            Arg::S(Some(phase.into())),               // cc :218 `phase`
            Arg::S(Some(self.survivor_label.as_str().into())), // cc :218 survivor_label.c_str()
            Arg::U(self.survivor as u64),             // cc :218 `static_cast<const void*>(survivor)` (%p)
            Arg::S(Some(self.module_label.as_str().into())), // cc :219 `module_name`
            Arg::S(Some(self.key.as_str().into())),   // cc :219 `key.c_str()`
            Arg::U(self.np_user_id),                  // cc :219 STDu64
            Arg::U(self.ip_user_id),                  // cc :219 STDu64
            Arg::U(elapsed),                          // cc :219 STDu64
            Arg::U(in_flight as u64),                 // cc :219 `%u callback(s)`
            Arg::U(held as u64),                      // cc :219 `%u borrow(s) held`
            Arg::S(Some(live_label.into())),          // cc :220 handler state
            Arg::U(rid as u64),                       // cc :221 `reload id %u`
        ];
        // the format string VERBATIM from cc :214-:217 (STDu64 -> %lu):
        warning_message(
            "RSS: %s still waiting on survivor '%s' (%p) handler '%s' \
             key '%s' (network policy %lu, inspection policy %lu) after \
             %lu ms; %u callback(s) in flight, %u borrow(s) held, handler %s, \
             reload id %u\n",
            &args,
        );
    }
}

// cc :133 `class RssLeaseHandler : public DataHandler` — the base-class face:
// the wrapper IS a DataHandler (the bus subscribes THE wrapper; cc :420 hands
// `leased` over). The C upcast `DataHandler(inner_->module_name)` base-ctor
// + the `module_name = module_label.c_str()` re-point land as the trait
// impl below (metadata answers through the wrapper's own cells).
impl DataHandler for RssLeaseHandler {
    fn handle(&self, event: &dyn DataEvent, flow: *const ()) {
        // cc :187 the override body IS the inherent face (explicit self-call,
        // no autoref recursion ambiguity):
        RssLeaseHandler::handle(self, event, flow)
    }
    fn module_name(&self) -> &str {
        // cc :142 `module_name = module_label.c_str()` — answers through the
        // owned label copy (same bytes as the wrapped handler's name).
        &self.module_label
    }
    fn order(&self) -> u32 {
        self.order // cc :142 `order = inner_->order;`
    }
    fn live(&self) -> &AtomicBool {
        &self.live // the wrapper's OWN live cell (retire() cc :204)
    }
}

impl Drop for RssLeaseHandler {
    fn drop(&mut self) {
        // cc :145-:174: the borrow spin, then `delete inner` (the Box drop).
        // The spin runs WITHOUT the self-borrow (the Arc outlives the spin in
        // C via the registry pin — the borrow face IS the pin).
        let me: &RssLeaseHandler = self;
        me.drain_borrows();
        // Box<dyn DataHandler> drops here == cc :173 `delete inner;`
    }
}

// ---------------------------------------------------------------------------
// cc :238-:243 `struct Registry { std::mutex mtx; unordered_map<Inspector*,
// SurvivorState> entries; unordered_map<DedupKey, DedupEntry, DedupKeyHash>
// dedup; };` — Rust: the mutex wraps the two maps (the C member-mutex face).
// ---------------------------------------------------------------------------
struct Registry {
    entries: HashMap<usize, SurvivorState>,
    dedup: HashMap<DedupKey, DedupEntry, RssBuildHasher>,
}

// cc :245-:250 `static Registry& reg() { static Registry* const r = new
// Registry(); return *r; }` — "leaked singleton: registry must outlive every
// SnortConfig / DataBus at process exit". Rust: the OnceLock lazy face models
// the SAME lazy-init ordering; the leak is unnecessary (the static outlives
// every user; the process-exit teardown-ordering hazard the C leak dodges is
// Rust's static-drop contract instead — cited deviation).
static REG: OnceLock<Mutex<Registry>> = OnceLock::new();

fn reg() -> &'static Mutex<Registry> {
    REG.get_or_init(|| {
        Mutex::new(Registry {
            entries: HashMap::new(),
            dedup: HashMap::<DedupKey, DedupEntry, RssBuildHasher>::default(),
        })
    })
}

// survivor-id face: the C `Inspector*` map key identity -> BOTH data and
// vtable segments folded (a fat dyn ref is never ONE address): the
// identities NEVER print into the vectors (the %p args ride the data
// segment via cfmt's (nil)/hex face — pointer identity is NOT a vectors
// face; deviation cited in the module docs parity tripwires).
fn survivor_id(s: &dyn RssSurvivor) -> usize {
    // the DATA segment address == the C `Inspector*` value face; two live
    // survivors never share it (same liveness discipline as the C key).
    let p: *const dyn RssSurvivor = ptr::from_ref(s);
    p.cast::<()>().addr()
}

fn policy_seam_id(ip: &RssInspectionPolicy) -> usize {
    ptr::from_ref(ip).addr()
}

// cc :252-:279 `static void drain(RssLeaseHandler* leased, const char* phase)`
// — "blocks until leased is quiescent; seq_cst pairs with retire()
// (store-buffer)".
fn drain(leased: &RssLeaseHandler, phase: &str) {
    let started = Instant::now(); // cc :255
    let mut warns: u32 = 0; // cc :256
    loop {
        // cc :260 `const unsigned in_flight = leased->inflight.load(seq_cst);`
        let in_flight = leased.inflight.load(Ordering::SeqCst);
        if in_flight == 0 {
            return; // cc :262-:263
        }
        let elapsed = elapsed_ms(started); // cc :265
        // cc :267-:275 the warn_due arm; cc :274 `leased->warn_slow_wait(phase,
        // elapsed, in_flight, leased->borrow_count())` — the borrow_count arg
        // face bound var-first (R6).
        if warn_due(elapsed, warns) {
            if warns == 0 {
                RSS_STATS.slow_drains.fetch_add(1, Ordering::Relaxed); // cc :269-:270
            }
            warns += 1; // cc :272
            let held = leased.borrow_count();
            leased.warn_slow_wait(phase, elapsed, in_flight, held);
        }
        std::thread::yield_now(); // cc :277
    }
}

// cc :281-:300 `static void note_reconcile_deferral(Inspector& survivor,
// SurvivorState& state, const char* phase)` — the T6 deferral + the warn
// ladder face. The C `Inspector& survivor` rides the same (never-null)
// seam ref the entry points carry; the label rides survivor_name (the same
// null-api '<unknown>' arm the wrapper label face takes).
fn note_reconcile_deferral(survivor: &dyn RssSurvivor, state: &mut SurvivorState, phase: &str) {
    state.reconcile_deferrals += 1; // cc :284 `state.reconcile_deferrals++;`
    RSS_STATS.reconcile_deferrals.fetch_add(1, Ordering::Relaxed); // cc :285
    let elapsed = elapsed_ms(state.reconcile_started); // cc :287
    if !warn_due(elapsed, state.reconcile_warns) {
        return; // cc :289-:290 `if ( !warn_due(...) ) return;`
    }
    state.reconcile_warns += 1; // cc :292
    // cc :294-:299 the warn face; every arg var-first (R6). name = cc :297
    // `survivor_name(&survivor)`, %p = cc :297 `static_cast<const void*>(&survivor)`:
    let name_arg = survivor_name(Some(survivor));
    let p_arg = survivor_id(survivor) as u64;
    let args: [Arg<'_>; 8] = [
        Arg::S(Some(phase.into())),                    // cc :297 phase ("release"/"await_quiescent")
        Arg::S(Some(name_arg.into())),                 // cc :297 survivor_name(&survivor)
        Arg::U(p_arg),                                 // cc :297 `static_cast<const void*>(&survivor)`
        Arg::U(state.np_user_id),                      // cc :298 STDu64
        Arg::U(state.ip_user_id),                      // cc :298 STDu64
        Arg::U(state.reconcile_reload_id as u64),      // cc :298 `%u`
        Arg::U(elapsed),                               // cc :298 STDu64
        Arg::U(state.reconcile_deferrals),             // cc :298 STDu64
    ];
    warning_message(
        "RSS: %s deferred for survivor '%s' (%p) (network policy %lu, inspection policy %lu)\
         : reconciliation gate open on top of configuration %u for %lu ms over %lu deferral(s), awaiting rss_end_reconcile()\n",
        &args,
    );
}

// cc :302-:313 `static bool duplicate_subscription(Registry& r, const
// DedupKey& dk, const PubKey& pub, unsigned eid, const char* key)` — the C
// takes the non-const `Registry&` but the body only ever find()s (deviation:
// Rust tightens to `&Registry`, identical observable face).
fn duplicate_subscription(r: &Registry, dk: &DedupKey, pub_key: &PubKey, eid: u32, key: Option<&str>) -> bool {
    // cc :305-:307 `auto dup = r.dedup.find(dk); if ( dup == end() ) return false;`
    let Some(dup) = r.dedup.get(dk) else {
        return false;
    };
    // cc :309-:311 `if ( classify_dedup(dup->second.first, dup->second.second, pub, eid)
    // == DedupClass::MismatchTuple ) record_dedup_conflict(key);` — the
    // conflict record only touches the global pegs + the warn seam (the C
    // body is identical under the same lock).
    if classify_dedup(dup.0, dup.1, pub_key, eid) == DedupClass::MismatchTuple {
        record_dedup_conflict(key);
    }
    true // cc :312
}

// ===========================================================================
// THE WarningMessage global bridge (messages.h :58; see module docs for the
// LogEngine twin + the provider-queued default sink face).
// ===========================================================================

/// A warning sink: receives the cfmt-formatted text (the witness_rsubs.cc
/// `WarningMessage(...) { vsnprintf(wr_last_warn,...); wrwarn_calls++; }`
/// capture mirror shape for the parity replay).
pub trait WarningSink: Send + Sync {
    fn on_warning(&self, text: &str);
}

/// the provider-queued default: pull-site census ONLY, text dropped (the
/// 19a show_prompt precedent; the production sink lands with the log/config
/// rows — LogEngine::warning_message is the landed Rust twin the row 20/21
/// wiring will bridge).
struct DefaultWarnSink;
impl WarningSink for DefaultWarnSink {
    fn on_warning(&self, _text: &str) {}
}

static WARN_SINK: OnceLock<Box<dyn WarningSink>> = OnceLock::new();

/// Register the warning capture (harness mirror face); first registration
/// wins (idempotent; NEVER overwrites a landed provider).
pub fn set_warning_sink(sink: Box<dyn WarningSink>) {
    let _ = WARN_SINK.set(sink);
}

/// C `WarningMessage(const char* format, ...)` (messages.h :58) — the ported
/// call face formats through the LANDDED cfmt core (utils/cfmt.rs :159, the
/// same engine LogEngine::warning_message drives, messages.rs :371) and hands
/// the text to the registered sink.
pub fn warning_message(format: &str, args: &[Arg<'_>]) {
    let text = cfmt::cfmt(format, args);
    let sink = WARN_SINK.get_or_init(|| Box::new(DefaultWarnSink));
    sink.on_warning(&text);
}

// ===========================================================================
// impl.h public surface (namespace snort, impl.h :36-:154) + the cc-side
// definitions (cc :317-:379 `namespace snort { ... }`).
// ===========================================================================

/// impl.h :42-:58 `enum class RssPeg : size_t` — "order must match RssStats
/// and rss_pegs[] exactly" (:42 — the TRIPLE-coupling law; the harness PYPIN
/// asserts the exact 13-token enum order against the ground file).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum RssPeg {
    Installed = 0,                // impl.h :45
    Retired = 1,                  // impl.h :46
    BusDestroyed = 2,             // impl.h :47
    PolicyResolutionFailures = 3, // impl.h :48 (NEVER bumped by this row — module docs)
    ListReturned = 4,             // impl.h :49
    Stripped = 5,                 // impl.h :50
    DeadHandlerSkips = 6,         // impl.h :51
    Active = 7,                   // impl.h :52
    RegistryTracked = 8,          // impl.h :53
    DedupConflicts = 9,           // impl.h :54
    SlowDrains = 10,              // impl.h :55
    ReconcileDeferrals = 11,      // impl.h :56
    Count = 12,                   // impl.h :57 (the harness FACE-A `count=12`)
}

/// impl.h :60-:89 `struct RssStats` — "atomic, not thread-local: written from
/// both main and packet threads" (:60). `PegCount` is the landed u64 face
/// (framework/counts.rs :22); the C `std::atomic<PegCount>` NSDMI {0} faces
/// ride AtomicU64 cells (RssBuildHasher/landed type aliases face: AtomicU64
/// IS PegCount-sized on every supported target — the u64 face below the
/// field rows is the deviation cite; no AtomicPegCount alias exists).
pub struct RssStats {
    pub installed: AtomicU64,                 // impl.h :63
    pub retired: AtomicU64,                   // impl.h :64
    pub bus_destroyed: AtomicU64,             // impl.h :65
    pub policy_resolution_failures: AtomicU64, // impl.h :66 (field+slot land; bump sites = inspector_manager row)
    pub list_returned: AtomicU64,             // impl.h :67
    pub stripped: AtomicU64,                  // impl.h :68
    pub dead_handler_skips: AtomicU64,        // impl.h :69
    pub active: AtomicU64,                    // impl.h :70
    pub registry_tracked: AtomicU64,          // impl.h :71
    pub dedup_conflicts: AtomicU64,           // impl.h :72
    pub slow_drains: AtomicU64,               // impl.h :73
    pub reconcile_deferrals: AtomicU64,       // impl.h :74
}

impl RssStats {
    /// the NSDMI law face: every field `{0}` rides this const ctor (zero-init,
    /// const-constructible for the static below — a derived Default cannot
    /// seed the static const face).
    pub const fn new() -> RssStats {
        RssStats {
            installed: AtomicU64::new(0),
            retired: AtomicU64::new(0),
            bus_destroyed: AtomicU64::new(0),
            policy_resolution_failures: AtomicU64::new(0),
            list_returned: AtomicU64::new(0),
            stripped: AtomicU64::new(0),
            dead_handler_skips: AtomicU64::new(0),
            active: AtomicU64::new(0),
            registry_tracked: AtomicU64::new(0),
            dedup_conflicts: AtomicU64::new(0),
            slow_drains: AtomicU64::new(0),
            reconcile_deferrals: AtomicU64::new(0),
        }
    }

    /// impl.h :76-:88 `void reset()` — THE TWO-FIELD CARVE-OUT: ten
    /// `.store(0, relaxed)` calls in this EXACT order; `active` and
    /// `registry_tracked` are NEVER cleared (the FACE-A `CARVE` line; the
    /// harness PYPIN re-derives the 10-store count + the two absences from
    /// the ground file, and rss_reset_for_test :616-:617 stores THOSE SAME
    /// two explicitly).
    pub fn reset(&self) {
        self.installed.store(0, Ordering::Relaxed);                // impl.h :78
        self.retired.store(0, Ordering::Relaxed);                   // impl.h :79
        self.bus_destroyed.store(0, Ordering::Relaxed);             // impl.h :80
        self.policy_resolution_failures.store(0, Ordering::Relaxed); // impl.h :81
        self.list_returned.store(0, Ordering::Relaxed);             // impl.h :82
        self.stripped.store(0, Ordering::Relaxed);                  // impl.h :83
        self.dead_handler_skips.store(0, Ordering::Relaxed);        // impl.h :84
        // impl.h skips active (:70) and registry_tracked (:71) — the carve-out
        self.dedup_conflicts.store(0, Ordering::Relaxed);           // impl.h :85
        self.slow_drains.store(0, Ordering::Relaxed);               // impl.h :86
        self.reconcile_deferrals.store(0, Ordering::Relaxed);       // impl.h :87
    }
}

impl Default for RssStats {
    fn default() -> Self {
        Self::new()
    }
}

// impl.h :91 `extern RssStats rss_stats;` — the C global B-symbol; Rust static
// face (UPPER_SNAKE per the landed NULL_PARAMS/SIMPLE_PEGS item-name law in
// framework/module.rs; the C name identity rides this cite).
pub static RSS_STATS: RssStats = RssStats::new();

// impl.h :92 `extern const PegInfo rss_pegs[];` — DEFINED at cc :321-:338:
// 12 named rows + the `CountType::END, nullptr, nullptr` sentinel (:337).
// The null name/help slots ride "" (the landed sentinel-slot face, misc9
// four_pegs precedent). Row order == RssPeg order == RssStats field order
// (the :42 law).
pub const RSS_PEGS: [PegInfo; 13] = [
    PegInfo { peg_type: CountType::Sum, name: "rss_survivors_installed", help: "successful RSS handler subscribes" }, // cc :323
    PegInfo { peg_type: CountType::Sum, name: "rss_release_retired", help: "RSS handler subscriptions retired via release()" }, // cc :324
    PegInfo { peg_type: CountType::Sum, name: "rss_bus_destroyed", help: "on_bus_destroyed() invocations across all bus teardowns" }, // cc :325
    PegInfo { peg_type: CountType::Sum, name: "rss_policy_resolve_fail", help: "old policy unresolvable in new config on removal of an inspector with both policies" }, // cc :326-:327
    PegInfo { peg_type: CountType::Sum, name: "rss_list_returned", help: "total SurvivorView entries returned by list_survivors()" }, // cc :328
    PegInfo { peg_type: CountType::Sum, name: "rss_bus_stripped", help: "handler entries stripped in on_bus_destroyed()" }, // cc :329
    PegInfo { peg_type: CountType::Sum, name: "rss_dead_pub_skips", help: "publishes skipped due to dead RSS handler" }, // cc :330
    PegInfo { peg_type: CountType::Now, name: "rss_survivors_active", help: "live RSS handler registrations" }, // cc :331
    PegInfo { peg_type: CountType::Now, name: "rss_registry_tracked", help: "distinct survivor inspectors tracked in RSS registry" }, // cc :332
    PegInfo { peg_type: CountType::Sum, name: "rss_dedup_conflicts", help: "subscribe() key reused with a different (publisher, event)" }, // cc :333
    PegInfo { peg_type: CountType::Sum, name: "rss_slow_drains", help: "callback or borrow waits that outlived the slow-wait threshold" }, // cc :334
    PegInfo { peg_type: CountType::Sum, name: "rss_reconcile_deferrals", help: "release or quiescence requests deferred because reconciliation held the survivor" }, // cc :335-:336
    PegInfo { peg_type: CountType::End, name: "", help: "" }, // cc :337 `{ CountType::END, nullptr, nullptr }`
];

// cc :340-:341 `static_assert(std::size(rss_pegs) == static_cast<size_t>(
// RssPeg::Count) + 1, "rss_pegs[] must have exactly one entry per RssPeg
// enumerator, plus the CountType::END sentinel");` — the COMPILE-shape face
// (harness: the .o exists = it held; NEVER runtime):
const _: () = assert!(
    RSS_PEGS.len() == RssPeg::Count as usize + 1,
    "rss_pegs[] must have exactly one entry per RssPeg enumerator, plus the CountType::END sentinel"
);

/// cc :343-:363 `void rss_stats_to_pegcounts(const RssStats& stats, PegCount* out)`
/// — impl.h :94 "out must have at least RssPeg::Count elements" (C UB below
/// that; Rust indexes face-equivalent, the harness probe feeds out[16]; a
/// short slice panics = the honest Rust seam of the C UB). Every load
/// relaxed; the assignment ORDER rides the slot map (the FACE-A `SLOTMAP`
/// triple-coupling walk).
pub fn rss_stats_to_pegcounts(stats: &RssStats, out: &mut [PegCount]) {
    out[RssPeg::Installed as usize] = stats.installed.load(Ordering::Relaxed);          // cc :345
    out[RssPeg::Retired as usize] = stats.retired.load(Ordering::Relaxed);              // cc :346
    out[RssPeg::BusDestroyed as usize] = stats.bus_destroyed.load(Ordering::Relaxed);   // cc :347
    // cc :348-:349 (the PolicyResolutionFailures slot — NEVER bumped here, module docs)
    out[RssPeg::PolicyResolutionFailures as usize] = stats.policy_resolution_failures.load(Ordering::Relaxed);
    out[RssPeg::ListReturned as usize] = stats.list_returned.load(Ordering::Relaxed);   // cc :350
    out[RssPeg::Stripped as usize] = stats.stripped.load(Ordering::Relaxed);            // cc :351
    out[RssPeg::DeadHandlerSkips as usize] = stats.dead_handler_skips.load(Ordering::Relaxed); // cc :352-:353
    out[RssPeg::Active as usize] = stats.active.load(Ordering::Relaxed);                // cc :354
    out[RssPeg::RegistryTracked as usize] = stats.registry_tracked.load(Ordering::Relaxed); // cc :355-:356
    out[RssPeg::DedupConflicts as usize] = stats.dedup_conflicts.load(Ordering::Relaxed); // cc :357-:358
    out[RssPeg::SlowDrains as usize] = stats.slow_drains.load(Ordering::Relaxed);       // cc :359-:360
    out[RssPeg::ReconcileDeferrals as usize] = stats.reconcile_deferrals.load(Ordering::Relaxed); // cc :361-:362
}

/// impl.h :97-:101 `enum class DedupClass { SameTuple, MismatchTuple }` —
/// ordinals 0/1 (the FACE-A `DEDUP same=0 pub-mismatch=1 eid-mismatch=1`
/// face prints the casts).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum DedupClass {
    SameTuple = 0,     // impl.h :99
    MismatchTuple = 1, // impl.h :100
}

/// impl.h :103-:104 + cc :365-:371 `DedupClass classify_dedup(const char*
/// prior_publisher, unsigned prior_eid, const PubKey& pub, unsigned eid)`:
/// cc :368 `if ( prior_eid != eid or std::strcmp(prior_publisher, pub.publisher)
/// != 0 ) return DedupClass::MismatchTuple;` — the `or` SHORT-CIRCUIT order
//  rides `||` exactly (var-first: both sides are direct param reads); the C
/// strcmp content-compare rides the Rust &str equality (same truth; the
/// pub.publisher face is the landed PubKey str slot).
pub fn classify_dedup(prior_publisher: &str, prior_eid: u32, pub_key: &PubKey, eid: u32) -> DedupClass {
    if prior_eid != eid || pub_key.publisher != prior_publisher {
        return DedupClass::MismatchTuple; // cc :369
    }
    DedupClass::SameTuple // cc :370
}

/// impl.h :106 + cc :373-:378 `void record_dedup_conflict(const char* key)`:
/// peg bump THEN the warn; cc :377 `key ? key : ""` the null-key ternary face.
pub fn record_dedup_conflict(key: Option<&str>) {
    RSS_STATS.dedup_conflicts.fetch_add(1, Ordering::Relaxed); // cc :375
    let key_label = key.unwrap_or(""); // cc :377 `key ? key : ""`
    let args: [Arg<'_>; 1] = [Arg::S(Some(key_label.into()))];
    warning_message(
        "RSS: key '%s' reused with a different (publisher, event); dropping the new subscription\n",
        &args,
    ); // cc :376-:377 (the `'k5'`-style key substrings ride this face)
}

/// impl.h :108-:114 `struct RssSurvivorView { Inspector* survivor; uint64_t
/// np_user_id; uint64_t ip_user_id; }` — "one row per survivor inspector
/// tracked in the registry". The survivor slot rides the id face (pointer
/// provider queued).
#[derive(Clone, Copy, Debug)]
pub struct RssSurvivorView {
    pub survivor: usize, // C `Inspector* survivor` (id face)
    pub np_user_id: u64,
    pub ip_user_id: u64,
}

// ===========================================================================
// The ReloadSurvivorSubscriptions ctor face (inspector.h :224-:242 — the
// class DECL lives in inspector.h, NOT in impl.h; the cc DEFINES the ctor
// :381-:384 + subscribe :386-:445; `using Factory = std::function<DataHandler*()>`
// inspector.h :226).
// ===========================================================================

/// inspector.h :226 `using Factory = std::function<DataHandler*()>;` — the
/// user-code factory hand-off.
pub type Factory = fn() -> Option<Box<dyn DataHandler>>;

pub struct ReloadSurvivorSubscriptions<'a> {
    np: &'a RssNetworkPolicy,     // inspector.h :240 `NetworkPolicy& np`
    ip: &'a RssInspectionPolicy,  // inspector.h :241 `InspectionPolicy& ip`
    survivor: &'a dyn RssSurvivor, // inspector.h :242 `Inspector& survivor`
}

impl<'a> ReloadSurvivorSubscriptions<'a> {
    /// cc :381-:384 `ReloadSurvivorSubscriptions::ReloadSurvivorSubscriptions(
    /// NetworkPolicy& np_, InspectionPolicy& ip_, Inspector& survivor_)
    /// : np(np_), ip(ip_), survivor(survivor_) { }` — the reference-member
    /// init list face. (inspector.h :231-:232 the copy-dtor law: Rust owns
    /// refs; no Copy/Clone derive lands.)
    pub fn new(np: &'a RssNetworkPolicy, ip: &'a RssInspectionPolicy, survivor: &'a dyn RssSurvivor) -> Self {
        ReloadSurvivorSubscriptions { np, ip, survivor }
    }

    /// cc :386-:445 `void ReloadSurvivorSubscriptions::subscribe(const char*
    /// key, const PubKey& pub, unsigned eid, Factory factory)`.
    pub fn subscribe(&self, key: Option<&str>, pub_key: &PubKey, eid: u32, factory: Factory) {
        // cc :389 `DedupKey dk{ &survivor, &ip, key ? key : "" };` — the
        // null-key ternary -> "" face lands VAR-first.
        let dk = DedupKey {
            survivor: survivor_id(self.survivor),
            target_ip: policy_seam_id(self.ip),
            key: key.unwrap_or("").to_string(),
        };
        let r = reg(); // cc :390 `Registry& r = reg();`

        // cc :392-:397 "skip the user factory entirely for a duplicate the
        // registry already knows" — the scoped lock_guard face:
        {
            let r = r.lock().unwrap_or_else(|e| e.into_inner());
            if duplicate_subscription(&r, &dk, pub_key, eid, key) {
                return; // cc :395-:396
            }
        }

        // cc :399-:403 "construct outside the lock: factory is user code and
        // may re-enter RSS" — `DataHandler* h = factory(); if ( !h ) return;`
        let Some(h) = factory() else {
            return;
        };

        // cc :405-:438 the second scoped lock with the re-entrant re-check.
        let mut duplicate = false; // cc :405 `bool duplicate = false;`
        {
            let mut r = r.lock().unwrap_or_else(|e| e.into_inner());

            // cc :409-411 `// factory() may have registered the key
            // re-entrantly; re-check`
            if duplicate_subscription(&r, &dk, pub_key, eid, key) {
                duplicate = true; // cc :410-:411
            } else {
                // cc :414 `const bool new_entry = (r.entries.find(&survivor)
                // == r.entries.end());`
                let sid = survivor_id(self.survivor);
                let new_entry = !r.entries.contains_key(&sid);
                // cc :415 `SurvivorState& state = r.entries[&survivor];`
                let bus_seam = self.ip.bus; // policy.h :163 the by-value dbus member face
                let bus_id = bus_seam.bus_id();

                let leased = Arc::new(RssLeaseHandler::new(
                    h,
                    &dk.key, // cc :417 `dk.key`
                    Some(self.survivor),
                    self.np.user_policy_id, // cc :418 `np.user_policy_id`
                    self.ip.user_policy_id, // cc :418 `ip.user_policy_id`
                ));

                // cc :420 `ip.dbus._subscribe(pub, eid, leased);` — THE
                // friend-unlock site the harness sed-pins; the bus seam face.
                bus_seam.rss_subscribe(pub_key, eid, &leased);

                // cc :422 `r.dedup.emplace(dk, DedupEntry{ pub.publisher, eid });`
                r.dedup.insert(dk.clone(), (pub_key.publisher, eid));

                // cc :424 `state.handlers.push_back({ &ip, &ip.dbus, dk.key, leased });`
                // borrow split: the state below through the entries map again.
                let state = r.entries.entry(sid).or_default();
                state
                    .handlers
                    .push(HandlerEntry { target_ip: policy_seam_id(self.ip), bus: bus_id, key: dk.key.clone(), handler: leased });

                // cc :426-:431 the ids-init once face
                if !state.ids_initialized {
                    state.np_user_id = self.np.user_policy_id;
                    state.ip_user_id = self.ip.user_policy_id;
                    state.ids_initialized = true;
                }

                // cc :433-:436 the peg ladder (installed, active, then the
                // new_entry tracker bump) — var order rides ground lines.
                RSS_STATS.installed.fetch_add(1, Ordering::Relaxed);
                RSS_STATS.active.fetch_add(1, Ordering::Relaxed);
                if new_entry {
                    RSS_STATS.registry_tracked.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // cc :440-:444 `if ( duplicate ) { // never registered, and user dtors
        // must not run under the registry lock
        //   delete h; }` — Rust: the Box dropped at the else-branch boundary
        // already; the comment face records the outside-the-lock law.
        let _ = duplicate;
    }
}

// ===========================================================================
// cc :447-:607 `namespace snort { ... }` — the lifecycle entry points
// (impl.h :116-:131 decls).
// ===========================================================================

/// impl.h :116-:117 + cc :450-:496 `bool rss_release(Inspector& survivor)` —
/// "returns false if reconcile_map() still owns this survivor".
pub fn rss_release(survivor: &dyn RssSurvivor) -> bool {
    let sid = survivor_id(survivor);
    let mut to_drain: Vec<Arc<RssLeaseHandler>> = Vec::new(); // cc :452

    {
        let r = reg();
        let mut r = r.lock().unwrap_or_else(|e| e.into_inner()); // cc :456 lock_guard

        // cc :458-:461 `auto it = r.entries.find(&survivor); if ( it == end() ) return true;`
        if !r.entries.contains_key(&sid) {
            return true;
        }

        // cc :463-:467 the reconcile GATE (the T6 deferral face):
        if r.entries[&sid].reconciling {
            let state = r.entries.get_mut(&sid).unwrap();
            note_reconcile_deferral(survivor, state, "release");
            return false;
        }

        // cc :469 `to_drain.reserve(it->second.handlers.size());`
        to_drain.reserve(r.entries[&sid].handlers.len());

        // cc :471-:483 the retire loop:
        //   leased = static_cast<RssLeaseHandler*>(e.handler);
        //   leased->retire(); leased->borrow();  // pin alive across the unlocked drain()
        //   to_drain.push_back(leased);
        //   DedupKey dk{ &survivor, e.target_ip, e.key }; r.dedup.erase(dk);
        //   retired++; active--; (both relaxed)
        // Vec::take face keeps the borrow split legal (the same elements move
        // out; the order face rides std::vector iteration).
        let handlers = std::mem::take(&mut r.entries.get_mut(&sid).unwrap().handlers);
        for e in handlers {
            let leased = &e.handler;
            leased.retire(); // cc :474
            leased.borrow(); // cc :475 "pin alive across the unlocked drain() below"
            to_drain.push(leased.clone()); // cc :476 (C push_back -> Vec::push)
            let dk = DedupKey { survivor: sid, target_ip: e.target_ip, key: e.key.clone() }; // cc :478
            r.dedup.remove(&dk); // cc :479 erase
            RSS_STATS.retired.fetch_add(1, Ordering::Relaxed); // cc :481
            RSS_STATS.active.fetch_sub(1, Ordering::Relaxed); // cc :482
        }

        // cc :485-:486 `r.entries.erase(it); rss_stats.registry_tracked.fetch_sub(1, relaxed);`
        r.entries.remove(&sid);
        RSS_STATS.registry_tracked.fetch_sub(1, Ordering::Relaxed);
    } // cc :487 "lock released before drain()"

    // cc :489-:493 `for ( auto* leased : to_drain ) { drain(leased, "release");
    // leased->unborrow(); }`
    for leased in &to_drain {
        drain(leased, "release");
        leased.unborrow();
    }

    true // cc :495
}

/// impl.h :119-:121 + cc :498-:534 `bool rss_await_quiescent(Inspector&
/// survivor)` — "Drain callbacks already executing for this survivor without
/// retiring its subscriptions; this does not stop later dispatch."
pub fn rss_await_quiescent(survivor: &dyn RssSurvivor) -> bool {
    let sid = survivor_id(survivor);
    let mut to_drain: Vec<Arc<RssLeaseHandler>> = Vec::new(); // cc :500

    {
        let r = reg();
        let mut r = r.lock().unwrap_or_else(|e| e.into_inner()); // cc :504

        if !r.entries.contains_key(&sid) {
            return true; // cc :508-:509
        }
        if r.entries[&sid].reconciling {
            // cc :511-:515 the gate face, phase "await_quiescent"
            let state = r.entries.get_mut(&sid).unwrap();
            note_reconcile_deferral(survivor, state, "await_quiescent");
            return false;
        }
        to_drain.reserve(r.entries[&sid].handlers.len()); // cc :517

        // cc :519-:524 the BORROW-ONLY loop (no retirement here):
        //   leased->borrow(); to_drain.push_back(leased);
        for e in r.entries[&sid].handlers.iter() {
            let leased = &e.handler;
            leased.borrow(); // cc :522 "pin alive across the unlocked drain() below"
            to_drain.push(leased.clone()); // cc :523 (C push_back -> Vec::push)
        }
    } // cc :525 "lock released before drain(); no retirement here"

    // cc :527-:531 `drain(leased, "await_quiescent"); leased->unborrow();`
    for leased in &to_drain {
        drain(leased, "await_quiescent");
        leased.unborrow();
    }

    true // cc :533
}

/// impl.h :123 + cc :536-:568 `void rss_on_bus_destroyed(const DataBus*
/// dying_bus)`.
pub fn rss_on_bus_destroyed(dying_bus: Option<&dyn DataBusSubscribeSeam>) {
    // cc :538-:540 `// defensive: production callers (~DataBus) always pass
    // 'this'; guards test scaffolding
    // if ( !dying_bus ) return;`
    let Some(bus) = dying_bus else {
        return;
    };
    let dying_id = bus.bus_id();

    RSS_STATS.bus_destroyed.fetch_add(1, Ordering::Relaxed); // cc :542

    let r = reg();
    let mut r = r.lock().unwrap_or_else(|e| e.into_inner()); // cc :545

    // cc :547-568 "full scan and keep-entry are load-bearing: InspectionPolicy*
    // addresses can be reused after SnortConfig teardown, which would
    // false-hit dedup on next reload". The C shape: for each entry, the
    // std::remove_if + erase tail (ORDER-PRESERVING). The Rust face rebuilds
    // each handlers Vec in the same kept order; the lambda body (the cc
    // :555-:564 capture face) erases the dedup row and bumps the two pegs.
    let reg = &mut *r; // reborrow the guard for the split below (the C's
                       // single Mutex<Registry> lock face)
    let Registry { entries, dedup } = reg;
    for (sid, state) in entries.iter_mut() {
        let survivor = *sid; // cc :551 `Inspector* survivor = kv.first;`
        let mut kept: Vec<HandlerEntry> = Vec::new();
        for e in std::mem::take(&mut state.handlers) {
            if e.bus != dying_id {
                kept.push(e); // cc :558 `return false;` (keep)
                continue;
            }
            // cc :559-:563 the strip arm:
            let dk = DedupKey { survivor, target_ip: e.target_ip, key: e.key.clone() };
            dedup.remove(&dk);
            RSS_STATS.stripped.fetch_add(1, Ordering::Relaxed);
            RSS_STATS.active.fetch_sub(1, Ordering::Relaxed);
            // the stripped HandlerEntry (and its Arc) drops here at the end of
            // the loop iteration — the C keeps the leased alive on the bus
            // (the remove_if only drops the registry row), the Arc face keeps
            // any provider-side strong ref (the harness wr_last_handler
            // mirror) valid past the strip. ORDER: the Arc drop order is a
            // Rust-face deviation from the C raw-ptr row drop, never
            // vectors-observable.
        }
        state.handlers = kept; // cc :566 `handlers.erase(new_end, handlers.end());`
    }
}

/// impl.h :125 + cc :570-:597 `std::vector<RssSurvivorView>
/// rss_list_survivors(unsigned reload_id)`.
pub fn rss_list_survivors(reload_id: u32) -> Vec<RssSurvivorView> {
    let mut out: Vec<RssSurvivorView> = Vec::new(); // cc :572

    let r = reg();
    let mut r = r.lock().unwrap_or_else(|e| e.into_inner()); // cc :575
    out.reserve(r.entries.len()); // cc :576 `out.reserve(r.entries.size());`

    // cc :578-:593 the reconcile-GATE OPENER face (T5/T6):
    for (sid, state) in r.entries.iter_mut() {
        if !state.ids_initialized {
            continue; // cc :580-:581
        }
        if !state.reconciling {
            // cc :585-:589 the five stores IN ORDER:
            state.reconciling = true;
            state.reconcile_started = Instant::now();
            state.reconcile_reload_id = reload_id;
            state.reconcile_deferrals = 0;
            state.reconcile_warns = 0;
        }
        out.push(RssSurvivorView {
            survivor: *sid, // cc :592 `kv.first` (id face)
            np_user_id: state.np_user_id,
            ip_user_id: state.ip_user_id,
        });
    }

    // cc :595 `rss_stats.list_returned.fetch_add(out.size(), relaxed);`
    RSS_STATS.list_returned.fetch_add(out.len() as u64, Ordering::Relaxed);
    out // cc :596
}

/// impl.h :127-:129 + cc :599-:607 `void rss_end_reconcile(Inspector&
/// survivor)` — "must be called exactly once for every entry
/// rss_list_survivors(reload_id) returns, or that survivor's teardown stalls
/// forever."
pub fn rss_end_reconcile(survivor: &dyn RssSurvivor) {
    let sid = survivor_id(survivor);
    let r = reg();
    let mut r = r.lock().unwrap_or_else(|e| e.into_inner()); // cc :602
    // cc :604-:606 `auto it = ...; if ( it != end() ) it->second.reconciling = false;`
    if let Some(state) = r.entries.get_mut(&sid) {
        state.reconciling = false;
    }
}

/// impl.h :131 + cc :609-:622 `void rss_reset_for_test()`.
pub fn rss_reset_for_test() {
    let r = reg();
    let mut r = r.lock().unwrap_or_else(|e| e.into_inner()); // cc :612
    r.entries.clear(); // cc :613
    r.dedup.clear(); // cc :614

    // cc :616-:617 the reset()-CARVE-OUT counterpart: rss_reset_for_test
    // stores EXACTLY the two fields reset() leaves alone:
    RSS_STATS.active.store(0, Ordering::Relaxed);
    RSS_STATS.registry_tracked.store(0, Ordering::Relaxed);

    // cc :619-:621 `#ifdef UNIT_TEST forced_elapsed_ms.store(0, relaxed); #endif`
    FORCED_ELAPSED_MS.store(0, Ordering::Relaxed); // the clock-seam clear (Rust unconditional face)
}

/// impl.h :133-:135 + cc :624-:629 `#ifdef UNIT_TEST void
/// rss_set_elapsed_for_test(uint64_t ms)` — the def line rides ground cc
/// :625 EXACTLY (the harness sed-pin; the NEXT ':619-:624 region' cite is
/// the DRIFT face, DISK WINS): the tier-1 59999ms vectors arm (T8b) drives
/// this face; 0 restores the real clock (cc :56 `zero means use the real
/// clock`). cargo-cfg face: landed unconditionally, the production build
/// never calls it (module docs).
pub fn rss_set_elapsed_for_test(ms: u64) {
    FORCED_ELAPSED_MS.store(ms, Ordering::Relaxed); // cc :627
}

// ===========================================================================
// impl.h :137-:152 `class SurvivorFlowData : public FlowData` — THE DECL-ONLY
// mirror face (module docs top): "pins a survivor Inspector alive across
// mid-flow gadget rebinds" (:137), `explicit SurvivorFlowData(Inspector*
// pin);` (:141), `void add_pin(Inspector* pin);` (:144 "idempotent: adding an
// already-held pin is a no-op"), `static unsigned get_flow_data_id() { return
// flow_data_id; }` (:147), `private: std::vector<Inspector*> pinned; static
// unsigned flow_data_id;` (:150-:151). DEFINED ONLY in survivor_flow_data.cc
// (row 21b/P3 provider NOT landed; harness nm census: EXACTLY-0
// SurvivorFlowData pulls from the row .o). ZERO reachable arm in THIS row
// touches it -> ZERO Rust type, ZERO stand-in (never-invent law).
// ===========================================================================
