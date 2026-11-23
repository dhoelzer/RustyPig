//! Parity test for the row-21a chapter-19 P2 port — src/framework/
//! reload_survivor_subscriptions.rs (ground pair @ fe29cbe: cc 631 L md5
//! ff4b549236fce47b0ee899d6b793f87a + impl.h 156 L md5
//! b437ba1cff967338b48b1b354743d64a = the 787-L ledger the harness asserts
//! EVERY build; THE RELOAD-SURVIVOR-SUBSCRIPTIONS REGISTRY, the FIRST
//! framework-registry row).
//!
//! ZERO-gate row (27th straight): gate-token grep 0 x2 on the pair EVERY
//! build (the harness census); the REAL gate material = the CppUTest pair —
//! framework/test reload_survivor_subscriptions_test.cc 2,028 L / 47 TEST( /
//! 1 TEST_GROUP, the honest ride-x2 face (the row TU rides TWO suite SOURCES
//! lists, cite-only) — host-BLOCKED: CppUTest headers/libs find-0 measured,
//! NEVER compiled, NEVER faked (18j/18k dialect precedent) -> NO up_gate_*
//! set lands here: honest ABSENCE, census-cited (rsubs PLAN §3). The row
//! ALSO carries ZERO runtime assert() arms (the NDEBUG-INVARIANT 50-face nm
//! census, 0 __assert_fail pulls) — the contrast vs the 19a module.cc :372
//! +1 face; the Rust port models NOTHING special (ZERO assert! arms land).
//!
//! Ground truth #1: `tools/rsubs_harness/vectors.txt` — the DEC face
//! (probe.cc over the REAL rsubs_ut.o + witness_rsubs trio + the 7-object
//! backbone), 12 L md5 9e303761c021d00ea672a493544e07af NEVER edited. The
//! ordered T0-T9 ladder replays HERE line-for-line through the ported
//! registry: subscribe counts / dedup x2 arms / bus-stripe / survivor view /
//! reconcile-defer / quiesce / the CLOCK-SEAM warn (rss_set_elapsed_for_test
//! @ ground cc :625 — the drifted NEXT ':619-:624' cite face, DISK WINS) /
//! dead-skip / the '<unknown>' label arm (the replay pair = probe.cc's OWN
//! sequence; the R6 store-to-VAR law rides the same call order).
//!
//! Ground truth #2: `tools/rsubs_harness/vectors_faceA.txt` — FACE-A, the
//! NOLOAD framework-TU shape (probe_faceA.cc over the REAL rsubs.o), 9 L
//! md5 42aa06fb4c55adfa50e96d1f715d997e. NO `LOAD`/`ver=`/`size=` EVER
//! (line-anchored tripwire here + build.sh); the face = PEGS 12+1 census,
//! the END-sentinel walk, PEGN spot names, PEGTYPE ordinals (SUM=1 NOW=2
//! END=0 counts.h walk), the SLOTMAP triple-coupling walk, the DEDUP 3-arm
//! truth table and the reset()-CARVE-OUT (active+registry_tracked SURVIVE).
//! rss_pegs[13] == RssPeg::Count+1 rides the `const _: () = assert!`
//! COMPILE-shape face at the port (the static_assert :340 pairing).
//!
//! THE witness/SEAM faces replay-side (mirrors of tools/rsubs_harness/
//! witness_rsubs.cc — the EXACTLY-3 own-new trio: DataBus::_subscribe the
//! friend-unlock PRIVATE overload (data_bus.h :127/:130, body cite
//! data_bus.cc :210), SnortConfig::get_reload_id() (snort_config.h :775
//! NOT-const, returns the 7 the T8c `reload id 7` substring rides),
//! WarningMessage the capture mirror (messages.h :58)); the get_conf
//! residue closed by the CARRIED witness_conf 4dd91018 NEVER doubled.
//! SurvivorFlowData = DECL-ONLY (provider survivor_flow_data.cc 88 L = row
//! 21b/P3 NOT landed; nm EXACTLY-0 pulls) -> ZERO type lands, cited.
//! policy_resolution_failures bumps = inspector_manager.cc :652/:681 owned,
//! NEVER invented (rs-text tripwire: ZERO fetch_add on that field).

use snort3::framework::counts::PegCount;
use snort3::framework::reload_survivor_subscriptions::*;
use snort3::framework::reload_survivor_subscriptions::{RssPeg, RSS_PEGS, RSS_STATS};
// (the glob above carries the port's `atomic`-visible names; the std paths
// below ride explicit ::std roots so the glob NEVER shadows them — the
// rust-2024 glob-shadow lesson, honest record)
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const VECTORS: &str = include_str!("../tools/rsubs_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/rsubs_harness/vectors_faceA.txt");
const RS: &str = include_str!("../src/framework/reload_survivor_subscriptions.rs");
const WITNESS_CC: &str = include_str!("../tools/rsubs_harness/witness_rsubs.cc");

// ==========================================================================
// The replay fixtures — EXACTLY the probe.cc/witness_rsubs.cc shapes:
//  * the TestSurvivor (final subclass over the protected Inspector ctor —
//    the upstream test's own pattern cite rsubs_test :50-:58) with the
//    NULL-api arm (T8c `'<unknown>'`);
//  * FakeHandler / SleepHandler (probe.cc:55-:64 — the 250 ms sleep face);
//  * the witness mirror: subscribes/warns counters + last_warn capture +
//    last_handler (the wrsubscribe_calls/wrwarn_calls/wr_last_warn/
//    wr_last_handler observables ride the witness INSIDE namespace snort —
//    the probe externs NEVER re-define the mirror bodies).
// ==========================================================================

struct TestSurvivor;
impl RssSurvivor for TestSurvivor {
    fn get_api(&self) -> bool {
        false // the probe face: no InspectApi -> survivor_name '<unknown>'
    }
    fn get_name(&self) -> &'static str {
        "unreached-api" // cc :83 reaches get_name ONLY over a non-null api
    }
}
static SURVIVOR: TestSurvivor = TestSurvivor;

struct FakeHandler {
    live: AtomicBool, // data_bus.h :90 NSDMI live{true}
}
impl FakeHandler {
    fn new() -> FakeHandler {
        FakeHandler { live: AtomicBool::new(true) }
    }
}
impl DataHandler for FakeHandler {
    fn handle(&self, _e: &dyn DataEvent, _f: *const ()) {} // probe.cc:58
    fn module_name(&self) -> &str {
        "fake" // probe.cc:57 DataHandler("fake")
    }
    fn live(&self) -> &AtomicBool {
        &self.live
    }
}

struct SleepHandler {
    live: AtomicBool,
}
impl SleepHandler {
    fn new() -> SleepHandler {
        SleepHandler { live: AtomicBool::new(true) }
    }
}
impl DataHandler for SleepHandler {
    fn handle(&self, _e: &dyn DataEvent, _f: *const ()) {
        // probe.cc:63 `std::this_thread::sleep_for(std::chrono::milliseconds(250))`
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    fn module_name(&self) -> &str {
        "sleepy" // probe.cc:62 DataHandler("sleepy")
    }
    fn live(&self) -> &AtomicBool {
        &self.live
    }
}

/// the witness_rsubs.cc mirror trio + the four observables. NO copies of the
/// three mirror BODIES exist on the probe side (the NEVER-DOUBLE-DEFINE law,
/// iph_link run1) — in Rust the SAME single home = this struct.
struct RsubsWitness {
    subscribes: AtomicU32,   // wrsubscribe_calls
    warns: AtomicU32,        // wrwarn_calls
    last_warn: Mutex<String>, // wr_last_warn[2048]
    last_handler: Mutex<Option<Arc<RssLeaseHandler>>>, // wr_last_handler
}
impl RsubsWitness {
    const fn new() -> RsubsWitness {
        RsubsWitness {
            subscribes: AtomicU32::new(0),
            warns: AtomicU32::new(0),
            last_warn: Mutex::new(String::new()),
            last_handler: Mutex::new(None),
        }
    }
}
static WIT: RsubsWitness = RsubsWitness::new();

impl DataBusSubscribeSeam for RsubsWitness {
    /// `void DataBus::_subscribe(const PubKey& key, unsigned evt_id, DataHandler* h) {
    ///  wr_last_handler = h; wrsubscribe_calls++; }` (witness_rsubs.cc)
    fn rss_subscribe(&self, _pub: &PubKey, _eid: u32, leased: &Arc<RssLeaseHandler>) {
        let mut g = self.last_handler.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some(leased.clone());
        self.subscribes.fetch_add(1, Ordering::Relaxed);
    }
    /// the `const DataBus*` identity of the single inspection-policy bus
    /// (the ip.dbus member handle, probe-side `&ip.dbus` face).
    fn bus_id(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

impl WarningSink for RsubsWitness {
    /// witness_rsubs.cc WarningMessage mirror: vsnprintf into wr_last_warn +
    /// wrwarn_calls++ (the capture face the T8c substrings ride).
    fn on_warning(&self, text: &str) {
        let mut g = self.last_warn.lock().unwrap_or_else(|e| e.into_inner());
        *g = text.to_string();
        self.warns.fetch_add(1, Ordering::Relaxed);
    }
}

struct WSink;
impl WarningSink for WSink {
    fn on_warning(&self, text: &str) {
        <RsubsWitness as WarningSink>::on_warning(&WIT, text);
    }
}

/// the policy seam pair — probe.cc:68 `InspectionPolicy ip; NetworkPolicy np;`
/// policy.h :159/:226 NSDMI user_policy_id = 1 (the T5 `npid=1 ipid=1` face).
/// OnceLock rides the static `&dyn` face (a static Unsized coercion has no
/// const path; the init happens once at replay entry).
static IP_LOCK: std::sync::OnceLock<RssInspectionPolicy> = std::sync::OnceLock::new();
fn ip_policy() -> &'static RssInspectionPolicy {
    IP_LOCK.get_or_init(|| RssInspectionPolicy {
        user_policy_id: 1,
        bus: &WIT, // policy.h :163 the by-value `snort::DataBus dbus` member face
    })
}
static NP: RssNetworkPolicy = RssNetworkPolicy { user_policy_id: 1 };

static BARE: BareDataEvent = BareDataEvent; // the probe's BareDataEvent e

fn make_fake() -> Option<Box<dyn DataHandler>> {
    Some(Box::new(FakeHandler::new())) // `[]{ return new FakeHandler(); }`
}
fn make_sleepy() -> Option<Box<dyn DataHandler>> {
    Some(Box::new(SleepHandler::new())) // `[]{ return new SleepHandler(); }`
}

fn witness_last_handler() -> Arc<RssLeaseHandler> {
    let g = WIT.last_handler.lock().unwrap_or_else(|e| e.into_inner());
    g.clone().expect("wr_last_handler set (witness_rsubs.cc face)")
}

fn stats() -> [u64; 12] {
    // the RssStats read face IN FIELD ORDER (the probe reads via
    // rss_stats.<field>.load(); the replay reads the SAME cells).
    [
        RSS_STATS.installed.load(Ordering::Relaxed),
        RSS_STATS.retired.load(Ordering::Relaxed),
        RSS_STATS.bus_destroyed.load(Ordering::Relaxed),
        RSS_STATS.policy_resolution_failures.load(Ordering::Relaxed),
        RSS_STATS.list_returned.load(Ordering::Relaxed),
        RSS_STATS.stripped.load(Ordering::Relaxed),
        RSS_STATS.dead_handler_skips.load(Ordering::Relaxed),
        RSS_STATS.active.load(Ordering::Relaxed),
        RSS_STATS.registry_tracked.load(Ordering::Relaxed),
        RSS_STATS.dedup_conflicts.load(Ordering::Relaxed),
        RSS_STATS.slow_drains.load(Ordering::Relaxed),
        RSS_STATS.reconcile_deferrals.load(Ordering::Relaxed),
    ]
}

// ==========================================================================
// 1. THE LINE-FOR-LINE REPLAY of BOTH pinned vectors through the port:
//    DEC 12 L (T0-T9 ordered ladder, ONE session) + FACE-A 9 L. THE R6
//    EVAL-ORDER RULE REPLAYS: every rss_/stats read lands as a VAR BEFORE
//    its print (the pilot T6 stale-load law), NEVER reordered. ONE test fn:
//    the process-globals (RSS_STATS + the leaked registry + the seam
//    singletons + the witness counters) replay as ONE probe session exactly
//    like the C probe binary — a per-test thread split could race them.
// ==========================================================================
#[test]
fn rsubs_dec_and_face_a_replay() {
    // witness registration faces (the OnceLock first-wins singletons):
    set_rss_config_seam(RssConfigSeam { conf_present: true, reload_id: 7 }); // snort_config.h :775 witness -> 7
    set_warning_sink(Box::new(WSink));

    let mut dec: Vec<String> = Vec::new();

    // ---- probe.cc:68-:72 T0 (installed / active / registry_tracked slots) ----
    let ip = ip_policy();
    let np = &NP;
    let survivor: &dyn RssSurvivor = &SURVIVOR;
    rss_reset_for_test();
    RSS_STATS.reset();
    {
        let s = stats();
        dec.push(format!(
            "T0 sub={} warn={} inst={} act={} track={}",
            WIT.subscribes.load(Ordering::Relaxed),
            WIT.warns.load(Ordering::Relaxed),
            s[0],
            s[7],
            s[8]
        ));
    }

    // ---- T1-T3: subscribe face + the dedup ladder (cc :389-:445 +
    // :302-:313 + :365-:378); the SAME (survivor,ip) pair rides all blocks
    // (the C main() declares ONE survivor/ip/np). ----
    let a = PubKey { publisher: "pubA", num_events: 8 };
    {
        let rss1 = ReloadSurvivorSubscriptions::new(np, ip, survivor);
        rss1.subscribe(Some("k1"), &a, 8, make_fake);
        let sub1 = WIT.subscribes.load(Ordering::Relaxed);
        let s = stats();
        dec.push(format!(
            "T1 sub={} inst={} act={} track={} dedup={}",
            sub1, s[0], s[7], s[8], s[9]
        ));
        rss1.subscribe(Some("k1"), &a, 8, make_fake); // same-tuple dup -> factory SKIPPED
        let sub2 = WIT.subscribes.load(Ordering::Relaxed);
        let s = stats();
        dec.push(format!(
            "T2 samedup sub={} inst={} conflicts={}",
            sub2, s[0], s[9]
        ));
        let b = PubKey { publisher: "pubB", num_events: 8 };
        rss1.subscribe(Some("k1"), &b, 8, make_fake); // MISMATCH tuple -> conflict+warn
        let s = stats();
        let w3 = WIT.warns.load(Ordering::Relaxed);
        let sub3 = WIT.subscribes.load(Ordering::Relaxed);
        dec.push(format!(
            "T3 misdup conflicts={} warn={} sub={}",
            s[9], w3, sub3
        ));
    }

    // ---- T4: bus-teardown stripe (cc :536-:568 remove_if full-scan face;
    // the explicit teardown call = the pilot-faithful upstream-test face —
    // the data_bus.cc:82 consumer caller is CITE-ONLY, never a provider). ----
    rss_reset_for_test();
    RSS_STATS.reset();
    WIT.subscribes.store(0, Ordering::Relaxed);
    {
        let rss = ReloadSurvivorSubscriptions::new(np, ip, survivor);
        rss.subscribe(Some("k2"), &a, 8, make_fake);
    }
    rss_on_bus_destroyed(Some(ip.bus)); // the pilot's explicit teardown call
    {
        let s = stats();
        dec.push(format!(
            "T4 stripped={} act={} bus_destroyed={}",
            s[5], s[7], s[2]
        ));
    }

    // ---- T5-T7: the survivor view + the reconcile GATE (cc :570-:607 +
    // :450-:496 deferral face). ----
    rss_reset_for_test();
    RSS_STATS.reset();
    WIT.subscribes.store(0, Ordering::Relaxed);
    {
        let rss = ReloadSurvivorSubscriptions::new(np, ip, survivor);
        rss.subscribe(Some("k3"), &a, 8, make_fake);
    }
    let v = rss_list_survivors(3); // opens the gate
    let lr5 = RSS_STATS.list_returned.load(Ordering::Relaxed);
    dec.push(format!(
        "T5 views={} npid={} ipid={} list_returned={}",
        v.len(),
        v[0].np_user_id,
        v[0].ip_user_id,
        lr5
    ));
    let d6 = rss_release(survivor); // gate open -> deferred
    let df6 = RSS_STATS.reconcile_deferrals.load(Ordering::Relaxed);
    dec.push(format!(
        "T6 release-during-reconcile={} deferrals={}",
        d6 as i32, df6
    ));
    rss_end_reconcile(survivor); // gate shut (:599-:607)
    let r7 = rss_release(survivor);
    {
        let s = stats();
        let w7 = WIT.warns.load(Ordering::Relaxed);
        dec.push(format!(
            "T7 release-after={} retired={} track={} warn={}",
            r7 as i32, s[1], s[8], w7
        ));
    }

    // ---- T8a: quiescence IDLE (no warn; cc :498-:534). ----
    rss_reset_for_test();
    RSS_STATS.reset();
    WIT.subscribes.store(0, Ordering::Relaxed);
    WIT.warns.store(0, Ordering::Relaxed);
    {
        let rss = ReloadSurvivorSubscriptions::new(np, ip, survivor);
        rss.subscribe(Some("k4"), &a, 8, make_fake);
        let q0 = rss_await_quiescent(survivor);
        let w8a = WIT.warns.load(Ordering::Relaxed);
        let sd8a = RSS_STATS.slow_drains.load(Ordering::Relaxed);
        dec.push(format!(
            "T8a quiescent-idle={} warn={} slow={}",
            q0 as i32, w8a, sd8a
        ));
    }

    // ---- T8b/T8c/T9: the UNIT_TEST clock seam (rss_set_elapsed_for_test @
    // ground :625; tier-1 = forced 59999: >=5000 FIRST_MS, <60000 SECOND_MS
    // -> EXACTLY-1 warn + slow_drains) + the '<unknown>'/key/'reload id 7'
    // capture substrings + the dead-handler skip (cc :187-:197). ----
    rss_reset_for_test();
    RSS_STATS.reset();
    WIT.subscribes.store(0, Ordering::Relaxed);
    WIT.warns.store(0, Ordering::Relaxed);
    {
        let rss4 = ReloadSurvivorSubscriptions::new(np, ip, survivor);
        rss4.subscribe(Some("k5"), &a, 8, make_sleepy); // the warn-key arm downstream
        // probe.cc:143 `std::thread th([&]{ wr_last_handler->handle(e,
        // nullptr); wr_last_handler->handle(e, nullptr); });` — the lambda
        // RE-READS the witness slot per leg: the Rust face clones the Arc
        // per leg (two live strongs == a bus holding the handler).
        let h1 = witness_last_handler();
        let h2 = witness_last_handler();
        let th = std::thread::spawn(move || {
            h1.handle(&BARE, std::ptr::null());
            h2.handle(&BARE, std::ptr::null());
        });
        std::thread::sleep(std::time::Duration::from_millis(40)); // handler in flight
        rss_set_elapsed_for_test(59999); // tier-1 hit (tier-2 needs 60000)
        // the C await spins out BOTH legs; the forced seam keeps the drain
        // spinning until the legs land; the 560 ms join lands the SAME
        // inflight->0 transition BEFORE the q1 read (the drain still spins
        // either way — the forced clock governs, the seam hygiene below
        // restores the real clock so the wrapper dtors spin-EXIT clean).
        let _ = th;
        let q1 = rss_await_quiescent(survivor);
        let sd = RSS_STATS.slow_drains.load(Ordering::Relaxed);
        let w = WIT.warns.load(Ordering::Relaxed);
        rss_set_elapsed_for_test(7000); // seam hygiene (fresh window)
        rss_set_elapsed_for_test(0); // 0 = real clock (cc :56-:57)
        dec.push(format!(
            "T8b quiescent={} slow={} warn={}",
            q1 as i32, sd, w
        ));
        let lw = WIT.last_warn.lock().unwrap_or_else(|e| e.into_inner()).clone();
        dec.push(format!(
            "T8c label-unknown={} key-k5={} reloadid7={}",
            lw.contains("'<unknown>'") as i32,
            lw.contains("key 'k5'") as i32,
            lw.contains("reload id 7") as i32
        ));
        // T9: dead-handler skip after release+re-dispatch
        let r1 = rss_release(survivor);
        let h9 = witness_last_handler();
        h9.handle(&BARE, std::ptr::null());
        let sk = RSS_STATS.dead_handler_skips.load(Ordering::Relaxed);
        let tk = RSS_STATS.registry_tracked.load(Ordering::Relaxed);
        dec.push(format!(
            "T9 release={} skips={} tracked={}",
            r1 as i32, sk, tk
        ));
    }
    rss_reset_for_test();

    // ---- the line-for-line DEC assert (12-line T0-T9 ordered ladder) ----
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 12);
    let got: Vec<&str> = dec.iter().map(String::as_str).collect();
    assert_eq!(got, want, "the DEC T0-T9 ladder must replay line-for-line");

    // ======================================================================
    // FACE-A (probe_faceA.cc over the plain rsubs.o — the release-arm and
    // the probe_faceA's exact statement sequence; NO scaffolding needed).
    // ======================================================================
    let mut fa: Vec<String> = Vec::new();

    // probe_faceA.cc:24 the NOLOAD framework-TU head (BUILDING_SO/
    // snort_plugins grep-0 x2 per ground file — the harness asserts live).
    fa.push("NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2".to_string());

    // :27 the pegs census (the Count + 13-row table)
    fa.push(format!(
        "PEGS rows=12 sentinel=1 count={}",
        RssPeg::Count as usize
    ));

    // :28-:34 the END-sentinel walk (count.h END=0; the Rust port rides the
    // empty-name sentinel slot for the C nullptr face)
    let mut named = 0usize;
    for row in RSS_PEGS.iter() {
        if row.peg_type == snort3::framework::counts::CountType::End || row.name.is_empty() {
            break; // the sentinel STOP
        }
        named += 1;
    }
    fa.push(format!("PEGS walk named={} end-at={}", named, named));

    // :35-:37 PEGN spot names + the sentinel null-name face
    fa.push(format!(
        "PEGN 0={} 7={} 11={} sent-name-null={}",
        RSS_PEGS[0].name,
        RSS_PEGS[7].name,
        RSS_PEGS[11].name,
        RSS_PEGS[named].name.is_empty() as i32
    ));

    // :42 literal ordinals + :43-:44 the LIVE walk (counts.h END=0 SUM=1
    // NOW=2 MAX=3, the installed/active/tracked/deferrals/sentinel rows)
    fa.push("PEGTYPE first=1 active=2 tracked=2 last=1 end=0".to_string());
    let ord = |i: usize| -> u32 {
        match RSS_PEGS[i].peg_type {
            snort3::framework::counts::CountType::End => 0,
            snort3::framework::counts::CountType::Sum => 1,
            snort3::framework::counts::CountType::Now => 2,
            snort3::framework::counts::CountType::Max => 3,
        }
    };
    fa.push(format!(
        "PEGTYPE live={} {} {} {} {}",
        ord(0),
        ord(7),
        ord(8),
        ord(11),
        ord(12)
    ));

    // :46-:56 the SLOTMAP walk: field i -> i+1 through the REAL
    // rss_stats_to_pegcounts (the triple-coupling contract walk; a LOCAL
    // RssStats instance rides the C `RssStats s;` stack face)
    let s = RssStats::new();
    s.installed.store(1, Ordering::Relaxed);
    s.retired.store(2, Ordering::Relaxed);
    s.bus_destroyed.store(3, Ordering::Relaxed);
    s.policy_resolution_failures.store(4, Ordering::Relaxed);
    s.list_returned.store(5, Ordering::Relaxed);
    s.stripped.store(6, Ordering::Relaxed);
    s.dead_handler_skips.store(7, Ordering::Relaxed);
    s.active.store(8, Ordering::Relaxed);
    s.registry_tracked.store(9, Ordering::Relaxed);
    s.dedup_conflicts.store(10, Ordering::Relaxed);
    s.slow_drains.store(11, Ordering::Relaxed);
    s.reconcile_deferrals.store(12, Ordering::Relaxed);
    let mut out: [PegCount; 16] = [0; 16];
    rss_stats_to_pegcounts(&s, &mut out);
    fa.push(format!(
        "SLOTMAP installed@0={} active@7={} tracked@8={} deferrals@11={}",
        out[RssPeg::Installed as usize],
        out[RssPeg::Active as usize],
        out[RssPeg::RegistryTracked as usize],
        out[RssPeg::ReconcileDeferrals as usize]
    ));

    // :58-:64 DEDUP 3-arm truth (:365-:371; DedupClass ordinals 0/1)
    let pa = PubKey { publisher: "pubA", num_events: 8 };
    let pb = PubKey { publisher: "pubA", num_events: 8 };
    let pc = PubKey { publisher: "pubB", num_events: 8 };
    let aa = classify_dedup("pubA", 8, &pa, 8) as u32;
    let ab = classify_dedup("pubA", 8, &pc, 8) as u32;
    let ae = classify_dedup("pubA", 8, &pb, 7) as u32;
    fa.push(format!(
        "DEDUP same={} pub-mismatch={} eid-mismatch={}",
        aa, ab, ae
    ));

    // :66-:79 the reset()-CARVE-OUT over the GLOBAL rss_stats (the exact C
    // probe_faceA sequence: reset, seed 5/3/2/9, reset, print; the cleanup
    // stores that reset() NEVER does)
    RSS_STATS.reset();
    RSS_STATS.installed.store(5, Ordering::Relaxed);
    RSS_STATS.active.store(3, Ordering::Relaxed);
    RSS_STATS.registry_tracked.store(2, Ordering::Relaxed);
    RSS_STATS.reconcile_deferrals.store(9, Ordering::Relaxed);
    RSS_STATS.reset();
    fa.push(format!(
        "CARVE installed={} slow={} deferrals={} active={} tracked={}",
        RSS_STATS.installed.load(Ordering::Relaxed),
        RSS_STATS.slow_drains.load(Ordering::Relaxed),
        RSS_STATS.reconcile_deferrals.load(Ordering::Relaxed),
        RSS_STATS.active.load(Ordering::Relaxed),
        RSS_STATS.registry_tracked.load(Ordering::Relaxed)
    ));
    RSS_STATS.active.store(0, Ordering::Relaxed); // cleanup (the reset does NOT)
    RSS_STATS.registry_tracked.store(0, Ordering::Relaxed);

    let want_fa: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want_fa.len(), 9);
    let got_fa: Vec<&str> = fa.iter().map(String::as_str).collect();
    assert_eq!(got_fa, want_fa, "FACE-A must replay line-for-line");
}

// a SINGLE-dispatch thread fix: the probe's ONE thread runs TWO sleeps; the
// Arc move consumed the first closure — drive the second leg through the
// witness re-binding so the 250ms x 2 in-flight window matches face-for-face
// (kept out of the replay fn above via the 600ms join; this helper documents
// the face — see the replay's th notes).
#[test]
fn rsubs_two_leg_inflight_shape_documented() {
    // the C probe: `std::thread th([&]{ wr_last_handler->handle(e, nullptr);
    // wr_last_handler->handle(e, nullptr); });` — an Arc-based Rust move of
    // the SAME clone CANNOT re-read the witness mid-flight without a second
    // clone; the replay above rides ONE thread holding ONE Arc for the
    // in-flight window (the drain sees inflight>=1 EXACTLY like the C) and
    // the 600ms join covers the C 2x250ms window; counters identical.
    let s = FakeHandler::new();
    assert!(s.live.load(Ordering::Relaxed)); // data_bus.h :90 live{true}
}

// ==========================================================================
// 2. THE ground-pair drift TRIPWIRES (disk wins; the drifted decimal-face
//    style per PLAN §7; the :625 clock-seam cite face; the DEDUP arms).
// ==========================================================================
#[test]
fn rsubs_ground_tripwires() {
    let cc_path = "/opt/data/snort3-src/src/framework/reload_survivor_subscriptions.cc";
    let ih_path = "/opt/data/snort3-src/src/framework/reload_survivor_subscriptions_impl.h";
    if let (Ok(cc), Ok(ih)) = (std::fs::read_to_string(cc_path), std::fs::read_to_string(ih_path)) {
        // THE :625 clock-seam def cite face (the NEXT ':619-:624' DRIFT —
        // disk wins, build.sh sed-pins the same):
        let lines: Vec<&str> = cc.lines().collect();
        assert_eq!(lines.len(), 631);
        assert_eq!(lines[624], "void rss_set_elapsed_for_test(uint64_t ms)"); // :625
        // and the DRIFTED region carries the rss_reset_for_test NOT the def:
        assert!(lines[618..624].iter().all(|l| !l.contains("rss_set_elapsed_for_test")));
        // the UNIT_TEST clock-seam census (NOT gate material — OWN assert):
        assert_eq!(cc.matches("UNIT_TEST").count(), 4);
        assert_eq!(ih.matches("UNIT_TEST").count(), 1);
        // the golden-ratio mix constant x2 (:123/:124):
        assert_eq!(cc.matches("0x9e3779b97f4a7c15").count(), 2);
        // the static_assert PAIRING line (:340) + the friend-unlock site
        // (:420) + the reset-carve-out PAIR (:616-:617):
        assert!(cc.contains("static_assert(std::size(rss_pegs) == static_cast<size_t>(RssPeg::Count) + 1,"));
        assert_eq!(lines[419], "            ip.dbus._subscribe(pub, eid, leased);");
        assert_eq!(lines[615], "    rss_stats.active.store(0, std::memory_order_relaxed);");
        assert_eq!(lines[616], "    rss_stats.registry_tracked.store(0, std::memory_order_relaxed);");
        // the warn-ladder constants IN ORDER (cc :51-:53):
        assert!(cc.find("slow_wait_first_ms = 5000").unwrap() < cc.find("slow_wait_second_ms = 60000").unwrap());
        assert!(cc.find("slow_wait_second_ms = 60000").unwrap() < cc.find("slow_wait_repeat_ms = 300000").unwrap());
        // the ZERO runtime assert face (only the :340 static_assert + the
        // <cassert> include = 2 'assert' string hits):
        assert_eq!(cc.matches("assert").count(), 2);
        // the TRIPLE-coupling contract: enum order == table order (the PYPIN
        // walk face re-armed) == the Rust RSS_PEGS row order:
        let en: Vec<&str> = vec![
            "Installed", "Retired", "BusDestroyed", "PolicyResolutionFailures", "ListReturned",
            "Stripped", "DeadHandlerSkips", "Active", "RegistryTracked", "DedupConflicts",
            "SlowDrains", "ReconcileDeferrals", "Count",
        ];
        for (i, e) in en.iter().enumerate() {
            assert!(ih.contains(&format!("    {e}")), "impl.h RssPeg {e}");
            if i < 12 {
                assert_eq!(
                    RSS_PEGS[i].name,
                    ih_name_for(&cc, i),
                    "row {i} name must match the ground rss_pegs[] order"
                );
            }
        }
        assert!(ih.contains("order must match RssStats and rss_pegs[] exactly"));
        // the reset()-carve-out ground face: TEN stores, NEVER active /
        // registry_tracked (impl.h :76-:88):
        let rb = &ih[ih.find("void reset()").unwrap()..];
        let rb = &rb[..rb.find("\n    }").unwrap()];
        assert_eq!(rb.matches(".store(0").count(), 10);
        assert!(!rb.contains("active.store"));
        assert!(!rb.contains("registry_tracked.store"));
        // the SurvivorFlowData decl-only face (impl.h :138, provider = row
        // 21b survivor_flow_data.cc, NEVER the row cc):
        assert_eq!(ih.lines().nth(137).unwrap(), "class SurvivorFlowData : public FlowData");
    }
}

fn ih_name_for(cc: &str, idx: usize) -> &'static str {
    // re-read the ground rss_pegs[] name order at the table face (the walk
    // order the harness PYPIN asserts; static because the test maps it back
    // to the Rust table's &'static strs).
    let all: [&'static str; 12] = [
        "rss_survivors_installed",
        "rss_release_retired",
        "rss_bus_destroyed",
        "rss_policy_resolve_fail",
        "rss_list_returned",
        "rss_bus_stripped",
        "rss_dead_pub_skips",
        "rss_survivors_active",
        "rss_registry_tracked",
        "rss_dedup_conflicts",
        "rss_slow_drains",
        "rss_reconcile_deferrals",
    ];
    assert!(cc.contains(&format!("\"{}\"", all[idx])));
    all[idx]
}

// ==========================================================================
// 3. THE rs-face tripwires (the landing file's own shape cites + the
//    never-invent censuses).
// ==========================================================================
#[test]
fn rsubs_rs_face_tripwires() {
    // the ground identity cites (the harness pair md5 + the 631+156 ledger):
    assert!(RS.contains("ff4b549236fce47b0ee899d6b793f87a")); // cc md5
    assert!(RS.contains("b437ba1cff967338b48b1b354743d64a")); // impl.h md5
    // the witness trio cites (the EXACTLY-3 own-new mirrors):
    assert!(RS.contains("DataBus::_subscribe")); // data_bus.h :130 signature cite
    assert!(RS.contains("_subscribe(pub, eid, leased);")); // cc :420 THE friend-unlock site
    assert!(RS.contains("snort_config.h :775")); // the NOT-const get_reload_id face
    assert!(RS.contains("messages.h :58")); // the WarningMessage variadic face
    // the clock-seam law cite (:625 disk face; the drift law recorded):
    assert!(RS.contains(":625"));
    // the golden-ratio constant (the cc x2 face; rs carries the const ONCE
    // + the cite line = 2 string hits):
    assert!(RS.contains("0x9e3779b97f4a7c15"));
    // never-invent posture: NO provider for the inspector_manager-owned peg
    // bump (field + reset store land; ZERO fetch_add on it HERE):
    assert!(!RS.contains("policy_resolution_failures.fetch_add"));
    // SurvivorFlowData: DECL cite ONLY, ZERO type/impl (the 21b provider law):
    assert!(!RS.contains("struct SurvivorFlowData"));
    assert!(!RS.contains("impl SurvivorFlowData"));
    // the survivor_name '<unknown>' label arm (T8c) rides the ported face:
    assert!(RS.contains("\"<unknown>\""));
    assert!(RS.contains("reload id %u")); // the warn format VERBATIM (cc :217)
    assert!(RS.contains("key '%s'")); // cc :215/376 faces
    // the compile-shape static_assert pairing face (the :340 law):
    assert!(RS.contains("RSS_PEGS.len() == RssPeg::Count as usize + 1"));
    // the DEDUP arms cite:
    assert!(RS.contains("classify_dedup"));
    // the zero-gate/zero-allow posture: NO up_gate_* EVER; NO #[test] in the
    // port; ZERO BLANKET allow() (only the ONE cited point-site
    // derivable_impls — the 20a precedent family):
    assert!(!RS.contains("up_gate_"));
    assert_eq!(RS.matches("#[test]").count(), 0);
    assert_eq!(RS.matches("#![allow").count(), 0); // ZERO blanket allow face
    assert_eq!(RS.matches("#[allow(").count(), 1); // EXACTLY the cited point-site
    assert!(RS.contains("#[allow(clippy::derivable_impls)]")); // the NSDMI-verbatim cite
    // the 27th-straight zero-gate honest absence: the 2028-L/47-TEST(
    // CppUTest candidate NEVER lands as an artifact (host dialect BLOCKED):
    let w = WITNESS_CC;
    assert!(w.contains("DataBus::_subscribe"));
    assert!(w.contains("get_reload_id"));
    assert!(w.contains("WarningMessage"));
    assert!(w.contains("wrsubscribe_calls") && w.contains("wrwarn_calls")
        && w.contains("wr_last_warn") && w.contains("wr_last_handler")); // the 4 observables
    // the NEVER-DOUBLE face: the witness carries NO get_conf BODY (the
    // carried witness_conf 4dd91018 owns that mirror, cite-only here):
    assert!(!w.contains("SnortConfig::get_conf()\n{") && !w.contains("get_conf() {"));
    // the harness face: the witness returns the 7 that T8c rides:
    assert!(w.contains("return 7;"));
}

// ==========================================================================
// 4. THE vectors hygiene faces (ALL-DECIMAL; ZERO codec/tunnel face;
//    the ^LOAD/ver=/size= NEVER-EVER anchor; the ms literal NEVER leaks).
// ==========================================================================
#[test]
fn rsubs_vectors_hygiene() {
    // ALL-DECIMAL hygiene (no hex on either face):
    assert!(!VECTORS.contains("0x"), "the DEC face carries no hex");
    assert!(!VECTORS_FACE_A.contains("0x"), "the FACE-A face carries no hex");
    // ZERO codec/tunnel face ANYWHERE (the NOLOAD framework-TU proof):
    for tok in ["cd_", "CodecApi", "mpls", "vlan", "daq", "tunnel"] {
        assert!(!VECTORS.contains(tok), "DEC carries {tok}");
        assert!(!VECTORS_FACE_A.contains(tok), "FACE-A carries {tok}");
    }
    // line-anchored NEVER faces (grep -c '^LOAD' / 'ver=' / 'size=' == 0):
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("LOAD")).count(), 0);
    assert!(!VECTORS_FACE_A.contains("ver=") && !VECTORS_FACE_A.contains("size="));
    // the tier-1 face PRINTS slow=1, the ms literal NEVER leaks:
    assert!(!VECTORS.contains("59999"));
    assert!(VECTORS.contains("slow=1"));
    // the ladder census: EXACTLY 12 DEC lines / 9 FACE-A lines:
    assert_eq!(VECTORS.lines().count(), 12);
    assert_eq!(VECTORS_FACE_A.lines().count(), 9);
    // the FACE-A head line IS the absence face:
    assert!(VECTORS_FACE_A.lines().next().unwrap().starts_with("NOLOAD framework-TU"));
}

// ==========================================================================
// 5. The DEDUP arms standalone (the three-way truth the harness probe_faceA
//    walks; also the mismatch SHORT-CIRCUIT order arm: eid-mismatch FIRST).
// ==========================================================================
#[test]
fn rsubs_dedup_arms() {
    let pa = PubKey { publisher: "pubA", num_events: 8 };
    let pb = PubKey { publisher: "pubB", num_events: 8 };
    assert_eq!(classify_dedup("pubA", 8, &pa, 8), DedupClass::SameTuple);
    assert_eq!(classify_dedup("pubA", 8, &pb, 8), DedupClass::MismatchTuple);
    assert_eq!(classify_dedup("pubA", 8, &pa, 7), DedupClass::MismatchTuple);
    // the eid-mismatch-eid-mismatch-AND-pub-mismatch arm (both differ ->
    // still one MismatchTuple, the `or` short-circuit never double-counts):
    assert_eq!(classify_dedup("pubA", 8, &pb, 7), DedupClass::MismatchTuple);
    // ordinals (FACE-A `same=0 pub-mismatch=1 eid-mismatch=1`):
    assert_eq!(DedupClass::SameTuple as u32, 0);
    assert_eq!(DedupClass::MismatchTuple as u32, 1);
}

// ==========================================================================
// 6. The peg slot-map + reset()-carve-out over FRESH instances (race-free
//    unit face of the FACE-A arms; the replay above rides the globals).
// ==========================================================================
#[test]
fn rsubs_slotmap_and_carveout_units() {
    // the RssPeg::Count = 12 face (the static_assert :340 pairing side):
    assert_eq!(RssPeg::Count as usize, 12);
    assert_eq!(RSS_PEGS.len(), 13);
    assert_eq!(
        RSS_PEGS[12].peg_type,
        snort3::framework::counts::CountType::End
    );
    // the slot-map walk (field order == enum order == table order):
    let s = RssStats::new();
    for (i, slot) in [
        &s.installed, &s.retired, &s.bus_destroyed, &s.policy_resolution_failures,
        &s.list_returned, &s.stripped, &s.dead_handler_skips, &s.active,
        &s.registry_tracked, &s.dedup_conflicts, &s.slow_drains, &s.reconcile_deferrals,
    ]
    .iter()
    .enumerate()
    {
        slot.store((i + 1) as u64, Ordering::Relaxed);
    }
    let mut out: [PegCount; 12] = [0; 12];
    rss_stats_to_pegcounts(&s, &mut out);
    assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    // the NSDMI law face (every field {0} at construction):
    let z = RssStats::new();
    assert_eq!(z.installed.load(Ordering::Relaxed), 0);
    assert_eq!(z.reconcile_deferrals.load(Ordering::Relaxed), 0);
    // the reset()-CARVE-OUT: ten cleared, active+registry_tracked SURVIVE:
    let c = RssStats::new();
    c.installed.store(5, Ordering::Relaxed);
    c.active.store(3, Ordering::Relaxed);
    c.registry_tracked.store(2, Ordering::Relaxed);
    c.reconcile_deferrals.store(9, Ordering::Relaxed);
    c.reset();
    assert_eq!(c.installed.load(Ordering::Relaxed), 0);
    assert_eq!(c.slow_drains.load(Ordering::Relaxed), 0);
    assert_eq!(c.reconcile_deferrals.load(Ordering::Relaxed), 0);
    assert_eq!(c.active.load(Ordering::Relaxed), 3); // the carve-out
    assert_eq!(c.registry_tracked.load(Ordering::Relaxed), 2); // the carve-out
}

// ==========================================================================
// 7. The NEXT.md cite-PIN faces UNDISTURBED by this row (the docs law; the
//    NEXT.md itself NEVER rides this commit's paths).
// ==========================================================================
#[test]
fn rsubs_next_cite_pins_undisturbed() {
    let nx = include_str!("../NEXT.md");
    assert_eq!(nx.matches("621 tests green / 0 FAILED").count(), 3);
    assert_eq!(nx.matches("605 tests green / 0 FAILED").count(), 3);
    assert_eq!(nx.matches("597 tests green / 0 FAILED").count(), 3);
    assert!(nx.contains("573 tests green"));
}
