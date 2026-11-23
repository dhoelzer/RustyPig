//! Parity test for the row-22a chapter-19 port — src/main/thread_config.rs
//! (ground truth @ fe29cbe: cc 920 L md5 ca123f895a028e53328b3b0451af8073
//! plus h 95 L md5 86a4d24805a6413ecebbbe72e4f10e5b — THE row pair rides
//! TOGETHER, h NOT a decl-only split: the PLAN q4 q-face — the pair has
//! always been one TU + one header, and the 5 stale `21c903df` donor
//! header copies prove what separating them does).
//!
//! THE GATE ROW (first REAL gate since gre/18g — the 28-straight zero-
//! gate streak ENDS here): the ground cc carries its OWN in-TU Catch
//! block (:613 `#ifdef UNIT_TEST` -> :615-:916, EXACTLY 14 TEST_CASE
//! "[ThreadConfig]" — 9 direct + 5 nested `#ifdef HAVE_NUMA` :797). The
//! harness RAN them host-green (gate.txt tail, RUNNER-MEASURED at
//! build-time: "All tests passed (23 assertions in 14 test cases)"; the
//! HAVE_NUMA-off hinge arm: "All tests passed (17 assertions in 9 test
//! cases)" — the 5 NUMA cases hinge on the define, HONESTLY). Below: the
//! 14 ground cases translate as 14 Rust test fns (the 18g gate-
//! semantics law), carrying EXACTLY the ground's 23 CHECKs re-expressed
//! as real Rust assertions (CENSUS MEASURED in-file below: the gate
//! section holds EXACTLY-23 assert statements — the Rust-side 23-
//! equivalent face, measured, NEVER typed from the C tail). The C tail
//! string itself stays the harness's RUNNER-MEASURED face (the tc
//! gate.txt is COPY-LOCAL UNTRACKED — same posture as periodic/numa;
//! the TRACKED gate face stays gre's ONLY, tracked count 1). The
//! harness's own tc_gate_main.cc (CATCH_CONFIG_RUNNER — first-ever
//! tracked runner main TU) + the 9 stageables ride tools/tc_harness.
//!
//! Ground truth #1: `tools/tc_harness/vectors.txt` — the DEC face, 9 L
//! md5 3ef16a1e66a1590fb0303e514b6334b3 NEVER edited: the probe.cc
//! cpuset-decision ladder (WIT_PARSE_ERR flow line + D1-D8) over the
//! REAL thread_config.o + the FUNCTIONAL hwloc witness (model CPUs
//! 0..255 — D4 fallback w=256, D6 ceiling 255-in/256-out, D7 dash
//! range) + the numa.cc HOME pair PLAIN (D8 — one-home: its 3 TEST_CASEs
//! stay numa_harness gate home, never re-gated). Replayed HERE line-for-
//! line over the ported Rust decision ladder.
//!
//! Ground truth #2: `tools/tc_harness/vectors_faceA.txt` — FACE-A, 9 L
//! md5 653103cb599ea633... (653103cb599ea6369949eeb35a8ed698): NOLOAD
//! head + MAXLADDER (auto = the witness model 256, NOT host nproc) +
//! TIDLADDER (cc :238-:246 map) + the NAME ladder (snort3 / s3.pkt-c0 /
//! the pthread ERANGE name-KEEP / s3.pkt-c9999 SURVIVING the fallback
//! re-name ERANGE — the 15-byte cap as REAL byte-length logic) +
//! NUMAFALSE (the witness 0/0 early-out) + WD-NOOP (the :585/:604 once-
//! const guards FALSE at the timer-0 stock conf). Line-for-line below.
//!
//! SESSION LAW: the C probes/gate each ran SEPARATE processes (fresh
//! file statics every run); the Rust session runs in ONE process — the
//! reinit face (`thread_config::reinit_for_fresh_process()`) mirrors a
//! fresh statics image at each section start, and TC_LOCK serializes the
//! session-touching tests. The pthread name cell is thread_local like
//! the C per-thread names: the FACE-A name ladder runs wholly on its own
//! test thread (the same-thread face). The C gate's cross-case bind
//! chain (:641-:802 same main test thread) is NOT leaned on: every gate
//! case re-init'd fresh passes its OWN CHECKs — recorded honest.

use snort3::log::messages::LogEngine;
use snort3::main::numa::{
    convert_string_to_numa_mempolicy, stringify_numa_mempolicy, NUMA_POLICY_DEFAULT,
};
use snort3::main::thread::SThreadType;
use snort3::main::thread_config::*;

use std::sync::Arc;

const VECTORS: &str = include_str!("../tools/tc_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/tc_harness/vectors_faceA.txt");
const RS: &str = include_str!("../src/main/thread_config.rs");

// THE session face (C = separate processes; Rust = one — reinit mirrors
// the fresh image, the sfd/21a session law).
fn lock() -> std::sync::MutexGuard<'static, ()> {
    static TC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn fresh_gate_process() {
    reinit_for_fresh_process();
    assert!(ThreadConfig::init(), "init() true on the witness arms (:74-:88)");
}

fn check_lines(replay: &[String], pinned: &str, face: &str) {
    let want: Vec<&str> = pinned.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(want.len(), 9, "{face}: pinned vectors are 9 L");
    assert_eq!(replay.len(), want.len(), "{face}: replay line count");
    for (i, (got, want)) in replay.iter().zip(want.iter()).enumerate() {
        assert_eq!(got.as_str(), *want, "{face} line {}: line-for-line vs the pinned vectors", i + 1);
    }
}

// ==========================================================================
// 1. DEC vectors replay (probe.cc D1-D7 over validate_cpuset_string
//    cc :109-:163 + the D8 numa HOME pair PLAIN — REUSE-cited, its gate
//    home stays numa_harness, one-home law).
// ==========================================================================

#[test]
fn tc_dec_vectors_replay() {
    let _g = lock();
    reinit_for_fresh_process();
    assert!(ThreadConfig::init());
    let mut out: Vec<String> = Vec::new();
    let mut log = LogEngine::default();

    // the WIT_PARSE_ERR flow line (probe.cc :14-:16 — the ParseError
    // witness PRINTS the ground :114 message; the Rust home is the REAL
    // LogEngine::parse_error and the transcript MUST carry the SAME
    // ground format text — the :114 literal via cfmt's %s face).
    let bad = ThreadConfig::validate_cpuset_string(Some("totally a bad cpuset string"), &mut log);
    assert!(
        log.transcript().contains("Invalid CPU set string 'totally a bad cpuset string'"),
        "the ground :114 ParseError flow must be OBSERVABLE through LogEngine (the WIT_PARSE_ERR face)"
    );
    out.push("WIT_PARSE_ERR Invalid CPU set string 'totally a bad cpuset string'".to_string());
    assert!(bad.is_none(), "D1 parse-fail => nullptr (:117)");
    out.push("D1 bad-null=1=1".to_string());

    // D2 fully-allowed set (the probe feeds the LITERAL "0,1,7" — all
    // model-inside => :120 trivially-included, the :162 pass-through):
    let ok = ThreadConfig::validate_cpuset_string(Some("0,1,7"), &mut log).expect("D2 Some");
    out.push(format!(
        "D2 ok=1 w={} isset7={}",
        ok.cpuset.weight(),
        if ok.cpuset.isset(7) { 1 } else { 0 }
    ));

    // D3 partial overlap: 5 inside, 300 outside -> the intersection arm
    // (:120-:159; cc :147-:152 the warning face rides LogEngine).
    let part = ThreadConfig::validate_cpuset_string(Some("5,300"), &mut log).expect("D3 Some");
    out.push(format!(
        "D3 part=1 w={} isset5={} isset300={}",
        part.cpuset.weight(),
        if part.cpuset.isset(5) { 1 } else { 0 },
        if part.cpuset.isset(300) { 1 } else { 0 }
    ));

    // D4 ZERO overlap -> the whole-process-set fallback (cc :130-:143):
    let fb = ThreadConfig::validate_cpuset_string(Some("300"), &mut log).expect("D4 Some");
    out.push(format!("D4 fb=1 w={}", fb.cpuset.weight()));

    // D5 the EMPTY string parses CLEAN and is trivially included (:112):
    let e = ThreadConfig::validate_cpuset_string(Some(""), &mut log).expect("D5 Some");
    out.push(format!("D5 empty=1 w={}", e.cpuset.weight()));

    // D6 the model ceiling: 256 outside (allowed face 0..255) -> zero
    // intersect -> fallback; 255 in, 256 never:
    let ceil = ThreadConfig::validate_cpuset_string(Some("256"), &mut log).expect("D6 Some");
    out.push(format!(
        "D6 model-ceil=1 w={} isset255={} isset256={}",
        ceil.cpuset.weight(),
        if ceil.cpuset.isset(255) { 1 } else { 0 },
        if ceil.cpuset.isset(256) { 1 } else { 0 }
    ));

    // D7 the list_sscanf dash arm (the witness comma/range round-trip):
    let rng = ThreadConfig::validate_cpuset_string(Some("10-13"), &mut log).expect("D7 Some");
    out.push(format!(
        "D7 range=1 w={} isset12={}",
        rng.cpuset.weight(),
        if rng.cpuset.isset(12) { 1 } else { 0 }
    ));

    // D8 the numa.cc HOME decision pair PLAIN — the landed main::numa
    // REUSE face (its 3 Catch cases stay numa_harness gate home).
    out.push(format!(
        "D8 numa cnv-bind={} cnv-nope={} dflt2str={}",
        stringify_numa_mempolicy(convert_string_to_numa_mempolicy("bind")),
        stringify_numa_mempolicy(convert_string_to_numa_mempolicy("nope")),
        stringify_numa_mempolicy(NUMA_POLICY_DEFAULT),
    ));

    check_lines(&out, VECTORS, "DEC");
}

// ==========================================================================
// 2. FACE-A replay (probe_faceA.cc): MAXLADDER 256-ModelState +
//    TIDLADDER + the NAME ladder incl the 15-byte ERANGE name-KEEP +
//    NUMAFALSE + WD-NOOP. One test thread top-to-bottom (the name cell
//    is thread_local — the same-thread face the C probe had).
// ==========================================================================

#[test]
fn tc_facea_vectors_replay() {
    let _g = lock();
    reinit_for_fresh_process();
    let mut out: Vec<String> = Vec::new();

    out.push("NOLOAD main-TU SO_PUBLIC-h-only (BUILDING_SO/NDEBUG/sids grep-0 pinned by build.sh greps)".to_string());
    assert!(ThreadConfig::init());
    let mut log = LogEngine::default();

    // the instance-max AUTO ladder (cc :92-:107): seed 1 -> 7 -> 0 =
    // AUTO = the WITNESS MODEL weight 256 (`std::thread::available_
    // parallelism` = the real-host face a REAL hwloc would report; the
    // 256-model arm is what the witness pins — MAXLADDER).
    let m1 = ThreadConfig::get_instance_max();
    ThreadConfig::set_instance_max(7);
    let m2 = ThreadConfig::get_instance_max();
    ThreadConfig::set_instance_max(0);
    let m3 = ThreadConfig::get_instance_max();
    out.push(format!("MAXLADDER 1={m1} 7={m2} auto=256={m3}"));

    // the tid map ladder (cc :238-:246): cold -1; set(3) => own tid
    // (the emplace first-insert face + the glibc >= 2.30 gettid face).
    let cold = ThreadConfig::get_instance_tid(7);
    ThreadConfig::set_instance_tid(3);
    let hit = ThreadConfig::get_instance_tid(3);
    let own = own_tid();
    out.push(format!(
        "TIDLADDER cold=-1={} hit-is-own-tid={} tid>0={}",
        if cold == -1 { 1 } else { 0 },
        if hit == own { 1 } else { 0 },
        if hit > 0 { 1 } else { 0 }
    ));

    // NAME1: unbound MAIN -> desired == current (process) -> name
    // "snort3" (:421-:426: MAIN KEEPS snort3, the suffix DROPPED :426).
    let tc1 = ThreadConfig::new();
    tc1.implement_thread_affinity(SThreadType::Main, 0, &mut log);
    out.push(format!("NAME1 main={}", get_thread_name()));

    // NAME2: bound {0} -> "-c"+list face (:411-:412) -> s3.pkt-c0.
    let mut one = CpuBitmap::new();
    one.set(0);
    let mut tc2 = ThreadConfig::new();
    tc2.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(one), &mut log); // h :55
    tc2.implement_thread_affinity(SThreadType::Packet, 0, &mut log);
    out.push(format!("NAME2 pkt-c0={}", get_thread_name()));

    // NAME3: unbound id1 -> desired = the 256-wide process list -> the
    // name is s3.pkt-c0,1,2,...,255 = 520 bytes > the 15-byte cap util.h
    // :41 -> pthread_setname_np ERANGE -> the OLD name SURVIVES (the
    // byte-length math rides REAL logic in set_thread_name).
    let tc3 = ThreadConfig::new();
    tc3.implement_thread_affinity(SThreadType::Packet, 1, &mut log);
    out.push(format!("NAME3 erange-name-kept={}", get_thread_name()));

    // NAME4: {9999} unbindable -> the PRIMARY name set BEFORE the bind
    // (:434) is s3.pkt-c9999 (12 bytes, FITS); the bind fails, the
    // fallback lands, and the :451-:453 re-name to s3.pkt-c<process
    // list> ERANGEs again -> s3.pkt-c9999 SURVIVES (cc :446-:455).
    let mut bogus = CpuBitmap::new();
    bogus.set(9999);
    let mut tc4 = ThreadConfig::new();
    tc4.set_thread_affinity(SThreadType::Packet, 2, CpuSet::new(bogus), &mut log);
    tc4.implement_thread_affinity(SThreadType::Packet, 2, &mut log);
    out.push(format!("NAME4 pkt-c9999-survives={}", get_thread_name()));

    // NUMAFALSE: the witness numa available()=0 / max_node()=0 => the cc
    // :314-:318 early-out FALSE (the honest no-NUMA-host arm; the
    // set_numa_mempolicy call side rides the convert REUSE).
    let mut tc5 = ThreadConfig::new();
    tc5.set_numa_mempolicy("bind", &mut log); // :274-:280 (known policy: no warn)
    let nret = tc5.implement_thread_mempolicy(SThreadType::Packet, 0, &mut log);
    out.push(format!("NUMAFALSE implemented=0={}", if nret { 0 } else { 1 }));

    // WD-NOOP: the stock timer-0 conf (snort_config.h :264) pins the
    // :585/:604 once-const guards FALSE -> start registers the handler
    // on the landed time::periodic home and kick/preemptive/update
    // return at the guard (all arms LIVE, NOOP).
    start_watchdog();
    kick_watchdog(0);
    preemptive_kick(0);
    update_thread_status(true, 0);
    update_thread_status(false, 0);
    out.push("WD-NOOP timer0-guard-false all-arms-live=1".to_string());

    ThreadConfig::term();
    check_lines(&out, VECTORS_FACE_A, "FACE-A");

    // DIRECT semantic tripwires under the face (the ERANGE ladder + the
    // 256-model face re-asserted, not just the transcript):
    assert_eq!(get_thread_name(), "s3.pkt-c9999", "the ERANGE name-KEEP chain ends at s3.pkt-c9999 (NAME4)");
    assert_eq!(m3, 256, "AUTO instance-max = the witness MODEL 256 (NOT the host nproc face)");
    assert_eq!(get_instance_max_public(), 256, "the statics home carries it process-wide");
}

fn get_instance_max_public() -> u32 {
    ThreadConfig::get_instance_max()
}

unsafe extern "C" {
    #[link_name = "gettid"] // the same glibc face the port links (:235)
    fn gettid_c() -> i32;
}

fn own_tid() -> i32 {
    unsafe { gettid_c() }
}

// ==========================================================================
// 3. THE GATE TRANSLATION — the 14 ground TEST_CASE("...", "[Thread-
//    Config]") faces cc :615-:916 as 14 Rust test fns (the 18g gate-
//    semantics law: the C block RAN host-green — runner face "All tests
//    passed (23 assertions in 14 test cases)", the HAVE_NUMA-off hinge
//    "All tests passed (17 assertions in 9 test cases)" — both RUNNER-
//    MEASURED in the harness, NEVER typed here; this section re-expresses
//    each ground CHECK as a real Rust assertion). Ground name -> Rust
//    fn mapping is 1:1 (the fn doc carries the CITE + the CHECK count).
//    The section's own assertion census: EXACTLY-23 asserts (measured by
//    the self-census tripwire below — the Rust-side 23-equivalent face
//    of the runner's 23 assertions; the 9-case HAVE_NUMA-off hinge's 17
//    ride cases 1-9 = 17 asserts, the NUMA five add 6 — 17+6=23).
//    GATE-ASSERT-BEGIN below marks the census window.
// ==========================================================================

// GATE-ASSERT-BEGIN
// ---- case 1 (:615-:619) 1 CHECK: parse-fail => nullptr ----
#[test]
fn up_gate_parse_cpuset_string_negative() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let cpuset = ThreadConfig::validate_cpuset_string(Some("totally a bad cpuset string"), &mut log);
    assert!(cpuset.is_none(), "cc :618 CHECK(cpuset == nullptr)");
}

// ---- case 2 (:621-:629) 1 CHECK: the process set's own list validates ----
#[test]
fn up_gate_parse_cpuset_string_positive() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    // :623-:625 the asprintf(process_cpuset) -> validate round-trip
    let s = get_process_cpuset().expect("process_cpuset (:624 deref face)").list_asprintf();
    let cpuset = ThreadConfig::validate_cpuset_string(Some(&s), &mut log);
    assert!(cpuset.is_some(), "cc :627 CHECK(cpuset != nullptr)");
    ThreadConfig::destroy_cpuset(cpuset); // :628
}

// ---- case 3 (:631-:639) 3 CHECKs: the instance-max ladder ----
#[test]
fn up_gate_set_and_check_max_packet_threads() {
    let _g = lock();
    fresh_gate_process();
    assert_eq!(ThreadConfig::get_instance_max(), 1, "cc :633 CHECK(get_instance_max() == 1) (:44 seed)");
    // :634-:636 the weight*2 override arm
    let w = get_process_cpuset().expect("process_cpuset (:634)").weight();
    let new_max = (w * 2) as u32;
    ThreadConfig::set_instance_max(new_max);
    assert_eq!(ThreadConfig::get_instance_max(), new_max, "cc :636 CHECK(== new_max)");
    // :637-:638 the AUTO arm (set 0 => the model weight)
    ThreadConfig::set_instance_max(0);
    assert_eq!(
        ThreadConfig::get_instance_max(),
        get_process_cpuset().expect("process_cpuset (:638)").weight() as u32,
        "cc :638 CHECK(== weight(process_cpuset))"
    );
}

// ---- case 4 (:641-:664) 2 CHECKs (support-gated — the witness 1/1
//      face runs them): set-then-replace, implement, bind observable ----
#[test]
fn up_gate_set_and_implement_thread_affinity() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:645/:646 dups)");
    let mut cpuset = proc.dup();
    let cpuset2 = proc.dup();
    let mut tc = ThreadConfig::new();
    cpuset.singlify(); // :649 -> {0}
    tc.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(cpuset2), &mut log); // :650
    tc.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(cpuset.dup()), &mut log); // :651 REPLACE (:207-:210)
    tc.implement_thread_affinity(SThreadType::Packet, 0, &mut log); // :652
    assert!(
        thread_cpubind_query()
            .expect("thread cpuset (:655)")
            .is_equal(&cpuset),
        "cc :656 CHECK(hwloc_bitmap_isequal(thread_cpuset, cpuset->cpuset))"
    );
    tc.implement_thread_affinity(SThreadType::Main, 0, &mut log); // :658 no entry => process set
    assert!(
        thread_cpubind_query()
            .expect("thread cpuset (:659)")
            .is_equal(&proc),
        "cc :660 CHECK(isequal(thread_cpuset, process_cpuset))"
    );
}

// ---- case 5 (:666-:692) 2 CHECKs: the named-map hit + the
//      miss-through-type path (fresh tc: NO type entry => process set) ----
#[test]
fn up_gate_named_thread_affinity_configured() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:670 dup)");
    let mut cpuset = proc.dup();
    let mut tc = ThreadConfig::new();
    cpuset.singlify(); // :676 -> {0}
    tc.set_named_thread_affinity("found", CpuSet::new(cpuset.clone()), &mut log); // :677
    tc.implement_named_thread_affinity("found", SThreadType::Main, &mut log); // :680 (the witness get_thread_type() = MAIN face)
    assert!(
        thread_cpubind_query()
            .expect("thread cpuset (:681)")
            .is_equal(&cpuset),
        "cc :682 CHECK(isequal(thread_cpuset, cpuset->cpuset))"
    );
    tc.implement_named_thread_affinity("not found, no type configured", SThreadType::Main, &mut log); // :686 miss
    assert!(
        thread_cpubind_query()
            .expect("thread cpuset (:687)")
            .is_equal(&proc),
        "cc :688 CHECK(isequal(thread_cpuset, process_cpuset)) (:492 through the empty type map)"
    );
}

// ---- case 6 (:694-:714) 1 CHECK: the named miss INHERITS the type ----
#[test]
fn up_gate_named_thread_affinity_with_type_configured() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:698 dup)");
    let mut type_cpuset = proc.dup();
    let mut tc = ThreadConfig::new();
    type_cpuset.singlify(); // :704 -> {0}
    tc.set_thread_affinity(SThreadType::Main, DEFAULT_THREAD_ID, CpuSet::new(type_cpuset.dup()), &mut log); // :705
    tc.implement_named_thread_affinity("not found, type other", SThreadType::Main, &mut log); // :708
    assert!(
        thread_cpubind_query()
            .expect("thread cpuset (:709)")
            .is_equal(&type_cpuset),
        "cc :710 CHECK(isequal(thread_cpuset, type_cpuset->cpuset)) (the :492 type inherit)"
    );
}

// ---- case 7 (:716-:743) 4 CHECKs: partial overlap => the intersection ----
#[test]
fn up_gate_validate_cpuset_partial_overlap_returns_intersection() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let original = get_process_cpuset().expect("process_cpuset (:719 dup)"); // cc :719
    let first_cpu = original.first().expect("hwloc_bitmap_first (:720)");
    let bogus_cpu = first_cpu + 100; // :721
    let mut restricted = CpuBitmap::new(); // :723-:726
    restricted.set(first_cpu as usize);
    set_process_cpuset(restricted.clone());
    // :729-:731 the partial request
    let req = format!("{first_cpu},{bogus_cpu}");
    let result = ThreadConfig::validate_cpuset_string(Some(&req), &mut log);
    assert!(result.is_some(), "cc :734 CHECK(result != nullptr)");
    let result = result.unwrap();
    assert_eq!(result.cpuset.weight(), 1, "cc :735 CHECK(hwloc_bitmap_weight(result->cpuset) == 1)");
    assert!(result.cpuset.isset(first_cpu as usize), "cc :736 CHECK(hwloc_bitmap_isset(result->cpuset, first_cpu))");
    assert!(!result.cpuset.isset(bogus_cpu as usize), "cc :737 CHECK(!hwloc_bitmap_isset(result->cpuset, bogus_cpu))");
    ThreadConfig::destroy_cpuset(Some(result)); // :738
    set_process_cpuset(original); // :741-:742 the RESTORE face
}

// ---- case 8 (:745-:770) 2 CHECKs: zero overlap => the fallback ----
#[test]
fn up_gate_validate_cpuset_zero_overlap_falls_back() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let original = get_process_cpuset().expect("process_cpuset (:748 dup)");
    let first_cpu = original.first().expect("hwloc_bitmap_first (:749)");
    let bogus_cpu = first_cpu + 100; // :750
    let mut restricted = CpuBitmap::new(); // :752-:755
    restricted.set(first_cpu as usize);
    set_process_cpuset(restricted.clone());
    let result = ThreadConfig::validate_cpuset_string(Some(&bogus_cpu.to_string()), &mut log); // :759-:760
    assert!(result.is_some(), "cc :763 CHECK(result != nullptr)");
    let result = result.unwrap();
    assert!(result.cpuset.is_equal(&restricted), "cc :764 CHECK(isequal(result->cpuset, process_cpuset))");
    ThreadConfig::destroy_cpuset(Some(result)); // :765
    set_process_cpuset(original); // :768-:769 the RESTORE face
}

// ---- case 9 (:772-:795) 1 CHECK: the unbindable-CPU graceful fallback
//      (witness law: bit >= 256 FAILS the bind => warn + fallback, the
//      NO-abort face the ground comment :776-:777 records) ----
#[test]
fn up_gate_implement_affinity_graceful_fallback_unbindable() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    // :774 support guard (the witness 1/1 face always runs this body)
    let mut bogus = CpuBitmap::new(); // :778-:779
    bogus.set(9999);
    let mut tc = ThreadConfig::new();
    tc.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(bogus), &mut log); // :783
    tc.implement_thread_affinity(SThreadType::Packet, 0, &mut log); // :786 must RETURN (no FatalError/abort here)
    assert!(
        !thread_cpubind_query()
            .expect("thread cpuset (:791)")
            .is_zero(),
        "cc :792 CHECK(!hwloc_bitmap_iszero(thread_cpuset)) (still bound to the fallback process set)"
    );
}

// ---- case 10 (:833-:854) 2 CHECKs: the mock pair drives the mempolicy
//      TRUE for both entries (the :842-:845 mock global installs —
//      set_numa_wrapper/set_hwloc_wrapper faces; os_index 0 then 1) ----
#[test]
fn up_gate_set_node_for_thread() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:835/:836 dups)");
    let cpuset = proc.dup();   // :835
    let cpuset2 = proc.dup();  // :836
    let mut tc = ThreadConfig::new();
    let numa_mock = NumaWrapperMock::default(); // :839 (:802-:804 defaults 1/1/0)
    let mut hwloc_mock = HwlocWrapperMock::default(); // :840 (:816-:817 defaults 1/2)
    hwloc_mock.node.os_index = 0; // :842
    set_numa_wrapper(Arc::new(numa_mock)); // :844 `numa = numa_mock;`
    set_hwloc_wrapper(Arc::new(hwloc_mock.clone())); // :845 `hwloc = hwloc_mock;`
    tc.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(cpuset2), &mut log); // :847
    tc.set_thread_affinity(SThreadType::Packet, 1, CpuSet::new(cpuset), &mut log); // :848
    assert!(
        tc.implement_thread_mempolicy(SThreadType::Packet, 0, &mut log),
        "cc :850 CHECK(true == implement_thread_mempolicy(PACKET, 0))"
    );
    // :852-:853 the SAME installed mock with node.os_index = 1 (Rust
    // Arc-immutable face: reinstall the updated mock — equivalent face)
    hwloc_mock.node.os_index = 1;
    set_hwloc_wrapper(Arc::new(hwloc_mock));
    assert!(
        tc.implement_thread_mempolicy(SThreadType::Packet, 1, &mut log),
        "cc :853 CHECK(true == implement_thread_mempolicy(PACKET, 1))"
    );
}

// ---- case 11 (:856-:869) 1 CHECK: available() < 0 => FALSE (:315) ----
#[test]
fn up_gate_numa_available_negative() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:858 dup)");
    let mut tc = ThreadConfig::new();
    tc.set_thread_affinity(SThreadType::Packet, 1, CpuSet::new(proc), &mut log); // :860
    let numa_mock = NumaWrapperMock { numa_avail: -1, ..NumaWrapperMock::default() }; // :865
    set_numa_wrapper(Arc::new(numa_mock));
    set_hwloc_wrapper(Arc::new(HwlocWrapperMock::default()));
    assert!(
        !tc.implement_thread_mempolicy(SThreadType::Packet, 0, &mut log),
        "cc :868 CHECK(false == implement_thread_mempolicy) (the :315 available() < 0 arm)"
    );
}

// ---- case 12 (:871-:885) 1 CHECK: depth UNKNOWN => FALSE (:288) ----
#[test]
fn up_gate_depth_unknown_negative() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:873 dup)");
    let mut tc = ThreadConfig::new();
    tc.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(proc), &mut log); // :876
    set_numa_wrapper(Arc::new(NumaWrapperMock::default()));
    let hw = HwlocWrapperMock { type_depth: HWLOC_TYPE_DEPTH_UNKNOWN, ..HwlocWrapperMock::default() }; // :881
    set_hwloc_wrapper(Arc::new(hw));
    assert!(
        !tc.implement_thread_mempolicy(SThreadType::Packet, 0, &mut log),
        "cc :884 CHECK(false) (both node lookups UNKNOWN => node_index -1 => apply false)"
    );
}

// ---- case 13 (:887-:901) 1 CHECK: set_mem_policy != 0 => FALSE (:306) ----
#[test]
fn up_gate_set_memory_policy_failure_negative() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:889 dup)");
    let mut tc = ThreadConfig::new();
    tc.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(proc), &mut log); // :891
    let numa = NumaWrapperMock { mem_policy: -1, ..NumaWrapperMock::default() }; // :897
    let hw = HwlocWrapperMock { node: HwlocObj { os_index: 0, cpuset: CpuBitmap::new() }, ..HwlocWrapperMock::default() }; // :896
    set_numa_wrapper(Arc::new(numa));
    set_hwloc_wrapper(Arc::new(hw));
    assert!(
        !tc.implement_thread_mempolicy(SThreadType::Packet, 0, &mut log),
        "cc :900 CHECK(false) (the mock set_mem_policy -1 arm :306)"
    );
}

// ---- case 14 (:903-:916) 1 CHECK: nbobjs 0 => node -1 => FALSE ----
#[test]
fn up_gate_get_nbobjs_by_depth_failure_negative() {
    let _g = lock();
    fresh_gate_process();
    let mut log = LogEngine::default();
    let proc = get_process_cpuset().expect("process_cpuset (:905 dup)");
    let mut tc = ThreadConfig::new();
    tc.set_thread_affinity(SThreadType::Packet, 0, CpuSet::new(proc), &mut log); // :907
    set_numa_wrapper(Arc::new(NumaWrapperMock::default()));
    let hw = HwlocWrapperMock { nbobjs_by_depth: 0, ..HwlocWrapperMock::default() }; // :912
    set_hwloc_wrapper(Arc::new(hw));
    assert!(
        !tc.implement_thread_mempolicy(SThreadType::Packet, 0, &mut log),
        "cc :915 CHECK(false) (the mock loop bound 0 => get_numa_node -1 :297)"
    );
}
// GATE-ASSERT-END

// ==========================================================================
// 4. THE TRIPOWIRE SECTION — the row's honest census + drift faces.
// ==========================================================================

#[test]
fn tc_gate_row_tripwires() {
    // --- (a) THE 23-assertion GATE CENSUS, MEASURED on this file: the
    //     gate section (GATE-ASSERT-BEGIN .. GATE-ASSERT-END) holds
    //     EXACTLY-23 assert statements — the Rust-side face of the
    //     runner's measured "All tests passed (23 assertions in 14 test
    //     cases)" (17 = the 9 direct cases = the HAVE_NUMA-off hinge's
    //     17-assertion arm + 6 = the NUMA five; the hinge face cited at
    //     (g)). MEASURED never cloned: this count is produced HERE from
    //     the source text, and the C tail's numbers were RUNNER-MEASURED
    //     by the harness — the two agree through translation, not copy.
    let me = std::fs::read_to_string("tests/tc_parity_test.rs")
        .expect("this test file readable from the workspace root (cargo test cwd)");
    let begin = me.find("// GATE-ASSERT-BEGIN").expect("gate census window opens");
    let end = me.find("// GATE-ASSERT-END").expect("gate census window closes");
    let gate: &str = &me[begin..end];
    let n_test_cases = gate.lines().filter(|l| l.trim_start().starts_with("#[test]")).count();
    assert_eq!(n_test_cases, 14, "EXACTLY-14 translated gate cases (the ground :615-:916 14-face face)");
    let n_asserts = gate
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("assert!(") || t.starts_with("assert_eq!(")
        })
        .count();
    assert_eq!(n_asserts, 23, "EXACTLY-23 gate assertions (the Rust-side 23-equivalent face of the RUNNER-MEASURED 23)");
    let n_direct = gate
        .find("case 10")
        .map(|i| {
            gate[..i]
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    t.starts_with("assert!(") || t.starts_with("assert_eq!(")
                })
                .count()
        })
        .expect("case 10 marker");
    assert_eq!(n_direct, 17, "the 9 direct cases carry 17 asserts — the HAVE_NUMA-off hinge's 17-assertion face maps exactly");

    // --- (b) THE ground anchors (ground-cite law, NEVER typed): cc
    //     TEST_CASE( EXACTLY-14, the WITH-SPACE gre shape grep-0, the
    //     inner HAVE_NUMA hinge at :797, the include-arm :34-:35 drift
    //     face (PLAN banked :34 — disk :35 wins, the cite-drift law).
    let cc = std::fs::read("/opt/data/snort3-src/src/main/thread_config.cc")
        .expect("ground cc present");
    let cc = String::from_utf8(cc).expect("ground cc utf8");
    let lines: Vec<&str> = cc.lines().collect();
    assert_eq!(lines.len(), 920, "ground cc 920 L (md5 face in the header)");
    assert_eq!(cc.matches("TEST_CASE(").count(), 14, "ground TEST_CASE( EXACTLY-14");
    assert_eq!(cc.matches("TEST_CASE (").count(), 0, "the gre-style 'TEST_CASE (' NEVER exists here (space-variant 0)");
    assert_eq!(lines[796], "#ifdef HAVE_NUMA", "the 5-case NUMA hinge at :797");
    assert_eq!(lines[612], "#ifdef UNIT_TEST", "the suite arm opens :613");
    assert_eq!(lines[614].trim_start(), "TEST_CASE(\"Parse cpuset string negative test\", \"[ThreadConfig]\")", "case 1 anchor :615");
    assert_eq!(lines[33], "#ifdef UNIT_TEST", "the include-arm drift face: :34 opens");
    assert_eq!(lines[34], "#include \"catch/snort_catch.h\"", "disk :35 (the PLAN banked :34 — CITE-DRIFT, disk wins)");
    assert_eq!(cc.matches("#ifdef HAVE_NUMA").count(), 6, "the six HAVE_NUMA arms");

    // --- (c) THE h face: 95 L NOT the banked "86" token (the drift
    //     face the harness ground-identity greps re-prove EVERY build).
    let h = std::fs::read("/opt/data/snort3-src/src/main/thread_config.h")
        .expect("ground h present");
    let h = String::from_utf8(h).expect("ground h utf8");
    assert_eq!(h.lines().count(), 95, "ground h 95 L — NOT 86 (h-95-not-86 face)");
    assert!(RS.contains("95 L"), "the port rs cites the 95-L face");
    assert!(!RS.contains("86 L"), "the rs NEVER rides the stale 86 token");

    // --- (d) THE stale-donor guard: the rs MUST cite the GROUND h md5
    //     (86a4d2...) and NEVER the 21c903df stale donor header face
    //     (the 5 copy trees carry it; the harness fresh-cp law re-proves
    //     the DIFF EVERY build).
    assert!(RS.contains("86a4d24805a6413ecebbbe72e4f10e5b"), "the rs cites the ground h md5 face");
    assert!(RS.contains("ca123f895a028e53328b3b0451af8073"), "the rs cites the ground cc md5 face");
    assert!(!RS.contains("21c903df9febbd9bfe08e1d3ad5d5f02"), "the stale-21c903df donor header md5 NEVER rides the rs (the fresh-cp law)");

    // --- (e) the hwloc TOKEN drift trio (disk wins law): cc raw 142 /
    //     grep-LINE 126 / h raw 2 — and the banked NEXT.md "133" face
    //     stays the STALE cite-only token (NEVER edited).
    assert_eq!(cc.matches("hwloc_").count(), 142, "cc raw hwloc_* occurrence face = 142");
    assert_eq!(lines.iter().filter(|l| l.contains("hwloc_")).count(), 126, "cc grep-LINE face = 126");
    assert_eq!(h.matches("hwloc_").count(), 2, "h raw tokens = 2 (h :22/:91 faces)");
    let nx = std::fs::read_to_string("NEXT.md").expect("NEXT.md present (cite-only, NEVER edited)");
    assert!(nx.contains("cc **133**"), "the NEXT banked 133 = the STALE trio member (cite-drift, disk wins)");

    // --- (f) the ONE-home face: the rs OWNS get_instance_max; the
    //     landed seams REUSE-cite it (file_cache :499 seam + module.rs
    //     cite + thread.rs :59-:63 naming mirror) — NEVER a re-fork.
    assert_eq!(RS.matches("fn get_instance_max").count(), 1, "EXACTLY-ONE get_instance_max home in the rs (the witness_conf CORE-SUBSET clash face proves the row owns it)");
    let fc = std::fs::read_to_string("src/file_api/file_cache.rs").expect("landed file_cache present");
    assert!(fc.contains("thread_config.h:44") && fc.contains("get_instance_max"), "the landed file_cache ThreadApi seam cites THE h:44 face (one-home REUSE, never re-forked)");

    // --- (g) the harness runner face is HARNESS-side (the gate.txt
    //     copy-local posture): if the harness ran, the tail face MUST
    //     be byte-face-exact; tracked-gate posture proof lives in the
     //     check-ignore arm (build.sh) + git ls-files (count 1, gre).
    if let Ok(g) = std::fs::read_to_string("tools/tc_harness/gate.txt") {
        assert!(
            g.contains("All tests passed (23 assertions in 14 test cases)"),
            "the RUNNER-MEASURED gate tail face (never typed; the harness pins it EVERY build)"
        );
        assert_eq!(g.lines().filter(|l| l.contains("[ThreadConfig]")).count(), 1, "gate.txt = the RUN transcript: the single Filters line only (the 14-name roster rides gate_l.txt)");
    }
    if let Ok(o) = std::fs::read_to_string("tools/tc_harness/gate_off.txt") {
        assert!(
            o.contains("All tests passed (17 assertions in 9 test cases)"),
            "the HAVE_NUMA-off hinge face (9 cases / 17 assertions)"
        );
    }
    if let Ok(l) = std::fs::read_to_string("tools/tc_harness/gate_l.txt") {
        assert_eq!(l.lines().filter(|x| x.contains("[ThreadConfig]")).count(), 14, "the 14-name -l census face");
    }

    // --- (h) the rs SELF-census: ZERO allow-attributes (the 19b/21b
    //     posture rides) + the gettid extern face is EXACTLY-1.
    assert!(!RS.contains("#![allow"), "ZERO blanket allow");
    // the ONE-`#[allow` face tolerance: none at all this row (the abort
    // arm rides a plain std::process::abort behind the faithful guard —
    // NEVER suppressed). If the rs grows an allow, this trips.
    assert_eq!(RS.matches("#[allow").count(), 0, "ZERO point-site allows (the row's clean-own posture)");
    assert_eq!(RS.matches("fn gettid_c").count(), 1, "EXACTLY-ONE extern gettid face");

    // --- (i) the init-ORDER proof faces (upstream cites, NEVER edited):
    //     snort.cc:109 boots init() and the upstream runner shape lives
    //     at unit_test.cc:26 — the E10 runner law's ground home.
    let sn = std::fs::read_to_string("/opt/data/snort3-src/src/main/snort.cc").expect("ground snort.cc");
    assert_eq!(sn.lines().nth(108).map(str::to_string), Some("    ThreadConfig::init();".to_string()), "the snort.cc:109 init-order law face");
    let ut = std::fs::read_to_string("/opt/data/snort3-src/src/catch/unit_test.cc").expect("ground unit_test.cc");
    assert!(ut.contains("#define CATCH_CONFIG_RUNNER"), "the upstream RUNNER shape (unit_test.cc) — the tc_gate_main.cc law it mirrors");
    assert!(std::fs::read_to_string("tools/tc_harness/tc_gate_main.cc").expect("tracked runner main present").contains("#define CATCH_CONFIG_RUNNER"), "the row's RUNNER TU rides the same shape (first-ever tracked main TU)");
}
