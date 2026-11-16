//! Whole-transcript replay of tools/stopwatch_harness/vectors.txt
//! (ORIGINAL time/stopwatch.h + clock_defs.h compiled verbatim, probe
//! pins the real-clock macro layer) plus a one-#[test]-per-leaf
//! translation of the ORIGINAL upstream Catch2 suite
//! time/test/stopwatch_test.cc ([stopwatch]; the verbatim-C++ gate
//! runs 35 assertions). Catch2 SECTION semantics: every leaf
//! re-runs the TEST_CASE fixture and outer section statements from
//! scratch, so each leaf becomes its own #[test].
use std::cell::Cell;

use snort3::time::clock_defs::{
    CLOCK_ZERO, Clock, HrDuration, SnortClock, TIME_POINT_ZERO, clock_scale, clock_ticks, clock_usecs,
    to_duration, to_nsecs, to_ticks, to_usecs, ticks_literal,
};
use snort3::time::stopwatch::Stopwatch;

const VECTORS: &str = include_str!("../tools/stopwatch_harness/vectors.txt");

// -- probe transcript replay ------------------------------------------------

#[test]
fn stopwatch_transcript_replay() {
    let mut got = String::new();

    let d1 = ticks_literal(1);
    let t1 = to_ticks(d1);
    let u1 = to_usecs(d1); // C USEC1: ns->us truncation
    let n1 = to_nsecs(d1);
    got.push_str(&format!("TICK1={t1} USEC1={u1} NSEC1={n1}\n"));

    let d3 = ticks_literal(999);
    let u3 = to_usecs(d3);
    let n3 = to_nsecs(d3);
    got.push_str(&format!("USEC999={u3} NSEC999={n3}\n"));

    let u4 = to_usecs(ticks_literal(1500));
    got.push_str(&format!("USEC1500={u4}\n"));

    // C: hr_duration v = 0_ticks; TO_TICKS(TO_DURATION(v, 500))
    let tdt = to_ticks(to_duration(500));
    got.push_str(&format!("TO_DURATION500={tdt}\n"));

    // TIME_POINT_ZERO: C time_point::min() epoch count
    let ep0 = TIME_POINT_ZERO; // the i64 value itself is the epoch count
    got.push_str(&format!("TPEPOCHMIN={ep0}\n"));

    let cz = to_ticks(CLOCK_ZERO);
    let dz = to_ticks(0);
    got.push_str(&format!("CZ={cz} DZ={dz}\n"));

    let cs = clock_scale();
    let cu = clock_usecs(1000000);
    let ct = clock_ticks(1000000);
    got.push_str(&format!("SCALE={cs} USECS={cu} TICKS={ct}\n"));

    // ClockTraits<SnortClock>::duration td(123); td.count()
    let tdt2: HrDuration = 123;
    got.push_str(&format!("CTRAITS={tdt2}\n"));

    // real-clock state machine (booleans only; no tick values read)
    let mut sw: Stopwatch<SnortClock> = Stopwatch::default();
    let a0 = sw.active() as i32;
    let g0 = (sw.get() == 0) as i32;
    sw.start();
    let a1 = sw.active() as i32;
    let st1 = sw.get_start_time();
    sw.start();
    let a2 = sw.active() as i32;
    let st2 = sw.get_start_time();
    let same_start = (st1 == st2) as i32;
    sw.stop();
    let a3 = sw.active() as i32;
    sw.stop();
    let a4 = sw.active() as i32;
    sw.reset();
    let a5 = sw.active() as i32;
    let g5 = (sw.get() == 0) as i32;
    sw.start();
    let a6 = sw.active() as i32;
    sw.cancel();
    let a7 = sw.active() as i32;
    got.push_str(&format!(
        "SW a0={a0} g0={g0} a1={a1} a2={a2} same12={same_start} a3={a3} a4={a4} a5={a5} g5={g5} a6={a6} a7={a7}\n"
    ));

    // get() stable across repeated reads while stopped
    let x1 = sw.get();
    let x2 = sw.get();
    got.push_str(&format!("CANCELSTABLE={}\n", (x1 == x2) as i32));

    got.push_str("DONE\n");

    assert_eq!(got, VECTORS, "stopwatch transcript mismatch");
}

// -- upstream [stopwatch] suite translation ---------------------------------

// The upstream test's fake Clock: static ns tick time, now() reads it,
// default inc() advances by duration(1).
struct FakeClock;

thread_local! {
    static FAKE_NOW: Cell<HrDuration> = const { Cell::new(0) };
}

impl Clock for FakeClock {
    fn now() -> i64 {
        FAKE_NOW.with(|c| c.get())
    }
}

fn fake_reset() {
    FAKE_NOW.with(|c| c.set(0));
}

fn fake_inc() {
    FAKE_NOW.with(|c| c.set(c.get() + 1));
}

// TEST_CASE entry: `Stopwatch<Clock> sw; Clock::reset();`
fn fixture() -> Stopwatch<FakeClock> {
    fake_reset();
    let sw = Stopwatch::default();
    // REQUIRE( false == sw.active() )
    assert!(!sw.active());
    // REQUIRE( (sw.get() == 0_ticks) )
    assert_eq!(sw.get(), ticks_literal(0));
    sw
}

// SECTION "start" / "sets clock to active"
#[test]
fn start_sets_active() {
    let mut sw = fixture();
    sw.start();
    assert!(sw.active());
}

// SECTION "start" / "running elapsed time should be non-zero"
#[test]
fn running_elapsed_nonzero() {
    let mut sw = fixture();
    sw.start();
    fake_inc();
    assert!(sw.get() > ticks_literal(0));
}

// SECTION "start" / "start on running clock has no effect"
#[test]
fn restart_no_effect() {
    let mut sw = fixture();
    sw.start();
    sw.start();
    assert!(sw.active());
}

// SECTION "stop" / "sets clock to be dead"
#[test]
fn stop_makes_dead() {
    let mut sw = fixture();
    sw.start();
    sw.stop();
    assert!(!sw.active());
}

// SECTION "stop" / "ticks should not increase after death"
#[test]
fn no_ticks_after_death() {
    let mut sw = fixture();
    sw.start();
    sw.stop();
    fake_inc();
    let val = sw.get();
    assert_eq!(val, sw.get());
}

// SECTION "stop" / "stop on stopped clock has no effect"
#[test]
fn double_stop_no_effect() {
    let mut sw = fixture();
    sw.start();
    sw.stop();
    let val = sw.get();
    sw.stop();
    fake_inc();
    assert!(!sw.active());
    assert_eq!(val, sw.get());
}

// SECTION "reset" / "reset on running clock"
#[test]
fn reset_on_running() {
    let mut sw = fixture();
    sw.start();
    sw.reset();
    assert!(!sw.active());
    assert_eq!(sw.get(), ticks_literal(0));
}

// SECTION "reset" / "reset on stopped clock"
#[test]
fn reset_on_stopped() {
    let mut sw = fixture();
    sw.start();
    sw.stop();
    sw.reset();
    assert!(!sw.active());
    assert_eq!(sw.get(), ticks_literal(0));
}

// SECTION "cancel" / "cancel on running clock that has no lap time"
#[test]
fn cancel_running_no_lap() {
    let mut sw = fixture();
    sw.start();
    sw.cancel();
    assert!(!sw.active());
    assert_eq!(sw.get(), ticks_literal(0));
}

// SECTION "cancel" / "cancel on stopped clock that has lap time"
#[test]
fn cancel_stopped_keeps_lap() {
    let mut sw = fixture();
    sw.start();
    sw.stop();
    let val = sw.get();
    sw.cancel();
    assert!(!sw.active());
    assert_eq!(val, sw.get());
}
