//! Faithful Rust port of `time/clock_defs.h` (row 17j, default
//! non-TSC config: `USE_TSC_CLOCK` undefined, `SnortClock =
//! std::chrono::high_resolution_clock`, `clock_scale() == 1`).
//!
//! Fidelity notes (canonical list in KNOWN DEVIATIONS.md):
//! - libstdc++ x86-64 `high_resolution_clock` is `steady_clock` with
//!   `rep = int64_t`, `period = nano`: durations and time points are
//!   signed 64-bit NANOSECOND tick counts, pinned by the harness
//!   (TICK1=1 NSEC1=1 USEC999=0 TPEPOCHMIN=i64::MIN).
//! - The C macros become functions. `duration_cast` to microseconds
//!   TRUNCATES toward zero — C and Rust integer `/` agree.
//! - `TIME_POINT_ZERO` is `time_point::min()` (most negative
//!   duration), `-9223372036854775808` pinned.
//! - TSC-clock branch (`SnortClock = TscClock`, raw tick ints,
//!   `clock_scale() != 1`) is not compiled in this build config and
//!   is not ported here.

use std::time::Instant;

/// C `hr_duration = SnortClock::duration` — ns tick count.
pub type HrDuration = i64;
/// C `hr_time = SnortClock::time_point` — ns ticks; the epoch base is
/// not transcript-observable (no probe row ever prints a start_time).
pub type HrTime = i64;

/// The C++ clock concept piece the port needs: a now().
pub trait Clock {
    fn now() -> HrTime;
}

/// C `using SnortClock = std::chrono::high_resolution_clock` ==
/// steady_clock on libstdc++. Monotonic ns ticks; the C epoch is
/// unspecified so the base offset is arbitrary (deviation note).
pub struct SnortClock;

impl Clock for SnortClock {
    fn now() -> HrTime {
        // steady_clock-style monotonic ns ticks. C++'s steady_clock
        // epoch is unspecified (typically boot); Rust `Instant`'s
        // base is unspecified too. Absolute tick values are NOT
        // observable in the locked transcript (only deltas and
        // equality of two reads), so a lazily-anchored Instant
        // reproduces every pinned behavior.
        static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let base = *BASE.get_or_init(Instant::now);
        let d = Instant::now().duration_since(base);
        i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
    }
}

/// C `#define TIME_POINT_ZERO SnortClock::time_point::min()` —
/// pinned TPEPOCHMIN=-9223372036854775808.
pub const TIME_POINT_ZERO: HrTime = i64::MIN;

/// C `#define CLOCK_ZERO 0_ticks`.
pub const CLOCK_ZERO: HrDuration = 0;

/// C `#define DURA_ZERO Clock::duration::zero()` (the macro names a
/// scope-dependent `Clock`; every use site in time/ has one, and its
/// value here is 0).
pub fn dura_zero() -> HrDuration {
    0
}

/// C `inline long clock_scale() { return 1; }` (pinned SCALE=1).
pub fn clock_scale() -> i64 {
    1
}

/// C `clock_usecs(ticks)` = ticks / scale — pinned USECS=1000000.
pub fn clock_usecs(ticks: i64) -> i64 {
    ticks / clock_scale()
}

/// C `clock_ticks(usecs)` = usecs * scale — pinned TICKS=1000000.
pub fn clock_ticks(usecs: i64) -> i64 {
    usecs * clock_scale()
}

/// C `TO_TICKS(t)` = t.count().
pub fn to_ticks(d: HrDuration) -> i64 {
    d
}

/// C `TO_USECS(t)` = duration_cast<microseconds>(t).count() —
/// truncates toward zero (USEC1=0, USEC999=0, USEC1500=1 pinned).
pub fn to_usecs(d: HrDuration) -> i64 {
    d / 1000
}

/// C `TO_USECS_FROM_EPOCH(t)` = TO_USECS(t.time_since_epoch()).
pub fn to_usecs_from_epoch(t: HrTime) -> i64 {
    to_usecs(t)
}

/// C `TO_NSECS(t)` = duration_cast<nanoseconds>(t).count() — identity
/// on this clock (NSEC1=1, NSEC999=999 pinned).
pub fn to_nsecs(d: HrDuration) -> i64 {
    d
}

/// C `TO_DURATION(v, t)` = duration_cast<decltype(v)>(microseconds(t))
/// at every production site `v` is an hr_duration, so this converts
/// microsecond values to ns ticks; multiplication is exact (pinned
/// TO_DURATION500=500000).
pub fn to_duration(usecs: i64) -> HrDuration {
    usecs.wrapping_mul(1000)
}

/// C `operator""_ticks`: hr_duration(v) directly.
#[allow(non_snake_case)]
pub fn ticks_literal(v: i64) -> HrDuration {
    v
}
