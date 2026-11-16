// Ground-truth probe for ORIGINAL time/stopwatch.h + time/clock_defs.h
// (compiled verbatim; the harness build is the DEFAULT config:
// USE_TSC_CLOCK undefined, so SnortClock is
// std::chrono::high_resolution_clock and clock_scale()==1). The
// upstream suite only exercises the template through its own fake
// clock; this probe pins the real macro layer production uses: the
// TO_* conversions, TIME_POINT_ZERO/CLOCK_ZERO/DURA_ZERO, the
// _ticks literal, clock_scale/clock_usecs/clock_ticks.
// DETERMINISM: no wall-clock tick VALUES are ever printed — only
// literal-derived conversions and state-machine booleans;
// start/stop pairs observe active-ness, start_time stability, and
// the zero-state of a never-started/reset stopwatch (always exactly
// DURA_ZERO regardless of the clock). printf hygiene: side effects
// land in locals before any printf.
#include <cstdio>
#include "time/clock_defs.h"
#include "time/stopwatch.h"

// NOTE: DURA_ZERO is literally `Clock::duration::zero()` and only
// compiles where a `Clock` name is in scope (inside Stopwatch the
// template parameter supplies it). The probe therefore compares
// against the equivalent literal `0_ticks` rather than fabricating a
// file-scope Clock alias upstream does not define.

int main()
{
    // clock vocabulary: hr_clock rep is signed int64 nanoseconds on
    // libstdc++ x86-64; conversions from literal ticks are exact.
    auto d1 = 1_ticks;
    long t1 = TO_TICKS(d1);
    long u1 = TO_USECS(d1);
    long n1 = TO_NSECS(d1);
    printf("TICK1=%ld USEC1=%ld NSEC1=%ld\n", t1, u1, n1);

    // TO_USECS truncates toward zero (duration_cast truncates)
    auto d3 = 999_ticks;
    long u3 = TO_USECS(d3);
    long n3 = TO_NSECS(d3);
    printf("USEC999=%ld NSEC999=%ld\n", u3, n3);

    auto d4 = 1500_ticks;
    long u4 = TO_USECS(d4);
    printf("USEC1500=%ld\n", u4);

    // TO_DURATION(v, t): duration_cast into v's duration type over
    // microseconds(t)
    hr_duration v = 0_ticks;
    long tdt = TO_TICKS(TO_DURATION(v, 500));
    printf("TO_DURATION500=%ld\n", tdt);

    // TIME_POINT_ZERO == time_point::min(): epoch count is the most
    // negative representable duration (deterministic constant)
    auto tp0 = TIME_POINT_ZERO;
    long long ep0 = (long long)tp0.time_since_epoch().count();
    printf("TPEPOCHMIN=%lld\n", ep0);

    // CLOCK_ZERO == 0_ticks; DURA_ZERO == duration 0
    long cz = TO_TICKS(CLOCK_ZERO);
    long dz = TO_TICKS(0_ticks);
    printf("CZ=%ld DZ=%ld\n", cz, dz);

    // inline scale helpers (scale == 1 in the default config)
    long cs = clock_scale();
    long cu = clock_usecs(1000000);
    long ct = clock_ticks(1000000);
    printf("SCALE=%ld USECS=%ld TICKS=%ld\n", cs, cu, ct);

    // ClockTraits alias for SnortClock
    ClockTraits<SnortClock>::duration td(123);
    long tdt2 = td.count();
    printf("CTRAITS=%ld\n", tdt2);

    // Stopwatch<SnortClock> state machine on the REAL clock: booleans
    // and zero-states only, never a tick value read mid-flight.
    Stopwatch<SnortClock> sw;
    int a0 = (int)sw.active();
    int g0 = (sw.get() == 0_ticks);
    sw.start();
    int a1 = (int)sw.active();
    auto st1 = sw.get_start_time();
    sw.start(); // start while running: no effect
    int a2 = (int)sw.active();
    auto st2 = sw.get_start_time();
    int same_start = (st1 == st2);
    sw.stop();
    int a3 = (int)sw.active();
    sw.stop(); // stop when stopped: no effect
    int a4 = (int)sw.active();
    sw.reset();
    int a5 = (int)sw.active();
    int g5 = (sw.get() == 0_ticks);
    sw.start();
    int a6 = (int)sw.active();
    sw.cancel(); // cancel: running off, accumulated elapsed KEPT
    int a7 = (int)sw.active();
    printf("SW a0=%d g0=%d a1=%d a2=%d same12=%d a3=%d a4=%d a5=%d g5=%d a6=%d a7=%d\n",
        a0, g0, a1, a2, same_start, a3, a4, a5, g5, a6, a7);

    // cancel-keeps-elapsed is only observable via the fake path; on
    // the real clock just pin that after cancel the get() is stable
    // across repeated reads (stopped clock frozen).
    long long x1 = sw.get().count();
    long long x2 = sw.get().count();
    printf("CANCELSTABLE=%d\n", (int)(x1 == x2));

    printf("DONE\n");
    return 0;
}
