#!/usr/bin/env bash
# Ground-truth probe + Catch gate over ORIGINAL time/stopwatch.h +
# time/clock_defs.h (header-only clock vocabulary + template Stopwatch).
# Gate = the ORIGINAL upstream suite time/test/stopwatch_test.cc (1
# TEST_CASE [time][stopwatch], 12 sections) compiled VERBATIM — it
# injects its own deterministic fake Clock, no production .cc needed,
# ZERO stubs (test includes catch/catch.hpp directly; HAVE_CONFIG_H
# left undefined so it pulls no config.h). The probe pins the
# clock_defs macro layer (TO_TICKS/TO_USECS/TO_NSECS/TO_DURATION/
# TIME_POINT_ZERO/CLOCK_ZERO/_ticks literal/clock_scale/usecs/ticks)
# which upstream never tests, plus the never-started Stopwatch
# start_time default. Non-TSC config (USE_TSC_CLOCK undefined = the
# default build): SnortClock = std::chrono::high_resolution_clock.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{time/test,catch}

cp "$SRC"/src/time/{clock_defs.h,stopwatch.h} "$C"/time/
cp "$SRC"/src/time/test/stopwatch_test.cc "$C"/time/test/
cp "/opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp" "$C"/catch/

# gate: ORIGINAL upstream test verbatim; fake clock keeps it deterministic
g++ -std=c++17 -O0 -w -I"$C" -DCATCH_CONFIG_MAIN -c "$C"/time/test/stopwatch_test.cc -o "$C"/sw_test_gate.o
g++ "$C"/sw_test_gate.o -o "$H"/gate

# probe: deterministic macro-layer pins (no wall-clock reads anywhere)
g++ -std=c++17 -O0 -w -I"$C" -c "$H"/probe.cc -o "$C"/probe.o
g++ "$C"/probe.o -o "$H"/probe

"$H"/probe > "$H"/vectors.txt
wc -l "$H"/vectors.txt
"$H"/gate "[stopwatch]" > "$H"/gate.txt 2>&1 || { tail -20 "$H"/gate.txt; exit 7; }
grep -q "All tests passed" "$H"/gate.txt && tail -2 "$H"/gate.txt | head -1
echo STOPWATCH_HARNESS_OK
