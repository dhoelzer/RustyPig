#!/usr/bin/env bash
# Ground-truth probe + Catch gate over ORIGINAL time/periodic.cc
# (priority-sorted handler list, period countdown). Upstream ships a
# CATCH_TEST_BUILD suite (TEST_CASE "periodic" [periodic]); gate compiles
# the ORIGINAL .cc with -DCATCH_TEST_BUILD + vendored catch.hpp.
# Zero witness seams needed beyond config.h + snort_types.h + catch shim:
# periodic.cc's only real include is main/snort_types.h (SO_PUBLIC macro).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{time,main,catch}

cp "$SRC"/src/time/{periodic.h,periodic.cc} "$C"/time/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "/opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp" "$C"/catch/

printf '#pragma once\n' > "$C"/config.h

CXXFLAGS="-std=c++17 -O0 -w -I$C"

# gate: ORIGINAL periodic.cc + its embedded CATCH_TEST_BUILD suite
g++ $CXXFLAGS -DCATCH_TEST_BUILD -DCATCH_CONFIG_MAIN -c "$C"/time/periodic.cc -o "$C"/periodic_gate.o
cat > "$C"/catch_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
g++ $CXXFLAGS -c "$C"/catch_main.cc -o "$C"/catch_main.o 2>/dev/null || true
# periodic_gate.o already has CATCH_CONFIG_MAIN via -D above; link directly
g++ "$C"/periodic_gate.o -o "$H"/gate

# probe: plain periodic.o + probe.cc (exercises register ordering,
# countdown, deregistration by pointer identity, re-register)
g++ $CXXFLAGS -c "$C"/time/periodic.cc -o "$C"/periodic.o
g++ $CXXFLAGS -c "$H"/probe.cc -o "$C"/probe.o
g++ "$C"/periodic.o "$C"/probe.o -o "$H"/probe

"$H"/probe > "$H"/vectors.txt
"$H"/gate "[periodic]" > "$H"/gate.txt 2>&1 || { tail -20 "$H"/gate.txt; exit 7; }
tail -1 "$H"/gate.txt
echo "PERIODIC_HARNESS_OK vectors=$(grep -c '' "$H"/vectors.txt)"
