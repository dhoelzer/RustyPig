#!/usr/bin/env bash
# Ground-truth capture for utils/util_jsnorm.{h,cc} @ fe29cbe7403a.
# The TU compiles VERBATIM (includes: util_jsnorm.h -> snort_types.h,
# ctype/cstdlib/cstring/vector only -- zero log/config coupling).
#
# Gate: embedded UNIT_TEST Catch block (2 [util_jsnorm] cases) via a
# -DUNIT_TEST CU, plus plain CU for the probe (gate links the UT CU in
# place of the plain one -- proven same-TU rule).
set -euo pipefail
S=/opt/data/snort3-src
H=/opt/data/snort3-rust/tools/jsnorm_harness
C=$H/copy
rm -rf "$C"; mkdir -p "$C"/{main,utils,catch}
cp "$S"/src/utils/{util_jsnorm.h,util_jsnorm.cc} "$C"/utils/
cp "$S"/src/main/snort_types.h "$C"/main/
cp "$S"/src/catch/catch.hpp "$C"/catch/
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#pragma GCC visibility push(default)
#include "catch/catch.hpp"
#pragma GCC visibility pop
EOF
cat > "$C"/config.h <<'EOF'
#pragma once
EOF
cat > "$H"/catch_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF

g++ -std=c++17 -O0 -w -I"$C" -c "$C"/utils/util_jsnorm.cc -o "$H"/jsnorm.o
g++ -std=c++17 -O0 -w -I"$C" -DUNIT_TEST -c "$C"/utils/util_jsnorm.cc -o "$H"/jsnorm_ut.o

g++ -std=c++17 -O0 -w -I"$C" -c "$H"/probe.cc -o "$H"/probe.o
g++ -std=c++17 -O0 -w "$H"/probe.o "$H"/jsnorm.o -o "$H"/probe
"$H"/probe > "$H"/vectors.txt
wc -l "$H"/vectors.txt

g++ -std=c++17 -O0 -w -I"$C" -c "$H"/catch_main.cc -o "$H"/catch_main.o
# jsnorm_ut.o REPLACES jsnorm.o in the gate (same TU + suite)
g++ -std=c++17 -O0 -w "$H"/catch_main.o "$H"/jsnorm_ut.o -o "$H"/gate
"$H"/gate > "$H"/gate.txt 2>&1 || true
grep -q "All tests passed" "$H"/gate.txt && tail -2 "$H"/gate.txt | head -1
echo JSNORM_HARNESS_OK
