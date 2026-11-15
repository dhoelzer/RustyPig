#!/usr/bin/env bash
# Ground-truth harness for parser/parse_so_rule.cc.
# Two binaries:
#  1) catch gate: ORIGINAL parse_so_rule.cc compiled -DUNIT_TEST with the
#     vendored catch.hpp so the upstream TEST_CASEs (syntax/basic/stub
#     tables) run as a semantic gate.
#  2) probe: ORIGINAL parse_so_rule.cc merged (single TU, sed only flips
#     `private:` to `public:` -- access control, no semantic change) with
#     probe code that replays every upstream table input plus extras
#     through parse_so_rule (stub AND opts channels visible) and
#     get_so_stub, emitting escaped IN/R/STUB/OPTS/GETSTUB vectors.
# Zero snort runtime deps beyond snort_types.h.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{parser,catch,main}

cp "$SRC"/src/parser/parse_so_rule.cc "$C"/parser/
cp "$SRC"/src/parser/parse_so_rule.h "$C"/parser/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/catch/{catch.hpp,snort_catch.h} "$C"/catch/

# --- catch gate (pristine original + UNIT_TEST) ---
cat > "$H"/catch_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
g++ -std=c++17 -O0 -DUNIT_TEST -I"$C" -o "$H/catchprobe" \
  "$H"/catch_main.cc "$C"/parser/parse_so_rule.cc "$H"/installer_stub.cc
"$H/catchprobe" 2>&1 | tail -5 | grep -q "All tests passed" && echo CATCH_GATE_OK

# --- probe (merged TU) ---
sed 's/^private:/public:/' "$C"/parser/parse_so_rule.cc > "$H"/merged.cc
cat "$H"/probe_tail.cc >> "$H"/merged.cc
# probe keeps UNIT_TEST so the original TEST_CASE bodies + table data are
# real objects; CHECK symbols are satisfied by catchrunner.cc and the
# TestCaseInstaller ctor by installer_stub.cc, but nothing runs the
# Catch session -- main() drives the tables directly.
g++ -std=c++17 -O0 -DUNIT_TEST -I"$C" -I"$C"/parser -o "$H"/probe \
  "$H"/merged.cc "$H"/catchrunner.cc "$H"/installer_stub.cc
"$H"/probe > "$H"/vectors.txt 2>/dev/null
cat "$H"/vectors.txt
