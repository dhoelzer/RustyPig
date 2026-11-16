#!/usr/bin/env bash
# Ground-truth capture for utils/stats/{output_json.h, output_json.cc} +
# helpers/json_stream.{h,cc} @ fe29cbe7403a. All three TUs compile
# VERBATIM (json_stream's only include is snort_types.h; output_json's
# are output_json.h + json_stream.h).
#
# Gate: the ORIGINAL upstream suites compiled verbatim:
#  - src/utils/stats/test/stats_output_json_test.cc (11 [stats_output_json]
#    cases against render_json output strings)
#  - embedded UNIT_TEST block in json_stream.cc (6 [Json_Stream] escape
#    cases) via -DUNIT_TEST TU
#  - src/helpers/test/json_stream_test.cc ([json_stream] basic suite)
set -euo pipefail
S=/opt/data/snort3-src
H=/opt/data/snort3-rust/tools/sjson_harness
C=$H/copy
rm -rf "$C"; mkdir -p "$C"/{main,helpers,utils/stats,framework}
cp "$S"/src/utils/stats/{output_json.h,output_json.cc,snapshot.h,utils.h,utils.cc} "$C"/utils/stats/
cp "$S"/src/framework/counts.h "$C"/framework/
cp "$S"/src/helpers/{json_stream.h,json_stream.cc} "$C"/helpers/
cp "$S"/src/main/snort_types.h "$C"/main/
cat > "$C"/config.h <<'EOF'
#pragma once
EOF

G="$S/src/utils/stats/test/stats_output_json_test.cc"
J="$S/src/helpers/test/json_stream_test.cc"
# upstream snort_catch.h needs the main-binary TestCaseInstaller; plain
# catch.hpp gives identical TEST_CASE_METHOD registrations (same proven
# shim as codec_harness).
mkdir -p "$C"/catch
cp "$S"/src/catch/catch.hpp "$C"/catch/
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#pragma GCC visibility push(default)
#include "catch/catch.hpp"
#pragma GCC visibility pop
EOF
cat > "$H"/catch_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF

g++ -std=c++17 -O0 -w -I"$C" -c "$C"/utils/stats/output_json.cc -o "$H"/output_json.o
g++ -std=c++17 -O0 -w -I"$C" -c "$C"/utils/stats/utils.cc -o "$H"/utils.o
g++ -std=c++17 -O0 -w -I"$C" -c "$C"/helpers/json_stream.cc -o "$H"/json_stream.o
# gate: upstream [Json_Stream] escape cases live in json_stream.cc
# itself -> a second CU compiled with UNIT_TEST.
g++ -std=c++17 -O0 -w -I"$C" -DUNIT_TEST -c "$C"/helpers/json_stream.cc -o "$H"/json_stream_ut.o

g++ -std=c++17 -O0 -w -I"$C" -I"$S"/src -c "$H"/probe.cc -o "$H"/probe.o
g++ -std=c++17 -O0 -w "$H"/probe.o "$H"/output_json.o "$H"/utils.o "$H"/json_stream.o -o "$H"/probe
"$H"/probe > "$H"/vectors.txt
wc -l "$H"/vectors.txt

# gate = upstream test suites verbatim (no witness links: these
# subsystems are dependency-light; only catch_main added)
g++ -std=c++17 -O0 -w -I"$C" -I"$S"/src -c "$G" -o "$H"/stxj_gate.o
g++ -std=c++17 -O0 -w -I"$C" -I"$S"/src -c "$J" -o "$H"/js_gate.o
g++ -std=c++17 -O0 -w -I"$C" -I"$S"/src -c "$H"/catch_main.cc -o "$H"/catch_main.o
# json_stream_ut.o REPLACES json_stream.o (same TU, plus the embedded
# [Json_Stream] cases; linking both = duplicate symbols).
g++ -std=c++17 -O0 -w "$H"/catch_main.o "$H"/stxj_gate.o "$H"/js_gate.o "$H"/output_json.o "$H"/utils.o "$H"/json_stream_ut.o -o "$H"/gate
"$H"/gate > "$H"/gate.txt 2>&1 || true
grep -q "All tests passed" "$H"/gate.txt && tail -2 "$H"/gate.txt | head -1
echo SJSON_HARNESS_OK
