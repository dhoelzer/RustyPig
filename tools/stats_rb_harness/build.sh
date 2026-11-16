#!/usr/bin/env bash
# Ground-truth harness for utils/stats/response_buf.{h,cc}: a
# std::streambuf subclass chunking stats output into <=STD_BUF control
# responses. The ORIGINAL response_buf.cc is compiled verbatim for BOTH:
#  * gate: the upstream suite src/utils/stats/test/response_buf_test.cc
#    (5 [stats_response_buf] Catch2 cases; it brings its own
#    ControlConn/LogMessage implementations, so NO stubs are needed)
#  * probe: response_buf.o verbatim + probe-side witness ControlConn /
#    LogMessage that print every chunk as `RSP len=N ret=R <text>` /
#    `LOG len=N <text>` so flush cadence, fail paths, embedded-NUL
#    truncation and dtor-flush ordering land in vectors.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{utils/stats/test,control,log,main,catch}

cp "$SRC"/src/utils/stats/{response_buf.h,response_buf.cc} "$C"/utils/stats/
cp "$SRC"/src/utils/stats/test/response_buf_test.cc "$C"/utils/stats/test/
cp "$SRC"/src/control/control.h "$C"/control/
cp "$SRC"/src/log/messages.h "$C"/log/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/catch/catch.hpp "$C"/catch/

printf '#pragma once\n' > "$C"/config.h

CXXFLAGS="-std=c++17 -O0 -w -I$C"

# ---- gate: original response_buf.cc + ORIGINAL upstream test verbatim ----
g++ $CXXFLAGS -c "$C"/utils/stats/response_buf.cc -o "$C"/response_buf_gate.o
cat > "$C"/catch_main.cc <<'EOFCM'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOFCM
g++ $CXXFLAGS -c "$C"/catch_main.cc -o "$C"/catch_main.o
g++ $CXXFLAGS -c "$C"/utils/stats/test/response_buf_test.cc -o "$C"/resp_test.o
g++ "$C"/response_buf_gate.o "$C"/resp_test.o "$C"/catch_main.o -o "$H"/gate

# ---- probe: original response_buf.cc + witness conn/log ------------------
g++ $CXXFLAGS -c "$C"/utils/stats/response_buf.cc -o "$C"/response_buf.o
g++ $CXXFLAGS -c "$H"/probe.cc -o "$C"/probe.o
g++ "$C"/response_buf.o "$C"/probe.o -o "$H"/probe

"$H"/probe > "$H"/vectors.txt
"$H"/gate "[stats_response_buf]" > "$H"/gate.txt 2>&1 || { tail -20 "$H"/gate.txt; exit 7; }
tail -1 "$H"/gate.txt
echo "STATS_RB_HARNESS_OK vectors=$(grep -c '' "$H"/vectors.txt)"
