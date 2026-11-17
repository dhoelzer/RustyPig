#!/usr/bin/env bash
# Harness for ORIGINAL utils/chunk.{h,cc} + lua/{lua.h,lua.cc} compiled
# VERBATIM against the locally-built LuaJIT 2.1 (/opt/data/tools/
# luajit-build = /opt/data/cache/scratch/luajit-src). Gate = the
# embedded upstream UNIT_TEST suite in chunk.cc ([chunk], 1 TEST_CASE,
# 6 leaf sections) run under a plain Catch shim (upstream catch/
# snort_catch.h needs main-binary TestCaseInstallers; shim is the
# proven per-harness pattern). ParseError is the ONLY production seam:
# witness prints it (real log/messages.h drags the messaging
# subsystem; upstream's suite has no expectations on it).
#
# vectors.txt pins the init_chunk decision table end-to-end through
# the REAL LuaJIT VM (load/init/args/init-return paths); deterministic
# by construction (pure state machine over fixed inputs).
set -u
H=$(cd "$(dirname "$0")" && pwd); SRC=/opt/data/snort3-src/src
LJ=/opt/data/tools/luajit-src
C="$H/copy"; rm -rf "$C"; mkdir -p "$C"/{utils,lua,catch,log,main}

cp "$SRC"/utils/chunk.h "$SRC"/utils/chunk.cc "$C"/utils/
cp "$SRC"/lua/lua.h "$SRC"/lua/lua.cc "$C"/lua/
grep -v snort_catch "$SRC"/log/messages.h > "$C"/log/messages.h
# main/snort_types.h grafted verbatim (SO_PUBLIC macro; proven pattern)
sed -e 's/#include "log\/log_text.h"//' -e 's/#include "log\/log_api.h"//' "$SRC"/main/snort_types.h > "$C"/main/snort_types.h
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#include "catch/catch.hpp"
EOF
cp "$SRC"/catch/catch.hpp "$C"/catch/catch.hpp

# probe TU (plain chunk.cc) -------------------------------
g++ -std=c++17 -O0 -w -DUNIT_TEST_NO -I"$C" -I"$LJ"/src -c "$C"/utils/chunk.cc -o "$H"/chunk.o || exit 1
g++ -std=c++17 -O0 -w -DUNIT_TEST_NO -I"$C" -I"$LJ"/src -c "$C"/lua/lua.cc -o "$H"/lua.o || exit 1
g++ -std=c++17 -O0 -w -I"$C" -I"$LJ"/src -c "$H"/probe.cc -o "$H"/probe.o || exit 1
cat > "$H"/stubs.cc <<'EOF'
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include "log/messages.h"
namespace snort {
void FatalError(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("FE ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    exit(1);
}
void ParseError(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("PE ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}
} // namespace snort
EOF
g++ -std=c++17 -O0 -w -I"$C" -I"$LJ"/src -c "$H"/stubs.cc -o "$H"/stubs.o || exit 1
g++ -std=c++17 "$H"/probe.o "$H"/chunk.o "$H"/lua.o "$H"/stubs.o \
    "$LJ"/src/libluajit.a -lm -ldl -o "$H"/probe || exit 1
"$H"/probe > "$H"/vectors.txt
[ $? -eq 0 ] && echo "vectors=$(wc -l < "$H"/vectors.txt)"; echo

# gate: chunk.cc with -DUNIT_TEST + main (no stubs needed for gate:
# real ParseError witness links in; upstream suite expects nothing)
cat > "$H"/catch_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
g++ -std=c++17 -O0 -w "$H"/catch_main.cc -c -I"$C" -o "$H"/catch_main.o || exit 1
g++ -std=c++17 -O0 -w -DUNIT_TEST -I"$C" -I"$LJ"/src -c "$C"/utils/chunk.cc -o "$H"/chunk_ut.o || exit 1
g++ -std=c++17 -O0 -w -I"$C" -I"$LJ"/src -c "$C"/lua/lua.cc -o "$H"/lua_ut.o || exit 1
g++ -std=c++17 -O0 -w -I"$C" -I"$LJ"/src -c "$H"/stubs.cc -o "$H"/stubs_ut.o || exit 1
g++ -std=c++17 "$H"/catch_main.o "$H"/chunk_ut.o "$H"/lua_ut.o "$H"/stubs_ut.o \
    "$LJ"/src/libluajit.a -lm -ldl -o "$H"/gate || exit 1
"$H"/gate > "$H"/gate.txt
tail -2 "$H"/gate.txt
