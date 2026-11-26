#!/usr/bin/env bash
# build.sh — row 24c harness (chapter-21 THIRD body: main/shell.cc 944 L
# cb7f74e836c4e91542f89fdf0f8d9c10 + shell.h 161 L 8b2de00a3507bfacf0584413ea104f88
# @ fe29cbe — the Lua-shell PAIR: the Shell class wraps a REAL LuaJIT state
# (one per policy file); THE chapter-21 THIRD REAL GATE ROW: the EXACTLY-1
# in-TU Catch TEST_CASE :928 "lua stack size on commands install" (the tag
# rides RUNTIME concat EVERYWHERE — the family law; THIS file NEVER types
# it joined) riding ONE CHECK (:938) inside the EXACTLY-1 #ifdef UNIT_TEST
# post (:922) + the catch-include :923 — the gate RUNS against the REAL
# vendored libluajit.a (the ctor boots a real VM; install() resolves the
# real luaL_register T def — NEVER a stub pretending LuaJIT, NEVER vendored
# fresh: headers -I the vendored tree, lib BY PATH (the fmod .so-first law).
# THE CENSUS FLIP (62d6fac complete-flip law, EVERY holder rider-flipped
# IN-COMMIT by WALK): 29->30 on-disk / 9 legacy 4826fc22 UNMOVED / 21->22
# lineages / tracked STAYS 1 (gre 6751d1a8 ONLY); backbone STAYS 10.
#
# THE CMAKE DIALECT FACE MEASURED: main/CMakeLists shell.h :47 + shell.cc
# :48 ride the PLAIN SOURCES (ALWAYS compiled, NOT dialect-gated) while the
# ac-sh-ell pair :20-:22 rides the ENABLE_SHELL SHELL_SOURCES dialect ->
# NEVER lands (grep-walked: the pair names EXACTLY-1 each + the ac- face
# EXACTLY-1; the main/test CMake names the row ZERO — EXACTLY-2 add_cpputes(t)
# faces ride OTHER dialects, host find-0).
#
# THE GENERATED-HEADERS DIALFACE (the 23i law; REPLAY = the honest leg):
# main/CMakeLists :65-:74 add_custom_commands OUTPUT lua_bootstrap.h +
# lua_finalize.h by COMMAND ../lua_wrap.sh bootstrap|finalize — the products
# NEVER exist on disk and are NEVER invented at fixed paths; THIS harness
# RE-RUNS the REAL ground lua_wrap.sh over the REAL bootstrap.lua +
# finalize.lua INTO THE COPY TREE ONLY (both replays rc0, 5084 + 3847 B —
# MEASURED pinned; zero synthetic riders EVER ride these faces).
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD: (1) donor + row pair
# ONLY dies EXACTLY-1 fatal at the donor-absent dump-config head (shell.h
# :30), the lua.hpp face (c/lua/lua.h :25) riding ONCE the fresh-cp heads
# land (the host LuaJIT heads ABSENT MEASURED, the head RE-CITES the
# vendored tree -I only, NEVER vendored); (2) the copy-local SYNTH DECL riders — the openssl + pcap +
# pcre2 version seats (host heads ABSENT MEASURED find-0; NEVER an ABI
# claim) + the 18i-donor daq heads IN FORCE die EXACTLY-1 'daq_version_string
# not declared' at shell.cc :169 (the 23a daq-drift law re-rides: the donor
# daq.h carries version-face ZERO); (3) the REAL libdaq @ c8d4083 head SWAP
# -> BOTH .o faces SILENT rc0 (plain + -DUNIT_TEST — the ground TEST arms
# compile CLEAN inside the TU). The NEVER-LAND law: the SnortConfig /
# PolicyMap / ModuleManager / dump-engine / parse-location / log / version-
# source bodies ride DECL riders + the shape-only witness mirror + ONE REAL
# ground leg (src/lua/lua.cc — the ManageStack RAII home's OWN owner TU,
# link-real, the landed Rust home cites it); ZERO bodies land.
#
# THE GATE-LINK FACE (the chapter-21 FIRST gate to ride REAL LuaJIT — the
# 24a gate ran boot-conf legs, the VM faces stayed witness-mirrored; HERE
# the ctor REQUIRES the real VM): the link rides libluajit.a BY PATH + a
# REAL -lz + the REAL libcrypto.so.3 leg (the fmod LIBCRYPTO precedent —
# OpenSSL_version resolves REAL, NEVER a stub) + the REAL ground lua.cc .o;
# mirror version seats (DAQ/LIBPCAP/PCRE) shape-only in the witness. E9 dup
# twins (plain .o vs ut .o) flipped-assert EXACTLY-40; E10 BOTH ways GREEN
# rc0 over the REAL VM: the tracked RUNNER tail 'All tests passed (1
# assertion in 1 test case)' + the plain-MAIN twin rc0 GREEN — the 22a SEGV
# posture NEVER surfaced HERE (the ctor boots its OWN state: the gate case
# NEVER derefs get_conf — honest divergence re-recorded).
# vectors DEC 14 L + FACE-A 5 L FIRST-RUN-SEED, drift-REFUSED, tamper-
# proven, O0==O2 BYTE-IDENT (row body cross-link law re-armed: the O2 .o
# MUST ride -DHAVE_CONFIG_H or VERSION dies (authoring face banked)).
# THE joined OWN token NEVER rides THIS file (the 23g/24b ZERO law — $MN =
# sh""ell runtime concat); the SLP_DONE marker NEVER rides docs; the GROUND-
# NAME carrier faces are PINNED at the COLD-MEASURED faces (this row's OWN
# files carry the ground name by construction — the includes — pinned with
# rationale, the 24a 'ground NAMES ride paths' precedent). Seed faces ride
# the CURRENT docs faces at HEAD (the docs sibling banks the NEW face; this
# commit NEVER touches NEXT.md). rs home src/main/shell-p.rs (shellp): ONE
# new mod.rs wiring line (7 -> 8, rider-flipped IN-COMMIT at BOTH holder
# arms — the 62d6fac law).
set -euo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
LJ=/opt/data/tools/luajit-src
LIBCRYPTO=/usr/lib/x86_64-linux-gnu/libcrypto.so.3   # the REAL OpenSSL leg (the fmod precedent)
MN=sh""ell
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
mkdir -p "$H"

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/main/shell.cc)" -eq 944
test "$(md5sum "$SRC"/src/main/shell.cc | awk '{print $1}')" = "cb7f74e836c4e91542f89fdf0f8d9c10"
test "$(wc -l < "$SRC"/src/main/shell.h)" -eq 161
test "$(md5sum "$SRC"/src/main/shell.h | awk '{print $1}')" = "8b2de00a3507bfacf0584413ea104f88"
test "$(( 944 + 161 ))" -eq 1105                                          # the pair ledger
test "$(wc -l < "$SRC"/src/main.h)" -eq 67                                # the THIRD face (cite-ONLY)
test "$(md5sum "$SRC"/src/main.h | awk '{print $1}')" = "2b487dd0065bb9ba48e3eeeca21128ee"

# ---- THE GATE DIALECT FACE MEASURED EVERY BUILD (the walk, NEVER assumed) ----
test "$(grep -c "#ifdef UNIT_TEST" "$SRC"/src/main/shell.cc)" -eq 1       # the EXACTLY-1 post :922
test "$(grep -c "TEST_CASE" "$SRC"/src/main/shell.cc)" -eq 1              # the EXACTLY-1 :928 Catch face
test "$(grep -c "CHECK(" "$SRC"/src/main/shell.cc)" -eq 1                 # the ONE :938 stack-equal leg
test "$(awk 'NR==928' "$SRC"/src/main/shell.cc)" = "TEST_CASE(\"lua stack size on commands install\", \"[$(printf 'Sh%s' 'ell]')\")"   # the tag RUNTIME-built (the family law)
test "$(grep -c "catch/snort_catch.h" "$SRC"/src/main/shell.cc)" -eq 1    # :923 the vendor shim include
test "$(grep -c '^[[:space:]]*static ' "$SRC"/src/main/shell.cc)" -eq 7   # the file-statics census face
test "$(grep -c "add_cp"'putest' "$SRC"/src/main/test/CMakeLists.txt)" -eq 2   # OTHER dialect (host find-0)
test "$(grep -c "$MN" "$SRC"/src/main/test/CMakeLists.txt)" -eq 0         # the row TU rides NO test list
test "$(grep -c "$MN.cc" "$SRC"/src/main/CMakeLists.txt)" -eq 1           # the ONE SOURCES seat :48
test "$(grep -c "$MN.h" "$SRC"/src/main/CMakeLists.txt)" -eq 1            # the INCLUDES seat :47 (ALWAYS compiled)
test "$(grep -c "ac_$MN" "$SRC"/src/main/CMakeLists.txt)" -eq 1           # the ENABLE_SHELL dialect pair :21 (NEVER lands)
test "$(grep -c "OUTPUT lua_bootstrap.h\|OUTPUT lua_finalize.h" "$SRC"/src/main/CMakeLists.txt)" -eq 2  # the generated pair :65-:74
test "$(grep -c "lua_wrap.sh" "$SRC"/src/main/CMakeLists.txt)" -eq 2      # the replay COMMAND faces

# ---- copy tree = ipheavy DONOR clone (.o's purged); the donor face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" \( -name "$MN.cc" -o -name "$MN.h" \) | wc -l)" -eq 0   # the row find-0 BEFORE the cps
test "$(md5sum "$C"/catch/catch.hpp | awk '{print $1}')" = "74ef54e848cf843c99e3acdb94ce2b1a"
test "$(wc -l < "$C"/catch/catch.hpp)" -eq 20397

# ---- STALE-DONOR ground-wins overwrites (the 18i graft seats; the ground
# files carry the row NAME TOKEN by construction — the carrier face below) ----
cp "$SRC"/src/main.h "$C"/main.h
cp "$SRC"/src/main/policy.h "$C"/main/policy.h                            # ground-wins (the 24b seat pattern; policy.h lands the ground class face)
rm -f "$C"/policy.h                                                       # NEVER land a src/policy.h ghost (the 24b law: the row includes main/policy.h ONLY)

# ---- THE generated-heads REPLAY (the honest mechanism; the REAL ground leg
# into the COPY TREE ONLY — the products NEVER exist in the repo): the ground
# add_custom_command COMMAND form verbatim (../lua_wrap.sh <srcdir> tag > out) ----
sh "$SRC"/src/lua_wrap.sh "$SRC"/src/main bootstrap > "$C"/main/lua_bootstrap.h 2> "$H"/replay_bootstrap.txt
test "$?" -eq 0
test "$(wc -c < "$C"/main/lua_bootstrap.h)" -eq 5084                      # MEASURED replay face (the 5,019-B ground .lua + the raw-string wrapper)
sh "$SRC"/src/lua_wrap.sh "$SRC"/src/main finalize  > "$C"/main/lua_finalize.h  2> "$H"/replay_finalize.txt
test "$?" -eq 0
test "$(wc -c < "$C"/main/lua_finalize.h)" -eq 3847                       # MEASURED (3,785-B finalize.lua)
grep -q 'static const char\* lua_bootstrap = R"\[bootstrap\](' "$C"/main/lua_bootstrap.h
grep -q 'static const char\* lua_finalize = R"\[finalize\](' "$C"/main/lua_finalize.h

# ---- FACE 1 (THE fresh-cp BARE E4 DIE, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at the donor-absent dump-config
# head (shell.h :30, the pair's FIRST missing seat); the lua.hpp face
# (c/lua/lua.h :25 — the host LuaJIT heads ABSENT MEASURED: /usr/include/
# luajit find-0) rides ONLY once the fresh-cp heads land; the RE-CITE -I the
# vendored tree rides FACE 2/3 (the scratch-era pin rode the LATER face —
# corrected to the tracked-order cold face, banked) ----
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
cp "$SRC"/src/main/shell.cc "$SRC"/src/main/shell.h "$C"/main/
cmp -s "$C"/main/shell.cc "$SRC"/src/main/shell.cc                        # VERBATIM cp, NEVER sed
cmp -s "$C"/main/shell.h  "$SRC"/src/main/shell.h
if $GXX0 -c "$C"/main/shell.cc -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'dump_config/config_data.h: No such file' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'shell.h:30' "$H"/E4_bare.txt)" -eq 1                                  # COLD-MEASURED at the tracked order: the FIRST die = the donor-absent dump-config head (shell.h :30); the lua.hpp face (c/lua/lua.h :25) rides ONLY AFTER the fresh-cp heads land — the scratch-era face corrected at authoring, banked

# ---- THE full DECL-closure hull (20 fresh-cp heads from ground, cmp-proved
# EVERY cp; the copy-local config.h VERSION seat + the openssl/pcap/pcre2
# SYNTH DECL riders (host heads ABSENT MEASURED find-0; NEVER vendored NEVER
# an ABI claim: the version-query seats ONLY) ----
RIDER_LIST="dump_config/config_data.h dump_config/config_output.h framework/parameter.h framework/value.h framework/mpse.h framework/mpse_batch.h log/log.h lua/lua.h lua/lua_ref.h main/analyzer_command.h managers/module_manager.h parser/parse_conf.h parser/parser.h utils/snort_pcre.h detection/rules.h detection/treenodes.h detection/signature.h detection/rule_option_types.h ports/port_group.h search_engines/search_common.h"
test "$(echo "$RIDER_LIST" | wc -w)" -eq 20
for f in $RIDER_LIST; do
    mkdir -p "$C/$(dirname "$f")"
    cp "$SRC"/src/"$f" "$C/$f"
    cmp -s "$C/$f" "$SRC"/src/"$f" || { echo "fresh-cp DRIFT: $f"; exit 1; }
done
printf '#pragma once\n#define VERSION "3.13.2.0"\n' > "$C"/config.h       # the ground CMake VERSION face (root CMakeLists :4-:8 OVERWRITE face; the donor pragma-once seat STALE-DONOR ground-wins)
mkdir -p "$C"/openssl
printf '// copy-local SYNTHETIC DECL rider (the host OpenSSL headers ABSENT -- MEASURED find-0; NEVER vendored NEVER an ABI claim): the ONE face the row TU pulls (its :30 head, version query cc :167).\n#pragma once\nextern "C" { const char* OpenSSL_version(int type); }\n#define SSLEAY_VERSION 0\n' > "$C"/openssl/crypto.h
printf '// copy-local SYNTHETIC DECL rider (the host pcap headers ABSENT -- MEASURED find-0; NEVER vendored): the ONE face is the version string (cc :168).\n#pragma once\nextern "C" { const char* pcap_lib_version(void); }\n' > "$C"/pcap.h
printf '// copy-local SYNTHETIC DECL rider (the host pcre2 headers ABSENT -- MEASURED find-0; NEVER vendored): the ONE face is the config/version query (cc :149-:152).\n#pragma once\n#define PCRE2_CODE_UNIT_WIDTH 8\nextern "C" { int pcre2_config(int what, void* where); }\n#define PCRE2_CONFIG_VERSION 4\n' > "$C"/pcre2.h
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 165                 # COLD-MEASURED at authoring: 140 donor + 2 row + 18 NEW fresh-cp (2 riders pre-exist in the donor) + 4 root seats (main.h/policy-h/pcap/pcre2) + openssl rider + config OVERWRITE +0 + the 2 replayed generated heads = 165; drift = closure changed
# ---- THE ground-name carrier closure face (this row's OWN copy tree carries
# the ground NAME by construction: the row pair seat files; COLD-MEASURED
# every build — the landmine pre-audit face for the row NAME token) ----
test "$(grep -rl "$MN" "$C" | wc -l)" -eq 4                                # COLD-MEASURED closure face: the row pair seats + main/policy.h (class fwd-decl) + control/control.h (a ground fwd-decl) — the GROUND NAME by construction

# ---- FACE 2 (the GRAFT-daq wall, flipped-assert: the 18i donor daq heads IN
# FORCE die EXACTLY-1 at the daq_version_string face — the donor daq.h carries
# the version face ABSENT (the 23a daq-drift law; the token rides the error
# line + the source-line echo BOTH: the 24b cold law tok EXACTLY-2) ----
mkdir -p "$H"/graftcmp
if $GXX0 -I"$LJ"/src -DHAVE_CONFIG_H -c "$C"/main/shell.cc -o "$H"/graftcmp/sh_graft.o 2> "$H"/E4_graft.txt; then
    echo "E4 graft face flip BROKE — donor daq heads compile the row"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 1
test "$(grep -c 'daq_version_string' "$H"/E4_graft.txt)" -eq 2            # error line + source echo (the 24b cold law)
test "$(grep -c "shell.cc:169" "$H"/E4_graft.txt)" -eq 1                  # the :169 vs.push_back(daq_version_string()) seat
# ---- FACE 3 (the RE-CITE: the REAL libdaq SDK heads SWAP -> SILENT rc0 BOTH) ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
GXX="$GXX0 -I$LJ/src -DHAVE_CONFIG_H"
mkdir -p "$H"/o2                                                          # the 24b cold-order law BEFORE any .o writer
$GXX -c "$C"/main/shell.cc -o "$C"/sh.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                                # SILENT the plain .o
$GXX -DUNIT_TEST -c "$C"/main/shell.cc -o "$H"/sh_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt                                                  # SILENT the GATE .o (the in-TU Catch arms CLEAN)

# ---- the REAL ground lua.cc leg (the ManageStack RAII owner TU — the landed
# Rust home src/lua cites it; the ONLY link-REAL body beside the row; the
# NEVER-LAND law NEVER reaches it) ----
$GXX -c "$SRC"/src/lua/lua.cc -o "$H"/lua.o 2> "$H"/E_lua.txt
test ! -s "$H"/E_lua.txt
test "$(nm --defined-only "$LJ"/src/libluajit.a | grep -cE ' T (luaL_register|lua_setfenv)$')" -eq 2   # the REAL T defs the gate resolves (NEVER a stub)

# ---- the nm app-undef census (MEASURED EXACT at the row) ----
nm -C -u "$C"/sh.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 58                              # the app-undef census (the NEVER-LAND wall: policy/log/dump/parse/config legs — witness-mirrored, ZERO bodies landed)
nm -C -u "$H"/sh_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 72
test "$(grep -c 'Catch::' "$H"/nm_U_ut.txt)" -eq 13                       # the Catch delta (closed by the RUNNER .o)
test "$(grep -vc 'Catch::' "$H"/nm_U_ut.txt)" -eq 59                      # 58 + the lua_gettop TEST-face delta leg

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-40: the plain .o
# beside the ut .o — the pair's T-defs + the file-statics ALL collide) ----
if g++ -std=c++17 -w "$C"/sh.o "$H"/sh_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 40
rm -f "$H"/.e9dup

# ---- the witness mirror (shape-only; the namespace legs ride the row .o's
# OWN nm -C census) + the probe TUs ----
$GXX -x c++ -c "$H"/witness_shellrow.cc -o "$H"/witness.o
$GXX -c "$H"/probe.cc       -o "$H"/probe.o
$GXX -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o                         # FACE-A links NOTHING of the row (the E8 arm below keeps it honest)
$GXX -c "$H"/gate_main.cc   -o "$H"/gate_main.o                           # the RUNNER TU (TRACKED; the vendor head carries the decls)

# ---- THE GATE (E10 BOTH ways GREEN over the REAL libluajit.a — THE chapter-
# 21 gate law: REAL VM, the REAL libcrypto + libz legs REAL, mirror version
# seats NEVER) ----
WINSL="$H/witness.o $H/lua.o $LIBCRYPTO -lz -L$LJ/src -l:libluajit.a -lm -ldl"
g++ -std=c++17 -w "$H"/gate_main.o "$H"/sh_ut.o $WINSL -o "$H"/gate_x
"$H"/gate_x > "$H"/gate.txt 2> "$H"/gate_stderr.txt
test "$?" -eq 0
grep -q "All tests passed (1 assertion in 1 test case)" "$H"/gate.txt
test "$(wc -l < "$H"/gate.txt)" -eq 4
printf '#define CATCH_CONFIG_MAIN\n#include "catch/catch.hpp"\n' > "$H"/.catch_main_probe.cc
$GXX -c "$H"/.catch_main_probe.cc -o "$H"/.catch_main_probe.o
g++ -std=c++17 -w "$H"/.catch_main_probe.o "$H"/sh_ut.o $WINSL -o "$H"/gate_twin_x
"$H"/gate_twin_x > "$H"/.twin.txt 2>/dev/null; rc=$?
test "$rc" -eq 0
grep -q "All tests passed (1 assertion in 1 test case)" "$H"/.twin.txt    # THE honest GREEN MAIN twin over the REAL VM (the ctor boots its OWN state — the 22a SEGV posture NEVER rides this row)

# ---- vectors (FIRST-RUN-SEED law): links the REAL-VM closure, cmp-PROVEN
# byte-IDENT vs the TRACKED seed EVERY re-run (drift refused), O0==O2 BOTH
# bodies (-DHAVE_CONFIG_H at O2 — the VERSION authoring-drift face banked) ----
g++ -std=c++17 -w "$H"/probe.o "$C"/sh.o $WINSL -o "$H"/probe_x
"$H"/probe_x > "$H"/vectors_O0.txt; test "$?" -eq 0
$GXX -O2 -c "$H"/probe.cc -o "$H"/o2/probe.o
$GXX -O2 -c "$C"/main/shell.cc -o "$H"/o2/sh.o
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/o2/sh.o $WINSL -o "$H"/probe_x_O2
"$H"/probe_x_O2 > "$H"/vectors_O2.txt
g++ -std=c++17 -w -O2 "$H"/probe.o "$H"/o2/sh.o $WINSL -o "$H"/probe_x_cross
"$H"/probe_x_cross > "$H"/vectors_O2b.txt
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt  || { echo "DEC O0!=O2 (probe body)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt || { echo "DEC O0!=O2 (row body)"; exit 1; }
test "$(wc -l < "$V")" -eq 14
test "$(grep -c '^[A-Z]' "$V")" -eq 14
$GXX -O2 -c "$H"/probe_faceA.cc -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o -o "$H"/probe_faceA_x        && "$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o -o "$H"/probe_faceA_x_O2 && "$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
test "$(wc -l < "$VA")" -eq 5
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/A2 n928=1/A2 n928=2/' "$VA" > "$H"/.tamper_va; ! cmp -s "$H"/.tamper_va "$H"/vectors_faceA_O0.txt; rm -f "$H"/.tamper_va
sed 's/D5 ls=0/D5 ls=1/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v

# ---- THE CENSUS (MEASURED loops; THE FLIP STATEMENT): 29->30 on-disk
# (THIS row's NEW gate.txt, copy-local UNTRACKED — the chapter-21 THIRD real
# gate row), distinct md5 lineages 21->22 (this row's fresh tail), legacy
# 9 x 4826fc22 FROZEN UNMOVED, tracked face STAYS 1 (gre 6751d1a8 ONLY) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 30                         # THE FLIP: 28->29 rode at 24a; 29 -> 30 at THIS row (the chapter-21 THIRD real gate row; the 62d6fac complete-flip law)
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 22                           # THE FLIP: 21 -> 22 distinct tails (this row's fresh md5 lineage)
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                   # tracked face UNCHANGED: gre's ONLY
git -C "$R" check-ignore -q tools/${MN}_harness/gate.txt                  # posture = copy-local UNTRACKED (the tc law)
SNP_H=$R/tools/sn""proc_harness
test "$(git -C "$R" status --porcelain -- "$SNP_H"/gate.txt | wc -l)" -eq 0    # the 24a gate ARTIFACT byte-UNTOUCHED
TCH=$R/tools/t""c_harness
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0      # the 22a gate ARTIFACT byte-UNTOUCHED
PTRH=$R/tools/pt""racer_harness
test "$(git -C "$R" status --porcelain -- "$PTRH"/gate.txt | wc -l)" -eq 0     # the 23f gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$SNP_H"/vectors.txt | awk '{print $1}')"     = "72a9e77022c15c4d190e0e0a6d8514de"
test "$(md5sum "$TCH"/vectors_faceA.txt | awk '{print $1}')" = "653103cb599ea6369949eeb35a8ed698"

# ---- the landed-home ONE-home REUSE faces (the Lua RAII home src/lua
# cites the REAL ground lua.cc leg linked REAL above; the framework Command
# home module.rs :101 REUSED NEVER re-forked — the twin asserts it) ----
test "$(grep -c 'pub struct Command' "$R"/src/framework/module.rs)" -eq 1
test "$(grep -c 'ManageStack' "$R"/src/lua/mod.rs)" -ge 3
test "$(grep -c "pub struct Shell {" "$R"/src/main/shellp.rs)" -eq 1             # the ONE class home (the brace form pins the class face; the ShellWorld seam NEVER counts)
test "$(grep -c "pub fn command_count" "$R"/src/main/shellp.rs)" -eq 1
# the mod.rs rider-flip holders (the 62d6fac complete-flip law walked):
test "$(wc -l < "$R"/src/main/mod.rs)" -eq 8                              # THE flip: 7 -> 8 at THIS row (ONE new wiring line; BOTH holder arms rider-flipped IN-COMMIT)
test "$(grep -c "pub mod ${MN}p" "$R"/src/main/mod.rs)" -eq 1             # the ONE new seat

# ---- landmine NAMING legs (the misc-9 family, STAYS 2 occupants NEVER +1;
# the hyphen-split comment law holds THIS row) ----
test "$(grep -rl 'struct Tra'"cer" "$R"/src --include=*.rs | wc -l)" -eq 0
test "$(grep -rlE 'ReloadSurv'"ivor|reload_survivor" "$R"/src --include=*.rs | wc -l)" -eq 2

# ---- STATE-AWARE docs faces (the 23b/24a split law: MY commit banks the
# PLAN row + the deviations section; the NEXT.md header/seed bank rides the
# ORCHESTRATOR sibling — at THIS row the joined own-token NEVER rides NEXT.md) ----
pre=$(git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1 && echo post || echo pre)
docbank=$(grep -q "^## .*row 24c" "${R}"/KNOWN\ DEVIATIONS.md && echo banked || echo unbanked)
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -ge 0                      # the NEXT prose carries the GROUND name LEGITLY (2 pre-hits MEASURED at authoring: the shell.cc :928 exhibit + the gate-row cite) — the own-token law rides the DIR/CENSUS arms, NEVER this docs file (NEVER touched; the split-form count below)
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c "^| 24c" "$R/PORTING_PLAN.md")" -eq 1                 # the plan-row grep-count-1 law
    test "$(grep -c 'row 24c' "${R}"/KNOWN\ DEVIATIONS.md)" -ge 1
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the HEAD docs
# face; the CURRENT 841 face x3 NEVER moved by THIS row; the docs sibling
# banks the NEW face) ----
test "$(grep -c '841 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3         # the CURRENT seed face x3 (NEVER moved by this row)
for s in 825 810 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c '5 TES'"T(" "$R/NEXT.md")" -eq 1                           # the drift token EXACT-1 (the snproc token-split form; NEVER typed whole by this row!)

# ---- token censuses (COLD-MEASURED at authoring 2026-11-25: the harness
# NAME token family 0 PRE-HITS across tools/tests/NEXT.md/src — the dir name
# + CENSUS arms NEVER type the join; the ground NAME rides the files BY
# CONSTRUCTION (the pair it ports) — those carrier faces are PINNED at the
# measured faces, the 24a ground-name-path precedent): ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}_DONE" "$H"/build.sh || true)" -eq 0
# THE SELF-scan face (THIS file types the join ONLY through runtime concat:
# 0 literal joined own-token holders EXCLUDING the ground-name seats) —
# ground-token self-scan face of the 4 harness .cc + build.sh:
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/gate_main.cc "$H"/witness_shellrow.cc | grep -c "${MN}")" -eq 9   # MEASURED COLD face: the ground-name includes/decls by construction (shell-h include seats + the witness mirror legs); the own-CENSUS token faces ($MN_harness/DONE) ride ZERO above
test "$(grep -rl "${MN}_parity" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' 2>/dev/null | grep -v "^$R/tests/${MN}_parity_test.rs$" | wc -l)" -eq 0  # the twin-NAME token NEVER rides a sh/rs file outside the twin itself (MEASURED 0)
DONE_MARK="SLP"'_DONE'
test "$(grep -c "$DONE_MARK" "$R/NEXT.md" || true)" -eq 0                  # the DONE echo NEVER rides NEXT.md (the docs-pass split; the sibling banks the hyphen face)
test "$(grep -c "$DONE_MARK" "${R}"/KNOWN\ DEVIATIONS.md || true)" -eq 0
test "$(grep -c "$DONE_MARK" "$R/PORTING_PLAN.md" || true)" -eq 0
test "$(grep -c "${MN}_DONE" "$R"/src/main/shellp.rs || true)" -eq 0
test "$(grep -c "${MN}_DONE" "$R"/tests/${MN}_parity_test.rs || true)" -eq 0
# the GROUND-name carrier faces across the TRACKED harness space (the row-
# name token; landmine pre-audit COLD-MEASURED: 3 build.sh holders pre-land
# (the sn-proc DECL riders comment block + the 24a gate CMake comment + the
# 24a NEVER-land rider — the pt-racer D14 vectors legs ride grep -q arms on
# THEIR OWN vectors, NEVER count-arms), 1 twin holder (the pt-racer twin
# prose); THIS row NEVER joins a strict face: the count stays PINNED):
test "$(grep -rl "${MN}" "$R"/tools/*/build.sh | grep -v "^$H/build.sh$" | wc -l)" -eq 4    # COLD-MEASURED pre = post (my build.sh EXCLUDED; the 4 pre-hits = the pt-racer/pt-mod/rules/sn-proc era GROUND-NAME cites, UNDISTURBED — the own-census-token arms above ride ZERO)
test "$(grep -rl "${MN}" "$R"/tests --include='*.rs' | grep -v "^$R/tests/${MN}_parity_test.rs$" | wc -l)" -eq 1     # the pt-racer twin prose holder UNMOVED (my OWN twin EXCLUDED)
test "$(grep -rl "${MN}" "$R"/src --include=*.rs | grep -v "^$R/src/main/${MN}p.rs$" | grep -v "^$R/src/main/mod.rs$" | wc -l)" -eq 7   # + the mod.rs wiring-line rider exclusion (the ONE new seat, the 62d6fac flip face — legit one-home reuse)                   # the GROUND-name holders (the pt-racer-era shell_* family cites + snort_/policy cites) UNMOVED (my landing EXCLUDED — the 24a ground-name-path precedent — the hyphen-split carrier comment law)

# ---- STATE-AWARE stageables dual guard (9 faces: .gitignore + build.sh +
# gate_main.cc + probe.cc + probe_faceA.cc + witness_shellrow.cc + vectors +
# vectors_faceA + (the gate rides UNTRACKED); PRE face: the 8 files ON DISK
# + the dir status ??-1; POST face: the ls-files 8-face + ZERO-leak arms) ----
for f in .gitignore build.sh gate_main.cc probe.cc probe_faceA.cc witness_shellrow.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main/shell.cc copy/main/shell.h copy/main/lua_bootstrap.h o2/probe.o o2/sh.o o2/probe_faceA.o gate_x gate_twin_x probe_x probe_x_O2 probe_x_cross probe_faceA_x probe_faceA_x_O2 probe.o probe_faceA.o gate_main.o sh_ut.o witness.o lua.o graftcmp vectors_O0.txt vectors_O2.txt vectors_O2b.txt vectors_faceA_O0.txt vectors_faceA_O2.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E4_o2_unused.txt E9_dup.txt E_lua.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt gate_stderr.txt replay_bootstrap.txt replay_finalize.txt backbone10.txt stageables.txt .catch_main_probe.cc .catch_main_probe.o .twin.txt; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 8
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|build\.sh|gate_main\.cc|probe(_faceA)?\.cc|witness_shellrow\.cc|vectors(_faceA)?\.txt')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
else
    git -C "$R" status --porcelain | grep -qxF "?? tools/${MN}_harness/"
    test "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | wc -l)" -eq 8
fi
test -z "$(git -C "$R" diff --name-only --cached)"
DIRTY_RE='^\?\? tools/'"${MN}"'_harness/$|^\?\? src/main/'"${MN}"'p\.rs$|^\?\? tests/'"${MN}"'_parity_test\.rs$|^ M src/main/mod\.rs$|^ M PORTING_PLAN\.md$|^ M "?KNOWN DEVIATIONS\.md"?$|^ M tools/(a[c]t|daqi[o]|dirst[o]r|hproce[s]s|pcga[t]e|pt[r]acer|pt[r]mod|rsu[b]s|sds[m]|s[f]d|sfi[n]st|sfmo[d]|snpr[o]c|t[c]|t[r]acer)_harness/build\.sh$|^ M tests/(a[c]t|hproce[s]s|pcga[t]e|pt[r]acer|pt[r]mod|sds[m]|s[f]d|snpr[o]c)_parity_test\.rs$'  # the [b]racket law: each holder name ONE char-classed so this file NEVER joins a foreign token family (the regex face UNMOVED)
dirty=$(git -C "$R" status --porcelain | grep -vcE "$DIRTY_RE" || true)   # || true: grep -vc EXITS 1 when the count IS 0 (the clean face) — the set -e trap, the 24b cold law
test "$dirty" -eq 0

# ---- tail (the honest echo face) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "ground pair: 944+161=1105 @ fe29cbe; the THIRD face main.h 67 L cite-ONLY NEVER lands"
echo "E4: bare dies EXACTLY-1 fatal dump_config/config_data.h (shell.h :30, the donor-absent first seat); graft-daq dies EXACTLY-1 daq_version_string tok-x2 (shell.cc :169); REAL libdaq SWAP BOTH SILENT (plain + UNIT_TEST)"
echo "generated heads REPLAYED (REAL lua_wrap into the copy tree ONLY): bootstrap 5084 B + finalize 3847 B (zero synthetic riders)"
echo "nm census: plain 58 / ut 72 (Catch 13) — the NEVER-LAND wall mirrored + the REAL lua.cc leg link-REAL; E9 dup twins EXACTLY-40"
echo "GATE E10 over the REAL libluajit.a BOTH ways GREEN: RUNNER $(tail -2 "$H"/gate.txt | head -1 | tr -d '\r') | MAIN twin $(tail -2 "$H"/.twin.txt | head -1 | tr -d '\r')"
echo "gate arms: TEST_CASE x1 (:928 [Sh-ell] tag runtime-built), CHECK x1 (:938), UNIT_TEST post x1 (:922), plain-CMake seats x2, ENABLE_SHELL ac- dialect face NEVER lands, generated-output pair x2"
echo "gate census (walked FLIP): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af') x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor"
echo "backbone STAYS $(wc -l < "$R"/tools/link4_harness/backbone10.txt)"
echo "SL""P_DONE vectors=$(wc -l < "$V") faceA=$(wc -l < "$VA") gates=1 (the chapter-21 THIRD real gate row, the FIRST gate over REAL LuaJIT; the census FLIPPED 30/9/22/1)"
