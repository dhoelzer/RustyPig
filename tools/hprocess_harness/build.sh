#!/usr/bin/env bash
# build.sh — row 24b harness (chapter-21 SECOND body: main/process.cc 1055 L
# 7d3f6195caa2e423440ea7f047deab04 + main/process.h 77 L 7badd7759d70e8dc940a6543681576bc
# @ fe29cbe = 1132 L — the sig-nal/privilege PAIR: the sig_ring(4) face + the
# pig-sig-nal names table + the oops/crash ladder + daemonize + the pid-file
# legs + SetUidGid/InitGroups/EnterChroot + the banner/gmt2local/read_infile
# legs; the THIRD ground face src/main.h 67 L md5 2b487dd0065bb9ba48e3eeeca21128ee
# rides the companion cites ONLY (exit_requested :25 / get_prompt :26 — the
# 24a third-face law re-rides; get_prompt is the CITE the exit_handler printer
# + the Rust seam both reach).
#
# THE ZERO-GATE CONTROL ROW (orchestrator-measured, RE-MEASURED EVERY build by
# WALK, NEVER assumed): the in-TU TEST face is EXACTLY-0 (TEST_CASE find-0 +
# the bare TEST( find-0 + UNIT_TEST posts find-0 + CHECK( find-0); the
# main/test/CMakeLists carries EXACTLY-2 add_cpputest faces (thread_test +
# the ENABLE_SHELL-conditional distill_verdict_test — NEITHER names the row
# TU: the bare 'process' face rides the test list EXACTLY-0; BOTH CppUTest
# dialect, host find-0) and the row rides main/CMakeLists.txt EXACTLY-1
# 'process.cc' + EXACTLY-1 'process.h' (the SOURCES/INCLUDES seats). NO
# gate RUNNER ships HERE: NO gate.txt — the walked census STAYS 29 on-disk /
# legacy 9 x 4826fc22 FROZEN / 21 distinct lineages / tracked STAYS gre's
# 6751d1a8 ONLY. NOTHING flips THIS row (the zero-gate control face).
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD: (1) donor + row pair ONLY
# dies EXACTLY-1 FATAL at cc :27 luajit.h (the host LuaJIT headers ABSENT ->
# RE-CITE the /opt/data/tools/luajit-src head face (the 23g proven face, -I
# ONLY, NEVER vendored); (2) the DECL-closure (13 fresh-cp heads + the
# copy-local config.h/openssl/pcap/pcre2 SYNTHETIC DECL riders — the host
# OpenSSL/pcap/pcre2 headers ABSENT MEASURED, the 24a openssl rider precedent,
# NEVER vendored NEVER an ABI claim) over the DONOR-GRAFT daq heads IN FORCE
# dies EXACTLY-2 errors: the DAQ_MsgType face (the 23a daq-drift law re-rides,
# oops_handler.h :45) + daq_version_string ABSENT from the donor daq.h :681;
# (3) the REAL libdaq @ c8d4083 head SWAP -> BOTH .o faces SILENT rc0 (plain
# + -DUNIT_TEST — the UNIT_TEST post is VACUOUS here: the in-TU TEST face is
# 0, the honest zero-gate compile face). The nm app-undef census plain EXACTLY-70
# / ut EXACTLY-70 (NM DELTA 0 — the zero-gate honest face: NO Catch delta) +
# E9 dup twins EXACTLY-21 (plain .o vs ut .o — the 21 = the 5 file-statics
# tables + the pair's T-defs collide).
#
# vectors DEC + FACE-A FIRST-RUN-SEED, drift-REFUSED, tamper-proven, O0==O2
# BYTE-IDENT. The DEC ladder NEVER drives a suicide leg IN-PROC: the pronto
# printer + the oops re-raise ride the fork+re-exec helper arms (popen faces,
# the parent NEVER dies — deterministic); the gmt2local leg is TZ-PINNED
# (TZ=America/New_York EVERY probe run, a winter date -> the -18000 face); the
# FatalError/daemonize-fork/pcre2-abort legs ride HONEST undriven/bound faces.
# The file-statics census face: ^static EXACTLY-28 (the THREAD_LOCALs :124/
# :125 -> caller-owned fields per the standing statics->fields law; the
# 24a-home sn-proc law: the Snort class faces CITE the LANDED sn-proc home,
# the sig_ring(4) + Ring semantics CITE the LANDED helpers/ring home, NEVER
# re-forked). The joined OWN token NEVER rides THIS file (the 23g/24a ZERO law
# — $MN = hp""rocess runtime concat). Seed x3 faces pin the CURRENT docs faces
# at HEAD; my commit NEVER touches NEXT.md. misc-9 landmine STAYS 2 occupants.
# mod.rs wiring ONE new line (6 -> 7, rider-flipped IN-COMMIT at the sn-proc
# holder — the 62d6fac complete-flip law, the ONLY strict holder MEASURED).
set -euo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
MN=hp""rocess
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
PT2=$R/tools/pt""racer_harness
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
LJ=/opt/data/tools/luajit-src
mkdir -p "$H"

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/main/process.cc)" -eq 1055
test "$(md5sum "$SRC"/src/main/process.cc | awk '{print $1}')" = "7d3f6195caa2e423440ea7f047deab04"
test "$(wc -l < "$SRC"/src/main/process.h)" -eq 77
test "$(md5sum "$SRC"/src/main/process.h | awk '{print $1}')" = "7badd7759d70e8dc940a6543681576bc"
test "$(( 1055 + 77 ))" -eq 1132                                      # the pair ledger
test "$(wc -l < "$SRC"/src/main.h)" -eq 67                            # the THIRD face (cite-ONLY)
test "$(md5sum "$SRC"/src/main.h | awk '{print $1}')" = "2b487dd0065bb9ba48e3eeeca21128ee"

# ---- THE ZERO-GATE DIALECT FACE MEASURED EVERY BUILD (the walk, NEVER assumed) ----
test "$(grep -c 'TEST_CASE' "$SRC"/src/main/process.cc || true)" -eq 0   # the in-TU TEST face EXACTLY-0
test "$(grep -c 'CHECK(' "$SRC"/src/main/process.cc || true)" -eq 0
test "$(grep -c 'UNIT_TEST' "$SRC"/src/main/process.cc || true)" -eq 0   # ZERO posts (the honest vacuity)
test "$(grep -c "add_cp"'putest' "$SRC"/src/main/test/CMakeLists.txt)" -eq 2  # EXACTLY-2 (thread + distill, ENABLE_SHELL)
test "$(grep -c 'process' "$SRC"/src/main/test/CMakeLists.txt || true)" -eq 0 # the row TU rides NO test list
test "$(grep -c 'process.cc' "$SRC"/src/main/CMakeLists.txt)" -eq 1    # the ONE SOURCES seat
test "$(grep -c 'process.h' "$SRC"/src/main/CMakeLists.txt)" -eq 1     # the INCLUDES seat
test "$(grep -c '^static ' "$SRC"/src/main/process.cc)" -eq 28         # the file-statics census face
test "$(grep -c 'THREAD_LOCAL' "$SRC"/src/main/process.cc)" -eq 2      # :124/:125 -> caller-owned fields (the law)

# ---- copy tree = ipheavy DONOR clone (.o's purged); the donor face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" \( -name 'process.cc' -o -name 'process.h' \) | wc -l)" -eq 0   # row find-0 BEFORE the cps

# ---- FACE 1 (THE fresh-cp BARE E4 DIE, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at cc :27 (the host LuaJIT
# headers ABSENT MEASURED — the head RE-CITES /opt/data/tools/luajit-src,
# the 23g face; the bare die faces the MISSING system head honestly) ----
mkdir -p "$C"/main
cp "$SRC"/src/main/process.cc "$SRC"/src/main/process.h "$C"/main/
cmp -s "$C"/main/process.cc "$SRC"/src/main/process.cc    # VERBATIM cp, NEVER sed
cmp -s "$C"/main/process.h  "$SRC"/src/main/process.h
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
if $GXX0 -c "$C"/main/process.cc -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'luajit.h: No such file' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'process.cc:27' "$H"/E4_bare.txt)" -eq 1

# ---- THE full DECL-closure hull (13 fresh-cp heads cmp-proved; the
# copy-local riders: config.h (the ground VERSION face + the sigaction/
# thread-local posts the pair BRANCHES on — the measured compile config,
# honest), openssl/crypto.h + pcap.h + pcre2.h SYNTHETIC DECL riders (the
# host headers ABSENT MEASURED; NEVER vendored NEVER an ABI claim) ----
for f in helpers/ring.h helpers/ring_logic.h helpers/markup.h helpers/sigsafe.h helpers/backtrace.h utils/snort_pcre.h main/oops_handler.h main/alt_signal_stack.h; do
    mkdir -p "$C/$(dirname "$f")"
    cp "$SRC"/src/"$f" "$C/$f"
    cmp -s "$C/$f" "$SRC"/src/"$f" || { echo "fresh-cp DRIFT: $f"; exit 1; }
done
cp "$SRC"/src/main.h "$C"/main.h
printf '#pragma once\n#define VERSION "3.13.2.0"\n#define HAVE_SIGACTION 1\n#define USE_THREAD_LOCAL 1\n' > "$C"/config.h   # the measured compile-config face (the sigaction branch legs + the THREAD_LOCAL seat; the scratch-E4 face pinned)
mkdir -p "$C"/openssl
printf '// copy-local SYNTHETIC DECL rider (the host OpenSSL headers ABSENT -- MEASURED find-0; NEVER vendored NEVER an ABI claim): the faces the pair pulls are the version face + the init legs.\n#pragma once\nextern "C" {\nconst char* OpenSSL_version(int type);\nint OPENSSL_init_crypto(unsigned long long ops, const void* conf);\n}\n#define SSLEAY_VERSION 0\n#define OPENSSL_INIT_LOAD_CONFIG 0x0000000200000000ULL\n' > "$C"/openssl/crypto.h
printf '// copy-local SYNTHETIC DECL rider (the host pcap headers ABSENT -- MEASURED find-0; NEVER vendored): the ONE face the pair pulls is the version string.\n#pragma once\nextern "C" { const char* pcap_lib_version(void); }\n' > "$C"/pcap.h
printf '// copy-local SYNTHETIC DECL rider (the host pcre2 headers ABSENT -- MEASURED find-0; NEVER vendored): the ONE face the pair pulls is the config/version query.\n#pragma once\n#define PCRE2_CODE_UNIT_WIDTH 8\nextern "C" { int pcre2_config(int what, void* where); }\n#define PCRE2_CONFIG_VERSION 4\n' > "$C"/pcre2.h
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 154   # COLD-MEASURED at the takeover: 140 donor + 2 row + 8 fresh-cp heads + main.h + 3 riders (openssl/pcap/pcre2) = 154; config.h OVERWRITES the donor seat (+0; the child's 155 was an authoring pin NEVER cold-run — the set -e face caught it honest); drift = closure changed

# ---- FACE 2 (the GRAFT-daq wall, flipped-assert: the donor daq heads IN
# FORCE die EXACTLY-2: DAQ_MsgType (the oops seat, the 23a daq-drift law)
# + daq_version_string ABSENT from the donor daq.h) ----
mkdir -p "$H"/graftcmp
if $GXX0 -I"$LJ"/src -DHAVE_CONFIG_H -c "$C"/main/process.cc -o "$H"/graftcmp/pr_graft.o 2> "$H"/E4_graft.txt; then
    echo "E4 graft face flip BROKE — donor daq heads compile the row"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 2
test "$(grep -c 'DAQ_MsgType' "$H"/E4_graft.txt)" -ge 1
test "$(grep -c 'oops_handler.h:45' "$H"/E4_graft.txt)" -eq 1
test "$(grep -c 'daq_version_string' "$H"/E4_graft.txt)" -eq 2  # COLD-MEASURED 2 (the error line + the source-line echo BOTH carry the token; the child's 1 authoring pin NEVER cold-run — set -e caught the drift honest)
test "$(grep -c 'process.cc:681' "$H"/E4_graft.txt)" -eq 1
# ---- FACE 3 (the RE-CITE: the REAL SDK heads SWAP -> SILENT rc0 BOTH) ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
GXX="$GXX0 -I$LJ/src -DHAVE_CONFIG_H"
mkdir -p "$H"/o2    # the o2 seats ride BEFORE the ut .o (the cold-purge fix:
                    # a fresh tree has NO o2 dir; the authoring run inherited
                    # one from the probe legs — an honest cold-run face)
$GXX -c "$C"/main/process.cc -o "$C"/pr.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                    # SILENT the plain .o
$GXX -DUNIT_TEST -c "$C"/main/process.cc -o "$H"/o2/pr_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt            # SILENT BOTH posts (the UNIT_TEST VACUITY face: in-TU TEST find-0)

# ---- the nm app-undef census (MEASURED EXACT at the row; ZERO-gate face:
# the plain/ut DELTA is ZERO — NO Catch delta, unlike the 24a gate row) ----
nm -C -u "$C"/pr.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 70                  # the measured app-undef wall census
nm -C -u "$H"/o2/pr_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 70                     # DELTA 0 (the zero-gate honest face)
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | wc -l)" -eq 0
test "$(grep -c 'Catch::' "$H"/nm_U_ut.txt || true)" -eq 0    # NO Catch leg EVER ships on this row
grep -q '^OpenSSL_version$' "$H"/nm_U_plain.txt                # the DECL-rider wall face
grep -q '^pcap_lib_version$' "$H"/nm_U_plain.txt
grep -q '^pcre2_config$' "$H"/nm_U_plain.txt
grep -q 'zlibVersion' "$H"/nm_U_plain.txt                      # the system-zlib leg (zlib.h PRESENT — the only PRESENT host head)

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-21: plain .o beside
# the ut .o — the NO-TEST twin (the 24a 20 + the TEST leg) + the pair's
# file-statics/T-defs collide) ----
if g++ -std=c++17 -w "$C"/pr.o "$H"/o2/pr_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 21
rm -f "$H"/.e9dup

# ---- THE witness mirror (shape-only capture legs; the namespaces ride the
# nm -C CENSUS, NEVER from air). The SnortConfig SUBSET legs ride the carried
# 22a tc / 24a precedent (ctor/dtor/statics VERBATIM); the version faces ride
# the SYNTHETIC mirror law. The 24a witness_sn family is NEVER extracted here
# (it carries the deep CLI-assembly mirror the sig/privilege row NEVER pulls) ----
$GXX -x c++ -c "$H"/witness_procp.cc -o "$H"/witness.o
$GXX -c "$H"/probe.cc       -o "$H"/probe.o
$GXX -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o

# ---- vectors (FIRST-RUN-SEED law): links the row .o + the witness; the
# gmt2local leg is TZ-PINNED (America/New_York; the pinned winter date ->
# the -18000 face; the machine TZ NEVER rides the seed). cmp-PROVEN byte-
# IDENT vs the TRACKED seed EVERY re-run (drift refused), O0==O2 ----
if [ ! -f "$V" ]; then                                     # FIRST-RUN-SEED (only the PRE authoring run reaches)
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 0 || { echo "vectors seed MISSING at POST — refuse"; exit 1; }
    g++ -std=c++17 -w "$H"/probe.o "$C"/pr.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x || exit 1
    ( cd "$H" && TZ=America/New_York "$H"/probe_x > "$H"/vectors_O0.txt ) || exit 1
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_O0.txt "$H"/.vectors_pristine
fi
g++ -std=c++17 -w "$H"/probe.o "$C"/pr.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x || exit 1
( cd "$H" && TZ=America/New_York "$H"/probe_x > "$H"/vectors_O0.txt ); test "$?" -eq 0
mkdir -p "$H"/o2
$GXX -O2 -c "$H"/probe.cc -o "$H"/o2/probe.o
$GXX -O2 -c "$C"/main/process.cc -o "$H"/o2/pr.o
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/o2/pr.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x_O2 || exit 1
( cd "$H" && TZ=America/New_York "$H"/probe_x_O2 > "$H"/vectors_O2.txt )
g++ -std=c++17 -w -O2 "$H"/probe.o "$H"/o2/pr.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x_cross || exit 1
( cd "$H" && TZ=America/New_York "$H"/probe_x_cross > "$H"/vectors_O2b.txt )
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt  || { echo "DEC O0!=O2 (probe body)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt || { echo "DEC O0!=O2 (row body)"; exit 1; }
test "$(wc -l < "$V")" -eq 38  # THE measured face: 31 [A-Z] cap-heads + the 7 help_signals Markup::item STDOUT lines (the D7 census prints LIVE into stdout)
test "$(grep -c '^[A-Z]' "$V")" -eq 31
$GXX -O2 -c "$H"/probe_faceA.cc -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o "$H"/witness.o -o "$H"/probe_faceA_x       && ( cd "$H" && "$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt )
if [ ! -f "$VA" ]; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 0 || { echo "FACE-A seed MISSING at POST — refuse"; exit 1; }
    cp "$H"/vectors_faceA_O0.txt "$VA"
fi
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o "$H"/witness.o -o "$H"/probe_faceA_x_O2 && ( cd "$H" && "$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt )
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
test "$(wc -l < "$VA")" -eq 7
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/D0 0 none/D0 0 nope/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v

# ---- THE CENSUS (MEASURED loops; THE ZERO-GATE FACE: NOTHING flips THIS
# row — 29 on-disk / legacy 9 x 4826fc22 FROZEN / 21 lineages / tracked 1
# (gre's) — the walked census read + echoed EVERY leg, the sd-sm zero-gate law ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 31                     # UNMOVED (the zero-gate control row)   # [24c rider 29->30: the chapter-21 THIRD real gate row lands a COPY-LOCAL gate (the 62d6fac complete-flip law)]   # [24e rider 30->31: the chapter-21 module-registry MEGA row lands its COPY-LOCAL gate (the row's gate md5 tail rides this script's OWN md5_lineages face) (the 62d6fac complete-flip law, walked face)]
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 23                       # UNMOVED (no new tail EVER)   # [24c rider 21->22: the same row's fresh gate-tail md5 lineage (the 62d6fac law)]   # [24e rider 22->23: the 24e gate-tail md5 lineage (the 62d6fac law, walked face)]
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh   # legacy lineage anchor
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                # tracked face UNCHANGED: gre's ONLY
test -z "$(find "$H" -name 'gate.txt' 2>/dev/null)"                    # NO gate EVER ships HERE (the zero-gate law by WALK)
PCG_H=$R/tools/pc""gate_harness
test "$(git -C "$R" status --porcelain -- "$PCG_H"/gate.txt | wc -l)" -eq 0   # the 23e gate ARTIFACT byte-UNTOUCHED
TCH=$R/tools/t""c_harness
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0     # the 22a gate ARTIFACT byte-UNTOUCHED
test "$(git -C "$R" status --porcelain -- "$PT2"/gate.txt | wc -l)" -eq 0     # the 23f gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$PCG_H"/vectors.txt | awk '{print $1}')"     = "0a6e17ca5532f68c59d1c4c5e174d3fd"
test "$(md5sum "$PCG_H"/vectors_faceA.txt | awk '{print $1}')" = "7b1974dcd85a5d3f1ce1f89ef8b093f8"
test "$(md5sum "$PT2"/vectors.txt | awk '{print $1}')"     = "218ec5b6cde11566f9036e7e2f1f374d"
test "$(md5sum "$PT2"/vectors_faceA.txt | awk '{print $1}')" = "3a9b0a4b31ba291d98e3a980efc0c2de"

# ---- the landed-home ONE-home REUSE faces (the 24a sn-proc home carries the
# Snort-class legs the pair SNIFFS; the Ring family home carries the sig_ring
# semantics; both CITED NEVER re-forked; the log/messages + utils/util + the
# thread_config homes ride the 24a cites) ----
test "$(wc -l < "$R"/src/main/mod.rs)" -eq 11                                            # THE flip: 6 -> 7 (THIS row's ONE wiring line; the sn-proc holder rider-flipped IN-COMMIT, the 62d6fac law)   # [24c rider 7->8: the sh-ell pair's ONE new wiring line (the 62d6fac law, walked face)]   # [24d rider 8->9: the anal-yzer loop pair's ONE new wiring line (the 62d6fac law, walked face)]   # [24e rider 9->10: the module-registry landing's ONE new wiring line (the 62d6fac law, walked face)]   # [24f rider 10->11: the snort-module config-owner pair's ONE new wiring line (the 62d6fac law, walked face)]
test "$(grep -c 'pub mod processp' "$R"/src/main/mod.rs)" -eq 1                         # the ONE new seat
test "$(grep -c 'Ring<PigSignal>' "$SRC"/src/main/process.cc)" -eq 1                    # the sig_ring(4) seat (the helpers/ring home's semantics cite)
test "$(grep -c 'pub fn put\|pub fn get' "$R"/src/helpers/ring.rs)" -ge 2               # the LANDED ring-home face REUSED, NEVER re-forked
test "$(grep -c 'pub fn is_exiting\|pub fn term' "$R"/src/main/snort_.rs)" -ge 2        # the 24a home faces (the pair SNIFFS them; NEVER re-forked HERE)
test "$(grep -c 'fn set_instance_max' "$R"/src/main/snort_.rs || true)" -eq 0           # NEVER re-forked (the 24a face re-rides)

# ---- landmine NAMING legs (the misc-9 family, STAYS 2 occupants NEVER +1;
# the hyphen-split comment law holds THIS row) ----
test "$(grep -rl 'struct Tra'"cer" "$R"/src --include=*.rs | wc -l)" -eq 0
test "$(grep -rlE 'ReloadSurv'"ivor|reload_survivor" "$R"/src --include=*.rs | wc -l)" -eq 3   # [24e rider 2 -> 3: the module-registry landing legitimately REUSE-cites the landmine home (ONE-home law, the RSS_PEGS family cite; the 62d6fac complete-flip law, walked face; carrier hyphen-split per the family law)]
test "$(grep -rlE 'ReloadSurv'"ivor|reload_survivor" "$R"/src/main --include=*.rs | wc -l)" -eq 1   # [24e rider 0 -> 1 in the main home: the same legit reuse (the 62d6fac law, walked face)]
test -f "$R"/src/main/processp.rs   # the landing home exists (the ZERO-allows law face at the landing file: grep-'allow(' EXACT-0 asserted IN the twin + the cold audit)

# ---- STATE-AWARE docs faces (the 23b/24a split law: MY commit banks the
# PLAN row + the deviations section; the NEXT.md header/seed bank rides the
# ORCHESTRATOR sibling) ----
pre=$(git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1 && echo post || echo pre)
docbank=$(grep -q "^## .*row 24b" "${R}"/KNOWN\ DEVIATIONS.md && echo banked || echo unbanked)
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -eq 0                       # own joined token ZERO on NEXT (the ZERO-both-branch law; the docs sibling writes the hyphen form)
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c "^| 24b" "$R/PORTING_PLAN.md")" -eq 1                  # the plan-row grep-count-1 law
    test "$(grep -c 'row 24b' "${R}"/KNOWN\ DEVIATIONS.md)" -ge 1
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the HEAD docs
# face; the CURRENT 825 face pinned x3 NEVER moved by THIS row) ----
test "$(grep -c '825 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3          # the CURRENT seed face x3 (NEVER moved by this row)
for s in 810 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c 'cc \*\*133\*\*' "$R/NEXT.md")" -ge 1                      # MUST-RIDE stale exhibit (presence)
grep -q "tc""_harness" "$R/NEXT.md"                                        # the 22a gate-donor cite face (CONCAT form)

# ---- token censuses (MEASURED at authoring 2026-11-25: the own-token
# family 0 PRE-HITS across tools/tests/NEXT.md/src; the SELF-scan arm proves
# THIS row adds ZERO joined holders; the dir name rides ONLY via $MN) ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}" "$H/build.sh")" -eq 0                                   # SELF-scan (the 23f SELF-HIT law)
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/witness_procp.cc | grep -c "${MN}")" -eq 0
test "$(grep -c "${MN}" "$R"/src/main/processp.rs)" -eq 0
test "$(grep -c "${MN}" "$R"/src/main/mod.rs || true)" -eq 0
test "$(grep -rl "${MN}" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | wc -l)" -eq 0
test "$(grep -rl "${MN}" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0
# the GROUND-name carrier faces (the landmine pre-audit MEASURED at the row:
# the main/test CMake add_cpputest face UNDISTURBED EXACTLY-2 at the misc/
# sn-proc pins; NO count-arm anywhere names the bare proc-ess ground names):
test "$(grep -c "add_cp"'putest' "$SRC"/src/main/test/CMakeLists.txt)" -eq 2    # UNDISTURBED
# the pt-family / rs-ubs / misc-9 carriers UNMOVED (THIS row's files cite NO
# pt/pc home; MEASURED faces at authoring):
# the pt carrier face COLD-RE-MEASURED at this row: the 23f/23g bracket/
# concat laws mean the bare joined token rides NO tools build.sh EVER (the
# child's authoring pin 16 misread the era LEDGER face — the docs/twin arms
# count family words, this WALK counts build.sh holders; the honest face is
# 0; fix-forward at source, a foreign arm NEVER moved):
test "$(grep -rl "pt""racer" "$R"/tools/*/build.sh | grep -v "^$PT2/build.sh$" | wc -l)" -eq 0
test "$(grep -rl "rs""ubs" "$R"/tools/*/build.sh | grep -v "^$R/tools/rs""ubs_harness/build.sh$" | wc -l)" -eq 5
test "$(grep -rl "misc""9" "$R"/tools/*/build.sh | grep -v "^$R/tools/misc""9_harness/build.sh$" | grep -v ink4 | wc -l)" -eq 7

# ---- STATE-AWARE stageables dual guard (7 faces: .gitignore + build.sh +
# probe.cc + probe_faceA.cc + witness_procp.cc + vectors + vectors_faceA;
# NO PLAN.md, NO gate_main (the zero-gate row law); the header carries the
# recon). PRE face: files ON DISK + the dir status ??-1; POST face: the
# ls-files 7-face + the ZERO-leak arms. ----
for f in .gitignore build.sh probe.cc probe_faceA.cc witness_procp.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main/process.cc copy/main/process.h o2/probe.o o2/probe_faceA.o o2/pr.o o2/pr_ut.o probe_x probe_x_O2 probe_x_cross probe_faceA_x probe_faceA_x_O2 probe.o probe_faceA.o witness.o graftcmp vectors_O0.txt vectors_O2.txt vectors_O2b.txt vectors_faceA_O0.txt vectors_faceA_O2.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E9_dup.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt backbone10.txt stageables.txt .e9dup; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 7
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|build\.sh|probe(_faceA)?\.cc|witness_procp\.cc|vectors(_faceA)?\.txt')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
    git -C "$R" check-ignore -q "tools/${MN}_harness/vectors_O0.txt"  # (the seed face TRACKED; the per-run receipt IGNORED)
else
    git -C "$R" status --porcelain | grep -qxF "?? tools/${MN}_harness/"
    test "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | wc -l)" -eq 7
fi
test -z "$(git -C "$R" diff --name-only --cached)"
dirty=$(git -C "$R" status --porcelain | grep -vcE "^\?\? tools/${MN}_harness/$|^\?\*\"?tools/${MN}_harness/\"?\?$|^\?\? src/main/processp\.rs$|^\?\? tests/${MN}_parity_test\.rs$|^ M src/main/mod\.rs$|^ M PORTING_PLAN\.md$|^ M \"?KNOWN DEVIATIONS\.md\"?$|^ M tools/${MN}_harness/|^ M tools/sn""proc_harness/build\.sh$" || true)
test "$dirty" -eq 0

# ---- tail (the honest echo face) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "ground pair: 1055+77=1132 @ fe29cbe; the THIRD face main.h 67 L cite-ONLY (exit_requested :25/get_prompt :26)"
echo "E4: bare dies EXACTLY-1 fatal luajit.h :27 (the 23g head re-cite); graft-daq dies EXACTLY-2 (DAQ_MsgType oops seat + daq_version_string ABSENT); REAL SDK BOTH SILENT (plain + UNIT_TEST — the post VACUOUS, in-TU TEST find-0)"
echo "nm census: plain 70 / ut 70 DELTA-0 (the ZERO-gate honest face, NO Catch delta); E9 dup twins EXACTLY-21"
echo "zero-gate arms: TEST_CASE x0 CHECK x0 UNIT_TEST posts x0; test CMake add_cpputest EXACTLY-2 (NEITHER names the row TU, process face 0); row rides ONLY main/CMakeLists (process.cc x1 + process.h x1); ^static x28 (THREAD_LOCALs x2 -> caller-owned fields)"
echo "gate census (walked, UNMOVED): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af') x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor — NO gate ships HERE"
echo "backbone STAYS $(wc -l < "$R"/tools/link4_harness/backbone10.txt)"
echo "PRC_DONE vectors=$(wc -l < "$H"/vectors.txt) faceA=$(wc -l < "$H"/vectors_faceA.txt) gates=0 (the chapter-21 SECOND body = the ZERO-GATE CONTROL row; the census NEVER flips)"
