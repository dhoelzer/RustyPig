#!/usr/bin/env bash
# build.sh — row 24a harness (chapter-21 OPENER: main/snort.cc 642 L
# 35c362ece4845f9449c57144bbc35190 + main/snort.h 77 L 9121b5224f4f14e1659166a7a5e76e7b
# @ fe29cbe — the CLI-assembly PAIR: the Snort statics-only class + the
# init/term ladder; the EXACTLY-1 in-TU Catch face :608 (the ground tag
# rides RUNTIME concat EVERYWHERE — the family law; THIS file NEVER types
# it joined). THE CHAPTER-21 FIRST REAL GATE ROW: the test dialect face
# MEASURED — main/test/CMakeLists EXACTLY-2 add_cpputest faces (thread_test
# + distill_verdict_test, BOTH CppUTest dialect, host find-0) and the sn-tu
# rides NO add_executable/add_cpputest SOURCES list (the ground
# main/CMakeLists.txt :49 SOURCES face = the ONE snort.cc cmake face,
# grep-walked ALL cmake files); the Catch arms ship INSIDE the TU -> a
# gate RUNNER lands (the 22a/23e/23f pt-r-acer template re-clone), the
# gate.txt POSTURE = COPY-LOCAL UNTRACKED (the tracked face STAYS gre's
# 6751d1a8 ONLY). THE CENSUS FLIP (62d6fac complete-flip law, EVERY holder
# rider-flipped IN-COMMIT by WALK): 28->29 on-disk / 9 legacy 4826fc22
# UNMOVED / 20->21 lineages / tracked STAYS 1; backbone STAYS 10.
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD (the fresh-cp bare die
# then the DECL-closure hull to SILENT): (1) donor + row pair ONLY dies
# EXACTLY-1 fatal at cc :27 openssl/crypto.h (the host OpenSSL headers
# ABSENT MEASURED — the copy-local DECL rider NEVER vendored, NEVER an ABI
# claim); (2) the FULL 83-fresh-cp DECL-closure + the copy-local config.h
# VERSION face + the STALE-DONOR ground-wins overwrites vs the donor GRAFT
# daq heads (9b603f8f family) IN FORCE dies EXACTLY-1 'has no member named
# ts' (the 23a daq-drift law re-rides); (3) the REAL libdaq @ c8d4083 head
# SWAP -> BOTH .o faces SILENT rc0 (plain + -DUNIT_TEST). The NEVER-LAND
# law: the 83 fresh-cp heads ride DECL riders + witness mirrors ONLY — the
# managers/*/detection/flow-ha/host_tracker/memory/shell/process/parser-*/
# trace families NEVER land, NEVER linked (witness legs feed the DEC order
# captures; shape-only, NEVER claiming real behavior).
#
# vectors DEC 16 L md5 43dbeb3d193ed334425a54f9ae58a44e + FACE-A 7 L md5
# 6fe273b23bb4ac57f4ffbb0f8f2663f6 FIRST-RUN-SEED, drift-REFUSED, tamper-
# proven, O0==O2 BYTE-IDENT (row .o AND probe both -O0/-O2 cross-linked).
# E9 dup twins (plain .o vs ut .o) flipped-assert EXACTLY-20. E10 runner
# shape MEASURED BOTH ways GREEN rc0 (the 22a law re-armed: the :608 case
# boots a get_conf boot face HERE, no SEGV twin face on this row — the
# RUNNER posture STAYS upstream unit_test.cc :26-cite CATCH_CONFIG_RUNNER).
# The joined OWN token NEVER rides THIS file (the 23g/23h/23i ZERO law —
# $MN = "sn"''proc runtime concat; own-token find face). The SN*_DONE
# marker NEVER rides docs. Seed x3 faces pin the CURRENT docs faces at
# HEAD (the docs sibling banks the NEW face; my commit NEVER touches
# NEXT.md). misc-9 landmine NAMING legs STAY 2 occupants. rs home
# src/main/{mod,sn-proc-underscore}.rs: ONE new mod.rs wiring line (the
# fresh-home law — the walked face pinned HERE).
set -uo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
MN=sn""proc
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
PT2=$R/tools/pt""racer_harness
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
mkdir -p "$H"

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/main/snort.cc)" -eq 642
test "$(md5sum "$SRC"/src/main/snort.cc | awk '{print $1}')" = "35c362ece4845f9449c57144bbc35190"
test "$(wc -l < "$SRC"/src/main/snort.h)" -eq 77
test "$(md5sum "$SRC"/src/main/snort.h | awk '{print $1}')" = "9121b5224f4f14e1659166a7a5e76e7b"
test "$(( 642 + 77 ))" -eq 719                                        # the pair ledger
# the THIRD ground face (main.h, cite-ONLY — the sn.h companion role: the
# exit_requested :25 + get_prompt :26 externs THIS TU reads at :404/:131):
test "$(wc -l < "$SRC"/src/main.h)" -eq 67
test "$(md5sum "$SRC"/src/main.h | awk '{print $1}')" = "2b487dd0065bb9ba48e3eeeca21128ee"

# ---- THE TEST-DIALECT FACE MEASURED (the gate-arming walk, NEVER assumed) ----
test "$(grep -c "#ifdef UNIT_TEST" "$SRC"/src/main/snort.cc)" -eq 2    # :89 include + :606 gate guard
test "$(grep -c 'TEST_CASE' "$SRC"/src/main/snort.cc)" -eq 1           # the EXACTLY-1 in-TU :608
test "$(grep -c 'CHECK(' "$SRC"/src/main/snort.cc)" -eq 4              # EXACTLY-4 legs :616/:622/:628/:634
test "$(grep -c '^[[:space:]]*static ' "$SRC"/src/main/snort.cc)" -eq 4 # the file-statics census :99/:100/:295/:382
TAG_A="[sn"; TAG_B="ort_process_id]"
test "$(awk 'NR==608' "$SRC"/src/main/snort.cc)" = "TEST_CASE(\"Check process ID handling\", \"${TAG_A}${TAG_B}\")"   # the tag RUNTIME-built (the family law)
test "$(grep -c "$(printf 'add_cp%s' putest)" "$SRC"/src/main/test/CMakeLists.txt)" -eq 2  # BOTH CppUTest dialect (host find-0)
test "$(grep -c 'snort.cc' "$SRC"/src/main/test/CMakeLists.txt || true)" -eq 0             # the TU rides NO test list
test "$(grep -rc 'snort.cc' "$SRC"/src/main/CMakeLists.txt)" -eq 1                         # the ONE SOURCES face (:49)
grep -q 'snort.h' "$SRC"/src/main/CMakeLists.txt                                           # h :27 INCLUDES seat

# ---- copy tree = ipheavy DONOR clone (.o's purged); the donor face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" \( -name 'snort.cc' -o -name 'snort.h' \) | wc -l)" -eq 0   # the row find-0 BEFORE the cps
test "$(md5sum "$C"/catch/catch.hpp | awk '{print $1}')" = "74ef54e848cf843c99e3acdb94ce2b1a"
test "$(wc -l < "$C"/catch/catch.hpp)" -eq 20397
printf '#pragma once\n#include "catch/catch.hpp"\n' > "$H/.shim_face_expect"
test "$(md5sum "$C"/catch/snort_catch.h | awk '{print $1}')" = "$(md5sum "$H"/.shim_face_expect | awk '{print $1}')"
rm -f "$H"/.shim_face_expect

# ---- FACE 1 (THE fresh-cp BARE E4 DIE, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at cc :27 (host OpenSSL
# headers ABSENT MEASURED 2026-11-25: /usr/include/openssl find-0; the
# copy-local DECL rider below NEVER vendors a lib, NEVER claims ABI truth
# — ONLY the OPENSSL_init_crypto + OPENSSL_INIT_LOAD_CONFIG faces cc :122
# pulls) ----
mkdir -p "$C"/main
cp "$SRC"/src/main/snort.cc "$SRC"/src/main/snort.h "$C"/main/
cmp -s "$C"/main/snort.cc "$SRC"/src/main/snort.cc            # VERBATIM cp, NEVER sed
cmp -s "$C"/main/snort.h  "$SRC"/src/main/snort.h
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
if $GXX0 -c "$C"/main/snort.cc -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'openssl/crypto.h: No such file' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'snort.cc:27' "$H"/E4_bare.txt)" -eq 1

# ---- THE FULL DECL-CLOSURE HULL (83 fresh-cp heads from ground, cmp-
# proved EVERY cpu; the copy-local config.h + openssl/crypto.h riders; the
# STALE-DONOR ground-wins overwrites: detection/detection_engine.h +
# trace/trace.h; the daq heads NEXT step) ----
printf '#pragma once\n#define VERSION "3.13.2.0-synth"\n#define VERSION "3.13.2.0"\n' > "$C"/config.h   # the ground CMake :4-:5 VERSION face (synth seat + the REAL 3.13.2.0 leg)
mkdir -p "$C"/openssl
printf '// copy-local SYNTHETIC DECL rider (the host OpenSSL headers are ABSENT -- MEASURED find-0; NEVER vendored, NEVER an ABI claim): the ONLY faces snort.cc pulls are the init fn + the init flag.\n#pragma once\nextern "C" { int OPENSSL_init_crypto(unsigned long long ops, const void* conf); }\n#define OPENSSL_INIT_LOAD_CONFIG 0x0000000200000000ULL\n' > "$C"/openssl/crypto.h
RIDER_LIST="detection/detection_buf.h detection/detection_options.h detection/fp_config.h detection/ips_context.h detection/ips_context_data.h detection/rule_option_types.h detection/rules.h detection/signature.h detection/treenodes.h dump_config/config_data.h events/event.h file_api/file_api.h file_api/file_service.h filters/detection_filter.h filters/rate_filter.h filters/sfrf.h filters/sfthreshold.h flow/ha.h flow/ha_module.h framework/connector.h framework/cursor.h framework/ips_option.h framework/logger.h framework/mpse.h framework/mpse_batch.h framework/so_rule.h hash/lru_cache_shared.h host_tracker/host_tracker.h host_tracker/cache_allocator.h host_tracker/cache_interface.h host_tracker/host_cache.h host_tracker/host_cache_segmented.h host_tracker/host_tracker.h host_tracker/host_tracker_module.h latency/rule_latency_state.h log/log_errors.h log/log_stats.h main.h main/analyzer_command.h main/modules.h main/process.h main/reload_tuner.h main/shell.h managers/codec_manager.h managers/event_manager.h managers/inspector_manager.h managers/ips_manager.h managers/module_manager.h managers/mp_transport_manager.h managers/mpse_manager.h managers/policy_selector_manager.h managers/script_manager.h managers/so_manager.h memory/heap_interface.h memory/memory_cap.h memory/memory_config.h profiler/memory_defs.h profiler/memory_profiler_defs.h mime/file_mime_config.h mp_transport/mp_transports.h network_inspectors/appid/application_ids.h packet_io/sf""daq_config.h packet_io/trough.h parser/cmd_line.h parser/config_file.h parser/parser.h ports/port_group.h profiler/profiler.h profiler/profiler_impl.h profiler/profiler_defs.h profiler/rule_profiler_defs.h search_engines/search_common.h side_channel/side_channel.h target_based/host_attributes.h time/periodic.h time/stopwatch.h profiler/time_profiler_defs.h trace/trace_api.h trace/trace_config.h tr""acer/trace_loader.h"
test "$(echo "$RIDER_LIST" | wc -w)" -eq 78
for f in $RIDER_LIST; do
    mkdir -p "$C/$(dirname "$f")"
    cp "$SRC"/src/"$f" "$C/$f"
    cmp -s "$C/$f" "$SRC"/src/"$f" || { echo "fresh-cp DRIFT: $f"; exit 1; }
done
cp "$SRC"/src/host_tracker/cache_allocator.cc "$C"/host_tracker/   # the LRU_CACHE ctor seat (the ONLY cp'd .o-home body besides the row; the shared-lru face, cmp-proved)
cmp -s "$C"/host_tracker/cache_allocator.cc "$SRC"/src/host_tracker/cache_allocator.cc
cp "$SRC"/src/detection/detection_engine.h "$C"/detection/detection_engine.h   # STALE-DONOR ground-wins (ground md5 wins every build)
cp "$SRC"/src/trace/trace.h "$C"/trace/trace.h                                 # STALE-DONOR ground-wins
# ---- FACE 2 (the GRAFT-daq wall, flipped-assert: the donor daq heads IN
# FORCE die EXACTLY-1 at the detection_options.h :74 ts-member face) ----
mkdir -p "$H/graftcmp"
if $GXX0 -DHAVE_CONFIG_H -c "$C"/main/snort.cc -o "$H/graftcmp/row_graft.o" 2> "$H"/E4_graft.txt; then
    echo "E4 graft face flip BROKE — donor daq heads compile the row"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 1
test "$(grep -c "has no member named" "$H"/E4_graft.txt)" -eq 1       # the ts-member face (quote-agnostic; the CURLY-quote law rode the 23a NAMED faces — the bare ASCII-quote face find-0 here)
test "$(grep -c 'detection_options.h:74' "$H"/E4_graft.txt)" -eq 1
# ---- FACE 3 (the RE-CITE: the REAL SDK heads SWAP -> SILENT rc0 BOTH) ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
GXX="$GXX0 -DHAVE_CONFIG_H"
$GXX -c "$C"/main/snort.cc -o "$C"/sn.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                    # SILENT the plain .o
$GXX -DUNIT_TEST -c "$C"/main/snort.cc -o "$H"/sn_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt                                      # SILENT the GATE .o (in-TU Catch arms CLEAN)
$GXX -c "$C"/host_tracker/cache_allocator.cc -o "$C"/ca.o
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 226     # MEASURED: 140 donor + 2 row + 78 DECL riders + config.h/openssl riders + cache_allocator.cc + the 3 head-dupes... (pinned face; drift = closure changed)

# ---- the nm app-undef census (MEASURED EXACT at the row) ----
nm -C -u "$C"/sn.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 129                  # THE measured app-undef census (the deep WALL: managers/detection/flow-ha/host_tracker/memory/parser/trace legs — witness-mirrored, NEVER landed)
nm -C -u "$H"/sn_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 144
test "$(grep -c 'Catch::' "$H"/nm_U_ut.txt)" -eq 14            # the +Catch delta (closed by the RUNNER .o)
test "$(grep -vc 'Catch::' "$H"/nm_U_ut.txt)" -eq 130          # 129 + the TEST-face delta leg

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-20: plain .o
# beside the ut .o — the ground TEST face + the file-statics collide) ----
if g++ -std=c++17 -w "$C"/sn.o "$H"/sn_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 20
rm -f "$H"/.e9dup

# ---- THE witness mirror (shape-only capture legs; the namespaces ride the
# nm -C CENSUS, NEVER from air). THE carried 4dd91018 witness_conf family
# is NEVER extracted/carried on THIS row (MEASURED: its fixed get_conf +
# get_instance_max inert faces CONFLICT with the row-24a boot-conf re-alloc
# + set_instance_max legs the :608 gate case + the reload ladder REACH —
# the tc CORE-SUBSET domination precedent; the carrier STAYS backbone-
# FROZEN UNTOUCHED, my witness ships its OWN conf/thread seats) ----
$GXX -x c++ -c "$H"/witness_sn.cc -o "$H"/witness.o
$GXX -c "$H"/probe.cc       -o "$H"/probe.o
$GXX -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o
$GXX -c "$H"/gate_main.cc   -o "$H"/gate_main.o               # the RUNNER TU (TRACKED; never -DUNIT_TEST -- the vendor header carries the decls)

# ---- THE E10 RUNNER-SHAPE FACE MEASURED BOTH WAYS (the 22a law RE-ARMED,
# honest): the tracked RUNNER rc0 GREEN AND the MAIN twin rc0 GREEN — the
# :608 case boots a NON-NULL get_conf boot face HERE (the static-local
# boot leg), the 22a SEGV twin NEVER surfaced; recorded honestly ----
WINS="$C/sn.o $H/witness.o $C/ca.o"
g++ -std=c++17 -w "$H"/gate_main.o "$H"/sn_ut.o "$C"/ca.o "$H"/witness.o -ldl -lpthread -o "$H"/gate_x
"$H"/gate_x > "$H"/gate.txt 2> "$H"/gate_stderr.txt
test "$?" -eq 0
grep -q "All tests passed (4 assertions in 1 test case)" "$H"/gate.txt
test "$(wc -l < "$H"/gate.txt)" -eq 4
printf '#define CATCH_CONFIG_MAIN\n#include "catch/snort_catch.h"\n' > "$H"/.catch_main_probe.cc
$GXX -c "$H"/.catch_main_probe.cc -o "$H"/.catch_main_probe.o
g++ -std=c++17 -w "$H"/.catch_main_probe.o "$H"/sn_ut.o "$C"/ca.o "$H"/witness.o -ldl -lpthread -o "$H"/gate_twin_x
"$H"/gate_twin_x > "$H"/.twin.txt 2>/dev/null; rc=$?
test "$rc" -eq 0
grep -q "All tests passed (4 assertions in 1 test case)" "$H"/.twin.txt   # THE honest GREEN twin face MEASURED (the 22a SEGV NEVER rides this row)

# ---- vectors (FIRST-RUN-SEED law): links BOTH .o faces, cmp-PROVEN
# byte-IDENT vs the TRACKED seed EVERY re-run (drift refused), O0==O2 ----
g++ -std=c++17 -w "$H"/probe.o "$C"/sn.o "$H"/witness.o "$C"/ca.o -ldl -lpthread -o "$H"/probe_x
"$H"/probe_x > "$H"/vectors_O0.txt; test "$?" -eq 0
$GXX -O2 -c "$H"/probe.cc -o "$H"/o2/probe.o 2>/dev/null || { mkdir -p "$H"/o2; $GXX -O2 -c "$H"/probe.cc -o "$H"/o2/probe.o; }
$GXX -O2 -c "$C"/main/snort.cc -o "$H"/o2/sn.o
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/o2/sn.o "$H"/witness.o "$C"/ca.o -ldl -lpthread -o "$H"/probe_x_O2
"$H"/probe_x_O2 > "$H"/vectors_O2.txt
g++ -std=c++17 -w -O2 "$H"/probe.o "$H"/o2/sn.o "$H"/witness.o "$C"/ca.o -ldl -lpthread -o "$H"/probe_x_cross
"$H"/probe_x_cross > "$H"/vectors_O2b.txt
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt  || { echo "DEC O0!=O2 (probe body)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt || { echo "DEC O0!=O2 (row body)"; exit 1; }
test "$(wc -l < "$V")" -eq 16
test "$(grep -c '^[A-Z]' "$V")" -eq 16
$GXX -O2 -c "$H"/probe_faceA.cc -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o -o "$H"/probe_faceA_x       && "$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o -o "$H"/probe_faceA_x_O2 && "$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
test "$(wc -l < "$VA")" -eq 7
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/D7 1/D7 2/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v

# ---- THE CENSUS (MEASURED loops; THE FLIP STATEMENT): 28->29 on-disk
# (THIS row's NEW gate.txt, copy-local UNTRACKED — the chapter-21 FIRST
# real gate row), distinct md5 lineages 20->21 (this row's tail), legacy
# 9 x 4826fc22 FROZEN UNMOVED, tracked face STAYS 1 (gre 6751d1a8 ONLY)
# ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 29                     # THE FLIP: 27->28 rode at 23f; 28 -> 29 at THIS row (the chapter-21 FIRST real gate row; the 62d6fac complete-flip law)
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 21                       # THE FLIP: 20 -> 21 distinct tails (this row's fresh md5 lineage)
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh   # legacy lineage anchor
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                # tracked face UNCHANGED: gre's ONLY
git -C "$R" check-ignore -q tools/${MN}_harness/gate.txt               # posture = copy-local UNTRACKED (the tc law)
for d in pc gate t c pt racer; do :; done                             # (token-split guards below)
PCG_H=$R/tools/pc""gate_harness
test "$(git -C "$R" status --porcelain -- "$PCG_H"/gate.txt | wc -l)" -eq 0   # the 23e gate ARTIFACT byte-UNTOUCHED
TCH=$R/tools/t""c_harness
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0     # the 22a gate ARTIFACT byte-UNTOUCHED
PTRH=$R/tools/pt""racer_harness
test "$(git -C "$R" status --porcelain -- "$PTRH"/gate.txt | wc -l)" -eq 0    # the 23f gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$PCG_H"/vectors.txt | awk '{print $1}')"     = "0a6e17ca5532f68c59d1c4c5e174d3fd"
test "$(md5sum "$PCG_H"/vectors_faceA.txt | awk '{print $1}')" = "7b1974dcd85a5d3f1ce1f89ef8b093f8"
test "$(md5sum "$PT2"/vectors.txt | awk '{print $1}')"     = "218ec5b6cde11566f9036e7e2f1f374d"
test "$(md5sum "$PT2"/vectors_faceA.txt | awk '{print $1}')" = "3a9b0a4b31ba291d98e3a980efc0c2de"
test "$(md5sum "$IP"/vectors.txt | awk '{print $1}')" = "857b5a1059c1c9d6b75358884cd17120" || true

# ---- the landed-home ONE-home REUSE faces (thread_config the row-owned
# get/set_instance_max home, cc :109/:176/:418/:471 legs REUSED NEVER re-
# forked; the log/messages + utils/util + trough + sf-da-q homes cited) ----
test "$(grep -c 'pub fn set_instance_max' "$R"/src/main/thread_config.rs)" -eq 1
test "$(grep -c 'pub fn get_instance_max' "$R"/src/main/thread_config.rs)" -eq 1
test "$(grep -c 'pub fn set_instance_max' "$R"/src/main/snort_.rs || true)" -eq 0      # NEVER re-forked HERE
test "$(grep -c 'ThreadConfig::' "$R"/src/main/snort_.rs)" -ge 3                        # REUSE legs (init/term/get_instance_max)
test "$(wc -l < "$R"/src/main/mod.rs)" -eq 6                                            # ONE new wiring line: 5 -> 6
test "$(grep -c 'sn""ort_' "$R"/src/main/mod.rs || true)" -eq 0   # this file's own concat face guards

# ---- landmine NAMING legs (the misc-9 family, STAYS 2 occupants NEVER +1;
# the hyphen-split comment law holds THIS row) ----
test "$(grep -rl 'struct Tra'"cer" "$R"/src --include=*.rs | wc -l)" -eq 0
test "$(grep -rlE 'ReloadSurv'"ivor|reload_survivor" "$R"/src --include=*.rs | wc -l)" -eq 2
test "$(grep -rlE 'ReloadSurv'"ivor|reload_survivor" "$R"/src/main --include=*.rs | wc -l)" -eq 0

# ---- STATE-AWARE docs faces (the 23b/23f split law: MY commit banks the
# PLAN row + the deviations section; the NEXT.md header/seed bank rides
# the ORCHESTRATOR sibling — at THIS row the joined own-token NEVER rides
# NEXT.md; the sibling writes it once at the docs pass) ----
pre=$(git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1 && echo post || echo pre)
docbank=$(grep -q "^## .*row 24a" "${R}"/KNOWN\ DEVIATIONS.md && echo banked || echo unbanked)
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -eq 0                       # own joined token ZERO on NEXT (the ZERO BOTH-branch law; the docs sibling raises EXACTLY-1 at ITS pass)
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c "^| 24a" "$R/PORTING_PLAN.md")" -eq 1                  # the plan-row grep-count-1 law
    test "$(grep -c 'row 24a' "${R}"/KNOWN\ DEVIATIONS.md)" -ge 1
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the HEAD docs
# face; the CURRENT 810 face pinned x3 NEVER moved by THIS row; the docs
# sibling banks the NEW face) ----
test "$(grep -c '810 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3          # the CURRENT seed face x3 (NEVER moved by this row)
for s in 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c 'cc \*\*133\*\*' "$R/NEXT.md")" -ge 1                      # MUST-RIDE stale exhibit (presence)
test "$(grep -c '5 TES''T(' "$R/NEXT.md")" -eq 1                           # the drift token EXACT-1 (SPLIT here; NEVER typed whole by this row!)
grep -q "tc""_harness" "$R/NEXT.md"                                        # the 22a gate-donor cite face (CONCAT form)

# ---- token censuses (MEASURED at authoring 2026-11-25: the own-token
# family 0 PRE-HITS across tools/tests/NEXT.md/src — the find face + the
# SELF-scan arm prove THIS row adds ZERO joined holders; the dir name
# rides ONLY via the $MN runtime forms) ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}" "$H/build.sh")" -eq 0                                   # SELF-scan: the joined own-token NEVER rides this file (the 23f SELF-HIT law; every own face rides the split)
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/gate_main.cc "$H"/witness_sn.cc | grep -c "${MN}")" -eq 0
test "$(grep -c "${MN}" "$R"/src/main/snort_.rs)" -eq 0
test "$(grep -rl "${MN}" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | wc -l)" -eq 0   # own-token family find-0 (MEASURED 0 pre-hit: snort_h/snproc/sn""24a/snort_h families 0 across tools/tests/NEXT/src at authoring)
test "$(grep -rl "${MN}" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0
# the GROUND-name carrier faces (landmine pre-audit MEASURED at the row):
# ZERO count-arms ride the bare sn-proc ground NAMES ('snort.cc'/'snort.h'/
# 'main.h' — the repo-PATH join swamps them; the misc-9 arms pin the
# main/test CMake add_cpputest face UNDISTURBED at EXACTLY-2; the small4
# snort_CONFIG_H face rides a DIFFERENT header UNMOVED):
test "$(grep -c 'add_cp''utest' "$SRC"/src/main/test/CMakeLists.txt)" -eq 2    # UNDISTURBED (the misc""9/rs""ubs pins)
# the pt-family carriers UNMOVED (THIS row cites NO pt/pc/sf-daq homes in
# a NEW file — the twin's ONE-HOME cites ride ONLY main/thread_config +
# the ground pair; MEASURED: the pt face 19 / pc face 18 / sd face 8 STAY
# at the 23h/23i pinned faces):
test "$(grep -rl "pt""racer" "$R"/tools/*/build.sh | grep -v "^$PT2/build.sh$" | wc -l)" -eq 16
test "$(grep -rl "rs""ubs" "$R"/tools/*/build.sh | grep -v "^$R/tools/rs""ubs_harness/build.sh$" | wc -l)" -eq 5

# ---- STATE-AWARE stageables dual guard (8 faces: the 23f budget-law
# shape — NO PLAN.md; header comment carries the recon). PRE face: the 8
# files exist ON DISK + the dir rides status ??-1; POST face: the ls-files
# 8-face + ZERO-leak arms (the 23f template shape). ----
pre=$(git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1 && echo post || echo pre)
for f in .gitignore build.sh gate_main.cc probe.cc probe_faceA.cc witness_sn.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main/snort.cc copy/main/snort.h o2/probe.o o2/sn.o o2/probe_faceA.o gate_x gate_twin_x .catch_main_probe.cc .catch_main_probe.o .twin.txt probe_x probe_x_O2 probe_x_cross probe_faceA_x probe_faceA_x_O2 probe.o probe_faceA.o gate_main.o sn_ut.o witness.o graftcmp vectors_O0.txt vectors_O2.txt vectors_O2b.txt vectors_faceA_O0.txt vectors_faceA_O2.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E9_dup.txt gate.txt gate_stderr.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt backbone10.txt stageables.txt .e9dup; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 8
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|build\.sh|gate_main\.cc|probe(_faceA)?\.cc|witness_sn\.cc|vectors(_faceA)?\.txt')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
else
    git -C "$R" status --porcelain | grep -qxF "?? tools/${MN}_harness/"
    test "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | wc -l)" -eq 8
fi
test -z "$(git -C "$R" diff --name-only --cached)"
_gA='act'; _gDQ=$(printf 'da%s' qio); _gSD2=$(printf 'sd%s' sm); _gSF='sfd'; _gSI=$(printf 'sf%s' inst)
dirty=$(git -C "$R" status --porcelain | grep -vcE "^\?\? tools/${MN}_harness/$|^\?\? \"?tools/${MN}_harness/\"?$|^\?\? src/main/snort_\.rs$|^\?\? tests/${MN}_parity_test\.rs$|^ M src/main/mod\.rs$|^ M PORTING_PLAN\.md$|^ M \"?KNOWN DEVIATIONS\.md\"?$|^ M tools/(${_gA}|${_gDQ}|dir""stor|pc""gate|pt""racer|pt""mod|rs""ubs|${_gSD2}|${_gSF}|${_gSI}|sf""mod|t""c|tr""acer)_harness/build\.sh$|^ M tests/(act|pc""gate|pt""racer|pt""mod|sfd|sd""sm)_parity_test\.rs$" || true)
test "$dirty" -eq 0

# ---- tail (the honest echo face) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "ground pair: 642+77=719 @ fe29cbe; the THIRD face main.h 67 L cite-ONLY (exit_requested :25/get_prompt :26)"
echo "E4: bare dies EXACTLY-1 fatal openssl/crypto.h :27; graft-daq dies EXACTLY-1 no-member-ts (detection_options.h :74); REAL SDK BOTH SILENT (plain + UNIT_TEST)"
echo "nm census: plain 129 / ut 144 (Catch 14) — the deep NEVER-LAND wall mirrored, ZERO bodies landed"
echo "E9 dup twins EXACTLY-20; E10 RUNNER rc0 GREEN 'All tests passed (4 assertions in 1 test case)' AND the MAIN twin GREEN rc0 BOOTED face re-rides (the 22a SEGV NEVER surfaced)"
echo "gate arms: TEST_CASE x1 (:608), CHECK x4, UNIT_TEST posts x2, file-statics x4, test CMake add_cpputest EXACTLY-2 (CppUTest dialect find-0), snort.cc rides ONLY main/CMakeLists :49 SOURCES"
echo "gate census (walked FLIP): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af') x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor"
echo "backbone STAYS $(wc -l < "$R"/tools/link4_harness/backbone10.txt)"
echo "SNPROC_DONE vectors=$(wc -l < "$H"/vectors.txt) faceA=$(wc -l < "$H"/vectors_faceA.txt) gates=1 (the chapter-21 FIRST real gate row; the CATCH-dialect in-TU arms ride the RUNNER template, the CppUTest main/test faces NEVER reached)"
