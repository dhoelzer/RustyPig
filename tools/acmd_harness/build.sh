#!/usr/bin/env bash
# build.sh — row 24i harness (chapter-21 NINTH body: src/main/analyzer_command.cc
# 583 L md5 2fe847d72cdac14b4b1f5a572d693646 + src/main/analyzer_command.h 267 L
# md5 9e9ee8432e295ddecfb5673bed316cc9 @ fe29cbe = 850 L pair — THE ANALYZER-
# COMMAND OWNER PAIR (the control-command family itself): the log_message core
# fork (:95-:121 the remote respond-vs-local skip), the six trivial execute()
# legs (:123-:158), the ACGetStats stats-dump machine (:160-:302 the snapshot
# table + the lock_guard seat + the aggregate/set-results/DropStats fold), the
# ACResetStats ordinal pass (:304-:311), the ACSwap reload-tuner ladder
# (:313-:391 the tinit keep/erase arms + the tuner_next/tuner_update report
# timers + the empty->Swapper::finish face), the HostAttributes/DAQSwap/
# ScratchUpdate reload trio (:393-:431), get_daq_instance (:433) and the CPU/
# latency REPORT LADDERS (:438-:583 the ioctl->dtor fold, the REAL format_ip_-
# addr v4/v6 legs, the %.1f/%.3f report arms).
#
# THE FIFTH ZERO-GATE CONTROL ROW (the 24b/24d/24f/24g pattern; MEASURED, RE-
# MEASURED EVERY build by WALK, NEVER assumed): the in-TU TEST face is EXACTLY-0
# (TEST_CASE + 'TEST(' + 'CATCH' + 'UNIT_TEST' find-0 in BOTH files — this pair
# carries ZERO test/dialect posts, so the -DUNIT_TEST post is VACUOUS-COMPILE
# AND 0-DELTA: the nm plain/ut delta MEASURED EXACTLY-0, pinned honestly at the
# walked zero-face; the ut post compiles SILENT). The REG_TEST dialect rides
# EXACTLY-0 in the cc + EXACTLY-1 in the h (:261, the main_unicast_command
# DECL inside #if defined(REG_TEST) — the pinned line list); the RAW 'SHELL'
# token face is EXACTLY-0 BOTH files (MEASURED — the walked true face, NEVER
# invented). The '#if' posts ride cc :20 (#ifdef HAVE_CONFIG_H ONLY) + h :20/:261.
# The main/test CMakeLists carries EXACTLY-2 add_cpputest dialect faces
# (thread_test :1 + the ENABLE_SHELL-gated distill_verdict_test whose SOURCES
# ride ../analyzer.cc — NEITHER host names the row TU: grep-c analyzer_command
# that file EXACTLY-0 MEASURED) and /usr/include/CppUTest find-0. The row rides
# main/CMakeLists.txt EXACTLY-1 .h (:3) + EXACTLY-1 .cc (:34) PLAIN seats
# OUTSIDE the ENABLE_SHELL gate pair (:20/:22). NO gate RUNNER ships HERE:
# NOTHING flips this row — the census STAYS 32 on-disk / legacy 9 x 4826fc22
# FROZEN / 24 distinct lineages / tracked gre's 6751d1a8 ONLY.
#
# THE statics census MEASURED EVERY BUILD (the walk law): '^static' cc EXACTLY-6
# (:55 report_time the file's ONE THREAD_LOCAL, :56 report_period {10,0}, :57
# invalid_ip, :60 format_ip_addr, :74 tuner_next, :83 tuner_update) + '^static'
# h EXACTLY-1 (:104 clear_counter_type_string_map) + THREAD_LOCAL cc EXACTLY-1
# h EXACTLY-0. The pair OWNS these seven — NEVER mirrored (the E9 twin law).
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD (NEVER a prior era's face
# copied): (1) the fresh-cp BARE donor + row pair dies EXACTLY-1 FATAL at cc
# :34:10 (managers/module_manager.h — the FIRST donor-absent head, MEASURED);
# (2) the DONOR-GRAFT closed hull (6 fresh-cp heads: module_manager.h, host_-
# attributes.h, analyzer.h, reload_tracker.h, reload_tuner.h, swapper.h — the
# walked transitive face; the row .h rides FRESH (the donor carries NO ground
# twin — MEASURED find-0, so the algebra is 140+2+6=148, the honest divergence
# from the 24g twin-overwrite face) with the DONOR daq trio (97bca757/9b603f8f/
# e8a39bf3 — the LEGAL family for THIS row per the NEXT.md donor-selection law:
# the h :255 std::vector<DIOCTL_GetSnortLatencyData> seat only the ext#4
# 9b603f8f family + the REAL SDK satisfy) IN FORCE: MEASURED EXACTLY-5 errors —
# the daq-GENERATION drift family (the legacy donor head lacks DIOCTL_GetCpu-
# ProfileData :465/:473[:474 cascade] + DIOCTL_GET_SNORT_LATENCY_DATA :570 +
# the ONE has-no-member snort_latency_data :501). The 24f/24g/24h EXACTLY-1 and
# 24e ZERO faces NEVER copied — YOU MEASURE, the honest face is FIVE (the pair
# is the ioctl COMMAND family; its whole reason to exist is the ext#4 DIOCTL
# surface); (3) the REAL libdaq @ c8d4083 head SWAP (3 api heads, md5 pinned vs
# the LIVE $L api face; daq_module_api.h/daq_defs/daq_version.h NEVER needed —
# MEASURED 0 extra seats) -> BOTH posts SILENT rc0 (the plain .o + the VACUOUS
# -DUNIT_TEST post).
#
# The nm app-undef census plain EXACTLY-34 / ut EXACTLY-34: delta EXACTLY-0
# BOTH ways (ZERO ut-post legs; the Catch:: count EXACTLY-0 BOTH + catch_set_-
# filter EXACTLY-0 BOTH — the FIFTH-control honest face vs the 24g 84/84 and
# the 24b/24d 137/137 rows). E9 dup twins EXACTLY-43 (the pair's per-DEFINE
# twins: the execute/dtor families ride DOUBLED where the dtor + C1/D1 faces
# split — GetStats/Swap/HostAttrSwap/DAQSwap/ScratchUpdate/ShowCPU/ShowLat +
# the log_message x3 + the plain-execute block; MEASURED, NEVER the 24g-67/
# 24d-44/24e-53 faces).
#
# The DEC ladder NEVER drives the walls: the inet_ntop-failure -> invalid_ip
# strcpy legs (a poke-wall-UNREACHABLE face — cited NF), the ControlConn
# socket-read wall, the Analyzer message loop, the DropStats REAL banner home
# (utils/stats.cc NEVER lands — the mirror echoes the REAL sums the row body
# folded) — cited NF rows, NEVER fired. The REAL ground legs: ONE — framework/
# module.cc (the Module stats home the ACGetStats machine drives LIVE: the
# REAL init_stats/collect_dump_stats_counts/aggregate_dump_stats_counts/
# set_dump_stats_results/sum_stats bodies ride the crafted probe module table
# through the REAL cc :222 lock_guard seat; the leg's OWN face drags the
# show_stats pair mirror). The SFDAQInstance::ioctl WALL MIRROR POKES the two
# DIOCTL out-structs with binary-exact fixed payloads (.5/.375/.125/.25 faces
# — ZERO %.1f/%.3f half-tie) and the packet clock rides a fixed +5 s tick vs
# the REAL :56 10-s period — the tuner report FIRE leg + the cold-face legs
# BOTH walk REAL. vectors 155 + FACE-A 16 FIRST-RUN-SEED, drift-REFUSED,
# tamper-proven, O0==O2 BYTE-IDENT (bodies + the cross face + the FACE-A
# cross + FACE-A O2). NO stderr wall ships HERE: the pair ships NO banner —
# honest omission.
# The joined OWN token NEVER rides THIS file (the ZERO law — $MN rides the
# runtime concat); the GROUND name rides PATHS by construction (the carrier
# precedent). mod.rs STAYS at the walked face at THIS row (the landing twin
# lands the ONE new wiring line CONCURRENTLY — the STATE-AWARE guard below
# runs GREEN before AND after; the 13-L pin rides ONLY the landing face).
set -euo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
LJ=/opt/data/tools/luajit-src
MN=a""cmd                                # the OWN token rides ONLY the concat
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
A_CC='analyzer_command.cc'; A_H='analyzer_command.h'   # GROUND path seats (carrier law)
mkdir -p "$H" "$H"/o2

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/main/$A_CC)" -eq 583
test "$(md5sum "$SRC"/src/main/$A_CC | awk '{print $1}')" = "2fe847d72cdac14b4b1f5a572d693646"
test "$(wc -l < "$SRC"/src/main/$A_H)" -eq 267
test "$(md5sum "$SRC"/src/main/$A_H | awk '{print $1}')" = "9e9ee8432e295ddecfb5673bed316cc9"
test "$(( 583 + 267 ))" -eq 850                                                  # the pair ledger

# ---- THE ZERO-GATE DIALECT FACE MEASURED EVERY BUILD (by WALK, NEVER
# assumed; the four-way: TEST/TEST_CASE/CATCH/UNIT_TEST find-0 BOTH — the
# ZERO-test-post law, the ut post 0-DELTA VACUOUS; the FIFTH control) ----
test "$(grep -c 'TEST_CASE' "$SRC"/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'TEST_CASE' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'TEST(' "$SRC"/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'TEST(' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'CATCH' "$SRC"/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'CATCH' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'UNIT_TEST' "$SRC"/src/main/$A_CC || true)" -eq 0                # ZERO posts (the walked 0-delta face)
test "$(grep -c 'UNIT_TEST' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c 'REG_TEST' "$SRC"/src/main/$A_CC || true)" -eq 0                 # cc rides ZERO
test "$(grep -c 'REG_TEST' "$SRC"/src/main/$A_H)" -eq 1                          # :261 (the post decl, the pinned face)
test "$(grep -n 'REG_TEST' "$SRC"/src/main/$A_H | cut -d: -f1)" = 261
test "$(grep -c 'SHELL' "$SRC"/src/main/$A_CC || true)" -eq 0                    # the RAW walk face MEASURED (the dialect token count is ZERO both files — NEVER invented; prose rides the hyphen carrier)
test "$(grep -c 'SHELL' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -c '^static' "$SRC"/src/main/$A_CC)" -eq 6                          # the file-statics census (the E9 cite pool)
test "$(grep -n '^static' "$SRC"/src/main/$A_CC | cut -d: -f1 | paste -sd,)" = "55,56,57,60,74,83"   # the pinned seat list
test "$(grep -c '^static' "$SRC"/src/main/$A_H)" -eq 1
test "$(grep -n '^static' "$SRC"/src/main/$A_H | cut -d: -f1)" = 104             # :104 the string_map
test "$(grep -c 'THREAD_LOCAL' "$SRC"/src/main/$A_CC)" -eq 1                     # :55 ONLY
test "$(grep -c 'THREAD_LOCAL' "$SRC"/src/main/$A_H || true)" -eq 0
test "$(grep -n '#if' "$SRC"/src/main/$A_CC | cut -d: -f1)" = 20                 # the HAVE_CONFIG_H rider ONLY
test "$(grep -n '#if' "$SRC"/src/main/$A_H | cut -d: -f1 | paste -sd,)" = "20,261" # the guard + the dialect post
# the cmake posture (the dialect NEVER compiled-in face) ----
test "$(grep -c 'option ( ENABLE_SHELL' "$SRC"/cmake/create_options.cmake)" -eq 1
test "$(grep 'option ( ENABLE_SHELL' "$SRC"/cmake/create_options.cmake | grep -c ' OFF ')" -eq 1
test "$(grep -r REG_TEST "$SRC"/CMakeLists.txt "$SRC"/cmake/ | wc -l)" -eq 0     # the token ABSENT from cmake (MEASURED)
test "$(grep -c 'add_cp'putest "$SRC"/src/main/test/CMakeLists.txt)" -eq 2       # thread_test + the gated distill face (the verbatim split-token arm)
test "$(grep -c "$A_CC" "$SRC"/src/main/test/CMakeLists.txt || true)" -eq 0      # NEITHER dialect list hosts the row TU
test "$(grep -c "$A_H" "$SRC"/src/main/test/CMakeLists.txt || true)" -eq 0
test "$(ls /usr/include/CppUTest 2>/dev/null | wc -l)" -eq 0                     # the dialect host ABSENT MEASURED
test "$(grep -c "$A_H" "$SRC"/src/main/CMakeLists.txt)" -eq 1                    # the ONE INCLUDES seat
test "$(grep -n "$A_H" "$SRC"/src/main/CMakeLists.txt | cut -d: -f1)" = 3
test "$(grep -c "$A_CC" "$SRC"/src/main/CMakeLists.txt)" -eq 1                   # the ONE SOURCES seat
test "$(grep -n "$A_CC" "$SRC"/src/main/CMakeLists.txt | cut -d: -f1)" = 34
test "$(grep -c ENABLE_SHELL "$SRC"/src/main/CMakeLists.txt)" -eq 2              # :20/:22 pair — the row seats ride OUTSIDE the gate

# ---- copy tree = the ipheavy DONOR clone (.o's PURGED after the cp); the
# donor self-heal face. THE DONOR SELECTION CITE (the NEXT.md law): the h :255
# std::vector<DIOCTL_GetSnortLatencyData> seat ONLY the ext#4 9b603f8f family
# satisfies — the trio face 97bca757/9b603f8f/e8a39bf3 IS the legal family. ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H"/o2; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" \( -name "$A_CC" -o -name "$A_H" \) | wc -l)" -eq 0            # the pair find-0 BEFORE the cp (NO ground twin in this donor — the algebra rides 140+2, the MEASURED DIVERGENCE from the 24g twin face)
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"   # the GRAFT trio IN FORCE (verified in the FRESH clone)
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
test "$(md5sum "$C"/config.h     | awk '{print $1}')" = "b5ad224e236fc4a36c19d3cfb71bb8da"   # the EMPTY dialect seat IN FORCE

# ---- FACE 1 (the fresh-cp BARE E4 die, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at cc :34:10 — managers/
# module_manager.h, the FIRST donor-absent head (MEASURED seat) ----
mkdir -p "$C"/main
cp "$SRC"/src/main/$A_CC "$SRC"/src/main/$A_H "$C"/main/
cmp -s "$C"/main/$A_CC "$SRC"/src/main/$A_CC       # VERBATIM cp, NEVER sed
cmp -s "$C"/main/$A_H  "$SRC"/src/main/$A_H
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 142             # 140 donor + BOTH row files FRESH (the MEASURED 140+2 face)
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -iquote$C/main -I$LJ/src -DHAVE_CONFIG_H"
if $GXX0 -c "$C"/main/$A_CC -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c ':34:10' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'managers/module_manager.h: No such file' "$H"/E4_bare.txt)" -eq 1   # the ONE head-missing face

# ---- THE full DECL-closure hull: 6 fresh-cp heads (cmp-PROVED every cp; the
# COLD-WALK face — the full transitive walk, NEVER guessed; the daq drift is
# NEVER chased by EXTRA heads — the SWAP below answers it) ----
FRESH="managers/module_manager.h target_based/host_attributes.h main/analyzer.h main/reload_tracker.h main/reload_tuner.h main/swapper.h"
test "$(echo "$FRESH" | wc -w)" -eq 6                                             # the COLD face
for f in $FRESH; do
    mkdir -p "$C/$(dirname "$f")"
    cp "$SRC"/src/"$f" "$C/$f"
    cmp -s "$C/$f" "$SRC"/src/"$f" || { echo "fresh-cp DRIFT: $f"; exit 1; }
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 148                         # 140 + 2 row + 6 fresh-cp (the closure algebra)

# ---- FACE 2 (the DONOR-GRAFT daq face, MEASURED EXACTLY-5 — the honest
# DIVERGENCE, NEVER the 24f/24g/24h ONE, NEVER the 24e ZERO): the pair IS the
# ioctl-command family; the legacy donor trio's daq_common.h predates the
# ext#4 DIOCTL family — the drift face is the FIVE-seat list below ----
if $GXX0 -c "$C"/main/$A_CC -o "$C"/ac_graft.o 2> "$H"/E4_graft.txt; then
    echo "E4 graft face MOVED — the donor trio suddenly compiles the row CLEAN; RE-MEASURE"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 5                                # MEASURED EXACTLY-5 (the walked seat list)
test "$(grep -c 'fatal error' "$H"/E4_graft.txt)" -eq 0
test "$(grep -c 'has no member named .snort_latency_data' "$H"/E4_graft.txt)" -eq 1   # the ONE struct-member drift leg :501
test "$(grep -c 'analyzer_command.cc:465:5' "$H"/E4_graft.txt)" -eq 1             # DIOCTL_GetCpuProfileData seat
test "$(grep -c 'analyzer_command.cc:473:48' "$H"/E4_graft.txt)" -eq 1            # DIOCTL_GET_CPU_PROFILE_DATA seat
test "$(grep -c 'analyzer_command.cc:474:19' "$H"/E4_graft.txt)" -eq 1            # the get_data cascade seat
test "$(grep -c 'analyzer_command.cc:501:43' "$H"/E4_graft.txt)" -eq 1            # the has-no-member seat
test "$(grep -c 'analyzer_command.cc:570:35' "$H"/E4_graft.txt)" -eq 1            # DIOCTL_GET_SNORT_LATENCY_DATA seat

# ---- FACE 3 (the RE-CITE: the REAL libdaq @ c8d4083 head SWAP -> SILENT
# rc0 BOTH posts; the 3 api heads md5-pinned vs the LIVE $L api face; the
# generated daq_version.h sed face NOT needed — MEASURED; daq_module_api.h/
# daq_defs NEVER pulled — MEASURED 0 seats (the 24h face MOVED for this row)) ----
test "$(git -C "$L" rev-parse HEAD | cut -c1-7)" = "c8d4083"
for h in daq.h daq_common.h daq_dlt.h; do
    cp "$L"/api/"$h" "$C"/
    cmp -s "$C/$h" "$L/api/$h" || { echo "SDK cp DRIFT: $h"; exit 1; }
done
test "$(md5sum "$C"/daq.h            | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h     | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h        | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(find "$C" -name 'daq_version.h' | wc -l)" -eq 0                  # ZERO sed faces shipped (MEASURED)
test "$(find "$C" -name 'daq_module_api.h' | wc -l)" -eq 0               # NEVER needed here (MEASURED)
test "$(find "$C" -name 'daq_defs*' | wc -l)" -eq 0                      # NEVER pulled (MEASURED)
mkdir -p "$H"/o2                                                         # the cold-order law BEFORE any .o writer
$GXX0 -c "$C"/main/$A_CC -o "$C"/ac.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                              # SILENT the plain .o
$GXX0 -DUNIT_TEST -c "$C"/main/$A_CC -o "$H"/o2/ac_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt            # SILENT BOTH posts (the VACUOUS post: ZERO UNIT_TEST posts — the zero-gate honest compile face; the nm delta EXACTLY-0)

# ---- the REAL ground legs (ONE: the Module stats home the ACGetStats
# machine drives LIVE through the REAL lock_guard seat; compiles SILENT
# inside the closed hull; the rest of the NEVER-LAND wall rides the witness
# mirror — every mirror leg prints name+arg, deterministic). ----
$GXX0 -c "$SRC"/src/framework/module.cc -o "$H"/leg_module.o 2> "$H"/E_leg_module.txt
test ! -s "$H"/E_leg_module.txt || { echo "leg COMPILE NOISE: module.cc"; cat "$H"/E_leg_module.txt; exit 1; }

# ---- the nm app-undef census (MEASURED EXACT at the row; the FIFTH-control
# face: plain 34 / ut 34, delta EXACTLY-0 BOTH arms — NO ut-post leg EVER
# ships, the walked zero-post law; NO Catch:: CLASS leg EITHER) ----
nm -C -u "$C"/ac.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 34                            # the measured app-undef wall census
nm -C -u "$H"/o2/ac_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 34                               # plain + ZERO ut legs (delta EXACTLY-0 pinned honest)
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | grep -c '^>')" -eq 0 # the delta FACE: EMPTY (the ZERO-post law)
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | grep -c '^<')" -eq 0
test "$(grep -c 'Catch::' "$H"/nm_U_ut.txt || true)" -eq 0               # NO dialect CLASS leg EVER ships
test "$(grep -c 'Catch::' "$H"/nm_U_plain.txt || true)" -eq 0
test "$(grep -c 'catch_set_filter' "$H"/nm_U_ut.txt || true)" -eq 0      # ABSENT BOTH postures
test "$(grep -c 'catch_set_filter' "$H"/nm_U_plain.txt || true)" -eq 0
nm -C -u "$C"/ac.o | grep -q ' U DropStats'                             # the banner-home seat (the std:: filtered census face — RAW nm rides it)
grep -q 'SFDAQInstance::ioctl' "$H"/nm_U_plain.txt                      # the ioctl wall seat (the poke mirror)
grep -q 'Analyzer::resume(unsigned long)' "$H"/nm_U_plain.txt           # the command-loop seats
grep -q 'snort::packet_gettimeofday' "$H"/nm_U_plain.txt                # the tuner report-timer seat
grep -q 'ModuleManager::reset_stats(clear_counter_type)' "$H"/nm_U_plain.txt   # the ordinal pass (the h enum crosses the wall)
grep -q 'Swapper::finish' "$H"/nm_U_plain.txt                           # the tuner-complete seat
grep -q 'HostAttributesManager::swap_cleanup' "$H"/nm_U_plain.txt       # the reload-dtor pair
grep -q 'ReloadTracker::end' "$H"/nm_U_plain.txt                        # the three reload dtors' seat

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-43 EVERY build: the
# plain .o beside the ut .o — the execute/dtor DEFINE twins ride DOUBLED on
# the C1/D1-split dtor family + the log_message x3 + the plain-exec block;
# NEVER assumed off the 24g-67/24d-44/24e-53 faces) ----
if g++ -std=c++17 -w "$C"/ac.o "$H"/o2/ac_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 43
rm -f "$H"/.e9dup

# ---- the witness mirror (shape-only capture legs; EVERY namespace place-
# ment rides the row's OWN raw-NAME nm census face — the compiler ENFORCED
# the restructure honestly). NO private-access flag EVER ships: the whole
# ladder is reached through PUBLIC seats + the header INLINES + the row's
# OWN bodies alone. ----
test -f "$H"/witness_row.cc
$GXX0 -x c++ -c "$H"/witness_row.cc -o "$H"/witness.o
$GXX0 -c "$H"/probe.cc       -o "$H"/probe.o
$GXX0 -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o

# ---- vectors (FIRST-RUN-SEED law): the row .o + the witness + the ONE
# REAL leg; cmp-PROVEN byte-IDENT vs the TRACKED seed EVERY re-run (drift
# REFUSED); O0==O2 BOTH bodies + the cross face BYTE-IDENT; the tamper arm
# proves the seed. NO stderr wall rides THIS row. ----
WINSL="$H/witness.o $H/leg_module.o -lpthread"
# STATE-AWARE seed guard (the walked face: the sibling may stage PART of this
# dir mid-iteration — the refusal semantic KEPT: a vectors seed tracked but
# MISSING on disk = POST face = refuse; untracked + absent = FIRST-RUN-SEED).
if [ ! -f "$V" ]; then                                   # FIRST-RUN-SEED
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -c vectors_faceA)" -eq 0 || { echo "vectors seed MISSING at POST — refuse"; exit 1; }
    g++ -std=c++17 -w "$H"/probe.o "$C"/ac.o $WINSL -o "$H"/probe_x || exit 1
    "$H"/probe_x > "$H"/vectors_O0.txt || exit 1
    cp "$H"/vectors_O0.txt "$V"
fi
g++ -std=c++17 -w "$H"/probe.o "$C"/ac.o $WINSL -o "$H"/probe_x || exit 1
"$H"/probe_x > "$H"/vectors_O0.txt || exit 1
$GXX0 -O2 -c "$H/probe.cc" -o "$H"/o2/probe.o
$GXX0 -O2 -c "$C/main/$A_CC" -o "$H"/o2/ac.o
$GXX0 -O2 -c "$SRC"/src/framework/module.cc -o "$H"/o2/leg_module.o
$GXX0 -O2 -x c++ -c "$H/witness_row.cc" -o "$H"/o2/witness.o
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/o2/ac.o "$H"/o2/witness.o "$H"/o2/leg_module.o -lpthread -o "$H"/probe_x_O2 || exit 1
"$H"/probe_x_O2 > "$H"/vectors_O2.txt
g++ -std=c++17 -w "$H"/probe.o "$H"/o2/ac.o "$H"/o2/witness.o "$H"/leg_module.o -lpthread -o "$H"/probe_x_cross || exit 1
"$H"/probe_x_cross > "$H"/vectors_O2b.txt
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt  || { echo "DEC O0!=O2 (probe body)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt || { echo "DEC O0!=O2 (row body)"; exit 1; }
test "$(wc -l < "$V")" -eq 155                       # the COLD face (the report-ladder legs MEASURED — the pair owns the long dtor ladders, NEVER stretched to a prior era's count)
test "$(grep -c '^B1 ' "$V")" -eq 1                   # the state-gate face
grep -q 'fin=PASS' "$V"                               # the ladder tail
test "$(grep -c '^NF ' "$V")" -eq 3                   # the cited-wall family face (NEVER fired)
test "$(grep -c 'X tuner.report_progress' "$V")" -eq 1   # the tuner FIRE arm (REAL :88 timercmp on the crafted clock)
test "$(grep -c 'ReloadResourceTuner' "$V")" -eq 3    # the start/running/complete REAL :76/:331/:362 echo legs
test "$(grep -c 'Average' "$V")" -eq 3                # the %.3f report arms (.500/.375/.125 binary-exact faces)
grep -q '203.2.113.7:80 -> 203.2.113.9:443' "$V"      # the REAL format_ip_addr v4 face
grep -q '2001:db8::1:5353' "$V"                       # the REAL v6 5-tuple face
grep -q 'L == reload complete' "$V"                   # the log_message fork face (REAL vprintf legs)
grep -q 'L ReloadResourceTuner\[0\] start' "$V"       # the tuner ladder echo

# ---- FACE-A vectors (the ENUM/ordinal census at the PLAIN posture; the
# walked ordinal map + the string_map law faces) ----
$GXX0 -O2 -c "$H/probe_faceA.cc" -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o "$H"/witness.o -lpthread -o "$H"/probe_faceA_x && "$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt
if [ ! -f "$VA" ]; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -c vectors_faceA.txt)" -eq 0 || { echo "FACE-A seed MISSING at POST — refuse"; exit 1; }
    cp "$H"/vectors_faceA_O0.txt "$VA"
fi
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o "$H"/o2/witness.o -lpthread -o "$H"/probe_faceA_x_O2 && "$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt
g++ -std=c++17 -w "$H"/probe_faceA.o "$H"/o2/witness.o -lpthread -o "$H"/probe_faceA_x_cross && "$H"/probe_faceA_x_cross > "$H"/vectors_faceA_O0b.txt
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O0b.txt || { echo "FACE-A cross drift"; exit 1; }
test "$(wc -l < "$VA")" -eq 16                        # the COLD face (the ordinal map + map law + the dialect ABSENT + the inet-identity legs, MEASURED NEVER stretched)
grep -q '^A1 ordinals: INVALID=-1 DAQ=0' "$VA"        # the h :88-:99 walk face
grep -q 'map_sz=7 .* all_gap=1' "$VA"                # the :101-:113 map vs TYPE_ALL=7 past-end law face
grep -q 'REG_TEST main_unicast_command DECL ABSENT' "$VA"   # the h :261 dialect cited face (the walked cmake OFF posture)
grep -q 'A3 strlen45=46' "$VA"                        # INET6_ADDRSTRLEN (the four dtor buffers' seat)
grep -q 'C2 v6=2001:db8::1' "$VA"                     # the inet-identity arm vs the DEC ladder face
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/fin=PASS/fin=BLOCK/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v
sed 's/map_sz=7/map_sz=6/' "$VA" > "$H"/.tamper_va; ! cmp -s "$H"/.tamper_va "$H"/vectors_faceA_O0.txt; rm -f "$H"/.tamper_va

# ---- THE CENSUS (MEASURED loops; THE ZERO-GATE FACE: NOTHING flips THIS
# row — 32 on-disk / legacy 9 x 4826fc22 FROZEN / 24 lineages / tracked 1
# (gre's) — read + echoed EVERY leg, the UNMOVED zero-gate control law; the
# FIFTH control row walks the SAME 32/9/24/1 face the 24h gate row banked) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 32                     # UNMOVED (the zero-gate control row)   # [24h rider 31->32: the chapter-21 po-li-cy gate row landed ITS copy-local gate (the 62d6fac complete law, walked face)]
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 24                       # UNMOVED (NO new tail EVER — this row ships NO gate)   # [24h rider 23->24: the 24h gate-tail md5 lineage (the 62d6fac law, walked face)]
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh   # the legacy lineage anchor
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1               # tracked face UNCHANGED: gre's ONLY
test -z "$(find "$H" -name 'gate.txt' 2>/dev/null)"                   # NO gate EVER ships HERE (the zero-gate law by WALK)
test -z "$(find "$H" -name 'gate_main.cc' 2>/dev/null)"               # NO runner HERE (the zero-gate companion)
PCG_H=$R/tools/pc""gate_harness
test "$(git -C "$R" status --porcelain -- "$PCG_H"/gate.txt | wc -l)" -eq 0   # the 23e gate ARTIFACT byte-UNTOUCHED
TCH=$R/tools/t""c_harness
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0     # the 22a gate ARTIFACT byte-UNTOUCHED
PT2=$R/tools/pt""racer_harness
test "$(git -C "$R" status --porcelain -- "$PT2"/gate.txt | wc -l)" -eq 0     # the 23f gate ARTIFACT byte-UNTOUCHED
SNP_H=$R/tools/sn""proc_harness
test "$(git -C "$R" status --porcelain -- "$SNP_H"/gate.txt | wc -l)" -eq 0   # the 24a gate ARTIFACT byte-UNTOUCHED
PLG_H=$R/tools/pl""g_harness
test "$(git -C "$R" status --porcelain -- "$PLG_H"/gate.txt | wc -l)" -eq 0   # the 24h gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (the direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$PCG_H"/vectors.txt | awk '{print $1}')"       = "0a6e17ca5532f68c59d1c4c5e174d3fd"
test "$(md5sum "$PCG_H"/vectors_faceA.txt | awk '{print $1}')" = "7b1974dcd85a5d3f1ce1f89ef8b093f8"
test "$(md5sum "$PT2"/vectors.txt | awk '{print $1}')"         = "218ec5b6cde11566f9036e7e2f1f374d"
test "$(md5sum "$PT2"/vectors_faceA.txt | awk '{print $1}')"   = "3a9b0a4b31ba291d98e3a980efc0c2de"

# ---- THE LANDED-HOME AUDIT NEVER rides this harness: the analyzer pair's
# .rs twin + the mod.rs wiring face is the landing SIBLING's home ENTIRELY
# (the walked law — this harness NEVER reads/greps the landing file as a pin
# face). The STATE-AWARE mod.rs arm below runs GREEN before AND after the
# twin lands (the 13-L pin rides ONLY behind the landing's existence — the
# pre-landing line-count face is NEVER pinned anywhere in this file). ----
if [ -f "$R"/src/main/analyzer_command.rs ]; then
    test "$(wc -l < "$R"/src/main/mod.rs)" -eq 13                       # the landing face (the 62d6fac law, walked when the twin lands)
    test "$(grep -c 'pub mod analyzer_command' "$R"/src/main/mod.rs)" -eq 1   # the GROUND-name wiring line (the carrier law)
fi

# ---- STATE-AWARE docs faces (the 23b/24a split law: the landing commit
# banks the PLAN row + the deviations section; the NEXT.md header/seed bank
# rides the ORCHESTRATOR sibling; at THIS row the joined own-token NEVER
# rides ANY doc) ----
docbank=$(grep -q "^## .*row 24i" "$R/KNOWN DEVIATIONS.md" && echo banked || echo unbanked)
echo "docs bank state (24i): $docbank"
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -eq 0                    # own joined token ZERO on NEXT
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c '^| 24i ' "$R/PORTING_PLAN.md")" -eq 1             # the plan-row grep-count-1 law
    test "$(grep -c 'row 24i' "$R/KNOWN DEVIATIONS.md")" -ge 1
    test "$(grep -c "${MN}" "$R/PORTING_PLAN.md")" -eq 0                # the DONE echo NEVER rides docs
    test "$(grep -c "${MN}_DONE" "$R/PORTING_PLAN.md")" -eq 0
    test "$(grep -c "${MN}" "$R/KNOWN DEVIATIONS.md" || true)" -eq 0    # the doc rows ride HYPHEN forms (the a-cmd family law)
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the CURRENT HEAD
# docs face; the NEXT.md file NEVER rides THIS row's commit) ----
test "$(grep -c '930 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3       # the CURRENT seed face x3
for s in 915 900 885 870 855 841 825 810 798 784 772 763 752 724 702 684 659 650 633 629 621 605 597; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c '5 TES'"T(" "$R/NEXT.md")" -eq 1                        # the drift token EXACT-1 (split form; NEVER typed whole HERE)

# ---- token censuses (the own-token family MEASURED 0 PRE-HITS across
# tools/tests/NEXT.md/src at authoring: the dir token rides ONLY the $MN
# concat; the GROUND name rides PATHS by construction (the carrier law —
# the pair it ports is NAMED that); the SELF-scan arms prove THIS row adds
# ZERO joined holders) ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}" "$H"/build.sh || true)" -eq 0                         # SELF-scan (the 23f SELF-HIT law)
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/witness_row.cc | grep -c "${MN}" || true)" -eq 0
test "$(grep -rl "${MN}" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --include='*.cc' --exclude-dir="${MN}_harness" 2>/dev/null | wc -l)" -eq 0   # foreign-holder sweep UNMOVED

# ---- STATE-AWARE stageables dual guard (7 faces: .gitignore + build.sh +
# probe.cc + probe_faceA.cc + witness_row.cc + the 2 vectors; NO PLAN.md,
# NO gate (the zero-gate row law); the header carries the recon). PRE face:
# the files ON DISK; POST face: the ls-files 7-face + the ZERO-leak arms. ----
for f in .gitignore build.sh probe.cc probe_faceA.cc witness_row.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main/analyzer_command.cc copy/main/analyzer_command.h copy/ac.o copy/ac_graft.o copy/daq.h o2/probe.o o2/probe_faceA.o o2/ac.o o2/ac_ut.o o2/witness.o o2/leg_module.o probe_x probe_x_O2 probe_x_cross probe_faceA_x probe_faceA_x_O2 probe_faceA_x_cross probe.o probe_faceA.o witness.o leg_module.o vectors_O0.txt vectors_O2.txt vectors_O2b.txt vectors_faceA_O0.txt vectors_faceA_O2.txt vectors_faceA_O0b.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E9_dup.txt E_leg_module.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt .e9dup .tamper_v .tamper_va stageables.txt run1.log run2.log run3.log run_x.log; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
if [ "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -c '^tools/'"$(basename "$H")"'/vectors(_faceA)\?\.txt$')" -eq 2 ]; then
    # the full-7 POST face fires ONLY once BOTH vector seeds ride the INDEX
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 7
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|build\.sh|probe(_faceA)?\.cc|witness_.*\.cc|vectors(_faceA)?\.txt')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
fi

echo "census (walked, UNMOVED): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $frozen x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor — NO gate ships HERE"
echo "E4: bare dies EXACTLY-1 fatal managers/module_manager.h (cc :34:10, MEASURED); donor-trio graft MEASURED EXACTLY-5 (the daq GENERATION drift family: :465/:473/:474 CPU seats + the :501 has-no-member snort_latency_data + the :570 latency cmd seat — the honest face, NEVER the 1/0-era copies); REAL libdaq SWAP (3 api heads) kills it SILENT rc0 BOTH posts (plain + the VACUOUS post, ZERO UNIT_TEST posts)"
echo "$(printf 'AC%s_DONE' 'MD') vectors=$(wc -l < "$V")/$(wc -l < "$VA") md5=$(md5sum "$V" | awk '{print $1}')/$(md5sum "$VA" | awk '{print $1}') closure=148(140+2+6) graft_err=5 seat501 sdk_swap=3 rc0x2 nm=34/34 delta=0 Catch0 e9=43 legsREAL=1 dialect=REGTEST-h1:261/SHELL0/UNITTEST0 STATIC6+1/TL1+0"
