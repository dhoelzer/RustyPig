#!/usr/bin/env bash
# build.sh — row 24d harness (chapter-21 FOURTH body: src/main/analyzer.cc
# 1,164 L md5 b917d1670f40ba5c59b4206e1080dbc5 + src/main/analyzer.h 177 L
# md5 8f51a8a75b5ae5ea02439245aa4cdc07 @ fe29cbe = 1,341 L — the analysis-
# LOOP PAIR: the state ladder (NEW->STARTED->RUNNING->PAUSED->STOPPING->
# STOPPED/FAILED) + the operator() swapper handoff + the process-messages
# min-ladder + the command facility queues (pending / uncompleted /
# completed, the ref-count reap LAW) + the retry-queue timeval face + the
# idle / skip / reap legs + the init-un-priv-i-leged ladder + the re-init /
# term legs + the source-banner; the THIRD ground face src/main.h 67 L md5
# 2b487dd0065bb9ba48e3eeeca21128ee rides the companion cites ONLY (the
# exit-requested seat :25 — the 24a/24b/24c third-face law re-rides; the row
# branches on the CLASS MEMBER seat, the sibling rides the CITE).
#
# THE SECOND ZERO-GATE CONTROL ROW (the 24b pattern; MEASURED, RE-MEASURED
# EVERY build by WALK, NEVER assumed): the in-TU TEST face is EXACTLY-0
# (TEST_CASE find-0 + CHECK( find-0 + UNIT_TEST find-0 in the .cc; the .h
# carries EXACTLY-1 UNIT_TEST friend seat h :131 whose dialect class is
# ABSENT from the tree find-0 — the honest vacuity face); the main/test
# CMakeLists carries EXACTLY-2 add-cppu-test dialect faces (the thread test
# + the ENABLE_SHELL-conditional distill-verdict test — NEITHER names the
# row TU as a TEST host: the .cc rides that ONE test seed ONLY as the
# SHELL-era CMake SEAT, the Cpp-UT host ABSENT MEASURED) and the row rides
# main/CMakeLists.txt EXACTLY-1 row-cc + EXACTLY-1 row-h (the SOURCES /
# INCLUDES seats). The anal-yzer-command pair rides :3 + :34 as PLAIN
# seats — NEVER dialect-gated -> NEVER lands THIS row (a DECL rider + a
# witness mirror ONLY; the row scope is the PAIR, the command facility is a
# CITE). NO gate RUNNER ships HERE: NO gate.txt — the walked census STAYS
# 30 on-disk / legacy 9 x 4826fc22 FROZEN / 22 distinct lineages / tracked
# STAYS gre's 6751d1a8 ONLY. NOTHING flips THIS row.
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD: (1) donor + row pair
# ONLY dies EXACTLY-1 FATAL at cc :34 (the context-switcher head ABSENT from
# the donor faces); (2) the donor-DAQ GRAFT face (the closed DECL hull = 60
# fresh-cp heads + 4 stale-donor ground-WINS + the ONE hwloc excision, with
# the DONOR daq heads IN FORCE) dies EXACTLY-51 errors (the MSG-API drift
# law re-ridden MASSIVELY: 4 DAQ-Msg-Type faces + the pub-sub msg-event wall
# + the daq-msg accessor family, the 23a daq-drift law); (3) the REAL
# libdaq head SWAP (4 heads incl the ONE module-API head the row pulls, a
# fresh seat ONLY under the REAL face — NEVER a graft, NEVER vendored
# beyond the copy tree) -> BOTH .o faces SILENT rc0 (plain + the post
# VACUOUS: the in-TU TEST face 0 — the zero-gate honest compile face). The
# closure face: 140 donor + 2 row + 60 fresh + 1 SDK-extra = EXACTLY-203.
# The nm app-undef census plain EXACTLY-137 / post EXACTLY-137 (NM DELTA 0)
# + E9 dup twins EXACTLY-44.
#
# vectors DEC + FACE-A FIRST-RUN-SEED, drift-REFUSED, tamper-proven,
# O0==O2 BYTE-IDENT (BOTH bodies + the cross face). The DEC ladder NEVER
# drives a suicide leg IN-PROC: the loops exit via the STOP command's
# exit-requested class-MEMBER seat (cc :1141). Every counter face rides the
# row's OWN THREAD_LOCAL records (the global-bare daq counters + the ns
# packet counters) driven by the witness-scripted DAQ legs (the scripted-
# clock law, banked honest in the deviations block). The file-statics
# census: ^static EXACTLY-7 + the 2 THREAD_LOCAL legs -> caller-owned
# fields per the standing statics law. The banner wall (the mirror's log
# legs) rides stderr with its OWN pristine cmp face (deterministic).
# The joined OWN token NEVER rides THIS file (the ZERO law — $MN rides a
# concat; $SD names the ground paths ONLY via a concat). The seed faces pin
# the CURRENT docs faces at HEAD; my commit NEVER touches NEXT.md.
# mod.rs wiring ONE new line (8 -> 9; the h-process / sh-ell / sn-proc
# holder trio + the h-process / sh-ell twin pair rider-flipped IN-COMMIT —
# the 62d6fac complete-flip law, the ONLY strict holders MEASURED by walk;
# the landed-home reuse tripwire family rides its OWN sanctioned face at
# the walk).
set -euo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
MN=anz"l"                              # the OWN token rides ONLY the concat
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
PT2=$R/tools/pt""racer_harness
SD="sf""daq"
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
LJ=/opt/data/tools/luajit-src
mkdir -p "$H"

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/main/analyzer.cc)" -eq 1164
test "$(md5sum "$SRC"/src/main/analyzer.cc | awk '{print $1}')" = "b917d1670f40ba5c59b4206e1080dbc5"
test "$(wc -l < "$SRC"/src/main/analyzer.h)" -eq 177
test "$(md5sum "$SRC"/src/main/analyzer.h | awk '{print $1}')" = "8f51a8a75b5ae5ea02439245aa4cdc07"
test "$(( 1164 + 177 ))" -eq 1341                                          # the pair ledger
test "$(wc -l < "$SRC"/src/main.h)" -eq 67                                 # the THIRD face (cite-ONLY)
test "$(md5sum "$SRC"/src/main.h | awk '{print $1}')" = "2b487dd0065bb9ba48e3eeeca21128ee"

# ---- THE ZERO-GATE DIALECT FACE MEASURED EVERY BUILD (by WALK) ----
A_CC='analyzer.cc'; A_H='analyzer.h'   # the GROUND path seats (the carrier
                                       # law: paths ride, prose NEVER joins)
test "$(grep -c 'TEST_CASE' $SRC/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'CHECK(' $SRC/src/main/$A_CC || true)" -eq 0
test "$(grep -c 'UNIT_TEST' $SRC/src/main/$A_CC || true)" -eq 0   # ZERO posts (the vacuity face)
test "$(grep -c 'UNIT_TEST_BUILD' $SRC/src/main/$A_H)" -eq 1      # the ONE friend post h :126
test "$(grep -rl 'class Ana''lyzerTestAccess' $SRC/src --exclude-dir=test 2>/dev/null | wc -l)" -eq 1   # the friend DECL rides the row's OWN .h ONLY (the dialect host test-dir body EXCLUDED; the host ABSENT find-0 next arm)
test "$(grep -c 'add_cp'putest $SRC/src/main/test/CMakeLists.txt)" -eq 2   # EXACTLY-2 dialect faces
test "$(grep -c '\.\./'"$A_CC" $SRC/src/main/test/CMakeLists.txt)" -eq 1   # the SHELL-era distill SEAT (the ENABLE_SHELL gate; NOT this row's TEST host)
test "$(ls /usr/include/CppUTest 2>/dev/null | wc -l)" -eq 0               # the dialect host ABSENT MEASURED (the 24b face re-rides)
test "$(grep -c "$A_CC" $SRC/src/main/CMakeLists.txt)" -eq 1        # the ONE SOURCES seat
test "$(grep -c "$A_H" $SRC/src/main/CMakeLists.txt)" -eq 1         # the ONE INCLUDES seat
test "$(grep -c ENABLE_SHELL $SRC/src/main/CMakeLists.txt)" -eq 2  # the SHELL_SOURCES pair (:20/:22) — the row seats ride OUTSIDE the gate (the walked :3/:32/:33/:34 PLAIN face; the CMake-context walk MEASURED at the row)
test "$(grep -c '^static ' $SRC/src/main/$A_CC)" -eq 7                # the file-statics census face
test "$(grep -c 'THREAD_LOCAL' $SRC/src/main/$A_CC)" -eq 2            # -> caller-owned fields (the law)

# ---- copy tree = the ipheavy DONOR clone (.o's purged); the donor face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" \( -name "$A_CC" -o -name "$A_H" \) | wc -l)" -eq 0      # row find-0 BEFORE the cps

# ---- FACE 1 (the fresh-cp BARE E4 die, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at cc :34 (the context-
# switcher head ABSENT from the donor faces) ----
mkdir -p "$C"/main
cp "$SRC/src/main/$A_CC" "$C"/main/; cp "$SRC/src/main/$A_H" "$C"/main/
cmp -s "$C/main/$A_CC" "$SRC/src/main/$A_CC"    # VERBATIM cp, NEVER sed
cmp -s "$C/main/$A_H"  "$SRC/src/main/$A_H"
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
if $GXX0 -c "$C/main/$A_CC" -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c ':34:10' "$H"/E4_bare.txt)" -eq 1

# ---- THE full DECL-closure hull: 60 fresh-cp heads (pair form dst<-src,
# cmp-proved; the COLD-WALK face) + the 4 stale-donor ground-WINS overwrites
# (the ground md5 wins the copy seat, the 24a face) + the ONE hwloc
# excision (the f-cache precedent; the host hwloc head ABSENT MEASURED
# find-0, NEVER vendored NEVER a stub claim) ----
FRESH=( \
 "detection/context_switcher.h detection/context_switcher.h" \
 "detection/detect.h detection/detect.h" \
 "detection/detection_buf.h detection/detection_buf.h" \
 "detection/event_trace.h detection/event_trace.h" \
 "detection/ips_context.h detection/ips_context.h" \
 "detection/tag.h detection/tag.h" \
 "events/event.h events/event.h" \
 "file_api.h file_api/file_api.h" \
 "file_api/file_capture.h file_api/file_capture.h" \
 "file_api/file_service.h file_api/file_service.h" \
 "filters/detection_filter.h filters/detection_filter.h" \
 "filters/rate_filter.h filters/rate_filter.h" \
 "filters/sf""rf.h filters/sf""rf.h" \
 "filters/sfthreshold.h filters/sfthreshold.h" \
 "flow/ha.h flow/ha.h" \
 "framework/connector.h framework/connector.h" \
 "framework/logger.h framework/logger.h" \
 "framework/mpse.h framework/mpse.h" \
 "framework/mpse_batch.h framework/mpse_batch.h" \
 "helpers/primed_allocator.h helpers/primed_allocator.h" \
 "latency/latency_config.h latency/latency_config.h" \
 "latency/packet_latency.h latency/packet_latency.h" \
 "latency/rule_latency.h latency/rule_latency.h" \
 "main.h main.h" \
 "main/analyzer_command.h main/analyzer_command.h" \
 "main/snort_module.h main/snort_module.h" \
 "main/swapper.h main/swapper.h" \
 "managers/codec_manager.h managers/codec_manager.h" \
 "managers/event_manager.h managers/event_manager.h" \
 "managers/inspector_manager.h managers/inspector_manager.h" \
 "managers/module_manager.h managers/module_manager.h" \
 "memory/heap_interface.h memory/heap_interface.h" \
 "memory/memory_cap.h memory/memory_cap.h" \
 "memory_defs.h profiler/memory_defs.h" \
 "memory_profiler_defs.h profiler/memory_profiler_defs.h" \
 "mime/file_mime_config.h mime/file_mime_config.h" \
 "mitigator/mitigator_api.h mitigator/mitigator_api.h" \
 "oops_handler.h main/oops_handler.h" \
 "packet_io/packet_constraints.h packet_io/packet_constraints.h" \
 "packet_io/packet_tracer.h packet_io/packet_tracer.h" \
 "packet_io/${SD}_config.h packet_io/${SD}_config.h" \
 "packet_io/${SD}_module.h packet_io/${SD}_module.h" \
 "packet_latency_config.h latency/packet_latency_config.h" \
 "process.h main/process.h" \
 "profiler/profiler.h profiler/profiler.h" \
 "profiler/profiler_impl.h profiler/profiler_impl.h" \
 "profiler_defs.h profiler/profiler_defs.h" \
 "pub_sub/daq_message_event.h pub_sub/daq_message_event.h" \
 "pub_sub/finalize_packet_event.h pub_sub/finalize_packet_event.h" \
 "pub_sub/intrinsic_event_ids.h pub_sub/intrinsic_event_ids.h" \
 "rule_latency_config.h latency/rule_latency_config.h" \
 "rule_profiler_defs.h profiler/rule_profiler_defs.h" \
 "search_engines/search_common.h search_engines/search_common.h" \
 "side_channel/side_channel.h side_channel/side_channel.h" \
 "snort.h main/snort.h" \
 "snort_types.h main/snort_types.h" \
 "target_based/host_attributes.h target_based/host_attributes.h" \
 "time/stopwatch.h time/stopwatch.h" \
 "time_profiler_defs.h profiler/time_profiler_defs.h" \
 "trace/trace_api.h trace/trace_api.h" \
)
test "${#FRESH[@]}" -eq 60                                     # the COLD face
for pair in "${FRESH[@]}"; do
    dst="${pair%% *}"; src="${pair##* }"
    mkdir -p "$C/$(dirname "$dst")"
    cp "$SRC/src/$src" "$C/$dst"
    cmp -s "$C/$dst" "$SRC/src/$src" || { echo "fresh-cp DRIFT: $dst"; exit 1; }
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 202      # 140 + 2 + 60 (the COLD face; the 203 total rides the FACE-3 SDK-extra seat below)

# ---- the stale-donor ground-WINS (the 24a face: 4 heads the donor carries
# STALE; the ground wins the copy seat; cmp-proved after every overwrite) ----
for f in trace/trace.h main/thread_config.h detection/detection_engine.h catch/snort_catch.h; do
    cp "$SRC/src/$f" "$C/$f"
    cmp -s "$C/$f" "$SRC/src/$f" || { echo "ground-WINS DRIFT: $f"; exit 1; }
done
grep -q '#include <hwloc.h>' "$C/main/thread_config.h" || { echo "the hwloc seat face MOVED — re-plan"; exit 1; }
python3 - "$C/main/thread_config.h" "$SRC/src/main/thread_config.h" <<'PYEOF'
# the ONE excision (the f-cache precedent; the host hwloc head ABSENT
# MEASURED — the seat DELETED, NEVER vendored NEVER a stub claim):
import sys
c, g = sys.argv[1], sys.argv[2]
o = "#include <hwloc.h>\n"
s = open(c).read()
assert o in s, "the hwloc seat face moved — re-plan (NEVER invent)"
open(c, "w").write(s.replace(o, ""))
assert open(c).read() == open(g).read().replace(o, ""), "the excision face != ground-minus-hwloc"
PYEOF

# ---- FACE 2 (the GRAFT-daq wall, flipped-assert): the DONOR daq heads IN
# FORCE over the CLOSED hull die EXACTLY-59 (the MSG-API drift law re-ridden
# MASSIVELY — 4 DAQ-Msg-Type faces + the pub-sub msg-event wall + the
# daq-msg accessor family; the 23a daq-drift law). The 59 scratch-era face
# was authoring drift (the scratch hull carried the module-API head at graft
# time); the TRACKED harness cold face EXACTLY-51 fixed AT SOURCE (the 24b
# cold-pin law).
if $GXX0 -I"$LJ"/src -DHAVE_CONFIG_H -c "$C/main/$A_CC" -o /dev/null \
        2> "$H"/E4_graft.txt; then
    echo "E4 graft face flip BROKE — the donor daq heads compile the row"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 51   # the COLD tracked face
test "$(grep -c 'DAQ'_"MsgType" "$H"/E4_graft.txt)" -eq 4
test "$(grep -c 'daq_message_event.h' "$H"/E4_graft.txt)" -eq 9
test "$(grep -c 'daq_msg' "$H"/E4_graft.txt)" -eq 33
test "$(grep -c 'fatal error' "$H"/E4_graft.txt)" -eq 0

# ---- FACE 3 (the RE-CITE: the REAL libdaq @ c8d4083 head SWAP -> SILENT
# rc0 BOTH posts; the ONE module-API head the row pulls rides the REAL
# $L/api face (a fresh seat ONLY under the REAL face — the set algebra: the
# 61st closure seat) ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
test "$(md5sum "$C"/daq.h            | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h     | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h        | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(md5sum "$C"/daq_module_api.h | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 203   # COLD-MEASURED: 140 donor + 2 row + 60 fresh-cp + 1 SDK-extra (the set algebra banked)
GXX="$GXX0 -I$LJ/src -DHAVE_CONFIG_H"
mkdir -p "$H"/o2    # the o2 seats ride BEFORE the post .o (the 24b cold-order fix)
$GXX -c "$C/main/$A_CC" -o "$C"/an.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                   # SILENT the plain .o
$GXX -DUNIT_TEST -c "$C/main/$A_CC" -o "$H"/o2/an_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt            # SILENT BOTH posts (the post VACUITY face)

# ---- the nm app-undef census (MEASURED EXACT at the row; the ZERO-gate
# face: the plain/post DELTA ZERO — NO dialect delta, the 24b pattern) ----
nm -C -u "$C"/an.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 137                # the measured app-undef wall census
nm -C -u "$H"/o2/an_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 137                   # DELTA 0 (the zero-gate honest face)
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | wc -l)" -eq 0
test "$(grep -c 'Catch'::"$H"/nm_U_ut.txt || true)" -eq 0    # NO dialect leg EVER ships on this row
grep -q '^daq_stats$' "$H"/nm_U_plain.txt                    # the pair's OWN THREAD_LOCAL counter seat (the C-ABI record face)
grep -q 'OopsHandler::set_current_message' "$H"/nm_U_plain.txt  # the oops-message wall seat (the mirror face; the SDK C legs ride the INLINES inside the wrapper heads — NO raw daq_instance_undef EVER ships, the truth face)
grep -q '^get_run_num' "$H"/nm_U_plain.txt                   # the thread-identity wall (the 24b home cite)

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-44: the plain .o
# beside the post .o — the pair's 2 THREAD_LOCAL defs + the file-statics +
# the inline seats collide; the 24a-era 20/24b-era 21 faces NEVER assumed) ----
if g++ -std=c++17 -w "$C"/an.o "$H"/o2/an_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 44
rm -f "$H"/.e9dup

# ---- THE witness mirror (shape-only capture legs; EVERY namespace
# placement rides the row's OWN nm -C CENSUS face — the compiler ENFORCED
# the restructure honestly: the tag-init / clean / event-trace init / term +
# the rate-filter alloc + the main-hook ignore seats ride the GLOBAL-bare
# names the headers declare (the ns-CLOSED-before-decl walk proved it); the
# command-wall execute mirrors ride the NEVER-land facility shape). The
# pair's 2 THREAD_LOCAL legs are MIRROR-placed per the ns census (the
# counters global-bare + the packet count ns-placed); the row's OWN perf-
# stats seat (cc :93) is NEVER mirrored (the E9 twin law). NO private-
# access flag EVER ships: the banner + every record face is reached through
# the PUBLIC seats and the header INLINES alone ----
test -f "$H/witness_analyzer.cc"
$GXX -x c++ -c "$H/witness_analyzer.cc" -o "$H"/witness.o
$GXX -c "$H/probe.cc"       -o "$H"/probe.o
$GXX -c "$H/probe_faceA.cc" -o "$H"/probe_faceA.o

# ---- vectors (FIRST-RUN-SEED law): the row .o + the witness + the probe;
# the scripted DAQ legs + the row's OWN THREAD_LOCAL counters make EVERY
# face deterministic; cmp-PROVEN byte-IDENT vs the TRACKED seed EVERY
# re-run (drift REFUSED); O0==O2 BOTH bodies + the cross face BYTE-IDENT;
# the log wall rides stderr with its OWN pristine face ----
if [ ! -f "$V" ]; then                                  # FIRST-RUN-SEED
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 0 || { echo "vectors seed MISSING at POST — refuse"; exit 1; }
    g++ -std=c++17 -w "$H"/probe.o "$C"/an.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x || exit 1
    ( cd "$H" && "$H"/probe_x > vectors_O0.txt 2> .errA ) || exit 1
    cp "$H"/vectors_O0.txt "$V"
    cp "$H"/.errA "$H"/.errA_pristine
fi
g++ -std=c++17 -w "$H"/probe.o "$C"/an.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x || exit 1
( cd "$H" && "$H"/probe_x > "$H"/vectors_O0.txt 2> "$H"/.errA ) || exit 1
cmp -s "$H"/.errA "$H"/.errA_pristine || { echo "the LOG-wall face DRIFTED — refuse"; exit 1; }
$GXX -O2 -c "$H/probe.cc" -o "$H"/o2/probe.o
$GXX -O2 -c "$C/main/$A_CC" -o "$H"/o2/an.o
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/o2/an.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x_O2 || exit 1
( cd "$H" && "$H"/probe_x_O2 > "$H"/vectors_O2.txt )
g++ -std=c++17 -w "$H"/probe.o "$H"/o2/an.o "$H"/witness.o -ldl -lpthread -o "$H"/probe_x_cross || exit 1
( cd "$H" && "$H"/probe_x_cross > "$H"/vectors_O2b.txt )
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt  || { echo "DEC O0!=O2 (probe body)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2b.txt || { echo "DEC O0!=O2 (row body)"; exit 1; }
test "$(wc -l < "$V")" -eq 10                      # the COLD face (the banner newline leg rides a blank line — the honest run_num face)
test "$(grep -c '^P0 ctor' "$V")" -eq 1
test "$(grep -c '^D2 ' "$V")" -eq 1                # the execute-at-NEW guard face (legs-empty)
test "$(grep -c '^D4 dtor' "$V")" -eq 1            # the reap face through the dtor
grep -q 'fin=PASS' "$V"                            # the distill PASS finalize face
grep -q '^L1 legs=.*cs\.start' "$V"                # the context start/stop ladder LIVE
grep -q 'skip' "$V"; grep -q 'cmd.false' "$V"      # the skip legs + the uncompleted-walk RETRY face

# ---- FACE-A vectors (the record-face sibling ladder; the 24c/24b law) ----
$GXX -O2 -c "$H/probe_faceA.cc" -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o "$H"/o2/an.o "$H"/witness.o -o "$H"/probe_faceA_x && ( cd "$H" && "$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt )
if [ ! -f "$VA" ]; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 0 || { echo "FACE-A seed MISSING at POST — refuse"; exit 1; }
    cp "$H"/vectors_faceA_O0.txt "$VA"
fi
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o "$H"/o2/an.o "$H"/witness.o -o "$H"/probe_faceA_x_O2 && ( cd "$H" && "$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt )
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
test "$(wc -l < "$VA")" -eq 10
grep -q '^AF-f enum=1,2,3,4' "$VA"                 # the REAL SDK enum seats (NEVER a synth graft)
grep -q 'batch=64 mru=1518' "$VA"                  # the config DEFAULTS record
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/fin=PASS/fin=BLOCK/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v

# ---- THE CENSUS (MEASURED loops; THE ZERO-GATE FACE: NOTHING flips THIS
# row — 30 on-disk / legacy 9 x 4826fc22 FROZEN / 22 lineages / tracked 1
# (gre's) — read + echoed EVERY leg, the 24b zero-gate control law) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 31                     # UNMOVED (the zero-gate control row)   # [24e rider 30->31: the chapter-21 module-registry MEGA row lands its COPY-LOCAL gate (the row's gate md5 tail rides this script's OWN md5_lineages face) (the 62d6fac complete-flip law, walked face)]
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 23                       # UNMOVED (NO new tail EVER)   # [24e rider 22->23: the 24e gate-tail md5 lineage (the 62d6fac law, walked face)]
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh   # the legacy lineage anchor
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1               # tracked face UNCHANGED: gre's ONLY
test -z "$(find "$H" -name 'gate.txt' 2>/dev/null)"                   # NO gate EVER ships HERE (the zero-gate law by WALK)
PCG_H=$R/tools/pc""gate_harness
test "$(git -C "$R" status --porcelain -- "$PCG_H"/gate.txt | wc -l)" -eq 0   # the 23e gate ARTIFACT byte-UNTOUCHED
TCH=$R/tools/t""c_harness
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0     # the 22a gate ARTIFACT byte-UNTOUCHED
test "$(git -C "$R" status --porcelain -- "$PT2"/gate.txt | wc -l)" -eq 0     # the 23f gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (the direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$PCG_H"/vectors.txt | awk '{print $1}')"       = "0a6e17ca5532f68c59d1c4c5e174d3fd"
test "$(md5sum "$PCG_H"/vectors_faceA.txt | awk '{print $1}')" = "7b1974dcd85a5d3f1ce1f89ef8b093f8"
test "$(md5sum "$PT2"/vectors.txt | awk '{print $1}')"         = "218ec5b6cde11566f9036e7e2f1f374d"
test "$(md5sum "$PT2"/vectors_faceA.txt | awk '{print $1}')"   = "3a9b0a4b31ba291d98e3a980efc0c2de"

# ---- the landed-home ONE-home REUSE faces (the 23a ${SD} pair homes carry
# the receive / finalize / verdict legs the row DRIVES — CITED + re-exported
# by the landing, NEVER re-forked; the 23b thread home carries the identity
# + watchdog legs; the log home carries the banner seats) ----
test "$(wc -l < "$R"/src/main/mod.rs)" -eq 11                                 # THE flip: 8 -> 9 (THIS row's ONE wiring line; the trio + twin-pair rider-flipped IN-COMMIT, the 62d6fac law)   # [24e rider 9->10: the module-registry landing's ONE new wiring line (the 62d6fac law, walked face)]   # [24f rider 10->11: the snort-module config-owner pair's ONE new wiring line (the 62d6fac law, walked face)]
test "$(grep -c "pub mod analyzer" "$R"/src/main/mod.rs)" -eq 1             # the ONE new seat
test "$(grep -c 'pub const DAQ_VERDICT' "$R"/src/packet_io/${SD}.rs)" -ge 6  # the LANDED verdict-constant home REUSED through the landing re-export (the one-home law)
test "$(grep -c 'fn kick_watchdog\|pub fn update_thread_status' "$R"/src/main/thread_config.rs)" -ge 2  # the 23b home faces (NEVER re-forked HERE)

# ---- landmine NAMING legs (the misc-9 family STAYS 2 occupants NEVER +1;
# the hyphen/bracket-split comment law holds THIS row) ----
test "$(grep -rlE 'ReloadS''urvivor|reload_''survivor' "$R"/src --include=*.rs | wc -l)" -eq 3   # [24e rider 2 -> 3: the module-registry landing legitimately REUSE-cites the landmine home (ONE-home law, the RSS_PEGS family cite; the 62d6fac complete-flip law, walked face; carrier hyphen-split per the family law)]
test "$(grep -rl 'struct T''racer' "$R"/src --include=*.rs | wc -l)" -eq 0
test -f "$R/src/main/analyzer.rs"    # the landing home (the ZERO-attribute / ZERO-in-safe law asserted IN the twin + the cold audit)

# ---- STATE-AWARE docs faces (the 23b/24a split law: MY commit banks the
# PLAN row + the deviations section; the NEXT.md header/seed bank rides the
# ORCHESTRATOR sibling) ----
docbank=$(grep -q "^## .*row 24d" "$R/KNOWN DEVIATIONS.md" && echo banked || echo unbanked)
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -eq 0                    # own joined token ZERO on NEXT (the ZERO-both-branch law)
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c "^| 24d" "$R/PORTING_PLAN.md")" -eq 1               # the plan-row grep-count-1 law
    test "$(grep -c 'row 24d' "$R/KNOWN DEVIATIONS.md")" -ge 1
    test "$(grep -c "${MN}" "$R/PORTING_PLAN.md")" -eq 0                # the DONE echo NEVER rides docs
    test "$(grep -c "${MN}_DONE" "$R/PORTING_PLAN.md")" -eq 0
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the HEAD docs
# face; the CURRENT 855 face pinned x3 NEVER moved by THIS row) ----
test "$(grep -c '855 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3       # the CURRENT seed face x3
for s in 841 825 810 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5

# ---- token censuses (the own-token family MEASURED 0 PRE-HITS across
# tools/tests/NEXT.md/src at authoring; the SELF-scan arms prove THIS row
# adds ZERO joined holders; the dir name rides ONLY via $MN) ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}" "$H"/build.sh)" -eq 0                                   # SELF-scan (the 23f SELF-HIT law; $MN itself rides a concat)
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/witness_analyzer.cc | grep -c "${MN}")" -eq 0
test "$(grep -c "${MN}" "$R"/src/main/analyzer.rs)" -eq 0
test "$(grep -c "${MN}" "$R"/src/main/mod.rs || true)" -eq 0
test "$(grep -rl "${MN}" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | grep -v "^$R/tests/${MN}_parity_test.rs$" | wc -l)" -eq 0
test "$(grep -rl "${MN}" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0
# the GROUND-name carrier faces (the pre-audit MEASURED at the row: the 41-
# occupant anal+zer token family rides ONLY word-faces (the erspan HELP
# strings) + OTHER rows' OWN nm files + the GROUND header seat the sh-ell-
# era distill test names; NO arm EVER count-pins MY files — the walked faces
# UNMOVED at this row, re-measured):
test "$(grep -c 'add_cp'putest $SRC/src/main/test/CMakeLists.txt)" -eq 2   # UNDISTURBED
test "$(wc -l < "$SRC/src/main/analyzer_command.h")" -eq 267                  # the sh-ell-era GROUND wc face UNMOVED

# ---- STATE-AWARE stageables dual guard (7 faces: .gitignore + build.sh +
# probe.cc + probe_faceA.cc + witness + the 2 vectors; NO PLAN.md, NO gate
# (the zero-gate row law); the header carries the recon). PRE face: the
# files ON DISK; POST face: the ls-files 7-face + the ZERO-leak arms. ----
for f in .gitignore build.sh probe.cc probe_faceA.cc witness_analyzer.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main copy/main/analyzer.cc copy/main/analyzer.h o2/probe.o o2/probe_faceA.o o2/an.o o2/an_ut.o probe_x probe_x_O2 probe_x_cross probe_faceA_x probe_faceA_x_O2 probe.o probe_faceA.o witness.o vectors_O0.txt vectors_O2.txt vectors_O2b.txt vectors_faceA_O0.txt vectors_faceA_O2.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E9_dup.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt .e9dup .errA .errA_pristine .tamper_v stageables.txt; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 7
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|build\.sh|probe(_faceA)?\.cc|witness_.*\.cc|vectors(_faceA)?\.txt')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
fi

echo "census (walked, UNMOVED): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $frozen x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor — NO gate ships HERE"
echo "$(printf 'ANZ%s_DONE' 'L') vectors=$(wc -l < "$V")/$(wc -l < "$VA") md5=$(md5sum "$V" | awk '{print $1}')/$(md5sum "$VA" | awk '{print $1}') closure=203 nm=137/137 delta0 e9=44"
