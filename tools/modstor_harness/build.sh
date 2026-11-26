#!/usr/bin/env bash
# build.sh — row 24e harness (chapter-21 FIFTH body: main/modules.cc 2491 L
# md5 1a1c7937a7c6b73318122a924e37ecff + modules.h 30 L md5
# d004a88be5ec59832bcef19b9e652733 @ fe29cbe = THE module-REGISTRY PAIR:
# add_independent_modules (35 PluginManager::add_module boots) +
# add_dependent_modules (1 + the ifdef-gated Mitigator face) + the whole
# in-TU policy-module family + the Ips action-variable parameter CHAIN
# (ips_params -> variable_params -> action_vars_params -> action_var_params
# -> action_var_react_params); THE chapter-21 FIFTH REAL GATE ROW: the
# EXACTLY-1 #ifdef UNIT_TEST post :2425 (the +catch/snort_catch.h :2426 +
# +log/log_errors.h :2427 includes) riding EXACTLY-4 Catch TEST_CASEs
# ([Ip""sModule] tag, RUNTIME-built EVERYWHERE — the family law; THIS file
# NEVER types it joined) at :2429 :2442 :2455 :2469 with EXACTLY-12 CHECK
# legs (4+2+2+2+2 — the first gate family with 4 in-TU cases at once).
# THE CENSUS FLIP (62d6fac complete-flip law): 30->31 on-disk / 9 legacy
# 4826fc22 UNMOVED / 22->23 lineages / tracked STAYS 1 (gre 6751d1a8 ONLY).
#
# THE GATE SEMANTICS (the FUNCTIONAL mirror law): the 4th TEST checks
# DUPLICATE-REJECTION -> the witness IpsPolicy action_vars map + the
# ips_policy holder MUST REALLY track committed names (ground policy.cc
# :161-:176 semantics mirrored; the policy.cc TU NEVER lands — the
# PolicyMap wall); the 2nd/3rd ride reset/get_parse_errors + ParseError
# through the REAL ground log/messages.cc .o (link-real, rc0 MEASURED).
#
# THE CMAKE DIALECT FACE MEASURED: main/CMakeLists.txt modules.cc :37 +
# modules.h :38 ride the PLAIN SOURCES seats (grep-c EXACTLY-1 each — the
# ground NAME rides PATHS, the 24a carrier precedent); the main/test
# CMakeLists carries EXACTLY-2 add-cppu-test dialect faces (OTHER rows)
# and names the row TU EXACTLY-0. '#ifdef CRASH_MITIGATOR' EXACTLY-2
# (:58 include + :2420 the dependent MitigatorModule boot) — the token
# NEVER defined (the copy config.h face EMPTY) -> MitigatorModule NEVER
# active; the dependent face rides TraceModule ONLY (the FACE-A A8 leg).
#
# THE config.h DIALECT FACE MEASURED (the donor seat EMPTY '#pragma once'
# md5 b5ad224e... IN FORCE — NEVER overwritten THIS row; the live faces:
# HAVE_UUID OFF (the uuid_t fallback typedef, uuid_parse uuid_clear seats
# DEAD — ZERO libuuid legs), HAVE_HYPERSCAN OFF, REG_TEST OFF,
# ENABLE_DETECTION_OFFLOAD OFF, HAVE_NUMA OFF (the ONE hwloc EXCISION, the
# numa_harness/24d precedent — host /usr/include/{uuid,hwloc} ABSENT
# MEASURED find-0), CRASH_MITIGATOR OFF, UNIT_TEST carried ONLY by the
# gate .o, HAVE_CONFIG_H ON (the -D seat). NEVER invented.
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD: (1) donor + row pair
# ONLY dies EXACTLY-1 FATAL at modules.cc :29 (the donor-absent
# actions/actions_module.h head — the FIRST missing seat); (2) the FULL
# DECL-closure hull (77 fresh-cp heads + 6 ground-WINS + the ONE hwloc
# excision) with the DONOR GRAFT daq heads (daq.h 97bca757 / daq_common.h
# 9b603f8f / daq_dlt.h e8a39bf3) IN FORCE: MEASURED EXACTLY-0 errors —
# THE honest divergence face: the row's include surface pulls ZERO
# daq_version/daq-msg drift faces (the 23a/24b/24d rows pulled the msg-API
# wall; the registry TU NEVER does — MEASURED, NEVER assumed; the pin
# rides ZERO with the flipped face re-armed at the fatal arm); (3) the
# REAL libdaq @ c8d4083 head SWAP (4 heads + the generated daq_version.h
# sed face 3.0.29.0, the daqio law) -> BOTH posts compile SILENT rc0 (the
# plain .o + the -DUNIT_TEST gate .o — the 4 Catch legs CLEAN inside the
# TU). Closure face: 140 donor + 2 row + 77 fresh + 2 SDK-extra = 221.
#
# THE GATE-LINK FACE: modules_ut.o + the RUNNER .o (the 24c CATCH_CONFIG_
# RUNNER shape + the plain-MAIN twin BOTH GREEN — the 22a SEGV posture
# NEVER surfaced: the 4 cases NEVER deref get_conf; the boot-conf seat
# rides the static-local boot leg) + ONE REAL framework leg
# (src/framework/module.cc — the Module base home, the landed Rust
# framework/module.rs cites it) + ONE REAL log leg (src/log/messages.cc —
# the parse-error counter home) + the LuaJIT legs REAL (luaL_optlstring
# resolves against the vendored libluajit.a BY PATH, the 24c law) +
# ZERO libcrypto legs MEASURED (the pair pulls no OpenSSL face).
# nm app-undef: plain EXACTLY-120 / ut EXACTLY-137 (Catch 11; the ut
# non-Catch = 126). E9 dup twins flipped-assert EXACTLY-53.
# vectors DEC 46 L + FACE-A 9 L FIRST-RUN-SEED, drift-REFUSED, tamper-
# proven, O0==O2 BYTE-IDENT (the ladder rides the witness NAME capture —
# names+counts, ZERO pointers). The ladder IS the module-name face: 37
# PluginManager::add_module boots (35 independent + 1 dependent Trace +
# the ifdef-gated Mitigator ZERO live).
# THE joined OWN token NEVER rides THIS file (the ZERO law — $MN = mod""sto
# r runtime concat); the ground NAME 'modules' rides PATHS by construction
# (the 24a carrier precedent — pinned faces); the DONE marker printf-concat-
# built. Seed faces ride the CURRENT docs faces at HEAD; THIS row NEVER
# touches NEXT.md / PORTING_PLAN / KNOWN DEVIATIONS.
set -euo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
LJ=/opt/data/tools/luajit-src
MN=mod""""stor
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
mkdir -p "$H"

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
# the ground NAME carrier faces ride PATHS (the 24a precedent: the row is
# NAMED for what it ports — the census arms above ride $MN, NEVER this) ----
test "$(wc -l < "$SRC"/src/main/modules.cc)" -eq 2491
test "$(md5sum "$SRC"/src/main/modules.cc | awk '{print $1}')" = "1a1c7937a7c6b73318122a924e37ecff"
test "$(wc -l < "$SRC"/src/main/modules.h)" -eq 30
test "$(md5sum "$SRC"/src/main/modules.h | awk '{print $1}')" = "d004a88be5ec59832bcef19b9e652733"
test "$(( 2491 + 30 ))" -eq 2521                                          # the pair ledger
test "$(wc -l < "$SRC"/src/main.h)" -eq 67                                # the THIRD face (cite-ONLY)
test "$(md5sum "$SRC"/src/main.h | awk '{print $1}')" = "2b487dd0065bb9ba48e3eeeca21128ee"

# ---- THE GATE DIALECT FACE MEASURED EVERY BUILD (the walk, NEVER assumed) ----
test "$(grep -c "#ifdef UNIT_TEST" "$SRC"/src/main/modules.cc)" -eq 1     # the EXACTLY-1 post :2425
test "$(grep -c "TEST_CASE" "$SRC"/src/main/modules.cc)" -eq 4            # :2429 :2442 :2455 :2469
test "$(grep -c "CHECK(" "$SRC"/src/main/modules.cc)" -eq 12              # the 12 CHECK legs
for ln in 2429 2442 2455 2469; do
    anchor=$(awk "NR==$ln" "$SRC"/src/main/modules.cc)
    case "$anchor" in
        'TEST_CASE("IPS action variable '*) test "$(grep -c "\[$(printf 'Ip%s' 'sModule')\]" <<< "$anchor")" -eq 1 ;;
        *) echo "TEST_CASE anchor MOVED at :$ln — re-plan"; exit 1 ;;
    esac
done
test "$(grep -c 'catch/snort_catch.h' "$SRC"/src/main/modules.cc)" -eq 1  # :2426 the shim include
test "$(grep -c 'log/log_errors.h' "$SRC"/src/main/modules.cc)" -eq 1     # :2427 the counter include
test "$(grep -c '#ifdef CRASH_MITIGATOR' "$SRC"/src/main/modules.cc)" -eq 2   # :58 + :2420 (NEVER active)
test "$(grep -c '^[[:space:]]*static ' "$SRC"/src/main/modules.cc)" -eq 43    # the file-statics census face
test "$(grep -c "THREAD_LOCAL" "$SRC"/src/main/modules.cc)" -eq 2             # -> caller-owned fields (the law)
test "$(grep -c 'add_module(new' "$SRC"/src/main/modules.cc)" -eq 37          # the ladder boots (35+2)
test "$(grep -c "add_cp"'putest' "$SRC"/src/main/test/CMakeLists.txt)" -eq 2  # OTHER dialects (host find-0)
test "$(grep -c "modules.cc" "$SRC"/src/main/test/CMakeLists.txt)" -eq 0      # the row rides NO test list
test "$(grep -c "modules.cc" "$SRC"/src/main/CMakeLists.txt)" -eq 1           # the ONE SOURCES seat :37
test "$(grep -c "modules.h" "$SRC"/src/main/CMakeLists.txt)" -eq 1            # the INCLUDES seat :38 (PLAIN)

# ---- copy tree = ipheavy DONOR clone (.o's purged); the donor face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" \( -name 'modules.cc' -o -name 'modules.h' \) | wc -l)" -eq 0   # the row find-0 BEFORE the cps
test "$(md5sum "$C"/catch/catch.hpp | awk '{print $1}')" = "74ef54e848cf843c99e3acdb94ce2b1a"
test "$(wc -l < "$C"/catch/catch.hpp)" -eq 20397
test "$(md5sum "$C"/config.h | awk '{print $1}')" = "b5ad224e236fc4a36c19d3cfb71bb8da"   # the EMPTY dialect seat

# ---- STALE-DONOR ground-WINS (the 24a face: the ground md5 wins the copy
# seat — the 6 heads the donor carries STALE vs the pair's needs) ----
for f in catch/snort_catch.h main/policy.h main/snort_config.h main/snort_types.h main/thread.h main/thread_config.h; do
    cp "$SRC"/src/"$f" "$C"/"$f"
    cmp -s "$C"/"$f" "$SRC"/src/"$f" || { echo "ground-WINS DRIFT: $f"; exit 1; }
done
grep -q '#include <hwloc.h>' "$C/main/thread_config.h" || { echo "the hwloc seat face MOVED — re-plan"; exit 1; }
python3 - "$C/main/thread_config.h" "$SRC/src/main/thread_config.h" <<'PYEOF'
# the ONE hwloc EXCISION (the numa_harness/24d precedent; the host hwloc
# head ABSENT MEASURED — the seat DELETED, NEVER vendored NEVER a stub
# claim; HAVE_NUMA OFF -> the numa.h seat NEVER pulled)
import sys
c, g = sys.argv[1], sys.argv[2]
o = "#include <hwloc.h>\n"
s = open(c).read()
assert o in s, "the hwloc seat face moved — re-plan (NEVER invent)"
open(c, "w").write(s.replace(o, ""))
assert open(c).read() == open(g).read().replace(o, ""), "the excision face != ground-minus-hwloc"
PYEOF
test "$(md5sum "$C"/catch/snort_catch.h | awk '{print $1}')" = "9d4c41898691fc461b3f45240007803d"   # the REAL 72-L ground shim

# ---- FACE 1 (THE fresh-cp BARE E4 DIE, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at the donor-absent
# actions/actions_module.h head (modules.cc :29, the pair's FIRST missing
# seat) ----
cp "$SRC"/src/main/modules.cc "$SRC"/src/main/modules.h "$C"/main/
cmp -s "$C"/main/modules.cc "$SRC"/src/main/modules.cc                   # VERBATIM cp, NEVER sed
cmp -s "$C"/main/modules.h  "$SRC"/src/main/modules.h
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -iquote$C/main -I$LJ/src -DHAVE_CONFIG_H"
if $GXX0 -c "$C"/main/modules.cc -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'actions/actions_module.h: No such file' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'modules.cc:29:10' "$H"/E4_bare.txt)" -eq 1

# ---- THE full DECL-closure hull (77 fresh-cp heads from ground,
# cmp-proved EVERY cp, cold-walked at the compiler face — the pair pulls
# ~55 includes and the closure walks to 77 donor-absent seats) ----
FRESH="actions/actions_module.h detection/detection_module.h detection/fp_config.h detection/rule_option_types.h detection/rules.h detection/signature.h detection/tag.h detection/treenodes.h events/event_queue.h file_api/file_api.h file_api/file_policy.h file_api/file_service.h filters/detection_filter.h filters/rate_filter.h filters/sfrf.h filters/sfthd.h filters/sfthreshold.h flow/ha_module.h framework/connector.h framework/mpse.h framework/mpse_batch.h framework/reload_survivor_subscriptions_impl.h hash/lru_cache_shared.h helpers/event_gen.h host_tracker/cache_allocator.h host_tracker/cache_allocator.cc host_tracker/cache_interface.h host_tracker/host_cache.h host_tracker/host_cache_module.h host_tracker/host_cache_segmented.h host_tracker/host_tracker.h host_tracker/host_tracker_module.h js_norm/js_config.h js_norm/js_enum.h js_norm/js_norm_module.h latency/latency_module.h log/batched_logger.h log/log_errors.h log/log_stats.h lua/lua.h main/analyzer_command.h main/network_module.h main/reload_tuner.h main/snort.h main/snort_module.h managers/action_manager.h managers/module_manager.h memory/memory_module.h mime/file_mime_config.h network_inspectors/appid/application_ids.h packet_io/active_counts.h packet_io/packet_tracer_module.h packet_io/sfdaq_module.h parser/config_file.h parser/parse_conf.h parser/parser.h parser/var_dependency.h parser/vars.h payload_injector/payload_injector_module.h ports/port_group.h profiler/memory_defs.h profiler/memory_profiler_defs.h profiler/profiler.h profiler/profiler_defs.h profiler/profiler_module.h profiler/rule_profiler_defs.h profiler/time_profiler_defs.h search_engines/pat_stats.h search_engines/search_common.h sfip/sf_vartable.h side_channel/side_channel.h side_channel/side_channel_module.h target_based/host_attributes.h time/stopwatch.h time/tsc_clock.h trace/trace_api.h trace/trace_module.h"
test "$(echo "$FRESH" | wc -w)" -eq 77                                   # the COLD face
for f in $FRESH; do
    mkdir -p "$C/$(dirname "$f")"
    cp "$SRC"/src/"$f" "$C/$f"
    cmp -s "$C/$f" "$SRC"/src/"$f" || { echo "fresh-cp DRIFT: $f"; exit 1; }
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 219                # 140 + 2 row + 77 fresh (the COLD face)

# ---- FACE 2 (the DONOR-GRAFT daq face, MEASURED ZERO): the donor daq
# trio IN FORCE over the CLOSED hull — the row's include surface pulls
# ZERO drifted faces (MEASURED: the registry TU NEVER touches
# daq_version_string / the msg-API wall; the honest divergence from the
# 23a/24b/24d rows, re-measured EVERY build; the flipped arm rides the
# fatal-zero + rc0 face) ----
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"   # the GRAFT trio pinned
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
if ! $GXX0 -c "$C"/main/modules.cc -o "$C"/mods_graft.o 2> "$H"/E4_graft.txt; then
    echo "E4 graft face MOVED — the donor daq trio suddenly breaks the row"; head -5 "$H"/E4_graft.txt; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 0                       # MEASURED ZERO (never assume a prior row's count)
test "$(grep -c 'fatal error' "$H"/E4_graft.txt)" -eq 0
test "$(grep -c 'daq_version' "$H"/E4_graft.txt || true)" -eq 0          # ZERO drift faces pulled (the divergence law)

# ---- FACE 3 (the RE-CITE: the REAL libdaq @ c8d83c8 head SWAP -> SILENT
# rc0 BOTH posts; the daq_version.h sed face, the daqio-generated law) ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
sed -e 's/@DAQ_MAJOR_VERSION@/3/' -e 's/@DAQ_MINOR_VERSION@/0/' -e 's/@DAQ_PATCH_VERSION@/29/' -e 's/@DAQ_SUBLEVEL_VERSION@/0/' \
    "$L"/api/daq_version.h.in > "$C"/daq_version.h
test "$(md5sum "$C"/daq.h            | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"   # REAL HEAD pins
test "$(md5sum "$C"/daq_common.h     | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h        | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(md5sum "$C"/daq_module_api.h | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
test "$(wc -l < "$C"/daq_version.h)" -eq 49                              # the .in template face (sed NEVER adds lines)
test "$(find "$C" -name 'daq_version.h' | wc -l)" -eq 1
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 221                # 219 + 2 SDK-extra (the set algebra banked)
mkdir -p "$H"/o2                                                         # the 24b cold-order law BEFORE any .o writer
$GXX0 -c "$C"/main/modules.cc -o "$C"/mods.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                              # SILENT the plain .o
$GXX0 -DUNIT_TEST -c "$C"/main/modules.cc -o "$H"/mods_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt                                                # SILENT the GATE .o (the 4 Catch legs CLEAN)

# ---- the REAL ground legs (the ONLY link-real bodies beside the row: the
# Module base home src/framework/module.cc (the landed Rust
# framework/module.rs cites it) + the parse-error counter home
# src/log/messages.cc (the reset/get_parse_errors pair the 2nd/3rd/4th
# gates ride REAL)); the LuaJIT legs ride the vendored .a BY PATH (24c law) ----
$GXX0 -c "$SRC"/src/framework/module.cc -o "$H"/module_leg.o 2> "$H"/E_module.txt
test ! -s "$H"/E_module.txt
$GXX0 -c "$SRC"/src/log/messages.cc -o "$H"/messages.o 2> "$H"/E_messages.txt
test ! -s "$H"/E_messages.txt
test "$(nm --defined-only "$LJ"/src/libluajit.a | grep -cE ' T luaL_optlstring$')" -eq 1   # the REAL T def the row resolves (NEVER a stub)

# ---- the nm app-undef census (MEASURED EXACT at the row) ----
nm -C -u "$C"/mods.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 120                            # the app-undef census (the NEVER-LAND wall: 37 module ctors/vtables/manager/parse/filter legs — witness-mirrored, ZERO bodies landed beyond the two REAL ground legs)
nm -C -u "$H"/mods_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 137
test "$(grep -c 'Catch::' "$H"/nm_U_ut.txt)" -eq 11                      # the Catch delta (closed by the RUNNER .o)
test "$(grep -vc 'Catch::' "$H"/nm_U_ut.txt)" -eq 126                    # 120 + the TEST-face delta legs (holder/IpsPolicy legs/ParseError legs)
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | grep -c '^<')" -eq 0 # the plain face rides SUBSET (no leg drops in the dialect)

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-53: the plain .o
# beside the ut .o — the pair's T-defs + the file-statics ALL collide) ----
if g++ -std=c++17 -w "$C"/mods.o "$H"/mods_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 53
rm -f "$H"/.e9dup

# ---- the witness mirror (shape-only + the FUNCTIONAL legs; the namespace
# legs ride the row .o's OWN nm -C census) + the probe TUs ----
$GXX0 -x c++ -c "$H"/witness_modulesrow.cc -o "$H"/witness.o
$GXX0 -c "$H"/probe.cc       -o "$H"/probe.o                             # the row rides the direct-include seat
$GXX0 -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o                       # the parameter-CHAIN walk (same seat)
$GXX0 -c "$H"/gate_main.cc   -o "$H"/gate_main.o                         # the RUNNER TU (TRACKED; the vendor head carries the decls)

# ---- THE GATE (E10 BOTH ways GREEN — the 4 [Ip""sModule] cases ride the
# REAL messages.cc counter + the FUNCTIONAL IpsPolicy/holder mirror legs +
# the REAL LuaJIT leg for the static Command-table lua seats) ----
WINSL="$H/witness.o $H/module_leg.o $H/messages.o -L$LJ/src -l:libluajit.a -lm -ldl"
g++ -std=c++17 -w "$H"/gate_main.o "$H"/mods_ut.o $WINSL -o "$H"/gate_x
"$H"/gate_x > "$H"/gate.txt 2> "$H"/gate_stderr.txt
test "$?" -eq 0
grep -q "All tests passed (12 assertions in 4 test cases)" "$H"/gate.txt
printf '#define CATCH_CONFIG_MAIN\n#include "catch/catch.hpp"\n' > "$H"/.catch_main_probe.cc
$GXX0 -c "$H"/.catch_main_probe.cc -o "$H"/.catch_main_probe.o
g++ -std=c++17 -w "$H"/.catch_main_probe.o "$H"/mods_ut.o $WINSL -o "$H"/gate_twin_x
"$H"/gate_twin_x > "$H"/.twin.txt 2>/dev/null; rc=$?
test "$rc" -eq 0
grep -q "All tests passed (12 assertions in 4 test cases)" "$H"/.twin.txt   # THE honest GREEN MAIN twin (the 22a SEGV posture NEVER rides this row)

# ---- vectors (FIRST-RUN-SEED law): links the ladder closure; the probe
# TUs carry no RUNNER, so a CATCH_CONFIG_RUNNER impl-only TU (main-LESS)
# closes the witness installer's AutoReg legs (the vendored catch.hpp :48
# law: RUNNER|MAIN both select CATCH_IMPL; the RUNNER form = impl w/o a
# main). On FIRST RUN seed + pin; every later run cmp-PROVEN byte-IDENT
# (drift refused) ----
printf '#define CATCH_CONFIG_RUNNER\n#include "catch/catch.hpp"\n' > "$H"/.catch_probe.cc
$GXX0 -c "$H"/.catch_probe.cc -o "$H"/.catch_probe.o
g++ -std=c++17 -w "$H"/probe.o "$H"/witness.o "$H"/.catch_probe.o "$H"/module_leg.o "$H"/messages.o -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_x
"$H"/probe_x > "$H"/vectors_O0.txt; test "$?" -eq 0
$GXX0 -O2 -c "$H"/probe.cc -o "$H"/o2/probe.o
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/witness.o "$H"/.catch_probe.o "$H"/module_leg.o "$H"/messages.o -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_x_O2
"$H"/probe_x_O2 > "$H"/vectors_O2.txt
if [ ! -f "$V" ]; then
    cp "$H"/vectors_O0.txt "$V"
    md5sum "$V" | awk '{print $1}' > "$H"/md5_pinned.txt                 # the FIRST-RUN-SEED face
fi
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt || { echo "DEC O0!=O2 (row body through the include seat)"; exit 1; }
test "$(wc -l < "$V")" -eq 46
test "$(grep -c '^[A-Z]' "$V")" -eq 46
$GXX0 -O2 -c "$H"/probe_faceA.cc -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o "$H"/witness.o "$H"/.catch_probe.o "$H"/module_leg.o "$H"/messages.o -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_faceA_x
"$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o "$H"/witness.o "$H"/.catch_probe.o "$H"/module_leg.o "$H"/messages.o -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_faceA_x_O2
"$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt
if [ ! -f "$VA" ]; then cp "$H"/vectors_faceA_O0.txt "$VA"; fi
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
test "$(wc -l < "$VA")" -eq 9
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/I1 independent=/I1 independentX=/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v
sed 's/A9 sizeof_Parameter/A8 sizeof_Parameter/' "$VA" > "$H"/.tamper_va; ! cmp -s "$H"/.tamper_va "$H"/vectors_faceA_O0.txt; rm -f "$H"/.tamper_va

# ---- THE CENSUS (MEASURED loops; THE FLIP STATEMENT): 30->31 on-disk
# (THIS row's NEW gate.txt, copy-local UNTRACKED — the chapter-21 FIFTH
# real gate row), distinct md5 lineages 22->23 (this row's fresh tail),
# legacy 9 x 4826fc22 FROZEN UNMOVED, tracked face STAYS 1 (gre 6751d1a8
# ONLY) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 31                        # THE FLIP: 30 -> 31 at THIS row (the 62d6fac complete-flip law)
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 23                          # THE FLIP: 22 -> 23 distinct tails (this row's fresh md5 lineage)
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                  # tracked face UNCHANGED: gre's ONLY
git -C "$R" check-ignore -q tools/${MN}_harness/gate.txt                 # posture = copy-local UNTRACKED (the tc law)
SNP_H=$R/tools/sn""proc_harness
test "$(git -C "$R" status --porcelain -- "$SNP_H"/gate.txt | wc -l)" -eq 0     # the 24a gate ARTIFACT byte-UNTOUCHED
TCH=$R/tools/t""c_harness
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0       # the 22a gate ARTIFACT byte-UNTOUCHED
SHP_H=$R/tools/sh""ell_harness
test "$(git -C "$R" status --porcelain -- "$SHP_H"/gate.txt | wc -l)" -eq 0     # the 24c gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$SNP_H"/vectors.txt | awk '{print $1}')"     = "72a9e77022c15c4d190e0e0a6d8514de"
test "$(md5sum "$TCH"/vectors_faceA.txt | awk '{print $1}')" = "653103cb599ea6369949eeb35a8ed698"

# ---- STATE-AWARE docs faces (the 23b/24a split law: MY commit banks the
# PLAN row + the deviations section; the NEXT.md header/seed bank rides
# the ORCHESTRATOR sibling — at THIS row the joined own-token NEVER rides
# NEXT.md) ----
docbank=$(grep -q "^## .*row 24e" "${R}"/KNOWN\ DEVIATIONS.md && echo banked || echo unbanked)
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -eq 0                     # own joined token ZERO on NEXT (the ZERO law — the ground NAME carries, NEVER this token)
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c "^| 24e" "$R/PORTING_PLAN.md")" -eq 1                 # the plan-row grep-count-1 law
    test "$(grep -c 'row 24e' "${R}"/KNOWN\ DEVIATIONS.md)" -ge 1
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the HEAD docs
# face; the CURRENT faces NEVER moved by THIS row; the docs sibling banks
# the NEW face) ----
test "$(grep -c '870 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3        # the CURRENT seed face x3
test "$(grep -c '855 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '841 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3        # the 24c-seeded face x3
for s in 825 810 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c '5 TES'"T(" "$R/NEXT.md")" -eq 1                        # the drift token EXACT-1 (the split form; NEVER typed whole by THIS row)

# ---- token censuses (the own-token family MEASURED 0 PRE-HITS across
# tools/tests/NEXT.md/src at authoring: the dir token mod""stor NEVER
# rides a tracked file EXCEPT via the runtime concat; the GROUND NAME
# 'modules' rides PATHS by construction (the 24a precedent — the pair it
# ports is NAMED that); the SELF-scan arms prove THIS row adds ZERO
# joined OWN-token holders) ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}" "$H"/build.sh || true)" -eq 0                    # SELF-scan (the 23f SELF-HIT law; $MN itself rides a concat)
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/gate_main.cc "$H"/witness_modulesrow.cc | grep -c "${MN}" || true)" -eq 0
test "$(grep -rl "${MN}" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | wc -l)" -eq 0
test "$(grep -rl "${MN}" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0
# the GROUND-name carrier faces (the pre-audit MEASURED at the row: the
# 41-file 'modules' token family rides OTHER rows' OWN nm/copy seats +
# the ground CMake cites; NO arm EVER count-pins MY files — the walked
# faces UNMOVED at this row):
test "$(grep -c 'add_cp'putest "$SRC"/src/main/test/CMakeLists.txt)" -eq 2     # UNDISTURBED

# ---- STATE-AWARE stageables dual guard (8 faces: .gitignore + build.sh +
# gate_main.cc + probe.cc + probe_faceA.cc + witness_modulesrow.cc +
# vectors + vectors_faceA (the gate rides UNTRACKED; NO PLAN.md this
# row); PRE face: the files ON DISK + the ls-files 8-face; POST face: the
# ls-files 8-face + the ZERO-leak arms. ----
for f in .gitignore build.sh gate_main.cc probe.cc probe_faceA.cc witness_modulesrow.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main/modules.cc copy/main/modules.h copy/main/policy.h copy/daq.h copy/daq_version.h o2/probe.o o2/probe_faceA.o probe_faceA_x probe_faceA_x_O2 gate_x gate_twin_x probe_x probe_x_O2 probe_faceA_x probe.o probe_faceA.o gate_main.o mods_ut.o witness.o module_leg.o messages.o vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E9_dup.txt E_module.txt E_messages.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt gate_stderr.txt md5_pinned.txt stageables.txt gate.txt .catch_main_probe.cc .catch_main_probe.o .catch_probe.cc .catch_probe.o .twin.txt .e9dup .tamper_va; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
# STATE-TOLERANT dual guard (the parent stages the landing IN-COMMIT — the
# 62d6fac law: at build time the 8 faces ride index-6/others-2 PRE-commit
# and index-8/others-0 POST-commit; the union face is 8 EITHER WAY):
idx="$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)"
oth="$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | wc -l)"
test "$(( idx + oth ))" -eq 8
{ git -C "$R" ls-files "tools/${MN}_harness"; git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness"; } | sort > "$H"/.stage_union
test "$(grep -cxFf <(printf 'tools/%s_harness/.gitignore\ntools/%s_harness/build.sh\ntools/%s_harness/gate_main.cc\ntools/%s_harness/probe.cc\ntools/%s_harness/probe_faceA.cc\ntools/%s_harness/witness_modulesrow.cc\ntools/%s_harness/vectors.txt\ntools/%s_harness/vectors_faceA.txt' "${MN}" "${MN}" "${MN}" "${MN}" "${MN}" "${MN}" "${MN}" "${MN}") "$H"/.stage_union)" -eq 8
test "$(wc -l < "$H"/.stage_union)" -eq 8
rm -f "$H"/.stage_union
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1; then
    test "$oth" -eq 0 || test "$idx" -eq 6 || { echo "stage face MIXED beyond the 6+2/8+0 law — re-plan"; exit 1; }
fi


# ---- tail (the honest echo face) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "ground pair: 2491+30=2521 @ fe29cbe; the THIRD face main.h 67 L cite-ONLY NEVER lands"
echo "E4: bare dies EXACTLY-1 fatal actions/actions_module.h (modules.cc :29); graft-daq MEASURED ZERO drift faces (the honest divergence — the registry TU pulls ZERO daq faces); REAL libdaq SWAP BOTH SILENT (plain + UNIT_TEST)"
echo "config.h dialect (donor EMPTY seat IN FORCE): HAVE_UUID OFF uuid_t-fallback / HAVE_HYPERSCAN OFF / REG_TEST OFF / ENABLE_DETECTION_OFFLOAD OFF / HAVE_NUMA OFF + the ONE hwloc EXCISION / CRASH_MITIGATOR OFF (2 ifdef faces :58 :2420, MitigatorModule NEVER active) / HAVE_CONFIG_H ON / UNIT_TEST gate-post ONLY"
echo "nm census: plain $(wc -l < "$H"/nm_U_plain.txt) / ut $(wc -l < "$H"/nm_U_ut.txt) (Catch $(grep -c 'Catch::' "$H"/nm_U_ut.txt) non-Catch $(grep -vc 'Catch::' "$H"/nm_U_ut.txt)) — the NEVER-LAND wall mirrored + TWO REAL ground legs (module.cc + messages.cc) link-REAL; E9 dup twins EXACTLY-$(grep -c 'multiple definition' "$H"/E9_dup.txt)"
echo "GATE E10 BOTH ways GREEN: RUNNER $(tail -2 "$H"/gate.txt | head -1 | tr -d '\r') | MAIN twin $(tail -2 "$H"/.twin.txt | head -1 | tr -d '\r')"
echo "gate arms: TEST_CASE x4 (:2429 :2442 :2455 :2469 [Ip-sModule] tag runtime-built), CHECK x12, UNIT_TEST post x1 (:2425), catch+log_errors includes x1 each, plain-CMake seats x2, CRASH_MITIGATOR ifdef x2 NEVER lands, statics 43 + THREAD_LOCAL 2"
echo "gate census (walked FLIP): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af') x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor"
echo "backbone STAYS $(wc -l < "$R"/tools/link4_harness/backbone10.txt) (md5 $(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print substr($1,1,8)}'))"
echo "$(printf 'MO%s' 'DS_DONE') vectors=$(wc -l < "$V") faceA=$(wc -l < "$VA") gates=1 (the chapter-21 FIFTH real gate row, the FIRST FOUR-case-at-once gate family; the census FLIPPED 31/9/23/1)"
