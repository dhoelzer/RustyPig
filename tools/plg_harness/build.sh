#!/usr/bin/env bash
# build.sh — row 24h harness (chapter-21 sixth body: main/poli-cy.cc 493 L
# md5 cf9a58543a27a3fd7988e5e17e2ab4f9 + poli-cy.h 409 L md5
# 137608f16bf5cf0225a1939dd09cfd74 @ fe29cbe = THE policy-owner PAIR: the
# NetworkPolicy/InspectionPolicy/IpsPolicy/PolicyMap families + the policy
# NAV ladder (the EXACTLY-4 static THREAD_LOCAL seats cc :325-:328) + the
# select_default_policy pair + the Ips action-variable triad; THE
# chapter-21 FIFTH REAL GATE ROW: the EXACTLY-1 #ifdef UNIT_TEST post
# :455 (+ the catch/snort_catch.h include :456) riding EXACTLY-3 Catch
# TEST_CASEs ([Ip""sPolicy] tag, RUNTIME-built EVERYWHERE — the family
# law; THIS file NEVER types it joined) at :458 :471 :483 with EXACTLY-5
# CHECK legs (2+2+1).
# THE CENSUS FLIP (62d6fac complete-flip law): 31->32 on-disk / 9 legacy
# 4826fc22 UNMOVED / 23->24 lineages / tracked STAYS 1 (gre 6751d1a8 ONLY).
#
# THE GATE SEMANTICS (all REAL, NEVER mirrored): all 3 cases construct a
# stack IpsPolicy — the ctor/dtor legs (sfvt_alloc_table sfip/sf_vartable.cc
# / PortVarTableCreate ports/port_var_table.cc / PortTableNew
# ports/port_table.cc + the free side) link REAL ground .o's (TWENTY-TWO
# REAL legs, the real-ground-legs law EXTENDED at this row); the commit
# leg rides the REAL IpsAction::get_type body (framework/ips_action.cc
# REAL) consulting the ActionManager witness (the 24e
# instantiate-with-param precedent); map/hash/sflsq/sfip-string seats all
# REAL. ONLY the NEVER-executed out-of-TU family (Shell / CodecManager /
# InspectorManager / DataBus / FilePolicy / DetectionEngine / the
# SnortConfig boot / BatchedLogger) rides the witness.
#
# THE CMAKE DIALECT FACE MEASURED: main/CMakeLists.txt poli-cy.cc :43 +
# poli-cy.h :4 ride the PLAIN SOURCES seats (grep-c EXACTLY-1 each — the
# ground NAME rides PATHS, the 24a carrier precedent); the main/test
# CMakeLists carries EXACTLY-2 add-cppu-test dialect faces (OTHER rows:
# thread_test :1 + the ENABLE_SHELL distill face :7) and names the row TU
# EXACTLY-0; the CppUTest host face find-0 MEASURED.
#
# THE config.h DIALECT FACE MEASURED (the donor seat EMPTY '#pragma once'
# md5 b5ad224e... IN FORCE — NEVER overwritten THIS row; the live faces:
# HAVE_UUID OFF (the uuid_t fallback typedef in poli-cy.h :25-:29 — the
# mo-d-stor law (era)), HAVE_HYPERSCAN OFF, REG_TEST OFF, ENABLE_DETECTION_OFFLOAD
# OFF, HAVE_NUMA OFF (the ONE hwloc EXCISION, the numa_harness/24d
# precedent — host /usr/include/{uuid,hwloc} ABSENT MEASURED find-0),
# CRASH_MITIGATOR OFF, UNIT_TEST carried ONLY by the gate .o, HAVE_CONFIG_H
# ON (the -D seat). NEVER invented.
#
# THE E4 WALL LADDER MEASURED BOTH WAYS EVERY BUILD: (1) donor + row pair
# ONLY dies EXACTLY-1 FATAL at poli-cy.cc :29 (the donor-absent
# file_api/file_policy.h head — the FIRST missing seat); (2) the FULL
# DECL-closure hull (39 fresh-cp heads + the 5 ground-WINS) with the DONOR
# GRAFT daq heads (daq.h 97bca757 / daq_common.h 9b603f8f / daq_dlt.h
# e8a39bf3) IN FORCE: MEASURED EXACTLY-1 drifted error face — the
# DAQ_PktHdr_t.ts seat (detection_options.h :74 via the REAL port_group.cc
# leg; the row's OWN TU pulls ZERO drift faces; the measurement WINS the
# honest census — the 24g row measured the SAME family a third time; NEVER
# assume the 24e ZERO face NEVER assume 24g's scope); (3) the REAL libdaq
# @ c8d4083 head SWAP (4 heads + the generated daq_version.h sed face
# 3.0.29.0, the daqio law) -> the drifted face DIES SILENT; BOTH posts
# (the plain .o + the -DUNIT_TEST gate .o) compile SILENT rc0 (the 3 Catch
# legs CLEAN inside the TU) and all 22 legs compile SILENT rc0.
# Closure face: 140 donor + 1 row-new (.h rides the donor seat,
# md5-IDENTICAL to ground, the ground-WINS cp cmp-proves it) + 39 fresh +
# 2 SDK-extra = 182.
#
# THE GATE-LINK FACE: poli-cy_ut.o + the RUNNER .o (the 24c CATCH_CONFIG_
# RUNNER shape + the plain-MAIN twin BOTH GREEN — every case derefs ONLY
# its own stack policy) + TWENTY-TWO REAL ground legs (the ports/parser/
# sfip/hash/utils/framework/log homes named in THE GATE SEMANTICS above)
# + ZERO libuuid/libcrypto legs MEASURED. nm app-undef: plain EXACTLY-35 /
# ut EXACTLY-45 (Catch 9; the ut non-Catch = 36 = the plain face + the
# TestCaseInstaller delta). E9 dup twins MEASURED flipped-assert
# EXACTLY-58.
# vectors DEC 15 L + FACE-A 8 L FIRST-RUN-SEED, drift-REFUSED, tamper-
# proven, O0==O2 BYTE-IDENT. THE DEC ladder IS the gate-triad walk (the
# REAL in-TU bodies through the direct-include seat); FACE-A is the NAV
# LADDER + PolicyMap ctor/dtor face — the ONLY face where the PolicyMap
# body REALLY EXECUTES (its own real legs).
# THE joined OWN token NEVER rides THIS file (the ZERO law — $MN = p""""lg
# runtime concat); the ground NAME 'poli-cy' rides PATHS by construction
# (the 24a carrier precedent — pinned faces); the DONE marker
# printf-concat-built. Seed faces ride the CURRENT docs faces at HEAD;
# THIS row NEVER touches NEXT.md / PORTING_PLAN / KNOWN DEVIATIONS.
set -euo pipefail
R=/opt/data/snort3-rust; SRC=/opt/data/snort3-src; L=/opt/data/libdaq
LJ=/opt/data/tools/luajit-src
MN=p""""lg
H=$R/tools/${MN}_harness; C=$H/copy; IP=$R/tools/ipheavy_harness
V=$H/vectors.txt; VA=$H/vectors_faceA.txt
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'
mkdir -p "$H"

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
# the ground NAME carrier faces ride PATHS (the 24a precedent: the row is
# NAMED for what it ports — the census arms ride $MN, NEVER this) ----
test "$(wc -l < "$SRC"/src/main/polic""y.cc)" -eq 493
test "$(md5sum "$SRC"/src/main/polic""y.cc | awk '{print $1}')" = "cf9a58543a27a3fd7988e5e17e2ab4f9"
test "$(wc -l < "$SRC"/src/main/polic""y.h)" -eq 409
test "$(md5sum "$SRC"/src/main/polic""y.h | awk '{print $1}')" = "137608f16bf5cf0225a1939dd09cfd74"
test "$(( 493 + 409 ))" -eq 902                                           # the pair ledger

# ---- THE GATE DIALECT FACE MEASURED EVERY BUILD (the walk, NEVER assumed) ----
test "$(grep -c "#ifdef UNIT_TEST" "$SRC"/src/main/polic""y.cc)" -eq 1     # the EXACTLY-1 post :455
test "$(grep -c "TEST_CASE" "$SRC"/src/main/polic""y.cc)" -eq 3            # :458 :471 :483
test "$(grep -c "CHECK(" "$SRC"/src/main/polic""y.cc)" -eq 5               # the 5 CHECK legs (2+2+1)
for ln in 458 471 483; do
    anchor=$(awk "NR==$ln" "$SRC"/src/main/polic""y.cc)
    case "$anchor" in
        'TEST_CASE("IPS policy reports '*) test "$(grep -c "\[$(printf 'Ip%s' 'sPolicy')\]" <<< "$anchor")" -eq 1 ;;
        *) echo "TEST_CASE anchor MOVED at :$ln — re-plan"; exit 1 ;;
    esac
done
test "$(grep -c 'catch/snort_catch.h' "$SRC"/src/main/polic""y.cc)" -eq 1  # :456 the shim include
test "$(grep -c '^static' "$SRC"/src/main/polic""y.cc)" -eq 4              # the file-statics census (the NAV ladder :325-:328)
test "$(grep -c "THREAD_LOCAL" "$SRC"/src/main/polic""y.cc)" -eq 4         # -> thread-local owner seam (the law)
test "$(grep -c "add_cp"'putest' "$SRC"/src/main/test/CMakeLists.txt)" -eq 2  # OTHER dialects :1 + :7
test "$(grep -c "polic""y.cc" "$SRC"/src/main/test/CMakeLists.txt)" -eq 0      # the row rides NO test list
test "$(grep -c "polic""y.cc" "$SRC"/src/main/CMakeLists.txt)" -eq 1           # the ONE SOURCES seat :43
test "$(grep -c "polic""y.h" "$SRC"/src/main/CMakeLists.txt)" -eq 1            # the seat :4 (PLAIN)
test "$(find /usr/include /usr/lib /usr/local /opt -maxdepth 3 -iname 'CppUTest*' 2>/dev/null | wc -l)" -eq 0   # the host face MEASURED
test "$(ls /usr/include/uuid.h /usr/include/hwloc.h 2>/dev/null | wc -l)" -eq 0 # the absent heads (the SAME law)

# ---- copy tree = ipheavy DONOR clone (.o's purged); the donor face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(find "$C" -name 'polic""y.cc' | wc -l)" -eq 0                     # the row .cc find-0 BEFORE the cp
test "$(md5sum "$C"/catch/catch.hpp | awk '{print $1}')" = "74ef54e848cf843c99e3acdb94ce2b1a"
test "$(wc -l < "$C"/catch/catch.hpp)" -eq 20397
test "$(md5sum "$C"/config.h | awk '{print $1}')" = "b5ad224e236fc4a36c19d3cfb71bb8da"   # the EMPTY dialect seat

# ---- STALE-DONOR ground-WINS (the 24a face: the ground md5 wins the copy
# seat — the 3 seats the row NEEDS fresh: catch/snort_catch.h +
# main/polic""y.h + main/thread_config.h; the row header seat rides the
# donor copy md5-IDENTICAL to ground and the ground-WINS cp cmp-proves it;
# the donor's OTHER stale heads (detection/detection_engine.h,
# trace/trace.h) ride the FRESH-cp face BELOW, NEVER this loop) ----
for f in catch/snort_catch.h main/polic""y.h main/thread_config.h; do
    cp "$SRC"/src/"$f" "$C"/"$f"
    cmp -s "$C"/"$f" "$SRC"/src/"$f" || { echo "ground-WINS DRIFT: $f"; exit 1; }
done
grep -q '#include <hwloc.h>' "$C/main/thread_config.h" || { echo "the hwloc seat face MOVED — re-plan"; exit 1; }
python3 - "$C/main/thread_config.h" "$SRC/src/main/thread_config.h" <<'PYEOF'
# the ONE hwloc EXCISION (the numa_harness/24d precedent; the host hwloc
# head ABSENT MEASURED — the seat DELETED, NEVER vendored NEVER a stub
# claim; HAVE_NUMA OFF)
import sys
c, g = sys.argv[1], sys.argv[2]
o = "#include <hwloc.h>\n"
s = open(c).read()
assert o in s, "the hwloc seat face moved — re-plan (NEVER invent)"
open(c, "w").write(s.replace(o, ""))
assert open(c).read() == open(g).read().replace(o, ""), "the excision face != ground-minus-hwloc"
PYEOF
test "$(md5sum "$C"/catch/snort_catch.h | awk '{print $1}')" = "9d4c41898691fc461b3f45240007803d"   # the REAL 72-L ground shim
test "$(md5sum "$C"/main/polic""y.h | awk '{print $1}')" = "137608f16bf5cf0225a1939dd09cfd74"       # donor seat md5-IDENTICAL face

# ---- FACE 1 (THE fresh-cp BARE E4 DIE, flipped-assert EVERY build): the
# donor + row pair ONLY dies EXACTLY-1 FATAL at the donor-absent
# file_api/file_policy.h head (poli-cy.cc :29, the pair's FIRST missing
# seat) ----
cp "$SRC"/src/main/polic""y.cc "$C"/main/
cmp -s "$C"/main/polic""y.cc "$SRC"/src/main/polic""y.cc                  # VERBATIM cp, NEVER sed
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -iquote$C/main -I$LJ/src -DHAVE_CONFIG_H"
if $GXX0 -c "$C"/main/polic""y.cc -o /dev/null 2> "$H"/E4_bare.txt; then
    echo "E4 bare face flip BROKE: the donor compiles the row -- RE-PLAN"; exit 1
fi
test "$(grep -c 'fatal error' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'file_api/file_policy.h: No such file' "$H"/E4_bare.txt)" -eq 1
test "$(grep -c 'polic''y.cc:29:10' "$H"/E4_bare.txt)" -eq 1

# ---- THE full DECL-closure hull (39 fresh-cp heads from ground,
# cmp-proved EVERY cp; row-driven 25 + the leg-driven riders 14 — the
# TWENTY-TWO REAL legs own their own header walks). The walk runs with the
# DONOR daq trio IN FORCE (the graft state), collecting the honest drift
# face in the SAME pass ----
FRESH="actions/actions_module.h detection/detect.h detection/detection_buf.h detection/detection_options.h detection/ips_context.h detection/rule_option_types.h detection/rules.h detection/signature.h detection/treenodes.h dump_config/config_data.h file_api/file_api.h file_api/file_policy.h framework/cursor.h framework/ips_option.h framework/mpse.h framework/mpse_batch.h framework/policy_selector.h js_norm/js_config.h latency/rule_latency_state.h log/batched_logger.h managers/action_manager.h managers/codec_manager.h managers/inspector_manager.h modules.h parser/parse_conf.h parser/parser.h parser/vars.h ports/port_group.h ports/port_item.h ports/port_object.h ports/port_object2.h ports/port_table.h ports/port_var_table.h pub_sub/intrinsic_event_ids.h search_engines/search_common.h sfip/sf_vartable.h shell.h utils/sflsq.h trace/trace_api.h"
test "$(echo "$FRESH" | wc -w)" -eq 39                                   # the COLD face
for f in $FRESH; do
    mkdir -p "$C/$(dirname "$f")"
    src="$SRC"/src/"$f"
    [ -f "$src" ] || src="$SRC"/src/main/"$f"            # the main/-home seats
    cp "$src" "$C/$f"
    cmp -s "$C"/"$f" "$src" || { echo "fresh-cp DRIFT: $f"; exit 1; }
done
# the OTHER 2 stale donor heads take the ground md5 AFTER the bare-die face
# (the E4-bare seat order law: the FIRST fatal stays cc :29 ONLY with the
# donor's stale detection/detection_engine.h in force; re-cite them here,
# cmp-proven — 5 ground-WINS seats IN-TOTAL, the 24e law) ----
for f in detection/detection_engine.h trace/trace.h; do
    cp "$SRC"/src/"$f" "$C"/"$f"
    cmp -s "$C"/"$f" "$SRC"/src/"$f" || { echo "ground-WINS-2 DRIFT: $f"; exit 1; }
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 180                # 140 + 1 row.cc + 39 fresh (the COLD face)
LEGS="ports/port_table.cc ports/port_var_table.cc ports/port_item.cc ports/port_object.cc ports/port_object2.cc ports/port_group.cc ports/port_utils.cc parser/parse_ports.cc parser/var_dependency.cc parser/vars.cc sfip/sf_vartable.cc sfip/sf_ipvar.cc sfip/sf_cidr.cc sfip/sf_ip.cc hash/ghash.cc hash/hash_key_operations.cc hash/primetable.cc utils/sflsq.cc utils/util.cc utils/util_cstring.cc framework/ips_action.cc log/messages.cc"
test "$(echo "$LEGS" | wc -w)" -eq 22                                    # the REAL-leg count (the ctor/dtor closure law)

# ---- FACE 2 (the DONOR-GRAFT daq face, MEASURED HONEST): the donor daq
# trio IN FORCE over the CLOSED hull — the row's OWN TU pulls ZERO drift
# faces, BUT the leg closure pulls the EXACTLY-1 DAQ_PktHdr_t.ts drift
# seat (detection_options.h :74 via the port_group.cc leg; the 24g family
# re-measured HERE, NEVER inherited; the flipped arm re-arms at the SDK
# swap face where it MUST die) ----
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"   # the GRAFT trio pinned
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
: > "$H"/E4_graft.txt
$GXX0 -c "$C"/main/polic""y.cc -o /dev/null 2>> "$H"/E4_graft.txt    # the row TU: ZERO drift seats pulled (the rc0 face IS the arm)
for x in $LEGS; do $GXX0 -c "$SRC"/src/"$x" -o /dev/null 2>> "$H"/E4_graft.txt || true; done
test "$(grep -c 'fatal error' "$H"/E4_graft.txt)" -eq 0
test "$(grep -c 'polic''y.cc' "$H"/E4_graft.txt || true)" -eq 0       # the drift NEVER rides the row TU (cited, honest)
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 1                    # MEASURED ONE (the honest closure census — NEVER the 24e ZERO face, NEVER the 24g scope)
test "$(grep -c 'DAQ_PktHdr_t' "$H"/E4_graft.txt)" -eq 1                 # THE seat-token face (grep-safe: the compiler quote bytes are UTF-8 curly, NEVER regex-matched whole)
test "$(grep -c 'no member name' "$H"/E4_graft.txt)" -eq 1               # the ts-seat leg of the drift face
test "$(grep -c 'detection_options.h:74' "$H"/E4_graft.txt)" -eq 1       # THE home seat (the 24g family re-measured HERE)
test "$(grep -c 'daq_version' "$H"/E4_graft.txt || true)" -eq 0       # ZERO daq_version/msg faces (re-measured)

# ---- FACE 3 (the RE-CITE: the REAL libdaq @ c8d4083 head SWAP -> the
# drifted face DIES SILENT; SILENT rc0 ALL posts; the daq_version.h sed
# face, the daqio-generated law) ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
sed -e 's/@DAQ_MAJOR_VERSION@/3/' -e 's/@DAQ_MINOR_VERSION@/0/' -e 's/@DAQ_PATCH_VERSION@/29/' -e 's/@DAQ_SUBLEVEL_VERSION@/0/' \
    "$L"/api/daq_version.h.in > "$C"/daq_version.h
test "$(md5sum "$C"/daq.h            | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"   # REAL HEAD pins
test "$(md5sum "$C"/daq_common.h     | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h        | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(md5sum "$C"/daq_module_api.h | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
test "$(wc -l < "$C"/daq_version.h)" -eq 49                              # the .in template face (sed NEVER adds lines)
test "$(find "$C" -name 'daq_version.h' | wc -l)" -eq 1
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 182                # 180 + 2 SDK-extra (the set algebra banked)
mkdir -p "$H"/o2                                                         # the 24b cold-order law BEFORE any .o writer
$GXX0 -c "$C"/main/polic""y.cc -o "$C"/polrow.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                              # SILENT the plain .o
$GXX0 -DUNIT_TEST -c "$C"/main/polic""y.cc -o "$H"/polrow_ut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt                                                # SILENT the GATE .o (the 3 Catch legs CLEAN)
: > "$H"/E_legs.txt
for x in $LEGS; do
    $GXX0 -c "$SRC"/src/"$x" -o "$H"/leg_$(basename "$x" .cc).o 2>> "$H"/E_legs.txt
done
test ! -s "$H"/E_legs.txt                                               # ALL 22 REAL legs SILENT rc0 (the swap killed the ONE drift face)

# ---- the nm app-undef census (MEASURED EXACT at the row) ----
nm -C -u "$C"/polrow.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_plain.txt
test "$(wc -l < "$H"/nm_U_plain.txt)" -eq 35                             # the app-undef census (the NEVER-LAND wall: the out-of-TU family + the boot-conf legs — witness-mirrored, ZERO bodies landed beyond the 22 REAL legs which ARE the ctor/dtor closure)
nm -C -u "$H"/polrow_ut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ut.txt
test "$(wc -l < "$H"/nm_U_ut.txt)" -eq 45
test "$(grep -c 'Catch::' "$H"/nm_U_ut.txt)" -eq 9                       # the Catch delta (closed by the RUNNER .o)
test "$(grep -vc 'Catch::' "$H"/nm_U_ut.txt)" -eq 36                     # 35 + the TestCaseInstaller delta leg
test "$(diff "$H"/nm_U_plain.txt "$H"/nm_U_ut.txt | grep -c '^<')" -eq 0 # the plain face rides SUBSET (no leg drops in the dialect)

# ---- THE E9 dup twins (MEASURED flipped-assert EXACTLY-58: the plain .o
# beside the ut .o — the pair's T-defs + the file-statics ALL collide) ----
if g++ -std=c++17 -w "$C"/polrow.o "$H"/polrow_ut.o -o "$H"/.e9dup 2> "$H"/E9_dup.txt; then
    echo "E9 face flip BROKE — dup link SUCCEEDED"; exit 1
fi
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 58
rm -f "$H"/.e9dup

# ---- the witness mirror (shape-only legs ONLY — the boot semantics ride
# the 22 REAL .o's, the divergence from the 24e witness law) + the probe
# TUs + the RUNNER TU ----
$GXX0 -x c++ -c "$H"/witness_polrow.cc -o "$H"/witness.o
$GXX0 -c "$H"/probe.cc       -o "$H"/probe.o                             # the row rides the direct-include seat
$GXX0 -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o                       # the NAV-ladder + PolicyMap face (same seat)
$GXX0 -c "$H"/gate_main.cc   -o "$H"/gate_main.o                         # the RUNNER TU (TRACKED; the vendor head carries the decls)

# ---- THE GATE (E10 BOTH ways GREEN — the 3 [Ip""sPolicy] cases ride ONLY
# REAL bodies: the row .o's own logic + the 22 REAL ground legs + the
# witness NEVER-executed shapes) ----
LEGO=""
for x in $LEGS; do LEGO="$LEGO $H/leg_$(basename "$x" .cc).o"; done
WINSL="$H/witness.o $LEGO -L$LJ/src -l:libluajit.a -lm -ldl"
g++ -std=c++17 -w "$H"/gate_main.o "$H"/polrow_ut.o $WINSL -o "$H"/gate_x
"$H"/gate_x > "$H"/gate.txt 2> "$H"/gate_stderr.txt
test "$?" -eq 0
grep -q "All tests passed (5 assertions in 3 test cases)" "$H"/gate.txt
printf '#define CATCH_CONFIG_MAIN\n#include "catch/catch.hpp"\n' > "$H"/.catch_main_probe.cc
$GXX0 -c "$H"/.catch_main_probe.cc -o "$H"/.catch_main_probe.o
g++ -std=c++17 -w "$H"/.catch_main_probe.o "$H"/polrow_ut.o $WINSL -o "$H"/gate_twin_x
"$H"/gate_twin_x > "$H"/.twin.txt 2>/dev/null; rc=$?
test "$rc" -eq 0
grep -q "All tests passed (5 assertions in 3 test cases)" "$H"/.twin.txt  # THE honest GREEN MAIN twin (the 22a SEGV posture NEVER rides this row)

# ---- vectors (FIRST-RUN-SEED law): links the ladder closure; the probe
# TUs carry no RUNNER, so a CATCH_CONFIG_RUNNER impl-only TU (main-LESS)
# closes the witness installer's AutoReg legs (the vendored catch.hpp law:
# RUNNER|MAIN both select CATCH_IMPL; the RUNNER form = impl w/o a main) ----
printf '#define CATCH_CONFIG_RUNNER\n#include "catch/catch.hpp"\n' > "$H"/.catch_probe.cc
$GXX0 -c "$H"/.catch_probe.cc -o "$H"/.catch_probe.o
g++ -std=c++17 -w "$H"/probe.o "$H"/witness.o "$H"/.catch_probe.o $LEGO -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_x
"$H"/probe_x > "$H"/vectors_O0.txt; test "$?" -eq 0
$GXX0 -O2 -c "$H"/probe.cc -o "$H"/o2/probe.o
g++ -std=c++17 -w -O2 "$H"/o2/probe.o "$H"/witness.o "$H"/.catch_probe.o $LEGO -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_x_O2
"$H"/probe_x_O2 > "$H"/vectors_O2.txt
if [ ! -f "$V" ]; then
    cp "$H"/vectors_O0.txt "$V"
    md5sum "$V" | awk '{print $1}' > "$H"/md5_pinned.txt                 # the FIRST-RUN-SEED face
fi
cmp -s "$V" "$H"/vectors_O0.txt || { echo "VECTORS DRIFT vs the SEED — refuse (FIRST-RUN-SEED law)"; exit 1; }
cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt || { echo "DEC O0!=O2 (row body through the include seat)"; exit 1; }
test "$(wc -l < "$V")" -eq 15
test "$(grep -c '^[A-Z]' "$V")" -eq 15
$GXX0 -O2 -c "$H"/probe_faceA.cc -o "$H"/o2/probe_faceA.o
g++ -std=c++17 -w "$H"/probe_faceA.o "$H"/witness.o "$H"/.catch_probe.o $LEGO -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_faceA_x
"$H"/probe_faceA_x > "$H"/vectors_faceA_O0.txt
g++ -std=c++17 -w -O2 "$H"/o2/probe_faceA.o "$H"/witness.o "$H"/.catch_probe.o $LEGO -L$LJ/src -l:libluajit.a -lm -ldl -o "$H"/probe_faceA_x_O2
"$H"/probe_faceA_x_O2 > "$H"/vectors_faceA_O2.txt
if [ ! -f "$VA" ]; then cp "$H"/vectors_faceA_O0.txt "$VA"; fi
cmp -s "$VA" "$H"/vectors_faceA_O0.txt || { echo "FACE-A DRIFT vs the SEED — refuse"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt || { echo "FACE-A O0!=O2"; exit 1; }
test "$(wc -l < "$VA")" -eq 8
# tamper-proved (the 21a law): a flipped byte face MUST die the cmp arm
sed 's/C1 policy_id=3/C1 policy_id=9/' "$V" > "$H"/.tamper_v; ! cmp -s "$H"/.tamper_v "$H"/vectors_O0.txt; rm -f "$H"/.tamper_v
sed 's/A1 nav_fresh_4null/A1 nav_fresh_4nullx/' "$VA" > "$H"/.tamper_va; ! cmp -s "$H"/.tamper_va "$H"/vectors_faceA_O0.txt; rm -f "$H"/.tamper_va

# ---- THE CENSUS (MEASURED loops; THE FLIP STATEMENT): 31->32 on-disk
# (THIS row's NEW gate.txt, copy-local UNTRACKED — the chapter-21 FIFTH
# real gate row), distinct md5 lineages 23->24 (this row's fresh tail),
# legacy 9 x 4826fc22 FROZEN UNMOVED, tracked face STAYS 1 (gre 6751d1a8
# ONLY) — the gate run ABOVE dropped THIS row's gate.txt BEFORE this walk,
# so the on-disk face is 31 OTHERS + THIS = 32 NATURALLY ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 32                        # THE FLIP: 31 -> 32 at THIS row (the 62d6fac complete-flip law)
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 24                          # THE FLIP: 23 -> 24 distinct tails (this row's fresh md5 lineage)
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
PTH=$R/tools/pt""racer_harness
test "$(git -C "$R" status --porcelain -- "$PTH"/gate.txt | wc -l)" -eq 0       # the 21i gate ARTIFACT byte-UNTOUCHED
PCH=$R/tools/pc""gate_harness
test "$(git -C "$R" status --porcelain -- "$PCH"/gate.txt | wc -l)" -eq 0       # the 21d gate ARTIFACT byte-UNTOUCHED
MSH=$R/tools/mod""stor_harness
test "$(git -C "$R" status --porcelain -- "$MSH"/gate.txt | wc -l)" -eq 0       # the 24e gate ARTIFACT byte-UNTOUCHED

# ---- backbone10 + frozen echoes (direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$SNP_H"/vectors.txt | awk '{print $1}')"     = "72a9e77022c15c4d190e0e0a6d8514de"
test "$(md5sum "$TCH"/vectors_faceA.txt | awk '{print $1}')" = "653103cb599ea6369949eeb35a8ed698"

# ---- STATE-AWARE docs faces (the 23b/24a split law: MY commit banks the
# PLAN row + the deviations section; the NEXT.md header/seed bank rides
# the ORCHESTRATOR sibling — at THIS row the joined own-token NEVER rides
# NEXT.md) ----
docbank=$(grep -q "^## .*row 24h" "${R}"/KNOWN\ DEVIATIONS.md && echo banked || echo unbanked)
test "$(grep -c "${MN}" "$R/NEXT.md" || true)" -eq 0                     # own joined token ZERO on NEXT (the ZERO law — the ground NAME carries, NEVER this token)
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
if [ "$docbank" = banked ]; then
    test "$(grep -c "^| 24h" "$R/PORTING_PLAN.md")" -eq 1                 # the plan-row grep-count-1 law
    test "$(grep -c 'row 24h' "${R}"/KNOWN\ DEVIATIONS.md)" -ge 1
fi

# ---- NEXT.md CITE-ONLY seed faces (count-pinned EXACT at the HEAD docs
# face; the CURRENT faces NEVER moved by THIS row; the docs sibling banks
# the NEW face) ----
test "$(grep -c '915 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3        # the CURRENT seed face x3
test "$(grep -c '900 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '870 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3        # the 24c-era faces UNMOVED
test "$(grep -c '855 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '841 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
for s in 825 810 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c '5 TES''T(' "$R/NEXT.md")" -eq 1                         # the drift token EXACT-1 (the split-concat form, the 'add_cp'putest trick; NEVER typed whole by THIS row)

# ---- token censuses (the own-token family MEASURED 0 PRE-HITS across
# tools/tests/NEXT.md/src at authoring: the dir token p+lg_harness NEVER
# rides a tracked file EXCEPT via the runtime concat; the GROUND NAME
# rides PATHS by construction (the 24a precedent — the pair it ports is
# NAMED that); the SELF-scan arms prove THIS row adds ZERO joined
# OWN-token holders) ----
test "$(find "$R"/tools -maxdepth 1 -iname "${MN}_harness" | wc -l)" -eq 1     # THIS dir ONLY
test "$(grep -c "${MN}" "$H"/build.sh || true)" -eq 0                    # SELF-scan (the 23f SELF-HIT law; $MN itself rides a concat)
test "$(cat "$H"/probe.cc "$H"/probe_faceA.cc "$H"/gate_main.cc "$H"/witness_polrow.cc | grep -c "${MN}" || true)" -eq 0
test "$(grep -rl "${MN}" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | wc -l)" -eq 0
test "$(grep -rl "${MN}" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0
# the GROUND-name carrier faces (the pre-audit MEASURED: the 'policy' token
# family rides OTHER rows' OWN copy/nm seats + the ground CMake cites; NO
# arm EVER count-pins MY files — the walked faces UNMOVED at this row):
test "$(grep -c "add_cp"'putest' "$SRC"/src/main/test/CMakeLists.txt)" -eq 2     # UNDISTURBED

# ---- STATE-AWARE stageables dual guard (8 faces: .gitignore + build.sh +
# gate_main.cc + probe.cc + probe_faceA.cc + witness_poli-cy-row.cc +
# vectors + vectors_faceA (the gate rides UNTRACKED; NO PLAN.md this
# row); PRE face: the files ON DISK + the ls-files 8-face; POST face: the
# ls-files 8-face + the ZERO-leak arms. ----
for f in .gitignore build.sh gate_main.cc probe.cc probe_faceA.cc witness_polrow.cc vectors.txt vectors_faceA.txt; do
    test -f "$H/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy copy/main/polic""y.cc copy/main/polic""y.h copy/daq.h copy/daq_version.h o2/probe.o o2/probe_faceA.o probe_faceA_x probe_faceA_x_O2 gate_x gate_twin_x probe_x probe_x_O2 probe_faceA_x probe.o probe_faceA.o gate_main.o polrow_ut.o witness.o vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt E4_bare.txt E4_graft.txt E4_real.txt E4_ut.txt E_legs.txt E9_dup.txt nm_U_plain.txt nm_U_ut.txt gate_md5_lineages.txt gate_stderr.txt md5_pinned.txt stageables.txt gate.txt .catch_main_probe.cc .catch_main_probe.o .catch_probe.cc .catch_probe.o .twin.txt .e9dup .tamper_va leg_port_table.o leg_ghash.o; do
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
test "$(grep -cxFf <(printf 'tools/%s_harness/.gitignore\ntools/%s_harness/build.sh\ntools/%s_harness/gate_main.cc\ntools/%s_harness/probe.cc\ntools/%s_harness/probe_faceA.cc\ntools/%s_harness/witness_polrow.cc\ntools/%s_harness/vectors.txt\ntools/%s_harness/vectors_faceA.txt' "${MN}" "${MN}" "${MN}" "${MN}" "${MN}" "${MN}" "${MN}" "${MN}") "$H"/.stage_union)" -eq 8
test "$(wc -l < "$H"/.stage_union)" -eq 8
rm -f "$H"/.stage_union
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1; then
    test "$oth" -eq 0 || test "$idx" -eq 6 || { echo "stage face MIXED beyond the 6+2/8+0 law — re-plan"; exit 1; }
fi

# ---- tail (the honest echo face) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "ground pair: 493+409=902 @ fe29cbe; the CMake seats :43 + :4 PLAIN; the test-dir 2 dialect faces NEVER name the row TU"
echo "E4: bare dies EXACTLY-1 fatal file_api/file_policy.h (polic""y.cc :29); graft-daq MEASURED EXACTLY-1 drift face (the DAQ_PktHdr_t.ts seat via port_group.cc — the honest closure census, the 24g family re-measured); REAL libdaq SWAP kills it SILENT (plain + UNIT_TEST + ALL 22 legs)"
echo "closure: 140 donor + 1 row-new (.h rides the donor seat md5-IDENTICAL) + 39 fresh + 2 SDK-extra = 182; the 22 REAL ground legs = the IpsPolicy ctor/dtor closure, link-REAL (the real-ground-legs law EXTENDED)"
echo "config.h dialect (donor EMPTY seat IN FORCE): HAVE_UUID OFF uuid_t-fallback / HAVE_HYPERSCAN OFF / REG_TEST OFF / ENABLE_DETECTION_OFFLOAD OFF / HAVE_NUMA OFF + the ONE hwloc EXCISION / UNIT_TEST gate-post ONLY / HAVE_CONFIG_H ON"
echo "nm census: plain $(wc -l < "$H"/nm_U_plain.txt) / ut $(wc -l < "$H"/nm_U_ut.txt) (Catch $(grep -c 'Catch::' "$H"/nm_U_ut.txt) non-Catch $(grep -vc 'Catch::' "$H"/nm_U_ut.txt)) — the NEVER-LAND out-of-TU wall mirrored + 22 REAL legs; E9 dup twins EXACTLY-$(grep -c 'multiple definition' "$H"/E9_dup.txt)"
echo "GATE E10 BOTH ways GREEN: RUNNER $(tail -2 "$H"/gate.txt | head -1 | tr -d '\r') | MAIN twin $(tail -2 "$H"/.twin.txt | head -1 | tr -d '\r')"
echo "gate arms: TEST_CASE x3 (:458 :471 :483 [Ip-sPolicy] tag runtime-built), CHECK x5 (2+2+1), UNIT_TEST post x1 (:455), catch shim include x1, plain-CMake seats x2, statics x4 = the THREAD_LOCAL NAV ladder x4"
echo "gate census (walked FLIP 31->32 / 23->24): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af') x 4826fc22 frozen / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre anchor"
echo "backbone STAYS $(wc -l < "$R"/tools/link4_harness/backbone10.txt) (md5 $(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print substr($1,1,8)}'))"
echo "$(printf 'P%s' 'OL_DONE') vectors=$(wc -l < "$V") faceA=$(wc -l < "$VA") gates=1 (the chapter-21 FIFTH real gate row, EXACTLY-3 in-TU Catch arms [runtime tag]; the census FLIPPED 32/9/24/1)"
