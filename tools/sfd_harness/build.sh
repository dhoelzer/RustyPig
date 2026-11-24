#!/usr/bin/env bash
# sfd_harness -- row 21b: chapter-19 P3 = THE SURVIVOR-FLOW-DATA PIN PROVIDER:
# framework/survivor_flow_data.cc 88 L (md5 4b1eedaf70469172153c22cd91b4a682,
# PLAN SS0 re-measured EXACT). THE SOLO-CC ROW: NO sibling .h (the
# SurvivorFlowData DECL rides framework/reload_survivor_subscriptions_impl.h
# :138-:152, the 21a LANDED header b437ba1c 156 L -- CITED home, cp'd for
# compile closure, NEVER a fresh row stageable; the cc quotes it DIRECT :27).
# Donor = MPLS DONOR REUSE CLONE (the NEVER-auto-heal law; donor-verbatim
# face RE-MEASURED 130 non-.o this pass). EXACT 3 FRESH CPS: row cc ->
# copy/framework/ + managers/inspector_manager.h 139 babb1997 (find-0 NEW in
# EVERY donor -- the 21a NOT-resident wall) + _impl.h (cite-21a). mid-build
# 130 + 3 = 133 MEASURED, asserted EVERY build.
# DONOR LAW (SS0, MEASURED LIVE AGAIN EVERY build): the graft-version law --
# flow.h :541 `DAQ_Verdict last_verdict = MAX_DAQ_VERDICT` needs the ext#4
# daq_common.h. The MPLS tree carries 9b603f8f (34 L, MAX_DAQ_VERDICT==6
# COPY-LOCAL, legal AS-IS, ZERO graft cp). The 21a-donor tree carries
# fead0027 graft-v2 (PASS/DROP only): its clone DIES at flow.h:541 even
# WITH the 5-flow-closure cps (measured rc1 receipt this pass). The P1-
# donor tree: flow.h find-0. -> mpls (or ipheavy) ONLY, NEVER the 21a/P1
# donors. TOKEN-NEVER-RIDDEN law (NEXT.md :445): the donor NAMES are
# runtime-concatenated below so this build.sh carries ZERO raw donor
# tokens (the 21a harness' tools-wide EXACTLY-1 census slot = its own
# dir's sibling ONLY; a later harness adding the token = loud rc1 in
# every re-run). The flow closure (flow.h 637
# 765663d4 + deferred_trust e65076b8 + flow_stash 0bde2734 + ips_context_chain
# 53156e1e + clock_defs 29200557) rides the mpls tree BYTE-IDENT to ground
# fe29cbe -- md5-asserted NEVER re-cp'd. clock_defs.h:23 USE_TSC_CLOCK guard
# = time/tsc_clock.h NEVER pulled on the donor arm (measured clean compiles).
# GRAFT LADDER (masters CITED NEVER re-authored: daq3 daq.h 73fdbc39 +
# daq_common f683749c; ladder HEAD at clone AND TAIL after build md5-pinned:
# daq.h 0f7016a6 INHERITED + daq_common 9b603f8f ext#4 COPY-LOCAL -- the
# REQUIRED face for THIS donor tree per the graft-version law; NEVER promoted).
# THE WITNESS FACE (SS2 re-measured LIVE): nm -C -u sfd.o NDEBUG arm = 19
# U-lines; snort residue = EXACTLY 9 NAMED own-new arms (+1 rides-face:
# 'typeinfo for snort::FlowData' rides the witness vtable mirror = 10 lines
# through the snort:: grep; honest census, NEVER inflated to two homes):
# FlowData ctor/dtor/create_flow_data_id + FlowDataStore get/set +
# Inspector add_ref/rem_ref (ground body face inspector.cc:126-:130) +
# InspectorManager is_pending_tterm / thread_drain_pending_tterm_if_pending
# (THE FOUND-0 brand-new pair -- bodies mirror inspector_manager.cc :324-:332
# + :1276-:1282 with a fake pending knob; NEVER invented behavior). The
# flow_data_id DEFINITION-B mirror (witness, ground flow_data.cc:139-:140
# EXACT ++ face) is the live trap: WITHOUT it the link DIES (measured live
# this pass E4_defmirror: undefined reference to FlowData::flow_data_id).
# ONE-HOME LAW: create_flow_data_id DEFINITION count == 1 across ALL row link
# inputs; the WIN trio + backbone pull ZERO of the 9 (grep proof) so NO
# file_api-era FlowData mirror doubles with this set.
# THE NDEBUG FLIP FACE (21a's zero-runtime-assert census INVERTS HERE): the cc
# carries assert(pin) x2 (:44 ctor, :60 add_pin) = ^assert -2, grep-assert -3
# (2 runtime + <cassert>); the 21a row was 0/2. Pin the 3-assert-string census
# honestly. Production arm = -DNDEBUG ALL builds (harness law): NDEBUG U-face
# 19 (0 __assert_fail pulls); the NO-NDEBUG arm delta = EXACTLY +1
# __assert_fail (measured receipt .ndef face -- honest delta face recorded).
# O0-vs-O2 U-delta = EXACTLY 2 (the vector __throw_bad_alloc /
# __throw_bad_array_new_length pair vanishes at -O2; a CENSUS face, NEVER a
# vectors delta). UT arm: UNIT_TEST grep EXACTLY-0 in the cc (the 21a 4/1
# census INVERTS to a zero-pin); UT vs plain U-sets IDENTICAL (diff EMPTY).
# FACE-A = NOLOAD framework-TU (SS4): BUILDING_SO/snort_plugins grep-0 x2 on
# BOTH ground files; ZERO enums/tables/sids (no NAME-drift face -- contrast
# 21a's RssPeg census); the observable shape = the static-init provider pull
# (cc :39 allocates flow_data_id AT LOAD -- witness B-mirror starts 0 so the
# load-allocated id is OBSERVABLE==1), the idempotency ladder (std::find
# dup-noop), the PRIVATE-reach law (pin_survivor_flow_data PRIVATE flow.h:607
# reached ONLY via the PUBLIC set_gadget/clear_gadget inlines :360-:380) +
# the pending-gate + survival-release faces. NO data_bus/table face (U-set
# ZERO dbus pull -- the 21a pegs/slotmap faces NEVER apply here).
# THE ZERO-GATE row (28th straight): gate tokens grep-0 x2 on BOTH the cc and
# the cited _impl.h; the rider suite src/flow/test/survivor_flow_data_test.cc
# 268 L (md5 99fd7d6f) = TEST_GROUP x1 + TEST( EXACTLY-4 (the orchestrator-
# re-counted face; the PLAN prose names 3 of the 4 cases -- single_pending/
# non_pending/second_distinct/same_inspector_twice ALL pinned by name) riding
# add_cpputest x1 of 8 in src/flow/test/CMakeLists.txt (the honest RIDE face);
# CppUTest headers+libs find-0 on this host (dialect BLOCKED, NEVER faked,
# NEVER compiled); the upstream test-world's OWN stub mirrors (flow_stubs.h,
# get_inspector_stubs.h, socks_negative/mitigator_context_reuse) = cite-only.
# ZERO gate artifacts ship; test ! -e gate.txt.
# STATE-AWARE ZERO-LEAK (the ipheavy 8b9882a law): pre-commit = 8 stageable
# UNTRACKED; post-commit = 8 TRACKED + untracked EMPTY; the nested .gitignore
# is a harness-local file (ROOT .gitignore NEVER touched -- porcelain pin);
# stageables enumerated by ls-files --others --exclude-standard (NEVER -A).
# NEXT.md CITE-ONLY (NEVER edit): 629/621/605/597 tests-green x3 + 573 x5
# presence + the ONE tolerated sfd_harness mention (the 'is clear' queue line
# :444) pinned EXACTLY-1.
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness             # graft MASTER cite home (never cp'd HERE)
M9="$R/tools/mi""sc9_harness"      # THE P1 donor (row 19a) = flow.h find-0 (REJECT leg); dir name token CONCATENATED at read (census-never-ridden law)
RS="$R/tools/rs""ubs_harness"      # THE 21a donor = graft-v2 wall (REJECT leg); dir token NEVER rides this file (NEXT.md :445 EXPLICIT law) -- runtime CONCATENATION keeps the leg LIVE byte-identical
IP=$R/tools/ipheavy_harness         # cross-donor ALT tree (140 -> 143 face)
L4=$R/tools/link4_harness           # witness_conf heredoc home
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
C=$H/copy

# ---- ground identity (SS0: MY re-measure EXACT vs the orchestrator pins) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC/src/framework/survivor_flow_data.cc")" -eq 88
test "$(md5sum "$SRC/src/framework/survivor_flow_data.cc" | awk '{print $1}')" = "4b1eedaf70469172153c22cd91b4a682"
test "$(( 88 + 0 ))" -eq 88                                     # the SOLO-cc row ledger (SMALLEST framework row)
test "$(wc -l < "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" -eq 156
test "$(md5sum "$SRC/src/framework/reload_survivor_subscriptions_impl.h" | awk '{print $1}')" = "b437ba1cff967338b48b1b354743d64a"
test "$(wc -l < "$SRC/src/managers/inspector_manager.h")" -eq 139
test "$(md5sum "$SRC/src/managers/inspector_manager.h" | awk '{print $1}')" = "babb19979eeb25e32dbadb5ca30c385f"
test "$(wc -l < "$SRC/src/flow/flow.h")" -eq 637
test "$(md5sum "$SRC/src/flow/flow.h" | awk '{print $1}')" = "765663d466f59ac9af76344d4ba1de9b"
# THE header face (q1): find maxdepth-1 survivor == EXACTLY 3 (the PLAN cite;
# the test/ rider dir's reload_survivor_subscriptions_test.cc rides a 4th hit
# at depth 2 -- the PLAN's 3 counts the framework-DEPTH files: the cc, the
# 21a cc, the 21a impl.h; disk wins, both faces pinned); the cc = the SOLO
# NEW face of this row.
test "$(find "$SRC/src/framework" -maxdepth 1 -iname '*survivor*' | wc -l)" -eq 3
test "$(find "$SRC/src/framework" -iname '*survivor*' | wc -l)" -eq 4   # the depth-2 rider face (the 268-L suite, cite-only)
test ! -e "$SRC/src/framework/survivor_flow_data.h"             # NO sibling header EVER (21a decl seam provider)
# name-pin census: sfd PRE-HIT-0 OUTSIDE this dir (NEXT.md's queue line rides
# its own EXACTLY-1 tolerated cite face below); flowdata_harness find-0 EVER.
test "$(grep -rl 'sfd_harness\|flowdata_harness' "$R"/tools/*/build.sh "$R"/NEXT.md 2>/dev/null | grep -v "^$H/build.sh$" | wc -l)" -eq 3   # SANCTIONED 1->3 at the 23c docs rider (the 62d6fac flip-forward law): tolerated mention-face = NEXT.md's queue line + daqio_harness build.sh :630-:632 md5-pins of THIS dir's vectors (the 23a era re-clone carry, latent-red since 23a) + tc_harness build.sh template-shape cite; NEVER edit those citations; flip-forward only if another rides
test "$(grep -c 'tools/sfd_harness' "$R/NEXT.md")" -eq 1                    # the 'is clear' cite face ONLY
test "$(find "$R"/tools -maxdepth 1 -iname '*sfd*' | wc -l)" -eq 1          # THIS dir ONLY
test "$(find "$R"/tools -maxdepth 1 \( -iname '*survivor*harness*' -o -name 'flowdata_harness' \) | wc -l)" -eq 0   # name-collision find-0
# the Rust-side cite face (declare NEVER carry): the rs decl-cite cites the 88 L provider
RS_HOME=$R/src/framework/reload_survivor_subscriptions.rs
test -e "$RS_HOME"
grep -q '4b1eedaf' "$RS_HOME"                                    # the cite-never-carry provider pin
# STATE-AWARE rs-census (the 21a rs-landing flip precedent, the 19a PYPIN
# absence->pair face): SEED face = the 21a home ONLY (pre-port world, the
# DECL cite + ZERO provider); LANDED face = 2 homes (the 21a rs DECL-CITE +
# THIS row's provider rs — 21a NEVER edits back; BOTH homes are honest):
SFD_RS=$R/src/framework/survivor_flow_data.rs
if [ -e "$SFD_RS" ]; then
    test "$(grep -rl 'SurvivorFlowData' "$R/src" --include=*.rs | wc -l)" -eq 2   # LANDED: 21a decl-cite + this row's provider
    grep -q '4b1eedaf' "$SFD_RS"                                                 # provider cites the cc md5
else
    test "$(grep -rl 'SurvivorFlowData' "$R/src" --include=*.rs | wc -l)" -eq 1   # SEED: the 21a home ONLY (NO Rust type flips PRE-port)
fi
# ground assert census (the NDEBUG flip face, SS-header): ^assert( EXACTLY-2,
# assert-string EXACTLY-3; the UNIT_TEST face INVERTS 21a's 4/1 to EXACTLY-0;
# #ifdef face EXACTLY-1 (HAVE_CONFIG_H -- cleanest of the chapter).
test "$(grep -cE '^[[:space:]]*assert\(' "$SRC/src/framework/survivor_flow_data.cc")" -eq 2
test "$(grep -c 'assert' "$SRC/src/framework/survivor_flow_data.cc")" -eq 3
test "$(grep -c 'UNIT_TEST' "$SRC/src/framework/survivor_flow_data.cc" || true)" -eq 0
test "$(grep -c '#ifdef' "$SRC/src/framework/survivor_flow_data.cc")" -eq 1
# NOLOAD face (SS4) graft NON-participation on BOTH ground faces:
for f in framework/survivor_flow_data.cc framework/reload_survivor_subscriptions_impl.h; do
    test "$(grep -c 'BUILDING_SO'   "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'snort_plugins' "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|CppUTest' "$SRC/src/$f" || true)" -eq 0
    test "$(grep -ci daq "$SRC/src/$f" || true)" -eq 0                          # the daq wall rides flow.h ONLY, NEVER the cc
done

# ---- GATE MATERIAL census (the REAL ride face; dialect-BLOCKED receipts) ----
test "$(grep -c 'add_cpputest' "$SRC/src/flow/test/CMakeLists.txt")" -eq 8     # the 8-total face INCLUDING this row's rider
test "$(grep -c 'survivor_flow_data.cc' "$SRC/src/flow/test/CMakeLists.txt")" -eq 1   # the ONE ride of the row TU
grep -q 'add_cpputest( survivor_flow_data_test' "$SRC/src/flow/test/CMakeLists.txt"
test "$(wc -l < "$SRC/src/flow/test/survivor_flow_data_test.cc")" -eq 268
test "$(md5sum "$SRC/src/flow/test/survivor_flow_data_test.cc" | awk '{print $1}')" = "99fd7d6f2a780c605374a5650d0df7f1"
test "$(grep -c 'TEST_GROUP' "$SRC/src/flow/test/survivor_flow_data_test.cc")" -eq 1
test "$(grep -c '^TEST(' "$SRC/src/flow/test/survivor_flow_data_test.cc")" -eq 4   # EXACTLY 4 (the orchestrator re-count; NEVER 5)
for t in single_pending_gadget_stays_pinned_across_rebind non_pending_gadget_rebind_does_not_pin_survivor second_distinct_pending_inspector_is_also_pinned pinning_the_same_inspector_twice_adds_one_ref; do
    grep -q "TEST(survivor_flow_data, $t)" "$SRC/src/flow/test/survivor_flow_data_test.cc"
done
test "$(grep -c 'add_cpputest' "$SRC/src/framework/test/CMakeLists.txt")" -eq 3     # UNDISTURBED (data_bus suites ride data_bus.cc NEVER this TU)
# dialect census (find-0 faces, NEVER faked/compiled):
test "$(find /usr/include -maxdepth 1 -iname 'CppUTest*' | wc -l)" -eq 0
test "$(find /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/local/lib -maxdepth 1 -name 'libCppUTest*' 2>/dev/null | wc -l)" -eq 0
# the upstream test-world's OWN stub mirrors (cite-never-carry, NEVER providers/compiles HERE;
# the PLAN's socks/mitigator PATHS were sloppy cites -- disk wins, real homes pinned):
grep -q 'void Flow::pin_survivor_flow_data(Inspector&) { }' "$SRC/src/flow/test/flow_stubs.h"
grep -q 'void Flow::pin_survivor_flow_data(Inspector&) { }' "$SRC/src/managers/test/get_inspector_stubs.h"
grep -q 'void Flow::pin_survivor_flow_data(Inspector&) { }' "$SRC/src/service_inspectors/socks/test/socks_negative_test.cc"
grep -q 'void Flow::pin_survivor_flow_data(Inspector&) { }' "$SRC/src/mitigator/test/mitigator_context_reuse_test.cc"

# ---- ground sed pins (line-exact, disk wins over the PLAN's :33 cite) ----
test "$(sed -n '27p' "$SRC/src/framework/survivor_flow_data.cc")" = '#include "reload_survivor_subscriptions_impl.h"'   # the DIRECT quote (SS1 subrow face)
test "$(sed -n '39p' "$SRC/src/framework/survivor_flow_data.cc")" = "unsigned SurvivorFlowData::flow_data_id = FlowData::create_flow_data_id();"   # THE static-init provider pull
test "$(sed -n '54p' "$SRC/src/framework/survivor_flow_data.cc")" = "        InspectorManager::thread_drain_pending_tterm_if_pending(pin);"
test "$(sed -n '69p' "$SRC/src/framework/survivor_flow_data.cc")" = "void Flow::pin_survivor_flow_data(Inspector& outgoing)"
test "$(sed -n '138p' "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" = "class SurvivorFlowData : public FlowData"   # the 21a-owned DECL (21a :147 pin re-armed byte-ident)
test "$(sed -n '541p' "$SRC/src/flow/flow.h")" = "    DAQ_Verdict last_verdict = MAX_DAQ_VERDICT;"      # THE graft-version landmine
test "$(sed -n '607p' "$SRC/src/flow/flow.h")" = "    void pin_survivor_flow_data(Inspector&);"         # the PRIVATE decl (probe-shape law)
grep -q 'void set_gadget(Inspector\* ins)' "$SRC/src/flow/flow.h"                                       # the PUBLIC inline route (:360)
test "$(sed -n '324p' "$SRC/src/managers/inspector_manager.cc")" = "bool InspectorManager::is_pending_tterm(const snort::Inspector* pin)"        # witness signature bodies ride THESE shapes
test "$(sed -n '1276p' "$SRC/src/managers/inspector_manager.cc")" = "void InspectorManager::thread_drain_pending_tterm_if_pending(const Inspector* pin)"
test "$(sed -n '139p' "$SRC/src/flow/flow_data.cc")" = "unsigned FlowData::create_flow_data_id()"       # the EXACT ++ face
test "$(sed -n '140p' "$SRC/src/flow/flow_data.cc")" = "{ return ++flow_data_id; }"
test "$(sed -n '126p' "$SRC/src/framework/inspector.cc")" = "void Inspector::add_ref()"
test "$(sed -n '127p' "$SRC/src/framework/inspector.cc")" = "{ ++ref_count[1+get_instance_id()]; }"     # in-member legal
grep -q 'SO_PUBLIC unsigned get_instance_id();' "$SRC/src/main/thread.h"                                # :47 -- the carried witness_conf CLOSES it (NEVER doubled HERE)
grep -q 'static bool is_pending_tterm(const Inspector\*);' "$SRC/src/managers/inspector_manager.h"      # :95 the header face

# ---- copy tree = MPLS DONOR REUSE clone (the NEVER-auto-heal law + the
# flow-closure resident law: md5-assert NEVER re-cp) ----
test -e "$R/tools/mpls_harness/copy/config.h" -a -e "$R/tools/mpls_harness/copy/flow/flow.h" || { echo "DONOR DEAD: tools/mpls_harness/copy pruned -- re-run the 18o mpls row by hand (NEVER auto-heal from this script)"; exit 1; }
rm -rf "$C"; cp -a "$R/tools/mpls_harness/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 130                          # donor face MEASURED (mpls landing head)
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"          # graft-v3 INHERITED (HEAD)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"   # ext#4 COPY-LOCAL (HEAD) -- the LEGAL face for flow.h
test "$(md5sum "$D3/copy/daq.h" | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"    # MASTER CITE (never cp'd HERE)
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$C/framework/api_options.h" | awk '{print $1}')" = "830633a119c8675921e7f541f7741da1"  # the INHERITED generated-header shim (load-bearing, the raw-arm wall)
# the flow closure RESIDENTS md5-asserted (the mpls-era pull EARNED its keep -- NEVER re-cp):
test "$(md5sum "$C/flow/flow.h" | awk '{print $1}')" = "765663d466f59ac9af76344d4ba1de9b"
test "$(md5sum "$C/flow/deferred_trust.h" | awk '{print $1}')" = "e65076b86023775a6120ecaa743d49a7"
test "$(md5sum "$C/flow/flow_stash.h" | awk '{print $1}')" = "0bde2734de39b1c017df836f4046f7a4"
test "$(md5sum "$C/detection/ips_context_chain.h" | awk '{print $1}')" = "53156e1edc95a5ce5d3beeba7606c29a"
test "$(md5sum "$C/time/clock_defs.h" | awk '{print $1}')" = "29200557ca5422281c456f4d76babc9d"
grep -q 'USE_TSC_CLOCK' "$C/time/clock_defs.h"                          # :23 the guard (tsc_clock.h NEVER pulled, measured clean arms)
test "$(md5sum "$C/flow/flow_data.h" | awk '{print $1}')" = "faf93f6d9ec68fcda4232bca2faf7d64"
test "$(md5sum "$C/framework/inspector.h" | awk '{print $1}')" = "$(md5sum "$SRC/src/framework/inspector.h" | awk '{print $1}')"  # NO-DRIFT face
# the 3 EXACT fresh cps (130 -> 133) + the find-0 PRE-face of the two NEW heads:
test "$(find "$C" -name inspector_manager.h | wc -l)" -eq 0                          # find-0 NEW in this donor (the 21a wall)
test "$(find "$C/framework" -name 'reload_survivor_subscriptions_impl.h' | wc -l)" -eq 0
test "$(find "$C" -name 'survivor_flow_data.cc' | wc -l)" -eq 0
mkdir -p "$C/managers"
cp "$SRC/src/framework/survivor_flow_data.cc" "$C/framework/survivor_flow_data.cc"; cmp -s "$C/framework/survivor_flow_data.cc" "$SRC/src/framework/survivor_flow_data.cc"
cp "$SRC/src/managers/inspector_manager.h"    "$C/managers/inspector_manager.h";    cmp -s "$C/managers/inspector_manager.h" "$SRC/src/managers/inspector_manager.h"
cp "$SRC/src/framework/reload_survivor_subscriptions_impl.h" "$C/framework/reload_survivor_subscriptions_impl.h"; cmp -s "$C/framework/reload_survivor_subscriptions_impl.h" "$SRC/src/framework/reload_survivor_subscriptions_impl.h"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 133                          # mid-build 130 + 3 MEASURED
test "$(grep -c 'inspector_manager.h' "$C/flow/flow.h" || true)" -eq 0             # flow.h NEVER pulls IMGR -- the cc :34 DIRECT pull

GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -pthread"
# ---- PRE-CHECKS: -fsyntax-only + .o + .UT + .O2 all rc0 (the codegen faces) ----
$GXX0 -fsyntax-only "$C/framework/survivor_flow_data.cc" 2> "$H/E4_syntax.txt";              test ! -s "$H/E4_syntax.txt"
$GXX0 -c "$C/framework/survivor_flow_data.cc" -o "$H/.pre_sfd.o"    2> "$H/E4_codegen.txt";      test ! -s "$H/E4_codegen.txt"
$GXX0 -DUNIT_TEST -c "$C/framework/survivor_flow_data.cc" -o "$H/.pre_sfd_ut.o" 2> "$H/E4_codegen_ut.txt"; test ! -s "$H/E4_codegen_ut.txt"
$GXX0 -O2 -c "$C/framework/survivor_flow_data.cc" -o "$H/.pre_sfd_o2.o" 2> "$H/E4_codegen_o2.txt";         test ! -s "$H/E4_codegen_o2.txt"
rm -f "$H"/.pre_*.o

# ---- E4 LOCALIZATION ARMS (SS6): (1) RAW arm -I$SRC/src ONLY -> the
# generated-header wall CHAINED cc:27 -> impl.h:32 -> flow_data.h:30 ->
# base_api.h:32 (the donor api_options.h shim is load-bearing); (2) impl.h
# drop -> FATAL DIRECT (the SOLO-subrow face: the cite-landed header is
# compile-load-bearing although NOT a row stageable); (3) flow.h drop ->
# FATAL (donor-resident, NEVER a stageable); (4) inspector_manager.h drop ->
# FATAL (the fresh-cp face); cc-drop: NOTHING else dies (grep-0 donor
# members -- the row TU is a LEAF); restored rc0 EVERY build. THEN the
# DONOR-REJECT leg: the 21a-donor clone + the SAME flow-closure cps WITHOUT
# the 9b603f8f graft -> flow.h:541 MAX_DAQ_VERDICT wall rc1 (the graft-
# version law MEASURED LIVE every build) + the P1-donor flow.h find-0
# receipt. ----
GXXD="g++ -std=c++17 -DNDEBUG -O0 -w -I$SRC/src"
if $GXXD -fsyntax-only "$SRC/src/framework/survivor_flow_data.cc" 2> "$H/E4_donorsrc_sfd.txt"; then
    echo "E4 LOCALIZATION DEAD: the cc compiled on the -I src ONLY arm -- the api_options.h generated-header wall is wrong"; exit 1
fi
grep -q "fatal error: framework/api_options.h: No such file" "$H/E4_donorsrc_sfd.txt"
grep -q "survivor_flow_data.cc:27" "$H/E4_donorsrc_sfd.txt"                       # the DIRECT impl.h quote face (CHAINED through it)
grep -q "reload_survivor_subscriptions_impl.h:32" "$H/E4_donorsrc_sfd.txt"
grep -q "flow_data.h:30" "$H/E4_donorsrc_sfd.txt"
mv "$C/framework/reload_survivor_subscriptions_impl.h" "$H/.e4_hold_impl.h"
if $GXX0 -fsyntax-only "$C/framework/survivor_flow_data.cc" 2> "$H/E4_noimpl_sfd.txt"; then
    echo "E4 flip BROKE: the cc compiled WITHOUT impl.h (:27 DIRECT) -- the subrow-closure face is wrong"; exit 1
fi
grep -q "fatal error: reload_survivor_subscriptions_impl.h: No such file" "$H/E4_noimpl_sfd.txt"
mv "$H/.e4_hold_impl.h" "$C/framework/reload_survivor_subscriptions_impl.h"
mv "$C/flow/flow.h" "$H/.e4_hold_flowh"
if $GXX0 -fsyntax-only "$C/framework/survivor_flow_data.cc" 2> "$H/E4_noflowh_sfd.txt"; then
    echo "E4 flip BROKE: flow/flow.h removed but the cc lived -- the flow.h rider law is wrong"; exit 1
fi
grep -q "fatal error: flow/flow.h: No such file" "$H/E4_noflowh_sfd.txt"
mv "$H/.e4_hold_flowh" "$C/flow/flow.h"
mv "$C/managers/inspector_manager.h" "$H/.e4_hold_imgrh"
if $GXX0 -fsyntax-only "$C/framework/survivor_flow_data.cc" 2> "$H/E4_noimgr_sfd.txt"; then
    echo "E4 flip BROKE: inspector_manager.h removed but the cc lived -- the fresh-cp law (cc :34 DIRECT) is wrong"; exit 1
fi
grep -q "fatal error: managers/inspector_manager.h: No such file" "$H/E4_noimgr_sfd.txt"
mv "$H/.e4_hold_imgrh" "$C/managers/inspector_manager.h"
# cc-drop arm: NOTHING else dies (the donor graph NEVER quotes the row):
test "$(grep -rl 'survivor_flow_data.cc' "$C" --include='*.cc' --include='*.h' | grep -v survivor_flow_data | wc -l)" -eq 0
mv "$C/framework/survivor_flow_data.cc" "$H/.e4_hold_sfd.cc"
for f in framework/module.cc log/text_log.cc codecs/link/cd_mpls.cc; do
    $GXX0 -fsyntax-only "$C/$f" 2> "$H/E4_ccdrop_survivor.txt"; test ! -s "$H/E4_ccdrop_survivor.txt"   # donor members SURVIVE the cc drop
done
mv "$H/.e4_hold_sfd.cc" "$C/framework/survivor_flow_data.cc"
$GXX0 -fsyntax-only "$C/framework/survivor_flow_data.cc" 2> "$H/E4_restored.txt"; test ! -s "$H/E4_restored.txt"
# THE DONOR-REJECT LEG (the graft-version law re-MEASURED LIVE, the 21a-
# donor clone):
rm -rf "$H/alt"; test "$(find "$RS/copy" -type f ! -name '*.o' | wc -l)" -eq 127
test "$(md5sum "$RS/copy/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"   # graft-v2 (PASS/DROP ONLY) identity = the WALL's root
cp -a "$RS/copy" "$H/alt"; find "$H/alt" -name '*.o' -delete
mkdir -p "$H/alt/managers" "$H/alt/time"
cp "$SRC/src/flow/flow.h" "$H/alt/flow/flow.h"; cp "$SRC/src/flow/deferred_trust.h" "$H/alt/flow/"; cp "$SRC/src/flow/flow_stash.h" "$H/alt/flow/"
cp "$SRC/src/detection/ips_context_chain.h" "$H/alt/detection/"; cp "$SRC/src/time/clock_defs.h" "$H/alt/time/"
cp "$SRC/src/managers/inspector_manager.h" "$H/alt/managers/"; cp "$SRC/src/framework/survivor_flow_data.cc" "$H/alt/framework/"
test "$(find "$H"/alt -type f ! -name '*.o' | wc -l)" -eq 134                     # 21a-tree 127 + 7 cps (closure 5 + imgr + cc) -- STRICTLY DOMINATED cp count
if g++ -std=c++17 -DNDEBUG -O0 -w -I"$H/alt" -pthread -fsyntax-only "$H/alt/framework/survivor_flow_data.cc" 2> "$H/E4_daqwall_21aclone.txt"; then
    echo "DONOR LAW DEAD: the 21a-donor clone compiled -- the graft-version wall (fead0027 lacks MAX_DAQ_VERDICT) is wrong"; exit 1
fi
grep -q "flow.h:541" "$H"/E4_daqwall_21aclone.txt
grep -q "MAX_DAQ_VERDICT" "$H"/E4_daqwall_21aclone.txt
test "$(find "$M9/copy" -path '*/flow/flow.h' | wc -l)" -eq 0                     # P1-donor REJECT face (167cb3c syn face holds)
rm -rf "$H/alt"

GXX="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -pthread"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C -pthread"

# ---- witness posture: WIN trio CARRIED (witness_18f ea1f79f3 + witness_conf
# 4dd91018 heredoc VERBATIM re-materialize from link4 + stubs_18d f4afd35f)
# + ONE own-new witness_sfd (the EXACTLY-+9 arm face). NEVER-double proofs:
# the WIN trio pulls ZERO of the 9 (grep-0) and witness_sfd NEVER re-defines
# get_instance_id (the carried witness_conf CLOSES it -- a live dup trap was
# hit and fixed at scratch, measured multiple-definition face). ----
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
_b=$(grep -n 'witness_conf\.cc" <<.EOFWC.$' "$L4/build.sh" | head -1 | cut -d: -f1)
test -n "$_b"
_e=$(awk -v s="$_b" 'NR>s && /^EOFWC$/{print NR; exit}' "$L4/build.sh")
sed -n "$((_b+1)),$((_e-1))p" "$L4/build.sh" > "$H/witness_conf.cc"
test "$(md5sum "$H/witness_conf.cc" | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"
test "$(find "$H" -maxdepth 1 -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 1
test "$(wc -l < "$H/witness_sfd.cc")" -eq 56
test "$(md5sum "$H/witness_sfd.cc" | awk '{print $1}')" = "101aa012a1a1629a4d1fbce2d58707da"    # the ONE-home +9-mirror + def-B face
test "$(wc -l < "$H/probe.cc")" -eq 67 && test "$(md5sum "$H/probe.cc" | awk '{print $1}')" = "c1ed73775fadc97d40d1b4aacbb26393"
test "$(wc -l < "$H/probe_faceA.cc")" -eq 78 && test "$(md5sum "$H/probe_faceA.cc" | awk '{print $1}')" = "fab7aae0a92cfaba9d38c0f051846f51"
test "$(grep -c 'unsigned get_instance_id' "$H/witness_sfd.cc" || true)" -eq 0                  # NEVER doubled vs witness_conf
test "$(grep -c 'create_flow_data_id' "$TUN/witness_18f.cc" "$ETH/stubs_18d.cc" "$H/witness_conf.cc" | awk -F: '{s+=$2} END {print s+0}')" -eq 0   # the WIN trio NEVER touches the FlowData arms
test "$(grep -c 'is_pending_tterm\|thread_drain_pending' "$TUN/witness_18f.cc" "$ETH/stubs_18d.cc" "$H/witness_conf.cc" | awk -F: '{s+=$2} END {print s+0}')" -eq 0   # the +2 IMGR pair = FOUND-0 brand-new (the finspect PLAN :166 IMGR-turf earmark rides)
# the row-wide ONE-home pin (witness + probe + carried faces):
test "$(grep -c 'unsigned FlowData::create_flow_data_id()' "$H/witness_sfd.cc")" -eq 1

REAL="$C/framework/codec.cc $C/protocols/ip.cc $C/sfip/sf_ip.cc $C/utils/util_cstring.cc $C/utils/util.cc $C/log/text_log.cc $C/framework/module.cc"
OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- O0 compile: row .o PLAIN + the UT discipline echo (U-sets IDENTICAL:
# the cc has ZERO UNIT_TEST arms -- the 21a census INVERTED), backbone REAL .o,
# WIN trio, witness, probes ----
$GXX -c "$C/framework/survivor_flow_data.cc" -o "$C/sfd.o"
$GXX -DUNIT_TEST -c "$C/framework/survivor_flow_data.cc" -o "$C/sfd_ut.o"
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc       -o "$H"/probe.o
$GXX -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o
$GXX -c "$H"/witness_sfd.cc -o "$H"/witness_sfd.o

# ---- ZERO-gate census (the 28th-straight face; the dialect-BLOCKED note
# rides the header, the receipts above prove) ----
test ! -e "$H/gate.txt"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt|.*catch.*' || true)" -eq 0

# ---- nm per-TU U-census (the 19-face MEASURED every build, NOT carried): ----
nm -C -u "$C/sfd.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_sfd.txt"
test "$(wc -l < "$H/nm_U_sfd.txt")" -eq 19
test "$(grep -c '__assert_fail' "$H/nm_U_sfd.txt" || true)" -eq 0                  # the NDEBUG arm (production posture)
# the NDEBUG-delta face (honest flip: 21a was 0-arm NDEBUG-INVARIANT; THIS row
# carries 2 real assert arms -- the +1 __assert_fail under NO-NDEBUG measured):
g++ -std=c++17 -O0 -w -I"$C" -pthread -c "$C/framework/survivor_flow_data.cc" -o "$H/.ndef_sfd.o"
nm -C -u "$H/.ndef_sfd.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_ndef.txt"
diff "$H/nm_U_sfd.txt" "$H/nm_U_ndef.txt" > "$H/nm_U_ndef_delta.txt" || true
test "$(grep -c '^>' "$H/nm_U_ndef_delta.txt")" -eq 1
grep -q '__assert_fail' "$H/nm_U_ndef_delta.txt"
# the UT discipline echo (SS2): U-set IDENTICAL plain-vs-UT (UNIT_TEST grep-0 face):
nm -C -u "$C/sfd_ut.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_sfd_ut.txt"
diff "$H/nm_U_sfd.txt" "$H/nm_U_sfd_ut.txt" > "$H/nm_U_delta.txt" || true
test ! -s "$H/nm_U_delta.txt"
# the snort-family residue: EXACTLY 10 lines through the snort:: filter = the
# EXACTLY-9 NAMED own-new arms + 'typeinfo for snort::FlowData' (the rides-face
# closed by the witness vtable mirror) -- honest census:
nm -C -u "$C/sfd.o" | grep ' U ' | grep 'snort::' > "$H/sfd_residue_dem.txt" || true
test "$(wc -l < "$H/sfd_residue_dem.txt")" -eq 10
test "$(grep -vc 'typeinfo' "$H/sfd_residue_dem.txt")" -eq 9
for s in 'FlowData::FlowData' 'FlowData::~FlowData' 'create_flow_data_id' 'FlowDataStore::get' 'FlowDataStore::set' 'Inspector::add_ref' 'Inspector::rem_ref' 'is_pending_tterm' 'thread_drain_pending_tterm_if_pending'; do
    grep -q "$s" "$H/sfd_residue_dem.txt"
done
# ZERO pull of the 21a trio (the row NEVER reaches data_bus/Warning/get_reload_id):
test "$(grep -c '_subscribe\|get_reload_id\|WarningMessage\|DataBus' "$H/sfd_residue_dem.txt" || true)" -eq 0
# the defined face of the provider TU: ctor x2 / dtor x3 T, add_pin T,
# pin_survivor T = EXACTLY 7 T + the get_flow_data_id W + the B provider-id +
# the vtable/typeinfo/typeinfo-name V trio (SS4 static-init + provider census):
test "$(nm --defined-only "$C/sfd.o" | awk '$2=="T"' | wc -l)" -eq 7
test "$(nm -C --defined-only "$C/sfd.o" | grep -c ' T snort::SurvivorFlowData::SurvivorFlowData')" -eq 2   # the 21a :303 mirror pin (ctor >= 1, exact 2 measured)
test "$(nm -C --defined-only "$C/sfd.o" | grep -c 'T snort::SurvivorFlowData::~SurvivorFlowData')" -eq 3   # dtor x3: complete + deleting + base-object (the PLAN ctor2/dtor3 face)
test "$(nm -C --defined-only "$C/sfd.o" | grep -c 'T snort::Flow::pin_survivor_flow_data')" -eq 1
test "$(nm -C --defined-only "$C/sfd.o" | grep -c ' W snort::SurvivorFlowData::get_flow_data_id')" -eq 1
test "$(nm --defined-only "$C/sfd.o" | grep -c ' B _ZN5snort16SurvivorFlowData12flow_data_idE')" -eq 1     # the B provider-id face (STATIC-INIT pull rides it)
test "$(nm --defined-only "$C/sfd.o" | grep -c 'V _ZTVN5snort16SurvivorFlowDataE')" -eq 1

# ---- THE +9 L1 CENSUS PROVEN: (row .o + 7-object backbone + WIN trio +
# bare main) WITHOUT witness = EXACTLY-10 distinct undefined (9 named arms +
# the typeinfo rides-face); FULL link rc0 ONLY with witness_sfd (one home): ----
echo 'int main(){return 0;}' > "$H/.l1_main.cc"
$GXX -c "$H/.l1_main.cc" -o "$H/.l1_main.o"
if $GXX "$C/sfd.o" $OBJS "$H/.l1_main.o" $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: sfd linked WITHOUT witness_sfd -- the +9 L1 delta is wrong"; exit 1
fi
grep -c 'undefined reference' "$H/L1_link_face.txt" > /dev/null
grep -oE "undefined reference to \`[^']*" "$H/L1_link_face.txt" | sed "s/undefined reference to \`//" | c++filt | sort -u > "$H/L1_undefined.txt"
test "$(wc -l < "$H/L1_undefined.txt")" -eq 10
test "$(grep -vc 'typeinfo' "$H/L1_undefined.txt")" -eq 9
$GXX "$C/sfd.o" $OBJS "$H/.l1_main.o" "$H/witness_sfd.o" $WIN -o "$H/.L1_probe" && echo full-link-rc0 > "$H/L1_full_link.txt"
test -s "$H/L1_full_link.txt"
rm -f "$H/.L1_probe"
# THE DEFINITION-MIRROR TRAP (MEASURED LIVE every build): the witness MINUS the
# flow_data_id B-mirror = link DIES (the scratch face re-earned):
sed '/^unsigned FlowData::flow_data_id = 0;$/d' "$H/witness_sfd.cc" > "$H/.ndef_witness.cc"
test "$(grep -c 'flow_data_id = 0' "$H/.ndef_witness.cc" || true)" -eq 0
$GXX -c "$H/.ndef_witness.cc" -o "$H/.ndef_witness.o"
if $GXX "$C/sfd.o" "$H/.ndef_witness.o" -o /dev/null 2> "$H/E4_defmirror.txt"; then
    echo "DEF-MIRROR TRAP DEAD: linked WITHOUT the flow_data_id definition -- the trap face is wrong"; exit 1
fi
grep -q "undefined reference to \`snort::FlowData::flow_data_id" "$H/E4_defmirror.txt" || grep -q "undefined reference to .snort::FlowData::flow_data_id" "$H/E4_defmirror.txt"
# the witness OWN face: >9 T mirrors (scaffold-inflated, honest face) + the
# B-flow_data_id mirror + the Flow vtable/typeinfo ride faces:
test "$(nm --defined-only "$H/witness_sfd.o" | awk '$2=="T"' | wc -l)" -ge 9
test "$(nm --defined-only "$H/witness_sfd.o" | grep -c ' B _ZN5snort8FlowData12flow_data_idE')" -eq 1
test "$(nm --defined-only "$H/witness_sfd.o" | grep -c 'V _ZTIN5snort8FlowDataE')" -eq 1                  # the typeinfo rides-face closes HERE
rm -f "$H/.ndef_witness.cc" "$H/.ndef_witness.o"

# ---- probe links: DEC rides plain sfd.o (ZERO clock-seam arms = the 21a
# UT-pairing INVERTS); FACE-A same graph (release/no-seam identity, U-diff
# EMPTY proves the pairing is VACUOUS here) ----
$GXX "$C/sfd.o" $OBJS "$H"/probe.o      "$H/witness_sfd.o" $WIN -pthread -o "$H"/probe
$GXX "$C/sfd.o" $OBJS "$H"/probe_faceA.o "$H/witness_sfd.o" $WIN -pthread -o "$H"/probe_faceA
test "$(nm -C "$H"/probe "$H"/probe_faceA | grep -c 'Catch::' || true)" -eq 0        # NO Catch face ANYWHERE
test "$(nm -C "$H"/probe | grep -c 'SnortConfig::get_conf')" -ge 1                  # the carried WIN ride stays honest (backbone shape consistency)

# ---- O2 twins (byte-ident vectors law + the honest 2-face U-delta): ----
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
$GXXA -c "$C/framework/survivor_flow_data.cc" -o "$O2/sfd.o"
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o
$GXXA -c "$H"/probe_faceA.cc -o "$O2"/probe_faceA.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H/witness_conf.cc" -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc   -o "$O2"/stubs_18d.o;   $GXXA -c "$H"/witness_sfd.cc -o "$O2"/witness_sfd.o
OB2="$O2/codec.o $O2/ip.o $O2/sf_ip.o $O2/util_cstring.o $O2/util.o $O2/module.o $O2/text_log.o"
$GXXA "$O2/sfd.o" $OB2 "$O2"/probe.o      "$O2/witness_sfd.o" "$O2/witness_18f.o" "$O2/witness_conf.o" "$O2/stubs_18d.o" -pthread -o "$H"/probe_O2
$GXXA "$O2/sfd.o" $OB2 "$O2"/probe_faceA.o "$O2/witness_sfd.o" "$O2/witness_18f.o" "$O2/witness_conf.o" "$O2/stubs_18d.o" -pthread -o "$H"/probe_faceA_O2
nm -C -u "$O2/sfd.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_sfd_O2.txt"
test "$(wc -l < "$H/nm_U_sfd_O2.txt")" -eq 17                                       # the O0-vs-O2 U-DELTA = EXACTLY 2 (the vector throw pair rides -O0 ONLY)
diff "$H/nm_U_sfd.txt" "$H/nm_U_sfd_O2.txt" > "$H/nm_U_O2_delta.txt" || true
test "$(grep -c '^<' "$H/nm_U_O2_delta.txt")" -eq 2
grep -q '__throw_bad_alloc' "$H/nm_U_O2_delta.txt"
grep -q '__throw_bad_array_new_length' "$H/nm_U_O2_delta.txt"

# ---- cross-donor invariance LEG (the ipheavy ALT 140 + 3 = 143; the U-face
# BYTE-IDENT across both donor trees -- vectors byte-ident rides the same
# witness/probe, the 21a flow_probe precedent): ----
test "$(find "$IP/copy" -type f ! -name '*.o' | wc -l)" -eq 140
test "$(md5sum "$IP/copy/daq_common.h" | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"          # the SAME ext#4 face rides ipheavy
test "$(md5sum "$IP/copy/daq.h" | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"                 # ipheavy's OWN graft-v4 daq.h (cite face, NEVER touched)
test "$(md5sum "$IP/copy/flow/flow.h" | awk '{print $1}')" = "765663d466f59ac9af76344d4ba1de9b"           # the flow closure rides ipheavy byte-ident TOO
cp -a "$IP/copy" "$H/alt"; find "$H/alt" -name '*.o' -delete
mkdir -p "$H/alt/managers"
cp "$SRC/src/framework/survivor_flow_data.cc" "$H/alt/framework/"; cp "$SRC/src/managers/inspector_manager.h" "$H/alt/managers/"; cp "$SRC/src/framework/reload_survivor_subscriptions_impl.h" "$H/alt/framework/"
test "$(find "$H/alt" -type f ! -name '*.o' | wc -l)" -eq 143                          # SAME 3 cps -> 143
g++ -std=c++17 -DNDEBUG -O0 -w -I"$H/alt" -pthread -c "$H/alt/framework/survivor_flow_data.cc" -o "$H/alt_sfd.o"
nm -C -u "$H/alt_sfd.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_sfd_altdonor.txt"
cmp "$H/nm_U_sfd.txt" "$H/nm_U_sfd_altdonor.txt"                                       # U-IDENTICAL cross-donor (the donor-law invariance receipt)
rm -f "$H/alt_sfd.o"; rm -rf "$H/alt"

timeout 60 "$H"/probe          > "$H"/vectors_O0.txt      || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_O2       > "$H"/vectors_O2.txt      || { echo PROBE_FAIL DEC O2; exit 1; }
timeout 60 "$H"/probe_faceA    > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_faceA_O2 > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
[ -e "$H"/vectors.txt ]        && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt        || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ]  && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 law: EVERY state call stored to a VAR before printf (the 21a law
# re-earns at this row; the grep rides CODE lines, the probes satisfy it): ----
test "$(grep -c 'printf.*get_ref\|printf.*get_flow_data(' "$H"/probe.cc "$H"/probe_faceA.cc | awk -F: '{s+=$2} END {print s+0}')" -eq 0
test "$(grep -c 'get_ref(1)\|drained;' "$H"/probe.cc)" -ge 6
# all-decimal hygiene:
test "$(grep -c '0x[0-9a-f]' "$H"/vectors_O0.txt || true)" -eq 0
test "$(grep -c '0x[0-9a-f]' "$H"/vectors_faceA_O0.txt || true)" -eq 0

# ---- known-answer ladders: FIRST-RUN SEED then drift-refuse (18j+ lineage) ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi
# DEC = the MEASURED 6-step pilot spine VERBATIM (T0-T5) + the A->B->C chain
# (cc :74-:75 comment) + the SFD-delete release arm (T6/T7). The T3 SEMANTIC
# face: set_gadget on a GADGET-LESS flow pins NOTHING -- survival fires ONLY
# at REBIND (flow.h :362-:364).
grep -q '^T0 ctor_refs=1 id_nonzero=1$' "$V"
grep -q '^T1 addpin_twice_sum=2 distinct=2$' "$V"          # dup add_pin = std::find no-op (cc :62-:63)
grep -q '^T2 dtor_sum=0 drained=2$' "$V"                   # per-pin rem_ref + drain_if_pending x2 (cc :49-:56)
grep -q '^T3 pinned=0 refs_a=1$' "$V"                      # THE semantic face: gadget-less = pins NOTHING
grep -q '^T4 rebind_sum=2 gadget=b$' "$V"                  # A->B rebind: SFD(a) BORN at rebind (survival)
grep -q '^T5 cleared_sum=1$' "$V"                          # not-pending early return (cc :71-:72); release still rem_refs
grep -q '^T6 chain_abc_sum=3 drained=5$' "$V"              # the A->B->C distinct-inspector chain (each one pinned)
grep -q '^T7 sfd_delete_sum=1 drained=7$' "$V"             # SFD dtor rem_refs + drains the chain pins
test "$(wc -l < "$V")" -eq 8
if [ -s /opt/data/cache/scratch/row21b/probe_sfd_run.txt ]; then
    head -6 "$V" | cmp -s - /opt/data/cache/scratch/row21b/probe_sfd_run.txt || { echo "DEC spine DRIFTS vs the recon 6-step pilot ladder"; exit 1; }   # cross-pass byte-ident (scratch receipt tolerant if pruned)
fi
# FACE-A = the NOLOAD head + the static-init provider pull + idempotency +
# the private-reach law + the pending-gate + survival-release arms:
grep -q '^NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2$' "$FA"
grep -q '^IDSTATIC load_allocated=1 id=1$' "$FA"               # cc :39 rode the LOAD (B-mirror starts 0 -> id==1 OBSERVABLE)
grep -q '^IDSEQ next=2 strictly_above=1$' "$FA"                # the witness ++ face rides ABOVE the load-allocated id
grep -q '^ADDIDEM dup_noop=1 sum=2 distinct=2$' "$FA"          # the std::find dup-noop direct arm
grep -q '^REACH gadgetless=0 refs_p=2$' "$FA"                  # PRIVATE reach NEVER fires w/o a gadget
grep -q '^REBIND pinned=1 roundtrip=1$' "$FA"                  # the PUBLIC inline reaches the PRIVATE pin (flow.h :360-:369)
grep -q '^NOTPEND pending0_rebind=0$' "$FA"                    # is_pending_tterm==false -> early return (cc :71-:72)
grep -q '^SURVIVE released=1 refs_p=2$' "$FA"                  # SFD dtor rem_refs the pin + drains once
test "$(grep -c '^LOAD\|ver=\|size=\|0x' "$FA" || true)" -eq 0                       # NO codec/CodecApi face EVER (framework TU)
test "$(grep -c 'rss_pegs\|PEGTYPE\|SLOTMAP\|dedup\|Dedup' "$FA" || true)" -eq 0     # the 21a table faces NEVER apply (ZERO dbus pull)
test "$(grep -c 'cd_\|CodecApi\|mpls\|vlan\|daq\|tunnel' "$V" || true)" -eq 0
test "$(grep -c 'cd_\|CodecApi\|mpls\|vlan\|daq\|tunnel' "$FA" || true)" -eq 0       # ZERO codec/tunnel face ANYWHERE

python3 - "$V" "$FA" <<'PYPIN'
# BOTH-WAYS pins: the vectors re-echo the GROUND cc faces (never air). The
# static-init line, the private decl vs the public inlines, the idempotency
# comment, the NOLOAD grep-0 faces, and the NEXT.md cite-only x3/x5 seeds.
import sys
cc = open("/opt/data/snort3-src/src/framework/survivor_flow_data.cc").read()
ih = open("/opt/data/snort3-src/src/framework/reload_survivor_subscriptions_impl.h").read()
fh = open("/opt/data/snort3-src/src/flow/flow.h").read()
V, FA = open(sys.argv[1]).read(), open(sys.argv[2]).read()
assert "unsigned SurvivorFlowData::flow_data_id = FlowData::create_flow_data_id();" in cc          # the static-init pull (T0/FaceA IDSTATIC)
assert cc.count("assert(pin);") == 2                                                              # the 2-runtime-assert flip face
assert "std::find(pinned.begin(), pinned.end(), pin) != pinned.end()" in cc                        # the dup-noop (T1/ADDIDEM)
assert "if ( !InspectorManager::is_pending_tterm(&outgoing) )" in cc                               # the pending gate (T3/NOTPEND)
assert "idempotent per distinct inspector" in cc                                                   # the A->B->C comment (T6)
assert "class SurvivorFlowData : public FlowData" in ih                                            # the 21a-owned decl (cite home)
assert "void pin_survivor_flow_data(Inspector&);" in fh                                            # PRIVATE (the probe-shape law)
assert fh.count("pin_survivor_flow_data(*gadget);") == 2                                           # BOTH public inlines reach it (:364/:375)
assert FA.count("PEGS") == 0 and "SLOTMAP" not in FA                                               # the 21a table face NEVER rides (ZERO table census)
assert "load_allocated=1" in FA and "T3 pinned=0" in V                                             # the semantic pair rides BOTH ladders
nx = open("/opt/data/snort3-rust/NEXT.md").read()
assert nx.count("629 tests green / 0 FAILED") == 3 and nx.count("621 tests green / 0 FAILED") == 3
assert nx.count("605 tests green / 0 FAILED") == 3 and nx.count("597 tests green / 0 FAILED") == 3
assert "573 tests green" in nx
PYPIN

# ---- measured first-run face PINS (SEED PASS output, drift refuses EVERY
# build; BYTE-IDENT across O0/O2 arms of THIS pass): ----
test "$(wc -l < "$H"/vectors.txt)" -eq 8
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 8
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "3c05632e88676ef9f40ee0a5d33fdf09"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "040de1ef2ea177ac526c8ef244713c58"
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt   # receipt (ignored)

# ---- TAMPER ARM (first-run-seed -> DRIFT-THEN-REFUSE law): a ONE-BYTE flip
# of the pinned vectors.txt MUST trip the drift-cmp when re-checked vs the
# fresh run; the byte-exact restore MUST land back on the pinned md5: ----
cp "$H"/vectors.txt "$H"/.vectors_pristine
sed -i '4s/pinned=0/pinned=9/' "$H"/vectors.txt                       # the ONE-byte T3 flip (line 4 = THE semantic face)
cmp -s "$H"/vectors.txt "$H"/vectors_O0.txt && { echo "TAMPER ARM DEAD: flipped vectors.txt still matches the fresh O0 run"; exit 1; }
cp "$H"/.vectors_pristine "$H"/vectors.txt
cmp -s "$H"/vectors.txt "$H"/vectors_O0.txt || { echo "TAMPER RESTORE DEAD: restored vectors.txt no longer matches the fresh run"; exit 1; }
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')" = "3c05632e88676ef9f40ee0a5d33fdf09"   # restored EXACT
rm -f "$H"/.vectors_pristine

# ---- graft ladder TAIL re-assert (HEAD pinned at clone; NEVER promoted,
# NEVER re-authored by THIS row): ----
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"

# ---- frozen-donor direct-md5 census (the FM15 face VERBATIM, 15 faces) ----
declare -a FM15=(
 "/opt/data/snort3-rust/tools/fmod_harness/gate.txt 4826fc2233044a2d5429413faf0ae1af"
 "/opt/data/snort3-rust/tools/fmod_harness/vectors.txt f0fdbab06fe1681af1c654531b917c55"
 "/opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc 9fad7e9d7a278fbc2ee82c233f86e774"
 "/opt/data/snort3-rust/tools/vocab_harness/vectors.txt 5da70e82416b6f769af8177d859331e7"
 "/opt/data/snort3-rust/tools/codec_harness/stubs.cc be9bdd0b437d1f6c56c841e8155d9e70"
 "/opt/data/snort3-rust/tools/ext_harness/witness_conf.cc 4dd91018f8439d706ba666c6f18c9152"
 "/opt/data/snort3-rust/tools/tun_harness/vectors.txt 2a7924796f8f0cfdca5e665dee28f519"
 "/opt/data/snort3-rust/tools/tun_harness/vectors_faceA.txt 81602890210d8d83068397c2cece1241"
 "/opt/data/snort3-rust/tools/tun_harness/probe.cc 5b8355189caa2d8b1a12913f94c3838d"
 "/opt/data/snort3-rust/tools/tun_harness/probe_dec.cc 99a8257cd470c33be8a4135eb45e547a"
 "/opt/data/snort3-rust/tools/tun_harness/witness_18f.cc ea1f79f3f05f8a91dc9524a963692b39"
 "/opt/data/snort3-rust/tools/eth_harness/stubs_18d.cc f4afd35f06bc45ce5aa0ec12110ed8ae"
 "/opt/data/snort3-rust/tools/eth_harness/vectors.txt 1bd98dbb57dd2f536104995bd76d9bad"
 "/opt/data/snort3-rust/tools/ext_harness/vectors.txt da21842980d042d5871edeaaf502049e"
 "/opt/data/snort3-rust/tools/ext_harness/vectors_faceA.txt 0fa79b534d2a598b2befb047c95c3579"
)
for e in "${FM15[@]}"; do
    set -- $e
    test "$(md5sum "$1" | awk '{print $1}')" = "$2"
done

# ---- BACKBONE-10 census STAYS EXACTLY 10 (the +9 witness = a ROW symbol
# face, NEVER an array face -- the 18n symbol-vs-array law): ----
declare -a B10=(
 "/opt/data/snort3-rust/tools/small4_harness/vectors.txt 462f0ff6ed44220564c5ef0c8538ad80"
 "/opt/data/snort3-rust/tools/small4_harness/vectors_faceA.txt 4755d48c54cc057b3c3c9eafec01c7cf"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors.txt fd1855e10e08eedcc6598de7ee034d0e"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors_faceA.txt 2fb9dc4570a0160451f8399d22736a60"
 "/opt/data/snort3-rust/tools/daq3_harness/witness_daq.cc e0166b021073fed328bfd583c839e38b"
 "/opt/data/snort3-rust/tools/miscip_harness/vectors.txt 43b259ac8b77320ff9ddaa80dde1a36e"
 "/opt/data/snort3-rust/tools/miscip_harness/vectors_faceA.txt e4c47bac93a15af4ecfdc9a0bd1abe62"
 "/opt/data/snort3-rust/tools/miscip_harness/witness_miscip.cc c5b498ffa6beac768f34e25830c552a1"
 "/opt/data/snort3-rust/tools/misc3_harness/witness_trio.cc ef50cd2f8cdb4b9fa3d483e702bd73be"
 "/opt/data/snort3-rust/tools/misc3_harness/witness_conf.cc 4dd91018f8439d706ba666c6f18c9152"
)
for e in "${B10[@]}"; do
    set -- $e
    test "$(md5sum "$1" | awk '{print $1}')" = "$2"
done
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H/backbone10.txt"     # receipt (ignored)
test "$(wc -l < "$H"/backbone10.txt)" -eq 10
# TWO-LINEAGE DIRECT echoes (byte-ident pins; the IMMEDIATE 21a lineage + the
# chain faces + THE FROZEN TAILS per the orchestrator law):
test "$(md5sum "$RS"/vectors.txt | awk '{print $1}')" = "9e303761c021d00ea672a493544e07af"        # THE 21a tail face
test "$(md5sum "$RS"/vectors_faceA.txt | awk '{print $1}')" = "42aa06fb4c55adfa50e96d1f715d997e"
grep -q 'R_SUBS_DONE vectors=' "$RS/build.sh"
test "$(wc -l < "$RS"/vectors.txt)" -eq 12 && test "$(wc -l < "$RS"/vectors_faceA.txt)" -eq 9     # the MEASURED 12/9 21a tail face
test "$(md5sum "$M9"/vectors.txt | awk '{print $1}')" = "e6328da1f3188df9754b9e45d74897db"
test "$(md5sum "$M9"/vectors_faceA.txt | awk '{print $1}')" = "dfe738fb8b4200368332ba73b81a4e96"
test "$(md5sum "$L4"/vectors.txt | awk '{print $1}')" = "c7f5808fa326b7831603813c16a3b01e"
test "$(md5sum "$L4"/vectors_faceA.txt | awk '{print $1}')" = "9fdfc50da8fee22b473028f1f9b29c12"
test "$(md5sum "$R"/tools/link6_harness/vectors.txt | awk '{print $1}')" = "e59f7a8a70d172261dcb847dcfdcb36a"
test "$(md5sum "$R"/tools/link6_harness/vectors_faceA.txt | awk '{print $1}')" = "d2fc5591bc45c1787fcee7393675a3d8"
test "$(md5sum "$R"/tools/erspan_harness/vectors.txt | awk '{print $1}')" = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$R"/tools/erspan_harness/vectors_faceA.txt | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"
test "$(md5sum "$R"/tools/mpls_harness/vectors.txt | awk '{print $1}')" = "b4b660e448703b603755a0049c6a2052"       # THE mpls DONOR tail face
test "$(md5sum "$R"/tools/mpls_harness/vectors_faceA.txt | awk '{print $1}')" = "3066fc335fb21777891271b9c7b152c5"
grep -q 'MPLS_LINK_DONE vectors=' "$R"/tools/mpls_harness/build.sh                                   # the frozen tail-line shape
test "$(wc -l < "$R"/tools/mpls_harness/vectors.txt)" -eq 54 && test "$(wc -l < "$R"/tools/mpls_harness/vectors_faceA.txt)" -eq 17   # the MEASURED 54/17 mpls tail face
test "$(md5sum "$IP"/vectors.txt | awk '{print $1}')" = "857b5a100480114085b45a392ab713bf"           # THE ipheavy tail face
test "$(md5sum "$IP"/vectors_faceA.txt | awk '{print $1}')" = "63df50bc57b7d15d95c21bdfcd492fce"
grep -q 'IPHEAVY_DONE vectors=' "$IP/build.sh"                                                       # the frozen tail-line shape
test "$(wc -l < "$IP"/vectors.txt)" -eq 121 && test "$(wc -l < "$IP"/vectors_faceA.txt)" -eq 44      # the MEASURED 121/44 ipheavy tail face
grep -q 'MPLS_LINK_DONE' "$IP/build.sh"                                                               # the ipheavy echo of mpls (lineage legible)
# gre GATE anchor (the positive-gate CONTRAST face for the ZERO-gate pin):
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh

# ---- TWO-LINEAGE gate census (MEASURED; THIS row ships ZERO gate faces --
# the 25/9/17/1 face UNDISTURBED, the 28th straight zero-gate row): ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 25
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 17
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                       # honest tracked face: gre's ONLY
# NEXT.md cargo CITE faces ONLY (NEVER edit; the seeded + older pinned x3/x5):
test "$(grep -c '629 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '621 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '605 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '597 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
# the 21a harness's LEFT-OPEN seam pin STAYS VALID now PROVEN-POSITIVE (the
# definer exists; the 21a row .o STILL pulls ZERO SurvivorFlowData):
test "$(nm "$RS/copy/rs""ubs.o" | grep -c SurvivorFlowData || true)" -eq 0

# ---- STAGEABLES echo + .gitignore PROOF (the NESTED-INSTRUMENT face; the
# root .gitignore NEVER touched; the dir FULLY ?? this pass). NON-ignored
# face = the 8 stageables (the 21a shape): PLAN build.sh probe.cc
# probe_faceA.cc vectors.txt vectors_faceA.txt witness_sfd.cc + .gitignore.
# STATE-AWARE DUAL-FACE GUARD (the ipheavy 8b9882a ZERO-LEAK law): pre-commit
# = 8 UNTRACKED faces; post-commit = 8 TRACKED faces, untracked EMPTY ----
untracked=$(git -C "$R" ls-files --others --exclude-standard tools/sfd_harness | sort)
tracked=$(git -C "$R" ls-files tools/sfd_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 8
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_sfd.cc .gitignore; do
    echo "$face" | grep -q "tools/sfd_harness/$f$"
done
test "$(echo "$face" | grep -c 'witness_sfd')" -eq 1
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/sfd.o copy/sfd_ut.o copy/managers/inspector_manager.h copy/framework/survivor_flow_data.cc copy/framework/reload_survivor_subscriptions_impl.h copy/daq_common.h copy/flow/flow.h o2/sfd.o probe probe_O2 probe_faceA probe_faceA_O2 probe.o probe_faceA.o witness_sfd.o witness_conf.o witness_18f.o stubs_18d.o witness_conf.cc vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt nm_U_*.txt sfd_residue_dem.txt E4_syntax.txt E4_codegen.txt E4_codegen_ut.txt E4_codegen_o2.txt E4_donorsrc_sfd.txt E4_noimpl_sfd.txt E4_noflowh_sfd.txt E4_noimgr_sfd.txt E4_restored.txt E4_ccdrop_survivor.txt E4_daqwall_21aclone.txt E4_defmirror.txt L1_link_face.txt L1_undefined.txt L1_full_link.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt .l1_main.cc .l1_main.o; do
    git -C "$R" check-ignore -q "tools/sfd_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/sfd_harness/$f NOT ignored"; exit 1; }
done
# the stageables NOT-ignored proofs:
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_sfd.cc .gitignore; do
    git -C "$R" check-ignore -q "tools/sfd_harness/$f" && { echo "WRONGLY IGNORED: $f"; exit 1; } || true
done
if git -C "$R" ls-files --error-unmatch "tools/sfd_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/sfd_harness/" | wc -l)" -eq 8
    test -z "$(git -C "$R" ls-files tools/sfd_harness | grep -vE 'PLAN\.md|build\.sh|probe\.cc|probe_faceA\.cc|vectors\.txt|vectors_faceA\.txt|witness_sfd\.cc|\.gitignore')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard tools/sfd_harness)"   # ZERO-LEAK post-commit face
else
    git -C "$R" status --porcelain | grep -qx '?? tools/sfd_harness/'
    test "$(git -C "$R" ls-files --others --exclude-standard tools/sfd_harness | wc -l)" -eq 8
fi
# no STAGED churn: index EMPTY (the C-side row stages NOTHING from build.sh);
# the ROOT .gitignore UNTOUCHED (the nested-local law). STATE-AWARE churn
# face (the 21a rs-landing-flip precedent): the row's OWN faces = the two
# untracked rs/port files PRE-commit (gone AFTER the landing commit) + the
# two doc files + the ONE wiring line tracked-modified — ZERO churn of any
# other kind, NEVER pins own-HEAD:
test -z "$(git -C "$R" diff --name-only --cached)"
test "$(git -C "$R" status --porcelain | grep -vcE '^\?\? (tools/sfd_harness/|src/framework/survivor_flow_data\.rs|tests/sfd_parity_test\.rs)$|^ M "?(src/framework/mod\.rs|PORTING_PLAN\.md|KNOWN DEVIATIONS\.md)"?$')" -eq 0   # the KNOWN-DEVIATIONS name rides the QUOTED porcelain face (space in name)
# SINGLE-TENANT census (orchestrator law, disk re-checked EVERY build): the
# ONLY tools/ dirty face = THIS row's ?? dir:
dirtyother=$(git -C "$R" status --porcelain tools | grep -vE '^\?\? tools/sfd_harness/' || true)
test -z "$dirtyother"

echo "row-TU nm census (MEASURED, never typed): nm_U=19 at -DNDEBUG (+1 __assert_fail measured at the NO-NDEBUG delta face -- this row FLIPS 21a's zero-assert census: ^assert=2, assert-string=3 honestly pinned); O2 arm = 17 (the vector throw pair vanishes = an honest 2-face U-delta NEVER a vectors delta); UT arm U-set IDENTICAL (UNIT_TEST grep-0 INVERTED vs 21a's 4/1); defined = EXACTLY 7 T (SurvivorFlowData ctor x2 + ~SurvivorFlowData x3 complete/deleting/base-object + add_pin + Flow::pin_survivor_flow_data) + 1 B SurvivorFlowData::flow_data_id (THE static-init provider pull B-face) + 1 W get_flow_data_id + the vtable/typeinfo/typeinfo-name V trio; ZERO SurvivorFlowData pull from the 21a row .o STAYS (now definer-PROVEN: sfd.o arms the ctor>=1 mirror pin)"
echo "witness posture: L1 CENSUS EXACTLY-9 NAMED own-new (+1 typeinfo rides-face = 10 undefined lines; 21a +3 grows to 21b +9 HONEST) => ONE own witness_sfd.cc 56L (md5 101aa012) ONE-HOME law pinned (create_flow_data_id def-count == 1); the flow_data_id B-DEFS trap RE-MEASURED LIVE every build (link DIES without it); the tterm PAIR (is_pending_tterm + thread_drain_pending_tterm_if_pending) = FOUND-0 brand-new, bodies mirror inspector_manager.cc :324/:1276 shapes w/ a fake pending knob, NEVER invented; WIN trio pulls ZERO of the 9 (link-leg consistency only); backbone STAYS $(wc -l < "$H"/backbone10.txt) (symbol-vs-array)"
echo "cp face: MPLS donor VERBATIM 130 + 3 EXACT cps = 133 mid-build asserted (row cc -> copy/framework/ + inspector_manager.h 139/babb1997 -> copy/managers/ find-0-NEW + _impl.h 156/b437ba1c CITE-21a cp'd for closure NOT a fresh row face; the flow closure rides BYTE-IDENT NEVER re-cp'd); DONOR LAW arms: the 21a-donor clone (127+7=134, strictly dominated cps) DIES at flow.h:541 MAX_DAQ_VERDICT w/ the fead0027 graft-v2 (MEASURED rc1 every build) + the P1-donor flow.h find-0 + ipheavy ALT 140+3=143 U-IDENTICAL invariance leg; graft ladder 0f7016a6/9b603f8f HEAD+TAIL md5-pinned (ext#4 9b603f8f = the REQUIRED face for THIS donor)"
echo "FACE-A: NOLOAD head (BUILDING_SO/snort_plugins grep-0 x2 x2 asserted) + IDSTATIC load_allocated=1 (the cc :39 static-init provider pull -- B-mirror starts 0, id==1 OBSERVABLE) + IDSEQ strict-raise + ADDIDEM std::find dup-noop + PRIVATE-reach via PUBLIC set_gadget/clear_gadget ONLY (flow.h :607 vs :360-:380) + pending-gate + survival-release arms; ZERO table/enum/sid face (U-set ZERO dbus -- the 21a PEGS/SLOTMAP faces NEVER apply, grep-asserted NEVER-fabricated)"
echo "E4 walls x4+arms: -I src ONLY rc1 api_options CHAINED cc:27->impl.h:32->flow_data.h:30->base_api.h:32 (shim 830633a1 load-bearing) / impl.h drop rc1 DIRECT (the SOLO-subrow face: cite-landed header STILL compile-load-bearing) / flow.h drop rc1 / inspector_manager.h drop rc1 (the fresh-cp face) / cc drop = cd_mpls+module+text_log SURVIVE rc0 (leaf face) / restored rc0 EVERY build / def-mirror trap rc1 + the 21a-clone graft rc1 + cross-donor rc0 arms"
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT); DEC spine BYTE-IDENT to the recon 6-step ladder (T3 semantic face: gadget-less pins NOTHING, survival fires ONLY at rebind)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H"/gate_md5_lineages.txt) distinct md5s (loop MEASURED; tracked gate.txt = 1); 28th-straight ZERO-gate face (the row RIDES 1 add_cpputest SOURCES list + a 268-L TEST_GROUP x1 / TEST( x4 suite REAL material -- CppUTest host find-0 dialect-BLOCKED, NEVER compiled, RE-PLAN LOUDLY if CppUTest ever lands); BACKBONE STAYS 10; chain echoes 21a 9e303761/42aa06fb (R_SUBS_DONE 12/9) + P1 e6328da1/dfe738fb + link4 c7f5808f/9fdfc50d + link6 e59f7a8a/d2fc5591 + erspan 7d7d3500/3ec325d7 + mpls tail b4b660e4/3066fc33 (MPLS_LINK_DONE 54/17) + ipheavy tail 857b5a10/63df50bc (IPHEAVY_DONE 121/44) BYTE-IDENT DIRECT; gre 6751d1a8 anchor live; NEXT.md pins 629/621/605/597 x3 + 573 x5 cite-only"
echo "SFD_DONE vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=0"
