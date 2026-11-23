#!/usr/bin/env bash
# rsubs_harness -- row 21a: chapter-19 P2 = THE RELOAD-SURVIVOR-SUBSCRIPTIONS
# PAIR: framework/reload_survivor_subscriptions.cc 631 L (md5 ff4b549236fceb
# 7b0ee899d6b793f87a) + framework/reload_survivor_subscriptions_impl.h 156 L
# (b437ba1cff967338b48b1b354743d64a) = 787 L (PLAN SS0 ledger, asserted EVERY
# build; the pair = ONE registry/pegs/enum/flow-pin mechanism -- impl.h drop
# KILLS the cc, SS1 measured).
# DONOR = misc9_harness REUSE clone (chapter-19 native; donor-verbatim face
# RE-MEASURED 124 non-.o THIS pass; NEVER auto-heal, the mpls/ipheavy DONOR
# DEAD law). EXACT 3 FRESH CPS (SS0): row cc + impl.h -> copy/framework/ and
# flow/flow_data.h 122 L faf93f6d AT THE GROUND PATH copy/flow/ -- the flowz
# DECOY NEVER satisfies flow/ (the mplS-row law; the decoy IS byte-ident to
# ground faf93f6d, the trap is the PATH). mid-build 124 + 3 = 127 MEASURED,
# asserted EVERY build.
# THE WITNESS FACE (SS2 re-measured): nm -C -u rsubs.o = EXACTLY 50 U-lines;
# snort residue EXACTLY 4 = get_conf CLOSED by the carried witness_conf
# 4dd91018 (link4 heredoc re-materialize) + EXACTLY-3 OWN-NEW = DataBus::
# _subscribe(const PubKey&,unsigned,DataHandler*) [the friend-unlock PRIVATE
# overload, data_bus.h:127, NEVER a pub_sub wall -- pub_sub world ZERO
# symbols in rsubs.o] + SnortConfig::get_reload_id() + WarningMessage. The
# 19a +1 witness face grows to 21a +3 (honest census, NOT carried); the
# backbone ARRAY STAYS 10 either way (symbol-vs-array, 18n law).
# THE NEVER-DOUBLE-DEFINE LAW RE-LEARNED (iph_link run1 receipt): the 3
# mirror bodies live ONLY in witness_rsubs.cc; probe.cc carries ONLY the
# policy/Inspector/DataBus-ctor scaffold mirrors (the upstream test's own
# pattern, cite test .cc :50-:58). The observables ride the witness INSIDE
# namespace snort -- the probe externs MUST ride that namespace (scratch
# face: _ZN5snort..E vs _Z1..E undefined-reference wall, measured fix).
# FACE-A = THE NOLOAD FRAMEWORK-TU SHAPE (19a precedent holds): BUILDING_SO
# grep-0 x2 + snort_plugins grep-0 x2 on BOTH ground files; the hidden table
# = rss_pegs[] 13 rows (12 named + CountType::END, cc :321-:337) + static_
# assert PAIRING (:340, COMPILE-proof only) + RssPeg hidden enum 12+Count
# (impl.h :43-:58) + rss_stats_to_pegcounts slot map (:343-:363) = table<->
# enum<->struct TRIPLE-coupling. ^LOAD / ver= / size= grep-0 EVER. The
# reset()-CARVE-OUT face: impl.h :76-:88 clears TEN fields, LEAVES active +
# registry_tracked (the 2-field carve-out; rss_reset_for_test cc :616-:617
# stores THOSE two).
# THE ZERO-GATE row (27th straight): gate-token grep-0 on the pair; the
# '47' NEXT token = the TEST( COUNT in src/framework/test/reload_survivor_
# subscriptions_test.cc 2028 L (1 TEST_GROUP) -- Cpputest material is REAL
# and this row TU RIDES TWO suite SOURCES lists (grep x2, the honest
# ride-face vs 19a's zero-ride) but CppUTest headers/libs are find-0 on this
# host (dialect BLOCKED, NEVER faked, 18j/18k precedent) -> ZERO gate
# artifacts ship; if the toolchain ever carries CppUTest the row RE-PLANS
# loud (PLAN SS3 flag). The UNIT_TEST grep 4/1 clock-seam census gets its
# OWN assert (NOT gate material, flip trips loud).
# NDEBUG posture (harness law rides the whole graph): the row TU carries
# ZERO runtime assert() arms (grep EXACTLY-0 outside static_assert/<cassert>
# -- measured ground face), so the 50-face nm census is NDEBUG-INVARIANT
# (0 __assert_fail pulls, scratch-measured); honestly recorded, NOT a +1 arm
# row like 19a's module.cc :372 face.
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness
M9=$R/tools/misc9_harness             # THE donor (19a tree, 124 face) -- REUSE clone
L4=$R/tools/link4_harness             # witness_conf heredoc home
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
C=$H/copy

# ---- ground identity (SS0: MY re-measure EXACT vs the orchestrator pins) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC/src/framework/reload_survivor_subscriptions.cc")" -eq 631
test "$(md5sum "$SRC/src/framework/reload_survivor_subscriptions.cc" | awk '{print $1}')" = "ff4b549236fce47b0ee899d6b793f87a"
test "$(wc -l < "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" -eq 156
test "$(md5sum "$SRC/src/framework/reload_survivor_subscriptions_impl.h" | awk '{print $1}')" = "b437ba1cff967338b48b1b354743d64a"
test "$(( 631 + 156 ))" -eq 787                                          # the row ledger line
test "$(wc -l < "$SRC/src/flow/flow_data.h")" -eq 122
test "$(md5sum "$SRC/src/flow/flow_data.h" | awk '{print $1}')" = "faf93f6d9ec68fcda4232bca2faf7d64"
# name-resolution face (SS0): docs 'rsubs' == the ground pair; '*rss*' find-0;
# '*rsub*' = only the time/timersub.h substring false-positive (NEVER a row)
test "$(find "$SRC/src" -iname '*rss*' | wc -l)" -eq 0
test "$(find "$SRC/src" -iname '*rsub*' | grep -v 'timersub' | wc -l)" -eq 0
test "$(find "$SRC/src" -iname '*survivor*' | grep -v 'reload_survivor_subscriptions\|survivor_flow_data' | wc -l)" -eq 0
# Rust-side PRESENCE faces (SS5: the seed pass pinned the clean landing
# ABSENT; the rs-LANDING flip face per the 19a PYPIN absence->presence
# precedent): when the row's rs home EXISTS on disk, the landmine greps pin
# ZERO collisions OUTSIDE the home + the framework/mod.rs wiring line; while
# it is ABSENT (the seed state) every grep stays EXACTLY-0.
RS_HOME=$R/src/framework/reload_survivor_subscriptions.rs
for pat in 'RssStats' 'RssPeg' 'SurvivorSubscriptions' 'rss_stats' 'DedupClass' 'reload_survivor'; do
    if [ -e "$RS_HOME" ]; then
        test "$(grep -rlE "$pat" "$R/src" --include=*.rs 2>/dev/null | grep -v "^$RS_HOME$" | grep -v "^$R/src/framework/mod.rs$" | wc -l)" -eq 0
    else
        test "$(grep -rlE "$pat" "$R/src" --include=*.rs 2>/dev/null | wc -l)" -eq 0
    fi
done
# gate-token grep-0 x2 on the pair (the zero-gate STOP face; a future suite
# NAMING the pair re-plans the row LOUDLY -- the rider face below already
# rides TWO CppUTest SOURCES lists):
for f in framework/reload_survivor_subscriptions.cc framework/reload_survivor_subscriptions_impl.h; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|CppUTest' "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'BUILDING_SO'   "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'snort_plugins' "$SRC/src/$f" || true)" -eq 0
    test "$(grep -ci daq "$SRC/src/$f" || true)" -eq 0                    # graft NON-participation x2
done
# the UNIT_TEST clock-seam census (SS3: NOT gate material -- the OWN census
# assert 4/1 EXACTLY, flip trips loud):
test "$(grep -c 'UNIT_TEST' "$SRC/src/framework/reload_survivor_subscriptions.cc")" -eq 4
test "$(grep -c 'UNIT_TEST' "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" -eq 1
# the NDEBUG face: EXACTLY 0 runtime assert() calls in the cc (only the
# :340 static_assert + the <cassert> include = 2 'assert' string hits):
test "$(grep -cE '^[[:space:]]*assert\(' "$SRC/src/framework/reload_survivor_subscriptions.cc" || true)" -eq 0
test "$(grep -c 'assert' "$SRC/src/framework/reload_survivor_subscriptions.cc")" -eq 2
test "$(grep -c '0x9e3779b97f4a7c15' "$SRC/src/framework/reload_survivor_subscriptions.cc")" -eq 2   # golden-ratio mix x2 (:123/:124)

# ---- GATE MATERIAL census (the REAL material dialect-BLOCKED: the honest
# ride-x2 face + the '47' TEST( count face; NO Catch names this row) ----
test "$(grep -c 'add_cpputest' "$SRC/src/framework/test/CMakeLists.txt")" -eq 3
test "$(grep -c 'reload_survivor_subscriptions.cc' "$SRC/src/framework/test/CMakeLists.txt")" -eq 2   # THE RIDES-TWO face (data_bus_test + rsubs_test SOURCES)
test "$(wc -l < "$SRC/src/framework/test/reload_survivor_subscriptions_test.cc")" -eq 2028
test "$(grep -c 'TEST(' "$SRC/src/framework/test/reload_survivor_subscriptions_test.cc")" -eq 47    # the NEXT '47' token = THIS case count, VERIFIED
test "$(grep -c 'TEST_GROUP' "$SRC/src/framework/test/reload_survivor_subscriptions_test.cc")" -eq 1
test "$(grep -c 'add_cpputest' "$SRC/src/main/test/CMakeLists.txt")" -eq 2                          # UNDISTURBED
test "$(grep -c 'add_catch_test' "$SRC/src/framework/CMakeLists.txt")" -eq 2                        # parameter/range ONLY (residents 16c/16j)
# the rsubs-test rider face: the test TU rides ../data_bus.cc + the row cc
# (the 3-SOURCE suite face, cite-only -- NEVER compiled HERE: dialect block)
grep -q 'SOURCES ../data_bus.cc ../reload_survivor_subscriptions.cc' "$SRC/src/framework/test/CMakeLists.txt"
# dialect census (find-0 faces, NEVER faked; host has no CppUTest headers or
# libs -- ldconfig absent on this host = the find-based face re-derived):
test "$(find /usr/include -maxdepth 1 -iname 'CppUTest*' | wc -l)" -eq 0
test "$(find /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/local/lib -maxdepth 1 -name 'libCppUTest*' 2>/dev/null | wc -l)" -eq 0
# consumer-side cites (cite-never-carry, NEVER providers here):
grep -q 'register_reload_survivor_handlers' "$SRC/src/framework/inspector.h"      # :202 opt-in hook
test "$(grep -cE 'policy_resolution_failures\.(fetch_add|store)' "$SRC/src/framework/reload_survivor_subscriptions.cc" || true)" -eq 0   # rsubs NEVER bumps the peg
grep -q 'rss_on_bus_destroyed(this);' "$SRC/src/framework/data_bus.cc"            # :82 caller (data_bus.cc)
grep -q 'rss_release(\*this);' "$SRC/src/framework/inspector.cc"                  # :61 caller (inspector.cc)
test "$(grep -c 'policy_resolution_failures' "$SRC/src/managers/inspector_manager.cc")" -ge 2       # the CONSUMER bumps live HERE (:652/:681 cite)

# ---- ground sed pins (line-exact, SS7; re-grep at row, disk wins) ----
test "$(sed -n '51p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "constexpr uint64_t slow_wait_first_ms = 5000;"
test "$(sed -n '52p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "constexpr uint64_t slow_wait_second_ms = 60000;"
test "$(sed -n '53p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "constexpr uint64_t slow_wait_repeat_ms = 300000;"
test "$(sed -n '321p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "const PegInfo rss_pegs[] ="
test "$(sed -n '337p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "    { CountType::END, nullptr, nullptr }"
test "$(sed -n '340p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "static_assert(std::size(rss_pegs) == static_cast<size_t>(RssPeg::Count) + 1,"
test "$(sed -n '420p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "            ip.dbus._subscribe(pub, eid, leased);"      # THE friend-unlock site
test "$(sed -n '616p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "    rss_stats.active.store(0, std::memory_order_relaxed);"          # the reset-carve-out pair
test "$(sed -n '617p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "    rss_stats.registry_tracked.store(0, std::memory_order_relaxed);"
test "$(sed -n '625p' "$SRC/src/framework/reload_survivor_subscriptions.cc")" = "void rss_set_elapsed_for_test(uint64_t ms)"             # THE clock-seam def (:624-:629 block -- the NEXT ':619-:624' cite DRIFT face, DISK WINS)
test "$(sed -n '32p' "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" = '#include "flow/flow_data.h"'                          # the ground-PATH include (never flowz)
test "$(sed -n '43p' "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" = "enum class RssPeg : size_t"
test "$(sed -n '91p' "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" = "extern RssStats rss_stats;"
test "$(sed -n '92p' "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" = "extern const PegInfo rss_pegs[];"
test "$(sed -n '138p' "$SRC/src/framework/reload_survivor_subscriptions_impl.h")" = "class SurvivorFlowData : public FlowData"           # decl-only (SS4 left-open: provider = survivor_flow_data.cc, P3)
grep -q 'friend class ReloadSurvivorSubscriptions;' "$SRC/src/framework/data_bus.h"                 # :127 the friend grant
grep -q 'void _subscribe(const PubKey&, unsigned evt_id, DataHandler\*);' "$SRC/src/framework/data_bus.h"                                    # :130 the mirror signature
test "$(sed -n '775p' "$SRC/src/main/snort_config.h")" = "    SO_PUBLIC static unsigned get_reload_id();"                                 # the NOT-const member face (killed mirror run1)
grep -q 'void DataBus::_subscribe(const PubKey& key, unsigned eid, DataHandler\* h)' "$SRC/src/framework/data_bus.cc"                    # :210 body-shape cite

# ---- copy tree = misc9-19a DONOR REUSE clone (the NEVER-auto-heal law;
# graft-v3 daq.h 0f7016a6 + graft-v2 daq_common.h fead0027 ride INHERITED,
# masters CITED; NO ipheavy chain -- the ext#4 97bca757/9b603f8f faces NEVER
# promoted; the harness donor is ext-churn-free PER PLAN SS6) ----
test -e "$M9/copy/config.h" -a -e "$M9/copy/framework/module.cc" || { echo "DONOR DEAD: tools/misc9_harness/copy pruned -- re-run the 19a misc9 row by hand (NEVER auto-heal from this script)"; exit 1; }
rm -rf "$C"; cp -a "$M9/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 124                          # donor face MEASURED (misc9 landing head)
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"          # graft-v3 INHERITED (head, ext-churn-free face)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"   # graft-v2 INHERITED (head)
test "$(md5sum "$D3/copy/daq.h" | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"    # MASTER CITE (never cp'd HERE)
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$C/framework/api_options.h" | awk '{print $1}')" = "830633a119c8675921e7f541f7741da1"  # the INHERITED generated-header shim (base_api.h:32 rider -- the raw-arm load-bearing face SS6)
# THE 5 project heads find-1 INHERITED + the NO-DRIFT inspector.h face:
for h in framework/data_bus.h framework/inspector.h log/messages.h main/policy.h main/snort_config.h main/snort_types.h framework/counts.h config.h; do
    test "$(find "$C" -path "*/$h" | wc -l)" -eq 1
done
test "$(md5sum "$C/framework/inspector.h" | awk '{print $1}')" = "df586e2ad090ab1bee96e7efdce26508"   # byte-ident to ground (the W-emitted get_name proof below)
test "$(md5sum "$SRC/src/framework/inspector.h" | awk '{print $1}')" = "df586e2ad090ab1bee96e7efdce26508"
# THE flowz DECOY law re-armed (mplS law via SS0): the quote TEXT flow/
# flow_data.h = find-0 PRE-cp; the decoy copy IS byte-ident faf93f6d -- the
# trap is the PATH, NEVER cp from flowz/, NEVER re-derived:
test "$(find "$C" -name 'flow_data.h' | wc -l)" -eq 1
test -e "$C/flowz/flow_data.h"
test "$(find "$C" -path '*/flow/flow_data.h' | wc -l)" -eq 0
test "$(md5sum "$C/flowz/flow_data.h" | awk '{print $1}')" = "faf93f6d9ec68fcda4232bca2faf7d64"       # decoy == ground face (measured 0-line diff)
# the 3 EXACT fresh cps (124 -> 127):
mkdir -p "$C/flow"
cp "$SRC/src/framework/reload_survivor_subscriptions.cc"    "$C/framework/reload_survivor_subscriptions.cc";    cmp -s "$C/framework/reload_survivor_subscriptions.cc"    "$SRC/src/framework/reload_survivor_subscriptions.cc"
cp "$SRC/src/framework/reload_survivor_subscriptions_impl.h" "$C/framework/reload_survivor_subscriptions_impl.h"; cmp -s "$C/framework/reload_survivor_subscriptions_impl.h" "$SRC/src/framework/reload_survivor_subscriptions_impl.h"
cp "$SRC/src/flow/flow_data.h" "$C/flow/flow_data.h";                                                        cmp -s "$C/flow/flow_data.h" "$SRC/src/flow/flow_data.h"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 127                          # mid-build 124 + 3 MEASURED
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probes pull NO codec_api)
test ! -e "$C/codecs/codec_api.cc"

GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -pthread"
# ---- PRE-CHECKS: -fsyntax-only rc0 x2 arms + .o rc0 x2 (plain + UNIT_TEST,
# the SS6 codegen faces re-run): ----
$GXX0 -fsyntax-only "$C/framework/reload_survivor_subscriptions.cc" 2> "$H/E4_syntax.txt";           test ! -s "$H/E4_syntax.txt"
$GXX0 -c "$C/framework/reload_survivor_subscriptions.cc" -o "$H/.pre_rsubs.o"    2> "$H/E4_codegen.txt";     test ! -s "$H/E4_codegen.txt"
$GXX0 -DUNIT_TEST -c "$C/framework/reload_survivor_subscriptions.cc" -o "$H/.pre_rsubs_ut.o" 2> "$H/E4_codegen_ut.txt"; test ! -s "$H/E4_codegen_ut.txt"
$GXX0 -O2 -c "$C/framework/reload_survivor_subscriptions.cc" -o "$H/.pre_rsubs_o2.o" 2> "$H/E4_codegen_o2.txt";          test ! -s "$H/E4_codegen_o2.txt"
rm -f "$H"/.pre_*.o

# ---- E4 LOCALIZATION ARMS BOTH WAYS (SS6): (a) RAW arm -I$SRC/src ONLY: rc1
# FATAL framework/api_options.h CHAINED cc:24 -> impl.h:32 -> flow_data.h:30
# -> base_api.h:32 (the generated-header wall; the donor api_options.h shim
# is load-bearing, the 19a hwloc-shape face); (b) IN-TREE walls: impl.h drop
# kills the cc DIRECT (:24); flow/flow_data.h drop kills it CHAINED (via
# impl.h:32) while the FLOWZ decoy SITS right there (the path-trap proof);
# cc drop kills NOTHING else (no donor OBJS member quotes impl.h -- grep-0
# census below, the pair-closure face); restored rc0 EVERY build. ----
GXXD="g++ -std=c++17 -DNDEBUG -O0 -w -I$SRC/src"
if $GXXD -fsyntax-only "$SRC/src/framework/reload_survivor_subscriptions.cc" 2> "$H/E4_donorsrc_rsubs.txt"; then
    echo "E4 LOCALIZATION DEAD: the cc compiled on the -I src ONLY arm -- the api_options.h generated-header wall is wrong"; exit 1
fi
grep -q "fatal error: framework/api_options.h: No such file" "$H/E4_donorsrc_rsubs.txt"
grep -q "reload_survivor_subscriptions.cc:24" "$H/E4_donorsrc_rsubs.txt"          # the chained face (grep the WHOLE receipt)
grep -q "reload_survivor_subscriptions_impl.h:32" "$H/E4_donorsrc_rsubs.txt"
grep -q "flow_data.h:30" "$H/E4_donorsrc_rsubs.txt"
mv "$C/framework/reload_survivor_subscriptions_impl.h" "$H/.e4_hold_impl.h"
if $GXX0 -fsyntax-only "$C/framework/reload_survivor_subscriptions.cc" 2> "$H/E4_noimpl_rsubs.txt"; then
    echo "E4 flip BROKE: the cc compiled WITHOUT impl.h (:24 DIRECT) -- the pair-closure face is wrong"; exit 1
fi
grep -q "fatal error: reload_survivor_subscriptions_impl.h: No such file" "$H/E4_noimpl_rsubs.txt"
mv "$H/.e4_hold_impl.h" "$C/framework/reload_survivor_subscriptions_impl.h"
mv "$C/flow/flow_data.h" "$H/.e4_hold_flow_data.h"
if $GXX0 -fsyntax-only "$C/framework/reload_survivor_subscriptions.cc" 2> "$H/E4_nofld_rsubs.txt"; then
    echo "E4 flip BROKE: flow/flow_data.h removed but the cc lived -- the flowz decoy SATISFIED flow/ (the mplS law died)"; exit 1
fi
grep -q "fatal error: flow/flow_data.h: No such file" "$H/E4_nofld_rsubs.txt"
grep -q "reload_survivor_subscriptions_impl.h:32" "$H/E4_nofld_rsubs.txt"          # CHAINED via impl.h:32
mv "$H/.e4_hold_flow_data.h" "$C/flow/flow_data.h"
# cc-drop arm: NOTHING else dies (the donor TUs NEVER quote the impl; the
# row .o is a LEAF of the donor graph -- grep census + the survivors):
test "$(grep -rl 'reload_survivor_subscriptions_impl.h' "$C" --include='*.cc' --include='*.h' | grep -v 'reload_survivor_subscriptions' | wc -l)" -eq 0
mv "$C/framework/reload_survivor_subscriptions.cc" "$H/.e4_hold_rsubs.cc"
for f in framework/module.cc log/text_log.cc; do
    $GXX0 -fsyntax-only "$C/$f" 2> "$H/E4_ccdrop_survivor.txt"; test ! -s "$H/E4_ccdrop_survivor.txt"     # donor members SURVIVE the cc drop
done
mv "$H/.e4_hold_rsubs.cc" "$C/framework/reload_survivor_subscriptions.cc"
$GXX0 -fsyntax-only "$C/framework/reload_survivor_subscriptions.cc" 2> "$H/E4_restored_rsubs.txt"; test ! -s "$H/E4_restored_rsubs.txt"

GXX="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -pthread"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C -pthread"

# ---- witness posture: WIN trio CARRIED (witness_18f ea1f79f3 + witness_conf
# 4dd91018 heredoc VERBATIM re-materialize from link4 + stubs_18d f4afd35f --
# rsubs pulls NO LogMessage so no dup-body trap) + ONE own-new witness_rsubs
# (the EXACTLY-+3 L1 face, the misc9 witness shape). ----
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
_b=$(grep -n 'witness_conf\.cc" <<.EOFWC.$' "$L4/build.sh" | head -1 | cut -d: -f1)
test -n "$_b"
_e=$(awk -v s="$_b" 'NR>s && /^EOFWC$/{print NR; exit}' "$L4/build.sh")
sed -n "$((_b+1)),$((_e-1))p" "$L4/build.sh" > "$H/witness_conf.cc"
test "$(md5sum "$H/witness_conf.cc" | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"
test "$(find "$H" -maxdepth 1 -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 1
test "$(wc -l < "$H/witness_rsubs.cc")" -eq 30
test "$(md5sum "$H/witness_rsubs.cc" | awk '{print $1}')" = "c0142f9b6384437fae54b70572f4603d"   # THE 3-mirror + observables face
test "$(grep -c 'get_reload_id' "$H/witness_conf.cc" || true)" -eq 0                             # NO dup mirror in the carried witness (the +3 own-new face)

REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"
OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- O0 compile: row .o PLAIN (FACE-A) + UNIT_TEST (DEC arm, the clock
# seam), backbone REAL .o (module from the donor-verbatim copy), witnesses,
# probes (the DEC probe compiled -DUNIT_TEST, the release/UT contrast rides
# FACE-A's plain rsubs.o + non-UT probe) ----
$GXX -c "$C/framework/reload_survivor_subscriptions.cc" -o "$C/rsubs.o"
$GXX -DUNIT_TEST -c "$C/framework/reload_survivor_subscriptions.cc" -o "$C/rsubs_ut.o"
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -DUNIT_TEST -o "$H"/probe.o
$GXX -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H/witness_conf.cc"  -o "$H/witness_conf.o"
$GXX -c "$ETH"/stubs_18d.cc   -o "$H/stubs_18d.o"
$GXX -c "$H"/witness_rsubs.cc -o "$H"/witness_rsubs.o

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row (the 27th-
# straight face; the dialect-BLOCKED note rides the header, receipts prove) ----
test ! -e "$H/gate.txt"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt|.*catch.*' || true)" -eq 0

# ---- nm per-TU U-census (the 50-face MEASURED every build, NOT carried): ----
nm -C -u "$C/rsubs.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_rsubs.txt"
test "$(wc -l < "$H/nm_U_rsubs.txt")" -eq 50
# the NDEBUG-invariance face: ZERO __assert_fail pulls (the row carries no
# runtime assert -- SS-header honest record vs the 19a +1-per-TU delta face):
test "$(grep -c '__assert_fail' "$H/nm_U_rsubs.txt" || true)" -eq 0
# the U-set delta law (SS2): PLAIN vs UNIT_TEST U-sets IDENTICAL; the UT arm
# differs ONLY by the DEFINED rss_set_elapsed_for_test:
nm -C -u "$C/rsubs_ut.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_rsubs_ut.txt"
diff "$H/nm_U_rsubs.txt" "$H/nm_U_rsubs_ut.txt" > "$H/nm_U_delta.txt" || true
test ! -s "$H/nm_U_delta.txt"
test "$(nm -C --defined-only "$C/rsubs_ut.o" | grep -c 'T snort::rss_set_elapsed_for_test')" -eq 1
test "$(nm -C --defined-only "$C/rsubs.o" | grep -c 'rss_set_elapsed_for_test' || true)" -eq 0
# the defined face: 12 T + rss_stats B + rss_pegs D (the release-arm census);
# the whole lease family LOCAL t-symbols (anon namespace, ZERO ABI exposure):
test "$(nm --defined-only "$C/rsubs.o" | awk '$2=="T"' | wc -l)" -eq 12
test "$(nm --defined-only "$C/rsubs.o" | grep -c ' B _ZN5snort9rss_statsE')" -eq 1
test "$(nm --defined-only "$C/rsubs.o" | grep -c ' D _ZN5snort8rss_pegsE')" -eq 1
test "$(nm --defined-only "$C/rsubs.o" | awk '$2=="t" && /RssLease|Registry|Dedup|DedupKey/' | wc -l)" -ge 30   # the local-identity family face (measured 59 t-faces)
# the W-emitted INLINE proof (inspector.h:284 get_name INLINE => W in the row
# .o, ZERO witness pull for survivor_name, the <unknown> arm rides get_api
# null NOT a missing symbol):
test "$(nm -C --defined-only "$C/rsubs.o" | grep -c ' W snort::Inspector::get_name() const')" -eq 1
test "$(nm -C --defined-only "$C/rsubs.o" | grep -c ' W snort::Inspector::get_api()')" -eq 1
# the LEFT-OPEN seam proofs (SS4, cite-preserve NEVER patch over):
test "$(nm "$C/rsubs.o" | grep -c SurvivorFlowData || true)" -eq 0                       # decl-only rides the header; provider = survivor_flow_data.cc P3
test "$(nm -C -u "$C/rsubs.o" | grep -c 'ReloadTracker\|pub_sub\|Subscriber' || true)" -eq 0   # NO reload-machinery/pub_sub pull EVER
# the snort-family residue census: EXACTLY 4 (get_conf + the +3 own-new):
nm -C -u "$C/rsubs.o" | grep ' U ' | grep 'snort::' > "$H/rsubs_residue_dem.txt" || true
test "$(wc -l < "$H/rsubs_residue_dem.txt")" -eq 4
grep -q 'SnortConfig::get_conf' "$H/rsubs_residue_dem.txt"
grep -q 'get_reload_id' "$H/rsubs_residue_dem.txt"
grep -q 'DataBus::_subscribe' "$H/rsubs_residue_dem.txt"
grep -q 'WarningMessage' "$H/rsubs_residue_dem.txt"
# the -pthread/sched-YIELD face (SS2: std::mutex over pthread, NO
# THREAD_LOCAL -- the 17l contrast):
test "$(grep -c 'pthread_mutex' "$H/nm_U_rsubs.txt")" -eq 2
test "$(grep -c 'sched_yield' "$H/nm_U_rsubs.txt")" -eq 1

# ---- THE +3 L1 CENSUS PROVEN: (row .o + 7-object backbone + WIN trio +
# bare main) = EXACTLY-3 distinct own-new undefined, and the FULL link rc0
# with witness_rsubs (the SS2 CLEAN-chain face re-measured EVERY build): ----
echo 'int main(){return 0;}' > "$H/.l1_main.cc"
$GXX -c "$H/.l1_main.cc" -o "$H/.l1_main.o"
if $GXX "$C/rsubs_ut.o" $OBJS "$H/.l1_main.o" $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: rsubs linked WITHOUT witness_rsubs -- the +3 L1 delta is wrong"; exit 1
fi
grep -c 'undefined reference' "$H/L1_link_face.txt" > /dev/null
grep -oE "undefined reference to \`[^']*" "$H/L1_link_face.txt" | sed "s/undefined reference to \`//" | c++filt | sort -u > "$H/L1_undefined.txt"
test "$(wc -l < "$H/L1_undefined.txt")" -eq 3
test "x$(sed -n '1p' "$H/L1_undefined.txt")" = "xsnort::DataBus::_subscribe(snort::PubKey const&, unsigned int, snort::DataHandler*)"
test "x$(sed -n '2p' "$H/L1_undefined.txt")" = "xsnort::SnortConfig::get_reload_id()"
test "x$(sed -n '3p' "$H/L1_undefined.txt")" = "xsnort::WarningMessage(char const*, ...)"
$GXX "$C/rsubs_ut.o" $OBJS "$H/.l1_main.o" "$H/witness_rsubs.o" $WIN -o "$H/.L1_probe" && echo full-link-rc0 > "$H/L1_full_link.txt"
test -s "$H/L1_full_link.txt"
rm -f "$H/.L1_probe"
# the witness OWN arm: EXACTLY-3 T mirrors + the 4 observables (the symbol
# face the backbone ARRAY NEVER grows for -- symbol-vs-array, B10 stays 10):
test "$(nm --defined-only "$H/witness_rsubs.o" | grep -c ' T ')" -eq 3
test "$(nm --defined-only "$H/witness_rsubs.o" | grep -c 'wrsubscribe_calls\|wrwarn_calls\|wr_last_warn\|wr_last_handler')" -eq 4
# the carried get_conf T face (witness_conf closes residue #4, NEVER doubled):
test "$(nm -C --defined-only "$H/witness_conf.o" | grep -c 'T snort::SnortConfig::get_conf()')" -eq 1

# ---- probe links: FULL graph (row .o + OBJS + WIN + witness_rsubs +
# -pthread; the glibc-2.34 host lives WITHOUT it -- the honest face recorded
# in the tail line. DEC rides rsubs_ut.o probe.o; FACE-A rides PLAIN rsubs.o
# + non-UT probe_faceA.o = the release/no-clock-seam CONTRAST pairing) ----
$GXX "$C/rsubs_ut.o" $OBJS "$H"/probe.o      "$H/witness_rsubs.o" $WIN -pthread -o "$H"/probe
$GXX "$C/rsubs.o"    $OBJS "$H"/probe_faceA.o "$H/witness_rsubs.o" $WIN -pthread -o "$H"/probe_faceA
test "$(nm -C "$H"/probe "$H"/probe_faceA | grep -c 'Catch::' || true)" -eq 0        # NO Catch face ANYWHERE
test "$(nm -u "$H"/probe.o "$H"/probe_faceA.o | grep -c 'load_codecs' || true)" -eq 0  # ZERO codec_api pull
test "$(nm -C "$H"/probe | grep -c 'T snort::SFDAQ::get_local_instance()' || true)" -eq 0   # misc3 witness NEVER linked
test "$(nm -C "$H"/probe | grep -c 'SnortConfig::get_reload_id' )" -ge 1              # the own mirror rides the DEC binary
grep -q 'wrsubscribe_calls' <<< "$(nm -C "$H"/probe "$H"/probe_faceA)"               # the OWN observables ride BOTH binaries (misc9_prompt_calls precedent)

# ---- O2 twins (byte-ident vectors law) ----
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
$GXXA -c "$C/framework/reload_survivor_subscriptions.cc" -o "$O2/rsubs.o"
$GXXA -DUNIT_TEST -c "$C/framework/reload_survivor_subscriptions.cc" -o "$O2/rsubs_ut.o"
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -DUNIT_TEST -c "$H"/probe.cc -o "$O2"/probe.o
$GXXA -c "$H"/probe_faceA.cc -o "$O2"/probe_faceA.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H/witness_conf.cc" -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc -o "$O2"/stubs_18d.o;     $GXXA -c "$H"/witness_rsubs.cc -o "$O2"/witness_rsubs.o
OB2="$O2/codec.o $O2/ip.o $O2/sf_ip.o $O2/util_cstring.o $O2/util.o $O2/module.o $O2/text_log.o"
$GXXA "$O2/rsubs_ut.o" $OB2 "$O2"/probe.o      "$O2/witness_rsubs.o" "$O2/witness_18f.o" "$O2/witness_conf.o" "$O2/stubs_18d.o" -pthread -o "$H"/probe_O2
$GXXA "$O2/rsubs.o"    $OB2 "$O2"/probe_faceA.o "$O2/witness_rsubs.o" "$O2/witness_18f.o" "$O2/witness_conf.o" "$O2/stubs_18d.o" -pthread -o "$H"/probe_faceA_O2

timeout 60 "$H"/probe        > "$H"/vectors_O0.txt      || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_O2     > "$H"/vectors_O2.txt      || { echo PROBE_FAIL DEC O2; exit 1; }
timeout 60 "$H"/probe_faceA  > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_faceA_O2 > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
[ -e "$H"/vectors.txt ]        && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt        || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ]  && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 law: EVERY state call stored to a VAR before printf (the pilot T6
# stale-load face re-earns the rule at this row, build.sh grep-pinned; the
# grep rides CODE lines only, NOT the law's own comment): ----
test "$(grep -c '^\s*printf.*rss_' "$H"/probe.cc || true)" -eq 0
test "$(grep -c ' = rss_' "$H"/probe.cc)" -ge 10
# all-decimal hygiene:
test "$(grep -c '0x[0-9a-f]' "$H"/vectors_O0.txt || true)" -eq 0
test "$(grep -c '0x[0-9a-f]' "$H"/vectors_faceA_O0.txt || true)" -eq 0

# ---- known-answer ladders: FIRST-RUN SEED then drift-refuse (18j+ lineage) ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi

# DEC ladder greps (the MEASURED 12-line T0-T9 face -- every arm rides a
# ground line, NEVER air; SS7 cross-check against the recon pilot face: the
# vectors are BYTE-IDENT to the scratch flow_O0.txt ladder, md5 pinned):
grep -q '^T0 sub=0 warn=0 inst=0 act=0 track=0$' "$V"
grep -q '^T1 sub=1 inst=1 act=1 track=1 dedup=0$' "$V"          # subscribe face (:420 friend-unlock + :433-:436 pegs)
grep -q '^T2 samedup sub=1 inst=1 conflicts=0$' "$V"            # same-tuple dup -> factory SKIPPED (:392-:397)
grep -q '^T3 misdup conflicts=1 warn=1 sub=1$' "$V"             # MISMATCH tuple -> conflict + warn (:309-:310 -> :373-:378)
grep -q '^T4 stripped=1 act=0 bus_destroyed=1$' "$V"            # bus-stripe (:536-:568 remove_if face)
grep -q '^T5 views=1 npid=1 ipid=1 list_returned=1$' "$V"       # survivor view (policy user_policy_id = 1 default faces)
grep -q '^T6 release-during-reconcile=0 deferrals=1$' "$V"      # the reconcile GATE deferral (:463-:467 + :281-:300)
grep -q '^T7 release-after=1 retired=1 track=0 warn=1$' "$V"    # end_reconcile -> release ok (:599-:607)
grep -q '^T8a quiescent-idle=1 warn=0 slow=0$' "$V"             # quiescent-idle, NO warn (:498-:534)
grep -q '^T8b quiescent=1 slow=1 warn=1$' "$V"                  # CLOCK SEAM 59999 tier-1 (:51-:53 + :625) -> EXACTLY-1 warn + slow_drains
grep -q '^T8c label-unknown=1 key-k5=1 reloadid7=1$' "$V"       # '<unknown>' + key 'k5' + 'reload id 7' INSIDE the captured warn (:214-:221 + witness get_reload_id()->7)
grep -q '^T9 release=1 skips=1 tracked=0$' "$V"                 # dead-handler skip (:187-:197)
test "$(wc -l < "$V")" -eq 12
if [ -s /opt/data/cache/scratch/row21a/flow_O0.txt ]; then
    cmp -s "$V" /opt/data/cache/scratch/row21a/flow_O0.txt || { echo "DEC ladder DRIFTS vs the recon cross-donor pilot ladder"; exit 1; }   # cross-pass byte-ident (scratch receipt tolerant if pruned)
fi
# FACE-A ladders (the NOLOAD head + the table-enum-slotmap triple):
grep -q '^NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2$' "$FA"
grep -q '^PEGS rows=12 sentinel=1 count=12$' "$FA"
grep -q '^PEGS walk named=12 end-at=12$' "$FA"                  # the END sentinel STOP (counts.h ordinal 0 walk)
grep -q '^PEGN 0=rss_survivors_installed 7=rss_survivors_active 11=rss_reconcile_deferrals sent-name-null=1$' "$FA"
grep -q '^PEGTYPE live=1 2 2 1 0$' "$FA"                        # SUM NOW NOW SUM END ordinals (:323/:331/:332/:335/:337)
grep -q '^SLOTMAP installed@0=1 active@7=8 tracked@8=9 deferrals@11=12$' "$FA"   # the RssPeg slot-map walk (:343-:363)
grep -q '^DEDUP same=0 pub-mismatch=1 eid-mismatch=1$' "$FA"    # the 3-arm truth table (:365-:371)
grep -q '^CARVE installed=0 slow=0 deferrals=0 active=3 tracked=2$' "$FA"         # reset() LEAVES active+registry_tracked (impl.h :76-:88)
test "$(grep -c '^LOAD' "$FA" || true)" -eq 0                    # NO codec LOAD EVER (framework TU)
test "$(grep -c 'ver=\|size=' "$FA" || true)" -eq 0              # NO CodecApi face EVER
test "$(grep -c '0x' "$FA" || true)" -eq 0
test "$(grep -c 'cd_\|CodecApi\|mpls\|vlan\|daq\|tunnel' "$V" || true)" -eq 0
test "$(grep -c 'cd_\|CodecApi\|mpls\|vlan\|daq\|tunnel' "$FA" || true)" -eq 0   # ZERO codec/tunnel face ANYWHERE

python3 - "$V" "$FA" <<'PYPIN'
# BOTH-WAYS pins: the enum/table walk rides the GROUND pair; the vectors re-
# echo the SAME faces (never air). The golden-ratio constant x2, the RssPeg
# enumeration order == rss_pegs[] row order == RssStats field order = the
# TRIPLE-coupling contract the static_assert (:340) guards.
import re, sys
cc = open("/opt/data/snort3-src/src/framework/reload_survivor_subscriptions.cc").read()
ih = open("/opt/data/snort3-src/src/framework/reload_survivor_subscriptions_impl.h").read()
V, FA = open(sys.argv[1]).read(), open(sys.argv[2]).read()
# enum order == table order == struct order:
en = re.findall(r'^\s{4}(Installed|Retired|BusDestroyed|PolicyResolutionFailures|ListReturned|Stripped|DeadHandlerSkips|Active|RegistryTracked|DedupConflicts|SlowDrains|ReconcileDeferrals|Count)\b', ih, re.M)
assert en == ["Installed","Retired","BusDestroyed","PolicyResolutionFailures","ListReturned","Stripped","DeadHandlerSkips","Active","RegistryTracked","DedupConflicts","SlowDrains","ReconcileDeferrals","Count"], en
names = re.findall(r'\{ CountType::(SUM|NOW|END), (nullptr|"[a-z_]+")', cc)
assert len(names) == 13 and names[-1] == ("END", "nullptr"), names
assert [t for t, n in names] == ["SUM","SUM","SUM","SUM","SUM","SUM","SUM","NOW","NOW","SUM","SUM","SUM","END"], names
assert [n[1:-1] for t, n in names[:-1]] == ["rss_survivors_installed","rss_release_retired","rss_bus_destroyed","rss_policy_resolve_fail","rss_list_returned","rss_bus_stripped","rss_dead_pub_skips","rss_survivors_active","rss_registry_tracked","rss_dedup_conflicts","rss_slow_drains","rss_reconcile_deferrals"], names
assert cc.count("0x9e3779b97f4a7c15") == 2
# the reset-carve-out ground face: 10 stores, active/registry_tracked NEVER in reset():
rb = re.search(r'void reset\(\)\s*\{(.*?)\n    \}', ih, re.S).group(1)
assert rb.count(".store(0") == 10 and "active.store" not in rb and "registry_tracked.store" not in rb
assert "rss_stats.active.store(0" in cc and "rss_stats.registry_tracked.store(0" in cc   # :616-:617 the SAME two, stored by rss_reset_for_test
# vectors-side faces re-asserted against the ground walk:
assert "rss_survivors_installed" in V or "rss_survivors_installed" in FA
assert FA.count("PEGS") >= 2 and "count=12" in FA
# the warn ladder constants ride the vectors face:
assert "59999" not in V and "slow=1" in V          # the tier-1 face printed, the ms literal NEVER leaks
assert cc.index("slow_wait_first_ms = 5000") < cc.index("slow_wait_second_ms = 60000") < cc.index("slow_wait_repeat_ms = 300000")
# warn-string pieces the T8c substrings ride (cc :214-:221 face):
assert "'<unknown>'" in cc.replace("survivor_name", "X") or '"<unknown>"' in cc
for lit in ("key '%s'", "reload id %u", "handler '%s' "):
    assert lit in cc, lit
# the doc face: impl.h:42 order law quoted:
assert "order must match RssStats and rss_pegs[] exactly" in ih
# NEXT.md cargo CITE face ONLY (NEVER edited; the seeded 621/605/597 x3):
nx = open("/opt/data/snort3-rust/NEXT.md").read()
assert nx.count("621 tests green / 0 FAILED") == 3 and nx.count("605 tests green / 0 FAILED") == 3
assert nx.count("597 tests green / 0 FAILED") == 3 and "573 tests green" in nx
PYPIN

# ---- measured first-run face PINS (SEED PASS output, drift refuses EVERY
# build; vectors BYTE-IDENT to the recon pilot ladder 9e303761 face): ----
test "$(wc -l < "$H"/vectors.txt)" -eq 12
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 9
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "9e303761c021d00ea672a493544e07af"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "42aa06fb4c55adfa50e96d1f715d997e"
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt   # receipt (ignored)

# ---- TAMPER ARM (first-run-seed -> DRIFT-THEN-REFUSE law, the row's OWN
# face per the vectors contract): a ONE-BYTE flip of the pinned vectors.txt
# MUST trip the drift-cmp rc1 when re-checked against the fresh run, and the
# byte-exact restore MUST land back on the pinned md5 (the tamper NEVER
# survives the build): ----
cp "$H"/vectors.txt "$H"/.vectors_pristine
sed -i '7s/deferrals=1/deferrals=9/' "$H"/vectors.txt                  # the ONE-byte T6 flip (line 7 of the 12-line ladder)
cmp -s "$H"/vectors.txt "$H"/vectors_O0.txt && { echo "TAMPER ARM DEAD: flipped vectors.txt still matches the fresh O0 run"; exit 1; }
cp "$H"/.vectors_pristine "$H"/vectors.txt
cmp -s "$H"/vectors.txt "$H"/vectors_O0.txt || { echo "TAMPER RESTORE DEAD: restored vectors.txt no longer matches the fresh run"; exit 1; }
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')" = "9e303761c021d00ea672a493544e07af"     # restored EXACT
rm -f "$H"/.vectors_pristine

# ---- graft ladder TAIL re-assert (head was pinned at clone; NEVER promoted,
# NEVER re-authored; the ipheavy ext#4 97bca757/9b603f8f copy-LOCAL faces ride
# ONLY as ipheavy's heredocs -- NEVER here, donor chain = misc9, ext-churn-
# free PLAN face): ----
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"

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

# ---- BACKBONE-10 census STAYS EXACTLY 10 (the +3-witness is a ROW symbol
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
# TWO-LINEAGE DIRECT echoes (byte-ident pins; the IMMEDIATE donor misc9-19a +
# the chain faces + THE FROZEN TAILS per the orchestrator law):
test "$(md5sum "$M9"/vectors.txt | awk '{print $1}')" = "e6328da1f3188df9754b9e45d74897db"
test "$(md5sum "$M9"/vectors_faceA.txt | awk '{print $1}')" = "dfe738fb8b4200368332ba73b81a4e96"
test "$(md5sum "$L4"/vectors.txt | awk '{print $1}')" = "c7f5808fa326b7831603813c16a3b01e"
test "$(md5sum "$L4"/vectors_faceA.txt | awk '{print $1}')" = "9fdfc50da8fee22b473028f1f9b29c12"
test "$(md5sum "$R"/tools/link6_harness/vectors.txt | awk '{print $1}')" = "e59f7a8a70d172261dcb847dcfdcb36a"
test "$(md5sum "$R"/tools/link6_harness/vectors_faceA.txt | awk '{print $1}')" = "d2fc5591bc45c1787fcee7393675a3d8"
test "$(md5sum "$R"/tools/erspan_harness/vectors.txt | awk '{print $1}')" = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$R"/tools/erspan_harness/vectors_faceA.txt | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"
test "$(md5sum "$R"/tools/mpls_harness/vectors.txt | awk '{print $1}')" = "b4b660e448703b603755a0049c6a2052"       # THE mpls tail face
test "$(md5sum "$R"/tools/mpls_harness/vectors_faceA.txt | awk '{print $1}')" = "3066fc335fb21777891271b9c7b152c5"
grep -q 'MPLS_LINK_DONE vectors=' "$R"/tools/mpls_harness/build.sh                           # the frozen tail-line shape
test "$(wc -l < "$R"/tools/mpls_harness/vectors.txt)" -eq 54 && test "$(wc -l < "$R"/tools/mpls_harness/vectors_faceA.txt)" -eq 17   # the MEASURED 54/17 tail face
test "$(md5sum "$R"/tools/ipheavy_harness/vectors.txt | awk '{print $1}')" = "857b5a100480114085b45a392ab713bf"   # THE ipheavy tail face
test "$(md5sum "$R"/tools/ipheavy_harness/vectors_faceA.txt | awk '{print $1}')" = "63df50bc57b7d15d95c21bdfcd492fce"
grep -q 'IPHEAVY_DONE vectors=' "$R"/tools/ipheavy_harness/build.sh                          # the frozen tail-line shape
test "$(wc -l < "$R"/tools/ipheavy_harness/vectors.txt)" -eq 121 && test "$(wc -l < "$R"/tools/ipheavy_harness/vectors_faceA.txt)" -eq 44   # the MEASURED 121/44 tail face
grep -q 'MPLS_LINK_DONE' "$R"/tools/ipheavy_harness/build.sh                                      # the ipheavy echo of mpls (lineage legible)
# gre GATE anchor (the positive-gate CONTRAST face for the ZERO-gate pin):
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh

# ---- TWO-LINEAGE gate census (MEASURED; THIS row ships ZERO gate faces --
# the 25/9/17/1 face UNDISTURBED, the 27th straight zero-gate row): ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 25
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 17
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                       # honest tracked face: gre's ONLY
# name-pin census (collision fires LOUDLY):
test "$(ls -d "$R"/tools/reload_survivor*_harness "$R"/tools/survivor*_harness "$R"/tools/rss_harness 2>/dev/null | wc -l)" -eq 0
test "$(find "$R"/tools -maxdepth 1 -iname '*rsubs*' | wc -l)" -eq 1          # THIS dir only
# the ONE tolerated tools-wide rsubs mention OUTSIDE this dir (the misc9:42
# dialect-census cite face, NEVER edited; count pinned EXACTLY-1):
test "$(grep -rl 'rsubs' "$R"/tools/*/build.sh | grep -v "$H/build.sh" | wc -l)" -eq 1
grep -q 'mp_data_bus/rsubs/thread/distill' "$M9/build.sh"
test "$(grep -c 'rsubs' "$M9/build.sh")" -eq 1
# NEXT.md cargo CITE faces ONLY (NEVER edit; the pinned x3 faces + presence):
test "$(grep -c '621 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '605 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '597 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
grep -q '573 tests green' "$R/NEXT.md"

# ---- STAGEABLES echo + .gitignore PROOF (the NESTED-INSTRUMENT face; the
# root .gitignore NEVER touched; the dir FULLY ?? this pass). NON-ignored
# face = the 8 stageables (PLAN §8 misc9 shape): PLAN build.sh probe.cc
# probe_faceA.cc vectors.txt vectors_faceA.txt witness_rsubs.cc .gitignore.
# STATE-AWARE DUAL-FACE GUARD (the ipheavy 8b9882a ZERO-LEAK law): pre-commit
# = 8 UNTRACKED faces; post-commit = 8 TRACKED faces, untracked EMPTY ----
untracked=$(git -C "$R" ls-files --others --exclude-standard tools/rsubs_harness | sort)
tracked=$(git -C "$R" ls-files tools/rsubs_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 8
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_rsubs.cc .gitignore; do
    echo "$face" | grep -q "tools/rsubs_harness/$f$"
done
test "$(echo "$face" | grep -c 'witness_rsubs')" -eq 1
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/rsubs.o copy/rsubs_ut.o copy/flow/flow_data.h copy/framework/reload_survivor_subscriptions.cc copy/daq.h copy/flowz/flow_data.h o2/rsubs.o probe probe_O2 probe_faceA probe_faceA_O2 probe.o probe_faceA.o witness_rsubs.o witness_conf.o witness_18f.o stubs_18d.o witness_conf.cc vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt nm_U_rsubs.txt nm_U_rsubs_ut.txt nm_U_delta.txt rsubs_residue_dem.txt E4_syntax.txt E4_codegen.txt E4_codegen_ut.txt E4_codegen_o2.txt E4_donorsrc_rsubs.txt E4_noimpl_rsubs.txt E4_nofld_rsubs.txt E4_restored_rsubs.txt E4_ccdrop_survivor.txt L1_link_face.txt L1_undefined.txt L1_full_link.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt .l1_main.cc .l1_main.o; do
    git -C "$R" check-ignore -q "tools/rsubs_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/rsubs_harness/$f NOT ignored"; exit 1; }
done
# the stageables NOT-ignored proofs:
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_rsubs.cc .gitignore; do
    git -C "$R" check-ignore -q "tools/rsubs_harness/$f" && { echo "WRONGLY IGNORED: $f"; exit 1; } || true
done
if git -C "$R" ls-files --error-unmatch "tools/rsubs_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/rsubs_harness/" | wc -l)" -eq 8
    test -z "$(git -C "$R" ls-files tools/rsubs_harness | grep -vE 'PLAN\.md|build\.sh|probe\.cc|probe_faceA\.cc|vectors\.txt|vectors_faceA\.txt|witness_rsubs\.cc|\.gitignore')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard tools/rsubs_harness)"   # ZERO-LEAK post-commit face
else
    git -C "$R" status --porcelain | grep -qx '?? tools/rsubs_harness/'
    test "$(git -C "$R" ls-files --others --exclude-standard tools/rsubs_harness | wc -l)" -eq 8
fi
# no STAGED churn: index EMPTY (the C-side row stages NOTHING from build.sh).
# The SEED-pass zero-tracked-churn face is FLIPPED by the rs landing (PLAN
# SS5 + the 19a precedent face): the row's OWN tracked-MODIFIED face is
# EXACTLY src/framework/mod.rs (the ONE wiring line) + the two doc files
# (ZERO churn of any other kind, NEVER pins own-HEAD):
test -z "$(git -C "$R" diff --name-only --cached)"
test "$(git -C "$R" status --porcelain | grep -v '^??' | grep -vcE ' M "?(src/framework/mod\.rs|PORTING_PLAN\.md|KNOWN DEVIATIONS\.md)"?$')" -eq 0   # the KNOWN-DEVIATIONS name rides the QUOTED porcelain face (space in name)
# SINGLE-TENANT census (orchestrator law, disk re-checked EVERY build): the
# ONLY tools/ dirty face = THIS row's ?? dir:
dirtyother=$(git -C "$R" status --porcelain tools | grep -vE '^\?\? tools/rsubs_harness/' || true)
test -z "$dirtyother"

echo "row-TU nm census (MEASURED, never typed): nm_U=50 NDEBUG-INVARIANT (0 __assert_fail pulls -- the row carries ZERO runtime assert arms, honest NON-delta vs 19a's +1 face); rsubs.o defined = 12 T + rss_stats B + rss_pegs D; lease/registry/dedup family LOCAL t-only ('$(nm --defined-only "$C/rsubs.o" | awk "\$2==\"t\"" | wc -l)' t-faces, ZERO ABI exposure); get_name/get_api W-emitted INLINE (inspector.h:284 NO-DRIFT df586e2a copy, ZERO witness pull); SurvivorFlowData nm-pull EXACTLY-0 = LEFT-OPEN P3 decl-only face"
echo "witness posture: L1 CENSUS EXACTLY-3 own-new (DataBus::_subscribe PubKey friend-unlock + SnortConfig::get_reload_id + WarningMessage) => ONE own witness_rsubs.cc 30L (md5 c0142f9b); get_conf closes on the carried witness_conf 4dd91018 heredoc; pub_sub/reload_tracker ZERO pulls; 19a +1 grows to 21a +3 HONEST census; backbone STAYS $(wc -l < "$H"/backbone10.txt) (symbol-vs-array); link WITHOUT -pthread ALSO rc0 on this host (glibc 2.34 merged -- harness passes -pthread per ground test CMakeLists face)"
echo "cp face: misc9 donor VERBATIM 124 + 3 EXACT cps = 127 mid-build asserted (row cc + impl.h -> copy/framework/, flow/flow_data.h faf93f6d AT THE GROUND PATH; the flowz decoy IS byte-ident faf93f6d but NEVER satisfies flow/ -- E4_nofld PROVES the path-trap CHAINED wall rc1 with the decoy sitting right there)"
echo "FACE-A: NOLOAD head (BUILDING_SO/snort_plugins grep-0 x2 x2 asserted) + rss_pegs 12+END census + PEGTYPE ordinals (SUM=1 NOW=2 END=0 counts.h walk) + SLOTMAP triple-coupling walk + DEDUP 3-arm + reset()-CARVE-OUT (active+registry_tracked SURVIVE); static_assert :340 ships as COMPILE-proof (the .o EXISTS); UNIT_TEST census EXACTLY cc4/impl1 (clock-seam arms, NOT gate material)"
echo "E4 both ways: -I src ONLY rc1 framework/api_options.h CHAINED cc:24->impl.h:32->flow_data.h:30->base_api.h:32 (generated-header wall, donor shim 830633a1 load-bearing) / impl.h drop rc1 DIRECT / flow/flow_data.h drop rc1 CHAINED (decoy fails, mplS law) / cc drop = donor members SURVIVE rc0 (leaf face) / restored rc0 EVERY build"
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT); DEC ladder BYTE-IDENT to the recon cross-donor pilot face 9e303761 (12-line T0-T9, cross-pass invariance receipt)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H"/gate_md5_lineages.txt) distinct md5s (loop MEASURED; tracked gate.txt = 1); 27th-straight ZERO-gate face (the row RIDES TWO CppUTest SOURCES lists + rides a 2028-L 47-TEST( suite REAL material -- dialect-BLOCKED is the ONLY reason for zero-gate, RE-PLAN LOUDLY if CppUTest ever lands); BACKBONE STAYS 10; chain echoes misc9 e6328da1/dfe738fb + link4 c7f5808f/9fdfc50d + link6 e59f7a8a/d2fc5591 + erspan 7d7d3500/3ec325d7 + mpls tail b4b660e4/3066fc33 (MPLS_LINK_DONE 54/17) + ipheavy tail 857b5a10/63df50bc (IPHEAVY_DONE 121/44) BYTE-IDENT DIRECT; gre 6751d1a8 anchor live"
echo "R_SUBS_DONE vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=0"
