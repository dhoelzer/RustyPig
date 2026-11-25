#!/usr/bin/env bash
# ---- ROW 23e: THE SECOND REAL GATE ROW — packet_io/packet_constraints.cc
# 331 L (md5 cb7b3584d08a22e01ae70d7b0b748124) + packet_constraints.h 76 L
# (md5 447e814a551709a99ffa165e60bb7a41) @ fe29cbe, FRESH cps + cmp-proved
# EVERY build. THE GATE FACE: the cc carries its OWN in-TU Catch block
# (#ifdef UNIT_TEST :143; catch include :145 -- EXACTLY-1, snort_catch.h
# pulls catch.hpp; flow.h :147) = EXACTLY-3 TEST_CASE "[framework]" faces
# (:149 comparison / :205 matching / :297 flow matching), 13 CHECK legs.
# THE RUNNER SHAPE LAW RE-MEASURED HONEST AT THIS ROW (the E10 face of
# 22a re-armed, NOT re-assumed): this row's tests touch NO init()-filled
# file-static (PacketConstraints is a pure value; the 22a snort.cc:109
# init-order SEGV law NEVER fires HERE -- the CATCH_CONFIG_MAIN twin link
# ran GREEN, measured e10_main_twin.txt rc=0), YET THE TRACKED POSTURE
# STAYS CATCH_CONFIG_RUNNER (the 22a template: upstream's own runner IS
# CATCH_CONFIG_RUNNER, src/catch/unit_test.cc :26 face-pinned; the
# default filter "[framework]" rides the ground tag face). The gate.txt
# posture COPY-LOCAL UNTRACKED exactly like tc -- the TRACKED gate.txt
# face STAYS gre's ONLY (tracked count 1).
# THE CENSUS FLIP (THE 22a law RE-ARMED, honest): landing THIS gate flips
# the WALKED on-disk gate.txt census 26->27 and the distinct-md5 lineage
# face 18->19 (this row's tail). EVERY fresh-chain harness build.sh + the
# sfd parity twin hardcode those faces: rider-flipped IN THIS COMMIT with
# sanctioned inline comments (the 62d6fac precedent applied COMPLETELY --
# the rs-subs-lineage harness carried a STALE 20a-era 25/17 face since the
# GREEN only because it never re-ran; flipped forward HERE, honestly
# annotated). The legacy 9 x 4826fc22 holders + the gre 6751d1a8 anchor
# + the OTHER 25 gate.txt ARTIFACTS stay byte-UNTOUCHED (never re-run,
# never re-written -- the walked census counts DISK faces, not fresh runs).
# THE E4 WALL LADDER BOTH WAYS (the 23d donor-eraser law re-cloned): (1)
# the FRESH pair vs the ipheavy ext#4 DONOR daq heads DIES with EXACTLY-1
# fatal class face: DAQ_PktHdr_t has-no-member 'tenant_id' (cc :115 --
# the 22b PKTH wall RE-ARMS at THIS row's line; donor daq_common.h
# 9b603f8f rides NO tenant_id) -- the flipped-assert receipt E4_donor.txt;
# (2) the REAL-SDK re-cite (the 23a law: /opt/data/libdaq @ c8d4083,
# daq_common.h 28789a3d, REAL DAQ_PktHdr_t 56B tenant_id@48) swaps SILENT
# rc0. Fresh-cp DECL riders (the 23c precedent): flow.h/flow_key.h/
# flow_data.h/flow_stash.h/packet.h/layer.h/ipv4.h/ip.h/sf_ip.h/
# decode_data.h/messages.h/util.h/snort_config.h -- ALL already BYTE-IDENT
# in the donor (md5-pinned vs ground EVERY build; the stale-DONOR face =
# ZERO drift here, the honest opposite of 22a's trap) + the pc pair itself
# is find-0 in the donor (fcapi/fpolicy/finspect copy trees ride the
# BYTE-EXACT h -- cite faces, the ipheavy donor rides NEITHER).
# THE flow.h:541 static_assert (MAX_DAQ_VERDICT == 6?) rides INERT: the
# REAL daq_common.h on the include path carries the MAX_DAQ_VERDICT enum
# CONSTANT (:321) -- the 23c law re-rides by the re-cite; the graft-face
# check (ext#4 9b603f8f has NO MAX_DAQ_VERDICT) stays cite-only.
# LINK SHAPE (E9 ONE-FACE + one-home law): gate link = pcgate_gate_main.o +
# pc_gateut.o (the -DUNIT_TEST .o, the ONLY Catch-bearing face -- Catch's
# static state EXACTLY-1 home, the tc law) + the REAL donors (sf_ip.o
# fresh-cp REAL body) + the fresh utility cps (ip.cc/util.cc/
# util_cstring.cc REAL bodies, donor-resident heads byte-EXACT -- the
# real-home law: snort_strdup util.cc :119, SnortSnprintf util_cstring.cc
# -- NEVER mirrored) + the carried witness_conf 4dd91018 extraction with
# the 23c noreturn jump rider (NEVER doubled, FatalError count EXACTLY-1)
# + witness_pcgate.cc OWN-9 (the scaffolding mirrors: Packet ctor/dtor +
# the Flow ctor/dtor + the EXACTLY-2 FlowDataStore-dtor/FlowStash-reset
# residuals + the get_inner_ip6_frag pull + the ErrorMessage/LogMessage
# pair the carried family nm-proved it NEVER defines). The E9 dup twin
# (the 3 row-body fns + the 2 dtors) flipped-asserts: co-link pc.o +
# pc_gateut.o DIES with EXACTLY-6 'multiple definition' lines (the plain
# .o beside the gateut .o -- the Catch-in-TU + plain co-link census at
# THIS row; and the twin-beside-pc.o leg MEASURED 6 too: the copy-ctor +
# operator= ride too -- the honest 6-face row-body family).
# ZERO graft, ZERO synthetic header ANYWHERE: the row speaks REAL SDK.
# vectors: DEC 20 L (P0-P12 the value ladder through the REAL pc.o:
# NSDMI/copy/assign/self-assign + the operator== mask ladder + the
# packet_match arms the gate NEVER takes (match=false, the no-IP TENANT-
# only TRUE face -- TENANT ABSENT from the :102 five-bit set, the two-
# order swapped OR, the tenant miss/hit/anonymous-skip) + F0-F5 the
# flow_match arms (the :129 key fallback, session-wins, :123 match=false,
# the SINGLE-ORDER asymmetry F5=0 vs the P9=1 two-order face)). FACE-A
# 7 L: the SetBits six decimals + the underlying uint8 width/signedness +
# the ~mask faces + sizeof(PacketConstraints)=72 + the REAL-SDK
# pkthdr-56/tenant@48 (the 23a ledger re-rides at THIS row's consumer) +
# the SfIp cold family=0 + IpProtocol vocabulary. THE FIRST-RUN-SEED law:
# vectors SEEDed by MEASURED run output NEVER typed, drift-refuse every
# re-run, O0==O2 BYTE-IDENT, tamper-proven both streams; the GATE tail
# RUNNER-MEASURED + pinned by md5 into gate_pinned.txt SEED pass, the
# literal NEVER typed into this file until measured (the 22a law).
# NAME/PIN LAW: the dir name NEVER typed whole in THIS file (runtime
# concat MN); own-token state-aware NEXT arms (pre-0 / post-EXACTLY-1
# LINE); the bare pc-token face: a TWO-segment token NEVER grep-pinned
# EVER (the pc family = frozen-era landmine; the own arms use the
# p-c-gate CONCAT runtime form so this file carries ZERO bare hits and
# adds ZERO to the tools-wide scan). misc-9 landmine NAMING law re-
# cloned (struct Tracer find-0 + the ReloadSurvivor EXACTLY-2 occupants,
# NEVER +1). SEED arithmetic: this landing banks the NEW seed x3 (752 +
# 11 twin fns = 763 over 84 result-lines) and ABSORBS 752 into the
# carried x3 set; every carried face line-counted EXACT post-edit (the
# the rs-subs-lineage trio 621/605/597 NEVER a 4th occurrence).
set -euo pipefail
R=/opt/data/snort3-rust
SRC=/opt/data/snort3-src
L=/opt/data/libdaq
IP=$R/tools/ipheavy_harness          # the 22b donor tree (self-heal)
L4=$R/tools/"link4_harness"          # the carried witness_conf host
SFD=$R/tools/s"f"d_harness             # token-CONCAT (the foreign-token scan law)
RSB=$R/tools/rs""ubs_harness          # the rs-subs lineage (the 23-era concat form)
DST=$R/tools/dir""stor_harness        # the 23d lineage (concat form)
TCH=$R/tools/t""c_harness             # the 22a GATE donor (concat form)
RH=$R/tools/rules_harness            # vendored catch.hpp master (cite face)
H=$(cd "$(dirname "$0")" && pwd)
MN="p""cgate"                        # the RUNTIME self-token (concat law)
C=$H/copy                            # the copy tree (the 23-era shape)
NMR='__|\.exp|std::|GOMP|_ITM_|_cxa|tanh|_Unwind|_GLOBAL_OFFSET|operator (new|delete)'

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC"/src/packet_io/packet_constraints.cc)" -eq 331
test "$(md5sum "$SRC"/src/packet_io/packet_constraints.cc | awk '{print $1}')" = "cb7b3584d08a22e01ae70d7b0b748124"
test "$(wc -l < "$SRC"/src/packet_io/packet_constraints.h)" -eq 76
test "$(md5sum "$SRC"/src/packet_io/packet_constraints.h | awk '{print $1}')" = "447e814a551709a99ffa165e60bb7a41"
test "$(( 331 + 76 ))" -eq 407                                     # the pair ledger
test "$(wc -l < "$L"/api/daq_common.h)" -eq 728
test "$(md5sum "$L"/api/daq_common.h | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(git -C "$L" status --porcelain | wc -l)" -eq 0             # THE SDK ground STAYS CLEAN
git -C "$L" log --oneline -1 | grep -q c8d4083

# ---- THE GATE CENSUS lives in the GROUND (ground-cite, NEVER typed): the
# EXACTLY-3 TEST_CASE faces + the UNIT_TEST arm line-faces ----
test "$(grep -c 'TEST_CASE' "$SRC"/src/packet_io/packet_constraints.cc)" -eq 3
test "$(grep -c 'CHECK(' "$SRC"/src/packet_io/packet_constraints.cc)" -eq 13
test "$(grep -c '\[framework\]' "$SRC"/src/packet_io/packet_constraints.cc)" -eq 3
test "$(sed -n '143p' "$SRC"/src/packet_io/packet_constraints.cc)" = "#ifdef UNIT_TEST"
test "$(sed -n '145p' "$SRC"/src/packet_io/packet_constraints.cc)" = "#include <catch/snort_catch.h>"
test "$(sed -n '147p' "$SRC"/src/packet_io/packet_constraints.cc)" = '#include "flow/flow.h"'
test "$(sed -n '149p' "$SRC"/src/packet_io/packet_constraints.cc)" = 'TEST_CASE("Packet constraints comparison", "[framework]")'
test "$(sed -n '205p' "$SRC"/src/packet_io/packet_constraints.cc)" = 'TEST_CASE("Packet constraints matching", "[framework]")'
test "$(sed -n '297p' "$SRC"/src/packet_io/packet_constraints.cc)" = 'TEST_CASE("Packet constraints flow matching", "[framework]")'
test "$(sed -n '330p' "$SRC"/src/packet_io/packet_constraints.cc)" = "#endif"   # the UNIT_TEST endif (:331 rides the trailing NEWLINE face -- wc counts 331, sed 331 = "")
test "$(sed -n '136p' "$SRC"/src/packet_io/packet_constraints.cc)" = "#ifndef DISABLE_TENANT_ID"
test "$(grep -rc 'define DISABLE_TENANT_ID' "$SRC"/src/ | grep -v ':0' | wc -l)" -eq 0   # NEVER defined -- the tenant arm LIVE
test "$(sed -n '84p'  "$SRC"/src/packet_io/packet_constraints.cc)" = 'bool PacketConstraints::operator==(const PacketConstraints& other) const'
test "$(sed -n '95p'  "$SRC"/src/packet_io/packet_constraints.cc)" = 'bool PacketConstraints::packet_match(const Packet& p) const'
test "$(sed -n '115p' "$SRC"/src/packet_io/packet_constraints.cc)" = '    const auto tenant = p.pkth->tenant_id;'   # THE pkth wall line (E4 subject)
test "$(sed -n '118p' "$SRC"/src/packet_io/packet_constraints.cc)" = '        match_constraints(*this, dip, sip, dp, sp, tenant);'   # the two-order OR
test "$(sed -n '121p' "$SRC"/src/packet_io/packet_constraints.cc)" = 'bool PacketConstraints::flow_match(const Flow& f) const'
test "$(sed -n '129p' "$SRC"/src/packet_io/packet_constraints.cc)" = '    const uint8_t proto = f.ip_proto ? f.ip_proto : f.key->ip_protocol;'   # the fallback law
test "$(sed -n '26p'  "$SRC"/src/packet_io/packet_constraints.h)" = '#include "sfip/sf_ip.h"'   # the h include face (vector :23 / protocol_ids :25 / sf_ip :26)
test "$(sed -n '36p'  "$SRC"/src/packet_io/packet_constraints.h)" = '    enum SetBits : uint8_t {'
test "$(sed -n '48p'  "$SRC"/src/packet_io/packet_constraints.h)" = '        const std::vector<uint32_t>& tenants = std::vector<uint32_t>()) :'   # the default-arg 8th ctor arm
grep -q '#define CATCH_CONFIG_RUNNER' "$SRC"/src/catch/unit_test.cc   # upstream's runner SHAPE (22a cite re-rides)
# the rider-suite face (the ZERO separate-suite finding re-measured):
test "$(grep -c 'add_cpputest' "$SRC"/src/packet_io/test/CMakeLists.txt)" -eq 2   # active_packet_trace + the 23c pair; NO packet_constraints suite EVER
test "$(grep -ci 'packet_constraints' "$SRC"/src/packet_io/test/CMakeLists.txt || true)" -eq 0
test "$(find /usr/include -maxdepth 1 -iname 'CppUTest*' | wc -l)" -eq 0

# ---- name-pin census (measured at 0 prehits; collisions fire LOUDLY) ----
test "$(find "$R"/tools -maxdepth 1 -iname "*${MN}*" | wc -l)" -eq 1
test "$(grep -rl "${MN}_harness" "$R"/tools/*/build.sh 2>/dev/null | grep -v "^$H/build.sh$" | wc -l)" -eq 0
test "$(grep -rl "$MN" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | grep -v "^$R/tests/${MN}_parity_test.rs$" | wc -l)" -eq 0
test "$(grep -rl "$MN" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0        # the landing rs NEVER names the harness token
# the landing-file token face: the landing rs NEVER rides a bare 2-seg
# p-c scan token (the landmine family law; runtime-built scan face):
_pc=$(printf '%s%s' "pa" "cket_constraint")
# the row-name foreign face MEASURED at the row: EXACTLY-13 fc*/f* era
# build.sh files each ride EXACTLY-ONE fresh-cp LINE of the ground header
# (the donor-era ground-path tripwire cp "packet_constraints.h" -- a cp
# path, NEVER a COUNT-arm of the row; the h itself rides their copy trees
# BYTE-EXACT 447e814a since the 17-era). The face STAYS 13 (the 23-era
# pre-hits re-read LIVE; the parity twin re-derives the SAME 13 face +
# the byte-EXACT h pins); flip-forward LOUDLY only if another re-clone lands:
test "$(grep -rl "$_pc" "$R"/tools/*/build.sh "$R"/tests/*.rs 2>/dev/null | grep -v "^$H/build.sh$" | grep -v "^$R/tests/${MN}_parity_test.rs$" | wc -l)" -eq 15   # SANCTIONED riders: 13 -> 14 at the pt-racer-23f twin + 14 -> 15 at the pt-rmod row-23g twin — the 23g landing's parity twin LEGITimately Reuses the 23e landing home in its Rust use-path (the one-home law MAKES the cite unavoidable; build.sh-ONLY face STAYS 13 — every twin + build.sh face split, the twin arm NEVER moved); the 62d6fac flip-forward law; the 23g landing NEVER edited; token-split in comments per the family law
test "$(grep -rc "$_pc" "$R"/tools/filib_harness/build.sh | cut -d: -f2)" -eq 2   # the ONE 2-line face (the filament pair); the rest EXACTLY-1
test "$(md5sum "$R"/tools/fcapi_harness/copy/packet_io/packet_constraints.h | awk '{print $1}')" = "447e814a551709a99ffa165e60bb7a41"   # the BYTE-EXACT donor ride (the h NEVER drifted since the 17-era)
# the misc-9 landmine NAMING law (the 23c/23d shape re-cloned; the pair
# STAYS the EXACTLY-2 occupants, the landmine NEVER rides a 3rd):
test "$(grep -rl 'struct Tracer' "$R"/src --include=*.rs | wc -l)" -eq 0
test "$(grep -rlE 'ReloadSurvivor|reload_survivor' "$R"/src --include=*.rs | sed "s|$R/||" | paste -sd,)" = "src/framework/mod.rs,src/framework/reload_survivor_subscriptions.rs"
test "$(grep -rlE 'ReloadSurvivor|reload_survivor' "$R"/src --include=*.rs | wc -l)" -eq 2
test "$(grep -rlE "ReloadSurv""ivor|struct Tra""cer" "$R"/src/packet_io --include=*.rs | wc -l)" -eq 0   # THIS row ships ZERO landmine-name hits in ITS home (concat form = landmine tokens ONLY)

# ---- NEXT.md token face, STATE-AWARE (pre-landing 0; POST the docs bank
# raises it to EXACTLY-1 grep-LINE per token): ----
pre=$(git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/PLAN.md" >/dev/null 2>&1 && echo post || echo pre)
docbank=$(grep -q "^## .*row 23e" "${R}"/KNOWN\ DEVIATIONS.md && echo banked || echo unbanked)
if [ "$docbank" = unbanked ]; then
    test "$(grep -c "$MN" "$R/NEXT.md" || true)" -eq 0
else
    test "$(grep -c "$MN" "$R/NEXT.md")" -eq 1                       # the ONE p-c-gate-token line (the header rewrite banks it; NEVER a 2nd)
    test "$(grep -c "${MN}_harness" "$R/NEXT.md")" -eq 1
    test "$(grep -c '^| 23e' "$R/PORTING_PLAN.md")" -eq 1            # the plan-row grep-count-1 law
    test "$(grep -c 'row 23e' "${R}"/KNOWN\ DEVIATIONS.md)" -ge 1
fi
grep -q "^## .*row 23e" "${R}"/KNOWN\ DEVIATIONS.md || true          # the LAST-section law (the section MUST be the tail face)
if [ "$pre" = post ]; then
    test "$(git -C "$R" ls-files | grep -c "^tools/${MN}_harness/")" -eq 9   # NINE stageables: the 22a gate shape (8 + the RUNNER main TU)
fi

# ---- NEXT.md CITE-ONLY read arms (every carried seed face count-pinned
# EXACT -- the faces re-measured at the row BEFORE authoring): ----
test "$(grep -c '684 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '659 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '650 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '633 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '629 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '621 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '605 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '597 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c 'cc \*\*133\*\*' "$R/NEXT.md")" -ge 1        # MUST-RIDE stale exhibit (presence)
test "$(grep -c '5 TEST(' "$R/NEXT.md")" -eq 1               # the drift token EXACT-1
grep -q 'address_space_id' "$R/NEXT.md"                      # the 23a ledger cite (THIS row's consumer rides it)
grep -q "tc""_harness" "$R/NEXT.md"                          # the 22a gate-donor cite face (CONCAT form: the tc :129 foreign-holder scan stays EXACTLY-0)
for sfn in 702 724; do
    test "$(grep -c "$sfn tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
# the 23d seed STAYS x3 at EVERY stage (carried face like every prior
# seed: the docs bank ABSORBS it, NEVER drops a line off; the NEW seed
# rides x3 ONLY post-bank -- this harness banks it IN the landing commit):
test "$(grep -c '752 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
if [ "$docbank" = banked ]; then
    test "$(grep -c '763 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3   # the NEW x3 seed this landing banks
else
    test "$(grep -c '763 tests green / 0 FAILED' "$R/NEXT.md" || true)" -eq 0
fi

# ---- copy tree = ipheavy DONOR clone (.o's purged); the STALE-DONOR +
# BYTE-IDENT-DEPENDENCY faces measured at the row (the honest OPPOSITE of
# 22a's drift trap: the pair's dependency heads ALL ride byte-EXACT) ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi   # donor self-heal
rm -rf "$C" "$H/o2"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140                  # the 22b/23-era donor face re-rides
# the row files find-0 BEFORE the fresh cps (the donor-eraser guard; the
# fcapi/fpolicy/finspect trees' BYTE-EXACT packet_constraints.h rides as a
# CITE face -- pinned in the parity twin, NEVER here):
test "$(find "$C" \( -name 'packet_constraints.cc' -o -name 'packet_constraints.h' \) | wc -l)" -eq 0
# dependency heads byte-EXACT vs ground (EVERY build; the fresh-cp law's
# audit side -- these ride the donor AS-IS, ZERO cp needed, pinned):
for f in flow/flow.h flow/flow_key.h flow/flow_data.h flow/flow_stash.h protocols/packet.h protocols/layer.h protocols/ipv4.h protocols/ip.h sfip/sf_ip.h framework/decode_data.h log/messages.h utils/util.h main/snort_config.h; do
    test "$(md5sum "$C/$f" | awk '{print $1}')" = "$(md5sum "$SRC/src/$f" | awk '{print $1}')"   # byte-EXACT
done
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"   # ext#4 graft trio HEAD
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
! grep -q 'MAX_DAQ_VERDICT' "$C"/daq_common.h                    # the graft head carries NO enum constant (the flow.h :541 would DIE here)
test "$(md5sum "$C"/catch/catch.hpp | awk '{print $1}')" = "74ef54e848cf843c99e3acdb94ce2b1a"
cmp -s "$C"/catch/catch.hpp "$RH"/copy/catch/catch.hpp           # the rules-era master face byte-ident
test "$(wc -l < "$C"/catch/catch.hpp)" -eq 20397
printf '#pragma once\n#include "catch/catch.hpp"\n' > "$H/.shim_face_expect"
test "$(md5sum "$C"/catch/snort_catch.h | awk '{print $1}')" = "$(md5sum "$H"/.shim_face_expect | awk '{print $1}')"   # the donor shim = the 2-L face (the ground's 72-L header NEVER rides the 140-tree -- the honest donor face pinned, cite in the ledger)
rm -f "$H/.shim_face_expect"

# ---- FACE 1 (THE E4 WALL RE-ARMED, flipped-assert EVERY build): the
# fresh row pair vs the ext#4 donor daq heads -- vocabulary DEATH at
# EXACTLY the 22b PKTH line ----
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
GXX="$GXX0"
cp "$SRC"/src/packet_io/packet_constraints.cc "$SRC"/src/packet_io/packet_constraints.h "$C"/packet_io/
cmp -s "$C"/packet_io/packet_constraints.cc "$SRC"/src/packet_io/packet_constraints.cc   # VERBATIM cp, NEVER sed
cmp -s "$C"/packet_io/packet_constraints.h  "$SRC"/src/packet_io/packet_constraints.h
printf '#pragma once\n' > "$C"/config.h                          # STOCK face (HAVE_* hinges NEVER needed HERE)
if $GXX0 -c "$C"/packet_io/packet_constraints.cc -o /dev/null 2> "$H"/E4_donor.txt; then
    echo "E4 face flip BROKE: the graft face COMPILES packet_constraints.cc -- RE-PLAN (graft mutation?)"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_donor.txt)" -eq 1
test "$(grep -c "DAQ_PktHdr_t’ has no member named ‘tenant_id" "$H"/E4_donor.txt)" -eq 1   # the NAMED face in gcc's UTF-8 CURLY-quote form (the daqio-era quote law re-rides)
test "$(grep -c 'packet_constraints.cc:115' "$H"/E4_donor.txt)" -eq 1   # THE 22b wall line RE-ARMED at this row's own face

# ---- THE RE-CITE (the 23a plan-20 law, DISCHARGED at the CONSUMER): the
# REAL SDK headers land IN THE COPY TREE (copy-local NEVER tracked) ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(md5sum "$C"/daq_module_api.h | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
grep -q 'MAX_DAQ_VERDICT' "$C"/daq_common.h                      # the enum-constant face (:321) -- flow.h :541 static_assert re-armed LIVE
$GXX0 -c "$C"/packet_io/packet_constraints.cc -o "$C"/pc.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt                                       # the flip receipt: SILENT rc0 vs REAL SDK
$GXX0 -DUNIT_TEST -c "$C"/packet_io/packet_constraints.cc -o "$H"/pc_gateut.o 2> "$H"/E4_ut.txt
test ! -s "$H"/E4_ut.txt                                         # the GATE .o (in-TU Catch arms compile CLEAN: the vendor-shim + the fresh flow.h head)
# the fresh utility cps (REAL bodies -- the 23d law; the donor .o's STALE
# copies of these NEVER cp'd; compile-check the fresh bodies SILENT):
cp "$SRC"/src/protocols/ip.cc "$C"/protocols/
cp "$SRC"/src/utils/util.cc "$SRC"/src/utils/util_cstring.cc "$C"/utils/
cmp -s "$C"/protocols/ip.cc "$SRC"/src/protocols/ip.cc
$GXX0 -c "$C"/protocols/ip.cc     -o "$C"/ip.o
$GXX0 -c "$C"/utils/util.cc       -o "$C"/util.o
$GXX0 -c "$C"/utils/util_cstring.cc -o "$C"/util_cstring.o
test "$(find "$C" -name 'ip.cc' -o -name 'sf_ip.cc' | wc -l)" -eq 2   # the fresh ip.cc cp + the donor-resident sf_ip.cc (byte-EXACT ground, pinned next)
test "$(md5sum "$C"/sfip/sf_ip.cc | awk '{print $1}')" = "a9505892c68927c7e0967f122e9908cb"   # donor == ground BYTE-EXACT (the 23-era pin re-rides)
$GXX0 -c "$C"/sfip/sf_ip.cc      -o "$C"/sf_ip.o

# ---- the nm app-undef census (MEASURED EXACT at the row; the NMR filter
# keeps ONLY app names) ----
nm -C -u "$C"/pc.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_pc.txt
test "$(wc -l < "$H"/nm_U_pc.txt)" -eq 2                          # memcmp+memmove ONLY -- the cleanest row body of the lineage (SfIp == is INLINE fast_equals_raw through the header; the tenant read speaks the REAL pkthdr)
nm -C -u "$H"/pc_gateut.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_gateut.txt
test "$(grep -vc 'Catch::' "$H"/nm_U_gateut.txt)" -eq 8                      # MEASURED (recon nm face): 4 libc (memcmp/memcpy/memmove/strlen) + SfIp::set x2 (the char* + void* arms) + the Flow pair
test "$(grep -c 'Flow::' "$H"/nm_U_gateut.txt)" -eq 2             # THE Pull: the gate's `Flow flow;` -- mirror law re-arms (22b shape)
test "$(grep -c 'SfIp::set' "$H"/nm_U_gateut.txt)" -eq 2
test "$(grep -c 'Catch::' "$H"/nm_U_gateut.txt)" -ge 15           # the +Catch delta (closed by the RUNNER .o)
nm -C -u "$C"/ip.o | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_ip.txt
test "$(grep -c 'get_inner_ip6_frag' "$H"/nm_U_ip.txt)" -eq 1     # the 22b layer pull re-rides (the donor-resident layer.cc NEVER cp'd -> the mirror)

# ---- THE carried witness_conf EXTRACTION (the 21b-row host law; NEVER
# doubled; the 23c noreturn rider on the EXTRACTED body only, NEVER the
# tracked 4dd91018 face): ----
_b=$(grep -n "EOFWC" "$L4"/build.sh | head -1 | cut -d: -f1)
_e=$(grep -n "EOFWC" "$L4"/build.sh | tail -1 | cut -d: -f1)
sed -n "$((_b+1)),$((_e-1))p" "$L4"/build.sh > "$H"/witness_conf.cc
test "$(md5sum "$H"/witness_conf.cc | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"   # the CARRIED face VERBATIM
python3 - "$H"/witness_conf.cc <<'EORIDER'
import sys
p = sys.argv[1]
s = open(p).read().split("\n")
i = next(k for k,l in enumerate(s) if l.startswith("void FatalError("))
s[i] = ("void FatalError(const char* f, ...) { va_list a; va_start(a,f); vfprintf(stderr,f,a); "
        "va_end(a); fputc(10, stderr); "
        "if (::fatal_jump_armed) { ::fatal_jump_armed = false; siglongjmp(::fatal_jump, 1); } "
        "abort(); }")
s[0] = ("#include <csetjmp>\n// THE 23c noreturn RIDER jump sites (GLOBAL scope; the :: refs\n"
        "// inside namespace snort resolve HERE -- NEVER a return past a noreturn\n"
        "// witness arm at -O2, the UB law):\nsigjmp_buf fatal_jump;\nbool fatal_jump_armed = false;\n\n") + s[0]
open(p,"w").write("\n".join(s))
EORIDER
test "$(grep -c 'siglongjmp(::fatal_jump, 1)' "$H"/witness_conf.cc)" -eq 1
test "$(grep -c 'void FatalError' "$H"/witness_conf.cc)" -eq 1               # EXACTLY-1 (never doubled)
$GXX0 -I"$SRC/src" -c "$H"/witness_conf.cc -o "$H"/witness_conf.o
$GXX0 -I"$SRC/src" -c "$H"/witness_pcgate.cc -o "$H"/witness_pcgate.o
$GXX0 -I"$SRC/src" -c "$H"/probe.cc          -o "$H"/probe.o
$GXX0 -I"$SRC/src" -c "$H"/probe_faceA.cc    -o "$H"/probe_faceA.o
$GXX0 -c "$H"/pcgate_gate_main.cc -o "$H"/pcgate_gate_main.o                 # the RUNNER TU (TRACKED; the -DUNIT_TEST NEVER rides HERE -- the Catch decls the runner needs ride the vendor header)

# ---- THE E10 RUNNER-SHAPE FACE, MEASURED THE OPPOSITE WAY from 22a
# (honest, NOT re-assumed): the MAIN-twin link runs GREEN HERE (the row
# tests ride NO init()-filled file-static -> the snort.cc:109 order law
# CANNOT bite); the flipped-assert NEVER fires on this row. The RUNNER
# posture STAYS tracked per the 22a template (upstream unit_test.cc face) ----
printf '#define CATCH_CONFIG_MAIN\n#include "catch/snort_catch.h"\n' > "$H"/.catch_main_probe.cc
$GXX0 -I"$SRC/src" -c "$H"/.catch_main_probe.cc -o "$H"/.catch_main_probe.o
WINS="$C/sf_ip.o $C/ip.o $C/util.o $C/util_cstring.o $H/witness_conf.o $H/witness_pcgate.o"   # the GATE-side link set (the row .o NEVER rides HERE -- pc_gateut.o carries it, E9 law)
DECLEG="$C/pc.o"   # the DEC/FACE-A leg: the PLAIN row .o (the gate NEVER co-links it)
$GXX "$H"/.catch_main_probe.o "$H"/pc_gateut.o $WINS -o "$H"/gate_main_shape_probe
set +e
"$H"/gate_main_shape_probe > "$H"/E10_main_twin.txt 2>&1
twin_rc=$?
set -e
test "$twin_rc" -eq 0        # THE MEASURED FACE (22a rode 139): GREEN -- the value-row face; NO init-order law, NO flip on this row. The law STAYS pinned in the runner-TU header comment; this arm asserts the row's honest OPPOSITE.
grep -q 'All tests passed' "$H"/E10_main_twin.txt

# ---- E9 ONE-FACE flipped-asserts BOTH ways (measured faces at the row):
# (a) plain pc.o beside pc_gateut.o DIES EXACTLY-6 multiple definitions
# (the row-body family at THIS row: the 3 fns + copy-ctor + operator= +
# the 2-in-1 Flow... no: the honest measured census = 6 faces listed in
# E9_dupc.txt); (b) the twin-beside-pc.o leg EXACTLY-6 likewise ----
printf '%s\n' '#include "packet_io/packet_constraints.h"' \
    'namespace snort {' \
    'bool PacketConstraints::operator==(const PacketConstraints&) const { return true; }' \
    'bool PacketConstraints::packet_match(const Packet&) const { return true; }' \
    'bool PacketConstraints::flow_match(const Flow&) const { return true; }' \
    '}' > "$H"/e9_dup_twin.cc
$GXX0 -I"$SRC/src" -c "$H"/e9_dup_twin.cc -o "$H"/e9_dup_twin.o
if $GXX "$C"/pc.o "$H"/pc_gateut.o -o "$H"/E9_dup_probe 2> "$H"/E9_dupc.txt; then
    echo "E9 law BROKE: plain + gateut co-linked (the Catch-state + row-body double home)"; exit 1
fi
rm -f "$H"/E9_dup_probe
test "$(grep -c 'multiple definition of' "$H"/E9_dupc.txt)" -eq 6       # MEASURED: 6 def-LINES over 4 unique families (the 3 fns + operator= + the copy-ctor C1+C2 construction-variant pair -- recon receipt pcg face)
if $GXX "$C"/pc.o "$H"/e9_dup_twin.o $WINS -o "$H"/E9_dup_probe2 2> "$H"/E9_dup.txt; then
    echo "E9 law BROKE: a mirror co-linked beside the real home"; exit 1
fi
rm -f "$H"/E9_dup_probe2
test "$(grep -c 'multiple definition of' "$H"/E9_dup.txt)" -eq 3        # the row fns' ONE-home law (operator==/packet_match/flow_match named)
# (the witness-beside-witness leg rode recon: wit-double co-link died
# EXACTLY-5 -- copy-LOCAL history receipt, the 23-era dup-witness face)

# ---- GATE stream (O0): the TRACKED RUNNER + the gate .o + the REAL links ----
$GXX "$H"/pcgate_gate_main.o "$H"/pc_gateut.o $WINS -o "$H"/gate
"$H"/gate > "$H"/gate.txt 2>&1 || { echo GATE_FAIL; cat "$H"/gate.txt; exit 1; }
grep -q 'All tests passed' "$H"/gate.txt
! grep -q 'FAILED' "$H"/gate.txt
"$H"/gate -l > "$H"/gate_l.txt || true
test "$(grep -c '\[framework\]' "$H"/gate_l.txt)" -eq 3            # the 3-name census (ground-cite loop)
while IFS= read -r nm2; do grep -qF "$nm2" "$H"/gate_l.txt || { echo "gate_l MISS: $nm2"; exit 1; }
done < <(grep -o 'TEST_CASE("[^"]*"' "$SRC"/src/packet_io/packet_constraints.cc | sed 's/TEST_CASE("//; s/"$//')
nm -C --defined-only "$H"/gate | grep -c ' T snort::PacketConstraints::operator==' > "$H"/nm_defined.txt
test "$(cat "$H"/nm_defined.txt)" -eq 1                          # EXACTLY-ONE row-home (gateut)
test "$(nm "$H"/pcgate_gate_main.o | grep -c ' T main')" -eq 1    # the RUNNER .o owns main
test "$(nm "$H"/pc_gateut.o | grep -c ' T main' || true)" -eq 0   # the gate .o NEVER carries main (ONE Catch-main home, the tc law re-rides)

# ---- O2 twins (the gate third stream + probes) ----
O2=$H/o2; mkdir -p "$O2"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C"
$GXXA -c "$C"/packet_io/packet_constraints.cc -o "$O2"/pc.o
$GXXA -DUNIT_TEST -c "$C"/packet_io/packet_constraints.cc -o "$O2"/pc_gateut.o
$GXXA -c "$C"/protocols/ip.cc -o "$O2"/ip.o
$GXXA -c "$C"/utils/util.cc -o "$O2"/util.o
$GXXA -c "$C"/utils/util_cstring.cc -o "$O2"/util_cstring.o
$GXXA -c "$C"/sfip/sf_ip.cc -o "$O2"/sf_ip.o
$GXXA -I"$SRC/src" -c "$H"/witness_conf.cc    -o "$O2"/witness_conf.o
$GXXA -I"$SRC/src" -c "$H"/witness_pcgate.cc  -o "$O2"/witness_pcgate.o
$GXXA -I"$SRC/src" -c "$H"/probe.cc           -o "$O2"/probe.o
$GXXA -I"$SRC/src" -c "$H"/probe_faceA.cc     -o "$O2"/probe_faceA.o
$GXXA -c "$H"/pcgate_gate_main.cc -o "$O2"/pcgate_gate_main.o
WINS2="$O2/sf_ip.o $O2/ip.o $O2/util.o $O2/util_cstring.o $O2/witness_conf.o $O2/witness_pcgate.o"   # the gate-side O2 link set (pc_gateut.o carries the row face; the plain .o NEVER doubles it -- E9)
DECLEG2="$O2/pc.o"   # the O2 DEC/FACE-A leg
$GXXA "$O2"/pcgate_gate_main.o "$O2"/pc_gateut.o $WINS2 -o "$H"/gate_O2
"$H"/gate_O2 > "$H"/gate_O2.txt 2>&1 || { echo GATE_O2_FAIL; exit 1; }
$GXX "$O2"/probe.o       $DECLEG2 $WINS2 -o "$H"/probe_O2
$GXX "$O2"/probe_faceA.o $DECLEG2 $WINS2 -o "$H"/probe_faceA_O2
( cd "$H" && timeout 60 ./probe_O2 > vectors_O2.txt 2>/dev/null ) || { echo PROBE_FAIL DEC O2; exit 1; }
( cd "$H" && timeout 60 ./probe_faceA_O2 > vectors_faceA_O2.txt 2>/dev/null ) || { echo PROBE_FAIL FACE-A O2; exit 1; }

# ---- DEC link + run (O0) ----
$GXX "$H"/probe.o $DECLEG $WINS -o "$H"/probe
nm -C -u "$H"/probe | grep ' U ' | grep -vE "$NMR" | sed 's/^ *U //' | sort -u > "$H"/nm_U_probe.txt
test "$(grep -v '@' "$H"/nm_U_probe.txt | wc -l)" -eq 0             # ZERO unresolved app names (full row graph closes IN-LINK)
( cd "$H" && timeout 120 ./probe > vectors_O0.txt 2> probe_dec_stderr.txt ) || { echo PROBE_FAIL DEC O0; exit 1; }
test ! -s "$H"/probe_dec_stderr.txt                                 # DEC runs SILENT
$GXX "$H"/probe_faceA.o $DECLEG $WINS -o "$H"/probe_faceA
( cd "$H" && timeout 60 ./probe_faceA > vectors_faceA_O0.txt 2> faceA_stderr.txt ) || { echo PROBE_FAIL FACE-A O0; exit 1; }
test ! -s "$H"/faceA_stderr.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt

# ---- FIRST-RUN-SEED law (vectors NEVER typed; drift-refuse; tamper) ----
if [ ! -e "$H"/vectors.txt ]; then
    cp "$H"/vectors_O0.txt "$H"/vectors.txt
    cp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt
    echo "SEED PASS: DEC + FACE-A vectors measured (NEVER typed)"
else
    cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt           || { echo "VECTORS DEC DRIFT vs tracked vectors.txt"; exit 1; }
    cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "VECTORS FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }
fi
test -e "$H"/vectors.txt
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt
cp "$H"/vectors.txt "$H"/.vectors_pristine
line=$(grep -n '^P1 ' "$H"/vectors.txt | head -1 | cut -d: -f1)
sed -i "${line}s/eq=1/eq=0/" "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt && { echo "TAMPER ARM DEAD (DEC)"; exit 1; }
cp "$H"/.vectors_pristine "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "TAMPER RESTORE DEAD (DEC)"; exit 1; }
rm -f "$H"/.vectors_pristine
cp "$H"/vectors_faceA.txt "$H"/.vectors_faceA_pristine
line=$(grep -n '^SIZES ' "$H"/vectors_faceA.txt | head -1 | cut -d: -f1)
sed -i "${line}s/pc=72/pc=73/" "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt && { echo "TAMPER ARM DEAD (FACE-A)"; exit 1; }
cp "$H"/.vectors_faceA_pristine "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "TAMPER RESTORE DEAD (FACE-A)"; exit 1; }
rm -f "$H"/.vectors_faceA_pristine

# ---- gate tail RUNNER-MEASURED + drift pins (the 22a shape: gate.txt
# COPY-LOCAL UNTRACKED, md5-pinned at seed, O0/O2 byte face) ----
GATE_TAIL=$(grep 'All tests passed' "$H"/gate.txt)                # RUNNER-MEASURED, never typed
test "$(echo "$GATE_TAIL" | grep -oE 'in [0-9]+ test cases' | grep -oE '[0-9]+')" -eq 3   # the runner's OWN census == 3 (the ground-cite cross-check)
GATE_ASSERTS=$(echo "$GATE_TAIL" | grep -oE '\(([0-9]+) assertion' | grep -oE '[0-9]+')
test "$GATE_ASSERTS" -eq 13                                       # == the ground CHECK( census (the runner face maps the cite face EXACT)
if [ ! -e "$H"/gate_pinned.txt ]; then
    md5sum "$H"/gate.txt | awk '{print $1}' > "$H"/gate_pinned.txt
    cp "$H"/gate.txt "$H"/gate.txt.seed_face
    echo "SEED PASS: gate tail face: $GATE_TAIL"
else
    test "$(md5sum "$H"/gate.txt | awk '{print $1}')" = "$(cat "$H"/gate_pinned.txt)" || { echo "GATE drift vs pinned md5"; exit 1; }
fi
cmp "$H"/gate.txt "$H"/gate_O2.txt                                # O0 == O2 gate face

# ---- vectors FACE greps (MEASURED at the seed run; authored post-run) ----
V=$H/vectors.txt; FA=$H/vectors_faceA.txt
test "$(wc -l < "$V")" -eq 20
test "$(wc -l < "$FA")" -eq 7
grep -q '^P0 def match=1 setbits=0 ipproto=255 tenants=0 sp=0 dp=0$' "$V"    # the h :60-:70 NSDMI cold face through the REAL ctor (match TRUE the :68 default)
grep -q '^P1 allunset eq=1$' "$V"                                              # gate SECTION "all unset" re-driven: mask 0 -> members NEVER compared (cc :86-:92)
grep -q '^P2 dstunset mask=251 eq=1$' "$V"                                     # ~DST_IP = 251 (the (uint8_t)~ face) -- the dst leg SKIPPED, differing dst rides eq=1
grep -q '^P3 neq allset=255 eq=0$' "$V"                                        # all-set differing src_ip -> FALSE (the fast_equals_raw v4 fold)
grep -q '^P4 tenants eq1=1 eq2=1 self=1$' "$V"                                 # tenants== leg (gate "equal") + copy-ctor/copy-assign/self-assign faces the GATE NEVER executes
grep -q '^P5 nomatch=0$' "$V"                                                  # cc :97 the :68 match=false arm (the gate NEVER arms it)
grep -q '^P6 noopkg tenantonly=1$' "$V"                                        # the NO-IP face: TENANT bit ALONE PASSES (the :102 five-bit set EXCLUDES TENANT -- the exact C face)
grep -q '^P7 noopkg protoset=0$' "$V"                                          # the NO-IP face: ANY IP-class bit armed -> false (:103)
grep -q '^P8 fwd match=1$' "$V"                                                # the forward order through the REAL .o
grep -q '^P9 swap two-order=1$' "$V"                                           # the cc :118 swapped SECOND chance (a single-order port would print 0 HERE -- the two-order pin)
grep -q '^P10 tenant-miss=0$' "$V"                                             # find_if MISS -> false (:50-:51)
grep -q '^P11 tenant-anon-skip=1$' "$V"                                        # tenant_id==0 SKIPS the scan (:45 the `and tenant_id` arm)
grep -q '^P12 tenant-hit=1$' "$V"                                              # find_if HIT (the [100,200] list @ 200)
grep -q '^F0 flow keyfallback=1$' "$V"                                         # cc :129 session ip_proto==0 -> the key->ip_protocol fallback arm
grep -q '^F1 flow keyfallback-miss=0$' "$V"                                    # the fallback value vs a mismatching constraint
grep -q '^F2 flow session-wins=1$' "$V"                                        # session ip_proto WINS over the key value (the :126-:128 comment law)
grep -q '^F3 flow nomatch=0$' "$V"                                             # cc :123 the match=false arm
grep -q '^F4 flow same-dir=1$' "$V"                                            # single-order client/server hit
grep -q '^F5 flow swapped=0$' "$V"                                             # THE ASYMMETRY: the flow face NEVER gets packet_match's swapped second chance (0 vs P9=1, cited)
grep -q '^Z terminator=0$' "$V"
test "$(grep -c '^P' "$V")" -eq 13
test "$(grep -c '^F' "$V")" -eq 6
grep -q '^SETBITS proto=1 sip=2 dip=4 sport=8 dport=16 ten=32$' "$FA"          # h :37-:42 the six decimals
grep -q '^UNDER width=1 signed=0$' "$FA"                                        # enum : uint8_t (alignof 1, unsigned)
grep -q '^OPS notdst=251 allset=255 notten=223$' "$FA"                          # the (uint8_t)~ gate-literals face
grep -q '^SIZES pc=72 sip=18 tenants_off_ge=1$' "$FA"                           # sizeof(PacketConstraints)=72; sizeof(SfIp)=18
grep -q '^PKTH sz=56 tn_off=48$' "$FA"                                         # THE 23a REAL-SDK face RE-RIDDEN at this consumer (56B pkthdr, tenant_id@48)
grep -q '^SIPCOLD fam=0 isset=0$' "$FA"                                        # SfIp() cold = AF_UNSPEC(0)
grep -q '^PROTO tcp=6 udp=17 icmp=1 notset=255$' "$FA"                         # the codec-home vocabulary REUSE face

# ---- python pin block (line-exact vs the landing semantics) ----
python3 - "$SRC" "$R" <<'PY'
import sys
S, R = sys.argv[1], sys.argv[2]
cc = open(S + "/src/packet_io/packet_constraints.cc").read()
h  = open(S + "/src/packet_io/packet_constraints.h").read()
rs = open(R + "/src/packet_io/packet_constraints.rs").read()
assert "sip == cs.src_ip" in cc and "dip == cs.dst_ip" in cc          # operator== masked legs
assert "p.pkth->tenant_id" in cc                                       # THE pkth consumer line
assert "f.key->tenant_id" in cc                                        # the LIVE ifdef arm
assert "std::find_if" in cc
assert "IpProtocol::PROTO_NOT_SET = " not in h
assert "IpProtocol ip_proto = IpProtocol::PROTO_NOT_SET;" in h         # h :60 NSDMI
assert "bool match = true;" in h                                       # h :68
assert "pub struct PacketConstraints" in rs
assert "fast_equals_raw" in rs                                          # the C operator== body mirror
assert "match_constraints(dip, sip, dp, sp, p.tenant_id)" in rs         # the two-order face
assert "key_tenant_id" in rs                                            # the LIVE arm
# the SetBits decimals == the landing's consts (one-home face by grep):
for name in ("IP_PROTO","SRC_IP","DST_IP","SRC_PORT","DST_PORT","TENANT"):
    assert ("pub const %s: u8 = " % name) in rs, name
assert "pub mod set_bits" in rs
PY

# ---- THE CENSUS (MEASURED loops; THE FLIP STATEMENT): 26->27 on-disk
# (this row's NEW gate.txt, copy-local UNTRACKED), distinct md5 lineages
# 18->19 (this row's tail), legacy 9 x 4826fc22 FROZEN, tracked face
# STAYS 1 (gre 6751d1a8); the 26 OTHER gate.txt artifacts NEVER touched ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 28                     # row-23f RIDER: 27 -> 28 by the THIRD real gate row's copy-local face (the 62d6fac complete-flip law; THIS row landed 26 -> 27)
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 20                       # row-23f RIDER: 19 -> 20 lineages (the row-23f fresh tail; the 62d6fac law; THIS row landed 18 -> 19)
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh   # legacy lineage anchor
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                # tracked face UNCHANGED: gre's ONLY
git -C "$R" check-ignore -q tools/${MN}_harness/gate.txt               # posture = copy-local UNTRACKED (the tc law)
test "$(git -C "$R" status --porcelain -- "$TCH"/gate.txt | wc -l)" -eq 0   # the 22a gate ARTIFACT byte-UNTOUCHED (re-runs NEVER happen; the walked census counts DISK)

# ---- backbone10 + frozen echoes (direct-md5 law, NEVER chase rc0) ----
test "$(wc -l < "$R"/tools/link4_harness/backbone10.txt)" -eq 10
test "$(md5sum "$R"/tools/link4_harness/backbone10.txt | awk '{print $1}')" = "5339c7ee501dab8a85277c37dc2d1e0c"
test "$(md5sum "$SFD"/vectors.txt | awk '{print $1}')"      = "3c05632e88676ef9f40ee0a5d33fdf09"
test "$(md5sum "$SFD"/vectors_faceA.txt | awk '{print $1}')" = "040de1ef2ea177ac526c8ef244713c58"
test "$(md5sum "$RSB"/vectors.txt | awk '{print $1}')"      = "9e303761c021d00ea672a493544e07af"
test "$(md5sum "$RSB"/vectors_faceA.txt | awk '{print $1}')" = "42aa06fb4c55adfa50e96d1f715d997e"
test "$(md5sum "$DST"/vectors.txt | awk '{print $1}')"      = "d0bb3eb949e4c610c6749de30c55ede9"
test "$(md5sum "$DST"/vectors_faceA.txt | awk '{print $1}')" = "0f4c30b5ed88ab20b14172674f9d3538"

# ---- STAGEABLES echo + .gitignore proof (NESTED-INSTRUMENT law; NINE
# faces = the 22a gate shape: 8 + the RUNNER main TU, the gate-row count) ----
if [ "$pre" = post ]; then
    test "$(git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/build.sh" >/dev/null 2>&1 && echo tracked)" = tracked
fi
for f in copy/pc.o copy/pc_gateut.o o2/pc_gateut.o probe probe_O2 probe_faceA probe_faceA_O2 gate gate_O2 gate_main_shape_probe gate.txt gate_O2.txt gate_l.txt gate_pinned.txt gate.txt.seed_face e9_dup_twin.cc e9_dup_twin.o witness_conf.cc witness_conf.o witness_pcgate.o pcgate_gate_main.o pc_gateut.o vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt nm_U_pc.txt nm_U_gateut.txt nm_U_ip.txt nm_U_probe.txt nm_defined.txt E4_donor.txt E4_real.txt E4_ut.txt E9_dup.txt E9_dupc.txt E10_main_twin.txt md5_pinned.txt gate.md5 gate_md5_lineages.txt stageables.txt .catch_main_probe.cc .catch_main_probe.o probe_dec_stderr.txt faceA_stderr.txt; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" 2>/dev/null || { echo "GITIGNORE face DEAD (ignored expected): $f"; exit 1; }
done
tracked_stage="$( (git -C "$R" ls-files "tools/${MN}_harness/" | { grep -v '.gitignore' || true; } | wc -l) )"
if [ "$pre" = post ]; then
    test "$tracked_stage" -eq 8     # build.sh PLAN.md probe.cc probe_faceA.cc pcgate_gate_main.cc vectors.txt vectors_faceA.txt witness_pcgate.cc (+ the .gitignore itself = the 9th ls-files face)
fi
for f in copy/pc.o pc_gateut.o gate gate_O2 gate_l.txt probe probe_O2 probe_faceA probe_faceA_O2 witness_conf.cc witness_conf.o witness_pcgate.o pcgate_gate_main.o vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt; do
    test -e "$H/$f" || { echo "stage leg MISSING: $f"; exit 1; }
done

echo "PCGATE_DONE vectors=$(wc -l < "$H"/vectors.txt)/$(wc -l < "$H"/vectors_faceA.txt) gate_tail=[$GATE_TAIL] census=$(ls "$R"/tools/*/gate.txt | wc -l)/$frozen/$(cat "$H"/gate_md5_lineages.txt)/$(git -C "$R" ls-files | grep -c gate.txt) backbone=10"
