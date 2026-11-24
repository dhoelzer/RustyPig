#!/usr/bin/env bash
# tracer_harness -- row 22b: THE chapter-19 LAST row: framework/tracer.cc 73 L
# (md5 9ee6b2ee33c4c98144f6a575891d1679) + tracer.h 125 L (md5
# 98d53205a5ddaff48ba5c304d0658931) = 198-L pair (RE-GROUNDED byte-EXACT at
# the 22a docs pass; re-wc/re-md5 EVERY build, the law). THE PT_TRACE
# TraceLoggerPlug / TraceLogApi plugin-API PAIR: print_ntuple (the SfIp pair
# + ntop + the TCP|UDP port GATE cc :44 + the ss stream face) + THE PKTH WALL
# (cc :52 AS=address_space_id, :54-:55 if(tenant_id) TN= -- the ONLY daq-
# touched face; direct `daq` grep on BOTH ground files EXACTLY-0) +
# print_timestamp (ts_print(nullptr, ts) -- the wall-clock + null-SnortConfig
# SEGV face of linking util.cc at probe time -> the witness ts_print MIRROR
# over a FIXED anchor timeval, honest determinism, NEVER fake vectors).
# THE PKTH-EXTENSION ARM (honest, pre-banked NEXT.md :765-:777 + :837-:840):
# the donor graft daq_common.h 9b603f8f (3-field DAQ_PktHdr_t) compile DIES
# with EXACTLY-3 errors :52 no-member address_space_id + :54/:55 tenant_id
# (the E4_pkthwall flipped-assert receipt EVERY build); the python GRAFT
# APPENDS the two DECL rows COPY-LOCAL (9b603f8f -> b99e44b9 md5 face pinned
# at BOTH sides) -- SYNTHETIC, NEVER ABI truth, NEVER a tracked cp, the
# row-20 RE-CITE ledger ABSORBS it (the NEXT ledger line grows). The daq3
# graft MASTERS (73fdbc39/f683749c) md5-asserted NEVER cp'd NEVER promoted.
# DONOR = ipheavy ext#4 tree 140-file face (the tc/22a donor identity; the
# 22b graft-version law SATISFIED AS-IS: daq_common 9b603f8f carries
# MAX_DAQ_VERDICT==6; the fead0027 graft-v2 NEVER applies HERE -- tracer.cc
# pulls NO flow.h). STALE-DONOR LAW applied: find tracer* IN the donor tree =
# EXACTLY-0 (the packet tracer-era stale-header trees are the f* family, NEVER
# this donor) + 2 FRESH cps (the row .cc VERBATIM cmp-proved + the row .h).
# WITNESS = OWN-3 face (witness_tracer.cc, the honest sfd FOUND-0 precedent):
# snort_strdup (the REAL body rides a utils TU the donor NEVER compiled) +
# layer::get_inner_ip6_frag() (the layer.cc provider NOT donor-resident; the
# pull ip.cc:112 UNREACHABLE on the tracer ladder -> nullptr mirror, NEVER
# invented) + ts_print (util.cc:140 REAL home CITED not linked -- the
# get_conf-null SEGV face; the witness mirrors the util.cc:148/:192 DEFAULT
# arm over the fixed anchor). packet-h mirror face in the PROBE TU (Packet
# ctor/dtor no-ops + PacketManager::max_layers=40, packet.cc's Active/Layer
# alloc ctor body NEVER reached by the tracer read-set). ONE-HOME pins:
# ts_print DEFINITION == 1 across the link; ZERO get_conf on the probe link
# face; the E9 ONE-FACE flipped-assert: co-linking util.o WITH the witness =
# EXACTLY-2 'multiple definition' lines (snort_strdup + ts_print) rc!=0
# receipt measured at recon. THE row .o nm app-undef census = EXACTLY-2
# (SfIp::ntop + ts_print -- the cleanest of the chapter; CLOSED to 0 at link
# by the REAL sf_ip.o + the witness).
# ZERO-GATE row face (RE-MEASURED by walk NEVER pre-assumed): tracer.cc/h
# UNIT_TEST/TEST_CASE/'^TEST(' grep-0 x2; src/framework/test/CMakeLists.txt
# add_cpputest EXACTLY-3, tracer grep-0 (the misc9 face RE-CONFIRMED at the
# row); NO rider suite EVER -> dialect cites only -> ZERO gate artifacts
# (test ! -e gate.txt; the 22a streak-closure does NOT re-arm). THE gate
# census FLIPPED forward row 23e, re-run EVERY build: 27 on-disk gate.txt /
# legacy 4826fc22 x9 FROZEN / 20 distinct md5 lineages [23f rider] / tracked-1 (gre
# 6751d1a8) -- the sfd parity rider (tests/sfd_parity_test.rs HARD-ASSERTS
# 26, the 62d6fac lesson) STAYS green because this row ships ZERO gate.
# FACE-A = NOLOAD framework-TU (the 19a/21a precedent): BUILDING_SO/
# snort_plugins grep-0 x2 on BOTH ground files; ZERO enums/tables/sids (the
# 21a-table contrast law); hearts = THE C-ABI TRUTH THE PORT CANNOT MIRROR:
# sizeof(BaseApi)=64 + sizeof(TraceLogApi)=88 + the BaseApi-PREFIX face (the
# base_api.h :74 comment observed: the record head IS the enum ordinal) +
# the h-NSDMI cold map + the typedef INSTANTIATION face (stub addresses fill
# the api slots, NEVER called) + the NO-statics per-object ISOLATE law.
# NAME CENSUS (measured at the row): `tracer_harness` = 0 hits in EVERY other
# tools/*/build.sh; NEXT.md rides the token EXACTLY-1 (the name-PIN law line
# ONLY); the bare `tracer` pre-hit = f*-family build.sh FILES (the 13 at the
# 22b landing; SANCTIONED 13->16 now — the daqio/sfinst/sfmod re-clones ride
# the template cite honestly; see the :115 flip-forward comment below): (the
# packet tracer (packet-underscore tracer) donor cargo, pinned EXACTLY-13 as the honest census hazard
# face, NEVER edited); the packet-underscore-tracer token NEVER rides THIS file (grep-0
# arm); the misc9 :461 landmine (ReloadSurvivor|reload_survivor|struct
# Tracer over src/) NEVER edited -- the Rust naming keeps the `struct Tracer`
# leg find-0 (names ride the C names verbatim; `struct Tracer` grep-0 arm on
# the own rs). 8 stageables STATE-AWARE census (the 21b/21a 8-face shape
# MEASURED at the row, NOT inherited: ZERO gate material = ZERO runner TU).
# NEXT.md CITE-ONLY (NEVER edit; the tc :649-:656 NEWEST template RE-CLONED
# + the NEW 650 seed x3): 633/629/621/605/597 x3, 588 x4, 580-PASSED x3,
# 573 x5 PRESENCE (the sfd :641 + tc :656 ENFORCE the 5-count; keep it).
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
IP=$R/tools/ipheavy_harness          # THE donor (140-file ext#4 tree; self-heal)
D3=$R/tools/daq3_harness             # graft MASTER cites (never cp'd HERE)
C=$H/copy

# ---- ground identity (RE-MEASURED EXACT vs the 22a-docs bank; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC/src/framework/tracer.cc")" -eq 73
test "$(md5sum "$SRC/src/framework/tracer.cc" | awk '{print $1}')" = "9ee6b2ee33c4c98144f6a575891d1679"
test "$(wc -l < "$SRC/src/framework/tracer.h")" -eq 125
test "$(md5sum "$SRC/src/framework/tracer.h" | awk '{print $1}')" = "98d53205a5ddaff48ba5c304d0658931"
test "$(( 73 + 125 ))" -eq 198                                    # pair ledger
# the CMakeLists ride face (framework OBJECT lib; the :28/:53 sed pins)
test "$(grep -c 'tracer.h' "$SRC/src/framework/CMakeLists.txt")" -eq 1
test "$(grep -c 'tracer.cc' "$SRC/src/framework/CMakeLists.txt")" -eq 1
test "$(sed -n '28p' "$SRC/src/framework/CMakeLists.txt")" = "    tracer.h"
test "$(sed -n '53p' "$SRC/src/framework/CMakeLists.txt")" = "    tracer.cc"

# ---- ground sed pins (line-exact, disk wins) ----
test "$(sed -n '33p' "$SRC/src/framework/tracer.h")" = '#define TRACE_LOGAPI_VERSION ((BASE_API_VERSION << 16) | 2)'
test "$(sed -n '35p' "$SRC/src/framework/tracer.h")" = '#define TRACER_FLAG__RESERVED 0x0'
test "$(sed -n '112p' "$SRC/src/framework/tracer.h")" = 'typedef TraceLoggerPlug* (* TraceLogNewFunc)(class Module*, const std::string& name);'
test "$(sed -n '113p' "$SRC/src/framework/tracer.h")" = 'typedef void (* TraceLogDelFunc)(TraceLoggerPlug*);'
test "$(sed -n '115p' "$SRC/src/framework/tracer.h")" = 'struct TraceLogApi'
test "$(sed -n '52p' "$SRC/src/framework/tracer.cc")" = '    ss << " AS=" << p->pkth->address_space_id;'
test "$(sed -n '54p' "$SRC/src/framework/tracer.cc")" = '    if (p->pkth->tenant_id)'
test "$(sed -n '55p' "$SRC/src/framework/tracer.cc")" = '        ss << " TN=" << p->pkth->tenant_id;'
test "$(sed -n '69p' "$SRC/src/framework/tracer.cc")" = '    ts_print(nullptr, ts);'
test "$(sed -n '122p' "$SRC/src/utils/util.h")" = 'SO_PUBLIC void ts_print(const struct timeval*, char*, bool yyyymmdd = false);'
test "$(sed -n '67p' "$SRC/src/utils/util.h")" = '#define TIMEBUF_SIZE 27'
test "$(sed -n '143p' "$SRC/src/protocols/layer.h")" = 'SO_PUBLIC const ip::IP6Frag* get_inner_ip6_frag();'
# ground arithmetic faces (the Rust consts' cites): BASE_API_VERSION 29 +
# the PT_TRACE ordinal face (base_api.h :41 + :52-:63 -- PT_TRACE = 10 the
# ordinal the h rides via framework/base_api.h include tracer.h :25).
test "$(sed -n '41p' "$SRC/src/framework/base_api.h")" = '#define BASE_API_VERSION 29'
test "$( (echo PT_CODEC; echo PT_INSPECTOR; echo PT_IPS_ACTION; echo PT_IPS_OPTION; echo PT_SEARCH_ENGINE; echo PT_SO_RULE; echo PT_LOGGER; echo PT_CONNECTOR; echo PT_POLICY_SELECTOR; echo PT_MP_TRANSPORT; echo PT_TRACE; echo PT_MAX) | grep -n 'PT_TRACE' | cut -d: -f1 )" -eq 11   # 1-based face == 0-based ordinal 10

# ---- name-pin census (measured THIS pass; collision fires LOUDLY) ----
test "$(find "$R"/tools -maxdepth 1 -iname '*tracer*' | wc -l)" -eq 2          # SANCTIONED row-23f flip-forward 1->2: the row-23f harness dir (THE THIRD real gate row) legitimately JOINS this dir-name glob; NEVER a third without a new row
test "$(grep -rl 'tracer_harness' "$R"/tools/*/build.sh | grep -v "^$H/build.sh$" | wc -l)" -eq 2   # SANCTIONED 0->2 at the 23c docs rider (the 62d6fac flip-forward law): the face = ONLY the two legitimate template re-clone TR= cite lines (daqio_harness :94 + sfinst_harness :117 'TR=$R/tools/tracer_harness the 22b pkth-EXT face cite'); NEVER edit those cites; flip-forward only if ANOTHER re-clone rides
test "$(grep -c 'tracer_harness' "$R/NEXT.md")" -eq 1                         # the ONE tolerated law-cite line (:789)
test "$(grep -rl 'tracer' "$R"/tools/*/build.sh | grep -v "^$H/build.sh$" | wc -l)" -eq 16          # SANCTIONED 13->16 at the 23c docs rider (the 62d6fac flip-forward law): the 23a/23b/23c harness build.sh files (daqio + sfinst + sfmod) legitimately RE-CLONE this template shape and cite the tracer arms — the 3 new members are daqio_harness :73/:94/:201, sfinst_harness :53/:117, sfmod_harness comment faces; NEVER edit those citations; flip-forward only if ANOTHER template re-clone lands (hazard face, FROZEN)
# the packet-underscore-tracer token NEVER rides this file (self-match-safe arm:
# the ERE splits the token so THIS line is never a hit -- the sfd [ ]-split twin):
test "$(grep -cE 'packet_(tr)acer' "$H/build.sh" || true)" -eq 0
# the misc9 landmine stays satisfiable by NAMING (direct-md5-verify face, NEVER edit it):
test "$(grep -rl 'struct Tracer' "$R/src" --include=*.rs | wc -l)" -eq 0       # the Rust naming face (21b-era pre-port 0 grows to 0 post-port)

# ---- ZERO-suite / ZERO-gate census (the measured walk, NEVER inherited) ----
for f in framework/tracer.cc framework/tracer.h; do
    test "$(grep -c 'UNIT_TEST\|TEST_CASE\|TEST_GROUP\|^TEST(\|CppUTest' "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'BUILDING_SO'   "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'snort_plugins' "$SRC/src/$f" || true)" -eq 0
done
test "$(grep -ci daq "$SRC/src/framework/tracer.cc" || true)" -eq 0           # the daq wall rides the pkth TYPE face ONLY
test "$(grep -c 'add_cpputest' "$SRC/src/framework/test/CMakeLists.txt")" -eq 3   # UNDISTURBED (the misc9 face RE-CONFIRMED)
test "$(grep -ic tracer "$SRC/src/framework/test/CMakeLists.txt" || true)" -eq 0 # NO tracer suite EVER
test ! -e "$SRC/src/framework/test/tracer_test.cc"                            # find-0 face
# dialect host faces (find-0 faces, NEVER faked; re-measured):
test "$(find /usr/include -maxdepth 1 -iname 'CppUTest*' | wc -l)" -eq 0
test "$(find /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/local/lib -maxdepth 1 -name 'libCppUTest*' 2>/dev/null | wc -l)" -eq 0

# ---- NEXT.md CITE-ONLY read arms (the tc :649-:656 NEWEST template + seed) ----
test "$(grep -c '650 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '633 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '629 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '621 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '605 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '597 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c 'cc \*\*133\*\*' "$R/NEXT.md")" -ge 1        # the MUST-RIDE stale hwloc exhibit (face-agnostic: presence, NEVER a hardcode the docs pass must chase)
# the pkth-wall ledger cite face the row EXTENDS (NEXT :837-:840 names the
# tracer fields -- presence face, cite-ONLY):
grep -q 'address_space_id' "$R/NEXT.md"
grep -q 'get_pkthdr' "$R/NEXT.md"

# ---- copy tree = ipheavy DONOR clone (.o's purged); ext#4 ladder HEAD pins ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f | wc -l)" -eq 140                                  # 150-era face MEASURED non-.o = 140
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"   # GRAFT HEAD
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
# graft-MASTER cite faces (NEVER cp'd/edited here):
test "$(md5sum "$D3/copy/daq.h"        | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
# donor-resident carrier md5 pins (the ones THIS link consumes):
test "$(md5sum "$C"/sfip/sf_ip.cc         | awk '{print $1}')" = "a9505892c68927c7e0967f122e9908cb"
test "$(md5sum "$C"/protocols/ip.cc       | awk '{print $1}')" = "ee76e12acb6812aee267fc28191f4b7c"
test "$(md5sum "$C"/utils/util_cstring.cc | awk '{print $1}')" = "9f8173ee42a23f9135238edcb82e6fb2"
test "$(md5sum "$C"/utils/util.h          | awk '{print $1}')" = "bcf83e41122f55004dc8a31c45183ffc"
test "$(md5sum "$C"/sfip/sf_ip.h          | awk '{print $1}')" = "7ad22ccfcd9be0734353ca8166182534"
test "$(md5sum "$C"/protocols/layer.h     | awk '{print $1}')" = "4f02062b833180307b4e6518da00cfb1"
test "$(md5sum "$C"/main/thread.h         | awk '{print $1}')" = "272021f4d75e104ac478ff4c54547a56"
test "$(md5sum "$C"/config.h              | awk '{print $1}')" = "b5ad224e236fc4a36c19d3cfb71bb8da"
# byte-ident-vs-ground trio (the REAL-provider carriers; cmp-proved ground fe29cbe):
cmp -s "$C"/utils/util_cstring.cc "$SRC/src/utils/util_cstring.cc"
cmp -s "$C"/sfip/sf_ip.cc        "$SRC/src/sfip/sf_ip.cc"
cmp -s "$C"/protocols/ip.cc      "$SRC/src/protocols/ip.cc"
# STALE-DONOR face MEASURED: NO tracer.{h,cc} EVER in the donor tree (find-0
# BEFORE the fresh cps -- the stale tracer.h copy trees are the packet tracer-
# era f* family, NEVER this donor):
test "$(find "$C" -iname 'tracer*' | wc -l)" -eq 0

# ---- 2 FRESH cps day one (VERBATIM, cmp-proved, NEVER sed) ----
cp "$SRC"/src/framework/tracer.h "$C"/framework/tracer.h
cp "$SRC"/src/framework/tracer.cc "$C"/framework/tracer.cc
cmp -s "$C"/framework/tracer.h  "$SRC"/src/framework/tracer.h
cmp -s "$C"/framework/tracer.cc "$SRC"/src/framework/tracer.cc
test "$(find "$C" -type f | wc -l)" -eq 142                    # 140 + 2 fresh rows (graft IN-PLACE)

# ---- THE E4 PKTH WALL (flipped-assert EVERY build, pre-graft arm) ----
GXX0="g++ -std=c++17 -O0 -w -I$C"
if $GXX0 -c "$C"/framework/tracer.cc -o /dev/null 2> "$H"/E4_pkthwall.txt; then
    echo "E4 face flip BROKE: UNGRAFTED pkth compiled -- the real daq SDK landed? RE-PLAN"; exit 1
fi
test "$(grep -c "no member named .address_space_id." "$H"/E4_pkthwall.txt)" -eq 1
test "$(grep -c "no member named .tenant_id." "$H"/E4_pkthwall.txt)" -eq 2   # :54 + :55 (the . = gcc's smart-quote face)
# the pkth EXTENSION graft (COPY-LOCAL DECL rows; the row-20 ledger absorbs):
python3 - "$C" <<'GRAFT'
import sys
C = sys.argv[1]
p = C + "/daq_common.h"
s = open(p).read()
old = """struct DAQ_PktHdr_t {
    uint64_t flags = 0;
    int ingress_group = 0;
    int egress_group = 0;
};"""
new = """// ROW-22b pkth EXTENSION (COPY-LOCAL, SYNTHETIC, NEVER ABI truth; the real
// daqCommon.h face RE-CITED at row 20; the tracer.cc :52/:54-:55 reads):
struct DAQ_PktHdr_t {
    uint64_t flags = 0;
    int ingress_group = 0;
    int egress_group = 0;
    uint16_t address_space_id = 0;
    uint32_t tenant_id = 0;
};"""
assert old in s
open(p, "w").write(s.replace(old, new))
print("GRAFT_PKTH_OK")
GRAFT
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "b99e44b9f7ef1d009bf7f158982bfb4e"   # THE EXTENDED face (HEAD-pin flips ONLY here, copy-local)
post_tail=$(mktemp); $GXX0 -c "$C"/framework/tracer.cc -o "$C"/framework/tracer.o 2> "$H"/E4_postgraft.txt
test ! -s "$H"/E4_postgraft.txt                        # post-graft compile SILENT rc0
rm -f "$post_tail"
cp "$C"/framework/tracer.o "$H"/tracer.o

# ---- O0/O2 production arms ----
GXX="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C"
$GXX -c "$H"/witness_tracer.cc -o "$H"/witness_tracer.o
$GXX -c "$H"/probe.cc -o "$H"/probe.o
$GXX -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o
$GXX -c "$SRC"/src/sfip/sf_ip.cc -o "$H"/sf_ip.o 2>/dev/null || $GXX -c "$C"/sfip/sf_ip.cc -o "$H"/sf_ip.o
$GXX -c "$C"/protocols/ip.cc -o "$H"/ip.o
$GXX -c "$C"/utils/util_cstring.cc -o "$H"/util_cstring.o
# NOTE the util.cc REAL provider NEVER linked at probe face (the get_conf-null
# SEGV + wall-clock face -- the ts_print witness law); util.o compiled from
# the graft ONLY as the E9 dup-leg input:
$GXX -c "$C"/utils/util.cc -o "$H"/util.o

# ---- THE row .o nm census (EXACTLY-2 app-undef -- the cleanest of the chapter) ----
undef() { nm -C -u "$1" | awk '/ U /{sub(/^[[:space:]]*U[[:space:]]*/,"");print}' \
  | grep -vE '^(std::|operator |__|_Unwind|typeinfo|vtable|abort$|free$|mem(move|set|cpy)$|strlen$|syscall$|pthread_|gettid$|_GLOBAL|exp10)' | sort -u; }
undef "$H"/tracer.o > "$H"/nm_U_tracer.txt
test "$(wc -l < "$H"/nm_U_tracer.txt)" -eq 2
test "$(grep -c 'SfIp::ntop' "$H"/nm_U_tracer.txt)" -eq 1
test "$(grep -c 'ts_print'   "$H"/nm_U_tracer.txt)" -eq 1
test "$(grep -c 'get_conf'   "$H"/nm_U_tracer.txt || true)" -eq 0            # the witness law's proof face

# ---- E9 ONE-FACE flipped-assert (the ONE-home law receipt, recon face EXACTLY-2) ----
if $GXX "$H"/probe.o "$H"/tracer.o "$H"/ip.o "$H"/sf_ip.o "$H"/util_cstring.o "$H"/util.o "$H"/witness_tracer.o -o "$H"/E9_dup_probe 2> "$H"/E9_dup.txt; then
    echo "E9 law BROKE: util.o + witness co-link LINKED"; exit 1
fi
rm -f "$H"/E9_dup_probe
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 2                # snort_strdup + ts_print

# ---- DEC + FACE-A link + run (the real-carrier link face; ZERO get_conf) ----
LINK="$H/tracer.o $H/ip.o $H/sf_ip.o $H/util_cstring.o $H/witness_tracer.o"
$GXX "$H"/probe.o      $LINK -o "$H"/probe
$GXX "$H"/probe_faceA.o $LINK -o "$H"/probe_faceA
test "$(nm -C --defined-only "$H"/probe | grep -c 'T snort::ts_print')" -eq 1     # ONE-HOME
test "$(nm -C "$H"/probe "$H"/probe_faceA | grep -c 'get_conf' || true)" -eq 0
timeout 60 "$H"/probe      > "$H"/vectors_O0.txt        || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_faceA > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL FACE-A O0; exit 1; }

# ---- O2 twins + the x-stream byte-identity law ----
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
$GXXA -c "$H"/witness_tracer.cc -o "$O2"/witness_tracer.o
$GXXA -c "$H"/probe.cc        -o "$O2"/probe.o
$GXXA -c "$H"/probe_faceA.cc  -o "$O2"/probe_faceA.o
$GXXA -c "$C"/sfip/sf_ip.cc   -o "$O2"/sf_ip.o
$GXXA -c "$C"/protocols/ip.cc -o "$O2"/ip.o
$GXXA -c "$C"/utils/util_cstring.cc -o "$O2"/util_cstring.o
$GXXA -c "$C"/framework/tracer.cc -o "$O2"/tracer.o          # the FRESH re-compile flipped-md5 face (NEVER re-ride tracer.o)
$GXXA -c "$C"/framework/tracer.cc -o /dev/null 2> "$H"/E4_postgraft_o2.txt
test ! -s "$H"/E4_postgraft_o2.txt
LINK2="$O2/tracer.o $O2/ip.o $O2/sf_ip.o $O2/util_cstring.o $O2/witness_tracer.o"
$GXXA "$O2"/probe.o        $LINK2 -o "$H"/probe_O2
$GXXA "$O2"/probe_faceA.o $LINK2 -o "$H"/probe_faceA_O2
timeout 60 "$H"/probe_O2        > "$H"/vectors_O2.txt        || { echo PROBE_FAIL DEC O2; exit 1; }
timeout 60 "$H"/probe_faceA_O2  > "$H"/vectors_faceA_O2.txt  || { echo PROBE_FAIL FACE-A O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt

# ---- FIRST-RUN-SEED face (17p law; NEVER typed) ----
if [ ! -e "$H"/vectors.txt ]; then
    cp "$H"/vectors_O0.txt "$H"/vectors.txt                      # SEED PASS (first run ever)
    cp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt          # SEED PASS
    echo "SEED PASS: DEC + FACE-A vectors measured (NEVER typed)"
else
    cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt           || { echo "VECTORS DEC DRIFT vs tracked vectors.txt"; exit 1; }
    cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "VECTORS FACE-A DRIFT vs tracked"; exit 1; }
fi
test -e "$H"/vectors.txt
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt   # receipt (ignored)

# ---- TAMPER-PROVEN blocks (the sfd/tc law) ----
cp "$H"/vectors.txt "$H"/.vectors_pristine
line=$(grep -n '^T1 ' "$H"/vectors.txt | head -1 | cut -d: -f1)
sed -i "${line}s/TN=42/TN=41/" "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt && { echo "TAMPER ARM DEAD: flipped DEC still matches the fresh run"; exit 1; }
cp "$H"/.vectors_pristine "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "TAMPER RESTORE DEAD"; exit 1; }
rm -f "$H"/.vectors_pristine
cp "$H"/vectors_faceA.txt "$H"/.vectors_faceA_pristine
line=$(grep -n '^SIZES ' "$H"/vectors_faceA.txt | head -1 | cut -d: -f1)
sed -i "${line}s/base=64/base=63/" "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt && { echo "TAMPER ARM DEAD (FACE-A): flipped face still matches"; exit 1; }
cp "$H"/.vectors_faceA_pristine "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "TAMPER RESTORE DEAD (FACE-A)"; exit 1; }
rm -f "$H"/.vectors_faceA_pristine

# ---- vectors FACE greps (the ladder face pins; line counts from the MEASURED file) ----
V=$H/vectors.txt; FA=$H/vectors_faceA.txt
test "$(wc -l < "$V")" -eq 10
test "$(wc -l < "$FA")" -eq 8                     # MEASURED 8-L face (the sfd-twin count; NOT 9 -- disk wins)
grep -q '^T0 ntuple_off=\[\] ts_off=\[\]$' "$V"
grep -q '^T1 v4tcp=\[203.0.113.7 1234 -> 198.51.100.23 80 6 AS=7 TN=42 \]$' "$V"
grep -q '^T2 udp=\[203.0.113.7 5353 -> 198.51.100.23 53 17 AS=7 TN=42 \]$' "$V"
grep -q '^T3 icmp_ports0=\[203.0.113.7 0 -> 198.51.100.23 0 1 AS=7 TN=42 \]$' "$V"    # the cc :44 port-GATE face: ports STAY 0
grep -q '^T4 tn0=\[203.0.113.7 0 -> 198.51.100.23 0 6 AS=0 \]$' "$V"                   # tenant 0 -> NO TN= (the trailing-space face)
grep -q '^T5 api_none=\[\]$' "$V"
grep -q '^T6 nullp=\[\]$' "$V"
grep -q '^T7 v6_ceils=\[2001:db8::cafe 1 -> 2001:db8::feed 2 17 AS=65535 TN=4294967295 \]$' "$V"  # the UINT16/UINT32 ceiling faces
grep -q '^T8 ts_on=\[03/14-09:00:00.000123:\]$' "$V"                                   # the witness anchor face
grep -q "^T9 map=PCO id=7 name=probe ntuple_backoff=\[\] api_null=1\$" "$V"
test "$(grep -c '^T' "$V")" -eq 10
test "$(grep -c 'WIT_' "$V" || true)" -eq 0                                            # honest vectors face (sfd/tc twin arms)
grep -q '^NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2$' "$FA"
grep -q '^APIV logapi=1900546 reserved=0 pt_trace=10$' "$FA"
grep -q '^SIZES base=64 tracelogapi=88$' "$FA"                                          # THE C-ABI face the port CANNOT mirror
grep -q "^DEFMAP cold='O' id=0 ntuple=0 ts=0 api_null=1\$" "$FA"
grep -q '^NAME roundtrip=alt-plug=1$' "$FA"
grep -q '^APIStruct head=10 ver_ok=1 ctor_set=1 dtor_set=1 flags=0$' "$FA"
grep -q '^SETAPI roundtrip=1 flags0=1$' "$FA"
grep -q '^ISOLATE a_set=1 b_null=1$' "$FA"

# ---- ground-cite two-way face (disk wins; the cc line-arms the probes ride) ----
python3 - "$SRC" "$H" <<'PYPIN'
import sys
SRC, H = sys.argv[1], sys.argv[2]
cc = open(SRC + "/src/framework/tracer.cc").read().splitlines()
h  = open(SRC + "/src/framework/tracer.h").read().splitlines()
assert len(cc) == 73 and len(h) == 125
assert cc[31].strip().startswith("if ( !ntuple or !p or !p->ptrs.ip_api.is_valid()")   # :32 the guard face
assert "PROTO_BIT__TCP | PROTO_BIT__UDP" in cc[43]                                     # :44 the port gate
assert cc[51] == '    ss << " AS=" << p->pkth->address_space_id;'                     # :52 exact
assert "address_space_id" in cc[51] and "AS=" in cc[51]                                # :52
assert "if (p->pkth->tenant_id)" == cc[53].strip()                                     # :54
assert "ts_print(nullptr, ts);" == cc[68].strip()                                      # :69
assert 'TIMEBUF_SIZE' in cc[67]                                                        # :68 the 27-buffer face
assert "virtual void log(const char* msg" in h[48]                                     # :49 the pure face
assert "thread_type = 'O';" in h[89] and "case STHREAD_TYPE_PACKET:" in h[82]          # :79-:92 the switch
assert h[107].strip() == "char thread_type = 'O';"                                     # :108 the NSDMI default
v = open(H + "/vectors.txt").read(); fa = open(H + "/vectors_faceA.txt").read()
assert "AS=7 TN=42" in v and "AS=0" in v                                               # the pkth-face pair
assert "logapi=1900546" in fa and (29 << 16 | 2) == 1900546                            # the version arithmetic
print("PYPIN_OK")
PYPIN

# ---- GATE census (ZERO-gate row: the MEASURED face STAYS; run by walk, never typed) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af'); test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 28   # SANCTIONED row-23e gate flip (the SECOND real gate row: the row-23e new gate.txt md5 bc199753 COPY-LOCAL UNTRACKED, in-TU Catch EXACTLY-3 TEST_CASE x 13 CHECK; walked census 26->27 on-disk / 18->19 lineages; legacy x9 + gre anchor + tracked-1 UNTOUCHED; the 62d6fac complete-flip law) [ROW-2->28 rider: 62d6fac law]
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(cat "$H/gate_md5_lineages.txt")" -eq 20   # SANCTIONED row-23e gate flip (the SECOND real gate row: the row-23e new gate.txt md5 bc199753 COPY-LOCAL UNTRACKED, in-TU Catch EXACTLY-3 TEST_CASE x 13 CHECK; walked 26->27 on-disk / 18->19 lineages; legacy x9 + gre anchor + tracked-1 UNTOUCHED; the 62d6fac complete-flip law) [ROW-23f rider 19->20: the THIRD real gate row fresh tail (the p-tracer gate); the 62d6fac complete-flip law, missed-holder repair before cold-chain]
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"   # the ONLY tracked gate byte-frozen
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1
test ! -e "$H/gate.txt"                                              # ZERO gate artifacts ship
git -C "$R" check-ignore -q tools/tracer_harness/gate.txt            # the NEVER-land posture is IGNORED-proved

# ---- backbone10 + frozen lineage echoes (direct-md5 law, NEVER chase rc0) ----
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
test "$(wc -l < "$H/backbone10.txt")" -eq 10                               # backbone STAYS 10 (symbol-vs-array law: the row adds NO backbone symbol)
# the ch19-era frozen chain-echo (the 21b + 21a heads; the LEGAL echo face).
# TOKEN-NEVER-RIDDEN law (the 21b donor precedent): dir tokens are runtime-
# CONCATENATED so THIS build.sh carries ZERO foreign harness-dir tokens
# (the sibling name-pin census arms STAY byte-undisturbed by this row):
SF=$R/tools/sf""d_harness
RSB=$R/tools/rs""ubs_harness
test "$(md5sum "$SF"/vectors.txt     | awk '{print $1}')" = "3c05632e88676ef9f40ee0a5d33fdf09"
test "$(md5sum "$SF"/vectors_faceA.txt | awk '{print $1}')" = "040de1ef2ea177ac526c8ef244713c58"
test "$(md5sum "$RSB"/vectors.txt   | awk '{print $1}')" = "9e303761c021d00ea672a493544e07af"
test "$(md5sum "$RSB"/vectors_faceA.txt | awk '{print $1}')" = "42aa06fb4c55adfa50e96d1f715d997e"
grep -q 'SFD_DONE vectors=' "$SF/build.sh"
grep -q 'R_SUBS_DONE vectors=' "$RSB/build.sh"

# ---- STATE-AWARE 8-face stageables dual guard (pre-commit untracked / post-commit tracked) ----
untracked=$(git -C "$R" ls-files --others --exclude-standard tools/tracer_harness | sort)
tracked=$(git -C "$R" ls-files tools/tracer_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 8                     # MEASURED 8-face shape (no runner TU: ZERO gate material)
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_tracer.cc .gitignore; do
    echo "$face" | grep -q "tools/tracer_harness/$f$" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
# check-ignore loop (every copy-local artifact gets an EXPLICIT arm):
for f in copy/daq_common.h copy/framework/tracer.cc copy/framework/tracer.o o2/tracer.o probe probe_O2 \
         probe_faceA probe_faceA_O2 tracer.o witness_tracer.o util.o vectors_O0.txt vectors_faceA_O2.txt \
         nm_U_tracer.txt E4_pkthwall.txt E4_postgraft.txt E9_dup.txt md5_pinned.txt \
         gate_md5_lineages.txt stageables.txt backbone10.txt vectors_O2.txt vectors_faceA_O0.txt .vectors_faceA_pristine; do
    git -C "$R" check-ignore -q "tools/tracer_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_tracer.cc .gitignore; do
    git -C "$R" check-ignore -q "tools/tracer_harness/$f" && { echo "WRONGLY IGNORED: $f"; exit 1; } || true
done
if git -C "$R" ls-files --error-unmatch tools/tracer_harness/PLAN.md >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files tools/tracer_harness | wc -l)" -eq 8
    test -z "$(git -C "$R" ls-files tools/tracer_harness | grep -vE 'PLAN\.md|build\.sh|probe\.cc|probe_faceA\.cc|vectors(_faceA)?\.txt|witness_tracer\.cc|\.gitignore')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard tools/tracer_harness)"   # ZERO-LEAK post-commit
else
    git -C "$R" status --porcelain | grep -qx '?? tools/tracer_harness/'
    test "$(echo "$untracked" | wc -l)" -eq 8
fi
test -z "$(git -C "$R" diff --name-only --cached)"        # ZERO staged churn
dirty=$(git -C "$R" status --porcelain | grep -vcE '^\?\? tools/tracer_harness/$|^ M "?(src/framework/mod\.rs|src/sfip/sf_ip\.rs|PORTING_PLAN\.md|KNOWN DEVIATIONS\.md)"?$|^\?\? src/framework/tracer\.rs$|^\?\? tests/tracer_parity_test\.rs$' || true)
test "$dirty" -eq 0                                       # single-tenant porcelain face (row stageables + the landed rs/tests face)

# ---- tail ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "pkth wall: ungrafted EXACTLY-3 no-member faces; graft = COPY-LOCAL DECL arms b99e44b9, the row-20 ledger absorbs"
echo "nm app-undef on tracer.o: EXACTLY-2 (ntop+ts_print); E9 dup co-link EXACTLY-2 multiple-defs receipt"
echo "gate census (walked, never typed): 28 on-disk / legacy 9 x 4826fc22 / 20 lineages [23f rider] / tracked-1 gre; ZERO gate ships row 22b"
echo "backbone STAYS $(wc -l < "$H/backbone10.txt") (symbol-vs-array)"
echo "TRACER_DONE vectors=$(wc -l < "$H/vectors.txt") faceA=$(wc -l < "$H/vectors_faceA.txt") gates=0 (ch19 LAST row; the 22a streak face does NOT re-arm)"
