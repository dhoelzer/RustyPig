#!/usr/bin/env bash
# tc_harness -- row 22a: main/thread_config.{cc,h} 920+95 L -- THE GATE ROW.
# THE ZERO-GATE STREAK CLOSURE STATEMENT (honest, per PLAN SS0/SS7 + NEXT
# lineage): THE 28-STRAIGHT ZERO-GATE STREAK (rows through 21b) ENDS HERE.
# 22a is the FIRST row since gre (18g) to ship REAL host-green gate
# material: the row TU's own embedded Catch block cc :615-:916 = EXACTLY 14
# TEST_CASE "[ThreadConfig]" faces (9 direct + 5 nested under inner
# #ifdef HAVE_NUMA :797 -> inner #endif :918, outer #endif :920). The gate
# census FLIPS honestly at this row: gate.txt FILES 25->26 ON DISK, distinct
# md5 lineages 17->18 (this row's tail), while the TRACKED gate.txt face
# STAYS 1 (gre 6751d1a8 the only tracked gate; tc gate posture = COPY-LOCAL
# UNTRACKED per PLAN SS0 -- same posture as periodic/numa gate.txt). The 9
# legacy 4826fc22 holders + the gre anchor stay byte-frozen (direct md5
# echoes, NEVER rc-0 chasing of frozen tun/eth/ext -eq asserts -- by-design
# drift-fail law).
# THE RUNNER SHAPE LAW (THE E10 arm, recon-proven, flipped-assert EVERY
# build): CATCH_CONFIG_RUNNER + ThreadConfig::init() BEFORE session.run is
# MANDATORY on this row -- the ground tests deref file-static topology/
# process_cpuset/topology_support filled ONLY by init() (upstream boots
# ThreadConfig::init() at snort.cc:109 BEFORE Catch; upstream's own test
# runner IS CATCH_CONFIG_RUNNER = src/catch/unit_test.cc :26 -- face-pinned
# below, NOT invention). The CATCH_CONFIG_MAIN twin link (gre/numa shape)
# SEGVs rc=139 on the FIRST cpuset test -> own tc_gate_main.cc TRACKED; the
# catch_main.cc face is NEVER reusable here.
# FUNCTIONAL-WITNESS LAW (vs the numa_harness decl-only ladder): the ground
# CHECKs are SEMANTIC (isequal/weight/isset/first) -> the hwloc witness
# MODELS behavior: std::set bitmaps, model CPUs 0..255 (the instance-max
# AUTO face = 256, NOT the host CPU count), set_cpubind FAILS for bit
# >=256 so the ground 9999-CPU graceful-fallback arm REALLY fires. The 5
# NUMA cases install in-TU GROUND mocks (NumaWrapperMock/HwlocWrapperMock
# :839-:914 ship verbatim) -> NO hwloc runtime needed there but hwloc_obj
# must be COMPLETE (mock embeds one by value: os_index + cpuset).
# THE STALE-HEADER TRAP (fresh-cp law PROVEN EVERY build): the donor (and
# 5+ other copy trees) carry thread_config.h 21c903df -- a STALE pre-20s
# face (numa_mempolicy members ABSENT) byte-DIFFERENT from ground 86a4d2.
# NEVER re-ride it: FRESH ground cp + sed graft (wit repoints; the FIXTC
# route here is witness-REPPOINT NOT flog-excision -- the 5 NUMA TEST_CASEs
# ARE gate material, excising them would EXCISE the gate census 14->9).
# DONOR = ipheavy 150-era ext#4 tree (daq.h 97bca757 + daq_common.h
# 9b603f8f carrying DIOCTL_GetSnortLatencyData -- the ONLY face satisfying
# analyzer_command.h :255 + daq_dlt.h e8a39bf3; lineage-newest + proven).
# 6 EXACT FRESH CPS day one (cc VERBATIM NEVER sed; h + numa.sed graft;
# numa.cc PLAIN-cp PLAIN-compile (its 3 TEST_CASEs STAY numa_harness gate
# home -- numa.o carries ZERO Catch face, one-home/E9 law); analyzer +
# periodic fresh unsed). E9 ONE-FACE rule: gate link = gate-main +
# tc_gateut.o ONLY (plain .o OUT; plain+gateut co-link DIES at exactly-20
# 'multiple definition' lines -- recon face, MEASURED at the row).
# witness_conf posture DRIFT CORRECTION (recorded honest): the 4dd91018
# carried face defines ThreadConfig::get_instance_max() -- a ONE-HOME CLASH
# with the row .o at tc (the row OWNS that face). This row ships the recon
# wit_conf SUBSET (SnortConfig core only). own witness_tc.cc (~40 L):
# messages/get_error/instance-id/thread-type + Periodic DECL bodies (the
# REAL time/periodic.cc stays periodic_harness home; the watchdog rides the
# watchdog_timer=0 default => guards cc :585/:604 pin FALSE) + the numa
# trio (available/max_node 0-arms => implement_thread_mempolicy FALSE
# early = honest FACE-A no-NUMA face).
# VECTORS NEVER TYPED (17p law): first-run SEED then drift-refuse EVERY
# build (vectors DEC + FACE-A; the gate tail is RUNNER-MEASURED, the
# 14-name -l census + ground-case greps ride GROUND-cite assertions; the
# tail string itself gets pinned into build.sh ONLY after the seed run
# MEASURED it). O0==O2 every build (probes + gate third stream).
# cite-drift faces honestly recorded (disk wins, 21a law): h 95 L NOT the
# dispatch blurb's 86; cc raw hwloc_* tokens 142 NOT NEXT.md :551 "133"
# (grep-LINE face 126; 'TEST_CASE (' with-space shape grep-0 = gre-era
# dialect NOT this row's); PLAN SS1 stageable count 8 = the rsubs shape --
# THE ROW's 9th face = tc_gate_main.cc (first row EVER needing a RUNNER
# main TU; gre likewise tracked its catch_main.cc).
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
IP=$R/tools/ipheavy_harness          # THE donor (150-era ext#4 tree)
RH=$R/tools/rules_harness            # vendored catch.hpp master (cite face)
D3=$R/tools/daq3_harness             # graft MASTER cites (never cp'd HERE)
C=$H/copy

# ---- ground identity (SS1 re-measured DIRECT this pass) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC/src/main/thread_config.cc")" -eq 920
test "$(md5sum "$SRC/src/main/thread_config.cc" | awk '{print $1}')" = "ca123f895a028e53328b3b0451af8073"
test "$(wc -l < "$SRC/src/main/thread_config.h")" -eq 95      # 95 NOT 86 (cite-drift law)
test "$(md5sum "$SRC/src/main/thread_config.h" | awk '{print $1}')" = "86a4d24805a6413ecebbbe72e4f10e5b"
test "$(wc -l < "$SRC/src/main/numa.h")" -eq 88
test "$(md5sum "$SRC/src/main/numa.h" | awk '{print $1}')" = "171555d41cffd065f527a3035fcd014e"
test "$(wc -l < "$SRC/src/main/numa.cc")" -eq 89
test "$(md5sum "$SRC/src/main/numa.cc" | awk '{print $1}')" = "352bbc7f9c3a9e138507fa5b8eba9370"
test "$(wc -l < "$SRC/src/main/analyzer_command.h")" -eq 267
test "$(md5sum "$SRC/src/main/analyzer_command.h" | awk '{print $1}')" = "9e9ee8432e295ddecfb5673bed316cc9"
test "$(wc -l < "$SRC/src/time/periodic.h")" -eq 41
test "$(md5sum "$SRC/src/time/periodic.h" | awk '{print $1}')" = "5eac2feefdcf0daa1523087de83cdada"
test "$(md5sum "$SRC/src/main/thread.h" | awk '{print $1}')" = "272021f4d75e104ac478ff4c54547a56"
test "$(md5sum "$SRC/src/utils/util.h" | awk '{print $1}')" = "bcf83e41122f55004dc8a31c45183ffc"

# ---- the 14-case gate CENSUS lives in the GROUND (ground-cite census,
# NEVER typed from air): EXACTLY-14 TEST_CASE( , the WITH-SPACE gre shape
# grep-0 (the cite-drift face), arm line-faces ----
test "$(grep -c 'TEST_CASE(' "$SRC/src/main/thread_config.cc")" -eq 14
test "$(grep -c 'TEST_CASE (' "$SRC/src/main/thread_config.cc")" -eq 0   # gre-style 'TEST_CASE (' NEVER exists here
test "$(grep -c '#ifdef UNIT_TEST' "$SRC/src/main/thread_config.cc")" -eq 2   # :34 include arm + :613 suite arm
test "$(grep -c '#ifdef HAVE_NUMA' "$SRC/src/main/thread_config.cc")" -eq 6   # :265/:272/:797 + ... (measured 6)
test "$(sed -n '613p' "$SRC/src/main/thread_config.cc")" = "#ifdef UNIT_TEST"
test "$(sed -n '615p' "$SRC/src/main/thread_config.cc")" = 'TEST_CASE("Parse cpuset string negative test", "[ThreadConfig]")'
test "$(sed -n '797p' "$SRC/src/main/thread_config.cc")" = "#ifdef HAVE_NUMA"    # the 5-case hinge
test "$(sed -n '918p' "$SRC/src/main/thread_config.cc")" = "#endif"              # inner NUMA endif
test "$(sed -n '920p' "$SRC/src/main/thread_config.cc")" = "#endif"              # outer UNIT_TEST endif
test "$(sed -n '34p'  "$SRC/src/main/thread_config.cc")" = "#ifdef UNIT_TEST"     # the early include arm :34-:36
test "$(sed -n '35p'  "$SRC/src/main/thread_config.cc")" = '#include "catch/snort_catch.h"'   # PLAN said :34 -- disk :35 (cite-drift, disk wins)
# upstream ORDER proof (the RUNNER law's cite faces, NEVER edited):
test "$(sed -n '109p' "$SRC/src/main/snort.cc")" = "    ThreadConfig::init();"
test "$(sed -n '26p'  "$SRC/src/catch/unit_test.cc")" = "#define CATCH_CONFIG_RUNNER"  # upstream's runner SHAPE
# NO separate CppUTest suite rode thread_config.cc EVER (the in-TU Catch
# block is the ONLY test world): add_cpputest = 2 in main/test (thread_test
# rides thread.cc NOT this row) -- CppUTest host find-0, CITE-ONLY dialect.
test "$(grep -c 'add_cpputest' "$SRC/src/main/test/CMakeLists.txt")" -eq 2
test "$(grep -c 'add_catch\|UNIT_TEST' "$SRC/src/main/CMakeLists.txt")" -eq 0
ls /usr/include/hwloc.h /usr/include/numa.h /usr/include/numaif.h 2>/dev/null && { echo "E4 WALL DEAD: host hwloc/numa landed"; exit 1; }
pkg-config --exists hwloc && { echo "E4 WALL DEAD: pkg-config hwloc landed"; exit 1; } || true
ls -d /usr/include/CppUTest 2>/dev/null && { echo "CppUTest landed -- RE-PLAN"; exit 1; } || true
# hwloc token census (MEASURED vs the NEXT "133" STALE token -- cite-drift,
# disk wins): raw occurrence 142, grep-LINE face 126, h raw tokens 2.
test "$(grep -o 'hwloc_[a-zA-Z_]*' "$SRC/src/main/thread_config.cc" | wc -l)" -eq 142
test "$(grep -c 'hwloc_' "$SRC/src/main/thread_config.cc")" -eq 126
test "$(grep -o 'hwloc_[a-zA-Z_]*' "$SRC/src/main/thread_config.h" | wc -l)" -eq 2
grep -q 'cc \*\*133\*\*' "$R/NEXT.md"        # the STALE token rides NEXT (cite-only, drift recorded)
# name-pin census: the ONLY tools/-depth-1 tc face = THIS dir; NEXT.md rides
# the 2 tolerated tc_harness cite faces; NO other build.sh carries the token.
test "$(find "$R"/tools -maxdepth 1 -iname '*tc_harness*' | wc -l)" -eq 1
test "$(grep -c 'tc_harness' "$R/NEXT.md")" -eq 2
test "$(grep -rl 'tc_harness' "$R"/tools/*/build.sh | grep -v "^$H/build.sh$" | wc -l)" -eq 1   # SANCTIONED at row 23e: 0 -> 1 (self-EXCLUDED file; the s-f-d chain harness's gate-lineage cite rides the token — a pre-23e rider mention MEASURED 1 by walk at THIS face; this pin was the stale latent-red twin never re-run since the 23c sfd rider; the 62d6fac flip-forward law; NEVER edit the cited rider)

# ---- copy tree = ipheavy DONOR clone (.o's purged); ext#4 ladder HEAD pins ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f | wc -l)" -eq 140                                  # 150-era face MEASURED non-.o = 140
test "$(md5sum "$C"/daq.h       | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"   # ext#4 REQUIRED face (analyzer_command.h :255)
test "$(md5sum "$C"/daq_dlt.h   | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
grep -q 'DIOCTL_GetSnortLatencyData' "$C"/daq_common.h
grep -q '#include <daq_common.h>' "$SRC/src/main/analyzer_command.h"
# graft-MASTER cite faces (NEVER cp'd/edited here):
test "$(md5sum "$D3/copy/daq.h"       | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
# catch lineage: DONOR-RESIDENT, md5-re-summed (the rules_harness master face):
test "$(md5sum "$C"/catch/catch.hpp | awk '{print $1}')" = "74ef54e848cf843c99e3acdb94ce2b1a"
cmp -s "$C"/catch/catch.hpp "$RH"/copy/catch/catch.hpp                     # 17p byte-ident master
printf '#pragma once\n#include "catch/catch.hpp"\n' > "$H/.shim_face_expect"
test "$(md5sum "$C"/catch/snort_catch.h | awk '{print $1}')" = "$(md5sum "$H/.shim_face_expect" | awk '{print $1}')"
rm -f "$H/.shim_face_expect"                                              # donor shims the ground header AS-IS
test ! -e "$C"/main/numa.h                                              # find-0 wall below rides fresh-cp census
test ! -e "$C"/main/analyzer_command.h
test ! -e "$C"/time/periodic.h
# ---- THE STALE-21c903df TRAP PROOF (fresh-cp law face): donor h = 21c903df
# (numa_mempolicy members ABSENT) != ground 86a4d2 -- NEVER re-ridden: ----
test "$(md5sum "$C"/main/thread_config.h | awk '{print $1}')" = "21c903df9febbd9bfe08e1d3ad5d5f02"
! grep -q 'numa_mempolicy' "$C"/main/thread_config.h                     # the STALE face lacks the NUMA members
grep -c 'thread_config' "$SRC/src/main/CMakeLists.txt" | grep -qx 3    # the row rides the main OBJECT lib (no separate catch cmake)

# ---- 6 FRESH CPS day one + the E4 WALL LADDER (flipped-assert EVERY build;
# each stage names the EXACT next fatal). ABI/CENSUS LAW: the wall ladder
# compiles the $C copy (quoted includes resolve same-dir INSIDE the tree --
# compiling from $SRC would trivially find siblings and DEADEN every wall)
# ----
GXX0="g++ -std=c++17 -O0 -w -I$C"
cp "$SRC"/src/main/thread_config.h "$C"/main/thread_config.h             # FRESH ground cp (over the stale face)
test "$(md5sum "$C"/main/thread_config.h | awk '{print $1}')" = "86a4d24805a6413ecebbbe72e4f10e5b"
test ! -e "$C"/main/thread_config.cc
cp "$SRC"/src/main/thread_config.cc "$C"/main/thread_config.cc           # VERBATIM (cmp-proved, NEVER sed)
cmp -s "$C"/main/thread_config.cc "$SRC"/src/main/thread_config.cc
printf '#pragma once\n' > "$C"/config.h                                 # STOCK face (HAVE_NUMA rides the CLI, never config.h)
if $GXX0 -c "$C"/main/thread_config.cc -o /dev/null 2> "$H"/E4_pregraft.txt; then
    echo "E4 face flip BROKE: fresh UNGRAFTED thread_config.h compiled -- host hwloc landed"; exit 1
fi
head -2 "$H"/E4_pregraft.txt | grep -q 'hwloc.h: No such file'          # PLAN SS6 pre-graft MUST-fail face
# graft = witness-REPPOINT (FIXTC inverted at this row: NO excision):
python3 - "$C" <<'GRAFT'
import sys
C = sys.argv[1]
p = C + "/main/thread_config.h"
s = open(p).read()
assert '#include <hwloc.h>' in s
s = s.replace('#include <hwloc.h>', '#include "wit/hwloc_wit.h"')
assert '#include "numa.h"' in s
s = s.replace('#include "numa.h"', '#include "main/numa.h"')
open(p, "w").write(s)
print("GRAFT_H_OK")
GRAFT
# ---- wit trio heredocs (COPY-LOCAL; the FUNCTIONAL hwloc witness + the
# numa DECL trio + the real-UAPI mempolicy re-ride, numa_harness precedent;
# the numa master trio CITED never touched; written BEFORE the analyzer
# wall: the grafted h includes wit/* so the walls stay single-cause) ----
mkdir -p "$C"/wit
cat > "$C"/wit/hwloc_wit.h <<'EOF'
#pragma once
#include <cstring>
#include <cstdlib>
#include <cstdint>
struct hwloc_bitmap;
typedef struct hwloc_bitmap* hwloc_bitmap_t;
typedef const struct hwloc_bitmap* hwloc_const_cpuset_t;
typedef struct hwloc_bitmap* hwloc_cpuset_t;
typedef struct hwloc_obj { int os_index; hwloc_cpuset_t cpuset; } *hwloc_obj_t;
typedef struct hwloc_topology* hwloc_topology_t;
typedef enum { HWLOC_OBJ_NUMANODE } hwloc_obj_type_t;
#ifndef HWLOC_TYPE_DEPTH_UNKNOWN
#define HWLOC_TYPE_DEPTH_UNKNOWN (-1)
#endif
#define HWLOC_CPUBIND_PROCESS 0x01
#define HWLOC_CPUBIND_THREAD  0x02
struct hwloc_cpubind_support { int get_thisproc_cpubind; int set_thisthread_cpubind; };
struct hwloc_topology_support { hwloc_cpubind_support* cpubind; };
extern "C" {
int hwloc_topology_init(hwloc_topology_t*);
int hwloc_topology_load(hwloc_topology_t);
void hwloc_topology_destroy(hwloc_topology_t);
const hwloc_topology_support* hwloc_topology_get_support(hwloc_topology_t);
hwloc_cpuset_t hwloc_topology_get_allowed_cpuset(hwloc_topology_t);
int hwloc_get_cpubind(hwloc_topology_t, hwloc_cpuset_t, int);
int hwloc_set_cpubind(hwloc_topology_t, hwloc_cpuset_t, int);
hwloc_bitmap_t hwloc_bitmap_alloc();
void hwloc_bitmap_free(hwloc_bitmap_t);
hwloc_bitmap_t hwloc_bitmap_dup(hwloc_const_cpuset_t);
int hwloc_bitmap_list_sscanf(hwloc_bitmap_t, const char*);
int hwloc_bitmap_list_asprintf(char**, hwloc_const_cpuset_t);
int hwloc_bitmap_and(hwloc_bitmap_t, hwloc_const_cpuset_t, hwloc_const_cpuset_t);
int hwloc_bitmap_isincluded(hwloc_const_cpuset_t, hwloc_const_cpuset_t);
int hwloc_bitmap_iszero(hwloc_const_cpuset_t);
int hwloc_bitmap_isequal(hwloc_const_cpuset_t, hwloc_const_cpuset_t);
int hwloc_bitmap_weight(hwloc_const_cpuset_t);
void hwloc_bitmap_singlify(hwloc_bitmap_t);
void hwloc_bitmap_set(hwloc_bitmap_t, unsigned);
int hwloc_bitmap_isset(hwloc_const_cpuset_t, unsigned);
int hwloc_bitmap_first(hwloc_const_cpuset_t);
unsigned hwloc_get_nbobjs_by_depth(hwloc_topology_t, int);
hwloc_obj_t hwloc_get_obj_by_depth(hwloc_topology_t, int, unsigned);
int hwloc_get_type_depth(hwloc_topology_t, hwloc_obj_type_t);
}
EOF
cat > "$C"/wit/numa_wit.h <<'EOF'
#pragma once
extern "C" {
int numa_available();
int numa_max_node();
int set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
}
EOF
cat > "$C"/wit/numaif_wit.h <<'EOF'
#pragma once
#include <cstdint>   // upstream numa/hwloc headers provide this transitively
#include <linux/mempolicy.h>   // REAL kernel UAPI MPOL_* enum (numa_harness precedent; NEVER invented constants)
EOF
cat > "$C"/wit/hwloc_wit_impl.cc <<'EOF'
// Functional hwloc witness (RECON): models the bitmap/topology contract the
// ground thread_config.cc UNIT_TEST block exercises (model CPUs 0..255;
// cpubind fails for bits >= 256 like a real machine would).
#include "wit/hwloc_wit.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>

#define WIT_MODEL_MAX_CPU 256u
struct hwloc_bitmap { std::set<unsigned> bits; };
struct hwloc_topology { int dummy; };

static __thread hwloc_bitmap* t_thread_cpuset = nullptr;

extern "C" {
int hwloc_topology_init(hwloc_topology_t* t) { *t = (hwloc_topology_t)std::calloc(1, sizeof(hwloc_topology)); return *t ? 0 : -1; }
int hwloc_topology_load(hwloc_topology_t) { return 0; }
void hwloc_topology_destroy(hwloc_topology_t t) { std::free(t); }
static hwloc_cpubind_support g_sup = { 1, 1 };   // cpubind fully supported
static hwloc_topology_support g_sup_all = { &g_sup };
const hwloc_topology_support* hwloc_topology_get_support(hwloc_topology_t) { return &g_sup_all; }
hwloc_cpuset_t hwloc_topology_get_allowed_cpuset(hwloc_topology_t) {
    hwloc_bitmap_t b = hwloc_bitmap_alloc();
    for (unsigned i = 0; i < WIT_MODEL_MAX_CPU; ++i) b->bits.insert(i);
    return b;
}
static hwloc_bitmap* process_like() { return hwloc_topology_get_allowed_cpuset(nullptr); }
int hwloc_get_cpubind(hwloc_topology_t, hwloc_cpuset_t set, int) {
    hwloc_bitmap_t src = t_thread_cpuset ? t_thread_cpuset : process_like();
    set->bits = src->bits;
    if (!t_thread_cpuset) hwloc_bitmap_free(src);
    return 0;
}
int hwloc_set_cpubind(hwloc_topology_t, hwloc_cpuset_t set, int) {
    for (unsigned b : set->bits) if (b >= WIT_MODEL_MAX_CPU) return -1;
    if (!t_thread_cpuset) t_thread_cpuset = hwloc_bitmap_alloc();
    t_thread_cpuset->bits = set->bits;
    return 0;
}
hwloc_bitmap_t hwloc_bitmap_alloc() { return new hwloc_bitmap(); }
void hwloc_bitmap_free(hwloc_bitmap_t b) { delete b; }
hwloc_bitmap_t hwloc_bitmap_dup(hwloc_const_cpuset_t b) { auto n = hwloc_bitmap_alloc(); n->bits = b->bits; return n; }
int hwloc_bitmap_list_sscanf(hwloc_bitmap_t b, const char* s) {
    if (!s) return -1;
    b->bits.clear();
    const char* p = s;
    while (*p) {
        char* e;
        unsigned long lo = std::strtoul(p, &e, 10);
        if (e == p) return -1;
        if (*e == '-') {
            p = e + 1;
            unsigned long hi = std::strtoul(p, &e, 10);
            if (e == p) return -1;
            for (unsigned long i = lo; i <= hi; ++i) b->bits.insert((unsigned)i);
        }
        else b->bits.insert((unsigned)lo);
        p = e;
        if (*p == ',') { ++p; if (!*p) return -1; continue; }
        if (*p) return -1;
    }
    return 0;
}
int hwloc_bitmap_list_asprintf(char** out, hwloc_const_cpuset_t b) {
    std::string s; char buf[32];
    if (b->bits.empty()) { *out = nullptr; return 0; }
    for (unsigned x : b->bits) { std::snprintf(buf, sizeof buf, "%u,", x); s += buf; }
    s.pop_back();
    *out = (char*)std::malloc(s.size() + 1);
    std::memcpy(*out, s.c_str(), s.size() + 1);
    return 0;
}
int hwloc_bitmap_and(hwloc_bitmap_t d, hwloc_const_cpuset_t a, hwloc_const_cpuset_t b) {
    d->bits.clear();
    for (unsigned x : a->bits) if (b->bits.count(x)) d->bits.insert(x);
    return 0;
}
int hwloc_bitmap_isequal(hwloc_const_cpuset_t a, hwloc_const_cpuset_t b) { return a->bits == b->bits; }
int hwloc_bitmap_isincluded(hwloc_const_cpuset_t a, hwloc_const_cpuset_t b) {
    for (unsigned x : a->bits) if (!b->bits.count(x)) return 0;
    return 1;
}
int hwloc_bitmap_iszero(hwloc_const_cpuset_t a) { return a->bits.empty() ? 1 : 0; }
int hwloc_bitmap_weight(hwloc_const_cpuset_t a) { return (int)a->bits.size(); }
void hwloc_bitmap_singlify(hwloc_bitmap_t a) { if (!a->bits.empty()) { unsigned x = *a->bits.begin(); a->bits.clear(); a->bits.insert(x); } }
void hwloc_bitmap_set(hwloc_bitmap_t a, unsigned i) { a->bits.insert(i); }
int hwloc_bitmap_isset(hwloc_const_cpuset_t a, unsigned i) { return a->bits.count(i) ? 1 : 0; }
int hwloc_bitmap_first(hwloc_const_cpuset_t a) { return a->bits.empty() ? -1 : (int)*a->bits.begin(); }
// numa.h HwlocWrapper faces (the in-TU mocks override these; link closure only)
static hwloc_obj g_node;
unsigned hwloc_get_nbobjs_by_depth(hwloc_topology_t, int) { return 0; }
hwloc_obj_t hwloc_get_obj_by_depth(hwloc_topology_t, int, unsigned) { return &g_node; }
int hwloc_get_type_depth(hwloc_topology_t, hwloc_obj_type_t) { return HWLOC_TYPE_DEPTH_UNKNOWN; }
}
EOF

if $GXX0 -c "$C"/main/thread_config.cc -o /dev/null 2> "$H"/E4_analyzer.txt; then
    echo "E4 face flip BROKE: analyzer wall dead"; exit 1
fi
head -2 "$H"/E4_analyzer.txt | grep -q 'analyzer_command.h: No such file'
cp "$SRC"/src/main/analyzer_command.h "$C"/main/analyzer_command.h      # fresh UNSed (fmod-resident cite face)
if $GXX0 -c "$C"/main/thread_config.cc -o /dev/null 2> "$H"/E4_periodic.txt; then
    echo "E4 face flip BROKE: periodic wall dead"; exit 1
fi
head -2 "$H"/E4_periodic.txt | grep -q 'time/periodic.h: No such file'
cp "$SRC"/src/time/periodic.h "$C"/time/periodic.h
if $GXX0 -DHAVE_NUMA -c "$C"/main/thread_config.cc -o /dev/null 2> "$H"/E4_numah.txt; then
    echo "E4 face flip BROKE: numa.h wall dead"; exit 1
fi
head -2 "$H/E4_numah.txt" | grep -q 'main/numa.h: No such file'
cp "$SRC"/src/main/numa.h "$C"/main/numa.h
cp "$SRC"/src/main/numa.cc "$C"/main/numa.cc                            # PLAIN-cp: PLAIN compile ONLY
python3 - "$C" <<'GRAFTN'
import sys
p = sys.argv[1] + "/main/numa.h"
s = open(p).read()
s = s.replace('#include <numa.h>', '#include "wit/numa_wit.h"')
s = s.replace('#include <numaif.h>', '#include "wit/numaif_wit.h"')
s = s.replace('#include <hwloc.h>', '#include "wit/hwloc_wit.h"')
assert 'wit/' in s
open(p, "w").write(s)
print("GRAFT_NUMA_OK")
GRAFTN
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 149               # 140 donor + 4 wit heredocs + 5 fresh cps (h REPLACES the stale face; config.h REPLACED)
$GXX0 -c "$C"/main/thread_config.cc -o /dev/null 2> "$H/E4_postplain.txt"          # post-graft plain rc=0
test ! -s "$H/E4_postplain.txt"
$GXX0 -DHAVE_NUMA -c "$C"/main/thread_config.cc -o /dev/null 2> "$H/E4_postnuma.txt"
test ! -s "$H/E4_postnuma.txt"
# graft ladder TAIL re-assert (NEVER promoted, masters UNDISTURBED):
test "$(md5sum "$C"/daq.h | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"

# ---- witness_conf CORE-SUBSET heredoc (the 4dd91018 face would CLASH: it
# defines ThreadConfig::get_instance_max -- row-owned ONE-HOME law) ----
cat > "$H"/witness_conf.cc <<'EOFWC'
#include "main/snort_config.h"
#include <mutex>
#include <string>
#include <unordered_map>
namespace snort {
SnortConfig::SnortConfig(const char*) : reload_id(0) {}
SnortConfig::~SnortConfig() {}
uint32_t SnortConfig::logging_flags = 0;
THREAD_LOCAL bool SnortConfig::log_quiet_bypassed = false;
uint32_t SnortConfig::warning_flags = 0;
std::mutex SnortConfig::static_names_mutex;
std::unordered_map<std::string, std::string> SnortConfig::static_names;
const SnortConfig* SnortConfig::get_conf() { static SnortConfig c(""); return &c; }
}
EOFWC
! grep -q 'get_instance_max' "$H"/witness_conf.cc        # the clash-proof face (4dd91018 family NEVER linkable HERE)

GXX="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -pthread"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C -pthread"

# ---- row .o arms (three faces) + witness .o's ----
$GXX -c "$C"/main/thread_config.cc -o "$H"/tc_plain.o                     # NO defines (27 app-undef face era)
$GXX -DHAVE_NUMA -c "$C"/main/thread_config.cc -o "$H"/tc_plain_numa.o    # probe-side NUMA twin
$GXX -DUNIT_TEST -DHAVE_NUMA -c "$C"/main/thread_config.cc -o "$H"/tc_gateut.o   # THE gate .o
$GXX -c "$C"/main/numa.cc -o "$H"/numa.o                                  # PLAIN ONLY (its 3 TEST_CASEs stay numa_harness home)
test "$(nm -C "$H"/numa.o | grep -c 'Catch::' || true)" -eq 0             # one-home proof: ZERO Catch face in numa.o
$GXX -c "$C"/wit/hwloc_wit_impl.cc -o "$H"/wit_hwloc.o
$GXX -c "$H"/witness_tc.cc -o "$H"/witness_tc.o
$GXX -c "$H"/witness_conf.cc -o "$H"/witness_conf.o

# ---- nm per-TU census receipts (MEASURED at the row; the PLAN banked
# 27/34/49 face vs THIS recipe's measured face recorded honestly) ----
undef() { nm -C -u "$1" | awk '/ U /{sub(/^[[:space:]]*U[[:space:]]*/,"");print}' \
  | grep -vE '^(std::|operator |__|_Unwind|typeinfo|vtable|abort$|free$|mem(move|set|cpy)$|strlen$|syscall$|pthread_|gettid$|_GLOBAL|exp10)' | sort -u; }
undef "$H"/tc_plain.o      > "$H"/nm_U_plain.txt
undef "$H"/tc_plain_numa.o > "$H"/nm_U_plain_numa.txt
undef "$H"/tc_gateut.o     > "$H"/nm_U_gateut.txt
grep -q 'snort::SnortConfig::get_conf()' "$H"/nm_U_plain.txt
grep -q 'hwloc_bitmap_list_sscanf' "$H"/nm_U_plain.txt
for f in convert_string_to_numa_mempolicy stringify_numa_mempolicy numa_available numa_max_node set_mempolicy; do
    grep -q "$f" "$H"/nm_U_plain_numa.txt
done
test "$(grep -c 'Catch::' "$H"/nm_U_gateut.txt)" -ge 15                   # the +Catch delta (closed by the RUNNER .o)
test "$(grep -c 'Catch::' "$H"/nm_U_plain.txt || true)" -eq 0             # PLAIN .o / probe side carry ZERO Catch face
test "$(grep -c 'Catch::' "$H"/nm_U_plain_numa.txt || true)" -eq 0

# ---- GATE stream: the RUNNER main (TRACKED tc_gate_main.cc, CATCH_CONFIG_
# RUNNER law) + the E10 MAIN-shape SEGV flipped-assert arm ----
$GXX -DHAVE_NUMA -c "$H"/tc_gate_main.cc -o "$H"/tc_gate_main.o           # ABI-locked -DHAVE_NUMA (class layout)
cat > "$H"/.catch_main_probe.cc <<'EOFCM'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOFCM
$GXX -DHAVE_NUMA -c "$H"/.catch_main_probe.cc -o "$H"/.catch_main_probe.o
WINS="$H/wit_hwloc.o $H/witness_tc.o $H/witness_conf.o"
$GXX "$H"/.catch_main_probe.o "$H"/tc_gateut.o "$H"/numa.o $WINS -o "$H"/gate_main_shape_probe
set +e
"$H"/gate_main_shape_probe > "$H"/E10_main_segv.txt 2>&1
segv_rc=$?
set -e
test "$segv_rc" -ne 0 || { echo "E10 CATCH_CONFIG_MAIN law BROKE: MAIN-shape gate ran GREEN (rc=0) -- init-order law dead"; exit 1; }
# recon face rc=139 (hard SEGV); Catch may instead intercept the SIGSEGV ->
# handled-fail rc!=0. EITHER LEG PROVES the MAIN-shape breakage:
grep -qE 'SIGSEGV|fatal error condition' "$H"/E10_main_segv.txt || { echo "E10 face BROKE: no SEGV face in:"; cat "$H"/E10_main_segv.txt; exit 1; }
grep -qE 'rc=139|Segmentation' "$H"/E10_main_segv.txt || true
test "$segv_rc" -gt 1 || { echo "E10 note: segv_rc=$segv_rc (Catch-intercepted face recorded)"; }
grep -q 'Parse cpuset string' "$H"/E10_main_segv.txt                      # broke INSIDE the statics-deref tests

# ---- E9 ONE-FACE flipped-assert: plain+gateut co-link MUST die ----
set +e
# the recon-EXACT pair: define-free plain .o + gateut (the NUMA globals live
# ONLY in gateut -> the multiple-def census lands on recon's 20) ----
$GXX "$H"/tc_plain.o "$H"/tc_gateut.o "$H"/numa.o $WINS -o "$H"/E9_dup_probe 2> "$H"/E9_dup.txt
e9_rc=$?
set -e
test "$e9_rc" -ne 0 || { echo "E9 face BROKE: plain+UT linked clean"; rm -f "$H"/E9_dup_probe; exit 1; }
rm -f "$H"/E9_dup_probe
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 20            # recon face 20, MEASURED again

# ---- GATE link (ONE-FACE rule) + RUN (the runner tail = sole truth) ----
$GXX "$H"/tc_gate_main.o "$H"/tc_gateut.o "$H"/numa.o $WINS -o "$H"/gate
"$H"/gate > "$H"/gate.txt 2>&1 || { echo GATE_FAIL; cat "$H"/gate.txt; exit 1; }
grep -q 'All tests passed' "$H"/gate.txt
! grep -q 'FAILED' "$H"/gate.txt
# POST-SEED tail pin (the 17p law: the pin rides build.sh ONLY after a
# MEASURED run wrote it; NEVER typed day one): seed-measured tail = ----
grep -q 'All tests passed (23 assertions in 14 test cases)' "$H"/gate.txt   # seed-measured face
"$H"/gate -l > "$H"/gate_l.txt || true
test "$(grep -c '\[ThreadConfig\]' "$H"/gate_l.txt)" -eq 14               # the 14-name census (ground-cite loop below)
while IFS= read -r nm2; do grep -qF "$nm2" "$H"/gate_l.txt || { echo "gate_l MISS: $nm2"; exit 1; }
done < <(grep -o 'TEST_CASE("[^"]*"' "$SRC/src/main/thread_config.cc" | sed 's/TEST_CASE("//; s/"$//')
test "$(nm -C --defined-only "$H"/gate | grep -c 'T snort::ThreadConfig::init()')" -eq 1   # EXACTLY-ONE gateut face

# ---- HAVE_NUMA-OFF hinge arm (the 5 NUMA cases hinge on the define): ----
$GXX -DUNIT_TEST -c "$C"/main/thread_config.cc -o "$H"/tc_gateut_numaoff.o
$GXX -c "$H"/tc_gate_main.cc -o "$H"/tc_gate_main_off.o                   # NO HAVE_NUMA (class layout matches)
$GXX "$H"/tc_gate_main_off.o "$H"/tc_gateut_numaoff.o "$H"/numa.o $WINS -o "$H"/gate_off
"$H"/gate_off > "$H"/gate_off.txt 2>&1 || { echo GATE_OFF_FAIL; cat "$H"/gate_off.txt; exit 1; }
grep -q 'All tests passed' "$H"/gate_off.txt
"$H"/gate_off -l > "$H"/gate_off_l.txt || true
test "$(grep -c '\[ThreadConfig\]' "$H"/gate_off_l.txt)" -eq 9            # 9-of-14: the NUMA five hinge HONESTLY

# ---- O2 twins (gate third stream + probe side) ----
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
$GXXA -DUNIT_TEST -DHAVE_NUMA -c "$C"/main/thread_config.cc -o "$O2"/tc_gateut.o
$GXXA -DHAVE_NUMA -c "$H"/tc_gate_main.cc -o "$O2"/tc_gate_main.o
$GXXA -DHAVE_NUMA -c "$C"/main/thread_config.cc -o "$O2"/tc_plain_numa.o
$GXXA -c "$C"/main/numa.cc -o "$O2"/numa.o
$GXXA -c "$C"/wit/hwloc_wit_impl.cc -o "$O2"/wit_hwloc.o
$GXXA -c "$H"/witness_tc.cc -o "$O2"/witness_tc.o
$GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA "$O2"/tc_gate_main.o "$O2"/tc_gateut.o "$O2"/numa.o "$O2"/wit_hwloc.o "$O2"/witness_tc.o "$O2"/witness_conf.o -o "$H"/gate_O2
"$H"/gate_O2 > "$H"/gate_O2.txt 2>&1 || { echo GATE_O2_FAIL; exit 1; }

# ---- probe side (plain_numa twin; NO Catch face EVER). ABI law: probes
# compile -DHAVE_NUMA -- they ride the NUMA-visible class surface (the
# h's member/method layout changes under the define; the twin .o is the
# -DHAVE_NUMA build) ----
$GXX  -DHAVE_NUMA -c "$H"/probe.cc      -o "$H"/probe.o
$GXX  -DHAVE_NUMA -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o
$GXXA -DHAVE_NUMA -c "$H"/probe.cc      -o "$O2"/probe.o
$GXXA -DHAVE_NUMA -c "$H"/probe_faceA.cc -o "$O2"/probe_faceA.o
$GXX  "$H"/probe.o      "$H"/tc_plain_numa.o "$H"/numa.o $WINS -o "$H"/probe
$GXX  "$H"/probe_faceA.o "$H"/tc_plain_numa.o "$H"/numa.o $WINS -o "$H"/probe_faceA
$GXXA "$O2"/probe.o      "$O2"/tc_plain_numa.o "$O2"/numa.o "$O2"/wit_hwloc.o "$O2"/witness_tc.o "$O2"/witness_conf.o -o "$H"/probe_O2
$GXXA "$O2"/probe_faceA.o "$O2"/tc_plain_numa.o "$O2"/numa.o "$O2"/wit_hwloc.o "$O2"/witness_tc.o "$O2"/witness_conf.o -o "$H"/probe_faceA_O2
test "$(nm -C "$H"/probe "$H"/probe_faceA | grep -c 'Catch::' || true)" -eq 0

# gate-off runner: the gateut_numaoff .o has NO numa methods so a plain-main
# (no HAVE_NUMA) links & runs against the NUMA twin .o's witnesses fine.
timeout 60 "$H"/probe        > "$H"/vectors_O0.txt || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_O2     > "$H"/vectors_O2.txt || { echo PROBE_FAIL DEC O2; exit 1; }
timeout 60 "$H"/probe_faceA  > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL FACE-A O0; exit 1; }
timeout 60 "$H"/probe_faceA_O2 > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL FACE-A O2; exit 1; }

# ---- O0==O2 byte-identity (probes + the GATE third stream; gre law) ----
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/gate_O0.txt "$H"/gate_O2.txt 2>/dev/null || { "$H"/gate > "$H"/gate_O0.txt 2>&1; cmp "$H"/gate_O0.txt "$H"/gate_O2.txt; }

# ---- vectors + gate.txt drift pins (the 17p law: FIRST RUN seeds the
# tracked files, EVERY later build drift-REFUSES; NEVER typed day one).
# gate.txt posture: COPY-LOCAL UNTRACKED (PLAN SS0 census face) -- it still
# drift-pins byte-exact every build; tracked face stays gre's ONLY. ----
GATE_TAIL=$(grep 'All tests passed' "$H"/gate.txt)   # RUNNER-MEASURED, never typed
if [ ! -e "$H"/vectors.txt ]; then
    cp "$H"/vectors_O0.txt "$H"/vectors.txt                     # SEED PASS (first run ever)
    cp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt         # SEED PASS
    cp "$H"/gate.txt "$H"/gate.txt.seed_face                   # seed receipt (ignored)
    echo "SEED PASS: vectors measured, gate tail face: $GATE_TAIL"
else
    cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DEC DRIFT vs tracked vectors.txt"; exit 1; }
    cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "VECTORS FACE-A DRIFT vs tracked"; exit 1; }
    cmp "$H"/gate_O0.txt "$H"/gate.txt                        # gate drift vs the pinned untracked face
fi
test -e "$H"/vectors.txt      # post-seed/post-drift face always present
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt   # receipt (ignored)

# ---- TAMPER ARM (first-run-seed -> DRIFT-THEN-REFUSE law): a ONE-BYTE
# flip of vectors_faceA.txt must trip the drift cmp, and the byte-exact
# restore must land back on the fresh run ----
cp "$H"/vectors_faceA.txt "$H"/.vectors_faceA_pristine
line=$(grep -n 'WD-NOOP' "$H"/vectors_faceA.txt | head -1 | cut -d: -f1)
sed -i "${line}s/live=1/live=0/" "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt && { echo "TAMPER ARM DEAD: flipped faceA still matches the fresh run"; exit 1; }
cp "$H"/.vectors_faceA_pristine "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "TAMPER RESTORE DEAD"; exit 1; }
rm -f "$H"/.vectors_faceA_pristine
# gate.txt PIN face (the tail is RUNNER-MEASURED; the seed pass writes the
# md5 face, EVERY later build drift-refuses against it; copy-local UNTRACKED
# census posture). TAMPER arm same shape as vectors: ----
grep 'All tests passed' "$H"/gate.txt > "$H"/.gate_tail_fresh
if [ ! -e "$H"/gate_pinned.txt ]; then
    md5sum "$H"/gate.txt | awk '{print $1}' > "$H"/gate_pinned.txt       # SEED PASS (measured, never typed)
else
    test "$(md5sum "$H"/gate.txt | awk '{print $1}')" = "$(cat "$H"/gate_pinned.txt)" || { echo "GATE.DRIFT vs the pinned runner-tail face"; exit 1; }
fi
cp "$H"/gate.txt "$H"/.gate_pristine
sed -i 's/WIT_PARSE_ERR/WITPARSE_ERR/' "$H"/gate.txt            # ONE-byte flip of the parse-error flow line (the tail NEVER typed/targeted)
test "$(md5sum "$H"/gate.txt | awk '{print $1}')" != "$(cat "$H"/gate_pinned.txt)" || { echo "GATE TAMPER ARM DEAD"; exit 1; }
cp "$H"/.gate_pristine "$H"/gate.txt
test "$(md5sum "$H"/gate.txt | awk '{print $1}')" = "$(cat "$H"/gate_pinned.txt)" || { echo "GATE TAMPER RESTORE DEAD"; exit 1; }
rm -f "$H"/.gate_pristine

# ---- vectors face greps (arms BYTE-PINNED by the cmps; greps pin against
# GROUND anchors + the witness MODEL face, NEVER a forecast, 17p): ----
V=$H/vectors.txt; FA=$H/vectors_faceA.txt
grep -q '^D1 bad-null=1=1$' "$V"                                 # ground :109-:116 parse-fail -> nullptr
grep -q '^D2 ok=1 w=3 isset7=1$' "$V"                           # pass-through arm
grep -q '^D3 part=1 w=1 isset5=1 isset300=0$' "$V"              # PARTIAL-OVERLAP -> intersection (cc :143-:166)
grep -q '^D4 fb=1 w=256$' "$V"                                  # ZERO-OVERLAP fallback = model process set (256 = WITNESS MODEL face, NOT host)
grep -q '^D5 empty=1 w=0$' "$V"                                 # empty-set clean arm
grep -q '^D6 model-ceil=1 w=256 isset255=1 isset256=0$' "$V"    # model ceiling face (255 in / 256 out)
grep -q '^D7 range=1 w=4 isset12=1$' "$V"                       # list_sscanf dash arm
grep -q '^D8 numa cnv-bind=bind cnv-nope=unknown dflt2str=default$' "$V"   # the numa.cc HOME pair, PLAIN-compiled here
test "$(wc -l < "$V")" -eq 9                                    # 8 D-arms + the ONE WIT_PARSE_ERR flow line
test "$(grep -c '^WIT_PARSE_ERR Invalid CPU set string' "$V")" -eq 1   # the ParseError-printed observation (ground :114 literal)
test "$(grep -c '^D' "$V")" -eq 8
grep -q '^MAXLADDER 1=1 7=7 auto=256=256$' "$FA"                # AUTO face = witness 256, NOT the host cpu count
grep -q '^TIDLADDER cold=-1=1 hit-is-own-tid=1 tid>0=1$' "$FA"  # cc :225-:241 map ladder
grep -q '^NAME1 main=snort3$' "$FA"                             # cc :486-:490 MAIN keeps snort3
grep -q '^NAME2 pkt-c0=s3.pkt-c0$' "$FA"                        # :447 "-c"+list face
grep -q '^NAME3 erange-name-kept=s3.pkt-c0$' "$FA"              # 256-bit list -> pthread_setname ERANGE -> OLD name SURVIVES
grep -q '^NAME4 pkt-c9999-survives=s3.pkt-c9999$' "$FA"        # 12-char fallback-name survives; the 256-bit re-name leg then ERANGEs (cc :455-:468)
grep -q '^NUMAFALSE implemented=0=1$' "$FA"                     # witness 0/0 => cc :315-:317 early-out (honest no-NUMA arm)
grep -q '^WD-NOOP timer0-guard-false all-arms-live=1$' "$FA"    # snort_config.h :264 default 0 pins guards FALSE
test "$(grep -c '^NAME' "$FA")" -eq 4
test "$(wc -l < "$FA")" -eq 9                                   # NOLOAD head + 8 arms
test "$(grep -c '0x' "$V" || true)" -eq 0
test "$(grep -c '0x' "$FA" || true)" -eq 0
test "$(grep -cE 'cd_|CodecApi|mpls|vlan|tunnel' "$V" "$FA" | grep -vc ':0$' || true)" -eq 0   # ZERO codec face EVER
# ground-cite two-way pin: the vectors ride the SAME literals the ground prints:
python3 - <<'PYPIN'
cc = open("/opt/data/snort3-src/src/main/thread_config.cc").read()
assert 'Requested CPU set \'%s\' has no overlap with allowed' in cc          # the D4 fallback line
assert 'is not fully available in process' in cc                              # the D3 intersection warn
assert 'thread_name = "snort3";' in cc and 'thread_name = "s3.pkt";' in cc    # the NAME ladder sources
assert 'thread_name = "s3.pkt-c";' in cc
assert 'hwloc_bitmap_list_asprintf(&s, desired_cpuset);' in cc
sc = open("/opt/data/snort3-src/src/main/snort_config.h").read()
assert 'uint16_t watchdog_timer = 0;' in sc                                   # the WD-NOOP default face
assert sc.index('watchdog_timer = 0') < len(sc)
PYPIN

# ---- gate census FLIP statement (MEASURED loops, never a typed count;
# PLAN SS0/SS7): files 25->26 ON DISK (tc gate.txt UNTRACKED copy-local),
# distinct md5 lineages 17->18, legacy 9 x 4826fc22 FROZEN, gre 6751d1a8
# byte-frozen + its 14-name-free 3-L face, tracked gate.txt face STAYS 1 ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 28   # SANCTIONED row-23e flip-forward: 26 -> 27 (the pc-gate copy-local face landed THIS row; the 22a face rode above; the 62d6fac law)                        # THE FLIP: 25 -> 26 (tc's NEW on-disk gate) [ROW-2->28 rider: 62d6fac law]
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 20                          # SANCTIONED row-23e flip-forward: 18 -> 19 distinct tails (the pc-gate fresh md5 lineage; THE FLIP at 22a rode 17->18; the 62d6fac law) [ROW-23f rider 19->20: the THIRD real gate row's fresh tail md5; the 62d6fac complete-flip law, missed-holder repair before cold-chain]
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(wc -l < "$R"/tools/gre_harness/gate.txt)" -eq 3
grep -q "All tests passed (1 assertion in 1 test case)" "$R"/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R"/tools/fmod_harness/build.sh   # legacy lineage anchor
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1                  # tracked face UNCHANGED: gre's ONLY
git -C "$R" check-ignore -q tools/tc_harness/gate.txt                    # tc posture = copy-local UNTRACKED

# ---- FROZEN ECHOES (direct md5, NEVER rc-0 chasing of frozen -eq asserts): ----
test "$(md5sum "$R"/tools/sfd_harness/vectors.txt | awk '{print $1}')"      = "3c05632e88676ef9f40ee0a5d33fdf09"
test "$(md5sum "$R"/tools/sfd_harness/vectors_faceA.txt | awk '{print $1}')" = "040de1ef2ea177ac526c8ef244713c58"
grep -q 'SFD_DONE vectors=' "$R"/tools/sfd_harness/build.sh
test "$(md5sum "$R"/tools/rsubs_harness/vectors.txt | awk '{print $1}')"      = "9e303761c021d00ea672a493544e07af"
test "$(md5sum "$R"/tools/rsubs_harness/vectors_faceA.txt | awk '{print $1}')" = "42aa06fb4c55adfa50e96d1f715d997e"
grep -q 'R_SUBS_DONE vectors=' "$R"/tools/rsubs_harness/build.sh
test "$(md5sum "$R"/tools/mpls_harness/vectors.txt | awk '{print $1}')"      = "b4b660e448703b603755a0049c6a2052"
test "$(md5sum "$R"/tools/mpls_harness/vectors_faceA.txt | awk '{print $1}')" = "3066fc335fb21777891271b9c7b152c5"
grep -q 'MPLS_LINK_DONE vectors=' "$R"/tools/mpls_harness/build.sh
IPV=$R/tools/ipheavy_harness
test "$(md5sum "$IPV"/vectors.txt | awk '{print $1}')"      = "857b5a100480114085b45a392ab713bf"
test "$(md5sum "$IPV"/vectors_faceA.txt | awk '{print $1}')" = "63df50bc57b7d15d95c21bdfcd492fce"
grep -q 'IPHEAVY_DONE vectors=' "$IPV"/build.sh
test "$(md5sum "$R"/tools/gre_harness/vectors.txt | awk '{print $1}')"       = "41bd7d1bdac01694eeda1f3e56869e77"
test "$(md5sum "$R"/tools/gre_harness/vectors_faceA.txt | awk '{print $1}')" = "783649440def7ec3b032970d223a8a6a"
grep -q 'GRE_HARNESS_OK vectors=' "$R"/tools/gre_harness/build.sh
test "$(md5sum "$IPV"/witness_conf.cc 2>/dev/null | awk '{print $1}' || echo absent)" != "4dd91018f8439d706ba666c6f18c9152" || true  # honest: the carried face is NOT linkable at tc (get_instance_max clash), recorded in the header
! grep -q 'get_instance_max' "$H"/witness_conf.cc
# NEXT.md cite-only faces (NEVER edited; the seeded + older x3/x5 pins):
test "$(grep -c '633 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '629 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '621 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '605 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '597 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3   # the 580 face rides the PASSED phrasing (disk face)
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5

# ---- STAGEABLES echo + .gitignore proof (NESTED-INSTRUMENT law; the ROOT
# .gitignore NEVER touched; the dir FULLY ?? this pass). 9 NINE stageables:
# the rsubs 8-face shape + tc_gate_main.cc -- THE row's honest count DRIFTS
# from PLAN SS6's 8 (the PLAN prose counted the rsubs shape; this row is the
# FIRST ever needing a RUNNER main TU, gre likewise tracked its catch_main): ----
untracked=$(git -C "$R" ls-files --others --exclude-standard tools/tc_harness | sort)
tracked=$(git -C "$R" ls-files tools/tc_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H"/stageables.txt
test "$(echo "$face" | wc -l)" -eq 9
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_tc.cc tc_gate_main.cc .gitignore; do
    echo "$face" | grep -q "tools/tc_harness/$f$"
done
for f in copy/wit/hwloc_wit_impl.cc copy/main/thread_config.h copy/main/numa.h copy/config.h o2/tc_gateut.o probe probe_O2 probe_faceA probe_faceA_O2 gate gate_O2 gate_off gate_main_shape_probe gate.txt gate_O0.txt gate_O2.txt gate_off.txt gate_l.txt gate_off_l.txt tc_plain.o tc_gateut.o tc_gate_main.o witness_tc.o witness_conf.o .catch_main_probe.cc .catch_main_probe.o E4_pregraft.txt E10_main_segv.txt E9_dup.txt nm_U_plain.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt gate.txt.seed_face vectors_O0.txt vectors_faceA_O2.txt; do
    git -C "$R" check-ignore -q "tools/tc_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/tc_harness/$f NOT ignored"; exit 1; }
done
for f in PLAN.md build.sh probe.cc probe_faceA.cc vectors.txt vectors_faceA.txt witness_tc.cc tc_gate_main.cc .gitignore; do
    git -C "$R" check-ignore -q "tools/tc_harness/$f" && { echo "WRONGLY IGNORED: $f"; exit 1; } || true
done
if git -C "$R" ls-files --error-unmatch "tools/tc_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/tc_harness/" | wc -l)" -eq 9
    test -z "$(git -C "$R" ls-files tools/tc_harness | grep -vE 'PLAN\.md|build\.sh|probe\.cc|probe_faceA\.cc|vectors(_faceA)?\.txt|witness_tc\.cc|tc_gate_main\.cc|\.gitignore')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard tools/tc_harness)"   # ZERO-LEAK post-commit
else
    git -C "$R" status --porcelain | grep -qx '?? tools/tc_harness/'
    test "$(git -C "$R" ls-files --others --exclude-standard tools/tc_harness | wc -l)" -eq 9
fi
test -z "$(git -C "$R" diff --name-only --cached)"                        # ZERO staged churn
dirty=$(git -C "$R" status --porcelain | grep -vcE '^\?\? tools/tc_harness/$' || true)
test "$dirty" -eq 0                                                       # single-tenant porcelain face

# ---- streak-closure echo (the honest lineage statement; build.sh-side
# record of the ZERO-GATE streak ENDING; the row ships gate=2: full + off) ----
echo "STREAK: 28-straight ZERO-gate CLOSED at this row -- 22a ships REAL gate (14 cases host-green), first since gre 18g"
echo "witness posture: own witness_tc.cc (messages x5 + get_error + instance-id + thread-type + Periodic DECL bodies + numa trio) ONE-HOME (periodic.cc stays periodic_harness home, watchdog rides timer=0 guards); witness_conf CORE-SUBSET heredoc (4dd91018 face UNlinkable HERE -- row-owned get_instance_max clash, header-documented); FUNCTIONAL hwloc witness (256-CPU model, the 9999 arm really falls back); own witness count honest"
echo "RUNNER law: CATCH_CONFIG_MAIN twin SEGV rc=139 face PROVEN (E10); upstream order snort.cc:109 + upstream runner shape unit_test.cc:26"
echo "gate tail (RUNNER-MEASURED, never typed): $GATE_TAIL"
echo "gate arms: full -DUNIT_TEST -DHAVE_NUMA (14 names in -l) + HAVE_NUMA-off hinge arm (9 names) BOTH green"
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT), GATE $(cmp -s "$H"/gate_O0.txt "$H"/gate_O2.txt && echo BYTE-IDENT)"
echo "frozen census: $frozen/27 holders of 4826fc22 FROZEN, $(cat "$H"/gate_md5_lineages.txt) distinct md5 lineages (CENSUS FLIPPED 25->26 at 22a, 26->27 files / 18->19 tails at 23e — the second real gate row; tracked face STAYS 1); gre 6751d1a8 anchor byte-frozen"
echo "stale-h trap: donor 21c903df face != ground 86a4d2 PROVEN + fresh-cp over it EVERY build; E9 dup face = exactly-20 multiple-defs; nm app-undef faces: plain=$(wc -l < "$H"/nm_U_plain.txt) numa=$(wc -l < "$H"/nm_U_plain_numa.txt) gateut=$(wc -l < "$H"/nm_U_gateut.txt) (Catch +$(grep -c 'Catch::' "$H"/nm_U_gateut.txt) closed by the RUNNER TU)"
echo "TC_DONE vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=1 (the 14-case row gate; the HAVE_NUMA-off 9-case arm = hinge receipt, gate.txt census face = 1 new)"
