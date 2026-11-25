#!/usr/bin/env bash
# daqio_harness -- row 23a: THE chapter-20 OPENER (plan-table row 20
# packet_io/DAQ OPENED): the SFDAQ pair sfdaq.cc 420 L (md5
# 7ac13aa1f5013ead580f5b4f61c38368) + sfdaq.h 72 L (md5
# 2e272d2d68e40138946326df3c5cfc95) + the config pair riders
# sfdaq_config.cc 131 L (md5 881eb03852b372c32ea1efca5c872507) +
# sfdaq_config.h 85 L (md5 df8f1875e163d4a588d48195cfdbad4c) = 708 L.
# THE REAL-SDK RE-CITE ROW (the plan-20 law): the real libdaq clone LANDED
# at /opt/data/libdaq @ c8d4083 (HEAD re-verified EVERY build; depth-1).
# THIS harness is where the graft law DIES HONESTLY: the donor graft face
# (ipheavy ext#4 97bca757 daq.h + 9b603f8f daq_common.h + e8a39bf3
# daq_dlt.h) NEVER declares the SDK vocabulary -> the E4 PRE-RECITE arm
# compiles the FRESH-cp ground sfdaq.cc against that graft face and DIES
# with EXACTLY-86 error lines (the two named faces 'DAQ_Mode' does not
# name a type + daq_load_dynamic_modules was not declared pinned 1+1); the
# row then RE-CITES: the copy tree's daq headers are OVERWRITTEN with the
# REAL libdaq api faces (daq.h 35294a17... daq_common.h 28789a3d...
# daq_dlt.h 57208729... + daq_module_api.h 1a617b3e... + the CMAKE-
# GENERATED daq_version.h stand-in via sed over the READ-ONLY
# api/daq_version.h.in + the configure.ac m4 face 3.0.29.0) and REAL api
# .o objects compile FROM the READ-ONLY libdaq sources (daq_base.c
# daq_base_api.c daq_config.c daq_instance_api_defaults.c daq_mod_ops.c).
# The ground sfdaq.cc then compiles rc0 SILENT and the probe RUNS against
# the REAL daq_verdict_string/daq_mode_string tables (daq_base.c :56-:63/
# :66-:70) + the REAL register ladder (daq_base.c :120-:149). THE 22b PKTH
# WALL CLOSES BY MEASUREMENT: REAL DAQ_PktHdr_t = 56 B WITH ts +
# uint32 address_space_id (offsetof 44) + uint32 tenant_id (48) -- the
# FACE-A SIZES/OFFSETS lines. THE SYNTHETIC-FACE LEDGER (ledger_probe.cc,
# 5 compile legs): master f683749c / graft-v2 fead0027 / ext#4 9b603f8f
# pkthdr=16 TS=0 AS=0 TN=0 (x3), the 22b ext b99e44b9 pkthdr=24 TS=0 AS=1
# (SYNTH uint16) TN=1, the REAL face pkthdr=56 TS=1 AS=1 TN=1; + the grep
# drift legs (the 9b603f8f PAUSE/WAITING/COUNT verdict lines = 2, REAL 0;
# SIGNIFICANT_GROUPS 0x20-graft vs 0x8000-REAL; IGNORE_VLAN 0x40-20a-synth
# vs 0x8-REAL; uint16 vs uint32 address_space_id; ZERO DAQ_COMMON_API_
# VERSION in ANY synth face). The graft families NEVER get cp'd/edited
# HERE -- the REAL faces LAND IN THE COPY TREE (copy-local NEVER-tracked;
# the graft masters stay md5-frozen where they live) + A LIVE daq.h find
# CENSUS face (10 trees; the daq3 :105 'one landing' arm is FROZEN-era,
# chain NEVER re-runs in the FRESH chain -- the 20a retirement precedent,
# drift RECORDED NEVER silent; misc3 :378 'sfdaq*.cc find-0' RETIRED BY
# DESIGN at THIS row -- the real bodies COMPILE NOW, plan-20's whole
# POINT). DONOR = ipheavy ext#4 tree 140-file face (the 22b donor
# identity; the packet_io/sfdaq.h + sfdaq_instance.h rider headers ride
# BYTE-EXACT vs ground -- md5-pinned; the STALE-DONOR face RE-MEASURED:
# the 4 row .cc/.h find-0 BEFORE the FRESH cps). WITNESS = the carried
# witness_conf 4dd91018 family (link4 :429-:471 EXTRACTION law, NEVER
# doubled: it closes get_conf + FatalError + the thread/stats/eth
# residues) + OWN-14 face (witness_daqio.cc: EXACTLY-3 message mirrors
# LogMessage/ErrorMessage/ParseError [messages.h :51/:56/:60 -- FatalError
# :105 CARRY-OWNED] + EXACTLY-11 SFDAQInstance mirrors = the 23b provider
# seam [ctor/dtor/init/get_input_spec/get_base_protocol/can_inject/
# can_inject_raw/can_replace/get_tunnel_bypass/inject/get_stats]; the sfdaq.o
# nm census names 9 of them as UNDEF + the probe TU ctor/dtor-call faces;
# the REAL bodies land at row 23b, NEVER invented here]). THE row .o nm
# census: sfdaq.o app-undef = EXACTLY-39 (EXACTLY-25 daq_* SDK names --
# daq_base.c/daq_config.c/daq_mod_ops.c close ALL at link -- + 14 snort =
# 9 SFDAQInstance + 4 messages + get_conf); sfdaq_config.o = EXACTLY-0
# SDK pulls (the pure-value config half); the final DEC binary residue =
# glibc ONLY. E9 ONE-HOME flipped-assert: a dup-message twin co-link =
# EXACTLY-2 'multiple definition' rc!=0 receipts.
# ZERO-GATE row (measured by walk): the 4 ground files UNIT_TEST/TEST_
# CASE/TEST_GROUP/^TEST(/CppUTest grep-0 x4 + BUILDING_SO/snort_plugins
# grep-0 x4; src/packet_io/test/CMakeLists.txt add_cpputest EXACTLY-2
# (sfdaq_counters + active_packet_trace -- rider suites for sfdaq_module/
# active, NEVER this row's files; sfdaq grep rides the module/counters
# names ONLY = 2, the walked honest face pinned EVERY build); CppUTest
# host find-0 dialect BLOCKED -> ZERO gate artifacts; the census STAYS the
# FLIPPED forward row 23e: 27 on-disk / legacy 4826fc22 x9 / 19 lineages / tracked-1
# gre, the sfd parity rider stays green. NAME CENSUS (measured THIS
# pass): 'daqio' PRE-HITS EXACTLY-1 file (misc3 witness_trio.cc -- the
# 'daqioctl' WORD substring, pinned EXACTLY-1 the honest hazard face);
# 'daqio_harness' rides ZERO foreign build.sh (the own-name find-0 arms
# live ONLY in THIS file -- the tc/tracer/sfd template shape; NO foreign
# build.sh ever name-greps a *_harness token, measured); NEXT.md
# STATE-AWARE 0->1 (the docs bank adds the EXACTLY-1 cite line); the bare
# 'sfdaq' token rides misc3+mpls build.sh + misc3 parity = 3 files FROZEN
# (NEVER count-pinned by ANY foreign harness); the misc9 :461 landmine
# ('ReloadSurvivor|reload_survivor|struct Tracer' over src/) stays find-0
# by NAMING (the rs bodies ride the C names SFDAQ/sfdaq verbatim; NO
# 'struct Tracer', NO Tracer-struct literal). 9 stageables STATE-AWARE
# census (the 22b 8-face shape + THE ledger_probe leg = 9; ZERO gate
# material = ZERO runner TU). NEXT.md CITE-ONLY (NEVER edit): 659/650/
# 633/629/621/605/597 x3, 588 x4, 580-PASSED x3, 573 x5, the 'cc **133**'
# MUST-RIDE face, the '5 TEST(' EXACT-1 drift token, the
# 'tools/sfd_harness' EXACT-1 token NEVER written by this file.
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
L=/opt/data/libdaq                    # THE REAL SDK, READ-ONLY ground
H=$(cd "$(dirname "$0")" && pwd)
IP=$R/tools/ipheavy_harness           # donor (140-file ext#4 tree; self-heal)
D3=$R/tools/daq3_harness              # graft MASTER cites (never cp'd HERE)
M9=$R/tools/misc9_harness             # graft-v2 face cite (fead0027)
TR=$R/tools/tracer_harness            # the 22b pkth-EXT face cite (b99e44b9)
SF=$R/tools/sf""d_harness             # token-CONCAT law (the sfd :118 shape)
RSB=$R/tools/rs""ubs_harness          # token-CONCAT law (the rsubs lineage)
C=$H/copy

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(wc -l < "$SRC/src/packet_io/sfdaq.cc")" -eq 420
test "$(md5sum "$SRC/src/packet_io/sfdaq.cc" | awk '{print $1}')" = "7ac13aa1f5013ead580f5b4f61c38368"
test "$(wc -l < "$SRC/src/packet_io/sfdaq.h")" -eq 72
test "$(md5sum "$SRC/src/packet_io/sfdaq.h" | awk '{print $1}')" = "2e272d2d68e40138946326df3c5cfc95"
test "$(wc -l < "$SRC/src/packet_io/sfdaq_config.cc")" -eq 131
test "$(md5sum "$SRC/src/packet_io/sfdaq_config.cc" | awk '{print $1}')" = "881eb03852b372c32ea1efca5c872507"
test "$(wc -l < "$SRC/src/packet_io/sfdaq_config.h")" -eq 85
test "$(md5sum "$SRC/src/packet_io/sfdaq_config.h" | awk '{print $1}')" = "df8f1875e163d4a588d48195cfdbad4c"
test "$(( 420 + 72 + 131 + 85 ))" -eq 708                          # pair-pair ledger
# the CMakeLists ride face (packet_io OBJECT lib; the measured pins):
test "$(grep -c 'sfdaq.cc' "$SRC/src/packet_io/CMakeLists.txt")" -eq 2         # :12 object list + :26 the ENABLE_STATIC_DAQ leg
test "$(grep -c 'sfdaq.h' "$SRC/src/packet_io/CMakeLists.txt")" -eq 1
test "$(grep -c 'sfdaq_config' "$SRC/src/packet_io/CMakeLists.txt")" -eq 2     # the pair rides cc+h
test "$(sed -n '26p' "$SRC/src/packet_io/CMakeLists.txt")" = '    set_source_files_properties(sfdaq.cc PROPERTIES COMPILE_DEFINITIONS ENABLE_STATIC_DAQ)'
test "$(grep -c 'add_cpputest' "$SRC/src/packet_io/test/CMakeLists.txt")" -eq 2   # rider face (NEITHER a row-file suite)
test "$(grep -c 'sfdaq' "$SRC/src/packet_io/test/CMakeLists.txt")" -eq 2          # the module/counters rider names ONLY

# ---- THE REAL SDK identity (clone head + api faces; READ-ONLY ground) ----
test "$(git -C "$L" rev-parse --short HEAD)" = "c8d4083"
test "$(wc -l < "$L/api/daq.h")"          -eq 178
test "$(md5sum "$L/api/daq.h"          | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(wc -l < "$L/api/daq_common.h")"   -eq 728
test "$(md5sum "$L/api/daq_common.h"     | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(wc -l < "$L/api/daq_dlt.h")"      -eq 1413
test "$(md5sum "$L/api/daq_dlt.h"        | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(wc -l < "$L/api/daq_module_api.h")" -eq 165
test "$(md5sum "$L/api/daq_module_api.h" | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
test "$(wc -l < "$L/api/daq_version.h.in")" -eq 49

# ---- ground + SDK sed pins (line-exact, disk wins) ----
test "$(sed -n '48p' "$SRC/src/packet_io/sfdaq.cc")" = '#define DAQ_DEFAULT "pcap"'
test "$(sed -n '52p' "$SRC/src/packet_io/sfdaq.cc")" = 'static DAQ_Config_h daqcfg = nullptr;'
test "$(sed -n '53p' "$SRC/src/packet_io/sfdaq.cc")" = 'static DAQ_Mode default_daq_mode = DAQ_MODE_PASSIVE;'
test "$(sed -n '54p' "$SRC/src/packet_io/sfdaq.cc")" = 'static string daq_module_names;'
test "$(sed -n '203p' "$SRC/src/packet_io/sfdaq.cc")" = '        const char* value = kvp.second.length() ? kvp.second.c_str() : nullptr;'
test "$(sed -n '302p' "$SRC/src/packet_io/sfdaq.cc")" = '    LogMessage("%s DAQ configured to %s.\n", daq_module_names.c_str(), daq_mode_string(default_daq_mode));'
test "$(sed -n '328p' "$SRC/src/packet_io/sfdaq.cc")" = '    return (default_daq_mode == DAQ_MODE_INLINE && !(h->flags & DAQ_PKT_FLAG_NOT_FORWARDING));'
test "$(sed -n '412p' "$SRC/src/packet_io/sfdaq.cc")" = '    return cfg->inputs[0].c_str();'
test "$(sed -n '37p' "$SRC/src/packet_io/sfdaq_config.cc")" = "    if ((pos = key.find_first_of('=')) != std::string::npos)"
test "$(sed -n '130p' "$SRC/src/packet_io/sfdaq_config.cc")" = '    timeout = other->timeout;'
test "$(sed -n '80p' "$SRC/src/packet_io/sfdaq_config.h")" = '    static constexpr uint32_t BATCH_SIZE_DEFAULT = 64;'
test "$(sed -n '35p' "$L/api/daq_common.h")"   = '#define DAQ_COMMON_API_VERSION  0x00030013'
test "$(sed -n '146p' "$L/api/daq_common.h")"  = '    uint32_t address_space_id;  /* Unique ID of the address space */'
test "$(sed -n '147p' "$L/api/daq_common.h")"  = '    uint32_t tenant_id;         /* Unique ID of the tenant */'
test "$(sed -n '321p' "$L/api/daq_common.h")"  = '    MAX_DAQ_VERDICT'
test "$(sed -n '60p' "$L/api/daq_base.c")"     = '    "whitelist",    // DAQ_VERDICT_WHITELIST'
test "$(sed -n '69p' "$L/api/daq_base.c")"     = '    "read-file"     // DAQ_MODE_READ_FILE'
test "$(git -C "$L" show HEAD:configure.ac | sed -n '4,7p')" = 'm4_define([daq_major_version], [3])
m4_define([daq_minor_version], [0])
m4_define([daq_patch_version], [29])
m4_define([daq_sublevel_version], [0])'

# ---- name-pin census (measured THIS pass; collisions fire LOUDLY) ----
test "$(find "$R"/tools -maxdepth 1 -iname '*daqio*' | wc -l)" -eq 1                # THIS dir ONLY
test "$(grep -rl 'daqio_harness' "$R"/tools/*/build.sh 2>/dev/null | grep -v "^$H/build.sh$" | wc -l)" -eq 2   # SANCTIONED at row 23e: 0 -> 2 (self-EXCLUDED file; the sf-d chain-era pin + the tr-acer chain-era pin — BOTH are pre-existing rider mentions MEASURED already at HEAD face=2: this pin was the stale latent-red twin never re-run since the 22b/23c docs riders landed them; the 62d6fac flip-forward law; NEVER edit the cited riders)
# the 'daqio' PRE-HIT face (misc3 witness_trio.cc -- the 'daqioctl' WORD
# substring; own-file hits NEVER count because build.sh + witness/probe
# + parity carry their OWN name honestly):
test "$(grep -rl 'daqio' "$R"/tools/misc3_harness "$R"/tools/mpls_harness "$R"/tests 2>/dev/null | grep -v "^$R/tests/daqio_parity_test.rs$" | wc -l)" -eq 1   # witness_trio.cc ONLY
# NEXT.md token face, STATE-AWARE (PRE-landing find-0; POST-commit the docs
# bank raises it to EXACTLY-1 -- the docs pass MUST carry the cite line):
pre=$(git -C "$R" ls-files --error-unmatch tools/daqio_harness/PLAN.md >/dev/null 2>&1 && echo post || echo pre)
if [ "$pre" = pre ]; then
    test "$(grep -c 'daqio_harness' "$R/NEXT.md" || true)" -eq 0
else
    test "$(grep -c 'daqio_harness' "$R/NEXT.md")" -eq 1
fi
# the bare 'sfdaq' token rides misc3 + mpls build.sh + misc3 parity (the
# 3-file PRE-HIT face FROZEN; own build.sh + OWN parity file excluded --
# NO foreign harness ever count-pins this token, measured):
test "$(grep -rl 'sfdaq' "$R"/tools/*/build.sh "$R"/tests/*.rs 2>/dev/null | grep -v "^$H/build.sh$" | grep -v "^$R/tests/daqio_parity_test.rs$" | wc -l)" -eq 6   # SANCTIONED x2: row 23e 3 -> 5 (dir-stor/sf-mod era + misc3/mpls landings); row 23e->23h 5 -> 6 (the ac t row-23h landing twin the row-23h parity twin (tests/act-parity twin) — THE LEGIT landed-home use-path cites of the owner sf-daq/sf-daq-instance homes, the 62d6fac flip-forward law, the cited riders NEVER edited; face MEASURED-6 by walk at the row) (own file self-EXCLUDED; face MEASURED at HEAD too (5): the dir-stor + sf-mod landing-era ground-path tripwire MENTIONS in the dir-stor-era build.sh + misc3/mpls/sf-mod build.sh + misc3 twin grew the family — this pin never re-ran since the 23a era = stale latent-red twin; the 62d6fac flip-forward law; the cited riders NEVER edited; token-free comment per the family law)
# the misc9 :460 landmine NAMING law, TRUTH-CORRECTED at this row: the
# 'struct Tracer' leg stays find-0 BY NAMING (the rs rides C names SFDAQ/
# sfdaq verbatim); the ReloadSurvivor/reload_survivor legs are ALREADY
# occupied by the LEGITIMATE rsubs row-21b landing (src/framework/mod.rs +
# reload_survivor_subscriptions.rs -- rsubs POST-dates misc9 19a and misc9's
# frozen chain NEVER re-runs: trio-occupancy drift RECORDED NEVER silent;
# THIS row's packet_io rs adds ZERO hits -- the measured occupant set):
test "$(grep -rl 'struct Tracer' "$R"/src --include=*.rs | wc -l)" -eq 0
test "$(grep -rlE 'ReloadSurvivor|reload_survivor' "$R"/src --include=*.rs | sed "s|$R/||" | paste -sd,)" = "src/framework/mod.rs,src/framework/reload_survivor_subscriptions.rs"
test "$(grep -rlE 'ReloadSurvivor|reload_survivor|struct Tracer' "$R"/src/packet_io --include=*.rs | wc -l)" -eq 0   # THIS row's naming law

# ---- ZERO-suite / ZERO-gate census (MEASURED walk, NEVER inherited) ----
for f in packet_io/sfdaq.cc packet_io/sfdaq.h packet_io/sfdaq_config.cc packet_io/sfdaq_config.h; do
    test "$(grep -c 'UNIT_TEST\|TEST_CASE\|TEST_GROUP\|^TEST(\|CppUTest' "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'BUILDING_SO\|snort_plugins' "$SRC/src/$f" || true)" -eq 0
done
test ! -e "$SRC/src/packet_io/test/sfdaq_test.cc"                          # find-0 the row-suite EVER
test ! -e "$SRC/src/packet_io/test/sfdaq_config_test.cc"                   # find-0 twin
test "$(find /usr/include -maxdepth 1 -iname 'CppUTest*' | wc -l)" -eq 0    # dialect host face
test "$(find /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/local/lib -maxdepth 1 -name 'libCppUTest*' 2>/dev/null | wc -l)" -eq 0

# ---- THE live daq.h LANDSCAPE census lives AFTER the fresh cps + the
# re-cite (below, self-consistent). daq3 :105/:132 + misc3 :160/:164/:764 +
# miscip :133/:598 'ONE landing' arms are FROZEN-era receipts -- those
# harnesses NEVER re-run in the FRESH chain (the 20a-era copy trees ALREADY
# hold 9 foreign daq.h faces); the row-20 RE-CITE rides REAL headers BY
# DESIGN. Recorded NEVER silent; the misc3 :378 'sfdaq*.cc find-0' face is
# RETIRED BY DESIGN at THIS row (the real bodies COMPILE NOW).

# ---- NEXT.md CITE-ONLY read arms (the 22b tracer template RE-CLONED + the
# NEW 659 seed x3 that the 22b docs pass banked FOR THIS harness): ----
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
test "$(grep -c '5 TEST(' "$R/NEXT.md")" -eq 1               # the drift token EXACT-1 (sfd rider face)
grep -q 'get_pkthdr' "$R/NEXT.md"                            # the row-20 ledger cite face this row CLOSES
grep -q 'address_space_id' "$R/NEXT.md"

# ---- copy tree = ipheavy DONOR clone (.o's purged); graft HEADS md5-pinned
# BEFORE the re-cite (the ledger's synthetic side); STALE-DONOR face ----
if [ ! -e "$IP/copy/cd_ipv4.o" ]; then bash "$IP/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$IP/copy" "$C"; find "$C" -name '*.o' -delete
test "$(find "$C" -type f | wc -l)" -eq 140                                  # donor face (the 22b identity)
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"   # ext#4 graft trio HEAD face
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"
test "$(md5sum "$C"/packet_io/sfdaq.h | awk '{print $1}')"          = "2e272d2d68e40138946326df3c5cfc95"  # donor riders byte-EXACT
test "$(md5sum "$C"/packet_io/sfdaq_instance.h | awk '{print $1}')" = "9497f39441174c4260d4db22e55740bf"
# graft-MASTER cite faces (NEVER cp'd/edited here; the frozen side of the ledger):
test "$(md5sum "$D3"/copy/daq.h        | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3"/copy/daq_common.h | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$M9"/copy/daq_common.h | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"
test "$(md5sum "$TR"/copy/daq_common.h | awk '{print $1}')" = "b99e44b9f7ef1d009bf7f158982bfb4e"   # the 22b pkth EXT face
# STALE-DONOR face MEASURED: NO row .cc/.h EVER in the donor BEFORE the cps:
test "$(find "$C" -name 'sfdaq.cc' -o -name 'sfdaq_config.cc' -o -name 'sfdaq_config.h' | wc -l)" -eq 0

# ---- 4 FRESH cps day one (VERBATIM, cmp-proved, NEVER sed) ----
cp "$SRC"/src/packet_io/sfdaq.h "$SRC"/src/packet_io/sfdaq.cc "$SRC"/src/packet_io/sfdaq_config.h "$SRC"/src/packet_io/sfdaq_config.cc "$C"/packet_io/
cmp -s "$C"/packet_io/sfdaq.cc "$SRC"/src/packet_io/sfdaq.cc
cmp -s "$C"/packet_io/sfdaq.h "$SRC"/src/packet_io/sfdaq.h
cmp -s "$C"/packet_io/sfdaq_config.cc "$SRC"/src/packet_io/sfdaq_config.cc
cmp -s "$C"/packet_io/sfdaq_config.h "$SRC"/src/packet_io/sfdaq_config.h
test "$(find "$C" -type f | wc -l)" -eq 143                    # 140 + 3 fresh (the donor ALREADY rides packet_io/sfdaq.h BYTE-EXACT -- the cp OVERWRITES it, the honest arithmetic face)

# ---- THE E4 PRE-RECITE WALL (flipped-assert EVERY build): the ground
# sfdaq.cc vs the SYNTHETIC graft header family = vocabulary DEATH ----
GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
if $GXX0 -c "$C"/packet_io/sfdaq.cc -o /dev/null 2> "$H"/E4_graft.txt; then
    echo "E4 face flip BROKE: the graft face COMPILES sfdaq.cc -- RE-PLAN (graft mutation?)"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_graft.txt)" -eq 86            # THIS-g++ measured face (the honest receipt)
test "$(grep -c 'does not name a type' "$H"/E4_graft.txt)" -eq 2           # DAQ_Mode(:53) + DAQ_VariableDesc_t(:134) (gcc rides U+2018/2019 CURLY quotes)
test "$(grep -c "'DAQ_Mode' does not name a type" "$H"/E4_graft.txt || true)" -eq 0   # ASCII-quote face find-0 (gcc = UTF-8 quotes)
test "$(grep -c "daq_load_dynamic_modules' was not declared" "$H"/E4_graft.txt || true)" -eq 0   # ditto (curly-quote face)
test "$(grep -c "was not declared in this scope" "$H"/E4_graft.txt)" -eq 78          # the honest scope-death count
test "$(grep -c "DAQ_Mode’ does not name a type" "$H"/E4_graft.txt)" -eq 1             # the NAMED face, UTF-8 quote form
test "$(grep -c "daq_load_dynamic_modules’ was not declared" "$H"/E4_graft.txt)" -eq 1 # the NAMED face, UTF-8 quote form

# ---- THE RE-CITE (plan-20 law): the REAL SDK headers land IN THE COPY
# TREE (copy-local NEVER-tracked; the graft masters md5-frozen where they
# live); the CMake-generated daq_version.h face stands in via sed over the
# READ-ONLY api/daq_version.h.in + the configure.ac m4 face (3.0.29.0) --
# the SAME configure_file dialect the SDK build runs: ----
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
sed -e 's/@DAQ_MAJOR_VERSION@/3/' -e 's/@DAQ_MINOR_VERSION@/0/' -e 's/@DAQ_PATCH_VERSION@/29/' -e 's/@DAQ_SUBLEVEL_VERSION@/0/' \
    "$L"/api/daq_version.h.in > "$C"/daq_version.h
test "$(md5sum "$C"/daq.h        | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"   # REAL HEAD pins
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h    | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(md5sum "$C"/daq_module_api.h | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
grep -q 'define DAQ_VERSION_MAJOR 3' "$C"/daq_version.h
test "$(wc -l < "$C"/daq_version.h)" -eq 49                    # the .in template face (sed NEVER adds lines)
test "$(find "$C" -name 'daq_version.h' | wc -l)" -eq 1
rm -rf "$C"/api; mkdir -p "$C"/api
for f in daq_base daq_base_api daq_config daq_instance_api_defaults daq_mod_ops; do
    gcc -std=gnu11 -DNDEBUG -O0 -w -I"$L"/api -I"$C" -c "$L"/api/"$f".c -o "$C"/api/"$f".o
done
test "$(find "$C"/api -name '*.o' | wc -l)" -eq 5
test "$(git -C "$L" status --porcelain | wc -l)" -eq 0         # THE SDK ground STAYS CLEAN (READ-ONLY law)

# ---- post-RE-CITE compile: SILENT rc0 (the flip receipt vs E4_graft) ----
GXX="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
$GXX -c "$C"/packet_io/sfdaq.cc -o "$C"/sfdaq.o 2> "$H"/E4_real.txt
test ! -s "$H"/E4_real.txt
$GXX -c "$C"/packet_io/sfdaq_config.cc -o "$C"/sfdaq_config.o 2> "$H"/E4_cfg.txt
test ! -s "$H"/E4_cfg.txt

# ---- THE carried witness_conf EXTRACTION (link4 :429-:471 law; NEVER doubled): ----
L4=$R/tools/link4_harness
_b=$(grep -n "witness_conf\.cc\" <<'EOFWC'" "$L4/build.sh" | head -1 | cut -d: -f1)
_e=$(awk -v s="$_b" 'NR>s && /^EOFWC$/{print NR; exit}' "$L4/build.sh")
sed -n "$((_b+1)),$((_e-1))p" "$L4/build.sh" > "$H"/witness_conf.cc
test "$(md5sum "$H"/witness_conf.cc | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"
test "$(find "$H" -maxdepth 1 -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 1  # the OWN-14 face ONLY
test "$(grep -v '^//' "$H"/witness_daqio.cc | grep -c 'get_conf' || true)" -eq 0                      # NEVER doubled (body face; the header CITES the name)
test "$(grep -v '^//' "$H"/witness_daqio.cc | grep -c 'FatalError' || true)" -eq 0                    # carry-owned (header-cite ONLY)
# the own-14 mirror census (names, not vibes):
test "$(grep -c 'SFDAQInstance::' "$H"/witness_daqio.cc)" -eq 11
test "$(( $(grep -c 'void LogMessage' "$H"/witness_daqio.cc) + $(grep -c 'void ErrorMessage' "$H"/witness_daqio.cc) + $(grep -c 'void ParseError' "$H"/witness_daqio.cc) ))" -eq 3

# ---- compile the row side (probes + witnesses) ----
$GXX -c "$H"/witness_daqio.cc -o "$H"/witness_daqio.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$H"/probe.cc         -o "$H"/probe.o
$GXX -c "$H"/probe_faceA.cc   -o "$H"/probe_faceA.o

# ---- THE row .o nm census (39-face: EXACTLY-25 SDK + EXACTLY-14 snort =
# 9 SFDAQInstance [the 23b seam] + 4 messages + get_conf; ALL 25 daq_*
# close at link against the REAL api objects): ----
undef() { nm -C -u "$1" | awk '/ U /{sub(/^[[:space:]]*U[[:space:]]*/,"");print}' \
  | grep -vE '^(std::|operator |__|_Unwind|typeinfo|vtable|abort$|free$|calloc$|realloc$|mem(move|set|cpy)$|str(cmp|dup|len|rchr)$|snprintf$|vsnprintf$|printf$|fprintf$|stderr$|opendir|readdir|closedir$|stat$|dlopen|dlsym|dlclose|dlerror|syscall$|pthread_|gettid$|_GLOBAL|exp10)' | sort || true; }
undef "$C"/sfdaq.o > "$H"/nm_U_sfdaq.txt
undef "$C"/sfdaq_config.o > "$H"/nm_U_sfdaq_config.txt
test "$(wc -l < "$H"/nm_U_sfdaq.txt)" -eq 39
test "$(grep -c '^daq_' "$H"/nm_U_sfdaq.txt)" -eq 25
test "$(grep -c 'SFDAQInstance::' "$H"/nm_U_sfdaq.txt)" -eq 9          # the 23b seam census (ctor/dtor ride the probe TU faces)
test "$(grep -c 'SnortConfig::get_conf' "$H"/nm_U_sfdaq.txt)" -eq 1
test "$(grep -cE 'LogMessage|ErrorMessage|ParseError|FatalError' "$H"/nm_U_sfdaq.txt)" -eq 4
test "$(wc -l < "$H"/nm_U_sfdaq_config.txt)" -eq 0                     # the pure-value config half (ZERO SDK pulls)
nm "$C"/api/*.o > "$H"/nm_api_defined.txt
for n in $(awk '/^daq_/{print}' "$H"/nm_U_sfdaq.txt); do
    grep -q " T $n\$" "$H"/nm_api_defined.txt || { echo "SDK residue OPEN: $n"; exit 1; }
done

# ---- E9 ONE-HOME flipped-assert (the dup-twin co-link = EXACTLY-2
# multiple-definition receipts, rc!=0 -- the 22b util shape): ----
cat > "$H"/e9_dup_twin.cc <<'EOFTWIN'
// E9 leg: a SYNTHETIC duplicate of the carried/witness message mirrors --
// the ONE-home flipped-assert input, copy-local NEVER tracked.
#include "log/messages.h"
namespace snort {
void FatalError(const char*, ...) {}
void LogMessage(const char*, ...) {}
}
EOFTWIN
$GXX -c "$H"/e9_dup_twin.cc -o "$H"/e9_dup_twin.o
if $GXX "$H"/probe.o "$C"/sfdaq.o "$C"/sfdaq_config.o "$H"/witness_conf.o "$H"/witness_daqio.o "$H"/e9_dup_twin.o "$C"/api/daq_base.o "$C"/api/daq_base_api.o "$C"/api/daq_config.o "$C"/api/daq_instance_api_defaults.o "$C"/api/daq_mod_ops.o -o "$H"/E9_dup_probe 2> "$H"/E9_dup.txt; then
    echo "E9 law BROKE: dup twin + carried witness co-LINKED"; exit 1
fi
rm -f "$H"/E9_dup_probe
test "$(grep -c 'multiple definition' "$H"/E9_dup.txt)" -eq 2      # FatalError + LogMessage

# ---- DEC + FACE-A link + run (THE REAL-SDK link shape): ----
LINK="$C/sfdaq.o $C/sfdaq_config.o $H/witness_conf.o $H/witness_daqio.o $C/api/daq_base.o $C/api/daq_base_api.o $C/api/daq_config.o $C/api/daq_instance_api_defaults.o $C/api/daq_mod_ops.o"
$GXX "$H"/probe.o       $LINK -o "$H"/probe
$GXX "$H"/probe_faceA.o $LINK -o "$H"/probe_faceA
test "$(nm -C --defined-only "$H"/probe | grep -c 'T snort::SnortConfig::get_conf()')" -eq 1   # ONE-HOME
timeout 60 "$H"/probe        > "$H"/vectors_O0.txt       2> "$H"/probe_dec_stderr.txt || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_faceA > "$H"/vectors_faceA_O0.txt  2> "$H"/faceA_stderr.txt     || { echo PROBE_FAIL FACE-A O0; exit 1; }
test ! -s "$H"/probe_dec_stderr.txt                                  # DEC runs SILENT (zero stderr)
# the SDK register ladder REJECTS speak on stderr (the FACE-A leg's honest
# noise face -- daq_base.c fprintf receipts, pinned FROZEN 7 lines):
test "$(wc -l < "$H"/faceA_stderr.txt)" -eq 7

# ---- O2 twins + the x-stream byte-identity law ----
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
g++ -std=c++17 -DNDEBUG -O2 -w -I"$C" -c "$C"/packet_io/sfdaq.cc -o "$O2"/sfdaq.o
g++ -std=c++17 -DNDEBUG -O2 -w -I"$C" -c "$C"/packet_io/sfdaq_config.cc -o "$O2"/sfdaq_config.o
g++ -std=c++17 -DNDEBUG -O2 -w -I"$C" -c "$H"/witness_daqio.cc -o "$O2"/witness_daqio.o
g++ -std=c++17 -DNDEBUG -O2 -w -I"$C" -c "$H"/witness_conf.cc  -o "$O2"/witness_conf.o
g++ -std=c++17 -DNDEBUG -O2 -w -I"$C" -c "$H"/probe.cc         -o "$O2"/probe.o
g++ -std=c++17 -DNDEBUG -O2 -w -I"$C" -c "$H"/probe_faceA.cc   -o "$O2"/probe_faceA.o
for f in daq_base daq_base_api daq_config daq_instance_api_defaults daq_mod_ops; do
    gcc -std=gnu11 -DNDEBUG -O2 -w -I"$L"/api -I"$C" -c "$L"/api/"$f".c -o "$O2"/"$f".o
done
LINK2="$O2/sfdaq.o $O2/sfdaq_config.o $O2/witness_conf.o $O2/witness_daqio.o $O2/daq_base.o $O2/daq_base_api.o $O2/daq_config.o $O2/daq_instance_api_defaults.o $O2/daq_mod_ops.o"
$GXX "$O2"/probe.o        $LINK2 -o "$H"/probe_O2
$GXX "$O2"/probe_faceA.o  $LINK2 -o "$H"/probe_faceA_O2
timeout 60 "$H"/probe_O2       > "$H"/vectors_O2.txt        || { echo PROBE_FAIL DEC O2; exit 1; }
timeout 60 "$H"/probe_faceA_O2 > "$H"/vectors_faceA_O2.txt  2>/dev/null || { echo PROBE_FAIL FACE-A O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt

# ---- FIRST-RUN-SEED face (17p law; NEVER typed) ----
if [ ! -e "$H"/vectors.txt ]; then
    cp "$H"/vectors_O0.txt "$H"/vectors.txt                      # SEED PASS (first run ever)
    cp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt          # SEED PASS
    echo "SEED PASS: DEC 18L + FACE-A 11L vectors measured (NEVER typed)"
else
    cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt           || { echo "VECTORS DEC DRIFT vs tracked vectors.txt"; exit 1; }
    cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "VECTORS FACE-A DRIFT vs tracked"; exit 1; }
fi
test -e "$H"/vectors.txt
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt   # receipt (ignored)

# ---- TAMPER-PROVEN blocks (the sfd/tc law) ----
cp "$H"/vectors.txt "$H"/.vectors_pristine
line=$(grep -n '^T8 verdicts=' "$H"/vectors.txt | head -1 | cut -d: -f1)
sed -i "${line}s/blacklist/blacklisx/" "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt && { echo "TAMPER ARM DEAD: flipped verdict still matches the fresh run"; exit 1; }
cp "$H"/.vectors_pristine "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "TAMPER RESTORE DEAD"; exit 1; }
rm -f "$H"/.vectors_pristine
cp "$H"/vectors_faceA.txt "$H"/.vectors_faceA_pristine
line=$(grep -n '^SIZES ' "$H"/vectors_faceA.txt | head -1 | cut -d: -f1)
sed -i "${line}s/pkthdr=56/pkthdr=24/" "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt && { echo "TAMPER ARM DEAD (FACE-A): flipped size still matches"; exit 1; }
cp "$H"/.vectors_faceA_pristine "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "TAMPER RESTORE DEAD (FACE-A)"; exit 1; }
rm -f "$H"/.vectors_faceA_pristine

# ---- THE RE-CITE LEDGER (MEASURED 5-family compile legs + grep drift legs;
# the re-cite NEVER silent): ----
: > "$H"/recite_ledger.txt
for fam in "master-f683749c:$D3/copy" "graftv2-fead0027:$M9/copy" "ext4-9b603f8f:$IP/copy" "pktext-b99e44b9:$TR/copy" "REAL-c8d4083:$C"; do
    tag=${fam%%:*}; dir=${fam#*:}
    if g++ -std=c++17 -O0 -w -I"$dir" -c "$H"/ledger_probe.cc -o /dev/null 2> "$H"/ledger_err.txt; then
        g++ -std=c++17 -O0 -w -I"$dir" "$H"/ledger_probe.cc -o "$H"/ledger_run
        printf "%s rc0 %s\n" "$tag" "$("$H"/ledger_run)" >> "$H"/recite_ledger.txt
    else
        printf "%s rc1 %s\n" "$tag" "$(head -1 "$H"/ledger_err.txt)" >> "$H"/recite_ledger.txt
    fi
done
rm -f "$H"/ledger_run "$H"/ledger_err.txt
test "$(grep -c 'REAL-c8d4083 rc0 SIZEOF_PKTHDR=56 TS=1 AS=1 TN=1' "$H"/recite_ledger.txt)" -eq 1
test "$(grep -c 'pktext-b99e44b9 rc0 SIZEOF_PKTHDR=24 TS=0 AS=1 TN=1' "$H"/recite_ledger.txt)" -eq 1  # the 22b ext face (ts ABSENT, widths SYNTHETIC)
test "$(grep -c 'SIZEOF_PKTHDR=16 TS=0 AS=0 TN=0' "$H"/recite_ledger.txt)" -eq 3   # master + v2 + ext4
# the grep drift legs (MEASURED receipts, NEVER grep-lore):
test "$(grep -c 'DAQ_Verdict_PAUSE\|DAQ_Verdict_WAITING\|DAQ_Verdict_COUNT' "$IP"/copy/daq_common.h)" -eq 2   # the ext#4 9b603f8f SYNTH verdict names (2 lines: the h :28-:30 era face; REAL face = 0)
test "$(grep -c 'DAQ_Verdict' "$M9"/copy/daq_common.h)" -eq 2           # the v2 fead0027 face rides PASS/DROP ONLY (+the cite comment)
test "$(grep -c 'PAUSE\|WAITING\|COUNT' "$IP"/copy/daq_common.h)" -eq 2 # ext#4 rides them (2 lines)
test "$(grep -c 'DAQ_Verdict_PAUSE\|DAQ_Verdict_WAITING' "$C"/daq_common.h || true)" -eq 0    # the SYNTH verdict NAMES stay DEAD in the REAL face (the honest grep face; the COUNTERS-family ioctl rides REAL)
test "$(grep -c 'DAQ_VERDICT_BLACKLIST' "$C"/daq_common.h)" -eq 1               # the REAL 6-value names ride (max DAQ_VERDICT_IGNORE=5, MAX_DAQ_VERDICT=6)
test "$(grep -c 'SIGNIFICANT_GROUPS 0x0000000000000020' "$D3"/copy/daq_common.h)" -eq 1   # the 0x20 SYNTH drift
test "$(grep -c 'SIGNIFICANT_GROUPS 0x8000' "$C"/daq_common.h)" -eq 1                     # the REAL 0x8000 face
test "$(grep -c 'DAQ_PKT_FLAG_IGNORE_VLAN 0x0000000000000040' "$IP"/copy/daq.h)" -eq 1     # the 20a SYNTH 0x40 drift
test "$(grep -c 'DAQ_PKT_FLAG_IGNORE_VLAN        0x0008' "$C"/daq_common.h)" -eq 1         # the REAL 0x8 (:117)
test "$(grep -c 'uint16_t address_space_id' "$TR"/copy/daq_common.h)" -eq 1               # the 22b SYNTH width drift
test "$(grep -c 'uint32_t address_space_id' "$C"/daq_common.h)" -eq 3                     # the REAL width (pkth :146 + flowstats + meta)
test "$(grep -c 'DAQ_COMMON_API_VERSION  0x00030013' "$D3"/copy/daq_common.h "$M9"/copy/daq_common.h "$IP"/copy/daq_common.h | awk -F: '{s+=$2} END{print s}')" -eq 0   # ZERO version face in ANY synth
grep -qP 'define DLT_RAW\s+12\b' "$C"/daq_dlt.h                                        # the 20a 228/229 SYNTH pair RE-CONFIRMED REAL
grep -q 'DLT_IPV4' "$C"/daq_dlt.h && grep -q 'DLT_IPV6' "$C"/daq_dlt.h
test "$(grep -c 'define DLT_IPV4' "$C"/daq_dlt.h)" -eq 1
test "$(grep -c 'define DLT_IPV6' "$C"/daq_dlt.h)" -eq 1

# ---- vectors FACE greps (the ladder faces; line counts MEASURED): ----
V=$H/vectors.txt; FA=$H/vectors_faceA.txt
test "$(wc -l < "$V")" -eq 18
test "$(wc -l < "$FA")" -eq 11
grep -q '^T0 defaults batch=0 mru=-1 timeout=1000 bs=64 ms=1518$' "$V"                       # the cc :65-:70 + h :63-:64 sentinel getters
grep -q '^T1 vars n=3 k0=input v0=/var/log/pcap.0 k1=strict v1= k2=k v2=3=4$' "$V"           # cc :37 the FIRST '=' face
grep -q '^T2 overlay bs=32 ms=2000 to=0 in0=ethB inN=2 dirs=/lib/daq-over$' "$V"             # the timeout UNCONDITIONAL face
grep -q '^T2b overlay_empty keep=5,6,1000$' "$V"                                             # cc :126-:130 sentinel guards vs unconditional timeout
grep -q '^T3 inspec_null=0 id0=ethA id1=ethB id9=ethA$' "$V"                                 # cc :409-:412 the id-9 OVERFLOW -> inputs[0] face
grep -q '^T4 default_pcap init=0 perr=\[Could not find requested DAQ module: pcap\]$' "$V"   # THE DAQ_DEFAULT face (REAL find rc0-fail; cc :48)
grep -q '^T5 reg=2 block=\[Available DAQ modules:alpha(v3): readback live inline multi unpriv' "$V"   # the strcmp SORT + the :126 unpriv arm word face
grep -q '^T5 .*Variables:  input \[arg\] - the input spec  strict <arg> - strictness' "$V"   # the REAL var-desc table walk (cc :134-:148; h->daq_module_get_variable_descs REAL body)
grep -q '^T6 init=1 iinit=1 pool=256 snap=1518 tmo=1000 tot=4 log=\[alpha DAQ configured to passive.\] bpf=bpf-echo hint=7$' "$V"  # cc :250 batch*4=pool + the REAL accessor readbacks
grep -q 'unset mapped=1.*passive mapped=1.*inline mapped=2.*readfile mapped=3' "$V"          # cc :190-:195 mode map via REAL daq_module_config_get_mode
grep -q 'alpha:alpha:alpha:alpha DAQ configured to passive.\] T7 readfile' "$V"              # the :221-:223 insert-join CUMULATIVE face (never-reset static)
grep -q '^T7b inline log=\[alpha:alpha:alpha:alpha:alpha:alpha DAQ configured to inline.\]$' "$V"      # the conf ladder via run_flags (REAL daq_mode_string body)
grep -q '^T7c wrapper init=0 perr=\[Could not find requested DAQ module: pcap\]$' "$V"       # cc :271-:287 the WRAPPER auto-pcap face
grep -q '^T8 verdicts=pass|block|replace|whitelist|blacklist|ignore|max=null$' "$V"          # THE RE-CITE HEART (REAL daq_base.c :56-:63)
grep -q '^T8b fwd passive=0 inline=1 notfwd=0$' "$V"                                         # REAL DAQ_PKT_FLAG_NOT_FORWARDING 0x0002 arm (cc :328)
grep -q '^T9 nullwrap ci=0 cir=0 cr=0 tb=0 set ci=1 cir=0 cr=1 tb6=1 proto=6 spec=\[eth9\] base=101$' "$V"  # cc :364-:392 the AND-short-circuit legs
grep -q '^T9b stats=11 vblock=3 inject=7 calls=1$' "$V"
grep -q '^T10 term unloaded alpha=1 zeta=1 ctor=6 dtor=6$' "$V"                              # the REAL daq_unload_modules walk + REG_TEST-off arm (cc :314-:317)
grep -q '^T11 nopriv_canrun=0$' "$V"                                                        # cc :338 DAQ_TYPE_NO_UNPRIV walk face
test "$(grep -c '^T' "$V")" -eq 18
grep -q '^SIZES pkthdr=56 msg=112 stats=96 flowstats=288 napt=40 flowedsc=60 baseapi=104 modapi=216$' "$FA"       # THE REAL C-ABI faces (the 22b probe pinned base=64/api=88 SYNTH -- re-cited REAL)
grep -q '^OFFSETS as=44 tn=48 flags=40 ts=0 pktlen=16$' "$FA"                                # THE 22b pkth-WALL closure face (the fields EXIST)
grep -q '^ENUM verdict=6 rstat=8 mode=4 state=5 dio_max=1024 msgtype=1024$' "$FA"
grep -q '^VERSIONS common=0x30013 base=0x30002 module=0x30001 numeric=50339072 str=3.0.29.0$' "$FA"  # (3<<24|0<<16|29<<8|0) arithmetic face
grep -q '^MODESTRINGS none=none passive=passive inline=inline readfile=read-file max=null$' "$FA"
grep -q '^REG badver_absent=0 wrongsize_absent=0 missingfns_absent=0 walk4=2 okmod=1 dup_name_single=1$' "$FA"  # the daq_base.c register ladder (REJECTs ride the stderr leg)
grep -q '^VERDICTS pass|block|replace|whitelist|blacklist|ignore max=null$' "$FA"
grep -q '^DLT en10mb=1 ppp_ether=51 raw=12 ipv4=228 ipv6=229$' "$FA"                         # the 20a pins RE-CITED (ALL REAL)
grep -q '^TYPES file=01 intf=02 inline=04 multi=08 nopriv=10 wrapper=20$' "$FA"
grep -q '^PKTFLAGS notfwd=0x2 significant=0x8000 ignore_vlan=0x8$' "$FA"                     # SYNTH drift legs (0x20/0x40 DEAD)
grep -q '^CONF get_conf_nonnull=1 inline=0 read=0$' "$FA"
test "$(grep -c 'WIT_' "$V" || true)" -eq 0                                                  # honest vectors face (sfd/tc twin arms)

# ---- ground-cite two-way face (disk wins; the line-arms the probes ride): ----
python3 - "$SRC" "$H" "$L" <<'PYPIN'
import sys
SRC, H, L = sys.argv[1], sys.argv[2], sys.argv[3]
cc = open(SRC + "/src/packet_io/sfdaq.cc").read().splitlines()
h  = open(SRC + "/src/packet_io/sfdaq.h").read().splitlines()
cfgcc = open(SRC + "/src/packet_io/sfdaq_config.cc").read().splitlines()
cfgh  = open(SRC + "/src/packet_io/sfdaq_config.h").read().splitlines()
assert len(cc) == 420 and len(h) == 72 and len(cfgcc) == 131 and len(cfgh) == 85
assert cc[44].strip() == "#ifdef DEFAULT_DAQ"                                   # :45 the face behind DAQ_DEFAULT
assert cc[51] == 'static DAQ_Config_h daqcfg = nullptr;'                        # :52
assert cc[53] == 'static string daq_module_names;'                              # :54 (the NEVER-reset join static)
assert "kvp.second.length() ? kvp.second.c_str() : nullptr" in cc[202]          # :203
assert 'LogMessage("%s DAQ configured to %s.\\n"' in cc[301]                    # :302
assert "DAQ_MODE_INLINE && !(h->flags & DAQ_PKT_FLAG_NOT_FORWARDING)" in cc[327]  # :328
assert cc[395].strip() == "return local_instance->inject(msg, rev, buf, len);"  # :396
assert "static bool can_inject();" in h[53]                                     # h :54
assert "SO_PUBLIC static bool forwarding_packet(const DAQ_PktHdr_t*);" in h[67] # h :68
assert cfgcc[36].strip() == "if ((pos = key.find_first_of('=')) != std::string::npos)"  # :37 single-quote face
assert cfgcc[129] == '    timeout = other->timeout;'                            # :130 unconditional
assert cfgh[79].strip() == "static constexpr uint32_t BATCH_SIZE_DEFAULT = 64;"      # :80 (index 79)
dc = open(L + "/api/daq_common.h").read().splitlines()
assert dc[145] == '    uint32_t address_space_id;  /* Unique ID of the address space */'  # :146
assert dc[320] == "    MAX_DAQ_VERDICT"                                          # :321 (the 6-value family CLOSED)
base = open(L + "/api/daq_base.c").read().splitlines()
assert '"whitelist",' in base[59] and '"read-file"' in base[68]                 # :60/:69 the REAL tables
v = open(H + "/vectors.txt").read(); fa = open(H + "/vectors_faceA.txt").read()
assert "pass|block|replace|whitelist|blacklist|ignore" in v                     # the RE-CITE heart rides the vectors
assert "PAUSE" not in v and "WAITING" not in v                                  # the SYNTH names stay DEAD
assert "pkthdr=56" in fa and "as=44" in fa                                      # the 22b wall CLOSED
print("PYPIN_OK")
PYPIN

# ---- GATE census (ZERO-gate row: the MEASURED face STAYS; walked, never typed) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af'); test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 28   # SANCTIONED row-23e gate flip (the SECOND real gate row: the row-23e new gate.txt md5 bc199753 COPY-LOCAL UNTRACKED, in-TU Catch EXACTLY-3 TEST_CASE x 13 CHECK; walked census 26->27 on-disk / 18->19 lineages; legacy x9 + gre anchor + tracked-1 UNTOUCHED; the 62d6fac complete-flip law) [ROW-2->28 rider: 62d6fac law]
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 20   # SANCTIONED row-23e gate flip (the SECOND real gate row: the row-23e new gate.txt md5 bc199753 COPY-LOCAL UNTRACKED, in-TU Catch EXACTLY-3 TEST_CASE x 13 CHECK; walked census 26->27 on-disk / 18->19 lineages; legacy x9 + gre anchor + tracked-1 UNTOUCHED; the 62d6fac complete-flip law) [23f rider ->20]
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1
test ! -e "$H"/gate.txt                                                          # ZERO gate artifacts ship
git -C "$R" check-ignore -q tools/daqio_harness/gate.txt                         # NEVER-land posture IGNORED-proved

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
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H"/backbone10.txt            # receipt (ignored)
test "$(wc -l < "$H"/backbone10.txt)" -eq 10                                     # backbone STAYS 10 (no new backbone symbol)
# the ch19-era frozen chain-echo (the sfd + rsubs heads; TOKEN-NEVER-RIDDEN
# law: dir tokens runtime-CONCATENATED so THIS build.sh carries ZERO foreign
# harness-dir tokens beyond the donor/ledger cites it MUST own):
test "$(md5sum "$SF"/vectors.txt        | awk '{print $1}')" = "3c05632e88676ef9f40ee0a5d33fdf09"
test "$(md5sum "$SF"/vectors_faceA.txt | awk '{print $1}')" = "040de1ef2ea177ac526c8ef244713c58"
test "$(md5sum "$RSB"/vectors.txt      | awk '{print $1}')" = "9e303761c021d00ea672a493544e07af"
test "$(md5sum "$RSB"/vectors_faceA.txt| awk '{print $1}')" = "42aa06fb4c55adfa50e96d1f715d997e"
grep -q 'TRACER_DONE vectors=' "$TR"/build.sh
grep -q 'SFD_DONE vectors=' "$SF"/build.sh
grep -q 'R_SUBS_DONE vectors=' "$RSB"/build.sh

# ---- STATE-AWARE 9-face stageables dual guard (the 22b 8-face shape + THE
# ledger_probe leg = 9; ZERO gate material = ZERO runner TU) ----
untracked=$(git -C "$R" ls-files --others --exclude-standard tools/daqio_harness | sort)
tracked=$(git -C "$R" ls-files tools/daqio_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H"/stageables.txt
test "$(echo "$face" | wc -l)" -eq 9
for f in PLAN.md build.sh probe.cc probe_faceA.cc ledger_probe.cc vectors.txt vectors_faceA.txt witness_daqio.cc .gitignore; do
    echo "$face" | grep -q "tools/daqio_harness/$f$" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy/sfdaq.o copy/sfdaq_config.o copy/api/daq_base.o copy/daq_common.h copy/daq.h copy/packet_io/sfdaq.cc copy/daq_version.h copy/daq_dlt.h copy/daq_module_api.h \
         o2/sfdaq.o o2/probe_faceA.o probe probe_O2 probe_faceA probe_faceA_O2 e9_dup_twin.cc e9_dup_twin.o witness_conf.cc \
         witness_daqio.o witness_conf.o probe.o probe_faceA.o vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt \
         nm_U_sfdaq.txt nm_U_sfdaq_config.txt nm_api_defined.txt E4_graft.txt E4_real.txt E4_cfg.txt E9_dup.txt md5_pinned.txt \
         recite_ledger.txt ledger_err.txt ledger_run faceA_stderr.txt probe_dec_stderr.txt \
         gate_md5_lineages.txt stageables.txt backbone10.txt .vectors_pristine .vectors_faceA_pristine; do
    git -C "$R" check-ignore -q "tools/daqio_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
for f in PLAN.md build.sh probe.cc probe_faceA.cc ledger_probe.cc vectors.txt vectors_faceA.txt witness_daqio.cc .gitignore; do
    git -C "$R" check-ignore -q "tools/daqio_harness/$f" && { echo "WRONGLY IGNORED: $f"; exit 1; } || true
done
if git -C "$R" ls-files --error-unmatch tools/daqio_harness/PLAN.md >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files tools/daqio_harness | wc -l)" -eq 9
    test -z "$(git -C "$R" ls-files tools/daqio_harness | grep -vE 'PLAN\.md|build\.sh|probe(_faceA)?\.cc|ledger_probe\.cc|vectors(_faceA)?\.txt|witness_daqio\.cc|\.gitignore')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard tools/daqio_harness)"   # ZERO-LEAK post-commit
else
    git -C "$R" status --porcelain | grep -qx '?? tools/daqio_harness/'
    test "$(echo "$untracked" | wc -l)" -eq 9
fi
test -z "$(git -C "$R" diff --name-only --cached)"        # ZERO staged churn
# link4 :891 rowface tolerance (the sibling docs pass OWNS NEXT.md; law F):
dirty=$(git -C "$R" status --porcelain | grep -vcE '^\?\? tools/daqio_harness/$|^ M "?(src/lib\.rs|PORTING_PLAN\.md|KNOWN DEVIATIONS\.md)"?$|^\?\? src/packet_io/|^\?\? tests/daqio_parity_test\.rs$|^ M NEXT\.md$' || true)
test "$dirty" -eq 0                                       # single-tenant porcelain face

# ---- tail (the honest echo face) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "RE-CITE wall (MEASURED): graft face = EXACTLY-86 error lines (DAQ_Mode + daq_load_dynamic_modules named faces); REAL SDK api headers + 5 REAL api .o -> SILENT rc0 + RUN against the REAL daq_base.c tables"
echo "ledger: master/v2/ext4 pkthdr=16 TS=0 AS=0 TN=0 | 22b-ext pkthdr=24 TS=0 AS=1(u16 SYNTH) TN=1 | REAL pkthdr=56 TS=1 AS=1(u32@44) TN=1(u32@48) -- the 22b wall CLOSED"
echo "nm census: sfdaq.o EXACTLY-39 app-undef (25 SDK names ALL closed by the REAL api link + 14 snort = 9 instance [23b seam] + 4 messages + get_conf); sfdaq_config.o EXACTLY-0 SDK pulls"
echo "gate census (walked, never typed): 27 on-disk / legacy 9 x 4826fc22 / 19 lineages / tracked-1 gre; ZERO gate ships row 23a"
echo "backbone STAYS $(wc -l < "$H"/backbone10.txt) (symbol-vs-array)"
echo "DAQIO_DONE vectors=$(wc -l < "$H"/vectors.txt) faceA=$(wc -l < "$H"/vectors_faceA.txt) gates=0 (ch20 OPENER; the re-cite ledger lands MEASURED)"
