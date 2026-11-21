#!/usr/bin/env bash
# misc9_harness -- row 19a: chapter-19 P1 = the FRAMEWORK/MAIN MISC PAIR:
# framework/module.cc 403 L (md5 9608434cb5d1820d6033a32632080499, the wc_md5
# receipt face) + main/reload_tracker.cc 89 L (bdd9e3d773904514e8672a261fb6
# fddc) = 492 L (PLAN §1 P1 pick; the sum asserted EVERY build).
# THE DONOR-VERBATIM HALF (the FIRST row of the port whose 403-L half needs
# NO cp AT ALL): framework/module.cc ALREADY rides the donor copy tree at
# copy/framework/module.cc (byte-ident to ground, md5-equality asserted EVERY
# build) -- module.o is a backbone member since the 18c lineage (PLAN §2;
# link4 REAL list :419 cites it). THE ONE-CP HALF: reload_tracker.cc + its
# 49-L header reload_tracker.h (md5 598e08b4...) = the ONLY cps THIS row
# makes: 1/4 includes fresh (RECON face re-measured: reload_tracker.h find-0;
# control/control.h + log/messages.h + main/snort_types.h find-1 INHERITED)
# => mid-build 122+2 = 124 MEASURED (the link4-18n landing-head 122 face).
# THE OWN-NEW-WITNESS FACE, CORRECTED BY OWN L1 RE-MEASURE (the spec-fix the
# §9 records honestly): the recon staged +2 (LogMessage + ControlConn::
# show_prompt) against (donor-OBJS + witness_conf) ONLY; over the FULL carried
# WIN trio the eth stubs_18d seam #3 ALREADY defines snort::LogMessage
# (vprintf body) -- a second body = 'multiple definition' link error (scratch
# seed run1 face, the dup-symbol/18d trio-retirement law). OWN L1 census
# (row .o + OBJS + WIN, NO own witness) = EXACTLY-1 distinct undefined:
# ControlConn::show_prompt() => witness_misc9.cc is the cited-minimal face
# (the 18n witness_pkthdr +1 shape; backbone array stays 10 either way).
# THE FRAMEWORK-TU FACE (NOT the codec-table family, recon §8 + the spec
# fix): module.cc/reload_tracker.cc carry NO hidden table -- BUILDING_SO
# grep-0 x4 + snort_plugins grep-0 x4 asserted EVERY build -- so FACE-A ships
# the NOLOAD line (cite-never-fabricate) + the null_params Parameter-table
# walk (module.cc :32-:35, PT_MAX sentinel) + the record/virtual/verified-
# trio census through the REAL module.o.
# THE -DNDEBUG law: BOTH row TUs + the whole graph compile -DNDEBUG -- the
# ground production arm (reload_tracker.cc NDEBUG branches :54-:57/:69-:72/
# :82-:85) and the ONLY way the get_global_count wrong-name arm (module.cc
# :372 assert(false) -> :374 return 0) is OBSERVABLE not fatal; the tracker
# ladder is assert-clean BOTH ways (comment in probe_dec.cc).
# THE DAQ NON-PARTICIPATION face: daq grep-0 x4 over the pair (.cc + .h)
# EVERY build; the graft-v3 daq.h 0f7016a6 rides INHERITED in the donor (the
# 18n landing face, NEVER re-authored here); masters 73fdbc39/f683749c +
# graft-v2 fead0027 CITED.
# THE ZERO-GATE row (chapter 19's FIRST row AT a real gate-material area):
# module.cc + reload_tracker.cc gate-token grep-0 x2 and NEITHER file rides
# any test CMakeLists SOURCES list (the CppUTest suites name data_bus/
# mp_data_bus/rsubs/thread/distill -- the §0 dialect census; grep-0 asserted).
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness
MI=$R/tools/misc3_harness
MIP=$R/tools/miscip_harness
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
L4=$R/tools/link4_harness          # THE donor (18n tree, 7-stageable) -- REUSE clone, §7
C=$H/copy

# ---- ground identity (the TWO row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [module.cc]=9608434cb5d1820d6033a32632080499 [reload_tracker.cc]=bdd9e3d773904514e8672a261fb6fddc )
declare -A WC=( [module.cc]=403 [reload_tracker.cc]=89 )
test "$(md5sum "$SRC/src/framework/module.cc" | awk '{print $1}')" = "${MD5[module.cc]}"
test "$(wc -l < "$SRC/src/framework/module.cc")" -eq 403
test "$(md5sum "$SRC/src/main/reload_tracker.cc" | awk '{print $1}')" = "${MD5[reload_tracker.cc]}"
test "$(wc -l < "$SRC/src/main/reload_tracker.cc")" -eq 89
test "$(( 403 + 89 ))" -eq 492                      # the row's ledger line (PLAN §1 P1 pick face)
# the 49-L header face (the ONE fresh cp):
test "$(wc -l < "$SRC/src/main/reload_tracker.h")" -eq 49
test "$(md5sum "$SRC/src/main/reload_tracker.h" | awk '{print $1}')" = "598e08b485165bd2fdc514954b13652b"
# combined gate grep ZERO x2 EVERY build (STOP-flag; if ground ships a suite
# naming the pair the row RE-PLANS to the gate shape -- flip trips loud)
for f in framework/module.cc main/reload_tracker.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST\|CppUTest' "$SRC/src/$f" || true)" -eq 0
done

# ---- THE zero-gate census AT the chapter-19 gate-material area (the §0 flag
# face: the CppUTest suites are REAL material but name the OTHER TUs -- the
# pair NEVER rides any SOURCES list; the dialect stays BLOCKED on this host) --
test "$(grep -c 'module.cc\|reload_tracker.cc\|reload_tracker.h' "$SRC/src/framework/test/CMakeLists.txt" || true)" -eq 0
test "$(grep -c 'module.cc\|reload_tracker.cc\|reload_tracker.h' "$SRC/src/main/test/CMakeLists.txt" || true)" -eq 0
test "$(grep -c 'add_cpputest' "$SRC/src/framework/test/CMakeLists.txt")" -eq 3   # the §0 suite count UNDISTURBED
test "$(grep -c 'add_cpputest' "$SRC/src/main/test/CMakeLists.txt")" -eq 2        # (dialect BLOCKED on this host -- find-0 face §0, cite-only)
test "$(grep -c 'add_catch_test' "$SRC/src/framework/CMakeLists.txt")" -eq 2      # parameter/range NO_TEST_SOURCE -- residents 16c/16j, UNDISTURBED
# the pair's OWN build-system faces (the library-list residency, NOT a gate):
test "$(grep -c 'module.cc' "$SRC/src/framework/CMakeLists.txt")" -eq 1
test "$(grep -c 'reload_tracker.cc' "$SRC/src/main/CMakeLists.txt")" -eq 1
# hidden-table ABSENCE census (the framework-TU face -- the codec-row CONTRAST):
for f in framework/module.cc framework/module.h main/reload_tracker.cc main/reload_tracker.h; do
    test "$(grep -c 'BUILDING_SO'   "$SRC/src/$f" || true)" -eq 0
    test "$(grep -c 'snort_plugins' "$SRC/src/$f" || true)" -eq 0
    test "$(grep -ci daq "$SRC/src/$f" || true)" -eq 0                             # graft NON-PARTICIPATION x4
done

# ---- THE framework-module sed pins (ground identity of the DEC/FACE-A arms;
# line# NEVER derivable from the probe -- every vector grep rides these) ----
test "$(sed -n '32p' "$SRC/src/framework/module.cc")" = "static const Parameter null_params[] ="
test "$(sed -n '34p' "$SRC/src/framework/module.cc")" = "    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }"
test "$(sed -n '59p' "$SRC/src/framework/module.cc")" = "    params = null_params;"
grep -q 'while ( p and p->name )' "$SRC/src/framework/module.cc"                   # get_arg_list walk :42
grep -q 'if ( list and table_level < 2 )' "$SRC/src/framework/module.cc"   # verified_set list-guard (the :384 face; the arm lives in the .cc)
grep -q 'PegCount Module::get_global_count' "$SRC/src/framework/module.cc"
test "$(sed -n '372p' "$SRC/src/framework/module.cc")" = '    assert(false); // wrong name = programmer error'   # :372 the -DNDEBUG-observed arm (exact line face)
grep -qF 'add_peg_count(i, p[i], dump_stats);' "$SRC/src/framework/module.cc"       # SUM arm (:219 face) BEFORE p[i] = 0 (:226) -- python order pin below
grep -q 'number_of_threads = new_thread ? 1 : ThreadConfig::get_instance_max' "$SRC/src/framework/module.cc"
grep -q 'const PegInfo simple_pegs\[\]' "$SRC/src/framework/module.cc"             # the RESIDENT table DEFINED by the row .o
grep -q 'SO_PUBLIC extern const struct PegInfo simple_pegs\[\];' "$SRC/src/framework/counts.h"  # the extern face (counts.h :55) -- NEVER re-authored
grep -q 'enum Usage { GLOBAL, CONTEXT, INSPECT, DETECT };' "$SRC/src/framework/module.h"        # the usage=1 ordinal face (:216)
# reload_tracker ground call-site pins (the DEC ladder's cites):
grep -q '^#include "reload_tracker.h"$' "$SRC/src/main/reload_tracker.cc"
grep -q '^#include "control/control.h"$' "$SRC/src/main/reload_tracker.cc"
grep -q '^#include "log/messages.h"$' "$SRC/src/main/reload_tracker.cc"
grep -q 'LogMessage("Reload started. \[%s\]\\n", current_command.c_str());' "$SRC/src/main/reload_tracker.cc"     # :48
grep -q 'LogMessage("Reload in progress \[%s\], attempting command: \[%s\]\\n",' "$SRC/src/main/reload_tracker.cc"  # :41
grep -q 'LogMessage("Reload ended. \[%s\]\\n", current_command.c_str());' "$SRC/src/main/reload_tracker.cc"        # :60
grep -q 'LogMessage("Reload failed! %s \[%s\]\\n", reason, current_command.c_str());' "$SRC/src/main/reload_tracker.cc"  # :75
grep -q 'LogMessage("Reload update: %s \[%s\]\\n", status, current_command.c_str());' "$SRC/src/main/reload_tracker.cc"  # :88
grep -q 'current_command = (ctrlcon ? ctrlcon->get_current_command().substr(0, 50) : "signal");' "$SRC/src/main/reload_tracker.cc"  # :47 THE "signal" arm
test "$(grep -c 'ctrl->show_prompt();' "$SRC/src/main/reload_tracker.cc")" -eq 1   # :63 EXACTLY-1 -- the ONE own-new witness pull
grep -q 'static void end(const ControlConn\* ctrlcon, bool prompt=false);' "$SRC/src/main/reload_tracker.h"        # :37 the false-default face
# the stubs_18d LogMessage seam (the +2-vs-+1 SPEC-FIX pin -- the carried face):
grep -q 'void LogMessage(const char\* fmt, ...)' "$ETH/stubs_18d.cc"

# ---- copy tree = link4-18n DONOR REUSE clone + ZERO fresh headers + 2 row
# cps. DONOR FACE MEASURED 122 non-.o; graft-v3 daq.h 0f7016a6 rides
# INHERITED (the 18n landing face, NEVER re-authored HERE); graft-v2
# daq_common.h fead0027 INHERITED; masters CITED; thread_config.h rides the
# INHERITED hwloc-shim face (the copy head has NO hwloc.h pull -- the raw-
# ground module wall below proves the shim is load-bearing). ----
if [ ! -e "$L4/copy/codecs/link/cd_vlan.cc" ] || [ ! -e "$L4/copy/config.h" ]; then bash "$L4/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$L4/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 122                          # donor face MEASURED (the 18n mid-build head)
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"    # graft-v3 INHERITED (link4 pin; NEVER re-authorized HERE)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"  # graft-v2 INHERITED
test "$(md5sum "$D3/copy/daq.h" | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"      # master CITE (never cp'd HERE)
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
grep -q "#include <hwloc.h>" "$SRC/src/main/thread_config.h"                                  # the ground head :22 face
    test "$(grep -c '#include <hwloc.h>' "$C/main/thread_config.h" || true)" -eq 0                # the INHERITED shim face (the ONE diff line: copy drops the pull, keeps the :90 hwloc_ token signature guarded by HAVE_NUMA)
# THE donor-verbatim half (the ZERO-cp 403-L face -- the FIRST such row):
test -e "$C/framework/module.cc"
test "$(md5sum "$C/framework/module.cc" | awk '{print $1}')" = "9608434cb5d1820d6033a32632080499"   # BYTE-IDENT to ground
# the pair closure headers find-1 INHERITED (the include census: tracker 4
# edges 1 fresh / module 5 edges ALL resident):
for h in framework/module.h framework/counts.h framework/parameter.h framework/value.h main/thread.h main/thread_config.h trace/trace.h utils/stats.h utils/bits.h control/control.h log/messages.h main/snort_types.h main/snort_config.h config.h; do
    test "$(find "$C" -path "*/$h" | wc -l)" -eq 1
done
test "$(find "$C" -name 'reload_tracker.h' | wc -l)" -eq 0                        # find-0 PRE-cp (the ONE fresh header)
cp "$SRC/src/main/reload_tracker.cc" "$C/main/reload_tracker.cc"; cmp -s "$C/main/reload_tracker.cc" "$SRC/src/main/reload_tracker.cc"
cp "$SRC/src/main/reload_tracker.h"  "$C/main/reload_tracker.h";  cmp -s "$C/main/reload_tracker.h"  "$SRC/src/main/reload_tracker.h"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 124                         # mid-build: 122 + 2 (the ONLY cps THIS row makes)
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probes pull NO codec_api)
test ! -e "$C/codecs/codec_api.cc"

GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
# ---- PRE-CHECKS: -fsyntax-only rc0 x2 + .o rc0 x2 (the RECON face RE-RUN:
# receipts E4_module.txt / E4_tracker.txt EMPTY) ----
$GXX0 -fsyntax-only "$C/framework/module.cc"      2> "$H/E4_module.txt";   test ! -s "$H/E4_module.txt"
$GXX0 -fsyntax-only "$C/main/reload_tracker.cc"   2> "$H/E4_tracker.txt";  test ! -s "$H/E4_tracker.txt"
$GXX0 -c "$C/framework/module.cc"    -o "$C/module.precheck.o"   2> "$H"/E4_codegen_module.txt;   test ! -s "$H/E4_codegen_module.txt";   rm -f "$C/module.precheck.o"
$GXX0 -c "$C/main/reload_tracker.cc" -o "$C/tracker.precheck.o"  2> "$H"/E4_codegen_tracker.txt;  test ! -s "$H/E4_codegen_tracker.txt";  rm -f "$C/tracker.precheck.o"

# ---- E4 LOCALIZATION ARMS BOTH WAYS (the pair-split face, 18h precedent):
# (a) stripped-donor arm -I src ONLY: module.cc MUST die (the raw head pulls
# <hwloc.h> via module.cc:25 -> thread_config.h:22 -- the host-toolchain face
# the INHERITED copy shim carries; CHAINED receipt, grep the WHOLE file) +
# reload_tracker.cc rc0 on the raw arm is the HONEST CONTRAST (all 4 of its
# includes exist in the ground tree -- raw rc0 face recorded, the raw-cp
# DISTINCTION lives in the in-tree walls).
# (b) IN-TREE walls: module.h drop kills ONLY module (DIRECT quoted include
# :23; tracker SURVIVES); reload_tracker.h drop kills ONLY tracker (head-1
# :21, the 1cp law's wall); control.h drop kills ONLY tracker (:26 DIRECT)
# and module SURVIVES (find-1 NON-participant face -- the link6 log_text wall
# INVERTED); restored rc0 x2 EVERY build. ----
GXXD="g++ -std=c++17 -DNDEBUG -O0 -w -I$SRC/src"
if $GXXD -fsyntax-only "$SRC/src/framework/module.cc" 2> "$H"/E4_donorsrc_module.txt; then
    echo "E4 LOCALIZATION DEAD: module.cc compiled on the -I src ONLY arm -- the hwloc face is wrong"; exit 1
fi
grep -q "fatal error: hwloc.h: No such file" "$H/E4_donorsrc_module.txt"          # chained via thread_config.h:22 (grep the WHOLE receipt)
grep -q "thread_config.h:22" "$H/E4_donorsrc_module.txt"
$GXXD -fsyntax-only "$SRC/src/main/reload_tracker.cc" 2> "$H/E4_donorsrc_tracker.txt"          # the honest raw-rc0 CONTRAST face (4/4 includes ground-resident)
test ! -s "$H/E4_donorsrc_tracker.txt"
mv "$C/framework/module.h" "$H/.e4_hold_module.h"
if $GXX0 -fsyntax-only "$C/framework/module.cc" -o /dev/null 2> "$H/E4_nomh_module.txt"; then
    echo "E4 flip BROKE: module.cc compiled WITHOUT framework/module.h (cc:23 DIRECT)"; exit 1
fi
head -1 "$H/E4_nomh_module.txt" | grep -q "fatal error: module.h: No such file"   # quoted-include face
$GXX0 -fsyntax-only "$C/main/reload_tracker.cc" 2> "$H/E4_nomh_tracker.txt"; test ! -s "$H/E4_nomh_tracker.txt"    # tracker SURVIVES the module.h wall
mv "$H/.e4_hold_module.h" "$C/framework/module.h"
mv "$C/main/reload_tracker.h" "$H/.e4_hold_reload_tracker.h"
if $GXX0 -fsyntax-only "$C/main/reload_tracker.cc" -o /dev/null 2> "$H/E4_noth_tracker.txt"; then
    echo "E4 flip BROKE: reload_tracker.cc compiled WITHOUT main/reload_tracker.h (the 1-cp law)"; exit 1
fi
head -1 "$H/E4_noth_tracker.txt" | grep -q "fatal error: reload_tracker.h: No such file"
$GXX0 -fsyntax-only "$C/framework/module.cc" 2> "$H/E4_noth_module.txt"; test ! -s "$H/E4_noth_module.txt"         # module SURVIVES (disjointness)
mv "$H/.e4_hold_reload_tracker.h" "$C/main/reload_tracker.h"
mv "$C/control/control.h" "$H/.e4_hold_control.h"
if $GXX0 -fsyntax-only "$C/main/reload_tracker.cc" -o /dev/null 2> "$H/E4_noctl_tracker.txt"; then
    echo "E4 flip BROKE: tracker compiled WITHOUT control/control.h (cc:26 DIRECT)"; exit 1
fi
head -1 "$H/E4_noctl_tracker.txt" | grep -q "fatal error: control/control.h: No such file"
$GXX0 -fsyntax-only "$C/framework/module.cc" 2> "$H/E4_noctl_module.txt"; test ! -s "$H/E4_noctl_module.txt"       # control.h NON-participant for module (link6 log_text wall INVERTED)
mv "$H/.e4_hold_control.h" "$C/control/control.h"
$GXX0 -fsyntax-only "$C/framework/module.cc"    2> "$H/E4_restored_module.txt";  test ! -s "$H/E4_restored_module.txt"
$GXX0 -fsyntax-only "$C/main/reload_tracker.cc" 2> "$H/E4_restored_tracker.txt"; test ! -s "$H/E4_restored_tracker.txt"

GXX="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C"
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc"

# ---- witness posture (OWN re-measure, NOT the recon cite): WIN trio CARRIED
# (witness_18f ea1f79f3 + witness_conf 4dd91018 heredoc VERBATIM re-
# materialize + stubs_18d f4afd35f -- the LogMessage seam lives THERE) +
# ONE own-new witness_misc9.cc (the EXACTLY-+1 L1 face; the 18n witness_
# pkthdr shape). witness_miscip c5b498ff + witness_trio ef50cd2f stay DONOR-
# INHERITED cites NEVER linked. ----
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
_b=$(grep -n 'witness_conf\.cc" <<.EOFWC.$' "$L4/build.sh" | head -1 | cut -d: -f1)
test -n "$_b"
_e=$(awk -v s="$_b" 'NR>s && /^EOFWC$/{print NR; exit}' "$L4/build.sh")
sed -n "$((_b+1)),$((_e-1))p" "$L4/build.sh" > "$H/witness_conf.cc"
test "$(md5sum "$H/witness_conf.cc" | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"
test "$(find "$H" -name 'witness_*.cc' ! -name witness_conf.cc | wc -l)" -eq 1
test "$(find "$H" -name 'witness_*.cc' ! -name witness_conf.cc | grep -c witness_misc9)" -eq 1
test "$(wc -l < "$H/witness_misc9.cc")" -eq 27
test "$(md5sum "$H/witness_misc9.cc" | awk '{print $1}')" = "ada2b1e83b0f15629a39000e6dae65aa"   # THE witness face (L1-remeasured minimal; the +2 recon GUESS died on the dup-symbol law -- §9)
test "$(wc -l < "$MIP/witness_miscip.cc")" -eq 27
test "$(md5sum "$MIP/witness_miscip.cc" | awk '{print $1}')" = "c5b498ffa6beac768f34e25830c552a1"

# ---- O0 compile: row .o (tracker; module = the donor-verbatim backbone .o)
# + donor REAL .o + probes + witnesses ----
$GXX -c "$C/framework/module.cc"    -o "$C/module.o"        # the REUSE half: source byte-ident to ground (asserted above); NDEBUG face fresh-measured EVERY build
$GXX -c "$C/main/reload_tracker.cc" -o "$C/reload_tracker.o"
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o
$GXX -c "$H"/witness_misc9.cc -o "$H"/witness_misc9.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/reload_tracker.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# the row .o symbol faces: the tracker defines ReloadTracker x8 (h:36-:39 +
# the 3 statics + guard surface); the backbone module.o DEFINES the resident
# simple_pegs table (the DEC face's provenance: extern counts.h:55 -> here):
test "$(nm --defined-only "$C/reload_tracker.o" | grep -c ReloadTracker)" -eq 8
test "$(nm --defined-only "$C/module.o" | grep -c 'simple_pegs')" -eq 1
test "$(nm -C --defined-only "$C"/module.o | grep -c 'T snort::Module::Module')" -ge 2   # the protected ctors (h:225/:226, C1/C2 halves)
# ---- nm per-TU U-census (receipts; -DNDEBUG faces MEASURED this pass: the
# RECON non-NDEBUG faces 32/26 ride the scratch receipts -- the NDEBUG arm
# drops one __assert_fail pull face on EACH TU, honestly recorded §9) ----
nm -C -u "$C/module.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_module.txt"
nm -C -u "$C/reload_tracker.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_tracker.txt"
test "$(wc -l < "$H/nm_U_module.txt")" -eq 31               # MEASURED NDEBUG face (RECON non-NDEBUG face 32 in scratch nm_U_module*.txt)
test "$(wc -l < "$H/nm_U_tracker.txt")" -eq 25              # MEASURED NDEBUG face (RECON 26 incl __assert_fail -- gone under NDEBUG)
test "$(grep -c 'show_prompt' "$H/nm_U_tracker.txt")" -eq 1                     # THE witness-forcing face
test "$(grep -c 'LogMessage' "$H/nm_U_tracker.txt")" -eq 1                      # CLOSED by the carried stubs_18d seam (NOT an own-new)
for f in module tracker; do
    test "$(grep -c 'tunnel' "$H/nm_U_$f.txt" || true)" -eq 0
    test "$(grep -c 'SFDAQ' "$H/nm_U_$f.txt" || true)" -eq 0
    test "$(grep -ci 'daq\|mpls\|vlan' "$H/nm_U_$f.txt" || true)" -eq 0         # q4/link4 names NEVER leak
done
cat "$H"/nm_U_module.txt "$H"/nm_U_tracker.txt | sort -u > "$H/nm_U_union.txt"
nm -u $ROWS | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
# residue class (MANGLED face; inherited classifier + the ControlConn pattern
# -- the 18n daq_msg precedent shape): every snort/ControlConn-family U of
# the row .o MUST be defined by OBJS + WIN + witness_misc9 (the +1 census).
donordefs=$(nm --defined-only $OBJS $WIN "$H"/witness_misc9.o | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*|*11ControlConn*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# the RECON §1 module-half residue face RE-RUN over OBJECTS (the don't-reuse-
# module.o proof): module.o's snort-family U's close on OBJS-MINUS-module.o +
# WIN ALONE (LogMessage NEED NOT appear: zero LogMessage U in module.o):
mres=0
MOBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/text_log.o"   # OBJS MINUS module.o (the §2 proof face)
mdefs=$(nm --defined-only $MOBJS "$H/witness_18f.o" "$H/witness_conf.o" "$H/stubs_18d.o" | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
while IFS= read -r u; do
    case "$u" in *5snort*) grep -qxF "$u" <<< "$mdefs" || { echo "MODULE RESIDUE UNRESOLVED: $u"; mres=1; };; esac
done < <(nm -u "$C/module.o" | sed 's/^ *U //' | sort -u)
test "$mres" -eq 0                                            # the ZERO-snort-residue face (libc/libstdc++ only, the §2 RECON face)
nm -C -u "$C/module.o" | grep ' U ' | grep -v 'std::\|operator new\|operator delete\|memcpy\|memmove\|strcmp\|strlen\|__assert_fail\|__cxa_\|__gxx_\|_Unwind_\|vtable for\|__dso_handle' > "$H/module_residue_dem.txt" || true
test "$(wc -l < "$H/module_residue_dem.txt")" -eq 3           # the -DNDEBUG face: show_stats (scalar overload) + ThreadConfig::get_instance_max + get_instance_id (the §2 face CLOSED by witness_conf 4dd91018; the RECON non-NDEBUG face showed show_stats x2 -- §9 delta face)
grep -q 'show_stats' "$H/module_residue_dem.txt"
grep -q 'ThreadConfig::get_instance_max' "$H/module_residue_dem.txt"
grep -q 'get_instance_id' "$H/module_residue_dem.txt"
test "$(grep -c 'LogMessage\|ReloadTracker\|show_prompt' "$H/module_residue_dem.txt" || true)" -eq 0   # NO tracker-family residue in module.o
# THE witness delta face (OWN L1 RE-MEASURE -- EXACTLY-1 undefined, the +2
# recon face CORRECTED: the LogMessage half is CLOSED by the carried
# stubs_18d seam; a second body would DIE multiple-definition):
if $GXX $ROWS $OBJS "$H"/probe.o $WIN -o "$H"/.L1_probe 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: tracker linked WITHOUT witness_misc9 -- the +1 L1 delta is wrong"; exit 1
fi
grep -c 'undefined reference' "$H/L1_link_face.txt" > /dev/null
grep -oE "undefined reference to \`[^']*" "$H/L1_link_face.txt" | sed "s/undefined reference to \`//" | sort -u > "$H/L1_undefined.txt"
test "$(wc -l < "$H/L1_undefined.txt")" -eq 1                 # EXACTLY-1 DISTINCT undefined face
test "$(cat "$H/L1_undefined.txt")" = "ControlConn::show_prompt()"             # the OWN witness-census pin (NOT LogMessage)
rm -f "$H"/.L1_probe
# witness_18f carries the tunnel T EXACTLY-1 (carried face; the pair carries
# NO bypass U -- nm greps ABOVE prove the backbone never moves):
test "$(nm --defined-only "$H"/witness_18f.o | grep -c 'tunnel_bypass_enabled')" -eq 1
# witness_misc9 defines EXACTLY-1 the own-new face + the observable (T census):
test "$(nm --defined-only "$H"/witness_misc9.o | grep -c 'show_prompt')" -eq 1
test "$(nm --defined-only "$H"/witness_misc9.o | grep -c 'misc9_prompt_calls')" -eq 1
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# real-symbol defines (donor face, gre-recipe):
grep -q 'T snort::Codec::codec_event' <<< "$(nm -C --defined-only "$C"/codec.o)"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"

# ---- probe links: WIN trio + witness_misc9 (the +1 face) -> GREEN ---------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN "$H"/witness_misc9.o -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN "$H"/witness_misc9.o -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::SFDAQ::get_local_instance()' || true)" -eq 0   # misc3's tracked witness NEVER linked
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'T snort::PacketManager::get_proto_name' || true)" -eq 0 # donor-inherited NEVER linked
grep -q 'tun_witness_set_mask' <<< "$(nm -C "$H"/probe_dec)"       # CARRIED face rides BOTH binaries (witness_18f inherited arm)
grep -q 'misc9_prompt_calls' <<< "$(nm -C "$H"/probe_dec)"          # the OWN observable rides the DEC binary (the pkthdr_witness_set_flags precedent)

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
$GXXA -c "$C/framework/module.cc"    -o "$O2/module.o"
$GXXA -c "$C/main/reload_tracker.cc" -o "$O2/reload_tracker.o"
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc -o "$O2"/stubs_18d.o; $GXXA -c "$H"/witness_misc9.cc -o "$O2"/witness_misc9.o
OB2="$O2/reload_tracker.o"
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_misc9.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_misc9.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: state calls stored to VARS before any printf ----
test "$(grep -c 'bool s. = ReloadTracker::' "$H"/probe_dec.cc)" -eq 4    # s1 s2 s3 s6 (the start-face arms BEFORE the log prints)
test "$(grep -c 'bool .. = .*verified_' "$H"/probe.cc)" -eq 6            # rb rs re cb cs ce (the table_level++ order law)
test "$(grep -c 'printf.*verified_' "$H"/probe.cc || true)" -eq 0
test "$(grep -c 'printf.*ReloadTracker::' "$H"/probe_dec.cc || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_O0.txt || true)" -eq 0    # all-decimal hygiene
grep -q 'usage=1' "$H"/vectors_faceA_O0.txt                  # CONTEXT ordinal face (python-pinned below)

# ---- known-answer ladders: greps pin the MEASURED first-run faces against
# GROUND anchors (17p). First run seeds; later runs cmp above. ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi

# ---- known-answer ladders (17p values NEVER typed -- ground walks below) --
# FACE-A: the honest NOLOAD head (the framework-TU face; the codec-family
# LOAD/ver=/size= lines NEVER fit -- spec correction):
grep -q '^NOLOAD framework-TU BUILDING_SO-grep0-x4 snort_plugins-grep0-x4$' "$FA"
grep -q '^NULLWALK entries=0 sentinel_type=21$' "$FA"        # null_params walk (empty -> the sentinel PT_MAX face)
grep -q '^ARGS default ()$' "$FA"                            # Command::get_arg_list over null_params (the :42 gate face)
grep -q '^ARGS two (one, two)$' "$FA"                       # the ", " joiner (:45) + 2-entry walk
grep -q '^REC c is_table=1 is_list=1 type=1$' "$FA"         # the PT_LIST ordinal face
test "$(grep -c '^REC ' "$FA")" -eq 3
grep -q '^DEFS .*matches=0 usage=1$' "$FA"                  # the default-virtual census + Usage::CONTEXT ordinal
grep -q '^VERB table begin=1 set=1 end=1$' "$FA"            # default begin/set/end all true
grep -q '^VERB list begin=1 set=0 end=1$' "$FA"             # THE list-guard face (verified_set false)
test "$(grep -c '^LOAD' "$FA" || true)" -eq 0   # NO hidden-table LOAD EVER (framework TU)
test "$(grep -c 'ver=\|size=' "$FA" || true)" -eq 0         # NO CodecApi face EVER (the codec-row CONTRAST)
grep -q 'order nullwalk:table:32->init:59->get:136' "$FA"   # eval-order cite
# DEC ladders (ground call-site arms; the printed Reload strings ride the
# CARRIED stubs_18d LogMessage seam -- BOTH-sides pinned vs cc literals):
grep -q '^Reload started. \[signal\]$' "$V"                 # cc :48 literal through the seam
test "$(grep -c '^Reload started. \[signal\]$' "$V")" -eq 5 # start arms x5 (:46-:49; the cc :47 "signal" half; s2 hits the :38 gate instead)
grep -q '^Reload in progress \[signal\], attempting command: \[signal\]$' "$V"   # cc :41-:43 DOUBLE-arg arm ONCE
test "$(grep -c '^Reload in progress' "$V")" -eq 1
grep -q '^Reload ended. \[signal\]$' "$V"; test "$(grep -c '^Reload ended. \[signal\]$' "$V")" -eq 2          # :60 x2 (true/false arms)
grep -q '^Reload failed! why \[signal\]$' "$V"; grep -q '^Reload failed! x \[signal\]$' "$V"                  # :75 x2 (reason half)
grep -q '^Reload update: st \[signal\]$' "$V"; grep -q '^Reload update: st2 \[signal\]$' "$V"                 # :88 x2
grep -q '^TRK start1 -> 1$' "$V"; grep -q '^TRK start2-during -> 0$' "$V"        # :38 gate face (true/false)
grep -q '^TRK end-prompt-true delta=1$' "$V"                # :62 TRUE -> :63 -> witness counter observable
grep -q '^TRK end-prompt-false delta=0$' "$V"              # h:37 default false -> NEVER :63
grep -q '^TRK start-after-failed -> 1$' "$V"               # :77/:78 drop re-arms
grep -q 'TRK order gate:39-before-log:41 | log:60-before-guard:62->prompt:63' "$V"
# the stats ladder (module.cc ground arms through the REAL module.o):
grep -q '^MS init-true num_counts=3 rows=1$' "$V"          # :322-:324 walk (END sentinel stops the loop) + new_thread true -> :330 threads=1
grep -q '^MS sum-false cell0=7 p0=0$' "$V"                 # SUM arm add :219 + clear :226
grep -q '^MS sum-true cell0=7 dcell0=10 p0=3$' "$V"        # dump-init copy :197-:198 + add dump half; p NEVER zeroed (:223-:226 dump branch)
grep -q '^MS max-arm dcell2=9$' "$V"                       # set_max_peg_count keeps 9 over 2
grep -q '^MS ggc hit=13 miss=0$' "$V"                      # accumulate 7+3+3 -> 13; hit :370; miss arm :372 DEAD-assert -> :373 return 0 (the -DNDEBUG face)
grep -q '^MS reset cell0=0 dcell0=0 p0=0 p1=5 p2=0$' "$V"  # reset loop :354-:355 zeroes accumulators; p[1] NOW peg survives the :357 type!=NOW guard
grep -q '^MS init-false rows=2 num_counts=3$' "$V"         # new_thread false -> ThreadConfig::get_instance_max()=1 (witness_conf) -> rows 1->2
grep -q '^SP num_counts=1 rows=1$' "$V"                    # the RESIDENT simple_pegs face (module.o :398-:401)
grep -q '^SP sum cell0=12 p0=0$' "$V"
grep -q '^SP ggc-hit=0$' "$V"                              # sized-but-never-accumulated face (honest)
grep -q 'MS order add:cc206-before-clear:cc208 | accumulate:cc96-before-ggc:cc362' "$V"
test "$(grep -c '^MS \|^SP \|^TRK ' "$V")" -ge 10
test "$(grep -c 'tunnel\|bypass\|CodecApi\|cd_' "$V" || true)" -eq 0            # ZERO codec/tunnel face ANYWHERE
python3 - "$V" "$FA" <<'PYPIN'
# BOTH-WAYS pins: the reload literals ride the GROUND file; the ordinal
# faces (PT_MAX/PT_LIST/PT_TABLE/Usage) ride the GROUND enum walks; the
# module.cc arm VALUES ride the ground code paths (never air).
import re, subprocess, sys
VF, FAF = sys.argv[1], sys.argv[2]
cc = open("/opt/data/snort3-src/src/main/reload_tracker.cc").read()
# ground LogMessage format literals == vector face (the carried-seam face):
for lit in ("Reload started. [%s]", "Reload ended. [%s]", "Reload in progress [%s], attempting command: [%s]",
            "Reload failed! %s [%s]", "Reload update: %s [%s]"):
    assert lit in cc, lit
v = open(VF).read()
assert '"[signal]"' not in v  # sanity: no quoting artefact
for printed in ("Reload started. [signal]", "Reload ended. [signal]",
                "Reload in progress [signal], attempting command: [signal]",
                "Reload failed! why [signal]", "Reload update: st [signal]"):
    assert printed in v, printed
assert 'current_command = (ctrlcon ? ctrlcon->get_current_command().substr(0, 50) : "signal");' in cc  # the 50-cap face
assert 'ctrl->show_prompt();' in cc and cc.count("ctrl->show_prompt();") == 1     # EXACTLY-1 pull site
assert v.count("TRK end-prompt-true delta=1") == 1 and v.count("TRK end-prompt-false delta=0") == 1
# parameter.h enum Type walk -> ordinals the vector rides:
p = open("/opt/data/snort3-src/src/framework/parameter.h").read()
names = [x for x in re.findall(r'\b(PT_[A-Z_0-9]+)\b', p[p.index("enum Type"):p.index("const char* name;")])]
assert names.index("PT_TABLE") == 0 and names.index("PT_LIST") == 1 and names.index("PT_MAX") == 21, names   # the vector face: sentinel_type=21 (the PT_MAX ordinal), type=1 (PT_LIST), type=0 (PT_TABLE)
fa = open(FAF).read()
assert "sentinel_type=21" in fa and "type=1" in fa and "type=0" in fa
u = re.search(r'enum Usage \{ ([A-Z_ ,]+)\}', open("/opt/data/snort3-src/src/framework/module.h").read()).group(1)
us = [x.strip() for x in u.split(",")]
assert us == ["GLOBAL", "CONTEXT", "INSPECT", "DETECT"] and f"usage={us.index('CONTEXT')}" in fa
# the null_params ground row sed-pinned (the probe-side sentinel rides the SAME shape):
mc = open("/opt/data/snort3-src/src/framework/module.cc").read()
assert "{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }" in mc
assert "params = null_params;" in mc
# eval-order ground faces (the vector cites ride these index orders):
assert mc.index("add_peg_count(i, p[i], dump_stats);") < mc.index("p[i] = 0;")
assert "if ( list and table_level < 2 )" in mc and mc.index("table_level++") < mc.index("if ( list and table_level < 2 )")
assert "assert(false); // wrong name = programmer error" in mc
assert "number_of_threads = new_thread ? 1 : ThreadConfig::get_instance_max" in mc
assert '{ CountType::SUM, "packets", "total packets" },' in mc                    # the resident simple_pegs row (:400)
# CountType ordinals the probe-side PegInfo table rides (counts.h :32-:38):
ch = open("/opt/data/snort3-src/src/framework/counts.h").read()
ct = re.findall(r"^\s+(END|SUM|NOW|MAX),", ch, re.M)
assert ct == ["END", "SUM", "NOW", "MAX"]
# the row's Rust-side PRESENCE faces (the rs pass LANDED THIS row -- the
# harness-side seed pass 19a carried the mirror ABSENCE faces, flipped here;
# the §3 collision landmine greps stay ZERO OUTSIDE the two new files):
import os
assert os.path.exists("/opt/data/snort3-rust/src/framework/module.rs")   # the Module base (closes the file_module.rs:75/:232 banked debt)
assert os.path.exists("/opt/data/snort3-rust/src/main/reload_tracker.rs") # the reload prompt shim
_out = subprocess.run(["grep","-rl","pub struct Module\\b","/opt/data/snort3-rust/src"],capture_output=True).stdout.decode().split()
assert _out == ["/opt/data/snort3-rust/src/framework/module.rs"], _out  # EXACTLY the new home, NO collision
_out = subprocess.run(["grep","-rl","null_params","/opt/data/snort3-rust/src"],capture_output=True).stdout.decode().split()
assert _out == ["/opt/data/snort3-rust/src/framework/module.rs"], _out  # same face
assert subprocess.run(["grep","-rlE","ReloadSurvivor|reload_survivor|struct Tracer","/opt/data/snort3-rust/src"],capture_output=True).stdout == b""  # the §3 landmine trio stays 0
# the docs cite face (NEVER edited; the cargo face of a LATER rs pass):
assert open("/opt/data/snort3-rust/NEXT.md").read().count("597 tests green / 0 FAILED") == 3
PYPIN

# ---- row's measured first-run face PINS (the md5s below are the MEASURED
# FIRST-RUN OUTPUT, drift refuses EVERY build; seeded by SEED PASS 19a --
# build.sh NEVER fabricates) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 41          # MEASURED first-run face: 24 ladder lines (12 printed ground LogMessage literals + 12 seam-putchar blank-line faces) + 6 TRK counter/order + 8 MS + 3 SP
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 11    # MEASURED first-run face: NOLOAD + REC x3 + NULLWALK + ARGS x2 + DEFS + VERB x2 + order
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "e6328da1f3188df9754b9e45d74897db"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "dfe738fb8b4200368332ba73b81a4e96"

# ---- known-answer wc+md5 pins (OUTPUT of the MEASURED run) ----
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)

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

# ---- BACKBONE-10 census: the row's own-new witness STAYS the row's OWN
# face (the witness_pkthdr rule: the B10 ARRAY is the cross-row witness/
# vector set and NEVER grows for a row witness -- symbol-vs-array, the 18n
# precedent). The B10 array rides misc3's post-row face VERBATIM ----
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
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H/backbone10.txt"   # receipt (ignored)
test "$(wc -l < "$H"/backbone10.txt)" -eq 10                            # backbone STAYS 10 (symbol-vs-array rule, 18n)
# two-lineage DIRECT echoes (byte-ident pins): the IMMEDIATE donor (link4-
# 18n, the tree this row clones) + the frozen link6/erspan carry faces:
test "$(md5sum "$L4"/vectors.txt | awk '{print $1}')" = "c7f5808fa326b7831603813c16a3b01e"
test "$(md5sum "$L4"/vectors_faceA.txt | awk '{print $1}')" = "9fdfc50da8fee22b473028f1f9b29c12"
test "$(md5sum "$R"/tools/link6_harness/vectors.txt | awk '{print $1}')" = "e59f7a8a70d172261dcb847dcfdcb36a"
test "$(md5sum "$R"/tools/link6_harness/vectors_faceA.txt | awk '{print $1}')" = "d2fc5591bc45c1787fcee7393675a3d8"
test "$(md5sum "$R"/tools/erspan_harness/vectors.txt | awk '{print $1}')" = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$R"/tools/erspan_harness/vectors_faceA.txt | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"
# gre GATE anchor (the positive-gate CONTRAST face for this row's ZERO-gate pin):
test "$(md5sum /opt/data/snort3-rust/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" /opt/data/snort3-rust/tools/gre_harness/gate.txt
grep -q "4826fc2233044a2d5429413faf0ae1af" /opt/data/snort3-rust/tools/fmod_harness/build.sh

# ---- TWO-LINEAGE census loop (MEASURED; THIS row adds ZERO gate.txt so the
# 25-tracked face is UNDISTURBED BY DESIGN): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(cat "$H/gate_md5_lineages.txt")" -eq 17
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY
# name-pin census (dir-name NEVER freezes a TU name; collision fires LOUDLY;
# the mpls/vlan/link rows' names NEVER land in a misc9 face):
test "$(ls -d "$R"/tools/module_harness "$R"/tools/reload_tracker_harness "$R"/tools/reload9_harness 2>/dev/null | wc -l)" -eq 0
# the ONE tools-wide misc9 mention at HEAD = link4's dirty-guard sibling
# exclusion face (VERBATIM pattern cited, NEVER a name-pin of this row's TUs):
test "$(grep -c 'tools/(link4|misc9)_harness' "$L4/build.sh")" -eq 1
for n in cd_mpls cd_vlan cd_pppoe erspan2; do
    test "$(cat "$H/probe.cc" "$H/probe_dec.cc" "$H/witness_misc9.cc" | grep -c "$n" || true)" -eq 0
done
test "$(grep -c '9fad7e9d7a278fbc2ee82c233f86e774' "$R/tools/vocab_harness/build.sh")" -ge 1   # 18e chain anchor readable face
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin (the 18i PROCESS-LESSONS law -- pin the immutable
# ground only; the dirty-guard template rides below).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (the SINGLE-TENANT FACE: the root
# .gitignore is NEVER touched by this pass -- the block lives in a NESTED
# tools/misc9_harness/.gitignore, itself a harness file; git honors it for
# ls-files/check-ignore). NON-ignored face = the 7 lineage-shape stageables
# (link4's 7-face shape: 6 + the tracked witness, the witness_pkthdr
# precedent) + the .gitignore instrument face = 8 others. The dir is FULLY
# UNTRACKED this pass (?? face); PRE/POST posture per 18i; NEVER staged. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/misc9_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/misc9_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 8
for f in PLAN.md build.sh probe.cc probe_dec.cc vectors.txt vectors_faceA.txt witness_misc9.cc .gitignore; do
    echo "$face" | grep -q "tools/misc9_harness/$f$"
done
test "$(echo "$face" | grep -c 'witness_misc9')" -eq 1     # the tracked-witness face (link4 shape)
# the gitignored faces re-proved individually via the NESTED block (a missing
# pattern = a blob in the future add = loud):
for f in copy/reload_tracker.o copy/module.o copy/main/reload_tracker.cc copy/daq.h o2/reload_tracker.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.o witness_18f.o witness_conf.cc witness_misc9.o vectors_O0.txt vectors_faceA_O2.txt nm_U_tracker.txt E4_module.txt E4_donorsrc_module.txt E4_noctl_tracker.txt E4_restored_module.txt L1_undefined.txt L1_link_face.txt module_residue_dem.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/misc9_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/misc9_harness/$f NOT ignored"; exit 1; }
done
git -C /opt/data/snort3-rust check-ignore -q "tools/misc9_harness/vectors.txt" && { echo "VECTORS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/misc9_harness/vectors_faceA.txt" && { echo "FACE-A WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/misc9_harness/witness_misc9.cc" && { echo "WITNESS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/misc9_harness/.gitignore" && { echo "GITIGNORE-INSTRUMENT WRONGLY IGNORED"; exit 1; } || true
# no STAGED churn: index EMPTY (the row stages NOTHING from build.sh). The
# SEED-pass zero-tracked-churn face is FLIPPED by the rs landing (PLAN §3/§9
# predicted the later rs pass): the row's OWN tracked-MODIFIED face is
# EXACTLY the two mod.rs wiring files + the two doc files (ZERO churn of any
# other kind, ZERO post-commit once the row's single commit lands in HEAD --
# the guard tolerance covers BOTH states and NEVER pins own-HEAD):
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"
test "$(git -C /opt/data/snort3-rust status --porcelain | grep -v '^??' | grep -vcE ' M "?(PORTING_PLAN\.md|KNOWN DEVIATIONS\.md|src/framework/mod\.rs|src/main/mod\.rs)"?$')" -eq 0   # the KNOWN-DEVIATIONS name rides the QUOTED porcelain face (space in name)
# dir face BOTH states: ?? tools/misc9_harness/ while UNTRACKED (pre-commit,
# the seed-pass face) else tracked at EXACTLY the 8 stageable faces (post-
# commit); a SIBLING harness's ?? dir (a concurrent row child -- e.g. the
# mpls q4 row landed during THIS pass) is TOLERATED, NEVER touched, NEVER
# staged, and NO tracked file of any other row may move. The row's own-new
# rs face (module.rs / reload_tracker.rs / the parity test) rides the ?? side
# pre-commit, the same single-tenancy tolerance:
if git -C /opt/data/snort3-rust ls-files --error-unmatch "tools/misc9_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C /opt/data/snort3-rust ls-files "tools/misc9_harness/" | wc -l)" -eq 8   # the 8 stageable faces pinned (6 lineage + witness + nested .gitignore)
else
    git -C /opt/data/snort3-rust status --porcelain | grep -qx '?? tools/misc9_harness/'
fi
# other build.sh misc9 mentions: ONLY the link4 dirty-guard exclusion above
# (the cited face); ZERO besides it (census single-tenant):
test "$(grep -rl 'misc9' "$R"/tools/*/build.sh | grep -v "$H/build.sh" | grep -v "$L4/build.sh" | wc -l)" -eq 0
# NEXT.md cargo CITE face ONLY (597/0 x3 seeded for the future rs pass; NEVER
# edited here, NEVER run here):
test "$(grep -c '597 tests green / 0 FAILED' "$R/NEXT.md")" -eq 3

echo "row-TU nm census (MEASURED, never typed): module=$(wc -l < "$H/nm_U_module.txt") tracker=$(wc -l < "$H/nm_U_tracker.txt") union=$(wc -l < "$H/nm_U_union.txt") (the -DNDEBUG 31/25 face; RECON non-NDEBUG 32/26 scratch face delta = one __assert_fail pull per TU, §9)"
echo "witness posture: OWN L1 RE-MEASURE EXACTLY-1 distinct undefined (ControlConn::show_prompt) => ONE own witness_misc9 (27L). The recon +2 face (LogMessage half) DIED by the carried stubs_18d seam (vprintf LogMessage body INHERITED -- multiple-definition face, scratch seed run1); LogMessage U x1 in tracker resolved by WIN ALONE; backbone array stays $(wc -l < "$H/backbone10.txt") (symbol-vs-array, 18n)"
echo "cp face: donor-VERBATIM module half (md5-equality copy==ground -- the FIRST row with a ZERO-cp 403-L half) + tracker cc+h ONLY: 122 -> 124 mid-build (reload_tracker.h find-0 1/4 fresh; control.h+messages.h+snort_types.h find-1; thread_config.h hwloc shim INHERITED)"
echo "framework-TU face: NOLOAD head (BUILDING_SO/snort_plugins grep-0 x4 asserted) + null_params PT_MAX walk + record/DEFS/VERB census + stats ladder over the REAL module.o + reload ladder through the cc :41/:48/:60/:75/:88 literals; -DNDEBUG BOTH row TUs (production arm + :372 assert arm observed; §9)"
echo "E4 both ways: -I src module rc1 hwloc.h chained via thread_config.h:22 (tracker raw rc0 HONEST contrast -- 4/4 includes ground-resident) / module.h kills module ONLY / reload_tracker.h kills tracker ONLY (the 1-cp law) / control.h kills tracker ONLY, module SURVIVES (link6 log_text wall INVERTED) / restored rc0 x2"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED; tracked gate.txt = 1); BACKBONE STAYS 10 (own witness is a ROW face, never an array face); chain echoes link4 c7f5808f/9fdfc50d + link6 e59f7a8a/d2fc5591 + erspan 7d7d3500/3ec325d7 BYTE-IDENT DIRECT"
echo "MISC9_FRAMEWORK_OK vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=0"
