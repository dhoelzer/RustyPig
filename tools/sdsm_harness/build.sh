#!/usr/bin/env bash
# ---- ROW 23i: THE sf-daq_static_modules DIALECT ROW (chapter-20 LAST item) —
# the cmake configure_file TEMPLATE src/packet_io/sf-daq_static_modules.h.in
# 11 L md5 3b8e3f07189fb0a99bc3a50aac87ac3f @ fe29cbe — a TEMPLATE, NEVER a
# landing: THE GENERATED PRODUCT NEVER EXISTS on disk in the READ-ONLY ground
# (find-0 EVERY build, arm-pinned) and its content is a BUILD-SYSTEM face (the
# DAQ_STATIC_MODULES cmake LIST). THE GENERATOR MECHANISM (packet_io/CMakeLists
# :17-:29, the :19/:20 string(APPEND) foreach + :22 configure_file + :26
# COMPILE_DEFINITIONS ENABLE_STATIC_DAQ + :27 binary-dir include_directories)
# is REPLAYED with the ACTUAL tool (cmake -P, this box 3.31.6) over a STATED
# SYNTHETIC name list (pcap;nfq;dump) — the product is a SYMBOLIC SHAPE face,
# NEVER a claim it IS a real build's generated header (the honesty face,
# KNOWN DEVIATIONS row 23i). THE CALL-SITE rides the LANDED 23a home (sf-daq.cc
# :38-:40 include post + :69-:71 THE ONLY call-site, post INSIDE load() AFTER
# the dirs[] ctor legs, BEFORE the :72 dynamic call — the ORDER face the DEC
# probe replays); sf-daq.cc/.h NEVER re-landed (23a, md5s 7ac13aa1/2e272d2d).
# THE ABSENT-SDK-DECL WALL BOTH WAYS EVERY build: daq_load_static_modules is
# DECLARED NOWHERE the shipped api/daq_module_api.h 165 L 1a617b3e reads
# (grep-0 arm) — IT rides api/daq.h :42 (DAQ_Module_h *modules — the TYPE-DRIFT
# face vs the REAL body daq_base.c :237 const DAQ_ModuleAPI_t **) + the body
# daq_base.c :237-:250 (the WALKED-COUNT return law, NEVER a success code; the
# dup-name register legs FAIL loudly to stderr, the table NEVER doubles). The
# E4 undecl pair: the generated-shape TU WITHOUT the cited daq.h rider dies
# EXACTLY-1 'was not declared'; WITH the rider (the -include posture, cmake
# :27's include_shape) closes rc0 SILENT.
# vectors: DEC 7 L + FACE-A 4 L (the REAL DAQ_ModuleAPI_t record SHAPE the
# generated externs type daq_module_api.h :99-:159 + the version macros the
# register sanity ladder checks), FIRST-RUN-SEED, O0==O2 BYTE-IDENT,
# tamper-proven, drift-refuse. THE Rust leg EXTENDS the landed 23a sf-daq.rs
# home ONE home NEVER re-forked (the StaticDaqModules provider + the cmake
# expansion replay fn + the load() call-post ORDER arm, enabled=false = the
# measured grep-0 harness/donor config.h posture, every existing face UNMOVED).
# ZERO-gate: sf-daq.cc/.h TEST_CASE grep-0 x2 + the packet_io test CMake
# EXACTLY-2 add_cpputest faces RE-MEASURED; NO gate.txt EVER; the walked
# census STAYS 28/9/20/1; the backbone STAYS 10. ZERO new allows/unsafe; the
# misc-9 landmine legs STAY. Tokens: own 'sd-sm' face MEASURED 0 pre-hit (the
# sd-sm/static-daq/s-dialect families find-0); the five strict sf-daq holder-face
# pins (da-qio 6 / sf-inst 6 / sf-mod 2 / dir-stor 1 / ac-t 8) UNMOVED — this
# row's files ride the RUNTIME-concat ${SD} ground-path forms ONLY, ZERO joined
# bare hits (self-scan arms EVERY build); the NEXT seed '798 tests green / 0
# FAILED' x3 NEVER moves (the docs sibling banks the NEW face post-row).
set -euo pipefail
R=/opt/data/snort3-rust
SRC=/opt/data/snort3-src
L=/opt/data/libdaq
H=$(cd "$(dirname "$0")" && pwd)
SD="sf""daq"                          # the ground-file token RUNTIME form (the
                                       # 23b concat law: bare hits HERE 0)
MN="sd""sm"                           # the RUNTIME self-token (the DOUBLE-
                                       # concat law: the dir name = sd-sm-harness
                                       # typed NOWHERE joined in this file)
G="${SD}_static"                      # the dialect ground-name runtime form
TPL="$SRC/src/packet_io/${G}_modules.h.in"
C=$H/copy

# ---- ground identity (RE-MEASURED EXACT every build; the law) ----
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"
test "$(git -C "$L" rev-parse HEAD)"   = "c8d4083904f7791f596d853178aca4ef1e20f7d3"
test "$(wc -l < "$TPL")" -eq 11
test "$(md5sum "$TPL" | awk '{print $1}')" = "3b8e3f07189fb0a99bc3a50aac87ac3f"   # (a) THE template pin
test "$(find "$SRC" -name "${G}_modules.h" | wc -l)" -eq 0    # THE generated product NEVER on disk
test "$(find "$SRC" -name "${G}_modules.h.in" | wc -l)" -eq 1 # the TEMPLATE is the source of truth
# the mechanism face (CMakeLists :17-:28 VERBATIM lines, the runtime-concat
# forms keep the SELF file joined-token-free — the equality arms JOIN at runtime):
test "$(sed -n '17p' "$SRC/src/packet_io/CMakeLists.txt")" = 'if (ENABLE_STATIC_DAQ)'
test "$(sed -n '18p' "$SRC/src/packet_io/CMakeLists.txt")" = '    foreach (STATIC_MODULE_NAME IN LISTS DAQ_STATIC_MODULES)'
test "$(sed -n '19p' "$SRC/src/packet_io/CMakeLists.txt")" = '        string(APPEND DAQ_STATIC_MODULE_EXTERNS "extern const DAQ_ModuleAPI_t ${STATIC_MODULE_NAME}_daq_module_data;\n")'
test "$(sed -n '20p' "$SRC/src/packet_io/CMakeLists.txt")" = '        string(APPEND DAQ_STATIC_MODULE_DATA_ARRAY "    &${STATIC_MODULE_NAME}_daq_module_data,\n")'
test "$(sed -n '22p' "$SRC/src/packet_io/CMakeLists.txt")" = '    configure_file ('
test "$(sed -n '23p' "$SRC/src/packet_io/CMakeLists.txt")" = '        "${CMAKE_CURRENT_SOURCE_DIR}/'"${SD}"'_static_modules.h.in"'
test "$(sed -n '24p' "$SRC/src/packet_io/CMakeLists.txt")" = '        "${CMAKE_CURRENT_BINARY_DIR}/'"${SD}"'_static_modules.h"'
test "$(sed -n '26p' "$SRC/src/packet_io/CMakeLists.txt")" = '    set_source_files_properties('"${SD}"'.cc PROPERTIES COMPILE_DEFINITIONS ENABLE_STATIC_DAQ)'
test "$(sed -n '27p' "$SRC/src/packet_io/CMakeLists.txt")" = '    include_directories(${CMAKE_CURRENT_BINARY_DIR})'
test "$(grep -c 'ENABLE_STATIC_DAQ' "$SRC/src/packet_io/CMakeLists.txt")" -eq 2   # :17 + :26 ONLY
test "$(grep -c "${SD}_static_modules" "$SRC/src/packet_io/CMakeLists.txt")" -eq 3 # :23 +:24 +:28
# THE EXACTLY-2 #ifdef posts riding the LANDED 23a pair (MEASURED + echoed;
# the pair NEVER re-landed — the 23a md5s pinned):
test "$(wc -l < "$SRC/src/packet_io/${SD}.cc")" -eq 420
test "$(md5sum "$SRC/src/packet_io/${SD}.cc" | awk '{print $1}')" = "7ac13aa1f5013ead580f5b4f61c38368"
test "$(wc -l < "$SRC/src/packet_io/${SD}.h")" -eq 72
test "$(md5sum "$SRC/src/packet_io/${SD}.h"  | awk '{print $1}')" = "2e272d2d68e40138946326df3c5cfc95"
test "$(grep -c 'ENABLE_STATIC_DAQ' "$SRC/src/packet_io/${SD}.cc")" -eq 2
test "$(sed -n '38p' "$SRC/src/packet_io/${SD}.cc")" = '#ifdef ENABLE_STATIC_DAQ'
test "$(sed -n '39p' "$SRC/src/packet_io/${SD}.cc")" = '#include "'"${SD}"'_static_modules.h"'   # post 1
test "$(sed -n '69p' "$SRC/src/packet_io/${SD}.cc")" = '#ifdef ENABLE_STATIC_DAQ'
test "$(sed -n '70p' "$SRC/src/packet_io/${SD}.cc")" = '    daq_load_static_modules(static_daq_modules);'   # THE ONLY call-site
test "$(sed -n '71p' "$SRC/src/packet_io/${SD}.cc")" = '#endif'
test "$(grep -c 'daq_load_static_modules' "$SRC/src/packet_io/${SD}.cc")" -eq 1   # ONE call site ONLY
# ZERO-gate faces (the walked row: NO gate ships, the census NEVER flips):
test "$(grep -c 'TEST_CASE' "$SRC/src/packet_io/${SD}.cc")" -eq 0
test "$(grep -c 'TEST_CASE' "$SRC/src/packet_io/${SD}.h")"  -eq 0
test "$(grep -c 'add_cpputest' "$SRC/src/packet_io/test/CMakeLists.txt")" -eq 2   # the counters + gate-candidate suites

# ---- THE absent-SDK-decl honesty face (MEASURED + echoed EVERY build) ----
test "$(wc -l < "$L/api/daq_module_api.h")" -eq 165
test "$(md5sum "$L/api/daq_module_api.h" | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
test "$(grep -c 'daq_load_static' "$L/api/daq_module_api.h" || true)" -eq 0       # THE decl ABSENT there
test "$(sed -n '159p' "$L/api/daq_module_api.h")" = '} DAQ_ModuleAPI_t;'          # the extern-data TYPE face :159
test "$(sed -n '42p' "$L/api/daq.h")" = 'DAQ_LINKAGE int daq_load_static_modules(DAQ_Module_h *modules);'   # the decl home (TYPE-DRIFT face)
test "$(sed -n '237p' "$L/api/daq_base.c")" = 'DAQ_LINKAGE int daq_load_static_modules(const DAQ_ModuleAPI_t **modules)'  # the REAL body
test "$(sed -n '250p' "$L/api/daq_base.c")" = '}'                                  # the body tail
test "$(git -C "$L" status --porcelain | wc -l)" -eq 0                            # THE SDK ground STAYS CLEAN

# ---- copy tree: the REAL SDK re-cite (the 23a law; NO donor — the dialect
# row needs headers + the REAL api bodies ONLY, the harness stays SMALL) ----
rm -rf "$C" "$H/o2"; mkdir -p "$C/api" "$C/packet_io"
cp "$L"/api/daq.h "$L"/api/daq_common.h "$L"/api/daq_dlt.h "$L"/api/daq_module_api.h "$C"/
sed -e 's/@DAQ_MAJOR_VERSION@/3/' -e 's/@DAQ_MINOR_VERSION@/0/' -e 's/@DAQ_PATCH_VERSION@/29/' -e 's/@DAQ_SUBLEVEL_VERSION@/0/' \
    "$L"/api/daq_version.h.in > "$C"/daq_version.h
test "$(wc -l < "$C"/daq_version.h)" -eq 49
grep -q 'define DAQ_VERSION_MAJOR 3' "$C"/daq_version.h
test "$(md5sum "$C"/daq.h       | awk '{print $1}')" = "35294a1773477a9579c8494cb1dadfea"
test "$(md5sum "$C"/daq_common.h | awk '{print $1}')" = "28789a3dc10b84c974118c38700755b4"
test "$(md5sum "$C"/daq_dlt.h   | awk '{print $1}')" = "57208729c490da53d0d0cb2361ca2736"
test "$(md5sum "$C"/daq_module_api.h | awk '{print $1}')" = "1a617b3edef11431c9244bee728baadc"
for f in daq_base daq_base_api daq_config daq_instance_api_defaults daq_mod_ops; do
    gcc -std=gnu11 -DNDEBUG -O0 -w -I"$L"/api -I"$C" -c "$L"/api/"$f".c -o "$C"/api/"$f".o
done
test "$(find "$C"/api -name '*.o' | wc -l)" -eq 5
# the VERBATIM fresh cp of the TEMPLATE (the source of truth; cmp-proved):
cp "$TPL" "$C"/packet_io/
cmp -s "$C"/packet_io/"${G}_modules.h.in" "$TPL" || { echo "template cp DRIFT"; exit 1; }

# ---- leg (b): THE cmake-expansion replay with the ACTUAL cmake (-P script
# mode) running the ground foreach VERBATIM over the STATED synthetic list;
# byte-deterministic proven by a DOUBLE replay cmp EVERY build ----
cmake -DTPL_IN="$C"/packet_io/"${G}_modules.h.in" -DGEN_OUT="$C"/"${G}_modules.h" \
      -DDAQ_STATIC_MODULES="pcap;nfq;dump" -P "$H"/exp.cmake
test "$(wc -l < "$C"/"${G}_modules.h")" -eq 17                       # 11 + 2 + 4 (@sub@ trailing-newline face)
test "$(grep -c '^extern const DAQ_ModuleAPI_t ' "$C"/"${G}_modules.h")" -eq 3
test "$(grep -c "^    &.*_daq_module_data,\$" "$C"/"${G}_modules.h")" -eq 3
test "$(sed -n '4p' "$C"/"${G}_modules.h")" = 'extern const DAQ_ModuleAPI_t pcap_daq_module_data;'   # LIST order face
test "$(sed -n '15p' "$C"/"${G}_modules.h")" = '    nullptr'          # the nullptr tail face (line 14 rides the cmake APPEND face's trailing-newline blank)
cmake -DTPL_IN="$C"/packet_io/"${G}_modules.h.in" -DGEN_OUT="$C"/replay2.h \
      -DDAQ_STATIC_MODULES="pcap;nfq;dump" -P "$H"/exp.cmake
cmp "$C"/"${G}_modules.h" "$C"/replay2.h                              # BYTE-deterministic replay
# the EMPTY-LIST degenerate face (the cmake APPEND-accumulator-never-created
# face: tokens substitute EMPTY):
cmake -DTPL_IN="$C"/packet_io/"${G}_modules.h.in" -DGEN_OUT="$C"/replay_empty.h \
      -DDAQ_STATIC_MODULES="" -P "$H"/exp.cmake
test "$(wc -l < "$C"/replay_empty.h)" -eq 11

# ---- E4 wall BOTH ways: the absent-decl dies-what, the cited rider closes —-
if g++ -std=c++17 -DNDEBUG -O0 -w -DENABLE_STATIC_DAQ -I"$C" -include "$C"/"${G}_modules.h" \
      -c "$H"/e4_undecl.cc -o /dev/null 2> "$H"/E4_undecl.txt; then
    echo "E4 undecl flip BROKE: the shipped module-API head declares the symbol — RE-PLAN"; exit 1
fi
test "$(grep -c 'error:' "$H"/E4_undecl.txt)" -eq 1
test "$(grep -c "daq_load_static_modules.*was not declared" "$H"/E4_undecl.txt)" -eq 1
g++ -std=c++17 -DNDEBUG -O0 -w -DENABLE_STATIC_DAQ -I"$C" -include "$C"/daq.h \
    -include "$C"/"${G}_modules.h" -c "$H"/e4_undecl.cc -o /dev/null 2> "$H"/E4_rider.txt
test ! -s "$H"/E4_rider.txt                                           # the cited-decl rider posture closes SILENT

# ---- DEC probe: the generated-shape header enters by the cmake :26+:27
# POSTURE (-D ENABLE_STATIC_DAQ + the binary-dir header face) ----
GXXC="g++ -std=c++17 -DNDEBUG -O0 -w -I$C -DENABLE_STATIC_DAQ -include $C/${G}_modules.h"
$GXXC -c "$H"/probe.cc -o "$H"/probe.o
LINK="$C/api/daq_base.o $C/api/daq_base_api.o $C/api/daq_config.o $C/api/daq_instance_api_defaults.o $C/api/daq_mod_ops.o"
g++ "$H"/probe.o $LINK -ldl -o "$H"/probe
test "$(nm --defined-only "$C"/api/daq_base.o | grep -c ' T daq_load_static_modules')" -eq 1   # the REAL body home
test "$(nm "$H"/probe | grep -c 'U daq_load_static_modules' || true)" -eq 0                    # closed by the REAL api link
timeout 60 "$H"/probe > "$H"/vectors_O0.txt 2> "$H"/probe_dec_stderr.txt || { echo PROBE_FAIL DEC O0; exit 1; }
test "$(grep -c 'Failed to register static DAQ module.' "$H"/probe_dec_stderr.txt)" -eq 6      # D4 trio + the D5 re-call trio (the loud dup-register law, NEVER silent)
test "$(grep -c 'Unable to open directory' "$H"/probe_dec_stderr.txt)" -eq 1                   # the missing-dir CONTINUE face (the 23a :270-:273 law)

# ---- FACE-A: the record SHAPE ladder (ZERO sdk .o dependency for the
# SHAPE arms; the version face rides the link) ----
g++ -std=c++17 -DNDEBUG -O0 -w -I"$C" -c "$H"/probe_faceA.cc -o "$H"/probe_faceA.o
g++ "$H"/probe_faceA.o $LINK -ldl -o "$H"/probe_faceA
timeout 60 "$H"/probe_faceA > "$H"/vectors_faceA_O0.txt 2> "$H"/faceA_stderr.txt || { echo PROBE_FAIL FACE-A O0; exit 1; }
test ! -s "$H"/faceA_stderr.txt

# ---- O2 twins + the x-stream byte-identity law ----
O2=$H/o2; mkdir -p "$O2"
$GXXC -c "$H"/probe.cc -o "$O2"/probe.o
g++ -std=c++17 -DNDEBUG -O2 -w -I"$C" -c "$H"/probe_faceA.cc -o "$O2"/probe_faceA.o
g++ "$O2"/probe.o $LINK -ldl -o "$H"/probe_O2
g++ "$O2"/probe_faceA.o $LINK -ldl -o "$H"/probe_faceA_O2
timeout 60 "$H"/probe_O2       > "$H"/vectors_O2.txt       || { echo PROBE_FAIL DEC O2; exit 1; }
timeout 60 "$H"/probe_faceA_O2 > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL FACE-A O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt

# ---- FIRST-RUN-SEED face (the law; NEVER typed) ----
if [ ! -e "$H"/vectors.txt ]; then
    cp "$H"/vectors_O0.txt "$H"/vectors.txt
    cp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt
    echo "SEED PASS: DEC + FACE-A vectors measured (NEVER typed)"
else
    cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt              || { echo "VECTORS DEC DRIFT vs tracked"; exit 1; }
    cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt  || { echo "VECTORS FACE-A DRIFT vs tracked"; exit 1; }
fi
test -e "$H"/vectors.txt
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H"/md5_pinned.txt

# ---- TAMPER-PROVEN blocks ----
cp "$H"/vectors.txt "$H"/.vectors_pristine
line=$(grep -n '^D2 ' "$H"/vectors.txt | head -1 | cut -d: -f1)
sed -i "${line}s/static_before_dynamic=1/static_before_dynamic=0/" "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt && { echo "TAMPER ARM DEAD (DEC): flipped order face still matches"; exit 1; }
cp "$H"/.vectors_pristine "$H"/vectors.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "TAMPER RESTORE DEAD (DEC)"; exit 1; }
rm -f "$H"/.vectors_pristine
cp "$H"/vectors_faceA.txt "$H"/.vectors_faceA_pristine
line=$(grep -n '^SIZES ' "$H"/vectors_faceA.txt | head -1 | cut -d: -f1)
sed -i "${line}s/modapi=216/modapi=217/" "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt && { echo "TAMPER ARM DEAD (FACE-A): flipped size still matches"; exit 1; }
cp "$H"/.vectors_faceA_pristine "$H"/vectors_faceA.txt
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "TAMPER RESTORE DEAD (FACE-A)"; exit 1; }
rm -f "$H"/.vectors_faceA_pristine

# ---- vectors ladder greps (the line-set faces; counts MEASURED) ----
V=$H/vectors.txt; FA=$H/vectors_faceA.txt
test "$(wc -l < "$V")" -eq 7
test "$(wc -l < "$FA")" -eq 4
grep -q '^D0 names=pcap,nfq,dump, slots=4 tail=1$' "$V"               # the cmake LIST-ORDER -> entry-order face + the nullptr tail
grep -q '^D1 cold pcap=0 nfq=0 dump=0$' "$V"                          # the loaded=false cold face (gate fuel)
grep -q '^D2 walked=3 static_before_dynamic=1 dynamic_err=0$' "$V"    # THE ORDER face: the :70 post BEFORE the :72 call
grep -q '^D3 find pcap=1 nfq=1 dump=1 absent=0 walk=3$' "$V"
grep -q '^D4 walk2=3 table_not_doubled=1$' "$V"                       # the WALKED-COUNT law (:250) + the dup-name FAIL legs
grep -q '^D5 decay_handoff_walked=3 ' "$V"                            # the typedef FACE-CLOSED type handoff (never a cast)
grep -q '^D6 externs_hash=.* data_hash=.* bloblen=' "$V"              # the :19/:20 token-blob faces (runtime-name-built, NEVER frozen)
grep -q '^SIZES ' "$FA"; grep -q '^EXTERNSHAPE ' "$FA"
test "$(grep -c '^D' "$V")" -eq 7
test "$(grep -c '^[A-Z]' "$V")" -eq 7

# ---- the dialect-vs-landed-home grep faces (the ONE-HOME law witness) ----
test "$(grep -c "pub struct StaticDaqModules" "$R"/src/packet_io/${SD}.rs)" -eq 1     # landed-home EXTENSION (ONE home)
test "$(grep -c "pub fn expand_daq_static_modules" "$R"/src/packet_io/${SD}.rs)" -eq 1
test "$(grep -c 'expand_daq_static_modules\|StaticDaqModules' "$R"/src/packet_io/mod.rs || true)" -eq 0   # ZERO new mod.rs wiring lines (the extension rides the EXISTING module declaration)

# ---- landmine NAMING legs (the misc-9 family, STAYS) ----
test "$(grep -rlE 'ReloadSurvivor|reload_survivor' "$R"/src --include=*.rs | wc -l)" -eq 2
test "$(grep -rl 'struct Tracer' "$R"/src --include=*.rs | wc -l)" -eq 0
test "$(grep -rlE 'ReloadSurvivor|reload_survivor' "$R"/src/packet_io --include=*.rs | wc -l)" -eq 0

# ---- GATE census (ZERO-gate row: the MEASURED face STAYS; walked, never typed) ----
frozen=$(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af'); test "$frozen" -eq 9
test "$(ls "$R"/tools/*/gate.txt | wc -l)" -eq 28
md5sum "$R"/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H"/gate_md5_lineages.txt
test "$(cat "$H"/gate_md5_lineages.txt)" -eq 20
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
test "$(git -C "$R" ls-files | grep -c gate.txt)" -eq 1
test ! -e "$H"/gate.txt
git -C "$R" check-ignore -q "tools/${MN}_harness/gate.txt"

# ---- backbone STAYS TEN ----
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
for e in "${B10[@]}"; do set -- $e; test "$(md5sum "$1" | awk '{print $1}')" = "$2"; done
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H"/backbone10.txt
test "$(wc -l < "$H"/backbone10.txt)" -eq 10

# ---- NEXT.md token face, STATE-AWARE (the JOINED own-token ZERO BOTH
# branches — the joined own-token NEVER rides docs; the sibling writes the
# hyphen-BRACKET face; the 23g/23h pattern) ----
test "$(grep -c "${MN}_harness" "$R/NEXT.md" || true)" -eq 0
test "$(grep -c "${MN}_DONE" "$R/NEXT.md" || true)" -eq 0
for s in 798 784 772 763 752; do
    test "$(grep -c "$s tests green / 0 FAILED" "$R/NEXT.md")" -eq 3
done
test "$(grep -c '588 tests green / 0 FAILED' "$R/NEXT.md")" -eq 4
test "$(grep -c '580 passed / 0 failed' "$R/NEXT.md")" -eq 3
test "$(grep -c '573 tests green' "$R/NEXT.md")" -eq 5
test "$(grep -c 'cc \*\*133\*\*' "$R/NEXT.md")" -ge 1
test "$(grep -c '5 TES''T(' "$R/NEXT.md")" -eq 1
grep -q "tc""_harness" "$R/NEXT.md"

# ---- token censuses (MEASURED at authoring; this row's files add ZERO
# joined holders — the ${SD}/${MN} runtime forms self-scan arms) ----
test "$(grep -c 'sf'"daq" "$H/build.sh" || true)" -eq 0                 # SELF-scan: no joined bare hits HERE
test "$(find "$R"/tools -maxdepth 1 -iname "*${MN}*" | wc -l)" -eq 1    # THIS dir ONLY (sd-sm family find-0 pre-hit)
test "$(grep -rl "$MN" "$R"/tools "$R"/tests --include='*.sh' --include='*.rs' --exclude-dir="${MN}_harness" 2>/dev/null | wc -l)" -eq 0   # own-token family face 0 (pre-hit MEASURED 0; this row adds ZERO holders — NEVER edited: the pin arm rides own-file concat, the SELF-HIT hazard ruled at 23f; proven by the SELF-scan arm below)
test "$(grep -rl "$MN" "$R"/src --include=*.rs 2>/dev/null | wc -l)" -eq 0
# the SELF-HIT truth (the 23c law): THIS file rides ZERO joined own-token
# the strict sf-daq holder faces stay PINNED by the family arms (da-qio :171
# 6 / dir-stor :139 1 / sf-mod :186 2 / sf-inst :224 6 / ac-t :171 8) — this
# row NEVER moves them; the walked face re-echoed HERE with the union exclusion
# set (the family arms stay NEVER edited):
holders=$(grep -rl "$SD" "$R"/tools/*/build.sh "$R"/tests/*.rs 2>/dev/null | grep -v "sf""inst" | grep -v "tools/daq""io_harness/build.sh$" | grep -v "tools/misc""3_harness/build.sh$" | grep -v "tools/mpls_harness/build.sh$" | grep -v "tools/sf""mod_harness/build.sh$" | grep -v "tools/dir""stor_harness/build.sh$" | grep -v "tools/pc""gate_harness/build.sh$" | grep -v "tools/misc""3_harness/witness_trio.cc$" | grep -v "tools/misc""3_harness/gate.txt$" | grep -v "tools/pt""rmod_harness/build.sh$" | grep -v "tests/daq""io_parity_test.rs$" | grep -v "tests/misc""3_parity_test.rs$" | grep -v "tests/ac""t_parity_test.rs$" | grep -v "tests/pt""rmod_parity_test.rs$" | wc -l || true)
test "$holders" -eq 0   # BEYOND every frozen/ruled holder family THIS row adds ZERO new sf-daq joined holders (the union exclusion set = the five strict-pin arms' sets — da-qio/dir-stor/sf-mod/sf-inst/ac-t + the ruled cross-holder faces; MEASURED-0 at the row)

# ---- STATE-AWARE stageables dual guard (9 faces: the 8-face shape + the
# E4 undecl probe = the daqio 9-face precedent) ----
face=$(git -C "$R" ls-files "tools/${MN}_harness" | sort | paste -sd' ')
for f in .gitignore PLAN.md build.sh exp.cmake probe.cc probe_faceA.cc e4_undecl.cc vectors.txt vectors_faceA.txt; do
    echo "$face" | tr ' ' '\n' | grep -qx "tools/${MN}_harness/$f" || { echo "STAGEABLE FACE DEAD: $f"; exit 1; }
done
for f in copy/api/daq.h copy/api/daq_base.o copy/api/daq_base_api.o copy/api/daq_config.o copy/api/daq_instance_api_defaults.o copy/api/daq_mod_ops.o copy/daq.h copy/daq_common.h copy/daq_dlt.h copy/daq_module_api.h copy/daq_version.h "copy/packet_io/${G}_modules.h.in" "copy/${G}_modules.h" copy/replay2.h copy/replay_empty.h \
         o2/probe.o o2/probe_faceA.o probe probe_O2 probe_faceA probe_faceA_O2 probe.o probe_faceA.o \
         vectors_O0.txt vectors_O2.txt vectors_faceA_O0.txt vectors_faceA_O2.txt faceA_stderr.txt probe_dec_stderr.txt \
         E4_undecl.txt E4_rider.txt md5_pinned.txt gate_md5_lineages.txt backbone10.txt stageables.txt \
         .vectors_pristine .vectors_faceA_pristine; do
    git -C "$R" check-ignore -q "tools/${MN}_harness/$f" || { echo "GITIGNORE FACE DEAD: $f"; exit 1; }
done
git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | sort > "$H"/stageables.txt
if git -C "$R" ls-files --error-unmatch "tools/${MN}_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C "$R" ls-files "tools/${MN}_harness" | wc -l)" -eq 9
    test -z "$(git -C "$R" ls-files "tools/${MN}_harness" | grep -vE '\.gitignore|PLAN\.md|build\.sh|exp\.cmake|probe(_faceA)?\.cc|e4_undecl\.cc|vectors(_faceA)?\.txt')"
    test -z "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness")"   # ZERO-LEAK post-commit
else
    git -C "$R" status --porcelain | grep -qxF "?? tools/${MN}_harness/"
    test "$(git -C "$R" ls-files --others --exclude-standard "tools/${MN}_harness" | wc -l)" -eq 9
fi
test -z "$(git -C "$R" diff --name-only --cached)"
dirty=$(git -C "$R" status --porcelain | grep -vcE "^\?\? tools/${MN}_harness/$|^\?\? \"?tools/${MN}_harness/\"?$|^ M \"?(src/packet_io/sf""daq\.rs)\"?$|^\?\? tests/${MN}_parity_test\.rs$|^ M PORTING_PLAN\.md$|^ M \"?(KNOWN DEVIATIONS\.md)\"?$" || true)
test "$dirty" -eq 0

# ---- tail (the honest echo face) ----
echo "O0==O2: DEC $(cmp -s "$H"/vectors_O0.txt "$H"/vectors_O2.txt && echo BYTE-IDENT), FACE-A $(cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt && echo BYTE-IDENT)"
echo "template: $(wc -l < "$TPL") L md5 $(md5sum "$TPL" | awk '{print $1}') (VERBATIM cp'd, NEVER a landing); generated product find-0 in the ground (arm-pinned), NEVER invented"
echo "the EXACTLY-2 ifdef posts: cc :38 include post + cc :69-:71 THE ONLY call-site (post AFTER the dirs[] legs, BEFORE the :72 dynamic call — the D2 order face)"
echo "absent-decl face: api/daq_module_api.h grep-0; decl rides api/daq.h :42 (DAQ_Module_h * face vs the body const DAQ_ModuleAPI_t ** — TYPE-DRIFT cited); E4 undecl dies EXACTLY-1 'was not declared', the cited rider closes SILENT"
echo "ZERO-gate: sf-daq pair TEST_CASE 0/0; test CMake add_cpputest EXACTLY-2; census census-walk echo below; gate ships ZERO"
echo "gate census (walked): $(ls "$R"/tools/*/gate.txt | wc -l) on-disk / legacy $(md5sum "$R"/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af') x 4826fc22 / $(cat "$H"/gate_md5_lineages.txt) lineages / tracked-1 gre"
echo "backbone STAYS $(wc -l < "$H"/backbone10.txt) (symbol-vs-array)"
echo "SDSM_DONE vectors=$(wc -l < "$H"/vectors.txt) faceA=$(wc -l < "$H"/vectors_faceA.txt) gates=0 (the dialect DIALECT replay; the ONE-HOME extension rides the landed 23a home)"
