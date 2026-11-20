#!/usr/bin/env bash
# tun_harness -- row 18f tunnel trio: codecs/misc/{cd_teredo,cd_gtp,
# cd_geneve}.cc 161+291+282 = 734 L (PLAN 0: per-file md5s + wc sum pinned
# below, own-measured). PROBE-ONLY: zero gate material on all three row files;
# the three ground suites live in misc/test AND self-include the TUs
# (../cd_*.cc :20/:29/:29) -- CppUTest box-dead, E4 wall flipped-assert every
# build NEVER replayed as a gate. ZERO gate.txt here; the 9 holders of
# 4826fc2233044a2d5429413faf0ae1af among exactly 24 tracked gate.txt are frozen
# dirs -> 14th straight rides the SESSION fresh fmod+vocab rebuilds (scratch
# row18f/{fmod,vocab}_rebuild_18f.log), NEVER typed (17p).
# Copy tree (PLAN 2): ext DONOR face VERBATIM (cp -a) + 3 row cps + EXACTLY
# 2 fresh header cps (protocols/teredo.h + packet_io/active.h; geneve.h
# RESIDENT byte-ident -- cmp asserts). 81 + 5 = 86 source files.
# E4 WALLS (PLAN 3, flipped-assert EVERY build): pre-cp face cd_teredo MUST
# fail protocols/teredo.h (cc:27), cd_geneve MUST fail packet_io/active.h
# (cc:28), cd_gtp MUST pass; post-cp face rc=0 x3 empty. CppUTest suites MUST
# die at CommandLineTestRunner.h (E4_cpputest_fatal.txt).
# WITNESS (PLAN 4): EXACTLY ONE new witness -- SnortConfig::tunnel_bypass_
# enabled (all three TUs U-dump it; ground main/snort_config.cc:1020-:1023)
# home witness_18f.cc: ground-shaped body over observable table tun_mask, DEC
# probe toggles the 3 ground masks (GTP 0x01 / TEREDO 0x02 / GENEVE 0x200).
# LANDMINE (PLAN 5): ZERO -- the three names UNstubbed in vocab/codec donor
# faces (grep asserts); no stubs_18f.cc; probes pull NO codec_api object.
# Vectors NEVER typed (17p): ladders grep the MEASURED 40-L DEC + 7-L FACE-A
# faces (md5-pinned, O0==O2 byte-ident).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
EXT=/opt/data/snort3-rust/tools/ext_harness
ETH=/opt/data/snort3-rust/tools/eth_harness
C=$H/copy

# ---- ground identity (3 row files pinned by OWN md5 + wc, measured) ----
for pair in "cd_teredo 649dde0666ee14a9514cd02744815dd5 161" \
            "cd_gtp d0719e95a9ddc985ae09c4ba853bf17a 291" \
            "cd_geneve 0d05bf86e27d8c9c0fac63edfb5bc7ed 282"; do
    set -- $pair
    test "$(md5sum "$SRC"/src/codecs/misc/$1.cc | awk '{print $1}')" = "$2"
    test "$(wc -l < "$SRC"/src/codecs/misc/$1.cc)" -eq "$3"
done
test "$(cat $SRC/src/codecs/misc/{cd_teredo,cd_gtp,cd_geneve}.cc | wc -l)" -eq 734
# TRUE NAMES (PLAN 0): file base == extern table name on all three (ternary
# face greps, NOT a typed table):
grep -q 'const BaseApi\* cd_teredo\[\] =' "$SRC/src/codecs/misc/cd_teredo.cc"
grep -q 'const BaseApi\* cd_gtp\[\] ='     "$SRC/src/codecs/misc/cd_gtp.cc"
grep -q 'const BaseApi\* cd_geneve\[\] ='  "$SRC/src/codecs/misc/cd_geneve.cc"
# zero suite material per row file (PLAN 0):
for f in cd_teredo cd_gtp cd_geneve; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST' "$SRC"/src/codecs/misc/$f.cc || true)" -eq 0
done
# misc/test trio + self-include shape (PLAN 0 suites row, own wc THIS pass):
test "$(wc -l < "$SRC"/src/codecs/misc/test/teredo_codec_test.cc)" -eq 121
test "$(wc -l < "$SRC"/src/codecs/misc/test/gtp_codec_test.cc)"   -eq 140
test "$(wc -l < "$SRC"/src/codecs/misc/test/geneve_codec_test.cc)" -eq 163
test "$(sed -n '29p' "$SRC"/src/codecs/misc/test/teredo_codec_test.cc)" = '#include "../cd_teredo.cc"'
test "$(sed -n '29p' "$SRC"/src/codecs/misc/test/gtp_codec_test.cc)"   = '#include "../cd_gtp.cc"'
test "$(sed -n '20p' "$SRC"/src/codecs/misc/test/geneve_codec_test.cc)" = '#include "../cd_geneve.cc"'
test "$(grep -c 'TEST_GROUP' "$SRC"/src/codecs/misc/test/*.cc | awk -F: '{s+=$2} END {print s}')" -eq 3
test "$(grep -c '^TEST(' "$SRC"/src/codecs/misc/test/*.cc | awk -F: '{s+=$2} END {print s}')" -eq 7
test "$(grep -c 'CHECK' "$SRC"/src/codecs/misc/test/teredo_codec_test.cc)" -eq 3
test "$(grep -c 'CHECK' "$SRC"/src/codecs/misc/test/gtp_codec_test.cc)"   -eq 8
test "$(grep -c 'CHECK' "$SRC"/src/codecs/misc/test/geneve_codec_test.cc)" -eq 19
test "$(find "$SRC"/src/codecs/misc -name '*.h' | wc -l)" -eq 0   # misc ships ZERO headers
# STATIC_CODECS tunnel six (PLAN 5 census cite, sed-anchor):
test "$(sed -n '51p' "$SRC"/src/codecs/codec_api.cc)" = "extern const BaseApi* cd_geneve[];"
test "$(sed -n '68p' "$SRC"/src/codecs/codec_api.cc)" = "extern const BaseApi* cd_teredo[];"
test "$(wc -l < "$SRC"/src/codecs/codec_api.cc)" -eq 121
# zero-landmine face (PLAN 5): the three names UNstubbed in donor faces:
test "$(grep -c 'cd_teredo\|cd_gtp\|cd_geneve' /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc || true)" -eq 0
test "$(grep -c 'cd_teredo\|cd_gtp\|cd_geneve' /opt/data/snort3-rust/tools/codec_harness/stubs.cc || true)" -eq 0
# cd_gre rule UNTOUCHED (PLAN 8): anchors re-measured, 18f pre-digs nothing:
test "$(sed -n '34p' "$SRC"/src/codecs/ip/cd_gre.cc)" = "#ifdef UNIT_TEST"
test "$(sed -n '35p' "$SRC"/src/codecs/ip/cd_gre.cc)" = '#include "catch/snort_catch.h"'
test "$(sed -n '352p' "$SRC"/src/codecs/ip/cd_gre.cc | grep -c 'TEST_CASE (')" -eq 1
test "$(wc -l < "$SRC"/src/codecs/ip/cd_gre.cc)" -eq 366
# frozen-donor re-md5 census (PLAN 9, FIVE diff-0 donors asserted by grep below)

# ---- copy tree = ext DONOR face VERBATIM + 3 row cps + 2 fresh header cps ----
if [ ! -e "$EXT/copy/codec.o" ]; then bash "$EXT/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$EXT/copy" "$C"
find "$C" -name '*.o' -delete
test "$(md5sum "$C"/codecs/codec_module.h | awk '{print $1}')" = "3f3bd92752ba46b8732f831724d3b279"
test "$(md5sum "$C"/main/snort_config.h   | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
test ! -e "$C"/codecs/codec_api.h    # FACE-flip precondition inherited (no codec_api TU)
test ! -e "$C"/codecs/codec_api.cc
# geneve.h RESIDENT byte-ident (fresh-cp census, NEXT 18f scoping):
cmp -s "$C"/protocols/geneve.h "$SRC"/src/protocols/geneve.h
test "$(md5sum "$C"/protocols/geneve.h | awk '{print $1}')" = "10cfe860d4dab013aca85b7cdbdde9a2"
test "$(grep -c 'Active' "$SRC"/src/codecs/misc/cd_geneve.cc || true)" -eq 0  # zero Active:: uses -- header cp NOT trimming ground C
for f in cd_teredo cd_gtp cd_geneve; do
    cp "$SRC"/src/codecs/misc/$f.cc "$C"/codecs/misc/
    cmp -s "$C"/codecs/misc/$f.cc "$SRC"/src/codecs/misc/$f.cc
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 84   # 81 ext + 3 row (pre-fresh-cp face)

# ---- E4 WALLS (PLAN 3): flipped-assert EVERY build. Pre-cp face = the tree
# WITHOUT the two fresh header cps (asserted absent): ----
test ! -e "$C"/protocols/teredo.h
test ! -e "$C"/packet_io/active.h
GXX0="g++ -std=c++17 -O0 -w -I$C"
if $GXX0 -c "$C"/codecs/misc/cd_teredo.cc -o /dev/null 2> "$H/E4_cd_teredo.txt"; then
    echo "E4 face flip BROKE: cd_teredo compiled WITHOUT protocols/teredo.h"; exit 1
fi
head -1 "$H/E4_cd_teredo.txt" | grep -q "fatal error: protocols/teredo.h: No such file"
if $GXX0 -c "$C"/codecs/misc/cd_geneve.cc -o /dev/null 2> "$H/E4_cd_geneve.txt"; then
    echo "E4 face flip BROKE: cd_geneve compiled WITHOUT packet_io/active.h"; exit 1
fi
head -1 "$H/E4_cd_geneve.txt" | grep -q "fatal error: packet_io/active.h: No such file"
$GXX0 -c "$C"/codecs/misc/cd_gtp.cc -o /dev/null 2> "$H/E4_cd_gtp.txt"   # MUST pass
test ! -s "$H/E4_cd_gtp.txt"                                             # gtp needs ZERO fresh cps
# ---- the TWO fresh header cps (PLAN 2 delta; byte pins): close ALL .o ----
test "$(md5sum "$SRC"/src/protocols/teredo.h | awk '{print $1}')" = "b7adb3d85e5f7dccccbf427ff119f6f5"
test "$(wc -l < "$SRC"/src/protocols/teredo.h)" -eq 44
test "$(md5sum "$SRC"/src/packet_io/active.h | awk '{print $1}')" = "ce6085794642721562df16740895a08a"
test "$(wc -l < "$SRC"/src/packet_io/active.h)" -eq 240
cp "$SRC"/src/protocols/teredo.h "$C"/protocols/
cp "$SRC"/src/packet_io/active.h "$C"/packet_io/
cmp -s "$C"/protocols/teredo.h "$SRC"/src/protocols/teredo.h
cmp -s "$C"/packet_io/active.h "$SRC"/src/packet_io/active.h
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 86   # 81 ext donor + 3 row + 2 header
# post-cp face: rc=0 x3 empty (2 FRESH cps CLOSE all .o -- scratch E4b face):
GXX="g++ -std=c++17 -O0 -w -I$C"
for f in cd_teredo cd_gtp cd_geneve; do
    $GXX -c "$C"/codecs/misc/$f.cc -o "$C/$f.o" 2> "$H/E4b_$f.txt"
    test ! -s "$H/E4b_$f.txt"
done
# CppUTest box-dead (every ground misc/test suite vs copy face MUST die at the
# CppUTest include -- the wall the 18b/18e receipts also print):
: > "$H/E4_cpputest_fatal.txt"
cpputest_dead=0
for f in teredo gtp geneve; do
    if ! g++ -std=c++17 -O0 -w -I"$C" -I"$C"/codecs/misc -fsyntax-only "$SRC"/src/codecs/misc/test/${f}_codec_test.cc 2>> "$H/E4_cpputest_fatal.txt"; then
        grep -q 'CppUTest/CommandLineTestRunner.h: No such file' "$H/E4_cpputest_fatal.txt" && cpputest_dead=$((cpputest_dead+1))
    fi
done
test "$cpputest_dead" -eq 3

# ---- witness face: donor witness_conf regenerated BYTE-IDENT (md5 below) ----
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

#include "log/messages.h"
#include "main/thread_config.h"
#include <cstdarg>
#include <cstdio>
namespace snort {

void FatalError(const char* f, ...) { va_list a; va_start(a,f); vfprintf(stderr,f,a); va_end(a); fputc('\n',stderr); (void)0; }

THREAD_LOCAL int thread_instance = 0;
unsigned get_instance_id() { return thread_instance; }
unsigned ThreadConfig::get_instance_max() { return 1; }
SThreadType get_thread_type() { return STHREAD_TYPE_MAIN; }
}

#include "utils/stats.h"
#include <string>
void show_stats(const PegCount*, const PegInfo*, unsigned, const char*) {}
void show_stats(const PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) {}
namespace snort {
const char* get_main_file(std::string& s, const char*) { return s.c_str(); }
const char* get_instance_file(std::string& s, const char*) { return s.c_str(); }
}
#include "protocols/eth.h"
namespace snort {
void LogEthAddrs(TextLog* log, const eth::EtherHdr* eh) { (void)log; (void)eh; }  // witness stand-in (log_text.cc:112 REAL body pulls the Packet/appid world)
}
EOFWC
test "$(md5sum "$H"/witness_conf.cc | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"
# ONE-new-witness guard (PLAN 4): nm census -- EXACTLY the tunnel_bypass U-line
# is resolved by witness_18f.o; witness_18f.cc defines EXACTLY that one SnortConfig
# member (never the conf ctor/dtor/statics -- donor witness_conf owns those):
test "$(grep -c 'SnortConfig::tunnel_bypass_enabled' "$H"/witness_18f.cc)" -ge 1
test "$(grep -c 'SnortConfig::SnortConfig\|SnortConfig::~' "$H"/witness_18f.cc || true)" -eq 0
# the 3 masks grep-asserted from ground enum (never typed from memory):
test "$(sed -n '119,120p' "$SRC"/src/main/snort_config.h)" = $'    TUNNEL_GTP    = 0x01,\n    TUNNEL_TEREDO = 0x02,'
grep -q 'TUNNEL_GENEVE = 0x200' "$SRC"/src/main/snort_config.h
# ground call sites (mask arms cite-anchored):
test "$(sed -n '106p' "$SRC"/src/codecs/misc/cd_teredo.cc)" = '        if ( codec.conf->tunnel_bypass_enabled(TUNNEL_TEREDO) )'
test "$(sed -n '177p' "$SRC"/src/codecs/misc/cd_gtp.cc)"    = '    if ( codec.conf->tunnel_bypass_enabled(TUNNEL_GTP) )'
test "$(sed -n '166p' "$SRC"/src/codecs/misc/cd_geneve.cc)" = '    if ( codec.conf->tunnel_bypass_enabled(TUNNEL_GENEVE) )'
# ground def anchor (the witness mirrors its shape):
test "$(sed -n '1022p' "$SRC"/src/main/snort_config.cc)" = '    return !((tunnel_mask & proto) or SFDAQ::get_tunnel_bypass(proto));'
# trackable pins (stageables EXACTLY 7 per PLAN 9):
test "$(md5sum "$H"/probe.cc | awk '{print $1}')"      = "5b8355189caa2d8b1a12913f94c3838d"
test "$(md5sum "$H"/probe_dec.cc | awk '{print $1}')"  = "99a8257cd470c33be8a4135eb45e547a"
test "$(md5sum "$H"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(wc -l < "$H"/vectors.txt)" -eq 40          # DEC face MEASURED
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 7     # FACE-A MEASURED
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "2a7924796f8f0cfdca5e665dee28f519"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "81602890210d8d83068397c2cece1241"

# ---- E1 compile: 3 row + donor REAL-cp .o's fresh THIS pass + probes ----
GXXA="g++ -std=c++17 -O2 -w -I$C"
ROW="$C/codecs/misc/cd_teredo.cc $C/codecs/misc/cd_gtp.cc $C/codecs/misc/cd_geneve.cc"
REAL="$C/framework/codec.cc $C/protocols/ip.cc $C/sfip/sf_ip.cc $C/utils/util_cstring.cc $C/utils/util.cc $C/log/text_log.cc $C/framework/module.cc"
for f in $ROW $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$H"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc -o "$H"/stubs_18d.o

# ---- donor fingerprint grep (5-frozen-donor diff-0 census, PLAN 9): the ext
# face itself stays undisturbed -- ext row md5s re-read by the session ritual;
# here: vocab witness_stubs + vocab vectors + codec stubs + eth stubs_18d:----
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/vectors.txt | awk '{print $1}')"     = "5da70e82416b6f769af8177d859331e7"
test "$(md5sum /opt/data/snort3-rust/tools/codec_harness/stubs.cc | awk '{print $1}')"        = "be9bdd0b437d1f6c56c841e8155d9e70"
test "$(md5sum "$ETH"/stubs_18d.cc | awk '{print $1}')"                                       = "f4afd35f06bc45ce5aa0ec12110ed8ae"
test "$(md5sum /opt/data/snort3-rust/tools/ext_harness/witness_conf.cc | awk '{print $1}')"   = "4dd91018f8439d706ba666c6f18c9152"

# ---- E2 per-TU nm U-census (receipts; counts MEASURED 10/24/42; every TU
# carries EXACTLY 1 tunnel_bypass U-line -- the witness census, PLAN 6) ----
for t in cd_teredo cd_gtp cd_geneve; do
    nm -C -u "$C"/"$t".o | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H"/nm_U_"$t".txt
done
test "$(wc -l < "$H"/nm_U_cd_teredo.txt)" -eq 10
test "$(wc -l < "$H"/nm_U_cd_gtp.txt)"   -eq 24
test "$(wc -l < "$H"/nm_U_cd_geneve.txt)" -eq 42
for t in cd_teredo cd_gtp cd_geneve; do
    test "$(grep -c 'SnortConfig::tunnel_bypass_enabled' "$H"/nm_U_$t.txt)" -eq 1
done
# codec_event asymmetry (measured): teredo decode emits NO events -> ZERO
# codec_event U-lines; gtp + geneve carry exactly 1 each:
test "$(grep -c 'Codec::codec_event' "$H"/nm_U_cd_teredo.txt || true)" -eq 0
for t in cd_gtp cd_geneve; do
    test "$(grep -c 'Codec::codec_event' "$H"/nm_U_$t.txt)" -eq 1
done
grep -q 'TextLog_Print' "$H"/nm_U_cd_geneve.txt            # geneve U-dumps TextLog_Print -- donor text_log.o T face (ZERO witness)
grep -q 'Module::Module' "$H"/nm_U_cd_geneve.txt
grep -q 'Module::Module' "$H"/nm_U_cd_gtp.txt
test "$(grep -c 'Module::Module' "$H"/nm_U_cd_teredo.txt || true)" -eq 0   # teredo NO module (mod_ctor null face)
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
w=$(nm -C --defined-only "$H"/witness_18f.o)
grep -q 'T snort::SnortConfig::tunnel_bypass_enabled' <<< "$w"
grep -q 'T tun_witness_set_mask' <<< "$w"
# the ONE-witness census: the three row .o's' tunnel_bypass U-lines are the
# ONLY ones across the link -- probes/stubs/witness_conf ask NONE:
test "$(nm -C -u "$H"/probe.o "$H"/probe_dec.o "$H"/witness_conf.o "$H"/stubs_18d.o | grep -c 'tunnel_bypass' || true)" -eq 0
# probe link pulls NO codec_api object (FACE rule inherited, nm guard):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool [a-z][a-z0-9]*=.*->decode' "$H"/probe_dec.cc)" -ge 10
test "$(grep -c 'printf.*->decode' "$H"/probe_dec.cc || true)" -eq 0

# ---- E5: link + run FACE-A and DEC at O0 AND O2; BYTE-IDENT pins ----
OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS_O="$C/cd_teredo.o $C/cd_gtp.o $C/cd_geneve.o"
$GXX $OBJS $ROWS_O "$H"/probe.o "$H"/witness_18f.o "$H"/witness_conf.o "$H"/stubs_18d.o -o "$H"/probe
$GXX $OBJS $ROWS_O "$H"/probe_dec.o "$H"/witness_18f.o "$H"/witness_conf.o "$H"/stubs_18d.o -o "$H"/probe_dec
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in $ROW $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2/probe.o"; $GXXA -c "$H"/probe_dec.cc -o "$O2/probe_dec.o"
$GXXA -c "$H"/witness_18f.cc -o "$O2/witness_18f.o"; $GXXA -c "$H"/witness_conf.cc -o "$O2/witness_conf.o"
$GXXA -c "$ETH"/stubs_18d.cc -o "$O2/stubs_18d.o"
OB2=$(for b in cd_teredo cd_gtp cd_geneve codec ip sf_ip util_cstring util module text_log; do printf '%s ' "$O2/$b.o"; done)
$GXXA $OB2 "$O2"/probe.o "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o -o "$H"/probe_dec_O2
timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }
test "$(grep -c '0x' "$H"/vectors.txt || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_faceA.txt || true)" -eq 0

# ---- known-answer ladders (arms BYTE-PINNED by the cmps; greps pin the
# decomposition against GROUND anchors, NEVER a forecast -- 17p) ----
test "$(sed -n '128,129p' "$SRC"/src/protocols/protocol_ids.h)" = $'    TEREDO = 0x0101,\n    GTP = 0x0102,'
grep -q 'GENEVE = 0x0109,' "$SRC"/src/protocols/protocol_ids.h
grep -q 'DECODE_GENEVE_DGRAM_LT_GENEVE_HDR = 180' "$SRC"/src/codecs/codec_module.h
grep -q 'DECODE_GTP_MULTIPLE_ENCAPSULATION = 297' "$SRC"/src/codecs/codec_module.h
grep -q 'DECODE_GTP_BAD_LEN = 298' "$SRC"/src/codecs/codec_module.h
# Rust-side enum ALREADY landed (18f NEVER re-walks):
grep -q 'DECODE_GENEVE_DGRAM_LT_GENEVE_HDR = 180' /opt/data/snort3-rust/src/codecs/codec_module.rs
grep -q 'DECODE_GTP_MULTIPLE_ENCAPSULATION = 297' /opt/data/snort3-rust/src/codecs/codec_module.rs
# face-A arms measured:
grep -q '^LOADS 3$' "$H"/vectors_faceA.txt
test "$(grep -c '^LOAD ' "$H"/vectors_faceA.txt)" -eq 3
grep -q '^API geneve type=0 size=112 ver=1900547 name=geneve$' "$H"/vectors_faceA.txt
grep -q '^API gtp mod_ctor=1$' "$H"/vectors_faceA.txt
grep -q '^API teredo mod_ctor=0$' "$H"/vectors_faceA.txt     # honest asymmetry arm
# CDAPI carry = 1900547 face inherited (PLAN 3):
test "$(grep -c '^API .* size=112 ver=1900547' "$H"/vectors.txt)" -eq 3
# teredo arms (cd_teredo.cc cites above): mask flip = the ONE witness observable
grep -q '^TER mask0000 -> 1 bypass=1$' "$H"/vectors.txt                 # ground tunnel_mask=0 face
grep -q '^TER mask0002 -> 1 bypass=0 lyr=8 next=41 bits=128 flags=646$' "$H"/vectors.txt
grep -q '^TERPID 257 n=1$' "$H"/vectors.txt
# gtp arms + EV family:
grep -q '^GTP v1-ok mask0001 -> 1 bypass=0 lyr=8 bits=256$' "$H"/vectors.txt
test "$(grep -c '^EV 116 298$' "$H"/vectors.txt)" -eq 2   # v0-shord + v1-badlen (measured face)
grep -q '^EV 116 297$' "$H"/vectors.txt
grep -q '^GTPPID 258 n=1$' "$H"/vectors.txt
grep -q '^GTP rules=2 sid0=297 name=gtp$' "$H"/vectors.txt
# geneve arms:
grep -q '^EV 116 180$' "$H"/vectors.txt
grep -q '^EV 116 181$' "$H"/vectors.txt
grep -q '^EV 116 184$' "$H"/vectors.txt
grep -q '^GEN mask0200 -> 1 bypass=0 lyr=8 next=0 bits=2097152$' "$H"/vectors.txt
grep -q '^GEN mask0000 -> 1 bypass=1$' "$H"/vectors.txt    # ground default face
grep -q '^GEN rules=5 sid0=180 name=geneve$' "$H"/vectors.txt
grep -q '^GENPID 265 n=1$' "$H"/vectors.txt
grep -q '^TER mod_ctor=0 mod_dtor=0$' "$H"/vectors.txt
# proto_bits literals grounding (never typed from air):
grep -q '#define PROTO_BIT__TEREDO           0x000080' "$SRC"/src/framework/decode_data.h
grep -q '#define PROTO_BIT__GTP              0x000100' "$SRC"/src/framework/decode_data.h
grep -q '#define PROTO_BIT__GENEVE           0x200000' "$SRC"/src/framework/decode_data.h

# ---- gate-lineage receipts (PLAN 8: the 14th-straight argument, ZERO-EDIT) ----
FM=/opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" "$FM"
grep -q "4826fc2233044a2d5429413faf0ae1af" "$FM"
test "$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 24
test ! -e "$H"/gate.txt
test " $(find "$H" -maxdepth 1 -name 'gate*' | wc -l) " = " 0 "

echo "row-TU nm census: teredo=$(wc -l < "$H/nm_U_cd_teredo.txt") gtp=$(wc -l < "$H/nm_U_cd_gtp.txt") geneve=$(wc -l < "$H/nm_U_cd_geneve.txt") (tunnel_bypass U-line x3; witnesses: ONE new (witness_18f) + donor text_log/module resolve)"
echo "E4 walls: pre-cp teredo/geneve MUST-fail + gtp MUST-pass + post-cp rc0x3 + CppUTest dead x$(grep -c 'fatal error' "$H"/E4_cpputest_fatal.txt || true) face flipped-assert"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "vectors md5: $(md5sum "$H/vectors.txt") faceA: $(md5sum "$H/vectors_faceA.txt")"
echo "gate census holders: $(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')/24 (tun harness gate.txt count 0)"
echo "TUN_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt") faceA=$(wc -l < "$H/vectors_faceA.txt")"
