#!/usr/bin/env bash
# small4_harness -- row 18h: the ip SMALL FOUR: codecs/ip/cd_esp.cc 227 L +
# cd_frag.cc 190 L + cd_pgm.cc 211 L + cd_auth.cc 172 L = 800 L total.
# ZERO-GATE row (18b-18g corollary): the four TUs ship NO embedded suite
# (combined gate grep 0 x4, re-asserted EVERY build below) -> probe-only,
# NO gate.txt, NO catch_main, NO -DUNIT_TEST faces, NO E9 face (no UT .o
# exists to collide; the one-symbol-per-.o face is still census-asserted).
# Copy tree: gre DONOR VERBATIM (92 find-count, the live face the 18g docs
# pass recorded honestly) + EXACTLY 4 row cps + ZERO fresh cps (PROVEN
# per-file: the E4 stripped-tree flipped-asserts -- drop checksum.h -> ONLY
# pgm dies; drop log/text_log.h -> ONLY frag dies; every other include
# resolves in the donor face -- NEXT :389 "(b) ZERO fresh cps" CONFIRMED).
# THE HEADLINE: name drift. File cd_auth.cc -> TABLE cd_ah (auth :166),
# extern cd_ah codec_api.cc :40 + load :85, ladder "cd_ah" codec_api.rs :98,
# but the NAME string is "auth" (CD_AUTH_NAME :30) and the api struct is
# ah_api :141. Second drift rider: cd_frag table ok but api ipv6_frag_api
# :159 + name "ipv6_frag" :31. Every tripwire greps the TABLE name cd_ah,
# NEVER the file base cd_auth (grep 'extern const BaseApi\* cd_auth\b'
# whole-src = 0 hits -- asserted below EVERY build).
# WITNESS: EXACTLY ZERO new -- tunnel_bypass U-census 0/0/0/0 measured; the
# WIN trio (witness_18f / witness_conf / stubs_18d) rides inherited; md5
# pins NEVER re-derived. Probe pulls NO codec_api object (ext/tun rule).
# Census ritual (two-lineage face): the 25-gate.txt loop lives HERE too and
# MEASURES, never types; the row adds ZERO gate.txt so the face is
# UNDISTURBED -- the script even asserts NO gate artifact of its own.
# Vectors NEVER typed (17p): the first run MEASURES + seeds the tracked
# faces; every later build DRIFTS-then-refuses, md5+wc pinned from the
# first measured run, O0==O2 byte-ident every build.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
GRE=/opt/data/snort3-rust/tools/gre_harness
TUN=/opt/data/snort3-rust/tools/tun_harness
ETH=/opt/data/snort3-rust/tools/eth_harness
FM=/opt/data/snort3-rust/tools/fmod_harness
C=$H/copy

# ---- ground identity (four row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [cd_esp.cc]=d9a20eae70244e652c54fc4c0281f7bd [cd_frag.cc]=2832f4fdf4bb93a88507c354049d4a47 \
                 [cd_pgm.cc]=6b476f5cec30acdfc6fe172bed53b657 [cd_auth.cc]=e9ce9351beeee3b7cedab63e6cede6c0 )
declare -A WC=( [cd_esp.cc]=227 [cd_frag.cc]=190 [cd_pgm.cc]=211 [cd_auth.cc]=172 )
for f in cd_esp.cc cd_frag.cc cd_pgm.cc cd_auth.cc; do
    test "$(md5sum "$SRC/src/codecs/ip/$f" | awk '{print $1}')" = "${MD5[$f]}"
    test "$(wc -l < "$SRC/src/codecs/ip/$f")" -eq "${WC[$f]}"
done
# combined gate grep ZERO x4 EVERY build (if ground ever ships a suite here
# the row is RE-PLANNED to the gre gate shape -- R1 face, flip trips loudly)
for f in cd_esp.cc cd_frag.cc cd_pgm.cc cd_auth.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST' "$SRC/src/codecs/ip/$f" || true)" -eq 0
done

# ---- TABLE face REAL x4 (BUILDING_SO arms; the table-name sed census --
# tripwire rule 18g: grep the TABLE names, NEVER the file base) ----
test "$(sed -n '218p' "$SRC/src/codecs/ip/cd_esp.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '221p' "$SRC/src/codecs/ip/cd_esp.cc")" = "const BaseApi* cd_esp[] ="
test "$(sed -n '181p' "$SRC/src/codecs/ip/cd_frag.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '184p' "$SRC/src/codecs/ip/cd_frag.cc")" = "const BaseApi* cd_frag[] ="
test "$(sed -n '203p' "$SRC/src/codecs/ip/cd_pgm.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '206p' "$SRC/src/codecs/ip/cd_pgm.cc")" = "const BaseApi* cd_pgm[] ="
test "$(sed -n '163p' "$SRC/src/codecs/ip/cd_auth.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '166p' "$SRC/src/codecs/ip/cd_auth.cc")" = "const BaseApi* cd_ah[] ="   # THE DRIFT FACE

# ---- NAME-DRIFT tripwires (HEADLINE, cite-pinned EVERY build) ----
# externs (ground codec_api.cc): cd_ah :40 + load :85 (NEVER 'cd_auth')
test "$(sed -n '40p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_ah[];"
test "$(sed -n '85p' "$SRC/src/codecs/codec_api.cc")" = "    PluginManager::load_plugins(cd_ah);"
test "$(sed -n '47p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_esp[];"
test "$(sed -n '92p' "$SRC/src/codecs/codec_api.cc")" = "    PluginManager::load_plugins(cd_esp);"
test "$(sed -n '50p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_frag[];"
test "$(sed -n '95p' "$SRC/src/codecs/codec_api.cc")" = "    PluginManager::load_plugins(cd_frag);"
test "$(sed -n '63p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_pgm[];"
test "$(sed -n '108p' "$SRC/src/codecs/codec_api.cc")" = "    PluginManager::load_plugins(cd_pgm);"
# THE drift tripwire: NO extern NAMED cd_auth EXISTS anywhere (rc 1 -> 0 hits)
if grep -rn 'extern const BaseApi\* cd_auth\b' "$SRC/src/" > "$H/drift_cd_auth_extern.txt" 2>/dev/null; then
    echo "DRIFT FACE DEAD: an extern named cd_auth exists -- 18g correction is wrong"; exit 1
fi
test ! -s "$H/drift_cd_auth_extern.txt"
# inside-file drift riders: api struct ah_api :141 + module name "auth" :30
test "$(sed -n '141p' "$SRC/src/codecs/ip/cd_auth.cc")" = "static const CodecApi ah_api ="
test "$(sed -n '30p'  "$SRC/src/codecs/ip/cd_auth.cc")" = '#define CD_AUTH_NAME "auth"'
# frag rider: file==table BUT api/name diverge: ipv6_frag_api :159 + name :31
test "$(sed -n '159p' "$SRC/src/codecs/ip/cd_frag.cc")" = "static const CodecApi ipv6_frag_api ="
test "$(sed -n '31p'  "$SRC/src/codecs/ip/cd_frag.cc")" = '#define CD_IPV6_FRAG_NAME "ipv6_frag"'
# the ladder face (rows ADD TUs, NEVER touch codec_api.rs): resident names
test "$(sed -n '98p'  /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_ah",'
test "$(sed -n '105p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_esp",'
test "$(sed -n '108p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_frag",'
test "$(sed -n '121p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_pgm",'
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern cc census
# landmine posture ZERO (18e rule): no 18h name frozen in ANY witness donor
for n in cd_ah cd_esp cd_frag cd_pgm cd_udp cd_icmp4 cd_icmp6; do
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc || true)" -eq 0
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/codec_harness/stubs.cc || true)" -eq 0
done
# sids resident x8 (ground enum h:-cites + Rust landed -- ZERO new)
for pair in "DECODE_IPV6_TRUNCATED_EXT 272" "DECODE_ESP_HEADER_TRUNC 294" \
            "DECODE_PGM_NAK_OVERFLOW 454" "DECODE_IP6_EXCESS_EXT_HDR 456" \
            "DECODE_IPV6_BAD_FRAG_PKT 458" "DECODE_ZERO_LENGTH_FRAG 459" \
            "DECODE_AUTH_HDR_TRUNC 465" "DECODE_AUTH_HDR_BAD_LEN 466"; do
    set -- $pair
    # ground enum: 123/:147 carry EXPLICIT = face; the 454-466 run is
    # ordinal in ground (land-rule h:-cites pin the walk) -- the VALUES are
    # pinned on the landed Rust face, the WALK cites tie it to ground:
    if grep -q "$1 = $2," "$SRC/src/codecs/codec_module.h"; then :; else
        grep -qE "^    $1,$" "$SRC/src/codecs/codec_module.h"        # ordinal enum member face
    fi
    grep -q "$1 = $2,  // h:" /opt/data/snort3-rust/src/codecs/codec_module.rs
done
# ground identity re-pin (seed @ fe29cbe7403 -- ground READ-ONLY, untouched)
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- copy tree = gre DONOR VERBATIM + 4 row cps + ZERO fresh cps --------
test -e "$GRE/copy/config.h" || { echo "gre donor missing -- run gre_harness first"; exit 1; }
rm -rf "$C"; cp -a "$GRE/copy" "$C"
find "$C" -name '*.o' -delete
# donor VERBATIM 92 (the 18g-acknowledged live find-count; the cd_gre* row
# sources + catch pair ride as inert ballast -- no Catch TU compiled HERE;
# ZERO-gate row). MEASURED assert, NEVER pre-typed (17p):
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 92
for f in cd_esp.cc cd_frag.cc cd_pgm.cc cd_auth.cc; do
    test ! -e "$C/codecs/ip/$f"                                   # fresh-landing face
    cp "$SRC/src/codecs/ip/$f" "$C/codecs/ip/$f"
    cmp -s "$C/codecs/ip/$f" "$SRC/src/codecs/ip/$f"
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 96   # 92 + 4 row cps + ZERO fresh
test -e "$C/codecs/ip/checksum.h"            # residency: gre paid it (pgm rides)
test -e "$C/log/text_log.h"                  # residency: tun lineage paid it (frag rides)
test "$(md5sum "$C/codecs/ip/checksum.h" | awk '{print $1}')" = "b43628f369e16b1d5c093ff447d3e954"
test "$(md5sum "$C/log/text_log.h"         | awk '{print $1}')" = "3e82711324beec67648a13d8b02a8c0c"
test "$(md5sum "$C/codecs/codec_module.h"  | awk '{print $1}')" = "3f3bd92752ba46b8732f831724d3b279"
test "$(md5sum "$C/framework/codec.h"      | awk '{print $1}')" = "32da89f1a204410825f750739c146410"
test "$(md5sum "$C/main/snort_config.h"    | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probe pulls NO codec_api)
test ! -e "$C/codecs/codec_api.cc"

# ---- E4 adaptation (PLAN 2/8): ZERO fresh cps -> residency PROVEN by
# STRIPPED-TREE flipped-asserts IN the build, one-shot receipts (permanent
# stripped face would fight the residency pins; a live strip here can ONLY
# mean donor drift -> the loud rc=1 wall below is the face). ----
GXX0="g++ -std=c++17 -O0 -w -I$C"
mv "$C/codecs/ip/checksum.h" "$H/.e4_hold_checksum.h"
for f in cd_esp cd_frag cd_auth; do
    $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" 2> "$H/E4_nochecksum_$f.txt"   # others MUST live
    test ! -s "$H/E4_nochecksum_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_pgm.cc" -o /dev/null 2> "$H/E4_nochecksum_pgm.txt"; then
    echo "E4 flip BROKE: cd_pgm compiled WITHOUT checksum.h -- residency face dead"; exit 1
fi
head -1 "$H/E4_nochecksum_pgm.txt" | grep -q "fatal error: checksum.h: No such file"   # cc:28 same-dir
mv "$H/.e4_hold_checksum.h" "$C/codecs/ip/checksum.h"
mv "$C/log/text_log.h" "$H/.e4_hold_text_log.h"
for f in cd_esp cd_pgm cd_auth; do
    $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" 2> "$H/E4_notextlog_$f.txt"
    test ! -s "$H/E4_notextlog_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_frag.cc" -o /dev/null 2> "$H/E4_notextlog_frag.txt"; then
    echo "E4 flip BROKE: cd_frag compiled WITHOUT log/text_log.h -- residency face dead"; exit 1
fi
head -1 "$H/E4_notextlog_frag.txt" | grep -q "fatal error: log/text_log.h: No such file"   # cc:26
mv "$H/.e4_hold_text_log.h" "$C/log/text_log.h"
for f in cd_esp cd_frag cd_pgm cd_auth; do   # restored full tree: rc 0 EVERY build
    $GXX0 -c "$C/codecs/ip/$f.cc" -o "$C/$f.precheck.o" 2> "$H/E4_$f.txt"
    test ! -s "$H/E4_$f.txt"
    rm -f "$C/$f.precheck.o"
done

# ---- witness carry (ZERO new, PLAN 6): md5 pins NEVER re-derived --------
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
cat > "$H/witness_conf.cc" <<'EOFWC'
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
test "$(md5sum "$H/witness_conf.cc" | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"

GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
REAL="$C/framework/codec.cc $C/protocols/ip.cc $C/sfip/sf_ip.cc $C/utils/util_cstring.cc $C/utils/util.cc $C/log/text_log.cc $C/framework/module.cc"

# ---- O0 compile: FOUR plain .o + donor REAL .o + probes -----------------
for f in cd_esp cd_frag cd_pgm cd_auth; do $GXX -c "$C/codecs/ip/$f.cc" -o "$C/$f.o"; done
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/cd_esp.o $C/cd_frag.o $C/cd_pgm.o $C/cd_auth.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# one-symbol-per-.o face (E9 trivially holds -- no UT .o exists to collide;
# each plain .o defines EXACTLY ONE table symbol, scratch R5 face):
for pair in "cd_esp cd_esp" "cd_frag cd_frag" "cd_pgm cd_pgm" "cd_auth cd_ah"; do
    set -- $pair
    test "$(nm --defined-only "$C/$1.o" | grep -cE ' [DdRr] cd_[a-z]+$')" -eq 1
    nm --defined-only "$C/$1.o" | grep -qE " [DdRr] $2\$"
done

# ---- nm per-TU U-census (receipts; counts MEASURED, NEVER typed) --------
for f in cd_esp cd_frag cd_pgm cd_auth; do
    nm -C -u "$C/$f.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$f.txt"
    test "$(grep -c 'tunnel_bypass' "$H/nm_U_$f.txt" || true)" -eq 0     # 0/0/0/0 face (contrast gre 1): ZERO new witness
done
cat "$H"/nm_U_cd_*.txt | sort -u > "$H/nm_U_union.txt"
# residue class (MANGLED face = robust): every snort-family U symbol of the
# four row .o MUST be defined by OBJS+WIN (snort-family residue ZERO -- an
# unresolved snort symbol means cp drift -> die loud; the rest of the union
# is libc/gcc-run-time family, scratch R5 face).
g4=""; for f in cd_esp cd_frag cd_pgm cd_auth; do g4="$g4 $C/$f.o"; done
nm -u $g4 | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
donordefs=$(nm --defined-only $OBJS $WIN | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*)
        grep -qxF "$u" <<< "$donordefs" || { echo "SNORT RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0

# ---- real-symbol defines (donor face, gre-recipe) -----------------------
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
grep -q 'T snort::Codec::CheckIPv6ExtensionOrder' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
grep -q 'T tun_witness_set_mask' <<< "$(nm -C --defined-only "$H"/witness_18f.o)"

# ---- probe links (ZERO new witness -- WIN trio INHERITED) ---------------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE here

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in cd_esp cd_frag cd_pgm cd_auth; do $GXXA -c "$C/codecs/ip/$f.cc" -o "$O2/$f.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc -o "$O2"/stubs_18d.o
OB2=""; for f in cd_esp cd_frag cd_pgm cd_auth; do OB2="$OB2 $O2/$f.o"; done
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool [a-z][a-z0-9]*=.*->decode' "$H"/probe_dec.cc)" -ge 12
test "$(grep -c 'printf.*->decode' "$H"/probe_dec.cc || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_O0.txt || true)" -eq 0    # all-decimal hygiene
test "$(grep -c '0x' "$H"/vectors_faceA_O0.txt || true)" -eq 0

# ---- known-answer ladders: greps pin the MEASURED faces against GROUND
# anchors (17p; decomposition greps read the GROUND lines, NEVER a value
# typed from air). First run seeds the tracked faces; later runs cmp above. ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi
# FACE-A drift face through the walk: LOAD/LADDER names = ground NAME macros:
grep -q '^LOAD esp$'      "$FA"     # CD_ESP_NAME :31
grep -q '^LOAD ipv6_frag$' "$FA"    # CD_IPV6_FRAG_NAME :31 (drift rider)
grep -q '^LOAD pgm$'      "$FA"     # CD_PGM_NAME :34
grep -q '^LOAD auth$'     "$FA"     # CD_AUTH_NAME :30 -- link symbol cd_ah, NAME auth
grep -q '^LOADS 4$'       "$FA"
grep -q '^API ah type=0 size=112 ver=1900547 name=auth$' "$FA"   # table cd_ah prints NAME auth (CDAPI carry inherited)
# mod_ctor asymmetry 1/0/1/1 (frag api :166-:167 nullptr face -- R2 pin):
grep -q '^esp mod_ctor=1 mod_dtor=1$'   "$FA"
grep -q '^frag mod_ctor=0 mod_dtor=0$'  "$FA"
grep -q '^pgm mod_ctor=1 mod_dtor=1$'   "$FA"
grep -q '^ah mod_ctor=1 mod_dtor=1$'    "$FA"
# HELP arms ride the ground #defines (never typed from air -- sed cites):
test "$(sed -n '32p'  "$SRC/src/codecs/ip/cd_esp.cc")"  = '#define CD_ESP_HELP "support for encapsulating security payload"'
test "$(sed -n '35p'  "$SRC/src/codecs/ip/cd_pgm.cc")"  = '#define CD_PGM_HELP "support for pragmatic general multicast"'
test "$(sed -n '31p'  "$SRC/src/codecs/ip/cd_auth.cc")" = '#define CD_AUTH_HELP "support for IP authentication header"'
grep -q '^HELP esp support for encapsulating security payload$' "$FA"
grep -q '^HELP ah support for IP authentication header$'        "$FA"
# DEC ladders (event sites sed-pinned in the ground block below):
test "$(sed -n '79p'  "$SRC/src/codecs/ip/cd_esp.cc")"  = "constexpr uint32_t ESP_HEADER_LEN = 8;"     # 8+12+2 = 22 gate
test "$(sed -n '32p'  "$SRC/src/codecs/ipv6.h" 2>/dev/null || sed -n '32p' "$SRC/src/protocols/ipv6.h")" = "constexpr uint32_t MIN_EXT_LEN = 8;"
test "$(sed -n '79p'  "$SRC/src/codecs/ip/cd_auth.cc" | cut -c1-36)" = "constexpr uint8_t MIN_AUTH_LEN = 16;"
# frag offlg accessors (the MF/off arms ride BE ntohs off these bytes):
test "$(sed -n '217p' "$SRC/src/protocols/ipv6.h")" = "    { return ntohs(ip6f_offlg) & IP6F_MF_MASK; }"
test "$(sed -n '205p' "$SRC/src/protocols/ipv6.h")" = "constexpr uint16_t IP6F_MF_MASK = 0x0001; /* more-fragments flag */" || grep -q 'IP6F_MF_MASK = 0x0001;' "$SRC/src/protocols/ipv6.h"
grep -q '^ESP short21 -> 0$' "$V"      # cc:108 EV 294 face (raw.len < 22)
grep -q '^EV 116 294$'       "$V"
test "$(grep -c '^EV 116 456$' "$V")" -eq 3     # one per ip6-guard site esp cc:131 + frag cc:60 + auth cc:113
grep -q '^FRAG short7 -> 0$' "$V"              # cc:54
grep -q '^EV 116 272$'       "$V"
grep -q '^FRAG zero8 -> 1'   "$V"              # cc:69 no-return face
test "$(grep -c '^EV 116 459$' "$V")" -eq 2     # ZERO_LENGTH_FRAG arms: zero8 + ooo2 (no return, cc:69)
test "$(grep -c '^EV 116 458$' "$V")" -eq 2     # cc:91 pair face (off==0 no-MF)
test "$(grep -c '^EV 116 296$' "$V")" -eq 3     # ORDER face x3: esp cc:135 + frag cc:111 2nd-call + auth cc:117 (codec.cc:178; frag = most arm-dense ordering face, two order calls :102/:111)
grep -q '^PGM len44 -> 1$'   "$V"              # pgm decode ALWAYS true
test "$( grep -c '^EV 116 454$' "$V")" -eq 1    # the ONLY pgm event site cc:156
grep -q '^PGM cksum-guard -> 1$' "$V"          # cc:139-:140 cheap-guard: NO EV for this arm
grep -q '^AH short15 -> 0$'  "$V"              # cc:92
test "$(grep -c '^EV 116 465$' "$V")" -eq 1
grep -q '^AH badlen -> 0$'   "$V"              # cc:102
test "$(grep -c '^EV 116 466$' "$V")" -eq 1
# PID census arms off the ground protocol_ids.h (never air):
grep -q '^    ESP = 50,$'  "$SRC/src/protocols/protocol_ids.h"
grep -q '^    AUTH = 51, // RFC 4302$' "$SRC/src/protocols/protocol_ids.h"
grep -q '^    PGM = 113,$' "$SRC/src/protocols/protocol_ids.h"
grep -q '^ESPPID 50 n=1$'  "$V"
grep -q '^FRAGPID 44 n=1$' "$V"
grep -q '^PGMPID 113 n=1$' "$V"
grep -q '^AHPID 51 n=1$'   "$V"
# RuleMap census (ground table rows -- static internals stay UN-exported, R3):
test "$(grep -cE '^\s+\{ DECODE_' "$SRC/src/codecs/ip/cd_esp.cc")" -eq 1
test "$(grep -cE '^\s+\{ DECODE_' "$SRC/src/codecs/ip/cd_pgm.cc")" -eq 1
test "$(grep -cE '^\s+\{ DECODE_' "$SRC/src/codecs/ip/cd_auth.cc")" -eq 2
test "$(grep -cE '^\s+\{ DECODE_' "$SRC/src/codecs/ip/cd_frag.cc" || true)" -eq 0   # R2: frag carries NO RuleMap at all
grep -q '^ESPRULES 1 sid0=294 name=esp$' "$V"
grep -q '^PGMRULES 1 sid0=454 name=pgm$' "$V"
grep -q '^AHRULES 2 sid0=465 name=auth$' "$V"   # module name face "auth" (CD_AUTH_NAME)
grep -q '^FRAG api mod_ctor=0 mod_dtor=0$' "$V"
# esp config-gate face (ground NSDMI default -- cc:44 param "false"):
grep -q '"false",' "$SRC/src/codecs/ip/cd_esp.cc"
test "$(grep -c '    bool enable_esp = false;' "$SRC/src/main/snort_config.h")" -eq 1
grep -q '^ESP gate-off -> 0$' "$V"
grep -q '^ESP ok24 -> 1' "$V"
# offlg flag + decomposition ladders (ground consts grep-pinned, NEVER air):
test "$(grep -cE 'DECODE_FRAG = +0x00000040,' "$SRC/src/framework/decode_data.h")" -eq 1
test "$(grep -cE 'DECODE_MF = +0x00000080,'   "$SRC/src/framework/decode_data.h")" -eq 1
test "$(grep -cE 'FINISHED_DECODE = 0x0100,'  "$SRC/src/protocols/protocol_ids.h")" -eq 1
test "$(grep -cE 'constexpr uint16_t CODEC_ENCAP_LAYER = \(CODEC_SAVE_LAYER \| CODEC_UNSURE_ENCAP \);' "$SRC/src/framework/codec.h")" -eq 1
test "$(grep -cE 'constexpr uint16_t CODEC_IP6_EXT_OOO = 0x0400;' "$SRC/src/framework/codec.h")" -eq 1
python3 - <<'PYPIN'
# decomposition check (ground-pinned BOTH ends, NEVER air): CODEC_SAVE_LAYER
# 0x04 | CODEC_UNSURE_ENCAP 0x02 = ENCAP 6; | OOO 0x0400 = 1030; DECODE_MF
# 0x80 | DECODE_FRAG 0x40 = 192; FINISHED_DECODE 0x0100 = 256; PKT_TRUST 32.
import re
g = open("/opt/data/snort3-src/src/framework/codec.h").read()
save = int(re.search(r'CODEC_SAVE_LAYER = (0x[0-9A-Fa-f]+)', g).group(1), 16)
unsure = int(re.search(r'CODEC_UNSURE_ENCAP = (0x[0-9A-Fa-f]+)', g).group(1), 16)
ooo = int(re.search(r'CODEC_IP6_EXT_OOO = (0x[0-9A-Fa-f]+)', g).group(1), 16)
assert save | unsure == 6 and (save | unsure) | ooo == 1030
d = open("/opt/data/snort3-src/src/framework/decode_data.h").read()
mf = int(re.search(r'DECODE_MF =\s+(0x[0-9A-Fa-f]+)', d).group(1), 16)
frag = int(re.search(r'DECODE_FRAG =\s+(0x[0-9A-Fa-f]+)', d).group(1), 16)
assert mf | frag == 192 and mf == 128 and frag == 64
PYPIN
grep -q '^FRAG mf -> 1 next=256 dflags=192$'   "$V"   # MF|FRAG (cc:77/:89) + FINISHED cc:124
grep -q '^FRAG off8 -> 1 next=256 dflags=64$'  "$V"   # FRAG only (no MF)
grep -q '^ESP ok24 -> 1 lyr=8 next=6 flags=6$' "$V"   # CODEC_ENCAP_LAYER face
grep -q '^ESP order66 -> 1 flags=1030$'        "$V"   # ENCAP|IP6_EXT_OOO -- 296 rides a SUCCESS
grep -q '^ESP pad255 -> 1 next=256 dflags=32$' "$V"   # cc:150-:155 PKT_TRUST face
grep -q '^FRAG zero8 -> 1 lyr=8 next=17 dflags=0$' "$V"  # 459 NO-return then 458: decode continues

# ---- trackable pins (vectors are OUTPUT of the MEASURED first run; the
# md5+wc pins below came from THAT run -- build.sh DRIFTS-then-refuses, it
# NEVER fabricates. 17p: no arithmetic/forecast typed.) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 46
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 17
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "462f0ff6ed44220564c5ef0c8538ad80"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "4755d48c54cc057b3c3c9eafec01c7cf"

# ---- frozen-donor direct-md5 census (15 faces, diff-0; the DIRECT face --
# tun/eth/ext -eq 24 ls-asserts stay UN-chased by design, R6) -------------
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
# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" "$FM/build.sh"
grep -q "4826fc2233044a2d5429413faf0ae1af" "$FM/build.sh"

# ---- TWO-LINEAGE census loop (MEASURED, never typed; THIS row adds ZERO
# gate.txt so the 25-tracked face is UNDISTURBED BY DESIGN): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY

echo "row-TU nm census (MEASURED, never typed): esp=$(wc -l < "$H/nm_U_cd_esp.txt") frag=$(wc -l < "$H/nm_U_cd_frag.txt") pgm=$(wc -l < "$H/nm_U_cd_pgm.txt") auth=$(wc -l < "$H/nm_U_cd_auth.txt") union=$(wc -l < "$H/nm_U_union.txt") (tunnel_bypass 0/0/0/0 -- ZERO new witness)"
echo "copy tree find-count (MEASURED): $(find "$C" -type f ! -name '*.o' | wc -l)"
echo "E4 adaptation: ZERO fresh cps -> stripped-tree flipped-asserts (checksum.h x pgm + text_log.x x frag) + restored rc0 x4 EVERY build"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED here; tracked gate.txt = 1, ls-files)"
echo "SMALL4_HARNESS_OK vectors=$( [ -e "$H/vectors.txt" ] && wc -l < "$H/vectors.txt" || wc -l < "$H/vectors_O0.txt") faceA=$( [ -e "$H/vectors_faceA.txt" ] && wc -l < "$H/vectors_faceA.txt" || wc -l < "$H/vectors_faceA_O0.txt") gates=0"
