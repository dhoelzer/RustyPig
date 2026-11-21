#!/usr/bin/env bash
# daq3_harness -- row 18i: the ip DAQ TRIO: codecs/ip/cd_udp.cc 660 L +
# cd_icmp4.cc 645 L + cd_icmp6.cc 518 L = 1,823 L total. THE daq.h head-on
# row: the SDK header is ABSENT tree+host (find = 0, tripwired EVERY build)
# -> a 33 L minimal graft LANDS (the defer route CANNOT compile: the include
# rides the ground TUs literally). Copy tree = small4 DONOR VERBATIM (96) +
# EXACTLY 3 fresh header cps (udp.h -- trio-side pair-rider, icmp4.h ONE cp
# feeds THREE faces incl the icmp6 :32 cross-rider, icmp6.h) + daq.h GRAFT +
# 3 row TUs = find-count 103 (MEASURED assert, NEVER pre-typed 17p; the
# per-file proof = E4 stripped-tree flipped-asserts, walls below).
# THE HEADLINE: witness delta = EXACTLY 4 NEW backbone-side symbols (the
# lineage's FIRST fn witnesses from a graft -- fmod daq_common.h 16 L and
# vocab daq_dlt.h 5 L were header-ONLY, ZERO fn witnesses): daq_msg_get_meta
# + daq_msg_get_data (ZERO precedent, SYNTHETIC bodies -- the 17d seam) +
# snort::get_network_policy (conf/fcap precedent shape, pinned raw storage,
# NSDMI faces hand-seeded policy.h :233/:234 so the THREE inline checksum
# gates cd_udp:367 / cd_icmp4:159 / cd_icmp6:197 read the ground default) +
# snort::Value::get_bits (ZERO precedent; first codec caller cd_udp set()
# :209/:214/:219 = the params seam, never vectorized -- R4 honest record).
# The staged-link census (L1 rc1 EXACTLY-4 undefined -> L2 +witness_daq rc0)
# re-measures the delta EVERY build. The bypass axis stays ZERO:
# tunnel_bypass U-census 0/0/0 (the 18h correction, nm-level re-armed).
# DUAL-FACE DEC probes (all THREE TUs): the SAME bad-checksum packet reads
# dflags=4/8 with DAQ meta OFF vs decode-SUCCEEDS dflags=0 with the
# synthetic-valid pdd (checksum_bypassed PEG, PEG not the tunnel_bypass
# HOOK -- cite-never-vectorize face, small4 pgm tri-state precedent); the
# icmp4 sweep is the arm-dense face: ALL 18 unique event names ride 19 arms.
# ZERO-GATE row (small4 ZERO-gate clone): combined gate grep 0 x3 re-asserted
# EVERY build -> probe-only, NO gate.txt, NO catch_main, NO E9 face.
# The misc pair (cd_icmp4_ip/cd_icmp6_ip, tcp.h-ONLY-extra, get_proto_name
# ZERO-precedent witness) TAILS per PLAN 8 -- its faces (E4 wall tcp-arm,
# mod_ctor=0 x2, misc-pair DAQ-free split) were scratch-rehearsed ONLY.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
TUN=/opt/data/snort3-rust/tools/tun_harness
ETH=/opt/data/snort3-rust/tools/eth_harness
FM=/opt/data/snort3-rust/tools/fmod_harness
C=$H/copy

# ---- ground identity (THREE row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [cd_udp.cc]=3c60f0f788de2da7c1d196b694d969a5 [cd_icmp4.cc]=12c1935ede670171715aeb970da42cc5 \
                 [cd_icmp6.cc]=778157526e26f194e8ca832290ce164e )
declare -A WC=( [cd_udp.cc]=660 [cd_icmp4.cc]=645 [cd_icmp6.cc]=518 )
for f in cd_udp.cc cd_icmp4.cc cd_icmp6.cc; do
    test "$(md5sum "$SRC/src/codecs/ip/$f" | awk '{print $1}')" = "${MD5[$f]}"
    test "$(wc -l < "$SRC/src/codecs/ip/$f")" -eq "${WC[$f]}"
done
# trio total face (the row's ledger line): 660+645+518 = 1823 SUM measured
test "$(( $(wc -l < "$SRC/src/codecs/ip/cd_udp.cc") + $(wc -l < "$SRC/src/codecs/ip/cd_icmp4.cc") + $(wc -l < "$SRC/src/codecs/ip/cd_icmp6.cc") ))" -eq 1823
# combined gate grep ZERO x3 EVERY build (if ground ever ships a suite here
# the row is RE-PLANNED to the gre gate shape -- flip trips loudly)
for f in cd_udp.cc cd_icmp4.cc cd_icmp6.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST' "$SRC/src/codecs/ip/$f" || true)" -eq 0
done

# ---- TABLE face REAL x3 (the table-name sed census; NO file-vs-table drift
# in the trio -- file base == table base, receipt R1) ----
test "$(sed -n '652p' "$SRC/src/codecs/ip/cd_udp.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '655p' "$SRC/src/codecs/ip/cd_udp.cc")" = "const BaseApi* cd_udp[] ="
test "$(sed -n '637p' "$SRC/src/codecs/ip/cd_icmp4.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '640p' "$SRC/src/codecs/ip/cd_icmp4.cc")" = "const BaseApi* cd_icmp4[] ="
test "$(sed -n '510p' "$SRC/src/codecs/ip/cd_icmp6.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '513p' "$SRC/src/codecs/ip/cd_icmp6.cc")" = "const BaseApi* cd_icmp6[] ="

# ---- externs + loads + ladder ALL RESIDENT (rows ADD TUs, NEVER touch) ----
test "$(sed -n '54p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_icmp4[];"
test "$(sed -n '56p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_icmp6[];"
test "$(sed -n '70p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_udp[];"
test "$(sed -n '99p'  "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_icmp4);"
test "$(sed -n '101p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_icmp6);"
test "$(sed -n '115p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_udp);"
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern cc census
# pair names :55/:57 (:100/:102 loads) stay resident-but-UNLINKED until the
# pair row -- completeness note, the measured pre-18i face for ALL of :54-:57
test "$(sed -n '55p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_icmp4_ip[];"
test "$(sed -n '57p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_icmp6_ip[];"
# the rust ladder face (rows NEVER re-touch): resident names
test "$(sed -n '112p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_icmp4",'
test "$(sed -n '114p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_icmp6",'
test "$(sed -n '128p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_udp",'

# ---- THE ipv6_api DRIFT RIDER (PLAN 3): cd_icmp6's api STRUCT is ipv6_api
# :488 while table cd_icmp6 + NAME "icmp6"; a grep for the name the FILE
# would suggest (icmp6_api) is a FALSE-CLEAN 0-hit face -- tripwire arms
# TABLE-side; the print face carries NAME icmp6 (FACE-A grep) ----
test "$(sed -n '488p' "$SRC/src/codecs/ip/cd_icmp6.cc")" = "static const CodecApi ipv6_api ="
test "$(grep -c 'extern const BaseApi\* cd_icmp6\b' "$SRC/src/codecs/codec_api.cc")" -eq 1
if grep -rn 'icmp6_api' /opt/data/snort3-rust/src/ > "$H/drift_ipv6_api_face.txt" 2>/dev/null; then
    echo "DRIFT FACE CHANGED: icmp6_api exists on the rust face -- re-read PLAN 3"; exit 1
fi
test ! -s "$H/drift_ipv6_api_face.txt"
# NAME macros (FACE-A greps ride these; sed cites, NEVER air)
test "$(sed -n '40p' "$SRC/src/codecs/ip/cd_udp.cc")"   = '#define CD_UDP_NAME "udp"'
test "$(sed -n '37p' "$SRC/src/codecs/ip/cd_icmp4.cc")" = '#define CD_ICMP4_NAME "icmp4"'
test "$(sed -n '39p' "$SRC/src/codecs/ip/cd_icmp6.cc")" = '#define CD_ICMP6_NAME "icmp6"'

# ---- THE daq.h face PROVEN EVERY BUILD (PLAN 2a/5; R1 tripwire): ----
# the SDK header MUST stay absent tree+host (a ground-side landing = the E4
# flip trips an honest RE-CITE + a possible graft edit -- fmod's mid-lineage
# DIOCTL placeholder pin proves graft edits are lineage-normal).
test "$(find "$SRC" -name daq.h | wc -l)" -eq 0
# tools-side census: NO graft EVER landed in ANOTHER copy tree (this row's
# live $C/daq.h face is the graft ITSELF -> excluded; a SECOND landing = drift)
test "$(find /opt/data/snort3-rust/tools -name daq.h ! -path '/opt/data/snort3-rust/tools/daq3_harness/*' | wc -l)" -eq 0
test "$(ls /usr/include/daq.h /usr/include/daq/*.h 2>/dev/null | wc -l)" -eq 0
# HYBRID route stays DISPROVEN re-armed (R8 compile-rehearsal face): the
# real ground daq_user.h carries NO decode-data/NAPT family at all.
test "$(grep -c 'DAQ_PktDecodeData_t\|DAQ_NAPTInfo_t\|DAQ_PKT_META' "$SRC/daqs/daq_user.h" || true)" -eq 0
test "$(wc -l < "$SRC/daqs/daq_user.h")" -eq 54
# GRAFT-FIDELITY CITE AUDIT (PLAN 2a per-symbol table, EVERY build vs the
# ground call faces -- the 7 grafted symbols vs the 13-line THIN usage):
test "$(sed -n '25p'  "$SRC/src/codecs/ip/cd_udp.cc")"   = "#include <daq.h>"       # include rides the ground TU literally = pure-defer DEAD
test "$(sed -n '263p' "$SRC/src/codecs/ip/cd_udp.cc")"   = "    const DAQ_PktDecodeData_t* pdd ="
test "$(sed -n '264p' "$SRC/src/codecs/ip/cd_udp.cc" | sed 's/^ *//')" = "(const DAQ_PktDecodeData_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA);"
test "$(sed -n '268p' "$SRC/src/codecs/ip/cd_udp.cc")"   = "    if (pdd->l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID)"
test "$(sed -n '270p' "$SRC/src/codecs/ip/cd_udp.cc" | sed 's/^ *//')" = "const uint8_t* data = daq_msg_get_data(raw.daq_msg);"
test "$(sed -n '420p' "$SRC/src/codecs/ip/cd_udp.cc" | sed 's/^ *//')" = "const DAQ_NAPTInfo_t* napti = (const DAQ_NAPTInfo_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_NAPT_INFO);"
test "$(sed -n '421p' "$SRC/src/codecs/ip/cd_udp.cc")"   = "    if (napti && codec.ip_layer_cnt == napti->ip_layer)"
test "$(sed -n '132p' "$SRC/src/codecs/ip/cd_icmp4.cc")" = "    const DAQ_PktDecodeData_t* pdd ="
test "$(sed -n '137p' "$SRC/src/codecs/ip/cd_icmp4.cc")" = "    if (pdd->l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID)"
test "$(sed -n '139p' "$SRC/src/codecs/ip/cd_icmp4.cc" | sed 's/^ *//')" = "const uint8_t* data = daq_msg_get_data(raw.daq_msg);"
test "$(sed -n '125p' "$SRC/src/codecs/ip/cd_icmp6.cc")" = "    const DAQ_PktDecodeData_t* pdd ="
test "$(sed -n '130p' "$SRC/src/codecs/ip/cd_icmp6.cc")" = "    if (pdd->l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID)"
test "$(sed -n '132p' "$SRC/src/codecs/ip/cd_icmp6.cc" | sed 's/^ *//')" = "const uint8_t* data = daq_msg_get_data(raw.daq_msg);"
# usage census per TU (the 7-symbol union face; raw.daq_msg = the 17d seam)
test "$(grep -c 'DAQ_\|daq_msg' "$SRC/src/codecs/ip/cd_udp.cc")"   -eq 5
test "$(grep -c 'DAQ_\|daq_msg' "$SRC/src/codecs/ip/cd_icmp4.cc")" -eq 4
test "$(grep -c 'DAQ_\|daq_msg' "$SRC/src/codecs/ip/cd_icmp6.cc")" -eq 4
test "$(grep -hoE 'DAQ_[A-Za-z0-9_]+|daq_msg_get_[a-z_]+' "$SRC/src/codecs/ip/cd_udp.cc" "$SRC/src/codecs/ip/cd_icmp4.cc" "$SRC/src/codecs/ip/cd_icmp6.cc" | sort -u | wc -l)" -eq 7   # symbol union = EXACTLY 7
# reuse bank: the graft pays ONCE -- 7 consumers (trio + ipv4/ipv6/tcp/vlan)
test "$(grep -rl '#include <daq.h>' "$SRC/src/codecs" | wc -l)" -eq 7
# the three checksum gates (policy.h INLINE udp/icmp_checksums() :205/:211)
test "$(sed -n '367p' "$SRC/src/codecs/ip/cd_udp.cc")" = "    if (snort::get_network_policy()->udp_checksums() && !valid_checksum_from_daq(raw))"
test "$(sed -n '159p' "$SRC/src/codecs/ip/cd_icmp4.cc")" = "    if (snort::get_network_policy()->icmp_checksums() && !valid_checksum_from_daq(raw))"
test "$(sed -n '197p' "$SRC/src/codecs/ip/cd_icmp6.cc" | sed 's/^ *//')" = "if ( snort::get_network_policy()->icmp_checksums() && !valid_checksum_from_daq(raw))"
# policy NSDMI faces the witness seeds + the decode-flags the arms print
test "$(sed -n '233p' "$SRC/src/main/policy.h")" = "    uint32_t checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF;"
test "$(sed -n '234p' "$SRC/src/main/policy.h")" = "    uint32_t checksum_drop = CHECKSUM_FLAG__DEF;"
test "$(grep -cE 'DECODE_ERR_CKSUM_UDP =  0x00000004,' "$SRC/src/framework/decode_data.h")" -eq 1   # :133 dflags=4 face
test "$(grep -cE 'DECODE_ERR_CKSUM_ICMP = 0x00000008,' "$SRC/src/framework/decode_data.h")" -eq 1   # :134 dflags=8 face
# peg-vs-hook scoping face (R2, 18h correction cited at source level)
test "$(grep -c 'checksum_bypassed\|cksum_bypassed' "$SRC/src/codecs/ip/cd_udp.cc")" -eq 3   # :49 peg-info + :57 counter + :274 ++ (twins :45/:52/:143 + :47/:54/:136)
test "$(grep -c 'tunnel_bypass' "$SRC/src/codecs/ip/cd_udp.cc" "$SRC/src/codecs/ip/cd_icmp4.cc" "$SRC/src/codecs/ip/cd_icmp6.cc" | grep -c ':0')" -eq 3
# sids resident (ground enum walk + Rust landed -- ZERO new constants; the
# VALUES ride the walk BELOW, never air)
for pair in "DECODE_UDP_DGRAM_LT_UDPHDR" "DECODE_UDP_DGRAM_INVALID_LENGTH" "DECODE_UDP_DGRAM_SHORT_PACKET" \
            "DECODE_UDP_DGRAM_LONG_PACKET" "DECODE_UDP_IPV6_ZERO_CHECKSUM" "DECODE_UDP_LARGE_PACKET" "DECODE_UDP_PORT_ZERO" \
            "DECODE_ICMP4_HDR_TRUNC" "DECODE_ICMP4_TYPE_OTHER" "DECODE_ICMP4_DST_BROADCAST" "DECODE_ICMP4_DST_MULTICAST" \
            "DECODE_ICMP_PATH_MTU_DOS" "DECODE_ICMP6_HDR_TRUNC" "DECODE_ICMP6_NOT_IP6" "DECODE_ICMP6_TYPE_OTHER" \
            "DECODE_ICMP6_DST_MULTICAST" "DECODE_ICMP6_OPT_ZERO_LENGTH"; do
    grep -qE "^ *$pair[ ,]" "$SRC/src/codecs/codec_module.h"
    grep -q "$pair = [0-9]*,  // h:" /opt/data/snort3-rust/src/codecs/codec_module.rs
done
# ground identity re-pin (seed @ fe29cbe7403 -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin: the lineage pins the IMMUTABLE ground only (the
# small4 build.sh:110 face) -- the working repo HEAD MOVES at EVERY row
# landing by design; a self-pin is a creation-time face that strands the
# post-commit session-start (the honest rc1 face receipts build_E/F/G:
# the first post-commit rituals tripped the seed face 8d2712a). Rows
# NEVER rewrite history: this comment records the re-rule.
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- copy tree = small4 DONOR VERBATIM (96) + 3 FRESH header cps + daq.h
# GRAFT + 3 row TUs = 103 (PLAN 2; the trio's closure has NO misc/pair parts;
# tcp.h stays OUT = the pair's ONLY-extra cp, scratch wall-4 rehearsal only) ----
if [ ! -e /opt/data/snort3-rust/tools/small4_harness/copy/codec.o ]; then bash /opt/data/snort3-rust/tools/small4_harness/build.sh; fi   # donor self-heal
rm -rf "$C"; cp -a /opt/data/snort3-rust/tools/small4_harness/copy "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 96   # live head-face donor count (small4 :125 face)
# fresh-landing face PROVEN find-0 vs the donor THIS build (3 headers + graft)
test ! -e "$C/protocols/udp.h"
test ! -e "$C/protocols/icmp4.h"
test ! -e "$C/protocols/icmp6.h"
test ! -e "$C/daq.h"
# the 3 FRESH header cps (md5+wc = ground faces measured in receipts R4)
declare -A HCM=( [udp.h]=c7671d5dc8bb32080dea47e6e8c37f50 [icmp4.h]=1a9126d08c2641368e9ac1307b1a8c03 [icmp6.h]=82d1e46945aab1d09a44420819718d93 )
declare -A HCW=( [udp.h]=68 [icmp4.h]=259 [icmp6.h]=196 )
for f in udp.h icmp4.h icmp6.h; do
    test "$(md5sum "$SRC/src/protocols/$f" | awk '{print $1}')" = "${HCM[$f]}"
    test "$(wc -l < "$SRC/src/protocols/$f")" -eq "${HCW[$f]}"
    cp "$SRC/src/protocols/$f" "$C/protocols/$f"
    cmp -s "$C/protocols/$f" "$SRC/src/protocols/$f"
done
# residency riders re-confirmed (teredo paid by tun, checksum.h by gre,
# value.h/policy.h/packet_manager.h by conf lineage -- face greps)
test -e "$C/protocols/teredo.h"
test -e "$C/codecs/ip/checksum.h"
test "$(md5sum "$C/codecs/ip/checksum.h" | awk '{print $1}')" = "b43628f369e16b1d5c093ff447d3e954"   # the csum-row pin, unchanged
test -e "$C/framework/value.h"
test -e "$C/main/policy.h"
test "$(md5sum "$C/main/policy.h" | awk '{print $1}')" = "$(md5sum "$SRC/src/main/policy.h" | awk '{print $1}')"   # BYTE-IDENT ground face (receipts R4 pin 137608f1 face, measured both sides EVERY build)
test "$(md5sum "$C/codecs/codec_module.h" | awk '{print $1}')" = "3f3bd92752ba46b8732f831724d3b279"
test "$(md5sum "$C/framework/codec.h"    | awk '{print $1}')" = "32da89f1a204410825f750739c146410"
test "$(md5sum "$C/main/snort_config.h"  | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probe pulls NO codec_api)
test ! -e "$C/codecs/codec_api.cc"
# the daq.h GRAFT (synthetic, NOT a ground cp; 33 L; rides the donor's
# daq_common.h = the fmod 16 L graft face, byte-ident tree-to-tree census)
test -e "$C/daq_common.h"
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"   # fmod-graft face (cmp'd scratch/fmod/small4 trees = SAME)
cat > "$C/daq.h" <<'EOFDAQ'
#ifndef DAQ_H
#define DAQ_H
// 18i CANDIDATE graft (scratch rehearsal only, NOT landed): the DAQ SDK
// header is not in the snort3 tree nor on the host (find whole-repo = 0
// hits at fe29cbe). Shapes drawn from the MEASURED call faces ONLY:
// cd_udp.cc:263-270/:420, cd_icmp4.cc:132-139, cd_icmp6.cc:125-132.
#include <cstdint>
#include <daq_common.h>           // rides the fmod 16 L graft (byte-ident in copy trees)
typedef enum
{
    DAQ_META_FIRST = 0,
    DAQ_PKT_META_DECODE_DATA,     // trio :133/:126/:264 2nd arg
    DAQ_PKT_META_NAPT_INFO        // cd_udp.cc:420 2nd arg
} DAQ_MetaType;
#define DAQ_PKT_DECODE_OFFSET_INVALID (-1)   // compared vs pdd->l4_offset
struct DAQ_PktDecodeData_t
{
    struct { struct { unsigned l4_checksum : 1;
                      unsigned udp         : 1;
                      unsigned icmp        : 1;
                      unsigned l4          : 1; } bits; } flags;
    int32_t l4_offset;            // :268/:137/:130 vs OFFSET_INVALID
};
struct DAQ_NAPTInfo_t
{
    uint32_t src_port;            // cd_udp.cc:422-424 ntohs
    uint32_t dst_port;
    uint8_t  ip_layer;            // :421 vs codec.ip_layer_cnt
};
struct _daq_msg;                  // fwd = framework/codec.h :38 face (same TU)
const void*    daq_msg_get_meta(const struct _daq_msg*, DAQ_MetaType);
const uint8_t* daq_msg_get_data(const struct _daq_msg*);
#endif
EOFDAQ
test "$(wc -l < "$C/daq.h")" -eq 33
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"   # the scratch-measured graft face (receipts R3)
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 100   # 96 + 3 fresh headers + 1 graft (MEASURED find-census face pre-row-TU)
for f in cd_udp.cc cd_icmp4.cc cd_icmp6.cc; do
    test ! -e "$C/codecs/ip/$f"                                   # fresh-landing face
    cp "$SRC/src/codecs/ip/$f" "$C/codecs/ip/$f"
    cmp -s "$C/codecs/ip/$f" "$SRC/src/codecs/ip/$f"
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 103   # 96 + 3 headers + 1 graft + 3 row TUs (the 17p MEASURED face)

# ---- E4 WALLS (PLAN 2): the fresh-cp residency PROVEN per-face by
# stripped-tree flipped-asserts EVERY build (one-shot: a live strip can ONLY
# mean donor drift -> loud rc 1). Landed trio face: the pair arms (udp.h <->
# cd_icmp4_ip :31, tcp.h <-> cd_icmp4_ip ONLY-dies) were scratch-rehearsed
# WITH the pair TUs in the tree -- here the tree has NO misc TUs, so each
# wall measures the trio face honestly (wall-1 trio x3 MUST die = pure-defer
# DEAD face; wall-3 icmp4.h cross-rider x2 = the ONE-cp-feeds-THREE face). ----
GXX0="g++ -std=c++17 -O0 -w -I$C"
mv "$C/daq.h" "$H/.e4_hold_daq.h"
for f in cd_udp cd_icmp4 cd_icmp6; do
    if $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" -o /dev/null 2> "$H/E4_nodaq_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT daq.h -- the pure-defer route is alive, PLAN 2a is dead"; exit 1
    fi
    head -1 "$H/E4_nodaq_$f.txt" | grep -q "fatal error: daq.h: No such file"   # cc:25 x3
done
mv "$H/.e4_hold_daq.h" "$C/daq.h"
mv "$C/protocols/udp.h" "$H/.e4_hold_udp.h"
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_udp.cc" -o /dev/null 2> "$H/E4_noudp_udp.txt"; then
    echo "E4 flip BROKE: cd_udp compiled WITHOUT protocols/udp.h (cc:34)"; exit 1
fi
head -1 "$H/E4_noudp_udp.txt" | grep -q "fatal error: protocols/udp.h: No such file"
for f in cd_icmp4 cd_icmp6; do
    $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" 2> "$H/E4_noudp_$f.txt"   # survivors
    test ! -s "$H/E4_noudp_$f.txt"
done
mv "$H/.e4_hold_udp.h" "$C/protocols/udp.h"
mv "$C/protocols/icmp4.h" "$H/.e4_hold_icmp4.h"
for f in cd_icmp4 cd_icmp6; do   # wall-3: the cross-rider face (icmp4.h x BOTH ip codecs: cc:31 + cc:32)
    if $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" -o /dev/null 2> "$H/E4_noicmp4_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT protocols/icmp4.h"; exit 1
    fi
    head -1 "$H/E4_noicmp4_$f.txt" | grep -q "fatal error: protocols/icmp4.h: No such file"
done
$GXX0 -fsyntax-only "$C/codecs/ip/cd_udp.cc" 2> "$H/E4_noicmp4_udp.txt"
test ! -s "$H/E4_noicmp4_udp.txt"
mv "$H/.e4_hold_icmp4.h" "$C/protocols/icmp4.h"
mv "$C/protocols/icmp6.h" "$H/.e4_hold_icmp6.h"
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_icmp6.cc" -o /dev/null 2> "$H/E4_noicmp6_icmp6.txt"; then
    echo "E4 flip BROKE: cd_icmp6 compiled WITHOUT protocols/icmp6.h (cc:31)"; exit 1
fi
head -1 "$H/E4_noicmp6_icmp6.txt" | grep -q "fatal error: protocols/icmp6.h: No such file"
for f in cd_udp cd_icmp4; do
    $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" 2> "$H/E4_noicmp6_$f.txt"
    test ! -s "$H/E4_noicmp6_$f.txt"
done
mv "$H/.e4_hold_icmp6.h" "$C/protocols/icmp6.h"
for f in cd_udp cd_icmp4 cd_icmp6; do   # restored full tree: rc 0 EVERY build
    $GXX0 -c "$C/codecs/ip/$f.cc" -o "$C/$f.precheck.o" 2> "$H/E4_$f.txt"
    test ! -s "$H/E4_$f.txt"
    rm -f "$C/$f.precheck.o"
done

# ---- witness carry: WIN trio INHERITED (md5 pins NEVER re-derived) + THE
# new face witness_daq.cc (tracked, md5-pinned = the honest delta vs small4) ----
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
test "$(md5sum "$H/witness_daq.cc" | awk '{print $1}')" = "e0166b021073fed328bfd583c839e38b"   # THE new tracked witness face (measured scratch face, receipts R6)

GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
REAL="$C/framework/codec.cc $C/protocols/ip.cc $C/sfip/sf_ip.cc $C/utils/util_cstring.cc $C/utils/util.cc $C/log/text_log.cc $C/framework/module.cc"

# ---- O0 compile: THREE plain .o + donor REAL .o + probes + witnesses ------
for f in cd_udp cd_icmp4 cd_icmp6; do $GXX -c "$C/codecs/ip/$f.cc" -o "$C/$f.o"; done
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o
$GXX -c "$H"/witness_daq.cc   -o "$H"/witness_daq.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/cd_udp.o $C/cd_icmp4.o $C/cd_icmp6.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# one-symbol-per-.o face (E9 trivially holds; each plain .o defines EXACTLY
# ONE table symbol -- NO drift face in the trio, contrast 18h cd_ah):
for f in cd_udp cd_icmp4 cd_icmp6; do
    test "$(nm --defined-only "$C/$f.o" | grep -cE ' [DdRr] cd_(udp|icmp4|icmp6)$')" -eq 1
done

# ---- nm per-TU U-census (receipts; counts MEASURED, NEVER typed) --------
for f in cd_udp cd_icmp4 cd_icmp6; do
    nm -C -u "$C/$f.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$f.txt"
    test "$(grep -c 'tunnel_bypass' "$H/nm_U_$f.txt" || true)" -eq 0     # 0/0/0 face: the BYPASS axis stays ZERO (18h correction, object-level)
done
cat "$H"/nm_U_cd_*.txt | sort -u > "$H/nm_U_union.txt"
# THE witness-delta face re-measured EVERY BUILD (staged links, PLAN 5):
# L1 = trio + OBJS + WIN, NO witness_daq -> MUST die at EXACTLY the 4 new
# backbone symbols (the face that moved "ZERO new witnesses" to +4).
if $GXX $ROWS $OBJS "$H"/probe.o $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: trio linked WITHOUT witness_daq -- the +4 delta is wrong"; exit 1
fi
grep "undefined reference to" "$H/L1_link_face.txt" > "$H/L1_undefined.txt"
for sym in 'daq_msg_get_meta' 'daq_msg_get_data' 'snort::Value::get_bits' 'snort::get_network_policy'; do
    grep -q "undefined reference to .*$sym" "$H/L1_link_face.txt"
done
test "$(grep -oE "undefined reference to \`[^']*'" "$H/L1_link_face.txt" | sort -u | wc -l)" -eq 4   # EXACTLY-4 undefined face
rm -f "$H/.L1_probe"
# residue class (MANGLED face = robust; small4 rule): every snort-family U
# symbol of the three row .o MUST be defined by OBJS+WIN+witness_daq.
g3=""; for f in cd_udp cd_icmp4 cd_icmp6; do g3="$g3 $C/$f.o"; done
nm -u $g3 | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
donordefs=$(nm --defined-only $OBJS $WIN "$H"/witness_daq.o | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*|*11daq_msg_get*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# landmine posture ZERO (18e rule): no 18i name frozen in ANY witness donor
for n in cd_udp cd_icmp4 cd_icmp6; do
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc || true)" -eq 0
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/codec_harness/stubs.cc || true)" -eq 0
done
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"

# ---- real-symbol defines (donor face, gre-recipe) -----------------------
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
grep -q 'T snort::Codec::CheckIPv6ExtensionOrder' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
grep -q 'T tun_witness_set_mask' <<< "$(nm -C --defined-only "$H"/witness_18f.o)"
grep -q 'daq_msg_get_meta' <<< "$(nm -C --defined-only "$H"/witness_daq.o)"

# ---- probe links: L2 face = WIN trio + witness_daq -> GREEN --------------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN "$H"/witness_daq.o -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN "$H"/witness_daq.o -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in cd_udp cd_icmp4 cd_icmp6; do $GXXA -c "$C/codecs/ip/$f.cc" -o "$O2/$f.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc -o "$O2"/stubs_18d.o; $GXXA -c "$H"/witness_daq.cc -o "$O2"/witness_daq.o
OB2=""; for f in cd_udp cd_icmp4 cd_icmp6; do OB2="$OB2 $O2/$f.o"; done
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_daq.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_daq.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool [a-z][a-z0-9]*=.*->decode' "$H"/probe_dec.cc)" -ge 30
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
# FACE-A: trio NAME face (ground #defines sed-pinned above; LOAD/LADDER grep)
grep -q '^LOAD udp$'   "$FA"
grep -q '^LOAD icmp4$' "$FA"
grep -q '^LOAD icmp6$' "$FA"
grep -q '^LOADS 3$'    "$FA"
grep -q '^API udp type=0 size=112 ver=1900547 name=udp$'     "$FA"   # CDAPI carry inherited
grep -q '^API icmp6 type=0 size=112 ver=1900547 name=icmp6$' "$FA"   # ipv6_api STRUCT never prints (drift rider ride)
# THE UNIFORM mod_ctor face x3 (contrast small4 1/0/1/1 -- trio asymmetry =
# NONE at this face; the misc pair 0 x2 rides ITS future row):
grep -q '^udp mod_ctor=1 mod_dtor=1$'     "$FA"
grep -q '^icmp4 mod_ctor=1 mod_dtor=1$'   "$FA"
grep -q '^icmp6 mod_ctor=1 mod_dtor=1$'   "$FA"
# HELP arms ride the ground #defines (sed cites, never typed):
test "$(sed -n '41p' "$SRC/src/codecs/ip/cd_udp.cc")"   = '#define CD_UDP_HELP "support for user datagram protocol"'
test "$(sed -n '38p' "$SRC/src/codecs/ip/cd_icmp4.cc")" = '#define CD_ICMP4_HELP "support for Internet control message protocol v4"'
test "$(sed -n '40p' "$SRC/src/codecs/ip/cd_icmp6.cc")" = '#define CD_ICMP6_HELP "support for Internet control message protocol v6"'
grep -q '^HELP udp support for user datagram protocol$'                     "$FA"
grep -q '^HELP icmp4 support for Internet control message protocol v4$'     "$FA"
grep -q '^HELP icmp6 support for Internet control message protocol v6$'     "$FA"
# DEC dual-face ladders (THE row's fidelity face -- ONE packet, TWO faces):
grep -q '^UDP cksumbad-daqoff -> 0 dflags=4 gate=1$' "$V"     # DECODE_ERR_CKSUM_UDP (:133 = 4) + witness-seeded gate live-read
grep -q '^UDP cksumbad-daqvalid -> 1 dflags=0 next=17$' "$V"  # peg face: bypass -> decode proceeds, PEG not hook
grep -q '^UDP daqoffsetmismatch -> 0 dflags=4$'  "$V"         # fallback face (offset compare cc:272)
grep -q '^ICMP4 cksumbad-daqoff -> 0 dflags=8$'  "$V"         # DECODE_ERR_CKSUM_ICMP (:134 = 8)
grep -q '^ICMP4 cksumbad-daqvalid -> 1 dflags=0$' "$V"        # same packet valid face
grep -q '^ICMP6 cksumbad-daqoff -> 0 dflags=8$'  "$V"
grep -q '^ICMP6 cksumbad-daqvalid -> 1 dflags=0 lyr=8$' "$V"  # ICMP6_HEADER_NORMAL_LEN face
grep -q '^UDP napt-hit -> 1 sp=3000 dp=6000$' "$V"            # NAPT hit (cc:421-:424, htons'd fakes)
grep -q '^UDP naptmiss-portzero -> 1 sp=0 dp=0$' "$V"         # NAPT miss -> raw ports + EV 447 arm
# length-ladder + misc arms
grep -q '^UDP short7 -> 0$'        "$V"
grep -q '^EV 116 95$'              "$V"   # cd_udp.cc:316 cc-face (LT_UDPHDR)
grep -q '^UDP badlen4 -> 0$'       "$V"
grep -q '^EV 116 96$'              "$V"   # :320
grep -q '^UDP uhlen20 -> 0$'       "$V"
grep -q '^EV 116 97$'              "$V"   # :328
grep -q '^UDP uhlen10 -> 0$'       "$V"
grep -q '^EV 116 98$'              "$V"   # :334
test "$(grep -c '^EV 116 445$' "$V")" -eq 1    # large4020 arm (cc:478)
test "$(grep -c '^EV 116 447$' "$V")" -eq 1    # port-zero face (cc:481) via napt-miss arm
grep -q '^UDP ip6zero -> 0 dflags=4$' "$V"
grep -q '^EV 116 406$'             "$V"   # ipv6 zero-checksum (cc:392)
grep -q '^UDP teredo3544 -> 1 next=257$' "$V"  # TEREDO 0x0101=257 face (protocol_ids.h grep below)
grep -q '^    TEREDO = 0x0101,$' "$SRC/src/protocols/protocol_ids.h"
grep -q '^UDP large4020 -> 1$' "$V"
# icmp4 arm-dense sweep: ALL 18 unique names (grep census R6; EV stream order = ground call order)
grep -q '^ICMP4 short3 -> 0$'      "$V"
grep -q '^EV 116 426$'             "$V"   # HDR_TRUNC cc:151
grep -q '^ICMP4 type3-grp4 -> 0$'  "$V"
grep -q '^EV 116 105$'             "$V"   # cc:212 group guard (6 sites across both ip TUs share this constant face)
grep -q '^ICMP4 enum666 -> 1$'     "$V"
grep -q '^EV 116 434$'             "$V"; grep -q '^EV 116 435$' "$V"   # PING_NMAP + ICMPENUM (cc:282/:295)
grep -q '^ICMP4 smurf -> 1$'       "$V"; grep -q '^EV 116 440$' "$V"   # BROADSCAN_SMURF (cc:317)
grep -q '^ICMP4 bcast -> 1$'       "$V"; grep -q '^EV 116 416$' "$V"   # cc:251
grep -q '^ICMP4 mcast -> 1$'       "$V"; grep -q '^EV 116 415$' "$V"   # cc:266
grep -q '^ICMP4 tstamp8 -> 0$'     "$V"; grep -q '^EV 116 106$' "$V"   # cc:197
grep -q '^ICMP4 addr8 -> 0$'       "$V"; grep -q '^EV 116 107$' "$V"   # cc:206
grep -q '^ICMP4 type99 -> 1$'      "$V"; grep -q '^EV 116 418$' "$V"   # TYPE_OTHER cc:212 default
grep -q '^ICMP4 sq8 -> 1 next=259$' "$V"  # SOURCE_QUENCH ok face + EV 439 (cc:325)
grep -q '^EV 116 439$'             "$V"
grep -q '^ICMP4 redirhost -> 1$'   "$V"; grep -q '^EV 116 436$' "$V"   # cc:299
grep -q '^ICMP4 redirnet -> 1$'    "$V"; grep -q '^EV 116 437$' "$V"   # cc:303
grep -q '^ICMP4 rr-echo -> 1$'     "$V"; grep -q '^EV 116 438$' "$V"   # cc:307 CODEC_IPOPT_RR_SEEN face codec.h :88
grep -q '^ICMP4 unreach13 -> 1$'   "$V"; grep -q '^EV 116 441$' "$V"   # cc:321
grep -q '^ICMP4 unreach10 -> 1$'   "$V"; grep -q '^EV 116 442$' "$V"   # cc:325
grep -q '^ICMP4 unreach9 -> 1$'    "$V"; grep -q '^EV 116 443$' "$V"   # cc:329
grep -q '^ICMP4 pmtu512 -> 1 next=259$' "$V"  # PATH_MTU_DOS EV 451 (cc:235) + IP_EMBEDDED_IN_ICMP4 0x0103
grep -q '^EV 116 451$'             "$V"
grep -q '^    IP_EMBEDDED_IN_ICMP4 = 0x0103,$' "$SRC/src/protocols/protocol_ids.h"
grep -q '^    IP_EMBEDDED_IN_ICMP6 = 0x0104,$' "$SRC/src/protocols/protocol_ids.h"
# icmp6 arms (the NOT_IP6 + too-big/RS/RA/NODE_INFO + OPT_ZERO walk faces)
grep -q '^ICMP6 short3 -> 0$'      "$V"; grep -q '^EV 116 427$' "$V"   # cc:152 HDR_TRUNC
grep -q '^ICMP6 noip6 -> 0$'       "$V"; grep -q '^EV 116 474$' "$V"   # cc:191 NOT_IP6
grep -q '^ICMP6 mcast -> 1$'       "$V"; grep -q '^EV 116 432$' "$V"   # is_dst_multicast IP6_MULTICAST 0xFF face (cc:225)
grep -q '^ICMP6 toobig1024 -> 1 lyr=8 next=260$' "$V"; grep -q '^EV 116 285$' "$V"  # TOO_BIG_BAD_MTU cc:232 + IP_EMBEDDED_IN_ICMP6
grep -q '^ICMP6 unreach2 -> 1$'    "$V"; grep -q '^EV 116 286$' "$V"   # NON_RFC_2463 (UNREACH_INVALID :87)
grep -q '^ICMP6 unreach7 -> 1$'    "$V"; grep -q '^EV 116 457$' "$V"   # NON_RFC_4443 cc:262
grep -q '^ICMP6 rs-bad -> 1$'      "$V"; grep -q '^EV 116 287$' "$V"; grep -q '^EV 116 289$' "$V"  # SOLICITATION bad-code + bad-reserved (cc:284/:287)
grep -q '^ICMP6 ra-bad -> 1$'      "$V"; grep -q '^EV 116 288$' "$V"; grep -q '^EV 116 290$' "$V"  # ADVERT bad-code + bad-reachable (cc:300/:303)
grep -q '^ICMP6 ra-zerolen -> 1$'  "$V"; grep -q '^EV 116 478$' "$V"   # NDP walk zero-length (cc:166)
grep -q '^ICMP6 nodeinfo3 -> 1$'   "$V"; grep -q '^EV 116 460$' "$V"   # NODE_INFO_BAD_CODE cc:371
grep -q '^ICMP6 toobig6 -> 0$'     "$V"; grep -q '^EV 116 105$' "$V"   # shared DLT_ICMPHDR guard face (cc:252)
grep -q '^ICMP6 type200 -> 1$'     "$V"; grep -q '^EV 116 431$' "$V"   # TYPE_OTHER default cc:407
# PID census arms off the ground protocol_ids.h (never air):
grep -q '^    UDP = 17,$'   "$SRC/src/protocols/protocol_ids.h"
grep -q '^    ICMPV4 = 1,$' "$SRC/src/protocols/protocol_ids.h"
grep -q '^    ICMPV6 = 58,$' "$SRC/src/protocols/protocol_ids.h"
grep -q '^UDPPID 17 n=1$'   "$V"
grep -q '^ICMP4PID 1 n=1$'  "$V"
grep -q '^ICMP6PID 58 n=1$' "$V"
# RuleMap census (ground table rows; row-1 face sed-pinned):
test "$(sed -n '81p' "$SRC/src/codecs/ip/cd_udp.cc")"    = '    { DECODE_UDP_DGRAM_LT_UDPHDR, "truncated UDP header" },'
test "$(sed -n '59p' "$SRC/src/codecs/ip/cd_icmp4.cc")"  = '    { DECODE_ICMP_DGRAM_LT_ICMPHDR, "ICMP header truncated" },'
test "$(sed -n '61p' "$SRC/src/codecs/ip/cd_icmp6.cc")"  = '    { DECODE_ICMP6_HDR_TRUNC, "truncated ICMPv6 header" },'
test "$(grep -cE '^\s+\{ DECODE_' "$SRC/src/codecs/ip/cd_udp.cc")"   -eq 7
test "$(grep -cE '^\s+\{ DECODE_' "$SRC/src/codecs/ip/cd_icmp4.cc")" -eq 25
test "$(grep -cE '^\s+\{ DECODE_' "$SRC/src/codecs/ip/cd_icmp6.cc")" -eq 13
grep -q '^UDPRULES 7 sid0=95 name=udp$'     "$V"   # udp_rules cc:79 (7 rows, exact match of the census)
grep -q '^ICMP4RULES 25 sid0=105 name=icmp4$' "$V" # icmp4 cc:57 (25 rows -- rules-table face > the 18-name event face: DOS_ATTEMPT etc. arms NOT decoded here)
grep -q '^ICMP6RULES 13 sid0=427 name=icmp6$' "$V" # icmp6 cc:59 (13 rows vs the 14-name census: ICMP_DGRAM_LT_ICMPHDR rider shared with icmp4, never in icmp6_rules)
python3 - <<'PYPIN'
# THE sids face PINNED BOTH WAYS (ground enum walk vs landed Rust face --
# every value the ladders above grep rides ground AND rust = never air).
import re
h = open("/opt/data/snort3-src/src/codecs/codec_module.h").read()
m = re.search(r'enum\s+CodecSid[^{]*\{', h); body = h[m.end():]; val = 0; g = {}
for line in body.split("\n"):
    mm = re.match(r"\s*([A-Z_0-9]+)\s*(?:=\s*(\d+))?\s*,", line)
    if mm:
        name = mm.group(1); val = int(mm.group(2)) if mm.group(2) else val + 1; g[name] = val
    if re.match(r"\s*};", line): break
r = dict((k, int(v)) for k, v in re.findall(r"(DECODE_[A-Z_0-9]+) = (\d+),",
        open("/opt/data/snort3-rust/src/codecs/codec_module.rs").read()))
NAMES = """DECODE_UDP_DGRAM_LT_UDPHDR DECODE_UDP_DGRAM_INVALID_LENGTH DECODE_UDP_DGRAM_SHORT_PACKET
DECODE_UDP_DGRAM_LONG_PACKET DECODE_UDP_IPV6_ZERO_CHECKSUM DECODE_UDP_LARGE_PACKET DECODE_UDP_PORT_ZERO
DECODE_ICMP4_HDR_TRUNC DECODE_ICMP_DGRAM_LT_ICMPHDR DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR DECODE_ICMP_DGRAM_LT_ADDRHDR
DECODE_ICMP4_TYPE_OTHER DECODE_ICMP_PATH_MTU_DOS DECODE_ICMP4_DST_BROADCAST DECODE_ICMP4_DST_MULTICAST
DECODE_ICMP_PING_NMAP DECODE_ICMP_ICMPENUM DECODE_ICMP_REDIRECT_HOST DECODE_ICMP_REDIRECT_NET
DECODE_ICMP_TRACEROUTE_IPOPTS DECODE_ICMP_SOURCE_QUENCH DECODE_ICMP_BROADSCAN_SMURF_SCANNER
DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED
DECODE_ICMP6_HDR_TRUNC DECODE_ICMP6_NOT_IP6 DECODE_ICMP6_TYPE_OTHER DECODE_ICMP6_DST_MULTICAST
DECODE_ICMPV6_TOO_BIG_BAD_MTU DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE
DECODE_ICMPV6_SOLICITATION_BAD_CODE DECODE_ICMPV6_SOLICITATION_BAD_RESERVED DECODE_ICMPV6_ADVERT_BAD_CODE
DECODE_ICMPV6_ADVERT_BAD_REACHABLE DECODE_ICMP6_OPT_ZERO_LENGTH DECODE_ICMPV6_NODE_INFO_BAD_CODE""".split()
assert len(NAMES) == 38
for n in NAMES:
    assert g[n] == r[n], (n, g.get(n), r.get(n))
# trio unique-EVENT census (the arms' coverage face): udp 7 / icmp4 18 / icmp6 14 unique names
import subprocess
u = subprocess.run(["grep","-oE","codec_event\\(codec,\\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/ip/cd_udp.cc"],capture_output=True,text=True).stdout
i = subprocess.run(["grep","-oE","codec_event\\(codec,\\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/ip/cd_icmp4.cc"],capture_output=True,text=True).stdout
s = subprocess.run(["grep","-oE","codec_event\\(codec,\\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/ip/cd_icmp6.cc"],capture_output=True,text=True).stdout
def uniq(t): return set(l.split()[-1] for l in t.splitlines() if l.strip())
cu, ci, cs = uniq(u), uniq(i), uniq(s)
assert len(cu) == 7 and len(ci) == 18 and len(cs) == 14, (len(cu), len(ci), len(cs))
PYPIN
# the three checksum-gate faces the witness drives (sed cites the ground
# gates; plan fidelity of the D-vs-E ladder above):
grep -q 'udp_checksums()\s*&& !valid_checksum_from_daq' "$SRC/src/codecs/ip/cd_udp.cc"
grep -q 'get_network_policy()->icmp_checksums() && !valid_checksum_from_daq' "$SRC/src/codecs/ip/cd_icmp4.cc"
grep -q 'get_network_policy()->icmp_checksums() && !valid_checksum_from_daq' "$SRC/src/codecs/ip/cd_icmp6.cc"

# ---- trackable pins (vectors are OUTPUT of the MEASURED first run; the
# md5+wc pins below came from THAT run -- build.sh DRIFTS-then-refuses, it
# NEVER fabricates. 17p: no arithmetic/forecast typed.) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 93
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 13
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "fd1855e10e08eedcc6598de7ee034d0e"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "2fb9dc4570a0160451f8399d22736a60"

# ---- frozen-donor direct-md5 census (same 15-face face as small4:415-435;
# the DIRECT face -- tun/eth/ext -eq 24 ls-asserts stay UN-chased by design) ----
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
# gre GATE anchor: the runner tail the 18g chain rides (VERBATIM face pin)
test "$(md5sum /opt/data/snort3-rust/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" /opt/data/snort3-rust/tools/gre_harness/gate.txt   # tail face VERBATIM (the file ends with the ====== + tail + blank)

# ---- TWO-LINEAGE census loop (MEASURED, never typed; THIS row adds ZERO
# gate.txt so the 25-tracked face is UNDISTURBED BY DESIGN): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY
# name-pin census re-armed (the row's dir name MUST stay family-free per gre
# :41 ip-name pre-ban; a future row's name colliding = loud):
test "$(ls -d /opt/data/snort3-rust/tools/udp_harness /opt/data/snort3-rust/tools/icmp_harness /opt/data/snort3-rust/tools/udpicmp_harness 2>/dev/null | wc -l)" -eq 0

# ---- STAGEABLES echo + .gitignore PROOF (git ls-files, NEVER pre-typed
# arithmetic, 17p): the NON-ignored face of this dir = exactly the 7
# stageable files (small4's 6 MINUS-NOTHING + ONE new witness face).
# FACE POSTURE (18i re-rule): PRE-commit these 7 are UNTRACKED (--others
# face, the small4 ruling); POST-commit the session-start ritual re-runs
# the SAME proof against the LANDED face -- --others goes 7 -> 0 (the
# honest rc1 receipts build_{H,I}: the pre-commit face stranded the
# landed face, a THIRD guard revision, recorded not hidden). Both faces
# assert EXACTLY 7 against the SAME name census. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/daq3_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/daq3_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 7
for f in PLAN.md build.sh probe.cc probe_dec.cc vectors.txt vectors_faceA.txt witness_daq.cc; do
    echo "$face" | grep -q "tools/daq3_harness/$f$"
done
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/daq.h copy/cd_udp.o o2/cd_udp.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_18f.o witness_conf.o witness_daq.o witness_daq2.o vectors_O0.txt vectors_faceA_O2.txt nm_U_cd_udp.txt E4_cd_udp.txt E4_nodaq_udp.txt L1_link_face.txt L1_undefined.txt drift_ipv6_api_face.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/daq3_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/daq3_harness/$f NOT ignored"; exit 1; }
done
# no STAGED churn: index EMPTY. Tracked-MODIFIED face (lineage-honest,
# this row's ruling): EVERY dirty tracked file must be one of THIS row's
# OWN 15 committed paths -- passes at every real face (pre-port: the
# .gitignore block + mod.rs wiring; docs pass: + the two docs; POST-
# commit session-start: EMPTY; a same-pass follow-up: the guard file
# itself), and fires LOUDLY on any face touching another row's/committed
# lineage file. Rows NEVER rewrite history: this comment records the
# face posture.
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
rowface='^\.gitignore$|^src/codecs/mod\.rs$|^src/codecs/(cd_udp|cd_icmp4|cd_icmp6)\.rs$|^tests/daq3_parity_test\.rs$|^PORTING_PLAN\.md$|^KNOWN DEVIATIONS\.md$|^tools/daq3_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|vectors\.txt|vectors_faceA\.txt|witness_daq\.cc)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface")"

echo "row-TU nm census (MEASURED, never typed): udp=$(wc -l < "$H/nm_U_cd_udp.txt") icmp4=$(wc -l < "$H/nm_U_cd_icmp4.txt") icmp6=$(wc -l < "$H/nm_U_cd_icmp6.txt") union=$(wc -l < "$H/nm_U_union.txt") (tunnel_bypass 0/0/0 -- bypass axis ZERO)"
echo "witness delta re-measured: L1 undefined-EXACTLY-4 (daq x2 + get_bits + get_network_policy) -> +witness_daq GREEN (the lineage's FIRST graft-borne fn witnesses; NEXT :183 'ZERO new' HALF WRONG at this face, bypass axis STANDS)"
echo "copy tree find-count (MEASURED): $(find "$C" -type f ! -name '*.o' | wc -l) (96 donor + 3 fresh hdrs + 1 graft + 3 row TUs)"
echo "E4 adaptation: 3 fresh hdr cps + graft, stripped-tree flipped-asserts (daq.h x3 MUST die = pure-defer DEAD; udp.h x1; icmp4.h x2 cross-rider; icmp6.h x1) + restored rc0 x3 EVERY build"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED here; tracked gate.txt = 1, ls-files)"
echo "DAQ3_HARNESS_OK vectors=$( [ -e "$H/vectors.txt" ] && wc -l < "$H/vectors.txt" || wc -l < "$H/vectors_O0.txt") faceA=$( [ -e "$H/vectors_faceA.txt" ] && wc -l < "$H/vectors_faceA.txt" || wc -l < "$H/vectors_faceA_O0.txt") gates=0"
