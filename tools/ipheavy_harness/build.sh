#!/usr/bin/env bash
# ipheavy_harness -- row 20a: the codecs/ip HEAVIES TRIO cd_ipv4 790 def01f1d
# / cd_ipv6 733 89267b1d / cd_tcp 839 144c4275 = 2,362 L, ONE row, verbatim
# (the q4 banked OWN-ROW; the trio closes chapter 18 == 100% CODECS CLOSED:
# the docs ledger 11,289 non-test L face re-measured EVERY build, the trio
# is the LAST 2,362 of the .cc book 10,710/41 non-test TU face).
# THE LANDMINE ROW: the vocab witness_stubs.cc trio extern-defs AT :11-:13
# (the static stub BaseApi consts stand at :7-:9 -- the orchestrator-cor-
# rected cite; :11-:13 = the EXTERN-DEF lines the retirement diff drops) ARE
# the trio tables. RETIREMENT happens ONLY in THIS row's OWN stubs_20a copy
# (frozen vocab MINUS :11-:13 PLUS the marker row citing the TRUE tables
# cd_ipv4[] :785 / cd_ipv6[] :728 / cd_tcp[] :834); the frozen donors (vocab
# 9fad7e9d + ext a700f77e) and their vectors (vocab 5da70e82 :25-:27 + the
# SECOND pin face ext vectors_faceII.txt :2-:4 cdaa92df) are NEVER touched,
# md5-asserted UNDISTURBED ladder head AND tail. Naive co-link receipt = EX-
# ACTLY-3 'multiple definition' face; post-retirement = dup 0 + nm surviving
# stub table EXACTLY-1 (cd_hopopts) -- the inverted dup-symbol law of 17y.
# GRAFT-EXTENSION #4 (copy-LOCAL heredoc ONLY; the trio DEMANDS it): daq.h
# pdd +l3_checksum/l3/ipv4/ipv6/tcp bits + l3_offset + NAPTInfo_t src/dst_
# addr + family accessors (use-sites cd_ipv4.cc:137/:140 cd_tcp.cc:159
# cd_ipv4.cc:250-251 cd_ipv6.cc:216-217) + daq_dlt.h DLT_IPV4 228/DLT_IPV6
# 229 (libpcap-master CITE, SYNTHETIC, NEVER ABI truth) + packet.h RE-POINT
# flowz/flow_fwd.h -> flow/flow.h (the flowz decoy class Flow REDEFINES).
# Masters daq.h 73fdbc39 / daq_common f683749c + INHERITED v2 fead0027 + v3
# daq.h 0f7016a6 + mpls-era ext2 9b603f8f md5-asserted UNDISTURBED ladder
# HEAD AND TAIL; the ext#4 NEVER promoted to repo (row 20 re-cites the real
# SDK). The daq.h-DROP face INVERTS at this row: pre-18o mpls SURVIVED the
# drop rc0; here ALL THREE TUs die at cc:25 -- the honest inversion receipt.
# THE WITNESS FACE (MEASURED, never pre-picked): own L1 = EXACTLY-10 distinct
# undefined (stubs_18d + witness_18f/conf + real chain + stubs_20a WITHOUT
# the own pair); definer census find-0 across ALL tracked harness .o -> the
# own-new witness DUO witness_ipvars.cc (3 sfvar arms) + witness_opts.cc
# (LogIpOptions/LogTcpOptions/get_held_pkt_seq + the FOUR IpOptionIterator
# arms). Backbone array STAYS EXACTLY 10 (own witnesses are SYMBOL faces).
# THE ZERO-GATE row: trio TEST_CASE/TEST_GROUP/UNIT_TEST/CppUTest grep-0 x3
# (26th straight); src/codecs/ip/test/checksum_test.cc 201 L = the recorded
# test-side CANDIDATE for checksum.h (already ported, csum era),CppUTest
# host headers find-0 = COMPILE-BLOCKED (the 19a posture), NEVER landed as
# gate artifacts. vectors: the trio sid bands {1-6,404-449} {270-296}
# {45-59,400-446} FRESH material; the 170-176 EV-34 face NEVER lands in
# THIS row's vectors (census 0) and the mpls vectors stay BYTE-FROZEN.
set -euo pipefail
SRC=/opt/data/snort3-src
R=/opt/data/snort3-rust
H=$(cd "$(dirname "$0")" && pwd)
D3=$R/tools/daq3_harness
L4=$R/tools/link4_harness
MPL=$R/tools/mpls_harness            # THE donor (18o 130-file tree)
TUN=$R/tools/tun_harness
ETH=$R/tools/eth_harness
EXT=$R/tools/ext_harness
VOC=$R/tools/vocab_harness
IP=$SRC/src/codecs/ip
C=$H/copy
G=$H/gen                            # scratch compile dir (ignored)

# ---- ground identity (the OWNING TUs pinned by OWN md5 + wc, MEASURED) ----
test "$(md5sum "$IP/cd_ipv4.cc" | awk '{print $1}')" = "def01f1df71ab250896da1764f6c0f92"
test "$(md5sum "$IP/cd_ipv6.cc" | awk '{print $1}')" = "89267b1d6d4f583434af207a14f90f56"
test "$(md5sum "$IP/cd_tcp.cc"  | awk '{print $1}')" = "144c427504a13c58dc117bcf93f6a604"
test "$(wc -l < "$IP/cd_ipv4.cc")" -eq 790
test "$(wc -l < "$IP/cd_ipv6.cc")" -eq 733
test "$(wc -l < "$IP/cd_tcp.cc")" -eq 839
# chapter ledger FACE CLOSES at this row: the trio = the LAST 2,362 of the
# non-test .cc book (10,710 L / 41 TU face) + the docs 11,289 non-test .cc+.h
test "$(( $(wc -l < "$IP/cd_ipv4.cc") + $(wc -l < "$IP/cd_ipv6.cc") + $(wc -l < "$IP/cd_tcp.cc") ))" -eq 2362
test "$(find "$SRC/src/codecs" -name '*.cc' ! -path '*/test/*' -exec cat {} + | wc -l)" -eq 10710
test "$(find "$SRC/src/codecs" \( -name '*.cc' -o -name '*.h' \) ! -path '*/test/*' -exec cat {} + | wc -l)" -eq 11289   # the PORTING_PLAN row-18 docs face
test "$(find "$SRC/src/codecs" -path '*/test/*' -name '*.cc' -exec cat {} + | wc -l)" -eq 625

# ---- THE zero-gate census (MEASURED EVERY BUILD, never typed) ----
for f in cd_ipv4.cc cd_ipv6.cc cd_tcp.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|UNIT_TEST\|CppUTest' "$IP/$f" || true)" -eq 0
done
test -e "$IP/test/checksum_test.cc"                       # the CANDIDATE face (vs link find-0)
test "$(wc -l < "$IP/test/checksum_test.cc")" -eq 201
test "$(grep -c add_cpputest "$IP/CMakeLists.txt" || true)" -eq 0
test "$(grep -c add_cpputest "$IP/test/CMakeLists.txt")" -eq 1
test "$(find /usr/include /usr/local/include -maxdepth 2 -name 'CppUTest' -type d 2>/dev/null | wc -l)" -eq 0   # the COMPILE-BLOCKED honest posture (19a face)

# ---- hidden table / NAME faces (sed census PINs -- PLAN sec-4 corrected) ----
test "$(sed -n '47p' "$IP/cd_ipv4.cc")" = '#define CD_IPV4_NAME "ipv4"'
test "$(sed -n '49p' "$IP/cd_ipv4.cc")" = '#define CD_IPV4_HELP ADD_DLT(CD_IPV4_HELP_STR, DLT_IPV4)'
test "$(sed -n '785p' "$IP/cd_ipv4.cc")" = 'const BaseApi* cd_ipv4[] ='
test "$(sed -n '210p' "$IP/cd_ipv4.cc")" = '#if 0'                            # DEAD block :210-:217 cite-NEVER-land
test "$(sed -n '379p' "$IP/cd_ipv4.cc")" = '#ifdef WORDS_BIGENDIAN'           # msb loopback arm (host LE = the measured arm)
test "$(grep -c '^[[:space:]]*#if 0' "$IP/cd_ipv4.cc")" -eq 1
test "$(grep -c '^[[:space:]]*#ifdef BUILDING_SO' "$IP/cd_ipv4.cc")" -eq 1
test "$(sed -n '37p' "$IP/cd_ipv6.cc")" = '#define CD_IPV6_NAME "ipv6"'
test "$(sed -n '39p' "$IP/cd_ipv6.cc")" = '#define CD_IPV6_HELP ADD_DLT(CD_IPV6_HELP_STR, DLT_IPV6)'
test "$(sed -n '728p' "$IP/cd_ipv6.cc")" = 'const BaseApi* cd_ipv6[] ='
test "$(grep -c 'WORDS_BIGENDIAN' "$IP/cd_ipv6.cc" || true)" -eq 0            # WORDS_BIGENDIAN :379 FACE: NEVER here (honest contrast face)
test "$(grep -c '^[[:space:]]*#if 0' "$IP/cd_ipv6.cc" || true)" -eq 0
test "$(grep -c '^[[:space:]]*#ifdef BUILDING_SO' "$IP/cd_ipv6.cc")" -eq 1
test "$(sed -n '42p' "$IP/cd_tcp.cc")" = '#define CD_TCP_NAME "tcp"'
test "$(sed -n '43p' "$IP/cd_tcp.cc")" = '#define CD_TCP_HELP "support for transmission control protocol"'   # NO-ADD_DLT HELP asymmetry
test "$(sed -n '834p' "$IP/cd_tcp.cc")" = 'const BaseApi* cd_tcp[] ='         # UNCONDITIONAL table
test "$(grep -c 'BUILDING_SO' "$IP/cd_tcp.cc")" -eq 1                          # grep-c LIES (the hit is the COMMENT :831)
test "$(grep -c '^[[:space:]]*#ifdef BUILDING_SO' "$IP/cd_tcp.cc" || true)" -eq 0   # the anchored truth face (PLAN q4)
test "$(sed -n '831p' "$IP/cd_tcp.cc")" = '//#ifdef BUILDING_SO'
test "$(grep -c '^[[:space:]]*#if 0' "$IP/cd_tcp.cc" || true)" -eq 0
# WORDS_BIGENDIAN :45-:51 the naptha pair (LE arm = THIS host, seed-drift tripwire) + t-arms:
test "$(sed -n '49p' "$IP/cd_tcp.cc")" = '    const uint32_t naptha_seq = 0x2a7b5c00;'
test "$(sed -n '50p' "$IP/cd_tcp.cc")" = '    const uint16_t naptha_id = 0x9d01;'
test "$(sed -n '776p' "$IP/cd_ipv4.cc")" = '    ipv4_codec_tinit, // tinit'    # the ONLY non-null t-arm trio face
test "$(sed -n '777p' "$IP/cd_ipv4.cc")" = '    ipv4_codec_tterm, // tterm'
test "$(sed -n '719,720p' "$IP/cd_ipv6.cc" | grep -c 'nullptr, // t')" -eq 2
test "$(sed -n '825,826p' "$IP/cd_tcp.cc" | grep -c 'nullptr, // t')" -eq 2
# CMakeLists static-build face: trio add_dynamic_module lines COMMENTED, live in add_library face:
test "$(grep -c '^#    add_dynamic_module(cd_ipv4' "$IP/CMakeLists.txt")" -eq 1
test "$(grep -c '^#    add_dynamic_module(cd_ipv6' "$IP/CMakeLists.txt")" -eq 1
test "$(grep -c '^#    add_dynamic_module(cd_tcp'  "$IP/CMakeLists.txt")" -eq 1
grep -q 'add_library( ip_codecs OBJECT' "$IP/CMakeLists.txt"
# Rust side NEVER here (C-side-only row): stub records FLIP face STILL pending, cite-pin:
test "$(grep -c 'CD_IPV4_STUB\|CD_IPV6_STUB\|CD_TCP_STUB' "$R/src/codecs/codec_api.rs")" -eq 6   # the FLIP NEVER lands silent; landing child re-cites
test -z "$(ls "$R/src/codecs/ip" 2>/dev/null || true)"                          # ip DIR find-0 = the row-21 territory face

# ---- FROZEN-donor census HEAD (retirement NEVER touches these) ----
test "$(md5sum "$VOC/witness_stubs.cc" | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(sed -n '11,13p' "$VOC/witness_stubs.cc" | grep -c 'extern const BaseApi\* cd_')" -eq 3   # the TRUE retirement cut face
test "$(sed -n '7,9p' "$VOC/witness_stubs.cc" | grep -c 'static const BaseApi stub_')" -eq 3     # the :7-:9 static-table cite (orchestrator correction)
test "$(md5sum "$EXT/stubs_18e.cc" | awk '{print $1}')" = "a700f77ef7f1ff718f1ae9626f10b826"
test "$(sed -n '11,13p' "$EXT/stubs_18e.cc" | grep -c 'extern const BaseApi\* cd_')" -eq 3
test "$(md5sum "$VOC/vectors.txt" | awk '{print $1}')" = "5da70e82416b6f769af8177d859331e7"
test "$(sed -n '25,27p' "$VOC/vectors.txt" | grep -c '^LOAD cd_')" -eq 3   # the frozen stub LOAD pin (:25-:27 cd_ipv4/cd_ipv6/cd_tcp_stub)
grep -q '^LOADS 5$' "$VOC/vectors.txt"
test "$(md5sum "$EXT/vectors_faceII.txt" | awk '{print $1}')" = "cdaa92dfb8bdb35ce1ffaa41c1ae3fc4"   # the SECOND frozen pin face :2-:4
test "$(sed -n '2,4p' "$EXT/vectors_faceII.txt" | grep -c '^LOAD cd_')" -eq 3
# daq masters + INHERITED faces (the ext#4 NEVER mutates these):
test "$(md5sum "$D3/copy/daq.h"       | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$L4/copy/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"
test "$(md5sum "$MPL/copy/daq.h"       | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"    # graft-v3 INHERITED
test "$(md5sum "$MPL/copy/daq_common.h" | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"   # mpls-era ext2 face
for f in "$D3/copy/daq.h" "$MPL/copy/daq.h"; do
    test "$(grep -c 'l3_checksum' "$f" || true)" -eq 0                        # ext#4 fields NEVER promoted
done
# mpls frozen tail (the DIRECT predecessor byte-ident echo):
test "$(md5sum "$MPL/vectors.txt" | awk '{print $1}')" = "b4b660e448703b603755a0049c6a2052"
test "$(md5sum "$MPL/vectors_faceA.txt" | awk '{print $1}')" = "3066fc335fb21777891271b9c7b152c5"
test "$(wc -l < "$MPL/vectors.txt")" -eq 54
test "$(wc -l < "$MPL/vectors_faceA.txt")" -eq 17
grep -q "MPLS_LINK_DONE" "$MPL/build.sh"

# ---- copy tree = mpls-18o 130-tree REUSE clone (the graft-v3 daq.h + ext2
# daq_common.h ride INHERITED; the flow/flow.h + safec.h PRE-PAY riders pay
# off at THIS packet.h re-point row) ----
test -e "$MPL/copy/codecs/link/cd_mpls.cc" -a -e "$MPL/copy/config.h" || { echo "DONOR DEAD: tools/mpls_harness/copy pruned -- re-run the 18o mpls row by hand (NEVER auto-heal from this script)"; exit 1; }
rm -rf "$C" "$G"; cp -a "$MPL/copy" "$C"; mkdir -p "$G"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 130                    # donor face MEASURED (the 18o landing head)
# fresh-cp ABSENCE face (the 7 cps are NOT resident):
for h in parse_ip.h sf_ipvar.h ipv4_options.h tcp_options.h stream.h prune_stats.h packet_time.h; do
    test "$(find "$C" -name "$h" | wc -l)" -eq 0
done
test "$(find "$C" -name 'flow.h' -path '*flow/*' | wc -l)" -eq 1             # the pre-paid rider (packet.h re-point target) resident
# THE fresh 7 cps (wc+md5 PIN at cp time, cmp-verified -- trio set, PLAN 2.2):
mkdir -p "$C/parser" "$C/sfip" "$C/protocols" "$C/stream" "$C/flow" "$C/time" "$C/codecs/ip"
cp "$SRC/src/parser/parse_ip.h" "$C/parser/parse_ip.h";               cmp -s "$C/parser/parse_ip.h" "$SRC/src/parser/parse_ip.h"
test "$(wc -l < "$C/parser/parse_ip.h")" -eq 28   # b7a32796 (ipv4,ipv6,tcp)
test "$(md5sum "$C/parser/parse_ip.h" | awk '{print $1}')" = "b7a327967e1f6a5303de363b77d56611"
cp "$SRC/src/sfip/sf_ipvar.h" "$C/sfip/sf_ipvar.h";                   cmp -s "$C/sfip/sf_ipvar.h" "$SRC/src/sfip/sf_ipvar.h"
test "$(wc -l < "$C/sfip/sf_ipvar.h")" -eq 116  # 90b4aa20 (ipv4,ipv6,tcp)
test "$(md5sum "$C/sfip/sf_ipvar.h" | awk '{print $1}')" = "90b4aa20110f66b690da1fa38cbfaae6"
cp "$SRC/src/protocols/ipv4_options.h" "$C/protocols/ipv4_options.h"; cmp -s "$C/protocols/ipv4_options.h" "$SRC/src/protocols/ipv4_options.h"
test "$(wc -l < "$C/protocols/ipv4_options.h")" -eq 150                       # cc4f7b4a (ipv4)
test "$(md5sum "$C/protocols/ipv4_options.h" | awk '{print $1}')" = "cc4f7b4ab7c966ae5b516789a32ae9f1"
cp "$SRC/src/protocols/tcp_options.h" "$C/protocols/tcp_options.h";   cmp -s "$C/protocols/tcp_options.h" "$SRC/src/protocols/tcp_options.h"
test "$(wc -l < "$C/protocols/tcp_options.h")" -eq 181                       # 68f3fc3b (tcp)
test "$(md5sum "$C/protocols/tcp_options.h" | awk '{print $1}')" = "68f3fc3b024290ebbb928c7a217e2c47"
cp "$SRC/src/stream/stream.h" "$C/stream/stream.h";                   cmp -s "$C/stream/stream.h" "$SRC/src/stream/stream.h"
test "$(wc -l < "$C/stream/stream.h")" -eq 288                              # c6bf6b8d (tcp)
test "$(md5sum "$C/stream/stream.h" | awk '{print $1}')" = "c6bf6b8deca24e2eea9273021b6338d3"
cp "$SRC/src/flow/prune_stats.h" "$C/flow/prune_stats.h";             cmp -s "$C/flow/prune_stats.h" "$SRC/src/flow/prune_stats.h"
test "$(wc -l < "$C/flow/prune_stats.h")" -eq 159                           # 26f386d3 (stream.h rider)
test "$(md5sum "$C/flow/prune_stats.h" | awk '{print $1}')" = "26f386d3e05de5fa2600ea92a7acd7fd"
cp "$SRC/src/time/packet_time.h" "$C/time/packet_time.h";             cmp -s "$C/time/packet_time.h" "$SRC/src/time/packet_time.h"
test "$(wc -l < "$C/time/packet_time.h")" -eq 38                            # 52b92736 (stream.h rider)
test "$(md5sum "$C/time/packet_time.h" | awk '{print $1}')" = "52b9273657d8fc7d96292f2476ded5c4"
# the trio VERBATIM (NEVER one char of these files is edited anywhere at this row):
cp "$IP/cd_ipv4.cc" "$C/codecs/ip/cd_ipv4.cc"; cmp -s "$C/codecs/ip/cd_ipv4.cc" "$IP/cd_ipv4.cc"
cp "$IP/cd_ipv6.cc" "$C/codecs/ip/cd_ipv6.cc"; cmp -s "$C/codecs/ip/cd_ipv6.cc" "$IP/cd_ipv6.cc"
cp "$IP/cd_tcp.cc"  "$C/codecs/ip/cd_tcp.cc";  cmp -s "$C/codecs/ip/cd_tcp.cc"  "$IP/cd_tcp.cc"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140                   # 130 donor + 7 cps + 3 TUs (RE-DERIVED face)

GXX0="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"
GXXA="g++ -std=c++17 -DNDEBUG -O2 -w -I$C"

# ---- THE EXT#4 LADDER (re-run EVERY build; graft-v3 law: COPY-LOCAL heredoc
# ONLY, masters md5-asserted UNDISTURBED head AND tail). ARM #1 (pre-ext):
# the 7-cp tree MUST die at the MEASURED error counts: ----
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_ipv4.cc" -o /dev/null 2> "$H/E4_preext_cd_ipv4.txt"; then
    echo "EXT-FACE DEAD: cd_ipv4 compiled on the graft-v3 daq.h -- the pdd/NAPT closure gap is wrong"; exit 1
fi
test "$(grep -c 'error:' "$H/E4_preext_cd_ipv4.txt")" -eq 10                # pdd l3/ipv4/l3_offset/NAPT-addr/FAMILY face
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_ipv6.cc" -o /dev/null 2> "$H/E4_preext_cd_ipv6.txt"; then
    echo "EXT-FACE DEAD: cd_ipv6 compiled pre-ext"; exit 1
fi
test "$(grep -c 'error:' "$H/E4_preext_cd_ipv6.txt")" -eq 5                 # DLT_IPV6 + the 4 NAPT member/accessor arms
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_tcp.cc" -o /dev/null 2> "$H/E4_preext_cd_tcp.txt"; then
    echo "EXT-FACE DEAD: cd_tcp compiled pre-ext"; exit 1
fi
test "$(grep -c 'error:' "$H/E4_preext_cd_tcp.txt")" -eq 2
grep -q "flowz/flow_fwd.h:11:.*redefinition of .class snort::Flow" "$H/E4_preext_cd_tcp.txt"   # the packet.h re-point demand face
grep -q "has no member named .tcp" "$H/E4_preext_cd_tcp.txt"
# ARM #2: the daq.h EXTENSION heredoc (51 L, ext#4 face 97bca757 -- my own
# row-20h MEASURED analog of the ext2 9b603f8f law; SYNTHETIC SDK, NEVER ABI):
cat > "$C/daq.h" <<'EOFEXT4'
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
    struct { struct { unsigned l3_checksum : 1;
                      unsigned l3           : 1;
                      unsigned l4_checksum : 1;
                      unsigned ipv4        : 1;
                      unsigned ipv6        : 1;
                      unsigned tcp         : 1;
                      unsigned udp         : 1;
                      unsigned icmp        : 1;
                      unsigned l4          : 1; } bits; } flags;
    int32_t l3_offset;            // cd_ipv4.cc:140/:143
    int32_t l4_offset;            // :268/:137/:130 vs OFFSET_INVALID
};
struct DAQ_NAPTInfo_t
{
    uint32_t src_addr;            // ext#4: cd_ipv4.cc:250 / cd_ipv6.cc:216
    uint32_t src_port;            // cd_udp.cc:422-424 ntohs
    uint32_t dst_addr;            // ext#4
    uint32_t dst_port;
    uint8_t  ip_layer;
    uint8_t  src_addr_family;     // ext#4 daq_napt_info_src_addr_family
    uint8_t  dst_addr_family;            // :421 vs codec.ip_layer_cnt
};
struct _daq_msg;                  // fwd = framework/codec.h :38 face (same TU)
const void*    daq_msg_get_meta(const struct _daq_msg*, DAQ_MetaType);
const uint8_t* daq_msg_get_data(const struct _daq_msg*);

// row18n graft-v3 EXTENSION CANDIDATE (harness-copy-LOCAL; daq3 master NEVER
// mutated): vlan.cc :141/:142 decl face MEASURED grep-0 in master -- DAQ_PktHdr_t
// ALREADY rides graft daq_common.h :4 so ONLY 2 DECL rows needed.
const struct DAQ_PktHdr_t* daq_msg_get_pkthdr(const struct _daq_msg*);
#define DAQ_PKT_FLAG_IGNORE_VLAN 0x0000000000000040
static inline uint8_t daq_napt_info_src_addr_family(const struct DAQ_NAPTInfo_t* n) { return n->src_addr_family; }
static inline uint8_t daq_napt_info_dst_addr_family(const struct DAQ_NAPTInfo_t* n) { return n->dst_addr_family; }
#endif
EOFEXT4
test "$(wc -l < "$C/daq.h")" -eq 51
test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"   # MY ext#4 face (the row-20h MEASURED bank), md5-EXACT
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"   # INHERITED ext2 face NEVER re-authored
# ARM #3: daq_dlt.h EXTENSION heredoc (228/229 = libpcap-master CITE face,
# SYNTHETIC pin -- row 20 re-cites the real SDK; the HELP(DLT n) vectors
# faces ride framework/codec.h:52 ADD_DLT + cd_ipv4.cc:152 / cd_ipv6.cc:123):
cat > "$C/daq_dlt.h" <<'EOFDLT'
#pragma once
// witness graft (fmod daq_common.h recipe): DAQ SDK header NOT in tree (fe29cbe) nor on host.
// DLT_RAW 12 CITE (18c): libpcap pcap/dlt.h :112-:114. 18c CITED the android.googlesource
// mirror -- that URL 404s as of THIS 18d pass; re-fetched the the-tcpdump-group/libpcap
// MASTER face (raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap/dlt.h,
// 1741 L): SAME :112 #define DLT_RAW 14 + :114 #define DLT_RAW 12 arms -- cite CONFIRMED.
#define DLT_RAW 12
// 18d EXTENSION (graft SECOND consumer: cd_eth.cc:38 ADD_DLT x2 + :76-:77):
// DLT_EN10MB 1 = master dlt.h :68; DLT_PPP_ETHER 51 = master dlt.h :243 (fetched THIS pass).
#define DLT_EN10MB 1
#define DLT_PPP_ETHER 51

#define DLT_IPV4 228
#define DLT_IPV6 229
EOFDLT
test "$(wc -l < "$C/daq_dlt.h")" -eq 14
test "$(md5sum "$C/daq_dlt.h" | awk '{print $1}')" = "e8a39bf30226fd7bccc1e86317c730db"   # MEASURED first-seed face (the ext2 9b603f8f analog law)
# ARM #4 (PLAN 2.3c): packet.h RE-POINT sed-assert (flowz decoy -> the real
# flow/flow.h rider; MEASURED cd_tcp rc0 after):
test "$(md5sum "$C/protocols/packet.h" | awk '{print $1}')" = "ee0d0239e11f3563410bd1b9a25dddb7"   # the INHERITED donor face pre-sed
sed -i 's|#include "flowz/flow_fwd.h"|#include "flow/flow.h"|' "$C/protocols/packet.h"
test "$(grep -c 'flowz/flow_fwd.h' "$C/protocols/packet.h" || true)" -eq 0
test "$(grep -c '#include "flow/flow.h"' "$C/protocols/packet.h")" -eq 1
test "$(md5sum "$C/protocols/packet.h" | awk '{print $1}')" = "1be562b2779b7b8d21cdf6122893645a"   # the re-pointed face MEASURED
# post-ext rc0 x3 (syntax-only; the -c faces ride the compile stage):
$GXX0 -fsyntax-only "$C/codecs/ip/cd_ipv4.cc" 2> "$H/E4_postext_cd_ipv4.txt"
test ! -s "$H/E4_postext_cd_ipv4.txt"
$GXX0 -fsyntax-only "$C/codecs/ip/cd_ipv6.cc" 2> "$H/E4_postext_cd_ipv6.txt"
test ! -s "$H/E4_postext_cd_ipv6.txt"
$GXX0 -fsyntax-only "$C/codecs/ip/cd_tcp.cc"  2> "$H/E4_postext_cd_tcp.txt"
test ! -s "$H/E4_postext_cd_tcp.txt"
# masters + INHERITED faces UNDISTURBED at the ladder TAIL (the heredocs
# wrote ONLY the copy-local faces):
test "$(md5sum "$D3/copy/daq.h"        | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
test "$(md5sum "$D3/copy/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(md5sum "$L4/copy/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"
test "$(md5sum "$MPL/copy/daq.h"       | awk '{print $1}')" = "0f7016a6fcf061c844897af44b9a7dc6"
test "$(md5sum "$MPL/copy/daq_common.h" | awk '{print $1}')" = "9b603f8f91e5003f907838415633b685"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 140   # ext heredocs NEVER change the file count

# ---- E4 LOCALIZATION ARMS BOTH WAYS: (a) the stripped-donor arm -I src ONLY
# MUST die rc1 at the daq.h:25 chained fatal TRIO face (the C14 face; NO
# graft on the -I src face); (b) IN-TREE drop walls MEASURED + the daq.h-drop
# SURVIVALS->KILLS INVERSION at this row (18o mpls survived rc0; here the
# trio consumes the graft -- the honest inversion receipt) ----
GXXD="g++ -std=c++17 -DNDEBUG -O0 -w -I$SRC/src"
for x in cd_ipv4 cd_ipv6 cd_tcp; do
    if $GXXD -fsyntax-only "$IP/$x.cc" 2> "$H/E4_donorsrc_$x.txt"; then
        echo "E4 LOCALIZATION DEAD: $x compiled on the -I src ONLY arm"; exit 1
    fi
    head -1 "$H/E4_donorsrc_$x.txt" | grep -q "fatal error: daq.h: No such file"
    grep -q "$x.cc:25:10" "$H/E4_donorsrc_$x.txt"       # the include-line face ALL THREE (:25 common head)
done
drop_wall () {  # $1 header  $2 TU  $3 expect-grep
    mv "$C/$1" "$H/.e4_hold_$(basename "$1")"
    if $GXX0 -fsyntax-only "$C/codecs/ip/$2.cc" -o /dev/null 2> "$H/E4_drop_$2_$(basename "$1").txt"; then
        echo "E4 flip BROKE: $2 compiled WITHOUT the fresh $1 cp"; exit 1
    fi
    grep -q "$3" "$H/E4_drop_$2_$(basename "$1").txt" || { echo "E4 wall face WRONG for $2 without $1"; exit 1; }
    mv "$H/.e4_hold_$(basename "$1")" "$C/$1"
    cmp -s "$C/$1" "$SRC/src/$1"
}
drop_wall parser/parse_ip.h        cd_ipv4 "fatal error: parser/parse_ip.h: No such file"
drop_wall parser/parse_ip.h        cd_ipv6 "fatal error: parser/parse_ip.h: No such file"
drop_wall parser/parse_ip.h        cd_tcp  "fatal error: parser/parse_ip.h: No such file"
drop_wall sfip/sf_ipvar.h          cd_ipv4 "fatal error: sfip/sf_ipvar.h: No such file"
drop_wall sfip/sf_ipvar.h          cd_ipv6 "fatal error: sfip/sf_ipvar.h: No such file"
drop_wall sfip/sf_ipvar.h          cd_tcp  "fatal error: sfip/sf_ipvar.h: No such file"
drop_wall protocols/ipv4_options.h cd_ipv4 "cd_ipv4.cc:38:10: fatal error: protocols/ipv4_options.h"
drop_wall protocols/tcp_options.h  cd_tcp  "cd_tcp.cc:33:10: fatal error: protocols/tcp_options.h"
drop_wall stream/stream.h          cd_tcp  "cd_tcp.cc:35:10: fatal error: stream/stream.h"
drop_wall flow/prune_stats.h       cd_tcp  "stream/stream.h:32:10: fatal error: flow/prune_stats.h"   # NESTED rider wall (the clock_defs-era face)
drop_wall time/packet_time.h       cd_tcp  "stream/stream.h:35:10: fatal error: time/packet_time.h"   # NESTED rider wall
# THE INVERSION face (the row's E4 headline): daq.h-drop KILLS all THREE here
# (contrast 18o where the SAME drop SURVIVED rc0 -- cd_mpls NEVER named daq):
for x in cd_ipv4 cd_ipv6 cd_tcp; do
    mv "$C/daq.h" "$H/.e4_hold_daq.h"
    if $GXX0 -fsyntax-only "$C/codecs/ip/$x.cc" -o /dev/null 2> "$H/E4_nodaq_$x.txt"; then
        echo "E4 INVERSION DEAD: $x SURVIVED the daq.h drop -- the ext#4 consumption face is wrong"; exit 1
    fi
    head -1 "$H/E4_nodaq_$x.txt" | grep -q "fatal error: daq.h: No such file"
    mv "$H/.e4_hold_daq.h" "$C/daq.h"
    test "$(md5sum "$C/daq.h" | awk '{print $1}')" = "97bca757be2863c3c1e13f5a6fde951c"
done
# packet.h NOT droppable (the ch18 chain rides it -- the direct-edge fatal):
mv "$C/protocols/packet.h" "$H/.e4_hold_packet.h"
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_tcp.cc" -o /dev/null 2> "$H/E4_nopacket_cd_tcp.txt"; then
    echo "E4 flip BROKE: cd_tcp compiled WITHOUT protocols/packet.h"; exit 1
fi
grep -q "stream/stream.h:34:10: fatal error: protocols/packet.h: No such file" "$H/E4_nopacket_cd_tcp.txt"   # the CHAINED edge face (cd_tcp.cc:35 -> stream.h:34 -> packet.h -- the header itself is NEVER a direct include of the trio)
mv "$H/.e4_hold_packet.h" "$C/protocols/packet.h"
test "$(md5sum "$C/protocols/packet.h" | awk '{print $1}')" = "1be562b2779b7b8d21cdf6122893645a"
# restored full tree rc0 EVERY build:
for x in cd_ipv4 cd_ipv6 cd_tcp; do
    $GXX0 -fsyntax-only "$C/codecs/ip/$x.cc" 2> "$H/E4_restored_$x.txt"
    test ! -s "$H/E4_restored_$x.txt"
done

# ---- THE stub RETIREMENT (the row's landmine face; OWN copy ONLY, diff-0
# ceremony): frozen vocab MINUS the 3 extern-def lines :11-:13 PLUS marker ----
sed '11,13d' "$VOC/witness_stubs.cc" > "$G/stubs_20a.cc"
printf '// RETIRED at 20a: cd_ipv4/cd_ipv6/cd_tcp stub tables (real tables ip/cd_ipv4.cc:785 / cd_ipv6.cc:728 / cd_tcp.cc:834 land them)\n' >> "$G/stubs_20a.cc"
test "$(wc -l < "$G/stubs_20a.cc")" -eq 12                                   # 14 -> 14-3+1 (the ONE atomic diff-0 retirement)
test "$(md5sum "$G/stubs_20a.cc" | awk '{print $1}')" = "21e6abf77134ee95c30cfd6599cf26b8"
diff <(sed '11,13d' "$VOC/witness_stubs.cc") <(sed '$d' "$G/stubs_20a.cc")   # the drops are EXACTLY the 3 extern-def lines

# ---- carried witnesses (tracked sources, md5 pins; witness_conf rides the
# ext tracked face -- the mpls heredoc face is BYTE-IDENT to it) ----
cp "$EXT/witness_conf.cc" "$G/witness_conf.cc"
test "$(md5sum "$G/witness_conf.cc" | awk '{print $1}')" = "4dd91018f8439d706ba666c6f18c9152"


# ---- own witness duo (the MEASURED 10-face: 3 sfvar + 2 log + 1 stream + 4
# iterator; find-0 definer census below says EVERY arm needs an own body) ----
test "$(wc -l < "$H/witness_ipvars.cc")" -eq 22
test "$(md5sum "$H/witness_ipvars.cc" | awk '{print $1}')" = "b18434c59f5a0850113f4bf1538b51cf"
test "$(wc -l < "$H/witness_opts.cc")" -eq 35
test "$(md5sum "$H/witness_opts.cc" | awk '{print $1}')" = "be040321b140644fce8d1f88007af4da"
test "$(find "$H" -maxdepth 1 -name 'witness_*.cc' | wc -l)" -eq 2   # EXACTLY-2 own-new (the duo shape; the PLAN 8-face under-count rides PLAN drift)

GXXC="g++ -std=c++17 -DNDEBUG -O0 -w -I$C"

# ---- O0 compile: the 3 row .o + donor REAL .o + probes + the witness set ----
for x in cd_ipv4 cd_ipv6 cd_tcp; do $GXXC -c "$C/codecs/ip/$x.cc" -o "$C/$x.o"; done
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"
for f in $REAL; do $GXXC -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXXC -c "$H"/probe.cc     -o "$H"/probe.o
$GXXC -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXXC -c "$D3"/witness_daq.cc  -o "$H"/witness_daq.o
$GXXC -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXXC -c "$G"/witness_conf.cc  -o "$H"/witness_conf.o
$GXXC -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o
$GXXC -c "$G"/stubs_20a.cc     -o "$H"/stubs_20a.o       # the RETIRED-copy face (stageable-adjacent gen/ artifact)
$GXXC -c "$H"/witness_ipvars.cc -o "$H"/witness_ipvars.o
$GXXC -c "$H"/witness_opts.cc   -o "$H"/witness_opts.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROW="$C/cd_ipv4.o $C/cd_ipv6.o $C/cd_tcp.o"
WIN="$H/witness_daq.o $H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o $H/stubs_20a.o"
OWN="$H/witness_ipvars.o $H/witness_opts.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0

# ---- THE nm DELTA face (the inverted dup-symbol law of 17y): the trio .o's
# own EXACTLY the 3 retired table names (TRUE-NAME D-face == file base, 18n
# equality) and the retired stubs_20a.o carries ZERO of them while its sur-
# viving EXPORTED stub table is EXACTLY-1 (cd_hopopts) ----
for x in cd_ipv4 cd_ipv6 cd_tcp; do
    test "$(nm --defined-only "$C/$x.o" | grep -cE " [DdRrBb] $x\$")" -eq 1
done
test "$(nm --defined-only "$H"/stubs_20a.o | grep -cE ' [DdBb] cd_(ipv4|ipv6|tcp)$' || true)" -eq 0      # ZERO of the retired trio names
test "$(nm --defined-only "$H"/stubs_20a.o | grep -cE ' [DdBb] cd_[a-z]+$')" -eq 1                        # EXACTLY-1 surviving stub table
test "$(nm --defined-only "$H"/stubs_20a.o | grep -cE ' [DdBb] cd_hopopts$')" -eq 1

# ---- per-TU nm U-census receipts (the NDEBUG row face) + the definer find-0
# census for the 10 witness-forcing names (every harness .o EXCLUDING this
# row's own -- the misc9 copy law) ----
for x in cd_ipv4 cd_ipv6 cd_tcp; do
    nm -C -u "$C/$x.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$x.txt"
done
test "$(grep -c 'sfvar_ip_in' "$H/nm_U_cd_ipv4.txt")" -eq 1
test "$(grep -c 'LogIpOptions' "$H/nm_U_cd_ipv4.txt")" -eq 1
test "$(grep -c 'IpOptionIterator' "$H/nm_U_cd_ipv4.txt")" -eq 4   # ctor+begin+end (3 lines) -- operator* rides the Iter face
test "$(grep -c 'LogTcpOptions\|get_held_pkt_seq' "$H/nm_U_cd_tcp.txt")" -eq 2
test "$(grep -c 'daq_msg' "$H/nm_U_cd_ipv4.txt" "$H/nm_U_cd_ipv6.txt" "$H/nm_U_cd_tcp.txt" | grep -vc ':0$')" -eq 3   # the trio CONSUME daq_msg_get_meta (the ext#4 face; contrast mpls ZERO)
defin=0
for o in "$R"/tools/*/copy/*.o "$R"/tools/*/*.o; do
    case "$o" in "$H"/*) continue;; esac
    [ -e "$o" ] || continue
    if nm --defined-only "$o" 2>/dev/null | grep -qE 'sfip_var_from_string|sfvar_free|sfvar_ip_in|LogIpOptions|LogTcpOptions|get_held_pkt_seq|IpOptionIterator'; then defin=$((defin+1)); fi
done
test "$defin" -eq 0                                                 # find-0 -> the own witness DUO is FORCED (measured, never pre-picked)

# ---- THE L1 WITNESS CENSUS (MEASURED): the trio + carried chain WITHOUT
# the own DUO dies at EXACTLY-10 distinct undefined (the PLAN 3.1 10-arm
# face); WITH the DUO the link goes GREEN (the 18 remaining -> 0 face) ----
if $GXXC $ROW $OBJS "$H"/probe.o $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: the trio linked WITHOUT the own DUO -- the EXACTLY-10 residue is wrong"; exit 1
fi
grep "undefined reference to" "$H/L1_link_face.txt" > "$H/L1_undefined.txt"
test "$(grep -oE "undefined reference to \`[^']+'" "$H/L1_link_face.txt" | sort -u | wc -l)" -eq 10
rm -f "$H/.L1_probe"
# per-file residue faces (the trio-vs-solo census, honest carry: 8/3/5 --
# the emptmain face NEVER counts `main`):
cat > "$G/.DUPMAIN.cc" <<'EOFPM'
int main(){return 0;}
EOFPM
$GXXC -c "$G/.DUPMAIN.cc" -o "$G/.DUPMAIN.o"
for x in cd_ipv4 cd_ipv6 cd_tcp; do
    $GXXC "$C/$x.o" $OBJS $WIN "$G/.DUPMAIN.o" -o /dev/null 2> "$H/L1_face_$x.txt" || true
    n=$(grep -oE "undefined reference to \`[^']+'" "$H/L1_face_$x.txt" | sort -u | wc -l)
    echo "$x-undist=$n" >> "$H/L1_undefined.txt"
    test "$n" -ge 3 && test "$n" -le 8
done
# carried witness T-census (the INHERITED faces, ZERO clone cost; backbone
# NEVER moves -- the symbol-vs-array law, 18n):
test "$(nm --defined-only "$H"/witness_18f.o | grep -c 'tunnel_bypass_enabled')" -eq 1
test "$(nm --defined-only "$H"/witness_daq.o | grep -c 'daq_msg_get_meta')" -eq 1
test "$(nm --defined-only "$H"/witness_daq.o | grep -c 'get_network_policy')" -eq 1
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0

# ---- THE LANDMINE REHEARSAL BOTH FACES (the 17y/18e pattern, LIVE):
# (a) naive co-link trio + the FROZEN vocab stub .o -> EXACTLY-3 multiple-
# definition face, ZERO other dups; (b) the post-retirement co-link here ->
# dup 0. The frozen donor NEVER re-authored; only its .o rides the rehearsal
# link face ----
cat > "$G/.DUPMAIN.cc" <<'EOFDM'
int main(){return 0;}
EOFDM
$GXXC -c "$G/.DUPMAIN.cc" -o "$G/.DUPMAIN.o"
$GXXC -c "$VOC/witness_stubs.cc" -o "$G/witness_stubs_vocab.o"
if g++ "$C/cd_ipv4.o" "$C/cd_ipv6.o" "$C/cd_tcp.o" "$G/witness_stubs_vocab.o" "$G/.DUPMAIN.o" -o "$G/.dup_probe" 2> "$H/dup_naive.txt"; then
    echo "LANDMINE FACE DEAD: the naive co-link linked -- the frozen stub trio no longer collides"; exit 1
fi
test "$(grep -c 'multiple definition' "$H/dup_naive.txt")" -eq 3
test "$(grep -oE "multiple definition of \`[^']+'" "$H/dup_naive.txt" | sort -u | wc -l)" -eq 3
grep -qE "multiple definition of .cd_ipv4" "$H/dup_naive.txt"
grep -qE "multiple definition of .cd_ipv6" "$H/dup_naive.txt"
grep -qE "multiple definition of .cd_tcp"  "$H/dup_naive.txt"
# (b) the post-retirement face (THIS row's own stubs_20a.o): dup 0 face on
# the same trio .o's + main (undefineds ride the DUO arms):
if g++ "$C/cd_ipv4.o" "$C/cd_ipv6.o" "$C/cd_tcp.o" $OBJS $WIN $OWN "$G/.DUPMAIN.o" -o "$G/.dup_retired" 2> "$H/dup_retired.txt"; then
    test "$(grep -c 'multiple definition' "$H/dup_retired.txt" || true)" -eq 0
else
    grep -q 'multiple definition' "$H/dup_retired.txt" && { echo "RETIREMENT FACE BROKE: dup survived"; exit 1; }
fi
test "$(md5sum "$VOC/witness_stubs.cc" | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"   # donor TAIL re-pin (NEVER edited by the rehearsal)
test "$(md5sum "$EXT/stubs_18e.cc"   | awk '{print $1}')" = "a700f77ef7f1ff718f1ae9626f10b826"

# ---- real-symbol defines (donor face, gre-recipe) + the trio LOAD .o face:
# the probes link the REAL tables (the frozen vocab/ext LOAD-stub faces NEVER
# ride this link -- the stubs_vocab .o appears ONLY in the dup rehearsal) ----
grep -q 'T snort::Codec::codec_event' <<< "$(nm -C --defined-only "$C"/codec.o)"
grep -q 'T snort::Module::Module' <<< "$(nm -C --defined-only "$C"/module.o)"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
test "$(nm -C --defined-only "$H"/probe.o | grep -c 'load_plugins' )" -ge 1   # the own witness body face (the print-only override)

$GXXC $ROW "$H"/probe.o      $OBJS $WIN $OWN -o "$H"/probe
$GXXC $ROW "$H"/probe_dec.o $OBJS $WIN $OWN -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
test "$(nm -C "$H"/probe_dec | grep -c 'T snort::Stream::get_held_pkt_seq' || true)" -eq 1     # the own-new T rides the DEC binary
test "$(nm -C "$H"/probe_dec | grep -c 'T snort::ip::IpOptionIterator' || true)" -ge 2         # the iterator arms LIVE (the I4I/I4J walk arms)
grep -q 'tun_witness_set_mask' <<< "$(nm -C "$H"/probe_dec)"                # the CARRIED bypass-hook observable rides DEC

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for x in cd_ipv4 cd_ipv6 cd_tcp; do $GXXA -c "$C/codecs/ip/$x.cc" -o "$O2/$x.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$D3"/witness_daq.cc -o "$O2"/witness_daq.o; $GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o
$GXXA -c "$G"/witness_conf.cc -o "$O2"/witness_conf.o; $GXXA -c "$ETH"/stubs_18d.cc -o "$O2"/stubs_18d.o
$GXXA -c "$G"/stubs_20a.cc -o "$O2"/stubs_20a.o
$GXXA -c "$H"/witness_ipvars.cc -o "$O2"/witness_ipvars.o; $GXXA -c "$H"/witness_opts.cc -o "$O2"/witness_opts.o
OB2="$O2/codec.o $O2/ip.o $O2/sf_ip.o $O2/util_cstring.o $O2/util.o $O2/module.o $O2/text_log.o"
W2="$O2/witness_daq.o $O2/witness_18f.o $O2/witness_conf.o $O2/stubs_18d.o $O2/stubs_20a.o"
OW2="$O2/witness_ipvars.o $O2/witness_opts.o"
$GXXA "$O2/cd_ipv4.o" "$O2/cd_ipv6.o" "$O2/cd_tcp.o" "$O2"/probe.o      $OB2 $W2 $OW2 -o "$H"/probe_O2
$GXXA "$O2/cd_ipv4.o" "$O2/cd_ipv6.o" "$O2/cd_tcp.o" "$O2"/probe_dec.o $OB2 $W2 $OW2 -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool b=.*->decode' "$H"/probe_dec.cc)" -eq 58    # MEASURED face (the pin follows the GREP, never the draft)
test "$(grep -c 'bool b2=.*->decode' "$H"/probe_dec.cc)" -eq 4    # the I4L/I4M/I4N/I6D-I6E twin arms
test "$(grep -c 'printf.*->decode' "$H"/probe_dec.cc || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_O0.txt || true)" -eq 0          # all-decimal hygiene
test "$(grep -c '0x' "$H"/vectors_faceA_O0.txt || true)" -eq 0

# ---- known-answer seeds: FIRST run seeds the tracked faces; later runs
# cmp-refuse drift. ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi

# ---- known-answer ladders: greps pin the MEASURED faces against GROUND
# anchors (values NEVER typed -- ground sed/enum walks; the trio sid bands
# {1-6,404-449}/{270-296}/{45-59,400-446} fire POSITIVE in THIS row's own
# vectors -- q4 NEVER-land census FLIPS AT its own row only) ----
# FACE-A (the LOAD-FLIP + HELP/DLT + T-ARM + NAPT face):
grep -q '^LOAD ipv4$'  "$FA"; grep -q '^LOAD ipv6$' "$FA"; grep -q '^LOAD tcp$' "$FA"   # the sec-3 STUB-name -> real-NAME flip
test "$(grep -c '^LOAD cd_' "$FA" || true)" -eq 0                       # ZERO stub names EVER in this row's faces
grep -q '^LOADS 3$' "$FA"
grep -q '^HELP ipv4 support for Internet protocol v4 (DLT 228)$' "$FA"  # ADD_DLT face :49 + the ext#4 228 SYNTHETIC CITE
grep -q '^HELP ipv6 support for Internet protocol v6 (DLT 229)$' "$FA"  # :39 + 229
grep -q '^HELP tcp support for transmission control protocol$' "$FA"    # :43 the NO-ADD_DLT asymmetry
grep -q '^TARM ipv4 tinit=1 tterm=1$' "$FA"                             # the ONLY non-null t-arm trio face :776/:777
grep -q '^TARM ipv6 tinit=0 tterm=0$' "$FA"; grep -q '^TARM tcp tinit=0 tterm=0$' "$FA" # nullptr :719-:720 / :825-:826
grep -q '^RULES ipv4 n=21 first=1 last=425$' "$FA"                      # ipv4_rules :69-:92 (n FACE MEASURED)
grep -q '^RULES ipv6 n=26 first=270 last=477$' "$FA"                    # ipv6_rules :44-:80
grep -q '^RULES tcp n=20 first=45 last=403$' "$FA"                      # tcp_rules :74-:96
grep -q '^PARAMS ipv4 n=0$' "$FA"; grep -q '^PARAMS ipv6 n=0$' "$FA"; grep -q '^PARAMS tcp n=0$' "$FA"  # the anti-18o no-parameter-table face
grep -q '^GETIDS ipv4 2048$' "$FA"; grep -q '^GETIDS ipv4 4$' "$FA"     # ORDER-pinned emplace face cc :157-:158
grep -q '^GETIDS ipv6 34525$' "$FA"; grep -q '^GETIDS ipv6 41$' "$FA"   # :127-:128
grep -q '^GETIDS tcp 6$' "$FA"                                         # :152
grep -q '^GETDLT ipv4 228$' "$FA"; grep -q '^GETDLT ipv6 229$' "$FA"    # the ext#4 DLT member face (:152/:123)
test "$(grep -c '^GETDLT tcp' "$FA" || true)" -eq 0                     # the NEVER-override base face
grep -q '^NAPT4 rc=1 src=167837954 dst=184549121 fam4=1$' "$FA"         # the ext#4 match arm: SfIp::set(&napti->src_addr, family) + IpApi::update OVERWRITE (cc :247-:253; 10.1.1.2/10.255.255.1)
grep -q '^NAPT6 rc=1 src=167837954 dst=184549121 fam4=1$' "$FA"         # :213-:219 (the v6 side prints the v4-value face -- fam4 pins the family accessors)
grep -q '^NAPTTCP rc=1 sp=25001 dp=25002$' "$FA"                        # tcp NEVER bumps ip_layer_cnt -> the MISMATCH header-path face :286-:287
test "$(grep -c '^EV ' "$FA" || true)" -eq 0                            # ZERO events on the FACE-A arms (the cksum-bypass + DF + valid-next clean path)

# DEC ladders (ground call-site arms; the trio sid bands FIRE POSITIVE here;
# the MEASURED compound faces are honestly pinned -- not the draft guesses):
grep -q '^I41 trunc19 -> 0 lyr=0 next=2048$' "$V"            # :219 EV 425 + the ctor-next NEXT face (2048 NEVER zeroed on the fail path)
grep -q '^I42 ver5 -> 0$' "$V"; grep -q '^I43 hlen16 -> 0$' "$V"; grep -q '^I44 len30gt20 -> 0$' "$V"; grep -q '^I45 len10lt20 -> 0$' "$V"   # EV 1/2/6/3 :226-:247
grep -q '^I46 cksum-off -> 0$' "$V"                          # the policy-ON csum FAIL face :264 (meta pdd bypass OFF = witness daq_enable 0)
grep -q '^I47 cksum-bypass -> 1 lyr=20 next=6 pb=1$' "$V"    # the pdd l3-consumption face :135-:145 (the ext#4 bits ARE consumed -- the E4 inversion driver)
grep -q '^I48 lb127 -> 1$' "$V"; grep -q '^I49 srcdst -> 1$' "$V"   # 150/151 IPMiscTests
grep -q '^I4A bcast -> 1$' "$V"; grep -q '^I4B thisnet -> 1$' "$V"; grep -q '^I4C mc239 -> 1$' "$V"   # 413/408/410 (the Reserved/loopback walk faces)
grep -q '^I4D anom-wfalse -> 1$' "$V"                        # anomaly ON + witness sfvar_ip_in FALSE -> ZERO 411/412 (the witness verdict face)
grep -q '^I4E rbmf -> 1 lyr=20 next=2048$' "$V"             # 448 + 459 (the MF + ip_len-=hlen :316 -> :358 !ip_len REACHABLE face)
grep -q '^I4F dfmf -> 1$' "$V"; grep -q '^I4G dfoff -> 1$' "$V"      # 405 SINGLE; 430 SINGLE (:331/:346 gates)
grep -q '^I4H lenoff -> 1 lyr=20 next=2048$' "$V"           # THE 4-sid compound 151+405+430+407 (:352-:355 the (8191<<3)+len>65535 face; DF set -> 430 rides, RB cleared -> 448 NEVER)
grep -q '^I4I optbadlen -> 1 lyr=20$' "$V"                  # EV 4 + CLAMP face: invalid 4 (o_len REF -> ip_opt_len 0) + lyr 20 PIN (:286-:290)
grep -q '^I4J optset -> 1 lyr=24$' "$V"                     # decoder-SILENT [9,4] + the walker 444 (OPTION_SET :444 -- the iterator/decoder SEPARATION face)
grep -q '^I4K unass143 -> 1 next=143$' "$V"                 # EV 449 :353-:354
grep -q '^I4L menc -> 1,0$' "$V"                            # 293 + 291-NEVER (max_ip_layers ON/OFF pair)
grep -q '^I4M byp4-0 -> 1 bypass=1$' "$V"; grep -q '^I4N byp4-10 -> 1 bypass=0$' "$V"  # TUNNEL_4IN4 mask face :181-:186 pair
grep -q '^I61 trunc39 -> 0 lyr=0 next=34525$' "$V"          # 273+291 (:141-:146/:151-:156) + ctor-next
grep -q '^I62 ver5 -> 0$' "$V"; grep -q '^I63 gt-cap -> 0$' "$V"; grep -q '^I64 teredo -> 0 lyr=0$' "$V"  # 271/275; Teredo gate :158-:163 return-false
grep -q '^I65 badnext -> 1 next=255 lyr=40$' "$V"           # 281 is_valid_next_header (:224-:225)
grep -q '^I66 srcmc -> 1$' "$V"; grep -q '^I67 dstzero -> 1$' "$V"  # 277; 276 (the napt-MISMATCH posture: update NEVER rewrites the observables -- honest ride)
grep -q '^I68 lb6 -> 1$' "$V"                               # fast_eq6 151 + loopback6 150 (the v6 kin of I48/I49)
grep -q '^I69 dstmc16 -> 1$' "$V"; grep -q '^I6A scope3 -> 1$' "$V"   # 278 (the u16-word face :335-:340); scope-3: the default-arm 280 fires FIRST, the 278 word-face SECOND (the CHECK-order pin MEASURED)
grep -q '^I6B isatap -> 1$' "$V"                            # 453 SINGLE (the iface 0x00005EFE mask face :244-:256; the v6-decode ip_api.set happens AFTER the isatap check -- :207 cite)
grep -q '^I6C isatap-ok -> 1$' "$V"                         # the embedded-v4 EQUAL negative pin (SILENT)
grep -q '^I6D byp64-04 -> 1 bypass=0$' "$V"; grep -q '^I6E byp64-0 -> 1 bypass=1$' "$V"   # TUNNEL_6IN4 pair :182-:186 (mask 0x04 = BYPASSED-ON -> bypass TRUE; mask 0 -> FALSE -- the witness_18f observable pair, MEASURED order)
grep -q '^IC1 trunc19 -> 0 lyr=0$' "$V"                     # 45 :204-:207
grep -q '^IC2 off4 -> 0$' "$V"; grep -q '^IC3 hlen24gt -> 0$' "$V"    # 46/47 :212-:222
grep -q '^IC4 xmas -> 1$' "$V"                              # 400+421+420 the 3-sid flag compound (:520-:523 all-set gates + the 24B form KEEPS the :266 URG gate closed: dsize 4 urp 4)
grep -q '^IC5 nmapxmas -> 1$' "$V"                          # 401 ELSE 400 + 423 + 422 (the are_flags_set(FPU) ALL-THREE face -- 0x29, NOT 0x0D)
grep -q '^IC6 ack -> 1 lyr=20 pb=2 sp=25001 dp=25002$' "$V" # the clean baseline ZERO-event face (pb 2 = PROTO_BIT__TCP)
grep -q '^IC7 noflags -> 1$' "$V"                           # 423 SINGLE :551-:553
grep -q '^IC8 synfin -> 1$' "$V"; grep -q '^IC9 synrst -> 1$' "$V"    # 420+422 / 421
grep -q '^IC10 fin22 -> 1$' "$V"                            # 423 (:551 ACK|RST absent) + 422 MUST_ACK
grep -q '^IC11 syn -> 1$' "$V"; grep -q '^IC12 synmc -> 1$' "$V"      # clean SYN zero; SYN+239 dst + anomaly ON + witness FALSE -> NO 403 (the tcp anomaly WIRE face :539-:542)
grep -q '^IC13 shaft -> 1$' "$V"                            # 433 (seq()==674711609 + TH_NORESERVED==SYN :549-:550)
grep -q '^IC14 naptha-LE -> 1$' "$V"                        # 402 THE LIVE LE ARM: th_seq FIELD == 0x2a7b5c00 (:49) + ip_id FIELD == 0x9d01 (:50) -- the wire order the FIELD-compare (:533-:534) demands
grep -q '^IC15 naptha-faceBE -> 1$' "$V"                    # the swapped-wire tripwire twin -> NEVER 402; the 402 census OVER IC14+IC15 EXACTLY-1 = the WORDS_BIGENDIAN seed-drift pin
test "$(grep -B1 '^IC14' "$V" | grep -c 'EV 116 402')" -eq 1
test "$(grep -A1 '^IC15' "$V" | grep -c '402' || true)" -eq 0
grep -q '^IC16 urp -> 1 lyr=20$' "$V"                       # the URPGATE NEGATIVE: urp 100 > dsize 4 -> GATE (:266) CLOSED -> ZERO (honest: the 419 event rides a different conjunct -- NEVER land)
test "$(grep -c 'EV 116 419' "$V" || true)" -eq 0           # the NEVER-land pin (the draft's 419-POSITIVE guess DISPROVED by the gate)
grep -q '^IC17 portzero -> 1 sp=0 dp=0$' "$V"               # 446 :290-:291 (the header-port path -- napt layer 255)
grep -q '^IC18 nanpt -> 1 sp=7 dp=9$' "$V"                  # THE NAPT PORT-override arm :281-:284 (ip_layer 0 == the tcp cnt face -- tcp NEVER bumps it)
grep -q '^IC19 wscale -> 1 lyr=23$' "$V"                    # 59 (validate expected-3 OK + data 15 > 14 :375-:379) + the MEASURED lyr 23 face (the 24-L ladder landing one short -- the pin follows the GREP)
grep -q '^IC20 wsok -> 1$' "$V"                             # clean WSCALE ZERO face
grep -q '^IC21 echo57 -> 1 lyr=26$' "$V"                    # 57 ELSE-IF obsolete face (:481-:483; the pair arms MUTUALLY EXCLUSIVE -- experimental FALSE pin)
grep -q '^IC22 trailer58 -> 1 lyr=20$' "$V"                 # the MEASURED correction face: default arm + len-4 vs the :465 experimental face under TCPOLEN_TRAILER_CSUM 3 -> EV 54 (the [18,3] FIXED-LEN face NEVER reaches the tail -- cite-never-land 58)
test "$(grep -c 'EV 116 58' "$V" || true)" -eq 0            # the NEVER-land honest pin
grep -q '^IC23 ttcp56 -> 1 lyr=26$' "$V"                    # 56 IMMEDIATE on ENTRY :454-:455
grep -q '^IC24 optbadlen54 -> 1 lyr=20$' "$V"               # 54 (WSCALE [3,1] the expected-3 validate BADLEN)
grep -q '^IC25 opttrunc55 -> 1 lyr=20$' "$V"                # 55 (TIMESTAMP [10,10] > o_len 4 -> OPT_TRUNC :473-:474)

# ---- band census (the row's OWN fresh material; the NEVER-land face vs the
# mpls 170-176 EV-34 band + the 459/58/419 NEVER-land honest pins) ----
test "$(grep -c '^EV 116 17[0-6]$' "$V" || true)" -eq 0                    # the trio NEVER lands the mpls resident band (census 0, both directions)
test "$(grep -c '^EV 116 459$' "$V")" -eq 1                                # EXACTLY the I4E reach arm (I4F/I4G/I4H pin the NEVER side)
test "$(grep -c '^EV 116 54$' "$V")" -eq 2                                 # IC22 + IC24 (the MEASURED correction face)
test "$(grep -c '^EV 116 151$' "$V")" -eq 3                                # I49 + the I4H land co-ride + I68
# the LANDED predecessor band census NEVER leaks (own-row flip law; the 4
# mpls-era + vocab/ext vectors RE-READ byte-frozen -- greps below):
python3 - <<'EOFPY'
for f in ("mpls_harness","link4_harness","misc9_harness","ext_harness"):
    t = open(f"/opt/data/snort3-rust/tools/{f}/vectors.txt").read() + open(f"/opt/data/snort3-rust/tools/{f}/vectors_faceA.txt").read()
    if f != "mpls_harness":
        for sid in ("170","171","172","173","174","175","176"):
            assert f"EV 116 {sid}" not in t, (f, sid)    # the 170-176 EV-34 band NEVER lands outside mpls own vectors
# vocab: a SINGLE vectors.txt face (no faceA file -- the 18c era shape):
tv = open("/opt/data/snort3-rust/tools/vocab_harness/vectors.txt").read()
for sid in ("170","171","172","173","174","175","176"):
    assert f"EV 116 {sid}" not in tv, ("vocab_harness", sid)
print("predecessor band census UNDISTURBED (5 harnesses re-read byte-frozen)")
EOFPY
# NEXT.md pinned-string carry law (docs CITE only, NEVER edited, NEVER run):
grep -q "605 tests green / 0 FAILED" "$R/NEXT.md"
grep -q "580 passed / 0 failed" "$R/NEXT.md"
grep -q "588 tests green / 0 FAILED" "$R/NEXT.md"
grep -q "597 tests green / 0 FAILED" "$R/NEXT.md"
grep -q "573 tests green" "$R/NEXT.md"

# ---- known-answer seeds (FIRST run seeds then DIES HERE per the 18n seed
# law; EVERY later run refuses drift; build.sh NEVER fabricates). MEASURED
# first-run faces (the row-20h scratch run, identical inputs): ----
test "$(wc -l < "$H"/vectors.txt)" -eq 121          # MEASURED first-run face
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 44     # MEASURED first-run face
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"      = "857b5a100480114085b45a392ab713bf"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "63df50bc57b7d15d95c21bdfcd492fce"
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)

# ---- frozen-donor direct-md5 census (link4/mpls face VERBATIM; the retired
# trio stubs NEVER touched -- the vectors LOAD-pin faces ride HEAD re-pins
# above; the TAIL re-pins below prove the whole build edited NOTHING) ----
for e in \
 "/opt/data/snort3-rust/tools/fmod_harness/vectors.txt f0fdbab06fe1681af1c654531b917c55" \
 "/opt/data/snort3-rust/tools/vocab_harness/vectors.txt 5da70e82416b6f769af8177d859331e7" \
 "/opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc 9fad7e9d7a278fbc2ee82c233f86e774" \
 "/opt/data/snort3-rust/tools/ext_harness/stubs_18e.cc a700f77ef7f1ff718f1ae9626f10b826" \
 "/opt/data/snort3-rust/tools/ext_harness/vectors_faceII.txt cdaa92dfb8bdb35ce1ffaa41c1ae3fc4" \
 "/opt/data/snort3-rust/tools/tun_harness/vectors.txt 2a7924796f8f0cfdca5e665dee28f519" \
 "/opt/data/snort3-rust/tools/eth_harness/vectors.txt 1bd98dbb57dd2f536104995bd76d9bad" \
 "/opt/data/snort3-rust/tools/ext_harness/vectors.txt da21842980d042d5871edeaaf502049e" \
 "/opt/data/snort3-rust/tools/ext_harness/vectors_faceA.txt 0fa79b534d2a598b2befb047c95c3579"; do
    set -- $e
    test "$(md5sum "$1" | awk '{print $1}')" = "$2"
done

# ---- BACKBONE-10 census: the 10-face PIN STAYS EXACTLY 10 UNDISTURBED --
# the B10 array rides link4 :796-:807 / mpls :666-:677 VERBATIM (absolute
# paths, NEVER re-derived); THIS row adds ZERO faces (the own witness DUO is
# SYMBOL faces -- the symbol-vs-array law, 18n/18o). ----
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
test "$(wc -l < "$H/backbone10.txt")" -eq 10                            # backbone STAYS 10
# THE chain echoes (DIRECT predecessor mpls FACE re-read byte-ident + the
# four-pair chain echo complete -- the mpls :682-:700 face VERBATIM):
test "$(md5sum "$R"/tools/misc9_harness/vectors.txt | awk '{print $1}')" = "e6328da1f3188df9754b9e45d74897db"
test "$(md5sum "$R"/tools/misc9_harness/vectors_faceA.txt | awk '{print $1}')" = "dfe738fb8b4200368332ba73b81a4e96"
test "$(md5sum "$L4"/vectors.txt | awk '{print $1}')" = "c7f5808fa326b7831603813c16a3b01e"
test "$(md5sum "$L4"/vectors_faceA.txt | awk '{print $1}')" = "9fdfc50da8fee22b473028f1f9b29c12"
test "$(md5sum "$R"/tools/misc3_harness/vectors.txt | awk '{print $1}')" = "e75f7385779aa89c365dd2ce4a208b67"
test "$(md5sum "$R"/tools/misc3_harness/vectors_faceA.txt | awk '{print $1}')" = "fe1189c6c78139b8828c1a8071e3df28"
test "$(md5sum "$R"/tools/link6_harness/vectors.txt | awk '{print $1}')" = "e59f7a8a70d172261dcb847dcfdcb36a"
test "$(md5sum "$R"/tools/link6_harness/vectors_faceA.txt | awk '{print $1}')" = "d2fc5591bc45c1787fcee7393675a3d8"
test "$(md5sum "$R"/tools/erspan_harness/vectors.txt | awk '{print $1}')" = "7d7d350073eda41074120532c65146bf"
test "$(md5sum "$R"/tools/erspan_harness/vectors_faceA.txt | awk '{print $1}')" = "3ec325d785e92c75458d747d2ab70be2"
# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" "$R/tools/fmod_harness/build.sh"
grep -q "4826fc2233044a2d5429413faf0ae1af" "$R/tools/fmod_harness/build.sh"
# gre GATE anchor (the positive-gate CONTRAST face for this row's ZERO-gate
# 26th-straight pin):
test "$(md5sum "$R"/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" "$R/tools/gre_harness/gate.txt"
# mpls chain anchor (18o, the IMMEDIATE predecessor harness):
grep -q "b4b660e448703b603755a0049c6a2052" "$MPL/build.sh"

# ---- TWO-LINEAGE census loop (MEASURED, never typed; THIS row adds ZERO
# gate.txt so the 25-tracked face is UNDISTURBED BY DESIGN -- the 26th-
# straight ZERO-gate claim rides these re-measures ONLY at the row build): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(cat "$H/gate_md5_lineages.txt")" -eq 17
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin (the 18i PROCESS-LESSONS law).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (the NESTED-INSTRUMENT face; the
# root .gitignore NEVER touched; the block lives IN this dir and check-ignore
# honors it). NON-ignored face = the 9 stageables (PLAN.md build.sh
# probe.cc probe_dec.cc witness_ipvars.cc witness_opts.cc vectors.txt
# vectors_faceA.txt + the .gitignore instrument -- the PLAN "8" prose under-
# counts the witness DUO; the MEASURED 2-own-witness face rides PLAN drift
# notes). PRE-commit the 9 are UNTRACKED (--others); POST-commit the SAME
# proof runs vs the landed face. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/ipheavy_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/ipheavy_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 9
for f in PLAN.md build.sh probe.cc probe_dec.cc witness_ipvars.cc witness_opts.cc vectors.txt vectors_faceA.txt .gitignore; do
    echo "$face" | grep -q "tools/ipheavy_harness/$f$"
done
test "$(echo "$face" | grep -c 'witness_')" -eq 2      # the own-witness DUO face
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/cd_ipv4.o copy/codecs/ip/cd_ipv4.cc copy/codecs/ip/cd_ipv4.cc copy/daq.h copy/daq_dlt.h copy/daq_common.h copy/protocols/packet.h copy/stream/stream.h o2/cd_ipv4.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_daq.o witness_18f.o witness_conf.o stubs_18d.o stubs_20a.o witness_ipvars.o witness_opts.o vectors_O0.txt vectors_faceA_O0.txt vectors_O2.txt vectors_faceA_O2.txt nm_U_cd_ipv4.txt nm_U_cd_ipv6.txt nm_U_cd_tcp.txt E4_preext_cd_ipv4.txt E4_preext_cd_ipv6.txt E4_preext_cd_tcp.txt E4_postext_cd_ipv4.txt E4_postext_cd_ipv6.txt E4_postext_cd_tcp.txt E4_donorsrc_cd_ipv4.txt E4_drop_cd_ipv4_parse_ip.h.txt E4_drop_cd_tcp_stream.h.txt E4_nodaq_cd_ipv4.txt E4_nodaq_cd_ipv6.txt E4_nodaq_cd_tcp.txt E4_nopacket_cd_tcp.txt E4_restored_cd_ipv4.txt E4_restored_cd_ipv6.txt E4_restored_cd_tcp.txt dup_naive.txt dup_retired.txt L1_link_face.txt L1_undefined.txt L1_face_cd_ipv4.txt L1_face_cd_tcp.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt o_size_receipt.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/ipheavy_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/ipheavy_harness/$f NOT ignored"; exit 1; }
done
test "$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/ipheavy_harness | wc -l)" -eq 9   # gen/ + probe .o + vectors_O* NEVER leak INTO the face
# the own witnesses + probes + vectors NEVER ignored (the stageable NOT-proofs):
for f in witness_ipvars.cc witness_opts.cc probe.cc probe_dec.cc vectors.txt vectors_faceA.txt .gitignore; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/ipheavy_harness/$f" && { echo "WRONGLY IGNORED: $f"; exit 1; } || true
done
# no STAGED churn: index EMPTY (the churn tolerance = NONE at the C-side row:
# mod.rs NOT touched, docs NOT touched -- the rs-LANDING child flips the
# tolerance face; the ZERO-tolerance face is the honest C-side posture):
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
rowface='^tools/ipheavy_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|witness_ipvars\.cc|witness_opts\.cc|vectors\.txt|vectors_faceA\.txt|\.gitignore)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface")"   # ZERO tracked-MOD churn at this row
# dir face BOTH states: ?? tools/ipheavy_harness/ while UNTRACKED (pre-commit)
# else tracked at EXACTLY the 9 stageable faces (post-commit):
if git -C /opt/data/snort3-rust ls-files --error-unmatch "tools/ipheavy_harness/PLAN.md" >/dev/null 2>&1; then
    test "$(git -C /opt/data/snort3-rust ls-files "tools/ipheavy_harness/" | wc -l)" -eq 9
    test -z "$(git -C /opt/data/snort3-rust ls-files tools/ipheavy_harness | grep -vE 'PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|witness_ipvars\.cc|witness_opts\.cc|vectors\.txt|vectors_faceA\.txt|\.gitignore')"
else
    git -C /opt/data/snort3-rust status --porcelain | grep -qx '?? tools/ipheavy_harness/'
fi
# SINGLE-TENANT census (orchestrator law, disk re-checked EVERY build): the
# ONLY dirty face in tools/ is THIS row's ?? dir -- NO sibling tracked churn:
dirtyother=$(git -C /opt/data/snort3-rust status --porcelain tools | grep -vE '^\?\? tools/ipheavy_harness/' || true)
test -z "$dirtyother"

# .o-size receipt (MEASURED sizes, NEVER pinned -- compile-env dependent):
ls -l "$C/cd_ipv4.o" "$O2/cd_ipv4.o" > "$H/o_size_receipt.txt" 2>/dev/null || true
git -C /opt/data/snort3-rust check-ignore -q "tools/ipheavy_harness/o_size_receipt.txt" || { echo "GITIGNORE FACE DEAD: o_size_receipt.txt NOT ignored"; exit 1; }

echo "row-trio nm census (MEASURED, never typed): nm_U=$(cat "$H"/nm_U_cd*.txt | sort -u | wc -l) distinct | daq_msg_get_meta U x3 TUs CONSUMED (the ext#4 face -- contrast mpls ZERO; the daq.h-drop KILLS all three HERE, the 18o SURVIVES inversion receipt) | own L1 EXACTLY-10 undefined -> witness DUO (ipvars 3 + opts 7 arms) closes to 0 | per-file faces: $(tail -3 "$H/L1_undefined.txt" | tr '\n' ' ')"
echo "witness posture: OWN DUO 2 files (b18434c5 / be040321); find-0 definer census ALL 10 names; backbone STAYS $(wc -l < "$H/backbone10.txt"); carried witness_daq e0166b02 + witness_18f + witness_conf + stubs_18d ride INHERITED (ZERO clone cost)"
echo "landmine rehearsal BOTH faces LIVE: naive co-link trio+vocab frozen stub .o = EXACTLY-3 'multiple definition' cd_ipv4/cd_ipv6/cd_tcp (zero other dups; dup_naive.txt receipt) | post-retirement own stubs_20a (frozen vocab MINUS :11-:13 externs + marker citing TRUE tables :785/:728/:834) = dup 0 + nm surviving stub table EXACTLY-1 cd_hopopts; frozen donors 9fad7e9d/a700f77e md5 UNDISTURBED head AND tail; vectors LOAD cd_ ZERO in THIS row (the LOAD ipv4/ipv6/tcp real-NAME flip -- vocab 5da70e82 :25-:27 + ext faceII cdaa92df :2-:4 stay FROZEN untouched)"
echo "cp face: 7 FRESH cps (parse_ip 28 + sf_ipvar 116 + ipv4_options 150 + tcp_options 181 + stream 288 + prune_stats 159 + packet_time 38; trio-unique set, riders ride ONCE) -> 130 -> 140 mid-build RE-DERIVED; flow/flow.h PRE-PAY rider lands the packet.h RE-POINT (flowz decoy class Flow REDEFINES -- the cd_tcp pre-ext cc-error face)"
echo "ext#4 ladder: pre-ext rc1 counts cd_ipv4=10 / cd_ipv6=5 / cd_tcp=2 (the flowz redefinition + pdd tcp faces); heredoc daq.h 51L 97bca757 + daq_dlt.h 14L e8a39bf3 + packet.h sed-repoint 1be562b2 -> rc0 x3; masters 73fdbc39/f683749c + v2 fead0027 + v3 0f7016a6 + ext2 9b603f8f md5-asserted UNDISTURBED ladder HEAD AND TAIL (NEVER promoted; 228/229 SYNTHETIC CITE, row-20 real-SDK re-cite NEVER silent)"
echo "E4 walls: -I src ONLY rc1 daq.h:25 TRIO head face | parse_ip kills cc:35/:32/:31 trio | sf_ipvar kills :40/:33/:34 | ipv4_options cc:38 | tcp_options cc:33 | stream cc:35 | prune_stats+packet_time NESTED stream.h:32/:35 (the clock_defs-era rider face) | daq.h-drop KILLS x3 (THE INVERSION vs 18o SURVIVES) | packet.h NOT droppable direct-edge fatal | restored rc0 EVERY build"
echo "hidden-table census: cd_ipv4[] :785 TRUE-NAME | cd_ipv6[] :728 | cd_tcp[] :834 UNCONDITIONAL (BUILDING_SO COMMENTED :831-:835 -- grep-c 'BUILDING_SO'=1 LIES; the anchored #ifdef census = ipv4 1 / ipv6 1 / tcp 0 face) | NAME :47/:37/:42 + HELP :49/:39 ADD_DLT vs tcp NO-ADD_DLT :43 | WORDS_BIGENDIAN: cd_ipv4 :379 + cd_tcp :45-:51 face, cd_ipv6 grep-0 (the honest contrast) | #if 0 cd_ipv4 :210 cite-NEVER-land | RULES n: 21/26/20 MEASURED | t-arms ipv4 REAL/ipv6+tcp nullptr | CMakeLists trio add_dynamic COMMENTED x3"
echo "sid bands FRESH: {1-6 + 404-449 ipv4} {270-296 ipv6} {45-59 + 400-446 tcp}; the 170-176 EV-34 face census ZERO BOTH ways (trio NEVER lands it; mpls vectors byte-frozen b4b660e4/3066fc33); NEVER-land pins: EV 419 ZERO + EV 58 ZERO (the IC22 [18,4]->54 MEASURED correction) + 459 EXACTLY-1 (I4E reach side)"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED; tracked gate.txt = 1 ls-files; 26th-straight ZERO-gate docs-lineage count: trio TEST_CASE/TEST_GROUP/UNIT_TEST/CppUTest grep-0 x3, test/checksum_test.cc 201L = recorded CANDIDATE for the ALREADY-ported checksum.h, CppUTest host find-0 COMPILE-BLOCKED honest posture NEVER landed); BACKBONE STAYS 10 (the witness DUO is SYMBOL faces, never an array face); chain echoes misc9 e6328da1/dfe738fb + link4 c7f5808f/9fdfc50d + mpls b4b660e4/3066fc33 BYTE-IDENT DIRECT"
echo "IPHEAVY_DONE vectors=$( [ -e "$H"/vectors.txt ] && wc -l < "$H"/vectors.txt || wc -l < "$H"/vectors_O0.txt) faceA=$( [ -e "$H"/vectors_faceA.txt ] && wc -l < "$H"/vectors_faceA.txt || wc -l < "$H"/vectors_faceA_O0.txt) gates=0"
