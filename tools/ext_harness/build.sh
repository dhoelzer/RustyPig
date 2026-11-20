#!/usr/bin/env bash
# ext_harness -- row 18e IPv6 extension chain: codecs/ip/{cd_hop_opts,
# cd_dst_opts,cd_routing,cd_mobility,cd_igmp}.cc 143+134+163+143+138 = 721 L
# (PLAN 0: per-file md5s + wc sum pinned below, own-measured).
# PROBE-ONLY (PLAN 0/7): zero gate material on all five row files; ip/test =
# checksum_test.cc 201 + CMakeLists 1 = 202 (18b CppUTest face, ZERO suite
# units inside row files). ZERO gate.txt shipped; the 9 holders of
# 4826fc2233044a2d5429413faf0ae1af among exactly 24 tracked gate.txt are
# frozen dirs -> 13th straight rides the SESSION fresh fmod+vocab rebuilds
# (scratch row18e/{fmod,vocab}_rebuild_18e.log), NEVER typed here (17p).
# Copy tree (PLAN 2): the eth DONOR face carried VERBATIM (cp -a) + EXACTLY
# 5 row cps -- the 18e finding: ZERO fresh cps/grafts needed (include
# closure fully resident; receipts E4_row_cd_*.txt rc=0 x5 asserted).
# THE LANDMINE (PLAN 4): cd_hopopts dup is 18a-INVERTED: the frozen vocab
# witness_stubs.cc:14 cd_hopopts stub FORKS against the real table
# (ip/cd_hop_opts.cc:137). Every build: (a) E6 co-link MUST fail
# multiple-definition (E6_hopopts_dup_collision.txt), (b) own stubs_18e.cc =
# frozen vocab MINUS :14 PLUS RETIRED marker -- diff-0 proven vs the frozen
# file, (c) 3-face census asserts (frozen 4 D tables / retired 3 / real 5),
# (d) FACE-II flip rehearsed: pulling codec_api.cc FORKS the frozen LOAD
# face to LOAD ipv6_hop_opts (vectors_faceII.txt = receipt). The FACE-A +
# DEC probes NEVER link any codec_api object (nm guard below).
# Values NEVER typed (17p): the ladders below grep the MEASURED 27-L DEC +
# 9-L FACE-A vectors (md5 da218429... / 0fa79b53..., O0==O2 byte-ident).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
ETH=/opt/data/snort3-rust/tools/eth_harness
C=$H/copy

# ---- ground identity (5 row files pinned by OWN md5 + wc, measured) ----
for pair in "cd_hop_opts ec3b0bed51c16c7eab9939aa484b0cb0 143" \
            "cd_dst_opts 033def126e4e32c6db272629fe91dde7 134" \
            "cd_routing 811d85c5dbe45398a10c97efcdb0291f 163" \
            "cd_mobility a053ea4f83cb866e9267d610c1ed08d2 143" \
            "cd_igmp 9dfbc89efc2a1eb7ea4861dca69fd826 138"; do
    set -- $pair
    test "$(md5sum "$SRC"/src/codecs/ip/$1.cc | awk '{print $1}')" = "$2"
    test "$(wc -l < "$SRC"/src/codecs/ip/$1.cc)" -eq "$3"
done
test "$(cat $SRC/src/codecs/ip/{cd_hop_opts,cd_dst_opts,cd_routing,cd_mobility,cd_igmp}.cc | wc -l)" -eq 721
# zero suite material per row file (PLAN 0):
for f in cd_hop_opts cd_dst_opts cd_routing cd_mobility cd_igmp; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST' "$SRC"/src/codecs/ip/$f.cc || true)" -eq 0
done
# ip/test census (18b face unchanged): checksum_test.cc 201 + CMakeLists 1
test "$(wc -l < "$SRC"/src/codecs/ip/test/checksum_test.cc)" -eq 201
test "$(wc -l < "$SRC"/src/codecs/ip/test/CMakeLists.txt)" -eq 1
# cd_gre rule UNTOUCHED (PLAN 7): anchors re-measured, 18e pre-digs nothing:
test "$(sed -n '34p' "$SRC"/src/codecs/ip/cd_gre.cc)" = "#ifdef UNIT_TEST"
test "$(sed -n '35p' "$SRC"/src/codecs/ip/cd_gre.cc)" = '#include "catch/snort_catch.h"'
test "$(sed -n '352p' "$SRC"/src/codecs/ip/cd_gre.cc | grep -c 'TEST_CASE (')" -eq 1
test "$(wc -l < "$SRC"/src/codecs/ip/cd_gre.cc)" -eq 366
# the frozen landmine trio md5 pins (vocab witness_stubs + vectors + codec stubs):
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/vectors.txt | awk '{print $1}')"     = "5da70e82416b6f769af8177d859331e7"
test "$(md5sum /opt/data/snort3-rust/tools/codec_harness/stubs.cc | awk '{print $1}')"        = "be9bdd0b437d1f6c56c841e8155d9e70"

# ---- copy tree = eth DONOR face VERBATIM + EXACTLY 5 row cps (delta 0) ----
if [ ! -e "$ETH/copy/codec.o" ]; then bash "$ETH/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$ETH/copy" "$C"
test "$(md5sum "$C"/codecs/codec_module.h | awk '{print $1}')" = "3f3bd92752ba46b8732f831724d3b279"
test "$(md5sum "$C"/main/snort_config.h   | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
test ! -e "$C"/codecs/codec_api.h                       # the FACE-flip precondition (donor has NO codec_api TU)
test ! -e "$C"/codecs/codec_api.cc
for f in cd_hop_opts cd_dst_opts cd_routing cd_mobility cd_igmp; do
    cp "$SRC"/src/codecs/ip/$f.cc "$C"/codecs/ip/
    cmp -s "$C"/codecs/ip/$f.cc "$SRC"/src/codecs/ip/$f.cc
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 81   # 76 donor + 5 row cps

# ---- E4 row face vs the donor copy tree: rc=0 x5, ZERO fresh cps needed ----
for f in cd_hop_opts cd_dst_opts cd_routing cd_mobility cd_igmp; do
    if ! g++ -std=c++17 -O0 -w -I"$C" -c "$C"/codecs/ip/$f.cc -o /dev/null 2> "$H/E4_row_$f.txt"; then
        echo "E4 BROKE: $f needs a fresh cp -- include-closure claim dead"; exit 1
    fi
    test ! -s "$H/E4_row_$f.txt"
done
# ---- cpc stage: ground codec_api.h ONLY for the FACE-II rehearsal (PLAN 4d)
mkdir -p "$H/cpc/codecs"
cp "$SRC"/src/codecs/codec_api.h "$H/cpc/codecs/"
test "$(md5sum "$H"/cpc/codecs/codec_api.h | awk '{print $1}')" = "df2bc9d1f74314408a3ced3be3e4d2ad"
cmp -s "$H"/cpc/codecs/codec_api.h "$SRC"/src/codecs/codec_api.h

# ---- witness_conf.cc: the eth DONOR witness face regenerated byte-ident ----
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
test "$(md5sum "$ETH"/stubs_18d.cc | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"  # queue_event/layer witness home (TRACKED donor copy)

# ---- trackable pins (stageables EXACTLY 7 per PLAN 8) ----
test "$(wc -l < "$H"/probe.cc)" -eq 21
test "$(wc -l < "$H"/probe_dec.cc)" -eq 48
test "$(wc -l < "$H"/stubs_18e.cc)" -eq 14
test "$(wc -l < "$H"/vectors.txt)" -eq 27            # DEC face, MEASURED (recon "31 L" corrected -- 17p: wc rules)
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 9       # FACE-A (recon "10 L" corrected)
test "$(md5sum "$H"/probe.cc | awk '{print $1}')"      = "af4c83fcd6845898c29784249bcb7edf"
test "$(md5sum "$H"/probe_dec.cc | awk '{print $1}')"  = "35d7f771c450657c0df6ffc313dc76e2"
test "$(md5sum "$H"/stubs_18e.cc | awk '{print $1}')"  = "a700f77ef7f1ff718f1ae9626f10b826"
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"   = "da21842980d042d5871edeaaf502049e"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "0fa79b534d2a598b2befb047c95c3579"

# ---- LANDMINE part 1: stubs_18e.cc = frozen vocab MINUS :14 PLUS marker.
# diff-0 proof: EXACTLY one '<' (the :14 def line) + one '>' (the marker). ----
diff /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc "$H"/stubs_18e.cc > "$H"/E_frozen_stubs_diff.txt || true
test "$(grep -c '^<' "$H"/E_frozen_stubs_diff.txt)" -eq 1
test "$(grep -c '^>' "$H"/E_frozen_stubs_diff.txt)" -eq 1
grep '^<' "$H"/E_frozen_stubs_diff.txt | grep -q 'cd_hopopts'
grep '^>' "$H"/E_frozen_stubs_diff.txt | grep -q 'RETIRED at 18e'
grep -q 'RETIRED at 18e' "$H"/stubs_18e.cc
python3 - "$H" <<'DIFFCHK'
import sys
H = sys.argv[1]
f = open("/opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc").read()
o = open(H + "/stubs_18e.cc").read()
drop = 'extern const BaseApi* cd_hopopts[]; const BaseApi* cd_hopopts[] = { &stub_hopopts, nullptr };\n'
marker = '// RETIRED at 18e: cd_hopopts stub (real table ip/cd_hop_opts.cc:137 lands this row)\n'
assert drop in f and drop not in o
assert marker in o and marker not in f
assert f.replace(drop, "") == o.replace(marker, ""), "diff-0 BROKE vs frozen vocab witness_stubs"
open(H + "/E_frozen_stubs_diff0.txt", "w").write("diff-0: stubs_18e == vocab witness_stubs minus :14 plus RETIRED marker\n")
DIFFCHK

# ---- E1 compile: 5 row + donor REAL-cp .o's fresh THIS pass + probes ----
GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
ROW="$C/codecs/ip/cd_hop_opts.cc $C/codecs/ip/cd_dst_opts.cc $C/codecs/ip/cd_routing.cc $C/codecs/ip/cd_mobility.cc $C/codecs/ip/cd_igmp.cc"
REAL="$C/framework/codec.cc $C/protocols/ip.cc $C/sfip/sf_ip.cc $C/utils/util_cstring.cc $C/utils/util.cc $C/framework/module.cc"
for f in $ROW $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$H"/stubs_18e.cc -o "$H"/stubs_18e.o
$GXX -c "$H"/witness_conf.cc -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc -o "$H"/stubs_18d.o
$GXX -c /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc -o "$H"/stubs_vocab.o

# ---- LANDMINE part 2 (E6): real cd_hop_opts.o + FROZEN vocab stubs MUST
# collide -- every build. First dup line names cd_hopopts (scratch E6 face). ----
OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o"
ROWS_O="$C/cd_hop_opts.o $C/cd_dst_opts.o $C/cd_routing.o $C/cd_mobility.o $C/cd_igmp.o"
if $GXX "$C/cd_hop_opts.o" "$H"/stubs_vocab.o -o "$H"/should_fail 2> "$H"/E6_hopopts_dup_collision.txt; then
    echo "E6 BROKE: real cd_hop_opts.o linked beside frozen vocab stubs -- dup rule unproven"; exit 1
fi
head -1 "$H"/E6_hopopts_dup_collision.txt | grep -q "multiple definition of .cd_hopopts"
rm -f "$H"/should_fail

# ---- LANDMINE part 3: 3-face stub census (fmod trio_retirement_census) ----
test "$(nm -C --defined-only "$H"/stubs_vocab.o | grep -c ' D cd_')" -eq 4   # frozen vocab face: 4 tables
test "$(nm -C --defined-only "$H"/stubs_18e.o | grep -c ' D cd_')" -eq 3    # retired face: 3 dormant
test "$(nm -C --defined-only "$H"/stubs_18e.o | grep -c 'cd_hopopts' || true)" -eq 0
for pair in "cd_hop_opts cd_hopopts" "cd_dst_opts cd_dstopts" "cd_routing cd_routing" "cd_mobility cd_mobility" "cd_igmp cd_igmp"; do
    set -- $pair
    d=$(nm -C --defined-only "$C/$1.o")
    grep -q " D $2" <<< "$d"
done

# ---- E2: per-TU nm residue census (receipts; counts MEASURED 11/11/10/10/21) ----
for t in cd_hop_opts cd_dst_opts cd_routing cd_mobility cd_igmp; do
    nm -C -u "$C"/"$t".o | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H"/nm_U_"$t".txt
done
test "$(wc -l < "$H"/nm_U_cd_hop_opts.txt)" -eq 11
test "$(wc -l < "$H"/nm_U_cd_dst_opts.txt)" -eq 11
test "$(wc -l < "$H"/nm_U_cd_routing.txt)" -eq 10
test "$(wc -l < "$H"/nm_U_cd_mobility.txt)" -eq 10
test "$(wc -l < "$H"/nm_U_cd_igmp.txt)" -eq 21
for t in cd_hop_opts cd_dst_opts cd_routing cd_mobility cd_igmp; do
    test "$(grep -c 'Codec::codec_event' "$H"/nm_U_$t.txt)" -eq 1
done
# CheckIPV6* app residues resolve by REAL donor codec.o T defs (ZERO new witnesses):
grep -q 'codec_event' "$H"/nm_U_cd_hop_opts.txt
grep -q 'CheckIPV6HopOptions' "$H"/nm_U_cd_hop_opts.txt
grep -q 'CheckIPv6ExtensionOrder' "$H"/nm_U_cd_routing.txt
test "$(grep -c 'CheckIPV6' "$H"/nm_U_cd_igmp.txt || true)" -eq 0   # igmp rides snort.ip_api, zero Check* (PLAN 0 correction)
grep -q 'Module::Module' "$H"/nm_U_cd_igmp.txt
s=$(nm -C --defined-only "$C"/codec.o)
grep -q 'T snort::Codec::codec_event' <<< "$s"
grep -q 'T snort::Codec::CheckIPV6HopOptions' <<< "$s"
grep -q 'T snort::Codec::CheckIPv6ExtensionOrder' <<< "$s"
m=$(nm --defined-only "$C"/module.o)
grep -q 'T _ZN5snort6ModuleC1EPKcS2_' <<< "$m"

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool [a-z][a-z0-9]*=.*->decode' "$H"/probe_dec.cc)" -eq 5
test "$(grep -c 'printf.*->decode' "$H"/probe_dec.cc || true)" -eq 0
# the NEVER-pull rule as an nm guard: FACE-A + DEC probe objects ask NO codec_api entry
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0

# ---- E5: link + run FACE-A and DEC at O0 AND O2; all BYTE-IDENT pins ----
$GXX $OBJS $ROWS_O "$H"/probe.o "$H"/stubs_18e.o "$H"/witness_conf.o "$H"/stubs_18d.o -o "$H"/probe
$GXX $OBJS $ROWS_O "$H"/probe_dec.o "$H"/stubs_18e.o "$H"/witness_conf.o "$H"/stubs_18d.o -o "$H"/probe_dec
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in $ROW $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2/probe.o"; $GXXA -c "$H"/probe_dec.cc -o "$O2/probe_dec.o"
$GXXA -c "$H"/stubs_18e.cc -o "$O2/stubs_18e.o"; $GXXA -c "$H"/witness_conf.cc -o "$O2/witness_conf.o"
$GXXA -c "$ETH"/stubs_18d.cc -o "$O2/stubs_18d.o"
$GXXA $(for b in cd_hop_opts cd_dst_opts cd_routing cd_mobility cd_igmp codec ip sf_ip util_cstring util module; do printf '%s ' "$O2/$b.o"; done) "$O2/probe.o" "$O2/stubs_18e.o" "$O2/witness_conf.o" "$O2/stubs_18d.o" -o "$H"/probe_O2
$GXXA $(for b in cd_hop_opts cd_dst_opts cd_routing cd_mobility cd_igmp codec ip sf_ip util_cstring util module; do printf '%s ' "$O2/$b.o"; done) "$O2/probe_dec.o" "$O2/stubs_18e.o" "$O2/witness_conf.o" "$O2/stubs_18d.o" -o "$H"/probe_dec_O2
timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }
cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }
# hygiene (all-decimal posture): zero 0x anywhere in either tracked face:
test "$(grep -c '0x' "$H"/vectors.txt || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_faceA.txt || true)" -eq 0

# ---- known-answer ladders (arms BYTE-PINNED by the cmps above; greps pin the
# decomposition against GROUND, NEVER a forecast -- 17p) ----
test "$(sed -n '30p' "$SRC"/src/codecs/ip/cd_hop_opts.cc)"   = '#define CD_HOPOPTS_NAME "ipv6_hop_opts"'
test "$(sed -n '30p' "$SRC"/src/codecs/ip/cd_dst_opts.cc)"   = '#define CD_DSTOPTS_NAME "ipv6_dst_opts"'
# CDAPI carry (18c pins re-confirmed by 18e): size=112 ver=1900547 on all 5
test "$(grep -c '^API .* size=112 ver=1900547' "$H"/vectors.txt)" -eq 5
grep -q '^API hopopts type=0 size=112 ver=1900547 name=ipv6_hop_opts$' "$H"/vectors.txt
grep -q '^API igmp type=0 size=112 ver=1900547 name=igmp$' "$H"/vectors.txt
grep -q '^HELP igmp support for Internet group management protocol$' "$H"/vectors.txt
grep -q '^API igmp type=0 name=igmp mod_ctor=1$' "$H"/vectors_faceA.txt
test "$(grep -c '^LOAD ' "$H"/vectors_faceA.txt)" -eq 5
grep -q '^LOADS 5$' "$H"/vectors_faceA.txt
# EV pins: 272/283 are LITERALS at codec_module.h:123/:134; 455/461/475 arms
# ride the ALREADY-LANDED Rust CodecSid enum (18e NEVER re-walks; 18d landed
# all 170): codec_module.rs :133/:144/:213/:219/:233 greps = grounding:
test "$(sed -n '123p' "$SRC"/src/codecs/codec_module.h)" = "    DECODE_IPV6_TRUNCATED_EXT = 272,"
test "$(sed -n '134p' "$SRC"/src/codecs/codec_module.h)" = "    DECODE_IPV6_TWO_ROUTE_HEADERS = 283,"
grep -q 'DECODE_IGMP_OPTIONS_DOS = 455'  /opt/data/snort3-rust/src/codecs/codec_module.rs
grep -q 'DECODE_IPV6_ROUTE_ZERO = 461'   /opt/data/snort3-rust/src/codecs/codec_module.rs
grep -q 'DECODE_MIPV6_BAD_PAYLOAD_PROTO = 475' /opt/data/snort3-rust/src/codecs/codec_module.rs
test "$(grep -c '^EV 116 272$' "$H"/vectors.txt)" -eq 2   # HOP short7 + HOP lyr>len
grep -q '^EV 116 461$' "$H"/vectors.txt
grep -q '^EV 116 283$' "$H"/vectors.txt
grep -q '^EV 116 475$' "$H"/vectors.txt
# decode arms + quirks (NEVER unify the ladders -- PLAN 3 cites):
grep -q '^HOP short7 -> 0$' "$H"/vectors.txt
grep -q '^HOP ok8 -> 1 next=6 lyr=8 bits=65536 cnt=1 csumproto=6$' "$H"/vectors.txt
grep -q '^HOP lyr>len -> 0$' "$H"/vectors.txt
grep -q '^MOB badpayl -> 1 next=60$' "$H"/vectors.txt   # returns TRUE WITH the 475 event (cd_mobility.cc:90 then :92)
grep -q '^ROUTE t0 -> 1 next=43 bits=65536$' "$H"/vectors.txt
grep -q '^IGMP rules=1 sid0=455 name=igmp$' "$H"/vectors.txt
test "$(sed -n '63,65p' "$SRC"/src/codecs/ip/cd_dst_opts.cc | grep -c return)" -eq 0   # dstopts EXCESS-without-return quirk (vs cd_hop_opts.cc:67-:70 return-false face)
test "$(sed -n '67,70p' "$SRC"/src/codecs/ip/cd_hop_opts.cc | grep -c 'return false')" -eq 1
# PIDS arms = protocol_ids.h literals (grep grounding):
test "$(grep -c 'HOPOPTS = 0,' "$SRC"/src/protocols/protocol_ids.h)" -ge 1
test "$(grep -c 'MOBILITY_IPV6 = 135,' "$SRC"/src/protocols/protocol_ids.h)" -ge 1
grep -q '^HOPPID 0 n=1$' "$H"/vectors.txt
grep -q '^DSTPID 60 n=1$' "$H"/vectors.txt
grep -q '^ROUTE_PID 43 n=1$' "$H"/vectors.txt
grep -q '^MOB_PID 135 n=1$' "$H"/vectors.txt
grep -q '^IGMP_PID 2 n=1$' "$H"/vectors.txt
grep -q 'PROTO_BIT__IP6_EXT' "$C"/framework/decode_data.h

# ---- LANDMINE part 4 (FACE-II flip rehearsal, GENERATION face only): pull
# codec_api.cc (+ ground codec_api.h via cpc/ + 4 no-op cd_* .o) -> the fmod
# face FORKS the frozen vocab LOAD line to the REAL table name, every build. ----
printf '#include <cstdio>\n#include "framework/base_api.h"\n#include "managers/plugin_manager.h"\n#include "codecs/codec_api.h"\nusing namespace snort;\nvoid PluginManager::load_plugins(const BaseApi** p)\n{ for (; p && *p; ++p) printf("LOAD %%s\\n", (*p)->name); }\nint main(){ load_codecs(); return 0; }\n' > "$H"/probe_lc.cc
test "$(md5sum "$H"/probe_lc.cc | awk '{print $1}')" = "41b81ccdf9d5e399fa1bd75138624027"
GXXC="g++ -std=c++17 -O0 -w -I$H/cpc -I$C"
$GXXC -c "$H"/probe_lc.cc -o "$H"/probe_lc.o
$GXXC -c "$SRC"/src/codecs/misc/cd_default.cc  -o "$C"/cd_default.o
$GXXC -c "$SRC"/src/codecs/ip/cd_bad_proto.cc  -o "$C"/cd_bad_proto.o
$GXXC -c "$SRC"/src/codecs/ip/cd_no_next.cc    -o "$C"/cd_no_next.o
$GXXC -c "$SRC"/src/codecs/root/cd_raw.cc      -o "$C"/cd_raw.o
$GXXC -c "$SRC"/src/codecs/codec_api.cc        -o "$C"/codec_api18e.o
$GXX $OBJS $ROWS_O "$C"/cd_default.o "$C"/cd_bad_proto.o "$C"/cd_no_next.o "$C"/cd_raw.o "$C"/codec_api18e.o "$H"/probe_lc.o "$H"/stubs_18e.o "$H"/witness_conf.o "$H"/stubs_18d.o -o "$H"/probe_ii 2>"$H"/linkII.txt
timeout 60 "$H"/probe_ii > "$H"/vectors_faceII.txt 2>"$H"/runII_err.txt
test "$(wc -l < "$H"/vectors_faceII.txt)" -eq 5
test "$(md5sum "$H"/vectors_faceII.txt | awk '{print $1}')" = "cdaa92dfb8bdb35ce1ffaa41c1ae3fc4"
grep -q '^LOAD cd_ipv4_stub$' "$H"/vectors_faceII.txt            # 3 stubs SURVIVE the flip
test "$(grep -c 'LOAD cd_hopopts_stub' "$H"/vectors_faceII.txt || true)" -eq 0
grep -q '^LOAD ipv6_hop_opts$' "$H"/vectors_faceII.txt           # ...and the 4th FORKS to the REAL table (codec_api.cc:34 extern + :82 load_plugins(cd_hopopts))
grep -q '^LOAD unknown$' "$H"/vectors_faceII.txt                 # cd_default via load_codecs()

# ---- gate-lineage receipts (PLAN 7: the 13th-straight argument, ZERO-EDIT) ----
FM=/opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" "$FM"
grep -q "4826fc2233044a2d5429413faf0ae1af" "$FM"
test "$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 24
test ! -e "$H"/gate.txt
test ! -e "$H"/gate
test "$(find "$H" -maxdepth 1 -name 'gate*' | wc -l)" -eq 0

echo "row-TU nm census: hopopts=$(wc -l < "$H/nm_U_cd_hop_opts.txt") dstopts=$(wc -l < "$H/nm_U_cd_dst_opts.txt") routing=$(wc -l < "$H/nm_U_cd_routing.txt") mobility=$(wc -l < "$H/nm_U_cd_mobility.txt") igmp=$(wc -l < "$H/nm_U_cd_igmp.txt") (witnesses: ZERO new; donor codec.o+module.o resolve all)"
echo "stub census 3-face: frozen=4 retired=3 real=5 + E6 dup $(test -s "$H/E6_hopopts_dup_collision.txt" && echo proven) + FACE-II flip $(grep -q '^LOAD ipv6_hop_opts$' "$H/vectors_faceII.txt" && echo FORK-MEASURED)"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "vectors md5: $(md5sum "$H/vectors.txt") faceA: $(md5sum "$H/vectors_faceA.txt")"
echo "gate census holders: $(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')/24 (ext harness gate.txt count 0)"
echo "EXT_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt") faceA=$(wc -l < "$H/vectors_faceA.txt")"
