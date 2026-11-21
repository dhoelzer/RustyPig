#!/usr/bin/env bash
# miscip_harness -- row 18j: the misc ip-in-icmp PAIR: codecs/misc/cd_icmp4_ip.cc
# 345 L + cd_icmp6_ip.cc 162 L = 507 L total. THE tcp.h-ONLY-fresh-cp row: the
# pair's 8 includes vs the LIVE daq3 donor tree = 7 find-1 + tcp.h find-0 ->
# EXACTLY 1 fresh header cp (protocols/tcp.h 211 L, cd_icmp6_ip's closure = 3
# includes, ZERO fresh cp of its own). THE hidden-table row: the cd_*_ip[]
# tables ride a #ifdef BUILDING_SO split (cd_icmp4_ip :336/:339/:342 +
# cd_icmp6_ip :154/:157/:160 sed-pinned EVERY build) -- the STATIC arm is what
# the harness compiles, nm table symbol EXACTLY-1 x2. THE witness headline:
# delta EXACTLY +1 fn symbol _ZN5snort13PacketManager14get_proto_nameE10IpProtocol
# (NEXT's +2 prediction MEASURED DOWN: both call sites :179/:297 pass
# ip4h->proto() = IpProtocol (ip.h:116); the ProtocolId overload (packet_manager.h
# :123) is NEVER referenced by these objs -- R2 honest record, PLAN 0/6).
# Staged-link census L1 (pair + DONOR OBJS + WIN + probe.o) MUST die at
# undefined-DISTINCT EXACTLY-1 -> +witness_miscip rc0 GREEN, re-measured EVERY
# build. daq axis: the pair grep-daq 0/0 (the 18i graft NEVER rides this row;
# the graft rides the donor cp but is STRIPPED at end-of-build so the daq3
# :105 second-landing census stays green post-landing -- the E4 daq.h wall
# proves the pair DAQ-free split IN-tree: trio x3 MUST die, pair x2 SURVIVE).
# ZERO-gate row (daq3/small4 clone): combined gate grep 0 x2 + the misc/test/
# CppUTest dialect census (geneve/gtp/teredo add_cpputest x3, TEST_CASE 0 x3)
# re-armed as a STOP-flag tripwire: if ground ever ships Catch material naming
# the pair, the row RE-PLANS to the gre gate shape, loudly. NO Catch face.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
D3=/opt/data/snort3-rust/tools/daq3_harness
TUN=/opt/data/snort3-rust/tools/tun_harness
ETH=/opt/data/snort3-rust/tools/eth_harness
C=$H/copy

# ---- ground identity (TWO row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [cd_icmp4_ip.cc]=c0744dc1d4d38b3b66c3293acae1c04d [cd_icmp6_ip.cc]=60723a7c04827eb877ae229015b9247c )
declare -A WC=( [cd_icmp4_ip.cc]=345 [cd_icmp6_ip.cc]=162 )
for f in cd_icmp4_ip.cc cd_icmp6_ip.cc; do
    test "$(md5sum "$SRC/src/codecs/misc/$f" | awk '{print $1}')" = "${MD5[$f]}"
    test "$(wc -l < "$SRC/src/codecs/misc/$f")" -eq "${WC[$f]}"
done
# pair total face (the row's ledger line): 345+162 = 507 SUM measured
test "$(( $(wc -l < "$SRC/src/codecs/misc/cd_icmp4_ip.cc") + $(wc -l < "$SRC/src/codecs/misc/cd_icmp6_ip.cc") ))" -eq 507
# combined gate grep ZERO x2 EVERY build (if ground ever ships a suite here
# the row is RE-PLANNED to the gre gate shape -- flip trips loudly)
for f in cd_icmp4_ip.cc cd_icmp6_ip.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST' "$SRC/src/codecs/misc/$f" || true)" -eq 0
done

# ---- THE hidden table (BUILDING_SO split) -- sed census PIN lines (R-Q) ----
# the cd_*_ip[] table EXISTS ONLY in the BUILDING_SO-NO (static) arm -- the
# harness face: string `#ifdef BUILDING_SO` guards the snort_plugins export.
test "$(sed -n '336p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '337p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = "SO_PUBLIC const BaseApi* snort_plugins[] ="
test "$(sed -n '339p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = "const BaseApi* cd_icmp4_ip[] ="
test "$(sed -n '342p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = "    &icmp4_ip_api.base,"
test "$(sed -n '154p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '157p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = "const BaseApi* cd_icmp6_ip[] ="
test "$(sed -n '160p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = "    &icmp6_ip_api.base,"
test "$(grep -c 'BUILDING_SO'  "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" -eq 1
test "$(grep -c 'snort_plugins' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" -eq 1
test "$(grep -c 'BUILDING_SO'  "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" -eq 1
test "$(grep -c 'snort_plugins' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" -eq 1
# file base == table base == NAME x2 (drift-family grep with NOTHING to catch;
# the icmp6 NAME rides #ifndef :33-:35 with the ground doc comment :31-:32
# "this macros is defined in the module to ensure identical names..." --
# a NAME-vs-MODULE doc cite, NOT drift)
test "$(sed -n '37p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = '#define ICMP4_IP_NAME "icmp4_ip"'
test "$(sed -n '33p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = '#ifndef ICMP6_IP_NAME'
test "$(sed -n '34p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = '#define ICMP6_IP_NAME "icmp6_ip"'
# HELP arms ride the ground #defines (FACE-A greps ride THESE, sed cites)
test "$(sed -n '38p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = '#define ICMP4_IP_HELP "support for IP in ICMPv4"'
test "$(sed -n '37p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = '#define ICMP6_IP_HELP "support for IP in ICMPv6"'

# ---- externs + loads + ladder ALL RESIDENT (rows ADD TUs, NEVER touch) ----
test "$(sed -n '55p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_icmp4_ip[];"
test "$(sed -n '57p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_icmp6_ip[];"
test "$(sed -n '100p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_icmp4_ip);"
test "$(sed -n '102p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_icmp6_ip);"
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern cc census
# the rust ladder face (rows NEVER re-touch): resident names
test "$(sed -n '113p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_icmp4_ip",'
test "$(sed -n '115p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_icmp6_ip",'
test "$(sed -n '97p'  /opt/data/snort3-rust/src/codecs/codec_api.rs)" = 'pub const STATIC_CODEC_EXTERN_NAMES: [&str; 34] = ['
# the daq3 test pin rides EXISTENCE-but-UNLOADED (re-grep, pin comment stays
# true: names remain CONTAINED; the future 18j parity test TURNS it loaded)
grep -q 'STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp4_ip")' /opt/data/snort3-rust/tests/daq3_parity_test.rs
grep -q 'STATIC_CODEC_EXTERN_NAMES.contains(&"cd_icmp6_ip")' /opt/data/snort3-rust/tests/daq3_parity_test.rs

# ---- misc/test dialect census (the STOP-flag probe, NEGATIVE, re-armed) ----
# ground misc/test/ = CppUTest suites ONLY (add_cpputest x3: geneve/gtp/teredo,
# TEST_CASE 0 x3, pair-TU includes 0 x3): NO Catch material at this row ->
# probe-only, NO STOP-flag. Flip = a Catch suite naming the pair = RE-PLAN.
test "$(grep -c 'add_cpputest' "$SRC/src/codecs/misc/test/CMakeLists.txt")" -eq 3
for f in geneve_codec_test.cc gtp_codec_test.cc teredo_codec_test.cc; do
    if [ "$(grep -c 'TEST_CASE' "$SRC/src/codecs/misc/test/$f")" -ne 0 ]; then
        echo "STOP-FLAG TRIP: $f carries Catch TEST_CASE material -- RE-PLAN to the gre gate shape"; exit 1
    fi
    test "$(grep -c 'cd_icmp4_ip\|cd_icmp6_ip' "$SRC/src/codecs/misc/test/$f" || true)" -eq 0
done

# ---- witness-body honesty (R1): the get_proto_name witness is a CITED
# MINIMAL OBSERVABLE stub -- the REAL body (packet_manager.cc :1004-:1008
# CodecManager walk) does NOT compile on the resident chain (the scratch
# bodytest rc1: managers/codec_manager.h NEVER cp'd = the pull-rule face);
# the real TU (1,047 L, find tools = 0 in EVERY donor) stays the REJECT face.
test "$(sed -n '1004p' "$SRC/src/protocols/packet_manager.cc")" = "const char* PacketManager::get_proto_name(IpProtocol protocol)"
test "$(wc -l < "$SRC/src/protocols/packet_manager.cc")" -eq 1047
test "$(find /opt/data/snort3-rust/tools -name packet_manager.cc | wc -l)" -eq 0
test "$(sed -n '179p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc" | sed 's/^ *//')" = "PacketManager::get_proto_name(ip4h->proto()),"
test "$(sed -n '297p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc" | sed 's/^ *//')" = "PacketManager::get_proto_name(ip4h->proto()),"
test "$(grep -c get_proto_name "$SRC/src/codecs/misc/cd_icmp6_ip.cc" || true)" -eq 0   # icmp6_ip: ZERO refs

# ---- copy tree = daq3 DONOR VERBATIM (103) + EXACTLY 1 fresh header cp
# (tcp.h) + 2 pair TUs = 106 (PLAN 2; MEASURED asserts, NEVER typed 17p) ----
if [ ! -e "$D3/copy/codec.o" ]; then bash "$D3/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$D3/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 103   # live head-face donor count (the 18i landed face)
# per-include residency census vs the donor (7 find-1 + tcp.h find-0 = the
# row's ONLY fresh cp; R-A/D MEASURED face re-run EVERY build)
for h in codecs/codec_module.h framework/codec.h log/text_log.h main/snort_config.h protocols/icmp4.h protocols/packet_manager.h protocols/udp.h; do
    test "$(find "$C" -path "*/$h" | wc -l)" -eq 1
done
test ! -e "$C/protocols/tcp.h"                                          # the EXACTLY-1 fresh-landing face
# the tcp.h fresh cp (md5+wc = ground faces, receipts R-D)
test "$(md5sum "$SRC/src/protocols/tcp.h" | awk '{print $1}')" = "a7ac7b82ce15c24d57b2fb9114a52cf9"
test "$(wc -l < "$SRC/src/protocols/tcp.h")" -eq 211
cp "$SRC/src/protocols/tcp.h" "$C/protocols/tcp.h"
cmp -s "$C/protocols/tcp.h" "$SRC/src/protocols/tcp.h"
# graft tripwires (inherited daq3 VERBATIM): the SDK header stays ABSENT
# ground+host; the graft rides the donor cp (NEVER re-cp'd, NEVER edited);
# NO third landing tools-side (excl daq3 = THE landing + this row's riding tree)
test "$(find "$SRC" -name daq.h | wc -l)" -eq 0
test "$(ls /usr/include/daq.h /usr/include/daq/*.h 2>/dev/null | wc -l)" -eq 0
test "$(find /opt/data/snort3-rust/tools -name daq.h ! -path '/opt/data/snort3-rust/tools/daq3_harness/*' ! -path '/opt/data/snort3-rust/tools/miscip_harness/*' | wc -l)" -eq 0
test "$(( $(grep -c daq "$SRC/src/codecs/misc/cd_icmp4_ip.cc" || true) + $(grep -c daq "$SRC/src/codecs/misc/cd_icmp6_ip.cc" || true) ))" -eq 0   # pair grep-daq 0/0
mkdir -p "$C/codecs/misc"
for f in cd_icmp4_ip.cc cd_icmp6_ip.cc; do
    test ! -e "$C/codecs/misc/$f"                                       # fresh-landing face
    cp "$SRC/src/codecs/misc/$f" "$C/codecs/misc/$f"
    cmp -s "$C/codecs/misc/$f" "$SRC/src/codecs/misc/$f"
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 106   # 103 donor + 1 fresh hdr + 2 pair TUs (MEASURED census face, graft riding included)
# residency riders (donor-paid): the pair's other 6 includes + codec.h chain
test -e "$C/protocols/icmp4.h"
test -e "$C/protocols/packet_manager.h"
test -e "$C/protocols/udp.h"
test -e "$C/codecs/codec_module.h"
test -e "$C/framework/codec.h"
test -e "$C/log/text_log.h"
test -e "$C/main/snort_config.h"
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probe pulls NO codec_api)
test ! -e "$C/codecs/codec_api.cc"

GXX0="g++ -std=c++17 -O0 -w -I$C"
# ---- E4 WALLS (PLAN 2): stripped-tree flipped-asserts EVERY build on the
# ADDITIVE all-5-TU face (one-shot: a live strip can ONLY mean donor drift ->
# loud rc 1). 18j table: tcp.h -> ONLY cd_icmp4_ip DIES (the row's headline
# wall, the scratch-rehearsed face now IN-TREE); daq.h -> trio x3 DIE, BOTH
# pair TUs SURVIVE (the pair-DAQ-free split IN-tree, the 18i wall-1 survivor
# face re-armed at this face); udp.h -> cd_udp + cd_icmp4_ip (:31); icmp4.h ->
# cd_icmp4 + cd_icmp6 + cd_icmp4_ip (:28, the daq3 cross-rider face extended
# pair-side); full restore -> ALL FIVE rc0 stderr-0. ----
mv "$C/protocols/tcp.h" "$H/.e4_hold_tcp.h"
# survivor paths differ by dir (ip/ + misc/); honest per-TU faces:
for pair in ip:cd_udp ip:cd_icmp4 ip:cd_icmp6 misc:cd_icmp6_ip; do
    d=${pair%%:*}; f=${pair##*:}
    $GXX0 -fsyntax-only "$C/codecs/$d/$f.cc" 2> "$H/E4_notcp_$f.txt"
    test ! -s "$H/E4_notcp_$f.txt"
done
if $GXX0 -fsyntax-only "$C/codecs/misc/cd_icmp4_ip.cc" -o /dev/null 2> "$H/E4_notcp_4.txt"; then
    echo "E4 flip BROKE: cd_icmp4_ip compiled WITHOUT protocols/tcp.h (cc:30)"; exit 1
fi
head -1 "$H/E4_notcp_4.txt" | grep -q "fatal error: protocols/tcp.h: No such file"
test ! -s "$H/E4_notcp_6.txt"                          # icmp6_ip NEVER includes tcp.h
mv "$H/.e4_hold_tcp.h" "$C/protocols/tcp.h"
mv "$C/daq.h" "$H/.e4_hold_daq.h"
for f in cd_udp cd_icmp4 cd_icmp6; do                  # daq.h: trio MUST die (graft rides their include)
    if $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" -o /dev/null 2> "$H/E4_nodaq_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT daq.h -- the graft face is dead, PLAN 2 graft-carry is wrong"; exit 1
    fi
    head -1 "$H/E4_nodaq_$f.txt" | grep -q "fatal error: daq.h: No such file"
done
for f in cd_icmp4_ip cd_icmp6_ip; do                   # pair SURVIVE = the DAQ-free split
    $GXX0 -fsyntax-only "$C/codecs/misc/$f.cc" 2> "$H/E4_nodaq_$f.txt"
    test ! -s "$H/E4_nodaq_$f.txt"
done
mv "$H/.e4_hold_daq.h" "$C/daq.h"
mv "$C/protocols/udp.h" "$H/.e4_hold_udp.h"
if $GXX0 -fsyntax-only "$C/codecs/ip/cd_udp.cc" -o /dev/null 2> "$H/E4_noudp_udp.txt"; then
    echo "E4 flip BROKE: cd_udp compiled WITHOUT protocols/udp.h"; exit 1
fi
if $GXX0 -fsyntax-only "$C/codecs/misc/cd_icmp4_ip.cc" -o /dev/null 2> "$H/E4_noudp_4.txt"; then
    echo "E4 flip BROKE: cd_icmp4_ip compiled WITHOUT protocols/udp.h (cc:31)"; exit 1
fi
head -1 "$H/E4_noudp_4.txt" | grep -q "fatal error: protocols/udp.h: No such file"
for pair in ip:cd_icmp4 ip:cd_icmp6 misc:cd_icmp6_ip; do
    d=${pair%%:*}; f=${pair##*:}
    $GXX0 -fsyntax-only "$C/codecs/$d/$f.cc" 2> "$H/E4_noudp_$f.txt"
    test ! -s "$H/E4_noudp_$f.txt"
done
mv "$H/.e4_hold_udp.h" "$C/protocols/udp.h"
mv "$C/protocols/icmp4.h" "$H/.e4_hold_icmp4.h"
for f in cd_icmp4 cd_icmp6; do                         # daq3 cross-rider face x2
    if $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" -o /dev/null 2> "$H/E4_noicmp4_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT protocols/icmp4.h"; exit 1
    fi
    head -1 "$H/E4_noicmp4_$f.txt" | grep -q "fatal error: protocols/icmp4.h: No such file"
done
if $GXX0 -fsyntax-only "$C/codecs/misc/cd_icmp4_ip.cc" -o /dev/null 2> "$H/E4_noicmp4_4.txt"; then
    echo "E4 flip BROKE: cd_icmp4_ip compiled WITHOUT protocols/icmp4.h (cc:28)"; exit 1
fi
head -1 "$H/E4_noicmp4_4.txt" | grep -q "fatal error: protocols/icmp4.h: No such file"
test ! -s "$H/E4_notcp_cd_icmp6_ip.txt"   # icmp6_ip SURVIVES the udp.h strip face
mv "$H/.e4_hold_icmp4.h" "$C/protocols/icmp4.h"
for p in ip:cd_udp ip:cd_icmp4 ip:cd_icmp6 misc:cd_icmp4_ip misc:cd_icmp6_ip; do   # restored full tree
    d=${p%%:*}; f=${p##*:}
    $GXX0 -c "$C/codecs/$d/$f.cc" -o "$C/$f.precheck.o" 2> "$H/E4_$f.txt"
    test ! -s "$H/E4_$f.txt"
    rm -f "$C/$f.precheck.o"
done

GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"

# ---- witness carry: WIN trio INHERITED (md5 pins NEVER re-derived) + THE
# new face witness_miscip.cc (tracked, md5-pinned = the honest +1 delta) ----
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
# witness_conf.cc = the landed 4dd91018 heredoc face (daq3 :303-:346 VERBATIM
# re-materialize -- NEVER re-derived, the pin proves byte-identity)
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
test "$(wc -l < "$H/witness_miscip.cc")" -eq 27
test "$(md5sum "$H/witness_miscip.cc" | awk '{print $1}')" = "c5b498ffa6beac768f34e25830c552a1"   # THE new tracked witness face (measured, PLAN 5 stageables pin like witness_daq e0166b02)
# ---- O0 compile: TWO plain .o + donor REAL .o + probes + witnesses --------
for f in cd_icmp4_ip cd_icmp6_ip; do $GXX -c "$C/codecs/misc/$f.cc" -o "$C/$f.o"; done
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o
$GXX -c "$H"/witness_miscip.cc -o "$H"/witness_miscip.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/cd_icmp4_ip.o $C/cd_icmp6_ip.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# hidden-table one-symbol-per-.o face: the STATIC-arm table symbol EXACTLY-1
# each (the BUILDING_SO-NO compile face = the harness face, R-G)
test "$(nm --defined-only "$C/cd_icmp4_ip.o" | grep -cE ' [DdRr] cd_icmp4_ip$')" -eq 1
test "$(nm --defined-only "$C/cd_icmp6_ip.o" | grep -cE ' [DdRr] cd_icmp6_ip$')" -eq 1

# ---- nm per-TU U-census (receipts; counts MEASURED, NEVER typed) --------
for f in cd_icmp4_ip cd_icmp6_ip; do
    nm -C -u "$C/$f.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$f.txt"
    test "$(grep -c 'tunnel_bypass' "$H/nm_U_$f.txt" || true)" -eq 0     # bypass axis stays ZERO
done
cat "$H"/nm_U_cd_*.txt | sort -u > "$H/nm_U_union.txt"
# THE witness-delta face re-measured EVERY BUILD (staged link, PLAN 6):
# L1 = pair + OBJS + WIN + probe.o (main EXISTS), NO witness_miscip -> MUST
# die at undefined-DISTINCT EXACTLY-1 (the MEASURED get_proto_name(IpProtocol)
# overload -- the +2 prediction MEASURED DOWN, R2).
if $GXX $ROWS $OBJS "$H"/probe.o $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: pair linked WITHOUT witness_miscip -- the +1 delta is wrong"; exit 1
fi
grep "undefined reference to" "$H/L1_link_face.txt" > "$H/L1_undefined.txt"
grep -q "undefined reference to .snort::PacketManager::get_proto_name(IpProtocol)" "$H/L1_link_face.txt"
test "$(grep -oE "undefined reference to \`[^']*'" "$H/L1_link_face.txt" | sort -u | wc -l)" -eq 1   # EXACTLY-1 undefined face
# the overload census face (R-K): the mangled undefined symbol is the
# IpProtocol overload EXACTLY-1; the ProtocolId overload NEVER referenced
test "$(nm -u $ROWS | grep -c '_ZN5snort13PacketManager14get_proto_nameE10IpProtocol')" -eq 1   # one U entry (2 call sites :179/:297 share it in ONE .o)
test "$(nm -u $ROWS | grep -c 'get_proto_nameE10ProtocolId' || true)" -eq 0
rm -f "$H/.L1_probe"
# residue class (MANGLED face = robust; daq3 classifier inherited): every
# snort-family U of the pair .o MUST be defined by OBJS+WIN+witness_miscip.
g2="$C/cd_icmp4_ip.o $C/cd_icmp6_ip.o"
nm -u $g2 | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
donordefs=$(nm --defined-only $OBJS $WIN "$H"/witness_miscip.o | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# THE own-new-symbol census pin (-eq 1, PLAN 6): the witness .o contributes
# EXACTLY ONE T symbol and NOTHING ELSE new (zero-other-new verify)
test "$(nm --defined-only "$H"/witness_miscip.o | grep -c ' T ')" -eq 1
nm -C --defined-only "$H"/witness_miscip.o | grep -q 'T snort::PacketManager::get_proto_name(IpProtocol)'
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# landmine posture ZERO (18e rule): no 18j name frozen in ANY witness donor
for n in cd_icmp4_ip cd_icmp6_ip; do
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc || true)" -eq 0
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/codec_harness/stubs.cc || true)" -eq 0
done
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"

# real-symbol defines (donor face, gre-recipe)
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
grep -q 'T snort::Codec::CheckIPv6ExtensionOrder' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
grep -q 'T tun_witness_set_mask' <<< "$(nm -C --defined-only "$H"/witness_18f.o)"
# (NO daq define face HERE: the pair NEVER touches the daq seam -- grep-daq 0/0)

# ---- probe links: L2 face = WIN trio + witness_miscip -> GREEN ----------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN "$H"/witness_miscip.o -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN "$H"/witness_miscip.o -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
# the witness symbol rides BOTH links EXACTLY-1 (the +1 backbone delta face)
test "$(nm -C "$H"/probe | grep -c 'T snort::PacketManager::get_proto_name')" -eq 1
test "$(nm -C "$H"/probe_dec | grep -c 'T snort::PacketManager::get_proto_name')" -eq 1

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in cd_icmp4_ip cd_icmp6_ip; do $GXXA -c "$C/codecs/misc/$f.cc" -o "$O2/$f.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc   -o "$O2"/stubs_18d.o; $GXXA -c "$H"/witness_miscip.cc -o "$O2"/witness_miscip.o
OB2="$O2/cd_icmp4_ip.o $O2/cd_icmp6_ip.o"
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_miscip.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_miscip.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool b=.*->decode' "$H"/probe_dec.cc)" -eq 14   # MEASURED face (10 icmp4 + 4 icmp6 arms)
test "$(grep -c 'printf.*->decode' "$H"/probe_dec.cc || true)" -eq 0
test "$(grep -c '0x' "$H"/vectors_O0.txt || true)" -eq 0    # all-decimal hygiene
test "$(grep -c '0x' "$H"/vectors_faceA_O0.txt || true)" -eq 0

# ---- known-answer ladders: greps pin the MEASURED faces against GROUND
# anchors (17p). First run seeds the tracked faces; later runs cmp above. ----
V=${V:-$H/vectors.txt}; FA=${FA:-$H/vectors_faceA.txt}
if [ ! -e "$V" ] || [ ! -e "$FA" ]; then
    cp "$H"/vectors_O0.txt "$V"; cp "$H"/vectors_faceA_O0.txt "$FA"
    echo "FIRST-RUN SEED: $(md5sum "$V" "$FA")"
fi
# FACE-A: pair NAME + hidden-table walk face (ground #defines sed-pinned above)
grep -q '^LOAD icmp4_ip$'  "$FA"
grep -q '^LOAD icmp6_ip$'  "$FA"
grep -q '^LOADS 2$'        "$FA"
grep -q '^API icmp4_ip type=0 size=112 ver=1900547 name=icmp4_ip$' "$FA"   # CDAPI carry (same framework/codec.h as daq3 :468)
grep -q '^API icmp6_ip type=0 size=112 ver=1900547 name=icmp6_ip$' "$FA"
grep -q '^HELP icmp4_ip support for IP in ICMPv4$' "$FA"
grep -q '^HELP icmp6_ip support for IP in ICMPv6$' "$FA"
# THE mod_ctor=0 x2 face (the row's asymmetry pin -- contrast daq3's uniform
# mod_ctor=1 x3 grep face daq3 build.sh :472-:474; ground api structs nullptr
# faces cd_icmp4_ip.cc :325/:326 + cd_icmp6_ip.cc :143/:144):
test "$(sed -n '325p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = "        nullptr, // module constructor"
test "$(sed -n '326p' "$SRC/src/codecs/misc/cd_icmp4_ip.cc")" = "        nullptr  // module destructor"
test "$(sed -n '143p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = "        nullptr, // module constructor"
test "$(sed -n '144p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc")" = "        nullptr  // module destructor"
grep -q '^icmp4_ip mod_ctor=0 mod_dtor=0$' "$FA"
grep -q '^icmp6_ip mod_ctor=0 mod_dtor=0$' "$FA"
# GETIDS face: the row-scoped embed ids PRINTED decimal (ground protocol_ids.h
# sed-pinned; the 259/260 values are DERIVED below by the python census)
grep -q '^GETIDS icmp4_ip 259$' "$FA"
grep -q '^GETIDS icmp6_ip 260$' "$FA"
grep -q '^    IP_EMBEDDED_IN_ICMP4 = 0x0103,$' "$SRC/src/protocols/protocol_ids.h"
grep -q '^    IP_EMBEDDED_IN_ICMP6 = 0x0104,$' "$SRC/src/protocols/protocol_ids.h"
# DEC ladders: the six-event icmp4 face (ground call sites, receipts W)
grep -q '^IP4 short19 -> 0$'          "$V"; grep -q '^EV 116 250$' "$V"   # :56/:58
grep -q '^IP4 ver6-ip4api -> 0$'      "$V"; grep -q '^EV 116 251$' "$V"   # :69/:71 dies (is_ip6 FALSE)
grep -q '^IP4 ver6-ip6rider -> 1 pb=16384 lyr=20$' "$V"                   # R5 rider arm survives (is_ip6 TRUE)
grep -q '^IP4 hlen24-22 -> 0$'        "$V"; grep -q '^EV 116 252$' "$V"   # :77/:79
grep -q '^IP4 pay7 -> 0$'             "$V"; grep -q '^EV 116 253$' "$V"   # :89/:91
grep -q '^IP4 gt576 -> 1 pb=8192 lyr=20$' "$V"; grep -q '^EV 116 254$' "$V"  # :97/:99 EVENT-THEN-CONTINUE
grep -q '^IP4 fragoff -> 0$'          "$V"; grep -q '^EV 116 255$' "$V"   # :102/:105
test "$(grep -c '^EV 116 250$' "$V")" -eq 2   # shared name x2 TUs (250 rides icmp4 :58 + icmp6 :63)
test "$(grep -c '^EV 116 251$' "$V")" -eq 2   # shared name x2 TUs (251 rides :71 + :73)
# embed-switch arms (PROTO_BIT values NEVER typed -- derived in the census below)
grep -q '^IP4 embed-tcp -> 1 pb=4096$'  "$V"
grep -q '^IP4 embed-icmp -> 1 pb=16384$'  "$V"
grep -q '^IP4 embed-other -> 1 pb=32768$' "$V"
# icmp6 arms (three-name census; :78/:80 GROUND-DEAD cite line NEVER EV'd)
grep -q '^IP6 short39 -> 0$'  "$V"
grep -q '^IP6 ver4 -> 0$'     "$V"
grep -q '^IP6 252-unarmed cc:78-fixed-true$' "$V"
test "$(sed -n '77p' "$SRC/src/codecs/misc/cd_icmp6_ip.cc" | grep -c 'cppcheck-suppress knownConditionTrueFalse')" -eq 1  # ground's OWN dead-code suppression = the cite
grep -q '^IP6 next-tcp -> 1 pb=4096 lyr=40$'     "$V"   # lyr = IP6_HEADER_LEN (ipv6.h :31 sed-pinned below)
grep -q '^IP6 next-default -> 1 pb=32768 lyr=40$' "$V"
test "$(wc -l < "$SRC/src/protocols/ipv6.h")" -ge 31
test "$(sed -n '31p' "$SRC/src/protocols/ipv6.h")" = "constexpr uint8_t IP6_HEADER_LEN = 40;"
test "$(sed -n '38p' "$SRC/src/protocols/ipv4.h")" = "constexpr uint8_t IP4_HEADER_LEN = 20;"
python3 - <<'PYPIN'
# THE sids + PROTO_BIT face PINNED BOTH WAYS (ground enum/#define walk vs the
# MEASURED vector face -- every value the ladders grep rides ground, never air).
import re
h = open("/opt/data/snort3-src/src/codecs/codec_module.h").read()
m = re.search(r'enum\s+CodecSid[^{]*\{', h); body = h[m.end():]; val = 0; g = {}
for line in body.split("\n"):
    mm = re.match(r"\s*([A-Z_0-9]+)\s*(?:=\s*(\d+))?\s*,", line)
    if mm:
        name = mm.group(1); val = int(mm.group(2)) if mm.group(2) else val + 1; g[name] = val
    if re.match(r"\s*};", line): break
NAMES = """DECODE_ICMP_ORIG_IP_TRUNCATED DECODE_ICMP_ORIG_IP_VER_MISMATCH DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP
DECODE_ICMP_ORIG_PAYLOAD_LT_64 DECODE_ICMP_ORIG_PAYLOAD_GT_576 DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET""".split()
assert len(NAMES) == 6
sids = set(g[n] for n in NAMES)
assert sids == {250,251,252,253,254,255}, sids
for n in NAMES:
    r = re.findall(rf"{n} = (\d+),", open("/opt/data/snort3-rust/src/codecs/codec_module.rs").read())
    assert r and int(r[0]) == g[n], (n, g[n], r)
# pair unique-EVENT census (ground grep): icmp4_ip 6 / icmp6_ip 3 (subset)
import subprocess
def uniq(t): return set(l.split()[-1] for l in t.splitlines() if l.strip())
u4 = subprocess.run(["grep","-oE",r"codec_event\(codec,\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/misc/cd_icmp4_ip.cc"],capture_output=True,text=True).stdout
u6 = subprocess.run(["grep","-oE",r"codec_event\(codec,\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/misc/cd_icmp6_ip.cc"],capture_output=True,text=True).stdout
c4, c6 = uniq(u4), uniq(u6)
assert len(c4) == 6 and len(c3:=c6) == 3 and c3 <= c4, (len(c4), len(c6))
# vector EV face: the MEASURED EV lines must be EXACTLY the ground sids the
# armed arms print (252 UNARMED pair-side face: icmp4 hlen24 arms it, icmp6
# NEVER does -- ground-fixed-true :78, cite line in the vectors, ZERO EV)
V = set(int(l.split()[2]) for l in open("/opt/data/snort3-rust/tools/miscip_harness/vectors.txt") if l.startswith("EV "))
assert V == {250,251,252,253,254,255}, V
# PROTO_BIT embed census (decode_data.h :99-:102 ground #defines -> decimal)
dd = open("/opt/data/snort3-src/src/framework/decode_data.h").read()
pb = {n:int(v,16) for n,v in re.findall(r'#define\s+(PROTO_BIT__[A-Z_0-9]+)\s+(0x[0-9A-Fa-f]+)', dd)}
fa = open("/opt/data/snort3-rust/tools/miscip_harness/vectors.txt").read()
for n in ("PROTO_BIT__TCP_EMBED_ICMP","PROTO_BIT__UDP_EMBED_ICMP","PROTO_BIT__ICMP_EMBED_ICMP","PROTO_BIT__ICMP_EMBED_OTHER"):
    assert f"pb={pb[n]}" in fa, (n, pb[n])
# the 4 embed names ride EXACTLY the pair's switch arms (ground site census 4)
assert len(set(re.findall(r'PROTO_BIT__[A-Z_0-9]+', open("/opt/data/snort3-src/src/codecs/misc/cd_icmp4_ip.cc").read()) +
               re.findall(r'PROTO_BIT__[A-Z_0-9]+', open("/opt/data/snort3-src/src/codecs/misc/cd_icmp6_ip.cc").read()))) == 4
PYPIN

# ---- known-answer wc+md5 pins (OUTPUT of the MEASURED first run; build.sh
# DRIFTS-then-refuses, NEVER fabricates; 17p no arithmetic/forecast typed) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 23          # MEASURED first-run face
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 11    # MEASURED first-run face
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "43b259ac8b77320ff9ddaa80dde1a36e"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "e4c47bac93a15af4ecfdc9a0bd1abe62"

# ---- frozen-donor direct-md5 census (daq3 :614-:636 face VERBATIM, 15
# faces -- the DIRECT face; tun/eth/ext -eq 24 ls-asserts stay UN-chased) ----
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

# ---- BACKBONE-8 census (the IMMEDIATE chain face: small4 + daq3 + the WIN
# trio -- 8 faces, additive-safe: NO gre/fmod/vocab self-literal rides THIS
# group -- those ride the FM15 clone above + the chain-echo greps below) ----
declare -a B8=(
 "/opt/data/snort3-rust/tools/small4_harness/vectors.txt 462f0ff6ed44220564c5ef0c8538ad80"
 "/opt/data/snort3-rust/tools/small4_harness/vectors_faceA.txt 4755d48c54cc057b3c3c9eafec01c7cf"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors.txt fd1855e10e08eedcc6598de7ee034d0e"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors_faceA.txt 2fb9dc4570a0160451f8399d22736a60"
 "/opt/data/snort3-rust/tools/daq3_harness/witness_daq.cc e0166b021073fed328bfd583c839e38b"
 "$H/witness_conf.cc 4dd91018f8439d706ba666c6f18c9152"
 "/opt/data/snort3-rust/tools/tun_harness/witness_18f.cc ea1f79f3f05f8a91dc9524a963692b39"
 "/opt/data/snort3-rust/tools/eth_harness/stubs_18d.cc f4afd35f06bc45ce5aa0ec12110ed8ae"
)
for e in "${B8[@]}"; do
    set -- $e
    test "$(md5sum "$1" | awk '{print $1}')" = "$2"
done
md5sum "${B8[@]%% *}" > "$H/backbone8.txt"   # receipt (ignored)

# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" /opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "4826fc2233044a2d5429413faf0ae1af" /opt/data/snort3-rust/tools/fmod_harness/build.sh
# gre GATE anchor (the 18g chain rides this VERBATIM face pin):
test "$(md5sum /opt/data/snort3-rust/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" /opt/data/snort3-rust/tools/gre_harness/gate.txt
# vocab chain anchor (18e witness face, self-literal in ITS OWN build.sh --
# additive-safe NEVER pinned by THIS row):
grep -q "9fad7e9d7a278fbc2ee82c233f86e774" /opt/data/snort3-rust/tools/vocab_harness/build.sh

# ---- TWO-LINEAGE census loop (MEASURED, never typed; THIS row adds ZERO
# gate.txt so the 25-tracked face is UNDISTURBED BY DESIGN): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY
# name-pin census re-armed (row dir stays family-FREE per gre :41 ip-name
# pre-ban; a future row's name colliding = loud; THE hidden-table tripwire
# face: the dir name NEVER freezes a table name):
test "$(ls -d /opt/data/snort3-rust/tools/icmpip_harness /opt/data/snort3-rust/tools/ipmisc_harness /opt/data/snort3-rust/tools/pair_harness 2>/dev/null | wc -l)" -eq 0
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin: the 18i PROCESS-LESSONS law (the working HEAD MOVES
# at EVERY landing; the daq3 build.sh :155-:161 drop-comment inherited).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (git ls-files, NEVER pre-typed
# arithmetic): the NON-ignored face of this dir = exactly the 7 stageables.
# FACE POSTURE (18i re-rule): PRE-commit the 7 are UNTRACKED (--others);
# POST-commit the SAME proof runs against the landed face. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/miscip_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/miscip_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 7
for f in PLAN.md build.sh probe.cc probe_dec.cc vectors.txt vectors_faceA.txt witness_miscip.cc; do
    echo "$face" | grep -q "tools/miscip_harness/$f$"
done
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/daq.h copy/cd_icmp4_ip.o o2/cd_icmp4_ip.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_18f.o witness_conf.o witness_miscip.o witness_miscip2.o vectors_O0.txt vectors_faceA_O2.txt nm_U_cd_icmp4_ip.txt E4_cd_icmp4_ip.txt E4_nodaq_cd_icmp4_ip.txt L1_link_face.txt L1_undefined.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone8.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/miscip_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/miscip_harness/$f NOT ignored"; exit 1; }
done
# vectors NEVER ignored (the stageable face, explicit NOT-proof):
git -C /opt/data/snort3-rust check-ignore -q "tools/miscip_harness/vectors.txt" && { echo "VECTORS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/miscip_harness/vectors_faceA.txt" && { echo "FACE-A WRONGLY IGNORED"; exit 1; } || true
# no STAGED churn: index EMPTY. Tracked-MODIFIED face (lineage-honest, the
# daq3 :677-:687 template): EVERY dirty tracked file must be one of THIS
# row's OWN paths (seed face: .gitignore ONLY -- no Rust wiring at the seed
# pass); POST-commit the face is EMPTY; fires LOUDLY on any face touching
# another row's/committed lineage file. Rows NEVER rewrite history.
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
rowface='^\.gitignore$|^tools/miscip_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|vectors\.txt|vectors_faceA\.txt|witness_miscip\.cc)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface")"

# ---- the graft does NOT stay: STRIP $C/daq.h at end-of-build AFTER every
# compile (the pair NEVER compiles it -- grep-daq 0/0 measured above; the E4
# daq wall proved the trio-only dependency IN-tree). Keeping miscip/copy
# daq.h-FREE is what keeps the daq3 :105 second-landing census green for
# EVERY future session post-landing (an honest addendum to the donor trip-
# wire; the 106 MEASURED find-count rode the graft-in-tree face mid-build).
rm -f "$C/daq.h"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 105   # post-strip pair-tree face (106 minus the riding graft)
test "$(find /opt/data/snort3-rust/tools -name daq.h ! -path '/opt/data/snort3-rust/tools/daq3_harness/*' | wc -l)" -eq 0   # THE landing stays ONE

echo "row-TU nm census (MEASURED, never typed): icmp4_ip=$(wc -l < "$H/nm_U_cd_icmp4_ip.txt") icmp6_ip=$(wc -l < "$H/nm_U_cd_icmp6_ip.txt") union=$(wc -l < "$H/nm_U_union.txt") (tunnel_bypass 0/0 -- bypass axis ZERO)"
echo "witness delta re-measured: L1 undefined-EXACTLY-1 (snort::PacketManager::get_proto_name(IpProtocol) ONLY; ProtocolId overload NEVER referenced) -> +witness_miscip GREEN; the NEXT +2 prediction MEASURED DOWN (R2 honest face)"
echo "copy tree find-count (MEASURED): mid-build 106 (103 donor + 1 fresh hdr tcp.h + 2 pair TUs) / post-strip 105 (the daq graft NEVER stays)"
echo "hidden-table census: BUILDING_SO sed x2 + snort_plugins grep 1/1 + nm table symbol EXACTLY-1 x2 (the STATIC arm IS the harness face)"
echo "E4 adaptation: 1 fresh hdr cp, stripped-tree flipped-asserts (tcp.h: ONLY cd_icmp4_ip DIES, survivors x4; daq.h: trio x3 DIE, pair x2 SURVIVE = in-tree DAQ-free split; udp.h x2; icmp4.h x3) + restored rc0 x5 EVERY build"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED here; tracked gate.txt = 1, ls-files); BACKBONE-8 md5 face pinned (receipt backbone8.txt)"
echo "MISCIP_HARNESS_OK vectors=$( [ -e "$H/vectors.txt" ] && wc -l < "$H/vectors.txt" || wc -l < "$H/vectors_O0.txt") faceA=$( [ -e "$H/vectors_faceA.txt" ] && wc -l < "$H/vectors_faceA.txt" || wc -l < "$H/vectors_O0.txt") gates=0"