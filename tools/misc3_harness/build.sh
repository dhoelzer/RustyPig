#!/usr/bin/env bash
# misc3_harness -- row 18k: the codecs/misc LEFTOVER TRIO: codecs/misc/cd_llc.cc
# 198 L + cd_vxlan.cc 133 L + cd_user.cc 167 L = 498 L total (misc tail CLOSED).
# THE graft-v2 row (R1 landmine): the fmod 16 L daq_common.h graft face FAILS
# the sfdaq pair -- `typedef void* DAQ_Msg_h` dies at cd_user.cc:101 aggregate-
# init { raw.daq_msg, nullptr } (codec.h:59 const struct _daq_msg*): g++ rc1
# "invalid conversion from const void* to DAQ_Msg_h" MEASURED (scratch
# R1_flip_repro). graft-v2 = the DAQ_Msg_h const VOID* FLIP + 6 SDK typedefs
# (DAQ_IoctlCmd/Config_h/Instance_h/Verdict/RecvStatus/Stats_t) + DAQ_SUCCESS,
# shapes cited per the sfdaq PAIR decl lines (sfdaq.h :44/:52/:68 + instance
# :45/:52/:79/:93/:101) + daqs/daq_user.h :30-:46. Frozen harnesses NEVER
# edited: graft-v2 rides ONLY this heredoc (copy/ gitignored, re-materialized
# every build -- per-link isolation, the 18a inverted-landmine corollary); the
# daq3 trio TUs stay GREEN under v2 rc0 x3 (E4_flipv2_* receipts re-run EVERY
# build). daq3's tracked copy/daq.h 33 L (73fdbc39) is REUSED via cp, NEVER a
# second graft (THE landing stays find-1, pinned post-strip).
# THE fresh-cp row: EXACTLY 3 new header cps = daqs/daq_user.h 54 + packet_io/
# sfdaq.h 72 + sfdaq_instance.h 105 (heads/lines sed-pinned; donor per-file
# strip-105 + 3 + 3 row TUs = 111 MEASURED post-strip find-count asserted by
# LITERAL); trio-header landmine ZERO (llc.h/vxlan.h/user.h NEVER exist -- the
# docs 'vxlan.h 82L' face FALSE, §1).
# THE witness row: staged L1 (trio .o + OBJS + WIN + probe.o, NO witness_trio)
# MUST die at undefined-DISTINCT EXACTLY-2 = {SFDAQ::get_local_instance(),
# SFDAQInstance::ioctl(uint,void*,ulong)} (scratch L1_undefined_distinct.txt);
# +witness_trio.cc (TRACKED, SYNTHETIC precedent get_local_instance->nullptr +
# ioctl fills static DAQ_UsrHdr_t -- observable channel) -> rc 0, own-new T
# census EXACTLY 2. tunnel_bypass U-census trio = 0/1/0: witness_18f CARRIED
# (ea1f79f3, EXACTLY zero new bypass witness -- the vxlan HOOK :73-:74 face,
# NOT a peg). get_proto_name U census row = 0: witness_miscip c5b498ff stays
# DONOR-INHERITED citation, NEVER linked here.
# ZERO-gate row (18th straight): combined gate grep 0 x3 + misc/test CppUTest
# dialect census re-armed as STOP-flag tripwire (the 18g grey gate-shape shape
# stays the 19g CONTRAST face). NO gate.txt shipped.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
D3=/opt/data/snort3-rust/tools/daq3_harness
MI=/opt/data/snort3-rust/tools/miscip_harness
TUN=/opt/data/snort3-rust/tools/tun_harness
ETH=/opt/data/snort3-rust/tools/eth_harness
C=$H/copy

# ---- ground identity (THREE row TUs pinned by OWN md5 + wc, measured) ----
declare -A MD5=( [cd_llc.cc]=df63cf75b1bf7642ca80b6a215a0f28c [cd_vxlan.cc]=c8479a2aa67ee6af89c22ecc8f763b7d [cd_user.cc]=01e41407b300562c840b4f66a4da4e45 )
declare -A WC=( [cd_llc.cc]=198 [cd_vxlan.cc]=133 [cd_user.cc]=167 )
for f in cd_llc.cc cd_vxlan.cc cd_user.cc; do
    test "$(md5sum "$SRC/src/codecs/misc/$f" | awk '{print $1}')" = "${MD5[$f]}"
    test "$(wc -l < "$SRC/src/codecs/misc/$f")" -eq "${WC[$f]}"
done
# trio total face (the row's ledger line): 198+133+167 = 498 SUM measured
test "$(( $(wc -l < "$SRC/src/codecs/misc/cd_llc.cc") + $(wc -l < "$SRC/src/codecs/misc/cd_vxlan.cc") + $(wc -l < "$SRC/src/codecs/misc/cd_user.cc") ))" -eq 498
# combined gate grep ZERO x3 EVERY build (if ground ever ships a suite naming
# the trio the row is RE-PLANNED to the gre gate shape -- flip trips loudly)
for f in cd_llc.cc cd_vxlan.cc cd_user.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST' "$SRC/src/codecs/misc/$f" || true)" -eq 0
done

# ---- THE hidden tables (BUILDING_SO split) -- sed census PIN lines x3 ----|
test "$(sed -n '190p' "$SRC/src/codecs/misc/cd_llc.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '191p' "$SRC/src/codecs/misc/cd_llc.cc")" = "SO_PUBLIC const BaseApi* snort_plugins[] ="
test "$(sed -n '193p' "$SRC/src/codecs/misc/cd_llc.cc")" = "const BaseApi* cd_llc[] ="
test "$(sed -n '196p' "$SRC/src/codecs/misc/cd_llc.cc")" = "    &llc_api.base,"
test "$(sed -n '124p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '127p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = "const BaseApi* cd_vxlan[] ="
test "$(sed -n '130p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = "    &vxlan_api.base,"
test "$(sed -n '158p' "$SRC/src/codecs/misc/cd_user.cc")" = "#ifdef BUILDING_SO"
test "$(sed -n '161p' "$SRC/src/codecs/misc/cd_user.cc")" = "const BaseApi* cd_user[] ="
test "$(sed -n '164p' "$SRC/src/codecs/misc/cd_user.cc")" = "    &user_api.base,"
for f in cd_llc.cc cd_vxlan.cc cd_user.cc; do
    test "$(grep -c 'BUILDING_SO'  "$SRC/src/codecs/misc/$f")" -eq 1
    test "$(grep -c 'snort_plugins' "$SRC/src/codecs/misc/$f")" -eq 1
done
# TRUE-NAME faces (file base == NAME): llc :30/:31 + vxlan :31/:32 + user :33/:34
test "$(sed -n '30p' "$SRC/src/codecs/misc/cd_llc.cc")"   = '#define LLC_NAME "llc"'
test "$(sed -n '31p' "$SRC/src/codecs/misc/cd_llc.cc")"   = '#define LLC_HELP "support for logical link control"'
test "$(sed -n '31p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = '#define CD_VXLAN_NAME "vxlan"'
test "$(sed -n '32p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = '#define CD_VXLAN_HELP "support for Virtual Extensible LAN"'
test "$(sed -n '33p' "$SRC/src/codecs/misc/cd_user.cc")"  = '#define CD_NAME "user"'
test "$(sed -n '34p' "$SRC/src/codecs/misc/cd_user.cc")"  = '#define CD_HELP_STR "support for user sessions"'
test "$(sed -n '35p' "$SRC/src/codecs/misc/cd_user.cc")"  = '#define CD_HELP ADD_DLT(CD_HELP_STR, DLT_USER)'
# ---- mod-pair ASYMMETRY pin 1/0/0 (the FACE-A grep face; contrast daq3
# uniform 1/1/1 + miscip pair 0/0/0 -- the 18i hand-off "do NOT carry the
# pair 0/0" face landed): llc mod_ctor :156 + mod_dtor :159 REAL, api slots
# :179/:180; vxlan nullptr pair :113/:114; user EXPLICIT comments :147/:148.
test "$(sed -n '156p' "$SRC/src/codecs/misc/cd_llc.cc")" = "static Module* mod_ctor()"
test "$(sed -n '159p' "$SRC/src/codecs/misc/cd_llc.cc")" = "static void mod_dtor(Module* m)"
test "$(sed -n '179p' "$SRC/src/codecs/misc/cd_llc.cc")" = "        mod_ctor,"
test "$(sed -n '180p' "$SRC/src/codecs/misc/cd_llc.cc")" = "        mod_dtor"
test "$(sed -n '113p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = "        nullptr,"
test "$(sed -n '147p' "$SRC/src/codecs/misc/cd_user.cc")" = "        nullptr,  // mod_ctor"
test "$(sed -n '148p' "$SRC/src/codecs/misc/cd_user.cc")" = "        nullptr,  // mod_dtor"
# llc dead-define census: SIX #defines, grep-count 1 each (#define ONLY, ZERO
# use sites; the SNAP arms ride literal 0 :117-:119; DSAP/SSAP_IP :84/:85 ARE
# used :105/:106/:139/:140 count 3) -- transcribe cite-NEVER-land (R3).
for d in ETH_DSAP_SNA ETH_SSAP_SNA ETH_DSAP_STP ETH_SSAP_STP ETH_ORG_CODE_ETHR ETH_ORG_CODE_CDP; do
    test "$(grep -c "$d" "$SRC/src/codecs/misc/cd_llc.cc")" -eq 1
done
test "$(grep -c ETH_DSAP_IP "$SRC/src/codecs/misc/cd_llc.cc")" -eq 3
# llc RuleMap face: 2 rows :35-:38 (llc_rules the trio's ONLY rule table;
# vxlan/user RuleMap 0/0) -- sids 131/132 ALREADY landed, NEVER re-walked.
test "$(sed -n '37p' "$SRC/src/codecs/misc/cd_llc.cc")" = '    { DECODE_BAD_LLC_HEADER, "bad LLC header" },'
test "$(sed -n '38p' "$SRC/src/codecs/misc/cd_llc.cc")" = '    { DECODE_BAD_LLC_OTHER, "bad extra LLC info"},'

# ---- externs + loads + ladder ALL RESIDENT (rows ADD TUs, NEVER touch) ----
test "$(sed -n '59p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_llc[];"
test "$(sed -n '71p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_user[];"
test "$(sed -n '73p' "$SRC/src/codecs/codec_api.cc")" = "extern const BaseApi* cd_vxlan[];"
test "$(sed -n '104p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_llc);"
test "$(sed -n '116p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_user);"
test "$(sed -n '118p' "$SRC/src/codecs/codec_api.cc" | sed 's/^ *//')" = "PluginManager::load_plugins(cd_vxlan);"
test "$(grep -c 'extern const BaseApi\* cd_' "$SRC/src/codecs/codec_api.cc")" -eq 39   # 39-extern cc census
# the rust ladder face (rows NEVER re-touch): trio names ALREADY resident
test "$(sed -n '117p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_llc",'
test "$(sed -n '129p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_user",'
test "$(sed -n '131p' /opt/data/snort3-rust/src/codecs/codec_api.rs)" = '    "cd_vxlan",'
test "$(sed -n '97p'  /opt/data/snort3-rust/src/codecs/codec_api.rs)" = 'pub const STATIC_CODEC_EXTERN_NAMES: [&str; 34] = ['

# ---- misc/test dialect census (the STOP-flag probe, NEGATIVE, re-armed) ----
test "$(grep -c 'add_cpputest' "$SRC/src/codecs/misc/test/CMakeLists.txt")" -eq 3
for f in geneve_codec_test.cc gtp_codec_test.cc teredo_codec_test.cc; do
    if [ "$(grep -c 'TEST_CASE' "$SRC/src/codecs/misc/test/$f")" -ne 0 ]; then
        echo "STOP-FLAG TRIP: $f carries Catch TEST_CASE material -- RE-PLAN to the gre gate shape"; exit 1
    fi
    test "$(grep -c 'cd_llc\|cd_vxlan\|cd_user' "$SRC/src/codecs/misc/test/$f" || true)" -eq 0
done

# ---- vxlan tunnel_bypass HOOK seam (central check §2, MEASURED cites) ----
test "$(sed -n '73p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = "    if ( codec.conf->tunnel_bypass_enabled(TUNNEL_VXLAN) )"
test "$(sed -n '74p' "$SRC/src/codecs/misc/cd_vxlan.cc")" = "        codec.tunnel_bypass = true;"
test "$(grep -c 'decap\|encap' "$SRC/src/codecs/misc/cd_vxlan.cc" || true)" -eq 0   # NOT a tunnel_decap face (dport-4789 rides cd_udp)
test "$(sed -n '777p' "$SRC/src/main/snort_config.h")" = "    SO_PUBLIC bool tunnel_bypass_enabled(uint16_t proto) const;"
test "$(sed -n '1022p' "$SRC/src/main/snort_config.cc")" = "    return !((tunnel_mask & proto) or SFDAQ::get_tunnel_bypass(proto));"
test "$(sed -n '58p' "$SRC/src/packet_io/sfdaq.h")"  = "    SO_PUBLIC static bool get_tunnel_bypass(uint16_t proto);"
# mask enum sed face (EXACTLY the 18f witness face + THE row's own bit)
test "$(sed -n '119p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_GTP    = 0x01,"
test "$(sed -n '120p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_TEREDO = 0x02,"
test "$(sed -n '125p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_GRE    = 0x40,"
test "$(sed -n '127p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_VXLAN  = 0x100,"
test "$(sed -n '128p' "$SRC/src/main/snort_config.h")" = "    TUNNEL_GENEVE = 0x200"
# user ground literals (FIXIT-L hardcoded face -- cite-NEVER-land, build.sh
# sed CITES them, vectors print ONLY ground-call-observable sp/dp/pb/flags)
test "$(sed -n '70p' "$SRC/src/codecs/misc/cd_user.cc")" = "    // FIXIT-L make configurable"
grep -q '192\.168\.1\.1' "$SRC/src/codecs/misc/cd_user.cc"
grep -q 'ip_proto == IPPROTO_TCP' "$SRC/src/codecs/misc/cd_user.cc"

# ---- copy tree = miscip DONOR POST-STRIP (105) + daq.h REUSE cp + graft-v2
# OVERLAY (same filename, in place) + EXACTLY 3 fresh header cps + 3 row TUs:
# mid-build 112 / POST-STRIP 111 = 105+3+3 MEASURED (asserted by LITERAL). ----
if [ ! -e "$MI/copy/cd_icmp4_ip.o" ]; then bash "$MI/build.sh"; fi   # donor self-heal
rm -rf "$C"; cp -a "$MI/copy" "$C"
find "$C" -name '*.o' -delete
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 105   # donor face (the 18j post-strip 105)
# the donor graft face pre-v2: fmod 16 L face rides the tree (byte-identity
# census tree-to-tree; the miscip face is the f683749c face at this step)
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "f683749cda1d7c4acef832d880df3b73"
test "$(wc -l < "$C/daq_common.h")" -eq 16
# daq.h REUSE cp (THE single landing stays daq3's tracked 33 L 73fdbc39 face;
# NEVER a second graft authored HERE -- a byte-exact cp REUSE rides the flipv2
# ip-trio checks, stripped again at end-of-build so the census stays green)
test "$(find /opt/data/snort3-rust/tools -name daq.h ! -path '/opt/data/snort3-rust/tools/daq3_harness/*' | wc -l)" -eq 0   # PRE-copy face
test "$(md5sum "$D3/copy/daq.h" | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"
cp "$D3/copy/daq.h" "$C/daq.h"
cmp -s "$C/daq.h" "$D3/copy/daq.h"
test "$(find /opt/data/snort3-rust/tools -name daq.h | wc -l)" -eq 2   # daq3 landing + THIS riding tree only (post-strip back to 1)
test "$(find "$SRC" -name daq.h | wc -l)" -eq 0
test "$(ls /usr/include/daq.h /usr/include/daq/*.h 2>/dev/null | wc -l)" -eq 0
# EXACTLY 3 fresh header cps (the row's ONE closure risk face, §4):
for h in framework/codec.h codecs/codec_module.h log/text_log.h main/snort_config.h main/snort_types.h protocols/protocol_ids.h packet_io/active.h; do
    test "$(find "$C" -path "*/$h" | wc -l)" -eq 1
done
for h in daqs/daq_user.h packet_io/sfdaq.h packet_io/sfdaq_instance.h; do
    test "$(find "$C" -path "*/$h" | wc -l)" -eq 0                       # fresh-landing face
done
test "$(md5sum "$SRC/daqs/daq_user.h" | awk '{print $1}')" = "1d2e2b9c37ee2f11ba68a676869a8eab"
test "$(wc -l < "$SRC/daqs/daq_user.h")" -eq 54
test "$(md5sum "$SRC/src/packet_io/sfdaq.h" | awk '{print $1}')" = "2e272d2d68e40138946326df3c5cfc95"
test "$(wc -l < "$SRC/src/packet_io/sfdaq.h")" -eq 72
test "$(md5sum "$SRC/src/packet_io/sfdaq_instance.h" | awk '{print $1}')" = "9497f39441174c4260d4db22e55740bf"
test "$(wc -l < "$SRC/src/packet_io/sfdaq_instance.h")" -eq 105
# heads cited (§4: "heads cite"): author lines of the THREE fresh cps
test "$(sed -n '19p' "$SRC/daqs/daq_user.h")"          = "/* daq_user.h author Russ Combs <rucombs@cisco.com> */"
test "$(sed -n '20p' "$SRC/src/packet_io/sfdaq.h")"        = "// sfdaq.h author Michael Altizer <mialtize@cisco.com>"
test "$(sed -n '20p' "$SRC/src/packet_io/sfdaq_instance.h")" = "// sfdaq.h author Michael Altizer <mialtize@cisco.com>"
# the SDK VALUES the row-scoped Rust side borrows (daqs/daq_user.h :30-:46):
test "$(sed -n '29p' "$SRC/daqs/daq_user.h")" = "#define DLT_USER 230"
test "$(sed -n '32p' "$SRC/daqs/daq_user.h")" = "#define DAQ_USR_FLAG_TO_SERVER  0x01"
test "$(sed -n '33p' "$SRC/daqs/daq_user.h")" = "#define DAQ_USR_FLAG_START_FLOW 0x02"
test "$(sed -n '34p' "$SRC/daqs/daq_user.h")" = "#define DAQ_USR_FLAG_END_FLOW   0x04"
test "$(sed -n '46p' "$SRC/daqs/daq_user.h")" = "#define DIOCTL_QUERY_USR_PCI    (DAQ_IoctlCmd) 2048"
# the sfdaq-pair decl faces the graft-v2 typedefs are shaped by (§R1 cites):
test "$(sed -n '44p' "$SRC/src/packet_io/sfdaq.h")"  = "    static const char* verdict_to_string(DAQ_Verdict verdict);"
test "$(sed -n '52p' "$SRC/src/packet_io/sfdaq.h")"  = "    SO_PUBLIC static const DAQ_Stats_t* get_stats();"
test "$(sed -n '63p' "$SRC/src/packet_io/sfdaq.h")"  = "    SO_PUBLIC static SFDAQInstance* get_local_instance();"
test "$(sed -n '45p' "$SRC/src/packet_io/sfdaq_instance.h")"  = "    bool init(DAQ_Config_h, const std::string& bpf_string);"
test "$(sed -n '52p' "$SRC/src/packet_io/sfdaq_instance.h")"  = "    DAQ_RecvStatus receive_messages(unsigned max_recv);"
test "$(sed -n '79p' "$SRC/src/packet_io/sfdaq_instance.h")"  = "    SO_PUBLIC int ioctl(DAQ_IoctlCmd cmd, void *arg, size_t arglen);"
test "$(sed -n '93p' "$SRC/src/packet_io/sfdaq_instance.h")"  = "    DAQ_Instance_h instance = nullptr;"
mkdir -p "$C/daqs"
cp "$SRC/daqs/daq_user.h" "$C/daqs/daq_user.h";                 cmp -s "$C/daqs/daq_user.h" "$SRC/daqs/daq_user.h"
cp "$SRC/src/packet_io/sfdaq.h" "$C/packet_io/sfdaq.h";             cmp -s "$C/packet_io/sfdaq.h" "$SRC/src/packet_io/sfdaq.h"
cp "$SRC/src/packet_io/sfdaq_instance.h" "$C/packet_io/sfdaq_instance.h"; cmp -s "$C/packet_io/sfdaq_instance.h" "$SRC/src/packet_io/sfdaq_instance.h"
mkdir -p "$C/codecs/misc"
for f in cd_llc.cc cd_vxlan.cc cd_user.cc; do
    cp "$SRC/src/codecs/misc/$f" "$C/codecs/misc/$f"; cmp -s "$C/codecs/misc/$f" "$SRC/src/codecs/misc/$f"
done
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 112   # mid-build: 105 + daq.h REUSE + 3 cps + 3 TUs
test ! -e "$C/codecs/codec_api.h"            # FACE-flip inherited (probe pulls NO codec_api)
test ! -e "$C/codecs/codec_api.cc"

GXX0="g++ -std=c++17 -O0 -w -I$C"
# ---- R1 LANDMINE REHEARSAL IN-TREE EVERY BUILD (the graft-v2 headline): the
# v16 donor face + the cps -> cd_user MUST die at cc:101 (the MEASURED const
# face rc1); graft-v2 OVERLAY -> green AND the daq3 ip trio stays green x3. ----
if $GXX0 -fsyntax-only "$C/codecs/misc/cd_user.cc" -o /dev/null 2> "$H/E4_cd_user_v1.txt"; then
    echo "R1 LANDMINE DEAD: cd_user compiled on the fmod 16 L graft face -- the graft-v2 landmine is wrong"; exit 1
fi
head -1 "$H/E4_cd_user_v1.txt" | grep -q "No such file" || grep -q "invalid conversion" "$H/E4_cd_user_v1.txt"
grep -q "invalid conversion" "$H/E4_cd_user_v1.txt"
grep -q "DAQ_Msg_h" "$H/E4_cd_user_v1.txt"
cat > "$C/daq_common.h" <<'EOFGRAFT'
#pragma once
#include <cstdint>
typedef const void* DAQ_Msg_h;
struct DAQ_PktHdr_t {
    uint64_t flags = 0;
    int ingress_group = 0;
    int egress_group = 0;
};
#define DAQ_PKTHDR_UNKNOWN            -1
#define DAQ_PKT_FLAG_SIGNIFICANT_GROUPS 0x0000000000000020

// NEW18a graft (PLAN 0.2b): analyzer_command.h:255 reads a std::vector
// of this DAQ-SDK type; grep of src/ shows it NEVER defined upstream (the
// SDK header is not in-tree). One-field placeholder: analyzer_command.cc
// NEVER compiles, the vector member only needs A type.
struct DIOCTL_GetSnortLatencyData { uint64_t placeholder = 0; };
// scratch row18k probe EXTENSION: the sfdaq-pair face NEVER pulled by ANY
// earlier row (grep census: DAQ_Config_h DAQ_Instance_h DAQ_RecvStatus
// DAQ_Stats_t DAQ_Verdict DAQ_IoctlCmd DAQ_SUCCESS + the const face of
// DAQ_Msg_h the ground cd_user.cc:101 aggregate-init demands).
#undef  DAQ_Msg_h_placeholder
typedef uint32_t DAQ_IoctlCmd;
typedef void* DAQ_Config_h;
typedef void* DAQ_Instance_h;
typedef enum { DAQ_Verdict_PASS = 0, DAQ_Verdict_DROP = 1 } DAQ_Verdict;
typedef enum { DAQ_RECV_STATUS_OK = 0 } DAQ_RecvStatus;
typedef struct { uint64_t pkgs_received; } DAQ_Stats_t;
#define DAQ_SUCCESS 0
EOFGRAFT
test "$(wc -l < "$C/daq_common.h")" -eq 28
test "$(md5sum "$C/daq_common.h" | awk '{print $1}')" = "fead00270dd5ded5ddb6f05d3b047dcf"   # graft-v2 face (scratch byte-ident; NEVER edit frozen harnesses -- per-link isolation)
# post-flip: misc trio rc0 x3 + the daq3 trio green-under-v2 rc0 x3 (the R1
# contrast face re-run EVERY build: the flip breaks NOTHING on the donor axis)
for f in cd_llc cd_vxlan cd_user; do
    $GXX0 -fsyntax-only "$C/codecs/misc/$f.cc" 2> "$H/E4_$f.txt"
    test ! -s "$H/E4_$f.txt"
done
for f in cd_udp cd_icmp4 cd_icmp6; do
    $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" 2> "$H/E4_flipv2_$f.txt"
    test ! -s "$H/E4_flipv2_$f.txt"     # green-under-graft-v2 (EMPTY receipts = the face)
done

# ---- E4 WALLS (PLAN §4 stripped-tree flipped-asserts EVERY BUILD): the 3
# fresh cps each alone KILL ONLY cd_user (the row's load-bearing closure);
# codec_module.h -> ONLY cd_llc dies; active.h -> ONLY cd_vxlan dies (the
# residency rider walls); daq.h -> the ip trio MUST die (graft REUSE rides)
# + misc trio SURVIVE (the cd_user-never-includes-daq.h face, cc:24 is
# daq_common.h NOT daq.h -- fresh-cp-vs-graft split IN-tree). ----
for h in daqs/daq_user.h packet_io/sfdaq.h packet_io/sfdaq_instance.h; do
    mv "$C/$h" "$H/.e4_hold_$(basename "$h")"
    for f in cd_llc cd_vxlan; do
        $GXX0 -fsyntax-only "$C/codecs/misc/$f.cc" 2> "$H/E4_no$(basename "$h")_$f.txt"
        test ! -s "$H/E4_no$(basename "$h")_$f.txt"
    done
    if $GXX0 -fsyntax-only "$C/codecs/misc/cd_user.cc" -o /dev/null 2> "$H/E4_no_$(basename "$h").txt"; then
        echo "E4 flip BROKE: cd_user compiled WITHOUT $h -- the fresh-cp census is wrong"; exit 1
    fi
    head -1 "$H/E4_no_$(basename "$h").txt" | grep -q "fatal error: $h: No such file"
    mv "$H/.e4_hold_$(basename "$h")" "$C/$h"
done
mv "$C/codecs/codec_module.h" "$H/.e4_hold_codec_module.h"
if $GXX0 -fsyntax-only "$C/codecs/misc/cd_llc.cc" -o /dev/null 2> "$H/E4_nocm_llc.txt"; then
    echo "E4 flip BROKE: cd_llc compiled WITHOUT codecs/codec_module.h (cc:24)"; exit 1
fi
head -1 "$H/E4_nocm_llc.txt" | grep -q "fatal error: codecs/codec_module.h: No such file"
for f in cd_vxlan cd_user; do
    $GXX0 -fsyntax-only "$C/codecs/misc/$f.cc" 2> "$H/E4_nocm_$f.txt"
    test ! -s "$H/E4_nocm_$f.txt"
done
mv "$H/.e4_hold_codec_module.h" "$C/codecs/codec_module.h"
mv "$C/packet_io/active.h" "$H/.e4_hold_active.h"
if $GXX0 -fsyntax-only "$C/codecs/misc/cd_vxlan.cc" -o /dev/null 2> "$H/E4_noactive_vxlan.txt"; then
    echo "E4 flip BROKE: cd_vxlan compiled WITHOUT packet_io/active.h (cc:27)"; exit 1
fi
head -1 "$H/E4_noactive_vxlan.txt" | grep -q "fatal error: packet_io/active.h: No such file"
for f in cd_llc cd_user; do
    $GXX0 -fsyntax-only "$C/codecs/misc/$f.cc" 2> "$H/E4_noactive_$f.txt"
    test ! -s "$H/E4_noactive_$f.txt"
done
mv "$H/.e4_hold_active.h" "$C/packet_io/active.h"
mv "$C/daq.h" "$H/.e4_hold_daq.h"
for f in cd_udp cd_icmp4 cd_icmp6; do                  # the REUSE-cp graft rides the ip trio
    if $GXX0 -fsyntax-only "$C/codecs/ip/$f.cc" -o /dev/null 2> "$H/E4_nodaq_$f.txt"; then
        echo "E4 flip BROKE: $f compiled WITHOUT daq.h"; exit 1
    fi
    head -1 "$H/E4_nodaq_$f.txt" | grep -q "fatal error: daq.h: No such file"
done
for f in cd_llc cd_vxlan cd_user; do                   # misc trio NEVER includes daq.h (cc:24 = daq_common.h, cc:25 graft-rides)
    $GXX0 -fsyntax-only "$C/codecs/misc/$f.cc" 2> "$H/E4_nodaq_$f.txt"
    test ! -s "$H/E4_nodaq_$f.txt"
done
mv "$H/.e4_hold_daq.h" "$C/daq.h"
# restored full tree: the THREE row TUs compile to .o rc0 stderr-0
for f in cd_llc cd_vxlan cd_user; do
    $GXX0 -c "$C/codecs/misc/$f.cc" -o "$C/$f.precheck.o" 2> "$H/E4_restored_$f.txt"
    test ! -s "$H/E4_restored_$f.txt"
    rm -f "$C/$f.precheck.o"
done

GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"
REAL="$D3/copy/framework/codec.cc $D3/copy/protocols/ip.cc $D3/copy/sfip/sf_ip.cc $D3/copy/utils/util_cstring.cc $D3/copy/utils/util.cc $D3/copy/log/text_log.cc $D3/copy/framework/module.cc"

# ---- witness carry: WIN trio INHERITED (md5 pins NEVER re-derived) + THE new
# tracked face witness_trio.cc (the EXACTLY-+2 SFDAQ witnesses, md5-pinned) ----
test "$(md5sum "$TUN"/witness_18f.cc | awk '{print $1}')" = "ea1f79f3f05f8a91dc9524a963692b39"
test "$(md5sum "$ETH"/stubs_18d.cc  | awk '{print $1}')" = "f4afd35f06bc45ce5aa0ec12110ed8ae"
# witness_conf.cc = the landed 4dd91018 heredoc face (miscip :231-:273 VERBATIM
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
test "$(wc -l < "$H/witness_trio.cc")" -eq 35
test "$(md5sum "$H/witness_trio.cc" | awk '{print $1}')" = "ef50cd2f8cdb4b9fa3d483e702bd73be"   # THE new tracked witness face
# witness-body honesty (R1-carry): the REAL sfdaq bodies stay the REJECT face
# (sfdaq.cc + sfdaq_instance.cc NEVER compiled by ANY donor, find-0 pinned):
test "$(find /opt/data/snort3-rust/tools -iname 'sfdaq*.cc' | wc -l)" -eq 0
test "$(wc -l < "$SRC/src/packet_io/sfdaq.cc")" -eq 420
test "$(wc -l < "$SRC/src/packet_io/sfdaq_instance.cc")" -eq 436
# ---- O0 compile: THREE plain .o + donor REAL .o + probes + witnesses -------
for f in cd_llc cd_vxlan cd_user; do $GXX -c "$C/codecs/misc/$f.cc" -o "$C/$f.o"; done
for f in $REAL; do $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"; done
$GXX -c "$H"/probe.cc     -o "$H"/probe.o
$GXX -c "$H"/probe_dec.cc -o "$H"/probe_dec.o
$GXX -c "$TUN"/witness_18f.cc -o "$H"/witness_18f.o
$GXX -c "$H"/witness_conf.cc  -o "$H"/witness_conf.o
$GXX -c "$ETH"/stubs_18d.cc   -o "$H"/stubs_18d.o
$GXX -c "$H"/witness_trio.cc -o "$H"/witness_trio.o

OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/module.o $C/text_log.o"
ROWS="$C/cd_llc.o $C/cd_vxlan.o $C/cd_user.o"
WIN="$H/witness_18f.o $H/witness_conf.o $H/stubs_18d.o"

# ---- ZERO-gate census: NO gate/catch artifacts of THIS row --------------
test ! -e "$H/gate.txt"
test ! -e "$H/catch_main.cc"
test "$(ls "$H" | grep -cxE 'gate|gate\.txt|gate_O[02]|gate_O[02]\.txt|gate_l\.txt' || true)" -eq 0
# hidden-table one-symbol-per-.o face x3 (the STATIC arm IS the harness face)
test "$(nm --defined-only "$C/cd_llc.o"   | grep -cE ' [DdRr] cd_llc$')"   -eq 1
test "$(nm --defined-only "$C/cd_vxlan.o" | grep -cE ' [DdRr] cd_vxlan$')" -eq 1
test "$(nm --defined-only "$C/cd_user.o"  | grep -cE ' [DdRr] cd_user$')"  -eq 1
# ---- nm per-TU U-census (receipts; counts MEASURED, NEVER typed: 22/10/13) --
for f in cd_llc cd_vxlan cd_user; do
    nm -C -u "$C/$f.o" | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H/nm_U_$f.txt"
done
test "$(grep -c 'tunnel_bypass' "$H/nm_U_cd_llc.txt" || true)" -eq 0     # 0... 
test "$(grep -c 'tunnel_bypass_enabled' "$H/nm_U_cd_vxlan.txt")" -eq 1   # ...1 (the HOOK ride)...
test "$(grep -c 'tunnel_bypass' "$H/nm_U_cd_user.txt" || true)" -eq 0    # ...0 -- census 0/1/0 face
cat "$H"/nm_U_cd_*.txt | sort -u > "$H/nm_U_union.txt"
# get_proto_name face: ROW census ZERO -> witness_miscip stays DONOR-INHERITED
# (the 18j tracked 27 L c5b498ff face CITED, NEVER linked/edited here)
test "$(nm -u $ROWS | grep -c get_proto_name || true)" -eq 0
test "$(md5sum "$MI/witness_miscip.cc" | awk '{print $1}')" = "c5b498ffa6beac768f34e25830c552a1"
test "$(wc -l < "$MI/witness_miscip.cc")" -eq 27
# THE witness-delta face re-measured EVERY BUILD (staged link, §WITNESS):
# L1 = trio + OBJS + WIN + probe.o (main EXISTS), NO witness_trio -> MUST die
# at undefined-DISTINCT EXACTLY-2 (the two SFDAQ seams, scratch receipt face).
if $GXX $ROWS $OBJS "$H"/probe.o $WIN -o "$H/.L1_probe" 2> "$H/L1_link_face.txt"; then
    echo "WITNESS FACE DEAD: trio linked WITHOUT witness_trio -- the +2 delta is wrong"; exit 1
fi
grep "undefined reference to" "$H/L1_link_face.txt" > "$H/L1_undefined.txt"
grep -q "undefined reference to \`snort::SFDAQ::get_local_instance()'" "$H/L1_link_face.txt"
grep -q "undefined reference to \`snort::SFDAQInstance::ioctl(unsigned int, void\*, unsigned long)'" "$H/L1_link_face.txt"
test "$(grep -oE "undefined reference to \`[^']*'" "$H/L1_link_face.txt" | sort -u | wc -l)" -eq 2   # EXACTLY-2 undefined face
rm -f "$H/.L1_probe"
# residue class (MANGLED face; inherited classifier): every snort-family U of
# the trio .o MUST be defined by OBJS+WIN+witness_trio.
g2="$C/cd_llc.o $C/cd_vxlan.o $C/cd_user.o"
nm -u $g2 | sed 's/^ *U //' | sort -u > "$H/nm_U_mangled_union.txt"
donordefs=$(nm --defined-only $OBJS $WIN "$H"/witness_trio.o | awk '$2 ~ /^[TtWwDdBbRrVvSs]$/' | awk '{print $3}' | sort -u)
res=0
while IFS= read -r u; do
    case "$u" in *5snort*)
        grep -qxF "$u" <<< "$donordefs" || { echo "RESIDUE UNRESOLVED: $u"; res=1; };; esac
done < "$H/nm_U_mangled_union.txt"
test "$res" -eq 0
# THE own-new-symbol census pin (-eq 2, the +2 witness face): the witness .o
# contributes EXACTLY TWO T symbols and NOTHING ELSE new.
test "$(nm --defined-only "$H"/witness_trio.o | grep -c ' T ')" -eq 2
nm -C --defined-only "$H"/witness_trio.o | grep -q 'T snort::SFDAQ::get_local_instance()'
nm -C --defined-only "$H"/witness_trio.o | grep -q 'T snort::SFDAQInstance::ioctl(unsigned int, void\*, unsigned long)'
# the bypass axis: witness_18f CARRIED exactly (zero NEW bypass symbols):
test "$(nm --defined-only "$H"/witness_18f.o | grep -c 'tunnel_bypass_enabled')" -eq 1
test "$(nm --defined-only "$H"/witness_trio.o | grep -c 'tunnel_bypass' || true)" -eq 0
# probe pulls NO codec_api object (inherited FACE rule):
test "$(nm -u "$H"/probe.o "$H"/probe_dec.o | grep -c 'load_codecs' || true)" -eq 0
# landmine posture ZERO (R4): no trio name frozen in ANY witness donor; the
# vocab witness_stubs table census STAYS 4 (NO retirement face this row).
for n in cd_llc cd_vxlan cd_user; do
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc || true)" -eq 0
    test "$(grep -c "$n" /opt/data/snort3-rust/tools/codec_harness/stubs.cc || true)" -eq 0
done
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(sed -n '11,14p' /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc | grep -c 'cd_ipv4\|cd_ipv6\|cd_tcp\|cd_hopopts')" -eq 4
# real-symbol defines (donor face, gre-recipe)
s=$(nm -C --defined-only "$C"/codec.o); grep -q 'T snort::Codec::codec_event' <<< "$s"
m=$(nm -C --defined-only "$C"/module.o); grep -q 'T snort::Module::Module' <<< "$m"
grep -q 'T snort::TextLog_Print' <<< "$(nm -C --defined-only "$C"/text_log.o)"
grep -q 'T tun_witness_set_mask' <<< "$(nm -C --defined-only "$H"/witness_18f.o)"

# ---- probe links: L2 face = WIN trio + witness_trio -> GREEN --------------
$GXX $ROWS $OBJS "$H"/probe.o      $WIN "$H"/witness_trio.o -o "$H"/probe
$GXX $ROWS $OBJS "$H"/probe_dec.o $WIN "$H"/witness_trio.o -o "$H"/probe_dec
test "$(nm -C "$H"/probe "$H"/probe_dec | grep -c 'Catch::' || true)" -eq 0   # NO Catch face ANYWHERE
# the witness symbols ride BOTH links EXACTLY-1 (the +2 backbone delta face)
for b in probe probe_dec; do
    test "$(nm -C "$H"/$b | grep -c 'T snort::SFDAQ::get_local_instance()')" -eq 1
    test "$(nm -C "$H"/$b | grep -c 'T snort::SFDAQInstance::ioctl')" -eq 1
    test "$(nm -C "$H"/$b | grep -c 'T snort::PacketManager::get_proto_name' || true)" -eq 0   # donor-inherited NEVER linked
done

# ---- O2 twins -------------------------------------------------------------
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in cd_llc cd_vxlan cd_user; do $GXXA -c "$C/codecs/misc/$f.cc" -o "$O2/$f.o"; done
for f in $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2"/probe.o; $GXXA -c "$H"/probe_dec.cc -o "$O2"/probe_dec.o
$GXXA -c "$TUN"/witness_18f.cc -o "$O2"/witness_18f.o; $GXXA -c "$H"/witness_conf.cc -o "$O2"/witness_conf.o
$GXXA -c "$ETH"/stubs_18d.cc   -o "$O2"/stubs_18d.o; $GXXA -c "$H"/witness_trio.cc -o "$O2"/witness_trio.o
OB2="$O2/cd_llc.o $O2/cd_vxlan.o $O2/cd_user.o"
for b in codec ip sf_ip util_cstring util module text_log; do OB2="$OB2 $O2/$b.o"; done
$GXXA $OB2 "$O2"/probe.o      "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_trio.o -o "$H"/probe_O2
$GXXA $OB2 "$O2"/probe_dec.o  "$O2"/witness_18f.o "$O2"/witness_conf.o "$O2"/stubs_18d.o "$O2"/witness_trio.o -o "$H"/probe_dec_O2

timeout 60 "$H"/probe     > "$H"/vectors_faceA_O0.txt || { echo PROBE_FAIL A O0; exit 1; }
timeout 60 "$H"/probe_O2  > "$H"/vectors_faceA_O2.txt || { echo PROBE_FAIL A O2; exit 1; }
timeout 60 "$H"/probe_dec    > "$H"/vectors_O0.txt    || { echo PROBE_FAIL DEC O0; exit 1; }
timeout 60 "$H"/probe_dec_O2 > "$H"/vectors_O2.txt    || { echo PROBE_FAIL DEC O2; exit 1; }
cmp "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA_O2.txt
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt
[ -e "$H"/vectors.txt ]      && { cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt      || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }; }
[ -e "$H"/vectors_faceA.txt ] && { cmp -s "$H"/vectors_faceA_O0.txt "$H"/vectors_faceA.txt || { echo "FACE-A DRIFT vs tracked vectors_faceA.txt"; exit 1; }; }

# ---- R6 eval-order rule: decode stored to bool VAR before any printf ----
test "$(grep -c 'bool b=.*->decode' "$H"/probe_dec.cc)" -eq 12   # MEASURED face (5 llc + 4 vxlan + 3 user arms)
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

# ---- known-answer ladders: greps pin the MEASURED vector faces against
# GROUND anchors (17p: values NEVER typed -- ground sed/enum walks below). ----
# FACE-A: trio LOAD walk + the mod-pair ASYMMETRY pin 1/0/0 (ground api struct
# sed-pinned above: llc REAL :179/:180, vxlan nullptr :113, user comments
# :147/:148 -- the trio-asymmetry face the 18i hand-off WARNED about):
grep -q '^LOAD llc$'   "$FA"
grep -q '^LOAD vxlan$' "$FA"
grep -q '^LOAD user$'  "$FA"
grep -q '^LOADS 3$'    "$FA"
grep -q '^API llc type=0 size=112 ver=1900547 name=llc$'   "$FA"   # CDAPI carry (ver DERIVED by the python census)
grep -q '^API vxlan type=0 size=112 ver=1900547 name=vxlan$' "$FA"
grep -q '^API user type=0 size=112 ver=1900547 name=user$'  "$FA"
grep -q '^HELP llc support for logical link control$'  "$FA"       # ground #define :31 sed-pinned
grep -q '^HELP vxlan support for Virtual Extensible LAN$' "$FA"    # ground #define :32
grep -q '^HELP user support for user sessions (DLT 230)$' "$FA"    # ADD_DLT face (codec.h:52 macro + DLT_USER :29)
grep -q '^llc mod_ctor=1 mod_dtor=1$'     "$FA"                    # THE asymmetry 1/0/0
grep -q '^vxlan mod_ctor=0 mod_dtor=0$'   "$FA"
grep -q '^user mod_ctor=0 mod_dtor=0$'    "$FA"
for n in llc vxlan user; do grep -q "^$n ctor=1 dtor=1$" "$FA"; done  # ctor/dtor 1/1/1 x3 (CodecApi slots)
grep -q '^GETIDS llc 263$'   "$FA"     # ETHERNET_LLC 0x0107 (protocol_ids.h derived)
grep -q '^GETIDS vxlan 264$' "$FA"     # VXLAN 0x0108 (derived)
test "$(grep -c '^GETIDS user' "$FA" || true)" -eq 0               # user: NO get_protocol_ids override
grep -q '^GETDLT user 230$'  "$FA"     # DLT_USER (daq_user.h :29 -- sed-pinned above)
test "$(grep -c '^GETDLT llc\|^GETDLT vxlan' "$FA" || true)" -eq 0 # the trio's ONLY data-link registrant
# DEC ladders (ground call-site arms, receipts row18k):
grep -q '^EV 116 131$'     "$V"
grep -q '^LLC short2 -> 0$' "$V"                                    # cc :96/:99 (TRUNCATED arm)
grep -q '^LLC dsap-aa-ssap-00 -> 1$' "$V"                           # cc :105&&FIRST-operand FALSE: NO event (eval order)
grep -q '^EV 116 132$'     "$V"
grep -q '^LLC snap7 -> 0$'  "$V"                                    # cc :108/:110
grep -q '^LLC snap0-org -> 1 lyr=8 next=2048 flags=4096$' "$V"      # cc :117-:123 (lyr/next/ETHER_NEXT derived)
grep -q '^LLC snap-org-nonzero -> 1 lyr=0$' "$V"                    # org gate FALSE face
test "$(grep -c '^EV 116 131$' "$V")" -eq 1                         # EXACTLY one 131
test "$(grep -c '^EV 116 132$' "$V")" -eq 1                         # EXACTLY one 132
grep -q '^VX len7 -> 0$'        "$V"                                # cc :65
grep -q '^VX flags-neq8 -> 0$'  "$V"                                # cc :70
grep -q '^VX mask256 -> 1 lyr=8 pb=262144 next=261 flags=512 bypass=0$' "$V"   # HOOK FALSE arm, sets :76-:79
grep -q '^VX mask0 -> 1 lyr=8 pb=262144 next=261 flags=512 bypass=1$'   "$V"   # HOOK TRUE face :73-:74
grep -q '^VX hook-before-sets' "$V"                                # eval-order cite line
test "$(grep -c 'tunnel_bypass=1' "$V" || true)" -eq 0             # the ONE bypass face uses bypass= label
grep -q '^US no-instance ground-SEGV cc:103 chain-call' "$V"        # synthetic-witness honesty cite
grep -q '^US proto0-key -> 1 pb=2 sp=12345 dp=54321 type=6 lyr=0$' "$V"     # set_key face cc:68-:79, FILE :119 (sp/dp ground hardcoded literals, observable-through-ground)
grep -q '^US tcp-c2s -> 1 pb=2 sp=12345 dp=0 type=5 df=512 lyr=0$' "$V"     # set_ip TCP cc:62-:63 + C2S cc:85 + USER cc:114
grep -q '^US udp-flags7 -> 1 pb=4 sp=20000 dp=30000 df=3584 lyr=4 type=5$' "$V" # UDP + C2S|SOF|EOF 3584 + lyr=raw.len cc:93
grep -q '^US arms-cc:95-:96-else-lyr0-face$' "$V"                   # else-lyr-0 cite (rides tcp-c2s lyr=0)
grep -q '^US ioctl-fail cc:103' "$V"                                # NEVER-armed cites (witness ALWAYS success/fills pci)
test "$(grep -c '^EV ' "$V")" -eq 2                                 # llc is the trio's ONLY event face (vxlan/user grep 0)
test "$(grep -c '4789' "$V" || true)" -eq 0                         # dport face NEVER here (cd_udp landed, PLAN 2)
python3 - "$V" "$FA" <<'PYPIN'
# THE sids + proto-bit + protocol-id + CDAPI face PINNED BOTH WAYS (ground
# enum/#define walks vs the MEASURED vector face -- every value the ladders
# grep rides ground, never air).
import re, sys
VF, FAF = sys.argv[1], sys.argv[2]
h = open("/opt/data/snort3-src/src/codecs/codec_module.h").read()
m = re.search(r'enum\s+CodecSid[^{]*\{', h); body = h[m.end():]; val = 0; g = {}
for line in body.split("\n"):
    mm = re.match(r"\s*([A-Z_0-9]+)\s*(?:=\s*(\d+))?\s*,", line)
    if mm:
        name = mm.group(1); val = int(mm.group(2)) if mm.group(2) else val + 1; g[name] = val
    if re.match(r"\s*};", line): break
NAMES = "DECODE_BAD_LLC_HEADER DECODE_BAD_LLC_OTHER".split()
assert g[NAMES[0]] == 131 and g[NAMES[1]] == 132, g["DECODE_BAD_LLC_HEADER"]
for n in NAMES:
    r = re.findall(rf"{n} = (\d+),", open("/opt/data/snort3-rust/src/codecs/codec_module.rs").read())
    assert r and int(r[0]) == g[n], (n, g[n], r)          # ALREADY landed -- NEVER re-walked
# llc ground event census == EXACTLY the 2 sids; vxlan/user ZERO
import subprocess
for tu, want in (("cd_llc.cc", 2), ("cd_vxlan.cc", 0), ("cd_user.cc", 0)):
    out = subprocess.run(["grep","-oE",r"codec_event\(codec,\s*[A-Z_0-9]+","/opt/data/snort3-src/src/codecs/misc/"+tu],capture_output=True,text=True).stdout
    assert len(set(l.split()[-1] for l in out.splitlines() if l.strip())) == want, (tu, out)
V = set(int(l.split()[2]) for l in open(VF) if l.startswith("EV "))
assert V == {131,132}, V
# PROTO_BIT face (decode_data.h #defines -> decimal): TCP/UDP/VXLAN
dd = open("/opt/data/snort3-src/src/framework/decode_data.h").read()
pb = {n:int(v,16) for n,v in re.findall(r'#define\s+(PROTO_BIT__[A-Z_0-9]+)\s+(0x[0-9A-Fa-f]+)', dd)}
assert (pb["PROTO_BIT__TCP"], pb["PROTO_BIT__UDP"]) == (2,4)
assert f"pb={pb['PROTO_BIT__VXLAN']}" in open(VF).read(), pb["PROTO_BIT__VXLAN"]  # 262144 face, row-scoped: the cd_vxlan.rs home is the ONLY Rust face
# trio Rust TUs LANDED (the PORT pass flipped this guard from the seed-pass
# not-exists face; the hidden-table consts + the mod_ctor 1/0/0 record face
# + the dead-define token-zero census pin the landing — R3 cite-NEVER-land)
import os
for f in ("cd_llc.rs","cd_vxlan.rs","cd_user.rs"):
    assert os.path.exists("/opt/data/snort3-rust/src/codecs/"+f)
RS = {f: open("/opt/data/snort3-rust/src/codecs/"+f).read() for f in ("cd_llc.rs","cd_vxlan.rs","cd_user.rs")}
assert "pub const CD_LLC: CodecTable = &[&LLC_API];" in RS["cd_llc.rs"]
assert "pub const CD_VXLAN: CodecTable = &[&VXLAN_API];" in RS["cd_vxlan.rs"]
assert "pub const CD_USER: CodecTable = &[&USER_API];" in RS["cd_user.rs"]
assert sum(t.count("#[no_mangle]") for t in RS.values()) == 0   # the src-wide zero face (landed pattern)
assert "mod_ctor: true" in RS["cd_llc.rs"]
assert RS["cd_vxlan.rs"].count("mod_ctor: false") == 1 and RS["cd_user.rs"].count("mod_ctor: false") == 1  # 1/0/0 Rust-side
for dead in ("ETH_DSAP_SNA","ETH_SSAP_SNA","ETH_DSAP_STP","ETH_SSAP_STP","ETH_ORG_CODE_ETHR","ETH_ORG_CODE_CDP"):
    assert dead not in RS["cd_llc.rs"]   # dead-define tokens NEVER land (grep-count ZERO Rust-side)
assert "12345" in RS["cd_user.rs"] and "54321" in RS["cd_user.rs"]  # the cc:75/:76 ground literals ARE the observable face (PLAN landing receipt)
import re as _re
assert not _re.search(r"192\.168\.", RS["cd_user.rs"])  # the dotted-quad pair cite-NEVER-lands (this build.sh sed-cites cc:72 ONLY)
fa = open(FAF).read()
# protocol ids (protocol_ids.h enum hexes -> decimal): LLC 0x0107, VXLAN 0x0108, 802_3 0x0105
pi = open("/opt/data/snort3-src/src/protocols/protocol_ids.h").read()
pids = {n:int(v,16) for n,v in re.findall(r'^\s*([A-Z_0-9]+)\s*=\s*(0x[0-9A-Fa-f]+),', pi, re.M)}
assert pids["ETHERNET_LLC"]==0x0107 and pids["VXLAN"]==0x0108 and pids["ETHERNET_802_3"]==0x0105
assert f"GETIDS llc {pids['ETHERNET_LLC']}" in fa and f"GETIDS vxlan {pids['VXLAN']}" in fa
assert f"next={pids['ETHERNET_802_3']}" in open(VF).read()
# CDAPI version face derived (base_api.h BASE_API_VERSION + codec.h CDAPI_VERSION)
ba = int(re.search(r'#define\s+BASE_API_VERSION\s+(\d+)', open("/opt/data/snort3-src/src/framework/base_api.h").read()).group(1))
cv = re.search(r'#define\s+CDAPI_VERSION\s+\(\(BASE_API_VERSION\s*<<\s*16\)\s*\|\s*(\d+)\)', open("/opt/data/snort3-src/src/framework/codec.h").read()).group(1)
ver = (ba << 16) | int(cv)
assert fa.count(f"ver={ver}") == 3, ver
# codec flags (framework/codec.h NSDMIs): ETHER_NEXT 0x1000 / NON_IP_TUNNEL 0x0200
ch = open("/opt/data/snort3-src/src/framework/codec.h").read()
cf = {n:int(v,16) for n,v in re.findall(r'constexpr uint16_t (CODEC_[A-Z_]+)\s*=\s*(0x[0-9A-Fa-f]+);', ch)}
v = open(VF).read()
assert f"flags={cf['CODEC_ETHER_NEXT']}" in v and f"flags={cf['CODEC_NON_IP_TUNNEL']}" in v
# DECODE_* flags (decode_data.h enum hexes): C2S/SOF/EOF; PktType USER/FILE indices
df = {n:int(vv,16) for n,vv in re.findall(r'\s*(DECODE_C2S|DECODE_SOF|DECODE_EOF)\s*=\s*(0x[0-9A-Fa-f]+),', dd)}
assert df["DECODE_C2S"]+df["DECODE_SOF"]+df["DECODE_EOF"] == 3584 and f"df={df['DECODE_C2S']} " in v and f"df={df['DECODE_C2S']+df['DECODE_SOF']+df['DECODE_EOF']}" in v
pt = re.findall(r'enum class PktType[^{]*\{([^}]*)\}', dd)[0].split(",")
idx = {t.strip(): i for i,t in enumerate(pt)}
assert idx["USER"]==5 and idx["FILE"]==6 and "type=5" in v and "type=6" in v
# VXLAN_MIN_HDR_LEN face (cc :55) -> lyr 8
assert re.search(r'constexpr uint16_t VXLAN_MIN_HDR_LEN = 8;', open("/opt/data/snort3-src/src/codecs/misc/cd_vxlan.cc").read())
# TUNNEL_VXLAN mask decimal (snort_config.h enum) drives the vector LABEL:
tk = {n:int(vv,16) for n,vv in re.findall(r'(TUNNEL_[A-Z]+)\s*=\s*(0x[0-9A-Fa-f]+),', open("/opt/data/snort3-src/src/main/snort_config.h").read())}
assert tk["TUNNEL_VXLAN"]==0x100 and f"mask{tk['TUNNEL_VXLAN']} " in v
# GID_DECODE (codec_module.h :38) drives the EV prefix
gid = int(re.search(r'constexpr int GID_DECODE = (\d+);', h).group(1))
assert all(l.split()[1]==str(gid) for l in open(VF) if l.startswith("EV "))
# daq_user.h SDK literals vs vector (DLT_USER + the flags the df face rides)
du = open("/opt/data/snort3-src/daqs/daq_user.h").read()
assert "GETDLT user 230" in fa and "#define DLT_USER 230" in du
PYPIN

# ---- row's measured first-run face PINS (vectors=18 / faceA=19 lines; the
# md5s below are the MEASURED FIRST-RUN OUTPUT, drift refuses EVERY build) ----
test "$(wc -l < "$H"/vectors.txt)" -eq 18          # MEASURED first-run face
test "$(wc -l < "$H"/vectors_faceA.txt)" -eq 19    # MEASURED first-run face
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"       = "e75f7385779aa89c365dd2ce4a208b67"
test "$(md5sum "$H"/vectors_faceA.txt | awk '{print $1}')" = "fe1189c6c78139b8828c1a8071e3df28"

# ---- known-answer wc+md5 pins (OUTPUT of the MEASURED first run; build.sh
# DRIFTS-then-refuses, NEVER fabricates) ----
md5sum "$H"/vectors.txt "$H"/vectors_faceA.txt > "$H/md5_pinned.txt"   # receipt (ignored)

# ---- frozen-donor direct-md5 census (miscip :492-:514 face VERBATIM, 15
# faces -- the DIRECT face; NEVER re-derived) ----
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

# ---- BACKBONE-10 census (POST-ROW PIN 8->10, §WITNESS append: the immediate
# chain face = small4 + daq3 + BOTH tracked witnesses of the landed misc rows)
# -- 10 faces, additive-safe: NO gre/fmod/vocab self-literal rides THIS group
# (those ride the FM15 clone above + the chain-echo greps below) ----
declare -a B10=(
 "/opt/data/snort3-rust/tools/small4_harness/vectors.txt 462f0ff6ed44220564c5ef0c8538ad80"
 "/opt/data/snort3-rust/tools/small4_harness/vectors_faceA.txt 4755d48c54cc057b3c3c9eafec01c7cf"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors.txt fd1855e10e08eedcc6598de7ee034d0e"
 "/opt/data/snort3-rust/tools/daq3_harness/vectors_faceA.txt 2fb9dc4570a0160451f8399d22736a60"
 "/opt/data/snort3-rust/tools/daq3_harness/witness_daq.cc e0166b021073fed328bfd583c839e38b"
 "/opt/data/snort3-rust/tools/miscip_harness/vectors.txt 43b259ac8b77320ff9ddaa80dde1a36e"
 "/opt/data/snort3-rust/tools/miscip_harness/vectors_faceA.txt e4c47bac93a15af4ecfdc9a0bd1abe62"
 "/opt/data/snort3-rust/tools/miscip_harness/witness_miscip.cc c5b498ffa6beac768f34e25830c552a1"
 "$H/witness_trio.cc ef50cd2f8cdb4b9fa3d483e702bd73be"
 "$H/witness_conf.cc 4dd91018f8439d706ba666c6f18c9152"
)
for e in "${B10[@]}"; do
    set -- $e
    test "$(md5sum "$1" | awk '{print $1}')" = "$2"
done
md5sum "${B10[@]%% *}" | awk '{print $1"  "$2}' > "$H/backbone10.txt"   # receipt (ignored)

# fmod frozen tail VERBATIM cross-read (chain anchor face):
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" /opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "4826fc2233044a2d5429413faf0ae1af" /opt/data/snort3-rust/tools/fmod_harness/build.sh
# gre GATE anchor (the 18g chain rides this VERBATIM face pin; the grey
# positive-gate CONTRAST face for this row's ZERO-gate 18th-straight pin):
test "$(md5sum /opt/data/snort3-rust/tools/gre_harness/gate.txt | awk '{print $1}')" = "6751d1a8c21da0fdfed87ddfd4d37c5f"
grep -q "All tests passed (1 assertion in 1 test case)" /opt/data/snort3-rust/tools/gre_harness/gate.txt
# vocab chain anchor (18e witness face, self-literal in ITS OWN build.sh --
# additive-safe NEVER pinned by THIS row):
grep -q "9fad7e9d7a278fbc2ee82c233f86e774" /opt/data/snort3-rust/tools/vocab_harness/build.sh
# two-lineage donor rebuild echoes (the chain-ride face gre/fmod/vocab stay
# frozen, miscip + daq3 ride DIRECT (frozen lineage, 18i-j re-rule): miscip
# vectors face pinned via B10; daq3 via B10 -- rebuild OPTIONAL at this row).

# ---- TWO-LINEAGE census loop (MEASURED, never typed; THIS row adds ZERO
# gate.txt so the 25-tracked face is UNDISTURBED BY DESIGN): ----
frozen=$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')
test "$frozen" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 25
md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l > "$H/gate_md5_lineages.txt"
test "$(git -C /opt/data/snort3-rust ls-files | grep -c gate.txt)" -eq 1   # honest tracked face: gre's ONLY
# name-pin census re-armed (dir-name NEVER freezes a table name; a future
# row's collision fires LOUDLY):
test "$(ls -d /opt/data/snort3-rust/tools/llc_harness /opt/data/snort3-rust/tools/vxlan_harness /opt/data/snort3-rust/tools/user_harness 2>/dev/null | wc -l)" -eq 0
# ground identity re-pin (seed @ fe29cbe -- ground READ-ONLY, untouched).
# NO own-repo HEAD pin: the 18i PROCESS-LESSONS law (NEVER pin a harness to
# the working repo's own HEAD -- pin the IMMUTABLE ground only).
test "$(git -C "$SRC" rev-parse HEAD)" = "fe29cbe7403acc0dd428065a69d8f29cc311c18e"

# ---- STAGEABLES echo + .gitignore PROOF (git ls-files, NEVER pre-typed
# arithmetic): the NON-ignored face of this dir = exactly the 7 stageables.
# FACE POSTURE (18i re-rule): PRE-commit the 7 are UNTRACKED (--others);
# POST-commit the SAME proof runs against the landed face. ----
untracked=$(git -C /opt/data/snort3-rust ls-files --others --exclude-standard tools/misc3_harness | sort)
tracked=$(git -C /opt/data/snort3-rust ls-files tools/misc3_harness | sort)
face="$untracked"; [ -z "$untracked" ] && face="$tracked"
echo "$face" > "$H/stageables.txt"
test "$(echo "$face" | wc -l)" -eq 7
for f in PLAN.md build.sh probe.cc probe_dec.cc vectors.txt vectors_faceA.txt witness_trio.cc; do
    echo "$face" | grep -q "tools/misc3_harness/$f$"
done
# the gitignored faces re-proved individually (a missing pattern = a blob in
# the future add = loud):
for f in copy/daq.h copy/daq_common.h copy/cd_llc.o o2/cd_llc.o probe probe_O2 probe_dec probe_dec_O2 probe.o probe_dec.o witness_conf.cc witness_18f.o witness_conf.o witness_trio.o witness_trio2.o vectors_O0.txt vectors_faceA_O2.txt nm_U_cd_llc.txt E4_cd_llc.txt E4_nodaq_cd_llc.txt E4_cd_user_v1.txt L1_link_face.txt L1_undefined.txt md5_pinned.txt gate_md5_lineages.txt stageables.txt backbone10.txt; do
    git -C /opt/data/snort3-rust check-ignore -q "tools/misc3_harness/$f" || { echo "GITIGNORE FACE DEAD: tools/misc3_harness/$f NOT ignored"; exit 1; }
done
# vectors NEVER ignored (the stageable face, explicit NOT-proof):
git -C /opt/data/snort3-rust check-ignore -q "tools/misc3_harness/vectors.txt" && { echo "VECTORS WRONGLY IGNORED"; exit 1; } || true
git -C /opt/data/snort3-rust check-ignore -q "tools/misc3_harness/vectors_faceA.txt" && { echo "FACE-A WRONGLY IGNORED"; exit 1; } || true
# no STAGED churn: index EMPTY. Tracked-MODIFIED face (lineage-honest, the
# daq3 :677-:687 template): EVERY dirty tracked file must be one of THIS
# row's OWN paths (seed face: .gitignore ONLY); POST-commit the face is
# EMPTY; fires LOUDLY on any face touching another row's/committed lineage
# file. Rows NEVER rewrite history. daq3's copy/daq.h stays TRACKED untouched
# (the REUSE cp reads it, NEVER writes -- the find-1 landing census above is
# the guard; NEVER pin own HEAD).
test -z "$(git -C /opt/data/snort3-rust diff --name-only --cached)"          # index EMPTY
rowface='^\.gitignore$|^src/codecs/mod\.rs$|^tests/misc3_parity_test\.rs$|^PORTING_PLAN\.md$|^KNOWN DEVIATIONS\.md$|^tools/misc3_harness/(PLAN\.md|build\.sh|probe\.cc|probe_dec\.cc|vectors\.txt|vectors_faceA\.txt|witness_trio\.cc)$'
test -z "$(git -C /opt/data/snort3-rust diff --name-only | grep -vE "$rowface")"

# ---- THE graft does NOT stay: STRIP $C/daq.h at end-of-build AFTER every
# compile (misc trio NEVER includes daq.h -- the E4 daq wall proved the split
# IN-tree; keeping misc3/copy daq.h-FREE is what keeps the daq3 :105 second-
# landing census green for EVERY future session post-landing; the mid-build
# 112 find-count rode the graft-in-tree face). ----
rm -f "$C/daq.h"
test "$(find "$C" -type f ! -name '*.o' | wc -l)" -eq 111   # post-strip trio-tree face = 105 + 3 cps + 3 TUs (MEASURED LITERAL per PLAN)
test "$(find /opt/data/snort3-rust/tools -name daq.h | wc -l)" -eq 1     # THE landing stays ONE (daq3's tracked 33 L 73fdbc39)
test "$(md5sum /opt/data/snort3-rust/tools/daq3_harness/copy/daq.h | awk '{print $1}')" = "73fdbc3983ca45246b554c46efdf1ad1"

echo "row-TU nm census (MEASURED, never typed): llc=$(wc -l < "$H/nm_U_cd_llc.txt") vxlan=$(wc -l < "$H/nm_U_cd_vxlan.txt") user=$(wc -l < "$H/nm_U_cd_user.txt") union=$(wc -l < "$H/nm_U_union.txt") | union-mangled=$(wc -l < "$H/nm_U_mangled_union.txt") (tunnel_bypass census 0/1/0 -- HOOK rides witness_18f CARRIED, zero new bypass)"
echo "witness delta re-measured: L1 undefined-EXACTLY-2 (SFDAQ::get_local_instance + SFDAQInstance::ioctl ONLY) -> +witness_trio GREEN, own-new T census EXACTLY-2; get_proto_name row census 0 -> witness_miscip c5b498ff DONOR-INHERITED cite NEVER linked"
echo "graft-v2 face: v16 cd_user rc1 at cc:101 invalid-conversion (E4_cd_user_v1.txt) -> v2 flip+typedefs rc0 x3 trio + daq3 ip trio green-under-v2 rc0 x3 (E4_flipv2_* EMPTY); graft-v2 rides ONLY this heredoc (per-link isolation, frozen harnesses NEVER edited); daq.h 33 L 73fdbc39 REUSE cp NEVER a second graft, STRIPPED end-of-build (landing census stays 1)"
echo "copy tree find-count (MEASURED): mid-build 112 (105 miscip post-strip + daq.h REUSE + 3 fresh hdr cps daqs/daq_user.h+sfdaq pair + 3 row TUs) / post-strip 111 = 105+3+3 (the REUSE graft NEVER stays)"
echo "hidden-table census: BUILDING_SO sed x3 + snort_plugins grep 1/1/1 + nm table D symbol EXACTLY-1 x3 (the STATIC arm IS the harness face) + mod_ctor asymmetry 1/0/0 FACE-A pin (llc REAL :156/:159 vs vxlan/user nullptr pairs)"
echo "E4 adaptation: 3 fresh cps each -> ONLY cd_user DIES; codec_module.h -> ONLY cd_llc; active.h -> ONLY cd_vxlan; daq.h -> ip trio x3 DIE + misc trio x3 SURVIVE (daq_common.h not daq.h face) + restored rc0 x3 EVERY build"
echo "O0==O2: FACE-A $(cmp -s "$H/vectors_faceA_O0.txt" "$H/vectors_faceA_O2.txt" && echo BYTE-IDENT), DEC $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "frozen census: $frozen/25 holders of 4826fc22, $(cat "$H/gate_md5_lineages.txt") distinct md5s (loop MEASURED here; tracked gate.txt = 1, ls-files); BACKBONE-10 md5 face pinned (receipt backbone10.txt; 8->10 post-row: +miscip vectors pair +witness_miscip +witness_trio)"
echo "MISC3_HARNESS_OK vectors=$( [ -e "$H/vectors.txt" ] && wc -l < "$H/vectors.txt" || wc -l < "$H/vectors_O0.txt") faceA=$( [ -e "$H/vectors_faceA.txt" ] && wc -l < "$H/vectors_faceA.txt" || wc -l < "$H/vectors_faceA_O0.txt") gates=0"
