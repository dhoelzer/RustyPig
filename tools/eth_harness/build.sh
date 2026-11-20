#!/usr/bin/env bash
# eth_harness -- row 18d root/link codec layer: codecs/root/cd_eth.cc 262 +
# codecs/codec_module.h 269 + codecs/codec_module.cc 71 + codecs/link/cd_arp.cc
# 128 = 730 L (PLAN 0: per-file md5s + wc sum pinned below, own-measured).
# PROBE-ONLY (PLAN 0/6): the 4 row files carry ZERO gate material (0/0/0 per
# file, asserted below) and link//root/ ship NO upstream test dirs (find-empty
# asserted). CppUTest unbuildable on host -- walls re-proven EVERY build
# (E4_cpputest_fatal.txt: donor wall cd_geneve.cc:26 log/text_log.h; ground-
# tree wall daq_common.h; 18d-face wall cd_geneve.cc:28 packet_io/active.h ->
# CppUTest headers host-absent, find-asserted). ZERO gate.txt shipped; the 9
# holders of 4826fc2233044a2d5429413faf0ae1af among exactly 24 tracked
# gate.txt are frozen dirs -> 12th straight byte-ident (fmod double-rebuild =
# session ritual OUTSIDE this script, per csum-18b/vocab-18c; the 12th claim
# rides THAT run, never typed here -- 17p lesson).
# Copy tree (PLAN 1): vocab donor VERBATIM + 3 row cps + EXACTLY 26 delta
# files (21 real cps + 2 surgery carries [packet.h flowz sed, thread_config.h
# hwloc excision] + 3 lineage heredoc carries [daq_common.h EOFDAQ, flowz/
# flow_fwd.h EOFLOW+FIXFLOW, trace/trace.h EOFTRH -- all fmod-proven, md5/
# cmp-pinned]). daq_dlt.h graft EXTENDED: DLT_EN10MB 1 + DLT_PPP_ETHER 51
# (graft SECOND consumer, cd_eth.cc:38 ADD_DLT x2 + :76-:77; CITE libpcap
# pcap/dlt.h tcpdump-group MASTER :68/:243 fetched THIS pass -- the 18c
# android mirror URL 404s, correction pinned; vectors pin DLT 1/DLT 51).
# E4 DITTO (walls BEFORE the row cps, donor face): the 3 row TUs die EXACTLY
# at cd_eth->log/log_text.h / cd_arp->protocols/arp.h / codec_module->trace/
# trace.h (recon-pinned first-missing), receipts E4_walls_*.txt asserted.
# UTIL DUP, INVERTED face (PLAN 4): the REAL utils/util.o cp IS the def home
# (util.cc:119); linking the TRACKED frozen codec_harness/stubs.cc UNMODIFIED
# => multiple-definition collision (link arm 10 MUST fail, E6_dup_collision.
# txt), the real link arm 20 uses THIS dir's stubs_18d.cc (RETIRED strdup/
# strndup; nm assert 0 T snort::snort_str* in stubs_18d.o, 2 in util.o).
# Frozen stubs.cc byte-frozen (md5 be9bdd0b re-pinned). NO cd_*[] retirement
# at 18d (PLAN 5): zero witness tables here (probe drives cd_eth[]/cd_arp[]
# DIRECTLY; cd_arp[] defined by cd_arp.cc:122 itself); vocab stub set + 
# vectors + codec_api.rs:82-:85 frozen, md5 re-pinned; 18e cd_hopopts landmine carried.
# Values NEVER typed from the PLAN (17p lesson): the ladder greps below are
# the scratch-MEASURED 15-L vectors (md5 1bd98dbb57dd2f536104995bd76d9bad,
# O0==O2 byte-ident) re-measured fresh.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy

# ---- ground identity (4 row files pinned by OWN md5 + wc, measured not typed) ----
test "$(md5sum "$SRC"/src/codecs/root/cd_eth.cc | awk '{print $1}')"      = "22f10ceb0e01ab6c505534bde42c04aa"
test "$(md5sum "$SRC"/src/codecs/codec_module.h | awk '{print $1}')"      = "3f3bd92752ba46b8732f831724d3b279"
test "$(md5sum "$SRC"/src/codecs/codec_module.cc | awk '{print $1}')"     = "27ca93d786e8532b7f9679efafc57726"
test "$(md5sum "$SRC"/src/codecs/link/cd_arp.cc | awk '{print $1}')"      = "3520b36cf3cfd62b01528021c156f48c"
test "$(cat "$SRC"/src/codecs/root/cd_eth.cc "$SRC"/src/codecs/codec_module.h "$SRC"/src/codecs/codec_module.cc "$SRC"/src/codecs/link/cd_arp.cc | wc -l)" -eq 730
# zero suite material per file (PLAN 0):
for f in codecs/root/cd_eth.cc codecs/codec_module.h codecs/codec_module.cc codecs/link/cd_arp.cc; do
    test "$(grep -c 'TEST_CASE\|TEST_GROUP\|^TEST(\|UNIT_TEST\|TEST_CASE[[:space:]]*(' "$SRC"/src/$f || true)" -eq 0
done
# link/ + root/ ship ZERO test material (PLAN 0 census):
test "$(find "$SRC"/src/codecs/link "$SRC"/src/codecs/root -iname '*test*' | wc -l)" -eq 0
# tree-level census (unchanged from 18c -- cd_gre stays a FUTURE row):
test "$(grep -rc 'TEST_CASE[[:space:]]*(' "$SRC"/src/codecs --include='*.cc' --include='*.h' | grep -vc ':0$' || true)" -eq 1
grep -q 'TEST_CASE (' "$SRC"/src/codecs/ip/cd_gre.cc
test "$(grep -h '^TEST(' "$SRC"/src/codecs/*/test/*_test.cc | wc -l)" -eq 17
test "$(grep -h 'TEST_GROUP' "$SRC"/src/codecs/*/test/*_test.cc | wc -l)" -eq 6
# Lua seam stays 18a's: row TUs carry ZERO lua refs (PLAN 0):
for f in codecs/root/cd_eth.cc codecs/codec_module.h codecs/codec_module.cc codecs/link/cd_arp.cc; do
    test "$(grep -ci 'lua' "$SRC"/src/$f || true)" -eq 0
done
# cd_gre rule UNTOUCHED (PLAN 6): anchors re-measured, 18d pre-digs nothing:
test "$(sed -n '34p' "$SRC"/src/codecs/ip/cd_gre.cc)" = "#ifdef UNIT_TEST"
test "$(sed -n '35p' "$SRC"/src/codecs/ip/cd_gre.cc)" = '#include "catch/snort_catch.h"'
test "$(sed -n '352p' "$SRC"/src/codecs/ip/cd_gre.cc | grep -c 'TEST_CASE (')" -eq 1
test "$(wc -l < "$SRC"/src/codecs/ip/cd_gre.cc)" -eq 366


# ---- copy tree: the 18c VOCAB DONOR VERBATIM (vocab_harness = lineage head,
# NEXT.md:206; mkdir dirs extended for the 18d delta dirs; every cp line and
# the four 17d printf grafts carried byte-for-byte from that donor block) ----
rm -rf "$C"
mkdir -p "$C"/{framework,codecs,detection,main,protocols,sfip,utils,log,managers,target_based,packet_io,control,helpers,codecs/misc,codecs/ip,codecs/root,codecs/link,trace,flow,flowz,hash}
cp "$SRC"/src/framework/{codec.h,codec.cc,decode_data.h,base_api.h,counts.h,parameter.h,value.h,module.h} "$C"/framework/
cp "$SRC"/src/codecs/codec_module.h "$C"/codecs/
cp "$SRC"/src/protocols/{ip.h,ip.cc,ipv4.h,ipv6.h,layer.h,mpls.h,protocol_ids.h} "$C"/protocols/
cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/utils/{cpp_macros.h,bits.h,util.h,util_cstring.h,util_cstring.cc,util_net.h} "$C"/utils/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/main/thread.h "$C"/main/
# 17d printf grafts (greppable in codec_harness/build.sh -- recipes carried):
printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
# 18d OVERRIDES the 17d messages.h printf graft below: text_log.cc
# (REAL cp) consumes the REAL header (STD_BUF :37 + the FatalError decl
# :126) -- the scratch recon face used the real file (recon 4 'messages.h
# REAL-decl cp'); cp lands in the delta block, this graft line stays for
# donor-VERBATIM integrity and is OVERWRITTEN (last-writer-wins, audited).
: # graft-line kept for donor byte-identity

printf '#pragma once\n#include <cstdint>\nnamespace snort {\nclass DetectionEngine {\npublic:\n    static int queue_event(unsigned gid, unsigned sid);\n};\n}\n' > "$C"/detection/detection_engine.h
# ---- 18c carried AS-IS: the pinned snort_config.h REAL cp + its 12-file
# closure + the 2 managers (md5-pinned; R2 inheritance later rows reuse) ----
# ---- cp delta: EXACTLY the pinned 12-file snort_config closure + managers ----
# snort_config.h REAL cp (NO shim): md5 == ground == action_harness holder.
test "$(md5sum "$SRC"/src/main/snort_config.h | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
test "$(wc -l < "$SRC"/src/main/snort_config.h)" -eq 798
if [ -e /opt/data/snort3-rust/tools/action_harness/copy/main/snort_config.h ]; then
    cmp -s /opt/data/snort3-rust/tools/action_harness/copy/main/snort_config.h "$SRC"/src/main/snort_config.h \
        && test "$(md5sum /opt/data/snort3-rust/tools/action_harness/copy/main/snort_config.h | awk '{print $1}')" = "638120b51712c12ce847829308ac5a01"
fi
cp "$SRC"/src/main/snort_config.h "$C"/main/
# the closure = 7 (recon auto-loop) + 4 (snort_config.h:35-:38 own includes) --
# EXACTLY 11, pinned as a list; R2 note: later snort_config rows inherit it.
for h in target_based/snort_protocols.h packet_io/active_action.h framework/data_bus.h framework/mp_data_bus.h control/control.h framework/mp_transport.h helpers/lockless_ring.h framework/inspector.h framework/ips_action.h helpers/scratch_allocator.h main/policy.h; do
    cp "$SRC"/src/$h "$C"/$h
done
# managers: 2 md5-pinned cps (action_harness md5-ident precedent for
# plugin_manager.h; plugin.h closure = base_api.h, donor-resident).
test "$(md5sum "$SRC"/src/managers/plugin_manager.h | awk '{print $1}')" = "a9242b711e2ca0ef9d4418dcc0caa014"
test "$(md5sum "$SRC"/src/managers/plugin.h | awk '{print $1}')"         = "4c2ea065852120a2144c06d5382c272b"
cp "$SRC"/src/managers/{plugin_manager.h,plugin.h} "$C"/managers/
if [ -e /opt/data/snort3-rust/tools/action_harness/copy/managers/plugin_manager.h ]; then
    cmp -s /opt/data/snort3-rust/tools/action_harness/copy/managers/plugin_manager.h "$SRC"/src/managers/plugin_manager.h
fi

# The 18c graft face EXTENDED for 18d: cd_eth.cc:25 includes <daq_dlt.h>
# BEFORE any row cp, so this block PRECEDES the row cps. DLT_EN10MB 1 +
# DLT_PPP_ETHER 51 = the graft's SECOND consumer (cd_eth.cc:38 ADD_DLT x2
# + :76-:77 get_data_link_type). CITE CORRECTED THIS pass: the 18c-era
# android.googlesource mirror URL 404s NOW; re-fetched the the-tcpdump-
# group/libpcap MASTER pcap/dlt.h (1741 L) -- SAME :112/:114 DLT_RAW arms,
# cite CONFIRMED at master; scratch row18d/dlt.h holds the fetched file.
test "$(find "$SRC" -name daq_dlt.h | wc -l)" -eq 0          # ABSENT in tree
printf '#pragma once\n// witness graft (fmod daq_common.h recipe): DAQ SDK header NOT in tree (fe29cbe) nor on host.\n// DLT_RAW 12 CITE (18c): libpcap pcap/dlt.h :112-:114. 18c CITED the android.googlesource\n// mirror -- that URL 404s as of THIS 18d pass; re-fetched the the-tcpdump-group/libpcap\n// MASTER face (raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap/dlt.h,\n// 1741 L): SAME :112 #define DLT_RAW 14 + :114 #define DLT_RAW 12 arms -- cite CONFIRMED.\n#define DLT_RAW 12\n// 18d EXTENSION (graft SECOND consumer: cd_eth.cc:38 ADD_DLT x2 + :76-:77):\n// DLT_EN10MB 1 = master dlt.h :68; DLT_PPP_ETHER 51 = master dlt.h :243 (fetched THIS pass).\n#define DLT_EN10MB 1\n#define DLT_PPP_ETHER 51\n' > "$C"/daq_dlt.h
# the corrected libpcap-master cite MUST ride the tracked PLAN (vocab
# precedent: cite greps run against PLAN.md every build):
grep -q '#define DLT_RAW 12' "$H"/PLAN.md
grep -q 'the-tcpdump-group/libpcap/master/pcap/dlt.h' "$H"/PLAN.md
grep -q '404' "$H"/PLAN.md                    # android-mirror 404 correction rides PLAN
grep -q ':68' "$H"/PLAN.md                    # DLT_EN10MB master cite
grep -q ':243' "$H"/PLAN.md                   # DLT_PPP_ETHER master cite
grep -q 'lines 112' "$H"/PLAN.md              # the DLT_RAW :112/:114 arms
# the EXTENDED graft face itself:
grep -q '#define DLT_EN10MB 1' "$C"/daq_dlt.h
grep -q '#define DLT_PPP_ETHER 51' "$C"/daq_dlt.h
grep -q '#define DLT_RAW 12' "$C"/daq_dlt.h


# ---- THE row: 3 NEW cps + the donor-resident codec_module.h -- the 18c
# rule "codec_module.cc links at 18d" PAYS OFF (first ever link of its body) ----
cp "$SRC"/src/codecs/root/cd_eth.cc "$C"/codecs/root/
cp "$SRC"/src/codecs/codec_module.cc "$C"/codecs/
cp "$SRC"/src/codecs/link/cd_arp.cc "$C"/codecs/link/

# ---- E4 DITTO rows AT THE DONOR FACE (the three first-missing includes the
# recon pinned; receipts asserted) ----
for t in codecs/root/cd_eth.cc codecs/link/cd_arp.cc codecs/codec_module.cc; do
    g++ -std=c++17 -O0 -w -I"$C" -c "$SRC"/src/"$t" -o /dev/null 2> "$H/E4_walls_$(basename "$t" .cc).txt" || true
done
grep -q 'fatal error: log/log_text.h'  "$H/E4_walls_cd_eth.txt"
grep -q 'fatal error: protocols/arp.h' "$H/E4_walls_cd_arp.txt"
grep -q 'fatal error: trace/trace.h'   "$H/E4_walls_codec_module.txt"

# ---- E4 walls 1/2 AT THE DONOR FACE = the 18c geneve double-wall RE-PROVEN
# (scratch row18d/E4_wall{1,2}.txt = the fresh targets): wall 1 dies INSIDE
# the row-TU family; wall 2 = the ground tree itself (DAQ SDK absent) ----
w1=$(g++ -fsyntax-only -I"$C" "$SRC"/src/codecs/misc/test/geneve_codec_test.cc 2>&1 || true)
printf '%s\n' "$w1" > "$H/E4_wall1.txt"
grep -q 'cd_geneve.cc:26:10: fatal error: log/text_log.h: No such file' <<< "$w1"
w2=$(g++ -fsyntax-only -I"$C" -I"$SRC"/src "$SRC"/src/codecs/misc/test/geneve_codec_test.cc 2>&1 || true)
printf '%s\n' "$w2" > "$H/E4_wall2.txt"
grep -q 'src/protocols/packet.h:27:10: fatal error: daq_common.h: No such file' <<< "$w2"

# ---- DELTA (PLAN 1: EXACTLY 26 delta files = 21 real cps + 2 surgery +
# 3 lineage heredoc carries; the packet_manager.h flow sub-closure rides the
# PROVEN fmod recipes -- list EXACT, recon 9.7 duty) ----
cp "$SRC"/src/log/{log_text.h,text_log.h,text_log.cc,log.h} "$C"/log/
cp "$SRC"/src/log/messages.h "$C"/log/               # REAL header OVERRIDES the 17d printf graft (above)
cp "$SRC"/src/protocols/{eth.h,arp.h,packet_manager.h,geneve.h} "$C"/protocols/
cp "$SRC"/src/framework/pdu_section.h "$C"/framework/
cp "$SRC"/src/hash/{ghash.h,hash_defs.h,hash_key_operations.h,primetable.h,fnv.h,xhash.h} "$C"/hash/
cp "$SRC"/src/flow/{flow_key.h,flow_data.h} "$C"/flow/
mv "$C"/flow/flow_data.h "$C"/flowz/flow_data.h
cp "$SRC"/src/utils/{stats.h,util.cc} "$C"/utils/          # REAL def home of the strdup pair (PLAN 4)
cp "$SRC"/src/framework/module.cc "$C"/framework/          # Module family closure (17z precedent)
cp "$SRC"/src/main/stats_output_format.h "$C"/main/        # module.cc need (flog :193-:194 precedent)
cp "$SRC"/src/protocols/packet.h "$C"/protocols/          # surgery 1/2 below
cp "$SRC"/src/main/thread_config.h "$C"/main/             # surgery 2/2 graft below
sed -i 's|#include "flow/flow.h"|#include "flowz/flow_fwd.h"|' "$C"/protocols/packet.h
python3 - "$C" <<'FIXTC'
import sys
p = sys.argv[1] + "/main/thread_config.h"
s = open(p).read()
assert "#include <hwloc.h>" in s
s = s.replace("#include <hwloc.h>\n", "")
open(p, "w").write(s)
FIXTC
# lineage carry 1/3: daq_common.h (fmod EOFDAQ VERBATIM; packet.h closure):
cat > "$C"/daq_common.h <<'EOFDAQ'
#pragma once
#include <cstdint>
typedef void* DAQ_Msg_h;
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
EOFDAQ
# lineage carry 2/3: flowz/flow_fwd.h (fmod EOFLOW + the 17q FIXFLOW fixlet
# VERBATIM; face md5 re-pinned -- ground ships NO such file (flow monolith):
cat > "$C"/flowz/flow_fwd.h <<'EOFFLOW'
#pragma once
#include <cstdint>
#include "protocols/layer.h"   // packet.h Layer* member (real chain: flow.h pulled it)
#include "sfip/sf_ip.h"        // Flow::client_ip/server_ip (real flow.h:523-524)
#include "flow/flow_key.h"     // const FlowKey* key (real flow.h:503)
#define SSNFLAG_SEEN_CLIENT         0x00000001
#define SSNFLAG_SEEN_SERVER         0x00000002
#define SSNFLAG_SEEN_BOTH (SSNFLAG_SEEN_SERVER | SSNFLAG_SEEN_CLIENT)
namespace snort {
class Flow {
public:
    using SnortProtocolId_stub = int;
    struct { bool client_initiated : 1; } flags = {};
    struct { int snort_protocol_id = 0; } ssn_state = {};
    uint64_t session_flags = 0;
    const char* service = nullptr;
    uint16_t client_port = 0;    // NEW17z: real flow.h:586
    uint16_t server_port = 0;    // NEW17z: real flow.h:587
    SfIp client_ip = {};       // real flow.h:523
    SfIp server_ip = {};       // real flow.h:524
    int16_t client_group = 0;  // real flow.h:583
    int16_t server_group = 0;  // real flow.h:584
    const FlowKey* key = nullptr;  // real flow.h:503
    bool two_way_traffic() const
    { return (session_flags & SSNFLAG_SEEN_BOTH) == SSNFLAG_SEEN_BOTH; }
};
}
struct FilteringState { uint64_t flow = 0; uint64_t pkt = 0; uint64_t session = 0; };
EOFFLOW
python3 - "$C" <<'FIXFLOW'
import sys
p = sys.argv[1] + "/flowz/flow_fwd.h"
s = open(p).read()
assert "get_flow_data" not in s
s = s.replace("namespace snort {\nclass Flow {",
              "namespace snort {\nclass FlowData;   // NEW17q: single-slot FlowData graft\n"
              "class Flow {")
anchor = "    bool two_way_traffic() const"
assert anchor in s
s = s.replace(anchor,
    "    // NEW17q graft (real flow.h:195/:200 shapes; single-slot witness\n"
    "    // bodies in stubs.cc -- PIN, one attached Flow per probe run)\n"
    "    FlowData* get_flow_data(unsigned id) const;\n"
    "    void set_flow_data(FlowData* fd);\n" + anchor)
open(p, "w").write(s)
FIXFLOW
test "$(md5sum "$C"/flowz/flow_fwd.h | awk '{print $1}')" = "e2903350f38977dbbf9d1121b62e2122"
# lineage carry 3/3: trace/trace.h = the fmod EOFTRH FACE (recon 2: BOTH
# faces compile; the face-full scratch rebuild PROVED this face compiles all
# three row TUs with vectors byte-ident; the lineage face carries the
# TraceOption pins codec_module.cc's trace seam consumes; ground face md5
# 67cf5f07bd09c668ce0310132f0c64fc recorded in PLAN):
cat > "$C"/trace/trace.h <<'EOFTRH'
#pragma once
#include <cstdint>
#include <string>
#include "main/snort_types.h"
#define DEFAULT_TRACE_LOG_LEVEL 1
#define TRACE_CRITICAL_LEVEL 2
#define TRACE_ERROR_LEVEL 3
#define TRACE_WARNING_LEVEL 4
#define TRACE_INFO_LEVEL 6
#define TRACE_DEBUG_LEVEL 7
#define DEFAULT_TRACE_OPTION_ID 0
#define DEFAULT_TRACE_OPTION_NAME "all"
using TraceOptionID = uint8_t;
using TraceLevel = uint8_t;
namespace snort {
// NEW18a graft (PLAN 0.2a): REAL struct verbatim from trace/trace.h:55-
// :63. file_module.cc:159 constructs a static TraceOption and get_trace_
// options() (file_module.h:76) returns it -- the class-Trace witness was
// incomplete for that call site.
struct TraceOption
{
    TraceOption(const char* n, TraceOptionID tid, const char* h) :
        name(n), id(tid), help(h) {}

    const char* name;
    TraceOptionID id;
    const char* help;
};

class Trace {
public:
    // witness: real Trace per-option level table collapses to one
    // DEFAULT_TRACE_OPTION_ID level (all file_cache call sites use it).
    uint8_t level = 0;
    std::string mod = "file_cache";
    bool enabled(TraceOptionID, TraceLevel log_level = DEFAULT_TRACE_LOG_LEVEL) const
    { return level >= log_level; }
    const char* module_name() const { return mod.c_str(); }
    const char* option_name(size_t) const { return DEFAULT_TRACE_OPTION_NAME; }
}; }
EOFTRH
test "$(find "$C" -type f | wc -l)" -eq 76   # 47 donor + 3 row + 26 delta; messages.h graft line OVERWRITTEN by the REAL cp (same path, no new file)
# ---- copy audit: EVERY non-graft copy byte-identical to ground ----
# (7 GRAFTS = config.h framework/api_options.h
# detection/detection_engine.h daq_dlt.h daq_common.h flowz/flow_fwd.h
# trace/trace.h (log/messages.h = REAL cp at 18d, graft line overwritten)
# + 2 SURGERY faces (packet.h cmp vs the pinned fmod copy
# face when present; thread_config.h vs ground-minus-the-hwloc-line).)
audit=0
while IFS= read -r f; do
    rel=${f#"$C"/}
    case "$rel" in
        config.h|framework/api_options.h|detection/detection_engine.h|daq_dlt.h|daq_common.h|flowz/flow_fwd.h|trace/trace.h) continue;;
        protocols/packet.h) if [ -e /opt/data/snort3-rust/tools/fmod_harness/copy/protocols/packet.h ]; then cmp -s "$f" /opt/data/snort3-rust/tools/fmod_harness/copy/protocols/packet.h || { echo "SURGERY-DRIFT packet.h" >&2; audit=1; }; fi; continue;;
        main/thread_config.h) diff <(sed '/#include <hwloc.h>/d' "$SRC"/src/main/thread_config.h) "$f" >/dev/null || { echo "SURGERY-DRIFT thread_config.h" >&2; audit=1; }; continue;;
        # ALIAS: flow_data.h is ground flow/flow_data.h staged into flowz/
        # (the fmod flowz dir convention, build.sh :407 -- cp then mv):
        flowz/flow_data.h) cmp -s "$f" "$SRC"/src/flow/flow_data.h || { echo "COPY-DRIFT flow/flow_data.h"; audit=1; }; continue;;
    esac
    if [ -e "$SRC"/src/"$rel" ]; then
        cmp -s "$f" "$SRC"/src/"$rel" || { echo "COPY-DRIFT $rel" >&2; audit=1; }
    else
        echo "NOT-IN-GROUND $rel" >&2; audit=1
    fi
done < <(find "$C" -type f)
test "$audit" -eq 0
printf 'cp-audit: non-graft copies byte-ident vs ground; grafted+surgery faces pinned\n' > "$H/cp_audit_ok.txt"


# ---- probe-stageable integrity (md5 pins + the FROZEN lineage trio re-pin;
# PLAN 8: stageables are EXACTLY these 5) ----
test "$(md5sum "$H"/probe.cc | awk '{print $1}')"       = "0e6c153fc267f05af1b354d7c7efb249"
test "$(md5sum "$H"/stubs_18d.cc | awk '{print $1}')"   = "f4afd35f06bc45ce5aa0ec12110ed8ae"
test "$(md5sum "$H"/vectors.txt | awk '{print $1}')"    = "1bd98dbb57dd2f536104995bd76d9bad"
test "$(wc -l < "$H"/vectors.txt)" -eq 15
test "$(md5sum /opt/data/snort3-rust/tools/codec_harness/stubs.cc | awk '{print $1}')"         = "be9bdd0b437d1f6c56c841e8155d9e70"
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/witness_stubs.cc | awk '{print $1}')" = "9fad7e9d7a278fbc2ee82c233f86e774"
test "$(md5sum /opt/data/snort3-rust/tools/vocab_harness/vectors.txt | awk '{print $1}')"      = "5da70e82416b6f769af8177d859331e7"
# stubs_18d retirement face: marker present; the ONLY mentions of the pair
# live in the retirement COMMENT (defs gone):
grep -q 'RETIRED at 18d' "$H"/stubs_18d.cc
# every mention of the pair is a COMMENT line (2 header/retirement comments;
# ZERO code defs -- the def-side proof is the nm/ld asserts in E6 + E2):
test "$(grep -c 'snort_strdup\|snort_strndup' "$H"/stubs_18d.cc)" -eq 2
test "$(grep 'snort_strdup\|snort_strndup' "$H"/stubs_18d.cc | grep -vc '^\s*//')" -eq 0
# FROZEN-STUBS diff-0: own copy == the TRACKED frozen stubs.cc with EXACTLY
# the 7-line strdup/strndup body removed and EXACTLY the 3-line RETIRED
# marker added -- nothing else differs (receipt E_frozen_stubs_diff0.txt):
diff /opt/data/snort3-rust/tools/codec_harness/stubs.cc "$H"/stubs_18d.cc > "$H"/E_frozen_stubs_diff.txt || true
test "$(grep -c '^<' "$H"/E_frozen_stubs_diff.txt)" -eq 7
test "$(grep -c '^>' "$H"/E_frozen_stubs_diff.txt)" -eq 3
grep '^<' "$H"/E_frozen_stubs_diff.txt | grep -q 'snort_strdup'
grep '^<' "$H"/E_frozen_stubs_diff.txt | grep -q 'snort_strndup'
grep '^>' "$H"/E_frozen_stubs_diff.txt | grep -q 'RETIRED at 18d'
python3 - "$H" <<'DIFFCHK'
import sys
H = sys.argv[1]
f = open("/opt/data/snort3-rust/tools/codec_harness/stubs.cc").read()
o = open(H + "/stubs_18d.cc").read()
pair = ('char* snort_strdup(const char* s) { return s ? strdup(s) : nullptr; }\n'
        'char* snort_strndup(const char* s, size_t n) {\n'
        '    if (!s) return nullptr;\n'
        '    char* p = (char*)calloc(n + 1, 1);\n'
        '    strncpy(p, s, n);\n'
        '    return p;\n}\n')
marker = ('// RETIRED at 18d: snort_strdup/strndup \u2014 the REAL utils/util.o cp is the\n'
          '// def home (util.cc:119 verbatim bodies) \u2014 per-link dup-symbol rule (18a\n'
          '// trio-retirement pattern, 18c-vocab->18d inverted face).\n')
assert pair in f and marker in o
assert f.replace(pair, "") == o.replace(marker, ""), "diff-0 BROKE vs frozen stubs"
open(H + "/E_frozen_stubs_diff0.txt", "w").write("diff-0: own stubs == frozen stubs minus the strdup pair (marker-only delta)\n")
DIFFCHK
# ZERO cd_*[] witness tables (PLAN 5): the vocab witness_stubs.cc is NOT
# lifted; no BaseApi table def in this harness's sources:
test ! -e "$H"/witness_stubs.cc
test "$(cat "$H"/probe.cc "$H"/stubs_18d.cc | grep -o 'const BaseApi\* cd_' | wc -l)" -eq 0
# R6 eval-order rule (17p sibling): the five decode arms store to bool VARS
# first; no printf line interleaves a next=/bits= read with a live ->decode:
test "$(grep -c 'bool [a-e] = \(eth\|arp\)->decode' "$H"/probe.cc)" -eq 5
test "$(grep -c 'next.*->decode' "$H"/probe.cc || true)" -eq 0
test ! -e "$H"/catch_main.cc

# ---- E4 wall 3 at the FULL 18d face: even with the COMPLETE copy the
# CppUTest suites never reach a runner -- inside-tree they die at
# cd_geneve.cc:28 packet_io/active.h (still the row family); + ground -I
# they reach the HOST-ABSENT CppUTest headers (find asserted 0 hits) => the
# C gate NEVER touched by CppUTest (PLAN 6). Dialect census carry: 0
# TEST_CASE in test dirs / 17 TEST / 4 add_cpputest (CMake never invoked):
test "$(find /usr/include /usr/local/include -maxdepth 2 -name 'CppUTest*' | wc -l)" -eq 0
w3=$(g++ -fsyntax-only -I"$C" "$SRC"/src/codecs/misc/test/geneve_codec_test.cc 2>&1 || true)
printf '%s\n' "$w3" > "$H/E4_cpputest_fatal.txt"
grep -q 'cd_geneve.cc:28:10: fatal error: packet_io/active.h: No such file' <<< "$w3"
w4=$(g++ -fsyntax-only -I"$C" -I"$SRC"/src "$SRC"/src/codecs/misc/test/geneve_codec_test.cc 2>&1 || true)
printf '%s\n' "$w4" >> "$H/E4_cpputest_fatal.txt"
grep -q 'CppUTest/CommandLineTestRunner.h: No such file' <<< "$w4"
test "$(grep -rh 'TEST_CASE[[:space:]]*(' "$SRC"/src/codecs/*/test/ | wc -l || true)" -eq 0
test "$(grep -rc 'add_cpputest' "$SRC"/src/codecs/*/test/CMakeLists.txt | awk -F: '{s+=$2} END {print s}')" -eq 4

# ---- witness_conf.cc: the scratch-VERBATIM witness face (md5 4dd91018f84
# 39d706ba666c6f18c9152 staged at scratch; regenerated heredoc -- snort_config.cc
# itself NOT compiled, inspector/BUS world, 17z note). 18d NEW vs the vocab
# face (recon 9.3): SnortConfig::get_conf() -- cd_eth.cc:164 the FIRST
# consumer (encode() eth_dst ladder :172-:181; the witness conf keeps
# sc->eth_dst null = the measurable arm). show_stats pair GLOBAL scope
# (stats.h:101/:102 sit AFTER the namespace snort close -- namespaced defs
# bind the WRONG name, recon 9.4). LogEthAddrs = 1-line stand-in (REAL body
# log_text.cc:112 drags the packet/appid world, recon 9.2). get_error is NOT
# witnessed -- REAL util.o resolves it (inversion evidence, PLAN 2). ----
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

# ---- E1: compile row 3 + the REAL-cp link objs (the NEW util.o / module.o /
# text_log.o join the 18c donor four; util.cc compiles ground-VERBATIM THIS
# toolchain -- the flog <sstream> add NOT needed, face-full rebuild receipt;
# module.cc compiles ONLY after the thread_config.h hwloc excision above) ----
GXX="g++ -std=c++17 -O0 -w -I$C"
GXXA="g++ -std=c++17 -O2 -w -I$C"   # no spaces in path -> unquoted split safe
ROW="$C/codecs/root/cd_eth.cc $C/codecs/link/cd_arp.cc $C/codecs/codec_module.cc"
REAL="$C/framework/codec.cc $C/protocols/ip.cc $C/sfip/sf_ip.cc $C/utils/util_cstring.cc $C/utils/util.cc $C/log/text_log.cc $C/framework/module.cc"
for f in $ROW $REAL; do
    $GXX -c "$f" -o "$C/$(basename "$f" .cc).o"
done
$GXX -c "$H"/probe.cc -o "$H"/probe.o
$GXX -c "$H"/witness_conf.cc -o "$H"/witness_conf.o
$GXX -c "$H"/stubs_18d.cc -o "$H"/stubs_18d.o

UTIL_OBJS="$C/codec.o $C/ip.o $C/sf_ip.o $C/util_cstring.o $C/util.o $C/text_log.o $C/module.o $C/cd_eth.o $C/cd_arp.o $C/codec_module.o"

# ---- E6: the UTIL-DUP proof, INVERTED retirement face (PLAN 4; the 18a
# trio pattern's INVERSE first OBSERVED: the NEW real cp retires an OLD stub
# IN THIS LINK ONLY). Link arm 10 = TRACKED frozen stubs.cc + REAL util.o ->
# MUST fail multiple-definition (receipt); arm 20 below links THIS dir's
# stubs_18d.cc and MUST succeed. Frozen donor byte-frozen (md5 pinned) ----
$GXX -c /opt/data/snort3-rust/tools/codec_harness/stubs.cc -o "$H"/stubs_frozen.o
if $GXX $UTIL_OBJS "$H"/probe.o "$H"/witness_conf.o "$H"/stubs_frozen.o -o "$H"/probe_should_fail 2> "$H"/E6_dup_collision.txt; then
    echo "E6 BROKE: frozen stubs linked beside REAL util.o -- dup rule unproven"; exit 1
fi
grep -qE 'multiple definition of .*(snort::)?snort_str' "$H"/E6_dup_collision.txt
rm -f "$H"/probe_should_fail "$H"/stubs_frozen.o

# ---- E2: per-TU nm residue census (PLAN 2 table, re-run EVERY build;
# name-preserving U-strip: demangled names CONTAIN spaces -- drop col 1 only) ----
for t in cd_eth cd_arp codec_module; do
    nm -C -u "$C"/"$t".o | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H"/nm_U_"$t".txt
done
nm -C -u "$C"/module.o    | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H"/nm_U_module.txt
nm -C -u "$C"/text_log.o  | grep ' U ' | sed 's/^[[:space:]]*U[[:space:]]*//' | sort -u > "$H"/nm_U_text_log.txt
test "$(grep -c 'Codec::codec_event' "$H"/nm_U_cd_eth.txt)" -eq 1
test "$(grep -c 'SnortConfig::get_conf' "$H"/nm_U_cd_eth.txt)" -eq 1
test "$(grep -c 'LogEthAddrs' "$H"/nm_U_cd_eth.txt)" -eq 1
test "$(grep -c 'snort::Module::' "$H"/nm_U_cd_eth.txt)" -eq 8   # ctor + 7 (vtable/typeinfo lines lack '::')
test "$(grep -c 'Codec::codec_event' "$H"/nm_U_cd_arp.txt)" -eq 1
test "$(grep -c 'snort::Module::' "$H"/nm_U_cd_arp.txt)" -eq 8
test "$(nm -C -u "$C"/codec_module.o | grep -c 'Module::Module')" -eq 1   # ONLY the 4-arg ctor (nm-measured)
# module.o asks the GLOBAL show_stats pair -- UNNAMESPACED mangling proves
# the scope (never _ZN5snort10show_statsE; recon 9.4 trap pinned):
test "$(nm -u "$C"/module.o | grep -c 'U _Z10show_stats')" -eq 2
grep -q 'ThreadConfig::get_instance_max' "$H"/nm_U_module.txt
grep -q 'get_instance_id' "$H"/nm_U_module.txt
# get_error: UNDEF in text_log.o, DEFINED by REAL util.o (witness DROPPED):
s0=$(nm -u "$C"/text_log.o)
grep -q ' U _ZN5snort9get_errorE' <<< "$s0"
s1=$(nm -C --defined-only "$C"/util.o)
grep -q 'T snort::get_error' <<< "$s1"
# stubs_18d.o ZERO strdup-pair defs; util.o EXACTLY 2 (util.cc:119 home):
test "$(nm -C --defined-only "$H"/stubs_18d.o | grep -c 'T snort::snort_str')" -eq 0
test "$(nm -C --defined-only "$C"/util.o | grep -c 'T snort::snort_str')" -eq 2
s2=$(nm -C --defined-only "$C"/codec.o)
grep -q 'T snort::Codec::codec_event' <<< "$s2"
# both Module ctor overloads live in REAL module.o (cd_* 2-arg; codec_module 4-arg):
s3=$(nm --defined-only "$C"/module.o)
grep -q 'T _ZN5snort6ModuleC1EPKcS2_' <<< "$s3"
s4=$(nm --defined-only "$C"/module.o)
grep -q 'T _ZN5snort6ModuleC1EPKcS2_PKNS_9ParameterEb' <<< "$s4"
# witness_conf.o by MANGLED spellings (scope is exactly what must pin):
s5=$(nm --defined-only "$H"/witness_conf.o)
grep -q 'T _Z10show_statsPKmPK7PegInfojPKc' <<< "$s5"
test "$(nm --defined-only "$H"/witness_conf.o | grep -c ' _Z10show_stats')" -eq 2
s6=$(nm --defined-only "$H"/witness_conf.o)
grep -q '_ZN5snort11SnortConfig8get_confEv' <<< "$s6"
s7=$(nm --defined-only "$H"/witness_conf.o)
grep -q '_ZN5snort11LogEthAddrsE' <<< "$s7"
# probe.o drives the TWO tables DIRECTLY, ZERO stub-name refs (PLAN 5):
s8=$(nm -u "$H"/probe.o)
grep -q ' U cd_eth' <<< "$s8"
s9=$(nm -u "$H"/probe.o)
grep -q ' U cd_arp' <<< "$s9"
test "$(nm -u "$H"/probe.o | grep -c 'cd_ipv4\|cd_ipv6\|cd_tcp\|cd_hopopts' || true)" -eq 0
# the cd_*[] D-symbols come from 18d's OWN TUs (cd_eth.cc / cd_arp.cc:122):
s10=$(nm -C --defined-only "$C"/cd_eth.o)
grep -q ' D cd_eth' <<< "$s10"
s11=$(nm -C --defined-only "$C"/cd_arp.o)
grep -q ' D cd_arp' <<< "$s11"
# link-wide ZERO defs of the four FROZEN stub names (no table lifted anywhere;
# grep on RAW symtab -- a cd_arp def in this link is OURS, never the four):
for a in cd_ipv4 cd_ipv6 cd_tcp cd_hopopts; do
    test "$(nm --defined-only $UTIL_OBJS "$H"/stubs_18d.o "$H"/probe.o "$H"/witness_conf.o 2>/dev/null | grep -c " $a\$")" -eq 0
done

# ---- E5: link + run at -O0 AND -O2; outputs BYTE-IDENTICAL (the face-full
# scratch rebuild proved O0==O2 == the 15-L skeleton, md5 1bd98dbb...) ----
$GXX $UTIL_OBJS "$H"/probe.o "$H"/witness_conf.o "$H"/stubs_18d.o -o "$H"/probe   # word-split by design
O2=$H/o2; rm -rf "$O2"; mkdir -p "$O2"
for f in $ROW $REAL; do $GXXA -c "$f" -o "$O2/$(basename "$f" .cc).o"; done
$GXXA -c "$H"/probe.cc -o "$O2/probe.o"
$GXXA -c "$H"/witness_conf.cc -o "$O2/witness_conf.o"
$GXXA -c "$H"/stubs_18d.cc -o "$O2/stubs_18d.o"
$GXXA $(for b in cd_eth cd_arp codec_module codec ip sf_ip util_cstring util text_log module; do printf '%s ' "$O2/$b.o"; done) "$O2/probe.o" "$O2/witness_conf.o" "$O2/stubs_18d.o" -o "$H"/probe_O2
timeout 60 "$H"/probe    > "$H"/vectors_O0.txt || { echo PROBE_FAIL O0; exit 1; }
timeout 60 "$H"/probe_O2 > "$H"/vectors_O2.txt || { echo PROBE_FAIL O2; exit 1; }
cmp "$H"/vectors_O0.txt "$H"/vectors_O2.txt      # the E5 byte-identity arm
cmp -s "$H"/vectors_O0.txt "$H"/vectors.txt || { echo "VECTORS DRIFT vs tracked vectors.txt"; exit 1; }
if [ -e /opt/data/cache/scratch/row18d/vectors_skeleton.txt ]; then
    diff /opt/data/cache/scratch/row18d/vectors_skeleton.txt "$H"/vectors.txt
fi
# hygiene gate (fmod recipe carried): zero pointer-ish hex; zero 0x at all
# (all-decimal posture like 18c, recon 3 hygiene):
! grep -E '0x[0-9a-f]{6,}' "$H"/vectors.txt
test "$(grep -c '0x' "$H"/vectors.txt || true)" -eq 0

# ---- known-answer ladder (every ARM byte-pinned by the cmp above; greps
# here pin the DECOMPOSITION against GROUND, NEVER a forecast -- 17p) ----
grep -q '^API eth type=0 size=112 ver=1900547 name=eth$' "$H/vectors.txt"          # CodecApi pins (framework/codec.rs CDAPI face)
grep -q '^HELP support for ethernet protocol (DLT 1) (DLT 51)$' "$H/vectors.txt"   # ADD_DLT ladder x2 = graft SECOND consumer
test "$(grep -c '^DLT 51$' "$H/vectors.txt")" -eq 1
test "$(grep -c '^DLT 1$'  "$H/vectors.txt")" -eq 1
grep -q '^EV 116 424$' "$H/vectors.txt"    # GID_DECODE + DECODE_ETH_HDR_TRUNC = WALK pin: :171 "= 418" + 6 -> :177
test "$(sed -n '171p' "$SRC"/src/codecs/codec_module.h)" = "    DECODE_ICMP4_TYPE_OTHER = 418,"
test "$(sed -n '177p' "$SRC"/src/codecs/codec_module.h)" = "    DECODE_ETH_HDR_TRUNC,"
test "$(sed -n '172,176p' "$SRC"/src/codecs/codec_module.h | grep -c 'DECODE_')" -eq 5   # the +6 walk distance MEASURED from ground
grep -q '^ETH short -> 0$' "$H/vectors.txt"
grep -q '^ETH v4 -> 1 next=2048 lyr=14 bits=2048$' "$H/vectors.txt"   # PROTO_BIT__ETH 0x000800 -> decimal posture (decode_data.h:98)
grep -q '^ETH llc -> 1 next=263$' "$H/vectors.txt"                    # ETHERNET_LLC arm cc:97-:102
grep -q '^PIDS 261 n=1$' "$H/vectors.txt"                            # ETHERNET_802_3 (cc:82)
grep -q '^API arp name=arp$' "$H/vectors.txt"
grep -q '^HELPARP support for address resolution protocol$' "$H/vectors.txt"   # NO DLT suffix (cd_arp.cc:32) = per-codec ladder contrast
grep -q '^EV 116 109$' "$H/vectors.txt"    # LITERAL pin (double-pin discipline vs the 424 walk)
test "$(sed -n '73p' "$SRC"/src/codecs/codec_module.h)" = "    DECODE_ARP_TRUNCATED = 109,"
grep -q '^ARP short -> 0$' "$H/vectors.txt"
grep -q '^ARP ok -> 1 lyr=28 bits=4194304$' "$H/vectors.txt"          # PROTO_BIT__ARP 0x400000 (decode_data.h:109)
grep -q '^MOD rules=8 gid=116 help=general decoder rules trace=null$' "$H/vectors.txt"  # 8-row walk + non-DEBUG_MSGS nullptr cc:44-:48
test "$(sed -n '55,67p' "$SRC"/src/codecs/codec_module.cc | grep -c 'DECODE_')" -eq 8   # ground table rows MEASURED; probe walks them

# ---- gate-lineage receipts (PLAN 6: ZERO-EDIT, the 12th-straight argument;
# the fmod double-rebuild ITSELF = the session ritual OUTSIDE this script,
# csum-18b/vocab-18c pattern -- the 12th claim rides THAT measured run) ----
FM=/opt/data/snort3-rust/tools/fmod_harness/build.sh
grep -q "grep -q 'All tests passed (114 assertions in 22 test cases)'" "$FM"
grep -q "4826fc2233044a2d5429413faf0ae1af" "$FM"
test "$(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')" -eq 9
test "$(ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l)" -eq 24
test ! -e "$H"/gate.txt
test ! -e "$H"/gate
test "$(find "$H" -maxdepth 1 -name 'gate*' | wc -l)" -eq 0

echo "row-TU app residue: cd_eth(snort::)=$(grep -c 'snort::' "$H/nm_U_cd_eth.txt" || true) arp=$(grep -c 'snort::' "$H/nm_U_cd_arp.txt" || true) codec_module=$(grep -c 'snort::' "$H/nm_U_codec_module.txt" || true) module=$(grep -c 'show_stats\|ThreadConfig\|get_instance_id' "$H/nm_U_module.txt" || true) text_log=$(grep -c 'snort::' "$H/nm_U_text_log.txt" || true) (witnesses per PLAN 2; ZERO cd_*[] tables)"
echo "O0==O2 vectors identity: $(cmp -s "$H/vectors_O0.txt" "$H/vectors_O2.txt" && echo BYTE-IDENT)"
echo "vectors md5: $(md5sum "$H/vectors.txt")"
echo "gate census holders: $(md5sum /opt/data/snort3-rust/tools/*/gate.txt 2>/dev/null | grep -c '^4826fc2233044a2d5429413faf0ae1af')/24 (chain intact; eth harness gate.txt count 0)"
echo "util-dup collision proven: $(test -s "$H/E6_dup_collision.txt" && echo E6-YES || echo E6-NO)"
echo "ETH_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"
