#!/usr/bin/env bash
# Ground-truth harness for file_api/file_flows.{h,cc} (row 17q).
# Lifted from the PROVEN tools/fcache_harness donor (row 17p); deltas:
#  * gate: file_flows.cc compiled with -DUNIT_TEST -> the TU's OWN embedded
#    [file_flows] suite (8 TEST_CASEs; assertions pinned from the RUNNER,
#    never grep — PLAN.md says grep tallied 22). Plain-catch shim like donor.
#    The UNIT_TEST block ships its OWN scaffolding (FF_TEST_CONTEXT +
#    FFTestAccessor friend) — no extra graft needed for the gate itself.
#  * probe: file_flows.cc VERBATIM minus its #ifdef UNIT_TEST block, linked
#    REAL. The donor's ENTIRE FileFlows WITNESS block (fcache stubs.cc:442-
#    573: file_flow_data_id/get_file_flows/get_file_policy/handle_retransmit/
#    get_current/set_current/swap/restore/get_file_context/get_ppc/remove/
#    get_new_file_instance/~FileFlows/set_file_name/file_process x2/
#    init_file_context(dead decl, links fine)/find_main/retire_victim/
#    add_pending_file) is RETIRED (17o->17p retirement precedent).
#  * ONE graft delta vs donor (PLAN.md 3): flowz/flow_fwd.h Flow witness
#    gains get_flow_data(unsigned)/set_flow_data(FlowData*) (real flow.h:
#    195/:200, needed by file_flows.cc:141/:149/:159) — single-slot arm
#    (stubs.cc definition; get returns the slot iff id == stored fd->get_id()).
#  * NEW witnesses (measured undefined in the donor link): get_network_policy
#    + NetworkPolicy::get_base_file_policy (hand back the heap StubFilePolicy
#    through the REAL ref-count protocol), get_file_processed_size (body
#    copied literally from file_service.cc:256-268), PacketTracer::get_time
#    (pinned constant) + restart_timer, is_daq_activated ARMED (donor
#    hardwired false -> populate_trace_data never ran), get_instance_id
#    ARMABLE (pins (id<<32)|max_file_id++ at file_flows.cc:205-209; the
#    THREAD_LOCAL max_file_id stays REAL inside the TU).
#  * KEEP from donor: file_cache.o/file_lib.o REAL (retire rule), xhash/
#    hash_lru_cache/packet_time real TUs, clock interpose, file_trace/
#    file_counts arming, IMGR/FileService/Inspector witnesses, FlowData
#    witnesses (real inline FileFlows ctor uses them), StubFilePolicy.
#  * clock: same interposed clock_gettime fake clock as donor -> SnortClock
#    (high_resolution_clock) routes through it, pinning advance-log
#    duration-0.000000 lines in gate.txt/vectors.txt deterministically.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
NODE_INC=$(ls -d /opt/hermes/tools/node-*-linux-x64/include/node | head -1)
LIBCRYPTO=/usr/lib/x86_64-linux-gnu/libcrypto.so.3
rm -rf "$C"
mkdir -p "$C"/{file_api,pub_sub,framework,main,log,hash,helpers,utils,utils/stats,sfip,protocols,time,target_based,catch,parser,trace,profiler,memory,packet_io,control,mime,flowz,detection,flow}

# ---- VERBATIM sources compiled into the link ----
cp "$SRC"/src/file_api/{file_lib.h,file_lib.cc,file_api.h,file_api.cc,file_config.h,file_config.cc,file_identifier.h,file_identifier.cc,file_stats.h,file_stats.cc,file_service.h,file_capture.h,file_capture.cc,file_cache.h,file_cache.cc,file_flows.h,file_flows.cc,file_inspect.h,file_segment.h,file_segment.cc,file_module.h,file_mempool.h,file_mempool.cc,circular_buffer.h,circular_buffer.cc} "$C"/file_api/
cp "$SRC"/src/pub_sub/{file_events.h,file_events.cc,file_events_ids.h,intrinsic_event_ids.h} "$C"/pub_sub/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc,fnv.h,hashes.h,hashes.cc,xhash.h,xhash.cc,hash_lru_cache.h,hash_lru_cache.cc} "$C"/hash/
cp "$SRC"/src/helpers/{utf.h,utf.cc,event_gen.h,memcap_allocator.h,lockless_ring.h} "$C"/helpers/
cp "$SRC"/src/utils/{util.h,util.cc,util_cstring.h,util_cstring.cc,cpp_macros.h,bits.h,util_net.h,util_net.cc} "$C"/utils/
# real profiler TU pair (file_lib.cc includes profiler/profiler.h;
# upstream default build = no CPU/memory profiling flags -> Profile
# collapses to the no-op contexts; THREAD_LOCAL enabled defs ride in stubs).
cp "$SRC"/src/profiler/{profiler.h,profiler_defs.h,profiler.cc,time_profiler_defs.h,time_profiler.cc,memory_defs.h,memory_profiler_defs.h,rule_profiler_defs.h} "$C"/profiler/
cp "$SRC"/src/utils/stats/{snapshot.h,utils.h} "$C"/utils/stats/
cp "$SRC"/src/framework/{counts.h,base_api.h,ips_action.h,pdu_section.h,decode_data.h,inspector.h,parameter.h,value.h,module.h,mp_transport.h,data_bus.h,mp_data_bus.h,codec.h} "$C"/framework/
cp "$SRC"/src/flow/flow_key.h "$C"/flow/
# real inspector_manager.h is declaration-only (inspector.h + module.h
# closure); its method BODIES live in stubs.cc as witnesses.
mkdir -p "$C"/managers
cp "$SRC"/src/managers/inspector_manager.h "$C"/managers/
cp "$SRC"/src/main/{snort_types.h,thread.h,thread_config.h} "$C"/main/
cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_cidr.cc,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/protocols/{ip.h,ipv4.h,ipv6.h,layer.h,protocol_ids.h,mpls.h,packet.h,geneve.h,packet_manager.h} "$C"/protocols/
cp "$SRC"/src/time/{clock_defs.h,stopwatch.h,packet_time.h,packet_time.cc,timersub.h} "$C"/time/
cp "$SRC"/src/target_based/snort_protocols.h "$C"/target_based/
cp "$SRC"/src/parser/parse_utils.h "$C"/parser/
cp "$SRC"/src/memory/heap_interface.h "$C"/memory/
cp "$SRC"/src/log/{messages.h,log_errors.h,log_stats.h} "$C"/log/
cp "$SRC"/src/control/control.h "$C"/control/
cp "$SRC"/src/mime/file_mime_config.h "$C"/mime/
cp "$SRC"/src/packet_io/{active_action.h,active.h,packet_tracer.h,packet_constraints.h} "$C"/packet_io/
cp /opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp "$C"/catch/
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#include "catch/catch.hpp"
EOF
printf '#pragma once\n#define HAVE_ICONV 1\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h

# ---- main/policy.h graft (PROVEN rules/stx/fstats/filib recipe) ----
cp "$SRC"/src/main/policy.h "$C"/main/
python3 - "$C" <<'FIXPOLICY'
import sys
p = sys.argv[1] + "/main/policy.h"
s = open(p).read()
s = s.replace('#include "framework/data_bus.h"', '#include "framework/data_bus_wit.h"')
s = s.replace('#include "framework/mp_data_bus.h"', '')
blk = s.index("class PolicyMap")
end = s.index("};", blk)
seg = s[blk:end].replace("private:", "public:")
s = s[:blk] + seg + s[end:]
open(p, "w").write(s)
FIXPOLICY
# data_bus.h is REAL here (file_lib.cc publishes through it; publish BODIES
# live in stubs.cc). policy.h's include is swapped to the small witness the
# graft expects; SnortConfig only stores a DataBus member there.
cat > "$C"/framework/data_bus_wit.h <<'EOF'
#pragma once
#include "framework/data_bus.h"
namespace snort { class SnortConfig; }
EOF

# ---- snort_config.h: proven rules_harness shim + members the file_api
# headers/bodies name (max_files_cached etc from file_service.cc paths). ----
python3 - "$C" <<'EOFPY'
import sys, re
cdir = sys.argv[1]
build = open("/opt/data/snort3-rust/tools/rules_harness/build.sh").read()
m = re.search(r"cat > \"\$C\"/main/snort_config\.h <<'EOFCFG'\n(.*?)\nEOFCFG\n", build, re.S)
assert m, "EOFCFG block not found in rules_harness build.sh"
shim = m.group(1)
# real snort_config.h pulls target_based/snort_protocols.h in this closure
assert '#include "target_based/snort_protocols.h"' not in shim
anchor = shim.index("\n", shim.index("#include")) + 1
shim = shim[:anchor] + '#include "target_based/snort_protocols.h"\n' + shim[anchor:]
old = "    static bool log_syslog() { return false; }"
assert shim.count(old) == 1, "log_syslog anchor not unique"
new = ("    enum { LOGGING_FLAG__VERBOSE = 0x00000001 };\n"
       "    static bool log_verbose() { return logging_flags & LOGGING_FLAG__VERBOSE; }\n"
       "    uint64_t max_files_cached = 65536;  // real member (file_service.cc)\n"
       "    unsigned max_procs = 1;             // real member (file_service.cc)\n"
       "    bool mp_dbus = false;               // real member\n"
       + old)
shim = shim.replace(old, new, 1)
open(cdir + "/main/snort_config.h", "w").write(shim + "\n")
EOFPY

# ---- daq witness + packet.h surgery (PROVEN rules_harness recipe) ----
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
EOFDAQ
# flow/flow.h is the flow monolith. Grafted witness (PROVEN rules recipe,
# extended AGAIN for file_cache): make_key (file_cache.cc:363-372) reads
# Flow::client_ip/server_ip (real flow.h:523-524), client_group/server_group
# (flow.h:583-584) and key->addressSpaceId (flow_key.h:56 with REAL
# flow/flow_key.h now copied). PINNED truncation: uint32_t addressSpaceId
# -> uint16_t asid (file_cache.h:47) -- pin, never "fix".
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
sed -i 's|#include "flow/flow.h"|#include "flowz/flow_fwd.h"|' "$C"/protocols/packet.h

# ---- file_flows.h: same flow.h graft; FlowData comes from the real
# flow_data.h (copied); FileFlows bodies are the REAL TU now (witness block
# retired in stubs.cc). ----
cp "$SRC"/src/flow/flow_data.h "$C"/flowz/
sed -i 's|#include "flow/flow.h"|#include "flowz/flow_fwd.h"\n#include "flowz/flow_data.h"|' "$C"/file_api/file_flows.h

# ---- NEW17q graft delta (PLAN.md 3, the ONLY flowz delta): the witness
# Flow gains get_flow_data(unsigned)/set_flow_data(FlowData*) (real
# flow.h:195/:200; call sites file_flows.cc:141/:149/:159). Bodies live in
# stubs.cc as a PINNED single-slot arm (one probe Flow ever attached); get
# hits the slot iff id == stored fd->get_id() (FlowData::get_id is real
# inline), so the get_file_flows chain + get_file_processed_size witness
# work against real logic (documented deviation: real Flow keeps a vector).
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

# ---- main/thread_config.h graft: thread_config.h:22 pulls <hwloc.h>
# (absent on this host); file_cache.cc only uses ThreadConfig::
# get_instance_max() (file_cache.cc:144) -> include excised (documented),
# declarations kept, witness body in stubs.cc. HAVE_NUMA stays undefined
# so both HAVE_NUMA arms vanish inertly. ----
python3 - "$C" <<'FIXTC'
import sys
p = sys.argv[1] + "/main/thread_config.h"
s = open(p).read()
assert "#include <hwloc.h>" in s
s = s.replace("#include <hwloc.h>\n", "")
open(p, "w").write(s)
FIXTC

# ---- thread_config.h graft above. Also: utils/util.cc in this
# toolchain needs <sstream> explicitly (upstream toolchains get it
# transitively from <random>); include added, body untouched (documented).
python3 - "$C" <<'FIXUTIL'
import sys
p = sys.argv[1] + "/utils/util.cc"
s = open(p).read()
assert "#include <sstream>" not in s
s = s.replace("#include <random>", "#include <random>\n#include <sstream>", 1)
open(p, "w").write(s)
FIXUTIL

python3 - "$C" <<'FIXACC'
import sys
c = sys.argv[1]
# NEW17q: + file_api.h — FilePolicyBase::ref_count is read by the policy
# ref-count witness readout (fcache_stub_policy_refs); access-only, the
# arithmetic stays the REAL file_api.cc protocol.
for f in ("/file_api/file_service.h", "/file_api/file_cache.h", "/file_api/file_flows.h", "/file_api/file_api.h"):
    p = c + f
    s = open(p).read()
    n = s.count("private:")
    assert n >= 1, f
    s = s.replace("private:", "public:")  # access only; probe touches seams
    open(p, "w").write(s)
FIXACC
# NOTE (delta vs donor): the mp_data_bus.h include is NOT excised here.
# file_cache.cc:563-571 genuinely uses MPDataBus::get_id/publish when
# SnortConfig::mp_dbus is true -> real header kept, witness BODIES in
# stubs.cc (documented deviation).

# ---- detection engine witness header: file_cache.cc's uses are
# p->context->conf (file_cache.cc:669) + event_gen's queue_event +
# GET_CURRENT_PACKET. witness IpsContext shape: exactly the members the
# closure reads/writes. Bodies in stubs.cc. detection_buf.h REAL. ----
cp "$SRC"/src/detection/{detection_buf.h,fp_detect.h} "$C"/detection/
cat > "$C"/detection/detection_engine.h <<'EOFDE'
#pragma once
#include "detection/detection_buf.h"
#include "main/snort_types.h"
#include "target_based/snort_protocols.h"
namespace snort {
struct Packet;
class Flow;
class SnortConfig;
// witness IpsContext shape: exactly the members file_cache.cc/file_lib.cc
// read/write. `conf` is the real member (flow/ips_context) file_cache.cc:669
// reads. upstream snapshot_flow(Flow*) keeps the Flow* and copies proto_id
// through it -- witness keeps proto_id inline, semantics pinned by the
// probe (documented deviation).
class IpsContext {
public:
    DataPointer file_data = DataPointer(nullptr, 0);
    uint64_t file_data_id = 0;
    unsigned file_pos = 0;
    bool file_type_process = false;
    SnortConfig* conf = nullptr;   // real member read at file_cache.cc:669
    struct { SnortProtocolId proto_id = UNKNOWN_PROTOCOL_ID; } flow;
    uint32_t session_flags = 0;
    void set_snort_protocol_id(SnortProtocolId id) { flow.proto_id = id; }
    SnortProtocolId get_snort_protocol_id() { return flow.proto_id; }
    uint32_t get_session_flags() { return session_flags; }
};
class DetectionEngine {
public:
    DetectionEngine() { }
    static Packet* get_current_packet();
    static Packet* set_next_packet(const Packet* parent = nullptr, Flow* flow = nullptr);
    static int queue_event(unsigned gid, unsigned sid);
}; }
EOFDE

# ---- trace witness: real FILE_DEBUG semantics. file_module.h maps
# FILE_DEBUG(module,oid,level,p,...) -> trace_logf(level,module,oid,p,...)
# -> trace_printf(TraceLevel, const Trace*, TraceOptionID, const Packet*,
# fmt, ...) (real trace_api.h shape). The witness keeps the trace_enabled
# gate VERBATIM (null trace -> false; else level check; the packet-
# constraint arm of the real gate is dropped -> documented deviation).
# Enabled lines print with FILEDBG tag so format strings (PRIi64/%d ...)
# inside file_cache.cc pin verbatim. ----
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
cat > "$C"/trace/trace_api.h <<'EOFTR'
#pragma once
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include "main/snort_types.h"
#include "trace/trace.h"
namespace snort { struct Packet; }
static inline bool trace_enabled(const snort::Trace* trace,
    TraceOptionID trace_option_id,
    TraceLevel log_level = DEFAULT_TRACE_LOG_LEVEL,
    const snort::Packet* p = nullptr)
{
    if ( !trace or !trace->enabled(trace_option_id, log_level) )
        return false;
    return true;
}
static inline void trace_printf(TraceLevel log_level,
    const snort::Trace* trace, TraceOptionID trace_option_id,
    const snort::Packet* p, const char* fmt, ...)
{
    if ( !trace_enabled(trace, trace_option_id, log_level, p) )
        return;
    std::printf("FILEDBG[%s] ", trace->module_name());
    va_list ap;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
}
#define trace_logf(...) trace_printf(__VA_ARGS__)
EOFTR

if [ ! -e "$H/probe.cc" ]; then echo "probe.cc missing" >&2; exit 1; fi
if [ ! -e "$H/stubs.cc" ]; then echo "stubs.cc missing" >&2; exit 1; fi

GXX="g++ -std=c++17 -O0 -w -I$C -I$NODE_INC"
# probe TU list: file_flows.cc VERBATIM (built WITHOUT -DUNIT_TEST, so the
# TU's own [file_flows] block is inert) + the full donor closure unchanged
# (file_cache.cc / file_lib.cc stay REAL — retire rule).
objs=()
for f in file_api file_config file_identifier file_stats file_capture file_mempool circular_buffer file_segment file_events utf util_cstring util util_net hashes ghash hash_key_operations primetable xhash hash_lru_cache packet_time sf_ip sf_cidr; do
  d=file_api; case $f in utf) d=helpers;; util_cstring|util|util_net) d=utils;; hashes|ghash|hash_key_operations|primetable|xhash|hash_lru_cache) d=hash;; file_events) d=pub_sub;; packet_time) d=time;; sf_ip|sf_cidr) d=sfip;; esac
  $GXX -fsyntax-only -c "$C/$d/$f.cc" || { echo "SYNTAX FAIL $f"; exit 1; }
  $GXX -c "$C/$d/$f.cc" -o "$C/$d/$f.o"
  objs+=("$C/$d/$f.o")
done
$GXX -fsyntax-only -c "$C"/file_api/file_lib.cc || { echo "SYNTAX FAIL file_lib"; exit 1; }
$GXX -c "$C"/file_api/file_lib.cc -o "$C"/file_api/file_lib.o
$GXX -fsyntax-only -c "$C"/file_api/file_cache.cc || { echo "SYNTAX FAIL file_cache"; exit 1; }
$GXX -c "$C"/file_api/file_cache.cc -o "$C"/file_api/file_cache.o
$GXX -fsyntax-only -c "$C"/file_api/file_flows.cc || { echo "SYNTAX FAIL file_flows"; exit 1; }
$GXX -c "$C"/file_api/file_flows.cc -o "$C"/file_api/file_flows.o

$GXX -c "$H/stubs.cc" -o "$H/stubs.o"
$GXX -c "$H/probe.cc" -o "$H/probe.o"
g++ -std=c++17 -O0 -g -w "$H/probe.o" "$H/stubs.o" "$C"/file_api/file_flows.o "$C"/file_api/file_cache.o "$C"/file_api/file_lib.o "${objs[@]}" \
  "$LIBCRYPTO" -lpthread -o "$H/probe"
"$H/probe" > "$H/vectors.txt"

# ---- upstream Catch gate: the 8 [file_flows] cases from the TU itself ----
# Same link closure as the probe, pristine file_flows.o swapped for the
# -DUNIT_TEST copy (skill rule). The block ships its OWN scaffolding
# (FF_TEST_CONTEXT + FFTestAccessor via the friend hook file_flows.h:130).
cat > "$H/catch_main.cc" <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
$GXX -c "$H/catch_main.cc" -o "$H/catch_main.o"
$GXX -DUNIT_TEST -c "$C"/file_api/file_flows.cc -o "$C"/file_api/file_flows_ut.o
g++ -std=c++17 -O0 -g -w "$H/catch_main.o" "$C"/file_api/file_flows_ut.o "$C"/file_api/file_cache.o "$C"/file_api/file_lib.o "$H/stubs.o" "${objs[@]}" \
  "$LIBCRYPTO" -lpthread -o "$H/gate"
"$H/gate" > "$H/gate.txt" 2>&1 || { echo GATE_FAIL; cat "$H/gate.txt"; exit 1; }
tail -1 "$H/gate.txt"
echo "FFLOWS_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"
