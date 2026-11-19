#!/usr/bin/env bash
# Ground-truth harness for the file-policy TU row,
# file_api/file_policy.{h,cc} (row 17x). Lifted from the PROVEN
# tools/finspect_harness donor (row 17w, freshest; 17p-17w lineage); the
# entire cp/objs/graft/shim/gate machinery is donor VERBATIM (retire rule)
# -- deltas marked NEW17x (fpolicy PLAN 1/2/5). DIR NAME PIN:
# fpolicy_harness per NEXT.md row 17x -- no reconciliation needed.
# The entire cp/objs/graft/shim/gate machinery is donor VERBATIM (retire
# rule; the row TU has 0 UNIT_TEST fragments and 0 TEST_CASEs at fe29cbe
# -> no grafts/seds fire on it, and FIXACC must NOT gain file_inspect.h:
# the header has no private:/protected:, the loop's `assert n >= 1` is
# R8 -- verify untouched). The cp delta is exactly ONE file: file_inspect.
# cc appended to the :54 braces + file_inspect appended to the :386 objs
# loop (PLAN 2). Closure facts (PLAN 1/2, measured): nm -u copy/file_api/
# file_inspect.o = 49 U entries by construction = 28 app + 21 plumbing;
# 20 app entries close against donor objs, 8 close against the NEW17w
# witness bodies in stubs.cc (DataBus::get_id, MPDataBus::
# register_event_helpers + subscribe, ConfigLogger log_flag + log_value x2
# overloads (long / unsigned long), FileIdModule::load_config +
# FileIdModule ctor -- the probe NEVER news a real FileIdModule via
# mod_ctor: never called, R3 leak-posture).
# RETIRED for the dup-symbol rule R5 (the real file_inspect.o DEFINES
# them): the FileInspect ctor/dtor/configure/show body block (donor
# stubs.cc:425-:436) + the get_file_adv_pub_id static/setter/getter block
# (:305-:309; the static is REAL cc:46 over the atomic now). The
# fcache_set_file_inspector toggle re-arms over a witness FileIdModule
# hand-off -- the REAL ctor dereferences fm at cc:50 (R1: never nullptr).
# The hand-off hands a HEAP-only FileConfig through the load_config steal
# (R2: the real ~FileInspect cc:55-:56 deletes config; NEVER
# &g_stub_file_config -> deleting static storage is UB). FileService::
# set_max_file_depth (donor stubs :469) is INSTRUMENTED (body replica of
# file_service.cc:227-:251 + g_max_file_depth readout), NOT retired.
#  * gate: UNCHANGED (gate delta ZERO by construction, PLAN 2). Zero new
#    TEST_CASEs -> 22 cases / 114 assertions stay byte-ident; tail must
#    read "All tests passed (114 assertions in 22 test cases)" AND
#    gate.txt md5 must match the fcapi donor gate md5
#    (4826fc2233044a2d5429413faf0ae1af). The gate never constructs a
#    FileInspect (toggle unarmed -> only IMGR acquire -> null lines).
# NEW17x row facts (PLAN 1/2, measured): file_policy.{h,cc} carry 0
# TEST_CASEs / 0 UNIT_TEST fragments at fe29cbe -> ZERO grafts fire, the
# cp delta is EXACTLY TWO FILES (file_policy.{h,cc} appended to the :63
# braces + file_policy appended to the objs loop -- plain VERBATIM
# compile). The row .o's residue = 59 U entries = 14 app + 45 plumbing;
# 9 app entries close against REAL .o's (file_lib/file_capture/file_api)
# and 3 against the RESIDENT stubs.cc Enable_* trio (:596-:598) -- NEW
# witness bodies: ZERO; witness retirements: ZERO (R5 measured: stubs.o
# carries only W/V StubFilePolicy symbols, zero T FilePolicy::/FileRule::
# defs to collide -- the landmine assert in the NEW17x pin block below).
# FIXACC gains "/file_api/file_policy.h" (n=1 private at h:82, assert-safe,
# R6): the probe reads the private table (file_rules/file_shas/
# verdict_delay/default_rule) + the match_* ladders -- access-only.
# R2 PIN: the donor enable_file_capture witness (stubs.cc:598) OMITS the
# real cascade (file_service.cc:200-:204 also enables signature). DECISION
# THIS ROW (PLAN 5 R2): REPLICATE the cascade witness-side (byte-semantics
# vs the real body; R5-safe, the real file_service.cc stays unlinked) --
# the V4_load_cap vector pins the member-vs-static drift it produces.
#  * gate: UNCHANGED (gate delta ZERO by construction, PLAN 2): 22 cases /
#    114 assertions stay byte-ident (tail + md5 4826fc22... re-asserted
#    below); file_policy.o rides the gate link inert-by-construction.
#  * probe: probe.cc = fresh 17x row probe (V1-V10 + V-ref arms over the
#    PLAN 3.3 ladder, heap-only DRAINED policies -- ~FilePolicyBase's live
#    assert(!ref_count) never fires); hygiene gate (no 0x[0-9a-f]{6,})
#    carried verbatim.
# (rows 17u/17v heritage, kept as context: this script descended from the
# fconf/fcapi harnesses; the file_config.o 30-U/6-app and file_api.o 3-U
# pin blocks below stay as link-invariant carry-overs.)
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
NODE_INC=$(ls -d /opt/hermes/tools/node-*-linux-x64/include/node | head -1)
LIBCRYPTO=/usr/lib/x86_64-linux-gnu/libcrypto.so.3
rm -rf "$C"
mkdir -p "$C"/{file_api,pub_sub,framework,main,log,hash,helpers,utils,utils/stats,sfip,protocols,time,target_based,catch,parser,trace,profiler,memory,packet_io,control,mime,flowz,detection,flow}

# ---- VERBATIM sources compiled into the link ----
# NEW17w: cp delta is exactly ONE file -- file_inspect.cc appended to this
# donor braced list (its .h was ALREADY cp'd here: fcapi build.sh:54,
# VERBATIM; stubs.cc includes it, stubs.cc:13). The row TU has 0 UNIT_TEST
# fragments and 0 TEST_CASEs (PLAN 2; hard-asserted below): no grafts/seds
# fire on it, it compiles byte-VERBATIM in the objs loop just below (also
# NEW17w: file_inspect appended to that loop -- no flowz/sed dir
# special-case needed). FIXACC below does NOT gain file_inspect.h: the
# header has NO private:/protected: and the loop's `assert n >= 1` would
# fire (R8 trap; NEXT.md:110's FIXACC parenthetical refers to the
# stubs.cc:13 include context only -- verified untouched this row).
cp "$SRC"/src/file_api/{file_lib.h,file_lib.cc,file_api.h,file_api.cc,file_config.h,file_config.cc,file_identifier.h,file_identifier.cc,file_stats.h,file_stats.cc,file_service.h,file_capture.h,file_capture.cc,file_cache.h,file_cache.cc,file_cache_share.h,file_cache_share.cc,file_flows.h,file_flows.cc,file_inspect.h,file_inspect.cc,file_segment.h,file_segment.cc,file_module.h,file_mempool.h,file_mempool.cc,circular_buffer.h,circular_buffer.cc,file_policy.h,file_policy.cc} "$C"/file_api/
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
# NEW17t: + pub_sub/file_events.h — the probe arms FileMPEvent's PRIVATE
# members (hashkey/file_ctx) for the S/D/H vectors; access-only, the
# codec walk (file_events.h:82-:127) stays byte-VERBATIM (PLAN 7 precedent).
# NEW17x: + file_api/file_policy.h — the probe READS the private table
# (file_rules/file_shas/verdict_delay/default_rule) and the match_*
# ladders for the V5/V6 readbacks; exactly ONE private: at h:82, 0
# protected: (assert n >= 1 safe, R6). Access-only: the cc bodies
# compile byte-VERBATIM, untouched by this loop's replace (no
# private:/protected: tokens in file_policy.cc).
for f in ("/file_api/file_service.h", "/file_api/file_cache.h", "/file_api/file_flows.h", "/file_api/file_api.h", "/file_api/file_lib.h", "/file_api/file_capture.h", "/pub_sub/file_events.h", "/file_api/file_policy.h"):
    p = c + f
    s = open(p).read()
    n = s.count("private:")
    assert n >= 1, f
    s = s.replace("private:", "public:")   # access only; probe touches seams
    s = s.replace("protected:", "public:") # NEW17r: FileInfo protected members
                                           # (file_name/url/file_type_id/...) are
                                           # read+armed by the P/M/L vectors
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
# probe TU list: the full donor closure + NEW17w file_inspect (the row TU,
# plain VERBATIM compile, no graft/sed/excision -- 0 UNIT_TEST fragments).
# file_capture.cc stays a REAL TU here -- the PLAIN .o is dropped from BOTH
# links below: the probe links the UT-compiled TEST_CASE-excised variant,
# the gate the verbatim -DUNIT_TEST copy; PLAN 6).
objs=()
for f in file_api file_config file_identifier file_stats file_capture file_cache_share file_mempool circular_buffer file_segment file_events utf util_cstring util util_net hashes ghash hash_key_operations primetable xhash hash_lru_cache packet_time sf_ip sf_cidr file_inspect file_policy; do
  d=file_api; case $f in utf) d=helpers;; util_cstring|util|util_net) d=utils;; hashes|ghash|hash_key_operations|primetable|xhash|hash_lru_cache) d=hash;; file_events) d=pub_sub;; packet_time) d=time;; sf_ip|sf_cidr) d=sfip;; esac
  $GXX -fsyntax-only -c "$C/$d/$f.cc" || { echo "SYNTAX FAIL $f"; exit 1; }
  $GXX -c "$C/$d/$f.cc" -o "$C/$d/$f.o"
  objs+=("$C/$d/$f.o")
done
# NEW17r carry: excise ONLY the :1363 [file_info] UNIT_TEST block (keep the
# early :37/:54 fragments: guarded via rfind on "#ifdef UNIT_TEST",
# brace-balance check the result). Both the probe AND the gate use this same
# copy, so the 19 [file_info] cases never leak into fcap gate.txt.
python3 - "$C" <<'FIXLIBUT'
import sys
p = sys.argv[1] + "/file_api/file_lib.cc"
s = open(p).read()
i = s.rfind("#ifdef UNIT_TEST")
assert i > 0 and s.count("#ifdef UNIT_TEST") >= 3, "expected the early fragments + the :1363 block"
tail = s[i:]
assert "[file_info]" in tail and "TEST_CASE" in tail, "last UNIT_TEST block is not [file_info]"
assert tail.count("#endif") == 1 and tail.rstrip().endswith("#endif")
s = s[:i]
assert s.count("{") - s.count("}") == 0, "brace imbalance after excision"
open(p, "w").write(s)
FIXLIBUT
$GXX -fsyntax-only -c "$C"/file_api/file_lib.cc || { echo "SYNTAX FAIL file_lib"; exit 1; }
$GXX -c "$C"/file_api/file_lib.cc -o "$C"/file_api/file_lib.o
$GXX -fsyntax-only -c "$C"/file_api/file_cache.cc || { echo "SYNTAX FAIL file_cache"; exit 1; }
$GXX -c "$C"/file_api/file_cache.cc -o "$C"/file_api/file_cache.o
$GXX -fsyntax-only -c "$C"/file_api/file_flows.cc || { echo "SYNTAX FAIL file_flows"; exit 1; }
$GXX -c "$C"/file_api/file_flows.cc -o "$C"/file_api/file_flows.o

# ---- NEW17s probe-copy excision (PLAN 4 recipe, DELTA vs FIXLIBUT): keep
# the file VERBATIM for the gate; the probe copy keeps ALL early
# #ifdef UNIT_TEST fragments (:45/:65/:100/:112/:197/:203) AND the UT
# scaffolding :620-:807 (hooks + gate + fixture), and excises ONLY the
# 4 TEST_CASE bodies :808-:912 via index("TEST_CASE ("). Guards: exactly 4
# "TEST_CASE (" in the tail, single tail #endif kept, 0 survive, brace +
# UNIT_TEST-arm balance, catch refs cannot leak (PLAN 9-5). ----
python3 - "$C" <<'FIXCAPUT'
import sys
c = sys.argv[1]
p = c + "/file_api/file_capture.cc"
s = open(p).read()
assert s.count("#ifdef UNIT_TEST") == 7, "fragments :45/:65/:100/:112/:197/:203 + block :620"
i = s.index("TEST_CASE (")
tail = s[i:]
assert tail.count("TEST_CASE (") == 4 and s.count("TEST_CASE (") == 4, "exactly 4 [file_capture] TEST_CASEs"
assert "[file_capture]" in tail and tail.count("[file_capture]") == 4
assert tail.count("#endif") == 1 and tail.rstrip().endswith("#endif"), "block #endif :913 must be the tail"
probe_src = s[:i] + "#endif\n"   # re-attach the :620 #ifdef's #endif
assert probe_src.count("TEST_CASE") == 0, "no TEST_CASE may survive in the probe copy"
assert probe_src.count("{") - probe_src.count("}") == 0, "brace imbalance after excision"
assert probe_src.count("#endif") == probe_src.count("#ifdef"), "#ifdef/#endif imbalance"
for frag in ("writer_test_hook", "writer_idle_test_hook", "flush_entry_test_hook", "flush_predicate_test_hook"):
    assert probe_src.count(frag) >= 2, frag + " fragment lost in the probe copy"

# ---- in-TU extern "C" driver: the 4 hook pointers (:65-:70) and the
# static gate ptr (:754) are FILE-LOCAL -- probe.cc cannot arm the ladder
# from outside. The driver mirrors AsyncCaptureFixture arms (:784-:788) and
# gate calls (:698-:740) verbatim through the SAME AsyncWriterGate
# (:663-:752) -- no custom barriers (PLAN 5). ----
driver = '''
// ---- build.sh-appended in-TU extern "C" driver (row 17s probe only) ----
static AsyncWriterGate* fcap_drv_gate = nullptr;
extern "C" void fcap_gate_arm_new(void)
{
    delete fcap_drv_gate;
    fcap_drv_gate = new AsyncWriterGate();
    async_writer_gate = fcap_drv_gate;
    writer_test_hook = wait_in_writer_test_hook;
    writer_idle_test_hook = wait_at_writer_idle_test_hook;
    flush_entry_test_hook = record_flush_entry_test_hook;
    flush_predicate_test_hook = record_flush_predicate_test_hook;
}
extern "C" void fcap_gate_unarm(void)
{
    writer_test_hook = nullptr;
    writer_idle_test_hook = nullptr;
    flush_entry_test_hook = nullptr;
    flush_predicate_test_hook = nullptr;
    delete fcap_drv_gate;
    fcap_drv_gate = nullptr;
    async_writer_gate = nullptr;
}
extern "C" void fcap_init(int64_t m, int64_t b) { FileCapture::init(m, b); }
extern "C" void fcap_exit(void) { FileCapture::exit(); }
extern "C" void fcap_test_reset(void) { FileCaptureTestAccess::reset(); }
extern "C" int fcap_resettable(void) { return FileCaptureTestAccess::resettable() ? 1 : 0; }
extern "C" void fcap_enqueue(void* c) { FileCaptureTestAccess::enqueue(static_cast<FileCapture*>(c)); }
extern "C" void fcap_enqueue2(void* a, void* b) { FileCaptureTestAccess::enqueue(static_cast<FileCapture*>(a), static_cast<FileCapture*>(b)); }
extern "C" uint64_t fcap_released_buffers(void) { return FileCaptureTestAccess::released_buffers(); }
extern "C" int fcap_queue_size(void)
{
    std::lock_guard<std::mutex> lk(FileCapture::capture_mutex);
    return (int)FileCapture::files_waiting.size();
}
extern "C" int fcap_file_storing_now(void)
{
    std::lock_guard<std::mutex> lk(FileCapture::capture_mutex);
    return FileCapture::file_storing ? 1 : 0;
}
// one writer_thread iteration VERBATIM (:83-:117) minus the hooks: the
// hookless-drain deviation vector (probe never arms hooks in this block).
extern "C" void fcap_drain_hookless(void)
{
    while (true)
    {
        std::unique_lock<std::mutex> lk(FileCapture::capture_mutex);
        if (FileCapture::files_waiting.empty())
            break;
        FileCapture* file = FileCapture::files_waiting.front();
        FileCapture::files_waiting.pop();
        FileCapture::file_storing = true;
        lk.unlock();
        file->store_file();
        delete file;
        lk.lock();
        FileCapture::file_storing = false;
        lk.unlock();
        FileCapture::capture_cv.notify_all();
    }
}
extern "C" void fcap_gate_wait_writer(void) { fcap_drv_gate->wait_for_writer(); }
extern "C" void fcap_gate_release_writer(void) { fcap_drv_gate->release_writer(); }
extern "C" void fcap_gate_wait_flush_callers(unsigned n) { fcap_drv_gate->wait_for_flush_callers(n); }
extern "C" void fcap_gate_pause_first_idle(void) { fcap_drv_gate->pause_first_idle_transition(); }
extern "C" void fcap_gate_wait_first_idle(void) { fcap_drv_gate->wait_for_first_idle_transition(); }
extern "C" void fcap_gate_wait_nonempty_idle_eval(void) { fcap_drv_gate->wait_for_nonempty_idle_evaluation(); }
extern "C" void fcap_gate_release_idle(void) { fcap_drv_gate->release_idle_transition(); }
'''
open(c + "/file_api/file_capture_probe.cc", "w").write(probe_src + driver)
FIXCAPUT
$GXX -DUNIT_TEST -fsyntax-only -c "$C"/file_api/file_capture_probe.cc || { echo "SYNTAX FAIL file_capture_probe"; exit 1; }
$GXX -DUNIT_TEST -c "$C"/file_api/file_capture_probe.cc -o "$C"/file_api/file_capture_probe.o
# nm -u residue (PLAN 6): expected witness delta ZERO apart from catch/std
# refs the unlinked scaffolding drags in; no NEW stubs ahead of this check.
diff <(nm -u "$C"/file_api/file_capture.o | sort -u) <(nm -u "$C"/file_api/file_capture_probe.o | sort -u) > "$H/nm_residue.txt" || true
# NEW17u PLAN 3 pin: the row TU's own residue -- file_config.o has exactly
# 30 U entries, of which exactly 6 app symbols (FileIdentifier::add_file_id/
# find_file_type_id/get_magic_rule_ids_from_type/get_rule_from_id -> REAL
# file_identifier.o; InspectorManager::get_file_inspector -> stubs.cc
# witness; SnortConfig::get_conf -> EOFCFG shim). The other 24 are
# libstdc++/libgcc plumbing (string dtors, _Unwind_Resume, __cxa_*,
# operator new/delete, strlen, __throw_*) -- PLAN 3 table, ZERO new stubs.
# NEW17u carry: the config row's residue table (30 U / 6 app) was a write to
# nm_config.txt -- the fcapi .gitignore block carries nm_api.txt INSTEAD
# (PLAN 5 hygiene), so the same 30-U / 6-app assertions run INLINE here with
# no artifact write; the row TU's own residue lands in nm_api.txt below.
fc_res="$(nm -u --demangle "$C"/file_api/file_config.o | sort -u)"
test "$(printf '%s\n' "$fc_res" | grep -c ' U ')" -eq 30
test "$(printf '%s\n' "$fc_res" | grep -cE 'U (FileIdentifier::(add_file_id|find_file_type_id|get_magic_rule_ids_from_type|get_rule_from_id)|snort::InspectorManager::get_file_inspector|snort::SnortConfig::get_conf)')" -eq 6

$GXX -c "$H/stubs.cc" -o "$H/stubs.o"

# ---- NEW17w PLAN 2 row-residue pins (land in nm_inspect.txt) ----
# (a) the row .o's OWN residue: exactly 49 U entries by construction
# (28 app + 21 libstdc++/libgcc plumbing -- scratch recon /opt/data/
# cache/scratch/row17w re-measured here for the copy-tree compile).
nm -u --demangle "$C"/file_api/file_inspect.o | grep ' U ' | sort -u > "$H"/nm_inspect.txt
test "$(wc -l < "$H"/nm_inspect.txt)" -eq 49
# (b) exactly 8 app entries close against the NEW17w witness bodies.
test "$(grep -cE 'U (snort::DataBus::get_id|snort::MPDataBus::register_event_helpers|snort::MPDataBus::subscribe|snort::ConfigLogger::log_flag|snort::ConfigLogger::log_value|FileIdModule::load_config|FileIdModule::FileIdModule)' "$H"/nm_inspect.txt)" -eq 8
# (c) comm-diff vs the WHOLE link-member defined set (MANGLED compare --
# demangled names carry spaces; mangled is exact 1:1): after the witness
# bodies land, exactly the 21 plumbing entries survive, ZERO app hits.
f_u="$(mktemp)"; f_d="$(mktemp)"
nm -u "$C"/file_api/file_inspect.o | awk '{print $2}' | sort -u > "$f_u"
{ for o in "${objs[@]}" "$H/stubs.o" "$C"/file_api/file_lib.o "$C"/file_api/file_cache.o "$C"/file_api/file_flows.o "$C"/file_api/file_capture_probe.o; do nm --defined-only "$o" | awk '$2!="U"{print $NF}'; done; } | sort -u > "$f_d"
test "$(comm -23 "$f_u" "$f_d" | wc -l)" -eq 21
test "$(comm -23 "$f_u" "$f_d" | grep -cE 'snort|FileI|FileC|serialize|6DataBus|ConfigLogger|FileIdModule' )" -eq 0
rm -f "$f_u" "$f_d"
# (d) DUP-SYMBOL verification (R5, the retire landmine): the five retired
# stub bodies must be defined EXACTLY ONCE in the whole link member set,
# in the REAL file_inspect.o only. This is the get_file_adv_pub_id seam
# consumer watch too: the copy's file_lib.cc:658 (publish seam) resolves
# against the real getter now, NEVER a stub shadow.
test "$(nm -C "$C"/file_api/file_inspect.o | grep -cE '^[0-9a-f]+ T (FileInspect::configure|FileInspect::show|get_file_adv_pub_id)')" -eq 3
nm -C "$C"/file_api/file_inspect.o | grep -cE '^[0-9a-f]+ T FileInspect::(~FileInspect|FileInspect)\(FileIdModule\*\)' > /dev/null   # real ctor+dtors present
test "$(nm "$C"/file_api/file_inspect.o | grep -c _Z19get_file_adv_pub_idv)" -eq 1                    # real T def, used by file_lib.o's U ref
test "$(nm "$C"/file_api/file_lib.o | grep -c 'U _Z19get_file_adv_pub_idv')" -eq 1                   # seam consumer still references it
test "$(nm -C "$H/stubs.o" | grep -cE '^[0-9a-f]+ T (FileInspect::configure\(snort::SnortConfig\*\)|FileInspect::show|get_file_adv_pub_id|FileInspect::~FileInspect|FileInspect::FileInspect)')" -eq 0   # zero stub survivors

# ---- NEW17x PLAN 2 row-residue pins (land in nm_policy.txt) ----
# (a) the row .o's OWN residue: exactly 59 U entries by construction
# (14 app + 45 libstdc++/libgcc plumbing -- scratch recon /opt/data/
# cache/scratch/row17x re-measured for the copy-tree compile).
nm -u --demangle "$C"/file_api/file_policy.o | grep ' U ' | sort -u > "$H"/nm_policy.txt
test "$(wc -l < "$H"/nm_policy.txt)" -eq 59
# (b) app-count: exactly 14 app U entries (7 FileInfo + 2 FileCapture +
# 3 FileService::enable (resident stubs.cc:596-:598) + base dtor D2 +
# base typeinfo -- the closure classification, PLAN 2 table).
test "$(grep -cE ' U (snort::FileInfo::|snort::FileService::enable|snort::FileCapture::|snort::FilePolicyBase::~FilePolicyBase|typeinfo for snort::FilePolicyBase)' "$H"/nm_policy.txt)" -eq 14
# (c) comm-diff vs the WHOLE link-member defined set (MANGLED compare):
# after the resident witnesses, exactly the 45 plumbing entries survive,
# ZERO app residue.
fp_u="$(mktemp)"; fp_d="$(mktemp)"
nm -u "$C"/file_api/file_policy.o | awk '{print $2}' | sort -u > "$fp_u"
{ for o in "${objs[@]}" "$H/stubs.o" "$C"/file_api/file_lib.o "$C"/file_api/file_cache.o "$C"/file_api/file_flows.o "$C"/file_api/file_capture_probe.o; do nm --defined-only "$o" | awk '$2!="U"{print $NF}'; done; } | sort -u > "$fp_d"
test "$(comm -23 "$fp_u" "$fp_d" | wc -l)" -eq 45
test "$(comm -23 "$fp_u" "$fp_d" | grep -cE 'snort|FileP|FileR|FileC|FileS')" -eq 0
rm -f "$fp_u" "$fp_d"
# (d) DUP-SYMBOL LANDMINE (R5 INVERSION, the zero-retirement guard): the
# real .o DEFINES the row symbols (>= 6 T defs over the ladder + the
# vtable V pinned in the row .o, Itanium key-function placement R4) and
# stubs.o defines ZERO of them -- no retirements this row and the
# landmine against re-adding FilePolicy/FileRule witness bodies ahead of
# the real .o stays armed for future rows.
test "$(nm -C "$C"/file_api/file_policy.o | grep -cE '^[0-9a-f]+ T (FilePolicy::(load|policy_check|type_lookup|signature_lookup|add_file_id)|FileRule::clear)')" -ge 6
test "$(nm "$C"/file_api/file_policy.o | grep -cE '_ZTV10FilePolicy$')" -eq 1
test "$(nm -C "$H/stubs.o" | grep -cE ' T (FilePolicy::|FileRule::)')" -eq 0

# ---- upstream Catch gate: FOUR UT TUs in one link (PLAN 1/2/6) -----------
# [file_capture] NEW (4 cases; assertions pinned from the RUNNER line, never
# grep) + the 17r trio carried verbatim: [file_flows] 8/22, [file_mempool]
# 3/27, [file_cache] 7/42. Duplicate-symbol rule: the plain .o of every
# UT-compiled TU (file_flows.o, file_mempool.o, file_cache.o, file_capture.o)
# is EXCLUDED from the gate objs list.
cat > "$H/catch_main.cc" <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
$GXX -c "$H/catch_main.cc" -o "$H/catch_main.o"
$GXX -DUNIT_TEST -c "$C"/file_api/file_flows.cc -o "$C"/file_api/file_flows_ut.o
$GXX -DUNIT_TEST -c "$C"/file_api/file_mempool.cc -o "$C"/file_api/file_mempool_ut.o
$GXX -DUNIT_TEST -c "$C"/file_api/file_cache.cc -o "$C"/file_api/file_cache_ut.o
$GXX -DUNIT_TEST -c "$C"/file_api/file_capture.cc -o "$C"/file_api/file_capture_ut.o
gate_objs=()
for o in "${objs[@]}"; do case "$o" in */file_flows.o|*/file_mempool.o|*/file_cache.o|*/file_capture.o) ;; *) gate_objs+=("$o");; esac; done
g++ -std=c++17 -O0 -g -w "$H/catch_main.o" "$C"/file_api/file_flows_ut.o "$C"/file_api/file_mempool_ut.o "$C"/file_api/file_cache_ut.o "$C"/file_api/file_capture_ut.o "$C"/file_api/file_lib.o "$H/stubs.o" "${gate_objs[@]}" \
  "$LIBCRYPTO" -lpthread -o "$H/gate"
"$H/gate" > "$H/gate.txt" 2>&1 || { echo GATE_FAIL; cat "$H/gate.txt"; exit 1; }
tail -1 "$H/gate.txt"
# case-name counts pinned from grep (assertions come from the RUNNER line):
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_flows.cc)" -ge 8
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_mempool.cc)" -eq 3
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_cache.cc)" -eq 7
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_capture.cc)" -eq 4
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_capture_probe.cc)" -eq 0
# NEW17u (PLAN 2/7): the row TU contributes ZERO cases -- file_config.cc is
# already UT-clean (0 TEST_CASE / 0 UNIT_TEST at fe29cbe, grep-verbatim no
# excision) and rides both links in VERBATIM form. The unified gate stays
# 22/114 byte-ident: hard-assert the tail AND recheck the donor gate md5.
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_config.cc)" -eq 0
# NEW17v (PLAN 5): the fcapi row TU is likewise UT-clean -- file_api.{h,cc}
# carry 0 TEST_CASE / 0 UNIT_TEST at fe29cbe (grep-verbatim, no excision),
# so the gate delta is ZERO BY CONSTRUCTION and the same donor pins carry.
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_api.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_api.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_api.h)" -eq 0
# NEW17w (PLAN 2 / PLAN 1): the finspect row TU is UT-clean as re-measured
# -- file_inspect.{h,cc} carry 0 TEST_CASE / 0 UNIT_TEST at fe29cbe (grep-
# verbatim, no excision): the 17v self-check pattern repeats for the row.
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_inspect.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_inspect.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_inspect.h)" -eq 0
# NEW17x (PLAN 1/2): the file_policy row TU is UT-clean as re-measured --
# file_policy.{h,cc} carry 0 TEST_CASE / 0 UNIT_TEST at fe29cbe (grep-
# verbatim, no excision/self-check pattern repeats for the row).
test "$(grep -c 'TEST_CASE' "$C"/file_api/file_policy.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_policy.cc)" -eq 0
test "$(grep -c 'UNIT_TEST' "$C"/file_api/file_policy.h)" -eq 0
# NEW17v PLAN 5: the row TU's own residue -- file_api.o has exactly 3 U
# entries, ALL libstdc++/libc plumbing (class_type_info vtable, sized
# operator delete, __assert_fail from the LIVE cc:32/cc:38 asserts), ZERO
# app residue -- the smallest residue of the queue. Nothing to stub.
nm -u --demangle "$C"/file_api/file_api.o | grep ' U ' | sort -u > "$H"/nm_api.txt
test "$(wc -l < "$H"/nm_api.txt)" -eq 3
test "$(nm -u --demangle "$C"/file_api/file_api.o | grep -cE 'U (vtable for __cxxabiv1::__class_type_info|operator delete\(void\*, unsigned long\)|__assert_fail)')" -eq 3
grep -q 'All tests passed (114 assertions in 22 test cases)' "$H/gate.txt"
md5sum "$H/gate.txt" | grep -q '^4826fc2233044a2d5429413faf0ae1af  '
# gate exposure unchanged (PLAN 2): 34x IMGR acquire -> null, ZERO
# FileInspect prints -- the gate never arms the toggle, the md5 pin above
# is the byte-ident invariant; these greps localize WHAT is identical.
test "$(grep -c 'IMGR acquire -> null' "$H/gate.txt")" -eq 34
test "$(grep -c 'FileInspect' "$H/gate.txt")" -eq 0

# ---- probe link (gate already GREEN above): plain file_capture.o EXCLUDED,
# UT-compiled TEST_CASE-excised copy in. NEW17t: file_cache_share.o rides
# in via ${objs[@]} for BOTH links -- PLAN 3 closure: zero new TUs/stubs.
$GXX -c "$H/probe.cc" -o "$H/probe.o"
pobjs=()
for o in "${objs[@]}"; do case "$o" in */file_capture.o) ;; *) pobjs+=("$o");; esac; done
g++ -std=c++17 -O0 -g -w "$H/probe.o" "$H/stubs.o" "$C"/file_api/file_capture_probe.o "$C"/file_api/file_flows.o "$C"/file_api/file_cache.o "$C"/file_api/file_lib.o "${pobjs[@]}" \
  "$LIBCRYPTO" -lpthread -o "$H/probe"
timeout 120 "$H/probe" > "$H/vectors.txt" || { echo PROBE_FAIL; cat "$H/vectors.txt"; exit 1; }
# hygiene gate (context rule): no pointer/0x values in vectors
! grep -E '0x[0-9a-f]{6,}' "$H/vectors.txt"
# R5 INVERSION consequence (fpolicy, PLAN 5): the probe NEVER resurrects a
# FilePolicy/FileRule WITNESS print -- every POLICY line below comes either
# from the donor stub bodies (VERBATIM formats, stubs.cc:357/:359/:361) or
# from the probe printing the REAL body results through those same formats.
# The gate never touches FilePolicy (gate.txt exposure stays 0, asserted).
test "$(grep -c 'POLICY' "$H/gate.txt")" -eq 0
test "$(grep -c 'FilePolicy' "$H/gate.txt")" -eq 0
echo "nm_residue lines: $(wc -l < "$H/nm_residue.txt")"
echo "nm_config U-entries: 30 (6 app closed by donor objs -- inline, PLAN 3)"
echo "nm_api U-entries: $(wc -l < "$H"/nm_api.txt) (3 plumbing, 0 app -- 17v carry)"
echo "nm_inspect U-entries: $(wc -l < "$H"/nm_inspect.txt) (49 by construction -- 17w carry)"
echo "nm_policy U-entries: $(wc -l < "$H"/nm_policy.txt) (59 by construction: 14 app + 45 plumbing; 11 close on REAL .o's + 3 on resident stubs; 0 new witnesses, 0 retirements -- PLAN 2)"
echo "vectors md5: $(md5sum "$H"/vectors.txt)"
echo "gate md5: $(md5sum "$H"/gate.txt)"
echo "FPOLICY_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"
