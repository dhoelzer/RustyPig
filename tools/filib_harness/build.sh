#!/usr/bin/env bash
# Ground-truth harness for file_api/file_lib.{h,cc} (FileInfo + FileContext).
#  * gate: file_lib.cc compiled with -DUNIT_TEST -> the TU's OWN embedded
#    [file_info] suite (19 TEST_CASEs). Plain-catch shim (codec/jsnorm/fid
#    recipe: catch/snort_catch.h -> vendored catch.hpp).
#  * probe: file_lib.cc VERBATIM minus its #ifdef UNIT_TEST block; links a
#    wide VERBATIM closure (file_config/file_identifier/file_stats/
#    file_capture/file_mempool/circular_buffer/file_segment/file_api/
#    file_events/utf/hashes + real ghash closure from the fid recipe).
#  * openssl: node-headers -I + link /usr/lib/x86_64-linux-gnu/libcrypto.so.3
#    (NEXT.md recipe; real EVP sha256 chains pinned through
#    process_file_signature_sha256).
#  * witnesses (documented in KNOWN DEVIATIONS.md): file_cache.cc /
#    file_service.cc / file_flows.cc / file_inspect.cc bodies are the
#    cache/inspector/flow monoliths -> witness method definitions live in
#    stubs.cc against the REAL headers (same member signatures).
#    DetectionEngine/InspectorManager/PacketTracer/trace/DataBus publish
#    are witness headers + stub bodies. flow/flow.h + <daq_common.h> are
#    grafted out of the real packet.h (rules recipe).
#  * clock_gettime is interposed by a stub (same recipe as the textlog
#    time() stub) so duration/packet_time-derived vector lines are
#    deterministic; fake_now is probe-controlled via filib_set_fake_now.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
NODE_INC=$(ls -d /opt/hermes/tools/node-*-linux-x64/include/node | head -1)
LIBCRYPTO=/usr/lib/x86_64-linux-gnu/libcrypto.so.3
rm -rf "$C"
mkdir -p "$C"/{file_api,pub_sub,framework,main,log,hash,helpers,utils,utils/stats,sfip,protocols,time,target_based,catch,parser,trace,profiler,memory,packet_io,control,mime,flowz,detection}

# ---- VERBATIM sources compiled into the link ----
cp "$SRC"/src/file_api/{file_lib.h,file_lib.cc,file_api.h,file_api.cc,file_config.h,file_config.cc,file_identifier.h,file_identifier.cc,file_stats.h,file_stats.cc,file_service.h,file_capture.h,file_capture.cc,file_cache.h,file_flows.h,file_inspect.h,file_segment.h,file_segment.cc,file_module.h,file_mempool.h,file_mempool.cc,circular_buffer.h,circular_buffer.cc} "$C"/file_api/
cp "$SRC"/src/pub_sub/{file_events.h,file_events.cc,file_events_ids.h,intrinsic_event_ids.h} "$C"/pub_sub/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc,fnv.h,hashes.h,hashes.cc} "$C"/hash/
cp "$SRC"/src/helpers/{utf.h,utf.cc,event_gen.h} "$C"/helpers/
cp "$SRC"/src/utils/{util.h,util_cstring.h,cpp_macros.h,bits.h} "$C"/utils/
# real profiler TU pair (file_lib.cc includes profiler/profiler.h;
# upstream default build = no CPU/memory profiling flags -> Profile
# collapses to the no-op contexts; THREAD_LOCAL enabled defs ride here).
cp "$SRC"/src/profiler/{profiler.h,profiler_defs.h,profiler.cc,time_profiler_defs.h,time_profiler.cc,memory_defs.h,memory_profiler_defs.h,rule_profiler_defs.h} "$C"/profiler/
cp "$SRC"/src/utils/stats/{snapshot.h,utils.h} "$C"/utils/stats/
cp "$SRC"/src/framework/{counts.h,base_api.h,ips_action.h,pdu_section.h,decode_data.h,inspector.h,parameter.h,value.h,module.h,mp_transport.h,data_bus.h} "$C"/framework/
# real inspector_manager.h is declaration-only (inspector.h + module.h
# closure); its method BODIES live in stubs.cc as witnesses.
mkdir -p "$C"/managers
cp "$SRC"/src/managers/inspector_manager.h "$C"/managers/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/main/thread.h "$C"/main/
cp "$SRC"/src/sfip/{sf_ip.h,sf_cidr.h,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/protocols/{ip.h,ipv4.h,ipv6.h,layer.h,protocol_ids.h,mpls.h,packet.h,geneve.h} "$C"/protocols/
cp "$SRC"/src/time/{clock_defs.h,stopwatch.h,packet_time.h} "$C"/time/
cp "$SRC"/src/target_based/snort_protocols.h "$C"/target_based/
cp "$SRC"/src/parser/parse_utils.h "$C"/parser/
cp "$SRC"/src/memory/heap_interface.h "$C"/memory/
cp "$SRC"/src/log/{messages.h,log_errors.h,log_stats.h} "$C"/log/
cp "$SRC"/src/control/control.h "$C"/control/
cp "$SRC"/src/mime/file_mime_config.h "$C"/mime/
cp "$SRC"/src/packet_io/{active_action.h,packet_tracer.h,packet_constraints.h} "$C"/packet_io/
cp "$SRC"/src/packet_io/packet_constraints.h "$C"/packet_io/
cp /opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp "$C"/catch/
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#include "catch/catch.hpp"
EOF
printf '#pragma once\n#define HAVE_ICONV 1\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h

# ---- main/policy.h graft (PROVEN rules/stx/fstats recipe) ----
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
# extended) carries exactly the members packet.h inlines + file_lib.cc
# touch: flags.client_initiated, ssn_state.snort_protocol_id,
# FilteringState (flow.h:122), service (flow.h:533) and
# two_way_traffic() (flow.h:287) with the SSNFLAG_* values PINNED
# verbatim from flow.h:53/55/96.
cat > "$C"/flowz/flow_fwd.h <<'EOFFLOW'
#pragma once
#include <cstdint>
#include "protocols/layer.h"   // packet.h Layer* member (real chain: flow.h pulled it)
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
    bool two_way_traffic() const
    { return (session_flags & SSNFLAG_SEEN_BOTH) == SSNFLAG_SEEN_BOTH; }
};
}
struct FilteringState { uint64_t flow = 0; uint64_t pkt = 0; uint64_t session = 0; };
EOFFLOW
sed -i 's|#include "flow/flow.h"|#include "flowz/flow_fwd.h"|' "$C"/protocols/packet.h

# ---- file_flows.h: same flow.h graft; FlowData comes from the real
# flow_data.h (copied); FileFlows bodies are witnesses in stubs.cc. ----
cp "$SRC"/src/flow/flow_data.h "$C"/flowz/
sed -i 's|#include "flow/flow.h"|#include "flowz/flow_fwd.h"\n#include "flowz/flow_data.h"|' "$C"/file_api/file_flows.h

# ---- mp_data_bus.h drags the MP transport monolith; nothing in the
# file_lib closure uses MP symbols -> include excised from the two
# pub_sub headers (documented). ----
python3 - "$C" <<'FIXACC'
import sys
c = sys.argv[1]
for f in ("/file_api/file_service.h", "/file_api/file_cache.h", "/file_api/file_flows.h"):
    p = c + f
    s = open(p).read()
    n = s.count("private:")
    assert n >= 1, f
    s = s.replace("private:", "public:")  # access only; witness bodies manage state
    open(p, "w").write(s)
FIXACC
sed -i '/#include "framework\/mp_data_bus.h"/d' "$C"/pub_sub/file_events.h "$C"/pub_sub/file_events_ids.h

# ---- detection engine witness header: file_lib.cc's only uses are
# set_next_packet/get_current_packet/DetectionEngine() ctor + event_gen's
# queue_event; ips_context shape mirrors the exact members file_lib.cc
# touches (file_data/file_pos/file_type_process/set_snort_protocol_id
# writing flow.proto_id). Bodies in stubs.cc. detection_buf.h REAL. ----
cp "$SRC"/src/detection/{detection_buf.h,fp_detect.h} "$C"/detection/
cat > "$C"/detection/detection_engine.h <<'EOFDE'
#pragma once
#include "detection/detection_buf.h"
#include "main/snort_types.h"
#include "target_based/snort_protocols.h"
namespace snort {
struct Packet;
class Flow;
// witness IpsContext shape: exactly the members file_lib.cc reads/writes.
// `flow` is the snapshot target; upstream snapshot_flow(Flow*) keeps the
// Flow* and copies proto_id through it -- witness keeps proto_id inline,
// semantics pinned by the probe (documented deviation).
class IpsContext {
public:
    DataPointer file_data = DataPointer(nullptr, 0);
    uint64_t file_data_id = 0;
    unsigned file_pos = 0;
    bool file_type_process = false;
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
# constraint arm of the real gate is dropped -> documented deviation,
# file_lib's FILE_DEBUG sites never depend on constraints) and formats
# enabled lines to stdout with a FILEDBG tag so the format strings
# themselves (PRIu64/%d/%f expansions inside file_lib) pin verbatim. ----
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
    // DEFAULT_TRACE_OPTION_ID level (all file_lib call sites use it).
    uint8_t level = 0;
    std::string mod = "file_inspect";
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

# ---- profiler: real defs (no -D flags -> Profile == NoMemContext like
# the upstream default build); THREAD_LOCAL enabled pinned to false. ----

if [ ! -e "$H/probe.cc" ]; then echo "probe.cc missing" >&2; exit 1; fi
if [ ! -e "$H/stubs.cc" ]; then echo "stubs.cc missing" >&2; exit 1; fi

GXX="g++ -std=c++17 -O0 -w -I$C -I$NODE_INC"
# probe TU list: file_lib.cc VERBATIM (built WITHOUT -DUNIT_TEST, so the
# TU's own [file_info] block is inert -- jsnorm shape).
objs=()
for f in file_api file_config file_identifier file_stats file_capture file_mempool circular_buffer file_segment file_events utf hashes ghash hash_key_operations primetable; do
  d=file_api; case $f in utf) d=helpers;; hashes|ghash|hash_key_operations|primetable) d=hash;; file_events) d=pub_sub;; esac
  $GXX -fsyntax-only -c "$C/$d/$f.cc" || { echo "SYNTAX FAIL $f"; exit 1; }
  $GXX -c "$C/$d/$f.cc" -o "$C/$d/$f.o"
  objs+=("$C/$d/$f.o")
done
$GXX -fsyntax-only -c "$C"/file_api/file_lib.cc || { echo "SYNTAX FAIL file_lib"; exit 1; }
$GXX -c "$C"/file_api/file_lib.cc -o "$C"/file_api/file_lib.o

$GXX -c "$H/stubs.cc" -o "$H/stubs.o"
$GXX -c "$H/probe.cc" -o "$H/probe.o"
g++ -std=c++17 -O0 -g -w "$H/probe.o" "$H/stubs.o" "$C"/file_api/file_lib.o "${objs[@]}" \
  "$LIBCRYPTO" -lpthread -o "$H/probe"
"$H/probe" > "$H/vectors.txt"

# ---- upstream Catch gate: the 19 [file_info] cases from the TU itself ----
# Same link closure as the probe, pristine file_lib.o swapped for the
# -DUNIT_TEST copy (skill rule).
cat > "$H/catch_main.cc" <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
$GXX -c "$H/catch_main.cc" -o "$H/catch_main.o"
$GXX -DUNIT_TEST -c "$C"/file_api/file_lib.cc -o "$C"/file_api/file_lib_ut.o
g++ -std=c++17 -O0 -g -w "$H/catch_main.o" "$C"/file_api/file_lib_ut.o "$H/stubs.o" "${objs[@]}" \
  "$LIBCRYPTO" -lpthread -o "$H/gate"
"$H/gate" > "$H/gate.txt" 2>&1 || { echo GATE_FAIL; cat "$H/gate.txt"; exit 1; }
tail -1 "$H/gate.txt"
echo "FILIB_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"
