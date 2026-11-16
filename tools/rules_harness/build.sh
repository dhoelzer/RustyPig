#!/usr/bin/env bash
# Ground-truth harness for the rule-tree core (plan row 17 keystone):
#   detection/rules.{h,cc}       RuleStateMap (upstream Catch gate: 2 cases)
#   detection/sfrim.{h,cc}       rule index map (upstream Catch gate: 1 case)
#   parse_rule.cc (FULL)         action/proto/nets/ports/dir, open/close,
#                                same_headers, mergeDuplicateOtn, process_rtn,
#                                counters, escape/opt accounting (gate: 5 cases)
#   parser.cc (RTN lifecycle)    addRtnToOtn/deleteRtnFromOtn/find_rtn/
#                                reduce_rtns/CreateRuleType/parser_init/term,
#                                RuleTreeCache+KeyOps, Free/DestroyRuleTreeNode
#   detection/{treenodes,signature} RTN/OTN structs, OtnLookup{,Add,Remove}
# Compiled VERBATIM (real semantics, real bodies where reachable):
#   parse_conf.cc config_file.cc (location stack, ParseIpVar, get_rule_list,
#   add_service_to_otn, parse_rules_string), fp_utils.cc statics (buffer_map,
#   guess_service, validate_services), log_stats.cc (LogLabel/LogCount ->
#   real LogfRespond->LogMessage path), util.cc (snort_strdup/strndup,
#   get_random_seed never-used), thread.cc (instance thread_type MAIN),
#   sfip, ports, sflsq, util_cstring, hash(ghash/xhash/lru/primetable),
#   vars+var_dependency, parse_ports, parse_so_rule, messages, protocols,
#   snort_bounds, json_stream, ips_option.cc (IpsOption core). Shimmed
#   (documented deviations):
#   main/snort_config.h  -> member subset (exactly what the TUs touch);
#   ActionManager        -> probe-ordered registration witness (numbering is
#                           plugin-init-order dependent upstream; order pinned);
#   ips_options meta     -> probe rules carry options ONLY through the
#                           IpsManager::option_* witness (name-only; probe
#                           registers opt names in opt_begin; no real option
#                           objects); flowbits witnesses abort if reached;
#   rtn_checks + FP funcs-> link stubs (packet-path only, never called);
#   ParseRules*/config monolith funcs in parser.cc: cut (documented).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{trace,search_engines,main,parser,ports,utils,hash,protocols,log,sfip,framework,detection,target_based,time,managers,catch,filterz,control,ips_options,helpers,packet_io,filters,profiler}

cp "$SRC"/src/main/{snort_types.h,thread.h,thread.cc} "$C"/main/
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

cp "$SRC"/src/parser/{vars.h,vars.cc,var_dependency.h,var_dependency.cc,parse_ports.h,parse_ports.cc,parse_rule.h,parse_so_rule.h,parse_so_rule.cc,config_file.h,config_file.cc,parse_conf.h,parse_conf.cc,parse_stream.h,parse_stream.cc} "$C"/parser/
cp "$SRC"/src/ports/{port_object.h,port_object.cc,port_object2.h,port_object2.cc,port_item.h,port_item.cc,port_utils.h,port_utils.cc,port_var_table.h,port_var_table.cc,port_table.h,port_table.cc,rule_port_tables.h,rule_port_tables.cc,port_group.h,port_group.cc} "$C"/ports/

cp "$SRC"/src/utils/{sflsq.h,sflsq.cc,util.h,util.cc,util_cstring.h,util_cstring.cc,bits.h,cpp_macros.h,util_net.h,util_net.cc,snort_bounds.h} "$C"/utils/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc,xhash.h,xhash.cc,hash_lru_cache.h,hash_lru_cache.cc,fnv.h,hashes.h,hashes.cc} "$C"/hash/
python3 - "$C" <<'FIXH'
import sys
p = sys.argv[1] + '/hash/hashes.cc'
s = open(p).read()
cut = s.index('#include <openssl/evp.h>')
NL = chr(10)
stub = s[:cut] + '#include <cstdlib>' + NL + 'namespace snort {' + NL
stub += 'void sha256(const unsigned char*, size_t, unsigned char*) { __builtin_abort(); }' + NL
stub += 'void sha512(const unsigned char*, size_t, unsigned char*) { __builtin_abort(); }' + NL + '}' + NL
open(p, 'w').write(stub)
FIXH

cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_cidr.cc,sf_ipvar.h,sf_ipvar.cc,sf_vartable.h,sf_vartable.cc,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/log/{messages.h,messages.cc,log_errors.h,log_stats.h,log_stats.cc,log.h,text_log.h,text_log.cc} "$C"/log/
sed -i 's|#include <atomic>|#include <atomic>\n#include <sstream>|' "$C"/log/messages.cc
sed -i 's|#include "log/messages.h"|#include <sstream>\n#include "log/messages.h"|' "$C"/parser/vars.cc
sed -i 's|#include <memory>|#include <cassert>\n#include <memory>|' "$C"/ports/port_table.cc
sed -i '1i #include <sstream>' "$C"/parser/parse_conf.cc
sed -i '1i #include <climits>\n#include <csignal>\n#include <cassert>\n#include <sstream>\n#include <limits.h>' "$C"/utils/util.cc
sed -i 's/defined(HAVE_GNU_STRERROR_R)/1/' "$C"/utils/util.cc  # force GNU strerror_r branch (glibc text)

cp "$SRC"/src/target_based/{snort_protocols.h,snort_protocols.cc} "$C"/target_based/
sed -i 's|#include "protocols/packet.h"||' "$C"/target_based/snort_protocols.cc
# parse_ports.cc keeps its packet.h include: witness header supplies snort::MAX_PORTS

cp "$SRC"/src/detection/{rules.h,rules.cc,treenodes.h,treenodes.cc,sfrim.h,sfrim.cc,signature.h,signature.cc,rule_option_types.h,fp_config.h,detection_buf.h,fp_utils.h,fp_utils.cc} "$C"/detection/
cp "$SRC"/src/framework/{ips_action.h,ips_option.cc,cursor.h,pdu_section.h,counts.h,base_api.h,ips_option.h,decode_data.h,mpse.h,mpse_batch.h} "$C"/framework/
cp "$SRC"/src/protocols/{ip.h,ipv4.h,ipv6.h,layer.h,protocol_ids.h,mpls.h} "$C"/protocols/
cp "$SRC"/src/framework/inspector.h "$C"/framework/
cp "$SRC"/src/catch/{catch.hpp,snort_catch.h} "$C"/catch/
cp "$SRC"/src/packet_io/active_action.h "$C"/packet_io/
cp "$SRC"/src/framework/so_rule.h "$C"/framework/
cp "$SRC"/src/parser/parser.cc "$C"/parser/parser.cc
cp "$SRC"/src/parser/parse_rule.cc "$C"/parser/parse_rule.cc
cp "$SRC"/src/helpers/{json_stream.h,json_stream.cc,memcap_allocator.h} "$C"/helpers/
cp "$SRC"/src/search_engines/search_common.h "$C"/search_engines/
cp "$SRC"/src/detection/pattern_match_data.h "$C"/detection/
cp "$SRC"/src/time/{clock_defs.h,tsc_clock.h,tsc_clock.cc} "$C"/time/

cat > "$C"/framework/data_bus_wit.h <<'EOF'
#pragma once
// witness: real framework/data_bus.h drags control/mp/lockless-ring
// monoliths; policy.h only embeds snort::DataBus members (used solely by
// policy.cc bodies, not header-inline code) -> empty minimal shape.
namespace snort { class SnortConfig; class DataBus { public: unsigned subscription_count() const { return 0; } }; }
EOF
printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
printf '#pragma once\n' > "$C"/time/packet_time.h
cat > "$C"/main/analyzer.h <<'EOF'
#pragma once
// witness: real main/analyzer.h drags the runtime monolith; config_file.cc
// calls Analyzer::set_main_hook once during config_conf (behavior invisible
// to every vector; probe never calls config_conf).
namespace snort { class Analyzer { public: static void set_main_hook(void (*)(void*)) { } }; }
EOF
printf '#pragma once\nnamespace snort {\nclass DetectionEngine { public: static void inspect(void*) { } };\n}\n' > "$C"/detection/detection_engine.h
cat > "$C"/main/thread_config.h <<'EOF'
#pragma once
#include <map>
#include <string>
namespace snort { class ThreadConfig {
public:
    static unsigned get_instance_max();
    static int get_instance_tid(int) { return 4242; }
}; }
EOF
cat > "$C"/main/snort.h <<'EOF'
#pragma once
namespace Snort { unsigned get_process_id(); }
EOF
cat > "$C"/control/control.h <<'EOF'
#pragma once
// witness header: real control/control.h drags the control monolith.
// log_stats.cc reaches LogfRespond -> cn==nullptr branch (snort::LogMessage)
// verbatim; set_log_conn is never called so s_ctrlcon stays null.
#include <cstdarg>
#include "log/messages.h"
class ControlConn;
#define LogRespond(cn, ...) \
    do { if (cn) __builtin_abort(); else snort::LogMessage(__VA_ARGS__); } while(0)
#define LogfRespond(cn, fh, ...) \
    do { if (cn) __builtin_abort(); else snort::LogMessage(fh, __VA_ARGS__); } while(0)
EOF
cat > "$C"/managers/inspector_manager.h <<'EOF'
#pragma once
#include <vector>
namespace snort {
#include "framework/base_api.h"
struct InspectApi {
    // real InspectApi fields used by signature.cc (framework/inspector.h);
    // harness get_apis() returns empty so values never read.
    static_assert(sizeof(BaseApi) > 0, "");
    BaseApi base;
    unsigned type;
    uint32_t proto_bits;
    const char** buffers;
    const char* service;
};
class InspectorManager {
public:
    // witness: real impl returns instantiated inspect plugin APIs;
    // harness has no plugins -> empty vector (OtnAdd meta path no-ops).
    static std::vector<const InspectApi*> get_apis() { return {}; }
    static bool get_ips_policy(const char*, IpsPolicy*&) { return false; }
}; }
EOF
cat > "$C"/log/batched_logger.h <<'EOF'
#pragma once
// witness: harness never enables log_batched; messages.cc branch aborts.
#include <cstdarg>
namespace snort { namespace BatchedLogger { namespace BatchedLogManager {
inline void log(void*, unsigned, const char*, va_list) { __builtin_abort(); }
} } }
EOF
cat > "$C"/protocols/packet.h <<'EOFPKT'
#pragma once
#include <cstdint>
// witness: real protocols/packet.h drags the DAQ/dataplane monolith.
// Harness TUs need only the Packet fwd + snort::MAX_PORTS (real line 119)
// + the inlines that detection/fp_utils.cc statics assert on.
namespace snort { class Packet; constexpr int32_t MAX_PORTS = 65536; }
struct Packet;
EOFPKT
cat > "$C"/trace/trace_api.h <<'EOFT'
#pragma once
// witness: real trace/trace_api.h drags TraceConfig/trace monolith.
// port_table.cc includes it but uses no trace symbols in the paths that
// matter to us -> empty header (documented deviation).
EOFT
cat > "$C"/detection/detection_options.h <<'EOFDO'
#pragma once
// witness: real detection_options.h is the option-tree monolith.
// port_group.cc only calls free_detection_option_root (void* nfp_tree in
// port_group.h); body VERBATIM from ORIGINAL detection_options.cc into a
// witness .cc (its root struct is private -> the exact dtor never runs in
// the harness; snort_free + null-out semantics are what the vector pins).
struct DetectionOptionTree;
void free_detection_option_root(void**);
EOFDO
cp "$SRC"/src/filters/sfthd.h "$C"/filterz/sfthd.h
cat > "$C"/profiler/profiler.h <<'EOF'
#pragma once
// witness: real profiler/profiler.h drags the profiling monolith;
// filters/detection_filter.h references profiler symbols we don't need.
EOF
cat > "$C"/filterz/detection_filter.h <<'EOF'
#pragma once
// witness decls matching real filters/detection_filter.h (the real header
// drags profiler + filter internals). framework/ips_option.cc
// set_detection_filter (VERBATIM) calls detection_filter_create; the probe
// never supplies one -> the link witness aborts if reached. THDX_STRUCT
// comes with real sfthd.h copied above.
#include "filterz/sfthd.h"
struct DetectionFilterConfig;
struct THD_NODE* detection_filter_create(DetectionFilterConfig*, struct THDX_STRUCT*);
void detection_filter_free(THD_NODE*);
EOF

# filters/ include-spelling alias (same witness headers, real path form).
mkdir -p "$C"/filters "$C"/profiler
sed 's|filterz/sfthd.h|filters/sfthd.h|' "$C"/filterz/detection_filter.h > "$C"/filters/detection_filter.h
cp "$SRC"/src/filters/sfthd.h "$C"/filters/sfthd.h
cat > "$C"/ips_options/ips_flowbits.h <<'EOF'
#pragma once
#include <ostream>
#include <string>
#include <vector>
// witness decls matching real ips_options/ips_flowbits.h; bodies abort in
// stubs.cc (probe rules carry no flowbits options).
struct FlowBitKey;
bool flowbits_setter(void*);
void get_flowbits_dependencies(void*, bool& set, std::vector<std::string>& bits);
void flowbits_counts(unsigned& total, unsigned& unchecked, unsigned& unset);
void flowbits_print_deps(std::ostream&);
EOF
cat > "$C"/managers/ips_manager.h <<'EOFMGR'
#pragma once
#include "detection/treenodes.h"
#include "framework/ips_option.h"
#include "target_based/snort_protocols.h"
#include <cstdint>
class IpsManager {
public:
    static bool option_begin(snort::SnortConfig*, const char*, SnortProtocolId, uint64_t);
    static bool option_set(snort::SnortConfig*, const char*, const char*, const char*);
    static snort::IpsOption* option_end(snort::SnortConfig*, OptTreeNode*, SnortProtocolId, const char*, snort::RuleOptType&);
    static const char* get_option_keyword();
};
EOFMGR
cat > "$C"/managers/module_manager.h <<'EOF'
#pragma once
#include <cstdint>
namespace snort { class ModuleManager { public: static bool gid_in_use(uint32_t); }; }
EOF
cat > "$C"/managers/event_manager.h <<'EOF'
#pragma once
// witness: real managers/event_manager.h drags the event/output monolith.
// parser.cc FreeOutputLists (kept verbatim) calls release_outputs; the
// harness never frees output lists (probe never registers outputs) -> abort
// witness pins unreachability.
namespace snort { class EventManager { public: static void release_outputs(void*) { __builtin_abort(); } }; }
EOF
cat > "$C"/managers/so_manager.h <<'EOF'
#pragma once
#include "framework/so_rule.h"
// witness: real managers/so_manager.h drags PluginManager; shapes mirror
// the real decls (get_so_rule/get_so_eval); bodies abort/return null in
// stubs.cc (probe has no so rules).
class SoManager
{
public:
    static const char* get_so_rule(const char* soid);
    static SoEvalFunc get_so_eval(const char* soid, const char* so, void** data);
};
EOF
cat > "$C"/parser/cmd_line.h <<'EOF'
#pragma once
void show_pcre_counts();
EOF
cat > "$C"/detection/extract.h <<'EOF'
#pragma once
// witness header: real extract.h drags protocols/packet.h (flow monolith);
// parse_rule.cc only needs ClearIpsOptionsVars (verbatim body in stubs.cc).
void ClearIpsOptionsVars();
EOF
cat > "$C"/detection/rtn_checks.h <<'EOF'
#pragma once
#include "framework/ips_option.h"
#include "main/snort_types.h"
struct RuleFpList;
struct RuleTreeNode;
namespace snort { struct Packet; }
int RuleListEnd(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckBidirectional(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckProto(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
EOF
cp "$SRC"/src/detection/service_map.h "$C"/detection/
cp "$SRC"/src/detection/fp_config.cc "$C"/detection/fp_config_copy.cc
cat > "$C"/managers/mpse_manager.h <<'EOF'
#pragma once
// witness: real managers/mpse_manager.h drags the MPSE plugin monolith.
// detection/fp_config_copy.cc ctor body is replaced (no plugins); no other
// MpseManager symbol is referenced by TUs compiled here.
namespace snort { class MpseManager { public: static const struct MpseApi* get_search_api(const char*) { return nullptr; } }; }
EOF
python3 - "$C" <<'FIXFPC'
import sys
p = sys.argv[1] + "/detection/fp_config_copy.cc"
s = open(p).read()
# ctor body (get_search_api("ac_bnfa")) + every member touching MpseManager /
# mpse creation: only the ctor + get_default_search_api-side init runs when
# we construct one; replace ONLY the ctor body (keep flag members verbatim).
i = s.index("FastPatternConfig::FastPatternConfig()")
lb = s.index("{", i); d = 0; e = lb
while True:
    if s[e] == "{": d += 1
    elif s[e] == "}":
        d -= 1
        if d == 0: break
    e += 1
s = s[:lb+1] + NL if False else s
s = s[:lb] + "{\n    // MpseManager::get_search_api(\"ac_bnfa\") witness (no MPSE\n    // plugins in harness; search_api never read: debug-print flags\n    // default 0, pattern compile paths never reached).\n}" + s[e+1:]
open(p, "w").write(s)
FIXFPC
cp "$SRC"/src/framework/ips_info.h "$C"/framework/

# ---- snort_config.h shim: exactly the members the big TUs touch ----
cat > "$C"/main/snort_config.h <<'EOFCFG'
#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "main/snort_types.h"
#include "main/policy.h"
// upstream declares the rule/linked-list types at GLOBAL scope
// (detection/rules.h, main/snort_config.h fwd decls); mirror exactly.
class RuleStateMap;
struct RuleListNode;
struct RulePortTables;   // global per upstream snort_config.h fwd decl
struct ListHead;
struct ReferenceSystem;
struct ReferenceNode;
struct ClassType;
struct PortObject;
struct sfip_var_t;
class FastPatternConfig;   // global per upstream (fp_config.h is global)
struct srmm_table_t;       // global per upstream (defined in service_map.h)
struct DetectionFilterConfig;  // global per upstream (filters/detection_filter.h)
namespace snort
{
class GHash;
class XHash;
struct ProtocolReference;
class SnortConfig {
public:
    SnortConfig() = default;
    bool global_rule_state = false;
    int num_rule_types = 0;
    bool global_default_rule_state = true;
    bool dump_rule_meta_flag = false;
    bool dump_rule_info_flag = false;
    bool allow_missing_so_rules = false;
    bool alert_refs_flag = true;
    bool enable_strict_reduction = false;
    unsigned run_flags = 0;
    int* evalOrder = nullptr;  // real member; OrderRuleLists target (never called by probe)
    std::string metadata_filter;
    std::string rule_order;
    std::string include_path;
    GHash* otn_map = nullptr;
    ::RuleListNode* rule_lists = nullptr;
    XHash* rtn_hash_table = nullptr;
    ::PolicyMap* policy_map = nullptr;
    ::RuleStateMap* rule_states = nullptr;
    ProtocolReference* proto_ref = nullptr;
    ::RulePortTables* port_tables = nullptr;
    ::FastPatternConfig* fast_pattern_config = nullptr;
    ::DetectionFilterConfig* detection_filter_config = nullptr;  // real member
    ::srmm_table_t* spgmmTable = nullptr;  // real member (fp_utils port_io; never called)
    unsigned num_slots = 0;  // real member (compile_mpses; never called)
    std::unordered_map<std::string, ::ReferenceSystem*> references;
    std::unordered_map<std::string, ::ClassType*> classifications;
    std::unordered_map<std::string, std::vector<std::string>> service_extension;
    std::unordered_map<std::string, PortObject*> port_map;
    std::unordered_map<std::string, sfip_var_t*> network_map;
    std::vector<std::string> protocol_names;
    bool dump_rule_meta() const { return dump_rule_meta_flag; }
    bool dump_rule_info() const { return dump_rule_info_flag; }
    bool dump_rule_state() const { return false; }
    bool alert_refs() const { return alert_refs_flag; }
    bool show_file_codes() const { return false; }
    int thiszone = 0;
    std::string log_dir;
    std::string run_prefix;
    uint16_t id_offset = 0;
    bool id_subdir = false;
    bool id_zero = false;
    bool create_inst_file() const { return false; }
    bool output_use_utc() const { return false; }
    bool output_include_year() const { return false; }
    bool get_default_rule_state() const;
    bool use_log_buffered() const { return false; }
    static bool log_syslog() { return false; }
    static bool log_quiet() { return false; }
    static bool static_hash() { return true; }
    int get_reference_id(const std::string&) const { return -1; }
    int get_classification_id(const char*) const { return -1; }
    SO_PUBLIC static SnortConfig* get_conf();
    SO_PUBLIC static SnortConfig* get_main_conf();
    SO_PUBLIC static const char* get_static_name(const char* name);
    static void cleanup_fatal_error();
    static uint32_t warning_flags;
    static uint32_t logging_flags;
    static uint32_t output_flags;
    static bool log_quiet_bypassed;
protected:
    static std::unordered_map<std::string, std::string> static_names;
    static std::mutex static_names_mutex;
};
} // namespace snort
EOFCFG

# ---- REAL parser/parse_conf.h (no shim): needs only string + rules.h ----
# ---- parser.h shim (getRtnFromOtn inline + lifecycle decls) ----
cat > "$C"/parser/parser.h <<'EOF'
#pragma once
#include <string>
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "main/policy.h"
int addRtnToOtn(snort::SnortConfig*, OptTreeNode*, RuleTreeNode*);
int addRtnToOtn(snort::SnortConfig*, OptTreeNode*, RuleTreeNode*, PolicyId);
void set_strict_rtn_reduction(bool);
bool same_headers(const RuleTreeNode*, const RuleTreeNode*);
RuleTreeNode* deleteRtnFromOtn(OptTreeNode*, snort::SnortConfig* sc = nullptr);
RuleTreeNode* deleteRtnFromOtn(OptTreeNode*, PolicyId, snort::SnortConfig* sc = nullptr, bool remove = true);
inline RuleTreeNode* getRtnFromOtn(const OptTreeNode* otn, PolicyId policyId)
{
    if (otn && otn->proto_nodes && (otn->proto_node_num > (unsigned)policyId))
        return otn->proto_nodes[policyId];
    return nullptr;
}
inline RuleTreeNode* getRtnFromOtn(const OptTreeNode* otn)
{
    return getRtnFromOtn(otn, snort::get_ips_policy()->policy_id);
}
RuleListNode* CreateRuleType(snort::SnortConfig*, const char*, snort::IpsAction::Type);
void FreeRuleTreeNode(RuleTreeNode*);
void DestroyRuleTreeNode(RuleTreeNode*);
int parser_get_rule_index(unsigned gid, unsigned sid);
void parser_get_rule_ids(int index, unsigned& gid, unsigned& sid);
void rule_index_map_print_index(int index, char* buf, int);
void parser_init();
void parser_term(snort::SnortConfig*);
void parser_append_rules(const char*);
void parser_append_rules_special(const char*, const char*);
const char* parser_get_special_includer();
void get_parse_location(const char*& name, unsigned& line);
void push_parse_location(
    const char* code, const char* path, const char* name = nullptr, unsigned line = 1);
void pop_parse_location();
void inc_parse_position();
struct RuleTreeNodeKey
{
    RuleTreeNode* rtn;
    PolicyId policyId;
};
EOF

# ---------------- surgery: parser.cc (keep the WHOLE statics block, 70-881,
# then excise only never-called monolith funcs; slice END anchor is past
# parser_get_rule_index so the RTN-lifecycle region survives) -----------
python3 - "$H" <<'PY'
import sys
p = sys.argv[1] + "/copy/parser/parser.cc"
s = open(p).read()
start = s.index("static struct rule_index_map_t* ruleIndexMap")
end_anchor = "const char* parser_get_special_includer()"
e = s.index(end_anchor)
e = s.index("}", s.index("{", e)) + 1
body = s[start:e]
def cut(body, sig):
    i = body.index(sig)
    lb = body.index("{", i); d = 0; ex = lb
    while True:
        if body[ex] == "{": d += 1
        elif body[ex] == "}":
            d -= 1
            if d == 0: break
        ex += 1
    j = ex + 1
    while body[j] == "\n": j += 1
    return body[:i] + body[j:]
for sig in ("static bool parse_file",
            "SnortConfig* ParseSnortConf",
            "void ParseRules(SnortConfig* sc)",
            "static void ShowPolicyStats",
            "void ParseRulesFinish(SnortConfig* sc)"):
    assert sig in body, sig
    body = cut(body, sig)
head = '''#include "config.h"
#include "parser.h"
#include "parser/parse_conf.h"
#include <sstream>
#include "utils/util_cstring.h"
#include "managers/event_manager.h"
#include "detection/fp_utils.h"
#include <cassert>
#include <cstring>
#include <list>
#include <string>
#include "detection/fp_config.h"
#include "detection/rules.h"
#include "detection/sfrim.h"
#include "detection/rtn_checks.h"
#include "hash/ghash.h"
#include "hash/hash_key_operations.h"
#include "hash/xhash.h"
#include "log/log_stats.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "ports/port_object.h"
#include "ports/port_table.h"
#include "ports/rule_port_tables.h"
#include "sfip/sf_ipvar.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"
#include "parser/vars.h"
#include "ports/port_var_table.h"
#include "parser/parse_ports.h"
#include "parser/parse_rule.h"
#include "filterz/sfthd.h"
using namespace snort;
'''
assert "CreateRuleType" in body and "reduce_rtns" in body and "OtnInit" in body
body = body.replace("static void reduce_rtns(SnortConfig* sc)", "void reduce_rtns(SnortConfig* sc)")
assert "void reduce_rtns" in body
open(p, "w").write(head + body)
PY

# ---------------- surgery: parse_rule.cc (includes only) -------------------
python3 - "$H" <<'PY'
import sys
p = sys.argv[1] + "/copy/parser/parse_rule.cc"
s = open(p).read()
# (pristine includes kept; filters/* witness headers cover them)
s = s.replace('#include "parse_rule.h"', '#include "parse_rule.h"\n#include <algorithm>\n#include <list>', 1)
s = s.replace('#include <vector>', '#include <vector>\n#include <list>')
open(p, "w").write(s)
PY

# ---------------- real-source witnesses (verbatim bodies) ------------------
cat > "$C"/detection/detopt_wit.cc <<'EOFDO'
// free_detection_option_root VERBATIM from ORIGINAL
// detection/detection_options.cc (its private root struct is unreachable
// here: the harness never populates an nfp_tree, so only the null-guard
// branch + snort_free/delete semantics run; declared in witness header).
#include "detection/detection_options.h"
#include "utils/util.h"
struct detection_option_tree_root_t { void* children = nullptr; ~detection_option_tree_root_t() { } };
void free_detection_option_root(void** existing_tree)
{
    detection_option_tree_root_t* root;

    if ( !existing_tree or !*existing_tree )
        return;

    root = (detection_option_tree_root_t*)*existing_tree;
    snort_free(root->children);

    delete root;
    *existing_tree = nullptr;
}
EOFDO
cat > "$C"/catch/mpse_batch_wit.cc <<'EOF'
// MpseGroup::~MpseGroup witness: real body lives in search_engines
// monolith; the harness never constructs one (link symbol only).
#include "framework/mpse_batch.h"
namespace snort { MpseGroup::~MpseGroup() { } }
EOF

# ---------------- stubs.cc (SINGLE heredoc pair; regenerated every run) ----
cat > "$H"/stubs.cc <<'STUBEOF'
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/policy.h"
#include "main/thread_config.h"
#include "main/snort.h"
#include "parser/parse_conf.h"
#include "parser/parse_stream.h"
#include "parser/parser.h"
#include "parser/parse_rule.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "managers/so_manager.h"
#include "parser/cmd_line.h"
#include "detection/extract.h"
#include "detection/rtn_checks.h"
#include "filterz/sfthd.h"
#include "framework/ips_option.h"
#include "log/log_stats.h"
#include "log/messages.h"
#include "sfip/sf_vartable.h"
#include "utils/util.h"
#include <climits>
#include <string>
#include "parser/vars.h"
#include "ports/port_var_table.h"
#include "ports/port_table.h"
#include "parser/parse_ports.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ostream>
using namespace snort;

uint32_t SnortConfig::warning_flags = 0;
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::output_flags = 0;
bool SnortConfig::log_quiet_bypassed = false;
std::unordered_map<std::string, std::string> SnortConfig::static_names;
std::mutex SnortConfig::static_names_mutex;
SnortConfig* g_probe_sc = nullptr;
static SnortConfig g_default_conf;  // upstream unit-test context: a main conf
SnortConfig* SnortConfig::get_conf() { return g_probe_sc ? g_probe_sc : &g_default_conf; }
SnortConfig* SnortConfig::get_main_conf() { return g_probe_sc ? g_probe_sc : &g_default_conf; }
const char* SnortConfig::get_static_name(const char* name)
{
    std::lock_guard<std::mutex> lk(static_names_mutex);
    auto entry = static_names.find(name);
    if ( entry != static_names.end() )
        return entry->second.c_str();
    static_names.emplace(name, name);
    return static_names[name].c_str();
}
void SnortConfig::cleanup_fatal_error() { }
bool SnortConfig::get_default_rule_state() const
{
    switch ( get_ips_policy()->default_rule_state )
    {
    case IpsPolicy::INHERIT_ENABLE:
        return global_default_rule_state;
    case IpsPolicy::ENABLED:
        return true;
    case IpsPolicy::DISABLED:
        return false;
    }
    return true;
}
// PolicyMap ctor/dtor: policy.cc's real body wires Shell/NetworkPolicy/
// InspectorManager/DataBus monoliths (out of scope). Substitute keeps the
// ips-policy semantics only (documented deviation; probe never reaches
// shells/network/selector paths).
PolicyMap::PolicyMap()
{
    empty_ips_policy = new IpsPolicy((PolicyId)ips_policy.size());
    ips_policy.push_back(empty_ips_policy);
}
PolicyMap::~PolicyMap() { for ( auto p : ips_policy ) delete p; ips_policy.clear(); }
unsigned ThreadConfig::get_instance_max() { return 2; }
unsigned Snort::get_process_id() { return 4242; }
STUBEOF
# Thread witnesses: get_instance_id/get_thread_type/get_run_num come from the
# REAL main/thread.cc (copied + compiled); probe sets STHREAD_TYPE_MAIN.
cat >> "$H"/stubs.cc <<'STUBEOF'

// ------------- IpsPolicy members: VERBATIM from main/policy.cc ----------
IpsPolicy::IpsPolicy(PolicyId id) :
    action(IpsAction::get_max_types(), nullptr),
    configured_action(1, nullptr)
{
    policy_id = id;
    policy_mode = POLICY_MODE__MAX;
    var_table = nullptr;
    var_id = 1;
    ip_vartable = sfvt_alloc_table();
    portVarTable = PortVarTableCreate();
    nonamePortVarTable = PortTableNew();
    enable_builtin_rules = false;
    obfuscate_pii = true;
}
IpsPolicy::~IpsPolicy()
{
    if ( var_table )
        DeleteVars(var_table);
    if ( ip_vartable )
        sfvt_free_table(ip_vartable);
    if ( portVarTable )
        PortVarTableFree(portVarTable);
    if ( nonamePortVarTable )
        PortTableFree(nonamePortVarTable);
}
void IpsPolicy::update_user_policy_id()
{
    if ( user_policy_id == 0 )
        user_policy_id = 1;
}
bool IpsPolicy::has_action_variable_capacity() const
{ return configured_action.size() <= UINT8_MAX; }
bool IpsPolicy::has_action_variable(const std::string& name) const
{ return action_vars.find(name) != action_vars.end(); }
void IpsPolicy::commit_action_variable(const std::string& name,
    const std::string& action_name, IpsAction* act)
{
    const auto selector = (ActionSelector)configured_action.size();
    const auto action_type = IpsAction::get_type(action_name.c_str());
    action_vars.emplace(name, std::make_tuple(action_name, action_type, selector));
    configured_action.push_back(act);
}
bool IpsPolicy::get_action_variable(const std::string& name, const std::string*& action_name,
    IpsAction::Type& action_type, ActionSelector& selector) const
{
    const auto it = action_vars.find(name);
    if ( it == action_vars.end() )
        return false;
    action_name = &std::get<0>(it->second);
    action_type = std::get<1>(it->second);
    selector = std::get<2>(it->second);
    return true;
}
STUBEOF
cat >> "$H"/stubs.cc <<'STUBEOF'
static IpsPolicy* s_detection_policy = nullptr;
IpsPolicy* snort::get_ips_policy() { return s_detection_policy; }
void snort::set_ips_policy(IpsPolicy* p) { s_detection_policy = p; }
void set_ips_policy(const SnortConfig* sc, unsigned i)
{ snort::set_ips_policy(sc->policy_map->get_ips_policy(i)); }
IpsPolicy* snort::get_ips_policy(const SnortConfig* sc, unsigned i)
{
    return sc && i < sc->policy_map->ips_policy_count() ?
        sc->policy_map->get_ips_policy(i) : nullptr;
}
NetworkPolicy* snort::get_network_policy()
{
    // PolicyMap substitute carries no NetworkPolicy (documented
    // deviation); nothing in the probe paths calls this.
    std::abort();
}
IpsPolicy* snort::get_empty_ips_policy(const SnortConfig* sc)
{ return sc->policy_map->get_empty_ips(); }

// ---------------- ActionManager seam -> probe-pinned ordering -------------
class ActionManager {
public:
    static std::string get_action_string(IpsAction::Type);
    static IpsAction::Type get_action_type(const char*);
    static IpsAction::Type get_max_action_types();
    static std::string get_action_priorities(bool alert_before_pass = false);
};
// REAL managers/action_manager.cc statics (s_act_types/s_act_priorities/
// s_act_index + the five registry fns) are pinned in the sibling
// action_harness registry.cc (am_* rename) with exact upstream semantics;
// linking that witness preserves quirks (unordered_map find, descending
// greater<int> priority join). Registration order/precedence pinned here.
#include <algorithm>
#include <map>
#include <unordered_map>
#include <vector>
static std::unordered_map<std::string, IpsAction::Type> s_act_types;
static std::map<IpsAction::IpsActionPriority, std::string, std::greater<int>> s_act_priorities;
static IpsAction::Type s_act_index = 0;
unsigned probe_register_action(const char* n, int prio)
{
    s_act_types.emplace(n, s_act_index++);
    s_act_priorities.emplace((IpsAction::IpsActionPriority)prio, n);
    return s_act_index;
}
std::string ActionManager::get_action_string(IpsAction::Type action)
{
    if ( action < s_act_index )
    {
        auto it = std::find_if(s_act_types.cbegin(), s_act_types.cend(),
            [action](const std::pair<const std::string, IpsAction::Type>& type){ return type.second == action; });
        if ( it != s_act_types.cend())
            return (*it).first;
    }
    return "ERROR";
}
IpsAction::Type ActionManager::get_action_type(const char* s)
{
    auto type = s_act_types.find(s);
    if (type != s_act_types.end())
        return type->second;
    return ActionManager::get_max_action_types();
}
IpsAction::Type ActionManager::get_max_action_types()
{
    return s_act_index;
}
std::string ActionManager::get_action_priorities(bool alert_before_pass)
{
    std::string priorities;
    for (auto iter = s_act_priorities.begin(); iter != s_act_priorities.end(); )
    {
        if ( alert_before_pass )
        {
            if ( iter->second == "pass" )
            {
                iter++;
                continue;
            }
            else if ( iter->second == "alert" )
            {
                priorities += "alert pass ";
                iter++;
                continue;
            }
        }
        priorities += iter->second;
        if ( ++iter != s_act_priorities.end() )
            priorities += " ";
    }
    return priorities;
}
STUBEOF
cat >> "$H"/stubs.cc <<'STUBEOF'
const char* probe_action_name(IpsAction::Type t)
{
    // snapshot into a static: get_action_string returns std::string BY VALUE;
    // handing its .c_str() to a later printf reads freed memory (the probe
    // printed 0x01 garbage before this guard).
    static std::string s_snap;
    s_snap = ActionManager::get_action_string(t);
    return s_snap.c_str();
}
// IpsAction member fns VERBATIM from ORIGINAL framework/ips_action.cc:40-53
// (their .cc drags actions/detect/stats monoliths; wrappers delegate to the
// ActionManager witness statics above -- same call graph, pinned numbering).
std::string IpsAction::get_string(IpsAction::Type action)
{ return ActionManager::get_action_string(action); }
IpsAction::Type IpsAction::get_type(const char* s)
{ return ActionManager::get_action_type(s); }
IpsAction::Type IpsAction::get_max_types()
{ return ActionManager::get_max_action_types(); }
bool IpsAction::is_valid_action(IpsAction::Type action)
{
    if ( action < get_max_types() )
        return true;
    return false;
}
std::string IpsAction::get_default_priorities(bool alert_before_pass)
{ return ActionManager::get_action_priorities(alert_before_pass); }

// option-keyword feed for IpsManager witness (probe registers what the
// meta layer would offer; option_begin matches the rule option token).
static std::vector<std::string> g_opt_keywords;
void probe_register_option(const char* n) { g_opt_keywords.emplace_back(n); }

// ---------------- option/plugin-layer witnesses ---------------------------
struct ProbeOption : public IpsOption {
    ProbeOption(const char* n) : IpsOption(n, RULE_OPTION_TYPE_CONTENT) { }
};
static ProbeOption* g_probe_opt = nullptr;
static bool opt_keyword_hit = false;
bool IpsManager::option_begin(SnortConfig*, const char* n, SnortProtocolId, uint64_t)
{
    // pinned witness: matches the probe's registered option keywords
    for ( auto& k : g_opt_keywords )
        if ( k == n ) { opt_keyword_hit = true; return true; }
    opt_keyword_hit = false;
    return false;
}
bool IpsManager::option_set(SnortConfig*, const char*, const char*, const char*)
{
    // pinned witness: real option modules parse args here (out of scope);
    // harness option keywords take no args worth transcribing.
    return opt_keyword_hit;
}
IpsOption* IpsManager::option_end(SnortConfig*, OptTreeNode*, SnortProtocolId, const char* n, RuleOptType& rot)
{
    if ( !opt_keyword_hit )
        return nullptr;
    // REAL IpsOption ctor (framework/ips_option.cc compiled verbatim):
    // parse_rule_opt_end's option bookkeeping (num_detection_opts,
    // section select, buffer_setters probe) runs against a pinned base
    // option (CAT_NONE cursor, PS_NONE section, no pattern).
    delete g_probe_opt;
    g_probe_opt = new ProbeOption(n);
    rot = OPT_TYPE_DETECTION;
    return g_probe_opt;
}
bool ModuleManager::gid_in_use(uint32_t) { return false; }
const char* SoManager::get_so_rule(const char*) { return nullptr; }
SoEvalFunc SoManager::get_so_eval(const char*, const char*, void**) { std::abort(); }

// ---------------- never-reached link witnesses ---------------------------
void sfthd_node_free(THD_NODE*) { std::abort(); }
THD_NODE* detection_filter_create(DetectionFilterConfig*, struct THDX_STRUCT*) { std::abort(); }
void detection_filter_free(THD_NODE*) { std::abort(); }
int RuleListEnd(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckBidirectional(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckProto(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
void flowbits_counts(unsigned& t, unsigned& u, unsigned& s) { t = u = s = 0; }
void flowbits_print_deps(std::ostream&) { std::abort(); }
void get_flowbits_dependencies(void*, bool&, std::vector<std::string>&) { std::abort(); }
bool flowbits_setter(void*) { return false; }
void ClearIpsOptionsVars()
{
    // verbatim-equivalent: extract.cc static counter zeroed (counter is
    // file-static in ORIGINAL extract.cc; never observable here)
}
void show_pcre_counts() { }

// parse_stream.{h,cc} is now COMPILED VERBATIM (parser cp + OBJS_SRC):
// the earlier STREAM-echo witness is gone; parse_rules_string drives the
// real tokenizer FSM (get_token/get_state/exec) end-to-end.
STUBEOF

# ---------------- Catch gate: pristine originals, strips for link ---------
cat > "$H"/catch_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
cat > "$H"/installer_stub.cc <<'EOF'
#include "catch/snort_catch.h"
namespace snort {
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name)
{ REGISTER_TEST_CASE(fun, name) }
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name, const char* group)
{ REGISTER_TEST_CASE(fun, name, group) }
}
EOF
# gate copies: strip UNIT_TEST blocks in LEAF/monolith files (they only
# serve the unit suites of OTHER subsystems and pull unneeded includes);
# rules.cc / sfrim.cc / parse_rule.cc UNIT_TEST blocks stay pristine --
# they are the gate. (vars.cc/sf_ipvar.cc/sf_vartable.cc/json_stream.cc/
# parse_so_rule.cc strips are done by the shared loop below after each cp?
# No: they live in copy tree; strip loop runs once here.)
python3 - "$C" <<'PY'
import sys
c = sys.argv[1]
for rel in ("parser/vars.cc", "sfip/sf_ipvar.cc", "sfip/sf_vartable.cc",
            "helpers/json_stream.cc", "parser/parse_so_rule.cc",
            "detection/fp_utils.cc", "framework/ips_option.cc",
            "detection/fp_config_copy.cc", "utils/util.cc",
            "parser/parse_conf.cc", "parser/config_file.cc"):
    p = c + "/" + rel
    s = open(p).read()
    out = []
    i = 0
    while True:
        a = s.find("#ifdef UNIT_TEST", i)
        if a == -1: break
        # find the matching #endif: blocks are not nested at these sites;
        # scan for the first '#endif' at line start after a.
        b = s.find("\n#endif", a)
        assert b != -1, rel
        b += len("\n#endif")
        out.append(s[i:a]); out.append("/* UNIT_TEST stripped for gate link */")
        i = b
    out.append(s[i:])
    open(p, "w").write("".join(out))
PY

g++ -std=c++17 -O0 -w -DUNIT_TEST -I"$C" -fsyntax-only \
  "$C"/parser/parse_rule.cc "$C"/detection/rules.cc "$C"/detection/sfrim.cc \
  "$C"/parser/parser.cc "$C"/parser/parse_conf.cc "$C"/detection/fp_utils.cc \
  "$C"/log/log_stats.cc "$C"/utils/util.cc "$C"/main/thread.cc \
  "$C"/framework/ips_option.cc 2>&1 | head -40

# link closure shared by BOTH binaries (gate: pristine+UNIT_TEST; probe: same)
OBJS_SRC=(
  "$C"/parser/vars.cc "$C"/parser/var_dependency.cc "$C"/parser/parse_ports.cc
  "$C"/parser/parse_conf.cc "$C"/parser/config_file.cc "$C"/parser/parse_stream.cc
  "$C"/ports/port_object.cc "$C"/ports/port_object2.cc "$C"/ports/port_item.cc
  "$C"/ports/port_utils.cc "$C"/ports/port_var_table.cc "$C"/ports/port_table.cc
  "$C"/ports/rule_port_tables.cc "$C"/ports/port_group.cc
  "$C"/utils/sflsq.cc "$C"/utils/util_cstring.cc "$C"/utils/util_net.cc "$C"/utils/util.cc
  "$C"/hash/ghash.cc "$C"/hash/hash_key_operations.cc "$C"/hash/primetable.cc
  "$C"/hash/xhash.cc "$C"/hash/hash_lru_cache.cc "$C"/hash/hashes.cc
  "$C"/sfip/sf_ip.cc "$C"/sfip/sf_cidr.cc "$C"/sfip/sf_ipvar.cc "$C"/sfip/sf_vartable.cc
  "$C"/log/messages.cc "$C"/log/log_stats.cc
  "$C"/target_based/snort_protocols.cc "$C"/time/tsc_clock.cc
  "$C"/detection/treenodes.cc "$C"/detection/fp_utils.cc
  "$C"/framework/ips_option.cc "$C"/detection/detopt_wit.cc
  "$C"/catch/mpse_batch_wit.cc "$C"/main/thread.cc
  "$C"/detection/fp_config_copy.cc
)

# ---------------- probe build (UNIT_TEST off; leaf strips applied above) ---
g++ -std=c++17 -O0 -g -w -I"$C" -o "$H"/probe \
  "$H"/probe.cc "$H"/stubs.cc \
  "$C"/parser/parse_rule.cc "$C"/parser/parser.cc \
  "$C"/detection/rules.cc "$C"/detection/sfrim.cc "$C"/detection/signature.cc \
  "$C"/helpers/json_stream.cc \
  "${OBJS_SRC[@]}"

"$H"/probe > "$H"/vectors.txt 2>&1
# fatal-abort channels pinned as subprocess vectors: ParseAbort -> FatalError
# prints "FATAL: ..." (ParseAbort -> FatalError -> main-thread path prints,
# then, since the stub config cannot clean up, abort via exit path below).
# Real shell does SnortConfig::cleanup_fatal_error + exit(1); witness aborts.
emit_fatal ()
{
  # 1: undefined $VAR port -> ParseAbort "PortVar Lookup failed"
  # 2: raw literal port parse error -> ParseAbort "Rule--PortVar Parse error"
  # 3: same var abort, but fed through the REAL parse_stream FSM
  # probe exits non-zero there (real shell: FatalError -> cleanup + exit 1);
  # tolerate so the pin stays stable.
  echo "FATAL$1 start"
  local rc=0
  FATAL_DEMO=$1 "$H"/probe > "/tmp/fatal_$1.txt" 2>&1 || rc=$?
  echo "FATAL$1 rc=$rc"
  grep -e FATAL -e Quitting "/tmp/fatal_$1.txt" || true
  echo "FATAL$1 end"
}
set +e
emit_fatal 1 >> "$H"/vectors.txt
emit_fatal 2 >> "$H"/vectors.txt
emit_fatal 3 >> "$H"/vectors.txt
set -e

# ---------------- Catch gate binary ---------------------------------------
g++ -std=c++17 -O0 -w -DUNIT_TEST -I"$C" -o "$H"/catchprobe \
  "$H"/catch_main.cc "$H"/installer_stub.cc "$H"/stubs.cc \
  "$C"/parser/parse_rule.cc "$C"/parser/parser.cc \
  "$C"/detection/rules.cc "$C"/detection/sfrim.cc "$C"/detection/signature.cc \
  "$C"/helpers/json_stream.cc \
  "${OBJS_SRC[@]}"

"$H"/catchprobe 2>&1 | tail -8 | sed 's/^/GATE /'
cat "$H"/vectors.txt
