#!/usr/bin/env bash
# Ground-truth harness for the rule-tree core (plan row 17 keystone):
#   detection/rules.{h,cc}       RuleStateMap (upstream Catch gate: 2 cases)
#   detection/sfrim.{h,cc}       rule index map (upstream Catch gate: 1 case)
#   parse_rule.cc (FULL)         action/proto/nets/ports/dir, open/close,
#                                same_headers, mergeDuplicateOtn, process_rtn,
#                                counters, escape/opt accounting
#   parser.cc (RTN lifecycle)    addRtnToOtn/deleteRtnFromOtn/find_rtn/
#                                reduce_rtns/CreateRuleType/parser_init/term,
#                                RuleTreeCache+KeyOps, Free/DestroyRuleTreeNode
#   detection/{treenodes,signature} RTN/OTN structs, Otn{Lookup,Remove}
# Verbatim leaves: sfip, ports(+group+table+rule_port_tables), sflsq,
# util_cstring, hash(ghash/xhash/lru/primetable/hashes), vars+var_dependency,
# parse_ports, parse_so_rule, messages, snort_protocols, snort_bounds,
# json_stream, parse_utils no. Shimmed (documented deviations):
#   main/snort_config.h  -> member subset (exactly what the TUs touch);
#   main/policy.h        -> struct shape verbatim; member bodies VERBATIM from
#                           policy.cc into stubs; policy seam via globals;
#   ActionManager        -> probe-ordered registration witness (numbering is
#                           plugin-init-order dependent upstream; order pinned);
#   ips_options layer    -> probe rules carry NO IPS options; IpsManager/
#                           ModuleManager/SoManager witnesses abort on reach;
#   rtn_checks + meta    -> link stubs (FP funcs never called by probe);
#   flowbits print_deps, pcap, ParseRules* config monolith: cut (documented).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{trace,search_engines,main,parser,ports,utils,hash,protocols,log,sfip,framework,detection,target_based,time,managers,catch,filterz,control,ips_options,helpers,packet_io}

cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/main/policy.h "$C"/main/
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

cp "$SRC"/src/parser/{vars.h,vars.cc,var_dependency.h,var_dependency.cc,parse_ports.h,parse_ports.cc,parse_rule.h,parse_so_rule.h,parse_so_rule.cc,config_file.h} "$C"/parser/
cp "$SRC"/src/ports/{port_object.h,port_object.cc,port_object2.h,port_object2.cc,port_item.h,port_item.cc,port_utils.h,port_utils.cc,port_var_table.h,port_var_table.cc,port_table.h,port_table.cc,rule_port_tables.h,rule_port_tables.cc,port_group.h,port_group.cc} "$C"/ports/

cp "$SRC"/src/utils/{sflsq.h,sflsq.cc,util.h,util_cstring.h,util_cstring.cc,bits.h,cpp_macros.h,util_net.h,util_net.cc,snort_bounds.h} "$C"/utils/
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
cp "$SRC"/src/log/{messages.h,messages.cc,log_errors.h,log_stats.h,log.h,text_log.h,text_log.cc} "$C"/log/
sed -i 's|#include <atomic>|#include <atomic>\n#include <sstream>|' "$C"/log/messages.cc
sed -i 's|#include "log/messages.h"|#include <sstream>\n#include "log/messages.h"|' "$C"/parser/vars.cc
sed -i 's|#include <memory>|#include <cassert>\n#include <memory>|' "$C"/ports/port_table.cc

cp "$SRC"/src/target_based/{snort_protocols.h,snort_protocols.cc} "$C"/target_based/
sed -i 's|#include "protocols/packet.h"||' "$C"/target_based/snort_protocols.cc
# parse_ports.cc keeps its packet.h include: witness header supplies snort::MAX_PORTS

cp "$SRC"/src/detection/{rules.h,rules.cc,treenodes.h,treenodes.cc,sfrim.h,sfrim.cc,signature.h,signature.cc,rule_option_types.h,fp_config.h,detection_buf.h} "$C"/detection/
cp "$SRC"/src/framework/{ips_action.h,cursor.h,pdu_section.h,counts.h,base_api.h,ips_option.h,decode_data.h,mpse.h,mpse_batch.h} "$C"/framework/
cp "$SRC"/src/protocols/{ip.h,ipv4.h,ipv6.h,layer.h,protocol_ids.h} "$C"/protocols/
cp "$SRC"/src/catch/{catch.hpp,snort_catch.h} "$C"/catch/
cp "$SRC"/src/detection/fp_utils.h "$C"/detection/
mkdir -p "$C"/protocols
cp "$SRC"/src/protocols/{mpls.h,layer.h} "$C"/protocols/ 2>/dev/null || cp "$SRC"/src/protocols/mpls.h "$C"/protocols/
cp "$SRC"/src/packet_io/active_action.h "$C"/packet_io/
cp "$SRC"/src/parser/parser.cc "$C"/parser/parser.cc
cp "$SRC"/src/parser/parse_rule.cc "$C"/parser/parse_rule.cc
cp "$SRC"/src/helpers/{json_stream.h,json_stream.cc,memcap_allocator.h} "$C"/helpers/
cp "$SRC"/src/search_engines/search_common.h "$C"/search_engines/

cat > "$C"/framework/data_bus_wit.h <<'EOF'
#pragma once
// witness: real framework/data_bus.h drags control/mp/lockless-ring
// monoliths; policy.h only embeds snort::DataBus members (used solely by
// policy.cc bodies, not header-inline code) -> empty minimal shape.
namespace snort { class SnortConfig; class DataBus { public: unsigned subscription_count() const { return 0; } }; }
EOF
printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
cp "$SRC"/src/time/{clock_defs.h,tsc_clock.h,tsc_clock.cc} "$C"/time/
printf '#pragma once\n' > "$C"/time/packet_time.h
printf '#pragma once\n#include "time/tsc_clock_note.h"\n' > /dev/null
cp "$SRC"/src/main/thread.h "$C"/main/
# thread.h bodies live in thread.cc (not linked): abort-witness in stubs.cc.
# thread.h itself is self-contained (string + snort_types.h only).
cat > "$C"/main/thread_config.h <<'EOF'
#pragma once
#include <map>
#include <string>
namespace snort { class ThreadConfig { public: static unsigned get_instance_max(); }; }
EOF
cat > "$C"/log/log_stats_note.txt <<'EOF'
log_stats.h copied; log_stats.cc NOT compiled (control monolith) -- probe
never prints rule stats through it; parse_rule_print lives in parse_rule.cc.
EOF
cat > "$C"/control/control.h <<'EOF'
#pragma once
#include <cstdlib>
namespace snort { class ControlConn { public: bool respond(const char*, ...)
{ std::abort(); } }; }
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
// Harness TUs need only the Packet fwd + snort::MAX_PORTS (real line 119).
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
// port_group.h); body stubbed in stubs.cc.
struct DetectionOptionTree;
void free_detection_option_root(void**);
EOFDO
cat > "$C"/filterz/sfthd.h <<'EOF'
#pragma once
struct THD_NODE;
void sfthd_node_free(THD_NODE*);
EOF
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
cat > "$C"/managers/so_manager.h <<'EOF'
#pragma once
namespace snort { class SoManager { public: static const char* get_so_rule(const char* soid); }; }
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

# ---- snort_config.h shim: exactly the members the four big TUs touch ----
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
    unsigned run_flags = 0;
    std::string metadata_filter;
    GHash* otn_map = nullptr;
    ::RuleListNode* rule_lists = nullptr;
    XHash* rtn_hash_table = nullptr;
    ::PolicyMap* policy_map = nullptr;
    ::RuleStateMap* rule_states = nullptr;
    ProtocolReference* proto_ref = nullptr;
    ::RulePortTables* port_tables = nullptr;
    ::FastPatternConfig* fast_pattern_config = nullptr;
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

# GHash/XHash forward decls come from real headers; add fwd decls in config head
python3 - "$C" <<'PY'
import sys
p = sys.argv[1] + "/main/snort_config.h"
s = open(p).read()
s = s.replace("namespace snort {\nstruct RuleStateMap;",
              "class GHash;\nclass XHash;\nnamespace snort {\nstruct RuleStateMap;", 1)
open(p, "w").write(s)
PY

# ---- parse_conf.h shim (only what parse_rule/parser/rules.cc reference) ----
cat > "$C"/parser/parse_conf.h <<'EOF'
#pragma once
#include <string>
#include "detection/signature.h"
namespace snort { struct SnortConfig; }
void parse_rules_string(snort::SnortConfig*, const char* str, bool ips_policy = true);
void add_service_to_otn(snort::SnortConfig*, OptTreeNode*, const char*);
void add_ref_map(snort::SnortConfig*) {}
struct ListHead;
ListHead* get_rule_list(snort::SnortConfig*, const char*);
bool ParseIpVar(const char* name, const char* value);
EOF

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
void get_parse_location(const char*& name, unsigned& line);
struct RuleTreeNodeKey
{
    RuleTreeNode* rtn;
    PolicyId policyId;
};
EOF

# ---------------- surgery: parser.cc (keep RTN lifecycle region) ----------
python3 - "$H" <<'PY'
import sys
p = sys.argv[1] + "/copy/parser/parser.cc"
s = open(p).read()
start = s.index("static struct rule_index_map_t* ruleIndexMap")
fs = s.index("RuleListNode* CreateRuleType") + len("RuleListNode* CreateRuleType")
fs = s.index("{", fs)
depth = 0; fe = fs
while True:
    if s[fe] == "{": depth += 1
    elif s[fe] == "}":
        depth -= 1
        if depth == 0: break
    fe += 1
end = fe + 1
body = s[start:end]
def cut(body, sig):
    i = body.index(sig)
    lb = body.index("{", i); d = 0; e = lb
    while True:
        if body[e] == "{": d += 1
        elif body[e] == "}":
            d -= 1
            if d == 0: break
        e += 1
    # also drop trailing blank line
    j = e + 1
    while body[j] == "\n": j += 1
    return body[:i] + body[j:]
for sig in ("static void FreeOutputLists",
            "static bool parse_file",
            "SnortConfig* ParseSnortConf",
            "void ParseRules(SnortConfig* sc)",
            "static void ShowPolicyStats",
            "void ParseRulesFinish(SnortConfig* sc)"):
    body = cut(body, sig)
head = '''#include "config.h"
#include "parser.h"
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
#include "parser/parse_conf.h"
#include "parser/vars.h"
#include "ports/port_var_table.h"
#include "ports/port_table.h"
#include "parser/parse_ports.h"
#include "parser/parse_rule.h"
#include "filterz/sfthd.h"
using namespace snort;
'''
assert "CreateRuleType" in body and "reduce_rtns" in body
body = body.replace("static void reduce_rtns(SnortConfig* sc)", "void reduce_rtns(SnortConfig* sc)")
assert "void reduce_rtns" in body
open(p, "w").write(head + body)
PY

# ---------------- surgery: parse_rule.cc (includes only) -------------------
python3 - "$H" <<'PY'
import sys
p = sys.argv[1] + "/copy/parser/parse_rule.cc"
s = open(p).read()
s = s.replace('#include "filterz/detection_filter.h"', '')
s = s.replace('#include "parse_rule.h"', '#include "parse_rule.h"\n#include <algorithm>\n#include <list>', 1)
s = s.replace('#include <vector>', '#include <vector>\n#include <list>')
# excise UNIT_TEST block (Catch gate covers the 5 TEST_CASEs separately? no:
# parse_rule Catch cases need the same TU; keep them but they need log_errors
# + snort_catch which ARE available; simpler: keep UNIT_TEST, compiled only
# for the gate binary. Strip for probe binary below.)
open(p, "w").write(s)
PY
# for the PROBE compile of parse_rule, guard off UNIT_TEST via a define toggle:
cp "$C"/parser/parse_rule.cc "$C"/parser/parse_rule_probe.cc
python3 - "$C" <<'PY'
import sys
p = sys.argv[1] + "/parser/parse_rule_probe.cc"
s = open(p).read()
i = s.index("#ifdef UNIT_TEST")
j = s.index("#endif", i) + len("#endif")
open(p, "w").write(s[:i] + s[j:])
PY
# rules.cc / sfrim.cc: same treatment (gate binary compiles pristine -DUNIT_TEST)
for f in rules sfrim; do
python3 - "$C" "$f" <<'PY'
import sys, shutil
c, f = sys.argv[1], sys.argv[2]
src = f"{c}/detection/{f}.cc"
s = open(src).read()
i = s.index("#ifdef UNIT_TEST")
j = s.rindex("#endif") + len("#endif")
open(f"{c}/detection/{f}_probe.cc", "w").write(s[:i] + s[j:])
PY
done

# signature.cc: flowbits-print deps -> witness decls; keep the rest verbatim.
python3 - "$C" <<'PY'
import sys
c = sys.argv[1]
p = c + "/detection/signature.cc"
s = open(p).read()
s = s.replace('#include "filters/sfthd.h"', '#include "filterz/sfthd.h"')
s = s.replace('#include "ips_options/ips_flowbits.h"',
              'void flowbits_print_deps(std::ostream&);\nvoid flowbits_setter(void*);\nvoid get_flowbits_dependencies(void*, bool&, std::vector<std::string>&);')
i = s.find("#ifdef UNIT_TEST")
if i != -1:
    j = s.rindex("#endif") + len("#endif")
    s2 = s[:i] + s[j:]
else:
    s2 = s
open(c + "/detection/signature_probe.cc","w").write(s2)
open(p,"w").write(s)
PY

# ports/port_object.cc group-free (no PortGroup here): revert -- port_group.cc
# IS compiled now, so keep the group code verbatim (no cut this time).

# ---------------- stubs.cc ----------------
cat > "$H"/stubs.cc <<'STUBEOF'
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/policy.h"
#include "main/thread_config.h"
#include "parser/parse_conf.h"
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
#include "log/messages.h"
#include "sfip/sf_vartable.h"
#include "utils/util.h"
#include <climits>
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
SnortConfig* SnortConfig::get_conf() { return g_probe_sc; }
SnortConfig* SnortConfig::get_main_conf() { return g_probe_sc; }
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
unsigned get_instance_id() { return 0; }

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
static IpsPolicy* s_detection_policy = nullptr;
IpsPolicy* snort::get_ips_policy() { return s_detection_policy; }
void snort::set_ips_policy(IpsPolicy* p) { s_detection_policy = p; }
void set_ips_policy(const SnortConfig* sc, unsigned i)
{ snort::set_ips_policy(sc->policy_map->get_ips_policy(i)); }
IpsPolicy* snort::get_empty_ips_policy(const SnortConfig* sc)
{ return sc->policy_map->get_empty_ips(); }

// ---------------- ActionManager seam -> probe-pinned ordering -------------
#include <vector>
static std::vector<std::string> g_acts;
unsigned probe_register_action(const char* n)
{ g_acts.emplace_back(n); return (unsigned)g_acts.size() - 1; }
STUBEOF
cat >> "$H"/stubs.cc <<'STUBEOF'
// member fns of framework/ips_action.cc (file NOT compiled: actions/plugin
// monolith). Bodies mirror upstream against the registration witness above.
IpsAction::Type IpsAction::get_type(const char* s)
{
    for ( size_t i = 0; i < g_acts.size(); ++i )
        if ( g_acts[i] == s )
            return (IpsAction::Type)i;
    return (IpsAction::Type)g_acts.size();
}
IpsAction::Type IpsAction::get_max_types() { return (IpsAction::Type)g_acts.size(); }
const char* probe_action_name(IpsAction::Type t)
{ return t < g_acts.size() ? g_acts[t].c_str() : "ERROR"; }

// ---------------- option/plugin-layer witnesses: abort on reach ----------
bool IpsManager::option_begin(SnortConfig*, const char*, SnortProtocolId, uint64_t) { std::abort(); }
bool IpsManager::option_set(SnortConfig*, const char*, const char*, const char*) { std::abort(); }
IpsOption* IpsManager::option_end(SnortConfig*, OptTreeNode*, SnortProtocolId, const char*, RuleOptType&) { std::abort(); }
bool ModuleManager::gid_in_use(uint32_t) { return false; }
const char* SoManager::get_so_rule(const char*) { return nullptr; }

// ---------------- never-reached link witnesses ---------------------------
void sfthd_node_free(THD_NODE*) { std::abort(); }
int RuleListEnd(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckBidirectional(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckProto(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
void flowbits_counts(unsigned& t, unsigned& u, unsigned& s) { t = u = s = 0; }
void flowbits_print_deps(std::ostream&) { std::abort(); }
void ClearIpsOptionsVars() { } // verbatim-equivalent: extract.cc body zeroes cnt
void show_pcre_counts() { }
STUBEOF

# get_error VERBATIM (GNU strerror_r branch) from utils/util.cc
python3 - "$SRC" "$H" <<'PY'
import sys
src, h = sys.argv[1], sys.argv[2]
s = open(src + "/src/utils/util.cc").read()
start = s.index("const char* get_error")
snippet = s[start:start+700]
snippet = snippet[:snippet.index("\n}")+3]
snippet = snippet.replace("defined(HAVE_GNU_STRERROR_R)", "1")
with open(h + "/stubs.cc", "a") as f:
    f.write("namespace snort {\n" + snippet + "\n}\n")
PY

# ---------------- Catch gate: pristine originals -DUNIT_TEST --------------
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

g++ -std=c++17 -O0 -w -DUNIT_TEST -I"$C" -o "$H"/catchprobe \
  "$H"/catch_main.cc "$H"/installer_stub.cc "$H"/stubs.cc \
  "$C"/detection/rules.cc "$C"/detection/sfrim.cc "$C"/parser/parse_rule.cc \
  "$C"/parser/parser.cc \
  "$C"/detection/treenodes.cc "$C"/detection/signature_probe.cc \
  "$C"/parser/vars.cc "$C"/parser/var_dependency.cc "$C"/parser/parse_ports.cc \
  "$C"/parser/parse_so_rule.cc \
  "$C"/ports/port_object.cc "$C"/ports/port_object2.cc "$C"/ports/port_item.cc \
  "$C"/ports/port_utils.cc "$C"/ports/port_var_table.cc "$C"/ports/port_table.cc \
  "$C"/ports/rule_port_tables.cc "$C"/ports/port_group.cc \
  "$C"/utils/sflsq.cc "$C"/utils/util_cstring.cc "$C"/utils/util_net.cc \
  "$C"/hash/ghash.cc "$C"/hash/hash_key_operations.cc "$C"/hash/primetable.cc \
  "$C"/hash/xhash.cc "$C"/hash/hash_lru_cache.cc "$C"/hash/hashes.cc \
  "$C"/sfip/sf_ip.cc "$C"/sfip/sf_cidr.cc "$C"/sfip/sf_ipvar.cc "$C"/sfip/sf_vartable.cc \
  "$C"/log/messages.cc "$C"/log/text_log.cc \
  "$C"/target_based/snort_protocols.cc \
  "$C"/helpers/json_stream.cc

# ---------------- probe build --------------------------------------------
g++ -std=c++17 -O0 -w -I"$C" -o "$H"/probe \
  "$H"/probe.cc "$H"/stubs.cc \
  "$C"/parser/vars.cc "$C"/parser/var_dependency.cc "$C"/parser/parse_ports.cc \
  "$C"/parser/parse_rule_probe.cc "$C"/parser/parser.cc "$C"/parser/parse_so_rule.cc \
  "$C"/ports/port_object.cc "$C"/ports/port_object2.cc "$C"/ports/port_item.cc \
  "$C"/ports/port_utils.cc "$C"/ports/port_var_table.cc "$C"/ports/port_table.cc \
  "$C"/ports/rule_port_tables.cc "$C"/ports/port_group.cc \
  "$C"/utils/sflsq.cc "$C"/utils/util_cstring.cc "$C"/utils/util_net.cc \
  "$C"/hash/ghash.cc "$C"/hash/hash_key_operations.cc "$C"/hash/primetable.cc \
  "$C"/hash/xhash.cc "$C"/hash/hash_lru_cache.cc "$C"/hash/hashes.cc \
  "$C"/sfip/sf_ip.cc "$C"/sfip/sf_cidr.cc "$C"/sfip/sf_ipvar.cc "$C"/sfip/sf_vartable.cc \
  "$C"/log/messages.cc \
  "$C"/target_based/snort_protocols.cc \
  "$C"/detection/rules_probe.cc "$C"/detection/treenodes.cc \
  "$C"/detection/sfrim_probe.cc "$C"/detection/signature_probe.cc \
  "$C"/helpers/json_stream

"$H"/probe > "$H"/vectors.txt 2>&1
"$H"/catchprobe 2>&1 | tail -6 | sed 's/^/GATE /'
cat "$H"/vectors.txt
