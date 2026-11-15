#!/usr/bin/env bash
# Ground-truth probe over ORIGINAL parser/parse_conf.cc core (location
# stack, get_config_file resolution walk, parse_include, parse_rules_
# file/string, ParseIpVar, get_rule_list) + parser/config_file.cc
# (GetChecksumFlags, conf-dir) + ORIGINAL log/messages.cc engine. No
# upstream suites for parser subsystems. Real sfip + vars + ports +
# hash + messages compile verbatim. Heavy deps shimmed: main/policy.h
# and main/snort_config.h carry the exact ChecksumFlag enum (verbatim
# policy.h 128-135) and checksum/includer fields; parse_stream is a
# witness stub; add_service_to_otn (OptTreeNode/SnortConfig monolith)
# is cut; Analyzer::set_main_hook line stripped.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{main,parser,ports,utils,hash,protocols,log,sfip,framework,detection,target_based,time,managers}

cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/parser/{vars.h,vars.cc,var_dependency.h,var_dependency.cc,parse_ports.h,parse_ports.cc,parse_conf.cc,config_file.h,config_file.cc,parse_stream.h} "$C"/parser/
cp "$SRC"/src/ports/{port_object.h,port_object.cc,port_item.h,port_item.cc,port_utils.h,port_utils.cc,port_var_table.h,port_var_table.cc,port_table.h} "$C"/ports/
cp "$SRC"/src/utils/{sflsq.h,sflsq.cc,util.h,util_cstring.h,util_cstring.cc,bits.h,cpp_macros.h,util_net.h,util_net.cc} "$C"/utils/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc} "$C"/hash/
cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_cidr.cc,sf_ipvar.h,sf_ipvar.cc,sf_vartable.h,sf_vartable.cc,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/log/{messages.h,messages.cc,log_errors.h} "$C"/log/
printf "#pragma once\n#include \"parser/parser.h\"\n" > /dev/null # (parser.h carries location decls)

printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
printf '#pragma once\n#include <cstdint>\nnamespace snort { constexpr int32_t MAX_PORTS = 65536; }\nusing snort::MAX_PORTS;\n' > "$C"/protocols/packet.h
printf '#pragma once\nnamespace snort { inline bool in_main_thread() { return true; } }\n' > "$C"/main/thread.h
printf '#pragma once\n' > "$C"/time/packet_time.h
printf '#pragma once\nunsigned get_instance_id();\nnamespace snort { inline bool in_main_thread() { return true; } }\n' > "$C"/main/thread.h
printf '#pragma once\n' > "$C"/main/analyzer.h
printf '#pragma once\n' > "$C"/detection/fp_utils.h
printf '#pragma once\nnamespace snort { class DetectionEngine { public: static void inspect(void*); }; }
' > "$C"/detection/detection_engine.h
printf '#pragma once\n' > "$C"/managers/module_manager.h
printf '#pragma once\n' > "$C"/target_based/snort_protocols.h
printf '#pragma once\n#include <cstdarg>\n#include <cstdio>\n#include <cstdlib>\nnamespace BatchedLogger { class BatchedLogManager {\npublic:\n static void log(FILE*, bool, const char*, size_t) { std::abort(); }\n static void log(FILE*, bool, const char*, va_list&) { std::abort(); }\n}; }\n' > "$C"/log/batched_logger.h

# parse_stream: real header shape; stub in stubs.cc witnesses the seam.
cat > "$C"/parser/parse_stream_shim_note.txt <<'EOF'
parse_stream.h copied VERBATIM from the source tree (it only declares
void parse_stream(std::istream&, snort::SnortConfig*)); the definition
lives in stubs.cc as the probe's witness for the rules-reading seam.
EOF

cat > "$C"/parser/parse_conf.h <<'EOF'
#pragma once
#include <string>
namespace snort { struct SnortConfig; }
void parse_conf_init();
void parse_conf_term();
void parse_conf_print();
const char* get_parse_file();
void get_parse_location(const char*& name, unsigned& line);
const char* get_config_file(const char* arg, std::string& file);
void parse_rules_file(snort::SnortConfig*, const char* fname);
void parse_rules_string(snort::SnortConfig*, const char* str, bool ips_policy = true);
struct ListHead;
ListHead* get_rule_list(snort::SnortConfig*, const char*);
void push_parse_location(
    const char* code, const char* path, const char* file, unsigned line = 1);
void pop_parse_location();
void inc_parse_position();
bool ParseIpVar(const char*, const char*);
void parse_include(snort::SnortConfig*, const char*);

EOF

cat > "$C"/parser/parser.h <<'EOF'
#pragma once
#include <string>
namespace snort {
struct SnortConfig;
struct OptTreeNode;
struct RuleTreeNode;
}
const char* parser_get_special_includer();
EOF

# policy.h shim: ChecksumFlag enum + checksum fields + includer VERBATIM
# from src/main/policy.h (128-135, 233-234, 274); ListHead forward decl
# so get_rule_list (kept verbatim in parse_conf.cc) compiles; everything
# else (DataBus/CodecManager/uuid/InspectionPolicy) out of scope.
cat > "$C"/main/policy.h <<'EOF'
#pragma once
#include <string>
#include <cstdint>
#include "ports/port_var_table.h"
#include "sfip/sf_vartable.h"
struct VarEntry;
struct ListHead;
namespace snort {
enum ChecksumFlag
{
    CHECKSUM_FLAG__IP   = 0x00000001,
    CHECKSUM_FLAG__TCP  = 0x00000002,
    CHECKSUM_FLAG__UDP  = 0x00000004,
    CHECKSUM_FLAG__ICMP = 0x00000008,
    CHECKSUM_FLAG__ALL  = 0x0000000f,
    CHECKSUM_FLAG__DEF  = 0x80000000
};
struct RuleListNode { const char* name; ListHead* RuleList; RuleListNode* next; };
struct NetworkPolicy {
    std::string includer;
    uint32_t checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF;
    uint32_t checksum_drop = CHECKSUM_FLAG__DEF;
};
NetworkPolicy* get_network_policy();
struct IpsPolicy {
    ::VarEntry* var_table = nullptr;
    PortVarTable* portVarTable = nullptr;
    vartable_t* ip_vartable = nullptr;
    uint32_t var_id = 0;
    std::string includer;
};
IpsPolicy* get_ips_policy();
}
EOF

# snort_config.h shim: exactly the members messages.cc + parse_conf.cc
# touch (include_path, rule_lists, the flag statics + accessors).
cat > "$C"/main/snort_config.h <<'EOF'
#pragma once
#include <cstdint>
#include <string>
#include "main/snort_types.h"
#include "main/policy.h"
namespace snort {
class SnortConfig {
public:
    std::string include_path;
    RuleListNode* rule_lists = nullptr;
    static uint32_t warning_flags;
    static uint32_t logging_flags;
    static uint32_t output_flags;
    static bool log_quiet_bypassed;
    static SnortConfig* get_conf();
    bool use_log_buffered() const { return output_flags & 0x00002000; }
    static bool log_syslog() { return logging_flags & 4; }
    static bool log_quiet() { return !log_quiet_bypassed && (logging_flags & 2); }
    static void cleanup_fatal_error();
    bool show_file_codes() const;
    bool dump_rule_info() const;
    static bool static_hash();
};
}
EOF

# real snort headers need <sstream> transitively in this shim world
sed -i '1i #include <sstream>' "$C"/parser/vars.cc
sed -i '1i #include <sstream>' "$C"/parser/parse_conf.cc
sed -i '1i #include <sstream>' "$C"/log/messages.cc
sed -i '1i #include "parser/parse_conf.h"' "$C"/log/messages.cc

# mechanical shims proven in vars_harness
sed -i 's|#include "port_group.h"||' "$C"/ports/port_object.cc
sed -i '/if (po->group )/,+1d' "$C"/ports/port_object.cc
sed -i 's|#include "port_item.h"|#include "port_item.h"\nvoid rule_index_map_print_index(int, char*, int);|' "$C"/ports/port_object.cc
sed -i 's|^void PortObjectPrint(PortObject\* po)$|void rule_index_map_print_index(int, char*, int) { }\nvoid PortObjectPrint(PortObject* po)|' "$C"/ports/port_object.cc
sed -i 's|#include "ports/port_object2.h"|struct PortObject2;|' "$C"/ports/port_table.h

# config_file.cc: hook wiring takes a (Packet*)->int member pointer that
# the shim signatures cannot express; the call is behaviorally invisible
# to everything this probe observes -> strip (documented substitution).
sed -i 's|^    Analyzer::set_main_hook(DetectionEngine::inspect);||' "$C"/parser/config_file.cc

# parse_conf.cc: cut add_service_to_otn{,_helper} (OptTreeNode +
# SnortConfig::proto_ref/service_extension monoliths, out of scope;
# get_rule_list and everything else stay verbatim).
python3 - "$H" <<'PY'
import sys
p = sys.argv[1] + "/copy/parser/parse_conf.cc"
s = open(p).read()
start = s.index("static void add_service_to_otn_helper")
end = s.index("// cppcheck-suppress constParameterPointer")
open(p, "w").write(s[:start] + s[end:])
PY

cat > "$H/stubs.cc" <<'EOF'
#include "main/snort_config.h"
#include "main/policy.h"
#include "main/analyzer.h"
#include "parser/parse_conf.h"
#include "parser/parse_stream.h"
#include "parser/vars.h"
#include "parser/var_dependency.h"
#include "parser/config_file.h"
#include "log/messages.h"
#include "sfip/sf_vartable.h"
#include "utils/util.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
using namespace snort;

bool g_show_file_codes = false;
int g_stream_reads = 0;

static SnortConfig g_conf;
static IpsPolicy g_policy;
static NetworkPolicy g_netpol;
SnortConfig* SnortConfig::get_conf() { return &g_conf; }
bool SnortConfig::show_file_codes() const { return g_show_file_codes; }
bool SnortConfig::dump_rule_info() const { return false; }
bool SnortConfig::static_hash() { return false; }
uint32_t SnortConfig::warning_flags = 0;
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::output_flags = 0;
bool SnortConfig::log_quiet_bypassed = false;
void SnortConfig::cleanup_fatal_error() { }
IpsPolicy* snort::get_ips_policy() { return &g_policy; }
NetworkPolicy* snort::get_network_policy() { return &g_netpol; }

// rules-reading seam witness (parse_stream is out of scope; reaching it
// means the file opened and depth bookkeeping happened -> count it).
const char* g_nested_arg = nullptr;
int g_nested_count = 0;
void parse_stream(std::istream&, snort::SnortConfig* sc) {
    ++g_stream_reads;
    if (g_nested_count > 0) { --g_nested_count; parse_include(sc, g_nested_arg); }
}

const char* parser_get_special_includer() { return "SPECIAL_INCLUDER"; }

SnortConfig& probe_sc() { return g_conf; }

namespace snort {
char* snort_strdup(const char* s) { return s ? strdup(s) : nullptr; }
char* snort_strndup(const char* s, size_t n) { if (!s) return nullptr; char* p = (char*)snort_calloc(n + 1); memcpy(p, s, n); return p; }
// parse_conf.cc parse_rules_file uses get_error(errno); real util.cc is
// not compiled (drags snort_config) -> glibc-shaped equivalent.
const char* snort_placeholder_unused();
EOF

# get_error lives in utils/util.h as SO_PUBLIC in namespace snort.
# util.cc stays out of the compile (needs snort_config.h monolith), so
# append the real definition (verbatim body, GNU strerror_r branch).
python3 - "$SRC" <<'PY'
import sys, re
src = sys.argv[1]
s = open(src + "/src/utils/util.cc").read()
start = s.index("const char* get_error")
end = s.index("\n", s.index("#endif", start)) if "#endif" in s[start:start+700] else None
# safer: grab through the closing brace of the function
snippet = s[start:start+700]
snippet = snippet[:snippet.index("\n}")+3]
with open(sys.argv[1] and "stub_get_error.inc", "w") as f:
    f.write(snippet + "\n")
PY
cat "${SRC%src}" > /dev/null 2>/dev/null || true
sed "s/defined(HAVE_GNU_STRERROR_R)/1/" stub_get_error.inc >> "$H/stubs.cc"
echo "}" >> "$H/stubs.cc"
printf "unsigned get_instance_id() { return 0; }\nunsigned int get_random_seed() { return 0x5EED; }\n" >> "$H/stubs.cc"

g++ -std=c++17 -O0 -I"$C" -o "$H/probe" \
  "$H"/probe.cc "$H"/stubs.cc \
  "$C"/parser/vars.cc "$C"/parser/var_dependency.cc "$C"/parser/parse_ports.cc \
  "$C"/parser/parse_conf.cc "$C"/parser/config_file.cc \
  "$C"/ports/port_object.cc "$C"/ports/port_item.cc \
  "$C"/ports/port_utils.cc "$C"/ports/port_var_table.cc \
  "$C"/utils/sflsq.cc "$C"/utils/util_cstring.cc "$C"/utils/util_net.cc \
  "$C"/hash/ghash.cc "$C"/hash/hash_key_operations.cc "$C"/hash/primetable.cc \
  "$C"/sfip/sf_ip.cc "$C"/sfip/sf_cidr.cc "$C"/sfip/sf_ipvar.cc "$C"/sfip/sf_vartable.cc \
  "$C"/log/messages.cc

rm -f stub_get_error.inc
"$H/probe" > "$H/vectors.txt" 2>&1
cat "$H/vectors.txt"
