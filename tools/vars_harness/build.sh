#!/usr/bin/env bash
# Ground-truth probe over ORIGINAL parser/vars.cc + parser/var_dependency.cc
# (no upstream suites for either). Real sfip + ports + parse_ports + hash
# compile from the proven cpp_harness copy-tree; only log/config/policy/
# parse_conf headers are shimmed. ParseAbort longjmps back to the probe
# (probe.cc) so every abort case continues and pins its message text.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{main,parser,ports,utils,hash,protocols,log,sfip,framework}

cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/parser/{vars.h,vars.cc,var_dependency.h,var_dependency.cc,parse_ports.h,parse_ports.cc} "$C"/parser/
cp "$SRC"/src/ports/{port_object.h,port_object.cc,port_item.h,port_item.cc,port_utils.h,port_utils.cc,port_var_table.h,port_var_table.cc,port_table.h} "$C"/ports/
cp "$SRC"/src/utils/{sflsq.h,sflsq.cc,util.h,util_cstring.h,util_cstring.cc,bits.h,cpp_macros.h,util_net.h,util_net.cc} "$C"/utils/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc} "$C"/hash/
cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_cidr.cc,sf_ipvar.h,sf_ipvar.cc,sf_vartable.h,sf_vartable.cc,sf_returns.h} "$C"/sfip/

printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
printf '#pragma once\n#include <cstdint>\nnamespace snort { constexpr int32_t MAX_PORTS = 65536; }\nusing snort::MAX_PORTS;\n' > "$C"/protocols/packet.h
printf '#pragma once\n' > "$C"/parser/parser.h
printf '#pragma once\nunsigned get_instance_id();\n' > "$C"/main/thread.h
printf '#pragma once\nbool ParseIpVar(const char*, const char*);\n' > "$C"/parser/parse_conf.h

# parse_conf.cc itself won't compile hermetically; provide its REAL ParseIpVar
# body (verbatim from src/parser/parse_conf.cc) in stubs.cc so resolve_nets
# exercises the genuine callback. Its deps (sfvt_define, Disallow..., weak-nets
# push) all come from the compiled originals.

cat > "$C"/log/messages.h <<'EOF'
#pragma once
#include <cstdarg>
#include <cstdio>
#include "main/snort_types.h"
namespace snort {
enum WarningGroup { WARN_RULES = 7, WARN_VARS = 3 };
__attribute__((format(printf,2,3))) void ParseWarning(WarningGroup, const char*, ...);
void ParseError(const char*, ...);
void LogMessage(const char*, ...);
void ErrorMessage(const char*, ...);
[[noreturn]] void ParseAbort(const char*, ...);
}
EOF

cat > "$C"/main/snort_config.h <<'EOF'
#pragma once
#include <cstdint>
#include "main/snort_types.h"
#include "ports/port_var_table.h"
#include "sfip/sf_vartable.h"
struct VarEntry;
namespace snort {
struct IpsPolicy {
    ::VarEntry* var_table = nullptr;
    PortVarTable* portVarTable = nullptr;
    vartable_t* ip_vartable = nullptr;
    uint32_t var_id = 0;
};
IpsPolicy* get_ips_policy();
struct SnortConfig {
    static SnortConfig* get_conf();
    bool dump_rule_info() const;
    static bool static_hash();
};
}
EOF

# vars.cc gets <sstream> transitively upstream (snort_config pulls it); add to copy
sed -i '1i #include <sstream>' "$C"/parser/vars.cc

# mechanical shims proven in cpp_harness
sed -i 's|#include "port_group.h"||' "$C"/ports/port_object.cc
sed -i '/if (po->group )/,+1d' "$C"/ports/port_object.cc
sed -i 's|#include "port_item.h"|#include "port_item.h"\nvoid rule_index_map_print_index(int, char*, int);|' "$C"/ports/port_object.cc
sed -i 's|^void PortObjectPrint(PortObject\* po)$|void rule_index_map_print_index(int, char*, int) { }\nvoid PortObjectPrint(PortObject* po)|' "$C"/ports/port_object.cc
sed -i 's|#include "ports/port_object2.h"|struct PortObject2;|' "$C"/ports/port_table.h

cat > "$H/stubs.cc" <<'EOF'
#include "main/snort_config.h"
#include "log/messages.h"
#include "parser/parse_conf.h"
#include "parser/vars.h"
#include "parser/var_dependency.h"
#include "sfip/sf_vartable.h"
#include "sfip/sf_returns.h"
#include "utils/util.h"
#include <csetjmp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
jmp_buf g_abort_jmp;
bool g_abort_armed = false;

// Verbatim from src/parser/parse_conf.cc (the file itself drags in Shell,
// DataBus, PluginManager). Its deps compile from the original sources.
namespace snort {
static SnortConfig g_conf;
static IpsPolicy g_policy;
SnortConfig* SnortConfig::get_conf() { return &g_conf; }
bool SnortConfig::dump_rule_info() const { return false; }
bool SnortConfig::static_hash() { return false; }
IpsPolicy* get_ips_policy() { return &g_policy; }
void ParseWarning(WarningGroup g, const char* fmt, ...)
{ std::printf("WARN(%d) ", (int)g); va_list ap; va_start(ap, fmt); std::vprintf(fmt, ap); va_end(ap); std::putchar('\n'); }
void ParseError(const char* fmt, ...)
{ std::printf("PERR "); va_list ap; va_start(ap, fmt); std::vprintf(fmt, ap); va_end(ap); std::putchar('\n'); }
void LogMessage(const char* fmt, ...)
{ std::printf("LOG "); va_list ap; va_start(ap, fmt); std::vprintf(fmt, ap); va_end(ap); std::putchar('\n'); }
void ErrorMessage(const char* fmt, ...)
{ std::printf("ERR "); va_list ap; va_start(ap, fmt); std::vprintf(fmt, ap); va_end(ap); std::putchar('\n'); }
void ParseAbort(const char* fmt, ...)
{ std::printf("ABORT "); va_list ap; va_start(ap, fmt); std::vprintf(fmt, ap); va_end(ap); std::putchar('\n');
  if (g_abort_armed) longjmp(g_abort_jmp, 1);
  std::exit(2); }
char* snort_strdup(const char* s) { return s ? strdup(s) : nullptr; }
char* snort_strndup(const char* s, size_t n) { if (!s) return nullptr; char* p = (char*)snort_calloc(n + 1); memcpy(p, s, n); return p; }
}

bool ParseIpVar(const char* var, const char* value)
{
    using namespace snort;  // parse_conf.cc has this at file scope
    int ret;
    IpsPolicy* p = get_ips_policy();
    DisallowCrossTableDuplicateVars(var, VAR_TYPE__IPVAR);
    // FIXIT-M: ip checked for duplicates twice: in the function above and in sfvt_add_str

    if ((ret = sfvt_define(p->ip_vartable, var, value)) != SFIP_SUCCESS)
    {
        switch (ret)
        {
        case SFIP_ARG_ERR:
            ParseError("the following is not allowed: %s.", value);
            return false;

        case SFIP_DUPLICATE:
            ParseWarning(WARN_VARS, "Var '%s' redefined.", var);
            break;

        case SFIP_CONFLICT:
            ParseError("negated IP ranges that are more general than "
                "non-negated ranges are not allowed. Consider "
                "inverting the logic in %s.", var);
            return false;

        case SFIP_NOT_ANY:
            ParseError("!any is not allowed in %s.", var);
            return false;

        case SFIP_LOOKUP_FAILURE:
            if (is_resolving_nets())
                ParseError("failed to parse the IP address: %s.", value);
            else
                push_to_weak_nets(var, value);
            return false;

        default:
            ParseError("failed to parse the IP address: %s.", value);
            return false;
        }
    }

    return true;
}
unsigned get_instance_id() { return 0; }
unsigned int get_random_seed() { return 0x5EED; }
EOF

g++ -std=c++17 -O0 -I"$C" -o "$H/probe" \
  "$H"/probe.cc "$H"/stubs.cc \
  "$C"/parser/vars.cc "$C"/parser/var_dependency.cc "$C"/parser/parse_ports.cc \
  "$C"/ports/port_object.cc "$C"/ports/port_item.cc \
  "$C"/ports/port_utils.cc "$C"/ports/port_var_table.cc \
  "$C"/utils/sflsq.cc "$C"/utils/util_cstring.cc "$C"/utils/util_net.cc \
  "$C"/hash/ghash.cc "$C"/hash/hash_key_operations.cc "$C"/hash/primetable.cc \
  "$C"/sfip/sf_ip.cc "$C"/sfip/sf_cidr.cc "$C"/sfip/sf_ipvar.cc "$C"/sfip/sf_vartable.cc

"$H/probe" > "$H/vectors.txt"
cat "$H/vectors.txt"
