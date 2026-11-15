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
