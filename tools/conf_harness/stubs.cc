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
const char* get_error(int errnum)
{
    static THREAD_LOCAL char buf[128];

#if 1
    return strerror_r(errnum, buf, sizeof(buf));
#else
    (void)strerror_r(errnum, buf, sizeof(buf));
    return buf;
#endif
}

}
unsigned get_instance_id() { return 0; }
unsigned int get_random_seed() { return 0x5EED; }
