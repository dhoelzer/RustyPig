#include "main/snort_config.h"
#include "log/messages.h"
#include "utils/util.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
namespace snort {
static SnortConfig g_conf;
SnortConfig* SnortConfig::get_conf() { return &g_conf; }
bool SnortConfig::dump_rule_info() const { return false; }
void ParseWarning(WarningGroup, const char* fmt, ...)
{ std::fprintf(stderr, "PARSE-WARNING: "); va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap); std::fprintf(stderr, "\n"); }
void LogMessage(const char* fmt, ...)
{ std::fprintf(stderr, "LOG: "); va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap); std::fprintf(stderr, "\n"); }
void ErrorMessage(const char* fmt, ...)
{ std::fprintf(stderr, "ERROR: "); va_list ap; va_start(ap, fmt); std::vfprintf(stderr, fmt, ap); va_end(ap); std::fprintf(stderr, "\n"); }
char* snort_strdup(const char* s) { return s ? strdup(s) : nullptr; }
char* snort_strndup(const char* s, size_t n) { if (!s) return nullptr; char* p = (char*)snort_calloc(n + 1); memcpy(p, s, n); return p; }
bool SnortConfig::static_hash() { return false; }
}
unsigned get_instance_id() { return 0; }
unsigned int get_random_seed() { return 0x5EED; }
