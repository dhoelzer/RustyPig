#include "main/snort_config.h"
#include "log/messages.h"
#include <cstdio>
using namespace snort;
uint32_t SnortConfig::warning_flags = 0;
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::output_flags = 0;
bool SnortConfig::log_quiet_bypassed = false;
static SnortConfig g_conf;
SnortConfig* SnortConfig::get_conf() { return &g_conf; }

// when armed, cleanup_fatal_error re-enters FatalError (after the first
// call already_fatal==1, so the reentry _exit(1)s without printing)
bool g_reentrant_cleanup = false;
void SnortConfig::cleanup_fatal_error()
{
    if (g_reentrant_cleanup)
        FatalError("inner fatal during cleanup\n");
}

static const char* g_loc_file = nullptr;
static unsigned g_loc_line = 0;
void set_parse_loc(const char* f, unsigned l) { g_loc_file = f; g_loc_line = l; }
void get_parse_location(const char*& file, unsigned& line)
{ file = g_loc_file; line = g_loc_line; }

// syslog stub: captures LOG_* prio + formatted text on stdout
extern "C" void syslog(int priority, const char* fmt, ...)
{
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    std::printf("SYSLOG(%d) %s\n", priority, buf);
}
extern "C" void openlog(const char*, int, int) { }
