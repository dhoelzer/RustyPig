#include "main/snort_config.h"
#include "log/messages.h"
#include "main/snort.h"
#include <cstdio>
#include <ctime>
using namespace snort;
uint32_t SnortConfig::warning_flags = 0;
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::output_flags = 0;
bool SnortConfig::log_quiet_bypassed = false;
static SnortConfig g_conf;
SnortConfig* SnortConfig::get_conf() { return &g_conf; }
SnortConfig& probe_conf() { return g_conf; }
void SnortConfig::cleanup_fatal_error() { }
unsigned Snort::get_process_id() { return 4242; }

static const char* g_loc_file = nullptr;
static unsigned g_loc_line = 0;
void set_parse_loc(const char* f, unsigned l) { g_loc_file = f; g_loc_line = l; }
void get_parse_location(const char*& file, unsigned& line)
{ file = g_loc_file; line = g_loc_line; }

// deterministic clock: time() everywhere (text_log last/roll names, messages
// if any) comes from one fake counter the probe bumps explicitly.
static time_t g_clock = 1000000;
extern "C" time_t time(time_t* t) { if (t) *t = g_clock; return g_clock; }
void bump_clock(long s) { g_clock += s; }

extern "C" void syslog(int priority, const char* fmt, ...)
{
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    std::printf("SYSLOG(%d) %s\n", priority, buf);
}
extern "C" void openlog(const char*, int, int) { }
