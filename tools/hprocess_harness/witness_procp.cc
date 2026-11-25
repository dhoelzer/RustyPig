// witness (row 24b): the app-level undefined mirror for the signal/privilege
// row TU (the 23b/22a mirror law). EVERY body is a SHAPE-ONLY capture mirror
// of a NOT-landed home (the log faces ride the LANDED log/messages semantics
// home CITED from Rust only; here the C-capture legs are harness mirrors):
// helpers/markup, main/oops_handler, helpers/sigsafe, the SnortConfig subset
// (the carried subset precedent, 22a tc / 24a sn-proc), the lib-version faces
// (DAQ/pcap/OpenSSL/PCRE2/ZLIB — the DECL-rider law: host headers ABSENT
// MEASURED, the witness NEVER claims ABI truth, NEVER vendored).
// BODIES NEVER land; the rec() legs feed the DEC order ladder ONLY. The
// namespace placement of each leg rides the row .o's OWN nm -C census face
// (build.sh asserts the census; this file NEVER guesses it).
// The family law: the ground row-name NEVER rides this file joined; comments
// split the family (proc-pair / sig-nal / sn-proc).
#include "main/process.h"
#include "main/snort_config.h"
#include "main/oops_handler.h"
#include "main.h"
#include "helpers/markup.h"
#include "helpers/sigsafe.h"
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

std::vector<std::string> g_probe_trace;
void probe_reset_trace() { g_probe_trace.clear(); }
static void rec(const char* n) { g_probe_trace.push_back(n); }
const char* probe_legs()
{
    static std::string s;
    s.clear();
    for (size_t i = 0; i < g_probe_trace.size(); ++i)
    { if (i) s += "|"; s += g_probe_trace[i]; }
    return s.c_str();
}

// the conf slot (the probe allocates a real SnortConfig via the subset ctor;
// get_main_conf BELOW hands the slot back — the honest subset rider face,
// the 24a precedent, banked in DEVIATIONS row 24b):
snort::SnortConfig* g_probe_conf = nullptr;
unsigned g_log_count = 0;       // the LogMessage tally face (banner census)

int g_pcre2_rc = 6;             // synth witness face (NOT the PCRE2 ABI)

// ------------------------------------------------------------- version faces
// copy-local SYNTHETIC mirrors for the DECL riders (host headers ABSENT
// MEASURED; NEVER vendored, NEVER ABI claims):
extern "C" {
const char* daq_version_string() { rec("daq.ver"); return "3.0.29-synth"; }
const char* pcap_lib_version() { rec("pcap.ver"); return "libpcap-version-synth"; }
const char* OpenSSL_version(int type) { rec("ossl.ver"); (void)type; return "OpenSSL-synth"; }
int pcre2_config(int what, void* where)
{
    rec("pcre2.ver");
    if (where) std::memcpy(where, "10.45", 6);
    return g_pcre2_rc;
}
const char* zlibVersion() { rec("zlib.ver"); return "1.3.1-synth"; }
}

// ------------------------------------------------------------------- Markup
const char* Markup::item() { rec("markup.item"); return "- "; }
const char* Markup::emphasis_on() { return ""; }
const char* Markup::emphasis_off() { return ""; }

// ------------------------------------------------------------- oops mirror
void OopsHandler::handle_crash(int fd) { rec("oops.handle_crash"); (void)fd; }

// --------------------------------------------------------- SigSafePrinter
void SigSafePrinter::printf(const char* format, ...)
{
    // the fd-ctor WRITE face (the sigsafe law: raw write(2) to the fd, the
    // stdio-buffer face NEVER rides a signal handler — the ground printer
    // writes STDOUT for the pronto banner / STDERR for the oops banner):
    char buf[512];
    va_list a; va_start(a, format);
    int n = vsnprintf(buf, sizeof buf, format, a);
    va_end(a);
    if (n > 0 && fd >= 0)
    {
        ssize_t w = write(fd, buf, (size_t)n);   // signal-safe seat
        (void)w;
    }
}
int SigSafePrinter::flush() { return 0; }   // via popen on the suicide leg

// ------------------------------------------------------------------ main.h
const char* get_prompt() { return "==>"; }
bool main_snort_started() { return true; }

namespace snort {

// --------------------------------------------------------- SnortConfig subset
// (the carried subset ctor/dtor/statics legs VERBATIM from the 24a family;
// get_main_conf hands the probe slot back — the honest subset rider face,
// the 22a tc / 24a sn-proc subset precedent):
SnortConfig::SnortConfig(const char*) : reload_id(0) {}
uint32_t SnortConfig::logging_flags = 0;
THREAD_LOCAL bool SnortConfig::log_quiet_bypassed = false;
uint32_t SnortConfig::warning_flags = 0;
std::mutex SnortConfig::static_names_mutex;
std::unordered_map<std::string, std::string> SnortConfig::static_names;
void SnortConfig::setup() { rec("sc.setup"); }
void SnortConfig::post_setup() { rec("sc.post_setup"); }
bool SnortConfig::verify() const { return true; }
SnortConfig* SnortConfig::get_main_conf() { return g_probe_conf; }
const SnortConfig* SnortConfig::get_conf() { return g_probe_conf; }
void SnortConfig::set_conf(SnortConfig* s) { rec("sc.set_conf"); g_probe_conf = s; }
void SnortConfig::register_reload_handler(ReloadResourceTuner*) { rec("sc.register_reload_handler"); }

// --------------------------------------------------------------- log legs
void LogMessage(const char* fmt, ...)
{
    g_log_count++;
    va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a);
}
void ErrorMessage(const char* fmt, ...)
{
    rec("ErrorMessage");
    va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a);
}
void ParseError(const char* fmt, ...)
{
    rec("ParseError");
    char buf[512];
    va_list a; va_start(a, fmt);
    vsnprintf(buf, sizeof buf, fmt, a);
    fprintf(stderr, "(ss) %s\n", buf);
    va_end(a);
}
void FatalError(const char* fmt, ...)
{
    rec("FatalError");
    va_list a; va_start(a, fmt);
    vfprintf(stderr, fmt, a);
    va_end(a);
    abort();
}
const char* get_error(int err) { return std::strerror(err); }
char* snort_strdup(const char* s) { return strdup(s); }
} // namespace snort
