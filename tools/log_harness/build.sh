#!/usr/bin/env bash
# Ground-truth probe over ORIGINAL log/messages.cc (no upstream suite).
# messages.cc compiles verbatim; only log/config/thread/location headers
# are shimmed. FatalError _exits and log_safec_error asserts, so those
# paths run in forked children; stdout/stderr are unbuffered so markers
# interleave exactly with messages.cc's own writes.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{main,parser,log,utils,time}

cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/log/{messages.h,messages.cc,log_errors.h} "$C"/log/
sed -i "1i #include <sstream>" "$C"/log/messages.cc  # sstream comes transitively via real snort_config.h

printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\nnamespace snort { inline bool in_main_thread() { return true; } }\n' > "$C"/main/thread.h
printf '#pragma once\nvoid get_parse_location(const char*& file, unsigned& line);\nvoid set_parse_loc(const char* f, unsigned l);\n' > "$C"/parser/parser.h
printf '#pragma once\n' > "$C"/utils/util_cstring.h
printf '#pragma once\n' > "$C"/time/packet_time.h

# batched logger: probe never arms OUTPUT_FLAG__LOG_BUFFERED; abort() if the
# buffered path is ever entered so a wiring mistake is loud.
cat > "$C"/log/batched_logger.h <<'EOF'
#pragma once
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
namespace BatchedLogger {
class BatchedLogManager {
public:
    static void log(FILE*, bool, const char*, size_t) { std::abort(); }
    static void log(FILE*, bool, const char*, va_list&) { std::abort(); }
};
}
EOF

# real SnortConfig statics + accessor shapes (subset messages.cc touches)
cat > "$C"/main/snort_config.h <<'EOF'
#pragma once
#include <cstdint>
#include "main/snort_types.h"
namespace snort {
class SnortConfig {
public:
    static uint32_t warning_flags;
    static uint32_t logging_flags;
    static uint32_t output_flags;
    static bool log_quiet_bypassed;
    static SnortConfig* get_conf();
    bool use_log_buffered() const { return output_flags & 0x00002000; }
    static bool log_syslog() { return logging_flags & 4; }
    static bool log_quiet() { return !log_quiet_bypassed && (logging_flags & 2); }
    static void set_log_quiet(bool en)
    { if (en) logging_flags |= 2; else logging_flags &= ~2u; }
    static void cleanup_fatal_error();
};
}
EOF

cat > "$H/stubs.cc" <<'EOF'
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
EOF

g++ -std=c++17 -O0 -I"$C" -o "$H/probe" \
  "$H"/probe.cc "$H"/stubs.cc "$C"/log/messages.cc

"$H/probe" > "$H/vectors.txt" 2>&1
cat "$H/vectors.txt"
