#!/usr/bin/env bash
# Ground-truth probe over ORIGINAL log/text_log.cc + main/thread.cc
# (neither has an upstream suite; log/test/ only covers obfuscator).
# Also compiles ORIGINAL utils/util.cc + util_cstring.cc + log/messages.cc
# so get_error / SnortSnprintf / ParseError / FatalError / ErrorMessage
# text is real. time() is stubbed for deterministic roll filenames;
# FatalError _exit paths run in forked children.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{main,parser,log,utils,time}

cp "$SRC"/src/main/{snort_types.h,thread.h,thread.cc} "$C"/main/
cp "$SRC"/src/log/{text_log.h,text_log.cc,log.h,messages.h,messages.cc,log_errors.h} "$C"/log/
cp "$SRC"/src/utils/{util.h,util.cc,util_cstring.h,util_cstring.cc} "$C"/utils/

sed -i "1i #include <sstream>" "$C"/log/messages.cc  # transitive in real build
sed -i "1i #include <climits>\n#include <csignal>\n#include <cassert>\n#include <sstream>\n#include <limits.h>" "$C"/utils/util.cc
sed -i "s/defined(HAVE_GNU_STRERROR_R)/1/" "$C"/utils/util.cc  # force GNU strerror_r branch (glibc text)
printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n' > "$C"/time/packet_time.h
printf '#pragma once\nvoid get_parse_location(const char*& file, unsigned& line);\nvoid set_parse_loc(const char* f, unsigned l);\n' > "$C"/parser/parser.h

# batched logger: same abort-loud stub as tools/log_harness
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

# real SnortConfig statics (messages.cc) + the fields thread.cc / util.cc touch
cat > "$C"/main/snort_config.h <<'EOF'
#pragma once
#include <cstdint>
#include <string>
#include "main/snort_types.h"
namespace snort {
class SnortConfig {
public:
    static uint32_t warning_flags;
    static uint32_t logging_flags;
    static uint32_t output_flags;
    static bool log_quiet_bypassed;
    static SnortConfig* get_conf();

    std::string log_dir;
    std::string run_prefix;
    uint16_t id_offset = 0;
    bool id_subdir = false;
    bool id_zero = false;
    int thiszone = 0;

    bool use_log_buffered() const { return output_flags & 0x00002000; }
    static bool log_syslog() { return logging_flags & 4; }
    static bool log_quiet() { return !log_quiet_bypassed && (logging_flags & 2); }
    static void set_log_quiet(bool en)
    { if (en) logging_flags |= 2; else logging_flags &= ~2u; }
    static void set_log_syslog(bool en)
    { if (en) logging_flags |= 4; else logging_flags &= ~4u; }
    bool create_inst_file() const { return false; }
    bool output_use_utc() const { return false; }
    bool output_include_year() const { return false; }
    static void cleanup_fatal_error();
};
}
EOF

# thread.cc: ThreadConfig::get_instance_max + tid accessors (subset used)
cat > "$C"/main/thread_config.h <<'EOF'
#pragma once
class ThreadConfig {
    static inline unsigned g_max = 1;
public:
    static void set_instance_max(unsigned m) { g_max = m; }
    static unsigned get_instance_max() { return g_max; }
    static void set_instance_tid(int) { }
    static int get_instance_tid(int) { return 4242; }
};
EOF

# thread.cc: Snort::get_process_id (populate_instance_maps only; dead here)
cat > "$C"/main/snort.h <<'EOF'
#pragma once
namespace Snort { unsigned get_process_id(); }
EOF

cat > "$H/stubs.cc" <<'EOF'
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
EOF

g++ -std=c++17 -O0 -fno-builtin-time -I"$C" -o "$H/probe" \
  "$H"/probe.cc "$H"/stubs.cc \
  "$C"/log/messages.cc "$C"/log/text_log.cc \
  "$C"/main/thread.cc "$C"/utils/util.cc "$C"/utils/util_cstring.cc

"$H/probe" > "$H/vectors.txt" 2>&1
cat "$H/vectors.txt"
