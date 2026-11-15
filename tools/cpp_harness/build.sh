#!/bin/bash
# Build the ORIGINAL snort3 ports/parser C++ sources out-of-tree against a
# hermetic copy tree with minimal shim/patch edits, to generate ground-truth
# parity vectors for the Rust port. All patches are mechanical include/type
# shims (port_group, SnortConfig, logging) — zero logic changes.
set -e
SRC=/opt/data/snort3-src
H=/opt/data/snort3-rust/tools/cpp_harness
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{main,parser,ports,utils,hash,protocols,log,framework}

# verbatim copies
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/parser/parse_ports.{h,cc} "$C"/parser/
cp "$SRC"/src/ports/{port_object.h,port_object.cc,port_item.h,port_item.cc,port_utils.h,port_utils.cc,port_var_table.h,port_var_table.cc,port_table.h} "$C"/ports/
cp "$SRC"/src/utils/{sflsq.h,sflsq.cc,util.h,util_cstring.h,util_cstring.cc,bits.h} "$C"/utils/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc} "$C"/hash/

# --- mechanical shims (no logic edits) ---
printf '#pragma once\n' > "$C/config.h"
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C/framework/api_options.h"
printf '#pragma once\n#include <cstdint>\nnamespace snort { constexpr int32_t MAX_PORTS = 65536; }\nusing snort::MAX_PORTS;\n' > "$C/protocols/packet.h"
printf '#pragma once\n' > "$C/parser/parser.h"
printf '#pragma once\nunsigned get_instance_id();\n' > "$C/main/thread.h"

cat > "$C/log/messages.h" <<'EOF'
#pragma once
#include <cstdarg>
#include <cstdio>
#include "main/snort_types.h"
namespace snort {
enum WarningGroup { WARN_RULES = 0 };
__attribute__((format(printf,2,3))) void ParseWarning(WarningGroup, const char*, ...);
void LogMessage(const char*, ...);
void ErrorMessage(const char*, ...);
}
EOF

cat > "$C/main/snort_config.h" <<'EOF'
#pragma once
#include "main/snort_types.h"
namespace snort {
struct SnortConfig {
    static SnortConfig* get_conf();
    bool dump_rule_info() const;
    static bool static_hash();
};
}
EOF

# port_object.cc: drop port_group include + inert group delete; forward-declare
# and stub the rule_index_map print callback (its home module is out of scope)
sed -i 's|#include "port_group.h"||' "$C/ports/port_object.cc"
sed -i '/if (po->group )/,+1d' "$C/ports/port_object.cc"
sed -i 's|#include "port_item.h"|#include "port_item.h"\nvoid rule_index_map_print_index(int, char*, int);|' "$C/ports/port_object.cc"
sed -i 's|^void PortObjectPrint(PortObject\* po)$|void rule_index_map_print_index(int, char*, int) { }\nvoid PortObjectPrint(PortObject* po)|' "$C/ports/port_object.cc"

# port_table.h: PortObject2 is only a pointer array here
sed -i 's|#include "ports/port_object2.h"|struct PortObject2;|' "$C/ports/port_table.h"

cat > "$H/stubs.cc" <<'EOF'
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
EOF

g++ -std=c++17 -O0 -I"$C" -o "$H/harness" \
  "$H"/harness.cc "$H"/stubs.cc \
  "$C"/ports/port_object.cc "$C"/ports/port_item.cc \
  "$C"/ports/port_utils.cc "$C"/ports/port_var_table.cc \
  "$C"/parser/parse_ports.cc \
  "$C"/utils/sflsq.cc "$C"/utils/util_cstring.cc \
  "$C"/hash/ghash.cc "$C"/hash/hash_key_operations.cc "$C"/hash/primetable.cc
echo BUILD-OK
