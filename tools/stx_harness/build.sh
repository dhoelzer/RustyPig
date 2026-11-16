#!/usr/bin/env bash
# Ground-truth harness for utils/stats/output_text.cc + utils.cc +
# snapshot.h (text renderer over the stats Snapshot data model).
#  * gate: the ORIGINAL upstream suite
#    src/utils/stats/test/stats_output_text_test.cc compiled verbatim --
#    it #includes ../output_text.cc directly (so the file-statics
#    counter_value_as_u64 / value_as_text / calc_pct are tested at
#    function granularity) and ships its own log/memory witnesses.
#    utils.cc (should_render) links verbatim next to it.
#  * probe: output_text.cc + utils.cc compiled VERBATIM against witness
#    Log*/set_log_conn/MemoryCap implementations that print every render
#    line raw between markers so exact padding/tabs pin into vectors.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{utils/stats/test,framework,log,main,memory,control,catch}

# real headers / sources verbatim
cp "$SRC"/src/utils/stats/{snapshot.h,utils.h,utils.cc,output_text.h,output_text.cc} "$C"/utils/stats/
cp "$SRC"/src/utils/stats/test/stats_output_text_test.cc "$C"/utils/stats/test/
cp "$SRC"/src/framework/counts.h "$C"/framework/
cp "$SRC"/src/log/{log_stats.h,messages.h} "$C"/log/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/memory/{heap_interface.h,memory_cap.h} "$C"/memory/
cp "$SRC"/src/control/control.h "$C"/control/
cp "/opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp" "$C"/catch/

printf '#pragma once\n' > "$C"/config.h

# ---- main/policy.h: same graft as the PROVEN rules_harness (data_bus
# witness; PolicyMap private->public). Upstream guards <uuid.h> with
# HAVE_UUID (undefined here -> uuid_t typedef). ----
cp "$SRC"/src/main/policy.h "$C"/main/
cp "$SRC"/src/framework/{ips_action.h,base_api.h} "$C"/framework/
# api_options.h shim exactly like rules_harness (real one absent; upstream
# generated -- witness provides API_OPTIONS)
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
mkdir -p "$C"/packet_io
cp "$SRC"/src/packet_io/active_action.h "$C"/packet_io/
python3 - "$C" <<'FIXPOLICY'
import sys
p = sys.argv[1] + "/main/policy.h"
s = open(p).read()
s = s.replace('#include "framework/data_bus.h"', '#include "framework/data_bus_wit.h"')
s = s.replace('#include "framework/mp_data_bus.h"', '')
blk = s.index("class PolicyMap")
end = s.index("};", blk)
seg = s[:blk][s.index("class PolicyMap"):] + s[blk:end].replace("private:", "public:") + s[end:]
seg = s[blk:end].replace("private:", "public:")
s = s[:blk] + seg + s[end:]
open(p, "w").write(s)
FIXPOLICY
cat > "$C"/framework/data_bus_wit.h <<'EOF'
#pragma once
// witness: real framework/data_bus.h drags control/mp/lockless-ring
// monoliths; policy.h only embeds snort::DataBus members (used solely by
// policy.cc bodies, not header-inline code) -> empty minimal shape.
namespace snort { class SnortConfig; class DataBus { public: unsigned subscription_count() const { return 0; } }; }
EOF

# ---- snort_config.h: same graft recipe as the PROVEN rules_harness shim
# (copy its EOFCFG block verbatim), plus the two members output_text.cc
# touches: real log_verbose() body + LOGGING_FLAG__VERBOSE value pinned
# from upstream snort_config.h:112 (0x00000001).
python3 - "$C" <<'EOFPY'
import sys, re
cdir = sys.argv[1]
build = open("/opt/data/snort3-rust/tools/rules_harness/build.sh").read()
m = re.search(r"cat > \"\$C\"/main/snort_config\.h <<'EOFCFG'\n(.*?)\nEOFCFG\n", build, re.S)
assert m, "EOFCFG block not found in rules_harness build.sh"
shim = m.group(1)
# graft the upstream log_verbose member with its real body+enum value
old = "    static bool log_syslog() { return false; }"
assert shim.count(old) == 1, "shim anchor not unique"
new = ("    enum { LOGGING_FLAG__VERBOSE = 0x00000001 };\n"
       "    static bool log_verbose() { return logging_flags & LOGGING_FLAG__VERBOSE; }\n"
       + old)
shim = shim.replace(old, new, 1)
open(cdir + "/main/snort_config.h", "w").write(shim + "\n")
print("shim grafted with real log_verbose")
EOFPY

CXXFLAGS="-std=c++17 -O0 -w -I$C"

# ---- gate: verbatim upstream suite; it includes output_text.cc itself,
# links verbatim utils.cc; witnesses live in the suite ----
g++ $CXXFLAGS -c "$C"/utils/stats/utils.cc -o "$C"/utils_gate.o
g++ $CXXFLAGS -c "$C"/utils/stats/test/stats_output_text_test.cc -o "$C"/stx_test.o
cat > "$C"/catch_main.cc <<'EOFCM'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOFCM
g++ $CXXFLAGS -c "$C"/catch_main.cc -o "$C"/catch_main.o
g++ "$C"/stx_test.o "$C"/utils_gate.o "$C"/catch_main.o -o "$H"/gate

# ---- probe: verbatim output_text.cc + utils.cc + witnesses ----
g++ $CXXFLAGS -c "$C"/utils/stats/output_text.cc -o "$C"/output_text.o
g++ $CXXFLAGS -c "$C"/utils/stats/utils.cc -o "$C"/utils.o
g++ $CXXFLAGS -c "$H"/probe.cc -o "$C"/probe.o
g++ "$C"/output_text.o "$C"/utils.o "$C"/probe.o -o "$H"/probe

"$H"/probe > "$H"/vectors.txt
"$H"/gate "[stats_output_text]" > "$H"/gate.txt 2>&1 || { tail -25 "$H"/gate.txt; exit 7; }
tail -1 "$H"/gate.txt
echo "STX_HARNESS_OK vectors=$(grep -c '' "$H"/vectors.txt)"
