#!/usr/bin/env bash
# Ground-truth harness for file_api/file_stats.{h,cc} (file stats
# snapshot collection: FileCounts/FileStats aggregates -> stats Builder).
#  * gate: the ORIGINAL upstream suite src/file_api/test/file_stats_test.cc
#    compiled VERBATIM -- like stats_output_text_test it #includes
#    ../file_stats.cc directly and ships its own file_type_name /
#    FileCapture / FileService static / FileCache witnesses. Zero
#    added stubs for the gate.
#  * probe: file_stats.cc compiled VERBATIM against the same witness
#    style (probe supplies its own definitions so it can flip
#    file_signature_enabled / feed cache counters), dumping the built
#    snapshot structurally between markers. Header closure grafted from
#    the PROVEN stx/rules recipes; detection_engine.h + file_mime
#    inline bodies never run in-probe, so a declaration witness covers
#    the missing <openssl> dep chain of file_lib (file_lib here is the
#    header-only shape the closure needs: FileInfo decls unused).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{file_api/test,framework,log,main,memory,control,catch,mime,sfip,utils,utils/stats,time,packet_io}

cp "$SRC"/src/file_api/{file_api.h,file_lib.h,file_config.h,file_identifier.h,file_service.h,file_capture.h,file_cache.h,file_stats.h,file_stats.cc} "$C"/file_api/
cp "$SRC"/src/file_api/test/file_stats_test.cc "$C"/file_api/test/
cp "$SRC"/src/framework/counts.h "$C"/framework/
cp "$SRC"/src/utils/stats/{snapshot.h,utils.h} "$C"/utils/stats/
cp "$SRC"/src/utils/{util.h,util_cstring.h,cpp_macros.h} "$C"/utils/
cp "$SRC"/src/log/{log_stats.h,messages.h} "$C"/log/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/time/clock_defs.h "$C"/time/
cp "$SRC"/src/sfip/{sf_ip.h,sf_cidr.h,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/memory/{heap_interface.h,memory_cap.h} "$C"/memory/
cp "$SRC"/src/control/control.h "$C"/control/
cp "$SRC"/src/mime/file_mime_config.h "$C"/mime/
cp "$SRC"/src/packet_io/active_action.h "$C"/packet_io/
cp "/opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp" "$C"/catch/
printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h

# FileService keeps the two statics the witnesses define private, and
# the probe must flip file_signature_enabled through the production
# is_file_signature_enabled(). Graft the class to public (same
# recipe/scope discipline as the policy.h graft); the upstream gate
# itself never touches privates, only the definitions above, so the
# gate semantics are unaffected.
python3 - "$C" <<'FIXFS'
import sys
p = sys.argv[1] + "/file_api/file_service.h"
s = open(p).read()
blk = s.index("class SO_PUBLIC FileService")
end = s.index("};", s.index("static FileCache* file_cache;", blk))
seg = s[blk:end].replace("private:", "public:")
s = s[:blk] + seg + s[end:]
open(p, "w").write(s)
FIXFS

# file_config.h includes detection_engine.h for .cc-side flush APIs only;
# header needs nothing from it -> witness.
printf '#pragma once\n' > "$C"/framework/detection_engine_wit.h
sed -i 's|#include "detection/detection_engine.h"|#include "framework/detection_engine_wit.h"|' "$C"/file_api/file_config.h
cp "$SRC"/src/detection/detection_buf.h "$C"/framework/ 2>/dev/null || true

# ---- main/policy.h graft (same as stx/rules) ----
cp "$SRC"/src/main/policy.h "$C"/main/
cp "$SRC"/src/framework/{ips_action.h,base_api.h} "$C"/framework/
python3 - "$C" <<'FIXPOLICY'
import sys
p = sys.argv[1] + "/main/policy.h"
s = open(p).read()
s = s.replace('#include "framework/data_bus.h"', '#include "framework/data_bus_wit.h"')
s = s.replace('#include "framework/mp_data_bus.h"', '')
blk = s.index("class PolicyMap")
end = s.index("};", blk)
seg = s[blk:end].replace("private:", "public:")
s = s[:blk] + seg + s[end:]
open(p, "w").write(s)
FIXPOLICY
mkdir -p "$C"/framework
cat > "$C"/framework/data_bus_wit.h <<'EOF'
#pragma once
namespace snort { class SnortConfig; class DataBus { public: unsigned subscription_count() const { return 0; } }; }
EOF

# ---- snort_config.h: proven rules_harness shim (EOFCFG block reused) ----
mkdir -p "$C"/target_based
cp "$SRC"/src/target_based/snort_protocols.h "$C"/target_based/
python3 - "$C" <<'EOFPY'
import sys, re
cdir = sys.argv[1]
build = open("/opt/data/snort3-rust/tools/rules_harness/build.sh").read()
m = re.search(r"cat > \"\$C\"/main/snort_config\.h <<'EOFCFG'\n(.*?)\nEOFCFG\n", build, re.S)
assert m, "EOFCFG block not found in rules_harness build.sh"
shim = m.group(1)
# file_config.h needs SnortProtocolId/UNKNOWN_PROTOCOL_ID; real
# snort_config.h pulls target_based/snort_protocols.h in upstream
# closure, the rules_harness shim does not -> graft verbatim header.
assert '#include "target_based/snort_protocols.h"' not in shim
anchor = shim.index("\n", shim.index("#include")) + 1
shim = shim[:anchor] + '#include "target_based/snort_protocols.h"\n' + shim[anchor:]
open(cdir + "/main/snort_config.h", "w").write(shim + "\n")
EOFPY

# probe #includes file_stats.cc (upstream-test trick for file-statics
# access) -> single TU, no separate object, no duplicate symbols.
compile_all() {
  g++ -std=c++17 -O0 -w -I"$C" -c "$H/probe.cc" -o "$H/probe.o"
  g++ -std=c++17 -O0 -g -w "$H/probe.o" -o "$H/probe"
}

g++ -std=c++17 -O0 -w -I"$C" -fsyntax-only "$C"/file_api/file_stats.cc 2>"$H/syntax.log" || { echo SYNTAX_FAIL; head -60 "$H/syntax.log"; exit 1; }

compile_all
"$H/probe" > "$H/vectors.txt"

# ---- upstream Catch gate: the ORIGINAL test verbatim ----
cat > "$H/catch_main.cc" <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
g++ -std=c++17 -O0 -w -I"$C" -c "$H/catch_main.cc" -o "$H/catch_main.o"
g++ -std=c++17 -O0 -w -I"$C" -c "$C"/file_api/test/file_stats_test.cc -o "$H/test_ut.o"
g++ -std=c++17 -O0 -w "$H/catch_main.o" "$H/test_ut.o" -o "$H/gate"
"$H/gate" > "$H/gate.txt" 2>&1 || { echo GATE_FAIL; cat "$H/gate.txt"; exit 1; }
tail -1 "$H/gate.txt"
echo "FSTATS_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"
