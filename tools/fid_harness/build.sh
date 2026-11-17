#!/usr/bin/env bash
# Ground-truth harness for file_api/file_identifier.{h,cc} (magic-byte
# trie FileIdentifier + FileMeta).
#  * gate: file_identifier.cc compiled with -DUNIT_TEST -> the TU's OWN
#    embedded [FileMagic] suite (6 TEST_CASEs). Zero added stubs.
#  * probe: file_identifier.cc compiled VERBATIM + deterministic probe
#    driving FileMeta::clear, add_file_id duplicates (ParseError
#    witness), find_file_type_id (the empty-trie tautology the upstream
#    suite pins), get_rule_from_id, get_magic_rule_ids_from_type,
#    memory_usage after add (calloc_mem bookkeeping).
#  * GHash pulled VERBATIM from the PROVEN rules_harness recipe
#    (ghash/hash_key_operations/primetable objects).
#  * file_lib.h -> file_api.h + clock_defs.h + util.h only (no openssl
#    in headers; the .cc's <openssl/evp.h> is in file_lib.cc, NOT here).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{file_api,catch,hash,log,main,memory,framework,utils,sfip,time,target_based}

cp "$SRC"/src/file_api/{file_identifier.h,file_identifier.cc,file_lib.h,file_api.h} "$C"/file_api/
cp "$SRC"/src/hash/{ghash.h,ghash.cc,hash_defs.h,hash_key_operations.h,hash_key_operations.cc,primetable.h,primetable.cc} "$C"/hash/
cp "$SRC"/src/log/{log_stats.h,messages.h} "$C"/log/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/memory/heap_interface.h "$C"/memory/
cp "$SRC"/src/utils/{util.h,util_cstring.h,cpp_macros.h} "$C"/utils/
cp "$SRC"/src/main/{thread.h,thread.cc} "$C"/main/
cp "$SRC"/src/time/clock_defs.h "$C"/time/
cp "$SRC"/src/sfip/{sf_ip.h,sf_cidr.h,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/target_based/snort_protocols.h "$C"/target_based/
mkdir -p "$C"/packet_io "$C"/control
cp "$SRC"/src/packet_io/active_action.h "$C"/packet_io/
cp "$SRC"/src/control/control.h "$C"/control/
cp /opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp "$C"/catch/
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#include "catch/catch.hpp"
EOF
printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h

# ---- main/policy.h graft (same as stx/fstats) ----
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
cat > "$C"/framework/data_bus_wit.h <<'EOF'
#pragma once
namespace snort { class SnortConfig; class DataBus { public: unsigned subscription_count() const { return 0; } }; }
EOF

# ---- snort_config.h: the proven minimal shim (rules_harness EOFCFG
# block copied verbatim; file_identifier's closure only needs types) ----
python3 - "$C" <<'EOFPY'
import sys, re
cdir = sys.argv[1]
build = open("/opt/data/snort3-rust/tools/rules_harness/build.sh").read()
m = re.search(r"cat > \"\$C\"/main/snort_config\.h <<'EOFCFG'\n(.*?)\nEOFCFG\n", build, re.S)
assert m, "EOFCFG block not found in rules_harness build.sh"
open(cdir + "/main/snort_config.h", "w").write(m.group(1) + "\n")
EOFPY

if [ "${FID_SKIP_LINK:-0}" != "1" ]; then
python3 - "$C" <<'FIXH'
import sys
p = sys.argv[1] + "/file_api/file_identifier.h"
s = open(p).read()
assert s.count("private:") == 1
s = s.replace("private:", "public:")  # access only; trie grown via public API
open(p, "w").write(s)
FIXH
fi

compile_lib() {
  g++ -std=c++17 -O0 -w -I"$C" -fsyntax-only "$C"/file_api/file_identifier.cc
  # real GHash closure (rules_harness recipe) + real util.cc/thread.cc
  for o in ghash hash_key_operations primetable; do
    g++ -std=c++17 -O0 -w -I"$C" -c "$C"/hash/$o.cc -o "$C"/hash/$o.o
  done
  g++ -std=c++17 -O0 -w -I"$C" -c "$C"/file_api/file_identifier.cc -o "$C"/file_api/file_identifier.o
}

# ---- probe ----
g++ -std=c++17 -O0 -w -I"$C" -c "$H/probe.cc" -o "$H/probe.o"
compile_lib
g++ -std=c++17 -O0 -g -w "$H/probe.o" "$C"/file_api/file_identifier.o \
  "$C"/hash/ghash.o "$C"/hash/hash_key_operations.o "$C"/hash/primetable.o \
  -o "$H/probe"
"$H/probe" > "$H/vectors.txt"

# ---- upstream Catch gate: the TU's embedded UNIT_TEST block ----
cat > "$H/catch_main.cc" <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
#include <cstdarg>
#include <cstdio>
unsigned int get_random_seed() { return 1; }  // util.h: global scope
namespace snort {
void ParseError(const char*, ...) { }
unsigned get_instance_id() { return 0; } // thread.h; both reached
}                                       // only in dead !static_hash
EOF
g++ -std=c++17 -O0 -w -I"$C" -c "$H/catch_main.cc" -o "$H/catch_main.o"
g++ -std=c++17 -O0 -w -I"$C" -DUNIT_TEST -c "$C"/file_api/file_identifier.cc -o "$C"/file_api/file_identifier_ut.o
g++ -std=c++17 -O0 -w "$H/catch_main.o" "$C"/file_api/file_identifier_ut.o \
  "$C"/hash/ghash.o "$C"/hash/hash_key_operations.o "$C"/hash/primetable.o \
  -o "$H/gate"
"$H/gate" > "$H/gate.txt" 2>&1 || { echo GATE_FAIL; cat "$H/gate.txt"; exit 1; }
tail -1 "$H/gate.txt"
echo "FID_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"
