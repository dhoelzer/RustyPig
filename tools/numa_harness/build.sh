#!/usr/bin/env bash
# Ground-truth harness for main/numa.{h,cc} (NumaMemPolicy <-> string).
#  * gate: numa.cc's OWN embedded UNIT_TEST suite (3 TEST_CASEs) under
#    the plain Catch shim (upstream snort_catch.h needs main-binary
#    TestCaseInstallers -- same shim as other harnesses).
#  * probe: numa.cc compiled VERBATIM; only the three external headers
#    numa.h / numaif.h / hwloc.h are witnessed. The NumaMemPolicy
#    ENUMERATOR VALUES come from the REAL kernel UAPI header
#    <linux/mempolicy.h> via the numaif witness (MPOL_* enum), NOT from
#    invented constants. NumaWrapper/HwlocWrapper inline bodies need
#    only declarations (probe never calls them; link-clean).
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{main,catch,wit}

cp "$SRC"/src/main/{numa.h,numa.cc} "$C"/main/
cp "/opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp" "$C"/catch/
printf '#pragma once\n' > "$C"/config.h

# numa.cc's UNIT_TEST block includes catch/snort_catch.h -> plain shim
cat > "$C"/catch/snort_catch.h <<'EOF'
#pragma once
#include "catch/catch.hpp"
EOF

# graft numa.h's three external includes to witnesses
sed -i 's|#include <numa.h>|#include "wit/numa_wit.h"|; s|#include <numaif.h>|#include "wit/numaif_wit.h"|; s|#include <hwloc.h>|#include "wit/hwloc_wit.h"|' "$C"/main/numa.h

# numaif witness: the MPOL_* enumerators are a REAL kernel ABI contract;
# pull the real UAPI enum rather than restating it.
cat > "$C"/wit/numaif_wit.h <<'EOF'
#pragma once
#include <cstdint>             // upstream numa/hwloc headers provide this
                               // transitively; numa.h uses uint8_t directly
#include <linux/mempolicy.h>   // real MPOL_DEFAULT..MPOL_LOCAL enum
EOF

# libnuma witness: declarations only (wrappers never invoked in probe).
cat > "$C"/wit/numa_wit.h <<'EOF'
#pragma once
extern "C" {
int numa_available();
int numa_max_node();
int set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
}
EOF

# hwloc witness: opaque types + declarations only.
cat > "$C"/wit/hwloc_wit.h <<'EOF'
#pragma once
typedef struct hwloc_topology* hwloc_topology_t;
typedef struct hwloc_obj* hwloc_obj_t;
typedef enum { HWLOC_OBJ_NUMANODE } hwloc_obj_type_t;
typedef struct hwloc_bitmap* hwloc_bitmap_t;
typedef const struct hwloc_bitmap* hwloc_const_cpuset_t;
extern "C" {
unsigned hwloc_get_nbobjs_by_depth(hwloc_topology_t, int);
hwloc_obj_t hwloc_get_obj_by_depth(hwloc_topology_t, int, unsigned);
int hwloc_get_type_depth(hwloc_topology_t, hwloc_obj_type_t);
int hwloc_bitmap_isincluded(hwloc_const_cpuset_t, hwloc_const_cpuset_t);
int hwloc_bitmap_iszero(hwloc_const_cpuset_t);
}
EOF

g++ -std=c++17 -O0 -w -I"$C" -c "$C"/main/numa.cc -o "$H/numa.o"
g++ -std=c++17 -O0 -w -I"$C" -c "$H/probe.cc" -o "$H/probe.o"
g++ -std=c++17 -O0 -w -I"$C" "$H/probe.o" "$H/numa.o" -o "$H/probe"
"$H/probe" > "$H/vectors.txt"

# ---- upstream Catch gate: embedded UNIT_TEST in numa.cc ----
cat > "$H/catch_main.cc" <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
g++ -std=c++17 -O0 -w -I"$C" -c "$H/catch_main.cc" -o "$H/catch_main.o"
g++ -std=c++17 -O0 -w -I"$C" -DUNIT_TEST -c "$C"/main/numa.cc -o "$H/numa_ut.o"
g++ -std=c++17 -O0 -w "$H/catch_main.o" "$H/numa_ut.o" -o "$H/gate"
"$H/gate" > "$H/gate.txt" 2>&1 || { echo GATE_FAIL; cat "$H/gate.txt"; exit 1; }
tail -1 "$H/gate.txt"
echo "NUMA_HARNESS_OK vectors=$(wc -l < "$H/vectors.txt")"
