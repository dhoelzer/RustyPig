#!/bin/bash
# Ground-truth harness for helpers/streambuf: compiles the ORIGINAL
# streambuf.cc together with the ORIGINAL streambuf_test.cc (17 TEST_CASEs /
# 97 sections) using the vendored catch.hpp, no snort runtime deps.
set -e
SRC=/opt/data/snort3-src
H=/opt/data/snort3-rust/tools/streambuf_harness
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{helpers,catch,main}

cp "$SRC"/src/helpers/streambuf.{h,cc} "$C"/helpers/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "$SRC"/src/catch/catch.hpp "$C"/catch/
cp "$SRC"/src/helpers/test/streambuf_test.cc "$C"/helpers/streambuf_test.cc

# the test includes "catch/catch.hpp"; keep that path working
cat > "$H"/test_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF

g++ -std=c++17 -O0 -I"$C" -o "$H/test" \
  "$H"/test_main.cc "$C"/helpers/streambuf_test.cc "$C"/helpers/streambuf.cc

"$H"/test -r compact 2>&1 | tail -40
