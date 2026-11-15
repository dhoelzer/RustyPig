#!/bin/bash
# Ground-truth harness for utils/util_unfold.cc's untested functions
# (sf_strip_CRLF / sf_strip_LWS; sf_unfold_header is covered by the
# embedded Catch2 sections). Compiles the ORIGINAL source verbatim.
set -e
SRC=/opt/data/snort3-src
H=/opt/data/snort3-rust/tools/unfold_harness
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{utils,main}

cp "$SRC"/src/utils/util_unfold.{h,cc} "$C"/utils/
cp "$SRC"/src/main/snort_types.h "$C"/main/

g++ -std=c++17 -O0 -I"$C" -o "$H/harness" \
  "$H"/harness.cc "$C"/utils/util_unfold.cc

"$H"/harness > "$H"/vectors.txt
wc -l "$H"/vectors.txt
