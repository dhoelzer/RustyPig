#!/usr/bin/env bash
# Ground-truth probe + Catch gate over ORIGINAL framework/codec.{h,cc}
# (Buffer inside-out encoder buffer, EncState::get_ttl, CodecData fields,
# CheckIPV6HopOptions + CheckIPv6ExtensionOrder + codec_event). No upstream
# suites for the two IPv6 helpers; upstream DOES ship 4 [buffer] Catch2
# TEST_CASEs inside codec.cc (UNIT_TEST) -> compiled as the gate.
# Witness seams (logged as deviations): detection/detection_engine.h
# (queue_event witness prints 'EV gid sid' instead of the ips_context
# queue), framework/module.h (fwd class Module only; plugin machinery not
# linked), catch/snort_catch.h -> plain-catch shim (upstream's
# TestCaseInstaller needs the snort main binary; the four [buffer] cases
# register identically with plain catch). Everything else (codec.{h,cc},
# decode_data.h, base_api.h, codec_module.h, ip.{h,cc}, ipv4.h, ipv6.h,
# layer.{h,cc}, mpls.h, protocol_ids.h, sf_ip.{h,cc}, sf_returns.h,
# cpp_macros.h, snort_types.h) is ORIGINAL code compiled verbatim.
set -euo pipefail
SRC=/opt/data/snort3-src
H=$(cd "$(dirname "$0")" && pwd)
C=$H/copy
rm -rf "$C"
mkdir -p "$C"/{framework,codecs,detection,main,protocols,sfip,utils,catch}

cp "$SRC"/src/framework/{codec.h,codec.cc,decode_data.h,base_api.h} "$C"/framework/
cp "$SRC"/src/codecs/codec_module.h "$C"/codecs/
cp "$SRC"/src/protocols/{ip.h,ip.cc,ipv4.h,ipv6.h,layer.h,mpls.h,protocol_ids.h} "$C"/protocols/
cp "$SRC"/src/sfip/{sf_ip.h,sf_ip.cc,sf_cidr.h,sf_returns.h} "$C"/sfip/
cp "$SRC"/src/utils/{cpp_macros.h,bits.h,util.h,util_cstring.h,util_cstring.cc,util_net.h} "$C"/utils/
cp "$SRC"/src/utils/bits.h "$C"/utils/
cp "$SRC"/src/main/snort_types.h "$C"/main/
cp "/opt/data/snort3-rust/tools/rules_harness/copy/catch/catch.hpp" "$C"/catch/
cp "$H"/catch_shim_snort_catch.h "$C"/catch/snort_catch.h
mkdir -p "$C"/log
printf '#pragma once\n#include <cstdarg>\nnamespace snort {\nvoid LogMessage(const char*, ...);\nvoid ErrorMessage(const char*, ...);\n}\n' > "$C"/log/messages.h

printf '#pragma once\n' > "$C"/config.h
printf '#pragma once\n#define API_OPTIONS 0\n' > "$C"/framework/api_options.h
cp "$SRC"/src/framework/{counts.h,parameter.h,value.h,module.h} "$C"/framework/
cp "$SRC"/src/main/thread.h "$C"/main/
printf '#pragma once\n#include <cstdint>\nnamespace snort {\nclass DetectionEngine {\npublic:\n    static int queue_event(unsigned gid, unsigned sid);\n};\n}\n' > "$C"/detection/detection_engine.h

CXXFLAGS="-std=c++17 -O0 -w -I$C"
OBJS=""
for f in framework/codec.cc protocols/ip.cc sfip/sf_ip.cc utils/util_cstring.cc; do
    g++ $CXXFLAGS -c "$C"/$f -o "$C"/$(basename $f .cc).o
    OBJS="$OBJS $C/$(basename $f .cc).o"
done
g++ $CXXFLAGS -c "$H"/probe.cc -o "$C"/probe.o
g++ $CXXFLAGS -c "$H"/stubs.cc -o "$C"/event_witness.o

cat > "$C"/catch_main.cc <<'EOF'
#define CATCH_CONFIG_MAIN
#include "catch/catch.hpp"
EOF
g++ $CXXFLAGS -DUNIT_TEST -c "$C"/framework/codec.cc -o "$C"/codec_ut.o
g++ $CXXFLAGS -DUNIT_TEST -c "$C"/catch_main.cc -o "$C"/catch_main.o

g++ $OBJS "$C"/probe.o "$C"/event_witness.o -o "$H"/probe
# gate links the -DUNIT_TEST TU (codec_ut.o) INSTEAD of codec.o: same file,
# one symbol set + the four [buffer] TEST_CASE registrations.
OBJS_UT=$(echo "$OBJS" | sed "s#$C/codec.o##")
g++ $OBJS_UT "$C"/codec_ut.o "$C"/catch_main.o "$C"/event_witness.o -o "$H"/gate

"$H"/probe > "$H"/vectors.txt
"$H"/gate "[buffer]" > "$H"/gate.txt 2>&1 || { tail -30 "$H"/gate.txt; exit 7; }
tail -1 "$H"/gate.txt
echo "CODEC_HARNESS_OK vectors=$(grep -c '' "$H"/vectors.txt) gate=[buffer]"
