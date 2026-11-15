#!/usr/bin/env bash
# Builds a ground-truth probe over the ORIGINAL framework/range.{h,cc}:
# exercises parse()/eval()/validate()/hash() and dumps observable state.
# (The embedded Catch cases in range.cc aren't compiled here; they are
# ported directly to tests/range_test.rs. This probe pins hash() and
# oddball parse cases that upstream tests do not cover.)
set -euo pipefail
S=${S:-/opt/data/snort3-src/src}
D=$(dirname "$0")
C="$D/copy"
rm -rf "$C"
mkdir -p "$C/framework" "$C/main" "$C/hash"
cp "$S/framework/range.h" "$S/framework/range.cc" "$C/framework/"
cp "$S/hash/hash_key_operations.h" "$C/hash/"

# minimal shim for main/snort_types.h
cat > "$C/main/snort_types.h" <<'EOF'
#ifndef SNORT_TYPES_SHIM_H
#define SNORT_TYPES_SHIM_H
#include <cstdint>
#define SO_PUBLIC
#endif
EOF

cat > "$D/probe.cc" <<'EOF'
#include <cstdio>
#include <cstring>
#include "framework/range.h"
using namespace snort;

static const char* cases[] = {
    "5", "=+0x5", "!-5", "!=5", "<5", "<=5", ">5", ">=5",
    "0<>5", "0<=>5", " 10 <> 50 ", "0x10 <=> 0x50", "-0123 <=> 0x123",
    "08", "1<>1", "-0", "+6", "<>5", "4<>2",
    "+9223372036854775808", "-9223372036854775808", "-9223372036854775809",
    "=5", "5 ", "x15", "0x", "000", "10<>10", "1>2",
};

int main()
{
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        RangeCheck rc;
        bool ok = rc.parse(cases[i]);
        if (ok)
            printf("RC %u|%s|%d|%lld|%lld|%u\n", i, cases[i],
                (int)rc.op,(long long)rc.min,(long long)rc.max, rc.hash());
        else
            printf("RC %u|%s|fail\n", i, cases[i]);
    }
    // validate() outcomes with a fresh parse each time
    struct V { const char* s; const char* r; };
    V vs[] = {
        {"2<>4","0:10"},{"2<>4","0"},{"2<>4","1:"},{"2<>4",":8"},
        {"2<>4","0x1:0x0A"},{"2<>4","3:"},{"2<>4","1:3"},{"200<>400","3:10"},
        {">=5","6"},{">=5","7"},{"<5","4"},{">=5",nullptr},
    };
    for (unsigned i = 0; i < sizeof(vs)/sizeof(vs[0]); ++i) {
        RangeCheck rc;
        bool ok = rc.validate(vs[i].s, vs[i].r);
        printf("VA %u|%s|%s|%d|%lld|%lld|%d\n", i, vs[i].s,
            vs[i].r ? vs[i].r : "(null)", ok ? 1 : 0,
            (long long)rc.min,(long long)rc.max,(int)rc.op);
    }
    return 0;
}
EOF

g++ -std=c++17 -I"$C" "$D/probe.cc" "$C/framework/range.cc" -o "$D/probe"
"$D/probe" > "$D/vectors.txt"
cat "$D/vectors.txt"
