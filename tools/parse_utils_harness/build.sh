#!/usr/bin/env bash
# Ground-truth probe over ORIGINAL parser/parse_utils.cc (no upstream suite
# for parse_byte_code). parse_int's 6 embedded Catch sections are ported
# directly; the probe pins ParseError positions, hex-state edges, and errno.
set -euo pipefail
S=${S:-/opt/data/snort3-src/src}
D=$(dirname "$0")
C="$D/copy"
rm -rf "$C"
mkdir -p "$C/parser" "$C/main" "$C/log" "$C/utils"
cp "$S/parser/parse_utils.cc" "$S/parser/parse_utils.h" "$C/parser/"
cat > "$C/main/snort_types.h" <<'EOF'
#ifndef SNORT_TYPES_SHIM_H
#define SNORT_TYPES_SHIM_H
#include <cstdint>
#define SO_PUBLIC
#endif
EOF
cat > "$C/log/messages.h" <<'EOF'
#pragma once
#include <cstdio>
#include <cstdarg>
namespace snort { inline void ParseError(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("ERR ");
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
} }
EOF
cat > "$C/utils/util_cstring.h" <<'EOF'
#pragma once
#include <cstdlib>
#include <cerrno>
inline long SnortStrtol(const char* n, char** e, int b){ errno = 0; return strtol(n, e, b); }
EOF

cat > "$D/probe.cc" <<'EOF'
#include <cstdio>
#include <cstring>
#include <cerrno>
#include "parser/parse_utils.h"

static void hexout(const std::string& s)
{
    for (unsigned char c : s) printf("%02x", c);
}

static void bc(const char* in)
{
    bool neg; std::string out;
    printf("BCIN "); hexout(in); printf("\n");
    bool ok = parse_byte_code(in, neg, out);
    printf("BCOUT %d %d ", ok ? 1 : 0, neg ? 1 : 0);
    hexout(out);
    printf("\n");
}

static void pint(const char* d, const char* tag, int lo, int hi)
{
    errno = 0;
    printf("PIIN "); hexout(d); printf(" %d %d\n", lo, hi);
    int r = parse_int(d, tag, lo, hi);
    printf("PIOUT %d errno=%d\n", r, errno);
}

int main()
{
    bc("\"abc\"");
    bc("!'!|41 42|'");           // leading ! outside quotes
    bc("\"|41 42|\"");
    bc("\"|0|\"");               // single nibble -> 0x0 via nx path? |0|: nx=2? digits...
    bc("\"| |\"");               // space with nx=0 then close pushes? 
    bc("\"|41|\"");              // odd nibble count
    bc("\"|41x|\"");             // bad hex -> error at idx
    bc("\"|041|\"");             // >2 digits flush
    bc("abc");                   // no quotes: state1 sees 'a' not space -> fail at idx=1
    bc("  x  ");                 // leading spaces then junk
    bc("\"a b\"");               // spaces kept in text mode
    bc("\"||\"");                // empty hex run -> nx==0
    bc("\"|ff|\"");              // 0xff
    bc("!\"|ff|\"");             // negate then quoted hex
    bc("\"|ABCDEF|\"");          // uppercase hex
    bc("\"|x41|\"");             // x is not hex digit
    bc("\"|414243|\"");          // six digits two bytes
    bc("\"!|41|\"");             // ! inside quotes stays text
    pint("10  ", "test", -65535, 65535);
    pint("test", "test", -65535, 65535);
    pint("99999999999999999999999999999999999999999999999999", "test", -65535, 65535);
    pint("-9999999999999999999999999999999999999999999999999", "test", -65535, 65535);
    pint("1", "test", 2, 3);
    pint("4", "test", 2, 3);
    pint("+5", "test", -65535, 65535);
    pint("0x10", "test", -65535, 65535);   // base 10: parses 0 then *endptr='x'
    pint("", "test", -65535, 65535);
    pint("-65536", "test", -65535, 65535);
    pint("65536", "test", -65535, 65535);
    return 0;
}
EOF

g++ -std=c++17 -I"$C" "$D/probe.cc" "$C/parser/parse_utils.cc" -o "$D/probe"
"$D/probe" > "$D/vectors.txt"
cat "$D/vectors.txt"
