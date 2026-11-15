#!/usr/bin/env bash
# Ground-truth probe over ORIGINAL parser/arg_list.cc (no upstream suite):
# replays get_arg() sequences per argv, incl the FIXIT-L "-n -4" rollback,
# "--" -> empty pending arg, bare "-", and the trailing-pending flush.
set -euo pipefail
S=${S:-/opt/data/snort3-src/src}
D=$(dirname "$0")
C="$D/copy"
rm -rf "$C"
mkdir -p "$C/parser"
cp "$S/parser/arg_list.cc" "$S/parser/arg_list.h" "$C/parser/"
sed -i 's/#include "config.h"//' "$C/parser/arg_list.cc"

cat > "$D/probe.cc" <<'EOF'
#include <cstdio>
#include <cstring>
#include "parser/arg_list.h"

static void dump(const char* const* v, const char* tag)
{
    int n = 0; while (v[n]) ++n;
    ArgList al(n, const_cast<char**>(v));
    printf("ARGV %s", tag);
    for (int i = 0; i < n; ++i) printf(" [%s]", v[i]);
    printf("\n");
    const char* key; const char* val;
    int guard = 0;
    while (al.get_arg(key, val)) {
        printf("GA (%s)=(%s)\n", key, val);
        if (++guard > 64) { printf("GA LOOP\n"); break; }
    }
    printf("GA end\n");
}

int main()
{
    // argv[0] is the program-name slot: C ArgList starts at idx=1.
    { const char* v[] = {"prog","-i","eth0","--pcap","f.pcap","-v",nullptr}; dump(v,"a"); }
    { const char* v[] = {"prog","-n","-4",nullptr}; dump(v,"b"); }        // FIXIT-L case
    { const char* v[] = {"prog","-sABC",nullptr}; dump(v,"c"); }
    { const char* v[] = {"prog","--",nullptr}; dump(v,"d"); }             // empty pending
    { const char* v[] = {"prog","-",nullptr}; dump(v,"e"); }              // bare dash
    { const char* v[] = {"prog","-o","x","-p",nullptr}; dump(v,"f"); }
    { const char* v[] = {"prog","--long=val=ue",nullptr}; dump(v,"g"); }  // first = splits
    { const char* v[] = {"prog","--novalue","next",nullptr}; dump(v,"h"); }
    { const char* v[] = {"prog","plain","args",nullptr}; dump(v,"i"); }
    { const char* v[] = {"prog","-x","--y","-z",nullptr}; dump(v,"j"); }
    { const char* v[] = {"prog","pos1","-a","pos2",nullptr}; dump(v,"k"); }
    { const char* v[] = {"prog",nullptr}; dump(v,"empty"); }
    { const char* v[] = {"prog","-","-",nullptr}; dump(v,"ll"); }         // two bare dashes
    { const char* v[] = {"prog","-4","-n",nullptr}; dump(v,"m"); }        // reverse of FIXIT-L
    { const char* v[] = {"prog","-x1","-y2","-z",nullptr}; dump(v,"n"); } // attached vals on short opts
    { const char* v[] = {"prog","--a=","b",nullptr}; dump(v,"o"); }       // empty after =
    return 0;
}
EOF

g++ -std=c++17 -I"$C" "$D/probe.cc" "$C/parser/arg_list.cc" -o "$D/probe"
"$D/probe" > "$D/vectors.txt"
cat "$D/vectors.txt"
