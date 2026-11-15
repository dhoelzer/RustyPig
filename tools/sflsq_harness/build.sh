#!/usr/bin/env bash
# Builds a ground-truth probe over the ORIGINAL utils/sflsq.cc (no upstream
# unit suite exists): dumps count/head/tail/data sequences through the whole
# API incl. add_before delegation and the first/next advance protocol.
set -euo pipefail
S=${S:-/opt/data/snort3-src/src}
D=$(dirname "$0")
C="$D/copy"
rm -rf "$C"
mkdir -p "$C/utils" "$C/main"
cp "$S/utils/sflsq.h" "$S/utils/sflsq.cc" "$C/utils/"
cat > "$C/main/snort_types.h" <<'EOF'
#ifndef SNORT_TYPES_SHIM_H
#define SNORT_TYPES_SHIM_H
#include <cstdint>
#define SO_PUBLIC
#endif
EOF
cat > "$C/utils/util.h" <<'EOF'
#pragma once
#include <cstdlib>
#include <cstring>
inline void* snort_calloc(size_t n){ return calloc(1,n); }
inline void* snort_alloc(size_t n){ return malloc(n); }
inline void snort_free(void* p){ free(p); }
EOF

cat > "$D/probe.cc" <<'EOF'
#include <cstdio>
extern "C" {}
#include "utils/sflsq.h"
using namespace snort;

static void dump(SF_LIST* s, const char* tag)
{
    printf("%s cnt=%u", tag, s->count);
    SF_LNODE* n = s->head;
    while (n) { printf(" %ld", (long)n->ndata); n = n->next; }
    printf("\n");
}

int main()
{
    SF_LIST* s = sflist_new();
    dump(s, "new");
    sflist_add_tail(s,(NODE_DATA)1);
    sflist_add_tail(s,(NODE_DATA)2);
    sflist_add_head(s,(NODE_DATA)0);
    sflist_add_head(s,(NODE_DATA)-1);
    dump(s,"hh/tt");

    // iterator protocol
    SF_LNODE* c;
    long d = (long)sflist_first(s,&c);
    printf("first %ld\n", d);
    while ((d = (long)sflist_next(&c)) != 0) printf("next %ld\n", d);
    printf("next-end %ld cursor-null=%d\n", (long)sflist_next(&c), c==nullptr);

    // remove head/tail
    printf("rmh %ld cnt=%u\n",(long)sflist_remove_head(s), s->count);
    printf("rmt %ld cnt=%u\n",(long)sflist_remove_tail(s), s->count);
    dump(s,"mid");

    // add_before delegations
    SF_LNODE* c2;
    (void)sflist_first(s,&c2);           // head
    sflist_add_before(s,c2,(NODE_DATA)100); // head -> add_head
    (void)sflist_first(s,&c2);
    sflist_next(&c2);                     // second node
    sflist_add_before(s,c2,(NODE_DATA)200);
    sflist_add_before(s,nullptr,(NODE_DATA)999); // null -> no-op
    dump(s,"before");

    // drain
    while (sflist_count(s)) printf("drain %ld\n",(long)sflist_remove_head(s));
    dump(s,"empty");
    printf("rmh-empty %ld\n", (long)sflist_remove_head(s));
    printf("rmt-empty %ld\n", (long)sflist_remove_tail(s));

    // single node add/removal updates both head and tail
    sflist_add_head(s,(NODE_DATA)42);
    dump(s,"one");
    sflist_remove_head(s);
    dump(s,"empty2");
    sflist_free(s);
    return 0;
}
EOF

g++ -std=c++17 -I"$C" "$D/probe.cc" "$C/utils/sflsq.cc" -o "$D/probe"
"$D/probe" > "$D/vectors.txt"
cat "$D/vectors.txt"
