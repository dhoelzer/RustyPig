// Ground truth for the hash layer: static-hash HashKeyOperations,
// mix_str/finalize, str_to_hash, GHash behavior.
#include <cstdio>
#include <cstring>
#include "hash/ghash.h"
#include "hash/hash_key_operations.h"
#include "hash/hash_defs.h"
#include "hash/primetable.h"
using namespace snort;

static void emit_hko(HashKeyOperations& h, const char* key) {
    printf("HK %s ", key);
    printf("%u ", h.do_hash((const unsigned char*)key, (int)strlen(key)+1));
    printf("%u\n", h.do_hash((const unsigned char*)key, 0));
}

int main() {
    // 1) nearest_prime parity table
    int vs[] = {-100,0,4,100,-10,-4,4095,8191,8192,8193,40000,65535,65536,
                100000,1048575,1048576,2000000,70000000,134217728,200000001,
                1073741823,1073741824,2000000000,-2147483647,997,9871,500};
    for (int v : vs) printf("NP %d %d\n", v, nearest_prime(v));

    // 2) hash_key_operations with static constants (seed 3193 scale 719
    //    hardener 133824503); do_hash with strlen+1 and 0
    HashKeyOperations h(1009);
    const char* keys[] = {"", "a", "KeyWord1", "KeyWord100", "hello", "snort",
        "101010101010101010101010101010101010101010101010101010101010101"};
    for (auto k : keys) emit_hko(h, k);

    // 3) mix_str + finalize (the IpsOption::hash path; n==0 => strlen)
    for (auto k : keys) {
        uint32_t a=0,b=0,c=0;
        mix_str(a,b,c,k);
        finalize(a,b,c);
        printf("MS %s %u %u %u\n", k, a, b, c);
    }

    // 4) str_to_hash including embedded NUL / arbitrary bytes
    const char t[] = {'h','i',0,'x'};
    printf("SH %d %u\n", 4, str_to_hash((const uint8_t*)t, 4));
    printf("SH %d %u\n", 0, str_to_hash((const uint8_t*)t, 0));
    printf("SH %d %u\n", 1, str_to_hash((const uint8_t*)t, 1));

    // 5) GHash string-key table: insert 30 keys with deliberate collision
    //    (nrows=-10 => nrows=10 literally, NOT primed), dump iteration
    //    order and data pointers, duplicate insert, removals.
    {
        // C quirk: GHash(0,...) yields nrows=0 (allocation of 0 rows, and
        // get_index would divide by zero). Construct + destroy only; never
        // insert/find. Pinned as a deviation note in Rust.
        GHash* t = new GHash(0, 0, false, nullptr);
        printf("GH nrows0 constructed\n");
        delete t;
    }
    char keys2[30][32];
    // 5a) fresh collision table: insert 30 + dup, dump iteration fully
    {
        GHash* g = new GHash(-10, 0, false, nullptr);
        for (int i = 0; i < 30; i++) {
            snprintf(keys2[i], 32, "KeyWord%d", i + 1);
            int r = g->insert(keys2[i], (void*)(size_t)(i + 100));
            printf("A ins %d %d\n", i, r);
        }
        int r = g->insert("KeyWord1", (void*)(size_t)999);
        printf("A dup %d\n", r);
        printf("A cnt %u\n", g->get_count());
        int idx = 0;
        for (const GHashNode* n = g->find_first(); n; n = g->find_next())
            printf("A it %d %s %ld\n", idx++, (const char*)n->key, (long)(size_t)n->data);
        printf("A endcnt %u\n", g->get_count());
        void* p = g->find("KeyWord17");
        printf("A find17 %ld\n", (long)(size_t)p);
        printf("A rm-miss %d\n", g->remove("Nope"));
        // remove KeyWord17 then dump again
        printf("A rm17 %d\n", g->remove("KeyWord17"));
        printf("A cnt2 %u\n", g->get_count());
        idx = 0;
        for (const GHashNode* n = g->find_first(); n; n = g->find_next())
            printf("A it2 %d %s\n", idx++, (const char*)n->key);
        delete g;
    }
    // 5b) fresh table: find_first, find_next, remove THAT node via the
    //     for-increment pattern from the upstream tests (remove(n->key)
    //     inside the loop body) — first two removals exactly.
    {
        GHash* g = new GHash(-10, 0, false, nullptr);
        for (int i = 0; i < 30; i++) {
            snprintf(keys2[i], 32, "KeyWord%d", i + 1);
            g->insert(keys2[i], (void*)(size_t)(i + 100));
        }
        int idx = 0;
        for (const GHashNode* n = g->find_first(); n; n = g->find_next()) {
            // upstream pattern reads n->key as the ARGUMENT of remove();
            // snapshot the key before removal to avoid pinning freed heap
            // bytes (the old version printed post-free "(null)").
            char snap[32];
            snprintf(snap, sizeof(snap), "%s", (const char*)n->key);
            int rr = g->remove(n ? n->key : n->key);   // n->key is now dangling; snap used
            printf("B rem %d %s %d %u\n", idx, snap, rr, g->get_count());
            idx++;
            if (idx >= 3) break;
        }
        idx = 0;
        for (const GHashNode* n = g->find_first(); n; n = g->find_next())
            printf("B it %d %s\n", idx++, (const char*)n->key);
        delete g;
    }
        // 6) binary-key table keysize=4, plus userkey ownership mode
    GHash* b = new GHash(100, 4, false, nullptr);
    uint8_t k1[4] = {1,2,3,4}, k2[4] = {1,2,3,5}, k3[4] = {1,2,3,4};
    printf("GH ins-b %d\n", b->insert(k1, (void*)(size_t)7));
    printf("GH dup-b %d\n", b->insert(k3, (void*)(size_t)8)); // same bytes
    printf("GH find-b %ld\n", (long)(size_t)b->find(k2));     // mismatch -> null
    printf("GH find-b2 %ld\n", (long)(size_t)b->find(k3));    // match -> 7
    printf("GH rm-b %d\n", b->remove(k2));
    delete b;

}
