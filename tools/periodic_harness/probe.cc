// Ground-truth probe for time/periodic.cc: priority-sorted handler list
// with countdown. All observable state flows through WHICH hooks fire on
// WHICH check() tick (the hook prints its arg value at CALL time), so the
// insertion order, cadence, and deregistration quirks all surface.
// Quirks pinned here:
//  * equal-priority insert goes BEFORE existing equal nodes (while
//    it->priority < priority, insert before first >=) -> LIFO per priority
//  * after firing, time_left = period (not period-1), so period p fires
//    once every p+1 checks (p=0 fires every check)
//  * unregister_handler removes by HOOK POINTER identity (all nodes with
//    that fn), regardless of arg
//  * hook arg pointer is dereferenced at fire time (value may have changed)
#include <cstdio>
#include <vector>

#include "time/periodic.h"

static std::vector<int> s_fired;

static void h1(void* p) { s_fired.push_back(*(int*)p); }
static void h2(void* p) { s_fired.push_back(100 + *(int* )p); }

static int s_label[8];  // mutable slots: deref-at-fire-time pin

static void dump(const char* tag)
{
    printf("%s fired:", tag);
    for (size_t i = 0; i < s_fired.size(); ++i)
        printf(" %d", s_fired[i]);
    printf("\n");
    s_fired.clear();
}

int main()
{
    for (int i = 0; i < 8; ++i) s_label[i] = i + 1;

    // P0: check on empty list -> nothing
    Periodic::check();
    dump("P0");

    // P1: insert band. Final list expected:
    // [L3(pri1), L2(pri5), L1(pri5), L4(pri7)]  (equal-pri LIFO)
    Periodic::register_handler(h1, &s_label[0], 5, 1);   // L1=1
    Periodic::register_handler(h1, &s_label[1], 5, 2);   // L2=2 (before L1)
    Periodic::register_handler(h1, &s_label[2], 1, 3);   // L3=3 (head)
    Periodic::register_handler(h1, &s_label[3], 7, 0);   // L4=4 (tail, period 0)
    for (int k = 1; k <= 8; ++k)
    {
        Periodic::check();
        dump("P1");
        if ( k == 2 )
            s_label[1] = 99;  // deref-at-fire: L2 next fire prints 99
    }

    // P2: unregister a hook that was never registered -> no change
    Periodic::unregister_handler(h2);
    for (int k = 1; k <= 4; ++k)
    {
        Periodic::check();
        dump("P2");
    }

    // P3: register h2 twice (same fn pointer, different args/periods) and
    // one h1; unregister h2 removes BOTH h2 nodes in one call.
    Periodic::register_handler(h2, &s_label[4], 5, 1);   // label 5 -> prints 105
    Periodic::register_handler(h2, &s_label[5], 3, 1);   // label 6 -> 106
    Periodic::register_handler(h1, &s_label[6], 5, 4);   // label 7, period 4
    for (int k = 1; k <= 5; ++k)
    {
        Periodic::check();
        dump("P3");
        if ( k == 3 )
            Periodic::unregister_handler(h2);
    }
    for (int k = 1; k <= 6; ++k)
    {
        Periodic::check();
        dump("P3b");
    }

    // P4: unregister_all then check -> nothing; re-register resumes fresh
    Periodic::unregister_all();
    Periodic::check();
    dump("P4");
    Periodic::register_handler(h1, &s_label[7], 9, 2);   // label 8
    Periodic::check();
    dump("P4b"); // time_left 2->1, no fire
    Periodic::check();
    dump("P4c"); // 1->0
    Periodic::check();
    dump("P4d"); // fire at 4th check (period 2 -> every 3rd after first)

    // P5: same hook + same arg registered twice; unregister removes both
    Periodic::unregister_all();
    Periodic::register_handler(h1, &s_label[0], 1, 0);
    Periodic::register_handler(h1, &s_label[0], 1, 1);
    Periodic::check();     // both have time_left 0 / 1 -> first fires only
    dump("P5");
    Periodic::check();
    dump("P5b");
    Periodic::unregister_handler(h1);   // removes BOTH
    Periodic::check();
    dump("P5c");

    printf("DONE\n");
    return 0;
}
