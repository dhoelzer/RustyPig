// Probe for main/numa.cc compiled VERBATIM (see build.sh for the three
// external-header witnesses; MPOL_* values come from <linux/mempolicy.h>).
// Everything printed is compile-time-stable: enum ints and pure mapping.
#include "main/numa.h"
#include <cstdio>

static const char* pn(NumaMemPolicy p) {
    switch (p) {
    case NumaMemPolicy::DEFAULT: return "DEFAULT";
    case NumaMemPolicy::PREFERRED: return "PREFERRED";
    case NumaMemPolicy::BIND: return "BIND";
    case NumaMemPolicy::LOCAL: return "LOCAL";
    case NumaMemPolicy::UNKNOWN: return "UNKNOWN";
    default: return "OTHER";
    }
}

int main() {
    // ABI pin: NumaMemPolicy : uint8_t, enumerators = kernel MPOL_*.
    printf("NUM %u %u %u %u %u\n",
        (unsigned)NumaMemPolicy::DEFAULT, (unsigned)NumaMemPolicy::PREFERRED,
        (unsigned)NumaMemPolicy::BIND, (unsigned)NumaMemPolicy::LOCAL,
        (unsigned)NumaMemPolicy::UNKNOWN);

    // string -> policy (round trip both directions)
    const char* ins[] = { "default", "preferred", "bind", "local",
        "interleave", "preferred_many", "fake_policy", "Default", "",
        "bind " };
    for (auto s : ins) {
        NumaMemPolicy p = convert_string_to_numa_mempolicy(s);
        printf("IN [%s] -> %s num=%u back=[%s] same=%d\n",
            s, pn(p), (unsigned)p, stringify_numa_mempolicy(p).c_str(),
            (int)(stringify_numa_mempolicy(p) == s));
    }

    // stringify of raw values NOT in the enum set: the default arm.
    for (unsigned v : { 0u, 1u, 2u, 3u, 4u, 5u, 254u, 255u })
        printf("VAL %u -> [%s]\n", v,
            stringify_numa_mempolicy((NumaMemPolicy)v).c_str());

    printf("DONE\n");
    return 0;
}
