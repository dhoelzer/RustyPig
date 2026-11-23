// probe.cc -- row 22a DEC-side vectors: the REAL cpuset-decision ladder of
// ThreadConfig::validate_cpuset_string running on the FUNCTIONAL hwloc
// witness (model CPUs 0..255, set_cpubind fails >=256). The WIT_PARSE_ERR
// line the ParseError witness prints is itSELF a vector face: the ground
// :114 bad-string flow OBSERVABLE (PLAN q2 demand). CpuSet READ MIRROR =
// the global struct's ONE member + the ground cc :55 one-line ctor face
// verbatim (layout + trivial init ONLY; the REAL dtor logic stays tc home
// -- destroy_cpuset's delete is instantiated in the row .o). NO
// access to the file-static topology/process_cpuset/topology_support (they
// are NOT link-visible -- the DEC probes ride the PUBLIC API + the witness
// bitmap ops ONLY). NO flow/codec/packet face ever (measured find-0
// closure, PLAN q1). numa pair rides PLAIN (the convert/stringify decision
// surface; the 3 numa TEST_CASEs STAY numa_harness gate home, never re-
// gated here -- one-home law).
#include "main/thread_config.h"
#include <cstdio>
struct CpuSet {                       // read-mirror (see header law)
    CpuSet(hwloc_cpuset_t set) : cpuset(set) { }
    hwloc_cpuset_t cpuset;
};

int main() {
    if (!snort::ThreadConfig::init()) { std::printf("INIT FAIL\n"); return 1; }

    // D1: garbage string -> ground :114 ParseError flow (WIT_PARSE_ERR line
    // rides this stdout above the D1 line) -> nullptr.
    const CpuSet* bad = snort::ThreadConfig::validate_cpuset_string("totally a bad cpuset string");
    std::printf("D1 bad-null=1=%d\n", bad == nullptr ? 1 : 0);

    // D2: fully-allowed set -> pass-through arm.
    CpuSet* ok = snort::ThreadConfig::validate_cpuset_string("0,1,7");
    std::printf("D2 ok=1 w=%d isset7=%d\n",
        hwloc_bitmap_weight(ok->cpuset), hwloc_bitmap_isset(ok->cpuset, 7));   // nullptr would CRASH the weight read = the ok guard face
    snort::ThreadConfig::destroy_cpuset(ok);

    // D3: partial overlap: 5 inside, 300 model-outside -> intersection arm.
    CpuSet* part = snort::ThreadConfig::validate_cpuset_string("5,300");
    std::printf("D3 part=1 w=%d isset5=%d isset300=%d\n",
        hwloc_bitmap_weight(part->cpuset), hwloc_bitmap_isset(part->cpuset, 5),
        hwloc_bitmap_isset(part->cpuset, 300));
    snort::ThreadConfig::destroy_cpuset(part);

    // D4: ZERO overlap -> graceful fallback = whole process cpuset (model
    // weight; cc :131-:141 no-overlap arm).
    CpuSet* fb = snort::ThreadConfig::validate_cpuset_string("300");
    std::printf("D4 fb=1 w=%d\n", hwloc_bitmap_weight(fb->cpuset));
    snort::ThreadConfig::destroy_cpuset(fb);

    // D5: the EMPTY set parses CLEAN + trivially included -> weight 0.
    CpuSet* e = snort::ThreadConfig::validate_cpuset_string("");
    std::printf("D5 empty=1 w=%d\n", hwloc_bitmap_weight(e->cpuset));
    snort::ThreadConfig::destroy_cpuset(e);

    // D6: model ceiling: 256 is model-outside (allowed face is 0..255) ->
    // zero intersect -> fallback face; 255 inside, 256 never set.
    CpuSet* ceil = snort::ThreadConfig::validate_cpuset_string("256");
    std::printf("D6 model-ceil=1 w=%d isset255=%d isset256=%d\n",
        hwloc_bitmap_weight(ceil->cpuset), hwloc_bitmap_isset(ceil->cpuset, 255),
        hwloc_bitmap_isset(ceil->cpuset, 256));
    snort::ThreadConfig::destroy_cpuset(ceil);

    // D7: range round-trip arm of list_sscanf (dash face).
    CpuSet* rng = snort::ThreadConfig::validate_cpuset_string("10-13");
    std::printf("D7 range=1 w=%d isset12=%d\n",
        hwloc_bitmap_weight(rng->cpuset), hwloc_bitmap_isset(rng->cpuset, 12));
    snort::ThreadConfig::destroy_cpuset(rng);

    // D8: the numa.cc HOME decision pair rides PLAIN (never the gate).
    std::printf("D8 numa cnv-bind=%s cnv-nope=%s dflt2str=%s\n",
        stringify_numa_mempolicy(convert_string_to_numa_mempolicy("bind")).c_str(),
        stringify_numa_mempolicy(convert_string_to_numa_mempolicy("nope")).c_str(),
        stringify_numa_mempolicy(NumaMemPolicy::DEFAULT).c_str());

    snort::ThreadConfig::term();
    return 0;
}
