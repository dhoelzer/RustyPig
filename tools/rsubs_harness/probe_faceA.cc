// probe_faceA.cc — row 21a FACE-A: the NOLOAD framework-TU shape (19a
// NOLOAD precedent + PLAN §4/§7) over the REAL rsubSURVIVOR .o symbols —
// NO codec tables EVER (BUILDING_SO grep-0 / snort_plugins grep-0 on BOTH
// ground files -> the head line; ^LOAD / ver= / size= grep-0 asserted vs
// the vectors in build.sh). THE hidden-table family here = rss_pegs[] 13
// rows = 12 named + CountType::END sentinel (cc :321-:338) + RssPeg
// hidden enum 12 + Count (impl.h :43-:58) + rss_stats_to_pegcounts slot
// map (cc :343-:363) = the table<->enum<->struct TRIPLE-coupling contract.
// The static_assert(std::size(rss_pegs) == RssPeg::Count + 1) (:340)
// PAIRS as a COMPILE-proof (the .o exists = it held; never runtime).
// PEGTYPE ordinals ride the counts.h CountType walk (END=0/SUM=1/NOW=2/
// MAX=3, smoke-measured). DEDUP 3-arm truth + the reset()-CARVE-OUT face
// (impl.h :76-:88 resets TEN fields, LEAVES active+registry_tracked — the
// two-field carve-out vs the 12-field struct; rss_reset_for_test cc
// :616-:617 stores THOSE SAME two) — both arms run live here. NO policy/
// Inspector scaffolding needed: pure-function + table surface only.
#include "framework/reload_survivor_subscriptions_impl.h"
#include "framework/counts.h"
#include "framework/data_bus.h"     // PubKey (data_bus.h :44-:48; impl.h front-declares it only)
#include <cstdio>
using namespace snort;

int main() {
    printf("NOLOAD framework-TU BUILDING_SO-grep0-x2 snort_plugins-grep0-x2\n");

    // rss_pegs[] census: 12 named rows + the END sentinel (:337)
    printf("PEGS rows=12 sentinel=1 count=%d\n", (int)static_cast<size_t>(RssPeg::Count));
    int named = 0, sent = 0;
    for ( int i = 0; ; i++ ) {
        if ( rss_pegs[i].type == CountType::END ) { sent = 1; break; }   // the counts.h enum is GLOBAL-scope
        if ( !rss_pegs[i].name ) { sent = 1; break; }
        named++;
    }
    printf("PEGS walk named=%d end-at=%d\n", named, (int)named);
    printf("PEGN 0=%s 7=%s 11=%s sent-name-null=%d\n",
        rss_pegs[0].name, rss_pegs[7].name, rss_pegs[11].name,
        rss_pegs[named].name == nullptr);

    // PEGTYPE ordinals (counts.h END=0 SUM=1 NOW=2 MAX=3): the row types
    // ride the walk: installed SUM=1, active NOW=2, registry_tracked NOW=2,
    // reconcile_deferrals SUM=1, sentinel END=0.
    printf("PEGTYPE first=1 active=2 tracked=2 last=1 end=0\n");
    printf("PEGTYPE live=%d %d %d %d %d\n", (int)rss_pegs[0].type, (int)rss_pegs[7].type,
        (int)rss_pegs[8].type, (int)rss_pegs[11].type, (int)rss_pegs[12].type);

    // slot-map walk: feed a synthetic RssStats (field i -> i+1) through the
    // REAL rss_stats_to_pegcounts; out[] must land in the RssPeg order.
    RssStats s;
    s.installed = 1; s.retired = 2; s.bus_destroyed = 3; s.policy_resolution_failures = 4;
    s.list_returned = 5; s.stripped = 6; s.dead_handler_skips = 7; s.active = 8;
    s.registry_tracked = 9; s.dedup_conflicts = 10; s.slow_drains = 11; s.reconcile_deferrals = 12;
    PegCount out[16] = {};
    rss_stats_to_pegcounts(s, out);
    printf("SLOTMAP installed@0=%llu active@7=%llu tracked@8=%llu deferrals@11=%llu\n",
        (unsigned long long)out[0], (unsigned long long)out[7],
        (unsigned long long)out[8], (unsigned long long)out[11]);

    // DEDUP 3-arm truth table (:365-:371): SameTuple=0, pub-mismatch=1,
    // eid-mismatch=1 (the DedupClass order, impl.h :97-:101).
    PubKey a{"pubA", 8}, b{"pubA", 8}, c{"pubB", 8};
    int aa = (int)classify_dedup("pubA", 8, a, 8);
    int ab = (int)classify_dedup("pubA", 8, c, 8);
    int ae = (int)classify_dedup("pubA", 8, b, 7);
    printf("DEDUP same=%d pub-mismatch=%d eid-mismatch=%d\n", aa, ab, ae);

    // reset()-CARVE-OUT face: reset() zeroes TEN fields (installed..
    // reconcile_deferrals) and NEVER touches active + registry_tracked
    // (the 2-field carve-out vs the 12-field RssStats struct).
    rss_stats.reset();
    rss_stats.installed = 5; rss_stats.active = 3; rss_stats.registry_tracked = 2;
    rss_stats.reconcile_deferrals = 9;
    rss_stats.reset();
    printf("CARVE installed=%llu slow=%llu deferrals=%llu active=%llu tracked=%llu\n",
        (unsigned long long)rss_stats.installed.load(),
        (unsigned long long)rss_stats.slow_drains.load(),
        (unsigned long long)rss_stats.reconcile_deferrals.load(),
        (unsigned long long)rss_stats.active.load(),
        (unsigned long long)rss_stats.registry_tracked.load());
    rss_stats.active = 0; rss_stats.registry_tracked = 0;                    // cleanup (the reset does NOT)
    return 0;
}
