// probe.cc — row 21a DEC probe: the MEASURED 12-line T0-T9 ladder over the
// REAL rsubs_ut.o (-DUNIT_TEST arm, the clock seam rss_set_elapsed_for_test
// rides ground cc :625) + witness_rsubs.o (the EXACTLY-3 mirror trio:
// _subscribe PubKey / get_reload_id -> 7 / WarningMessage capture) + the
// carried WIN trio (witness_conf closes get_conf) + the 7-object backbone.
// THE scaffolding here is the UPSTREAM TEST's OWN mirror pattern cited
// src/framework/test/reload_survivor_subscriptions_test.cc :50-:58
// (policy ctor/dtor mirrors + Inspector ctor/dtor + the 3 non-inline
// virtuals; TestInspector final subclass because the Inspector ctor is
// protected — the :49 protected-context wall face, pattern banked). It
// carries ZERO copies of the three witness mirror bodies (iph_link.txt
// run1: three 'multiple definition' faces = the embedded+witness DOUBLE
// face — receipts banked; the ONE-home law).
// ~DataBus mirror calls rss_on_bus_destroyed = the data_bus.cc:82 CONSUMER
// shape mirrored for the bus-stripe arm (T4) — the provider itself is the
// real rsubs symbol; cite-only law on production callers preserved.
// R6 LAW (re-earned at pilot T6: the state-calls-store-to-VARs rule —
// every rss_/stats read lands in a VAR before any printf; grep-pinned in
// build.sh: zero printf lines may call rss_* or touch rss_stats inline).
#include "framework/reload_survivor_subscriptions_impl.h"
#include "framework/data_bus.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "framework/inspector.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
using namespace snort;

// ---- the witness observables (defined ONLY in witness_rsubs.cc, INSIDE
// namespace snort — the extern decls must ride the same namespace: the
// _ZN5snort...E vs _Z1...E lookup face measured at scratch) ----
namespace snort {
extern unsigned wrsubscribe_calls;
extern unsigned wrwarn_calls;
extern char wr_last_warn[2048];
extern DataHandler* wr_last_handler;
}

// ---- scaffolding mirrors ONLY (the upstream test pattern) ----
InspectionPolicy::InspectionPolicy(unsigned int) : service_group(nullptr) {}
InspectionPolicy::~InspectionPolicy() = default;
NetworkPolicy::NetworkPolicy(unsigned int, unsigned int) : file_policy(nullptr) {}
NetworkPolicy::~NetworkPolicy() = default;
Inspector::Inspector() : ref_count(nullptr) {}
Inspector::~Inspector() { rss_release(*this); }          // mirrors ~Inspector() rss_release call-site (inspector.cc:61 cite)
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
DataBus::DataBus() = default;
DataBus::~DataBus() { rss_on_bus_destroyed(this); }      // the data_bus.cc:82 consumer shape (mirror)

class FakeHandler final : public DataHandler {
public:
    FakeHandler() : DataHandler("fake") {}
    void handle(DataEvent&, Flow*) override {}
};
class SleepHandler final : public DataHandler {
public:
    SleepHandler() : DataHandler("sleepy") {}
    void handle(DataEvent&, Flow*) override { std::this_thread::sleep_for(std::chrono::milliseconds(250)); }
};
class TestInspector final : public Inspector { public: TestInspector() = default; };

int main() {
    InspectionPolicy ip; NetworkPolicy np; TestInspector survivor;
    rss_reset_for_test(); rss_stats.reset();
    printf("T0 sub=%u warn=%u inst=%llu act=%llu track=%llu\n", wrsubscribe_calls, wrwarn_calls,
        (unsigned long long)rss_stats.installed.load(), (unsigned long long)rss_stats.active.load(),
        (unsigned long long)rss_stats.registry_tracked.load());

    // T1-T3: subscribe face + the dedup ladder (same-tuple factory-skip,
    // MISMATCH-tuple conflict+warn — cc :389-:445 + :302-:313 + :365-:378)
    PubKey A{"pubA", 8};
    {
        ReloadSurvivorSubscriptions rss(np, ip, survivor);
        rss.subscribe("k1", A, 8, []{ return new FakeHandler(); });
        unsigned s1 = wrsubscribe_calls;
        unsigned long long i1 = rss_stats.installed.load(), a1 = rss_stats.active.load(),
            t1 = rss_stats.registry_tracked.load(), d1 = rss_stats.dedup_conflicts.load();
        printf("T1 sub=%u inst=%llu act=%llu track=%llu dedup=%llu\n", s1, i1, a1, t1, d1);
        rss.subscribe("k1", A, 8, []{ return new FakeHandler(); });            // same-tuple dup -> factory skipped
        unsigned s2 = wrsubscribe_calls;
        unsigned long long i2 = rss_stats.installed.load(), d2 = rss_stats.dedup_conflicts.load();
        printf("T2 samedup sub=%u inst=%llu conflicts=%llu\n", s2, i2, d2);
        PubKey B{"pubB", 8};
        rss.subscribe("k1", B, 8, []{ return new FakeHandler(); });            // mismatch tuple -> conflict+warn
        unsigned long long d3 = rss_stats.dedup_conflicts.load();
        unsigned w3 = wrwarn_calls, s3 = wrsubscribe_calls;
        printf("T3 misdup conflicts=%llu warn=%u sub=%u\n", d3, w3, s3);
    }

    // T4: bus-teardown stripe (real ~DataBus mirror -> rss_on_bus_destroyed,
    // cc :536-:568 remove_if full-scan face)
    rss_reset_for_test(); rss_stats.reset(); wrsubscribe_calls = 0;
    {
        ReloadSurvivorSubscriptions rss(np, ip, survivor);
        rss.subscribe("k2", A, 8, []{ return new FakeHandler(); });
    }
    rss_on_bus_destroyed(&ip.dbus);                                           // the pilot-faithful explicit teardown call (the upstream-test face; ~DataBus mirror stays link-scaffolding)
    unsigned long long st4 = rss_stats.stripped.load(), a4 = rss_stats.active.load(),
        bd4 = rss_stats.bus_destroyed.load();
    printf("T4 stripped=%llu act=%llu bus_destroyed=%llu\n", st4, a4, bd4);

    // T5-T7: the survivor view + the reconcile GATE (release deferred ->
    // end_reconcile -> release ok; cc :570-:607 + :450-:496 deferral face)
    rss_reset_for_test(); rss_stats.reset(); wrsubscribe_calls = 0;
    {
        ReloadSurvivorSubscriptions rss(np, ip, survivor);
        rss.subscribe("k3", A, 8, []{ return new FakeHandler(); });
    }
    auto v = rss_list_survivors(3);                                          // opens the gate
    unsigned long long lr5 = rss_stats.list_returned.load();
    printf("T5 views=%zu npid=%llu ipid=%llu list_returned=%llu\n", v.size(),
        (unsigned long long)v[0].np_user_id, (unsigned long long)v[0].ip_user_id, lr5);
    bool d6 = rss_release(survivor);                                         // gate open -> deferred
    unsigned long long df6 = rss_stats.reconcile_deferrals.load();
    printf("T6 release-during-reconcile=%d deferrals=%llu\n", (int)d6, df6);
    rss_end_reconcile(survivor);                                             // gate shut (:599-:607)
    bool r7 = rss_release(survivor);
    unsigned long long rt7 = rss_stats.retired.load(), tk7 = rss_stats.registry_tracked.load();
    unsigned w7 = wrwarn_calls;
    printf("T7 release-after=%d retired=%llu track=%llu warn=%u\n", (int)r7, rt7, tk7, w7);

    // T8: quiescence arms — idle (no warn), then the UNIT_TEST clock seam:
    // forced 59999ms = tier-1 (>=5000, <60000) -> EXACTLY-1 warn + slow_drains
    rss_reset_for_test(); rss_stats.reset(); wrsubscribe_calls = 0; wrwarn_calls = 0;
    {
        ReloadSurvivorSubscriptions rss(np, ip, survivor);
        rss.subscribe("k4", A, 8, []{ return new FakeHandler(); });
        bool q0 = rss_await_quiescent(survivor);
        unsigned w8a = wrwarn_calls;
        unsigned long long sd8a = rss_stats.slow_drains.load();
        printf("T8a quiescent-idle=%d warn=%u slow=%llu\n", (int)q0, w8a, sd8a);
    }
    rss_reset_for_test(); rss_stats.reset(); wrsubscribe_calls = 0; wrwarn_calls = 0;
    {
        ReloadSurvivorSubscriptions rss4(np, ip, survivor);
        rss4.subscribe("k5", A, 8, []{ return new SleepHandler(); });         // :376-:378 warn-key arm downstream
        BareDataEvent e;
        std::thread th([&]{ wr_last_handler->handle(e, nullptr); wr_last_handler->handle(e, nullptr); });
        std::this_thread::sleep_for(std::chrono::milliseconds(40));           // handler in flight
        rss_set_elapsed_for_test(59999);                                      // tier-1 hit, tier-2 needs 60000
        bool q1 = rss_await_quiescent(survivor);
        th.join();
        unsigned long long sd = rss_stats.slow_drains.load(); unsigned w = wrwarn_calls;
        rss_set_elapsed_for_test(7000);                                        // seam hygiene (fresh window)
        rss_set_elapsed_for_test(0);                                           // 0 = real clock (cc :56-:57)
        printf("T8b quiescent=%d slow=%llu warn=%u\n", (int)q1, sd, w);
        printf("T8c label-unknown=%d key-k5=%d reloadid7=%d\n", strstr(wr_last_warn,"'<unknown>'")!=nullptr,
            strstr(wr_last_warn,"key 'k5'")!=nullptr, strstr(wr_last_warn,"reload id 7")!=nullptr);
        // T9: dead-handler skip after release+re-dispatch (cc :187-:197 live-face)
        bool r1 = rss_release(survivor);
        wr_last_handler->handle(e, nullptr);
        unsigned long long sk = rss_stats.dead_handler_skips.load(), tk = rss_stats.registry_tracked.load();
        printf("T9 release=%d skips=%llu tracked=%llu\n", (int)r1, sk, tk);
    }
    rss_reset_for_test();
    return 0;
}
