// probe_faceA.cc -- row 22a FACE-A: the observable-shape surface PLAN q5
// measured (which parts of the ground test block ride on it and what's not
// visible in nm): the instance-max AUTO ladder (set_instance_max(0) =>
// weight(process_cpuset) = witness model 256, not the host CPU count), the
// tid map hit/miss ladder (cold -1, set => the thread's own tid), the
// thread-NAME ladder after implement (pthread_getname_np => "snort3" for
// MAIN (cc :486-:490 keeps the main name), "s3.pkt-c0" after the
// singlified bind, the ERANGE face where a >15-char list-name refuses to
// replace an older name, and "s3.pkt-c9999" which SURVIVES the unbindable-
// CPU graceful-fallback warning path cc :455-:468), the numa FALSE ladder
// (witness available()=0 / max_node()=0 => implement_thread_mempolicy
// FALSE early at cc :315-:317 -- the honest no-NUMA-host arm, not a fake
// NUMA success), and the watchdog NO-OP arm (conf default
// watchdog_timer=0 snort_config.h :264 pins the cc :585/:604
// enabled-guard FALSE => start registers one witness handler, the kick /
// update paths return early; Periodic is DECL-witnessed only, the real
// periodic.cc stays periodic_harness home -- one-home law). NOLOAD head:
// BUILDING_SO/NDEBUG/sids grep-0 pinned in build.sh. NO access to file-
// static topology/process_cpuset (NOT link-visible) -- the PUBLIC API +
// witness ops ONLY.
#include "main/thread_config.h"
#include <cstdio>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

struct CpuSet {                       // read-mirror (probe.cc law)
    CpuSet(hwloc_cpuset_t set) : cpuset(set) { }
    hwloc_cpuset_t cpuset;
};

static void tname(char* buf) { buf[0] = 0; pthread_getname_np(pthread_self(), buf, 64); }

int main() {
    std::printf("NOLOAD main-TU SO_PUBLIC-h-only (BUILDING_SO/NDEBUG/sids grep-0 pinned by build.sh greps)\n");
    if (!snort::ThreadConfig::init()) return 1;

    // instance-max ladder: seed 1 -> set 7 -> set 0 = AUTO = witness model
    // process-cpuset weight (256), NOT this host's CPU count.
    unsigned m1 = snort::ThreadConfig::get_instance_max();
    snort::ThreadConfig::set_instance_max(7);
    unsigned m2 = snort::ThreadConfig::get_instance_max();
    snort::ThreadConfig::set_instance_max(0);
    unsigned m3 = snort::ThreadConfig::get_instance_max();
    std::printf("MAXLADDER 1=%u 7=%u auto=256=%u\n", m1, m2, m3);

    // tid map ladder (cc :225-:241): cold miss -1; set(3) => own tid hit.
    int cold = snort::ThreadConfig::get_instance_tid(7);
    snort::ThreadConfig::set_instance_tid(3);
    int hit = snort::ThreadConfig::get_instance_tid(3);
    std::printf("TIDLADDER cold=-1=%d hit-is-own-tid=%d tid>0=%d\n",
        cold == -1 ? 1 : 0, hit == (int)syscall(SYS_gettid) ? 1 : 0, hit > 0 ? 1 : 0);

    // thread-NAME ladder (the real observable nm NEVER sees).
    char nb[64];
    snort::ThreadConfig tc1;
    tc1.implement_thread_affinity(STHREAD_TYPE_MAIN, 0);      // unbound MAIN -> process set, name "snort3"
    tname(nb); std::printf("NAME1 main=%s\n", nb);

    CpuSet* one = new CpuSet(hwloc_bitmap_alloc());
    hwloc_bitmap_set(one->cpuset, 0);                        // {0}
    snort::ThreadConfig tc2;
    tc2.set_thread_affinity(STHREAD_TYPE_PACKET, 0, one);
    tc2.implement_thread_affinity(STHREAD_TYPE_PACKET, 0);   // binds {0}, -c0 name
    tname(nb); std::printf("NAME2 pkt-c0=%s\n", nb);

    snort::ThreadConfig tc3;
    tc3.implement_thread_affinity(STHREAD_TYPE_PACKET, 1);   // unbound id1 -> desired = 256-bit list -> ERANGE (>15 chars): NAME KEEPS tc2's
    tname(nb); std::printf("NAME3 erange-name-kept=%s\n", nb);

    CpuSet* bogus = new CpuSet(hwloc_bitmap_alloc());
    hwloc_bitmap_set(bogus->cpuset, 9999);                   // model-unbindable
    snort::ThreadConfig tc4;
    tc4.set_thread_affinity(STHREAD_TYPE_PACKET, 2, bogus);
    tc4.implement_thread_affinity(STHREAD_TYPE_PACKET, 2);   // warn+fallback; name fallback face rides ERANGE too
    tname(nb); std::printf("NAME4 pkt-c9999-survives=%s\n", nb);

    // numa FALSE ladder (witness arm): set a known policy, then the cc
    // :315 early-out (max_node() <= 0 on the no-NUMA witness) => FALSE.
    snort::ThreadConfig tc5;
    tc5.set_numa_mempolicy("bind");
    bool nret = tc5.implement_thread_mempolicy(STHREAD_TYPE_PACKET, 0);
    std::printf("NUMAFALSE implemented=0=%d\n", nret ? 0 : 1);

    // watchdog NO-OP arms (timer 0): start registers ONE handler on the
    // Periodic DECL-witness; kick/preemptive/update return at the guard.
    snort::ThreadConfig::start_watchdog();
    snort::ThreadConfig::kick_watchdog();
    snort::ThreadConfig::preemptive_kick();
    snort::ThreadConfig::update_thread_status(true);
    snort::ThreadConfig::update_thread_status(false);
    std::printf("WD-NOOP timer0-guard-false all-arms-live=1\n");

    snort::ThreadConfig::term();
    return 0;
}
