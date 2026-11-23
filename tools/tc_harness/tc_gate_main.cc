// tc_gate_main.cc -- row 22a GATE RUNNER TU (TRACKED). THE
// CATCH_CONFIG_RUNNER LAW (recon-proven, E10-arm re-proved EVERY build): a
// plain CATCH_CONFIG_MAIN catch_main (the gre/numa/periodic shape) MUST NOT
// be used on THIS row: the ground [ThreadConfig] tests dereference TU
// statics (topology / process_cpuset / topology_support) filled ONLY by
// ThreadConfig::init() -- upstream calls init() at snort.cc:109 BEFORE Catch
// ever runs tests, and upstream's own test runner IS CATCH_CONFIG_RUNNER
// (src/catch/unit_test.cc). The MAIN-shape twin link SEGVs rc=139 on the
// FIRST cpuset test (measured recon face gate_plain). Upstream-order face:
// ThreadConfig::init() -> session.run -> term() (the HAVE_NUMA global
// shared_ptrs numa/hwloc -- mock-ALIASED by the 5 NUMA tests -- reset in
// our own term() so no at-exit shared_ptr deref rides a destroyed Catch
// static; the ground cc gates those resets under HAVE_NUMA, never our own).
#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"
#include "main/thread_config.h"

int main(int argc, char* argv[]) {
    if (!snort::ThreadConfig::init()) return 2;
    Catch::Session session;
    int rc;
    if (argc == 1) { const char* def[] = {"gate", "[ThreadConfig]"}; rc = session.run(2, def); }
    else rc = session.run(argc, argv);
    snort::ThreadConfig::term();
    return rc;
}
