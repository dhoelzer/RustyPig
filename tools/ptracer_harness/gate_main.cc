// gate_main.cc (the RUNNER TU; the file NAME carries ZERO family tokens) — row 23f GATE RUNNER TU (TRACKED; the third runner
// main TU EVER — the 22a tc + 23e pc templates re-cloned per the gate-row
// law). THE RUNNER SHAPE POSTURE, MEASURED HONEST AT THIS ROW (E10 face
// re-armed BOTH ways, NEVER re-assumed): the row's gate TUs build their
// tracer through _thread_init on the heap (the ctor pulls the carried
// get_conf static-local + the witness open_file legs — NO boot-order
// file-static deref before main), so unlike thread_config (22a: the
// CATCH_CONFIG_MAIN twin SEGVs rc=139, the snort.cc:109 init-order law)
// the plain-MAIN twin shape is MEASURED here at the harness
// (E10_main_twin.txt rc captured EVERY build — face asserted in build.sh).
// The tracked posture STAYS CATCH_CONFIG_RUNNER (upstream unit_test.cc :26
// face-pinned cite + the deterministic "[PacketTracer]" default filter —
// the tag the ground rides at all TEN TEST_CASE faces, cite-pinned, NEVER
// re-typed from air).
#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

int main(int argc, char* argv[]) {
    Catch::Session session;
    if (argc == 1) { const char* def[] = {"gate", "[PacketTracer]"}; return session.run(2, def); }
    return session.run(argc, argv);
}
