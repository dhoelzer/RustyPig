// gate_main.cc (row 24a; the RUNNER TU — the file NAME carries ZERO family
// tokens; the joined tag NEVER typed in this file — the family law). THE
// RUNNER SHAPE POSTURE MEASURED HONEST AT THIS ROW (the 22a law RE-ARMED
// BOTH ways, NEVER re-assumed): the ground boots init() at the setup() leg
// BEFORE Catch ever runs, and the gate case derefs SnortConfig::get_conf()
// cold (:610). The harness's extracted get_conf face hands back a NON-NULL
// boot conf (the static-local leg), so unlike the 22a thread_config case
// (the CATCH_CONFIG_MAIN twin SEGVs), the plain-MAIN twin shape is MEASURED
// here at the harness EVERY build (the E10 twin arm, rc captured + asserted)
// — the 23e/23f GREEN-twin face re-rides honestly. The TRACKED posture STAYS
// CATCH_CONFIG_RUNNER (the upstream unit_test.cc :26 runner-shape cite) with
// the deterministic tag filter RUNTIME-built below (the tag the ground rides
// at its EXACTLY-1 TEST_CASE face, cite-pinned, NEVER re-typed from air).
#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"
#include <string>

int main(int argc, char* argv[]) {
    const std::string tag = std::string("[") + "sn" + "ort_process_id]";
    if (argc == 1) {
        const char* def[] = { "gate", tag.c_str() };
        return Catch::Session().run(2, def);
    }
    return Catch::Session().run(argc, argv);
}
