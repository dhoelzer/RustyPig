// pcgate_gate_main.cc -- row 23e GATE RUNNER TU (TRACKED; the second runner
// main TU EVER -- the 22a tc_gate_main.cc template re-cloned per the gate-row
// law). THE RUNNER SHAPE POSTURE, MEASURED HONEST AT THIS ROW (E10 face
// re-armed BOTH ways): this row's TU carries ZERO init()-filled file-statics
// (the whole gate builds locals: PacketConstraints cs + SfIp locals + a stack
// FlowKey/Flow), so unlike thread_config (22a: CATCH_CONFIG_MAIN twin SEGVs
// rc=139 on the first statics deref, snort.cc:109 init-order law) the
// CATCH_CONFIG_MAIN twin here runs GREEN (measured both shapes 13/3). The
// law BINDS TUs WITH boot-time statics; on this TU it is INERT. The runner is
// STILL shipped tracked (the gate-row template posture + the deterministic
// "[framework]" default filter face -- the tag the ground rides, NEVER
// re-typed from air: cite-pinned by the build.sh ground arms).
#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"

int main(int argc, char* argv[]) {
    Catch::Session session;
    if (argc == 1) { const char* def[] = {"gate", "[framework]"}; return session.run(2, def); }
    return session.run(argc, argv);
}
