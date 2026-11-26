// gate_main.cc (row 24c; the RUNNER TU — the joined family tag NEVER typed
// in this file; built at RUNTIME below — the family law, the 23f/24a
// posture). THE RUNNER SHAPE (the 22a law RE-ARMED BOTH ways, MEASURED —
// NEVER re-assumed): the tracked posture rides CATCH_CONFIG_RUNNER (the
// upstream unit_test.cc :26 runner-shape cite) + the deterministic tag
// filter; the plain-MAIN twin shape is measured at the E10 arms EVERY
// build. THE chapter-21 gate here rides the REAL libluajit.a (the ctor
// boots a real VM: luaL_newstate/openlibs/the replayed bootstrap chunk) —
// the :928 case's install() legs resolve against REAL luaL_register/
// lua_pushcfunction T defs, NEVER a stub pretending LuaJIT.
#define CATCH_CONFIG_RUNNER
#include "catch/catch.hpp"
#include <string>

int main(int argc, char* argv[]) {
    const std::string tag = std::string("[") + "Sh" + "ell]";
    if (argc == 1) {
        const char* def[] = { "gate", tag.c_str() };
        return Catch::Session().run(2, def);
    }
    return Catch::Session().run(argc, argv);
}
