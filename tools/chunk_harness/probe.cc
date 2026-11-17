// Ground-truth probe for ORIGINAL utils/chunk.cc + lua/{lua.h,lua.cc}
// over the REAL locally-built LuaJIT 2.1 VM. init_chunk decision
// table observed end-to-end: rc + the ParseError witness lines (real
// chunk.cc body, fixed inputs -> fixed lua error strings, fully
// deterministic). One Lua::State shared across ALL cases — same as
// upstream's suite — pinning ManageStack RAII stack balancing through
// every failure path. printf hygiene: results in locals first.
#include <cstdio>
#include <string>
#include "utils/chunk.h"
#include "lua/lua.h"

using namespace std;

int main()
{
    Lua::State lua(true);

    struct Case {
        const char* chunk;
        const char* args;
    };
    // order pins: normal / init-not-function / init-not-defined /
    // malformed chunk / malformed args / init-false / init-string /
    // void init / default state (openlibs)
    const Case cases[] = {
        { "function init() return true end", "args = { a = 1, b = 2 }" },
        { "init = 1", "args = { a = 1, b = 2 }" },
        { "", "args = { a = 1, b = 2 }" },
        { "function init()", "args = { a = 1, b = 2 }" },
        { "function init() return true end", "args = {" },
        { "function init() return false end", "args = { a = 1, b = 2 }" },
        { "function init() return 'boom' end", "args = { a = 1, b = 2 }" },
        { "function init() end", "args = { a = 1, b = 2 }" },
        { "function init() return true end", "" },
    };
    const char* name = "test";

    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
    {
        string c = cases[i].chunk;
        string a = cases[i].args;
        bool rc = init_chunk(lua, c, name, a);
        printf("C%u rc=%d\n", i + 1, (int)rc);
    }

    // the shared state is still healthy after the failure storm
    string c = "function init() return true end";
    string a = "args = { c = 3 }";
    bool rc = init_chunk(lua, c, name, a);
    printf("ALIVE rc=%d\n", (int)rc);

    printf("DONE\n");
    return 0;
}
