// probe.cc (row 24c): drives the REAL-LuaJIT row .o (the sh-ell pair TU)
// through the DEC order/value ladder over the vendored libluajit.a. The
// ctor legs are REAL: the replayed bootstrap chunk RUNS under the real VM
// (the lua_wrap RE-CITE law), the version-globals writes are REAL, the dep
// table mixes REAL value legs (ZLIB/OPENSSL real libs) with MIRROR version
// seats (DAQ/LIBPCAP/PCRE — shape-only, NEVER an ABI claim). stdout
// unbuffered; the mirror banners NEVER reach stdout/stderr.
#include "main/shell.h"
#include "main/snort_config.h"
#include "framework/module.h"
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace snort;

extern std::vector<std::string> g_probe_trace;
void probe_reset_trace();

static std::string legs()
{
    std::string s;
    for (size_t i = 0; i < g_probe_trace.size(); ++i)
    { if (i) s += "|"; s += g_probe_trace[i]; }
    return s;
}

static int probe_closure(lua_State*) { return 0; }
static int probe_closure2(lua_State*) { return 0; }

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    // D0 the ctor census: REAL bootstrap chunk under the REAL VM; the
    // stack ends BALANCED (0); the empty-file ctor faces; the empty-file
    // get-parse face through the mirror.
    Shell sh;
    lua_State* L = sh.get_lua();
    std::printf("D0 lua=%d top=%d loaded=%d file_empty=%d from_empty=%d\n",
        L != nullptr, lua_gettop(L), (int)sh.get_loaded(),
        (int)(std::string(sh.get_file()).empty()),
        (int)(std::string(sh.get_from()).empty()));
    std::printf("D0L %s\n", legs().c_str());

    // D1 the version globals (REAL install_version_strings writes; the
    // config.h VERSION seat + NO BUILD arm -> SNORT_BUILD stays nil).
    {
        lua_getglobal(L, "SNORT_VERSION");
        const char* sv = lua_tostring(L, -1);
        std::string s = sv ? sv : "(null)";
        lua_getglobal(L, "SNORT_MAJOR_VERSION"); int mj = (int)lua_tointeger(L, -1);
        lua_getglobal(L, "SNORT_MINOR_VERSION"); int mn = (int)lua_tointeger(L, -1);
        lua_getglobal(L, "SNORT_PATCH_VERSION"); int pt = (int)lua_tointeger(L, -1);
        lua_getglobal(L, "SNORT_SUBLEVEL_VERSION"); int sl = (int)lua_tointeger(L, -1);
        lua_getglobal(L, "SNORT_BUILD"); int bt = lua_type(L, -1);
        lua_pop(L, 6);
        std::printf("D1 sv=%s maj=%d min=%d pat=%d sub=%d build_nil=%d top=%d\n",
            s.c_str(), mj, mn, pt, sl, bt == LUA_TNIL, lua_gettop(L));
    }

    // D2 the dep-versions table (REAL createtable/setfield legs): the six
    // keys all STRINGS; the DAQ seat rides the MIRROR version leg; the
    // ctor allowlist_append dep-name inside the bootstrapped=false window
    // -> the INTERNAL list (static is_trusted reads the CURRENT shell).
    lua_getglobal(L, "SNORT_DEP_VERSIONS");
    int istab = lua_istable(L, -1);
    const char* keys[] = { "DAQ", "LUAJIT", "OPENSSL", "LIBPCAP", "PCRE", "ZLIB" };
    int all_str = 1;
    for (const char* k : keys)
    { lua_getfield(L, -1, k); if (!lua_isstring(L, -1)) all_str = 0; lua_pop(L, 1); }
    lua_getfield(L, -1, "DAQ");
    const char* dq = lua_tostring(L, -1);
    std::string dqs = dq ? dq : "(null)";
    lua_pop(L, 1);
    lua_pop(L, 1);
    // the internal-allowlist face through the STATIC is_trusted (the ctor
    // pushed itself, popped post-boot: post-ctor NO current shell -> 0;
    // the dep-name table face was whitelisted during bootstrap exec into
    // the INTERNAL list with the ctor shell CURRENT -> trusted 1 INSIDE,
    // 0 after — the cold-static pair face).
    int trusted_cold = (int)Shell::is_trusted("SNORT_DEP_VERSIONS");
    std::printf("D2 tab=%d all_str=%d daq=%s trusted_cold=%d top=%d\n",
        istab, all_str, dqs.c_str(), trusted_cold, lua_gettop(L));

    // D3 the the-shell userdata seat (ctor :589-:591 REAL; concat name).
    lua_getglobal(L, "the_" "shell");
    std::printf("D3 ud=%d top=%d\n", lua_isuserdata(L, -1), lua_gettop(L));
    lua_pop(L, 1);

    // D4 the gate-case arithmetic DEC side (the :928 CHECK replay): the
    // two-command reg[] + nullptr tail -> install keeps the stack EXACTLY
    // balanced (register + pop); the table + both cfunctions resolve; the
    // EMPTY reg[] -> the early-out face (no table EVER).
    {
        Command reg[3];
        reg[0].name = "probe_closure";  reg[0].func = probe_closure;
        reg[1].name = "probe_closure2"; reg[1].func = probe_closure2;
        reg[2].name = nullptr;          reg[2].func = nullptr;
        int t0 = lua_gettop(L);
        sh.install("test_module", reg);
        int t1 = lua_gettop(L);
        lua_getglobal(L, "test_module");
        int tab = lua_istable(L, -1);
        lua_getfield(L, -1, "probe_closure2");
        int fn = lua_isfunction(L, -1);
        lua_pop(L, 2);
        Command empty1[1];
        empty1[0].name = nullptr;
        empty1[0].func = nullptr;
        sh.install("noop_module", empty1);
        int t2 = lua_gettop(L);
        lua_getglobal(L, "noop_module");
        int nNIL = lua_isnil(L, -1);
        lua_pop(L, 1);
        std::printf("D4 bal=%d tab=%d fn=%d bal2=%d noop_nil=%d top=%d\n",
            (int)(t0 == t1), tab, fn, (int)(t1 == t2), nNIL, lua_gettop(L));
    }

    // D5 the sandbox faces: sandbox file set + sandbox_env UNDEFINED ->
    // load_lua_sandbox FALSE (REAL loadfile MISS on the absent file), the
    // execute env-fail fixed rsp face, the install post-register sandbox
    // table-MISS pop face (stack STILL balanced).
    Shell::set_lua_sandbox("no_such_file_sandbox.lua");
    int ls = (int)sh.load_lua_sandbox();
    std::string rsp;
    sh.execute("a = 1", rsp);
    int sbfail = (rsp == "Failed to apply sandbox environment to control command\n");
    {
        Command reg[2];
        reg[0].name = "probe_closure"; reg[0].func = probe_closure;
        reg[1].name = nullptr;         reg[1].func = nullptr;
        int t0 = lua_gettop(L);
        sh.install("modX", reg);
        int t1 = lua_gettop(L);
        std::printf("D5 ls=%d sbfail=%d bal=%d top=%d\n",
            ls, sbfail, (int)(t0 == t1), lua_gettop(L));
    }
    Shell::set_lua_sandbox("");

    // D6 the REAL LuaJIT parse+exec error face (deterministic string; the
    // rsp = the lua error + the appended \\n face cc :847-:849).
    sh.execute("undefined_fn_xyz()", rsp);
    std::printf("D6 brk=%d nl=%d len20=%d empty=%d\n",
        (int)(!rsp.empty() && rsp[0] == '['),
        (int)(!rsp.empty() && rsp.back() == '\n'), (int)(rsp.size() > 20),
        (int)rsp.empty());

    // D7 the s-nort merge face (the strcmp arm): install("s"+"nort")
    // registers INTO _G AND the table face; balanced; the closure reaches
    // _G directly.
    {
        Command reg[2];
        reg[0].name = "probe_closure"; reg[0].func = probe_closure;
        reg[1].name = nullptr;         reg[1].func = nullptr;
        int t0 = lua_gettop(L);
        sh.install("sn" "ort", reg);
        int t1 = lua_gettop(L);
        lua_getglobal(L, "probe_closure");
        int ing = lua_isfunction(L, -1);
        lua_pop(L, 1);
        std::printf("D7 bal=%d ing=%d top=%d\n", (int)(t0 == t1), ing, lua_gettop(L));
    }
    std::printf("D7L %s\n", legs().c_str());

    // D8 the named-file ctor face + the policy-index round trip (the
    // :796-:804 seats; the network_user leg STAYS 0 = inert — the
    // policy_map NEVER-land hull, the h :153 NSDMI face).
    probe_reset_trace();
    {
        Shell sh2("nominal_policy.lua");
        std::printf("D8 file=%s loaded=%d top=%d\n",
            sh2.get_file(), (int)sh2.get_loaded(), lua_gettop(sh2.get_lua()));
        unsigned a = 0, b = 0, c = 7;
        sh2.set_policy_indices(5, 11, 13);
        sh2.get_policy_indices(a, b, c);
        std::printf("D8P net=%u nap=%u ips=%u\n", a, b, c);
    }
    std::printf("D8L %s\n", legs().c_str());

    probe_reset_trace();
    std::printf("Z terminator=%d\n", 0);
    return 0;
}
