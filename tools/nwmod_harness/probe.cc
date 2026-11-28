// probe.cc — row 24k DEC ladder: link the REAL row TU body (the pair owns
// EVERY non-inline network face: the static network_params table :37 (8
// config rows + the PT_MAX sentinel), the file-static network_set_policy
// lua leg :73 (the luaL_optstring seat + PolicyMap::get_user_network ->
// Shell::set_network_policy_user_id HIT fork, ELSE -> ControlConn::query_
// from_lua + the LogRespond macro face), the NON-static network_set_poly-
// _params :88 + network_cmds :94 tables (the external-linkage nm face —
// the file-static lua handler is REACHED THROUGH the REAL command table's
// func slot — the E9 twin law keeps the statics row-owned), the REAL
// NetworkModule ctor :101 (through the REAL framework/module.cc Module
// base leg), get_commands() :104 (the REAL table + the REAL Command::-
// get_arg_list body) and set() :107 (the eight v.is legs: the check-
// sum_drop/eval legs drive the REAL GetChecksumFlags machine through the
// config-file checksum home's REAL ConfigChecksumDrop/ConfigChecksumMode
// bodies in the leg set — the row's RICHEST deterministic face: all/
// none/ip/noip/tcp/notcp/udp/noudp/icmp/noicmp + combos; the id/min_ttl/
// new_ttl legs WRITE the mirrored NetworkPolicy fields (the NEVER-fired-
// cited get_network_policy home); the layers/max_ip6_extensions/max_ip_
// layers legs WRITE the witness-init SnortConfig NSDMI fields).
//
// NO FORK MECHANISM RIDES THIS ROW: the pair carries ZERO [[noreturn]]
// exit-0 printers (the walked face — the simplest chapter-21 pair), so the
// vectors ship ZERO 'X ' receipts; single-writer order is plain program
// order. The Lua seam drives the REAL LuaJIT linked BY ARCHIVE PATH (the
// fmod lesson: -lluajit resolves the .so first and the probe dies at
// load) with real luaL_newstate + lua_pushstring + the table-dispatched
// network_set_policy: uid==7 HIT face (the mirrored PolicyMap seam -> the
// mirrored Shell name+arg echo), uid==0 + uid==99 miss faces (query_from-
// lua -> the mirror-nil LogRespond ELSE branch -> LogMessage). The no-arg
// arm NEVER rides (luaL_optstring NULL -> strtoull UB — the cited never-
// driven face, an NF line in the vectors).
//
// NEVER driven (cited NF rows, NEVER fired): the ParseError unknown-token
// wall (ONLY valid tokens ride the ladder — the deterministic law), the
// Analyzer::set_main_hook + DetectionEngine::inspect pair (the config_-
// conf home the config-file leg CARRIES but NEVER drives HERE), the Con-
// trolConn non-nil respond legs (query returns the mirror-nil), the Log-
// Message(FILE*) overload, the PolicyMap she-ll/setup family, SnortConf-
// ig::set_conf. SnortConfig rides ONE stack instance THROUGH the witness
// SHAPE ctor (the CITED row-24k witness-init deviation: shape-init ONLY
// so the row's OWN set() legs write num_layers/max_ip6_extensions/max_ip_
// layers; the leaked get_conf face carries the mirrored policy_map the
// lua legs need — the cited seam deviation). Determinism law: ZERO wall-
// clock, ZERO heap-pointer values, ZERO randomness in the vectors. The
// -DUNIT_TEST face is EXACTLY-0 BOTH files — the post is VACUOUS, ZERO
// delta legs (the SEVENTH zero-gate control).
#include <cstdio>
#include <cstring>
#include <string>

#include <lua.hpp>

#include "network_module.h"
#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/policy.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/value.h"

using namespace snort;

// the checksum token ladder through the row's REAL set() legs + the REAL
// GetChecksumFlags machine (the config-file checksum home, REAL body):
// the flags land on the mirrored NetworkPolicy — the printed face rides
// the header INLINES (checksum_drops + the *_checksums predicates).
static void ck_arm(NetworkModule& mod, SnortConfig& sc, const char* what, const char* tok)
{
    const Parameter* p = Parameter::find(mod.get_parameters(), what);
    Value v(tok);
    v.set(p);
    mod.set("", v, &sc);
    NetworkPolicy* pol = get_network_policy();
    printf("K %s in=%s eval=0x%x drop=0x%x drops%sTcp%sUdp%sIcmp\n", what, tok,
        pol->checksum_eval, pol->checksum_drop,
        pol->checksum_drops(CHECKSUM_FLAG__TCP) ? "-" : "no-",
        pol->checksum_drops(CHECKSUM_FLAG__UDP) ? "-" : "no-",
        pol->checksum_drops(CHECKSUM_FLAG__ICMP) ? "-" : "no-");
}

int main()
{
    printf("Q row24k-dec-ladder\n");

    // ---- D1: the REAL ctor leg (Module("network", network_help, network_-
    // params)) — the name/help/usage faces ride the REAL base leg + the
    // h :38-:39 inline get_usage (the CONTEXT ordinal face) ----
    SnortConfig sc;                       // the CITED witness-init deviation
    NetworkModule mod;                    // the REAL Module base leg
    printf("D1 ctor name=%s help=%s usage=%d-%d params=%s\n",
        mod.get_name(), mod.get_help(), (int)mod.get_usage(),
        (int)Module::CONTEXT, mod.get_parameters() ? "live" : "null");

    // ---- D2: the network_params table walk through the REAL get_params
    // inline (the cc :37 static table — the 8 rows + sentinel face) ----
    int n = 0, sel = 0, multi = 0, sent = 0;
    for (const Parameter* p = mod.get_parameters(); p->name; ++p)
    {
        printf("D2 p%d %s type=%d deflt=%s\n", n, p->name, (int)p->type,
            p->deflt ? p->deflt : "(none)");
        if (p->type == Parameter::PT_SELECT) ++sel;
        if (p->type == Parameter::PT_MULTI) ++multi;
        ++n;
    }
    sent = (mod.get_parameters()[n].type == Parameter::PT_MAX) ? 1 : 0;
    printf("D2 rows=%d multi=%d select=%d sentinel=%d\n", n, multi, sel, sent);

    // ---- D3: the checksum ladder (the row's richest face) — the REAL
    // GetChecksumFlags machine behind the REAL drop/mode homes ----
    ck_arm(mod, sc, "checksum_eval", "all");
    ck_arm(mod, sc, "checksum_eval", "none");
    ck_arm(mod, sc, "checksum_eval", "ip");
    ck_arm(mod, sc, "checksum_eval", "noip");
    ck_arm(mod, sc, "checksum_eval", "tcp");
    ck_arm(mod, sc, "checksum_eval", "notcp");
    ck_arm(mod, sc, "checksum_eval", "udp");
    ck_arm(mod, sc, "checksum_eval", "noudp");
    ck_arm(mod, sc, "checksum_eval", "icmp");
    ck_arm(mod, sc, "checksum_eval", "noicmp");
    ck_arm(mod, sc, "checksum_eval", "all icmp");        // the all-reset face
    ck_arm(mod, sc, "checksum_eval", "tcp noicmp");      // pos+neg combine face
    ck_arm(mod, sc, "checksum_drop", "all");
    ck_arm(mod, sc, "checksum_drop", "noip notcp");      // negative-only face
    ck_arm(mod, sc, "checksum_drop", "none");            // the deflt face
    NetworkPolicy* pol = get_network_policy();
    printf("K preds ip=%d udp=%d tcp=%d icmp=%d\n", pol->ip_checksums(),
        pol->udp_checksums(), pol->tcp_checksums(), pol->icmp_checksums());

    // ---- D4: the id/min_ttl/new_ttl legs WRITE the mirrored policy ----
    Value vid((uint64_t)4242);
    vid.set(Parameter::find(mod.get_parameters(), "id"));
    NetworkModule mod2;                                   // ctor NOT re-fired marker rides mod
    mod2.set("", vid, &sc);
    Value vmax((uint64_t)9007199254740992ULL);            // the id range max53 bound face
    vmax.set(Parameter::find(mod.get_parameters(), "id"));
    printf("D4 id=%llu max53=%llu\n",
        (unsigned long long)pol->user_policy_id,
        (unsigned long long)vmax.get_uint64());
    Value vmin((uint64_t)3);  vmin.set(Parameter::find(mod.get_parameters(), "min_ttl"));
    Value vnew((uint64_t)64); vnew.set(Parameter::find(mod.get_parameters(), "new_ttl"));
    mod.set("", vmin, &sc); mod.set("", vnew, &sc);
    printf("D4 min=%d new=%d\n", (int)pol->min_ttl, (int)pol->new_ttl);

    // ---- D5: the layers/max_ip6_extensions/max_ip_layers legs WRITE the
    // witness SnortConfig NSDMI fields (the shape-init deviation cited) ----
    {
        Value vl((uint64_t)40); vl.set(Parameter::find(mod.get_parameters(), "layers"));
        Value v6((uint64_t)7);  v6.set(Parameter::find(mod.get_parameters(), "max_ip6_extensions"));
        Value vi((uint64_t)9);  vi.set(Parameter::find(mod.get_parameters(), "max_ip_layers"));
        mod.set("", vl, &sc); mod.set("", v6, &sc); mod.set("", vi, &sc);
    }
    printf("D5 layers=%d ip6ext=%d iplayers=%d\n",
        (int)sc.num_layers, (int)sc.max_ip6_extensions, (int)sc.max_ip_layers);

    // ---- D6: get_commands() — the REAL network_cmds table + the REAL
    // Command::get_arg_list body (the framework/module.cc leg): the name
    // + arg-list census through the :88 params table (2-row incl sentinel) ----
    const Command* cmds = mod.get_commands();
    int c = 0;
    for (const Command* q = cmds; q->name; ++q)
    {
        printf("D6 cmd%d %s args=%s canrun=%d help=%s\n", c, q->name,
            q->get_arg_list().c_str(), q->can_run_in_parallel ? 1 : 0, q->help);
        ++c;
    }
    printf("D6 rows=%d tail-sentinel=%d\n", c, cmds[c].name == nullptr);

    // ---- D7: the lua seam through the REAL LuaJIT (ARCHIVE-linked): the
    // file-static handler REACHED through the table's func slot (the E9
    // law keeps the static row-owned — the probe NEVER names it) ----
    lua_State* L = luaL_newstate();
    printf("D7 lua-state=%d\n", L ? 1 : 0);
    if (L)
    {
        lua_settop(L, 0);
        lua_pushstring(L, "7");
        int r1 = cmds[0].func(L); printf("D7a hit rc=%d top=%d\n", r1, lua_gettop(L));
        lua_settop(L, 0);
        lua_pushstring(L, "0");
        int r2 = cmds[0].func(L); printf("D7b zero rc=%d top=%d\n", r2, lua_gettop(L));
        lua_settop(L, 0);
        lua_pushstring(L, "99");
        int r3 = cmds[0].func(L); printf("D7c miss rc=%d top=%d\n", r3, lua_gettop(L));
        lua_close(L);
        printf("D7 closed=1\n");
    }

    // ---- cited NF walls (NEVER fired — the census faces ride witness+nm) ----
    printf("NF ParseError-unknown-token wall NEVER fires (only valid tokens ride)\n");
    printf("NF Analyzer-set-main-hook + DetectionEngine-inspect (the config-conf home) NEVER fire\n");
    printf("NF ControlConn non-nil respond legs NEVER fire (query_from_lua mirror-nil)\n");
    printf("NF LogMessage FILE-pointer overload NEVER fires\n");
    printf("NF no-arg lua arm (optstring NULL into strtoull UB) NEVER drives\n");

    printf("fin=PASS\n");
    return 0;
}
