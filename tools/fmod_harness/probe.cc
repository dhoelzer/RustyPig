// probe.cc — ground-truth transcript for the file-id Module TU row,
// file_api/file_module.{h,cc} (row 18a; probe-vectors-only). INVERTED
// LANDMINE ROW (R1/R2): the row .o now DEFINES what four donor harnesses
// witnessed -- FileIdModule C1/C2 ctors (T), the vtable/typeinfo trio (V),
// load_config (T) and the THREAD_LOCAL file_trace (B collapses). The
// retired trio left stubs.o EMPTY (zero survivors asserted in build.sh),
// so the probe arms the REAL surface FIRST-TIME: REAL heap `new FileIdModule`
// (the 17w "symbol merely exists" raw-storage posture is DEAD -- the real
// ~FileIdModule cc:148-:152 `if(fc) delete fc` over raw storage is a crash
// class), the REAL set() 17-arm ladder (lazy `new FileConfig` on the FIRST
// param, mid-ladder, not the ctor -- R5), the REAL end() (ALWAYS true;
// appends magic_file EVEN when empty, cc:256-:261) through the W1/W2
// witnesses, the REAL load_config STEAL (cc:263-:266 `dst = fc; fc =
// nullptr;`) -- PRINTS-FROZEN: the real body has NO print (the old
// "FIM load_config stole=" line was witness-ONLY; vectors grep-assert it
// stays ZERO here). Steal observability = the REAL FileInspect ctor
// (file_inspect.cc:48-:51 fm->load_config(config), config public h:36) +
// POST-CALL load_config readbacks (stolen slot answers null). file_trace:
// REAL definition in the row .o, armed through set_trace (cc:154) and the
// carried fcache_set_file_trace seam (its definition retired, R3).
// LUAJIT REAL LINK (R4, first third-party link in the lineage): the two
// Command lambdas are driven through function pointers with a REAL
// lua_State from luaL_newstate (live libluajit.a under -L$LUA_SRC -lluajit
// -lm -ldl; NO hand-stubbed luaL_*). query_from_lua witness returns the
// UPSTREAM VERBATIM non-SHELL nullptr -> every LogRespond arm routes to the
// LOGMSG-prefixed LogMessage witness (control.h:99-:100 null branch,
// pinned). dump_cache/dump_cache_entry run REAL code in file_cache.o over
// REAL cache rows (count ladder incl. the -1 sentinel cc:296-:301, the
// displayed-N-of-M arm, the SHA-lowercase-normalize-0xAB match cc:337-:347
// and the reject ladders).
// Hygiene: no 0x[0-9a-f]{6,} anywhere (identities print as 0/1 flags).
#include "file_api/file_cache.h"            // FileCache + fixture rows
#include "file_api/file_config.h"           // FileConfig (FILE_ID_NAME/HELP)
#include "file_api/file_inspect.h"          // REAL FileInspect steal ctor
#include "file_api/file_lib.h"              // FileContext arms + file_perf_stats
#include "file_api/file_module.h"           // the row header (REAL FileIdModule)
#include "file_api/file_service.h"          // get_file_cache/decode_conf seam
#include "file_api/file_stats.h"            // file_stats_init (rc-139 rule)
#include "framework/inspector.h"            // Inspector base
#include "framework/module.h"               // Command/RuleMap/PegInfo
#include "framework/parameter.h"
#include "framework/value.h"
#include "main/snort_config.h"

#include <lua.hpp>                          // LIVE LuaJIT (never a stub)
#include <lauxlib.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

using namespace snort;

// donor seams (stubs.cc, VERBATIM arms)
extern "C" void fcache_set_file_cache(FileCache* c);
extern "C" void fcache_enable_fake_clock(int on);
extern "C" void fcache_set_fake_now(double t);
extern "C" void fcache_set_file_trace(int on, int level);   // def retired @18a (R3)
extern "C" void fcache_set_file_inspector(int on);          // REAL ctor re-wire @18a
extern "C" void fmod_set_includer_null(int on);             // NEW18a W2 arm
FileInspect* get_stub_file_inspector();                     // stubs.cc readback

static FileHashKey mkkey(uint64_t file_id)
{
    FileHashKey key{};
    key.file_id = file_id;
    return key;
}

int main(void)
{
    fcache_enable_fake_clock(1);
    fcache_set_fake_now(100.0);
    file_stats_init();                       // THREAD_LOCAL counts armed

    // ---- V0: sizeof pins BEFORE any construction (sizeof STRINGS: the
    // magic_file std::string member, h:83 -- libstdc++ 32-byte SSO body;
    // the FileIdModule object = Module + FileMeta rule + fc + string). ----
    std::printf("V0_sizes str=%zu mod_ge=%zu pegsz=%zu pc8=%d rulemap=%zu cmd=%zu\n",
        sizeof(std::string),
        sizeof(FileIdModule) >= sizeof(snort::Module) ? 1 : 0,
        sizeof(PegInfo), sizeof(PegCount) == 8 ? 1 : 0,
        sizeof(RuleMap), sizeof(Command));

    // ---- V1: FIRST-TIME REAL heap ctor (R2: the real T _ZN12FileIdModule
    // C1Ev resolves for the first time in the lineage) + zero-call table
    // readbacks (all answers are REAL row-.o bodies). ----
    FileIdModule* m = new FileIdModule;
    const Parameter* p = m->get_parameters();
    const PegInfo* pegs = m->get_pegs();
    const RuleMap* rules = m->get_rules();
    const Command* cmds_v1 = m->get_commands();
    {
        int np = 0; while (p[np].name) ++np;
        int ng = 0; while (pegs[ng].type != CountType::END) ++ng;
        std::printf("V1_ctor name=%s help=%s gid=%u usage=%d dyn=%d params=%d "
            "p0=%s d0=%s pt0=%d pegs=%d peg0=%s rule0=%u msg0_null=%d "
            "cmd0=%s cmd1=%s cmd2_null=%d tr_opt=%d tname_null=%d\n",
            m->get_name(), m->get_help(), m->get_gid(), (int)m->get_usage(),
            m->has_dynamic_stats() ? 1 : 0, np,
            p[0].name, p[0].deflt, (int)p[0].type, ng, pegs[0].name,
            rules[0].sid, rules[0].msg ? 0 : 1,
            cmds_v1[0].name, cmds_v1[1].name,
            cmds_v1[2].name ? 0 : 1,
            m->get_trace_options() ? 1 : 0,
            m->get_trace_options()->name ? 0 : 1);
        {
            int nc = 0; while (cmds_v1[nc].name) ++nc;
            std::printf("V1_cmds n=%d fp0=%d fp1=%d params0=%s def0=%s "
                "params1=%s def1_null=%d\n",
                nc, cmds_v1[0].func ? 1 : 0, cmds_v1[1].func ? 1 : 0,
                cmds_v1[0].params ? cmds_v1[0].params[0].name : "-",
                cmds_v1[0].params ? cmds_v1[0].params[0].deflt : "-",
                cmds_v1[1].params ? cmds_v1[1].params[0].name : "-",
                cmds_v1[1].params and cmds_v1[1].params[0].deflt ? 0 : 1);
        }
        std::printf("V1_profile prof_nonnull=%d counts_nonnull=%d\n",
            m->get_profile() ? 1 : 0, m->get_counts() ? 1 : 0);
    }

    // ---- V2: end() BEFORE any set(): the cc:256-:261 ALWAYS-append quirk
    // (empty magic_file -> parser_append_rules_special("", inc), R5 pin) +
    // the armable NULL-includer arm (cc:258 flows straight into the W1
    // call, nullptr legal). THEN the REAL set() ladder: lazy new FileConfig
    // on the FIRST param (mid-ladder, not the ctor), the DECODE arm -> the
    // W3 witness (cc:245), the rules_file "include " prefix (cc:247-:251),
    // the bogus-name arm (set ALWAYS returns true, cc:252). Second end()
    // re-arms W1/W2 with magic_file set. ----
    std::printf("V2_end_empty ret=%d\n", m->end("", 0, nullptr) ? 1 : 0);
    fmod_set_includer_null(1);
    std::printf("V2_end_nullic ret=%d\n", m->end("", 0, nullptr) ? 1 : 0);
    fmod_set_includer_null(0);
    {
        Parameter pd = { "type_depth", Parameter::PT_INT, "0:max53", "1460", nullptr };
        Parameter pb = { "decompress_buffer_size", Parameter::PT_INT, "1024:max31", "100000", nullptr };
        Parameter pr = { "rules_file", Parameter::PT_STRING, nullptr, nullptr, nullptr };
        Parameter px = { "bogus_name", Parameter::PT_INT, nullptr, "0", nullptr };
        Value vd((int64_t)512);  vd.set(&pd);
        Value vb((uint64_t)4096); vb.set(&pb);
        Value vr("magic.rules"); vr.set(&pr);
        Value vx((int64_t)7);    vx.set(&px);
        int a = m->set("type_depth", vd, nullptr) ? 1 : 0;
        int b = m->set("decompress_buffer_size", vb, nullptr) ? 1 : 0;
        int c = m->set("rules_file", vr, nullptr) ? 1 : 0;
        int d = m->set("bogus_name", vx, nullptr) ? 1 : 0;
        std::printf("V2_set ret=%d%d%d%d (order d,b,r,x)\n", a, b, c, d);
        std::printf("V2_end_rules ret=%d\n", m->end("", 0, nullptr) ? 1 : 0);
    }

    // ---- V3: file_trace through the REAL definition (row-.o B):
    // fcache_set_file_trace arms it non-null, the REAL set_trace (cc:154)
    // overwrites it null, re-arm shows both faces. get_trace_options static
    // null-option pin rides V1. ----
    fcache_set_file_trace(1, 3);
    int armed = file_trace ? 1 : 0;
    m->set_trace(nullptr);
    int after = file_trace ? 1 : 0;
    fcache_set_file_trace(1, 3);
    std::printf("V3_trace armed=%d set_trace_nulled=%d rearm=%d\n",
        armed, after, file_trace ? 1 : 0);

    // ---- V4: the REAL load_config STEAL, post-call observation. STEAL-A:
    // the REAL FileInspect ctor (file_inspect.cc:48-:51) consumes m's set-
    // armed fc; ins->config IS the stolen cell (identity flag), the
    // post-call m->load_config answers NULL (cc:266 nulls fc; PRINTS-FROZEN:
    // zero prints from the real body). delete m -> the REAL dtor SKIPS the
    // delete (fc null, the cc:148-:152 leak-vs-ownership pin, R5);
    // ~FileInspect frees the config exactly once. STEAL-B on a SECOND fresh
    // module: pre-set load hands null; after one set() the direct load
    // hands the fc pointer (identity flag), caller deletes it (Rust Box
    // semantics twin: Option::take). ----
    {
        FileInspect* ins = new FileInspect(m);          // REAL steal
        FileConfig* dst1 = nullptr;
        m->load_config(dst1);                           // post-call: null
        std::printf("V4_steal_a ins_cfg=%d post_null=%d\n",
            ins->config ? 1 : 0, dst1 ? 0 : 1);
        delete ins;                                     // frees the stolen cell
        delete m;                                       // dtor: fc null, no delete

        FileIdModule* m2 = new FileIdModule;
        FileConfig* dst0 = nullptr;
        m2->load_config(dst0);                          // fresh fc -> null
        Parameter pd = { "type_depth", Parameter::PT_INT, "0:max53", "1460", nullptr };
        Value vd((int64_t)99);  vd.set(&pd);
        m2->set("type_depth", vd, nullptr);             // lazy fc
        FileConfig* dst2 = nullptr;
        m2->load_config(dst2);                          // hands the fc
        FileConfig* dst3 = nullptr;
        m2->load_config(dst3);                          // steal AGAIN -> null
        std::printf("V4_steal_b pre_null=%d post_got=%d again_null=%d\n",
            dst0 ? 0 : 1, dst2 ? 1 : 0, dst3 ? 0 : 1);
        delete dst2;                                    // caller owns (Box)
        delete m2;                                      // dtor: fc null
        (void)dst0;
    }

    // ---- V5: the fcache_set_file_inspector re-wire arm: REAL new
    // FileIdModule (fc NEVER set) -> REAL steal hands a NULL config (the
    // cc:263-:266 null arm); ~FileInspect's `if (config)` guard is safe. ----
    fcache_set_file_inspector(1);
    std::printf("V5_wit_ctor cfg_null=%d\n",
        get_stub_file_inspector() and !get_stub_file_inspector()->config ? 1 : 0);

    // ---- V6: the Command lambdas through function pointers over a REAL
    // lua_State (live LuaJIT: luaL_newstate/lua_pushinteger/lua_close are
    // T defs in libluajit.a -- first third-party link in the lineage).
    // query_from_lua -> nullptr (upstream VERBATIM) pins every LogRespond
    // through the LOGMSG-prefixed LogMessage witness. dump_cache/
    // dump_cache_entry bodies are REAL file_cache.o code. ----
    {
        FileIdModule* m3 = new FileIdModule;            // fresh (no set arms)
        const Command* cmds = m3->get_commands();
        lua_State* L = luaL_newstate();
        std::printf("V6_lua state=%d cmds=%d func0=%d\n", L ? 1 : 0, 2,
            cmds[0].func ? 1 : 0);

        // cache-null arms (both commands; FileService::file_cache static is
        // the REAL D cell, armed through the donor seam).
        fcache_set_file_cache(nullptr);
        lua_settop(L, 0);
        cmds[0].func(L);                                // cc:289 null branch
        lua_settop(L, 0);
        cmds[1].func(L);                                // cc:312 null branch

        // REAL cache: two rows (AB-sha + 11-sha), count + SHA ladders.
        static FileCache v6_cache(16);
        fcache_set_file_cache(&v6_cache);
        bool cf = false; int64_t ce = 0;
        FileContext* r1 = v6_cache.add(mkkey(101), 1000, cf, ce, true);
        FileContext* r2 = v6_cache.add(mkkey(102), 1000, cf, ce, true);
        r1->set_file_name("gamma.bin", 9);
        r2->set_file_name("delta.bin", 9);
        r1->sha256 = new uint8_t[32]; std::memset(r1->sha256, 0xAB, 32);
        r2->sha256 = new uint8_t[32]; std::memset(r2->sha256, 0x11, 32);

        lua_settop(L, 0);
        cmds[0].func(L);                                // default 100, both rows
        lua_settop(L, 0); lua_pushinteger(L, 0);
        cmds[0].func(L);                                // cc:297 reject arm
        lua_settop(L, 0); lua_pushinteger(L, -2);
        cmds[0].func(L);                                // negative rejected too
        lua_settop(L, 0); lua_pushinteger(L, 1);
        cmds[0].func(L);                                // displayed 1 of 2
        lua_settop(L, 0); lua_pushinteger(L, -1);
        cmds[0].func(L);                                // sentinel ALL cc:305

        lua_settop(L, 0);
        cmds[1].func(L);                                // usage line (null sha)
        lua_settop(L, 0); lua_pushstring(L, "");
        cmds[1].func(L);                                // empty sha -> usage
        {
            std::string long65(65, 'a');
            lua_settop(L, 0); lua_pushstring(L, long65.c_str());
            cmds[1].func(L);                            // length reject cc:330
        }
        lua_settop(L, 0); lua_pushstring(L, "zz");
        cmds[1].func(L);                                // hex reject cc:340
        lua_settop(L, 0); lua_pushstring(L, "ab");      // lowercase -> upper
        cmds[1].func(L);                                // REAL match (0xAB row)
        lua_settop(L, 0); lua_pushstring(L, "FFFF");
        cmds[1].func(L);                                // no-match arm cc:1111

        lua_close(L);                                   // REAL LuaJIT close
        fcache_set_file_cache(nullptr);
        std::printf("V6_done\n");
        delete m3;                                      // fc null, dtor no-op
    }

    // ---- V7: the REAL stats pair (module.o bodies + the real file_stats
    // cell aliases, 17z R2 pattern): get_counts alias pre/post, sum_stats
    // (true) -> file_stats_sum + update_buffers, reset_stats ->
    // file_stats_clear + Module::reset_stats. ----
    {
        FileIdModule* m4 = new FileIdModule;
        PegCount* c = m4->get_counts();
        uint64_t pre = *c;
        m4->sum_stats(true);
        c = m4->get_counts();
        uint64_t post = *c;
        m4->reset_stats();
        c = m4->get_counts();
        std::printf("V7_stats pre=%" PRIu64 " post=%" PRIu64 " reset=%" PRIu64 "\n",
            pre, post, *c);
        delete m4;
        long total = 0;
        (void)total;
    }

    std::printf("FMOD_PROBE_DONE\n");
    return 0;
}
