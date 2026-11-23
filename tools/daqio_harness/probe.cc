// row-23a probe.cc — THE real-SDK DEC ladder for the sfdaq 4-pair.
// GROUND: sfdaq.cc 420 (7ac13aa1f5013ead580f5b4f61c38368) + sfdaq.h 72
// (2e272d2d68e40138946326df3c5cfc95) + sfdaq_config.cc 131 (881eb038...)
// + sfdaq_config.h 85 (df8f1875...) @ fe29cbe FRESH cps. The <daq.h> face
// now rides the REAL libdaq SDK api (c8d4083) copy-LOCAL (the row-20
// RE-CITE law) + the REAL api .o objects link at run time — the verdict/
// mode/state STRING families and the register/sanity ladder are REAL SDK
// faces, NEVER synthetic. The SFDAQInstance provider (sfdaq_instance.cc
// 436+105, row 23b) stays the own-11 witness mirror law (NEVER invented).
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_instance.h"

#include <daq.h>
#include <daq_module_api.h>   // DAQ_ModuleAPI_t / DAQ_BaseAPI_t (the real
                              // SDK module-API face the probe's static
                              // test modules implement)
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "main/snort_config.h"

// witness knobs (witness_daqio.cc; probe reads externs, NEVER re-defines).
// The message mirrors + knobs live in namespace snort (the witness defines
// them there — the SAME mangling face the carriers ride):
namespace snort {
extern char wlog_buf[4096];      extern unsigned wlog_calls;
extern char werr_buf[4096];      extern unsigned werr_calls;
extern char wperr_buf[4096];     extern unsigned wperr_calls;
extern unsigned wsi_ctor_calls, wsi_dtor_calls;
extern unsigned wsi_init_calls, wsi_last_total_hint;
extern char wsi_last_bpf[256];   extern const void* wsi_last_cfg;
extern bool wsi_can_inject_b, wsi_can_inject_raw_b, wsi_can_replace_b;
extern bool wsi_bypass_b;        extern unsigned wsi_bypass_proto;
extern int wsi_inject_calls, wsi_inject_rc;
extern DAQ_Stats_t wsi_stats;
}

// ---- the copy-LOCAL static test modules (the SDK registration face; the
// ENABLE_STATIC_DAQ arm is OFF in the donor config.h — sfdaq.cc :69-:71
// never compiles — so the probe calls daq_load_static_modules DIRECTLY,
// the SDK entry the ifdef'd branch would call, with its OWN module data).
static unsigned zeta_unload_calls = 0, alpha_unload_calls = 0;
static uint32_t alpha_seen_base_api_version = 0, alpha_seen_base_api_size = 0;

static int alpha_load(const DAQ_BaseAPI_t* b) {
    alpha_seen_base_api_version = b->api_version;
    alpha_seen_base_api_size = b->api_size;
    return DAQ_SUCCESS;
}
static int alpha_unload(void) { alpha_unload_calls++; return DAQ_SUCCESS; }
static const DAQ_VariableDesc_t alpha_descs[2] = {
    { "input",  "the input spec", 0 },
    { "strict", "strictness",     DAQ_VAR_DESC_REQUIRES_ARGUMENT },
};
static int alpha_var_descs(const DAQ_VariableDesc_t** t) { *t = alpha_descs; return 2; }
static int alpha_instantiate(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) { *c = nullptr; return DAQ_SUCCESS; }
static void alpha_destroy(void*) {}

static int zeta_load(const DAQ_BaseAPI_t*) { return DAQ_SUCCESS; }
static int zeta_unload(void) { zeta_unload_calls++; return DAQ_SUCCESS; }
static int zeta_var_descs(const DAQ_VariableDesc_t** t) { *t = nullptr; return 0; }
static int zeta_instantiate(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) { *c = nullptr; return DAQ_SUCCESS; }
static void zeta_destroy(void*) {}

static DAQ_ModuleAPI_t alpha_mod = {
    /*api_version*/ DAQ_MODULE_API_VERSION,
    /*api_size*/    sizeof(DAQ_ModuleAPI_t),
    /*version*/     3,  "alpha",
    /*type*/        DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_FILE_CAPABLE,
    alpha_load, alpha_unload, alpha_var_descs, alpha_instantiate, alpha_destroy,
    /*set_filter*/ nullptr,
};
static DAQ_ModuleAPI_t zeta_mod = {
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t),
    5, "zeta", DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_WRAPPER,
    zeta_load, zeta_unload, zeta_var_descs, zeta_instantiate, zeta_destroy,
    nullptr,
};
static int nopriv_load(const DAQ_BaseAPI_t*) { return DAQ_SUCCESS; }
static int nopriv_instantiate(const DAQ_ModuleConfig_h, DAQ_ModuleInstance_h, void** c) { *c = nullptr; return DAQ_SUCCESS; }
static void nopriv_destroy(void*) {}
static DAQ_ModuleAPI_t nopriv_mod = {
    DAQ_MODULE_API_VERSION, sizeof(DAQ_ModuleAPI_t),
    4, "nopriv", DAQ_TYPE_NO_UNPRIV | DAQ_TYPE_INTF_CAPABLE,
    nopriv_load, nullptr, nullptr, nopriv_instantiate, nopriv_destroy,
    nullptr,
};

using namespace snort;

static std::string squash(const std::string& s) {
    std::string o;
    for (char c : s) if (c != '\n') o += c;
    return o;
}

int main() {
    // ---- T0 the C-struct defaults (sfdaq_config.h :78-:82 + cc :65-:70) ----
    SFDAQConfig cfg;
    printf("T0 defaults batch=%u mru=%d timeout=%u bs=%u ms=%d\n",
        cfg.batch_size, cfg.mru_size, cfg.timeout,
        cfg.get_batch_size(), cfg.get_mru_size());

    // ---- T1 the set_variable parse ladder (cc :31-:44 find_first_of '=') ----
    SFDAQModuleConfig mc;
    mc.set_variable("input=/var/log/pcap.0");
    mc.set_variable("strict");
    mc.set_variable("k=3=4");
    printf("T1 vars n=%zu k0=%s v0=%s k1=%s v1=%s k2=%s v2=%s\n",
        mc.variables.size(),
        mc.variables[0].first.c_str(), mc.variables[0].second.c_str(),
        mc.variables[1].first.c_str(), mc.variables[1].second.c_str(),
        mc.variables[2].first.c_str(), mc.variables[2].second.c_str());

    // ---- T2 the overlay sentinel ladder (cc :108-:131: dirs/inputs/
    // module_configs replace-if-nonempty; batch/mru sentinel-guarded;
    // timeout UNCONDITIONAL — the = other->timeout face at :130) ----
    SFDAQConfig base;
    base.add_input("ethA");
    base.add_module_dir("/lib/daq-base");
    base.set_batch_size(32);
    SFDAQConfig over;
    over.add_input("ethB");
    over.add_input("ethC");          // inputs size 2 for T3
    over.add_module_dir("/lib/daq-over");
    over.set_mru_size(2000);          // mru set, batch STAYS UNSET sentinel
    over.timeout = 0;                 // the unconditional-overwrite face
    base.overlay(&over);
    printf("T2 overlay bs=%u ms=%d to=%u in0=%s inN=%zu dirs=%s\n",
        base.get_batch_size(), base.get_mru_size(), base.timeout,
        base.inputs[0].c_str(), base.inputs.size(), base.module_dirs[0].c_str());
    SFDAQConfig keep;                  // overlay with NOTHING: all preserved
    keep.batch_size = 5; keep.mru_size = 6; keep.timeout = 7;
    SFDAQConfig empty_over;
    keep.overlay(&empty_over);
    printf("T2b overlay_empty keep=%u,%d,%u\n", keep.batch_size, keep.mru_size, keep.timeout);

    // ---- T3 the get_input_spec two-arg ladder (cc :404-:413) ----
    SFDAQConfig icfg;
    printf("T3 inspec_null=%d ", SFDAQ::get_input_spec(&icfg, 0) ? 1 : 0);
    icfg.add_input("ethA"); icfg.add_input("ethB");
    printf("id0=%s id1=%s id9=%s\n",
        SFDAQ::get_input_spec(&icfg, 0), SFDAQ::get_input_spec(&icfg, 1),
        SFDAQ::get_input_spec(&icfg, 9));

    // ---- T4 THE DEFAULT_DAQ face (cc :45-:49: no DEFAULT_DAQ define in
    // the harness config.h -> DAQ_DEFAULT "pcap"; init with NO modules ->
    // AddDaqModuleConfig fails at daq_find_module ("pcap" is NEVER
    // registered) -> the ParseError face + init FALSE + daqcfg null-out) ----
    SFDAQConfig ncfg;
    bool ok = SFDAQ::init(&ncfg, 1);
    printf("T4 default_pcap init=%d perr=[%s]\n", ok ? 1 : 0, squash(wperr_buf).c_str());

    // ---- T5 THE REAL SDK registration + print_types face: register alpha
    // + zeta STATICALLY (the SDK entry cc :70 would call under
    // ENABLE_STATIC_DAQ — copy-LOCAL probe-side, honest cite), then the
    // cc :87-:150 ladder walks REAL daq_modules_first/next + the strcmp
    // SORT + the type-cap string family (:114-:131 REAL values) + the
    // REAL DAQ_VariableDesc_t table ----
    DAQ_Module_h mods[3] = { &zeta_mod, &alpha_mod, nullptr };
    int nreg = daq_load_static_modules(mods);
    std::ostringstream oss;
    SFDAQ::print_types(oss);
    std::string ts = oss.str();
    // THE FULL print_types block (the cc :89-:149 face — the available-
    // header, the strcmp SORT (alpha before zeta), the cap-string family
    // :114-:131 with the INVERTED `!(type & NO_UNPRIV)` unpriv arm, the
    // Variables table :136-:148 <arg>/[arg] faces): squashed onto ONE
    // vector line, byte-exact vs the vectors pin:
    printf("T5 reg=%d block=[%s]\n", nreg, squash(ts).c_str());

    // ---- T6 init with the REAL alpha module: the msg_pool (batch*4),
    // snaplen, timeout, total_instances faces ride the REAL daq_config.c
    // accessors through the witness init capture (instance->init receives
    // the real daqcfg): pool=64*4=256, snap=1518, t=1000, total=4 + the
    // LogMessage face from REAL daq_mode_string ----
    SFDAQConfig mcfg;                 // fresh (timeout 1000 defaults)
    SFDAQModuleConfig* d = mcfg.add_module_config("alpha");
    d->set_variable("input=x");       // value non-empty
    d->set_variable("empty=");        // cc :203 empty-string -> nullptr face
    ok = SFDAQ::init(&mcfg, 4);
    {
    snort::SFDAQInstance inst("x", 7, &mcfg);   // ctor rides wsi (id 7 = the hint face)
    bool iok = SFDAQ::init_instance(&inst, "bpf-echo");
    printf("T6 init=%d iinit=%d pool=%d snap=%d tmo=%d tot=%u log=[%s] bpf=%s hint=%u\n",
        ok ? 1 : 0, iok ? 1 : 0,
        daq_config_get_msg_pool_size((DAQ_Config_h)wsi_last_cfg),
        daq_config_get_snaplen((DAQ_Config_h)wsi_last_cfg),
        daq_config_get_timeout((DAQ_Config_h)wsi_last_cfg),
        daq_config_get_total_instances((DAQ_Config_h)wsi_last_cfg),
        squash(wlog_buf).c_str(), wsi_last_bpf, wsi_last_total_hint);

    // unpriv face (cc :331-:343 walks the REAL cfg modcfg stack via
    // daq_config_top/next_module_config + daq_module_config_get_module):
    printf("T6b canrun_unpriv=%d\n", SFDAQ::can_run_unprivileged() ? 1 : 0);

    // ---- T7 the SFDAQMode -> DAQ_Mode MAP face (cc :189-:198) measured
    // through the REAL SDK daq_module_config_get_mode on the pushed
    // modcfg (the wrapper never echoes it, so ask the SDK). The :302
    // LogMessage face rides the global default_daq_mode (always passive
    // under the witness conf run_flags=0 — the honest :235-:242 face).
    // T7b drives the REAL conf ladder via the get_conf seam (the cc
    // :235-:242 adaptor_inline_mode/read_mode face): the witness conf is
    // public for set_run_flags/clear_run_flags (snort_config.h :702-:708
    // const-callable through const_cast — the seam the cc itself uses). ----
    struct ModeCase { SFDAQModuleConfig::SFDAQMode m; const char* tag; };
    ModeCase cases[4] = {
        { SFDAQModuleConfig::SFDAQ_MODE_UNSET, "unset" },
        { SFDAQModuleConfig::SFDAQ_MODE_PASSIVE, "passive" },
        { SFDAQModuleConfig::SFDAQ_MODE_INLINE, "inline" },
        { SFDAQModuleConfig::SFDAQ_MODE_READ_FILE, "readfile" } };
    for (auto& c : cases) {
        SFDAQConfig mc7;
        mc7.add_module_config("alpha")->mode = c.m;
        bool okr = SFDAQ::init(&mc7, 1);
        (void)okr;
        SFDAQInstance i7("x", 0, &mc7);
        SFDAQ::init_instance(&i7, "bpf7");
        DAQ_ModuleConfig_h mcfg7 = daq_config_top_module_config((DAQ_Config_h)wsi_last_cfg);
        printf("T7 %s mapped=%d log=[%s] ", c.tag, (int)daq_module_config_get_mode(mcfg7), squash(wlog_buf).c_str());
    }
    printf("\n");
    const_cast<SnortConfig*>(SnortConfig::get_conf())->set_run_flags(RUN_FLAG__INLINE);
    SFDAQConfig il;
    il.add_module_config("alpha");          // UNSET -> conf face INLINE
    SFDAQ::init(&il, 1);
    { SFDAQInstance i8("x", 0, &il); SFDAQ::init_instance(&i8, "bpf8"); }
    std::string w_inline = wlog_buf;
    const_cast<SnortConfig*>(SnortConfig::get_conf())->clear_run_flags(RUN_FLAG__INLINE);
    printf("T7b inline log=[%s]\n", squash(w_inline).c_str());
    // the wrapper auto-pcap convenience face (cc :271-:287): a WRAPPER-typed
    // first module -> the hardcoded "pcap" READ_FILE base push -> the REAL
    // find face (pcap NEVER registered here) -> ParseError -> init false:
    SFDAQConfig wl;
    wl.add_module_config("zeta");           // zeta is DAQ_TYPE_WRAPPER
    bool wok = SFDAQ::init(&wl, 1);
    printf("T7c wrapper init=%d perr=[%s]\n", wok ? 1 : 0, squash(wperr_buf).c_str());

    // ---- T8 THE RE-CITE verdict heart: SFDAQ::verdict_to_string -> the
    // REAL daq_base.c :56-:63 table (pass/block/replace/whitelist/
    // blacklist/ignore; MAX -> NULL) — the 9b603f8f synthetic face's
    // PAUSE/WAITING/COUNT names DIE against the real SDK face ----
    const char* vv[6] = { SFDAQ::verdict_to_string(DAQ_VERDICT_PASS),
        SFDAQ::verdict_to_string(DAQ_VERDICT_BLOCK),
        SFDAQ::verdict_to_string(DAQ_VERDICT_REPLACE),
        SFDAQ::verdict_to_string(DAQ_VERDICT_WHITELIST),
        SFDAQ::verdict_to_string(DAQ_VERDICT_BLACKLIST),
        SFDAQ::verdict_to_string(DAQ_VERDICT_IGNORE) };
    printf("T8 verdicts=");
    for (const char* s : vv) printf("%s|", s);
    printf("max=%s\n", SFDAQ::verdict_to_string(MAX_DAQ_VERDICT) ? "notnull" : "null");

    // forwarding_packet (cc :325-:329) rides the GLOBAL default_daq_mode
    // set by the LAST init's conf ladder (:235-:242) — NOT the per-dmc
    // mapping. PASSIVE after T7c -> false; via the conf seam INLINE ->
    // true; the REAL DAQ_PKT_FLAG_NOT_FORWARDING 0x0002 arm -> false. ----
    DAQ_PktHdr_t h{ };
    h.flags = 0;
    int f_passive = SFDAQ::forwarding_packet(&h) ? 1 : 0;
    const_cast<SnortConfig*>(SnortConfig::get_conf())->set_run_flags(RUN_FLAG__INLINE);
    SFDAQConfig il8;
    il8.add_module_config("alpha");
    SFDAQ::init(&il8, 1);
    h.flags = 0;
    int f_inline = SFDAQ::forwarding_packet(&h) ? 1 : 0;
    h.flags = DAQ_PKT_FLAG_NOT_FORWARDING;   // the REAL 0x0002 (daq_common.h :113)
    int f_notfwd = SFDAQ::forwarding_packet(&h) ? 1 : 0;
    printf("T8b fwd passive=%d inline=%d notfwd=%d\n", f_passive, f_inline, f_notfwd);
    const_cast<SnortConfig*>(SnortConfig::get_conf())->clear_run_flags(RUN_FLAG__INLINE);
    SFDAQConfig pl8;
    pl8.add_module_config("alpha");
    SFDAQ::init(&pl8, 1);                    // restore the PASSIVE global face

    // ---- T9 the local-instance wrapper ladder (cc :354-:402): can_*
    // short-circuit on nullptr, then the witness provider (row 23b face) ----
    SFDAQ::set_local_instance(nullptr);
    printf("T9 nullwrap ci=%d cir=%d cr=%d tb=%d ",
        SFDAQ::can_inject() ? 1 : 0, SFDAQ::can_inject_raw() ? 1 : 0,
        SFDAQ::can_replace() ? 1 : 0, SFDAQ::get_tunnel_bypass(6) ? 1 : 0);
    snort::wsi_can_inject_b = true; snort::wsi_can_inject_raw_b = false;
    snort::wsi_can_replace_b = true; snort::wsi_bypass_b = true;
    SFDAQ::set_local_instance(&inst);
    int tb6 = SFDAQ::get_tunnel_bypass(6) ? 1 : 0;
    unsigned bp = snort::wsi_bypass_proto;
    printf("set ci=%d cir=%d cr=%d tb6=%d proto=%u spec=[%s] base=%d\n",
        SFDAQ::can_inject() ? 1 : 0, SFDAQ::can_inject_raw() ? 1 : 0,
        SFDAQ::can_replace() ? 1 : 0, tb6, bp,
        SFDAQ::get_input_spec(), SFDAQ::get_base_protocol());
    wsi_stats.packets_received = 11; wsi_stats.verdicts[DAQ_VERDICT_BLOCK] = 3;
    const DAQ_Stats_t* st = SFDAQ::get_stats();
    int ir = SFDAQ::inject(nullptr, 1, (const uint8_t*)"abc", 3);
    printf("T9b stats=%llu vblock=%llu inject=%d calls=%d\n",
        (unsigned long long)st->packets_received,
        (unsigned long long)st->verdicts[DAQ_VERDICT_BLOCK], ir, wsi_inject_calls);
    }   // inst dtor fires HERE (the cc :399-:402 provider is the witness;
        // the ctor/dtor census at T10 counts EVERY scoped instance face)

    // ---- T10 term + the REAL unload walk (cc :307-:318 + :81-:85; the
    // #ifndef REG_TEST arm COMPILES with the harness config.h) + T11 the
    // nopriv can_run face through a fresh registration ----
    SFDAQ::set_local_instance(nullptr);
    SFDAQ::term();
    printf("T10 term unloaded alpha=%u zeta=%u ctor=%u dtor=%u\n",
        alpha_unload_calls, zeta_unload_calls, wsi_ctor_calls, wsi_dtor_calls);
    DAQ_Module_h nm[2] = { &nopriv_mod, nullptr };
    daq_load_static_modules(nm);
    SFDAQConfig nl;
    nl.add_module_config("nopriv");
    SFDAQ::init(&nl, 1);
    printf("T11 nopriv_canrun=%d\n", SFDAQ::can_run_unprivileged() ? 1 : 0);
    SFDAQ::term();
    return 0;
}
