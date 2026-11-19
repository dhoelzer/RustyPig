// probe.cc — ground-truth transcript for the inspector-registration row,
// file_api/file_inspect.{h,cc} (row 17w). The TU has ZERO TEST_CASEs and
// ZERO #ifdef UNIT_TEST fragments (PLAN 2; re-asserted in build.sh): every
// oracle rides here as a labeled vector arm (V1..V8 per PLAN 4 / NEXT.md
// :119-:128). The REAL file_inspect.o is compiled into BOTH links, so
// configure/show/ctor/dtor/get_file_adv_pub_id run REAL bodies over the 8
// NEW stub-side witnesses (DataBus::get_id, MPDataBus::register_event_
// helpers + subscribe, ConfigLogger log_flag + log_value(long) +
// log_value(unsigned long), FileIdModule::load_config steal + ctor symbol
// standover).
//
// R1/R2 posture: the ctor NEVER takes nullptr-mod (real cc:50 derefs fm);
// the FileConfig hand-off is the load_config STEAL over a HEAP-only slot —
// a local `delete insp` runs the real ~FileInspect (cc:53-:57, deletes the
// heap config, safe; NEVER &g_stub_file_config = static-storage UB). The
// gate link never constructs a FileInspect (toggle unarmed -> gate.txt
// byte-ident md5 4826fc22...).
// R3 posture: mod_ctor/mod_dtor are NEVER called (FileIdModule vtable/dtor
// hole, file_module.cc NOT compiled); the probe news FileInspect over
// PINNED raw byte storage cast to FileIdModule* — the witness load_config
// body ignores `this` (file_module.cc:263-:266 only touches the private fc
// member), witness standover documented. V7 reaches the file-static
// wiring THROUGH the InspectApi record off the sin_file_flow global
// (BaseApi is the prefix; iapi->pinit/ctor/dtor == file_init/file_ctor/
// file_dtor).
// R11: eval() is inline-empty (h:33) — no eval vector exists.
//
// Ordering hygiene: mutating calls hoisted into locals before printf; no
// addresses (vectors hygiene gate rejects 0x[0-9a-f]{6,}); counts and enum
// ints only.
#include "file_api/file_cache.h"
#include "file_api/file_config.h"
#include "file_api/file_flows.h"
#include "file_api/file_inspect.h"
#include "file_api/file_module.h"
#include "file_api/file_service.h"
#include "framework/inspector.h"
#include "main/snort_config.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>

// stub seams (stubs.cc) + the row's own public free getter (real cc:87).
extern "C" void fcache_set_file_inspector(int on);
extern "C" void fcache_set_file_cache(FileCache* c);
extern "C" void fcache_set_mp_dbus(int on);
extern "C" void fcache_set_max_file_depth(long long d);
extern "C" void fcache_set_file_service(int on);
extern "C" void fconf_set_file_inspector_null(int on);
extern "C" void finspect_arm_mod_fc(void);
extern "C" void finspect_set_dbus_get_id(unsigned id);
extern "C" unsigned finspect_mp_reg_calls();
extern "C" unsigned finspect_mp_sub_calls();
FileInspect* get_stub_file_inspector();           // stubs.cc (C++ linkage)
extern const snort::BaseApi* sin_file_flow;       // file_inspect.cc:175

using namespace snort;

static FileIdModule* pinned_mod()
{
    // R3 standover: never constructed/destroyed; the witness load_config
    // body ignores `this` (documented deviation).
    alignas(FileIdModule) static unsigned char buf[sizeof(FileIdModule)];
    return reinterpret_cast<FileIdModule*>(buf);
}

int main(void)
{
    SnortConfig* sc = SnortConfig::get_conf();

    // ---- V8a: load_config STEAL semantics standalone (file_module.cc:
    // 263-:266 replica): arm -> first steal hands the heap ptr, slot goes
    // null; SECOND arm = dst null (the steal-then-second-null arm). ----
    finspect_arm_mod_fc();
    FileConfig* s1 = nullptr;
    pinned_mod()->load_config(s1);
    FileConfig* s2 = nullptr;
    pinned_mod()->load_config(s2);
    std::printf("V8a_steal first=%d second=%d\n", s1 ? 1 : 0, s2 ? 1 : 0);
    delete s1;                                     // heap-only hand-off (R2)

    // ---- V2-V7 over the TOGGLE singleton (the re-armed
    // fcache_set_file_inspector path, R1/R2): the ctor runs the REAL
    // load_config steal (FIM line rides: dst=fc, fc=nullptr), config is
    // HEAP-owned only. The singleton deliberately LEAKS at exit: the IMGR
    // frozen witnesses keep the pointer; deleting it here would strand
    // them (production owns it via InspectorManager).
    // V8b: ctor steal -> non-null h:36 member + second-null proven in V8a.
    fcache_set_file_inspector(1);
    FileInspect* insp = get_stub_file_inspector();
    std::printf("V8b_ctor cfg=%d\n", insp->config ? 1 : 0);   // h:36 real member

    // V1: null-config early return arm (cc:61-:62): steal the freshly
    // armed heap slot AWAY from a LOCAL ctor so config stays nullptr;
    // configure returns true with ZERO DBUS/SMD witnesses and the REAL
    // adv static (cc:46) is still 0; show() :121 guard silent.
    {
        finspect_arm_mod_fc();                 // fresh heap slot
        FileConfig* held = nullptr;
        pinned_mod()->load_config(held);       // arm consumed by probe
        FileInspect nullcfg(pinned_mod());     // ctor steal -> config 0
        std::printf("V1_pre ctor_stole_null=%d adv=%u\n",
            nullcfg.config ? 1 : 0, get_file_adv_pub_id());
        delete held;
        bool v1 = nullcfg.configure(sc);
        std::printf("V1_null_arm ret=%d adv=%u\n", v1 ? 1 : 0,
            get_file_adv_pub_id());
        nullcfg.show(sc);
        std::printf("V1_show silent=1\n");
    }

        // V2: cache-armed trio ladder through the REAL FileCache setters
        // (cc:64-:70 -> file_cache.cc:130-:153, private members READ via
        // the FIXACC graft on the copy). instance_max=1 -> minimal_files=2:
        // clean arms land verbatim; max_files_cached=1 hits the clamp arm
        // (max_files = 2 + the REAL ErrorMessage format string, see the
        // fcache_harness twin line "WITNESS ErrorMessage Maximal number of
        // files cached should be greater than number of threads").
        FileCache cache(4);                        // real public ctor
        fcache_set_file_cache(&cache);
        insp->config->file_block_timeout = 777;    // -> set_block_timeout
        insp->config->file_lookup_timeout = 9;     // -> set_lookup_timeout
        insp->config->max_files_cached = 64;       // -> set_max_files
        bool v2 = insp->configure(sc);
        std::printf("V2_trio ret=%d bt=%" PRId64 " lt=%" PRId64 " mf=%" PRId64 "\n",
            v2 ? 1 : 0, (int64_t)cache.block_timeout,
            (int64_t)cache.lookup_timeout, (int64_t)cache.max_files);
        // clamp arm: below minimal_files(=instance_max+1=2) -> clamp to 2.
        insp->config->max_files_cached = 1;
        insp->configure(sc);
        std::printf("V2_clamp mf=%" PRId64 "\n", (int64_t)cache.max_files);
        insp->config->max_files_cached = 64;

        // V5: mp_dbus skip arm then armed arm (cc:76-:83). Before arming,
        // two configures already ran -> reg/sub counts still 0 (skip pin).
        std::printf("V5_skip reg=%u sub=%u\n",
            finspect_mp_reg_calls(), finspect_mp_sub_calls());
        fcache_set_mp_dbus(1);
        insp->configure(sc);                       // reg_helpers + sub + leak
        std::printf("V5_arm reg=%u sub=%u\n",
            finspect_mp_reg_calls(), finspect_mp_sub_calls());
        fcache_set_mp_dbus(0);

        // V4: adv-pub-id static round trip over the REAL cc:46 atomic:
        // witness id 7 -> static -> REAL getter (cc:87) = 7; re-pin 9 ->
        // configure -> getter = 9 (monotonic readback through the real
        // getter, no setter left — static is file-local to the row .o).
        std::printf("V4_id a=%u\n", get_file_adv_pub_id());
        finspect_set_dbus_get_id(9);
        insp->configure(sc);
        std::printf("V4_id b=%u\n", get_file_adv_pub_id());

        // V3: set_max_file_depth INSTRUMENTED body (stubs, replica of
        // file_service.cc:227-:251) riding the REAL get_file_config ->
        // fi->config chain (file_config.cc:89-:100, R9). type enabled ->
        // depth = type_depth(+1 extra byte cc:245-:248 per call since
        // file_depth was consumed); sig-enabled bump path; conf-null arm
        // through the fconf null toggle (NOT retired, R9; re-arm after —
        // frozen fconf G3 teardown rule).
        fcache_set_file_service(1);                // type static enabled
        insp->configure(sc);
        std::printf("V3_depth typeon=%" PRId64 " cfgdepth=%" PRId64 "\n",
            (int64_t)FileService::get_max_file_depth(insp->config),
            (int64_t)insp->config->file_depth);
        FileService::file_signature_enabled = true;   // FIXACC-public static
        insp->configure(sc);
        std::printf("V3_depth sigon=%" PRId64 "\n",
            (int64_t)FileService::get_max_file_depth(insp->config));
        fconf_set_file_inspector_null(1);          // get_file_config -> null
        insp->configure(sc);                       // SMD conf=0 readout arm
        fcache_set_max_file_depth(4242);           // stub-side static arm (getter body is the donor stub: returns g)
        std::printf("V3_depth gsetter=%" PRId64 "\n",
            (int64_t)FileService::get_max_file_depth(insp->config));
        fconf_set_file_inspector_null(0);          // re-arm BEFORE next reads

        // V6: the 18-caption show ladder (file_config_show cc:90-:117),
        // four enable arms: FileService statics x3 (cc:92/:95/:101 gates),
        // block_timeout_lookup (cc:98) + the 3 trace flags (cc:114-:116).
        // The CFGLOG lines replicate the REAL caption column ("%25s: " +
        // PRId64/PRIu64/enabled|disabled, messages.cc:364-:371/:545-:559);
        // gating semantics (log_flag RETURNS the flag) are the real ones.
        // arm A: everything off -> only the 7 unconditional tail lines.
        fcache_set_file_service(0);
        FileService::file_signature_enabled = false;
        FileService::file_capture_enabled = false;
        insp->config->block_timeout_lookup = false;
        insp->config->trace_type = false;
        insp->config->trace_signature = false;
        insp->config->trace_stream = false;
        insp->show(sc);
        // arm B: type + block_timeout_lookup on -> gated values ride.
        fcache_set_file_service(1);
        insp->config->block_timeout_lookup = true;
        insp->show(sc);
        // arm C: capture on -> the 4-value capture block (ulong overload).
        fcache_set_file_service(0);
        insp->config->block_timeout_lookup = false;
        FileService::file_capture_enabled = true;
        insp->show(sc);
        // arm D: the three trace flags on (ungated log_flag tails).
        FileService::file_capture_enabled = false;
        insp->config->trace_type = true;
        insp->config->trace_signature = true;
        insp->config->trace_stream = true;
        insp->show(sc);
        fcache_set_file_service(0);
        insp->config->trace_type = false;
        insp->config->trace_signature = false;
        insp->config->trace_stream = false;

        // V7: sin_file_flow record consts read OFF the global (cc:147-:175
        // + :175): PT_INSPECTOR, sizeof(InspectApi), INSAPI_VERSION split,
        // version 0, API_RESERVED, API_OPTIONS(=0 harness macro),
        // FILE_ID_NAME/FILE_ID_HELP (17u consts), IT_PASSIVE,
        // PROTO_BIT__NONE, "file", wiring fn presence. file_init round
        // trip: file_flow_data_id transitions via the stub-side
        // FlowData::create_flow_data_id ladder; file_ctor/file_dtor wired
        // probe against the witness module (NEVER mod_ctor/mod_dtor).
        const BaseApi* base = sin_file_flow;
        // the InspectApi prefix trick (base_api.h:72-73 "BaseApi must be
        // the prefix"): C-style downcast between UNRELATED structs --
        // reinterpret_cast, the plugin loader's own idiom.
        const InspectApi* iapi = reinterpret_cast<const InspectApi*>(base);
        std::printf("V7_base type=%d size=%u apiver=%d apiver_lo=%d ver=%u feat=%llu opts=%d name=%s help=%s\n",
            (int)base->type, base->size, (int)(base->api_version >> 16),
            (int)(base->api_version & 0xffff), base->version,
            (unsigned long long)base->features, base->options ? 1 : 0,
            base->name, base->help);
        std::printf("V7_api itype=%d proto_bits=%u svc=%s bufs=%d pinit=%d pterm=%d tinit=%d tterm=%d ctor=%d dtor=%d ssn=%d reset=%d\n",
            (int)iapi->type, iapi->proto_bits, iapi->service ? iapi->service : "(null)",
            iapi->buffers ? 1 : 0, iapi->pinit ? 1 : 0, iapi->pterm ? 1 : 0,
            iapi->tinit ? 1 : 0, iapi->tterm ? 1 : 0, iapi->ctor ? 1 : 0,
            iapi->dtor ? 1 : 0, iapi->ssn ? 1 : 0, iapi->reset ? 1 : 0);
        unsigned fd_before = FileFlows::file_flow_data_id;
        iapi->pinit();                             // file_init -> FileFlows::init()
        unsigned fd_after = FileFlows::file_flow_data_id;
        std::printf("V7_init fdid=%u->%d\n", fd_before,
            (int)(fd_after - fd_before));          // +1 via stub create_flow_data_id
        finspect_arm_mod_fc();                     // fresh heap for the wiring probe
        Inspector* w = iapi->ctor(static_cast<Module*>(pinned_mod()));  // = file_ctor
        std::printf("V7_wiring ctor_have=%d\n", w ? 1 : 0);
        iapi->dtor(w);                             // = file_dtor -> real dtor, heap config freed
        std::printf("V7_wiring dtor_done=1\n");
        fcache_set_file_cache(nullptr);

    // ---- V8c: the IMGR seam against the REAL .o: the toggle-armed
    // singleton (constructed once at V8b above over the witness module,
    // FIM load_config print rode there) — get_file_config(sc) — the REAL
    // file_config.cc:94-:99 cast chain — must hand back the same member
    // (R9: the cast reads the REAL h:36 member now). Singleton deliberately
    // LEAKS: the harness never runs InspectorManager teardown (production
    // owns it; R3 leak posture, documented). ----
    FileInspect* fi = get_stub_file_inspector();
    FileConfig* thru = get_file_config(sc);        // REAL fi->config read
    std::printf("V8c_seam insp=%d cfg=%d thru_same=%d\n",
        fi ? 1 : 0, fi ? (fi->config ? 1 : 0) : 0,
        (fi and thru == fi->config) ? 1 : 0);

    std::printf("FINSPECT_PROBE_DONE\n");
    return 0;
}
