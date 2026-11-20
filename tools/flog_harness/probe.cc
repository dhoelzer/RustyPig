// probe.cc — ground-truth transcript for the file-log Inspector TU row,
// file_api/file_log.cc (row 17z; NO file_log.h exists — every class is
// TU-local, so the probe reaches the ENTIRE row through its only data
// export sin_file[] + the witness seams). ZERO TEST_CASEs / ZERO
// UNIT_TEST (PLAN 1: file_log.cc / text_log.cc / module.cc all 0/0) and
// ZERO retired witnesses (R5: the donor closure witnessed NOTHING of
// this row): the row .o's sin_file[0]=&fl_api.base answers the whole
// record ladder (base.mod_ctor -> REAL FileLogModule + REAL Module
// ctor; api.ctor -> REAL fl_ctor -> REAL FileLog over the stub
// Inspector; configure -> W1 DataBus::subscribe witness ONLY, the real
// bus NEVER runs (R4) — flog_sub_handler() fires handle() DIRECTLY off
// the DataHandler vtable; api.tinit/tterm -> dl_tinit/dl_tterm -> the
// REAL TextLog_Init/Term over the get_main_file witness (file.log in
// CWD; R2 single-thread TLS posture for fl_stats + tlog).
// R1 TIME PIN: packet clock fixed via the REAL packet_time_update
// ({1700000000,500000} -> ts_print mm/dd-hh:mm:ss.uuuuuu under the shim
// conf: thiszone 0, output_use_utc false, output_include_year false);
// log_sys_time STAYs false through every handle arm — the wall
// gettimeofday is NEVER read (the sys-time arm is pinned by the set()
// ladder + the CFGLOG show pair ONLY).
// WINDOW TRICK (TextLog's 64K buffer holds the lines until Term): the
// row api pair closes/opens the log twice — window 1 = V4+V5 bodies,
// window 2 = V6+V7 — each tterm flush+fclose, then log_lines() dumps the
// bytes written since the last read (REAL flush/roll ladder, R2).
// R3 FORMAT PINS: SHA hex UPPERCASE (conv[] file_lib.cc), the sanitizer
// |XX XX| add_space run quirk (cc:119-:128 first byte NO leading space),
// TIMEBUF_SIZE 27, one SfIpString reused for the ip pair (cc:162-:164).
// The V2 show_stats pair rides ONLY the REAL Module::show_stats /
// show_interval_stats bodies in module.o -> the W2 witnesses (stats.cc
// NEVER cps). Hygiene: no 0x[0-9a-f]{6,} anywhere in the transcript.
#include "file_api/file_cache.h"            // FileCache (the context seam)
#include "file_api/file_config.h"           // get_file_config (REAL 17u)
#include "file_api/file_lib.h"              // FileContext fixture arms
#include "file_api/file_flows.h"            // REAL FileFlows (17o carry)
#include "framework/data_bus.h"             // DataHandler + BareDataEvent
#include "framework/inspector.h"            // the REAL InspectApi record
#include "framework/module.h"               // REAL module.o method ladder
#include "framework/parameter.h"            // the params-table readback
#include "framework/value.h"                // set() ladder Values
#include "log/text_log.h"                   // the REAL 17z cp (TextLog)
#include "main/snort_config.h"              // the EOFCFG shim
#include "time/packet_time.h"               // REAL packet clock arms
#include "utils/util.h"                     // TIMEBUF_SIZE

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/time.h>
#include <vector>

using namespace snort;

// the row's only non-static data export (file_log.cc:324, D, global)
extern const BaseApi* sin_file[];

// donor seams (stubs.cc, VERBATIM arms)
extern "C" void fcache_set_file_cache(FileCache* c);        // donor
extern "C" void fcache_set_file_service(int on);            // donor
extern "C" void fcache_clear_flow_slot();                   // donor :723
extern "C" void fcache_enable_fake_clock(int on);           // donor :96
extern "C" void finspect_arm_mod_fc(void);                  // donor
extern "C" void fcache_set_file_inspector(int on);          // donor

// NEW17z W1 witness seams (stubs.cc NEW17z block)
extern "C" DataHandler* flog_sub_handler();
extern "C" unsigned flog_sub_calls();

static FlowKey g_fkey;
static Flow g_flow;

// file.log readback: every byte the REAL TextLog stack wrote since the
// previous read (call only between a tterm and the next tinit).
static long g_log_off = 0;
static int g_log_lines = 0;
static void log_lines(const char* tag)
{
    FILE* f = fopen("file.log", "rb");
    if (!f) { std::printf("%s missing=1 bytes=0 lines=0 noeol=0\n", tag); return; }
    fseek(f, 0, SEEK_END);
    long end = ftell(f);
    fseek(f, g_log_off, SEEK_SET);
    int lines = 0, c, last = '\n';
    while ((c = fgetc(f)) != EOF)
    {
        std::putchar(c);
        if (c == '\n') ++lines;
        last = c;
    }
    if (last != '\n') std::printf("(noeol)\n");
    fclose(f);
    std::printf("%s bytes=%ld lines=%d noeol=%d\n", tag, end - g_log_off,
        lines, last != '\n' ? 1 : 0);
    g_log_lines += lines;
    g_log_off = end;
}

int main(void)
{
    fcache_enable_fake_clock(1);
    remove("file.log");
    g_flow.key = &g_fkey;
    finspect_arm_mod_fc();
    fcache_set_file_inspector(1);
    FileConfig* const cfg = get_file_config();   // REAL (17u heap chain)
    g_flow.client_port = 1234;                   // NEW17z flowz ports
    g_flow.server_port = 80;
    g_flow.client_ip.set("1.2.3.4");
    g_flow.server_ip.set("5.6.7.8");

    // ---- V1: registry + record statics (zero-call) + open log window 1.
    const InspectApi* api = reinterpret_cast<const InspectApi*>(sin_file[0]);
    {
        int n = 0; while (sin_file[n]) ++n;
        std::printf("V1_registry n=%d name=%s help=%s size=%u apiver=%u plugtype=%d "
            "itype=%d pbits=%d second=%s third_null=%d\n",
            n, api->base.name, api->base.help, api->base.size, api->base.api_version,
            (int)api->base.type, (int)api->type, (int)api->proto_bits,
            sin_file[1] ? sin_file[1]->name : "-", sin_file[2] ? 0 : 1);
        std::printf("V1_statics tb=%d api_sz_ge=%d pc8=%d pegsz=%d pubkey_sz=%zu mfpf=%" PRIu64 " "
            "tinit=%d tterm=%d ctor=%d dtor=%d pinit=%d pterm=%d ssn=%d reset=%d buf=%d file=%d\n",
            TIMEBUF_SIZE,
            sizeof(InspectApi) >= sizeof(BaseApi) ? 1 : 0,
            sizeof(PegCount) == 8 ? 1 : 0,
            sizeof(PegInfo) == 24 ? 1 : 0,
            sizeof(PubKey), cfg->max_files_per_flow,
            api->tinit ? 1 : 0, api->tterm ? 1 : 0, api->ctor ? 1 : 0,
            api->dtor ? 1 : 0, api->pinit ? 1 : 0, api->pterm ? 1 : 0,
            api->ssn ? 1 : 0, api->reset ? 1 : 0, 64 * K_BYTES, 1 * M_BYTES);
        api->tinit();                             // dl_tinit -> REAL Init
        FILE* probe_f = fopen("file.log", "rb");
        if (probe_f) fclose(probe_f);
    }

    // ---- V2: REAL module ladder: real mod_ctor + real Module ctor, the
    // params table, pegs, usage (module.o bodies).
    Module* mod = api->base.mod_ctor();
    {
        const Parameter* p = mod->get_parameters();
        const PegInfo* pegs = mod->get_pegs();
        std::printf("V2_params p0=%s d0=%s pt0=%d p1=%s d1=%s pt1=%d last_null=%d ptmax=%d "
            "name=%s peg0=%s help0=%s type0=%d end1=%d usage=%d counts=%d\n",
            p[0].name, p[0].deflt, (int)p[0].type, p[1].name, p[1].deflt,
            (int)p[1].type, p[2].name ? 0 : 1, (int)Parameter::PT_MAX,
            mod->get_name(), pegs[0].name, pegs[0].help,
            (int)pegs[0].type, pegs[1].type == CountType::END ? 1 : 0,
            (int)mod->get_usage(), mod->get_counts() ? 1 : 0);
    }

    // ---- V2b: ctor + set() ladder + the REAL FileLog::show CFGLOG pair.
    // NOTE the real wiring (cc:283-:287): fl_ctor COPIES the module config
    // into the inspector -- so one more ctor after each flip re-signs it.
    Inspector* insp = nullptr;
    {
        insp = api->ctor(mod);                    // fl_ctor, defaults
        insp->show(SnortConfig::get_conf());      // CFGLOG pkt=enabled sys=disabled
        Parameter pp = { "log_sys_time", Parameter::PT_BOOL, nullptr, "false", nullptr };
        Parameter pq = { "log_pkt_time", Parameter::PT_BOOL, nullptr, "true", nullptr };
        Parameter pu = { "bogus_name", Parameter::PT_BOOL, nullptr, "false", nullptr };
        Value v1(true);  v1.set(&pp);
        Value v2(false); v2.set(&pq);
        Value v5(true);  v5.set(&pu);             // neither arm matches
        int a = mod->set("log_sys_time", v1, nullptr) ? 1 : 0;
        int b = mod->set("log_pkt_time", v2, nullptr) ? 1 : 0;
        int c = mod->set("bogus_name", v5, nullptr) ? 1 : 0;
        Inspector* insp_flip = api->ctor(mod);    // re-signed copy: sys=1 pkt=0
        std::printf("V2b_set non=%d ret=%d%d%d show_flip\n", insp ? 1 : 0, a, b, c);
        insp_flip->show(SnortConfig::get_conf());
        Value v3(false); v3.set(&pp);
        Value v4(true);  v4.set(&pq);
        mod->set("log_sys_time", v3, nullptr);
        mod->set("log_pkt_time", v4, nullptr);
        insp = api->ctor(mod);                    // back to defaults (the LIVE one)
        std::printf("V2b_back\n");
        insp->show(SnortConfig::get_conf());
    }

    // ---- V3: configure() -> W1 subscribe ONLY (R4: the bus never runs).
    {
        unsigned before = flog_sub_calls();
        bool ok = insp->configure(nullptr);       // real body cc:210-:214
        DataHandler* h = flog_sub_handler();
        std::printf("V3_sub ret=%d calls=%d->%d stashed=%d tag=%s\n",
            ok ? 1 : 0, before, flog_sub_calls(), h ? 1 : 0,
            (h and h->module_name) ? h->module_name : "(null)");
    }
    DataHandler* hnd = flog_sub_handler();
    BareDataEvent evt;
    struct timeval tv = { 1700000000, 500000 };   // the R1 pinned clock

    // ---- V4: the pinned packet clock + handle() early-return arms. The
    // R1 arm: log_sys_time stays false -> ONLY packet_gettimeofday is
    // read. Both early-return arms STILL emit the timestamp + ip pair
    // (cc:142-:164) -- the buffer merges them into the NEXT line (the
    // partial-line handle() quirk, frozen in the window dump).
    {
        packet_time_update(&tv);                  // REAL body (17o carry)
        fcache_set_file_service(0);
        fcache_clear_flow_slot();
        hnd->handle(evt, &g_flow);                // no FileFlows -> early
        fcache_set_file_service(1);               // the create arm
        hnd->handle(evt, &g_flow);                // FileFlows yes, ctx null
    }

    // ---- V4c: REAL context through the cache seam + ip pair + Verdict
    // walk x8 (VerdictName cc:178 <- file_lib.h:38-:39) + Type 3-arm.
    FileFlows* ff = FileFlows::get_file_flows(&g_flow, false);
    FileContext* x = nullptr;
    static FileCache v4_cache(16);
    {
        fcache_set_file_cache(&v4_cache);
        bool isnew = false;
        x = ff->get_file_context(700, true, isnew);   // the REAL create arm
        ff->set_current_file_context(x);              // file_id slot cleared
        x->set_file_name("hello.txt", 9);
        x->set_file_size(0);
        std::printf("V4c_ctx isnew=%d name=%s sv=%ld.%ld\n", isnew ? 1 : 0,
            x->get_file_name().c_str(), (long)tv.tv_sec, (long)tv.tv_usec);
        for (int v = 0; v <= 7; ++v)
        {
            x->verdict = (FileVerdict)v;            // 7 names + INVALID idx
            hnd->handle(evt, &g_flow);
        }
        x->verdict = FILE_VERDICT_UNKNOWN;
        x->set_file_type(SNORT_FILE_TYPE_CONTINUE); // the 2 Type arms (cc:44)
        hnd->handle(evt, &g_flow);
        x->set_file_type(SNORT_FILE_TYPE_UNKNOWN);
        hnd->handle(evt, &g_flow);
        x->set_file_type(SNORT_FILE_TYPE_CONTINUE); // restore (no rule-5 drag)
    }

    // ---- V5: sanitizer arms (empty / printable / runs / tail run). ----
    {
        x->file_name.clear();                       // empty -> NO [Name:]
        x->file_name_set = false;                   // (FIXACC: file_lib.h
        hnd->handle(evt, &g_flow);
        x->set_file_name("aZ~ ", 4);                // printable incl. space
        hnd->handle(evt, &g_flow);
        char mixed[] = { 'A', 0x01, 0x02, 0x7F, 'B', '\xE9', 'C' };
        x->set_file_name(mixed, 7);
        hnd->handle(evt, &g_flow);                  // A|01 02 7F|B|E9|C
        x->set_file_name("tail:", 5);               // single-byte tail run
        x->file_name.append(1, '\x80');             //   -> tail:|80|
        hnd->handle(evt, &g_flow);
        api->tterm();                               // dl_tterm: flush+close
        log_lines("W1_file");                       // window-1 dump
        api->tinit();                               // window 2 (append)
    }

    // ---- V6: SHA UPPERCASE pin + Size skip-at-0 vs present arm. ----
    {
        x->set_file_name("sha.bin", 7);
        delete[] x->sha256;                         // null (dtor-safe)
        x->sha256 = new uint8_t[32];                // FileInfo dtor delete[]s
        std::memset(x->sha256, 0xAB, 32);
        x->set_file_size(0);
        hnd->handle(evt, &g_flow);                  // [SHA: ABAB...] no Size
        x->set_file_size(4096);
        hnd->handle(evt, &g_flow);                  // SHA + [Size: 4096]
        hnd->handle(evt, &g_flow);                  // V7-lead re-arm (3rd SHA)
    }

    // ---- V7: the REAL module.o stats ladder -> the W2 show_stats pair.
    // sum_stats(false): init_stats via the get_instance_max witness -> the
    // SUM drain zeroes the THREAD_LOCAL peg; show_stats/show_interval_stats
    // reach W2 ONLY through the real inlines (stats.cc NEVER links).
    {
        uint64_t pre = *mod->get_counts();
        mod->sum_stats(false);
        uint64_t post = *mod->get_counts();
        mod->main_accumulate_stats();
        std::printf("V7_counts pre=%" PRIu64 " post=%" PRIu64 "\n", pre, post);
        mod->show_stats();                          // -> W2 scalar arm
        std::vector<unsigned> idx = { 0 };
        mod->show_interval_stats(idx, stdout);      // -> W2 vector arm
        std::printf("V7_ggc g=%" PRIu64 "\n", mod->get_global_count("total_events"));
        hnd->handle(evt, &g_flow);                  // counter runs again
        std::printf("V7_again now=%" PRIu64 "\n", *mod->get_counts());
        mod->reset_stats();                         // the REAL dtor-free reset
        std::printf("V7_reset now=%" PRIu64 "\n", *mod->get_counts());
        api->tterm();                               // close window 2
        log_lines("W2_file");
    }

    // ---- V8: drain the fixture VERBATIM (fflows protocol: null current,
    // delete ff drains partially_processed_contexts incl x -> the REAL
    // FileInfo dtor frees the sha256 buffer); then the file cleanup pin
    // (git-clean harness dir: the probe removes what it wrote).
    {
        ff->set_current_file_context(nullptr);
        delete ff;                                  // dtor: policy ref pair
        fcache_clear_flow_slot();
        fcache_set_file_cache(nullptr);
        fcache_set_file_service(0);
        long total = 0;
        FILE* f = fopen("file.log", "rb");
        if (f) { fseek(f, 0, SEEK_END); total = ftell(f); fclose(f); }
        std::printf("V8_sweep lines=%d total_bytes=%ld removed=%d\n",
            g_log_lines, total, remove("file.log") == 0 ? 1 : 0);
        api->base.mod_dtor(mod);                    // real mod_dtor: delete
    }

    std::printf("FLOG_PROBE_DONE\n");
    return 0;
}
