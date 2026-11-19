// probe.cc — ground-truth transcript for the file_service TU row,
// file_api/file_service.{h,cc} (row 17y). ZERO TEST_CASEs / ZERO UNIT_TEST
// (PLAN 1; re-asserted in build.sh): the ENTIRE FileService witness block is
// RETIRED (R5 dup rule, 23 hard collisions: 17 T + 6 B/D) and the probe
// drives the REAL file_service.o bodies through the donor seam stack:
//   V1  sizeofs/enum pins (PLAN 0.8) + h:60 default-init + REAL find seed
//   V2  enable trio + REAL cascade (cc:199-:204) + the is_file_service
//       2-OR QUIRK (cc:208) vs the retired 3-OR witness drift (PLAN 5 R3)
//       -- the capture-ONLY arm is written through the FIXACC-public real
//       static (the drift condition t=0,s=0,c=1 is UNREACHABLE via the
//       public API because of the cc:203 cascade; the pin documents that)
//   V3  clear-status 5-arm ladder (cc:86-:105): UNAVAILABLE (fsvc conf-null
//       arm), MULTIPROCESS x2 (||-short-circuit -> ZERO pause-witness
//       calls: freeze=0), NOT_INITIALIZED, PACKET_THREADS_BUSY
//       pause-both-ways, READY + the REAL FileCache::clear() report
//       (cc:112-:113) + h:94 const-contract + the non-READY clear NO-FIRE
//       arm (cc:111) + READY/empty zero-walk
//   V9  the reset() gate BOTH ways over the NEW get_inspector witness
//       (cc:66-:74): closed -> the statics clear; open -> they SURVIVE
//       (gate-open is ALSO what keeps capture lit into the verify_reload
//       cc:157 guard and the post_init cc:136 arm -- the upstream order)
//   V4  verify_reload FIRST pass: shadows are 0 at load -> ReloadError x3
//       through the RESIDENT witness (stubs.cc:123; max drift cc:154 +
//       the capture pair under the file_capture_enabled guard cc:157-:163)
//       + the UNKNOWN_PROTOCOL_ID re-arm through the REAL find (17y cp);
//       the conf-null arm (cc:149) where reset STILL clears the statics
//   V5  post_init EXACTLY ONCE (cc:118-:144): gate-open reset, "WITNESS
//       MimeSession::init" BEFORE the conf check (cc:120-:121 order pin),
//       lazy cache NEW(8) + timeouts (cc:128-:134), capture pair ->
//       file-scope shadow COPY + the REAL FileCapture::init writer thread
//       (R9 the ONE pair, closed by the real close, R2), proto arm cc:143;
//       V5b the lazy-cache KEEP cc:127 + empty READY clear
//   V6  verify_reload SECOND pass: shadows LANDED from post_init -> ZERO
//       ReloadError lines (the copy-vs-compare semantics pin: cc:154 NEVER
//       assigns; only post_init copies) + spid stays (cc:165 false)
//   V8  depth ladders cc:211-:252: conf-null -1, neg -1, config pass, the
//       fc-ARG arm wins, the h:89 default-arg arm, the R4 drift (the armed
//       g_max_file_depth shadow INERT); set: type copy + "extra byte"++,
//       sig-gt raise, both-off neg stays (cc:245 guard)
//   V10 collect_cache_usage (cc:76-:84) over the REAL snapshot.h inlines:
//       null-cache return, entries>0 gate, "File cache entries" counter
//       name + uint64 Value readback
//   V11 close (cc:171-:181): ONLY-owner delete + null (R2 pair pin),
//       "WITNESS MimeSession::exit", FileCapture::exit joins the V5 thread
//   V12 thread_init/term -> the REAL file_stats calloc/free cycle
//   V13 the REAL snort::get_file_processed_size three arms (cc:254-:270,
//       the retired stubs.cc:711 verbatim copy is GONE -- landmine): no
//       FileFlows -> 0; no current context -> 0; REAL context + REAL
//       update_file_size(7, MIDDLE) -> 7; fflows fixture drained VERBATIM
//   V14 the REAL init() -> the inlined FileFlows::init() -> the resident
//       create_flow_data_id witness: the id ladder lands 1
// R2/heap posture: the config flows through the REAL donor chain
// (finspect_arm_mod_fc -> fcache_set_file_inspector(1): the real ~FileInspect
// owns the HEAP g_mod_fc steal; get_file_config() answers fi->config;
// NEVER &g_stub_file_config (the 17w R2 static-UB rule). The proto_ref is a
// REAL ProtocolReference (17y real cp: ctor unknown..file, probe
// add("file_id")=6; find BODY resolves cc:143/:167) -- pinned leak
// (exit-borrow like the npolicy block). post_init ONCE, close ONCE, same
// cache: the R2 new/delete pair. Writer thread: init V5 -> exit V11 only.
// The fake clock rides ON at t=100 (donor arms); MPDataBus NEVER armed.
// Determinism: the NEW witnesses emit their donor formats VERBATIM
// (WITNESS packet_threads_fully_paused=<v> / WITNESS MimeSession::init|
// exit / IMGR get_inspector file_inspect usage=0 -> inspector|null); no
// pointers in the transcript (hygiene gate: 0x[0-9a-f]{6,} banned).
#include "file_api/file_api.h"             // FileCacheClearReport + free fn
#include "file_api/file_cache.h"           // FileCache + FileHashKey
#include "file_api/file_capture.h"         // the capture seam pair
#include "file_api/file_config.h"          // get_file_config + FileConfig
#include "file_api/file_flows.h"           // REAL FileFlows (17o carry)
#include "file_api/file_lib.h"             // FileContext members
#include "file_api/file_service.h"         // THE ROW (real statics/getters)
#include "file_api/file_stats.h"           // donor file_stats_init pin (rc 139)
#include "flow/flow_key.h"                 // harness FlowKey (make_key seam)
#include "main/snort_config.h"             // the EOFCFG shim (public arms)
#include "target_based/snort_protocols.h"  // the REAL 17y cp

#include "utils/stats/snapshot.h"          // REAL stats inlines

#include <cinttypes>
#include <cstdint>
#include <cstdio>

using namespace snort;

// donor seams (stubs.cc, VERBATIM arms)
extern "C" void fcache_set_file_cache(FileCache* c);        // :639
extern "C" void fcache_set_max_file_depth(long long d);     // :732
extern "C" void fcache_set_file_service(int on);            // :735
extern "C" void fcache_set_mp_dbus(int on);                 // :345
extern "C" void fcache_clear_flow_slot();                   // :709
extern "C" void fcache_enable_fake_clock(int on);           // :89
extern "C" void finspect_arm_mod_fc(void);                  // :425
extern "C" void fcache_set_file_inspector(int on);          // :432
extern "C" void fconf_set_file_inspector_null(int on);      // :458

// NEW17y witness seams (stubs.cc NEW17y block)
extern "C" void fsvc_set_paused(int v);
extern "C" int  fsvc_pause_calls();
extern "C" void fsvc_get_inspector_arm(int on);
extern "C" void fsvc_set_conf_null(int on);

// harness fixture Flow + FlowKey (VERBATIM fflows probe :75-:77 pattern:
// zero statics, FlowKey asid 0 so FileCache::make_key lands == FileHashKey{}
// bytes except file_id; cc:371 derefs flow->key -- a null key = SEGV, the
// fflows :96 g_flow.key = &g_fkey seam is CARRIED).
static FlowKey g_fkey;
static Flow g_flow;

int main(void)
{
    fcache_enable_fake_clock(1);                    // t pinned at 100.0
    g_flow.key = &g_fkey;                           // fflows :96 seam (cc:371)
    // the REAL config chain: heap FileConfig via the load_config steal
    // (17w R2), reached through the REAL get_file_config (file_config.o).
    finspect_arm_mod_fc();
    fcache_set_file_inspector(1);
    FileConfig* const cfg = get_file_config();
    // the harness proto_ref: REAL ctor (snort_protocols.o: unknown..file)
    // + the literal "file_id" the row cc:143/cc:167 look up.
    ProtocolReference* pr = new ProtocolReference;
    SnortConfig::get_conf()->proto_ref = pr;
    int spid_file_id = (int)pr->add("file_id");     // REAL add body -> 6

    // ---- V1: sizeof/enum pins (PLAN 0.8) + the h:60 default init.
    {
        FileCacheClearResult r;
        std::printf("V1_sizes rc=%u st=%u rs=%u dec=%u def=%d spid=%d\n",
            (unsigned)sizeof(FileCacheClearReport),
            (unsigned)sizeof(FileCacheClearStatus),
            (unsigned)sizeof(FileCacheClearResult),
            (unsigned)sizeof(FileService::decode_conf),
            (int)r.status, spid_file_id);
        std::printf("V1_enum r=%d m=%d u=%d n=%d b=%d\n",
            (int)FileCacheClearStatus::READY,
            (int)FileCacheClearStatus::MULTIPROCESS,
            (int)FileCacheClearStatus::UNAVAILABLE,
            (int)FileCacheClearStatus::NOT_INITIALIZED,
            (int)FileCacheClearStatus::PACKET_THREADS_BUSY);
    }

    // ---- V2: pre-init static read (R1 zero-init arm), the enable trio +
    // the REAL cascade (cc:203 re-signs), svc 2-OR true side. V2b: the
    // capture-ONLY drift arm through the FIXACC-public real static (the
    // ONLY way to reach t=0,s=0,c=1 -- the public API cascades): REAL 2-OR
    // -> svc=0; the retired donor witness (3-OR) would have said 1.
    {
        fcache_set_file_service(0);
        int pre = (int)FileService::is_file_service_enabled();
        FileService::enable_file_type();
        int t = (int)FileService::is_file_type_id_enabled();
        FileService::enable_file_signature();
        int s = (int)FileService::is_file_signature_enabled();
        FileService::enable_file_capture();
        int c = (int)FileService::is_file_capture_enabled();
        int casc = (int)FileService::is_file_signature_enabled();
        std::printf("V2_enable pre=%d t=%d s=%d c=%d casc=%d svc=%d\n",
            pre, t, s, c, casc, (int)FileService::is_file_service_enabled());
        fcache_set_file_service(0);
        FileService::file_capture_enabled = true;   // FIXACC direct arm
        std::printf("V2b_drift c=%d svc=%d\n",
            (int)FileService::is_file_capture_enabled(),
            (int)FileService::is_file_service_enabled());   // 1 0 REAL 2-OR
        FileService::file_capture_enabled = false;
    }

    // ---- V3: the clear-status 5-arm ladder + pause-both-ways + the REAL
    // clear reports + contract pins over a populated LOCAL cache (the
    // svc static stays null through this block).
    {
        fsvc_set_paused(1);
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        bool cf = false; int64_t ce = 0;
        FileHashKey k1{}; k1.file_id = 11;
        FileHashKey k2{}; k2.file_id = 12;
        cache.add(k1, 60, cf, ce);
        cache.add(k2, 60, cf, ce);
        long long e_pop = cache.get_num_entries();

        fsvc_set_conf_null(1);                      // cc:89-:91
        int st_unavail = (int)FileService::get_file_cache_clear_status();
        fsvc_set_conf_null(0);
        int pc0 = fsvc_pause_calls();
        SnortConfig::get_conf()->max_procs = 2;     // cc:93
        int st_multi = (int)FileService::get_file_cache_clear_status();
        SnortConfig::get_conf()->max_procs = 1;
        fcache_set_mp_dbus(1);                      // cc:94
        int st_dbus = (int)FileService::get_file_cache_clear_status();
        fcache_set_mp_dbus(0);
        int freeze = fsvc_pause_calls() - pc0;      // || short-circuit: 0
        fcache_set_file_cache(nullptr);             // cc:96-:97
        int st_notinit = (int)FileService::get_file_cache_clear_status();
        fcache_set_file_cache(&cache);
        fsvc_set_paused(0);                         // cc:99-:101
        int st_busy = (int)FileService::get_file_cache_clear_status();
        long long e_unch = cache.get_num_entries(); // h:94 contract
        fsvc_set_paused(1);                         // cc:104 READY
        int st_ready = (int)FileService::get_file_cache_clear_status();
        std::printf("V3_ladder unavail=%d multi=%d dbus=%d freeze=%d notinit=%d busy=%d ready=%d\n",
            st_unavail, st_multi, st_dbus, freeze, st_notinit, st_busy,
            st_ready);
        std::printf("V3_unchanged same=%d\n", e_unch == e_pop ? 1 : 0);

        FileCacheClearResult clr = FileService::clear_file_cache();
        std::printf("V3_clear st=%d freed=%llu rem=%llu entries=%lld\n",
            (int)clr.status,
            (unsigned long long)clr.report.freed,
            (unsigned long long)clr.report.remaining,
            (long long)cache.get_num_entries());

        // the NON-READY clear (cc:111 guard): re-pop, unpaused -> BUSY ->
        // clear NO-FIRE -> the report is zero and the entries stay; then
        // re-paused the SAME entries clear to zero (READY walk).
        cf = false;
        cache.add(k1, 60, cf, ce);
        cache.add(k2, 60, cf, ce);
        fsvc_set_paused(0);
        FileCacheClearResult r2 = FileService::clear_file_cache();
        long long kept = cache.get_num_entries();
        fsvc_set_paused(1);
        FileCacheClearResult r3 = FileService::clear_file_cache();
        std::printf("V3_busyarm st=%d freed=%llu kept=%lld then st=%d freed=%llu empty=%lld\n",
            (int)r2.status, (unsigned long long)r2.report.freed, kept,
            (int)r3.status, (unsigned long long)r3.report.freed,
            (long long)cache.get_num_entries());
        // READY on the already-empty cache: zero-walk arm (freed=0).
        FileCacheClearResult r4 = FileService::clear_file_cache();
        std::printf("V3_empty st=%d freed=%llu\n",
            (int)r4.status, (unsigned long long)r4.report.freed);
        // R2 PIN: the local cache dies at block end -- the real static
        // NEVER dangles (post_init cc:127 then sees the true null).
        fcache_set_file_cache(nullptr);

        // ---- V9: the reset() gate BOTH ways (cc:66-:74). Closed (arm 0):
        // the get_inspector print shows -> null and the statics CLEAR.
        // Open (armed + toggle lit -> -> inspector): reset returns at cc:68
        // and the statics SURVIVE (this arm is also what feeds the V4
        // capture-guard + the V5 cc:136 capture arm -- upstream order).
        fcache_set_file_service(0);
        FileService::enable_file_type();
        FileService::enable_file_signature();
        FileService::reset();
        std::printf("V9_clear t=%d s=%d\n",
            (int)FileService::is_file_type_id_enabled(),
            (int)FileService::is_file_signature_enabled());
        fsvc_get_inspector_arm(1);
        FileService::enable_file_type();
        FileService::enable_file_signature();
        FileService::reset();                      // gate OPEN -> no clear
        std::printf("V9b_gate t=%d s=%d\n",
            (int)FileService::is_file_type_id_enabled(),
            (int)FileService::is_file_signature_enabled());
    }

    // ---- V4: verify_reload FIRST (the row shadows are 0 at load): the
    // get_inspector gate is OPEN (V9b left it armed) so reset returns at
    // cc:68 -> the enables SURVIVE -> the cc:157 file_capture_enabled
    // guard is TRUE -> reload-error x3 through the resident witness + the
    // re-arm cc:165-:168 answers REAL find("file_id")=6. NOTE the sc-
    // contract pin: cc:167 derefs the RAW sc param (NOT the get_conf()
    // fallback get_file_config uses at file_config.cc:91-:92) -- the
    // upstream caller snort.cc:542 always passes non-null (a null sc with
    // spid==UNKNOWN segfaults: contract pinned on the Rust side, not the
    // vectors).
    {
        cfg->max_files_cached = 8;                  // shadow drift
        FileService::enable_file_capture();         // t+s+c lit (cascade)
        cfg->capture_memcap = 1;                    // shadow drift
        cfg->capture_block_size = 32768;            // shadow drift
        cfg->snort_protocol_id = UNKNOWN_PROTOCOL_ID;
        FileService::verify_reload(SnortConfig::get_conf());   // 3 witness lines
        std::printf("V4_reload t=%d spid=%d\n",
            (int)FileService::is_file_type_id_enabled(),
            (int)cfg->snort_protocol_id);
        // conf-null arm (cc:149-:152): the inspector slot NULLed ->
        // get_file_config -> null -> EARLY RETURN before the sc deref,
        // but reset ran FIRST (gate now closed -> the statics clear).
        fsvc_get_inspector_arm(0);
        fconf_set_file_inspector_null(1);
        FileService::verify_reload(SnortConfig::get_conf());
        fconf_set_file_inspector_null(0);
        std::printf("V4c_nullconf t=%d spid=%d\n",
            (int)FileService::is_file_type_id_enabled(),
            (int)cfg->snort_protocol_id);
    }

    // ---- V5: post_init EXACTLY ONCE. Re-arm the gate (reset early-
    // returns -> the enables SURVIVE into cc:136 -- upstream order), the
    // Mime print BEFORE the conf check, lazy cache NEW(8) + timeouts,
    // capture pair shadow COPY + the writer thread (R9/RE2: closed by the
    // real close at V11 only), proto arm lands find again (idempotent).
    {
        fsvc_get_inspector_arm(1);
        FileService::enable_file_capture();               // re-arm cascade
        FileService::post_init();
        FileCache* svc_cache = FileService::get_file_cache();
        std::printf("V5_post cache=%d spid=%d t=%d c=%d\n",
            svc_cache ? 1 : 0, (int)cfg->snort_protocol_id,
            (int)FileService::is_file_type_id_enabled(),
            (int)FileService::is_file_capture_enabled());
        fsvc_get_inspector_arm(0);
        // V5b: cc:127 lazy-cache KEEP -- the identity survives a READY
        // status/clear pair on the FRESH (empty) cache.
        FileCacheClearResult r = FileService::clear_file_cache();
        std::printf("V5b_keep st=%d freed=%llu same=%d\n",
            (int)r.status, (unsigned long long)r.report.freed,
            (FileService::get_file_cache() == svc_cache) ? 1 : 0);
    }

    // ---- V6: verify_reload SECOND pass: post_init COPIED the shadow
    // statics (cc:129/:140-:141) -> ZERO reload-error lines (cc:154
    // NEVER assigns -- copy-vs-compare semantics); the gate closed here
    // clears the enables (t=0) yet spid STAYS (cc:165 false on the armed
    // find result).
    {
        FileService::verify_reload(SnortConfig::get_conf());    // zero witness lines
        std::printf("V6_clean t=%d spid=%d\n",
            (int)FileService::is_file_type_id_enabled(),
            (int)cfg->snort_protocol_id);
    }

    // ---- V8: the depth ladders (cc:211-:252).
    {
        cfg->file_depth = 1460;                     // type default pin
        fcache_set_max_file_depth(-7);              // INERT shadow (R4)
        int64_t ddef = FileService::get_max_file_depth();   // answers 1460
        fconf_set_file_inspector_null(1);           // conf-null cc:217-:219
        int64_t dnull = FileService::get_max_file_depth();
        fconf_set_file_inspector_null(0);
        fcache_set_max_file_depth(-9);              // still inert
        FileConfig fc; fc.file_depth = -5;          // fc-arg wins cc:215
        int64_t dneg = FileService::get_max_file_depth(&fc);
        std::printf("V8_get def=%lld null=%lld fcneg=%lld\n",
            (long long)ddef, (long long)dnull, (long long)dneg);
        fcache_set_file_service(0);
        FileService::enable_file_type();            // type-on cc:234-:237
        cfg->file_type_depth = 1460;
        cfg->file_signature_depth = 20;
        cfg->file_depth = 7;
        FileService::set_max_file_depth(nullptr);   // ->1460 then cc:247 ++
        std::printf("V8_set type=%lld\n", (long long)cfg->file_depth);  //1461
        fcache_set_file_service(0);
        FileService::enable_file_signature();       // sig-gt cc:239-:243
        cfg->file_depth = 7;
        FileService::set_max_file_depth(nullptr);   // 20>7 ->20 then ++
        std::printf("V8_set2 sig=%lld\n", (long long)cfg->file_depth);  //21
        fcache_set_file_service(0);                 // both off: neg stays
        cfg->file_depth = -5;
        FileService::set_max_file_depth(nullptr);
        std::printf("V8_set3 neg=%lld\n", (long long)cfg->file_depth);  //-5
    }

    // ---- V10: collect_cache_usage (cc:76-:84) over the REAL snapshot.h
    // inlines (PLAN 0.4: ZERO stats symbols in the residue). NOTE the
    // arm ORDER: capture the post_init cache ptr BEFORE nulling the real
    // static (null-cache arm), then re-arm the SAME cache -- the row owns
    // it (deleted by V11 close, R2 pair).
    {
        stats::Snapshot s;
        stats::Builder b(s);
        stats::Section& sec = b.section("file_api");
        stats::Group& grp = stats::Builder::group(sec, "File Cache");
        FileCache* svc_cache = FileService::get_file_cache(); // post_init cache
        fcache_set_file_cache(nullptr);
        FileService::collect_cache_usage(b, grp);          // cc:78 return
        std::printf("V10_null counters=%zu\n", grp.counters.size());
        fcache_set_file_cache(svc_cache);
        bool cf = false; int64_t ce = 0;
        FileHashKey k{}; k.file_id = 77;
        svc_cache->add(k, 60, cf, ce);                     // 1 entry
        FileService::collect_cache_usage(b, grp);          // cc:82-:83
        const stats::Counter& ctr = grp.counters[0];
        std::printf("V10_ctr counters=%zu name=%s v=%llu\n",
            grp.counters.size(), ctr.get_name(),
            (unsigned long long)std::get<uint64_t>(ctr.value));
        FileService::collect_cache_usage(b, grp);          // 2nd call -> +1
        std::printf("V10_twice counters=%zu\n", grp.counters.size());
    }

    // ---- V11: close (cc:171-:181): deletes + nulls the post_init cache
    // (the ONLY owner, R2 pair), the Mime exit witness, FileCapture::exit
    // JOINS the V5 writer thread (donor :645 posture, idempotent after).
    {
        int had = FileService::get_file_cache() ? 1 : 0;
        FileService::close();
        std::printf("V11_close had=%d after=%d\n", had,
            FileService::get_file_cache() ? 1 : 0);
    }

    // ---- V12: thread_init/thread_term (cc:183-:187 brace-on-line) -> the
    // REAL file_stats_init/term (snort_calloc/snort_free; one clean cycle).
    {
        FileService::thread_init();
        FileService::thread_term();
        std::printf("V12_cycle done=1\n");
    }

    // ---- V13: REAL snort::get_file_processed_size arms (cc:254-:270; the
    // retired stubs.cc:711 verbatim copy is GONE -- the row .o owns it):
    // (a) no FileFlows on the slot -> 0; (b) fresh FileFlows, no current
    // context -> 0 (cc:262-:264); (c) REAL context through the cache seam
    // + REAL update_file_size(7, MIDDLE) -> 7. Drain VERBATIM fflows.
    {
        static FileCache v13_cache(16);        // the get_file_context seam
        fcache_clear_flow_slot();
        uint64_t a = get_file_processed_size(&g_flow);           // (a)
        fcache_set_file_service(1);            // get_file_flows creates
        fcache_set_file_cache(&v13_cache);
        FileFlows* ff = FileFlows::get_file_flows(&g_flow, true);
        uint64_t b = get_file_processed_size(&g_flow);           // (b)
        bool isnew = false;
        FileContext* x = ff->get_file_context(900, true, isnew);
        ff->set_current_file_context(x);
        x->update_file_size(7, SNORT_FILE_MIDDLE);               // REAL body
        uint64_t c = get_file_processed_size(&g_flow);           // (c) 7
        std::printf("V13_size noff=%d noctx=%d sized=%llu\n",
            (int)(a == 0), (int)(b == 0), (unsigned long long)c);
        ff->set_current_file_context(nullptr); // frees via the retire path
        delete ff;                             // ~FileFlows drains ppc
        fcache_clear_flow_slot();
        fcache_set_file_cache(nullptr);
        fcache_set_file_service(0);
    }

    // ---- V14: the REAL init() (cc:61-:64): FileFlows::init() INLINED into
    // file_service.o -> the resident create_flow_data_id witness (stubs
    // :753 KEEP): the ladder lands 1, file_flow_data_id == flow_data_id.
    {
        FileService::init();
        std::printf("V14_init ffd=%u\n", FileFlows::file_flow_data_id);
    }

    std::printf("FSVC_PROBE_DONE\n");
    return 0;
}
