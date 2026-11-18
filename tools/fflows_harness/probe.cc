// probe.cc — ground-truth transcript for the REAL file_api/file_flows.cc TU
// (row 17q). Everything deterministic: interposed fake clock (stubs.cc) +
// fixed inputs + FIXED CALL ORDER (max_file_id THREAD_LOCAL inside the real
// TU is a global counter — deterministic only because this transcript walks
// it in a pinned sequence). Printf hygiene: mutating calls hoisted into
// locals before any printf (fid/codec lesson).
//
// FileFlows is REAL here (donor witness block RETIRED). file_cache.cc /
// file_lib.cc stay REAL from the donor (retire rule). Witnesses remain only
// at the seams: network policy (get_network_policy + NetworkPolicy::
// get_base_file_policy -> heap StubFilePolicy through the REAL ref-count
// protocol), get_file_processed_size (body copied literally from
// file_service.cc:256-268), Flow::get/set_flow_data single slot (the ONE
// flow_fwd.h graft delta), PacketTracer restart_timer/get_time/
// is_daq_activated (armable), get_instance_id (armable; pins the
// (id<<32)|max_file_id++ ladder at file_flows.cc:205-209).
//
// The probe NEVER crosses a context->process(...) call site
// (file_flows.cc:473/:486/:531 — the 17q/17r cut from PLAN.md): every
// file_process/handle_retransmit section stops at an early-return or
// cached-verdict arm. Light FileContext members (update_file_size,
// check_policy, set_file_name/log_file_event through the REAL EventSink
// path, find_main_file_context lifecycle) are reached via REAL FileFlows
// bodies.
//
// Stack-vs-heap note: every FileFlows whose dtor output must land at a
// pinned point in the transcript is heap-allocated and deleted explicitly;
// ~FileFlows -> retire_victim -> REAL ~FileContext (IMGR release lines).
#include "file_api/file_lib.h"
#include "file_api/file_api.h"
#include "file_api/file_cache.h"
#include "file_api/file_config.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "file_api/file_stats.h"
#include "flowz/flow_fwd.h"
#include "flow/flow_key.h"
#include "detection/detection_engine.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "trace/trace.h"

// defined in stubs.cc (witness bodies TU)
snort::FilePolicyBase* stub_file_policy();
FileConfig* get_harness_file_config();

#include <cstdio>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace snort;

// stubs.cc setters / helpers (extern "C")
extern "C" void fcache_set_fake_now(double t);
extern "C" void fcache_enable_fake_clock(int on);
extern "C" void fcache_set_file_trace(int on, int level);
extern "C" void fcache_set_file_inspector(int on);
extern "C" void fcache_set_adv_pub_id(unsigned id);
extern "C" void fcache_set_policy_verdicts(int type_v, int sig_v);
extern "C" void fcache_release_stub_policy();
extern "C" void fcache_set_next_packet(Packet* p);
extern "C" void fcache_set_file_cache(FileCache* c);
extern "C" void fcache_set_pt_active(int on);
// NEW17q arms (stubs.cc)
extern "C" void fcache_set_pt_daq(int on);
extern "C" void fcache_set_instance_id(unsigned n);
extern "C" void fcache_set_max_file_depth(long long d);
extern "C" void fcache_set_file_service(int on);
extern "C" void fcache_clear_flow_slot(void);
extern "C" unsigned fcache_stub_policy_refs(void);

// zero statics as in the donor probe (FlowKey asid 0 -> make_key bytes ==
// FileHashKey{} bytes except file_id; two_way_traffic off: session_flags 0)
static FlowKey g_fkey;
static Flow g_flow;

static FileHashKey mkkey(uint64_t file_id)
{
    FileHashKey key{};
    key.file_id = file_id;
    return key;
}

static FileContext* cache_add(FileCache& c, const FileHashKey& k, int64_t timeout,
    bool& cache_full, int64_t& cache_expire, bool sync = true)
{
    return c.add(k, timeout, cache_full, cache_expire, sync);
}

int main()
{
    fcache_enable_fake_clock(1);
    file_stats_init();   // THREAD_LOCAL file_stats/file_counts armed (rc 139 rule)
    g_flow.key = &g_fkey;
    fcache_set_fake_now(100.0);
    fcache_set_adv_pub_id(7);
    fcache_set_instance_id(0);

    // ================= A: layout / enum vocabulary =====================
    std::printf("A_SZ_FF=%zu SZ_SLOT=%zu OFS_slot_ctx=%zu OFS_slot_id=%zu\n",
        sizeof(FileFlows), sizeof(FileFlows::CurrentContextSlot),
        offsetof(FileFlows::CurrentContextSlot, ctx),
        offsetof(FileFlows::CurrentContextSlot, id));
    std::printf("A_ENUM pos_unk=%d pos_start=%d pos_mid=%d pos_end=%d pos_full=%d "
        "sid_none=%d sid_overlimit=%d sid_max=%d gid=%u\n",
        (int)SNORT_FILE_POSITION_UNKNOWN, (int)SNORT_FILE_START, (int)SNORT_FILE_MIDDLE,
        (int)SNORT_FILE_END, (int)SNORT_FILE_FULL,
        (int)EVENT__NONE, (int)EVENT_FILE_DROPPED_OVER_LIMIT, (int)EVENT__MAX_VALUE,
        (unsigned)FILE_ID_GID);
    FileFlows::init();
    std::printf("A_FFDATA_ID=%u (post-init)\n", FileFlows::file_flow_data_id);

    // ================= B: get_file_flows factory ladder =================
    // (single-slot FlowData graft + network-policy witness + REAL ref-count)
    {
        fcache_clear_flow_slot();
        fcache_set_file_service(0);
        FileFlows* none = FileFlows::get_file_flows(&g_flow, true);
        FilePolicyBase* pol0 = FileFlows::get_file_policy(&g_flow);
        std::printf("B_DISABLED ff=%d pol=%d\n", none ? 1 : 0, pol0 ? 1 : 0);

        fcache_set_file_service(1);
        unsigned refs_before = fcache_stub_policy_refs();
        FileFlows* ff = FileFlows::get_file_flows(&g_flow, true);
        unsigned refs_after = fcache_stub_policy_refs();
        FilePolicyBase* pol = ff ? ff->get_file_policy() : nullptr;
        size_t szof = ff ? ff->size_of() : 0;
        FileFlows* again = FileFlows::get_file_flows(&g_flow, true);
        FileFlows* no_create = FileFlows::get_file_flows(&g_flow, false);
        FilePolicyBase* static_pol = FileFlows::get_file_policy(&g_flow);
        std::printf("B_CREATE ff=%d pol_is_stub=%d refs=%u->%u size_of=%zu "
            "same_ptr=%d same_nocreate=%d static_pol=%d\n",
            ff ? 1 : 0, (pol == stub_file_policy()) ? 1 : 0, refs_before, refs_after,
            szof, (ff == again) ? 1 : 0, (ff == no_create) ? 1 : 0,
            (static_pol == pol) ? 1 : 0);

        // ============ C: retire/defer aliasing matrix beyond the gate ====
        fcache_set_file_inspector(1);   // config reachable: FileContext ctor +
                                        // log_file_event config->trace_type arm
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);

        // C1: get_file_context create -> ppc store; ppc-hit lookup
        bool isnew = false;
        FileContext* x = ff->get_file_context(201, true, isnew);
        FileContext* hit = ff->get_partially_processed_context(201);
        size_t ppc1 = ff->partially_processed_contexts.size();
        std::printf("C1_CREATE have=%d is_new=%d ppc=%zu ppc_hit_same=%d fcid=%llu\n",
            x ? 1 : 0, (int)isnew, ppc1, (hit == x) ? 1 : 0,
            x ? (unsigned long long)x->get_file_id() : 0ull);

        // C2: set_current, remove erase->park, caller alias survives,
        // self-install SKIP arm, then other-install drains via retire_victim
        ff->set_current_file_context(x);
        ff->remove_processed_file_context(201);
        FileContext* cur_alias = ff->get_current_file_context();
        size_t ppc2 = ff->partially_processed_contexts.size();
        std::printf("C2_PARK deferred_is_x=%d ppc=%zu current_alias_survives=%d\n",
            (ff->deferred_delete_context == x) ? 1 : 0, ppc2,
            (cur_alias == x) ? 1 : 0);
        ff->set_current_file_context(x);   // deferred == ctx -> SKIP retire
        std::printf("C2_SELFSET deferred_kept=%d current_is_x=%d\n",
            (ff->deferred_delete_context == x) ? 1 : 0,
            (ff->current_context == x) ? 1 : 0);
        FileContext* y = ff->get_file_context(202, true, isnew);
        ff->set_current_file_context(y);   // deferred != ctx -> retire_victim(x)
        std::printf("C2_DRAIN deferred_nonnull=%d current_is_y=%d\n",
            ff->deferred_delete_context ? 1 : 0,
            (ff->current_context == y) ? 1 : 0);

        // C3: dup_cache_context path (ppc-miss + cache-hit) -> private copy,
        // set_cache_dup + set_limit_excluded + cache_dup_count++, then
        // remove_processed_file_context decrements (file_flows.cc:371-372).
        bool cf = false; int64_t ce = 0;
        FileContext* entry = cache_add(cache, mkkey(300), 3600, cf, ce);
        entry->verdict = FILE_VERDICT_BLOCK;
        FileContext* dctx = ff->get_file_context(300, false, isnew);
        size_t cdc1 = ff->cache_dup_count;
        int dupf = dctx ? (int)dctx->is_cache_dup() : -1;
        int limf = dctx ? (int)dctx->is_limit_excluded() : -1;
        std::printf("C3_DUP have=%d not_entry=%d is_new=%d cache_dup=%d limit_excl=%d cdc=%zu\n",
            dctx ? 1 : 0, (dctx != entry) ? 1 : 0, (int)isnew, dupf, limf, cdc1);
        ff->remove_processed_file_context(300);
        size_t cdc2 = ff->cache_dup_count;
        std::printf("C3_UNDEC cdc=%zu deferred_is_dctx=%d\n",
            cdc2, (ff->deferred_delete_context == dctx) ? 1 : 0);
        ff->set_current_file_context(y);   // y != dctx -> retire_victim(dctx)
        std::printf("C3_DRAINED deferred_nonnull=%d\n", ff->deferred_delete_context ? 1 : 0);

        // C4: find_main_file_context ladder (check_policy -> REAL
        // file_counts.files_total++ + StubFilePolicy::policy_check witness;
        // index 0 -> get_new_file_instance + set_not_cacheable;
        // MIDDLE returns existing main; START replaces (old deleted);
        // FULL NOT in the (MIDDLE|END) keep-list -> also replaces).
        unsigned ft0 = (unsigned)file_counts.files_total;
        FileContext* m1 = ff->find_main_file_context(SNORT_FILE_START, FILE_DOWNLOAD, 0);
        // HOIST BEFORE the ladder: a second START retires (deletes) the old
        // main -- reading m1 after m3 is use-after-free.
        size_t m1id = m1 ? (size_t)m1->get_file_id() : 0;
        int m1cache = (int)m1->is_cacheable();
        FileContext* m2 = ff->find_main_file_context(SNORT_FILE_MIDDLE, FILE_DOWNLOAD, 0);
        FileContext* m3 = ff->find_main_file_context(SNORT_FILE_START, FILE_DOWNLOAD, 0);
        FileContext* m4 = ff->find_main_file_context(SNORT_FILE_FULL, FILE_UPLOAD, 5);
        size_t m4id = m4 ? (size_t)m4->get_file_id() : 0;
        int m4cache = (int)m4->is_cacheable();
        unsigned ft3 = (unsigned)file_counts.files_total;
        std::printf("C4_MAIN m2_same_m1=%d m3_new=%d m1id=%zu m1_cacheable=%d "
            "m4id=%zu m4_cacheable=%d files_total+=%u main_is_m4=%d\n",
            (m2 == m1) ? 1 : 0, (m3 != m2) ? 1 : 0, m1id, m1cache, m4id, m4cache,
            ft3 - ft0, (ff->main_context == m4) ? 1 : 0);

        fcache_set_file_trace(0, 0);
        fcache_set_file_cache(nullptr);
        unsigned refs_pre_delete = fcache_stub_policy_refs();
        delete ff;   // REAL ~FileFlows: nulls aliases, drains deferred/main/ppc
                     // via retire_victim, then delete_file_policy: refs 2 -> 1
        unsigned refs_post_delete = fcache_stub_policy_refs();
        std::printf("C5_DTOR policy_refs=%u->%u\n", refs_pre_delete, refs_post_delete);
        fcache_clear_flow_slot();
        cache.clear();
    }

    // ================= D: get_new_file_instance bit ladder ===============
    {
        fcache_set_instance_id(5);
        FileFlows* ff3 = new FileFlows(nullptr);
        uint64_t u1 = ff3->get_new_file_instance();
        uint64_t u2 = ff3->get_new_file_instance();
        fcache_set_instance_id(0);
        uint64_t u3 = ff3->get_new_file_instance();
        std::printf("D_INSTANCE id5: %llx %llx (lo=%u,%u) id0: %llx\n",
            (unsigned long long)u1, (unsigned long long)u2,
            (unsigned)(u1 & 0xffffffff), (unsigned)(u2 & 0xffffffff),
            (unsigned long long)u3);
        delete ff3;
    }

    // ================= E: get_current_file_context id ladder =============
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        FileFlows* ff4 = new FileFlows(&g_flow);
        bool isnew = false;
        FileContext* x = ff4->get_file_context(500, true, isnew);
        ff4->set_current_file_context(x);
        ff4->current_file_id = 501;             // ppc-miss + cache-miss -> null
        FileContext* g0 = ff4->get_current_file_context();
        ff4->current_file_id = 500;             // routes via get_file_context ppc-hit
        FileContext* g1 = ff4->get_current_file_context();
        ff4->current_file_id = 0;               // alias arm
        FileContext* g2 = ff4->get_current_file_context();
        std::printf("E_IDLADDER miss=%d hit_same=%d alias_same=%d\n",
            g0 ? 1 : 0, (g1 == x) ? 1 : 0, (g2 == x) ? 1 : 0);
        delete ff4;   // ~FileFlows drains ppc 500 -> REAL ~FileContext (IMGR release)
        fcache_set_file_cache(nullptr);
        cache.clear();
    }

    // ================= F: get_file_position ladder =======================
    // (real Packet flags + REAL get_file_processed_size witness chain:
    // single-slot Flow graft + light update_file_size -> processed>0 -> MIDDLE)
    {
        fcache_clear_flow_slot();
        fcache_set_file_service(1);
        FileFlows* ff5 = FileFlows::get_file_flows(&g_flow, true);
        Packet p;
        p.flow = &g_flow;
        Active act;
        p.active = &act;
        IpsContext ictx;
        ictx.conf = SnortConfig::get_conf();
        p.context = &ictx;
        fcache_set_next_packet(&p);
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        bool isnew = false;
        FileContext* x = ff5->get_file_context(600, true, isnew);
        ff5->set_current_file_context(x);
        x->update_file_size(10, SNORT_FILE_MIDDLE);   // light member, REAL body
        FilePosition f1 = get_file_position(&p);      // flags 0 -> processed -> MIDDLE
        p.packet_flags = PKT_PDU_FULL;
        FilePosition f2 = get_file_position(&p);
        p.packet_flags = PKT_PDU_HEAD;
        FilePosition f3 = get_file_position(&p);
        p.packet_flags = PKT_PDU_TAIL;
        FilePosition f4 = get_file_position(&p);
        std::printf("F_POSITION mid=%d full=%d start=%d end=%d\n",
            (int)f1, (int)f2, (int)f3, (int)f4);
        p.packet_flags = 0;
        fcache_set_file_cache(nullptr);
        fcache_set_next_packet(nullptr);
        delete ff5;
        fcache_clear_flow_slot();
        cache.clear();
    }

    // ================= G: over-limit event arm ===========================
    // (shrunk cap: new_context_count == fc->max_files_per_flow ->
    // file_counts.files_over_flow_limit_not_processed++ +
    // events.create_event(EVENT_FILE_DROPPED_OVER_LIMIT) ->
    // DE queue_event gid=150 sid=1 EXACTLY ONCE; the EventGen bitset
    // (helpers/event_gen.h:48) suppresses the second fire -> once-only pin.)
    {
        fcache_set_file_inspector(1);
        FileConfig* fc = get_harness_file_config();
        uint64_t cap_saved = fc->max_files_per_flow;
        fc->max_files_per_flow = 2;
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        FileFlows* ff6 = new FileFlows(&g_flow);
        file_counts.files_over_flow_limit_not_processed = 0;
        file_counts.max_concurrent_files_per_flow = 0;
        bool isnew = false;
        FileContext* a = ff6->get_file_context(700, true, isnew);
        FileContext* b = ff6->get_file_context(701, true, isnew);
        FileContext* c = ff6->get_file_context(702, true, isnew);   // count==max -> ARM
        FileContext* d = ff6->get_file_context(703, true, isnew);   // still ==max -> suppressed arm
        size_t ppc = ff6->partially_processed_contexts.size();
        std::printf("G_OVERLIMIT a=%d b=%d c=%d d=%d ppc=%zu over_cnt=%llu maxconc=%llu\n",
            a ? 1 : 0, b ? 1 : 0, c ? 1 : 0, d ? 1 : 0, ppc,
            (unsigned long long)file_counts.files_over_flow_limit_not_processed,
            (unsigned long long)file_counts.max_concurrent_files_per_flow);
        fc->max_files_per_flow = cap_saved;
        fcache_set_file_cache(nullptr);
        delete ff6;    // drains the 2 created contexts (REAL ~FileContext)
        cache.clear();
    }

    // ================= H: set_file_name arms =============================
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        FileFlows* ff7 = new FileFlows(&g_flow);
        bool isnew = false;
        FileContext* ctxA = ff7->get_file_context(801, true, isnew);
        ff7->set_current_file_context(ctxA);
        fcache_set_max_file_depth(0);
        // arm 1: url set (url unset) + name set (name unset -> set +
        // log_file_event: silent UNKNOWN) + processed(0)==depth(0) ->
        // processing_complete=true, remove_processed_file_context(0) MISS
        // (key 801 stays in ppc — pinned real aliasing of the mpid default),
        // return false.
        bool r1 = ff7->set_file_name((const uint8_t*)"n", 1, 0, 0,
            (const uint8_t*)"http://x/y", 10);
        size_t ppcA = ff7->partially_processed_contexts.size();
        std::printf("H_SETNAME1 ret=%d ppc=%zu complete=%d url=%d name=%d\n",
            (int)r1, ppcA, (int)ctxA->processing_complete,
            (int)ctxA->is_url_set(), (int)ctxA->is_file_name_set());
        // arm 2: file_id set -> id lookup (ppc hit 802); processed(5)!=depth(10)
        // and type CONTINUE -> return true (no completion, no removal).
        fcache_set_max_file_depth(10);
        FileContext* ctxB = ff7->get_file_context(802, true, isnew);
        ff7->set_current_file_context(ctxB);
        ctxB->update_file_size(5, SNORT_FILE_MIDDLE);
        bool r2 = ff7->set_file_name((const uint8_t*)"b.bin", 5, 802, 0,
            (const uint8_t*)"http://x/z", 10);
        size_t ppcB = ff7->partially_processed_contexts.size();
        std::printf("H_SETNAME2 ret=%d ppc=%zu complete=%d\n",
            (int)r2, ppcB, (int)ctxB->processing_complete);
        delete ff7;
        fcache_set_file_cache(nullptr);
        cache.clear();
    }

    // ================= I: log_file_event through the REAL FileContext =====
    // (light half FileCacheEventSink path: PUBBYTES "LOG" verdict publish +
    // PUB pub=7 FileEvent + config->trace_type false print bypass; the
    // full advance-log FILEDBG + populate_trace_data daq_log format ladder
    // pin rides J_CACHEHIT where the cached-verdict path re-enters
    // log_file_event and then populate_trace_data with daq armed)
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);   // armed: get_file_context :294 assert
        // flow-armed: the ppc-miss arm of get_file_context routes through
        // the REAL file_cache->get_file(FFLOW,...) -> make_key(flow) (a
        // null FileFlows::flow segfaults there -- pinned harness rule)
        FileFlows* ff8 = new FileFlows(&g_flow);
        bool isnew = false;
        FileContext* ctx = ff8->get_file_context(850, true, isnew);
        ctx->set_file_id(850);
        ctx->set_file_name("pub.bin", 7);
        ctx->verdict = FILE_VERDICT_LOG;
        // one-way traffic (session_flags 0 keeps !two_way_traffic TRUE gate open)
        ff8->set_current_file_context(ctx);
        ctx->log_file_event(&g_flow, stub_file_policy());
        std::printf("I_LOGEVENT verdict=%d name=%s\n", (int)ctx->verdict,
            ctx->get_file_name().c_str());
        ff8->set_current_file_context(nullptr);  // null alias before dtor
        delete ff8;                              // dtor drains ppc 850
    }

    // ================= J: file_process / handle_retransmit arms ===========
    // (EVERY path stops at an early-return or cached-verdict arm; the
    // context->process ladder (17r) is never crossed.)
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        Packet p;
        p.flow = &g_flow;
        Active act;
        p.active = &act;
        IpsContext ictx;
        ictx.conf = SnortConfig::get_conf();
        p.context = &ictx;
        fcache_set_next_packet(&p);
        fcache_set_pt_daq(1);           // armed daq flag (restart_timer + trace-data)
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);

        // single file_process: service-disabled early return (:505)
        fcache_set_file_service(0);
        {
            FileFlows* t = new FileFlows(nullptr);
            bool j0 = t->file_process(&p, (const uint8_t*)"", 0,
                SNORT_FILE_FULL, true, 0, nullptr, 0);
            std::printf("J_SVC_OFF ret=%d\n", (int)j0);
            delete t;
        }
        // single file_process: position-unknown early return (:512)
        fcache_set_file_service(1);
        {
            FileFlows* t = new FileFlows(&g_flow);
            bool j1 = t->file_process(&p, (const uint8_t*)"", 0,
                SNORT_FILE_POSITION_UNKNOWN, true, 0, nullptr, 0);
            std::printf("J_POS_UNK ret=%d\n", (int)j1);
            delete t;
        }
        // multi file_process: file_depth < 0 early return (:401)
        fcache_set_max_file_depth(-5);
        {
            FileFlows* t = new FileFlows(&g_flow);
            bool j2 = t->file_process(&p, 901, (const uint8_t*)"abcd", 4, 0,
                FILE_DOWNLOAD);
            std::printf("J_DEPTH_NEG ret=%d ppc=%zu\n", (int)j2,
                t->partially_processed_contexts.size());
            delete t;
        }
        // multi file_process: offset(11) > depth(10) early return (:401)
        fcache_set_max_file_depth(10);
        {
            FileFlows* t = new FileFlows(&g_flow);
            bool j3 = t->file_process(&p, 902, (const uint8_t*)"abcd", 4, 11,
                FILE_DOWNLOAD);
            std::printf("J_OFFSET_PAST ret=%d ppc=%zu\n", (int)j3,
                t->partially_processed_contexts.size());
            delete t;
        }
        // multi file_process cache-hit arm (:446-461): get_file_context
        // finds id 903 in the CACHE (not ppc) -> dup_cache_context private
        // copy (is_new=false, cache_dup, cdc++). At :446 (cacheable and not
        // is_new) -> REAL cached_verdict_lookup (entry UNKNOWN + policy
        // type LOG -> LOG, donor G2 shape) -> file_cache_hits++,
        // processing_complete=true, remove_processed_file_context (erase->
        // park + cdc--), daq-armed populate_trace_data (REAL static:
        // print_file_name empty fast path + VerdictName + file_type_name
        // CONTINUE + daq_log witness format ladder), return false. NEVER
        // crosses the :486 process ladder (is_new=false routes away).
        fcache_set_max_file_depth(0);
        bool cf = false; int64_t ce = 0;
        FileContext* entry = cache_add(cache, mkkey(903), 3600, cf, ce);
        entry->set_file_id(903);
        entry->set_config(get_harness_file_config());
        fcache_set_policy_verdicts(FILE_VERDICT_LOG, FILE_VERDICT_UNKNOWN);
        {
            // factory-built: file_policy armed (check_policy :442 through
            // the REAL body does policy->policy_check unguarded -- a null
            // policy there is a pinned segfault, never exercised)
            FileFlows* t = FileFlows::get_file_flows(&g_flow, true);
            file_counts.file_cache_hits = 0;          // count the HIT arm only
            bool j4 = t->file_process(&p, 903, (const uint8_t*)"abcd", 4, 0,
                FILE_DOWNLOAD);                       // cache dup -> LOG -> early false
            std::printf("J_CACHEHIT ret=%d hits=%llu ppc=%zu cdc=%zu deferred=%d\n",
                (int)j4,
                (unsigned long long)file_counts.file_cache_hits,
                t->partially_processed_contexts.size(),
                t->cache_dup_count,
                (t->deferred_delete_context != nullptr) ? 1 : 0);
            delete t;   // dtor drains the parked (deferred) 903 context + policy 2->1
        }
        fcache_clear_flow_slot();
        fcache_set_file_trace(0, 0);

        // handle_retransmit ladder:
        // arm 0: file_policy == nullptr -> plain return (bare FileFlows)
        {
            FileFlows* bare = new FileFlows(&g_flow);
            bare->add_pending_file(7);
            bare->handle_retransmit(&p);
            std::printf("J_RETRANS_NOPOL pol=%d pend_res=%d\n",
                bare->get_file_policy() ? 1 : 0, (int)bare->pending_resolution);
            delete bare;
        }
        // factory-built (policy armed through the network-policy witness)
        fcache_clear_flow_slot();
        FileFlows* ff9 = FileFlows::get_file_flows(&g_flow, true);
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
        // arm 1: lookup null (pending id absent from ppc AND cache) -> return
        ff9->add_pending_file(999);
        ff9->handle_retransmit(&p);
        std::printf("J_RETRANS_NOFILE cur=%d def=%d pend_res=%d\n",
            ff9->current_context ? 1 : 0, ff9->deferred_delete_context ? 1 : 0,
            (int)ff9->pending_resolution);
        // arm 2: cache present -> REAL resume_pending_verdict: node MISS ->
        // verdict UNKNOWN; the real body writes dup->verdict=UNKNOWN, so the
        // PENDING stays observable only via the untouched pending_resolution.
        bool isnew = false;
        FileContext* x = ff9->get_file_context(900, true, isnew);
        x->set_file_id(900);
        x->verdict = FILE_VERDICT_PENDING;
        ff9->add_pending_file(900);
        ff9->handle_retransmit(&p);
        std::printf("J_RETRANS_CACHE cur_is_x=%d pend_res=%d verdict=%d\n",
            (ff9->current_context == x) ? 1 : 0, (int)ff9->pending_resolution,
            (int)x->verdict);
        // arm 3: NO cache -> policy->signature_lookup witness +
        // file->log_file_event (REAL light body, silent: UNKNOWN verdict,
        // one-way traffic gate, no print — config->trace_type false); the
        // real body DISCARDS the lookup verdict in this arm -> file->verdict
        // stays UNKNOWN -> pending_resolution STAYS true (pin).
        fcache_set_file_cache(nullptr);
        fcache_set_policy_verdicts((int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_LOG);
        ff9->handle_retransmit(&p);
        std::printf("J_RETRANS_NOCACHE pend_res=%d verdict=%d\n",
            (int)ff9->pending_resolution, (int)x->verdict);
        fcache_set_file_trace(0, 0);
        fcache_set_pt_daq(0);
        delete ff9;   // drains ppc 900 (REAL ~FileContext) + policy ref 2->1
        fcache_clear_flow_slot();
        fcache_set_next_packet(nullptr);
        cache.clear();
    }

    fcache_release_stub_policy();      // final base ref -> real delete (ref 1->0)
    std::fflush(stdout);
    return 0;
}
