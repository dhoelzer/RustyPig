// probe.cc — ground-truth transcript for the HEAVY FileContext half,
// file_lib.cc:825–1362 (row 17r). The file_lib.cc TU is REAL, compiled
// with the :1363 [file_info] UNIT_TEST block excised (build.sh FIXLIBUT):
// the process ladders the fflows probe (row 17q) cut BEFORE are now driven
// directly. FileFlows / FileCache / FileSegment / FileMemPool / FileCapture
// / utf / hashes are all REAL TUs in this link (donor closure).
//
// Seams (stubs.cc witnesses): network policy + StubFilePolicy settable
// tv/sv, PacketTracer armable, DetectionEngine set_next_packet /
// get_current_packet (GET_CURRENT_PACKET sites), fp_eval_service_group
// NEW17r armable (optional type-set side effect + re-entrant current
// context swap — pins the L-block restore both ways), FileInspect witness
// (arms the harness FileConfig). FileService statics REAL-shape witness.
//
// Determinism: interposed fake clock, fixed inputs, fixed call order, NO
// pointer values in vectors (identity compared to booleans). Printf
// hygiene: every side-effecting call is hoisted into a local BEFORE any
// printf in the same statement group.
//
// Pinned harness rules (deviation-adjacent, recorded in the plan row):
//  * FileService::get_file_cache() returns the probe-armed cache; where C
//    dereferences it unguarded (file_lib.cc:853) the probe arms it.
//  * FileCapture::init() spawns the async writer thread -> NEVER called;
//    the probe arms FileCapture::init_mempool + capture_block_size through
//    the FIXACC'd public access so process_buffer reaches the REAL
//    mempool code (FileCapture::exit() never called; deviation).
//  * FileContext ctor config comes from the FileInspect witness -> the
//    harness global FileConfig (same as donor: config NEVER null while an
//    inspector is armed).
#include "file_api/file_lib.h"
#include "file_api/file_api.h"
#include "file_api/file_cache.h"
#include "file_api/file_capture.h"
#include "file_api/file_config.h"
#include "file_api/file_flows.h"
#include "file_api/file_segment.h"
#include "file_api/file_service.h"
#include "file_api/file_stats.h"
#include "flowz/flow_fwd.h"
#include "flow/flow_key.h"
#include "hash/hashes.h"
#include "detection/detection_engine.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "trace/trace.h"

#include <cctype>
#include <cstdio>
#include <iostream>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace snort;

// defined in stubs.cc (witness bodies TU)
snort::FilePolicyBase* stub_file_policy();
FileConfig* get_harness_file_config();

// donor arms (stubs.cc, names kept — the fflows vectors retire, the arms
// stay) + NEW17r arms
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
extern "C" void fcache_set_pt_daq(int on);
extern "C" void fcache_set_instance_id(unsigned n);
extern "C" void fcache_set_max_file_depth(long long d);
extern "C" void fcache_set_file_service(int on);
extern "C" void fcache_clear_flow_slot(void);
extern "C" unsigned fcache_stub_policy_refs(void);
// NEW17r (stubs.cc)
extern "C" void fctx_set_fp_eval_type(unsigned spid, unsigned ftype); // 0 = plain
extern "C" void fctx_set_fp_eval_swap(int on);                        // re-entrant arm
extern "C" void fctx_set_fp_eval_install(FileContext* c);             // swap target
extern "C" int  fcache_fp_eval_calls(void);
extern "C" void fcache_set_capture_mem(int on);                       // arm mempool
extern "C" void fcache_set_capture_block_size(int64_t bytes);
extern "C" uint64_t fcache_capture_size(FileCapture* fc);

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

// Shared probe packet (flow/active/context wired once; packet_flags reset
// per section like the donor F-block).
static Packet g_p;
static Active g_act;
static IpsContext g_ictx;

// single process-wide cache (the donor per-scope pattern collapsed: every
// get_file_context ppc-miss routes through FileService::get_file_cache()
// with a REAL asserting body, so the arm must stay live for the whole
// transcript; ids/keys are unique per section instead).
static FileCache g_cache(64);

// fresh FileFlows + FileContext pair: factory-built (real network-policy
// witness arms file_policy through the REAL ref-count protocol), context
// id = 1000 + n; installed as current.
static FileFlows* g_ff = nullptr;
static FileContext* fresh_ctx(unsigned n, bool set_id = true)
{
    if (g_ff) { delete g_ff; g_ff = nullptr; }   // dtor drains ppc (REAL ~FileContext)
    fcache_clear_flow_slot();
    g_ff = FileFlows::get_file_flows(&g_flow, true);
    bool isnew = false;
    FileContext* ctx = nullptr;
    if (g_ff)
    {
        ctx = g_ff->get_file_context(1000 + n, true, isnew);
        g_ff->set_current_file_context(ctx);
        if (ctx && set_id) ctx->set_file_id(1000 + n);
        // NOTE: get_file_context keys ppc by the multi-file id 1000+n while
        // set_file_id above pins file_id for the cached-verdict/lookup arms.
    }
    return ctx;
}

static uint8_t g_data[4096];
static void fill_data(int n, int seed)
{
    for (int i = 0; i < n; i++)
        g_data[i] = (uint8_t)((i * 31 + seed) & 0xFF);
}
// printable alphabet for the segment/reassembly ladders: 0x41 'A' + i%26
static void printable_data(int n, int seed)
{
    for (int i = 0; i < n; i++)
        g_data[i] = (uint8_t)(0x41 + ((i + seed) % 26));
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    fcache_enable_fake_clock(1);
    file_stats_init();   // THREAD_LOCAL file_stats/file_counts armed (rc 139 rule)
    g_flow.key = &g_fkey;
    fcache_set_fake_now(100.0);
    fcache_set_adv_pub_id(7);
    fcache_set_instance_id(0);
    fcache_set_file_inspector(1);   // ctor config reachable (harness FileConfig)
    fcache_set_file_service(1);     // NEW17r: get_file_flows(to_create) gate
                                    // (donor armed it per-block; a fresh_ctx
                                    // factory is used from P1 on)
    FileConfig* fc = get_harness_file_config();

    g_p.flow = &g_flow;
    g_p.active = &g_act;
    g_ictx.conf = SnortConfig::get_conf();
    g_p.context = &g_ictx;
    fcache_set_next_packet(&g_p);
    fcache_set_file_cache(&g_cache);

    // ================= A: layout / enum vocabulary =====================
    std::printf("A_SZ ctx=%zu segs=%zu slot=%zu\n", sizeof(FileContext),
        sizeof(FileSegments), sizeof(FileFlows::CurrentContextSlot));
    std::printf("A_ENUM sig=%d,%d,%d,%d cap=%d,%d,%d,%d,%d pos=%d,%d,%d,%d,%d "
        "ftype_unk=%u ftype_cont=%u spid=%d\n",
        (int)FILE_SIG_PROCESSING, (int)FILE_SIG_DEPTH_FAIL, (int)FILE_SIG_FLUSH,
        (int)FILE_SIG_DONE,
        (int)FILE_CAPTURE_SUCCESS, (int)FILE_CAPTURE_MIN, (int)FILE_CAPTURE_MAX,
        (int)FILE_CAPTURE_MEMCAP, (int)FILE_CAPTURE_FAIL,
        (int)SNORT_FILE_POSITION_UNKNOWN, (int)SNORT_FILE_START, (int)SNORT_FILE_MIDDLE,
        (int)SNORT_FILE_END, (int)SNORT_FILE_FULL,
        (unsigned)SNORT_FILE_TYPE_UNKNOWN, (unsigned)SNORT_FILE_TYPE_CONTINUE,
        (int)fc->snort_protocol_id);
    std::printf("A_CFG typed=%lld sigd=%lld showd=%lld capmin=%lld capmax=%lld\n",
        (long long)fc->file_type_depth, (long long)fc->file_signature_depth,
        (long long)fc->show_data_depth, (long long)fc->capture_min_size,
        (long long)fc->capture_max_size);

    // ================= P0: print_file_data hexdump (static) =============
    // (file_lib.cc:1226; len caps + isprint/isspace table edges: the C
    //  expr is isprint(c) and (c==' ' or !isspace(c)) — under the C locale
    //  '\t','\n','\v','\f','\r' are print-adjacent control chars that land
    //  in '.', 0xA0 is notprint. len 7/8/9/17/18 pin the pos==8 double
    //  space, the tail-padding %s arms, and the pos==17 line break.)
    {
        static const uint8_t alpha[20] =
            { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T' };
        for (int len : { 0, 1, 7, 8, 9, 17, 18, 20 })
        {
            std::printf("P0_LEN=%d>>>\n", len);
            FileContext::print_file_data(stdout, alpha, len, 100);
            std::printf("<<<P0\n");
        }
        // max_depth clamp BELOW len (len=20 depth=9 exercises both the
        // clamp, the double pos==8 row and the pos==17 mid-row break at once)
        std::printf("P0_CLAMP>>>\n");
        FileContext::print_file_data(stdout, alpha, 20, 9);
        std::printf("<<<P0\n");
        uint8_t mixed[36];
        for (int i = 0; i < 36; i++) mixed[i] = (uint8_t)i;                 // 0x00..0x23
        std::printf("P0_CTL>>>\n");
        FileContext::print_file_data(stdout, mixed, 36, 100);
        std::printf("<<<P0\n");
        const uint8_t hi[18] = { 0x7F,0x80,0xA0,0xFF,0xB5,0xC0,0xE9,0xF0,0x20,
            0x09,0x0A,0x0B,0x0C,0x0D,0x1C,0x85,0xAA,0x81 };
        std::printf("P0_HI>>>\n");
        FileContext::print_file_data(stdout, hi, 18, 100);
        std::printf("<<<P0\n");
        // char c = 0x80 -> (char)-128; isprint(-128) == 0 pins sign behavior
        static const uint8_t neg[3] = { 0x80, 0xFF, 0x7F };
        std::printf("P0_SIGN>>>\n");
        FileContext::print_file_data(stdout, neg, 3, 100);
        std::printf("<<<P0\n");
    }

    // ================= P1: print_file_sha256 / print (FileContext) =====
    {
        FileContext* ctx = fresh_ctx(1);
        uint8_t sha[SHA256_HASH_SIZE];
        // sha256 is the FileInfo protected member (FIXACC public): the
        // REAL print reads it; armed via snort_alloc like the FLUSH arm.
        memcpy(sha, "0123456789abcdef0123456789ABCDEF", 32);
        ctx->set_file_id(1002);
        ctx->reset_sha();
        ctx->sha256 = (uint8_t*)snort_alloc(SHA256_HASH_SIZE);
        memcpy(ctx->sha256, sha, SHA256_HASH_SIZE);
        std::printf("P1_SHA>>>\n");
        ctx->print_file_sha256(std::cout);
        std::printf("<<<P1\n");
        // print tail: name arms + URI/host/file_type/file size/processed
        ctx->unset_file_name();
        std::printf("P1_PRINT0>>>\n");
        ctx->print(std::cout);
        std::printf("<<<P1\n");
        ctx->set_file_name("plain.txt", 9);
        ctx->set_url("http://e/h", 10);
        ctx->set_host("host.h", 6);
        std::printf("P1_PRINT1>>>\n");
        ctx->print(std::cout);
        std::printf("<<<P1\n");
        // UTF-16LE BOM run: "\xFF\xFE" + 'A','\0','B','\0' -> get_UTF8_fname
        // HAS_ICONV arm converts; the |XX| run arm prints raw nonprint bytes
        ctx->set_file_name("\xFF\xFE" "A\0B\0", 8);
        std::printf("P1_BOM>>>\n");
        ctx->print(std::cout);
        std::printf("<<<P1\n");
        // daq-activated suppresses the "File name: " header and EOL
        fcache_set_pt_daq(1);
        std::printf("P1_DAQ>>>\n");
        ctx->print_file_name(std::cout);
        std::printf("\n<<<P1\n");
        fcache_set_pt_daq(0);
        // nonprint |XX| runs (non-BOM name so get_UTF8_fname passes through)
        char raw[8] = { 'a', (char)0xC3, (char)0xA9, 'z', (char)0x01, (char)0x80, 'q', 0 };
        ctx->set_file_name(raw, 7);
        std::printf("P1_HEX>>>\n");
        ctx->print_file_name(std::cout);
        std::printf("<<<P1\n");
        ctx->reset_sha();   // snort_free + null (real body)
        std::printf("P1_RESETSHA null_after=%d\n", ctx->get_file_sig_sha256() ? 0 : 1);
    }

    // ================= K: process position-form ladder ==================
    {
        // K0: data_size < 0 -> true (Profile + flow read first; C :831)
        {
            FileContext* ctx = fresh_ctx(10);
            fill_data(8, 1);
            bool r0 = ctx->process(&g_p, g_data, -1, SNORT_FILE_FULL, stub_file_policy());
            std::printf("K0_NEG ret=%d processed=%llu\n", (int)r0,
                (unsigned long long)ctx->get_processed_bytes());
        }

        // K1: trace_stream print arm (:834 hexdump INTO stdout between the
        // markers; show_data_depth clamp 2 pins max_depth < data_size)
        {
            FileContext* ctx = fresh_ctx(11);
            fc->trace_stream = true;
            fc->show_data_depth = 2;
            fill_data(6, 7);
            bool r = ctx->process(&g_p, g_data, 6, SNORT_FILE_FULL, nullptr);
            fc->trace_stream = false;
            fc->show_data_depth = 100;
            std::printf("K1_STREAM ret=%d data_total_plus=%llu\n", (int)r,
                (unsigned long long)file_counts.file_data_total);
        }

        // K2: type+sig both disabled (:842): update_file_size +
        // (context feature bits are per-FileInfo config bits; the REAL
        // FilePolicy::policy_check sets them from policy config --
        // file_policy.cc:172-176 -- the probe arms them DIRECTLY on the
        // context: same observable inputs, witness substitution recorded)
        // processing_complete + FILE_DEBUG + return false.
        // PacketTracer armed pins the "File: Type and Sig not enabled" line.
        {
            FileContext* ctx = fresh_ctx(12);
            fcache_set_file_service(0);
            fcache_set_pt_active(1);
            fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
            printable_data(5, 0);
            bool r = ctx->process(&g_p, g_data, 5, SNORT_FILE_FULL, stub_file_policy());
            fcache_set_pt_active(0);
            fcache_set_file_trace(0, 0);
            std::printf("K2_OFF ret=%d complete=%d processed=%llu file_size=%llu\n",
                (int)r, (int)ctx->processing_complete,
                (unsigned long long)ctx->get_processed_bytes(),
                (unsigned long long)ctx->get_file_size());
        }

        // K3: cached verdict HIT (:853 REAL cached_verdict_lookup):
        //   entry verdict BLOCK -> find_and_pin hit -> check_verdict:
        //   policy type_lookup sv=UNKNOWN -> stays BLOCK -> apply_verdict
        //   (resume=true) + file->verdict copied -> file_lib returns true.
        FileContext* entry = nullptr;
        {
            bool cfull = false; int64_t cexp = 0;
            entry = cache_add(g_cache, mkkey(1014), 3600, cfull, cexp);
            entry->set_file_id(1014);
            entry->verdict = FILE_VERDICT_BLOCK;
            fcache_set_file_service(1);
            // type_lookup LOG -> check_verdict LOG (entry sha null skips
            // the signature sub-arm) -> != UNKNOWN -> apply_verdict
            // (resume=true): PUBBYTES "LOG" + log_file_action RESUME_LOG
            fcache_set_policy_verdicts((int)FILE_VERDICT_LOG, (int)FILE_VERDICT_UNKNOWN);
            fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
            FileContext* ctx = fresh_ctx(14);   // cacheable by default
            ctx->config_file_type(true);
            unsigned hits = (unsigned)file_counts.file_cache_hits;
            printable_data(4, 0);
            bool r = ctx->process(&g_p, g_data, 4, SNORT_FILE_FULL, stub_file_policy());
            unsigned hits2 = (unsigned)file_counts.file_cache_hits;
            std::printf("K3_HIT ret=%d hits+=%u verdict=%d complete=%d cdup=%d\n",
                (int)r, hits2 - hits, (int)ctx->verdict, (int)ctx->processing_complete,
                (int)ctx->is_cache_dup());
            fcache_set_file_trace(0, 0);
        }
        // K4: cached verdict MISS (empty file_id-less lookup path):
        //   :862-863 file_cache_misses++, then BOTH features off? No:
        //   service on makes ctx features on. Force features off on ctx so
        //   the block below falls into update_file_size? C shape: after
        //   the cacheable arms, neither is_file_type_enabled nor
        //   is_file_signature_enabled -> only :980 else update_file_size.
        //   Features ride the FileInfo per-context config bits: fresh
        {
            FileContext* ctx = fresh_ctx(15);
            ctx->config_file_type(false);
            ctx->config_file_signature(false);
            fcache_set_file_service(1);   // cache arm reached (cacheable), features local-off
            unsigned misses = (unsigned)file_counts.file_cache_misses;
            printable_data(3, 0);
            bool r = ctx->process(&g_p, g_data, 3, SNORT_FILE_FULL, stub_file_policy());
            unsigned misses2 = (unsigned)file_counts.file_cache_misses;
            std::printf("K4_MISS ret=%d misses+=%u processed=%llu complete=%d\n",
                (int)r, misses2 - misses,
                (unsigned long long)ctx->get_processed_bytes(),
                (int)ctx->processing_complete);
        }

        // K5-K8: type-found ladder via the fp_eval type-set seam
        // (conf spid NONZERO so the witness type-set gate fires)
        fc->snort_protocol_id = 66;
        fcache_set_file_service(1);
        {
            // K5: type set to UNKNOWN(65535) -> :871 "Type unknown" arm:
            // config clears x2, update, complete, stop_file_capture, false
            fctx_set_fp_eval_type((unsigned)fc->snort_protocol_id, SNORT_FILE_TYPE_UNKNOWN);
            fcache_set_file_trace(1, TRACE_INFO_LEVEL);
            FileContext* ctx = fresh_ctx(16);
            ctx->config_file_type(true);
            printable_data(40, 0);
            bool r = ctx->process(&g_p, g_data, 40, SNORT_FILE_FULL, stub_file_policy());
            std::printf("K5_UNK ret=%d t_en=%d s_en=%d complete=%d processed=%llu "
                "fpn=%d\n", (int)r, (int)ctx->is_file_type_enabled(),
                (int)ctx->is_file_signature_enabled(), (int)ctx->processing_complete,
                (unsigned long long)ctx->get_processed_bytes(), fcache_fp_eval_calls());
            fcache_set_file_trace(0, 0);
        }
        {
            // K6: type found (7) + policy STOP (:909 clears sig config;
            // type_lookup verdict != UNKNOWN -> apply_verdict(UNKNOWN? no,
            // STOP -> no switch case in apply_verdict? STOP is not in the
            // apply switch: default not shown -> STOP falls through the
            // switch tail; pinned below). PT armed for the block/reject
            // arms of K7.
            fctx_set_fp_eval_type((unsigned)fc->snort_protocol_id, 7);
            fcache_set_policy_verdicts((int)FILE_VERDICT_STOP, (int)FILE_VERDICT_UNKNOWN);
            fcache_set_file_trace(1, TRACE_INFO_LEVEL);
            FileContext* ctx = fresh_ctx(17);
            ctx->config_file_type(true);
            ctx->config_file_signature(true);
            printable_data(40, 0);
            bool r = ctx->process(&g_p, g_data, 40, SNORT_FILE_FULL, stub_file_policy());
            std::printf("K6_STOP ret=%d sig=%d t=%d ftype=%u verdict=%d "
                "processed=%llu size=%llu complete=%d\n",
                (int)r, (int)ctx->is_file_signature_enabled(), (int)ctx->is_file_type_enabled(),
                ctx->file_type_id,
                (int)ctx->verdict, (unsigned long long)ctx->get_processed_bytes(),
                (unsigned long long)ctx->get_file_size(), (int)ctx->processing_complete);
            fcache_set_file_trace(0, 0);
        }
        {
            // K7: type found + policy BLOCK + PT active (:915 log arms,
            // apply_verdict BLOCK: ACT block + drop reason + PT line)
            fcache_set_policy_verdicts((int)FILE_VERDICT_BLOCK, (int)FILE_VERDICT_UNKNOWN);
            fcache_set_pt_active(1);
            fcache_set_file_trace(1, TRACE_INFO_LEVEL);
            FileContext* ctx = fresh_ctx(18);
            ctx->config_file_type(true);
            ctx->config_file_signature(false);
            printable_data(40, 0);
            bool r = ctx->process(&g_p, g_data, 40, SNORT_FILE_FULL, stub_file_policy());
            std::printf("K7_BLOCK ret=%d verdict=%d ftype=%d complete=%d\n",
                (int)r, (int)ctx->verdict, (int)ctx->file_type_id, (int)ctx->processing_complete);
            fcache_set_file_trace(0, 0);
        }
        {
            // K8: type found + policy UNKNOWN + sig enabled: the real
            // SHA256 ladder :930-977 (see M block). trace_signature armed
            // pins print_file_sha256. sv=UNKNOWN -> finish_signature_lookup
            // (final_lookup true at FULL? file_state.sig_state != FLUSH ->
            // final true) writes file_type_name tail... keep type 7 +
            // type UNKNOWN verdict -> log_file_event silent path.
            // K7b: REJECT verdict: PT says reject, ACT reset arm
            fcache_set_policy_verdicts((int)FILE_VERDICT_REJECT, (int)FILE_VERDICT_UNKNOWN);
            fcache_set_file_trace(1, TRACE_INFO_LEVEL);
            FileContext* ctx18b = fresh_ctx(27);
            ctx18b->config_file_type(true);
            ctx18b->config_file_signature(false);
            fctx_set_fp_eval_type((unsigned)fc->snort_protocol_id, 8);
            printable_data(40, 0);
            bool r7b = ctx18b->process(&g_p, g_data, 40, SNORT_FILE_FULL, stub_file_policy());
            std::printf("K7b_REJECT ret=%d verdict=%d ftype=%d\n", (int)r7b,
                (int)ctx18b->verdict, (int)ctx18b->file_type_id);
            fcache_set_file_trace(0, 0);
            fcache_set_pt_active(0);
            fctx_set_fp_eval_type(0, 0);
            fc->snort_protocol_id = UNKNOWN_PROTOCOL_ID;

            // K8: type UNKNOWN verdict + sig ladder end-to-end
            fc->snort_protocol_id = 66;
            fctx_set_fp_eval_type((unsigned)fc->snort_protocol_id, 7);
            fcache_set_policy_verdicts((int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_UNKNOWN);
            fc->trace_signature = true;
            FileContext* ctx = fresh_ctx(19);
            ctx->config_file_type(true);
            ctx->config_file_signature(true);
            printable_data(40, 0);
            bool r = ctx->process(&g_p, g_data, 40, SNORT_FILE_FULL, stub_file_policy());
            std::printf("K8_SIGKICK ret=%d ftype=%u sha=%d sig_state=%d s_en=%d "
                "processed=%llu size=%llu complete=%d\n",
                (int)r, ctx->file_type_id, ctx->get_file_sig_sha256() ? 1 : 0,
                (int)ctx->file_state.sig_state, (int)ctx->is_file_signature_enabled(),
                (unsigned long long)ctx->get_processed_bytes(),
                (unsigned long long)ctx->get_file_size(), (int)ctx->processing_complete);
            fc->trace_signature = false;
            ctx->reset_sha();
        }
        // K9: process-side DEPTH_FAIL ladder (:930->:935 depth-fail ->
        // :951 finish no-op (sha null) -> :953 arms). sig ON, type OFF,
        // file_signature_depth 5, processed 3, data 10 -> 13 > 5.
        {
            int64_t sd = fc->file_signature_depth;
            fc->file_signature_depth = 5;
            // K9a: sv UNKNOWN -> :966 PT/FILEDBG + force_adv_log sandwich +
            // return false.
            fcache_set_policy_verdicts((int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_UNKNOWN);
            fcache_set_pt_active(1);
            fcache_set_file_trace(1, TRACE_INFO_LEVEL);
            FileContext* ctx = fresh_ctx(25);
            ctx->config_file_type(false);
            ctx->config_file_signature(true);
            ctx->processed_bytes = 3;
            printable_data(10, 0);
            bool r = ctx->process(&g_p, g_data, 10, SNORT_FILE_MIDDLE, stub_file_policy());
            std::printf("K9a_DEPTH ret=%d sig_state=%d verdict=%d\n", (int)r,
                (int)ctx->file_state.sig_state, (int)ctx->verdict);
            // K9b: sv LOG -> :956 != UNKNOWN: apply_verdict(LOG) +
            // log_file_event -> :983 return true.
            fcache_set_policy_verdicts((int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_LOG);
            FileContext* ctx2 = fresh_ctx(26);
            ctx2->config_file_type(false);
            ctx2->config_file_signature(true);
            ctx2->processed_bytes = 3;
            printable_data(10, 0);
            bool r2 = ctx2->process(&g_p, g_data, 10, SNORT_FILE_MIDDLE, stub_file_policy());
            std::printf("K9b_DEPTHLOG ret=%d sig_state=%d verdict=%d s_en=%d\n", (int)r2,
                (int)ctx2->file_state.sig_state, (int)ctx2->verdict,
                (int)ctx2->is_file_signature_enabled());
            fcache_set_pt_active(0);
            fcache_set_file_trace(0, 0);
            fc->file_signature_depth = sd;
        }
        fctx_set_fp_eval_type(0, 0);
        fc->snort_protocol_id = UNKNOWN_PROTOCOL_ID;
        // 1014 entry stays in the global cache.
    }

    // ================= L: find_file_type_from_ips =======================
    {
        fc->snort_protocol_id = 55;

        // L1: depth truncation: processed 30 >= file_type_depth 20 ->
        // negative data_size -> early return (:1012).
        {
            FileConfig* cfg = fc;
            int64_t depth_saved = cfg->file_type_depth;
            cfg->file_type_depth = 20;
            FileContext* ctx = fresh_ctx(20);
            ctx->processed_bytes = 30;
            fctx_set_fp_eval_type(0, 0);
            printable_data(10, 0);
            ctx->find_file_type_from_ips(&g_p, g_data, 10, SNORT_FILE_MIDDLE);
            std::printf("L1_TRUNC processed=%llu ftype=%u\n",
                (unsigned long long)ctx->get_processed_bytes(), ctx->file_type_id);
            cfg->file_type_depth = depth_saved;
        }

        // L2: happy path, NO swap (current == this): FP_EVAL plain witness
        // arm + no finalize at MIDDLE (file_state stays CONTINUE 0).
        {
            FileContext* ctx = fresh_ctx(21);
            printable_data(10, 0);
            ctx->find_file_type_from_ips(&g_p, g_data, 10, SNORT_FILE_MIDDLE);
            std::printf("L2_PLAIN ftype=%u mult=%d proto_bits=%u file_pos=%u fdp=%d ftp=%d fpn=%d\n",
                ctx->file_type_id,
                (g_p.packet_flags & PKT_ALLOW_MULTIPLE_DETECT) ? 1 : 0,
                (unsigned)g_p.proto_bits, (unsigned)g_ictx.file_pos,
                (g_ictx.file_data.data != nullptr) ? 1 : 0,
                (int)g_ictx.file_type_process, fcache_fp_eval_calls());
        }

        // L3: swap + FP_EVAL swap-arm + conditional restore (:1048-1054):
        // current != this -> saved swap; witness installs ctx2; restore
        // condition fails (current != this after) -> stale saved NOT written.
        // then L4: swap + plain witness -> restore happens (current back).
        {
            FileContext* ctx = fresh_ctx(22);
            // park an ALIASED context in the cache so the swap target for
            // the witness exists (find_and_pin -> find_add creates it; the
            // witness swaps current_context to that pinned node -- REAL
            // FileContext identity that outlives the eval).
            // probe-owned LONG-LIVED alt context (deleted at scope end,
            // after g_ff nulled its alias). The fp_eval witness (stubs.cc
            // NEW17r) re-enters set_current_file_context(alt) mid-eval.
            FileContext* alt = new FileContext();
            fcache_set_file_trace(1, TRACE_INFO_LEVEL);
            fctx_set_fp_eval_install(alt);     // re-entrant target
            fctx_set_fp_eval_swap(1);          // arm the mode
            printable_data(10, 0);
            ctx->find_file_type_from_ips(&g_p, g_data, 10, SNORT_FILE_END);
            fcache_set_file_trace(0, 0);
            std::printf("L3_REENT cur_is_alt=%d cur_is_ctx=%d ftype=%u finalize=%d\n",
                (g_ff->get_current_file_context() == alt) ? 1 : 0,
                (g_ff->get_current_file_context() == ctx) ? 1 : 0,
                ctx->file_type_id, ctx->file_type_id == 0 ? 1 : 0);
            fctx_set_fp_eval_swap(0);
            fctx_set_fp_eval_install(nullptr);

            FileContext* ctx2 = fresh_ctx(23);
            printable_data(10, 0);
            ctx2->find_file_type_from_ips(&g_p, g_data, 10, SNORT_FILE_FULL);
            std::printf("L4_RESTORE cur_is_ctx=%d ftype=%u (finalize -> unk)\n",
                (g_ff->get_current_file_context() == ctx2) ? 1 : 0, ctx2->file_type_id);
            // ~FileFlows nulled the alias before owning-slot delete: the
            // probe-owned alt survives every fresh_ctx delete.
            delete alt;

            // L5: current != this (null) -> the real swap_current fires
            // (saved {null,0}); plain witness; the restore guard sees
            // current == this -> restore_current writes the saved back.
            // Pins :1035-1043 + the :1048-1053 TRUE side end to end.
            FileContext* ctx3 = fresh_ctx(24);
            g_ff->set_current_file_context(nullptr);
            printable_data(10, 0);
            ctx3->find_file_type_from_ips(&g_p, g_data, 10, SNORT_FILE_MIDDLE);
            std::printf("L5_SWAPPED cur_null=%d cur_ctx=%d\n",
                (g_ff->get_current_file_context() == nullptr) ? 1 : 0,
                (g_ff->get_current_file_context() == ctx3) ? 1 : 0);
        }
        fc->snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    }

    // ================= M: process_file_signature_sha256 (REAL EVP) =====
    {
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);

        // M0: depth fail: processed + data > file_signature_depth (:1070)
        {
            int64_t sd = fc->file_signature_depth;
            fc->file_signature_depth = 10;
            FileContext* ctx = fresh_ctx(30);
            ctx->set_signature_state(false);   // PROCESSING
            printable_data(20, 0);
            ctx->process_file_signature_sha256(g_data, 20, SNORT_FILE_START);
            std::printf("M0_DEPTH sig_state=%d d_exceeded+%llu\n",
                (int)ctx->file_state.sig_state,
                (unsigned long long)file_counts.file_sig_depth_exceeded);
            fc->file_signature_depth = sd;
        }

        // M1: FULL known answer: "abc" -> BA7816BF... uppercase print
        {
            FileContext* ctx = fresh_ctx(31);
            ctx->set_signature_state(false);
            const uint8_t abc[3] = { 'a','b','c' };
            ctx->process_file_signature_sha256(abc, 3, SNORT_FILE_FULL);
            std::printf("M1_FULL sha=%d state=%d\n", ctx->get_file_sig_sha256() ? 1 : 0,
                (int)ctx->file_state.sig_state);
            std::printf("M1_HASH>>>\n");
            ctx->print_file_sha256(std::cout);
            std::printf("<<<M1\n");
        }

        // M2: FLUSH sandwich (START then MIDDLE, sig_state=FLUSH ->
        // EVP_MD_CTX_copy_ex arm + sha256 pinned at the SPLIT point) then
        // update further without FLUSH, finally END finalize overwrites.
        {
            FileContext* ctx = fresh_ctx(32);
            ctx->set_signature_state(true);    // FLUSH (sha256 null)
            const uint8_t s1[10] = { 'S','T','A','R','T','1','2','3','4','5' };
            ctx->process_file_signature_sha256(s1, 10, SNORT_FILE_START);
            std::printf("M2_FLUSH1 sha=%d state=%d\n", ctx->get_file_sig_sha256() ? 1 : 0,
                (int)ctx->file_state.sig_state);
            std::printf("M2_H1>>>\n"); ctx->print_file_sha256(std::cout); std::printf("<<<M2\n");
            const uint8_t m1[6] = { 'M','I','D','1','2','3' };
            ctx->process_file_signature_sha256(m1, 6, SNORT_FILE_MIDDLE);  // still FLUSH
            std::printf("M2_H2>>>\n"); ctx->print_file_sha256(std::cout); std::printf("<<<M2\n");
            ctx->set_signature_state(false);   // PROCESSING
            const uint8_t m2[6] = { 'M','I','D','4','5','6' };
            ctx->process_file_signature_sha256(m2, 6, SNORT_FILE_MIDDLE);
            std::printf("M2_MID sha_now=%d state=%d\n", ctx->get_file_sig_sha256() ? 1 : 0,
                (int)ctx->file_state.sig_state);
            const uint8_t e1[4] = { 'E','N','D','1' };
            ctx->process_file_signature_sha256(e1, 4, SNORT_FILE_END);     // new[] overwrite + DONE
            std::printf("M2_END state=%d\n", (int)ctx->file_state.sig_state);
            std::printf("M2_H3>>>\n"); ctx->print_file_sha256(std::cout); std::printf("<<<M2\n");
            // full-stream known answer for the SAME stream, one FULL call
            {
                FileContext* ref = fresh_ctx(33);
                ref->set_signature_state(false);
                const char* whole = "START12345MID123456MID456END1";
                ref->process_file_signature_sha256((const uint8_t*)whole,
                    (int)strlen(whole), SNORT_FILE_FULL);
                std::printf("M2_HREF>>>\n"); ref->print_file_sha256(std::cout); std::printf("<<<M2\n");
            }
        }

        // M3: MIDDLE/END with null ctx -> early return (:1112/:1136)
        {
            FileContext* ctx = fresh_ctx(34);
            printable_data(5, 0);
            ctx->process_file_signature_sha256(g_data, 5, SNORT_FILE_MIDDLE);
            ctx->process_file_signature_sha256(g_data, 5, SNORT_FILE_END);
            std::printf("M3_MISSING sha=%d state=%d\n", ctx->get_file_sig_sha256() ? 1 : 0,
                (int)ctx->file_state.sig_state);
        }

        // M4: finish_signature_lookup DIRECT (private, FIXACC public):
        // M4a else-arm (verdict UNKNOWN, final FALSE): the :729-734
        // force_adv_log sandwich + the mixed-allocator FREE site pinned
        // OBSERVATIONALLY as the sha NULLING (Rust models Option::take;
        // the snort_free/new[] mismatch is structurally excluded).
        {
            fcache_set_policy_verdicts((int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_UNKNOWN);
            fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
            FileContext* ctx = fresh_ctx(35);
            printable_data(20, 0);
            ctx->process_file_signature_sha256(g_data, 20, SNORT_FILE_FULL);  // sha set
            ctx->processing_complete = true;
            ctx->finish_signature_lookup(&g_p, false, stub_file_policy());
            std::printf("M4a_FINELSE sha_after=%d verdict=%d sig_en=%d complete=%d\n",
                ctx->get_file_sig_sha256() ? 1 : 0, (int)ctx->verdict,
                (int)ctx->is_file_signature_enabled(), (int)ctx->processing_complete);
            // M4b true-side (sv LOG, final FALSE): apply_verdict(LOG,
            // resume=false) + log_file_event + sig config off + stats arm
            fcache_set_policy_verdicts((int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_LOG);
            fcache_set_file_cache(&g_cache);
            FileContext* ctx2 = fresh_ctx(36);
            printable_data(20, 0);
            ctx2->process_file_signature_sha256(g_data, 20, SNORT_FILE_FULL);
            ctx2->finish_signature_lookup(&g_p, false, stub_file_policy());
            std::printf("M4b_FINTREE verdict=%d sha=%d sig_en_after=%d file_id=%llu\n",
                (int)ctx2->verdict, ctx2->get_file_sig_sha256() ? 1 : 0,
                (int)ctx2->is_file_signature_enabled(),
                (unsigned long long)ctx2->get_file_id());
            fcache_set_file_trace(0, 0);
        }

        // M5: file_signature_lookup 3 arms + process_file_type 2 arms.
        {
            // null sha -> UNKNOWN, no policy call
            FileContext* ctx = fresh_ctx(37);
            FileVerdict v0 = ctx->file_signature_lookup(&g_p);
            // sha set + policy armed (factory flow carries file_policy)
            printable_data(20, 0);
            ctx->process_file_signature_sha256(g_data, 20, SNORT_FILE_FULL);
            fcache_set_policy_verdicts((int)FILE_VERDICT_UNKNOWN, (int)FILE_VERDICT_BLOCK);
            FileVerdict v1 = ctx->file_signature_lookup(&g_p);
            std::printf("M5_SIGLOOK v0=%d v1=%d\n", (int)v0, (int)v1);
            ctx->reset_sha();
            // process_file_type: type != CONTINUE -> no-op no FP_EVAL
            unsigned fpn0 = (unsigned)fcache_fp_eval_calls();
            ctx->set_file_type(9);
            printable_data(10, 0);
            ctx->process_file_type(&g_p, g_data, 10, SNORT_FILE_MIDDLE);
            unsigned fpn1 = (unsigned)fcache_fp_eval_calls();
            // type CONTINUE -> routes into find_file_type_from_ips (witness
            // armed type-set 11 through the real current-context chain)
            fc->snort_protocol_id = 77;
            fctx_set_fp_eval_type((unsigned)fc->snort_protocol_id, 11);
            FileContext* ctx2 = fresh_ctx(38);   // file_type_id CONTINUE default
            printable_data(10, 0);
            ctx2->process_file_type(&g_p, g_data, 10, SNORT_FILE_MIDDLE);
            fc->snort_protocol_id = UNKNOWN_PROTOCOL_ID;
            fctx_set_fp_eval_type(0, 0);
            std::printf("M5_PFT fpn_delta_noref=%u ftype=%u\n", fpn1 - fpn0, ctx2->file_type_id);
        }
        fcache_set_file_trace(0, 0);
    }

    // ================= N: process_file_capture (REAL FileCapture) ======
    {
        fcache_set_capture_block_size(16);
        fcache_set_capture_mem(1);
        int64_t cmax_saved = fc->capture_max_size;
        fc->capture_max_size = 15;   // FileCapture ctor reads config -> MAX arm
        {
            FileContext* ctx = fresh_ctx(40);
            printable_data(10, 0);
            FileCaptureState st = ctx->process_file_capture(g_data, 10, SNORT_FILE_START);
            std::printf("N1_START st=%d cap_en=%d state_cap=%d\n", (int)st,
                (int)ctx->is_file_capture_enabled(), (int)ctx->file_state.capture_state);
            // over MAX arm: capture_max_size 20 -> 10+10 fits? push 12 more -> FAIL/MAX
            printable_data(12, 0);
            FileCaptureState st2 = ctx->process_file_capture(g_data, 12, SNORT_FILE_MIDDLE);
            std::printf("N2_MAX st=%d cap_en_after=%d\n", (int)st2,
                (int)ctx->is_file_capture_enabled());
            // stop-on-nonsuccess: second call after stop -> capture re-created
            FileCaptureState st3 = ctx->process_file_capture(g_data, 4, SNORT_FILE_MIDDLE);
            std::printf("N3_AFTER st=%d cap_en=%d\n", (int)st3,
                (int)ctx->is_file_capture_enabled());
            // FULL -> file_within_packet, no buffering
            FileCaptureState st4 = ctx->process_file_capture(g_data, 4, SNORT_FILE_FULL);
            std::printf("N4_FULL st=%d within+%llu buffered+%llu\n", (int)st4,
                (unsigned long long)file_counts.file_within_packet,
                (unsigned long long)file_counts.files_buffered_total);
        }
        fc->capture_max_size = cmax_saved;
        {
            // memcap: block 700000 -> init_mempool(1 MiB) yields max_files==1;
            // an 800000-byte buffer force-splits -> second alloc fails
            FileContext* ctx = fresh_ctx(41);
            fcache_set_capture_block_size(700000);
            fcache_set_capture_mem(1);
            static uint8_t big[800000];
            for (int i = 0; i < 800000; i++) big[i] = (uint8_t)i;
            FileCaptureState st = ctx->process_file_capture(big, 800000, SNORT_FILE_START);
            std::printf("N5_MEMCAP st=%d memcap_fail+%llu bufs_alloc+%llu\n", (int)st,
                (unsigned long long)file_counts.file_memcap_failures_total,
                (unsigned long long)file_counts.file_buffers_allocated_total);
        }
        // restore defaults for later blocks
        {
            FileCapture::capture_block_size = 0;
            FileService::file_capture_enabled = false;
        }
    }

    // ================= O: offset process -> FileSegments ================
    {
        fc->snort_protocol_id = 0;
        fcache_set_file_trace(1, TRACE_INFO_LEVEL);

        // O1: single FULL blob via the offset form: segments == null ->
        // new FileSegments; offset 0, file_size 0 -> FULL (get_file
        // position :247), process -> K-ladder: features? ctx defaults:
        // type CONTINUE... the fp_eval sets type 7. ret true.
        {
            fctx_set_fp_eval_type(0, 7);
            FileContext* ctx = fresh_ctx(50);
            printable_data(8, 0);
            bool r = ctx->process(&g_p, g_data, 8, (uint64_t)0, stub_file_policy(), SNORT_FILE_FULL);
            std::printf("O1_FULL ret=%d queued=%d processed=%llu size=%llu ftype=%u\n",
                (int)r, (int)ctx->segments_queued(),
                (unsigned long long)ctx->get_processed_bytes(),
                (unsigned long long)ctx->get_file_size(), ctx->file_type_id);
            fctx_set_fp_eval_type(0, 0);
        }

        // O2: drop + partial-trim arms (flushes must RETURN TRUE so
        // current_offset advances: features ON + fp_eval type-set 7).
        fctx_set_fp_eval_type((unsigned)66, 7);
        fc->snort_protocol_id = 66;
        {
            FileContext* ctx = fresh_ctx(51);
            ctx->config_file_type(true);
            ctx->set_file_size(100);
            printable_data(10, 0);
            bool a = ctx->process(&g_p, g_data, 10, (uint64_t)0, stub_file_policy(), (FilePosition)0);
            // consumed 10 -> current_offset 10; a stale 0..5 range DROPS
            printable_data(5, 1);
            bool b = ctx->process(&g_p, g_data, 5, (uint64_t)0, stub_file_policy(), (FilePosition)0);
            // partial overlap 5..15 -> trimmed to 10..15 (5 bytes)
            printable_data(10, 5);
            bool c = ctx->process(&g_p, g_data, 10, (uint64_t)5, stub_file_policy(), (FilePosition)0);
            std::printf("O2_DROP a=%d b=%d c=%d queued=%d processed=%llu\n",
                (int)a, (int)b, (int)c, (int)ctx->segments_queued(),
                (unsigned long long)ctx->get_processed_bytes());
        }

        // O3: full TRUE-side drain: each direct feed re-arms the type
        // feature (the :885 found-type pass self-disables it at :892 -> an
        // un-armed next segment takes the :842 false exit and clear()s --
        // that quirk is itself pinned at O3c).
        {
            FileContext* ctx = fresh_ctx(52);
            ctx->set_file_size(30);
            ctx->config_file_type(true);                       // a
            printable_data(6, 0);
            bool a = ctx->process(&g_p, g_data, 6, (uint64_t)0, stub_file_policy(), (FilePosition)0);
            printable_data(6, 12);                             // b: queued (6<12<30)
            bool b = ctx->process(&g_p, g_data, 6, (uint64_t)12, stub_file_policy(), (FilePosition)0);
            std::printf("O3a a=%d b=%d queued=%d processed=%llu\n", (int)a, (int)b,
                (int)ctx->segments_queued(), (unsigned long long)ctx->get_processed_bytes());
            ctx->config_file_type(true);                       // c: 6..12 flush
            printable_data(6, 6);                              //   + process_all drains 12..18
            bool c = ctx->process(&g_p, g_data, 6, (uint64_t)6, stub_file_policy(), (FilePosition)0);
            std::printf("O3b c=%d processed=%llu size=%llu complete=%d\n", (int)c,
                (unsigned long long)ctx->get_processed_bytes(),
                (unsigned long long)ctx->get_file_size(), (int)ctx->processing_complete);
            // O3b WHY c=0: the direct 6..12 flush TRUE'd (fp_eval armed
            // the type, :892 then SELF-DISABLED it); process_all then
            // drained the queued 12..18 with features OFF -> :842
            // "Type and Sig not enabled" arm -> update(MIDDLE,6) +
            // complete -> false -> clear() -> break -> ret 0.
            // c): clear() reset current_offset/head; 18 != 0 -> re-queued
            printable_data(6, 18);
            bool d = ctx->process(&g_p, g_data, 6, (uint64_t)18, stub_file_policy(), (FilePosition)0);
            std::printf("O3c d=%d processed=%llu complete=%d\n", (int)d,
                (unsigned long long)ctx->get_processed_bytes(),
                (int)ctx->processing_complete);
            ctx->config_file_type(true);
            printable_data(6, 0);       // e: current==0 flush TRUE (queued 18 head != current 6)
            bool e = ctx->process(&g_p, g_data, 6, (uint64_t)0, stub_file_policy(), (FilePosition)0);
            std::printf("O3d e=%d processed=%llu queued=%d\n", (int)e,
                (unsigned long long)ctx->get_processed_bytes(), (int)ctx->segments_queued());
        }

        // O4: CONTINUE-type mode (the fp_eval seam re-arms type 0 =
        // SNORT_FILE_TYPE_CONTINUE: process_file_type re-enters
        // find_file_type_from_ips every segment and the :885 found-type
        // pass NEVER runs -> the type feature never self-disables -> a
        // TRUE multi-segment drain, terminating naturally when the END
        // position finalizes CONTINUE -> UNKNOWN and the :871 arm returns
        // false (+clear). Exercises add()/insert_segment head-insert +
        // end-trim, the :321 old-range drop, and the END terminal.
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
        fc->snort_protocol_id = 66;
        fctx_set_fp_eval_type((unsigned)66, SNORT_FILE_TYPE_CONTINUE);
        {
            FileContext* ctx = fresh_ctx(53);
            ctx->config_file_type(true);
            ctx->set_file_size(40);
            printable_data(10, 0);   // a: DIRECT flush current==0 (START pos)
            bool a = ctx->process(&g_p, g_data, 10, (uint64_t)0, stub_file_policy(), (FilePosition)0);
            printable_data(10, 20);  // b: queue @20 current==10 (list: 20..30)
            bool b = ctx->process(&g_p, g_data, 10, (uint64_t)20, stub_file_policy(), (FilePosition)0);
            printable_data(10, 12);  // c: 12..22: tail@20>start, no head<=start ->
                                     // head-insert + end-trim data_size = 20-12 = 8
            bool c = ctx->process(&g_p, g_data, 10, (uint64_t)12, stub_file_policy(), (FilePosition)0);
            std::printf("O4a a=%d b=%d c=%d processed=%llu\n", (int)a,(int)b,(int)c,
                (unsigned long long)ctx->get_processed_bytes());
            printable_data(5, 5);    // d: 5..10 fully below current(10) -> :321 DROP ret 1,
                                     // no "Adding segment" print
            bool d = ctx->process(&g_p, g_data, 5, (uint64_t)5, stub_file_policy(), (FilePosition)0);
            std::printf("O4b_drop d=%d processed=%llu\n", (int)d,
                (unsigned long long)ctx->get_processed_bytes());
            printable_data(2, 10);   // e: on current(10): DIRECT flush -> process_all
                                     // drains 12..20 then 20..30 (all TRUE, END never
                                     // reached: file_size 40 > 30 keeps MIDDLE)
            bool e = ctx->process(&g_p, g_data, 2, (uint64_t)10, stub_file_policy(), (FilePosition)0);
            std::printf("O4c_drain e=%d processed=%llu size=%llu complete=%d\n", (int)e,
                (unsigned long long)ctx->get_processed_bytes(),
                (unsigned long long)ctx->get_file_size(), (int)ctx->processing_complete);
            printable_data(10, 30);  // g: 30..40 == tail: current==30 -> DIRECT flush,
                                     // get_file_position -> END -> finalize -> UNKNOWN
                                     // -> :871 arm -> update(END) complete + false +
                                     // clear()+return 0 at :341-342
            bool g2 = ctx->process(&g_p, g_data, 10, (uint64_t)30, stub_file_policy(), (FilePosition)0);
            std::printf("O4d_END g=%d processed=%llu size=%llu complete=%d ftype=%u queued=%d\n",
                (int)g2, (unsigned long long)ctx->get_processed_bytes(),
                (unsigned long long)ctx->get_file_size(), (int)ctx->processing_complete,
                (unsigned)ctx->file_type_id, (int)ctx->segments_queued());
        }
        fctx_set_fp_eval_type(0, 0);
        fcache_set_file_trace(0, 0);
        fc->snort_protocol_id = UNKNOWN_PROTOCOL_ID;

        // O5: ret FALSE from the flushed feed -> clear() DROPS the backlog
        // (:341-342) while the segments QUEUED pointer survives; the second
        // "Adding segment" print (head-null fast path, !left trim arm was
        // NOT re-taken) proves the list itself was emptied.
        {
            FileContext* ctx = fresh_ctx(54);
            ctx->config_file_type(true);
            ctx->config_file_signature(false);
            ctx->set_file_size(50);
            fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
            printable_data(10, 20);   // queued (current 0 < 20 < file_size 50)
            bool q = ctx->process(&g_p, g_data, 10, (uint64_t)20, stub_file_policy(), (FilePosition)0);
            // seam switch (conf spid re-armed so the set fires): the type
            // now lands UNKNOWN -> K :871 arm -> false -> :341-342 clear()
            fc->snort_protocol_id = 66;
            fctx_set_fp_eval_type((unsigned)66, SNORT_FILE_TYPE_UNKNOWN);
            printable_data(8, 0);
            bool r = ctx->process(&g_p, g_data, 8, (uint64_t)0, stub_file_policy(), (FilePosition)0);
            std::printf("O5_CLEAR r=%d queued_ptr=%d complete=%d processed=%llu\n",
                (int)r, (int)ctx->segments_queued(), (int)ctx->processing_complete,
                (unsigned long long)ctx->get_processed_bytes());
            fctx_set_fp_eval_type(0, 0);
            fc->snort_protocol_id = UNKNOWN_PROTOCOL_ID;
            printable_data(10, 20);   // re-queue: the head-null "Adding segment
                                      // offset : 20" line AGAIN proves the list
                                      // itself was cleared by the false arm
            bool q2 = ctx->process(&g_p, g_data, 10, (uint64_t)20, stub_file_policy(), (FilePosition)0);
            std::printf("O5b q2=%d queued=%d\n", (int)q2, (int)ctx->segments_queued());
            fcache_set_file_trace(0, 0);
        }
        fctx_set_fp_eval_type(0, 0);
        fc->snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    }

    // ================= P2: segments lifecycle + DropReason-free arms ===
    {
        // remove_segments goes live: queue a segment via the backlog arm,
        // remove_segments, then segments_queued false; reset() path.
        FileContext* ctx = fresh_ctx(60);
        ctx->config_file_type(false);
        ctx->config_file_signature(false);
        ctx->set_file_size(40);
        printable_data(6, 10);
        ctx->process(&g_p, g_data, 6, (uint64_t)10, stub_file_policy(), (FilePosition)0);
        int q1 = (int)ctx->segments_queued();
        ctx->remove_segments();
        int q2 = (int)ctx->segments_queued();
        std::printf("P2_SEGS queued1=%d queued2=%d\n", q1, q2);
    }

    delete g_ff;
    g_ff = nullptr;
    fcache_set_next_packet(nullptr);
    fcache_release_stub_policy();
    std::fflush(stdout);
    return 0;
}
