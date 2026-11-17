// probe.cc — ground-truth transcript for the REAL file_api/file_cache.cc
// TU (row 17p). Everything deterministic: packet clock armed ONLY via
// packet_time_update (clamps forward); SnortClock pinned by the
// interposed clock_gettime fake clock (stubs.cc); fixed inputs; hash
// seeding pinned via SnortConfig::static_hash() (rules EOFCFG shim).
// FileCache/XHash/HashLruCache/packet_time are REAL bodies; the donor's
// FileCache witnesses are RETIRED — witnesses remain only for the
// monolith seams (Active/MPDataBus/DataBus/PacketTracer/FileService/
// FileFlows/InspectorManager/ThreadConfig/ControlConn/trace).
//
// Key discipline: cache entries added with mkkey(id) build a fully-
// zero FileHashKey except file_id — byte-identical (via memcmp-compare
// keysize) to make_key() output for a zero-initialized probe Flow whose
// FlowKey.addressSpaceId == 0. Sections that mix cache_add + Flow-based
// lookups therefore use g_flow (zero, asid 0); F uses nonzero asid on
// both sides on purpose (PIN: uint32 addressSpaceId -> uint16 asid).
//
// Printf hygiene: mutating calls hoisted into locals before any printf.
#include "file_api/file_lib.h"
#include "file_api/file_api.h"
#include "file_api/file_cache.h"
#include "file_api/file_config.h"
#include "file_api/file_service.h"
#include "file_api/file_stats.h"
#include "flowz/flow_fwd.h"
#include "flow/flow_key.h"
#include "detection/detection_engine.h"
#include "hash/hashes.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "time/packet_time.h"
#include "trace/trace.h"

// defined in stubs.cc (witness bodies TU)
snort::FilePolicyBase* stub_file_policy();
FileConfig* get_harness_file_config();

#include <cstdio>
#include <cstddef>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

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
extern "C" void fcache_set_instance_max(unsigned n);
extern "C" void fcache_set_mp_dbus(int on);

// zero statics: fully zero-initialized (family=AF_UNSPEC=0, union bytes 0)
// so make_key bytes == FileHashKey{} bytes except file_id (see header note)
static FlowKey g_fkey;
static Flow g_flow;

// deterministic packet-clock arm (real packet_time.cc clamps forward)
static void pkt_now(long sec, long usec)
{
    struct timeval tv = { sec, usec };
    ::packet_time_update(&tv);
    struct timeval got;
    packet_gettimeofday(&got);
    std::printf("CLK tv=%ld.%06ld\n", (long)got.tv_sec, (long)got.tv_usec);
}

static FileHashKey mkkey(uint64_t file_id)
{
    FileHashKey key{};
    key.file_id = file_id;
    return key;
}

static FileHashKey mkkey(uint64_t file_id, uint16_t asid)
{
    FileHashKey key{};
    key.file_id = file_id;
    key.asid = asid;
    return key;
}

static FileContext* cache_add(FileCache& c, const FileHashKey& k, int64_t timeout,
    bool& cache_full, int64_t& cache_expire, bool sync = true)
{
    return c.add(k, timeout, cache_full, cache_expire, sync);
}

static std::string keyhex(const FileHashKey& k)
{
    std::string s;
    char x[3];
    const unsigned char* b = (const unsigned char*)&k;
    for (size_t i = 0; i < sizeof(k); i++)
        { std::snprintf(x, sizeof x, "%02x", b[i]); s += x; }
    return s;
}

static std::string shahex(const uint8_t* sha)
{
    std::string s;
    char x[3];
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
        { std::snprintf(x, sizeof x, "%02x", sha[i]); s += x; }
    return s;
}

// real EVP chain on a throwaway context: pins the sha bytes the dump
// filters then match against (same api production uses).
struct FC : public FileContext
{
    // throwaway real-API sha chain (SNORT_FILE_FULL arm finalizes).
    // config must be armed: process_file_signature_sha256 reads
    // config->file_signature_depth (file_lib.cc:1070).
    static void chain(const uint8_t* d, int n, uint8_t* out)
    {
        FC t;
        t.set_config(get_harness_file_config());
        t.process_file_signature_sha256(d, n, SNORT_FILE_FULL);
        memcpy(out, t.get_file_sig_sha256(), SHA256_HASH_SIZE);
    }
};

int main()
{
    fcache_enable_fake_clock(1);
    file_stats_init();   // THREAD_LOCAL file_stats/file_counts armed (rc 139 rule)
    g_flow.key = &g_fkey;
    fcache_set_fake_now(100.0);
    fcache_set_adv_pub_id(7);
    pkt_now(1000, 0);

    // ================= A: layout vocabulary =================
    std::printf("A_SZ_FHK=%zu OFS_sip=%zu OFS_sgroup=%zu OFS_dip=%zu OFS_dgroup=%zu "
        "OFS_fileid=%zu OFS_asid=%zu OFS_pad=%zu SZ_SFIP=%zu\n",
        sizeof(FileHashKey), offsetof(FileHashKey, sip), offsetof(FileHashKey, sgroup),
        offsetof(FileHashKey, dip), offsetof(FileHashKey, dgroup),
        offsetof(FileHashKey, file_id), offsetof(FileHashKey, asid),
        offsetof(FileHashKey, padding), sizeof(SfIp));
    std::printf("A_SZ_FILENODE=%zu OFS_expire=%zu OFS_file=%zu\n",
        sizeof(FileCache::FileNode), offsetof(FileCache::FileNode, cache_expire_time),
        offsetof(FileCache::FileNode, file));
    std::printf("A_DEFAULTS block=%d lookup=%d maxfiles=%d\n",
        DEFAULT_FILE_BLOCK_TIMEOUT, DEFAULT_FILE_LOOKUP_TIMEOUT, DEFAULT_MAX_FILES_CACHED);
    std::printf("A_ACTS trust=%d allow=%d hold=%d retry=%d rewrite=%d drop=%d block=%d reset=%d max=%d\n",
        (int)Active::ACT_TRUST, (int)Active::ACT_ALLOW, (int)Active::ACT_HOLD,
        (int)Active::ACT_RETRY, (int)Active::ACT_REWRITE, (int)Active::ACT_DROP,
        (int)Active::ACT_BLOCK, (int)Active::ACT_RESET, (int)Active::ACT_MAX);
    { FileHashKey k{}; k.file_id = 0x0BADC0DE; k.asid = 0x1234; k.sgroup = -2; k.dgroup = 3;
      std::printf("A_KEYHEX sg=-2 dg=3 id=0x0BADC0DE asid=0x1234 -> %s\n", keyhex(k).c_str()); }

    // ================= B: add / find / get_file vocabulary =================
    {
        fcache_set_file_inspector(0);
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        bool cf = false; int64_t ce = 0;
        FileContext* e1 = cache_add(cache, mkkey(1), 60, cf, ce);
        FileContext* e1b = cache_add(cache, mkkey(1), 60, cf, ce);
        long long expire = ce;
        std::printf("B_ADD1 have=%d same_ptr=%d cache_full=%d expire_off=%lld entries=%lld\n",
            e1 ? 1 : 0, (e1 == e1b), cf, expire - 1000,
            (long long)cache.get_num_entries());
        e1->verdict = FILE_VERDICT_LOG;
        FileContext* found = cache.get_file(&g_flow, 1, false, false);
        std::printf("B_GET_FILE hit=%d same=%d\n", found ? 1 : 0, found == e1);
        FileContext* made = cache.get_file(&g_flow, 7, true, false);
        std::printf("B_GET_FILE create=%d entries=%lld\n", made ? 1 : 0,
            (long long)cache.get_num_entries());
        FileContext* a1 = cache_add(cache, mkkey(1, 9), 60, cf, ce);
        long long ent = cache.get_num_entries();
        std::printf("B_ASID_KEY distinct=%d entries=%lld\n", (a1 != e1) ? 1 : 0, ent);
        const FileCacheClearReport rep = cache.clear();
        std::printf("B_CLEAR freed=%llu remaining=%llu\n",
            (unsigned long long)rep.freed, (unsigned long long)rep.remaining);
        fcache_set_file_cache(nullptr);
    }

    // ================= C: capacity churn (HASH_NOMEM ladder) =============
    {
        FileCache cache(2);
        fcache_set_file_cache(&cache);
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
        bool cf = false; int64_t ce = 0;
        file_counts.file_cache_full = 0; file_counts.file_cache_failures = 0;
        file_counts.cache_add_fails = 0; file_counts.file_cache_total_entries = 0;
        file_counts.file_cache_max_entries = 0;
        FileContext* c1 = cache_add(cache, mkkey(1), 60, cf, ce);
        FileContext* c2 = cache_add(cache, mkkey(2), 60, cf, ce);
        std::printf("C_FULL first have=%d %d\n", c1 ? 1 : 0, c2 ? 1 : 0);
        cf = false; ce = 0;
        FileContext* c3 = cache_add(cache, mkkey(3), 60, cf, ce);
        std::printf("C_FULL third have=%d cache_full=%d full=%llu fails=%llu add_fails=%llu "
            "total_entries=%llu max_entries=%llu entries=%lld\n",
            c3 ? 1 : 0, cf,
            (unsigned long long)file_counts.file_cache_full,
            (unsigned long long)file_counts.file_cache_failures,
            (unsigned long long)file_counts.cache_add_fails,
            (unsigned long long)file_counts.file_cache_total_entries,
            (unsigned long long)file_counts.file_cache_max_entries,
            (long long)cache.get_num_entries());
        const FileCacheClearReport rep = cache.clear();
        std::printf("C_CLEAR freed=%llu remaining=%llu\n",
            (unsigned long long)rep.freed, (unsigned long long)rep.remaining);
        // capacity survives clear(): re-add exactly 2, third still full
        FileContext* d1 = cache_add(cache, mkkey(10), 60, cf, ce);
        FileContext* d2 = cache_add(cache, mkkey(11), 60, cf, ce);
        FileContext* d3 = cache_add(cache, mkkey(12), 60, cf, ce);
        std::printf("C_RECAPPED d1=%d d2=%d d3=%d entries=%lld\n",
            d1 ? 1 : 0, d2 ? 1 : 0, d3 ? 1 : 0, (long long)cache.get_num_entries());
        fcache_set_file_trace(0, 0);
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= D: set_max_files clamp (ThreadConfig seam) =========
    {
        fcache_set_instance_max(2);   // minimal_files = instance_max + 1 = 3
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        cache.set_max_files(1);       // clamped to 3 + ErrorMessage witness
        bool cf = false; int64_t ce = 0;
        FileContext* m1 = cache_add(cache, mkkey(20), 60, cf, ce);
        FileContext* m2 = cache_add(cache, mkkey(21), 60, cf, ce);
        FileContext* m3 = cache_add(cache, mkkey(22), 60, cf, ce);
        FileContext* m4 = cache_add(cache, mkkey(23), 60, cf, ce);
        std::printf("D_CLAMP m=[%d,%d,%d,%d] entries=%lld\n",
            m1 ? 1 : 0, m2 ? 1 : 0, m3 ? 1 : 0, m4 ? 1 : 0,
            (long long)cache.get_num_entries());
        cache.set_max_files(9);       // no clamp; witness still fires
        FileCacheClearReport rep = cache.clear();
        FileContext* n9 = nullptr;
        for (uint64_t i = 30; i < 39; i++)
        {
            FileContext* n = cache_add(cache, mkkey(i), 60, cf, ce);
            if (i == 38) n9 = n;
        }
        FileContext* n10 = cache_add(cache, mkkey(39), 60, cf, ce);
        std::printf("D_RAISED cleared=%llu ninth=%d tenth=%d entries=%lld\n",
            (unsigned long long)rep.freed, n9 ? 1 : 0, n10 ? 1 : 0,
            (long long)cache.get_num_entries());
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= E: expiry ladder (packet clock) ====================
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        bool cf = false; int64_t ce = 0;
        FileContext* e = cache_add(cache, mkkey(1), 100, cf, ce);
        std::printf("E_ARM have=%d expire_off=%lld\n", e ? 1 : 0, (long long)ce - 1000);
        e->pin();
        pkt_now(1200, 0);   // +200s: cache_expire (t+100) well in the past
        FileContext* g = cache.get_file(&g_flow, 1, false, false);
        long long during = cache.get_num_entries();
        std::printf("E_EXPIRED_PINNED found=%d kept_entries=%lld\n",
            g ? 1 : 0, during);
        e->unpin();
        FileContext* g2 = cache.get_file(&g_flow, 1, false, false);
        long long after = cache.get_num_entries();
        std::printf("E_EXPIRED_FREE found=%d entries=%lld\n", g2 ? 1 : 0, after);
        // fresh add: fresh FileContext (fresh verdict) despite node recycling
        FileContext* again = cache_add(cache, mkkey(1), 100, cf, ce);
        int freshv = again ? (int)again->verdict : -1;
        std::printf("E_READD fresh_verdict=%d entries=%lld\n", freshv,
            (long long)cache.get_num_entries());
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= F: make_key / Flow field mapping ===================
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        Flow flow;
        FlowKey fkey{};
        fkey.addressSpaceId = 0x12345;   // uint32 -> uint16 asid PIN truncation
        flow.key = &fkey;
        flow.client_group = 7;
        flow.server_group = -5;
        uint8_t cip[4] = { 192, 0, 2, 1 };
        uint8_t sip[4] = { 10, 1, 2, 3 };
        flow.client_ip.set(cip, AF_INET);
        flow.server_ip.set(sip, AF_INET);
        FileContext* fe = cache.get_file(&flow, 5, true, false);
        std::printf("F_FLOWKEY have=%d\n", fe ? 1 : 0);
        fkey.addressSpaceId = 0x67890;   // different asid (both nonzero tail)
        FileContext* fe2 = cache.get_file(&flow, 5, true, false);
        long long ent = cache.get_num_entries();
        std::printf("F_ASID_TRUNC distinct=%d entries=%lld\n",
            (fe != fe2) ? 1 : 0, ent);
        fkey.addressSpaceId = 0xAB2345;  // same truncated asid 0x2345 (0x12345 & 0xFFFF)
        FileContext* fe3 = cache.get_file(&flow, 5, false, false);
        std::printf("F_ASID_SAME same=%d\n", (fe == fe3) ? 1 : 0);
        fkey.addressSpaceId = 0x12345;
        FileContext* fe4 = cache.get_file(&flow, 5, false, false);
        std::printf("F_ASID_ORIG same=%d\n", (fe == fe4) ? 1 : 0);
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= G: cached_verdict_lookup arms ======================
    {
        fcache_set_file_inspector(0);
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        fcache_set_file_trace(1, TRACE_ERROR_LEVEL);

        FlowKey fkey{};             // asid 0 -> byte-match with mkkey()
        g_flow.session_flags = SSNFLAG_SEEN_BOTH;

        Packet p;
        p.flow = &g_flow;
        Active act;
        p.active = &act;
        IpsContext ictx;
        ictx.conf = SnortConfig::get_conf();
        p.context = &ictx;
        fcache_set_next_packet(&p);

        // G1: lookup FileInfo without file id -> early UNKNOWN + TRACE_ERROR
        FC probe;
        FileVerdict v0 = cache.cached_verdict_lookup(&p, &probe, stub_file_policy(), nullptr, 0);
        std::printf("G_NOID verdict=%d\n", (int)v0);

        // G2: cached UNKNOWN entry, type LOG / sig UNKNOWN -> LOG + copy-back
        bool cf = false; int64_t ce = 0;
        FileContext* entry = cache_add(cache, mkkey(8), 3600, cf, ce);
        entry->set_file_id(8);
        probe.set_file_id(8);
        fcache_set_policy_verdicts(FILE_VERDICT_LOG, FILE_VERDICT_UNKNOWN);
        FileVerdict v1 = cache.cached_verdict_lookup(&p, &probe, stub_file_policy(), nullptr, 0);
        std::printf("G_TYPELOG verdict=%d probe_verdict=%d\n", (int)v1, (int)probe.verdict);

        // G3: cached PENDING, lookup FileInfo not a dup -> UNKNOWN
        entry->verdict = FILE_VERDICT_PENDING;
        FileVerdict v2 = cache.cached_verdict_lookup(&p, &probe, stub_file_policy(), nullptr, 0);
        std::printf("G_PEND_NODUP verdict=%d\n", (int)v2);

        // G4: sig arm — entry with capture buffer + sha; type UNKNOWN(<=LOG)
        // triggers set_capture_file_data + signature_lookup -> BLOCK
        FileContext* entry4 = cache_add(cache, mkkey(9), 3600, cf, ce);
        entry4->set_file_id(9);
        entry4->set_config(get_harness_file_config());
        entry4->process_file_capture((const uint8_t*)"abc", 3, SNORT_FILE_FULL);
        uint8_t sha[SHA256_HASH_SIZE];
        FC::chain((const uint8_t*)"abc", 3, sha);
        entry4->set_capture_file_data((const uint8_t*)"abc", 3);
        entry4->process_file_signature_sha256((const uint8_t*)"abc", 3, SNORT_FILE_FULL);
        probe.set_file_id(9);
        fcache_set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_BLOCK);
        fcache_set_pt_active(1);
        FileVerdict v3 = cache.cached_verdict_lookup(&p, &probe, stub_file_policy(), (const uint8_t*)"abc", 3);
        std::printf("G_SIGBLOCK verdict=%d sha=%s sha_match_entry=%d\n",
            (int)v3, shahex(sha).c_str(),
            entry4->get_file_sig_sha256() and 0 == memcmp(sha, entry4->get_file_sig_sha256(), SHA256_HASH_SIZE) ? 1 : 0);
        fcache_set_pt_active(0);

        // G5: no cached entry for an id -> miss -> UNKNOWN
        FC probe2;
        probe2.set_file_id(77);
        FileVerdict v4 = cache.cached_verdict_lookup(&p, &probe2, stub_file_policy(), nullptr, 0);
        std::printf("G_MISS verdict=%d\n", (int)v4);

        fcache_set_file_trace(0, 0);
        fcache_set_next_packet(nullptr);
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= H: apply_verdict arms ==============================
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        g_flow.session_flags = SSNFLAG_SEEN_BOTH;   // log_file_event asymmetry off
        Packet p;
        p.flow = &g_flow;
        Active act;
        p.active = &act;
        IpsContext ictx;
        ictx.conf = SnortConfig::get_conf();
        p.context = &ictx;
        fcache_set_next_packet(&p);

        bool cf = false; int64_t ce = 0;
        FileContext* e = cache_add(cache, mkkey(101), 3600, cf, ce);
        e->set_file_id(101);
        e->set_config(get_harness_file_config());
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
        bool r1 = cache.apply_verdict(&p, e, FILE_VERDICT_UNKNOWN, false, stub_file_policy());
        bool r2 = cache.apply_verdict(&p, e, FILE_VERDICT_LOG, false, stub_file_policy());
        bool r3 = cache.apply_verdict(&p, e, FILE_VERDICT_STOP_CAPTURE, false, stub_file_policy());
        int ve = (int)e->verdict;
        std::printf("H_STATIC unk=%d log=%d stopcap=%d verdict=%d\n",
            (int)r1, (int)r2, (int)r3, ve);
        // H2: BLOCK: Active ACT_BLOCK + drop_reason, then store (cacheable);
        // mp_dbus on -> MPDataBus get_id/publish witnesses fire in store
        fcache_set_mp_dbus(1);
        bool r4 = cache.apply_verdict(&p, e, FILE_VERDICT_BLOCK, false, stub_file_policy());
        int ve4 = (int)e->verdict;
        std::printf("H_BLOCK applied=%d verdict=%d\n", (int)r4, ve4);
        fcache_set_mp_dbus(0);
        // H3: REJECT arm -> Active ACT_RESET
        bool r5 = cache.apply_verdict(&p, e, FILE_VERDICT_REJECT, false, stub_file_policy());
        int ve5 = (int)e->verdict;
        std::printf("H_REJECT applied=%d verdict=%d\n", (int)r5, ve5);

        // H4: PENDING fresh arm (pending_expire unset) -> ACT_RETRY +
        // retry-queue FILEDBG/PT + add_pending_file + store_verdict OK
        p.packet_flags = 0;
        FileContext* e102 = cache_add(cache, mkkey(102), 3600, cf, ce);
        e102->set_file_id(102);
        e102->set_config(get_harness_file_config());
        e102->verdict = FILE_VERDICT_PENDING;
        cache.set_lookup_timeout(5);
        file_counts.file_lookup_timeouts = 0;
        fcache_set_file_trace(1, TRACE_INFO_LEVEL);
        fcache_set_pt_active(1);
        bool r6 = cache.apply_verdict(&p, e102, FILE_VERDICT_PENDING, false, stub_file_policy());
        int64_t pet = e102->pending_expire_time.tv_sec;
        std::printf("H_PEND_FRESH applied=%d armed_expire=%lld\n",
            (int)r6, (long long)pet);
        // H5: re-pending, expire armed but future, PKT_RETRANSMIT set and
        // not PKT_RETRY -> retry-queue PT log suppressed (file_cache.cc:723)
        p.packet_flags = PKT_RETRANSMIT;
        pkt_now(1205, 0);
        bool r7 = cache.apply_verdict(&p, e102, FILE_VERDICT_PENDING, false, stub_file_policy());
        std::printf("H_PEND_RETRANS applied=%d\n", (int)r7);
        p.packet_flags = 0;
        // H6: PENDING expired (pending_expire 1205 < now 1210),
        // block_timeout_lookup false -> no ACT_RESET, LOG downgrade +
        // timedout + file_lookup_timeouts++ (file_cache.cc:686-692);
        // time_elapsed_ms = 5*1000 + (1210-1205)*1000 = 10000ms pinned.
        // get_file_config(p->context->conf) (file_cache.cc:669) resolves
        // via the InspectorManager seam -> the harness FileConfig must be
        // reachable (a null fc at :673 is upstream's own NPE — real snort
        // always has the file inspector) -> arm the inspector witness.
        fcache_set_file_inspector(1);
        FileConfig* fc = get_harness_file_config();
        fc->block_timeout_lookup = false;
        pkt_now(1210, 0);
        int before = (int)e102->verdict;
        bool r8 = cache.apply_verdict(&p, e102, FILE_VERDICT_PENDING, false, stub_file_policy());
        int after = (int)e102->verdict;
        std::printf("H_PEND_EXPIRED applied=%d before=%d after=%d timedout=%d touts=%llu\n",
            (int)r8, before, after, (int)e102->get_timedout(),
            (unsigned long long)file_counts.file_lookup_timeouts);
        // H7: same but block_timeout_lookup TRUE -> ACT_RESET + resume BLOCK
        e102->verdict = FILE_VERDICT_PENDING;
        fc->block_timeout_lookup = true;
        file_counts.file_lookup_timeouts = 0;
        bool r9 = cache.apply_verdict(&p, e102, FILE_VERDICT_PENDING, true, stub_file_policy());
        std::printf("H_PEND_BTL applied=%d touts=%llu resume_action=BLOCK\n",
            (int)r9, (unsigned long long)file_counts.file_lookup_timeouts);
        fc->block_timeout_lookup = false;
        fcache_set_pt_active(0);
        fcache_set_file_trace(0, 0);

        // H8: store_verdict on an entry that is NOT cached, cache full ->
        // add returns HASH_NOMEM -> cache_full -> ACT_RETRY ladder
        FileCache small(2);
        fcache_set_file_cache(&small);
        cache_add(small, mkkey(900), 3600, cf, ce);  // fill capacity 2
        cache_add(small, mkkey(901), 3600, cf, ce);
        FC* s1 = new FC();
        s1->set_config(get_harness_file_config());
        s1->set_file_id(200);
        s1->verdict = FILE_VERDICT_PENDING;
        small.set_lookup_timeout(5);
        small.set_block_timeout(5);
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
        fcache_set_pt_active(1);
        bool rs = small.apply_verdict(&p, s1, FILE_VERDICT_PENDING, false, stub_file_policy());
        std::printf("H_PEND_CACHEFULL applied=%d entries=%lld\n",
            (int)rs, (long long)small.get_num_entries());
        fcache_set_pt_active(0);
        fcache_set_file_trace(0, 0);
        small.clear();
        delete s1;

        cache.clear();
        fcache_set_next_packet(nullptr);
        fcache_set_file_cache(nullptr);
    }

    // ================= I: store_shared_verdict arms =======================
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        bool cf = false; int64_t ce = 0;
        FileContext* entry = cache_add(cache, mkkey(300), 3600, cf, ce);
        entry->set_file_id(300);
        entry->verdict = FILE_VERDICT_BLOCK;     // cached terminal
        FC src;
        src.verdict = FILE_VERDICT_PENDING;      // incoming nonterminal -> blocked
        cache.store_shared_verdict(mkkey(300), 3600, src);
        int v = (int)entry->verdict;
        std::printf("I_SHARED_BLOCKED verdict=%d\n", v);
        FC src2;
        src2.verdict = FILE_VERDICT_BLOCK;       // condemned==condemned -> copy runs
        src2.set_file_name("shared.exe", 10);
        cache.store_shared_verdict(mkkey(300), 3600, src2);
        int v2 = (int)entry->verdict;
        std::string nm = entry->get_file_name();
        std::printf("I_SHARED_CONDEMNED verdict=%d name=%s\n", v2, nm.c_str());
        // condemn a nonterminal cached entry
        FileContext* entry2 = cache_add(cache, mkkey(301), 3600, cf, ce);
        entry2->verdict = FILE_VERDICT_LOG;
        FC src3;
        src3.verdict = FILE_VERDICT_REJECT;
        cache.store_shared_verdict(mkkey(301), 3600, src3);
        int v3 = (int)entry2->verdict;
        std::printf("I_SHARED_CONDENM_NEW verdict=%d\n", v3);
        // cached condemned, incoming nonterminal -> early return arm
        FC src4;
        src4.verdict = FILE_VERDICT_LOG;
        cache.store_shared_verdict(mkkey(301), 3600, src4);
        int v4 = (int)entry2->verdict;
        std::printf("I_SHARED_KEEP_CONDEMNED verdict=%d\n", v4);
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= J: dup / take_pending / not_cacheable ==============
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        bool is_pending = true;
        FileContext* d0 = cache.dup_cache_context(&g_flow, 400, is_pending);
        std::printf("J_DUP_MISS have=%d pending=%d\n", d0 ? 1 : 0, (int)is_pending);
        bool cf = false; int64_t ce = 0;
        FileContext* entry = cache_add(cache, mkkey(400), 3600, cf, ce);
        entry->verdict = FILE_VERDICT_BLOCK;
        entry->set_file_name("dup.bin", 7);
        is_pending = true;
        FileContext* dup = cache.dup_cache_context(&g_flow, 400, is_pending);
        int dv = dup ? (int)dup->verdict : -1;
        std::string dn = dup ? dup->get_file_name() : std::string("<null>");
        int dcd = dup ? (int)dup->is_cache_dup() : -1;
        std::printf("J_DUP have=%d pending=%d verdict=%d name=%s cache_dup=%d\n",
            dup ? 1 : 0, (int)is_pending, dv, dn.c_str(), dcd);
        delete dup;
        // not_cacheable cached entry -> true
        entry->set_not_cacheable();
        bool nc = cache.cached_context_not_cacheable(&g_flow, 400);
        std::printf("J_NOTCACHEABLE=%d\n", (int)nc);
        // pending entry + user_file_data -> take moves ownership
        FileContext* pe = cache_add(cache, mkkey(401), 3600, cf, ce);
        pe->verdict = FILE_VERDICT_PENDING;
        UserFileDataBase* ud = new UserFileDataBase;
        pe->set_file_data(ud);
        FC dst;
        cache.take_pending_file_data(&g_flow, 401, &dst);
        int src_now = pe->get_file_data() ? 1 : 0;
        int dst_now = dst.get_file_data() ? 1 : 0;
        std::printf("J_TAKE src=%d dst=%d\n", src_now, dst_now);
        // dst nonempty now -> second take is a no-op (dst->get_file_data() set)
        cache.take_pending_file_data(&g_flow, 401, &dst);
        int dst2 = dst.get_file_data() ? 1 : 0;
        std::printf("J_TAKE2 dst=%d\n", dst2);
        // pending dup -> is_pending flagged, clear_data=false keeps user data?
        // (nothing set on the entry now — take moved it out)
        is_pending = false;
        FileContext* dup2 = cache.dup_cache_context(&g_flow, 401, is_pending);
        int dv2 = dup2 ? (int)dup2->verdict : -1;
        int dup2ud = dup2 ? (dup2->get_file_data() ? 1 : 0) : -1;
        std::printf("J_DUP_PEND have=%d pending=%d verdict=%d user_data=%d\n",
            dup2 ? 1 : 0, (int)is_pending, dv2, dup2ud);
        delete dup2;
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= K: resume_pending_verdict ==========================
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        g_flow.session_flags = SSNFLAG_SEEN_BOTH;
        Packet p;
        p.flow = &g_flow;
        Active act;
        p.active = &act;
        IpsContext ictx;
        ictx.conf = SnortConfig::get_conf();
        p.context = &ictx;
        fcache_set_next_packet(&p);
        fcache_set_file_trace(1, TRACE_DEBUG_LEVEL);
        fcache_set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_LOG);

        FC dup0;   // no file id -> gate UNKNOWN + TRACE_ERROR FILEDBG
        FileVerdict r0 = cache.resume_pending_verdict(&p, &dup0, stub_file_policy());
        std::printf("K_RESUME_NOID verdict=%d\n", (int)r0);

        bool cf = false; int64_t ce = 0;
        // long cache lease (3600s) so the balance probe below works
        FileContext* entry = cache_add(cache, mkkey(500), 3600, cf, ce);
        entry->set_file_id(500);
        entry->set_config(get_harness_file_config());
        entry->verdict = FILE_VERDICT_PENDING;
        FC dup;
        dup.set_file_id(500);
        dup.set_file_name("resume.exe", 10);
        dup.set_url("http://h/r", 10);
        dup.set_host("h", 1);
        FileVerdict r1 = cache.resume_pending_verdict(&p, &dup, stub_file_policy());
        int evn = (int)entry->verdict;
        std::string ename = entry->get_file_name();
        std::string eurl = entry->get_url();
        std::string ehost = entry->get_host_name();
        std::printf("K_RESUME_LOG resolved=%d entry_verdict=%d name=%s url=%s host=%s\n",
            (int)r1, evn, ename.c_str(), eurl.c_str(), ehost.c_str());
        // pin balance: expire the entry, then an expired find releases the
        // node ONLY when in_use == 0. If CacheNodePin unbalanced, the entry
        // would be kept forever.
        pkt_now(6000, 0);   // cache_expire (clk 1210 + 3600) in the past
        FileContext* g = cache.get_file(&g_flow, 500, false, false);
        long long remaining = cache.get_num_entries();
        std::printf("K_RESUME_PINBALANCED found=%d released=%d\n",
            g ? 1 : 0, remaining == 0 ? 1 : 0);
        fcache_set_file_trace(0, 0);
        fcache_set_next_packet(nullptr);
        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= L: dump_cache / dump_cache_entry ===================
    {
        FileCache cache(4);
        fcache_set_file_cache(&cache);
        std::printf("L_EMPTY_DUMP begin\n");
        cache.dump_cache(nullptr, 10);
        std::printf("L_EMPTY_DUMP end\n");
        std::printf("L_EMPTY_ENTRY begin\n");
        cache.dump_cache_entry(nullptr, "AB");
        std::printf("L_EMPTY_ENTRY end\n");

        bool cf = false; int64_t ce = 0;
        uint8_t sha[SHA256_HASH_SIZE];
        FC::chain((const uint8_t*)"abc", 3, sha);
        std::printf("L_SHA256_ABC=%s\n", shahex(sha).c_str());

        // entry 1: long name (20-col truncate pin), UNKNOWN type, BLOCK, sha
        FileContext* e1 = cache_add(cache, mkkey(601), 3600, cf, ce);
        e1->set_file_name("this_file_name_is_waaaaaaaaay_too_long.exe", 39);
        e1->set_file_type(SNORT_FILE_TYPE_UNKNOWN);
        e1->verdict = FILE_VERDICT_BLOCK;
        e1->process_file_signature_sha256((const uint8_t*)"abc", 3, SNORT_FILE_FULL);
        // entry 2: short name, no sha -> <pending>, CONTINUE type name pin
        FileContext* e2 = cache_add(cache, mkkey(602), 3600, cf, ce);
        e2->set_file_name("short.exe", 9);
        e2->verdict = FILE_VERDICT_LOG;
        // entry 3: same sha, detail-row fields (dump_cache_entry hits)
        FileContext* e3 = cache_add(cache, mkkey(603), 3600, cf, ce);
        e3->set_file_name("mid_name_exact20ch.exe", 22);
        e3->set_url("http://example.com/m", 22);
        e3->set_host("example.com", 11);
        e3->set_file_size(4100);
        e3->set_file_id(603);
        e3->set_file_direction(FILE_UPLOAD);
        e3->set_file_type(SNORT_FILE_TYPE_UNKNOWN);
        e3->verdict = FILE_VERDICT_PENDING;
        e3->process_file_signature_sha256((const uint8_t*)"abc", 3, SNORT_FILE_FULL);

        std::printf("L_DUMP_ALL begin\n");
        cache.dump_cache(nullptr, 10);          // insertion-order walk
        std::printf("L_DUMP_ALL end\n");
        std::printf("L_DUMP_CAP1 begin\n");
        cache.dump_cache(nullptr, 1);           // "... displayed 1 of 3"
        std::printf("L_DUMP_CAP1 end\n");
        std::printf("L_ENTRY_LOWER begin\n");   // lowercase prefix NEVER matches (uppercase digits)
        cache.dump_cache_entry(nullptr, shahex(sha).substr(0, 6));
        std::printf("L_ENTRY_LOWER end\n");
        std::printf("L_ENTRY_UPPER begin\n");
        {
            // uppercase-hex prefix DOES match (hex_digit table is "0-9A-F")
            char up[3]; std::string pfx;
            for (int i = 0; i < 6; i++)
                { std::snprintf(up, sizeof up, "%02X", sha[i]); pfx += up; }
            cache.dump_cache_entry(nullptr, pfx);
        }
        std::printf("L_ENTRY_UPPER end\n");
        std::printf("L_ENTRY_MISS begin\n");
        cache.dump_cache_entry(nullptr, "00");
        std::printf("L_ENTRY_MISS end\n");
        std::printf("L_ENTRY_TOOLONG begin\n");
        cache.dump_cache_entry(nullptr, std::string(65, '0'));
        std::printf("L_ENTRY_TOOLONG end\n");

        cache.clear();
        fcache_set_file_cache(nullptr);
    }

    // ================= M: pinned-entry expiry vs clear ====================
    {
        FileCache cache(16);
        fcache_set_file_cache(&cache);
        bool cf = false; int64_t ce = 0;
        FileContext* e = cache_add(cache, mkkey(700), 50, cf, ce);
        e->pin();
        pkt_now(7000, 0);   // way past expire
        FileContext* g = cache.get_file(&g_flow, 700, false, false);
        long long during = cache.get_num_entries();
        e->unpin();
        FileCacheClearReport rep = cache.clear();
        std::printf("M_PINNED_SKIP found=%d during=%lld freed=%llu remaining=%lld\n",
            g ? 1 : 0, during,
            (unsigned long long)rep.freed, (long long)rep.remaining);
        fcache_set_file_cache(nullptr);
    }

    fcache_release_stub_policy();
    std::fflush(stdout);
    return 0;
}
