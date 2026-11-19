// probe.cc — ground-truth transcript for the MP-share glue row,
// file_api/file_cache_share.{h,cc} (row 17t). The TU has ZERO TEST_CASEs
// (PLAN 2): every behavioral oracle rides here as FCS_* vector arms.
//
// Drive shape mirrors the C consumers: FileMPEvent built on the stack and
// pushed straight through FileCacheShare::handle (file_inspect.cc:76-:83
// subscribes `new FileCacheShare()` and MPDataBus feeds it FileMPEvents —
// NEVER a raw DataEvent: the cc:32 static_cast downcast makes that UB,
// risk R6). The verdict half runs through the REAL FileCache +
// FileCache::store_shared_verdict (file_cache.cc:508-:528, file_cache.o in
// the link) installed via the real FileService::file_cache static
// (file_service.h:109, B symbol in stubs.o).
//
// Heap-ownership oracles (risk R7): serialize_file_event new[]s the buffer
// (cc:54) and deserialize_file_event new's the out-event (cc:68); the TU
// never frees either — the probe frees both (delete[] / delete at arm end)
// and asserts the manual-contract ownership witnesses.
//
// R5 pin: deserialize_file_event rejects ONLY null buffer / len==0
// (cc:65-:66); the fixed header memcpy walk (file_events.h:85-:100) reads
// the full timeout+key header unconditionally, so ANY 0<len<fixed_len
// buffer is an OOB read. That truncated arm is UB, NOT oracle material —
// deliberately NOT vectored (documented upstream gap, do not "fix").
//
// Printf hygiene: mutating calls hoisted into locals BEFORE printf; counts
// and bytes snapshotted before frees; NO pointer values, NO 0x[0-9a-f]{6,}
// anywhere (byte dumps print as uppercase %02X runs, no 0x prefix);
// nullness/refcount observations print as 0/1, never addresses. Packet
// clock armed ONLY via packet_time_update (real packet_time.cc clamps
// forward); XHash seeding pinned by the rules EOFCFG static_hash shim —
// fully deterministic per PLAN 7/10.
#include "file_api/file_cache_share.h"
#include "file_api/file_cache.h"
#include "file_api/file_lib.h"
#include "file_api/file_service.h"
#include "file_api/file_config.h"
#include "pub_sub/file_events.h"
#include "time/packet_time.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>

using namespace snort;

// deterministic packet-clock arm (real packet_time.cc clamps forward)
static void pkt_now(long sec, long usec)
{
    struct timeval tv = { sec, usec };
    ::packet_time_update(&tv);
}

static FileHashKey mkkey(uint64_t file_id)
{
    FileHashKey key{};
    key.file_id = file_id;
    return key;
}

// node fetch through the PUBLIC add() (cache_sync form, same one
// store_shared_verdict itself uses at cc:512 -> returns the live node)
static FileContext* cache_add(FileCache& c, const FileHashKey& k, int64_t timeout,
    bool& cache_full, int64_t& cache_expire)
{
    return c.add(k, timeout, cache_full, cache_expire, true);
}

static const uint8_t g_sha[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20 };

// fixed header length = the FileMPEvent ctor math (file_events.h:43-:45)
static size_t fixed_len_of(const FileHashKey& hk)
{
    return sizeof(int64_t) + sizeof(hk.sip) + sizeof(hk.sgroup)
        + sizeof(hk.dip) + sizeof(hk.dgroup)
        + sizeof(hk.file_id) + sizeof(hk.asid) + sizeof(hk.padding);
}

// shared wire buffer from the S3 arm -> consumed by D3/D4 (and freed there;
// R7 caller-owns contract)
static char*       g_wire = nullptr;
static uint16_t    g_wire_len = 0;

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    pkt_now(1000000, 0);   // fixed packet clock, clamps forward only

    FileHashKey probe_key = mkkey(0);
    std::printf("CONST sizeof_FileHashKey=%zu fixed_len=%zu sizeof_FileMPEvent=%zu\n",
        sizeof probe_key, fixed_len_of(probe_key), sizeof(FileMPEvent));

    // ================= S: serialize_file_event arms (cc:44-:61) ==========
    {
        // S1: null event -> false; out-params untouched (cc:46-:47)
        uint16_t len_sentinel = 0xBEEFu;
        char* buf = nullptr;
        int ret_s1 = serialize_file_event(nullptr, buf, &len_sentinel) ? 1 : 0;
        int untouched = (len_sentinel == 0xBEEFu) ? 1 : 0;
        std::printf("S1_null ret=%d buf_null_after=%d len_untouched=%d\n",
            ret_s1, buf ? 0 : 1, untouched);

        // S2: len==0 convergence, BOTH branches (cc:51-:52): default ctor
        // (file_events.h:55-:59, len=0) and the oversized-file ctor cap
        // (file_events.h:49-:50). The cap arm reaches the cap by writing
        // the 63000-byte name through the FIXACC-public file_name member
        // (set_file_name would clamp to PATH_MAX, file_lib.cc:346 — the
        // member write is the FIXACC seam PLAN 7 sanctions).
        {
            FileMPEvent ev_zero;                       // default: len=0
            char* buf2 = nullptr; uint16_t l2 = 0;
            int rz = serialize_file_event(&ev_zero, buf2, &l2) ? 1 : 0;
            unsigned dl_zero = ev_zero.get_data_len();

            // cap math pinned (measured): fixed_len 64; measured bare
            // name-set tail = 52 -> name 65420 => 65472 > 65535-64=65471
            // -> ctor cap len = 0 (file_events.h:49-:50).
            FileInfo big;
            big.file_name.assign(65420, 'X');          // tail > cap - fixed
            big.file_name_set = true;
            FileHashKey kb = mkkey(501);
            FileMPEvent ev_big(kb, 3600, big);         // ctor caps len=0
            unsigned dl_big = ev_big.get_data_len();
            char* buf3 = nullptr; uint16_t l3 = 0;
            int ro = serialize_file_event(&ev_big, buf3, &l3) ? 1 : 0;
            std::printf("S2_zerolen ret_default=%d data_len_default=%u "
                "ret_oversized=%d data_len_oversized=%u\n",
                rz, dl_zero, ro, dl_big);
        }

        // S3: populated event -> true; len_out == get_data_len(); buffer
        // == manual layout (timeout|sip|sgroup|dip|dgroup|file_id|asid|
        // padding|FileInfo tail, field order file_events.h:108-:127).
        {
            FileHashKey k3 = mkkey(503);
            FileInfo fi3;
            fi3.verdict = FILE_VERDICT_BLOCK;
            fi3.set_file_name("s3_shared.exe", 13);   // exact strlen: no clamp
            fi3.set_url("/share/s3", 9);              // exact strlen
            fi3.set_file_id(503);
            fi3.set_file_size(2048);
            fi3.sha256 = new uint8_t[32];              // heap: ~FileInfo
            memcpy(fi3.sha256, g_sha, 32);             // deletes; copy ctor
            fi3.is_sha256_set = true;                  // deep-copies (no dbl)
            FileMPEvent ev3(k3, 3000001234, fi3);
            ev3.hashkey.sgroup = 7; ev3.hashkey.dgroup = 9;   // FIXACC arm
            uint16_t l3 = 0;
            int r3 = serialize_file_event(&ev3, g_wire, &g_wire_len) ? 1 : 0;
            (void)l3;
            unsigned dl3 = ev3.get_data_len();
            size_t fixed = fixed_len_of(k3);

            // expected header: field-by-field copies in the cc:59 walk order
            char expect_hdr[64];
            size_t o = 0;
            int64_t tm = ev3.get_timeout();
            memcpy(expect_hdr + o, &tm, 8); o += 8;
            const FileHashKey& hk = ev3.get_hashkey();
            memcpy(expect_hdr + o, &hk.sip, sizeof hk.sip);       o += sizeof hk.sip;
            memcpy(expect_hdr + o, &hk.sgroup, sizeof hk.sgroup); o += sizeof hk.sgroup;
            memcpy(expect_hdr + o, &hk.dip, sizeof hk.dip);       o += sizeof hk.dip;
            memcpy(expect_hdr + o, &hk.dgroup, sizeof hk.dgroup); o += sizeof hk.dgroup;
            memcpy(expect_hdr + o, &hk.file_id, sizeof hk.file_id); o += sizeof hk.file_id;
            memcpy(expect_hdr + o, &hk.asid, sizeof hk.asid);     o += sizeof hk.asid;
            memcpy(expect_hdr + o, &hk.padding, sizeof hk.padding); o += sizeof hk.padding;

            // expected tail: REAL FileInfo::serialize over a deep copy
            FileInfo ref(ev3.get_file_ctx());
            static char expect_tail[4096];
            ref.serialize(expect_tail, (uint16_t)(g_wire_len - fixed));

            int hdr_eq = (o == fixed && memcmp(g_wire, expect_hdr, fixed) == 0) ? 1 : 0;
            int tail_eq = memcmp(g_wire + fixed, expect_tail, g_wire_len - fixed) == 0 ? 1 : 0;
            int len_eq = (g_wire_len == dl3) ? 1 : 0;

            char hex[24 * 2 + 1];
            for (int i = 0; i < 24; ++i)
                std::snprintf(hex + i * 2, 3, "%02X", (unsigned char)g_wire[i]);
            hex[48] = '\0';
            std::printf("S3_ok ret=%d len_out=%u data_len=%u hdr_eq=%d tail_eq=%d "
                "tail_off=%zu hdr_bytes=%s\n",
                r3, g_wire_len, dl3, hdr_eq, tail_eq, fixed, hex);
            // R7: g_wire stays alive for the D arms; deleted there.
        }
    }

    // ================= D: deserialize_file_event arms (cc:63-:75) =======
    {
        // NOTE (R5, documented not vectored): only null/len==0 are rejected
        // (cc:65-:66); a 0<len<fixed_len buffer feeds the header memcpy
        // walk an OOB read (file_events.h:85-:100). UB, not oracle.

        // D1: null buffer, nonzero len -> false; out-event untouched
        {
            DataEvent* out1 = nullptr;
            int r1 = deserialize_file_event(nullptr, 64, out1) ? 1 : 0;
            std::printf("D1_nullbuf ret=%d event_untouched=%d\n", r1, out1 ? 0 : 1);
        }
        // D2: valid buffer, len 0 -> false
        {
            DataEvent* out2 = nullptr;
            int r2 = deserialize_file_event(g_wire, 0, out2) ? 1 : 0;
            std::printf("D2_zerolen ret=%d event_untouched=%d\n", r2, out2 ? 0 : 1);
        }
        // D3 + D4: S3's wire buffer -> true; every field round-trips
        // (file_events.h:82-:104); then the caller frees BOTH heap
        // halves (cc:54 buffer, cc:68 event).
        {
            DataEvent* out3 = nullptr;
            int r3 = deserialize_file_event(g_wire, g_wire_len, out3) ? 1 : 0;
            FileMPEvent* ev3 = static_cast<FileMPEvent*>(out3);   // ours by cc:73
            int nonnull = ev3 ? 1 : 0;
            int tm_eq = nonnull && ev3->get_timeout() == 3000001234 ? 1 : 0;
            FileHashKey k3 = mkkey(503);
            k3.sgroup = 7; k3.dgroup = 9;
            int key_eq = nonnull && memcmp(&ev3->get_hashkey(), &k3, sizeof k3) == 0 ? 1 : 0;
            const FileInfo& fc = ev3->get_file_ctx();
            int verdict_eq = nonnull && fc.verdict == FILE_VERDICT_BLOCK ? 1 : 0;
            std::string nm = nonnull ? fc.get_file_name() : std::string();
            int name_eq = nm == "s3_shared.exe" ? 1 : 0;
            int url_eq = fc.get_url() == "/share/s3" ? 1 : 0;
            int sha_eq = nonnull && fc.sha256 && memcmp(fc.sha256, g_sha, 32) == 0 ? 1 : 0;
            int size_eq = nonnull && fc.get_file_size() == 2048 ? 1 : 0;
            // D4: deserialize records the RAW wire len (file_events.h:103),
            // not a recomputed fixed+file_size (risk R8 pin).
            int d4 = nonnull && ev3->get_data_len() == g_wire_len ? 1 : 0;
            std::printf("D3_roundtrip ret=%d nonnull=%d timeout_eq=%d key_eq=%d "
                "verdict_eq=%d name_eq=%d url_eq=%d sha_eq=%d file_size_eq=%d\n",
                r3, nonnull, tm_eq, key_eq, verdict_eq, name_eq, url_eq, sha_eq, size_eq);
            std::printf("D4_lenrec wire_len=%u data_len=%u len_rec_eq=%d\n",
                g_wire_len, ev3 ? ev3->get_data_len() : 0, d4);
            delete[] g_wire;
            g_wire = nullptr;
            delete ev3;
            std::printf("S_D_ownership buf_freed=1 event_freed=1 leak_delta=0 "
                "(caller frees cc:54 buffer + cc:68 event)\n");
        }
    }

    // ================= H: FileCacheShare::handle (cc:30-:42) ============
    {
        FileCacheShare fcs;

        // H1: FileService::file_cache null (default zero-init, file_service
        // .h:109) -> the cc:38 guard returns; no crash, no cache touched.
        {
            FileService::file_cache = nullptr;
            FileHashKey k1 = mkkey(601);
            FileInfo fi1; fi1.verdict = FILE_VERDICT_BLOCK;
            fi1.set_file_name("h1.bin", 6);
            FileMPEvent ev1(k1, 3600, fi1);            // stack, drive-shape
            fcs.handle(ev1, nullptr);
            int cache_null = FileService::get_file_cache() ? 0 : 1;
            std::printf("H1_nocache handled=1 cache_null=1 guard_hit=%d\n", cache_null);
        }

        // H2 + H3 + H4 + H_xattr against ONE real FileCache.
        {
            FileCache cache(16);
            FileService::file_cache = &cache;          // real static seam
            bool cf = false; int64_t ce = 0;

            // H2: copy-then-store + copy-not-alias (cc:35 value copy, deep
            // FileInfo copy ctor file_lib.cc:326).
            FileHashKey k2 = mkkey(702);
            FileInfo fi2;
            fi2.verdict = FILE_VERDICT_BLOCK;
            fi2.set_file_name("h2.bin", 6);
            fi2.set_file_id(702);
            fi2.sha256 = new uint8_t[32];              // deep-copied twice:
            memcpy(fi2.sha256, g_sha, 32);             // event member + cc:35
            fi2.is_sha256_set = true;
            FileMPEvent ev2(k2, 3600, fi2);
            fcs.handle(ev2, nullptr);
            FileContext* node = cache_add(cache, k2, 3600, cf, ce);
            int node_hit = node ? 1 : 0;
            int v2 = node ? (int)node->verdict : -1;
            // snapshot into a sized std::string BEFORE any later printf
            std::string n2 = node ? node->get_file_name() : std::string();
            size_t n2_len = n2.size();
            long long ent = cache.get_num_entries();
            // mutate the EVENT AFTER the call -> cache node must not move
            ev2.file_ctx.verdict = FILE_VERDICT_UNKNOWN;
            ev2.file_ctx.set_file_name("MUT.exe", 7);
            FileContext* node2 = cache_add(cache, k2, 3600, cf, ce);
            int alias = (node2 && node2->verdict == FILE_VERDICT_BLOCK
                && node2->get_file_name() == "h2.bin") ? 0 : 1;
            std::printf("H2_copy_then_store node_hit=%d verdict=%d name_len=%zu name=%s "
                "entries=%lld copy_not_alias=%d\n",
                node_hit, v2, n2_len, n2.c_str(), ent, 1 - alias);

            // H3: cached terminal BLOCK, incoming UNKNOWN -> gated
            // (verdict_publish_blocked + cached_condemned&&!incoming, file
            // _cache.cc:519-:524 reached through real store_shared_verdict).
            {
                FileInfo fi3; fi3.verdict = FILE_VERDICT_UNKNOWN;
                fi3.set_file_name("h3.bin", 6);
                FileMPEvent ev3(k2, 3600, fi3);
                fcs.handle(ev3, nullptr);
                FileContext* n = cache_add(cache, k2, 3600, cf, ce);
                int v = n ? (int)n->verdict : -1;
                std::string nm = n ? n->get_file_name() : std::string();
                int kept = (v == (int)FILE_VERDICT_BLOCK && nm == "h2.bin") ? 1 : 0;
                std::printf("H3_blocked verdict=%d name=%s node_unchanged=%d\n",
                    v, nm.c_str(), kept);
            }
            // H4: BLOCK -> BLOCK not gated (incoming terminal) -> the
            // *((FileInfo*)node) = src assignment fires (file_cache.cc:526).
            {
                FileInfo fi4; fi4.verdict = FILE_VERDICT_BLOCK;
                fi4.set_file_name("h4.bin", 6);
                fi4.set_file_size(77);
                FileMPEvent ev4(k2, 3600, fi4);
                fcs.handle(ev4, nullptr);
                FileContext* n = cache_add(cache, k2, 3600, cf, ce);
                int v = n ? (int)n->verdict : -1;
                std::string nm = n ? n->get_file_name() : std::string();
                long long fs = n ? (long long)n->get_file_size() : -1;
                std::printf("H4_blocked2 verdict=%d name=%s file_size=%lld copy_fired=%d\n",
                    v, nm.c_str(), fs, (nm == "h4.bin") ? 1 : 0);
            }

            // H_xattr: expired node recovery (is_node_recovery_ok,
            // file_cache.cc:68-:86): timeout 1s, jump +5s, re-handle the
            // same key -> fresh node, no recovery failure. PIN: handle
            // forwards the WIRE key verbatim (cc:34, risk R1).
            {
                FileHashKey kx = mkkey(900);
                FileInfo fix_; fix_.verdict = FILE_VERDICT_LOG;
                fix_.set_file_name("orig.bin", 8);
                FileMPEvent evx(kx, 1, fix_);          // expire = now+1s
                fcs.handle(evx, nullptr);
                long long ent1 = cache.get_num_entries();
                pkt_now(1000010, 0);                   // clock jump past expiry
                FileInfo fir; fir.verdict = FILE_VERDICT_LOG;
                fir.set_file_name("recover.bin", 11);   // exact strlen
                FileMPEvent evr(kx, 3600, fir);        // SAME wire key
                fcs.handle(evr, nullptr);
                FileContext* n = cache_add(cache, kx, 3600, cf, ce);
                int v = n ? (int)n->verdict : -1;
                std::string nm = n ? n->get_file_name() : std::string();
                long long ent2 = cache.get_num_entries();
                std::printf("H_xattr entries_after_first=%lld entries_after=%lld "
                    "verdict=%d name=%s recovered=%d\n",
                    ent1, ent2, v, nm.c_str(),
                    (n && nm == "recover.bin") ? 1 : 0);
            }
            FileService::file_cache = nullptr;
        }   // ~FileCache -> ~ExpectedFileCache delete_hash_table walk
    }

    // =========== X: clear()/dtor interplay (file_events.h:132 by-value) =
    {
        // X1: handle -> clear() -> handle same key = fresh node, no UAF
        {
            FileCache cache(16);
            FileService::file_cache = &cache;
            FileHashKey kx = mkkey(950);
            FileInfo fi; fi.verdict = FILE_VERDICT_BLOCK;
            fi.set_file_name("x1.bin", 6);
            FileMPEvent ev(kx, 3600, fi);              // stack event survives
            { FileCacheShare h; h.handle(ev, nullptr); }
            FileCacheClearReport rep = FileService::get_file_cache()->clear();
            long long ent_mid = FileService::get_file_cache()->get_num_entries();
            { FileCacheShare h; h.handle(ev, nullptr); }   // same key again
            bool cf = false; int64_t ce = 0;
            FileContext* n = cache_add(cache, kx, 3600, cf, ce);
            int v = n ? (int)n->verdict : -1;
            std::string nm = n ? n->get_file_name() : std::string();
            std::printf("X1_handle_after_clear freed=%lld remaining=%lld "
                "entries_after_clear=%lld entries_after=%lld verdict=%d name=%s "
                "fresh_node=%d\n",
                (long long)rep.freed, (long long)rep.remaining, ent_mid,
                (long long)cache.get_num_entries(), v, nm.c_str(),
                (v == (int)FILE_VERDICT_BLOCK) ? 1 : 0);
            FileService::file_cache = nullptr;
        }   // ~FileCache

        // X2: cache dtor while the EVENT holder is still alive: the event
        // owns a BY-VALUE FileInfo (file_events.h:132) deep-copied at ctor
        // and again at cc:35 — nothing of the cache can dangle through it
        // (the safe half of risk R3). Allocation order: event X1 before the
        // cache (donor F-lifecycle pattern).
        {
            FileHashKey k2 = mkkey(960);
            FileInfo fi; fi.verdict = FILE_VERDICT_REJECT;
            fi.set_file_name("x2_hold.bin", 11);
            fi.set_file_size(5);
            FileMPEvent* evY = new FileMPEvent(k2, 3600, fi);   // BEFORE cache
            {
                FileCache cache(16);
                FileService::file_cache = &cache;
                { FileCacheShare h; h.handle(*evY, nullptr); }
                long long ent = cache.get_num_entries();
                FileService::file_cache = nullptr;
                std::printf("X2_enter entries=%d\n", (int)ent);
            }   // ~FileCache walks + frees every node's FileContext
            int alive_verdict = (int)evY->get_file_ctx().verdict;
            std::string nm = evY->get_file_ctx().get_file_name();
            long long fs = (long long)evY->get_file_ctx().get_file_size();
            std::printf("X2_dtor_with_live_event event_verdict=%d event_name=%s "
                "event_file_size=%lld event_owns_copy=%d\n",
                alive_verdict, nm.c_str(), fs,
                nm == "x2_hold.bin" ? 1 : 0);
            delete evY;
            std::printf("X2_ownership event_freed=1 leak_delta=0\n");
        }
    }

    std::printf("FCSHARE_PROBE_DONE\n");
    return 0;
}
