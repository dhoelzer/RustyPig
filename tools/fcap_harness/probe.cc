// probe.cc — ground-truth transcript for the async-writer row,
// file_capture.{h,cc} (row 17s). The file_capture TU is compiled WITH
// -DUNIT_TEST keeping the early hook fragments (:45/:65/:100/:112/:197/:203)
// and the UT scaffolding :620-:807 (FileCaptureTestAccess + AsyncWriterGate
// + static gate ptr + hook wrappers + fixture); ONLY the 4 TEST_CASE bodies
// :808-:912 are excised (build.sh FIXCAPUT). The async vectors drive the
// SAME upstream gate ladder through the extern "C" driver build.sh appends
// at the tail of that TU copy (it lives in-TU: the hook pointers + the
// static gate ptr are file-local; PLAN 4/5 — no custom barriers invented).
//
// Determinism: the gate ladder is armed exactly like AsyncCaptureFixture
// (:784-:789, minus the REQUIRE) and released in dtor order (:794-:796:
// release_writer, release_idle_transition, exit()). NEVER exit() while a
// hook is parked (PLAN 9-1). Hookless buffer vectors use the FIXACC-public
// init_mempool/capture_block_size/file_mempool seams (donor pattern) and
// NEVER init() -> no writer thread there.
//
// THREAD_LOCAL pin (PLAN 5/9-2): file_counts is PER-THREAD. The `delete
// file` at :106 bumps the WRITER thread's counts; main's file_counts only
// sees them after file_counts_update_buffers() recomputes
// file_buffers_in_use from the SHARED mempool (file_stats.cc:60). Vectors
// print the main-thread deltas + label the split; the writer-thread TLS is
// not readable cross-thread (recorded deviation; the C++ gate pins the
// truth via released_buffers()).
//
// Hygiene: every side-effecting call hoisted into a local BEFORE printf;
// counts snapshotted before frees; NO pointer values in vectors; no
// 0x[0-9a-f]{6,} anywhere (shas print as uppercase hex, no 0x prefix); the
// disk-writing vector runs inside a self-created scratch subdir that is
// removed again (PLAN 6 disk hygiene).
#include "file_api/file_capture.h"
#include "file_api/file_lib.h"
#include "file_api/file_stats.h"
#include "file_api/file_mempool.h"
#include "utils/stats/snapshot.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <variant>
#include <thread>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

using namespace snort;

// ---- build.sh-appended in-TU driver (file_capture_probe.cc tail) ----
extern "C" void fcap_gate_arm_new(void);          // fresh gate + 4 hooks
extern "C" void fcap_gate_unarm(void);            // hooks nullptr + gate gone
extern "C" void fcap_init(int64_t memcap, int64_t block);
extern "C" void fcap_exit(void);
extern "C" void fcap_test_reset(void);
extern "C" int  fcap_resettable(void);
extern "C" void fcap_enqueue(void* c);
extern "C" void fcap_enqueue2(void* a, void* b);
extern "C" uint64_t fcap_released_buffers(void);
extern "C" int  fcap_queue_size(void);
extern "C" int  fcap_file_storing_now(void);
extern "C" void fcap_drain_hookless(void);
extern "C" void fcap_gate_wait_writer(void);
extern "C" void fcap_gate_release_writer(void);
extern "C" void fcap_gate_wait_flush_callers(unsigned n);
extern "C" void fcap_gate_pause_first_idle(void);
extern "C" void fcap_gate_wait_first_idle(void);
extern "C" void fcap_gate_wait_nonempty_idle_eval(void);
extern "C" void fcap_gate_release_idle(void);

// ---- helpers ---------------------------------------------------------------
static FileCounts g_counts_snap;
static void snap_counts(void) { g_counts_snap = file_counts; }
static unsigned long long dc(PegCount now, PegCount before)
{ return (unsigned long long)(now - before); }

static std::string value_str(const stats::Value& v)
{
    if (const int64_t* p = std::get_if<int64_t>(&v)) return std::to_string(*p);
    if (const uint64_t* p = std::get_if<uint64_t>(&v)) return std::to_string(*p);
    if (const bool* p = std::get_if<bool>(&v)) return *p ? "true" : "false";
    return "nonint";
}

static int count_dir_entries(const char* dir)
{
    DIR* d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    while (dirent* e = readdir(d))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) ++n;
    closedir(d);
    return n;
}

// walk every block through the REAL get_file_data (:471-:486); returns
// block count, sums lengths, pins first/last byte.
static int walk_capture(FileCapture& fc, int64_t& len_sum, int& first, int& last)
{
    int blocks = 0;
    len_sum = 0;
    first = -1;
    last = -1;
    uint8_t* buff = nullptr;
    int size = 0;
    while (true) {
        FileCaptureBlock* nxt = fc.get_file_data(&buff, &size);   // snapshot BEFORE use
        int64_t len = size;
        int fb = buff && size > 0 ? buff[0] : -1;
        int lb = buff && size > 0 ? buff[size - 1] : -1;
        if (!buff || size == 0) break;
        ++blocks;
        len_sum += len;
        if (blocks == 1) first = fb;
        last = lb;
        if (!nxt) break;   // :485 returns the NEXT block; nullptr = done
    }
    return blocks;
}

static const uint8_t g_sha[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20 };

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    // ---- V-CONST layout constants (PLAN 9-3: probe-printed, never mental) --
    FileCapture probe_obj(0, 0);
    (void)probe_obj;
    unsigned long long sz_fc   = sizeof probe_obj;          // :220 slot math
    unsigned long long sz_blk  = sizeof(FileCaptureBlock);  // :294/:481 payload math
    unsigned long long slot64  = 64 + sz_fc;
    if (slot64 & 7) slot64 += 8 - (slot64 & 7);             // :228-:229
    std::printf("CONST sizeof_FileCapture=%llu sizeof_FileCaptureBlock=%llu slot_block64=%llu\n",
        sz_fc, sz_blk, slot64);

    // ---- V-A gate-case-A mirror, hookless: no mempool -> MEMCAP (:384-387) --
    {
        FileCapture fc(0, 0);
        FileCaptureState st = fc.process_buffer((const uint8_t*)"dummy", 5, SNORT_FILE_START);
        std::printf("A_nomempool_state=%d (MEMCAP=%d)\n", (int)st, (int)FILE_CAPTURE_MEMCAP);
    }
    std::printf("A_flush_no_pending_returns=1\n");
    FileCapture::flush();   // mirrors case B :817 — bare flush, no writer, predicate true

    // ---- V-B hookless buffer ladder (init_mempool seam, NO init()/thread) --
    {
        FileCapture::file_mempool = nullptr;
        FileCapture::capture_block_size = 64;
        FileCapture::init_mempool(1, 64);   // :218-:234 real math
        int64_t maxb = FileCapture::get_buffers_max();
        int64_t inu0 = FileCapture::get_buffers_in_use();
        std::printf("B_memcap1mb_block64 buffers_max=%lld buffers_in_use=%lld\n",
            (long long)maxb, (long long)inu0);

        snap_counts();
        // SNORT_FILE_FULL: counts-only path (:369-:371)
        {
            FileCapture fc(0, 100000);
            FileCaptureState st = fc.process_buffer((const uint8_t*)"x", 1, SNORT_FILE_FULL);
            std::printf("B_full st=%d within_packet_d=%llu\n",
                (int)st, dc(file_counts.file_within_packet, g_counts_snap.file_within_packet));
        }
        // SNORT_FILE_END: no buffer, SUCCESS (:372-:373)
        snap_counts();
        {
            FileCapture fc(0, 100000);
            FileCaptureState st = fc.process_buffer((const uint8_t*)"x", 1, SNORT_FILE_END);
            std::printf("B_end st=%d buffered_d=%llu\n",
                (int)st, dc(file_counts.files_buffered_total, g_counts_snap.files_buffered_total));
        }
        // START multi-block split: 150 B over 64 B blocks = 64+64+22 (:287-:331)
        snap_counts();
        static uint8_t data150[150];
        for (int i = 0; i < 150; ++i) data150[i] = (uint8_t)(i & 0x7f);
        int64_t sz_sum = 0; int fb = -1, lb = -1;
        {
            FileCapture fc(0, 100000);
            FileCaptureState st = fc.process_buffer(data150, 150, SNORT_FILE_START);
            FileInfo fi;
            fi.set_file_size(150);
            FileCaptureState rst = fc.reserve_file(&fi);   // :399-:458 -> SUCCESS
            int blocks = walk_capture(fc, sz_sum, fb, lb);
            std::printf("B_split st=%d rst=%d blocks=%d len_sum=%lld first=%d last=%d capsize=%lld "
                "buffered_d=%llu alloc_d=%llu used_max=%llu in_use=%lld\n",
                (int)st, (int)rst, blocks, (long long)sz_sum, fb, lb,
                (long long)fc.get_file_capture_size(),
                dc(file_counts.files_buffered_total, g_counts_snap.files_buffered_total),
                dc(file_counts.file_buffers_allocated_total, g_counts_snap.file_buffers_allocated_total),
                (unsigned long long)file_counts.file_buffers_used_max,
                (long long)FileCapture::get_buffers_in_use());
            // get_file_reset re-walk (:112 seam -> current_block=head)
            fc.get_file_reset();
            int64_t sz2 = 0; int f2 = -1, l2 = -1;
            int blocks2 = walk_capture(fc, sz2, f2, l2);
            std::printf("B_reset_walk blocks=%d len_sum=%lld first=%d last=%d\n",
                blocks2, (long long)sz2, f2, l2);
            // nameless FileInfo -> store_file fopen("", "wx") fails fast,
            // NO disk write and NO ErrorMessage (PLAN 7 :536-:540 pin)
            fc.store_file();
            std::printf("B_store_nameless_noop=1\n");
            // dtor path: file_info set -> m_release + files_released (:143-:147)
        }
        std::printf("B_dtor files_released_d=%llu bufs_released_d=%llu in_use_after=%lld\n",
            dc(file_counts.files_released_total, g_counts_snap.files_released_total),
            dc(file_counts.file_buffers_released_total, g_counts_snap.file_buffers_released_total),
            (long long)FileCapture::get_buffers_in_use());

        // max-size arm: 150 > max 100 -> FILE_CAPTURE_MAX (:277-:281)
        snap_counts();
        {
            FileCapture fc(0, 100);
            FileCaptureState st = fc.process_buffer(data150, 150, SNORT_FILE_START);
            FileInfo fi;
            fi.set_file_size(30);
            FileCaptureState rst = fc.reserve_file(&fi);  // capture_state != SUCCESS
            std::printf("B_max st=%d rst=%d(MAX=%d) size_max_d=%llu reserve_fail_d=%llu\n",
                (int)st, (int)rst, (int)FILE_CAPTURE_MAX,
                dc(file_counts.file_size_max, g_counts_snap.file_size_max),
                dc(file_counts.file_reserve_failures, g_counts_snap.file_reserve_failures));
        }
        // error_capture direct (:72-:76)
        snap_counts();
        {
            FileCaptureState st = FileCapture::error_capture(FILE_CAPTURE_MIN);
            std::printf("B_errcap st=%d(MIN=%d) reserve_fail_d=%llu\n",
                (int)st, (int)FILE_CAPTURE_MIN,
                dc(file_counts.file_reserve_failures, g_counts_snap.file_reserve_failures));
        }
        // reserve min/max arms on a SUCCESS capture (:415-:425)
        {
            FileCapture fc(10, 20);
            static uint8_t d12[12] = { 1 };
            fc.process_buffer(d12, 12, SNORT_FILE_START);
            fc.set_data(d12, 12);
            FileInfo small; small.set_file_size(3);
            FileCaptureState st_min = fc.reserve_file(&small);
            FileCapture fc2(10, 20);
            fc2.process_buffer(d12, 12, SNORT_FILE_START);
            fc2.set_data(d12, 12);
            FileInfo big; big.set_file_size(99);
            FileCaptureState st_max = fc2.reserve_file(&big);
            std::printf("B_reserve_arms min=%d(MIN=%d) max=%d(MAX=%d)\n",
                (int)st_min, (int)FILE_CAPTURE_MIN, (int)st_max, (int)FILE_CAPTURE_MAX);
        }

        // ---- V-C collect_mem_usage (real header-only Builder, :595-:599) --
        {
            stats::Snapshot snapshot;
            stats::Builder builder(snapshot);
            stats::Section& section = builder.section("fcap");
            stats::Group& group = stats::Builder::group(section, "file capture");
            FileCapture::collect_mem_usage(builder, group);
            std::printf("C_counters n=%zu", group.counters.size());
            for (auto& ctr : group.counters)
                std::printf(" | %s=%s", ctr.get_name(), value_str(ctr.value).c_str());
            std::printf("\n");
        }

        // ---- V-D memcap exhaustion: pool sized for 2 slots -> MEMCAP arm --
        {
            delete FileCapture::file_mempool;
            FileCapture::file_mempool = new FileMemPool(2, (int64_t)slot64);
            FileCapture::capture_block_size = 64;
            snap_counts();
            static uint8_t data200[200];
            for (int i = 0; i < 200; ++i) data200[i] = (uint8_t)i;
            {
                FileCapture fc(0, 100000);
                FileCaptureState st = fc.process_buffer(data200, 200, SNORT_FILE_START);
                std::printf("D_exhaust st=%d(MEMCAP=%d) memcap_fail_d=%llu in_use=%lld\n",
                    (int)st, (int)FILE_CAPTURE_MEMCAP,
                    dc(file_counts.file_memcap_failures_total, g_counts_snap.file_memcap_failures_total),
                    (long long)FileCapture::get_buffers_in_use());
                // dtor with head set but file_info null -> m_free + freed_total
                // (:151-:153) — fc dtors at scope end; snapshot BEFORE scope close:
            }
            std::printf("D_exhaust bufs_freed_d=%llu in_use_after=%lld\n",
                dc(file_counts.file_buffers_freed_total, g_counts_snap.file_buffers_freed_total),
                (long long)FileCapture::get_buffers_in_use());
            // reserve-file memcap arm with empty head (:430-:437); fc MUST
            // dtor (m_free back into the pool) BEFORE the pool is deleted.
            {
                snap_counts();
                {
                    FileCapture fc(0, 100000);
                    fc.set_data(data200, 200);
                    FileInfo fi; fi.set_file_size(1);
                    FileCaptureState rst = fc.reserve_file(&fi);
                    std::printf("D_reserve_memcap rst=%d(MEMCAP=%d) fail_reserve_d=%llu memcap_total_d=%llu in_use=%lld\n",
                        (int)rst, (int)FILE_CAPTURE_MEMCAP,
                        dc(file_counts.file_memcap_failures_reserve, g_counts_snap.file_memcap_failures_reserve),
                        dc(file_counts.file_memcap_failures_total, g_counts_snap.file_memcap_failures_total),
                        (long long)FileCapture::get_buffers_in_use());
                    // dtor here: file_info null -> m_free arms (:151-:153)
                }
                std::printf("D_reserve_dtored in_use=%lld bufs_freed_d=%llu\n",
                    (long long)FileCapture::get_buffers_in_use(),
                    dc(file_counts.file_buffers_freed_total, g_counts_snap.file_buffers_freed_total));
            }
            delete FileCapture::file_mempool;
            FileCapture::file_mempool = nullptr;
            FileCapture::capture_block_size = 0;
        }
    }

    // ---- V-E hookless async enqueue via TestAccess seam + hookless drain --
    {
        FileCapture::capture_block_size = 0;
        fcap_test_reset();                        // scaffold reset (:631-:639)
        std::printf("E_resettable=%d\n", fcap_resettable());
        FileCapture::init_mempool(1, 64);
        FileCapture::capture_block_size = 64;     // reset zeroed it; save math needs it
        {
            auto* fc = new FileCapture(0, 128);
            static uint8_t d4[4] = { 1, 2, 3, 4 };
            fc->process_buffer(d4, 4, SNORT_FILE_START);
            FileInfo fi; fi.set_file_size(4);
            fc->reserve_file(&fi);                // file_info set (nameless)
            fcap_enqueue(fc);
            int qs = fcap_queue_size();
            fcap_drain_hookless();                // store_file nameless -> no-op (:536)
            std::printf("E_hookless_drain q_before=%d q_after=%d in_use=%lld\n",
                qs, fcap_queue_size(), (long long)FileCapture::get_buffers_in_use());
        }
        fcap_test_reset();
    }

    // ---- V-F real async ladder, gate-armed (case C mirror) ---------------
    {
        fcap_gate_arm_new();
        fcap_init(1, 64);                         // init :166-:172 REAL spawn
        snap_counts();
        auto* cap = new FileCapture(0, 128);
        static uint8_t d4[4] = { 9, 8, 7, 6 };
        cap->process_buffer(d4, 4, SNORT_FILE_START);
        FileInfo fi; fi.set_file_size(4);
        FileCaptureState rst = cap->reserve_file(&fi);
        int64_t inuse1 = FileCapture::get_buffers_in_use();
        fcap_enqueue(cap);
        fcap_gate_wait_writer();                  // :101 hook parks AFTER pop
        int storing = fcap_file_storing_now();
        std::atomic<unsigned> done = 0;
        std::thread t1([&]{ FileCapture::flush(); ++done; });
        std::thread t2([&]{ FileCapture::flush(); ++done; });
        fcap_gate_wait_flush_callers(2);          // :198 hook, both callers in
        unsigned mid = done.load();
        int64_t inuse_mid = FileCapture::get_buffers_in_use();
        fcap_gate_release_writer();               // writer: store->delete->idle
        t1.join();
        t2.join();
        unsigned after = done.load();
        file_counts_update_buffers();             // :858 pattern, MAIN thread
        std::printf("F_ladder rst=%d inuse1=%lld storing_when_parked=%d done_mid=%u "
            "done_after=%u inuse_mid=%lld update_inuse=%llu inuse_after=%lld released=%llu\n",
            (int)rst, (long long)inuse1, storing, mid, after, (long long)inuse_mid,
            (unsigned long long)file_counts.file_buffers_in_use,
            (long long)FileCapture::get_buffers_in_use(),
            (unsigned long long)fcap_released_buffers());
        // THREAD_LOCAL split pin: the writer thread's delete (:106) never hit
        // MAIN's file_counts TLS:
        std::printf("F_tls_split main_files_released_d=%llu (writer-thread TLS invisible, deviation)\n",
            dc(file_counts.files_released_total, g_counts_snap.files_released_total));
        fcap_gate_release_writer();               // dtor-order safety, idempotent
        fcap_gate_release_idle();
        fcap_exit();                              // join :188 — NEVER with parked hooks
        fcap_gate_unarm();
        fcap_test_reset();
    }

    // ---- V-G queued-capture ladder (case D mirror: two captures) ---------
    {
        fcap_gate_arm_new();
        fcap_init(1, 64);
        auto* c1 = new FileCapture(0, 128);
        auto* c2 = new FileCapture(0, 128);
        static uint8_t a1[1] = { 0x21 }, a2[1] = { 0x22 };
        c1->process_buffer(a1, 1, SNORT_FILE_START);
        c2->process_buffer(a2, 1, SNORT_FILE_START);
        FileInfo f1; f1.set_file_size(1);
        FileInfo f2; f2.set_file_size(1);
        int r1 = (int)c1->reserve_file(&f1), r2 = (int)c2->reserve_file(&f2);
        int64_t inuse2 = FileCapture::get_buffers_in_use();
        fcap_enqueue2(c1, c2);
        fcap_gate_wait_writer();
        fcap_gate_pause_first_idle();             // :887
        std::atomic<unsigned> done = 0;
        std::thread th([&]{ FileCapture::flush(); ++done; });
        fcap_gate_wait_flush_callers(1);
        fcap_gate_release_writer();               // first capture processes...
        fcap_gate_wait_first_idle();
        fcap_gate_wait_nonempty_idle_eval();      // :203-:206 hook pinned
        unsigned mid = done.load();
        int64_t inuse_half = FileCapture::get_buffers_in_use();
        fcap_gate_release_idle();                 // queue drains second
        th.join();
        unsigned after = done.load();
        file_counts_update_buffers();
        std::printf("G_queued r1=%d r2=%d inuse2=%lld done_mid=%u done_after=%u inuse_half="
            "%lld update_inuse=%llu inuse_after=%lld released=%llu\n",
            r1, r2, (long long)inuse2, mid, after, (long long)inuse_half,
            (unsigned long long)file_counts.file_buffers_in_use,
            (long long)FileCapture::get_buffers_in_use(),
            (unsigned long long)fcap_released_buffers());
        fcap_gate_release_writer();
        fcap_gate_release_idle();
        fcap_exit();
        fcap_gate_unarm();
        fcap_test_reset();
    }

    // ---- V-H store_file_async full disk path (scratch dir, cleaned) -----
    {
        int made = mkdir("fcap_probe_scratch", 0755);   // fresh relative capture
        if (made != 0 && errno != EEXIST) std::printf("H_mkdir_fail=%d\n", errno);
        char before_cwd[4096];
        if (!getcwd(before_cwd, sizeof before_cwd)) std::printf("H_getcwd_fail\n");
        if (chdir("fcap_probe_scratch") != 0) std::printf("H_chdir_fail\n");

        fcap_gate_arm_new();
        fcap_init(1, 64);
        auto* cap = new FileCapture(0, 128);
        static uint8_t d7[7] = { 'h','a','r','n','e','s','s' };
        cap->process_buffer(d7, 7, SNORT_FILE_START);
        FileInfo fi;
        fi.set_file_size(7);
        fi.sha256 = new uint8_t[32];        // FIXACC flipped protected->public;
        memcpy(fi.sha256, g_sha, 32);       // heap: ~FileInfo does delete[] +
                                            // FileInfo::copy deep-copies (no double free)
        fi.is_sha256_set = true;            // get_file_sig_sha256 :453 non-null
        cap->reserve_file(&fi);
        std::string ret = cap->store_file_async();  // :564-:584 real; get_instance_file
        std::string expect = fi.sha_to_string(g_sha);   // witness: name = bare sha
        fcap_gate_wait_writer();
        fcap_gate_release_writer();
        fcap_gate_wait_first_idle();
        int entries = count_dir_entries(".");         // snapshot before free
        struct stat sb;
        int have = stat(expect.c_str(), &sb) == 0 ? 1 : 0;
        long long fsize = have ? (long long)sb.st_size : -1;
        std::printf("H_async name_len=%zu name_eq_sha=%d file_present=%d file_size=%lld dir_entries=%d\n",
            ret.size(), ret == expect ? 1 : 0, have, fsize, entries);
        if (have) unlink(expect.c_str());
        fcap_gate_release_writer();
        fcap_gate_release_idle();
        fcap_exit();
        fcap_gate_unarm();
        fcap_test_reset();

        if (chdir(before_cwd) != 0) std::printf("H_chdir_back_fail\n");
        rmdir("fcap_probe_scratch");
    }

    // ---- V-I exit()/reinit lifecycle --------------------------------------
    {
        std::printf("I_resettable_before=%d\n", fcap_resettable());
        fcap_gate_arm_new();
        fcap_init(1, 64);
        fcap_exit();                             // join path :178-:192
        int after_null = fcap_resettable();
        fcap_gate_unarm();
        fcap_test_reset();
        fcap_gate_arm_new();                     // reinit after exit (fixture reuse)
        fcap_init(1, 64);
        fcap_gate_release_writer();
        fcap_gate_release_idle();
        fcap_exit();
        fcap_gate_unarm();
        fcap_test_reset();
        std::printf("I_exit_then_resettable=%d\n", after_null);
    }

    std::printf("FCAP_PROBE_DONE\n");
    return 0;
}
