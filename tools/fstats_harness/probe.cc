// Probe for file_api/file_stats.cc compiled by INCLUDING it VERBATIM
// (same trick as the upstream gate suite: gives access to the
// file-statics file_totals and pins production bodies of the
// thread-local plumbing). Witnesses follow the upstream test's own
// witness style (file_type_name, FileCapture/FileService statics).
// Everything printed is deterministic: fixed seeds, no clock/random.
#include "file_api/file_capture.h"
#include "file_api/file_cache.h"
#include "file_api/file_service.h"
#include "utils/stats/snapshot.h"

#include <cstdio>

// ---- witnesses (mirroring upstream file_stats_test.cc style) ----
static bool name_file_type = false;
static bool name_zero_file_type = false;
static bool name_last_file_type = false;
static bool use_file_cache = false;
static uint64_t file_cache_entries = 0;
static bool use_capture_counter = false;
static uint64_t capture_mem_bytes = 0;

std::string file_type_name(uint32_t id)
{
    if (name_file_type && id == 1)
        return "TEST";
    if (name_zero_file_type && id == 2)
        return "ZERO";
    if (name_last_file_type && id == FILE_ID_MAX)
        return "LAST";
    return "";
}

namespace snort
{
bool FileService::file_signature_enabled = false;
FileCache* FileService::file_cache = nullptr;

int64_t FileCapture::get_buffers_max()
{ return 41; }

int64_t FileCapture::get_buffers_in_use()
{ return 7; }

void FileCapture::collect_mem_usage(stats::Builder& builder, stats::Group& group)
{
    if (use_capture_counter)
        builder.counter(group, "Capture memcap", capture_mem_bytes);
}

void FileService::collect_cache_usage(stats::Builder& builder, stats::Group& group)
{
    if (use_file_cache)
        builder.counter(group, "File cache entries", file_cache_entries);
}
} // namespace snort

#include "file_api/file_stats.cc"

// ---- dump helpers ----
static std::string vstr(const snort::stats::Value& v)
{
    if (std::holds_alternative<std::monostate>(v)) return "x";
    if (std::holds_alternative<bool>(v)) return std::get<bool>(v) ? "b1" : "b0";
    if (std::holds_alternative<int64_t>(v)) return "i:" + std::to_string(std::get<int64_t>(v));
    if (std::holds_alternative<uint64_t>(v)) return "n:" + std::to_string(std::get<uint64_t>(v));
    if (std::holds_alternative<double>(v)) return "d:" + std::to_string(std::get<double>(v));
    return "s:" + std::get<std::string>(v);
}

static void dump_snapshot(const snort::stats::Snapshot& s)
{
    printf("SECCTIONS=%zu\n", s.sections.size());
    for (const auto& sec : s.sections) {
        printf("SEC %s ng=%zu\n", sec.name.c_str(), sec.groups.size());
        for (const auto& g : sec.groups) {
            printf(" GRP %s nc=%zu nt=%zu\n", g.name.c_str(), g.counters.size(), g.tables.size());
            for (const auto& c : g.counters)
                printf("  CTR %s=%s\n", c.get_name(), vstr(c.value).c_str());
            for (const auto& t : g.tables) {
                printf("  TBL %s %zu fc=%d\n", t.name.c_str(), t.columns.size(), (int)t.first_column_has_colon);
                for (const auto& col : t.columns)
                    printf("   COL %s\n", col.c_str());
                for (const auto& row : t.rows) {
                    printf("   ROW");
                    for (const auto& cell : row)
                        printf(" %s", vstr(cell).c_str());
                    printf("\n");
                }
            }
        }
    }
}

static void reset_witnesses()
{
    name_file_type = name_zero_file_type = name_last_file_type = false;
    use_file_cache = use_capture_counter = false;
    file_cache_entries = capture_mem_bytes = 0;
    snort::FileService::file_signature_enabled = false;
}

// flat-layout pins: FileStats is all-PegCount; file_stats_sum walks it
// as one flat array of sizeof()/8 slots.
static const unsigned NFLAT = sizeof(file_totals) / sizeof(PegCount);
static uint64_t flatsum(const PegCount* p)
{
    uint64_t s = 0;
    for (unsigned i = 0; i < NFLAT; ++i) s += p[i];
    return s;
}

int main()
{
    printf("LAYOUT nfl=%u nfc=%u\n", NFLAT,
        (unsigned)(sizeof(file_counts) / sizeof(PegCount)));

    // Z0: everything empty -> collect bails, no section at all.
    reset_witnesses();
    file_stats_clear();
    { snort::stats::Snapshot s; snort::stats::Builder b(s);
      snort::stats::DynamicStatsPolicy p; file_stats_collect(b, p);
      dump_snapshot(s); }

    // Z1: no file rows but a cache counter -> section kept.
    reset_witnesses(); use_capture_counter = true; capture_mem_bytes = 99;
    use_file_cache = true; file_cache_entries = 5;
    { snort::stats::Snapshot s; snort::stats::Builder b(s);
      snort::stats::DynamicStatsPolicy p; file_stats_collect(b, p);
      dump_snapshot(s); }

    // S1: named row 1; unnamed nonzero rows 40; out-of-render index
    // 1024 (inside array, past loop bound). sigs off.
    reset_witnesses(); name_file_type = true; name_last_file_type = true;
    file_stats_clear();
    file_totals.files_processed[1][0] = 2;   file_totals.files_processed[1][1] = 3;
    file_totals.data_processed[1][0] = 20;   file_totals.data_processed[1][1] = 30;
    file_totals.files_processed[40][1] = 11;             // unnamed: sees gate, no row
    file_totals.files_processed[FILE_ID_MAX][0] = 4;     // index past every loop
    printf("FLATSUM1=%llu\n", (unsigned long long)flatsum(reinterpret_cast<PegCount*>(&file_totals)));
    { snort::stats::Snapshot s; snort::stats::Builder b(s);
      snort::stats::DynamicStatsPolicy p; file_stats_collect(b, p);
      dump_snapshot(s); }

    // S2: signatures enabled + total>0 -> 7-col shape; sig on named row
    // plus sig on unnamed row (in check_sum, never in Total).
    reset_witnesses(); name_file_type = true;
    snort::FileService::file_signature_enabled = true;
    file_totals.signatures_processed[1][0] = 9;
    file_totals.signatures_processed[5][0] = 7;
    { snort::stats::Snapshot s; snort::stats::Builder b(s);
      snort::stats::DynamicStatsPolicy p; file_stats_collect(b, p);
      dump_snapshot(s); }

    // S3: include_zeros -> ZERO(2) row (named, all-zero) joins the table.
    reset_witnesses(); name_file_type = true; name_zero_file_type = true;
    snort::FileService::file_signature_enabled = true;
    { snort::stats::Snapshot s; snort::stats::Builder b(s);
      snort::stats::DynamicStatsPolicy p; p.include_zeros = true;
      file_stats_collect(b, p);
      dump_snapshot(s); }

    // S4: sigs ENABLED but check_sig_total == 0 -> still 5-col.
    reset_witnesses(); name_file_type = true;
    snort::FileService::file_signature_enabled = true;
    file_stats_clear();
    file_totals.files_processed[1][0] = 1;
    { snort::stats::Snapshot s; snort::stats::Builder b(s);
      snort::stats::DynamicStatsPolicy p; file_stats_collect(b, p);
      dump_snapshot(s); }

    // S6: buffer counters (witness FileCapture statics).
    reset_witnesses();
    file_stats_clear();
    file_counts_update_buffers();
    printf("BUFFERS max=%llu in_use=%llu\n",
        (unsigned long long)file_counts.file_buffers_max,
        (unsigned long long)file_counts.file_buffers_in_use);
    file_stats_clear();
    printf("FLATSUMEND=%llu\n", (unsigned long long)flatsum(reinterpret_cast<PegCount*>(&file_totals)));

    // S5 last: term() frees the heap FileStats but does NOT null the
    // global (upstream semantics). Reading the freed block afterwards
    // is a live use-after-free; the probe only observes the stale
    // POINTER (its null-ness), never its contents.
    file_stats_init();
    printf("INIT notnull=%d\n", (int)(file_stats != nullptr));
    file_stats->files_processed[40][1] = 6;     // unnamed even in totals after sum? id40 stays unnamed
    file_stats->files_processed[1][0] = 8;
    file_stats->data_processed[1][1] = 12;
    file_stats_clear();                         // zeroes counts+totals+thread stats (incl. fresh seeds)
    file_stats->files_processed[1][0] = 5;
    file_stats_sum();
    printf("AFTER_SUM flat_totals=%llu flat_thread=%llu\n",
        (unsigned long long)flatsum(reinterpret_cast<PegCount*>(&file_totals)),
        (unsigned long long)flatsum(reinterpret_cast<PegCount*>(file_stats)));
    file_stats_sum();                           // thread was zeroed: totals unchanged
    printf("AGAIN flat_totals=%llu\n", (unsigned long long)flatsum(reinterpret_cast<PegCount*>(&file_totals)));
    printf("PRETERM notnull=%d\n", (int)(file_stats != nullptr));
    file_stats_term();
    printf("TERM dangling=%d\n", (int)(file_stats != nullptr));
    printf("DONE\n");
    return 0;
}
