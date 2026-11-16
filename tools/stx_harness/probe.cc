// Ground-truth probe for utils/stats/output_text.cc + utils.cc (compiled
// VERBATIM). Witnesses for LogLabel/LogText/LogCount/LogStat/MemoryCap
// print each rendered line RAW between <LT>...<LT_END> markers (or the
// label/counter equivalents) so exact padding, tabs, widths and C++
// number formatting pin verbatim into vectors.txt. Every log call is one
// transcript record.
#include <cstdint>
#include <cstdio>
#include <string>

#include "utils/stats/output_text.h"
#include "main/snort_config.h"
#include "memory/memory_cap.h"

using namespace snort;
using namespace snort::stats;

namespace snort
{
uint32_t SnortConfig::logging_flags = 0;

static bool s_set_conn_called = false;
static uint32_t s_set_conn_nulls = 0;

void set_log_conn(ControlConn* c)
{
    s_set_conn_called = true;
    if ( !c )
        ++s_set_conn_nulls;
}

void LogLabel(const char* s, FILE*)
{
    printf("<LL>%s<LL_END>\n", s ? s : "");
}

void LogText(const char* s, FILE*)
{
    printf("<LT>%s<LT_END>\n", s ? s : "");
}

void LogValue(const char*, const char*, FILE*) { printf("<LV>\n"); }

void LogCount(const char* n, uint64_t v, FILE*)
{
    printf("<LC>%s %llu<LC_END>\n", n ? n : "", (unsigned long long)v);
}

void LogStat(const char* n, uint64_t v, uint64_t tot, FILE*)
{
    printf("<LC2>%s %llu/%llu<LC2_END>\n", n ? n : "", (unsigned long long)v,
        (unsigned long long)tot);
}

void LogStat(const char* n, double v, FILE*)
{
    printf("<LD>%s<LD_END>\n", n ? n : "");
    (void)v;
}
}

namespace memory
{
void MemoryCap::print(bool verbose, bool initial)
{
    printf("<MC>verbose=%d initial=%d<MC_END>\n", (int)verbose, (int)initial);
}
}

static void header(const char* name)
{
    printf("CASE %s\n", name);
}

int main()
{
    // S1: Summary Statistics section triggers MemoryCap::print; empty
    // group (no counters, no tables) -> LogLabel(section) only.
    header("S1");
    {
        Snapshot snap;
        auto& sec = snap.sections.emplace_back();
        sec.name = "Summary Statistics";
        render_text(nullptr, snap, RenderOptions{});
    }
    printf("S1 set_conn_called=%d set_conn_nulls=%u\n", (int)s_set_conn_called,
        (unsigned)s_set_conn_nulls);
    s_set_conn_called = false;

    // S2: zero counters (include_zeros) exercise render_zero_counter:
    // padding (setw 25 right), ": ", value, total-percent branch with
    // tab + setw(12) + setw(7) right fixed setprecision(3).
    header("S2");
    {
        Snapshot snap;
        auto& sec = snap.sections.emplace_back();
        sec.name = "Module Statistics";
        auto& grp = sec.groups.emplace_back();
        grp.name = "appid";
        Builder::counter(grp, "packets", (uint64_t)0);
        auto c2 = Counter{};
        c2.set_name("drop%");
        c2.value = (uint64_t)0;
        c2.total = 10;
        grp.counters.push_back(c2);
        auto c3 = Counter{};
        c3.set_name("neg-int");
        c3.value = (int64_t)-5;
        grp.counters.push_back(c3);
        auto c4 = Counter{};
        c4.set_name("-0 double");  // longer than 25? no: 11 chars
        c4.value = -0.0;
        grp.counters.push_back(c4);
        RenderOptions opt;
        opt.include_zeros = true;
        render_text(nullptr, snap, opt);
    }

    // S3: long names (> 25) truncate the first column (resize, verbatim
    // byte semantics); non-zero counters go LogStat/LogCount instead.
    header("S3");
    {
        Snapshot snap;
        auto& sec = snap.sections.emplace_back();
        sec.name = "Other";
        auto& grp = sec.groups.emplace_back();
        grp.name = "long";
        Builder::counter(grp, "name-that-is-definitely-over-twenty-five-chars",
            (uint64_t)7);
        Builder::counter(grp, "with-total", (uint64_t)1);
        grp.counters.back().total = 4;
        // zero counter with include_zeros=false must not render at all
        Builder::counter(grp, "not-shown", (uint64_t)0);
        // has percent but NO total -> percent ignored, plain LogCount
        auto cp = Counter{};
        cp.set_name("pct-only");
        cp.value = (uint64_t)2;
        cp.percent = 33.3;
        grp.counters.push_back(cp);
        render_text(nullptr, snap, RenderOptions{});
    }

    // S4: tables. Header line renders from columns even when first
    // column is empty string; per-row first-column truncation; left
    // setw(10) for later columns; row with one value renders first
    // column only (punct matters).
    header("S4");
    {
        Snapshot snap;
        auto& sec = snap.sections.emplace_back();
        sec.name = "T Sections";
        auto& grp = sec.groups.emplace_back();
        grp.name = "tables";
        auto& t1 = Builder::table(grp, "colon table",
            { "name", "count", "percent" }, true);
        Builder::row(t1, { std::string("row-one"), (uint64_t)12, 33.3 });
        Builder::row(t1, { std::string("x-that-is-over-twenty-five-chars-long"),
            std::string("val"), std::monostate{} });
        Builder::row(t1, { std::string("solo") });
        auto& t2 = Builder::table(grp, "nocolon", { "", "second" }, false);
        Builder::row(t2, { std::string("a"), std::string("bb") });
        // group also has a counter AFTER the tables: order pins tables
        // first, counters second.
        Builder::counter(grp, "tail", (uint64_t)9);
        render_text(nullptr, snap, RenderOptions{});
    }

    // S5: value_as_text variants surface via table first column + the
    // counter u64 conversion (monostate bool true, negative double, big
    // double).
    header("S5");
    {
        Snapshot snap;
        auto& sec = snap.sections.emplace_back();
        sec.name = "V2";
        auto& grp = sec.groups.emplace_back();
        grp.name = "values";
        auto& t =
            Builder::table(grp, "types", { "v" }, true);
        Builder::row(t, { true });
        Builder::row(t, { false });
        Builder::row(t, { (int64_t)-42 });
        Builder::row(t, { 1.25 });
        Builder::row(t, { 1e6 });
        Builder::row(t, { std::monostate{} });
        Builder::row(t, { std::string("active") });
        // monostate-valued counter with include_zeros: u64 0 -> plain "0"
        auto cm = Counter{};
        cm.set_name("mono");
        cm.value = std::monostate{};
        grp.counters.push_back(cm);
        RenderOptions opt;
        opt.include_zeros = true;
        render_text(nullptr, snap, opt);
    }

    // S6: section name compared against SUMMARY_STATS_SECTION exactly
    // ("Summary Statistics " with a trailing space must NOT match).
    header("S6");
    {
        Snapshot snap;
        auto& sec = snap.sections.emplace_back();
        sec.name = "Summary Statistics ";
        render_text(nullptr, snap, RenderOptions{});
    }

    // S7: group with only NON-renderable (zero with include_zeros=false)
    // content -> group entirely skipped, but the section label above is
    // still emitted.
    header("S7");
    {
        Snapshot snap;
        auto& sec = snap.sections.emplace_back();
        sec.name = "S7sec";
        auto& grp = sec.groups.emplace_back();
        grp.name = "skipme";
        Builder::counter(grp, "zeros", (uint64_t)0);
        auto& t = Builder::table(grp, "notable", { "c" }, true);
        (void)t; // table exists but has no rows -> not renderable
        render_text(nullptr, snap, RenderOptions{});
    }

    printf("DONE\n");
    return 0;
}
