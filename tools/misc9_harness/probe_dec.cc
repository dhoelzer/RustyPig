// 19a DEC -- the reload state machine over the REAL ReloadTracker TU + the
// stats ladder over the REAL module.o base (PLAN §8: init_stats new_thread
// true/false :312/:330, sum_stats dump arms :164-:228, reset_stats :339-:358,
// get_global_count name-hit/miss :362-:374; reload_tracker start/end/failed/
// update LogMessage witness ladder, cc :41/:48/:60/:75/:88 MEASURED sed-face
// every build). NO pkth, NO codec, NO daq (graft NON-PARTICIPATION: daq
// grep-0 x4 ground faces), decimal values throughout.
// THE LogMessage OUTPUT face (the +1-vs-+2 spec-correction, PLAN §9): the
// reload ladder's messages PRINT through the CARRIED stubs_18d seam (its
// LogMessage = vprintf body) -- the same first-class printed-stub face as
// the 'EV gid sid' lines the queue_event seam has emitted since 18c: the
// strings ride the ground format literals (sed-pinned in build.sh), the
// seam's trailing putchar('\\n') yields the recorded BLANK-LINE face.
// THE -DNDEBUG law (recorded, NEVER hidden): BOTH row TUs compile -DNDEBUG
// here -- that IS the ground production arm (reload_tracker.cc :54-:57/
// :69-:72/:82-:85 NDEBUG branch = UNUSED(ctrlcon), the shipped face) and it
// keeps module.cc :372 assert(false) -- the get_global_count WRONG-NAME arm,
// :374 return 0 -- OBSERVABLE instead of aborting. The tracker ladder is
// assert-clean BOTH ways (every end/failed/update below has ctrl==ctrlcon
// ==nullptr with reload_in_progress true -- :58/:73/:86 never violated).
// R6 eval-order law: every state call stored to a VAR before any print.
#include "main/reload_tracker.h"
#include "framework/module.h"
#include "framework/counts.h"
#include <cstdio>
using namespace snort;

extern "C" int misc9_prompt_calls();

struct StatsMod : public Module {
    PegCount peg_store[4];
    const PegInfo* pegs;
    StatsMod(const char* n, const char* h, const PegInfo* p) : Module(n, h), pegs(p) {
        for (int i = 0; i < 4; i++) peg_store[i] = 0;
    }
    const PegInfo* get_pegs() const override { return pegs; }
    PegCount* get_counts() const override { return const_cast<PegCount*>(peg_store); }  // module.h:154 returns NON-const PegCount*
    int rows() const { return (int)counts.size(); }
    PegCount cell(int t, int i) const { return counts[t][i]; }
    PegCount dcell(int t, int i) const { return dump_stats_counts[t][i]; }
};

// probe-side PegInfo table riding the SAME struct shape as the ground
// counts.h :45-:50 (type,name,help); the resident simple_pegs face (module.o
// :398-:401) is exercised by the second probe module below.
static const PegInfo four_pegs[] = {
    { CountType::SUM, "s", "sum peg" },
    { CountType::NOW, "n", "now peg" },
    { CountType::MAX, "m", "max peg" },
    { CountType::END, nullptr, nullptr }
};
struct SimpleMod : public Module {                             // THE resident module.o simple_pegs face :398-:401
    PegCount peg_store[2];
    SimpleMod() : Module("simple", "simple module") { peg_store[0] = 0; peg_store[1] = 0; }
    const PegInfo* get_pegs() const override { return simple_pegs; }        // counts.h:55 extern face, DEFINED at module.cc :398
    PegCount* get_counts() const override { return const_cast<PegCount*>(peg_store); }
    int rows() const { return (int)counts.size(); }
    PegCount cell(int t, int i) const { return counts[t][i]; }
};

int main()
{
    // ---------------- reload_tracker ladder (ground cc sites sed-pinned) --
    // the LogMessage strings below print via the CARRIED stubs_18d seam --
    // ground literals cc :41-:43/:48/:60/:75/:88, pinned against the vectors
    // in build.sh (printed-stub precedent: the EV lines from queue_event).
    bool s1 = ReloadTracker::start(nullptr);                 // :37; :47 null -> "signal"; :48 msg
    printf("TRK start1 -> %d\n", (int)s1);
    bool s2 = ReloadTracker::start(nullptr);                 // :39 in-progress gate -> :41 msg #2 DOUBLE-arg arm
    printf("TRK start2-during -> %d\n", (int)s2);
    ReloadTracker::update(nullptr, "st");                    // :81; :88 msg
    ReloadTracker::failed(nullptr, "why");                   // :68; :75 msg; :77/:78 drop
    bool s3 = ReloadTracker::start(nullptr);                 // :46-:49 re-arm
    int p_before1 = misc9_prompt_calls();
    ReloadTracker::end(nullptr, true);                       // :53 void (h:37); :60 msg; :62 TRUE -> :63 show_prompt #1
    printf("TRK end-prompt-true delta=%d\n", misc9_prompt_calls() - p_before1);
    ReloadTracker::start(nullptr);                           // :46-:49
    ReloadTracker::update(nullptr, "st2");                   // :88 msg
    int p_before2 = misc9_prompt_calls();
    ReloadTracker::end(nullptr);                             // h:37 default prompt=false -> :62 FALSE -> NO :63
    printf("TRK end-prompt-false delta=%d\n", misc9_prompt_calls() - p_before2);
    ReloadTracker::start(nullptr);                           // :46-:49
    ReloadTracker::failed(nullptr, "x");                     // :75 msg (reason half differs ONLY in the printed string)
    bool s6 = ReloadTracker::start(nullptr);                 // re-arms after failed -> true
    printf("TRK start-after-failed -> %d\n", (int)s6);
    printf("TRK order gate:39-before-log:41 | log:60-before-guard:62->prompt:63 | drop ctrl:64-before-flag:65\n");

    // ---------------- module stats ladder (ground module.cc arms) ---------
    StatsMod m("modS", "stats", four_pegs);
    m.init_stats(true);                                       // :312 new_thread=TRUE -> :327 threads=1 (NO ThreadConfig pull)
    printf("MS init-true num_counts=%d rows=%d\n", m.get_num_counts(), m.rows());   // h:159; walk :322-:324 (END sentinel stops BEFORE its null name -- while :323)
    m.peg_store[0] = 7;
    bool r3 = m.verified_begin("f", 0, nullptr); (void)r3;    // R6: table_level++ before the sum arms (h:227 etc read get_instance_id)
    m.sum_stats(false);                                       // SUM arm :205-:209 add_peg_count :206 + clear p[i]=0 :208
    printf("MS sum-false cell0=%llu p0=%llu\n", (unsigned long long)m.cell(0,0), (unsigned long long)m.peg_store[0]);
    m.peg_store[0] = 3; m.peg_store[2] = 9;
    m.sum_stats(true);                                        // dump arm: first dump copies counts->dump :177-:181, then add dump half; p NEVER zeroed (:207 guard)
    printf("MS sum-true cell0=%llu dcell0=%llu p0=%llu\n",
           (unsigned long long)m.cell(0,0), (unsigned long long)m.dcell(0,0), (unsigned long long)m.peg_store[0]);
    m.peg_store[2] = 2; m.sum_stats(true);                    // MAX set_max_peg_count keeps 9 (2 > 9 FALSE face)
    printf("MS max-arm dcell2=%llu\n", (unsigned long long)m.dcell(0,2));
    m.main_accumulate_stats();                                // cc :96-:107 -> aggregate over dump_stats_counts (:109/:126 statics)
    // name-hit :369-:370 (strcmp hit -> dump_stats_results[i]); wrong name
    // :372 assert(false) DEAD under -DNDEBUG -> :373 return 0:
    printf("MS ggc hit=%llu miss=%llu\n",
           (unsigned long long)m.get_global_count("s"), (unsigned long long)m.get_global_count("nope"));
    m.peg_store[1] = 5;
    m.reset_stats();                                          // fn :339; loop zeroes counts/dump :354-:355; p[i]=0 ONLY if :357 type!=NOW -> p[1] (NOW) survives
    printf("MS reset cell0=%llu dcell0=%llu p0=%llu p1=%llu p2=%llu\n",
           (unsigned long long)m.cell(0,0), (unsigned long long)m.dcell(0,0),
           (unsigned long long)m.peg_store[0], (unsigned long long)m.peg_store[1], (unsigned long long)m.peg_store[2]);
    m.init_stats(false);                                      // new_thread=FALSE -> :327 ThreadConfig::get_instance_max() (witness_conf arm) rows 1->2
    printf("MS init-false rows=%d num_counts=%d\n", m.rows(), m.get_num_counts());

    SimpleMod sm;                                             // THE resident simple_pegs face (module.o :398-:401)
    sm.init_stats(true);
    printf("SP num_counts=%d rows=%d\n", sm.get_num_counts(), sm.rows());   // 1 real peg + END sentinel face
    sm.peg_store[0] = 12; sm.sum_stats(false);
    printf("SP sum cell0=%llu p0=%llu\n", (unsigned long long)sm.cell(0,0), (unsigned long long)sm.peg_store[0]);
    printf("SP ggc-hit=%llu\n", (unsigned long long)sm.get_global_count("packets"));   // :398 name-hit arm
    printf("MS order add:cc206-before-clear:cc208 | accumulate:cc96-before-ggc:cc362\n"); // eval-order cites (measured ground lines)
    return 0;
}
