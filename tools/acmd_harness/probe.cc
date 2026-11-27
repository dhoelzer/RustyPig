// probe.cc — row 24i DEC ladder: link the REAL row TU body (the pair owns
// EVERY non-inline analyzer-command body: AnalyzerCommand::log_message x3
// :95-:121, the six trivial execute() legs :123-:158, the ACGetStats ctor/
// execute/dtor stats-dump machine :173-:302 — REAL Module stats bodies ride
// via the ONE real framework/module.cc leg, ACResetStats :304-:311, the
// ACSwap tuner ladder :313-:391 — the cc-file-statics tuner_next/tuner_-
// update (:74/:83) + the THREAD_LOCAL :55 report_time + the :56 report_-
// period fire REAL on the crafted +20 s clock legs, HostAttributes/DAQSwap/
// ScratchUpdate :393-:431, get_daq_instance :433, the CPU report ladder
// :438-:488 + the latency report ladder :490-:583 — format_ip_addr (:60)
// REAL through the 5-tuple legs). Determinism law: ZERO wall-clock, ZERO
// heap-pointer values, ZERO randomness in the vectors — the witness pins
// fixed DIOCTL out-pokes (binary-exact %.1f/%.3f faces: .5/.375/.125/.25
// quarters, NO half-tie) + the fixed +20 s packet clock vs the REAL 10 s
// period. NEVER driven (cited NF rows): the inet_ntop-failure -> invalid_ip
// strcpy leg (a poke-wall-UNREACHABLE face), ControlConn socket reads,
// the Analyzer message loop, DropStats' REAL banner home (utils/stats.cc
// NEVER lands — the mirror echoes the REAL sums the row body folded). The
// REG_TEST h :261 decl NEVER compiled (the walked zero-gate face, the
// cmake token-ABSENT face); the UNIT_TEST face is EXACTLY-0 BOTH files —
// the ut post is VACUOUS, ZERO delta legs ride.
#include <cstdio>
#include <cstring>
#include <string>
#include <list>
#include <vector>

#include "main/snort_config.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/reload_tuner.h"
#include "main/swapper.h"
#include "main/thread_config.h"
#include "main/thread.h"
#include "framework/module.h"
#include "framework/counts.h"
#include "framework/parameter.h"
#include "helpers/scratch_allocator.h"
#include "packet_io/sfdaq_instance.h"
#include "protocols/packet_manager.h"
#include "log/messages.h"
#include "control/control.h"

extern "C" void witness_set_instance_id(unsigned);
extern "C" void witness_analyzer_ctor_state(int);
extern "C" int witness_daq_idx(void);

using namespace snort;

extern "C" void witness_set_modules(Module**, int);

// ---- the crafted reload tuner (the REAL ACSwap tuner ladder + the REAL
// tuner_next/tuner_update bodies + the REAL :55/:56 report_time arithmetic
// fire through these vtables; the tinit-true/false pair drives the REAL
// keep/erase arms). ----
class ProbeTuner : public ReloadResourceTuner
{
    int keep; int progress_calls; int tpc_n;
public:
    explicit ProbeTuner(int k) : keep(k), progress_calls(0), tpc_n(0) { }
    const char* name() const override { return keep ? "ProbeTunerA" : "ProbeTunerB"; }
    bool tinit() override
    { printf("X tuner.tinit %s keep=%d\n", name(), keep); return keep != 0; }
    bool tune_packet_context() override
    {
        int v = tpc_n < 3 ? 0 : 1;          // calls 1-3 false (the tuner_update legs, one report FIRE on the +10 s face), call 4+ true (the pop/complete/finish face)
        ++tpc_n;
        printf("X tuner.tpc %s n=%d v=%d\n", name(), tpc_n, v);
        return v != 0;
    }
    bool tune_idle_context() override
    { printf("X tuner.tic %s\n", name()); return true; }
    void report_progress() override
    { printf("X tuner.report_progress %s calls=%d\n", name(), ++progress_calls); }
};

// ---- the crafted module table the REAL ACGetStats stats machine walks:
// the REAL Module ctor/init + the REAL init_stats/collect/aggregate/set_-
// results bodies (framework/module.cc — the ONE real leg) ride them. The
// peg faces: SUM + MAX + END-null-terminator (the init_stats walk face). ----
struct ProbeMod : Module
{
    static const PegInfo pegs2[3];
    static const PegInfo pegs1[2];
    mutable PegCount c[2];
    bool glob;
    int np;
    ProbeMod(const char* nm, bool g, int peg_count, PegCount v0, PegCount v1)
        : Module(nm, "witness-probe"), glob(g), np(peg_count)
    { c[0] = v0; c[1] = v1; }
    const PegInfo* get_pegs() const override { return np == 2 ? pegs2 : (np == 1 ? pegs1 : nullptr); }
    bool global_stats() const override { return glob; }
    PegCount* get_counts() const override { return (PegCount*)c; }
};
const PegInfo ProbeMod::pegs2[3] = {
    { CountType::SUM, "probe.sum", "sum peg" },
    { CountType::MAX, "probe.max", "max peg" },
    { CountType::END, nullptr, nullptr } };
const PegInfo ProbeMod::pegs1[2] = {
    { CountType::SUM, "probe.gsum", "global sum peg" },
    { CountType::END, nullptr, nullptr } };

// ---- the scratch-update handlers (the SimpleScratchAllocator inline faces;
// the update fn prints the X line; the vector's FIRST slot stays nullptr —
// the REAL :421 skip arm). ----
static bool x_setup(SnortConfig*) { printf("X alloc.setup\n"); return true; }
static void x_cleanup(SnortConfig*) { printf("X alloc.cleanup\n"); }
static void x_update(SnortConfig*) { printf("X alloc.update\n"); }

int main()
{
    witness_set_instance_id(0);

    // the crafted conns: local fd 3 (the respond-skips face inside
    // log_message) + remote fd 4 (the FULL echo fork REAL).
    ControlConn* lc = new ControlConn(3, true);
    ControlConn* rc = new ControlConn(4, false);

    // the crafted module table (non-global 2-peg, global 1-peg, no-peg)
    ProbeMod modA("ProbeModA", false, 2, 7, 9);
    ProbeMod modG("ProbeModG", true, 1, 5, 0);
    ProbeMod modN("ProbeModN", false, 0, 0, 0);
    Module* mods[3] = { &modA, &modG, &modN };
    witness_set_modules(mods, 3);

    ThreadConfig::set_instance_max(2);          // the 2-instance ladder face

    // the crafted conf + the tuner list INJECTED through the PUBLIC h :710
    // inline (const_cast over the NON-const conf — by-construction face).
    SnortConfig conf;
    std::list<ReloadResourceTuner*>& tl =
        const_cast<std::list<ReloadResourceTuner*>&>(conf.get_reload_resource_tuners());
    ProbeTuner tA(1), tB(0);
    tl.push_back(&tA);
    tl.push_back(&tB);

    // the crafted analyzer + daq handle (state faces ride the witness arm:
    // a0 NEW=0 the reject leg; a1 RUNNING=3 the walk face)
    SFDAQInstance inst("w0", 0, nullptr);
    witness_analyzer_ctor_state(0);
    Analyzer a0(nullptr, 1, "w1");
    witness_analyzer_ctor_state(3);
    Analyzer a1(&inst, 0, "w0");
    printf("B1 a0.state=%d a1.state=%d a1.idling=%d\n",
        (int)a0.get_state(), (int)a1.get_state(), a1.is_idling() ? 1 : 0);

    // ---- the log_message core fork (REAL :95-:121): the remote conn rides
    // BOTH legs (respond + LogMessage); the local conn skips respond. ----
    AnalyzerCommand::log_message(rc, "V remote=%d\n", 7);
    AnalyzerCommand::log_message(lc, "V local=%d\n", 9);

    // ---- the six trivial commands (REAL execute + the inline stringify) ----
    ACStart st; ACRun run(false); ACRun runp(true); ACStop stop;
    ACPause pause; ACResume resume(12u); ACRotate rot;
    printf("K1 str=%s,%s,%s,%s,%s,%s,%s\n", st.stringify(), run.stringify(),
        runp.stringify(), stop.stringify(), pause.stringify(), resume.stringify(),
        rot.stringify());
    printf("K2 start=%d ", st.execute(a1)); printf("run=%d ", run.execute(a1));
    printf("runp=%d ", runp.execute(a1)); printf("stop=%d ", stop.execute(a1));
    printf("pause=%d ", pause.execute(a1)); printf("resume=%d ", resume.execute(a1));
    printf("rotate=%d nur=%d\n", rot.execute(a1), st.need_update_reload_id() ? 1 : 0);

    // ---- ACResetStats (the REAL h :88-:99 ordinals straight to the
    // mirror; string_map-vs-ordinal arithmetic rides FACE-A) ----
    {
        ACResetStats rdaq(TYPE_DAQ); rdaq.execute(a1);
        ACResetStats rall(TYPE_ALL); rall.execute(a1);
        ACResetStats rinv(TYPE_INVALID); rinv.execute(a1);
        printf("RS str=%s type_daq=%d type_all=%d type_inv=%d\n",
            rdaq.stringify(), (int)TYPE_DAQ, (int)TYPE_ALL, (int)TYPE_INVALID);
    }

    // ---- the stats-dump machine (REAL ACGetStats ctor/execute/dtor + the
    // REAL Module stats bodies via the module.cc leg): dump results fold
    // REAL (SUM out=7 via get_counts pokes; MAX=9) ----
    {
        ACGetStats gs(rc, StatsOutputFormat::Text);
        unsigned r1 = gs.get(); unsigned r2 = gs.get(); unsigned r3 = gs.put();
        printf("G0 refs=%u,%u,%u fmt_str=%s\n", r1, r2, r3, gs.stringify());
        printf("G1 ex=%d\n", gs.execute(a1) ? 1 : 0);
        printf("G2 pre-dtor countsA=%d nmods-seen-above=3\n", modA.get_num_counts());
    }   // dtor: the aggregate/set_results/DropStats fold + the END-OF-STATS marker
    printf("G3 resA=%llu,%llu resG_sz=%zu resN_sz=%zu\n",
        (unsigned long long)modA.get_dump_stats_results()[0],
        (unsigned long long)modA.get_dump_stats_results()[1],
        modG.get_dump_stats_results().size(), modN.get_dump_stats_results().size());

    // ---- the ACSwap legs ----
    {
        ACSwap sw_a(new Swapper(&conf), lc);
        printf("S1 new-state=%d\n", sw_a.execute(a0) ? 1 : 0);       // the :315 reject
    }   // dtor teardown legs fire regardless (the REAL :376-:391 body)
    {
        ACSwap sw_b(new Swapper(nullptr), lc);
        printf("S2 null-conf=%d\n", sw_b.execute(a1) ? 1 : 0);       // the :373 face
    }
    {
        ACSwap sw_c(new Swapper(&conf), lc);
        printf("X1 leg1=%d\n", sw_c.execute(a1) ? 1 : 0);            // list build + erase-tB + tuner_next
        printf("X2 leg2=%d\n", sw_c.execute(a1) ? 1 : 0);            // tpc-false -> tuner_update (cold face)
        printf("X3 leg3=%d\n", sw_c.execute(a1) ? 1 : 0);            // tpc-false -> tuner_update (the fire face)
        printf("X4 leg4=%d\n", sw_c.execute(a1) ? 1 : 0);            // tpc-true -> pop -> empty -> complete + finish
    }   // the dtor: delete-lists, clear_tuner_list, delete ps, swap_cleanup, end, "== reload complete"

    // ---- the swap/scratch/reload trio ----
    {
        ACHostAttributesSwap h(rc);
        h.execute(a1);
    }
    {
        ACDAQSwap ds;
        ds.execute(a1);
    }
    {
        SimpleScratchAllocator alloc(x_setup, x_cleanup, x_update);
        std::vector<ScratchAllocator*> handlers = { nullptr, &alloc };
        ACScratchUpdate su(&conf, handlers, rc);
        printf("SU ex=%d\n", su.execute(a1) ? 1 : 0);
    }   // dtor: log_message + ReloadTracker.end prompt=true

    // ---- the CPU report ladder (REAL :463-:488 execute x3 + REAL :438-
    // :461 dtor fold): pokeA id0, pokeB id1, the status-fail reject leg ----
    {
        ACShowSnortCPU cpu(rc);
        printf("CP ex1=%d idx=%d\n", cpu.execute(a1) ? 1 : 0, witness_daq_idx());
        witness_set_instance_id(1);
        printf("CP ex2=%d idx=%d\n", cpu.execute(a1) ? 1 : 0, witness_daq_idx());
        witness_set_instance_id(0);
        printf("CP ex3-fail=%d idx=%d\n", cpu.execute(a1) ? 1 : 0, witness_daq_idx());
    }   // dtor: the 2 instances + the summary mean ladder (%.1f exact quarters)

    // ---- the latency report ladder (REAL :559-:583 execute + REAL :490-
    // :557 dtor: the REAL format_ip_addr v4 + v6 legs, the zero-skip arms,
    // the zero-PORT reject arms) ----
    {
        ACShowSnortPacketLatencyData lat(lc);
        printf("LT ex1=%d idx=%d\n", lat.execute(a1) ? 1 : 0, witness_daq_idx());
        witness_set_instance_id(1);
        printf("LT ex2=%d idx=%d\n", lat.execute(a1) ? 1 : 0, witness_daq_idx());
        witness_set_instance_id(0);
        printf("LT ex3-null=%d idx=%d\n", lat.execute(a0) ? 1 : 0, witness_daq_idx());
        SFDAQInstance* gi = AnalyzerCommand::get_daq_instance(a1);
        SFDAQInstance* gn = AnalyzerCommand::get_daq_instance(a0);
        printf("LT gdi=%d,%d\n", gi ? 1 : 0, gn ? 1 : 0);
    }   // dtor: the 2-instance protocol ladders + the separators

    // ---- the cited-NEVER-driven walls (the walked face, NEVER fired) ----
    printf("NF inet_ntop-fail invalid_ip strcpy leg cited (poke-wall unreachable)\n");
    printf("NF Analyzer message-loop cited wall\n");
    printf("NF DropStats real banner home cited (utils/stats NEVER lands)\n");

    // ---- teardown (mirror dtor echoes, ONCE per object) ----
    delete rc;
    delete lc;
    printf("fin=PASS\n");
    return 0;
}
