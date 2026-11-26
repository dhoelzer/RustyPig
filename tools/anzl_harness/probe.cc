// probe.cc (row 24d): drives the analysis-loop row .o through the DEC order
// + face ladder in ONE in-proc operator() pass. Captures are MIRROR rec()
// legs riding the ONE g_probe_trace ladder (row legs + mock-command legs
// feed the SAME ladder, ground call order); the counter census rides the
// row's OWN THREAD_LOCAL pull faces (daq_stats / snort::pc re-exports —
// scripted deterministic seats per the banked deviations law). The command
// facility rides HEAP MOCK commands with once-fired next-seats (the
// NEVER-land command wall served-in HERE ONLY): each execute() recs its leg,
// queues the NEXT mock through the row's OWN execute() seat (the interrupt
// LAW true-face arms while >= STARTED), then drives the PUBLIC command-entry
// faces. The scripted rstat/msg-per-receive face makes the WHOLE ladder
// LIVE: start/run init ladders at NEW (the pre-start drain), the RUNNING
// TIMEOUT idle legs, the INTERRUPTED kick+handle_commands walk, pause-
// while-RUNNING, resume(3) arm, reload, the FALSE mock parked in the
// UNCOMPLETED set (the handle_uncompleted_commands walk + the cc :966 kick
// xN LIVE), the skip x2 PASS finalizes, the SOF/EOF/OTHER message faces,
// the pause-after ZERO-roll pause() arm, and the STOP chain (rotate + stop
// -> the exit MEMBER seat cc :1141 ends the loop); the reap_commands + dtor
// reap legs close it. The show_source banner prints LIVE (pcap_show TRUE,
// run_num 2 -> the newline leg). stdout unbuffered; mirror banners ride
// stderr. The family law: the row-name NEVER rides this file joined
// (comments split: anal-yzer loop).
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "main/thread.h"
#include "main/policy.h"
#include "main/swapper.h"
#include "latency/latency_config.h"
#include "time/clock_defs.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_module.h"
#include "filters/sfthreshold.h"
#include "filters/sfrf.h"
#include "profiler_defs.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "main.h"
#include <new>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace snort;

extern std::vector<std::string> g_probe_trace;
void probe_reset_trace();
const char* probe_legs();
void probe_rec(const char* n);

// witness seams (externs):
extern unsigned g_run_num_face;
extern unsigned g_rstat_seq[9];
extern unsigned g_rstat_count;
extern DAQ_Msg_t** g_msg_seq;        // per-receive script: 4 seats/row
extern uint8_t g_grinder_face;
extern char* g_exbuf;
namespace snort { extern SnortConfig* g_probe_conf; }  // the witness get_conf seat
extern unsigned g_poke_count, g_log_count, g_err_count;

static char g_exbuf_slot[64];

// message ring (shape-only SDK record seats, harness-scripted):
static DAQ_Msg_t m_pkt, m_sof, m_eof, m_other;
static DAQ_PktHdr_t pkt_hdr;
static DAQ_FlowStats_t flow_stats;
static uint8_t bytes[16] = { 0 };

// the mock command wall (once-fired chain; legs feed the SAME ladder):
class MockAC : public AnalyzerCommand
{
public:
    MockAC(Analyzer* t, const char* n, const char* l, int m, MockAC* nx)
        : target(t), name(n), leg(l), mode(m), next(nx), fired(false) { }
    MockAC* stop2 = nullptr;   // the FALSE mock's 2nd-walk STOP re-arm seat
    int walks = 0;
    bool execute(Analyzer& a) override
    {
        (void)a;
        probe_rec(leg);
        if (next && !fired) { fired = true; target->execute(next); }
        if (std::strcmp(name, "FALSE") == 0 && ++walks == 2 && stop2)
            target->execute(stop2);   // the uncompleted-walk RETRY face:
            // the walk re-executes the PARKED mock each pass; the 2nd pass
            // rides the row's queued-STOP leg (cc :972 the re-execute).
        if (std::strcmp(name, "START") == 0) target->start();
        else if (std::strcmp(name, "RUN") == 0) target->run(false);
        else if (std::strcmp(name, "SKIP") == 0) target->set_skip_cnt(2);   // h :90
        else if (std::strcmp(name, "PAUSE") == 0) target->pause();
        else if (std::strcmp(name, "RESUME") == 0) target->resume(3);
        else if (std::strcmp(name, "RELOAD") == 0) target->reload_daq();
        else if (std::strcmp(name, "STOP") == 0) { target->rotate(); target->stop(); }
        return mode == 1;
    }
    const char* stringify() override { return name; }
    Analyzer* target; const char* name; const char* leg; int mode; MockAC* next;
    bool fired;
};

template <class T> static T* zero_seat(std::vector<char>& bank)
{
    bank.resize(sizeof(T), 0);
    return (T*)bank.data();
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    g_exbuf = g_exbuf_slot;

    m_pkt.type = DAQ_MSG_TYPE_PACKET; m_pkt.hdr = &pkt_hdr;
    m_pkt.data = bytes; m_pkt.data_len = 16;
    m_sof.type = DAQ_MSG_TYPE_SOF;    m_sof.hdr = &flow_stats;
    m_eof.type = DAQ_MSG_TYPE_EOF;    m_eof.hdr = &flow_stats;
    m_other.type = (DAQ_MsgType)9;    m_other.hdr = &flow_stats;  // user range

    // ---- the conf boot (the subset-seat precedent; run_flags the LIVE-
    // banner face; the read-through-inlines member seats are zeroed cast-
    // seats, field-ONLY reads, NEVER method calls, NEVER an ABI claim —
    // banked honest in the deviations block). The LATENCY arms ride the REAL
    // LatencyConfig (the max_time seat makes enabled() TRUE through the
    // ground inline — an honest arm, the latency_config head IS linked):
    static std::vector<char> conf_bank, tc_bank, thr_bank, rf_bank, prof_bank;
    conf_bank.resize(sizeof(SnortConfig), 0);
    SnortConfig* conf = (SnortConfig*)conf_bank.data();
    new (conf) SnortConfig((const char*)nullptr);          // the ctor mirror
    conf->thread_config = zero_seat<ThreadConfig>(tc_bank);
    conf->latency = new LatencyConfig();
    conf->latency->packet_latency.max_time = hr_duration(1000);
    conf->latency->rule_latency.max_time = hr_duration(1000);
    conf->threshold_config = zero_seat<ThresholdConfig>(thr_bank);
    conf->rate_filter_config = zero_seat<RateFilterConfig>(rf_bank);
    conf->profiler = zero_seat<ProfilerConfig>(prof_bank);
    conf->run_flags |= RUN_FLAG__PCAP_SHOW;
    g_probe_conf = conf;             // the get_conf() seat the row reads
    SFDAQConfig* dconf = new SFDAQConfig();                // DEFAULTS 64/1518
    conf->daq_config = dconf;

    // ---- per-receive script (rstat row + msg row; 9 rows; the final rows
    // NEVER run honestly — the STOP exits FIRST):
    static const unsigned rs[9] = {
        DAQ_RSTAT_TIMEOUT,          // rc1 at NEW: pre-start drain (no recv)
        DAQ_RSTAT_TIMEOUT,          // rc2 RUNNING: idle() LIVE
        DAQ_RSTAT_INTERRUPTED,      // rc3 RUNNING: kick + handle_commands
        DAQ_RSTAT_OK,               // rc4 RUNNING: [pkt,sof,eof] skip x2 + the eof
        DAQ_RSTAT_INTERRUPTED,      // rc5 RUNNING: [] the command chain drains
                                    // (skip2 + pause-guard-ERR + resume(3) +
                                    // reload + the false mock parks)
        DAQ_RSTAT_OK,               // rc6 RUNNING: [pkt,sof,eof] -> skip x2
                                    // LIVE + the eof finalize; post-roll
                                    // pause_after 3-3=0 -> pause() LIVE
        DAQ_RSTAT_TIMEOUT,          // rc7 PAUSED: idle() LIVE (the false-mock
                                    // parked -> the uncompleted walk)
        DAQ_RSTAT_INTERRUPTED,      // rc8 drains the queued STOP -> exit face
        0 };
    for (int i = 0; i < 9; i++) g_rstat_seq[i] = rs[i];
    g_rstat_count = 7;
    static DAQ_Msg_t* flat[36];
    for (int i = 0; i < 36; i++) flat[i] = nullptr;
    flat[4]  = &m_pkt; flat[5]  = &m_sof; flat[6]  = &m_eof;          // rc4 x3
    flat[16] = &m_pkt; flat[17] = &m_sof; flat[18] = &m_eof;          // rc6 x3
                                    // (skip legs + pause_after 3-3=0 roll)
    g_msg_seq = flat;
    g_run_num_face = 2;                    // the banner newline-leg face

    // ---- P0 ctor + D2 execute-at-NEW guard face:
    probe_reset_trace();
    SFDAQInstance* inst = new SFDAQInstance("d-in", 7, dconf);
    alignas(Analyzer) static char an_seat[sizeof(Analyzer)];
    Analyzer* an = new (an_seat) Analyzer(inst, 7, "d-a", 0, 200);
    std::string p0 = probe_legs();
    std::printf("P0 ctor legs=%s\n", p0.c_str());   // inst.ctor + retry log
    std::printf("P1 state0=%s source=%s idling=%d\n",
        an->get_state_string(), an->get_source(), (int)an->is_idling());
    probe_reset_trace();
    MockAC* z = new MockAC(an, "Z", "cmd.z", 1, nullptr);   // rides the dtor
    z->get();                                              // the ref seat
    an->execute(z);                // state NEW: push ONLY (no interrupt leg)
    std::printf("D2 execute@NEW legs-empty=%d\n",
        (int)(std::strlen(probe_legs()) == 0));

    // ---- the command chain (heap mocks; the reaps ride put()->0 delete):
    MockAC* c_stop   = new MockAC(an, "STOP",   "cmd.stop",   1, nullptr);
    MockAC* c_false  = new MockAC(an, "FALSE",  "cmd.false",  0, nullptr);
    c_false->stop2 = c_stop;          // the retry-face stop arm
    MockAC* c_reload = new MockAC(an, "RELOAD", "cmd.reload", 1, c_false);
    MockAC* c_resume = new MockAC(an, "RESUME", "cmd.resume", 1, c_reload);
    MockAC* c_pause  = new MockAC(an, "PAUSE",  "cmd.pause",  1, c_resume);
    MockAC* c_skip   = new MockAC(an, "SKIP",   "cmd.skip",   1, c_pause);
    MockAC* c_run    = new MockAC(an, "RUN",    "cmd.run",    1, c_skip);
    MockAC* c_start  = new MockAC(an, "START",  "cmd.start",  1, c_run);
    // every queued push carries the get()/put() ref face (reap delete once):
    c_start->get(); c_run->get(); c_skip->get(); c_pause->get();
    c_resume->get(); c_reload->get(); c_false->get(); c_stop->get();

    probe_reset_trace();
    an->execute(c_start);          // the pre-start push (NEW guard face too)
    Swapper sw(conf);              // the ctor/dtor mirror recs bracket
    (*an)(&sw, 2);
    std::printf("L1 legs=%s\n", probe_legs());
    std::printf("L1b state=%s switcher=%d local=%d fin=%s\n",
        an->get_state_string(),
        (int)(Analyzer::get_switcher() != nullptr),
        (int)(Analyzer::get_local_analyzer() != nullptr),
        g_exbuf_slot);
    std::printf("L1c idle=%llu skipped=%llu sof=%llu eof=%llu other=%llu rx=%llu iwl=%llu ibl=%llu rq=%llu rp=%llu rdisc=%llu analyzed=%llu\n",
        (unsigned long long)daq_stats.idle,
        (unsigned long long)daq_stats.skipped,
        (unsigned long long)daq_stats.sof_messages,
        (unsigned long long)daq_stats.eof_messages,
        (unsigned long long)daq_stats.other_messages,
        (unsigned long long)daq_stats.rx_bytes,
        (unsigned long long)daq_stats.internal_whitelist,
        (unsigned long long)daq_stats.internal_blacklist,
        (unsigned long long)daq_stats.retries_queued,
        (unsigned long long)daq_stats.retries_processed,
        (unsigned long long)daq_stats.retries_discarded,
        (unsigned long long)pc.analyzed_pkts);
    std::printf("L1d poke=%u log=%u err=%u\n",
        g_poke_count, g_log_count, g_err_count);

    probe_reset_trace();
    an->~Analyzer();
    std::printf("D4 dtor legs=%s\n", probe_legs());
    return 0;
}
