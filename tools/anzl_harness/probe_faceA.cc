// probe_faceA.cc (row 24d): the C-ABI record-face sibling ladder (the
// 24c face-A pattern): the real libdaq msg record through the REAL SDK
// INLINES (daq_msg_get_type/_pkthdr/_data/_data_len/_hdr_len — live ABI,
// zero witness leg: the row TU reads THESE very inlines (cc :236 the
// is_sticky seat reads flow->last_verdict, cc :250+ the distill switch),
// so the record VALUE face is the capture — a header inline NEVER recs);
// the SDK enum seats
// (DAQ_MSG_TYPE_* / DAQ_VERDICT_* from the real SDK heads — the landed-home
// law: NEVER a synthetic graft); the SFDAQConfig DEFAULTS record (the
// header member seats — the copy-closure heads face, NEVER an SDK ABI
// claim); the reload-ladder command SET faces (the public command
// accessors: get_daq/set_daq/get_instance/get_swapper/get_config_string/
// get_inspector_db_file/... — the pure value/param faces, zero leg); the
// apply-instrument / clear-file-data mirror legs (the row private seats —
// the -fno-access-control banking face); and the show_source banner face
// through the row's OWN public banner legs. stdout unbuffered; mirror
// banners ride stderr. The family law: the row-name NEVER rides this file
// joined (comments split: anal-yzer loop).
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"
#include "main/swapper.h"
#include "main/policy.h"
#include "filters/sfthreshold.h"
#include "filters/sfrf.h"
#include "main/thread_config.h"
#include "latency/latency_config.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_module.h"
#include "profiler_defs.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "daq.h"
#include "main.h"
#include <new>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace snort;

extern std::vector<std::string> g_probe_trace;
void probe_reset_trace();
const char* probe_legs();
void probe_rec(const char* n);
namespace snort { extern SnortConfig* g_probe_conf; }  // the witness get_conf seat
extern char* g_exbuf;
extern unsigned g_run_num_face;

static char g_exbuf_slot[64];

static DAQ_Msg_t msg;
static DAQ_PktHdr_t hdr;
static DAQ_FlowStats_t flow_stats;
static uint8_t bytes[16] = { 0xde, 0xad, 0xbe, 0xef, 0,0,0,0, 0,0,0,0 };

template <class T> static T* zero_seat(std::vector<char>& bank)
{
    bank.resize(sizeof(T), 0);
    return (T*)bank.data();
}

static void af1_records()
{
    hdr.pktlen = 120; hdr.opaque = 77;
    hdr.ts.tv_sec = 1700000000; hdr.ts.tv_usec = 555;
    msg.type = DAQ_MSG_TYPE_PACKET; msg.hdr = &hdr;
    msg.data = bytes; msg.data_len = 16;
    std::printf("AF-a type=%d/%d pkthdr=%d len=%d pktlen=%d ts=%lld.%06ld\n",
        (int)daq_msg_get_type(&msg), (int)msg.type,
        (int)(daq_msg_get_pkthdr(&msg) == &hdr),
        (int)daq_msg_get_data_len(&msg),
        (int)daq_msg_get_pkthdr(&msg)->pktlen,
        (long long)daq_msg_get_pkthdr(&msg)->ts.tv_sec,
        (long)daq_msg_get_pkthdr(&msg)->ts.tv_usec);
    const uint8_t* d = (const uint8_t*)daq_msg_get_data(&msg);
    std::printf("AF-b data=%02x%02x ref=%d\n", d[0], d[1], (int)(d == bytes));

    DAQ_Msg_t m2 = msg; m2.type = DAQ_MSG_TYPE_SOF; m2.hdr = &flow_stats;
    DAQ_Msg_t m3 = msg; m3.type = DAQ_MSG_TYPE_EOF; m3.hdr = &flow_stats;
    DAQ_Msg_t m4 = msg; m4.type = (DAQ_MsgType)9;  m4.hdr = &flow_stats;
    std::printf("AF-c types=%d,%d,%d,%d hdr_len=%d meta=%d\n", (int)msg.type,
        (int)daq_msg_get_type(&m2), (int)daq_msg_get_type(&m3),
        (int)daq_msg_get_type(&m4), (int)daq_msg_get_hdr_len(&msg),
        (int)(daq_msg_get_hdr(&msg) == &hdr));
    // (the sticky-verdict + the msg wrapper live as TU-STATIC inlines in the
    // row TU — cc :227-:231 — NEVER callable from HERE; their VALUE face
    // rides the main probe's LIVE distill/finalize legs (the g_exbuf echo).)

    std::printf("AF-f enum=%d,%d,%d,%d %d,%d,%d,%d\n",
        (int)DAQ_MSG_TYPE_PACKET, (int)DAQ_MSG_TYPE_PAYLOAD,
        (int)DAQ_MSG_TYPE_SOF, (int)DAQ_MSG_TYPE_EOF,
        (int)DAQ_VERDICT_PASS, (int)DAQ_VERDICT_IGNORE,
        (int)DAQ_VERDICT_BLACKLIST, (int)DAQ_VERDICT_WHITELIST);
}

static void af2_daqconf()
{
    // the DEFAULTS record face through the getters (BATCH_SIZE 64 /
    // SNAPLEN 1518 — the copy-closure heads law, NEVER an SDK ABI claim):
    SFDAQConfig c;
    std::printf("AF-g batch=%d mru=%d timeout=%d\n",
        (int)c.get_batch_size(), (int)c.get_mru_size(), (int)c.timeout);
    c.set_batch_size(7); c.set_mru_size(99);
    std::printf("AF-g2 set=%d,%d\n", (int)c.get_batch_size(), (int)c.get_mru_size());
}

// ---- the wall-command SET face (stringify / need_update_reload_id and the
// inline ref-count faces cc h :60-:61; the execute legs ride the mirror
// wall set in the MAIN probe ladder; the dtor face rides =delete):
static void af3_ac_faces()
{
    ACPause  cp;
    ACResume cr(3);
    ACRotate co;
    ACRun    cu(true);
    ACStart  cs;
    ACStop   ct;
    AnalyzerCommand* all[6] = { &cp, &cr, &co, &cu, &cs, &ct };
    int ok = 1;
    for (auto* a : all)
        if (!a->stringify() || !*a->stringify()) ok = 0;
    std::printf("AF-h ac=%d names=%s|%s|%s|%s|%s|%s\n",
        ok, cp.stringify(), cr.stringify(), co.stringify(), cu.stringify(),
        cs.stringify(), ct.stringify());
    ACRotate* rc2 = new ACRotate();
    unsigned a1 = rc2->get(), a2 = rc2->get(), a3 = rc2->put();
    std::printf("AF-i ref=%d,%d,%d\n", a1, a2, a3);
    if (rc2->put() == 0) delete rc2;   // the reap LAW face (the row reaps
    // through the SAME put()->0 delete law — harness rides it honest)
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    g_exbuf = g_exbuf_slot;

    af1_records();
    af2_daqconf();

    static std::vector<char> conf_bank, tc_bank, thr_bank, rf_bank, prof_bank;
    conf_bank.resize(sizeof(SnortConfig), 0);
    SnortConfig* conf = (SnortConfig*)conf_bank.data();
    new (conf) SnortConfig((const char*)nullptr);
    g_probe_conf = conf;
    conf->thread_config = zero_seat<ThreadConfig>(tc_bank);
    conf->latency = new LatencyConfig();
    conf->threshold_config = zero_seat<ThresholdConfig>(thr_bank);
    conf->rate_filter_config = zero_seat<RateFilterConfig>(rf_bank);
    conf->profiler = zero_seat<ProfilerConfig>(prof_bank);
    SFDAQConfig* dconf = new SFDAQConfig();
    conf->daq_config = dconf;

    SFDAQInstance* inst = new SFDAQInstance("d-in", 7, dconf);
    alignas(Analyzer) static char seat_lo[sizeof(Analyzer)];
    Analyzer* an = new (seat_lo) Analyzer(inst, 7, "d-a", 0, 200);

    af3_ac_faces();

    daq_stats.rx_bytes += 120; daq_stats.idle += 3;
    pc.analyzed_pkts += 1;
    std::printf("AF-r idle=%llu rx=%llu analyzed=%llu\n",
        (unsigned long long)daq_stats.idle,
        (unsigned long long)daq_stats.rx_bytes,
        (unsigned long long)pc.analyzed_pkts);

    probe_reset_trace();
    // the banner face rides the MAIN probe's LIVE operator() pass (show_-
    // source is PRIVATE in the header — NEVER a private-access flag EVER
    // ships HERE; the faceA ladder stays RECORD-face ONLY: the SDK inlines
    // + the header inlines + the SFDAQConfig DEFAULTS + the AC-wall stringify
    // /ref seats). The AF-s probe legs below ride the reset-empty face:
    std::printf("AF-s legs-empty=%d\n", (int)(std::strlen(probe_legs()) == 0));
    an->~Analyzer();
    return 0;
}
