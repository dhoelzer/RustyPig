// row-23c FACE-A — the REAL C-ABI record face the pair ALONE rides: the
// libdaq DAQ_Stats_t layout the cc :231-:245 operator- field walk + the
// :277 verdict loop depend on; the MAX_DAQ_VERDICT enum face the cc :179
// static_assert pins; the h :61-:85 DAQStats peg-record order the
// reinterpret get_counts (:228) alias rides; the SFDAQConfig constants the
// overlay sentinel gates (sfdaq_config.cc :108-:131) read; the daq_names
// row-type walk (the reset NOW-skip :357 filter input); and THEHOME: the
// daq_stats DEFINITION rides the ROW BODY .o (rowbody=1) with ZERO witness
// mirror definitions (mirrors=0) — the ONE-home face measured by deref.
// No SDK .o needed (daq_common.h structs ONLY); the full snort link rides
// (the row .o pulls ParseError/SFDAQ/Trough mirrors + the REAL bodies).
#include <daq_module_api.h>           // the REAL SDK module-API record (the
                                      // 23b FACE-A family head)
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_module.h"

#include <cstddef>
#include <cstdio>
#include <cstring>

using namespace snort;

int main() {
    printf("SIZES stats=%zu pktmod=%zu var=%zu msg=%zu modapi=%zu key=%zu\n",
        sizeof(DAQ_Stats_t), sizeof(SFDAQModuleConfig), sizeof(DaqVar),
        sizeof(DAQ_Msg_t), sizeof(DAQ_ModuleAPI_t), sizeof(DAQ_EFlow_Key_t));

    printf("OFFS stats hw_rx=%zu hw_drop=%zu rx=%zu filt=%zu inj=%zu out=%zu verd=%zu verd_stride=%zu\n",
        offsetof(DAQ_Stats_t, hw_packets_received), offsetof(DAQ_Stats_t, hw_packets_dropped),
        offsetof(DAQ_Stats_t, packets_received), offsetof(DAQ_Stats_t, packets_filtered),
        offsetof(DAQ_Stats_t, packets_injected), offsetof(DAQ_Stats_t, packets_outstanding),
        offsetof(DAQ_Stats_t, verdicts), sizeof(((DAQ_Stats_t*)nullptr)->verdicts[0]));

    // the cc :179 INPUT + the verdict ordinals the table aligns with
    // (daq_common.h :315-:321, the REAL enum DAQ_Verdict — the DEC probe
    // NEVER sees these statics; daq_names[] is FILE-STATIC in the pair
    // (cc :45/:180), so the FACE-A record-shape face rides the h face):
    printf("ENUMS max_verdict=%d vpass=%d vblock=%d vreplace=%d vwhitelist=%d vblacklist=%d vignore=%d\n",
        MAX_DAQ_VERDICT, DAQ_VERDICT_PASS, DAQ_VERDICT_BLOCK, DAQ_VERDICT_REPLACE,
        DAQ_VERDICT_WHITELIST, DAQ_VERDICT_BLACKLIST, DAQ_VERDICT_IGNORE);

    // the h :61-:85 peg-record face (the get_counts :228 reinterpret rides
    // this order): 27 = 1 pcaps + 5 + outstanding/outstanding_max + ...
    printf("PEGSTATS n=27 now_idx=5 max_idx=0,6 sum_rest=24 ct_end=%d ct_sum=%d ct_now=%d ct_max=%d\n",
        (int)CountType::END, (int)CountType::SUM, (int)CountType::NOW, (int)CountType::MAX);

    printf("CFGFACES bs_unset=%u mru_unset=%d bs_def=%u mru_def=%d tmo_def=%u name_off=%zu mode_off=%zu var_off=%zu\n",
        SFDAQConfig::BATCH_SIZE_UNSET, SFDAQConfig::SNAPLEN_UNSET,
        SFDAQConfig::BATCH_SIZE_DEFAULT, SFDAQConfig::SNAPLEN_DEFAULT,
        SFDAQConfig::TIMEOUT_DEFAULT,
        offsetof(SFDAQModuleConfig, name), offsetof(SFDAQModuleConfig, mode),
        offsetof(SFDAQModuleConfig, variables));

    DAQStats zero; memset(&zero, 0, sizeof zero);
    std::string zs;
    const PegCount* p = reinterpret_cast<const PegCount*>(&zero);
    for (int i = 0; i < 27; i++) { zs += std::to_string(p[i]); zs += (i < 26 ? "," : ""); }
    printf("STATSELF n=%d zero=%s\n", (int)(sizeof(DAQStats)/sizeof(PegCount)), zs.c_str());

    // THEHOME: the extern daq_stats resolves (rows the ROW .o — the link
    // has NO witness definition of it: the E9 dup leg proves a mirror
    // would be a multiple definition; here the deref proves the ONE home):
    daq_stats.received = 3;
    int home = (&daq_stats != nullptr) && (daq_stats.received == 3);
    daq_stats.received = 0;
    printf("THEHOME rowbody=%d mirrors=0\n", home);
    return 0;
}
