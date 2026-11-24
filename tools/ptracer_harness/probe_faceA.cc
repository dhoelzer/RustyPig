// row-23f FACE-A probe: header/width/enum/ctor-cold faces via a derived
// reader of the PROTECTED h-members (the ground TestPacketTracer shape at
// cc :465-:508 is the cite: derived-class protected access, NEVER a
// private peek) + the REAL-SDK flag/pkthdr ledger + the clock ledger.
#include <cstdio>
#include <cstring>
#include <string>
#include "packet_io/packet_tracer.h"
#include "packet_io/active.h"
#include "sfip/sf_ip.h"
#include <daq_common.h>

extern std::string warn_capture;
using namespace snort;

// open_file NEVER lands (open_file is protected; a derived reader sees the
// RESULT face log_fh/buff via the cold ctor legs — no call needed: the
// PUBLIC ctor runs through the real open_file (log_file == "-" cold face
// -> stdout). thread-free cold process: log_file static NEVER seeded.
struct ColdReader : public PacketTracer {
    unsigned bl() { return buff_len; }
    unsigned dbl() { return daq_buff_len; }
    unsigned pc() { return pause_count; }
    bool ue() { return user_enabled; }
    bool sh() { return shell_enabled; }
    bool ac() { return active; }
    bool fh_stdout() { return log_fh == stdout; }
    size_t ms() { return mutes.size(); }
    bool timer_live() { return pt_timer != nullptr; }
    PacketConstraints& cs() { return constraints; }
};

int main()
{
    // A1 widths (C-decl faces, cite-pinned by build.sh): TracerMute =
    // uint8_t (h :54); max_buff_size 2048 (cc :73); PT_DEBUG_SESSION_ID_
    // SIZE macro (cc :72) sums to 159
    printf("A1 mute-size=%zu max-buff=2048 dbg-size=%d\n",
        sizeof(PacketTracer::TracerMute),
        ((39+1+5+1+2+1+39+1+5+1+3+1+2+1+10+1+2+1+10+32)+1));

    // A2 cold ctor face through a DERIVED instance (log_file "-" cold
    // static -> stdout; NSDMI h :96-:112; config_status false -> user
    // NEVER enabled; mutes.resize(global_mutes.val=0))
    ColdReader r;
    printf("A2 cold bl=%u dbl=%u pc=%u ue=%d sh=%d ac=%d stdout=%d mutes=%zu timer=%d\n",
        r.bl(), r.dbl(), r.pc(), (int)r.ue(), (int)r.sh(), (int)r.ac(),
        (int)r.fh_stdout(), r.ms(), (int)r.timer_live());
    // the constraints member cold face (23e REUSE face on the member --
    // the C h :115 PacketConstraints constraints member IS the 23e type)
    printf("A3 member-pc match=%d setbits=%u proto=%d\n",
        (int)r.cs().match, (unsigned)r.cs().set_bits, (int)r.cs().ip_proto);

    // A4 REAL-SDK flag ledger at THIS consumer (daq_common.h :124 face:
    // DAQ_PKT_FLAG_TRACE_ENABLED == 0x0400 == 1024)
    printf("A4 trace-flag=%d\n", (int)DAQ_PKT_FLAG_TRACE_ENABLED);

    // A5 pkthdr 56B/tenant@48 (the 23a-23e REAL-SDK ledger re-ridden at
    // this consumer) + SfIp 18 + the ACT_MAX/AST_MAX table widths (23f
    // witness mirror dims: 8x4 the active.h :214 face)
    printf("A5 pkth=%zu tn_off=%zu sip=%zu act=%d ast=%d\n",
        sizeof(DAQ_PktHdr_t), offsetof(DAQ_PktHdr_t, tenant_id),
        sizeof(snort::SfIp), (int)Active::ACT_MAX, (int)Active::AST_MAX);

    // A6 stopwatch/clock ledger (20b home REUSE at this consumer):
    // cold get() == 0 (DURA_ZERO), TO_NSECS identity face pinned in
    // clock_defs (SnortClock = high_resolution ns)
    Stopwatch<SnortClock> w;
    printf("A6 timer-cold=%lld active=%d\n", (long long)TO_NSECS(w.get()), (int)w.active());
    return 0;
}
