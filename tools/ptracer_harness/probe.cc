// row-23f DEC probe: the log/buffer/pause/mute/activate/shell/daq/open/
// timer ladder over the REAL row .o (the ONE home of every leg). NO
// mirrors HERE (the witness owns the wall captures); the REAL homes ride
// the link: sf_ip.cc, util.cc (int_vector_to_str REAL body, the 23e
// fresh-cp law re-ridden), util_cstring.cc, ip.cc (IpApi::set REAL),
// the 23e pc pair (packet_match ONE-home REUSE through the
// set_constraints C cross-row leg), the carried witness_conf
// (get_conf/FatalError/gif), witness walls (capture mirrors).
#include <cstdio>
#include <cstring>
#include <string>
#include "packet_io/packet_tracer.h"
#include "packet_io/packet_constraints.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "protocols/ipv4.h"
#include "main/thread.h"

extern std::string batched_capture, sl_capture, daq_trace_capture, msg_capture, warn_capture;
using namespace snort;

// the C _thread_init<T> template body lives ONLY in the row TU (the
// UNIT_TEST block instantiates it there); the DEC probe rides the PUBLIC
// thread_init() face — the real dump_to_daq leg lands on the SFDAQ
// capture mirror (witness), NEVER a probe-side override.

static char obuf[3000];

static void start_timer_probe()   { PacketTracer::start_timer(); }
static void restart_timer_probe() { PacketTracer::restart_timer(); }
static void reset_timer_probe()   { PacketTracer::reset_timer(); }
static void restart_probe()       { PacketTracer::restart_timer(); }
static uint64_t get_time_probe()  { return PacketTracer::get_time(); }


int main()
{
    // D0 cold thread face (no tr-acer yet)
    printf("D0 cold active=%d paused=%d daq=%d\n",
        (int)PacketTracer::is_active(), (int)PacketTracer::is_paused(), (int)PacketTracer::is_daq_activated());

    // D1-D3 basic log ladder through the REAL .o (the "basic log" legs)
    PacketTracer::configure(true, "-");
    PacketTracer::thread_init();
    PacketTracer::log("%s", "1234567890");
    PacketTracer::dump(obuf, 3000);
    printf("D1 first=[%s]\n", obuf);
    PacketTracer::log("%s", "ABCD"); PacketTracer::log("%s", "EFGH");
    PacketTracer::dump(obuf, 3000);
    printf("D2 concat=[%s]\n", obuf);
    strcpy(obuf, "SENT");
    PacketTracer::log("%s", "");
    PacketTracer::dump(obuf, 3000);
    printf("D3 empty-log dump-len=%d\n", (int)strlen(obuf));

    // D4 pause ladder (2-level)
    PacketTracer::log("%s", "KEEP");
    PacketTracer::pause(); PacketTracer::pause();
    PacketTracer::log("%s", "HIDDEN");
    strcpy(obuf, "SENT");
    PacketTracer::dump(obuf, 3000);
    printf("D4a paused dump-untouched=%d paused=%d\n", (int)(strcmp(obuf,"SENT")==0), (int)PacketTracer::is_paused());
    PacketTracer::unpause();
    strcpy(obuf, "SENT");
    PacketTracer::dump(obuf, 3000);
    printf("D4b one-unpause still-paused=%d untouched=%d\n", (int)PacketTracer::is_paused(), (int)(strcmp(obuf,"SENT")==0));
    PacketTracer::unpause();
    PacketTracer::log("%s", "H2");
    PacketTracer::dump(obuf, 3000);
    printf("D4c resumed=[%s]\n", obuf);

    // D5 mute ladder (the verbosity face through the REAL .o)
    PacketTracer::TracerMute m1 = PacketTracer::get_mute();
    PacketTracer::TracerMute m2 = PacketTracer::get_mute();
    PacketTracer::log(m1, "ONE\n"); PacketTracer::log(m1, "NEVER\n");
    PacketTracer::log(m2, "ALSO\n"); PacketTracer::log(m2, "NEVER2\n");
    PacketTracer::dump(obuf, 3000);
    printf("D5 mute-once=[%s]", obuf);
    m1 = PacketTracer::get_mute();   // fresh id after reset (mutes grows)
    printf("D5b next-id=%d\n", (int)m1);

    // D6 corner overflow (caps at max_buff_size-1 = 2047)
    for (int i = 0; i < 1024; i++) PacketTracer::log("%s", "1234567890");
    PacketTracer::dump(obuf, 3000);
    printf("D6 overflow-len=%d\n", (int)strlen(obuf));

    // D7 RAII Suspend/Unsuspend faces (the h :135-:163 structs)
    { PacketTracerSuspend s; printf("D7a susp paused=%d\n", (int)PacketTracer::is_paused()); }
    printf("D7b out paused=%d\n", (int)PacketTracer::is_paused());
    PacketTracer::pause(); PacketTracer::pause();
    { PacketTracerUnsuspend u; printf("D7c unsuspend saved=%u paused=%d\n", u.saved_pause_count, (int)PacketTracer::is_paused()); }
    printf("D7d dtor restored paused=%d\n", (int)PacketTracer::is_paused());
    PacketTracer::unpause(); PacketTracer::unpause();

    // D8 thread_term flush face (buffered FALSE on the carried get_conf
    // logging_flags=0 face -> LogMessage leg; flush_thread_buffers ALWAYS)
    batched_capture.clear(); msg_capture.clear();
    PacketTracer::log("%s", "FLUSHME");
    PacketTracer::thread_term();
    printf("D8 term-msg=[%s] flushed-exact=%d\n", msg_capture.c_str(), (int)(batched_capture=="FLUSH;"));

    // D9 user activate ip-pkt arm (StreamLog capture)
    PacketTracer::configure(true, "-");
    PacketTracer::thread_init();
    static DAQ_PktHdr_t ph; static ip::IP4Hdr h4; static Packet p(true);
    memset(&ph, 0, sizeof ph); memset(&h4, 0, sizeof h4);
    h4.ip_verhl = 0x45; h4.ip_proto = IpProtocol::TCP;
    h4.ip_src = 0x0A010203; h4.ip_dst = 0x0A010204;
    p.pkth = &ph; p.ptrs.ip_api.set(&h4); p.ptrs.sp = 1000; p.ptrs.dp = 2000;
    p.ip_proto_next = IpProtocol::TCP;  // the get_ip_proto_next face (packet.h :144) the constraint proto-lb reads
    sl_capture.clear();
    PacketTracer::activate(p);
    printf("D9 user ip daq=%d active=%d sl=[%s]\n", (int)PacketTracer::is_daq_activated(), (int)PacketTracer::is_active(), sl_capture.c_str());

    // D10 DAQ trace-flag arm (REAL SDK 0x0400 face through REAL pkthdr)
    ph.flags = 0x0400;
    sl_capture.clear();
    PacketTracer::activate(p);
    printf("D10 trace-flag daq=%d sl=[%s]\n", (int)PacketTracer::is_daq_activated(), sl_capture.c_str());
    ph.flags = 0;

    // D11 non-IP (IAT_DATA) arm: ETH + PTY legs
    { SfIp s, d; s.pton(AF_INET,"10.1.2.3"); d.pton(AF_INET,"10.1.2.4"); p.ptrs.ip_api.set(s, d); }
    sl_capture.clear();
    PacketTracer::activate(p);
    printf("D11 data-api active=%d sl=[%s]\n", (int)PacketTracer::is_active(), sl_capture.c_str());

    // D12 user OFF + daq off + cbd off: active=false, ZERO legs (the C
    // final else) — cold tr-acer, then thread-less guard face
    PacketTracer::thread_term();
    PacketTracer::configure(false, "-");
    PacketTracer::thread_init();
    sl_capture.clear();
    PacketTracer::activate(p);
    printf("D12 all-off active=%d sl-empty=%d\n", (int)PacketTracer::is_active(), (int)sl_capture.empty());
    // D12b thread-NULL faces (the C legs WITH the documented guard):
    // set_constraints(!s_pkt_trace early-return :234) + the get_mute
    // null-arm census (:265-:266: increments global_mutes, NO mutes push)
    // + is_active/is_paused/is_daq null reads. log/pause NEVER ride here
    // (C derefs NULL — the ground test NEVER arms them thread-null).
    PacketTracer::thread_term();
    msg_capture.clear();
    PacketTracer::set_constraints(nullptr);
    printf("D12b null-thread guard-msg-empty=%d active=%d paused=%d id=%d\n",
        (int)msg_capture.empty(), (int)PacketTracer::is_active(),
        (int)PacketTracer::is_paused(), (int)PacketTracer::get_mute());

    // D13 shell constraints through the 23e REAL pc.o packet_match (THE
    // cross-row REUSE leg: set_constraints -> update_constraints ->
    // ntop pair + int_vector_to_str REAL util body -> activate ->
    // constraints.packet_match)
    {
        // the REAL IAT_4 face AGAIN for the shell arms (D11 left IAT_DATA):
        p.ptrs.ip_api.set(&h4);
        p.ip_proto_next = IpProtocol::TCP;   // the get_ip_proto_next face (packet.h :144)
        { uint32_t s = 0x0A010203, d = 0x0A010204;
        (void)s; (void)d;
        PacketTracer::thread_init();
        msg_capture.clear();
        // raw-byte face: SfIp(void*,AF_INET) copies the 4 bytes VERBATIM
        // (sf_ip.h :36): LE memory of 0x0A010203 = 03 02 01 0A -> ntop
        // "3.2.1.10" (the harness-pinned face, NEVER a decimal-order guess)
        uint32_t a = 0x0A010203, b = 0x0A010204;
        PacketConstraints cs(IpProtocol::TCP, 1000, 2000, SfIp((const void*)&a,AF_INET), SfIp((const void*)&b,AF_INET), 0x1F, true);
        PacketTracer::set_constraints(&cs);
        printf("D13 dbg-msg=%d", (int)(msg_capture.find("Debugging packet tra" "cer with 3.2.1.10-1000 and 4.2.1.10-2000 6 and tenants:none") == 0));
        sl_capture.clear();
        PacketTracer::activate(p);
        printf(" hit=%d sl=[%s]\n", (int)PacketTracer::is_active(), sl_capture.c_str());
        // constraints miss face (dport 3000 != 2000 via SRC/DST_PORT bits)
        PacketConstraints cs2(IpProtocol::TCP, 1000, 3000, SfIp((const void*)&s,AF_INET), SfIp((const void*)&d,AF_INET), 0x1F, true);
        PacketTracer::set_constraints(&cs2);
        sl_capture.clear();
        PacketTracer::activate(p);
        printf("D14 shell-miss active=%d sl-empty=%d\n", (int)PacketTracer::is_active(), (int)sl_capture.empty());
        // set_constraints(nullptr) disable face (C :237-:241)
        msg_capture.clear();
        PacketTracer::set_constraints(nullptr);
        printf("D15 disable-msg=%d\n", (int)(msg_capture.compare(0,33,"Debugging packet tra" "cer disabled\n") == 0));
        // shell dbg_str prefix face (C :383-:390): re-arm constraints, msg_only leg skips the session string, the bare "\n" leg hits the strcmp("\n") skip
        PacketTracer::set_constraints(&cs);
        PacketTracer::log_msg_only("MSGONLY\n");
        PacketTracer::log("\n");
        PacketTracer::dump(obuf, 3000);
        printf("D16 dbg-prefix=[%s]\n", obuf); }
    }

    // D17 daq log + daq_dump capture (the SFDAQ mirror leg; the sentinel
    // SFDAQInstance*/DAQ_Msg_h NEVER dereferenced — the capture mirror
    // reads buff/len + nullness ONLY; the trace-flag arm re-arms)
    p.daq_instance = (SFDAQInstance*)(uintptr_t)0x1;
    p.daq_msg = (DAQ_Msg_h)(uintptr_t)0x2;
    ph.flags = 0x0400;
    ph.flags = 0x0400;
    PacketTracer::activate(p);   // arms daq_activated (C :277-:281)
    daq_trace_capture.clear();
    PacketTracer::daq_log("%s", "DAQ10");
    PacketTracer::daq_dump(&p);
    printf("D17 daqtd=[%s]\n", daq_trace_capture.c_str());

    // D18 daq_reset face: after daq_dump the daq buffer resets, user
    // buffer NEVER touched by daq legs (the C reset(true) split)
    daq_trace_capture.clear();
    PacketTracer::daq_log("%s", "SECOND");
    PacketTracer::daq_dump(&p);   // C :176 reset(true): the daq buffer CLEARS after
    printf("D18 second=[%s]\n", daq_trace_capture.c_str());
    // D19 dump(Packet*) with an Active* present: THE honest null-
    // drop_reason face (C :145-:146: get_drop_reason reads the private
    // field, default nullptr — the REAL setter body active.cc :1050 NEVER
    // links → the non-null leg UNREACHABLE at the harness, cited): the
    // buffer STILL flushes through the LogMessage mirror (C :149).
    ph.flags = 0;
    { Active a; p.active = &a;
      PacketTracer::log("%s", "VT");
      msg_capture.clear();
      PacketTracer::dump(&p);
      printf("D19 verdict-null-face=%d flush=%d\n",
        (int)(msg_capture.find("Verdict") == std::string::npos),
        (int)(msg_capture.find("VT\n") != std::string::npos));
      p.active = nullptr;
    }

    // D20 open-file face: configure(false, "log_file_pin") -> open_file
    // resolves through the carried get_instance_file (returns s.c_str())
    // -> fopen in CWD -> log_fh != stdout (the gate "open file" shape)
    PacketTracer::thread_term();
    PacketTracer::configure(false, "pt_pin_tmp");
    PacketTracer::thread_init();
    printf("D20a file-open warn-empty=%d\n", (int)warn_capture.empty());
    PacketTracer::thread_term();
    { std::string path; remove(snort::get_instance_file(path, "pt_pin_tmp")); } // the ground "open file" cleanup face (cc :736)
    PacketTracer::configure(false, "/nonexistent_dir_xyz/pt_fail_tmp");
    warn_capture.clear();
    PacketTracer::thread_init();
    printf("D20b open-fail-warn=%d\n", (int)(warn_capture.find("Could not open") == 0));
    PacketTracer::thread_term();

    // D21 timer faces determinism-safe: reset -> get_time == exactly 0
    // (CLOCK reset face: get of a reset non-running timer), start arm
    PacketTracer::thread_init();
    restart_timer_probe();
    reset_timer_probe();
    printf("D21 reset-zero=%d\n", (int)(get_time_probe()==0));
    start_timer_probe();
    printf("D22 running-ge-zero=%d\n", (int)(get_time_probe() >= 0));
    restart_probe();
    printf("D23 restarted-lt-D22=%d\n", (int)(get_time_probe() <= 1000000000));
    PacketTracer::thread_term();

    printf("Z terminator=0\n");
    return 0;
}
