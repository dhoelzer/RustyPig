// witness_row.cc — row 24i witness mirror (shape-only capture legs for the
// NEVER-LAND wall the row .o's OWN nm -C census enumerates (plain EXACTLY-34,
// MEASURED); EVERY name + namespace placement rides the row's OWN raw-NAME
// nm -C CENSUS face — the compiler ENFORCED the restructure honestly). The
// ONE leg that links REAL and is NEVER mirrored here: framework/module.cc
// (the Module stats home the ACGetStats ctor/execute/dtor ladder drives
// LIVE — init_stats/collect_dump_stats_counts/aggregate_dump_stats_
// counts/set_dump_stats_results/sum_stats bodies are REAL ground code in
// the closed hull; the leg's OWN nm face drags the show_stats mirror). The
// row's OWN six cc-file-statics (:55 report_time the THREAD_LOCAL, :56
// report_period, :57 invalid_ip, :60 format_ip_addr, :74 tuner_next, :83
// tuner_update) + the h :104 string_map are NEVER mirrored — the ROW TU
// DEFINES them (the E9 twin law). The SFDAQInstance::ioctl wall mirror POKES
// the DIOCTL out-structs with fixed binary-exact payloads (the %.1f/%.3f
// report ladders NEVER ride a half-tie; the call-count arms ride a fixed
// probe order — the deterministic witness law: ZERO heap pointers, ZERO
// wall-clock times, ZERO randomness in the vectors). The packet_gettimeofday
// mirror feeds crafted FIXED timevals (+20 s per call vs the REAL :56
// 10-s report_period — the tuner timer arithmetic REAL). NO private-access
// flag EVER ships: every mirror is a member/ctor of ITS OWN class touching
// its OWN privates exactly as the ground does; the SnortConfig tuner-
// injection face rides the PUBLIC h :710 inline const-ref through a probe
// const_cast (the conf object itself is NON-const by construction).
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <list>
#include <mutex>
#include <string>
#include <vector>
#include <array>

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/reload_tracker.h"
#include "main/reload_tuner.h"
#include "main/swapper.h"
#include "main/thread_config.h"
#include "main/thread.h"
#include "main/stats_output_format.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "framework/module.h"
#include "framework/counts.h"
#include "framework/parameter.h"
#include "packet_io/sfdaq_instance.h"
#include "helpers/scratch_allocator.h"
#include "protocols/packet_manager.h"
#include "target_based/host_attributes.h"
#include "time/packet_time.h"
#include "utils/stats.h"
#include "control/control.h"
#include "log/messages.h"

using namespace snort;

// ---- witness-settable deterministic controls (probe-driven, pinned once;
// NEVER a time/pointer/random face). ----
static unsigned w_instance_id = 0;          // the get_instance_id seat
static long w_pticks = 0;                   // the crafted packet-clock arm
static int w_analyzer_state = 3;            // the Analyzer ctor state seat (RUNNING=3)
static int w_daq_idx = 0;                   // the ioctl call-sequence arm (fixed probe order)
static unsigned w_imax = 1;                 // the instance-max mirror seat
static std::list<Module*> w_modules;        // the get_all_modules mirror face
extern "C" void witness_set_instance_id(unsigned i) { w_instance_id = i; }
extern "C" void witness_analyzer_ctor_state(int s) { w_analyzer_state = s; }
extern "C" int witness_daq_idx() { return w_daq_idx; }
extern "C" void witness_reset_daq_idx() { w_daq_idx = 0; }
extern "C" void witness_set_modules(Module** mods, int n)
{ w_modules.clear(); for (int i = 0; i < n; ++i) w_modules.push_back(mods[i]); }

// ---- main/thread.cc NEVER lands: the identity seat census face. ----
namespace snort { unsigned get_instance_id() { return w_instance_id; } }

// ---- main/thread_config.cc NEVER lands (the hwloc wall the donor already
// excised): the two statics + the tid seat the census + report ladders pull. ----
void ThreadConfig::set_instance_max(unsigned m)
{ w_imax = m; printf("W ThreadConfig::set_instance_max %u\n", m); }
unsigned ThreadConfig::get_instance_max() { return w_imax; }
int ThreadConfig::get_instance_tid(int idx) { printf("W ThreadConfig::get_instance_tid %d\n", idx); return 3100 + idx; }
ThreadConfig::~ThreadConfig() { printf("W ThreadConfig.dtor\n"); }

// ---- time/packet_time.cc NEVER lands: the crafted FIXED clock (+5 s per
// call vs the REAL 10-s report_period (:56): the tuner ladder legs then
// walk BOTH timercmp arms — the :83 tuner_update equal/under-face twice +
// the fire-face with the REAL :55 report_time arithmetic — deterministi-
// cally on the fixed tick counter (ZERO wall-clock faces). ----
namespace snort {
void packet_gettimeofday(struct timeval* tv)
{ tv->tv_sec = 100 + 5 * (w_pticks++); tv->tv_usec = 0; }
}

// ---- log/messages.cc NEVER lands: the LogMessage varargs pair (the row's
// log_message core + every "== " report + the tuner run/complete legs ride
// them; the mirrors vprintf the ROW's OWN format calls — deterministic). ----
namespace snort {
void LogMessage(const char* fmt, ...)
{
    printf("L ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
void LogMessage(const char* fmt, va_list& ap)
{
    printf("L ");
    vprintf(fmt, ap);
}
void ErrorMessage(const char* fmt, ...) { printf("W ErrorMessage\n"); (void)fmt; }
}

// ---- control/control.cc NEVER lands (the shell/socket read wall): the
// respond pair + the ctor/dtor the probe's two crafted conns (local fd=3,
// remote fd=4) construct. is_local() rides the GROUND const inline
// (control.h :69) reading the ctor-stored member — the local-vs-remote
// echo fork is REAL row logic. ----
ControlConn::ControlConn(int fd, bool local)
    : shell(nullptr), fd(fd), local(local)
{ printf("W ControlConn.ctor fd=%d local=%d\n", fd, local ? 1 : 0); }
ControlConn::~ControlConn() { printf("W ControlConn.dtor fd=%d\n", fd); }
bool ControlConn::respond(const char* fmt, va_list& ap)
{
    printf("R ");
    vprintf(fmt, ap);
    return true;
}
bool ControlConn::respond(const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    bool r = respond(fmt, ap);
    va_end(ap);
    return r;
}

// ---- main/analyzer.cc NEVER lands (the message-loop wall): the ctor stores
// its OWN privates (the ctor arm's state seat drives the PAUSED-OR-RUNNING gate
// + the NEW-face reject REAL through the h inline get_state(); the
// is_idling() face rides the NSDMI-false inline). The seven command legs. ----
Analyzer::Analyzer(snort::SFDAQInstance* di, unsigned ident, const char* src,
    uint64_t, const uint32_t)
    : id(ident), source(src ? src : ""), daq_instance(di),
      retry_queue(nullptr), oops_handler(nullptr)
{
    state = (Analyzer::State)w_analyzer_state;
    printf("W Analyzer.ctor id=%u daq=%d state=%d\n", ident, di ? 1 : 0, w_analyzer_state);
}
Analyzer::~Analyzer() { printf("W Analyzer.dtor\n"); }
void Analyzer::start()  { printf("W Analyzer.start\n"); }
void Analyzer::run(bool paused) { printf("W Analyzer.run paused=%d\n", paused ? 1 : 0); }
void Analyzer::stop()   { printf("W Analyzer.stop\n"); }
void Analyzer::pause()  { printf("W Analyzer.pause\n"); }
void Analyzer::resume(uint64_t msg_cnt) { printf("W Analyzer.resume cnt=%llu\n", (unsigned long long)msg_cnt); }
void Analyzer::reload_daq() { printf("W Analyzer.reload_daq\n"); }
void Analyzer::rotate() { printf("W Analyzer.rotate\n"); }

// ---- main/swapper.cc NEVER lands: stores its OWN new_conf seat; the row's
// ps->get_new_conf() rides the GROUND inline (swapper.h :46) — the conf
// flows REAL through the entire ACSwap ladder. ----
Swapper::Swapper(snort::SnortConfig* s)
    : old_conf(nullptr), new_conf(s)
{ printf("W Swapper.ctor\n"); }
Swapper::Swapper(const snort::SnortConfig* sold, snort::SnortConfig* snew)
    : old_conf(sold), new_conf(snew)
{ printf("W Swapper.ctor2\n"); }
Swapper::~Swapper() { printf("W Swapper.dtor\n"); }
void Swapper::apply(Analyzer&) { printf("W Swapper.apply\n"); }
void Swapper::finish() { printf("W Swapper.finish\n"); }

// ---- main/snort_config.cc NEVER lands AT THIS ROW (the 24g config-owner
// home): the two census seats + the ctor/dtor the probe's crafted conf
// rides (the reload_tuners seat rides the NSDMI-empty face). ----
SnortConfig::SnortConfig(const char* exclude_name)
{ printf("W SnortConfig.ctor ex=%s\n", exclude_name ? exclude_name : "(none)"); }
SnortConfig::~SnortConfig() { printf("W SnortConfig.dtor\n"); }
void SnortConfig::clear_reload_resource_tuner_list()
{ printf("W SnortConfig.clear_tuner_list\n"); }

// ---- main/reload_tracker.cc NEVER lands: the end() seat the three reload
// dtors drag (the prompt-leg face rides the arg). ----
namespace snort {
void ReloadTracker::end(const ControlConn*, bool prompt)
{ printf("W ReloadTracker.end prompt=%d\n", prompt ? 1 : 0); }
}

// ---- target_based/host_attributes.cc NEVER lands: the two swap seats (the
// class rides GLOBAL scope exactly as the raw-NAME nm census face shows). ----
void HostAttributesManager::initialize() { printf("W HostAttributesManager.initialize\n"); }
void HostAttributesManager::swap_cleanup() { printf("W HostAttributesManager.swap_cleanup\n"); }

// ---- managers/module_manager.cc NEVER lands: the stats wall + the
// reset_stats ENUM face (the ACResetStats legs drive the REAL h :88-:99
// ordinals straight through) + the mutex DEFINITION the REAL lock_guard
// seat inside ACGetStats::execute needs (the lock itself is ground code). ----
namespace snort {
std::mutex ModuleManager::stats_mutex;
bool ModuleManager::is_dynamic_stats_module(const Module* m)
{ printf("W MM.is_dynamic_stats %s\n", m ? m->get_name() : "(null)"); return false; }
void ModuleManager::collect_global_dump_stats(Module* m)
{ printf("W MM.collect_global_dump_stats %s\n", m ? m->get_name() : "(null)"); }
void ModuleManager::get_accumulated_counts(Module* m, unsigned thread_idx, std::vector<PegCount>& out)
{ printf("W MM.get_accumulated_counts %s t=%u\n", m ? m->get_name() : "(null)", thread_idx); out.assign(3, 40); }
void ModuleManager::reset_stats(clear_counter_type_t t)
{ printf("W MM.reset_stats type=%d\n", (int)t); }
}

// ---- managers/plugin_manager.cc NEVER lands: the ALL-modules seat (the
// REAL ACGetStats ctor body stores the returned list through the witness-
// pinned probe module table — deterministic names, ZERO heap surprises; the
// class rides GLOBAL scope per the raw-NAME nm census face). ----
std::list<snort::Module*> PluginManager::get_all_modules(const snort::SnortConfig*)
{ printf("W PM.get_all_modules n=%zu\n", w_modules.size()); return w_modules; }

// ---- protocols/packet_manager.cc NEVER lands: the two fixed stat-table
// fills the REAL ~ACGetStats summation legs then fold REAL (display =
// global_before + thread_sum inside the row body — the arithmetic is REAL
// ground code, only the inputs are crafted fixed). ----
namespace snort {
void PacketManager::get_thread_stats(Stats& out)
{ out.fill(0); out[0] = 7; out[1] = 11; out[2] = 13; out[3] = 17; printf("W PM.get_thread_stats 7|11|13|17\n"); }
void PacketManager::get_global_stats(Stats& out)
{ out.fill(0); out[0] = 101; out[1] = 103; out[2] = 107; out[3] = 109; printf("W PM.get_global_stats 101|103|107|109\n"); }
}

// ---- utils/stats.cc NEVER lands: the DropStats banner home (the REAL
// ~ACGetStats leg) — the mirror echoes the REAL display sums the row body
// computed (name+arg law; the fold itself already happened in the row). ----
void DropStats(ControlConn* ctrlcon, bool already_accumulated,
    const snort::PacketManager::Stats* packet_stats, StatsOutputFormat format)
{
    unsigned long long s0 = 0, s1 = 0;
    if (packet_stats)
        for (size_t i = 0; i < 4; ++i) { s0 += (*packet_stats)[i]; if (i < 2) s1 += (*packet_stats)[i]; }
    printf("W DropStats acc=%d sum4=%llu sum2=%llu fmt=%d ctrl=%d\n",
        already_accumulated ? 1 : 0, s0, s1, (int)format, ctrlcon ? 1 : 0);
}
void show_stats(const PegCount*, const PegInfo*, unsigned, const char*)
{ printf("W show_stats\n"); }
void show_stats(const PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*)
{ printf("W show_stats_ivecs\n"); }

// helpers/scratch_allocator.cc NEVER lands: the base ctor/dtor the probe's
// two crafted allocators' vtables drag (the id seat rides its OWN member).
ScratchAllocator::ScratchAllocator() { printf("W ScratchAllocator.ctor\n"); id = 0; }
ScratchAllocator::~ScratchAllocator() { printf("W ScratchAllocator.dtor\n"); }

// the clear seat the REAL ~ACGetStats tail drag (the census face).
namespace snort {
void ModuleManager::clear_global_active_counters() { printf("W MM.clear_global_active_counters\n"); }
}

// ---- packet_io/sfdaq_instance.cc NEVER lands (the acquisition wall): the
// ioctl WALL MIRROR POKES the two DIOCTL out-structs deterministically per
// the fixed call table idx 0..4: 0 = CPU poke A {12.5, 25.0, 6.0}; 1 = CPU
// poke B {2.5, 5.0, 1.0}; 2 = CPU FAILURE status (the :476 reject leg);
// 3 = latency poke A (TCP full legs + UDP all-zero skips + Others partial
// arms, v4 5-tuples); 4 = latency poke B (the v6 5-tuple faces + the null-
// conn-meta leg). EVERY value is binary-exact (.5/.25 quarters; average =
// sum/count/1000 rides .375/.5/.125) — ZERO %.1f/%.3f half-tie; ZERO time,
// ZERO randomness. The SFDAQInstance ctor/dtor the probe's crafted handle
// NEVER rides (the probe drives its OWN instance handle through the
// Analyzer's stored seat — the mirror NEVER touches instance privates). ----
namespace snort {
SFDAQInstance::SFDAQInstance(const char* intf, unsigned id, const SFDAQConfig*)
{ printf("W SFDAQInstance.ctor if=%s id=%u\n", intf ? intf : "(null)", id); }
SFDAQInstance::~SFDAQInstance() { printf("W SFDAQInstance.dtor\n"); }
int SFDAQInstance::ioctl(DAQ_IoctlCmd cmd, void* arg, unsigned long arglen)
{
    int idx = w_daq_idx++;
    printf("W SFDAQ.ioctl call=%d cmd=%d arglen=%lu\n", idx, (int)cmd, arglen);
    if (cmd == (DAQ_IoctlCmd)DIOCTL_GET_CPU_PROFILE_DATA)
    {
        if (idx == 2) return 1;                       // the DAQ_SUCCESS reject leg
        auto* d = (DIOCTL_GetCpuProfileData*)arg;
        d->cpu_usage_percent_30s  = idx == 0 ? 12.5f : 2.5f;
        d->cpu_usage_percent_120s = idx == 0 ? 25.0f : 5.0f;
        d->cpu_usage_percent_300s = idx == 0 ? 6.0f  : 1.0f;
        return DAQ_SUCCESS;
    }
    if (cmd == (DAQ_IoctlCmd)DIOCTL_GET_SNORT_LATENCY_DATA && arglen == sizeof(DIOCTL_GetSnortLatencyData))
    {
        auto* l = (DIOCTL_GetSnortLatencyData*)arg;
        memset(l, 0, sizeof(*l));
        if (idx == 3)
        {
            // TCP: full leg face — average 4000/8/1000 = .5 exact; the v4
            // 5-tuples 203.2.113.7:80 -> 203.2.113.9:443 (in6 seats hold
            // the v4 in the first four bytes, flags v4)
            auto& t = l->snort_latency_data[DAQ_SNORT_LATENCY_PROTO_TCP];
            t.max_pkt_time = 1500; t.snort_up_max_pkt_time = 2500;
            t.pkt_count = 8; t.sum_time = 4000; t.conn_meta_null_counters = 3;
            t.max_pkt_src_addr.s6_addr[0] = 203; t.max_pkt_src_addr.s6_addr[1] = 2;
            t.max_pkt_src_addr.s6_addr[2] = 113; t.max_pkt_src_addr.s6_addr[3] = 7;
            t.max_pkt_dst_addr.s6_addr[0] = 203; t.max_pkt_dst_addr.s6_addr[1] = 2;
            t.max_pkt_dst_addr.s6_addr[2] = 113; t.max_pkt_dst_addr.s6_addr[3] = 9;
            t.max_pkt_src_port = 80; t.max_pkt_dst_port = 443;
            t.snort_up_max_pkt_src_addr.s6_addr[0] = 10; t.snort_up_max_pkt_src_addr.s6_addr[3] = 1;
            const unsigned char v6[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
            memcpy(t.snort_up_max_pkt_dst_addr.s6_addr, v6, 16);
            t.snort_up_max_pkt_src_ipv6 = 0; t.snort_up_max_pkt_dst_ipv6 = 1;
            t.snort_up_max_pkt_src_port = 53; t.snort_up_max_pkt_dst_port = 5353;
            // UDP rides ALL-ZERO (the :514/:517/:520/:523/:526/:529 skip arms)
            // Others: the snort-up-only lat + the fixed counts + the v4 MAX
            // face the ZERO-port reject arms (the :534 condition false leg)
            auto& o = l->snort_latency_data[DAQ_SNORT_LATENCY_PROTO_OTHERS];
            o.snort_up_max_pkt_time = 777; o.pkt_count = 16; o.sum_time = 6000;   // avg .375 exact
            o.max_pkt_src_addr.s6_addr[0] = 198; o.max_pkt_src_addr.s6_addr[1] = 51;
            o.max_pkt_src_addr.s6_addr[2] = 100; o.max_pkt_src_addr.s6_addr[3] = 4;
            o.max_pkt_dst_addr.s6_addr[0] = 198; o.max_pkt_dst_addr.s6_addr[1] = 51;
            o.max_pkt_dst_addr.s6_addr[2] = 100; o.max_pkt_dst_addr.s6_addr[3] = 5;
            o.max_pkt_src_port = 0; o.max_pkt_dst_port = 0;                       // the zero-port reject
        }
        else if (idx == 4)
        {
            // poke B: the second-instance TCP face with the v6 MAX pair +
            // the MAX peg face (avg .125 exact)
            auto& t = l->snort_latency_data[DAQ_SNORT_LATENCY_PROTO_TCP];
            const unsigned char v6s[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,1, 0,0,0,0, 0,0,0,2 };
            const unsigned char v6d[16] = { 0xfe,0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,9 };
            memcpy(t.max_pkt_src_addr.s6_addr, v6s, 16);
            memcpy(t.max_pkt_dst_addr.s6_addr, v6d, 16);
            t.max_pkt_src_ipv6 = 1; t.max_pkt_dst_ipv6 = 1;
            t.max_pkt_src_port = 8080; t.max_pkt_dst_port = 443;
            t.pkt_count = 8; t.sum_time = 1000;    // avg 1000/8/1000 = .125 exact
            t.max_pkt_time = 2000;
        }
        return DAQ_SUCCESS;
    }
    return 1;
}
}
