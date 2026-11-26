// witness (row 24d): the app-level undefined mirror for the analysis-loop
// row TU (the 23b/22a mirror law). EVERY body is a SHAPE-ONLY capture mirror
// of a NOT-landed home. THE GROUND DONOR for this row's mirror SET is the
// ground's OWN test-stub TU main/test/distill_verdict_stubs.h (277 L, the
// ENABLE_SHELL dialect host the row TU itself rides at main/test/CMakeLists
// :7-:12) — re-cloned WITH rec() legs (the stubs' body SET is the ground
// face of which walls stand in; my file NEVER copies the file, it mirrors
// the same wall SET per the banked deviation). The DAQ wrapper seats are the
// C++ capture mirrors over the REAL libdaq@ heads (the SDK swap face, the
// 24b law); the conf slot rides the carried SUBSET-CTOR precedent (22a tc /
// 24a sn-proc / 24b / 24c). BODIES NEVER land; the rec() legs feed the DEC
// order ladder ONLY. The namespace placement of every leg rides the row .o's
// OWN nm -C census face (the MEASURED walk — build.sh asserts the census;
// this file NEVER guesses it). The family rule: the ground row-name NEVER
// rides this file joined; comments split the family (sn-proc / sh-ell /
// h-proc-ess / the anal-yzer loop).
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/snort_config.h"
#include "oops_handler.h"
#include "main/policy.h"
#include "main/swapper.h"
#include "main/thread.h"
#include "main/thread_config.h"
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_instance.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/sfdaq_module.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "detection/detection_engine.h"
#include "detection/context_switcher.h"
#include "detection/ips_context.h"
#include "detection/detection_buf.h"
#include "detection/tag.h"
#include "detection/event_trace.h"
#include "flow/flow.h"
#include "flow/ha.h"
#include "framework/data_bus.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "log/messages.h"
#include "managers/codec_manager.h"
#include "managers/event_manager.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "memory/memory_cap.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "time/packet_time.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "target_based/host_attributes.h"
#include "trace/trace_api.h"
#include "filters/sfthreshold.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "profiler/profiler_impl.h"
#include "profiler_defs.h"
#include "memory_defs.h"
#include "rule_profiler_defs.h"
#include "time_profiler_defs.h"
#include "file_api/file_service.h"
#include "file_api/file_capture.h"
#include "protocols/packet.h"
#include "main.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <vector>

std::vector<std::string> g_probe_trace;
void probe_reset_trace() { g_probe_trace.clear(); }
static void rec(const char* n) { g_probe_trace.push_back(n); }
void probe_rec(const char* n) { g_probe_trace.push_back(n); }   // probe-side mock legs feed the SAME ladder
const char* probe_legs()
{
    static std::string s;
    s.clear();
    for (size_t i = 0; i < g_probe_trace.size(); ++i)
    { if (i) s += "|"; s += g_probe_trace[i]; }
    return s.c_str();
}

// scripted capture faces (the probe arms these BEFORE the legs drive):
unsigned g_log_count = 0;
unsigned g_err_count = 0;
unsigned g_poke_count = 0;
bool g_daq_start_ok = true;
unsigned g_rstat_seq[8] = { 0 };        // per-receive rstat script
unsigned g_rstat_count = 0;
unsigned g_rstat_idx = 0;
DAQ_Msg_t** g_msg_seq = nullptr;       // per-receive batch script (NULL-tail)
unsigned g_msg_script_idx = 0;
const char* g_input_spec = "d-in";
const char* g_daq_error = "d-err";
unsigned g_run_num_face = 2;
uint8_t g_grinder_face = 1;
char* g_exbuf = nullptr;               // exported finalize-verdict echo seat
unsigned g_ctx_ctors = 0;              // the IpsContext ctor count face

// the pair's THREAD_LOCAL globals (the mangled-name law, the census face:
// daq_stats is GLOBAL-bare, snort::pc rides the ns block below; the ROW .o
// defines daqPerfStats (cc :93) — NEVER mirrored HERE (the E9 law)):
THREAD_LOCAL DAQStats daq_stats;

// ======================================================================
// GLOBAL-scope seats (the census face, the bare names — the classes the
// headers declare OUTSIDE namespace snort; the mirror NEVER re-places):
// ======================================================================
bool exit_requested = false;   // main.h :25 (THIRD ground face seat; the
                               // loop branches on the CLASS MEMBER; define
                               // ONLY for the sibling link faces)
void main_poke(unsigned) { rec("poke"); g_poke_count++; }
void set_instance_id(unsigned) { rec("set_inst"); }
void set_thread_type(SThreadType) { rec("set_type"); }
void set_run_num(uint16_t) { rec("set_run_num"); }
uint16_t get_run_num() { return (uint16_t)g_run_num_face; }
void packet_time_update(const timeval*) { rec("pkt.timeupd"); }
int sfthreshold_alloc(unsigned, unsigned) { rec("sf.thr-alloc"); return 0; }
void sfthreshold_free() { rec("sf.thr-free"); }
void sfthreshold_reset() { rec("sf.thr-reset"); }
void InitTag() { rec("tag.init"); }              // the bare-name seats per
void CleanupTag() { rec("tag.clean"); }          // the OWN nm -C census
void EventTrace_Init() { rec("et.init"); }       // face (the headers
void EventTrace_Term() { rec("et.term"); }       //  declare GLOBAL-bare)
void SFRF_Alloc(unsigned) { rec("rf.alloc"); }   // sfrf.h :211 (ns close
                                                 // before the decl — bare)
bool snort_ignore(snort::Packet*)                // mitigator_api.h :72,
{ rec("ignore"); return true; }                  // ns CLOSED before it:
// the harness mirror keeps the packet path ALIVE past the hook (the probe
// arms the analyze()/process legs); the ground leg NEVER lands (shape law).


void OopsHandler::tinit() { rec("oops.tinit"); }
void OopsHandler::tterm() { rec("oops.tterm"); }
void OopsHandler::set_current_message(DAQ_Msg_h, snort::SFDAQInstance*) { rec("oops.set"); }

// the wall-command execute mirrors (the NEVER-land facility; ONLY the
// legs the ladder reaches; stringify rides the header inlines):
bool ACPause::execute(Analyzer&) { rec("ac.pause"); return true; }
bool ACResume::execute(Analyzer&) { rec("ac.resume"); return true; }
bool ACRotate::execute(Analyzer&) { rec("ac.rotate"); return true; }
bool ACRun::execute(Analyzer&) { rec("ac.run"); return true; }
bool ACStart::execute(Analyzer&) { rec("ac.start"); return true; }
bool ACStop::execute(Analyzer&) { rec("ac.stop"); return true; }

Swapper::Swapper(snort::SnortConfig*) { rec("sw.ctor"); }
Swapper::~Swapper() { rec("sw.dtor"); }
void Swapper::apply(Analyzer&) { rec("sw.apply"); }

snort::IpsContext* g_ctx0 = nullptr;        // the FIRST pushed context seat
unsigned g_cs_pushed = 0, g_cs_starts = 0, g_cs_stops = 0;
extern snort::Active g_w_mirror_active;     // the packet wiring seat below
ContextSwitcher::~ContextSwitcher() { rec("cs.dtor"); }
void ContextSwitcher::push(snort::IpsContext* c)
{
    g_cs_pushed++;
    if (c && !c->packet)
    {
        // the mirror wiring seat (ground ips_ctx ctor seats the row inlines
        // read; real ctor NEVER runs — the stub-shape ctor leaves them null
        // per the ground stub law):
        c->packet = new snort::Packet(false);
        c->packet->context = c;
        c->packet->active = &g_w_mirror_active;
        if (!g_ctx0) g_ctx0 = c;
    }
}
void ContextSwitcher::start() { rec("cs.start"); g_cs_starts++; }
void ContextSwitcher::stop() { rec("cs.stop"); g_cs_stops++; }
snort::IpsContext* ContextSwitcher::get_context() const
{
    rec("cs.ctx");
    return g_ctx0;   // the mirror hands back the FIRST pushed seat
}

void select_default_policy(const _daq_pkt_hdr&, const snort::SnortConfig*) { rec("pol.sel-pkt"); }
void select_default_policy(const _daq_flow_stats&, const snort::SnortConfig*) { rec("pol.sel-flow"); }

CodecManager::CodecManager() { }
CodecManager::~CodecManager() { }
uint8_t CodecManager::get_grinder() { rec("cdmgr.grind"); return g_grinder_face; }
void CodecManager::thread_init() { rec("cdmgr.tinit"); }
void CodecManager::thread_term() { rec("cdmgr.tterm"); }

void PluginManager::thread_init() { rec("plug.tinit"); }
void PluginManager::thread_reinit(const snort::SnortConfig*) { rec("plug.trein"); }
void PluginManager::thread_term(bool) { rec("plug.tterm"); }
void EventManager::close_outputs() { rec("evt.close"); }
void EventManager::open_outputs() { rec("evt.open"); }

void SideChannelManager::thread_init() { rec("sc.tinit"); }
void SideChannelManager::thread_term() { rec("sc.tterm"); }
void HostAttributesManager::initialize() { rec("ham.init"); }

namespace memory
{
void MemoryCap::free_space() { rec("mem.free"); }
void MemoryCap::thread_init() { rec("mem.tinit"); }
void MemoryCap::thread_term() { rec("mem.tterm"); }
}

void Profiler::start() { rec("prof.start"); }
void Profiler::stop(uint64_t) { rec("prof.stop"); }
void Profiler::consolidate_stats(snort::ProfilerType) { rec("prof.consol"); }
THREAD_LOCAL bool RuleContext::enabled = false;

void PacketLatency::tterm() { rec("lat.pktterm"); }
void RuleLatency::tterm() { rec("lat.ruleterm"); }
namespace packet_latency { void set_force_enable(bool) { rec("lat.pktforce"); } }
namespace rule_latency { void set_force_enable(bool) { rec("lat.ruleforce"); } }

void RateFilter_SessionRelease(snort::Flow&) { rec("rf.release"); }

// ======================================================================
// namespace snort seats (the census face: the snort::-prefixed names):
// ======================================================================
namespace snort
{
THREAD_LOCAL PacketCount pc;                    // stats.h :97 (ns seat)

void LogMessage(const char* fmt, ...)
{
    rec("log.msg"); g_log_count++;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "LOG %s", buf);
}
void ErrorMessage(const char* fmt, ...)
{
    rec("log.err"); g_err_count++;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "ERR %s", buf);
}

unsigned get_instance_id() { rec("get_inst"); return 0; }
void populate_instance_maps() { rec("maps.pop"); }
void invalidate_instance_maps() { rec("maps.inv"); }
void packet_gettimeofday(timeval* tv)
{ rec("pkt.tv"); if (tv) { tv->tv_sec = 0; tv->tv_usec = 0; } }

void ThreadConfig::apply_thread_policy(SThreadType, unsigned) { rec("tc.policy"); }
void ThreadConfig::kick_watchdog() { rec("tc.kick"); }
void ThreadConfig::update_thread_status(bool a) { rec(a ? "tc.status-on" : "tc.status-off"); }
void ThreadConfig::set_instance_tid(int) { rec("tc.tid"); }

// the conf slot (the 24b conf-boot face re-rides):
SnortConfig* g_probe_conf = nullptr;
const SnortConfig* SnortConfig::get_conf() { return g_probe_conf; }
SnortConfig::SnortConfig(const char*) { rec("conf.ctor"); }
SnortConfig::~SnortConfig() { }

// the DAQ wrapper mirrors over the REAL SDK heads (the C++ capture seats —
// NEVER an SDK ABI claim; the scripted receive leg arms the PRIVATE batch
// seats the inline next_message reads):
SFDAQInstance::SFDAQInstance(const char* intf, unsigned, const SFDAQConfig*)
{ rec("inst.ctor"); input_spec = intf ? intf : ""; batch_size = 3; }
SFDAQInstance::~SFDAQInstance() { rec("inst.dtor"); }
bool SFDAQInstance::init(DAQ_Config_h, const std::string&) { return true; }
bool SFDAQInstance::start() { rec("inst.start"); return g_daq_start_ok; }
bool SFDAQInstance::was_started() const { return true; }
bool SFDAQInstance::stop() { rec("inst.stop"); return true; }
void SFDAQInstance::reload() { rec("inst.reload"); }
DAQ_RecvStatus SFDAQInstance::receive_messages(unsigned)
{
    rec("inst.recv");
    unsigned idx = g_rstat_idx < g_rstat_count ? g_rstat_idx : g_rstat_count - 1;
    g_rstat_idx++;
    DAQ_RecvStatus r = (DAQ_RecvStatus)g_rstat_seq[idx];
    static DAQ_Msg_h batch[8];
    DAQ_Msg_t** seq = (g_msg_seq && g_msg_script_idx < 8)
        ? &g_msg_seq[g_msg_script_idx * 4] : nullptr;
    g_msg_script_idx++;
    unsigned n = 0;
    if (seq) while (n < 4 && seq[n]) { batch[n] = seq[n]; n++; }
    daq_msgs = n ? batch : nullptr;
    curr_batch_size = n;
    curr_batch_idx = 0;
    return r;
}
int SFDAQInstance::finalize_message(DAQ_Msg_h msg, DAQ_Verdict v)
{
    rec("inst.fin");
    if (msg && g_exbuf)
    {
        static const char* names[] = { "PASS","BLOCK","REPLACE","WHITELIST","BLACKLIST","IGNORE" };
        std::snprintf(g_exbuf, 64, "%s", (v <= DAQ_VERDICT_IGNORE) ? names[v] : "MAX");
    }
    return DAQ_SUCCESS;
}
const char* SFDAQInstance::get_error() { rec("inst.err"); return g_daq_error; }
int SFDAQInstance::get_base_protocol() const { return 0; }
const char* SFDAQInstance::get_input_spec() const { return g_input_spec; }
const DAQ_Stats_t* SFDAQInstance::get_stats() { static DAQ_Stats_t s{}; return &s; }
bool SFDAQInstance::interrupt() { rec("inst.interrupt"); return true; }

void SFDAQ::set_local_instance(SFDAQInstance*) { rec("sf.local"); }
const char* SFDAQ::verdict_to_string(DAQ_Verdict v)
{
    rec("sf.verdict");
    static const char* names[] = { "pass", "block", "replace", "whitelist", "blacklist", "ignore" };
    return (v <= DAQ_VERDICT_IGNORE) ? names[v] : "max";
}

void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { rec("bus.pub"); }
void DataBus::publish(unsigned, unsigned, Packet*, Flow*) { rec("bus.pub-pkt"); }
void DataBus::publish_to_all_network_policies(unsigned, unsigned) { rec("bus.pub-net"); }

bool Active::thread_init(const SnortConfig*) { rec("act.tinit"); return true; }
void Active::thread_term() { rec("act.tterm"); }
void Active::clear_queue(Packet*) { rec("act.clearq"); }
void Active::execute(Packet*) { rec("act.exec"); }
void Active::send_reason_to_daq(Packet&) { rec("act.reason"); }

void PacketTracer::thread_init() { rec("pt.tinit"); }
void PacketTracer::thread_term() { rec("pt.tterm"); }
void PacketTracer::activate(const Packet&) { rec("pt.actv"); }
bool PacketTracer::is_active() { return false; }
bool PacketTracer::is_daq_activated() { return false; }
void PacketTracer::daq_dump(Packet*) { rec("pt.daqdump"); }
void PacketTracer::dump(Packet*) { rec("pt.dump"); }
void PacketTracer::log(const char* fmt, ...)
{
    rec("pt.log");
    char buf[512];
    va_list ap; va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "TRC %s", buf);
}

void DetectionEngine::idle() { rec("de.idle"); }
void DetectionEngine::onload() { rec("de.onload"); }
void DetectionEngine::reset() { rec("de.reset"); }
void DetectionEngine::set_file_data(const DataPointer&) { rec("de.filedata"); }
void DetectionEngine::thread_init() { rec("de.tinit"); }
void DetectionEngine::thread_term() { rec("de.tterm"); }
void DetectionEngine::wait_for_context() { rec("de.waitctx"); }

bool Flow::handle_allowlist() { rec("flow.allow"); return true; }

void HighAvailabilityManager::process_receive() { rec("ha.rec"); }
void HighAvailabilityManager::process_update(Flow*, Packet*) { rec("ha.upd"); }
void HighAvailabilityManager::thread_init() { rec("ha.tinit"); }
void HighAvailabilityManager::thread_term() { rec("ha.tterm"); }
void HighAvailabilityManager::thread_term_beginning() { rec("ha.ttermb"); }

void Stream::daq_log_start() { rec("st.logstart"); }
void Stream::daq_log_end(Packet*) { rec("st.logend"); }
void Stream::handle_timeouts(bool) { rec("st.timeouts"); }
void Stream::purge_flows() { rec("st.purge"); }
bool Stream::set_packet_action_to_hold(Packet*) { rec("st.hold"); return false; }

void InspectorManager::thread_init() { rec("insp.tinit"); }
void InspectorManager::thread_term() { rec("insp.tterm"); }
void ModuleManager::accumulate(const SnortConfig*, const char*) { rec("mod.accum"); }

// the packet wall's capture seats (the NEVER-land protocol home; the ctor
// face rides the ground stub shape — memset + the two seats, the honest
// stand-in per the banked deviation; the decode leg records ONLY):
Packet::Packet(bool)
{
    std::memset(this, 0, sizeof(*this));
    ip_proto_next = IpProtocol::PROTO_NOT_SET;
    packet_flags = PKT_FROM_CLIENT;
}
Packet::~Packet() { }
int Packet::inject() { rec("pkt.inject"); return DAQ_SUCCESS; }
void PacketManager::decode(Packet*, const DAQ_PktHdr_t*, const uint8_t*, uint32_t, bool, bool) { rec("pm.decode"); }
void PacketManager::encode_update(Packet*) { rec("pm.encupd"); }
void PacketManager::thread_init() { rec("pm.tinit"); }
void PacketManager::thread_term() { rec("pm.tterm"); }

void FileService::thread_init() { rec("fs.tinit"); }
void FileService::thread_term() { rec("fs.tterm"); }
void FileCapture::flush() { rec("fc.flush"); }

void TraceApi::thread_init(const TraceConfig*) { rec("tr.tinit"); }
void TraceApi::thread_reinit(const TraceConfig*) { rec("tr.trein"); }
void TraceApi::thread_term() { rec("tr.tterm"); }

THREAD_LOCAL bool TimeProfilerStats::enabled = false;

// the packet wall's ignore hook (the ground face TRUE — the detect.cc :56
// leg; the cc :91 main-hook stand returns TRUE = process continues):

// the policy getters (the census face snort::-prefixed; the LANDED
// main/policy home CITES the id faces; the C getters mirror ONLY for the
// C-side DEC census — shape casts, NEVER ABI):
InspectionPolicy* get_inspection_policy()
{
    rec("pol.insp");
    static std::vector<char>* seat = new std::vector<char>(sizeof(InspectionPolicy), 0);
    return (InspectionPolicy*)seat->data();
}
IpsPolicy* get_ips_policy()
{
    rec("pol.ips");
    static std::vector<char>* seat = new std::vector<char>(sizeof(IpsPolicy), 0);
    return (IpsPolicy*)seat->data();
}
NetworkPolicy* get_network_policy()
{
    rec("pol.net");
    static std::vector<char>* seat = new std::vector<char>(sizeof(NetworkPolicy), 0);
    return (NetworkPolicy*)seat->data();
}
NetworkPolicy* get_default_network_policy(const SnortConfig*)
{
    NetworkPolicy* p = get_network_policy();
    static std::vector<char>* cm = new std::vector<char>(sizeof(::CodecManager) + 64, 0);
    p->cd_mgr = (CodecManager*)cm->data();   // the mirror seat the cd_mgr
    return p;                                // legs NEVER deref (subset law)
}


IpsContext::IpsContext(unsigned) { g_ctx_ctors++; }   // the stub-shape ctor
// (ground ctor NEVER runs; packet/conf seats ride the push mirror)

}// namespace snort

snort::Active g_w_mirror_active;   // the wiring seat (default ctor — the
// ACT_MAX / AST_MAX default face is the deterministic distill input)

// ======================================================================
// the SFDAQConfig subset face (the seats the PAIR reads through the header
// inlines get_batch_size/get_mru_size — the DEFAULTS 64/1518 ride UNtouched;
// the ctor mirrors the config face ONLY — NEVER the real home TU):
// ======================================================================
SFDAQConfig::SFDAQConfig()
{
    batch_size = BATCH_SIZE_UNSET;
    mru_size = SNAPLEN_UNSET;
    timeout = 1500;   // the scripted seat face (the idle-increment arm)
}
SFDAQConfig::~SFDAQConfig() { }
void SFDAQConfig::set_batch_size(uint32_t b) { batch_size = b; }
void SFDAQConfig::set_mru_size(int m) { mru_size = m; }
