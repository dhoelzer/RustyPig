// stubs.cc — witness bodies for the fcache harness (row 17p).
// Lifted from the proven tools/filib_harness donor; deltas marked NEW17p.
// Every witness stands at the REAL header's exact member signature.
// A witness prints a WITNESS/label line when reached, so no silent fork.
// RETIRED (NEXT.md retire rule): the donor's FileCache::* witness block
// (filib stubs.cc:345-417) is GONE — file_cache.cc is a REAL TU here.
#include "file_api/file_lib.h"
#include "file_api/file_api.h"
#include "file_api/file_cache.h"
#include "file_api/file_capture.h"
#include "file_api/file_config.h"
#include "file_api/file_flows.h"
#include "file_api/file_inspect.h"
#include "file_api/file_service.h"
#include "file_api/file_stats.h"
#include "control/control.h"
#include "detection/detection_engine.h"
#include "flowz/flow_data.h"
#include "framework/mp_data_bus.h"
#include "main/thread_config.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "managers/inspector_manager.h"
#include "packet_io/packet_tracer.h"
#include "trace/trace.h"
#include "utils/util.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

using namespace snort;

// ------------------------------------------------------------------
// SnortConfig statics + accessors (rules_harness donor recipe verbatim)
// ------------------------------------------------------------------
uint32_t SnortConfig::warning_flags = 0;
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::output_flags = 0;
bool SnortConfig::log_quiet_bypassed = false;
std::unordered_map<std::string, std::string> SnortConfig::static_names;
std::mutex SnortConfig::static_names_mutex;
SnortConfig* g_probe_sc = nullptr;
static SnortConfig g_default_conf;  // upstream unit-test context: a main conf
SnortConfig* SnortConfig::get_conf() { return g_probe_sc ? g_probe_sc : &g_default_conf; }
SnortConfig* SnortConfig::get_main_conf() { return g_probe_sc ? g_probe_sc : &g_default_conf; }
const char* SnortConfig::get_static_name(const char* name)
{
    std::lock_guard<std::mutex> lk(static_names_mutex);
    auto entry = static_names.find(name);
    if ( entry != static_names.end() )
        return entry->second.c_str();
    static_names.emplace(name, name);
    return static_names[name].c_str();
}
void SnortConfig::cleanup_fatal_error() { }
bool SnortConfig::get_default_rule_state() const { return true; }

// NOTE (delta vs donor): the donor's duplicate witnesses get_random_seed /
// snort::get_error are retired here — utils/util.cc is a REAL TU in this
// closure (needed by the real sf_ip.cc: snort_strdup).

// profiler THREAD_LOCAL pins (profiler .cc files not in closure;
// upstream default build has profiling disabled -> enabled=false).
#include "profiler/profiler.h"
namespace snort { THREAD_LOCAL bool TimeProfilerStats::enabled = false; }

// ------------------------------------------------------------------
// clock interposition (textlog time()-stub recipe; same as donor).
// SnortClock == steady/high_resolution clock -> fake clock starts at
// 100.0s and advances ONLY when the probe steps it -> exact duration
// decimals in FileContext start_time/duration paths. Orthogonal to the
// packet clock: file_cache.cc itself is packet_time-driven
// (real time/packet_time.cc TU; probe arms via packet_time_update).
// ------------------------------------------------------------------
static double fake_now = 100.0;
static int faked = 0;
extern "C" void fcache_set_fake_now(double t) { fake_now = t; }
extern "C" void fcache_enable_fake_clock(int on) { faked = on; }
extern "C" int clock_gettime(clockid_t clk, struct timespec* ts)
{
    if ( faked )
    {
        ts->tv_sec  = (clk == CLOCK_REALTIME) ? 1700000000 + (time_t)fake_now : (time_t)fake_now;
        ts->tv_nsec = (long)((fake_now - (double)(time_t)fake_now) * 1e9 + 0.5);
        return 0;
    }
    ts->tv_sec = 0; ts->tv_nsec = 0;
    return -1;
}
// NOTE (delta vs donor): the donor's `struct timeval packet_now` stub is
// retired here — packet_time.cc is a REAL TU in this closure.

// ------------------------------------------------------------------
// log/messages.h witnesses: loud prints, no side effects. Declared in
// namespace snort by messages.h. LogMessage formats its args (donor
// printed a tag only) so dump_cache/dump_cache_entry LogRespond null-
// branch lines pin file_cache.cc's format strings verbatim.
// ------------------------------------------------------------------
namespace snort {
void ParseError(const char*, ...) { std::printf("WITNESS ParseError\n"); }
void LogMessage(const char* fmt, ...)
{
    std::printf("LOGMSG ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
void LogMessage(FILE*, const char*, ...) { std::printf("WITNESS LogMessageFh\n"); }
void ErrorMessage(const char* fmt, ...)
{
    std::printf("WITNESS ErrorMessage ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
void ReloadError(const char* fmt, ...)
{
    std::printf("WITNESS ReloadError ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
void FatalError(const char* fmt, ...)
{
    std::printf("FATAL_DEMO ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    std::fflush(stdout);
    abort();
}
// (get_error rides the real utils/util.cc TU now — donor witness retired)
} // namespace snort

// ------------------------------------------------------------------
// control/control.h witness: real body formats to the control socket.
// Gate path passes null ControlConn (LogRespond -> LogMessage); the
// responder exists for link closure of the LogRespond macro arm.
// ------------------------------------------------------------------
bool ControlConn::respond(const char* fmt, ...)
{
    std::printf("RESP ");
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    return true;
}

// ------------------------------------------------------------------
// NEW17p: main/thread_config.h graft (hwloc include excised).
// Only get_instance_max is used (file_cache.cc:144 set_max_files clamp).
// ------------------------------------------------------------------
static unsigned g_instance_max = 1;
extern "C" void fcache_set_instance_max(unsigned n) { g_instance_max = n; }
namespace snort {
unsigned ThreadConfig::get_instance_max()
{ std::printf("WITNESS ThreadConfig::get_instance_max=%u\n", g_instance_max); return g_instance_max; }
}  // namespace snort

// ------------------------------------------------------------------
// main/thread.h witnesses. THREAD_LOCAL file_trace is declared by the
// real file_module.h; the module cc that usually defines it is not in
// closure -> definition + probe arm here.
// ------------------------------------------------------------------
void set_instance_id(unsigned) { }
void set_thread_type(SThreadType) { }
void set_run_num(uint16_t) { }
uint16_t get_run_num() { return 0; }
// NEW17q: armable (donor hardwired 0) — pins the
// (get_instance_id()<<32)|max_file_id++ bit ladder at file_flows.cc:205-209
// (THREAD_LOCAL max_file_id stays REAL inside the real file_flows TU).
// Setter lives in the NEW17q block below (fcache_set_instance_id); single
// file-scope variable so the arm and the read can never fork.
// NOTE: Inspector witness ref_count array sized 16 to survive a nonzero
// instance arm (only [0] global / [1] instance-0 are exercised).
static unsigned g_instance_id = 0;
extern "C" void fcache_set_instance_id(unsigned n) { g_instance_id = n; }
namespace snort {
void populate_instance_maps() { }
void invalidate_instance_maps() { }
unsigned get_instance_id() { return g_instance_id; }
unsigned get_relative_instance_number() { return g_instance_id; }
SThreadType get_thread_type() { return STHREAD_TYPE_MAIN; }
const char* get_instance_file(std::string& s, const char* n) { s = n; return s.c_str(); }
const char* get_main_file(std::string& s, const char* n) { s = n; return s.c_str(); }
}  // namespace snort

THREAD_LOCAL const snort::Trace* file_trace = nullptr;  // global scope (file_module.h)
extern "C" void fcache_set_file_trace(int on, int level)
{
    static snort::Trace t;
    t.level = (uint8_t)level;
    file_trace = on ? &t : nullptr;
}

// ------------------------------------------------------------------
// packet_io/packet_tracer.h witnesses (its .cc drags the tracer monolith
// + DAQ). file_cache.cc hit sites: is_active + log (and the TracerMute
// overload for link shape). Format output tagged "PT ".
// ------------------------------------------------------------------
static int g_pt_active = 0;
extern "C" void fcache_set_pt_active(int on) { g_pt_active = on; }
// NEW17q: is_daq_activated ARMED (PLAN.md 3.4: donor hardwired false ->
// populate_trace_data never ran and its daq_log format ladder — a main pin
// target of this row — never fired).
static int g_pt_daq = 0;
extern "C" void fcache_set_pt_daq(int on) { g_pt_daq = on; }
namespace snort {
void PacketTracer::set_log_file(const std::string&) { std::printf("WITNESS PT set_log_file\n"); }
void PacketTracer::thread_init() { }
void PacketTracer::thread_term() { }
void PacketTracer::configure(bool, const std::string&) { }
bool PacketTracer::is_active() { return g_pt_active != 0; }
bool PacketTracer::is_daq_activated() { return g_pt_daq != 0; }
void PacketTracer::pause() { }
void PacketTracer::unpause() { }
// NEW17q: get_time + restart_timer witnesses (populate_trace_data format
// arg file_flows.cc:87 + :427/:520). get_time PINNED to a constant (the
// real body rides the tracer monolith clock; the fake SnortClock stays
// orthogonal — deviation documented).
uint64_t PacketTracer::get_time() { return 1700000100000000ull; }
void PacketTracer::restart_timer() { std::printf("PT restart_timer\n"); }
void PacketTracer::log(const char* format, ...)
{
    std::printf("PT ");
    va_list ap; va_start(ap, format); vprintf(format, ap); va_end(ap);
}
void PacketTracer::log(TracerMute mute, const char* format, ...)
{
    (void)mute;
    std::printf("PT(mute) ");
    va_list ap; va_start(ap, format); vprintf(format, ap); va_end(ap);
}
void PacketTracer::daq_log(const char* format, ...)
{
    std::printf("PTdaq ");
    va_list ap; va_start(ap, format); vprintf(format, ap); va_end(ap);
}
}  // namespace snort

// ------------------------------------------------------------------
// NEW17p: packet_io/active.h witnesses (active.cc drags the DAQ +
// action monoliths). file_cache.cc apply_verdict arms reach
// set_delayed_action + set_drop_reason on the probe-armed Active.
// The ACT_* enum values are the REAL header's (file_cache switch pins
// which action was queued).
// ------------------------------------------------------------------
namespace snort {
void Active::set_delayed_action(Active::ActiveActionType action, bool force)
{ std::printf("ACT delayed=%d force=%d\n", (int)action, (int)force); }
void Active::set_drop_reason(const char* reason)
{ std::printf("ACT drop_reason=%s\n", reason ? reason : "(null)"); }
}  // namespace snort

// ------------------------------------------------------------------
// framework/data_bus.h witness publish bodies (data_bus.cc drags the
// MP transport + policy dbus monoliths). Payload bytes printed as hex.
// ------------------------------------------------------------------
namespace snort {
void DataBus::publish(unsigned pub_id, unsigned evt_id, DataEvent& e, Flow*)
{
    unsigned len = 0;
    const uint8_t* d = e.get_data(len);
    std::printf("PUB pub=%u evt=%u len=%u", pub_id, evt_id, len);
    if ( d and len )
    {
        std::printf(" data=");
        for (unsigned i = 0; i < len; i++) std::printf("%02x", d[i]);
    }
    else if ( d )
        std::printf(" datapt=1");
    std::printf("\n");
}
void DataBus::publish(unsigned pid, unsigned eid, const uint8_t* buf, unsigned len, Flow*)
{
    std::printf("PUBBYTES pub=%u evt=%u len=%u data=", pid, eid, len);
    for (unsigned i = 0; i < len; i++) std::printf("%02x", buf[i]);
    std::printf("\n");
}
void DataBus::publish(unsigned pid, unsigned eid, Packet* p, Flow* f)
{
    if ( p && !f )
        f = p->flow;
    std::printf("PUBPKT pub=%u evt=%u p=%d f=%d\n", pid, eid, p ? 1 : 0, f ? 1 : 0);
}
void DataBus::publish_to_all_network_policies(unsigned, unsigned)
{ std::printf("WITNESS publish_to_all_network_policies\n"); }
}  // namespace snort

// ------------------------------------------------------------------
// NEW17p: framework/mp_data_bus.h witness bodies (--include excision
// NOT possible here: file_cache.cc:563-571 really calls these when
// SnortConfig::mp_dbus is true). get_id returns a fixed probe-visible
// id; publish prints pub/evt and keeps the shared_ptr alive to the
// print (event bytes NOT dumped: FileMPEvent payload is the full
// serialized FileInfo, deterministic anyway but noise; size pinned via
// the FileMPEvent ctor math instead).
// ------------------------------------------------------------------
namespace snort {
unsigned MPDataBus::get_id(const PubKey& key)
{ std::printf("MPDBUS get_id name=%s events=%u -> 42\n", key.publisher, key.num_events); return 42; }
bool MPDataBus::publish(unsigned pub_id, unsigned evt_id, std::shared_ptr<DataEvent> e, Flow*)
{ std::printf("MPDBUS publish pub=%u evt=%u have_event=%d\n", pub_id, evt_id, e ? 1 : 0); return true; }
}  // namespace snort
extern "C" void fcache_set_mp_dbus(int on) { g_default_conf.mp_dbus = on != 0; }

// pub_sub/file_events.h: get_file_adv_pub_id lands in file_inspect.cc
// (module monolith closure) -> fixed probe-controlled id.
static unsigned g_stub_adv_pub_id = 7;
extern "C" void fcache_set_adv_pub_id(unsigned id) { g_stub_adv_pub_id = id; }
unsigned get_file_adv_pub_id() { return g_stub_adv_pub_id; }

// ------------------------------------------------------------------
// Stub file policy: exercises the REAL FilePolicyBase ref-count +
// virtual dispatch (file_api.cc linked verbatim) with probe-armed
// verdicts. file_cache.cc check_verdict/resume arms drive it.
// ------------------------------------------------------------------
class StubFilePolicy : public FilePolicyBase
{
public:
    FileVerdict type_lookup(Packet*, FileInfo*) override
    { std::printf("POLICY type_lookup -> %d\n", (int)tv); return tv; }
    FileVerdict signature_lookup(Packet*, FileInfo*) override
    { std::printf("POLICY signature_lookup -> %d\n", (int)sv); return sv; }
    void policy_check(Flow*, FileInfo*) override
    { std::printf("POLICY policy_check\n"); }
    void log_file_action(Flow*, FileInfo*, FileAction action) override
    { std::printf("POLICY log_file_action a=%d\n", (int)action); }
    FileVerdict tv = FILE_VERDICT_UNKNOWN;
    FileVerdict sv = FILE_VERDICT_UNKNOWN;
};
// heap: a static object would hit ~FilePolicyBase's assert(!ref_count)
// at exit (real protocol pairs ctor ref=1 with delete_file_policy).
static StubFilePolicy* g_stub_policy = new StubFilePolicy();
FilePolicyBase* stub_file_policy() { return g_stub_policy; }
extern "C" void fcache_release_stub_policy()
{ FilePolicyBase::delete_file_policy(g_stub_policy); g_stub_policy = nullptr; }
extern "C" void fcache_set_policy_verdicts(int type_v, int sig_v)
{
    if (g_stub_policy)
    {
        g_stub_policy->tv = (FileVerdict)type_v;
        g_stub_policy->sv = (FileVerdict)sig_v;
    }
}

// ------------------------------------------------------------------
// managers/inspector_manager.h witnesses. FileConfig is REAL (its .cc
// links); get_file_config() resolves through this seam (file_cache.cc:669).
// ------------------------------------------------------------------
static FileConfig g_stub_file_config;
static FileInspect* g_stub_file_inspector = nullptr;
FileInspect* get_stub_file_inspector() { return g_stub_file_inspector; }
extern "C" void fcache_set_file_inspector(int on)
{
    if (on and !g_stub_file_inspector)
        g_stub_file_inspector = new FileInspect(nullptr);
}
namespace snort {
Inspector* InspectorManager::acquire_file_inspector()
{
    std::printf("IMGR acquire -> %s\n", g_stub_file_inspector ? "inspector" : "null");
    if (g_stub_file_inspector) g_stub_file_inspector->add_global_ref();
    return g_stub_file_inspector;
}
Inspector* InspectorManager::get_file_inspector(const SnortConfig*)
{ return g_stub_file_inspector; }
void InspectorManager::release(Inspector* i)
{
    std::printf("IMGR release\n");
    if (i) i->rem_global_ref();
}
}  // namespace snort

// ------------------------------------------------------------------
// Inspector witness bodies (framework/inspector.cc drags ThreadConfig,
// the RSS registry, StreamSplitter). inspector.h grafted private->
// public (documented): the witness manages ref_count itself. The
// add_global_ref/rem_global_ref pair FileContext uses is real arithmetic.
// ------------------------------------------------------------------
namespace snort {
Inspector::Inspector()
{
    // NEW17q: sized 16 (donor 2) to survive the armable instance-id witness
    // (add_ref/rem_ref index 1+get_instance_id(); only [0] global and [1]
    // instance-0 are exercised by this probe — size is a safety margin,
    // documented deviation).
    ref_count = new std::atomic_uint[16];
    ref_count[0] = 0;
    ref_count[1] = 0;
}
Inspector::~Inspector()
{
    std::printf("Inspector dtor gref=%u\n", (unsigned)ref_count[0]);
    delete[] ref_count;
}
bool Inspector::is_inactive() { return ref_count[0] == 0; }
unsigned Inspector::get_buf_id(const char*) { return 0; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { std::printf("WITNESS get_splitter\n"); return nullptr; }
bool Inspector::likes(Packet*) { std::printf("WITNESS Inspector::likes\n"); return true; }
void Inspector::add_ref() { ++ref_count[1 + get_instance_id()]; }
void Inspector::rem_ref() { --ref_count[1 + get_instance_id()]; }
void Inspector::add_global_ref() { ++ref_count[0]; }
void Inspector::rem_global_ref() { --ref_count[0]; }
void Inspector::allocate_thread_storage() { }
void Inspector::copy_thread_storage(Inspector*) { }
}  // namespace snort

// ------------------------------------------------------------------
// FileInspect witness bodies: header shape `FileInspect(FileIdModule*,
// ...)`: real ctor does FileIdModule::load_config (module monolith) and
// real dtor deletes config when owned; here the config is a harness
// global -> not deleted (documented deviation).
// ------------------------------------------------------------------
FileInspect::FileInspect(FileIdModule* mod)
{
    std::printf("FileInspect ctor\n");
    (void)mod;
    config = &g_stub_file_config;
}
FileInspect::~FileInspect()
{
    std::printf("FileInspect dtor\n");
}
bool FileInspect::configure(SnortConfig*) { std::printf("FileInspect configure\n"); return true; }
void FileInspect::show(const SnortConfig*) const { std::printf("FileInspect show\n"); }

// FileConfig seam: harness-owned real FileConfig (real class, real .cc).
FileConfig* get_harness_file_config() { return &g_stub_file_config; }

// ------------------------------------------------------------------
// FileService witness bodies: the four statics + enable flags are REAL
// shapes (file_lib/config_* paths read them); heavy lifecycle paths
// print. get_file_cache() (inline in the real header) returns the
// static the probe arms via fcache_set_file_cache — with the REAL
// file_cache TU linked, file_lib.cc:853 now hits the REAL
// cached_verdict_lookup (retire rule; no witness shadowing).
// ------------------------------------------------------------------
static long long g_max_file_depth = 0;  // armable; setter fcache_set_max_file_depth
namespace snort {
std::atomic<bool> FileService::file_type_id_enabled(false);
bool FileService::file_signature_enabled = false;
bool FileService::file_capture_enabled = false;
bool FileService::file_processing_initiated = false;
FileCache* FileService::file_cache = nullptr;
DecodeConfig FileService::decode_conf;
void FileService::init() { std::printf("FileService init\n"); }
void FileService::post_init() { std::printf("FileService post_init\n"); }
void FileService::verify_reload(const SnortConfig*) { std::printf("FileService verify_reload\n"); }
void FileService::close() { std::printf("FileService close\n"); }
void FileService::thread_init() { std::printf("FileService thread_init\n"); }
void FileService::thread_term() { std::printf("FileService thread_term\n"); }
void FileService::enable_file_type() { file_type_id_enabled.store(true, std::memory_order_relaxed); }
void FileService::enable_file_signature() { file_signature_enabled = true; }
void FileService::enable_file_capture() { file_capture_enabled = true; }
bool FileService::is_file_service_enabled()
{ return file_type_id_enabled or file_signature_enabled or file_capture_enabled; }
int64_t FileService::get_max_file_depth(FileConfig*) { return g_max_file_depth; }
void FileService::set_max_file_depth(const SnortConfig*) { }
void FileService::collect_cache_usage(stats::Builder&, stats::Group&) { }
FileCacheClearStatus FileService::get_file_cache_clear_status() { return FileCacheClearStatus::UNAVAILABLE; }
FileCacheClearResult FileService::clear_file_cache() { return {}; }
void FileService::reset() { }
}  // namespace snort
extern "C" void fcache_set_file_cache(FileCache* c) { FileService::file_cache = c; }

// NEW17r: FileCapture seams (file_capture.cc is a REAL TU in this link;
// FileCapture::init spawns the async writer thread -> NEVER called by the
// probe. The probe arms the static mempool + block size through the
// FIXACC-public init_mempool/capture_block_size instead; FileCapture::exit
// is never called -> the mempool leaks at exit, pinned deviation).
extern "C" void fcache_set_capture_mem(int on)
{
    if (on)
        FileCapture::init_mempool(1, FileCapture::capture_block_size);
}
extern "C" void fcache_set_capture_block_size(int64_t bytes)
{ FileCapture::capture_block_size = bytes; }
extern "C" uint64_t fcache_capture_size(FileCapture* fc)
{ return (uint64_t)fc->get_file_capture_size(); }

// ------------------------------------------------------------------
// NEW17q: the donor FileFlows WITNESS block (fcache stubs.cc:442-573:
// file_flow_data_id / get_file_flows / get_file_policy / handle_retransmit
// / get_current / set_current / swap / restore / get_file_context /
// get_partially_processed_context / remove_processed_file_context /
// get_new_file_instance / ~FileFlows / set_file_name / file_process x2 /
// init_file_context / find_main_file_context / retire_victim /
// add_pending_file) is RETIRED — the REAL file_flows.cc TU defines them
// all (17o->17p retirement precedent). init_file_context is a DEAD
// declaration upstream (no definition anywhere in snort3-src) -> retiring
// its stub links fine.
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// NEW17q witnesses (measured undefined in the donor link — PLAN.md 3):
//  (1) network policy seam: get_network_policy + NetworkPolicy::
//      get_base_file_policy hand back the heap StubFilePolicy through the
//      REAL ref-count protocol (set_file_policy: delete old, add_ref new;
//      ~FileFlows: delete_file_policy -> refs 2->1; final release 1->0).
//      The NetworkPolicy object is PINNED raw storage: never constructed,
//      never destroyed; get_base_file_policy (our body) ignores this
//      (documented deviation — the real class drags the policy monolith).
//  (2) get_file_processed_size — body copied LITERALLY from
//      file_service.cc:256-268 (file_service.cc stays a witness TU); works
//      against REAL FileFlows bodies once the single-slot Flow graft arms.
//  (3) Flow single-slot FlowData graft bodies (flowz/flow_fwd.h delta):
//      PINNED one attached Flow per probe run; get hits iff
//      id == stored fd->get_id() (real inline getter).
//  (4) instance-id arm pins (get_instance_id()<<32)|max_file_id++ at
//      file_flows.cc:205-209 (THREAD_LOCAL max_file_id stays REAL in the
//      TU). NOTE: Inspector witness ref_count array sized 16 to survive
//      a nonzero instance arm (only [0] global / [1] instance-0 used).
// ------------------------------------------------------------------
#include "main/policy.h"

// NetworkPolicy is PINNED raw storage: the real ctor/dtor ride the policy
// monolith; NO member of it is ever touched (our get_base_file_policy body
// ignores this) -- documented deviation.
alignas(NetworkPolicy) static unsigned char g_npolicy_storage[sizeof(NetworkPolicy)];
static NetworkPolicy* g_npolicy = reinterpret_cast<NetworkPolicy*>(g_npolicy_storage);
namespace snort {
NetworkPolicy* get_network_policy()
{ std::printf("WITNESS get_network_policy\n"); return g_npolicy; }
}  // namespace snort
snort::FilePolicyBase* NetworkPolicy::get_base_file_policy() const
{ std::printf("POLICY base_file_policy -> stub\n"); return (snort::FilePolicyBase*)stub_file_policy(); }

// single-slot FlowData graft (PIN: one attached Flow per probe run; the
// real Flow keeps a vector — deviation documented in the plan row).
static FlowData* g_flow_slot = nullptr;
FlowData* Flow::get_flow_data(unsigned id) const
{ return (g_flow_slot and g_flow_slot->get_id() == id) ? g_flow_slot : nullptr; }
void Flow::set_flow_data(FlowData* fd) { g_flow_slot = fd; }
extern "C" void fcache_clear_flow_slot() { g_flow_slot = nullptr; }

namespace snort {
// file_service.cc:256-268 body VERBATIM (file_service.proper stays backlog)
uint64_t get_file_processed_size(Flow* flow)
{
    FileFlows* file_flows = FileFlows::get_file_flows(flow);

    if (!file_flows)
        return 0;

    const FileContext* context = file_flows->get_current_file_context();

    if ( !context )
        return 0;

    return context->get_processed_bytes();
}
}  // namespace snort

// FileService::get_max_file_depth armable (donor returned constant 0;
// file_process :401 offset>depth arms + set_file_name :565 depth-compare
// need both sides). Variable lives above the FileService witness block.
extern "C" void fcache_set_max_file_depth(long long d) { g_max_file_depth = d; }

// is_file_service_enabled arm (three real statics behind the real OR).
extern "C" void fcache_set_file_service(int on)
{
    FileService::file_type_id_enabled.store(on != 0, std::memory_order_relaxed);
    if (!on)
    {
        FileService::file_signature_enabled = false;
        FileService::file_capture_enabled = false;
    }
}

// policy ref_count readout (FIXACC made FilePolicyBase privates public;
// access-only, arithmetic stays REAL).
extern "C" unsigned fcache_stub_policy_refs()
{ return g_stub_policy ? (unsigned)g_stub_policy->ref_count : 0u; }

// FlowData witness bodies (flow_data.cc drags PluginManager + accounting)
namespace snort {
unsigned FlowData::flow_data_id = 0;
unsigned FlowData::create_flow_data_id() { return ++flow_data_id; }
FlowData::FlowData(unsigned u) : id(u) { }
FlowData::FlowData(unsigned u, const char*) : id(u) { }
FlowData::~FlowData() { }
}  // namespace snort

// ------------------------------------------------------------------
// DetectionEngine witness (the real class rides the detection engine
// + IpsContext chain monoliths). set_next_packet hands back the probe-
// armed Packet*; get_current_packet returns the same, pinning
// GET_CURRENT_PACKET sites. queue_event prints (event_gen site).
// ------------------------------------------------------------------
namespace snort {
static Packet* g_next_pkt = nullptr;
static Packet* g_cur_pkt = nullptr;
extern "C" void fcache_set_next_packet(Packet* p) { g_next_pkt = p; }
Packet* DetectionEngine::set_next_packet(const Packet* parent, Flow* flow)
{
    std::printf("DE set_next_packet parent=%d flow=%d next=%d\n",
        parent ? 1 : 0, flow ? 1 : 0, g_next_pkt ? 1 : 0);
    g_cur_pkt = g_next_pkt;
    return g_cur_pkt;
}
Packet* DetectionEngine::get_current_packet()
{
    std::printf("DE get_current_packet have=%d\n", g_cur_pkt ? 1 : 0);
    return g_cur_pkt;
}
int DetectionEngine::queue_event(unsigned gid, unsigned sid)
{
    std::printf("DE queue_event gid=%u sid=%u\n", gid, sid);
    return 0;
}
}  // namespace snort

// ------------------------------------------------------------------
// protocols/packet.h Packet ctor/dtor witnesses (PacketManager pools +
// decode monolith). probe builds one heap Packet; fields zero-init like
// the real ctor (members carry header defaults already). Probe wires
// p->flow / p->active / p->context by hand.
// ------------------------------------------------------------------
namespace snort {
Packet::Packet(bool) { }
Packet::~Packet() { }
}  // namespace snort

// detection/fp_detect.h free fn used by find_file_type_from_ips.
static int g_fp_eval_calls = 0;
extern "C" int fcache_fp_eval_calls() { return g_fp_eval_calls; }
// NEW17r side-effect arms (row-17r plan 5-L): optional type-set through
// the REAL FileFlows current-context chain + re-entrant current-context
// swap (pins the file_lib.cc:1048-1054 conditional-restore guard both
// ways). Witness substitution for the real inspection chain: documented.
static unsigned g_fp_eval_set_spid = 0;
static unsigned g_fp_eval_set_ftype = 0;
static int g_fp_eval_swap = 0;
static FileContext* g_fp_eval_alt = nullptr;
extern "C" void fctx_set_fp_eval_type(unsigned spid, unsigned ftype)
{ g_fp_eval_set_spid = spid; g_fp_eval_set_ftype = ftype; }
extern "C" void fctx_set_fp_eval_swap(int on) { g_fp_eval_swap = on; }
extern "C" void fctx_set_fp_eval_install(FileContext* c) { g_fp_eval_alt = c; }
static void fp_eval_side_effects(snort::Packet* p, SnortProtocolId spid)
{
    if (!p or !p->context)
        return;
    if (g_fp_eval_swap and g_fp_eval_alt)
    {
        FileFlows* files = FileFlows::get_file_flows(p->flow, false);
        if (files)
        {
            std::printf("FP_EVAL swap -> alt\n");
            files->set_current_file_context(g_fp_eval_alt);
        }
    }
    if (g_fp_eval_set_spid and (unsigned)spid == g_fp_eval_set_spid
        and p->context->file_type_process)
    {
        FileFlows* files = FileFlows::get_file_flows(p->flow, false);
        FileContext* cur = files ? files->get_current_file_context() : nullptr;
        if (cur)
        {
            std::printf("FP_EVAL set_type=%u\n", g_fp_eval_set_ftype);
            cur->set_file_type(g_fp_eval_set_ftype);
        }
    }
}
void fp_eval_service_group(snort::Packet* p, SnortProtocolId spid)
{
    std::printf("FP_EVAL spid=%d have_pkt=%d n=%d\n", (int)spid, p ? 1 : 0, ++g_fp_eval_calls);
    // NEW17r side-effect arms (see the NEW17r block above the parser
    // witnesses; g_fp_eval_* + fctx_set_* live there -- forward-linked via
    // the file-scope statics re-declared in that block).
    fp_eval_side_effects(p, spid);
}
void fp_set_context(snort::IpsContext&) { std::printf("WITNESS fp_set_context\n"); }
void fp_clear_context(const snort::IpsContext&) { std::printf("WITNESS fp_clear_context\n"); }

// ------------------------------------------------------------------
// NEW17r (row 17r): find_file_type_from_ips (file_lib.cc:1004) needs the
// fp_eval witness to model the side effects a REAL service group has on
// FileInfo, observably:
//   (a) optional type-set side effect: when armed (spid, ftype) with
//       spid != 0 and the packet's IpsContext::file_type_process is set,
//       the witness calls ((FileContext*)files->get_current_file_context())
//       ->set_file_type(ftype). This pins the L-block "type found" arms
//       through the REAL FileFlows current-context chain (the real chain
//       rides the inspector rule-match tree; witness substitution
//       documented in the plan row).
//   (b) re-entrant current-context swap: with fctx_set_fp_eval_swap(1) and
//       an installed target, the witness calls
//       FileFlows::get_file_flows(p->flow,false)->set_current_file_context
//       (target) BEFORE the type-set arm — exercising the C :1048
//       conditional-restore guard (current != this -> saved NOT restored).
// The counter getter fcache_fp_eval_calls is reused from the donor.
// ------------------------------------------------------------------
// (the g_fp_eval_* statics + setters moved ABOVE fp_eval_service_group)

// parser/parse_utils.h decls compiled in... file_config.cc references
// nothing; keep link clean.
void get_magic_rule_ids_from_type(const std::string&, const std::string&,
    snort::FileTypeBitSet&, snort::SnortConfig*)
{ std::printf("WITNESS get_magic_rule_ids_from_type\n"); }
void set_rule_id_from_type(snort::SnortConfig*, uint64_t, std::string,
    std::string, std::string, std::vector<std::string>)
{ std::printf("WITNESS set_rule_id_from_type\n"); }
