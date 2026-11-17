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
namespace snort {
void populate_instance_maps() { }
void invalidate_instance_maps() { }
unsigned get_instance_id() { return 0; }
unsigned get_relative_instance_number() { return 0; }
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
namespace snort {
void PacketTracer::set_log_file(const std::string&) { std::printf("WITNESS PT set_log_file\n"); }
void PacketTracer::thread_init() { }
void PacketTracer::thread_term() { }
void PacketTracer::configure(bool, const std::string&) { }
bool PacketTracer::is_active() { return g_pt_active != 0; }
bool PacketTracer::is_daq_activated() { return false; }
void PacketTracer::pause() { }
void PacketTracer::unpause() { }
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
    ref_count = new std::atomic_uint[2];
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
int64_t FileService::get_max_file_depth(FileConfig*) { return 0; }
void FileService::set_max_file_depth(const SnortConfig*) { }
void FileService::collect_cache_usage(stats::Builder&, stats::Group&) { }
FileCacheClearStatus FileService::get_file_cache_clear_status() { return FileCacheClearStatus::UNAVAILABLE; }
FileCacheClearResult FileService::clear_file_cache() { return {}; }
void FileService::reset() { }
}  // namespace snort
extern "C" void fcache_set_file_cache(FileCache* c) { FileService::file_cache = c; }

// ------------------------------------------------------------------
// FileFlows witnesses (the real bodies ride FlowDataStore/policy maps).
// swap/restore/get_current keep the EXACT field discipline of the real
// bodies (pure member bookkeeping, copied donor-verbatim; the
// get_file_context lookup the probe never triggers stays).
// ------------------------------------------------------------------
namespace snort {
unsigned FileFlows::file_flow_data_id = 1;
static FileFlows* g_ffl = nullptr;
FileFlows* FileFlows::get_file_flows(Flow*, bool to_create)
{
    std::printf("FFL get_file_flows to_create=%d exists=%d -> %s\n",
        (int)to_create, g_ffl ? 1 : 0,
        (to_create and !g_ffl) ? "new" : (g_ffl ? "existing" : "null"));
    if (to_create and !g_ffl)
        g_ffl = new FileFlows(nullptr);
    return g_ffl;
}
FilePolicyBase* FileFlows::get_file_policy(Flow*)
{
    std::printf("FFL get_file_policy -> stub\n");
    return (FilePolicyBase*)stub_file_policy();
}
void FileFlows::handle_retransmit(Packet*) { std::printf("WITNESS FFL retransmit\n"); }
FileContext* FileFlows::get_current_file_context()
{
    std::printf("FFL get_current_file_context cur=%d cfid=%llu\n",
        current_context ? 1 : 0, (unsigned long long)current_file_id);
    if (current_file_id != 0)
    {
        bool is_new = false;
        return get_file_context(current_file_id, false, is_new);
    }
    return current_context;
}
void FileFlows::set_current_file_context(FileContext* ctx)
{
    std::printf("FFL set_current_file_context\n");
    current_context = ctx;
    current_file_id = 0;
}
FileFlows::CurrentContextSlot
FileFlows::swap_current_file_context_no_delete(FileContext* new_ctx)
{
    std::printf("FFL swap_current prev=%d\n", current_context ? 1 : 0);
    CurrentContextSlot saved { current_context, current_file_id };
    current_context = new_ctx;
    current_file_id = 0;
    return saved;
}
void FileFlows::restore_current_file_context_no_delete(const CurrentContextSlot& saved)
{
    std::printf("FFL restore_current id=%llu\n", (unsigned long long)saved.id);
    current_context = saved.ctx;
    current_file_id = saved.id;
}
FileContext* FileFlows::get_file_context(uint64_t file_id, bool to_create,
    bool& is_new_context, uint64_t)
{
    std::printf("FFL get_file_context id=%llu to_create=%d\n",
        (unsigned long long)file_id, (int)to_create);
    auto it = partially_processed_contexts.find(file_id);
    if (it != partially_processed_contexts.end())
        return it->second;
    if (to_create)
    {
        FileContext* fc = new FileContext();
        fc->set_file_id(file_id);
        partially_processed_contexts[file_id] = fc;
        is_new_context = true;
        return fc;
    }
    is_new_context = false;
    return nullptr;
}
FileContext* FileFlows::get_partially_processed_context(uint64_t file_id)
{
    auto it = partially_processed_contexts.find(file_id);
    return it == partially_processed_contexts.end() ? nullptr : it->second;
}
void FileFlows::remove_processed_file_context(uint64_t file_id)
{
    std::printf("FFL remove id=%llu\n", (unsigned long long)file_id);
    auto it = partially_processed_contexts.find(file_id);
    if (it == partially_processed_contexts.end())
        return;
    if (current_context == it->second) current_context = nullptr;
    delete it->second;
    partially_processed_contexts.erase(it);
}
uint64_t FileFlows::get_new_file_instance() { static uint64_t n = 0; return ++n; }
FileFlows::~FileFlows()
{
    std::printf("FileFlows dtor nctx=%zu\n", partially_processed_contexts.size());
    for (auto& kv : partially_processed_contexts)
        if (kv.second != current_context and kv.second != main_context)
            delete kv.second;
    partially_processed_contexts.clear();
    if (deferred_delete_context) { delete deferred_delete_context; deferred_delete_context = nullptr; }
    if (current_context) { delete current_context; current_context = nullptr; }
    if (main_context) { delete main_context; main_context = nullptr; }
    if (file_policy) FilePolicyBase::delete_file_policy(file_policy);
}
bool FileFlows::set_file_name(const uint8_t*, uint32_t, uint64_t, uint64_t, const uint8_t*, uint32_t)
{ std::printf("WITNESS FFL set_file_name\n"); return false; }
bool FileFlows::file_process(Packet*, const uint8_t*, int, FilePosition, bool, size_t, const uint8_t*, uint32_t)
{ std::printf("WITNESS FFL file_process\n"); return false; }
bool FileFlows::file_process(Packet*, uint64_t, const uint8_t*, int, uint64_t, FileDirection,
    uint64_t, FilePosition, const uint8_t*, uint32_t, const uint8_t*, uint32_t, const std::string&, bool)
{ std::printf("WITNESS FFL file_process2\n"); return false; }
void FileFlows::init_file_context(FileDirection, FileContext*)
{ std::printf("WITNESS FFL init_file_context\n"); }
FileContext* FileFlows::find_main_file_context(FilePosition, FileDirection, size_t)
{ std::printf("WITNESS FFL find_main_file_context\n"); return main_context; }
void FileFlows::retire_victim(FileContext* victim)
{
    std::printf("WITNESS FFL retire_victim\n");
    if (current_context == victim) current_context = nullptr;
    auto it = partially_processed_contexts.begin();
    while (it != partially_processed_contexts.end())
    {
        if (it->second == victim) { delete it->second; it = partially_processed_contexts.erase(it); }
        else ++it;
    }
    if (main_context == victim) main_context = nullptr;
    if (deferred_delete_context == victim) deferred_delete_context = nullptr;
}
void FileFlows::add_pending_file(uint64_t file_id)
{
    std::printf("FFL add_pending_file %llu\n", (unsigned long long)file_id);
    pending_file_id = file_id;
}
}  // namespace snort

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
void fp_eval_service_group(snort::Packet* p, SnortProtocolId spid)
{
    std::printf("FP_EVAL spid=%d have_pkt=%d n=%d\n", (int)spid, p ? 1 : 0, ++g_fp_eval_calls);
}
void fp_set_context(snort::IpsContext&) { std::printf("WITNESS fp_set_context\n"); }
void fp_clear_context(const snort::IpsContext&) { std::printf("WITNESS fp_clear_context\n"); }

// parser/parse_utils.h decls compiled in... file_config.cc references
// nothing; keep link clean.
void get_magic_rule_ids_from_type(const std::string&, const std::string&,
    snort::FileTypeBitSet&, snort::SnortConfig*)
{ std::printf("WITNESS get_magic_rule_ids_from_type\n"); }
void set_rule_id_from_type(snort::SnortConfig*, uint64_t, std::string,
    std::string, std::string, std::vector<std::string>)
{ std::printf("WITNESS set_rule_id_from_type\n"); }
