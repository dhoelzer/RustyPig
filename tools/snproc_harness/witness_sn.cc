// witness (row 24a): the app-level undefined mirror for the CLI-assembly row
// TU (the 23b/22a mirror law). EVERY body is a SHAPE-ONLY capture mirror of a
// NOT-landed home (managers/*, filters/*, flow/ha, memory/*, main/process,
// parser/*, profiler/*, side_channel, target_based, trace/*, time/periodic,
// host_tracker/*, packet_io/trough, file_api/file_service, log legs, utils).
// BODIES NEVER land; the rec() legs feed the DEC order ladder ONLY. The
// namespace placement of each leg rides the row .o's OWN nm -C census face
// (build.sh asserts the census; this file NEVER guesses it).
// The carried 4dd91018 witness_conf family is DOMINATED here: its fixed-1
// get_instance_max + static-local get_conf CLASH with this row's conf-swap +
// ceil-ladder faces (the 22a tc CORE-SUBSET precedent) — the SnortConfig
// subset legs below ride the carried ctor/dtor/statics VERBATIM, with the
// get_conf body SLOT-patched (recorded honest in DEVIATIONS row 24a).
// The ground row-name token rides runtime concat forms in build.sh (the
// family law); comments here split the family (sn-proc).
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "main/policy.h"
#include "main/process.h"
#include "main/modules.h"
#include "main/reload_tuner.h"
#include "main.h"
#include "managers/inspector_manager.h"
#include "managers/event_manager.h"
#include "managers/mp_transport_manager.h"
#include "managers/mpse_manager.h"
#include "managers/policy_selector_manager.h"
#include "managers/script_manager.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "framework/module.h"
#include "framework/inspector.h"
#include "framework/ips_action.h"
#include "detection/detection_engine.h"
#include "detection/fp_config.h"
#include "detection/ips_context_data.h"
#include "filters/detection_filter.h"
#include "file_api/file_service.h"
#include "flow/ha.h"
#include "flow/ha_module.h"
#include "framework/data_bus.h"
#include "framework/mp_data_bus.h"
#include "framework/mpse.h"
#include "host_tracker/host_cache.h"
#include "host_tracker/host_cache_segmented.h"
#include "host_tracker/host_tracker.h"
#include "host_tracker/host_tracker_module.h"
#include "target_based/host_attributes.h"
#include "memory/memory_cap.h"
#include "memory/memory_config.h"
// NOTE: real sf-d-a-q family heads (the copy tree fresh-cps):
#include "packet_io/sfdaq.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/trough.h"
#include "parser/parser.h"
#include "parser/cmd_line.h"
#include "parser/config_file.h"
#include "profiler/profiler.h"
#include "profiler/profiler_impl.h"
#include "side_channel/side_channel.h"
#include "stream/stream.h"
#include "time/periodic.h"
#include "time/stopwatch.h"
#include "trace/trace_api.h"
#include "trace/trace_config.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "log/log.h"
#include "log/messages.h"

#include <csetjmp>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

using namespace snort;   // the ground TU rides the SAME leg (snort.cc :94)

// ------------------------------------------------------------- ledger face
std::vector<std::string> g_probe_trace;
static void rec(const char* s) { g_probe_trace.emplace_back(s); }
void probe_reset_trace() { g_probe_trace.clear(); }

bool exit_requested = false;              // main.h :24 (the extern ride face)

sigjmp_buf probe_jump;
bool probe_jump_armed = false;
void probe_arm_jump(bool on) { probe_jump_armed = on; }

static bool g_probe_verify = true;
void probe_set_verify(bool v) { g_probe_verify = v; }

static int g_parse_errors = 0;
static int g_reload_errors = 0;

// the conf-swap slot (the row's OWN set sc -> SnortConfig::set_conf writes
// here; get_conf BELOW hands the slot back once installed — the honest
// harness rider face for the conf-swap legs, banked in DEVIATIONS row 24a):
SnortConfig* g_probe_conf = nullptr;
static SnortConfig* g_boot_conf = nullptr;

// zero-storage record members the ladders deref (mirror law: raw zero):
alignas(PolicyMap) static char g_policy_buf[sizeof(PolicyMap)];
alignas(FastPatternConfig) static char g_fp_buf[sizeof(FastPatternConfig)];
alignas(SFDAQConfig) static char g_daq_cfg_buf[sizeof(SFDAQConfig)];
alignas(MemoryConfig) static char g_mem_cfg_buf[sizeof(MemoryConfig)];
alignas(TraceConfig) static char g_trace_cfg_buf[sizeof(TraceConfig)];

SnortConfig* probe_make_conf()
{
    SnortConfig* sc = new SnortConfig("");
    std::memset(g_policy_buf, 0, sizeof g_policy_buf);
    std::memset(g_fp_buf, 0, sizeof g_fp_buf);
    std::memset(g_daq_cfg_buf, 0, sizeof g_daq_cfg_buf);
    std::memset(g_mem_cfg_buf, 0, sizeof g_mem_cfg_buf);
    std::memset(g_trace_cfg_buf, 0, sizeof g_trace_cfg_buf);
    sc->policy_map = reinterpret_cast<PolicyMap*>(g_policy_buf);
    sc->fast_pattern_config = reinterpret_cast<FastPatternConfig*>(g_fp_buf);
    sc->daq_config = reinterpret_cast<SFDAQConfig*>(g_daq_cfg_buf);
    sc->memory = reinterpret_cast<MemoryConfig*>(g_mem_cfg_buf);
    sc->ha_config = new HighAvailabilityConfig();
    sc->trace_config = reinterpret_cast<TraceConfig*>(g_trace_cfg_buf);
    sc->detection_filter_config = new DetectionFilterConfig();
    sc->id_offset = 0;
    sc->max_procs = 1;
    g_probe_conf = sc;
    return sc;
}

// ------------------------------------------------------------------ main.h
const char* get_prompt() { return "==>"; }
bool main_snort_started() { return true; }
void main_poke(unsigned) { rec("main_poke"); }

// ------------------------------------------------------------------ parser
SnortConfig* parse_cmd_line(int argc, char** argv)
{ rec("parse_cmd_line"); (void)argc; (void)argv; return probe_make_conf(); }
SnortConfig* ParseSnortConf(const SnortConfig*, const char* fname)
{ rec("ParseSnortConf"); (void)fname; return probe_make_conf(); }
void parser_init() { rec("parser.init"); }
void parser_term(SnortConfig*) { rec("parser.term"); }
const char* get_snort_conf() { static const char* s = "synth.conf"; return s; }
std::string read_infile(const char* tag, const char* fname)
{ rec("read_infile"); (void)tag; (void)fname; return std::string(); }
int get_parse_errors() { return g_parse_errors; }
void reset_parse_errors() { rec("reset_parse_errors"); g_parse_errors = 0; }
int get_reload_errors() { return g_reload_errors; }

// ----------------------------------------------------------------- process
void init_signals() { rec("proc.init_signals"); }
void term_signals() { rec("proc.term_signals"); }
void daemonize() { rec("proc.daemonize"); }
void set_quick_exit(bool v) { rec(v ? "proc.qexit-true" : "proc.qexit-false"); }
void set_main_thread() { rec("proc.set_main_thread"); }
void StoreSnortInfoStrings() { rec("proc.store_info"); }
void InitGroups(int, int) { rec("proc.init_groups"); }
void CreatePidFile(pid_t) { rec("proc.create_pidfile"); }
void ClosePidFile() { rec("proc.close_pidfile"); }
bool SetUidGid(int, int) { rec("proc.set_uid_gid"); return true; }
bool EnterChroot(const std::string&, std::string&) { rec("proc.enter_chroot"); return true; }
void SetNoCores() { rec("proc.set_no_cores"); }

// ------------------------------------------------------- stats/util/time legs
void PrintStatistics() { rec("stats.print"); }
void InitProtoNames() { rec("utils.init_proto_names"); }
void CleanupProtoNames() { rec("utils.cleanup_proto_names"); }
void trim_heap() { rec("trim_heap"); }
void TimeStart() { rec("time.start"); }
void TimeStop() { rec("time.stop"); }

// -------------------------------------------------------------- logger legs
void OpenLogger() { rec("log.open_logger"); }
void CloseLogger() { rec("log.close_logger"); }

// ------------------------------------------------------- detection filter
void detection_filter_init(DetectionFilterConfig*) { rec("dfilter.init"); }
void detection_filter_term() { rec("dfilter.term"); }

// ------------------------------------------------------------ host globals
HostCacheSegmentedIp host_cache;
void host_cache_module_dump() { rec("host_cache_module_dump"); }

// --------------------------------------------- global-ns mirrors (census face)
void EventManager::instantiate(const char*, snort::SnortConfig*) { rec("evt.instantiate"); }
void EventManager::copy_outputs(OutputSet*, const OutputSet*) { rec("evt.copy_outputs"); }

void PluginManager::init() { rec("pl.init"); }
void PluginManager::load_plugins(const std::string&) { rec("pl.load_plugins"); }
void PluginManager::capture_plugins(snort::SnortConfig*) { rec("pl.capture_plugins"); }
void PluginManager::revert_plugins(snort::SnortConfig*) { rec("pl.revert_plugins"); }
void PluginManager::release_plugins() { rec("pl.release_plugins"); }

void ScriptManager::load_scripts(const std::vector<std::string>&) { rec("script.load_scripts"); }

void PolicySelectorManager::print_config(const snort::SnortConfig*) { rec("psm.print_config"); }
void MpseManager::activate_search_engine(const snort::MpseApi*, snort::SnortConfig*) { rec("mpse.activate"); }

void Periodic::unregister_all() { rec("periodic.unregister_all"); }
void Profiler::setup(snort::SnortConfig*) { rec("prof.setup"); }

void Trough::setup() { rec("trough.setup"); }
void Trough::cleanup() { rec("trough.cleanup"); }

void HostAttributesManager::activate(snort::SnortConfig*) { rec("ham.activate"); }
bool HostAttributesManager::load_hosts_file(snort::SnortConfig*, const char*) { rec("ham.load"); return true; }
void HostAttributesManager::term() { rec("ham.term"); }

void HostTrackerModule::init_data() { rec("htm.init_data"); }
void set_default_policy(const snort::SnortConfig*) { rec("set_default_policy"); }
Module* PluginManager::get_module(const char*) { rec("pl.get_module"); static Module* none = nullptr; return none; }
HostCacheIp default_host_cache(LRU_CACHE_INITIAL_SIZE);

void HAReloadTuner::tswap() { rec("ha.tswap"); }
bool PolicyMap::setup_network_policies() { rec("pmap.setup"); return true; }

void SideChannelManager::pre_config_init() { rec("scm.pre_config_init"); }
void SideChannelManager::term() { rec("scm.term"); }

// ------------------------------------------------------------- memory:: legs
namespace memory {
void MemoryCap::init(unsigned) { rec("memcap.init"); }
void MemoryCap::start(const MemoryConfig& m, bool (*f)()) { rec("memcap.start"); (void)f; }
void MemoryCap::stop() { rec("memcap.stop"); }
void MemoryCap::term() { rec("memcap.term"); }
void MemoryCap::print(bool a, bool b) { rec(b ? (a ? "memcap-print-tt" : "memcap-print-ft") : (a ? "memcap-print-tf" : "memcap-print-ff")); }
} // namespace memory

// ----------------------------------------------------------- OPENSSL leg
extern "C" int OPENSSL_init_crypto(unsigned long long, const void*)
{ rec("ossl.init_crypto"); return 1; }

namespace snort {

// --------------------------------------------------------- SnortConfig subset
// (the CARRIED 4dd91018 ctor/dtor/statics legs VERBATIM; get_conf is the
// SLOT-patched face — see DEVIATIONS row 24a; the subset law per 22a tc)
SnortConfig::SnortConfig(const char*) : reload_id(0) {}
SnortConfig::~SnortConfig()
{
    // the slot/boot hygiene face (recorded rider):
    if (g_probe_conf == this) g_probe_conf = nullptr;
    if (g_boot_conf == this) g_boot_conf = nullptr;   // get_conf re-allocs fresh
}
uint32_t SnortConfig::logging_flags = 0;
THREAD_LOCAL bool SnortConfig::log_quiet_bypassed = false;
uint32_t SnortConfig::warning_flags = 0;
std::mutex SnortConfig::static_names_mutex;
std::unordered_map<std::string, std::string> SnortConfig::static_names;
const SnortConfig* SnortConfig::get_conf()
{
    if (g_probe_conf) return g_probe_conf;
    if (!g_boot_conf) g_boot_conf = new SnortConfig("");
    return g_boot_conf;
}

void SnortConfig::setup() { rec("sc.setup"); }
void SnortConfig::post_setup() { rec("sc.post_setup"); }
bool SnortConfig::verify() const { if (!g_probe_verify) rec("sc.verify-fail"); return g_probe_verify; }
SnortConfig* SnortConfig::get_main_conf() { return g_probe_conf; }
void SnortConfig::set_conf(SnortConfig* s) { rec("sc.set_conf"); g_probe_conf = s; }
void SnortConfig::register_reload_handler(ReloadResourceTuner*) { rec("sc.register_reload_handler"); }


// -------------------------------------------------------------- ThreadConfig
static unsigned g_inst_max = 1;
bool ThreadConfig::init() { rec("tc.init"); return true; }
void ThreadConfig::term() { rec("tc.term"); }
void ThreadConfig::set_instance_max(unsigned m) { rec("tc.set_imax"); g_inst_max = m; }
unsigned ThreadConfig::get_instance_max() { return g_inst_max; }

// ----------------------------------------------------------------- managers
void ModuleManager::load_params() { rec("mod.load_params"); }
void ModuleManager::init_stats() { rec("mod.init_stats"); }
void ModuleManager::reset_stats(SnortConfig*) { rec("mod.reset_stats"); }
void ModuleManager::reset_errors() { rec("mod.reset_errors"); }
unsigned ModuleManager::get_errors() { return 0; }

void InspectorManager::load_buffer_map() { rec("insp.load_buffer_map"); }
void InspectorManager::new_map() { rec("insp.new_map"); }
bool InspectorManager::configure(SnortConfig*) { rec("insp.configure"); return true; }
void InspectorManager::print_config(SnortConfig*) { rec("insp.print_config"); }
void InspectorManager::prepare_map() { rec("insp.prepare_map"); }
void InspectorManager::prepare_inspectors(SnortConfig*) { rec("insp.prepare_inspectors"); }
void InspectorManager::reconcile_map(SnortConfig*) { rec("insp.reconcile_map"); }
void InspectorManager::tear_down(SnortConfig*) { rec("insp.tear_down"); }
void InspectorManager::abort_map() { rec("insp.abort_map"); }
void InspectorManager::cleanup() { rec("insp.cleanup"); }

void MPTransportManager::term() { rec("mpt.term"); }

// ----------------------------------------------------------- detection legs
void DetectionEngine::init() { rec("de.init"); }
void DetectionEngine::set_data(unsigned, IpsContextData*) {}
IpsContextData* DetectionEngine::get_data(unsigned) { return nullptr; }
void IpsContextData::clear_ips_id() { rec("icd.clear_ips_id"); }
std::string IpsAction::get_default_priorities(bool) { rec("ipsact.priorities"); return std::string(); }

// ----------------------------------------------------------------- file_api
void FileService::init() { rec("fs.init"); }
void FileService::post_init() { rec("fs.post_init"); }
void FileService::close() { rec("fs.close"); }
void FileService::verify_reload(const SnortConfig*) { rec("fs.verify_reload"); }

// --------------------------------------------------------------------- ha
void HighAvailabilityManager::configure(HighAvailabilityConfig*) { rec("ha.configure"); }
bool HighAvailabilityManager::configured() { rec("ha.configured"); return false; }
void HighAvailabilityManager::finalize_ha_client_indices() { rec("ha.finalize"); }
void HighAvailabilityManager::term() { rec("ha.term"); }

// ----------------------------------------------------------------- data bus
unsigned DataBus::init() { rec("databus.init"); return 1; }

// ------------------------------------------------------------- mp data bus
MPDataBus::MPDataBus() { rec("mpdb.ctor"); }
MPDataBus::~MPDataBus() {}
unsigned MPDataBus::init(int) { rec("mpdb.init"); return 0; }

// ------------------------------------------------------------------- trace
void TraceApi::global_init() { rec("trace.global_init"); }
void TraceApi::capture_outputs(SnortConfig*) { rec("trace.capture_outputs"); }
void TraceApi::thread_init(const TraceConfig*) { rec("trace.thread_init"); }
void TraceApi::thread_term() { rec("trace.thread_term"); }
void TraceApi::thread_reinit(const TraceConfig*) { rec("trace.thread_reinit"); }

// witness LEGS (the witness mirrors the sf-d-a-q family wall legs; NEVER the landed 23a home)
bool SFDAQ::init(const SFDAQConfig*, unsigned) { rec("sf-daq.init"); return true; }
void SFDAQ::term() { rec("sf-daq.term"); }
bool SFDAQ::can_run_unprivileged() { rec("sf-daq.can_unpriv"); return true; }

// ------------------------------------------------------------ host tracker
void HostTracker::remove_flows() { rec("hosttracker.remove_flows"); }

// ------------------------------------------------------------------ stream
bool Stream::prune_flows() { rec("stream.prune_flows"); return true; }

// ------------------------------------------------------ codec manager base
void PacketManager::global_init(uint8_t) { rec("pkgmgr.global_init"); }

// ----------------------------------------------------------- messages legs
void LogLabel(const char*, FILE*) {}
void LogMessage(const char* fmt, ...) { va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a); }
void ErrorMessage(const char* fmt, ...) { va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a); }
void WarningMessage(const char* fmt, ...) { va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a); }
void ParseError(const char* fmt, ...)
{
    va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a);
    rec("ParseError");
    if (probe_jump_armed) { probe_jump_armed = false; siglongjmp(probe_jump, 1); }
}
void FatalError(const char* fmt, ...)
{
    va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a);
    rec("FatalError");
    if (probe_jump_armed) { probe_jump_armed = false; siglongjmp(probe_jump, 1); }
}
const char* get_error(int err) { return std::strerror(err); }

} // namespace snort
