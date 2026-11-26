// witness (row 24e): shape-only + FUNCTIONAL mirrors for the row TU's
// app-undef face — the namespaces ride the row .o's OWN nm -C census,
// NEVER from air. FUNCTIONAL legs: the PluginManager::add_module NAME
// capture (the DEC ladder), the IpsPolicy action_vars tracking (the 4th
// ground gate checks duplicate-REJECTION), the ips-policy holder, the
// Catch TestCaseInstaller (the REAL ground catch/unit_test.cc :62-:65
// body shape cited). The rest are shape-only bodies NEVER executed by the
// 4 gates NOR by the ladder.
#include "main/snort_config.h"
#include "main/policy.h"
#include "main/thread_config.h"
#include "main/snort.h"
#include "main/snort_module.h"
#include "main/network_module.h"
#include "main/thread.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/value.h"
#include "framework/ips_action.h"
#include "framework/reload_survivor_subscriptions_impl.h"
#include "framework/mp_data_bus.h"
#include "framework/counts.h"
#include "managers/plugin_manager.h"
#include "managers/module_manager.h"
#include "managers/action_manager.h"
#include "detection/fp_config.h"
#include "detection/signature.h"
#include "detection/detection_module.h"
#include "file_api/file_policy.h"
#include "file_api/file_service.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "filters/sfthd.h"
#include "filters/sfthreshold.h"
#include "sfip/sf_ipvar.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"
#include "parser/vars.h"
#include "parser/var_dependency.h"
#include "target_based/host_attributes.h"
#include "target_based/snort_protocols.h"
#include "packet_io/active_counts.h"
#include "host_tracker/host_cache_module.h"
#include "host_tracker/host_tracker_module.h"
#include "host_tracker/host_cache_segmented.h"
#include "actions/actions_module.h"
#include "codecs/codec_module.h"
#include "packet_io/packet_tracer_module.h"
#include "packet_io/sfdaq_module.h"
#include "payload_injector/payload_injector_module.h"
#include "profiler/profiler_module.h"
#include "latency/latency_module.h"
#include "side_channel/side_channel_module.h"
#include "flow/ha_module.h"
#include "js_norm/js_norm_module.h"
#include "memory/memory_module.h"
#include "trace/trace_module.h"
#include "control/control.h"
#include "utils/stats.h"
#include "log/batched_logger.h"
#include "log/messages.h"
#include "catch/snort_catch.h"
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace snort;

// ---- FUNCTIONAL capture: PluginManager::add_module appends the module
// NAME (Module::get_name — the ground module.h :114 inline face) ----
std::vector<std::string> g_captured_names;
void capture_reset() { g_captured_names.clear(); }
void PluginManager::add_module(Module* m) { g_captured_names.emplace_back(m->get_name()); }
const char* PluginManager::get_available_plugins(PlugType, const char*) { return nullptr; }

// ---- the Catch TEST_CASE installer (the REAL ground catch/unit_test.cc
// :62-:65 body shape cited; the unit_test.cc TU NEVER lands — its
// filter-family owns seats the gate NEVER drives; the REGISTER_TEST_CASE
// macro rides the VENDORED catch.hpp decl face (gate_main.o carries the
// impl) — the 24c shim law) ----
namespace snort {
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name)
{ REGISTER_TEST_CASE(fun, name) }
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name, const char* group)
{ REGISTER_TEST_CASE(fun, name, group) }
}

// ---- the ips-policy holder FUNCTIONAL face (the 4th ground gate seeds a
// stack IpsPolicy then NULLs it) ----
static IpsPolicy* g_ips_policy = nullptr;
namespace snort {
IpsPolicy* get_ips_policy() { return g_ips_policy; }
void set_ips_policy(IpsPolicy* p) { g_ips_policy = p; }
NetworkPolicy* get_network_policy() { return nullptr; }
InspectionPolicy* get_inspection_policy() { return nullptr; }
}

// ---- the IpsPolicy FUNCTIONAL semantic mirror (the layout rides the REAL
// ground main/policy.h DECL seat; bodies mirror the ground main/policy.cc
// :161-:176 semantics so duplicate-REJECTION is REAL; the policy.cc TU
// NEVER lands — the PolicyMap wall) ----
IpsPolicy::IpsPolicy(PolicyId id) : policy_id(id) { }
IpsPolicy::~IpsPolicy() { for (auto a : configured_action) delete a; }
bool IpsPolicy::has_action_variable_capacity() const
{ return configured_action.size() <= UINT8_MAX; }
bool IpsPolicy::has_action_variable(const std::string& name) const
{ return action_vars.find(name) != action_vars.end(); }
void IpsPolicy::commit_action_variable(const std::string& name,
    const std::string& action_name, IpsAction* act)
{
    auto selector = (ActionSelector)configured_action.size();
    action_vars.emplace(name, std::make_tuple(action_name, IpsAction::Type(0), selector));
    configured_action.emplace_back(act);
}

// ---- the legs the REAL ground log/messages.cc .o (linked REAL) pulls ----
void get_parse_location(const char*& file, unsigned& line) { file = ""; line = 0; }
THREAD_LOCAL bool SnortConfig::log_quiet_bypassed = false;
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::warning_flags = 0;
void SnortConfig::cleanup_fatal_error() { }
SnortConfig::SnortConfig(const char*) : reload_id(0) { }
SnortConfig::~SnortConfig() { }
static SnortConfig* g_boot_conf = nullptr;
const SnortConfig* SnortConfig::get_conf()
{
    if (!g_boot_conf) g_boot_conf = new SnortConfig("");
    return g_boot_conf;
}

// ---- the pulled legs the two REAL ground .o's (module.cc + messages.cc
// links) reference — the namespaces ride the nm -C census (snort::
// get_instance_id / snort::get_thread_type; the show_stats +
// get_parse_location faces ride the GLOBAL home face) ----
namespace snort { unsigned get_instance_id() { return 0; }
SThreadType get_thread_type() { return STHREAD_TYPE_MAIN; } }
unsigned ThreadConfig::get_instance_max() { return 1; }
void show_stats(const PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(const PegCount*, const PegInfo*, const std::vector<unsigned>&,
    const char*, FILE*) { }        // the vector-seat variant the REAL
                                   // module.cc :300 leg references

// ---- ThreadConfig shape-only legs (NEVER reached by gates/ladder) ----
struct CpuSet { unsigned dummy; };
CpuSet* ThreadConfig::validate_cpuset_string(const char*) { return nullptr; }
void ThreadConfig::destroy_cpuset(CpuSet*) { }
void ThreadConfig::set_thread_affinity(SThreadType, unsigned, CpuSet*) { }

// ---- SnortConfig::set_* mirrors (the row TU's in-TU process-module set
// legs; the snort_config.cc home NEVER lands; NEVER executed by the gates) ----
void SnortConfig::set_chroot_dir(const char*) { }
void SnortConfig::set_daemon(bool) { }
void SnortConfig::set_dirty_pig(bool) { }
void SnortConfig::set_dst_mac(const char*) { }
void SnortConfig::set_gid(const char*) { }
void SnortConfig::set_tunnel_verdicts(const char*) { }
void SnortConfig::set_uid(const char*) { }
void SnortConfig::set_umask(uint32_t) { }
void SnortConfig::set_utc(bool) { }
void SnortConfig::set_watchdog(uint16_t) { }
void SnortConfig::set_watchdog_min_thread_count(uint16_t) { }
bool Snort::is_reloading() { return false; }

// ---- the free parser/family mirrors (the homes NEVER land; shape-only) ----
bool ParseIpVar(const char*, const char*) { return true; }
void ParsePathVar(const char*, const char*) { }
bool ParsePortVar(const char*, const char*) { return true; }
void resolve_nets() { }
void resolve_ports() { }
void add_classification(SnortConfig*, const char*, const char*, unsigned) { }
sfip_var_t* sfip_var_from_string(const char*, const char*) { return nullptr; }
void sfvar_free(sfip_var_t*) { }
int sfthreshold_create(SnortConfig*, ThresholdConfig*, THDX_STRUCT*, PolicyId) { return 0; }
int RateFilter_Create(SnortConfig*, RateFilterConfig*, tSFRFConfigNode*) { return 0; }
void RateFilter_Cleanup() { }
PegCount* get_active_counts() { static PegCount c[16]; return c; }
const char* ModuleManager::get_includer(const char*) { return ""; }
ControlConn* ControlConn::query_from_lua(const lua_State*) { return nullptr; }
IpsAction* ActionManager::instantiate_action_with_param(const char*, const char*,
    const char*, SnortConfig*)
{ return nullptr; }   // NEVER executed by the 4 gates: the duplicate END
                      // leg REJECTS at the has_action_variable seat BEFORE
                      // this one (the row :1516-:1521 re-read face)
IpsAction::Type IpsAction::get_type(const char*) { return IpsAction::Type(0); }
bool IpsAction::is_valid_action(IpsAction::Type) { return false; }

// ---- stat data faces the row references ----
// the row-referenced global data faces (the sf_ homes NEVER land; the
// counts.h / stats seats the in-TU vtables reference)
const PegInfo pc_names[] = { { END, "mirror", "shape-only" }, { END, nullptr, nullptr } };
THREAD_LOCAL SimpleStats sc_stats;
// the sfrf.h home face rides GLOBAL scope (the nm face: unmangled ref)
THREAD_LOCAL RateFilterStats rate_filter_stats;
void HostTracker::remove_flows() { }
bool HostAttributesManager::add_host(HostAttributesEntry, const SnortConfig*)
{ return false; }
const ReferenceSystem* reference_system_add(SnortConfig*, const std::string&, const char*) { return nullptr; }
SfIpRet SfCidr::set(const char*) { return SFIP_SUCCESS; }
namespace snort { THREAD_LOCAL PacketCount pc; }
void ThreadConfig::set_named_thread_affinity(const std::string&, CpuSet*) { }
FileRule::FileRule() { }
void FileRule::clear() { }
void Value::get_addr(SfIp&) const { }
void Value::update_mask(unsigned&, unsigned, bool) { }
THREAD_LOCAL EventFilterStats event_filter_stats;   // the row :1877 extern
                                                    // seat (the sfthd.cc
                                                    // home NEVER lands)

// ---- RSS mirrors (the reload_survivor_subscriptions.cc home NEVER
// lands; shapes cited, NEVER claiming real behavior) ----
namespace snort {
RssStats rss_stats;
const PegInfo rss_pegs[] =
{
    { CountType::SUM, "rss mirror", "shape-only" },
    { CountType::END, nullptr, nullptr }
};
void rss_stats_to_pegcounts(const RssStats&, PegCount* out) { out[0] = 0; }
}

// ---- MPDataBus statics + method mirrors ----
uint32_t MPDataBus::mp_max_eventq_size = 0;
std::string MPDataBus::transport = "";
bool MPDataBus::enable_debug = false;
MPDataBusStats MPDataBus::mp_global_stats;
void MPDataBus::set_debug_enabled(bool) { }
MPDataBusStats MPDataBus::get_stats_copy() { return MPDataBusStats(); }
void MPDataBus::reset_stats() { }
void MPDataBus::dump_stats(ControlConn*, const char*) { }
void MPDataBus::dump_events(ControlConn*, const char*) { }
void MPDataBus::show_channel_status(ControlConn*) { }

// ---- FastPatternConfig / FilePolicy / FileService / NetworkPolicy /
// host-attributes mirrors ----
bool FastPatternConfig::set_search_method(const char*) { return true; }
void FastPatternConfig::set_max_pattern_len(unsigned) { }
void FastPatternConfig::set_queue_limit(unsigned) { }
void FilePolicy::load() { }
void FilePolicy::set_file_type(bool) { }
void FilePolicy::set_file_signature(bool) { }
void FilePolicy::set_file_capture(bool) { }
bool FileService::file_capture_enabled = false;
void NetworkPolicy::add_file_policy_rule(FileRule&) { }
FilePolicy* NetworkPolicy::get_file_policy() const { return nullptr; }
bool HostAttributesDescriptor::update_service(uint16_t, uint16_t, SnortProtocolId, bool&, bool)
{ return false; }
const PegInfo* HostAttributesManager::get_pegs() { return nullptr; }
PegCount* HostAttributesManager::get_peg_counts() { return nullptr; }
SnortProtocolId ProtocolReference::add(const char*) { return 0; }
SnortProtocolId ProtocolReference::get_count() const { return 0; }

// ---- BatchedLogger mirrors (shape-only) ----
void BatchedLogger::BatchedLogManager::init() { }
void BatchedLogger::BatchedLogManager::shutdown() { }
void BatchedLogger::BatchedLogManager::log(FILE*, bool, const char*, va_list&) { }

// ==================================================================
// The out-of-TU module ctor mirrors — the ladder boots each; the name
// string rides the REAL ground s_name / *_NAME face of the .cc home NEVER
// landed (a CITE at each seat, the 24a ground-name-path precedent). The
// out-of-line virtuals ride shape-only bodies.
// ==================================================================
SnortModule::SnortModule() : Module("snort", "", nullptr) { }            // the s_name cite
bool SnortModule::begin(const char*, int, SnortConfig*) { return true; }
bool SnortModule::set(const char*, Value&, SnortConfig*) { return true; }
bool SnortModule::end(const char*, int, SnortConfig*) { return true; }
const PegInfo* SnortModule::get_pegs() const { return nullptr; }
PegCount* SnortModule::get_counts() const { return nullptr; }
void SnortModule::reset_stats() { }
ProfileStats* SnortModule::get_profile(unsigned, const char*&, const char*&) const { return nullptr; }
void SnortModule::set_trace(const Trace*) const { }
const TraceOption* SnortModule::get_trace_options() const { return nullptr; }

CodecModule::CodecModule() : BaseCodecModule("decode", "", nullptr) { }  // the s_name cite
const RuleMap* CodecModule::get_rules() const { return nullptr; }
void CodecModule::set_trace(const Trace*) const { }
const TraceOption* CodecModule::get_trace_options() const { return nullptr; }

DetectionModule::DetectionModule() : Module("detection", "", nullptr) { }
bool DetectionModule::begin(const char*, int, SnortConfig*) { return true; }
bool DetectionModule::set(const char*, Value&, SnortConfig*) { return true; }
bool DetectionModule::end(const char*, int, SnortConfig*) { return true; }
void DetectionModule::set_trace(const Trace*) const { }
const TraceOption* DetectionModule::get_trace_options() const { return nullptr; }

MemoryModule::MemoryModule() : Module("memory", "", nullptr) { }         // the s_name cite
const PegInfo* MemoryModule::get_pegs() const { return nullptr; }
PegCount* MemoryModule::get_counts() const { return nullptr; }
void MemoryModule::show_stats() { }
void MemoryModule::reset_stats() { }
void MemoryModule::prep_counts(bool) { }
bool MemoryModule::set(const char*, Value&, SnortConfig*) { return true; }
bool MemoryModule::end(const char*, int, SnortConfig*) { return true; }
void MemoryModule::set_trace(const Trace*) const { }
const TraceOption* MemoryModule::get_trace_options() const { return nullptr; }

PacketTracerModule::PacketTracerModule() : Module("packet_tracer", "", nullptr) { } // *_NAME cite
const Command* PacketTracerModule::get_commands() const { return nullptr; }
bool PacketTracerModule::begin(const char*, int, SnortConfig*) { return true; }
bool PacketTracerModule::set(const char*, Value&, SnortConfig*) { return true; }
bool PacketTracerModule::end(const char*, int, SnortConfig*) { return true; }

PayloadInjectorModule::PayloadInjectorModule() : Module("payload_injector", "", nullptr) { } // s_name cite
const PegInfo* PayloadInjectorModule::get_pegs() const { return nullptr; }
PegCount* PayloadInjectorModule::get_counts() const { return nullptr; }
bool PayloadInjectorModule::end(const char*, int, SnortConfig*) { return true; }

ProfilerModule::ProfilerModule() : Module("profiler", "", nullptr) { }   // the ctor-face cite
bool ProfilerModule::set(const char*, Value&, SnortConfig*) { return true; }
bool ProfilerModule::end(const char*, int, SnortConfig*) { return true; }
ProfileStats* ProfilerModule::get_profile(unsigned, const char*&, const char*&) const { return nullptr; }
const Command* ProfilerModule::get_commands() const { return nullptr; }

SFDAQModule::SFDAQModule() : Module("daq", "", nullptr) { }              // the ctor-face cite
SFDAQModule::~SFDAQModule() { }
bool SFDAQModule::set(const char*, Value&, SnortConfig*) { return true; }
bool SFDAQModule::begin(const char*, int, SnortConfig*) { return true; }
bool SFDAQModule::end(const char*, int, SnortConfig*) { return true; }
const PegInfo* SFDAQModule::get_pegs() const { return nullptr; }
PegCount* SFDAQModule::get_counts() const { return nullptr; }
void SFDAQModule::prep_counts(bool) { }
void SFDAQModule::reset_stats() { }

SideChannelModule::SideChannelModule() : Module("side_channel", "", nullptr) { } // *_NAME cite
bool SideChannelModule::set(const char*, Value&, SnortConfig*) { return true; }
bool SideChannelModule::begin(const char*, int, SnortConfig*) { return true; }
bool SideChannelModule::end(const char*, int, SnortConfig*) { return true; }
ProfileStats* SideChannelModule::get_profile() const { return nullptr; }

HighAvailabilityModule::HighAvailabilityModule() : Module("high_availability", "", nullptr) { } // HA_NAME cite
HighAvailabilityModule::~HighAvailabilityModule() { }
bool HighAvailabilityModule::begin(const char*, int, SnortConfig*) { return true; }
bool HighAvailabilityModule::set(const char*, Value&, SnortConfig*) { return true; }
bool HighAvailabilityModule::end(const char*, int, SnortConfig*) { return true; }
const PegInfo* HighAvailabilityModule::get_pegs() const { return nullptr; }
PegCount* HighAvailabilityModule::get_counts() const { return nullptr; }
ProfileStats* HighAvailabilityModule::get_profile() const { return nullptr; }

JSNormModule::JSNormModule() : Module("js_norm", "", nullptr) { }        // the s_name cite
JSNormModule::~JSNormModule() { }
bool JSNormModule::begin(const char*, int, SnortConfig*) { return true; }
bool JSNormModule::set(const char*, Value&, SnortConfig*) { return true; }
void JSNormModule::set_trace(const Trace*) const { }
const TraceOption* JSNormModule::get_trace_options() const { return nullptr; }
unsigned JSNormModule::get_gid() const { return 0; }
const Parameter JSNormModule::params[] = { { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };
const RuleMap JSNormModule::events[] = { { 0, nullptr } };
const PegInfo JSNormModule::peg_names[] = { { CountType::SUM, "js_norm mirror", "shape-only" }, { CountType::END, nullptr, nullptr } };
THREAD_LOCAL PegCount JSNormModule::peg_counts[] = { 0, 0 };
THREAD_LOCAL ProfileStats JSNormModule::profile_stats;

LatencyModule::LatencyModule() : Module("latency", "", nullptr) { }      // the s_name cite
bool LatencyModule::set(const char*, Value&, SnortConfig*) { return true; }
bool LatencyModule::end(const char*, int, SnortConfig*) { return true; }
const RuleMap* LatencyModule::get_rules() const { return nullptr; }
unsigned LatencyModule::get_gid() const { return 0; }
const PegInfo* LatencyModule::get_pegs() const { return nullptr; }
PegCount* LatencyModule::get_counts() const { return nullptr; }
void LatencyModule::set_trace(const Trace*) const { }
const TraceOption* LatencyModule::get_trace_options() const { return nullptr; }

NetworkModule::NetworkModule() : snort::Module("network", "", nullptr) { } // the ctor-face cite
bool NetworkModule::set(const char*, Value&, SnortConfig*) { return true; }
const Command* NetworkModule::get_commands() const { return nullptr; }

TraceModule::TraceModule() : Module("trace", "", nullptr) { }            // the s_name cite
TraceModule::~TraceModule() { }
const Command* TraceModule::get_commands() const { return nullptr; }
bool TraceModule::begin(const char*, int, SnortConfig*) { return true; }
bool TraceModule::set(const char*, Value&, SnortConfig*) { return true; }
bool TraceModule::end(const char*, int, SnortConfig*) { return true; }

// ActionsModule + HostTrackerModule: the inline ctors ride the ROW TU (the
// row's OWN seats — the vtables emit there); the out-of-line virtuals +
// the static params data face the row references ride the home mirrors:
PegCount* ActionsModule::get_counts() const { return nullptr; }
const PegInfo* ActionsModule::get_pegs() const { return nullptr; }
void ActionsModule::prep_counts(bool) { }
void ActionsModule::reset_stats() { }
THREAD_LOCAL std::array<PegCount, ACTIONS_ARRAY_SIZE> ActionsModule::peg_count_array;
THREAD_LOCAL std::array<PegCount, ACTIONS_ARRAY_SIZE> ActionsModule::prev_peg_count_array;
const Parameter HostTrackerModule::host_tracker_params[] =
{ { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } };
const PegInfo* HostTrackerModule::get_pegs() const { return nullptr; }
PegCount* HostTrackerModule::get_counts() const { return nullptr; }
bool HostTrackerModule::set(const char*, Value&, SnortConfig*) { return true; }
bool HostTrackerModule::begin(const char*, int, SnortConfig*) { return true; }
bool HostTrackerModule::end(const char*, int, SnortConfig*) { return true; }

// HostCacheModule ctor (the HOST_CACHE_NAME cite) + the ~Virtual + the
// default cache object data face the segmented header externs
HostCacheModule::HostCacheModule() : Module("host_cache", "", nullptr) { }
HostCacheModule::~HostCacheModule() { }
bool HostCacheModule::end(const char*, int, SnortConfig*) { return true; }
bool HostCacheModule::set(const char*, Value&, SnortConfig*) { return true; }
const Command* HostCacheModule::get_commands() const { return nullptr; }
const PegInfo* HostCacheModule::get_pegs() const { return nullptr; }
PegCount* HostCacheModule::get_counts() const { return nullptr; }
void HostCacheModule::prep_counts(bool) { }
void HostCacheModule::sum_stats(bool) { }
void HostCacheModule::reset_stats() { }
void HostCacheModule::set_trace(const Trace*) const { }
const TraceOption* HostCacheModule::get_trace_options() const { return nullptr; }
void HostCacheModule::log_host_cache(const char*, bool) { }
std::string HostCacheModule::get_host_cache_stats() { return ""; }
std::string HostCacheModule::get_host_cache_segment_stats(int) { return ""; }
HostCacheIp default_host_cache(1024);
