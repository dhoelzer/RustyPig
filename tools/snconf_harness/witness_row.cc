// witness_row.cc — row 24g witness mirror (shape-only capture legs for the
// NEVER-LAND wall the row .o's OWN nm -C census enumerates (plain EXACTLY-84,
// MEASURED); EVERY name + namespace placement rides the row's OWN raw-NAME
// nm -C CENSUS face — the compiler ENFORCED the restructure honestly). The
// legs that link REAL and are NEVER mirrored here: packet_io/sfdaq_config.cc
// (the DAQ-config home, the 23a landed home), sfip/sf_cidr.cc (the SfCidr
// set/clear/get_family home), sfip/sf_ip.cc (the SfIp home), utils/util.cc
// (the snort_strdup home), target_based/snort_protocols.cc (the
// ProtocolReference home) and trace/trace_config.cc (the TraceConfig home).
// The three SnortConfig statics (warning/logging flags + the THREAD_LOCAL
// log_quiet_bypassed) are NEVER mirrored — the ROW TU DEFINES them (cc
// :110-:112; the E9 twin law). The dnet shim legs (eth_pton/eth_ntop) ride
// the copy-tree grafted dnet.h (libdnet ABSENT on this box — the act-family
// graft precedent) and are mirrored HERE. The uid/gid getpwnam/getgrnam
// family is libc (NEVER mirrored, NEVER driven in the ladder — cited rows).
// Every mirror echoes name+arg to stdout -> deterministic vectors rows
// (ZERO pointers, ZERO times, ZERO randomness). No private-access flag EVER
// ships: every face is reached through the PUBLIC seats + header INLINES
// (PolicyMap/NetworkPolicy/IpsPolicy mirror ctors DO touch their own
// privates exactly as the ground ctors do — a member definition may).
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <cstdlib>
#include <list>
#include <string>
#include <vector>
#include <memory>

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/policy.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/snort.h"
#include "main/process.h"
#include "main/reload_tuner.h"
#include "main/thread_config.h"
#include "framework/data_bus.h"
#include "framework/mp_data_bus.h"
#include "framework/mpse.h"
#include "helpers/scratch_allocator.h"
#include "helpers/challenge_response_auth.h"
#include "log/messages.h"
#include "managers/action_manager.h"
#include "managers/event_manager.h"
#include "managers/ips_manager.h"
#include "managers/plugin_manager.h"
#include "managers/mpse_manager.h"
#include "utils/dnet_header.h"
#include "packet_io/sfdaq.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "detection/rules.h"
#include "detection/signature.h"
#include "detection/fp_create.h"
#include "parser/parser.h"
#include "filters/rate_filter.h"
#include "filters/sfthreshold.h"
#include "filters/detection_filter.h"
#include "events/event_queue.h"
#include "file_api/file_service.h"
#include "ports/rule_port_tables.h"
#include "profiler/profiler_impl.h"
#include "dump_config/config_data.h"
#include "dump_config/config_output.h"
#include "dump_config/json_config_output.h"
#include "dump_config/text_config_output.h"
#include "managers/module_manager.h"
#include "packet_io/packet_constraints.h"
#include "trace/trace.h"

using namespace snort;

static unsigned mirror_instance_max = 1;      // the -z seat (ThreadConfig mirror)

// ---- the dnet shim legs (the grafted head rides utils/dnet_header.h :40):
// the row's set_dst_mac body (cc :664-:684) drives eth_pton; the mirror
// parses ONLY a fixed deterministic face (a leading '0' name parses OK with
// a canned 6-byte pattern; everything else the reject face). ----
extern "C" {
int eth_pton(const char* name, eth_addr_t* eth)
{
    printf("W eth_pton %s\n", name ? name : "(null)");
    if (!name || name[0] != '0')
        return -1;
    for (int i = 0; i < 6; ++i)
        eth->data[i] = (unsigned char)(0xa0 + i);
    return 0;
}
int eth_ntop(const eth_addr_t* eth, char* buf, int len)
{
    (void)eth; (void)buf; (void)len;
    printf("W eth_ntop\n");
    return 0;
}
}

// ---- main/process.cc NEVER lands (the uid/gid + daemon/kill wall): the
// TWO seats the row census pulls mirrored (the dtor trim_heap leg + the
// setup gmt2local leg — the probe NEVER calls setup, cited NF rows). ----
void trim_heap() { printf("W trim_heap\n"); }
int gmt2local(time_t t) { printf("W gmt2local %ld\n", (long)t); return 0; }

// ---- main/thread_config.cc NEVER lands (the hwloc wall face, the seat
// EXCISION the donor rides): the statics mirrored with the mirror counter
// (the merge() num_slots = offload_threads + get_instance_max():513 face) +
// the dtor the row ~SnortConfig drags. ----
void ThreadConfig::set_instance_max(unsigned m)
{ mirror_instance_max = m; printf("W ThreadConfig::set_instance_max %u\n", m); }
unsigned ThreadConfig::get_instance_max() { return mirror_instance_max; }
ThreadConfig::~ThreadConfig() { printf("W ThreadConfig.dtor\n"); }

// ---- manager statics the census pulls: EventManager's two bools (the
// alert/log mode legs write them through the header INLINES — the GROUND
// defaults mirrored honest), the ActionManager/IpsManager/PluginManager/
// MpseManager statics mirrored name+arg. ----
bool EventManager::alert_enabled = true;
bool EventManager::log_enabled = true;
void ActionManager::new_config(SnortConfig*) { printf("W ActionManager.new_config\n"); }
void ActionManager::delete_config(SnortConfig*) { printf("W ActionManager.delete_config\n"); }
bool IpsManager::verify(SnortConfig*) { printf("W IpsManager.verify\n"); return true; }
void PluginManager::release_plugins(PlugSet*) { printf("W PluginManager.release_plugins\n"); }
void MpseManager::stop_search_engine(const MpseApi*) { printf("W MpseManager.stop_search_engine\n"); }

// ---- main/snort.h home NEVER lands: the is_reloading gate the
// register_reload_handler body reads (cc :1058-:1064 — the false delete-
// away face LIVE). ----
bool Snort::is_reloading() { printf("W Snort::is_reloading\n"); return false; }

// ---- file_api NEVER lands: the dtor-safe close seat cleanup_fatal_error
// (cc :1096-:1113, the REG_TEST insides NEVER compiled at this posture). ----
void FileService::close() { printf("W FileService::close\n"); }

// ---- packet_io/sfdaq.cc NEVER lands (the msg-API wall the SFDAQ DECL
// face skates): the tunnel-bypass seat the tunnel_bypass_enabled body (cc
// :1020-:1023) drags mirrored (the constant-false face = pure mask face). ----
bool SFDAQ::get_tunnel_bypass(uint16_t proto)
{ printf("W SFDAQ::get_tunnel_bypass %x\n", (unsigned)proto); return false; }

// ---- framework/data_bus.cc NEVER lands (the pub_sub + reload-survivor
// wall): both bus ctors/dtors mirrored (the ctor new's + the dtor deletes). ----
DataBus::DataBus() { printf("W DataBus.ctor\n"); }
DataBus::~DataBus() { printf("W DataBus.dtor\n"); }
MPDataBus::MPDataBus() { printf("W MPDataBus.ctor\n"); }
MPDataBus::~MPDataBus() { printf("W MPDataBus.dtor\n"); }

// ---- main/policy.cc NEVER lands (the file_policy + js_norm wall): the
// PolicyMap seat family mirrored — the ctor touches its OWN privates (like
// the ground ctor) and seats ONE NetworkPolicy (the merge() -k checksum
// face :412-:420 + the min_ttl()/new_ttl() readbacks ride it); the
// NetworkPolicy/IpsPolicy ctors mirrored with their unmasked members set;
// PolicyTuple/get_policies mirrored shape-only (the set_conf face :1052-
// :1054 short-circuits on the EMPTY sh-ells vector — NEVER fires). ----
PolicyMap::PolicyMap()
{
    printf("W PolicyMap.ctor\n");
    empty_ips_policy = nullptr;
    global_group = nullptr;
    network_policy.push_back(new NetworkPolicy());
}
PolicyMap::~PolicyMap()
{
    printf("W PolicyMap.dtor\n");
    for ( auto p : network_policy ) delete p;
    for ( auto p : ips_policy ) delete p;
}
std::shared_ptr<PolicyTuple> PolicyMap::get_policies(Shell*)
{ printf("W PolicyMap.get_policies\n"); return std::shared_ptr<PolicyTuple>(); }
bool PolicyMap::setup_network_policies()
{ printf("W PolicyMap.setup_network_policies\n"); return true; }

NetworkPolicy::NetworkPolicy(PolicyId id, PolicyId def_ips) :
    policy_id(id), default_ips_policy_id(def_ips)
{ printf("W NetworkPolicy.ctor id=%u\n", id); }
NetworkPolicy::~NetworkPolicy() { printf("W NetworkPolicy.dtor\n"); }

IpsPolicy::IpsPolicy(PolicyId id) :
    policy_id(id), enable_builtin_rules(false), var_id(0), var_table(nullptr),
    ip_vartable(nullptr), portVarTable(nullptr), nonamePortVarTable(nullptr),
    obfuscate_pii(false)
{ printf("W IpsPolicy.ctor id=%u\n", id); }
IpsPolicy::~IpsPolicy() { printf("W IpsPolicy.dtor\n"); }

namespace snort {
// the current-seat navigators (the get_default_rule_state :982-:996 face
// rides the mirrored static IpsPolicy — the INHERIT_ENABLE NSDMI default +
// the row's global_default_rule_state NSDMI true — the walked LIVE face)
IpsPolicy* get_ips_policy() { static IpsPolicy p(0); return &p; }
NetworkPolicy* get_network_policy() { static NetworkPolicy np; return &np; }
// the sc,i navigator mirrors the GROUND body honest (policy.cc :366-:370)
IpsPolicy* get_ips_policy(const SnortConfig* sc, unsigned i)
{ return (sc && i < sc->policy_map->ips_policy_count()) ? sc->policy_map->get_ips_policy(i) : nullptr; }
}
void set_policies(const SnortConfig*, Shell*) { printf("W set_policies\n"); }

// ---- log/messages.cc NEVER lands (the batched_logger + config-warning
// walls): the three Parse*/ReloadError varargs legs + the util legs'. ----
namespace snort {
void ParseError(const char* fmt, ...) { printf("W ParseError\n"); (void)fmt; }
void ParseWarning(WarningGroup g, const char* fmt, ...) { printf("W ParseWarning g=%d\n", (int)g); (void)fmt; }
void ReloadError(const char* fmt, ...) { printf("W ReloadError\n"); (void)fmt; }
void ErrorMessage(const char* fmt, ...) { printf("W ErrorMessage\n"); (void)fmt; }
void ErrorMessage(const char* fmt, va_list& ap) { (void)fmt; (void)ap; }
int SnortSnprintf(char* buf, size_t buf_len, const char* fmt, ...)
{ (void)buf; (void)buf_len; (void)fmt; return 0; }
}

// ---- main/analyzer.cc + analyzer_command.cc NEVER land: the hook seat
// (the alert/log mode legs :953-:978 record inspect/ignore/log identities —
// a NAME face, NEVER a pointer) + the update_scratch broadcast :381-:384
// (the ACScratchUpdate vtable the row census pulls). ----
void Analyzer::set_main_hook(MainHook_f f)
{
    int who = (f == DetectionEngine::inspect) ? 1 : (f == snort_ignore) ? 2 : (f == snort_log) ? 3 : 0;
    printf("W Analyzer::set_main_hook who=%d\n", who);
}
namespace snort {
void main_broadcast_command(AnalyzerCommand*, ControlConn*)
{ printf("W main_broadcast_command\n"); }
bool Trace::set(const std::string& opt, uint8_t level, const Module*)
{ printf("W Trace.set %s lvl=%u\n", opt.c_str(), (unsigned)level); return true; }
}
bool ACScratchUpdate::execute(Analyzer&) { printf("W ACScratchUpdate.execute\n"); return true; }
ACScratchUpdate::~ACScratchUpdate() { printf("W ACScratchUpdate.dtor\n"); }
bool snort_ignore(snort::Packet*) { printf("W snort_ignore\n"); return false; }
bool snort_log(snort::Packet*) { printf("W snort_log\n"); return false; }
namespace snort {
bool DetectionEngine::inspect(snort::Packet*) { printf("W DetectionEngine::inspect\n"); return true; }
}

// ---- helpers NEVER land: the scratch ctor/dtor the probe's allocator
// seats ride + the control-socket secret loader (the setup :343-:344 leg,
// cited). The loader + the analyzer broadcast ride the snort:: namespace
// (the RAW -u census faces, the demangled table NEVER pins these). ----
ScratchAllocator::ScratchAllocator() { printf("W ScratchAllocator.ctor\n"); }
ScratchAllocator::~ScratchAllocator() { printf("W ScratchAllocator.dtor\n"); }
namespace snort {
uint8_t* load_shared_secret(const char* fname, size_t& len)
{ printf("W load_shared_secret %s\n", fname ? fname : "(null)"); len = 0; return nullptr; }
}

// ---- parser/rule walls (the free-family + the dtor/set up legs): every
// one a deterministic name echo; the dtor family fires ONCE per live
// SnortConfig delete, the setup family NEVER (the ParseRules wall, cited). ----
void ParseRules(SnortConfig*) { printf("W ParseRules\n"); }
void ParseRulesFinish(SnortConfig*) { printf("W ParseRulesFinish\n"); }
void OrderRuleLists(SnortConfig*) { printf("W OrderRuleLists\n"); }
void FreeRuleLists(SnortConfig*) { printf("W FreeRuleLists\n"); }
void OtnLookupFree(GHash*) { printf("W OtnLookupFree\n"); }
void PortTablesFree(RulePortTables*) { printf("W PortTablesFree\n"); }
void ThresholdConfigFree(ThresholdConfig*) { printf("W ThresholdConfigFree\n"); }
void RateFilter_ConfigFree(RateFilterConfig*) { printf("W RateFilter_ConfigFree\n"); }
void DetectionFilterConfigFree(DetectionFilterConfig*) { printf("W DetectionFilterConfigFree\n"); }
void EventQueueConfigFree(EventQueueConfig*) { printf("W EventQueueConfigFree\n"); }
int fpCreateFastPacketDetection(SnortConfig*) { printf("W fpCreateFastPacketDetection\n"); return 0; }
void fpDeleteFastPacketDetection(SnortConfig*) { printf("W fpDeleteFastPacketDetection\n"); }
void RuleStateMap::apply(SnortConfig*) { printf("W RuleStateMap.apply\n"); }
void Profiler::clear(SnortConfig*) { printf("W Profiler.clear\n"); }
snort::IpsAction::Type IpsAction::get_max_types() { printf("W IpsAction::get_max_types\n"); return 16; }

// ---- the REAL trace_config.cc leg drags these NEVER-LAND homes (the
// set_trace/load_traces wall): the PluginManager module-lookup seats + the
// Trace trio + the PacketConstraints copy seat (the TraceConfig COPY ctor's
// clone leg — NEVER fired at this ladder, link-only honest). ----
snort::Module* PluginManager::get_module(const char* n)
{ printf("W PluginManager::get_module %s\n", n ? n : "(null)"); return nullptr; }
std::list<snort::Module*> PluginManager::get_all_modules(const SnortConfig*)
{ printf("W PluginManager::get_all_modules\n"); return std::list<snort::Module*>(); }
Trace::Trace(const Module* mod) : mod_name(mod ? mod->get_name() : "(no-mod)")
{ printf("W Trace.ctor mod=%s\n", mod_name.c_str()); }
void Trace::set_module_trace() const { printf("W Trace.set_module_trace\n"); }
void Trace::clear() { printf("W Trace.clear\n"); }
namespace snort {
PacketConstraints::PacketConstraints(const PacketConstraints& o) :
    ip_proto(o.ip_proto), src_port(o.src_port), dst_port(o.dst_port),
    src_ip(o.src_ip), dst_ip(o.dst_ip), set_bits(o.set_bits), match(o.match),
    tenants(o.tenants)
{ printf("W PacketConstraints.copy_ctor\n"); }
} // namespace snort

// ---- dump_config walls (the JsonAll/T/Text + ConfigData legs the
// create_config_output :998-:1018 switch + the generate_dump :1082-:1094
// rider pull; NEVER fired in-proc — the thread/getpid/time run face cited). ----
ConfigData::~ConfigData() { printf("W ConfigData.dtor\n"); }
void ConfigOutput::dump_config(ConfigData&, bool) { printf("W ConfigOutput.dump_config\n"); }
JsonAllConfigOutput::JsonAllConfigOutput(const char* fname) : file(nullptr), json(nullptr)
{ printf("W JsonAllConfigOutput.ctor %s\n", fname ? fname : "(stdout)"); }
JsonAllConfigOutput::~JsonAllConfigOutput() { printf("W JsonAllConfigOutput.dtor\n"); }
void JsonAllConfigOutput::dump(const ConfigData&) { printf("W JsonAllConfigOutput.dump\n"); }
void JsonTopConfigOutput::dump(const ConfigData&) { printf("W JsonTopConfigOutput.dump\n"); }
void TextConfigOutput::dump(const ConfigData&) { printf("W TextConfigOutput.dump\n"); }
