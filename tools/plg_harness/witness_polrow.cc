// witness (row 24h): shape-only + FUNCTIONAL mirrors for the row TU's
// app-undef face — the namespaces ride the row .o's OWN nm -C census,
// NEVER from air. THE DIVERGENCE from the 24e witness law: this row LINKS
// the row's OWN boot legs REAL (the IpsPolicy ctor/dtor pull the ports/
// parser/hash/sfip homes — 22 REAL ground .o's link, NEVER stubs); the
// witness closes ONLY the NEVER-executed out-of-TU seats the row TU
// references (Shell/CodecManager/InspectorManager/DataBus/FilePolicy
// family/DetectionEngine/SnortConfig boot/ActionManager/PluginManager +
// the messages.cc counter legs). The nav-home family (get_ips_policy /
// set_* / the only_* pair / get_policies) is OWNED by policy.cc ITSELF:
// the gate takes it from the row .o; the probes carry it through the
// direct-include seat (the include-trick the task licenses — the
// static THREAD_LOCAL nav ladder cc :325-:328 rides there).
#include "main/snort_config.h"
#include "main/policy.h"
#include "main/thread_config.h"
#include "main/thread.h"
#include "framework/parameter.h"
#include "framework/value.h"
#include "framework/ips_action.h"
#include "framework/data_bus.h"
#include "framework/mp_data_bus.h"
#include "framework/counts.h"
#include "framework/mpse.h"
#include "managers/codec_manager.h"
#include "managers/inspector_manager.h"
#include "managers/action_manager.h"
#include "managers/plugin_manager.h"
#include "actions/actions_module.h"
#include "file_api/file_policy.h"
#include "detection/detection_engine.h"
#include "detection/detect.h"
#include "detection/detection_options.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"
#include "ports/port_group.h"
#include "log/batched_logger.h"
#include "log/messages.h"
#include "control/control.h"
#include "shell.h"
#include "utils/stats.h"
#include "catch/snort_catch.h"
#include <climits>
#include <cstdio>
#include <cstring>
#include <string>

using namespace snort;

// ---- the Catch TEST_CASE installer (the REAL ground catch/unit_test.cc
// body shape cited; the unit_test.cc TU NEVER lands; REGISTER_TEST_CASE
// rides the VENDORED catch.hpp decl seat — the RUNNER .o carries the
// impl; the 24c/24e shim law) ----
namespace snort {
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name)
{ REGISTER_TEST_CASE(fun, name) }
TestCaseInstaller::TestCaseInstaller(void(*fun)(), const char* name, const char* group)
{ REGISTER_TEST_CASE(fun, name, group) }
}

// ---- the NEVER-executed policy-shell family mirrors (the homes NEVER
// land; the 3 in-TU cases construct ONLY IpsPolicy — the Shell/
// NetworkPolicy/InspectorManager/CodecManager/DataBus/DetectionEngine
// seats NEVER execute at the gate NOR at the probes) ----
CodecManager::CodecManager() { }
CodecManager::~CodecManager() { }
Shell::Shell(const char*, bool) { }
Shell::~Shell() { }
TrafficPig* InspectorManager::create_traffic_group() { return nullptr; }
ServicePig* InspectorManager::create_service_group() { return nullptr; }
GlobalPig* InspectorManager::create_global_group() { return nullptr; }
void InspectorManager::delete_group(TrafficPig*) { }
void InspectorManager::delete_group(ServicePig*) { }
void InspectorManager::delete_group(GlobalPig*) { }
DataBus::DataBus() { }
DataBus::~DataBus() { }
void DataBus::subscribe(const PubKey&, unsigned, DataHandler*) { }
bool DetectionEngine::detect(Packet*, bool) { return false; }

// ---- the FilePolicy family mirror (the file_api homes NEVER land; the
// 3 cases NEVER construct a FilePolicy — the vtable-for-FilePolicy +
// FilePolicyBase seats ride the row .o's own nm census) ----
FilePolicyBase::FilePolicyBase() { }
FilePolicyBase::~FilePolicyBase() { }
void FilePolicyBase::delete_file_policy(FilePolicyBase* fp) { delete fp; }
void FilePolicy::add_file_id(FileRule&) { }
void FilePolicy::policy_check(Flow*, FileInfo*) { }
FileVerdict FilePolicy::type_lookup(Packet*, FileInfo*) { return FILE_VERDICT_UNKNOWN; }
FileVerdict FilePolicy::signature_lookup(Packet*, FileInfo*) { return FILE_VERDICT_UNKNOWN; }
FileRule::FileRule() { }
void FileRule::clear() { }

// ---- the REAL port_group.cc .o cleanup seats the gate/probes NEVER
// reach (no options EVER compiled, no mpse group EVER built — the
// ANY-only ctor path is MEASURED) ----
MpseGroup::~MpseGroup() { }
void free_detection_option_root(void**) { }

// ---- the legs the REAL ground log/messages.cc .o (linked REAL) pulls
// (the BatchedLogger + parse-location homes NEVER land; 24e law) ----
void BatchedLogger::BatchedLogManager::init() { }
void BatchedLogger::BatchedLogManager::shutdown() { }
void BatchedLogger::BatchedLogManager::log(FILE*, bool, const char*, va_list&) { }
void get_parse_location(const char*& file, unsigned& line) { file = ""; line = 0; }

// ---- SnortConfig boot legs (the snort_config.cc home NEVER lands; the
// static-local boot seat, the 24e shape; the gate NEVER derefs get_conf
// beyond the boot seat the legs consult) ----
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

// ---- pulled legs the REAL ground .o's reference (namespaces ride the
// nm -C census: get_instance_id / get_thread_type / pc / the stats face) ----
namespace snort { unsigned get_instance_id() { return 0; }
SThreadType get_thread_type() { return STHREAD_TYPE_MAIN; } }
namespace snort { THREAD_LOCAL PacketCount pc; }
unsigned ThreadConfig::get_instance_max() { return 1; }

// ---- the NEVER-executed parser/action-family mirrors (homes NEVER land;
// shape-only, cited at the reference seats; the in-TU commit leg rides
// the REAL IpsAction::get_type body (ips_action.cc REAL) which consults
// the ActionManager mirror — the 24e instantiate-with-param precedent) ----
bool ParseIpVar(const char*, const char*) { return true; }
Module* PluginManager::get_module(const char*) { return nullptr; }
Module* PluginManager::get_module(const char*, const BaseApi*&) { return nullptr; }
std::string ActionManager::get_action_string(IpsAction::Type) { return ""; }
IpsAction::Type ActionManager::get_action_type(const char*) { return IpsAction::Type(0); }
IpsAction::Type ActionManager::get_max_action_types() { return IpsAction::Type(0); }
std::string ActionManager::get_action_priorities(bool) { return ""; }
void ActionsModule::add_action(std::string, const PegInfo*) { }
void CallLogFuncs(Packet*, const OptTreeNode*, ListHead*) { }
void CallAlertFuncs(Packet*, const OptTreeNode*, ListHead*) { }
void rule_index_map_print_index(int, char*, int) { }
