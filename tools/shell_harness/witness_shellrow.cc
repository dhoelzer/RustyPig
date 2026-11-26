// witness (row 24c scratch): shape-only mirror for the row TU app-undef face.
#include "main/shell.h"
#include "main/snort_config.h"
#include "main/policy.h"
#include "dump_config/config_data.h"
#include "dump_config/config_output.h"
#include "framework/module.h"
#include "managers/module_manager.h"
#include "parser/parse_conf.h"
#include "log/messages.h"
#include "utils/stats.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdarg>

using namespace snort;

std::vector<std::string> g_probe_trace;
void probe_reset_trace() { g_probe_trace.clear(); }
static void rec(const char* s) { g_probe_trace.emplace_back(s); }

// ---- parse_conf legs ----
const char* get_parse_file() { return ""; }
const char* get_config_file(const char*, std::string& f) { return f.empty() ? nullptr : "W"; }
void push_parse_location(const char*, const char*, const char*, unsigned) { rec("parse.push_loc"); }
void pop_parse_location() { rec("parse.pop_loc"); }
void parse_include(SnortConfig*, const char*) {}

// ---- policy legs (the ground DECL mirror; shape-only; the free fns ride
// namespace snort exactly as the ground policy.h h :96-:117 declares them) ----
namespace snort {
void set_network_policy(NetworkPolicy*) { rec("pol.set_net"); }
void set_network_policy(unsigned) {}
void set_network_parse_policy(NetworkPolicy*) { rec("pol.set_netparse"); }
void set_inspection_policy(InspectionPolicy*) { rec("pol.set_insp"); }
void set_inspection_policy(unsigned) {}
void set_ips_policy(IpsPolicy*) { rec("pol.set_ips"); }
void set_ips_policy(const SnortConfig*, unsigned) {}
}
void set_default_policy(const snort::SnortConfig*) { rec("pol.set_default"); }
std::shared_ptr<PolicyTuple> PolicyMap::get_policies(Shell*) { rec("pmap.get_policies"); return nullptr; }
NetworkPolicy* PolicyMap::get_user_network(uint64_t) const { return nullptr; }

// ---- SnortConfig subset legs (the 24a witness pattern, OWN seats) ----
static SnortConfig* g_boot_conf = nullptr;
SnortConfig::SnortConfig(const char*) : reload_id(0) {}
SnortConfig::~SnortConfig() { if (g_boot_conf == this) g_boot_conf = nullptr; }
uint32_t SnortConfig::logging_flags = 0;
const SnortConfig* SnortConfig::get_conf()
{
    if (!g_boot_conf) g_boot_conf = new SnortConfig("");
    return g_boot_conf;
}
void SnortConfig::set_conf(SnortConfig* s) { rec("sc.set_conf"); (void)s; }

// ---- ModuleManager legs ----
void ModuleManager::set_config(SnortConfig*) { rec("mod.set_config"); }
const char* ModuleManager::get_lua_coreinit() { return nullptr; }

// ---- dump_config legs (DECL rider home; shape-only) ----
BaseConfigNode::BaseConfigNode(BaseConfigNode* p) : parent(p) {}
void BaseConfigNode::add_child_node(BaseConfigNode* node) { children.push_back(node); }
void BaseConfigNode::clear_nodes(BaseConfigNode*) {}
void BaseConfigNode::sort_nodes(BaseConfigNode*) {}
TreeConfigNode::TreeConfigNode(BaseConfigNode* p, const std::string& n, const Parameter::Type t)
    : BaseConfigNode(p), name(n), type(t) {}
BaseConfigNode* TreeConfigNode::get_node(const std::string& n)
{
    for (auto* c : children)
        if (auto* t = dynamic_cast<TreeConfigNode*>(c))
            if (t->get_name() == n) return c;
    return nullptr;
}
snort::Parameter::Type Value::get_param_type() const { return snort::Parameter::PT_MAX; }
ValueConfigNode::ValueConfigNode(BaseConfigNode* p, const Value& v, const std::string& n)
    : BaseConfigNode(p), value(v), custom_name(n) {}
void ValueConfigNode::set_value(const Value&) {}
BaseConfigNode* ValueConfigNode::get_node(const std::string&) { return nullptr; }
ConfigData::ConfigData(const char* f) { if (f) file_name = f; rec("cfgdata.ctor"); }
ConfigData::~ConfigData() { for (auto* t : config_trees) delete t; }
void ConfigOutput::dump_config(ConfigData&, bool) { rec("cout.dump"); }

// ---- log legs (shape-only; NOTHING reaches stdout/stderr; the ground
// decls ride namespace snort per log/messages.h) ----
namespace snort {
void ErrorMessage(const char*, ...) {}
void ParseError(const char*, ...) {}
void LogMessage(const char*, ...) {}
void LogMessage(const char*, va_list&) {}
void LogMessage(FILE*, const char*, ...) {}
void ConsoleMessage(bool, const char*, ...) {}
void ErrOrWarnMsg(const char*, ...) {}
void FatalError(const char*, ...) { std::fprintf(stderr, "witness FatalError\n"); std::abort(); }
void ConfigLogger::log_list(const char*, const char*, const char*, bool) { rec("clog.list3"); }
void ConfigLogger::log_list(const char*) { rec("clog.list1"); }
}

// ---- dep-version mirror legs (SYNTH rider homes; NEVER an ABI claim) ----
extern "C" {
const char* pcap_lib_version() { return "libpcap version 1.10.4-witness"; }
const char* daq_version_string() { return "3.0.14-witness"; }
int pcre2_config(int what, void* where)
{
    (void)what;
    const char* v = "10.42-witness";
    if (where) std::strncpy((char*)where, v, 64);
    return (int)std::strlen(v);
}
}


// ---- THE ffi legs (row 24c): the extern "C" faces the ground bootstrap.lua


extern "C" {

// ---- bootstrap.lua cdef :27-:31 ----
const char* push_include_path(const char* f) { return f; }
void pop_include_path() {}
void snort_whitelist_append(const char* kw) { Shell::allowlist_append(kw, false); }
void snort_whitelist_add_prefix(const char* kw) { Shell::allowlist_append(kw, true); }
int get_module_version(const char*, const char*) { return 0x00030000; }

// ---- finalize.lua cdef :25-:32 (the config-dump table legs; the ground
// seats these on Shell statics; dump is FALSE in the boot posture so the
// legs are reached ONLY for the traverse census, NEVER for a real dump) ----
bool open_table(const char*, int) { return false; }
void close_table(const char*, int) {}
bool set_bool(const char*, bool) { return true; }
bool set_number(const char*, double) { return true; }
bool set_string(const char*, const char*) { return true; }
bool set_includer(const char*, const char*) { return true; }
bool set_alias(const char*, const char*) { return true; }
void clear_alias() {}

}
