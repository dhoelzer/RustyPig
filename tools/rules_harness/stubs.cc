#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/policy.h"
#include "main/thread_config.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"
#include "parser/parse_rule.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "managers/so_manager.h"
#include "parser/cmd_line.h"
#include "detection/extract.h"
#include "detection/rtn_checks.h"
#include "filterz/sfthd.h"
#include "framework/ips_option.h"
#include "log/messages.h"
#include "sfip/sf_vartable.h"
#include "utils/util.h"
#include <climits>
#include "parser/vars.h"
#include "ports/port_var_table.h"
#include "ports/port_table.h"
#include "parser/parse_ports.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ostream>
using namespace snort;

uint32_t SnortConfig::warning_flags = 0;
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::output_flags = 0;
bool SnortConfig::log_quiet_bypassed = false;
std::unordered_map<std::string, std::string> SnortConfig::static_names;
std::mutex SnortConfig::static_names_mutex;
SnortConfig* g_probe_sc = nullptr;
SnortConfig* SnortConfig::get_conf() { return g_probe_sc; }
SnortConfig* SnortConfig::get_main_conf() { return g_probe_sc; }
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
bool SnortConfig::get_default_rule_state() const
{
    switch ( get_ips_policy()->default_rule_state )
    {
    case IpsPolicy::INHERIT_ENABLE:
        return global_default_rule_state;
    case IpsPolicy::ENABLED:
        return true;
    case IpsPolicy::DISABLED:
        return false;
    }
    return true;
}
// PolicyMap ctor/dtor: policy.cc's real body wires Shell/NetworkPolicy/
// InspectorManager/DataBus monoliths (out of scope). Substitute keeps the
// ips-policy semantics only (documented deviation; probe never reaches
// shells/network/selector paths).
PolicyMap::PolicyMap()
{
    empty_ips_policy = new IpsPolicy((PolicyId)ips_policy.size());
    ips_policy.push_back(empty_ips_policy);
}
PolicyMap::~PolicyMap() { for ( auto p : ips_policy ) delete p; ips_policy.clear(); }
unsigned ThreadConfig::get_instance_max() { return 2; }
unsigned get_instance_id() { return 0; }

// ------------- IpsPolicy members: VERBATIM from main/policy.cc ----------
IpsPolicy::IpsPolicy(PolicyId id) :
    action(IpsAction::get_max_types(), nullptr),
    configured_action(1, nullptr)
{
    policy_id = id;
    policy_mode = POLICY_MODE__MAX;
    var_table = nullptr;
    var_id = 1;
    ip_vartable = sfvt_alloc_table();
    portVarTable = PortVarTableCreate();
    nonamePortVarTable = PortTableNew();
    enable_builtin_rules = false;
    obfuscate_pii = true;
}
IpsPolicy::~IpsPolicy()
{
    if ( var_table )
        DeleteVars(var_table);
    if ( ip_vartable )
        sfvt_free_table(ip_vartable);
    if ( portVarTable )
        PortVarTableFree(portVarTable);
    if ( nonamePortVarTable )
        PortTableFree(nonamePortVarTable);
}
void IpsPolicy::update_user_policy_id()
{
    if ( user_policy_id == 0 )
        user_policy_id = 1;
}
bool IpsPolicy::has_action_variable_capacity() const
{ return configured_action.size() <= UINT8_MAX; }
bool IpsPolicy::has_action_variable(const std::string& name) const
{ return action_vars.find(name) != action_vars.end(); }
void IpsPolicy::commit_action_variable(const std::string& name,
    const std::string& action_name, IpsAction* act)
{
    const auto selector = (ActionSelector)configured_action.size();
    const auto action_type = IpsAction::get_type(action_name.c_str());
    action_vars.emplace(name, std::make_tuple(action_name, action_type, selector));
    configured_action.push_back(act);
}
bool IpsPolicy::get_action_variable(const std::string& name, const std::string*& action_name,
    IpsAction::Type& action_type, ActionSelector& selector) const
{
    const auto it = action_vars.find(name);
    if ( it == action_vars.end() )
        return false;
    action_name = &std::get<0>(it->second);
    action_type = std::get<1>(it->second);
    selector = std::get<2>(it->second);
    return true;
}
static IpsPolicy* s_detection_policy = nullptr;
IpsPolicy* snort::get_ips_policy() { return s_detection_policy; }
void snort::set_ips_policy(IpsPolicy* p) { s_detection_policy = p; }
void set_ips_policy(const SnortConfig* sc, unsigned i)
{ snort::set_ips_policy(sc->policy_map->get_ips_policy(i)); }
IpsPolicy* snort::get_empty_ips_policy(const SnortConfig* sc)
{ return sc->policy_map->get_empty_ips(); }

// ---------------- ActionManager seam -> probe-pinned ordering -------------
#include <vector>
static std::vector<std::string> g_acts;
unsigned probe_register_action(const char* n)
{ g_acts.emplace_back(n); return (unsigned)g_acts.size() - 1; }
// member fns of framework/ips_action.cc (file NOT compiled: actions/plugin
// monolith). Bodies mirror upstream against the registration witness above.
IpsAction::Type IpsAction::get_type(const char* s)
{
    for ( size_t i = 0; i < g_acts.size(); ++i )
        if ( g_acts[i] == s )
            return (IpsAction::Type)i;
    return (IpsAction::Type)g_acts.size();
}
IpsAction::Type IpsAction::get_max_types() { return (IpsAction::Type)g_acts.size(); }
const char* probe_action_name(IpsAction::Type t)
{ return t < g_acts.size() ? g_acts[t].c_str() : "ERROR"; }

// ---------------- option/plugin-layer witnesses: abort on reach ----------
bool IpsManager::option_begin(SnortConfig*, const char*, SnortProtocolId, uint64_t) { std::abort(); }
bool IpsManager::option_set(SnortConfig*, const char*, const char*, const char*) { std::abort(); }
IpsOption* IpsManager::option_end(SnortConfig*, OptTreeNode*, SnortProtocolId, const char*, RuleOptType&) { std::abort(); }
bool ModuleManager::gid_in_use(uint32_t) { return false; }
const char* SoManager::get_so_rule(const char*) { return nullptr; }

// ---------------- never-reached link witnesses ---------------------------
void sfthd_node_free(THD_NODE*) { std::abort(); }
int RuleListEnd(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckBidirectional(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckProto(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
void flowbits_counts(unsigned& t, unsigned& u, unsigned& s) { t = u = s = 0; }
void flowbits_print_deps(std::ostream&) { std::abort(); }
void ClearIpsOptionsVars() { } // verbatim-equivalent: extract.cc body zeroes cnt
void show_pcre_counts() { }
namespace snort {
const char* get_error(int errnum)
{
    static THREAD_LOCAL char buf[128];

#if 1
    return strerror_r(errnum, buf, sizeof(buf));
#else
    (void)strerror_r(errnum, buf, sizeof(buf));
    return buf;
#endif
}

}
