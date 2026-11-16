#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/policy.h"
#include "main/thread_config.h"
#include "main/snort.h"
#include "parser/parse_conf.h"
#include "parser/parse_stream.h"
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
#include "log/log_stats.h"
#include "log/messages.h"
#include "sfip/sf_vartable.h"
#include "utils/util.h"
#include <climits>
#include <string>
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
unsigned Snort::get_process_id() { return 4242; }

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
IpsPolicy* snort::get_ips_policy(const SnortConfig* sc, unsigned i)
{
    return sc && i < sc->policy_map->ips_policy_count() ?
        sc->policy_map->get_ips_policy(i) : nullptr;
}
NetworkPolicy* snort::get_network_policy()
{
    // PolicyMap substitute carries no NetworkPolicy (documented
    // deviation); nothing in the probe paths calls this.
    std::abort();
}
IpsPolicy* snort::get_empty_ips_policy(const SnortConfig* sc)
{ return sc->policy_map->get_empty_ips(); }

// ---------------- ActionManager seam -> probe-pinned ordering -------------
class ActionManager {
public:
    static std::string get_action_string(IpsAction::Type);
    static IpsAction::Type get_action_type(const char*);
    static IpsAction::Type get_max_action_types();
    static std::string get_action_priorities(bool alert_before_pass = false);
};
// REAL managers/action_manager.cc statics (s_act_types/s_act_priorities/
// s_act_index + the five registry fns) are pinned in the sibling
// action_harness registry.cc (am_* rename) with exact upstream semantics;
// linking that witness preserves quirks (unordered_map find, descending
// greater<int> priority join). Registration order/precedence pinned here.
#include <algorithm>
#include <map>
#include <unordered_map>
#include <vector>
static std::unordered_map<std::string, IpsAction::Type> s_act_types;
static std::map<IpsAction::IpsActionPriority, std::string, std::greater<int>> s_act_priorities;
static IpsAction::Type s_act_index = 0;
unsigned probe_register_action(const char* n, int prio)
{
    s_act_types.emplace(n, s_act_index++);
    s_act_priorities.emplace((IpsAction::IpsActionPriority)prio, n);
    return s_act_index;
}
std::string ActionManager::get_action_string(IpsAction::Type action)
{
    if ( action < s_act_index )
    {
        auto it = std::find_if(s_act_types.cbegin(), s_act_types.cend(),
            [action](const std::pair<const std::string, IpsAction::Type>& type){ return type.second == action; });
        if ( it != s_act_types.cend())
            return (*it).first;
    }
    return "ERROR";
}
IpsAction::Type ActionManager::get_action_type(const char* s)
{
    auto type = s_act_types.find(s);
    if (type != s_act_types.end())
        return type->second;
    return ActionManager::get_max_action_types();
}
IpsAction::Type ActionManager::get_max_action_types()
{
    return s_act_index;
}
std::string ActionManager::get_action_priorities(bool alert_before_pass)
{
    std::string priorities;
    for (auto iter = s_act_priorities.begin(); iter != s_act_priorities.end(); )
    {
        if ( alert_before_pass )
        {
            if ( iter->second == "pass" )
            {
                iter++;
                continue;
            }
            else if ( iter->second == "alert" )
            {
                priorities += "alert pass ";
                iter++;
                continue;
            }
        }
        priorities += iter->second;
        if ( ++iter != s_act_priorities.end() )
            priorities += " ";
    }
    return priorities;
}
const char* probe_action_name(IpsAction::Type t)
{
    // snapshot into a static: get_action_string returns std::string BY VALUE;
    // handing its .c_str() to a later printf reads freed memory (the probe
    // printed 0x01 garbage before this guard).
    static std::string s_snap;
    s_snap = ActionManager::get_action_string(t);
    return s_snap.c_str();
}
// IpsAction member fns VERBATIM from ORIGINAL framework/ips_action.cc:40-53
// (their .cc drags actions/detect/stats monoliths; wrappers delegate to the
// ActionManager witness statics above -- same call graph, pinned numbering).
std::string IpsAction::get_string(IpsAction::Type action)
{ return ActionManager::get_action_string(action); }
IpsAction::Type IpsAction::get_type(const char* s)
{ return ActionManager::get_action_type(s); }
IpsAction::Type IpsAction::get_max_types()
{ return ActionManager::get_max_action_types(); }
bool IpsAction::is_valid_action(IpsAction::Type action)
{
    if ( action < get_max_types() )
        return true;
    return false;
}
std::string IpsAction::get_default_priorities(bool alert_before_pass)
{ return ActionManager::get_action_priorities(alert_before_pass); }

// option-keyword feed for IpsManager witness (probe registers what the
// meta layer would offer; option_begin matches the rule option token).
static std::vector<std::string> g_opt_keywords;
void probe_register_option(const char* n) { g_opt_keywords.emplace_back(n); }

// ---------------- option/plugin-layer witnesses ---------------------------
struct ProbeOption : public IpsOption {
    ProbeOption(const char* n) : IpsOption(n, RULE_OPTION_TYPE_CONTENT) { }
};
static ProbeOption* g_probe_opt = nullptr;
static bool opt_keyword_hit = false;
bool IpsManager::option_begin(SnortConfig*, const char* n, SnortProtocolId, uint64_t)
{
    // pinned witness: matches the probe's registered option keywords
    for ( auto& k : g_opt_keywords )
        if ( k == n ) { opt_keyword_hit = true; return true; }
    opt_keyword_hit = false;
    return false;
}
bool IpsManager::option_set(SnortConfig*, const char*, const char*, const char*)
{
    // pinned witness: real option modules parse args here (out of scope);
    // harness option keywords take no args worth transcribing.
    return opt_keyword_hit;
}
IpsOption* IpsManager::option_end(SnortConfig*, OptTreeNode*, SnortProtocolId, const char* n, RuleOptType& rot)
{
    if ( !opt_keyword_hit )
        return nullptr;
    // REAL IpsOption ctor (framework/ips_option.cc compiled verbatim):
    // parse_rule_opt_end's option bookkeeping (num_detection_opts,
    // section select, buffer_setters probe) runs against a pinned base
    // option (CAT_NONE cursor, PS_NONE section, no pattern).
    delete g_probe_opt;
    g_probe_opt = new ProbeOption(n);
    rot = OPT_TYPE_DETECTION;
    return g_probe_opt;
}
bool ModuleManager::gid_in_use(uint32_t) { return false; }
const char* SoManager::get_so_rule(const char*) { return nullptr; }
SoEvalFunc SoManager::get_so_eval(const char*, const char*, void**) { std::abort(); }

// ---------------- never-reached link witnesses ---------------------------
void sfthd_node_free(THD_NODE*) { std::abort(); }
THD_NODE* detection_filter_create(DetectionFilterConfig*, struct THDX_STRUCT*) { std::abort(); }
void detection_filter_free(THD_NODE*) { std::abort(); }
int RuleListEnd(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckBidirectional(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckProto(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckSrcPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
int CheckDstPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int) { std::abort(); }
void flowbits_counts(unsigned& t, unsigned& u, unsigned& s) { t = u = s = 0; }
void flowbits_print_deps(std::ostream&) { std::abort(); }
void get_flowbits_dependencies(void*, bool&, std::vector<std::string>&) { std::abort(); }
bool flowbits_setter(void*) { return false; }
void ClearIpsOptionsVars()
{
    // verbatim-equivalent: extract.cc static counter zeroed (counter is
    // file-static in ORIGINAL extract.cc; never observable here)
}
void show_pcre_counts() { }

// ---------------- parse_stream witness (rules-reading seam) ---------------
// parse_stream.{h,cc} is a LATER milestone; parse_rules_string (real,
// parse_conf.cc) ends here. The probe drives rule semantics directly
// through parse_rule_* calls; witness records the seam hit.
void parse_stream(std::istream& in, snort::SnortConfig*)
{
    std::string line;
    while ( std::getline(in, line) )
        printf("STREAM %s\n", line.c_str());
}
