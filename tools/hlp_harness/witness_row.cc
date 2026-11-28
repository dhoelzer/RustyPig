// witness_row.cc — row 24j witness mirror (shape-only capture legs for the
// NEVER-LAND wall the row .o's OWN nm -C census enumerates (plain EXACTLY-42,
// MEASURED); EVERY name + namespace placement rides the row's OWN raw-NAME
// nm -C CENSUS face — the compiler ENFORCED the restructure honestly). The
// THREE legs that link REAL and are NEVER mirrored here: framework/module.cc
// (the Module base the crafted ProbeMod tables ride through the REAL
// get_parameters seat), helpers/markup.cc (the Markup enable/item/emphasis
// tokens ARE the help_args printer face — the DEC ladder drives BOTH
// markup postures through the REAL bodies) and framework/parameter.cc (the
// REAL Parameter::get_range the help_args range arms drive). The row's OWN
// two cc-file-statics (:53 snort_help, :89 help_args) are NEVER mirrored —
// the ROW TU DEFINES them (the E9 twin law). Every wall mirror prints
// name+arg ONLY (the shape-only law): the ModuleManager/PluginManager/
// SoManager/InspectorManager/MPTransportManager/TraceApi/SFDAQ/SnortConfig/
// ScriptManager/DisplayBanner/help_signals()/show_help-manager homes NEVER
// land — the show_help wrappers are NEVER called by the probe (they drive
// new SnortConfig + load_plugins walls); they ride the nm/E9 faces ONLY,
// cited NF in probe comments. The determinism law holds: ZERO heap
// pointers, ZERO wall-clock, ZERO randomness in the vectors — every mirror
// echoes fixed args the probe passes. NO private-access flag EVER ships.
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <string>
#include <vector>

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/process.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/so_manager.h"
#include "managers/inspector_manager.h"
#include "managers/mp_transport_manager.h"
#include "managers/script_manager.h"
#include "packet_io/sfdaq.h"
#include "trace/trace_api.h"
#include "framework/parameter.h"
#include "framework/counts.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "main/thread_config.h"
#include "utils/stats.h"
#include "utils/dnet_header.h"

using namespace snort;

// ---- framework/module.cc's OWN legs NEVER land AT THIS ROW (the stats
// pair): the module .cc leg drags the two show_stats overloads + the id/
// instance-max seats (the module.h inlines). Shape-only; NEVER fired by
// this row's ladder (help_args NEVER touches stats) — census fuel ONLY. ----
void show_stats(const PegCount*, const PegInfo*, unsigned, const char*)
{ printf("W show_stats (NEVER fired)\n"); }
void show_stats(const PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*)
{ printf("W show_stats_ivecs (NEVER fired)\n"); }
namespace snort {
unsigned get_instance_id() { return 0; }
}
unsigned ThreadConfig::get_instance_max() { return 1; }

// ---- the dnet addr home NEVER lands (the parameter .cc MAC/IP4/ADDR valid
// legs; get_range NEVER touches them): the GRAFT-shim-shaped mirror the
// act-family law rides. NEVER fired; the vectors NEVER see these names. ----
int addr_pton(const char*, addr_t*) { return -1; }
int addr_ntop(const addr_t*, char*, unsigned) { return -1; }

// ---- main/process.cc NEVER lands (the signal/banner wall): the
// help_signals() seat the row's help_signals wrapper drags + the
// DisplayBanner() seat the help_version wrapper drags + the VERSION-config
// face NEVER read here (DisplayBanner NEVER called by the probe — the
// mirror DEFINES the homes for the nm/E9 census faces ONLY, never fired).
void help_signals()
{ printf("W help_signals (process home, NEVER fired by the probe)\n"); }
int DisplayBanner()
{ printf("W DisplayBanner (process home, NEVER fired by the probe)\n"); return 0; }

// ---- managers/module_manager.cc NEVER lands (the 12-method show wall):
// every show_help case body shape-echoes its name + the val arg the row
// passes. The probe NEVER drives show_help — these ride nm/E9 ONLY. ----
namespace snort {
void ModuleManager::show_configs(const char* v, bool e)
{ printf("W MM.show_configs val=%s exact=%d\n", v ? v : "(null)", e ? 1 : 0); }
void ModuleManager::show_commands(const char* v, bool e)
{ printf("W MM.show_commands val=%s exact=%d\n", v ? v : "(null)", e ? 1 : 0); }
void ModuleManager::show_gids(const char* v, bool e)
{ printf("W MM.show_gids val=%s exact=%d\n", v ? v : "(null)", e ? 1 : 0); }
void ModuleManager::show_pegs(const char* v, bool e)
{ printf("W MM.show_pegs val=%s exact=%d\n", v ? v : "(null)", e ? 1 : 0); }
void ModuleManager::show_rules(const char* v, bool e)
{ printf("W MM.show_rules val=%s exact=%d\n", v ? v : "(null)", e ? 1 : 0); }
void ModuleManager::list_modules(const char* v)
{ printf("W MM.list_modules val=%s\n", v ? v : "(null)"); }
void ModuleManager::show_module(const char* v)
{ printf("W MM.show_module val=%s\n", v ? v : "(null)"); }
void ModuleManager::show_modules() { printf("W MM.show_modules\n"); }
void ModuleManager::show_modules_json() { printf("W MM.show_modules_json\n"); }
void ModuleManager::dump_modules() { printf("W MM.dump_modules\n"); }
void ModuleManager::dump_defaults(const char* v)
{ printf("W MM.dump_defaults val=%s\n", v ? v : "(null)"); }
void ModuleManager::dump_rules(const char* v, const char* o)
{ printf("W MM.dump_rules val=%s opts=%s\n", v ? v : "(null)", o ? o : "(null)"); }
}

// ---- managers/plugin_manager.cc NEVER lands (the plugin wall): the four
// census homes (the h :86-:89 DEFAULT-arm twins show(val="") the show_help
// HT_* legs carry — the walked val="" seat). ----
void PluginManager::load_plugins(const std::string& p)
{ printf("W PM.load_plugins path=%s (NEVER fired by the probe)\n", p.c_str()); }
void PluginManager::show_plugins(const char* v)
{ printf("W PM.show_plugins val=%s\n", v ? v : "(null)"); }
void PluginManager::list_plugins(const char* v)
{ printf("W PM.list_plugins val=%s\n", v ? v : "(null)"); }
void PluginManager::dump_plugins() { printf("W PM.dump_plugins\n"); }
void PluginManager::revert_plugins(SnortConfig*) { printf("W PM.revert_plugins\n"); }
void PluginManager::release_plugins() { printf("W PM.release_plugins\n"); }

// ---- managers/so_manager.cc NEVER lands (the so-rule wall). ----
void SoManager::dump_rule_stubs() { printf("W SoManager.dump_rule_stubs\n"); }
void SoManager::rule_to_hex(const char* v)
{ printf("W SoManager.rule_to_hex val=%s\n", v ? v : "(null)"); }
void SoManager::rule_to_text(const char* v)
{ printf("W SoManager.rule_to_text val=%s\n", v ? v : "(null)"); }

// ---- managers/inspector_manager.cc NEVER lands (the buffer wall). ----
namespace snort {
void InspectorManager::dump_buffers() { printf("W IM.dump_buffers\n"); }
}

// ---- managers/mp_transport_manager.cc NEVER lands (the mp wall). ----
namespace snort {
void MPTransportManager::term() { printf("W MPTransportManager.term\n"); }
}

// ---- managers/script_manager.cc NEVER lands (the lua wall): the vector-of-
// paths face the show_help prelude drags (NEVER fired; the mirror echoes
// the count the SAME static table size would carry). ScriptManager rides
// GLOBAL scope exactly as the head does (the raw-name nm census face). ----
void ScriptManager::load_scripts(const std::vector<std::string>& paths)
{ printf("W SM.load_scripts n=%zu (NEVER fired by the probe)\n", paths.size()); }

// ---- trace/trace_api.cc NEVER lands (the trace wall). ----
namespace snort {
void TraceApi::global_init() { printf("W TraceApi.global_init (NEVER fired by the probe)\n"); }
}

// ---- packet_io/sfdaq.cc NEVER lands (the daq wall): the three list_daqs
// homes (NEVER fired by the probe — the SFDAQConfig seat rides nullptr). ----
namespace snort {
void SFDAQ::load(const SFDAQConfig* c)
{ printf("W SFDAQ.load cfg=%d (NEVER fired by the probe)\n", c ? 1 : 0); }
void SFDAQ::print_types(std::ostream&) { printf("W SFDAQ.print_types (NEVER fired)\n"); }
void SFDAQ::unload() { printf("W SFDAQ.unload (NEVER fired)\n"); }
}

// ---- main/snort_config.cc NEVER lands AT THIS ROW (the 24g config-owner
// home): the ctor/dtor/set_conf triple the show_help prelude drags (NEVER
// fired by the probe — cited NF; the mirrors own the seats for the nm/E9
// census faces ONLY). ----
SnortConfig::SnortConfig(const char* exclude_name)
{ printf("W SnortConfig.ctor ex=%s (NEVER fired by the probe)\n", exclude_name ? exclude_name : "(none)"); }
SnortConfig::~SnortConfig() { printf("W SnortConfig.dtor (NEVER fired by the probe)\n"); }
void SnortConfig::set_conf(SnortConfig*) { printf("W SnortConfig.set_conf (NEVER fired)\n"); }
