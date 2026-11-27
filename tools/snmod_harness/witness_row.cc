// witness_row.cc — row 24f witness mirror (shape-only capture legs for the
// NEVER-LAND wall the row .o's OWN nm -C census enumerates; EVERY name +
// namespace placement rides the row's OWN raw-NAME nm -C CENSUS face — the
// compiler ENFORCED the restructure honestly). The legs that link REAL and
// are NEVER mirrored here: framework/module.cc (the Module base home, the
// landed Rust framework/module.rs cites it), framework/value.cc (the Value
// accessors home), packet_io/sfdaq_config.cc (the DAQ-config home, the 23a
// landed home), parser/parse_utils.cc (the byte-code home the file-static
// x2s/x2c helper shape rides), sfip/sf_ip.cc (the SfIp + test_features
// home), utils/util.cc (the snort_strdup home the sf_ip leg drags).
// snort_trace is NEVER mirrored (the row TU OWNS it — the E9 twin law);
// the five THREAD_LOCAL perf records (the get_profile ladder) ARE mirrored
// global-bare per the census (their home TUs: analyzer.cc = row 24d,
// codec.cc = 23a, detect/fp_detect = NEVER — NEVER land THIS row). Every
// mirror echoes name+arg to stdout -> deterministic vectors rows (ZERO
// pointers, ZERO times). The help/dump/list family rides [[noreturn]] in
// the GROUND head (main/help.h); the mirrors echo and RETURN so the set()
// ladder walks clean through the probe (the anz-l command-wall mirror law,
// the honest face of a NEVER-land facility). No private-access flag EVER
// ships: every face is reached through the PUBLIC seats + header INLINES.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <cstdlib>
#include <string>
#include <vector>

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "main/thread_config.h"
#include "main/shell.h"
#include "main/help.h"
#include "framework/module.h"
#include "framework/pig_pen.h"
#include "framework/parameter.h"
#include "packet_io/sfdaq_config.h"
#include "packet_io/trough.h"
#include "managers/plugin_manager.h"
#include "profiler/profiler_defs.h"
#include "utils/stats.h"
#include "parser/config_file.h"
#include "log/messages.h"

using namespace snort;

static unsigned mirror_instance_max = 1;      // -z / --max-packet-threads seat

// ---- the five THREAD_LOCAL perf records the get_profile() ladder returns;
// ground declares them EXTERN (analyzer.h :175 / codec_manager.h :43 /
// detect.h :35 / fp_detect.h :48-49); the HOME TUs NEVER land THIS row ->
// mirrored global-bare per the nm census (the face shows the names BARE).
// NEVER a snort_trace definition (the row owns it; E9 law). ----
THREAD_LOCAL ProfileStats daqPerfStats;
THREAD_LOCAL ProfileStats decodePerfStats;
THREAD_LOCAL ProfileStats mpsePerfStats;
THREAD_LOCAL ProfileStats rulePerfStats;
THREAD_LOCAL ProfileStats eventqPerfStats;

// ---- utils/stats.cc NEVER lands (the control/file_api/memory walls):
// proc_stats + the proc_names table mirrored VERBATIM vs stats.cc :176-189
// (the get_pegs/get_counts ladder); the show_stats family mirrored (the
// REAL module.cc leg pulls the 4-arg face). ----
ProcessCount proc_stats;
const PegInfo proc_names[] =
{
    { CountType::SUM, "local_commands", "total local commands processed" },
    { CountType::SUM, "remote_commands", "total remote commands processed" },
    { CountType::SUM, "signals", "total signals processed" },
    { CountType::SUM, "conf_reloads", "number of times configuration was reloaded" },
    { CountType::SUM, "policy_reloads", "number of times policies were reloaded" },
    { CountType::SUM, "inspector_deletions", "number of times inspectors were deleted" },
    { CountType::SUM, "daq_reloads", "number of times daq configuration was reloaded" },
    { CountType::SUM, "attribute_table_reloads", "number of times hosts attribute table was reloaded" },
    { CountType::SUM, "attribute_table_hosts", "number of hosts added to the attribute table" },
    { CountType::SUM, "attribute_table_overflow", "number of host additions that failed due to attribute table full" },
    { CountType::END, nullptr, nullptr }
};
void show_stats(const PegCount* counts, const PegInfo* names, unsigned n, const char* module_name)
{ printf("W show_stats n=%u mod=%s\n", n, module_name ? module_name : "(null)"); (void)counts; (void)names; }
void show_stats(const PegCount* counts, const PegInfo* names, const std::vector<unsigned>& idx, const char* module_name, FILE*)
{ printf("W show_stats_vec n=%zu mod=%s\n", idx.size(), module_name ? module_name : "(null)"); (void)counts; (void)names; }

// ---- main/thread.cc NEVER lands (the instance-map wall): the seats the
// census pulls are get_thread_type (the row's in_main_thread inline,
// thread.h :51, + the REAL module.cc stats bodies), get_instance_id (the
// REAL module.cc bodies), and snort::ParseError (the REAL parse_utils.cc
// body) — placements ride the RAW -u nm face measured off the REAL leg
// .o's (the demangled app-undef table NEVER pins these three ns faces).
// The mirror rides MAIN + instance 0 (the row's reset_stats gate tracks
// the main thread honestly through the header inline). ----
namespace snort
{
void ParseError(const char* fmt, ...) { printf("W ParseError\n"); (void)fmt; }
SThreadType get_thread_type() { return STHREAD_TYPE_MAIN; }
unsigned get_instance_id() { return 0; }
}

// ---- ThreadConfig NEVER lands (the hwloc wall face; the ONE hwloc
// EXCISION rides the DECL head): the statics mirrored with counters (the
// -z / --max-packet-threads readback; the REAL module.cc init_stats calls
// get_instance_max -> the SAME mirror seat; the end() offload gate is DEAD
// — ENABLE_DETECTION_OFFLOAD OFF, the walked cmake face). ----
void ThreadConfig::set_instance_max(unsigned m)
{ mirror_instance_max = m; printf("W ThreadConfig::set_instance_max %u\n", m); }
unsigned ThreadConfig::get_instance_max() { return mirror_instance_max; }

// ---- SnortConfig NEVER lands (the actions/ips_actions + PolicyMap +
// thread_config.cc walls): the two statics + the member-setter legs the
// census enumerates mirrored with name+arg echoes; the ctor/dtor mirrored
// shape-only (the ground init() new's the ActionManager/PolicyMap/
// ProfilerConfig/ThreadConfig/DataBus walls; the probe ONLY needs the
// NSDMI-initialized public fields + the REAL SFDAQConfig sub-config the
// daq legs drive, so the mirror new's JUST that). The header INLINES
// (log_quiet/enable_log_syslog/...) ride the GROUND head — NO mirror. ----
uint32_t SnortConfig::logging_flags = 0;
uint32_t SnortConfig::warning_flags = 0;
THREAD_LOCAL bool SnortConfig::log_quiet_bypassed = false;

SnortConfig::SnortConfig(const char*)
{ daq_config = new SFDAQConfig(); printf("W SnortConfig.mirror_ctor\n"); }
SnortConfig::~SnortConfig()
{ delete daq_config; daq_config = nullptr; printf("W SnortConfig.mirror_dtor\n"); }
void SnortConfig::add_plugin_path(const char* s) { printf("W Sc.add_plugin_path %s\n", s); }
void SnortConfig::add_script_path(const char* s) { printf("W Sc.add_script_path %s\n", s); }
void SnortConfig::set_alert_before_pass(bool b) { printf("W Sc.set_alert_before_pass %d\n", (int)b); }
void SnortConfig::set_alert_mode(const char* s) { printf("W Sc.set_alert_mode %s\n", s); }
void SnortConfig::set_chroot_dir(const char* s) { printf("W Sc.set_chroot_dir %s\n", s); }
void SnortConfig::set_create_instance_file(bool b) { printf("W Sc.set_create_instance_file %d\n", (int)b); }
void SnortConfig::set_create_pid_file(bool b) { printf("W Sc.set_create_pid_file %d\n", (int)b); }
void SnortConfig::set_daemon(bool b) { printf("W Sc.set_daemon %d\n", (int)b); }
void SnortConfig::set_decode_data_link(bool b) { printf("W Sc.set_decode_data_link %d\n", (int)b); }
void SnortConfig::set_dirty_pig(bool b) { printf("W Sc.set_dirty_pig %d\n", (int)b); }
void SnortConfig::set_dump_chars_only(bool b) { printf("W Sc.set_dump_chars_only %d\n", (int)b); }
void SnortConfig::set_dump_payload(bool b) { printf("W Sc.set_dump_payload %d\n", (int)b); }
void SnortConfig::set_dump_payload_verbose(bool b) { printf("W Sc.set_dump_payload_verbose %d\n", (int)b); }
void SnortConfig::set_gid(const char* s) { printf("W Sc.set_gid %s\n", s); }
void SnortConfig::set_include_path(const char* s) { printf("W Sc.set_include_path %s\n", s); }
void SnortConfig::set_log_dir(const char* s) { printf("W Sc.set_log_dir %s\n", s); }
void SnortConfig::set_log_mode(const char* s) { printf("W Sc.set_log_mode %s\n", s); }
void SnortConfig::set_max_procs(uint8_t m) { printf("W Sc.set_max_procs %u\n", (unsigned)m); }
void SnortConfig::set_no_logging_timestamps(bool b) { printf("W Sc.set_no_logging_timestamps %d\n", (int)b); }
void SnortConfig::set_obfuscate(bool b) { printf("W Sc.set_obfuscate %d\n", (int)b); }
void SnortConfig::set_obfuscation_mask(const char* s) { printf("W Sc.set_obfuscation_mask %s\n", s); }
void SnortConfig::set_pid_filename(const char* s) { printf("W Sc.set_pid_filename [%s]\n", s); }
void SnortConfig::set_process_all_events(bool b) { printf("W Sc.set_process_all_events %d\n", (int)b); }
void SnortConfig::set_show_year(bool b) { printf("W Sc.set_show_year %d\n", (int)b); }
void SnortConfig::set_tweaks(const char* s) { printf("W Sc.set_tweaks %s\n", s); }
void SnortConfig::set_uid(const char* s) { printf("W Sc.set_uid %s\n", s); }
void SnortConfig::set_umask(uint32_t m) { printf("W Sc.set_umask %u\n", m); }
void SnortConfig::set_utc(bool b) { printf("W Sc.set_utc %d\n", (int)b); }

// ---- Shell NEVER lands (the LuaJIT + config-node wall): the seats the
// census pulls are the lua_sandbox static string (the --lua-sandbox INLINE
// writes it per the GROUND head — no leg ships for it) + set_overrides
// (the --lua leg; policy_map/Shell wiring rides the wall, NEVER scripted —
// the body ships for the LINK and NEVER fires at this ladder). ----
std::string Shell::lua_sandbox;
void Shell::set_overrides(const char* s) { printf("W Shell::set_overrides %s\n", s); }

// ---- Trough NEVER lands (the helpers/directory wall): the statics + the
// legs the census pulled mirrored (set_loop_count is INLINE in the GROUND
// head -> it writes the pcap_loop_count data seat mirrored, the honest
// --pcap-loop readback face). ----
std::vector<struct Trough::PcapReadObject> Trough::pcap_object_list;
std::vector<std::string> Trough::pcap_queue;
unsigned Trough::pcap_loop_count = 0;
void Trough::set_filter(const char* f) { printf("W Trough::set_filter %s\n", f ? f : "(null)"); }
void Trough::add_source(SourceType type, const char* list)
{ printf("W Trough::add_source type=%u %s\n", (unsigned)type, list); pcap_queue.emplace_back(list); }

// ---- PluginManager / PigPen NEVER land (the managers + main/process
// walls): the two legs the census pulled mirrored. ----
void PluginManager::set_close_all_plugins(bool b) { printf("W PluginManager::set_close_all_plugins %d\n", (int)b); }
void PigPen::open_syslog() { printf("W PigPen::open_syslog\n"); }

// ---- parser/config_file.cc NEVER lands (the LuaJIT + policy wall): the
// four config legs mirrored (the REAL parse_utils.cc leg covers ONLY the
// byte-code home parse_byte_code/parse_int). ----
void config_conf(const char* s) { printf("W config_conf %s\n", s); }
void ConfigChecksumMode(const char* s) { printf("W ConfigChecksumMode %s\n", s); }
void parser_append_rules(const char* s) { printf("W parser_append_rules %s\n", s); }
void parser_append_includes(const char* s) { printf("W parser_append_includes %s\n", s); }

// ---- the help/dump/list facility family (main/help.h; the managers +
// plugin walls keep them NEVER-LAND): mirrors echo name+arg and RETURN. ----
void config_markup(SnortConfig*, const char* s) { printf("W config_markup %s\n", s); }
void help_basic(SnortConfig*, const char* s) { printf("W help_basic %s\n", s); }
void help_buffers(const SnortConfig*, const char* s) { printf("W help_buffers %s\n", s); }
void help_builtin(const SnortConfig*, const char* s) { printf("W help_builtin %s\n", s); }
void help_commands(const SnortConfig*, const char* s) { printf("W help_commands %s\n", s); }
void help_config(const SnortConfig*, const char* s) { printf("W help_config %s\n", s); }
void help_counts(const SnortConfig*, const char* s) { printf("W help_counts %s\n", s); }
void help_gids(const SnortConfig*, const char* s) { printf("W help_gids %s\n", s); }
void help_limits(SnortConfig*, const char* s) { printf("W help_limits %s\n", s); }
void help_module(const SnortConfig*, const char* s) { printf("W help_module %s\n", s); }
void help_modules(const SnortConfig*, const char* s) { printf("W help_modules %s\n", s); }
void help_modules_json(const SnortConfig*, const char* s) { printf("W help_modules_json %s\n", s); }
void help_options(SnortConfig*, const char* s, const Module* m) { printf("W help_options %s mod=%s\n", s, m ? m->get_name() : "(null)"); }
void help_plugins(const SnortConfig*, const char* s) { printf("W help_plugins %s\n", s); }
void help_signals(SnortConfig*, const char* s) { printf("W help_signals %s\n", s); }
void help_usage(SnortConfig*, const char* s) { printf("W help_usage %s\n", s); }
void help_version(SnortConfig*) { printf("W help_version\n"); }
void list_daqs(const SnortConfig*) { printf("W list_daqs\n"); }
void list_modules(const SnortConfig*, const char* s) { printf("W list_modules %s\n", s); }
void list_plugins(const SnortConfig*, const char* s) { printf("W list_plugins %s\n", s); }
void dump_builtin_rules(const SnortConfig*, const char* s, const char* t) { printf("W dump_builtin_rules %s|%s\n", s, t); }
void dump_defaults(const SnortConfig*, const char* s) { printf("W dump_defaults %s\n", s); }
void dump_dynamic_rules(const SnortConfig*, const char* s) { printf("W dump_dynamic_rules %s\n", s); }
void dump_modules(const SnortConfig*) { printf("W dump_modules\n"); }
void dump_rule_hex(SnortConfig*, const char* s) { printf("W dump_rule_hex %s\n", s); }
void dump_rule_text(SnortConfig*, const char* s) { printf("W dump_rule_text %s\n", s); }
void dump_version(SnortConfig*) { printf("W dump_version\n"); }

// ---- log/messages.cc NEVER lands (the batched_logger wall): the three
// seats the REAL utils/util.cc leg drags mirrored shape-only (NEVER fire
// at this ladder — the file legs NEVER run); placements ride the RAW -u
// census off L_util.o (ErrorMessage/SnortSnprintf ride snort::; get_conf
// rides the SnortConfig static seat). ----
namespace snort {
void ErrorMessage(const char* fmt, ...) { printf("W ErrorMessage\n"); (void)fmt; }
void ErrorMessage(const char* fmt, va_list& ap) { (void)fmt; (void)ap; }
int SnortSnprintf(char* buf, size_t buf_len, const char* fmt, ...)
{ (void)buf; (void)buf_len; (void)fmt; return 0; }
} // namespace snort
const SnortConfig* SnortConfig::get_conf() { return nullptr; }
