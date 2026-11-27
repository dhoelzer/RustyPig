//! Row 24f — the snort-module CLI MEGA pair landing (chapter-21 SIXTH body).
//!
//! Ground: main/snort_module.cc 1,338 L (md5 34ac6432449d694c0eb3683ccb01a200)
//! the ground pair: main/snort_module.h 93 L (md5 088a264aad42c171bea37253a2fc2705)
//! @ fe29cbe = the 1,431 L pair ledger. This landing adds ONLY this file + the
//! ONE `pub mod snort_module;` wiring line at src/main/mod.rs (10 -> 11 L).
//! THE CITE-REACH: main/modules.rs :3605 already carries
//! `w.add_modules_box(INDEPENDENT_MODULE_IDS[0]); // :2367 new SnortModule
//! (main/snort_module.cc :702)` — the GROUND anchor main/modules.cc :2367
//! `PluginManager::add_module(new SnortModule)` (24e walk face: the box
//! helper NEVER exists in the C++ — the witness legs ride it); THIS file is
//! the body that cite reaches (the 24e register-ladder id "snort" +
//! INDEPENDENT_MODULE_IDS[0]); the
//! modules.rs line is a CITE, NEVER edited by this row (the ONE-HOME law).
//! get_usage GLOBAL -> the landed C_USAGE_GLOBAL ordinal (codecs/
//! codec_module.rs :273 REUSE, NEVER re-authored).
//!
//! THE ZERO-GATE CONTROL (measured AT the landing, the disk face wins):
//! TEST_CASE + CATCH + TEST( = EXACTLY-0 x0 in BOTH files — THE row ships
//! NO gate, the 24b/24d control census repeats: test-ADJACENT faces ONLY:
//! the `#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)` include-guard x3
//! (.cc :51/:637/:1234), the catch/unit_test.h include seat (.cc :52 — that
//! header declares ONLY catch_set_filter, unit_test.h :27), the s_params
//! --catch-test row (:637-:640) and its set-leg (:1234-:1237) — ALL
//! dialect-cited, NEVER live.
//!
//! THE DIALECT CENSUS (grep-measured at the pair; the cmake posture the row
//! mirrors): `#ifdef SHELL` x9 in the .cc (:68 :278 :364 :610 :692 :705
//! :794 :888 :1211) + x1 in the .h (:53); `REG_TEST` x4 LINES (:445 :553
//! :1052 :1157 = the 2 table rows + the 2 set-legs, each an
//! #ifdef/#endif conditional pair); `#if defined(UNIT_TEST) || defined(
//! BENCHMARK_TEST)` x3 (:51 include seat, :637 table row, :1234 set-leg) +
//! the include x1 (:52); `#ifdef DEBUG_MSGS` x1 (:223, the 3 trace rows
//! main/mime/conf :224-:226); `#ifdef ENABLE_DETECTION_OFFLOAD` x1
//! (:1287-:1290, the end() offload_threads ParseError leg); the `#define
//! s_name` seat x1 (:690) + the s_help two-arm define (:692-:698 — the
//! SHELL arm inside the SHELL census, :693 vs the LIVE arm :697).
//! cmake posture (cite): create_options.cmake ENABLE_SHELL :19 OFF /
//! ENABLE_UNIT_TESTS :20 OFF / ENABLE_BENCHMARK_TESTS :21 OFF /
//! ENABLE_DEBUG_MSGS :47 OFF; the REG_TEST + ENABLE_DETECTION_OFFLOAD
//! tokens are ABSENT from create_options.cmake (grep-0 MEASURED — REG_TEST
//! rides a compile flag only, main/CMake face, OFF on the compile face);
//! the SHELL-era source seat = main/CMakeLists.txt :20-:22 the
//! `if ( ENABLE_SHELL ) set ( SHELL_SOURCES ac_shell_cmd.h ac_shell_cmd.cc)
//! endif` pair (grep -c SHELL_SOURCES = 2: :21 set-seat + :61 the
//! add_library rider). THE ROW LANDS THE FALSE ARM EVERYWHERE: every
//! dialect row/leg/table rides a CITED comment face pinned to its ground
//! line, NEVER a live seat. Dialect s_params rows = 9 (-j :278-:281;
//! --control-socket/--control-socket-uid/--control-socket-gid/
//! --control-secret-file :364-:376; --shell :610-:613 = 6 SHELL;
//! --exit-after-reload :445-:448 + --pause-after-n :553-:556 = 2 REG_TEST;
//! --catch-test :637-:640 = 1 UNIT_TEST/BENCHMARK); LIVE s_params =
//! [Parameter; 135] = 134 named + 1 sentinel (`{ nullptr,
//! Parameter::PT_MAX, ... }` :683). Set-ladder dialect legs = the SAME 9
//! options: the SHELL set-legs :794-:800 (-j), :888-:939 (the control
//! cluster incl. the getpwnam/getgrnam ParseError legs), :1211-:1214
//! (--shell); REG_TEST legs :1052-:1055, :1157-:1160; --catch-test leg
//! :1234-:1237 (the catch_set_filter WALL, unit_test.h :27) — ALL cited
//! comment arms.
//!
//! THE SHELL-ERA TABLES (cc :68-:169, ENTIRELY under the :68 `#ifdef
//! SHELL`) land as ONE CITED comment block with the per-table row censuses
//! pinned at the seat (SHELL OFF posture, the 24e dialect law):
//! s_reload 1 named + sentinel (:69-:75); s_reload_w_path 1 + s (:77-:83);
//! s_pktnum 1 + s (:85-:91); s_watchdog 2 + s (:93-:101);
//! main_log_command_param 2 + s (:103-:108); reset_stat_param 1 + s
//! (:110-:115); dump_stats_param 1 + s (PT_SELECT "text | json" deflt
//! "text" — the deflt rides the 4th C slot) (:117-:122); s_heap_params 2 +
//! s (:124-:130); snort_cmds named + sentinel (:132-:168, the census pinned
//! at the block below). get_commands (h :53-:55 + cc :705-:708) is
//! likewise a SHELL cite, NEVER a live method.
//!
//! THE STATICS LAW: the .cc's ^static count is EXACTLY-11 (s_reload,
//! s_reload_w_path, s_pktnum, s_watchdog, main_log_command_param,
//! reset_stat_param, dump_stats_param, s_heap_params, snort_cmds,
//! snort_trace_options, s_params) + the THREAD_LOCAL pair x2 (the .cc :700
//! `THREAD_LOCAL const Trace* snort_trace` DEFINITION seat — this TU is
//! the home, the codec_module.rs :38-:41 DECODE_TRACE precedent — + the
//! .h :38 extern DECL, declare-cite NEVER re-forked). The 9 SHELL tables
//! ride the cite block; snort_trace_options + s_params land as pub static
//! table faces; c2x/x2c/x2s (:175-:201, [[noreturn]] file-statics — NOT in
//! the ^static census, they open on `[[noreturn]]`) land as PURE
//! format-shape fns returning String (the printf formats are the faces:
//! "'%c' = 0x%2.2X (%d)\n" / "0x%2.2X (%u) = '%c'\n" / "%s = '%s'\n"), the
//! exit(0) legs cite the LANDED process-p home EXIT_REQUESTED (main/
//! snort_.rs :309) — NEVER exit in-proc, NEVER re-fork the seat.
//!
//! THE PARAM-CONTIGUITY LAW (the 24e s_params precedent re-ridden): the
//! s_params array is ONE contiguous live table, the 9 dialect rows ride as
//! cited comment arms INSIDE their ground slots (never reordered, never
//! faked). Parameter = the landed { name, ptype, deflt } face (framework/
//! parameter.rs); the C 3rd slot (range) + 5th slot (help) are THAT home's
//! own deferred face (parameter.rs :39-:41, cite-never-invent) — range/
//! help strings ride as cites in the row comments, ZERO new fields. The
//! four live deflt slots (4th C slot): -B Some("255.255.255.255/32")
//! (:242), -k Some("all") (:283), --id-offset Some("0") (:489),
//! --retry-timeout Some("200") (:588). The "(optional)" help-ish strings
//! sit in the range slot (:234 etc.) and stay cites — and --rule-to-text
//! "16" (:600) is likewise a RANGE-slot face (PT_STRING max-length slot),
//! dflt nullptr there (the disk face wins over the authoring map).
//!
//! THE SNIFFED-`is` LADDER CENSUS (grep-measured at the pair): EXACTLY-143
//! `is(v, ` call sites across 1 top if + 137 else-if legs; EXACTLY-5
//! doubled-call legs (:779 -G|--logid, :837 -r|--pcap-list, :843 -s|
//! --snaplen — NOTE the C++ alternative token `or`, the face kept as a
//! cite, :867 -x|--pedantic, :873 -z|--max-packet-threads). LIVE arms =
//! 129 (138 minus the 9 dialect legs), live `is(v, ` sites = 134 (143
//! minus 9). return true :1280.
//!
//! THE SnortConfig OWNER FACE (DEV-001, main/snort_.rs :196-:202 comment:
//! the owner NEVER landed; CliConf rides snort_.rs :202): the sc-> legs of
//! set/end therefore ride a ROW-OWNED [`SnortConfigMirror`] — THIS row's
//! landed face for the snort_config.h slots it touches, every slot + every
//! setter leg cited to its h/cc line (flag-ops of the h :47-:84 RUN_FLAG
//! ladder and the h :90-:107 OUTPUT_FLAG ladder reproduced as cited
//! bit-ops, the C set_* bodies snort_config.cc :567-:940 measured). The
//! warning/logging STATICS (snort_config.h :196/:200) are NOT mirrored
//! twice: they ride the LANDED log/messages.rs LogEngine mirror (warning_
//! flags :98, logging_flags :99, set_log_quiet :139 REUSE, LOGGING_FLAG_-
//! QUIET/SYSLOG :41-:42 REUSE; the WARN_* ordinals :27-:36 REUSE — the
//! enum WarningGroup home is log/messages.h :41-:44, detection/detect.h
//! carries ZERO of them, the ordinal walk main->mime... WARN_DAQ=0
//! WARN_CONF=1 WARN_CONF_STRICT=2 WARN_VARS=3 WARN_SYMBOLS=4 WARN_SCRIPTS=5
//! WARN_HOSTS=6 WARN_RULES=7 WARN_FLOWBITS=8 WARN_PLUGINS=9 WARN_MAX=10
//! REUSE-cited, NEVER re-pinned).
//!
//! THE ONE-HOME REUSE census (grep BEFORE authoring, ZERO re-forks):
//!   Module / ModuleVirt / Command / NULL_PARAMS -> framework/module.rs
//!     (new_params :318-:331; the reset_stats base face :794).
//!   Parameter / Type -> framework/parameter.rs.
//!   Value -> framework/value.rs (is :181, get_uint16/32/64/uint8, get_string
//!     -> &[u8], get_as_string :269 — the from_utf8_lossy string posture,
//!     the 24e/23c file face).
//!   PegInfo / CountType / PegCount -> framework/counts.rs.
//!   TraceToken / TraceOptionFace -> codecs/codec_module.rs :36 / :431
//!     (the 18a graft faces REUSED — ZERO third fork of either token).
//!   C_USAGE_GLOBAL -> codecs/codec_module.rs :273 (the Usage ordinal home).
//!   ProfileStatsToken -> file_api/file_module.rs :132 (the data-free
//!     profile token home; REUSED for the get_profile seat, NEVER re-
//!     authored; the five perf-globals the C hands back (daqPerfStats
//!     analyzer.cc :93 DEFINITION / decodePerfStats codec_manager.h :43
//!     extern / mpsePerfStats + rulePerfStats fp_detect.cc :99-:100 /
//!     eventqPerfStats detect.cc :54 — NONE landed) ride ROW-OWNED token
//!     seats cited to those DECL homes (the file_module.rs :132-:133
//!     precedent) since the profile layer NEVER landed.
//!   SFDAQConfig / SFDAQModuleConfig / SFDAQ_MODE_* + the add_input/
//!     add_module_config -> usize / add_module_dir / set_batch_size /
//!     set_mru_size(i32) / set_variable legs -> packet_io/sfdaq_config.rs
//!     (23a REUSE — NEVER re-forked; the --daq-mode legs ride the
//!     SFDAQ_MODE_PASSIVE/INLINE/READ_FILE consts).
//!   ThreadConfig::set_instance_max(u32) -> main/thread_config.rs :726
//!     REUSE (the C ThreadConfig::set_instance_max leg :873-:874).
//!   in_main_thread -> main/thread.rs :65 REUSE (the reset_stats gate).
//!   Trough (facade VALUE, the C pure-static class -> fields) + SourceType
//!     {SourceFileList,SourceList,SourceDir} + add_source/set_filter/
//!     set_loop_count -> packet_io/trough.rs (23d REUSE; one caller-owned
//!     Trough models the C static face).
//!   config_conf (ConfFiles) + config_checksum_mode -> parser/config_file.rs
//!     :46 / :165 REUSE (the -c and -k legs; NetworkPolicy -> main/policy.rs
//!     :188 rides the checksum legs; the set_main_hook half of config_conf
//!     stays the home's no-op face, cited there).
//!   parse_byte_code -> parser/parse_utils.rs :53 REUSE (the x2s pull; the
//!     landed (input) -> ByteCodeResult face drifts from the C
//!     (const char*, bool& negate, std::string&) -> bool (parse_utils.h :27)
//!     — cited at the seat).
//!   parser_append_rules -> detection/parse_rule.rs :1225 REUSE (the -R and
//!     --rule legs over a caller-ownable RuleCoreState :194).
//!   LogEngine (warning/logging statics mirror + parse_error/
//!     log_message_stdout homes) -> log/messages.rs :82 REUSE.
//!   ShellWorld + set_lua_sandbox -> main/shellp.rs :201 / :584 REUSE (the
//!     --lua-sandbox leg; the PolicyMap::get_shell() --lua leg stays a seam
//!     CITE, the PolicyMap shell getter NEVER landed; Shell::
//!     set_overrides_str :482 rides that cite-DECL).
//!   EXIT_REQUESTED -> main/snort_.rs :309 REUSE (cite only, NEVER written
//!     by this row — the process-p home owns the writes).
//! NOT-LAND walls that ride seam CITE legs (bodies NEVER invented): the
//! main/help.cc free family help_basic/options/version/commands/config/
//! counts/limits/module(s)(_json)/plugins/signals/buffers/builtin/gids +
//! list_modules/list_daqs/dump_modules/dump_builtin_rules/
//! dump_dynamic_rules/dump_defaults/dump_version/dump_rule_hex/
//! dump_rule_text (help.h), config_markup (markup), ParserManager/
//! parser_append_includes (parser/parser.h :59), PigPen::open_syslog
//! (framework/pig_pen.h), PluginManager::set_close_all_plugins
//! (managers/plugin_manager.h), SnortConfig::set_alert_mode/
//! set_log_mode bodies (snort_config.cc :944-:979, EventManager/Analyzer
//! legs), SnortConfig::set_gid/set_uid NAME-RESOLUTION ladders
//! (snort_config.cc :734-:799, the getgrnam/getpwnam/getpwuid legs —
//! ZERO libc pulls in this tree), utils/stats.h proc_names (:93 extern,
//! DEFINITION utils/stats.cc :176) + proc_stats (:89 extern, DEFINITION
//! utils/stats.cc :61), catch_set_filter (catch/unit_test.h :27). They all
//! ride ONE row-owned [`SnortModuleWorld`] seam trait with default no-op/
//! no-pull bodies + the NullWorld impl (the analyzer.rs 24d pattern).
//!
//! DEVIATIONS (row-scoped, cited at each seat):
//! - C raw `SFDAQModuleConfig* module_config` (h :84) lands as an
//!   `Option<usize>` INDEX into the reused SFDAQConfig.module_configs (the
//!   sfdaq_config.rs :141 add_module_config -> usize identity face); the
//!   C null-vs-deref crash legs (--daq-mode :969-:970, --daq-var
//!   :989-:990) keep the C `return false` posture verbatim, the
//!   crash-vs-None law as sfdaq_module.rs measured.
//! - std::set<std::string> cli_opts (h :88) -> BTreeSet<String> (ordered-
//!   set twin, no hash-order drift); cli_mode (h :89) stays a plain bool
//!   field flipped ONLY by end() (cc :1285).
//! - ProfileStats has no landed type: the get_profile(index, name, parent)
//!   switch lands as the (name, parent out-params) legs + the data-free
//!   token seats (18a posture, one-home via file_module.rs :132).
//! - The `[[noreturn]]` print+exit shape: the three helpers RETURN the
//!   formatted line (the format strings are the faces); the printf rides
//!   the world seam and the exit(0) arm cites EXIT_REQUESTED — the port
//!   NEVER terminates the process in-proc (never an exit leg).
//! - get_pegs/get_counts ride the proc_names/proc_stats NOT-LAND wall as
//!   seam legs (None default = the record NEVER landed); the C
//!   reinterpret_cast<PegCount*>(&proc_stats) (cc :714) is a layout-alias
//!   face, ported as the seam handing the veneer directly, ZERO casts.
//! - zero allow-attributes on THIS landing; zero raw unsafe (the prose
//!   face rides the split word un-safe where the family law needs it).

use std::cell::Cell;
use std::collections::BTreeSet;

use crate::codecs::codec_module::{
    C_USAGE_GLOBAL, TraceOptionFace, TraceToken,
};
use crate::detection::parse_rule::{parser_append_rules, RuleCoreState};
use crate::file_api::file_module::ProfileStatsToken;
use crate::framework::counts::{PegCount, PegInfo};
use crate::framework::module::Module;
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::framework::value::Value;
use crate::log::messages::{
    LogEngine, LOGGING_FLAG_SYSLOG, WARN_CONF, WARN_CONF_STRICT, WARN_DAQ,
    WARN_FLOWBITS, WARN_HOSTS, WARN_PLUGINS, WARN_RULES, WARN_SCRIPTS,
    WARN_SYMBOLS, WARN_VARS,
};
use crate::main::modules::{
    OUTPUT_FLAG__ALERT_REFS, OUTPUT_FLAG__APP_DATA, OUTPUT_FLAG__CHAR_DATA,
    OUTPUT_FLAG__INCLUDE_YEAR, OUTPUT_FLAG__OBFUSCATE, OUTPUT_FLAG__VERBOSE_DUMP,
};
use crate::main::policy::NetworkPolicy;
use crate::main::shellp::{set_lua_sandbox, ShellWorld};
use crate::main::thread::ThreadState;
use crate::main::thread_config::ThreadConfig;
use crate::parser::config_file::{config_checksum_mode, ConfFiles};
use crate::parser::parse_utils::parse_byte_code;
use crate::packet_io::sfdaq_config::{
    SFDAQConfig, SFDAQ_MODE_INLINE, SFDAQ_MODE_PASSIVE, SFDAQ_MODE_READ_FILE,
};
use crate::packet_io::trough::{SourceType, Trough};

// ======================================================================
// the trace id ladder — h :40-:46 (the unnamed enum: TRACE_INSPECTOR_-
// MANAGER = 0, TRACE_MAIN, TRACE_MIME, TRACE_CONF — order pins VERBATIM;
// the h enum is the ordinal home for THIS row's trace table) — pub consts
// (order pins).
// ======================================================================

pub const TRACE_INSPECTOR_MANAGER: u32 = 0; // h :42
pub const TRACE_MAIN: u32 = 1;              // h :43
pub const TRACE_MIME: u32 = 2;              // h :44
pub const TRACE_CONF: u32 = 3;              // h :45

// ======================================================================
// snort_trace — h :38 `extern THREAD_LOCAL const snort::Trace*
// snort_trace;` (declare-cite) + cc :700 the THREAD_LOCAL DEFINITION seat
// (statics law: the definition rides its OWN trace-slot seam at the
// definition home = THIS TU, the codec_module.rs :38-:41 DECODE_TRACE
// precedent; the Trace type never landed, the 18a data-free token rides
// the codec_module.rs :36 REUSE).
// ======================================================================

std::thread_local! {
    pub static SNORT_TRACE: Cell<Option<&'static TraceToken>> =
        const { Cell::new(None) }; // cc :700 `= nullptr`
}

// ======================================================================
// snort_trace_options — cc :220-:230. LIVE face = the inspector_manager
// row + the sentinel; the 3 #ifdef DEBUG_MSGS rows (:224-:226, the
// DEBUG_MSGS conditional :223) are OFF on the cmake posture
// (create_options.cmake :47) and ride cited, NEVER live (the codec.rs :392
// DEBUG_MSGS autotools-flag-vs-cargo-cfg ruling re-ridden).
// ======================================================================

pub static SNORT_TRACE_OPTIONS: [TraceOptionFace; 2] = [
    // cc :222 (row VERBATIM; the id rides the h :42 ordinal):
    TraceOptionFace {
        name: Some("inspector_manager"),
        id: TRACE_INSPECTOR_MANAGER,
        help: Some("enable inspector manager trace logging"),
    },
    // cc :223-:227 #ifdef DEBUG_MSGS arms — CITED, NEVER landed (OFF face,
    // create_options.cmake :47):
    //   :224 { "main", TRACE_MAIN, "enable main trace logging" }
    //   :225 { "mime", TRACE_MIME, "enable mime trace logging" }
    //   :226 { "conf", TRACE_CONF, "enable configuration trace logging" }
    // cc :229 `{ nullptr, 0, nullptr }` sentinel (the landed face):
    TraceOptionFace { name: None, id: 0, help: None },
];

// ======================================================================
// THE SHELL-ERA TABLES — cc :68-:169, the WHOLE block under one `#ifdef
// SHELL` (:68 ... :169). ENABLE_SHELL is OFF (create_options.cmake :19)
// and the SHELL_SOURCES seat (main/CMakeLists.txt :21) confirms the
// shell facility is OFF-COMPILE: the 8 Parameter tables + the command
// table land as THIS cited census block, NEVER as live tables, and the
// get_commands override (h :53-:55 + cc :705-:708 `return snort_cmds;`)
// as a CITE. Per-table census (grep-measured, named rows + sentinel):
//   s_reload              :69-:75   1 named (filename PT_STRING) + 1 s
//   s_reload_w_path       :77-:83   1 named (filename, range "(optional)") + 1 s
//   s_pktnum              :85-:91   1 named (pkt_num PT_INT "1:max53") + 1 s
//   s_watchdog            :93-:101  2 named (timer / min_thread_count,
//                                   both PT_INT "0:max32") + 1 s
//   main_log_command_param :103-:108 2 named (command PT_STRING, logging
//                                   PT_BOOL) + 1 s
//   reset_stat_param      :110-:115 1 named (type PT_STRING, the
//                                   daq|module|appid|file_inspect|snort|ha|all
//                                   help face) + 1 s
//   dump_stats_param      :117-:122 1 named (format PT_SELECT "text |
//                                   json" with the deflt slot "text") + 1 s
//   s_heap_params         :124-:130 2 named (enable PT_BOOL, sample_rate
//                                   PT_INT "0:max32") + 1 s
//   snort_cmds            :132-:168 the command table: detach :134 /
//     dump_heap_profile :135 / dump_heap_stats :136 / dump_inspector_map
//     :137 / dump_stats :138 / heap_profile :139 / help :140 /
//     list_plugins :141 / log_command :142 / pause :143 / (the :146
//     commented-out `//{ "process", ... }` FIXIT-M trough face — a C
//     comment, NEVER a row) / quit :148 / reload_config :149 /
//     reload_daq :150 / reload_hosts :151 / reset_stats :152-:154 /
//     resume :155-:156 / rotate_stats :158 / set_watchdog_params :159 /
//     show_heap_profile :160 / show_plugins :161 / show_config_generation
//     :162 / show_control_port :163 / show_snort_cpu :164 /
//     show_snort_packet_latency :165 + the :167 sentinel — THE named-
//     command census pinned AT the landing: EXACTLY-24 named rows (the
//     commented process row at :146 rides as the C comment face it is,
//     the disk face wins over any head count).
// ======================================================================

// ======================================================================
// the name/help define pair — cc :690 `#define s_name "snort"` and the
// :692-:698 s_help two-arm define: the SHELL arm :693-:694 "command line
// configuration and shell commands" (OFF face, CITED) vs the LIVE arm
// :696-:697 "command line configuration".
// ======================================================================

pub const S_NAME: &str = "snort"; // cc :690
pub const S_HELP: &str = "command line configuration"; // cc :697 (live arm;
// the SHELL arm at :693-:694 rides cited above, ENABLE_SHELL OFF)

// ======================================================================
// s_params — cc :232-:684. THE contiguous law (the 24e ruling): ONE live
// table in ground order; the 9 dialect rows ride cited comment arms at
// their ground slots. Range strings (the "0:65535"/"max53"/"0x000:0x1FF"
// family + the "(optional)" range-slot faces) have NO slot in the landed
// Parameter struct (parameter.rs :39-:41 deferred face) — they ride the
// per-row cites. deflt (4th C slot) lands ONLY where C carries one.
// LIVE = 134 named + 1 sentinel = 135 rows; dialect = 9.
// ======================================================================

pub static S_PARAMS: [Parameter; 135] = [
    Parameter { name: Some("-?"), ptype: PtType::PtString, deflt: None },   // :234 range "(optional)" (cited)
    Parameter { name: Some("-A"), ptype: PtType::PtString, deflt: None },   // :239 (the :237-:238 FIXIT-M PluginManager face cited)
    Parameter { name: Some("-B"), ptype: PtType::PtAddr, deflt: Some("255.255.255.255/32") }, // :242 (the 1st of the four live deflt slots; range slot nullptr)
    Parameter { name: Some("-C"), ptype: PtType::PtImplied, deflt: None },  // :245
    Parameter { name: Some("-c"), ptype: PtType::PtString, deflt: None },   // :248
    Parameter { name: Some("-D"), ptype: PtType::PtImplied, deflt: None },  // :251
    Parameter { name: Some("-d"), ptype: PtType::PtImplied, deflt: None },  // :254
    Parameter { name: Some("-e"), ptype: PtType::PtImplied, deflt: None },  // :257
    Parameter { name: Some("-f"), ptype: PtType::PtImplied, deflt: None },  // :260
    Parameter { name: Some("-G"), ptype: PtType::PtInt, deflt: None },      // :263 range "0:65535" (cited)
    Parameter { name: Some("-g"), ptype: PtType::PtString, deflt: None },   // :266
    Parameter { name: Some("-H"), ptype: PtType::PtImplied, deflt: None },  // :269
    Parameter { name: Some("-h"), ptype: PtType::PtImplied, deflt: None },  // :272
    Parameter { name: Some("-i"), ptype: PtType::PtString, deflt: None },   // :275
    // :278-:281 dialect (SHELL): { "-j", Parameter::PT_PORT, ... Telnet
    // control-port face } — ENABLE_SHELL OFF, CITED never live.
    Parameter { name: Some("-k"), ptype: PtType::PtEnum, deflt: Some("all") },   // :283 range "all|noip|notcp|noudp|noicmp|none" (cited)
    Parameter { name: Some("-L"), ptype: PtType::PtString, deflt: None },   // :286
    Parameter { name: Some("-l"), ptype: PtType::PtString, deflt: None },   // :289
    Parameter { name: Some("-M"), ptype: PtType::PtImplied, deflt: None },  // :292
    Parameter { name: Some("-m"), ptype: PtType::PtInt, deflt: None },      // :295 range "0x000:0x1FF" (cited)
    Parameter { name: Some("-n"), ptype: PtType::PtInt, deflt: None },      // :298 range "0:max53" (cited)
    Parameter { name: Some("-O"), ptype: PtType::PtImplied, deflt: None },  // :301
    Parameter { name: Some("-Q"), ptype: PtType::PtImplied, deflt: None },  // :304
    Parameter { name: Some("-q"), ptype: PtType::PtImplied, deflt: None },  // :307
    Parameter { name: Some("-R"), ptype: PtType::PtString, deflt: None },   // :310
    Parameter { name: Some("-r"), ptype: PtType::PtString, deflt: None },   // :313
    Parameter { name: Some("-s"), ptype: PtType::PtInt, deflt: None },      // :316 range "0:65535"; help carries the 1518 face (cited)
    Parameter { name: Some("-T"), ptype: PtType::PtImplied, deflt: None },  // :319
    Parameter { name: Some("-t"), ptype: PtType::PtString, deflt: None },   // :322
    Parameter { name: Some("-U"), ptype: PtType::PtImplied, deflt: None },  // :325
    Parameter { name: Some("-u"), ptype: PtType::PtString, deflt: None },   // :328
    Parameter { name: Some("-V"), ptype: PtType::PtImplied, deflt: None },  // :331
    Parameter { name: Some("-v"), ptype: PtType::PtImplied, deflt: None },  // :334
    Parameter { name: Some("-X"), ptype: PtType::PtImplied, deflt: None },  // :337
    Parameter { name: Some("-x"), ptype: PtType::PtImplied, deflt: None },  // :340
    Parameter { name: Some("-y"), ptype: PtType::PtImplied, deflt: None },  // :343
    Parameter { name: Some("-z"), ptype: PtType::PtInt, deflt: None },      // :348 range "0:max32"; the :346-:347 NO-default law comment face (an allocated optional-run-mode arg)
    Parameter { name: Some("--alert-before-pass"), ptype: PtType::PtImplied, deflt: None }, // :352
    Parameter { name: Some("--bpf"), ptype: PtType::PtString, deflt: None }, // :355
    Parameter { name: Some("--c2x"), ptype: PtType::PtString, deflt: None }, // :358
    Parameter { name: Some("--close-all-plugins"), ptype: PtType::PtImplied, deflt: None }, // :361
    // :364-:376 dialect (SHELL x4): --control-socket :365 / --control-
    // socket-uid :368 / --control-socket-gid :371 / --control-secret-file
    // :374 (all PT_STRING) — ENABLE_SHELL OFF, CITED never live.
    Parameter { name: Some("--create-instance-file"), ptype: PtType::PtImplied, deflt: None }, // :378
    Parameter { name: Some("--create-pidfile"), ptype: PtType::PtString, deflt: None }, // :381 range "(optional)" (cited)
    Parameter { name: Some("--max-procs"), ptype: PtType::PtInt, deflt: None }, // :384 range "1:" (cited)
    Parameter { name: Some("--daq"), ptype: PtType::PtString, deflt: None }, // :387
    Parameter { name: Some("--daq-batch-size"), ptype: PtType::PtInt, deflt: None }, // :390 range "1:"; help carries the 64 default face (cited)
    Parameter { name: Some("--daq-dir"), ptype: PtType::PtString, deflt: None }, // :393
    Parameter { name: Some("--daq-list"), ptype: PtType::PtImplied, deflt: None }, // :396
    Parameter { name: Some("--daq-mode"), ptype: PtType::PtEnum, deflt: None }, // :399 range "passive | inline | read-file" (cited)
    Parameter { name: Some("--daq-var"), ptype: PtType::PtString, deflt: None }, // :402
    Parameter { name: Some("--dirty-pig"), ptype: PtType::PtImplied, deflt: None }, // :405
    Parameter { name: Some("--dump-builtin-options"), ptype: PtType::PtString, deflt: None }, // :408
    Parameter { name: Some("--dump-builtin-rules"), ptype: PtType::PtString, deflt: None }, // :411 range "(optional)" (cited)
    Parameter { name: Some("--dump-config"), ptype: PtType::PtSelect, deflt: None }, // :414 range "all | top" (cited)
    Parameter { name: Some("--dump-config-text"), ptype: PtType::PtImplied, deflt: None }, // :417
    Parameter { name: Some("--dump-dynamic-rules"), ptype: PtType::PtImplied, deflt: None }, // :421 (the :420 FIXIT-L face cited)
    Parameter { name: Some("--dump-defaults"), ptype: PtType::PtString, deflt: None }, // :424 range "(optional)" (cited)
    Parameter { name: Some("--dump-rule-deps"), ptype: PtType::PtImplied, deflt: None }, // :427
    Parameter { name: Some("--dump-rule-meta"), ptype: PtType::PtImplied, deflt: None }, // :430
    Parameter { name: Some("--dump-rule-state"), ptype: PtType::PtImplied, deflt: None }, // :433
    Parameter { name: Some("--dump-version"), ptype: PtType::PtImplied, deflt: None }, // :436
    Parameter { name: Some("--enable-inline-test"), ptype: PtType::PtImplied, deflt: None }, // :439
    Parameter { name: Some("--enable-test-features"), ptype: PtType::PtImplied, deflt: None }, // :442
    // :445-:448 dialect (REG_TEST): --exit-after-reload PT_IMPLIED (the
    // --daq pcap --daq-var rewind=true face) — REG_TEST ABSENT from
    // create_options.cmake (grep-0), CITED never live.
    Parameter { name: Some("--gen-dump-config"), ptype: PtType::PtString, deflt: None }, // :450
    Parameter { name: Some("--gen-msg-map"), ptype: PtType::PtImplied, deflt: None }, // :453
    Parameter { name: Some("--help"), ptype: PtType::PtImplied, deflt: None }, // :456
    Parameter { name: Some("--help-commands"), ptype: PtType::PtString, deflt: None }, // :459 range "(optional)" (cited)
    Parameter { name: Some("--help-config"), ptype: PtType::PtString, deflt: None }, // :462 range "(optional)" (cited)
    Parameter { name: Some("--help-counts"), ptype: PtType::PtString, deflt: None }, // :465 range "(optional)" (cited)
    Parameter { name: Some("--help-limits"), ptype: PtType::PtImplied, deflt: None }, // :468
    Parameter { name: Some("--help-module"), ptype: PtType::PtString, deflt: None }, // :471
    Parameter { name: Some("--help-modules"), ptype: PtType::PtImplied, deflt: None }, // :474
    Parameter { name: Some("--help-modules-json"), ptype: PtType::PtImplied, deflt: None }, // :477
    Parameter { name: Some("--help-options"), ptype: PtType::PtString, deflt: None }, // :480 range "(optional)" (cited)
    Parameter { name: Some("--help-plugins"), ptype: PtType::PtString, deflt: None }, // :483 range "(optional)" (cited)
    Parameter { name: Some("--help-signals"), ptype: PtType::PtImplied, deflt: None }, // :486
    Parameter { name: Some("--id-offset"), ptype: PtType::PtInt, deflt: Some("0") }, // :489 range "0:65535" (cited)
    Parameter { name: Some("--id-subdir"), ptype: PtType::PtImplied, deflt: None }, // :492
    Parameter { name: Some("--id-zero"), ptype: PtType::PtImplied, deflt: None }, // :495
    Parameter { name: Some("--include-path"), ptype: PtType::PtString, deflt: None }, // :498
    Parameter { name: Some("--list-buffers"), ptype: PtType::PtImplied, deflt: None }, // :502
    Parameter { name: Some("--list-builtin"), ptype: PtType::PtString, deflt: None }, // :505 range "(optional)" (cited)
    Parameter { name: Some("--list-gids"), ptype: PtType::PtString, deflt: None }, // :508 range "(optional)" (cited)
    Parameter { name: Some("--list-modules"), ptype: PtType::PtString, deflt: None }, // :511 range "(optional)" (cited)
    Parameter { name: Some("--list-plugins"), ptype: PtType::PtString, deflt: None }, // :514 range "(optional)" (cited)
    Parameter { name: Some("--lua"), ptype: PtType::PtString, deflt: None }, // :517
    Parameter { name: Some("--lua-sandbox"), ptype: PtType::PtString, deflt: None }, // :520
    Parameter { name: Some("--logid"), ptype: PtType::PtInt, deflt: None }, // :523 range "0:65535" (cited)
    Parameter { name: Some("--markup"), ptype: PtType::PtImplied, deflt: None }, // :526
    Parameter { name: Some("--max-packet-threads"), ptype: PtType::PtInt, deflt: None }, // :529 range "0:max32" (cited)
    Parameter { name: Some("--mem-check"), ptype: PtType::PtImplied, deflt: None }, // :532
    Parameter { name: Some("--metadata-filter"), ptype: PtType::PtString, deflt: None }, // :535
    Parameter { name: Some("--nostamps"), ptype: PtType::PtImplied, deflt: None }, // :538
    Parameter { name: Some("--nolock-pidfile"), ptype: PtType::PtImplied, deflt: None }, // :541
    Parameter { name: Some("--no-warn-flowbits"), ptype: PtType::PtImplied, deflt: None }, // :544
    Parameter { name: Some("--no-warn-rules"), ptype: PtType::PtImplied, deflt: None }, // :547
    Parameter { name: Some("--pause"), ptype: PtType::PtImplied, deflt: None }, // :550
    // :553-:556 dialect (REG_TEST): --pause-after-n PT_INT "1:max53" —
    // CITED never live (the h :310 pkt_pause_cnt SLOT is NOT dialect —
    // the slot lands on the mirror, ONLY this write-leg is gated, the
    // 24e HAVE_NUMA asymmetry precedent).
    Parameter { name: Some("--pcap-file"), ptype: PtType::PtString, deflt: None }, // :558
    Parameter { name: Some("--pcap-list"), ptype: PtType::PtString, deflt: None }, // :561
    Parameter { name: Some("--pcap-dir"), ptype: PtType::PtString, deflt: None }, // :564
    Parameter { name: Some("--pcap-filter"), ptype: PtType::PtString, deflt: None }, // :567
    Parameter { name: Some("--pcap-loop"), ptype: PtType::PtInt, deflt: None }, // :570 range "0:max32" (cited)
    Parameter { name: Some("--pcap-no-filter"), ptype: PtType::PtImplied, deflt: None }, // :573
    Parameter { name: Some("--pcap-show"), ptype: PtType::PtImplied, deflt: None }, // :576
    Parameter { name: Some("--pedantic"), ptype: PtType::PtImplied, deflt: None }, // :579
    Parameter { name: Some("--plugin-path"), ptype: PtType::PtString, deflt: None }, // :582
    Parameter { name: Some("--process-all-events"), ptype: PtType::PtImplied, deflt: None }, // :585
    Parameter { name: Some("--retry-timeout"), ptype: PtType::PtInt, deflt: Some("200") }, // :588 range "0:max32" (cited)
    Parameter { name: Some("--rule"), ptype: PtType::PtString, deflt: None }, // :591
    Parameter { name: Some("--rule-path"), ptype: PtType::PtString, deflt: None }, // :594
    Parameter { name: Some("--rule-to-hex"), ptype: PtType::PtImplied, deflt: None }, // :597
    Parameter { name: Some("--rule-to-text"), ptype: PtType::PtString, deflt: None }, // :600 range "16" (the delimiter face cited; help carries [Snort_SO_Rule])
    Parameter { name: Some("--run-prefix"), ptype: PtType::PtString, deflt: None }, // :604
    Parameter { name: Some("--script-path"), ptype: PtType::PtString, deflt: None }, // :607
    // :610-:613 dialect (SHELL): --shell PT_IMPLIED interactive-command-
    // line face — CITED never live (RUN_FLAG__SHELL h :80 is ALSO inside
    // the C-header SHELL gate — the ordinal NEVER lands on OFF face).
    Parameter { name: Some("--show-file-codes"), ptype: PtType::PtImplied, deflt: None }, // :615
    Parameter { name: Some("--show-modules"), ptype: PtType::PtImplied, deflt: None }, // :619
    Parameter { name: Some("--skip"), ptype: PtType::PtInt, deflt: None },  // :622 range "0:max53" (cited)
    Parameter { name: Some("--snaplen"), ptype: PtType::PtInt, deflt: None }, // :625 range "0:65535" (cited)
    Parameter { name: Some("--stdin-rules"), ptype: PtType::PtImplied, deflt: None }, // :628
    Parameter { name: Some("--talos"), ptype: PtType::PtImplied, deflt: None }, // :631
    Parameter { name: Some("--tweaks"), ptype: PtType::PtString, deflt: None }, // :634
    // :637-:640 dialect (UNIT_TEST||BENCHMARK_TEST): --catch-test
    // PT_STRING Catch-tags face — the include seat :51-:53 + the unit_test.h
    // :27 catch_set_filter WALL; CITED never live.
    Parameter { name: Some("--version"), ptype: PtType::PtImplied, deflt: None }, // :641
    Parameter { name: Some("--warn-all"), ptype: PtType::PtImplied, deflt: None }, // :644
    Parameter { name: Some("--warn-conf"), ptype: PtType::PtImplied, deflt: None }, // :647
    Parameter { name: Some("--warn-conf-strict"), ptype: PtType::PtImplied, deflt: None }, // :650
    Parameter { name: Some("--warn-daq"), ptype: PtType::PtImplied, deflt: None }, // :653
    Parameter { name: Some("--warn-flowbits"), ptype: PtType::PtImplied, deflt: None }, // :656
    Parameter { name: Some("--warn-hosts"), ptype: PtType::PtImplied, deflt: None }, // :659
    Parameter { name: Some("--warn-plugins"), ptype: PtType::PtImplied, deflt: None }, // :662
    Parameter { name: Some("--warn-rules"), ptype: PtType::PtImplied, deflt: None }, // :665
    Parameter { name: Some("--warn-scripts"), ptype: PtType::PtImplied, deflt: None }, // :668
    Parameter { name: Some("--warn-symbols"), ptype: PtType::PtImplied, deflt: None }, // :671
    Parameter { name: Some("--warn-vars"), ptype: PtType::PtImplied, deflt: None }, // :674
    Parameter { name: Some("--x2c"), ptype: PtType::PtInt, deflt: None },   // :677 range "0x00:0xFF" (cited)
    Parameter { name: Some("--x2s"), ptype: PtType::PtString, deflt: None }, // :680
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },            // :683 sentinel
];

// ======================================================================
// the hex-conversion helpers — cc :175-:201, the `[[noreturn]] static`
// print+exit file face (NOT in the ^static census — the lines open on
// [[noreturn]]). THE DEVIATION (header, deviation row 3): the three land
// as PURE format-shape legs RETURNING the formatted line (the printf
// format strings are the faces, kept VERBATIM in the cites); the world
// seam owns the stdout leg and the exit(0) arms cite the LANDED
// EXIT_REQUESTED home (main/snort_.rs :309 process-p seat) — THIS row
// NEVER exits in-proc and NEVER re-forks that static.
// ======================================================================

/// cc :175-:179 — `printf("'%c' = 0x%2.2X (%d)\n", s[0], s[0], s[0]);
/// exit(0);` The C char promotes signed for %d (x86 signed char); the
/// port reproduces the %c face (the byte as char) + 0x%2.2X (width-2 zero-
/// pad, exactly = 0x{:02X} through the C upcast to u8) + the signed (%d)
/// leg. The exit(0) arm: the EXIT_REQUESTED cite (never written HERE —
/// the process-p home owns it).
pub fn c2x(s: &[u8]) -> String {
    let b = s.first().copied().unwrap_or(0); // the C s[0] (never-null CLI
    // face; the empty face lands 0, panic-free law, cited deviation)
    format!("'{}' = 0x{:02X} ({})\n", b as char, b, b as i8 as i32) // :177
}

/// cc :181-:185 — `printf("0x%2.2X (%u) = '%c'\n", x, x,
/// static_cast<char>(x)); exit(0);` (%u = unsigned, the face).
pub fn x2c(x: u8) -> String {
    format!("0x{:02X} ({}) = '{}'\n", x, x, x as char) // :183
}

/// cc :187-:201 — `in = "\"" + s + "\""; if (parse_byte_code(in.c_str(),
/// inv, out)) printf("%s = '%s'\n", s, out.c_str()); else printf("%s =
/// '%s'\n", s, "error"); exit(0);` parse_byte_code REUSES the landed
/// parser/parse_utils.rs :53 face (the ByteCodeResult return drifts from
/// the C (const char*, bool& negate, std::string&) -> bool DECL at
/// parse_utils.h :27 — cited, the negate/inv slot stays unused exactly as
/// the C `inv` is unused after the call).
pub fn x2s(s: &[u8]) -> String {
    let in_str = {
        // cc :190-:192 the quote-wrap face (`string in = "\""; in += s;
        // in += "\"";` — the byte face rides Vec<u8>, any C byte allowed):
        let mut v = Vec::with_capacity(s.len() + 2);
        v.push(b'"');
        v.extend_from_slice(s);
        v.push(b'"');
        v
    };
    let r = parse_byte_code(&in_str); // :194
    if r.ok {
        let out = String::from_utf8_lossy(&r.out).into_owned();
        let s = String::from_utf8_lossy(s).into_owned();
        format!("{s} = '{out}'\n") // :195
    } else {
        let s = String::from_utf8_lossy(s).into_owned();
        format!("{s} = 'error'\n") // :198
    }
}

// ======================================================================
// the SnortConfig mirror — THE landed face for the snort_config.h slots
// THIS row touches while the owner NEVER lands (DEV-001, main/snort_.rs
// :196-:202; CliConf stays that home's own rider, NEVER re-forked).
// Every slot cites its snort_config.h line; every flag-op setter mirrors
// the measured snort_config.cc body (the RUN_FLAG ladder h :46-:85 and
// the OUTPUT_FLAG ladder h :88-:108 bit-ops). The warning/logging
// STATICS do NOT double-mirror: they ride the landed LogEngine (messages.
// rs :98-:100 the explicit "SnortConfig statics this file reads" mirror).
// ======================================================================

/// main/snort_config.h :46-:85 the RUN_FLAG ordinals the set/end ladder
/// drives (head-VERBATIM; the SHELL gate :79-:81 and the REG_TEST gate
/// :83-:85 neighbours RUN_FLAG__SHELL 0x02000000 / RUN_FLAG__EXIT_AFTER_-
/// RELOAD 0x08000000 stay CITED, NEVER landed — the OFF dialect arms):
pub const RUN_FLAG__READ: u32 = 0x0000_0001;               // h :47
pub const RUN_FLAG__DAEMON: u32 = 0x0000_0002;             // h :48
pub const RUN_FLAG__DUMP_MSG_MAP: u32 = 0x0000_0004;       // h :49
pub const RUN_FLAG__DUMP_RULE_META: u32 = 0x0000_0008;     // h :50
pub const RUN_FLAG__INLINE: u32 = 0x0000_0010;             // h :52
pub const RUN_FLAG__STATIC_HASH: u32 = 0x0000_0020;        // h :53
pub const RUN_FLAG__CREATE_PID_FILE: u32 = 0x0000_0040;    // h :54 (the
    // MAIN/snort_.rs :203 comment cite-reach already names this ordinal —
    // REUSE cite, no re-pin of that home's face; a row-local const here
    // mirrors the same measured h line for THIS row's bit-ops)
pub const RUN_FLAG__NO_LOCK_PID_FILE: u32 = 0x0000_0080;   // h :55
pub const RUN_FLAG__ALERT_BEFORE_PASS: u32 = 0x0000_0100;  // h :57
pub const RUN_FLAG__CONF_ERROR_OUT: u32 = 0x0000_0200;     // h :58
pub const RUN_FLAG__PROCESS_ALL_EVENTS: u32 = 0x0000_0400; // h :59
pub const RUN_FLAG__INLINE_TEST: u32 = 0x0000_0800;        // h :60
pub const RUN_FLAG__PCAP_SHOW: u32 = 0x0000_1000;          // h :62
pub const RUN_FLAG__SHOW_FILE_CODES: u32 = 0x0000_2000;    // h :63
pub const RUN_FLAG__PAUSE: u32 = 0x0000_4000;              // h :64
pub const RUN_FLAG__DUMP_RULE_STATE: u32 = 0x0001_0000;    // h :67
pub const RUN_FLAG__DUMP_RULE_DEPS: u32 = 0x0002_0000;     // h :68
pub const RUN_FLAG__TEST: u32 = 0x0004_0000;               // h :69
pub const RUN_FLAG__MEM_CHECK: u32 = 0x0008_0000;          // h :70
pub const RUN_FLAG__TEST_FEATURES: u32 = 0x0040_0000;      // h :74
pub const RUN_FLAG__GEN_DUMP_CONFIG: u32 = 0x0080_0000;    // h :75
pub const RUN_FLAG__CREATE_INST_FILE: u32 = 0x0100_0000;   // h :77

/// main/snort_config.h :131-:136 the DumpConfigType enum (NONE=0,
/// JSON_ALL=1, JSON_TOP=2, TEXT=3, the h :432 default NONE face) — pub
/// consts land (the :1006-:1016 set legs drive them).
pub const DUMP_CONFIG_NONE: u32 = 0;    // h :133
pub const DUMP_CONFIG_JSON_ALL: u32 = 1; // h :134
pub const DUMP_CONFIG_JSON_TOP: u32 = 2; // h :135
pub const DUMP_CONFIG_TEXT: u32 = 3;     // h :136

// — sibling seats the landed homes already carry (REUSE, NEVER re-fork):
//   OUTPUT_FLAG__LINE_BUFFER h :90 / __SHOW_DATA_LINK :95 / __USE_UTC :96 /
//   __NO_TIMESTAMP :102 have NO landed home yet -> this row owns them:

/// main/snort_config.h :90/:95/:96/:102 the OUTPUT_FLAG seats this row
/// needs and NO landed home carries (the :91-:107 siblings ride the main/
/// modules.rs :1470-:1477 row-owned seats — REUSE at the imports; the
/// LOG_BUFFERED identity stays log/messages.rs :40 through that home):
pub const OUTPUT_FLAG__LINE_BUFFER: u32 = 0x0000_0001;    // h :90
pub const OUTPUT_FLAG__SHOW_DATA_LINK: u32 = 0x0000_0010; // h :95
pub const OUTPUT_FLAG__USE_UTC: u32 = 0x0000_0020;        // h :96
pub const OUTPUT_FLAG__NO_TIMESTAMP: u32 = 0x0000_0200;   // h :102

/// snort_config.h :111 LOGGING_FLAG__VERBOSE (the messages.rs home carries
/// QUIET :41 / SYSLOG :42 — REUSE; the VERBOSE seat has no home — owned
/// here, cited):
pub const LOGGING_FLAG__VERBOSE: u32 = 0x0000_0001; // h :111

/// snort_config.h :200 static warning_flags — ALL_WARN legs ride the 0xF-
///FFFFFF store at cc :1242 (the C `=` face, NOT |=, kept):
pub const ALL_WARN_FLAGS: u32 = 0xFFFF_FFFF; // cc :1242 `= 0xFFFFFFFF;`

/// the row-scoped profile token seats — the C get_profile hands back
/// &daqPerfStats/&decodePerfStats/&mpsePerfStats/&rulePerfStats/&-
/// eventqPerfStats, whose DEFINITION homes (analyzer.cc :93, the extern
/// walls codec_manager.h :43 / fp_detect.h :48-:49 / detect.h :35,
/// definitions fp_detect.cc :99-:100 / detect.cc :54) NEVER landed ->
/// data-free liveness tokens at the file_module.rs :132-:133 precedent
/// (ProfileStatsToken REUSE import; the DEFINITION homes NEVER aliased).
pub static DAQ_PERF_STATS: ProfileStatsToken = ProfileStatsToken;        // analyzer.h :175 extern / analyzer.cc :93 definition
pub static DECODE_PERF_STATS: ProfileStatsToken = ProfileStatsToken;     // codec_manager.h :43 extern (definition home unported)
pub static MPSE_PERF_STATS: ProfileStatsToken = ProfileStatsToken;       // fp_detect.h :48 extern / fp_detect.cc :99
pub static RULE_PERF_STATS: ProfileStatsToken = ProfileStatsToken;       // fp_detect.h :49 extern / fp_detect.cc :100
pub static EVENTQ_PERF_STATS: ProfileStatsToken = ProfileStatsToken;     // detect.h :35 extern / detect.cc :54

/// the config mirror + the landed sub-records the set-legs ride. Records
/// are record-threaded (the 23c law): the caller owns one instance and
/// drives the ladder with it.
#[derive(Default)]
pub struct SnortConfigMirror {
    /// the run/output bit-flags (h :323 / :214-:216 — the REG_TEST
    /// WIDE_HEX default pair :212-:217: the OFF compile face stays 0):
    pub run_flags: u32,     // h :237 `uint32_t run_flags = 0;`
    pub output_flags: u32,  // h :216 `uint32_t output_flags = 0;` (OFF face)

    /// the warning/logging STATIC mirrors ride the landed messages home:
    pub log: LogEngine, // log/messages.rs :82 (warning_flags :98,
    // logging_flags :99, set_log_quiet :139 REUSE)

    // — direct-field legs (the cc set-legs store straight members): —
    pub event_log_id: u16,   // h :328 (cc :780 sc->event_log_id =
                            // v.get_uint16())
    pub bpf_filter: String,  // h :330 (cc :880)
    pub metadata_filter: String, // h :331 (cc :1140)
    pub run_prefix: String,  // h :335 (cc :1206)
    pub id_offset: u16,      // h :336 (cc :1101)
    pub id_subdir: bool,     // h :337 (cc :1104)
    pub id_zero: bool,       // h :338 (cc :1107)
    pub dump_config_file: String, // h :434 (cc :1059)
    pub stdin_rules: bool,   // h :340 (cc :1226)
    pub pkt_cnt: u64,        // h :308 (cc :820; the C ctor 0 face)
    pub pkt_skip: u64,       // h :309 (cc :1223)
    pub pkt_pause_cnt: u64,  // h :310 — the SLOT is NOT dialect (only the
    // REG_TEST writer leg cc :1157-:1160 is, cited)
    pub retry_timeout: u32,  // h :433 `= 200` C-face (the s_params deflt
                            // slot at :588 carries the same 200)
    pub dump_config_type: u32, // h :432 default DUMP_CONFIG_NONE (cc
    // :1007/:1009/:1016 write legs)
    pub max_procs: u8,       // h :343 `uint8_t max_procs = 1;`
    pub pid_filename: String, // h :342 (the set_pid_filename empty ->
    // DEFAULT_PID_FILENAME "snort.pid" face, h :43, cc :599-:603)
    pub chroot_dir: String,  // h :268 (set_chroot_dir cc :575-:581)
    pub include_path: String, // h :269 (set_include_path cc :911-:917)
    pub plugin_path: String,  // h :270 (add_plugin_path cc :919-:928,
    // the colon-append face)
    pub script_paths: Vec<String>, // h :271 (add_script_path cc
    // :938-:941 emplace)
    pub tweaks: String,       // h :388 (set_tweaks cc :930-:935)
    pub file_mask: u32,       // h :273 `mode_t file_mask = 0;` (set_umask
    // cc :829-:832 plain store)
    pub dirty_pig: bool,      // h :266 (set_dirty_pig cc :704-:706)
    pub log_dir: String,      // h :221 (set_log_dir cc :686-:690)
    pub user_id: i32,         // h :262 `int user_id = -1;` — the
    // NAME-RESOLUTION ladder (set_uid cc snort_config.cc :765-:799, the
    // getpwnam legs) rides the NEVER-landed owner: the mirror stores the
    // raw argv face (uid_face) this row can carry, the int slot pins the
    // h NSDMI.
    pub group_id: i32,        // h :263 `int group_id = -1;` (same face)
    pub uid_face: String,     // raw -u argv face (the resolution wall cited)
    pub gid_face: String,     // raw -g argv face (the resolution wall cited)
    pub obfuscation_mask: String, // the -B text face (set_obfuscation_mask
    // cc :725-:731: flag | OBFUSCATE + obfuscation_net.set — the SfCidr
    // .set leg is NOT a landed face (sfip/sf_cidr.rs :8 has no set), the
    // mirror stores the CIDR text, cited)
    /// the landed sub-records the ladder reuses through this bag:
    pub log_net: NetworkPolicy,     // main/policy.rs :188 (the -k checksum
    // legs ride parser/config_file.rs :165 config_checksum_mode REUSE)
    pub conf_files: ConfFiles,      // parser/config_file.rs :16 (the -c
    // leg rides config_conf :46 REUSE)
    pub rules: RuleCoreState,       // detection/parse_rule.rs :194 (the
    // -R / --rule legs ride parser_append_rules :1225 REUSE)
    pub daq_config: Option<SFDAQConfig>, // snort_config.h :225
    // `SFDAQConfig* daq_config` (the ctor seat snort_config.cc :186 new
    // SFDAQConfig — the None face = that ctor unported, the sfdaq_module
    // crash-vs-None posture); the record = the 23a REUSE home.
    pub trough: Trough,             // packet_io/trough.rs :81 (the C
    // pure-static Trough:: legs -> ONE caller-owned facade)
    pub sfip_test_features: bool,   // sf_ip.h :107 `static bool
    // test_features;` — the landed sfip homes take it as an explicit arg
    // (sf_ip.rs :203 test_features-mode legs); the class-static face rides
    // the mirror, cited.
}

impl SnortConfigMirror {
    /// DEFAULT_PID_FILENAME — snort_config.h :43 (the set_pid_filename
    /// empty-name arm, cc snort_config.cc :599-:603).
    pub const DEFAULT_PID_FILENAME: &'static str = "snort.pid"; // h :43

    /// the flag-op setters mirroring the measured snort_config.cc bodies
    /// (each body cited; the |=/&= pairs are 1:1 with the C if/else).
    pub fn run_flag_on(&mut self, f: u32) { self.run_flags |= f; }   // the C leg shape
    pub fn output_flag_on(&mut self, f: u32) { self.output_flags |= f; }
    pub fn output_flag_off(&mut self, f: u32) { self.output_flags &= !f; }

    /// snort_config.cc :612-:620 `set_daemon` (the RUN_FLAG__DAEMON pair).
    pub fn set_daemon(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__DAEMON; }
        else { self.run_flags &= !RUN_FLAG__DAEMON; }
    }
    /// snort_config.cc :622-:630 `set_decode_data_link` (SHOW_DATA_LINK).
    pub fn set_decode_data_link(&mut self, enabled: bool) {
        if enabled { self.output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK; }
        else { self.output_flags &= !OUTPUT_FLAG__SHOW_DATA_LINK; }
    }
    /// snort_config.cc :632-:641 `set_dump_chars_only` (CHAR_DATA — the
    //  main/modules.rs :1471 OUTPUT_FLAG__CHAR_DATA REUSE at the leg).
    pub fn set_dump_chars_only(&mut self, enabled: bool, flag: u32) {
        if enabled { self.output_flags |= flag; }
        else { self.output_flags &= !flag; }
    }
    /// snort_config.cc :709-:715 `set_obfuscate` (OBFUSCATE).
    pub fn set_obfuscate(&mut self, enabled: bool, flag: u32) {
        if enabled { self.output_flags |= flag; }
        else { self.output_flags &= !flag; }
    }
    /// snort_config.cc :717-:723 `set_no_logging_timestamps` (NO_TIMESTAMP).
    pub fn set_no_logging_timestamps(&mut self, enabled: bool) {
        if enabled { self.output_flags |= OUTPUT_FLAG__NO_TIMESTAMP; }
        else { self.output_flags &= !OUTPUT_FLAG__NO_TIMESTAMP; }
    }
    /// snort_config.cc :801-:810 `set_show_year` (INCLUDE_YEAR).
    pub fn set_show_year(&mut self, enabled: bool, flag: u32) {
        if enabled { self.output_flags |= flag; }
        else { self.output_flags &= !flag; }
    }
    /// snort_config.cc :834-:840 `set_utc` (USE_UTC).
    pub fn set_utc(&mut self, enabled: bool) {
        if enabled { self.output_flags |= OUTPUT_FLAG__USE_UTC; }
        else { self.output_flags &= !OUTPUT_FLAG__USE_UTC; }
    }
    /// snort_config.cc :911-:917 `set_include_path` (store-or-clear).
    pub fn set_include_path(&mut self, path: &str) {
        self.include_path = path.to_string(); // the Some face; the nullptr
        // arm clears — the C `if (path)` legs land as the caller never
        // passing empty for the CLI set-leg cc :1110 (value->get_string()
        // is never null at the CLI face).
    }
    /// snort_config.cc :919-:928 `add_plugin_path` (the colon-append).
    pub fn add_plugin_path(&mut self, path: &str) {
        if !self.plugin_path.is_empty() {
            self.plugin_path.push(':');
            self.plugin_path.push_str(path); // :925 `plugin_path += ":" + path`
        } else {
            self.plugin_path = path.to_string(); // :927
        }
    }
    /// snort_config.cc :930-:935 `set_tweaks` (store; the nullptr clear arm
    /// the CLI never hits).
    pub fn set_tweaks(&mut self, t: &str) {
        self.tweaks = t.to_string(); // :932
    }
    /// snort_config.cc :938-:941 `add_script_path` (emplace).
    pub fn add_script_path(&mut self, path: &str) {
        self.script_paths.push(path.to_string()); // :940
    }
    /// snort_config.cc :599-:603 `set_pid_filename` (the empty ->
    /// DEFAULT_PID_FILENAME arm VERBATIM).
    pub fn set_pid_filename(&mut self, name: &str) {
        if !name.is_empty() {
            self.pid_filename = name.to_string(); // :601
        } else {
            // snort_config.h :29-:31 comment face
            self.pid_filename = Self::DEFAULT_PID_FILENAME.to_string(); // h :43
        }
    }
    /// snort_config.cc :607-:610 `set_max_procs` (plain store).
    pub fn set_max_procs(&mut self, n: u8) {
        self.max_procs = n; // :609
    }
    /// snort_config.cc :567-:573 `set_alert_before_pass` (the C legs the
    /// -y... pair shape; this row's ONLY caller is cc :876-:877 = the on-
    /// arm, kept 1:1).
    pub fn set_alert_before_pass(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__ALERT_BEFORE_PASS; }
        else { self.run_flags &= !RUN_FLAG__ALERT_BEFORE_PASS; }
    }
    /// snort_config.cc :575-:581 `set_chroot_dir` (store-or-clear).
    pub fn set_chroot_dir(&mut self, directory: &str) {
        self.chroot_dir = directory.to_string(); // :577
    }
    /// snort_config.cc :583-:589 `set_create_instance_file` (the
    /// RUN_FLAG__CREATE_INST_FILE pair).
    pub fn set_create_instance_file(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__CREATE_INST_FILE; }
        else { self.run_flags &= !RUN_FLAG__CREATE_INST_FILE; }
    }
    /// snort_config.cc :591-:597 `set_create_pid_file` (the
    /// RUN_FLAG__CREATE_PID_FILE pair).
    pub fn set_create_pid_file(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__CREATE_PID_FILE; }
        else { self.run_flags &= !RUN_FLAG__CREATE_PID_FILE; }
    }
    /// snort_config.cc :686-:690 `set_log_dir` (store-or-clear).
    pub fn set_log_dir(&mut self, directory: &str) {
        self.log_dir = directory.to_string(); // :688
    }
    /// snort_config.cc :704-:706 `set_dirty_pig` (plain store).
    pub fn set_dirty_pig(&mut self, enabled: bool) {
        self.dirty_pig = enabled; // :705
    }
    /// snort_config.cc :811-:828 `set_process_all_events` (the
    /// RUN_FLAG__PROCESS_ALL_EVENTS pair).
    pub fn set_process_all_events(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__PROCESS_ALL_EVENTS; }
        else { self.run_flags &= !RUN_FLAG__PROCESS_ALL_EVENTS; }
    }
    /// snort_config.cc :829-:832 `set_umask` (`file_mask = (mode_t)mask;`
    //  plain store — the ACCESSPERMS/S_IAMB h :822-:828 comment block is a
    //  doc face, not code).
    pub fn set_umask(&mut self, mask: u32) {
        self.file_mask = mask; // :831
    }
    /// snort_config.cc :725-:731 `set_obfuscation_mask` (the nullptr gate
    /// :727 never hits at the CLI face; flag | OBFUSCATE :730 + the
    /// obfuscation_net.set leg on the un-landed SfCidr face -> the text
    /// store deviation cited at the field).
    pub fn set_obfuscation_mask(&mut self, mask: &str, obfuscate_flag: u32) {
        self.output_flags |= obfuscate_flag; // :730
        self.obfuscation_mask = mask.to_string(); // :731 the .set leg face
    }
}

// ======================================================================
// the provider seam — EVERY cite-NEVER-land body the C calls rides ONE
// leg (the analyzer.rs 24d / modules.rs 24e pattern): help/dump/list
// family, the alert/log-mode setter bodies, the plugin/syslog/markup
// legs, the proc pegs wall, the Catch wall. The landed homes (log/
// messages, shellp::set_lua_sandbox) are reached THROUGH the accessors,
// NEVER re-forked.
// ======================================================================

pub trait SnortModuleWorld {
    /// the main/help.cc free family (help.h DECL, NEVER-land): the CLI
    /// help legs. Each leg carries the ground call cite; `this` (the
    /// Module*) rides the help_options face only (the C arg kept as a
    /// cite, never a value).
    fn help_options(&mut self, _prefix: &str) {}   // cc :753 / :1092 (the
    // :1092 sibling passes this Module face, help.h cite)
    fn help_basic(&mut self, _prefix: &str) {}     // cc :789 / :1068
    fn help_version(&mut self) {}                  // cc :859 / :1239
    fn help_commands(&mut self, _prefix: &str) {}  // cc :1071
    fn help_config(&mut self, _prefix: &str) {}    // cc :1074
    fn help_counts(&mut self, _prefix: &str) {}    // cc :1077
    fn help_limits(&mut self, _prefix: &str) {}    // cc :1080
    fn help_module(&mut self, _prefix: &str) {}    // cc :1083
    fn help_modules(&mut self, _prefix: &str) {}   // cc :1086
    fn help_modules_json(&mut self, _prefix: &str) {} // cc :1089
    fn help_plugins(&mut self, _prefix: &str) {}   // cc :1095
    fn help_signals(&mut self, _prefix: &str) {}   // cc :1098
    fn help_buffers(&mut self, _prefix: &str) {}   // cc :1113 (the
    // --list-buffers leg body)
    fn help_builtin(&mut self, _prefix: &str) {}   // cc :1116 (the
    // --list-builtin leg body)
    fn help_gids(&mut self, _prefix: &str) {}       // cc :1119 (the --list-
    // gids leg body)
    /// main/main.cc list family (help.h/main.h DECL, NEVER-land):
    fn list_modules(&mut self, _module_type: &str) {} // cc :1122
    fn list_plugins(&mut self, _prefix: &str) {}      // cc :1125
    fn list_daqs(&mut self) {}                        // cc :985 (the sc
    // arg cite; dump_builtin face at the C comment :396-:397)
    fn dump_modules(&mut self) {}                     // cc :1220 (the
    // --show-modules body)
    fn dump_builtin_rules(&mut self, _prefix: &str, _stub_opts: &str) {} // cc :999-:1000 (the stub_opts.c_str() third arg)
    fn dump_dynamic_rules(&mut self, _prefix: &str) {} // cc :1020
    fn dump_defaults(&mut self, _prefix: &str) {}      // cc :1023
    fn dump_version(&mut self) {}                      // cc :1042
    fn dump_rule_hex(&mut self, _prefix: &str) {}      // cc :1200
    fn dump_rule_text(&mut self, _delim: &str) {}      // cc :1203
    /// main/markup.cc face (parser/parser.h :34 `void config_markup(...)`
    /// CITE-DECL):
    fn config_markup(&mut self, _enabled: &str) {}     // cc :1134
    /// PluginManager::set_close_all_plugins (managers/plugin_manager.h,
    /// NEVER-land):
    fn set_close_all_plugins(&mut self) {}             // cc :886
    /// framework/pig_pen.h PigPen::open_syslog (NEVER-land):
    fn open_syslog(&mut self) {}                       // cc :813
    /// snort_config.cc :944-:963 set_alert_mode BODY (EventManager/
    /// OUTPUT_* faces, NEVER-land) + :966-:979 set_log_mode BODY (the
    /// Analyzer::set_main_hook + EventManager::enable_logs + output =
    /// val/dump->codecs legs, NEVER-land):
    fn set_alert_mode(&mut self, _mode: &str) {}       // cc :756
    fn set_log_mode(&mut self, _mode: &str) {}         // cc :806
    /// the getpwnam/getgrnam NAME-RESOLUTION walls (snort_config.cc :734-
    /// :799; libc faces this tree NEVER pulls): the raw face lands on the
    /// mirror, the resolution legs ride here as CITE legs:
    fn set_uid_gid_resolve(&mut self, _uid: &str, _gid: &str) {} // cc :783 / :856 faces
    /// parser/parser.h :59 parser_append_includes (NEVER land):
    fn parser_append_includes(&mut self, _path: &str) {} // cc :1197
    /// the --lua leg: sc->policy_map->get_shell()->set_overrides — the
    /// PolicyMap::get_shell() face NEVER landed (main/policy.h), the
    /// landed Shell::set_overrides_str seat (shellp.rs :482) rides behind
    /// this seam once the policy_map lands (the shellp.rs header's own
    /// PolicyMap-defer note, REUSE cite):
    fn policy_map_shell_overrides(&mut self, _chunk: &str) {} // cc :1128
    /// THE proc pegs wall — utils/stats.h :93 `extern const PegInfo
    /// proc_names[]` (DEFINITION utils/stats.cc :176, NEVER-land) + :89
    /// `extern ProcessCount proc_stats` (DEFINITION utils/stats.cc :61):
    /// the seam owns the mirrored table/veneer in a witness; the default
    /// None face = the record NEVER landed at the Rust face:
    fn proc_names(&self) -> Option<&'static [PegInfo]> { None } // cc :711
    fn proc_counts_mut(&mut self) -> Option<&mut [PegCount]> { None } // cc :714
    /// the c2x/x2c/x2s printf face (the RETURNED line rides this leg; the
    /// C exit(0) arms cite main/snort_.rs :309 EXIT_REQUESTED — NEVER
    /// written by this row):
    fn print_stdout_line(&mut self, _line: &str) {} // cc :177/:183/:195+:198

    /// the landed 24c home REUSE (the --lua-sandbox leg calls the landed
    /// shellp::set_lua_sandbox :584 THROUGH this accessor — NEVER
    /// re-forked):
    fn shell_world(&mut self) -> &mut ShellWorld;
}

/// the NullWorld default impl (the analyzer.rs 24d pattern).
pub struct NullWorld {
    pub shell_world: ShellWorld, // the shellp.rs :201 home rides through
}

impl Default for NullWorld {
    fn default() -> Self {
        NullWorld { shell_world: ShellWorld::new_boot() }
    }
}

impl SnortModuleWorld for NullWorld {
    fn shell_world(&mut self) -> &mut ShellWorld {
        &mut self.shell_world
    }
}

// ======================================================================
// the module class — h :48-:90 (the ctor h :51; the SHELL get_commands
// override :53-:55 cited at the census block; begin/set/end :57-:59;
// get_pegs/get_counts :61-:62; global_stats :64-:65 `return true`; the
// sum_stats base-passthrough :67-:69 — the C++
// `// cppcheck-suppress uselessOverride` comment face transcribes as a
// CITE, NEVER an attribute: `void sum_stats(bool dump_stats) {
// Module::sum_stats(dump_stats); }` — the landed base face is framework/
// module.rs :539 (v, p, dump_stats), the caller drives that home through
// the stats wire; THIS row keeps the passthrough contract as this cite,
// the same ruling as the 19a transcribe).
// ======================================================================

/// the ctor cc :702-:703 `SnortModule() : Module(s_name, s_help,
/// s_params) { }` (the three-arg params seat rides the landed new_params,
/// the C NSDMI false default, module.h :226).
pub struct SnortModule {
    /// h :84 the raw `SFDAQModuleConfig* module_config = nullptr` -> the
    /// index identity into mirror.daq_config.module_configs (the
    /// sfdaq_config.rs :141 add_module_config->usize face, deviation at
    /// the header); the overlay-replay staleness law rides the 23a home.
    module_config: Option<usize>,
    // — the h :85-:89 NSDMI privates: —
    pub no_warn_flowbits: bool, // h :85 `= false`
    pub no_warn_rules: bool,    // h :86 `= false`
    pub stub_opts: String,      // h :87
    pub cli_opts: BTreeSet<String>, // h :88
    pub cli_mode: bool,         // h :89 `= true`
    base: Module,
}

impl Default for SnortModule {
    fn default() -> Self {
        Self::new()
    }
}

impl SnortModule {
    pub fn new() -> SnortModule {
        SnortModule {
            // cc :702-:703 (S_NAME :691, S_HELP the live arm
            // :697, S_PARAMS :232-:684, the is_list=false default):
            base: Module::new_params(S_NAME, S_HELP, Some(&S_PARAMS), false),
            module_config: None, // h :84 `= nullptr`
            no_warn_flowbits: false, // h :85
            no_warn_rules: false,    // h :86
            stub_opts: String::new(), // h :87 (the
            // --dump-builtin-options :997 store target)
            cli_opts: BTreeSet::new(), // h :88
            cli_mode: true,            // h :89
        }
    }

    /// the ctor cite — `#ifdef SHELL ... get_commands()` (h :53-:55 +
    /// cc :705-:708 `return snort_cmds;`): SHELL OFF, CITED, NEVER a live
    /// method (the table census lives at the block above).
    pub const fn global_stats(&self) -> bool {
        true // h :64-:65
    }

    /// h :75-:76 `Usage get_usage() const { return GLOBAL; }` (the landed
    /// C_USAGE_GLOBAL ordinal REUSE).
    pub const fn get_usage(&self) -> u32 {
        C_USAGE_GLOBAL
    }

    pub fn get_name(&self) -> Option<&'static str> {
        self.base.get_name() // module.h :114-:115 base face REUSE
    }
    pub fn get_help(&self) -> Option<&'static str> {
        self.base.get_help() // module.h :133-:134
    }
    pub fn get_parameters(&self) -> Option<&'static [Parameter]> {
        self.base.get_parameters() // module.h :136-:137 -> S_PARAMS
    }

    /// cc :710-:711 `const PegInfo* get_pegs() const { return
    /// proc_names; }` — the proc_names NOT-LAND wall rides the seam leg
    /// (None = the record never landed; the witness owns the mirrored
    /// table, the 24d NOT-LAND-wall posture).
    pub fn get_pegs<W: SnortModuleWorld + ?Sized>(&self, w: &W) -> Option<&'static [PegInfo]> {
        w.proc_names()
    }

    /// cc :713-:714 `PegCount* get_counts() const { return
    /// reinterpret_cast<PegCount*>(&proc_stats); }` — the layout-alias
    /// face: the veneer rides the seam directly (deviation row 5 in the
    /// header; ZERO casts authored).
    pub fn get_counts<'a, W: SnortModuleWorld + ?Sized>(
        &self,
        w: &'a mut W,
    ) -> Option<&'a mut [PegCount]> {
        w.proc_counts_mut()
    }

    /// cc :716-:720 — `void SnortModule::reset_stats() { if
    /// (snort::in_main_thread()) Module::reset_stats(); }` — the
    /// in_main_thread gate REUSES the landed main/thread.rs :65 face
    /// (ThreadState rides the arg, the 17l thread-static law); the base
    /// Module::reset_stats (module.cc :339-:360, the landed framework/
    /// module.rs :794 face — REUSE cite) short-circuits at its own
    /// :343-:344 `if ( !p ) return;` gate while the ProcessCount veneer
    /// stays the NOT-LAND wall: the None face means the base leg lands
    /// its null gate verbatim, and this row NEVER re-forks the base loop.
    pub fn reset_stats(
        &mut self,
        ts: &ThreadState,
        counts: Option<&mut [PegCount]>,
    ) {
        if !thread_in_main(ts) {
            return; // cc :718 the gate
        }
        // cc :719 the Module::reset_stats base leg: with the veneer
        // None this is the C `p = get_counts(); if (!p) return;`
        // (module.cc :343-:344) arm; the counts[]/dump_stats_counts[]
        // rows ride the landed base when ProcessCount lands:
        if let Some(_veneer) = counts {
            // the veneer exists but the peg table (proc_names, cc :710-
            // :711) keeps its own wall: the landed base's module.cc
            // :348-:349 `if ( !q ) return;` arm short-circuits — cited,
            // NEVER a re-forked loop (see get_pegs).
        }
    }

    /// cc :722-:723 `void SnortModule::set_trace(const Trace* trace)
    /// const { snort_trace = trace; }` — the THREAD_LOCAL definition-home
    /// write (the codec.rs :377-:381 DECODE_TRACE twin posture, this TU
    /// owns snort_trace cc :700).
    pub fn set_trace(&self, trace: Option<&'static TraceToken>) {
        SNORT_TRACE.with(|t| t.set(trace)); // :723
    }

    /// the current-slot readback (the definition-home probe face).
    pub fn snort_trace_armed() -> bool {
        SNORT_TRACE.with(|t| t.get().is_some())
    }

    /// cc :725-:728 `const TraceOption* get_trace_options() const {
    /// return snort_trace_options; }` — the live table above (the landed
    /// TraceOptionFace REUSE, the codec.rs :399 face).
    pub fn get_trace_options(&self) -> Option<&'static [TraceOptionFace]> {
        Some(&SNORT_TRACE_OPTIONS)
    }

    /// cc :730-:735 `bool SnortModule::begin(const char* fqn, int,
    /// SnortConfig*) { if (!strcmp(fqn, "snort")) module_config =
    /// nullptr; return true; }` — the C unqualified "snort" == S_NAME :690,
    /// the same-string face kept.
    pub fn begin(&mut self, fqn: &str, _idx: i32) -> bool {
        if fqn == S_NAME {
            // :732-:733 (`!strcmp(fqn, "snort")` -> the module_config
            // reset):
            self.module_config = None; // (the sfdaq_module.rs :361-:381
            // set_config reset posture REUSE cite; C's raw ptr -> the
            // index face, deviation row 1)
        }
        true // :734
    }
}

/// the landed in_main_thread REUSE shim (main/thread.rs :65; kept local
/// so the one-home face stays the only definition).
fn thread_in_main(ts: &ThreadState) -> bool {
    crate::main::thread::in_main_thread(ts)
}

impl SnortModule {
    /// h :82 `inline bool is(const snort::Value& v, const char* opt);` +
    /// cc :737-:748 — the sniffed-ladder gate:
    /// ```text
    /// if ( !v.is(opt) ) return false;
    /// if ( cli_mode ) cli_opts.emplace(string(opt));
    /// else return cli_opts.end() == cli_opts.find(string(opt));
    /// return true;
    /// ```
    /// The cli_opts BTreeSet records EVERY option consumed during CLI
    /// mode (h :88; the Lua re-set pass then only replays options that
    /// were NOT already applied from the command line — the
    /// double-apply-prevention face).
    fn is(&mut self, v: &Value, opt: &str) -> bool {
        if !v.is(opt) {
            return false; // :739-:740
        }
        if self.cli_mode {
            self.cli_opts.insert(opt.to_string()); // :742-:743
        } else {
            return !self.cli_opts.contains(opt); // :744-:745 (C find == end)
        }
        true // :747
    }

    /// cc :750-:1281 THE set ladder — EXACTLY-1 top if + EXACTLY-137
    /// else-if legs, EXACTLY-143 `is(v, ` call sites (the 5 doubled legs
    /// :779 -G|--logid, :837 -r|--pcap-list, :843 -s|--snaplen (the C++
    /// `or` alternative-token face kept as a cite), :867 -x|--pedantic,
    /// :873 -z|--max-packet-threads). LIVE legs = 129 / live call sites =
    /// 134; the 9 dialect legs ride cited comment arms at their ground
    /// slots. The string legs ride the landed from_utf8_lossy posture
    /// (get_string -> &[u8], the 23c/24e file face).
    pub fn set<W>(&mut self, v: &mut Value, sc: &mut SnortConfigMirror, w: &mut W) -> bool
    where
        W: SnortModuleWorld + ?Sized,
    {
        // — the s[]-string accessors ride the lossy face once per leg: —
        let sv = String::from_utf8_lossy(v.get_string()).into_owned();
        let sv = sv.as_str();

        if self.is(v, "-?") {
            w.help_options(sv); // :752-:753 (the third C arg = this Module*, cited)
        } else if self.is(v, "-A") {
            // :755-:756 sc->set_alert_mode — the BODY (snort_config.cc
            // :944-:963, the strcasecmp none/cmg/jh/djr arms +
            // EventManager::enable_alerts + OUTPUT_* seats) rides the
            // NEVER-land seam:
            w.set_alert_mode(sv);
        } else if self.is(v, "-B") {
            // :758-:759 sc->set_obfuscation_mask (the body
            // snort_config.cc :725-:731 mirrored on the bag, cited):
            sc.set_obfuscation_mask(sv, OUTPUT_FLAG__OBFUSCATE);
        } else if self.is(v, "-C") {
            sc.set_dump_chars_only(true, OUTPUT_FLAG__CHAR_DATA); // :761-:762
        } else if self.is(v, "-c") {
            // :764-:765 config_conf(v.get_string()) — the landed parser/
            // config_file.rs :46 REUSE (the set_main_hook half stays that
            // home's cited no-op face):
            sc.conf_files.config_conf(sv);
        } else if self.is(v, "-D") {
            sc.set_daemon(true); // :767-:768
        } else if self.is(v, "-d") {
            // :770-:771 sc->set_dump_payload(true) — snort_config.cc
            // :643-:652 the OUTPUT_FLAG__APP_DATA if-arm:
            sc.output_flag_on(OUTPUT_FLAG__APP_DATA);
        } else if self.is(v, "-e") {
            sc.set_decode_data_link(true); // :773-:774
        } else if self.is(v, "-f") {
            // :776-:777 sc->output_flags |= OUTPUT_FLAG__LINE_BUFFER:
            sc.output_flag_on(OUTPUT_FLAG__LINE_BUFFER);
        } else if self.is(v, "-G") || self.is(v, "--logid") {
            // :779-:780 DOUBLED leg — sc->event_log_id = v.get_uint16()
            // (the direct h :328 store face):
            sc.event_log_id = v.get_uint16();
        } else if self.is(v, "-g") {
            // :782-:783 sc->set_gid(v.get_string()) — the NAME-RESOLUTION
            // body (snort_config.cc :734-:763, the strtol/getgrnam/
            // getgrgid getgid legs, libc faces ZERO-pulled here): the raw
            // face lands on the bag, the wall cited:
            sc.gid_face = sv.to_string();
        } else if self.is(v, "-H") {
            sc.run_flag_on(RUN_FLAG__STATIC_HASH); // :785-:786
        } else if self.is(v, "-h") {
            w.help_basic(sv); // :788-:789
        } else if self.is(v, "-i") {
            // :791-:792 sc->daq_config->add_input — the SFDAQConfig :78-
            // :82 add_input leg on the 23a REUSE record (the C ctor face
            // snort_config.cc :186 never-null; the None face = the ctor
            // seat unported, cited):
            if let Some(dc) = sc.daq_config.as_mut() {
                dc.add_input(Some(sv));
            }
        }
        // :794-:800 dialect (SHELL) — the -j leg body, CITED never live
        // (ENABLE_SHELL OFF; remote_control_port h :407 `= -1` + remote_-
        // control_socket h :408 never written on this row):
        //     else if ( is(v, "-j") )
        //     {
        //         sc->remote_control_port = v.get_uint16();
        //         sc->remote_control_socket.clear();
        //     }
        else if self.is(v, "-k") {
            // :802-:803 ConfigChecksumMode(v.get_string()) — the landed
            // parser/config_file.rs :165 REUSE (config_file.cc :161-:165
            // network_policy->checksum_eval = GetChecksumFlags(args); the
            // parse-error store-0 face rides that home):
            config_checksum_mode(Some(sv), &mut sc.log_net, &mut sc.log);
        } else if self.is(v, "-L") {
            // :805-:806 sc->set_log_mode — the BODY (snort_config.cc
            // :966-:979, the Analyzer::set_main_hook + EventManager::
            // enable_logs + output = val/(dump->codecs) arms) NEVER-land:
            w.set_log_mode(sv);
        } else if self.is(v, "-l") {
            sc.set_log_dir(sv); // :808-:809 (snort_config.cc :686-:690)
        } else if self.is(v, "-M") {
            // :811-:815 the brace leg: PigPen::open_syslog() (framework/
            // pig_pen.h, NEVER-land -> seam) + SnortConfig::enable_log_-
            // syslog (snort_config.h :733 `logging_flags |= LOGGING_FLAG_-
            // __SYSLOG;` — the landed LOGGING_FLAG_SYSLOG identity REUSE
            // (messages.rs :42) at the mirror field the home owns):
            w.open_syslog();
            sc.log.logging_flags |= LOGGING_FLAG_SYSLOG;
        } else if self.is(v, "-m") {
            sc.set_umask(v.get_uint32()); // :816-:817 (snort_config.cc :829-:832)
        } else if self.is(v, "-n") {
            sc.pkt_cnt = v.get_uint64(); // :819-:820 (direct h :308 store)
        } else if self.is(v, "-O") {
            sc.set_obfuscate(true, OUTPUT_FLAG__OBFUSCATE); // :822-:823
        } else if self.is(v, "-Q") {
            sc.run_flag_on(RUN_FLAG__INLINE); // :825-:826
        } else if self.is(v, "-q") {
            sc.log.set_log_quiet(true); // :828-:829 (h :739-:745 static -> the
            // landed messages.rs :139 REUSE face)
        } else if self.is(v, "-R") {
            // :831-:836 the brace leg: `string s = "include "; s +=
            // v.get_string(); parser_append_rules(s.c_str());` — the
            // landed detection/parse_rule.rs :1225 REUSE over the bag's
            // RuleCoreState (C cc :833-:834 the literal face):
            let s = format!("include {sv}");
            parser_append_rules(&mut sc.rules, &s);
        } else if self.is(v, "-r") || self.is(v, "--pcap-list") {
            // :837-:841 DOUBLED leg, brace: run_flags |= RUN_FLAG__READ;
            // Trough::add_source(Trough::SOURCE_LIST, ..) — the 23d
            // facade REUSE (the C static legs -> the bag's one Trough):
            sc.run_flag_on(RUN_FLAG__READ);
            sc.trough.add_source(SourceType::SourceList, sv);
        } else if self.is(v, "-s") || self.is(v, "--snaplen") {
            // :843-:844 DOUBLED leg (the C++ `or` token face kept cited):
            // sc->daq_config->set_mru_size(v.get_uint16()) — the landed
            // setter takes i32 (the SNAPLEN_UNSET -1 face), the u16 ->
            // i32 widening cited:
            if let Some(dc) = sc.daq_config.as_mut() {
                dc.set_mru_size(i32::from(v.get_uint16()));
            }
        } else if self.is(v, "-T") {
            sc.run_flag_on(RUN_FLAG__TEST); // :846-:847
        } else if self.is(v, "-t") {
            sc.set_chroot_dir(sv); // :849-:850 (snort_config.cc :575-:581)
        } else if self.is(v, "-U") {
            sc.set_utc(true); // :852-:853 (snort_config.cc :834-:840)
        } else if self.is(v, "-u") {
            // :855-:856 sc->set_uid — the NAME-RESOLUTION body (snort_
            // config.cc :765-:799, the getpwnam/getpwuid legs, NEVER-land
            // libc wall): the raw face lands on the bag, cited:
            sc.uid_face = sv.to_string();
        } else if self.is(v, "-V") {
            w.help_version(); // :858-:859
        } else if self.is(v, "-v") {
            // :861-:862 SnortConfig::enable_log_verbose (h :766
            // `logging_flags |= LOGGING_FLAG__VERBOSE;` — the VERBOSE
            // seat this row owns, the flag op on the home's mirror):
            sc.log.logging_flags |= LOGGING_FLAG__VERBOSE;
        } else if self.is(v, "-X") {
            // :864-:865 set_dump_payload_verbose(true) — snort_config.cc
            // :654-:662 the OUTPUT_FLAG__VERBOSE_DUMP if-arm:
            sc.output_flag_on(OUTPUT_FLAG__VERBOSE_DUMP);
        } else if self.is(v, "-x") || self.is(v, "--pedantic") {
            // :867-:868 DOUBLED leg — run_flags |= RUN_FLAG__CONF_ERROR_OUT
            sc.run_flag_on(RUN_FLAG__CONF_ERROR_OUT);
        } else if self.is(v, "-y") {
            sc.set_show_year(true, OUTPUT_FLAG__INCLUDE_YEAR); // :870-:871
        } else if self.is(v, "-z") || self.is(v, "--max-packet-threads") {
            // :873-:874 DOUBLED leg — ThreadConfig::set_instance_max:
            // the landed thread_config.rs :726 REUSE (the C static face
            // == the row-owned home; NEVER re-forked):
            ThreadConfig::set_instance_max(v.get_uint32());
        } else if self.is(v, "--alert-before-pass") {
            sc.set_alert_before_pass(true); // :876-:877 (snort_config.cc :567-:573)
        } else if self.is(v, "--bpf") {
            sc.bpf_filter = sv.to_string(); // :879-:880 (direct h :330 store)
        } else if self.is(v, "--c2x") {
            // :882-:883 c2x(v.get_string()) — the pure format leg + the
            // world print seam (the exit(0) arm cites EXIT_REQUESTED):
            w.print_stdout_line(&c2x(v.get_string()));
        } else if self.is(v, "--close-all-plugins") {
            w.set_close_all_plugins(); // :885-:886 (plugin_manager.h NEVER-land)
        }
        // :888-:939 dialect (SHELL x4) — the control-socket cluster,
        // CITED never live (ENABLE_SHELL OFF): the --control-socket leg
        // :889-:893 (`sc->remote_control_socket = v.get_string(); sc->
        // remote_control_port = -1;`), the --control-socket-uid leg
        // :895-:913 (the strtol endptr/`uid_val >= 0` numeric arm ->
        // control_socket_uid h :409 `static_cast<uid_t>(-1)` seat, else
        // the getpwnam arm + the :911 ParseError("Unknown user '%s' for
        // --control-socket-uid", uid_str) leg), the --control-socket-gid
        // leg :915-:933 (the getgrnam twin + the :931 ParseError("Unknown
        // group '%s' for --control-socket-gid", gid_str) leg) and the
        // --control-secret-file leg :935-:938 (h :411 control_secret_file
        // store). The getpwnam/getgrnam libc wall + the uid_t/gid_t h
        // :409-:411 seats NEVER land on the OFF face — the full C bodies
        // transcribe here as the cite block, NEVER as live legs.
        else if self.is(v, "--create-pidfile") {
            // :941-:945 the brace leg: set_create_pid_file(true) +
            // set_pid_filename (snort_config.cc :591-:597 / :599-:603):
            sc.set_create_pid_file(true);
            sc.set_pid_filename(sv);
        } else if self.is(v, "--max-procs") {
            sc.set_max_procs(v.get_uint8()); // :947-:948 (snort_config.cc :607-:610)
        } else if self.is(v, "--create-instance-file") {
            sc.set_create_instance_file(true); // :950-:951
        } else if self.is(v, "--daq") {
            // :953-:954 `module_config = sc->daq_config->add_module_config(
            // v.get_string())` — the 23a REUSE add -> usize identity face
            // (the deviation row 1: index into module_configs, NEVER a
            // raw pointer):
            if let Some(dc) = sc.daq_config.as_mut() {
                self.module_config = Some(dc.add_module_config(sv));
            }
        } else if self.is(v, "--daq-batch-size") {
            if let Some(dc) = sc.daq_config.as_mut() {
                dc.set_batch_size(v.get_uint32()); // :956-:957 (sfdaq_config.cc :98-:101)
            }
        } else if self.is(v, "--daq-dir") {
            // :959-:966 the brace leg: `stringstream ss { v.get_string()
            // }; string path; while ( getline(ss, path, ':') ) sc->daq_
            // config->add_module_dir(path.c_str());` — the ':' getline
            // ladder -> split_inclusive face (getline on ':' NEVER drops
            // an empty trailing token the way split does: the last token
            // lands whenever the stream had ANY chars):
            if let Some(dc) = sc.daq_config.as_mut() {
                for path in split_colon(sv) {
                    dc.add_module_dir(Some(&path)); // sfdaq_config.cc :92-:96
                }
            }
        } else if self.is(v, "--daq-mode") {
            // :967-:983 the brace leg — the C null gate `if
            // (!module_config) return false;` (:969-:970) kept VERBATIM
            // on the Option face (the crash-vs-None law as
            // sfdaq_module.rs measured); the switch over
            // v.get_uint8(): case 0 PASSIVE / 1 INLINE / 2 READ_FILE
            // (:971-:982) — the SFDAQ_MODE_* consts REUSE (the
            // PT_ENUM-ordinal face 0..2, the landed sfdaq_config.rs
            // ordinals 1/2/3 ride through the consts, NEVER re-mapped):
            let Some(idx) = self.module_config else {
                return false; // :969-:970
            };
            let mode = match v.get_uint8() {
                0 => Some(SFDAQ_MODE_PASSIVE), // :973-:975
                1 => Some(SFDAQ_MODE_INLINE),  // :976-:978
                2 => Some(SFDAQ_MODE_READ_FILE), // :979-:981
                _ => None, // the C switch default: NO write, falls to break
            };
            if let (Some(m), Some(cfgs)) = (mode, sc.daq_config.as_mut())
                && let Some(mc) = cfgs.module_configs.get_mut(idx)
            {
                mc.mode = m; // :974/:977/:980 `module_config->mode = ...`
            }
        } else if self.is(v, "--daq-list") {
            w.list_daqs(); // :984-:985 (main/main.cc NEVER-land)
        } else if self.is(v, "--daq-var") {
            // :987-:992 the C null gate + the set_variable leg:
            let Some(idx) = self.module_config else {
                return false; // :989-:990
            };
            if let Some(cfgs) = sc.daq_config.as_mut()
                && let Some(mc) = cfgs.module_configs.get_mut(idx)
            {
                mc.set_variable(Some(sv)); // module.h :55 (sfdaq_config face)
            }
        } else if self.is(v, "--dirty-pig") {
            sc.set_dirty_pig(true); // :993-:994
        } else if self.is(v, "--dump-builtin-options") {
            self.stub_opts = sv.to_string(); // :996-:997 (h :87 store)
        } else if self.is(v, "--dump-builtin-rules") {
            // :999-:1000 dump_builtin_rules(sc, v.get_string(), stub_opts
            // .c_str()) — the main/main.cc NEVER-land seam (the third C
            // arg = this TU's stub_opts face):
            w.dump_builtin_rules(sv, &self.stub_opts);
        } else if self.is(v, "--dump-config") {
            // :1002-:1010 the brace leg: set_log_quiet(true) + run_flags
            // |= RUN_FLAG__TEST + the get_as_string "all"/"top" arms
            // (DUMP_CONFIG_JSON_ALL :1007 / _JSON_TOP :1009, h :134-:135):
            sc.log.set_log_quiet(true);
            sc.run_flag_on(RUN_FLAG__TEST);
            let gs = v.get_as_string();
            if gs == "all" {
                sc.dump_config_type = DUMP_CONFIG_JSON_ALL;
            } else if gs == "top" {
                sc.dump_config_type = DUMP_CONFIG_JSON_TOP;
            }
        } else if self.is(v, "--dump-config-text") {
            // :1012-:1017 the brace leg (DUMP_CONFIG_TEXT :1016):
            sc.log.set_log_quiet(true);
            sc.run_flag_on(RUN_FLAG__TEST);
            sc.dump_config_type = DUMP_CONFIG_TEXT;
        } else if self.is(v, "--dump-dynamic-rules") {
            w.dump_dynamic_rules(sv); // :1019-:1020
        } else if self.is(v, "--dump-defaults") {
            w.dump_defaults(sv); // :1022-:1023
        } else if self.is(v, "--dump-rule-deps") {
            // :1025-:1029 the brace leg (the `|=` compound face kept):
            sc.run_flags |= RUN_FLAG__DUMP_RULE_DEPS | RUN_FLAG__TEST;
            sc.log.set_log_quiet(true);
        } else if self.is(v, "--dump-rule-meta") {
            // :1030-:1035 the brace leg (+ OUTPUT_FLAG__ALERT_REFS :1033):
            sc.run_flags |= RUN_FLAG__DUMP_RULE_META | RUN_FLAG__TEST;
            sc.output_flags |= OUTPUT_FLAG__ALERT_REFS;
            sc.log.set_log_quiet(true);
        } else if self.is(v, "--dump-rule-state") {
            // :1036-:1040 the brace leg:
            sc.run_flags |= RUN_FLAG__DUMP_RULE_STATE | RUN_FLAG__TEST;
            sc.log.set_log_quiet(true);
        } else if self.is(v, "--dump-version") {
            w.dump_version(); // :1041-:1042
        } else if self.is(v, "--enable-inline-test") {
            sc.run_flag_on(RUN_FLAG__INLINE_TEST); // :1044-:1045
        } else if self.is(v, "--enable-test-features") {
            // :1047-:1051 the brace leg: RUN_FLAG__TEST_FEATURES + SfIp::
            // test_features = true (sf_ip.h :107 class static -> the bag
            // field, the sfip homes' explicit-arg faces REUSE cited):
            sc.run_flag_on(RUN_FLAG__TEST_FEATURES);
            sc.sfip_test_features = true;
        }
        // :1052-:1055 dialect (REG_TEST) — the --exit-after-reload leg,
        // CITED never live (REG_TEST grep-0 in create_options.cmake; the
        // RUN_FLAG__EXIT_AFTER_RELOAD h :84 ordinal gated too):
        //     else if ( is(v, "--exit-after-reload") )
        //         sc->run_flags |= RUN_FLAG__EXIT_AFTER_RELOAD;
        else if self.is(v, "--gen-dump-config") {
            // :1056-:1060 the brace leg:
            sc.run_flag_on(RUN_FLAG__GEN_DUMP_CONFIG);
            sc.dump_config_file = sv.to_string();
        } else if self.is(v, "--gen-msg-map") {
            // :1061-:1066 the brace leg (DUMP_MSG_MAP|TEST + ALERT_REFS):
            sc.run_flags |= RUN_FLAG__DUMP_MSG_MAP | RUN_FLAG__TEST;
            sc.output_flags |= OUTPUT_FLAG__ALERT_REFS;
            sc.log.set_log_quiet(true);
        } else if self.is(v, "--help") {
            w.help_basic(sv); // :1067-:1068
        } else if self.is(v, "--help-commands") {
            w.help_commands(sv); // :1070-:1071
        } else if self.is(v, "--help-config") {
            w.help_config(sv); // :1073-:1074
        } else if self.is(v, "--help-counts") {
            w.help_counts(sv); // :1076-:1077
        } else if self.is(v, "--help-limits") {
            w.help_limits(sv); // :1079-:1080 (the C passes
            // v.get_string() although the row is PT_IMPLIED, the disk
            // face kept at the seam arg)
        } else if self.is(v, "--help-module") {
            w.help_module(sv); // :1082-:1083
        } else if self.is(v, "--help-modules") {
            w.help_modules(sv); // :1085-:1086
        } else if self.is(v, "--help-modules-json") {
            w.help_modules_json(sv); // :1088-:1089
        } else if self.is(v, "--help-options") {
            w.help_options(sv); // :1091-:1092 (== the -? face :752-:753)
        } else if self.is(v, "--help-plugins") {
            w.help_plugins(sv); // :1094-:1095
        } else if self.is(v, "--help-signals") {
            w.help_signals(sv); // :1097-:1098
        } else if self.is(v, "--id-offset") {
            sc.id_offset = v.get_uint16(); // :1100-:1101 (direct h :336)
        } else if self.is(v, "--id-subdir") {
            sc.id_subdir = true; // :1103-:1104 (direct h :337)
        } else if self.is(v, "--id-zero") {
            sc.id_zero = true; // :1106-:1107 (direct h :338)
        } else if self.is(v, "--include-path") {
            sc.set_include_path(sv); // :1109-:1110 (snort_config.cc :911-:917)
        } else if self.is(v, "--list-buffers") {
            w.help_buffers(sv); // :1112-:1113 (the help_body face)
        } else if self.is(v, "--list-builtin") {
            w.help_builtin(sv); // :1115-:1116
        } else if self.is(v, "--list-gids") {
            w.help_gids(sv); // :1118-:1119
        } else if self.is(v, "--list-modules") {
            w.list_modules(sv); // :1121-:1122
        } else if self.is(v, "--list-plugins") {
            w.list_plugins(sv); // :1124-:1125
        } else if self.is(v, "--lua") {
            // :1127-:1128 `sc->policy_map->get_shell()->set_overrides(
            // v.get_string())` — the PolicyMap::get_shell() face NEVER
            // landed; the landed shellp.rs :482 Shell::set_overrides_str
            // seat rides behind the seam once policy_map lands (the CITE-
            // DECL posture, the shellp.rs defer note REUSE):
            w.policy_map_shell_overrides(sv);
        } else if self.is(v, "--lua-sandbox") {
            // :1130-:1131 `Shell::set_lua_sandbox(v.get_string())` — the
            // LANDED 24c home shellp.rs :584 set_lua_sandbox REUSE (the
            // file-static seat that home's ShellWorld :201 owns; NEVER
            // re-forked):
            set_lua_sandbox(w.shell_world(), sv);
        } else if self.is(v, "--markup") {
            w.config_markup(sv); // :1133-:1134 (main/main.cc NEVER-land)
        } else if self.is(v, "--mem-check") {
            // :1136-:1137 sc->run_flags |= (RUN_FLAG__TEST | RUN_FLAG__
            // MEM_CHECK):
            sc.run_flags |= RUN_FLAG__TEST | RUN_FLAG__MEM_CHECK;
        } else if self.is(v, "--metadata-filter") {
            sc.metadata_filter = sv.to_string(); // :1139-:1140 (direct h :331)
        } else if self.is(v, "--nostamps") {
            sc.set_no_logging_timestamps(true); // :1142-:1143
        } else if self.is(v, "--nolock-pidfile") {
            sc.run_flag_on(RUN_FLAG__NO_LOCK_PID_FILE); // :1145-:1146
        } else if self.is(v, "--no-warn-flowbits") {
            self.no_warn_flowbits = true; // :1148-:1149 (h :85; the CLEAR
            // leg lands in end() :1292-:1296)
        } else if self.is(v, "--no-warn-rules") {
            self.no_warn_rules = true; // :1151-:1152 (h :86; end :1298-:1302)
        } else if self.is(v, "--pause") {
            sc.run_flag_on(RUN_FLAG__PAUSE); // :1154-:1155
        }
        // :1157-:1160 dialect (REG_TEST) — the --pause-after-n leg, CITED
        // never live (the h :310 pkt_pause_cnt SLOT is NOT dialect — the
        // bag field landed, ONLY this writer leg gated, the 24e
        // asymmetry precedent):
        //     else if ( is(v, "--pause-after-n") )
        //         sc->pkt_pause_cnt = v.get_uint64();
        else if self.is(v, "--pcap-file") {
            // :1162-:1166 the brace leg:
            sc.run_flag_on(RUN_FLAG__READ);
            sc.trough.add_source(SourceType::SourceFileList, sv);
        } else if self.is(v, "--pcap-dir") {
            // :1167-:1171 the brace leg:
            sc.run_flag_on(RUN_FLAG__READ);
            sc.trough.add_source(SourceType::SourceDir, sv);
        } else if self.is(v, "--pcap-filter") {
            sc.trough.set_filter(Some(sv)); // :1172-:1173 (trough.cc face REUSE)
        } else if self.is(v, "--pcap-loop") {
            sc.trough.set_loop_count(v.get_uint32()); // :1175-:1176
        } else if self.is(v, "--pcap-no-filter") {
            sc.trough.set_filter(None); // :1178-:1179 (`Trough::set_filter
            // (nullptr)` — the Option face)
        } else if self.is(v, "--pcap-show") {
            sc.run_flag_on(RUN_FLAG__PCAP_SHOW); // :1181-:1182
        } else if self.is(v, "--plugin-path") {
            sc.add_plugin_path(sv); // :1184-:1185 (snort_config.cc :919-:928)
        } else if self.is(v, "--process-all-events") {
            sc.set_process_all_events(true); // :1187-:1188 (snort_config.cc :811-:)
        } else if self.is(v, "--retry-timeout") {
            sc.retry_timeout = v.get_uint32(); // :1190-:1191 (direct h :433)
        } else if self.is(v, "--rule") {
            // :1193-:1194 parser_append_rules(v.get_string()) — the
            // parse_rule.rs :1225 REUSE (the C takes a C-cstr; the landed
            // face takes &str):
            parser_append_rules(&mut sc.rules, sv);
        } else if self.is(v, "--rule-path") {
            // :1196-:1197 parser_append_includes (parser/parser.h :59 —
            // NEVER-land; note detection/parse_rule.rs landed the RULES
            // twin ONLY, grep-0 the includes twin, the disk face wins):
            w.parser_append_includes(sv);
        } else if self.is(v, "--rule-to-hex") {
            w.dump_rule_hex(sv); // :1199-:1200 (main/main.cc NEVER-land)
        } else if self.is(v, "--rule-to-text") {
            w.dump_rule_text(sv); // :1202-:1203
        } else if self.is(v, "--run-prefix") {
            sc.run_prefix = sv.to_string(); // :1205-:1206 (direct h :335)
        } else if self.is(v, "--script-path") {
            sc.add_script_path(sv); // :1208-:1209 (snort_config.cc :938-:941)
        }
        // :1211-:1214 dialect (SHELL) — the --shell leg, CITED never live
        // (RUN_FLAG__SHELL h :80 — gated ordinal — NEVER landed):
        //     else if ( is(v, "--shell") )
        //         sc->run_flags |= RUN_FLAG__SHELL;
        else if self.is(v, "--show-file-codes") {
            sc.run_flag_on(RUN_FLAG__SHOW_FILE_CODES); // :1216-:1217
        } else if self.is(v, "--show-modules") {
            w.dump_modules(); // :1219-:1220 (main/main.cc NEVER-land)
        } else if self.is(v, "--skip") {
            sc.pkt_skip = v.get_uint64(); // :1222-:1223 (direct h :309)
        } else if self.is(v, "--stdin-rules") {
            sc.stdin_rules = true; // :1225-:1226 (direct h :340)
        } else if self.is(v, "--talos") {
            sc.set_tweaks("talos"); // :1228-:1229 (the literal C face)
        } else if self.is(v, "--tweaks") {
            sc.set_tweaks(sv); // :1231-:1232 (snort_config.cc :930-:935)
        }
        // :1234-:1237 dialect (UNIT_TEST||BENCHMARK_TEST) — the
        // --catch-test leg, CITED never live; the catch_set_filter WALL
        // (catch/unit_test.h :27, the include seat at :52):
        //     else if ( is(v, "--catch-test") )
        //         catch_set_filter(v.get_string());
        else if self.is(v, "--version") {
            w.help_version(); // :1238-:1239
        } else if self.is(v, "--warn-all") {
            // :1241-:1242 `sc->warning_flags = 0xFFFFFFFF;` — the `=`
            // store face kept (NOT |=). The static rides the landed
            // messages.rs :98 mirror; the WARN ordinals the home's
            // :27-:36 (the log/messages.h :41-:44 WARNING-GROUP walk):
            sc.log.warning_flags = ALL_WARN_FLAGS;
        } else if self.is(v, "--warn-conf") {
            sc.log.warning_flags |= 1 << WARN_CONF; // :1244-:1245
        } else if self.is(v, "--warn-conf-strict") {
            sc.log.warning_flags |= 1 << WARN_CONF_STRICT; // :1247-:1248
        } else if self.is(v, "--warn-daq") {
            sc.log.warning_flags |= 1 << WARN_DAQ; // :1250-:1251
        } else if self.is(v, "--warn-flowbits") {
            sc.log.warning_flags |= 1 << WARN_FLOWBITS; // :1253-:1254
        } else if self.is(v, "--warn-hosts") {
            sc.log.warning_flags |= 1 << WARN_HOSTS; // :1256-:1257
        } else if self.is(v, "--warn-plugins") {
            sc.log.warning_flags |= 1 << WARN_PLUGINS; // :1259-:1260
        } else if self.is(v, "--warn-rules") {
            sc.log.warning_flags |= 1 << WARN_RULES; // :1262-:1263
        } else if self.is(v, "--warn-scripts") {
            sc.log.warning_flags |= 1 << WARN_SCRIPTS; // :1265-:1266
        } else if self.is(v, "--warn-symbols") {
            sc.log.warning_flags |= 1 << WARN_SYMBOLS; // :1268-:1269
        } else if self.is(v, "--warn-vars") {
            sc.log.warning_flags |= 1 << WARN_VARS; // :1271-:1272
        } else if self.is(v, "--x2c") {
            w.print_stdout_line(&x2c(v.get_uint8())); // :1274-:1275
        } else if self.is(v, "--x2s") {
            w.print_stdout_line(&x2s(v.get_string())); // :1277-:1278
        }
        true // :1280 `return true;`
    }

    /// cc :1283-:1305 `bool SnortModule::end(const char*, int,
    /// SnortConfig*)` — cli_mode flip + the two warn-clear legs. The
    /// ENABLE_DETECTION_OFFLOAD conditional (:1287-:1290) rides cited
    /// (the token is NOT a cmake seat, grep-0; the sc->offload_threads
    /// field NEVER lands):
    /// ```text
    /// #ifdef ENABLE_DETECTION_OFFLOAD
    ///     if ( sc->offload_threads and ThreadConfig::get_instance_max() != 1 )
    ///         ParseError("You can not enable experimental offload with more than one packet thread.");
    /// #endif
    /// ```
    pub fn end(&mut self, _fqn: &str, _idx: i32, sc: &mut SnortConfigMirror) -> bool {
        self.cli_mode = false; // :1285
        if self.no_warn_flowbits {
            // :1292-:1296 the clear leg (`sc->warning_flags &= ~(1 <<
            // WARN_FLOWBITS);` — the landed WARN ordinal REUSE):
            sc.log.warning_flags &= !(1 << WARN_FLOWBITS);
            self.no_warn_flowbits = false; // :1295
        }
        if self.no_warn_rules {
            // :1298-:1302:
            sc.log.warning_flags &= !(1 << WARN_RULES);
            self.no_warn_rules = false; // :1301
        }
        true // :1304
    }

    /// cc :1307-:1338 `ProfileStats* get_profile(unsigned index,
    /// const char*& name, const char*& parent) const` — the 5 named perf
    /// legs (name-out VERBATIM, parent = nullptr :1314/:1319/:1324/
    /// :1329/:1334) + the nullptr default :1337. The C hands back the
    /// extern THREAD_LOCAL ProfileStats homes (analyzer.cc :93,
    /// codec_manager.h :43, fp_detect.cc :99-:100, detect.cc :54 — the
    /// DEFINITION homes NEVER landed): the token seats above ride the
    /// row-owned file_module.rs :132-:133 precedent (deviation row 4).
    pub fn get_profile(
        &self,
        index: u32,
        name: &mut Option<&'static str>,
        parent: &mut Option<&'static str>,
    ) -> Option<&'static ProfileStatsToken> {
        match index {
            0 => {
                *name = Some("daq"); // :1313
                *parent = None; // :1314
                Some(&DAQ_PERF_STATS) // :1315 &daqPerfStats
            }
            1 => {
                *name = Some("decode"); // :1318
                *parent = None;
                Some(&DECODE_PERF_STATS) // :1320
            }
            2 => {
                *name = Some("mpse"); // :1323
                *parent = None;
                Some(&MPSE_PERF_STATS) // :1325
            }
            3 => {
                *name = Some("rule_eval"); // :1328
                *parent = None;
                Some(&RULE_PERF_STATS) // :1330
            }
            4 => {
                *name = Some("eventq"); // :1333
                *parent = None;
                Some(&EVENTQ_PERF_STATS) // :1335
            }
            _ => None, // :1337 `return nullptr;` (the C switch falls
            // through past case 4 — NO default case seat, the face kept)
        }
    }
}

/// the cc :961-:965 getline-on-':' ladder face: `while ( getline(ss,
/// path, ':') )` mirrors std::getline(sstream, tok, ':') exactly:
/// consecutive colons keep their empty interior tokens, eof stops the
/// loop so a TRAILING colon feeds no final token ("a:" -> ["a"],
/// "a::b" -> ["a","","b"], "a::" -> ["a",""], "" -> []).
fn split_colon(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new(); // getline at fresh eof = false immediately
    }
    let mut out: Vec<String> = s.split(':').map(str::to_string).collect();
    if out.last().map(|t| t.is_empty()) == Some(true) {
        out.pop(); // the trailing-delimiter arm: split's final "" is
        // exactly the token the getline loop NEVER emits (eof before
        // any extraction -> failbit); interior empties are KEPT.
    }
    out
}
