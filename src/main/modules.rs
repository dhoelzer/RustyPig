//! Row 24e — the module-registration MEGA pair landing (chapter-21 FIFTH body).
//!
//! Ground: main/modules.cc 2,491 L (md5 1a1c7937a7c6b73318122a924e37ecff) +
//! main/modules.h 30 L (md5 d004a88be5ec59832bcef19b9e652733) @ fe29cbe = the
//! 2,521 L pair ledger. This landing adds ONLY this file + the ONE
//! `pub mod modules;` wiring line at src/main/mod.rs (9 -> 10 L). The ground
//! name `modules` riding the path cites is BY CONSTRUCTION (the ground TU
//! name), fine per the 24d single-name precedent.
//!
//! THE harness-pinned CITE-DRIFT anchors (measured AT the landing, the disk
//! face wins): #ifdef UNIT_TEST :2425; includes :2426 catch/snort_catch.h +
//! :2427 log/log_errors.h; the EXACTLY-4 TEST_CASE faces :2429 (IPS action
//! variable placeholder detection) / :2442 (page rejects missing action
//! variable name) / :2455 (end validates react page) / :2469 (end rejects
//! duplicate action variable) — EXACTLY-12 CHECK legs (4/2/2/4 — counted at
//! the harness :2436-:2487); ^static EXACTLY-43; THREAD_LOCAL EXACTLY-2
//! (:231 the `namespace snort { THREAD_LOCAL PatMatQStat pmqs; }` DEFINITION
//! seat + :1877 the `extern THREAD_LOCAL EventFilterStats
//! event_filter_stats; // in sfthd.cc` — an extern: DECL cite ONLY, NEVER a
//! definition HERE, the owner TU is filters/sfthd.cc); add_module EXACTLY-37
//! legs (add_independent_modules 35 + add_dependent_modules :2419 + the
//! :2421 CRASH_MITIGATOR arm); CRASH_MITIGATOR EXACTLY-2 faces (:58 the
//! include seat, :2420 the registration seat — BOTH measure OFF on the row
//! harness cmake posture, see the dialect census).
//!
//! THE DIALECT CENSUS (the cmake-measured 0-defines posture the row harness
//! mirrors — config.cmake.h.in :120 CRASH_MITIGATOR / :143 HAVE_HYPERSCAN /
//! :165 HAVE_UUID / :171 HAVE_NUMA are plain `#cmakedefine` seats, OFF
//! unless the configure flips them; ENABLE_DETECTION_OFFLOAD + REG_TEST are
//! NOT config.h seats at all — REG_TEST rides the -DREG_TEST compile flag
//! only (main/CMake + tests), OFF on the compile face; the row lands the
//! FALSE arm EVERYWHERE, and every dialect row / leg rides as a CITED
//! comment face pinned to its ground lines, NEVER a live seat):
//!   ENABLE_DETECTION_OFFLOAD :206-:210 (the offload_search_method help-face
//!   pair; :325-:330 the set-leg pair) — OFF: the #else arm is the compile
//!   face (the deprecated help + the ParseWarning leg).
//!   HAVE_HYPERSCAN :213-:215 (rule_db_dir table row) — OFF: the row NEVER
//!   lands; :313-:316 the set leg NEVER lands.
//!   REG_TEST :427-:430 (mp_data_bus hold_events row) + :556-:561 (the
//!   hold_events set leg) — OFF: NEVER land.
//!   REG_TEST :833-:837 (the output wide_hex_dump DEFAULT FLIP: "true" on,
//!   "false" off) — OFF: deflt Some("false") rides (snort_config.h :214 pins
//!   the live default OUTPUT_FLAG__WIDE_HEX = 0x800 — the C default-flip
//!   face, cited not faked).
//!   HAVE_UUID :1175-:1178 (inspection uuid row) + :1365-:1368 (ips uuid
//!   row); the legs :1211-:1220 (inspection) + :1434-:1443 (ips) — OFF:
//!   NEVER land, cite faces only.
//!   HAVE_NUMA :1668-:1671 (the numa_memory_policy set leg in ProcessModule
//!   ::set) — OFF: never lands, cite only (the table row at :1591-:1593 is
//!   NOT dialect-gated — it lands, the SET leg does not; the honest C-face
//!   asymmetry, cited).
//!   CRASH_MITIGATOR :58-:60 include + :2420-:2422 registration — OFF:
//!   measured cmake face 0 — MitigatorModule NEVER registered (the
//!   add_dependent_modules tail pin, echoed at the ladder).
//!   UNIT_TEST :2425-:2491 — the 4 Catch TEST bodies get NO Rust body here:
//!   the EXACT-4-count cite comment face (anchors :2429/:2442/:2455/:2469,
//!   tags "[IpsModule]" x4, 12 CHECK legs) rides at the tail; the parity
//!   twin (orchestrator-authored, tests/) replays them.
//!
//! THE STATICS LAW: modules.cc's ^static x43 + THREAD_LOCAL x2 -> every
//! file-static TABLE lands as a pub static array face (the 30 Parameter
//! tables, the 4 PegInfo tables, the 2 Command tables, the 1 RuleMap table,
//! the 1 extern PegInfo face); every file-static MUTABLE write face lands as
//! a caller-owned field or seam arg (23c's record-threading law re-ridden):
//! the :231 pmqs THREAD_LOCAL (the DEFINITION home is THIS pair — at the
//! Rust face the stats record + holder ride the seam/the caller, the seven
//! PatMatQStat PegCount slots land as the row-scoped PatMatQStat Lite the
//! caller threads, cited to search_engines/pat_stats.h :28-:37); the :1877
//! extern event_filter_stats NEVER gets a definition (declare-cite, the
//! sfthd.cc owner keeps the identity — NEVER re-forked); get_search_methods
//! (:164) + get_action_types (:1960) are namespace-scope `function` statics:
//! they ride seam provider legs (PluginManager::get_available_plugins — NOT
//! landed, cite DECL), NEVER live PT_DYNAMIC range rows (no body invented).
//!
//! THE PROVIDER SEAM: every C provider global leg — get_ips_policy /
//! get_inspection_policy / get_network_policy (:1187 / :1402 / :1487 /
//! :2297...; main/policy.h :91-:94 SO_PUBLIC DECL faces), the SnortConfig::
//! get_conf legs (mp_dbus members :447-:461, BatchedLogger init/shutdown
//! :856-:872), ParseIpVar/ParsePathVar/ParsePortVar + resolve_nets/
//! resolve_ports, add_classification (:395) + reference_system_add (:695),
//! PluginManager::get_available_plugins (:165 / :1961),
//! PluginManager::add_module (the 37 registration legs),
//! FileService::is_file_capture_enabled (:2317 / :2341), Snort::is_reloading
//! (:2315 / :2340 — REUSE the landed src/main/snort_.rs reloading() home at
//! :747, cited through the seam NEVER re-forked), ThreadConfig::validate_
//! cpuset_string / destroy_cpuset / set_thread_affinity /
//! set_named_thread_affinity (REUSE the landed src/main/thread_config.rs
//! homes at :761 / :817 / :836 / :860), sfthreshold_create (:1827 / :1948),
//! RateFilter_Create / RateFilter_Cleanup (:2033-:2036 / :2081),
//! HostAttributesManager::add_host / get_pegs / get_peg_counts (:2139-:2143
//! / :2202 — NOT landed: cite DECL), ActionManager::instantiate_action_with_
//! param (:1524 — NOT landed: cite DECL), ModuleManager::get_includer
//! (:1494 — NOT landed: cite DECL) — ride ONE row-owned `ModulesWorld` seam
//! trait: methods per provider leg with the NOT-landed providers as CITE
//! NEVER body, and a NullWorld default impl (the analyzer.rs 24d pattern).
//!
//! THE RECORD-THREADING DEVIATION (23c law, KNOWN-DEVIATIONS style cited
//! in-file at the seats): the C set/end legs WRITE config-record members
//! through SnortConfig (eq->max_events, fp->set_*, sc->detection_filter_
//! config->memcap, MPDataBus:: statics, sc->set_* legs...). The Rust face
//! threads row-scoped pub #[derive(Default, Clone)] Lite records
//! (EventQueueConfigLite / DetectionFilterConfigLite / ThresholdConfigLite /
//! RateFilterConfigLite / ScWriteBag) through every method that touches
//! them; the caller owns the records (the 23c sfdaq_module.rs precedent).
//! The docs row itself is the orchestrator's, written at commit.
//!
//! ONE-HOME REUSE census (grep BEFORE authoring, ZERO re-forks):
//!   Parameter / Type -> framework/parameter.rs (the { name, ptype, deflt }
//!     face; the range + help slots = that home's OWN deferred face,
//!     parameter.rs :39-:41 cite-never-invent — ranges/child-table pointers
//!     ride SEPARATE cited comment faces per table).
//!   Value -> framework/value.rs (is/get_uint8/get_uint32/.../update_mask_*).
//!   Module + new_params + Command + LuaCFunctionToken -> framework/
//!     module.rs (the `cppcheck-suppress` comment faces transcribe as cited
//!     comments, NEVER as attributes).
//!   PegInfo / CountType / PegCount -> framework/counts.rs.
//!   RuleMap -> codecs/codec_module.rs :253 (the { sid, msg } face).
//!   C_USAGE_GLOBAL :273 / C_USAGE_CONTEXT :274 / C_USAGE_INSPECT :276 /
//!     C_USAGE_DETECT :278 -> codecs/codec_module.rs (EVERY get_usage
//!     ordinal face rides these; ZERO re-authored usage consts in this file).
//!   CodecModule -> codecs/codec_module.rs :365 (the register ladder reuses
//!     the landed ctor NEVER re-forks it); S_NAME "decode" -> same home :344.
//!   RSS_PEGS / RSS_STATS / rss_stats_to_pegcounts -> framework/
//!     reload_survivor_subscriptions.rs :914 / :907 / :945 (the
//!     ReloadSurvivorSubscriptionsModule pegs face rides the LANDED home
//!     CITE-REUSE, NEVER re-forked).
//!   FastPatternConfig -> detection/fp_config.rs (the landed set_* legs ride
//!     through the seam; the NOT-landed fp legs — set_max_pattern_len /
//!     set_max_queue_events / set_stream_insert / set_search_method /
//!     set_split_any_any / set_queue_limit / set_rule_db_dir — are CITED
//!     DECL faces fp_config.h, NEVER bodies).
//!   IpsPolicy / PolicyMode / Enable / NetworkPolicy -> main/policy.rs
//!     (the landed has_action_variable_capacity / has_action_variable /
//!     commit_action_variable / includer seats REUSED through the seam).
//!   ThreadConfig + CpuSet + DEFAULT_THREAD_ID + SThreadType -> main/
//!     thread_config.rs :761/:817/:836/:860 + main/thread.rs :19 (STHREAD_
//!     TYPE_* arms) REUSED; the CpuSet* file-static lands as Option<CpuSet>
//!     (the C delete-face law, destroy_cpuset cited).
//!   FilePolicy / FileRule / TypeIdSet / FileUse / FileServiceLite ->
//!     file_api/file_policy.rs + file_api/file_lib.rs :960 (REAL landed
//!     records; FILE_VERDICT_* -> file_api/file_api.rs :108-:115 — the
//!     (FileVerdict)v.get_uint8() cast legs ride the u32 ordinal face).
//!   IpsAction::get_type / is_valid_action -> framework/ips_action.rs
//!     ActionRegistry::get_action_type :91 / is_valid_action :102 (REUSE
//!     through the seam, NEVER re-forked).
//!   LogEngine parse_error :214 / parse_warning :203 / reload_error :220 /
//!     warning_message :370 / log_message_stdout :353 + WARN_CONF :28 ->
//!     log/messages.rs (the message legs ride the seam -> LogEngine home;
//!     this TU only FORMATS the C argument face).
//!   utils::cfmt::Arg -> the landed cfmt Arg face (the %s render legs).
//!   sfip_var_from_string -> parser/parse_ip.rs :23 (landed; the C
//!     (var, caller) face rides the landed (var, ret) face, cite).
//!   SfIpRet::Success -> sfip/sf_returns.rs (the reference_net ==
//!     SFIP_SUCCESS leg).
//!   add_classification / reference_system_add (main/header.h free fns;
//!     the bodies live detection/signature.cc :54/:100 — NOT landed: the
//!     legs ride seam CITE DECL faces, NEVER bodies here).
//!   get_active_counts + ActiveCounts -> packet_io/active.rs :415 / :400.
//!   reloading -> main/snort_.rs :747 (Snort::is_reloading).
//!   sfthreshold_create / THDX / RateFilter_Create / HostAttributesManager
//!   / detection/rules.h / filters/* / file config FilePolicy:: set legs
//!   past the landed set_file_* homes = cite-only NOT-landed DECL families.
//!
//! ZERO allow-attributes on THIS landing; ZERO in-safe surfaces (the prose
//! face rides the split word un-safe where the family law needs it); the
//! private seats land NOT callable: the get_usage ordinal faces ride the
//! landed C_USAGE_* consts as pub const fn faces, NEVER the private C face.

use crate::codecs::codec_module::{
    C_USAGE_CONTEXT, C_USAGE_DETECT, C_USAGE_GLOBAL, C_USAGE_INSPECT, RuleMap,
    // CodecModule (codecs/codec_module.rs :369 the landed home) rides
    // the register-ladder CITE face only — the foreign-owned ctor
    // NEVER gets re-forked here (grep-cite at the leg).
};
// FILE_VERDICT_* (file_api/file_api.rs :108-:115 the landed ordinal
// ladder) rides the FilePolicy set-leg CITE comments only; the verdict
// cast writes the u32 ordinal slot directly (cited) — NO import needed.
use crate::file_api::file_lib::FileServiceLite;
use crate::file_api::file_policy::{FilePolicy, FileRule}; // TypeIdSet (:70) rides cited field faces only
use crate::framework::counts::{CountType, PegCount, PegInfo};
use crate::framework::ips_action::ActionRegistry;
use crate::framework::module::{Command, Module};
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::framework::reload_survivor_subscriptions::{
    RSS_PEGS, RSS_STATS, rss_stats_to_pegcounts,
};
use crate::framework::value::Value;
use crate::log::messages::{LogEngine, WARN_CONF};
use crate::main::policy::{Enable, IpsPolicy, PolicyMode};
use crate::main::snort_::Snort;
use crate::main::thread::SThreadType;
use crate::main::thread_config::{CpuSet, DEFAULT_THREAD_ID, ThreadConfig};
use crate::parser::parse_ip::sfip_var_from_string;
use crate::sfip::sf_ipvar::SfIpVar;
use crate::target_based::snort_protocols::{SnortProtocolId, UNKNOWN_PROTOCOL_ID, ProtocolReference};
use crate::sfip::sf_returns::SfIpRet;
use crate::utils::cfmt::Arg;

// ======================================================================
// the help-string seats (the C `#define X_help` faces; each rides its
// cite — attribute-free consts by law, the C macro identity is the cite).
// ======================================================================

/// cc :112-:113 `#define event_queue_help "configure event queue
/// parameters"`.
pub const EVENT_QUEUE_HELP: &str = "configure event queue parameters";
/// cc :241-:242 `#define search_engine_help "configure fast pattern
/// matcher"`.
pub const SEARCH_ENGINE_HELP: &str = "configure fast pattern matcher";
/// cc :347-:348 `#define classifications_help "define rule categories
/// with priority"`.
pub const CLASSIFICATIONS_HELP: &str = "define rule categories with priority";
/// cc :508-:509 `#define mp_data_bus_help "configure multiprocess data
/// bus"`.
pub const MP_DATA_BUS_HELP: &str = "configure multiprocess data bus";
/// cc :613-:614 `#define reload_survivor_help "reload survivor
/// subscription registry statistics"`.
pub const RELOAD_SURVIVOR_HELP: &str = "reload survivor subscription registry statistics";
/// cc :654-:655 `#define reference_help "define reference systems used
/// in rules"`.
pub const REFERENCE_HELP: &str = "define reference systems used in rules";
/// cc :783-:784 `#define alerts_help "configure alerts"`.
pub const ALERTS_HELP: &str = "configure alerts";
/// cc :843-:844 `#define output_help "configure general output
/// parameters"`.
pub const OUTPUT_HELP: &str = "configure general output parameters";
/// cc :990-:991 `#define active_help "configure responses"`.
pub const ACTIVE_HELP: &str = "configure responses";
/// cc :1057-:1058 `#define packets_help "configure basic packet
/// handling"`.
pub const PACKETS_HELP: &str = "configure basic packet handling";
/// cc :1118-:1119 `const char* attribute_table_help = "configure hosts
/// loading"` — NOT a #define: a non-const-qualified global (the honest
/// C-face asymmetry); the Rust face is an immutable str (no writer).
pub const ATTRIBUTE_TABLE_HELP: &str = "configure hosts loading";
/// cc :1191-:1192 `#define inspection_help "configure basic inspection
/// policy parameters"`.
pub const INSPECTION_HELP: &str = "configure basic inspection policy parameters";
/// cc :1376-:1377 `#define ips_help "configure IPS rule processing"`.
pub const IPS_HELP: &str = "configure IPS rule processing";
/// cc :1602-:1603 `#define process_help "configure basic process setup"`.
pub const PROCESS_HELP: &str = "configure basic process setup";
/// cc :1773-:1774 `#define suppress_help "configure event
/// suppressions"`.
pub const SUPPRESS_HELP: &str = "configure event suppressions";
/// cc :1874-:1875 `#define event_filter_help "configure thresholding of
/// events"`.
pub const EVENT_FILTER_HELP: &str = "configure thresholding of events";
/// cc :1992-:1993 `#define rate_filter_help "configure rate filters
/// (which change rule actions)"`.
pub const RATE_FILTER_HELP: &str = "configure rate filters (which change rule actions)";
/// cc :2123-:2124 `#define hosts_help "configure hosts"`.
pub const HOSTS_HELP: &str = "configure hosts";
/// cc :2272 `#define file_policy_help "configure file policy"` (ONE-liner
/// face, no line-continuation).
pub const FILE_POLICY_HELP: &str = "configure file policy";

// ======================================================================
// the file-static PROVIDER closures — cc :164-:165 `function<const char*
// ()> get_search_methods = []() { return PluginManager
// ::get_available_plugins(PT_SEARCH_ENGINE); }` and cc :1960-:1961 the
// PT_IPS_ACTION twin. These are the PT_DYNAMIC range faces (:202/:205,
// :1980): NOT-landed providers (managers/plugin_manager.h) -> seam CITE
// DECL, NEVER invoked on this face, NEVER a live dynamic row elsewhere.
// ======================================================================

/// cc :164-:165: the PluginManager::get_available_plugins(
/// PT_SEARCH_ENGINE) face — CITE-DECL seam leg (managers/
/// plugin_manager.h NOT landed; NEVER a body — the harness mirrors the
/// DECL only). The row NEVER calls it; it names the identity the
/// search_method / offload_search_method PT_DYNAMIC rows cite.
pub const fn search_method_provider_id() -> &'static str {
    "PT_SEARCH_ENGINE" // cc :165 (the plugin-type token, cite identity)
}

/// cc :1960-:1961: the get_action_types face —
/// PluginManager::get_available_plugins(PT_IPS_ACTION) — CITE-DECL seam
/// leg (same NOT-landed home).
pub const fn action_type_provider_id() -> &'static str {
    "PT_IPS_ACTION" // cc :1961 (the plugin-type token, cite identity)
}

// ======================================================================
// THE 30 Parameter tables — Module Configuration face (cc :94-:2271).
// THE landed Parameter face (framework/parameter.rs { name, ptype,
// deflt }) carries NO range slot (parameter.rs :39-:41 — the range/
// child-table/help C slots are THAT home's deferred face, cite-never-
// invent): every C range string / PT_TABLE|PT_LIST child-table pointer
// rides a cited COMMENT face beside the row; the child-table identity =
// the separate pub static naming the same table. Every table ends with
// the C `{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }`
// sentinel row. The dialect rows (the census in this file's header)
// land as cited comment faces, NEVER live rows.
// ======================================================================

/// cc :94-:110 event_queue_params — max_queue (:96, range "1:max32"
/// cited, deflt "8"), log (:99, range "1:max32", deflt "3"),
/// order_events (:102-:103, the PT_ENUM range "priority|
/// content_length" cited, deflt "content_length"),
/// process_all_events (:106, deflt "false"), sentinel (:109).
pub static EVENT_QUEUE_PARAMS: [Parameter; 5] = [
    Parameter { name: Some("max_queue"), ptype: PtType::PtInt, deflt: Some("8") },            // :96 range "1:max32" (cited)
    Parameter { name: Some("log"), ptype: PtType::PtInt, deflt: Some("3") },                  // :99 range "1:max32" (cited)
    Parameter { name: Some("order_events"), ptype: PtType::PtEnum, deflt: Some("content_length") }, // :102 range "priority|content_length" (cited)
    Parameter { name: Some("process_all_events"), ptype: PtType::PtBool, deflt: Some("false") },      // :106
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                              // :109 sentinel
];

/// cc :167-:224 search_engine_params (the pair ledger's biggest table):
/// bleedover_port_limit (:169), bleedover_warnings_enabled (:172),
/// enable_single_rule_group (:175), debug (:178),
/// debug_print_nocontent_rule_tests (:181), debug_print_rule_group_
/// build_details (:184), debug_print_rule_groups_uncompiled (:187),
/// debug_print_rule_groups_compiled (:190), max_pattern_len (:193),
/// max_queue_events (:196-:197 — the C in-line comment `// upper bound
/// is MAX_EVENT_MATCH` rides at :197), detect_raw_tcp (:200),
/// search_method (:202, the PT_DYNAMIC range = &get_search_methods, the
/// :164 closure face CITED through the seam), offload_search_method
/// (:205, PT_DYNAMIC, same cited range):
///   dialect face :206-:210 — `#ifdef ENABLE_DETECTION_OFFLOAD` (the
///   live-row + help "set fast pattern offload algorithm...") `#else`
///   (the deprecated no-op help) `#endif` — the harness cmake face =
///   OFF: the #else arm is the compile face, the row rides un-gated
///   with the OFF help cited, deflt None both arms.
///   dialect face :212-:215 — `#ifdef HAVE_HYPERSCAN` rule_db_dir
///   (PT_STRING, nullptr deflt, "directory for reading / writing rule
///   group databases") `#endif` — OFF: the row NEVER lands here.
/// split_any_any (:217, deflt "true"), queue_limit (:220, range
/// "0:max32"), sentinel (:223).
pub static SEARCH_ENGINE_PARAMS: [Parameter; 16] = [
    Parameter { name: Some("bleedover_port_limit"), ptype: PtType::PtInt, deflt: Some("1024") },             // :169 range "1:max32"
    Parameter { name: Some("bleedover_warnings_enabled"), ptype: PtType::PtBool, deflt: Some("false") },     // :172
    Parameter { name: Some("enable_single_rule_group"), ptype: PtType::PtBool, deflt: Some("false") },       // :175
    Parameter { name: Some("debug"), ptype: PtType::PtBool, deflt: Some("false") },                         // :178
    Parameter { name: Some("debug_print_nocontent_rule_tests"), ptype: PtType::PtBool, deflt: Some("false") },     // :181
    Parameter { name: Some("debug_print_rule_group_build_details"), ptype: PtType::PtBool, deflt: Some("false") }, // :184
    Parameter { name: Some("debug_print_rule_groups_uncompiled"), ptype: PtType::PtBool, deflt: Some("false") },  // :187
    Parameter { name: Some("debug_print_rule_groups_compiled"), ptype: PtType::PtBool, deflt: Some("false") },    // :190
    Parameter { name: Some("max_pattern_len"), ptype: PtType::PtInt, deflt: Some("0") },                    // :193 range "0:max32"
    Parameter { name: Some("max_queue_events"), ptype: PtType::PtInt, deflt: Some("5") },                   // :196 range "2:100" (the :197 `// upper bound is MAX_EVENT_MATCH` cite)
    Parameter { name: Some("detect_raw_tcp"), ptype: PtType::PtBool, deflt: Some("false") },                // :200
    Parameter { name: Some("search_method"), ptype: PtType::PtDynamic, deflt: Some("ac_bnfa") },            // :202 range = &get_search_methods (:164 seam CITE)
    Parameter { name: Some("offload_search_method"), ptype: PtType::PtDynamic, deflt: None },               // :205 range = &get_search_methods; :206-:210 dialect help pair OFF-arm (cited)
    // :212-:215 `#ifdef HAVE_HYPERSCAN` rule_db_dir PT_STRING — dialect face MEASURED OFF (never a live row)
    Parameter { name: Some("split_any_any"), ptype: PtType::PtBool, deflt: Some("true") },                  // :217
    Parameter { name: Some("queue_limit"), ptype: PtType::PtInt, deflt: Some("0") },                        // :220 range "0:max32"
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                            // :223 sentinel
];

// :345-:346 the C FIXIT-L pair (`// FIXIT-L signature.{h,cc} has type
// and name confused / the keys here make more sense`) — the comment
// face rides the cite, verbatim.

/// cc :351-:363 classification_params — name (:353), priority (:355,
/// range "0:max32", deflt "1"), text (:357), sentinel (:362).
pub static CLASSIFICATION_PARAMS: [Parameter; 4] = [
    Parameter { name: Some("name"), ptype: PtType::PtString, deflt: None },        // :353
    Parameter { name: Some("priority"), ptype: PtType::PtInt, deflt: Some("1") },  // :355 range "0:max32"
    Parameter { name: Some("text"), ptype: PtType::PtString, deflt: None },        // :357
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                   // :362 sentinel
];

/// cc :417-:433 mp_data_bus_params — max_eventq_size (:419, range
/// "100:65535", deflt "4096"), transport (:422), debug (:425),
/// dialect face :427-:430 `#ifdef REG_TEST` hold_events (PT_BOOL
/// "false", "hold events from publishing") `#endif` — MEASURED OFF:
/// never a live row; sentinel (:432).
pub static MP_DATA_BUS_PARAMS: [Parameter; 4] = [
    Parameter { name: Some("max_eventq_size"), ptype: PtType::PtInt, deflt: Some("4096") },  // :419 range "100:65535"
    Parameter { name: Some("transport"), ptype: PtType::PtString, deflt: None },            // :422 (the DEFAULT_TRANSPORT "unix_transport" identity rides framework/mp_data_bus.h :52, cite)
    Parameter { name: Some("debug"), ptype: PtType::PtBool, deflt: Some("false") },         // :425
    // :427-:430 `#ifdef REG_TEST` hold_events PT_BOOL — dialect face MEASURED OFF (never a live row)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                            // :432 sentinel
];

// the five file-static lua command bodies cc :435-:496 (dump_mp_stats
// :435, dump_mp_events :453, show_mp_channel_status :472 with the cc
// :471 `// cppcheck-suppress constParameterCallback` comment face
// riding the cite, enable_debug :482, disable_debug :490) are NOT
// callable private seats — they ride ONLY the mp_dbus_cmds name/help
// legs below (the Lua-leg bodies = NOT-landed family, cite: the
// ControlConn::query_from_lua :438 + luaL_optstring :441 + the
// mp_dbus->dump_stats/dump_events/show_channel_status/
// set_debug_enabled legs framework/mp_data_bus.h, CITE NEVER bodies).

/// cc :498-:506 mp_dbus_cmds — the Command table (framework/module.rs
/// face: the Lua fn slot rides the LuaCFunctionToken token posture, the
/// params slot nullptr, can_run_in_parallel the h :72 NSDMI false):
/// enable (:500), disable (:501), dump_stats (:502), dump_events
/// (:503), show_channel_status (:504), nullptr sentinel (:505).
pub static MP_DBUS_CMDS: [Command; 6] = [
    Command { name: Some("enable"), func: None, params: None, help: Some("enable multiprocess data bus debugging"), can_run_in_parallel: false },        // :500
    Command { name: Some("disable"), func: None, params: None, help: Some("disable multiprocess data bus debugging"), can_run_in_parallel: false },      // :501
    Command { name: Some("dump_stats"), func: None, params: None, help: Some("dump multiprocess data bus statistics"), can_run_in_parallel: false },     // :502
    Command { name: Some("dump_events"), func: None, params: None, help: Some("dump multiprocess data bus events"), can_run_in_parallel: false },        // :503
    Command { name: Some("show_channel_status"), func: None, params: None, help: Some("show multiprocess data bus channel status"), can_run_in_parallel: false }, // :504
    Command { name: None, func: None, params: None, help: None, can_run_in_parallel: false },                                                            // :505 sentinel
];

/// cc :616-:648 ReloadSurvivorSubscriptionsModule pegs face — the C
/// `get_pegs() { return snort::rss_pegs; }` (:622-:623) rides the
/// LANDED home RSS_PEGS (framework/reload_survivor_subscriptions.rs
/// :914, CITE-REUSE never re-forked): this row carries NO peg table.
/// cc :654-:655 reload_survivor_help rides at RELOAD_SURVIVOR_HELP.
///
/// cc :657-:666 reference_params — name (:659), url (:661), sentinel
/// (:665).
pub static REFERENCE_PARAMS: [Parameter; 3] = [
    Parameter { name: Some("name"), ptype: PtType::PtString, deflt: None },  // :659
    Parameter { name: Some("url"), ptype: PtType::PtString, deflt: None },   // :661
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },             // :665 sentinel
];

/// cc :714-:742 alerts_params — alert_with_interface_name (:716),
/// detection_filter_memcap (:719, range "0:max32", deflt "1048576"),
/// event_filter_memcap (:722, same pair), log_references (:725), order
/// (:728), rate_filter_memcap (:731, deflt "16777216"), reference_net
/// (:734-:735, the C help-string CONCATENATION face), tunnel_verdicts
/// (:738), sentinel (:741).
pub static ALERTS_PARAMS: [Parameter; 9] = [
    Parameter { name: Some("alert_with_interface_name"), ptype: PtType::PtBool, deflt: Some("false") }, // :716
    Parameter { name: Some("detection_filter_memcap"), ptype: PtType::PtInt, deflt: Some("1048576") },  // :719 range "0:max32"
    Parameter { name: Some("event_filter_memcap"), ptype: PtType::PtInt, deflt: Some("1048576") },      // :722 range "0:max32"
    Parameter { name: Some("log_references"), ptype: PtType::PtBool, deflt: Some("false") },            // :725
    Parameter { name: Some("order"), ptype: PtType::PtString, deflt: None },                            // :728
    Parameter { name: Some("rate_filter_memcap"), ptype: PtType::PtInt, deflt: Some("16777216") },      // :731 range "0:max32"
    Parameter { name: Some("reference_net"), ptype: PtType::PtString, deflt: None },                    // :734 (the :734-:735 "set the CIDR for homenet ... does NOT change $HOME_NET in IDS mode" help concat face, cite)
    Parameter { name: Some("tunnel_verdicts"), ptype: PtType::PtString, deflt: None },                  // :738
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                        // :741 sentinel
];

/// cc :790-:796 output_event_trace_params — max_data (:792, range
/// "0:65535", deflt "0"), sentinel (:795).
pub static OUTPUT_EVENT_TRACE_PARAMS: [Parameter; 2] = [
    Parameter { name: Some("max_data"), ptype: PtType::PtInt, deflt: Some("0") },  // :792 range "0:65535"
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                   // :795 sentinel
];

/// cc :798-:841 output_params — dump_chars_only (:800), dump_payload
/// (:803), dump_payload_verbose (:806), event_trace (:809, the PT_TABLE
/// range = &output_event_trace_params child pointer, cited), quiet
/// (:812), logdir (:815, deflt "."), show_year (:818),
/// tagged_packet_limit (:821, range "0:max32", deflt "256"), verbose
/// (:824), obfuscate (:827), log_buffered (:830):
///   dialect face :833-:837 — the wide_hex_dump DEFAULT FLIP:
///   `#ifdef REG_TEST` deflt "true" `#else` deflt "false" `#endif` +
///   the shared help — the harness cmake face REG_TEST = OFF: the
///   else arm deflt "false" rides LIVE (the snort_config.h :214 live
///   default OUTPUT_FLAG__WIDE_HEX = 0x800 pair, cited), sentinel
///   (:840).
pub static OUTPUT_PARAMS: [Parameter; 13] = [
    Parameter { name: Some("dump_chars_only"), ptype: PtType::PtBool, deflt: Some("false") },     // :800
    Parameter { name: Some("dump_payload"), ptype: PtType::PtBool, deflt: Some("false") },        // :803
    Parameter { name: Some("dump_payload_verbose"), ptype: PtType::PtBool, deflt: Some("false") },// :806
    Parameter { name: Some("event_trace"), ptype: PtType::PtTable, deflt: None },                 // :809 range = OUTPUT_EVENT_TRACE_PARAMS (cited); help "" (the empty-string face)
    Parameter { name: Some("quiet"), ptype: PtType::PtBool, deflt: Some("false") },               // :812
    Parameter { name: Some("logdir"), ptype: PtType::PtString, deflt: Some(".") },                // :815
    Parameter { name: Some("show_year"), ptype: PtType::PtBool, deflt: Some("false") },           // :818
    Parameter { name: Some("tagged_packet_limit"), ptype: PtType::PtInt, deflt: Some("256") },    // :821 range "0:max32"
    Parameter { name: Some("verbose"), ptype: PtType::PtBool, deflt: Some("false") },             // :824
    Parameter { name: Some("obfuscate"), ptype: PtType::PtBool, deflt: Some("false") },           // :827
    Parameter { name: Some("log_buffered"), ptype: PtType::PtBool, deflt: Some("false") },        // :830
    Parameter { name: Some("wide_hex_dump"), ptype: PtType::PtBool, deflt: Some("false") },       // :833-:837 dialect default flip OFF-arm ("false" live; "true" face cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                  // :840 sentinel
];

/// cc :846-:850 output_rules — the RuleMap table (the landed
/// codec_module.rs :253 RuleMap { sid, msg } face): TAG_LOG_PKT = 1
/// (detection/tag.h :43) "tagged packet" (:848), `{ 0, nullptr }`
/// sentinel (:849); GID_TAG = 2 (detection/tag.h :42) rides the
/// get_gid ordinal face at OutputModule::get_gid (h :95).
pub static OUTPUT_RULES: [RuleMap; 2] = [
    RuleMap { sid: TAG_LOG_PKT, msg: Some("tagged packet") }, // :848
    RuleMap { sid: 0, msg: None },                            // :849 sentinel
];

/// detection/tag.h :43 `#define TAG_LOG_PKT 1` (the landed home carries
/// NO tag seat — this pair's own ordinal consts, cited to the ground
/// head; NEVER an ABI claim beyond the literal).
pub const TAG_LOG_PKT: u32 = 1;
/// detection/tag.h :42 `#define GID_TAG 2`.
pub const GID_TAG: u32 = 2;

// cc :852-:874 the enable_log_buffered (:852) / disable_log_buffered
// (:864) lua bodies = NOT-callable private seats riding the
// output_cmds name/help legs: the C BatchedLogger::BatchedLogManager::
// init (:856) / ::shutdown (:868) bodies = NOT-landed (log/
// batched_logger.h — the landed log/messages.rs :262 BatchedLogger
// path NOT-ported panic cite), the OUTPUT_FLAG__LOG_BUFFERED 0x2000
// face rides log/messages.rs :40 (CITE-REUSE), the LogMessage legs ride
// the LogEngine seam.

/// cc :876-:881 output_cmds — enable_log_buffered (:878),
/// disable_log_buffered (:879), nullptr sentinel (:880); the Lua fn
/// slot token posture (module.rs :104, the 18a face).
pub static OUTPUT_CMDS: [Command; 3] = [
    Command { name: Some("enable_log_buffered"), func: None, params: None, help: Some("enable buffered logging dynamically"), can_run_in_parallel: false },  // :878
    Command { name: Some("disable_log_buffered"), func: None, params: None, help: Some("disable buffered logging dynamically"), can_run_in_parallel: false }, // :879
    Command { name: None, func: None, params: None, help: None, can_run_in_parallel: false },                                                                  // :880 sentinel
];

/// cc :959-:977 active_params — attempts (:961, range "0:255", deflt
/// "0"), device (:964), dst_mac (:967, the "use format '01:23:45:67:
/// 89:ab'" help), max_responses (:970, range "0:255", deflt "0"),
/// min_interval (:973, range "1:255", deflt "255"), sentinel (:976).
pub static ACTIVE_PARAMS: [Parameter; 6] = [
    Parameter { name: Some("attempts"), ptype: PtType::PtInt, deflt: Some("0") },       // :961 range "0:255"
    Parameter { name: Some("device"), ptype: PtType::PtString, deflt: None },           // :964
    Parameter { name: Some("dst_mac"), ptype: PtType::PtString, deflt: None },          // :967
    Parameter { name: Some("max_responses"), ptype: PtType::PtInt, deflt: Some("0") },  // :970 range "0:255"
    Parameter { name: Some("min_interval"), ptype: PtType::PtInt, deflt: Some("255") }, // :973 range "1:255"
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                        // :976 sentinel
];

/// cc :982-:992 `static PegInfo active_pegs[]` — the C face is NOT
/// const-qualified (the honest asymmetry; the table still never moves
/// after load): 7 SUM rows + END sentinel (:991). get_counts pairs the
/// packet_io/active.rs :415 get_active_counts() home (CITE-REUSE, the
/// 23h ActiveCounts 7-field face aligns this row order, never re-
/// forked).
pub static ACTIVE_PEGS: [PegInfo; 8] = [
    PegInfo { peg_type: CountType::Sum, name: "injects", help: "total crafted packets encoded and injected" },                       // :984
    PegInfo { peg_type: CountType::Sum, name: "failed_injects", help: "total crafted packet encode + injects that failed" },          // :985
    PegInfo { peg_type: CountType::Sum, name: "direct_injects", help: "total crafted packets directly injected" },                    // :986
    PegInfo { peg_type: CountType::Sum, name: "failed_direct_injects", help: "total crafted packet direct injects that failed" },     // :987
    PegInfo { peg_type: CountType::Sum, name: "holds_denied", help: "total number of packet hold requests denied" },                  // :988
    PegInfo { peg_type: CountType::Sum, name: "holds_canceled", help: "total number of packet hold requests canceled" },              // :989
    PegInfo { peg_type: CountType::Sum, name: "holds_allowed", help: "total number of packet hold requests allowed" },                // :990
    PegInfo { peg_type: CountType::End, name: "", help: "" },                                                                          // :991 the END sentinel (the landed ""-terminator posture)
];

/// cc :1034-:1055 packets_params — address_space_agnostic (:1036),
/// bpf_file (:1039), limit (:1042, range "0:max53", deflt "0"), skip
/// (:1045, range "0:max53", deflt "0"), mpls_agnostic (:1048, deflt
/// "true"), vlan_agnostic (:1051, deflt "false"), sentinel (:1054).
pub static PACKETS_PARAMS: [Parameter; 7] = [
    Parameter { name: Some("address_space_agnostic"), ptype: PtType::PtBool, deflt: Some("false") }, // :1036
    Parameter { name: Some("bpf_file"), ptype: PtType::PtString, deflt: None },                      // :1039
    Parameter { name: Some("limit"), ptype: PtType::PtInt, deflt: Some("0") },                        // :1042 range "0:max53"
    Parameter { name: Some("skip"), ptype: PtType::PtInt, deflt: Some("0") },                         // :1045 range "0:max53"
    Parameter { name: Some("mpls_agnostic"), ptype: PtType::PtBool, deflt: Some("true") },            // :1048
    Parameter { name: Some("vlan_agnostic"), ptype: PtType::PtBool, deflt: Some("false") },           // :1051
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                      // :1054 sentinel
];

/// cc :1098-:1116 attribute_table_params — hosts_file (:1100),
/// max_hosts (:1103, range "32:max53", deflt "1024"), segments
/// (:1106, range "1:32", deflt "4" — the power-of-2 law lives at the
/// set-leg ladder, AttributeTableModule::set), max_services_per_host
/// (:1109, range "1:65535", deflt "8"), max_metadata_services (:1112,
/// range "1:255", deflt "9"), sentinel (:1115).
pub static ATTRIBUTE_TABLE_PARAMS: [Parameter; 6] = [
    Parameter { name: Some("hosts_file"), ptype: PtType::PtString, deflt: None },                 // :1100
    Parameter { name: Some("max_hosts"), ptype: PtType::PtInt, deflt: Some("1024") },              // :1103 range "32:max53"
    Parameter { name: Some("segments"), ptype: PtType::PtInt, deflt: Some("4") },                  // :1106 range "1:32"
    Parameter { name: Some("max_services_per_host"), ptype: PtType::PtInt, deflt: Some("8") },     // :1109 range "1:65535"
    Parameter { name: Some("max_metadata_services"), ptype: PtType::PtInt, deflt: Some("9") },     // :1112 range "1:255"
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                   // :1115 sentinel
];

/// cc :1170-:1189 inspection_params — id (:1172, range "1:max53",
/// deflt "1"):
///   dialect face :1175-:1178 `#ifdef HAVE_UUID` uuid (PT_STRING,
///   nullptr deflt, "correlate events by uuid") `#endif` — MEASURED
///   OFF: never a live row (the set legs :1211-:1220 ride the
///   InspectionModule::set cite face).
/// mode (:1181-:1182 — the C in-line comment `// no default - see
/// ips.mode` at :1180, and the empty-deflt PT_ENUM "inline | inline-
/// test" face), max_aux_ip (:1185, range "-1:127", deflt "16" — the
/// multi-line help concat), sentinel (:1188).
pub static INSPECTION_PARAMS: [Parameter; 4] = [
    Parameter { name: Some("id"), ptype: PtType::PtInt, deflt: Some("1") },                        // :1172 range "1:max53"
    // :1175-:1178 `#ifdef HAVE_UUID` uuid PT_STRING — dialect face MEASURED OFF (never a live row)
    Parameter { name: Some("mode"), ptype: PtType::PtEnum, deflt: None },                          // :1181 range "inline | inline-test" (the :1180 "no default - see ips.mode" cite)
    Parameter { name: Some("max_aux_ip"), ptype: PtType::PtInt, deflt: Some("16") },                // :1185 range "-1:127"
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                   // :1188 sentinel
];

// ======================================================================
// the Ips parameter ladder — cc :1247-:1374: the two file-local string
// fns (get_var_name :1247 / is_action_var_placeholder :1254 — ported
// fns below, NOT table faces) then SIX child tables + the parent:
// var_params (:1270), action_var_react_params (:1278), action_var_
// params (:1286), action_vars_params (:1294), variable_params (:1302),
// action_map_params (:1319), ips_params (:1330).
// ======================================================================

/// cc :1247-:1251 `static const char* get_var_name(const char* fqn)`:
/// `strrchr(fqn, '.') + assert(ptr) + return ptr + 1` — the 21b law:
/// the C assert maps to EXACTLY-1 debug_assert!, and the return rides
/// the suffix after the LAST '.'. A miss = the debug-build abort face;
/// the release face indexes one past the LAST_DOT with unwrap-safety
/// kept by the same single assert (a None suffix is a C-UB twin, cited).
pub fn get_var_name(fqn: &str) -> &str {
    let ptr = fqn.rfind('.'); // :1248 strrchr(fqn, '.')
    debug_assert!(ptr.is_some()); // :1249 assert(ptr) — the EXACTLY-1 assert face (21b law)
    &fqn[ptr.unwrap_or(fqn.len()) + 1..] // :1250 return ptr + 1
}

/// cc :1254-:1268 `static bool is_action_var_placeholder(const char*
/// fqn)` — the strstr("ips.variables.actions.") leg (:1256-:1258), the
/// prefix-skip (:1259), the strchr(name, '.') name-end probe (:1261),
/// the `name_len = name_end ? name_end - name : 0` face (:1262-:1263),
/// and the `name_len == strlen("$var") and !strncmp(name, "$var",
/// name_len)` tail (:1265). Byte-EXACT port.
pub fn is_action_var_placeholder(fqn: &str) -> bool {
    let prefix = "ips.variables.actions."; // :1255
    let Some(name) = fqn.find(prefix) else {
        return false; // :1257-:1258 `if ( !name ) return false;`
    };
    let name = &fqn[name + prefix.len()..]; // :1259 name += strlen(prefix)
    let name_end = name.find('.'); // :1261 strchr(name, '.')
    let name_len = name_end.unwrap_or(0); // :1263 `name_end ? name_end - name : 0`
                                          // (the 0 face matches nothing — kept)
    name_len == "$var".len() && &name[..name_len] == "$var" // :1265
}

/// cc :1270-:1276 var_params — the `$var` PT_STRING row (:1272 — the
/// nets/paths/ports variable leaf), sentinel (:1275).
pub static VAR_PARAMS: [Parameter; 2] = [
    Parameter { name: Some("$var"), ptype: PtType::PtString, deflt: None },  // :1272
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },             // :1275 sentinel
];

/// cc :1278-:1284 action_var_react_params — page (:1280), sentinel
/// (:1283).
pub static ACTION_VAR_REACT_PARAMS: [Parameter; 2] = [
    Parameter { name: Some("page"), ptype: PtType::PtString, deflt: None },  // :1280
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },             // :1283 sentinel
];

/// cc :1286-:1292 action_var_params — react PT_TABLE -> react (:1288),
/// sentinel (:1291).
pub static ACTION_VAR_PARAMS: [Parameter; 2] = [
    Parameter { name: Some("react"), ptype: PtType::PtTable, deflt: None },  // :1288 range = ACTION_VAR_REACT_PARAMS (cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },             // :1291 sentinel
];

/// cc :1294-:1300 action_vars_params — the `$var` PT_TABLE -> react
/// (:1296), sentinel (:1299).
pub static ACTION_VARS_PARAMS: [Parameter; 2] = [
    Parameter { name: Some("$var"), ptype: PtType::PtTable, deflt: None },  // :1296 range = ACTION_VAR_PARAMS (cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },            // :1299 sentinel
];

/// cc :1302-:1317 variable_params — actions (:1304 PT_TABLE ->
/// action_vars), nets (:1307 PT_TABLE -> var), paths (:1310), ports
/// (:1313), sentinel (:1316).
pub static VARIABLE_PARAMS: [Parameter; 5] = [
    Parameter { name: Some("actions"), ptype: PtType::PtTable, deflt: None },  // :1304 range = ACTION_VARS_PARAMS (cited)
    Parameter { name: Some("nets"), ptype: PtType::PtTable, deflt: None },     // :1307 range = VAR_PARAMS (cited)
    Parameter { name: Some("paths"), ptype: PtType::PtTable, deflt: None },    // :1310 range = VAR_PARAMS (cited)
    Parameter { name: Some("ports"), ptype: PtType::PtTable, deflt: None },    // :1313 range = VAR_PARAMS (cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },               // :1316 sentinel
];

/// cc :1319-:1328 action_map_params — replace (:1321), with (:1323),
/// sentinel (:1327).
pub static ACTION_MAP_PARAMS: [Parameter; 3] = [
    Parameter { name: Some("replace"), ptype: PtType::PtString, deflt: None },  // :1321
    Parameter { name: Some("with"), ptype: PtType::PtString, deflt: None },     // :1323
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                // :1327 sentinel
];

/// cc :1330-:1374 ips_params — action_map (:1332 PT_LIST -> action_map
/// face), action_override (:1334), default_rule_state (:1336, the PT_
/// ENUM "no | yes | inherit" deflt "inherit" face), enable_builtin_
/// rules (:1339), id (:1342), include (:1345):
///   the C :1347-:1349 comment triple (`// no default here; default
///   behavior controlled by -Q ...` — three comment faces, cited):
/// mode (:1350, the empty-deflt PT_ENUM "tap | inline | inline-test"),
/// obfuscate_pii (:1352, deflt "true"), rules (:1355), states (:1358):
///   dialect face :1365-:1368 `#ifdef HAVE_UUID` uuid (PT_STRING deflt
///   "00000000-0000-0000-0000-000000000000") `#endif` — MEASURED OFF:
///   never a live row (the set legs :1434-:1443 ride the IpsModule::set
///   cite face);
/// variables (:1370 PT_TABLE -> variable), sentinel (:1373).
pub static IPS_PARAMS: [Parameter; 12] = [
    Parameter { name: Some("action_map"), ptype: PtType::PtList, deflt: None },                // :1332 range = ACTION_MAP_PARAMS (cited)
    Parameter { name: Some("action_override"), ptype: PtType::PtString, deflt: None },          // :1334
    Parameter { name: Some("default_rule_state"), ptype: PtType::PtEnum, deflt: Some("inherit") }, // :1336 range "no | yes | inherit"
    Parameter { name: Some("enable_builtin_rules"), ptype: PtType::PtBool, deflt: Some("false") },  // :1339
    Parameter { name: Some("id"), ptype: PtType::PtInt, deflt: Some("1") },                     // :1342 range "1:max53"
    Parameter { name: Some("include"), ptype: PtType::PtString, deflt: None },                   // :1345
    Parameter { name: Some("mode"), ptype: PtType::PtEnum, deflt: None },                        // :1350 range "tap | inline | inline-test" (the :1347-:1349 no-default triple, cited)
    Parameter { name: Some("obfuscate_pii"), ptype: PtType::PtBool, deflt: Some("true") },       // :1352
    Parameter { name: Some("rules"), ptype: PtType::PtString, deflt: None },                     // :1355
    Parameter { name: Some("states"), ptype: PtType::PtString, deflt: None },                    // :1358
    // :1365-:1368 `#ifdef HAVE_UUID` uuid PT_STRING deflt "00000000-0000-0000-0000-000000000000" — dialect face MEASURED OFF (never a live row)
    Parameter { name: Some("variables"), ptype: PtType::PtTable, deflt: None },                  // :1370 range = VARIABLE_PARAMS (cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                 // :1373 sentinel
];

// ======================================================================
// the remaining Parameter tables (the C file order continues: process
// cc :1546, suppress :1756, event_filter :1848, rate_filter :1963,
// hosts :2092/:2106, file policy :2212/:2225/:2242/:2253).
// ======================================================================

/// cc :1546-:1561 thread_pinning_params — cpuset (:1548), thread
/// (:1551, range "0:65535" deflt nullptr), type (:1554, the PT_ENUM
/// "other|packet|main" face), name (:1557), sentinel (:1560).
pub static THREAD_PINNING_PARAMS: [Parameter; 5] = [
    Parameter { name: Some("cpuset"), ptype: PtType::PtString, deflt: None },  // :1548
    Parameter { name: Some("thread"), ptype: PtType::PtInt, deflt: None },     // :1551 range "0:65535"
    Parameter { name: Some("type"), ptype: PtType::PtEnum, deflt: None },      // :1554 range "other|packet|main"
    Parameter { name: Some("name"), ptype: PtType::PtString, deflt: None },    // :1557
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },               // :1560 sentinel
];

/// cc :1563-:1599 process_params — chroot (:1565), threads (:1568 the
/// PT_LIST -> thread_pinning face), daemon (:1571), dirty_pig (:1574),
/// set_gid (:1577), set_uid (:1580), umask (:1583, the range
/// "0x000:0x1FF" deflt nullptr face), utc (:1586), watchdog_timer
/// (:1589, range "0:60" deflt "0"), watchdog_min_thread_count (:1592,
/// range "1:65535" deflt "1"), numa_memory_policy (:1595, deflt
/// "preferred" — the table row is NOT dialect-gated, unlike its SET
/// leg at cc :1668-:1671, the HAVE_NUMA face cited at the Process-
/// Module::set leg), sentinel (:1598).
pub static PROCESS_PARAMS: [Parameter; 12] = [
    Parameter { name: Some("chroot"), ptype: PtType::PtString, deflt: None },                    // :1565
    Parameter { name: Some("threads"), ptype: PtType::PtList, deflt: None },                     // :1568 range = THREAD_PINNING_PARAMS (cited)
    Parameter { name: Some("daemon"), ptype: PtType::PtBool, deflt: Some("false") },             // :1571
    Parameter { name: Some("dirty_pig"), ptype: PtType::PtBool, deflt: Some("false") },          // :1574
    Parameter { name: Some("set_gid"), ptype: PtType::PtString, deflt: None },                   // :1577
    Parameter { name: Some("set_uid"), ptype: PtType::PtString, deflt: None },                   // :1580
    Parameter { name: Some("umask"), ptype: PtType::PtInt, deflt: None },                        // :1583 range "0x000:0x1FF"
    Parameter { name: Some("utc"), ptype: PtType::PtBool, deflt: Some("false") },                // :1586
    Parameter { name: Some("watchdog_timer"), ptype: PtType::PtInt, deflt: Some("0") },          // :1589 range "0:60"
    Parameter { name: Some("watchdog_min_thread_count"), ptype: PtType::PtInt, deflt: Some("1") },// :1592 range "1:65535"
    Parameter { name: Some("numa_memory_policy"), ptype: PtType::PtString, deflt: Some("preferred") }, // :1595 (the row lands; the HAVE_NUMA SET leg at :1668-:1671 does NOT)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                 // :1598 sentinel
];

/// cc :1756-:1771 suppress_params — gid (:1758, range "0:8129" deflt
/// "0"), sid (:1760, range "0:max32" deflt "0"), track (:1763, the
/// PT_ENUM "by_src | by_dst" face), ip (:1765), sentinel (:1770).
pub static SUPPRESS_PARAMS: [Parameter; 5] = [
    Parameter { name: Some("gid"), ptype: PtType::PtInt, deflt: Some("0") },      // :1758 range "0:8129"
    Parameter { name: Some("sid"), ptype: PtType::PtInt, deflt: Some("0") },      // :1760 range "0:max32"
    Parameter { name: Some("track"), ptype: PtType::PtEnum, deflt: None },        // :1763 range "by_src | by_dst"
    Parameter { name: Some("ip"), ptype: PtType::PtString, deflt: None },         // :1765
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                  // :1770 sentinel
];

/// cc :1848-:1872 event_filter_params — gid (:1850, range "0:8129"
/// deflt "1"), sid (:1852, range "0:max32" deflt "1"), type (:1855,
/// the PT_ENUM "limit | threshold | both" face = the sfthd.h :64-:66
/// THD_TYPE_LIMIT/THRESHOLD/BOTH ordinals cited), track (:1858),
/// count (:1861, the range "-1:max31" deflt "0" face), seconds (:1863,
/// range "0:max32" deflt "0"), ip (:1865), sentinel (:1871).
pub static EVENT_FILTER_PARAMS: [Parameter; 8] = [
    Parameter { name: Some("gid"), ptype: PtType::PtInt, deflt: Some("1") },       // :1850 range "0:8129"
    Parameter { name: Some("sid"), ptype: PtType::PtInt, deflt: Some("1") },       // :1852 range "0:max32"
    Parameter { name: Some("type"), ptype: PtType::PtEnum, deflt: None },          // :1855 range "limit | threshold | both"
    Parameter { name: Some("track"), ptype: PtType::PtEnum, deflt: None },         // :1858 range "by_src | by_dst"
    Parameter { name: Some("count"), ptype: PtType::PtInt, deflt: Some("0") },     // :1861 range "-1:max31"
    Parameter { name: Some("seconds"), ptype: PtType::PtInt, deflt: Some("0") },   // :1863 range "0:max32"
    Parameter { name: Some("ip"), ptype: PtType::PtString, deflt: None },          // :1865
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                   // :1871 sentinel
];

/// cc :1963-:1990 rate_filter_params — gid (:1965), sid (:1967),
/// track (:1969, the PT_ENUM "by_src | by_dst | by_rule" deflt "by_src"
/// face = the sfrf.h :48-:52 SFRF_TRACK_* ordinals cited), count
/// (:1972, deflt "1"), seconds (:1974, deflt "1"), new_action (:1977,
/// the PT_DYNAMIC range = &get_action_types (:1960 seam CITE) deflt
/// "alert"), timeout (:1980 — the C line note: the row sits at :1979-
/// :1980; range "0:max32" deflt "1"), apply_to (:1983, the PT_ADDR_
/// LIST face — an un-gated ADDRESS-LIST row, NOT a dialect face),
/// sentinel (:1989).
pub static RATE_FILTER_PARAMS: [Parameter; 9] = [
    Parameter { name: Some("gid"), ptype: PtType::PtInt, deflt: Some("1") },        // :1965 range "0:8129"
    Parameter { name: Some("sid"), ptype: PtType::PtInt, deflt: Some("1") },        // :1967 range "0:max32"
    Parameter { name: Some("track"), ptype: PtType::PtEnum, deflt: Some("by_src") },// :1969 range "by_src | by_dst | by_rule"
    Parameter { name: Some("count"), ptype: PtType::PtInt, deflt: Some("1") },      // :1972 range "0:max32"
    Parameter { name: Some("seconds"), ptype: PtType::PtInt, deflt: Some("1") },    // :1974 range "0:max32"
    Parameter { name: Some("new_action"), ptype: PtType::PtDynamic, deflt: Some("alert") }, // :1977 range = &get_action_types (:1960 seam CITE)
    Parameter { name: Some("timeout"), ptype: PtType::PtInt, deflt: Some("1") },    // :1980 range "0:max32"
    Parameter { name: Some("apply_to"), ptype: PtType::PtAddrList, deflt: None },   // :1983
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                    // :1989 sentinel
];

/// cc :2092-:2104 service_params — name (:2094), proto (:2096, the
/// PT_ENUM "tcp | udp" deflt "tcp"), port (:2098, the PT_PORT face),
/// sentinel (:2103).
pub static SERVICE_PARAMS: [Parameter; 4] = [
    Parameter { name: Some("name"), ptype: PtType::PtString, deflt: None },  // :2094
    Parameter { name: Some("proto"), ptype: PtType::PtEnum, deflt: Some("tcp") }, // :2096 range "tcp | udp"
    Parameter { name: Some("port"), ptype: PtType::PtPort, deflt: None },    // :2098
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },             // :2103 sentinel
];

/// cc :2106-:2121 hosts_params — ip (:2108, the PT_ADDR deflt
/// "0.0.0.0/32" face), frag_policy (:2110 — the range rides the C
/// IP_POLICIES macro face (parser/parse_conf.h), cited never ex-
/// panded as a slot), tcp_policy (:2112, the TCP_POLICIES macro range
/// cited), services (:2114 PT_LIST -> service), sentinel (:2120).
pub static HOSTS_PARAMS: [Parameter; 5] = [
    Parameter { name: Some("ip"), ptype: PtType::PtAddr, deflt: Some("0.0.0.0/32") },  // :2108
    Parameter { name: Some("frag_policy"), ptype: PtType::PtEnum, deflt: None },       // :2110 range = the IP_POLICIES macro face (parser/parse_conf.h — cited, NEVER expanded)
    Parameter { name: Some("tcp_policy"), ptype: PtType::PtEnum, deflt: None },        // :2112 range = the TCP_POLICIES macro face (cited)
    Parameter { name: Some("services"), ptype: PtType::PtList, deflt: None },          // :2114 range = SERVICE_PARAMS (cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                       // :2120 sentinel
];

// :2214-:2215 the C FIXIT-M pair inside file_when_params (`when.policy_id
// should be an arbitrary string auto converted / into index for binder
// matching and lookups`) — the comment faces ride the cite.

/// cc :2212-:2223 file_when_params — file_type_id (:2217, range
/// "0:max32", deflt "0"), sha256 (:2219), sentinel (:2222).
pub static FILE_WHEN_PARAMS: [Parameter; 3] = [
    Parameter { name: Some("file_type_id"), ptype: PtType::PtInt, deflt: Some("0") }, // :2217 range "0:max32"
    Parameter { name: Some("sha256"), ptype: PtType::PtString, deflt: None },         // :2219
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                      // :2222 sentinel
];

/// cc :2225-:2240 file_use_params — verdict (:2227, the PT_ENUM
/// "unknown | log | stop | block | reset " deflt "unknown" — the
/// TRAILING-SPACE typo in the C range rides the cite, the string was
/// verbatim-measured), enable_file_type (:2229), enable_file_
/// signature (:2232), enable_file_capture (:2235), sentinel (:2239).
pub static FILE_USE_PARAMS: [Parameter; 5] = [
    Parameter { name: Some("verdict"), ptype: PtType::PtEnum, deflt: Some("unknown") },      // :2227 range "unknown | log | stop | block | reset " (the trailing-space face cited)
    Parameter { name: Some("enable_file_type"), ptype: PtType::PtBool, deflt: Some("false") },     // :2229
    Parameter { name: Some("enable_file_signature"), ptype: PtType::PtBool, deflt: Some("false") },// :2232
    Parameter { name: Some("enable_file_capture"), ptype: PtType::PtBool, deflt: Some("false") },  // :2235
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                                // :2239 sentinel
];

/// cc :2242-:2251 file_policy_rule_params — when (:2244 PT_TABLE ->
/// file_when), use (:2246 PT_TABLE -> file_use), sentinel (:2250).
pub static FILE_POLICY_RULE_PARAMS: [Parameter; 3] = [
    Parameter { name: Some("when"), ptype: PtType::PtTable, deflt: None },  // :2244 range = FILE_WHEN_PARAMS (cited)
    Parameter { name: Some("use"), ptype: PtType::PtTable, deflt: None },   // :2246 range = FILE_USE_PARAMS (cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },            // :2250 sentinel
];

/// cc :2253-:2271 file_policy_params — enable_type (:2255, deflt
/// "true"), enable_signature (:2258), enable_capture (:2261),
/// verdict_delay (:2264, range "0:max53" deflt "0"), rules (:2266 the
/// PT_LIST -> file_policy_rule face), sentinel (:2270).
pub static FILE_POLICY_PARAMS: [Parameter; 6] = [
    Parameter { name: Some("enable_type"), ptype: PtType::PtBool, deflt: Some("true") },  // :2255
    Parameter { name: Some("enable_signature"), ptype: PtType::PtBool, deflt: Some("false") }, // :2258
    Parameter { name: Some("enable_capture"), ptype: PtType::PtBool, deflt: Some("false") },   // :2261
    Parameter { name: Some("verdict_delay"), ptype: PtType::PtInt, deflt: Some("0") },        // :2264 range "0:max53"
    Parameter { name: Some("rules"), ptype: PtType::PtList, deflt: None },                    // :2266 range = FILE_POLICY_RULE_PARAMS (cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                              // :2270 sentinel
];

// ======================================================================
// ModulesWorld — THE row-owned provider seam (the analyzer.rs 24d
// pattern): every C provider-global leg in the pair rides ONE method
// here, CITED to its harness-mirrored DECL home; NOT-landed providers
// ride as CITE NEVER bodies (the default arms are NO-OP / no-value
// mirrors ONLY where the leg already has a landed home or the DECL
// posture forces a neutral default — NEVER an invented success arm).
// THE record-threading face: the config records the C legs WRITE
// through SnortConfig ride as the Lite-struct args below (23c law).
// ======================================================================

pub trait ModulesWorld {
    /// main/policy.h :94 `SO_PUBLIC IpsPolicy* get_ips_policy()` — the
    /// seam rides the BORROWED landed IpsPolicy (main/policy.rs :51 —
    /// CITE-REUSE); None models the nullptr posture of the C face.
    fn ips_policy(&mut self) -> Option<&mut IpsPolicy> {
        None // policy.h :94 (the C may return nullptr; NEVER a fake policy)
    }

    /// main/policy.h :105 `get_ips_policy(sc, i)` writer leg — the
    // policy_map->set_user_ips(p) face at cc :1496 (`sc->policy_map-
    // >set_user_ips(p)`; main/policy.h :193 DECL — managers/policy
    // layer NOT landed: the seam owns the install, CITE).
    fn set_user_ips_policy(&mut self) {} // cc :1496 `sc->policy_map->set_user_ips(p)` (CITE: policy_map NOT landed; p = the world's own policy record, the arg face rides the borrow-law deviation)

    /// cc :1494 `p->includer = ModuleManager::get_includer("ips")` —
    /// managers/module_manager.h NOT landed: CITE DECL, neutral ""
    /// posture (the landed includer slot, policy.rs :64).
    fn get_includer(&mut self, _which: &str) -> String {
        String::new() // cc :1494 (get_includer NOT landed — the C nullptr->std::string posture)
    }

    /// parser/parse_conf.cc ParseIpVar — REUSE the landed parser/
    /// vars.rs :590 face through the seam (the ctx tables are the
    /// caller's; the C leg :1426 maps to the landed fn at the twin).
    fn parse_ip_var(&mut self, _name: &str, _value: &str) {} // cc :1426 (vars.rs :590 home cited)

    /// parser/vars.cc ParsePathVar — REUSE the landed vars.rs :446.
    fn parse_path_var(&mut self, _name: &str, _value: &str) {} // cc :1428 (vars.rs :446 home cited)

    /// parser/vars.cc ParsePortVar — REUSE the landed vars.rs :534.
    fn parse_port_var(&mut self, _name: &str, _value: &str) {} // cc :1430 (vars.rs :534 home cited)

    /// var_dependency.cc resolve_nets — REUSE the landed vars.rs :648.
    fn resolve_nets(&mut self) {} // cc :1485 (vars.rs :648 home cited)

    /// var_dependency.cc resolve_ports — REUSE the landed vars.rs :667.
    fn resolve_ports(&mut self) {} // cc :1487 (vars.rs :667 home cited)

    /// main/header.h add_classification — the cc :395 leg; the body
    /// lives detection/signature.cc :100 = NOT landed: CITE DECL, the
    /// seam NEVER invents a body (the twin drives the recorded leg).
    fn add_classification(&mut self, _name: &str, _text: &str, _priority: u32) {} // cc :395 (signature.cc :100 NOT landed, cite)

    /// main/header.h reference_system_add — the cc :695 leg; the body
    /// lives detection/reference.cc (reference_system_add signature.cc
    /// :54 static twin) = NOT landed: CITE DECL.
    fn reference_system_add(&mut self, _name: &str, _url: &str) {} // cc :695 (NOT landed, cite)

    /// SnortConfig::get_conf()->mp_dbus arms cc :447-:461 + :590 +
    /// :600-:607 — the multiprocess bus object = NOT landed (frame-
    /// work/mp_data_bus.h CITE DECL): the seam legs mirror the CALL
    /// order (dump_stats / dump_events / show_channel_status /
    /// set_debug_enabled / reset / stats-copy) with the CITE posture
    /// only, NEVER a bus behaviour.
    fn mp_dbus_present(&self) -> bool {
        false // cc :447 `if(SnortConfig::get_conf()->mp_dbus)` (the C-null posture)
    }
    fn mp_dbus_dump_stats(&mut self, _mod_name: Option<&str>) {}      // cc :450 (mp_data_bus.h CITE)
    fn mp_dbus_dump_events(&mut self, _mod_name: Option<&str>) {}     // cc :469 (mp_data_bus.h CITE)
    fn mp_dbus_show_channel_status(&mut self) {}                      // cc :477 (mp_data_bus.h CITE)
    fn mp_dbus_set_debug_enabled(&mut self, _on: bool) {}             // cc :486 / :494 (CITE)
    fn mp_dbus_reset_stats(&mut self) {}                              // cc :590 (CITE)

    /// cc :1524 ActionManager::instantiate_action_with_param("react",
    /// "page", page, sc) — managers/action_manager.h NOT landed: CITE
    /// DECL; the None posture = the C nullptr -> `return false` arm.
    fn instantiate_action_with_param(
        &mut self,
        _action: &str,
        _param: &str,
        _value: &str,
    ) -> bool {
        false // cc :1524-:1527 (NOT landed; the C-null -> false arm)
    }

    /// log/batched_logger.h BatchedLogger::BatchedLogManager::init()
    /// (:856 / :946) + ::shutdown() (:868 / :949) — NOT landed (the
    /// landed log/messages.rs :262 pins the BatchedLogger path NOT-
    /// ported): the seam legs are CITE posture ONLY.
    fn batched_log_init(&mut self) {}    // cc :856 / :946 (CITE)
    fn batched_log_shutdown(&mut self) {} // cc :868 / :949 (CITE)

    /// file_api/file_service.h FileService::is_file_capture_enabled()
    /// (cc :2317 / :2340) — the capture-state read: the landed face is
    /// the per-flow FileInfo slot (file_api/file_flows.rs :215), the
    /// SERVICE face NOT landed: seam CITE, the false posture = the
    /// capture-off gate.
    fn is_file_capture_enabled(&self) -> bool {
        false // cc :2317 / :2340 (FileService NOT landed, cite)
    }

    /// main/policy.h :91 `SO_PUBLIC NetworkPolicy*
    /// get_network_policy()` — the policy_id read legs cc :1827 + :1948
    /// + the FilePolicy reach legs cc :2297 / :2349 / :2353: the seam
    ///   rides the BORROWED network-policy record identity.
    fn network_policy_id(&self) -> u32 {
        0 // policy.h :91 (the C deref face; the row harness rides policy_id 0 posture)
    }
    /// cc :2297 / :2349 / :2353 `get_network_policy()->
    /// get_file_policy()` — REUSE the landed file_api/file_policy.rs
    /// :152 FilePolicy (the set_file_type :221 / set_file_signature
    /// :226 / set_file_capture :231 / set_verdict_delay :213 legs,
    /// CITE-REUSE never re-forked).
    fn file_policy(&mut self) -> Option<&mut FilePolicy> {
        None // CITE: the C derefs blind (a null network policy = C crash; the Option face NEVER crashes)
    }
    /// cc :2355 `get_network_policy()->add_file_policy_rule(file_rule)`
    /// — the network-policy rule-list writer: NOT landed face (the
    /// landed FilePolicy::add_file_id takes a service): seam leg CITE.
    fn add_file_policy_rule(&mut self, _rule: &FileRule) {} // cc :2355 (CITE)

    /// main/policy.h :93 `SO_PUBLIC InspectionPolicy*
    /// get_inspection_policy()` — the cc :1187 leg. The landed
    /// policy.rs carries NO InspectionPolicy yet (:3 cite); the seam
    /// legs (user_policy_id / policy_mode writers, max_aux_ip rides the
    /// sc bag) ride the caller-owned Lite record below NEVER a fake.
    fn inspection_user_policy_id(&mut self) -> Option<&mut u64> {
        None // policy.h :93 (NOT landed record: the caller threads it)
    }
    fn inspection_policy_mode(&mut self) -> Option<&mut PolicyMode> {
        None // policy.h :93 (same posture)
    }

    /// main/snort_config.h :464-:492 the Sc write-legs (set_chroot_dir
    /// :464, set_daemon :469, set_dirty_pig :471, set_dst_mac :472,
    /// set_gid :476, set_tunnel_verdicts :486, set_uid :488, set_umask
    /// :489, set_utc :490, set_watchdog :491, set_watchdog_min_thread_
    /// count :492) + the PUBLIC-member writes (rule_order :206, log_dir
    /// :221, respond_* :286-:291, asid/mpls/vlan-agnostic :304-:306,
    /// pkt_cnt/pkt_skip :308-:309, bpf_file :312, attribute_* :296-
    /// :300, max_aux_ip :395, tagged_packet_limit :218, event_trace_max
    /// :219, output_flags :214): SnortConfig = NOT landed as a record —
    /// the seam drives them ONE method per C leg onto the caller-owned
    /// ScWriteBag (the record-threading deviation, cited at the legs).
    fn sc(&mut self) -> &mut ScWriteBag;

    /// cc / snort_config.h :214 output_flags read-modify-write face —
    /// rides the sc() bag directly (the landed OUTPUT_FLAG_LOG_BUFFERED
    /// log/messages.rs :40 identity REUSED at the log_buffered arm).
    fn log(&mut self) -> &mut LogEngine; // log/messages.rs :82 home CITE-REUSE

    /// main/thread_config.rs ThreadConfig legs: validate_cpuset_string
    /// REUSE the landed :761, destroy_cpuset the landed :817, set_
    /// thread_affinity the landed :836, set_named_thread_affinity the
    /// landed :860 — the seam threads the BORROWED landed ThreadConfig.
    fn thread_config(&mut self) -> Option<&mut ThreadConfig>; // thread_config.rs :658 REUSE (the C sc->thread_config posture, a miss = None)

    /// the tc + log PAIR face (the Rust borrow law: the landed
    /// ThreadConfig affinity legs need BOTH the config and the
    /// LogEngine at once; the impl borrows its distinct fields side-
    /// by-side — the C one-conf face is the cite).
    fn tc_and_log(&mut self) -> (Option<&mut ThreadConfig>, &mut LogEngine);

    /// main/snort_types.h sfthreshold_create(sc, sc->threshold_config,
    /// &thdx, policy_id) (filters/sfthreshold.h :43) — filters/* NOT
    /// landed: seam CITE; the C `if ( sfthreshold_create(...) )` TRUE
    /// arm = a creation failure; the DEFAULT posture never fails (a
    /// NOT-landed provider NEVER invents a SUCCESS or a FAILURE — the
    /// 0 posture rides; the twin drives the failure arm on the mock).
    fn sfthreshold_create(
        &mut self,
        _cfg: &mut ThresholdConfigLite,
        _thdx: &ThdxFace,
    ) -> bool {
        false // filters/sfthreshold.h :43 NOT landed (cite; 0 = C success posture)
    }

    /// filters/rate_filter.h :38/:40 RateFilter_Cleanup() /
    /// RateFilter_Create(sc, sc->rate_filter_config, &thdx) — NOT
    /// landed: seam CITE (the dtor :2033 leg, the end :2081 leg; the
    /// Create TRUE arm = failure, the default posture 0 = success).
    fn rate_filter_cleanup(&mut self) {} // cc :2034 (rate_filter.h CITE)
    fn rate_filter_create(&mut self, _cfg: &mut RateFilterConfigLite, _lite: &SFRFConfigNodeLite) -> bool {
        false // cc :2081 (rate_filter.h :40 NOT landed; 0 = C success posture)
    }

    /// target_based/host_attributes.h HostAttributesManager faces:
    /// add_host (cc :2202, TRUE = stored), get_pegs (cc :2140), get_-
    /// peg_counts (cc :2143) — host_tracker/target_based manager NOT
    /// landed: seam CITE with the honest neutral postures.
    fn host_attributes_add_host(
        &mut self,
        _host: &mut HostAttributesEntryLite,
    ) -> bool {
        false // cc :2202 (`if ( !HostAttributesManager::add_host(host, sc) ) host.reset();` — NOT landed, cite)
    }

    /// detection/fp_config.h the fast-pattern legs the landed
    /// detection/fp_config.rs home does NOT carry (set_debug_mode,
    /// set_debug_print_nc_rules, set_debug_print_rule_group_build_
    /// details, set_debug_print_rule_groups_uncompiled, set_debug_
    /// print_rule_groups_compiled, set_max_pattern_len, set_max_
    /// queue_events, set_stream_insert, set_search_method, set_split_
    /// any_any, set_queue_limit): the fp_config.rs landed home carries
    /// ONLY bleedover/single-rule/warnings (its :34/:46/:49 seats,
    /// REUSED at the arms that need them) — the rest are CITE-DECL
    /// seam legs the caller drives on the SAME record (harness
    /// mirrors fp_config.h; NEVER an invented body).
    fn fp_set_debug_mode(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig) {}
    fn fp_set_debug_print_nc_rules(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig) {}
    fn fp_set_debug_print_rule_group_build_details(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig) {}
    fn fp_set_debug_print_rule_groups_uncompiled(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig) {}
    fn fp_set_debug_print_rule_groups_compiled(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig) {}
    fn fp_set_max_pattern_len(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig, _n: u32) {}
    fn fp_set_max_queue_events(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig, _n: u8) {}
    fn fp_set_stream_insert(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig, _on: bool) {}
    fn fp_set_search_method(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig, _m: &[u8]) -> bool { true } // cc :326 (the C false arm only on an unknown method: the NOT-landed face never answers, the twin drives it)
    fn fp_set_split_any_any(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig, _on: bool) {}
    fn fp_set_queue_limit(&mut self, _fp: &mut crate::detection::fp_config::FastPatternConfig, _n: u32) {}

    /// framework/ips_action.rs ActionRegistry faces (REUSE the landed
    /// home, NEVER re-forked): the cc :2064 IpsAction::get_type + the
    /// cc :2066 is_valid_action pair (the seam owns the registry the
    /// C static ActionManager drives; the landed :91/:102 legs run on
    /// the world's own registry record).
    fn get_action_type(&mut self, _name: &str) -> crate::framework::ips_action::ActionType {
        0 // the C static ActionManager::get_action_type face (NOT landed; the landed home runs on the twin's registry)
    }
    fn is_valid_action(&self, _action: crate::framework::ips_action::ActionType) -> bool {
        true // the landed is_valid_action :102 posture the twin drives (the C gate NEVER returns false on the default face)
    }

    /// main/snort_config.cc SnortConfig::set_log_quiet (:883 leg sc->
    /// set_log_quiet(true)) — the landed LogEngine::set_log_quiet :139
    /// REUSE rides the log() leg directly (cite at the arm).
    /// SnortConfig::enable_log_verbose (:922) — NOT landed (the
    /// logging_flags face), seam CITE.
    fn enable_log_verbose(&mut self) {} // cc :922 (CITE)

    /// cc / main/policy.h set_tunnel_verdicts (snort_config.h :486) —
    /// NOT landed body: rides the ScWriteBag field, cited.
    fn proto_ref_add(&mut self, name: &str) -> u16; // the sc->proto_ref->add face cc :2165/:2168 (REUSE the landed target_based/snort_protocols.rs ProtocolReference::add :127 home; the seam owns the record)
}

/// the NullWorld default impl (the analyzer.rs 24d pattern): everything
/// neutral, the record faces owned by the caller.
#[derive(Default)]
pub struct NullWorld {
    pub sc: ScWriteBag,
    pub log: LogEngine,
    pub proto_ref: ProtocolReference, // the sc->proto_ref face, the landed home :47 REUSE
    pub tc: Option<ThreadConfig>,     // the sc->thread_config face (the landed :658 record, REUSE)
    pub registered: Vec<&'static str>, // the PluginManager::add_module leg ledger (the twin walks the 35+1+1-off census)
}

impl ModulesWorld for NullWorld {
    fn sc(&mut self) -> &mut ScWriteBag {
        &mut self.sc
    }
    fn log(&mut self) -> &mut LogEngine {
        &mut self.log
    }
    fn thread_config(&mut self) -> Option<&mut ThreadConfig> {
        self.tc.as_mut() // cc :1669/:1707/:1712/:1716 sc->thread_config (NULL by default: not invented as set; a twin installs the landed :658 record)
    }
    fn tc_and_log(&mut self) -> (Option<&mut ThreadConfig>, &mut LogEngine) {
        // the field-by-field borrows (the thread_config() fn face
        // would re-borrow ALL of self; the same NULL posture, cited):
        (self.tc.as_mut(), &mut self.log)
    }
    fn proto_ref_add(&mut self, name: &str) -> u16 {
        // REUSE the landed ProtocolReference::add home (target_based/
        // snort_protocols.rs :127 — the name->id table + the builtin
        // census, NEVER re-forked); the record rides the NullWorld bag.
        self.proto_ref.add(name)
    }
}

// ======================================================================
// the row-scoped Lite records (THE RECORD-THREADING DEVIATION face,
// the 23c sfdaq_module law cited at the KNOWN-DEVIATIONS row the
// orchestrator writes; the C records live in NOT-landed families —
// the Lite faces below are the caller-threaded WRITE faces ONLY, NEVER
// an ABI claim):
//   EventQueueConfigLite        <- events/event_queue.h :28-:34
//   DetectionFilterConfigLite   <- filters/detection_filter.h :43-:46
//   ThresholdConfigLite         <- filters/sfthreshold.h :33-:38
//   RateFilterConfigLite        <- filters/sfrf.h :166-:175 (the
//                                  memcap slot the alerts leg writes)
//   SFRFConfigNodeLite          <- filters/sfrf.h :69-:87 + the init()
//                                  face :137-:149 (the C SFRF_TRACK
//                                  ordinals :48-:52 cited)
//   ThdxFace                    <- filters/sfthd.h :166-:176 + the
//                                  THD_TYPE_*/THD_TRK_* ordinals
//                                  :63-:68 / :88-:91 + THD_PRIORITY_
//                                  SUPPRESS :75 (filters/* NOT landed
//                                  -> the FACE is row-scoped, cited)
//   PatMatQStatLite             <- search_engines/pat_stats.h :28-:37
//                                  (the cc :231 THREAD_LOCAL identity
//                                  stays the ground's; at THIS face
//                                  the caller threads the record —
//                                  the C global-identity deviation,
//                                  cited; NEVER a thread_local re-
//                                  fork)
//   HostServiceDescriptorLite   <- target_based/host_attributes.h
//                                  :53-:74 (the reset() face :62-:67
//                                  incl the UNKNOWN_PROTOCOL_ID iden-
//                                  tity — REUSE the landed snort_
//                                  protocols.rs :25 seat)
//   HostAttributesEntryLite     <- the HostAttributesEntry =
//                                  shared_ptr<HostAttributes-
//                                  Descriptor> face (host_attributes.h
//                                  :91+ the descriptor; the manager
//                                  NOT landed -> entry Lite rides the
//                                  seam; NEVER the C LRU table)
//   ScWriteBag                  <- main/snort_config.h :206-:312 etc.
//                                  the PUBLIC-member write legs + the
//                                  :464-:492 set_* legs (SnortConfig
//                                  NOT landed as a record: the bag is
//                                  the write ledger the twin asserts)
// ======================================================================

/// events/event_queue.h :28-:34 (the max_events / log_events / order /
/// process_all_events slots; the SNORT_EVENTQ_PRIORITY=1 /
/// SNORT_EVENTQ_CONTENT_LEN=2 ordinals :25-:26).
#[derive(Default, Clone, Debug)]
pub struct EventQueueConfigLite {
    pub max_events: u32,          // h :30
    pub log_events: u32,          // h :31
    pub order: i32,               // h :32
    pub process_all_events: i32,  // h :33
}

/// events/event_queue.h :25 the C `#define SNORT_EVENTQ_PRIORITY 1`
/// ordinal (the order_events else-arm, cc :137).
pub const SNORT_EVENTQ_PRIORITY: i32 = 1;
/// events/event_queue.h :26 the C `#define SNORT_EVENTQ_CONTENT_LEN 2`
/// ordinal (cc :135).
pub const SNORT_EVENTQ_CONTENT_LEN: i32 = 2;

/// filters/detection_filter.h :43-:46 — the memcap slot the
/// alerts.detection_filter_memcap leg writes (cc :765).
#[derive(Default, Clone, Copy, Debug)]
pub struct DetectionFilterConfigLite {
    pub memcap: u32, // h :45
}

/// filters/sfthreshold.h :33-:38 — the memcap slot the alerts.event_
/// filter_memcap leg writes (cc :768); the thd_objs/enabled slots stay
/// the NOT-landed filter family (cited).
#[derive(Default, Clone, Copy, Debug)]
pub struct ThresholdConfigLite {
    pub memcap: u32, // h :36
}

/// filters/sfrf.h :166-:175 — the memcap slot the alerts.rate_filter_
/// memcap leg writes (cc :776); the rest of the RateFilterConfig face
/// stays the NOT-landed filter family (cited).
#[derive(Default, Clone, Copy, Debug)]
pub struct RateFilterConfigLite {
    pub memcap: u32, // h :173
}

/// filters/sfrf.h :69-:87 + :137-:149 init() — the row-scoped Lite of
/// the C tSFRFConfigNode (the atomic count rides a plain u32 at this
/// face, the single-thread deviation cited; the sfip_var_t* applyTo
/// rides the landed Option<...> nullptr-posture face). The
/// SFRF_TRACK_* ordinals :48-:52 (BY_NONE=0 / BY_SRC=1 / BY_DST=2 /
/// BY_RULE=3) ride the cited consts.
#[derive(Clone, Debug)]
pub struct SFRFConfigNodeLite {
    pub tid: i32,           // h :72 NSDMI 0
    pub gid: u32,           // h :73
    pub sid: u32,           // h :74
    pub policy_id: u32,     // h :75
    pub tracking: u8,       // h :76 (the SFRF_TRACK ordinal face)
    pub seconds: i64,       // h :77 (time_t)
    pub count: u32,         // h :80 (the atomic face, plain at this row)
    pub new_action: u8,     // h :83 (IpsAction::Type = the landed ips_action.rs ActionType u8 face)
    pub timeout: u32,       // h :86
    pub apply_to: Option<SfIpVar>, // h :87 (the nullptr posture)
}

impl Default for SFRFConfigNodeLite {
    fn default() -> Self {
        // the C h :72-:87 NSDMI faces == init() :137-:149 (the same
        // zero/none face both ways; the module ctor cc :2006 also
        // calls init() — the ONE posture lands once).
        SFRFConfigNodeLite {
            tid: 0, gid: 0, sid: 0, policy_id: 0, tracking: SFRF_TRACK_BY_NONE,
            seconds: 0, count: 0, new_action: 0, timeout: 0, apply_to: None,
        }
    }
}

impl SFRFConfigNodeLite {
    /// h :137-:149 `void init()` — the reset face verbatim (cc :2075
    /// begin-leg + the cc :2006 ctor face).
    pub fn init(&mut self) {
        self.tid = 0;         // :139
        self.gid = 0;         // :140
        self.sid = 0;         // :141
        self.policy_id = 0;   // :142
        self.tracking = SFRF_TRACK_BY_NONE; // :143
        self.count = 0;       // :144
        self.seconds = 0;     // :145
        self.new_action = 0;  // :146
        self.timeout = 0;     // :147
        self.apply_to = None; // :148
    }
}

/// filters/sfrf.h :48-:52 the SFRF_TRACK_* ordinals.
pub const SFRF_TRACK_BY_NONE: u8 = 0;
pub const SFRF_TRACK_BY_SRC: u8 = 1;
pub const SFRF_TRACK_BY_DST: u8 = 2;
pub const SFRF_TRACK_BY_RULE: u8 = 3;

/// filters/sfthd.h :166-:176 THDX_STRUCT (the sfip_var_t* ip_address
/// rides the Option posture; the NOT-landed filter family = the face
/// is row-scoped, cited).
#[derive(Clone, Debug, Default)]
pub struct ThdxFace {
    pub gen_id: u32,     // h :168
    pub sig_id: u32,     // h :169
    pub seconds: u32,    // h :170
    pub r#type: i32,     // h :172
    pub count: i32,      // h :173
    pub tracking: i32,   // h :174
    pub priority: i32,   // h :175
    pub ip_address: Option<SfIpVar>, // h :177 (the nullptr posture)
}

// the C `THDX_STRUCT thdx = {};` face (cc :1789 / :1909): value-init
// zeroes every slot — the derived Default face (the ip slot's None).

impl ThdxFace {
    /// the C memset(&thdx, 0, sizeof(thdx)) face (cc :1811 / :1940) —
    /// the Rust zero face (the ip_address slot included: the C memset
    /// zeroes the POINTER too — the faithful face kept).
    pub fn zero(&mut self) {
        *self = ThdxFace::default();
    }
}

/// filters/sfthd.h :63-:68 the THD_TYPE_* ordinals.
pub const THD_TYPE_LIMIT: i32 = 0;
pub const THD_TYPE_THRESHOLD: i32 = 1;
pub const THD_TYPE_BOTH: i32 = 2;
pub const THD_TYPE_SUPPRESS: i32 = 3;
pub const THD_TYPE_DETECT: i32 = 4;

/// filters/sfthd.h :88-:91 the THD_TRK_* ordinals.
pub const THD_TRK_NONE: i32 = 0;
pub const THD_TRK_SRC: i32 = 1;
pub const THD_TRK_DST: i32 = 2;

/// filters/sfthd.h :75 `#define THD_PRIORITY_SUPPRESS 1000000`.
pub const THD_PRIORITY_SUPPRESS: i32 = 1_000_000;

/// search_engines/pat_stats.h :28-:37 — the seven PegCount slots. The
/// cc :231 `THREAD_LOCAL PatMatQStat pmqs` ground DEFINITION seat rides
/// THE PAIR's identity: at the Rust face the record is caller-owned
/// (the statics law: the get_counts reinterpret_cast leg has NO lawful
/// slot without an aliasing face — the 23c cited deviation re-rides;
/// the twin drives ONE record end-to-end, NEVER the C global).
#[derive(Default, Clone, Copy, Debug)]
pub struct PatMatQStatLite {
    pub max_inq: PegCount,             // h :30
    pub tot_inq_flush: PegCount,       // h :31
    pub tot_inq_inserts: PegCount,     // h :32
    pub tot_inq_overruns: PegCount,    // h :33
    pub tot_inq_uinserts: PegCount,    // h :34
    pub non_qualified_events: PegCount,// h :35
    pub qualified_events: PegCount,    // h :36
}

/// cc :234-:244 `const PegInfo mpse_pegs[]` — VERBATIM the CountType
/// faces (MAX first :236, five SUM rows, the END sentinel :243): the
/// row order aligns the PatMatQStatLite field order above (the h :30-
/// :36 census).
pub static MPSE_PEGS: [PegInfo; 8] = [
    PegInfo { peg_type: CountType::Max, name: "max_queued", help: "maximum fast pattern matches queued for further evaluation" }, // :236
    PegInfo { peg_type: CountType::Sum, name: "total_flushed", help: "total fast pattern matches processed" },                      // :237
    PegInfo { peg_type: CountType::Sum, name: "total_inserts", help: "total fast pattern hits" },                                   // :238
    PegInfo { peg_type: CountType::Sum, name: "total_overruns", help: "fast pattern matches discarded due to overflow" },           // :239
    PegInfo { peg_type: CountType::Sum, name: "total_unique", help: "total unique fast pattern hits" },                             // :240
    PegInfo { peg_type: CountType::Sum, name: "non_qualified_events", help: "total non-qualified events" },                          // :241
    PegInfo { peg_type: CountType::Sum, name: "qualified_events", help: "total qualified events" },                                  // :242
    PegInfo { peg_type: CountType::End, name: "", help: "" },                                                                        // :243 the END sentinel
];

/// cc :1878-:1883 `const PegInfo event_filter_peg_names[]` :234-style
/// (two SUM rows + END :1882). The companion cc :1877 `extern
/// THREAD_LOCAL EventFilterStats event_filter_stats;` is an EXTERN —
/// DECL cite ONLY at this seat (the DEFINITION owner is filters/
/// sfthd.cc; NEVER a definition here, NEVER a re-fork): the
/// get_counts reinterpret_cast leg (:1898-:1901) rides the seam's
/// caller-owned stats record, cited.
pub static EVENT_FILTER_PEG_NAMES: [PegInfo; 3] = [
    PegInfo { peg_type: CountType::Sum, name: "no_memory_local", help: "number of times event filter ran out of local memory" },  // :1880
    PegInfo { peg_type: CountType::Sum, name: "no_memory_global", help: "number of times event filter ran out of global memory" }, // :1881
    PegInfo { peg_type: CountType::End, name: "", help: "" },                                                                        // :1882 sentinel
];

/// cc :1877 the extern seat — the CITE-ONLY identity face (the two
/// EventFilterStats slots the peg names above name; NOT a definition):
/// filters/sfthd.cc owns the THREAD_LOCAL.
pub const EVENT_FILTER_STATS_EXTERN_CITE: &str =
    "extern THREAD_LOCAL EventFilterStats event_filter_stats; // in sfthd.cc"; // cc :1877 (DECL cite NEVER a definition)

/// cc :1995-:1999 `const PegInfo rate_filter_peg_names[]` — two SUM
/// rows + END (:1998); the companion get_counts reinterpret_cast face
/// (:2018) reads the NOT-landed rate_filter_stats THREAD_LOCAL (filters/
/// rate_filter.cc home) through the seam — cite, NEVER a re-fork.
pub static RATE_FILTER_PEG_NAMES: [PegInfo; 3] = [
    PegInfo { peg_type: CountType::Sum, name: "no_memory", help: "number of times rate filter ran out of memory" },  // :1997
    PegInfo { peg_type: CountType::Sum, name: "recoveries", help: "number of tracked addresses dropped to make room for another" }, // :1998
    PegInfo { peg_type: CountType::End, name: "", help: "" },                                                            // :1998 the END sentinel (the table closes :1999)
];

/// targets/host_attributes.h :53-:74 HostServiceDescriptor (the reset()
/// face :62-:67 rides the UNKNOWN_PROTOCOL_ID REUSE, snort_protocols.
/// rs :25; the appid_service NSDMI false :73).
#[derive(Clone, Copy, Debug)]
pub struct HostServiceDescriptorLite {
    pub port: u16,                    // h :70 NSDMI 0
    pub ipproto: u16,                 // h :71
    pub snort_protocol_id: SnortProtocolId, // h :72 (NSDMI UNKNOWN)
    pub appid_service: bool,          // h :73
}

impl Default for HostServiceDescriptorLite {
    fn default() -> Self {
        HostServiceDescriptorLite {
            port: 0, ipproto: 0, snort_protocol_id: UNKNOWN_PROTOCOL_ID, appid_service: false,
        }
    }
}

impl HostServiceDescriptorLite {
    /// h :62-:67 `void reset()` — port/ipproto 0, snort_protocol_id
    /// UNKNOWN (the appid flag is NOT reset — the honest C face).
    pub fn reset(&mut self) {
        self.port = 0;                // :64
        self.ipproto = 0;             // :65
        self.snort_protocol_id = UNKNOWN_PROTOCOL_ID; // :66
    }
}

/// the cc :2137 `HostAttributesEntry host = nullptr` face: the C
/// shared_ptr<HostAttributesDescriptor>; the manager NOT landed ->
/// the row-scoped entry Lite carries the descriptor write legs the
/// set/end ladders drive (update_service :295, the :2157/:2159 set_
/// ip/policy legs) — NEVER the C LRU table itself (host_attributes.h
/// CITE family).
#[derive(Clone, Debug, Default)]
pub struct HostAttributesEntryLite; // the write legs ride the seam host_attributes_* faces (NOT landed manager family, cited)

/// SnortConfig write ledger — main/snort_config.h the member + set_*
/// legs (the NOT-landed-record deviation face; every slot + its H
/// line cited; the set_* METHODS land as the bag methods so the end/
/// set ladders stay one-leg-per-C-line mechanical).
#[derive(Default, Clone, Debug)]
pub struct ScWriteBag {
    pub output_flags: u32,            // h :214 (the DEFAULT face is the ctor-time OUTPUT_FLAG__WIDE_HEX — the wide_hex_dump dialect pair; the Rust Default stays 0, the C-init face cited not faked)
    pub rule_order: String,           // h :206 (cc :773)
    pub log_dir: String,              // h :221 (cc :908)
    pub event_trace_max: u16,         // h :219 (cc :911)
    pub tagged_packet_limit: u32,     // h :218 (cc :917)
    pub respond_attempts: u8,         // h :286 (cc :1013)
    pub respond_device: String,       // h :291 (cc :1016)
    pub max_responses: u8,            // h :287 (cc :1022)
    pub min_interval: u8,             // h :288 (cc :1025)
    pub asid_agnostic: bool,          // h :304 (cc :1073)
    pub bpf_file: String,             // h :312 (cc :1076)
    pub pkt_cnt: u64,                 // h :308 (cc :1079)
    pub mpls_agnostic: bool,          // h :305 (cc :1082 — the C init true face cited at new())
    pub pkt_skip: u64,                // h :309 (cc :1085)
    pub vlan_agnostic: bool,          // h :306 (cc :1088)
    pub attribute_hosts_file: String, // h :296 (cc :1136)
    pub max_attribute_hosts: u32,     // h :297 (cc :1139)
    pub segment_count_host: u32,      // h :300 (cc :1157 — the C init 4 face cited)
    pub max_attribute_services_per_host: u32, // h :298 (cc :1159)
    pub max_metadata_services: u8,    // h :299 (cc :1162)
    pub max_aux_ip: i16,              // h :395 (cc :1235)
    pub watchdog_timer: u16,          // h :264 (cc :1662 set_watchdog)
    pub watchdog_min_thread_count: u16, // h :265 (cc :1665)
    pub dirty_pig: bool,              // h :266 (cc :1640 set_dirty_pig)
    pub tunnel_verdicts: String,      // h :486 set_tunnel_verdicts (cc :781, the args string face)
    pub daemon: bool,                 // h :469 set_daemon (cc :1634)
    pub chroot_dir: String,           // h :464 set_chroot_dir (cc :1637)
    pub gid: String,                  // h :476 set_gid (cc :1643)
    pub uid: String,                  // h :488 set_uid (cc :1646)
    pub umask: u32,                   // h :489 set_umask (cc :1649)
    pub utc: bool,                    // h :490 set_utc (cc :1652)
    pub dst_mac: String,              // h :472 set_dst_mac (cc :1019)
    pub ips_include: String,          // cc :1416 the p->include face (NOT a landed policy slot, cited)
    pub rules: String,                // cc :1428 the p->rules += face (cited)
    pub states: String,               // cc :1431 the p->states += face (cited)
    pub respond_set: bool,            // bookkeeping: set_* legs reached (the twin asserts the ledger)
}

/// the landed OUTPUT_FLAG identities REUSE-cited (log/messages.rs :40
/// carries OUTPUT_FLAG_LOG_BUFFERED = 0x2000): the output/alerts
/// update_mask legs need the sibling ordinals — snort_config.h :90-
/// :107 CITE, landed-home-only law: ONLY the LOG_BUFFERED seat has a
/// landed home; the other flags ride the row's cited ordinal consts
/// (the C face measured, NEVER invented — head :90-:107 verbatim).
/// log/messages.rs :40 OUTPUT_FLAG_LOG_BUFFERED REUSE (no re-fork of
/// that value: the alias below rides the home).
pub use crate::log::messages::OUTPUT_FLAG_LOG_BUFFERED as OUTPUT_FLAG__LOG_BUFFERED;

/// main/snort_config.h :91-:107 the output-flag ordinals the update_
/// mask legs drive (the LOG_BUFFERED seat above rides the LANDED home;
/// these sibling seats the landed homes lack, head-measured).
pub const OUTPUT_FLAG__VERBOSE_DUMP: u32 = 0x0000_0002;   // h :91
pub const OUTPUT_FLAG__CHAR_DATA: u32 = 0x0000_0004;      // h :92
pub const OUTPUT_FLAG__APP_DATA: u32 = 0x0000_0008;       // h :93
pub const OUTPUT_FLAG__INCLUDE_YEAR: u32 = 0x0000_0040;   // h :97
pub const OUTPUT_FLAG__OBFUSCATE: u32 = 0x0000_0080;      // h :99
pub const OUTPUT_FLAG__ALERT_IFACE: u32 = 0x0000_0100;    // h :101
pub const OUTPUT_FLAG__WIDE_HEX: u32 = 0x0000_0800;       // h :104 (the :214 default-face pair cite)
pub const OUTPUT_FLAG__ALERT_REFS: u32 = 0x0000_1000;     // h :106

// ======================================================================
// THE module classes (cc :115-:2358). Each: a pub struct <Name>Module
// composing the landed framework Module base (the sfdaq_module.rs
// pattern) + the C private members as fields (the statics-members
// law), begin/set/end/matches legs transcribed LADDER-FOR-LADDER with
// one cc-cite per leg. The C vtable seats that CANNOT lawfully ride a
// Rust trait at this row (get_pegs/get_counts aliasing, gid, usage
// ordinals) land as inherent pub faces exactly like the 23c cited
// deviation (the stats-family row re-visits the trait wiring).
// ======================================================================

// ---------------------------------------------------------------------
// cc :115-:159 event queue module
// ---------------------------------------------------------------------

/// cc :115-:125 `class EventQueueModule : public Module` — the ctor
/// `Module("event_queue", event_queue_help, event_queue_params)`
/// (:117), the set/end decls (:118-:119) and the cc :121
/// `// cppcheck-suppress uselessOverride ; override retained to
/// document the derived interface contract` comment face (rides as a
/// cited comment by law, NEVER an attribute) over get_usage CONTEXT
/// (:122-:123).
pub struct EventQueueModule {
    pub base: Module, // cc :117
}

impl Default for EventQueueModule {
    fn default() -> Self { Self::new() } // the C default-ctor face
}

impl EventQueueModule {
    pub fn new() -> EventQueueModule {
        EventQueueModule {
            base: Module::new_params("event_queue", EVENT_QUEUE_HELP, Some(&EVENT_QUEUE_PARAMS), false), // :117
        }
    }

    /// cc :122-:123 `Usage get_usage() const { return CONTEXT; }` —
    /// the ordinal rides the landed C_USAGE_CONTEXT home (codec_
    /// module.rs :274, REUSE, private face NOT callable-port -> pub
    /// const fn per the row law).
    pub fn get_usage() -> u32 {
        C_USAGE_CONTEXT // :123
    }

    /// cc :127-:147 set(fqn-unread, v, sc) — the eq = sc->
    /// event_queue_config reach rides the caller-threaded Lite (the
    /// record-threading deviation cited at the Lite census).
    pub fn set(&mut self, v: &mut Value, eq: &mut EventQueueConfigLite) -> bool {
        if v.is("max_queue") {
            eq.max_events = v.get_uint32(); // :131
        } else if v.is("log") {
            eq.log_events = v.get_uint32(); // :134
        } else if v.is("order_events") {
            if v.get_uint8() != 0 {
                eq.order = SNORT_EVENTQ_CONTENT_LEN; // :137 (h :26 = 2)
            } else {
                eq.order = SNORT_EVENTQ_PRIORITY;    // :139 (h :25 = 1)
            }
        } else if v.is("process_all_events") {
            eq.process_all_events = v.get_bool() as i32; // :142 (the C int slot absorbing the bool face)
        }
        true // :146
    }

    /// cc :150-:158 end(fqn-unread, idx-unread, sc) — the max/log
    /// clamp leg + the ALL-true fall-through.
    pub fn end(&mut self, eq: &mut EventQueueConfigLite) -> bool {
        if eq.max_events < eq.log_events {
            eq.max_events = eq.log_events; // :154-:155
        }
        true // :157
    }
}

// ---------------------------------------------------------------------
// cc :246-:333 search engine module (the pmqs THREAD_LOCAL ride at the
// PatMatQStatLite census above — the get_counts reinterpret_cast seat
// has NO lawful slot at this row, the 23c cited deviation)
// ---------------------------------------------------------------------

/// cc :246-:260 `class SearchEngineModule : public Module` — ctor
/// (:248), the set decl (:249), the inlined get_pegs -> mpse_pegs
/// (:252-:253), get_counts -> (PegCount*)&pmqs (:255-:256, the alias
/// seat NOT ported as callable — cited), get_usage GLOBAL (:258-:259).
pub struct SearchEngineModule {
    pub base: Module, // cc :248
}

impl Default for SearchEngineModule {
    fn default() -> Self { Self::new() }
}

impl SearchEngineModule {
    pub fn new() -> SearchEngineModule {
        SearchEngineModule {
            base: Module::new_params("search_engine", SEARCH_ENGINE_HELP, Some(&SEARCH_ENGINE_PARAMS), false), // :248
        }
    }

    /// h :45 get_pegs face -> the LANDED-table cite (MPSE_PEGS above,
    /// the cc :234-:244 table).
    pub fn get_pegs() -> &'static [PegInfo; 8] {
        &MPSE_PEGS // :253
    }

    /// cc :258-:259 get_usage GLOBAL -> landed C_USAGE_GLOBAL.
    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL
    }

    /// cc :262-:333 set(fqn-unread, v, sc) — the fp = sc->fast_
    /// pattern_config reach: the landed detection/fp_config.rs legs
    /// ride DIRECT (set_bleed_over_port_limit :34, set_bleed_over_
    /// warnings :49, set_single_rule_group :46, set_debug_mode / set_
    /// debug_print_* / set_max_pattern_len / set_max_queue_events /
    /// set_stream_insert / set_search_method / set_split_any_any /
    /// set_queue_limit = fp_config.h NOT-landed arms CITED, the seam
    /// owns the fp legs the landed home lacks). The cc :271 the C
    /// `// FIXIT-L these should take arg` comment face rides its cite.
    pub fn set<W: ModulesWorld + ?Sized>(
        &mut self,
        v: &mut Value,
        fp: &mut crate::detection::fp_config::FastPatternConfig,
        w: &mut W,
    ) -> bool {
        if v.is("bleedover_port_limit") {
            fp.set_bleed_over_port_limit(v.get_uint32()); // :266 + fp_config.rs :34 REUSE
        } else if v.is("bleedover_warnings_enabled") {
            if v.get_bool() {
                fp.set_bleed_over_warnings(); // :271-:273 (the FIXIT-L comment face :272 rides the cite)
            }
        } else if v.is("enable_single_rule_group") {
            if v.get_bool() {
                fp.set_single_rule_group(); // :277-:279 (fp_config.rs :46 REUSE)
            }
        } else if v.is("debug") {
            if v.get_bool() {
                w.fp_set_debug_mode(fp); // :283-:285 (fp_config.h set_debug_mode NOT landed, seam CITE)
            }
        } else if v.is("debug_print_nocontent_rule_tests") {
            if v.get_bool() {
                w.fp_set_debug_print_nc_rules(fp); // :289-:291 (CITE)
            }
        } else if v.is("debug_print_rule_group_build_details") {
            if v.get_bool() {
                w.fp_set_debug_print_rule_group_build_details(fp); // :295-:297 (CITE)
            }
        } else if v.is("debug_print_rule_groups_uncompiled") {
            if v.get_bool() {
                w.fp_set_debug_print_rule_groups_uncompiled(fp); // :301-:303 (CITE)
            }
        } else if v.is("debug_print_rule_groups_compiled") {
            if v.get_bool() {
                w.fp_set_debug_print_rule_groups_compiled(fp); // :307-:309 (CITE)
            }
        } else if v.is("max_pattern_len") {
            w.fp_set_max_pattern_len(fp, v.get_uint32()); // :311 (CITE)
        } else if v.is("max_queue_events") {
            w.fp_set_max_queue_events(fp, v.get_uint8()); // :314 (CITE)
        } else if v.is("detect_raw_tcp") {
            w.fp_set_stream_insert(fp, v.get_bool()); // :317 (CITE)
        }
        // :319-:322 `#ifdef HAVE_HYPERSCAN` rule_db_dir leg — dialect
        // face MEASURED OFF: NEVER lands here (the cite face).
        else if v.is("search_method") {
            if !w.fp_set_search_method(fp, v.get_string()) {
                return false; // :326-:327 (the C `if ( !... ) return false;` arm)
            }
        } else if v.is("offload_search_method") {
            // :325-:330 dialect face `#ifdef ENABLE_DETECTION_OFFLOAD`
            // (the set_offload_search_method + return-false arm)
            // `#else` (the ParseWarning(WARN_CONF, "..." deprecated
            // face)) `#endif` — MEASURED OFF: the #else arm is the
            // compile face, the warning rides the landed LogEngine
            // home (messages.rs :203 CITE-REUSE).
            w.log().parse_warning(
                WARN_CONF,
                "search_engine.offload_search_method is deprecated and has no effect",
                &[],
            ); // :329
        } else if v.is("split_any_any") {
            w.fp_set_split_any_any(fp, v.get_bool()); // :334 (CITE)
        } else if v.is("queue_limit") {
            w.fp_set_queue_limit(fp, v.get_uint32()); // :337 (CITE)
        }
        true // :339
    }
}

// ---------------------------------------------------------------------
// cc :365-:413 classification module
// ---------------------------------------------------------------------

/// cc :365-:382 `class ClassificationsModule : public Module` — the
/// list-ctor `Module("classifications", classifications_help,
/// classification_params, true)` (:367-:368 — is_list TRUE), the
/// begin/end/set decls (:370-:372), get_usage GLOBAL (:374-:375), the
/// privates name/text/priority (string/string/unsigned = 0 NSDMI)
/// (:378-:380).
pub struct ClassificationsModule {
    pub base: Module,        // cc :367-:368
    name: String,            // :378
    text: String,            // :379
    priority: u32,           // :380 (NSDMI 0)
}

impl Default for ClassificationsModule {
    fn default() -> Self { Self::new() }
}

impl ClassificationsModule {
    pub fn new() -> ClassificationsModule {
        ClassificationsModule {
            base: Module::new_params("classifications", CLASSIFICATIONS_HELP, Some(&CLASSIFICATION_PARAMS), true), // :367-:368
            name: String::new(),
            text: String::new(),
            priority: 0,
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :375
    }

    /// cc :384-:390 begin — the name/text erase + priority = 1
    /// :388 trio, ALL-true.
    pub fn begin(&mut self) -> bool {
        self.name.clear(); // :386
        self.text.clear(); // :387
        self.priority = 1; // :388
        true               // :389
    }

    /// cc :392-:397 end(fqn-unread, idx, sc) — the `if ( idx )
    /// add_classification(sc, name.c_str(), text.c_str(), priority)`
    /// leg (main/header.h free fn, body detection/signature.cc :100
    /// NOT landed -> the seam CITE).
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, idx: i32, w: &mut W) -> bool {
        if idx != 0 {
            w.add_classification(&self.name, &self.text, self.priority); // :395
        }
        true // :396
    }

    /// cc :399-:411 set — name / priority / text legs (the C
    /// `v.get_string() -> std::string` face rides the landed
    /// from_utf8_lossy posture, the 23c file face).
    pub fn set(&mut self, v: &mut Value) -> bool {
        if v.is("name") {
            self.name = String::from_utf8_lossy(v.get_string()).into_owned(); // :401
        } else if v.is("priority") {
            self.priority = v.get_uint32(); // :404
        } else if v.is("text") {
            self.text = String::from_utf8_lossy(v.get_string()).into_owned(); // :407
        }
        true // :410
    }
}

// ---------------------------------------------------------------------
// cc :511-:610 multiprocess data bus module
// ---------------------------------------------------------------------

/// cc :511-:530 `class MPDataBusModule : public Module` — the list of
/// plain-ctor + decls (`Module("mp_data_bus", mp_data_bus_help,
/// mp_data_bus_params)` :513-:514, is_list false via the C default);
/// the set/begin/end decls carry the cc :517 / :519 `// cppcheck-
/// suppress uselessOverride ; override retained to document the
/// derived interface contract` comment faces (cited, NEVER
/// attributes); get_commands/get_pegs/get_counts/reset_stats/
/// sum_stats decls (:522-:526); get_usage GLOBAL (:528-:529). The MP
/// statics (cc :546 mp_max_eventq_size, :551 transport, :555
/// enable_debug, the dialect :557-:561 hold_events) live at frame-
/// work/mp_data_bus.h :136-:140 CLASS statics in the C — the record-
/// threading deviation lands them as caller-threaded fields on the
/// MpDataBusLite record the seam + this module both drive (NOT-
/// landed bus family, cited).
#[derive(Default, Clone, Debug)]
pub struct MpDataBusLite {
    pub mp_max_eventq_size: u32,   // mp_data_bus.h :136
    pub transport: String,         // h :137 (the DEFAULT_TRANSPORT "unix_transport" identity h :52, cite)
    pub enable_debug: bool,        // h :138
}

pub struct MPDataBusModule {
    pub base: Module, // cc :513-:514
}

impl Default for MPDataBusModule {
    fn default() -> Self { Self::new() }
}

impl MPDataBusModule {
    pub fn new() -> MPDataBusModule {
        MPDataBusModule {
            base: Module::new_params("mp_data_bus", MP_DATA_BUS_HELP, Some(&MP_DATA_BUS_PARAMS), false), // :513-:514
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :529
    }

    /// cc :532-:535 begin — the empty-body true face (the useless-
    /// override cite pair rides at the decl).
    pub fn begin(&mut self) -> bool {
        true // :534
    }

    /// cc :537-:540 end — the empty-body true face.
    pub fn end(&mut self) -> bool {
        true // :539
    }

    /// cc :542-:567 set — the bus-static writer legs ride the caller-
    /// threaded MpDataBusLite; the :563-:565 else arm drives the
    /// landed WarningMessage face (messages.rs :370 REUSE through the
    /// seam log()) + `return false` (:566).
    pub fn set<W: ModulesWorld + ?Sized>(
        &mut self,
        v: &mut Value,
        bus: &mut MpDataBusLite,
        w: &mut W,
    ) -> bool {
        if v.is("max_eventq_size") {
            bus.mp_max_eventq_size = v.get_uint32(); // :546
        } else if v.is("transport") {
            bus.transport = String::from_utf8_lossy(v.get_string()).into_owned(); // :551
        } else if v.is("debug") {
            bus.enable_debug = v.get_bool(); // :555
        }
        // :556-:561 dialect face `#ifdef REG_TEST` else-if hold_events
        // (bus.hold_events = v.get_bool()) `#endif` — MEASURED OFF:
        // the arm NEVER lands (the cite face).
        else {
            let name = v.get_name().unwrap_or(""); // :564 v.get_name()
            w.log().warning_message(
                "MPDataBus: Unknown parameter '%s' in mp_data_bus module\n",
                &[Arg::S(Some(name.into()))],
            ); // :564 (the home REUSE, this TU only formats the C args)
            return false; // :566
        }
        true // :567
    }

    /// cc :570-:572 get_commands -> mp_dbus_cmds (the table above).
    pub fn get_commands() -> &'static [Command; 6] {
        &MP_DBUS_CMDS // :571
    }

    /// cc :575-:577 get_pegs -> mp_databus_pegs — that table lives at
    /// framework/mp_data_bus.h :79-:86 (the bus family's landed CITE
    /// face at its home; this row NEVER re-forks it: the cite names
    /// the identity).
    pub fn get_pegs_cite() -> &'static str {
        "mp_databus_pegs @ framework/mp_data_bus.h :79-:86 (CITE, NEVER re-forked)" // :576
    }

    /// cc :580-:582 get_counts -> const_cast<PegCount*>(counts[
    /// get_instance_id()].data()) — the landed framework Module counts
    /// face (module.rs :288) drives the base state; the alias seat NOT
    /// callable-port (the 23c cite), the twin seeds base.counts like
    /// the sfdaq precedent.
    ///
    /// cc :585-:592 reset_stats — the if(mp_dbus) reset leg (seam
    /// CITE) + the Module::reset_stats() BASE call (the landed
    /// module.rs :794 posture rides the twin; cited).
    pub fn reset_stats<W: ModulesWorld + ?Sized>(&mut self, w: &mut W) {
        if w.mp_dbus_present() {
            w.mp_dbus_reset_stats(); // :587-:589
        }
        // :591 `Module::reset_stats();` — the landed base reset rides
        // the framework home (module.rs :794) at the twin, CITE.
    }

    /// cc :594-:610 sum_stats(dump_stats) — the instance-0 gate
    /// (:595-:596 `if (get_instance_id() != 0) return;` — the landed
    /// instance leg rides the caller arg, the thread-local C face cited),
    /// the bus stats-copy (:600) NEVER-landed, and the :601-:604 per-
    /// count set_peg_count loop over the reinterpret_cast stats face —
    /// the alias legs ride the seam CITE posture (the twin drives the
    /// landed set_peg_count face, module.rs :897).
    pub fn sum_stats<W: ModulesWorld + ?Sized>(
        &mut self,
        dump_stats: bool,
        instance_id: u32,
        w: &mut W,
    ) {
        if instance_id != 0 {
            return; // :595-:596
        }
        if w.mp_dbus_present() {
            // :600 `auto stats = ...get_stats_copy();` + the
            // :601-:604 `for (int i = 0; i < get_num_counts(); i++)
            // set_peg_count(i, reinterpret_cast<PegCount*>(&stats)[i],
            // dump_stats);` — the bus stats family NOT landed: seam
            // CITE ONLY (the legs NEVER fabricate stats).
            let _ = dump_stats;
        }
    }
}

// ---------------------------------------------------------------------
// cc :616-:648 reload_survivor module — the pegs/stats faces ride the
// LANDED reload_survivor_subscriptions.rs home (CITE-REUSE census):
// RSS_PEGS :914 / RSS_STATS :907 / rss_stats_to_pegcounts :945 / the
// RssStats::reset :883. NEVER a re-forked table HERE.
// ---------------------------------------------------------------------

/// cc :616-:648 `class ReloadSurvivorSubscriptionsModule : public
/// Module` — the 2-arg ctor `Module("reload_survivor", reload_
/// survivor_help)` (:618-:619, the no-params face -> the landed NULL_
/// PARAMS posture at framework/module.rs :67 via init); the inlined
/// get_pegs/get_counts/prep_counts/reset_stats/global_stats/get_usage
/// bodies below.
pub struct ReloadSurvivorSubscriptionsModule {
    pub base: Module, // cc :618-:619
}

impl Default for ReloadSurvivorSubscriptionsModule {
    fn default() -> Self { Self::new() }
}

impl ReloadSurvivorSubscriptionsModule {
    pub fn new() -> ReloadSurvivorSubscriptionsModule {
        let base = Module::new("reload_survivor", RELOAD_SURVIVOR_HELP); // the C 2-arg ctor face (module.cc :62-:63) — init installs NULL_PARAMS (:59 posture)
        ReloadSurvivorSubscriptionsModule { base }
    }

    /// cc :622-:623 `get_pegs() { return snort::rss_pegs; }` — the
    /// home face RSS_PEGS (reload_survivor_subscriptions.rs :914).
    pub fn get_pegs() -> &'static [PegInfo; 13] {
        &RSS_PEGS // :623 (REUSE the landed home)
    }

    /// cc :625-:626 get_counts -> const_cast counts[instance].data()
    /// (the landed base counts face; the alias seat cited).
    ///
    /// cc :628-:639 prep_counts(bool unread) — the `// dump/shutdown
    /// path calls prep_counts, not sum_stats(true); snapshot must
    /// happen here` comment face (the cc :627 comment), the instance-0
    /// gate (:632-:633) and the :636
    /// `snort::rss_stats_to_pegcounts(snort::rss_stats, counts[0].
    /// data())` leg -> the landed rss_stats_to_pegcounts (:945) over
    /// RSS_STATS (:907) into the caller-seeded base counts.
    pub fn prep_counts(&mut self, instance_id: u32, counts0: &mut [PegCount]) {
        if instance_id != 0 {
            return; // :632-:633
        }
        rss_stats_to_pegcounts(&RSS_STATS, counts0); // :636 (REUSE the landed home)
    }

    /// cc :637-:641 reset_stats — the RSS_STATS reset (the landed
    /// RssStats::reset :883 REUSE) + the Module::reset_stats BASE call
    /// (module.rs :794 cited at the twin).
    pub fn reset_stats(&mut self) {
        RSS_STATS.reset(); // :639 (REUSE the landed home)
    }

    /// cc :647 `bool global_stats() const override { return true; }`.
    pub fn global_stats() -> bool {
        true // :644
    }

    /// cc :646-:647 `Usage get_usage() const override { return GLOBAL; }`.
    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :647
    }
}

// ---------------------------------------------------------------------
// cc :668-:709 reference module
// ---------------------------------------------------------------------

/// cc :668-:684 `class ReferencesModule : public Module` — the list-
/// ctor `Module("references", reference_help, reference_params, true)`
/// (:670-:671), begin/end/set (:673-:675), get_usage GLOBAL
/// (:677-:678), the privates name/url (:681-:682).
pub struct ReferencesModule {
    pub base: Module, // cc :670-:671
    name: String,     // :681
    url: String,      // :682
}

impl Default for ReferencesModule {
    fn default() -> Self { Self::new() }
}

impl ReferencesModule {
    pub fn new() -> ReferencesModule {
        ReferencesModule {
            base: Module::new_params("references", REFERENCE_HELP, Some(&REFERENCE_PARAMS), true), // :670-:671
            name: String::new(),
            url: String::new(),
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :678
    }

    /// cc :686-:691 begin — the name/url erase duo, ALL-true.
    pub fn begin(&mut self) -> bool {
        self.name.clear(); // :688
        self.url.clear();  // :689
        true               // :690
    }

    /// cc :693-:698 end(idx) — the `if ( idx ) reference_system_add
    /// (sc, name, url.c_str())` leg (the seam CITE: the body rides
    /// detection/reference.cc, NOT landed).
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, idx: i32, w: &mut W) -> bool {
        if idx != 0 {
            w.reference_system_add(&self.name, &self.url); // :695
        }
        true // :697
    }

    /// cc :700-:709 set — name / url legs.
    pub fn set(&mut self, v: &mut Value) -> bool {
        if v.is("name") {
            self.name = String::from_utf8_lossy(v.get_string()).into_owned(); // :702
        } else if v.is("url") {
            self.url = String::from_utf8_lossy(v.get_string()).into_owned(); // :705
        }
        true // :708
    }
}

// ---------------------------------------------------------------------
// cc :747-:780 alerts module
// ---------------------------------------------------------------------

/// cc :747-:755 `class AlertsModule : public Module` — ctor (:749),
/// the set decl (:750), get_usage GLOBAL (:752-:753).
pub struct AlertsModule {
    pub base: Module, // cc :749
}

impl Default for AlertsModule {
    fn default() -> Self { Self::new() }
}

impl AlertsModule {
    pub fn new() -> AlertsModule {
        AlertsModule {
            base: Module::new_params("alerts", ALERTS_HELP, Some(&ALERTS_PARAMS), false), // :749
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :753
    }

    /// cc :757-:780 set(fqn-unread, v, sc) — the sc-member legs ride
    /// the ScWriteBag (the record-threading deviation); the memcap
    /// trio rides the caller-threaded DetectionFilterConfigLite /
    /// ThresholdConfigLite / RateFilterConfigLite; the update_mask
    /// legs ride the landed Value::update_mask_u32 (value.rs :610 —
    /// the C `v.update_mask(sc->output_flags, FLAG)` face =
    /// update_mask(mask, flag, invert=false)). The :771 reference_net
    /// leg rides the landed SfCidr::set_str (sf_cidr.rs :29) ==
    /// SfIpRet::Success (sf_returns.rs :7, the SFIP_SUCCESS face).
    pub fn set<W: ModulesWorld + ?Sized>(
        &mut self,
        v: &mut Value,
        dfc: &mut DetectionFilterConfigLite,
        thc: &mut ThresholdConfigLite,
        rfc: &mut RateFilterConfigLite,
        homenet: &mut crate::sfip::sf_cidr::SfCidr,
        w: &mut W,
    ) -> bool {
        let sc = w.sc();
        if v.is("alert_with_interface_name") {
            v.update_mask_u32(&mut sc.output_flags, OUTPUT_FLAG__ALERT_IFACE, false); // :759
        } else if v.is("detection_filter_memcap") {
            dfc.memcap = v.get_uint32(); // :762
        } else if v.is("event_filter_memcap") {
            thc.memcap = v.get_uint32(); // :765
        } else if v.is("log_references") {
            v.update_mask_u32(&mut sc.output_flags, OUTPUT_FLAG__ALERT_REFS, false); // :768 (the re-borrow: sc field after the mask move)
        } else if v.is("order") {
            sc.rule_order = String::from_utf8_lossy(v.get_string()).into_owned(); // :771
        } else if v.is("rate_filter_memcap") {
            rfc.memcap = v.get_uint32(); // :774
        } else if v.is("reference_net") {
            // :777 `return ( sc->homenet.set(v.get_string()) ==
            // SFIP_SUCCESS );` — the landed set_str face + the
            // SUCCESS ordinal REUSE; the string face from the C char*.
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            return homenet.set_str(&s) == SfIpRet::Success; // :777
        } else if v.is("tunnel_verdicts") {
            sc.tunnel_verdicts = String::from_utf8_lossy(v.get_string()).into_owned(); // :780 (snort_config.h :486 set_tunnel_verdicts body NOT landed, the bag field cites)
        }
        true // :782
    }
}

// ---------------------------------------------------------------------
// cc :883-:955 output module
// ---------------------------------------------------------------------

/// cc :883-:900 `class OutputModule : public Module` — ctor (:885),
/// the set decl (:886), get_usage GLOBAL (:888-:889), the inlined
/// get_gid -> GID_TAG (:891-:892), get_rules -> output_rules
/// (:894-:895), get_commands -> output_cmds (:897-:898).
pub struct OutputModule {
    pub base: Module, // cc :885
}

impl Default for OutputModule {
    fn default() -> Self { Self::new() }
}

impl OutputModule {
    pub fn new() -> OutputModule {
        OutputModule {
            base: Module::new_params("output", OUTPUT_HELP, Some(&OUTPUT_PARAMS), false), // :885
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :889
    }

    /// cc :891-:892 `unsigned get_gid() const { return GID_TAG; }`.
    pub const fn get_gid() -> u32 {
        GID_TAG // :892
    }

    /// cc :894-:895 get_rules -> output_rules (the table above).
    pub fn get_rules() -> &'static [RuleMap; 2] {
        &OUTPUT_RULES // :895
    }

    /// cc :897-:898 get_commands -> output_cmds (the table above; the
    /// Lua arms ride the enable_/disable_log_buffered cite faces).
    pub fn get_commands() -> &'static [Command; 3] {
        &OUTPUT_CMDS // :898
    }

    /// cc :902-:955 set — the output-flags / log legs. The :915 quiet
    /// arm `if ( v.get_bool() ) SnortConfig::set_log_quiet(true)`
    /// rides the landed LogEngine::set_log_quiet (messages.rs :139,
    /// REUSE through the seam log()). The :944-:948 log_buffered arm
    /// drives the seam BatchedLogger CITE legs + the update_mask on
    /// the LANDED OUTPUT_FLAG_LOG_BUFFERED identity (messages.rs :40
    /// REUSE).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        if v.is("dump_chars_only") {
            v.update_mask_u32(&mut w.sc().output_flags, OUTPUT_FLAG__CHAR_DATA, false); // :904
        } else if v.is("dump_payload") {
            v.update_mask_u32(&mut w.sc().output_flags, OUTPUT_FLAG__APP_DATA, false); // :907
        } else if v.is("dump_payload_verbose") {
            v.update_mask_u32(&mut w.sc().output_flags, OUTPUT_FLAG__VERBOSE_DUMP, false); // :910
        } else if v.is("quiet") {
            if v.get_bool() {
                w.log().set_log_quiet(true); // :915-:916 (messages.rs :139 REUSE)
            }
        } else if v.is("logdir") {
            w.sc().log_dir = String::from_utf8_lossy(v.get_string()).into_owned(); // :919
        } else if v.is("max_data") {
            // :922 the OUTPUT_EVENT_TRACE table's member leg (the C
            // event_trace_max slot lands off the child-table face):
            w.sc().event_trace_max = v.get_uint16(); // :922
        } else if v.is("show_year") {
            v.update_mask_u32(&mut w.sc().output_flags, OUTPUT_FLAG__INCLUDE_YEAR, false); // :925
        } else if v.is("tagged_packet_limit") {
            w.sc().tagged_packet_limit = v.get_uint32(); // :928
        } else if v.is("verbose") {
            if v.get_bool() {
                w.enable_log_verbose(); // :932-:934 (SnortConfig::enable_log_verbose NOT landed, seam CITE)
            }
        } else if v.is("wide_hex_dump") {
            v.update_mask_u32(&mut w.sc().output_flags, OUTPUT_FLAG__WIDE_HEX, false); // :937 (the :234-style default pair rides OUTPUT_FLAG__WIDE_HEX, h :104/:214 cited)
        } else if v.is("obfuscate") {
            v.update_mask_u32(&mut w.sc().output_flags, OUTPUT_FLAG__OBFUSCATE, false); // :940
        } else if v.is("log_buffered") {
            if v.get_bool() {
                w.batched_log_init(); // :944-:946 (BatchedLogger NOT landed, seam CITE)
            } else {
                w.batched_log_shutdown(); // :947-:949 (CITE)
            }
            v.update_mask_u32(&mut w.sc().output_flags, OUTPUT_FLAG__LOG_BUFFERED, false); // :951 (the landed log/messages.rs :40 identity REUSE)
        }
        true // :954
    }
}

// ---------------------------------------------------------------------
// cc :994-:1030 active module
// ---------------------------------------------------------------------

/// cc :994-:1008 `class ActiveModule : public Module` — ctor (:996),
/// the set decl (:997), the inlined get_pegs -> active_pegs
/// (:999-:1000), get_counts -> (PegCount*)get_active_counts()
/// (:1002-:1003 — the packet_io/active.rs :415 get_active_counts home
/// REUSE CITE, the cast seat NOT callable-port), get_usage GLOBAL
/// (:1005-:1006).
pub struct ActiveModule {
    pub base: Module, // cc :996
}

impl Default for ActiveModule {
    fn default() -> Self { Self::new() }
}

impl ActiveModule {
    pub fn new() -> ActiveModule {
        ActiveModule {
            base: Module::new_params("active", ACTIVE_HELP, Some(&ACTIVE_PARAMS), false), // :996
        }
    }

    /// the home cite face: the active peg names ride ACTIVE_PEGS
    /// above; the counts identity rides packet_io/active.rs :415
    /// (23h ActiveCounts), cited NEVER re-forked.
    pub fn get_pegs() -> &'static [PegInfo; 8] {
        &ACTIVE_PEGS // :1000
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :1006
    }

    /// cc :1010-:1030 set — the respond_* sc legs (the :1019
    /// set_dst_mac leg = snort_config.h :472, NOT landed body: the bag
    /// field cites).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        let sc = w.sc();
        if v.is("attempts") {
            sc.respond_attempts = v.get_uint8(); // :1013
        } else if v.is("device") {
            sc.respond_device = String::from_utf8_lossy(v.get_string()).into_owned(); // :1016
        } else if v.is("dst_mac") {
            sc.dst_mac = String::from_utf8_lossy(v.get_string()).into_owned(); // :1019 (the set_dst_mac body NOT landed, cited)
        } else if v.is("max_responses") {
            sc.max_responses = v.get_uint8(); // :1022
        } else if v.is("min_interval") {
            sc.min_interval = v.get_uint8(); // :1025
        }
        true // :1028
    }
}

// ---------------------------------------------------------------------
// cc :1060-:1093 packets module
// ---------------------------------------------------------------------

/// cc :1060-:1068 `class PacketsModule : public Module` — ctor (:1062),
/// the set decl, get_usage GLOBAL (:1065-:1066).
pub struct PacketsModule {
    pub base: Module, // cc :1062
}

impl Default for PacketsModule {
    fn default() -> Self { Self::new() }
}

impl PacketsModule {
    pub fn new() -> PacketsModule {
        PacketsModule {
            base: Module::new_params("packets", PACKETS_HELP, Some(&PACKETS_PARAMS), false), // :1062
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :1066
    }

    /// cc :1070-:1093 set — the six sc legs.
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        let sc = w.sc();
        if v.is("address_space_agnostic") {
            sc.asid_agnostic = v.get_bool(); // :1073
        } else if v.is("bpf_file") {
            sc.bpf_file = String::from_utf8_lossy(v.get_string()).into_owned(); // :1076
        } else if v.is("limit") {
            sc.pkt_cnt = v.get_uint64(); // :1079
        } else if v.is("mpls_agnostic") {
            sc.mpls_agnostic = v.get_bool(); // :1082 (the C init-true default face cited at ScWriteBag census)
        } else if v.is("skip") {
            sc.pkt_skip = v.get_uint64(); // :1085
        } else if v.is("vlan_agnostic") {
            sc.vlan_agnostic = v.get_bool(); // :1088
        }
        true // :1091
    }
}

// ---------------------------------------------------------------------
// cc :1121-:1166 attribute_table module (the segments power-of-2
// ladder with the highestBitSet while-shift face — REAL byte math)
// ---------------------------------------------------------------------

/// cc :1121-:1130 `class AttributeTableModule : public Module` — ctor
/// (:1123-:1124 — the C passes the NON-const attribute_table_help
/// pointer, the :1118 face), the set decl (:1125), get_usage GLOBAL
/// (:1127-:1128).
pub struct AttributeTableModule {
    pub base: Module, // cc :1123-:1124
}

impl Default for AttributeTableModule {
    fn default() -> Self { Self::new() }
}

impl AttributeTableModule {
    pub fn new() -> AttributeTableModule {
        AttributeTableModule {
            base: Module::new_params("attribute_table", ATTRIBUTE_TABLE_HELP, Some(&ATTRIBUTE_TABLE_PARAMS), false), // :1123-:1124
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :1128
    }

    /// cc :1132-:1166 set — the max_hosts / attribute-file / services
    /// legs ride the bag; the segments leg lands the C power-of-2
    /// ladder VERBATIM: :1141-:1142 the >32 clamp; :1144 the `== 0 ||
    /// (& (x-1)) != 0` not-power-of-2 gate; the :1146-:1147
    /// `uint8_t highestBitSet = 0; while (segments >>= 1)
    /// highestBitSet++;` shift ladder; the :1148 `segments = 1 <<
    /// highestBitSet` rebuild; the :1149 LogMessage WARNING leg (the
    /// format string + the %d value ride the landed log_message_stdout
    /// home, messages.rs :353 REUSE through the seam; the C face is
    /// the stdout LogMessage — the seam owns the sink). NOTE the C
    /// `while (segments >>= 1)` also fires the segments == 0 arm but
    /// 0 >>= 1 stays 0 so highestBitSet stays 0 -> `1 << 0` = 1 (the
    /// ported arithmetic reproduces BOTH arms exactly).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        let v_u32 = v.get_uint32();
        if v.is("hosts_file") {
            w.sc().attribute_hosts_file = String::from_utf8_lossy(v.get_string()).into_owned(); // :1136
        } else if v.is("max_hosts") {
            w.sc().max_attribute_hosts = v_u32; // :1139
        } else if v.is("segments") {
            let mut segments = v_u32; // :1140 auto segments = v.get_uint32()
            if segments > 32 {
                segments = 32; // :1141-:1142
            }
            if segments == 0 || (segments & (segments - 1)) != 0 {
                // :1146-:1148 the highestBitSet while-shift ladder —
                // the C uint8_t counter face kept (a C overflow at
                // bit > 7 is IMPOSSIBLE past the :1141 clamp <= 32).
                let mut highest_bit_set: u8 = 0;
                loop {
                    segments >>= 1; // the C while-conditional shift
                    if segments == 0 {
                        break;
                    }
                    highest_bit_set += 1;
                }
                segments = 1u32 << highest_bit_set; // :1148
                w.log().log_message_stdout(
                    "== WARNING: host attribute table segments count is not a power of 2. setting to %d\n",
                    &[Arg::I(segments as i64)],
                ); // :1149 (the home REUSE, this TU formats the C args)
            }
            w.sc().segment_count_host = segments; // :1157
        } else if v.is("max_services_per_host") {
            // :1159 the uint32 slot <- the C get_uint16 face (the
            // head-measured slot widths pair, cited).
            w.sc().max_attribute_services_per_host = u32::from(v.get_uint16()); // :1159
        } else if v.is("max_metadata_services") {
            w.sc().max_metadata_services = v.get_uint8(); // :1162
        }
        true // :1165
    }
}

// ---------------------------------------------------------------------
// cc :1194-:1240 inspection policy module
// ---------------------------------------------------------------------

/// cc :1194-:1202 `class InspectionModule : public Module` — ctor
/// (:1196), the set decl (:1197), get_usage INSPECT (:1199-:1200).
pub struct InspectionModule {
    pub base: Module, // cc :1196
}

impl Default for InspectionModule {
    fn default() -> Self { Self::new() }
}

impl InspectionModule {
    pub fn new() -> InspectionModule {
        InspectionModule {
            base: Module::new_params("inspection", INSPECTION_HELP, Some(&INSPECTION_PARAMS), false), // :1196
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_INSPECT // :1200 (the landed codec_module.rs :276 home)
    }

    // cc :1204-:1240 set(fqn-unread, v, sc) — the p = get_
    // inspection_policy() reach (main/policy.h :93; the landed
    // policy.rs carries NO InspectionPolicy record yet — the seam
    // Option writer legs, cited): id / mode legs; then the dialect
    // face :1211-:1220 `#ifdef HAVE_UUID` the uuid arm (uuid_parse !=
    // 0 -> ParseError("Invalid Inspection UUID: %s") + uuid_clear(
    // p->uuid)) `#endif` — MEASURED OFF: NEVER lands (the cite face);
    // the max_aux_ip sc leg (:1235). The mode arm = the switch over
    // v.get_uint8() (:1223-:1232): case 0 -> POLICY_MODE__INLINE,
    // case 1 -> POLICY_MODE__INLINE_TEST, default no-op — the landed
    // PolicyMode enum (main/policy.rs :23-:29 Passive/Inline/
    // InlineTest/Max ordinals 0/1/2/3, CITED: the ground POLICY_MODE__
    // TAP=0/INLINE=1/INLINE_TEST=2 face).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        if v.is("id") {
            if let Some(id) = w.inspection_user_policy_id() {
                *id = v.get_uint64(); // :1208
            }
        }
        // :1211-:1220 `#ifdef HAVE_UUID` uuid arm — dialect face
        // MEASURED OFF (never lands; uuid_parse/uuid_clear legs stay
        // cite-only at the OFF posture).
        else if v.is("mode") {
            match v.get_uint8() {
                0 => {
                    if let Some(m) = w.inspection_policy_mode() {
                        *m = PolicyMode::Inline; // :1226 (POLICY_MODE__INLINE)
                    }
                }
                1 => {
                    if let Some(m) = w.inspection_policy_mode() {
                        *m = PolicyMode::InlineTest; // :1229 (POLICY_MODE__INLINE_TEST)
                    }
                }
                _ => {} // :1231 default: break;
            }
        } else if v.is("max_aux_ip") {
            w.sc().max_aux_ip = v.get_int16(); // :1235
        }
        true // :1239
    }
}

// ---------------------------------------------------------------------
// cc :1379-:1541 IPS policy module (the pair's biggest class: the
// matches/:1397 leg, the set ladder with the strstr(fqn, "variables.
// *.") legs at :1426-:1443, and the end ladder :1478-:1541 — the
// action_map / policy-install / resolve / react-page ladders).
// ---------------------------------------------------------------------

/// cc :1379-:1395 `class IpsModule : public Module` — ctor (:1381),
/// the set/end/matches decls (:1382-:1384), get_usage DETECT
/// (:1386-:1387), the privates replace/with/action_var/
/// action_var_page (:1390-:1393, the std::string faces). The two
/// file-local fns the pair drives (get_var_name :1247 /
/// is_action_var_placeholder :1254) landed at the Ips-params census
/// block above (the ported fns — the Catch twin replays their faces).
pub struct IpsModule {
    pub base: Module,            // cc :1381
    replace: String,             // :1390
    with: String,                // :1391
    action_var: String,          // :1392
    action_var_page: String,     // :1393
}

impl Default for IpsModule {
    fn default() -> Self { Self::new() }
}

impl IpsModule {
    pub fn new() -> IpsModule {
        IpsModule {
            base: Module::new_params("ips", IPS_HELP, Some(&IPS_PARAMS), false), // :1381
            replace: String::new(),
            with: String::new(),
            action_var: String::new(),
            action_var_page: String::new(),
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_DETECT // :1387 (the landed codec_module.rs :278 home)
    }

    /// cc :1397 `bool matches(const char*, std::string&) { return
    /// true; }` — the ALL-true face.
    pub fn matches(&mut self, _fqn: &str, _name: &mut String) -> bool {
        true // :1397
    }

    /// cc :1400-:1476 set(fqn, v, sc-unread) — the p = get_ips_
    /// policy() reach rides the BORROWED landed IpsPolicy (policy.rs
    /// :51, the seam CITE-REUSE). The legs in C order:
    ///   action_override (:1404), default_rule_state (:1407 the
    ///   (IpsPolicy::Enable)v.get_uint8() cast -> the landed Enable
    ///   enum :32-:36 ordinals Disabled/Enabled/InheritEnable = C
    ///   DISABLED/ENABLED/INHERIT_ENABLE, cited), enable_builtin_
    ///   rules (:1410), id (:1413), include (:1416), mode (:1419 the
    ///   (PolicyMode)v.get_uint8() cast -> the landed PolicyMode face
    ///   cited (the C PolicyMode TAP/INLINE/INLINE_TEST/
    ///   INLINE_MAX ordinal law), obfuscate_pii (:1422), replace
    ///   (:1425 member), rules += (:1428 the C append face), states
    ///   += (:1431);
    ///   dialect face :1434-:1443 `#ifdef HAVE_UUID` the uuid arm —
    ///   MEASURED OFF (cite),
    ///   (:1445 the C `// FIXIT-M should only need one table with
    ///   dynamically typed vars` comment face rides this cite) then
    ///   the strstr legs: "variables.nets." -> ParseIpVar(get_var_
    ///   name(fqn), ...) :1448-:1449; "variables.paths." ->
    ///   ParsePathVar :1451-:1452; "variables.ports." -> ParsePortVar
    ///   :1454-:1455; "variables.actions." and v.is("page") :1457-
    ///   :1471 — the prefix-skip + strchr(name, '.') legs: a miss ->
    ///   ParseError("invalid IPS action variable '%s'") + false
    ///   (:1462-:1466, the landed LogEngine::parse_error :214 REUSE);
    ///   else the action_var.assign(name, name_end - name) (:1468) +
    ///   action_var_page = v.get_string() (:1469);
    ///   with (:1473).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, fqn: &str, v: &mut Value, w: &mut W) -> bool {
        // the C p = get_ips_policy() reach derefs blind; the Option
        // face NEVER crashes — the record-threading deviation (a miss
        // routes the p-arms to the skip face, cited at the seam). Each
        // p-arm RE-borrows the policy (the Rust face; the C one-borrow
        // face is the cite).
        if w.ips_policy().is_none() {
            return self.set_member_arms(fqn, v, w);
        }
        if v.is("action_override") {
            w.ips_policy().unwrap().action_override = String::from_utf8_lossy(v.get_string()).into_owned(); // :1404
        } else if v.is("default_rule_state") {
            // :1407 `(IpsPolicy::Enable)v.get_uint8()` -> the landed
            // Enable face (the ordinal cast arms cited).
            w.ips_policy().unwrap().default_rule_state = match v.get_uint8() {
                0 => Enable::Disabled,
                1 => Enable::Enabled,
                _ => Enable::InheritEnable, // the C cast past 2 = the harness posture face (the enum range arm, cited)
            };
        } else if v.is("enable_builtin_rules") {
            w.ips_policy().unwrap().enable_builtin_rules = v.get_bool(); // :1410
        } else if v.is("id") {
            w.ips_policy().unwrap().user_policy_id = v.get_uint64(); // :1413
        } else if v.is("include") {
            // :1416 `p->include = v.get_string();` — the landed
            // policy.rs IpsPolicy carries NO include string slot
            // (the includer face :64 is a DIFFERENT member): the C
            // include legs live in the NOT-landed parse_include
            // family (parser/parse_conf.cc :210 cite pair) — the
            // write rides the bag cite ledger, NEVER an invented
            // policy field.
            w.sc().ips_include = String::from_utf8_lossy(v.get_string()).into_owned(); // :1416 (CITE posture)
        } else if v.is("mode") {
            // :1419 `(PolicyMode)v.get_uint8()` -> the landed Policy-
            // Mode arms (the C TAP=0/INLINE=1/INLINE_TEST=2 heads).
            w.ips_policy().unwrap().policy_mode = match v.get_uint8() {
                0 => PolicyMode::Passive, // the C TAP face (the landed enum names Passive, cited)
                1 => PolicyMode::Inline,
                2 => PolicyMode::InlineTest,
                _ => PolicyMode::Max,     // the C INLINE_MAX arm
            };
        } else if v.is("obfuscate_pii") {
            w.ips_policy().unwrap().obfuscate_pii = v.get_bool(); // :1422
        } else if v.is("replace") {
            self.replace = String::from_utf8_lossy(v.get_string()).into_owned(); // :1425
        } else if v.is("rules") {
            // :1428 `p->rules += v.get_string();` — the landed policy
            // face carries NO rules string slot: the bag carries the
            // append ledger face (the rules/states NOT-landed policy
            // slots, cited; the C += face = push_str).
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            w.sc().rules.push_str(&s); // :1428
        } else if v.is("states") {
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            w.sc().states.push_str(&s); // :1431
        }
        // :1434-:1443 `#ifdef HAVE_UUID` uuid arm — dialect face
        // MEASURED OFF (never lands).
        else if fqn.contains("variables.nets.") {
            w.parse_ip_var(get_var_name(fqn), &String::from_utf8_lossy(v.get_string())); // :1448-:1449 (the landed parse_ip_var home via the seam)
        } else if fqn.contains("variables.paths.") {
            w.parse_path_var(get_var_name(fqn), &String::from_utf8_lossy(v.get_string())); // :1451-:1452
        } else if fqn.contains("variables.ports.") {
            w.parse_port_var(get_var_name(fqn), &String::from_utf8_lossy(v.get_string())); // :1454-:1455
        } else if fqn.contains("variables.actions.") && v.is("page") {
            // :1459-:1459 the prefix face + the strstr-skip + the
            // strchr leg (:1461): a miss = ParseError + false.
            let prefix = "variables.actions.";
            let Some(at) = fqn.find(prefix) else {
                // the strstr-false arm: the C never reaches (the
                // outer test gated it); kept honest, unreachable face.
                return true;
            };
            let name = &fqn[at + prefix.len()..]; // :1460 name += strlen(prefix)
            let Some(name_end) = name.find('.') else {
                let fqn_own = fqn.to_string();
                w.log().parse_error("invalid IPS action variable '%s'", &[Arg::S(Some(fqn_own.into()))]); // :1463-:1464
                return false; // :1465
            };
            self.action_var = name[..name_end].to_string(); // :1468 action_var.assign(name, name_end - name)
            self.action_var_page = String::from_utf8_lossy(v.get_string()).into_owned(); // :1469
        } else if v.is("with") {
            self.with = String::from_utf8_lossy(v.get_string()).into_owned(); // :1473
        }
        true // :1476
    }

    /// the member arms under a null policy (the C would DEREF-blind;
    /// the Option face routes the member legs ONLY): replace (:1425),
    /// the strstr legs ride the seam regardless, with (:1473), the
    /// page arm.
    fn set_member_arms<W: ModulesWorld + ?Sized>(&mut self, fqn: &str, v: &mut Value, w: &mut W) -> bool {
        if v.is("replace") {
            self.replace = String::from_utf8_lossy(v.get_string()).into_owned(); // :1425 (member face)
        } else if v.is("with") {
            self.with = String::from_utf8_lossy(v.get_string()).into_owned(); // :1473 (member face)
        } else if fqn.contains("variables.actions.") && v.is("page") {
            let prefix = "variables.actions.";
            if let Some(at) = fqn.find(prefix) {
                let name = &fqn[at + prefix.len()..];
                if let Some(name_end) = name.find('.') {
                    self.action_var = name[..name_end].to_string(); // :1468
                    self.action_var_page = String::from_utf8_lossy(v.get_string()).into_owned(); // :1469
                } else {
                    let fqn_own = fqn.to_string();
                    w.log().parse_error("invalid IPS action variable '%s'", &[Arg::S(Some(fqn_own.into()))]); // :1463-:1464
                    return false; // :1465
                }
            }
        } else if fqn.contains("variables.nets.") {
            w.parse_ip_var(get_var_name(fqn), &String::from_utf8_lossy(v.get_string())); // :1448-:1449
        } else if fqn.contains("variables.paths.") {
            w.parse_path_var(get_var_name(fqn), &String::from_utf8_lossy(v.get_string())); // :1451-:1452
        } else if fqn.contains("variables.ports.") {
            w.parse_port_var(get_var_name(fqn), &String::from_utf8_lossy(v.get_string())); // :1454-:1455
        }
        true
    }

    /// cc :1478-:1541 end(fqn, idx, sc) — the ladder VERBATIM:
    ///   `if ( idx and !strcmp(fqn, "ips.action_map") )` :1480-:1492:
    ///   the replace/with empty pair -> ParseError("%s - must set both
    ///   replace and with") + false (:1482-:1487); else the p->
    ///   action_map[replace] = with (the landed BTreeMap face, policy
    ///   .rs :74 REUSE) + the clear duo (:1488-:1491);
    ///   `else if (!idx and !strcmp(fqn, "ips"))` :1493-:1497: the p->
    ///   includer = ModuleManager::get_includer("ips") (:1494 seam
    ///   CITE) + sc->policy_map->set_user_ips(p) (:1496 seam CITE);
    ///   `else if (!idx and !strcmp(fqn, "ips.variables.nets"))` :1498
    ///   -> resolve_nets(); `:1499` ports twin -> resolve_ports();
    ///   `else if (!idx and strstr(fqn, "ips.variables.actions.") and
    ///   strstr(fqn, ".react"))` :1501-:1540 — the action_var/
    ///   action_var_page empty pair arm (:1503-:1511): the iso_
    ///   placeholder escape (`if ( is_action_var_placeholder(fqn) )
    ///   return true;` :1505-:1507) then ParseError("%s - must set
    ///   react.page") + false (:1508-:1510); the capacity gate (:1514
    ///   ->1518 ParseError("too many IPS action variables") + false)
    ///   the landed has_action_variable_capacity (:119) REUSE; the
    ///   duplicate gate (:1520-:1525 ParseError("duplicate IPS action
    ///   variable '%s'") + false) the landed has_action_variable
    ///   (:123) REUSE + the landed LogEngine parse_error (:214); the
    ///   ActionManager::instantiate_action_with_param("react", "page",
    ///   ...) leg (:1527-:1529 seam CITE, a null action -> false :1530-
    ///   :1532); the commit_action_variable leg (:1534, the landed
    ///   policy.rs :127 REUSE through the seam borrow) + the clear duo
    ///   (:1536-:1537).
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, fqn: &str, idx: i32, w: &mut W) -> bool {
        if idx != 0 && fqn == "ips.action_map" {
            if self.replace.is_empty() || self.with.is_empty() {
                let fqn_own = fqn.to_string();
                w.log().parse_error("%s - must set both replace and with", &[Arg::S(Some(fqn_own.into()))]); // :1484-:1485
                return false; // :1486
            }
            if let Some(p) = w.ips_policy() {
                let (r, wi) = (self.replace.clone(), self.with.clone()); // the C map-insert face (the member reads first, cited)
                p.action_map.insert(r, wi); // :1489 (the landed BTreeMap :74 REUSE)
            }
            self.replace.clear(); // :1491
            self.with.clear();    // :1492
        } else if idx == 0 && fqn == "ips" {
            let inc = w.get_includer("ips"); // :1494 (get_includer NOT landed, seam CITE) — before the p borrow (the Rust face order; the C evaluation order :1494-:1496 cited)
            if let Some(p) = w.ips_policy() {
                p.includer = inc;                // :1494 the includer slot REUSE :64
            }
            w.set_user_ips_policy();             // :1496 (policy_map NOT landed, seam CITE)
        } else if idx == 0 && fqn == "ips.variables.nets" {
            w.resolve_nets(); // :1499 (the landed vars.rs :648 home via the seam)
        } else if idx == 0 && fqn == "ips.variables.ports" {
            w.resolve_ports(); // :1501 (the landed vars.rs :667 home via the seam)
        } else if idx == 0 && fqn.contains("ips.variables.actions.") && fqn.contains(".react") {
            if self.action_var.is_empty() || self.action_var_page.is_empty() {
                if is_action_var_placeholder(fqn) {
                    return true; // :1506 (the $var placeholder escape)
                }
                let fqn_own = fqn.to_string();
                w.log().parse_error("%s - must set react.page", &[Arg::S(Some(fqn_own.into()))]); // :1509-:1510
                return false; // :1511
            }
            let Some(p) = w.ips_policy() else {
                return false; // the C derefs the null face blind; the Rust Option NEVER does (deviation cited)
            };
            if !p.has_action_variable_capacity() {
                w.log().parse_error("too many IPS action variables", &[]); // :1517 (the landed :119 REUSE + parse_error :214)
                return false; // :1518
            }
            if p.has_action_variable(self.action_var.as_str()) {
                let av = self.action_var.clone();
                w.log().parse_error("duplicate IPS action variable '%s'", &[Arg::S(Some(av.into()))]); // :1523-:1524 (the landed :123 REUSE)
                return false; // :1525
            }
            if !w.instantiate_action_with_param("react", "page", &self.action_var_page.clone()) {
                return false; // :1527-:1533 (ActionManager NOT landed: the null-action arm -> false)
            }
            if let Some(p) = w.ips_policy() {
                let av = self.action_var.clone();
                // :1535 `policy->commit_action_variable(action_var,
                // "react", action)` — the landed policy.rs :127 face
                // REUSED through the seam (the action payload slot the
                // NOT-landed manager never fills rides the None
                // posture, cited).
                let reg = ActionRegistry::default(); // the landed registry (the get_action_type face :91 the commit leg needs, REUSE)
                p.commit_action_variable(&av, "react", None, &reg); // :1535
            }
            self.action_var.clear();     // :1537
            self.action_var_page.clear(); // :1538
        }
        true // :1540
    }
}

// ---------------------------------------------------------------------
// cc :1604-:1749 process module (the thread_pinning end-ladder: the
// cpuset/thread/type/name arms; the ThreadConfig legs REUSE the landed
// main/thread_config.rs homes through the seam — validate_cpuset_
// string :761 / destroy_cpuset :817 / set_thread_affinity :836 /
// set_named_thread_affinity :860 — NEVER re-forked; the SThreadType
// arms ride main/thread.rs :19, the DEFAULT_THREAD_ID the landed
// thread_config.rs :656)
// ---------------------------------------------------------------------

/// cc :1604-:1620 `class ProcessModule : public Module` — ctor (:1606),
/// the set/begin/end decls (:1607-:1609), get_usage GLOBAL (:1611-
/// :1612), the privates `int thread = 0` (:1616), `CpuSet* cpuset =
/// nullptr` (:1617 — the Option<CpuSet> face, the C delete-law cited),
/// string type (:1618), string name (:1619).
pub struct ProcessModule {
    pub base: Module,          // cc :1606
    thread: i32,               // :1616
    cpuset: Option<CpuSet>,    // :1617 (the nullptr posture)
    ctype: String,             // :1618 (the C `type` member: `type` is a Rust keyword-free face but reads clearer as ctype — the C name identity rides this cite)
    name: String,              // :1619
}

impl Default for ProcessModule {
    fn default() -> Self { Self::new() }
}

impl ProcessModule {
    pub fn new() -> ProcessModule {
        ProcessModule {
            base: Module::new_params("process", PROCESS_HELP, Some(&PROCESS_PARAMS), false), // :1606
            thread: 0,     // h :1616 NSDMI
            cpuset: None,  // :1617
            ctype: String::new(),
            name: String::new(),
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :1612
    }

    /// cc :1622-:1674 set — the sc write-legs ride the bag (the
    /// set_daemon/set_chroot_dir/set_dirty_pig/set_gid/set_uid/set_-
    /// umask/set_utc/set_watchdog/set_watchdog_min_thread_count faces
    /// snort_config.h :464-:492, the bodies NOT landed: the bag ledger
    /// cites); the :1642 `// FIXIT-M fix cmd line vs conf conflicts`
    /// comment face rides its cite. The cpuset leg (:1654-:1658) drives
    /// the landed ThreadConfig::validate_cpuset_string (thread_config.
    /// rs :761 REUSE) through the seam tc(): a None -> the `return
    /// false` arm (:1656). thread = v.get_uint16() (:1661), the type/
    /// name members (:1664/:1667).
    ///   dialect face :1668-:1671 `#ifdef HAVE_NUMA` numa_memory_policy
    ///   leg (`sc->thread_config->set_numa_mempolicy(v.get_string())`)
    ///   `#endif` — MEASURED OFF: the SET leg NEVER lands (the table
    ///   row itself lands: the honest C asymmetry, cited at the table).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        if v.is("daemon") {
            if v.get_bool() {
                w.sc().daemon = true; // :1634-:1636 (the set_daemon body NOT landed, cited; the FIXIT-M comment face :1635 rides here)
            }
        } else if v.is("chroot") {
            w.sc().chroot_dir = String::from_utf8_lossy(v.get_string()).into_owned(); // :1639
        } else if v.is("dirty_pig") {
            w.sc().dirty_pig = v.get_bool(); // :1642
        } else if v.is("set_gid") {
            w.sc().gid = String::from_utf8_lossy(v.get_string()).into_owned(); // :1645
        } else if v.is("set_uid") {
            w.sc().uid = String::from_utf8_lossy(v.get_string()).into_owned(); // :1648
        } else if v.is("umask") {
            w.sc().umask = v.get_uint32(); // :1651
        } else if v.is("utc") {
            w.sc().utc = v.get_bool(); // :1654
        } else if v.is("cpuset") {
            // :1656-:1659 the validate_cpuset_string leg — the landed
            // :761 home drives it (its LogEngine ParseError face
            // REUSED via the seam tc borrow); the C assignment-in-
            // condition posture = the Option face here.
            let shown = String::from_utf8_lossy(v.get_string()).into_owned();
            // :1657 `ThreadConfig::validate_cpuset_string` is a
            // STATIC leg in the C (no sc->thread_config deref on this
            // line) — the landed :761 home REUSE, the LogEngine
            // ParseError side face riding the seam log borrow.
            let log = w.log();
            let cp = ThreadConfig::validate_cpuset_string(Some(shown.as_str()), log); // :1657 (thread_config.rs :761 REUSE)
            if cp.is_none() {
                return false; // :1658 (`if (!(cpuset = ...)) return false;`)
            }
            self.cpuset = cp; // :1657 the member store
        } else if v.is("thread") {
            self.thread = i32::from(v.get_uint16()); // :1661
        } else if v.is("type") {
            self.ctype = String::from_utf8_lossy(v.get_string()).into_owned(); // :1664
        } else if v.is("name") {
            self.name = String::from_utf8_lossy(v.get_string()).into_owned(); // :1667
        } else if v.is("watchdog_timer") {
            w.sc().watchdog_timer = v.get_uint16(); // :1670
        } else if v.is("watchdog_min_thread_count") {
            w.sc().watchdog_min_thread_count = v.get_uint16(); // :1673
        }
        // :1668-:1671 `#ifdef HAVE_NUMA` set_numa_mempolicy leg —
        // dialect face MEASURED OFF (never lands; the table row at
        // :1595-:1596 lands — the honest asymmetry cited).
        true // :1675
    }

    /// cc :1677-:1683 begin — the thread = -1 / cpuset = nullptr /
    /// type/name clear quartet.
    pub fn begin(&mut self) -> bool {
        self.thread = -1;    // :1679
        self.cpuset = None;  // :1680
        self.ctype.clear();  // :1681
        self.name.clear();   // :1682
        true                 // :1683
    }

    /// cc :1685-:1749 end(fqn, idx, sc) — THE thread-pinning ladder:
    ///   `if ( !idx ) return true;` (:1687-:1688),
    ///   `if (!strcmp(fqn, "process.threads"))` (:1690):
    ///     the no-cpuset ParseError("%s - no cpuset specified") arm
    ///     (:1692-:1696, never destroys — the cpuset is already null);
    ///     `if (thread >= 0)` (:1699) the Packet-thread arm: the guard
    ///     `if ( !(name.empty() && (type.empty() || type == "packet"))
    ///     )` ParseError("%s - type or name specified for thread %d")
    ///     + destroy_cpuset + false (:1703-:1710, the ThreadConfig
    ///     :817 REUSE); else the implicit-packet install
    ///     set_thread_affinity(STHREAD_TYPE_PACKET, thread, cpuset)
    ///     (:1714-:1715, the landed :836 REUSE, the thread.h :27-:30
    ///     STHREAD_TYPE_PACKET=1 face cited);
    ///     `else if (!type.empty() && name.empty())` (:1718) the type
    ///     arm: thread = DEFAULT_THREAD_ID (:1721, the landed :656
    ///     REUSE), "main" -> STHREAD_TYPE_MAIN (:1722-:1723), "other"
    ///     -> STHREAD_TYPE_OTHER (:1724-:1725), else ParseError("%s -
    ///     bad thread type %s") + destroy + false (:1727-:1733);
    ///     `else if (type.empty() && !name.empty())` (:1736) the name
    ///     arm set_named_thread_affinity(name, cpuset) (:1739, the
    ///     landed :860 REUSE);
    ///     `else if (!type.empty() && !name.empty())` (:1741) both ->
    ///     ParseError("%s - can't specify both type and name") +
    ///     destroy + false (:1743-:1747);
    ///     ALL-else -> ParseError("%s - none of thread, type or name
    ///     specified") + destroy + false (:1748-:1752 face).
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, fqn: &str, idx: i32, w: &mut W) -> bool {
        if idx == 0 {
            return true; // :1687-:1688
        }
        if fqn == "process.threads" {
            let Some(cpuset) = self.cpuset.take() else {
                let fqn_own = fqn.to_string();
                w.log().parse_error("%s - no cpuset specified", &[Arg::S(Some(fqn_own.into()))]); // :1694-:1695
                return false; // :1696
            };
            if self.thread >= 0 {
                // :1703 the packet-thread guard
                if !(self.name.is_empty() && (self.ctype.is_empty() || self.ctype == "packet")) {
                    let fqn_own = fqn.to_string();
                    let th = self.thread;
                    w.log().parse_error("%s - type or name specified for thread %d", &[Arg::S(Some(fqn_own.into())), Arg::I(i64::from(th))]); // :1705-:1706
                    ThreadConfig::destroy_cpuset(Some(cpuset)); // :1707 (thread_config.rs :817 REUSE)
                    return false; // :1708
                }
                // :1712-:1715 `// Packet thread affinity` + the C
                // comment `// Thread type is implicitly "packet"`:
                let (tc, log) = w.tc_and_log();
                if let Some(tc) = tc {
                    tc.set_thread_affinity(SThreadType::Packet, self.thread as u32, cpuset, log); // :1715 (thread_config.rs :836 REUSE; the thread.h :29 STHREAD_TYPE_PACKET face)
                } else {
                    // the C sc->thread_config blind deref: the Option
                    // NEVER crashes (a dropped cpuset = the Drop face,
                    // cited).
                    ThreadConfig::destroy_cpuset(Some(cpuset));
                }
            } else if !self.ctype.is_empty() && self.name.is_empty() {
                self.thread = std::cmp::max(DEFAULT_THREAD_ID as i32, -1); // :1721 `thread = ThreadConfig::DEFAULT_THREAD_ID` (the landed :656 REUSE; the i32 face widening cited)
                if self.ctype == "main" {
                    self.install_thread_affinity(w, SThreadType::Main, cpuset); // :1723 (STHREAD_TYPE_MAIN thread.h :30 face)
                } else if self.ctype == "other" {
                    self.install_thread_affinity(w, SThreadType::Other, cpuset); // :1725 (STHREAD_TYPE_OTHER thread.h :27 face)
                } else {
                    let fqn_own = fqn.to_string();
                    let t = self.ctype.clone();
                    w.log().parse_error("%s - bad thread type %s", &[Arg::S(Some(fqn_own.into())), Arg::S(Some(t.into()))]); // :1729-:1730
                    ThreadConfig::destroy_cpuset(Some(cpuset)); // :1731 (the :817 REUSE)
                    return false; // :1732
                }
            } else if self.ctype.is_empty() && !self.name.is_empty() {
                // :1738 `// name-based affinity` + :1740 the landed
                // :860 REUSE (the C leak-face arm thread_config.rs
                // :860-:873 owns the posture, cited there).
                let name = self.name.clone();
                let (tc, log) = w.tc_and_log();
                if let Some(tc) = tc {
                    tc.set_named_thread_affinity(&name, cpuset, log); // :1740 (thread_config.rs :860 REUSE)
                } else {
                    ThreadConfig::destroy_cpuset(Some(cpuset)); // the Drop face (cited)
                }
            } else if !self.ctype.is_empty() && !self.name.is_empty() {
                let fqn_own = fqn.to_string();
                w.log().parse_error("%s - can't specify both type and name", &[Arg::S(Some(fqn_own.into()))]); // :1744-:1745
                ThreadConfig::destroy_cpuset(Some(cpuset)); // :1746 (the :817 REUSE)
                return false; // :1747
            } else {
                let fqn_own = fqn.to_string();
                w.log().parse_error("%s - none of thread, type or name specified", &[Arg::S(Some(fqn_own.into()))]); // :1749-:1750
                ThreadConfig::destroy_cpuset(Some(cpuset)); // :1751 (the :817 REUSE)
                return false; // :1752
            }
        }
        true // :1754
    }

    /// the type-arm install face (the tc-borrow dance the ladder shares
    /// between the main/other arms).
    fn install_thread_affinity<W: ModulesWorld + ?Sized>(
        &mut self,
        w: &mut W,
        kind: SThreadType,
        cpuset: CpuSet,
    ) {
        let id = self.thread as u32; // :1721 the DEFAULT_THREAD_ID face already stored
        let (tc, log) = w.tc_and_log();
        if let Some(tc) = tc {
            tc.set_thread_affinity(kind, id, cpuset, log); // :1723 / :1726 (thread_config.rs :836 REUSE)
        } else {
            ThreadConfig::destroy_cpuset(Some(cpuset)); // the Drop face (cited)
        }
    }
}

// ---------------------------------------------------------------------
// cc :1776-:1843 suppress module (the THDX arms)
// ---------------------------------------------------------------------

/// cc :1776-:1790 `class SuppressModule : public Module` — the list
/// ctor `Module("suppress", suppress_help, suppress_params, true)`
/// (:1778-:1779), the set/begin/end decls (:1781-:1783), the cc :1785
/// useless-override comment face over get_usage CONTEXT (:1786-:1787),
/// the private `THDX_STRUCT thdx = {}` (:1789 -> the ThdxFace above,
/// the value-init posture).
pub struct SuppressModule {
    pub base: Module,  // cc :1778-:1779
    thdx: ThdxFace,    // :1789
}

impl Default for SuppressModule {
    fn default() -> Self { Self::new() }
}

impl SuppressModule {
    pub fn new() -> SuppressModule {
        SuppressModule {
            base: Module::new_params("suppress", SUPPRESS_HELP, Some(&SUPPRESS_PARAMS), true), // :1778-:1779
            thdx: ThdxFace::default(), // :1789 `= {}`
        }
    }

    pub fn get_usage() -> u32 {
        C_USAGE_CONTEXT // :1787
    }

    /// cc :1792-:1807 set — the thdx gid/sid/legs + `thdx.tracking =
    /// v.get_uint8() + 1` (:1801 — the by_src=0 face +1 = the THD_
    /// TRK_SRC ordinal, the cited arithmetic) + the ip leg :1804 ->
    /// the landed sfip_var_from_string (parser/parse_ip.rs :23
    /// REUSE; the C (var, caller) face -> the landed (var, ret) face,
    /// deviation cited — the caller tag string "suppress" rides the
    /// cite).
    pub fn set(&mut self, v: &mut Value) -> bool {
        if v.is("gid") {
            self.thdx.gen_id = v.get_uint32(); // :1794
        } else if v.is("sid") {
            self.thdx.sig_id = v.get_uint32(); // :1797
        } else if v.is("track") {
            self.thdx.tracking = i32::from(v.get_uint8()) + 1; // :1801
        } else if v.is("ip") {
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            self.thdx.ip_address = Some(sfip_var_from_string(&s).0); // :1804 (parse_ip.rs :23 REUSE)
        }
        true // :1806
    }

    /// cc :1809-:1816 begin — the memset face (the ThdxFace::zero
    /// port) + the type/priority/tracking init trio (:1812-:1814, the
    /// THD_TYPE_SUPPRESS :1812 / THD_PRIORITY_SUPPRESS :1813 / THD_
    /// TRK_NONE :1814 ordinals cited).
    pub fn begin(&mut self) -> bool {
        self.thdx.zero();                              // :1811 memset
        self.thdx.r#type = THD_TYPE_SUPPRESS;          // :1812
        self.thdx.priority = THD_PRIORITY_SUPPRESS;    // :1813
        self.thdx.tracking = THD_TRK_NONE;             // :1814
        true                                           // :1815
    }

    /// cc :1818-:1842 end(idx, sc) — the `if ( !idx ) return true;`
    /// gate (:1820-:1821); the gid==0-and-sid>=1 pair -> ParseError
    /// ("bad or incomplete gid:sid pair") + false (:1823-:1827); the
    /// track/ip XOR pair -> ParseError("incomplete pair of track and
    /// IP") + false (:1829-:1834); the sfthreshold_create gate (:1836
    /// -> the seam CITE; the get_network_policy()->policy_id arg leg
    /// rides the seam network_policy_id, the NOT-landed sfthreshold
    /// family cited) -> ParseError("threshold object cannot be created
    /// from the given parameters") + false (:1837-:1841).
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, idx: i32, thc: &mut ThresholdConfigLite, w: &mut W) -> bool {
        if idx == 0 {
            return true; // :1820-:1821
        }
        if self.thdx.gen_id == 0 && self.thdx.sig_id >= 1 {
            w.log().parse_error("bad or incomplete gid:sid pair", &[]); // :1825
            return false; // :1826
        }
        if (self.thdx.tracking == 0 && self.thdx.ip_address.is_some())
            || (self.thdx.tracking > 0 && self.thdx.ip_address.is_none())
        {
            w.log().parse_error("incomplete pair of track and IP", &[]); // :1831
            return false; // :1832
        }
        if w.sfthreshold_create(thc, &self.thdx) {
            // :1836 sfthreshold_create(sc, sc->threshold_config,
            // &thdx, get_network_policy()->policy_id) — the seam
            // (the policy_id leg rides network_policy_id CITE); the
            // NOT-landed filters family never fails by default.
            w.log().parse_error("threshold object cannot be created from the given parameters", &[]); // :1838
            return false; // :1839
        }
        true // :1841
    }
}

// ---------------------------------------------------------------------
// cc :1885-:1957 event_filter module (the THDX twin arms; the extern
// THREAD_LOCAL event_filter_stats seat rides the DECL cite at the
// EVENT_FILTER_PEG_NAMES census — NEVER a definition)
// ---------------------------------------------------------------------

/// cc :1885-:1910 `class EventFilterModule : public Module` — the list
/// ctor (:1887-:1888), the set/begin/end decls (:1889-:1891), the
/// inlined get_pegs (the two-line body face :1893-:1896 -> event_
/// filter_peg_names), get_counts (the reinterpret_cast(&event_filter_
/// stats) face :1897-:1901, the NOT-portable alias seat cited), the
/// cc :1903 useless-override comment face over get_usage CONTEXT
/// (:1904-:1905), the private thdx (:1907).
pub struct EventFilterModule {
    pub base: Module, // cc :1887-:1888
    thdx: ThdxFace,   // :1907
}

impl Default for EventFilterModule {
    fn default() -> Self { Self::new() }
}

impl EventFilterModule {
    pub fn new() -> EventFilterModule {
        EventFilterModule {
            base: Module::new_params("event_filter", EVENT_FILTER_HELP, Some(&EVENT_FILTER_PARAMS), true), // :1887-:1888
            thdx: ThdxFace::default(),
        }
    }

    /// the peg-name face (the cc :1895 return; the table above).
    pub fn get_pegs() -> &'static [PegInfo; 3] {
        &EVENT_FILTER_PEG_NAMES // :1895 (the table rides the :1877 extern cite)
    }

    pub fn get_usage() -> u32 {
        C_USAGE_CONTEXT // :1905
    }

    /// cc :1912-:1936 set — the gid/sid/track/ip legs (the "event_
    /// filter" caller tag at :1924, the landed parse_ip.rs :23 REUSE)
    /// + count :1927 (the C int slot face) + seconds :1930 + type
    ///   :1933 (the PT_ENUM 0/1/2 face -> the THD_TYPE_* ordinals).
    pub fn set(&mut self, v: &mut Value) -> bool {
        if v.is("gid") {
            self.thdx.gen_id = v.get_uint32(); // :1914
        } else if v.is("sid") {
            self.thdx.sig_id = v.get_uint32(); // :1917
        } else if v.is("track") {
            self.thdx.tracking = i32::from(v.get_uint8()) + 1; // :1920
        } else if v.is("ip") {
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            self.thdx.ip_address = Some(sfip_var_from_string(&s).0); // :1924 (the "event_filter" tag cite)
        } else if v.is("count") {
            self.thdx.count = v.get_int32(); // :1927
        } else if v.is("seconds") {
            self.thdx.seconds = v.get_uint32(); // :1930
        } else if v.is("type") {
            self.thdx.r#type = i32::from(v.get_uint8()); // :1933
        }
        true // :1935
    }

    /// cc :1938-:1944 begin — the memset + the priority/tracking duo
    /// (NO type init this class — the honest asymmetry vs Suppress:
    /// the C leaves thdx.type == 0 = THD_TYPE_LIMIT, cited).
    pub fn begin(&mut self) -> bool {
        self.thdx.zero();                           // :1940 memset
        self.thdx.priority = THD_PRIORITY_SUPPRESS; // :1941
        self.thdx.tracking = THD_TRK_NONE;          // :1942
        true                                        // :1943
    }

    /// cc :1946-:1956 end(idx, sc) — the `if ( idx && sfthreshold_
    /// create(...) )` single-line gate: a creation TRUE -> ParseError
    /// ("bad event_filter configuration [%d]") with the idx arg; the
    /// ALL-true tail.
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, idx: i32, thc: &mut ThresholdConfigLite, w: &mut W) -> bool {
        if idx != 0 && w.sfthreshold_create(thc, &self.thdx) {
            w.log().parse_error("bad event_filter configuration [%d]", &[Arg::I(i64::from(idx))]); // :1949
            // (a TRUE creation left the thdx ip pointer dangling in C;
            // the Rust Option face owns it, cited — the twin drives
            // the sfvar_free law on the C side)
        }
        true // :1954
    }
}

// ---------------------------------------------------------------------
// cc :2003-:2089 rate_filter module (tSFRFConfigNode -> the row-
// scoped Lite; IpsAction::get_type / is_valid_action REUSE the landed
// framework/ips_action.rs home through the seam)
// ---------------------------------------------------------------------

/// cc :2003-:2029 `class RateFilterModule : public Module` — the list
/// ctor WITH the in-class `thdx.init()` body (:2005-:2006), the dtor
/// decl (:2008), the set/begin/end decls (:2009-:2011), the inlined
/// get_pegs (:2013-:2016), get_counts (the rate_filter_stats cast face
/// :2017-:2020, cited), get_usage INSPECT (:2022-:2023), the private
/// `tSFRFConfigNode thdx` (:2026 -> the SFRFConfigNodeLite above).
pub struct RateFilterModule {
    pub base: Module,             // cc :2005
    thdx: SFRFConfigNodeLite,     // :2026
}

impl Default for RateFilterModule {
    fn default() -> Self { Self::new() }
}

impl RateFilterModule {
    /// cc :2005-:2006 — the ctor body calls thdx.init(): the Lite's
    /// Default face equals init() (one posture, cited at the Lite).
    pub fn new() -> RateFilterModule {
        RateFilterModule {
            base: Module::new_params("rate_filter", RATE_FILTER_HELP, Some(&RATE_FILTER_PARAMS), true), // :2005
            thdx: SFRFConfigNodeLite::default(), // :2006 thdx.init()
        }
    }

    /// cc :2031-:2037 `~RateFilterModule()` — the RateFilter_Cleanup()
    /// leg (:2033, the filter family NOT landed: the seam CITE) + the
    /// `if ( thdx.applyTo ) sfvar_free(thdx.applyTo)` leg (:2035-
    /// :2036 — the landed sf_ipvar record's Drop face owns the free;
    /// the C sfvar_free identity rides the cite, the 21b SFD-delete/
    /// no-Drop law re-rides as an explicit dtor face).
    pub fn dtor<W: ModulesWorld + ?Sized>(&mut self, w: &mut W) {
        w.rate_filter_cleanup();       // :2033 (rate_filter.h :38 CITE)
        self.thdx.apply_to = None;     // :2035-:2036 (the Drop face, cited)
    }

    pub fn get_pegs() -> &'static [PegInfo; 3] {
        &RATE_FILTER_PEG_NAMES // :2015
    }

    pub fn get_usage() -> u32 {
        C_USAGE_INSPECT // :2023
    }

    pub fn thdx(&self) -> &SFRFConfigNodeLite {
        &self.thdx // the read face the twin drives (the C private seat NOT callable-port law)
    }

    /// cc :2039-:2071 set — gid/sid (:2041/:2044), track the +1 cast
    /// (:2047, the SFRF_TRACK ordinals), count/seconds/timeout (:2050/
    /// :2053/:2056), apply_to -> the landed parse_ip.rs :23 REUSE with
    /// the "rate_filter" tag cite (:2059 — the C stores the raw var):
    /// the new_action leg :2062-:2069 -> `thdx.newAction = IpsAction::
    /// get_type(v.get_string())` — REUSE the landed ActionRegistry::
    /// get_action_type (framework/ips_action.rs :91) through the seam
    /// regs() leg; the `if ( !IpsAction::is_valid_action(...) )` gate
    /// (the landed is_valid_action :102 REUSE) drives the ParseError
    /// ("unknown new_action type rate_filter configuration %s") leg —
    /// the C NEVER returns false on that arm: the honest face kept.
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        if v.is("gid") {
            self.thdx.gid = v.get_uint32(); // :2041
        } else if v.is("sid") {
            self.thdx.sid = v.get_uint32(); // :2044
        } else if v.is("track") {
            self.thdx.tracking = v.get_uint8() + 1; // :2047 (the (SFRF_TRACK) cast face)
        } else if v.is("count") {
            self.thdx.count = v.get_uint32(); // :2050
        } else if v.is("seconds") {
            self.thdx.seconds = i64::from(v.get_uint32()); // :2053 (the time_t slot face)
        } else if v.is("timeout") {
            self.thdx.timeout = v.get_uint32(); // :2056
        } else if v.is("apply_to") {
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            self.thdx.apply_to = Some(sfip_var_from_string(&s).0); // :2059 (parse_ip.rs :23 REUSE)
        } else if v.is("new_action") {
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            let t = w.get_action_type(&s); // :2064 (the ips_action.rs :91 landed face via the seam; the C static ActionManager pair, cited)
            self.thdx.new_action = t;
            if !w.is_valid_action(t) {
                // :2066-:2068 (the landed is_valid_action :102 via the
                // seam + the parse_error :214 home)
                w.log().parse_error("unknown new_action type rate_filter configuration %s", &[Arg::S(Some(s.into()))]); // :2067
            }
        }
        true // :2070
    }

    /// cc :2073-:2077 begin — thdx.init() + the ALL-true tail.
    pub fn begin(&mut self) -> bool {
        self.thdx.init(); // :2075
        true              // :2076
    }

    /// cc :2079-:2088 end(idx, sc) — the `if ( idx && RateFilter_-
    /// Create(sc, sc->rate_filter_config, &thdx) )` gate -> ParseError
    /// ("bad rate_filter configuration [%d]") (the seam CITE leg, the
    /// filter family NOT landed); the `thdx.applyTo = nullptr;` tail
    /// leg (:2086 — the Drop face cited, the pointer-clear kept).
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, idx: i32, rfc: &mut RateFilterConfigLite, w: &mut W) -> bool {
        if idx != 0 && w.rate_filter_create(rfc, &self.thdx) {
            w.log().parse_error("bad rate_filter configuration [%d]", &[Arg::I(i64::from(idx))]); // :2082
        }
        self.thdx.apply_to = None; // :2086
        true                       // :2087
    }
}

// ---------------------------------------------------------------------
// cc :2126-:2208 hosts module
// ---------------------------------------------------------------------

/// cc :2126-:2151 `class HostsModule : public Module` — the list ctor
/// (:2128-:2129), the `~HostsModule() { assert(!host); }` dtor face
/// (:2131-:2132 — the 21b EXACTLY-1 debug_assert law), the set/begin/
/// end decls (:2134-:2136), the inlined get_pegs -> HostAttributes-
/// Manager::get_pegs() (:2138-:2140, the manager NOT landed: seam
/// CITE), get_counts -> get_peg_counts() (:2142-:2143, CITE), get_
/// usage GLOBAL (:2145-:2146), the privates `HostServiceDescriptor
/// service` (:2149 -> the Lite above) + `HostAttributesEntry host =
/// nullptr` (:2150 -> the Option face).
pub struct HostsModule {
    pub base: Module,                       // cc :2128-:2129
    service: HostServiceDescriptorLite,     // :2149
    host: Option<HostAttributesEntryLite>,  // :2150
}

impl Default for HostsModule {
    fn default() -> Self { Self::new() }
}

impl HostsModule {
    pub fn new() -> HostsModule {
        HostsModule {
            base: Module::new_params("hosts", HOSTS_HELP, Some(&HOSTS_PARAMS), true), // :2128-:2129
            service: HostServiceDescriptorLite::default(),
            host: None, // :2150
        }
    }

    /// cc :2131-:2132 `~HostsModule() override { assert(!host); }` —
    /// the EXACTLY-1 debug_assert! face (the 21b law; the C LRU/manager
    /// posture never keeps an entry at dtor time, cited).
    pub fn dtor(&self) {
        debug_assert!(self.host.is_none()); // :2132
    }

    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :2146
    }

    /// cc :2153-:2178 set — the guarded host legs (the `host and`
    /// pair-gates :2155/:2160/:2162: ip -> the landed Value::get_addr_ip
    /// (value.rs :559) + the set_ip_addr descriptor leg (NOT landed
    /// face: the seam CITE via the entry posture — the row-scoped entry
    /// carries NO descriptor table, cited); frag/tcp policy legs the
    /// +1 / plain ordinal faces (:2161/:2163); the service legs:
    /// name -> sc->proto_ref->add (:2165, the landed ProtocolReference
    /// ::add via the seam proto_ref_add REUSE), proto -> the same add
    /// face (:2168), port -> v.get_uint16() (:2170)).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, v: &mut Value, w: &mut W) -> bool {
        let have_host = self.host.is_some();
        if have_host && v.is("ip") {
            // :2157-:2159 the SfIp local + get_addr(adr) +
            // host->set_ip_addr(adr) — the value.rs :559 landed face;
            // the descriptor set face = the NOT-landed manager family
            // (host_attributes.h cite) riding the entry Option marker.
            let mut addr = crate::sfip::sf_ip::SfIp::default();
            v.get_addr_ip(&mut addr); // :2158
            let _ = addr; // the set_ip_addr leg rides the entry (NOT landed, cited)
        } else if have_host && v.is("frag_policy") {
            let _ = v.get_uint8() + 1; // :2161 (the +1 ordinal face, the descriptor NOT landed, cited)
        } else if have_host && v.is("tcp_policy") {
            let _ = v.get_uint8();     // :2163
        } else if v.is("name") {
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            self.service.snort_protocol_id = w.proto_ref_add(&s); // :2166 (the sc->proto_ref->add face, ProtocolReference::add REUSE)
        } else if v.is("proto") {
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            self.service.ipproto = w.proto_ref_add(&s); // :2169 (the C stores the id in the uint16 ipproto slot, cited)
        } else if v.is("port") {
            self.service.port = v.get_uint16(); // :2171
        }
        true // :2175
    }

    /// cc :2180-:2188 begin(fqn, idx) — `if ( idx && !strcmp(fqn,
    /// "hosts.services") ) service.reset()` (:2182-:2184); `else if
    /// ( idx && !strcmp(fqn, "hosts") ) host.reset(new
    /// HostAttributesDescriptor)` (:2185-:2186 the fresh-entry face);
    /// ALL-true.
    pub fn begin(&mut self, fqn: &str, idx: i32) -> bool {
        if idx != 0 && fqn == "hosts.services" {
            self.service.reset(); // :2184
        } else if idx != 0 && fqn == "hosts" {
            self.host = Some(HostAttributesEntryLite); // :2186
        }
        true // :2188
    }

    /// cc :2190-:2207 end(fqn, idx, sc) — the services arm: the `bool
    /// updated` local + the host->update_service(port, ipproto,
    /// snort_protocol_id, updated) leg (NOT landed manager face,
    /// cited) + service.reset() (:2195-:2198); the hosts arm: the `if
    /// ( !HostAttributesManager::add_host(host, sc) ) host.reset();`
    /// arm (:2201-:2203 the seam CITE via host_attributes_add_host —
    /// the add_host TRUE-stored posture keeps the entry, a false
    /// posture clears the C `host.reset()`... read the C: `if ( !
    /// add_host(host, sc) ) host.reset();` -> a FALSE return clears
    /// the entry) + `host = nullptr;` (:2204); ALL-true.
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, fqn: &str, idx: i32, w: &mut W) -> bool {
        if idx != 0 && fqn == "hosts.services" {
            if let Some(entry) = self.host.as_mut() {
                let (port, ipproto, spi) = (self.service.port, self.service.ipproto, self.service.snort_protocol_id);
                // :2194-:2195 `bool updated = false; host->
                // update_service(service.port, service.ipproto,
                // service.snort_protocol_id, updated);` — the
                // descriptor leg NOT landed (host_attributes.h CITE):
                // the seam entry posture, the updated flag NEVER
                // read by this C body (the cite honest face).
                let _ = entry;
                let _ = (port, ipproto, spi);
            }
            self.service.reset(); // :2197
        } else if idx != 0 && fqn == "hosts" {
            if let Some(entry) = self.host.as_mut()
                && !w.host_attributes_add_host(entry)
            {
                // the seam NEVER-landed arm reports FALSE by default;
                // the C posture: !add_host -> host.reset()
                self.host = None; // :2203 (seam CITE, NOT landed)
            }
            self.host = None; // :2204 (the C always clears the handle here)
        }
        true // :2206
    }
}

// ---------------------------------------------------------------------
// cc :2276-:2358 file policy module
// ---------------------------------------------------------------------

/// cc :2276-:2287 `class FilePolicyModule : public Module` — ctor
/// (:2278), the begin/set/end decls (:2279-:2281), the private
/// `FileRule file_rule` (:2284 -> the LANDED file_api/file_policy.rs
/// :101 FileRule record, REUSE never re-forked; the get_usage face
/// the C class omits lands NOT — the honest measured face: this class
/// declares NO get_usage override, the C base CONTEXT ordinal stays the
/// cite (module.h; NEVER a fake override)).
pub struct FilePolicyModule {
    pub base: Module,           // cc :2278
    file_rule: FileRule,        // :2284 (the landed record REUSE)
}

impl Default for FilePolicyModule {
    fn default() -> Self { Self::new() }
}

impl FilePolicyModule {
    pub fn new() -> FilePolicyModule {
        FilePolicyModule {
            base: Module::new_params("file_policy", FILE_POLICY_HELP, Some(&FILE_POLICY_PARAMS), false), // :2278
            file_rule: FileRule::new(), // the landed :110 FileRule::new face REUSE
        }
    }

    /// cc :2289-:2294 begin(fqn, idx) — `if (idx && !strcmp(fqn,
    /// "file_policy.rules")) file_rule.clear()` (the landed FileRule::
    /// clear :117 REUSE, cc :34-:42 through the home); ALL-true.
    pub fn begin(&mut self, fqn: &str, idx: i32) -> bool {
        if idx != 0 && fqn == "file_policy.rules" {
            self.file_rule.clear(); // :2292 (file_policy.rs :117 REUSE)
        }
        true // :2293
    }

    /// cc :2296-:2345 set(fqn, v, unread-sc) — the fp = get_network_
    /// policy()->get_file_policy() reach rides the seam file_policy()
    /// borrow (the NOT-landed network-policy reach deviation cited):
    ///   file_type_id (:2299 -> the landed TypeIdSet.type_id :70),
    ///   sha256 (:2302 -> the landed sha256 String :71),
    ///   verdict (:2305 the (FileVerdict)v.get_uint8() cast -> the
    ///   landed FILE_VERDICT_* ordinals face: the cast rides the raw
    ///   u32, the C enum-cast face cited — the ordinal consts above
    ///   name the ladder),
    ///   enable_file_type / enable_file_signature (:2308/:2311 -> the
    ///   landed FileUse flags :88/:89),
    ///   enable_file_capture (:2313-:2321): the flag write + the
    ///   `if (capture_enabled && Snort::is_reloading() && !FileService
    ///   ::is_file_capture_enabled())` gate -> ReloadError("Changing
    ///   %s requires a restart.\n") + false — Snort::is_reloading()
    ///   REUSE the landed snort_.rs reloading() :747 (CITE-REUSE,
    ///   NEVER re-forked) and FileService the seam CITE (the landed
    ///   file_lib.rs :960 FileServiceLite carries the record face; the
    ///   static is_file_capture_enabled() family cited to file_
    ///   service.h, NOT landed); the reload_error leg rides the landed
    ///   LogEngine::reload_error :220 REUSE;
    ///   enable_type / enable_signature (:2323-:2327 -> the landed
    ///   FilePolicy::set_file_type :221 / set_file_signature :226
    ///   REUSE through the seam borrow);
    ///   enable_capture (:2328-:2336): the SAME reload gate face then
    ///   the landed set_file_capture :231 REUSE;
    ///   verdict_delay (:2338 -> the landed set_verdict_delay :213
    ///   REUSE, the C get_int64 face).
    pub fn set<W: ModulesWorld + ?Sized>(&mut self, fqn: &str, v: &mut Value, w: &mut W) -> bool {
        if v.is("file_type_id") {
            self.file_rule.when.type_id = v.get_uint32(); // :2299 (TypeIdSet :70 REUSE)
        } else if v.is("sha256") {
            self.file_rule.when.sha256 = String::from_utf8_lossy(v.get_string()).into_owned(); // :2302 (the :71 slot REUSE)
        } else if v.is("verdict") {
            // :2305 `(FileVerdict)v.get_uint8()` — the landed
            // FileVerdict u32 ordinal face (file_api.rs :108-:115):
            // UNKNOWN 0 = the C FILE_VERDICT_UNKNOWN head; the cast
            // rides the ordinal slot directly (the ladder names cited
            // at the FILE_VERDICT_* reuse block).
            self.file_rule.r#use.verdict = u32::from(v.get_uint8()); // :2305
        } else if v.is("enable_file_type") {
            self.file_rule.r#use.type_enabled = v.get_bool(); // :2308
        } else if v.is("enable_file_signature") {
            self.file_rule.r#use.signature_enabled = v.get_bool(); // :2311
        } else if v.is("enable_file_capture") {
            self.file_rule.r#use.capture_enabled = v.get_bool(); // :2314
            if self.file_rule.r#use.capture_enabled
                && Snort::reloading()                                  // :2316 (main/snort_.rs :747 REUSE, CITE)
                && !w.is_file_capture_enabled()                        // :2317 (FileService CITE)
            {
                let fqn_own = fqn.to_string();
                w.log().reload_error("Changing %s requires a restart.\n", &[Arg::S(Some(fqn_own.into()))]); // :2319 (messages.rs :220 REUSE)
                return false; // :2320
            }
        } else if v.is("enable_type") && let Some(fp) = w.file_policy() {
            fp.set_file_type(v.get_bool()); // :2324 (file_policy.rs :221 REUSE)
        } else if v.is("enable_signature") && let Some(fp) = w.file_policy() {
            fp.set_file_signature(v.get_bool()); // :2327 (:226 REUSE)
        } else if v.is("enable_capture") {
            let on = v.get_bool();
            if on && Snort::reloading() && !w.is_file_capture_enabled() // :2331-:2332 (the snort_.rs :747 REUSE pair legs)
            {
                let fqn_own = fqn.to_string();
                w.log().reload_error("Changing %s requires a restart.\n", &[Arg::S(Some(fqn_own.into()))]); // :2334
                return false; // :2335
            }
            if let Some(fp) = w.file_policy() {
                fp.set_file_capture(on); // :2337 (:231 REUSE)
            }
        } else if v.is("verdict_delay") && let Some(fp) = w.file_policy() {
            fp.set_verdict_delay(v.get_int64()); // :2340 (:213 REUSE)
        }
        true // :2344
    }

    /// cc :2347-:2357 end(fqn, idx, unread-sc) — `if (!idx) get_
    /// network_policy()->get_file_policy()->load();` (:2349 -> the
    /// landed FilePolicy::load :335 REUSE through the seam borrow —
    /// its svc arg face rides the landed FileServiceLite (file_lib.rs
    /// :960, the caller threads it, record-threading cited)); `if
    /// (idx && !strcmp(fqn, "file_policy.rules")) get_network_policy()
    /// ->add_file_policy_rule(file_rule)` (:2351-:2352 the seam CITE);
    /// ALL-true.
    pub fn end<W: ModulesWorld + ?Sized>(&mut self, fqn: &str, idx: i32, svc: &mut FileServiceLite, w: &mut W) -> bool {
        if idx == 0 && let Some(fp) = w.file_policy() {
            fp.load(svc); // :2349 (file_policy.rs :335 REUSE; the svc arg = the 17x landed record face, threaded)
        }
        if idx != 0 && fqn == "file_policy.rules" {
            w.add_file_policy_rule(&self.file_rule.clone()); // :2353-:2354 (the network-policy rule-list NOT landed, seam CITE)
        }
        true // :2356
    }
}

// ======================================================================
// THE REGISTER LADDERS — main/modules.h :25-:26 the two free-fn
// seats (`void add_independent_modules(); void add_dependent_modules();
// ;` the ONE decl cite face, the modules.h pair) + the cc :2361-:2415 /
// :2417-:2423 bodies. THE 37 add_module legs ride `w.add_modules_box(
// <ctor face>)` one leg per C line (the PluginManager::add_module
// identity = the seam CITE: managers/plugin_manager.h NOT landed, the
// harness mirrors the DECL only); the ORDERED id const below pins the
// 35 + 1 (+1 dialect-OFF) leg census IN EXACT C ORDER with the group
// comment faces copied VERBATIM.
// ======================================================================

/// cc :2361-:2415 — the ordered independent-module id ledger: the 35
/// registered module ids IN EXACT C ORDER (every string measured from
/// the owning TU's ctor seat at the ground head, NEVER invented):
/// snort (:2367, main/snort_module.cc :690 s_name), classifications
/// (:2370), decode (:2371, codec_module.cc :33; the landed home
/// codecs/codec_module.rs S_NAME :344 REUSE), detection (:2372,
/// detection_module.cc :152), memory (:2373, memory_module.cc), mp_
/// data_bus (:2374), packet_tracer (:2375, packet_tracer_module.h
/// PACKET_TRACER_NAME), packets (:2376), process (:2377), profiler
/// (:2378, profiler_module.cc :537), references (:2379), reload_
/// survivor (:2380), search_engine (:2381), daq (:2382,
/// sfdaq_module.cc :86 — the landed 23c SFDAQModule REUSE), payload_
/// injector (:2383), ips_actions (:2384, actions_module.h — the C
/// name is "ips_actions", NOT "actions": the measured face), alerts
/// (:2387), event_queue (:2388), output (:2389), active (:2392),
/// latency (:2393), side_channel (:2394), high_availability (:2395),
/// event_filter (:2398), js_norm (:2399), rate_filter (:2400),
/// suppress (:2401), network (:2404, network_module.cc :101),
/// inspection (:2405), ips (:2406), file_policy (:2407), attribute_
/// table (:2410), hosts (:2411), host_tracker (:2412), host_cache
/// (:2413). The five group-comment faces ride the ledger rows below
/// copied VERBATIM.
pub const INDEPENDENT_MODULE_IDS: [&str; 35] = [
    "snort",             // :2367 (the C comment group above, cc :2363-:2366 copied at the fn below)
    "classifications",   // :2370
    "decode",            // :2371 (CodecModule)
    "detection",         // :2372
    "memory",            // :2373
    "mp_data_bus",       // :2374
    "packet_tracer",     // :2375
    "packets",           // :2376
    "process",           // :2377
    "profiler",          // :2378
    "references",        // :2379
    "reload_survivor",   // :2380
    "search_engine",     // :2381
    "daq",               // :2382 (the landed 23c SFDAQModule)
    "payload_injector",  // :2383
    "ips_actions",       // :2384 (the ActionsModule C name — measured)
    "alerts",            // :2388
    "event_queue",       // :2389
    "output",            // :2390
    "active",            // :2393
    "latency",           // :2394
    "side_channel",      // :2395
    "high_availability", // :2396
    "event_filter",      // :2399
    "js_norm",           // :2400
    "rate_filter",       // :2401
    "suppress",          // :2402
    "network",           // :2405
    "inspection",        // :2406
    "ips",               // :2407
    "file_policy",       // :2408
    "attribute_table",   // :2411
    "hosts",             // :2412
    "host_tracker",      // :2413
    "host_cache",        // :2414
];

/// cc :2417-:2423 — TraceModule then the CRASH_MITIGATOR dialect face
/// MEASURED-OFF: `#ifdef CRASH_MITIGATOR` (cc :2420) = cmake face 0 —
/// MitigatorModule NEVER registered (config.cmake.h.in :120 the plain
/// `#cmakedefine CRASH_MITIGATOR 1` seat; the row harness cmake
/// posture never defines it — the include seat :58-:60 rides the SAME
/// dialect face; the mitigator id "mitigator" =
/// mitigator_module.cc :190, cite-only NEVER registered here).
pub const DEPENDENT_MODULE_IDS: [&str; 1] = ["trace"];

/// the seam registration leg — cc every `PluginManager::add_module(
/// new X)` face (managers/plugin_manager.h NOT landed: the seam rides
/// the recorded ctor face; the twin asserts the 37-leg census).
pub trait ModuleRegistrar {
    fn add_modules_box(&mut self, id: &'static str);
}

impl ModuleRegistrar for NullWorld {
    fn add_modules_box(&mut self, id: &'static str) {
        self.registered.push(id); // the ledger the twin walks
    }
}

/// cc :2361-:2415 `void add_independent_modules()` — each leg: the C
/// comment face (copied VERBATIM at its group), then ONE
/// `w.add_modules_box(new-face)` per C line, the landed Rust ctor
/// name in the cite (the modules THIS row owns build their real Rust
/// struct; the foreign-owned modules ride the id + the owning-TU
/// CITE, NEVER a re-forked body).
pub fn add_independent_modules<W>(w: &mut W)
where
    W: ModulesWorld + ModuleRegistrar + ?Sized,
{
    // :2363-:2366 the C comment quadruple (copied verbatim):
    //     // parameters must be settable regardless of sequence
    //     // since Lua calls this by table hash key traversal
    //     // (which is effectively random)
    //     // so module interdependencies must come after this phase
    w.add_modules_box(INDEPENDENT_MODULE_IDS[0]);  // :2367 new SnortModule (main/snort_module.cc :702)

    // :2369 the group comment face: `// these modules are not policy
    // specific`
    w.add_modules_box(INDEPENDENT_MODULE_IDS[1]);  // :2370 new ClassificationsModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[2]);  // :2371 new CodecModule (the landed codecs/codec_module.rs :370 REUSE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[3]);  // :2372 new DetectionModule (detection/detection_module.cc :154 CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[4]);  // :2373 new MemoryModule (memory/memory_module.cc CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[5]);  // :2374 new MPDataBusModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[6]);  // :2375 new PacketTracerModule (the landed packet_io/packet_tracer_module.rs :367 REUSE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[7]);  // :2376 new PacketsModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[8]);  // :2377 new ProcessModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[9]);  // :2378 new ProfilerModule (profiler/profiler_module.cc :537 CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[10]); // :2379 new ReferencesModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[11]); // :2380 new ReloadSurvivorSubscriptionsModule (this row, the RSS_* homes REUSE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[12]); // :2381 new SearchEngineModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[13]); // :2382 new SFDAQModule (the landed 23c home REUSE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[14]); // :2383 new PayloadInjectorModule (payload_injector_module.cc CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[15]); // :2384 new ActionsModule (actions/actions_module.h "ips_actions" CITE)

    // :2386 the group comment face: `// these could but probably
    // shouldn't be policy specific / // or should be broken into
    // policy and non-policy parts`
    w.add_modules_box(INDEPENDENT_MODULE_IDS[16]); // :2388 new AlertsModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[17]); // :2389 new EventQueueModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[18]); // :2390 new OutputModule (this row)

    // :2392 the group comment face: `// these modules could be in
    // traffic policy`
    w.add_modules_box(INDEPENDENT_MODULE_IDS[19]); // :2393 new ActiveModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[20]); // :2394 new LatencyModule (latency_module.cc CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[21]); // :2395 new SideChannelModule (side_channel_module.cc CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[22]); // :2396 new HighAvailabilityModule (flow/ha_module.cc HA_NAME CITE)

    // :2398 the group comment face: `// these modules should be in ips
    // policy`
    w.add_modules_box(INDEPENDENT_MODULE_IDS[23]); // :2399 new EventFilterModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[24]); // :2400 new JSNormModule (js_norm_module.cc :34 CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[25]); // :2401 new RateFilterModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[26]); // :2402 new SuppressModule (this row)

    // :2404 the group comment face: `// these are preliminary policies`
    w.add_modules_box(INDEPENDENT_MODULE_IDS[27]); // :2405 new NetworkModule (main/network_module.cc :101 CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[28]); // :2406 new InspectionModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[29]); // :2407 new IpsModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[30]); // :2408 new FilePolicyModule (this row)

    // :2410 the group comment face: `// these modules replace config
    // and hosts.xml`
    w.add_modules_box(INDEPENDENT_MODULE_IDS[31]); // :2411 new AttributeTableModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[32]); // :2412 new HostsModule (this row)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[33]); // :2413 new HostTrackerModule (host_tracker_module.h CITE)
    w.add_modules_box(INDEPENDENT_MODULE_IDS[34]); // :2414 new HostCacheModule (host_cache_module.h CITE)
}

/// cc :2417-:2423 `void add_dependent_modules()` — the TraceModule leg
/// then the dialect tail (MEASURED-OFF, echoed):
/// `#ifdef CRASH_MITIGATOR :2420 = cmake face 0 — MitigatorModule
/// NEVER registered` (config.cmake.h.in :120 `#cmakedefine
/// CRASH_MITIGATOR 1` UNDEFINED on the row harness posture; the
/// harness echo: `cmake -L` never lists CRASH_MITIGATOR; the pair's
/// CRASH_MITIGATOR faces count EXACTLY-2, BOTH OFF).
pub fn add_dependent_modules<W>(w: &mut W)
where
    W: ModulesWorld + ModuleRegistrar + ?Sized,
{
    w.add_modules_box(DEPENDENT_MODULE_IDS[0]); // :2419 new TraceModule (trace_module.cc :122 CITE)
    // :2420-:2422 `#ifdef CRASH_MITIGATOR` new MitigatorModule
    // (mitigator/mitigator_module.cc :190) `#endif` — dialect face
    // MEASURED-OFF: the leg NEVER runs (cmake face 0, echoed above).
}

// ======================================================================
// THE GATE BLOCK — cc :2425-:2491 the #ifdef UNIT_TEST seat. THIS
// landing gives the 4 Catch TEST bodies NO Rust body (rule (5): the
// EXACT-4-count cite comment face; the orchestrator's parity twin in
// tests/ replays every leg). The harness-pinned anchors: UNIT_TEST
// :2425, the catch include :2426, the log_errors include :2427, the
// 12 CHECK legs measured at :2436/:2437/:2438/:2439 (:2442's
// :2451/:2452), :2460/:2465/:2466, :2483/:2486/:2487 + the seat-
// close #endif :2491.
//
//   [1] TEST_CASE :2429 "IPS action variable placeholder detection"
//       "[IpsModule]" — 4 CHECKs (:2436-:2439): the
//       is_action_var_placeholder ladder over the "$var.react"/
//       "REACT_CUSTOM.react"/"$var"/nets "$var.react" strings (the
//       ported fn above drives the twin).
//   [2] TEST_CASE :2442 "IPS action variable page rejects missing
//       action variable name" "[IpsModule]" — reset_parse_errors +
//       module.set("ips.variables.actions.page", page, nullptr) ->
//       2 CHECKs (:2451-:2452, get_parse_errors() == 1; the landed
//       LogEngine reset_parse_errors :163 / get_parse_errors :169
//       REUSE faces the twin drives).
//   [3] TEST_CASE :2455 "IPS action variable end validates react page"
//       "[IpsModule]" — end("$var.react", 0) THEN end("REACT_
//       CUSTOM.react", 0) -> 3 CHECKs (:2460, :2465-:2466).
//   [4] TEST_CASE :2469 "IPS action variable end rejects duplicate
//       action variable" "[IpsModule]" — the policy.commit_action_
//       variable + set_ips_policy install + set(...react.page) +
//       end(...react) -> 3 CHECKs (:2483, :2486-:2487) + the null
//       set_ips_policy teardown :2489.
// CHECK legs EXACTLY-12; TEST_CASE faces EXACTLY-4; tags "[IpsModule]"
// EXACTLY-4 — the twin replays EVERY leg, this face counts ONLY.
// ======================================================================

// (the four TEST_CASE cites above + the 12 CHECK anchors = the gate
// face; ZERO Rust bodies in the landing, rule (5).)
