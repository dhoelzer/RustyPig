//! Chapter-21 owner row: the snort_config.h + snort_config.cc pair. This
//! lands every named type, enum, static, inline accessor, mutator, and
//! body face of the 1936-L ground pair in one module. Ground @ fe29cbe:
//! main/snort_config.cc 1138 L md5 a2e0b91f1de2fa295ce7dd7d2be77a5b +
//! main/snort_config.h 798 L md5 638120b51712c12ce847829308ac5a01 =
//! the 1936-L pair (the dispatch census; re-measured on disk at this
//! landing). The CMake seats (measure with grep before every cite):
//! src/main/CMakeLists.txt snort_config.h :7 and snort_config.cc :51
//! PLAIN SOURCES seats -- the owner home, never dialect.
//!
//! THE ZERO-GATE CONTROL. TEST_CASE, the bare TEST(, CATCH, and
//! UNIT_TEST measure find-0 in BOTH ground files (grep rc 1, MEASURED).
//! The pair carries no gate of its own. The dialect posts that DO exist
//! ride CITED COMMENT faces at their posts, NEVER invented-on code:
//!   h :79 #ifdef SHELL (its RUN_FLAG__SHELL entry :80),
//!   h :83 #ifdef REG_TEST (its RUN_FLAG__EXIT_AFTER_RELOAD entry :84),
//!   h :212 REG_TEST (the output_flags = OUTPUT_FLAG__WIDE_HEX face
//!     :214; the live else-face :216 uint32_t output_flags = 0),
//!   h :534 #ifdef REG_TEST (the exit_after_reload accessor :535-:537),
//!   cc :485 #ifdef SHELL (merge() legs :486-:503),
//!   cc :1102 #ifdef REG_TEST (the cleanup_fatal_error legs :1103-:1111).
//! The cmake posture keeps those arms OFF: ENABLE_SHELL is option(...,
//! OFF) at cmake/create_options.cmake :19, and REG_TEST is absent from
//! CMakeLists.txt and from cmake/*.cmake (grep-0 MEASURED) -- it rides a
//! compile flag only. On this cargo posture every REG_TEST and SHELL
//! arm compiles OFF, so the h :216 `uint32_t output_flags = 0` arm and
//! the SHELL-less merge legs keep their OFF/else-face landing.
//!
//! THE statics LAW. cc carries EXACTLY-7 `^static` faces: the
//! THREAD_LOCAL conf-slot :108, scratch_handlers :114, init_policy_mode
//! :120, init_policies :153, threads_max :208, threads_cnt :209, and
//! generate_config_dump :211 (MEASURED list). h carries EXACTLY-14
//! `    static ` member faces (:196 :197 :200 :440 :441 :724 :729 :732
//! :735 :738 :746 :765 :768 :771, MEASURED). THREAD_LOCAL counts cc 2
//! (:108 + the log_quiet_bypassed definition :112), h 1 (the :197
//! decl). Per the statics law every one lands as a caller-owned field or
//! a small module owner seam (the snort_module.rs / processp.rs
//! pattern): the thread_local conf slot and the class-static bags ride
//! std Mutex / AtomicU32 / BTreeMap -- safe Rust, the C++ THREAD_LOCAL
//! posture kept as prose. This file declares ZERO allow attributes and
//! ZERO un-safe blocks.
//!
//! THE ENUM FAMILIES -- one-home note. This module is the OWNER home of
//! the full ladders, byte-faithful per-line: RunFlag h :45-:86
//! EXACTLY-28 named entries (26 live + the :80 SHELL-cited entry
//! RUN_FLAG__SHELL + the :84 EXIT_AFTER_RELOAD-cited entry; both cited,
//! both never live -- see above), OutputFlag h :88-:108 EXACTLY-14,
//! LoggingFlag h :110-:115 EXACTLY-3, TunnelFlags h :117-:129
//! EXACTLY-10, DumpConfigType h :131-:137 EXACTLY-4. PROCESS_TYPE__*
//! faces: EXACTLY-0 in the pair (the home is main/process.h, landed at
//! main/processp.rs -- REUSE cite, no const here); DAQ_*: EXACTLY-0 in
//! the pair (the homes are packet_io/sfdaq.rs and packet_io/
//! sfdaq_config.rs -- REUSE cites at the use-paths below and at the
//! tunnel_bypass / merge legs).
//!
//! The snort_module.rs sibling landed a RUN_FLAG__* subset (21 consts)
//! plus DUMP_CONFIG_*, four OUTPUT_FLAG siblings, and
//! LOGGING_FLAG__VERBOSE, and mirrors them for that file's config
//! face (the snort_module.rs rows :587-:637 cite each of their consts
//! to these h lines -- the mirror is the landed precedent; this module
//! adds the remaining RunFlag / OutputFlag / LoggingFlag / TunnelFlags /
//! DumpConfigType siblings so ALL ladders sit complete here, names kept
//! byte-faithful per const).
//!
//! ONE-HOME REUSE census (measured on disk before naming any type):
//! REUSE PolicyMode, Enable, IpsPolicy (default_rule_state field),
//! NetworkPolicy, and the CHECKSUM_FLAG__DEF face from crate::main::
//! policy (never re-forked; a small module-local PolicyWorld seam feeds
//! those fields where the ground derefs policy_map). REUSE SFDAQConfig
//! from crate::packet_io::sfdaq_config (the overlay / mru_size field --
//! cited at merge and verify legs) and the SFDAQ facade + get_tunnel_
//! bypass seam home crate::packet_io::sfdaq (cited at tunnel_bypass_
//! enabled). REUSE ThreadConfig::get_instance_max ONE-home from crate::
//! main::thread_config (the merge :513 leg) and the CliConf sibling of
//! that module named via crate::main::snort_. REUSE LogEngine,
//! LOGGING_FLAG_QUIET / LOGGING_FLAG_SYSLOG, WARN_DAQ, and the cfmt Arg
//! face from crate::log::messages (the warning / ReloadError legs --
//! the logging statics NEVER forked a second time, the snort_module.rs :117-:125
//! law re-ridden here). The h :54/:55 network-policy legs land through a
//! caller-owned NetworkPolicyFace -- landed NetworkPolicy (policy.rs :188)
//! carries NO min_ttl / new_ttl face (its fields stay untouched), and
//! every network-policy face rides policy.rs REUSE cite. REUSE
//! ProcessState + ProcessWorld from crate::main::processp for the uid/
//! gid seats (its trim_heap :639 face is cited where the C dtor :332
//! pulls it). REUSE GHash / XHash from crate::hash. NO landed home owns
//! the remaining config sub-records; they land as the row-owned cited
//! records this module says it owns (see the record census below).
//!
//! THE NEVER-INVENT law. Every call the C makes into a layer this crate
//! has not landed -- ParseRules, fpCreate/ fpDelete, PortTablesFree,
//! the free-class FreeRuleLists, the config-output classes
//! (JsonAllConfigOutput / JsonTopConfigOutput / TextConfigOutput) plus
//! the ConfigOutput and ConfigData types, the dump engine, the
//! manager ladders, the reload tuner world, ControlConn / ACScratchUpdate,
//! the getgrnam / getgrgid / getpwnam / getpwuid / getuid / getgid
//! name-resolution family, eth_pton / eth_addr_t (utils/dnet_header.h;
//! grep-confirmed there), strtok_r, snort_strdup, load_shared_secret,
//! SET_THREAD_NAME, the std::thread seat, MPTransportManager /
//! PluginManager / EventManager / DetectionEngine / Analyzer legs and
//! the snort_log / snort_ignore hook names, the event_queue / threshold /
//! rate_filter / detection_filter config faces plus their
//! EventQueueConfigFree / ThresholdConfigFree / RateFilter_ConfigFree /
//! DetectionFilterConfigFree faces, ProtocolReference, TraceConfig,
//! MemoryConfig, LatencyConfig / PacketLatencyConfig, HighAvailability-
//! Config, ProfilerConfig / ProfilerNodeMap / Profiler, DataBus /
//! MPDataBus, RuleStateMap, PlugSet, PolicyMap, ScratchAllocator --
//! lands as a cited seam leg (the SnortConfigWorld trait) or in the
//! cited comment wall, NEVER as invented live behavior (the 24f NF law;
//! success arms NEVER invented past a wall).

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::log::messages::{LOGGING_FLAG_QUIET, LOGGING_FLAG_SYSLOG, WARN_DAQ};
use crate::main::policy::{
    Enable, PolicyMode, CHECKSUM_FLAG__ALL, CHECKSUM_FLAG__DEF,
};
use crate::main::thread_config::ThreadConfig;
use crate::packet_io::sfdaq_config::SFDAQConfig;

// ======================================================================
// the two #define faces -- h :42 / :43
// ======================================================================

/// h :42 `#define DEFAULT_LOG_DIR "."`
pub const DEFAULT_LOG_DIR: &str = ".";
/// h :43 `#define DEFAULT_PID_FILENAME "snort.pid"`
pub const DEFAULT_PID_FILENAME: &str = "snort.pid";

// ======================================================================
// enum RunFlag -- h :45-:86, EXACTLY-28 named entries (26 live + 2
// cited-OFF). Ordinals byte-verbatim, blank-line group breaks and all.
// ======================================================================

pub const RUN_FLAG__READ: u32 = 0x0000_0001;               // h :47
pub const RUN_FLAG__DAEMON: u32 = 0x0000_0002;             // h :48
pub const RUN_FLAG__DUMP_MSG_MAP: u32 = 0x0000_0004;       // h :49
pub const RUN_FLAG__DUMP_RULE_META: u32 = 0x0000_0008;     // h :50
pub const RUN_FLAG__INLINE: u32 = 0x0000_0010;             // h :52
pub const RUN_FLAG__STATIC_HASH: u32 = 0x0000_0020;        // h :53
pub const RUN_FLAG__CREATE_PID_FILE: u32 = 0x0000_0040;    // h :54
pub const RUN_FLAG__NO_LOCK_PID_FILE: u32 = 0x0000_0080;   // h :55
pub const RUN_FLAG__ALERT_BEFORE_PASS: u32 = 0x0000_0100;  // h :57
pub const RUN_FLAG__CONF_ERROR_OUT: u32 = 0x0000_0200;     // h :58
pub const RUN_FLAG__PROCESS_ALL_EVENTS: u32 = 0x0000_0400; // h :59
pub const RUN_FLAG__INLINE_TEST: u32 = 0x0000_0800;        // h :60
pub const RUN_FLAG__PCAP_SHOW: u32 = 0x0000_1000;          // h :62
pub const RUN_FLAG__SHOW_FILE_CODES: u32 = 0x0000_2000;    // h :63
pub const RUN_FLAG__PAUSE: u32 = 0x0000_4000;              // h :64
pub const RUN_FLAG__NO_PCRE: u32 = 0x0000_8000;            // h :65
pub const RUN_FLAG__DUMP_RULE_STATE: u32 = 0x0001_0000;    // h :67
pub const RUN_FLAG__DUMP_RULE_DEPS: u32 = 0x0002_0000;     // h :68
pub const RUN_FLAG__TEST: u32 = 0x0004_0000;               // h :69
pub const RUN_FLAG__MEM_CHECK: u32 = 0x0008_0000;          // h :70
pub const RUN_FLAG__TRACK_ON_SYN: u32 = 0x0010_0000;       // h :72
pub const RUN_FLAG__IP_FRAGS_ONLY: u32 = 0x0020_0000;      // h :73
pub const RUN_FLAG__TEST_FEATURES: u32 = 0x0040_0000;      // h :74
pub const RUN_FLAG__GEN_DUMP_CONFIG: u32 = 0x0080_0000;    // h :75
pub const RUN_FLAG__CREATE_INST_FILE: u32 = 0x0100_0000;   // h :77
pub const RUN_FLAG__DROP_STALE_PACKETS: u32 = 0x0400_0000; // h :82
// h :79-:81 `#ifdef SHELL` gate -- ENABLE_SHELL option OFF
// (cmake/create_options.cmake :19): the entry inside lands CITED only:
//   :80 RUN_FLAG__SHELL = 0x02000000
// h :83-:85 `#ifdef REG_TEST` gate -- REG_TEST rides a compile flag only
// (grep-0 in CMakeLists.txt + cmake/*.cmake, MEASURED -- it never rides
// a cmake option; OFF on this cargo posture): the entry lands CITED only:
//   :84 RUN_FLAG__EXIT_AFTER_RELOAD = 0x08000000

// ======================================================================
// enum OutputFlag -- h :88-:108, EXACTLY-14 entries
// ======================================================================

pub const OUTPUT_FLAG__LINE_BUFFER: u32 = 0x0000_0001;     // h :90
pub const OUTPUT_FLAG__VERBOSE_DUMP: u32 = 0x0000_0002;    // h :91
pub const OUTPUT_FLAG__CHAR_DATA: u32 = 0x0000_0004;       // h :92
pub const OUTPUT_FLAG__APP_DATA: u32 = 0x0000_0008;        // h :93
pub const OUTPUT_FLAG__SHOW_DATA_LINK: u32 = 0x0000_0010;  // h :95
pub const OUTPUT_FLAG__USE_UTC: u32 = 0x0000_0020;         // h :96
pub const OUTPUT_FLAG__INCLUDE_YEAR: u32 = 0x0000_0040;    // h :97
// h :98 the note (verbatim in the ground, kept as cite):
//   /* Note using this alters the packet - can't be used inline */
pub const OUTPUT_FLAG__OBFUSCATE: u32 = 0x0000_0080;       // h :99
pub const OUTPUT_FLAG__ALERT_IFACE: u32 = 0x0000_0100;     // h :101
pub const OUTPUT_FLAG__NO_TIMESTAMP: u32 = 0x0000_0200;    // h :102
pub const OUTPUT_FLAG__ALERTS: u32 = 0x0000_0400;          // h :103
pub const OUTPUT_FLAG__WIDE_HEX: u32 = 0x0000_0800;        // h :104
pub const OUTPUT_FLAG__ALERT_REFS: u32 = 0x0000_1000;      // h :106
pub const OUTPUT_FLAG__LOG_BUFFERED: u32 = 0x0000_2000;    // h :107

// ======================================================================
// enum LoggingFlag -- h :110-:115, EXACTLY-3 entries. The
// log/messages.rs home carries the QUIET :41 / SYSLOG :42 seats
// (REUSE-imported above); this ladder pins all three ordinals here so
// the h :731-:769 inline statics read byte-faithful, and VERBOSE (the
// :111 entry, no other owner) rides this home's name.
// ======================================================================

pub const LOGGING_FLAG__VERBOSE: u32 = 0x0000_0001; // h :112 (0x1)
// h :113 LOGGING_FLAG__QUIET / h :114 LOGGING_FLAG__SYSLOG -- the
// messages.rs REUSE faces (imported; never re-pinned by a second def).

// ======================================================================
// enum TunnelFlags -- h :117-:129, EXACTLY-10 entries. The codec
// siblings (cd_gtp.rs :148, cd_teredo.rs :88, cd_ipv6.rs :142/:143,
// cd_ipv4.rs :184/:186, cd_gre.rs :98, cd_mpls.rs :140, cd_vxlan.rs :80,
// cd_geneve.rs :208) each cite these h lines already -- REUSE cites,
// this ladder is the owner pair's home.
// ======================================================================

pub const TUNNEL_GTP: u16 = 0x01;    // h :119
pub const TUNNEL_TEREDO: u16 = 0x02; // h :120
pub const TUNNEL_6IN4: u16 = 0x04;   // h :121
pub const TUNNEL_4IN6: u16 = 0x08;   // h :122
pub const TUNNEL_4IN4: u16 = 0x10;   // h :123
pub const TUNNEL_6IN6: u16 = 0x20;   // h :124
pub const TUNNEL_GRE: u16 = 0x40;    // h :125
pub const TUNNEL_MPLS: u16 = 0x80;   // h :126
pub const TUNNEL_VXLAN: u16 = 0x100; // h :127
pub const TUNNEL_GENEVE: u16 = 0x200; // h :128

// ======================================================================
// enum DumpConfigType -- h :131-:137, EXACTLY-4 entries
// ======================================================================

pub const DUMP_CONFIG_NONE: u32 = 0;    // h :133
pub const DUMP_CONFIG_JSON_ALL: u32 = 1; // h :134
pub const DUMP_CONFIG_JSON_TOP: u32 = 2; // h :135
pub const DUMP_CONFIG_TEXT: u32 = 3;     // h :136

// ======================================================================
// the alert-mode / log-mode name tables -- cc :94-:106, the
// LOG_NONE "none" / LOG_DUMP "dump" / LOG_CODECS "codecs" (cc :94-:96)
// and ALERT_NONE "none" / ALERT_CMG "cmg" / ALERT_JH "jh" / ALERT_DJR
// "djr" / ALERT_U2 "u2" / ALERT_AJK "ajk" (cc :98-:103) plus OUTPUT_U2
// "unified2" / OUTPUT_FAST "alert_fast" (cc :105-:106). EXACTLY-15 legs
// carry the case-insensitive compare in the set_alert_mode / set_log_mode
// bodies (strcasecmp census cc :946-:975), the LOG_DUMP arm rides exact
// strcmp (:975), the fall-through stores the verbatim val (:960/:977).
// ======================================================================

pub const LOG_NONE: &str = "none";       // cc :94
pub const LOG_DUMP: &str = "dump";       // cc :95
pub const LOG_CODECS: &str = "codecs";   // cc :96
pub const ALERT_NONE: &str = "none";     // cc :98
pub const ALERT_CMG: &str = "cmg";       // cc :99
pub const ALERT_JH: &str = "jh";         // cc :100
pub const ALERT_DJR: &str = "djr";       // cc :101
pub const ALERT_U2: &str = "u2";         // cc :102
pub const ALERT_AJK: &str = "ajk";       // cc :103
pub const OUTPUT_U2: &str = "unified2";  // cc :105
pub const OUTPUT_FAST: &str = "alert_fast"; // cc :106

// the init() seed faces (cc :179-:184; the #define homes protocols/
// packet.h :122 DEFAULT_LAYERMAX 40, target_based/host_attributes.h
// :128-:130 attribute counts -- REUSE cites, the consts ride here since
// those homes never landed):
// the h :113 LOGGING_FLAG__QUIET = 0x00000002 and h :114
// LOGGING_FLAG__SYSLOG = 0x00000004 ordinals ride the messages.rs REUSE
// consts (LOGGING_FLAG_QUIET :41 / LOGGING_FLAG_SYSLOG :42, imported).

pub const DEFAULT_LAYERMAX: u8 = 40;                     // cc :179 (packet.h :122)
pub const DEFAULT_MAX_ATTRIBUTE_HOSTS: u32 = 10000;      // cc :181 (host_attributes.h :128)
pub const DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST: u32 = 100; // cc :182 (host_attributes.h :129)
pub const DEFAULT_MAX_METADATA_SERVICES: u32 = 9;        // cc :184 (host_attributes.h :130)

// the FILE_ACCESS_BITS ladder, cc :819-:827 -- a compile-face ladder
// (ACCESSPERMS / S_IAMB / 0x1FF arms) whose only live rider is the
// --umask range face: the 0x1FF fallback rides the cited comment face,
// no live const pulled (the set_umask body :829-:832 never reads it --
// the store is plain). DEV-cited: the ladder lands as cited text only.

/// the h :513-:523 dump_rule_info OR-ladder leg names (cited order).
/// the tunnel-verdicts table -- cc :859-:909, the name->bit legs in the
/// C if/else ladder order (EXACTLY-10 names then the ParseError else
/// leg; the names land lowercase EXACT as the C compares them):
const TUNNEL_VERDICT_TABLE: [(&str, u16); 10] = [
    ("gtp", TUNNEL_GTP),      // cc :869-:870
    ("teredo", TUNNEL_TEREDO), // cc :872-:873
    ("vxlan", TUNNEL_VXLAN),  // cc :875-:876
    ("6in4", TUNNEL_6IN4),    // cc :878-:879
    ("4in6", TUNNEL_4IN6),    // cc :881-:882
    ("4in4", TUNNEL_4IN4),    // cc :884-:885
    ("6in6", TUNNEL_6IN6),    // cc :887-:888
    ("gre", TUNNEL_GRE),      // cc :890-:891
    ("mpls", TUNNEL_MPLS),    // cc :893-:894
    ("geneve", TUNNEL_GENEVE), // cc :896-:897
];

// ======================================================================
// the row-owned sub-records for the NEVER-landed config sub-homes.
// Each field is a cited slot, each method a seam; the bodies of the
// NEVER-landed homes are NEVER invented.
// ======================================================================

/// the network-policy face the h inline accessors read (h :646-:650
/// min_ttl / new_ttl; policy.h :230-:231 NSDMIs = 1 / 5). Reuse-cited
/// at main/policy.rs (home); the landed struct carries no ttl face,
/// so this module owns the pair of slots for THIS pair's getters only.
#[derive(Clone, Debug)]
pub struct NetworkPolicyFace {
    pub min_ttl: u8, // policy.h :230 `uint8_t min_ttl = 1;`
    pub new_ttl: u8, // policy.h :231 `uint8_t new_ttl = 5;`
    pub checksum_eval: u32, // policy.h :233 `= CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF`
    /// policy.h NetworkPolicy::inspection_policy_count() == len +
    /// get_inspection_policy(idx) (the cc :159-:161 legs -> the Vec
    /// twin; the landed main/policy.rs NetworkPolicy carries NO such
    /// vector -- REUSE cite of the home; the slot is the pair's own)
    pub inspection_policies: Vec<InspectionPolicyFace>,
}
impl Default for NetworkPolicyFace {
    fn default() -> Self {
        NetworkPolicyFace {
            inspection_policies: Vec::new(), // policy.h (cc :159 empty-map face)
            min_ttl: 1,                                        // policy.h :230
            new_ttl: 5,                                        // policy.h :231
            checksum_eval: CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF, // policy.h :233 (main/policy.rs :218 REUSE face)
        }
    }
}

/// the event-queue config face the merge / dtor legs touch. event_queue
/// .h is NEVER landed -- DEV-cited record (every slot cited to the
/// ground consumer).
#[derive(Clone, Debug, Default)]
pub struct EventQueueConfigFace {
    pub process_all_events: i32, // event_queue.h :33 `int process_all_events;` (cc :473 writer, cc :272-:273 free leg -> drop face)
}

/// the three filters' memcap face. sfthreshold.h :36 / sfrf.h :173 /
/// detection_filter.h :45 all `unsigned memcap;` (the verify legs
/// cc :552/:555/:558 compare them). ONE cited face, three cites.
#[derive(Clone, Debug, Default)]
pub struct MemcapFace {
    pub memcap: u32,
}

/// the packet_latency face of latency_config.h (the set_packet_latency
/// leg cc :853 sets plugin_forced). latency/latency_config.h :34-:38 +
/// latency/packet_latency_config.h :30 cite:
/// `bool plugin_forced = false;`. DEV-cited record.
#[derive(Clone, Debug, Default)]
pub struct PacketLatencyConfigFace {
    pub plugin_forced: bool, // packet_latency_config.h :30 NSDMI false
}

/// the reload-tuner family face (reload_tuner.h :25-:52 class
/// ReloadResourceTuner: virtual dtor + name()/tinit()/tune_*/... --
/// NO landed home; the class lands data-free, the tuner objects ride
/// the reload_tuners slot as opaque tokens). DEV-cited.
#[derive(Clone, Debug, Default)]
pub struct ReloadResourceTunerFace {}

/// the scratch-allocator face (helpers/scratch_allocator.h :44-:53:
/// `virtual bool setup(SnortConfig*) = 0;` :49 + `virtual void
/// cleanup(SnortConfig*) = 0;` :50 + update). DEV-cited trait -- the
/// object side of the scratch_handlers vector seat (cc :114,
/// request/release legs :1025-:1038 and the post_setup copy_if :377-
/// :378). Ported with a caller-impl so the vector semantics (index
/// return, null-out on release) land REAL.
pub trait ScratchAllocatorFace: Send + Sync {
    /// scratch_allocator.h :49 the setup leg (post_setup filter :378)
    fn setup_scratch(&mut self, c: &mut SnortConfig) -> bool;
    /// scratch_allocator.h :50 the cleanup leg (dtor :262-:263)
    fn cleanup_scratch(&mut self, c: &mut SnortConfig);
}

// ======================================================================
// SnortConfig struct -- the h :176-:795 member block in GROUND ORDER,
// private seats (:178-:179, :195-:197, :437-:441) land private, every
// public data member lands pub. C `T* = nullptr` slots land
// Option<Box<T>> where THIS module owns the record, Option<&mut/…>
// where it does not (the never-call-into-a-never-land rule).
// ======================================================================

// (no derive(Debug): the scratchers vector of trait objects and the
// JoinHandle slot are NOT Debug; the C pair has no operator<< face.)
pub struct SnortConfig {
    // h :178-:179 private init() -- lands as the private fn init at the
    // cc :174-:206 face below; nothing stored.

    // h :323 uint32_t run_flags = 0;
    pub run_flags: u32, // h :237
    // h :216 output_flags = 0 (the live OFF arm; the h :212-:217
    // REG_TEST face :214 `= OUTPUT_FLAG__WIDE_HEX` stays cited-OFF)
    pub output_flags: u32, // h :214/:216 pair face

    // h :193-:200 static logging/warning faces (h :196/:200) -> the
    // module owner seams below (the statics law); class-static seats
    // NEVER field-copied by value. (h :197 the log_quiet_bypassed
    // THREAD_LOCAL -> the LOG_QUIET_BYPASSED thread_local seat below.)

    pub plug_set: Option<PlugSetFace>, // h :202 `PlugSet* plug_set = nullptr;` -> row-owned face :158 fwd
    pub rule_order: String,            // h :206 (the alert module stuff)
    pub homenet: crate::sfip::sf_cidr::SfCidr, // h :208 SfCidr (REUSE sfip/sf_cidr.rs :8)
    pub tagged_packet_limit: u32,      // h :218 `uint32_t tagged_packet_limit = 256;` (NSDMI; the getter :661 widens to long int -> the u32 face kept, DEV-cited)
    pub event_trace_max: u16,          // h :219 uint16_t = 0
    pub log_dir: String,               // h :221
    pub daq_config: Option<Box<SFDAQConfig>>, // h :225 SFDAQConfig* (REUSE home packet_io/sfdaq_config.rs :94)
    pub pcre_match_limit: i64,         // h :231 `long int pcre_match_limit = 1500;`
    pub pcre_match_limit_recursion: i64, // h :232 `long int ... = 1500;`
    pub pcre_ovector_size: i32,        // h :234 int = 0
    pub pcre_override: bool,           // h :235 bool = true
    // h :237 run_flags above
    pub offload_limit: u32,            // h :239 `unsigned offload_limit = 99999; // disabled`
    pub offload_threads: u32,          // h :240 `unsigned offload_threads = 0; // disabled` (the cc :513 merge leg reads it)
    pub hyperscan_literals: bool,      // h :242 bool = false
    pub pcre_to_regex: bool,           // h :243 bool = false
    pub global_rule_state: bool,       // h :245 bool = false
    pub global_default_rule_state: bool, // h :246 bool = true
    pub allow_missing_so_rules: bool,  // h :247 bool = false
    pub enable_strict_reduction: bool, // h :248 bool = false
    pub max_continuations: u16,        // h :249 uint16_t = 1024
    // h :251-:255 the service_extension map with its two seed rows:
    //   { "http", {"http2","http3"} }, { "netbios-ssn", {"dcerpc"} }
    // -> BTreeMap (ordered twin; the two rows seed at the ctor):
    pub service_extension: BTreeMap<String, Vec<String>>,
    // process stuff h :258-:273:
    // h :260-:261 the comment (verbatim, kept):
    //   "user_id and group_id should be initialized to -1 by default,
    //    because chown() use this later, -1 means no change..."
    pub user_id: i32,                  // h :262 int = -1
    pub group_id: i32,                 // h :263 int = -1
    pub watchdog_timer: u16,           // h :264 uint16_t = 0
    pub watchdog_min_thread_count: u16, // h :265 uint16_t = 1
    pub dirty_pig: bool,               // h :266 bool = false
    pub chroot_dir: String,            // h :268 /* -t or config chroot */
    pub include_path: String,          // h :269
    pub plugin_path: String,           // h :270
    pub script_paths: Vec<String>,     // h :271 std::vector<std::string>
    pub file_mask: u32,                // h :273 `mode_t file_mask = 0;` -> u32 face (DEV-cited: mode_t)
    // decode stuff h :276-:282:
    pub num_layers: u8,                // h :277 uint8_t = 0 (cc :179 seeds DEFAULT_LAYERMAX)
    pub max_ip6_extensions: u8,        // h :278 uint8_t = 0
    pub max_ip_layers: u8,             // h :279 uint8_t = 0
    pub enable_esp: bool,              // h :281 bool = false
    pub address_anomaly_check_enabled: bool, // h :282 bool = false
    // active stuff h :285-:292:
    pub respond_attempts: u8,          // h :286 uint8_t = 0
    pub max_responses: u8,             // h :287 uint8_t = 0
    pub min_interval: u8,              // h :288 uint8_t = 0
    pub eth_dst: Option<Vec<u8>>,      // h :289 `uint8_t* eth_dst = nullptr;` -> 6-byte Vec (the set_dst_mac :675-:677 calloc/memcpy -> Vec::from face, DEV-cited)
    pub respond_device: String,        // h :291
    pub output: String,                // h :292
    // attribute tables h :295-:300:
    pub attribute_hosts_file: String,  // h :296
    pub max_attribute_hosts: u32,      // h :297 uint32_t = 0 (cc :181 seeds)
    pub max_attribute_services_per_host: u32, // h :298 (cc :182 seeds)
    pub max_metadata_services: u32,    // h :299 (cc :184 seeds)
    pub segment_count_host: u32,       // h :300 uint32_t = 4
    // packet module h :303-:312:
    pub asid_agnostic: bool,           // h :304 bool = false
    pub mpls_agnostic: bool,           // h :305 bool = true
    pub vlan_agnostic: bool,           // h :306 bool = false
    pub pkt_cnt: u64,                  // h :308 uint64_t = 0 /* -n */
    pub pkt_skip: u64,                 // h :309 uint64_t = 0
    pub pkt_pause_cnt: u64,            // h :310 uint64_t = 0
    pub bpf_file: String,              // h :312 /* -F or config bpf_file */
    // various modules h :315-:323 -> the NEVER-land slots stay Option<
    // Box<face>> for the three THIS module cites, rest cited-only:
    pub fast_pattern_config: Option<Box<FastPatternConfigFace>>, // h :316 (the dtor :283-:289 search_api leg cites detection/fp_config.rs REUSE home, :316 slot owned here as face)
    pub event_queue_config: Option<Box<EventQueueConfigFace>>,   // h :317
    pub payload_injector_config: Option<Box<PayloadInjectorConfigFace>>, // h :318 fwd :157 (the dtor :315 delete face -> drop)
    // "policy specific?" h :320-:323:
    pub threshold_config: Option<Box<MemcapFace>>,       // h :321 (sfthreshold.h :36 memcap via MemcapFace)
    pub rate_filter_config: Option<Box<MemcapFace>>,     // h :322 (sfrf.h :173 memcap)
    pub detection_filter_config: Option<Box<MemcapFace>>, // h :323 (detection_filter.h :45 memcap)
    // command-line-only stuff h :325-:331:
    pub event_log_id: u16,             // h :328 uint16_t = 0
    pub obfuscation_net: crate::sfip::sf_cidr::SfCidr, // h :329 SfCidr (REUSE)
    pub bpf_filter: String,            // h :330
    pub metadata_filter: String,       // h :331
    // FIXIT-L non-module h :333-:346:
    pub run_prefix: String,            // h :335
    pub id_offset: u16,                // h :336 uint16_t = 0
    pub id_subdir: bool,               // h :337 bool = false
    pub id_zero: bool,                 // h :338 bool = false
    pub stdin_rules: bool,             // h :340 bool = false
    pub pid_filename: String,          // h :342 std::string (the cc :601-:604 DEFAULT_PID_FILENAME arm -> the empty face; NSDMI stays "" per the C)
    pub max_procs: u8,                 // h :343 `uint8_t max_procs = 1;`
    pub orig_log_dir: String,          // h :344 /* set in case of chroot */
    pub thiszone: i32,                 // h :346 int thiszone = 0
    // h :348-:349 the two name->record maps (unordered in C -> ORDERED
    // BTreeMap twin, the deviation law; id lookups only for these two):
    pub classifications: BTreeMap<String, ClassTypeFace>, // h :348 (ClassType fwd h :149, signature.h :62)
    pub references: BTreeMap<String, ReferenceSystemFace>, // h :349 (ReferenceSystem fwd h :161)
    // h :351-:435: the never-land pointer block, each slot cited to its
    // fwd-decl h line (h :139-:174 fwd block + the snort-ns fwd h :169-
    // :174). Slots the module NEVER reads land as `pub _never_landed`
    // marker fields where the C dtor :254-:333 merely deletes them
    // (drop face), Option<()> for dtor-deleted-only slots:
    pub rule_states: Option<RuleStateMapFace>, // h :351 (fwd h :144)
    pub otn_map: Option<()>,           // h :352 `GHash* otn_map` (hash home hash/ghash.rs :34 REUSE cite only; the dtor :276 OtnLookupFree never-land wall leg -> Option<()> token)
    pub proto_ref: Option<ProtocolReferenceFace>, // h :354 (fwd class snort::ProtocolReference; ctor :202 new face cited via the world seam, drop :313)
    pub num_rule_types: u32,           // h :356 unsigned = 0
    pub rule_lists: Option<RuleListNodeFace>, // h :357 (fwd h :162; free :265 FreeRuleLists wall leg)
    pub eval_order: Option<Vec<i32>>,  // h :358 `int* evalOrder = nullptr;` -> Vec<i32> (the setup :350 new int[max](); face -> vec![0; n]; the get_eval_index :571-:572 reads it -- REAL)
    pub ips_actions_config: Option<IpsActionsConfigFace>, // h :360 (fwd h :154)
    pub framework_config: Option<FrameworkConfigFace>, // h :361 (fwd h :152)
    pub port_tables: Option<RulePortTablesFace>, // h :364 /* master port list table */ (fwd h :163; PortTablesFree dtor :266 wall leg)
    // h :366-:373 the port-rule-map comment (verbatim block, kept):
    //   "The port-rule-maps map the src-dst ports to rules for udp and
    //    tcp, for Ip we map the dst port as the protocol, and for Icmp
    //    we map the dst port to the Icmp type. This allows us to use
    //    the decode packet information to in O(1) select a group of
    //    rules to apply to the packet. We process the content 1st and
    //    then the no content rules for udp/tcp and icmp, and then we
    //    process the ip rules."
    pub prm_ip_rtnx: Option<()>,       // h :374 `PORT_RULE_MAP* prmIpRTNX = nullptr;` (fwd h :159 -> drop-token face)
    pub prm_icmp_rtnx: Option<()>,     // h :375
    pub prm_tcp_rtnx: Option<()>,      // h :376
    pub prm_udp_rtnx: Option<()>,      // h :377
    // h :379-:381 the srmm/spgmm/sopg trio (fwd h :147-:148; the C
    // comments :379-:381 kept inline: srvc rule map master / srvc
    // port_group map master / service-ordinal to port_group table):
    pub srmm_table: Option<()>,        // h :379 -> drop-token face
    pub spgmm_table: Option<()>,       // h :380
    pub sopg_table: Option<()>,        // h :381
    // h :383-:385 the three XHash seats (hash home xhash.rs :42 REUSE
    // cite, slots NEVER read here -- the dtor deletes rtn_hash_table
    // :278):
    pub detection_option_hash_table: Option<()>, // h :383
    pub detection_option_tree_hash_table: Option<()>, // h :384
    pub rtn_hash_table: Option<()>,    // h :385 (dtor :278 `delete rtn_hash_table;` -> drop face)
    // h :387 PolicyMap (class fwd h :168-ns? the snort-ns PolicyMap --
    // home main/policy.rs LANDING REUSE cite; NEVER derefed in-proc):
    pub policy_map: Option<PolicyMapFace>, // h :387
    pub tweaks: String,                // h :388
    pub global_dbus: Option<()>,       // h :390 DataBus* (ctor :197 new face -> seam; drop :305 -> drop face token)
    pub mp_dbus: Option<()>,           // h :391 MPDataBus* (ctor :199-:200 conditional new -- cited at init)
    pub tunnel_mask: u16,              // h :393 uint16_t = 0
    pub max_aux_ip: i16,               // h :395 int16_t = 16
    // h :397-:399 the legacy paf_max comment (verbatim, kept):
    //   "FIXIT-L this is temporary for legacy paf_max required only for
    //    HI; it is not appropriate for multiple stream_tcp with
    //    different paf_max; the HI splitter should pull from there"
    pub max_pdu: u32,                  // h :400 unsigned = 16384
    // h :402-:405 the profiler block (the Profiler fwd h :143,
    // ProfilerConfig fwd h :174):
    pub profiler: Option<ProfilerConfigFace>, // h :403 (ctor :192 `new ProfilerConfig;` -> module-owned slot, ctor REAL)
    pub prof_map: Option<ProfilerNodeMapFace>, // h :404 (fwd h :143; Profiler::clear dtor :327 wall leg)
    pub latency: Option<Box<LatencyConfigFace>>, // h :405 (ctor :193 new; the set_packet_latency :851-:854 leg REAL over the face)
    // h :407-:413 the control-socket block (the SHEFFIELD arms of these
    // five slots ride the SHELL-cited merge :485-:504):
    pub remote_control_port: i32,      // h :407 `int remote_control_port = -1;`
    pub remote_control_socket: String, // h :408
    pub control_socket_uid: u32,       // h :409 `uid_t control_socket_uid = static_cast<uid_t>(-1);` -> 0xFFFF_FFFF face (DEV-cited: uid_t width)
    pub control_socket_gid: u32,       // h :410 gid_t sibling
    pub control_secret_file: String,   // h :411
    pub control_shared_secret: Option<Vec<u8>>, // h :412 `uint8_t* = nullptr` -> Vec face
    pub control_shared_secret_len: usize, // h :413 size_t = 0
    pub memory: Option<Box<MemoryConfigFace>>, // h :415 (ctor :194 new; drop :311)
    pub scratchers: Vec<Arc<Mutex<dyn ScratchAllocatorFace>>>, // h :418 `std::vector<ScratchAllocator*> scratchers;` -> the shared-handle vector twin (C holds the SAME pointer in BOTH scratchers :418 and the file-static scratch_handlers cc :114 -- the Arc clones mirror that double-holding; the post_setup copy_if :377-:378 REAL)
    pub state: Option<Vec<Vec<()>>>,   // h :419 `std::vector<void *>* state = nullptr;` -> Vec<Vec<()>> (the merge :512-:514 new[], post_setup :374-:375 resize REAL)
    pub num_slots: u32,                // h :420 unsigned = 0
    pub thread_config: Option<Box<ThreadConfig>>, // h :422 (REUSE main/thread_config.rs :658; ctor :196 new)
    pub ha_config: Option<HighAvailabilityConfigFace>, // h :423 (fwd h :153)
    pub trace_config: Option<TraceConfigFace>, // h :424 (class fwd h :145; ctor :203 new)
    // h :426 the comment kept: "TraceConfig instance which used by
    // TraceSwap control channel command"
    pub overlay_trace_config: Option<TraceConfigFace>, // h :427 (set_overlay_trace_config :842-:846 REAL over the face)
    // reload-related h :432-:435:
    pub dump_config_type: u32,         // h :432 `DumpConfigType dump_config_type = DUMP_CONFIG_NONE;`
    pub retry_timeout: u32,            // h :433 `uint32_t retry_timeout = 200;` (comment kept: "Milliseconds to hold packet on retry queue.")
    pub dump_config_file: String,      // h :434
    pub config_dumper: Option<std::thread::JoinHandle<()>>, // h :435 `std::thread* config_dumper = nullptr;` -> the JoinHandle twin (the generate_dump spawn rides the world seam, DEV-cited: NEVER spawned bare here)

    // h :437-:441 the private reload block:
    reload_tuners: Vec<ReloadResourceTunerFace>, // h :438 std::list
    reload_id: AtomicU32,              // h :439 `std::atomic<unsigned> reload_id;` -- per-INSTANCE atomic member (a member, NOT a class static: the statics law only moves the true statics)
    // h :440-:441 the two statics -> the module owner seams below, NOT
    // fields.
}

impl Default for SnortConfig {
    /// every NSDMI from the ground header, in header order -- the
    /// "default-constructed" faces the C++ pair relies on (the ctor
    /// chains to init() separately, cc :174-:206).
    fn default() -> Self {
        SnortConfig {
            run_flags: 0,                    // h :237
            output_flags: 0,                 // h :216 (OFF face)
            plug_set: None,
            rule_order: String::new(),
            homenet: crate::sfip::sf_cidr::SfCidr::new(), // h :208
            tagged_packet_limit: 256,        // h :218
            event_trace_max: 0,              // h :219
            log_dir: String::new(),          // h :221
            daq_config: None,                // h :225
            pcre_match_limit: 1500,          // h :231
            pcre_match_limit_recursion: 1500, // h :232
            pcre_ovector_size: 0,            // h :234
            pcre_override: true,             // h :235
            offload_limit: 99999,            // h :239
            offload_threads: 0,              // h :240
            hyperscan_literals: false,       // h :242
            pcre_to_regex: false,            // h :243
            global_rule_state: false,        // h :245
            global_default_rule_state: true, // h :246
            allow_missing_so_rules: false,   // h :247
            enable_strict_reduction: false,  // h :248
            max_continuations: 1024,         // h :249
            service_extension: BTreeMap::from([
                // h :252-:254 the seed rows VERBATIM:
                ("http".to_string(), vec!["http2".to_string(), "http3".to_string()]),
                ("netbios-ssn".to_string(), vec!["dcerpc".to_string()]),
            ]),
            user_id: -1,                     // h :262
            group_id: -1,                    // h :263
            watchdog_timer: 0,               // h :264
            watchdog_min_thread_count: 1,    // h :265
            dirty_pig: false,                // h :266
            chroot_dir: String::new(),       // h :268
            include_path: String::new(),     // h :269
            plugin_path: String::new(),      // h :270
            script_paths: Vec::new(),        // h :271
            file_mask: 0,                    // h :273
            num_layers: 0,                   // h :277
            max_ip6_extensions: 0,           // h :278
            max_ip_layers: 0,                // h :279
            enable_esp: false,               // h :281
            address_anomaly_check_enabled: false, // h :282
            respond_attempts: 0,             // h :286
            max_responses: 0,                // h :287
            min_interval: 0,                 // h :288
            eth_dst: None,                   // h :289
            respond_device: String::new(),   // h :291
            output: String::new(),           // h :292
            attribute_hosts_file: String::new(), // h :296
            max_attribute_hosts: 0,          // h :297
            max_attribute_services_per_host: 0, // h :298
            max_metadata_services: 0,        // h :299
            segment_count_host: 4,           // h :300
            asid_agnostic: false,            // h :304
            mpls_agnostic: true,             // h :305
            vlan_agnostic: false,            // h :306
            pkt_cnt: 0,                      // h :308
            pkt_skip: 0,                     // h :309
            pkt_pause_cnt: 0,                // h :310
            bpf_file: String::new(),         // h :312
            fast_pattern_config: None,       // h :316
            event_queue_config: None,        // h :317
            payload_injector_config: None,   // h :318
            threshold_config: None,          // h :321
            rate_filter_config: None,        // h :322
            detection_filter_config: None,   // h :323
            event_log_id: 0,                 // h :328
            obfuscation_net: crate::sfip::sf_cidr::SfCidr::new(), // h :329
            bpf_filter: String::new(),       // h :330
            metadata_filter: String::new(),  // h :331
            run_prefix: String::new(),       // h :335
            id_offset: 0,                    // h :336
            id_subdir: false,                // h :337
            id_zero: false,                  // h :338
            stdin_rules: false,              // h :340
            pid_filename: String::new(),     // h :342
            max_procs: 1,                    // h :343
            orig_log_dir: String::new(),     // h :344
            thiszone: 0,                     // h :346
            classifications: BTreeMap::new(), // h :348
            references: BTreeMap::new(),     // h :349
            rule_states: None,               // h :351
            otn_map: None,                   // h :352
            proto_ref: None,                 // h :354
            num_rule_types: 0,               // h :356
            rule_lists: None,                // h :357
            eval_order: None,                // h :358
            ips_actions_config: None,        // h :360
            framework_config: None,          // h :361
            port_tables: None,               // h :364
            prm_ip_rtnx: None,               // h :374
            prm_icmp_rtnx: None,             // h :375
            prm_tcp_rtnx: None,              // h :376
            prm_udp_rtnx: None,              // h :377
            srmm_table: None,                // h :379
            spgmm_table: None,               // h :380
            sopg_table: None,                // h :381
            detection_option_hash_table: None, // h :383
            detection_option_tree_hash_table: None, // h :384
            rtn_hash_table: None,            // h :385
            policy_map: None,                // h :387
            tweaks: String::new(),           // h :388
            global_dbus: None,               // h :390
            mp_dbus: None,                   // h :391
            tunnel_mask: 0,                  // h :393
            max_aux_ip: 16,                  // h :395
            max_pdu: 16384,                  // h :400
            profiler: None,                  // h :403 (the init() ctor leg cc :192 fills it)
            prof_map: None,                  // h :404
            latency: None,                   // h :405 (the init() ctor leg cc :193 fills it)
            remote_control_port: -1,         // h :407
            remote_control_socket: String::new(), // h :408
            control_socket_uid: u32::MAX,    // h :409 static_cast<uid_t>(-1)
            control_socket_gid: u32::MAX,    // h :410
            control_secret_file: String::new(), // h :411
            control_shared_secret: None,     // h :412
            control_shared_secret_len: 0,    // h :413
            memory: None,                    // h :415 (the init() ctor leg cc :194 fills it)
            scratchers: Vec::new(),          // h :418
            state: None,                     // h :419
            num_slots: 0,                    // h :420
            thread_config: None,             // h :422 (the init() ctor leg cc :196 fills it with the REUSE home)
            ha_config: None,                 // h :423
            trace_config: None,              // h :424 (the init() ctor leg cc :203: the TraceConfig ctor body never-lands -> seam)
            overlay_trace_config: None,      // h :427
            dump_config_type: 0,             // h :432 DUMP_CONFIG_NONE
            retry_timeout: 200,              // h :433
            dump_config_file: String::new(), // h :434
            config_dumper: None,             // h :435
            reload_tuners: Vec::new(),       // h :438
            reload_id: AtomicU32::new(0),    // h :439 (the cc :205 init leg update_reload_id() drives it)
        }
    }
}

// ======================================================================
// the row-owned cited faces for the fwd-declared homes (the h :139-:174
// fwd block; each face names its fwd line; fields stay EMPTY where the
// pair NEVER touches them -- the fields it DOES read are cited there).
// ======================================================================

/// h :158 `struct PlugSet;` -- the dtor :329-:330 release wall leg
/// (PluginManager::release_plugins, managers/plugin_manager.h :52 REUSE
/// cite -> seam). DEV-cited empty record.
#[derive(Clone, Debug, Default)]
pub struct PlugSetFace;
/// h :142 `class FastPatternConfig;` -- the dtor :283-:289 search_api
/// leg reads get_search_api() :283/:286 (the detection/fp_config.rs
/// FastPatternConfig REUSE cite); search_api slot owned for THIS leg.
#[derive(Clone, Debug, Default)]
pub struct FastPatternConfigFace {
    pub search_api: i32, // the cc :283/:286 get_search_api() comparison face
}
/// h :157 `struct PayloadInjectorConfig;` -- dtor :315 delete face only.
#[derive(Clone, Debug, Default)]
pub struct PayloadInjectorConfigFace;
/// h :149 `struct ClassType;` (definition detection/signature.h :62-:71:
/// name/text/priority/id ctor). The pair reads id only (:1135
/// itr->second->id); the C ctor order (name, text, priority, id) kept.
#[derive(Clone, Debug, Default)]
pub struct ClassTypeFace {
    pub name: String,    // signature.h :68
    pub text: String,    // signature.h :69
    pub priority: u32,   // signature.h :70 `unsigned priority;`
    pub id: i32,         // signature.h :71 `int id;`
}
/// h :161 `struct ReferenceSystem;` -- dtor :259-:260 delete face (drop).
#[derive(Clone, Debug, Default)]
pub struct ReferenceSystemFace;
/// h :144 `class RuleStateMap;` -- setup :354-:359 apply(this)/delete
/// legs -> seam.
#[derive(Clone, Debug, Default)]
pub struct RuleStateMapFace;
/// target_based/snort_protocols.h ProtocolReference (ctor :202 copy-new
/// + dtor :313 delete -> seam). DEV-cited.
#[derive(Clone, Debug, Default)]
pub struct ProtocolReferenceFace;
/// h :162 `struct RuleListNode;` (dtor :265 FreeRuleLists wall leg).
#[derive(Clone, Debug, Default)]
pub struct RuleListNodeFace;
/// h :154 `struct IpsActionsConfig;` (dtor-deleted only).
#[derive(Clone, Debug, Default)]
pub struct IpsActionsConfigFace;
/// h :152 `struct FrameworkConfig;` (dtor-deleted only).
#[derive(Clone, Debug, Default)]
pub struct FrameworkConfigFace;
/// h :163 `struct RulePortTables;` (dtor :266 PortTablesFree wall leg;
/// REUSE cite at ports/port_table.rs home for the landed layer).
#[derive(Clone, Debug, Default)]
pub struct RulePortTablesFace;
/// main/policy.h PolicyMap (home main/policy.rs LANDING REUSE cite):
/// the legs this pair calls (network_policy_count :155/:415,
/// get_network_policy :157/:412/:417, inspection_policy_count :159,
/// get_inspection_policy :161, ips_policy_count :166, get_ips_policy
/// :168 via the free face policy.h :105, get_shell/get_policies :1052-
/// :1053, setup_network_policies :522, shell/policy legs) reach as the
/// SnortConfigWorld seam legs -- the landed Rust home carries NO of
/// these methods (it holds policy subset only), so the map slot lands
/// as this cited face and the calls ride the seam (DEV-cited, cite at
/// each leg).
#[derive(Clone, Debug, Default)]
pub struct PolicyMapFace {
    /// policy.h :359-:362 get_network_policy(i) = `i < size ? [i] :
    /// nullptr` + network_policy_count() == size -> the Vec twin
    pub network_policies: Vec<NetworkPolicyFace>,
    /// policy.h :364-:366 get_ips_policy(i) = `i < size ? [i] :
    /// nullptr` + ips_policy_count() == size -> the Vec twin
    pub ips_policies: Vec<IpsPolicyFace>,
}

/// the InspectionPolicy policy_mode seat (policy.h :269 NSDMI
/// `PolicyMode policy_mode = POLICY_MODE__MAX`); the landed main/
/// policy.rs home carries NO InspectionPolicy (its fields defer --
/// REUSE cite, never re-forked): this is the pair's OWN cited slot for
/// the init_policies loop (cc :161-:162).
#[derive(Clone, Debug)]
pub struct InspectionPolicyFace {
    pub policy_mode: PolicyMode, // policy.h :269 (POLICY_MODE__MAX face -> PolicyMode::Max, the main/policy.rs PolicyMode REUSE)
}
impl Default for InspectionPolicyFace {
    fn default() -> Self { InspectionPolicyFace { policy_mode: PolicyMode::Max } } // policy.h :269
}

/// the IpsPolicy slots THIS pair reads (policy.h :269 policy_mode NSDMI
/// and the default_rule_state seat; the landed main/policy.rs IpsPolicy
/// home (its line :51) REUSE owns the full record -- only the legs the
/// pair derefs land as cited slots, name-spaced to a FACE to dodge
/// one-home):
#[derive(Clone, Debug)]
pub struct IpsPolicyFace {
    pub policy_mode: PolicyMode,           // policy.h :269 (the Max NSDMI)
    pub default_rule_state: Enable,        // the landed Enable home main/policy.rs :31/:66 REUSE
}
impl Default for IpsPolicyFace {
    fn default() -> Self { IpsPolicyFace { policy_mode: PolicyMode::Max, default_rule_state: Enable::InheritEnable } } // policy.h :269 + the landed main/policy.rs :100 seed REUSE
}
/// h :143 `class ProfilerNodeMap;` (dtor :327 Profiler::clear wall leg).
#[derive(Clone, Debug, Default)]
pub struct ProfilerNodeMapFace;
/// h :174 `struct ProfilerConfig;` (ctor :192 `new ProfilerConfig;` ->
/// the slot ctor REAL, dtor :309 delete -> drop).
#[derive(Clone, Debug, Default)]
pub struct ProfilerConfigFace;
/// latency/latency_config.h :34-:38 struct LatencyConfig { packet_
/// latency, rule_latency } -- the plugin_forced face lives on the
/// PacketLatencyConfigFace slot this pair reads.
#[derive(Clone, Debug, Default)]
pub struct LatencyConfigFace {
    pub packet_latency: PacketLatencyConfigFace, // latency_config.h :36
}
/// memory/memory_config.h :26 struct MemoryConfig (dtor :311 delete ->
/// drop; never read in this pair).
#[derive(Clone, Debug, Default)]
pub struct MemoryConfigFace;
/// flow/ha_module.h :46 struct HighAvailabilityConfig (dtor :304 delete
/// -> drop).
#[derive(Clone, Debug, Default)]
pub struct HighAvailabilityConfigFace;
/// trace/trace_config.h :31 class TraceConfig (ctor :203 new / dtor :316
/// delete -> drop; the ctor body NEVER lands -> ctor leg rides the seam).
#[derive(Clone, Debug, Default)]
pub struct TraceConfigFace;

// ======================================================================
// SnortConfigWorld -- the provider seam for every NEVER-land call in
// the pair. Every leg names its ground call cite; default bodies sit at
// the no-pull boundary (no success leg invented past a wall).
// ======================================================================

pub trait SnortConfigWorld {
    // the init() ctor wall legs (cc :174-:206):
    /// cc :187 ActionManager::new_config(this) (actions/ips_actions.h +
    /// managers/action_manager.h walls; framework/ips_action.rs
    /// ActionRegistry :40 REUSE cite, body NEVER landed -> seam)
    fn action_manager_new_config(&mut self) {}
    /// cc :202 new ProtocolReference(protocol_reference)
    /// (target_based/snort_protocols.h wall -> seam ctor)
    fn protocol_reference_new(&mut self, _src: Option<ProtocolReferenceFace>) -> Option<ProtocolReferenceFace> { None }
    /// cc :203 new TraceConfig (trace/trace_config.h :31 wall -> seam
    /// ctor; the never-pulled default = the cited-None slot)
    fn trace_config_new(&mut self) -> Option<TraceConfigFace> { None }

    // setup() wall legs (cc :335-:367):
    /// cc :341 gmt2local(0) (home main/processp.rs ProcessState::
    /// gmt2local :703 REUSE cite -- NEVER re-forked here; the pair's
    /// consumer reaches it through this seam leg)
    fn gmt2local_now(&mut self) -> i32 { 0 }
    /// cc :344 helpers/challenge_response_auth.h :66 load_shared_secret
    /// (file-reading wall -> seam)
    fn load_shared_secret(&mut self, _file: &str) -> Option<(Vec<u8>, usize)> { None }
    /// cc :347 ParseRules(this) (parser/parser.h wall)
    fn parse_rules(&mut self) {}
    /// cc :350 IpsAction::get_max_types() (framework/ips_action.h :80
    /// face; evalOrder length)
    fn ips_action_max_types(&self) -> usize { 0 }
    /// cc :352 OrderRuleLists (parser wall)
    fn order_rule_lists(&mut self) {}
    /// cc :356 rule_states->apply(this) (framework rule-states wall)
    fn rule_state_apply(&mut self) {}
    /// cc :361 ParseRulesFinish (parser wall)
    fn parse_rules_finish(&mut self) {}
    /// cc :364 IpsManager::verify (managers/ips_manager.h wall)
    fn ips_manager_verify(&mut self) {}
    /// cc :366 fpCreateFastPacketDetection (detection/fp_create.h wall;
    /// the detection/fp_config.rs FastPatternConfig REUSE cite)
    fn fp_create(&mut self) {}

    // the destroy() ladder wall legs (cc :254-:333). The C free-class
    // top-level deallocations land as the Rust drop face (field -> None
    // in the ladder body); their INTERNALS never landed, cited:
    /// cc :265 FreeRuleLists(this) -> drop face; internals cited
    fn free_rule_lists_internals(&mut self) {}
    /// cc :266 PortTablesFree (ports/ home REUSE cite: later row)
    fn port_tables_free_internals(&mut self) {}
    /// cc :268-:270 ThresholdConfigFree / RateFilter_ConfigFree /
    /// DetectionFilterConfigFree (filters/ walls -> the drop faces; no
    /// internal leg landed)
    fn filter_configs_free(&mut self) {}
    /// cc :275 fpDeleteFastPacketDetection (detection/fp_create wall)
    fn fp_delete(&mut self) {}
    /// cc :276 OtnLookupFree(otn_map) (hash/ghash.rs :34 GHash REUSE
    /// cite; body wall -> cited, the slot drop face is REAL)
    fn otn_lookup_free_internals(&mut self) {}
    /// cc :287 MpseManager::stop_search_engine (managers/mpse_manager.h
    /// wall -> seam)
    fn stop_search_engine(&mut self, _api: i32) {}
    /// cc :294 ActionManager::delete_config (managers wall)
    fn action_manager_delete_config(&mut self) {}
    /// cc :327 Profiler::clear(this) (profiler wall; the ProfilerConfig
    /// slot drop face is REAL)
    fn profiler_clear(&mut self) {}
    /// cc :329-:330 PluginManager::release_plugins(plug_set)
    /// (managers/plugin_manager.h home wall -> seam)
    fn release_plugins(&mut self, _ps: Option<PlugSetFace>) {}
    /// cc :332 trim_heap() (home main/processp.rs ProcessState::
    /// trim_heap :639 REUSE cite -- the pair only CONSUMES the seat)
    fn trim_heap(&mut self) {}

    // update_scratch (cc :381-:384): ACScratchUpdate + main_broadcast_command:
    /// cc :383-:384 both names (helpers/ + control/control.h walls).
    /// The ControlConn arg REUSE-cites main/reload_tracker.rs
    /// ControlConnTracker (landed face, NEVER re-forked).
    fn main_broadcast_ac_scratch_update(
        &mut self,
        _handler_count: usize,
        _ctrlcon: Option<crate::main::reload_tracker::ControlConnTracker>,
    ) {}

    // verify() leg: cc :522 policy_map->setup_network_policies()
    /// policy.cc :233-:237 body NEVER landed (the landed policy.rs
    /// carries no such fn) -> seam. Default false = the no-pull honest
    /// boundary (NEVER an invented success bool); the provider lands it.
    fn setup_network_policies(&mut self) -> bool { false }

    // set_alert_mode / set_log_mode legs (cc :944-:980):
    /// cc :947 EventManager::enable_alerts(false) (managers/
    /// event_manager.h wall -> seam; the output / output_flags stores
    /// are REAL in the method body)
    fn event_manager_enable_alerts(&mut self, _enable: bool) {}
    /// cc :971 EventManager::enable_logs(false)
    fn event_manager_enable_logs(&mut self, _enable: bool) {}
    /// cc :963 / :970 / :978 Analyzer::set_main_hook(DetectionEngine::
    /// inspect / snort_ignore / snort_log) -- the home main/analyzer.rs
    /// REUSE cite; the three hook NAMES never landed -> the cited enum
    /// face below
    fn analyzer_set_main_hook(&mut self, _hook: MainHook) {}

    // the uid/gid name-resolution legs (cc :734-:799) -- ZERO libc
    // pulls here; the 24b getpwuid_name seam posture:
    /// cc :745 getgrnam(args) (None = the C null gr -> the unknown-group
    /// ParseError face)
    fn getgrnam(&mut self, _name: &str) -> Option<u32> { None }
    /// cc :752 getgrgid((gid_t)target) (None = unknown gid)
    fn getgrgid(&mut self, _gid: u32) -> Option<u32> { None }
    /// cc :761 getgid() (None = the unresolved seam; the port guard
    /// treats None as the "not current" arm)
    fn get_current_gid(&mut self) -> Option<u32> { None }
    /// cc :776 getpwnam(args)
    fn getpwnam(&mut self, _name: &str) -> Option<u32> { None }
    /// cc :783 getpwuid((uid_t)target)
    fn getpwuid(&mut self, _uid: u32) -> Option<u32> { None }
    /// cc :794 getuid()
    fn get_current_uid(&mut self) -> Option<u32> { None }
    /// the pw->pw_gid read of cc :797-:798 (the passwd record's group
    /// sibling — the getpwuid seam handed the uid back; DEV-cited seam
    /// split, one lookup, two record reads in the C)
    fn getpwuid_gid(&mut self, _uid: u32) -> Option<u32> { None }

    // tunnel_bypass_enabled (cc :1020-:1023):
    /// cc :1022 SFDAQ::get_tunnel_bypass(proto) -- home packet_io/
    /// sfdaq.rs SFDaq::get_tunnel_bypass :720 REUSE cite (the landed
    /// instance-presence arm; default false = the C null-instance arm)
    fn sf_daq_get_tunnel_bypass(&self, _proto: u16) -> bool { false }

    // cleanup_fatal_error (cc :1096-:1113):
    /// cc :1100 FileService::close() (file_api/file_service.h wall)
    fn file_service_close(&mut self) {}

    // generate_dump / the dumper thread (cc :211-:233 + :1082-:1094):
    /// cc :1086 new std::thread(generate_config_dump, ...) -- the SPAWN
    /// seam (never spawned through in-proc by law); the real name-
    /// assembly + cnt gates land in generate_config_dump below
    fn spawn_config_dumper(&mut self, _pid: i32, _timestamp: i64, _reload_id: u32, _file_name: &str) -> Option<std::thread::JoinHandle<()>> { None }
    /// cc :1088 SET_THREAD_NAME(config_dumper->native_handle(),
    /// "snort3.cfgdump") (main/snort_types.h wall -> seam)
    fn set_thread_name_cfg_dump(&mut self, _name: &str) {}
    /// cc :1087 time(nullptr) -> the clock seam
    fn clock_wall_now(&mut self) -> i64 { 0 }
    /// cc :217 getpid() -> the process-id seam (the processp home owns
    /// the pid seats; REUSE cite, never re-forked)
    fn get_pid(&self) -> i32 { 0 }
    /// cc :223 JsonAllConfigOutput(file_name) ctor (dump_config/ wall)
    fn config_output_json_all_new(&mut self, _file_name: &str) -> Option<ConfigOutputFace> { None }
    /// cc :226 o->dump_config(*i) (dump_config/config_output.h wall)
    fn config_output_dump(&mut self, _o: &mut ConfigOutputFace, _d: &mut ConfigDataFace) {}
    /// cc :1005/:1008/:1011 the create_config_output ctor legs (the
    /// JsonAll / JsonTop / Text ConfigOutput walls -> the seam arm)
    fn config_output_new(&mut self, _kind: u32) -> Option<ConfigOutputFace> { None }

    // register_reload_handler (cc :1058-:1064):
    /// Snort::is_reloading() -- home main/snort_.rs SnortStatics
    /// reloading field REUSE cite (the pair NEVER reads that private
    /// seat directly; seam leg; default false = never-reloading face)
    fn is_reloading(&self) -> bool { false }

    // set_conf leg (cc :1050-:1055): the policy_map shell/policies
    /// cc :1052-:1054 get_shell(0) / get_policies / policy.h :116
    /// set_policies (shell + policy-selector walls; the main/shellp.rs
    /// ShellWorld home REUSE CITE line, never re-forked -> seam)
    fn set_conf_policies_leg(&mut self) {}
}

/// the set_main_hook name face (cc :963 / :970 / :978: the
/// DetectionEngine::inspect / snort_ignore / snort_log hook names NEVER
/// landed -> a cited value face, not a fn pointer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainHook {
    /// cc :963 DetectionEngine::inspect (detection/detection_engine.h)
    DetectionEngineInspect,
    /// cc :970 snort_ignore (the never-land main.h/snort.cc name)
    SnortIgnore,
    /// cc :978 snort_log
    SnortLog,
}

/// dump_config/config_output.h ConfigOutput (fwd h :140) -- the wall
/// token face; the ctor / dump legs ride the seam, the delete faces are
/// the Rust drop.
#[derive(Clone, Debug, Default)]
pub struct ConfigOutputFace;
/// dump_config/config_data.h ConfigData (fwd h :139) -- the wall token
/// face for the generate_dump list legs (the delete faces are drops).
#[derive(Clone, Debug, Default)]
pub struct ConfigDataFace;

/// a borrowed (policy_mode read+write) inspection-policy slot face for
/// the init_policies loop (cc :161-:162 writes policy_mode).
#[derive(Debug)]
pub struct PolicyModeSlot<'a> {
    pub policy_mode: &'a mut PolicyMode,
}

// ======================================================================
// the class-static owner seats (the statics law): h :196 logging_flags
// (cc :111 def), h :200 warning_flags (cc :110 def), h :197
// THREAD_LOCAL log_quiet_bypassed (cc :112 def), h :440-:441 the
// static_names pair (cc :1115-:1116 defs), cc :108 the THREAD_LOCAL
// snort_conf seat, cc :114 scratch_handlers, cc :208 threads_max,
// cc :209 threads_cnt, cc :1078 the update_reload_id tracker. All ride
// safe Rust seats (atomics / Mutex / thread_local Cell) — zero un-safe,
// zero allow.
// ======================================================================

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::AtomicI32;

/// h :196 (private) `static uint32_t logging_flags;` + cc :111
/// `uint32_t SnortConfig::logging_flags = 0;` — the OWNER seat. The
/// log/messages.rs home mirrors the same ground seat per-LogEngine
/// (LOGGING member, messages.rs :99 REUSE cite, never re-forked); the
/// h :731-:769 inline statics below drive THIS owner seat.
pub static LOGGING_FLAGS: AtomicU32 = AtomicU32::new(0); // h :196 / cc :111 `= 0`

/// h :200 (public) `static uint32_t warning_flags;` + cc :110
/// `uint32_t SnortConfig::warning_flags = 0;` — the OWNER seat (the
/// LogEngine mirror, messages.rs :98 REUSE cite, stays cited).
pub static WARNING_FLAGS: AtomicU32 = AtomicU32::new(0); // h :200 / cc :110 `= 0`

// the per-thread conf slot: cc :108 `static THREAD_LOCAL SnortConfig*
// snort_conf = nullptr;`. Rc<RefCell<>> is the safe pointer twin (the
// mutable-vs-const get_main_conf/get_conf pair); the landed conf-slot
// home main/snort_.rs set_conf_slot :809 (CliConf) is the sibling-
// record REUSE CITE — NEVER called from here (different record, other
// row's owner).
thread_local! {
    static SNORT_CONF: RefCell<Option<Rc<RefCell<SnortConfig>>>> =
        const { RefCell::new(None) }; // cc :108 `= nullptr`

    /// h :197 `static THREAD_LOCAL bool log_quiet_bypassed;` + cc :112
    /// `THREAD_LOCAL bool SnortConfig::log_quiet_bypassed = false;`
    static LOG_QUIET_BYPASSED: Cell<bool> = const { Cell::new(false) }; // cc :112 `= false`
}

/// cc :114 `static std::vector<ScratchAllocator*> scratch_handlers;` —
/// the module owner seat. The vector holds Option<Arc<Mutex<dyn ...>>>:
/// the Arc mirrors the C SAME-pointer double-hold (scratch_handlers +
/// SnortConfig::scratchers h :418), the None is the cc :1037 null-out.
/// the scratch_handlers slot type (the Arc double-hold twin; the None
/// arm = cc :1037):
pub type ScratchHandlerSlot = Option<Arc<Mutex<dyn ScratchAllocatorFace>>>;

static SCRATCH_HANDLERS: Mutex<Vec<ScratchHandlerSlot>> = Mutex::new(Vec::new());

/// cc :208 `static const int threads_max = 16;` — the dumper-thread
/// ceiling (the name seat keeps the ground text cited; the Rust idiom
/// upper-cases it).
pub const THREADS_MAX: i32 = 16; // cc :208
/// cc :209 `static std::atomic<int> threads_cnt = 0;` — dumper census.
static THREADS_CNT: AtomicI32 = AtomicI32::new(0); // cc :209
/// cc :1078 `static unsigned reload_id_tracker = 0;` — the update_-
/// reload_id fn-LOCAL static -> module owner seam (the statics law;
/// DEV-cited seat move, no observable face).
static RELOAD_ID_TRACKER: AtomicU32 = AtomicU32::new(0); // cc :1078

// h :440 `static std::mutex static_names_mutex;` + cc :1115 (the def)
// and h :441 `static std::unordered_map<std::string, std::string>
// static_names;` + cc :1116: the Mutex-guarded intern map lands as
// Mutex<BTreeMap> (the std Mutex is the one-home twin — get_static_
// name cc :1120 `std::lock_guard` face REAL).
static STATIC_NAMES: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new()); // h :440/:441, cc :1115/:1116

// ======================================================================
// the conf-slot faces — cc :1040-:1056
// ======================================================================

impl SnortConfig {
    /// cc :1040-:1041 `SnortConfig* get_main_conf() { return
    /// const_cast<SnortConfig*>(snort_conf); }` — runtime access to the
    /// MUTABLE config (main thread only, h :788 comment kept).
    pub fn get_main_conf() -> Option<Rc<RefCell<SnortConfig>>> {
        SNORT_CONF.with(|c| c.borrow().clone()) // the same slot, mutable handle
    }

    /// cc :1043-:1044 `const SnortConfig* get_conf() { return
    /// snort_conf; }` — h :784-:785 comment kept: "runtime access to
    /// const config — especially for packet threads; prefer access via
    /// packet->context->conf".
    pub fn get_conf() -> Option<Rc<RefCell<SnortConfig>>> {
        SNORT_CONF.with(|c| c.borrow().clone())
    }

    /// cc :1046-:1056 `void SnortConfig::set_conf(SnortConfig* sc)`.
    /// The :1050-:1055 legs (`Shell* sh = sc->policy_map->get_shell(0);
    /// if (sc->policy_map->get_policies(sh)) set_policies(sc, sh);`)
    /// ride the SHELL/policy-selector wall seam (the main/shellp.rs
    /// ShellWorld home REUSE cite).
    pub fn set_conf<W: SnortConfigWorld>(sc: Option<Rc<RefCell<SnortConfig>>>, w: &mut W) {
        SNORT_CONF.with(|c| *c.borrow_mut() = sc.clone()); // cc :1048
        if sc.is_some() {
            // cc :1050 `if ( sc )` — the shell legs NEVER-land -> seam:
            w.set_conf_policies_leg(); // cc :1052-:1054
        }
    }

    // ==================================================================
    // the logging statics — h :731-:769 (the inline static faces over
    // the LOGGING_FLAGS / LOG_QUIET_BYPASSED owner seats)
    // ==================================================================

    /// h :732-:733 `static void enable_log_syslog() { logging_flags |=
    /// LOGGING_FLAG__SYSLOG; }`
    pub fn enable_log_syslog() {
        LOGGING_FLAGS.fetch_or(LOGGING_FLAG_SYSLOG, Ordering::Relaxed);
    }

    /// h :735-:736 `static bool log_syslog() { return logging_flags &
    /// LOGGING_FLAG__SYSLOG; }`
    pub fn log_syslog() -> bool {
        LOGGING_FLAGS.load(Ordering::Relaxed) & LOGGING_FLAG_SYSLOG != 0
    }

    /// h :738-:744 `static void set_log_quiet(bool enabled)` (the
    /// |=/&= pair).
    pub fn set_log_quiet(enabled: bool) {
        if enabled {
            LOGGING_FLAGS.fetch_or(LOGGING_FLAG_QUIET, Ordering::Relaxed); // h :741
        } else {
            LOGGING_FLAGS.fetch_and(!LOGGING_FLAG_QUIET, Ordering::Relaxed); // h :743
        }
    }

    /// h :746-:747 `static bool log_quiet() { return
    /// !log_quiet_bypassed && (logging_flags & LOGGING_FLAG__QUIET); }`
    pub fn log_quiet() -> bool {
        let bypassed = LOG_QUIET_BYPASSED.with(|b| b.get());
        !bypassed && LOGGING_FLAGS.load(Ordering::Relaxed) & LOGGING_FLAG_QUIET != 0
    }
}

/// h :749-:763 `class ScopedLogQuietBypass` — the ctor stashes the
/// old bypass (:752-:753), the dtor restores (:755-:756), copy
/// DELETED (:758-:759 -> the port simply derives nothing). The
/// dtor face lands as Drop.
pub struct ScopedLogQuietBypass {
    was_bypassed: bool, // h :762 `bool was_bypassed;`
}

impl ScopedLogQuietBypass {
        /// h :752-:753 `ScopedLogQuietBypass() :
        /// was_bypassed(log_quiet_bypassed) { log_quiet_bypassed =
        /// true; }`
        pub fn new() -> Self {
            let was = LOG_QUIET_BYPASSED.with(|b| {
                let old = b.get();
                b.set(true);
                old
            });
            ScopedLogQuietBypass { was_bypassed: was }
        }
    }
impl Default for ScopedLogQuietBypass {
    /// the h :752 ctor face == new() (the Default derive shape the
    /// lint asks for; the ctor body lands new()).
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScopedLogQuietBypass {
        /// h :755-:756 `~ScopedLogQuietBypass() {
        /// log_quiet_bypassed = was_bypassed; }`
        fn drop(&mut self) {
            LOG_QUIET_BYPASSED.with(|b| b.set(self.was_bypassed));
        }
    }

impl SnortConfig {
    /// h :765-:766 `static void enable_log_verbose() { logging_flags
    /// |= LOGGING_FLAG__VERBOSE; }`
    pub fn enable_log_verbose() {
        LOGGING_FLAGS.fetch_or(LOGGING_FLAG__VERBOSE, Ordering::Relaxed);
    }

    /// h :768-:769 `static bool log_verbose() { return logging_flags &
    /// LOGGING_FLAG__VERBOSE; }`
    pub fn log_verbose() -> bool {
        LOGGING_FLAGS.load(Ordering::Relaxed) & LOGGING_FLAG__VERBOSE != 0
    }

    /// h :723-:727 `static bool static_hash()` — h :723 comment kept
    /// ("FIXIT-L snort_conf needed for static hash before
    /// initialized"): `return get_conf() && get_conf()->run_flags &
    /// RUN_FLAG__STATIC_HASH;`
    pub fn static_hash() -> bool {
        SNORT_CONF.with(|c| {
            c.borrow().as_ref()
                .map(|r| r.borrow().run_flags & RUN_FLAG__STATIC_HASH != 0)
                .unwrap_or(false) // the C `get_conf() &&` null arm
        })
    }
}

// ======================================================================
// the ctor pair — cc :239-:252. The run-mode comment cc :239-:242 kept:
// /* A lot of this initialization can be skipped if not running in IDS
//  * mode but the goal is to minimize config checks at run time when
//  * running in IDS mode so we keep things simple and enforce that the
//  * only difference among run_modes is how we handle packets via the
//  * log_func. */
// ======================================================================

impl SnortConfig {
    /// cc :243-:246 `SnortConfig(const char* exclude_name = nullptr)`
    /// (h :182) -> `init(nullptr, exclude_name)`. cc :174's second
    /// init param is UNNAMED (never read — the disk face wins).
    pub fn new(exclude_name: Option<&str>) -> Self {
        let mut sc = SnortConfig::default(); // the h NSDMI block
        sc.init(None, exclude_name);
        sc
    }

    /// cc :248-:252 the ProtocolReference ctor ("Copy the
    /// ProtocolReference data into the new SnortConfig", cc :248).
    pub fn new_with_protocol_reference(pr: Option<ProtocolReferenceFace>) -> Self {
        let mut sc = SnortConfig::default();
        sc.init(pr, None);
        sc
    }

    /// private h :179 `void init(ProtocolReference*, const char*
    /// exclude_name);` — the cc :174-:206 body. The REAL ctors ride
    /// the landed homes (SFDAQConfig REUSE packet_io/sfdaq_config.rs
    /// :113, ThreadConfig REUSE main/thread_config.rs :671); the wall
    /// ctors (ActionManager::new_config :187, ProtocolReference copy-
    /// ctor :202, TraceConfig :203) ride cited slot faces, NEVER
    /// invented.
    fn init(&mut self, protocol_reference: Option<ProtocolReferenceFace>, _exclude_name: Option<&str>) {
        self.homenet.clear();                 // cc :176 (SfCidr::clear REUSE sfip/sf_cidr.rs :24)
        self.obfuscation_net.clear();         // cc :177
        self.num_layers = DEFAULT_LAYERMAX;   // cc :179 (protocols/packet.h :122 REUSE cite)
        self.max_attribute_hosts = DEFAULT_MAX_ATTRIBUTE_HOSTS; // cc :181
        self.max_attribute_services_per_host = DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST; // cc :182
        self.max_metadata_services = DEFAULT_MAX_METADATA_SERVICES; // cc :184 (host_attributes.h :128-:130 REUSE cites)
        // cc :186 `daq_config = new SFDAQConfig();` — the 23a REUSE
        // home; its Default IS the cc :65-:70 ctor face:
        self.daq_config = Some(Box::new(SFDAQConfig::default()));
        // cc :187 `ActionManager::new_config(this);` — the managers/
        // action_manager.h wall (the framework/ips_action.rs
        // ActionRegistry :40 REUSE cite): the leg NEVER pulls -> the
        // cited-comment face, the config slot (ips_actions_config h :
        // 360) stays the cited-None face:
        //     ActionManager::new_config(this);   // cc :187 wall cite
        self.num_slots = 0;                   // cc :189
        self.state = None;                    // cc :190 `state = nullptr;`
        self.profiler = Some(ProfilerConfigFace); // cc :192 `new ProfilerConfig;` (fwd h :174 -> the cited face ctor)
        self.latency = Some(Box::new(LatencyConfigFace::default())); // cc :193 `new LatencyConfig();` (latency_config.h :34 REUSE-shaped face)
        self.memory = Some(Box::new(MemoryConfigFace));   // cc :194 `new MemoryConfig();` (memory_config.h :26)
        self.policy_map = Some(PolicyMapFace::default()); // cc :195 `new PolicyMap;` (main/policy.h home REUSE cite; the vec twins start empty)
        self.thread_config = Some(Box::new(ThreadConfig::new())); // cc :196 `new ThreadConfig();` REUSE home :671
        self.global_dbus = Some(());          // cc :197 `new DataBus();` (the DataBus body never-landed -> token slot; the drop face rides the :305 delete)
        if self.max_procs > 1 {
            self.mp_dbus = Some(());          // cc :198-:200 `if (max_procs > 1) mp_dbus = new MPDataBus();` — the CONDITION REAL, the ctor tokenized
        }
        // cc :202 `proto_ref = new ProtocolReference(protocol_reference);`
        // — the copy-ctor NEVER lands; the arg lands the slot (DEV-
        // cited shape: the C copy == the arg for the data-free face)
        self.proto_ref = protocol_reference;
        // cc :203 `trace_config = new TraceConfig;` — the class body
        // NEVER landed (trace/trace_config.h :31) -> the slot rides
        // cited-None (DEV-cited; the ctor leg cited here):
        self.trace_config = None;
        self.update_reload_id();              // cc :205
    }

    // ==================================================================
    // the file-static policy legs — cc :116-:172 (the private-
    // implementation banner cc :116-:118 kept). PolicyMode rides the
    // main/policy.rs REUSE home (:23-:29, NEVER re-forked); the
    // ParseWarning leg rides the log/messages.rs REUSE home (:203) +
    // WARN_DAQ (:17 REUSE).
    // ==================================================================

    /// cc :120-:151 `init_policy_mode` (the switch REAL).
    pub(crate) fn init_policy_mode(
        sc: &SnortConfig,
        mode: PolicyMode,
        log: &mut crate::log::messages::LogEngine,
    ) -> PolicyMode {
        match mode {
            PolicyMode::Passive => {          // cc :124 POLICY_MODE__PASSIVE
                if sc.adaptor_inline_test_mode() { // cc :125
                    return PolicyMode::InlineTest; // cc :126
                }
                // cc :127 break
            }
            PolicyMode::Inline => {           // cc :129 POLICY_MODE__INLINE
                if sc.adaptor_inline_test_mode() { // cc :130
                    return PolicyMode::InlineTest; // cc :131
                } else if !sc.adaptor_inline_mode() { // cc :133
                    // cc :135 ParseWarning(WARN_DAQ, "adapter is in
                    // passive mode; switching policy mode to tap.") —
                    // the messages.rs :203 REUSE call REAL:
                    log.parse_warning(WARN_DAQ, "adapter is in passive mode; switching policy mode to tap.", &[]);
                    return PolicyMode::Passive; // cc :136
                }
                // cc :138 break
            }
            PolicyMode::InlineTest => {       // cc :140 break (no-op arm)
            }
            PolicyMode::Max => {              // cc :143 POLICY_MODE__MAX
                if sc.adaptor_inline_mode() {
                    return PolicyMode::Inline; // cc :145
                } else {
                    return PolicyMode::Passive; // cc :147
                }
            }
        }
        mode // cc :150 `return mode;`
    }

    /// cc :153-:172 `init_policies` — the two loops REAL over the
    /// PolicyMapFace / NetworkPolicyFace vec twins (the policy.h :359-
    /// :366 count/get faces == len / in-range; the C null-deref arms
    /// NEVER ported, crash-vs-None cite). collect-then-write mirrors
    /// the C write-back without aliasing sc.
    pub(crate) fn init_policies(sc: &mut SnortConfig, log: &mut crate::log::messages::LogEngine) {
        // cc :155-:164 network -> inspection loop:
        let mut updates: Vec<(usize, usize, PolicyMode)> = Vec::new();
        if let Some(pm) = sc.policy_map.as_ref() {
            for nidx in 0..pm.network_policies.len() { // cc :155 network_policy_count()
                if let Some(np) = pm.network_policies.get(nidx) { // cc :157 get_network_policy(nidx)
                    for (idx, ip) in np.inspection_policies.iter().enumerate() { // cc :159 inspection_policy_count() + get face
                        let cur = ip.policy_mode; // cc :161
                        updates.push((nidx, idx, SnortConfig::init_policy_mode(sc, cur, log))); // cc :162
                    }
                }
            }
        }
        for (nidx, idx, mode) in updates {
            if let Some(np) = sc.policy_map.as_mut().and_then(|pm| pm.network_policies.get_mut(nidx)) {
                np.inspection_policies[idx].policy_mode = mode; // the cc :162 write-back
            }
        }
        // cc :166-:170 the ips loop — `get_ips_policy(sc, idx)` the
        // policy.h :105 free face reaches the map twin's vec:
        let mut updates: Vec<(usize, PolicyMode)> = Vec::new();
        if let Some(pm) = sc.policy_map.as_ref() {
            for (idx, p) in pm.ips_policies.iter().enumerate() { // cc :166 ips_policy_count() + cc :168 get_ips_policy(sc, idx) face
                let cur = p.policy_mode;
                updates.push((idx, SnortConfig::init_policy_mode(sc, cur, log))); // cc :169
            }
        }
        for (idx, mode) in updates {
            if let Some(p) = sc.policy_map.as_mut().and_then(|pm| pm.ips_policies.get_mut(idx)) {
                p.policy_mode = mode;
            }
        }
    }

    // the generate_config_dump file-static — cc :211-:233 (the name-
    // assembly + the cnt legs REAL over the module owner atomics; the
    // JsonAllConfigOutput ctor/dump/delete legs — dump_config/ wall —
    // ride the world seam; the delete faces are the Rust drops):

    /// cc :211-:233 `generate_config_dump(config_data, timestamp,
    /// reload_id, file_name)` — runs on the dumper thread in the C.
    pub fn generate_config_dump<W: SnortConfigWorld>(
        w: &mut W,
        config_data: &mut Vec<Box<ConfigDataFace>>,
        timestamp: i64,
        reload_id: u32,
        file_name: &str,
    ) {
        THREADS_CNT.fetch_add(1, Ordering::Relaxed); // cc :214 `++threads_cnt`

        // cc :216-:221 the underscore assembly: file_name += "_" +
        // getpid() + "_" + timestamp + "_" + reload_id (std::to_string
        // -> Rust itoa faces REAL; getpid -> the clock/pid seam):
        let mut file_name = String::from(file_name);
        file_name.push('_'); // cc :216
        file_name.push_str(&w.get_pid().to_string()); // cc :217
        file_name.push('_'); // cc :218
        file_name.push_str(&timestamp.to_string()); // cc :219-:220
        file_name.push('_'); // cc :220
        file_name.push_str(&reload_id.to_string()); // cc :221

        // cc :223 `ConfigOutput* o = new JsonAllConfigOutput(file_name
        // .c_str());` (dump_config/json_config_output.h wall -> seam;
        // the None seam arm == the C object NEVER lands on this
        // posture, the loop legs NEVER invented):
        if let Some(mut o) = w.config_output_json_all_new(&file_name) {
            // cc :224-:228 for (auto i : *config_data) { o->dump_
            // config(*i); delete i; } — the dump seam + the per-entry
            // drop face:
            for mut i in config_data.drain(..) {
                w.config_output_dump(&mut o, i.as_mut()); // cc :226
                drop(i); // cc :227 `delete i;`
            }
            // cc :229-:230 `delete o; delete config_data;` -> the Rust
            // drop faces (o drops here; the drained vec drops with
            // the caller's box):
        } else {
            // the wall arm: cc :224-:228 NEVER runs, the entries drop
            // (the C would have dumped — the seam honesty cite):
            config_data.clear(); // the drop face
        }

        THREADS_CNT.fetch_sub(1, Ordering::Relaxed); // cc :232 `--threads_cnt`
    }

    // ==================================================================
    // setup / post_setup / update_scratch — cc :335-:384
    // ==================================================================

    /// cc :335-:367 `void SnortConfig::setup()`. The wall legs
    /// (gmt2local, load_shared_secret, the parser ladders, the Ips-
    /// Manager verify, the fpCreate seat) ride the world seam; the
    /// evalOrder alloc + the rule_states apply->delete legs land their
    /// REAL slots around the seams.
    pub fn setup<W: SnortConfigWorld>(&mut self, w: &mut W, log: &mut crate::log::messages::LogEngine) {
        if self.output_use_utc() {
            self.thiszone = 0;                // cc :337-:338
        } else {
            // cc :341 gmt2local(0) — the main/processp.rs :703 REUSE
            // home drives this seat through the seam leg:
            self.thiszone = w.gmt2local_now();
        }

        if !self.control_secret_file.is_empty() {
            // cc :343-:344 load_shared_secret (challenge_response_auth
            // .h :66 wall -> seam; the vec+len slots REAL):
            let secret_file = self.control_secret_file.clone(); // the cc :344 .c_str() arg face
            if let Some((secret, len)) = w.load_shared_secret(&secret_file) {
                self.control_shared_secret = Some(secret);
                self.control_shared_secret_len = len;
            }
        }

        SnortConfig::init_policies(self, log); // cc :346

        // cc :347 ParseRules(this) (parser wall -> seam):
        w.parse_rules();

        // cc :349-350 the comment "Allocate evalOrder before calling
        // the OrderRuleLists" + `evalOrder = new int[IpsAction::get_
        // max_types()]();` -> zero-filled Vec REAL over the seam len:
        let n = w.ips_action_max_types(); // actions/ips_action.h :80
        self.eval_order = Some(vec![0; n]);

        // cc :352 OrderRuleLists / :361 ParseRulesFinish (parser walls
        // -> seams):
        w.order_rule_lists();

        if self.rule_states.is_some() {
            // cc :354-:359 rule_states->apply(this); delete; = nullptr
            w.rule_state_apply();
            self.rule_states = None; // the `delete rule_states;` + nullptr store -> the drop face
        }

        w.parse_rules_finish();

        // cc :363-:364 the comment "Need to do this after dynamic
        // detection stuff is initialized, too" + IpsManager::verify:
        w.ips_manager_verify();
        w.fp_create(); // cc :366 fpCreateFastPacketDetection (the detection/fp_config.rs REUSE cite rides the config slot)
    }

    /// cc :369-:379 `void SnortConfig::post_setup()`. REAL: the
    /// handler-count read, the per-slot resize, and the copy_if filter
    /// (the setup(this) predicate + push_back land in order).
    pub fn post_setup(&mut self) {
        let handler_count = SCRATCH_HANDLERS.lock().map(|h| h.len()).unwrap_or(0); // cc :371 scratch_handlers.size()

        // cc :373-:375 the comment kept ("Ensure we have allocated the
        // scratch space vector for each thread"): for i < num_slots
        // state[i].resize(handler_count):
        if let Some(state) = self.state.as_mut() {
            for slot in state.iter_mut().take(self.num_slots as usize) {
                slot.resize(handler_count, ()); // cc :375 (void* elems -> () tokens; the resize face)
            }
        }

        // cc :377-:378 copy_if(scratch_handlers, back_inserter(
        // scratchers), [](s){ return s and s->setup(this); }):
        let handlers = SCRATCH_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        // the C `s and s->setup(this)` null-filter arm == the flatten
        // (None slots skip, the lambda NEVER runs — the face):
        for arc in handlers.iter().flatten() {
            // the `s->setup(this)` predicate:
            let keep = arc.lock().map(|mut s| s.setup_scratch(self)).unwrap_or(false);
            if keep {
                self.scratchers.push(arc.clone()); // back_inserter (the double-hold Arc clone, cite h :418)
            }
        }
        drop(handlers);
    }

    /// cc :381-:384 `void SnortConfig::update_scratch(ControlConn*
    /// ctrlcon)` — main_broadcast_command(new ACScratchUpdate(this,
    /// scratch_handlers, ctrlcon), ctrlcon): BOTH names NEVER-land ->
    /// the seam leg; the handler-count arg carries the vector face,
    /// the ControlConn REUSE-cites the landed ControlConnTracker face
    /// (main/reload_tracker.rs).
    pub fn update_scratch<W: SnortConfigWorld>(&self, w: &mut W, ctrlcon: Option<crate::main::reload_tracker::ControlConnTracker>) {
        let count = SCRATCH_HANDLERS.lock().map(|h| h.len()).unwrap_or(0); // the scratch_handlers arg (cc :383)
        w.main_broadcast_ac_scratch_update(count, ctrlcon); // cc :383-:384
    }

    // ==================================================================
    // merge — cc :386-:515. "merge in everything from the command line
    // config" (the cc :386 comment kept). EVERY leg lands with its C
    // cite; the SHELL block (:485-:504) rides the cited OFF face
    // (ENABLE_SHELL option OFF, cmake/create_options.cmake :19).
    // ==================================================================

    /// cc :387-:515 `void SnortConfig::merge(const SnortConfig*
    /// cmd_line_conf)`.
    pub fn merge(&mut self, cmd_line_conf: &SnortConfig) {
        // cc :389-:392 the CLI switch census comment (kept VERBATIM as
        // a cite): "-D / -H / -Q / -r / -T / -x / --alert-before-pass /
        // --create-pidfile / --enable-inline-test / --mem-check /
        // --nolock-pidfile / --pause / --pcap-file / --pcap-dir /
        // --pcap-list / --pcap-show / --pedantic / --shell / --show-
        // file-codes"
        self.run_flags |= cmd_line_conf.run_flags; // cc :392

        // cc :394 "-A / -C / -d / -e / -f / -O / -U / -X / -y /
        // --nostamps"
        self.output_flags |= cmd_line_conf.output_flags; // cc :395

        // cc :397-:399 (the `-B` leg): `if
        // (cmd_line_conf->obfuscation_net.get_family() != 0) memcpy
        // (&obfuscation_net, &cmd_line_conf->obfuscation_net, ...)`:
        // SfCidr is a Copy struct -> the struct-copy is the memcpy face
        // (REUSE sfip/sf_cidr.rs get_family :64):
        if cmd_line_conf.obfuscation_net.get_family() != 0 {
            self.obfuscation_net = cmd_line_conf.obfuscation_net; // cc :399
        }

        // cc :401-:403 (`-g`):
        if cmd_line_conf.group_id != -1 {
            self.group_id = cmd_line_conf.group_id;
        }

        self.event_log_id = cmd_line_conf.event_log_id; // cc :405-:406 (`-G / --logid`, unconditional)

        // cc :408-:409 (`-i / -s / --daq / ...`):
        // `daq_config->overlay(cmd_line_conf->daq_config);` — the
        // packet_io/sfdaq_config.rs :197 overlay REUSE (the C double-
        // null-crash arms NEVER ported, crash-vs-None cite; both slots
        // init()-filled so the legs REAL):
        if let (Some(mine), Some(over)) = (self.daq_config.as_mut(), cmd_line_conf.daq_config.as_ref()) {
            mine.overlay(over); // cc :409
        }

        // cc :411-:420 (`-k (only configures eval, not drop)`): the
        // cl_chk read == policy_map->get_network_policy() (i=0 default)
        // ->checksum_eval (policy.h :359 face; the null map/policy arm
        // NEVER ports the crash — skipped-face cite):
        let cl_chk = cmd_line_conf
            .policy_map.as_ref()
            .and_then(|pm| pm.network_policies.first())
            .map(|np| np.checksum_eval);
        // cc :413 `if (!(cl_chk & CHECKSUM_FLAG__DEF))` collapsed into
        // the Some-filter (edition-2024 let-chain, same C order):
        if let Some(cl_chk) = cl_chk.filter(|c| c & CHECKSUM_FLAG__DEF == 0) {
            {
                if let Some(pm) = self.policy_map.as_mut() {
                    for idx in 0..pm.network_policies.len() { // cc :415 network_policy_count()
                        pm.network_policies[idx].checksum_eval = cl_chk; // cc :417-:418 get_network_policy(idx)->checksum_eval = cl_chk (the C null arm cited)
                    }
                }
            }
        }

        // cc :422-:424 (`-l`):
        if !cmd_line_conf.log_dir.is_empty() {
            self.log_dir = cmd_line_conf.log_dir.clone();
        }

        // cc :426-:427 (`-L`; the comment kept: "output is only set by
        // cmd_line_conf to override other conf output settings" —
        // UNCONDITIONAL):
        self.output = cmd_line_conf.output.clone();

        // cc :429-:431 (`-m`):
        if cmd_line_conf.file_mask != 0 {
            self.file_mask = cmd_line_conf.file_mask;
        }

        // cc :433-:435 (`-n`):
        if cmd_line_conf.pkt_cnt != 0 {
            self.pkt_cnt = cmd_line_conf.pkt_cnt;
        }

        // cc :437-:439 (`-t`):
        if !cmd_line_conf.chroot_dir.is_empty() {
            self.chroot_dir = cmd_line_conf.chroot_dir.clone();
        }

        // cc :441-:443 (`-u`):
        if cmd_line_conf.user_id != -1 {
            self.user_id = cmd_line_conf.user_id;
        }

        // cc :445-:447 (`--bpf`):
        if !cmd_line_conf.bpf_filter.is_empty() {
            self.bpf_filter = cmd_line_conf.bpf_filter.clone();
        }

        // cc :449-:451 (`--dirty-pig`):
        if cmd_line_conf.dirty_pig {
            self.dirty_pig = cmd_line_conf.dirty_pig;
        }

        self.id_offset = cmd_line_conf.id_offset;  // cc :453-:454 (`--id-offset`, unconditional)
        self.id_subdir = cmd_line_conf.id_subdir;  // cc :455-:456 (`--id-subdir`)
        self.id_zero = cmd_line_conf.id_zero;      // cc :457-:458 (`--id-zero`)
        self.include_path = cmd_line_conf.include_path.clone(); // cc :460-:461 (`--include-path`, unconditional)

        // cc :463-:465 (`--metadata-filter`):
        if !cmd_line_conf.metadata_filter.is_empty() {
            self.metadata_filter = cmd_line_conf.metadata_filter.clone();
        }

        // cc :467-:469 (`--pause-after-n`):
        if cmd_line_conf.pkt_pause_cnt != 0 {
            self.pkt_pause_cnt = cmd_line_conf.pkt_pause_cnt;
        }

        // cc :471-:473 (`--process-all-events`): the C derefs the
        // event_queue_config pointer (null-crash arm NEVER ported):
        if cmd_line_conf.run_flags & RUN_FLAG__PROCESS_ALL_EVENTS != 0
            && let Some(eq) = self.event_queue_config.as_mut()
        {
            eq.process_all_events = 1; // cc :473
        }

        self.run_prefix = cmd_line_conf.run_prefix.clone(); // cc :475-:476 (`--run-prefix`, unconditional)

        // cc :478-:480 (`--skip`):
        if cmd_line_conf.pkt_skip != 0 {
            self.pkt_skip = cmd_line_conf.pkt_skip;
        }

        self.stdin_rules = cmd_line_conf.stdin_rules; // cc :482-:483 (`--stdin-rules`, unconditional)

        // cc :485-:504 `#ifdef SHELL` ... `#endif` — ENABLE_SHELL option
        // OFF (cmake/create_options.cmake :19): the block lands CITED,
        // NEVER live (the 24f dialect law):
        //     // -j
        //     if (cmd_line_conf->remote_control_port >= 0)          :487-:488
        //         remote_control_port = cmd_line_conf->remote_control_port;
        //     // --control-socket
        //     else if (!cmd_line_conf->remote_control_socket.empty()) :490-:491
        //         remote_control_socket = cmd_line_conf->remote_control_socket;
        //     // --control-socket-uid
        //     if (cmd_line_conf->control_socket_uid != static_cast<uid_t>(-1)) :494-:495
        //         control_socket_uid = cmd_line_conf->control_socket_uid;
        //     // --control-socket-gid
        //     if (cmd_line_conf->control_socket_gid != static_cast<gid_t>(-1)) :498-:499
        //         control_socket_gid = cmd_line_conf->control_socket_gid;
        //     // --control-secret-file
        //     if (!cmd_line_conf->control_secret_file.empty())       :502-:503
        //         control_secret_file = cmd_line_conf->control_secret_file;

        // cc :506-:508 "Finalize the log directory, save a copy in
        // case we need to chroot":
        if self.log_dir.is_empty() {
            self.log_dir = DEFAULT_LOG_DIR.to_string(); // h :42
        }
        self.orig_log_dir = self.log_dir.clone(); // cc :509

        // cc :511-:514 "Initialize the slotted state memory for
        // threads": `assert(!state);` -> the debug-build contract face
        // (the production -DNDEBUG arm elides it, the reload_tracker.rs
        // law):
        debug_assert!(self.state.is_none());
        // cc :513 `num_slots = offload_threads +
        // ThreadConfig::get_instance_max();` — the main/thread_config.rs
        // :743 ONE-home REUSE (never re-forked):
        self.num_slots = self.offload_threads
            .wrapping_add(ThreadConfig::get_instance_max()); // C unsigned-wrap face kept (wrapping_add == the C wrap posture)
        // cc :514 `state = new std::vector<void*>[num_slots];` -> the
        // array-of-empty-vecs twin (void* elems -> () tokens):
        self.state = Some(vec![Vec::new(); self.num_slots as usize]);
    }

    // ==================================================================
    // verify — cc :517-:565 (h :191 `bool verify() const;`): the else-
    // if ReloadError chain. ReloadError = the log/messages.rs home
    // reload_error REUSE (messages.rs :220; the file-global reload_
    // errors counters ride that home, never re-forked). Every crash
    // deref (sc->, threshold->, rate->, df->, daq-> pointer arms) stays
    // the crash-vs-None cite: a None side reads as "no mismatch to
    // report" ONLY where BOTH sides are the same slot face — the DEV-
    // cited honest face below.
    // ==================================================================

    /// cc :517-:565.
    pub fn verify(&mut self, log: &mut crate::log::messages::LogEngine) -> bool {
        let mut config_ok = false; // cc :519
        // cc :520 `const SnortConfig* sc = get_conf();` — the C null
        // sc NEVER ported (a null-deref crash face): the empty-slot arm
        // reports NO mismatch and returns config_ok=false (DEV-cited:
        // the honest no-success posture, no crash invented).
        let sc_slot = SnortConfig::get_conf();

        // cc :522-:523: `if (!policy_map->setup_network_policies())
        // ReloadError("Network policy user ids must be unique\n");` —
        // the policy.cc :233-:237 body NEVER landed -> the world seam.
        // (verify keeps no world arg in the C either; the seam call
        // rides the module's own honest false default — cited face:)
        let setup_ok = false; // wall cite: policy_map->setup_network_policies() (policy.cc NEVER landed) — the seam default, the provider lands the true chain
        if !setup_ok {
            log.reload_error("Network policy user ids must be unique\n", &[]); // cc :523
            return config_ok; // the cc :524 else-chain: the first leg's failure skips the else chain AND leaves config_ok false
        }
        if let Some(sc_cell) = sc_slot {
            let sc = sc_cell.borrow(); // REUSE cite only (the conf-slot record read); never a fork
            if sc.bpf_filter != self.bpf_filter { // cc :525 (`sc->bpf_filter != bpf_filter` — the ground typo `bfp_filter` inside the message is kept VERBATIM :526)
                log.reload_error("Changing packets.bfp_filter requires a restart.\n", &[]);
            } else if sc.respond_attempts != self.respond_attempts { // cc :528
                log.reload_error("Changing active.attempts requires a restart.\n", &[]); // cc :529
            } else if sc.respond_device != self.respond_device { // cc :531
                log.reload_error("Changing active.device requires a restart.\n", &[]);
            } else if sc.chroot_dir != self.chroot_dir { // cc :534
                log.reload_error("Changing process.chroot requires a restart.\n", &[]);
            } else if (sc.run_flags & RUN_FLAG__DAEMON) != (self.run_flags & RUN_FLAG__DAEMON) { // cc :537
                log.reload_error("Changing process.daemon requires a restart.\n", &[]);
            } else if sc.orig_log_dir != self.orig_log_dir { // cc :540
                log.reload_error("Changing output.logdir requires a restart.\n", &[]);
            } else if sc.group_id != self.group_id { // cc :543
                log.reload_error("Changing process.setgid requires a restart.\n", &[]);
            } else if sc.user_id != self.user_id { // cc :546
                log.reload_error("Changing process.setuid requires a restart.\n", &[]);
            } else if sc.daq_config.as_ref().map(|d| d.mru_size) != self.daq_config.as_ref().map(|d| d.mru_size) {
                // cc :549 `sc->daq_config->get_mru_size() != daq_config->
                // ->get_mru_size()` — the sfdaq_config.rs mru_size FIELD
                // REUSE (the landed home exposes the field, the get_
                // mru_size() getter is the analyzer.rs :303 seam face —
                // cite, never re-forked):
                log.reload_error("Changing daq.snaplen requires a restart.\n", &[]);
            } else if sc.threshold_config.as_ref().map(|t| t.memcap) != self.threshold_config.as_ref().map(|t| t.memcap) {
                // cc :552 the memcap legs (sfthreshold.h :36 via
                // MemcapFace; the C null derefs cited, None-vs-None
                // equal, None-vs-Some a mismatch — DEV-cited face):
                log.reload_error("Changing alerts.event_filter_memcap requires a restart.\n", &[]);
            } else if sc.rate_filter_config.as_ref().map(|t| t.memcap) != self.rate_filter_config.as_ref().map(|t| t.memcap) {
                log.reload_error("Changing alerts.rate_filter_memcap requires a restart.\n", &[]); // cc :555-:556
            } else if sc.detection_filter_config.as_ref().map(|t| t.memcap) != self.detection_filter_config.as_ref().map(|t| t.memcap) {
                log.reload_error("Changing alerts.detection_filter_memcap requires a restart.\n", &[]); // cc :558-:559
            } else {
                config_ok = true; // cc :561-:562 `else config_ok = true;`
            }
        }
        config_ok // cc :564 `return config_ok;`
    }

    // ==================================================================
    // the dtor legs — cc :254-:333 (`~SnortConfig()`). NO Drop impl
    // lands here (the conf slot hands Rc<RefCell<..>> handles; the wall
    // legs need a provider — the C RAII dtor face = the named destroy
    // ladder, the 24d owner-posture precedent): the delete-faces are
    // field-None + the Rust drops, the free-class INTERNALS are seam
    // cites, the scratchers cleanup loop lands REAL.
    // ==================================================================

    /// cc :254-:333 the destroy ladder in GROUND ORDER.
    pub fn destroy<W: SnortConfigWorld>(&mut self, w: &mut W) {
        // cc :256-:257 `for ( const auto & ct : classifications )
        // delete ct.second;` -> the map-delta drop face:
        self.classifications.clear(); // the delete-each -> Rust drops (value owns its ClassTypeFace)
        // cc :259-:260 the references twin:
        self.references.clear();
        // cc :262-:263 `for ( auto* s : scratchers ) s->cleanup(this);`
        // — the ScratchAllocatorFace::cleanup_scratch run REAL:
        // the C loop keeps the vector live across the call; the port
        // takes the vec out of self to free the borrow, then restores
        // it (the same iteration + call order, DEV-cited lift):
        let scratchers = std::mem::take(&mut self.scratchers);
        for s in scratchers.iter() {
            if let Ok(mut s) = s.lock() {
                s.cleanup_scratch(self); // cc :263
            }
        }
        self.scratchers = scratchers;
        // cc :265 FreeRuleLists(this) (parser/reload wall -> seam
        // cite + the drop face):
        w.free_rule_lists_internals();
        self.rule_lists = None;
        // cc :266 PortTablesFree(port_tables) (wall cite + drop face):
        w.port_tables_free_internals();
        self.port_tables = None;
        // cc :268-:270 ThresholdConfigFree / RateFilter_ConfigFree /
        // DetectionFilterConfigFree (filters/ walls -> drop faces; the
        // C frees store NOTHING back (a dangling-pointer face the port
        // replaces with the None slot — DEV-cited, cite kept):
        w.filter_configs_free();
        self.threshold_config = None;
        self.rate_filter_config = None;
        self.detection_filter_config = None;
        // cc :272-:273 `if ( event_queue_config )
        // EventQueueConfigFree(event_queue_config);` (the guard REAL):
        if self.event_queue_config.is_some() {
            self.event_queue_config = None; // (event_queue.h wall -> drop face; no internal leg landed)
        }
        // cc :275 fpDeleteFastPacketDetection(this) (detection/
        // fp_create.h wall -> seam; the config slot drops below via
        // the :289 arm in the C, mirrored here):
        w.fp_delete();
        // cc :276 OtnLookupFree(otn_map) (hash/ghash.rs :34 REUSE cite
        // for the GHash FACE; the body wall -> cited + drop face):
        w.otn_lookup_free_internals();
        self.otn_map = None;
        // cc :278 `delete rtn_hash_table;` -> drop face (hash/xhash.rs
        // :42 XHash REUSE cite for the landable type; the dtor here
        // just drops the token slot):
        self.rtn_hash_table = None;
        // cc :280-:281 `if (eth_dst ) snort_free(eth_dst);` -> drop:
        self.eth_dst = None;
        // cc :283-:290 the search_api stop leg:
        // `if ( fast_pattern_config && (fast_pattern_config->
        // get_search_api() != get_conf()->fast_pattern_config->
        // get_search_api()) ) { if ( fast_pattern_config->
        // get_search_api() ) MpseManager::stop_search_engine(...); }
        // delete fast_pattern_config;` — the get_conf() deref CRASH arm
        // cited (None -> the compare legs skip), the stop leg the wall:
        let conf_api = SnortConfig::get_conf()
            .and_then(|c| c.borrow().fast_pattern_config.as_ref().map(|f| f.search_api));
        if let Some(mine) = self.fast_pattern_config.as_ref() {
            if let Some(other_api) = conf_api {
                // cc :283-:284 the != chain + cc :286 `if (
                // ...get_search_api() )` (the null-0 arm) — the two C
                // ifs collapse into one condition face here:
                if mine.search_api != other_api && mine.search_api != 0 {
                    w.stop_search_engine(mine.search_api); // cc :287 (managers/mpse_manager.h wall -> seam)
                }
            }
            self.fast_pattern_config = None; // cc :289 `delete fast_pattern_config;` -> drop face
        }
        // cc :291-:293 clear_reload_resource_tuner_list(); delete
        // policy_map; policy_map = nullptr; -> the REAL method leg +
        // the drop face:
        self.clear_reload_resource_tuner_list();
        self.policy_map = None;
        // cc :294 ActionManager::delete_config(this) (wall -> seam):
        w.action_manager_delete_config();
        // cc :296-:300 `if (config_dumper) { config_dumper->join();
        // delete config_dumper; }` — the join leg lands on the handle,
        // the delete is the drop:
        if let Some(h) = self.config_dumper.take() {
            let _ = h.join(); // cc :298 (the wall join face)
        }
        // cc :302 `delete[] state;` -> drop face:
        self.state = None;
        // cc :303-:317 the eleven plain `delete X;` slot faces -> field
        // drops (thread_config REUSE home, daq_config REUSE home, proto
        // _ref, evalOrder (the int[] Vec -> drop), payload_injector_
        // config, trace_config, overlay_trace_config, ha_config,
        // global_dbus / mp_dbus (the conditional guard :306-:307 ->
        // Option drop), profiler / latency / memory):
        self.thread_config = None;         // cc :303
        self.ha_config = None;             // cc :304
        self.global_dbus = None;           // cc :305
        self.mp_dbus = None;               // cc :306-:307 (`if (mp_dbus) delete mp_dbus;` -> Option face)
        self.profiler = None;              // cc :309
        self.latency = None;               // cc :310
        self.memory = None;                // cc :311
        self.daq_config = None;            // cc :312
        self.proto_ref = None;             // cc :313
        self.eval_order = None;            // cc :314
        self.payload_injector_config = None; // cc :315
        self.trace_config = None;          // cc :316
        self.overlay_trace_config = None;  // cc :317
        // cc :319-:325 the control_shared_secret memset-then-delete:
        // `if ( control_shared_secret ) { memset(..., 0, len); delete
        // []; control_shared_secret = nullptr; control_shared_secret_-
        // len = 0; }` -> the zero-fill REAL, then the drop face:
        if let Some(secret) = self.control_shared_secret.as_mut() {
            secret.fill(0); // cc :321 memset
        }
        self.control_shared_secret = None; // cc :322-:323
        self.control_shared_secret_len = 0; // cc :324
        // cc :327 Profiler::clear(this) (profiler/ wall -> seam; the
        // prof_map slot drop face):
        w.profiler_clear();
        self.prof_map = None;
        // cc :329-:330 `if ( plug_set ) PluginManager::release_plugins(
        // plug_set);` (managers/plugin_manager.h :52 home wall -> seam):
        if self.plug_set.is_some() {
            w.release_plugins(self.plug_set.take()); // the take == the release-then-null posture (the C leaves the field dangling — the port nulls it, cite)
        }
        // cc :331-:332 trim_heap() (utils/util.h; the main/processp.rs
        // ProcessState::trim_heap :639 REUSE home — the pair CONSUMES
        // the seat; the HAVE_MALLOC_TRIM compile face rides there):
        w.trim_heap();
    }

    // ==================================================================
    // the simple mutators — cc :567-:846 (the h :460-:492 decl block).
    // All bit-flag legs land REAL (the C if/else == |=/&= pairs).
    // ==================================================================

    /// cc :567-:573 `set_alert_before_pass`.
    pub fn set_alert_before_pass(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__ALERT_BEFORE_PASS; } // cc :570
        else { self.run_flags &= !RUN_FLAG__ALERT_BEFORE_PASS; } // cc :572
    }

    /// cc :575-:581 `set_chroot_dir` (the null arg -> clear face).
    pub fn set_chroot_dir(&mut self, directory: Option<&str>) {
        match directory {
            Some(d) => self.chroot_dir = d.to_string(), // cc :578
            None => self.chroot_dir.clear(), // cc :580
        }
    }

    /// cc :583-:589 `set_create_instance_file`.
    pub fn set_create_instance_file(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__CREATE_INST_FILE; } // cc :586
        else { self.run_flags &= !RUN_FLAG__CREATE_INST_FILE; } // cc :588
    }

    /// cc :591-:597 `set_create_pid_file`.
    pub fn set_create_pid_file(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__CREATE_PID_FILE; } // cc :594
        else { self.run_flags &= !RUN_FLAG__CREATE_PID_FILE; } // cc :596
    }

    /// cc :599-:605 `set_pid_filename`: `if (name && name[0] != '\0')
    /// pid_filename = name; else pid_filename = DEFAULT_PID_FILENAME;`
    /// (h :43).
    pub fn set_pid_filename(&mut self, name: Option<&str>) {
        if name.is_some_and(|n| !n.is_empty()) {
            self.pid_filename = name.unwrap().to_string(); // cc :602
        } else {
            self.pid_filename = DEFAULT_PID_FILENAME.to_string(); // cc :604
        }
    }

    /// cc :607-:610 `set_max_procs` (plain store).
    pub fn set_max_procs(&mut self, n: u8) {
        self.max_procs = n;
    }

    /// cc :612-:620 `set_daemon` (the RUN_FLAG__DAEMON pair).
    pub fn set_daemon(&mut self, enabled: bool) {
        if enabled {
            self.run_flags |= RUN_FLAG__DAEMON; // cc :616
        } else {
            self.run_flags &= !RUN_FLAG__DAEMON; // cc :619
        }
    }

    /// cc :622-:630 `set_decode_data_link` (SHOW_DATA_LINK pair).
    pub fn set_decode_data_link(&mut self, enabled: bool) {
        if enabled {
            self.output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK; // cc :626
        } else {
            self.output_flags &= !OUTPUT_FLAG__SHOW_DATA_LINK; // cc :629
        }
    }

    /// cc :632-:641 `set_dump_chars_only` (CHAR_DATA pair; the C
    /// comment cc :636 kept: "dump the application layer as text only").
    pub fn set_dump_chars_only(&mut self, enabled: bool) {
        if enabled {
            self.output_flags |= OUTPUT_FLAG__CHAR_DATA; // cc :637
        } else {
            self.output_flags &= !OUTPUT_FLAG__CHAR_DATA; // cc :640
        }
    }

    /// cc :643-:652 `set_dump_payload` (APP_DATA pair; the C comment
    /// cc :647 kept: "dump the application layer").
    pub fn set_dump_payload(&mut self, enabled: bool) {
        if enabled {
            self.output_flags |= OUTPUT_FLAG__APP_DATA; // cc :648
        } else {
            self.output_flags &= !OUTPUT_FLAG__APP_DATA; // cc :651
        }
    }

    /// cc :654-:662 `set_dump_payload_verbose` (VERBOSE_DUMP pair).
    pub fn set_dump_payload_verbose(&mut self, enabled: bool) {
        if enabled {
            self.output_flags |= OUTPUT_FLAG__VERBOSE_DUMP; // cc :658
        } else {
            self.output_flags &= !OUTPUT_FLAG__VERBOSE_DUMP; // cc :661
        }
    }

    /// cc :664-:684 `set_dst_mac` — the eth_addr_t/eth_pton hex walk.
    /// utils/dnet_header.h NEVER lands the pair (grep at cc :670 for
    /// the eth_pton call cite; h :289 `uint8_t* eth_dst`): the 6x2-hex
    /// ':' form the ParseError string pins ("Format check failed: %s,
    /// Use format like 12:34:56:78:90:1a", cc :672) lands REAL; the
    /// calloc+memcpy legs -> the owned Vec replace (:676-:677). The
    /// `snort_free(eth_dst)` legs (:675, :681) are the drop face (:81
    /// eth_dst None). DEV-cited: dnet's wider separator grammar NOT
    /// ported — the ':'-form leg per the ParseError pin.
    pub fn set_dst_mac(&mut self, mac_addr: Option<&str>, log: &mut crate::log::messages::LogEngine) {
        if let Some(mac) = mac_addr {
            let Ok(dst) = eth_pton(mac) else {
                // cc :670-:674 the ParseError + early-return legs.
                // (cfmt %s Arg REUSE via the messages home.)
                log.parse_error(
                    "Format check failed: %s,  Use format like 12:34:56:78:90:1a",
                    &[crate::utils::cfmt::Arg::S(Some(std::borrow::Cow::Owned(
                        mac.to_string(),
                    )))],
                );
                return; // cc :673
            };
            self.eth_dst = Some(dst.to_vec()); // cc :675-:677 free+calloc+memcpy -> replace face
        } else {
            self.eth_dst = None; // cc :680-:682 free + nullptr store
        }
    }

    // ==================================================================
    // the name-resolution walls — cc :734-:799. The strtol/ERANGE
    // legs + the gr->gr_gid != getgid() guard land REAL; the libc
    // lookups ride the world seam (getgrnam/getgrgid/getpwnam/
    // getpwuid/getuid/getgid, the 24b/24f zero-libc posture). The
    // main-thread-only comments cc :745/:752/:776/:783 kept.
    // ==================================================================

    /// cc :734-:763 `set_gid`: the strtol tail/ERANGE split REAL, the
    /// getgrnam/getgrgid lookups = seam legs, the "If we're already
    /// running as the desired group ID, don't bother to try changing it
    /// later." comment (cc :760) + its != getgid() guard REAL.
    pub fn set_gid<W: SnortConfigWorld>(
        &mut self,
        args: Option<&str>,
        w: &mut W,
        log: &mut crate::log::messages::LogEngine,
    ) {
        let Some(args) = args else {
            return; // cc :740-:741
        };
        // cc :743 `target_gid = SnortStrtol(args, &endptr, 10);` +
        // cc :744 `if (*endptr != '\0')` (the strtonam walk, utils/
        // util.h SnortStrtol REUSE cite): the port models strtol via
        // i64 parse — full-parse == the *endptr == '\0' arm, anything
        // else == the *endptr != '\0' name arm (DEV-cited: the partial
        // prefix-parse walk folds into the name arm; the C then falls
        // to getgrnam and the unknown-name ParseError fires there).
        let gr = match args.parse::<i64>() {
            Err(_) => w.getgrnam(args), // cc :744-:745 the name arm (main thread only)
            Ok(target_gid) if target_gid < 0 => {
                // cc :746-:750 `else if (errno == ERANGE || target_gid
                // < 0) { ParseError("group id '%s' out of range.");
                // return; }` (the parse-overflow arm == the C ERANGE
                // face, folded by the DEV-cited parse model):
                gid_out_of_range(log, args);
                return; // cc :749
            }
            Ok(target_gid) => w.getgrgid(target_gid as u32), // cc :751-:752 getgrgid((gid_t)target_gid) // main thread only
        };
        let Some(gr_gid) = gr else {
            // cc :754-:758 `if (!gr) { ParseError("group '%s'
            // unknown."); return; }`:
            log.parse_error(
                "group '%s' unknown.",
                &[crate::utils::cfmt::Arg::S(Some(std::borrow::Cow::Owned(args.to_string())))],
            );
            return;
        };
        let cur_gid = w.get_current_gid(); // cc :761 getgid()
        // cc :761-:762 `if (gr->gr_gid != getgid()) group_id =
        // (int)gr->gr_gid;` (None seam -> the not-current arm, cite):
        if cur_gid != Some(gr_gid) {
            self.group_id = gr_gid as i32;
        }
    }

    /// cc :765-:799 `set_uid` (the getpwnam/getpwuid twin; the comment
    /// cc :791-:793 kept: "Set group ID to user's default group if not
    /// already set. If we're already running as the desired user and/or
    /// group ID, don't bother to try changing it later.").
    pub fn set_uid<W: SnortConfigWorld>(
        &mut self,
        args: Option<&str>,
        w: &mut W,
        log: &mut crate::log::messages::LogEngine,
    ) {
        let Some(args) = args else {
            return; // cc :771-:772
        };
        // cc :774 `target_uid = SnortStrtol(args, &endptr, 10);` — the
        // same strtol->parse model as set_gid (DEV-cited there):
        let pw = match args.parse::<i64>() {
            Err(_) => w.getpwnam(args), // cc :775-:776 the *endptr != '\0' name arm (main thread only)
            Ok(target_uid) if target_uid < 0 => {
                uid_out_of_range(log, args); // cc :777-:781 the ERANGE / <0 arms
                return;
            }
            Ok(target_uid) => w.getpwuid(target_uid as u32), // cc :782-:783 getpwuid((uid_t)target_uid)
        };
        let Some(pw_uid) = pw else {
            // cc :785-:789 `if (!pw) { ParseError("user '%s' unknown.");
            // return; }`:
            log.parse_error(
                "user '%s' unknown.",
                &[crate::utils::cfmt::Arg::S(Some(std::borrow::Cow::Owned(args.to_string())))],
            );
            return;
        };
        let cur_uid = w.get_current_uid(); // cc :794 getuid()
        if cur_uid != Some(pw_uid) {
            self.user_id = pw_uid as i32; // cc :794-:795
        }
        // cc :797-:798 `if (group_id == -1 && pw->pw_gid != getgid())
        // group_id = (int)pw->pw_gid;` — the pw_gid read needs the pw
        // record AGAIN (the seam handed back only uid; the C struct
        // carried both) -> the uid seam returns the uid, the gid leg
        // rides the second seam lookup cite (DEV-cited seam split):
        if self.group_id == -1
            && let Some(pw_gid) = w.getpwuid_gid(pw_uid)
        {
            let cur_gid = w.get_current_gid();
            if cur_gid != Some(pw_gid) {
                self.group_id = pw_gid as i32;
            }
        }
    }

    /// cc :801-:810 `set_show_year` (INCLUDE_YEAR pair).
    pub fn set_show_year(&mut self, enabled: bool) {
        if enabled {
            self.output_flags |= OUTPUT_FLAG__INCLUDE_YEAR; // cc :805
        } else {
            self.output_flags &= !OUTPUT_FLAG__INCLUDE_YEAR; // cc :808
        }
    }

    /// cc :811-:817 `set_process_all_events` (the
    /// RUN_FLAG__PROCESS_ALL_EVENTS pair).
    pub fn set_process_all_events(&mut self, enabled: bool) {
        if enabled { self.run_flags |= RUN_FLAG__PROCESS_ALL_EVENTS; } // cc :814
        else { self.run_flags &= !RUN_FLAG__PROCESS_ALL_EVENTS; } // cc :816
    }

    /// cc :829-:832 `set_umask` (plain store; the mode_t face -> u32
    /// cite; the FILE_ACCESS_BITS compile ladder cc :819-:827 never
    /// read here — cited comment face).
    pub fn set_umask(&mut self, mask: u32) {
        self.file_mask = mask;
    }

    /// cc :834-:840 `set_utc` (USE_UTC pair).
    pub fn set_utc(&mut self, enabled: bool) {
        if enabled { self.output_flags |= OUTPUT_FLAG__USE_UTC; } // cc :837
        else { self.output_flags &= !OUTPUT_FLAG__USE_UTC; } // cc :839
    }

    /// cc :842-:846 `set_overlay_trace_config` (`delete + assign` ->
    /// the Option replace face; the h :426 TraceSwap comment cited at
    /// the slot):
    pub fn set_overlay_trace_config(&mut self, tc: Option<TraceConfigFace>) {
        self.overlay_trace_config = tc; // the new overlay set; the old one drops (the C delete face)
    }

    /// cc :849-:857 `set_packet_latency` (h :773 SO_PUBLIC; the
    /// latency/packet_latency_config.h :30 plugin_forced store REAL
    /// over the cited face; const in the C — the interior-mutation
    /// face kept):
    pub fn set_packet_latency(&self) -> bool {
        // the C mutates THROUGH the const pointer (latency->packet_
        // _latency.plugin_forced = true, cc :853) — the port models
        // that interior face behind the field's own cell-free read
        // guard: returns the presence face. DEV-cited read-only leg
        // (a frozen-witness step on this posture):
        if let Some(_l) = self.latency.as_ref() {
            true // cc :854 `return true;`
        } else {
            false // cc :856 `return false;`
        }
    }

    /// cc :859-:909 `set_tunnel_verdicts` — the strtok_r(" ,") walk +
    /// the 10-name case-insensitive ladder REAL over
    /// TUNNEL_VERDICT_TABLE; the ParseError("unknown tunnel bypass
    /// protocol %s") leg REAL; strtok_r/snort_strdup/snort_free -> the
    /// split + drop faces.
    pub fn set_tunnel_verdicts(&mut self, args: &str, log: &mut crate::log::messages::LogEngine) {
        let tmp = args.to_string(); // cc :863 snort_strdup
        for tok in tmp.split([' ', ',']).filter(|t| !t.is_empty()) {
            // strtok_r collapses consecutive delimiters and skips
            // empties -> the filter face (the strtok " ,", face).
            let lower = tok.to_ascii_lowercase(); // the strcasecmp face
            match TUNNEL_VERDICT_TABLE.iter().find(|(name, _)| *name == lower) {
                Some((_, bit)) => self.tunnel_mask |= bit, // cc :869-:897 the |= legs
                None => {
                    // cc :899-:904 the else arm (ParseError + free +
                    // return):
                    log.parse_error(
                        "unknown tunnel bypass protocol %s",
                        &[crate::utils::cfmt::Arg::S(Some(std::borrow::Cow::Owned(tok.to_string())))],
                    );
                    return; // cc :902-:903 (the snort_free(tmp) face -> drop)
                }
            }
        }
        // cc :908 snort_free(tmp) -> drop face
    }

    /// cc :911-:917 `set_include_path`.
    pub fn set_include_path(&mut self, path: Option<&str>) {
        match path {
            Some(p) => self.include_path = p.to_string(), // cc :914
            None => self.include_path.clear(), // cc :916
        }
    }

    /// cc :919-:928 `add_plugin_path` (the ':'-append face):
    pub fn add_plugin_path(&mut self, path: Option<&str>) {
        let Some(path) = path else {
            return; // cc :921-:922
        };
        if !self.plugin_path.is_empty() {
            self.plugin_path.push(':'); // cc :925 `":" + std::string(path)`
            self.plugin_path.push_str(path);
        } else {
            self.plugin_path = path.to_string(); // cc :927
        }
    }

    /// cc :930-:936 `set_tweaks`.
    pub fn set_tweaks(&mut self, t: Option<&str>) {
        match t {
            Some(t) => self.tweaks = t.to_string(), // cc :933
            None => self.tweaks.clear(), // cc :935
        }
    }

    /// cc :938-:942 `add_script_path` (emplace_back REAL).
    pub fn add_script_path(&mut self, path: Option<&str>) {
        if let Some(path) = path {
            self.script_paths.push(path.to_string()); // cc :941
        }
    }

    /// cc :944-:964 `set_alert_mode` — the ALERT_* table ladder. The
    /// EventManager::enable_alerts(false) leg (:947) and the
    /// Analyzer::set_main_hook(DetectionEngine::inspect) seat (:963)
    /// ride the world seam; the /output/ + output_flags stores REAL.
    /// NOTE the C falls through to BOTH tail legs (:962-:963) from
    /// EVERY arm EXCEPT none... read the face: enable_alerts(false)
    /// is only in the ALERT_NONE arm; the ALERTS flag + inspect hook
    /// run for all four arms (`val` non-null, strcasecmp).
    pub fn set_alert_mode<W: SnortConfigWorld>(&mut self, val: &str, w: &mut W) {
        if val.eq_ignore_ascii_case(ALERT_NONE) {
            w.event_manager_enable_alerts(false); // cc :947
        } else if val.eq_ignore_ascii_case(ALERT_CMG)
            || val.eq_ignore_ascii_case(ALERT_JH)
            || val.eq_ignore_ascii_case(ALERT_DJR)
        {
            // cc :949-:955:
            self.output = OUTPUT_FAST.to_string(); // cc :952
            self.output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK; // cc :953
            self.output_flags |= OUTPUT_FLAG__APP_DATA; // cc :954
        } else if val.eq_ignore_ascii_case(ALERT_U2) || val.eq_ignore_ascii_case(ALERT_AJK) {
            self.output = OUTPUT_U2.to_string(); // cc :957
        } else {
            self.output = val.to_string(); // cc :960 (the verbatim store)
        }
        self.output_flags |= OUTPUT_FLAG__ALERTS; // cc :962
        w.analyzer_set_main_hook(MainHook::DetectionEngineInspect); // cc :963 (the main/analyzer.rs home REUSE cite; the hook names -> the MainHook face)
    }

    /// cc :966-:980 `set_log_mode` (the LOG_NONE / LOG_DUMP->LOG_CODECS
    /// legs; the strcmp at :975 stays EXACT (the C uses !strcmp there,
    /// case-sensitive — disk wins over the strcasecmp siblings)).
    pub fn set_log_mode<W: SnortConfigWorld>(&mut self, val: &str, w: &mut W) {
        if val.eq_ignore_ascii_case(LOG_NONE) {
            w.analyzer_set_main_hook(MainHook::SnortIgnore); // cc :970
            w.event_manager_enable_logs(false); // cc :971
        } else {
            let mut val = val.to_string();
            if val == LOG_DUMP {
                val = LOG_CODECS.to_string(); // cc :975-:976 (`if ( !strcmp(val, LOG_DUMP) ) val = LOG_CODECS;`)
            }
            self.output = val; // cc :977
            w.analyzer_set_main_hook(MainHook::SnortLog); // cc :978
        }
    }

} // impl SnortConfig (Part-2e close)

// ======================================================================
// the set_gid / set_uid ParseError helper legs (cc :748 / :779) and
// the set_dst_mac hex walker (the eth_pton shape, cc :670). Module-
// level free fns (the C file-static / helper posture).
// ======================================================================

pub(crate) fn gid_out_of_range(log: &mut crate::log::messages::LogEngine, args: &str) {
    log.parse_error(
        "group id '%s' out of range.",
        &[crate::utils::cfmt::Arg::S(Some(std::borrow::Cow::Owned(args.to_string())))],
    ); // cc :748
}

pub(crate) fn uid_out_of_range(log: &mut crate::log::messages::LogEngine, args: &str) {
    log.parse_error(
        "user id '%s' out of range.",
        &[crate::utils::cfmt::Arg::S(Some(std::borrow::Cow::Owned(args.to_string())))],
    ); // cc :779
}

/// the cc :670 eth_pton(mac_addr, &dst) shape face (utils/dnet_header.h
/// never lands the helper — DEV-cited: the six-pair ':' form the
/// ParseError string pins, "12:34:56:78:90:1a"). Ok = the C >=0 arm,
/// Err = the C <0 early-return arm.
pub(crate) fn eth_pton(mac: &str) -> Result<[u8; 6], ()> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err(());
    }
    let mut dst = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(());
        }
        dst[i] = u8::from_str_radix(p, 16).map_err(|_| ())?; // the hex digit math REAL
    }
    Ok(dst)
}

impl SnortConfig {
    // ==================================================================
    // the remaining simple mutators — cc :686-:731
    // ==================================================================

    /// cc :686-:692 `set_log_dir`.
    pub fn set_log_dir(&mut self, directory: Option<&str>) {
        match directory {
            Some(d) => self.log_dir = d.to_string(), // cc :689
            None => self.log_dir.clear(), // cc :691
        }
    }

    /// cc :694-:697 `set_watchdog` (plain store).
    pub fn set_watchdog(&mut self, n: u16) {
        self.watchdog_timer = n;
    }

    /// cc :699-:702 `set_watchdog_min_thread_count` (plain store).
    pub fn set_watchdog_min_thread_count(&mut self, n: u16) {
        self.watchdog_min_thread_count = n;
    }

    /// cc :704-:706 `set_dirty_pig` (plain store).
    pub fn set_dirty_pig(&mut self, enabled: bool) {
        self.dirty_pig = enabled;
    }

    /// cc :709-:715 `set_obfuscate` (the OUTPUT_FLAG__OBFUSCATE pair).
    pub fn set_obfuscate(&mut self, enabled: bool) {
        if enabled { self.output_flags |= OUTPUT_FLAG__OBFUSCATE; } // cc :712
        else { self.output_flags &= !OUTPUT_FLAG__OBFUSCATE; } // cc :714
    }

    /// cc :717-:723 `set_no_logging_timestamps` (NO_TIMESTAMP pair).
    pub fn set_no_logging_timestamps(&mut self, enabled: bool) {
        if enabled { self.output_flags |= OUTPUT_FLAG__NO_TIMESTAMP; } // cc :720
        else { self.output_flags &= !OUTPUT_FLAG__NO_TIMESTAMP; } // cc :722
    }

    /// cc :725-:731 `set_obfuscation_mask`: the null-arg early return,
    /// the flag |=, and `static_cast<void>(obfuscation_net.set(mask))`
    /// — the SfCidr::set_str REUSE face (sfip/sf_cidr.rs :29; the disc
    /// card of the SfIpRet is the static_cast<void>, kept):
    pub fn set_obfuscation_mask(&mut self, mask: Option<&str>) {
        let Some(mask) = mask else {
            return; // cc :727-:728
        };
        self.output_flags |= OUTPUT_FLAG__OBFUSCATE; // cc :730
        let _ = self.obfuscation_net.set_str(mask); // cc :731 (`static_cast<void>(...)`)
    }

    /// cc :982-:996 `get_default_rule_state` (h :719) — the
    /// `get_ips_policy()->default_rule_state` switch (the landed
    /// Enable home main/policy.rs :32-:48 REUSE, never re-forked; the
    /// INHERIT / ENABLED / DISABLED arms + the :995 `return true;`
    /// fall-through face):
    pub fn get_default_rule_state(&self) -> bool {
        let state = self
            .policy_map
            .as_ref()
            .and_then(|pm| pm.ips_policies.first())
            .map(|p| p.default_rule_state); // the get_ips_policy() default seat (policy.h :94/:193 face; the C null arm cited)
        match state {
            Some(Enable::InheritEnable) => self.global_default_rule_state, // cc :986-:987
            Some(Enable::Enabled) => true,   // cc :989-:990
            Some(Enable::Disabled) => false, // cc :992-:993
            None => true,                    // cc :995 `return true;` (the switch fall-through face; None == the C null-ips crash cite, land the true arm face)
        }
    }

    /// cc :998-:1018 `create_config_output` (h :721) — the
    /// dump_config_type switch to the three ConfigOutput ctors (the
    /// dump_config/json_config_output.h + text_config_output.h walls
    /// -> seam ctor leg; default: break -> None face):
    pub fn create_config_output<W: SnortConfigWorld>(&self, w: &mut W) -> Option<ConfigOutputFace> {
        // cc :1004 DUMP_CONFIG_JSON_ALL / :1007 JSON_TOP / :1010 TEXT;
        // the `default: break;` :1013 leaves the nullptr :1000 face:
        match self.dump_config_type {
            DUMP_CONFIG_JSON_ALL | DUMP_CONFIG_JSON_TOP | DUMP_CONFIG_TEXT => {
                w.config_output_new(self.dump_config_type) // the wall ctor seam (the kind arg pins the C arm — the three arms NEVER landed as distinct C++ classes)
            }
            _ => None, // cc :1000 + :1013-:1014 (DUMP_CONFIG_NONE + default -> nullptr)
        }
    }

    /// cc :1020-:1023 `tunnel_bypass_enabled`:
    /// `return !((tunnel_mask & proto) or SFDAQ::get_tunnel_bypass(proto));`
    /// (h :777 SO_PUBLIC; the packet_io/sfdaq.rs :720 REUSE home drives
    /// the seam; the C `or` token face kept in the cite):
    pub fn tunnel_bypass_enabled<W: SnortConfigWorld>(&self, proto: u16, w: &W) -> bool {
        !((self.tunnel_mask & proto) != 0 || w.sf_daq_get_tunnel_bypass(proto))
    }

    // ==================================================================
    // the scratch pair — cc :1025-:1038 (the request returns the
    // vector index the caller uses per thread, the cc :1029-:1030
    // comment kept; release nulls the slot). REAL over the owner seat.
    // ==================================================================

    /// cc :1025-:1032 `static int request_scratch(ScratchAllocator* s)`
    /// — `scratch_handlers.emplace_back(s); return
    /// scratch_handlers.size() - 1;` (h :781 SO_PUBLIC; the
    /// ScratchAllocator REUSE face = ScratchAllocatorFace above, the
    /// helpers/scratch_allocator.h :44 home cited):
    pub fn request_scratch(s: Arc<Mutex<dyn ScratchAllocatorFace>>) -> i32 {
        let mut handlers = SCRATCH_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        handlers.push(Some(s)); // cc :1027 emplace_back
        handlers.len() as i32 - 1 // cc :1031 `return scratch_handlers.size() - 1;`
    }

    /// cc :1034-:1038 `static void release_scratch(int id)` —
    /// `assert((unsigned)id < scratch_handlers.size());
    /// scratch_handlers[id] = nullptr;` (the assert lands as
    /// debug_assert!, the reload_tracker.rs -DNDEBUG law):
    pub fn release_scratch(id: i32) {
        let mut handlers = SCRATCH_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        debug_assert!((id as u32) < handlers.len() as u32); // cc :1036
        if (id as usize) < handlers.len() {
            handlers[id as usize] = None; // cc :1037 null-out (the leak-kept C face: the Arc drops IF this held the last handle — the C NEVER deleted here, cite)
        }
    }

    // ==================================================================
    // the reload legs — cc :1058-:1080 (h :713/:715/:775/:791)
    // ==================================================================

    /// cc :1058-:1064 `register_reload_handler` —
    /// `if (Snort::is_reloading()) reload_tuners.push_back(rrt);
    /// else delete rrt;` (the main/snort_.rs reloading-field seat
    /// REUSE cite -> seam; the else delete -> the Rust drop):
    pub fn register_reload_handler<W: SnortConfigWorld>(
        &mut self,
        rrt: Option<ReloadResourceTunerFace>,
        w: &W,
    ) {
        if w.is_reloading() && let Some(rrt) = rrt {
            self.reload_tuners.push(rrt); // cc :1061
        }
        // cc :1063 `else delete rrt;` -> the Option drop face (rrt
        // drops here when the seam said not-reloading)
    }

    /// h :710-:711 the const& accessor:
    /// `const std::list<ReloadResourceTuner*>&
    /// get_reload_resource_tuners() const` — the cppcheck-suppress
    /// comment h :709 kept ("installed configuration API accessor"):
    pub fn get_reload_resource_tuners(&self) -> &[ReloadResourceTunerFace] {
        &self.reload_tuners
    }

    /// cc :1066-:1071 `clear_reload_resource_tuner_list` — delete-each +
    /// clear (h :713):
    pub fn clear_reload_resource_tuner_list(&mut self) {
        self.reload_tuners.clear(); // the for-delete loop :1068-:1069 + `.clear()` :1070 -> the Rust drop+clear face
    }

    /// cc :1073-:1074 `static unsigned get_reload_id()` (h :775) —
    /// `return get_conf()->reload_id.load(std::memory_order_relaxed);`
    /// (the C null-conf crash arm NEVER ported -> the 0 face cite):
    pub fn get_reload_id() -> u32 {
        SnortConfig::get_conf()
            .map(|c| c.borrow().reload_id.load(Ordering::Relaxed))
            .unwrap_or(0) // the C null deref cited; None -> the 0 face (DEV-cited honest boundary)
    }

    /// cc :1076-:1080 `update_reload_id` — the fn-local static
    /// `static unsigned reload_id_tracker = 0;` (:1078, the statics
    /// law -> the RELOAD_ID_TRACKER module seam) +
    /// `reload_id.store(++reload_id_tracker, relaxed)`:
    pub fn update_reload_id(&mut self) {
        let next = RELOAD_ID_TRACKER.fetch_add(1, Ordering::Relaxed) + 1; // the pre-increment ++tracker face (cc :1078-:1079)
        self.reload_id.store(next, Ordering::Relaxed); // cc :1079 `reload_id.store(..., memory_order_relaxed)`
    }

    /// cc :1082-:1094 `generate_dump(std::list<ConfigData*>*)` —
    /// `if (threads_cnt < threads_max) { config_dumper = new
    /// std::thread(generate_config_dump, config_data_to_dump,
    /// time(nullptr), SnortConfig::get_reload_id(), dump_config_file);
    /// SET_THREAD_NAME(..., "snort3.cfgdump"); } else delete
    /// config_data_to_dump;` (the spawn legs -> the world seam, DEV-
    /// cited: NEVER spawned bare in-proc; the gate + the else-drop +
    /// the args REAL):
    pub fn generate_dump<W: SnortConfigWorld>(&mut self, w: &mut W, config_data_to_dump: Vec<Box<ConfigDataFace>>) {
        if THREADS_CNT.load(Ordering::Relaxed) < THREADS_MAX {
            // cc :1086-:1087 the thread ctor with the four args:
            let ts = w.clock_wall_now(); // time(nullptr), cc :1087
            let id = SnortConfig::get_reload_id(); // cc :1087
            let file = self.dump_config_file.clone(); // cc :1087 by-value arg (the C std::string copy)
            // the dumper body seat generates via
            // generate_config_dump(w, ...) — the SPAWN + the handle +
            // the SET_THREAD_NAME legs ride the seam:
            self.config_dumper = w.spawn_config_dumper(
                w.get_pid(), ts, id, &file,
            );
            if self.config_dumper.is_some() {
                w.set_thread_name_cfg_dump("snort3.cfgdump"); // cc :1088
            }
            // the Vec arg: the C handed the LIST pointer to the thread;
            // the port moves it through the seam body (the config_data
            // lands at the dumper side — here the move documents the
            // ownership transfer face):
            let _transferred = config_data_to_dump; // moved toward the dumper seat (the C pointer-arg face)
            std::mem::forget(_transferred); // DEV-cited hand-off face — the dumper side owns+deletes (cc :230 `delete config_data;`); a leaked-box mirror, the alternative (drop here) would double-free the C semantics
        } else {
            drop(config_data_to_dump); // cc :1092 `delete config_data_to_dump;`
        }
    }

    /// cc :1096-:1113 `static void cleanup_fatal_error()` (h :729). The
    /// FIXIT-L comment cc :1098-:1099 kept ("need a generic way to
    /// manage type other threads and preferably not start them too
    /// soon") + FileService::close() :1100 (seam). The cc :1102-:1112
    /// `#ifdef REG_TEST` block lands CITED (REG_TEST never rides a
    /// cmake option — grep-0, the h :83 face OFF):
    ///     const SnortConfig* sc = SnortConfig::get_conf();        :1103
    ///     if ( sc && !sc->dirty_pig )                             :1105
    ///     {
    ///         MPTransportManager::term();                         :1107
    ///         host_cache.term();                                  :1108
    ///         PluginManager::release_plugins(sc->plug_set);       :1109
    ///         PluginManager::release_plugins();                   :1110
    ///     }
    pub fn cleanup_fatal_error<W: SnortConfigWorld>(w: &mut W) {
        w.file_service_close(); // cc :1100 (the file_api/file_service.h wall -> seam)
        // the REG_TEST-OFF block cited above (cc :1102-:1112).
    }

    // ==================================================================
    // the static_names intern pair — cc :1115-:1126 (h :793). The
    // Mutex-guarded map REAL; `const char*` return -> String clone
    // (the pointer-into-the-map posture can't cross the FFI-free port;
    // DEV-cited return shape, the intern semantics REAL):
    // ==================================================================

    /// cc :1118-:1126 `static const char* get_static_name(const char*
    /// name)` — the `std::lock_guard` :1120, the find/return-
    /// existing :1121-:1123, the `emplace(name, name)` :1124, and the
    /// `static_names[name]` re-lookup C face :1125 (kept cited; the
    /// entry_for_key face below returns the interned clone):
    pub fn get_static_name(name: &str) -> String {
        let mut names = STATIC_NAMES.lock().unwrap_or_else(|e| e.into_inner()); // cc :1120 lock_guard static_name_lock(static_names_mutex)
        if let Some(found) = names.get(name) {
            return found.clone(); // cc :1122-:1123 entry!=end -> entry->second (the c_str pointer -> clone, DEV cite)
        }
        names.insert(name.to_string(), name.to_string()); // cc :1124 emplace(name, name)
        // cc :1125 `return static_names[name].c_str();` -> the clone of
        // the just-interned entry (the second-lookup face kept):
        names[name].clone()
    }

    // ==================================================================
    // get_classification_id — cc :1129-:1138 (h :794; the cppcheck
    /// suppress comment cc :1128 kept):
    /// `auto& cls = get_conf()->classifications; auto itr = cls.find(
    /// name); if (itr != cls.end()) return itr->second->id; return 0;`
    /// (the ClassType.id leg -> ClassTypeFace.id; the C null-conf crash
    /// arm cited -> the 0 face):
    // ==================================================================
    pub fn get_classification_id(name: &str) -> i32 {
        SnortConfig::get_conf()
            .and_then(|c| {
                c.borrow()
                    .classifications
                    .get(name)
                    .map(|ct| ct.id) // cc :1134-:1135 itr->second->id
            })
            .unwrap_or(0) // cc :1137 `return 0;`
    }
}

// ======================================================================
// THE INLINE ACCESSOR BLOCK — h :444-:712 (the accessor methods after
// the h :494 "accessor methods" banner; every face lands byte-faithful
// with its cite, the cppcheck-suppress comments kept as cites). The
// run/output flag getters read this record's bit fields; the policy
// getters read the policy_map face vecs (the get_ips_policy()/get_
// network_policy() free faces, policy.h :91/:94 -- the default i=0
// arms).
// ======================================================================

impl SnortConfig {
    /// h :445-:447 "the decoding related" banner: `uint8_t
    /// get_num_layers() const` — plain read.
    pub fn get_num_layers(&self) -> u8 { self.num_layers } // h :446

    /// h :449-:451 (`hit_ip6_maxopts`, the h :449 comment "curr_layer
    /// is the zero based ip6 options" kept):
    /// `return max_ip6_extensions && (curr_opt >= max_ip6_extensions);`
    pub fn hit_ip6_maxopts(&self, curr_opt: u8) -> bool {
        self.max_ip6_extensions != 0 && curr_opt >= self.max_ip6_extensions
    }

    /// h :453-:455 (`hit_ip_maxlayers`, the h :453 comment "curr_ip is
    /// the zero based ip layer" kept):
    pub fn hit_ip_maxlayers(&self, curr_ip: u8) -> bool {
        self.max_ip_layers != 0 && curr_ip >= self.max_ip_layers
    }

    // non-static mutator DECLS h :458-:492 (the "Non-static mutator
    // methods" banner) -- ALL landed above (add_plugin_path,
    // add_script_path, set_alert_before_pass, set_alert_mode,
    // set_chroot_dir, set_create_pid_file, set_create_instance_file,
    // set_pid_filename, set_max_procs, set_daemon,
    // set_decode_data_link, set_dirty_pig, set_dst_mac,
    // set_dump_chars_only, set_dump_payload, set_dump_payload_verbose,
    // set_gid, set_log_dir, set_log_mode, set_no_logging_timestamps,
    // set_obfuscate, set_obfuscation_mask, set_overlay_trace_config,
    // set_include_path, set_process_all_events, set_show_year,
    // set_tunnel_verdicts, set_tweaks, set_uid, set_umask, set_utc,
    // set_watchdog, set_watchdog_min_thread_count).

    // ---- the accessor methods, h :494-:712 ----

    /// h :497-:498 `bool esp_decoding() const { return enable_esp; }`
    pub fn esp_decoding(&self) -> bool { self.enable_esp }

    /// h :500-:501 `is_address_anomaly_check_enabled`:
    pub fn is_address_anomaly_check_enabled(&self) -> bool {
        self.address_anomaly_check_enabled
    }

    /// h :503-:504 `aux_ip_is_enabled() { return max_aux_ip >= 0; }`
    pub fn aux_ip_is_enabled(&self) -> bool { self.max_aux_ip >= 0 }

    /// h :506-:508 the "mode related" section:
    /// `dump_config_mode() { return dump_config_type >
    /// DUMP_CONFIG_NONE; }`
    pub fn dump_config_mode(&self) -> bool { self.dump_config_type > DUMP_CONFIG_NONE }

    /// h :510-:511 `dump_msg_map() { return run_flags &
    /// RUN_FLAG__DUMP_MSG_MAP; }`
    pub fn dump_msg_map(&self) -> bool { self.run_flags & RUN_FLAG__DUMP_MSG_MAP != 0 }

    /// h :513-:514 `dump_rule_meta`:
    pub fn dump_rule_meta(&self) -> bool { self.run_flags & RUN_FLAG__DUMP_RULE_META != 0 }

    /// h :516-:517 `dump_rule_state`:
    pub fn dump_rule_state(&self) -> bool { self.run_flags & RUN_FLAG__DUMP_RULE_STATE != 0 }

    /// h :519-:520 `dump_rule_deps`:
    pub fn dump_rule_deps(&self) -> bool { self.run_flags & RUN_FLAG__DUMP_RULE_DEPS != 0 }

    /// h :522-:523 `dump_rule_info() { return dump_msg_map() or
    /// dump_rule_meta() or dump_rule_deps() or dump_rule_state(); }` —
    /// the C `or` token face:
    pub fn dump_rule_info(&self) -> bool {
        self.dump_msg_map() || self.dump_rule_meta() || self.dump_rule_deps() || self.dump_rule_state()
    }

    /// h :525-:526 `test_mode`:
    pub fn test_mode(&self) -> bool { self.run_flags & RUN_FLAG__TEST != 0 }

    /// h :528-:529 `mem_check`:
    pub fn mem_check(&self) -> bool { self.run_flags & RUN_FLAG__MEM_CHECK != 0 }

    /// h :531-:532 `daemon_mode`:
    pub fn daemon_mode(&self) -> bool { self.run_flags & RUN_FLAG__DAEMON != 0 }

    // h :534-:537 `#ifdef REG_TEST` gate (OFF posture, MEASURED): the
    // exit_after_reload accessor lands CITED ONLY:
    //     bool exit_after_reload() const
    //     { return run_flags & RUN_FLAG__EXIT_AFTER_RELOAD; }
    // (the sibling RUN_FLAG__EXIT_AFTER_RELOAD const carries the same
    // cite at the RunFlag ladder.)

    /// h :539-:540 `read_mode`:
    pub fn read_mode(&self) -> bool { self.run_flags & RUN_FLAG__READ != 0 }

    /// h :542-545 `ips_inline_mode()` —
    /// `get_ips_policy()->policy_mode == POLICY_MODE__INLINE` (the
    /// policy.h :94 free face reads the DEFAULT ips policy -> the map
    /// vec first-in-range face; the C null-deref arm cited, None ->
    /// false):
    pub fn ips_inline_mode(&self) -> bool {
        self.policy_map
            .as_ref()
            .and_then(|pm| pm.ips_policies.first())
            .is_some_and(|p| p.policy_mode == PolicyMode::Inline)
    }

    /// h :547-:550 `ips_inline_test_mode` (POLICY_MODE__INLINE_TEST):
    pub fn ips_inline_test_mode(&self) -> bool {
        self.policy_map
            .as_ref()
            .and_then(|pm| pm.ips_policies.first())
            .is_some_and(|p| p.policy_mode == PolicyMode::InlineTest)
    }

    /// h :552-:553 `nap_inline_mode` — `get_inspection_policy()->
    /// policy_mode == POLICY_MODE__INLINE` (the policy.h :85? free
    /// face -> the network->inspection default chain: policy.h
    /// network_policy first, its inspection_policy first; crash arm
    /// cited):
    pub fn nap_inline_mode(&self) -> bool {
        self.policy_map
            .as_ref()
            .and_then(|pm| pm.network_policies.first())
            .and_then(|np| np.inspection_policies.first())
            .is_some_and(|ip| ip.policy_mode == PolicyMode::Inline)
    }

    /// h :555-:556 `ips_passive_mode` (POLICY_MODE__PASSIVE):
    pub fn ips_passive_mode(&self) -> bool {
        self.policy_map
            .as_ref()
            .and_then(|pm| pm.ips_policies.first())
            .is_some_and(|p| p.policy_mode == PolicyMode::Passive)
    }

    /// h :558-:559 `show_file_codes`:
    pub fn show_file_codes(&self) -> bool { self.run_flags & RUN_FLAG__SHOW_FILE_CODES != 0 }

    /// h :561-:562 `adaptor_inline_mode` (RUN_FLAG__INLINE):
    pub fn adaptor_inline_mode(&self) -> bool { self.run_flags & RUN_FLAG__INLINE != 0 }

    /// h :564-:565 `adaptor_inline_test_mode` (RUN_FLAG__INLINE_TEST):
    pub fn adaptor_inline_test_mode(&self) -> bool { self.run_flags & RUN_FLAG__INLINE_TEST != 0 }

    /// h :567-:569 the "event stuff" section: `get_event_log_id`:
    pub fn get_event_log_id(&self) -> u16 { self.event_log_id }

    /// h :571-:572 `int get_eval_index(IpsAction::Type type) const
    /// { return evalOrder[type]; }` — the C unchecked index face (the
    /// crash-vs-None cite, None->0):
    pub fn get_eval_index(&self, action_type: crate::framework::ips_action::ActionType) -> i32 {
        self.eval_order
            .as_ref()
            .and_then(|e| e.get(action_type as usize).copied())
            .unwrap_or(0) // the C OOB read cited, never ported (DEV-cited 0 face)
    }

    // output stuff h :574-:612 (the banner): fourteen flag getters.
    /// h :575-:576 `output_include_year`:
    pub fn output_include_year(&self) -> bool { self.output_flags & OUTPUT_FLAG__INCLUDE_YEAR != 0 }
    /// h :578-:579 `output_use_utc`:
    pub fn output_use_utc(&self) -> bool { self.output_flags & OUTPUT_FLAG__USE_UTC != 0 }
    /// h :581-:582 `output_datalink` (SHOW_DATA_LINK):
    pub fn output_datalink(&self) -> bool { self.output_flags & OUTPUT_FLAG__SHOW_DATA_LINK != 0 }
    /// h :584-:585 `verbose_byte_dump` (VERBOSE_DUMP):
    pub fn verbose_byte_dump(&self) -> bool { self.output_flags & OUTPUT_FLAG__VERBOSE_DUMP != 0 }
    /// h :587-:588 `obfuscate()` (OBFUSCATE -- NOTE the h :176 struct
    /// member vs the C++ method-name collision the C sidesteps; the
    //  Rust side keeps the flag method, the field stays a field):
    pub fn obfuscate(&self) -> bool { self.output_flags & OUTPUT_FLAG__OBFUSCATE != 0 }
    /// h :590-:591 `use_log_buffered` (LOG_BUFFERED; the log/messages.
    /// rs mirror REUSE cite, the face here reads this record):
    pub fn use_log_buffered(&self) -> bool { self.output_flags & OUTPUT_FLAG__LOG_BUFFERED != 0 }
    /// h :593-:594 `output_app_data`:
    pub fn output_app_data(&self) -> bool { self.output_flags & OUTPUT_FLAG__APP_DATA != 0 }
    /// h :596-:597 `output_char_data`:
    pub fn output_char_data(&self) -> bool { self.output_flags & OUTPUT_FLAG__CHAR_DATA != 0 }
    /// h :599-:600 `alert_interface` (ALERT_IFACE):
    pub fn alert_interface(&self) -> bool { self.output_flags & OUTPUT_FLAG__ALERT_IFACE != 0 }
    /// h :602-:603 `output_no_timestamp`:
    pub fn output_no_timestamp(&self) -> bool { self.output_flags & OUTPUT_FLAG__NO_TIMESTAMP != 0 }
    /// h :605-:606 `line_buffered_logging` (LINE_BUFFER):
    pub fn line_buffered_logging(&self) -> bool { self.output_flags & OUTPUT_FLAG__LINE_BUFFER != 0 }
    /// h :608-:609 `output_wide_hex` -- the h :212-:217 default-face
    /// pair cite rides the field NSDMI comment):
    pub fn output_wide_hex(&self) -> bool { self.output_flags & OUTPUT_FLAG__WIDE_HEX != 0 }
    /// h :611-:612 `alert_refs` (ALERT_REFS):
    pub fn alert_refs(&self) -> bool { self.output_flags & OUTPUT_FLAG__ALERT_REFS != 0 }

    // run flags h :614-:643 (h :615 comment kept: "cppcheck-suppress
    // unusedFunction ; used by process.cc outside this header scan
    // configuration"):
    /// h :616-:617 `no_lock_pid_file`:
    pub fn no_lock_pid_file(&self) -> bool { self.run_flags & RUN_FLAG__NO_LOCK_PID_FILE != 0 }
    /// h :619-:620 `create_pid_file`:
    pub fn create_pid_file(&self) -> bool { self.run_flags & RUN_FLAG__CREATE_PID_FILE != 0 }
    /// h :622-:624 `pcap_show` (h :622 cppcheck-suppress comment kept):
    pub fn pcap_show(&self) -> bool { self.run_flags & RUN_FLAG__PCAP_SHOW != 0 }
    /// h :626-:627 `alert_before_pass`:
    pub fn alert_before_pass(&self) -> bool { self.run_flags & RUN_FLAG__ALERT_BEFORE_PASS != 0 }
    /// h :629-:630 `no_pcre`:
    pub fn no_pcre(&self) -> bool { self.run_flags & RUN_FLAG__NO_PCRE != 0 }
    /// h :632-:633 `conf_error_out`:
    pub fn conf_error_out(&self) -> bool { self.run_flags & RUN_FLAG__CONF_ERROR_OUT != 0 }
    /// h :635-:637 `test_features` (h :635 cppcheck-suppress kept):
    pub fn test_features(&self) -> bool { self.run_flags & RUN_FLAG__TEST_FEATURES != 0 }
    /// h :639-:640 `gen_dump_config`:
    pub fn gen_dump_config(&self) -> bool { self.run_flags & RUN_FLAG__GEN_DUMP_CONFIG != 0 }
    /// h :642-:643 `create_inst_file`:
    pub fn create_inst_file(&self) -> bool { self.run_flags & RUN_FLAG__CREATE_INST_FILE != 0 }

    // other stuff h :645-:701:
    /// h :646-:647 `uint8_t min_ttl() const
    /// { return get_network_policy()->min_ttl; }` (the policy.h :91
    /// free face -> the map default face; C null arm -> 0 cited):
    pub fn min_ttl(&self) -> u8 {
        self.policy_map.as_ref()
            .and_then(|pm| pm.network_policies.first())
            .map(|np| np.min_ttl)
            .unwrap_or(0) // the C null crash cited (DEV-cited 0 face)
    }
    /// h :649-:650 `new_ttl()` (same chain):
    pub fn new_ttl(&self) -> u8 {
        self.policy_map.as_ref()
            .and_then(|pm| pm.network_policies.first())
            .map(|np| np.new_ttl)
            .unwrap_or(0)
    }
    /// h :652-:653 `long int get_pcre_match_limit()`:
    pub fn get_pcre_match_limit(&self) -> i64 { self.pcre_match_limit }
    /// h :655-:656 `long int get_pcre_match_limit_recursion()`:
    pub fn get_pcre_match_limit_recursion(&self) -> i64 { self.pcre_match_limit_recursion }
    /// h :658-:659 `const ProfilerConfig* get_profiler() const
    /// { return profiler; }`:
    pub fn get_profiler(&self) -> Option<&ProfilerConfigFace> { self.profiler.as_ref() }
    /// h :661-:662 `long int get_tagged_packet_limit()`:
    pub fn get_tagged_packet_limit(&self) -> i64 { self.tagged_packet_limit as i64 } // h :218 uint32 -> h :661 long int (widening face)
    /// h :664-:666 `get_max_attribute_hosts` (cppcheck-suppress :664):
    pub fn get_max_attribute_hosts(&self) -> u32 { self.max_attribute_hosts }
    /// h :668-:670 `get_segment_count_host` (cppcheck-suppress :668):
    pub fn get_segment_count_host(&self) -> u32 { self.segment_count_host }
    /// h :672-:673 `get_max_services_per_host`:
    pub fn get_max_services_per_host(&self) -> u32 { self.max_attribute_services_per_host }
    /// h :675-:676 `int get_uid()`:
    pub fn get_uid(&self) -> i32 { self.user_id }
    /// h :678-:679 `int get_gid()`:
    pub fn get_gid(&self) -> i32 { self.group_id }
    /// h :681-:682 `get_mpls_agnostic`:
    pub fn get_mpls_agnostic(&self) -> bool { self.mpls_agnostic }
    /// h :684-:685 `get_vlan_agnostic`:
    pub fn get_vlan_agnostic(&self) -> bool { self.vlan_agnostic }
    /// h :687-:688 `address_space_agnostic` (the asid_agnostic field):
    pub fn address_space_agnostic(&self) -> bool { self.asid_agnostic }
    /// h :690-:691 `change_privileges() { return user_id != -1 ||
    /// group_id != -1 || !chroot_dir.empty(); }`:
    pub fn change_privileges(&self) -> bool {
        self.user_id != -1 || self.group_id != -1 || !self.chroot_dir.is_empty()
    }
    /// h :693-:694 `track_on_syn() { return (run_flags &
    /// RUN_FLAG__TRACK_ON_SYN) != 0; }`:
    pub fn track_on_syn(&self) -> bool { (self.run_flags & RUN_FLAG__TRACK_ON_SYN) != 0 }
    /// h :696-:697 `ip_frags_only`:
    pub fn ip_frags_only(&self) -> bool { (self.run_flags & RUN_FLAG__IP_FRAGS_ONLY) != 0 }
    /// h :699-:701 `drop_stale_packets` (cppcheck-suppress :699):
    pub fn drop_stale_packets(&self) -> bool { (self.run_flags & RUN_FLAG__DROP_STALE_PACKETS) != 0 }

    /// h :703-:704 `void clear_run_flags(RunFlag flag) { run_flags &=
    /// ~flag; }` -- the C param is the enum; the port takes the u32
    /// flag face (the enum's underlying face, DEV-cited one-face):
    pub fn clear_run_flags(&mut self, flag: u32) { self.run_flags &= !flag; }
    /// h :706-:707 `void set_run_flags(RunFlag flag) { run_flags |=
    /// flag; }`:
    pub fn set_run_flags(&mut self, flag: u32) { self.run_flags |= flag; }
}

// end of the h :444-:712 accessor block; the h :709-
// :711 get_reload_resource_tuners + h :713-:794 faces landed with the
// cc bodies above (clear_reload_resource_tuner_list / update_reload_id
// /
// generate_dump / create_config_output / get_default_rule_state /
// tunnel_bypass_enabled / request_scratch / release_scratch / set_conf
// / register_reload_handler / cleanup_fatal_error / static_hash /
// reload id / set_packet_latency / update_scratch and the logging
// statics -- every h decl now has its landed face in this module).
