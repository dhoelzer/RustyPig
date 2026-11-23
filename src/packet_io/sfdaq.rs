//! Flat, cite-heavy literal port of the row-23a wrapper pair:
//! `packet_io/sfdaq.h` 72 L (ground truth @ fe29cbe: md5
//! `2e272d2d68e40138946326df3c5cfc95`) + `packet_io/sfdaq.cc` 420 L (md5
//! `7ac13aa1f5013ead580f5b4f61c38368`) = 492 L — THE SFDAQ static facade
//! over the DAQ SDK: load/unload, print_types (the sorted module walk +
//! the capability-string family), the AddDaqModuleConfig -> daq_config_
//! push ladder, the init mode ladder (inline/read-file/passive from the
//! SnortConfig run-flags face), the verdict/mode STRING faces, the
//! forwarding_packet flag face, the local-instance wrapper family, the
//! two-arg get_input_spec ladder, and the DAQ_DEFAULT "pcap" face.
//!
//! THE REAL-SDK RE-CITE LAW (plan row 20; THIS row is the opener): the
//! `<daq.h>` face rides the REAL libdaq SDK @ c8d4083 (READ-ONLY
//! `/opt/data/libdaq`, api/daq.h 178 L md5 35294a1773477a9579c8494cb1dadfea,
//! api/daq_common.h 728 L md5 28789a3dc10b84c974118c38700755b4 plus
//! api/daq_module_api.h 165 L md5 1a617b3edef11431c9244bee728baadc). The
//! harness (tools/daqio_harness) lands the REAL SDK headers plus the REAL
//! api .c objects (daq_base.c daq_config.c daq_mod_ops.c...) and compiles
//! plus RUNS the ground sfdaq.cc byte-exact against them: the E4 PRE-RECITE
//! arm shows the legacy graft face dies with EXACTLY-86 errors, the
//! RE-CITED header swap compiles rc0, and the vectors ride REAL
//! daq_verdict_string/daq_mode_string bodies. The synthetic graft faces
//! (73fdbc39/f683749c masters, fead0027 v2, 0f7016a6 v3, 9b603f8f ext#4,
//! 97bca757 plus e8a39bf3 plus 1be562b2 the ext#4 trio, b99e44b9 the 22b
//! pkth ext) are EVIDENCE NEVER ABI truth — the measured face-by-face
//! ledger lands in the harness recite_ledger + KNOWN DEVIATIONS.md (row
//! 23a).
//!
//! KEY MEASURED RE-CITE faces the port pins as consts (probe-measured,
//! NEVER size_of/guess): DAQ_COMMON_API_VERSION 0x00030013, verdict
//! family TRUE 6 values MAX_DAQ_VERDICT=6 (the 22b honest face STAYS),
//! the verdict STRINGS pass/block/replace/whitelist/blacklist/ignore
//! (daq_base.c:56-:63 — the 9b603f8f PAUSE/WAITING/COUNT names DIE),
//! mode strings none/passive/inline/read-file (:65-:70), the REAL
//! DAQ_PktHdr_t 56 bytes WITH address_space_id/tenant_id (the 22b
//! pkth-wall fields EXIST in the real SDK — the ledger line closes),
//! flags NOT_FORWARDING 0x0002 / IGNORE_VLAN 0x0008 / SIGNIFICANT_GROUPS
//! 0x8000 (the synthetic 0x20 face DRIFTS), DLT_RAW 12 / DLT_IPV4 228 /
//! DLT_IPV6 229 / DLT_EN10MB 1 / DLT_PPP_ETHER 51 vs the real faces.
//!
//! THE SFDAQInstance half (sfdaq_instance.{h,cc} 105+436) is row 23b —
//! NEVER invented here (the cd_user.rs:163 provider law): the local-
//! instance wrapper family rides an opaque `DaqInstanceSeam` provider
//! seam, LEFT-OPEN, the harness witness mirrors it at C level (own-11
//! face) and the Rust trait stands in for the replay; the LEFT-OPEN
//! honesty rides vectors as the wrapper-default legs (can_* false on no
//! instance — cc :374-:392 short-circuits ARE literal ported).

use std::borrow::Cow;

use crate::log::messages::LogEngine;
use crate::utils::cfmt::Arg;

use super::sfdaq_config::{SFDAQConfig, SFDAQModuleConfig, SFDAQ_MODE_INLINE, SFDAQ_MODE_PASSIVE, SFDAQ_MODE_READ_FILE};

// ---- THE REAL-SDK vocabulary (libdaq api/daq_common.h @ c8d4083, every
// value probe-pinned by tools/daqio_harness vectors_faceA) ----

/// api/daq_common.h:56 `#define DAQ_SUCCESS 0`.
pub const DAQ_SUCCESS: i32 = 0;
/// :57-:65 the error family VERBATIM (the synth faces carried ONLY
/// DAQ_SUCCESS — the real family lands with the SDK):
pub const DAQ_ERROR: i32 = -1;
pub const DAQ_ERROR_NOMEM: i32 = -2;
pub const DAQ_ERROR_NODEV: i32 = -3;
pub const DAQ_ERROR_NOTSUP: i32 = -4;
pub const DAQ_ERROR_NOMOD: i32 = -5;
pub const DAQ_ERROR_NOCTX: i32 = -6;
pub const DAQ_ERROR_INVAL: i32 = -7;
pub const DAQ_ERROR_EXISTS: i32 = -8;
pub const DAQ_ERROR_AGAIN: i32 = -9;

/// api/daq_common.h:35 `#define DAQ_COMMON_API_VERSION 0x00030013` — the
/// FACE-A `common=0x30013` pin (the synth faces carry NO version face).
pub const DAQ_COMMON_API_VERSION: u32 = 0x0003_0013;

/// api/daq_common.h:67-:78 DAQ_RSTAT_OK 0 .. MAX_DAQ_RSTAT 8 (`rstat=8`).
pub const DAQ_RSTAT_OK: u32 = 0;
pub const DAQ_RSTAT_WOULD_BLOCK: u32 = 1;
pub const DAQ_RSTAT_TIMEOUT: u32 = 2;
pub const DAQ_RSTAT_EOF: u32 = 3;
pub const DAQ_RSTAT_INTERRUPTED: u32 = 4;
pub const DAQ_RSTAT_NOBUF: u32 = 5;
pub const DAQ_RSTAT_ERROR: u32 = 6;
pub const DAQ_RSTAT_INVALID: u32 = 7;
pub const MAX_DAQ_RSTAT: u32 = 8;

/// api/daq_common.h:313-:322 the TRUE verdict family — MAX_DAQ_VERDICT
/// == 6 CONFIRMED against the real SDK (the ext#4 9b603f8f ordinal 0..4
/// +MAX=6 face was HONEST on the VALUES-COUNT but WRONG on the extra
/// PAUSE/WAITING/COUNT names — this ledger measures it EVERY build):
pub const DAQ_VERDICT_PASS: u32 = 0;
pub const DAQ_VERDICT_BLOCK: u32 = 1;
pub const DAQ_VERDICT_REPLACE: u32 = 2;
pub const DAQ_VERDICT_WHITELIST: u32 = 3;
pub const DAQ_VERDICT_BLACKLIST: u32 = 4;
pub const DAQ_VERDICT_IGNORE: u32 = 5;
pub const MAX_DAQ_VERDICT: u32 = 6;

/// api/daq_common.h:324-:331 DAQ_Mode — MODE_NONE 0 / PASSIVE 1 /
/// INLINE 2 / READ_FILE 3 / MAX_DAQ_MODE 4 (`mode=4`). NOT to be
/// confused with the snort-own SFDAQ_MODE_* ordinals (sfdaq_config.rs —
/// the cc :189-:197 mapping lands `map_mode`).
pub const DAQ_MODE_NONE: u32 = 0;
pub const DAQ_MODE_PASSIVE: u32 = 1;
pub const DAQ_MODE_INLINE: u32 = 2;
pub const DAQ_MODE_READ_FILE: u32 = 3;
pub const MAX_DAQ_MODE: u32 = 4;

/// api/daq_common.h:342-:350 DAQ_State (`state=5` MAX face).
pub const DAQ_STATE_UNINITIALIZED: u32 = 0;
pub const DAQ_STATE_INITIALIZED: u32 = 1;
pub const DAQ_STATE_STARTED: u32 = 2;
pub const DAQ_STATE_STOPPED: u32 = 3;
pub const DAQ_STATE_UNKNOWN: u32 = 4;
pub const MAX_DAQ_STATE: u32 = 5;

/// api/daq_common.h:371-:377 the module-type flag faces (the print_types
/// ladder :114-:131 + can_run_unprivileged :338 ride these EXACT
/// values — FACE-A TYPES line):
pub const DAQ_TYPE_FILE_CAPABLE: u32 = 0x01;
pub const DAQ_TYPE_INTF_CAPABLE: u32 = 0x02;
pub const DAQ_TYPE_INLINE_CAPABLE: u32 = 0x04;
pub const DAQ_TYPE_MULTI_INSTANCE: u32 = 0x08;
pub const DAQ_TYPE_NO_UNPRIV: u32 = 0x10;
pub const DAQ_TYPE_WRAPPER: u32 = 0x20;

/// api/daq_common.h:112-:130 the packet-flag family — THE RE-CITE
/// DRIFTS: cc :328 NOT_FORWARDING lands 0x0002 (synth face rode a
/// different layout; cc :117? NO — sfdaq.cc reads ONLY :328); the 20a
/// synthetic IGNORE_VLAN 0x40 DRIFTS -> REAL 0x0008 (:117); the f683749c
/// master SIGNIFICANT_GROUPS 0x20 DRIFTS -> REAL 0x8000 (:129). The
/// harness E9/ledger leg measures this EVERY build (22b's graft face
/// stays EVIDENCE, NEVER ABI truth).
pub const DAQ_PKT_FLAG_OPAQUE_IS_VALID: u32 = 0x0001;
pub const DAQ_PKT_FLAG_NOT_FORWARDING: u32 = 0x0002; // sfdaq.cc:328 THE read-face
pub const DAQ_PKT_FLAG_IGNORE_VLAN: u32 = 0x0008;
pub const DAQ_PKT_FLAG_SIGNIFICANT_GROUPS: u32 = 0x8000;

/// api/daq_common.h:132-:133 (`UNKNOWN -1 / FLOOD -2`).
pub const DAQ_PKTHDR_UNKNOWN: i32 = -1;
pub const DAQ_PKTHDR_FLOOD: i32 = -2;

/// C-ABI probe pins (NEVER size_of — the harness FACE-A SIZES line @
/// c8d4083): sizeof(DAQ_PktHdr_t)=56 WITH address_space_id at offset 44
/// (uint32) + tenant_id at 48 (uint32) — THE 22b pkth-wall closure face;
/// DAQ_Stats_t=96; DAQ_MSG_META_SLOTS 8 (:97).
pub const PROBE_SIZEOF_DAQ_PKTHDR: usize = 56;
pub const PROBE_SIZEOF_DAQ_STATS: usize = 96;
pub const OFFSETOF_PKTHDR_ADDRESS_SPACE_ID: usize = 44;
pub const OFFSETOF_PKTHDR_TENANT_ID: usize = 48;

/// THE REAL verdict-string table (libdaq api/daq_base.c:56-:63) —
/// SFDAQ::verdict_to_string (sfdaq.cc:320-:323 one-liner over
/// daq_verdict_string) rides THESE; MAX/above lands the SDK's NULL face
/// (harness DEC T8 `max=null` + FACE-A VERDICTS line):
pub fn daq_verdict_string(verdict: u32) -> Option<&'static str> {
    match verdict {
        DAQ_VERDICT_PASS => Some("pass"),
        DAQ_VERDICT_BLOCK => Some("block"),
        DAQ_VERDICT_REPLACE => Some("replace"),
        DAQ_VERDICT_WHITELIST => Some("whitelist"),
        DAQ_VERDICT_BLACKLIST => Some("blacklist"),
        DAQ_VERDICT_IGNORE => Some("ignore"),
        _ => None, // daq_base.c:82 `if (verdict >= MAX_DAQ_VERDICT) return NULL`
    }
}

/// THE REAL mode-string table (daq_base.c:65-:70 + :90-:93): the cc
/// :302 LogMessage face rides it; MAX -> NULL (`max=null`).
pub fn daq_mode_string(mode: u32) -> Option<&'static str> {
    match mode {
        DAQ_MODE_NONE => Some("none"),
        DAQ_MODE_PASSIVE => Some("passive"),
        DAQ_MODE_INLINE => Some("inline"),
        DAQ_MODE_READ_FILE => Some("read-file"),
        _ => None,
    }
}

// THE h-side static-face census (h :40-:68): the wrappers land as an
// SFDAQ facade struct over the harness-measured seams. The C file-statics
// cc :52-:58 — daqcfg / default_daq_mode / daq_module_names / loaded +
// the THREAD_LOCAL local_instance — land as SFDAQ-instance fields (the
// file-global posture of the port, the messages.rs file-globals-on-engine
// law); local_instance is the row-23b seam provider.

/// The SDK config-mirror face (the daqcfg handle cc :52): the push
/// ladder lands real contents over the provider seam (the harness links
/// the REAL daq_config.c — the Rust mirror replays the OBSERVABLE
/// accessors: msg_pool_size/snaplen/timeout/total_instances + the pushed
/// modcfg stack in walk order, the can_run_unprivileged face).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DaqConfigMirror {
    pub msg_pool_size: u32, // :250 set(batch*4) — harness T6 pool=256
    pub snaplen: i32,       // :251 set(mru) — T6 snap=1518
    pub timeout: u32,       // :252 — T6 tmo=1000
    pub total_instances: u32, // :253-:254 set ONLY when > 1 — T6 tot=4
    pub pushed: Vec<PushedModCfg>, // :213 push stack (walk order = push order)
}

/// The pushed per-module config (the daq_module_config_new/set ladder):
/// the mapped mode (cc :189-:198 — the harness T7 mapped=1/1/2/3 face) +
/// the var pairs where an EMPTY string lands NONE (cc :203
/// `value = kvp.second.length() ? .. : nullptr` — T6 empty= face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedModCfg {
    pub name: String,
    pub mode: u32,
    pub variables: Vec<(String, Option<String>)>,
}

/// The module descriptor seam (a LOADED DAQ module as the wrapper sees
/// it — name/version/type/variable-descs; the REAL provider = the SDK's
/// DAQ_ModuleAPI_t registration, daq_base.c; the Rust side takes caller-
/// supplied records — the SAME left-open provider law as cd_user.rs —
/// NEVER a fake dynamic loader). The VariableDesc face (daq_common.h:
/// :335-:340 + the DAQ_VAR_DESC flags :333-:334) rides print_types.
pub const DAQ_VAR_DESC_REQUIRES_ARGUMENT: u32 = 0x01;
pub const DAQ_VAR_DESC_FORBIDS_ARGUMENT: u32 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaqVariableDesc {
    pub name: String,
    pub description: String,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaqModuleDesc {
    pub name: String,   // daq_module_get_name (cc :106/:110)
    pub version: u32,   // daq_module_get_version (cc :110)
    pub type_flags: u32, // daq_module_get_type (cc :112/:275/:338)
    pub var_descs: Vec<DaqVariableDesc>, // :134-:135
}

/// cc :189-:197 the SFDAQMode -> DAQ_Mode map EXACT (the else arm rides
/// the caller-provided default_daq_mode — the facade field).
pub fn map_mode(sfdq_mode: u32, default_daq_mode: u32) -> u32 {
    match sfdq_mode {
        SFDAQ_MODE_PASSIVE => DAQ_MODE_PASSIVE,
        SFDAQ_MODE_INLINE => DAQ_MODE_INLINE,
        SFDAQ_MODE_READ_FILE => DAQ_MODE_READ_FILE,
        _ => default_daq_mode, // cc :197 `mode = default_daq_mode`
    }
}

/// THE SFDAQ facade (the static-class posture of h :37-:69 — every
/// static becomes a method over these fields; the h :52/:58/:63-:65
/// SO_PUBLIC face is a naming cite, the Rust pub carries it).
#[derive(Default)]
pub struct SFDaq {
    // cc :52 static DAQ_Config_h daqcfg = nullptr — present face:
    pub daqcfg: Option<DaqConfigMirror>,
    // cc :53 static DAQ_Mode default_daq_mode = DAQ_MODE_PASSIVE:
    pub default_daq_mode: u32,
    // cc :54 static string daq_module_names (the ':'-join face :221-:223):
    pub daq_module_names: String,
    // cc :55 static bool loaded = false:
    pub loaded: bool,
    // cc :58 THREAD_LOCAL SFDAQInstance* local_instance — THE 23b seam
    // (opaque provider, NEVER invented; the wrapper legs that READ it
    // take it as an explicit Option arg — the port's no-thread_local law,
    // main/thread.rs ThreadState precedent):
    pub local_instance: Option<Box<dyn DaqInstanceSeam>>,
    // the loaded-module table seam (print_types / find / can-run walk):
    pub modules: Vec<DaqModuleDesc>,
}

/// The row-23b provider seam (sfdaq_instance.h :37-:78 public surface —
/// cite-never-carry: the C class lands at 23b; this trait carries ONLY
/// the methods sfdaq.cc :345-:402 WRAPS, the exact legs the 23a harness
/// witness mirrors at C level (own-11 face):
pub trait DaqInstanceSeam {
    fn init(&mut self, cfg: &DaqConfigMirror, bpf_string: &str) -> bool; // cc :347 instance->init
    fn get_input_spec(&self) -> &str;        // cc :366
    fn get_base_protocol(&self) -> i32;      // cc :371
    fn can_inject(&self) -> bool;            // cc :376
    fn can_inject_raw(&self) -> bool;        // cc :381
    fn can_replace(&self) -> bool;           // cc :386
    fn get_tunnel_bypass(&self, proto: u16) -> bool; // cc :391
    fn inject(&mut self, rev: i32, buf: &[u8]) -> i32; // cc :396 (DAQT handled SDK-side)
    fn get_stats(&self) -> (u64, [u64; MAX_DAQ_VERDICT as usize]); // cc :401 -> DAQ_Stats_t (harness T9b stats=11 vblock=3 face)
}

impl SFDaq {
    /// cc :45-:49 `#ifdef DEFAULT_DAQ -> STRINGIFY_MX(DEFAULT_DAQ) #else
    /// "pcap"`: the harness config.h carries NO DEFAULT_DAQ (measured
    /// grep-0) so the build rides "pcap" — the Rust side pins the SAME
    /// build face (the build-system DEFAULT_DAQ knob is out-repo; cite).
    pub const DAQ_DEFAULT: &'static str = "pcap";

    /// cc :60-:79 load: builds the dirs[] nullptr-terminated array
    /// (cfg.module_dirs), (ENABLE_STATIC_DAQ branch: OFF in the harness/
    /// donor config.h — measured grep-0, cite-never-land — the
    /// sfdaq_static_modules.h CMAKE-GENERATED face rides .h.in header-find
    /// 0 dialect, honestly cited), then daq_load_dynamic_modules(dirs):
    /// THE REAL body daq_base.c:259-:303 walks dirs dlopen'ing every
    /// *.so (missing dirs CONTINUE, :270-:273 — NO error face for them);
    /// non-zero err -> cc :73-:74 FatalError (the Rust port surfaces
    /// Err — C's _exit is the driver layer, never reached here). The
    /// Rust mirror NEVER dlopens (the provider seam law): the caller
    /// supplies the walked module table (the harness feeds the REAL
    /// static-registration face). SUCCESS logs NOTHING (the C face —
    /// only the err arm logs); loaded = true.
    pub fn load(&mut self, cfg: &SFDAQConfig, walked: Vec<DaqModuleDesc>) -> Result<(), i32> {
        let _ = &cfg.module_dirs; // the dirs[] array face (nullptr-terminated): the walk CONSUMES it
        self.modules = walked; // daq_load_dynamic_modules landed-table mirror
        self.loaded = true;
        Ok(())
    }

    /// cc :81-:85 unload: daq_unload_modules() (REAL daq_base.c:305-:319
    /// walk-unload+dlclose) then loaded = false. The mirror CLEARS the
    /// module table (the observable face).
    pub fn unload(&mut self) {
        self.modules.clear();
        self.loaded = false;
    }

    /// cc :87-:150 print_types: the FIRST/next walk -> sort by strcmp
    /// (:104-:106 the module_get_name comparator) -> per module:
    /// `name(vN):` + the cap strings (:114-:131: readback / live / inline
    /// / multi / `if (!(type & NO_UNPRIV)) unpriv` THE INVERTED ARM /
    /// wrapper) + the Variables table (num>0 -> `  name <arg>|[arg] - desc`,
    /// REQUIRES first, FORBIDS-suppresses the [arg] arm). The ostream
    /// lands as a String sink (the file_log buffer posture).
    pub fn print_types(&self, out: &mut String) {
        if !self.modules.is_empty() {
            out.push_str("Available DAQ modules:\n");
        } else {
            out.push_str("No available DAQ modules (try adding directories with --daq-dir).\n");
        }
        let mut modules = self.modules.clone();
        modules.sort_by(|a, b| a.name.cmp(&b.name)); // std::sort strcmp face
        for m in modules {
            out.push_str(&format!("{}(v{}):", m.name, m.version));
            if m.type_flags & DAQ_TYPE_FILE_CAPABLE != 0 {
                out.push_str(" readback");
            }
            if m.type_flags & DAQ_TYPE_INTF_CAPABLE != 0 {
                out.push_str(" live");
            }
            if m.type_flags & DAQ_TYPE_INLINE_CAPABLE != 0 {
                out.push_str(" inline");
            }
            if m.type_flags & DAQ_TYPE_MULTI_INSTANCE != 0 {
                out.push_str(" multi");
            }
            if m.type_flags & DAQ_TYPE_NO_UNPRIV == 0 {
                // cc :126 THE INVERTED face `if (!(type & DAQ_TYPE_NO_UNPRIV))`
                out.push_str(" unpriv");
            }
            if m.type_flags & DAQ_TYPE_WRAPPER != 0 {
                out.push_str(" wrapper");
            }
            out.push('\n');
            if !m.var_descs.is_empty() {
                out.push_str(" Variables:\n");
                for vd in &m.var_descs {
                    out.push_str(&format!("  {} ", vd.name));
                    if vd.flags & DAQ_VAR_DESC_REQUIRES_ARGUMENT != 0 {
                        out.push_str("<arg> ");
                    } else if vd.flags & DAQ_VAR_DESC_FORBIDS_ARGUMENT == 0 {
                        out.push_str("[arg] ");
                    }
                    out.push_str(&format!("- {}\n", vd.description));
                }
            }
        }
    }

    /// Find a loaded module by name (the REAL daq_find_module face
    /// daq_base.c:333-:337 strcmp walk — cc :174/:274).
    pub fn find_module(&self, name: &str) -> Option<&DaqModuleDesc> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// cc :171-:226 the static AddDaqModuleConfig(dmc): find -> ParseError
    /// plus false (harness T4/T7c ParseError face); daq_module_config_new,
    /// the mode map (:189-:198), the var loop (:200-:211 the empty-
    /// string -> nullptr :203 face; a failed set -> ParseError then destroy
    /// then false — the SDK NEVER rejects a plain set, daq_config.c:226);
    /// push (:213); daq_module_names insert-join (:221-:223 — prepend plus
    /// ':' separator, the harness `alpha:alpha:...` cumulative face).
    /// Ok(()) vs Err(ParseError-observed) — the log counters carry the
    /// ParseError side (messages.rs parse_error :214 — the landed twin).
    pub fn add_daq_module_config(
        &mut self,
        dmc: &SFDAQModuleConfig,
        cfg_mirror: &mut DaqConfigMirror,
        log: &mut LogEngine,
    ) -> bool {
        let module = match self.find_module(&dmc.name) {
            Some(m) => m.clone(),
            None => {
                log.parse_error(
                    "Could not find requested DAQ module: %s\n",
                    &[Arg::S(Some(Cow::from(dmc.name.as_str())))],
                );
                return false;
            }
        };
        let mode = map_mode(dmc.mode, self.default_daq_mode);
        let variables: Vec<(String, Option<String>)> = dmc
            .variables
            .iter()
            .map(|(k, v)| (k.clone(), if v.is_empty() { None } else { Some(v.clone()) }))
            .collect();
        cfg_mirror.pushed.push(PushedModCfg {
            name: module.name.clone(),
            mode,
            variables,
        });
        if !self.daq_module_names.is_empty() {
            // cc :222 daq_module_names.insert(0, 1, ':')
            let mut s = String::from(":");
            s.push_str(&self.daq_module_names);
            self.daq_module_names = s;
        }
        // cc :223 insert(0, module_name)
        let mut s = module.name.clone();
        s.push_str(&self.daq_module_names);
        self.daq_module_names = s;
        true
    }

    /// cc :228-:305 init (returns bool — h :45): auto-load (:230-:231),
    /// the conf ladder (:235-:242 adaptor_inline_mode/read_mode ->
    /// default_daq_mode; the caller passes the two booleans — the conf
    /// seam, harness T7b set_run_flags(RUN_FLAG__INLINE) face), the
    /// daq_config_new + the 4 setters + the total>1 guard (:244-:254 —
    /// the harness pool=256/snap=1518/tmo=1000/tot=4 pins), the empty-
    /// modules default face (:256-:267 name=DAQ_DEFAULT -> the find fail
    /// -> destroy + nullptr + false), the WRAPPER auto-pcap convenience
    /// (:271-:287 a DAQ_TYPE_WRAPPER first module -> push pcap READ_FILE,
    /// same find fail here), the any_of push loop + destroy/null-false
    /// (:289-:295), and the :302 LogMessage "%s DAQ configured to %s."
    /// face over daq_module_names + daq_mode_string(default). The five
    /// args stay UNDER clippy's too_many_arguments bar (threshold 7) --
    /// ZERO allow, the house face.
    pub fn init(
        &mut self,
        cfg: &SFDAQConfig,
        total_instances: u32,
        adaptor_inline: bool,
        read_mode: bool,
        log: &mut LogEngine,
    ) -> bool {
        if !self.loaded {
            // cc :230-:231 if (!loaded) load(cfg) — the provider seam
            // arg here = the CURRENT module table (the mirror's re-walk
            // lands the same table; the C auto-load feeds dirs to the
            // REAL loader):
            let walked = self.modules.clone();
            let _ = self.load(cfg, walked);
        }
        // cc :54 — the NAMES static is NOT reset by init (the harness
        // T7 cumulative `alpha:alpha:` evidence face — the ONLY reset is
        // the fresh-process face; honest deviation: the C++ static rides
        // process lifetime, so do the fields; the harness vectors pin the
        // cumulative join face EVERY build).
        let mut mirror = DaqConfigMirror {
            msg_pool_size: cfg.get_batch_size() * 4, // cc :250
            snaplen: cfg.get_mru_size(),             // cc :251
            timeout: cfg.timeout,                    // cc :252
            ..Default::default()
        };
        if total_instances > 1 {
            mirror.total_instances = total_instances; // cc :253-:254 :265
        }

        // cc :235-:242 the conf face (before the module legs):
        self.default_daq_mode = if adaptor_inline {
            DAQ_MODE_INLINE
        } else if read_mode {
            DAQ_MODE_READ_FILE
        } else {
            DAQ_MODE_PASSIVE
        };
        // cc :256-:267 no modules -> the DAQ_DEFAULT record:
        if cfg.module_configs.is_empty() {
            let dmc = SFDAQModuleConfig {
                name: Self::DAQ_DEFAULT.to_string(),
                ..Default::default()
            };
            if !self.add_daq_module_config(&dmc, &mut mirror, log) {
                self.daqcfg = None; // cc :263-:264 destroy + daqcfg = nullptr (the ParseError COUNTER STAYS — the NEVER-reset C face, no invented reset)
                return false;
            }
        } else {
            // cc :271-:287 the WRAPPER convenience arm (first module's
            // REAL type face drives it):
            let first = &cfg.module_configs[0];
            if let Some(m) = self.find_module(&first.name).filter(|m| m.type_flags & DAQ_TYPE_WRAPPER != 0) {
                let _ = m; // the type face ONLY gates the arm (cc :273-:274)
                let dmc = SFDAQModuleConfig {
                    name: "pcap".to_string(),
                    mode: SFDAQ_MODE_READ_FILE,
                    ..Default::default()
                };
                if !self.add_daq_module_config(&dmc, &mut mirror, log) {
                    self.daqcfg = None;
                    return false;
                }
            }
            // cc :289-:295 any_of the push loop:
            let mut failed = false;
            for dmc in cfg.module_configs.iter() {
                if !self.add_daq_module_config(dmc, &mut mirror, log) {
                    failed = true;
                    break; // std::any_of SHORT-CIRCUITS — the honest leg
                }
            }
            if failed {
                self.daqcfg = None;
                return false;
            }
        }
        self.daqcfg = Some(mirror);
        // cc :302 LogMessage("%s DAQ configured to %s.\n", names, mode):
        let mode_str = daq_mode_string(self.default_daq_mode).unwrap_or("");
        let names = self.daq_module_names.clone();
        log.log_message_stdout(
            "%s DAQ configured to %s.\n",
            &[
                Arg::S(Some(Cow::from(names.as_str()))),
                Arg::S(Some(Cow::from(mode_str))),
            ],
        );
        true
    }

    /// cc :307-:318 term: daqcfg destroy + nullptr; the `#ifndef
    /// REG_TEST` unload arm COMPILES in the harness/donor config.h
    /// (measured grep-0 REG_TEST) -> if loaded, unload(). Honest
    /// REG_TEST arm: cite-never-land (the reg-test define NEVER rides).
    pub fn term(&mut self) {
        self.daqcfg = None;
        if self.loaded {
            self.unload();
        }
    }

    /// cc :320-:323 verdict_to_string — the REAL SDK table (the row-20
    /// heart face; the harness DEC T8 vs the 22b synth ledger):
    pub fn verdict_to_string(verdict: u32) -> Option<&'static str> {
        daq_verdict_string(verdict)
    }

    /// cc :325-:329 forwarding_packet: mode INLINE AND the REAL
    /// NOT_FORWARDING 0x0002 flag arm ABSENT:
    pub fn forwarding_packet(&self, pkth_flags: u32) -> bool {
        self.default_daq_mode == DAQ_MODE_INLINE && (pkth_flags & DAQ_PKT_FLAG_NOT_FORWARDING) == 0
    }

    /// cc :331-:343 can_run_unprivileged: walk the pushed modcfg stack
    /// (daq_config_top/next_module_config); ANY module with the
    /// NO_UNPRIV bit -> false. The walk pairs the pushed stack against
    /// the module table BY NAME (the REAL face walks modcfg->module,
    /// daq_config.c — the mirror pairs by name, the push ladder guarantees
    /// the record):
    pub fn can_run_unprivileged(&self) -> bool {
        if let Some(cfg) = &self.daqcfg {
            for p in cfg.pushed.iter() {
                if let Some(m) = self.find_module(&p.name).filter(|m| m.type_flags & DAQ_TYPE_NO_UNPRIV != 0) {
                    let _ = m; // the NO_UNPRIV bit -> false (cc :338-:341)
                    return false;
                }
            }
        }
        true
    }

    /// cc :345-:348 init_instance: instance->init(daqcfg, bpf) — the
    /// 23b seam; None daqcfg rides the C nullptr arg face (the SDK
    /// instance_instantiate would INVAL — NEVER reached pre-23b, cite).
    pub fn init_instance(&mut self, bpf_string: &str) -> bool {
        let cfg = self.daqcfg.clone().unwrap_or_default();
        match self.local_instance.as_mut() {
            Some(i) => i.init(&cfg, bpf_string),
            None => false, // cc DEREFACES on nullptr local — the Rust Option face (deviation: C would SIGSEGV-then-crash; the harness witness instance ALWAYS rides — the vectors pin the Some leg)
        }
    }

    /// cc :354-:362 set/get_local_instance (the FIXIT-M X helpers h :60-
    /// :63): plain store/take.
    pub fn set_local_instance(&mut self, sdi: Option<Box<dyn DaqInstanceSeam>>) {
        self.local_instance = sdi;
    }

    /// cc :364-:372 the two wrapper getters — local_instance DEREF faces;
    /// the Rust Option face (None = the C nullptr deref that NEVER fires
    /// on the landed legs; the vectors pin the Some legs).
    pub fn get_input_spec(&self) -> Option<&str> {
        self.local_instance.as_deref().map(|i| i.get_input_spec())
    }
    pub fn get_base_protocol(&self) -> Option<i32> {
        self.local_instance.as_deref().map(|i| i.get_base_protocol())
    }

    /// cc :374-:392 the can_* + tunnel short-circuits (`local_instance
    /// &&` — the NULL legs ARE literal, the vectors pin BOTH sides):
    pub fn can_inject(&self) -> bool {
        self.local_instance.as_deref().is_some_and(|i| i.can_inject())
    }
    pub fn can_inject_raw(&self) -> bool {
        self.local_instance.as_deref().is_some_and(|i| i.can_inject_raw())
    }
    pub fn can_replace(&self) -> bool {
        self.local_instance.as_deref().is_some_and(|i| i.can_replace())
    }
    pub fn get_tunnel_bypass(&self, proto: u16) -> bool {
        self.local_instance
            .as_deref()
            .is_some_and(|i| i.get_tunnel_bypass(proto))
    }

    /// cc :394-:397 inject(msg, rev, buf, len) — DAQT msg selector is the
    /// SDK's (LEFT-OPEN pre-23b); local DEREF face as above:
    pub fn inject(&mut self, rev: i32, buf: &[u8]) -> Option<i32> {
        self.local_instance.as_mut().map(|i| i.inject(rev, buf))
    }

    /// cc :399-:402 get_stats() — the DAQ_Stats_t* face; the mirror
    /// returns the seam's counters (the harness T9b 11/3 pins):
    pub fn get_stats(&self) -> Option<(u64, [u64; MAX_DAQ_VERDICT as usize])> {
        self.local_instance.as_deref().map(|i| i.get_stats())
    }

    /// cc :404-:413 the two-arg get_input_spec ladder (NOT the wrapper —
    /// h :50; the house overload law, module.rs :457/:474 precedent: the
    /// suffixed unique name): empty -> nullptr; 0 < id < len ->
    /// inputs[id]; else inputs[0] (id 9 OVERFLOW lands [0] — the harness
    /// T3 id9=ethA face, the unsigned compare face `(instance_id > 0 &&
    /// instance_id < inputs.size())`):
    pub fn get_input_spec_for_instance(cfg: &SFDAQConfig, instance_id: usize) -> Option<&str> {
        if cfg.inputs.is_empty() {
            return None;
        }
        if instance_id > 0 && instance_id < cfg.inputs.len() {
            return Some(cfg.inputs[instance_id].as_str());
        }
        Some(cfg.inputs[0].as_str())
    }

    /// cc :415-:419 default_type (cppcheck-suppressed unusedFunction —
    /// the entry-point-retained face): rides DAQ_DEFAULT.
    pub fn default_type() -> &'static str {
        Self::DAQ_DEFAULT
    }
}

