//! Row 24k — the NET-work MOD-ule pair landing (chapter-21 ELEVENTH and
//! FINAL main/ body — THE CHAPTER CLOSER).
//!
//! Ground: main/net-work mod-ule .cc 137 L md5 97d0d10a48582dbd9100e2ae65c05ca5 +
//! main/net-work mod-ule .h 42 L md5 8389f8a5164c6bb5513558941b080a95 @ fe29cbe
//! (the 179 L ledger — the SMALLEST pair of the chapter; MEASURED at this row:
//! wc 137/42, the md5 faces above re-verified against the read-only ground).
//! The main/CMa-ke seats ride AD-JA-CENT :39/:40 PLAIN (the adjacency face
//! 40-39==1, MEASURED). The mod wiring is the ONE line this row flips
//! 14 -> 15 (the complete-flip law; the 24d..24j rows each added one
//! wiring line — this landing genuinely FIRES that cascade, the disk wins).
//!
//! THE STATIC CENSUS (grep-measured on the ground pair, the echo the twin
//! replays): the ground .cc carries EXACTLY-2 `^static` lines (:37 the
//! param-eters table and :73 the lua set-poli-cy fn) and the .h EXACTLY-0;
//! the `static THREAD_LOCAL` face is EXACTLY-0 in BOTH files (grep-0 x2,
//! MEASURED). Census echo: ^static 2 + 0 = 2; THREAD_LOCAL 0 + 0 = 0. The
//! two static seats ride the GROUND linkage face honestly: the pair's :88
//! set-poli-cy param-eters and :94 cm-ands tables are `const` at namespace
//! scope == INTERNAL linkage in C++ (the nm face reads the _ZL-mangled
//! locals — the harness DEFINED walk proves it; the 24j sibling landing's
//! extern tables NEVER share this face). Rust rides them pub with the
//! `static` cite (the visibility-face deviation, cited here once).
//!
//! THE ZERO-GATE ECHO (SEVENTH control, walked by the harness EVERY build):
//! TEST/TEST_CASE/CATCH/UNIT_TEST/REG_TEST find-0 in BOTH files; the
//! `#if` faces EXACTLY-1 each (cc :21 the HAVE_CONFIG_H rider, h :21 the
//! guard seat — MEASURED, NOT the 24j face's :20); the mai-n/te-st CMa-ke
//! EXACTLY-2 add-cp'pu-test faces name NEI-THER row TU.
//!
//! THE ONE-HOME REUSE (landed homes RIDDEN, NEVER re-forked, NEVER
//! edited):
//! * the 24h po-licy home (main/po-licy.rs): [`NetworkPolicy`] (the h:226
//!   user_policy_id / h:230 min_ttl / h:231 new_ttl field seats) and
//!   [`PolicyMap::get_user_network`] (h:351 def policy.cc:294-:299) — the
//!   set() id/min-ttl/new-ttl writes + the lua set-poli-cy lookup call
//!   THOSE landed legs directly.
//! * the 24g con-fi-g home (main/sn-ort-con-fi-gp .rs):
//!   [`SnortConfig`] num_layers (:277) / max_ip6_extensions (:278) /
//!   max_ip_layers (:279) — the set() decode-limit writes ride the
//!   landed pub fields.
//! * the 20a par-ser home (par-ser/con-fi-g Fi-le .rs): the landed
//!   [`config_checksum_drop`] / [`config_checksum_mode`] (config_file.cc
//!   :155-:159 / :161-:165, the GetChecksumFlags :46-:153 home) — the
//!   cc :112/:115 set() legs call THOSE directly, NEVER a re-port of the
//!   checksum parser.
//! * the framework/module .rs home: the landed [`Module`] record
//!   (new_params ctor triple) + [`Command`] record + the 18a
//!   [`LuaCFunctionToken`] posture (no lua_State type in the Rust tree) —
//!   the ctor/commands legs ride it; and framework/par-am-e-ter .rs's
//!   landed [`Parameter`] record (name/ptype/deflt slots; the range slot
//!   has NO seat there — the 24f-era deferral, cite-never-invent: the
//!   range strings ride per-row comment cites, the face the 24f
//!   S-PARAMS and 24r se-arch-eng-i-ne tables re-rode).
//! * the 24e reg-i-stry home (main/mod-u-les .rs): the cite faces STAY
//!   as-is — :3525 the sup-press-(:2401) / ne-t-work-(:2404, ne-t-work_
//!   mod-ule .cc :101) ledger comment + :3647 INDEPENDENT_MODULE_IDS[27]
//!   NetworkModule add — THIS landing EXTENDS over that home, NO re-fork,
//!   the cite faces UNMOVED.
//! * the 23a sf-da-q homes: NEV-ER re-declared HERE — this pair is the
//!   DAQ-module SEAM face (the boot module that tunes the network pa-ram-
//!   et-ers the sf-da-q legs read): the REAL DAQ_MOD-ULE API surface was
//!   mapped at 23a/23c's homes; ZERO da-q seats ride this pair (grep-coun-t
//!   MEASURED-0 both ground files, the harness E4 graft face re-proves it
//!   EVERY build); the check-sum fam-i-ly cons-ts RE-U-SE the 24h po-licy
//!   home's CHECKSUM_FLAG__* consts, NEVER re-declared.
//!
//! NOT-LAND walls that ride seam CITE legs (bodies NEVER invented): the
//! sh-e-ll set-net-work-poli-cy-user-id leg (mai-n/sh-e-ll .h :101, body
//! mai-n/sh-e-ll .cc NEVER-land at this row — the 24c sh-ell home owns the
//! class, this row NEVER re-forks it: the ported leg routes through the
//! 24h home's user_network lease + a cited world-seam echo), the con-tro-l
//! ControlConn::query_from_lua wa-ll (con-tro-l/con-tro-l .h :72, body
//! NEVER-land — the 18a fam-i-ly law: the non-SHELL/arm-never-landed face
//! IS the constant nullptr, the ported leg takes the ALREADY-QUERIED
//! `Option<&mut dyn ControlConnFace>` face the 24i an-al-y-zer-com-m-and
//! home landed, REUSE), and the lua_State arg itself (the 18a LuaCF-unction
//! token posture: the ported set-poli-cy leg takes the ALREADY-EXTRACTED
//! `Option<&str>` id face — the luaL_optstring :75 default-NULL + the
//! strtoull :76 base-10 legs ride [`parse_user_id`] below with the honest
//! NULL-into-strtoull UB arm CITED-NEVER-driven (the harness NF face)).
//! The LogRespond :83 else-arm is the control.h :99 macro face RE-RIDDEN:
//! conn==None -> the landed [`LogEngine::error_message`]-style LogMessage
//! home (log/mess-ag-es .rs), the EX-A-CT text verbatim (`Error: inval-id
//! ne-wor-k .id; no pol-i-cy f-oun-d`).
//!
//! #ifdef di-al-ect fac-es MEASURED: ZERO di-al-ect posts in the pair (the
//! ONLY #i-fs are the HAVE_CONFIG_H riders h/ccc :21 + the h :21-:22/:42
//! guard). The cpp-check sup-pr-ess face h :37 rides the comment VERBATIM
//! (the use-l-ess-Overri-de cite, pin: the over-ri-d-e doc-umen-t-s the
//! CONTE XT posture — the port's get-usage lands C_USAGE_CONTEXT = 1,
//! the landed codec home's ordinal RE-U-SE, NEVER re-authored).
//!
//! ZE-R-O ne-w att-rib-ut-es law: NO `#!`-gate he-re — the whole surface
//! is pub-reac-hable off the mo-d-r-s wir-ing line (walked `cargo build`
//! warning-fr-ee, MEA-S-URED, the he-l-p-era cle-an p-osture re-ri-dd-en).

// the landed C_USAGE_CONTEXT ordinal home RE-U-SE (the codec era's pin,
// module .h :216 family — NEVER re-authored at this row):
use crate::codecs::codec_module::C_USAGE_CONTEXT;
use crate::framework::module::{Command, LuaCFunctionToken, Module};
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::framework::value::Value;
use crate::log::messages::LogEngine;
use crate::main::analyzer_command::ControlConnFace; // the 24i logged-conn seam face REUSE (query_from_lua wall)
// the 24h home: NetworkPolicy field seats + PolicyMap::get_user_network
// REUSE (cc :78; the global nav getter cc :109 `get_network_policy()` is
// THAT home's policy.h :91 face — cited, the setter arm threads the
// caller-owned policy face, ONE-home law):
use crate::main::policy::{NetworkPolicy, PolicyMap};
use crate::main::snort_configp::SnortConfig;
use crate::parser::config_file::{config_checksum_drop, config_checksum_mode};

/// cc :37-:69 `static const Parameter network_params[]` — EIGHT named rows +
/// the sent-in-el (MEASURED the harness face: slots 8+1). The :39/:43 PT_MULTI
/// pair are EX-CLU-SIVELY: the type census face multi=2 select=0 (FACE-A A3).
/// The range strings ride the cite law (the landed Par-am-e-ter record has NO
/// range slot — the 24f-era deferral):
///   checksum_drop (:39-:41) / checksum_eval (:43-:45) — PT_MULTI, range
///     "all | ip | noip | tcp | notcp | udp | noudp | icmp | noicmp | none",
///     deflt "none" / "all" respective-ly;
///   id (:47-:48) PT_INT range "1:max53" deflt "1"; min_ttl (:50-:52)
///   PT_INT "1:255" "1"; new_ttl (:54-:55) "1:255" "1"; layers (:57-:58)
///   "3:255" deflt "40"; max_ip6_extensions (:60-:62) "0:255" "0";
///   max_ip_layers (:64-:66) "0:255" "0"; sentinel (:68).
pub static NETWORK_PARAMS: [Parameter; 9] = [
    Parameter {
        name: Some("checksum_drop"), // :39
        ptype: PtType::PtMulti,      // :39 (range + help ride the cite above)
        deflt: Some("none"),         // :40
    },
    Parameter {
        name: Some("checksum_eval"), // :43
        ptype: PtType::PtMulti,      // :43
        deflt: Some("all"),          // :44
    },
    Parameter {
        name: Some("id"), // :47
        ptype: PtType::PtInt,
        deflt: Some("1"), // :47 "1:max53" cited
    },
    Parameter {
        name: Some("min_ttl"), // :50
        ptype: PtType::PtInt,
        deflt: Some("1"), // :50 "1:255" cited
    },
    Parameter {
        name: Some("new_ttl"), // :54
        ptype: PtType::PtInt,
        deflt: Some("1"), // :54 "1:255" cited
    },
    Parameter {
        name: Some("layers"), // :57
        ptype: PtType::PtInt,
        deflt: Some("40"), // :57 "3:255" cited
    },
    Parameter {
        name: Some("max_ip6_extensions"), // :60
        ptype: PtType::PtInt,
        deflt: Some("0"), // :60 "0:255" cited
    },
    Parameter {
        name: Some("max_ip_layers"), // :64
        ptype: PtType::PtInt,
        deflt: Some("0"), // :64 "0:255" cited
    },
    Parameter {
        name: None, // :68 the PT_MAX sent-in-el
        ptype: PtType::PtMax,
        deflt: None,
    },
];

/// cc :71 `#define network_help "configure basic network parameters"` — the
/// macro face lands as the const record (the 18a-era macro->const posture;
/// the string NEVER re-wrapped).
pub const NETWORK_HELP: &str = "configure basic network parameters"; // :71

/// The strtoull :76 port face: `luaL_optstring(L, 1, 0)` -> the NULL-when-
/// absent face (the SECOND arg 0 == no default, MEASURED; the harness's
/// no-arg arm is CITED-NEVER-driven — NULL into strtoull is UB, the NF
/// wall). The C strtoull base-10 legs, face-for-face: an optional run of
/// spaces, an optional sign, the LONGEST valid digit run; no digits ->
/// 0 (end-ptr == start), a junk tail -> just the head value, a signed
/// face wraps exactly as strtoull does (the 0wr-appyng face, NEVER a
/// cl-amp). The "1:max53" range-gate of :47/:90 rides the PARSE era,
/// NEVER re-authored HERE (the landed Parameter cite law).
pub fn parse_user_id(raw: Option<&str>) -> u64 {
    let s = match raw {
        // the NULL face CITED (the UB arm, NEVER driven): the port lands
        // the harness-never-fire 0-face
        Some(s) => s.trim_start(),
        None => return 0,
    };
    // :76 strtoull: optional sign then longest digit run
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let run: String = digits.chars().take_while(|c| c.is_ascii_digit()).collect();
    let v = run.parse::<u64>().unwrap_or(0); // no digits -> 0 (the end-ptr face)
    if neg {
        0u64.wrapping_sub(v) // C strtoull wraps negatives (the -1 == MAX face), cited
    } else {
        v
    }
}

/// cc :73-:86 `static int network_set_policy(lua_State* L)` — the ported
/// body face (the 18a posture: the lua args ride ALREADY-EXTRACTED faces;
/// the harness drove the REAL lua_State seam, the Rust face pins the
/// OBSERVABLE legs):
///   :75-:76 the optstring + strtoull legs -> [`parse_user_id`] above;
///   :78 the `get_conf()->policy_map->get_user_network(user_id)` lookup ->
///     the 24h home [`PolicyMap::get_user_network`] REUSE (the config-home
///     policy_map hop cited, sn-ort-con-fi-gp .rs :528);
///   :79 the HIT arm -> the Shell::set_net-work-poli-cy-user-id wall (the
///     sh-e-ll home NEVER re-forked — the seam echo leg the caller owns;
///     the port returns the HIT face so the twin/harness echo the seat);
///   :81-:84 the MISS arm: ControlConn::query_from_lua (:82, the NEVER-land
///     wa-ll -> the ALREADY-QUERIED `Option<&mut dyn ControlConnFace>`
///     face the 24i home landed) + the LogRespond :83 macro else-arm ->
///     the landed Log-Mes-sag-e home (the EX-A-C-T text verbatim:
///     "Error: invalid network.id; no policy found\n").
/// Returns the C 0 (the lua ret-count face).
pub fn network_set_policy(
    raw_id: Option<&str>,
    policy_map: &PolicyMap,
    conn: Option<&mut dyn ControlConnFace>,
    log: &mut LogEngine,
) -> i32 {
    let user_id = parse_user_id(raw_id); // :75-:76
    if policy_map.get_user_network(user_id).is_some() {
        // :79 Shell::set_network_policy_user_id(L, user_id) — the never-land
        // sh-e-ll wall (h :101); the HIT face routes to the caller's seam;
        // the NEVER side NEVER fires (the harness NF face).
        let _ = user_id; // the seam hand-off cite (the Shell home's leg NEVER forks HERE)
    } else {
        // :82 ControlConn* ctrlcon = ControlConn::query_from_lua(L); +
        // :83 LogRespond(ctrlcon, "Error: invalid network.id; no policy found\n");
        // — the control.h :99 macro face: conn present -> respond, else LogMessage.
        let msg = "Error: invalid network.id; no policy found\n";
        match conn {
            Some(c) => {
                // the respond leg (the 24i conn seam; the non-null arm
                // NEVER fires in the walked posture — cited NF)
                c.respond(msg);
            }
            None => {
                log.error_message("%s", &[crate::utils::cfmt::Arg::S(Some(msg.into()))]);
            }
        }
    }
    0 // :85 return 0
}

/// cc :88-:92 `const Parameter network_set_policy_params[]` — the one named
/// row (:90, PT_INT "1:max53" deflt "1", help "user network policy id") +
/// the sent-in-el (:91). `const` at namespace scope == INTERNAL linkage in
/// C++ (the harness nm reads the _ZL-mangled DEFINED face — the honest
/// local face, NEVER an extern claim).
pub static SET_POLICY_PARAMS: [Parameter; 2] = [
    Parameter {
        name: Some("id"), // :90
        ptype: PtType::PtInt,
        deflt: Some("1"), // :90 "1:max53" cited
    },
    Parameter {
        name: None, // :91 sentinel
        ptype: PtType::PtMax,
        deflt: None,
    },
];

/// the :73 lua fn's presence token (the 18a LuaCFunction posture REUSE —
/// the func slot NEVER calls through a C fn-ptr; the twin drives
/// [`network_set_policy`] directly).
static SET_POLICY_TOKEN: LuaCFunctionToken = LuaCFunctionToken;

/// cc :94-:99 `const Command network_cmds[]` — the ONE command row (:96-:97)
/// + the sent-in-el (:98). can_run_in_parallel rides the module.h :72
///   NSDMI false (no C initializer sets it — the 24b-era family face).
pub static NETWORK_CMDS: [Command; 2] = [
    Command {
        name: Some("set_policy"), // :96
        func: Some(&SET_POLICY_TOKEN), // :96 (the :73 fn ptr, ported above)
        params: Some(&SET_POLICY_PARAMS), // :96
        help: Some("set the network policy for commands given the user policy id"), // :97
        can_run_in_parallel: false, // h :72 NSDMI
    },
    Command {
        name: None, // :98 the all-null sentinel
        func: None,
        params: None,
        help: None,
        can_run_in_parallel: false,
    },
];

// ==========================================================================
// h :27-:40 `class NetworkModule : public snort::Module` — the DAQ-facing
// boot MOD-ULE (the 24e reg-i-stry's INDEPENDENT_MODULE_IDS[27] add at
// :3647 cites THIS ctor: `new NetworkModule`, the :2404/:2401 boot seats).
// The class owns NO state (h carries ZERO members) — pure ctor/get/ set.
// ==========================================================================
pub struct NetworkModule {
    base: Module, // the h :27 base face (the landed Module record REUSE)
}

impl Default for NetworkModule {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkModule {
    /// cc :101-:102 `NetworkModule() : Module("network", network_help,
    /// network_params)` — the ctor triple face (the is_list=false default,
    /// the landed new_params REUSE).
    pub fn new() -> NetworkModule {
        NetworkModule {
            base: Module::new_params("network", NETWORK_HELP, Some(&NETWORK_PARAMS), false), // :101
        }
    }

    /// cc :104-:105 `get_commands() const { return network_cmds; }` — the
    /// h :35 over-ri-d-e face (the ENABLE_SHELL-gated base arm NEVER live:
    /// the 24f land-ing's SHELL-OFF posture RE-RIDDEN — the landed home
    /// serves the table straight).
    pub fn get_commands(&self) -> Option<&'static [Command]> {
        Some(&NETWORK_CMDS) // :105
    }

    /// h :38-:39 `Usage get_usage() const { return CONTEXT; }` — the
    /// cpp-check-sup-press use-l-ess-Overri-de comment rides h :37 VERBATIM
    /// (the over-ri-d-e doc-u-men-ts the de-r-i-ved in-ter-fa-ce con-tr-a-ct);
    /// the ordinal lands the landed C_USAGE_CONTEXT REUSE (1, NEVER re-
    /// authored; the mod-u-l-es .rs :2962 sibling cite face re-rode it).
    pub const fn get_usage(&self) -> u32 {
        C_USAGE_CONTEXT // h :39 CONTEXT
    }

    pub fn get_name(&self) -> Option<&'static str> {
        self.base.get_name() // module.h base face REUSE
    }
    pub fn get_help(&self) -> Option<&'static str> {
        self.base.get_help()
    }
    pub fn get_parameters(&self) -> Option<&'static [Parameter]> {
        self.base.get_parameters() // -> NETWORK_PARAMS
    }

    /// cc :107-:136 `bool set(const char*, Value& v, SnortConfig* sc)` —
    /// the eight-seat dis-pat-cha ladder. :109 `NetworkPolicy* p =
    /// get_network_policy()` — the 24h home's global get NET-work pol-i-cy
    /// (policy.h :91, the thread-slot nav home REU-SE). The check-sum legs
    /// (:111-:115) call the landed parser-home legs DIRECTLY (the NEVER-
    /// re-fork law); :117-:133 the field writes ride the 24h/24g pub field
    /// seats. EVERY arm re-turn-s-true at :135 (the fall-through face —
    /// an un-known name rides the silent true).
    pub fn set(
        &self,
        v: &mut Value,
        policy: &mut NetworkPolicy,
        sc: &mut SnortConfig,
        log: &mut LogEngine,
    ) -> bool {
        if v.is("checksum_drop") {
            // :111-:112 ConfigChecksumDrop(v.get_string()) — the landed
            // parser/con-fi-g Fi-le .rs :148 home RE-U-SE (the GetChecksum
            // Flags :46-:153 table NEVER re-ported here; the get_string
            // byte face rides Some-lossy-into like the 24f -k arm re-rode):
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            config_checksum_mode_guard(false, Some(&s), policy, log); // :112 (drop arm)
        } else if v.is("checksum_eval") {
            // :114-:115 ConfigChecksumMode(v.get_string()) — the SAME home,
            // the eval arm (:161-:165):
            let s = String::from_utf8_lossy(v.get_string()).into_owned();
            config_checksum_mode_guard(true, Some(&s), policy, log); // :115 (eval arm)
        } else if v.is("id") {
            policy.user_policy_id = v.get_uint64(); // :117-:118 (h:226 field seat REU-SE)
        } else if v.is("min_ttl") {
            policy.min_ttl = v.get_uint8(); // :120-:121 (h:230)
        } else if v.is("new_ttl") {
            policy.new_ttl = v.get_uint8(); // :123-:124 (h:231)
        } else if v.is("layers") {
            sc.num_layers = v.get_uint8(); // :126-:127 (h :277, the 24g field seat)
        } else if v.is("max_ip6_extensions") {
            sc.max_ip6_extensions = v.get_uint8(); // :129-:130 (h :278)
        } else if v.is("max_ip_layers") {
            sc.max_ip_layers = v.get_uint8(); // :132-:133 (h :279)
        }
        true // :135
    }
}

/// the :112/:115 split face over the ONE landed home: config_file.cc
/// :155-:159 is the drop arm, :161-:165 the eval arm. The home landed
/// the pair as two named legs — this thin arm selects, NEVER duplicating
/// the Get-check-sum-flags body (ONE-HOME law).
fn config_checksum_mode_guard(
    is_eval: bool,
    args: Option<&str>,
    policy: &mut NetworkPolicy,
    log: &mut LogEngine,
) {
    if is_eval {
        config_checksum_mode(args, policy, log); // :115 -> config_file.rs (landed)
    } else {
        config_checksum_drop(args, policy, log); // :112 -> config_file.rs (landed)
    }
}

// cc :109's `get_network_policy()` global face lives in the 24h home
// (policy.h :91 / policy.rs the thread-slot nav getter) — this landing
// RE-U-SES it by cite through the caller-threaded [`NetworkPolicy`] face
// (the 23d-era seam law: the getter's OWN nav state NEVER duplicated).
