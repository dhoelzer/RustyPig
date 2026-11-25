//! Flat, cite-heavy literal port of row 23g:
//! `packet_io/packet_tracer_module.h` 59 L (md5 `ab0bbe5ebe247315ccf57ffeb65e6e06`) +
//! `packet_io/packet_tracer_module.cc` 262 L (md5
//! `f5b3507d8868abda27f3ce94a2af99bd`) @ fe29cbe = 321 L — THE
//! packet_tracer Module shell: the two Parameter tables (s_params :45-:54,
//! enable_packet_tracer_params :56-:68), the Command table
//! packet_tracer_cmds :70-:75, the PacketTracerDebug AnalyzerCommand pair
//! (:77-:106), the lua legs enable (:108-:205) / disable (:208-:212), and
//! the begin/set/end config-parser body (:214-:262). ZERO in-TU TEST faces
//! (the harness ground-cites the ZERO-gate pick EVERY build).
//!
//! THE LANDED-HOME REUSE faces (one-home law, NEVER re-forked; every use
//! path below is a LEGIT strict-face cite, the row-23f 13->14/17->18
//! sanction law):
//!  - the 23e `packet_constraints` home: the constraints VALUE + the
//!    set_bits mask consts (PacketTracerDebug::constraints member h-side +
//!    the enable() bit-set legs cc :137-:168);
//!  - the 23f `packet_tracer` facade home: set_constraints (:380 — the cc
//!    :101/:103 consumer target) + TraceThreadWorld::configure (:165 — the
//!    cc :257 end() consumer target);
//!  - the 19a `framework::module` home: Module base + the Parameter rows +
//!    the Command record + the LuaCFunctionToken func-pointer posture (:99,
//!    the 18a no-lua-value law this row RE-RIDES: the C lua_State legs land
//!    as the seam-arg enable_face()/disable execution, cited below);
//!  - the 19a `framework::value` home (Value::is/get_bool/get_uint8 = the cc
//!    :220-:225 body legs);
//!  - the 23c codec home C_USAGE_GLOBAL ordinal (the get_usage GLOBAL face
//!    h :52-:53);
//!  - the landed sfip `set_str` home (the cc :127/:133 set() legs, the
//!    landed SfIpRet home rides the SFIP_SUCCESS == Success ordinal 0);
//!  - the landed utils `str_to_int_vector` home (cc :141);
//!  - the landed `log::messages` LogEngine home (the LogMessage/
//!    WarningMessage capture legs, one message home).
//!
//! THE walls (harness-cited, NEVER landed): control/control.h
//! (ControlConn::query_from_lua), main/analyzer_command.h (AnalyzerCommand
//! base + main_broadcast_command), log/batched_logger.h
//! (BatchedLogManager::set_filter), the vendored-lua include face (the
//! harness re-cites the REAL luajit header tree — the chunk-era Lua seam).
//!
//! THE Rust-shape deviations (all cited in KNOWN DEVIATIONS row 23g):
//! the AnalyzerCommand/broadcast world -> the caller-threaded execution
//! face (PacketTracerDebug::execute against the 23f facade, the 23c
//! seam-param law); the lua_State args -> the 9 typed seam args + the
//! use_log_buffered bool provider (the cc :173 get_conf() read face);
//! the BatchedLogManager::set_filter static -> the row-scoped
//! BatchedFilterFace seam trait (the 23f StreamLogFace precedent; the
//! landed BatchedLogFace trait is NEVER re-opened); the h :29-:33
//! PacketTracerConfig POD + the h :56 raw-pointer member -> owned fields /
//! Option<Box<..>> (the 23a FLAT law). ZERO new allows, ZERO unsafe.
use std::borrow::Cow;

use crate::codecs::codec_module::C_USAGE_GLOBAL;
use crate::framework::codec::ip_protocol::{IpProtocol, PROTO_NOT_SET};
use crate::framework::module::{Command, LuaCFunctionToken, Module};
use crate::framework::parameter::{Parameter, Type as PtType};
use crate::framework::value::Value;
use crate::log::messages::LogEngine;
use crate::packet_io::packet_constraints::{set_bits, PacketConstraints};
use crate::packet_io::packet_tracer::{PacketTrace, TraceThreadWorld};
use crate::sfip::sf_ip::SfIp;
use crate::sfip::sf_returns::SfIpRet;
use crate::utils::cfmt::Arg;
use crate::utils::util::str_to_int_vector;

/// h :26 `#define PACKET_TRACER_NAME "packet_tracer"` — the Module name.
pub const PACKET_TRACER_NAME: &str = "packet_tracer";
/// h :27 `#define PACKET_TRACER_HELP "generate debug trace messages for packets"`.
pub const PACKET_TRACER_HELP: &str = "generate debug trace messages for packets";

/// h :41-:45 `enum PacketTraceOutput { PACKET_TRACE_CONSOLE, PACKET_TRACE_FILE }`
/// — the unscoped ordinals 0/1 (the set() switch index, cc :225-:236).
pub const PACKET_TRACE_CONSOLE: u8 = 0; // h :43
pub const PACKET_TRACE_FILE: u8 = 1;    // h :44

// ---------------------------------------------------------------------------
// cc :29-:33 `struct PacketTracerConfig { bool enabled = false; std::string
// file; }` — the POD lands verbatim (the harness FACE-A pins the layout).
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Default)]
pub struct PacketTracerConfig {
    pub enabled: bool,   // h :31
    pub file: String,    // h :32
}

// ---------------------------------------------------------------------------
// cc :45-:54 `static const Parameter s_params[]` — enable PT_BOOL deflt
// "false" (:47-:48), output PT_ENUM deflt "console" (:50-:51, the C range
// "console | file" rides the cite face — the landed Parameter carrier has
// NO range slot, the 23c parameter.rs face), sentinel (:53).
// ---------------------------------------------------------------------------
pub static S_PARAMS: [Parameter; 3] = [
    Parameter { name: Some("enable"), ptype: PtType::PtBool, deflt: Some("false") }, // :47
    Parameter { name: Some("output"), ptype: PtType::PtEnum, deflt: Some("console") }, // :50 (range "console | file" cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                     // :53
];

/// cc :56-:68 `static const Parameter enable_packet_tracer_params[]` — the
/// lua enable() filter table: proto PT_INT range "0:255" (:58), src_ip /
/// src_port / dst_ip / dst_port / tenants / regex (:59-:64),
/// stop_after_match PT_BOOL (:65), match_count PT_INT range "1:max32"
/// deflt "1" (:66), sentinel (:67). The range/help STRINGS ride cites ONLY
/// (the landed Parameter-shape law, 23c).
pub static ENABLE_PACKET_TRACER_PARAMS: [Parameter; 10] = [
    Parameter { name: Some("proto"), ptype: PtType::PtInt, deflt: None },        // :58 (range "0:255" cited)
    Parameter { name: Some("src_ip"), ptype: PtType::PtString, deflt: None },    // :59
    Parameter { name: Some("src_port"), ptype: PtType::PtInt, deflt: None },     // :60
    Parameter { name: Some("dst_ip"), ptype: PtType::PtString, deflt: None },    // :61
    Parameter { name: Some("dst_port"), ptype: PtType::PtInt, deflt: None },     // :62
    Parameter { name: Some("tenants"), ptype: PtType::PtString, deflt: None },   // :63
    Parameter { name: Some("regex"), ptype: PtType::PtString, deflt: None },     // :64
    Parameter { name: Some("stop_after_match"), ptype: PtType::PtBool, deflt: None }, // :65
    Parameter { name: Some("match_count"), ptype: PtType::PtInt, deflt: Some("1") },  // :66 (range "1:max32" cited)
    Parameter { name: None, ptype: PtType::PtMax, deflt: None },                 // :67
];

/// cc :42-:43 the two lua fns forward-declared; the 18a LuaCFunctionToken
/// posture RE-RIDDEN (no lua_State value exists in the Rust tree): the
/// func slots ride PRESENCE tokens whose bodies are the ported
/// enable_face()/disable_execute below (the const table NEVER calls through
/// a C fn-ptr; the twin drives the ported fns directly).
static LUA_ENABLE_TOKEN: LuaCFunctionToken = LuaCFunctionToken;
static LUA_DISABLE_TOKEN: LuaCFunctionToken = LuaCFunctionToken;

/// cc :70-:75 `static const Command packet_tracer_cmds[]` — enable ->
/// enable (:72, params -> enable_packet_tracer_params), disable -> disable
/// (:73, params null), sentinel (:74). can_run_in_parallel rides the
/// module.h :72 default false on every row (no C initializer sets it).
pub static PACKET_TRACER_CMDS: [Command; 3] = [
    Command {
        name: Some("enable"),                            // :72
        func: Some(&LUA_ENABLE_TOKEN),                   // :72 (the enable fn-ptr, ported below)
        params: Some(&ENABLE_PACKET_TRACER_PARAMS),      // :72
        help: Some("enable packet tracer debugging"),    // :72
        can_run_in_parallel: false,                      // h :72 NSDMI
    },
    Command {
        name: Some("disable"),                           // :73
        func: Some(&LUA_DISABLE_TOKEN),                  // :73 (the disable fn-ptr)
        params: None,                                    // :73 (C nullptr range)
        help: Some("disable packet tracer"),             // :73
        can_run_in_parallel: false,                      // h :72
    },
    Command {
        name: None, func: None, params: None, help: None, can_run_in_parallel: false, // :74
    },
];

// ---------------------------------------------------------------------------
// cc :77-:106 `class PacketTracerDebug : public AnalyzerCommand` — the
// constraints snapshot + the execute leg that aims it at the landed 23f
// facade. The C AnalyzerCommand base + main_broadcast_command + ControlConn
// ride NOT-landed walls (deviation cited): the Rust face lands the data +
// execute against the caller-threaded facade Option (the C s_pkt_trace
// null-arm, cc-side tr.cc :234-:236 early return, RE-RIDDEN through the
// 23f set_constraints body which owns that arm).
// ---------------------------------------------------------------------------
pub struct PacketTracerDebug {
    constraints: Option<PacketConstraints>, // :85 `PacketConstraints constraints;` + :86 enable bool fused by the cs-null law (cited: the C copy runs ONLY when cs != nullptr, so Option IS the enable face)
}

impl PacketTracerDebug {
    /// cc :89-:96 ctor: `if (cs) { constraints = *cs; enable = true; }` —
    /// the null-cs face leaves the cold zero face (enable=false, the
    /// constraints member default).
    pub fn new(cs: Option<&PacketConstraints>) -> Self {
        PacketTracerDebug { constraints: cs.cloned() } // :91-:95
    }

    /// cc :98-:106 execute: enable -> set_constraints(&constraints) else
    /// set_constraints(nullptr) (`return true` at :105). The 23f facade
    /// owns the null-arm LogMessage + shell-off legs (cc :237-:241 there).
    pub fn execute(&self, tracer: Option<&mut PacketTrace>, log: &mut LogEngine) -> bool {
        if let Some(t) = tracer {
            // :100-:103 — the &constraints vs nullptr split lands through
            // self.constraints.as_ref() (Some cs rode Some constraints).
            if self.constraints.is_some() {
                t.set_constraints(self.constraints.as_ref(), log); // :101
            } else {
                t.set_constraints(None, log);                     // :103
            }
        }
        // NOTE the null-tracer leg types nothing else: the C static-leg
        // face reaches tr.cc :234-:236 `if (!s_pkt_trace) return;` = NO
        // log, NO state change; the parameter stays read-trivially (the
        // 23c seam-param law — the provider arrives caller-threaded).
        true // :105
    }

    /// cc :82 `stringify() override { return "PACKET_TRACER_DEBUG"; }`
    /// — both enable and disable broadcasts ride this SAME string (the
    /// harness D14 capture face).
    pub fn stringify(&self) -> &'static str {
        "PACKET_TRACER_DEBUG" // :82
    }
}

// ---------------------------------------------------------------------------
// The row-scoped BatchedLogger filter seam (batched_logger.h NEVER landed
// — THE wall; the cc :202 `BatchedLogger::BatchedLogManager::set_filter
// (filter_str)` static leg). The 23f landed BatchedLogFace is NEVER
// re-opened (frozen home): the set_filter static lands as THIS row-scoped
// trait (the StreamLogFace precedent law).
// ---------------------------------------------------------------------------
pub trait BatchedFilterFace {
    fn set_filter(&mut self, filter: &str); // cc :202 (the "" cleared face rides)
}

/// cc :108-:119 the lua-arg read face (the luaL_opt* defaults pinned as
/// Rust-level constants the caller mirrors: proto/sport/dport default 0,
/// match_count default 1, the strings default nullptr,
/// stop_after_match default false — lua's own `luaL_opt(L,lua_toboolean,8,
/// false)` :118). Clone rides the twin's ladder arms (the C body mutates
/// the local arg copy face).
#[derive(Clone)]
pub struct LuaEnableArgs {
    pub proto: i32,                    // :110 luaL_optint(L, 1, 0) (the C int face)
    pub sip: Option<String>,           // :111 luaL_optstring(L, 2, nullptr)
    pub sport: i32,                    // :112 luaL_optint(L, 3, 0)
    pub dip: Option<String>,           // :113 luaL_optstring(L, 4, nullptr)
    pub dport: i32,                    // :114 luaL_optint(L, 5, 0)
    pub tenants: Option<String>,       // :116 luaL_optstring(L, 6, nullptr)
    pub regex: Option<String>,         // :117 luaL_optstring(L, 7, nullptr)
    pub stop_after_match: bool,        // :118 luaL_opt...false
    pub match_count: i32,              // :119 luaL_optint(L, 9, 1)
}

/// THE cc :145 proto gate in the C cast posture: `(IpProtocol)proto <
/// PROTO_NOT_SET` casts through the uint8_t underlying face
/// (protocol_ids.h :54 `enum class IpProtocol : std::uint8_t`) — the
/// wrap face proto=300 -> 44 is WELL-DEFINED and harness-pinned (D8), the
/// literal never read raw.
pub fn ip_protocast_bits(proto: i32) -> IpProtocol {
    proto as IpProtocol // :145 (IpProtocol)proto (the fixed uint8_t face: gcc's mod-256 low-byte conversion — Rust's i32->u8 cast is the IDENTICAL wrapping arithmetic, signed legs included; the D4 face proto=300 -> 44)
}

/// cc :108-:205 `static int enable(lua_State*)` — the full constraint-
/// builder leg, seam-shaped (deviation cited): the provider param
/// `use_log_buffered` = the cc :173 `SnortConfig::get_conf()->
/// use_log_buffered()` read face (the landed provider-param law, 23c);
/// the side-effect legs land as outputs: the returned constraints +
/// the filter string written to the batched seam + the LogEngine captures.
/// The cc :203 broadcast leg lands in the caller (the twin drives
/// PacketTracerDebug::new(Some(&cs))).
pub fn enable_face(
    a: &LuaEnableArgs,
    use_log_buffered: bool,
    log: &mut LogEngine,
    batched: &mut dyn BatchedFilterFace,
) -> (PacketConstraints, String) {
    let mut sip = SfIp::new(); // :121 SfIp sip, dip (:122-:123 clear() = the zero ctor face)
    let mut dip = SfIp::new();

    if let Some(s) = a.sip.as_deref()
        && sip.set_str(s) != SfIpRet::Success
    {
        // :127-:129 the SFIP_SUCCESS != set face (landed ordinal Success=0)
        log.log_message_stdout(
            "Invalid source IP address provided: %s\n",
            &[Arg::S(Some(Cow::Borrowed(s)))],
        );
    }
    if let Some(s) = a.dip.as_deref()
        && dip.set_str(s) != SfIpRet::Success
    {
        log.log_message_stdout(
            "Invalid destination IP address provided: %s\n",
                &[Arg::S(Some(Cow::Borrowed(s)))],
        ); // :133-:134
    }

    let mut constraints = PacketConstraints::default(); // :137 PacketConstraints constraints = {}

    if let Some(t) = a.tenants.as_deref() {
        constraints.tenants = str_to_int_vector(t, b','); // :141 (landed home; C default delim ',')
        constraints.set_bits |= set_bits::TENANT;         // :142
    }

    let cast = ip_protocast_bits(a.proto);               // :145 (IpProtocol)proto
    if a.proto != 0 && cast < PROTO_NOT_SET {            // :145 `if (proto and ... < PROTO_NOT_SET)`
        constraints.ip_proto = cast;                     // :147
        constraints.set_bits |= set_bits::IP_PROTO;      // :148
    }

    if sip.is_set() {
        constraints.src_ip = sip;                        // :153
        constraints.set_bits |= set_bits::SRC_IP;        // :154
    }
    if dip.is_set() {
        constraints.dst_ip = dip;                        // :159
        constraints.set_bits |= set_bits::DST_IP;        // :160
    }

    constraints.src_port = a.port_wrap(a.sport);         // :163 (the C int -> uint16_t conversion face: the PARAMETER range "0:65535" validates upstream; the conversion ITSELF wraps mod 2^16 — the faithful law, cited deviation vs a saturating guess)
    constraints.dst_port = a.port_wrap(a.dport);         // :164
    if a.sport != 0 {
        constraints.set_bits |= set_bits::SRC_PORT;      // :165-:166
    }
    if a.dport != 0 {
        constraints.set_bits |= set_bits::DST_PORT;      // :167-:168
    }

    // :170-:200 the regex/use_log_buffered ladder.
    let mut filter_str: String = a.regex.clone().unwrap_or_default(); // :170
    if !filter_str.is_empty() {
        if !use_log_buffered {
            // :173-:180 the cold-face warning trio + the cleared filter
            log.log_message_stdout(
                "WARNING: Regex filtering requires log_buffered to be enabled.\n",
                &[],
            ); // :175
            log.log_message_stdout(
                "         Continuing with packet tracer but ignoring regex filter.\n",
                &[],
            ); // :176
            log.log_message_stdout(
                "         To enable regex filtering, add 'log_buffered = true' to output configuration.\n",
                &[],
            ); // :177
            filter_str.clear();                          // :179
        } else {
            if a.stop_after_match {
                // :183-:196 the 1..=20 clamp ladder (the PARAMETER says
                // "1:max32" but the CLAMP says 20 — the disk face wins,
                // cited honestly):
                let mut mc = a.match_count; // local copy, C mutates the arg
                if mc < 1 {
                    log.log_message_stdout(
                        "WARNING: Invalid match_count (%d). Must be a number between 1 and 20. Using default of 1.\n",
                        &[Arg::I(mc as i64)],
                    ); // :187
                    mc = 1;                              // :188
                } else if mc > 20 {
                    log.log_message_stdout(
                        "WARNING: Invalid match_count (%d). Must be a number between 1 and 20. Using max limit of 20.\n",
                        &[Arg::I(mc as i64)],
                    ); // :192
                    mc = 20;                             // :193
                }
                filter_str = format!("Y:{}:{}", mc, filter_str); // :195
            } else {
                filter_str = format!("N{}", filter_str); // :198
            }
        }
    }

    batched.set_filter(&filter_str);                     // :202
    (constraints, filter_str)                            // :203 rides in the caller's broadcast leg
}

impl LuaEnableArgs {
    /// the :163-:164 int -> uint16_t member store face: the C conversion
    /// wraps mod 2^16 (gcc's well-defined face); the Rust `as u16` cast is
    /// the SAME mod-2^16 arithmetic — the conversion face lands faith-
    /// fully (the PARAMETER range arms live in the parse layer upstream,
    /// NEVER here).
    fn port_wrap(&self, p: i32) -> u16 {
        p as u16
    }
}

// ---------------------------------------------------------------------------
// h :35-:57 `class PacketTracerModule : public Module` — the body
// :214-:262. get_usage() h :52-:53 GLOBAL rides the landed C_USAGE_GLOBAL
// ordinal (codec_module.rs :273 cite face).
// ---------------------------------------------------------------------------
pub struct PacketTracerModule {
    pub base: Module,                       // :215 Module(NAME, HELP, s_params)
    config: Option<Box<PacketTracerConfig>>, // h :56 `PacketTracerConfig* config = nullptr`
}

impl Default for PacketTracerModule {
    fn default() -> Self { PacketTracerModule::new() } // the C default-ctor face (clippy honest)
}

impl PacketTracerModule {
    /// cc :214-:216 `PacketTracerModule::PacketTracerModule() :
    /// Module(PACKET_TRACER_NAME, PACKET_TRACER_HELP, s_params) {}` (the
    /// module.cc :65-:70 params ctor, is_list=false NSDMI face).
    pub fn new() -> Self {
        PacketTracerModule {
            base: Module::new_params(
                PACKET_TRACER_NAME,
                PACKET_TRACER_HELP,
                Some(&S_PARAMS),
                false,
            ), // :215
            config: None, // h :56 nullptr NSDMI
        }
    }

    /// h :52-:53 `Usage get_usage() const { return GLOBAL; }` — the C
    /// Usage enum GLOBAL ordinal 0 == the landed C_USAGE_GLOBAL.
    pub fn get_usage() -> u32 {
        C_USAGE_GLOBAL // :53
    }

    /// h :47 `get_commands() const` -> cc :242-:245: return the table.
    pub fn get_commands(&self) -> Option<&'static [Command]> {
        Some(&PACKET_TRACER_CMDS) // :244
    }

    /// cc :247-:252 begin: `assert(!config); config = new
    /// PacketTracerConfig; return true;` — the C assert maps to
    /// debug_assert! (the NDEBUG arm +0 observable, the 21b precedent).
    pub fn begin(&mut self, fqn: &str, idx: i32, _sc: ()) -> bool {
        let _ = (fqn, idx);
        debug_assert!(self.config.is_none()); // :249
        self.config = Some(Box::new(PacketTracerConfig::default())); // :250
        true // :251
    }

    /// cc :218-:240 set: `v.is("enable")` -> get_bool (:220-:221);
    /// `v.is("output")` -> the get_uint8 switch: CONSOLE -> "-", FILE ->
    /// "packet_trace.txt", default -> false (:223-:238); fall-through
    /// return true (:239). The config null-deref face (C derefs
    /// config unguarded — a begin-less set is UB): the port lands
    /// debug_assert!(config.is_some()) mapping the C contract (cited
    /// deviation, the harness NEVER drives a null-config set).
    pub fn set(&mut self, fqn: &str, v: &mut Value, _sc: ()) -> bool {
        let _ = fqn;
        // :221/:223 the C unguarded-deref face: config is NEVER null in
        // the begin()-first contract (the harness NEVER drives a null-set);
        // the null arm lands as honest false (NEVER-invent-panic law).
        let Some(config) = self.config.as_mut() else { return false };
        if v.is("enable") {
            config.enabled = v.get_bool(); // :221
        } else if v.is("output") {
            match v.get_uint8() {
                PACKET_TRACE_CONSOLE => config.file = "-".to_string(),        // :227-:229
                PACKET_TRACE_FILE => config.file = "packet_trace.txt".to_string(), // :231-:233
                _ => return false,                                            // :235-:236
            }
        }
        true // :239
    }

    /// cc :253-:262 end: `if (config) { PacketTracer::configure(
    /// config->enabled, config->file); delete config; config = nullptr; }`
    /// — the configure consumer targets the LANDED 23f
    /// TraceThreadWorld::configure home (world = the cc thread-static face
    /// under the 23f owned-split law); the null face returns true without
    /// touching the world.
    pub fn end(&mut self, fqn: &str, idx: i32, world: &mut TraceThreadWorld, _sc: ()) -> bool {
        let _ = (fqn, idx);
        if let Some(c) = self.config.take() { // :255-:259 (take() == the delete+nullptr pair, one face)
            world.configure(c.enabled, &c.file); // :257 (the landed 23f home, one home)
        }
        true // :261
    }
}
