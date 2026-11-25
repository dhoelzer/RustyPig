//! Flat, cite-heavy literal port of row 23h:
//! `packet_io/active.h` 240 L (md5 `ce6085794642721562df16740895a08a`) +
//! `packet_io/active.cc` 1074 L (md5 `3a2a2380073775c90383a9c41ead2282`)
//! @ fe29cbe = 1314 L — THE Active packet-verdict/response manager: the
//! h rides the DECLs + the inline getters/setters (the WHOLE public
//! surface: `get_action`/`get_status`/`can_act`/`get_action_string`/
//! `get_delayed_action_string`/`block_again`/`reset_again`/`set_trust`/
//! `set_allow`/`packet_was_dropped`/`packet_would_be_dropped`/
//! `can_partial_block_session` + the private fields h :213-:226 + the
//! `Counts` struct h :41-:50 + the 4 `: uint8_t` enums h :52-:65 + the
//! `ActiveSuspendContext` RAII h :229-:236) and the cc carries every
//! function body: the `kill_session` switch, the `thread_init` clamp
//! ladder, `thread_term`, the `add_trace_log` trio+payload faces + the
//! FOUR `add_*_trace_log` string pins, `send_reset` (loop + direct-inject
//! branch + the pure `Strafe` byte-exact), `send_unreach`, `send_data`
//! (the whole long body: RST_SRVR arm, the do/while blen loop with the C
//! `while (blen -= toSend)` unsigned decref, the FIN +1, the RST_CLNT
//! arm), `inject_data`, `is_reset_candidate` (TH_RST REUSE),
//! `is_unreachable_candidate`, `cant_drop` escalation,
//! `update_status_actionable`, `suspend`/`is_suspended`/`resume`,
//! `get_whd_reason_from_suspend_reason` full map, `update_status`,
//! `daq_update_status`, `drop_packet`, `daq_drop_packet`,
//! `rewrite_packet`, `retry_packet` (pool heuristic + the landed
//! retries_dropped bump), `hold_packet`, `cancel_packet_hold`,
//! `trust_session`, the `block_session` overload pair, the
//! `reset_session` pair, the queue priority law, the
//! `set_delayed_action` pair, `apply_delayed_action`, `open`/`close`
//! (eth-vs-ip arm, `strcasecmp("ip")` face), `reset`, `clear_queue`,
//! `execute`, `set_default_drop_reason`, `map_drop_reason_id`,
//! `set_drop_reason`, `get_drop_reason_id`, `send_reason_to_daq`.
//! ZERO allows, ZERO unsafe.
//!
//! THE LANDED-HOME REUSE faces (one-home law, NEVER re-forked; every use
//! path below is a legit strict-face cite):
//!  - the 23a `sfdaq` home: `DAQ_SUCCESS` (:60) + `DAQ_ERROR` (:63), the sfdaq inject/can_* /forwarding_packet C faces (cc
//!    :364-:397 -> the landed wrappers :557/:608/:611/:614/:625 — the
//!    Active TU reaches them through the landed `SFDaq` handle leg on
//!    the row context below, the C file-static call shape kept); the
//!    per-packet DAQ legs (the DIRECT_INJECT ioctls, pool/batch, the
//!    verdict reason) ride the row-scoped io seam (DEV-020).
//!  - the 23b `sfdaq_instance` home: the DIOCTL ordinal family (:170-:173
//!    — the DIRECT_INJECT ordinals are the two MISSING slots, landed here
//!    row-scoped with the api enum cite), landed `set_packet_verdict_reason`
//!    (:1147), the pool/batch getters (:743/:746), landed `retries_dropped`
//!    field (:226) + the landed DAQ_STATS home (:240-:264);
//!  - the 23f `packet_tracer` home: `PacketTrace::is_active` (:298) +
//!    `log` (:545) — the pt-racer-pull-through legs the add_trace_log legs
//!    call through (the h-side static call sites land as the landed
//!    instance threaded via the row context — DEV-011);
//!  - the landed `codecs::cd_tcp::TH_RST` (cd_tcp.rs:248) + landed
//!    `PKT_TYPE__TCP` (cd_tcp.rs:384) + the cd_tcp.rs:130-:141
//!    CITE-NEVER-LAND encode law (same law this row rides for the
//!    packet_manager encode trio — DEV-010);
//!  - the landed `log::messages` home: `parse_warning` (:203), `WARN_DAQ`
//!    (:27), the `Fatal` enum (:73-:79) + `fatal_error` (:317) — the
//!    FatalError->Err law the trough home set (trough.rs:29, :382-:387);
//!  - the landed `framework::codec` EncodeFlags family (:67-:81) and the
//!    landed `framework::counts::PegCount` (:20);
//!  - the landed `file_api::file_cache::PKT_RETRANSMIT` (:242);
//!  - HISTORY CITE (left UNTOUCHED per the row law): the earlier consumer
//!    at file_api/file_cache.rs:191-:200 copied the `active.h:64` ACT_*
//!    u8 consts before the owner pair landed; the OWNER enum now lands
//!    HERE (h :64-:65, `: uint8_t` discriminants) and that copy rides as
//!    history — NEVER re-forked a second time, NEVER edited there.
//!
//! THE C TU world the pair includes — active.cc :28-:43 — maps to the use
//! paths below: the stream/detection/dnet worlds were NEVER landed and
//! ride harness seams (DEV-009/DEV-012); the SnortConfig fields the pair
//! reads (snort_config.h:286/:291/:539/:542/:547/:555) have NO landed
//! face — the landed `parser::parse_conf::SnortConfig` carries neither
//! respond_attempts nor respond_device nor read_mode nor any ips_* mode
//! face (grep-verified at the row): the config read is a MINIMAL CITED
//! READ TRAIT here, LEFT-OPEN named at DEV-006.
//!
//! THE Rust-shape deviations (all cited by number below; the sections are
//! banked in KNOWN DEVIATIONS.md at the row):
//!   DEV-001 the `active_action.h` `ActionPriority` enum (:30-:38) + the
//!     `ActiveAction` base class (:45-:58) have NO landed home in this
//!     repo (the landed `framework::ips_action::IpsActionPriority` :26 is
//!     a DIFFERENT vocabulary — NEVER re-forked/confused); landed here
//!     first, class -> trait shape.
//!   DEV-002 the C++ raw-pointer action slot (`*p->action`) -> owned
//!     handle legs (`clone_action`, swap-out install/read legs).
//!   DEV-003 the C `struct Packet` legs the pair reads/mutates (active
//!     ptr, flow ptr, daq ptr + ioctls, ptrs.tcph, packet_flags,
//!     disable_inspect, context->conf reads) -> `ActivePacketFace` /
//!     `ActiveFlowFace` harness legs + context-paired reads.
//!   DEV-004 `drop_reason` (C raw first-wins `const char*`, h :217, set
//!     cc :1050-:1054) -> `Option<&'static str>`.
//!   DEV-005 `delayed_reject` (C raw `ActiveAction*`, h :226) ->
//!     `Option<&'static dyn ActiveActionFace>` (static-instance lifetime
//!     law; the C `static ResetAction default_reset` cc :85 rides the
//!     landed `DEFAULT_RESET` static below).
//!   DEV-006 the file-statics (THREAD_LOCAL s_attempts/s_suspend/
//!     s_suspend_reason/active_counts/s_link/s_ipnet/s_send cc :72-:83 +
//!     the globals default_reset/default_drop_reason_id/drop_reason_id_map
//!     cc :85-:88) -> ONE caller-owned `ActiveWorld` struct (the
//!     TraceThreadWorld shape law from the 23f packet_tracer home) + the
//!     `ActiveCtx` face bundle; the config read = the row-scoped
//!     `ActiveConfigReadFace` citing snort_config.h:286/:291/:539/:542/
//!     :547/:555 — LEFT-OPEN (grep-verified: NO landed face fields; the
//!     sfdaq.rs:446-:451 caller-bool precedent).
//!   DEV-007 the `send_t` function-pointer seam (cc :78-:83, default
//!     `SFDAQ::inject`) -> `SendKind` tag on the world + the fn-ptr
//!     arms dispatching in `send_via` (the three arms need world/handle
//!     capture, unrepresentable as a bare C fn pointer; the typedef
//!     DECL rides the cite at the world field).
//!   DEV-008 `FatalError` -> emit-then-`Err(Fatal)` (trough.rs:29 /
//!     :382-:387 + messages.rs:11 law).
//!   DEV-009 the libdnet wall (eth_t/ip_t/eth_open/eth_send/eth_close/
//!     ip_open/ip_send/ip_close, utils/dnet_header.h cc :37) -> the
//!     row-scoped Dnet seam traits, LEFT-OPEN provider.
//!   DEV-010 the packet_manager encode trio `encode_response`/
//!     `encode_reject`/`encode_get_max_payload` (packet_manager.h:105-:116)
//!     = CITE-NEVER-LAND provider seam (the cd_tcp.rs:130-:141 law names
//!     the same left-open encoder; the real bodies live protocols/
//!     packet_manager.cc, NEVER in scope): the row-scoped
//!     `ActiveEncodeFace` models the legs, `TcpResponse` :41-:46 +
//!     `UnreachResponse` :48-:53 DECL land (header enums the TU uses),
//!     the `plen` out-arg legs fold into the returned-slice length.
//!   DEV-011 the C static call sites `PacketTracer::is_active()`/
//!     `PacketTracer::log(...)` (the sf pt-racer family wall) -> the landed
//!     `PacketTrace` instance methods threaded via the context.
//!   DEV-012 the Stream statics (`block_flow` stream.h:154, `drop_flow`
//!     :150, `init_active_response` :192) + the DetectionEngine statics
//!     (`disable_all` detection_engine.h:105, `clear_replacement` :90) =
//!     never-landed walls -> row-scoped seam traits.
//!   DEV-013 `get_active_counts()` (cc :90-:91) returns the C
//!     `reinterpret_cast<PegCount*>` flat walk -> the port returns the
//!     owned `&ActiveCounts` struct face (7 PegCount fields, h :43-:49;
//!     consumers walk the named fields per the sfdaq_module.rs:560-:596
//!     precedent).
//!   DEV-014 the private `block_session(const Packet*, ActiveActionType,
//!     bool)` DECL (h :207): the owner TU carries NO definition at this
//!     revision (grep: exactly one definition, cc :867, for the PUBLIC
//!     overload) — Rust has no overloading, so the private pair port lands
//!     RENAMED `block_session_tagged`, the h :207 DECL ported as a
//!     documented UNREACHABLE arm (the C link-error face on any call).
//!   DEV-015 `assert(...)` -> `debug_assert!` (the NDEBUG-elision law,
//!     module.rs:831 + survivor_flow_data.rs:25-:31 precedents).
//!   DEV-016 the `#ifndef REG_TEST` arm (cc :208-:210, the `s_attempts =
//!     0` store): the production (non-REG_TEST) arm lands, the test-build
//!     preprocessor arm rides the cite ONLY.
//!   DEV-017 the two string getters `get_action_string`/
//!     `get_delayed_action_string` (h :98-:102) index `act_str[ACT_MAX]
//!     [AST_MAX]` = row/col OUTSIDE the 8x4 table under the NSDMI cold
//!     face (h :222-:225 seed ACT_MAX/AST_MAX): C is UB there; the safe
//!     face returns `Option<&'static str>` (the in-table 32 cells are
//!     NEVER null in C).
//!   DEV-018 the h-side default arguments (h :92/:104/:106/:108/:113-:116/
//!     :179-:207 `= false` etc.) are C++ call-site sugar; every port leg
//!     makes the `force`/`flags`/`reject` arg explicit.
//!   DEV-019 `thread_init` lands `Result<bool, Fatal>` because the open()
//!     leg can reach the FatalError->Err arm (DEV-008) inside the cc
//!     :201-:212 ladder.
//!   DEV-020 the retry/hold pool heuristics (cc :800-:807, :825-:830) ride
//!     the row-scoped io seam Option leg (the cc :800
//!     `p->daq_instance ? : SFDAQ::get_local_instance()` selector + the
//!     landed SFDAQInstance getters :743/:746 behind it — the 23c
//!     seam-param law) and `daq_stats.retries_dropped++` (cc :805) bumps
//!     the landed `retries_dropped` field (sfdaq_instance.rs:226) through
//!     the ctx leg (DEV-024).
//!   DEV-021 `ActiveSuspendContext` holds a `&mut ActiveWorld` re-borrow
//!     so the Drop-side `resume()` (h :234-:235) reaches the file-
//!     statics world (the C RAII object itself carries no fields).
//!   DEV-022 the `p->active->kill_session(p, ...)` back-pointer shape
//!     (cc :56, :162) ports as a packet-face `kill_session` leg the
//!     PROVIDER implements over its stored `Active` (the Rust borrow law;
//!     the REAL landed body is `Active::kill_session` right here).
//!   DEV-023 the `send_data` C param locals `buf`/`blen` walk (the C
//!     pointer bump :496 + the `while (blen -= toSend)` unsigned decref
//!     :498) port as a re-sliced `&[u8]` walk + a mirrored `u32` local
//!     subtracted EXACTLY as C (toSend is clamped by the min at :474 so
//!     the decref NEVER wraps in either language — cited at the leg).
//!   DEV-024 the DAQ_STATS thread_local HOME (sfdaq_instance.rs:240-:242)
//!     is FROZEN at 23b (its interior-Cell mut face covers ONLY
//!     expected_flows, :236-:239 — the frozen-struct law NEVER re-opens
//!     it); the cc :805 bump therefore rides an explicit `&mut DAQStats`
//!     leg on the row ctx (the landed type, never re-forked).
use std::borrow::Cow;
use std::collections::HashMap;

use crate::codecs::cd_tcp::{PKT_TYPE__TCP, TH_RST};
use crate::file_api::file_cache::PKT_RETRANSMIT;
use crate::framework::codec::{
    EncodeFlags, ENC_FLAG_FWD, ENC_FLAG_ID, ENC_FLAG_RAW, ENC_FLAG_RST_CLNT, ENC_FLAG_RST_SRVR,
    ENC_FLAG_SEQ, ENC_FLAG_VAL,
};
use crate::framework::counts::PegCount;
use crate::log::messages::{Fatal, LogEngine, WARN_DAQ};
use crate::packet_io::packet_tracer::PacketTrace;
use crate::packet_io::sfdaq::{DAQ_ERROR, DAQ_SUCCESS, SFDaq};
use crate::packet_io::sfdaq_instance::DAQStats;
use crate::utils::cfmt::Arg;

/// cc :47 `#define MAX_ATTEMPTS 20` — the thread_init clamp ceiling.
pub const MAX_ATTEMPTS: u8 = 20;

/// protocols/packet.h:81 `#define PKT_IGNORE 0x00800000` — the
/// trust_session force arm (cc :855). (The PKT_RETRANSMIT sibling :82
/// rides the landed file_cache.rs:242 home — REUSE above, NEVER
/// re-forked.)
pub const PKT_IGNORE: u32 = 0x0080_0000;
/// protocols/packet.h:84 `#define PKT_USE_DIRECT_INJECT 0x04000000` —
/// `Use ioctl when injecting.` (the send_reset/send_data direct arms,
/// cc :277, :372).
pub const PKT_USE_DIRECT_INJECT: u32 = 0x0400_0000;
/// decode_data.h:45-:48 `enum class PktType : uint8_t { NONE, IP, TCP,
/// UDP, ... }` — NONE ordinal 0 (the kill_session early-return arm, cc
/// :166; the cd_tcp.rs:487 pkt_type:0 NSDMI face + the cd_ipv4.rs:221
/// landed-twin family precedent for the unlanded ordinals).
const PKT_TYPE__NONE: u8 = 0;
/// decode_data.h:45-:48 — UDP ordinal 3 (the is_unreachable_candidate
/// arm, cc :650; the same landed-twin family cite as PKT_TYPE__NONE).
const PKT_TYPE__UDP: u8 = 3;

/// api/daq_common.h:406-:421 the DIOCTL ordinal enum: DIRECT_INJECT_-
/// PAYLOAD :419 = ordinal 12, DIRECT_INJECT_RESET :420 = ordinal 13 (the
/// enum counts GET_DEVICE_INDEX=1 at :408). The landed sfdaq_instance.rs:
/// :170-:173 family carries ordinals 2/6/7/11 — these two are the
/// MISSING slots the pair names (cc :282, :387, :447, :548), landed
/// row-scoped (the one-home law never claims a NOT-landed ordinal).
pub const DIOCTL_DIRECT_INJECT_PAYLOAD: u32 = 12;
pub const DIOCTL_DIRECT_INJECT_RESET: u32 = 13;

/// api/daq_common.h:623-:625 the DAQ_DIR_* ordinals (the :625 BOTH arm
/// NEVER rides this TU): the DIOCTL_DirectInjectReset.direction field
/// (:629) and the DIOCTL_DirectInjectPayload.reverse field (:613).
pub const DAQ_DIR_FORWARD: u8 = 0;
pub const DAQ_DIR_REVERSE: u8 = 1;

/// flow.h:173-:180 `enum class FlowState : uint8_t { SETUP = 0, INSPECT,
/// BLOCK, RESET, ALLOW }` — the two ordinals the pair SETS (cc :877
/// BLOCK, cc :902 RESET). The Flow world is a NEVER-landed wall
/// (DEV-012); the ordinals land with the cite (the cd_ipv4.rs:221-family
/// unlanded-ordinal precedent).
pub const FLOW_STATE_BLOCK: u8 = 2;
pub const FLOW_STATE_RESET: u8 = 3;

// ---------------------------------------------------------------------------
// h :52-:65 — the four `: uint8_t` enums, discriminants EXACT.
// h :35 `class SO_PUBLIC Active` nests them; the Rust top-level names
// carry the C scope cite (the nested-path law).
// ---------------------------------------------------------------------------

/// h :52-:53 `enum ActiveStatus : uint8_t { AST_ALLOW, AST_CANT,
/// AST_WOULD, AST_FORCE, AST_MAX }` — "action (what to do) is separate
/// from status (whether we can actually do it or not)" (h :25-:26).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActiveStatus {
    AstAllow = 0, // h :53
    AstCant = 1,
    AstWould = 2,
    AstForce = 3,
    AstMax = 4,
}

/// h :55-:56 `enum ActiveWouldReason : uint8_t { WHD_NONE,
/// WHD_INTERFACE_IDS, WHD_IPS_INLINE_TEST, WHD_NAP_INLINE_TEST,
/// WHD_TIMEOUT, WHD_PRUNE, WHD_RELOAD, WHD_EXIT }` (the NAP arm NEVER
/// set in this TU — cited, never reached).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActiveWouldReason {
    WhdNone = 0, // h :56
    WhdInterfaceIds = 1,
    WhdIpsInlineTest = 2,
    WhdNapInlineTest = 3,
    WhdTimeout = 4,
    WhdPrune = 5,
    WhdReload = 6,
    WhdExit = 7,
}

/// h :58-:59 `enum ActiveSuspendReason : uint8_t { ASP_NONE, ASP_PRUNE,
/// ASP_TIMEOUT, ASP_RELOAD, ASP_EXIT }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActiveSuspendReason {
    AspNone = 0, // h :59
    AspPrune = 1,
    AspTimeout = 2,
    AspReload = 3,
    AspExit = 4,
}

/// h :61-:65 — the C comment rides verbatim:
/// "FIXIT-M: these are only used in set_delayed_action and
/// apply_delayed_action, in a big switch(action). Do away with these and
/// use the actual (Base)Action objects."
/// `enum ActiveActionType : uint8_t { ACT_TRUST, ACT_ALLOW, ACT_HOLD,
/// ACT_RETRY, ACT_REWRITE, ACT_DROP, ACT_BLOCK, ACT_RESET, ACT_MAX }`.
/// HISTORY (DEV-adjacent, left UNTOUCHED): an earlier consumer copied
/// these eight ordinals as u8 consts at file_api/file_cache.rs:192-:200
/// citing `active.h:64` before the owner pair landed; the OWNER enum
/// lands HERE, the old copy stays lawfully frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActiveActionType {
    ActTrust = 0, // h :65
    ActAllow = 1,
    ActHold = 2,
    ActRetry = 3,
    ActRewrite = 4,
    ActDrop = 5,
    ActBlock = 6,
    ActReset = 7,
    ActMax = 8,
}

// ---------------------------------------------------------------------------
// active_action.h :30-:38 + :40-:58 — the ActionPriority vocabulary +
// the ActiveAction base. DEV-001: NO landed home in this repo (`grep
// AP_RESET src/` = zero hits at the row); the landed framework home
// `ips_action.rs::IpsActionPriority` :26-:37 is the INTERFACE-registry
// vocabulary (Other/Log/.../Pass) — a DIFFERENT enum, NEVER conflated.
// The h :40-:44 comment rides verbatim:
// "These are injection actions (e.g. send a RST packet, or respond to a
// query with an \"Access denied\" message). Instances of this class are
// queued into the packet at inspection / detection time and executed at
// the end by Analyzer. The pure virtual exec() method can call into
// Active methods for the low-level stuff."
// ---------------------------------------------------------------------------

/// active_action.h:30-:38 `enum ActionPriority { AP_LOCAL, AP_MODIFY,
/// AP_PROXY, AP_RESET, AP_REMOTE, AP_MAX }` (plain enum, NO `: uint8_t`
/// — the C default int width rides the cite).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionPriority {
    ApLocal = 0, // :32
    ApModify = 1,
    ApProxy = 2,
    ApReset = 3,
    ApRemote = 4,
    ApMax = 5,
}

/// active_action.h:45-:58 `class SO_PUBLIC ActiveAction` -> the trait
/// shape (DEV-001 class->trait). The :48 ctor-default `AP_MAX` becomes
/// the required method (implementers name their priority like the C
/// ctor-init list does); :51 `virtual void delayed_exec(Packet*) { }`
/// carries the empty default body; :53 `ActionPriority get_action()
/// const { return action; }`; the :56 protected `action` field rides
/// each implementor. DEV-002: `clone_action` is NOT a C++ member —
/// forced by the Rust owned-handle action slot (the queue law at cc
/// :908-:912 installs by copy-of-reference where C stores the raw ptr;
/// every landed implementor is a zero-state unit, so copy == alias at
/// the observable face).
pub trait ActiveActionFace: 'static {
    /// h :53 the get_action() face;
    fn get_action(&self) -> ActionPriority;
    /// h :51 the delayed_exec() virtual (default-EMPTY body rides):
    fn delayed_exec(&mut self, _pkt: &mut dyn ActivePacketFace, _ctx: &mut ActiveCtx<'_>) {}
    /// DEV-002 (NOT-C member):
    fn clone_action(&self) -> Box<dyn ActiveActionFace>;
}

/// cc :49-:58 `class ResetAction : public snort::ActiveAction` — the cc's
/// ONLY locally-defined ActiveAction. :52 `ResetAction() :
/// ActiveAction(ActionPriority::ApReset)` — the unit shape lands
/// stateless (the ctor priority cite).
#[derive(Clone, Copy, Debug, Default)]
pub struct ResetAction; // cc :50

impl ActiveActionFace for ResetAction {
    fn get_action(&self) -> ActionPriority {
        ActionPriority::ApReset // cc :52
    }

    fn clone_action(&self) -> Box<dyn ActiveActionFace> {
        Box::new(*self) // DEV-002 (zero-state unit: copy == alias)
    }

    /// cc :54-:57 `void delayed_exec(snort::Packet* p) override {
    /// p->active->kill_session(p, ENC_FLAG_FWD); }` — the active
    /// back-pointer leg ports as the packet-face `kill_session` the
    /// provider implements over its stored `Active` (DEV-022; the REAL
    /// landed body is `Active::kill_session` below, reached through the
    /// provider's stored instance).
    fn delayed_exec(&mut self, pkt: &mut dyn ActivePacketFace, ctx: &mut ActiveCtx<'_>) {
        pkt.kill_session(
            ENC_FLAG_FWD, // cc :56 the default-flag site spelled out (DEV-018)
            ctx,
        );
    }
}

/// cc :85 `static ResetAction default_reset;` — the file-static instance
/// (NOT thread_local) landing as the static unit (DEV-006 field-home law
/// for the non-TLS globals: DEFAULT_RESET stays here, the TLS trio +
/// counts + handles + the map ride `ActiveWorld`).
pub static DEFAULT_RESET: ResetAction = ResetAction;

// ---------------------------------------------------------------------------
// h :41-:50 `struct Counts { PegCount injects; ... }` (nested in Active)
// + cc :76 `static THREAD_LOCAL Active::Counts active_counts;` — the
// counts ride ActiveWorld.active_counts (DEV-006).
// ---------------------------------------------------------------------------

/// h :41-:50 the seven PegCount legs (the landed `framework::counts::
/// PegCount` u64 home — never re-typed).
#[derive(Clone, Debug, Default)]
pub struct ActiveCounts {
    pub injects: PegCount,                 // h :43
    pub failed_injects: PegCount,          // h :44
    pub direct_injects: PegCount,          // h :45
    pub failed_direct_injects: PegCount,   // h :46
    pub holds_denied: PegCount,            // h :47
    pub holds_canceled: PegCount,          // h :48
    pub holds_allowed: PegCount,           // h :49
}

/// cc :90-:91 `PegCount* get_active_counts() { return
/// reinterpret_cast<PegCount*>(&active_counts); }` — the flat-cast walk
/// ports as the owned struct face (DEV-013; the consumer walk rides the
/// named fields per the sfdaq_module.rs:560-:596 get_counts precedent —
/// no reinterpret cast, no unsafe).
pub fn get_active_counts(world: &ActiveWorld) -> &ActiveCounts {
    &world.active_counts
}

// ---------------------------------------------------------------------------
// cc :78-:83 — the send_t function-pointer seam.
// `typedef int (* send_t) (DAQ_Msg_h msg, int rev, const uint8_t* buf,
// uint32_t len);` — the C fn-ptr DECL (its Rust shape would be
// `fn(u64, i32, &[u8], u32) -> i32`) rides the cite ONLY (DEV-007: the
// three arms need world/handle capture, unrepresentable as a bare C fn
// pointer — the runtime slot is the SendKind tag below and the arms
// dispatch in `send_via`):
/// the s_send slot (DEV-007): `Daq` = the cc :83 default
/// `s_send = SFDAQ::inject` (the landed sfdaq.rs:625 inject wrapper
/// reached through the ctx daq handle); `Eth`/`Ip` = the open() legs cc
/// :979/:989 (`s_send = send_eth` / `s_send = send_ip`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SendKind {
    /// cc :83 the file-static NSDMI face SFDAQ::inject:
    #[default]
    Daq,
    Eth, // cc :979
    Ip,  // cc :989
}

// ---------------------------------------------------------------------------
// cc :72-:88 — THE file-statics -> world-struct mapping (DEV-006; THE
// TraceThreadWorld shape law from the 23f packet_tracer home: one plain
// pub field per C thread-static, caller-owned struct, ZERO thread_local /
// static-mut / unsafe in this file):
//   cc :72 `static THREAD_LOCAL uint8_t s_attempts = 0;`
//   cc :73 `static THREAD_LOCAL bool s_suspend = false;`
//   cc :74 `static THREAD_LOCAL Active::ActiveSuspendReason
//           s_suspend_reason = Active::ASP_NONE;`
//   cc :76 `static THREAD_LOCAL Active::Counts active_counts;`
//   cc :81 `static THREAD_LOCAL eth_t* s_link = nullptr;`
//   cc :82 `static THREAD_LOCAL ip_t* s_ipnet = nullptr;`
//   cc :83 `static THREAD_LOCAL send_t s_send = SFDAQ::inject;`
//   cc :85 `static ResetAction default_reset;`  -> the landed
//          `DEFAULT_RESET` static above (NOT thread_local in C, stays a
//          static unit — DEV-005/DEV-006)
//   cc :86 `static int default_drop_reason_id = -1;`
//   cc :88 `static std::unordered_map<std::string, uint8_t>
//           drop_reason_id_map;`
// The NOT-TLS cc :86/:88 pair rides the SAME world field-home (the
// active world IS the per-thread packet-Verdict world; the C TLS/non-TLS
// split has no observable seam in this TU — cited with DEV-006).
// ---------------------------------------------------------------------------

/// the per-thread Active world (the C file-statics, DEV-006). The NSDMI
/// pin rides `new()` EXACT against the cc quotes above (NO derive: the
/// default_drop_reason_id seed is -1 per cc :86, NOT the 0 a derive
/// would mint; the Box<dyn> handle legs are NOT Debug-derivable at the
/// seam, cited):
pub struct ActiveWorld {
    pub s_attempts: u8,                    // cc :72 = 0
    pub s_suspend: bool,                   // cc :73 = false
    pub s_suspend_reason: u8,              // cc :74 = ASP_NONE ordinal 0
    pub active_counts: ActiveCounts,       // h :41-:50, cc :76
    pub s_link: Option<Box<dyn EthHandleFace>>,   // cc :81 (dnet wall, DEV-009)
    pub s_ipnet: Option<Box<dyn IpHandleFace>>,   // cc :82 (dnet wall, DEV-009)
    pub s_send: SendKind,                  // cc :83 (DEV-007)
    pub default_drop_reason_id: i32,       // cc :86 = -1
    pub drop_reason_id_map: HashMap<&'static str, u8>, // cc :88 (DEV-004 key law)
}

impl ActiveWorld {
    /// the cc :72-:88 NSDMI pins (ASP_NONE ordinal 0 per the h :59
    /// enum row; s_send Daq per cc :83; the id sentinel -1 per cc :86):
    pub fn new() -> Self {
        ActiveWorld {
            s_attempts: 0,
            s_suspend: false,
            s_suspend_reason: ASP_NONE,
            active_counts: ActiveCounts::default(),
            s_link: None,
            s_ipnet: None,
            s_send: SendKind::Daq,
            default_drop_reason_id: -1,
            drop_reason_id_map: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// h :213-:226 — the private fields + the NSDMI cold face:
//   h :214 `static const char* act_str[ACT_MAX][AST_MAX];` -> the landed
//          `ACT_STR` table below (cc :60-:70, byte-exact)
//   h :216 `int active_tunnel_bypass = 0;`
//   h :217 `const char* drop_reason = nullptr;` -> DEV-004 &'static str
//   h :219-:221 the C comment rides verbatim: "these can't be pkt flags
//        because we do the handling of these flags following all
//        processing and the drop or response may have been produced by a
//        pseudopacket." -> on the two action/status fields below
//   h :222 `ActiveStatus active_status = AST_MAX;`
//   h :223 `ActiveWouldReason active_would_reason = WHD_EXIT;`
//   h :224 `ActiveActionType active_action = ACT_MAX;`
//   h :225 `ActiveActionType delayed_active_action = ACT_MAX;`
//   h :226 `ActiveAction* delayed_reject = nullptr; // set with
//          set_delayed_action()` -> DEV-005
// The fields ride the u8 ordinal homes so EVERY C `>=`/`<`/`!` numeric
// comparison lands EXACT under the : uint8_t discriminant law (the
// enums above name the same ordinals; DEV-adjacent shape note at the
// enum heads).
// ---------------------------------------------------------------------------

/// h :53 the AST_* ordinals (u8 field home, DEV-adjacent shape law).
pub const AST_ALLOW: u8 = 0;
pub const AST_CANT: u8 = 1;
pub const AST_WOULD: u8 = 2;
pub const AST_FORCE: u8 = 3;
pub const AST_MAX: u8 = 4;

/// h :56 the WHD_* ordinals:
pub const WHD_NONE: u8 = 0;
pub const WHD_INTERFACE_IDS: u8 = 1;
pub const WHD_IPS_INLINE_TEST: u8 = 2;
pub const WHD_NAP_INLINE_TEST: u8 = 3;
pub const WHD_TIMEOUT: u8 = 4;
pub const WHD_PRUNE: u8 = 5;
pub const WHD_RELOAD: u8 = 6;
pub const WHD_EXIT: u8 = 7;

/// h :59 the ASP_* ordinals:
pub const ASP_NONE: u8 = 0;
pub const ASP_PRUNE: u8 = 1;
pub const ASP_TIMEOUT: u8 = 2;
pub const ASP_RELOAD: u8 = 3;
pub const ASP_EXIT: u8 = 4;

/// h :65 the ACT_* ordinals (the OWNER home; the frozen file_cache.rs:
/// 192-:200 copy stays history, NEVER touched):
pub const ACT_TRUST: u8 = 0;
pub const ACT_ALLOW: u8 = 1;
pub const ACT_HOLD: u8 = 2;
pub const ACT_RETRY: u8 = 3;
pub const ACT_REWRITE: u8 = 4;
pub const ACT_DROP: u8 = 5;
pub const ACT_BLOCK: u8 = 6;
pub const ACT_RESET: u8 = 7;
pub const ACT_MAX: u8 = 8;

/// cc :60-:70 `const char* Active::act_str[Active::ACT_MAX]
/// [Active::AST_MAX]` — BYTE-EXACT, all 8 x 4 = 32 cells (rows in the
/// ACT_* order, cols in the AST_* order; "error" fills the unused
/// AST_CANT/AST_WOULD/AST_FORCE arms of the four pre-rewrite rows):
pub const ACT_STR: [[&str; 4]; 8] = [
    ["trust", "error", "error", "error"],     // cc :62 (ACT_TRUST)
    ["allow", "error", "error", "error"],     // cc :63 (ACT_ALLOW)
    ["hold", "error", "error", "error"],      // cc :64 (ACT_HOLD)
    ["retry", "error", "error", "error"],     // cc :65 (ACT_RETRY)
    ["rewrite", "cant_rewrite", "would_rewrite", "force_rewrite"], // cc :66
    ["drop", "cant_drop", "would_drop", "force_drop"],             // cc :67
    ["block", "cant_block", "would_block", "force_block"],         // cc :68
    ["reset", "cant_reset", "would_reset", "force_reset"],         // cc :69
];

// ---------------------------------------------------------------------------
// the u8 field-home <-> enum-name bridges (the twins name the enum
// variants; the fields above ride the EXACT : uint8_t ordinals so every
// C numeric comparison — `>= ACT_DROP`, `< AST_CANT`, `!active_status` —
// lands literal; the From arms map the out-of-table NSDMI seeds to MAX
// with the h :222-:225 cite).
// ---------------------------------------------------------------------------

impl From<u8> for ActiveStatus {
    fn from(v: u8) -> Self {
        [ActiveStatus::AstAllow, ActiveStatus::AstCant, ActiveStatus::AstWould,
         ActiveStatus::AstForce]
            .get(v as usize).copied().unwrap_or(ActiveStatus::AstMax) // h :222 cold seed
    }
}

impl From<u8> for ActiveWouldReason {
    fn from(v: u8) -> Self {
        [ActiveWouldReason::WhdNone, ActiveWouldReason::WhdInterfaceIds,
         ActiveWouldReason::WhdIpsInlineTest, ActiveWouldReason::WhdNapInlineTest,
         ActiveWouldReason::WhdTimeout, ActiveWouldReason::WhdPrune,
         ActiveWouldReason::WhdReload]
            .get(v as usize).copied().unwrap_or(ActiveWouldReason::WhdExit) // h :223 seed
    }
}

impl From<u8> for ActiveSuspendReason {
    fn from(v: u8) -> Self {
        [ActiveSuspendReason::AspNone, ActiveSuspendReason::AspPrune,
         ActiveSuspendReason::AspTimeout, ActiveSuspendReason::AspReload]
            .get(v as usize).copied().unwrap_or(ActiveSuspendReason::AspExit)
    }
}

impl From<u8> for ActiveActionType {
    fn from(v: u8) -> Self {
        [ActiveActionType::ActTrust, ActiveActionType::ActAllow, ActiveActionType::ActHold,
         ActiveActionType::ActRetry, ActiveActionType::ActRewrite, ActiveActionType::ActDrop,
         ActiveActionType::ActBlock, ActiveActionType::ActReset]
            .get(v as usize).copied().unwrap_or(ActiveActionType::ActMax) // h :224-:225 seed
    }
}

// ---------------------------------------------------------------------------
// DEV-006 the LEFT-OPEN config READ trait: the SnortConfig legs the pair
// reads. snort_config.h:286 `uint8_t respond_attempts = 0;`, :291
// `std::string respond_device;`, :539 `bool read_mode() const`, :542
// `bool ips_inline_mode() const`, :547 `bool ips_inline_test_mode()
// const`, :555 `bool ips_passive_mode() const` (the NAP :552 + adaptor
// :561 getters NEVER ride this TU — cited, never read). The landed
// parser home (parse_conf.rs:68 SnortConfig) carries NONE of these
// (grep-verified at the row, the reload-survivor home's "NO landed
// SnortConfig type" law restated at the row): LEFT-OPEN until the
// config row lands (the sfdaq.rs:446-:451 caller-param provider
// precedent). respond_device: the C `.empty()` guards (cc :201/:204)
// land as the empty->None face.
// ---------------------------------------------------------------------------
pub trait ActiveConfigReadFace {
    fn respond_attempts(&self) -> u8;            // h :286
    fn respond_device(&self) -> Option<&str>;    // h :291 (empty -> None)
    fn read_mode(&self) -> bool;                 // h :539
    fn ips_inline_mode(&self) -> bool;           // h :542
    fn ips_inline_test_mode(&self) -> bool;      // h :547
    fn ips_passive_mode(&self) -> bool;          // h :555
}

// ---------------------------------------------------------------------------
// protocols/packet_manager.h :41-:53 — the two response-kind enums the
// pair names (header enums the TU USES land; the CITE-NEVER-LAND trio
// they index rides the DEV-010 seam below — the encoder bodies live in
// protocols/packet_manager.cc, the same left-open provider the
// cd_tcp.rs:130-:141 law names).
// ---------------------------------------------------------------------------

/// packet_manager.h:41-:46 `enum class TcpResponse { FIN, RST, PUSH }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpResponse {
    FIN = 0, // :43
    RST = 1, // :44
    PUSH = 2, // :45
}

/// packet_manager.h:48-:53 `enum class UnreachResponse { NET, HOST,
/// PORT, FWD }` (the NET/HOST arms NEVER set in this TU — cited).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnreachResponse {
    NET = 0, // :50
    HOST = 1, // :51
    PORT = 2, // :52
    FWD = 3, // :53
}

// ---------------------------------------------------------------------------
// api/daq_common.h :602-:606 / :608-:615 / :626-:630 — the direct-inject
// ioctl records the pair BUILDS (cc :280-:283, :384-:388, :440-:448,
// :546-:549): DAQ_DIPayloadSegment / DIOCTL_DirectInjectPayload /
// DIOCTL_DirectInjectReset. The `sizeof(msg)` leg (cc :283/:388/:448/
// :549) rides the provider side (the landed ioctl marshal law,
// sfdaq_instance.rs:395-:396 "the C `sizeof` rides the provider side,
// cited").
// ---------------------------------------------------------------------------

/// api/daq_common.h:602-:606 `DAQ_DIPayloadSegment { const uint8_t*
/// data; uint32_t length; }`.
#[derive(Clone, Copy, Debug)]
pub struct DaqDiPayloadSegment<'a> {
    pub data: &'a [u8], // :604
    pub length: u32,    // :605
}

/// api/daq_common.h:608-:615 `DIOCTL_DirectInjectPayload` (the :611
/// `const DAQ_DIPayloadSegment** segments` two-level array ports as the
/// slice-of-segments face; the cc :443 `payload[] = { &segments[0] }`
/// single-slot array lands as the one-element slice below, cc :444).
#[derive(Debug)]
pub struct DioctlDirectInjectPayload<'a> {
    pub msg: u64,                                            // :610
    pub segments: &'a [DaqDiPayloadSegment<'a>],             // :611
    pub num_segments: u8,                                    // :612
    pub reverse: u8,                                         // :613
}

/// api/daq_common.h:626-:630 `DIOCTL_DirectInjectReset` (the :629
/// DAQ_DIR_* direction field; the cc :281 ternary
/// `(ef & ENC_FLAG_FWD) ? DAQ_DIR_FORWARD : DAQ_DIR_REVERSE`).
#[derive(Clone, Copy, Debug)]
pub struct DioctlDirectInjectReset {
    pub msg: u64,        // :628
    pub direction: u8,   // :629
}

// ---------------------------------------------------------------------------
// DEV-010 — the packet_manager encode trio provider seam (CITE-NEVER-
// LAND law, cd_tcp.rs:130-:141 names the SAME left-open encoder world):
//   packet_manager.h:105-:107 `static const uint8_t* encode_response(
//     TcpResponse, EncodeFlags, const Packet* orig, uint32_t& len,
//     const uint8_t* const payload = nullptr, uint32_t payload_len = 0);`
//     ("Send a TCP response. ... Len will be set to the response's
//     length. payload && payload_len are optional." :102-:104 — the
//     optional legs land as the payload slice; empty = the C nullptr
//     default face DEV-018);
//   :110-:111 `encode_reject(UnreachResponse, EncodeFlags, const
//     Packet*, uint32_t& len)` ("Send an ICMP unreachable response!");
//   :116 `encode_get_max_payload(const Packet*)` ("get the max payload
//     for the current packet" :115).
// The C `uint32_t& len` out-args fold into the returned-slice length
// (DEV-010 — the cc's `plen = 0` pre-seeds (cc :403/:472/:510/:565)
// ride the cite: the out-param only ever READS after the call).
// ---------------------------------------------------------------------------
pub trait ActiveEncodeFace {
    fn encode_response(
        &mut self,
        resp: TcpResponse,
        flags: EncodeFlags,
        pkt: &dyn ActivePacketFace,
        payload: &[u8], // the C default-null pair legs (empty = nullptr)
    ) -> Option<&[u8]>;
    fn encode_reject(
        &mut self,
        resp: UnreachResponse,
        flags: EncodeFlags,
        pkt: &dyn ActivePacketFace,
    ) -> Option<&[u8]>;
    fn encode_get_max_payload(&self, pkt: &dyn ActivePacketFace) -> u16;
}

// ---------------------------------------------------------------------------
// DEV-020 — the per-packet DAQ io seam (the legs C runs on
// `p->daq_instance` — SFDAQInstance legs, NEVER reachable from the
// packet face; the landed provider legs live at
// sfdaq_instance.rs: get_pool_available :746 / get_batch_size :743 /
// set_packet_verdict_reason :1147 (the `msg, verdict_reason` shape
// :384-:385) / ioctl over DaqIoctlReq :1122). The cc :800
// `p->daq_instance ? p->daq_instance : SFDAQ::get_local_instance()`
// selector + the cc :825 `!p->daq_instance` face land as the Option
// legs (None = the C nullptr instance; sfdaq.rs:265-:268 names the
// local_instance seam law).
// ---------------------------------------------------------------------------
pub trait ActiveIoFace {
    /// cc :282-:283/:387-:388/:548-:549 `ioctl(DIOCTL_DIRECT_INJECT_-
    /// RESET, &msg, sizeof(msg))` (the ordinal const above):
    fn direct_inject_reset(&mut self, req: &DioctlDirectInjectReset) -> i32;
    /// cc :447-:448 `ioctl(DIOCTL_DIRECT_INJECT_PAYLOAD, &msg,
    /// sizeof(msg))`:
    fn direct_inject_payload(&mut self, req: &DioctlDirectInjectPayload<'_>) -> i32;
    /// cc :801 `get_pool_available() < get_batch_size()` (the selected
    /// instance pair; None = the C nullptr instance after the cc :800
    /// local-instance fallback) and cc :825-:826 (the p->daq_instance-
    /// only face — the harness provider keeps them ONE leg, cited):
    fn pool_and_batch(&self, daq_msg: u64) -> Option<(u32, u32)>;
    /// cc :1073 `p.daq_instance->set_packet_verdict_reason(p.daq_msg,
    /// reason)` (the landed shape, sfdaq_instance.rs:1147; the C int ->
    /// uint8_t IMPLICIT narrowing rides the caller, cited there):
    fn set_packet_verdict_reason(&mut self, msg: u64, verdict_reason: u8);
}

// ---------------------------------------------------------------------------
// DEV-009 — the libdnet wall (cc :37 utils/dnet_header.h; the eth_t*/
// ip_t* handles on the world :81-:82): eth_open :973, eth_send :99,
// eth_close :997, ip_open :983, ip_send :106, ip_close :1000. The
// ssize_t returns stay i64-shaped (the C `(uint32_t)sent != len`
// truncate-compare lands in the send_eth/send_ip bodies: an ssize_t of
// -1 truncates to 0xFFFFFFFF — NOT equal to a short len — cited).
// ---------------------------------------------------------------------------
pub trait DnetFace {
    fn eth_open(&mut self, dev: &str) -> Option<Box<dyn EthHandleFace>>; // cc :973
    fn ip_open(&mut self) -> Option<Box<dyn IpHandleFace>>;              // cc :983
}

/// the eth_t handle face (cc :99 eth_send, :997 eth_close):
pub trait EthHandleFace {
    fn eth_send(&mut self, buf: &[u8], len: u32) -> i64;
    fn eth_close(&mut self);
}

/// the ip_t handle face (cc :106 ip_send, :1000 ip_close):
pub trait IpHandleFace {
    fn ip_send(&mut self, buf: &[u8], len: u32) -> i64;
    fn ip_close(&mut self);
}

// ---------------------------------------------------------------------------
// DEV-012 — the never-landed Stream + DetectionEngine statics:
//   stream.h:154 `static void block_flow(const Packet*);` ("Mark flow
//   session as block pending. Resources will be released at the end of
//   inspection" :152-:153) — cc :874;
//   stream.h:150 `static void drop_flow(const Packet*);` — cc :894;
//   stream.h:192 `static void init_active_response(const Packet*,
//   Flow*);` — cc :901 (the SECOND C arg IS `p->flow` — it folds into
//   the packet leg, cited at the call site);
//   detection_engine.h:105 `static void disable_all(Packet*);` — cc :851;
//   detection_engine.h:90 `static void clear_replacement();` — cc :1021.
// ---------------------------------------------------------------------------
pub trait StreamSeam {
    fn block_flow(&mut self, pkt: &mut dyn ActivePacketFace); // stream.h:154
    fn drop_flow(&mut self, pkt: &mut dyn ActivePacketFace);  // stream.h:150
    fn init_active_response(&mut self, pkt: &mut dyn ActivePacketFace); // stream.h:192
}

pub trait DetectionSeam {
    fn disable_all(&mut self, pkt: &mut dyn ActivePacketFace); // de.h:105
    fn clear_replacement(&mut self);                          // de.h:90
}

// ---------------------------------------------------------------------------
// DEV-003 — the C `struct Packet` legs this TU reads/mutates land as
// the harness face (the protocols/packet.h world was NEVER landed; the
// DumpReadFace :203 / ConstraintPacketFace (23e) precedents named). The
// `p->active` back-pointer (the kill_session sites cc :56) rides the
// provider's stored `Active` (DEV-022). `p->context->conf` (cc :672/
// :687/:692/:873/:893) reads THROUGH the ctx conf leg — the packet-
// context pairing face.
// ---------------------------------------------------------------------------
pub trait ActivePacketFace {
    /// decode_data.h:45-:48 the PktType ordinal home (the kill_session
    /// switch cc :164, the is_unreachable_candidate arms cc :650):
    fn type_(&self) -> u8;
    /// the C inline `bool is_tcp() const` face (cc :637):
    fn is_tcp(&self) -> bool {
        self.type_() == PKT_TYPE__TCP
    }
    /// pkth->flags for the landed SFDaq::forwarding_packet leg
    /// (sfdaq.rs:557 takes the u32 flags face):
    fn pkth_flags(&self) -> u32;
    /// cc :133/:140/:146 `p->dsize`:
    fn dsize(&self) -> u32;
    /// cc :277/:372 the packet_flags word (PKT_USE_DIRECT_INJECT /
    /// PKT_RETRANSMIT / PKT_IGNORE reads + the cc :855 |= leg):
    fn packet_flags(&self) -> u32;
    fn packet_flags_bor(&mut self, mask: u32); // cc :855 `|=`
    /// the p->flow nullptr face (cc :278/:856/:876/:899/:1032):
    fn flow_present(&self) -> bool;
    /// cc :278/:373 `p->flow and p->flow->flags.use_direct_inject`
    /// (flow.h:562) — the nullptr short-circuit fused (false when
    /// flow_present() is false, cited):
    fn flow_uses_direct_inject(&self) -> bool;
    fn flow_mut(&mut self) -> Option<&mut dyn ActiveFlowFace>;
    /// cc :637/:645 `p->ptrs.tcph` present face + the th_flags leg:
    fn tcph_flags(&self) -> Option<u8>;
    /// cc :152 `ntohs(p->ptrs.tcph->th_win)` — the byte-order leg
    /// (the landed window face reads th_win at cd_icmp4_ip.rs:355
    /// u16::from_be_bytes — the REUSE cite the row carries):
    fn tcph_win(&self) -> Option<u16>;
    /// the opaque DAQ_Msg_h handle (the landed law rides u64,
    /// sfdaq_instance.rs:273-:275):
    fn daq_msg(&self) -> u64;
    /// cc :861/:879/:905 `p->disable_inspect = true`:
    fn set_disable_inspect(&mut self);
    /// the `p->action` slot legs (DEV-002 — the cc :910-:911 queue law,
    /// the cc :1020 clear, the cc :1026-:1029 execute swap):
    fn current_action_priority(&self) -> Option<ActionPriority>;
    fn install_action(&mut self, a: Box<dyn ActiveActionFace>);
    fn take_action(&mut self) -> Option<Box<dyn ActiveActionFace>>;
    fn clear_action(&mut self);
    /// DEV-022: the `p->active->kill_session(p, ...)` back-pointer
    /// (cc :56) — the provider implements it over its stored `Active`
    /// whose REAL body is `Active::kill_session` below:
    fn kill_session(&mut self, flags: EncodeFlags, ctx: &mut ActiveCtx<'_>);
}

/// the `p->flow` legs (flow.h — the never-landed flow world, DEV-003/
/// DEV-012): :447 trust() (cc :858/:1036), :439 stop_deferring_trust()
/// (cc :859), :436 try_trust() (cc :863), :314 set_state(FlowState)
/// (cc :877/:902), :442 finalize_trust(Active&) (cc :1034).
pub trait ActiveFlowFace {
    fn trust(&mut self);
    fn stop_deferring_trust(&mut self);
    fn try_trust(&mut self) -> bool;
    fn set_state(&mut self, state: u8); // the FLOW_STATE_* ordinals
    fn finalize_trust(&mut self, active: &mut Active);
}

// ---------------------------------------------------------------------------
// DEV-006/DEV-011 — the bundle the statics-replacing legs thread: the
// world + the landed homes (SFDaq :256, DAQStats the landed 22-field
// type :207 — cc :805 `daq_stats.retries_dropped++` bumps the landed
// `retries_dropped` field :226 through this leg; the landed DAQ_STATS
// thread_local HOME :240-:242 exposes mut only on expected_flows' Cell
// (the sfdaq_instance.rs:236-:239 interior-Cell law) and the frozen
// 23b struct is NEVER re-opened — hence the ctx &mut-DAQStats leg,
// DEV-024) + the pt-racer instance (DEV-011) + the provider seams.
// ---------------------------------------------------------------------------
pub struct ActiveCtx<'a> {
    pub world: &'a mut ActiveWorld,
    /// the landed 23a facade (the can_*/forwarding/inject legs cc
    /// :114/:201/:675/:681/:873/:893 ride it; the C file-static call
    /// shape `SFDAQ::x()` lands as the handle method — sfdaq.rs law):
    pub daq: &'a mut SFDaq,
    /// the landed DAQStats home bump leg (cc :805, DEV-024):
    pub daq_stats: &'a mut DAQStats,
    pub log: &'a mut LogEngine,
    pub conf: &'a dyn ActiveConfigReadFace,
    /// DEV-011 the landed pt-racer instance behind the C static shape:
    pub pt: Option<&'a mut PacketTrace>,
    pub encode: &'a mut dyn ActiveEncodeFace,
    pub io: &'a mut dyn ActiveIoFace,
    pub stream: &'a mut dyn StreamSeam,
    pub detection: &'a mut dyn DetectionSeam,
    pub dnet: &'a mut dyn DnetFace,
}

impl ActiveCtx<'_> {
    /// DEV-011: the C `PacketTracer::is_active()` static-call shape
    /// (the fifteen `if (PacketTracer::is_active())` sites — the
    /// knownConditionTrueFalse cppcheck suppresses ride the cites at
    /// each call site):
    fn pt_is_active(&self) -> bool {
        self.pt.as_deref().is_some_and(|t| t.is_active())
    }
}

// ---------------------------------------------------------------------------
// h :35-:227 `class SO_PUBLIC Active` — the object itself. h :38-:39
// `Active() = default; ~Active() = default;` -> `new()` pinning the
// NSDMI cold face EXACT (h :216-:226). THE h :219-:221 C comment rides
// verbatim on the two action/status fields: "these can't be pkt flags
// because we do the handling of these flags following all processing and
// the drop or response may have been produced by a pseudopacket."
// ---------------------------------------------------------------------------

pub struct Active {
    pub active_tunnel_bypass: i32, // h :216 `int active_tunnel_bypass = 0;`
    pub drop_reason: Option<&'static str>, // h :217 DEV-004 (C raw const char*, first-wins set cc :1050-:1054)
    pub active_status: u8,            // h :222 `= AST_MAX;` (the cold seed)
    pub active_would_reason: u8,      // h :223 `= WHD_EXIT;`
    pub active_action: u8,            // h :224 `= ACT_MAX;`
    pub delayed_active_action: u8,    // h :225 `= ACT_MAX;`
    pub delayed_reject: Option<&'static dyn ActiveActionFace>, // h :226 DEV-005 `// set with set_delayed_action()`
}

impl Active {
    /// h :38 the defaulted ctor + the h :216-:225 NSDMI pin face (the
    /// cold seed the reset() later overwrites, cc :1006-:1015):
    pub fn new() -> Active {
        Active {
            active_tunnel_bypass: 0, // h :216
            drop_reason: None,       // h :217 nullptr
            active_status: AST_MAX,  // h :222
            active_would_reason: WHD_EXIT, // h :223
            active_action: ACT_MAX,  // h :224
            delayed_active_action: ACT_MAX, // h :225
            delayed_reject: None,    // h :226
        }
    }
}

impl Default for Active {
    fn default() -> Self { Active::new() } // h :38 `Active() = default;`
}

impl Default for ActiveWorld {
    fn default() -> Self { ActiveWorld::new() } // cc :72-:88 NSDMI pin
}

// ---------------------------------------------------------------------------
// h :229-:236 `struct ActiveSuspendContext` — the RAII guard:
//   ctor: `ActiveSuspendContext(Active::ActiveSuspendReason
//   suspend_reason) { Active::suspend(suspend_reason); }` (:231-:232)
//   dtor: `~ActiveSuspendContext() { Active::resume(); }` (:234-:235)
// -> the Drop impl (DEV-021: the C guard carries NO fields; the Rust
// guard re-borrows the world so the Drop-side resume() reaches the
// file-statics home).
// ---------------------------------------------------------------------------

pub struct ActiveSuspendContext<'a> {
    world: &'a mut ActiveWorld, // DEV-021 (the resume() leg rides it)
}

impl ActiveSuspendContext<'_> {
    /// h :231-:232 (the suspend_reason arg carries the ASP_* ordinal):
    pub fn new(world: &mut ActiveWorld, suspend_reason: u8) -> ActiveSuspendContext<'_> {
        Active::suspend(world, suspend_reason); // h :232
        ActiveSuspendContext { world }
    }
}

impl Drop for ActiveSuspendContext<'_> {
    /// h :234-:235:
    fn drop(&mut self) {
        Active::resume(self.world); // h :235
    }
}

// ---------------------------------------------------------------------------
// h :69-:70 + cc :190-:220 — thread_init / thread_term.
// ---------------------------------------------------------------------------

impl Active {
    /// cc :190-:215 `bool Active::thread_init(const SnortConfig* sc)` —
    /// the clamp ladder: attempts store :192, the MAX_ATTEMPTS clamp
    /// :194-:195, the zero->1 floor :197-:198, the inject-capability /
    /// respond-device gate :201 (the cppcheck-suppress comment rides
    /// verbatim: "knownConditionTrueFalse ; capability comes from the
    /// active DAQ module"), the read-mode/open short-circuit :203-:204
    /// (read_mode TRUE skips open EXACTLY), the ParseWarning leg
    /// :206-:207 (the C string-concat face "active responses disabled
    /// since DAQ " "can't inject packets." = ONE string), and the
    /// `#ifndef REG_TEST` zero-store :208-:210 (DEV-016: the
    /// production arm lands, the test-build preproc arm rides the
    /// cite). DEV-019: Result<bool, Fatal> — the open() leg inside the
    /// :204 gate can reach the FatalError->Err arm (DEV-008).
    pub fn thread_init(ctx: &mut ActiveCtx) -> Result<bool, Fatal> {
        ctx.world.s_attempts = ctx.conf.respond_attempts(); // cc :192 (h :286 read face)

        // cc :194-:195 C faces `if (s_attempts > MAX_ATTEMPTS) s_attempts
        // = MAX_ATTEMPTS;` + `if (s_attempts == 0) s_attempts = 1;` — the
        // min/ceil clamp pair as idiomatic arithmetic faces (rustc >= 1.90
        // rejects the C if-assign face via the clamp lint):
        ctx.world.s_attempts = ctx.world.s_attempts.min(MAX_ATTEMPTS);
        if ctx.world.s_attempts == 0 {
            ctx.world.s_attempts = 1; // cc :197-:198
        }

        // cppcheck-suppress knownConditionTrueFalse ; capability comes from the active DAQ module
        if !ctx.daq.can_inject() || ctx.conf.respond_device().is_some() {
            // cc :203-:204 `sc->read_mode() || !open(...)` — the C
            // short-circuit: read_mode TRUE NEVER opens the device:
            let gate_fail = if ctx.conf.read_mode() {
                true
            } else {
                let dev = ctx.conf.respond_device(); // cc :204 the empty -> nullptr leg
                !Self::open(ctx.world, &mut *ctx.dnet, &mut *ctx.log, dev)?
            };
            if gate_fail {
                ctx.log.parse_warning(
                    WARN_DAQ, // the landed WARN_DAQ home, messages.rs:27
                    "active responses disabled since DAQ can't inject packets.", // cc :206-:207 (concat one string)
                    &[],
                );
                ctx.world.s_attempts = 0; // cc :209 (deviation cited)
            }
        }

        Ok(true) // cc :214
    }

    /// cc :217-:220 `void Active::thread_term() { Active::close(); }`:
    pub fn thread_term(world: &mut ActiveWorld) {
        Active::close(world); // cc :219
    }
}

// ---------------------------------------------------------------------------
// cc :96-:117 — the send_eth/send_ip arms (DEV-007 tag-dispatched in
// `Active::send_via`) + the GetFlags helper. The ssize_t -> u32 TRUNCATE
// compare (cc :100/:107 `return ( (uint32_t)sent != len );`) is
// BYTE-EXACT: Rust `as u32` wraps two's-complement like C, so the -1
// ssize face lands as 0xFFFFFFFF != len -> 1 (the C failure truthy):
// ---------------------------------------------------------------------------

/// cc :110-:117 `static inline EncodeFlags GetFlags()` — the C
/// cppcheck-suppress comment rides verbatim: "knownConditionTrueFalse ;
/// capability comes from the active DAQ module":
fn get_flags(daq: &SFDaq, world: &ActiveWorld) -> EncodeFlags {
    let mut flags = ENC_FLAG_ID;
    // cppcheck-suppress knownConditionTrueFalse ; capability comes from the active DAQ module
    if daq.can_inject_raw() || world.s_ipnet.is_some() {
        flags |= ENC_FLAG_RAW;
    }
    flags
}

/// the s_send slot dispatch (DEV-007): the cc :112-:116 default
/// `SFDAQ::inject` arm reaches the landed sfdaq.rs:625 wrapper (the 23a
/// frozen face drops the DAQT msg arg, "DAQT msg selector is the SDK's"
/// cited THERE; the None local_instance face = the C nullptr deref at
/// sfdaq.cc :396 that NEVER fires on the vectors — the landed DAQ_ERROR
/// sentinel (sfdaq.rs:63) stands in, cited). The Eth/Ip arms replay
/// cc :96-:101 / :103-:108 send_eth / send_ip bodies (the s_link /
/// s_ipnet nullptr faces = the C dnet-NULL UB arms, harness-infeasible,
/// the failure truthy stands in per DEV-009):
fn send_via(
    ctx: &mut ActiveCtx,
    daq_msg: u64,
    rev: i32,
    rej: &[u8],
    len: u32,
) -> i32 {
    match ctx.world.s_send {
        SendKind::Daq => {
            let _ = daq_msg; // the landed inject face drops msg (cited DEV/23a law)
            ctx.daq.inject(rev, rej).unwrap_or(DAQ_ERROR)
        }
        SendKind::Eth => match ctx.world.s_link.as_mut() {
            Some(link) => {
                let sent = link.eth_send(rej, len); // cc :99 `eth_send(s_link, buf, len)`
                ((sent as u32) != len) as i32 // cc :100 the truncate-compare face
            }
            None => 1, // cc :99 the s_link-NULL face (harness-infeasible, DEV-009)
        },
        SendKind::Ip => match ctx.world.s_ipnet.as_mut() {
            Some(net) => {
                let sent = net.ip_send(rej, len); // cc :106 `ip_send(s_ipnet, buf, len)`
                ((sent as u32) != len) as i32 // cc :107 the truncate-compare face
            }
            None => 1, // cc :106 the s_ipnet-NULL face (harness-infeasible, DEV-009)
        },
    }
}

// ---------------------------------------------------------------------------
// cc :119-:158 — the strafing note + the pure Strafe fn. THE C comment
// rides verbatim: "TBD strafed sequence numbers could be divided by
// window scaling if present." The u32 `p->dsize << 1/2` C wraps mod
// 2^32 — the wrapping_shl legs + the VAL mask land EXACT (the u64 add
// then mask = the C (flags + x) & VAL face); the default arm's
// `ntohs(p->ptrs.tcph->th_win)` byte swap rides the packet-face leg
// (the landed window-read precedent at cd_icmp4_ip.rs:355 cited at the
// face) — pure read, no mutation (a pure fn, per the row law):
// ---------------------------------------------------------------------------

/// cc :122-:158 `static uint64_t Strafe(int i, uint64_t flags, const
/// Packet* p)` byte-exact (the cc :152 tcph-NULL face is harness-
/// infeasible — the tcph_win Option unwrap_or(0) stand-in cited):
fn strafe(i: i32, flags: EncodeFlags, pkt: &dyn ActivePacketFace) -> EncodeFlags {
    let mut flags = flags & ENC_FLAG_VAL; // cc :124

    match i {
        0 => {
            flags |= ENC_FLAG_SEQ; // cc :128-:130
        }

        1 => {
            flags = (pkt.dsize() as EncodeFlags) & ENC_FLAG_VAL; // cc :133-:134
            flags |= ENC_FLAG_SEQ; // cc :135
        }

        2 | 3 => {
            flags += pkt.dsize().wrapping_shl(1) as EncodeFlags; // cc :140
            flags &= ENC_FLAG_VAL; // cc :141
            flags |= ENC_FLAG_SEQ; // cc :142
        }

        4 => {
            flags += pkt.dsize().wrapping_shl(2) as EncodeFlags; // cc :146
            flags &= ENC_FLAG_VAL; // cc :147
            flags |= ENC_FLAG_SEQ; // cc :148
        }

        _ => {
            let win = pkt.tcph_win().unwrap_or(0); // cc :152 (the th_win ntohs face)
            flags += (win >> 1) as EncodeFlags; // cc :152
            flags &= ENC_FLAG_VAL; // cc :153
            flags |= ENC_FLAG_SEQ; // cc :154
        }
    }
    flags
}

// ---------------------------------------------------------------------------
// h :92 + cc :162-:186 `void Active::kill_session(Packet* p,
// EncodeFlags flags)` (the h default `ENC_FLAG_FWD` spelled out per
// DEV-018) — the switch on p->type():
// ---------------------------------------------------------------------------

impl Active {
    /// cc :162-:186:
    pub fn kill_session(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &mut dyn ActivePacketFace,
        flags: EncodeFlags, // h :92 (ENC_FLAG_FWD) default face
    ) {
        match p.type_() {
            PKT_TYPE__NONE => {
                // Can only occur if we have never seen IP (cc :167) — the
                // bare-C-return arm as the empty block (match arms never
                // need the `return` face, rustc unneeded-return law):
            }

            PKT_TYPE__TCP => {
                Self::send_reset(self, ctx, p, 0); // cc :171 (the 0-flags leg EXACT, NOT the h default)
                if flags & ENC_FLAG_FWD != 0 {
                    Self::send_reset(self, ctx, p, ENC_FLAG_FWD); // cc :172-:173
                }
            }

            _ => {
                if Self::is_unreachable_candidate(p) {
                    // cc :177-:183:
                    if self.packet_force_dropped() {
                        Self::send_unreach(self, ctx, p, UnreachResponse::FWD); // cc :180
                    } else {
                        Self::send_unreach(self, ctx, p, UnreachResponse::PORT); // cc :182
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// cc :222-:265 — the add_trace_log trio + payload faces (h :193-:196).
// The C `if ( not prefix or not pkt_type)` nullptr legs (cc :226-:227)
// are inexpressible over the owned &str face (C raw const char* keys —
// the DEV-004 family; cited): every landed caller passes table
// literals, the nullptr arms NEVER fire. C's printf argument eval-order
// hygiene rides naturally (every arg pre-hoisted as a local here).
// The pt-racer legs ride the landed 23f homes through the ctx (DEV-011:
// C's `PacketTracer::is_active()`/`log()` static shape over the
// thread-local singleton; a NOT-planted pt-racer rides the C
// pt-racer-off face — the fifteen `if (PacketTracer::is_active())` sites
// gate EVERY log, so the None face is unreachable-live).
// ---------------------------------------------------------------------------

impl Active {
    /// cc :223-:246 the shared body (the C `%u` leg on payload_len as
    /// the landed cfmt Arg::U home):
    pub fn add_trace_log(
        ctx: &mut ActiveCtx,
        ef: EncodeFlags,
        direct_inject: bool,
        success: bool,
        prefix: &str,
        pkt_type: &str,
        payload_len: u32,
    ) {
        // cc :226-:227 the raw-pointer nullptr legs (inexpressible over
        // the owned face — cited; callers pass literals):
        let forward_direction = ef & ENC_FLAG_FWD != 0; // cc :229
        let mut direction = "reverse"; // cc :230
        let mut inject_type = "injection"; // cc :231
        let mut status = "failed"; // cc :232
        if forward_direction {
            direction = "forward"; // cc :233-:234
        }

        if success {
            status = "successful"; // cc :236-:237
        }

        if direct_inject {
            inject_type = "direct injection"; // cc :239-:240
        }

        // the DEV-011 face (the C pt-racer live whenever this leg runs):
        if let Some(t) = ctx.pt.as_deref_mut() {
            if payload_len != 0 {
                // cc :243:
                t.log(
                    "%s: %s %s of %s (length %u) in %s direction\n",
                    &[
                        Arg::S(Some(Cow::from(prefix))),
                        Arg::S(Some(Cow::from(status))),
                        Arg::S(Some(Cow::from(inject_type))),
                        Arg::S(Some(Cow::from(pkt_type))),
                        Arg::U(payload_len as u64),
                        Arg::S(Some(Cow::from(direction))),
                    ],
                );
            } else {
                // cc :245:
                t.log(
                    "%s: %s %s of %s in %s direction\n",
                    &[
                        Arg::S(Some(Cow::from(prefix))),
                        Arg::S(Some(Cow::from(status))),
                        Arg::S(Some(Cow::from(inject_type))),
                        Arg::S(Some(Cow::from(pkt_type))),
                        Arg::S(Some(Cow::from(direction))),
                    ],
                );
            }
        }
    }

    /// h :193 cc :248-:251 — the FIRST string pin EXACT: "RST packet":
    pub fn add_reset_trace_log(
        ctx: &mut ActiveCtx,
        ef: EncodeFlags,
        direct_inject: bool,
        success: bool,
        prefix: &str,
    ) {
        Active::add_trace_log(ctx, ef, direct_inject, success, prefix, "RST packet", 0);
    }

    /// h :194 cc :252-:255 — pin "FIN packet":
    pub fn add_fin_trace_log(
        ctx: &mut ActiveCtx,
        ef: EncodeFlags,
        direct_inject: bool,
        success: bool,
        prefix: &str,
    ) {
        Active::add_trace_log(ctx, ef, direct_inject, success, prefix, "FIN packet", 0);
    }

    /// h :195 cc :257-:260 — pin "packet unreachable":
    pub fn add_unreach_trace_log(
        ctx: &mut ActiveCtx,
        ef: EncodeFlags,
        direct_inject: bool,
        success: bool,
        prefix: &str,
    ) {
        Active::add_trace_log(ctx, ef, direct_inject, success, prefix, "packet unreachable", 0);
    }

    /// h :196 cc :262-:265 — pin "payload packet" + the len leg:
    pub fn add_payload_trace_log(
        ctx: &mut ActiveCtx,
        ef: EncodeFlags,
        direct_inject: bool,
        success: bool,
        prefix: &str,
        payload_len: u32,
    ) {
        Active::add_trace_log(ctx, ef, direct_inject, success, prefix, "payload packet", payload_len);
    }
}

// ---------------------------------------------------------------------------
// h :78 + cc :267-:327 `void Active::send_reset(Packet* p, EncodeFlags
// ef)`. THE two C comments ride verbatim at the body head (cc :269-:270,
// the SAME pair sits at send_unreach :331-:332, send_data :367-:368,
// inject_data :598-:599): "The combined project database includes
// constant PacketTracer test stubs; production reads pt-racer state
// established at runtime." Each attempt-iteration takes ONE shot at the
// direct-inject branch; the else branch strafes the seq VALUE through
// the pure Strafe then encodes + sends. The encode seam returns the
// provider-owned borrow; the port COPIES the segment bytes (the send
// re-borrows ctx — DEV-010 shape cite, byte-identity preserved).
// ---------------------------------------------------------------------------

impl Active {
    /// cc :267-:327:
    pub fn send_reset(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &mut dyn ActivePacketFace,
        ef: EncodeFlags,
    ) {
        // The combined project database includes constant PacketTracer test stubs;
        // production reads pt-racer state established at runtime.
        let attempts = ctx.world.s_attempts; // cc :275 (s_attempts read)
        let flags = (get_flags(&*ctx.daq, &*ctx.world) | ef) & !ENC_FLAG_VAL; // cc :272 (the C local is read-after-init only)
        let mut value = ef & ENC_FLAG_VAL; // cc :273

        let mut i: i32 = 0; // cc :271 `int i`
        while i < attempts as i32 {
            // cc :277-:279 (the flow nullptr short-circuit fused into
            // the face leg, cited at ActivePacketFace):
            if (p.packet_flags() & PKT_USE_DIRECT_INJECT) != 0
                || (p.flow_present() && p.flow_uses_direct_inject())
            {
                // cc :280-:281 the DIOCTL_DirectInjectReset aggregate:
                let msg = DioctlDirectInjectReset {
                    msg: p.daq_msg(),
                    direction: if (ef & ENC_FLAG_FWD) != 0 { DAQ_DIR_FORWARD } else { DAQ_DIR_REVERSE },
                };
                let ret = ctx.io.direct_inject_reset(&msg); // cc :282-:283
                if ret != DAQ_SUCCESS {
                    ctx.world.active_counts.failed_direct_injects += 1; // cc :286
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_reset_trace_log(ctx, ef, true, false, "send_reset"); // cc :288
                    }
                    return; // cc :289 (the FAILED shot returns, no retry)
                }

                ctx.world.active_counts.direct_injects += 1; // cc :292
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    Active::add_reset_trace_log(ctx, ef, true, true, "send_reset"); // cc :294
                }
            } else {
                value = strafe(i, value, p); // cc :301 (value = Strafe(i, value, p))

                // cc :303 encode_response(TcpResponse::RST, flags|value,
                // p, len) (DEV-010 seam; the bytes copied for the send
                // re-borrow):
                let rej: Vec<u8> = match ctx.encode.encode_response(
                    TcpResponse::RST,
                    flags | value,
                    &*p,
                    &[], // the C payload/payload_len default pair (nullptr, 0)
                ) {
                    Some(s) => s.to_vec(),
                    None => {
                        ctx.world.active_counts.failed_injects += 1; // cc :306
                        if ctx.pt_is_active() {
                            // cppcheck-suppress knownConditionTrueFalse
                            // string pin EXACT cc :308:
                            Active::add_reset_trace_log(ctx, ef, false, false, "send_reset failed to encode");
                        }
                        return; // cc :309
                    }
                };
                let len = rej.len() as u32; // the folded `uint32_t& len` out-arg (DEV-010)

                // cc :312 s_send(p->daq_msg, !(ef & ENC_FLAG_FWD), rej, len):
                let ret = send_via(ctx, p.daq_msg(), (!(ef & ENC_FLAG_FWD) != 0) as i32, &rej, len);
                if ret != 0 {
                    ctx.world.active_counts.failed_injects += 1; // cc :315
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_reset_trace_log(ctx, ef, false, false, "send_reset"); // cc :317
                    }
                } else {
                    ctx.world.active_counts.injects += 1; // cc :321
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_reset_trace_log(ctx, ef, false, true, "send_reset"); // cc :323
                    }
                }
            }
            i += 1; // cc :275 the loop step
        }
    }

    /// h :79 + cc :329-:362 `void Active::send_unreach(Packet* p,
    /// snort::UnreachResponse type)` (the `flags` the trace legs pass
    /// are the GetFlags() VALUE at cc :335, cited at each pin):
    pub fn send_unreach(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &mut dyn ActivePacketFace,
        type_: UnreachResponse,
    ) {
        // The combined project database includes constant PacketTracer test stubs;
        // production reads pt-racer state established at runtime.
        let flags = get_flags(&*ctx.daq, &*ctx.world); // cc :335

        if ctx.world.s_attempts == 0 {
            return; // cc :337-:338
        }

        // cc :340 encode_reject(type, flags, p, len):
        let rej: Vec<u8> = match ctx.encode.encode_reject(type_, flags, &*p) {
            Some(s) => s.to_vec(),
            None => {
                ctx.world.active_counts.failed_injects += 1; // cc :343
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    // string pin EXACT cc :345:
                    Active::add_unreach_trace_log(ctx, flags, false, false, "send_unreach failed to encode");
                }
                return; // cc :346
            }
        };
        let len = rej.len() as u32; // folded out-arg (DEV-010)

        // cc :349 s_send(p->daq_msg, 1, rej, len) — the rev leg is the
        // literal 1 (unreach sends REVERSE always):
        let ret = send_via(ctx, p.daq_msg(), 1, &rej, len);
        if ret != 0 {
            ctx.world.active_counts.failed_injects += 1; // cc :352
            if ctx.pt_is_active() {
                // cppcheck-suppress knownConditionTrueFalse
                Active::add_unreach_trace_log(ctx, flags, false, false, "send_unreach"); // cc :354
            }
        } else {
            ctx.world.active_counts.injects += 1; // cc :358
            if ctx.pt_is_active() {
                // cppcheck-suppress knownConditionTrueFalse
                Active::add_unreach_trace_log(ctx, flags, false, true, "send_unreach"); // cc :360
            }
        }
    }

    /// h :80 + cc :364-:593 `uint32_t Active::send_data(Packet* p,
    /// EncodeFlags flags, const uint8_t* buf, uint32_t blen)` — the
    /// whole long body (the C `const uint8_t* buf` nullptr face cc :434
    /// lands as Option<&[u8]>; DEV-023: the C `buf += toSend` pointer
    /// bump ports as a re-slice and the `blen` walk rides ONE mirrored
    /// u32 local subtracted EXACTLY as C — `toSend = blen > maxPayload
    /// ? maxPayload : blen` (cc :474) clamps toSend<=blen so the C
    /// `while (blen -= toSend)` UNSIGNED decref never wraps: the
    /// wrapping_sub leg is identical either way, cited at the loop foot.
    /// The encode_response segment bytes are COPIED per call (DEV-010
    /// re-borrow shape; byte-identity preserved):
    pub fn send_data(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &mut dyn ActivePacketFace,
        mut flags: EncodeFlags,
        buf: Option<&[u8]>,
        mut blen: u32,
    ) -> u32 {
        // The combined project database includes constant PacketTracer test stubs;
        // production reads pt-racer state established at runtime.
        let use_direct_inject = (p.packet_flags() & PKT_USE_DIRECT_INJECT) != 0
            || (p.flow_present() && p.flow_uses_direct_inject()); // cc :372-:373

        flags |= get_flags(&*ctx.daq, &*ctx.world); // cc :375
        flags &= !ENC_FLAG_VAL; // cc :376

        // Send RST to the originator of the data. (cc :378)
        if flags & ENC_FLAG_RST_SRVR != 0 {
            let tmp_flags = flags ^ ENC_FLAG_FWD; // cc :381
            if use_direct_inject {
                // cc :384-:386 the aggregate + the tmp_flags direction:
                let msg = DioctlDirectInjectReset {
                    msg: p.daq_msg(),
                    direction: if (tmp_flags & ENC_FLAG_FWD) != 0 { DAQ_DIR_FORWARD } else { DAQ_DIR_REVERSE },
                };
                let ret = ctx.io.direct_inject_reset(&msg); // cc :387-:388
                if ret != DAQ_SUCCESS {
                    ctx.world.active_counts.failed_direct_injects += 1; // cc :391
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_reset_trace_log(ctx, tmp_flags, true, false, "send_data to originator"); // cc :393
                    }
                    return 0; // cc :394
                }

                ctx.world.active_counts.direct_injects += 1; // cc :397
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    Active::add_reset_trace_log(ctx, tmp_flags, true, true, "send_data to originator"); // cc :399
                }
            } else {
                // cc :403-:404 plen = 0 + encode (the out-arg folds,
                // DEV-010; the pre-seed rides the cite). The C two-
                // branch shape `if ( seg ) {...} else { counts + the
                // pin EXACT }` (cc :406 vs :422-:427) ports as the
                // Option if/let-else pair:
                let seg: Option<Vec<u8>> =
                    ctx.encode.encode_response(TcpResponse::RST, tmp_flags, &*p, &[]).map(|s| s.to_vec());
                if let Some(seg) = seg {
                    let plen = seg.len() as u32;
                    let ret = send_via(ctx, p.daq_msg(), (!(tmp_flags & ENC_FLAG_FWD) != 0) as i32, &seg, plen); // cc :408
                    if ret != 0 {
                        ctx.world.active_counts.failed_injects += 1; // cc :411
                        if ctx.pt_is_active() {
                            // cppcheck-suppress knownConditionTrueFalse
                            Active::add_reset_trace_log(ctx, tmp_flags, false, false, "send_data to originator"); // cc :413
                        }
                    } else {
                        ctx.world.active_counts.injects += 1; // cc :417
                        if ctx.pt_is_active() {
                            // cppcheck-suppress knownConditionTrueFalse
                            Active::add_reset_trace_log(ctx, tmp_flags, false, true, "send_data to originator"); // cc :419
                        }
                    }
                } else {
                    // cc :422-:427 the else arm — pin EXACT cc :426:
                    ctx.world.active_counts.failed_injects += 1; // cc :424
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_reset_trace_log(ctx, tmp_flags, false, false, "send_data to originator failed to encode");
                    }
                }
            }
        }
        flags |= ENC_FLAG_SEQ; // cc :430

        let mut sent: u32 = 0; // cc :432

        if let Some(mut buf) = buf {
            // Inject the payload. (cc :436)
            if use_direct_inject {
                flags &= !ENC_FLAG_VAL; // cc :439
                // cc :440-:446 the segment array + the two-level
                // payload[] single-slot array + num_segments 1 + the
                // direction ternary:
                let segments = [DaqDiPayloadSegment { data: buf, length: blen }];
                let msg = DioctlDirectInjectPayload {
                    msg: p.daq_msg(),
                    segments: &segments,
                    num_segments: 1,
                    reverse: if (flags & ENC_FLAG_FWD) != 0 { DAQ_DIR_FORWARD } else { DAQ_DIR_REVERSE },
                };
                let ret = ctx.io.direct_inject_payload(&msg); // cc :447-:448
                if ret != DAQ_SUCCESS {
                    ctx.world.active_counts.failed_direct_injects += 1; // cc :451
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_payload_trace_log(ctx, flags, true, false, "send_data", blen); // cc :453
                    }
                    return 0; // cc :454
                }

                sent = blen; // cc :457
                ctx.world.active_counts.direct_injects += 1; // cc :458
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    Active::add_payload_trace_log(ctx, flags, true, true, "send_data", blen); // cc :460
                }
            } else {
                let max_payload = ctx.encode.encode_get_max_payload(&*p); // cc :464 (encode_get_max_payload, uint16_t)

                if max_payload != 0 {
                    let mut success = true; // cc :469
                    // THE do/while blen loop (cc :470-:498): the FIRST
                    // pass runs UNCONDITIONALLY (C do/while, even at
                    // blen == 0 the body encodes ONE empty-PUSH
                    // attempt); DEV-023 the unsigned decref foot:
                    loop {
                        // cc :472-:476 plen = 0; flags VAL-replacement
                        // with `sent`; toSend = min(blen, maxPayload)
                        // (the ternary as-is):
                        flags = (flags & !ENC_FLAG_VAL) | sent as EncodeFlags;
                        let to_send = if blen > max_payload as u32 { max_payload as u32 } else { blen };
                        let seg: Vec<u8> = match ctx.encode.encode_response(
                            TcpResponse::PUSH,
                            flags,
                            &*p,
                            &buf[..(to_send as usize)],
                        ) {
                            Some(s) => s.to_vec(),
                            None => {
                                // cc :478-:484 the !seg arm — pin EXACT:
                                ctx.world.active_counts.failed_injects += 1; // cc :480
                                if ctx.pt_is_active() {
                                    // cppcheck-suppress knownConditionTrueFalse
                                    Active::add_payload_trace_log(ctx, flags, false, false, "send_data failed to encode", blen);
                                }
                                return sent; // cc :483
                            }
                        };
                        let plen = seg.len() as u32; // folded out-arg (DEV-010)

                        // cc :486 s_send(p->daq_msg, !(flags &
                        // ENC_FLAG_FWD), seg, plen):
                        let ret = send_via(ctx, p.daq_msg(), (!(flags & ENC_FLAG_FWD) != 0) as i32, &seg, plen);
                        if ret != 0 {
                            ctx.world.active_counts.failed_injects += 1; // cc :489
                            success = false; // cc :490
                        } else {
                            ctx.world.active_counts.injects += 1; // cc :493
                        }

                        sent += to_send; // cc :495
                        buf = &buf[(to_send as usize)..]; // cc :496 the pointer bump as a re-slice (DEV-023)
                        // cc :498 `while (blen -= toSend)` — the
                        // UNSIGNED decref (DEV-023: toSend <= blen by
                        // the :474 clamp, so wrapping_sub == C exactly,
                        // no wrap either side; the loop STOPS at 0 like
                        // the C while):
                        blen = blen.wrapping_sub(to_send);
                        if blen == 0 {
                            break;
                        }
                    }

                    // cc :500-:501 (the END-of-loop single trace, the
                    // C flags value = the LAST re-written flags):
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_payload_trace_log(ctx, flags, false, success, "send_data", sent);
                    }
                }
            }
        }

        // FIXIT-L: Currently there is no support for injecting a FIN via
        // direct injection. (cc :506-:507)
        if !use_direct_inject {
            // cc :510-:512 plen = 0 + encode(FIN, ..., nullptr, 0) (the
            // C default pair = the empty payload leg, DEV-018):
            flags = (flags & !ENC_FLAG_VAL) | sent as EncodeFlags;
            let seg: Vec<u8> = match ctx.encode.encode_response(TcpResponse::FIN, flags, &*p, &[]) {
                Some(s) => s.to_vec(),
                None => {
                    // cc :514-:519 the !seg arm — pin EXACT:
                    ctx.world.active_counts.failed_injects += 1; // cc :516
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_fin_trace_log(ctx, flags, false, false, "send_data failed to encode");
                    }
                    return sent; // cc :519
                }
            };
            let plen = seg.len() as u32;

            let ret = send_via(ctx, p.daq_msg(), (!(flags & ENC_FLAG_FWD) != 0) as i32, &seg, plen); // cc :522
            if ret != 0 {
                ctx.world.active_counts.failed_injects += 1; // cc :525
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    Active::add_fin_trace_log(ctx, flags, false, false, "send_data"); // cc :527
                }
            } else {
                ctx.world.active_counts.injects += 1; // cc :531
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    Active::add_fin_trace_log(ctx, flags, false, true, "send_data"); // cc :533
                }
            }

            // Sending a FIN requires that we bump the seq by 1. (cc :536)
            sent += 1; // cc :537
        }

        //  Send RST to the receiver of the data. (cc :540)
        if flags & ENC_FLAG_RST_CLNT != 0 {
            flags = (flags & !ENC_FLAG_VAL) | sent as EncodeFlags; // cc :543
            if use_direct_inject {
                let msg = DioctlDirectInjectReset {
                    msg: p.daq_msg(),
                    direction: if (flags & ENC_FLAG_FWD) != 0 { DAQ_DIR_FORWARD } else { DAQ_DIR_REVERSE },
                }; // cc :546-:547
                let ret = ctx.io.direct_inject_reset(&msg); // cc :548-:549
                if ret != DAQ_SUCCESS {
                    ctx.world.active_counts.failed_direct_injects += 1; // cc :552
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_reset_trace_log(ctx, flags, true, false, "send_data"); // cc :554
                    }
                    return sent; // cc :555
                }

                ctx.world.active_counts.direct_injects += 1; // cc :558
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    Active::add_reset_trace_log(ctx, flags, true, true, "send_data"); // cc :560
                }
            } else {
                // cc :564-:565 + the two-branch cc :567/:585-:588
                // shape (pin EXACT cc :587 — same style as the
                // RST_SRVR arm above):
                let seg: Option<Vec<u8>> =
                    ctx.encode.encode_response(TcpResponse::RST, flags, &*p, &[]).map(|s| s.to_vec());
                if let Some(seg) = seg {
                    let plen = seg.len() as u32;
                    let ret = send_via(ctx, p.daq_msg(), (!(flags & ENC_FLAG_FWD) != 0) as i32, &seg, plen); // cc :569
                    if ret != 0 {
                        ctx.world.active_counts.failed_injects += 1; // cc :572
                        if ctx.pt_is_active() {
                            // cppcheck-suppress knownConditionTrueFalse
                            Active::add_reset_trace_log(ctx, flags, false, false, "send_data"); // cc :574
                        }
                    } else {
                        ctx.world.active_counts.injects += 1; // cc :578
                        if ctx.pt_is_active() {
                            // cppcheck-suppress knownConditionTrueFalse
                            Active::add_reset_trace_log(ctx, flags, false, true, "send_data"); // cc :580
                        }
                    }
                } else {
                    ctx.world.active_counts.failed_injects += 1; // cc :586
                    if ctx.pt_is_active() {
                        // cppcheck-suppress knownConditionTrueFalse
                        Active::add_reset_trace_log(ctx, flags, false, false, "send_data failed to encode");
                    }
                }
            }
        }

        sent // cc :592
    }

    /// h :81 + cc :595-:631 `void Active::inject_data(Packet* p,
    /// EncodeFlags flags, const uint8_t* buf, uint32_t blen)` (the C
    /// body runs the encode DIRECTLY on buf — no nullptr gate here,
    /// unlike send_data :434, cited):
    pub fn inject_data(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &mut dyn ActivePacketFace,
        mut flags: EncodeFlags,
        buf: &[u8],
        blen: u32,
    ) {
        // The combined project database includes constant PacketTracer test stubs;
        // production reads pt-racer state established at runtime.
        if ctx.world.s_attempts == 0 {
            return; // cc :603-:604
        }

        flags |= get_flags(&*ctx.daq, &*ctx.world); // cc :606
        flags &= !ENC_FLAG_VAL; // cc :607

        // cc :609 encode_response(PUSH, flags, p, plen, buf, blen):
        let seg: Vec<u8> = match ctx.encode.encode_response(TcpResponse::PUSH, flags, &*p, buf) {
            Some(s) => s.to_vec(),
            None => {
                ctx.world.active_counts.failed_injects += 1; // cc :612
                if ctx.pt_is_active() {
                    // cppcheck-suppress knownConditionTrueFalse
                    // string pin EXACT cc :614:
                    Active::add_payload_trace_log(ctx, flags, false, false, "inject_data failed to encode", blen);
                }
                return; // cc :615
            }
        };
        let plen = seg.len() as u32; // folded out-arg (DEV-010)

        // cc :618 s_send(p->daq_msg, !(flags & ENC_FLAG_FWD), seg, plen):
        let ret = send_via(ctx, p.daq_msg(), (!(flags & ENC_FLAG_FWD) != 0) as i32, &seg, plen);
        if ret != 0 {
            ctx.world.active_counts.failed_injects += 1; // cc :621
            if ctx.pt_is_active() {
                // cppcheck-suppress knownConditionTrueFalse
                Active::add_payload_trace_log(ctx, flags, false, false, "inject_data", blen); // cc :623
            }
        } else {
            ctx.world.active_counts.injects += 1; // cc :627
            if ctx.pt_is_active() {
                // cppcheck-suppress knownConditionTrueFalse
                Active::add_payload_trace_log(ctx, flags, false, true, "inject_data", blen); // cc :629
            }
        }
    }

    // -----------------------------------------------------------------------
    // cc :633-:654 — the candidate tests (h :83-:84):
    // -----------------------------------------------------------------------

    /// cc :635-:646 `bool Active::is_reset_candidate(const Packet* p)`
    /// (the TH_RST REUSE-cite: `crate::codecs::cd_tcp::TH_RST` :248,
    /// tcp.h:34 — NEVER re-declared):
    pub fn is_reset_candidate(p: &dyn ActivePacketFace) -> bool {
        let th_flags = match p.tcph_flags() {
            Some(f) => f,
            None => return false, // cc :637 `!p->ptrs.tcph`
        };
        if !p.is_tcp() {
            return false; // cc :637
        }

        /*
        **  This ensures that we don't reset packets that we just
        **  spoofed ourselves, thus inflicting a self-induced DOS
        **  attack.
        */
        // cc :645 (the C comment block rides verbatim above):
        (th_flags & TH_RST) == 0
    }

    /// cc :648-:654 `bool Active::is_unreachable_candidate(const
    /// Packet* p)` (TCP||UDP true, else false):
    pub fn is_unreachable_candidate(p: &dyn ActivePacketFace) -> bool {
        p.type_() == PKT_TYPE__TCP || p.type_() == PKT_TYPE__UDP
    }

    // -----------------------------------------------------------------------
    // cc :656-:764 — the escalation + status + suspend family (h :204-
    // :205 privates + h :72-:76/:104 statics and members):
    // -----------------------------------------------------------------------

    /// cc :656-:668 `void Active::cant_drop()` — the escalation ladder
    /// (`< AST_CANT` then `< AST_WOULD`; the u8 ordinals keep the C
    /// numeric arms literal):
    pub fn cant_drop(&mut self, world: &ActiveWorld) {
        if self.active_status < AST_CANT {
            self.active_status = AST_CANT; // cc :660
            self.active_would_reason = Active::get_whd_reason_from_suspend_reason(world); // cc :661
        } else if self.active_status < AST_WOULD {
            self.active_status = AST_WOULD; // cc :665
            self.active_would_reason = Active::get_whd_reason_from_suspend_reason(world); // cc :666
        }
    }

    /// cc :670-:697 `void Active::update_status_actionable(const
    /// Packet* p)` — the C `p->context->conf->...` reads ride the ctx
    /// conf leg (the packet-context pairing face, DEV-003 cite); the
    /// two cppcheck-suppress comments ride verbatim:
    pub fn update_status_actionable(
        &mut self,
        ctx: &ActiveCtx,
        p: &dyn ActivePacketFace, // cc :672 (`p->context->conf` reads through the ctx conf leg; the pkth legs feed forwarding_packet)
    ) {
        if ctx.conf.ips_inline_mode() {
            // cppcheck-suppress knownConditionTrueFalse ; forwarding comes from runtime DAQ metadata
            if !ctx.daq.forwarding_packet(p.pkth_flags()) {
                // cc :677-:678:
                self.active_status = AST_WOULD;
                self.active_would_reason = WHD_INTERFACE_IDS;
            }
            // cppcheck-suppress knownConditionTrueFalse ; capability comes from the active DAQ module
            else if self.active_action == ACT_REWRITE && !ctx.daq.can_replace() {
                // cc :681-:685:
                self.active_status = AST_WOULD;
                self.active_would_reason = WHD_INTERFACE_IDS;
            }
        } else if ctx.conf.ips_inline_test_mode() {
            // cc :689-:690:
            self.active_status = AST_WOULD;
            self.active_would_reason = WHD_IPS_INLINE_TEST;
        } else if ctx.conf.ips_passive_mode() {
            // cc :694-:695:
            self.active_status = AST_WOULD;
            self.active_would_reason = WHD_INTERFACE_IDS;
        }
    }

    /// cc :699-:703 `static void suspend(ActiveSuspendReason)` (h :72 —
    /// a file-static write, so the world leg carries it):
    pub fn suspend(world: &mut ActiveWorld, suspend_reason: u8) {
        world.s_suspend = true; // cc :701
        world.s_suspend_reason = suspend_reason; // cc :702
    }

    /// cc :705-:706 `static bool is_suspended()`:
    pub fn is_suspended(world: &ActiveWorld) -> bool {
        world.s_suspend
    }

    /// cc :708-:712 `static void resume()` (the ASP_NONE reset pair):
    pub fn resume(world: &mut ActiveWorld) {
        world.s_suspend = false; // cc :710
        world.s_suspend_reason = ASP_NONE; // cc :711
    }

    /// cc :714-:715 `bool Active::can_partial_block_session() const` —
    /// member `active_status == AST_CANT and s_suspend_reason >
    /// ASP_NONE and s_suspend_reason != ASP_TIMEOUT` (the numeric
    /// arms literal, the h :143 DECL):
    pub fn can_partial_block_session(&self, world: &ActiveWorld) -> bool {
        self.active_status == AST_CANT
            && world.s_suspend_reason > ASP_NONE
            && world.s_suspend_reason != ASP_TIMEOUT
    }

    /// cc :717-719 `bool Active::keep_pruned_flow() const` — reads ONLY
    /// the s_suspend_reason static (the member legs NONE, cited):
    pub fn keep_pruned_flow(world: &ActiveWorld) -> bool {
        world.s_suspend_reason == ASP_PRUNE || world.s_suspend_reason == ASP_RELOAD
    }

    /// cc :720-721 `bool Active::keep_timedout_flow() const`:
    pub fn keep_timedout_flow(world: &ActiveWorld) -> bool {
        world.s_suspend_reason == ASP_TIMEOUT
    }

    /// cc :723-734
    /// `Active::ActiveWouldReason Active::get_whd_reason_from_suspend
    /// _reason()` — the FULL map (every ASP_* arm names its WHD_*; the
    /// fall-through after the switch = WHD_NONE :733 — in Rust the `_`
    /// arm stands for the C out-of-range face that NEVER fires (C
    /// switch on a closed enum; cited with DEV-006 world leg):
    pub fn get_whd_reason_from_suspend_reason(world: &ActiveWorld) -> u8 {
        match world.s_suspend_reason {
            ASP_NONE => WHD_NONE, // cc :727
            ASP_PRUNE => WHD_PRUNE, // cc :728
            ASP_TIMEOUT => WHD_TIMEOUT, // cc :729
            ASP_RELOAD => WHD_RELOAD, // cc :730
            ASP_EXIT => WHD_EXIT, // cc :731
            _ => WHD_NONE, // cc :733 (the post-switch default leg)
        }
    }

    /// cc :736-749 `void Active::update_status(const Packet* p, bool
    /// force)` (h :104 the `= false` default, DEV-018) — the C `if (
    /// !active_status )` = the AST_ALLOW ordinal-0 test (the numeric
    /// face literal, cited):
    pub fn update_status(&mut self, ctx: &ActiveCtx, p: &dyn ActivePacketFace, force: bool) {
        if ctx.world.s_suspend {
            self.update_status_actionable(ctx, p); // cc :740

            if self.active_status == AST_ALLOW {
                // cc :742 (!active_status, the ordinal-0 face)
                self.cant_drop(ctx.world); // cc :743
            }
        } else if force {
            self.active_status = AST_FORCE; // cc :746
        } else if self.active_status != AST_FORCE {
            self.update_status_actionable(ctx, p); // cc :748
        }
    }

    /// cc :751-764 `void Active::daq_update_status(const Packet* p)` —
    /// the private legs (h :205): the SAME arms minus the force arm,
    /// the `!active_status` ordinal-0 leg repeated (cc :757):
    pub fn daq_update_status(&mut self, ctx: &ActiveCtx, p: &dyn ActivePacketFace) {
        if ctx.world.s_suspend {
            self.update_status_actionable(ctx, p); // cc :755

            if self.active_status == AST_ALLOW {
                // cc :757 (!active_status, the ordinal-0 face)
                self.cant_drop(ctx.world); // cc :758
            }
        } else if self.active_status != AST_FORCE {
            self.update_status_actionable(ctx, p); // cc :762
        }
    }

    // -----------------------------------------------------------------------
    // cc :766-844 — the packet verdicts (h :106-111):
    // -----------------------------------------------------------------------

    /// cc :766-772 `void Active::drop_packet(const Packet* p, bool
    /// force)` — the "only escalate" law (`< ACT_DROP`):
    pub fn drop_packet(&mut self, ctx: &mut ActiveCtx, p: &dyn ActivePacketFace, force: bool) {
        if self.active_action < ACT_DROP {
            self.active_action = ACT_DROP; // cc :769
        }

        self.update_status(ctx, p, force); // cc :771
    }

    /// cc :774-780 `void Active::daq_drop_packet(const Packet* p)`:
    pub fn daq_drop_packet(&mut self, ctx: &mut ActiveCtx, p: &dyn ActivePacketFace) {
        if self.active_action < ACT_DROP {
            self.active_action = ACT_DROP; // cc :777
        }

        self.daq_update_status(ctx, p); // cc :779
    }

    /// cc :782-788 `void Active::rewrite_packet(const Packet* p, bool
    /// force)` (the `< ACT_REWRITE` escalation):
    pub fn rewrite_packet(&mut self, ctx: &mut ActiveCtx, p: &dyn ActivePacketFace, force: bool) {
        if self.active_action < ACT_REWRITE {
            self.active_action = ACT_REWRITE; // cc :785
        }

        self.update_status(ctx, p, force); // cc :787
    }

    /// cc :790-817 `bool Active::retry_packet(const Packet* p)` — the
    /// retry queue + THE pool heuristic (DEV-020: the io leg None =
    /// the cc :800/:801 nullptr-instance face, the selector fused
    /// provider-side); the `daq_stats.retries_dropped++` (cc :805)
    /// bumps the landed DAQStats home field (DEV-024):
    pub fn retry_packet(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &dyn ActivePacketFace,
    ) -> bool {
        if ActiveActionType::ActRetry as u8 == self.active_action {
            return true; // cc :792-793
        }

        // cppcheck-suppress knownConditionTrueFalse ; forwarding comes from runtime DAQ metadata
        if (ActiveActionType::ActRetry as u8) < self.active_action
            || !ctx.daq.forwarding_packet(p.pkth_flags())
        {
            return false; // cc :796-797
        }

        // FIXIT-L semi-arbitrary heuristic for preventing retry queue
        // saturation - reevaluate later (cc :799)
        // cc :800-801 `!daq_instance || daq_instance->
        // get_pool_available() < daq_instance->get_batch_size()` (the
        // None leg = the nullptr face after the :800 local fallback):
        let shortfall = match ctx.io.pool_and_batch(p.daq_msg()) {
            None => true,
            Some((pool_available, batch_size)) => pool_available < batch_size,
        };
        if shortfall {
            // Fall back on dropping the packet and relying on the host
            // to retransmit (cc :803)
            self.active_action = ACT_DROP; // cc :804
            ctx.daq_stats.retries_dropped += 1; // cc :805 (the landed retries_dropped field bump, DEV-024)
            return false; // cc :806
        }

        // If a retransmit would be added to the retry queue, drop it
        // instead.  FIXIT-L this behavior needs to be reevaluated and
        // probably moved somewhere else (cc :809-810)
        if (p.packet_flags() & PKT_RETRANSMIT) != 0 {
            self.active_action = ACT_DROP; // cc :811-812
        } else {
            self.active_action = ACT_RETRY; // cc :814
        }

        true // cc :816
    }

    /// cc :819-836 `bool Active::hold_packet(const Packet* p)` — the
    /// SAME semi-arbitrary pool heuristic (cc :824, THE p->daq_instance
    /// only face — the io leg None covers the nullptr):
    pub fn hold_packet(&mut self, ctx: &mut ActiveCtx, p: &dyn ActivePacketFace) -> bool {
        if self.active_action >= ACT_HOLD {
            return false; // cc :821-822
        }

        // FIXIT-L same semi-arbitrary heuristic as the retry queue
        // logic - reevaluate later (cc :824) — cc :825-:826 (THE
        // p->daq_instance-only face, NO :800 fallback here):
        let shortfall = match ctx.io.pool_and_batch(p.daq_msg()) {
            None => true,
            Some((pool_available, batch_size)) => pool_available < batch_size,
        };
        if shortfall {
            ctx.world.active_counts.holds_denied += 1; // cc :828
            return false; // cc :829
        }

        self.active_action = ACT_HOLD; // cc :832
        ctx.world.active_counts.holds_allowed += 1; // cc :833

        true // cc :835
    }

    /// cc :838-844 the C `// cppcheck-suppress unusedFunction ; entry
    /// point retained for external, conditional, or test use` rides.
    /// The `assert(active_action == ACT_HOLD);` (cc :841) -> debug_assert!
    /// per the NDEBUG-elision law (module.rs:831 /
    /// survivor_flow_data.rs:25-31 precedents — DEV-015):
    pub fn cancel_packet_hold(&mut self, world: &mut ActiveWorld) {
        debug_assert!(self.active_action == ACT_HOLD, "active.cc:841 assert(active_action == ACT_HOLD)");
        world.active_counts.holds_canceled += 1; // cc :842
        self.active_action = ACT_ALLOW; // cc :843
    }

    // -----------------------------------------------------------------------
    // cc :846-965 — the session ops + the queue law + the delayed pair:
    // -----------------------------------------------------------------------

    /// h :113 cc :846-866 `void Active::trust_session(Packet* p, bool
    /// force)` (the `!ACT_ALLOW < active_action` escalation guard,
    /// numeric-literal):
    pub fn trust_session(&mut self, ctx: &mut ActiveCtx, p: &mut dyn ActivePacketFace, force: bool) {
        if ACT_ALLOW < self.active_action {
            return; // cc :848-849
        }

        ctx.detection.disable_all(p); // cc :851 (detection_engine.h:105 seam, DEV-012)

        if force {
            p.packet_flags_bor(PKT_IGNORE); // cc :855 `p->packet_flags |= PKT_IGNORE`
            // cc :856-:860 — the flow-nullptr short-circuit fused (the
            // flow_present && Some chain, the edition-2024 let-chain law):
            if p.flow_present() && let Some(f) = p.flow_mut() {
                f.trust(); // cc :858 (flow.h:447)
                f.stop_deferring_trust(); // cc :859 (flow.h:439)
            }
            p.set_disable_inspect(); // cc :861 (packet.h:145)
        } else if p.flow_mut().is_some_and(|f| f.try_trust()) {
            // cc :863 `else if (p->flow && p->flow->try_trust())` — the
            // nullptr short-circuit fused (None = the C false leg):
            self.active_action = ACT_TRUST; // cc :864
        }
    }

    /// h :114 cc :867-880 `void Active::block_session(Packet* p, bool
    /// force)` (the PUBLIC overload, DEV-014 names the private one):
    pub fn block_session(&mut self, ctx: &mut ActiveCtx, p: &mut dyn ActivePacketFace, force: bool) {
        self.active_action = ACT_BLOCK; // cc :869
        self.update_status(ctx, p, force); // cc :870

        // cppcheck-suppress knownConditionTrueFalse ; forwarding comes from runtime DAQ metadata
        if force || (ctx.conf.ips_inline_mode() && ctx.daq.forwarding_packet(p.pkth_flags())) {
            ctx.stream.block_flow(p); // cc :874 (stream.h:154 seam, DEV-012)
        }

        if force && p.flow_present() && let Some(f) = p.flow_mut() {
            f.set_state(FLOW_STATE_BLOCK); // cc :877 (flow.h:173-:180 BLOCK ordinal 2)
        }

        p.set_disable_inspect(); // cc :879
    }

    /// h :207 DEV-014 private DECL `void block_session(const Packet*,
    /// ActiveActionType, bool)` — the owner TU carries NO definition at
    /// this revision (grep at the row: exactly ONE definition, cc :876,
    /// for the PUBLIC overload above; the consumers that name
    /// block_again/reset_again use the h :122-:128 inlines). Rust has no
    /// overloading: the private tagged arm lands RENAMED with the C++
    /// undefined-reference face as the unreachable body (a C link error
    /// on any call, NEVER callable in a linked program):
    pub fn block_session_tagged(
        &mut self,
        _ctx: &mut ActiveCtx,
        _p: &mut dyn ActivePacketFace,
        _action: ActiveActionType,
        _force: bool,
    ) {
        unreachable!("active.h :207 DECL — no definition in active.cc (link-error face, DEV-014)");
    }

    /// h :115 cc :882-885 `void Active::reset_session(Packet* p, bool
    /// force) { reset_session(p, &default_reset, force); }` (the landed
    /// DEFAULT_RESET static leg, DEV-005/DEV-006):
    pub fn reset_session(&mut self, ctx: &mut ActiveCtx, p: &mut dyn ActivePacketFace, force: bool) {
        self.reset_session_with_reject(ctx, p, Some(&DEFAULT_RESET), force);
    }

    /// h :116 cc :887-905 `void Active::reset_session(Packet* p,
    /// ActiveAction* reject, bool force)` (the h default `= false`,
    /// DEV-018):
    pub fn reset_session_with_reject(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &mut dyn ActivePacketFace,
        reject: Option<&'static dyn ActiveActionFace>,
        force: bool,
    ) {
        self.active_action = ACT_RESET; // cc :889
        self.update_status(ctx, p, force); // cc :890

        // cppcheck-suppress knownConditionTrueFalse ; forwarding comes from runtime DAQ metadata
        if force || (ctx.conf.ips_inline_mode() && ctx.daq.forwarding_packet(p.pkth_flags())) {
            ctx.stream.drop_flow(p); // cc :894 (stream.h:150 seam)
        }

        if let Some(r) = reject {
            Active::queue(ctx, r, p); // cc :896-897
        }

        if p.flow_present() {
            // cc :901 init_active_response(p, p->flow) — the SECOND C
            // arg IS p->flow (stream.h:192); it folds into the packet
            // leg (cited at the seam trait):
            ctx.stream.init_active_response(p);
            if let Some(f) = p.flow_mut() {
                f.set_state(FLOW_STATE_RESET); // cc :902 (RESET ordinal 3)
            }
        }

        p.set_disable_inspect(); // cc :905
    }

    /// h :118 cc :908-912 `void Active::queue(ActiveAction* a,
    /// Packet* p)` — THE queue priority law (C raw-pointer install ->
    /// DEV-002 owned clone; every landed action is a zero-state unit so
    /// copy == alias at the observable face):
    /// the ctx rides the seam-threading law (the C static has NO state
    /// legs — `_ctx` pinned, cited):
    pub fn queue(_ctx: &mut ActiveCtx, a: &'static dyn ActiveActionFace, p: &mut dyn ActivePacketFace) {
        let current = p.current_action_priority();
        // cc :910-911 `!(*p->action) || a->get_action() >
        // (*p->action)->get_action()`:
        if current.is_none() || a.get_action() > current.unwrap() {
            p.install_action(a.clone_action()); // DEV-002 install-by-clone
        }
    }

    /// h :179 cc :914-917 `void Active::set_delayed_action
    /// (ActiveActionType action, bool force) { set_delayed_action
    /// (action, action == ACT_RESET ? &default_reset : nullptr, force);
    /// }` (the ternary select leg EXACT):
    pub fn set_delayed_action(&mut self, action: ActiveActionType, force: bool) {
        let act: Option<&'static dyn ActiveActionFace> =
            if action as u8 == ACT_RESET { Some(&DEFAULT_RESET) } else { None };
        self.set_delayed_action_with_act(action, act, force);
    }

    /// h :180 cc :919-933 `void Active::set_delayed_action
    /// (ActiveActionType action, ActiveAction* act, bool force)` — THE
    /// C comment rides verbatim: "Don't update the delayed active action
    /// to a less strict one, with the exception of going from allow to
    /// trust.":
    pub fn set_delayed_action_with_act(
        &mut self,
        action: ActiveActionType,
        act: Option<&'static dyn ActiveActionFace>,
        force: bool,
    ) {
        // cc :923-924 `if(delayed_active_action >= action and
        // delayed_active_action > ACT_ALLOW) return;`:
        if self.delayed_active_action >= action as u8 && self.delayed_active_action > ACT_ALLOW {
            return;
        }

        self.delayed_active_action = action as u8; // cc :926

        if self.delayed_reject.is_none() {
            self.delayed_reject = act; // cc :928-929
        }

        if force {
            self.active_status = AST_FORCE; // cc :931-932
        }
    }

    /// h :181 cc :935-965 `void Active::apply_delayed_action(Packet*
    /// p)` — the switch + the assert (cc :950 `assert(delayed_reject);
    /// // resets must have been told which reject to use` ->
    /// debug_assert! per DEV-015) + the ACT_ALLOW tail store :964:
    pub fn apply_delayed_action(&mut self, ctx: &mut ActiveCtx, p: &mut dyn ActivePacketFace) {
        let force = self.active_status == AST_FORCE; // cc :937

        match ActiveActionType::from(self.delayed_active_action) {
            ActiveActionType::ActAllow => {} // cc :941-942 break
            ActiveActionType::ActDrop => self.drop_packet(ctx, p, force), // cc :943-945
            ActiveActionType::ActBlock => self.block_session(ctx, p, force), // cc :946-948
            ActiveActionType::ActReset => {
                // cc :950 (the C comment rides: resets must have been
                // told which reject to use):
                debug_assert!(self.delayed_reject.is_some(), "active.cc:950 assert(delayed_reject)");
                self.reset_session_with_reject(ctx, p, self.delayed_reject, force); // cc :951
            }
            ActiveActionType::ActRetry => {
                // cc :953-956:
                if !self.retry_packet(ctx, p) {
                    self.drop_packet(ctx, p, force);
                }
            }
            ActiveActionType::ActTrust => self.trust_session(ctx, p, force), // cc :957-959
            _ => {} // cc :960-961 default: break
        }

        self.delayed_active_action = ACT_ALLOW; // cc :964
    }

    // -----------------------------------------------------------------------
    // h :199-:200 + cc :967-1004 — open/close (the eth-vs-ip arm; the
    // `strcasecmp("ip")` face -> eq_ignore_ascii_case per the landed
    // text_log.rs:90 precedent; FatalError -> emit-then-Err per the
    // landed trough law, trough.rs:29 / :382-:387 + messages.rs:11 —
    // DEV-008; the two C cppcheck-suppress comments ride verbatim):
    // -----------------------------------------------------------------------

    /// cc :969-992 `bool Active::open(const char* dev)` (the C nullptr
    /// dev -> the Option face, cc :204 the empty->nullptr leg):
    pub fn open(
        world: &mut ActiveWorld,
        dnet: &mut dyn DnetFace,
        log: &mut LogEngine,
        dev: Option<&str>,
    ) -> Result<bool, Fatal> {
        // cc :971 `if ( dev && strcasecmp(dev, "ip") )` — the C single
        // condition; the nullptr-dev arm falls to the ip side EXACTLY
        // like C; the strcasecmp face -> the landed eq_ignore_ascii_case
        // precedent (text_log.rs:90):
        if let Some(dev) = dev {
            if !dev.eq_ignore_ascii_case("ip") {
                world.s_link = dnet.eth_open(dev); // cc :973 (dnet wall, DEV-009)

                // cppcheck-suppress knownConditionTrueFalse ; device open can fail in the packet I/O library
                if world.s_link.is_none() {
                    // cc :977 FatalError -> Err (DEV-008; C's
                    // never-returning shape; the printf legs hoisted
                    // before the call, eval-order hygiene natural):
                    let f = log.fatal_error(
                        "%s: can't open %s\n",
                        &[
                            Arg::S(Some(Cow::from("Active response"))),
                            Arg::S(Some(Cow::from(dev))),
                        ],
                    );
                    return Err(f);
                }

                world.s_send = SendKind::Eth; // cc :979 `s_send = send_eth`
            } else {
                world.s_ipnet = dnet.ip_open(); // cc :983

                // cppcheck-suppress knownConditionTrueFalse ; raw IP open can fail in the packet I/O library
                if world.s_ipnet.is_none() {
                    let f = log.fatal_error(
                        "%s: can't open ip\n",
                        &[Arg::S(Some(Cow::from("Active response")))],
                    ); // cc :987 (DEV-008)
                    return Err(f);
                }

                world.s_send = SendKind::Ip; // cc :989 `s_send = send_ip`
            }
        } else {
            world.s_ipnet = dnet.ip_open(); // cc :983 (the nullptr-dev C arm falls to the ip side)

            // cppcheck-suppress knownConditionTrueFalse ; raw IP open can fail in the packet I/O library
            if world.s_ipnet.is_none() {
                let f = log.fatal_error(
                    "%s: can't open ip\n",
                    &[Arg::S(Some(Cow::from("Active response")))],
                ); // cc :987 (DEV-008)
                return Err(f);
            }

            world.s_send = SendKind::Ip; // cc :989
        }
        Ok(world.s_link.is_some() || world.s_ipnet.is_some()) // cc :991 `return ( s_link or s_ipnet );`
    }

    /// cc :994-1004 `void Active::close()` (the handles TAKE-out + the
    /// two nullptr stores :1002-:1003 EXACT):
    pub fn close(world: &mut ActiveWorld) {
        if let Some(mut link) = world.s_link.take() {
            link.eth_close(); // cc :997
        }

        if let Some(mut net) = world.s_ipnet.take() {
            net.ip_close(); // cc :1000
        }

        world.s_link = None; // cc :1002 (the take() above already
        world.s_ipnet = None; // cleared; the stores ride C literal)
    }

    /// h :183 cc :1006-1015 `void Active::reset()` — the seven stores
    /// EXACT (the NSDMI cold seeds -> the ALLOW-side face, cited by the
    /// line pins):
    pub fn reset(&mut self) {
        self.active_tunnel_bypass = 0; // cc :1008
        self.active_status = AST_ALLOW; // cc :1009
        self.active_would_reason = WHD_NONE; // cc :1010
        self.active_action = ACT_ALLOW; // cc :1011
        self.delayed_active_action = ACT_ALLOW; // cc :1012
        self.delayed_reject = None; // cc :1013
        self.drop_reason = None; // cc :1014 (DEV-004 face)
    }

    /// h :119 cc :1017-1022 — the C `// cppcheck-suppress
    /// unusedFunction ; entry point retained for external, conditional,
    /// or test use` rides: `*p->action = nullptr;` (the DEV-002 clear
    /// leg) + clear_replacement (detection_engine.h:90, DEV-012):
    pub fn clear_queue(ctx: &mut ActiveCtx, p: &mut dyn ActivePacketFace) {
        p.clear_action(); // cc :1020
        ctx.detection.clear_replacement(); // cc :1021
    }

    /// h :120 cc :1024-1038 `void Active::execute(Packet* p)` — the C
    /// order is exec-THEN-clear (:1028/:1029); the take leg + the
    /// post-exec clear pair the order (DEV-002 swap-out) and the
    /// finalize_trust / session_was_trusted / trust trio:
    pub fn execute(&mut self, ctx: &mut ActiveCtx, p: &mut dyn ActivePacketFace) {
        let action = p.take_action(); // cc :1026 `if ( *p->action )`
        if let Some(mut a) = action {
            a.delayed_exec(p, ctx); // cc :1028
            p.clear_action(); // cc :1029
        }

        if p.flow_present() {
            // cc :1034 `p->flow->finalize_trust(*p->active)` (flow.h:442):
            if let Some(f) = p.flow_mut() {
                f.finalize_trust(self);
            }
            // cc :1035-1036 (the h :151-152 inline face):
            if self.session_was_trusted() && let Some(f) = p.flow_mut() {
                f.trust();
            }
        }
    }

    // -----------------------------------------------------------------------
    // h :185-188 / h :190-:191 / h :211 + cc :1040-1074 — the drop-
    // reason family (the C raw const char* first-wins law -> the
    // &'static str face, DEV-004):
    // -----------------------------------------------------------------------

    /// h :185 cc :1040-1043 `void Active::set_default_drop_reason
    /// (uint8_t reason_id)` (the static, cc :86 = -1 seed):
    pub fn set_default_drop_reason(world: &mut ActiveWorld, reason_id: u8) {
        world.default_drop_reason_id = reason_id as i32; // cc :1042
    }

    /// h :186 cc :1045-1048 `void Active::map_drop_reason_id(const
    /// char* verdict_reason, uint8_t id)` — the C `operator[]`
    /// default-insert-then-assign lands as insert (the FINAL cell map
    /// == [key]=id, identical observable face, cited):
    pub fn map_drop_reason_id(world: &mut ActiveWorld, verdict_reason: &'static str, id: u8) {
        world.drop_reason_id_map.insert(verdict_reason, id); // cc :1047
    }

    /// h :190-:191 `const char* get_drop_reason() { return
    /// drop_reason; }` (DEV-004 Option face):
    pub fn get_drop_reason(&self) -> Option<&'static str> {
        self.drop_reason
    }

    /// h :187 cc :1050-1054 `void Active::set_drop_reason(const char*
    /// reason)` — the FIRST-WINS law (`!drop_reason and
    /// !is_suspended()`):
    pub fn set_drop_reason(&mut self, world: &ActiveWorld, reason: &'static str) {
        if self.drop_reason.is_none() && !Active::is_suspended(world) {
            self.drop_reason = Some(reason); // cc :1053
        }
    }

    /// h :211 cc :1056-1063 `int Active::get_drop_reason_id()` (the C
    /// unordered_map::find -> ends leg; the -1 default rides the
    /// cc :86 seed):
    pub fn get_drop_reason_id(&self, world: &ActiveWorld) -> i32 {
        if let Some(reason) = self.drop_reason
            && let Some(id) = world.drop_reason_id_map.get(reason)
        {
            return *id as i32; // cc :1059-1060
        }

        world.default_drop_reason_id // cc :1062
    }

    /// h :188 cc :1065-1074 — the C `// cppcheck-suppress
    /// unusedFunction ; entry point retained for external, conditional,
    /// or test use` rides (the `reason != -1` gate + the C int ->
    /// uint8_t IMPLICIT narrowing on the landed set- leg,
    /// sfdaq_instance.rs:1147):
    pub fn send_reason_to_daq(
        &mut self,
        ctx: &mut ActiveCtx,
        p: &mut dyn ActivePacketFace,
    ) {
        if self.drop_reason.is_none() {
            return; // cc :1068-1069
        }

        let reason = self.get_drop_reason_id(ctx.world); // cc :1071 (the world reborrow pair)
        if reason != -1 {
            ctx.io.set_packet_verdict_reason(p.daq_msg(), reason as u8); // cc :1073
        }
    }
}

// ---------------------------------------------------------------------------
// h :86-:177 — THE inline accessor/setter surface (every item a one-
// liner in C, the braces-and-return face rides the cite; DEV-017 covers
// the two act_str getters' out-of-table NSDMI seeds):
// ---------------------------------------------------------------------------

impl Active {
    /// h :86-87 `ActiveActionType get_action() const`:
    pub fn get_action(&self) -> ActiveActionType {
        ActiveActionType::from(self.active_action)
    }

    /// h :89-90 `ActiveStatus get_status() const`:
    pub fn get_status(&self) -> ActiveStatus {
        ActiveStatus::from(self.active_status)
    }

    /// h :94-96 `bool can_act() const` (the C cppcheck-suppress
    /// unusedFunction ; installed packet-control API accessor rides):
    pub fn can_act(&self) -> bool {
        self.active_status == AST_ALLOW || self.active_status == AST_FORCE
    }

    /// h :98-99 `const char* get_action_string() const { return
    /// act_str[active_action][active_status]; }` — DEV-017: the C index
    /// pair is OUT OF TABLE under the NSDMI cold face (h :222-:224 seed
    /// ACT_MAX/AST_MAX = the row/col boundary); C is UB reading there,
    /// the in-table 32 cells are NEVER null -> the Option face:
    pub fn get_action_string(&self) -> Option<&'static str> {
        ACT_STR
            .get(self.active_action as usize)
            .and_then(|row| row.get(self.active_status as usize))
            .copied()
    }

    /// h :101-102 `get_delayed_action_string()` — same DEV-017 face off
    /// the delayed_active_action row:
    pub fn get_delayed_action_string(&self) -> Option<&'static str> {
        ACT_STR
            .get(self.delayed_active_action as usize)
            .and_then(|row| row.get(self.active_status as usize))
            .copied()
    }

    /// h :122-123 `void block_again()`:
    pub fn block_again(&mut self) {
        self.active_action = ACT_BLOCK;
    }

    /// h :125-126 `void reset_again()`:
    pub fn reset_again(&mut self) {
        self.active_action = ACT_RESET;
    }

    /// h :128-129 `void set_trust()`:
    pub fn set_trust(&mut self) {
        self.active_action = ACT_TRUST;
    }

    /// h :131-132 `void set_allow()`:
    pub fn set_allow(&mut self) {
        self.active_action = ACT_ALLOW;
    }

    /// h :134-135 `packet_was_dropped() const`: >= ACT_DROP:
    pub fn packet_was_dropped(&self) -> bool {
        self.active_action >= ACT_DROP
    }

    /// h :137-138 `packet_would_be_dropped() const`: == AST_WOULD:
    pub fn packet_would_be_dropped(&self) -> bool {
        self.active_status == AST_WOULD
    }

    /// h :140-141 `get_would_be_dropped_reason() const`:
    pub fn get_would_be_dropped_reason(&self) -> ActiveWouldReason {
        ActiveWouldReason::from(self.active_would_reason)
    }

    /// h :147-149 `packet_retry_requested() const` (C unusedFunction
    /// suppress rides): == ACT_RETRY:
    pub fn packet_retry_requested(&self) -> bool {
        self.active_action == ACT_RETRY
    }

    /// h :151-152 `session_was_trusted() const`:
    pub fn session_was_trusted(&self) -> bool {
        self.active_action == ACT_TRUST
    }

    /// h :154-155 `session_was_blocked() const`: >= ACT_BLOCK:
    pub fn session_was_blocked(&self) -> bool {
        self.active_action >= ACT_BLOCK
    }

    /// h :157-158 `session_was_allowed() const`: <= ACT_ALLOW:
    pub fn session_was_allowed(&self) -> bool {
        self.active_action <= ACT_ALLOW
    }

    /// h :160-161 `bool packet_force_dropped() const { return
    /// active_status == AST_FORCE; }` (read at cc :179, the
    /// kill_session unreach arm):
    pub fn packet_force_dropped(&self) -> bool {
        self.active_status == AST_FORCE
    }

    /// h :163-165 `is_packet_held() const` (C unusedFunction
    /// suppress rides): == ACT_HOLD:
    pub fn is_packet_held(&self) -> bool {
        self.active_action == ACT_HOLD
    }

    /// h :167-168 `set_tunnel_bypass()`:
    pub fn set_tunnel_bypass(&mut self) {
        self.active_tunnel_bypass += 1;
    }

    /// h :170-171 `clear_tunnel_bypass()`:
    pub fn clear_tunnel_bypass(&mut self) {
        self.active_tunnel_bypass -= 1;
    }

    /// h :173-174 `get_tunnel_bypass() const` (the C int face keeps
    /// the signed >-0 test literal):
    pub fn get_tunnel_bypass(&self) -> bool {
        self.active_tunnel_bypass > 0
    }

    /// h :176-177 `get_delayed_action() const`:
    pub fn get_delayed_action(&self) -> ActiveActionType {
        ActiveActionType::from(self.delayed_active_action)
    }
}