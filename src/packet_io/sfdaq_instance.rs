//! Flat, cite-heavy literal port of the row-23b REAL pair:
//! `packet_io/sfdaq_instance.h` 105 L (ground truth @ fe29cbe: md5
//! `9497f39441174c4260d4db22e55740bf`) + `packet_io/sfdaq_instance.cc`
//! 436 L (md5 `0b2a92f5b16344794714cfeda2cae8ed`) = 541 L — THE
//! SFDAQInstance per-instance DAQ session class: the ctor (id+1 1-based
//! law :45, batch read :46, alloc :47), the dtor destroy (:54), the
//! file-static validate (:57-:68) + the init ladder (set_input :77 ->
//! id gate :78-:79 -> instantiate :80 -> validate :91 -> set_filter
//! :96-:98), reload (:102-:115), the getters, the six can_* faces
//! (:133-:161), the start() ladder (:163-:196), the receive/finalize
//! accounting (:198-:222), inject (:289-:301), interrupt (:303-:306),
//! the stats walk (:308-:319), the raw ioctl (:321-:324), the three
//! DIOCTL record legs (:326-:362), the add_expected key ladder
//! (:365-:436 - the ONLY reader of the THREAD_LOCAL global `daq_stats`,
//! :433), was_started (:264-:271) and stop (:273-:287), and the private
//! get_tunnel_capabilities map (:229-:257).
//!
//! THE REAL-SDK LAW (row 23b = THE SEAM-CLOSE row; tools/sfinst_harness
//! PLAN.md carries the measured ledger): the ground .cc compiles
//! BYTE-EXACT (4 FRESH cps, cmp-proved, NEVER sed) against the REAL
//! libdaq SDK @ c8d4083 (api/daq.h 178 L md5 35294a1773477a9579c8494cb1dadfea,
//! api/daq_common.h 728 L md5 28789a3dc10b84c974118c38700755b4, api/daq_dlt.h
//! 209 L md5 57208729d55b02341367d7ff9c24b39d, api/daq_module_api.h 165 L
//! md5 1a617b3edef11431c9244bee728baadc + the sed-generated daq_version.h
//! 3.0.29 face) and links 5 REAL api .o
//! (daq_base / daq_base_api / daq_config / daq_instance_api_defaults /
//! daq_mod_ops). THE MEASURED nm face: the pair .o app-undef =
//! EXACTLY-32, of which 22 are the REAL daq_instance_*/daq_config_* SDK
//! dispatches ALL closed by the REAL api link — ZERO `SFDAQInstance::`
//! mirror residues (the 23a witness-mirror law DIES BY DESIGN HERE: the
//! harness flipped arm asserts grep-0 of that name). E4 wall faces:
//! the legacy-copy graft wall = 85 'was not declared' error lines
//! flipped-assert EVERY build (ZERO type-deaths — the honest pair-vs-
//! pair drift vs the 23a wall's 86/78+2 face, cited); the REAL face =
//! SILENT rc0 + RUNS; the trough sibling wall (the NOT-landed
//! helpers/directory seam) re-measures EVERY build = the row-pick arm.
//! Fresh-cp DECL riders: `sfdaq_module.h` 89 L md5
//! 2d53ba758a9c5be47865523dedc84983 (struct DAQStats :61 + `extern
//! THREAD_LOCAL DAQStats daq_stats` :87 OUTSIDE `namespace snort` — the
//! mangled-name law: the inside-ns form mints `_ZN5snort9daq_statsE` and
//! leaves the bare GLOBAL read by :433 undefined — + `expected_flows`
//! :82) and `sfdaq_config.h` 85 L md5 df8f1875e163d4a588d48195cfdbad4c
//! whose get_batch_size face (h :63; the landed 23a sfdaq_config.rs) the
//! ctor :46 reads.
//!
//! THE PROVIDER LAW (the cd_user.rs left-open precedent — DISCHARGED at
//! this row with MEASURED faces): DAQ_Instance_h / DAQ_Config_h are
//! opaque SDK handles over C fn-tables; the Rust port models them as
//! caller-supplied provider traits (`DaqCfgProvider`,
//! `DaqInstanceProvider`) — NEVER a fake loader, NO unsafe, NO dl* legs.
//! tools/sfinst_harness MEASURED the OPTIONAL-fn resolve defaults
//! (api/daq_mod_ops.c `resolve_instance_api`) on the stub module
//! (required-trio-only): caps 0 / check-status faces / start & stop
//! SUCCESS / get_error NULL (the `%s` log legs then print "(null)" at
//! cfmt — the harness `stats:  (-4)` double-space face pinned in faceA
//! stderr) / msg_finalize -7? NO — MEASURED per-leg below; the harness
//! STATE line `rinc=0 s_init=1 start=0 s_started=2 stop=0 s_stopped=3
//! pool=-4 dlt=0` + NULLFACE `caps=0 state=4 errnull=1 fin=-6 inj=-6
//! intr=-6` + the T11 stub rows pin every default ONE leg at a time:
//! the DefaultProvider note below carries the values.
//! tests/sfinst_parity_test.rs re-drives the harness DEC ladder BYTE-
//! EQUAL through the same scripts (pool 8/8, stats hw=7 rx=1 vblk=9,
//! the caps 0x1007c7 can_* walk, the ef=1/ef=2 global walk).
//!
//! THE GLOBAL-STATE LAW (NO static mut, NO unsafe, NO thread_local
//! copies of C pointers — the main/thread.rs ThreadState precedent): the
//! THREAD_LOCAL global `daq_stats` (sfdaq_module.h :87 — the pair reads/
//! bumps ONLY `expected_flows` at :433; the DEFINITION home
//! sfdaq_module.cc = NOT landed, the harness witness owns the C
//! definition face) lands as the packet_io-home `DAQ_STATS`
//! thread_local (deviation cited, KNOWN DEVIATIONS.md row 23b). The
//! conf faces `SnortConfig::get_conf()->adaptor_inline_mode()` (:61)
//! and `SnortConfig::log_verbose()` (:185) ride CALLER ARGS (the landed
//! sfdaq.rs seam-arg precedent); `get_instance_id()` (:188/:190; main/
//! thread.h get_instance_id NOT landed as a Rust fn face at this row —
//! thread_config.rs names it in cites only) rides an explicit arg. The
//! harness scripts pin BOTH faces (verbose FALSE logs NOTHING — the T2
//! face; the TRUE inline legs fire the T3b ParseWarning + the pool/
//! batch pair).
//!
//! THE 23a SEAM-CLOSE (the plan-23b heart): the 23a `DaqInstanceSeam`
//! trait (sfdaq.rs, LEFT-OPEN at 23a with scripted stand-ins in
//! the 23a parity twin test file) gains its REAL provider: `impl
//! DaqInstanceSeam for SFDAQInstance` lands HERE (both types crate-
//! local — lawful impl; the wiring doc rides mod.rs). From there EVERY
//! 23a wrapper leg (init_instance :347 / get_input_spec :366 / get_
//! base_protocol :371 / can_* :376-:392 / get_tunnel_bypass :391 /
//! inject :396 / get_stats :401 — sfdaq.cc faces) dispatches the
//! ported bodies through the 23a facade UNCHANGED (the trait signature
//! FROZEN at 23a — the seam legs take the seams the trait carries: see
//! the impl notes; the 23a parity twin's scripted SeamHandle face STAYS
//! (its legs never carried a real body) — the rider notes ride the
//! commit body, NEVER the harnesses (frozen build.sh law).

use std::borrow::Cow;
use std::cell::{Cell, RefCell};

use crate::codecs::cd_geneve::TUNNEL_GENEVE;
use crate::codecs::cd_gre::TUNNEL_GRE;
use crate::codecs::cd_gtp::{PROTO_BIT__GTP, TUNNEL_GTP};
use crate::codecs::cd_ipv4::{TUNNEL_4IN4, TUNNEL_4IN6};
use crate::codecs::cd_ipv6::{TUNNEL_6IN4, TUNNEL_6IN6};
use crate::codecs::cd_mpls::TUNNEL_MPLS;
use crate::codecs::cd_teredo::TUNNEL_TEREDO;
use crate::codecs::cd_vlan::PROTO_BIT__VLAN;
use crate::codecs::cd_vxlan::TUNNEL_VXLAN;
use crate::detection::rtn_checks::PROTO_BIT__MPLS; // :34 (the landed
                                                    // 0x000200 home;
                                                    // decode_data.h :96)
use crate::framework::codec::IpProtocol;
use crate::framework::counts::PegCount;
use crate::log::messages::{LogEngine, WARN_DAQ};
use crate::sfip::sf_ip::SfIp;
use crate::utils::cfmt::Arg;

use super::sfdaq::{DAQ_ERROR_INVAL, DAQ_ERROR_NOCTX, DAQ_RSTAT_ERROR, DAQ_STATE_STARTED,
                   MAX_DAQ_VERDICT};

// THE SEAM-CLOSE facade surface (cited wiring law; the bindings ride
// through the pub-use): the 23a trait + mirror + config types re-ride
// HERE so the 23b twins and the future consumer code wire the CLOSED
// seam through ONE file-name-free path (the token-census law: the test
// homes NEVER carry the C-file-name token — the mod.rs re-export block
// completes the path).
pub use super::sfdaq::DaqConfigMirror;
pub use super::sfdaq::DaqInstanceSeam;
pub use super::sfdaq_config::SFDAQConfig;

// ---------------------------------------------------------------------------
// THE SDK vocabulary the pair names (libdaq api/daq_common.h @ c8d4083;
// the CAPA / DIOCTL / EFLOW families land HERE — grep-0 across src/
// pre-row, re-walked by the parity twin; the 23a sfdaq.rs home already
// carries the error/verdict/state/rstat enums — import above). Values
// probe-pinned by tools/sfinst_harness vectors_faceA: CAPA line
// block=1 inject=4 inject_raw=200 unpriv=20 whitelist=8 replace=2
// inject_drop=100000 dsum=ffc00 (the 10-DECODE sum); DIO line sfo=2
// trace=6 reason=7 eflow=11 last=1024; EFLOW float=1 multi=2 persist=4
// bidir=8; EFLOW_TUNNEL_TYPE non=0 gtp=1 mpls=2 other=3; TUNNEL line
// gtp=1 teredo=2 6in4=4 4in6=8 4in4=16 6in6=32 gre=64 mpls=128 vxlan=256
// geneve=512 ceiling=1023 (the snort_config.h :119-:128 TunnelEncap
// enum face — the landed per-codec consts, the one-home law).
// ---------------------------------------------------------------------------

/// api/daq_common.h:196-:215 the DAQ_CAPA_* family VERBATIM (the six
/// can_* + :65 the validate BLOCK leg + the :236-:256 DECODE map).
pub const DAQ_CAPA_BLOCK: u32 = 0x0000_0001;
pub const DAQ_CAPA_REPLACE: u32 = 0x0000_0002;
pub const DAQ_CAPA_INJECT: u32 = 0x0000_0004;
pub const DAQ_CAPA_WHITELIST: u32 = 0x0000_0008;
pub const DAQ_CAPA_BLACKLIST: u32 = 0x0000_0010;
pub const DAQ_CAPA_UNPRIV_START: u32 = 0x0000_0020;
pub const DAQ_CAPA_INTERRUPT: u32 = 0x0000_0040;
pub const DAQ_CAPA_BPF: u32 = 0x0000_0080;
pub const DAQ_CAPA_DEVICE_INDEX: u32 = 0x0000_0100;
pub const DAQ_CAPA_INJECT_RAW: u32 = 0x0000_0200;
pub const DAQ_CAPA_DECODE_GTP: u32 = 0x0000_0400;
pub const DAQ_CAPA_DECODE_TEREDO: u32 = 0x0000_0800;
pub const DAQ_CAPA_DECODE_GRE: u32 = 0x0000_1000;
pub const DAQ_CAPA_DECODE_4IN4: u32 = 0x0000_2000;
pub const DAQ_CAPA_DECODE_6IN4: u32 = 0x0000_4000;
pub const DAQ_CAPA_DECODE_4IN6: u32 = 0x0000_8000;
pub const DAQ_CAPA_DECODE_6IN6: u32 = 0x0001_0000;
pub const DAQ_CAPA_DECODE_MPLS: u32 = 0x0002_0000;
pub const DAQ_CAPA_DECODE_VXLAN: u32 = 0x0004_0000;
pub const DAQ_CAPA_DECODE_GENEVE: u32 = 0x0008_0000;
pub const DAQ_CAPA_INJECT_DROP: u32 = 0x0010_0000;

/// api/daq_common.h:409/:413/:414/:418 the DIOCTL ordinals the legs
/// name (the pair passes them EXACT: :335/:348/:362/:435).
pub const DIOCTL_SET_FLOW_OPAQUE: u32 = 2;
pub const DIOCTL_SET_PACKET_TRACE_DATA: u32 = 6;
pub const DIOCTL_SET_PACKET_VERDICT_REASON: u32 = 7;
pub const DIOCTL_CREATE_EXPECTED_FLOW: u32 = 11;

/// api/daq_common.h:581-:584 the DAQ_EFLOW_* flag faces (the copy-
/// through trio :414-:422 IS literal; FLOAT + the legacy multi block =
/// the :419-:424 + the commented :424-:430 C++ blocks — cite-never-
/// land):
pub const DAQ_EFLOW_FLOAT: u32 = 0x01;
pub const DAQ_EFLOW_ALLOW_MULTIPLE: u32 = 0x02;
pub const DAQ_EFLOW_PERSIST: u32 = 0x04;
pub const DAQ_EFLOW_BIDIRECTIONAL: u32 = 0x08;

/// api/daq_common.h:554-:557 the EFLOW_TUNNEL_TYPE ordinals (OTHER
/// rides the COMMENTED FIXIT-L block :399-:403 — cite-never-land):
pub const DAQ_EFLOW_TUNNEL_TYPE_NON_TUNNEL: u8 = 0;
pub const DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL: u8 = 1;
pub const DAQ_EFLOW_TUNNEL_TYPE_MPLS_TUNNEL: u8 = 2;
pub const DAQ_EFLOW_TUNNEL_TYPE_OTHER_TUNNEL: u8 = 3;

// api/daq_common.h:342-:350 the DAQ_State values (the 23a enum home
// pins MAX_DAQ_STATE=5; the was_started hinge rides STARTED=2 — the
// faceA `state_started=2` re-pin rides the vectors, cite-only).

// ---------------------------------------------------------------------------
// sfdaq_module.h :61-:87 — the `struct DAQStats` face (the DECL rider;
// the definition law THREAD_LOCAL GLOBAL-scope: the mangled-name law
// cited at the top) + the pair's ONLY contact: `expected_flows` (:82;
// bumped at cc :433). The 22-field list rides cite-complete (the
// consumer walk = sfdaq_module.cc, NOT landed; PegCount = the landed
// counts.rs u64).
// ---------------------------------------------------------------------------

/// sfdaq_module.h:61-:85 `struct DAQStats` VERBATIM (verdicts[] rides
/// MAX_DAQ_VERDICT = 6, the 23a REAL-confirmed face).
#[derive(Debug, Default)]
pub struct DAQStats {
    pub pcaps: PegCount,            // :62
    pub received: PegCount,         // :63
    pub analyzed: PegCount,         // :64
    pub dropped: PegCount,          // :65
    pub filtered: PegCount,         // :66
    pub outstanding: PegCount,      // :67
    pub outstanding_max: PegCount,  // :68
    pub injected: PegCount,         // :69
    pub verdicts: [PegCount; MAX_DAQ_VERDICT as usize], // :70
    pub internal_blacklist: PegCount, // :71
    pub internal_whitelist: PegCount, // :72
    pub skipped: PegCount,          // :73
    pub idle: PegCount,             // :74
    pub rx_bytes: PegCount,         // :75
    /// :76 the CITE-mirror slot (the struct stays the honest 22-field
    /// face; the LIVE count rides the holder Cell below — cited):
    pub expected_flows: PegCount,
    pub retries_queued: PegCount,   // :77
    pub retries_dropped: PegCount,  // :78
    pub retries_processed: PegCount, // :79
    pub retries_discarded: PegCount, // :80
    pub sof_messages: PegCount,     // :81
    pub eof_messages: PegCount,     // :82-:83 block (struct rides 22
    pub other_messages: PegCount,   // fields; harness pypin modh[60]
                                    // struct-line + modh[86] extern)
}

// sfdaq_module.h:87 `extern THREAD_LOCAL DAQStats daq_stats` — the
// GLOBAL-face lands as packet_io-home thread_local (deviation cited).
// The bump leg (:433) `daq_stats.expected_flows++` mutates with NO
// owner: interior Cell on the LIVE count (the C same-need law; NO
// unsafe, NO static mut).
thread_local! {
    pub static DAQ_STATS: DAQStatsHolder = DAQStatsHolder::default();
}

#[derive(Debug, Default)]
pub struct DAQStatsHolder {
    pub stats: DAQStats,
    /// the LIVE count (the bump target; the struct slot rides the
    /// cite-mirror — the deviation pair cited):
    pub expected_flows: Cell<PegCount>,
}

impl DAQStatsHolder {
    /// cc :433 `daq_stats.expected_flows++` (the pair's ONLY global
    /// write; the harness T8 `ef=1` then T8b `ef=2` walk pins ORDER):
    pub fn stats_bump(&self) {
        self.expected_flows.set(self.expected_flows.get() + 1);
    }
}

/// the READ face for the replay twins + the stats consumers (the `ef=`
/// print legs):
pub fn daq_stats_expected_flows() -> PegCount {
    DAQ_STATS.with(|h| h.expected_flows.get())
}

// ---------------------------------------------------------------------------
// THE provider traits (the SDK-handle seam; the row-23b close of the
// 23a left-open law). A provider = the loaded DAQ module's instance-ops
// (the resolve-filled DAQ_InstanceAPI_t face, api/daq_mod_ops.c) over a
// per-instance context. EVERY leg face + DEFAULT is MEASURED at the row
// (the probe's "inst" full-API module + the "stub" required-trio-only
// module; the harness vectors STATE/NULLFACE/T11 rows pin each one leg
// at a time). Msg handles: the opaque DAQ_Msg_h rides u64 (0 = the
// nullptr face; providers mint NON-ZERO — the probe msg_store law).
// ---------------------------------------------------------------------------

/// The three DAQ_Config_h legs init rides (:77-:79; the SFDAQ::init
/// push ladder = the 23a mirror home; the seam adapter lands at the
/// trait impl below).
pub trait DaqCfgProvider {
    /// :77 `daq_config_set_input(daqcfg, input_spec.c_str())` — the
    /// SDK stores; the provider owns the record face (:81's error
    /// print reads the INSTANCE-side input_spec back, NOT the cfg —
    /// the pair never reads the cfg face back).
    fn set_input(&mut self, spec: &str);
    /// :78 `daq_config_get_total_instances(daqcfg) > 0` — the
    /// multi-instance gate.
    fn get_total_instances(&self) -> u32;
    /// :79 `daq_config_set_instance_id(daqcfg, instance_id)` — THE SDK
    /// WINDOW LAW (api/daq_base.h inline: stores ONLY when `instance_
    /// id < total_instances`; a violation leaves id 0 and the NEXT
    /// instantiate lands the SDK sanity gate — daq_mod_ops.c:186
    /// `snprintf(errbuf, len, "Can't instantiate with an invalid
    /// instance ID!")` + the INVAL face; the harness T1b legs pin the
    /// errbuf + (-7); the provider carries the gate — the pair NEVER
    /// sees the internals, cite).
    fn set_instance_id(&mut self, snort_id: u32);
}

/// The DAQ_Instance_h legs the pair dispatches (the full DAQ_
/// InstanceAPI_t surface the resolve ladder fills). DEFAULT RESOLVE
/// FACES (MEASURED at the row, stub legs — api/daq_mod_ops.c
/// resolve_instance_api): instantiate/destroy/check_status = the
/// REQUIRED trio (da_instance_instantiate ALWAYS resolves via the
/// module; the STATE legs start/stop = SUCCESS defaults: `start=0
/// stop=0` with the status walk INITIALIZED(1) -> STARTED(2) ->
/// STOPPED(3); caps() default 0 (NULLFACE caps=0); get_error default
/// NULL (NULLFACE errnull=1 — the `%s` legs render "(null)" downstream
/// at cfmt — the T11 `stats:  (-4)` face); msg_finalize / inject_
/// relative / interrupt defaults = DAQ_ERROR_NOCTX(-6) (NULLFACE
/// fin=-6 inj=-6 intr=-6 — the CONTEXT-missing defaults, MEASURED,
/// NOT the NOTSUP guess); get_msg_pool_info default NOTSUP (STATE
/// pool=-4 + T11); get_datalink_type default DLT_NULL (STATE dlt=0 +
/// h :100 dlt=-1 NEVER-read face); set_filter default NOTSUP (the
/// faceA fatal driver: `Couldn't set DAQ instance (iface) BPF filter
/// to 'vlan 7':  (-4)` stderr face + the jumped=1 control face);
/// config_load/swap/free + get_stats default NOTSUP (T11 statelog
/// leg); msg_receive default = the zero-count face (cite; NEVER pin-
/// driven, the pair's receive legs run on the "inst" script).
pub trait DaqInstanceProvider {
    /// daq_instance_instantiate (REQUIRED): Err((rval, errbuf)) — the
    /// SDK-gate + module-fail faces (`Couldn't construct a DAQ
    /// instance (%s): %s (%d)` at :82-:85 rides BOTH through the SAME
    /// leg).
    fn instantiate(&mut self) -> Result<(), (i32, String)>;
    /// daq_instance_destroy (REQUIRED; the dtor leg :54 — no return):
    fn destroy(&mut self);
    /// daq_instance_check_status (REQUIRED): the state face
    /// (DAQ_STATE_* values; the was_started hinge :270):
    fn check_status(&self) -> u32;
    /// daq_instance_start (default SUCCESS — the resolved default
    /// pair; the faceA STATE `start=0` + s_started):
    fn start(&mut self) -> i32;
    /// daq_instance_stop (default SUCCESS — STATE `stop=0` s_stopped):
    fn stop(&mut self) -> i32;
    /// daq_instance_get_capabilities (0 default):
    fn get_capabilities(&self) -> u32;
    /// daq_instance_get_error (NULL default):
    fn get_error(&self) -> Option<String>;
    /// daq_instance_set_filter (NOTSUP default):
    fn set_filter(&mut self, bpf_string: &str) -> i32;
    /// daq_instance_get_msg_pool_info (NOTSUP default; Ok((size,
    /// available)) — the harness pool 8/8 pin):
    fn get_msg_pool_info(&mut self) -> Result<(u32, u32), i32>;
    /// daq_instance_msg_receive (returns (handle-count face, rstat) —
    /// the SDK fills the daq_msgs slots; the Rust face hands back the
    /// handles the pair stores at :206-:208 accounting):
    fn msg_receive(&mut self, max_recv: u32) -> (Vec<u64>, u32);
    /// daq_instance_msg_finalize (NOCTX default):
    fn msg_finalize(&mut self, msg: u64, verdict: u32) -> i32;
    /// daq_instance_inject_relative (NOCTX default; :294 legs the
    /// (msg, buf, len, rev) faces):
    fn inject_relative(&mut self, msg: u64, buf: &[u8], rev: i32) -> i32;
    /// daq_instance_interrupt (NOCTX default → FALSE face pinned):
    fn interrupt(&mut self) -> i32;
    /// daq_instance_get_stats (NOTSUP default; OUT-store face — :312
    /// `daq_instance_get_stats(instance, &daq_instance_stats)` fills
    /// the LOCAL record on SUCCESS):
    fn get_stats(&mut self, s: &mut DaqStatsRecord) -> i32;
    /// daq_instance_get_datalink_type (DLT_NULL default):
    fn get_datalink_type(&mut self) -> i32;
    /// daq_instance_config_load (NOTSUP default → the reload legs
    /// NEVER fire):
    fn config_load(&mut self) -> Result<(), i32>;
    /// daq_instance_config_swap (NOTSUP default):
    fn config_swap(&mut self) -> Result<(), i32>;
    /// daq_instance_config_free (the reload free legs — the C passes
    /// old-vs-new; the trait keeps one free leg, the harness T9 `f=1`
    /// pins ONE free per path, deviation cited):
    fn config_free(&mut self);
    /// daq_instance_ioctl (:323/:335/:348/:362/:435 — the record faces
    /// marshal over DaqIoctlReq; the C `sizeof` rides the provider
    /// side, cited):
    fn ioctl(&mut self, cmd: u32, req: &mut DaqIoctlReq<'_>) -> i32;
}

/// The DIOCTL record union the four legs marshal (the MEASURED C sizes
/// sfo=16 spvr=16 sptd=24 cef=88 ride the vectors faceA `SIZES` line —
/// the parity twin mirrors the field faces, NEVER size_of-as-pin).
#[derive(Debug)]
pub enum DaqIoctlReq<'a> {
    /// DIOCTL_SetFlowOpaque — api/daq_common.h:451-:454 (msg, value):
    SetFlowOpaque { msg: u64, value: u32 },
    /// DIOCTL_SetPacketVerdictReason — :498-:502 (msg, verdict_reason):
    SetPacketVerdictReason { msg: u64, verdict_reason: u8 },
    /// DIOCTL_SetPacketTraceData — :484-:490 (msg, trace_data ptr +
    /// trace_data_len):
    SetPacketTraceData { msg: u64, trace_data: &'a [u8] },
    /// DIOCTL_CreateExpectedFlow — :586-:598:
    CreateExpectedFlow(DdaqIoctlCreateExpectedFlow),
}

/// The DIOCTL_CreateExpectedFlow record (the :369-:435 build legs). The
/// C `data`/`length` pair (:429-:430 `d_cef.data = nullptr; d_cef.
/// length = 0;` — the NEVER-populated blob) rides ABSENT (the record
/// has NO dead field pair; deviation cited — every leg is the null/0
/// face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdaqIoctlCreateExpectedFlow {
    pub ctrl_msg: u64, // :372 `d_cef.ctrl_msg = ctrlPkt->daq_msg`
    pub key: DdaqEFlowKey,
    pub flags: u32, // :415-:430 build face
    pub timeout_ms: u32, // :427-:428 face (`d_cef.timeout_ms =
                         // timeout_ms` + the unused-arg honesty:
                         // timeout_ms rides through, cite)
}

/// The DAQ_EFlow_Key_t face (api/daq_common.h:567-:579; faceA OFFS
/// line MEASURED: key=56, src_af=0 dst_af=2 sa=4 da=20 proto=36
/// sport=38 dport=40 as=44 tun=48 vlan=50 cnots=52 — the parity twin
/// re-maps these faces through its mirror struct, NEVER size_of-as-
/// pin). `address_space_id` EXISTS at off 44 (the 22b wall face CLOSED
/// at 23a) and is NEVER populated here (cc :391 FIXIT-M law — the zero
/// face rides, NEVER garbage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdaqEFlowKey {
    pub src_af: u16,  // :377 `key->src_af = cliIP->get_family()`
    pub dst_af: u16,  // :385 face
    /// sa / da = the DAQ_EFlow_AddrUnion_t faces (16 B): the v4 leg
    /// :378-:379 `key->sa.src_ip4.s_addr = get_ip4_value()` stores the
    /// 4 NET-order octets AT THE UNION HEAD (the sfip get_ip4_value
    /// face = ip32_raw(3) = the network-order word — the landed law);
    /// the v6 leg :380-:382 `memcpy(&key->sa.src_ip6, get_ip6_ptr(),
    /// sizeof)` = the 16-octet copy (the landed SfIp ip8 face):
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16, // :383
    pub dst_port: u16, // :389
    pub protocol: u8,  // :410-:411 (`key->protocol = (uint8_t)protocol`)
    pub address_space_id: u32, // NEVER-FILL (:391), off 44 EXISTS
    pub tunnel_type: u8, // :394-:405 chain (:406-:408 ELSE face)
    pub vlan_id: u16,    // :406-:409 (ELSE 0xFFFF)
    pub vlan_cnots: u8,  // :410 `key->vlan_cnots = 1`
}

/// The DAQ_Stats_t face (api/daq_common.h:351-:361, SIZES stats=96;
/// h :101 `DAQ_Stats_t daq_instance_stats = { }` — the all-zero
/// initial face the NOTSUP default leg LEAVES untouched).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaqStatsRecord {
    pub hw_packets_received: u64,
    pub hw_packets_dropped: u64,
    pub packets_received: u64,
    pub packets_filtered: u64,
    pub packets_injected: u64,
    pub packets_outstanding: u64,
    pub verdicts: [u64; MAX_DAQ_VERDICT as usize],
}

impl Default for DaqStatsRecord {
    fn default() -> Self {
        DaqStatsRecord {
            hw_packets_received: 0,
            hw_packets_dropped: 0,
            packets_received: 0,
            packets_filtered: 0,
            packets_injected: 0,
            packets_outstanding: 0,
            verdicts: [0; MAX_DAQ_VERDICT as usize],
        }
    }
}

// ---------------------------------------------------------------------------
// THE class (h :39-:103). FIELDS ride the C list EXACT (h :91-:102):
// the h :93 `DAQ_Instance_h instance = nullptr` rides the provider
// slot; the h :94 `DAQ_Msg_h* daq_msgs = nullptr` batch-alloc face
// rides a handle Vec (the h :56-:59 inline walk reads slots; delete[]
// :52 = the clear leg). One rider field `pending` (the C++ pair takes
// the module-table-loaded face at instantiate time; the Rust port
// injects the provider pre-init — the cd_user provider law; the
// nullptr-guard faces reload :104 / was_started :266 / get_stats :310
// / get_tunnel_capabilities :232 read `instance` ONLY = the post-
// instantiate face, EXACT preserved).
//
// clippy law: NO allows — the C add_expected 8-arg signature (:367-
// :368) packs into DaqExpectedFlowRequest (deviation cited; every
// field named by the C arg list + the two Packet legs the body READS).
// ---------------------------------------------------------------------------

pub struct SFDAQInstance {
    // h :91 `std::string input_spec` (ctor :42-:43 nullptr -> "" face):
    input_spec: String,
    // h :92 `uint32_t instance_id = 0` (ctor :45 `id + 1`):
    instance_id: u32,
    // h :93 `DAQ_Instance_h instance = nullptr`:
    instance: Option<Box<dyn DaqInstanceProvider>>,
    // rider (cited): the provider BEFORE instantiate:
    pending: Option<Box<dyn DaqInstanceProvider>>,
    // h :94 `DAQ_Msg_h* daq_msgs = nullptr` (ctor :47 alloc):
    daq_msgs: Vec<u64>,
    // h :95 `unsigned curr_batch_size = 0`:
    curr_batch_size: u32,
    // h :96 `unsigned curr_batch_idx = 0`:
    curr_batch_idx: u32,
    // h :97 `uint32_t batch_size = 0`:
    batch_size: u32,
    // h :98 `uint32_t pool_size = 0`:
    pool_size: u32,
    // h :99 `uint32_t pool_available = 0`:
    pool_available: u32,
    // h :100 `int dlt = -1` — the NEVER-read initial face (the vectors
    // `base=-1` pin; start :192 overwrites):
    dlt: i32,
    // h :101 `DAQ_Stats_t daq_instance_stats = { }`:
    daq_instance_stats: DaqStatsRecord,
    // h :102 `uint16_t daq_tunnel_mask = 0`:
    daq_tunnel_mask: u16,
    /// rider (cited; the seam-adapter conf face): the
    /// SnortConfig::get_conf()->adaptor_inline_mode() seam the cc :61
    /// leg reads — NONE lands HERE (the seam NEVER gates: the
    /// validate leg is ALWAYS-true BOTH ways); the seam legs ride
    /// FALSE, the harness T3b face re-drives the TRUE arg at the PAIR
    /// level (the explicit-arg law); a setter exists for honest future
    /// wiring, NEVER used by the DEC replay:
    adaptor_inline: bool,
}

/// the conf-seam wiring rider (the harness T3b legs drive the TRUE
/// face through the pair-level init arg instead — the seam face):
impl SFDAQInstance {
    pub fn set_adaptor_inline(&mut self, v: bool) {
        self.adaptor_inline = v;
    }
}

/// The add_expected request face (the :367-:368 8-arg C signature +
/// the TWO Packet legs the body READS: `daq_msg` at :372 +
/// `proto_bits` at :394/:406 — framework/codec.rs RawData carries the
/// daq_msg-drop law, so the handle + bits ride the request (deviation
/// cited); `layer::get_vlan_layer(ctrlPkt)->vid()` (:407) = the NOT-
/// landed protocols/layer.cc seam (the harness witness face: vid() =
/// the ntohs-0xFFF masked face pinned `vlan=ffa` via the request slot,
/// deviation cited):
#[derive(Debug, Clone)]
pub struct DaqExpectedFlowRequest {
    pub ctrl_msg: u64,
    pub ctrl_proto_bits: u32,
    pub cli_ip: SfIp,
    pub cli_port: u16,
    pub srv_ip: SfIp,
    pub srv_port: u16,
    pub protocol: IpProtocol,
    pub timeout_ms: u32,
    pub flags: u32,
    /// the :407 vlan leg ARRIVED pre-read (read ONLY when the VLAN bit
    /// set, :406):
    pub vlan_vid: u16,
}

impl SFDAQInstance {
    /// cc :40-:49 the ctor: :42-:43 `if (input) input_spec = input`
    /// (nullptr -> the EMPTY String face); :45 `instance_id = id + 1`
    /// (the 0-based Snort vs 1-based DAQ law — the vectors T1 iid=2
    /// from id=1 pin); :46 `batch_size = cfg->get_batch_size()` — THE
    /// with_config rider = the landed 23a SFDAQConfig::get_batch_size
    /// (sfdaq_config.rs :168-:174, the h :63 UNSET->DEFAULT face —
    /// the vectors bs=64 from a UNSET batch pin); :47 `daq_msgs = new
    /// DAQ_Msg_h[batch_size]` = the SAME-length zero-handle Vec (the
    /// dtor :52 delete[] = the clear face; deviation cited).
    pub fn new(input: Option<&str>, id: u32, config: &SFDAQConfig) -> Self {
        SFDAQInstance {
            input_spec: input.unwrap_or_default().to_string(),
            instance_id: id + 1,
            instance: None,
            pending: None,
            daq_msgs: vec![0; config.get_batch_size() as usize],
            curr_batch_size: 0,
            curr_batch_idx: 0,
            batch_size: config.get_batch_size(),
            pool_size: 0,
            pool_available: 0,
            dlt: -1,
            daq_instance_stats: DaqStatsRecord::default(),
            daq_tunnel_mask: 0,
            adaptor_inline: false,
        }
    }

    /// THE provider-attach rider (the C++ module-table face; the Rust
    /// seam close injects the provider BEFORE init — cited):
    pub fn attach_provider(&mut self, provider: Box<dyn DaqInstanceProvider>) {
        self.pending = Some(provider);
    }

    /// the instance_id READ face the provider legs ride (the SDK
    /// gate-side needs `instance_id`; harness iid=2):
    pub fn instance_id(&self) -> u32 {
        self.instance_id
    }

    /// cc :50-:55 the dtor: :52 `delete[] daq_msgs` (the clear) then
    /// :53-:54 `if (instance) daq_instance_destroy(instance)`. NO
    /// Drop-impl (cited: the C++ implicit member dtor face; the Rust
    /// leg stays EXPLICIT so the destroy-count faces ride: the harness
    /// T12 destroy counts pin the Some leg exactly once).
    pub fn dtor(&mut self) {
        self.daq_msgs.clear();
        if let Some(mut inst) = self.instance.take() {
            inst.destroy();
        }
    }

    /// cc :57-:68 the file-static `bool DAQ_ValidateInstance(DAQ_
    /// Instance_h)`: :59 caps read; :61-:62 `if (!get_conf()->adaptor_
    /// inline_mode()) return true` (the CONF seam arg; the FALSE-conf
    /// -> TRUE early face the DEFAULT legs ride); :64-:66 the BLOCK-caps
    /// `ParseWarning(WARN_DAQ, "inline mode configured but DAQ can't
    /// block packets.\n")` leg (the T3b wpw pin + the parse_warnings
    /// counter face — the landed messages.rs :203-:212 leg); :67
    /// `return true` — the function NEVER gates the ladder BOTH ways
    /// (the harness face: a BLOCK-less module CONTINUES — the vectors
    /// `init=1` under inline TRUE pin the honest ALWAYS-true face).
    pub fn validate_instance(caps: u32, adaptor_inline_mode: bool, log: &mut LogEngine) -> bool {
        if !adaptor_inline_mode {
            return true; // :61-:62
        }
        if caps & DAQ_CAPA_BLOCK == 0 {
            // the WARN_DAQ group arg EXACT (log/messages.h :74-:98 the
            // group enum; parse_warning's wg leg = the landed
            // messages.rs :203 face):
            log.parse_warning(
                WARN_DAQ,
                "inline mode configured but DAQ can't block packets.\n",
                &[],
            );
        }
        true // :67 (the file-static returns true regardless — the
             // cppcheck-suppress :90 comment face cites the loaded-
             // module validation truth)
    }

    /// cc :70-:101 init (h :45 `bool init(DAQ_Config_h, const std::
    /// string&)`): :72 `char buf[256] = ""` -> the provider Err tuple
    /// String face; :77 set_input; :78-:79 the `> 0` id gate; :80-:87
    /// the instantiate leg: FAIL -> :82-:85 `ErrorMessage("Couldn't
    /// construct a DAQ instance (%s): %s (%d)\n", input_spec, buf,
    /// rval)` + :87 `return false` (the T1b pin: errbuf = the REAL SDK
    /// gate string `Can't instantiate with an invalid instance ID!` +
    /// (-7) — the SDK-side speech, the pair NEVER owns it); :91-:92
    /// the validate call (the TRUE face; a TRUE return NEVER gates —
    /// the harness `knownConditionTrueFalse` suppress cites it);
    /// :94-:98 the NON-empty bpf leg: set_filter FAIL -> `FatalError
    /// ("Couldn't set DAQ instance (%s) BPF filter to '%s': %s (%d)"
    /// , input_spec, bpf, daq_instance_get_error(), rval)` — the
    /// landed LogEngine fatal_error (:317) renders the IDENTICAL cfmt
    /// face (the NULL get_error -> the `(null)` face — the faceA
    /// stderr pin); THE NEVER-returns law (messages.h :105
    /// [[noreturn]] — the fatal_error returns the Fatal face HERE and
    /// init CONTINUES to :100 `return true` = the harness jumped-or-
    /// continues control face at BOTH -O levels (the 23b noreturn
    /// rider face, cited in the harness PLAN §5: the REAL snort exits;
    /// the port surfaces the Fatal face, driver-owned); :100 true.
    pub fn init(
        &mut self,
        cfg: &mut dyn DaqCfgProvider,
        bpf_string: &str,
        adaptor_inline_mode: bool,
        log: &mut LogEngine,
    ) -> bool {
        // :76 `int rval` rides the legs.
        cfg.set_input(&self.input_spec); // :77
        if cfg.get_total_instances() > 0 {
            cfg.set_instance_id(self.instance_id); // :78-:79
        }
        let mut provider = match self.pending.take() {
            Some(p) => p,
            None => return false, // NEVER reached: the attach law (the
                                  // C++ pair ALWAYS carries the loaded-
                                  // module face; cited provider law)
        };
        let instance: &mut dyn DaqInstanceProvider = &mut *provider;
        if let Err((rval, errbuf)) = instance.instantiate() {
            log.error_message(
                "Couldn't construct a DAQ instance (%s): %s (%d)\n",
                &[
                    Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                    Arg::S(Some(Cow::from(errbuf.as_str()))),
                    Arg::I(rval as i64),
                ],
            );
            return false; // :87 — the provider drops HERE (the C++
                          // never ASSIGNED instance: the nullptr face
                          // stands — the C++ leaks no SDK handle
                          // because instantiate never created one;
                          // the Rust provider drop = the same face)
        }
        self.instance = Some(provider);
        // :91-:92 validate (the caps face :59):
        let caps = self.daq_caps();
        Self::validate_instance(caps, adaptor_inline_mode, log);
        // :94-:98 the bpf legs (EMPTY string: :358 face NEVER touched):
        if !bpf_string.is_empty() {
            let inst = self.instance.as_mut().expect("the Some-instantiated face");
            let rval = inst.set_filter(bpf_string);
            if rval != 0 {
                let err = inst.get_error();
                let _ = log.fatal_error(
                    "Couldn't set DAQ instance (%s) BPF filter to '%s': %s (%d)\n",
                    &[
                        Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                        Arg::S(Some(Cow::from(bpf_string))),
                        Arg::S(err.as_deref().map(Cow::from)), // NULL ->
                        // cfmt "(null)" face (the faceA stderr `:  (-4)`
                        // double-space pin rides)
                        Arg::I(rval as i64),
                    ],
                ); // the NEVER-returns law: Fatal face SURFACED,
                   // CONTINUES to the true face (cited above)
            }
        }
        true // :100 `return true`
    }

    /// cc :102-:116 reload: :103-:105 `if (!instance) return` (the h
    /// :93 nullptr face — the pre-init reload guard, the vectors T9x
    /// guard pin); :108-:114 the config_load -> config_swap -> config_
    /// free ladder: load FAIL -> NOTHING; swap OK -> free(old) :112;
    /// swap FAIL -> free(new) :114 (the T9 face `l=2 s=1 f=1` = the
    /// SUCCESS swap -> EXACTLY ONE free — the trait's single free leg
    /// face, deviation cited at the trait).
    pub fn reload(&mut self) {
        let inst = match self.instance.as_mut() {
            Some(i) => i,
            None => return,
        };
        if let Ok(()) = inst.config_load() {
            if inst.config_swap().is_ok() {
                inst.config_free(); // :112 frees old_config
            } else {
                inst.config_free(); // :114 frees new_config
            }
        }
    }

    /// cc :118-:121 `const char* get_input_spec() const` (h :66):
    pub fn get_input_spec(&self) -> &str {
        &self.input_spec
    }

    /// h :64 `int get_batch_size() const { return batch_size; }` + h
    /// :65 pool:
    pub fn get_batch_size(&self) -> u32 {
        self.batch_size
    }
    pub fn get_pool_available(&self) -> u32 {
        self.pool_available
    }

    /// cc :127-:131 `int get_base_protocol() const { return dlt; }` (h
    /// :63) — the cached-datalink law (the file comment :123-:126
    /// rides as prose cite: the pcap-file dlt face may need the START,
    /// cache because shutdown needs it):
    pub fn get_base_protocol(&self) -> i32 {
        self.dlt
    }

    /// cc :133-:161 the six can_* faces (h :69-:74; `can_whitelist` =
    /// the SO_PUBLIC h :74 face): EVERY leg reads
    /// `daq_instance_get_capabilities(instance) & BIT` — the UN-guarded
    /// instance DEREF; the nullptr face = the SDK-0 caps face OBSERVED
    /// (NULLFACE caps=0 re-walk; the pair NEVER null-guards — the Rust
    /// None read OBSERVES the same 0, deviation-free by faceA):
    pub fn can_inject(&self) -> bool {
        self.daq_caps() & DAQ_CAPA_INJECT != 0 // :135
    }
    pub fn can_inject_raw(&self) -> bool {
        self.daq_caps() & DAQ_CAPA_INJECT_RAW != 0 // :140
    }
    pub fn can_replace(&self) -> bool {
        self.daq_caps() & DAQ_CAPA_REPLACE != 0 // :145
    }
    pub fn can_start_unprivileged(&self) -> bool {
        self.daq_caps() & DAQ_CAPA_UNPRIV_START != 0 // :150
    }
    pub fn can_whitelist(&self) -> bool {
        self.daq_caps() & DAQ_CAPA_WHITELIST != 0 // :155
    }
    pub fn can_invoke_inject_drop(&self) -> bool {
        self.daq_caps() & DAQ_CAPA_INJECT_DROP != 0 // :160
    }

    /// the caps READ seam (the unguarded-0 face cited above):
    fn daq_caps(&self) -> u32 {
        self.instance.as_ref().map(|i| i.get_capabilities()).unwrap_or(0)
    }

    /// cc :163-:196 start(): :165-:170 the start leg FAIL -> :167-:168
    /// `ErrorMessage("Couldn't start DAQ instance (%s): %s (%d)",
    /// input_spec, get_error(), rval)` + false (the T11 `start=0
    /// was=0` start-TRUE pair; the pool-Fail arm's re-stop `start_err=
    /// []` face pins the stub status legs); :172-:180 the pool-info
    /// leg: NOTSUP -> :174-:175 `ErrorMessage("Couldn't query DAQ
    /// message pool info (%s): %s (%d)"...)` + :177 `stop()` + false
    /// (the T-start-fail pin: the stop legs run SILENT — the stub STOP
    /// SUCCESS + the was_started false face NEVER fires the stop log);
    /// :182-:183 `pool_size/pool_available = mpool_info.*`; :184
    /// `assert(pool_size == pool_available)` — the NDEBUG DEAD face
    /// (the harness -DNDEBUG compiles assert() OUT; NEVER replicated —
    /// the scripts honor the equality face); :185-:192 `if (SnortConfig
    /// ::log_verbose())` the `%d daq pool size: %d` / `... batch size:
    /// %d` pair (log_message_stdout = the landed STDOUT legs;
    /// get_instance_id() = the explicit seam ARG; the FALSE face logs
    /// NOTHING — the T2 pin); :192 `dlt = daq_instance_get_datalink_
    /// type(instance)`; :193 get_tunnel_capabilities(); :195-:196
    /// `return (rval == DAQ_SUCCESS)` — the start-rval face after the
    /// pool-success path = TRUE.
    pub fn start(&mut self, log_verbose: bool, instance_id: u32, log: &mut LogEngine) -> bool {
        let inst = match self.instance.as_mut() {
            Some(i) => i,
            None => return false, // the unguarded-DEREF collapse face
                                  // (cited; NEVER harness-driven — the
                                  // vectors pin the Some legs)
        };
        let rval = inst.start(); // :165
        if rval != 0 {
            let err = inst.get_error();
            log.error_message(
                "Couldn't start DAQ instance (%s): %s (%d)\n",
                &[
                    Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                    Arg::S(err.as_deref().map(Cow::from)),
                    Arg::I(rval as i64),
                ],
            );
            return false; // :170
        }
        match inst.get_msg_pool_info() {
            Ok((size, available)) => {
                self.pool_size = size;     // :182
                self.pool_available = available; // :183
            }
            Err(e) => {
                // the C leg order: the ErrorMessage FIRST, the stop()
                // SECOND: scope the provider borrow so it releases
                // BEFORE self.stop() re-borrows (the C pointer re-entry
                // has no alias law; the borrow-shape deviation cited):
                let (err, rval_msg) = {
                    let inst = self.instance.as_mut().expect("the Some face");
                    (inst.get_error(), e)
                };
                log.error_message(
                    "Couldn't query DAQ message pool info (%s): %s (%d)\n",
                    &[
                        Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                        Arg::S(err.as_deref().map(Cow::from)),
                        Arg::I(rval_msg as i64),
                    ],
                );
                self.stop(log); // :177 (the re-entry; the stub legs:
                                // check_status NOT-STARTED -> the TRUE-
                                // early face -> SILENT, pinned)
                return false; // :179
            }
        }
        // :184 the assert NDEBUG DEAD face (cited):
        if log_verbose {
            log.log_message_stdout(
                "DAQ instance (%s) %d daq pool size: %d\n", // :187-:188
                &[
                    Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                    Arg::I(instance_id as i64), // get_instance_id seam
                    Arg::I(self.pool_size as i64),
                ],
            );
            log.log_message_stdout(
                "DAQ instance (%s) %d daq batch size: %d\n", // :190-:191
                &[
                    Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                    Arg::I(instance_id as i64),
                    Arg::I(self.batch_size as i64),
                ],
            );
        }
        self.dlt = self.instance.as_mut().expect("the Some face").get_datalink_type(); // :192
        self.get_tunnel_capabilities(); // :193 + the private decl h :89
        true // :195-:196 `return (rval == DAQ_SUCCESS)` — the start-
             // SUCCESS face reached (the pool legs overwrote rval? NO
             // — the C returns the START rval: the face TRUE)
    }

    /// cc :264-:271 was_started (h :48): :266-:268 `if (!instance)
    /// return false` — the guard EXISTS HERE (the can_* legs do NOT
    /// guard — the :270 check + `s == DAQ_STATE_STARTED` hinge (the
    /// faceA STATE walk pins the TRUE leg, the NULLFACE state=4 the
    /// false):
    pub fn was_started(&self) -> bool {
        match &self.instance {
            None => false, // :266-:268
            Some(i) => i.check_status() == DAQ_STATE_STARTED, // :270
        }
    }

    /// cc :273-:287 stop(): :275 `assert(pool == avail)` NDEBUG DEAD
    /// face (cited); :277-:279 `if (!was_started()) return true` — the
    /// TRUE-early face (the T11 `stop=1` stub NOT-STARTED pin + the
    /// started pair); :281-:285 the stop leg + the FAIL-side
    /// `LogMessage("Couldn't stop DAQ instance (%s): %s (%d)")` — the
    /// LOG legs NEVER gate; :286 `return (rval == DAQ_SUCCESS)`:
    pub fn stop(&mut self, log: &mut LogEngine) -> bool {
        if !self.was_started() {
            return true; // :277-:279
        }
        let inst = self.instance.as_mut().expect("the was_started face");
        let rval = inst.stop(); // :281
        if rval != 0 {
            let err = inst.get_error();
            log.log_message_stdout(
                "Couldn't stop DAQ instance (%s): %s (%d)\n",
                &[
                    Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                    Arg::S(err.as_deref().map(Cow::from)),
                    Arg::I(rval as i64),
                ],
            );
        }
        rval == 0 // :286
    }

    /// cc :198-:211 receive_messages (h :52 `receive_messages(unsigned
    /// max_recv)`): :200 `assert(max_recv <= batch_size)` the NDEBUG
    /// DEAD face (NEVER replicated; the scripts honor the bound face);
    /// :202-:203 the pool CLAMP leg `if (max_recv > pool_available)
    /// max_recv = pool_available` (the T4 clamp pin); :206 `curr_
    /// batch_size = daq_instance_msg_receive(instance, max_recv,
    /// daq_msgs, &rstat)` — the Rust provider face returns the handles
    /// with rstat, the pair stores slots + count (the SAME observable
    /// slots :209-:210 walk reads); :207 `pool_available -= curr_
    /// batch_size`; :208 `curr_batch_idx = 0`; :210 return rstat (the
    /// DAQ_RecvStatus face; the pair's rstat value rides u32 — the
    /// 23a rstat enum):
    pub fn receive_messages(&mut self, max_recv: u32) -> u32 {
        let inst = match self.instance.as_mut() {
            Some(i) => i,
            None => return DAQ_RSTAT_ERROR, // the unguarded-DEREF
                                            // collapse cite (NEVER
                                            // harness-driven)
        };
        let mut max_recv = max_recv;
        if max_recv > self.pool_available {
            max_recv = self.pool_available;
        }
        let (handles, rstat) = inst.msg_receive(max_recv);
        self.curr_batch_size = handles.len() as u32; // :206
        for (slot, h) in self.daq_msgs.iter_mut().zip(handles) {
            *slot = h; // the msg_receive slot-fill face
        }
        self.pool_available -= self.curr_batch_size; // :207
        self.curr_batch_idx = 0; // :208
        rstat // :210
    }

    /// h :54-:59 the inline `DAQ_Msg_h next_message()`: the `curr_
    /// batch_idx < curr_batch_size -> daq_msgs[curr_batch_idx++]` walk
    /// ELSE nullptr (the Option face; the pair's OWN dtor/alloc
    /// companion — the consumer loop is the NOT-landed main face,
    /// cite):
    pub fn next_message(&mut self) -> Option<u64> {
        if self.curr_batch_idx < self.curr_batch_size {
            let h = self.daq_msgs[self.curr_batch_idx as usize];
            self.curr_batch_idx += 1; // the post-increment walk
            if h != 0 {
                return Some(h);
            }
        }
        None
    }

    /// cc :213-:222 finalize_message: :215-:216 `if (!msg) return
    /// DAQ_ERROR_INVAL` (the T5 null-guard pin -7 — the SDK leg NEVER
    /// reached on the null face); :218-:219 the msg_finalize leg
    /// (DAQT verdict face :112 of daq_common rides the verdict u32);
    /// :220-:221 `if (rval == DAQ_SUCCESS) pool_available++` (the T5
    /// avail 6->7 face):
    pub fn finalize_message(&mut self, msg: u64, verdict: u32) -> i32 {
        if msg == 0 {
            return DAQ_ERROR_INVAL;
        }
        let inst = match self.instance.as_mut() {
            Some(i) => i,
            None => return DAQ_ERROR_NOCTX, // DEREF-collapse face = THE
            // SDK guard the unguarded C leg OBSERVES (NULLFACE fin=-6)
        };
        let rval = inst.msg_finalize(msg, verdict);
        if rval == 0 {
            self.pool_available += 1;
        }
        rval
    }

    /// cc :224-:227 `const char* get_error()` (h :61 — the NON-const
    /// face): the instance-leg get_error; NO null guard rides HERE
    /// (the SDK default NULL face):
    pub fn get_error(&self) -> Option<String> {
        self.daq_err()
    }

    /// the get_error seam read (UN-guarded: the SDK-leg nullptr face):
    fn daq_err(&self) -> Option<String> {
        self.instance.as_ref().and_then(|i| i.get_error())
    }

    /// cc :229-:257 the private get_tunnel_capabilities (h :89): :231
    /// `daq_tunnel_mask = 0` — the reset OUTSIDE the guard (the tb
    /// zero=0 leg AFTER a full map = the FALSE-face pin: the reset
    /// fires on a null-instance reload too, cited); :232-:256 `if
    /// (instance)` the caps -> 10 tunnel-mask map (the CAPA sum + the
    /// tunnel-ceiling faces pin; the TUNNEL_* one-home consts, the
    /// landed codec files):
    fn get_tunnel_capabilities(&mut self) {
        self.daq_tunnel_mask = 0;
        if let Some(inst) = &self.instance {
            let caps = inst.get_capabilities();
            // :236-:255 (the ORDER-EXACT 10 legs — GTP..GENEVE):
            if caps & DAQ_CAPA_DECODE_GTP != 0 {
                self.daq_tunnel_mask |= TUNNEL_GTP;
            }
            if caps & DAQ_CAPA_DECODE_TEREDO != 0 {
                self.daq_tunnel_mask |= TUNNEL_TEREDO;
            }
            if caps & DAQ_CAPA_DECODE_VXLAN != 0 {
                self.daq_tunnel_mask |= TUNNEL_VXLAN;
            }
            if caps & DAQ_CAPA_DECODE_GRE != 0 {
                self.daq_tunnel_mask |= TUNNEL_GRE;
            }
            if caps & DAQ_CAPA_DECODE_4IN4 != 0 {
                self.daq_tunnel_mask |= TUNNEL_4IN4;
            }
            if caps & DAQ_CAPA_DECODE_6IN4 != 0 {
                self.daq_tunnel_mask |= TUNNEL_6IN4;
            }
            if caps & DAQ_CAPA_DECODE_4IN6 != 0 {
                self.daq_tunnel_mask |= TUNNEL_4IN6;
            }
            if caps & DAQ_CAPA_DECODE_6IN6 != 0 {
                self.daq_tunnel_mask |= TUNNEL_6IN6;
            }
            if caps & DAQ_CAPA_DECODE_MPLS != 0 {
                self.daq_tunnel_mask |= TUNNEL_MPLS;
            }
            if caps & DAQ_CAPA_DECODE_GENEVE != 0 {
                self.daq_tunnel_mask |= TUNNEL_GENEVE;
            }
        }
    }

    /// cc :259-:262 get_tunnel_bypass (h :86): the mask-AND face:
    pub fn get_tunnel_bypass(&self, proto: u16) -> bool {
        (self.daq_tunnel_mask & proto) != 0
    }

    /// cc :289-:301 inject (h :76 `inject(DAQ_Msg_h, int rev, const
    /// uint8_t* buf, uint32_t len)`): :291-:293 `if (!msg) return
    /// DAQ_ERROR_INVAL` (the T6 injnull=-7 pin); :294-:295 the
    /// inject_relative `(instance, msg, buf, len, rev)` face (the SDK
    /// REORDER: msg-anchor; the injection legs ride):
    /// :296-:299 `#ifdef DEBUG_MSGS` the Fail-LogMessage block =
    /// cite-never-land (the harness/donor NDEBUG config.h face —
    /// DEBUG_MSGS grep-0 re-walked at the row); :300 `return rval`:
    pub fn inject(&mut self, msg: u64, rev: i32, buf: &[u8]) -> i32 {
        if msg == 0 {
            return DAQ_ERROR_INVAL;
        }
        let inst = match self.instance.as_mut() {
            Some(i) => i,
            None => return DAQ_ERROR_NOCTX, // SDK guard face (NULLFACE
            // inj=-6 — the C unguarded leg rides the SAME observable)
        };
        inst.inject_relative(msg, buf, rev)
    }

    /// cc :303-:306 interrupt (h :77; the C is NON-const): the
    /// `== DAQ_SUCCESS` face (the T11 stub intr: default NOTSUP ->
    /// false; the harness NULLFACE intr=-6 -> FALSE pin):
    pub fn interrupt(&mut self) -> bool {
        let inst = match self.instance.as_mut() {
            Some(i) => i,
            None => return false, // the SDK guard face the C unguarded
            // leg rides (NOCTX -6 -> false, the measured pair face)
        };
        inst.interrupt() == 0
    }

    /// cc :308-:320 get_stats (h :67 `const DAQ_Stats_t* get_stats()`
    /// — the pointer face lands &): :310-:318 `if (instance)` the
    /// :312 store-INTO leg `daq_instance_get_stats(instance, &daq_
    /// instance_stats)` + :313-:315 the FAIL `LogMessage("Couldn't
    /// query DAQ instance (%s) stats: %s (%d)")` — the NULL get_error
    /// face rides the DOUBLE-SPACE `:  (-4)` pin (the T11 statelog);
    /// :319 `return &daq_instance_stats` — the ALWAYS-return face (the
    /// guard-false leg returns the initial record, NOT nullptr — the
    /// vectors stats_ptr=1 pin); the harness T10 fills hw=7 rx=1
    /// vblk=9, others 0:
    pub fn get_stats(&mut self, log: &mut LogEngine) -> &DaqStatsRecord {
        if let Some(inst) = self.instance.as_mut() {
            let rval = inst.get_stats(&mut self.daq_instance_stats);
            if rval != 0 {
                let err = inst.get_error();
                log.log_message_stdout(
                    "Couldn't query DAQ instance (%s) stats: %s (%d)\n",
                    &[
                        Arg::S(Some(Cow::from(self.input_spec.as_str()))),
                        Arg::S(err.as_deref().map(Cow::from)),
                        Arg::I(rval as i64),
                    ],
                );
            }
        }
        &self.daq_instance_stats // :319
    }

    /// the &self snapshot face (the seam get_stats tuple rider, cited
    /// at the impl):
    pub fn stats_snapshot(&self) -> &DaqStatsRecord {
        &self.daq_instance_stats
    }

    /// cc :322-:324 ioctl (h :79 SO_PUBLIC `int ioctl(DAQ_IoctlCmd,
    /// void* arg, size_t arglen)`) — the record enum marshals the
    /// void*+sizeof face (deviation cited at DaqIoctlReq):
    pub fn ioctl(&mut self, cmd: u32, req: &mut DaqIoctlReq<'_>) -> i32 {
        let inst = match self.instance.as_mut() {
            Some(i) => i,
            None => return DAQ_ERROR_NOCTX, // SDK guard face (the ioctl
            // legs' null-instance observable, same NULLFACE law)
        };
        inst.ioctl(cmd, req)
    }

    /// cc :326-:336 modify_flow_opaque (h :80 SO_PUBLIC): :328-:330
    /// the `!msg` INVAL pair; :332-:334 the DIOCTL_SetFlowOpaque
    /// record build (`d_sfo.msg = msg; d_sfo.value = opaque` — the
    /// DAQT msg store face rides the handle COPY); :335 the ioctl leg
    /// (`DIOCTL_SET_FLOW_OPAQUE, &d_sfo, sizeof(d_sfo)` — the size
    /// face 16, provider-marshalled):
    pub fn modify_flow_opaque(&mut self, msg: u64, opaque: u32) -> i32 {
        if msg == 0 {
            return DAQ_ERROR_INVAL;
        }
        let mut req = DaqIoctlReq::SetFlowOpaque { msg, value: opaque };
        self.ioctl(DIOCTL_SET_FLOW_OPAQUE, &mut req)
    }

    /// cc :338-:349 set_packet_verdict_reason (h :81): the :340-:342
    /// INVAL pair + the :345-:346 record build + the :348 ioctl leg:
    pub fn set_packet_verdict_reason(&mut self, msg: u64, verdict_reason: u8) -> i32 {
        if msg == 0 {
            return DAQ_ERROR_INVAL;
        }
        let mut req = DaqIoctlReq::SetPacketVerdictReason { msg, verdict_reason };
        self.ioctl(DIOCTL_SET_PACKET_VERDICT_REASON, &mut req)
    }

    /// cc :351-:363 set_packet_trace_data (h :82): the :353-:354 INVAL
    /// pair + the :357-:359 record (msg / trace_data ptr / len) + the
    /// :362 ioctl leg:
    pub fn set_packet_trace_data(&mut self, msg: u64, buff: &[u8]) -> i32 {
        if msg == 0 {
            return DAQ_ERROR_INVAL;
        }
        let mut req = DaqIoctlReq::SetPacketTraceData { msg, trace_data: buff };
        self.ioctl(DIOCTL_SET_PACKET_TRACE_DATA, &mut req)
    }

    /// cc :365-:436 add_expected (h :83-:85; the FIXIT-L :365 comment
    /// rides): THE single `daq_stats` reader. Build face EXACT: :369
    /// the local record; :372 the ctrl_msg = daq_msg face; :375 the
    /// key pointer alias face (`DAQ_EFlow_Key_t* key = &d_cef.key` —
    /// the Rust direct field); :377-:382 the src legs (get_family;
    /// is_ip4 -> the s_addr NET-order = the get_ip4_value landed face
    /// stored at the union head; ELSE the 16-B ip6 memcpy = the landed
    /// ip8); :383 sport; :385-:388 the dst legs; :389 dport; :391 the
    /// FIXIT-M NEVER-FILL law comment (the address_space_id zero
    /// face); :394-:397 the GTP/MPLS proto_bits -> tunnel_type chain +
    /// the COMMENTED else-if `encapsulated` block :399-:403 (FIXIT-L —
    /// cite-never-land; the ELSE leaves the initial 0 = NON_TUNNEL
    /// face — the T8b `tun=2` MPLS + T8 `tun=1` GTP pins); :410-:411
    /// `key->protocol = (uint8_t)protocol`; :412-:415? NO — :406-:409
    /// the vlan legs (`if (ctrlPkt->proto_bits & PROTO_BIT__VLAN)
    /// key->vlan_id = layer::get_vlan_layer(ctrlPkt)->vid(); else
    /// key->vlan_id = 0xFFFF` — the T8 vlan=ffa / T8b vlan=ffff pins;
    /// the layer-seam slot cited at the request); :416? NO, the C
    /// ORDER: :410 vlan-cnots=1 sits AFTER :406-:409;
    /// :412/:426-:430 flags: :412 `d_cef.flags = 0` then the COPY-
    /// through trio legs :414-:418 (`if (flags & X) d_cef.flags |= X`
    /// — ALLOW_MULTIPLE / BIDIRECTIONAL / PERSIST; the T8 `flags=6`
    /// multi+bidir face, the T8b 8) + the COMMENTED :419-:424 DC_
    /// legacy block (cite-never-land — the FLOAT bit NEVER lands);
    /// :426? the `d_cef.timeout_ms` store (the FIXIT-L X unused? the
    /// C :365 FIXIT-L X comment; the timeout_ms store rides :426, the
    /// `unsigned timeout_ms` arg — the vectors `tmo=5000` pin);
    /// :429-:430 `d_cef.data = nullptr; d_cef.length = 0` (the
    /// NEVER-populated blob — ABSENT on the Rust record, cited); the
    /// FIXIT-L X `:364` header comment face (`Opaque data blob ...
    /// unused`); :433 `daq_stats.expected_flows++` — THE global bump
    /// BEFORE the ioctl (the ORDER-EXACT law: the ef=1/ef=2 walk pins
    /// the bump EVEN on an SDK-side failure face — the counter moves
    /// FIRST); :435-:436 the ioctl return leg (the T8 `cmd=11` pin =
    /// the SDK ioctl dispatch to the provider):
    pub fn add_expected(&mut self, req: &DaqExpectedFlowRequest) -> i32 {
        let mut key = DdaqEFlowKey {
            src_af: 0,
            dst_af: 0,
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            address_space_id: 0, // NEVER-FILL law (:391):
            tunnel_type: 0, // the ELSE-NON_TUNNEL initial face (:404-
                            // :408 chain NEVER writes a zero):
            vlan_id: 0xFFFF, // the :409 ELSE face pre-set, OVERWRITTEN
                             // on the VLAN-bit leg:
            vlan_cnots: 1, // :410 (`key->vlan_cnots = 1` the TRUE
                           // constant face pin cnots=1)
        };
        key.src_af = req.cli_ip.get_family(); // :377 (the SF::get_
                                              // family landed face =
                                              // the AF_INET 2 /
                                              // AF_INET6 10 values —
                                              // the T8 src_af=2 T8b
                                              // 10 pins)
        if req.cli_ip.is_ip4() {
            // :378-:379 `key->sa.src_ip4.s_addr = cliIP->get_ip4_value
            // ()` — THE NATIVE WORD STORE: s_addr holds the host-face
            // word ip32_raw(3) (the landed sfip LE face); on x86-64
            // the word's MEMORY bytes (what the C union head + the
            // probe's ntohl/%s legs READ) = the NET-order octets
            // 0a010203 — the MEASURED vectors ip4=a010203 [0a010203]
            // pin drives this leg (NEVER to_be: that flips the bytes):
            key.src_addr[0..4].copy_from_slice(&req.cli_ip.get_ip4_value().to_le_bytes());
        } else {
            // :380-:382 `memcpy(&key->sa.src_ip6, cliIP->get_ip6_ptr
            // (), sizeof(...))`:
            key.src_addr.copy_from_slice(&req.cli_ip.ip8);
        }
        key.src_port = req.cli_port; // :383
        key.dst_af = req.srv_ip.get_family(); // :385
        if req.srv_ip.is_ip4() {
            // the same NATIVE-word-store law (the T8b dst_ip4=
            // c0000209 [c0000209] face, cited above):
            key.dst_addr[0..4].copy_from_slice(&req.srv_ip.get_ip4_value().to_le_bytes());
        } else {
            key.dst_addr.copy_from_slice(&req.srv_ip.ip8);
        }
        key.dst_port = req.srv_port; // :389
        // :394-:408 the tunnel chain (the ELSE arms = the commented
        // OTHER block NEVER lands; the initial 0 rides):
        if req.ctrl_proto_bits & PROTO_BIT__GTP != 0 {
            key.tunnel_type = DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL;
        } else if req.ctrl_proto_bits & PROTO_BIT__MPLS != 0 {
            key.tunnel_type = DAQ_EFLOW_TUNNEL_TYPE_MPLS_TUNNEL;
        }
        key.protocol = req.protocol; // :410-:411
        if req.ctrl_proto_bits & PROTO_BIT__VLAN != 0 {
            // :407 the layer-seam leg (the vid() face pre-masked —
            // deviation cited at the request struct):
            key.vlan_id = req.vlan_vid;
        } // :409: 0xFFFF stays
        let mut flags = 0u32; // :412
        if req.flags & DAQ_EFLOW_ALLOW_MULTIPLE != 0 {
            flags |= DAQ_EFLOW_ALLOW_MULTIPLE; // :414
        }
        if req.flags & DAQ_EFLOW_BIDIRECTIONAL != 0 {
            flags |= DAQ_EFLOW_BIDIRECTIONAL; // :416
        }
        if req.flags & DAQ_EFLOW_PERSIST != 0 {
            flags |= DAQ_EFLOW_PERSIST; // :417-:418
        }
        let mut cef = DaqIoctlReq::CreateExpectedFlow(DdaqIoctlCreateExpectedFlow {
            ctrl_msg: req.ctrl_msg, // :372
            key,
            flags,
            timeout_ms: req.timeout_ms, // the timeout store face
                                        // (unused-flag honesty: the
                                        // provider leg rides it)
        });
        // :433 THE bump BEFORE the ioctl (the ef-walk ORDER law):
        DAQ_STATS.with(DAQStatsHolder::stats_bump);
        self.ioctl(DIOCTL_CREATE_EXPECTED_FLOW, &mut cef) // :435
    }
}

// ---------------------------------------------------------------------------
// THE 23a SEAM-CLOSE impl (the trait legs = ONLY the methods
// sfdaq.cc :345-:402 WRAPS — the 23a frozen trait, sfdaq.rs). The seam
// legs take ONLY the seams the frozen trait carries; every shortfall
// gets an honest rider (cited face-by-face — these are NOT body fakes:
// the bodies are the REAL ported legs):
//  * init(cfg, bpf): the trait's `DaqConfigMirror` (a VALUE record,
//    23a-frozen) wraps into the DaqCfgProvider legs via `SeamCfg` (the
//    three :77-:79 legs RECORD onto Cells — the observable faces the
//    provider-side pins, the mirror struct NEVER mutated; the
//    adaptor_inline conf face = FALSE here: the 23a trait has NO conf
//    seam and the harness facade legs ride the non-inline default; the
//    TRUE face is pinned at the PAIR level with the explicit arg). The
//    LogEngine seam: the trait has no engine — a throwaway engine owns
//    the seam-leg log faces (the C++ rides C file-global log homes —
//    the landed engine law; the 23a parity seam-face legs NEVER pin
//    log lines through local_instance, cited);
//  * get_stats(): the trait &-face — the pair's get_stats needs &mut
//    + engine; the seam returns the OBSERVABLE snapshot tuple (the
//    record only changes on provider query legs; the tuple face (
//    packets_received, verdicts) = the 23a trait's pinned shape);
//  * inject(rev, buf): the trait drops the DAQT msg arg (the 23a
//    "handled SDK-side" cite) — the seam leg rides the next_message()
//    walk face (None -> the 0 -> the :291-:293 INVAL face honest);
// ---------------------------------------------------------------------------

/// the three-leg mirror adapter (Cells: trait set_* needs &mut self,
/// the mirror stays 23a-frozen and shared):
// THE adapter state face (cited deviation, KNOWN DEVIATIONS row 23b):
// the 23a-FROZEN trait signature never carries the conf seams. The
// seam legs ride the SAME pair bodies with the pair-local seam faces:
// * adaptor_inline_mode = FALSE — the sfdaq.cc :61-:62 wrapper NEVER
//   drives an inline-TRUE face through this seam (the harness T3b leg
//   rides the PAIR-level arg, the vectors pin ONLY there), cited;
// * get_instance_id = the pair's OWN 1-based instance_id (the seam has
//   no thread seam — the thread-local face the cc :188/:190 print legs
//   ride arrives from the instance itself, cited);
// * the engine: a per-seam-call throwaway LogEngine owns the seam-leg
//   log faces (the C++ rides C file-global log homes; the landed
//   engine law; the seam legs NEVER pin log lines through the
//   facade — the 23a parity seam legs stand scripted, cited).
struct SeamCfg<'a> {
    mirror: &'a DaqConfigMirror,
    recorded_input: RefCell<Option<String>>,
    recorded_instance_id: Cell<Option<u32>>,
}

impl DaqCfgProvider for SeamCfg<'_> {
    fn set_input(&mut self, spec: &str) {
        *self.recorded_input.borrow_mut() = Some(spec.to_string());
    }
    fn get_total_instances(&self) -> u32 {
        self.mirror.total_instances
    }
    fn set_instance_id(&mut self, snort_id: u32) {
        self.recorded_instance_id.set(Some(snort_id));
    }
}

impl DaqInstanceSeam for SFDAQInstance {
    fn init(&mut self, cfg: &DaqConfigMirror, bpf_string: &str) -> bool {
        let mut seam_cfg = SeamCfg {
            mirror: cfg,
            recorded_input: RefCell::new(None),
            recorded_instance_id: Cell::new(None),
        };
        let mut log = LogEngine::default(); // the seam-engine rider
        let inline = self.adaptor_inline; // the pair-local conf seam
                                          // face (the sfdaq.cc wrapper
                                          // NEVER drives TRUE HERE —
                                          // cited, KNOWN DEVIATIONS)
        SFDAQInstance::init(self, &mut seam_cfg, bpf_string, inline, &mut log)
    }
    fn get_input_spec(&self) -> &str {
        SFDAQInstance::get_input_spec(self)
    }
    fn get_base_protocol(&self) -> i32 {
        SFDAQInstance::get_base_protocol(self)
    }
    fn can_inject(&self) -> bool {
        SFDAQInstance::can_inject(self)
    }
    fn can_inject_raw(&self) -> bool {
        SFDAQInstance::can_inject_raw(self)
    }
    fn can_replace(&self) -> bool {
        SFDAQInstance::can_replace(self)
    }
    fn get_tunnel_bypass(&self, proto: u16) -> bool {
        SFDAQInstance::get_tunnel_bypass(self, proto)
    }
    fn inject(&mut self, rev: i32, buf: &[u8]) -> i32 {
        let msg = self.next_message().unwrap_or(0);
        SFDAQInstance::inject(self, msg, rev, buf)
    }
    fn get_stats(&self) -> (u64, [u64; MAX_DAQ_VERDICT as usize]) {
        let s = self.stats_snapshot();
        (s.packets_received, s.verdicts)
    }
}
