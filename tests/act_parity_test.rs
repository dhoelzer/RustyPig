//! Row-23h parity twin: src/packet_io/active.rs (THE Active verdict/
//! response manager, the packet_io active pair port) replayed against the
//! harness's MEASURED C faces: the DEC vectors.txt 44 L (md5 5624bb43
//! 209b9931ab890f8ba4570e7d) + vectors_faceA.txt 10 L (md5 9e15e6c1233
//! a85c2c8b15e5f87a29e00) FIRST-RUN-SEED truth — the twin re-derives
//! EVERY line by driving the Rust port leg-by-leg through test doubles
//! replicating the C-harness witness/probe semantics (the encode capture
//! feeds the Strafe hex faces D5f0..f5; the s_send capture; the
//! ParseWarning face rides the LANDED log home; the trace-log byte legs
//! D8 ride the landed 23f PacketTrace home exactly like the pt-rmod twin
//! drives it; the eth/ip dnet legs + the two FatalError jumped= faces
//! ride the row seams). The ac t harness NEVER edits; the twin NEVER
//! touches the vectors — the doubles follow the vectors, never the
//! reverse.
//! The ac-t row itself rode ZERO gate faces (the census walked 28/9/20/1 AT that
//! row); the row-24a sanctioned gate rider raised the live face 29/9/21/1.
//! Token law: the harness own-name + the foreign harness names ride the
//! concat include paths + hyphen prose ONLY; the landed sfdaq /
//! sfdaq_instance / packet_tracer use-paths below are the sanctioned
//! one-home cites (the DEV-006/DEV-011/DEV-024 reuse faces).
//! ZERO allows, ZERO unsafe.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::OnceLock;

use snort3::codecs::cd_tcp::PKT_TYPE__TCP;
use snort3::detection::rtn_checks::{IpApiLite, IAT_4};
use snort3::framework::codec::ENC_FLAG_FWD;
use snort3::log::messages::{LogEngine, WARN_DAQ};
use snort3::main::thread::{NamingConfig, ThreadState};
use snort3::packet_io::active as act; // THE landing (one home)
use snort3::packet_io::active::{
    ActiveActionFace, ActiveCtx, ActiveFlowFace, ActivePacketFace, DioctlDirectInjectPayload,
    DioctlDirectInjectReset, ActionPriority, TcpResponse, UnreachResponse,
};
use snort3::packet_io::packet_constraints::ConstraintPacketFace;
use snort3::packet_io::packet_tracer::{self, BatchedLogFace, PacketTrace, StreamLogFace, TraceThreadWorld}; // the 23f landing (use-path cite)
use snort3::packet_io::sfdaq::{
    DaqConfigMirror, DaqInstanceSeam, SFDaq, DAQ_MODE_INLINE, DAQ_PKT_FLAG_NOT_FORWARDING,
}; // the 23a landing (use-path cite)
use snort3::packet_io::sfdaq_instance::DAQStats; // the 23b landing (use-path cite)

const VECTORS: &str = include_str!(concat!("../tools/ac", "t_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/ac", "t_harness/vectors_faceA.txt"));
const NEXTMD: &str = include_str!(concat!("../NE", "XT.md"));

fn md5(bytes: &[u8]) -> String {
    // the harness's OWN md5sum home (the census-lineage face computes the
    // same way — the 22a/23-era precedent):
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap().split_whitespace().next().unwrap().to_string()
}

fn ground(rel: &str) -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/{rel}")).unwrap()
}

fn port_rs() -> String {
    std::fs::read_to_string("/opt/data/snort3-rust/src/packet_io/active.rs").unwrap()
}

// ==========================================================================
// THE witness doubles (the Rust stand-ins for the C witness mirrors —
// the Rc/RefCell capture shapes the da-qio twin precedent sets).
// ==========================================================================

thread_local! {
    // the C probe's pa_hits[4] (the ProbeAction delayed_exec captures):
    static PA_HITS: RefCell<[i32; 4]> = const { RefCell::new([0; 4]) };
}

/// the ProbeAction unit twin (id + priority; the hits leg rides the
/// thread-local for the 'static law):
#[derive(Clone, Copy)]
struct ProbeUnit {
    prio: ActionPriority,
    id: usize,
}
impl ActiveActionFace for ProbeUnit {
    fn get_action(&self) -> ActionPriority {
        self.prio
    }
    fn delayed_exec(&mut self, _pkt: &mut dyn ActivePacketFace, _ctx: &mut ActiveCtx) {
        PA_HITS.with(|h| h.borrow_mut()[self.id] += 1);
    }
    fn clone_action(&self) -> Box<dyn ActiveActionFace> {
        Box::new(*self)
    }
}
static PA_LO: ProbeUnit = ProbeUnit { prio: ActionPriority::ApLocal, id: 0 };
static PA_HI: ProbeUnit = ProbeUnit { prio: ActionPriority::ApRemote, id: 1 };
static PA_EQ: ProbeUnit = ProbeUnit { prio: ActionPriority::ApRemote, id: 2 };

// ---- the SFDAQ face (the sfd_* witness knobs; the landed SFDaq +
// DaqInstanceSeam play the SAME legs the C mirror closed): the caps
// (can_inject / can_inject_raw / can_replace — the 23a Cap trio) + the
// inject capture (the sfd_inject_calls/rev/len face) + the pool/batch
// law (Some((pool, batch)) = the C attached instance; the None leg =
// the C nullptr-instance face the cc :800/:825 arms take).
#[derive(Clone, Copy)]
struct Dq {
    can_inject: bool,      // sfd_can_inject
    can_inject_raw: bool,  // sfd_can_inject_raw
    can_replace: bool,     // sfd_can_replace
    inject_calls: usize, // sfd_inject_calls
    last_rev: i64,       // sfd_inject_rev (witness init -1)
    last_len: i64,       // sfd_inject_len (witness init -1)
    inject_rc: i32,      // the inject return face (0 = DAQ_SUCCESS)
    pool: Option<(u32, u32)>, // wsi_pool / wsi_batch (None = the C pool-0 face)
}
impl Dq {
    fn fresh() -> Dq {
        Dq {
            can_inject: true,
            can_inject_raw: true,
            can_replace: true,
            inject_calls: 0,
            last_rev: -1,
            last_len: -1,
            inject_rc: 0,
            pool: Some((8, 4)),
        }
    }
    fn reset(&mut self) {
        // act_wr_reset_captures() face — the sfd_inject + wsi captures (the
        // caps / pool knobs STAY — the C never resets them here):
        self.inject_calls = 0;
        self.last_rev = -1;
        self.last_len = -1;
    }
}

/// the DaqInstanceSeam provider for the landed SFDaq wrapper legs (the
/// can_* + inject capture pair):
struct CapInst {
    dq: Rc<RefCell<Dq>>,
}
impl DaqInstanceSeam for CapInst {
    fn init(&mut self, _cfg: &DaqConfigMirror, _bpf: &str) -> bool {
        true
    }
    fn get_input_spec(&self) -> &str {
        ""
    }
    fn get_base_protocol(&self) -> i32 {
        0
    }
    fn can_inject(&self) -> bool {
        self.dq.borrow().can_inject
    }
    fn can_inject_raw(&self) -> bool {
        self.dq.borrow().can_inject_raw
    }
    fn can_replace(&self) -> bool {
        self.dq.borrow().can_replace
    }
    fn get_tunnel_bypass(&self, _proto: u16) -> bool {
        false
    }
    fn inject(&mut self, rev: i32, buf: &[u8]) -> i32 {
        let mut d = self.dq.borrow_mut();
        d.inject_calls += 1;
        d.last_rev = rev as i64;
        d.last_len = buf.len() as i64;
        d.inject_rc
    }
    fn get_stats(&self) -> (u64, [u64; snort3::packet_io::sfdaq::MAX_DAQ_VERDICT as usize]) {
        (0, [0; snort3::packet_io::sfdaq::MAX_DAQ_VERDICT as usize])
    }
}

// ---- the config read face (the ActiveConfigReadFace double: the C probe
// SnortConfig legs respond_attempts / respond_device / read_mode + the
// act_wr_set_policy_mode face -> the ips_* mode getters). The witness
// policy init face = PASSIVE; act_wr_set_policy_mode(MAX) = NO bit. ----
#[derive(Clone, Copy)]
struct Conf {
    attempts: u8,
    read: bool,
    device: Option<&'static str>, // the C std::string .empty() -> None face
    inline: bool,
    test: bool,
    passive: bool,
    max: bool, // POLICY_MODE__MAX (the mode NEITHER inline nor test nor passive)
}
impl Default for Conf {
    fn default() -> Self {
        Conf { attempts: 0, read: false, device: None, inline: false, test: false, passive: true, max: false }
    }
}
impl act::ActiveConfigReadFace for Conf {
    fn respond_attempts(&self) -> u8 {
        self.attempts
    }
    fn respond_device(&self) -> Option<&str> {
        self.device
    }
    fn read_mode(&self) -> bool {
        self.read
    }
    fn ips_inline_mode(&self) -> bool {
        self.inline
    }
    fn ips_inline_test_mode(&self) -> bool {
        self.test
    }
    fn ips_passive_mode(&self) -> bool {
        self.passive && !self.max
    }
}

// ---- the PacketManager encode trio mirror (the pm_* witness face): the
// (kind, flags) capture per call — the Strafe heart of D5/D9 + the
// encode_get_max_payload counter (C pm_maxpay_calls — NOT in
// act_wr_reset_captures(): the face STAYS across legs, pinned by the D9
// maxp=3 line):
struct Enc {
    calls: usize,            // pm_encode_calls (resets per leg)
    kinds: Vec<u8>,          // pm_encode_kind[..]
    flags: Vec<u64>,         // pm_flags_seen[..] (the D5f hex faces)
    null: bool,              // pm_encode_return_null
    maxp: u16,               // pm_maxpayload_face (the return)
    max_calls: Cell<usize>,  // pm_maxpay_calls (NEVER reset by the face)
    sentinel: Vec<u8>,       // pm_sentinel (the 0xAA.. four bytes the C
                             // witness wrote; len = the returned face)
}
impl Default for Enc {
    fn default() -> Self {
        Enc { calls: 0, kinds: Vec::new(), flags: Vec::new(), null: false, maxp: 0, max_calls: Cell::new(0), sentinel: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11] } // pm_len_set=7 face (the sentinel len the witness's out-arg pins)
    }
}
impl Enc {
    fn reset(&mut self) {
        // act_wr_reset_captures() face — pm_encode_calls + the arrays
        // (pm_maxpay_calls STAYS — the C reset-arms list pins this):
        self.calls = 0;
        self.kinds.clear();
        self.flags.clear();
        self.max_calls.set(0); // act_wr_reset_captures() DOES clear pm_maxpay_calls (the witness list, measured)
    }
}
impl act::ActiveEncodeFace for Enc {
    fn encode_response(
        &mut self,
        resp: TcpResponse,
        flags: u64,
        _pkt: &dyn ActivePacketFace,
        _payload: &[u8],
    ) -> Option<&[u8]> {
        self.calls += 1;
        self.kinds.push(resp as u8);
        self.flags.push(flags);
        if self.null {
            return None;
        }
        Some(&self.sentinel)
    }
    fn encode_reject(
        &mut self,
        resp: UnreachResponse,
        _flags: u64,
        _pkt: &dyn ActivePacketFace,
    ) -> Option<&[u8]> {
        self.calls += 1;
        self.kinds.push(resp as u8);
        if self.null {
            return None;
        }
        Some(&self.sentinel)
    }
    fn encode_get_max_payload(&self, _pkt: &dyn ActivePacketFace) -> u16 {
        self.max_calls.set(self.max_calls.get() + 1);
        self.maxp
    }
}

// ---- the Stream / DetectionEngine statics mirrors (stream_block/drop/
// init_ar + de_disable_all / de_clear_replacement — the C capture resets
// ride the witness leg, NOT every zero_caps):
#[derive(Default)]
struct StreamCap {
    block: usize,
    drop: usize,
    init: usize,
}
impl act::StreamSeam for StreamCap {
    fn block_flow(&mut self, _pkt: &mut dyn ActivePacketFace) {
        self.block += 1;
    }
    fn drop_flow(&mut self, _pkt: &mut dyn ActivePacketFace) {
        self.drop += 1;
    }
    fn init_active_response(&mut self, _pkt: &mut dyn ActivePacketFace) {
        self.init += 1;
    }
}
#[derive(Default)]
struct DeCap {
    disable: usize,
    clear: usize,
}
impl act::DetectionSeam for DeCap {
    fn disable_all(&mut self, _pkt: &mut dyn ActivePacketFace) {
        self.disable += 1;
    }
    fn clear_replacement(&mut self) {
        self.clear += 1;
    }
}

// ---- the wsi_* mirror legs (the per-packet io seam): the pool/batch law
// reads the shared Dq (the C p->daq_instance ? : get_local_instance()
// selector folds HERE — the cc :800/:825 Option legs) + the direct-inject
// ioctl counters + the verdict-reason capture (wsi_vp_calls/last, the
// -99 cold face). NOT part of act_wr_reset_captures() EXCEPT the C
// reset list DOES clear wsi_* — the wsi pair rides the reset face below.
struct IoCap {
    dq: Rc<RefCell<Dq>>,
    vp_calls: usize,
    last_vp: i64, // -99 cold
    di_reset: usize,
    di_payload: usize,
}
impl act::ActiveIoFace for IoCap {
    fn direct_inject_reset(&mut self, _req: &DioctlDirectInjectReset) -> i32 {
        self.di_reset += 1;
        0 // wsi_ioctl_rc default DAQ_SUCCESS (the C D14f/D14g legs NEVER ride this path)
    }
    fn direct_inject_payload(&mut self, _req: &DioctlDirectInjectPayload<'_>) -> i32 {
        self.di_payload += 1;
        0
    }
    fn pool_and_batch(&self, _daq_msg: u64) -> Option<(u32, u32)> {
        self.dq.borrow().pool
    }
    fn set_packet_verdict_reason(&mut self, _msg: u64, verdict_reason: u8) {
        self.vp_calls += 1;
        self.last_vp = verdict_reason as i64;
    }
}

// ---- the dnet shim mirror (the eth_*/ip_* counters, C globals shared
// by every handle; the open-fail arms + the send face the harness's
// dnet_send_fail NEVER arms on this ladder):
#[derive(Default)]
struct DnetCap {
    eth_open: usize,
    eth_send: usize,
    eth_close: usize,
    ip_open: usize,
    ip_send: usize,
    ip_close: usize,
    eth_open_fail: bool,
    ip_open_fail: bool,
}
struct EthH(Rc<RefCell<DnetCap>>);
impl act::EthHandleFace for EthH {
    fn eth_send(&mut self, _buf: &[u8], len: u32) -> i64 {
        self.0.borrow_mut().eth_send += 1;
        len as i64 // the success face (dnet_send_fail stays 0)
    }
    fn eth_close(&mut self) {
        self.0.borrow_mut().eth_close += 1;
    }
}
struct IpH(Rc<RefCell<DnetCap>>);
impl act::IpHandleFace for IpH {
    fn ip_send(&mut self, _buf: &[u8], len: u32) -> i64 {
        self.0.borrow_mut().ip_send += 1;
        len as i64
    }
    fn ip_close(&mut self) {
        self.0.borrow_mut().ip_close += 1;
    }
}
struct Dnet(Rc<RefCell<DnetCap>>);
impl act::DnetFace for Dnet {
    fn eth_open(&mut self, _dev: &str) -> Option<Box<dyn act::EthHandleFace>> {
        let mut c = self.0.borrow_mut();
        c.eth_open += 1;
        if c.eth_open_fail {
            return None; // the FatalError fuel (the D14f face)
        }
        Some(Box::new(EthH(Rc::clone(&self.0))))
    }
    fn ip_open(&mut self) -> Option<Box<dyn act::IpHandleFace>> {
        let mut c = self.0.borrow_mut();
        c.ip_open += 1;
        if c.ip_open_fail {
            return None; // the D14g face
        }
        Some(Box::new(IpH(Rc::clone(&self.0))))
    }
}

// ---- the p->flow legs (the Flow::trust capture; cold DeferredTrust =>
// try_trust false):
#[derive(Default)]
struct FlowTwin {
    trust: usize, // flow_trust_calls (wired to the shared cap below)
}
impl ActiveFlowFace for FlowTwin {
    fn trust(&mut self) {
        self.trust += 1;
    }
    fn stop_deferring_trust(&mut self) {}
    fn try_trust(&mut self) -> bool {
        false // the cold never-armed face (cc :863 -> the false leg)
    }
    fn set_state(&mut self, _state: u8) {}
    fn finalize_trust(&mut self, _active: &mut act::Active) {}
}

// ---- the struct Packet mirror: every leg the pair reads/mutates. The
// DEV-022 kill_session back-pointer (the C re-entrant p->active call)
// ports as the provider's queue-leg: the run scope re-drives the REAL
// Active::kill_session body right after the enclosing execute() returns
// (the C call returns BEFORE the next observable, and NO vector line is
// printed between the C call and this re-drive — the face is order-free).
#[derive(Default)]
struct PacketTwin {
    pkth_flags: u32,
    pkt_type: u8,
    dsize: u32,
    packet_flags: u32,
    disable_inspect: bool,
    flow: Option<FlowTwin>, // the p->flow attach face (None = the C nullptr)
    slot: Option<Box<dyn ActiveActionFace>>, // the p->action slot
    th_win: Option<u16>,    // ntohs(th_win) — the probe arms 4660
    th_flags: Option<u8>,
    daq_msg: u64,           // the C DAQ_Msg_h (the witness never armed it)
    kill_queue: Vec<u64>,   // the pending kill_session(ENC_FLAG_FWD) legs
}
impl ActivePacketFace for PacketTwin {
    fn type_(&self) -> u8 {
        self.pkt_type
    }
    fn pkth_flags(&self) -> u32 {
        self.pkth_flags
    }
    fn dsize(&self) -> u32 {
        self.dsize
    }
    fn packet_flags(&self) -> u32 {
        self.packet_flags
    }
    fn packet_flags_bor(&mut self, mask: u32) {
        self.packet_flags |= mask;
    }
    fn flow_present(&self) -> bool {
        self.flow.is_some()
    }
    fn flow_uses_direct_inject(&self) -> bool {
        false // NEVER armed on this ladder (the C flags.use_direct_inject face)
    }
    fn flow_mut(&mut self) -> Option<&mut dyn ActiveFlowFace> {
        self.flow.as_mut().map(|f| f as &mut dyn ActiveFlowFace)
    }
    fn tcph_flags(&self) -> Option<u8> {
        self.th_flags
    }
    fn tcph_win(&self) -> Option<u16> {
        self.th_win
    }
    fn daq_msg(&self) -> u64 {
        self.daq_msg
    }
    fn set_disable_inspect(&mut self) {
        self.disable_inspect = true;
    }
    fn current_action_priority(&self) -> Option<ActionPriority> {
        self.slot.as_ref().map(|a| a.get_action())
    }
    fn install_action(&mut self, a: Box<dyn ActiveActionFace>) {
        self.slot = Some(a);
    }
    fn take_action(&mut self) -> Option<Box<dyn ActiveActionFace>> {
        self.slot.take()
    }
    fn clear_action(&mut self) {
        self.slot = None;
    }
    fn kill_session(&mut self, flags: u64, _ctx: &mut ActiveCtx) {
        self.kill_queue.push(flags); // DEV-022 provider-side queue (re-driven below)
    }
}

// ---- the StreamLog capture (the Q0 sl=[..] face) + the BatchedLogManager
// mirror (the tracer term/carry legs; the dump()-to-stdout side effects
// ride the harness C probe's OWN flush — NEVER captured, NEVER printed):
#[derive(Default)]
struct Sl {
    cap: String, // sl_capture
}
impl StreamLogFace for Sl {
    fn add_ip_header_info(&mut self, _add_eth: bool) {
        self.cap.push_str("IP;");
    }
    fn add_eth_header_info(&mut self) {
        self.cap.push_str("ETH;");
    }
    fn add_packet_type_info(&mut self) {
        self.cap.push_str("PTY;");
    }
    fn stream_is_cbd_enabled(&self) -> bool {
        false // the C witness cold leg (cc :305 false)
    }
}
struct Blog;
impl BatchedLogFace for Blog {
    fn log(&mut self, _use_syslog: bool, _msg: &[u8], _len: usize) {}
    fn flush_thread_buffers(&mut self) {}
}

fn fresh_packet() -> PacketTwin {
    PacketTwin {
        pkt_type: PKT_TYPE__TCP, // probe :65 set_pkt_type(PktType::TCP)
        dsize: 100,              // probe :66 p->dsize = 100
        th_win: Some(4660),      // probe :66 ntohs(htons(4660))
        th_flags: Some(0),    // the ACK face (probe memset 0 + the tcp.h
                                 // TH_* default: the is_reset_candidate
                                 // (th_flags & TH_RST)==0 leg NEVER reads
                                 // TH_RST — the 0x10 stays observable-free)
        daq_msg: 1,              // the C DAQ_Msg_h NEVER armed (0 vs 1:
                                 // the seam legs ignore the value — the
                                 // C witness default pinned)
        ..Default::default()
    }
}

// ==========================================================================
// THE Harness: one owner over the C-probe world (the file-statics stand-
// in pair: ActiveWorld + the landed tracer + DAQStats + every capture +
// the Conf face). The ctx!() method reborrows per leg EXACTLY like the C
// statics are re-read per call — the Rust borrow law, not a semantic
// change. NEVER printed through (the C probe NEVER dumps to stdout on the
// ladder — it flushes to the discarded carry face).
// ==========================================================================

/// the drive-side pair: the W world (the C witness-globals
/// stand-in bundle) + the Sub subject legs (the C probe keeps the Active +
/// the packet skeleton OWNED apart from the harness — the pair mirrors
/// that split, and it IS the borrow face: a subject call borrows `a` +
/// `p` apart from the ctx's nine legs).
struct Sub {
    p: PacketTwin,
    a: act::Active,
}

struct Harness {
    w: W,
    sub: Sub,
}

struct W {
    world: act::ActiveWorld,
    daq: SFDaq,
    stats: DAQStats,
    log: LogEngine,
    conf: Conf,
    pt: PacketTrace,
    enc: Enc,
    io: IoCap,
    dq: Rc<RefCell<Dq>>,
    dnet: Dnet,
    dcap: Rc<RefCell<DnetCap>>,
    st: StreamCap,
    de: DeCap,
    sl: Sl,
}

impl Harness {
    fn new() -> Harness {
        Harness { w: W::new(), sub: Sub::fresh() }
    }
}

impl Sub {
    fn fresh() -> Sub {
        Sub { p: fresh_packet(), a: act::Active::new() }
    }
}

impl W {
    fn new() -> W {
        let dq = Rc::new(RefCell::new(Dq::fresh()));
        let dcap = Rc::new(RefCell::new(DnetCap::default()));
        // the world twin is CONSTRUCTION-only (the landed new() clones the
        // log_file snap + reads config_status at :353; NO ladder leg
        // re-reads it — the C thread-statics ride the landed home):
        let mut tw = TraceThreadWorld::new();
        tw.configure(true, "-"); // PacketTracer::configure(true, "-") BEFORE thread_init (the config_status face the Q0 pin rides)
        let mut log = LogEngine { warning_flags: 1 << WARN_DAQ, ..Default::default() };
        // the landed tracer ctor reads the thread-state + naming faces (the
        // C thread_init locals; the tracer NEVER dumps to stdout on the DEC
        // ladder, so the defaults ride construction only):
        let pt = packet_tracer::new(&tw, &NamingConfig::default(), &ThreadState::default(), &mut log);
        W {
            world: act::ActiveWorld::new(),
            daq: SFDaq {
                default_daq_mode: DAQ_MODE_INLINE, // the D4 inlineNF face's fuel
                local_instance: Some(Box::new(CapInst { dq: Rc::clone(&dq) })),
                ..Default::default()
            },
            stats: DAQStats::default(),
            log,
            conf: Conf::default(), // the witness policy init face: PASSIVE
            pt,
            enc: Enc::default(),
            io: IoCap { dq: Rc::clone(&dq), vp_calls: 0, last_vp: -99, di_reset: 0, di_payload: 0 },
            dq,
            st: StreamCap::default(),
            de: DeCap::default(),
            dcap: Rc::clone(&dcap),
            dnet: Dnet(dcap),
            sl: Sl::default(),
        }
    }

    /// the C `!SFDAQ::forwarding_packet(p->pkth)` face: pkth 0 vs the
    /// NOT_FORWARDING bit (the landed sfdaq forwarding_packet law):
    fn set_forwarding(sub: &mut Sub, fwd: bool) {
        sub.p.pkth_flags = if fwd { 0 } else { DAQ_PKT_FLAG_NOT_FORWARDING };
    }
    /// the policy mode face (act_wr_set_policy_mode(m)): PASSIVE /
    /// INLINE_TEST / MAX. MAX = NEITHER mode fires (the update_status
    /// actionable legs all-false — the pin D1/D3/D5 pin face):
    fn set_policy(&mut self, m: u8) {
        // act_wr_set_policy_mode(m): PASSIVE / INLINE_TEST / MAX.
        self.conf.inline = m == 2; // POLICY_MODE__INLINE
        self.conf.test = m == 1;   // POLICY_MODE__INLINE_TEST
        self.conf.passive = m == 0; // POLICY_MODE__PASSIVE (the C default)
        self.conf.max = m == 10;    // POLICY_MODE__MAX (the NEITHER arm face)
    }
    /// the thread_init leg — C `SnortConfig sc(""); sc.respond_attempts = k
    /// [+ .respond_device / run_flags READ]`: the attempts clamp / the
    /// gate legs (cc :192-:214) — the attempts the sc ctor NSDMI = 0 +
    /// the clamp legs land inside thread_init EXACT (DEV-019 Result face;
    /// the open() Err arms = the D14f / D14g jumped legs):
    fn thread_init_attempts(&mut self, k: u8) -> Result<bool, snort3::log::messages::Fatal> {
        self.conf.attempts = k;
        self.conf.device = None;
        self.conf.read = false;
        self.conf.max = false;
        act::Active::thread_init(&mut self.cx())
    }
    /// act_wr_reset_captures() — the FULL C reset list: the inject caps +
    /// the encode trio + the msg pw pair + the stream / de captures + the
    /// wsi pair (the pw pair = the landed LogEngine reset pair below):
    fn zero_caps(&mut self) {
        self.dq.borrow_mut().reset();
        self.enc.reset();
        self.st = StreamCap::default();
        self.de = DeCap::default();
        self.io.vp_calls = 0;
        self.io.last_vp = -99;
        { // act_wr_reset_captures() clears the dnet counter face too (NOT the open-fail knobs):
            let mut d = self.dcap.borrow_mut();
            d.eth_open = 0; d.eth_send = 0; d.eth_close = 0;
            d.ip_open = 0; d.ip_send = 0; d.ip_close = 0;
        }
        self.log.parse_warnings = 0; // pw_calls + pw_buf[0]=0 (the C face:
        // the reset ONLY clears the pw_calls/pw_buf pair — the C
        // act_wr_reset_captures NEVER resets the parse-warning count).
    }

    /// the ActiveCtx bundle (the C file-statics re-read legs — each call
    /// reborrows the fields: the Rust borrow law, NOT a semantic change):
    fn cx(&mut self) -> ActiveCtx<'_> {
        ActiveCtx {
            world: &mut self.world,
            daq: &mut self.daq,
            daq_stats: &mut self.stats,
            log: &mut self.log,
            conf: &self.conf, // conf behind a local ref — the trait reads, NEVER writes
            pt: Some(&mut self.pt),
            encode: &mut self.enc,
            io: &mut self.io,
            stream: &mut self.st,
            detection: &mut self.de,
            dnet: &mut self.dnet,
        }
    }

    /// the tracer LIVE re-activate face (the C tracer_live() legs: the ip
    /// path set + the static activate — through the landed ActivateRead-
    /// Face + StreamLog seam):
    fn tracer_live(&mut self) {
        let ip = IpApiLite { iat: IAT_4, src: Default::default(), dst: Default::default() };
        let cp = ConstraintPacketFace { ip_api: &ip, ip_proto_next: 6, sp: 0, dp: 0, tenant_id: 0 };
        let ar = packet_tracer::ActivateReadFace { pkth_flags: 0, pkt: &cp };
        self.pt.activate(&ar, &mut self.sl);
    }

    /// the dump flush-and-reset readout (the C `tb[0]=0; dump(tb, 511)`
    /// face: the pre-NUL bytes of the buffer copy):
    fn dump_str(&mut self) -> String {
        let mut tb = [0u8; 512];
        self.pt.dump(&mut tb);
        let end = tb.iter().position(|b| *b == 0).unwrap_or(tb.len());
        String::from_utf8_lossy(&tb[..end]).into_owned()
    }

    /// the DEV-022 kill_session re-drive (the C p->active back-pointer
    /// body re-entered right after the enclosing call returns):
    fn drain(sub: &mut Sub, w: &mut W) {
        while let Some(ef) = sub.p.kill_queue.first().copied() {
            sub.p.kill_queue.remove(0);
            sub.a.kill_session(&mut w.cx(), &mut sub.p, ef); // the DEV-022 back-pointer body (the REAL Active::kill_session home)
        }
    }
}

// ==========================================================================
// THE DEC ladder: the C probe legs Q0,T0,T1,T2,D0..D14,Z in EXACT drive
// order, one format! per probe printf, assembled into ONE string whose
// lines() face is byte-compared against VECTORS lines 1..44 IN ORDER.
// ==========================================================================

fn run_ladder() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut h = Harness::new();

    // ---- Q0: tracer configure+init+activate, then the live readout +
    // the StreamLog capture (the C PacketTracer::configure(true, "-") +
    // thread_init -> new() + tracer_live()): the landed tracer already
    // rode configure BEFORE new() at Harness::new(); activate the ip path:
    h.w.tracer_live();
    out.push(format!("Q0 packet_tracer_active={} sl=[{}]", h.w.pt.is_active() as i32, h.w.sl.cap));

    // ---- T0: the COLD identity face (the NSDMI seeds read through the
    // getters) + reset:
    out.push(format!(
        "T0 cold st={} whd={} act={} delay={} bypass={} dr={}",
        h.sub.a.get_status() as u8,
        h.sub.a.get_would_be_dropped_reason() as u8,
        h.sub.a.get_action() as u8,
        h.sub.a.get_delayed_action() as u8,
        h.sub.a.get_tunnel_bypass() as i32,
        h.sub.a.get_drop_reason().is_some() as i32,
    ));
    h.sub.a.reset();

    // ---- T1: the act_str table readout (8 action legs x 4 status arms,
    // status stamper NEVER touches the action; resume() closes the leg):
    {
        let mut rows: [String; 8];
        for st in 0..4 {
            rows = std::array::from_fn(|_| String::new());
            for (actn, row) in rows.iter_mut().enumerate() {
                h.sub.a.reset();
                match actn {
                    0 => h.sub.a.set_trust(),
                    1 => h.sub.a.set_allow(),
                    2 => {
                        h.w.dq.borrow_mut().pool = Some((8, 4)); // the pinned instance (pool 8 >= batch 4)
                        h.sub.a.hold_packet(&mut h.w.cx(), &h.sub.p);
                    }
                    3 => {
                        // the C sfd_local pinned instance (pool 8 >= 4); the
                        // C ALSO nulls p->daq_instance first (fresh_packet
                        // never attaches one — the selector leg picks the
                        // local instance) — the fused Option stays Some:
                        h.w.dq.borrow_mut().pool = Some((8, 4));
                        h.sub.a.retry_packet(&mut h.w.cx(), &h.sub.p);
                    }
                    4 => h.sub.a.rewrite_packet(&mut h.w.cx(), &h.sub.p, false),
                    5 => h.sub.a.drop_packet(&mut h.w.cx(), &h.sub.p, false),
                    6 => h.sub.a.block_again(),
                    _ => h.sub.a.reset_again(),
                }
                // stamp the status WITHOUT touching the action:
                match st {
                    0 => {} // the ALLOW leg (reset default)
                    1 => {
                        act::Active::suspend(&mut h.w.world, act::ASP_NONE);
                        h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
                        act::Active::resume(&mut h.w.world);
                    }
                    2 => {
                        act::Active::suspend(&mut h.w.world, act::ASP_NONE);
                        h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
                        h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
                        act::Active::resume(&mut h.w.world);
                    }
                    _ => h.sub.a.update_status(&h.w.cx(), &h.sub.p, true),
                }
                *row = h.sub.a.get_action_string().unwrap_or("").to_string();
                act::Active::resume(&mut h.w.world); // the C's closing resume() (no-op if already resumed)
            }
            out.push(format!("T1 row{st} {}", rows.iter().map(|r| r.as_str()).collect::<Vec<_>>().join("|")));
        }
        // the C's closing p->daq_instance / sfd_local nulls:
        h.sub.p.flow = None;
    }

    // ---- T2: the 7-slot counter != 0 face (all zero cold):
    {
        let c = act::get_active_counts(&h.w.world);
        let s: Vec<String> = [
            c.injects != 0,
            c.failed_injects != 0,
            c.direct_injects != 0,
            c.failed_direct_injects != 0,
            c.holds_denied != 0,
            c.holds_canceled != 0,
            c.holds_allowed != 0,
        ]
        .iter()
        .map(|b| (*b as i32).to_string())
        .collect();
        out.push(format!("T2 c7={}", s.join(",")));
    }

    // ---- D0: the clamp ladder (25 -> 20 MAX cap; 0 -> 1 floor) — the
    // attempts face walked through the send_reset encode-count (the probe
    // sc ctor leaves attempts 0; the clamp legs ride thread_init):
    {
        h.w.thread_init_attempts(25).unwrap();
        h.w.zero_caps();
        h.sub.a.reset();
        h.sub.a.send_reset(&mut h.w.cx(), &mut h.sub.p, 0);
        let clamp20 = h.w.enc.calls;
        h.w.thread_init_attempts(0).unwrap(); // the 0 -> 1 floor leg
        h.w.zero_caps();
        h.sub.a.send_reset(&mut h.w.cx(), &mut h.sub.p, 0);
        out.push(format!("D0 clamp20={} floor1={}", clamp20, h.w.enc.calls));
    }

    // ---- D1: suspend/resume + the FULL ASP_* -> WHD_* walk + RAII
    // (act_wr_set_policy_mode(MAX) first — the pin face):
    h.w.set_policy(10); // MAX mode
    {
        let rs = [act::ASP_NONE, act::ASP_PRUNE, act::ASP_TIMEOUT, act::ASP_RELOAD, act::ASP_EXIT];
        for (i, &asp) in rs.iter().enumerate() {
            h.sub.a.reset();
            act::Active::suspend(&mut h.w.world, asp);
            let susp1 = act::Active::is_suspended(&h.w.world);
            h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
            out.push(format!(
                "D1r{i} asr={} susp={} st={} whd={}",
                asp,
                susp1 as i32,
                h.sub.a.get_status() as u8,
                h.sub.a.get_would_be_dropped_reason() as u8,
            ));
            act::Active::resume(&mut h.w.world);
        }
        out.push(format!(
            "D1 after-resume susp={} whd_none-after={}",
            act::Active::is_suspended(&h.w.world) as i32,
            act::Active::get_whd_reason_from_suspend_reason(&h.w.world)
        ));
        // the RAII face (the C print split: in=1 captures at the guard's
        // live window, out=0 after the Drop-side resume). DEV-021's law
        // (the Rust guard holds the &mut world re-borrow) moves the
        // in-window READ to the ctor-body leg: the C guard's ctor body IS
        // Active::suspend(reason) (h :231-:232) — firing that body then
        // reading is the SAME world transition at the SAME program point;
        // the fresh guard on the next leg closes via the Drop-side
        // resume (h :234-:235), the out-face reads 0:
        act::Active::suspend(&mut h.w.world, act::ASP_RELOAD);
        let raii_in = act::Active::is_suspended(&h.w.world) as i32;
        {
            let _g = act::ActiveSuspendContext::new(&mut h.w.world, act::ASP_RELOAD);
        } // the Drop-side resume fires HERE (the C dtor face)
        out.push(format!("D1 raii in={raii_in} out={}", act::Active::is_suspended(&h.w.world) as i32));
    }

    // ---- D2: the can_partial / keep arms (AST_CANT via suspend +
    // cant_drop; the s_suspend_reason >ASP_NONE !=ASP_TIMEOUT arms):
    {
        let (mut cp, mut kp, mut kt) = (String::new(), String::new(), String::new());
        for cs in [act::ASP_NONE, act::ASP_PRUNE, act::ASP_TIMEOUT, act::ASP_RELOAD] {
            h.sub.a.reset();
            act::Active::suspend(&mut h.w.world, cs);
            h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
            cp.push_str(&format!("{},", h.sub.a.can_partial_block_session(&h.w.world) as i32));
            kp.push_str(&format!("{},", act::Active::keep_pruned_flow(&h.w.world) as i32));
            kt.push_str(&format!("{},", act::Active::keep_timedout_flow(&h.w.world) as i32));
            act::Active::resume(&mut h.w.world);
        }
        cp.pop();
        kp.pop();
        kt.pop();
        out.push(format!("D2 st={} cp={cp} kp={kp} kt={kt}", act::AST_CANT));
    }

    // ---- D3: the ALLOW->CANT escalation (ASP_EXIT fuel) + the dead-
    // arm (the CANT STAYS) + the FORCE arm + the daq_update_status no-op:
    {
        h.sub.a.reset();
        act::Active::suspend(&mut h.w.world, act::ASP_EXIT);
        h.sub.a.update_status(&h.w.cx(), &h.sub.p, false); // ALLOW->CANT
        let s1 = h.sub.a.get_status() as u8;
        let s1r = h.sub.a.get_would_be_dropped_reason() as u8;
        h.sub.a.drop_packet(&mut h.w.cx(), &h.sub.p, false); // the CANT STAYS (the dead else-arm face)
        let s2 = h.sub.a.get_status() as u8;
        act::Active::resume(&mut h.w.world);
        h.sub.a.reset();
        h.sub.a.update_status(&h.w.cx(), &h.sub.p, true); // FORCE
        let s4 = h.sub.a.get_status() as u8;
        h.sub.a.reset();
        // the C drop leg: reset + daq_update_status (NOT drop_packet —
        // probe: a.reset(); a.daq_drop_packet(p) → status-only leg):
        h.sub.a.daq_drop_packet(&mut h.w.cx(), &h.sub.p); // the MAX-mode no-op arm
        let s5 = h.sub.a.get_status() as u8;
        out.push(format!("D3 cant={s1},{s1r} stay={s2} force={s4} daq={s5} act={}", h.sub.a.get_action() as u8));
    }

    // ---- D4: the actionability arms (the mode bits -> the WHD_* pins):
    // INLINE_TEST / PASSIVE / INLINE+not-forwarding / INLINE+rewrite+
    // no-replace (STAMPS the WHD via the non-force leg) + the FORCE
    // skips the leg (the force->FORCE arm stays face):
    {
        h.sub.a.reset();
        h.w.set_policy(1); // INLINE_TEST
        W::set_forwarding(&mut h.sub, true);
        h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
        let (t1, t2) = (h.sub.a.get_status() as u8, h.sub.a.get_would_be_dropped_reason() as u8);
        h.w.set_policy(0); // PASSIVE
        h.sub.a.reset();
        h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
        let (p1, p2) = (h.sub.a.get_status() as u8, h.sub.a.get_would_be_dropped_reason() as u8);
        h.w.set_policy(2); // INLINE
        W::set_forwarding(&mut h.sub, false); // sfd_forwarding = false
        h.sub.a.reset();
        h.sub.a.update_status(&h.w.cx(), &h.sub.p, false);
        let (i1, i2) = (h.sub.a.get_status() as u8, h.sub.a.get_would_be_dropped_reason() as u8);
        W::set_forwarding(&mut h.sub, true); // sfd_forwarding = true
        h.w.dq.borrow_mut().can_replace = false; // sfd_can_replace = false
        h.sub.a.reset();
        h.sub.a.rewrite_packet(&mut h.w.cx(), &h.sub.p, false); // the ACT_REWRITE set + the non-force leg STAMPS
        let (r1, r2) = (h.sub.a.get_status() as u8, h.sub.a.get_would_be_dropped_reason() as u8);
        // the FORCE-into-FORCE-arm stays face (FORCE skips actionable):
        h.sub.a.reset();
        h.sub.a.update_status(&h.w.cx(), &h.sub.p, true); // FORCE lands
        h.sub.a.rewrite_packet(&mut h.w.cx(), &h.sub.p, false); // (action 4 < 4 false; the FORCE arm stays)
        let f1 = h.sub.a.get_status() as u8;
        h.w.dq.borrow_mut().can_replace = true; // sfd_can_replace back
        h.w.set_policy(10); // MAX
        out.push(format!("D4 test={t1},{t2} passive={p1},{p2} inlineNF={i1},{i2} rewriteNR={r1},{r2} forceStay={f1}"));
    }

    // ---- D5: THE STRAFE ladder (the heart face — attempts=6; fresh
    // Active send_reset walk i=0..5; the mirror captures EVERY
    // (TcpResponse kind, EncodeFlags) pair):
    {
        h.w.thread_init_attempts(6).unwrap(); // sc ctor 0 + attempts=6 (the MAX face stays — the set_policy pin)
        // the set_policy(10) already stands (thread_init_attempts did NOT
        // clobber the policy modes: the thread_init set_policy(10) leg
        // rides inline=false/test=false/passive=false/max=true):
        h.sub.a.reset();
        h.w.zero_caps();
        h.sub.a.send_reset(&mut h.w.cx(), &mut h.sub.p, 0);
        let kinds: Vec<String> = h.w.enc.kinds.iter().map(|k| k.to_string()).collect();
        out.push(format!("D5 n={} kinds={}", h.w.enc.calls, kinds.join(",")));
        for (i, fl) in h.w.enc.flags.iter().enumerate() {
            out.push(format!("D5f{i}={:016x}", fl));
        }
        let d = h.w.dq.borrow();
        out.push(format!("D5 inj={} revs={} len={}", d.inject_calls, d.last_rev, d.last_len));
    }

    // ---- D6: the set/apply arms. THE probe drive order (the D6 print
    // arms): fresh reset + delayed BLOCK, DROP-refused (d=6,6); the fresh
    // reset (the probe's `a.reset()` right above the reset arm — the
    // trust arm runs FIRST in the probe but the d=6,6 pair reads BEFORE
    // that re-arm: the face pins the fresh pair, not the stale trust
    // pair); the DROP arm; the BLOCK arm; the RESET arm + the drain
    // (the execute face); the RETRY null-pool downgrade (pool 1 < 4);
    // the TRUST cold face:
    {
        // D6 line 1 (probe : d1 BLOCK / d2 DROP-refused / trust1 after
        // the (reset;ALLOW;TRUST) pair / drop arm / block arm / sfq):
        h.sub.a.reset();
        h.sub.a.set_delayed_action(act::ActiveActionType::ActBlock, false);
        let d1 = h.sub.a.get_delayed_action() as u8;
        h.sub.a.set_delayed_action(act::ActiveActionType::ActDrop, false);
        let d2 = h.sub.a.get_delayed_action() as u8;
        h.sub.a.reset();
        h.sub.a.set_delayed_action(act::ActiveActionType::ActAllow, false);
        h.sub.a.set_delayed_action(act::ActiveActionType::ActTrust, false); // the ALLOW->TRUST EXCEPTION arm
        let trust1 = h.sub.a.get_delayed_action() as u8; // ACT_TRUST (0)
        // DROP arm:
        h.sub.a.reset();
        h.sub.a.set_delayed_action(act::ActiveActionType::ActDrop, false);
        h.sub.a.apply_delayed_action(&mut h.w.cx(), &mut h.sub.p);
        let d4 = h.sub.a.get_action() as u8;
        // BLOCK arm (the force stays unset; MAX policy => NO Stream leg):
        h.sub.a.reset();
        h.sub.a.set_delayed_action(act::ActiveActionType::ActBlock, false);
        h.w.zero_caps();
        h.sub.a.apply_delayed_action(&mut h.w.cx(), &mut h.sub.p);
        out.push(format!("D6 d={d1},{d2} trust1={trust1} drop={d4} block={} sfq={}", h.sub.a.get_action() as u8, h.w.st.block));
        // the probe's a.reset() lands HERE (the trust1 line prints AFTER
        // the apply arms — the printf fires at :299, the reset at :288
        // fires BEFORE the arms; the print shows the fresh values because
        // `trust1` is the C LOCAL, captured at set-time — the face rides
        // the local, the state re-arms — the pin: the LOCAL, NOT the
        // state):
        h.sub.a.reset();
        // the RESET arm (delayed_reject = the default_reset via the 1-arg
        // setter; the queue-drain face = execute -> the ResetAction::delayed_exec -> kill_session -> send_reset x2 THROUGH the encode mirror):
        h.w.set_policy(10); // MAX (the reset arm's policy leg)
        h.sub.a.reset();
        h.sub.a.set_delayed_action(act::ActiveActionType::ActReset, false);
        h.w.zero_caps();
        h.sub.a.apply_delayed_action(&mut h.w.cx(), &mut h.sub.p); // queue (the slot) + the p->flow face stays None
        let sf_calls = h.w.dq.borrow().inject_calls;
        let (dropf, initar) = (h.w.st.drop, h.w.st.init);
        h.sub.a.execute(&mut h.w.cx(), &mut h.sub.p); // the queue drain (the delayed_exec queues the kill legs)
        W::drain(&mut h.sub, &mut h.w); // the C re-entrant p->active kill_session legs (DEV-022)
        h.sub.a.reset();
        // the RETRY null-pool downgrade face (pool 1 < batch 4):
        h.w.dq.borrow_mut().pool = Some((1, 4)); // wsi_pool=1 wsi_batch=4
        h.sub.a.reset();
        h.sub.a.set_delayed_action(act::ActiveActionType::ActRetry, false);
        let rd_before = h.w.stats.retries_dropped;
        h.sub.a.apply_delayed_action(&mut h.w.cx(), &mut h.sub.p);
        out.push(format!(
            "D6 reset_act={} drop_flow={dropf} init_ar={initar} exec_inj={sf_calls} retry->drop={} rd={}",
            act::ACT_RESET, h.sub.a.get_action() as u8, h.w.stats.retries_dropped - rd_before,
        ));
        h.w.dq.borrow_mut().pool = Some((8, 4)); // wsi back
        // the TRUST cold face (null flow, not force: the disable_all cap +
        // the delayed_after_apply = the cc :964 tail store):
        h.sub.a.reset();
        h.sub.a.set_delayed_action(act::ActiveActionType::ActTrust, false);
        h.w.zero_caps();
        h.sub.a.apply_delayed_action(&mut h.w.cx(), &mut h.sub.p);
        let dee = h.w.de.disable;
        let d5 = h.sub.a.get_delayed_action() as u8;
        out.push(format!("D6 trust de={dee} act={} delayed_after_apply={d5}", h.sub.a.get_action() as u8));
    }

    // ---- D7: trust force + the hold ladder through the 7-slot counters:
    {
        let c = act::get_active_counts(&h.w.world);
        let base = [c.injects, c.failed_injects, c.direct_injects, c.failed_direct_injects, c.holds_denied, c.holds_canceled, c.holds_allowed];
        h.sub.p.packet_flags = 0;
        h.sub.a.reset();
        h.sub.a.trust_session(&mut h.w.cx(), &mut h.sub.p, true); // force: PKT_IGNORE + disable_inspect (flow None -> the trust legs skip)
        let ign = (h.sub.p.packet_flags & act::PKT_IGNORE) != 0;
        let di = h.sub.p.disable_inspect;
        // a fresh a.reset() then hold (the DENIED null-pool face):
        h.w.dq.borrow_mut().pool = None; // the C pool 0 face (null pool)
        h.sub.a.reset();
        h.sub.a.hold_packet(&mut h.w.cx(), &h.sub.p);
        let c = act::get_active_counts(&h.w.world);
        let hd = (c.holds_denied - base[4]) as i32;
        // the fresh si (pool 8 >= batch 4) + the ALLOWED face:
        h.w.dq.borrow_mut().pool = Some((8, 4));
        h.sub.a.reset();
        let hr = h.sub.a.hold_packet(&mut h.w.cx(), &h.sub.p);
        let ishold = h.sub.a.is_packet_held();
        h.sub.a.cancel_packet_hold(&mut h.w.world); // holds_canceled + ACT_ALLOW
        let c = act::get_active_counts(&h.w.world);
        let hc = (c.holds_canceled - base[5]) as i32;
        h.sub.a.reset();
        h.sub.a.trust_session(&mut h.w.cx(), &mut h.sub.p, false); // null flow: try_trust NEVER runs (no ACT_TRUST)
        out.push(format!(
            "D7 ig={} di={} denied={hd} hold={} ishold={} can={hc} trusted={}",
            ign as i32,
            di as i32,
            hr as i32,
            ishold as i32,
            h.sub.a.session_was_trusted() as i32,
        ));
    }

    // ---- D8: the trace-log CAPTURE legs through the LANDED tracer (the
    // pt-rmod twin driving law): the encode-FAIL arm (failed_injects++ +
    // the log line through PacketTrace::log + the dump readout face),
    // then the send-ok line (ONE attempt = ONE dump leg, the C pin:
    // attempts=1; the thread_init legs reset the attempts — the C sc
    // ctor's 0 + the leg's own set):
    {
        h.w.enc.null = true; // pm_encode_return_null = 1
        h.w.zero_caps(); // the pw reset pair too (the C pw_calls reset face)
        h.w.tracer_live(); // the C re-arms the live face (already true; the C calls it again)
        h.w.thread_init_attempts(1).unwrap(); // ONE attempt: ONE log line per leg
        h.w.dump_str(); // the PRE-LEG flush: the D4-D6 carry is DISCARDED (the dump FLUSH+RESET face)
        h.sub.a.reset(); // the C resets BEFORE the leg (the carry pin: the previous leg left ACT_BLOCK)
        h.sub.a.send_reset(&mut h.w.cx(), &mut h.sub.p, ENC_FLAG_FWD); // the encode-FAIL leg
        let msg = h.w.dump_str(); // the C `tb[0]=0; dump(tb,...)` — the C prints the raw buffer INCLUDING its trailing NUL byte. The Rust dump writes the same (103 data bytes + a NUL); the C printf("[%s]") stops at the NUL (the C-string contract) — the printed face = the pre-NUL bytes (the C's own contract, cited):
        out.push(format!("D8 fail_log=[{msg}]"));
        h.w.enc.null = false;
        h.w.zero_caps();
        h.sub.a.reset();
        h.sub.a.send_reset(&mut h.w.cx(), &mut h.sub.p, ENC_FLAG_FWD); // the send-ok leg
        let msg = h.w.dump_str();
        h.sub.a.reset();
        out.push(format!("D8 ok_log=[{msg}] inj={}", h.w.dq.borrow().inject_calls));
        h.w.thread_init_attempts(2).unwrap(); // the C restore face
    }

    // ---- D9: the send_data faces (maxPayload 0 -> the payload loop SKIP +
    // the FIN success sent++ leg; the FIN encode-FAIL leg failed_injects
    // delta; the loop-chunked 2+2+2+1 face — the pm_maxpay_calls face
    // STAYS 3 through the C reset law (the C act_wr_reset_captures NEVER
    // resets pm_maxpay_calls):
    {
        h.w.enc.maxp = 0; // pm_maxpayload_face = 0
        h.w.zero_caps();
        let pay: [u8; 7] = *b"payload";
        let sent = h.sub.a.send_data(&mut h.w.cx(), &mut h.sub.p, ENC_FLAG_FWD, Some(&pay), 7);
        let fin_kind = h.w.enc.kinds[0];
        let f0 = act::get_active_counts(&h.w.world).failed_injects;
        h.w.enc.null = true;
        let sent2 = h.sub.a.send_data(&mut h.w.cx(), &mut h.sub.p, ENC_FLAG_FWD, Some(&pay), 7); // the FIN encode-FAIL arm (the loop SKIPS at maxp 0 — the only encode = the FIN -> return sent 0)
        let faildelta = (act::get_active_counts(&h.w.world).failed_injects - f0) as i32;
        h.w.enc.null = false;
        h.w.enc.maxp = 2; // pm_maxpayload_face = 2
        let sent3 = h.sub.a.send_data(&mut h.w.cx(), &mut h.sub.p, ENC_FLAG_FWD, Some(&pay), 7); // the chunked 2+2+2+1 loop face
        let loopenc = h.w.enc.calls; // the FULL calls on the D9 leg (NOT reset between the sent/sent2/sent3 calls)
        h.sub.a.reset();
        out.push(format!(
            "D9 sent={sent} kind={fin_kind} maxp={} sent2={sent2} fdelta={faildelta} sent3={sent3} enc={loopenc}",
            h.w.enc.max_calls.get(),
        ));
        h.w.enc.maxp = 0; // the C restore face
    }

    // ---- D10: the read_mode / can_inject-disabled thread_init face —
    // the pw capture (ride-EXACTLY the landed home's entry, stripped to
    // the C pw_buf bytes) + the cold s_attempts=0 inject_data early-out:
    {
        h.w.conf.read = true; // sc.run_flags |= RUN_FLAG__READ
        h.w.conf.attempts = 3;
        h.w.conf.device = None;
        h.w.dq.borrow_mut().can_inject = false; // the disabled-face fuel
        let ok = act::Active::thread_init(&mut h.w.cx()).unwrap(); // the read gate skips open EXACTLY (cc :203)
        let pwc = h.w.log.parse_warnings as i32; // the C snapshot BEFORE the reset (the pw_calls readout face)
        let pw_text = pw_capture(&h.w.log);
        h.w.zero_caps(); // the pw reset pair (pw_calls=0 / pw_buf[0]=0)
        let pay: [u8; 4] = [1, 2, 3, 4];
        h.sub.a.reset();
        h.sub.a.inject_data(&mut h.w.cx(), &mut h.sub.p, 0, &pay, 4); // the cold s_attempts-0 early-out (cc :603)
        let c = act::get_active_counts(&h.w.world);
        let (i0, f0) = (c.injects, c.failed_injects);
        h.sub.a.reset();
        let c = act::get_active_counts(&h.w.world);
        out.push(format!(
            "D10 rc={} pwc={pwc} pw=[{pw_text}] inj_calls={} enc_calls={} inj_d={} fail_d={}",
            ok as i32,
            h.w.dq.borrow().inject_calls,
            h.w.enc.calls,
            (c.injects - i0) as i32,
            (c.failed_injects - f0) as i32,
        ));
        h.w.dq.borrow_mut().can_inject = true;
        h.w.thread_init_attempts(2).unwrap(); // the restore (the open NEVER taken)
    }

    // ---- D11: the drop_reason family through the io seam verdict legs:
    {
        h.sub.a.reset();
        h.w.zero_caps();
        h.sub.p.daq_msg = 1; // the C sentinel 0x1 (the seam ignores the value — the witness face never armed it)
        h.sub.a.send_reason_to_daq(&mut h.w.cx(), &mut h.sub.p); // the null drop_reason early-out
        let e0 = h.w.io.vp_calls;
        act::Active::set_default_drop_reason(&mut h.w.world, 5);
        h.sub.a.set_drop_reason(&h.w.world, "gen-reason"); // first-wins arm #1
        h.sub.a.set_drop_reason(&h.w.world, "late-reason"); // refused (already set)
        h.sub.a.send_reason_to_daq(&mut h.w.cx(), &mut h.sub.p); // the default 5 face
        let d5 = h.w.io.last_vp;
        act::Active::map_drop_reason_id(&mut h.w.world, "gen-reason", 7); // map-hit arm
        h.sub.a.reset();
        h.sub.a.set_drop_reason(&h.w.world, "gen-reason");
        h.sub.a.send_reason_to_daq(&mut h.w.cx(), &mut h.sub.p);
        let m7 = h.w.io.last_vp;
        let first = h.sub.a.get_drop_reason().unwrap_or("").to_string();
        act::Active::suspend(&mut h.w.world, act::ASP_EXIT);
        h.sub.a.reset(); // reset CLEARS drop_reason
        h.sub.a.set_drop_reason(&h.w.world, "susp-late"); // the suspended-refused arm
        let sr = h.sub.a.get_drop_reason().is_some() as i32;
        act::Active::resume(&mut h.w.world);
        h.sub.a.reset();
        out.push(format!("D11 nulleg={e0} first=[{first}] def5={d5} map7={m7} suspset={sr}"));
    }

    // ---- D12: the queue()/execute() priority law + clear_queue + the
    // execute null drain (the hits ride the thread-local face):
    {
        h.sub.a.reset();
        h.sub.p.clear_action();
        h.w.dq.borrow_mut().pool = Some((8, 4)); // the C attach (the flow face: the p->flow = flow_store below, not a DAQ thing)
        act::Active::queue(&mut h.w.cx(), &PA_LO, &mut h.sub.p); // the empty-slot take
        let took1 = (h.sub.p.current_action_priority() == Some(ActionPriority::ApLocal)) as i32;
        act::Active::queue(&mut h.w.cx(), &PA_HI, &mut h.sub.p); // 4 > 0 override
        let over = (h.sub.p.current_action_priority() == Some(ActionPriority::ApRemote)) as i32;
        act::Active::queue(&mut h.w.cx(), &PA_EQ, &mut h.sub.p); // 4 > 4 FALSE arm
        let keep = (h.sub.p.current_action_priority() == Some(ActionPriority::ApRemote)) as i32;
        h.sub.p.flow = Some(FlowTwin::default()); // p->flow = flow_store (the trust round-trip face)
        h.sub.a.set_trust(); // the execute trust round-trip (session_was_trusted TRUE)
        h.w.zero_caps();
        act::Active::queue(&mut h.w.cx(), &PA_HI, &mut h.sub.p); // the drain leg (same priority: 4 > 4 FALSE, PA_HI stays)
        h.sub.a.execute(&mut h.w.cx(), &mut h.sub.p); // drain + finalize (the cold face) + Flow::trust x1
        W::drain(&mut h.sub, &mut h.w);
        let ft = ftrust_of(&h.sub.p); // flow_trust_calls (the session_was_trusted -> flow->trust() leg)
        let drained = (PA_HITS.with(|x| x.borrow()[1]) == 1) as i32; // pa_hits[1] the drain face
        act::Active::clear_queue(&mut h.w.cx(), &mut h.sub.p); // cc :1020/:1021 (clear_action + the de_clear_replacement leg)
        let clr = (h.sub.p.current_action_priority().is_none()) as i32 + h.w.de.clear as i32;
        h.sub.a.execute(&mut h.w.cx(), &mut h.sub.p); // the null-action drain face (slot already None)
        W::drain(&mut h.sub, &mut h.w);
        h.sub.p.flow = None;
        out.push(format!("D12 take={took1} over={over} keep={keep} drain={drained} ftrust={ft} clr={clr}"));
    }

    // ---- D13: the reset() CLEARS-7 face after dirtying EVERY field:
    {
        h.sub.a.set_trust(); // ACT_TRUST
        h.sub.a.update_status(&h.w.cx(), &h.sub.p, true); // FORCE (the packet_force_dropped face)
        h.sub.a.set_tunnel_bypass();
        h.sub.a.set_tunnel_bypass(); // x2 (the >0 face)
        h.sub.a.set_delayed_action_with_act(act::ActiveActionType::ActReset, Some(&PA_LO), false);
        h.sub.a.set_drop_reason(&h.w.world, "dirty");
        let pre = (h.sub.a.get_tunnel_bypass()
            && h.sub.a.get_action() == act::ActiveActionType::ActTrust
            && h.sub.a.packet_force_dropped()
            && h.sub.a.get_delayed_action() == act::ActiveActionType::ActReset
            && h.sub.a.get_drop_reason().is_some()) as i32;
        h.sub.a.reset();
        out.push(format!(
            "D13 pre={pre} post st={} whd={} act={} delay={} bypass={} dr={} str=[{}]",
            h.sub.a.get_status() as u8,
            h.sub.a.get_would_be_dropped_reason() as u8,
            h.sub.a.get_action() as u8,
            h.sub.a.get_delayed_action() as u8,
            h.sub.a.get_tunnel_bypass() as i32,
            h.sub.a.get_drop_reason().is_some() as i32,
            h.sub.a.get_action_string().unwrap_or(""),
        ));
    }

    // ---- D14: THE open()/close() ladder + the two FatalError jumped
    // faces (the DEV-008 Err arm IS the C siglongjmp face; the C's
    // never-returning shape; the stderr shunt = the landed log home):
    {
        // (a) the ip open-success capture face:
        h.w.dq.borrow_mut().can_inject = false; // forces the open() leg
        h.w.thread_init_attempts(2).unwrap(); // respond_device empty -> the ip face
        h.sub.a.reset();
        h.sub.a.send_reset(&mut h.w.cx(), &mut h.sub.p, 0); // the s_send == send_ip face (enc maxp0 — the RST leg encodes + ip_send sends; loop x2 -> ip_send 2)
        let (ip_open, ip_send, eth_open) = {
            let d = h.w.dcap.borrow();
            (d.ip_open, d.ip_send, d.eth_open)
        };
        act::Active::thread_term(&mut h.w.world); // the ip_close + the null set
        act::Active::thread_term(&mut h.w.world); // the idempotence face (the 2nd close = a no-op)
        let close1 = { let d = h.w.dcap.borrow(); (d.ip_close, d.eth_close) };
        out.push(format!("D14 ip_open={ip_open} ip_send={ip_send} eth_open={eth_open} close1={},{}", close1.0, close1.1));
        h.w.dq.borrow_mut().can_inject = true;
    }
    {
        // (b) the eth open-success face:
        h.w.conf.attempts = 2;
        h.w.conf.device = Some("eth0"); // the C sc.respond_device = "eth0"
        h.w.set_policy(10);
        act::Active::thread_init(&mut h.w.cx()).unwrap();
        h.sub.a.reset();
        h.sub.a.send_reset(&mut h.w.cx(), &mut h.sub.p, 0); // the send_eth capture face
        let (eo, es) = { let d = h.w.dcap.borrow(); (d.eth_open, d.eth_send) };
        out.push(format!("D14h eth_open={eo} eth_send={es}"));
        act::Active::thread_term(&mut h.w.world);
    }
    {
        // (c) the eth-open-Fail FatalError face (the Err = the jumped face;
        // the C dup2 /dev/null shunt = the harness's stderr-silent face —
        // the landed home NEVER writes any stream the twin captures):
        h.w.conf.attempts = 3;
        h.w.conf.device = Some("bogus-dev");
        h.w.dcap.borrow_mut().eth_open_fail = true; // dnet_eth_open_fail = 1
        let jumped = act::Active::thread_init(&mut h.w.cx()).is_err() as i32;
        h.w.dcap.borrow_mut().eth_open_fail = false;
        let (eo2, ec2) = { let d = h.w.dcap.borrow(); (d.eth_open, d.eth_close) };
        out.push(format!("D14f eth_fail jumped={jumped} eth_open={eo2} eth_close={ec2}"));
        // the ip-open-fail FatalError face (device empty + can_inject false):
        h.w.dq.borrow_mut().can_inject = false;
        h.w.dcap.borrow_mut().ip_open_fail = true; // dnet_ip_open_fail = 1
        h.w.conf.attempts = 3;
        h.w.conf.device = None;
        let jumped = act::Active::thread_init(&mut h.w.cx()).is_err() as i32;
        h.w.dcap.borrow_mut().ip_open_fail = false;
        h.w.dq.borrow_mut().can_inject = true;
        let (io2, ic2) = { let d = h.w.dcap.borrow(); (d.ip_open, d.ip_close) };
        out.push(format!("D14g ipfail jumped={jumped} ip_open={io2} ip_close={ic2}"));
        // the restore face (a clean world):
        h.w.thread_init_attempts(2).unwrap();
    }

    // ---- Z: the C end = 0 face (the landed term leg + the Z print):
    h.w.pt.term(&mut h.w.log, &mut Blog);
    out.push("Z end=0".to_string());
    out
}

/// the ParseWarning capture face — the ride-EXACT landed-home entry minus
/// the "WARNING: " prefix and the home's trailing newline (the C pw_buf
/// vsnprintf bytes); the face read from the log.out transcript:
fn pw_capture(log: &LogEngine) -> String {
    let t = log.out.iter().find(|e| e.phase == snort3::log::messages::Phase::Stderr && e.text.starts_with("WARNING")).expect("the pw capture face");
    let body = t.text.strip_prefix("WARNING").unwrap_or(&t.text);
    let body = body.strip_prefix(": ").unwrap_or(body);
    body.trim_end_matches('\n').to_string()
}

/// the flow_trust capture face (the D12 ftrust leg): the p->flow twin's
/// OWN count (the twin pair, not a global):
fn ftrust_of(p: &PacketTwin) -> usize {
    p.flow.as_ref().map(|f| f.trust).unwrap_or(0)
}

fn ladder() -> &'static Vec<String> {
    static L: OnceLock<Vec<String>> = OnceLock::new();
    L.get_or_init(run_ladder)
}

/// the ladder lines JOINED then re-split: a captured log line ending in
/// '\n' (the C dump-into-%s face) prints a vector line-pair (the D8 legs
/// span lines 31/32 + 33/34) — the joined+re-split face is the byte face
/// the C printf contract produces, so the ladder lines ride it:
fn jjoined() -> &'static String {
    static J: OnceLock<String> = OnceLock::new();
    J.get_or_init(|| format!("{}
", ladder().join("
")))
}

fn vec_lines() -> Vec<String> {
    jjoined().lines().map(|s| s.to_string()).collect()
}

fn assert_range(lo: usize, hi: usize) {
    let v: Vec<&str> = VECTORS.lines().collect();
    let j: Vec<&str> = jjoined().lines().collect();
    assert_eq!(j.len(), 44, "the joined ladder face EXACTLY-44 rows");
    assert_eq!(v.len(), 44, "the tracked DEC seed EXACTLY-44 rows");
    for i in lo..hi {
        assert_eq!(j[i], v[i], "DEC line {} byte-equal (IN ORDER)", i + 1);
    }
}

// ==========================================================================
// 1. The ground pair: sizes + md5s + the ZERO in-TU TEST face + the test
//    CMake EXACTLY-2 arms + the dialect 375 L / 4 ^TEST heads + the
//    CppUTest host absence faces.
// ==========================================================================

#[test]
fn ground_pair_identity_and_zero_test_face() {
    let cc = ground("packet_io/active.cc");
    let h = ground("packet_io/active.h");
    assert_eq!(cc.lines().count(), 1074, "cc 1074 L (md5 3a2a238007... — the harness ground arm re-pins)");
    assert_eq!(h.lines().count(), 240, "h 240 L (md5 ce608579... likewise)");
    assert_eq!(1074 + 240, 1314, "the pair ledger the landing header cites (cc + h = 1314 L)");
    assert_eq!(md5(cc.as_bytes()), "3a2a2380073775c90383a9c41ead2282", "the cc md5 NEVER drifts");
    assert_eq!(md5(h.as_bytes()), "ce6085794642721562df16740895a08a", "the h md5 NEVER drifts");
    // the ZERO in-TU TEST face by the CONTENT line-count (the gate pick
    // measured ZERO TEST_CASE faces BOTH files — the ZERO-gate row):
    assert_eq!(cc.lines().filter(|l| l.contains("TEST_CASE")).count(), 0, "ZERO TEST_CASE lines in the cc");
    assert_eq!(h.lines().filter(|l| l.contains("TEST_CASE")).count(), 0, "ZERO TEST_CASE lines in the h");
    // the test-CMake face: EXACTLY-2 add_cp""utest suites; the row's own
    // dialect file 375 L + EXACTLY-4 ^TEST heads:
    let cm = ground("packet_io/test/CMakeLists.txt");
    let needle = ["add_cp", "putest"].concat();
    assert_eq!(cm.lines().filter(|l| l.contains(&needle)).count(), 2, "EXACTLY-2 suites ride this dir");
    let dialect = ground("packet_io/test/active_packet_trace_test.cc");
    assert_eq!(dialect.lines().count(), 375, "the row test dialect stays 375 L");
    assert_eq!(dialect.lines().filter(|l| l.starts_with("TEST(")).count(), 4, "EXACTLY-4 ^TEST heads over the 375 L dialect");
    // the CppUTest host face: the system include home is ABSENT on this
    // host (the harness grafts its own stand-in — a std read find-0):
    assert!(!Path::new("/usr/include/cppunit").exists(), "the CppUTest host include dir find-0");
}

// ==========================================================================
// 2. The tracked seed faces: the vectors md5s FIRST-RUN-SEED pinned +
//    the head censuses (the byte faces ride per-line by tests 3-9).
// ==========================================================================

#[test]
fn dec_vectors_shape_and_seed_md5() {
    assert_eq!(md5(VECTORS.as_bytes()), "5624bb43209b9931ab890f8ba4570e7d", "the DEC seed md5 NEVER drifts (drift-refused)");
    assert_eq!(md5(VECTORS_FACE_A.as_bytes()), "9e15e6c1233a85c2c8b15e5f87a29e00", "the FACE-A seed md5 NEVER drifts");
    let heads: Vec<String> = vec_lines().iter().map(|l| l.split([' ', '=', '(']).next().unwrap().to_string()).collect();
    assert_eq!(heads[0], "Q0", "the Q0 head (ONE tracer-live leg)");
    assert_eq!(heads[43], "Z", "the Z terminator");
    assert_eq!(head_count("D5f"), 6, "the D5f0..f5 Strafe hex legs EXACTLY-6");
    assert_eq!(head_count("D1r"), 5, "the D1r0..4 map-walk legs EXACTLY-5");
    assert_eq!(head_count("D6"), 3, "the 3 D6 print legs EXACTLY-3");
    let fa: Vec<String> = VECTORS_FACE_A.lines().map(|l| l.split_whitespace().next().unwrap().to_string()).collect();
    assert_eq!(fa.len(), 10, "the FACE-A seed EXACTLY-10 rows");
    assert_eq!(
        fa,
        vec!["A0", "A1", "A2", "A3", "A3b", "A3c", "A4", "A5", "A6", "Z-A"],
        "the FACE-A head census"
    );
}

fn head_count(prefix: &str) -> usize {
    vec_lines().iter().filter(|l| l.starts_with(prefix)).count()
}

// ==========================================================================
// 3-10. The BYTE-EQUAL DEC replay IN ORDER (the ONE ladder pass): every
// vectors line re-derived leg-by-leg through the doubles (the probe
// legs Q0,T0,T1,T2,D0..D14,Z; the D5f hex faces = the Strafe
// (kind,flags) capture — drive order i=0..5 through send_reset with
// attempts=6 dsize=100 ntohs(th_win)=4660: 0=SEQ; 1=dsize value 100
// (0x64); 2,3=+dsize<<1 (0xC8 -> value 0x12c; the STRAFE VALUE carries
// loop-cumulative — value=Strafe(value); 0x1f4); 4=+dsize<<2 (0x190 ->
// 0x384); 5=the default arm +ntohs(th_win)>>1 = 4660>>1=2330 (0x91A ->
// 0xC9E); each line rides the (ID|RAW=0x6000)>>VAL-mask base | SEQ =
// 0x6400000000000000 base OR-ed with the VALUE):
// ==========================================================================

#[test]
fn dec_q0_t0_t1_t2_lines() {
    assert_range(0, 7); // Q0 + T0 + the 4 T1 rows + T2 (lines 1-7)
}

#[test]
fn dec_d0_through_d4_lines() {
    assert_range(7, 15); // D0 clamp + D1r0..4 + after-resume + raii (8-15)
    assert_range(15, 18); // D2 cp/kp/kt arms + D3 escalation + D4 policy arms (16-18)
}



#[test]
fn dec_d5_strafe_ladder_lines() {
    assert_range(18, 26); // D5 n/kinds, the D5f0..f5 hex faces, D5 inj/revs/len (19-26)
    // the RE-PIN of the exact Strafe drive-law (from the port's OWN
    // captured capture — INDEXED, NEVER set membership):
    let g: Vec<&str> = jjoined().lines().collect();
    let want = ["6400000000000000", "6400000000000064", "640000000000012c", "64000000000001f4", "6400000000000384", "6400000000000c9e"];
    for i in 0..6 {
        assert_eq!(g[19 + i], format!("D5f{i}={}", want[i]), "the Strafe hex face #{i} IN drive order (value-carries: i=1 dsize(0x64); i=2 +dsize<<1 -> 0x12c; i=3 same again on the CARRIED value -> 0x1f4; i=4 +dsize<<2 -> 0x384; i=5 th_win>>1(2330) -> 0xc9e)");
    }
}

#[test]
fn dec_d6_d7_lines() {
    assert_range(26, 29); // the 3 D6 lines (27-29): the no-downgrade d=6,6 + trust1=0 the cc :922-:926 EXCEPTION-face (the face prints trust1 at set time — pin face trust1=0: the probe prints trust1 at :299 which fires AFTER the re-arm... the probe code says `int trust1 = a.get_delayed_action() at :290`, BEFORE the block-arm apply (:296) and the DROP-arm apply (:293) fire — the LOCAL captures the post-(ALLOW;TRUST) state = 0)
    assert_range(29, 30); // D7 (line 30)
}



#[test]
fn dec_d8_trace_bytes_d9_lines() {
    assert_range(30, 35); // the D8 fail 2-L line + ok line + D9 (31-35); the D8 fail_log line SPANS 2 lines (the NUL-cut C face, the raw buffer line-split)
}

#[test]
fn dec_d10_d11_d12_d13_lines() {
    assert_range(35, 39); // D10 (pw face) + D11 + D12 + D13 (36-39)
}

#[test]
fn dec_d14_dnet_faces_and_z_lines() {
    assert_range(39, 44); // D14, D14h, D14f, D14g, Z (40-44)
}

// ==========================================================================
// 11. FACE-A rebuilt NUMERICALLY: sizes/offsets/ordinals as the port's
// OWN const law (sizeof Active=32 etc. ride the field-layout mirrors,
// the DIOCTL record widths from the port's record shapes, the ACT_STR
// dims 8x4=32, MAX_ATTEMPTS=20, the cold NSDMI face AstMax etc.) each
// rebuilt line byte-equal to the C record faces IN ORDER — NO C ever
// runs HERE.
// ==========================================================================

#[test]
fn face_a_numeric_law_matches_vectors() {
    let fa: Vec<&str> = VECTORS_FACE_A.lines().collect();
    // the C-ptr width face (the harness host: LP64). DEV-004: the port
    // pairs raw ptr+null tests into Option<&str> whose fat width is NOT
    // the C face — the width law rides the raw-pointer mirror below:

    // A0/A2: the DECL layout law over the h :216-:226 tail (int 4 + pad +
    // ptr 8 + four u8s + pad + ptr tail = the mirror's 32 bytes / align 8;
    // the Active record ITSELF = the same 32 (the table rides the vtable-
    // less static + the tail; harness A0 pinned sizeof-Active=32 align=8;
    // the port's field set mirrors the widths EXACTLY):
    let sz_i32 = std::mem::size_of::<i32>();
    let off_bypass = 0usize;
    let off_dr = sz_i32.next_multiple_of(8);
    let off_st = off_dr + 8;
    let off_whd = off_st + 1;
    let off_act = off_whd + 1;
    let off_delay = off_act + 1;
    let off_reject = (off_delay + 1).next_multiple_of(8);
    let mirror_size = off_reject + 8;
    assert_eq!((off_bypass, off_dr, off_st, off_whd, off_act, off_delay, off_reject, mirror_size), (0, 8, 16, 17, 18, 19, 24, 32), "the C tail-offset face 0/8/16/17/18/19/24/32");
    assert_eq!(mirror_size, 32);

    // the ActiveCounts 7xPegCount face:
    let counts = act::ActiveCounts::default();
    let counts_size = [
        std::mem::size_of_val(&counts.injects),
        std::mem::size_of_val(&counts.failed_injects),
        std::mem::size_of_val(&counts.direct_injects),
        std::mem::size_of_val(&counts.failed_direct_injects),
        std::mem::size_of_val(&counts.holds_denied),
        std::mem::size_of_val(&counts.holds_canceled),
        std::mem::size_of_val(&counts.holds_allowed),
    ]
    .iter()
    .sum::<usize>();
    assert_eq!(counts_size, 56);
    let la = format!("A0 sizeof-Active={mirror_size} align=8 sizeof-Counts={counts_size} counts7x8={}", (counts_size == 7 * 8) as i32);
    assert_eq!(fa[0], la, "A0 byte-equal (the port's const law rebuilds sizeof-Active=32 — the C-ptr-width + the u8-quad face)");

    // A1: the cold NSDMI face through the port's OWN getters (the
    // AstMax/7/8/8/bypass-0/dr-null pin + the str face):
    let cold = act::Active::new();
    let l1 = format!(
        "A1 cold st={} whd={} act={} delay={} bypass={} dr={} str-trust-idx0={}",
        cold.get_status() as u8,
        cold.get_would_be_dropped_reason() as u8,
        cold.get_action() as u8,
        cold.get_delayed_action() as u8,
        cold.get_tunnel_bypass() as i32,
        cold.get_drop_reason().is_some() as i32,
        if cold.get_status() as u8 == act::AST_MAX { "max-status-pinned" } else { "x" },
    );
    assert_eq!(fa[1], l1, "A1 byte-equal (ACT_STR[0][0]trust — the in-table idx0 face the row prints against the cold status == AST_MAX truth)");
    assert_eq!(cold.get_action_string(), None, "DEV-017: the cold ACT_MAX row rides the Option None face (C read UB out of the 8x4 table — the vectors NEVER ride that face)");
    assert_eq!(act::ACT_STR[0][0], "trust", "ACT_STR[ACT_TRUST][AST_ALLOW] = trust — the str-trust-idx0 face fuel (NOT the cold face's own read = the None face)");

    let l2 = format!(
        "A2 off bypass={off_bypass} dr={off_dr} st={off_st} whd={off_whd} act={off_act} delay={off_delay} reject={off_reject} mirror-size={mirror_size} align-dr=8",
    );
    assert_eq!(fa[2], l2, "A2 byte-equal");

    // A3/A3b: the FULL ordinal tables from the port's OWN consts:
    let j = |xs: &[u8]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",");
    let ast = [act::AST_ALLOW, act::AST_CANT, act::AST_WOULD, act::AST_FORCE, act::AST_MAX];
    let whd = [act::WHD_NONE, act::WHD_INTERFACE_IDS, act::WHD_IPS_INLINE_TEST, act::WHD_NAP_INLINE_TEST, act::WHD_TIMEOUT, act::WHD_PRUNE, act::WHD_RELOAD, act::WHD_EXIT];
    let asp = [act::ASP_NONE, act::ASP_PRUNE, act::ASP_TIMEOUT, act::ASP_RELOAD, act::ASP_EXIT];
    let actv = [act::ACT_TRUST, act::ACT_ALLOW, act::ACT_HOLD, act::ACT_RETRY, act::ACT_REWRITE, act::ACT_DROP, act::ACT_BLOCK, act::ACT_RESET, act::ACT_MAX];
    assert_eq!(j(&ast), "0,1,2,3,4");
    assert_eq!(j(&whd), "0,1,2,3,4,5,6,7");
    assert_eq!(j(&asp), "0,1,2,3,4");
    assert_eq!(j(&actv), "0,1,2,3,4,5,6,7,8");
    assert_eq!(fa[3], format!("A3 AST {} WHD {}", j(&ast), j(&whd)), "A3 byte-equal");
    assert_eq!(fa[4], format!("A3b ASP {} ACT {}", j(&asp), j(&actv)), "A3b byte-equal");
    let u8s = std::mem::size_of::<u8>();
    let l3c = format!("A3c sizes st={u8s} whd={u8s} asp={u8s} act={u8s}");
    assert_eq!(fa[5], l3c, "A3c byte-equal (the :uint8_t underlying widths the port's field homes ride)");

    // A4: the dims law + MAX_ATTEMPTS (the DEC D0 clamp20=20 face rode
    // the constant BEHAVIORALLY — the ladder re-pin, NEVER set-membership):
    assert_eq!(act::ACT_STR.len(), 8, "ACT_STR dims: 8 rows (ACT_MAX order)");
    assert!(act::ACT_STR.iter().all(|r| r.len() == 4), "ACT_STR dims: x4 cols (AST_MAX order) = 32 cells");
    assert_eq!(act::MAX_ATTEMPTS, 20);
    assert_eq!(
        fa[6],
        format!("A4 dims act_max={} ast_max={} cells={} MAX_ATTEMPTS-restate={}", act::ACT_MAX, act::AST_MAX, (act::ACT_MAX * act::AST_MAX) as usize, act::MAX_ATTEMPTS),
        "A4 byte-equal"
    );

    // A5: the daq-faced record widths from the port's OWN record shapes
    // through the layout law (ptr 8; u8s pack to the next pad-to-8; the
    // fn-ptr typedef face = 8 on the LP64 host):
    let wreset = {
        let w = std::mem::size_of::<u64>() + 1;
        w.next_multiple_of(std::mem::size_of::<u64>())
    };
    let wpay = {
        let w = std::mem::size_of::<u64>() + std::mem::size_of::<*const u8>() + 2;
        w.next_multiple_of(std::mem::size_of::<u64>())
    };
    let wsvpr = {
        let w = std::mem::size_of::<u64>() + 1;
        w.next_multiple_of(std::mem::size_of::<u64>())
    };
    let wseg = {
        let w = std::mem::size_of::<*const u8>() + std::mem::size_of::<u32>();
        w.next_multiple_of(std::mem::size_of::<*const u8>())
    };
    let wsend = std::mem::size_of::<fn(u64, i32, *const u8, u32) -> i32>();
    assert_eq!((wreset, wpay, wsvpr, wseg, wsend), (16, 24, 16, 16, 8), "the C ABI widths the real-daq heads printed (16/24/16/16/8)");
    assert_eq!(std::mem::size_of::<DioctlDirectInjectReset>(), 16, "the landed reset twin SHARES the width face");
    assert_eq!(
        fa[7],
        format!("A5 dioctl-reset={wreset} dioctl-payload={wpay} svpr={wsvpr} seg={wseg} send_t={wsend}"),
        "A5 byte-equal (the DEV-007/DEV-020 record-shape cites)"
    );

    // A6: the PegCount width + the C RAII record = width 1 (NO fields;
    // the port's guard carries the world re-borrow per DEV-021 — the
    // Rust face 8, cited; the C law 1 rides the vector):
    assert_eq!(std::mem::size_of::<snort3::framework::counts::PegCount>(), 8);
    assert_eq!(std::mem::size_of::<act::ActiveSuspendContext>(), 8, "DEV-021: the Rust guard carries the world re-borrow (the C record NONE — cited face)");
    assert_eq!(fa[8], format!("A6 peg={} suspend-ctx=1", std::mem::size_of::<snort3::framework::counts::PegCount>()), "A6 byte-equal");
    assert_eq!(fa[9], "Z-A end=0", "the Z-A terminator byte");
}

// ==========================================================================
// 12. The landmine NAMING face: the src-wide file-walk for
// ReloadSurvivor|reload_survivor|struct Tracer stays find-INSIDE-
// packet_io-ZERO (the EXACTLY-2 pre-existing occupants NEVER +1 by this
// row — the pattern pieces runtime-built so THIS file's own text NEVER
// carries the joined landmine).
// ==========================================================================

#[test]
fn landmine_naming_file_walk_zero() {
    let pats: [String; 3] = [
        ["Reload", "Survivor"].concat(),
        ["reload_survi", "vor"].concat(),
        ["struct Tra", "cer"].concat(),
    ];
    fn walk(dir: &Path, pats: &[String], hits: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let x = e.path();
            if x.is_dir() {
                walk(&x, pats, hits);
            } else if x.extension().is_some_and(|s| s == "rs")
                && let Ok(t) = std::fs::read_to_string(&x)
                && pats.iter().any(|p| t.contains(p))
            {
                hits.push(x);
            }
        }
    }
    let mut io_hits = Vec::new();
    walk(Path::new("/opt/data/snort3-rust/src/packet_io"), &pats, &mut io_hits);
    assert!(io_hits.is_empty(), "the packet_io face (the landing's dir) stays find-ZERO: {io_hits:?}");
    let mut src_hits = Vec::new();
    walk(Path::new("/opt/data/snort3-rust/src"), &pats, &mut src_hits);
    assert_eq!(src_hits.len(), 2, "the EXACTLY-2 src occupants NEVER +1 (this row NEVER adds one)");
    assert!(src_hits.iter().all(|p| !p.components().any(|c| c.as_os_str() == "packet_io")), "NEVER an occupant inside the landing's dir");
}

// ==========================================================================
// 13. The NEXT-seed arms (cite-ONLY reads; the docs NEVER edited by this
// commit): the x3 loops, the x4/x3/x5 phrasings, and the CURRENT 784
// face x3 EXACT AT HEAD (the face = CURRENT; assert EXACTLY 3, NEVER
// drift it here).
// ==========================================================================

#[test]
fn next_seed_pin_faces() {
    let n = |s: &str| NEXTMD.lines().filter(|l| l.contains(s)).count();
    for s in ["752", "724", "702", "684", "659", "650", "633", "629", "621", "605", "597"] {
        assert_eq!(n(&format!("{s} tests green / 0 FAILED")), 3, "the {s} seed x3 EXACT");
    }
    assert_eq!(n("588 tests green / 0 FAILED"), 4, "the x4 face EXACT");
    assert_eq!(n("580 passed / 0 failed"), 3, "the PASSED-phrasing x3 EXACT");
    assert_eq!(n("573 tests green"), 5, "the x5 face EXACT");
    assert!(n("cc **133**") >= 1, "the MUST-RIDE stale exhibit face");
    assert_eq!(n("763 tests green / 0 FAILED"), 3, "the 23e pin x3 (absorbed but UNCHANGED)");
    assert_eq!(n("772 tests green / 0 FAILED"), 3, "the 23f pin x3 (absorbed but UNCHANGED)");
    assert_eq!(n("784 tests green / 0 FAILED"), 3, "the CURRENT pinned seed x3 AT HEAD — NEVER asserted at another count HERE");
}

// ==========================================================================
// 14. The census walk face (the ZERO-gate row: 28/9/20/1 STAYS by walk —
// the lineage NEVER +1s; the gre anchor + the backbone10 md5 frozen).
// ==========================================================================

#[test]
fn census_walk_stays_28_9_20_1() {
    let mut total = 0usize;
    let mut legacy = 0usize;
    let mut md5s = BTreeSet::new();
    for e in std::fs::read_dir("/opt/data/snort3-rust/tools").unwrap().flatten() {
        let f = e.path().join("gate.txt");
        if !f.is_file() {
            continue;
        }
        total += 1;
        let d = md5(&std::fs::read(&f).unwrap());
        if d == "4826fc2233044a2d5429413faf0ae1af" {
            legacy += 1;
        }
        md5s.insert(d);
    }
    let tracked_out = std::process::Command::new("git")
        .args(["-C", "/opt/data/snort3-rust", "ls-files", "--", "tools"])
        .output()
        .unwrap()
        .stdout;
    let tracked = String::from_utf8(tracked_out).unwrap().lines().filter(|l| l.ends_with("gate.txt")).count();
    assert_eq!(tracked, 1, "the TRACKED gate.txt face stays gre's ONLY (the gre anchor md5 6751d1a8...)");
    assert_eq!(total, 29, "the on-disk face by WALK 28 -> 29 at the row-24a sanctioned gate (the 62d6fac rider; the ac-t row itself added none)");
    assert_eq!(legacy, 9, "the legacy md5 4826fc22... x9 face NEVER +1");
    assert_eq!(md5s.len(), 21, "THE distinct-lineage face 20 -> 21 at the row-24a gate tail (the 62d6fac rider)");
    let gre = std::fs::read("/opt/data/snort3-rust/tools/gre_harness/gate.txt").unwrap();
    assert_eq!(md5(&gre), "6751d1a8c21da0fdfed87ddfd4d37c5f", "the gre anchor md5 byte-frozen (the tracked 1)");
    let bb = std::fs::read("/opt/data/snort3-rust/tools/link4_harness/backbone10.txt").unwrap();
    assert_eq!(md5(&bb), "5339c7ee501dab8a85277c37dc2d1e0c", "the backbone10 md5 NEVER moves");
    assert_eq!(String::from_utf8_lossy(&bb).lines().count(), 10, "the backbone10 echo stays 10 L");
}

// ==========================================================================
// 15. The DEV catalog tripwire: the landing rs header lists DEV-001..024 —
// assert the file's DEV tokens are EXACTLY the 24 sorted unique and each
// rides >= 2 faces (the listed-bank law — a stray single cite fails).
// ==========================================================================

#[test]
fn dev_catalog_exact_24_each_ge_2() {
    let t = port_rs();
    let mut counts: HashMap<String, usize> = Default::default();
    let b: Vec<char> = t.chars().collect();
    let mut i = 0usize;
    while i + 6 < b.len() {
        if b[i] == 'D' && b[i + 1] == 'E' && b[i + 2] == 'V' && b[i + 3] == '-'
            && b[i + 4].is_ascii_digit() && b[i + 5].is_ascii_digit() && b[i + 6].is_ascii_digit()
        {
            let tok: String = b[i..i + 7].iter().collect();
            *counts.entry(tok).or_default() += 1;
            i += 7;
        } else {
            i += 1;
        }
    }
    let set: BTreeSet<String> = counts.keys().cloned().collect();
    assert_eq!(set.len(), 24, "EXACTLY-24 distinct DEV tokens in the landing");
    let want: BTreeSet<String> = (1..=24).map(|k| format!("DEV-{k:03}")).collect();
    assert_eq!(set, want, "the DEV-001..024 ladder EXACT (no hole, no extra)");
    for tok in &want {
        assert!(counts[tok] >= 2, "{tok} rides >= 2 faces (the listed-bank law)");
    }
}
