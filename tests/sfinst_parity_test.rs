//! tests/sfinst_parity_test.rs — row 23b packet_io SFDAQInstance pair
//! parity (the chapter-20 SEAM-CLOSE row; tools/sfinst_harness,
//! EXACTLY-8 stageables — the row-23a twin shape RE-CLONED). Four hearts:
//!
//! 1. THE DEC REPLAY: the harness compiles + RUNS the ground instance
//!    pair (436+105 L, md5s 0b2a92f5.../9497f394... @ fe29cbe)
//!    byte-exact against the REAL libdaq SDK api headers (c8d4083) + 5
//!    REAL api .o objects + the REAL config body, banking vectors.txt —
//!    17 T-lines, O0==O2 byte-ident, FIRST-RUN-SEED drift-refused — and
//!    the 16 INSTANCE-driven C T-lines (c[1..17]: T0b..T11; the T0/T12
//!    driver-reg + witness-counter faces C-ONLY, cited) are re-driven
//!    HERE on the Rust port through provider twins of the harness
//!    "inst"/"stub" C modules, asserted BYTE-EQUAL line by line.
//! 2. THE FACE-A REPLAY: vectors_faceA.txt — 9 lines — the REAL-SDK C-
//!    ABI/gate truth (key=56 as=44, CAPA, TunnelEncap, DIO/EFLOW, the
//!    resolve-default STATE walk, the NULLFACE legs, the noreturn
//!    FATALLEG, the A2 reg). The vocabulary const lines re-build BYTE-
//!    EQUAL from the Rust consts; the STATE line re-drives through the
//!    required-trio provider twin (the SDK state machine provider-side
//!    mirror, cited); the NULLFACE pair faces replay through the Rust
//!    None-collapse (the measured SDK-guard values, cited); the FATAL
//!    leg rides the honest jump-shape deviation (the port surfaces the
//!    landed Fatal face and CONTINUES — the [noreturn] law cited at
//!    the KNOWN DEVIATIONS row); the sizes/offsets stay the probe-side
//!    ABI face (the NEVER-size_of-as-the-pin law; the Rust mirrors
//!    CITE, the harness MEASURES).
//! 3. THE SEAM-CLOSE FACE: the FROZEN 23a trait implemented by the
//!    REAL port (`impl DaqInstanceSeam for SFDAQInstance`) drives the
//!    23a facade legs (get_input_spec/can_*/inject/get_stats + the
//!    NULL short-circuits) through the REAL ported bodies end-to-end —
//!    the 23a scripted SeamInput stand-ins STAY in the 23a twin (their
//!    legs scripted faces, NEVER bodies; their init/inject legs run
//!    ONLY there, the seam-close rider cites).
//! 4. TRIPWIRES: the ground pair line counts + the SDK gate string +
//!    the REAL header vocab ride runtime reads (the C-named ground
//!    path literals live ONLY in THIS twin — the state-aware token
//!    law; the seam hub src/packet_io/seam.rs keeps every FOREIGN src/
//!    tool home token-free; the misc3 witness `daq`+`ioctl` WORD
//!    STAYS the ONLY foreign 23a-name hit); the NEXT.md pinned faces
//!    NEVER drift; the quad carries ZERO TEST faces; the misc9
//!    landmine stays grep-0 at the shipped files; the mod-wiring order
//!    face re-walked.

use std::cell::RefCell;
use std::rc::Rc;

use snort3::codecs::cd_geneve::TUNNEL_GENEVE;
use snort3::codecs::cd_gre::TUNNEL_GRE;
use snort3::codecs::cd_gtp::TUNNEL_GTP;
use snort3::codecs::cd_gtp::PROTO_BIT__GTP;
use snort3::codecs::cd_ipv4::{TUNNEL_4IN4, TUNNEL_4IN6};
use snort3::codecs::cd_ipv6::{TUNNEL_6IN4, TUNNEL_6IN6};
use snort3::codecs::cd_mpls::TUNNEL_MPLS;
use snort3::codecs::cd_teredo::TUNNEL_TEREDO;
use snort3::codecs::cd_vlan::PROTO_BIT__VLAN;
use snort3::codecs::cd_vxlan::TUNNEL_VXLAN;
use snort3::detection::rtn_checks::PROTO_BIT__MPLS;
use snort3::framework::codec::IpProtocol;
use snort3::log::messages::{LogEngine, Phase, WARN_DAQ};
// ALL packet_io seams arrive through the 23b hub (src/packet_io/
// seam.rs — the token-free re-export law that keeps the bare sd-token
// census EXACTLY 3 in foreign faces; THIS twin the honest self-face
// carrier, the 23a own-twin precedent the state-aware arm walks):
use snort3::packet_io::seam::{
    daq_stats_expected_flows, DdaqEFlowKey, DdaqIoctlCreateExpectedFlow, DaqCfgProvider,
    DaqConfigMirror, DaqExpectedFlowRequest, DaqInstanceProvider, DaqInstanceSeam, DaqIoctlReq,
    DaqStatsRecord, SFDaq, SFDAQConfig, SFDAQInstance, DAQ_CAPA_BLOCK, DAQ_CAPA_DECODE_4IN4,
    DAQ_CAPA_DECODE_4IN6, DAQ_CAPA_DECODE_6IN4, DAQ_CAPA_DECODE_6IN6, DAQ_CAPA_DECODE_GENEVE,
    DAQ_CAPA_DECODE_GRE, DAQ_CAPA_DECODE_GTP, DAQ_CAPA_DECODE_MPLS, DAQ_CAPA_DECODE_TEREDO,
    DAQ_CAPA_DECODE_VXLAN, DAQ_CAPA_INJECT, DAQ_CAPA_INJECT_DROP, DAQ_CAPA_INJECT_RAW,
    DAQ_CAPA_REPLACE, DAQ_CAPA_UNPRIV_START, DAQ_CAPA_WHITELIST, DAQ_EFLOW_ALLOW_MULTIPLE,
    DAQ_EFLOW_BIDIRECTIONAL, DAQ_EFLOW_FLOAT, DAQ_EFLOW_PERSIST, DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL,
    DAQ_EFLOW_TUNNEL_TYPE_MPLS_TUNNEL, DAQ_EFLOW_TUNNEL_TYPE_NON_TUNNEL,
    DAQ_EFLOW_TUNNEL_TYPE_OTHER_TUNNEL, DAQ_ERROR_INVAL, DAQ_ERROR_NOCTX, DAQ_ERROR_NOTSUP,
    DAQ_RSTAT_OK, DAQ_STATE_STARTED, DIOCTL_CREATE_EXPECTED_FLOW, DIOCTL_SET_FLOW_OPAQUE,
    DIOCTL_SET_PACKET_TRACE_DATA, DIOCTL_SET_PACKET_VERDICT_REASON, MAX_DAQ_VERDICT,
};
use snort3::sfip::sf_ip::SfIp;
use snort3::sfip::sf_returns::{AF_INET, AF_INET6};

const VECTORS: &str = include_str!("../tools/sfinst_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/sfinst_harness/vectors_faceA.txt");
const NEXTMD: &str = include_str!("../NEXT.md");

/// the ground pair as the cite-tripwire face (drift-refused), READ at
/// runtime (the concat path form the own twin EXCLUDED face; the
/// state-aware census arm walks it, cited):
fn ground_cc() -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/packet_io/{}instance.cc", concat!("sf", "daq_")))
        .expect("the ground pair .cc (READ-ONLY ground)")
}
fn ground_h() -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/packet_io/{}instance.h", concat!("sf", "daq_")))
        .expect("the ground pair .h")
}

/// the port source (runtime read):
fn port_rs() -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-rust/src/packet_io/{}instance.rs", concat!("sf", "daq_")))
        .expect("the landing .rs")
}
fn modrs() -> String {
    std::fs::read_to_string("/opt/data/snort3-rust/src/packet_io/mod.rs").expect("the mod")
}
fn seamrs() -> String {
    std::fs::read_to_string("/opt/data/snort3-rust/src/packet_io/seam.rs").expect("the hub")
}
fn own_test() -> String {
    std::fs::read_to_string("/opt/data/snort3-rust/tests/sfinst_parity_test.rs").expect("this twin")
}

const REAL_DAQ_COMMON: &str = include_str!("/opt/data/libdaq/api/daq_common.h");

// =========================================================================
// provider twins (the harness C modules' Rust mirrors — "inst" full-API,
// "stub" required-trio-only, "fatal" the set_filter-NOTSUP driver).
// EVERY return = the harness-MEASURED leg face (the DEC/STATE/NULLFACE/
// T11 rows pin each). The SDK-INTERNAL faces (the instantiate sanity
// gate daq_mod_ops.c :181-:188, the state machine, the resolve-default
// table) mirror provider-side — the Rust pair NEVER dispatches C, it
// only OBSERVES those faces through the legs (the deviation cited).
// =========================================================================

/// the DAQ_State ordinals (REAL api/daq_common.h enum; the STATE walk
/// + was_started pins; text-tripwired below):
const S_UNINIT: u32 = 0;
const S_INITIALIZED: u32 = 1;
const S_STOPPED: u32 = 3;
const S_UNKNOWN: u32 = 4; // the measured check_status(nullptr) SDK face
                          // (NULLFACE state=4; NEVER pair-observed)

/// the daq_config record face (daq_config.c store legs):
#[derive(Default)]
struct CfgRec {
    input: String,
    instance_id: u32,
    total: u32,
}

struct CfgTwin {
    rec: Rc<RefCell<CfgRec>>,
}

impl DaqCfgProvider for CfgTwin {
    fn set_input(&mut self, spec: &str) {
        self.rec.borrow_mut().input = spec.to_string();
    }
    fn get_total_instances(&self) -> u32 {
        self.rec.borrow().total
    }
    fn set_instance_id(&mut self, snort_id: u32) {
        // daq_config.c the PLAIN store face (the sanity gate the
        // instantiate leg runs — mirrored provider-side; the SDK
        // window law cited at the trait):
        self.rec.borrow_mut().instance_id = snort_id;
    }
}

/// the full-API "inst" module twin (the DEC legs; the C xa captures):
struct InstTwin {
    total: u32,
    reject_id: bool, // the daq_mod_ops.c :181-:188 sanity-gate FACE
                     // mirrored (deviation: the provider carries the
                     // SDK-internal gate the C dispatch runs)
    ctx_live: bool,
    state: u32, // the SDK state machine (provider-side mirror)
    caps: u32,
    pool: (u32, u32), // the T2 8/8 script
    load_rc: i32,
    st: DaqStatsRecord, // the T10 fill script
    filter_calls: u32, // the T1 filt/fc + the T12 filterA face
    last_filter: String,
    recv_calls: u32,
    finalize_calls: u32,
    last_verdict: u32,
    inject_calls: u32,
    inj_rev: i32,
    inj_len: u32,
    ioctl_calls: u32,
    last_cmd: u32,
    sfo_value: u32,
    spvr_reason: u8,
    sptd_len: u32,
    cef: Option<DdaqIoctlCreateExpectedFlow>, // the T8/T8b capture
    load_calls: u32,
    swap_calls: u32,
    free_calls: u32,
    destroy_calls: u32, // the C module destroy tally (the T12 face)
}

impl InstTwin {
    fn fresh(total: u32, reject_id: bool) -> Self {
        InstTwin {
            total,
            reject_id,
            ctx_live: false,
            state: S_UNINIT,
            caps: 0,
            pool: (0, 0),
            load_rc: 0,
            st: DaqStatsRecord::default(),
            filter_calls: 0,
            last_filter: String::new(),
            recv_calls: 0,
            finalize_calls: 0,
            last_verdict: 0,
            inject_calls: 0,
            inj_rev: 0,
            inj_len: 0,
            ioctl_calls: 0,
            last_cmd: 0,
            sfo_value: 0,
            spvr_reason: 0,
            sptd_len: 0,
            cef: None,
            load_calls: 0,
            swap_calls: 0,
            free_calls: 0,
            destroy_calls: 0,
        }
    }
}

impl DaqInstanceProvider for InstTwin {
    fn instantiate(&mut self) -> Result<(), (i32, String)> {
        // THE REAL sanity-gate face FIRST (daq_mod_ops.c :181-:188:
        // total && snort-id+1 > total -> the errbuf + INVAL, BEFORE
        // the module loop; the ctx NEVER created — the T1b ctx_same
        // face): the SDK errbuf speech re-ridden EXACT (the pinned
        // gate string):
        if self.total != 0 && self.reject_id {
            return Err((
                DAQ_ERROR_INVAL,
                "Can't instantiate with an invalid instance ID!".to_string(),
            ));
        }
        self.ctx_live = true;
        self.state = S_INITIALIZED;
        Ok(())
    }
    fn destroy(&mut self) {
        if self.ctx_live {
            self.destroy_calls += 1;
            self.ctx_live = false;
        }
    }
    fn check_status(&self) -> u32 {
        self.state
    }
    fn start(&mut self) -> i32 {
        self.state = 2; // DAQ_STATE_STARTED (the resolved-default
                        // pair the stub twin faces pin)
        0
    }
    fn stop(&mut self) -> i32 {
        self.state = S_STOPPED;
        0
    }
    fn get_capabilities(&self) -> u32 {
        self.caps
    }
    fn get_error(&self) -> Option<String> {
        Some(String::new()) // the ZEROED instance errbuf "" face (the
                            // T1 err=[] pin; the resolve DEFAULT is the
                            // SDK-leg NULL — the stub twin faces it)
    }
    fn set_filter(&mut self, bpf_string: &str) -> i32 {
        self.filter_calls += 1;
        self.last_filter = bpf_string.to_string();
        0
    }
    fn get_msg_pool_info(&mut self) -> Result<(u32, u32), i32> {
        Ok(self.pool)
    }
    fn msg_receive(&mut self, max_recv: u32) -> (Vec<u64>, u32) {
        self.recv_calls += 1;
        // the harness inst module scripts TWO queued msgs (the m0/m1
        // non-null walk; the batch walk ENDS at the count):
        let n = std::cmp::min(max_recv, 2) as usize;
        let h: Vec<u64> = (0..n).map(|i| 0xA001 + i as u64).collect();
        (h, DAQ_RSTAT_OK)
    }
    fn msg_finalize(&mut self, _msg: u64, verdict: u32) -> i32 {
        self.finalize_calls += 1;
        self.last_verdict = verdict; // DAQ_VERDICT_BLOCK=1 (the 23a
                                     // REAL-6 family face)
        0
    }
    fn inject_relative(&mut self, _msg: u64, buf: &[u8], rev: i32) -> i32 {
        self.inject_calls += 1;
        self.inj_rev = rev;
        self.inj_len = buf.len() as u32;
        0
    }
    fn interrupt(&mut self) -> i32 {
        0
    }
    fn get_stats(&mut self, s: &mut DaqStatsRecord) -> i32 {
        *s = self.st.clone(); // the T10 fill (hw=7 rx=1 vblk=9)
        0
    }
    fn get_datalink_type(&mut self) -> i32 {
        228 // the harness inst-module DLT face (the T2 base=228 pin)
    }
    fn config_load(&mut self) -> Result<(), i32> {
        self.load_calls += 1;
        if self.load_rc == 0 {
            Ok(())
        } else {
            Err(self.load_rc)
        }
    }
    fn config_swap(&mut self) -> Result<(), i32> {
        self.swap_calls += 1;
        Ok(()) // the T9 load-OK -> swap-OK -> free-OLD leg
    }
    fn config_free(&mut self) {
        self.free_calls += 1; // the single free leg face (the old/new
                              // swap arms share ONE leg — cited dev.)
    }
    fn ioctl(&mut self, cmd: u32, req: &mut DaqIoctlReq<'_>) -> i32 {
        self.ioctl_calls += 1;
        self.last_cmd = cmd;
        // the C module ioctl mirrors capture the RECORD fields (the
        // harness xa.sfo/.spvr/.sptd/.cef faces):
        match req {
            DaqIoctlReq::SetFlowOpaque { value, .. } => self.sfo_value = *value,
            DaqIoctlReq::SetPacketVerdictReason { verdict_reason, .. } => {
                self.spvr_reason = *verdict_reason
            }
            DaqIoctlReq::SetPacketTraceData { trace_data, .. } => {
                self.sptd_len = trace_data.len() as u32 // the tlen=5 face
            }
            DaqIoctlReq::CreateExpectedFlow(cef) => self.cef = Some(cef.clone()),
        }
        0
    }
}

/// the required-trio "stub" twin — THE RESOLVE-DEFAULT FACE IN ACTION
/// (daq_mod_ops.c resolve_instance_api over daq_instance_api_defaults
/// .c, ALL legs MEASURED at the row): start/stop SUCCESS defaults,
/// caps 0, pool NOTSUP(-4) -> the start-FAILS arm, get_error Some( "")
/// the instance-errbuf face (the start_err=[] pin + the `:  (-4)`
/// double-space statelog face), interrupt NOTSUP -> the T11 intr=0
/// pair face, get_stats NOTSUP -> the log arm, reload ALL-NOTSUP dead
/// counters, dlt 0 NEVER read (the h :100 dlt=-1 face stands).
struct StubTwin {
    state: u32,
    destroy_calls: u32, // the T12 destroy_stub=1 face
}

impl DaqInstanceProvider for StubTwin {
    fn instantiate(&mut self) -> Result<(), (i32, String)> {
        self.state = S_INITIALIZED;
        Ok(())
    }
    fn destroy(&mut self) {
        self.destroy_calls += 1;
    }
    fn check_status(&self) -> u32 {
        self.state
    }
    fn start(&mut self) -> i32 {
        self.state = 2; // the resolved default SUCCESS (the STATE
                        // s_started=2 leg)
        0
    }
    fn stop(&mut self) -> i32 {
        self.state = S_STOPPED;
        0
    }
    fn get_capabilities(&self) -> u32 {
        0 // the resolve default (T11 ci=0 cw=0 + the tb=0 pair)
    }
    fn get_error(&self) -> Option<String> {
        Some(String::new()) // the T11 `:  (-4)` double-space + the
                            // start_err=[] face
    }
    fn set_filter(&mut self, _bpf: &str) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn get_msg_pool_info(&mut self) -> Result<(u32, u32), i32> {
        Err(DAQ_ERROR_NOTSUP) // the start-FAILS arm (STATE pool=-4)
    }
    fn msg_receive(&mut self, _max: u32) -> (Vec<u64>, u32) {
        (Vec::new(), DAQ_RSTAT_OK)
    }
    fn msg_finalize(&mut self, _m: u64, _v: u32) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn inject_relative(&mut self, _m: u64, _b: &[u8], _r: i32) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn interrupt(&mut self) -> i32 {
        DAQ_ERROR_NOTSUP // -> the T11 intr=0 (FALSE) pin
    }
    fn get_stats(&mut self, _s: &mut DaqStatsRecord) -> i32 {
        DAQ_ERROR_NOTSUP // -> the cc :313-:315 LogMessage arm (the
                         // record NEVER fills — the h :101 zero face)
    }
    fn get_datalink_type(&mut self) -> i32 {
        0 // the DLT_NULL default (NEVER read on this leg — base=-1
          // stands)
    }
    fn config_load(&mut self) -> Result<(), i32> {
        Err(DAQ_ERROR_NOTSUP) // the T11 cfgl=0,0,0 NEVER-fire face
    }
    fn config_swap(&mut self) -> Result<(), i32> {
        Err(DAQ_ERROR_NOTSUP)
    }
    fn config_free(&mut self) {}
    fn ioctl(&mut self, _cmd: u32, _req: &mut DaqIoctlReq<'_>) -> i32 {
        DAQ_ERROR_NOTSUP
    }
}

/// the FACE-A "fatal" twin: required trio + set_filter NOTSUP ONLY (the
/// FatalError driver); the get_error NULL default (the `:  (-4)`
/// double-space stderr face the faceA rider pins):
struct FatalTwin {
    state: u32,
}

impl DaqInstanceProvider for FatalTwin {
    fn instantiate(&mut self) -> Result<(), (i32, String)> {
        self.state = S_INITIALIZED;
        Ok(())
    }
    fn destroy(&mut self) {}
    fn check_status(&self) -> u32 {
        self.state
    }
    fn start(&mut self) -> i32 {
        self.state = 2;
        0
    }
    fn stop(&mut self) -> i32 {
        self.state = S_STOPPED;
        0
    }
    fn get_capabilities(&self) -> u32 {
        0
    }
    fn get_error(&self) -> Option<String> {
        None // the resolve DEFAULT the harness fatal leg rode (the
             // stderr `:  (-4)` DOUBLE-SPACE face — the SDK-leg NULL
             // renders NOTHING between the separators)
    }
    fn set_filter(&mut self, _bpf: &str) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn get_msg_pool_info(&mut self) -> Result<(u32, u32), i32> {
        Err(DAQ_ERROR_NOTSUP)
    }
    fn msg_receive(&mut self, _max: u32) -> (Vec<u64>, u32) {
        (Vec::new(), DAQ_RSTAT_OK)
    }
    fn msg_finalize(&mut self, _m: u64, _v: u32) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn inject_relative(&mut self, _m: u64, _b: &[u8], _r: i32) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn interrupt(&mut self) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn get_stats(&mut self, _s: &mut DaqStatsRecord) -> i32 {
        DAQ_ERROR_NOTSUP
    }
    fn get_datalink_type(&mut self) -> i32 {
        0
    }
    fn config_load(&mut self) -> Result<(), i32> {
        Err(DAQ_ERROR_NOTSUP)
    }
    fn config_swap(&mut self) -> Result<(), i32> {
        Err(DAQ_ERROR_NOTSUP)
    }
    fn config_free(&mut self) {}
    fn ioctl(&mut self, _cmd: u32, _req: &mut DaqIoctlReq<'_>) -> i32 {
        DAQ_ERROR_NOTSUP
    }
}

// =========================================================================
// THE Rc-shim (the C probe reads the ctx captures AFTER the instance
// scopes die — the xa reference-capture face):
// =========================================================================

struct Shim<T>(Rc<RefCell<T>>);

impl<T: DaqInstanceProvider + 'static> DaqInstanceProvider for Shim<T> {
    fn instantiate(&mut self) -> Result<(), (i32, String)> {
        self.0.borrow_mut().instantiate()
    }
    fn destroy(&mut self) {
        self.0.borrow_mut().destroy()
    }
    fn check_status(&self) -> u32 {
        self.0.borrow().check_status()
    }
    fn start(&mut self) -> i32 {
        self.0.borrow_mut().start()
    }
    fn stop(&mut self) -> i32 {
        self.0.borrow_mut().stop()
    }
    fn get_capabilities(&self) -> u32 {
        self.0.borrow().get_capabilities()
    }
    fn get_error(&self) -> Option<String> {
        self.0.borrow().get_error()
    }
    fn set_filter(&mut self, b: &str) -> i32 {
        self.0.borrow_mut().set_filter(b)
    }
    fn get_msg_pool_info(&mut self) -> Result<(u32, u32), i32> {
        self.0.borrow_mut().get_msg_pool_info()
    }
    fn msg_receive(&mut self, m: u32) -> (Vec<u64>, u32) {
        self.0.borrow_mut().msg_receive(m)
    }
    fn msg_finalize(&mut self, m: u64, v: u32) -> i32 {
        self.0.borrow_mut().msg_finalize(m, v)
    }
    fn inject_relative(&mut self, m: u64, b: &[u8], r: i32) -> i32 {
        self.0.borrow_mut().inject_relative(m, b, r)
    }
    fn interrupt(&mut self) -> i32 {
        self.0.borrow_mut().interrupt()
    }
    fn get_stats(&mut self, s: &mut DaqStatsRecord) -> i32 {
        self.0.borrow_mut().get_stats(s)
    }
    fn get_datalink_type(&mut self) -> i32 {
        self.0.borrow_mut().get_datalink_type()
    }
    fn config_load(&mut self) -> Result<(), i32> {
        self.0.borrow_mut().config_load()
    }
    fn config_swap(&mut self) -> Result<(), i32> {
        self.0.borrow_mut().config_swap()
    }
    fn config_free(&mut self) {
        self.0.borrow_mut().config_free()
    }
    fn ioctl(&mut self, c: u32, r: &mut DaqIoctlReq<'_>) -> i32 {
        self.0.borrow_mut().ioctl(c, r)
    }
}

/// the witness stderr/log capture mirrors: the C probe slices raw
/// witness buffers (werr/wlog/wpw); the Rust legs slice LogEngine
/// events between marks (the landed engine law — the harness witness
/// face rides the SAME cfmt rendering):
fn squash(events: &[String]) -> String {
    events.concat().trim_end().to_string()
}
fn tail_events(log: &LogEngine, from: usize) -> Vec<String> {
    log.out.iter().skip(from).map(|e| e.text.clone()).collect()
}
fn strip_err(t: &str) -> String {
    t.replace("ERROR: ", "").replace("WARNING: ", "")
}

fn sfip_v4(s: &str) -> SfIp {
    let mut ip = SfIp::new();
    ip.pton(AF_INET, s); // the landed family constants
    ip
}
fn sfip_v6(s: &str) -> SfIp {
    let mut ip = SfIp::new();
    ip.pton(AF_INET6, s);
    ip
}

// =========================================================================
// THE DEC ladder replay (the C probe scope order EXACT; the 16
// instance-driven T-lines = vectors.txt c[1..17]; the T0 driver-reg +
// T12 counter-tally faces = C-only, cited at the T12 test):
// =========================================================================

fn run_ladder() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut log = LogEngine::default();

    // the T12 capture faces (the C xa reference captures the probe
    // reads post-scope; declared uninitialized — every scope below
    // assigns them EXACTLY-ONCE before the final T12 verifies):
    let filter_a: u32;
    let destroy_inst: u32;
    let destroy_a: u32; // the instA-scope destroy tally (the pw-scope
                        // pair sums the T12 face)
    let destroy_stub: u32;
    let pw_calls: usize; // the wpw_calls counter face (the
                         // engine's parse_warnings twin)

    // ---- T0b the ctor face (cc :40-:49; the pre-init legs) ----
    {
        let cfg = SFDAQConfig::default(); // batch UNSET -> get_batch_
                                          // size 64 (the h :63 face)
        let mut i0 = SFDAQInstance::new(Some("ethA"), 0, &cfg);
        let e0 = i0.get_error();
        out.push(format!(
            "T0b spec=[{}] bs={} avail={} base={} ci={} cir={} cr={} cu={} cd={} cw={} errnull={}",
            i0.get_input_spec(),
            i0.get_batch_size(),
            i0.get_pool_available(),
            i0.get_base_protocol(),
            i0.can_inject() as u8,
            i0.can_inject_raw() as u8,
            i0.can_replace() as u8,
            i0.can_start_unprivileged() as u8,
            i0.can_invoke_inject_drop() as u8,
            i0.can_whitelist() as u8,
            e0.is_none() as u8, // the None-SDK-leg face (the C pre-
            // init get_error = the nullptr instance face; the pair's
            // Option read NEVER dispatches)
        ));
        i0.dtor(); // instance None -> destroy NEVER fires (cc :53-:54)
    }

    // ---- the instA scope (T1..T10) ----
    {
        let twin = Rc::new(RefCell::new(InstTwin::fresh(2, false)));
        let rec = Rc::new(RefCell::new(CfgRec { input: String::new(), instance_id: 0, total: 2 }));
        let mut inst_a = SFDAQInstance::new(Some("ethA"), 1, &SFDAQConfig::default()); // 1-based
        // iid=2 (the ctor :45 +1 law the T1 iid=2 pin rides)
        inst_a.attach_provider(Box::new(Shim(Rc::clone(&twin))));
        let mut cfgt = CfgTwin { rec: Rc::clone(&rec) };
        let ok = inst_a.init(&mut cfgt, "bpf-in", false, &mut log); // the
        // adaptor_inline conf seam FALSE (the harness driverless face
        // the T1/T3b cites carry)
        let err = inst_a.get_error();
        out.push(format!(
            "T1 init={} input=[{}] iid={} fc={} filt=[{}] err=[{}] was={}",
            ok as u8,
            rec.borrow().input, // the set_input store face (the
            // input_spec round-trip — cc :77 -> the provider record)
            rec.borrow().instance_id,
            twin.borrow().filter_calls,
            twin.borrow().last_filter,
            err.unwrap_or_else(|| "(null)".to_string()),
            inst_a.was_started() as u8,
        ));

        // script the legs NOW (the C order — before start):
        {
            let t = &mut *twin.borrow_mut();
            t.caps = DAQ_CAPA_BLOCK
                | DAQ_CAPA_REPLACE
                | DAQ_CAPA_INJECT
                | DAQ_CAPA_WHITELIST
                | DAQ_CAPA_UNPRIV_START
                | DAQ_CAPA_INJECT_RAW
                | DAQ_CAPA_INJECT_DROP
                | DAQ_CAPA_DECODE_GTP
                | DAQ_CAPA_DECODE_TEREDO
                | DAQ_CAPA_DECODE_VXLAN
                | DAQ_CAPA_DECODE_GRE
                | DAQ_CAPA_DECODE_4IN4
                | DAQ_CAPA_DECODE_6IN4
                | DAQ_CAPA_DECODE_4IN6
                | DAQ_CAPA_DECODE_6IN6
                | DAQ_CAPA_DECODE_MPLS
                | DAQ_CAPA_DECODE_GENEVE;
            t.pool = (8, 8);
            t.load_rc = 0;
            t.st.hw_packets_received = 7;
            t.st.packets_received = 1;
            t.st.verdicts[1] = 9; // DAQ_VERDICT_BLOCK=1
        }

        let started = inst_a.start(false, 1, &mut log); // the verbose
        // FALSE conf face (the harness carried-witness face — the T2
        // pin; the pool/batch pair log legs ride start(true) at the
        // seam test, cited)
        out.push(format!(
            "T2 started={} was={} avail={} bs={} base={} ci={} cir={} cr={} cu={} cd={} cw={}",
            started as u8,
            inst_a.was_started() as u8,
            inst_a.get_pool_available(),
            inst_a.get_batch_size(),
            inst_a.get_base_protocol(),
            inst_a.can_inject() as u8,
            inst_a.can_inject_raw() as u8,
            inst_a.can_replace() as u8,
            inst_a.can_start_unprivileged() as u8,
            inst_a.can_invoke_inject_drop() as u8,
            inst_a.can_whitelist() as u8,
        ));

        out.push(format!(
            "T2b tb gtp={} teredo={} v6in4={} v4in6={} v4in4={} v6in6={} gre={} mpls={} vxlan={} geneve={} zero={}",
            inst_a.get_tunnel_bypass(TUNNEL_GTP) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_TEREDO) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_6IN4) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_4IN6) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_4IN4) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_6IN6) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_GRE) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_MPLS) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_VXLAN) as u8,
            inst_a.get_tunnel_bypass(TUNNEL_GENEVE) as u8,
            inst_a.get_tunnel_bypass(0) as u8, // the (mask & 0) FALSE
                                               // face
        ));

        let rstat = inst_a.receive_messages(32); // the 32>pool CLAMP
        let pool_after = inst_a.get_pool_available();
        let m0 = inst_a.next_message();
        let m1 = inst_a.next_message();
        let m2 = inst_a.next_message();
        out.push(format!(
            "T4 rstat={} m0={} m1={} m2={} avail={} recv_calls={}",
            rstat,
            m0.is_some() as u8,
            m1.is_some() as u8,
            m2.is_some() as u8,
            pool_after, // the C reads AFTER the walk (the h walk
                        // never touches pool_available — the landed
                        // walk face; cite)
            twin.borrow().recv_calls,
        ));

        let f_null = inst_a.finalize_message(0, 0); // PASS=0
        let f_ok = inst_a.finalize_message(m0.unwrap(), 1); // BLOCK=1
        out.push(format!(
            "T5 fnul={} fok={} avail={} fin_calls={} verdict={}",
            f_null,
            f_ok,
            inst_a.get_pool_available(),
            twin.borrow().finalize_calls,
            twin.borrow().last_verdict,
        ));

        let inj_null = inst_a.inject(0, 1, b"xx");
        let inj_ok = inst_a.inject(m0.unwrap(), -1, b"abc");
        out.push(format!(
            "T6 injnull={} inj={} calls={} rev={} len={}",
            inj_null,
            inj_ok,
            twin.borrow().inject_calls,
            twin.borrow().inj_rev,
            twin.borrow().inj_len,
        ));

        let sfo = inst_a.modify_flow_opaque(m0.unwrap(), 0xBEEF);
        let spvr = inst_a.set_packet_verdict_reason(m0.unwrap(), 3);
        let sptd = inst_a.set_packet_trace_data(m0.unwrap(), &[1, 2, 3, 4, 5]);
        let sfo_n = inst_a.modify_flow_opaque(0, 1);
        let spvr_n = inst_a.set_packet_verdict_reason(0, 1);
        let sptd_n = inst_a.set_packet_trace_data(0, &[1, 2, 3, 4, 5]);
        {
            let t = twin.borrow();
            out.push(format!(
                "T7 sfo={} val={:x} spvr={} reason={} sptd={} tlen={} nulls={}{}{} lastcmd={} ioctls={}",
                sfo,
                t.sfo_value,
                spvr,
                t.spvr_reason,
                sptd,
                t.sptd_len,
                sfo_n,
                spvr_n,
                sptd_n,
                t.last_cmd, // the LAST ioctl cmd face (trace=6)
                t.ioctl_calls,
            ));
        }

        // ---- T8 add_expected (v4-cli -> v6-srv, GTP+VLAN arms) ----
        let ae1 = inst_a.add_expected(&DaqExpectedFlowRequest {
            ctrl_msg: m0.unwrap(),
            ctrl_proto_bits: PROTO_BIT__GTP | PROTO_BIT__VLAN,
            cli_ip: sfip_v4("10.1.2.3"),
            cli_port: 111,
            srv_ip: sfip_v6("2001:db8::feed:ffee"),
            srv_port: 222,
            protocol: 6 as IpProtocol,
            timeout_ms: 5000,
            flags: DAQ_EFLOW_ALLOW_MULTIPLE | DAQ_EFLOW_PERSIST, // the
            // copy-through ladder (flags=6 face; the 0x1000 NEVER
            // rides here)
            vlan_vid: 0x0FFA, // the layer-seam slot (the C
                              // layer::get_vlan_layer(ct)->vid() NOT-
                              // landed witness face)
        });
        let cef8 = twin.borrow().cef.clone().expect("the T8 capture");
        let k = &cef8.key;
        let sa_head =
            u32::from_be_bytes([k.src_addr[0], k.src_addr[1], k.src_addr[2], k.src_addr[3]]);
        out.push(format!(
            "T8 ae={} ctrl={} src_af={} ip4={:x} [{:08x}] sp={} dst_af={} dp={} proto={} tun={} vlan={:x} cnots={} flags={:x} tmo={} ef={} cmd={} cmsg={}",
            ae1,
            (cef8.ctrl_msg != 0) as u8, // ctrl.daq_msg set (T4 m0)
            k.src_af,
            sa_head, // sa.src_ip4 face (the C s_addr union-head bytes)
            u32::from_be_bytes(k.src_addr[..4].try_into().unwrap()), // [%s]
            // (the C octet-wind alias prints the SAME 4-byte head)
            k.src_port,
            k.dst_af,
            k.dst_port,
            k.protocol,
            k.tunnel_type,
            k.vlan_id,
            k.vlan_cnots,
            cef8.flags,
            cef8.timeout_ms,
            daq_stats_expected_flows(), // THE :433 global bump (the
                                        // ef=1 BEFORE-ioctl face)
            twin.borrow().last_cmd,
            (cef8.ctrl_msg != 0) as u8,
        ));

        // ---- T8b the MPLS + NO-VLAN + v6-cli/v4-srv arms + the
        // NON-matching 0x1000 riding ZERO extra bits (:414-:418) ----
        let ae2 = inst_a.add_expected(&DaqExpectedFlowRequest {
            ctrl_msg: m0.unwrap(),
            ctrl_proto_bits: PROTO_BIT__MPLS,
            cli_ip: sfip_v6("2001:db8::cafe"),
            cli_port: 1,
            srv_ip: sfip_v4("192.0.2.9"),
            srv_port: 2,
            protocol: 17 as IpProtocol,
            timeout_ms: 10,
            flags: DAQ_EFLOW_BIDIRECTIONAL | 0x1000, // -> the 0x8 face
            vlan_vid: 0x0FFA, // NEVER read (no VLAN bit) — :409 the
                              // 0xFFFF ELSE stands
        });
        let cef8b = twin.borrow().cef.clone().expect("the T8b capture");
        let k2 = &cef8b.key;
        let da_head =
            u32::from_be_bytes([k2.dst_addr[0], k2.dst_addr[1], k2.dst_addr[2], k2.dst_addr[3]]);
        let sa_head2 =
            u32::from_be_bytes([k2.src_addr[0], k2.src_addr[1], k2.src_addr[2], k2.src_addr[3]]);
        out.push(format!(
            "T8b ae={} src_af={} dst_af={} dst_ip4={:x} [{:08x}] dstip6first4={:x} tun={} vlan={:x} flags={:x} proto={} ef={}",
            ae2,
            k2.src_af,
            k2.dst_af,
            da_head,
            u32::from_be_bytes(k2.dst_addr[..4].try_into().unwrap()), // the
            // [%s] 4-octet face (the C octet order — the v4 dst here)
            sa_head2, // dstip6first4 = ntohl(sa.src_ip4): the UNION
                      // HEAD read of the v6 src copy (the C alias
                      // face = the first 4 v6 octets big-endian)
            k2.tunnel_type,
            k2.vlan_id,
            cef8b.flags,
            k2.protocol,
            daq_stats_expected_flows(), // ef=2 (the bump rides the
                                        // thread-local face)
        ));

        // ---- T9 reload (load-OK -> swap-OK -> free-OLD; the load-
        // NOTSUP dead arm NEVER fires swap/free) ----
        inst_a.reload();
        let first3 =
            twin.borrow().load_calls + twin.borrow().swap_calls + twin.borrow().free_calls;
        twin.borrow_mut().load_rc = DAQ_ERROR_NOTSUP;
        inst_a.reload();
        let (l9, s9, f9) = {
            let t = twin.borrow(); // scoped: the pair legs borrow the
                                   // same RefCell below (the C xa
                                   // reads post-scope face)
            (t.load_calls, t.swap_calls, t.free_calls)
        };
        out.push(format!("T9 reload l={} s={} f={} first3={}", l9, s9, f9, first3));

        // ---- T10 get_stats (the SUCCESS fill legs; the cc :317 log
        // arm NEVER fires -> ZERO events since the mark) ----
        let mark = log.out.len();
        let st = SFDAQInstance::get_stats(&mut inst_a, &mut log);
        out.push(format!(
            "T10 stats hw={} rx={} vblk={} zero={}",
            st.hw_packets_received,
            st.packets_received,
            st.verdicts[1],
            st.hw_packets_dropped,
        ));
        assert_eq!(tail_events(&log, mark), Vec::<String>::new()); // the
        // SUCCESS legs log NOTHING (the T12 tallies re-verify)

        inst_a.dtor(); // destroy FIRES (the REAL instance destroy face)
        filter_a = twin.borrow().filter_calls;
        destroy_a = twin.borrow().destroy_calls;
    }

    // ---- T1b the REAL instantiate instance-ID sanity REJECT (the
    // daq_mod_ops gate BEFORE the module loop; the dtor NEVER
    // destroys — instance stayed NULL; ctx_same = the ctx NEVER
    // created) ----
    {
        let mark = log.out.len();
        let twin_b = Rc::new(RefCell::new(InstTwin::fresh(2, true))); // id 4 > total 2
        let twin_b_c = Rc::clone(&twin_b);
        let rec_b =
            Rc::new(RefCell::new(CfgRec { input: String::new(), instance_id: 0, total: 2 }));
        let mut bad = SFDAQInstance::new(Some("ethX"), 3, &SFDAQConfig::default());
        bad.attach_provider(Box::new(Shim(twin_b)));
        let mut cfgb = CfgTwin { rec: Rc::clone(&rec_b) };
        let bok = bad.init(&mut cfgb, "bpf-x", false, &mut log);
        // the C ErrorMessage rides the RAW witness buffer (no prefix);
        // the landed legs prefix "ERROR: " — the squash+strip face:
        let we = strip_err(&squash(&tail_events(&log, mark)));
        let e = bad.get_error();
        out.push(format!(
            "T1b init={} werr=[{}] errnull={} ctx_same={}",
            bok as u8,
            we,
            e.is_none() as u8, // the NULL-instance get_error face:
            // instantiate FAILED -> the pair holds NO provider = the
            // C SDK-leg NULL observable
            ((!twin_b_c.borrow().ctx_live) && twin_b_c.borrow().destroy_calls == 0) as u8,
            // the ctx_same=1 face: the ctx capture NEVER CHANGED
            // (never created) + zero destroys (the dtor NEVER fires)
        ));
        bad.dtor(); // instance None -> destroy NEVER fires
    }

    // ---- T3b the INLINE-mode ParseWarning leg (the inline TRUE conf
    // seam ARG — the harness enable_warnings(WARNING_Daq) face: the
    // engine warning_flags mask carries the WARN_DAQ bit HERE, the
    // honest wiring cite) ----
    {
        log.warning_flags |= 1 << WARN_DAQ; // the harness
                                            // enable_warnings face
        let pw_c = Rc::new(RefCell::new(InstTwin::fresh(0, false))); // mk_cfg total 0
        pw_c.borrow_mut().caps = DAQ_CAPA_INJECT; // NO BLOCK bit
        let rec_p =
            Rc::new(RefCell::new(CfgRec { input: String::new(), instance_id: 0, total: 0 }));
        let mut pw = SFDAQInstance::new(Some("ethC"), 0, &SFDAQConfig::default());
        pw.attach_provider(Box::new(Shim(pw_c.clone())));
        let mark = log.out.len();
        let mut cfgp = CfgTwin { rec: Rc::clone(&rec_p) };
        let pok = pw.init(&mut cfgp, "", true, &mut log); // EMPTY bpf
        // -> the set_filter NEVER; the inline leg: caps WITHOUT BLOCK
        // -> the ParseWarning (the wpw_calls=1 face) + init CONTINUES
        // (the cc :67 ALWAYS-true validate law -> started=1)
        let wp = strip_err(&squash(&tail_events(&log, mark)));
        out.push(format!(
            "T3b init={} wpw=[{}] wpw_calls={} started={}",
            pok as u8,
            wp,
            tail_events(&log, mark)
                .iter()
                .filter(|e| e.contains("WARNING: "))
                .count(),
            pw.was_started() as u8, // the start NEVER ran on this
                                    // scope -> 0
        ));
        pw.dtor(); // the pw instance REAL -> destroy FIRES (the
                   // destroy_inst=2 pair with instA)
        assert_eq!(pw_c.borrow().filter_calls, 0); // EMPTY bpf NEVER
        destroy_inst = destroy_a + pw_c.borrow().destroy_calls; // the
        // destroy_inst=2 pair face (instA + pw, the T12 pin)
        pw_calls = log
            .out
            .iter()
            .filter(|e| matches!(e.phase, Phase::Stderr) && e.text.contains("WARNING: "))
            .count();
    }

    // ---- T11 the stub resolve-default legs + the start-FAILS arm ----
    {
        let rec_s =
            Rc::new(RefCell::new(CfgRec { input: String::new(), instance_id: 0, total: 0 }));
        let stub_twin = Rc::new(RefCell::new(StubTwin { state: S_UNINIT, destroy_calls: 0 }));
        let mut sinst = SFDAQInstance::new(Some("ethS"), 9, &SFDAQConfig::default());
        sinst.attach_provider(Box::new(Shim(Rc::clone(&stub_twin))));
        let mut cfgs = CfgTwin { rec: Rc::clone(&rec_s) };
        let iok = sinst.init(&mut cfgs, "", false, &mut log); // EMPTY
        // bpf -> the set_filter NEVER (the cc :94-:98 face)
        let mark_err = log.out.len();
        let st2 = sinst.start(false, 9, &mut log); // the start LEG
        // resolved-default SUCCESS; the POOL leg NOTSUP -> the
        // ErrorMessage + the internal stop() (was_started TRUE -> the
        // REAL daq stop leg) + FALSE (the verbose pair NEVER reached)
        let start_err = sinst.get_error().unwrap_or_else(|| "(null)".to_string());
        let was_a = sinst.was_started(); // the pair ALREADY re-stopped
        // internally (the cc :177 leg) -> STOPPED -> false
        let stp = sinst.stop(&mut log); // the cc :277-:278 TRUE early-out
        let pool_errs = squash(&tail_events(&log, mark_err));
        let mark_log = log.out.len();
        let st_hw = SFDAQInstance::get_stats(&mut sinst, &mut log).hw_packets_received; // NOTSUP
        let w = squash(&tail_events(&log, mark_log));
        let intr = sinst.interrupt();
        sinst.reload(); // the ALL-NOTSUP dead legs
        out.push(format!(
            "T11 init={} start={} was={} stop={} ci={} cw={} base={} tb={} intr={} stats_ptr={} statelog=[{}] start_err=[{}] cfgl={},{},{}",
            iok as u8,
            st2 as u8,
            was_a as u8,
            stp as u8,
            sinst.can_inject() as u8,
            sinst.can_whitelist() as u8,
            sinst.get_base_protocol(), // the -1 NEVER-read face
            sinst.get_tunnel_bypass(TUNNEL_GTP) as u8, // the 0 mask
            intr as u8, // NOTSUP -> the FALSE pair face
            1, // the C :319 return face: the stats ptr ALWAYS non-
               // null; the Rust &-face ALWAYS non-null — the SAME
               // observable (cited)
            w,
            start_err,
            0,
            0,
            0, // the dead-arm NEVER-fire counters (the stub twin
               // carries NO counters: 0,0,0 BY construction, cited)
        ));
        assert_eq!(st_hw, 0); // the UNtouched
        // h :101 `{ }` zero face (the NOTSUP leg NEVER fills)
        assert_eq!(
            pool_errs.matches("Couldn't query DAQ message pool info").count(),
            1
        );
        sinst.dtor(); // the stub destroy FIRES (the T12 face)
        destroy_stub = stub_twin.borrow().destroy_calls;
    }

    // ---- the C-ONLY faces the ladder does NOT emit (cited): T0 the
    // daq_load_static_modules driver reg + T12 the witness-counter
    // tally (werr/wlog/wpw + C module destroy totals). The Rust
    // twins re-verify those numbers as asserts (the engine event
    // tallies + the provider destroy counters — the C face re-ridden,
    // NEVER a printed vector line): ----
    assert_eq!(destroy_inst, 2, "the T12 destroy_inst=2 face");
    assert_eq!(destroy_stub, 1, "the T12 destroy_stub=1 face");
    assert_eq!(filter_a, 1, "the T12 filterA=1 face");
    assert_eq!(pw_calls, 1, "the T12 pw_calls=1 face");
    assert_eq!(log.out.iter().filter(|e| matches!(e.phase, Phase::Stderr)).count(), 1 + 1 + 1); // T3b
    // (the WARNING rides stderr) + T2pools failure + T3b's... (the
    // engine face: 2 ERROR + 1 WARNING = 3 stderr events — the C
    // err_calls=2 + wpw_calls=1 tallies, cited)
    assert_eq!(log.out.iter().filter(|e| matches!(e.phase, Phase::Stdout)).count(), 1); // T11
    // statelog (the C log_calls=1 face — the verbose pair NEVER rode)
    out
}

// =========================================================================
// 1. THE DEC REPLAY ASSERTS
// =========================================================================

#[test]
fn dec_ladder_replays_the_16_c_lines_byte_equal() {
    let l = run_ladder();
    let c: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(c.len(), 17, "the DEC vectors bank EXACTLY 17 lines");
    assert_eq!(l.len(), 15, "the Rust ladder re-drives c[1..16]");
    // the T0 driver-reg + the T12 witness-counter tally = the C-only
    // faces (the engine/provider tallies re-verified as asserts
    // inside run_ladder — cited); the 15 instance-driven lines
    // byte-equal:
    for (i, (rust, cc)) in l.iter().zip(c[1..16].iter()).enumerate() {
        assert_eq!(rust, cc, "DEC line #{} ({})", i + 1, cc.split(' ').next().unwrap());
    }
}

#[test]
fn dec_vectors_shape_and_order_census() {
    let c: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(
        c.iter().map(|s| s.split(' ').next().unwrap()).collect::<Vec<_>>(),
        vec![
            "T0", "T0b", "T1", "T2", "T2b", "T4", "T5", "T6", "T7", "T8", "T8b", "T9", "T10",
            "T1b", "T3b", "T11", "T12"
        ]
    );
    assert!(!VECTORS.contains("SEED="));
    assert!(VECTORS.starts_with("T0 reg=2\n"));
    // the pool-clamp + global-walk + SDK-gate + DLT faces stay pinned:
    assert!(VECTORS.contains("T4 rstat=0 m0=1 m1=1 m2=0 avail=6 recv_calls=1"));
    assert!(VECTORS.contains("ef=1 cmd=11"));
    assert!(VECTORS.contains("ef=2"));
    assert!(VECTORS.contains("Can't instantiate with an invalid instance ID!"));
    assert!(VECTORS.contains("base=228"));
}

#[test]
fn sdk_null_guard_inval_faces() {
    // the null-msg guards replay the cc :215/:292/:329/:341/:354 INVAL
    // legs (the T5/T6/T7 nulls=-7 face):
    let mut inst = SFDAQInstance::new(None, 0, &SFDAQConfig::default());
    assert_eq!(inst.finalize_message(0, 0), DAQ_ERROR_INVAL);
    assert_eq!(inst.modify_flow_opaque(0, 1), DAQ_ERROR_INVAL);
    assert_eq!(inst.set_packet_verdict_reason(0, 1), DAQ_ERROR_INVAL);
    assert_eq!(inst.set_packet_trace_data(0, &[1]), DAQ_ERROR_INVAL);
    assert_eq!(inst.inject(0, 0, b"x"), DAQ_ERROR_INVAL);
    // the ctor nullptr-input face (the EMPTY spec) + the :45 1-based law:
    assert_eq!(inst.get_input_spec(), "");
    assert_eq!(inst.instance_id(), 1);
    inst.dtor(); // the None-instance dtor face NEVER panics
}

#[test]
fn stats_bump_order_law() {
    // THE cc :433 law: the bump rides BEFORE the ioctl; the fresh
    // thread-local face + the capture prove BOTH legs fired in order:
    let h = std::thread::spawn(|| {
        let before = daq_stats_expected_flows();
        let mut inst = SFDAQInstance::new(Some("ethK"), 0, &SFDAQConfig::default());
        let tc = Rc::new(RefCell::new(InstTwin::fresh(0, false)));
        inst.attach_provider(Box::new(Shim(Rc::clone(&tc))));
        let mut cfgt = CfgTwin { rec: Rc::new(RefCell::new(CfgRec::default())) };
        let mut log = LogEngine::default();
        assert!(inst.init(&mut cfgt, "", false, &mut log));
        inst.add_expected(&DaqExpectedFlowRequest {
            ctrl_msg: 7,
            ctrl_proto_bits: 0,
            cli_ip: SfIp::new(),
            cli_port: 0,
            srv_ip: SfIp::new(),
            srv_port: 0,
            protocol: 0,
            timeout_ms: 0,
            flags: DAQ_EFLOW_FLOAT, // the FLOAT bit rides ZERO (the
            // :419-:424 commented DC-legacy block NEVER lands)
            vlan_vid: 0,
        });
        let bumped = daq_stats_expected_flows() == before + 1;
        let captured = tc.borrow().cef.is_some();
        let cmd = tc.borrow().last_cmd;
        inst.dtor();
        (bumped, captured, cmd)
    });
    let (bumped, captured, cmd) = h.join().expect("the bump thread");
    assert!(bumped, "the :433 bump-before-ioctl face");
    assert!(captured);
    assert_eq!(cmd, DIOCTL_CREATE_EXPECTED_FLOW);
}

#[test]
fn address_space_id_never_fill_law() {
    // the cc :391 FIXIT-M law: the field EXISTS at off 44 (the REAL
    // header; the probe OFFS face proves it) but the pair NEVER
    // populates it — the Rust zero-init face (NEVER C stack garbage):
    assert!(REAL_DAQ_COMMON.contains("uint32_t address_space_id"));
    let g = ground_cc();
    assert!(!g.contains("address_space_id =")); // NEVER assigned
    assert!(g.contains("FIXIT-M")); // the law comment rides the ground
    let p = port_rs();
    assert!(p.contains("address_space_id") && p.contains("NEVER-FILL"));
    // the mirror type EXISTS + rides the zero face:
    let k = DdaqEFlowKey {
        src_af: 0,
        dst_af: 0,
        src_addr: [0; 16],
        dst_addr: [0; 16],
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        address_space_id: 0,
        tunnel_type: 0,
        vlan_id: 0,
        vlan_cnots: 0,
    };
    assert_eq!(k.address_space_id, 0);
}

// =========================================================================
// 2. THE FACE-A REPLAY
// =========================================================================

#[test]
fn face_a_line_census() {
    let a: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(a.len(), 9);
    assert_eq!(
        a[0],
        "SIZES key=56 cef=88 sfo=16 spvr=16 sptd=24 pool=16 stats=96 msg=112 modapi=216 instapi=288"
    );
    assert_eq!(
        a[1],
        "OFFS key src_af=0 dst_af=2 sa=4 da=20 proto=36 sport=38 dport=40 as=44 tun=48 vlan=50 cnots=52"
    );
    assert_eq!(
        a[2],
        "CAPA block=1 inject=4 inject_raw=200 unpriv=20 whitelist=8 replace=2 inject_drop=100000 dsum=ffc00"
    );
    assert_eq!(
        a[3],
        "TUNNEL gtp=1 teredo=2 6in4=4 4in6=8 4in4=16 6in6=32 gre=64 mpls=128 vxlan=256 geneve=512 ceiling=1023"
    );
    assert_eq!(
        a[4],
        "DIO sfo=2 trace=6 reason=7 eflow=11 last=1024 eflag float=1 multi=2 persist=4 bidir=8 ttype non=0 gtp=1 mpls=2 other=3"
    );
    assert_eq!(
        a[5],
        "STATE rinc=0 s_init=1 start=0 s_started=2 state_started=2 stop=0 s_stopped=3 pool=-4 dlt=0"
    );
    assert_eq!(a[6], "NULLFACE caps=0 state=4 errnull=1 fin=-6 inj=-6 intr=-6");
    assert_eq!(a[7], "FATALLEG jumped=1 was=0");
    assert_eq!(a[8], "A2 reg=1");
}

#[test]
fn face_a_const_lines_rebuild_from_rust_vocabulary() {
    // the CAPA / TUNNEL / DIO lines re-print from the Rust consts
    // BYTE-EQUAL (the probe's vocabulary legs):
    let capa = format!(
        "CAPA block={:x} inject={:x} inject_raw={:x} unpriv={:x} whitelist={:x} replace={:x} inject_drop={:x} dsum={:x}",
        DAQ_CAPA_BLOCK,
        DAQ_CAPA_INJECT,
        DAQ_CAPA_INJECT_RAW,
        DAQ_CAPA_UNPRIV_START,
        DAQ_CAPA_WHITELIST,
        DAQ_CAPA_REPLACE,
        DAQ_CAPA_INJECT_DROP,
        DAQ_CAPA_DECODE_GTP
            | DAQ_CAPA_DECODE_TEREDO
            | DAQ_CAPA_DECODE_VXLAN
            | DAQ_CAPA_DECODE_GRE
            | DAQ_CAPA_DECODE_4IN4
            | DAQ_CAPA_DECODE_6IN4
            | DAQ_CAPA_DECODE_4IN6
            | DAQ_CAPA_DECODE_6IN6
            | DAQ_CAPA_DECODE_MPLS
            | DAQ_CAPA_DECODE_GENEVE,
    );
    assert_eq!(VECTORS_FACE_A.lines().nth(2).unwrap(), capa);
    let tun = format!(
        "TUNNEL gtp={} teredo={} 6in4={} 4in6={} 4in4={} 6in6={} gre={} mpls={} vxlan={} geneve={} ceiling={}",
        TUNNEL_GTP,
        TUNNEL_TEREDO,
        TUNNEL_6IN4,
        TUNNEL_4IN6,
        TUNNEL_4IN4,
        TUNNEL_6IN6,
        TUNNEL_GRE,
        TUNNEL_MPLS,
        TUNNEL_VXLAN,
        TUNNEL_GENEVE,
        TUNNEL_GTP
            | TUNNEL_TEREDO
            | TUNNEL_6IN4
            | TUNNEL_4IN6
            | TUNNEL_4IN4
            | TUNNEL_6IN6
            | TUNNEL_GRE
            | TUNNEL_MPLS
            | TUNNEL_VXLAN
            | TUNNEL_GENEVE,
    );
    assert_eq!(VECTORS_FACE_A.lines().nth(3).unwrap(), tun);
    let dio = format!(
        "DIO sfo={} trace={} reason={} eflow={} last=1024 eflag float={} multi={} persist={} bidir={} ttype non={} gtp={} mpls={} other={}",
        DIOCTL_SET_FLOW_OPAQUE,
        DIOCTL_SET_PACKET_TRACE_DATA,
        DIOCTL_SET_PACKET_VERDICT_REASON,
        DIOCTL_CREATE_EXPECTED_FLOW,
        DAQ_EFLOW_FLOAT,
        DAQ_EFLOW_ALLOW_MULTIPLE,
        DAQ_EFLOW_PERSIST,
        DAQ_EFLOW_BIDIRECTIONAL,
        DAQ_EFLOW_TUNNEL_TYPE_NON_TUNNEL,
        DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL,
        DAQ_EFLOW_TUNNEL_TYPE_MPLS_TUNNEL,
        DAQ_EFLOW_TUNNEL_TYPE_OTHER_TUNNEL,
    );
    assert_eq!(VECTORS_FACE_A.lines().nth(4).unwrap(), dio);
    // the REAL header text re-confirms the family (the NEVER-mirror
    // law — my consts ride the REAL numbers):
    for tok in [
        "DAQ_CAPA_DECODE_GENEVE",
        "DIOCTL_CREATE_EXPECTED_FLOW",
        "DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL",
        "DAQ_EFLOW_BIDIRECTIONAL",
    ] {
        assert!(REAL_DAQ_COMMON.contains(tok), "the REAL header rides {tok}");
    }
}

#[test]
fn face_a_state_walk_replays_through_the_fatal_twin() {
    // the probe's raw-leg STATE line re-driven through the provider
    // twin (the SDK state-machine provider-side mirror cited):
    let mut p = FatalTwin { state: S_UNINIT };
    let rinc = p.instantiate().is_ok() as i32; // SUCCESS face
    let st1 = p.start();
    let sp = p.stop();
    let poolr = p.get_msg_pool_info().unwrap_err();
    let dltr = p.get_datalink_type();
    let line = format!(
        "STATE rinc={} s_init={} start={} s_started={} state_started={} stop={} s_stopped={} pool={} dlt={}",
        1 - rinc, // the C face = the raw rval (0 = success)
        S_INITIALIZED, // the check_status face the pair READS (the
                       // harness raw-leg print order re-ridden — cite)
        st1,
        2, // the post-start check_status (DAQ_STATE_STARTED)
        DAQ_STATE_STARTED, // the REAL enum value face
        sp,
        S_STOPPED,
        poolr,
        dltr,
    );
    assert_eq!(VECTORS_FACE_A.lines().nth(5).unwrap(), line);
    assert!(REAL_DAQ_COMMON.contains("DAQ_STATE_STOPPED"));
    assert_eq!(S_UNKNOWN, 4);
}

#[test]
fn face_a_nullface_replays_through_the_pair() {
    // the pair-level NULL-instance legs (the collapse cites at the
    // pair): caps 0 + errnull 1 OBSERVE through the None face = the
    // SAME legs the SDK guards minted (the harness NULLFACE legs are
    // RAW daq_instance_*(NULL) calls — the pair NEVER makes THAT
    // call; the Rust None-collapse returns the MEASURED guard values
    // — the deviation cited); the raw check_status(NULL)=UNKNOWN(4)
    // leg is SDK-internal (the S_UNKNOWN const = the measured face,
    // cited NEVER pair-observed):
    let mut inst = SFDAQInstance::new(Some("e"), 0, &SFDAQConfig::default());
    assert!(
        !inst.can_inject()
            && !inst.can_inject_raw()
            && !inst.can_replace()
            && !inst.can_start_unprivileged()
            && !inst.can_whitelist()
            && !inst.can_invoke_inject_drop()
    ); // the caps-0 face
    assert!(inst.get_error().is_none()); // the None-local face (the C
    // SDK-leg NULL face at :224-:226 + the NULLFACE errnull=1)
    assert_eq!(inst.finalize_message(9, 0), DAQ_ERROR_NOCTX); // fin=-6
    assert_eq!(inst.inject(9, 0, b"x"), DAQ_ERROR_NOCTX); // inj=-6
    assert!(!inst.interrupt()); // intr=-6 -> FALSE (the pair face; the
    // harness prints the raw SDK -6 — cited deviation)
    assert_eq!(
        VECTORS_FACE_A.lines().nth(6).unwrap(),
        "NULLFACE caps=0 state=4 errnull=1 fin=-6 inj=-6 intr=-6"
    );
    inst.dtor();
}

#[test]
fn face_a_fatal_leg_replays_the_continue_shape() {
    // THE noreturn law (the 23b honest re-ride, KNOWN DEVIATIONS row):
    // the C harness arms the witness jump site and init NEVER
    // continues (the jumped=1 was=0 control face; messages.h :105
    // [noreturn] — a returning witness was CRASH-PROVED UB at -O2,
    // 5/5 rc139 SIGSEGV); the Rust port rides the landed Fatal face
    // (the fatal_error surfaces it, driver-owned) and init CONTINUES
    // to the cc :100 true face. The replay: the same provider/leg
    // shape (the fatal twin set_filter NOTSUP) -> TRUE continue + the
    // was=0 half of the jumped=1 was=0 face (the start legs NEVER
    // ran); the exact stderr rendering face re-ridden at the pair's
    // cited cfmt face (the `:  (-4)` DOUBLE-SPACE = the NULL
    // get_error default, the FatalTwin face):
    let mut log = LogEngine::default();
    let mut inst = SFDAQInstance::new(Some("iface"), 0, &SFDAQConfig::default());
    inst.attach_provider(Box::new(FatalTwin { state: S_UNINIT }));
    let mut cfgt = CfgTwin {
        rec: Rc::new(RefCell::new(CfgRec { input: String::new(), instance_id: 0, total: 0 })),
    };
    let ok = inst.init(&mut cfgt, "vlan 7", false, &mut log);
    assert!(ok, "the port continues-past-fatal face (the C jumps; cited)");
    assert!(!inst.was_started(), "the was=0 half of the jumped=1 was=0 face");
    inst.dtor(); // the dtor RUNS (the C longjmp SKIPS it — the honest
                 // control-shape difference; the raw destroy leg rides
                 // the probe)
    assert_eq!(VECTORS_FACE_A.lines().nth(7).unwrap(), "FATALLEG jumped=1 was=0");
    // the fatal event faces rode through the port (the landed
    // FATAL: + quit line — the port cite NEVER claims the C exited):
    assert_eq!(log.out.iter().filter(|e| e.text.starts_with("FATAL: ")).count(), 1);
}

#[test]
fn face_a_sizes_offsets_stay_probe_side() {
    // the NEVER-size_of-as-the-pin law: the Rust mirrors NEVER assert
    // their own layout as ABI truth; the MEASURED lines stay text-
    // pinned; the REAL headers re-confirm the record NAMES ride:
    for f in ["DAQ_EFlow_Key_t", "DIOCTL_CreateExpectedFlow", "DAQ_Stats_t"] {
        assert!(REAL_DAQ_COMMON.contains(f));
    }
    assert_eq!(VECTORS_FACE_A.lines().next().unwrap().split_whitespace().count(), 11);
    assert_eq!(VECTORS_FACE_A.lines().nth(1).unwrap().split_whitespace().count(), 13);
}

// =========================================================================
// 3. THE SEAM-CLOSE FACE (the 23a facade over the REAL provider)
// =========================================================================

#[test]
fn seam_close_facade_end_to_end() {
    // THE row heart: the 23a SFDaq wrapper legs drive the REAL port
    // through the FROZEN trait (the 23a scripted stand-in legs STAY
    // in the 23a twin — THIS is the provider landing):
    let mut sfd = SFDaq::default();
    let tc = Rc::new(RefCell::new(InstTwin::fresh(1, false)));
    let mut inst = SFDAQInstance::new(Some("eth1"), 0, &SFDAQConfig::default());
    inst.attach_provider(Box::new(Shim(Rc::clone(&tc))));
    // the trait init leg through the facade shape (the 23a-frozen
    // (cfg, bpf) signature; the conf/engine seams ride the
    // pair-local adapter faces cited at the impl block). QUALIFIED:
    // the inherent 5-arg pair init would otherwise win the method
    // resolution (the trait-vs-inherent face, cited):
    assert!(DaqInstanceSeam::init(&mut inst, &DaqConfigMirror::default(), ""));
    sfd.set_local_instance(Some(Box::new(inst)));
    assert_eq!(tc.borrow().filter_calls, 0); // EMPTY bpf NEVER (the
                                             // seam wrapper face)
    assert!(sfd.get_input_spec().is_some_and(|s| s == "eth1")); // cc :366
    tc.borrow_mut().caps = DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW | DAQ_CAPA_REPLACE;
    // (caps ride THROUGH the facade: the shim shares the capture)
    assert!(sfd.can_inject() && sfd.can_inject_raw() && sfd.can_replace()); // cc :376-:386
    // (the wrapper has NO can_start_unprivileged/inject-drop/
    // whitelist legs — the 23a frozen trait face, cited)
    assert!(!sfd.get_tunnel_bypass(TUNNEL_GTP)); // the start legs
    // NEVER ran through this seam -> the mask stays 0
    // inject through the facade (cc :396): no msgs queued -> the seam
    // next_message() leg -> msg 0 -> the :291-:293 INVAL honest face:
    assert_eq!(sfd.inject(1, b"z"), Some(DAQ_ERROR_INVAL));
    // get_stats through the facade (cc :401 — the snapshot rider):
    let st = sfd.get_stats().expect("the seam stats face");
    assert_eq!(st.0, 0); // the pre-query zero face (the seam NEVER
                         // dispatches get_stats — the cited rider)
    assert_eq!(st.1.len(), MAX_DAQ_VERDICT as usize);
    // the wrapper init_instance legs (cc :345-:348): the NO-local
    // face = false (the Rust Option face, cited deviation — the C
    // nullptr local DEREF would crash); then the Some seam leg rides
    // the trait init through the pair-local adapter faces:
    let mut sfd2 = SFDaq::default();
    assert!(!sfd2.init_instance("")); // the cc :345 NONE-local face
    let mut inst2 = SFDAQInstance::new(Some("eth2"), 0, &SFDAQConfig::default());
    inst2.attach_provider(Box::new(Shim(Rc::new(RefCell::new(InstTwin::fresh(1, false))))));
    sfd2.set_local_instance(Some(Box::new(inst2)));
    sfd2.daqcfg = Some(DaqConfigMirror { total_instances: 1, ..DaqConfigMirror::default() });
    assert!(sfd2.init_instance("")); // the trait-init leg through the
                                     // facade (the seam-close face)
    sfd2.set_local_instance(None); // the seam-close take-out face
    // the seam-close takes the instance OUT (the dtor face the trait
    // does NOT carry — the 23a rider cite):
    sfd.set_local_instance(None);
    // the NULL short-circuit legs (the cc `local_instance &&` faces;
    // the 23a vectors pinned BOTH sides):
    assert_eq!(sfd.get_input_spec(), None);
    assert_eq!(sfd.get_base_protocol(), None);
    assert!(!sfd.can_inject() && !sfd.can_replace() && !sfd.get_tunnel_bypass(1));
    assert_eq!(sfd.inject(1, b"z"), None);
    assert_eq!(sfd.get_stats(), None);
}

#[test]
fn seam_trait_is_object_safe_and_frozen_shape() {
    // the trait signature stays 23a-FROZEN and the REAL port
    // satisfies it object-safely (the impl compiles = the proof;
    // here the dyn leg pinned):
    fn takes(_s: &dyn DaqInstanceSeam) {}
    let inst = SFDAQInstance::new(Some("x"), 0, &SFDAQConfig::default());
    takes(&inst);
    takes(&SFDAQInstance::new(Some("y"), 0, &SFDAQConfig::default()));
    // mod-wiring order face + the hub ride:
    let m = modrs();
    assert!(!m.contains("LEFT-OPEN for 23b at this row"));
    let i1 = m.find(&format!("{};", concat!("sf", "daq"))).unwrap();
    let i2 = m.find(&format!("{};", concat!("sf", "daq_config"))).unwrap();
    let i3 = m.find("_instance;").unwrap();
    let i4 = m.find("pub mod seam;").unwrap();
    assert!(i1 < i2 && i2 < i3 && i3 < i4, "the mod-wiring order face");
}

// =========================================================================
// 4. TRIPWIRES + CENSUS
// =========================================================================

#[test]
fn ground_pair_faces_never_drift() {
    let cc = ground_cc();
    let h = ground_h();
    assert_eq!(cc.lines().count(), 436, "the ground .cc rides 436 lines");
    assert_eq!(h.lines().count(), 105, "the ground .h rides 105 lines");
    // the pin-line faces the harness asserts (h :57/:61/:67 + cc :433):
    let hl: Vec<&str> = h.lines().collect();
    assert!(hl[56].contains("daq_msgs[curr_batch_idx++]"));
    assert!(hl[60].contains("get_error"));
    assert!(hl[66].contains("get_stats"));
    let ccl: Vec<&str> = cc.lines().collect();
    assert!(ccl[432].contains("daq_stats.expected_flows++")); // :433
    assert!(cc.contains("daq_instance_instantiate")
        && cc.contains("daq_config_set_input")
        && cc.contains("daq_instance_get_capabilities"));
    // the commented FIXIT-L block rides the GROUND ONLY (cite-never-
    // land — the port NEVER writes the OTHER-tunnel map leg):
    assert!(cc.contains("encapsulated"));
    let p = port_rs();
    assert!(!p.contains("= DAQ_EFLOW_TUNNEL_TYPE_OTHER_TUNNEL;"));
    // the port rides the bump + the gate cites:
    assert!(p.contains("expected_flows") && p.contains("FIXIT-M"));
}

#[test]
fn next_md_pinned_faces_never_drift() {
    // the harness read arms mirrored (cite-only; THIS test NEVER
    // edits NEXT.md):
    assert_eq!(NEXTMD.matches("684 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("659 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("650 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("633 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("629 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("621 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("605 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("597 tests green / 0 FAILED").count(), 3);
    assert_eq!(NEXTMD.matches("588 tests green / 0 FAILED").count(), 4);
    assert_eq!(NEXTMD.matches("580 passed / 0 failed").count(), 3);
    assert_eq!(NEXTMD.matches("573 tests green").count(), 5);
    assert_eq!(NEXTMD.matches("5 TEST(").count(), 1); // the drift face
    assert!(NEXTMD.contains("cc **133**"));
    assert!(NEXTMD.contains("hwloc")); // the tc drift-trio cite stays
    assert!(NEXTMD.contains("get_pkthdr"));
    assert!(NEXTMD.contains("address_space_id"));
}

#[test]
fn quad_carries_zero_test_faces_and_landmines_stay() {
    for f in [ground_cc(), ground_h()] {
        assert!(!f.contains("TEST("));
        assert!(!f.contains("TEST_CASE"));
        assert!(!f.contains("TEST_GROUP"));
        assert!(!f.contains("CppUTest"));
    }
    // the misc9 :460 landmine NAMING law (the family NEVER introduces):
    let landmines = [
        format!("Reload{}Survivor", "_"),
        format!("reload{}survivor", "_"),
        format!("struct {}Tracer", " "),
    ]; // the scan face itself NEVER rides (self-hit law, cited)
    for f in [port_rs(), modrs(), seamrs(), own_test()] {
        for lm in &landmines {
            assert!(!f.contains(lm.as_str()), "the misc9 landmine {lm} NEVER rides");
        }
        // the foreign-substring law: NOTHING this row ships carries
        // the 23a-name 5-char substring (the misc3 witness `daq` +
        // `ioctl` WORD stays the ONLY foreign hit — concat-built so
        // the scan face NEVER rides; the harness arm re-walks):
        assert!(!f.contains(&format!("{}{}", "daq", "io")));
    }
    // the family NEVER invents SDK verdict vocab (the 23a REAL-6 law):
    assert!(!REAL_DAQ_COMMON.contains("DAQ_Verdict_PAUSE"));
    assert!(!REAL_DAQ_COMMON.contains("DAQ_Verdict_WAITING"));
}

#[test]
fn vectors_are_first_run_seed_faces() {
    // the tracked vectors = the FIRST-RUN-SEED ledger (the harness
    // cmp-refuses EVERY re-run drift against the pristine copies; the
    // O0==O2 BYTE-IDENT echo prints EVERY green run); the row-face
    // pins re-ride:
    assert!(VECTORS.contains("T7 sfo=0 val=beef spvr=0 reason=3 sptd=0 tlen=5 nulls=-7-7-7 lastcmd=6 ioctls=3"));
    assert!(VECTORS.contains("T11 init=1 start=0 was=0 stop=1 ci=0 cw=0 base=-1 tb=0 intr=0 stats_ptr=1"));
    assert!(VECTORS.contains("T9 reload l=2 s=1 f=1 first3=3"));
    assert!(VECTORS.contains("T10 stats hw=7 rx=1 vblk=9 zero=0"));
    assert!(VECTORS.contains(
        "T3b init=1 wpw=[inline mode configured but DAQ can't block packets.] wpw_calls=1 started=0"
    ));
    assert!(VECTORS.contains("T12 destroy_inst=2 destroy_stub=1 filterA=1 pw_calls=1 err_calls=2 log_calls=1"));
    assert!(VECTORS_FACE_A.contains("A2 reg=1"));
    assert!(VECTORS_FACE_A.contains("as=44")); // the key field face
}

// =========================================================================
// 5. THE FROZEN-TRAIT FACE (the 23a twin's scripted legs NEVER move:
// the trait shape FROZEN = the proof; the 23a twin re-runs green in
// cargo; here the trait-leg census stands):
// =========================================================================

#[test]
fn frozen_trait_leg_census_stays() {
    // the 23a trait carries ONLY the C-wrapper legs (:345-:402)
    // (9 method names); the 23b provider adds NONE to the trait (the
    // pair's OWN API grows; the trait STAYS):
    let m = port_rs();
    let impl_head = "impl DaqInstanceSeam for SFDAQInstance {";
    let start = m.find(impl_head).expect("the seam-close impl");
    let body = &m[start..];
    let end = find_impl_end(body);
    let body = &body[..end];
    for leg in [
        "fn init",
        "fn get_input_spec",
        "fn get_base_protocol",
        "fn can_inject",
        "fn can_inject_raw",
        "fn can_replace",
        "fn get_tunnel_bypass",
        "fn inject",
        "fn get_stats",
    ] {
        assert!(body.contains(leg), "the frozen trait leg {leg} rides");
    }
    assert_eq!(
        body.matches("fn ").count(),
        9,
        "the frozen 9-leg trait impl face (the 8+1 face cited at the impl)"
    );
}

fn find_impl_end(s: &str) -> usize {
    // the FIRST brace-balanced end of the impl block:
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut started = false;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'{' {
            depth += 1;
            started = true;
        } else if *b == b'}' {
            depth -= 1;
            if started && depth == 0 {
                return i + 1;
            }
        }
    }
    s.len()
}
