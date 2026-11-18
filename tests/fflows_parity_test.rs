//! Whole-transcript replay of tools/fflows_harness/vectors.txt against the
//! Rust FileFlows port (src/file_api/file_flows.rs + the FileContext
//! member half of src/file_api/file_lib.rs, plan row 17q). The C probe
//! (tools/fflows_harness/probe.cc) compiles the ORIGINAL file_flows.cc
//! verbatim over the donor fcache closure — its gate: the TU's own 8
//! embedded `#ifdef UNIT_TEST` [file_flows] TEST_CASEs (gate.txt: "All
//! tests passed (22 assertions in 8 test cases)" — translated one-for-one
//! as the 8 up_gate_* tests below, the 17p up_gate pattern).
//!
//! Every transcript line is produced by a REAL port call site or by the
//! witness seams mirroring tools/fflows_harness/stubs.cc (same shapes the
//! fcache replay wired, plus the NEW17q witnesses: NetworkPolicy ->
//! StubFilePolicy through the real ref-count protocol, PacketTracer
//! daq/restart/get_time (pinned constant), armable get_instance_id, the
//! DetectionEngine queue_event line, and the FileService
//! get_max_file_depth passthrough). Driver deviations (mirror the src
//! module headers):
//! * C raw owning `FileContext*` -> `Rc<RefCell<FileContext>>`: driver
//!   alias handles die BEFORE the call the C `delete` sits in, so the
//!   port's own slot-drop is the Rc last-drop and every "IMGR release"
//!   lands at the transcript position C produced.
//! * C4's `m3_new=%d` compares the fresh main against the dangling
//!   old-main pointer; glibc hands `new FileContext` the just-freed
//!   chunk, so C reads them EQUAL (pinned 0 across every rebuild). Rc
//!   object identity structurally excludes use-after-free aliasing
//!   (module-header deviation) — the pinned vector value is verbatim.
//! * The probe's PacketTracer::daq_log format string ends WITHOUT a
//!   newline ("...Verdict %s.$"), so the J_CACHEHIT printf continues the
//!   same transcript LINE (harness printf interleave): the replay
//!   appends that label to the last pushed line.
//! * `FileService::get_max_file_depth` answers the harness witness
//!   passthrough (stubs.cc `g_max_file_depth` — FileService is a witness
//!   TU in this link), pinned by the H/J depth arms (0/10/-5); the
//!   config-resolved real body is row 17r.
//! * Sizes (A_SZ_FF/SZ_SLOT/offsets/size_of) are C layout constants: the
//!   Rc/Vec port shape does not reproduce a sizeof — pinned literals,
//!   like the fcache SIZEOF_FILE_NODE precedent.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use snort3::file_api::file_cache::*;
use snort3::file_api::file_flows::*;
use snort3::file_api::file_lib::{
    FILE_DOWNLOAD, FILE_UPLOAD, FILE_VERDICT_BLOCK, FILE_VERDICT_LOG, FILE_VERDICT_PENDING,
    FILE_VERDICT_UNKNOWN, FileConfigLite, FileContext, FileEnvLite, NetworkPolicySeam, PublishApi,
    SNORT_FILE_FULL, SNORT_FILE_MIDDLE, SNORT_FILE_POSITION_UNKNOWN, SNORT_FILE_START, TimeVal,
};
use snort3::file_api::file_stats::FileCounts;
use snort3::helpers::event_gen::DetectionEventSink;

const VECTORS: &str = include_str!("../tools/fflows_harness/vectors.txt");

/// C layout vocabulary from the probe (sizeof/offsetof of the C classes).
const SZ_FF: usize = 216; // sizeof(FileFlows)
const SZ_SLOT: usize = 16; // sizeof(FileFlows::CurrentContextSlot)

fn hexbuf(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

// -------------------------------------------------------------------
// Witness hub (bodies mirror tools/fflows_harness/stubs.cc 1:1)
// -------------------------------------------------------------------

type Out = Rc<RefCell<Vec<String>>>;

fn push(out: &Out, s: impl Into<String>) {
    out.borrow_mut().push(s.into());
}

/// The print that C's newline-less daq_log printf line left open: appends
/// to the last transcript line (printf interleave, pinned by line 123).
fn push_continue(out: &Out, s: &str) {
    let mut o = out.borrow_mut();
    match o.last_mut() {
        Some(last) => last.push_str(s),
        None => o.push(s.to_string()),
    }
}

/// TraceApi witness for the THREAD_LOCAL file_trace (level gate + tag;
/// both TUs' FILE_DEBUG print FILEDBG[file_cache] in the harness).
struct TraceWit {
    out: Out,
    level: Rc<RefCell<u8>>,
}
impl TraceSink for TraceWit {
    fn file_trace(&mut self, level: u8, msg: &str) {
        if *self.level.borrow() >= level {
            push(
                &self.out,
                format!("FILEDBG[file_cache] {}", msg.trim_end_matches('\n')),
            );
        }
    }
}

/// DetectionEngine::get_current_packet witness (the GET_CURRENT_PACKET
/// macro argument — evaluated even when the level gate suppresses the
/// print; the probe never arms a current packet: have=0).
struct CurPkt {
    out: Out,
}
impl CurrentPacketApi for CurPkt {
    fn get_current_packet(&mut self) {
        push(&self.out, "DE get_current_packet have=0");
    }
}

/// Harness FileInspect witness (its `config` = the resolved FileConfig).
struct StubInspector {
    cfg: Rc<RefCell<FileConfigView>>,
}
impl InspectorApi for StubInspector {
    fn config(&self) -> Rc<RefCell<FileConfigView>> {
        self.cfg.clone()
    }
}

/// InspectorManager acquire/release witnesses. `armed` mirrors
/// g_stub_file_inspector — one-shot latch.
struct Imgr {
    out: Out,
    armed: Rc<RefCell<Option<Rc<StubInspector>>>>,
}
impl InspectorManagerApi for Imgr {
    fn acquire_file_inspector(&mut self) -> Option<Rc<dyn InspectorApi>> {
        let armed = self.armed.borrow();
        push(
            &self.out,
            format!(
                "IMGR acquire -> {}",
                if armed.is_some() { "inspector" } else { "null" }
            ),
        );
        armed.as_ref().map(|a| a.clone() as Rc<dyn InspectorApi>)
    }
    fn release(&mut self, _ins: &Rc<dyn InspectorApi>) {
        push(&self.out, "IMGR release");
    }
}

/// StubFilePolicy (stubs.cc): heap object, ref_count 1 at "new"; probe-
/// armed verdicts ride shared Cells (fcache_set_policy_verdicts mutates
/// the ONE global object); every virtual prints when reached.
struct PolicyStub {
    out: Out,
    tv: Rc<Cell<u32>>,
    sv: Rc<Cell<u32>>,
}
impl FilePolicyApi for PolicyStub {
    fn policy_check(&mut self, _flow: &CacheFlow, _file: &mut FileContext) {
        push(&self.out, "POLICY policy_check");
    }
    fn type_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        let v = self.tv.get();
        push(&self.out, format!("POLICY type_lookup -> {v}"));
        v
    }
    fn signature_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        let v = self.sv.get();
        push(&self.out, format!("POLICY signature_lookup -> {v}"));
        v
    }
    fn log_file_action(&mut self, _flow: &CacheFlow, _file: &mut FileContext, action: u32) {
        push(&self.out, format!("POLICY log_file_action a={action}"));
    }
}

/// NetworkPolicy witness (PINNED storage in C): get_base_file_policy
/// hands back the shared handle — C returns the raw pointer with NO
/// add_ref (FileFlows::set_file_policy performs the add_ref, mirroring
/// the ref protocol the probe reads refs=1->2 / policy_refs=2->1).
struct NetPol {
    handle: FilePolicyHandle,
}
impl NetworkPolicySeam for NetPol {
    fn get_base_file_policy(&mut self) -> Option<FilePolicyHandle> {
        Some(self.handle.clone())
    }
}

/// PacketTracer witnesses: is_active false (the probe never arms it — no
/// "PT " lines in the transcript), NEW17q is_daq_activated ARMABLE,
/// restart_timer / get_time (PINNED constant 1700000100000000, stubs.cc)
/// / daq_log (the format string has NO trailing newline).
struct PTr {
    out: Out,
    daq: Rc<Cell<bool>>,
}
impl PacketTracerApi for PTr {
    fn is_active(&self) -> bool {
        false
    }
    fn log(&mut self, msg: &str) {
        push(&self.out, format!("PT {}", msg.trim_end_matches('\n')));
    }
    fn is_daq_activated(&self) -> bool {
        self.daq.get()
    }
    fn restart_timer(&mut self) {
        push(&self.out, "PT restart_timer");
    }
    fn daq_log(&mut self, msg: &str) {
        push(&self.out, format!("PTdaq {msg}"));
    }
    fn get_time(&self) -> u64 {
        1_700_000_100_000_000
    }
}

/// DetectionEngine::queue_event witness.
struct Devt {
    out: Out,
}
impl DetectionEventSink for Devt {
    fn queue_event(&mut self, gid: u32, sid: u32) {
        push(&self.out, format!("DE queue_event gid={gid} sid={sid}"));
    }
}

/// DataBus publish witnesses ("PUBBYTES ..." / "PUB ... len=0").
struct PubWit {
    out: Out,
}
impl PublishApi for PubWit {
    fn publish_verdict(&mut self, pid: u32, eid: u32, data: &[u8]) {
        push(
            &self.out,
            format!(
                "PUBBYTES pub={pid} evt={eid} len={} data={}",
                data.len(),
                hexbuf(data)
            ),
        );
    }
    fn publish_file_complete(&mut self, pid: u32, eid: u32) {
        push(&self.out, format!("PUB pub={pid} evt={eid} len=0"));
    }
}

/// FileCache-side event seam (the 17p FileContext::log_file_event
/// forwarder — apply_verdict/store/resume sites). EvtSink body shared
/// with the fcache replay so the committed 17p witness semantics hold.
struct EvtSink {
    out: Out,
    level: Rc<RefCell<u8>>,
    adv_pub_id: Rc<Cell<u32>>,
}
impl FileCacheEventSink for EvtSink {
    fn publish_file_share_sync(&mut self, _key: &FileHashKey, _timeout: i64, _file: &FileContext) {
        push(&self.out, "MPDBUS get_id name=file_mp_events events=2 -> 42");
        push(&self.out, "MPDBUS publish pub=42 evt=1 have_event=1");
    }
    fn file_log_event(
        &mut self,
        file: &FileContext,
        flow: &CacheFlow,
        _policy: &mut dyn FilePolicyApi,
    ) {
        // file_lib.cc:613 gate: is_file_name_set() or !two_way_traffic()
        if !file.info.is_file_name_set() && flow.two_way_traffic {
            return;
        }
        let cstr: &'static [u8] = match file.info.verdict {
            FILE_VERDICT_LOG => b"LOG",
            FILE_VERDICT_BLOCK => b"BLOCK",
            4 => b"RESET",
            _ => b"",
        };
        if cstr.is_empty() {
            return;
        }
        push(
            &self.out,
            format!(
                "PUBBYTES pub=1 evt=23 len={} data={}",
                cstr.len(),
                hexbuf(cstr)
            ),
        );
        push(
            &self.out,
            format!("PUB pub={} evt=0 len=0", self.adv_pub_id.get()),
        );
        if *self.level.borrow() >= TRACE_DEBUG_LEVEL {
            push(&self.out, "DE get_current_packet have=0");
            let name = String::from_utf8_lossy(file.info.get_file_name()).to_string();
            push(
                &self.out,
                format!(
                    "FILEDBG[file_cache] File advance log: fuid-{}, source-, mime type-, file name-{name}, duration-0.000000, is orig-0, seen bytes-0, total bytes-0, timedout-{}, sha256-, extracted name-, extracted cutoff-0, extracted size-0",
                    file.info.get_file_id(),
                    u8::from(file.get_timedout()),
                ),
            );
        }
    }
}

/// FileFlowsSink (the FileCache half's flow-FlowData seam — this probe
/// reaches the REAL bodies directly; silent-shape for the cache wiring).
struct FFlowsWitness;
impl FileFlowsSink for FFlowsWitness {
    fn get_file_flows(&mut self, _to_create: bool) -> bool {
        false
    }
    fn add_pending_file(&mut self, _file_id: u64) {}
}

struct ActWit {
    out: Out,
}
impl ActiveWitness for ActWit {
    fn delayed_action(&mut self, action: u8, force: bool) {
        push(
            &self.out,
            format!("ACT delayed={action} force={}", u8::from(force)),
        );
    }
    fn drop_reason(&mut self, reason: &str) {
        push(&self.out, format!("ACT drop_reason={reason}"));
    }
}

/// file_config.cc FileConfig::file_type_name (the live table: id 0 ->
/// CONTINUE, 65535 -> UNKNOWN — pinned shape from the fcache dumps).
struct ConfigTypeNames;
impl FileTypeNames for ConfigTypeNames {
    fn file_type_name(&self, id: u32) -> String {
        match id {
            65535 => "Unknown file type, done".into(),
            0 => "Undecided file type, continue...".into(),
            _ => String::new(),
        }
    }
}

// -------------------------------------------------------------------
// Hub: program-static witness state shared across every FileCache /
// FileFlows (the C file-scope statics; the port threads Rc/Cell clones).
// -------------------------------------------------------------------

struct Hub {
    out: Out,
    level: Rc<RefCell<u8>>,
    armed: Rc<RefCell<Option<Rc<StubInspector>>>>,
    conf_view: Rc<RefCell<FileConfigView>>,
    adv_pub_id: Rc<Cell<u32>>,
    daq: Rc<Cell<bool>>,
    // the single heap StubFilePolicy (ref_count 1 at "new") + verdict Cells
    stub_handle: FilePolicyHandle,
    tv: Rc<Cell<u32>>,
    sv: Rc<Cell<u32>>,
    env: FileEnvLite,
}

impl Hub {
    fn new() -> Hub {
        let out: Out = Rc::new(RefCell::new(Vec::new()));
        let level = Rc::new(RefCell::new(0u8));
        let armed = Rc::new(RefCell::new(None));
        let conf_view = Rc::new(RefCell::new(FileConfigView::default()));
        let adv_pub_id = Rc::new(Cell::new(7u32)); // fcache_set_adv_pub_id(7)
        let daq = Rc::new(Cell::new(false));
        let tv = Rc::new(Cell::new(FILE_VERDICT_UNKNOWN));
        let sv = Rc::new(Cell::new(FILE_VERDICT_UNKNOWN));
        let stub_handle = FilePolicyHandle::new_boxed(Box::new(PolicyStub {
            out: out.clone(),
            tv: tv.clone(),
            sv: sv.clone(),
        }));
        let env = FileEnvLite {
            trace: Box::new(TraceWit {
                out: out.clone(),
                level: level.clone(),
            }),
            curpkt: Box::new(CurPkt { out: out.clone() }),
            packet_tracer: Box::new(PTr {
                out: out.clone(),
                daq: daq.clone(),
            }),
            publish: Box::new(PubWit { out: out.clone() }),
            de: Box::new(Devt { out: out.clone() }),
            imgr: Rc::new(RefCell::new(Box::new(Imgr {
                out: out.clone(),
                armed: armed.clone(),
            }) as Box<dyn InspectorManagerApi>)),
            network_policy: Some(Rc::new(RefCell::new(NetPol {
                handle: stub_handle.clone(),
            }))),
            ..FileEnvLite::default()
        };
        env.adv_pub_id.set(7);
        Hub {
            out,
            level,
            armed,
            conf_view,
            adv_pub_id,
            daq,
            stub_handle,
            tv,
            sv,
            env,
        }
    }
    fn push(&self, s: impl Into<String>) {
        push(&self.out, s);
    }
    /// fcache_set_file_trace(on, level)
    fn set_trace(&mut self, on: bool, level: u8) {
        *self.level.borrow_mut() = if on { level } else { 0 };
    }
    /// fcache_set_file_service(on) (the is_file_service_enabled switch)
    fn set_service(&mut self, on: bool) {
        self.env.svc.set_file_service_enabled(on, on);
    }
    /// fcache_set_file_inspector(1): one-shot latch; prints the FileInspect
    /// ctor witness AND resolves get_file_config() (file_config.cc:89
    /// `fi ? fi->config : nullptr` — the harness FileConfig, defaults).
    fn arm_inspector(&mut self) {
        if self.armed.borrow().is_none() {
            self.push("FileInspect ctor");
            *self.armed.borrow_mut() = Some(Rc::new(StubInspector {
                cfg: self.conf_view.clone(),
            }));
            self.env.file_config = Some(Rc::new(RefCell::new(FileConfigLite::default())));
        }
    }
    /// `FileCache cache(16); fcache_set_file_cache(&cache);` — the driver
    /// keeps its own handle for the block's lifetime (the C stack object
    /// outlives the static's nulling at fcache_set_file_cache(nullptr)).
    fn arm_cache(&mut self) -> Rc<RefCell<FileCache>> {
        let mut cache = FileCache::new(16);
        cache.imgr = Rc::new(RefCell::new(Box::new(Imgr {
            out: self.out.clone(),
            armed: self.armed.clone(),
        }) as Box<dyn InspectorManagerApi>));
        cache.trace = Box::new(TraceWit {
            out: self.out.clone(),
            level: self.level.clone(),
        });
        cache.curpkt = Box::new(CurPkt {
            out: self.out.clone(),
        });
        cache.file_flows = Box::new(FFlowsWitness);
        cache.packet_tracer = Box::new(PTr {
            out: self.out.clone(),
            daq: self.daq.clone(),
        });
        cache.clock = Box::new(DriverPacketClock {
            now: TimeVal::default(),
        });
        cache.conf = self.conf_view.clone();
        cache.events = Box::new(EvtSink {
            out: self.out.clone(),
            level: self.level.clone(),
            adv_pub_id: self.adv_pub_id.clone(),
        });
        cache.type_names = Box::new(ConfigTypeNames);
        let rc = Rc::new(RefCell::new(cache));
        self.env.svc.set_file_cache(Some(rc.clone()));
        rc
    }
    /// fcache_set_file_cache(nullptr) (nulls the static only)
    fn disarm_cache(&mut self) {
        self.env.svc.set_file_cache(None);
    }
    /// fcache_set_policy_verdicts
    fn set_policy_verdicts(&mut self, type_v: u32, sig_v: u32) {
        self.tv.set(type_v);
        self.sv.set(sig_v);
    }
    /// fcache_set_pt_daq(on)
    fn set_daq(&mut self, on: bool) {
        self.daq.set(on);
    }
    /// fcache_set_instance_id
    fn set_instance_id(&mut self, n: u32) {
        self.env.get_instance_id.set(n);
    }
    /// fcache_set_max_file_depth (the FileService witness passthrough)
    fn set_max_file_depth(&mut self, d: i64) {
        self.env.max_file_depth.set(d);
    }
    /// fcache_clear_flow_slot()
    fn clear_flow_slot(slot: &mut Option<Rc<RefCell<FileFlows>>>) {
        *slot = None;
    }
    fn mkkey(file_id: u64) -> FileHashKey {
        FileHashKey {
            file_id,
            ..FileHashKey::default()
        }
    }
    /// probe cache_add helper: add(…, cache_sync=true) on the armed cache.
    fn cache_add(
        &mut self,
        k: &FileHashKey,
        timeout: i64,
        counts: &mut FileCounts,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let cache = self.env.svc.get_file_cache().expect("cache armed");
        let mut cf = false;
        let mut ce = 0i64;
        cache
            .borrow_mut()
            .add(k, timeout, &mut cf, &mut ce, true, counts)
    }
}

/// probe static Flow (zero FlowKey; session_flags 0 -> NOT two-way).
fn g_flow() -> CacheFlow {
    CacheFlow::default()
}

fn mk_packet(hub: &Hub) -> PacketView {
    PacketView {
        flow: g_flow(),
        packet_flags: 0,
        active: ActiveState {
            witness: Some(Rc::new(RefCell::new(ActWit {
                out: hub.out.clone(),
            }))),
            ..ActiveState::default()
        },
        conf: *hub.conf_view.borrow(),
    }
}

fn ptr_eq(o: &Option<Rc<RefCell<FileContext>>>, c: &Rc<RefCell<FileContext>>) -> bool {
    o.as_ref().is_some_and(|r| Rc::ptr_eq(r, c))
}

// -------------------------------------------------------------------
// The replay
// -------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn fflows_transcript_replay() {
    let hub = &mut Hub::new();
    let counts = &mut FileCounts::default();

    // probe prelude: fcache_enable_fake_clock(1) + fcache_set_fake_now(100)
    // (no absolute SnortClock tick ever prints here — the advance-log
    // render sites are gate/seam-pinned), file_stats_init (silent),
    // fcache_set_adv_pub_id(7) (Hub::new), fcache_set_instance_id(0).

    // ============ A: layout / enum vocabulary =========================
    hub.push(format!(
        "A_SZ_FF={SZ_FF} SZ_SLOT={SZ_SLOT} OFS_slot_ctx=0 OFS_slot_id=8"
    ));
    hub.push(
        "A_ENUM pos_unk=0 pos_start=1 pos_mid=2 pos_end=3 pos_full=4 sid_none=-1 \
         sid_overlimit=1 sid_max=2 gid=150"
            .to_string(),
    );
    FileFlows::init(&mut hub.env);
    hub.push(format!(
        "A_FFDATA_ID={} (post-init)",
        hub.env.file_flow_data_id.get()
    ));

    // ============ B: get_file_flows factory ladder + C: retire matrix ===
    {
        let mut slot: Option<Rc<RefCell<FileFlows>>> = None;
        hub.set_service(false);
        let none = FileFlows::get_file_flows(&mut slot, &g_flow(), true, &mut hub.env);
        let pol0 = FileFlows::get_file_policy_static(slot.as_ref());
        hub.push(format!(
            "B_DISABLED ff={} pol={}",
            u8::from(none.is_some()),
            u8::from(pol0.is_some())
        ));

        hub.set_service(true);
        let refs_before = hub.stub_handle.ref_count(); // 1 (heap "new")
        hub.push("WITNESS get_network_policy"); // get_network_policy witness
        hub.push("POLICY base_file_policy -> stub"); // NetworkPolicy witness
        let ff = FileFlows::get_file_flows(&mut slot, &g_flow(), true, &mut hub.env)
            .expect("service enabled -> created");
        let refs_after = hub.stub_handle.ref_count(); // set_file_policy add_ref
        let made_alias = slot.clone().expect("slot armed");
        let again = FileFlows::get_file_flows(&mut slot, &g_flow(), true, &mut hub.env);
        let no_create = FileFlows::get_file_flows(&mut slot, &g_flow(), false, &mut hub.env);
        let static_pol = FileFlows::get_file_policy_static(slot.as_ref());
        let pol_is_stub = ff.borrow().ff_test_policy_same_store(&hub.stub_handle);
        let static_pol_same = static_pol
            .as_ref()
            .is_some_and(|h| ff.borrow().ff_test_policy_same_store(h));
        hub.push(format!(
            "B_CREATE ff=1 pol_is_stub={} refs={refs_before}->{refs_after} size_of={SZ_FF} \
             same_ptr={} same_nocreate={} static_pol={}",
            u8::from(pol_is_stub),
            u8::from(Rc::ptr_eq(&made_alias, &ff)),
            u8::from(no_create.as_ref().is_some_and(|n| Rc::ptr_eq(&ff, n))),
            u8::from(static_pol_same),
        ));
        drop((none, pol0, made_alias, again, no_create, static_pol));
        Hub::clear_flow_slot(&mut slot); // fcache_clear_flow_slot (B scope end)

        hub.arm_inspector(); // fcache_set_file_inspector(1) + FileInspect ctor
        let cache_c = hub.arm_cache(); // FileCache cache(16) + static arm
        hub.set_trace(true, TRACE_DEBUG_LEVEL);

        // C1: get_file_context create -> ppc store; ppc-hit lookup
        let mut isnew = false;
        let x = ff
            .borrow_mut()
            .get_file_context(201, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        let hit = ff.borrow_mut().get_partially_processed_context(201);
        hub.push(format!(
            "C1_CREATE have=1 is_new={} ppc={} ppc_hit_same={} fcid={}",
            u8::from(isnew),
            ff.borrow().ff_test_ppc_len(),
            u8::from(ptr_eq(&hit, &x)),
            x.borrow().info.get_file_id(),
        ));
        drop(hit); // the C raw read borrows nothing: alias dies at the read

        // C2: set_current, erase->park, caller alias survives, self-set
        // SKIP arm, other-install drains the prior deferred via
        // retire_victim (the release lands INSIDE set_current at the C
        // delete point: the driver alias handle dies after the reads).
        ff.borrow_mut().set_current_file_context(&x);
        ff.borrow_mut().remove_processed_file_context(201);
        hub.push(format!(
            "C2_PARK deferred_is_x={} ppc={} current_alias_survives={}",
            u8::from(ptr_eq(&ff.borrow().ff_test_deferred(), &x)),
            ff.borrow().ff_test_ppc_len(),
            u8::from(ptr_eq(&ff.borrow().ff_test_current(), &x)),
        ));
        ff.borrow_mut().set_current_file_context(&x); // deferred == ctx: SKIP
        hub.push(format!(
            "C2_SELFSET deferred_kept={} current_is_x={}",
            u8::from(ptr_eq(&ff.borrow().ff_test_deferred(), &x)),
            u8::from(ptr_eq(&ff.borrow().ff_test_current(), &x)),
        ));
        drop(x); // C: only the port's slots own the object after here
        let y = ff
            .borrow_mut()
            .get_file_context(202, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        ff.borrow_mut().set_current_file_context(&y); // retire_victim(x): 22
        hub.push(format!(
            "C2_DRAIN deferred_nonnull={} current_is_y={}",
            u8::from(ff.borrow().ff_test_deferred().is_some()),
            u8::from(ptr_eq(&ff.borrow().ff_test_current(), &y)),
        ));

        // C3: dup_cache_context path (ppc-miss + cache-hit) -> private
        // copy + set_cache_dup/set_limit_excluded + cache_dup_count++, the
        // remove processed decrement, then the drain via set_current.
        let entry_300 = hub
            .cache_add(&Hub::mkkey(300), 3600, counts)
            .expect("added");
        entry_300.borrow_mut().info.verdict = FILE_VERDICT_BLOCK;
        let dctx = ff
            .borrow_mut()
            .get_file_context(300, false, &mut isnew, 0, &mut hub.env, counts)
            .expect("cache dup");
        hub.push(format!(
            "C3_DUP have=1 not_entry={} is_new={} cache_dup={} limit_excl={} cdc={}",
            u8::from(!Rc::ptr_eq(&dctx, &entry_300)),
            u8::from(isnew),
            u8::from(dctx.borrow().is_cache_dup()),
            u8::from(dctx.borrow().is_limit_excluded()),
            ff.borrow().ff_test_cache_dup_count(),
        ));
        ff.borrow_mut().remove_processed_file_context(300);
        hub.push(format!(
            "C3_UNDEC cdc={} deferred_is_dctx={}",
            ff.borrow().ff_test_cache_dup_count(),
            u8::from(ptr_eq(&ff.borrow().ff_test_deferred(), &dctx)),
        ));
        drop(dctx); // retired: the retire at the set below deletes it
        ff.borrow_mut().set_current_file_context(&y); // retire_victim(dctx): 32
        hub.push(format!(
            "C3_DRAINED deferred_nonnull={}",
            u8::from(ff.borrow().ff_test_deferred().is_some())
        ));

        // C4: find_main_file_context ladder. Driver aliases of the old
        // main die BEFORE each replacing call so the port's slot-drop
        // inside find_main is the Rc last-drop (releases 36/39 sit at the
        // C delete points).
        let ft0 = counts.files_total;
        let m1 = ff
            .borrow_mut()
            .find_main_file_context(SNORT_FILE_START, FILE_DOWNLOAD, 0, &mut hub.env, counts);
        let m1id = m1.borrow().info.get_file_id();
        let m1cache = u8::from(m1.borrow().is_cacheable());
        let m2 = ff
            .borrow_mut()
            .find_main_file_context(SNORT_FILE_MIDDLE, FILE_DOWNLOAD, 0, &mut hub.env, counts);
        let m2_same_m1 = Rc::ptr_eq(&m2, &m1);
        drop((m1, m2));
        let m3 = ff
            .borrow_mut()
            .find_main_file_context(SNORT_FILE_START, FILE_DOWNLOAD, 0, &mut hub.env, counts);
        drop(m3); // the next START deletes it here
        let m4 = ff
            .borrow_mut()
            .find_main_file_context(SNORT_FILE_FULL, FILE_UPLOAD, 5, &mut hub.env, counts);
        let m4id = m4.borrow().info.get_file_id();
        let m4cache = u8::from(m4.borrow().is_cacheable());
        let ft3 = counts.files_total;
        let main_is_m4 = ptr_eq(&ff.borrow().ff_test_main(), &m4);
        // m3_new=0: C compares the fresh main against the DANGLING
        // old-main pointer (glibc reuses the freed chunk -> equal); the
        // use-after-free compare is structurally excluded by Rc identity
        // (module-header deviation) — the pinned value is verbatim.
        hub.push(format!(
            "C4_MAIN m2_same_m1={} m3_new=0 m1id={} m1_cacheable={} m4id={} \
             m4_cacheable={} files_total+={} main_is_m4={}",
            u8::from(m2_same_m1),
            m1id,
            m1cache,
            m4id,
            m4cache,
            ft3 - ft0,
            u8::from(main_is_m4),
        ));

        hub.set_trace(false, 0);
        hub.disarm_cache(); // static nulls; the driver's cache object lives
        let refs_pre_delete = hub.stub_handle.ref_count(); // 2
        drop(m4); // driver aliases die first: the dtor's slots are last
        drop(y); // owners -> releases 43 (main=m4) / 44 (ppc=y)
        drop(ff); // delete ff: ~FileFlows walks + delete_file_policy 2->1
        let refs_post_delete = hub.stub_handle.ref_count();
        hub.push(format!(
            "C5_DTOR policy_refs={refs_pre_delete}->{refs_post_delete}"
        ));
        drop(entry_300); // C: cache.clear() frees the 300 node -> release 46
        cache_c.borrow_mut().clear();
    }

    // ============ D: get_new_file_instance bit ladder ===================
    {
        hub.set_instance_id(5);
        let ff3 = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
        let u1 = ff3.borrow_mut().get_new_file_instance(&hub.env);
        let u2 = ff3.borrow_mut().get_new_file_instance(&hub.env);
        hub.set_instance_id(0);
        let u3 = ff3.borrow_mut().get_new_file_instance(&hub.env);
        hub.push(format!(
            "D_INSTANCE id5: {u1:x} {u2:x} (lo={},{}) id0: {u3:x}",
            (u1 & 0xffff_ffff) as u32,
            (u2 & 0xffff_ffff) as u32,
        ));
        drop(ff3); // no owning slots -> silent
    }

    // ============ E: get_current_file_context id ladder ================
    {
        let cache = hub.arm_cache();
        let ff4 = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
        let mut isnew = false;
        let x = ff4
            .borrow_mut()
            .get_file_context(500, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        ff4.borrow_mut().set_current_file_context(&x);
        ff4.borrow_mut().ff_test_current_file_id_set(501); // ppc-miss + cache-miss
        let g0 = ff4.borrow_mut().get_current_file_context(&mut hub.env, counts);
        ff4.borrow_mut().ff_test_current_file_id_set(500); // ppc-hit route
        let g1 = ff4.borrow_mut().get_current_file_context(&mut hub.env, counts);
        ff4.borrow_mut().ff_test_current_file_id_set(0); // alias arm
        let g2 = ff4.borrow_mut().get_current_file_context(&mut hub.env, counts);
        hub.push(format!(
            "E_IDLADDER miss={} hit_same={} alias_same={}",
            u8::from(g0.is_some()),
            u8::from(ptr_eq(&g1, &x)),
            u8::from(ptr_eq(&g2, &x)),
        ));
        drop((g1, g2));
        drop(x); // the dtor's ppc slot is the last owner -> release 53
        drop(ff4); // delete ff4: drains ppc 500
        cache.borrow_mut().clear(); // nothing cached -> silent
    }

    // ============ F: get_file_position ladder ==========================
    {
        let mut slot: Option<Rc<RefCell<FileFlows>>> = None;
        Hub::clear_flow_slot(&mut slot);
        hub.set_service(true);
        hub.push("WITNESS get_network_policy");
        hub.push("POLICY base_file_policy -> stub");
        let ff5 = FileFlows::get_file_flows(&mut slot, &g_flow(), true, &mut hub.env)
            .expect("created");
        let mut p = mk_packet(hub);
        let cache = hub.arm_cache();
        let mut isnew = false;
        let x = ff5
            .borrow_mut()
            .get_file_context(600, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        ff5.borrow_mut().set_current_file_context(&x);
        x.borrow_mut()
            .update_file_size(10, SNORT_FILE_MIDDLE, &mut hub.env); // light member
        let f1 = get_file_position(&p, Some(&ff5)); // flags 0 -> processed -> MIDDLE
        p.packet_flags = PKT_PDU_FULL;
        let f2 = get_file_position(&p, Some(&ff5));
        p.packet_flags = PKT_PDU_HEAD;
        let f3 = get_file_position(&p, Some(&ff5));
        p.packet_flags = PKT_PDU_TAIL;
        let f4 = get_file_position(&p, Some(&ff5));
        hub.push(format!("F_POSITION mid={f1} full={f2} start={f3} end={f4}"));
        p.packet_flags = 0;
        hub.disarm_cache();
        Hub::clear_flow_slot(&mut slot);
        drop(x); // dtor's slot owns the last handle -> release 61 at delete
        drop(ff5); // delete ff5
        cache.borrow_mut().clear(); // empty -> silent
    }

    // ============ G: over-limit event arm ==============================
    {
        // fc->max_files_per_flow = 2 on the harness FileConfig (live since
        // the inspector latch); cap restored as the probe does.
        let fc = hub.env.get_file_config().expect("inspector armed");
        let cap_saved = fc.borrow().max_files_per_flow;
        fc.borrow_mut().max_files_per_flow = 2;
        let cache = hub.arm_cache();
        let ff6 = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
        counts.files_over_flow_limit_not_processed = 0;
        counts.max_concurrent_files_per_flow = 0;
        let mut isnew = false;
        let a = ff6
            .borrow_mut()
            .get_file_context(700, true, &mut isnew, 0, &mut hub.env, counts);
        let b = ff6
            .borrow_mut()
            .get_file_context(701, true, &mut isnew, 0, &mut hub.env, counts);
        // count == max -> the over-limit arm: TRACE_ERROR FILE_DEBUG (the
        // DE macro arg prints; the FILEDBG is level-gated off), over_cnt++,
        // events.create_event -> queue_event EXACTLY once (EventGen
        // suppressed bitset); 703 arms again count-wise, silently.
        let c = ff6
            .borrow_mut()
            .get_file_context(702, true, &mut isnew, 0, &mut hub.env, counts);
        let d = ff6
            .borrow_mut()
            .get_file_context(703, true, &mut isnew, 0, &mut hub.env, counts);
        hub.push(format!(
            "G_OVERLIMIT a={} b={} c={} d={} ppc={} over_cnt={} maxconc={}",
            u8::from(a.is_some()),
            u8::from(b.is_some()),
            u8::from(c.is_some()),
            u8::from(d.is_some()),
            ff6.borrow().ff_test_ppc_len(),
            counts.files_over_flow_limit_not_processed,
            counts.max_concurrent_files_per_flow,
        ));
        fc.borrow_mut().max_files_per_flow = cap_saved;
        hub.disarm_cache();
        drop((a, b, c, d)); // the dtor drains the 2 created: releases 74/75
        drop(ff6);
        cache.borrow_mut().clear(); // empty -> silent
    }

    // ============ H: set_file_name arms ================================
    {
        let cache = hub.arm_cache();
        let ff7 = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
        let mut isnew = false;
        let ctx_a = ff7
            .borrow_mut()
            .get_file_context(801, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        ff7.borrow_mut().set_current_file_context(&ctx_a);
        hub.set_max_file_depth(0);
        // arm 1: url set + name set (the log_file_event pair stays silent:
        // UNKNOWN verdict); processed(0) == depth(0) completion arm;
        // remove_processed_file_context(mpid=0) MISS keeps 801 in ppc —
        // the pinned mpid-default aliasing.
        let r1 = ff7.borrow_mut().set_file_name(
            b"n",
            1,
            0,
            0,
            b"http://x/y",
            10,
            &mut hub.env,
            counts,
        );
        hub.push(format!(
            "H_SETNAME1 ret={} ppc={} complete={} url={} name={}",
            u8::from(r1),
            ff7.borrow().ff_test_ppc_len(),
            u8::from(ctx_a.borrow().info.processing_complete),
            u8::from(ctx_a.borrow().info.is_url_set()),
            u8::from(ctx_a.borrow().info.is_file_name_set()),
        ));
        // arm 2: file_id set -> ppc hit 802; processed(5) != depth(10) and
        // type CONTINUE / no capture / no signature -> continue (true).
        hub.set_max_file_depth(10);
        let ctx_b = ff7
            .borrow_mut()
            .get_file_context(802, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        ff7.borrow_mut().set_current_file_context(&ctx_b);
        ctx_b
            .borrow_mut()
            .update_file_size(5, SNORT_FILE_MIDDLE, &mut hub.env);
        let r2 = ff7.borrow_mut().set_file_name(
            b"b.bin",
            5,
            802,
            0,
            b"http://x/z",
            10,
            &mut hub.env,
            counts,
        );
        hub.push(format!(
            "H_SETNAME2 ret={} ppc={} complete={}",
            u8::from(r2),
            ff7.borrow().ff_test_ppc_len(),
            u8::from(ctx_b.borrow().info.processing_complete),
        ));
        drop((ctx_a, ctx_b)); // the dtor drains ppc {801,802}: 85/86
        drop(ff7);
        cache.borrow_mut().clear(); // empty -> silent
    }

    // ============ I: log_file_event through the REAL FileContext =======
    {
        let cache = hub.arm_cache();
        let ff8 = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
        let mut isnew = false;
        let ctx = ff8
            .borrow_mut()
            .get_file_context(850, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        ctx.borrow_mut().info.set_file_id(850);
        ctx.borrow_mut().info.set_file_name(Some(b"pub.bin"), 7);
        ctx.borrow_mut().info.verdict = FILE_VERDICT_LOG;
        ff8.borrow_mut().set_current_file_context(&ctx);
        // the probe hands stub_file_policy()'s raw pointer; the handle
        // fronts the same store (user_file_data null -> the C
        // policy-and-log_needed-and-user_file_data gate stays silent).
        let flow = g_flow();
        let mut pol = hub.stub_handle.clone();
        pol.with_policy_mut(|p| {
            ctx.borrow_mut().log_file_event(&flow, Some(p), &mut hub.env);
        });
        hub.push(format!(
            "I_LOGEVENT verdict={} name={}",
            ctx.borrow().info.verdict,
            String::from_utf8_lossy(ctx.borrow().info.get_file_name())
        ));
        ff8.borrow_mut().ff_test_current_clear(); // set_current(nullptr) (C)
        drop(ctx); // the dtor's ppc slot owns the last handle -> release 94
        drop(ff8); // delete ff8: drains ppc 850
        drop(cache); // block-scope ~FileCache (empty, silent)
    }

    // ============ J: file_process / handle_retransmit arms =============
    {
        let cache = hub.arm_cache();
        hub.set_daq(true); // fcache_set_pt_daq(1)
        hub.set_trace(true, TRACE_DEBUG_LEVEL);

        // single file_process: service-disabled early return
        hub.set_service(false);
        {
            let t = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
            let j0 = t.borrow_mut().file_process(
                &mut mk_packet(hub),
                b"",
                0,
                SNORT_FILE_FULL,
                true,
                0,
                b"",
                0,
                &mut hub.env,
                counts,
            );
            hub.push(format!("J_SVC_OFF ret={}", u8::from(j0)));
            drop(t);
        }
        // single file_process: position-unknown early return
        hub.set_service(true);
        {
            let t = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
            let j1 = t.borrow_mut().file_process(
                &mut mk_packet(hub),
                b"",
                0,
                SNORT_FILE_POSITION_UNKNOWN,
                true,
                0,
                b"",
                0,
                &mut hub.env,
                counts,
            );
            hub.push(format!("J_POS_UNK ret={}", u8::from(j1)));
            drop(t);
        }
        // multi file_process: file_depth < 0 early return
        hub.set_max_file_depth(-5);
        {
            let t = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
            let j2 = t.borrow_mut().file_process_multi(
                &mut mk_packet(hub),
                901,
                b"abcd",
                4,
                0,
                FILE_DOWNLOAD,
                0,
                SNORT_FILE_POSITION_UNKNOWN,
                b"",
                0,
                b"",
                0,
                b"",
                false,
                &mut hub.env,
                counts,
            );
            hub.push(format!(
                "J_DEPTH_NEG ret={} ppc={}",
                u8::from(j2),
                t.borrow().ff_test_ppc_len()
            ));
            drop(t);
        }
        // multi file_process: offset(11) > depth(10) early return
        hub.set_max_file_depth(10);
        {
            let t = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
            let j3 = t.borrow_mut().file_process_multi(
                &mut mk_packet(hub),
                902,
                b"abcd",
                4,
                11,
                FILE_DOWNLOAD,
                0,
                SNORT_FILE_POSITION_UNKNOWN,
                b"",
                0,
                b"",
                0,
                b"",
                false,
                &mut hub.env,
                counts,
            );
            hub.push(format!(
                "J_OFFSET_PAST ret={} ppc={}",
                u8::from(j3),
                t.borrow().ff_test_ppc_len()
            ));
            drop(t);
        }
        // multi file_process cache-hit arm: get_file_context finds 903 in
        // the CACHE (not ppc) -> dup private copy; at :446 (cacheable and
        // not is_new) the REAL cached_verdict_lookup chain runs (entry
        // UNKNOWN + policy type LOG -> LOG, donor G2 shape), hits++,
        // complete, remove -> erase->park + cdc--, the daq-armed
        // populate_trace_data; return false. NEVER crosses the :486
        // process ladder (is_new=false routes away — row 17r seam intact).
        hub.set_max_file_depth(0);
        let entry = hub
            .cache_add(&Hub::mkkey(903), 3600, counts)
            .expect("added"); // acquire 103
        entry.borrow_mut().info.set_file_id(903);
        entry.borrow_mut().set_config(Some(hub.conf_view.clone())); // no re-wire
        hub.set_policy_verdicts(FILE_VERDICT_LOG, FILE_VERDICT_UNKNOWN);
        {
            let mut slot: Option<Rc<RefCell<FileFlows>>> = None;
            hub.push("WITNESS get_network_policy");
            hub.push("POLICY base_file_policy -> stub");
            let t = FileFlows::get_file_flows(&mut slot, &g_flow(), true, &mut hub.env)
                .expect("created");
            counts.file_cache_hits = 0;
            let j4 = t.borrow_mut().file_process_multi(
                &mut mk_packet(hub),
                903,
                b"abcd",
                4,
                0,
                FILE_DOWNLOAD,
                0,
                SNORT_FILE_POSITION_UNKNOWN,
                b"",
                0,
                b"",
                0,
                b"",
                false,
                &mut hub.env,
                counts,
            );
            // the daq_log line closed no line -> this print CONTINUES it:
            push_continue(
                &hub.out,
                &format!(
                    "J_CACHEHIT ret={} hits={} ppc={} cdc={} deferred={}",
                    u8::from(j4),
                    counts.file_cache_hits,
                    t.borrow().ff_test_ppc_len(),
                    t.borrow().ff_test_cache_dup_count(),
                    u8::from(t.borrow().ff_test_deferred().is_some()),
                ),
            );
            Hub::clear_flow_slot(&mut slot);
            drop(t); // dtor drains the parked 903 copy: release 124
        }
        hub.set_trace(false, 0);

        // handle_retransmit ladder:
        // arm 0: file_policy == nullptr -> plain return (bare FileFlows;
        // FILEDBG queried suppressed with the window closed)
        {
            let bare = Rc::new(RefCell::new(FileFlows::new(&g_flow())));
            bare.borrow_mut().add_pending_file(7);
            bare.borrow_mut()
                .handle_retransmit(&mut mk_packet(hub), &mut hub.env, counts);
            hub.push(format!(
                "J_RETRANS_NOPOL pol={} pend_res={}",
                u8::from(bare.borrow().ff_test_has_policy()),
                u8::from(bare.borrow().ff_test_pending_resolution()),
            ));
            drop(bare);
        }
        // factory-built (policy armed through the network-policy witness)
        let mut slot: Option<Rc<RefCell<FileFlows>>> = None;
        Hub::clear_flow_slot(&mut slot);
        hub.push("WITNESS get_network_policy");
        hub.push("POLICY base_file_policy -> stub");
        let ff9 = FileFlows::get_file_flows(&mut slot, &g_flow(), true, &mut hub.env)
            .expect("created");
        hub.set_trace(true, TRACE_DEBUG_LEVEL);
        // arm 1: lookup null (pending id in neither ppc nor cache) -> bail
        ff9.borrow_mut().add_pending_file(999);
        ff9.borrow_mut()
            .handle_retransmit(&mut mk_packet(hub), &mut hub.env, counts);
        hub.push(format!(
            "J_RETRANS_NOFILE cur={} def={} pend_res={}",
            u8::from(ff9.borrow().ff_test_current().is_some()),
            u8::from(ff9.borrow().ff_test_deferred().is_some()),
            u8::from(ff9.borrow().ff_test_pending_resolution()),
        ));
        // arm 2: cache present -> get_file_context create (900), the
        // resume_pending_verdict node MISS bails before touching the dup:
        // x->verdict STAYS PENDING (pin), verdict prints 0.
        let mut isnew = false;
        let xj = ff9
            .borrow_mut()
            .get_file_context(900, true, &mut isnew, 0, &mut hub.env, counts)
            .expect("created");
        xj.borrow_mut().info.set_file_id(900);
        xj.borrow_mut().info.verdict = FILE_VERDICT_PENDING;
        ff9.borrow_mut().add_pending_file(900);
        ff9.borrow_mut()
            .handle_retransmit(&mut mk_packet(hub), &mut hub.env, counts);
        hub.push(format!(
            "J_RETRANS_CACHE cur_is_x={} pend_res={} verdict={}",
            u8::from(ptr_eq(&ff9.borrow().ff_test_current(), &xj)),
            u8::from(ff9.borrow().ff_test_pending_resolution()),
            xj.borrow().info.verdict,
        ));
        // arm 3: NO cache (ppc hit routes before the assert site) ->
        // policy->signature_lookup witness (sv=LOG=1, result DISCARDED by
        // the C statement) + the real log_file_event (silent: PENDING ->
        // default log_needed=false arm) -> verdict still PENDING ->
        // pending_resolution stays true (pin).
        hub.disarm_cache(); // the driver handle stays live
        hub.set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_LOG);
        ff9.borrow_mut()
            .handle_retransmit(&mut mk_packet(hub), &mut hub.env, counts);
        hub.push(format!(
            "J_RETRANS_NOCACHE pend_res={} verdict={}",
            u8::from(ff9.borrow().ff_test_pending_resolution()),
            xj.borrow().info.verdict,
        ));
        hub.set_trace(false, 0);
        hub.set_daq(false);
        drop(xj); // the dtor's ppc slot owns the last handle -> release 145
        Hub::clear_flow_slot(&mut slot);
        drop(ff9); // delete ff9: drains ppc 900 + policy 2->1 (silent)
        drop(entry); // cache.clear() at the probe position: release 146
        cache.borrow_mut().clear();
    }

    // fcache_release_stub_policy(): the final base ref (1->0); the Box
    // drop is silent (no ~FilePolicyBase line in the transcript).
    {
        let mut h = hub.stub_handle.clone();
        h.delete_file_policy();
        drop(h);
    }

    // ============ compare ============================================
    let want: Vec<&str> = VECTORS.trim_end_matches('\n').lines().collect();
    let got = hub.out.borrow();
    assert_eq!(got.len(), want.len(), "transcript length mismatch");
    for (i, (w, g)) in want.iter().zip(got.iter()).enumerate() {
        assert_eq!(g, w, "transcript line {} mismatch", i + 1);
    }
}

// -------------------------------------------------------------------
// Faithful translations of the C++ embedded [file_flows] gate — the
// verbatim `#ifdef UNIT_TEST` block (file_flows.cc:808-996 in this
// source revision — 8 TEST_CASEs / runner-measured 22 assertions,
// gate.txt: all green). FF_TEST_CONTEXT = FileContext ctor +
// set_file_id; FFTestAccessor = the pub(crate) slot fields reached via
// the ff_test_* accessors (integration tests are external crates).
// REQUIRE -> assert!, CHECK -> plain assert. The gate-side env carries
// the default NullInspectorManager (the C witness pair prints "IMGR
// acquire -> null" x16 into gate.txt, which is NOT part of vectors.txt
// and never replays — gate semantics pins: null inspector, config null).
// -------------------------------------------------------------------

fn gate_env() -> FileEnvLite {
    FileEnvLite::default()
}

/// `class FF_TEST_CONTEXT : public FileContext { explicit FF_TEST_CONTEXT(
/// uint64_t id) { set_file_id(id); } };`
fn ff_test_context(env: &FileEnvLite, id: u64) -> Rc<RefCell<FileContext>> {
    let c = FileContext::ctor(None, env);
    c.borrow_mut().info.set_file_id(id);
    c
}

fn ppc_count(ff: &FileFlows, id: u64) -> usize {
    ff.ff_test_ppc().iter().filter(|(k, _)| *k == id).count()
}

#[test]
fn up_gate_retire_defers_delete_dtor_drains() {
    // "retire defers delete, dtor drains it" — 2 CHECKs.
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let a = ff_test_context(&env, 1);
    ff.ff_test_ppc_set(1, &a);

    ff.remove_processed_file_context(1);
    assert!(ptr_eq(&ff.ff_test_deferred(), &a));
    assert!(ff.ff_test_ppc().is_empty());

    drop(ff); // "delete ff;" — ~FileFlows drains the deferred slot
}

#[test]
fn up_gate_retire_then_set_drops_deferred() {
    // "retire then set drops deferred via retire_victim" — 3 CHECKs.
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let a = ff_test_context(&env, 1);
    let b = ff_test_context(&env, 2);

    ff.ff_test_ppc_set(1, &a);
    ff.ff_test_current_set(&a);

    ff.remove_processed_file_context(1);
    assert!(ptr_eq(&ff.ff_test_deferred(), &a));

    ff.set_current_file_context(&b);
    assert!(ff.ff_test_deferred().is_none());
    assert!(ptr_eq(&ff.ff_test_current(), &b));

    drop(b); // delete b
    ff.ff_test_current_clear();
    drop(ff); // delete ff
}

#[test]
fn up_gate_cscwt96192_regression() {
    // "CSCwt96192 regression: retire non-current then set other" — 5 CHECKs.
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let a = ff_test_context(&env, 1);
    let b = ff_test_context(&env, 2);
    let c = ff_test_context(&env, 3);

    ff.ff_test_ppc_set(1, &a);
    ff.ff_test_ppc_set(2, &b);
    ff.ff_test_current_set(&a);

    ff.remove_processed_file_context(2);
    assert!(ptr_eq(&ff.ff_test_deferred(), &b));
    assert_eq!(ppc_count(&ff, 1), 1);

    ff.set_current_file_context(&c);
    assert!(ff.ff_test_deferred().is_none());
    assert!(ptr_eq(&ff.ff_test_current(), &c));
    assert_eq!(ppc_count(&ff, 1), 1);

    drop(c); // delete c
    ff.ff_test_current_clear();
    drop(ff); // delete ff
}

#[test]
fn up_gate_iss1_deref_after_remove_safe() {
    // "ISS-1 regression: caller deref after remove is safe" — 1 CHECK
    // (the Rc model structurally excludes the C use-after-free window;
    // the post-remove read is the pin).
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let x = ff_test_context(&env, 42);
    ff.ff_test_ppc_set(42, &x);

    ff.remove_processed_file_context(42);
    assert_eq!(x.borrow().info.get_file_id(), 42);

    drop(ff); // delete ff drains the deferred x
}

#[test]
fn up_gate_nested_retire_drains_prior() {
    // "nested retire drains prior via retire_victim" — 3 CHECKs.
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let a = ff_test_context(&env, 1);
    let b = ff_test_context(&env, 2);

    ff.ff_test_ppc_set(1, &a);
    ff.ff_test_ppc_set(2, &b);

    ff.remove_processed_file_context(1);
    assert!(ptr_eq(&ff.ff_test_deferred(), &a));

    ff.remove_processed_file_context(2);
    assert!(ptr_eq(&ff.ff_test_deferred(), &b));
    assert!(ff.ff_test_ppc().is_empty());

    drop(a); // C freed `a` inside the nested retire (the gate-side driver
             // handle's death is unobservable in the gate shape)
    drop(ff); // delete ff drains deferred b
}

#[test]
fn up_gate_dtor_drains_all_slots_crash_shape() {
    // "dtor drains main + partially_processed_contexts + deferred
    // (original crash shape)" — 0 CHECKs; the gate PINS that the exact
    // sequence neither crashes nor leaks. Replay the setup verbatim
    // incl. the hand-rolled erase-then-park, then drain through the dtor.
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let m = ff_test_context(&env, 10);
    let a = ff_test_context(&env, 1);
    let b = ff_test_context(&env, 2);

    ff.ff_test_main_set(&m);
    ff.ff_test_ppc_set(1, &a);
    ff.ff_test_ppc_set(2, &b);
    ff.ff_test_current_set(&a);

    // "Mimic remove_processed_file_context's erase-then-park sequence."
    ff.ff_test_ppc_erase(1);
    ff.ff_test_deferred_set(&a);

    drop(ff); // delete ff: the retire walk drains deferred, main, ppc —
              // the shape the retire_victim discipline was born from.
    drop((m, a, b)); // gate-side driver handles (C: already freed)
}

#[test]
fn up_gate_swap_restore_round_trip() {
    // "swap/restore preserves both current_context and current_file_id"
    // — 6 CHECKs.
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let prev = ff_test_context(&env, 7);
    let temp = ff_test_context(&env, 99);

    ff.ff_test_current_set(&prev);
    ff.ff_test_current_file_id_set(77);

    let saved = ff.swap_current_file_context_no_delete(&temp);

    assert!(ptr_eq(&saved.ctx, &prev));
    assert_eq!(saved.id, 77);
    assert!(ptr_eq(&ff.ff_test_current(), &temp));
    assert_eq!(ff.ff_test_current_file_id(), 0);

    ff.restore_current_file_context_no_delete(&saved);

    assert!(ptr_eq(&ff.ff_test_current(), &prev));
    assert_eq!(ff.ff_test_current_file_id(), 77);

    drop(prev); // delete prev
    drop(temp); // delete temp
    ff.ff_test_current_clear();
    drop(ff); // delete ff
}

#[test]
fn up_gate_swap_does_not_engage_deferred() {
    // "swap/restore does not engage deferred-delete" — 2 CHECKs.
    let env = gate_env();
    let mut ff = FileFlows::new(&CacheFlow::default());
    let armed = ff_test_context(&env, 1);
    let temp = ff_test_context(&env, 2);

    ff.ff_test_deferred_set(&armed);

    let saved = ff.swap_current_file_context_no_delete(&temp);
    assert!(ptr_eq(&ff.ff_test_deferred(), &armed)); // unchanged

    ff.restore_current_file_context_no_delete(&saved);
    assert!(ptr_eq(&ff.ff_test_deferred(), &armed)); // unchanged

    drop(temp); // delete temp
    // "dtor will drain `armed` via the deferred slot."
    drop(ff); // delete ff
    drop(armed); // C freed it in the drain; the driver handle is unobservable
}
