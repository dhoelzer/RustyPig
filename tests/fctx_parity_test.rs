//! Whole-transcript replay of tools/fctx_harness/vectors.txt (610 lines,
//! md5 839b5566be0a2191876e0f34b4ed56e4, rebuilt STABLE x2) against the
//! Rust HEAVY FileContext half (src/file_api/file_lib.rs process pair /
//! find_file_type_from_ips / process_file_type / process_file_capture /
//! finish_signature_lookup / the print ladder + src/file_api/file_segment.rs
//! + src/helpers/sha256.rs + the 17r mempool pair, plan row 17r).
//!
//! The C probe compiles the ORIGINAL file_lib.cc (its :1363 [file_info]
//! UNIT_TEST block excised) plus the REAL file_flows/file_cache/
//! file_segment/file_mempool/circular_buffer/file_capture TUs over the
//! fflows donor closure. Gate binary = 18 cases / 91 assertions (the
//! carried fcache 7/42 + fflows 8/22 plus the NEW [file_mempool] block,
//! gate.txt "All tests passed (91 assertions in 18 test cases)"). The
//! [file_mempool] block (file_mempool.cc:223-303, 3 TEST_CASEs / 27
//! assertions, plan-RECON "All tests passed (27 assertions in 3 test
//! cases)") translates one-for-one as the up_gate_mempool_* tests below.
//!
//! Driver deviations (mirror the src module headers):
//! * C probe statics (g_ff / the fresh_ctx factory / one process-wide
//!   cache) ride the donor's Option<Rc<RefCell<FileFlows>>> slot + a
//!   hub-owned cache; every IMGR acquire/release lands at the C delete
//!   point because the Rc alias handles die exactly where C's raw
//!   `delete g_ff` sits (each fresh drops the prior FileFlows FIRST —
//!   pinned: K2's ctx release follows the K3 cache_add acquire:
//!   contexts live in the flows ppc slot, not the block scope).
//! * `new FileContext` with NO inspector == FileContext::ctor(None,
//!   env) (the L3 probe-owned alt; its delete emits no release —
//!   pinned). Contexts created through FileFlows/FileCache acquire
//!   through their owner's Imgr seam at the exact C site (the K3
//!   cache_add :122 vs fresh :127 pair pins the two positions).
//! * Sizes (ctx=424 segs=32 slot=16) are C layout constants (the Rc/Vec
//!   port shape does not reproduce a sizeof — fcache SIZEOF_FILE_NODE
//!   precedent); A_ENUM/A_CFG echo the harness FileConfig/enum
//!   vocabulary, armed through the port's DEFAULT_* consts.
//! * SZ_FILE_CAPTURE=64 (init_mempool's `block_len + sizeof(FileCapture)`
//!   overhead constant, harness-side like A_SZ): 1 MiB/(700000+64) = 1
//!   pool slot pins N5's init-OK + split-memcap st=3, memcap_fail=1,
//!   absolute bufs_alloc=3 (N1 init + N3 re-init + N5 init); the
//!   1 MiB/(16+64) = 13107-slot pool keeps every N1..N4 alloc live.
//! * file_capture.cc (913 LOC, async writer thread) stays its own row;
//!   CaptureWitness mirrors the REAL process_buffer / save_to_file_buffer
//!   / create_file_buffer / ~FileCapture observable stat ladder verbatim:
//!   the FULL within-packet-only arm, the `!head` init + buffered_total
//!   AFTER a successful create, the MAX early return BEFORE any create,
//!   the exact `file_current + capture_block_size < file_end` strict-<
//!   split loop, and the file_info-null dtor walk (freed_total + one
//!   m_free per chain block, each SUCCESS because create_file_buffer
//!   wrote the in-use header — modeled by mark_block_in_use, the
//!   [file_mempool] UT precedent).
//! * K1's process-site hexdump rides TraceSink::raw_line (C
//!   fprintf(stdout) — NO FILEDBG prefix, pinned); P0/P1/P1_BOM print
//!   ladders are direct calls printed verbatim.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use snort3::file_api::file_cache::*;
use snort3::file_api::file_flows::*;
use snort3::file_api::file_lib::{
    DEFAULT_FILE_CAPTURE_BLOCK_SIZE, DEFAULT_FILE_CAPTURE_MAX_SIZE, DEFAULT_FILE_CAPTURE_MIN_SIZE,
    DEFAULT_FILE_SHOW_DATA_DEPTH, DEFAULT_FILE_SIGNATURE_DEPTH, DEFAULT_FILE_TYPE_DEPTH,
    FILE_CAPTURE_FAIL, FILE_CAPTURE_MAX, FILE_CAPTURE_MEMCAP, FILE_CAPTURE_MIN,
    FILE_CAPTURE_SUCCESS,
    FILE_SIG_DEPTH_FAIL, FILE_SIG_DONE, FILE_SIG_FLUSH, FILE_SIG_PROCESSING, FILE_VERDICT_BLOCK,
    FILE_VERDICT_LOG, FILE_VERDICT_REJECT, FILE_VERDICT_STOP, FILE_VERDICT_UNKNOWN, FlowsRef,
    FileCaptureApi, FileCaptureFactory, FileConfigLite, FileContext, FileEnvLite,
    FpEvalApi, HrClock, NetworkPolicySeam, PublishApi, SNORT_FILE_END,
    SNORT_FILE_FULL, SNORT_FILE_MIDDLE, SNORT_FILE_POSITION_UNKNOWN, SNORT_FILE_START,
    SNORT_FILE_TYPE_CONTINUE, SNORT_FILE_TYPE_UNKNOWN, TimeVal, file_config_view_of,
    find_file_type_from_ips, process as fctx_process, process_file_capture as fctx_capture,
    process_pos as fctx_process_pos,
};
use snort3::file_api::file_mempool::{FileMemPool, FILE_MEM_FAIL, FILE_MEM_SUCCESS};
use snort3::file_api::file_stats::{file_stats_init, FileCounts};
use snort3::helpers::event_gen::DetectionEventSink;

const VECTORS: &str = include_str!("../tools/fctx_harness/vectors.txt");

/// C layout constants (sizeofs of the C classes; vector line 2).
const SZ_CTX: usize = 424;
const SZ_SEGS: usize = 32;
const SZ_SLOT: usize = 16;
/// sizeof(FileCapture) — the init_mempool block-overhead constant
/// (file_capture.h member layout; harness-side layout vocabulary like
/// A_SZ, see the module-header deviation note).
const SZ_FILE_CAPTURE: i64 = 64;

fn fill_data(n: usize, seed: u32) -> Vec<u8> {
    (0..n)
        .map(|i| ((i as u32 * 31 + seed) & 0xFF) as u8)
        .collect()
}
fn printable_data(n: usize, seed: u32) -> Vec<u8> {
    (0..n).map(|i| (0x41 + ((i as u32 + seed) % 26)) as u8).collect()
}
fn hexbuf(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

// -------------------------------------------------------------------
// Witness hub (bodies mirror tools/fctx_harness/stubs.cc 1:1; the
// shared witness shapes are the committed fflows 17q replay verbatim)
// -------------------------------------------------------------------

type Out = Rc<RefCell<Vec<String>>>;

fn push(out: &Out, s: impl Into<String>) {
    out.borrow_mut().push(s.into());
}

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
    /// NEW17r: plain-stdout sites (K-block trace_stream hexdump
    /// file_lib.cc:835; trace_signature SHA256 print) — NO prefix.
    fn raw_line(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }
        push(&self.out, line.trim_end_matches('\n'));
    }
}

/// DetectionEngine witnesses (stubs.cc:589-611). The probe prelude
/// arms the next-packet static SILENTLY (extern setter); the C latch
/// gate (g_cur_pkt) therefore reads 1 forever after the prelude — the
/// K3-area DE lines show have=0 only until find_file_type's
/// set_next_packet (:1019) first runs, exactly the C sequence.
struct CurPkt {
    out: Out,
    latched: Rc<Cell<bool>>,
    armed: Rc<Cell<bool>>, // g_next_pkt non-null (prelude arms it, silent)
}
impl CurrentPacketApi for CurPkt {
    fn get_current_packet(&mut self) {
        push(
            &self.out,
            format!(
                "DE get_current_packet have={}",
                u8::from(self.latched.get())
            ),
        );
    }
    fn set_next_packet(&mut self, _parent: &PacketView) {
        push(
            &self.out,
            format!(
                "DE set_next_packet parent=1 flow=0 next={}",
                u8::from(self.armed.get())
            ),
        );
        self.latched.set(self.armed.get());
    }
}

struct StubInspector {
    cfg: Rc<RefCell<FileConfigView>>,
}
impl InspectorApi for StubInspector {
    fn config(&self) -> Rc<RefCell<FileConfigView>> {
        self.cfg.clone()
    }
}

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

/// NetworkPolicy witness (stubs.cc:522-526): get_network_policy prints
/// WITNESS via the port's flows-site seam note, then this pair.
struct NetPolWit {
    out: Out,
    handle: FilePolicyHandle,
}
impl NetworkPolicySeam for NetPolWit {
    /// the donor witness pair (stubs.cc:522-526): get_network_policy()
    /// prints "WITNESS get_network_policy", then
    /// get_base_file_policy() prints "POLICY base_file_policy -> stub"
    /// — one chained call site (file_flows.cc:150), both lines per
    /// new-FileFlows build.
    fn get_base_file_policy(&mut self) -> Option<FilePolicyHandle> {
        push(&self.out, "WITNESS get_network_policy");
        push(&self.out, "POLICY base_file_policy -> stub");
        Some(self.handle.clone())
    }
}

struct PTr {
    out: Out,
    daq: Rc<Cell<bool>>,
    active: Rc<Cell<bool>>,
}
impl PacketTracerApi for PTr {
    fn is_active(&self) -> bool {
        self.active.get()
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

struct Devt {
    out: Out,
}
impl DetectionEventSink for Devt {
    fn queue_event(&mut self, gid: u32, sid: u32) {
        push(&self.out, format!("DE queue_event gid={gid} sid={sid}"));
    }
}

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

/// FileCache-side event seam — the committed 17p EvtSink body verbatim
/// (apply/resume/store sites drive it). Process-side sites ride the
/// port's real FileContext::log_file_event (17q split, module header).
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

struct FFlowsWitness;
impl FileFlowsSink for FFlowsWitness {
    fn get_file_flows(&mut self, _to_create: bool) -> bool {
        false
    }
    fn add_pending_file(&mut self, _file_id: u64) {}
}

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

/// NEW17r fp_eval witness (stubs.cc:625-671): the counter line ALWAYS
/// prints; then the re-entrant swap arm (prints before the install),
/// then the type-set arm armed (spid != 0 and conf spid match and the
/// packet's file_type_process) through the REAL FileFlows current
/// chain. The port keeps `this` identity so the pinned cur_is_* reads
/// hold; reading through the flows slot mirrors C's get_file_flows(...
/// false)->get_current() (current_file_id is 0 at every fp_eval site in
/// this probe — fresh set_current zeroes it — so the current alias IS
/// the whole lookup).
struct FpEvalWit {
    out: Out,
    set_spid: Rc<Cell<u32>>,
    set_ftype: Rc<Cell<u32>>,
    swap: Rc<Cell<bool>>,
    alt: Rc<RefCell<Option<Rc<RefCell<FileContext>>>>>,
    calls: Rc<Cell<u32>>,
    ff: Rc<RefCell<Option<Rc<RefCell<FileFlows>>>>>,
}
impl FpEvalApi for FpEvalWit {
    fn fp_eval_service_group(
        &mut self,
        p: &PacketView,
        snort_protocol_id: i32,
        _ctx: &Rc<RefCell<FileContext>>,
    ) {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        push(
            &self.out,
            format!(
                "FP_EVAL spid={snort_protocol_id} have_pkt=1 n={n}"
            ),
        );
        let ff = self.ff.borrow().clone();
        if let Some(ff2) = ff.clone() {
            if self.swap.get() && self.alt.borrow().is_some() {
                push(&self.out, "FP_EVAL swap -> alt");
                let alt = self.alt.borrow().clone().expect("armed above");
                ff2.borrow_mut().set_current_file_context(&alt);
            }
            let _ = ff2;
        }
        let arm = self.set_spid.get();
        if arm != 0 && (snort_protocol_id as u32) == arm && p.file_type_process {
            let cur = ff.and_then(|ff| ff.borrow().ff_test_current());
            if let Some(cur) = cur {
                let ftype = self.set_ftype.get();
                push(&self.out, format!("FP_EVAL set_type={ftype}"));
                cur.borrow_mut().info.set_file_type(ftype as u64);
            }
        }
    }
}

/// N-block capture seam: mirrors FileCapture's ctor/process_buffer/
/// save_to_file_buffer/create_file_buffer/~FileCapture observable
/// ladder (file_capture.cc:121-129, 262-281, 284-298, 311-375,
/// 379-408, :12-56 dtor) over the Rust FileMemPool. Counts ride a
/// dedicated witness-side FileCounts (the process-wide file_counts
/// global the file_capture TU reaches directly; the port side is
/// separate and the driver merges the two before any pinned read —
/// disjoint field sets per ladder, no interleaving observable).
struct HubCapture {
    block_size: Rc<Cell<i64>>,
    pool: Rc<RefCell<Option<FileMemPool>>>,
    wc: Rc<RefCell<FileCounts>>,
    max_size: i64,
    capture_size: i64,
    blocks: Vec<(usize, u64)>, // (pool slot, block length) — chain order
    head: Option<usize>,       // index into blocks
}

impl HubCapture {
    fn create_file_buffer(&mut self) -> Option<usize> {
        let created = {
            let mut pb = self.pool.borrow_mut();
            let pool = pb
                .as_mut()
                .expect("file_mempool null at create_file_buffer (never null in pinned runs)");
            match pool.m_alloc() {
                Some(idx) => {
                    // create_file_buffer writes the in-use block header
                    // (`fileBlock->length = 0; fileBlock->next = nullptr`
                    // == clearing the FREE magic) — the [file_mempool]
                    // mark_block_in_use precedent.
                    pool.mark_block_in_use(Some(idx));
                    Some(idx)
                }
                None => {
                    self.wc.borrow_mut().file_memcap_failures_total += 1;
                    None
                }
            }
        };
        if created.is_some() {
            self.wc.borrow_mut().file_buffers_allocated_total += 1;
        }
        created
    }

    fn save_to_file_buffer(&mut self, data_size: i32) -> u32 {
        // cc:313 if (data_size <= 0) return SUCCESS
        if data_size <= 0 {
            return FILE_CAPTURE_SUCCESS;
        }
        // cc:316 size-limit test BEFORE any block work
        if (data_size as i64) + self.capture_size > self.max_size {
            self.wc.borrow_mut().file_size_max += 1;
            return FILE_CAPTURE_MAX;
        }
        let block_size = self.block_size.get();
        let last = self.head.expect("head armed by process_buffer");
        let available = block_size - self.blocks[last].1 as i64;
        if (data_size as i64) > available {
            // fill the current block first, then the split loop
            self.blocks[last].1 = block_size as u64;
            let mut file_current = available;
            loop {
                let nb = match self.create_file_buffer() {
                    Some(nb) => nb,
                    None => return FILE_CAPTURE_MEMCAP,
                };
                let nbi = self.blocks.len();
                self.blocks.push((nb, 0));
                self.head = Some(nbi); // `last = new_block`
                // cc:346 the exact strict-< quirk
                if file_current + block_size < data_size as i64 {
                    self.blocks[nbi].1 = block_size as u64;
                    file_current += block_size;
                } else {
                    self.blocks[nbi].1 = (data_size as i64 - file_current) as u64;
                    break;
                }
            }
        } else {
            let last = self.head.expect("head");
            self.blocks[last].1 += data_size as u64;
        }
        self.capture_size += data_size as i64;
        FILE_CAPTURE_SUCCESS
    }
}

impl FileCaptureApi for HubCapture {
    fn reserve_file(&mut self, _file: &snort3::file_api::file_lib::FileInfo) -> u32 {
        FILE_CAPTURE_SUCCESS // capture_state SUCCESS at every pinned point
    }
    fn get_file_capture_size(&self) -> i64 {
        self.capture_size
    }
    fn get_max_file_capture_size(&self) -> i64 {
        self.max_size
    }
    fn set_data(&mut self, _file_data: &[u8], _size: u32) {}
    fn process_buffer(&mut self, _file_data: &[u8], data_size: i32, position: u32) -> u32 {
        match position {
            SNORT_FILE_FULL => {
                self.wc.borrow_mut().file_within_packet += 1; // cc:370
            }
            // cc:372 case SNORT_FILE_END: break;
            // default: the START/MIDDLE buffering arm (cc:375-404)
            _ => {
            if self.head.is_none() {
                    let b = match self.create_file_buffer() {
                        Some(b) => b,
                        None => return FILE_CAPTURE_MEMCAP, // cc:386
                    };
                    self.blocks.push((b, 0));
                    self.head = Some(0);
                    self.wc.borrow_mut().files_buffered_total += 1; // cc:389
                }
                return self.save_to_file_buffer(data_size);
            }
        }
        FILE_CAPTURE_SUCCESS
    }
}

impl Drop for HubCapture {
    fn drop(&mut self) {
        // ~FileCapture (cc:12-56) file_info-null arm: freed_total +
        // one m_free per chain block (each SUCCESS — the in-use header
        // was written at create).
        self.wc.borrow_mut().files_freed_total += 1;
        let mut pb = self.pool.borrow_mut();
        if let Some(pool) = pb.as_mut() {
            for (idx, _len) in self.blocks.drain(..) {
                if pool.m_free(Some(idx)) != FILE_MEM_SUCCESS {
                    self.wc.borrow_mut().file_buffers_free_errors += 1;
                }
                self.wc.borrow_mut().file_buffers_freed_total += 1;
            }
        }
        self.head = None;
    }
}

/// FileService::init-time `new FileCapture(min, max)` factory witness
/// (process_file_capture :1174 — the capture engine body stays its own
/// row; the witness carries the real ctor's min/max capture).
struct CaptureFactory {
    block_size: Rc<Cell<i64>>,
    pool: Rc<RefCell<Option<FileMemPool>>>,
    wc: Rc<RefCell<FileCounts>>,
}
impl FileCaptureFactory for CaptureFactory {
    fn new_capture(&mut self, min: i64, max: i64) -> Option<Box<dyn FileCaptureApi>> {
        let _ = min;
        Some(Box::new(HubCapture {
            block_size: self.block_size.clone(),
            pool: self.pool.clone(),
            wc: self.wc.clone(),
            max_size: max,
            capture_size: 0,
            blocks: Vec::new(),
            head: None,
        }))
    }
}

struct FixedClock(f64);
impl HrClock for FixedClock {
    fn now(&self) -> f64 {
        self.0
    }
}

// -------------------------------------------------------------------
// Hub: the C file-scope statics (g_ff, one process-wide cache, the
// harness FileConfig, the fp_eval arm set, the capture statics, the
// latch cells) threaded as Rc/Cell clones.
// -------------------------------------------------------------------

struct Hub {
    out: Out,
    ff: Rc<RefCell<Option<Rc<RefCell<FileFlows>>>>>, // static g_ff
    level: Rc<RefCell<u8>>,
    armed: Rc<RefCell<Option<Rc<StubInspector>>>>,
    lite: Rc<RefCell<FileConfigLite>>,   // the harness FileConfig
    view: Rc<RefCell<FileConfigView>>,   // the inspector->config view
    counts: Rc<RefCell<FileCounts>>,     // port-side file_counts
    wc: Rc<RefCell<FileCounts>>,         // witness-side (capture stats)
    adv_pub_id: Rc<Cell<u32>>,
    daq: Rc<Cell<bool>>,
    pt_active: Rc<Cell<bool>>,
    cur_latched: Rc<Cell<bool>>,
    cur_armed: Rc<Cell<bool>>,
    set_spid: Rc<Cell<u32>>,
    set_ftype: Rc<Cell<u32>>,
    swap: Rc<Cell<bool>>,
    alt: Rc<RefCell<Option<Rc<RefCell<FileContext>>>>>,
    fpe_calls: Rc<Cell<u32>>,
    block_size: Rc<Cell<i64>>,
    pool: Rc<RefCell<Option<FileMemPool>>>,
    stub_handle: FilePolicyHandle,
    tv: Rc<Cell<u32>>,
    sv: Rc<Cell<u32>>,
    env: FileEnvLite,
}

impl Hub {
    fn new() -> Hub {
        let out: Out = Rc::new(RefCell::new(Vec::new()));
        let ff: Rc<RefCell<Option<Rc<RefCell<FileFlows>>>>> = Rc::new(RefCell::new(None));
        let level = Rc::new(RefCell::new(0u8));
        let armed = Rc::new(RefCell::new(None));
        let lite = Rc::new(RefCell::new(FileConfigLite::default()));
        let view = Rc::new(RefCell::new(file_config_view_of(&lite.borrow())));
        let counts = Rc::new(RefCell::new(FileCounts::default()));
        let wc = Rc::new(RefCell::new(FileCounts::default()));
        let adv_pub_id = Rc::new(Cell::new(7));
        let daq = Rc::new(Cell::new(false));
        let pt_active = Rc::new(Cell::new(false));
        let cur_latched = Rc::new(Cell::new(false));
        let cur_armed = Rc::new(Cell::new(false));
        let set_spid = Rc::new(Cell::new(0));
        let set_ftype = Rc::new(Cell::new(0));
        let swap = Rc::new(Cell::new(false));
        let alt: Rc<RefCell<Option<Rc<RefCell<FileContext>>>>> = Rc::new(RefCell::new(None));
        let fpe_calls = Rc::new(Cell::new(0));
        let block_size = Rc::new(Cell::new(0));
        let pool: Rc<RefCell<Option<FileMemPool>>> = Rc::new(RefCell::new(None));
        let tv = Rc::new(Cell::new(FILE_VERDICT_UNKNOWN));
        let sv = Rc::new(Cell::new(FILE_VERDICT_UNKNOWN));
        let stub_handle = FilePolicyHandle::new_boxed(Box::new(PolicyStub {
            out: out.clone(),
            tv: tv.clone(),
            sv: sv.clone(),
        }));
        let mut env = FileEnvLite {
            trace: Box::new(TraceWit {
                out: out.clone(),
                level: level.clone(),
            }),
            curpkt: Box::new(CurPkt {
                out: out.clone(),
                latched: cur_latched.clone(),
                armed: cur_armed.clone(),
            }),
            packet_tracer: Box::new(PTr {
                out: out.clone(),
                daq: daq.clone(),
                active: pt_active.clone(),
            }),
            publish: Box::new(PubWit { out: out.clone() }),
            de: Box::new(Devt { out: out.clone() }),
            clock: Box::new(FixedClock(100.0)), // fcache_set_fake_now(100)
            imgr: Rc::new(RefCell::new(Box::new(Imgr {
                out: out.clone(),
                armed: armed.clone(),
            }) as Box<dyn InspectorManagerApi>)),
            network_policy: Some(Rc::new(RefCell::new(NetPolWit {
                out: out.clone(),
                handle: stub_handle.clone(),
            }))),
            ..FileEnvLite::default()
        };
        env.adv_pub_id.set(7);
        env.capture_factory = Box::new(CaptureFactory {
            block_size: block_size.clone(),
            pool: pool.clone(),
            wc: wc.clone(),
        });
        env.fpe = Box::new(FpEvalWit {
            out: out.clone(),
            set_spid: set_spid.clone(),
            set_ftype: set_ftype.clone(),
            swap: swap.clone(),
            alt: alt.clone(),
            calls: fpe_calls.clone(),
            ff: ff.clone(),
        });
        // fcache_set_instance_id(0); the fake clock is the FixedClock.
        // file_stats_init (silent; the heavy-half stats derefs never null).
        file_stats_init(env.stats.get_mut());
        Hub {
            out,
            ff,
            level,
            armed,
            lite,
            view,
            counts,
            wc,
            adv_pub_id,
            daq,
            pt_active,
            cur_latched,
            cur_armed,
            set_spid,
            set_ftype,
            swap,
            alt,
            fpe_calls,
            block_size,
            pool,
            stub_handle,
            tv,
            sv,
            env,
        }
    }

    fn push(&self, s: impl Into<String>) {
        push(&self.out, s);
    }
    /// Print a C stream write (NUL-free, newline-terminated chunks) as
    /// transcript lines, preserving exact spacing incl. trailing.
    fn push_dump(&self, s: &str) {
        for line in s.split('\n') {
            if !line.is_empty() {
                push(&self.out, line);
            }
        }
    }
    fn set_trace(&mut self, on: bool, level: u8) {
        *self.level.borrow_mut() = if on { level } else { 0 };
    }
    /// fcache_set_file_service(on): the three statics under the OR
    fn set_service(&mut self, on: bool) {
        self.env.svc.set_file_service_enabled(on, on);
    }
    /// fcache_set_file_inspector(1): one-shot latch + FileInspect ctor
    /// witness + get_file_config() resolution (harness FileConfig).
    fn arm_inspector(&mut self) {
        if self.armed.borrow().is_none() {
            self.push("FileInspect ctor");
            *self.armed.borrow_mut() = Some(Rc::new(StubInspector {
                cfg: self.view.clone(),
            }));
            self.env.file_config = Some(self.lite.clone());
        }
    }
    /// `static FileCache g_cache(64); fcache_set_file_cache(&g_cache)`
    fn arm_cache(&mut self) -> Rc<RefCell<FileCache>> {
        let mut cache = FileCache::new(64);
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
            latched: self.cur_latched.clone(),
            armed: self.cur_armed.clone(),
        });
        cache.file_flows = Box::new(FFlowsWitness);
        cache.packet_tracer = Box::new(PTr {
            out: self.out.clone(),
            daq: self.daq.clone(),
            active: self.pt_active.clone(),
        });
        cache.clock = Box::new(DriverPacketClock {
            now: TimeVal::default(),
        });
        cache.conf = self.view.clone();
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
    /// The ONE harness FileConfig is reached through two Rust views
    /// (module-header deviation); every probe arm mutates lite and
    /// re-syncs the ctx-visible view (trace_stream / show_data_depth /
    /// file_signature_depth / file_type_depth... ride both).
    fn sync_view(&mut self) {
        *self.view.borrow_mut() = file_config_view_of(&self.lite.borrow());
    }
    fn set_policy_verdicts(&mut self, type_v: u32, sig_v: u32) {
        self.tv.set(type_v);
        self.sv.set(sig_v);
    }
    fn set_daq(&mut self, on: bool) {
        self.daq.set(on);
    }
    fn set_pt_active(&mut self, on: bool) {
        self.pt_active.set(on);
    }
    /// fcache_set_next_packet(&g_p) prelude arm — SILENT setter with
    /// the latch (have=0 until the first set_next_packet method call).
    fn prelude_next_packet(&mut self) {
        self.cur_armed.set(true);
    }
    /// fctx_set_fp_eval_type(spid, ftype)
    fn fpe_type(&self, spid: u32, ftype: u32) {
        self.set_spid.set(spid);
        self.set_ftype.set(ftype);
    }
    /// fctx_set_fp_eval_swap(on) / fctx_set_fp_eval_install(c) /
    /// fcache_fp_eval_calls()
    fn fpe_swap(&self, on: bool) {
        self.swap.set(on);
    }
    fn fpe_install(&self, c: Option<Rc<RefCell<FileContext>>>) {
        *self.alt.borrow_mut() = c;
    }
    fn fpe_calls(&self) -> u32 {
        self.fpe_calls.get()
    }
    /// fcache_set_capture_block_size(bytes) / fcache_set_capture_mem(1)
    /// == FileCapture::init_mempool(1, capture_block_size)
    fn set_block_size(&mut self, bytes: i64) {
        self.block_size.set(bytes);
    }
    fn init_mempool(&mut self) {
        let mut bs = self.block_size.get() + SZ_FILE_CAPTURE; // cc:245
        if bs <= 0 {
            return;
        }
        if bs & 7 != 0 {
            bs += 8 - (bs & 7); // cc:253-254
        }
        let max_files = ((1_048_576_i64) / bs) as u64; // cc:256 int (1 MiB memcap)
        *self.pool.borrow_mut() = Some(FileMemPool::new(max_files, bs as usize));
    }
    /// probe cache_add helper on the armed (process-wide) cache
    fn cache_add(
        &mut self,
        file_id: u64,
        timeout: i64,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let cache = self.env.svc.get_file_cache().expect("cache armed");
        let k = FileHashKey {
            file_id,
            ..FileHashKey::default()
        };
        let mut cf = false;
        let mut ce = 0i64;
        let counts = self.counts.clone();
        cache
            .borrow_mut()
            .add(&k, timeout, &mut cf, &mut ce, true, &mut counts.borrow_mut())
    }
    /// fresh_ctx(n): probe factory verbatim — delete prior g_ff FIRST
    /// (its dtor drains current/ppc: the pinned IMGR releases), clear
    /// the flow slot, rebuild, get + install + pin the file_id.
    fn fresh(&mut self, n: u64) -> Rc<RefCell<FileContext>> {
        let old = self.ff.borrow_mut().take();
        if let Some(ff) = old {
            // probe `delete g_ff`: ~FileFlows runs AT this point
            // (file_flows.cc:236 -> dtor drain of deferred/main/ppc,
            // each context's IMGR release via the 17r owner-delete
            // model); driver-side Rc aliases must not defer it. A
            // later last-Drop re-runs dtor() silently (all slots
            // already taken).
            ff.borrow_mut().dtor();
            drop(ff); // ~FileFlows: no-op walk (drained above)
        }
        let flow = CacheFlow::default();
        let ff = {
            let slot = &mut *self.ff.borrow_mut();
            FileFlows::get_file_flows(slot, &flow, true, &mut self.env).expect("g_ff")
        };
        let mut isnew = false;
        let ctx = ff
            .borrow_mut()
            .get_file_context(
                1000 + n,
                true,
                &mut isnew,
                0,
                &mut self.env,
                &mut self.counts.borrow_mut(),
            )
            .expect("fresh ctx");
        ff.borrow_mut().set_current_file_context(&ctx);
        ctx.borrow_mut().info.set_file_id(1000 + n);
        ctx
    }
    /// merge the witness-side capture counters into the port-side set
    /// before any absolute stat read (disjoint fields; order-free).
    fn merge_wc(&mut self) {
        let d = std::mem::take(&mut *self.wc.borrow_mut());
        let c = &mut *self.counts.borrow_mut();
        c.file_within_packet += d.file_within_packet;
        c.files_buffered_total += d.files_buffered_total;
        c.file_memcap_failures_total += d.file_memcap_failures_total;
        c.file_buffers_allocated_total += d.file_buffers_allocated_total;
        c.file_size_max += d.file_size_max;
        c.files_freed_total += d.files_freed_total;
        c.file_buffers_freed_total += d.file_buffers_freed_total;
        c.file_buffers_free_errors += d.file_buffers_free_errors;
    }
    fn stat(&self, f: impl Fn(&FileCounts) -> u64) -> u64 {
        f(&self.counts.borrow())
    }
    fn flows_ref<'f>(&self, ff: &'f Rc<RefCell<FileFlows>>) -> FlowsRef<'f> {
        FlowsRef::Handle(ff)
    }
}

fn mk_packet(hub: &Hub) -> PacketView {
    PacketView {
        flow: CacheFlow::default(),
        packet_flags: 0,
        active: ActiveState {
            witness: Some(Rc::new(RefCell::new(ActWit {
                out: hub.out.clone(),
            }))),
            ..ActiveState::default()
        },
        conf: *hub.view.borrow(),
        proto_bits: 0,
        file_data: None,
        file_pos: 0,
        file_type_process: false,
        snort_protocol_id: 0,
    }
}

// -------------------------------------------------------------------
// The replay (probe.cc main() line-for-line)
// -------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn fctx_transcript_replay() {
    let hub = &mut Hub::new();

    // probe prelude (probe.cc:153-171 order): the Hub ctor already arms
    // the fake clock (fcache_enable_fake_clock(1) + fcache_set_fake_now
    // (100)), adv_pub_id 7, and instance 0 (defaults + env.adv_pub_id).
    // FileInspect(1) -> the "FileInspect ctor" witness line, service on,
    // next-packet armed (have=0), one process-wide g_cache(64).
    hub.arm_inspector();
    hub.set_service(true);
    hub.prelude_next_packet();
    let _cache = hub.arm_cache();

    // ============ A: layout / enum vocabulary =========================
    hub.push(format!(
        "A_SZ ctx={SZ_CTX} segs={SZ_SEGS} slot={SZ_SLOT}"
    ));
    // scoped: the Ref<'_> must die before the first `hub` re-borrow
    {
        let lite = hub.lite.borrow();
        hub.push(format!(
            "A_ENUM sig={},{},{},{} cap={},{},{},{},{} pos={},{},{},{},{} ftype_unk={} ftype_cont={} spid={}",
            FILE_SIG_PROCESSING,
            FILE_SIG_DEPTH_FAIL,
            FILE_SIG_FLUSH,
            FILE_SIG_DONE,
            FILE_CAPTURE_SUCCESS,
            FILE_CAPTURE_MIN,
            FILE_CAPTURE_MAX,
            FILE_CAPTURE_MEMCAP,
            FILE_CAPTURE_FAIL,
            SNORT_FILE_POSITION_UNKNOWN,
            SNORT_FILE_START,
            SNORT_FILE_MIDDLE,
            SNORT_FILE_END,
            SNORT_FILE_FULL,
            SNORT_FILE_TYPE_UNKNOWN,
            SNORT_FILE_TYPE_CONTINUE,
            lite.snort_protocol_id,
        ));
        hub.push(format!(
            "A_CFG typed={} sigd={} showd={} capmin={} capmax={}",
            lite.file_type_depth,
            lite.file_signature_depth,
            lite.show_data_depth,
            lite.capture_min_size,
            lite.capture_max_size,
        ));
    }
    debug_assert_eq!(
        (
            DEFAULT_FILE_TYPE_DEPTH,
            DEFAULT_FILE_SIGNATURE_DEPTH,
            DEFAULT_FILE_SHOW_DATA_DEPTH,
            DEFAULT_FILE_CAPTURE_MIN_SIZE,
            DEFAULT_FILE_CAPTURE_MAX_SIZE,
            DEFAULT_FILE_CAPTURE_BLOCK_SIZE
        ),
        (1460, 10_485_760, 100, 0, 1_048_576, 32_768)
    );

    // ============ P0: print_file_data hexdump (static) ================
    {
        let alpha: Vec<u8> = (0..20u8).map(|i| b'A' + i).collect();
        for len in [0i32, 1, 7, 8, 9, 17, 18, 20] {
            hub.push(format!("P0_LEN={len}>>>"));
            let s = FileContext::print_file_data(&alpha, len, 100);
            hub.push_dump(&s);
            hub.push("<<<P0");
        }
        hub.push("P0_CLAMP>>>");
        hub.push_dump(&FileContext::print_file_data(&alpha, 20, 9));
        hub.push("<<<P0");
        let mixed: Vec<u8> = (0..36u8).collect();
        hub.push("P0_CTL>>>");
        hub.push_dump(&FileContext::print_file_data(&mixed, 36, 100));
        hub.push("<<<P0");
        let hi: [u8; 18] = [
            0x7F, 0x80, 0xA0, 0xFF, 0xB5, 0xC0, 0xE9, 0xF0, 0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x1C, 0x85, 0xAA, 0x81,
        ];
        hub.push("P0_HI>>>");
        hub.push_dump(&FileContext::print_file_data(&hi, 18, 100));
        hub.push("<<<P0");
        let neg: [u8; 3] = [0x80, 0xFF, 0x7F];
        hub.push("P0_SIGN>>>");
        hub.push_dump(&FileContext::print_file_data(&neg, 3, 100));
        hub.push("<<<P0");
    }

    // ============ P1: print_file_sha256 / print ======================
    {
        let ctx = hub.fresh(1);
        let sha: [u8; 32] = *b"0123456789abcdef0123456789ABCDEF";
        ctx.borrow_mut().info.set_file_id(1002);
        ctx.borrow_mut().info.reset_sha();
        ctx.borrow_mut().info.sha256 = Some(sha);
        hub.push("P1_SHA>>>");
        hub.push_dump(&ctx.borrow().print_file_sha256_str());
        hub.push("<<<P1");
        ctx.borrow_mut().info.unset_file_name();
        hub.push("P1_PRINT0>>>");
        hub.push_dump(&ctx.borrow().print(&hub.env));
        hub.push("<<<P1");
        ctx.borrow_mut().info.set_file_name(Some(b"plain.txt"), 9);
        ctx.borrow_mut().info.set_url(Some(b"http://e/h"), 10);
        ctx.borrow_mut().info.set_host(Some(b"host.h"), 6);
        hub.push("P1_PRINT1>>>");
        hub.push_dump(&ctx.borrow().print(&hub.env));
        hub.push("<<<P1");
        // UTF-16LE BOM: C read the literal's terminating NUL + one OOB
        // zero (size arg 8 > 6-byte content); zero padding reproduces.
        ctx.borrow_mut()
            .info
            .set_file_name(Some(b"\xFF\xFE\x41\x00\x42\x00\x00\x00"), 8);
        hub.push("P1_BOM>>>");
        hub.push_dump(&ctx.borrow().print(&hub.env));
        hub.push("<<<P1");
        hub.set_daq(true);
        hub.push("P1_DAQ>>>");
        // the C endl is skipped under daq (the probe's printf("\n")
        // closes the line — the driver's own line push stands in)
        let s = ctx.borrow().print_file_name_str(&hub.env);
        for line in s.split('\n') {
            if !line.is_empty() {
                hub.push(line);
            }
        }
        hub.push("<<<P1");
        hub.set_daq(false);
        let raw: [u8; 7] = [b'a', 0xC3, 0xA9, b'z', 0x01, 0x80, b'q'];
        ctx.borrow_mut().info.set_file_name(Some(&raw), 7);
        hub.push("P1_HEX>>>");
        hub.push_dump(&ctx.borrow().print_file_name_str(&hub.env));
        hub.push("<<<P1");
        ctx.borrow_mut().info.reset_sha();
        hub.push(format!(
            "P1_RESETSHA null_after={}",
            u8::from(ctx.borrow().info.get_file_sig_sha256().is_none())
        ));
    }

    // ============ K: process position-form ladder ====================
    {
        // K0: data_size < 0 -> true before any stat
        let ctx = hub.fresh(10);
        let d = fill_data(8, 1);
        let mut p = mk_packet(hub);
        let ff = hub.ff.borrow().clone().expect("g_ff live");
        let r0 = fctx_process_pos(
            &ctx,
            &mut p,
            &d,
            -1,
            SNORT_FILE_FULL,
            Some(hub.stub_handle.clone()),
            &mut hub.flows_ref(&ff),
            &mut hub.env,
            &mut hub.counts.borrow_mut(),
        );
        hub.push(format!(
            "K0_NEG ret={} processed={}",
            u8::from(r0),
            ctx.borrow().get_processed_bytes()
        ));

        // K1: trace_stream print arm (show_data_depth 2 clamp)
        {
            let ctx = hub.fresh(11);
            lite_arm(hub, |c| {
                c.trace_stream = true;
                c.show_data_depth = 2;
            });
            let d = fill_data(6, 7);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                6,
                SNORT_FILE_FULL,
                None, // policy nullptr
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            lite_arm(hub, |c| {
                c.trace_stream = false;
                c.show_data_depth = 100;
            });
            hub.push(format!(
                "K1_STREAM ret={} data_total_plus={}",
                u8::from(r),
                hub.stat(|c| c.file_data_total)
            ));
        }

        // K2: type+sig both disabled :842 (arms the PT + DEBUG pair)
        {
            let ctx = hub.fresh(12);
            hub.set_service(false);
            hub.set_pt_active(true);
            hub.set_trace(true, TRACE_DEBUG_LEVEL);
            let d = printable_data(5, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                5,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.set_pt_active(false);
            hub.set_trace(false, 0);
            hub.push(format!(
                "K2_OFF ret={} complete={} processed={} file_size={}",
                u8::from(r),
                u8::from(ctx.borrow().info.processing_complete),
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.get_file_size(),
            ));
            hub.set_service(true);
        }

        // K3: cached verdict HIT (entry 1014 pinned by file_id)
        {
            // cache_add FIRST (the acquire precedes the fresh's g_ff
            // drop-release: contexts live in the prior flows ppc slot)
            let entry = hub.cache_add(1014, 3600).expect("entry");
            entry.borrow_mut().info.set_file_id(1014);
            entry.borrow_mut().info.verdict = FILE_VERDICT_BLOCK;
            hub.set_policy_verdicts(FILE_VERDICT_LOG, FILE_VERDICT_UNKNOWN);
            hub.set_trace(true, TRACE_DEBUG_LEVEL);
            let ctx = hub.fresh(14);
            ctx.borrow_mut().info.config_file_type(true);
            let hits = hub.stat(|c| c.file_cache_hits);
            let d = printable_data(4, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                4,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let hits2 = hub.stat(|c| c.file_cache_hits);
            hub.push(format!(
                "K3_HIT ret={} hits+={} verdict={} complete={} cdup={}",
                u8::from(r),
                hits2 - hits,
                ctx.borrow().info.verdict,
                u8::from(ctx.borrow().info.processing_complete),
                u8::from(ctx.borrow().is_cache_dup()),
            ));
            hub.set_trace(false, 0);
        }

        // K4: cached verdict MISS (features off, cacheable on) —
        // the PARITY-FIX arm: cacheable && lookup UNKNOWN -> misses++
        {
            let ctx = hub.fresh(15);
            ctx.borrow_mut().info.config_file_type(false);
            ctx.borrow_mut().info.config_file_signature(false);
            let misses = hub.stat(|c| c.file_cache_misses);
            let d = printable_data(3, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                3,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let misses2 = hub.stat(|c| c.file_cache_misses);
            hub.push(format!(
                "K4_MISS ret={} misses+={} processed={} complete={}",
                u8::from(r),
                misses2 - misses,
                ctx.borrow().get_processed_bytes(),
                u8::from(ctx.borrow().info.processing_complete),
            ));
        }

        // K5-K9: the fp_eval type-set ladder (conf spid 66)
        lite_arm(hub, |c| c.snort_protocol_id = 66);
        {
            let ctx = hub.fresh(16);
            hub.fpe_type(66, SNORT_FILE_TYPE_UNKNOWN);
            hub.set_trace(true, TRACE_INFO_LEVEL);
            ctx.borrow_mut().info.config_file_type(true);
            let d = printable_data(40, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                40,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "K5_UNK ret={} t_en={} s_en={} complete={} processed={} fpn={}",
                u8::from(r),
                u8::from(ctx.borrow().info.is_file_type_enabled()),
                u8::from(ctx.borrow().info.is_file_signature_enabled()),
                u8::from(ctx.borrow().info.processing_complete),
                ctx.borrow().get_processed_bytes(),
                hub.fpe_calls(),
            ));
            hub.set_trace(false, 0);
        }
        {
            // K6: type found 7 + policy STOP
            hub.fpe_type(66, 7);
            hub.set_policy_verdicts(FILE_VERDICT_STOP, FILE_VERDICT_UNKNOWN);
            hub.set_trace(true, TRACE_INFO_LEVEL);
            let ctx = hub.fresh(17);
            ctx.borrow_mut().info.config_file_type(true);
            ctx.borrow_mut().info.config_file_signature(true);
            let d = printable_data(40, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                40,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "K6_STOP ret={} sig={} t={} ftype={} verdict={} processed={} size={} complete={}",
                u8::from(r),
                u8::from(ctx.borrow().info.is_file_signature_enabled()),
                u8::from(ctx.borrow().info.is_file_type_enabled()),
                ctx.borrow().info.file_type_id,
                ctx.borrow().info.verdict,
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.get_file_size(),
                u8::from(ctx.borrow().info.processing_complete),
            ));
            hub.set_trace(false, 0);
        }
        {
            // K7: found + BLOCK + PT active
            hub.set_policy_verdicts(FILE_VERDICT_BLOCK, FILE_VERDICT_UNKNOWN);
            hub.set_pt_active(true);
            hub.set_trace(true, TRACE_INFO_LEVEL);
            let ctx = hub.fresh(18);
            ctx.borrow_mut().info.config_file_type(true);
            ctx.borrow_mut().info.config_file_signature(false);
            let d = printable_data(40, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                40,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "K7_BLOCK ret={} verdict={} ftype={} complete={}",
                u8::from(r),
                ctx.borrow().info.verdict,
                ctx.borrow().info.file_type_id,
                u8::from(ctx.borrow().info.processing_complete),
            ));
            hub.set_trace(false, 0);
        }
        {
            // K7b: found 8 + REJECT: PT reject arms + ACT reset
            hub.set_policy_verdicts(FILE_VERDICT_REJECT, FILE_VERDICT_UNKNOWN);
            hub.set_trace(true, TRACE_INFO_LEVEL);
            let ctx = hub.fresh(27);
            ctx.borrow_mut().info.config_file_type(true);
            ctx.borrow_mut().info.config_file_signature(false);
            hub.fpe_type(66, 8);
            let d = printable_data(40, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                40,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "K7b_REJECT ret={} verdict={} ftype={}",
                u8::from(r),
                ctx.borrow().info.verdict,
                ctx.borrow().info.file_type_id,
            ));
            hub.set_trace(false, 0);
            hub.set_pt_active(false);
            hub.fpe_type(0, 0);
            lite_arm(hub, |c| c.snort_protocol_id = 0); // UNKNOWN_PROTOCOL_ID

            // K8: type UNKNOWN verdict + the sig ladder end-to-end
            lite_arm(hub, |c| {
                c.snort_protocol_id = 66;
                c.trace_signature = true;
            });
            hub.fpe_type(66, 7);
            hub.set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_UNKNOWN);
            let ctx = hub.fresh(19);
            ctx.borrow_mut().info.config_file_type(true);
            ctx.borrow_mut().info.config_file_signature(true);
            let d = printable_data(40, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                40,
                SNORT_FILE_FULL,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "K8_SIGKICK ret={} ftype={} sha={} sig_state={} s_en={} processed={} size={} complete={}",
                u8::from(r),
                ctx.borrow().info.file_type_id,
                u8::from(ctx.borrow().info.get_file_sig_sha256().is_some()),
                ctx.borrow().info.file_state.sig_state,
                u8::from(ctx.borrow().info.is_file_signature_enabled()),
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.get_file_size(),
                u8::from(ctx.borrow().info.processing_complete),
            ));
            lite_arm(hub, |c| c.trace_signature = false);
            ctx.borrow_mut().info.reset_sha();
        }
        {
            // K9a/K9b: the DEPTH_FAIL ladder (sig ON, type OFF, depth 5)
            let sd = {
                let mut saved = 0i64;
                lite_arm(hub, |c| {
                    saved = c.file_signature_depth;
                    c.file_signature_depth = 5;
                });
                saved
            };
            hub.set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_UNKNOWN);
            hub.set_pt_active(true);
            hub.set_trace(true, TRACE_INFO_LEVEL);
            let ctx = hub.fresh(25);
            ctx.borrow_mut().info.config_file_type(false);
            ctx.borrow_mut().info.config_file_signature(true);
            ctx.borrow_mut().fl_test_processed_bytes_set(3);
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process_pos(
                &ctx,
                &mut p,
                &d,
                10,
                SNORT_FILE_MIDDLE,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "K9a_DEPTH ret={} sig_state={} verdict={}",
                u8::from(r),
                ctx.borrow().info.file_state.sig_state,
                ctx.borrow().info.verdict,
            ));
            hub.set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_LOG);
            let ctx2 = hub.fresh(26);
            ctx2.borrow_mut().info.config_file_type(false);
            ctx2.borrow_mut().info.config_file_signature(true);
            ctx2.borrow_mut().fl_test_processed_bytes_set(3);
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r2 = fctx_process_pos(
                &ctx2,
                &mut p,
                &d,
                10,
                SNORT_FILE_MIDDLE,
                Some(hub.stub_handle.clone()),
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "K9b_DEPTHLOG ret={} sig_state={} verdict={} s_en={}",
                u8::from(r2),
                ctx2.borrow().info.file_state.sig_state,
                ctx2.borrow().info.verdict,
                u8::from(ctx2.borrow().info.is_file_signature_enabled()),
            ));
            hub.set_pt_active(false);
            hub.set_trace(false, 0);
            lite_arm(hub, |c| c.file_signature_depth = sd);
        }
        hub.fpe_type(0, 0);
        lite_arm(hub, |c| c.snort_protocol_id = 0);
        // (1014 entry stays in the global cache — drained at the drop)
    }

    // ============ L: find_file_type_from_ips =========================
    {
        lite_arm(hub, |c| c.snort_protocol_id = 55);
        {
            // L1: depth truncation
            let saved = {
                let mut d0 = 0i64;
                lite_arm(hub, |c| {
                    d0 = c.file_type_depth;
                    c.file_type_depth = 20;
                });
                d0
            };
            let ctx = hub.fresh(20);
            ctx.borrow_mut().fl_test_processed_bytes_set(30);
            hub.fpe_type(0, 0);
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            find_file_type_from_ips(
                &ctx,
                &mut p,
                &d,
                10,
                SNORT_FILE_MIDDLE,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "L1_TRUNC processed={} ftype={}",
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.file_type_id,
            ));
            lite_arm(hub, |c| c.file_type_depth = saved);
        }
        {
            // L2: happy path, no swap
            let ctx = hub.fresh(21);
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            find_file_type_from_ips(
                &ctx,
                &mut p,
                &d,
                10,
                SNORT_FILE_MIDDLE,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "L2_PLAIN ftype={} mult={} proto_bits={} file_pos={} fdp={} ftp={} fpn={}",
                ctx.borrow().info.file_type_id,
                u8::from((p.packet_flags & PKT_ALLOW_MULTIPLE_DETECT) != 0),
                p.proto_bits,
                p.file_pos,
                u8::from(p.file_data.is_some()),
                u8::from(p.file_type_process),
                hub.fpe_calls(),
            ));
        }
        {
            // L3: re-entrant swap (restore guard FALSE side)
            let ctx = hub.fresh(22);
            // C `new FileContext()`: the default ctor ACQUIRES the
            // inspector (file_lib.cc:565 — the extra "IMGR acquire"
            // pinned at vectors line 299 right after fresh(22)'s DE
            // pair; its release at the `delete alt` below).
            let alt = FileContext::ctor(Some(hub.env.imgr.clone()), &hub.env);
            hub.set_trace(true, TRACE_INFO_LEVEL);
            hub.fpe_install(Some(alt.clone()));
            hub.fpe_swap(true);
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            find_file_type_from_ips(
                &ctx,
                &mut p,
                &d,
                10,
                SNORT_FILE_END,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.set_trace(false, 0);
            let cur = {
                let ff = hub.ff.borrow().clone().expect("g_ff");
                ff.borrow().ff_test_current()
            };
            hub.push(format!(
                "L3_REENT cur_is_alt={} cur_is_ctx={} ftype={} finalize={}",
                u8::from(cur.as_ref().is_some_and(|c| Rc::ptr_eq(c, &alt))),
                u8::from(cur.as_ref().is_some_and(|c| Rc::ptr_eq(c, &ctx))),
                ctx.borrow().info.file_type_id,
                u8::from(ctx.borrow().info.file_type_id == 0),
            ));
            hub.fpe_swap(false);
            hub.fpe_install(None);

            // L4: swap + plain witness -> restore (TRUE guard)
            let ctx2 = hub.fresh(23);
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            find_file_type_from_ips(
                &ctx2,
                &mut p,
                &d,
                10,
                SNORT_FILE_FULL,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let cur = {
                let ff = hub.ff.borrow().clone().expect("g_ff");
                ff.borrow().ff_test_current()
            };
            hub.push(format!(
                "L4_RESTORE cur_is_ctx={} ftype={} (finalize -> unk)",
                u8::from(cur.as_ref().is_some_and(|c| Rc::ptr_eq(c, &ctx2))),
                ctx2.borrow().info.file_type_id,
            ));
            // C `delete alt` (probe.cc:578) at exactly this point:
            // owner-delete model — the witness release fires NOW even
            // though driver Rc aliases (the hub's fpe slot was already
            // cleared above) may linger.
            FileContext::owner_delete(&alt);
            drop(alt);

            // L5: current null -> the real swap + restore pair
            let ctx3 = hub.fresh(24);
            {
                let ff = hub.ff.borrow().clone().expect("g_ff");
                ff.borrow_mut().ff_test_current_clear();
            }
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            find_file_type_from_ips(
                &ctx3,
                &mut p,
                &d,
                10,
                SNORT_FILE_MIDDLE,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let cur = {
                let ff = hub.ff.borrow().clone().expect("g_ff");
                ff.borrow().ff_test_current()
            };
            hub.push(format!(
                "L5_SWAPPED cur_null={} cur_ctx={}",
                u8::from(cur.is_none()),
                u8::from(cur.as_ref().is_some_and(|c| Rc::ptr_eq(c, &ctx3))),
            ));
        }
        lite_arm(hub, |c| c.snort_protocol_id = 0);
    }

    // ============ M: process_file_signature_sha256 (REAL sha256) =====
    {
        hub.set_trace(true, TRACE_DEBUG_LEVEL);
        {
            // M0: depth fail
            let sd = {
                let mut s0 = 0i64;
                lite_arm(hub, |c| {
                    s0 = c.file_signature_depth;
                    c.file_signature_depth = 10;
                });
                s0
            };
            let ctx = hub.fresh(30);
            ctx.borrow_mut().set_signature_state(false); // PROCESSING
            let d = printable_data(20, 0);
            ctx.borrow_mut().process_file_signature_sha256(
                &d,
                20,
                SNORT_FILE_START,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M0_DEPTH sig_state={} d_exceeded+{}",
                ctx.borrow().info.file_state.sig_state,
                hub.stat(|c| c.file_sig_depth_exceeded),
            ));
            lite_arm(hub, |c| c.file_signature_depth = sd);
        }
        {
            // M1: FULL "abc" known answer
            let ctx = hub.fresh(31);
            ctx.borrow_mut().set_signature_state(false);
            ctx.borrow_mut().process_file_signature_sha256(
                b"abc",
                3,
                SNORT_FILE_FULL,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M1_FULL sha={} state={}",
                u8::from(ctx.borrow().info.get_file_sig_sha256().is_some()),
                ctx.borrow().info.file_state.sig_state,
            ));
            hub.push("M1_HASH>>>");
            hub.push_dump(&ctx.borrow().print_file_sha256_str());
            hub.push("<<<M1");
        }
        {
            // M2: the FLUSH sandwich + END overwrite + full-stream ref
            let ctx = hub.fresh(32);
            ctx.borrow_mut().set_signature_state(true); // FLUSH
            ctx.borrow_mut().process_file_signature_sha256(
                b"START12345",
                10,
                SNORT_FILE_START,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M2_FLUSH1 sha={} state={}",
                u8::from(ctx.borrow().info.get_file_sig_sha256().is_some()),
                ctx.borrow().info.file_state.sig_state,
            ));
            hub.push("M2_H1>>>");
            hub.push_dump(&ctx.borrow().print_file_sha256_str());
            hub.push("<<<M2");
            ctx.borrow_mut().process_file_signature_sha256(
                b"MID123",
                6,
                SNORT_FILE_MIDDLE,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push("M2_H2>>>");
            hub.push_dump(&ctx.borrow().print_file_sha256_str());
            hub.push("<<<M2");
            ctx.borrow_mut().set_signature_state(false);
            ctx.borrow_mut().process_file_signature_sha256(
                b"MID456",
                6,
                SNORT_FILE_MIDDLE,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M2_MID sha_now={} state={}",
                u8::from(ctx.borrow().info.get_file_sig_sha256().is_some()),
                ctx.borrow().info.file_state.sig_state,
            ));
            ctx.borrow_mut().process_file_signature_sha256(
                b"END1",
                4,
                SNORT_FILE_END,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M2_END state={}",
                ctx.borrow().info.file_state.sig_state
            ));
            hub.push("M2_H3>>>");
            hub.push_dump(&ctx.borrow().print_file_sha256_str());
            hub.push("<<<M2");
            {
                let rf = hub.fresh(33);
                rf.borrow_mut().set_signature_state(false);
                rf.borrow_mut().process_file_signature_sha256(
                    b"START12345MID123456MID456END1",
                    29, // strlen (probe.cc:654) — the FULL-stream known answer
                    SNORT_FILE_FULL,
                    &mut hub.env,
                    &mut hub.counts.borrow_mut(),
                );
                hub.push("M2_HREF>>>");
                hub.push_dump(&rf.borrow().print_file_sha256_str());
                hub.push("<<<M2");
            }
        }
        {
            // M3: MIDDLE/END with null ctx -> early return
            let ctx = hub.fresh(34);
            let d = printable_data(5, 0);
            ctx.borrow_mut().process_file_signature_sha256(
                &d,
                5,
                SNORT_FILE_MIDDLE,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            ctx.borrow_mut().process_file_signature_sha256(
                &d,
                5,
                SNORT_FILE_END,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M3_MISSING sha={} state={}",
                u8::from(ctx.borrow().info.get_file_sig_sha256().is_some()),
                ctx.borrow().info.file_state.sig_state,
            ));
        }
        {
            // M4a/M4b: finish_signature_lookup direct
            hub.set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_UNKNOWN);
            hub.set_trace(true, TRACE_DEBUG_LEVEL);
            let ctx = hub.fresh(35);
            let d = printable_data(20, 0);
            ctx.borrow_mut().process_file_signature_sha256(
                &d,
                20,
                SNORT_FILE_FULL,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            ctx.borrow_mut().info.processing_complete = true;
            let mut p = mk_packet(hub);
            FileContext::finish_signature_lookup(
                &ctx,
                &mut p,
                false,
                Some(hub.stub_handle.clone()),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M4a_FINELSE sha_after={} verdict={} sig_en={} complete={}",
                u8::from(ctx.borrow().info.get_file_sig_sha256().is_some()),
                ctx.borrow().info.verdict,
                u8::from(ctx.borrow().info.is_file_signature_enabled()),
                u8::from(ctx.borrow().info.processing_complete),
            ));
            hub.set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_LOG);
            let ctx2 = hub.fresh(36);
            let d = printable_data(20, 0);
            ctx2.borrow_mut().process_file_signature_sha256(
                &d,
                20,
                SNORT_FILE_FULL,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let mut p = mk_packet(hub);
            FileContext::finish_signature_lookup(
                &ctx2,
                &mut p,
                false,
                Some(hub.stub_handle.clone()),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "M4b_FINTREE verdict={} sha={} sig_en_after={} file_id={}",
                ctx2.borrow().info.verdict,
                u8::from(ctx2.borrow().info.get_file_sig_sha256().is_some()),
                u8::from(ctx2.borrow().info.is_file_signature_enabled()),
                ctx2.borrow().info.get_file_id(),
            ));
            let _ = ff;
            hub.set_trace(false, 0);
        }
        {
            // M5: file_signature_lookup 2 arms + process_file_type 2
            let ctx = hub.fresh(37);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let mut p = mk_packet(hub);
            let v0 = FileContext::file_signature_lookup(&ctx, &mut p, FlowsRef::Handle(&ff));
            let d = printable_data(20, 0);
            ctx.borrow_mut().process_file_signature_sha256(
                &d,
                20,
                SNORT_FILE_FULL,
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.set_policy_verdicts(FILE_VERDICT_UNKNOWN, FILE_VERDICT_BLOCK);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let v1 = FileContext::file_signature_lookup(&ctx, &mut p, FlowsRef::Handle(&ff));
            hub.push(format!("M5_SIGLOOK v0={v0} v1={v1}"));
            ctx.borrow_mut().info.reset_sha();
            let fpn0 = hub.fpe_calls();
            ctx.borrow_mut().info.set_file_type(9);
            let d = printable_data(10, 0);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let mut p = mk_packet(hub);
            FileContext::process_file_type(
                &ctx,
                &mut p,
                &d,
                10,
                SNORT_FILE_MIDDLE,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let fpn1 = hub.fpe_calls();
            lite_arm(hub, |c| c.snort_protocol_id = 77);
            hub.fpe_type(77, 11);
            let ctx2 = hub.fresh(38);
            let d = printable_data(10, 0);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let mut p = mk_packet(hub);
            FileContext::process_file_type(
                &ctx2,
                &mut p,
                &d,
                10,
                SNORT_FILE_MIDDLE,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            lite_arm(hub, |c| c.snort_protocol_id = 0);
            hub.fpe_type(0, 0);
            hub.push(format!(
                "M5_PFT fpn_delta_noref={} ftype={}",
                fpn1 - fpn0,
                ctx2.borrow().info.file_type_id,
            ));
        }
        hub.set_trace(false, 0);
    }

    // ============ N: process_file_capture (mempool-backed) ===========
    {
        hub.set_block_size(16);
        hub.init_mempool();
        let cmax_saved = {
            let mut s0 = 0i64;
            lite_arm(hub, |c| {
                s0 = c.capture_max_size;
                c.capture_max_size = 15; // FileCapture ctor -> MAX arm
            });
            s0
        };
        {
            let ctx = hub.fresh(40);
            let d = printable_data(10, 0);
            let st = fctx_capture(&ctx, &d, 10, SNORT_FILE_START, &mut hub.env);
            hub.push(format!(
                "N1_START st={} cap_en={} state_cap={}",
                st,
                u8::from(ctx.borrow().info.is_file_capture_enabled()),
                ctx.borrow().info.file_state.capture_state,
            ));
            let d = printable_data(12, 0);
            let st2 = fctx_capture(&ctx, &d, 12, SNORT_FILE_MIDDLE, &mut hub.env);
            hub.push(format!(
                "N2_MAX st={} cap_en_after={}",
                st2,
                u8::from(ctx.borrow().info.is_file_capture_enabled()),
            ));
            let d = printable_data(4, 0);
            let st3 = fctx_capture(&ctx, &d, 4, SNORT_FILE_MIDDLE, &mut hub.env);
            hub.push(format!(
                "N3_AFTER st={} cap_en={}",
                st3,
                u8::from(ctx.borrow().info.is_file_capture_enabled()),
            ));
            let st4 = fctx_capture(&ctx, &d, 4, SNORT_FILE_FULL, &mut hub.env);
            hub.merge_wc();
            hub.push(format!(
                "N4_FULL st={} within+{} buffered+{}",
                st4,
                hub.stat(|c| c.file_within_packet),
                hub.stat(|c| c.files_buffered_total),
            ));
        }
        lite_arm(hub, |c| c.capture_max_size = cmax_saved);
        {
            // N5: block 700000 -> a single-slot pool (1 MiB/(bs+64));
            // an 800000 buffer force-splits -> second create memcaps
            let ctx = hub.fresh(41);
            hub.set_block_size(700000);
            hub.init_mempool();
            let big: Vec<u8> = (0..800000u32).map(|i| i as u8).collect();
            let st = fctx_capture(&ctx, &big, 800000, SNORT_FILE_START, &mut hub.env);
            hub.merge_wc();
            hub.push(format!(
                "N5_MEMCAP st={} memcap_fail+{} bufs_alloc+{}",
                st,
                hub.stat(|c| c.file_memcap_failures_total),
                hub.stat(|c| c.file_buffers_allocated_total),
            ));
        }
        // restore defaults for later blocks (probe.cc:772-776): ONLY
        // FileCapture::capture_block_size = 0 and
        // FileService::file_capture_enabled = false — the type/sig
        // service statics stay ON (pinned: the N5 fresh_ctx re-emits
        // "WITNESS get_network_POLICY"/"POLICY base_file_policy" after
        // one IMGR release, i.e. ~FileFlows + a NEW FileFlows build,
        // which get_file_flows only does while is_file_service_enabled).
        // The port never sets the service-level capture bit (the O
        // block reaches capture through the FileInfo per-ctx bit only).
        hub.set_block_size(0);
    }

    // ============ O: offset process -> FileSegments ==================
    {
        lite_arm(hub, |c| c.snort_protocol_id = 0);
        hub.set_trace(true, TRACE_INFO_LEVEL);
        {
            // O1: single FULL blob via the offset form
            hub.fpe_type(0, 7);
            let ctx = hub.fresh(50);
            let d = printable_data(8, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let r = fctx_process(
                &ctx,
                &mut p,
                &d,
                8,
                0,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_FULL,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "O1_FULL ret={} queued={} processed={} size={} ftype={}",
                u8::from(r),
                u8::from(ctx.borrow().segments_queued()),
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.get_file_size(),
                ctx.borrow().info.file_type_id,
            ));
            hub.fpe_type(0, 0);
        }
        hub.fpe_type(66, 7);
        lite_arm(hub, |c| c.snort_protocol_id = 66);
        {
            // O2: drop + partial-trim arms
            let ctx = hub.fresh(51);
            ctx.borrow_mut().info.config_file_type(true);
            ctx.borrow_mut().info.set_file_size(100);
            let d = printable_data(10, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let a = fctx_process(
                &ctx,
                &mut p,
                &d,
                10,
                0,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let d = printable_data(5, 1);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let b = fctx_process(
                &ctx,
                &mut p,
                &d,
                5,
                0,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let d = printable_data(10, 5);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let c = fctx_process(
                &ctx,
                &mut p,
                &d,
                10,
                5,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "O2_DROP a={} b={} c={} queued={} processed={}",
                u8::from(a),
                u8::from(b),
                u8::from(c),
                u8::from(ctx.borrow().segments_queued()),
                ctx.borrow().get_processed_bytes(),
            ));
        }
        {
            // O3: the full TRUE-side drain + the self-disable quirk
            let ctx = hub.fresh(52);
            ctx.borrow_mut().info.set_file_size(30);
            ctx.borrow_mut().info.config_file_type(true);
            let d = printable_data(6, 0);
            let mut p = mk_packet(hub);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let a = fctx_process(
                &ctx,
                &mut p,
                &d,
                6,
                0,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            let d = printable_data(6, 12);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let b = fctx_process(
                &ctx,
                &mut p,
                &d,
                6,
                12,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "O3a a={} b={} queued={} processed={}",
                u8::from(a),
                u8::from(b),
                u8::from(ctx.borrow().segments_queued()),
                ctx.borrow().get_processed_bytes(),
            ));
            ctx.borrow_mut().info.config_file_type(true);
            let d = printable_data(6, 6);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let c = fctx_process(
                &ctx,
                &mut p,
                &d,
                6,
                6,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "O3b c={} processed={} size={} complete={}",
                u8::from(c),
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.get_file_size(),
                u8::from(ctx.borrow().info.processing_complete),
            ));
            let d = printable_data(6, 18);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let dflag = fctx_process(
                &ctx,
                &mut p,
                &d,
                6,
                18,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "O3c d={} processed={} complete={}",
                u8::from(dflag),
                ctx.borrow().get_processed_bytes(),
                u8::from(ctx.borrow().info.processing_complete),
            ));
            ctx.borrow_mut().info.config_file_type(true);
            let d = printable_data(6, 0);
            let ff = hub.ff.borrow().clone().expect("g_ff");
            let e = fctx_process(
                &ctx,
                &mut p,
                &d,
                6,
                0,
                Some(hub.stub_handle.clone()),
                SNORT_FILE_POSITION_UNKNOWN,
                &mut hub.flows_ref(&ff),
                &mut hub.env,
                &mut hub.counts.borrow_mut(),
            );
            hub.push(format!(
                "O3d e={} processed={} queued={}",
                u8::from(e),
                ctx.borrow().get_processed_bytes(),
                u8::from(ctx.borrow().segments_queued()),
            ));
        }
        hub.set_trace(true, TRACE_DEBUG_LEVEL);
        lite_arm(hub, |c| c.snort_protocol_id = 66);
        hub.fpe_type(66, SNORT_FILE_TYPE_CONTINUE);
        {
            // O4: the CONTINUE-type multi-segment drain, END terminal
            let ctx = hub.fresh(53);
            ctx.borrow_mut().info.config_file_type(true);
            ctx.borrow_mut().info.set_file_size(40);
            let feed = |hub: &mut Hub,
                            ctx: &Rc<RefCell<FileContext>>,
                            data: &[u8],
                            size: i32,
                            off: u64|
             -> bool {
                let mut p = mk_packet(hub);
                let ff = hub.ff.borrow().clone().expect("g_ff");
                fctx_process(
                    ctx,
                    &mut p,
                    data,
                    size,
                    off,
                    Some(hub.stub_handle.clone()),
                    SNORT_FILE_POSITION_UNKNOWN,
                    &mut hub.flows_ref(&ff),
                    &mut hub.env,
                    &mut hub.counts.borrow_mut(),
                )
            };
            // (the probe arms the type feature back before a/c/e — the
            // found-type self-disable quirk is itself pinned at O3c)
            let a = feed(hub, &ctx, &printable_data(10, 0), 10, 0);
            let b = feed(hub, &ctx, &printable_data(10, 20), 10, 20);
            ctx.borrow_mut().info.config_file_type(true);
            let c = feed(hub, &ctx, &printable_data(10, 12), 10, 12);
            hub.push(format!(
                "O4a a={} b={} c={} processed={}",
                u8::from(a),
                u8::from(b),
                u8::from(c),
                ctx.borrow().get_processed_bytes(),
            ));
            let dflag = feed(hub, &ctx, &printable_data(5, 5), 5, 5);
            hub.push(format!(
                "O4b_drop d={} processed={}",
                u8::from(dflag),
                ctx.borrow().get_processed_bytes(),
            ));
            let e = feed(hub, &ctx, &printable_data(2, 10), 2, 10);
            hub.push(format!(
                "O4c_drain e={} processed={} size={} complete={}",
                u8::from(e),
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.get_file_size(),
                u8::from(ctx.borrow().info.processing_complete),
            ));
            let g2 = feed(hub, &ctx, &printable_data(10, 30), 10, 30);
            hub.push(format!(
                "O4d_END g={} processed={} size={} complete={} ftype={} queued={}",
                u8::from(g2),
                ctx.borrow().get_processed_bytes(),
                ctx.borrow().info.get_file_size(),
                u8::from(ctx.borrow().info.processing_complete),
                ctx.borrow().info.file_type_id,
                u8::from(ctx.borrow().segments_queued()),
            ));
        }
        hub.fpe_type(0, 0);
        hub.set_trace(false, 0);
        lite_arm(hub, |c| c.snort_protocol_id = 0);
        {
            // O5: FALSE from the flushed feed -> clear drops the backlog
            let ctx = hub.fresh(54);
            ctx.borrow_mut().info.config_file_type(true);
            ctx.borrow_mut().info.config_file_signature(false);
            ctx.borrow_mut().info.set_file_size(50);
            hub.set_trace(true, TRACE_DEBUG_LEVEL);
            let feed = |hub: &mut Hub,
                            ctx: &Rc<RefCell<FileContext>>,
                            data: &[u8],
                            size: i32,
                            off: u64|
             -> bool {
                let mut p = mk_packet(hub);
                let ff = hub.ff.borrow().clone().expect("g_ff");
                fctx_process(
                    ctx,
                    &mut p,
                    data,
                    size,
                    off,
                    Some(hub.stub_handle.clone()),
                    SNORT_FILE_POSITION_UNKNOWN,
                    &mut hub.flows_ref(&ff),
                    &mut hub.env,
                    &mut hub.counts.borrow_mut(),
                )
            };
            let q = feed(hub, &ctx, &printable_data(10, 20), 10, 20);
            dbg_marker_noop(q);
            lite_arm(hub, |c| c.snort_protocol_id = 66);
            hub.fpe_type(66, SNORT_FILE_TYPE_UNKNOWN);
            let r = feed(hub, &ctx, &printable_data(8, 0), 8, 0);
            hub.push(format!(
                "O5_CLEAR r={} queued_ptr={} complete={} processed={}",
                u8::from(r),
                u8::from(ctx.borrow().segments_queued()),
                u8::from(ctx.borrow().info.processing_complete),
                ctx.borrow().get_processed_bytes(),
            ));
            hub.fpe_type(0, 0);
            lite_arm(hub, |c| c.snort_protocol_id = 0);
            let q2 = feed(hub, &ctx, &printable_data(10, 20), 10, 20);
            hub.push(format!(
                "O5b q2={} queued={}",
                u8::from(q2),
                u8::from(ctx.borrow().segments_queued()),
            ));
            hub.set_trace(false, 0);
        }
        hub.fpe_type(0, 0);
        lite_arm(hub, |c| c.snort_protocol_id = 0);
    }

    // ============ P2: remove_segments =================================
    {
        let ctx = hub.fresh(60);
        ctx.borrow_mut().info.config_file_type(false);
        ctx.borrow_mut().info.config_file_signature(false);
        ctx.borrow_mut().info.set_file_size(40);
        let d = printable_data(6, 10);
        let mut p = mk_packet(hub);
        let ff = hub.ff.borrow().clone().expect("g_ff");
        let _ = fctx_process(
            &ctx,
            &mut p,
            &d,
            6,
            10,
            Some(hub.stub_handle.clone()),
            SNORT_FILE_POSITION_UNKNOWN,
            &mut hub.flows_ref(&ff),
            &mut hub.env,
            &mut hub.counts.borrow_mut(),
        );
        let q1 = ctx.borrow().segments_queued();
        ctx.borrow_mut().remove_segments();
        let q2 = ctx.borrow().segments_queued();
        hub.push(format!(
            "P2_SEGS queued1={} queued2={}",
            u8::from(q1),
            u8::from(q2)
        ));
    }

    // delete g_ff FIRST (drains current/ppc releases), then the
    // global cache entry (1014), as at C static-destruction time the
    // transcript pins (4 trailing releases).
    let ff = hub.ff.borrow_mut().take();
    ff.as_ref()
        .map(|f| f.borrow_mut().dtor())
        .unwrap_or(()); // probe delete g_ff (owner-drain NOW)
    drop(ff);
    // C: `g_cache` is a static; its death (static dtor at exit, after
    // every section) is its ONLY release point. The port's seam copy
    // in env.svc must let go first so drop(_cache) below is the real
    // ~FileCache (delete fileHash -> per-node free_user_data -> the 3
    // pinned trailing IMGR releases).
    hub.env.svc.set_file_cache(None);
    drop(_cache);

    // transcript assertion
    let want: Vec<&str> = VECTORS.trim_end_matches('\n').lines().collect();
    let got = hub.out.borrow();
    if std::env::var("FCTX_DUMP").is_ok() {
        let _ = std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../cache/scratch/fctx_got.txt"),
            got.join("\n") + "\n",
        );
    }
    for (i, w) in want.iter().enumerate() {
        let g = got.get(i).map(String::as_str).unwrap_or("<MISSING>");
        assert_eq!(g, *w, "transcript line {} mismatch", i + 1);
    }
    assert_eq!(got.len(), want.len(), "transcript length mismatch");
}

fn dbg_marker_noop<T>(_t: T) {}

/// Probe `fc->member = v` arms: mutate the ONE harness FileConfig
/// (lite) and re-sync the ctx-visible copy (the two-view deviation).
fn lite_arm(hub: &mut Hub, f: impl FnOnce(&mut FileConfigLite)) {
    {
        let lite = &mut *hub.lite.borrow_mut();
        f(lite);
    }
    hub.sync_view();
}

// -------------------------------------------------------------------
// Faithful translations of the C++ [file_mempool] gate — the verbatim
// `#ifdef UNIT_TEST` block (file_mempool.cc:223-303, 3 TEST_CASEs / 27
// assertions). mark_block_in_use = the pool seam that clears the FREE
// magic (the production caller writes the block header right after
// m_alloc; the UT models it via the Rust port's pub method).
// -------------------------------------------------------------------

#[test]
fn up_gate_mempool_free_detects_double_free() {
    // "FileMemPool m_free detects double free" — 2 CHECKs + 1 REQUIRE.
    let mut pool = FileMemPool::new(2, 8);
    let ptr = pool.m_alloc().expect("ptr != nullptr");
    pool.mark_block_in_use(Some(ptr));
    assert_eq!(pool.m_free(Some(ptr)), FILE_MEM_SUCCESS);
    assert_eq!(pool.m_free(Some(ptr)), FILE_MEM_FAIL);
}

#[test]
fn up_gate_mempool_free_no_duplicate_queue() {
    // "m_free double free does not duplicate queue entries" —
    // 3 REQUIREs + 3 identity REQUIREs + 3 CHECKs + 2 REQUIREs + CHECK.
    let mut pool = FileMemPool::new(3, 8);
    let a = pool.m_alloc();
    let b = pool.m_alloc();
    let c = pool.m_alloc();
    let (a, b, c) = (a.expect("a"), b.expect("b"), c.expect("c"));
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    pool.mark_block_in_use(Some(a));
    pool.mark_block_in_use(Some(b));
    assert_eq!(pool.m_free(Some(a)), FILE_MEM_SUCCESS);
    assert_eq!(pool.m_free(Some(a)), FILE_MEM_FAIL);
    assert_eq!(pool.m_free(Some(b)), FILE_MEM_SUCCESS);
    let first = pool.m_alloc().expect("first");
    let second = pool.m_alloc().expect("second");
    assert_ne!(first, second);
}

#[test]
fn up_gate_mempool_release_no_duplicate_queue() {
    // "m_release double free does not duplicate queue entries" — the
    // releaseList twin, same 12 assertions.
    let mut pool = FileMemPool::new(3, 8);
    let a = pool.m_alloc();
    let b = pool.m_alloc();
    let c = pool.m_alloc();
    let (a, b, c) = (a.expect("a"), b.expect("b"), c.expect("c"));
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    pool.mark_block_in_use(Some(a));
    pool.mark_block_in_use(Some(b));
    assert_eq!(pool.m_release(Some(a)), FILE_MEM_SUCCESS);
    assert_eq!(pool.m_release(Some(a)), FILE_MEM_FAIL);
    assert_eq!(pool.m_release(Some(b)), FILE_MEM_SUCCESS);
    let first = pool.m_alloc().expect("first");
    let second = pool.m_alloc().expect("second");
    assert_ne!(first, second);
}
