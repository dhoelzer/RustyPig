// Port of snort3 file_api/file_cache.{h,cc} — plan row 17p.
//
// Seam vocabulary (several types here are only consumed once the later
// rows wire them; same discipline as hash/xhash.rs):
#![allow(dead_code)]
//
// Ground truth: /opt/data/snort3-src @ fe29cbe7403a — file_cache.h
// (115 lines) + file_cache.cc (1287 lines). The C++ TU's embedded
// `#ifdef UNIT_TEST` [file_cache] block (file_cache.cc:1140-1287)
// drives this row's verification tests; it is not transcribed into
// src/ (row contract: no tests written by this agent).
//
// Everything file_cache.cc CALLS into that later rows own is declared
// here as an explicit seam at the exact signatures the C++ TU uses (the
// 17o witness pattern):
//
//   * `FileInfo`     — already ported (`file_lib.rs`, row 17o). C++'s
//     `FileContext` derives from it: modeled as the embedded `info`.
//   * `FileContext`  — its full body is the second half of file_lib.cc
//     (row 17q). Only the members file_cache.cc touches are carried,
//     each copied from the real file_lib.h declaration.
//   * `Flow`/`Packet`/`Active`/`FileFlows`/`InspectorManager`/
//     `FilePolicyBase`/`PacketTracer`/`ControlConn`/`SnortConfig`/
//     MPDataBus/`time/packet_time` — unported subsystems; seams below.
//   * FILE_DEBUG trace lines (file_trace) — omitted exactly as in
//     file_lib.rs (row 17o precedent; the 17o gate pinned the trace
//     witness silent); the C call sites are kept as comments.
//
// Deviations (recorded in KNOWN DEVIATIONS.md, row 17p):
//   * `std::mutex cache_mutex` / `std::recursive_mutex
//     user_file_data_mutex` / `std::atomic<int64_t>` timeouts are NOT
//     reproduced: the port models the single-threaded data plane the
//     gates run with, Rust exclusive borrows standing in for the locks
//     (precedent: hash/lru_cache_shared.rs). `CacheNodePin` keeps the
//     C pin/unpin accounting faithfully.
//   * XHash's `void* data` slot carries an index into the wrapper's
//     FileNode arena (no pointer casts). The C++
//     `ExpectedFileCache::is_node_recovery_ok` / `free_user_data`
//     virtuals are re-asserted by the wrapper around XHash's pin-list
//     hook (hash/xhash.rs precedent): around `insert` the keys of
//     not-recoverable nodes are pinned (the exact answer the virtual
//     gives per walked node), and any ANR victim is detected after the
//     insert by its dead back-link, dropping the FileContext exactly as
//     `free_user_data` deletes it (file_cache.cc:68-91).
//   * C++ stores FileNode *by value* inside the hash node's datasize
//     block; the port keeps it in the wrapper arena and clones the one
//     Rc handle the C++ `(FileNode*)hnode->data` reads yield.
//   * THREAD_LOCAL `file_counts` (file_stats.cc:32) is a driver-owned
//     `&mut FileCounts` at every counting call site (rows 17m/17o
//     discipline). `ErrorMessage(...)` in set_max_files is a comment
//     until the log row.
//   * `new FileContext` reaches the globals
//     (InspectorManager::acquire_file_inspector(),
//     SnortConfig::get_conf()); FileCache::new_file_context gates nulls
//     exactly as the C++ ctor does.
//   * The C++ `FileInfo*`/`FileInfo&` parameters of
//     publish_flow_verdict_locked / store_shared_verdict /
//     take_pending_file_data are FileContext handles in every real
//     path (the C++ argument is always a FileContext sliced to its
//     FileInfo base); the port threads the whole handle and compares
//     aliasing with `Rc::ptr_eq` instead of raw pointer `==`. Each
//     aliased C++ case is a self-guarded no-op (file_lib assign/copy
//     ptr::eq guards, row 17o) and is mirrored by an early return.
//   * C overloads `get_file` at 4 and 7 params; Rust cannot overload:
//     `get_file` (private, 7-arg) + `get_file_public` (4-arg).
//   * `SnortConfig::get_conf()->mp_dbus` (snort_config.h:391) and
//     FileContext's raw FileConfig*/FileInspect* pointers: Rc shared
//     seams with identical null-gating. `make_key` keeps C's uint32
//     `addressSpaceId` -> uint16 `asid` truncation and the deliberate
//     client/server swap (dip=client_ip, sip=server_ip,
//     file_cache.cc:363).
//   * Control-console printf field widths (%-20s byte semantics) via
//     `pad_c`; byte-carrying names render through
//     `String::from_utf8_lossy` (names carry raw 0xFF/UTF-16, 17o).
//   * FileHashKey wire layout probe-verified from the verbatim headers
//     (g++ + the filib include graft): sizeof(FileHashKey)=56,
//     sip@0 sgroup@18 dip@20 dgroup@38 file_id@40 asid@48 padding@50;
//     SfIp = 18 bytes (ip8[16] + family i16); sizeof(FileCache::
//     FileNode)=24; sizeof(timeval)=16.
//   * `log_file_event`'s DataBus body is row 17q (file_lib.cc:613);
//     the call sites stay literal through `FileCacheEventSink`.

use std::cell::RefCell;
use std::rc::Rc;

use super::file_lib::{
    FILE_DOWNLOAD, FILE_VERDICT_BLOCK, FILE_VERDICT_LOG, FILE_VERDICT_PENDING,
    FILE_VERDICT_REJECT, FILE_VERDICT_STOP_CAPTURE, FILE_VERDICT_UNKNOWN, TimeVal, VERDICT_NAME,
    SHA256_HASH_SIZE,
};
// (row 17q) FileContext moved to file_lib.rs; re-exported here so the
// committed 17p wiring (`use snort3::file_api::file_cache::*`) keeps
// resolving the type in this module's namespace.
pub use super::file_lib::FileContext;
use super::file_stats::FileCounts;
use crate::hash::{HASH_NOMEM, HASH_OK, XHash};
use crate::sfip::sf_ip::SfIp;

// ------------------------------------------------------------------
// file_config.h constants used by the in-class field initializers
// (the FileConfig class itself: a later row).
// ------------------------------------------------------------------

/// file_config.h:33 `#define DEFAULT_FILE_BLOCK_TIMEOUT 86400 /*1 day*/`
pub const DEFAULT_FILE_BLOCK_TIMEOUT: i64 = 86400;
/// file_config.h:34 `#define DEFAULT_FILE_LOOKUP_TIMEOUT 2 /*2 seconds*/`
pub const DEFAULT_FILE_LOOKUP_TIMEOUT: i64 = 2;
/// file_config.h:39 `#define DEFAULT_MAX_FILES_CACHED 65536`
pub const DEFAULT_MAX_FILES_CACHED: i64 = 65536;
/// file_cache.cc:52 `#define DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM 3600`
const DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM: i64 = 3600; // 1 hour

/// file_api.h:121 `struct FileCacheClearReport { uint64_t freed = 0;
/// uint64_t remaining = 0; };`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileCacheClearReport {
    pub freed: u64,
    pub remaining: u64,
}

// ------------------------------------------------------------------
// FileHashKey (file_cache.h:40, PADDING_GUARD block). C hashes and
// memcmps the raw struct bytes; layout PROBED from the verbatim
// headers: sizeof=56; sip@0, sgroup@18, dip@20, dgroup@38, file_id@40,
// asid@48, padding[3]@50.
// ------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileHashKey {
    pub sip: SfIp,
    pub sgroup: i16, // = 0
    pub dip: SfIp,
    pub dgroup: i16, // = 0
    pub file_id: u64, // = 0
    pub asid: u16,   // = 0
                     // uint16_t padding[3] = {}; implicit zeros in to_bytes
}

/// sizeof(FileHashKey) — probe-pinned (module header).
pub const FILE_HASH_KEY_BYTES: usize = 56;

impl FileHashKey {
    /// The struct's on-wire bytes exactly as XHash hashes / memcmps
    /// them in C (member offsets probe-pinned; the trailing
    /// `padding[3]` stays zero because `make_key` starts at
    /// `hashKey = {};`).
    pub fn to_bytes(&self) -> [u8; FILE_HASH_KEY_BYTES] {
        let mut b = [0u8; FILE_HASH_KEY_BYTES];
        b[0..16].copy_from_slice(&self.sip.ip8); // sip.ip8 @0
        b[16..18].copy_from_slice(&self.sip.family.to_le_bytes()); // sip.family @16
        b[18..20].copy_from_slice(&self.sgroup.to_le_bytes()); // sgroup @18
        b[20..36].copy_from_slice(&self.dip.ip8); // dip.ip8 @20
        b[36..38].copy_from_slice(&self.dip.family.to_le_bytes()); // dip.family @36
        b[38..40].copy_from_slice(&self.dgroup.to_le_bytes()); // dgroup @38
        b[40..48].copy_from_slice(&self.file_id.to_le_bytes()); // file_id @40
        b[48..50].copy_from_slice(&self.asid.to_le_bytes()); // asid @48
        b
    }
}

// ------------------------------------------------------------------
// Seams for unported subsystems (17o witness pattern; each documents
// its C origin).
// ------------------------------------------------------------------

/// The `Flow` members `make_key` reads (flow/flow.h client_group:583;
/// flow/flow_key.h addressSpaceId:56). The Flow monolith itself is a
/// flow row; this carries exactly the members the C++ file touches.
/// C keeps `Flow*` live through the calls; the port passes value views
/// (no flow mutation happens in this TU).
#[derive(Clone, Copy, Debug, Default)]
pub struct CacheFlow {
    pub client_ip: SfIp,
    pub client_group: i16,
    pub server_ip: SfIp,
    pub server_group: i16,
    pub address_space_id: u32, // FlowKey::addressSpaceId (uint32 in C)
    /// flow.h:287 `two_way_traffic()` — read by the log_file_event call
    /// sites (file_lib.cc:615, body row 17q through the event sink).
    pub two_way_traffic: bool,
    // `char* service` (read by FileContext::set_source, file_lib.cc:
    // 608): CacheFlow stays Copy with the committed 17p field set (the
    // fcache test literal + by-value convention); the service name
    // rides the driver-armed FileEnvLite flow_service Cell (row 17q
    // deviation — the C char* is static storage anyway, and every
    // pinned line renders source- with the null/empty answer).
}

/// `packet_io/active.h:64` `ActiveActionType` values this file sets
/// through `set_delayed_action(type, true)` (ACT_TRUST=0 ...).
pub const ACT_TRUST: u8 = 0;
pub const ACT_ALLOW: u8 = 1;
pub const ACT_HOLD: u8 = 2;
pub const ACT_RETRY: u8 = 3;
pub const ACT_REWRITE: u8 = 4;
pub const ACT_DROP: u8 = 5;
pub const ACT_BLOCK: u8 = 6;
pub const ACT_RESET: u8 = 7;
pub const ACT_MAX: u8 = 8;

/// The `Active` members file_cache.cc drives (full Active: packet_io
/// row). `p->active` is a field of PacketView below, matching the C
/// `Active* act = p->active;` aliasing.
#[derive(Clone, Default)]
pub struct ActiveState {
    pub delayed_action: Option<u8>,
    pub drop_reason: Option<&'static str>,
    /// Witness seam for the unported `Active` setters (stubs.cc body at
    /// the 17p harness prints ACT lines when reached). The port's setters
    /// keep the C field discipline; the sink sees the exact same call
    /// boundary the C harness witnessed.
    pub witness: Option<Rc<RefCell<dyn ActiveWitness>>>,
}

/// `Active::set_delayed_action` / `set_drop_reason` witness seam (the
/// Active monolith itself is a later row).
pub trait ActiveWitness {
    fn delayed_action(&mut self, action: u8, force: bool);
    fn drop_reason(&mut self, reason: &str);
}

impl ActiveState {
    /// `Active::set_delayed_action(ActiveActionType, bool force)`
    /// (active.h:179) — only the force=true call sites exist here.
    fn set_delayed_action(&mut self, action: u8) {
        self.delayed_action = Some(action);
        if let Some(w) = &self.witness {
            w.borrow_mut().delayed_action(action, true);
        }
    }
    /// `Active::set_drop_reason(const char*)` (active.h:187) — "file".
    fn set_drop_reason(&mut self, reason: &'static str) {
        self.drop_reason = Some(reason);
        if let Some(w) = &self.witness {
            w.borrow_mut().drop_reason(reason);
        }
    }
}

/// `protocols/packet.h:82-83`
pub const PKT_RETRANSMIT: u32 = 0x01000000;
pub const PKT_RETRY: u32 = 0x02000000;

/// `protocols/packet.h:58-59,104` (row 17q: get_file_position arms)
pub const PKT_PDU_HEAD: u32 = 0x0000_0100;
pub const PKT_PDU_TAIL: u32 = 0x0000_0200;
pub const PKT_PDU_FULL: u32 = PKT_PDU_HEAD | PKT_PDU_TAIL;

/// `protocols/packet.h:62` PKT_ALLOW_MULTIPLE_DETECT (file_lib.cc:1026
/// `p->packet_flags |=` arm of find_file_type_from_ips; row 17r).
pub const PKT_ALLOW_MULTIPLE_DETECT: u32 = 0x0000_0800;
/// `framework/decode_data.h:93` PROTO_BIT__PDU (file_lib.cc:1027
/// `p->proto_bits |=` arm — pinned = 64 by the L2_vectors vector line;
/// row 17r).
pub const PROTO_BIT__PDU: u64 = 0x0040;

/// The per-packet state file_cache.cc reads: `p->flow`,
/// `p->packet_flags`, `p->is_retry()` (packet.h:336), `p->active`, and
/// the `p->context->conf` that `get_file_config(p->context->conf)`
/// consults (file_config.h:79).
#[derive(Clone, Default)]
pub struct PacketView {
    pub flow: CacheFlow,
    pub packet_flags: u32,
    pub active: ActiveState,
    pub conf: FileConfigView,
    // Row 17r (find_file_type_from_ips, file_lib.cc:1021-1027): the
    // IpsContext witness shape the C TU writes through
    // `p->context->...` — mirrored as PacketView fields (deviation:
    // the Rust view folds packet + IpsContext into one value; the
    // vectors pin the post-write reads L2_PLAIN / L2_*).
    /// `IpsContext::proto_bits` (framework/decode_data.h ladder; the
    /// PROTO_BIT__PDU |= arm reads back = 64 in L2_PLAIN).
    pub proto_bits: u64,
    /// `IpsContext::file_data` (`std::string_view {ptr, len}`): the
    /// Some(vec) models the non-null view (fdp=1 pin); len rides the
    /// Vec (the C truncated int width is re-materialized at the read).
    pub file_data: Option<Vec<u8>>,
    /// `IpsContext::file_pos` (uint64; = processed_bytes at the write)
    pub file_pos: u64,
    /// `IpsContext::file_type_process` (bool)
    pub file_type_process: bool,
    /// `IpsContext::set_snort_protocol_id(SnortProtocolId)` — int
    /// storage (UNKNOWN_PROTOCOL_ID = 0 per A_ENUM spid=0 pin)
    pub snort_protocol_id: i32,
}

impl PacketView {
    /// `Packet::is_retry()` (packet.h:336)
    pub fn is_retry(&self) -> bool {
        (self.packet_flags & PKT_RETRY) != 0
    }
    /// `Packet::is_full_pdu()` (packet.h:321) — row 17q
    /// get_file_position ladder.
    pub fn is_full_pdu(&self) -> bool {
        (self.packet_flags & PKT_PDU_FULL) == PKT_PDU_FULL
    }
    /// `Packet::is_pdu_start()` (packet.h:324)
    pub fn is_pdu_start(&self) -> bool {
        (self.packet_flags & PKT_PDU_HEAD) != 0
    }
}

/// `file_api.h:43` `enum FileAction`
pub const FILE_ACTION_DEFAULT: u32 = 0;
pub const FILE_RESUME_BLOCK: u32 = 1;
pub const FILE_RESUME_LOG: u32 = 2;

/// The `FileConfig`/`SnortConfig` fields this file reaches through
/// Copy views: `fc->block_timeout_lookup` (file_config.h:59, default
/// false) and `SnortConfig::get_conf()->mp_dbus` (snort_config.h:391,
/// default null=false). Row 17q adds the config-MEMBER fields the
/// FileContext print tail reads: `trace_type` (file_config.h:71,
/// default false) — the view stays `Copy` because PacketView::conf and
/// the harness share it by value (17p pinned). The full C-declared
/// field set rides `FileConfigLite` in file_lib.rs (the
/// `get_file_config()` resolution side; row 17q).
#[derive(Clone, Copy, Debug)]
pub struct FileConfigView {
    pub block_timeout_lookup: bool,
    pub mp_dbus: bool,
    /// file_config.h:71 (the `config->trace_type` dead tail gate)
    pub trace_type: bool,
    // Row 17r (process position-form ladder, file_lib.cc:834/:953):
    // file_config.h:72-74 `trace_signature` / `trace_stream` + the
    // :836 `show_data_depth` hexdump clamp. C defaults: false/false/100
    // (defaults at FileConfigLite; the view's derive-Default zeroes
    // show_data_depth — harness arms it).
    pub trace_signature: bool,
    pub trace_stream: bool,
    pub show_data_depth: i64,
    /// file_config.h:48 `file_signature_depth` (the
    /// process_file_signature_sha256 gate, file_lib.cc:1070; row 17r
    /// grows the view). Default hand-written below: a derive would
    /// zero the C 10 MiB default and depth-fail every armed ladder
    /// off a FileConfigView::default()-built driver config (the old
    /// doc note "derive-Default zeroes show_data_depth — harness
    /// arms it" is retired: the trio now defaults to the C values;
    /// the harness arms stay).
    pub file_signature_depth: i64,
}

impl Default for FileConfigView {
    /// C in-class initializers (file_config.h): everything false,
    /// show_data_depth 100 (DEFAULT_FILE_SHOW_DATA_DEPTH),
    /// file_signature_depth DEFAULT_FILE_SIGNATURE_DEPTH (10 MiB).
    fn default() -> Self {
        FileConfigView {
            block_timeout_lookup: false,
            mp_dbus: false,
            trace_type: false,
            trace_signature: false,
            trace_stream: false,
            show_data_depth: super::file_lib::DEFAULT_FILE_SHOW_DATA_DEPTH,
            file_signature_depth: super::file_lib::DEFAULT_FILE_SIGNATURE_DEPTH,
        }
    }
}

impl FileConfigView {
    /// harness-view resolution of `FileConfig::file_type_name`
    /// (file_config.cc:63-77): the two special-case ids answer
    /// literally; the private FileIdentifier table does not ride the
    /// Copy view (deviation: the full table rides `FileConfigLite` —
    /// `FileEnvLite::file_type_name`; no pinned transcript resolves a
    /// table id through the config-member path, and the print tail is
    /// dead with trace_type=false).
    pub fn file_type_name(&self, id: u32) -> String {
        if super::file_lib::SNORT_FILE_TYPE_UNKNOWN == id {
            "Unknown file type, done".to_string()
        } else if super::file_lib::SNORT_FILE_TYPE_CONTINUE == id {
            "Undecided file type, continue...".to_string()
        } else {
            String::new()
        }
    }
}

// `ThreadConfig::get_instance_max()` seam value (main/thread_config.h:44;
// thread_config.cc:44 `static unsigned instance_max = 1` until the
// hwloc/thread row). Driver/test-owned value; set_max_files consults it
// exactly where C calls the static.

/// (file_flows.cc uses SNORT_FILE_END/FILE_START etc.; file_lib.rs
/// re-exports the FilePosition constants under the C names.)
/// trace/trace.h levels (harness copy pins the numeric ladder; the witness
/// gate is `level >= log_level` on a single DEFAULT_TRACE_OPTION_ID entry).
pub const TRACE_DEFAULT_LEVEL: u8 = 1;
pub const TRACE_CRITICAL_LEVEL: u8 = 2;
pub const TRACE_ERROR_LEVEL: u8 = 3;
pub const TRACE_WARNING_LEVEL: u8 = 4;
pub const TRACE_INFO_LEVEL: u8 = 6;
pub const TRACE_DEBUG_LEVEL: u8 = 7;

/// FILE_DEBUG(file_trace, ...) sites (file_module.h:39 -> trace/trace_api.h
/// witness in the 17p harness: level gate + "FILEDBG[module] " prefix +
/// fmt+args). The port threads every call site through this seam (deviation:
/// 17o omitted the trace lines entirely; the 17p whole-transcript replay
/// requires them visible to a witness driver — the gating/lives in the sink,
/// mirroring `Trace::enabled`, so the port stays call-site-literal).
pub trait TraceSink {
    fn file_trace(&mut self, level: u8, msg: &str);
    /// Row 17r: the C heavy half writes some output to PLAIN stdout /
    /// std::cout, NOT through file_trace (the K-block trace_stream
    /// hexdump, file_lib.cc:835; the pinned K1 vectors carry those
    /// lines WITHOUT the FILEDBG prefix). The seam renders those
    /// sites; default silent (production Rust writes nothing).
    fn raw_line(&mut self, _line: &str) {}
}

pub struct NoTrace;
impl TraceSink for NoTrace {
    fn file_trace(&mut self, _level: u8, _msg: &str) {}
}

/// `GET_CURRENT_PACKET` (file_module.h:41 -> DetectionEngine::
/// get_current_packet(), detection/detection_engine.h witness body prints
/// "DE get_current_packet have=%d"). The macro argument is evaluated even
/// when the trace is off — the port therefore calls this seam at every
/// GET_CURRENT_PACKET call site regardless of the sink's gate.
pub trait CurrentPacketApi {
    fn get_current_packet(&mut self);
    /// `DetectionEngine::set_next_packet(Packet* p)` (detection/
    /// detection_engine.cc witness; file_lib.cc:1019 in
    /// find_file_type_from_ips, row 17r). C returns the replacement
    /// `p` the ladder keeps driving; the Rust port drives the
    /// caller's PacketView through (deviation: single-view port —
    /// the witness prints the "DE set_next_packet parent=% flow=%
    /// next=%" shape and arms the current-packet latch).
    fn set_next_packet(&mut self, _parent: &PacketView) {}
}

pub struct NoCurrentPacket;
impl CurrentPacketApi for NoCurrentPacket {
    fn get_current_packet(&mut self) {}
}

/// `InspectorManager::acquire_file_inspector()` / `InspectorManager::
/// release()` (managers/inspector_manager.h witness pair). C's
/// `new FileContext` ctor calls acquire ONCE (witness prints
/// "IMGR acquire -> inspector|null"); `~FileContext` calls release when it
/// holds an inspector. A FileContext learns the manager from its creator
/// (deviation vs C's static call: the port threads the Rc so the Drop
/// witness line fires at the exact C delete moment).
pub trait InspectorManagerApi {
    fn acquire_file_inspector(&mut self) -> Option<Rc<dyn InspectorApi>>;
    fn release(&mut self, ins: &Rc<dyn InspectorApi>);
}

pub(crate) type ImgrRc = Rc<RefCell<Box<dyn InspectorManagerApi>>>;

/// `managers/inspector_manager.h` null-manager default (until the
/// InspectorManager row); FileContext ctors through it print nothing but
/// model the null arm exactly.
pub struct NullInspectorManager;
impl InspectorManagerApi for NullInspectorManager {
    fn acquire_file_inspector(&mut self) -> Option<Rc<dyn InspectorApi>> {
        None
    }
    fn release(&mut self, _ins: &Rc<dyn InspectorApi>) {}
}

/// `log/messages.h` ErrorMessage seam (file_cache.cc:148 clamp warning).
pub trait ErrorLogApi {
    fn error_message(&mut self, msg: &str);
}

pub struct NoErrorLog;
impl ErrorLogApi for NoErrorLog {
    fn error_message(&mut self, _msg: &str) {}
}

/// `main/thread_config.h:44` `ThreadConfig::get_instance_max()` seam
/// (thread_config.cc:44 `static unsigned instance_max = 1` until the
/// hwloc/thread row). The 17p harness witness prints a WITNESS line per
/// call (file_cache.cc:144 reaches it through set_max_files only).
pub trait ThreadApi {
    fn get_instance_max(&mut self) -> u32;
}

pub struct DefaultThread;
impl ThreadApi for DefaultThread {
    fn get_instance_max(&mut self) -> u32 {
        1
    }
}

/// `FileInspect` handle seam exposing the one member this TU reads:
/// `inspector->config` (FileConfig* in C).
pub trait InspectorApi {
    fn config(&self) -> Rc<RefCell<FileConfigView>>;
}

/// Seam for the pub/sub paths file_cache.cc publishes into:
///   * `MPDataBus::publish(file_pub_id, FileMPEvents::FILE_SHARE_SYNC,
///     std::make_shared<FileMPEvent>(hashkey, timeout, *file))`
///     (publish_file_cache_event; mp bus default-off, gate pinned it
///     off).
///   * `FileContext::log_file_event` (file_lib.cc:613, full body row
///     17q: DataBus FILE_VERDICT event + policy->log_file_action(
///     FILE_ACTION_DEFAULT) + FileEvent FILE_COMPLETE). The FileContext
///     seam forwards here so the apply/resume call sites stay literal.
pub trait FileCacheEventSink {
    fn publish_file_share_sync(
        &mut self,
        _key: &FileHashKey,
        _timeout: i64,
        _file: &FileContext,
    ) {
    }
    fn file_log_event(
        &mut self,
        _file: &FileContext,
        _flow: &CacheFlow,
        _policy: &mut dyn FilePolicyApi,
    ) {
    }
}

pub struct NoopFileCacheEventSink;
impl FileCacheEventSink for NoopFileCacheEventSink {}

/// `FileFlows::get_file_flows(flow)` + `add_pending_file`
/// (file_flows.h:106; the FileFlows object lives in per-flow FlowData —
/// flow row). Deviation: the sink is cache-owned (C reaches the same
/// code through the flow's FlowData slot; the flow id is passed).
pub trait FileFlowsSink {
    /// `FileFlows::get_file_flows(flow)` -> pointer null-ness (the
    /// witness prints its to_create/exists state).
    fn get_file_flows(&mut self, to_create: bool) -> bool;
    fn add_pending_file(&mut self, file_id: u64);
}

pub struct NoopFileFlowsSink;
impl FileFlowsSink for NoopFileFlowsSink {
    fn get_file_flows(&mut self, _to_create: bool) -> bool {
        false
    }
    fn add_pending_file(&mut self, _file_id: u64) {}
}

/// `FilePolicyBase` virtuals this TU calls (file_api.h:20+; FilePolicy
/// impl: file_policy.cc row).
pub trait FilePolicyApi {
    /// file_api.h:152 `virtual void policy_check(Flow*, FileInfo*)` —
    /// reached from FileContext::check_policy (file_lib.cc:763, 17q;
    /// C base no-op, the harness stub prints "POLICY policy_check").
    /// Default = the C base-class empty body.
    fn policy_check(&mut self, _flow: &CacheFlow, _file: &mut FileContext) {}
    fn type_lookup(&mut self, p: &mut PacketView, file: &mut FileContext) -> u32;
    fn signature_lookup(&mut self, p: &mut PacketView, file: &mut FileContext) -> u32;
    fn log_file_action(&mut self, flow: &CacheFlow, file: &mut FileContext, action: u32);
}

/// `FilePolicyBase*` (file_api.h:160-172) ownership handle
/// (row 17q): the C ref protocol is a raw atomic ref_count with
/// `add_ref()` (:165) and the static `delete_file_policy` (:168 ->
/// file_api.cc:34: `if (policy) { assert(policy->ref_count); unsigned
/// ref = --policy->ref_count; if (!ref) delete policy; }`). The port
/// wraps `Rc<FilePolicyBox>`... simpler: an Rc-based clone-count model
/// is WRONG for the pinned witness reads (refs=1->2, policy_refs=2->1
/// read the C atomic member directly), so the handle carries an
/// explicit counter over a Box, mirroring the C member; the clone-
/// discipline at the C sites (set_file_policy pair, NetworkPolicy-
/// owned base) is the driver's. `ref_count()` answers the probe read.
#[derive(Clone)]
pub struct FilePolicyHandle {
    inner: Rc<RefCell<PolicyStore>>,
}

struct PolicyStore {
    policy: Box<dyn FilePolicyApi>,
    /// std::atomic_uint ref_count (file_api.h:171)
    ref_count: u32,
}

impl FilePolicyHandle {
    /// C `new FilePolicy` sites yield ref_count == 1
    /// (file_api.h:28 FilePolicyBase() { ref_count = 1; }).
    pub fn new_boxed(policy: Box<dyn FilePolicyApi>) -> FilePolicyHandle {
        FilePolicyHandle {
            inner: Rc::new(RefCell::new(PolicyStore { policy, ref_count: 1 })),
        }
    }
    /// `void add_ref() { ++ref_count; }` (file_api.h:165)
    pub fn add_ref(&mut self) {
        self.inner.borrow_mut().ref_count += 1;
    }
    /// `static void delete_file_policy(FilePolicyBase* policy)`
    /// (file_api.cc:34) on the handle's own object: decrement; at 0
    /// the Box drops (C `delete policy`; ~FilePolicyBase asserts
    /// !ref_count — already 0). The C null-argument arm = the port's
    /// Option-slot None (callers pass through Option).
    pub fn delete_file_policy(&mut self) {
        let mut st = self.inner.borrow_mut();
        debug_assert!(st.ref_count > 0); // assert(policy->ref_count)
        st.ref_count -= 1; // unsigned ref = --policy->ref_count
    }
    pub fn ref_count(&self) -> u32 {
        self.inner.borrow().ref_count
    }
    /// C pointer-identity compare `policy == stub_file_policy()` /
    /// `static_pol == pol` (file_flows probe B_CREATE / get_file_policy
    /// static): two handles front the same object iff they share the
    /// store (the C raw pointers compare by address).
    pub fn same_store(&self, other: &FilePolicyHandle) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }
    /// Borrow the object (null-ness = C `if (!fp)` arms).
    pub fn is_null(&self) -> bool {
        false // the handle type only ever fronts a real object
    }
    /// Run a closure with `&mut dyn FilePolicyApi` — the C raw-pointer
    /// call shape (file_policy->signature_lookup(...) etc.).
    pub fn with_policy_mut<R, F: FnOnce(&mut dyn FilePolicyApi) -> R>(&mut self, f: F) -> R {
        let mut st = self.inner.borrow_mut();
        f(st.policy.as_mut())
    }
    /// Read the object immutably.
    pub fn with_policy<R, F: FnOnce(&dyn FilePolicyApi) -> R>(&self, f: F) -> R {
        let st = self.inner.borrow();
        f(st.policy.as_ref())
    }
}

/// `control/control.h` `LogRespond(ctrlcon, fmt, ...)` seam.
pub trait ControlConsole {
    fn respond(&mut self, msg: &str);
}

/// Driver/test console capturing every LogRespond line verbatim.
#[derive(Clone, Debug, Default)]
pub struct VecConsole {
    pub lines: Vec<String>,
}
impl ControlConsole for VecConsole {
    fn respond(&mut self, msg: &str) {
        self.lines.push(msg.to_string());
    }
}

/// `file_config.cc file_type_name(uint32_t)` (live FileConfig type
/// table; the fstats/filib witness convention returns "" for unnamed
/// ids).
pub trait FileTypeNames {
    fn file_type_name(&self, id: u32) -> String;
}

pub struct NoFileTypeNames;
impl FileTypeNames for NoFileTypeNames {
    fn file_type_name(&self, _id: u32) -> String {
        String::new()
    }
}

/// `PacketTracer::is_active()` / `PacketTracer::log`
/// (packet_io/packet_tracer.h:25-26; the tracer is off unless
/// per-packet tracing is on — the gates pinned it off, so
/// NoPacketTracer reproduces the observed behavior while the C
/// `if (is_active()) log(...)` call-site shape stays literal).
pub trait PacketTracerApi {
    fn is_active(&self) -> bool;
    fn log(&mut self, msg: &str);
    // Row 17q additions (defaults keep the 17p witness impls source-
    // compatible; the fflows test arms the real witness bodies):
    /// packet_io/packet_tracer.h `is_daq_activated()` (the
    /// file_flows/file_lib `if (is_daq_activated())` gates + the
    /// print_file_name "File name: "-suppression arm).
    fn is_daq_activated(&self) -> bool {
        false
    }
    /// `PacketTracer::restart_timer()` (file_flows.cc:429/:521 — the
    /// witness prints "PT restart_timer").
    fn restart_timer(&mut self) {}
    /// `PacketTracer::daq_log(fmt, ...)` (populate_trace_data — the
    /// witness prints "PTdaq <formatted>").
    fn daq_log(&mut self, _msg: &str) {}
    /// `PacketTracer::get_time()` (populate_trace_data's first daq_log
    /// arg, file_flows.cc:87): the fflows witness PINNED the constant
    /// 1700000100000000 (stubs.cc — the real body rides the tracer
    /// monolith clock; the fake SnortClock stays orthogonal, deviation
    /// documented at the harness).
    fn get_time(&self) -> u64 {
        0
    }
}

pub struct NoPacketTracer;
impl PacketTracerApi for NoPacketTracer {
    fn is_active(&self) -> bool {
        false
    }
    fn log(&mut self, _msg: &str) {}
}

/// time/packet_time.{h,cc}: the THREAD_LOCAL recent-packet clock
/// (`packet_gettimeofday`; `timersub_ms` below as a free function,
/// mirroring packet_time.cc:55). The driver feeds `now` from outside
/// (like the filib fake clock); `packet_time_update` semantics stay
/// driver-side until the packet-time row.
pub trait PacketClock {
    /// `packet_gettimeofday(&now)` (packet_time.cc:46)
    fn packet_now(&self) -> TimeVal;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DriverPacketClock {
    pub now: TimeVal,
}
impl PacketClock for DriverPacketClock {
    fn packet_now(&self) -> TimeVal {
        self.now
    }
}

// <sys/time.h> macros the C file leans on (glibc semantics).
fn timerisset(tv: &TimeVal) -> bool {
    tv.tv_sec != 0 || tv.tv_usec != 0
}
fn timerclear(tv: &mut TimeVal) {
    tv.tv_sec = 0;
    tv.tv_usec = 0;
}
/// `timeradd(a, b, res)` — glibc does not normalize; kept unnormalized.
fn timeradd(a: &TimeVal, b: &TimeVal, res: &mut TimeVal) {
    res.tv_sec = a.tv_sec + b.tv_sec;
    res.tv_usec = a.tv_usec + b.tv_usec;
}
/// `timercmp(&a, &b, <)`
fn timer_lt(a: &TimeVal, b: &TimeVal) -> bool {
    a.tv_sec < b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec)
}

/// `timersub_ms(end, start)` (time/packet_time.cc:55). C callers here
/// always pass real timeval pointers; glibc TIMERSUB's µs
/// carry-normalization reproduced.
fn timersub_ms(end: &TimeVal, start: &TimeVal) -> i64 {
    if start.tv_sec == 0 || end.tv_sec == 0 {
        return 0; // "can't really compare when values are not set"
    }
    let mut sec = end.tv_sec - start.tv_sec;
    let mut usec = end.tv_usec - start.tv_usec;
    if usec < 0 {
        usec += 1_000_000;
        sec -= 1;
    }
    sec * 1000 + usec / 1000
}

/// file_cache.cc:110 static `time_elapsed_ms(now, expire_time,
/// lookup_timeout)` — "Return the time in ms since we started waiting
/// for pending file lookup."
fn time_elapsed_ms(now: &TimeVal, expire_time: &TimeVal, lookup_timeout: i64) -> i64 {
    if now.tv_sec == 0 || expire_time.tv_sec == 0 {
        return 0;
    }
    lookup_timeout * 1000 + timersub_ms(now, expire_time)
}

/// file_cache.cc:96 anonymous-namespace `CacheNodePin`: dtor takes
/// cache_mutex and `file->unpin()`. The mutex maps to Rust exclusivity
/// (deviation); the pin accounting is literal.
struct CacheNodePin {
    file: Rc<RefCell<FileContext>>,
}

impl Drop for CacheNodePin {
    fn drop(&mut self) {
        // std::lock_guard<std::mutex> lock(cache_mutex);
        // file->unpin();
        self.file.borrow_mut().unpin();
    }
}

// ------------------------------------------------------------------
// ExpectedFileCache (file_cache.cc:56) — XHash subclass. The two C++
// virtual overrides are answered by the wrapper (module header).
// FileNodes live in the wrapper arena; XHash's payload slot is the
// arena index.
// ------------------------------------------------------------------

/// `FileCache::FileNode` (file_cache.h:56):
/// `{ struct timeval cache_expire_time = {0,0}; snort::FileContext* file; }`
struct FileNode {
    cache_expire_time: TimeVal,
    file: Option<Rc<RefCell<FileContext>>>,
}

/// probe-pinned `sizeof(FileNode)` = TimeVal(16) + FileContext*(8) = 24
/// (file_cache.cc:121 datasize arg; feeds XHash memcap math, memcap 0).
pub const SIZEOF_FILE_NODE: u32 = 24;

/// One live hash node's wrapper-side state: key + back-link to the
/// XHash arena node + the FileNode payload C stored in the node.
struct HashSlot {
    key: Vec<u8>,
    node: usize, // usize::MAX == not linked into XHash
    payload: FileNode,
}

struct ExpectedFileCache {
    xh: XHash,
    slots: Vec<HashSlot>, // index == the payload value stored in XHash
    free_slots: Vec<usize>,
}

impl ExpectedFileCache {
    /// `ExpectedFileCache(unsigned rows, unsigned key_len, unsigned
    /// datasize) : XHash(rows, key_len, datasize, 0)` — the C++ 4-arg
    /// ctor defaults num_lru_caches=1; memcap 0 (unbounded).
    fn new(rows: i64, key_len: usize, datasize: u32) -> ExpectedFileCache {
        ExpectedFileCache {
            xh: XHash::new(rows as i32, key_len as u32, datasize, 0, 1),
            slots: Vec::new(),
            free_slots: Vec::new(),
        }
    }

    // ~ExpectedFileCache -> delete_hash_table() (file_cache.cc:63-66):
    // the Rust wrapper drops the whole arena; XHash's own
    // ~XHash/clear path deletes each node's data via C++
    // free_user_data — here the FileContext handles drop with self.

    /// `is_node_recovery_ok(HashNode*)` (file_cache.cc:68), answered
    /// per node with `packet_gettimeofday(&now)`:
    ///   file in use             -> false
    ///   cache_expire_time < now -> true
    ///   otherwise               -> false
    /// (C's early `if (!node) return true` covers a null data
    /// pointer — the port's payload slot is never null; dead indices
    /// are never handed out.)
    fn is_node_recovery_ok(node: &FileNode, now: &TimeVal) -> bool {
        // C++: `if ( node->file and node->file->is_in_use() )
        //     return false;` — let-chain keeps it one statement.
        if let Some(file) = &node.file
            && file.borrow().is_in_use()
        {
            return false;
        }
        timer_lt(&node.cache_expire_time, now)
    }

    /// `free_user_data(HashNode*)` (file_cache.cc:86): `delete
    /// node->file`.
    fn free_user_data(slot: &mut HashSlot) {
        if let Some(file) = slot.payload.file.take() {
            // `delete node->file` (file_cache.cc:90 / :244): ~FileContext
            // + the IMGR release witness run AT this point (17r
            // owner-delete model, file_lib.cc:574) even while driver-
            // side Rc aliases (get_file/dup handles) still live.
            FileContext::owner_delete(&file);
        }
    }

    /// Slot is still the live occupant of its XHash arena node?
    /// (Recycled/ANR-stolen nodes carry another slot's key+data.)
    fn live(&self, idx: usize) -> bool {
        let s = &self.slots[idx];
        s.node != usize::MAX
            && self.xh.nodes[s.node].key == s.key
            && self.xh.nodes[s.node].data == idx
    }

    /// XHash can only ANR-recycle an existing node when allocating a
    /// new one is impossible (memcap unbounded here => max_nodes
    /// ceiling reached with an empty free list; xhash.rs
    /// allocate_node order).
    fn anr_possible(&self) -> bool {
        self.xh.anr_enabled
            && self.xh.max_nodes > 0
            && self.xh.num_nodes >= self.xh.max_nodes
            && self.xh.num_free_nodes == 0
    }

    /// `insert((void*)&hashKey, &new_node)` (file_cache.cc:220). The
    /// is_node_recovery_ok answer for every node XHash may walk is
    /// handed to the pin-list hook up front; free_user_data is applied
    /// to any ANR victim afterwards. Also returns the tv_sec C reads
    /// off `new_node` right after the insert (both paths).
    fn insert(
        &mut self,
        key: &[u8],
        payload: FileNode,
        now: &TimeVal,
    ) -> (i32, Option<usize>, i64) {
        let need_anr = self.anr_possible();
        if need_anr {
            for i in 0..self.slots.len() {
                if self.free_slots.contains(&i) {
                    continue;
                }
                if self.live(i) {
                    let recoverable = Self::is_node_recovery_ok(&self.slots[i].payload, now);
                    if !recoverable {
                        self.xh.pinned_keys.push(self.slots[i].key.clone());
                    }
                }
            }
        }

        let slot_idx = match self.free_slots.pop() {
            Some(i) => {
                self.slots[i] = HashSlot {
                    key: key.to_vec(),
                    node: usize::MAX,
                    payload,
                };
                i
            }
            None => {
                self.slots.push(HashSlot {
                    key: key.to_vec(),
                    node: usize::MAX,
                    payload,
                });
                self.slots.len() - 1
            }
        };

        // C++: cache_expire = new_node.cache_expire_time.tv_sec;
        // (file_cache.cc:221 — immediately after insert, read off the
        // stack FileNode either way)
        let expire_sec = self.slots[slot_idx].payload.cache_expire_time.tv_sec;

        let ret = self.xh.insert(key, slot_idx);
        self.xh.pinned_keys.clear();

        if need_anr {
            // C++ ran free_user_data() inline on each ANR victim
            // (xhash release_lru_node -> virtual); victims are the
            // slots whose back-links died during the insert.
            let victims: Vec<usize> = (0..self.slots.len())
                .filter(|&i| {
                    i != slot_idx
                        && !self.free_slots.contains(&i)
                        && !self.live(i)
                })
                .collect();
            for i in victims {
                Self::free_user_data(&mut self.slots[i]);
                self.slots[i].node = usize::MAX;
                self.free_slots.push(i);
            }
        }

        if ret == HASH_OK {
            let n = self.xh.cursor.expect("XHash insert sets cursor on HASH_OK");
            self.slots[slot_idx].node = n;
            (ret, Some(slot_idx), expire_sec)
        } else {
            // C++: the failed insert leaves `new_node` a live stack
            // copy (payload owned, unlinkable) until add()'s `delete
            // new_node.file` (file_cache.cc:244) — which runs AFTER
            // the PT/DE/FILE_DEBUG sites; add() reclaims the payload
            // through reclaim_failed_slot at that exact point. The
            // slot index is returned for that reclamation.
            (ret, Some(slot_idx), expire_sec)
        }
    }

    /// add()'s `delete new_node.file` (file_cache.cc:244) for the
    /// failed-insert slot (payload still owned by the slot).
    fn reclaim_failed_slot(&mut self, slot_idx: usize) {
        Self::free_user_data(&mut self.slots[slot_idx]);
        self.slots[slot_idx].node = usize::MAX;
        self.free_slots.push(slot_idx);
    }

    /// `release_node(hash_node)` with the C++ free_user_data ordering
    /// (HashTable release calls the virtual; wrapper does both).
    fn release_slot(&mut self, slot_idx: usize) {
        let n = self.slots[slot_idx].node;
        if n != usize::MAX {
            self.xh.release_node_handle(n, 0);
            self.slots[slot_idx].node = usize::MAX;
        }
        // C++ XHash::release_node -> virtual free_user_data(hnode) ->
        // `delete node->file` happens at THIS point (file_cache.cc:90;
        // the 17p harness IMGR-release witness lines pin the moment).
        Self::free_user_data(&mut self.slots[slot_idx]);
        self.free_slots.push(slot_idx);
    }
}

impl Drop for ExpectedFileCache {
    /// file_cache.cc:125 `~FileCache` -> `delete fileHash` ->
    /// ~ExpectedFileCache (file_cache.cc:63) -> `delete_hash_table()`
    /// -> per-node free_user_data (file_cache.cc:86-91 `delete
    /// node->file`). 17r: the pinned tail vectors — the 3 "IMGR
    /// release" lines after P2_SEGS (the cache entry 1014 + the two
    /// lookup-created nodes) — fire at THIS walk in C, whatever Rc
    /// aliases the driver still holds (owner-delete model,
    /// file_lib.cc:574). Walk order: the C table-row walk
    /// (xhash.cc:172-186) — the port's slot-index order matches it
    /// for the pinned set (insertion-ordered slot ids).
    fn drop(&mut self) {
        for idx in 0..self.slots.len() {
            if self.slots[idx].node != usize::MAX {
                Self::free_user_data(&mut self.slots[idx]);
            }
        }
    }
}

// ------------------------------------------------------------------
// file_cache.cc:906+ anonymous namespace — FileCacheRow snapshot
// machinery (the upstream comment "Two locks are involved ...
// Formatting into display strings is deferred until both locks are
// released" applies verbatim to the borrow model).
// ------------------------------------------------------------------

#[derive(Clone, Debug)]
struct FileCacheRow {
    sha: [u8; SHA256_HASH_SIZE], // = {}
    has_sha: bool,
    name: Vec<u8>, // std::string — byte carrier (17o)
    type_id: u32,
    verdict: u32,

    // Deferred display strings (sha_to_hex / file_type_name /
    // VerdictName) — unset until format_common_row:
    sha_str: String,
    type_name: String,
    verdict_name: String,
}

impl Default for FileCacheRow {
    fn default() -> Self {
        FileCacheRow {
            sha: [0; SHA256_HASH_SIZE],
            has_sha: false,
            name: Vec::new(),
            type_id: 0,
            verdict: FILE_VERDICT_UNKNOWN,
            sha_str: String::new(),
            type_name: String::new(),
            verdict_name: String::new(),
        }
    }
}

/// file_cache.cc:929 `struct FileCacheDetailRow : FileCacheRow`
/// (Rust composition: the `base` field IS the C++ base subobject).
/// C++ member initializers `= {}` / `= false` / `= 0` / std::string()
/// render as the derived Default.
#[derive(Clone, Debug, Default)]
struct FileCacheDetailRow {
    base: FileCacheRow,
    size: u64,
    is_download: bool,
    direction: String,
    file_id: u64,
    url: Vec<u8>,
    host: Vec<u8>,
}

// (C++ member initializers `= {}`/`= false`/`= 0`/std::string() ==
// the derived Default; clippy derivable_impls)

/// file_cache.cc:940 `snapshot_common_row(FileCacheRow& row,
/// FileContext* file)` — "Caller must hold cache_mutex and the node's
/// user_file_data_mutex."
fn snapshot_common_row(row: &mut FileCacheRow, file: &FileContext) {
    match file.info.get_file_sig_sha256() {
        Some(sha) => {
            row.has_sha = true;
            row.sha = *sha; // memcpy(row.sha, sha, SHA256_HASH_SIZE)
        }
        None => row.has_sha = false,
    }

    let name = file.info.get_file_name();
    row.name = if name.is_empty() {
        b"<empty>".to_vec() // name.empty() ? "<empty>" : name
    } else {
        name.to_vec()
    };

    row.type_id = file.info.get_file_type();
    row.verdict = file.info.verdict;
}

/// file_cache.cc:954 `inline char hex_digit(uint8_t byte, bool
/// low_nibble)`
fn hex_digit(byte: u8, low_nibble: bool) -> u8 {
    const CONV: &[u8; 16] = b"0123456789ABCDEF";
    if low_nibble {
        CONV[usize::from(byte & 0x0F)]
    } else {
        CONV[usize::from((byte >> 4) & 0x0F)]
    }
}

/// file_cache.cc:960 `sha_to_hex(const uint8_t* digest)`
fn sha_to_hex(digest: &[u8; SHA256_HASH_SIZE]) -> String {
    let mut out = String::with_capacity(2 * SHA256_HASH_SIZE); // out.reserve(2*SHA256)
    for &byte in digest.iter() {
        out.push(hex_digit(byte, false) as char);
        out.push(hex_digit(byte, true) as char);
    }
    out
}

/// file_cache.cc:976 `sha_hex_prefix_matches(const uint8_t* sha256,
/// const std::string& hex_prefix)` — allocation-free leading-hex
/// comparison (held under cache_mutex in C).
fn sha_hex_prefix_matches(sha256: &[u8; SHA256_HASH_SIZE], hex_prefix: &[u8]) -> bool {
    if hex_prefix.len() > 2 * SHA256_HASH_SIZE {
        return false;
    }

    for (i, &c) in hex_prefix.iter().enumerate() {
        if hex_digit(sha256[i / 2], (i & 1) != 0) != c {
            return false;
        }
    }
    true
}

/// `printf("%-*s", w, s)` byte-width left padding (deviation:
/// from_utf8_lossy rendering of byte-carrying names, module header).
fn pad_c(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        let mut out = String::with_capacity(width);
        out.push_str(s);
        for _ in s.len()..width {
            out.push(' ');
        }
        out
    }
}

/// `row.name.substr(0, 17) + "..."` on byte carriers.
fn truncate_name(name: &mut Vec<u8>) {
    name.truncate(17);
    name.extend_from_slice(b"...");
}

// ------------------------------------------------------------------
// FileCache (file_cache.h:52)
// ------------------------------------------------------------------

pub struct FileCache {
    /* The hash table of expected files */
    file_hash: ExpectedFileCache,

    block_timeout: i64, // atomic<int64_t> store relaxed in C
    lookup_timeout: i64,
    max_files: i64,

    // Seam wiring (C reachables): the InspectorManager acquire/release
    /// witness pair (every `new FileContext` reaches it — file_lib.cc:566),
    /// FileFlows, PacketTracer, the packet clock, the FILE_DEBUG sink
    /// (TraceSink/CurrentPacketApi — call-site-literal witness pair),
    /// ThreadConfig::get_instance_max + ErrorMessage (set_max_files), the
    /// mp_dbus conf gate, event sinks, mime/type-name resolver.
    pub imgr: ImgrRc,
    pub file_flows: Box<dyn FileFlowsSink>,
    pub packet_tracer: Box<dyn PacketTracerApi>,
    pub trace: Box<dyn TraceSink>,
    pub curpkt: Box<dyn CurrentPacketApi>,
    pub thread: Box<dyn ThreadApi>,
    pub errlog: Box<dyn ErrorLogApi>,
    pub clock: Box<dyn PacketClock>,
    /// `SnortConfig::get_conf()` side: the mp_dbus gate of
    /// publish_file_cache_event (get_file_config's per-packet conf
    /// lives on PacketView::conf).
    pub conf: Rc<RefCell<FileConfigView>>,
    pub events: Box<dyn FileCacheEventSink>,
    pub type_names: Box<dyn FileTypeNames>,
}

impl FileCache {
    /// file_cache.cc:118 `FileCache(int64_t max_files_cached)`
    pub fn new(max_files_cached: i64) -> FileCache {
        // max_files = max_files_cached;
        let max_files = max_files_cached;
        // fileHash = new ExpectedFileCache(max_files,
        //     sizeof(FileHashKey), sizeof(FileNode));
        let mut file_hash = ExpectedFileCache::new(max_files, FILE_HASH_KEY_BYTES, SIZEOF_FILE_NODE);
        // fileHash->set_max_nodes(max_files);
        file_hash.xh.set_max_nodes(max_files as u32);
        FileCache {
            file_hash,
            block_timeout: DEFAULT_FILE_BLOCK_TIMEOUT, // std::atomic init
            lookup_timeout: DEFAULT_FILE_LOOKUP_TIMEOUT,
            max_files: DEFAULT_MAX_FILES_CACHED, // header default, then
                                                 // the ctor arg above
            imgr: Rc::new(RefCell::new(Box::new(NullInspectorManager))),
            file_flows: Box::new(NoopFileFlowsSink),
            packet_tracer: Box::new(NoPacketTracer),
            trace: Box::new(NoTrace),
            curpkt: Box::new(NoCurrentPacket),
            thread: Box::new(DefaultThread),
            errlog: Box::new(NoErrorLog),
            clock: Box::new(DriverPacketClock::default()),
            conf: Rc::new(RefCell::new(FileConfigView::default())),
            events: Box::new(NoopFileCacheEventSink),
            type_names: Box::new(NoFileTypeNames),
        }
    }

    // ~FileCache(): `delete fileHash;` -> Rust drop chain.

    /// `GET_CURRENT_PACKET` (file_module.h:41): the macro argument is
    /// evaluated at every reached FILE_DEBUG site even when the level gate
    /// suppresses the print — the seam call reflects exactly that.
    fn curbkt(&mut self) {
        self.curpkt.get_current_packet();
    }

    /// file_cache.cc:130 `set_block_timeout(int64_t)`
    pub fn set_block_timeout(&mut self, timeout: i64) {
        self.block_timeout = timeout; // store(relaxed)
    }

    /// file_cache.cc:135 `set_lookup_timeout(int64_t)`
    pub fn set_lookup_timeout(&mut self, timeout: i64) {
        self.lookup_timeout = timeout; // store(relaxed)
    }

    /// file_cache.cc:140 `set_max_files(int64_t)`
    pub fn set_max_files(&mut self, max: i64) {
        // std::lock_guard<std::mutex> lock(cache_mutex); (borrow
        // exclusivity — deviation)
        let minimal_files = self.thread.get_instance_max() as i64 + 1;
        if max < minimal_files {
            self.max_files = minimal_files;
            // ErrorMessage("Maximal number of files cached should be
            // greater than number of threads\n");
            self.errlog.error_message(
                "Maximal number of files cached should be greater than number of threads\n",
            );
        } else {
            self.max_files = max;
        }
        self.file_hash.xh.set_max_nodes(self.max_files as u32);
    }

    /// file_cache.cc:156 `get_num_entries()`
    pub fn get_num_entries(&mut self) -> i64 {
        // std::lock_guard<std::mutex> lock(cache_mutex);
        // `fileHash ? ... : 0`: C++ null only post-dtor; the port's
        // table is never null.
        self.file_hash.xh.get_num_nodes() as i64
    }

    /// file_cache.cc:162 `find_add(const FileHashKey&, int64_t
    /// timeout)` — C++ callers hold cache_mutex (Rust: `&mut self`).
    fn find_add(
        &mut self,
        hash_key: &FileHashKey,
        timeout: i64,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let num = self.file_hash.xh.get_num_nodes();
        if num == 0 {
            return None;
        }

        let hb = hash_key.to_bytes();
        let hash_node = self.file_hash.xh.find_node(&hb)?;
        let slot_idx = self.file_hash.xh.nodes[hash_node].data;
        if slot_idx >= self.file_hash.slots.len()
            || !self.file_hash.live(slot_idx)
            || self.file_hash.slots[slot_idx].node != hash_node
        {
            return None; // wrapper invariant: never handed a dead slot
        }

        // C++ reads node = (FileNode*)hnode->data — the arena copy;
        // the port clones the single Rc handle the C++ pointer yields.
        let (file_opt, expire) = {
            let s = &self.file_hash.slots[slot_idx];
            (s.payload.file.clone(), s.payload.cache_expire_time)
        };

        // C: `if (!node)` — port data slot never null; `!node->file`
        // is what free_user_data leaves behind on released nodes.
        let file = match file_opt {
            None => {
                self.file_hash.release_slot(slot_idx); // release_node
                return None;
            }
            Some(f) => f,
        };

        let now = self.clock.packet_now();
        if timer_lt(&expire, &now) {
            if !file.borrow().is_in_use() {
                self.file_hash.release_slot(slot_idx);
            }
            return None;
        }

        let mut next_expire_time = TimeVal::default();
        let time_to_add = TimeVal { tv_sec: timeout, tv_usec: 0 };
        timeradd(&now, &time_to_add, &mut next_expire_time);

        //  Refresh the timer on the cache.
        {
            let s = &mut self.file_hash.slots[slot_idx];
            if timer_lt(&s.payload.cache_expire_time, &next_expire_time) {
                s.payload.cache_expire_time = next_expire_time;
            }
        }

        Some(file)
    }

    /// `new FileContext` — file_lib.cc ctor against the seams:
    /// `inspector = static_cast<FileInspect*>(
    ///     InspectorManager::acquire_file_inspector());
    ///  if (inspector and SnortConfig::get_conf())
    ///      config = inspector->config; else config = nullptr;`
    pub fn new_file_context(&self) -> Rc<RefCell<FileContext>> {
        let mut fc = FileContext::base(Some(self.imgr.clone()));
        // inspector = static_cast<FileInspect*>(
        //     InspectorManager::acquire_file_inspector());
        let ins = self.imgr.borrow_mut().acquire_file_inspector();
        if let Some(ins) = ins {
            // if (inspector and SnortConfig::get_conf())
            //     config = inspector->config;
            let cfg = ins.config();
            fc.set_inspector(Some(ins));
            fc.set_config(Some(cfg));
        }
        Rc::new(RefCell::new(fc))
    }

    /// file_cache.cc:199 `add(const FileHashKey&, int64_t timeout,
    /// bool& cache_full, int64_t& cache_expire,
    /// bool cache_sync = false)`
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        hash_key: &FileHashKey,
        timeout: i64,
        cache_full: &mut bool,
        cache_expire: &mut i64,
        cache_sync: bool,
        file_counts: &mut FileCounts,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let mut new_node = FileNode {
            cache_expire_time: TimeVal::default(),
            file: None,
        };
        /*
         * use the time that we keep files around
         * since this info would effectively be invalid
         * after that anyway because the file that
         * caused this will be gone.
         */
        let now = self.clock.packet_now();
        let time_to_add = TimeVal { tv_sec: timeout, tv_usec: 0 };
        timeradd(&now, &time_to_add, &mut new_node.cache_expire_time);

        // std::lock_guard<std::mutex> lock(cache_mutex);
        let file = self.find_add(hash_key, timeout);

        if file.is_none() {
            new_node.file = Some(self.new_file_context()); // new FileContext

            let hb = hash_key.to_bytes();
            let (ret, slot_idx, expire_sec) = self.file_hash.insert(&hb, new_node, &now);
            *cache_expire = expire_sec;

            if ret != HASH_OK {
                /* There is already a node or couldn't alloc space for
                 * key or cache is full. We would retry the packet in
                 * case of HASH_NOMEM and fail gracefully in other
                 * cases.
                 */
                if ret == HASH_NOMEM {
                    if self.packet_tracer.is_active() {
                        // PacketTracer::log("add:Insert failed in file
                        // cache, returning\n")
                        self.packet_tracer
                            .log("add:Insert failed in file cache, returning\n");
                    }
                    *cache_full = true;
                    file_counts.file_cache_full += 1;
                } else {
                    file_counts.file_cache_failures += 1;
                }

                if !cache_sync {
                    // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
                    // TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
                    // "add:Insert failed in file cache, returning\n")
                    self.curbkt();
                    self.trace.file_trace(
                        TRACE_CRITICAL_LEVEL,
                        "add:Insert failed in file cache, returning\n",
                    );
                }
                file_counts.cache_add_fails += 1;
                // delete new_node.file (file_cache.cc:244) — after the
                // PT/DE/FILE_DEBUG sites above, exactly where C frees.
                let idx = slot_idx.expect("failed insert still reports its slot");
                self.file_hash.reclaim_failed_slot(idx);
                return None;
            }

            file_counts.file_cache_total_entries += 1;
            let num_entries = self.file_hash.xh.get_num_nodes() as i64;
            if num_entries > file_counts.file_cache_max_entries as i64 {
                file_counts.file_cache_max_entries = num_entries as u64;
            }
            // C returns `new_node.file` — the linked slot's handle:
            let idx = slot_idx.expect("HASH_OK insert returns its slot");
            self.file_hash.slots[idx].payload.file.clone()
        } else {
            if !cache_sync {
                // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
                // TRACE_CRITICAL_LEVEL, GET_CURRENT_PACKET,
                // "add:file already found in file cache, returning\n")
                self.curbkt();
                self.trace.file_trace(
                    TRACE_CRITICAL_LEVEL,
                    "add:file already found in file cache, returning\n",
                );
            }
            file
        }
    }

    /// file_cache.cc:263 `find(const FileHashKey&, int64_t timeout,
    /// int64_t& cache_expire)` — C++ callers hold cache_mutex.
    fn find(
        &mut self,
        hash_key: &FileHashKey,
        timeout: i64,
        cache_expire: &mut i64,
    ) -> Option<Rc<RefCell<FileContext>>> {
        // std::lock_guard<std::mutex> lock(cache_mutex);
        let num = self.file_hash.xh.get_num_nodes();
        if num == 0 {
            return None;
        }

        let hb = hash_key.to_bytes();
        let hash_node = self.file_hash.xh.find_node(&hb)?;
        let slot_idx = self.file_hash.xh.nodes[hash_node].data;
        if slot_idx >= self.file_hash.slots.len()
            || !self.file_hash.live(slot_idx)
            || self.file_hash.slots[slot_idx].node != hash_node
        {
            return None;
        }

        let (file_opt, expire) = {
            let s = &self.file_hash.slots[slot_idx];
            (s.payload.file.clone(), s.payload.cache_expire_time)
        };

        let file = match file_opt {
            None => {
                self.file_hash.release_slot(slot_idx);
                return None;
            }
            Some(f) => f,
        };

        let now = self.clock.packet_now();
        if timer_lt(&expire, &now) {
            if !file.borrow().is_in_use() {
                self.file_hash.release_slot(slot_idx);
            }
            return None;
        }

        let mut next_expire_time = TimeVal::default();
        let time_to_add = TimeVal { tv_sec: timeout, tv_usec: 0 };
        timeradd(&now, &time_to_add, &mut next_expire_time);

        //  Refresh the timer on the cache.
        {
            let s = &mut self.file_hash.slots[slot_idx];
            if timer_lt(&s.payload.cache_expire_time, &next_expire_time) {
                s.payload.cache_expire_time = next_expire_time;
            }
        }

        let s = &self.file_hash.slots[slot_idx];
        *cache_expire = s.payload.cache_expire_time.tv_sec;
        Some(file)
    }

    /// file_cache.cc:302 private `get_file(Flow*, uint64_t file_id,
    /// bool to_create, int64_t timeout, bool using_cache_entry,
    /// bool& cache_full, int64_t& cache_expire)`.
    #[allow(clippy::too_many_arguments)]
    fn get_file(
        &mut self,
        flow: &CacheFlow,
        file_id: u64,
        to_create: bool,
        timeout: i64,
        using_cache_entry: bool,
        cache_full: &mut bool,
        cache_expire: &mut i64,
        file_counts: &mut FileCounts,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let mut hash_key = FileHashKey::default();
        self.make_key(flow, file_id, &mut hash_key);

        let mut file = if using_cache_entry {
            self.find(&hash_key, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM, cache_expire)
        } else {
            self.find(&hash_key, timeout, cache_expire)
        };

        if to_create && file.is_none() {
            file = self.add(&hash_key, timeout, cache_full, cache_expire, false, file_counts);
        }

        if file.is_some() {
            let f = file.clone().expect("just checked");
            let need_wiring = {
                let fb = f.borrow();
                !fb.get_config() && !fb.get_inspector()
            };
            if need_wiring {
                // FileInspect *inspector = (FileInspect*)
                //     InspectorManager::acquire_file_inspector();
                // (the witness fires even on the null arm — vectors pin)
                let inspector = self.imgr.borrow_mut().acquire_file_inspector();
                if let Some(ins) = inspector {
                    // FileConfig *fc = inspector->config;
                    let cfg = ins.config();
                    let mut fb = f.borrow_mut();
                    fb.set_config(Some(cfg)); // file->set_config(fc)
                    fb.set_inspector(Some(ins)); // file->set_inspector
                }
            }
        }
        file
    }

    /// file_cache.cc:330 public `get_file(Flow*, uint64_t file_id,
    /// bool to_create, bool using_cache_entry)` (4-arg overload half;
    /// deviation: `*_public` names the pair — Rust cannot overload).
    pub fn get_file_public(
        &mut self,
        flow: &CacheFlow,
        file_id: u64,
        to_create: bool,
        using_cache_entry: bool,
        file_counts: &mut FileCounts,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let mut cache_full = false;
        let mut cache_expire = 0i64;
        let t = self.lookup_timeout; // load(relaxed)
        self.get_file(
            flow,
            file_id,
            to_create,
            t,
            using_cache_entry,
            &mut cache_full,
            &mut cache_expire,
            file_counts,
        )
    }

    /// file_cache.cc:338 private `find_and_pin(Flow*, uint64_t
    /// file_id, int64_t timeout)`.
    fn find_and_pin(
        &mut self,
        flow: &CacheFlow,
        file_id: u64,
        timeout: i64,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let mut hash_key = FileHashKey::default();
        self.make_key(flow, file_id, &mut hash_key);

        let file;
        {
            // { std::lock_guard<std::mutex> lock(cache_mutex);
            file = self.find_add(&hash_key, timeout);
            if let Some(f) = &file {
                f.borrow_mut().pin(); // file->pin()
            }
        }

        if file.is_some() {
            let f = file.clone().expect("just checked");
            let need_wiring = {
                let fb = f.borrow();
                !fb.get_config() && !fb.get_inspector()
            };
            if need_wiring {
                // FileInspect* inspector = (FileInspect*)
                //     InspectorManager::acquire_file_inspector();
                let inspector = self.imgr.borrow_mut().acquire_file_inspector();
                if let Some(ins) = inspector {
                    let mut fb = f.borrow_mut();
                    fb.set_config(Some(ins.config())); // file->set_config(inspector->config)
                    fb.set_inspector(Some(ins)); // file->set_inspector(inspector)
                }
            }
        }
        file
    }

    /// file_cache.cc:363 `make_key(Flow*, uint64_t file_id,
    /// FileHashKey&) const` — the deliberate client/server swap
    /// (dip=client_ip, sip=server_ip; kept verbatim) and the uint32
    /// `flow->key->addressSpaceId` -> uint16 `asid` truncation.
    fn make_key(&self, flow: &CacheFlow, file_id: u64, hash_key: &mut FileHashKey) {
        *hash_key = FileHashKey::default(); // hashKey = {};
        hash_key.dip = flow.client_ip;
        hash_key.sip = flow.server_ip;
        hash_key.dgroup = flow.client_group;
        hash_key.sgroup = flow.server_group;
        hash_key.file_id = file_id;
        hash_key.asid = flow.address_space_id as u16;
    }

    /// file_cache.cc:374 `dup_cache_context(Flow*, uint64_t file_id,
    /// bool& is_pending)`
    pub fn dup_cache_context(
        &mut self,
        flow: &CacheFlow,
        file_id: u64,
        is_pending: &mut bool,
    ) -> Option<Rc<RefCell<FileContext>>> {
        let copy = self.new_file_context(); // new FileContext() ctor
        *is_pending = false;

        let mut hash_key = FileHashKey::default();
        self.make_key(flow, file_id, &mut hash_key);
        {
            // std::lock_guard<std::mutex> lock(cache_mutex);
            let cached = self.find_add(&hash_key, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM);
            if let Some(cached) = cached {
                {
                    // std::lock_guard<std::recursive_mutex>
                    //     udlock(cached->user_file_data_mutex);
                    let cb = cached.borrow();
                    *is_pending = cb.info.verdict == FILE_VERDICT_PENDING;
                    let mut copyb = copy.borrow_mut();
                    // copy->copy(*cached, false) — FileInfo::copy
                    // (file_lib.cc:134, row 17o); FileContext declares
                    // no override of its own base-copy in this closure.
                    copyb.info.copy(&cb.info, false);
                    if !*is_pending && !cb.is_cacheable() {
                        copyb.set_not_cacheable();
                    }
                }
                return Some(copy);
            }
        }
        // delete copy;
        None
    }

    /// file_cache.cc:398 static `verdict_publish_blocked(FileVerdict
    /// cached, FileVerdict incoming)`
    fn verdict_publish_blocked(cached: u32, incoming: u32) -> bool {
        let cached_terminal = cached != FILE_VERDICT_UNKNOWN && cached != FILE_VERDICT_PENDING;
        let incoming_nonterminal =
            incoming == FILE_VERDICT_UNKNOWN || incoming == FILE_VERDICT_PENDING;
        cached_terminal && incoming_nonterminal
    }

    /// file_cache.cc:405 private `publish_flow_verdict_locked(
    /// const FileHashKey&, int64_t timeout, FileInfo* src,
    /// bool is_cacheable)`. C's `FileInfo* src` is a FileContext sliced
    /// to its base in every caller (store_verdict) — the port threads
    /// the FileContext handle (deviation note in module header).
    fn publish_flow_verdict_locked(
        &mut self,
        key: &FileHashKey,
        timeout: i64,
        src: &Rc<RefCell<FileContext>>,
        is_cacheable: bool,
    ) {
        // std::lock_guard<std::mutex> lock(cache_mutex);
        // find(hKey, timeout, cache_expire_time) under cache_mutex;
        // `timeout` is the caller-provided lease (the harness's store
        // ladder pins it reaches find_add verbatim).
        let node = match self.find_add(key, timeout) {
            Some(n) => n,
            None => return,
        };

        // const bool same = (src == static_cast<FileInfo*>(node));
        let same = Rc::ptr_eq(&node, src);
        if same {
            // Every remaining statement in C++ is `!same`-guarded or
            // self-assigned (17o ptr::eq guard); the blocked-case data
            // transfer is `!same`-guarded too => whole call is a no-op
            // (find_add's timer refresh above already ran).
            return;
        }

        // std::lock_guard<std::recursive_mutex> udlock(node->
        //     user_file_data_mutex);
        let mut nb = node.borrow_mut();
        let mut sb = src.borrow_mut();

        // const uint8_t* node_sha = node->get_file_sig_sha256();
        // const uint8_t* src_sha = src->get_file_sig_sha256();
        // const bool cross_file = node_sha and src_sha and
        //     memcmp(node_sha, src_sha, SHA256_HASH_SIZE) != 0;
        let cross_file = match (nb.info.sha256, sb.info.sha256) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        };

        if Self::verdict_publish_blocked(nb.info.verdict, sb.info.verdict) && !cross_file {
            if FILE_VERDICT_PENDING == sb.info.verdict && !same {
                // C++ guard `!same` — always true below.
                if sb.info.get_file_data() && !nb.info.get_file_data() {
                    // node->set_file_data(src->get_file_data());
                    // src->set_file_data(nullptr);  (pointer transfer
                    // == ownership move of the ufd slot, 17o)
                    let moved = sb.info.user_file_data.take();
                    nb.info.user_file_data = moved;
                }
                if timerisset(&sb.info.pending_expire_time)
                    && !timerisset(&nb.info.pending_expire_time)
                {
                    nb.info.pending_expire_time = sb.info.pending_expire_time;
                }
            }
            return;
        }

        // *((FileInfo*)node) = *src;  (file_lib.cc:331 operator= ->
        // FileInfo::assign with clear_data = true, row 17o)
        nb.info.assign(&sb.info);

        // if (!same and not is_cacheable)
        //     node->set_not_cacheable();
        if !same && !is_cacheable {
            nb.set_not_cacheable();
        }

        if FILE_VERDICT_PENDING == sb.info.verdict && !same {
            if sb.info.get_file_data() && !nb.info.get_file_data() {
                let moved = sb.info.user_file_data.take();
                nb.info.user_file_data = moved;
            }
        } else if !same && sb.info.get_file_data() {
            nb.info.user_file_data = None; // node->set_file_data(nullptr)
        }
    }

    /// file_cache.cc:457 `clear()` — "Free every cache entry.
    /// PRECONDITION: every packet thread is fully paused and this is a
    /// single-process configuration."
    pub fn clear(&mut self) -> FileCacheClearReport {
        let mut report = FileCacheClearReport::default();

        // std::lock_guard<std::mutex> lock(cache_mutex);
        // if (!fileHash) return report; — C++ null only post-dtor.
        // XHash::clear_hash() also resets the configured cache
        // capacity, hence the manual walk.
        let mut hnode = self.file_hash.xh.find_first_node();
        while let Some(current) = hnode {
            // Find the next entry before removing the current one.
            hnode = self.file_hash.xh.find_next_node();
            let slot_idx = self.file_hash.xh.nodes[current].data;
            if slot_idx < self.file_hash.slots.len()
                && self.file_hash.live(slot_idx)
                && self.file_hash.slots[slot_idx].node == current
            {
                self.file_hash.release_slot(slot_idx);
            }
            report.freed += 1;
        }

        report.remaining = self.file_hash.xh.get_num_nodes() as u64;
        report
    }

    /// file_cache.cc:483 `take_pending_file_data(Flow*, uint64_t
    /// file_id, FileInfo* dst)` — C's `FileInfo* dst` is the flow's
    /// FileContext (handle threading, module header).
    pub fn take_pending_file_data(
        &mut self,
        flow: &CacheFlow,
        file_id: u64,
        dst: &Rc<RefCell<FileContext>>,
    ) {
        let mut hash_key = FileHashKey::default();
        self.make_key(flow, file_id, &mut hash_key);

        // std::lock_guard<std::mutex> lock(cache_mutex);
        let node = self.find_add(&hash_key, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM);
        let node = match node {
            Some(n) => n,
            None => return,
        };
        if Rc::ptr_eq(&node, dst) {
            // C aliasing: `node->get_file_data() and
            // !dst->get_file_data()` == x && !x -> false.
            return;
        }
        // node->verdict == FILE_VERDICT_PENDING and
        // node->get_file_data() and !dst->get_file_data()
        let nb = node.borrow();
        let db = dst.borrow();
        if nb.info.verdict == FILE_VERDICT_PENDING && nb.info.get_file_data() && !db.info.get_file_data() {
            drop(nb);
            drop(db);
            // std::lock_guard<std::recursive_mutex> udlock(node->
            //     user_file_data_mutex);
            // dst->set_file_data(node->get_file_data());
            // node->set_file_data(nullptr);
            let moved = node.borrow_mut().info.user_file_data.take();
            dst.borrow_mut().info.user_file_data = moved;
        }
    }

    /// file_cache.cc:498 `cached_context_not_cacheable(Flow*, uint64_t
    /// file_id)`
    pub fn cached_context_not_cacheable(&mut self, flow: &CacheFlow, file_id: u64) -> bool {
        let mut hash_key = FileHashKey::default();
        self.make_key(flow, file_id, &mut hash_key);

        // std::lock_guard<std::mutex> lock(cache_mutex);
        // return node and !node->is_cacheable();
        match self.find_add(&hash_key, DEFAULT_FILE_LOOKUP_TIMEOUT_CACHED_ITEM) {
            Some(node) => !node.borrow().is_cacheable(),
            None => false,
        }
    }

    /// file_cache.cc:508 `store_shared_verdict(const FileHashKey&,
    /// int64_t timeout, FileInfo& src)` — the mp-share receive side
    /// (FileMPEvent handler; C's FileInfo& is a FileContext in every
    /// real path — handle threading, module header).
    pub fn store_shared_verdict(
        &mut self,
        key: &FileHashKey,
        timeout: i64,
        src: &Rc<RefCell<FileContext>>,
        file_counts: &mut FileCounts,
    ) {
        let mut cache_full = false;
        let mut cache_expire = 0i64;
        // add(key, timeout, cache_full, cache_expire, true) — cache
        // sync publish (its counters already fired inside add); the C++
        // call's return value is discarded.
        self.add(key, timeout, &mut cache_full, &mut cache_expire, true, file_counts);

        // std::lock_guard<std::mutex> lock(cache_mutex);
        let node = match self.find_add(key, timeout) {
            Some(n) => n,
            None => return,
        };

        if Rc::ptr_eq(&node, src) {
            // C aliasing: both verdict compares reduce to
            // f(v, v)/condemned&&!condemned = false, then
            // self-assign (17o guard) — a no-op.
            return;
        }

        // const bool cached_condemned = (node->verdict == BLOCK or
        //     node->verdict == REJECT);
        // const bool incoming_condemned = (src.verdict == BLOCK or
        //     src.verdict == REJECT);
        let (cached_condemned, incoming_condemned, blocked) = {
            let nb = node.borrow();
            let sb = src.borrow();
            let cached_condemned =
                nb.info.verdict == FILE_VERDICT_BLOCK || nb.info.verdict == FILE_VERDICT_REJECT;
            let incoming_condemned =
                sb.info.verdict == FILE_VERDICT_BLOCK || sb.info.verdict == FILE_VERDICT_REJECT;
            let blocked = Self::verdict_publish_blocked(nb.info.verdict, sb.info.verdict)
                || (cached_condemned && !incoming_condemned);
            (cached_condemned, incoming_condemned, blocked)
        };
        let _ = (cached_condemned, incoming_condemned);
        if blocked {
            return;
        }

        // std::lock_guard<std::recursive_mutex> udlock(node->
        //     user_file_data_mutex);
        // *((FileInfo*)node) = src;
        node.borrow_mut().info.assign(&src.borrow().info);
    }

    /// file_cache.cc:530 private `check_verdict(Packet*, FileInfo*,
    /// FilePolicyBase*, const uint8_t* current_data,
    /// uint32_t current_data_len)`. C++ method body never uses `this`
    /// fields -> associated fn (deviation, no behavior).
    fn check_verdict(
        p: &mut PacketView,
        file: &mut FileContext,
        policy: &mut dyn FilePolicyApi,
        current_data: &[u8],
        current_data_len: u32,
        trc: &mut dyn TraceSink,
    ) -> u32 {
        // assert(file); Rust non-null by type.
        // std::lock_guard<std::recursive_mutex> udlock(file->
        //     user_file_data_mutex);
        // verdict = policy->type_lookup(p, file);
        let mut verdict = policy.type_lookup(p, file);

        // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
        // TRACE_DEBUG_LEVEL, p, "check_verdict:verdict after type
        // lookup %d\n", verdict)
        trc.file_trace(TRACE_DEBUG_LEVEL, &format!("check_verdict:verdict after type lookup {}\n", verdict));
        if verdict == FILE_VERDICT_STOP_CAPTURE {
            verdict = FILE_VERDICT_UNKNOWN;
        }

        // if ( file->get_file_sig_sha256() and verdict <=
        // FILE_VERDICT_LOG )
        if file.info.sha256.is_some() && verdict <= FILE_VERDICT_LOG {
            // std::lock_guard<std::recursive_mutex> udlock(file->...)
            file.info.set_capture_file_data(current_data, current_data_len);
            verdict = policy.signature_lookup(p, file);
        }

        // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
        // TRACE_DEBUG_LEVEL, p, "check_verdict:verdict being returned
        // %d\n", verdict)
        trc.file_trace(TRACE_DEBUG_LEVEL, &format!("check_verdict:verdict being returned {}\n", verdict));
        verdict
    }

    /// file_cache.cc:561 private `publish_file_cache_event(Flow*,
    /// FileInfo*, int64_t timeout)`
    fn publish_file_cache_event(&mut self, flow: &CacheFlow, file: &FileContext, timeout: i64) {
        // if (SnortConfig::get_conf()->mp_dbus)
        if self.conf.borrow().mp_dbus {
            let mut hashkey = FileHashKey::default();
            self.make_key(flow, file.info.get_file_id(), &mut hashkey);

            // std::shared_ptr<FileMPEvent> fe =
            //     std::make_shared<FileMPEvent>(hashkey, timeout, *file);
            // unsigned file_pub_id = MPDataBus::get_id(file_mp_pub_key);
            // MPDataBus::publish(file_pub_id,
            //     FileMPEvents::FILE_SHARE_SYNC, fe);
            self.events.publish_file_share_sync(&hashkey, timeout, file);

            // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
            // TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET, "File Cache
            // Sharing: Publish event with file_id %" PRIu64 "\n",
            // hashkey.file_id)
            self.curbkt();
            self.trace.file_trace(
                TRACE_DEBUG_LEVEL,
                &format!(
                    "File Cache Sharing: Publish event with file_id {}\n",
                    hashkey.file_id
                ),
            );
        }
    }

    /// file_cache.cc:578 private `store_verdict(Flow*, FileInfo*,
    /// int64_t timeout, bool& cache_full, bool is_cacheable)` -> int
    fn store_verdict(
        &mut self,
        flow: &CacheFlow,
        file: &Rc<RefCell<FileContext>>,
        timeout: i64,
        cache_full: &mut bool,
        is_cacheable: bool,
        file_counts: &mut FileCounts,
    ) -> i32 {
        // assert(file);
        let file_id = file.borrow().info.get_file_id(); // uint64_t
        let mut cache_expire = 0i64;

        if file_id == 0 {
            // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
            // TRACE_ERROR_LEVEL, GET_CURRENT_PACKET, "store_verdict:
            // file context doesn't have file id\n")
            self.curbkt();
            self.trace.file_trace(
                TRACE_ERROR_LEVEL,
                "store_verdict:file context doesn't have file id\n",
            );
            return 0;
        }

        let file_got =
            self.get_file(flow, file_id, true, timeout, false, cache_full, &mut cache_expire, file_counts);
        if file_got.is_none() {
            return -1;
        }
        let _ = file_got; // C++ never reads file_got again

        self.publish_file_cache_event(flow, &file.borrow(), cache_expire);

        let mut key = FileHashKey::default();
        self.make_key(flow, file_id, &mut key);
        self.publish_flow_verdict_locked(&key, timeout, file, is_cacheable);
        0
    }

    /// file_cache.cc:603 `apply_verdict(Packet*, FileContext*,
    /// FileVerdict verdict, bool resume, FilePolicyBase*)` -> bool
    #[allow(clippy::too_many_arguments)]
    pub fn apply_verdict(
        &mut self,
        p: &mut PacketView,
        file_ctx: &Rc<RefCell<FileContext>>,
        verdict: u32,
        resume: bool,
        policy: &mut dyn FilePolicyApi,
        file_counts: &mut FileCounts,
    ) -> bool {
        // Flow* flow = p->flow;  Active* act = p->active;
        // (C keeps these pointers live across calls; the value-view
        // deviation is documented in the module header — p.active is
        // mutated through p.active directly, same object.)
        let flow = p.flow; // value view (CacheFlow: Copy)
        // struct timeval now = {0,0}; struct timeval add_time; — the
        // C `{0,0}` init is never read on any path (packet_gettimeofday
        // reassigns before first use), so the port binds `now` at its
        // assignment point; `add_time` likewise (deviation: dead-init).
        let mut cache_full = false;

        if verdict != FILE_VERDICT_PENDING {
            timerclear(&mut file_ctx.borrow_mut().info.pending_expire_time);
        }

        file_ctx.borrow_mut().info.verdict = verdict; // file_ctx->verdict
        // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
        // TRACE_INFO_LEVEL, p, "apply_verdict %d\n", verdict)
        self.trace.file_trace(TRACE_INFO_LEVEL, &format!("apply_verdict {verdict}\n"));

        match verdict {
            FILE_VERDICT_UNKNOWN => {
                return false;
            }
            FILE_VERDICT_LOG => {
                if resume {
                    file_ctx
                        .borrow()
                        .log_file_event_sink(&flow, policy, self.events.as_mut());
                    policy.log_file_action(&flow, &mut file_ctx.borrow_mut(), FILE_RESUME_LOG);
                }
                return false;
            }
            FILE_VERDICT_BLOCK => {
                // can't block session inside a session
                // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
                // TRACE_DEBUG_LEVEL, p, "apply_verdict:
                // FILE_VERDICT_BLOCK with action block\n")
                self.trace.file_trace(
                    TRACE_DEBUG_LEVEL,
                    "apply_verdict:FILE_VERDICT_BLOCK with action block\n",
                );
                if self.packet_tracer.is_active() {
                    self.packet_tracer
                        .log("File: FILE_VERDICT_BLOCK with action block\n");
                }
                p.active.set_delayed_action(ACT_BLOCK); // ACT_BLOCK, force
                p.active.set_drop_reason("file");
            }
            FILE_VERDICT_REJECT => {
                // can't reset session inside a session
                // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
                // TRACE_DEBUG_LEVEL, p, "apply_verdict:
                // FILE_VERDICT_REJECT with action reset\n")
                self.trace.file_trace(
                    TRACE_DEBUG_LEVEL,
                    "apply_verdict:FILE_VERDICT_REJECT with action reset\n",
                );
                if self.packet_tracer.is_active() {
                    self.packet_tracer
                        .log("File: FILE_VERDICT_REJECT with action reset\n");
                }
                p.active.set_delayed_action(ACT_RESET); // ACT_RESET, force
                p.active.set_drop_reason("file");
            }
            FILE_VERDICT_STOP_CAPTURE => {
                file_ctx.borrow_mut().stop_file_capture();
                return false;
            }
            FILE_VERDICT_PENDING => {
                // int64_t cur_lookup_timeout = lookup_timeout.load
                // (memory_order_relaxed);
                let cur_lookup_timeout = self.lookup_timeout;
                // packet_gettimeofday(&now);
                let now = self.clock.packet_now();

                let ped = file_ctx.borrow().info.pending_expire_time;
                if timerisset(&ped) && timer_lt(&ped, &now) {
                    //  Timed out while waiting for pending verdict.
                    //  FileConfig* fc = get_file_config(
                    //      p->context->conf);
                    let fc = &p.conf;

                    //  Block session on timeout if configured,
                    //  otherwise use the current action.
                    if fc.block_timeout_lookup {
                        // FILE_DEBUG(file_trace, ..., TRACE_DEBUG_LEVEL,
                        // p, "apply_verdict:FILE_VERDICT_PENDING with
                        // action reset\n")
                        self.trace.file_trace(
                            TRACE_DEBUG_LEVEL,
                            "apply_verdict:FILE_VERDICT_PENDING with action reset\n",
                        );
                        if self.packet_tracer.is_active() {
                            self.packet_tracer.log(
                                "File: FILE_VERDICT_PENDING with action reset due to timeout\n",
                            );
                        }
                        p.active.set_delayed_action(ACT_RESET);
                    }

                    file_ctx.borrow_mut().set_timedout(); // set_timedout()
                    file_counts.file_lookup_timeouts += 1;

                    if resume {
                        policy.log_file_action(&flow, &mut file_ctx.borrow_mut(), FILE_RESUME_BLOCK);
                    } else {
                        file_ctx.borrow_mut().info.verdict = FILE_VERDICT_LOG;
                    }

                    // FILE_DEBUG(file_trace, ..., TRACE_INFO_LEVEL, p,
                    // "File signature lookup: timed out after
                    // %" PRIi64 "ms.\n",
                    //  time_elapsed_ms(&now, &file_ctx->
                    //  pending_expire_time, cur_lookup_timeout));
                    {
                        let ped2 = file_ctx.borrow().info.pending_expire_time;
                        let ms = time_elapsed_ms(&now, &ped2, cur_lookup_timeout);
                        self.trace.file_trace(
                            TRACE_INFO_LEVEL,
                            &format!("File signature lookup: timed out after {ms}ms.\n"),
                        );
                        if self.packet_tracer.is_active() {
                            self.packet_tracer.log(&format!(
                                "File signature lookup: timed out after {ms}ms.\n"
                            ));
                        }
                    }
                } else {
                    //  Add packet to retry queue while we wait for
                    //  response.
                    if !timerisset(&ped) {
                        let add_time = TimeVal { tv_sec: cur_lookup_timeout, tv_usec: 0 };
                        let mut fb = file_ctx.borrow_mut();
                        timeradd(&now, &add_time, &mut fb.info.pending_expire_time);

                        // FILE_DEBUG(file_trace, ..., TRACE_INFO_LEVEL,
                        // p, "File signature lookup: adding new packet
                        // to retry queue.\n")
                        self.trace.file_trace(
                            TRACE_INFO_LEVEL,
                            "File signature lookup: adding new packet to retry queue.\n",
                        );
                        if self.packet_tracer.is_active() {
                            self.packet_tracer.log(
                                "File signature lookup: adding new packet to retry queue.\n",
                            );
                        }
                    } else if self.packet_tracer.is_active() {
                        //  Won't add packet to retry queue if it is a
                        //  retransmit and not from the retry queue
                        //  since it should already be there.
                        if (p.packet_flags & PKT_RETRANSMIT) == 0 || p.is_retry() {
                            // PacketTracer::log("File signature
                            // lookup: adding packet to retry queue.
                            // Resume=%d, Waited %" PRIi64 "ms.\n",
                            // resume, time_elapsed_ms(&now,
                            // &file_ctx->pending_expire_time,
                            // cur_lookup_timeout));
                            let waited = time_elapsed_ms(&now, &ped, cur_lookup_timeout);
                            let resume_i = u32::from(resume);
                            self.packet_tracer.log(&format!(
                                "File signature lookup: adding packet to retry queue. Resume={resume_i}, Waited {waited}ms.\n"
                            ));
                            // FILE_DEBUG(file_trace, ...,
                            // "File signature lookup adding packet to
                            // retry queue Resume=%d, Waited
                            // %" PRIi64 "ms.\n", resume, ...)
                            self.trace.file_trace(
                                TRACE_INFO_LEVEL,
                                &format!(
                                    "File signature lookup adding packet to retry queueResume={resume_i}, Waited {waited}ms.\n"
                                ),
                            );
                        }
                    }

                    p.active.set_delayed_action(ACT_RETRY);
                    // FILE_DEBUG(file_trace, ..., TRACE_DEBUG_LEVEL, p,
                    // "apply_verdict:FILE_VERDICT_PENDING with action
                    // retry\n")
                    self.trace.file_trace(
                        TRACE_DEBUG_LEVEL,
                        "apply_verdict:FILE_VERDICT_PENDING with action retry\n",
                    );
                    // FileFlows *files = FileFlows::get_file_flows(
                    //     flow);
                    let fid = file_ctx.borrow().info.get_file_id();
                    let files = self.file_flows.get_file_flows(true);
                    // if (files) files->add_pending_file(
                    //     file_ctx->get_file_id());
                    if files {
                        self.file_flows.add_pending_file(fid);
                    }

                    if resume {
                        policy.log_file_action(&flow, &mut file_ctx.borrow_mut(), FILE_RESUME_BLOCK);
                    } else {
                        let cached = file_ctx.borrow().is_cacheable(); // file_ctx->is_cacheable()
                        if self.store_verdict(
                            &flow,
                            file_ctx,
                            cur_lookup_timeout,
                            &mut cache_full,
                            cached,
                            file_counts,
                        ) != 0
                        {
                            if cache_full {
                                p.active.set_delayed_action(ACT_RETRY);
                                if self.packet_tracer.is_active() {
                                    self.packet_tracer.log(
                                        "apply_verdict:FILE_VERDICT_PENDING with action retry\n",
                                    );
                                }
                            } else {
                                p.active.set_delayed_action(ACT_DROP);
                                // FILE_DEBUG(file_trace, ...,
                                // TRACE_DEBUG_LEVEL, p, "apply_verdict:
                                // FILE_VERDICT_PENDING with action
                                // drop\n")
                                self.trace.file_trace(
                                    TRACE_DEBUG_LEVEL,
                                    "apply_verdict:FILE_VERDICT_PENDING with action drop\n",
                                );
                            }
                        } else if files {
                            // FILE_DEBUG(file_trace, ...,
                            // TRACE_DEBUG_LEVEL, p,
                            // "apply_verdict:Adding file id to pending\n")
                            self.trace.file_trace(
                                TRACE_DEBUG_LEVEL,
                                "apply_verdict:Adding file id to pending\n",
                            );
                        }
                    }
                }
                return true;
            }
            _ => {
                // default: return false;
                return false;
            }
        }

        // (C++ fall-through of the BLOCK/REJECT cases):
        if resume {
            // FILE_DEBUG(file_trace, ..., TRACE_DEBUG_LEVEL, p,
            // "apply_verdict:Resume block file\n")
            self.trace.file_trace(TRACE_DEBUG_LEVEL, "apply_verdict:Resume block file\n");
            file_ctx
                .borrow()
                .log_file_event_sink(&flow, policy, self.events.as_mut());
            policy.log_file_action(&flow, &mut file_ctx.borrow_mut(), FILE_RESUME_BLOCK);
        } else {
            // else if (bool is_cacheable = file_ctx->is_cacheable())
            let is_cacheable = file_ctx.borrow().is_cacheable();
            if is_cacheable {
                // block_timeout.load(memory_order_relaxed)
                if self.store_verdict(
                    &flow,
                    file_ctx,
                    self.block_timeout,
                    &mut cache_full,
                    is_cacheable,
                    file_counts,
                ) != 0
                {
                    if self.packet_tracer.is_active() {
                        self.packet_tracer
                            .log("apply_verdict:storing the file verdict failed\n");
                    }
                } else {
                    // FILE_DEBUG(file_trace, ..., TRACE_DEBUG_LEVEL, p,
                    // "apply_verdict:storing the file verdict\n")
                    self.trace.file_trace(
                        TRACE_DEBUG_LEVEL,
                        "apply_verdict:storing the file verdict\n",
                    );
                }
            }
        }

        true
    }

    /// file_cache.cc:800 `cached_verdict_lookup(Packet*, FileInfo*,
    /// FilePolicyBase*, const uint8_t* current_data,
    /// uint32_t current_data_len)` -> FileVerdict
    #[allow(clippy::too_many_arguments)]
    pub fn cached_verdict_lookup(
        &mut self,
        p: &mut PacketView,
        file: &Rc<RefCell<FileContext>>,
        policy: &mut dyn FilePolicyApi,
        current_data: &[u8],
        current_data_len: u32,
        file_counts: &mut FileCounts,
    ) -> u32 {
        // Flow* flow = p->flow;
        let flow = p.flow;
        let mut verdict = FILE_VERDICT_UNKNOWN;

        // assert(file);
        // uint64_t file_id = file->get_file_id();
        let file_id = file.borrow().info.get_file_id();
        if file_id == 0 {
            // FILE_DEBUG(file_trace, ..., TRACE_ERROR_LEVEL, p,
            // "cached_verdict_lookup:File id not found, returning\n")
            self.trace.file_trace(
                TRACE_ERROR_LEVEL,
                "cached_verdict_lookup:File id not found, returning\n",
            );
            return verdict;
        }

        // int64_t lease = lookup_timeout.load(memory_order_relaxed);
        let lease = self.lookup_timeout;
        // FileContext* file_found = find_and_pin(flow, file_id,
        //     lease < 1 ? 1 : lease);
        let file_found = self.find_and_pin(&flow, file_id, if lease < 1 { 1 } else { lease });

        if let Some(file_found) = file_found {
            // CacheNodePin node_pin(cache_mutex, file_found);
            // [dtor unpins on every exit path, incl. early returns]
            let _node_pin = CacheNodePin {
                file: file_found.clone(),
            };
            {
                // std::lock_guard<std::recursive_mutex> udlock(
                //     file_found->user_file_data_mutex);
                // if (not static_cast<FileContext*>(file)
                //        ->is_cache_dup() and file_found->verdict ==
                //        FILE_VERDICT_PENDING) return FILE_VERDICT_UNKNOWN;
                let dup = file.borrow();
                if !dup.is_cache_dup() {
                    let cached = file_found.borrow();
                    if cached.info.verdict == FILE_VERDICT_PENDING {
                        return FILE_VERDICT_UNKNOWN;
                    }
                }

                let partial = file.borrow().info.is_partial_download();
                file_found.borrow_mut().info.set_partial_flag(partial);

                // verdict = check_verdict(p, file_found, policy, ...)
                verdict = Self::check_verdict(
                    p,
                    &mut file_found.borrow_mut(),
                    policy,
                    current_data,
                    current_data_len,
                    self.trace.as_mut(),
                );
            }
            // FILE_DEBUG(file_trace, ..., TRACE_DEBUG_LEVEL, p,
            // "cached_verdict_lookup:Verdict received from
            // cached_verdict_lookup %d\n", verdict)
            self.trace.file_trace(
                TRACE_DEBUG_LEVEL,
                &format!("cached_verdict_lookup:Verdict received from cached_verdict_lookup {verdict}\n"),
            );
            file.borrow_mut().info.verdict = verdict; // file->verdict = verdict;
            if verdict != FILE_VERDICT_UNKNOWN {
                self.apply_verdict(p, &file_found, verdict, true, policy, file_counts);
            }
            if verdict != FILE_VERDICT_UNKNOWN {
                // const bool cur_type_enabled = file->
                //     is_file_type_enabled();
                // const bool cur_sig_enabled = file->
                //     is_file_signature_enabled();
                // std::lock_guard<std::mutex> lock(cache_mutex);
                // std::lock_guard<std::recursive_mutex> udlock(
                //     file_found->user_file_data_mutex);
                // file->copy(*(FileInfo*)file_found, false);
                // file->config_file_type(cur_type_enabled);
                // file->config_file_signature(cur_sig_enabled);
                let cur_type_enabled = file.borrow().info.is_file_type_enabled();
                let cur_sig_enabled = file.borrow().info.is_file_signature_enabled();
                let same = Rc::ptr_eq(file, &file_found);
                {
                    let mut fb = file.borrow_mut();
                    if !same {
                        let cf = file_found.borrow();
                        fb.info.copy(&cf.info, false);
                    }
                    fb.info.config_file_type(cur_type_enabled);
                    fb.info.config_file_signature(cur_sig_enabled);
                }
            }
        }

        verdict
    }

    /// file_cache.cc:851 `resume_pending_verdict(Packet*, FileInfo*
    /// dup, FilePolicyBase*)` -> FileVerdict
    pub fn resume_pending_verdict(
        &mut self,
        p: &mut PacketView,
        dup: &Rc<RefCell<FileContext>>,
        policy: &mut dyn FilePolicyApi,
        file_counts: &mut FileCounts,
    ) -> u32 {
        // Flow* flow = p->flow;
        let flow = p.flow;
        let mut verdict = FILE_VERDICT_UNKNOWN;

        // assert(dup);
        // uint64_t file_id = dup->get_file_id();
        let file_id = dup.borrow().info.get_file_id();
        if file_id == 0 {
            // FILE_DEBUG(file_trace, ..., TRACE_ERROR_LEVEL, p,
            // "resume_pending_verdict:File id not found, returning\n")
            self.trace.file_trace(
                TRACE_ERROR_LEVEL,
                "resume_pending_verdict:File id not found, returning\n",
            );
            return verdict;
        }

        // int64_t lease = lookup_timeout.load(memory_order_relaxed);
        // FileContext* node = find_and_pin(flow, file_id,
        //     lease < 1 ? 1 : lease);
        let lease = self.lookup_timeout;
        let node = match self.find_and_pin(&flow, file_id, if lease < 1 { 1 } else { lease }) {
            Some(n) => n,
            None => {
                // FILE_DEBUG(file_trace, ..., TRACE_DEBUG_LEVEL, p,
                // "resume_pending_verdict:node not found, returning\n")
                self.trace.file_trace(
                    TRACE_DEBUG_LEVEL,
                    "resume_pending_verdict:node not found, returning\n",
                );
                return verdict;
            }
        };

        // CacheNodePin node_pin(cache_mutex, node);
        let _node_pin = CacheNodePin {
            file: node.clone(),
        };
        {
            // std::lock_guard<std::recursive_mutex> udlock(
            //     node->user_file_data_mutex);
            // (bytes cloned before writing so the C++ self-copy case
            // stays side-effect-free without aliasing UB)
            // if (dup->is_file_name_set()) node->set_file_name(
            //     dup->get_file_name().c_str(),
            //     dup->get_file_name().size());
            if dup.borrow().info.is_file_name_set() {
                let name = dup.borrow().info.file_name.clone();
                let size = dup.borrow().info.get_file_name().len() as u32;
                node.borrow_mut().info.set_file_name(Some(&name), size);
            }
            // if (dup->is_url_set()) node->set_url(...);
            if dup.borrow().info.is_url_set() {
                let url = dup.borrow().info.url.clone();
                let size = dup.borrow().info.get_url().len() as u32;
                node.borrow_mut().info.set_url(Some(&url), size);
            }
            // if (dup->is_host_set()) node->set_host(...);
            if dup.borrow().info.is_host_set() {
                let host = dup.borrow().info.host_name.clone();
                let size = dup.borrow().info.get_host_name().len() as u32;
                node.borrow_mut().info.set_host(Some(&host), size);
            }

            // verdict = policy->signature_lookup(p, node);
            verdict = policy.signature_lookup(p, &mut node.borrow_mut());
        }
        // dup->verdict = verdict;
        dup.borrow_mut().info.verdict = verdict;
        // FILE_DEBUG(file_trace, ..., TRACE_DEBUG_LEVEL, p,
        // "resume_pending_verdict:applying file cache verdict %d\n",
        // verdict)
        self.trace.file_trace(
            TRACE_DEBUG_LEVEL,
            &format!("resume_pending_verdict:applying file cache verdict {verdict}\n"),
        );
        self.apply_verdict(p, &node, verdict, false, policy, file_counts);
        // const FileVerdict resolved = node->verdict;
        let resolved = node.borrow().info.verdict;
        // dup->verdict = resolved;
        dup.borrow_mut().info.verdict = resolved;
        // node->log_file_event(flow, policy);
        node.borrow()
            .log_file_event_sink(&flow, policy, self.events.as_mut());
        {
            // const bool cur_type_enabled = dup->is_file_type_enabled();
            // const bool cur_sig_enabled =
            //     dup->is_file_signature_enabled();
            // std::lock_guard<std::mutex> lock(cache_mutex);
            // std::lock_guard<std::recursive_mutex> udlock(
            //     node->user_file_data_mutex);
            // dup->copy(*(FileInfo*)node, false);
            // dup->config_file_type(cur_type_enabled);
            // dup->config_file_signature(cur_sig_enabled);
            let cur_type_enabled = dup.borrow().info.is_file_type_enabled();
            let cur_sig_enabled = dup.borrow().info.is_file_signature_enabled();
            let same = Rc::ptr_eq(dup, &node);
            {
                let mut db = dup.borrow_mut();
                if !same {
                    let nb = node.borrow();
                    db.info.copy(&nb.info, false);
                }
                db.info.config_file_type(cur_type_enabled);
                db.info.config_file_signature(cur_sig_enabled);
            }
        }
        resolved
    }

    /// file_cache.cc:992 `format_common_row(FileCacheRow& row,
    /// bool truncate_name = true)` — "Called after cache_mutex is
    /// released: formatting/allocation only." Needs the
    /// `file_type_name` seam, hence a method.
    fn format_common_row(&self, row: &mut FileCacheRow, truncate_name: bool) {
        row.sha_str = if row.has_sha {
            sha_to_hex(&row.sha)
        } else {
            "<pending>".to_string()
        };

        if truncate_name && row.name.len() > 20 {
            // row.name.substr(0, 17) + "..."
            truncate_name_bytes(&mut row.name);
        }

        row.type_name = self.type_names.file_type_name(row.type_id);
        // C++ table lookup: VerdictName[row.verdict]
        row.verdict_name = VERDICT_NAME[row.verdict as usize].to_string();
    }

    /// file_cache.cc:1004 private `walk_locked(unsigned max_entries,
    /// const std::function<bool(FileContext*)>& visit)`
    fn walk_locked(
        &mut self,
        max_entries: u32,
        visit: &mut dyn FnMut(&mut FileContext) -> bool,
    ) -> u32 {
        // std::lock_guard<std::mutex> lock(cache_mutex);
        let total = self.file_hash.xh.get_num_nodes(); // fileHash ? : 0
        if total == 0 {
            return 0;
        }

        let mut hash_node = self.file_hash.xh.find_first_node();
        let mut visited: u32 = 0;

        while let Some(n) = hash_node {
            if visited >= max_entries {
                break;
            }
            let slot_idx = self.file_hash.xh.nodes[n].data;
            let file_opt = if slot_idx < self.file_hash.slots.len()
                && self.file_hash.live(slot_idx)
                && self.file_hash.slots[slot_idx].node == n
            {
                // C: `FileNode* node = (FileNode*)hash_node->data;
                //  if (node and node->file)`
                self.file_hash.slots[slot_idx].payload.file.clone()
            } else {
                None
            };
            if let Some(f) = file_opt {
                visited += 1;
                if !visit(&mut f.borrow_mut()) {
                    break;
                }
            }
            hash_node = self.file_hash.xh.find_next_node();
        }

        total
    }

    /// file_cache.cc:1031 `dump_cache(ControlConn*, unsigned
    /// max_entries)`
    pub fn dump_cache(&mut self, ctrlcon: &mut dyn ControlConsole, max_entries: u32) {
        let mut rows: Vec<FileCacheRow> = Vec::new();

        // Field copies only (one short std::string each), under
        // cache_mutex plus the node's user_file_data_mutex.
        let total = self.walk_locked(max_entries, &mut |file: &mut FileContext| {
            // std::lock_guard<std::recursive_mutex> udlock(
            //     file->user_file_data_mutex);
            let mut row = FileCacheRow::default();
            snapshot_common_row(&mut row, file);
            rows.push(row);
            // rows.emplace_back(std::move(row));
            true
        });

        // Formatting/allocation happens here, after cache_mutex is
        // released.
        for row in rows.iter_mut() {
            self.format_common_row(row, true);
        }

        ctrlcon.respond(&format!("\nTotal number of cache entries: {total}\n"));

        if total == 0 {
            return;
        }

        // LogRespond(ctrlcon, "%-20s | %-10s | %-12s | %s\n",
        //     "File Name", "File Type", "Verdict", "SHA256");
        ctrlcon.respond(&format!(
            "{} | {} | {} | {}\n",
            pad_c("File Name", 20),
            pad_c("File Type", 10),
            pad_c("Verdict", 12),
            "SHA256"
        ));

        // (row.name printf via from_utf8_lossy: deviation, header)
        for row in rows.iter() {
            ctrlcon.respond(&format!(
                "{}   {}   {}   {}\n",
                pad_c(&String::from_utf8_lossy(&row.name), 20),
                pad_c(&row.type_name, 10),
                pad_c(&row.verdict_name, 12),
                row.sha_str
            ));
        }

        if (rows.len() as u32) < total {
            // LogRespond(ctrlcon, "... displayed %zu of %u entries\n",
            //     rows.size(), total);
            ctrlcon.respond(&format!("... displayed {} of {} entries\n", rows.len(), total));
        }
    }

    /// file_cache.cc:1073 `dump_cache_entry(ControlConn*, const
    /// std::string& sha_hex)` — the sha_hex prefix kept as raw bytes
    /// (C std::string comparison was byte-wise).
    pub fn dump_cache_entry(&mut self, ctrlcon: &mut dyn ControlConsole, sha_hex: &[u8]) {
        let mut rows: Vec<FileCacheDetailRow> = Vec::new();

        // Per-node work is one allocation-free SHA prefix comparison;
        // every entry whose SHA matches the prefix is copied (the same
        // file seen on multiple flows yields multiple cache entries
        // sharing a SHA). Each copy is done holding the node's
        // user_file_data_mutex so the row is internally consistent and
        // the string copies cannot race with a concurrent
        // set_url()/set_host(). All hex/string formatting is deferred
        // until after the locks are released.
        let sha_hex = sha_hex.to_vec();
        let total = self.walk_locked(u32::MAX, &mut |file: &mut FileContext| {
            // std::lock_guard<std::recursive_mutex> udlock(
            //     file->user_file_data_mutex);
            // uint8_t* sha = file->get_file_sig_sha256();
            // if (!sha) return true;
            let sha = match file.info.get_file_sig_sha256() {
                Some(s) => *s,
                None => return true,
            };

            if !sha_hex_prefix_matches(&sha, &sha_hex) {
                return true;
            }

            let mut row = FileCacheDetailRow::default();
            snapshot_common_row(&mut row.base, file);
            row.size = file.info.get_file_size();
            row.is_download = file.info.get_file_direction() == FILE_DOWNLOAD;
            row.file_id = file.info.get_file_id();
            row.url = file.info.get_url().to_vec(); // std::string copies
            row.host = file.info.get_host_name().to_vec();

            rows.push(row);
            true
        });

        if rows.is_empty() {
            if total == 0 {
                ctrlcon.respond("File cache is empty\n");
            } else {
                // LogRespond(..., "No cache entry found matching
                // SHA256: %s\n", sha_hex.c_str());
                ctrlcon.respond(&format!(
                    "No cache entry found matching SHA256: {}\n",
                    String::from_utf8_lossy(&sha_hex)
                ));
            }
            return;
        }

        for row in rows.iter_mut() {
            self.format_common_row(&mut row.base, false);
            row.direction = if row.is_download { "Download" } else { "Upload" }.to_string();
            let base = &row.base;
            let name_lossy = String::from_utf8_lossy(&base.name).to_string();

            ctrlcon.respond(&format!("\nSHA256: {}\n", base.sha_str));
            ctrlcon.respond(&format!("File Name: {name_lossy}\n"));
            // LogRespond(..., "File Type: %s (id: %u)\n", ...)
            ctrlcon.respond(&format!("File Type: {} (id: {})\n", base.type_name, base.type_id));
            ctrlcon.respond(&format!("File Size: {}\n", row.size));
            ctrlcon.respond(&format!("Verdict: {}\n", base.verdict_name));
            ctrlcon.respond(&format!("Direction: {}\n", row.direction));
            ctrlcon.respond(&format!("File ID: {}\n", row.file_id));

            if !row.url.is_empty() {
                ctrlcon.respond(&format!(
                    "URL: {}\n",
                    String::from_utf8_lossy(&row.url)
                ));
            }

            if !row.host.is_empty() {
                ctrlcon.respond(&format!(
                    "Host: {}\n",
                    String::from_utf8_lossy(&row.host)
                ));
            }
        }
    }
}

/// truncate_name renamed (clippy would shadow the bool param name).
fn truncate_name_bytes(name: &mut Vec<u8>) {
    name.truncate(17);
    name.extend_from_slice(b"...");
}
