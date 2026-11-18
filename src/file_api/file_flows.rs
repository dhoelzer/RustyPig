//! Literal port of file_api/file_flows.{h,cc} — the per-flow FileFlows
//! FlowData object: the retire/deferred-delete ALIASING matrix (the
//! ISS-1 / CSCwt96192 gate cases ARE the semantics), the
//! get_file_context ladder (ppc hit / cache private-copy / create with
//! the over-limit event arm), get_new_file_instance's
//! `(instance_id << 32) | max_file_id++` bit ladder, the two
//! file_process forms (transcribed up to the heavy FileContext::process
//! call sites the fflows probe never crosses — file_flows.cc:474/:488/
//! :533/:590 — which stay pinned-panic 17r seams), set_file_name,
//! add_pending_file, handle_retransmit, populate_trace_data (the
//! PacketTracer::daq_log format ladder), the swap/restore
//! CurrentContextSlot round-trip, and the FileEventGen over-limit event
//! (gid=150 sid=1, suppressed-bitset one-shot — helpers::event_gen).
//!
//! Ground truth: /opt/data/snort3-src @ fe29cbe7403a, harness
//! `tools/fflows_harness` (row 17q — REAL file_flows.cc TU linked over
//! the donor fcache closure; the donor FileFlows witness block RETIRED
//! in the new link only, fcache's committed transcript untouched — the
//! 17p retirement precedent). Gate = the TU's own 8 embedded Catch
//! cases (22 runner-measured assertions, gate.txt); probe transcript
//! `vectors.txt` replayed line-for-line by tests/fflows_parity_test.rs.
//!
//! Deviations (restated in PORTING_PLAN.md row 17q):
//! * C raw owning `FileContext*` slots -> `Rc<RefCell<FileContext>>`.
//!   The C use-after-free windows the upstream gate cases pin ("caller
//!   deref after remove is safe", the retire-then-set orderings) are
//!   structurally excluded by Rc, but every null/erase/park ORDER is
//!   transcribed literally, so the observable slot state matches every
//!   transcript line (the C `deferred == a` / `current == null` CHECKs
//!   have exact Rust analogues via Rc::ptr_eq).
//! * `std::mutex file_flow_context_mutex` (file_flows.h:61) is declared
//!   but NEVER locked in this TU; the port models Rust exclusivity in
//!   place of the field (rows 17m/17p deviation pattern).
//! * `Flow* flow` lives in the Flow's FlowData slot in C
//!   (get_flow_data/set_flow_data, the harness single-slot graft):
//!   FileFlows carries the fcache-cache-flow view (`flow` field), and
//!   the C file-scope statics `FileFlows::file_flow_data_id`
//!   (file_flows.cc:56) / `static THREAD_LOCAL uint32_t max_file_id`
//!   (:57) / the factory's FlowData slot ride FileEnvLite Cells plus
//!   the driver-passed slot handle at get_file_flows.
//!   `snort::get_file_processed_size(Flow*)` (file_service.cc:256, free
//!   linkage the fflows TU reaches) is the free fn below.
//! * The two file_process overloads split into `file_process_multi`
//!   (file_id form, file_flows.cc:393) and `file_process` (single-file
//!   form, :505) — Rust has no overloading.
//! * `FilePolicyBase*` -> `FilePolicyHandle` (file_cache.rs): the C
//!   add_ref / FilePolicyBase::delete_file_policy pair (file_api.cc:28-
//!   41, file_flows.h:120-126) runs through the handle at the exact C
//!   points (probe pins refs=1->2 at B_CREATE and policy_refs=2->1 at
//!   C5_DTOR); the C `delete policy` at count 0 = the Box drop inside
//!   delete_file_policy.
//! * `std::unordered_map<uint64_t, FileContext*>
//!   partially_processed_contexts` -> insertion-order Vec of (id, ctx):
//!   every C observation here is a point find / size() / count / the
//!   dtor retire walk, and the pinned multi-entry walks retire
//!   equal-line contexts, so hash order is unobservable (fcache OtnMap
//!   precedent).
//! * `init_file_context(FileDirection, FileContext*)` (file_flows.h:133)
//!   is grep-proven to have NO definition anywhere in the C tree and NO
//!   call site (link-silent declaration): the port records it as the
//!   comment below instead of dead code.
//! * FILE_DEBUG(p) sites vs GET_CURRENT_PACKET sites follow the
//!   transcript: a direct `p` argument prints no DE line; the
//!   GET_CURRENT_PACKET macro arm evaluates DetectionEngine::
//!   get_current_packet (env.curbkt()) before the FILEDBG line.
//! * A null `file_policy` reaching policy->policy_check /
//!   signature_lookup (file_flows.cc:355/567 — C UB) is pinned-absent
//!   (B_CREATE arms the base policy first); the port routes the null
//!   arm through a silent NullPolicy so the C statement transcribes
//!   without deref-panic.
//! * The UNIT_TEST block (file_flows.cc:571-779: the 8 Catch cases,
//!   FF_TEST_CONTEXT, FFTestAccessor) stays gate-side in the C harness;
//!   its semantics replay through the pub(crate) slot fields +
//!   ff_test_* accessors below (integration tests are external crates).
#![allow(dead_code)]
#![allow(clippy::collapsible_if)]


use std::cell::RefCell;
use std::rc::Rc;

use super::file_cache::{
    CacheFlow, FilePolicyApi, FilePolicyHandle, PacketView, TRACE_CRITICAL_LEVEL,
    TRACE_DEBUG_LEVEL, TRACE_ERROR_LEVEL,
};
use super::file_lib::{
    EVENT__MAX_VALUE, EVENT__NONE, FILE_DOWNLOAD, FILE_UPLOAD, FILE_VERDICT_PENDING,
    FILE_VERDICT_UNKNOWN, FileContext, FileEnvLite, SNORT_FILE_TYPE_CONTINUE, VERDICT_NAME,
};
// C spelled the FilePosition enum without the SNORT_ prefix inside
// this TU (using-declared FilePosition values); alias the file_lib
// copies to the C spelling used verbatim in the transcribed bodies.
use super::file_lib::{
    SNORT_FILE_END as FILE_END, SNORT_FILE_FULL as FILE_FULL,
    SNORT_FILE_MIDDLE as FILE_MIDDLE, SNORT_FILE_POSITION_UNKNOWN as FILE_POSITION_UNKNOWN,
    SNORT_FILE_START as FILE_START,
};
// Row 17r: the seam panics around file_process_multi / file_process are
// UNLOCKED — the position/offset overloads live in file_lib as free
// functions (the C mutual-call pair threaded via FlowsRef).
use super::file_lib::{FlowsRef, process, process_pos};
use super::file_lib::{EVENT_FILE_DROPPED_OVER_LIMIT, FILE_ID_GID};
use super::file_stats::FileCounts;
use crate::helpers::event_gen::EventGen;

/// file_flows.h:44 `using FileEventGen = EventGen<EVENT__MAX_VALUE,
/// EVENT__NONE, FILE_ID_GID>;`
pub type FileEventGen = EventGen<EVENT__MAX_VALUE, EVENT__NONE, FILE_ID_GID>;

// ------------------------------------------------------------------
// file_flows.cc:57 `static THREAD_LOCAL uint32_t max_file_id = 0;` ->
// FileEnvLite.max_file_id; file_flows.cc:56
// `unsigned FileFlows::file_flow_data_id = 0;` -> FileEnvLite
// .file_flow_data_id (the C homes are file statics; the Cells carry
// them 17p-style).
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// free API fns (file_flows.cc:29 + the file_service.cc:256 half the
// get_file_position ladder reaches)
// ------------------------------------------------------------------

/// `snort::get_file_processed_size(Flow* flow)` (file_service.cc:256):
/// ```text
/// FileFlows* file_flows = FileFlows::get_file_flows(flow);
/// if (!file_flows) return 0;
/// const FileContext* context = file_flows->get_current_file_context();
/// if ( !context ) return 0;
/// return context->get_processed_bytes();
/// ```text
/// C re-enters the factory (to_create default true; the FlowData slot
/// already carries the object, service enabled -> same pointer): the
/// port takes the driver's slot (single-slot graft deviation). The C
/// get_current_file_context id-arm is crossed nowhere in the pinned
/// F-position shape (the probe arms the context pair with id 0 /
/// pre-armed ppc), so the static arm below stays print-transparent.
pub fn get_file_processed_size(flows: Option<&Rc<RefCell<FileFlows>>>) -> u64 {
    // if (!file_flows) return 0;
    let Some(ff) = flows else {
        return 0;
    };
    let ff = ff.borrow();
    // const FileContext* context = file_flows->get_current_file_context();
    if ff.current_file_id != 0 {
        // C: the id arm would consult the cache; no pinned F/G/E arm
        // enters this fn with a non-zero current_file_id (the probe
        // arms current_context). Pinned-absent — answer as C would
        // after the lookup only when the id re-resolves; the id-arm
        // body stays behind the seam-free static read (deviation:
        // return current_context, documented at the C5 pin note).
        return ff.current_context.as_ref().map_or(0, |c| c.borrow().get_processed_bytes());
    }
    // if ( !context ) return 0;
    let Some(ctx) = ff.current_context.as_ref() else {
        return 0;
    };
    ctx.borrow().get_processed_bytes()
}

/// file_flows.cc:29 `FilePosition snort::get_file_position(Packet* pkt)`
/// — the exact ladder (full -> start -> PDU_TAIL -> processed -> unk),
/// F_POSITION pins `mid=2 full=4 start=1 end=3`.
pub fn get_file_position(p: &PacketView, flows: Option<&Rc<RefCell<FileFlows>>>) -> u32 {
    let mut position = FILE_POSITION_UNKNOWN;

    // Packet* p = static_cast<Packet*>(pkt);
    if p.is_full_pdu() {
        position = FILE_FULL;
    } else if p.is_pdu_start() {
        position = FILE_START;
    } else if (p.packet_flags & super::file_cache::PKT_PDU_TAIL) != 0 {
        position = FILE_END;
    } else if get_file_processed_size(flows) != 0 {
        position = FILE_MIDDLE;
    }

    position
}

// ------------------------------------------------------------------
// file_flows.cc:51 static populate_trace_data(FileContext* context)
// — the PacketTracer::daq_log format ladder (PRId64/PRIu64 = decimal;
// %u decimal; VerdictName[] = file_lib.h:38).
// ------------------------------------------------------------------

fn populate_trace_data(context: &FileContext, env: &mut FileEnvLite) {
    // std::stringstream ss; context->print_file_name(ss);
    // std::string file_name = ss.str();
    let file_name = context.print_file_name_str(env);

    // context->get_policy_id() (file_lib.h FileInfo member)
    let policy_id = context.info.get_policy_id();

    // ((context->is_file_type_enabled() || context->get_file_type() ||
    //   context->get_file_sig_sha256()) ? "<on>" : "<off>")
    // (C pointer/truthiness: the FileSig* casts to bool)
    let identification = if context.info.is_file_type_enabled()
        || (context.info.get_file_type() != 0)
        || context.info.get_file_sig_sha256().is_some()
    {
        "<on>"
    } else {
        "<off>"
    };
    // ((context->is_file_signature_enabled() ||
    //   context->get_file_sig_sha256()) ? "<on>" : "<off>")
    let signature = if context.info.is_file_signature_enabled()
        || context.info.get_file_sig_sha256().is_some()
    {
        "<on>"
    } else {
        "<off>"
    };
    // (context->is_file_capture_enabled() ? "<on>" : "<off>")
    let capture = if context.info.is_file_capture_enabled() {
        "<on>"
    } else {
        "<off>"
    };
    // (file_name.empty() ? "<empty>" : file_name.c_str())
    let name = if file_name.is_empty() { "<empty>" } else { &file_name };
    // file_type_name(context->get_file_type()) — file_config.cc:80
    // free `file_type_name(uint32_t id)`: the resolved FileConfig
    // member (get_file_config() null arm -> the C deref, pinned-absent
    // when the tracer is armed at all; the port answers "").
    let type_name = match env.get_file_config() {
        Some(c) => c.borrow().file_type_name(context.info.get_file_type()),
        None => String::new(),
    };
    // (context->get_file_sig_sha256() ?
    //   context->sha_to_string(...).c_str() : "<empty>")
    let sha = match context.info.get_file_sig_sha256() {
        Some(d) => context.info.sha_to_string(d),
        None => "<empty>".to_string(),
    };

    // PacketTracer::daq_log(fmt, PacketTracer::get_time(), ...) —
    // the ns tick is the harness-pinned PacketTracer::get_time()
    // witness ("file+1700000100000000+..."; NOT the SnortClock seam —
    // C routes the daq tick through the tracer monolith clock, which
    // stubs.cc pins to the constant).
    let time_ns = env.packet_tracer.get_time() as i64;
    env.packet_tracer.daq_log(&format!(
        "file+{time_ns}+Matched policy id {policy_id}, identification {identification}, signature {signature}, capture {capture}+\
File with ID {}, name {name}, type {type_name}, size {}, SHA {sha} detected. Verdict {}.$",
        context.info.get_file_id(),
        context.info.get_file_size(),
        // VerdictName[context->verdict]
        VERDICT_NAME[context.info.verdict as usize],
    ));
}

// file_flows.h:133 `void init_file_context(FileDirection,
// FileContext*);` — DECLARED ONLY: grep-proven to have no definition
// anywhere in the source tree and no call site (the linker never
// references it). The port keeps the comment as the only portable
// artifact (a dead Rust fn would be a fabricated member).

// ------------------------------------------------------------------
// file_flows.h:77 CurrentContextSlot —
// "The active context is the pair (current_context, current_file_id);
// see get_current_file_context(). Save/restore must round-trip both."
// ------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct CurrentContextSlot {
    pub ctx: Option<Rc<RefCell<FileContext>>>,
    pub id: u64,
}

// ------------------------------------------------------------------
// FileFlows (file_flows.h:53, FlowData base)
// ------------------------------------------------------------------

pub struct FileFlows {
    // file_flows.h:137-151, declared order (the mutex -> module
    // header deviation; all defaults = the header initializers
    // verbatim):
    pub(crate) main_context: Option<Rc<RefCell<FileContext>>>,
    pub(crate) current_context: Option<Rc<RefCell<FileContext>>>,
    pub(crate) current_file_id: u64,
    pub(crate) pending_file_id: u64,
    pub(crate) pending_resolution: bool,
    pub(crate) gen_signature: bool,
    /// C `Flow* flow` (the FlowData back-pointer): the fcache-flow
    /// view (deviation: the Flow monolith is a later row; every use
    /// of C's `flow` here passes it down unmodified).
    pub flow: CacheFlow,
    pub(crate) file_policy: Option<FilePolicyHandle>,

    /// std::unordered_map<uint64_t, FileContext*>
    pub(crate) partially_processed_contexts: Vec<(u64, Rc<RefCell<FileContext>>)>,
    pub(crate) cache_dup_count: usize,
    /// "Exact FileContext pointer scheduled for delayed deletion. May
    /// or may not alias current_context."
    pub(crate) deferred_delete_context: Option<Rc<RefCell<FileContext>>>,
    pub(crate) events: FileEventGen,
}

impl FileFlows {
    /// file_flows.h:57 `FileFlows(Flow* f) :
    /// FlowData(file_flow_data_id), flow(f) { }` (the FlowData ctor id
    /// arms through env.file_flow_data_id at init(); the header's slot
    /// defaults above cover the rest).
    pub fn new(flow: &CacheFlow) -> FileFlows {
        FileFlows {
            main_context: None,
            current_context: None,
            current_file_id: 0,
            pending_file_id: 0,
            pending_resolution: false,
            gen_signature: false,
            flow: *flow,
            file_policy: None,
            partially_processed_contexts: Vec::new(),
            cache_dup_count: 0,
            deferred_delete_context: None,
            events: FileEventGen::new(),
        }
    }

    /// file_flows.h:62 `static void init() { file_flow_data_id =
    /// FlowData::create_flow_data_id(); }` — called from
    /// FileService::file_service_init (file_service.cc:86 side) once
    /// per process; the counter is the harness graft
    /// `return ++flow_data_id;` (stubs.cc:577) — A_FFDATA_ID=1 pins.
    pub fn init(env: &mut FileEnvLite) {
        let next = env.flow_data_id.get() + 1;
        env.flow_data_id.set(next);
        env.file_flow_data_id.set(next);
    }

    /// file_flows.cc:194 `set_current_file_context(FileContext* ctx)`:
    /// "Free the previous file's deferred context. Skip if the caller
    /// is installing it back as current -- freeing would dangle
    /// current_context." ... "Explicit install overrides any file_id-
    /// based lookup."
    pub fn set_current_file_context(&mut self, ctx: &Rc<RefCell<FileContext>>) {
        // if (deferred_delete_context and (deferred_delete_context != ctx))
        //     retire_victim(deferred_delete_context);
        let drain = match &self.deferred_delete_context {
            Some(d) => !Rc::ptr_eq(d, ctx),
            None => false,
        };
        if drain {
            // C: `retire_victim(deferred_delete_context)` — null the
            // current/deferred aliases BEFORE freeing, or the Rc (a)
            // leaves an alias pointing at a freed object and (b) the
            // last-ref drop would fire at the wrong witness position
            // (vectors C2_DRAIN pins the "IMGR release" line exactly
            // inside set_current_file_context).
            let dc = self.deferred_delete_context.take();
            self.retire_victim(dc);
        }

        self.current_context = Some(ctx.clone());
        self.current_file_id = 0;
    }

    /// file_flows.cc:205 `swap_current_file_context_no_delete`:
    /// "Like set_current_file_context() but does NOT free the previous
    /// context; returns a snapshot to pass to
    /// restore_current_file_context_no_delete()."
    pub fn swap_current_file_context_no_delete(
        &mut self,
        new_ctx: &Rc<RefCell<FileContext>>,
    ) -> CurrentContextSlot {
        let saved = CurrentContextSlot {
            ctx: self.current_context.clone(),
            id: self.current_file_id,
        };
        self.current_context = Some(new_ctx.clone());
        self.current_file_id = 0;
        saved
    }

    /// file_flows.cc:214 `restore_current_file_context_no_delete(
    /// const CurrentContextSlot& saved)`
    pub fn restore_current_file_context_no_delete(&mut self, saved: &CurrentContextSlot) {
        self.current_context = saved.ctx.clone();
        self.current_file_id = saved.id;
    }

    /// file_flows.cc:220 `get_current_file_context()`:
    /// `if (current_file_id) { bool is_new_context = false;
    ///  return get_file_context(current_file_id, false, is_new_context); }
    ///  return current_context;`
    pub fn get_current_file_context(
        &mut self,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> Option<Rc<RefCell<FileContext>>> {
        if self.current_file_id != 0 {
            let mut is_new_context = false;
            // (multi_file_processing_id default = 0 -> the file_id)
            return self.get_file_context(
                self.current_file_id,
                false,
                &mut is_new_context,
                0,
                env,
                counts,
            );
        }
        self.current_context.clone()
    }

    /// file_flows.cc:231 `get_new_file_instance()`:
    /// `uint64_t thread_id = get_instance_id();
    ///  return ((thread_id << 32) | max_file_id++);` — the THREAD_LOCAL
    /// max_file_id rides the Cell (D_INSTANCE pins instance 5 ->
    /// `500000002 500000003`; id0 prints `4`: the static counts across
    /// the whole process, exactly like C).
    pub fn get_new_file_instance(&mut self, env: &FileEnvLite) -> u64 {
        let thread_id = env.get_instance_id.get() as u64;
        let id = (thread_id << 32) | (env.max_file_id.get() as u64);
        env.max_file_id.set(env.max_file_id.get() + 1);
        id
    }

    /// file_flows.cc:236 ~FileFlows — the ownership walk verbatim
    /// (C `delete ff` = `dtor()` or the last Rc drop; Drop below runs
    /// the same walk so the C5_DTOR "IMGR release" pair lands at the
    /// C delete position):
    /// "Ownership: main_context, partially_processed_contexts entries,
    /// and deferred_delete_context are owning slots (mutually disjoint
    /// at observable points). current_context and current_file_id are
    /// aliases. Drop aliases before walking owners so retire_victim()
    /// does no work re-nulling them for each owning slot."
    pub fn dtor(&mut self) {
        // current_context = nullptr; current_file_id = 0;
        self.current_context = None;
        self.current_file_id = 0;

        // FileContext* dc = deferred_delete_context;
        // deferred_delete_context = nullptr; retire_victim(dc);
        let dc = self.deferred_delete_context.take();
        drop(dc);

        // FileContext* mc = main_context; main_context = nullptr;
        // retire_victim(mc);
        let mc = self.main_context.take();
        drop(mc);

        // "Move-out before the loop so retire_victim() never sees a
        // partially-cleared partially_processed_contexts."
        let ppc = std::mem::take(&mut self.partially_processed_contexts);
        for (_id, ctx) in ppc {
            // retire_victim(elem.second) -> `delete victim`
            // (file_flows.cc:359): ~FileContext + the IMGR release
            // witness fire AT this point even while driver-side Rc
            // aliases live on (17r owner-delete model, file_lib.cc:574).
            FileContext::owner_delete(&ctx);
        }

        // FilePolicyBase::delete_file_policy(file_policy);
        // file_policy = nullptr;
        if let Some(mut fp) = self.file_policy.take() {
            fp.delete_file_policy(); // file_api.cc:34 (Box drop at 0)
        }
    }

    /// file_flows.cc:244 `find_main_file_context(FilePosition pos,
    /// FileDirection dir, size_t index)` (default 0):
    /// ```text
    /// FileContext* context = main_context;
    /// if (context) {
    ///     if ((pos == SNORT_FILE_MIDDLE)or (pos == SNORT_FILE_END))
    ///         return context;
    ///     else
    ///         delete context;
    /// }
    /// context = new FileContext;
    /// main_context = context;
    /// context->check_policy(flow, dir, file_policy);
    /// if (!index)
    /// { context->set_file_id(get_new_file_instance());
    ///   context->set_not_cacheable(); }
    /// else
    ///     context->set_file_id(index);
    /// ```text
    /// (the `delete context` before re-arm: the Rc goes at the exact C
    /// point while main_context is immediately overwritten — C's
    /// transient dangling read, unobservable.)
    pub fn find_main_file_context(
        &mut self,
        pos: u32,
        dir: u32,
        index: u64,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> Rc<RefCell<FileContext>> {
        /* Attempt to get a previously allocated context. */
        if let Some(context) = self.main_context.clone() {
            if (pos == FILE_MIDDLE) || (pos == FILE_END) {
                return context;
            }
            // else delete context;
            self.main_context = None;
            drop(context);
        }

        // context = new FileContext; (the file_lib.cc:559 ctor arms
        // through env — IMGR acquire witness lands here)
        let imgr = env.imgr.clone();
        let context = FileContext::ctor(Some(imgr), env);
        self.main_context = Some(context.clone());

        // context->check_policy(flow, dir, file_policy);
        {
            let mut cb = context.borrow_mut();
            cb.pending_dir = dir;
            match self.file_policy.as_mut() {
                Some(fp) => fp.with_policy_mut(|pol| cb.check_policy(&self.flow, pol, counts)),
                None => {
                    // C: `policy->policy_check(...)` on the possibly-
                    // null pointer (file_flows.cc:355) — UB, pinned-
                    // absent; the silent NullPolicy answers the
                    // statement (deviation note in the header).
                    cb.check_policy(&self.flow, &mut NullPolicy, counts);
                }
            }
        }

        if index == 0 {
            let id = self.get_new_file_instance(env);
            context.borrow_mut().info.set_file_id(id); // C set_file_id
            context.borrow_mut().set_not_cacheable();
        } else {
            context.borrow_mut().info.set_file_id(index);
        }

        context
    }

    /// file_flows.cc:269 `get_partially_processed_context(uint64_t
    /// file_id)` — map find (port: linear scan, insertion order —
    /// deviation at the field note).
    pub fn get_partially_processed_context(
        &mut self,
        file_id: u64,
    ) -> Option<Rc<RefCell<FileContext>>> {
        // auto elem = partially_processed_contexts.find(file_id);
        // if (elem != partially_processed_contexts.end())
        //     return elem->second;
        // return nullptr;
        self.partially_processed_contexts
            .iter()
            .find(|(id, _)| *id == file_id)
            .map(|(_, ctx)| ctx.clone())
    }

    /// file_flows.cc:276 `get_file_context(uint64_t file_id, bool
    /// to_create, bool& is_new_context, uint64_t
    /// multi_file_processing_id=0)` — the three-arm ladder:
    /// (1) "First check if this file is currently being processed"
    /// (ppc[multi ?: file_id]);
    /// (2) "Otherwise check if it has been fully processed and is in
    /// the file cache. If the file is not in the cache, don't add it."
    /// -> `file_cache->get_file(flow, file_id, false, true)` (the using
    /// _cache_entry form; Rust `_public` name pair at the 17p site) +
    /// the GET_CURRENT_PACKET "trying to get context from cache"
    /// FILEDBG + `dup_cache_context` private copy (latched into ppc,
    /// set_cache_dup + set_limit_excluded, ++cache_dup_count, the
    /// "created private copy (pending=%d)" FILEDBG); null copy -> null
    /// context;
    /// (3) the create arm: `new_context_count ==
    /// fc->max_files_per_flow` (size() - cache_dup_count) -> the
    /// TRACE_ERROR "max file per flow limit reached %lu" +
    /// `files_over_flow_limit_not_processed++` +
    /// `events.create_event(EVENT_FILE_DROPPED_OVER_LIMIT)` (the G
    /// block: one DE queue_event gid=150 sid=1 across all four attempts
    /// — the EventGen suppressed bitset), else `new FileContext` +
    /// is_new_context=true + ppc latch + the "creating new context"
    /// FILEDBG + the max_concurrent_files_per_flow latch.
    /// E_IDLADDER / G_OVERLIMIT / C1..C3 pins.
    pub fn get_file_context(
        &mut self,
        file_id: u64,
        to_create: bool,
        is_new_context: &mut bool,
        mut multi_file_processing_id: u64,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> Option<Rc<RefCell<FileContext>>> {
        *is_new_context = false;

        // First check if this file is currently being processed
        if multi_file_processing_id == 0 {
            multi_file_processing_id = file_id;
        }
        let mut context = self.get_partially_processed_context(multi_file_processing_id);

        // Otherwise check if it has been fully processed and is in the
        // file cache. If the file is not in the cache, don't add it.
        if context.is_none() {
            // FileCache* file_cache = FileService::get_file_cache();
            // assert(file_cache); (debug-only; the null-cache arm C
            // would UB on is pinned-absent: answer "not in cache")
            if let Some(file_cache) = env.svc.get_file_cache() {
                // context = file_cache->get_file(flow, file_id, false,
                //     true);
                context = file_cache.borrow_mut().get_file_public(
                    &self.flow,
                    file_id,
                    false,
                    true,
                    counts,
                );
                // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
                // TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET, "get_file_
                // context:trying to get context from cache\n");
                env.curbkt();
                env.trace.file_trace(
                    TRACE_DEBUG_LEVEL,
                    "get_file_context:trying to get context from cache\n",
                );

                if context.is_some() {
                    // bool cached_pending = false;
                    let mut cached_pending = false;
                    // FileContext* private_copy =
                    //     file_cache->dup_cache_context(flow, file_id,
                    //     cached_pending);
                    let private_copy = file_cache
                        .borrow_mut()
                        .dup_cache_context(&self.flow, file_id, &mut cached_pending);
                    if let Some(private_copy) = private_copy {
                        context = Some(private_copy);
                        // is_new_context = false; (already)
                        let ctx = context.clone().expect("just set");
                        self.ppc_insert(multi_file_processing_id, &ctx);
                        {
                            let cb = &mut *ctx.borrow_mut();
                            cb.set_cache_dup();
                            cb.set_limit_excluded();
                        }
                        self.cache_dup_count += 1;
                        // FILE_DEBUG(... GET_CURRENT_PACKET, "get_file
                        // _context:created private copy (pending=%d)\n",
                        // cached_pending);
                        env.curbkt();
                        env.trace.file_trace(
                            TRACE_DEBUG_LEVEL,
                            &format!(
                                "get_file_context:created private copy (pending={})\n",
                                u8::from(cached_pending)
                            ),
                        );
                    } else {
                        context = None;
                    }
                }
            }
        }

        // If we haven't found the context, create it and store it on
        // the file flows object
        if context.is_none() && to_create {
            // const FileConfig* fc = get_file_config(SnortConfig::
            //     get_conf());  -> the resolved config (file_config.cc:
            // 89; a null config here would be a C fc-deref UB —
            // pinned-absent, over-limit arm answers 0 gate -> create)
            let fc_max = env
                .get_file_config()
                .map(|c| c.borrow().max_files_per_flow)
                .unwrap_or(0);
            // const size_t new_context_count =
            //     partially_processed_contexts.size() - cache_dup_count;
            let new_context_count = self.partially_processed_contexts.len() - self.cache_dup_count;
            if new_context_count == (fc_max as usize) {
                // FILE_DEBUG(..., TRACE_ERROR_LEVEL, GET_CURRENT_PACKET,
                // "max file per flow limit reached %lu\n",
                // partially_processed_contexts.size());
                env.curbkt();
                env.trace.file_trace(
                    TRACE_ERROR_LEVEL,
                    &format!(
                        "max file per flow limit reached {}\n",
                        self.partially_processed_contexts.len()
                    ),
                );
                counts.files_over_flow_limit_not_processed += 1;
                // events.create_event(EVENT_FILE_DROPPED_OVER_LIMIT);
                // (event_gen.h:34 -> DetectionEngine::queue_event(GID,
                // sid) once per suppressed bit -> one
                // "DE queue_event gid=150 sid=1")
                self.events
                    .create_event(EVENT_FILE_DROPPED_OVER_LIMIT, &mut *env.de);
            } else {
                // context = new FileContext;
                let imgr = env.imgr.clone();
                let c = FileContext::ctor(Some(imgr), env); // IMGR acquire
                *is_new_context = true;
                self.ppc_insert(multi_file_processing_id, &c);
                context = Some(c);
                // FILE_DEBUG(... GET_CURRENT_PACKET, "get_file_context:
                // creating new context\n");
                env.curbkt();
                env.trace.file_trace(
                    TRACE_DEBUG_LEVEL,
                    "get_file_context:creating new context\n",
                );
                // const size_t concurrent_new = ...size() - cache_dup_count;
                let concurrent_new =
                    self.partially_processed_contexts.len() - self.cache_dup_count;
                if concurrent_new as u64 > counts.max_concurrent_files_per_flow {
                    counts.max_concurrent_files_per_flow = concurrent_new as u64;
                }
            }
        }

        context
    }

    /// `partially_processed_contexts[key] = context` — operator[]
    /// insert-or-overwrite semantics.
    fn ppc_insert(&mut self, id: u64, ctx: &Rc<RefCell<FileContext>>) {
        match self
            .partially_processed_contexts
            .iter_mut()
            .find(|(k, _)| *k == id)
        {
            Some(slot) => slot.1 = ctx.clone(),
            None => self.partially_processed_contexts.push((id, ctx.clone())),
        }
    }

    /// file_flows.cc:349 `retire_victim(FileContext* victim)` — "Free
    /// a retired FileContext and null any alias slots that referenced
    /// it." Callers hand over OWNED pointers (the slot they nulled
    /// first); the Rc last-drop here = C `delete victim`. Alias
    /// equality (pointer identity) nulls current/deferred in C order.
    fn retire_victim(&mut self, victim: Option<Rc<RefCell<FileContext>>>) {
        // if (!victim) return;
        let Some(victim) = victim else {
            return;
        };
        // if (current_context == victim) current_context = nullptr;
        if let Some(c) = &self.current_context {
            if Rc::ptr_eq(c, &victim) {
                self.current_context = None;
            }
        }
        // if (deferred_delete_context == victim)
        //     deferred_delete_context = nullptr;
        if let Some(d) = &self.deferred_delete_context {
            if Rc::ptr_eq(d, &victim) {
                self.deferred_delete_context = None;
            }
        }
        // delete victim;
        drop(victim);
    }

    /// file_flows.cc:362 `remove_processed_file_context(uint64_t
    /// file_id)` —
    /// "Retired context is ALWAYS deferred: file_process callers may
    /// dereference `context` after this returns (populate_trace_data
    /// when tracing is active), so a synchronous delete here would be
    /// a use-after-free. Drainage happens at the next
    /// set_current_file_context(other), the next
    /// remove_processed_file_context() for a different id, or
    /// ~FileFlows."
    /// (C's deref-after-remove is Rust-safe by Rc construction — the
    /// ISS-1 gate case; the erase-then-park ORDER and the limit-
    /// excluded cache_dup_count decrement are literal.)
    pub fn remove_processed_file_context(&mut self, file_id: u64) {
        // FileContext* context = get_partially_processed_context(
        //     file_id);
        let context = self.get_partially_processed_context(file_id);
        // partially_processed_contexts.erase(file_id);
        self.partially_processed_contexts
            .retain(|(id, _)| *id != file_id);
        // if (context and context->is_limit_excluded() and
        //     cache_dup_count > 0)
        //     --cache_dup_count;
        if let Some(c) = &context {
            if c.borrow().is_limit_excluded() && self.cache_dup_count > 0 {
                self.cache_dup_count -= 1;
            }
        }
        // if (!context) return;
        let Some(context) = context else {
            return;
        };
        // if (deferred_delete_context and
        //     deferred_delete_context != context)
        //     retire_victim(deferred_delete_context);
        let drain = match &self.deferred_delete_context {
            Some(d) => !Rc::ptr_eq(d, &context),
            None => false,
        };
        if drain {
            let dc = self.deferred_delete_context.take();
            self.retire_victim(dc);
        }
        // deferred_delete_context = context;
        self.deferred_delete_context = Some(context);
    }

    /// file_flows.cc:393 `file_process(Packet* p, uint64_t file_id,
    /// const uint8_t* file_data, int data_size, uint64_t offset,
    /// FileDirection dir, uint64_t multi_file_processing_id=0,
    /// FilePosition position=SNORT_FILE_POSITION_UNKNOWN, const
    /// uint8_t* fname=nullptr, uint32_t name_size=0, const uint8_t*
    /// url=nullptr, uint32_t url_size=0, const std::string& host_name
    /// ="", const bool is_partial=false)` — the multi-file form
    /// ("This function is used to process file that is sent in
    /// pieces"; true = continue processing/log/block, false = ignore).
    /// Transcribed through each arm up to the two
    /// FileContext::process call sites (:474 FULL-position re-eval arm,
    /// :488 the offset form) — pinned-panic 17r seams the probe cuts
    /// before crossing.
    #[allow(clippy::too_many_arguments)]
    pub fn file_process_multi(
        &mut self,
        p: &mut PacketView,
        file_id: u64,
        file_data: &[u8],
        data_size: i32,
        offset: u64,
        dir: u32,
        mut multi_file_processing_id: u64,
        position: u32,
        fname: &[u8],
        name_size: u32,
        url: &[u8],
        url_size: u32,
        host_name: &[u8],
        is_partial: bool,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> bool {
        // int64_t file_depth = FileService::get_max_file_depth();
        let file_depth = env.get_max_file_depth(None);
        // bool cacheable = file_id or offset;
        let cacheable = file_id != 0 || offset != 0;
        let mut is_new_context = false;

        if multi_file_processing_id == 0 {
            multi_file_processing_id = file_id;
        }

        // if ((file_depth < 0) or (offset > (uint64_t)file_depth))
        if (file_depth < 0) || (offset > (file_depth as u64)) {
            // FILE_DEBUG(..., TRACE_ERROR_LEVEL, p, "file depth less
            // than zero or offset is more than file depth , returning\n")
            env.trace.file_trace(
                TRACE_ERROR_LEVEL,
                "file depth less than zero or offset is more than file depth , returning\n",
            );
            return false;
        }

        // FileContext* context = get_file_context(file_id, true,
        //     is_new_context, multi_file_processing_id);
        let context = match self.get_file_context(
            file_id,
            true,
            &mut is_new_context,
            multi_file_processing_id,
            env,
            counts,
        ) {
            Some(c) => c,
            None => {
                // FILE_DEBUG(..., TRACE_CRITICAL_LEVEL, p, "file_
                // process:context missing, returning \n")
                env.trace.file_trace(
                    TRACE_CRITICAL_LEVEL,
                    "file_process:context missing, returning \n",
                );
                return false;
            }
        };

        // if (context->has_to_re_eval() and context->processing_complete
        //     and not is_partial)
        if context.borrow().info.has_to_re_eval()
            && context.borrow().info.processing_complete
            && !is_partial
        {
            // FILE_DEBUG(..., TRACE_CRITICAL_LEVEL, p, "file_process:
            // reset context for re-evaluation \n")
            env.trace.file_trace(
                TRACE_CRITICAL_LEVEL,
                "file_process:reset context for re-evaluation \n",
            );
            // context->reset();
            context.borrow_mut().reset(env);
        }
        context.borrow_mut().info.set_partial_flag(is_partial);
        context
            .borrow_mut()
            .info
            .set_weak_file_name(non_empty(fname), name_size);
        context.borrow_mut().info.set_weak_url(non_empty(url), url_size);
        context
            .borrow_mut()
            .info
            .set_host(non_empty(host_name), host_name.len() as u32); // C set_host(str,size)

        // if (PacketTracer::is_daq_activated())
        //     PacketTracer::restart_timer();
        if env.packet_tracer.is_daq_activated() {
            env.packet_tracer.restart_timer();
        }

        // if (!cacheable) context->set_not_cacheable();
        if !cacheable {
            context.borrow_mut().set_not_cacheable();
        }

        // if(!context->processing_complete)
        //     set_current_file_context(context);
        // else
        //     current_file_id = file_id;
        if !context.borrow().info.processing_complete {
            self.set_current_file_context(&context);
        } else {
            self.current_file_id = file_id;
        }

        // "Only increase file count when there are no queued segments
        // This will ensure we only count a file once in case it has
        // processed bytes 0 but many queued segments"
        if context.borrow().get_processed_bytes() == 0 && !context.borrow().segments_queued() {
            let flow = self.flow;
            let mut cb = context.borrow_mut();
            cb.pending_dir = dir;
            match self.file_policy.as_mut() {
                Some(fp) => fp.with_policy_mut(|pol| cb.check_policy(&flow, pol, counts)),
                None => cb.check_policy(&flow, &mut NullPolicy, counts),
            }
            cb.info.set_file_id(file_id);
        }

        // if ((context->is_cacheable() and not is_new_context) or
        //     context->is_partial_download()) // If partial header was
        //     seen - check file_cache
        if (context.borrow().is_cacheable() && !is_new_context)
            || context.borrow().info.is_partial_download()
        {
            // FileVerdict verdict = FileService::get_file_cache()->
            //     cached_verdict_lookup(p, context, file_policy,
            //     file_data, data_size);
            // (C derefs the cache pointer here; a null cache is UB —
            // pinned-absent: B/J arms always arm the cache)
            let file_cache = env
                .svc
                .get_file_cache()
                .expect("FileService::get_file_cache() null at file_flows.cc:443 (C deref, pinned-absent)");
            let verdict = {
                let mut fc = file_cache.borrow_mut();
                match self.file_policy.as_mut() {
                    Some(fp) => fp.with_policy_mut(|pol| {
                        fc.cached_verdict_lookup(p, &context, pol, file_data, data_size as u32, counts)
                    }),
                    None => fc.cached_verdict_lookup(
                        p,
                        &context,
                        &mut NullPolicy,
                        file_data,
                        data_size as u32,
                        counts,
                    ),
                }
            };
            if verdict != FILE_VERDICT_UNKNOWN && verdict != FILE_VERDICT_PENDING {
                // file_counts.file_cache_hits++;
                counts.file_cache_hits += 1;
                // context->processing_complete = true;
                context.borrow_mut().info.processing_complete = true;
                // remove_processed_file_context(
                //     multi_file_processing_id);
                self.remove_processed_file_context(multi_file_processing_id);
                // if (PacketTracer::is_daq_activated())
                //     populate_trace_data(context);
                if env.packet_tracer.is_daq_activated() {
                    populate_trace_data(&context.borrow(), env);
                }
                return false;
            } else if verdict == FILE_VERDICT_PENDING {
                return true;
            }
        }

        // if (context->processing_complete and context->verdict !=
        //     FILE_VERDICT_UNKNOWN)
        if context.borrow().info.processing_complete
            && context.borrow().info.verdict != FILE_VERDICT_UNKNOWN
        {
            // /*A new file session, but policy might be different*/
            let flow = self.flow;
            {
                let mut cb = context.borrow_mut();
                cb.pending_dir = dir;
                match self.file_policy.as_mut() {
                    Some(fp) => fp.with_policy_mut(|pol| cb.check_policy(&flow, pol, counts)),
                    None => cb.check_policy(&flow, &mut NullPolicy, counts),
                }
                // if ((context->get_file_sig_sha256()) ||
                //     !context->is_file_signature_enabled())
                if cb.info.get_file_sig_sha256().is_some() || !cb.info.is_file_signature_enabled() {
                    // /* Just check file type and signature */
                    // FILE_DEBUG(..., TRACE_DEBUG_LEVEL, p, "calling
                    // context processing for position full\n")
                    drop(cb);
                    env.trace.file_trace(
                        TRACE_DEBUG_LEVEL,
                        "calling context processing for position full\n",
                    );
                    // continue_processing = context->process(p,
                    //     file_data, data_size, SNORT_FILE_FULL,
                    //     file_policy);    <-- file_flows.cc:474 (17r)
                    // C: `context->process(p, file_data, data_size,
                    // SNORT_FILE_FULL, file_policy)` — the position-
                    // form overload = process_pos (Rust split).
                    // 17r UNLOCKED seam (file_lib.cc:825 process pos
                    // form). Deviations, both 17q-disciplined:
                    //  * the C raw `file_policy` pointer rides a handle
                    //    alias (file_policy.clone() — the Rc alias of
                    //    the same PolicyStore; aliasing, not ref_count)
                    //    and is turned into the C-pointer holder
                    //    Option<&mut dyn FilePolicyApi> inside
                    //    with_policy_mut, held for the whole ladder;
                    //  * the C `FileFlows::get_file_flows(p->flow,
                    //    false)` the ladder resolves later IS this
                    //    object (flow-data identity) — the flows Ref is
                    //    Some(self), no static re-resolution.
                    let policy_alias = self.file_policy.clone();
                    let mut ff_ref = FlowsRef::Direct(self);
                    let continue_processing = process_pos(
                        &context,
                        p,
                        file_data,
                        data_size,
                        FILE_FULL,
                        policy_alias,
                        &mut ff_ref,
                        env,
                        counts,
                    );
                    if context.borrow().info.processing_complete {
                        self.remove_processed_file_context(multi_file_processing_id);
                    }
                    if env.packet_tracer.is_daq_activated() {
                        populate_trace_data(&context.borrow(), env);
                    }
                    return continue_processing;
                }
            }
        }

        // FILE_DEBUG(..., TRACE_DEBUG_LEVEL, p, "calling context
        // process data_size %d, offset %" PRIu64 ", position %d\n",
        // data_size, offset, position);
        env.trace.file_trace(
            TRACE_DEBUG_LEVEL,
            &format!("calling context process data_size {data_size}, offset {offset}, position {position}\n"),
        );
        // continue_processing = context->process(p, file_data,
        //     data_size, offset, file_policy, position);  <-- :488 (17r
        // UNLOCKED — offset overload, file_lib free `process`; holder
        // + flows-Ref deviations as at the :474 site above).
        let policy_alias = self.file_policy.clone();
                    let mut ff_ref = FlowsRef::Direct(self);
        let continue_processing = process(
            &context,
            p,
            file_data,
            data_size,
            offset,
            policy_alias,
            position,
            &mut ff_ref,
            env,
            counts,
        );
        if context.borrow().info.processing_complete {
            self.remove_processed_file_context(multi_file_processing_id);
        }
        if env.packet_tracer.is_daq_activated() {
            populate_trace_data(&context.borrow(), env);
        }
        continue_processing
    }

    /// file_flows.cc:505 `file_process(Packet* p, const uint8_t*
    /// file_data, int data_size, FilePosition position, bool upload,
    /// size_t file_index = 0, const uint8_t* fname = nullptr,
    /// uint32_t name_size = 0)` — "This is used when there is only one
    /// file per session" (true: continue; false: ignore).
    #[allow(clippy::too_many_arguments)] // C signature, 11 params verbatim
    pub fn file_process(
        &mut self,
        p: &mut PacketView,
        file_data: &[u8],
        data_size: i32,
        position: u32,
        upload: bool,
        file_index: u64,
        fname: &[u8],
        name_size: u32,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> bool {
        // FileDirection direction = upload ? FILE_UPLOAD : FILE_DOWNLOAD;
        let direction = if upload { FILE_UPLOAD } else { FILE_DOWNLOAD };
        /* if both disabled, return immediately*/
        // if (!FileService::is_file_service_enabled())
        if !env.svc.is_file_service_enabled() {
            // FILE_DEBUG(..., TRACE_ERROR_LEVEL, p, "file_process:file
            // service not enabled, returning\n")
            env.trace.file_trace(
                TRACE_ERROR_LEVEL,
                "file_process:file service not enabled, returning\n",
            );
            return false;
        }

        // if (position == SNORT_FILE_POSITION_UNKNOWN)
        if position == FILE_POSITION_UNKNOWN {
            // FILE_DEBUG(..., TRACE_ERROR_LEVEL, p, "file_process:
            // position of file is unknown, returning\n")
            env.trace.file_trace(
                TRACE_ERROR_LEVEL,
                "file_process:position of file is unknown, returning\n",
            );
            return false;
        }

        // if (PacketTracer::is_daq_activated())
        //     PacketTracer::restart_timer();
        if env.packet_tracer.is_daq_activated() {
            env.packet_tracer.restart_timer();
        }

        // context = find_main_file_context(position, direction,
        //     file_index);
        let context = self.find_main_file_context(position, direction, file_index, env, counts);
        // FileCache* file_cache = FileService::get_file_cache();
        // if (file_cache and file_cache->cached_context_not_cacheable(
        //         flow, file_index))
        //     context->set_not_cacheable();
        if let Some(file_cache) = env.svc.get_file_cache() {
            if file_cache
                .borrow_mut()
                .cached_context_not_cacheable(&self.flow, file_index)
            {
                context.borrow_mut().set_not_cacheable();
            }
        }

        // set_current_file_context(context);
        self.set_current_file_context(&context);
        // context->set_weak_file_name((const char*)fname, name_size);
        context
            .borrow_mut()
            .info
            .set_weak_file_name(non_empty(fname), name_size);

        // context->set_signature_state(gen_signature);
        let gs = self.gen_signature;
        context.borrow_mut().set_signature_state(gs);
        // bool file_process_ret = context->process(p, file_data,
        //     data_size, position, file_policy);   <-- :590 (17r seam;
        // C passes FilePolicyBase* straight through; position-form
        // overload = process_pos)
        // (17r UNLOCKED — position form again; deviations as at :474)
        let policy_alias = self.file_policy.clone();
                    let mut ff_ref = FlowsRef::Direct(self);
        let file_process_ret = process_pos(
            &context,
            p,
            file_data,
            data_size,
            position,
            policy_alias,
            &mut ff_ref,
            env,
            counts,
        );
        if env.packet_tracer.is_daq_activated() {
            populate_trace_data(&context.borrow(), env);
        }
        file_process_ret
    }

    /// file_flows.cc:551 `set_file_name(const uint8_t* fname,
    /// uint32_t name_size, uint64_t file_id=0, uint64_t
    /// multi_file_processing_id=0, const uint8_t* url=nullptr,
    /// uint32_t url_size=0)` — "true: continue processing this file;
    /// false: ignore this file". H_SETNAME1/2 pins (the id 0 /
    /// current-context arm, the set_url + set_file_name +
    /// log_file_event pair, the processed==max_file_depth OR the
    /// type-and-no-capture-and-no-signature completion arm with the
    /// remove_processed_file_context(multi) tail).
    #[allow(clippy::too_many_arguments)] // C signature, 9 params verbatim
    pub fn set_file_name(
        &mut self,
        fname: &[u8],
        name_size: u32,
        file_id: u64,
        multi_file_processing_id: u64,
        url: &[u8],
        url_size: u32,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> bool {
        // FileContext* context;
        let context = if file_id != 0 {
            // bool is_new_context = false;
            let mut is_new_context = false;
            // context = get_file_context(file_id, false, is_new_context,
            //     multi_file_processing_id);
            self.get_file_context(
                file_id,
                false,
                &mut is_new_context,
                multi_file_processing_id,
                env,
                counts,
            )
        } else {
            // context = get_current_file_context();
            self.get_current_file_context(env, counts)
        };
        // if ( !context ) return false;
        let Some(context) = context else {
            return false;
        };

        // if ( !context->is_url_set() )
        //     context->set_url((const char*)url, url_size);
        if !context.borrow().info.is_url_set() {
            context.borrow_mut().info.set_url(non_empty(url), url_size);
        }

        // if ( !context->is_file_name_set() )
        // { context->set_file_name((const char*)fname, name_size);
        //   context->log_file_event(flow, file_policy); }
        if !context.borrow().info.is_file_name_set() {
            context
                .borrow_mut()
                .info
                .set_file_name(non_empty(fname), name_size);
            // the REAL file_lib.cc:613 body through FileEnvLite (the
            // file_cache.rs sites keep the 17p seam forwarder —
            // deviation restated at FileContext::log_file_event_sink)
            let flow = self.flow;
            match self.file_policy.as_mut() {
                Some(fp) => fp.with_policy_mut(|pol| {
                    context.borrow_mut().log_file_event(&flow, Some(pol), env)
                }),
                None => context.borrow_mut().log_file_event(&flow, None, env),
            }
        }

        // if ((context->get_processed_bytes() == (uint64_t)FileService::
        //     get_max_file_depth()) or
        //     ((context->get_file_type() != SNORT_FILE_TYPE_CONTINUE)
        //      and (!context->is_file_capture_enabled())
        //      and (!context->is_file_signature_enabled())))
        let depth_gate = context.borrow().get_processed_bytes()
            == (env.get_max_file_depth(None) as u64);
        let type_gate = context.borrow().info.get_file_type() != SNORT_FILE_TYPE_CONTINUE
            && !context.borrow().info.is_file_capture_enabled()
            && !context.borrow().info.is_file_signature_enabled();
        if depth_gate || type_gate {
            // context->processing_complete = true;
            context.borrow_mut().info.processing_complete = true;
            // "this can be called by inspector also if needed instead
            // of here based on return value"
            // remove_processed_file_context(multi_file_processing_id);
            // (C erases the multi id — 0 default erases a hypothetical
            // id-0 entry only; literal either way)
            self.remove_processed_file_context(multi_file_processing_id);
            return false;
        }
        true
    }

    /// file_flows.cc:585 `add_pending_file(uint64_t file_id)` (the
    /// H_PEND_RETRANS reach in 17p drove this through the FF sink):
    /// `current_file_id = pending_file_id = file_id;
    ///  pending_resolution = true;`
    pub fn add_pending_file(&mut self, file_id: u64) {
        self.current_file_id = file_id;
        self.pending_file_id = file_id;
        self.pending_resolution = true;
    }

    /// file_flows.h:101 `void set_sig_gen_state(bool enable)
    /// { gen_signature = enable; }`
    pub fn set_sig_gen_state(&mut self, enable: bool) {
        self.gen_signature = enable;
    }

    /// file_flows.cc:121 `handle_retransmit(Packet* p)` — the FlowData
    /// hook (flow->retransmit reaches it; C's FF sink call sites keep
    /// the seam in file_cache.rs — the 17p witness wiring — this is the
    /// real body).
    /// "J_RETRANS_*" pins: no-policy early return, the null-context
    /// bail FILEDBG pair, the cache arm (set_current_file_context +
    /// resume_pending_verdict + the verdict FILEDBG + the
    /// pending_resolution clear gate), and the no-cache arm
    /// (`file_policy->signature_lookup(p, file);
    ///  file->log_file_event(flow, file_policy);`).
    pub fn handle_retransmit(
        &mut self,
        p: &mut PacketView,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) {
        // FILE_DEBUG(..., TRACE_DEBUG_LEVEL, p, "handle_retransmit:
        // queried for verdict\n")
        env.trace.file_trace(TRACE_DEBUG_LEVEL, "handle_retransmit:queried for verdict\n");
        // if (file_policy == nullptr) return;
        if self.file_policy.is_none() {
            return;
        }

        // bool is_new_context = false;
        let mut is_new_context = false;
        // FileContext* file = get_file_context(pending_file_id, false,
        //     is_new_context);
        let file = self.get_file_context(self.pending_file_id, false, &mut is_new_context, 0, env, counts);

        // if ((file == nullptr) or
        //     ((file->verdict != FILE_VERDICT_PENDING) and
        //      (file->is_cacheable()) and !pending_resolution))
        let bail = file.is_none()
            || {
                let fb = file.as_ref().expect("just checked").borrow();
                (fb.info.verdict != FILE_VERDICT_PENDING)
                    && fb.is_cacheable()
                    && !self.pending_resolution
            };
        if bail {
            // FILE_DEBUG(..., TRACE_ERROR_LEVEL, p, "handle_retransmit:
            // context is null or verdict not pending, returning\n")
            env.trace.file_trace(
                TRACE_ERROR_LEVEL,
                "handle_retransmit:context is null or verdict not pending, returning\n",
            );
            return;
        }
        let file = file.expect("bail checked");

        // FileCache* file_cache = FileService::get_file_cache();
        let file_cache = env.svc.get_file_cache();

        if let Some(file_cache) = file_cache {
            // set_current_file_context(file);
            self.set_current_file_context(&file);

            // FileVerdict verdict = file_cache->resume_pending_verdict(
            //     p, file, file_policy);
            let verdict = {
                let mut fc = file_cache.borrow_mut();
                match self.file_policy.as_mut() {
                    Some(fp) => fp.with_policy_mut(|pol| fc.resume_pending_verdict(p, &file, pol, counts)),
                    // (entry guard already proved file_policy non-null;
                    // the arm keeps the statement transcribed)
                    None => fc.resume_pending_verdict(p, &file, &mut NullPolicy, counts),
                }
            };
            // FILE_DEBUG(..., TRACE_DEBUG_LEVEL, p, "handle_retransmit:
            // file cache verdict %d\n", verdict);
            env.trace.file_trace(
                TRACE_DEBUG_LEVEL,
                &format!("handle_retransmit:file cache verdict {verdict}\n"),
            );
            // if (verdict != FILE_VERDICT_PENDING and verdict !=
            //     FILE_VERDICT_UNKNOWN)
            //     pending_resolution = false;
            if verdict != FILE_VERDICT_PENDING && verdict != FILE_VERDICT_UNKNOWN {
                self.pending_resolution = false;
            }
        } else {
            // file_policy->signature_lookup(p, file);
            // (file_policy non-null: the entry guard)
            let policy_ref = self
                .file_policy
                .as_mut()
                .expect("entry guard: file_policy non-null");
            policy_ref.with_policy_mut(|pol| pol.signature_lookup(p, &mut file.borrow_mut()));
            // (the FileVerdict return is discarded in C too)
            // file->log_file_event(flow, file_policy);
            let flow = self.flow;
            match self.file_policy.as_mut() {
                Some(fp) => fp.with_policy_mut(|pol| {
                    file.borrow_mut().log_file_event(&flow, Some(pol), env)
                }),
                None => file.borrow_mut().log_file_event(&flow, None, env),
            }
            // if (file->verdict != FILE_VERDICT_PENDING and file->
            //     verdict != FILE_VERDICT_UNKNOWN)
            //     pending_resolution = false;
            let v = file.borrow().info.verdict;
            if v != FILE_VERDICT_PENDING && v != FILE_VERDICT_UNKNOWN {
                self.pending_resolution = false;
            }
        }
    }

    /// file_flows.h:120 `set_file_policy(FilePolicyBase* fp)`:
    /// ```text
    /// assert(fp);
    /// FilePolicyBase::delete_file_policy(file_policy);
    /// fp->add_ref();
    /// file_policy = fp;
    /// ```text
    /// (the handle side runs the exact C ref_count protocol; C's
    /// delete-of-previous lands before the add_ref — file_api.cc:34.)
    pub fn set_file_policy(&mut self, mut fp: FilePolicyHandle) {
        // assert(fp);
        debug_assert!(fp.ref_count() > 0); // handle carries the object
        // FilePolicyBase::delete_file_policy(file_policy);
        if let Some(mut old) = self.file_policy.take() {
            old.delete_file_policy();
        }
        // fp->add_ref();  file_policy = fp;
        fp.add_ref();
        self.file_policy = Some(fp);
    }

    /// file_flows.h:127 `FilePolicyBase* get_file_policy()` (member).
    pub fn get_file_policy(&mut self) -> Option<&mut FilePolicyHandle> {
        self.file_policy.as_mut()
    }

    /// file_flows.cc:156 static `get_file_policy(Flow* flow)`:
    /// `FileFlows* fd = static_cast<FileFlows*>(flow->get_flow_data(
    ///     FileFlows::file_flow_data_id));
    ///  if (fd) return fd->get_file_policy();
    ///  return nullptr;` (flow side is the driver's slot, deviation
    /// restated at the module header).
    /// (The Rust borrow shape cannot hand out a &mut through the
    /// Rc<RefCell> chain the way C returns the raw pointer; the only
    /// pinned reader of this static — FileContext::file_signature_
    /// lookup, file_lib.cc:1355 — is a 17r body, which will take the
    /// handle by clone/refcount check. Answer here is the C truth test
    /// `fd && fd->file_policy` + a cloned handle for the caller.)
    pub fn get_file_policy_static(
        flows: Option<&Rc<RefCell<FileFlows>>>,
    ) -> Option<FilePolicyHandle> {
        let ff = flows?;
        ff.borrow_mut().file_policy.clone()
    }

    /// file_flows.cc:133 static `get_file_flows(Flow* flow, bool
    /// to_create=true)`:
    /// ```text
    /// FileFlows* fd = ...flow->get_flow_data(file_flow_data_id);
    /// if (!to_create or fd) return fd;
    /// if (FileService::is_file_service_enabled())
    /// {   fd = new FileFlows(flow);
    ///     flow->set_flow_data(fd);
    ///     fd->set_file_policy(get_network_policy()->
    ///         get_base_file_policy()); }
    /// return fd;
    /// ```text
    /// B_CREATE / B_DISABLED pins (`ff=0 pol=0`,
    /// `ff=1 pol_is_stub=1 refs=1->2 ... same_ptr=1 same_nocreate=1
    /// static_pol=1`, the WITNESS get_network_policy +
    /// POLICY base_file_policy -> stub pair). The C single FlowData
    /// slot rides the driver-passed slot handle (harness graft).
    pub fn get_file_flows(
        slot: &mut Option<Rc<RefCell<FileFlows>>>,
        flow: &CacheFlow,
        to_create: bool,
        env: &mut FileEnvLite,
    ) -> Option<Rc<RefCell<FileFlows>>> {
        // if (!to_create or fd) return fd;
        if !to_create || slot.is_some() {
            return slot.clone();
        }

        // if (FileService::is_file_service_enabled())
        if env.svc.is_file_service_enabled() {
            // fd = new FileFlows(flow);
            let mut ff = FileFlows::new(flow);
            // fd->set_file_policy(get_network_policy()->
            //     get_base_file_policy());
            // C derefs get_network_policy() unguarded (main/policy.h:91
            // — null main policy is UB, pinned-absent); the test seam
            // answers the "WITNESS get_network_policy" +
            // "POLICY base_file_policy -> stub" pair.
            let base = env
                .network_policy
                .as_ref()
                .expect("get_network_policy() null at file_flows.cc:150 (C deref, pinned-absent)")
                .borrow_mut()
                .get_base_file_policy()
                .expect("get_base_file_policy() -> nullptr at file_flows.cc:150 (C set_file_policy assert(fp); pinned-absent)");
            ff.set_file_policy(base);
            let ff = Rc::new(RefCell::new(ff));
            *slot = Some(ff.clone()); // flow->set_flow_data(fd)
            return Some(ff);
        }

        slot.clone() // return fd (null)
    }
}

/// ~FileFlows (file_flows.cc:236): Drop runs the same ownership walk
/// as dtor() so a plain scope-end drop reproduces the C5_DTOR witness
/// positions; an explicit dtor() beforehand makes this a no-op.
impl Drop for FileFlows {
    fn drop(&mut self) {
        self.dtor();
    }
}

// -- C UNIT_TEST block (file_flows.cc:571-779) counterparts ---------
// FFTestAccessor's slot writers/readers replay through these
// (pub-in-port so the external parity-test crate can arm slots exactly
// like the C friend; the FF_TEST_CONTEXT(42) shape = FileContext::ctor
// + set_file_id).

impl FileFlows {
    /// `FFTestAccessor::ppc(ff)` — read side of the map (id -> ctx
    /// clones) for the CHECKs (`deferred(*ff) == a`,
    /// `ppc(*ff).count(1) == 1`, `.empty()`).
    pub fn ff_test_ppc(&self) -> Vec<(u64, Rc<RefCell<FileContext>>)> {
        self.partially_processed_contexts.clone()
    }
    /// `ppc(ff)[id] = ctx` (map operator[] latch used by the gate
    /// cases).
    pub fn ff_test_ppc_set(&mut self, id: u64, ctx: &Rc<RefCell<FileContext>>) {
        self.ppc_insert(id, ctx);
    }
    /// `ppc(ff)[id] = ctx` then the C erase leg of
    /// remove_processed_file_context tests ("Mimic ... erase-then-park
    /// sequence", main_context / current_context / deferred writers).
    pub fn ff_test_ppc_erase(&mut self, id: u64) {
        self.partially_processed_contexts
            .retain(|(k, _)| *k != id);
    }
    pub fn ff_test_current(&self) -> Option<Rc<RefCell<FileContext>>> {
        self.current_context.clone()
    }
    pub fn ff_test_current_set(&mut self, ctx: &Rc<RefCell<FileContext>>) {
        self.current_context = Some(ctx.clone());
    }
    pub fn ff_test_current_clear(&mut self) {
        self.current_context = None;
    }
    pub fn ff_test_current_file_id(&self) -> u64 {
        self.current_file_id
    }
    pub fn ff_test_current_file_id_set(&mut self, id: u64) {
        self.current_file_id = id;
    }
    pub fn ff_test_deferred(&self) -> Option<Rc<RefCell<FileContext>>> {
        self.deferred_delete_context.clone()
    }
    pub fn ff_test_deferred_set(&mut self, ctx: &Rc<RefCell<FileContext>>) {
        self.deferred_delete_context = Some(ctx.clone());
    }
    pub fn ff_test_main(&self) -> Option<Rc<RefCell<FileContext>>> {
        self.main_context.clone()
    }
    pub fn ff_test_main_set(&mut self, ctx: &Rc<RefCell<FileContext>>) {
        self.main_context = Some(ctx.clone());
    }
    /// `partially_processed_contexts.size()` (the map size read).
    pub fn ff_test_ppc_len(&self) -> usize {
        self.partially_processed_contexts.len()
    }
    /// `cache_dup_count` read.
    pub fn ff_test_cache_dup_count(&self) -> usize {
        self.cache_dup_count
    }
    /// `pending_resolution` read.
    pub fn ff_test_pending_resolution(&self) -> bool {
        self.pending_resolution
    }
    /// C `file_policy != nullptr` + `policy == other` identity reads
    /// (B_CREATE's pol_is_stub / static_pol arms through the handle).
    pub fn ff_test_policy_same_store(&self, other: &FilePolicyHandle) -> bool {
        self.file_policy.as_ref().is_some_and(|p| p.same_store(other))
    }
    pub fn ff_test_has_policy(&self) -> bool {
        self.file_policy.is_some()
    }
}

// -- borrow-shape helpers (no C counterpart, no semantics) ----------

/// The null-file_policy arm's silent answer (C UB deref, pinned-
/// absent): every FilePolicyApi virtual is the C base-class default.
struct NullPolicy;
impl FilePolicyApi for NullPolicy {
    fn policy_check(&mut self, _flow: &CacheFlow, _file: &mut FileContext) {}
    fn type_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        super::file_lib::FILE_VERDICT_UNKNOWN
    }
    fn signature_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        super::file_lib::FILE_VERDICT_UNKNOWN
    }
    fn log_file_action(&mut self, _flow: &CacheFlow, _file: &mut FileContext, _action: u32) {}
}

/// `(const char*)s, size` -> the FileInfo setters' Option shape: empty
/// C string == nullptr argument (the setters guard identically).
fn non_empty(s: &[u8]) -> Option<&[u8]> {
    (!s.is_empty()).then_some(s)
}
