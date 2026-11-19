//! Literal port of `file_api/file_capture.{h,cc}` — the file-capture
//! buffer ladder (mempool blocks, the MIN/MAX/MEMCAP state machine,
//! reserve/get/store), the disk-store pair and the async-writer half,
//! row 17s.
//!
//! Ground truth: /opt/data/snort3-src (file_capture.h 150 +
//! file_capture.cc 913 lines) @ fe29cbe7403a. Compilable region =
//! file_capture.cc:1-:619; :620-:913 is the upstream UNIT_TEST block
//! (4 `[file_capture]` TEST_CASEs + the AsyncWriterGate scaffold) —
//! its C transcripts live in `tools/fcap_harness/` (vectors.txt md5
//! 0208a69116861a506f0c46a7dc36b2ac, NEVER edited). Parity test =
//! `tests/fcapture_parity_test.rs`.
//!
//! C shapes -> Rust shapes (deviations, recorded under the
//! KNOWN DEVIATIONS.md row for this file):
//! * **Single-thread async model** (17r `user_file_data_mutex`
//!   precedent, fcap PLAN §8-2): `capture_mutex`/`capture_cv`
//!   (:58-:59) and `std::thread* file_storer` (:60, spawned :171,
//!   joined :188) are comment-transcribed, never ported — NO OS
//!   thread is ever spawned. `writer_thread` (:79-:117) splits at the
//!   UNIT_TEST hook sites (:100-:103 post-pop / :112-:115
//!   post-release) into `writer_pop()` + `writer_finish()` so the
//!   gate ladder's interleavings stay scriptable single-threaded;
//!   `flush()` (:194-:209) inline-performs the writer's iterations
//!   (the C predicate :207 waits ON the writer); `exit()` (:178-:192)
//!   models the join as "drain the queue first" per the C writer
//!   comment :89-:91 ("When !running we write out any remaining
//!   files before exiting").
//! * **C file-statics live in `FileCaptureShared`** (17r in-object
//!   precedent): `file_mempool` (:55), `capture_block_size` (:56),
//!   `files_waiting` (:61), `file_storing` (:62), `running` (:63)
//!   plus a `file_storer_alive` flag standing in for the :60 thread
//!   pointer. `store_file_async` (:564-:584) consumes `Box<Self>`: C
//!   pushes the raw `this` and the writer `delete`s it (:106); the
//!   Rust queue owns the Box (move = the C ownership transfer). The
//!   trait-object seam `Box<dyn FileCaptureApi>` never reaches the
//!   async half — its only C feeder is `file_policy.cc:197`
//!   (`store_file_async` on a reserved capture), a later row, and
//!   `FileCaptureTestAccess::enqueue` (:641-:654) builds concrete
//!   captures itself. `Rc` note: a queued capture holds
//!   `Rc<FileCaptureShared>` whose queue holds its Box — the pool
//!   stays unreachable until the writer drains (C leaks raw
//!   `this` the same way); every pinned sequence drains
//!   (writer_step / flush / exit) before teardown, and the factory's
//!   Rc's die with it.
//! * **THREAD_LOCAL `file_counts` merge** (fcap PLAN §9-2): the C
//!   probe pinned that the writer thread's `delete file` (:106)
//!   bumps the WRITER's per-thread counts, invisible on the main
//!   thread (`F_tls_split main_files_released_d=0`, vectors.txt:22).
//!   Single-thread port -> ONE counts object (driver-owned
//!   `Rc<RefCell<FileCounts>>`, 17m FileStatsEnv discipline): which
//!   counter bumps where is unchanged, only the per-thread split
//!   merges — deltas the C vectors recorded as writer-invisible
//!   become visible 1:1 here.
//! * **Layout constants are pinned literals, never `size_of`**:
//!   `SIZEOF_FILE_CAPTURE = 72` drives the slot-size math (:220/:591)
//!   and 16 = `sizeof(FileCaptureBlock)` is the C payload offset
//!   (:294/:318/:335/:481) — probe CONST line, vectors.txt:1;
//!   cross-check `SLOT_BLOCK64 = align8(64+72) = 136` (:228-:229
//!   math, vectors.txt:1). C `FileCaptureBlock` lives INSIDE the
//!   mempool slot (slot = block_len + 72 bytes); the Rust block
//!   keeps the slot index for m_release/m_free and an owned
//!   `payload: Vec<u8>` (capacity = capture_block_size) for the
//!   region C addresses at block + 16 — the mempool arena stays
//!   accounting-only (slot ids, counters, double-free magic), the
//!   same block-identity discipline as file_mempool.rs's
//!   `Option<usize>` slots.
//! * `std::queue<FileCapture*>` (:61) -> `VecDeque<Box<FileCapture>>`.
//! * `fopen(name, "wx")` (:536) -> `OpenOptions::create_new(true)`
//!   (`O_WRONLY|O_CREAT|O_EXCL`); each `fclose` site = `File` drop at
//!   scope end.
//! * block chain: C `FileCaptureBlock* next` -> `Option<usize>`
//!   arena index; `current_data` (:141 `const uint8_t*`) -> owned
//!   `Vec<u8>` copy (the C dangling-pointer hazard is structurally
//!   excluded; pinned runs satisfy `current_data_len <=
//!   current_data.len()` — C UB otherwise).

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::Write;
use std::rc::Rc;

use super::file_lib::{
    FileCaptureApi, FileCaptureFactory, FileInfo, FILE_CAPTURE_MAX, FILE_CAPTURE_MEMCAP,
    FILE_CAPTURE_MIN, FILE_CAPTURE_SUCCESS, SNORT_FILE_END, SNORT_FILE_FULL,
};
use super::file_mempool::{FILE_MEM_SUCCESS, FileMemPool};
use super::file_stats::FileCounts;
use crate::framework::counts::PegCount;
use crate::utils::stats::snapshot::Builder;

/// Pinned C layout constant: `sizeof(FileCapture)` (probe CONST line,
/// vectors.txt:1) — drives the mempool slot math at :220/:591. NEVER
/// recompute from Rust `size_of` (fcap PLAN §9-3).
pub const SIZEOF_FILE_CAPTURE: i64 = 72;

/// Pinned C layout constant: `sizeof(FileCaptureBlock)` =
/// `length(4) + pad(4) + next(8)` on x86-64 (probe CONST line,
/// vectors.txt:1). The C payload starts at block + 16
/// (:294/:318/:335/:481); here the payload is the per-block `Vec<u8>`
/// and 16 remains the slot-math cross-check.
pub const SIZEOF_FILE_CAPTURE_BLOCK: i64 = 16;

/// vectors.txt:1 cross-check: 8-align(64 + SIZEOF_FILE_CAPTURE) = 136
/// — the slot the 1 MiB / 64 B config carve uses (:220 + :228-:229,
/// 1 MiB / 136 = 7710 buffers, vectors.txt:4).
pub const SLOT_BLOCK64: i64 = 136;

/// Linux `errno` values the :513 retry arms name (`EINTR`, `EAGAIN`).
/// The crate hand-links libc symbols (util.rs extern block), so the
/// constants are pinned here (C fcntl.h <asm-generic/errno.h> arm).
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;

/// `struct FileCaptureBlock` (file_capture.h:56-:60): the C
/// in-slot header (`length`, `next`) + the payload region C
/// addresses at block + 16 (module header).
pub struct FileCaptureBlock {
    /// C `uint32_t length` — valid payload bytes (never > block_size)
    length: u32,
    /// C `FileCaptureBlock* next` -> arena index (module header)
    next: Option<usize>,
    /// the mempool slot backing this block (C: the block pointer IS
    /// the slot; needed verbatim for m_release/m_free at :145/:151)
    slot: usize,
    /// the C slot payload region (capacity = capture_block_size)
    payload: Vec<u8>,
}

/// seam for `main/thread.h get_instance_file` at file_capture.cc:577
pub trait InstanceFileApi {
    fn get_instance_file(&self, name: &str) -> String;
}

/// The harness witness shape (fcap PLAN §3: stubs.cc:182
/// `s = n; return s.c_str()`): the bare name, no dir prefix. Vectors
/// `H_async name_len=64 name_eq_sha=1` (vectors.txt:24) pin THAT
/// semantics, so it is the port default; the full
/// `crate::main::thread::get_instance_file` needs the
/// NamingConfig/ThreadState/LogEngine trio and stays injectable by a
/// row that wires the config plumbing.
pub struct BareInstanceFile;
impl InstanceFileApi for BareInstanceFile {
    fn get_instance_file(&self, name: &str) -> String {
        name.to_string() // stubs.cc:182 `s = n`
    }
}

/// C file-statics file_capture.cc:55-:63 modeled in-object (17r
/// precedent, module header). `capture_mutex`/`capture_cv` (:58-:59)
/// are the single-thread exclusivity rule; `file_storer` (:60) is
/// the alive flag (no OS thread ever exists in Rust).
pub struct FileCaptureShared {
    /// :55 `FileMemPool* file_mempool` -> owned Option
    file_mempool: RefCell<Option<FileMemPool>>,
    /// :56 `int64_t capture_block_size`
    capture_block_size: Cell<i64>,
    /// :61 `std::queue<FileCapture*> files_waiting` -> owned queue
    /// (module header move-semantics note)
    files_waiting: RefCell<VecDeque<Box<FileCapture>>>,
    /// :62 `bool file_storing`
    file_storing: Cell<bool>,
    /// :63 `bool running` — initializer TRUE, :182 clears
    running: Cell<bool>,
    /// :60 `std::thread* file_storer` stand-in (nullptr vs live;
    /// spawn/join never happen — deviation, module header)
    file_storer_alive: Cell<bool>,
    /// get_instance_file(:577) seam (see [BareInstanceFile])
    instance_file: RefCell<Box<dyn InstanceFileApi>>,
}

impl FileCaptureShared {
    /// the C static initializers :55-:63: pool nullptr, block size 0,
    /// storer nullptr (:60), empty queue (:61), file_storing false
    /// (:62), running TRUE (:63)
    pub fn new() -> Self {
        FileCaptureShared {
            file_mempool: RefCell::new(None), // :55
            capture_block_size: Cell::new(0), // :56
            files_waiting: RefCell::new(VecDeque::new()), // :61
            file_storing: Cell::new(false),   // :62
            running: Cell::new(true),         // :63 `bool running = true`
            file_storer_alive: Cell::new(false), // :60 nullptr
            instance_file: RefCell::new(Box::new(BareInstanceFile)), // :577 seam
        }
    }

    /// arm the :577 get_instance_file seam (harness tests wire a
    /// temp-dir seam; the C side drives the same hole via the
    /// stubs.cc:182 witness)
    pub fn set_instance_file(&self, seam: Box<dyn InstanceFileApi>) {
        *self.instance_file.borrow_mut() = seam;
    }

    /// `capture_block_size` (:56) — the C harness FIXACC poke
    /// pattern (probe.cc:152/:306/:316); the port routes it through
    /// the same static the public [FileCapture::init] (:168) writes.
    pub fn set_capture_block_size(&self, n: i64) {
        self.capture_block_size.set(n);
    }

    /// `files_waiting` size (:61) — the gate's fcap_queue_size
    /// driver witness
    pub fn queue_len(&self) -> usize {
        self.files_waiting.borrow().len()
    }

    /// `file_storing` read (:62) — the gate's fcap_file_storing_now
    /// witness
    pub fn is_writer_storing(&self) -> bool {
        self.file_storing.get()
    }

    /// the :577 seam answer (the gate probe reads the witness
    /// output; the parity test pins the BareInstanceFile default)
    pub fn instance_file_answer(&self, name: &str) -> String {
        self.instance_file.borrow().get_instance_file(name)
    }
}

impl Default for FileCaptureShared {
    fn default() -> Self {
        Self::new()
    }
}

/// C `class FileCapture` (file_capture.h:62-:147) — instance members
/// in C order (:137-:146). The `blocks` arena stands in for the C
/// block chain living inside mempool slots (module header).
pub struct FileCapture {
    shared: Rc<FileCaptureShared>,
    counts: Rc<RefCell<FileCounts>>,

    capture_size: u64, // :137 `uint64_t capture_size`
    blocks: Vec<FileCaptureBlock>, // (module header arena)
    head: Option<usize>, // :139 `FileCaptureBlock* head`
    last: Option<usize>, // :138 `FileCaptureBlock* last`
    current_block: Option<usize>, // :140 `= nullptr`
    /// :141 `const uint8_t* current_data` + :142
    /// `uint32_t current_data_len` -> owned copy (module header)
    current_data: Vec<u8>,
    current_data_len: u32,
    capture_state: u32, // :143 `FileCaptureState capture_state`
    /// :144 `snort::FileInfo* file_info = nullptr` -> owned copy
    /// (`new FileInfo(*file)` :455 = the copy-ctor, whose clear_data
    /// default is true per file_lib.h:97)
    file_info: Option<FileInfo>,
    capture_min_size: i64, // :145
    capture_max_size: i64, // :146
}

impl FileCapture {
    /// file_capture.cc:120-:129 ctor `FileCapture(min_size,
    /// max_size)`: capture_size 0 (:122), last = head = nullptr
    /// (:123), current_data null (:124)/len 0 (:125), capture_state
    /// FILE_CAPTURE_SUCCESS (:126), min/max stored (:127-:128). The
    /// .h :140/:144 in-class initializers (current_block, file_info
    /// nullptr) land as `None`. C `new` never answers null — the
    /// Rust ctor keeps that shape (real total, no Option around it).
    pub fn new(
        min_size: i64,
        max_size: i64,
        shared: Rc<FileCaptureShared>,
        counts: Rc<RefCell<FileCounts>>,
    ) -> Self {
        FileCapture {
            shared,
            counts,
            capture_size: 0, // :122
            blocks: Vec::new(),
            head: None, // :123
            last: None, // :123
            current_block: None, // :140
            current_data: Vec::new(), // :124
            current_data_len: 0, // :125
            capture_state: FILE_CAPTURE_SUCCESS, // :126
            file_info: None, // :144
            capture_min_size: min_size, // :127
            capture_max_size: max_size, // :128
        }
    }

    /// file_capture.cc:72-:76 `static FileCaptureState
    /// error_capture(FileCaptureState state)`: one
    /// `file_counts.file_reserve_failures++` (:74), state returned
    /// verbatim (:75). (file_lib.rs:175 mirrors this body for the
    /// seam; 17s owns the real one.)
    pub fn error_capture(state: u32, counts: &mut FileCounts) -> u32 {
        counts.file_reserve_failures = counts.file_reserve_failures.wrapping_add(1); // :74
        state // :75
    }

    // ---- statics surface ----

    /// file_capture.cc:166-:172 `static init(int64_t memcap,
    /// int64_t block_size)`: block size static (:168),
    /// `init_mempool(memcap, capture_block_size)` (:169),
    /// `file_counts.file_buffers_max = get_buffers_max()` (:170),
    /// `file_storer = new std::thread(writer_thread)` (:171) ->
    /// alive flag ONLY (no OS thread ever spawned; deviation, module
    /// header — the gate ladder's interleavings are scripted through
    /// [FileCapture::writer_pop]/[FileCapture::writer_finish]).
    pub fn init(
        shared: &FileCaptureShared,
        counts: &RefCell<FileCounts>,
        memcap: i64,
        block_size: i64,
    ) {
        shared.capture_block_size.set(block_size); // :168
        Self::init_mempool(shared, memcap, shared.capture_block_size.get()); // :169
        let maxb = Self::get_buffers_max(shared); // :170 rhs
        counts.borrow_mut().file_buffers_max = maxb as PegCount; // :170 lhs
        shared.file_storer_alive.set(true); // :171 (flag, not thread)
    }

    /// file_capture.cc:218-:234 `static init_mempool(max_file_mem,
    /// block_len)`: slot size = `block_len + sizeof(FileCapture)`
    /// (:220, pinned 72 — NEVER Rust `size_of`, module header);
    /// `<= 0` bails (:222-:223); memcap MiB -> bytes (:226, C
    /// int64-product wrap fidelity via wrapping_mul); 8-align UP
    /// (:228-:229); `max_files = max_file_mem_in_bytes / block_size`
    /// (:231, C int64 division); `new FileMemPool(max_files,
    /// block_size)` (:233) REPLACES a live pool exactly like C. pub:
    /// harness FIXACC reached it as a private static (fcap PLAN §7);
    /// the probe hookless vectors drive it directly.
    pub fn init_mempool(shared: &FileCaptureShared, max_file_mem: i64, block_len: i64) {
        let mut block_size = block_len.wrapping_add(SIZEOF_FILE_CAPTURE); // :220

        if block_size <= 0 {
            return; // :222-:223
        }

        /*Convert megabytes to bytes*/
        // :226 `max_file_mem * 1024 * 1024`
        let max_file_mem_in_bytes = max_file_mem.wrapping_mul(1024).wrapping_mul(1024);

        if block_size & 7 != 0 {
            // :228-:229
            block_size += 8 - (block_size & 7);
        }

        let max_files = max_file_mem_in_bytes / block_size; // :231

        // :233 `file_mempool = new FileMemPool(max_files, block_size);`
        *shared.file_mempool.borrow_mut() =
            Some(FileMemPool::new(max_files as u64, block_size as usize));
    }

    /// file_capture.h:103 inline `static get_block_size()`
    pub fn get_block_size(shared: &FileCaptureShared) -> i64 {
        shared.capture_block_size.get()
    }

    /// file_capture.cc:602-:607 `static get_buffers_max()`: pool
    /// `total_objects()` (:605), 0 without one (:606)
    pub fn get_buffers_max(shared: &FileCaptureShared) -> i64 {
        let pool = shared.file_mempool.borrow();
        match pool.as_ref() {
            Some(p) => p.total_objects() as i64, // :605
            None => 0,                           // :606
        }
    }

    /// file_capture.cc:609-:614 `static get_buffers_in_use()`: pool
    /// `allocated()` (:612), 0 without one (:613)
    pub fn get_buffers_in_use(shared: &FileCaptureShared) -> i64 {
        let pool = shared.file_mempool.borrow();
        match pool.as_ref() {
            Some(p) => p.allocated() as i64, // :612
            None => 0,                       // :613
        }
    }

    /// file_capture.cc:586-:600 `static collect_mem_usage(builder,
    /// group)`: no pool -> nothing (:588-:589); `block_size =
    /// get_block_size() + sizeof(FileCapture)` RE-aligned (:591-:593
    /// — recomputed from the block-size static, NOT the slot the ctor
    /// allocated: literal); then the five counters in C order —
    /// Max file buffer capacity = total_objects (:595), Buffers in
    /// use = allocated (:596), Buffers in free list = freed (:597),
    /// Buffers in release list = released (:598), Memory usage in
    /// bytes = allocated * block_size (:599).
    // The C `Builder&` forwarding parameter is OMITTED here,
    // following the in-repo fstats precedent (file_stats.rs:150-:152
    // FileStatsHooks::collect seam note): :595-:599 call the
    // builder's counter STATIC pair (snapshot.rs marks
    // section/group/table/row/counter as "C statics"; the C member
    // body never touches `this`), so the receiver carries no
    // behavior.
    pub fn collect_mem_usage(
        shared: &FileCaptureShared,
        group: &mut crate::utils::stats::snapshot::Group,
    ) {
        let pool_borrow = shared.file_mempool.borrow();
        let Some(pool) = pool_borrow.as_ref() else {
            return; // :588-:589 `if (!file_mempool) return;`
        };

        let mut block_size = Self::get_block_size(shared).wrapping_add(SIZEOF_FILE_CAPTURE); // :591
        if block_size & 7 != 0 {
            block_size += 8 - (block_size & 7); // :592-:593
        }

        use crate::utils::stats::snapshot::Value;
        // :595 (Value::U64 — the snapshot renders every numeric arm
        // identically; vectors.txt:14 pins name/value pairs)
        Builder::counter(
            group,
            "Max file buffer capacity",
            Value::U64(pool.total_objects()),
        );
        // :596
        Builder::counter(group, "Buffers in use", Value::U64(pool.allocated()));
        // :597
        Builder::counter(group, "Buffers in free list", Value::U64(pool.freed()));
        // :598
        Builder::counter(group, "Buffers in release list", Value::U64(pool.released()));
        // :599 `file_mempool->allocated() * block_size` (int64 arm —
        // the C int64 product, vectors.txt:14 "Memory usage in
        // bytes=0")
        Builder::counter(
            group,
            "Memory usage in bytes",
            Value::I64((pool.allocated() as i64).wrapping_mul(block_size)),
        );
    }

    // ---- async-writer half (single-thread model, module header) ----

    /// file_capture.cc:178-:192 `static exit()`: `running = false`
    /// under the lock (:180-:183), `capture_cv.notify_one()` (:184),
    /// the join arm (:186-:191). Single-thread: `join()` is modeled
    /// as the C writer's documented exit behavior — ":89-:91 When
    /// !running we write out any remaining files before exiting" —
    /// the queue drains via [FileCapture::writer_step] BEFORE the
    /// storer pointer (:60) nulls. NEVER drive an exit over a parked
    /// [FileCapture::writer_pop] (the C join deadlock face, fcap
    /// PLAN §9-1, fixture dtor order :794-:796).
    pub fn exit(shared: &FileCaptureShared) {
        shared.running.set(false); // :182
        // :184 capture_cv.notify_one() — single-thread, the
        // predicate re-evaluates synchronously (module header)

        if shared.file_storer_alive.get() {
            // :186 `if (file_storer)`
            while Self::writer_step(shared) {
                // :188 file_storer->join(): the writer's loop spins
                // (:83) until, !running or empty, it breaks (:92-:93)
                // after draining what is queued (:89-:91)
            }
            shared.file_storer_alive.set(false); // :189-:190 delete + nullptr
        }
    }

    /// file_capture.cc:194-:209 `static flush()`: lock (:196), the
    /// UT flush-entry hook (:197-:200 — scripted at call sites by
    /// the parity translations), then `capture_cv.wait(lk, pred)`
    /// with pred `files_waiting.empty() and !file_storing`
    /// (:201-:208, sampling hook :203-:206). Single-thread: the C
    /// wait wakes on the writer's :111 notify_all; here THIS thread
    /// performs the writer's iterations (writer_step) to make the
    /// predicate progress — the observable ladder is unchanged: the
    /// predicate is re-sampled after every drain iteration, and a
    /// nonempty queue keeps it waiting (case D / vectors G).
    pub fn flush(shared: &FileCaptureShared) {
        // :197-:200 flush_entry_test_hook (scripted; PLAN §4-:197)
        loop {
            // :203-:206 flush_predicate_test_hook(files_waiting.
            // empty(), file_storing) — the sampling site below:
            // [FileCapture::flush_pending] answers what the C hook
            // saw.
            if !Self::flush_pending(shared) {
                return; // :201 wait returns once the predicate holds
            }
            // only the writer flips the predicate; single-thread,
            // perform one writer iteration (module header).
            if !Self::writer_step(shared) {
                // queue empty yet flush_pending still true can only
                // mean file_storing was set by a PARKED
                // [FileCapture::writer_pop] — in C a flush there
                // waits forever unless the hook releases, and the
                // gate always releases before exit (:794-:796).
                // Panic loudly instead of hanging (deviation,
                // PLAN §9-1 join face made observable).
                panic!(
                    "flush(): predicate pending while the queue is empty — a writer pop is parked; release it (fixture dtor order :794-:796) before flushing (fcap PLAN 9-1)"
                );
            }
        }
    }

    /// the :201-:207 wait predicate sampled exactly as the UT hook
    /// :203-:206 sees it (the hook receives
    /// `flush_predicate_test_hook(files_waiting.empty(),
    /// file_storing)`): the TRUE C predicate, kept in C polarity.
    pub fn flush_predicate_empty_and_idle(shared: &FileCaptureShared) -> bool {
        let queue_empty = shared.files_waiting.borrow().is_empty(); // :207 part 1
        let writer_active = shared.file_storing.get(); // :207 part 2
        queue_empty && !writer_active // :207 `empty and !storing`
    }

    /// the wait predicate inverted: true = flush must keep waiting
    /// (== the AsyncWriterGate sampling of the :207 predicate).
    pub fn flush_pending(shared: &FileCaptureShared) -> bool {
        !Self::flush_predicate_empty_and_idle(shared)
    }

    /// one complete `writer_thread` (:79-:117) iteration, unhooked
    /// semantics: pop (:85-:99) -> :100-:103 hook not armed ->
    /// `file->store_file()` (:105) -> :106 `delete file` -> :108-:109
    /// `file_storing = false` -> :111 notify_all; returns false where
    /// C breaks (`files_waiting.empty()`, :92-:93). The cv wait
    /// (:86-:87) reads `[FileCaptureShared::running]` verbatim: this
    /// port's writer_step only pops when work exists, so the C
    /// `!running` wake just ends the join drain (exit models it).
    pub fn writer_step(shared: &FileCaptureShared) -> bool {
        let Some(mut file) = Self::writer_pop(shared) else {
            return false; // :92-:93 break
        };
        // :100-:103 `if (writer_test_hook) ...` — not armed -> no
        // park, straight through.
        file.store_file(); // :105 `file->store_file()`
        Self::writer_finish(shared, file); // :106 delete + :108-:115
        true
    }

    /// the pop HALF of writer_thread (:85-:99). The gate-armed C
    /// thread parks at :100-:103 AFTER front/pop (:95-:96) and
    /// `file_storing = true` (:97), while it OWNS the capture —
    /// vectors `F_ladder storing_when_parked=1` pin that window.
    /// Scripted single-thread: the caller holds the returned Box in
    /// exactly that window until [FileCapture::writer_finish].
    pub fn writer_pop(shared: &FileCaptureShared) -> Option<Box<FileCapture>> {
        // :86-:87 capture_cv.wait(lk, [] { return !running or
        // !files_waiting.empty(); }) — single-thread the predicate is
        // whatever it is at the call; the pop arm (:92-:96) reads the
        // queue.
        // :92-:93 `if (files_waiting.empty()) break;`
        let file = shared.files_waiting.borrow_mut().pop_front(); // :95-:96 front+pop
        let Some(file) = file else {
            return None; // break (:93)
        };
        shared.file_storing.set(true); // :97
        Some(file) // :98 lk.unlock — parked-window shape
    }

    /// the release HALF of writer_thread (:104-:115): the :106
    /// `delete file` (Rust: drop of the moved Box runs the
    /// ~FileCapture at :131-:164 — per-thread counts merge, module
    /// header) then lk.lock (:108) + `file_storing = false` (:109) +
    /// unlock (:110) + :111 `capture_cv.notify_all()` (the flush
    /// predicate re-evaluates, single-thread), then the :112-:115
    /// writer_idle_test_hook (scripted at call sites).
    pub fn writer_finish(shared: &FileCaptureShared, file: Box<FileCapture>) {
        drop(file); // :106
        shared.file_storing.set(false); // :109
        // :111 notify_all + :112-:115 idle hook (scripted; PLAN
        // §4-:112): the queue re-drains on the next step/flush.
    }

    // ---- FileCaptureTestAccess surface (file_capture.cc:625-:659) ----
    // The UT scaffold itself is gate C++ only; its test-visible
    // semantics land here (fcap PLAN §8-2 final clause) so the
    // parity translations replay fixtures C/D single-thread.

    /// :625-:629 `resettable()`: `file_storer == nullptr and
    /// files_waiting.empty()` (the lock_guard is single-thread
    /// exclusivity)
    pub fn resettable(shared: &FileCaptureShared) -> bool {
        !shared.file_storer_alive.get() && shared.files_waiting.borrow().is_empty() // :628
    }

    /// :631-:639 `reset()`: delete pool + nullptr (:633-:634, pool
    /// Drop = `delete`), `capture_block_size = 0` (:635),
    /// `file_storing = false` (:636), `running = true` (:637).
    pub fn test_reset(shared: &FileCaptureShared) {
        let _ = shared.file_mempool.borrow_mut().take(); // :633-:634
        shared.capture_block_size.set(0); // :635
        shared.file_storing.set(false); // :636
        shared.running.set(true); // :637
    }

    /// :641-:648 `enqueue(FileCapture* capture)`: push + notify_one,
    /// bypassing store_file_async so NO sha256/name is ever set (the
    /// nameless store_file no-op pin, fcap PLAN §5 last bullet).
    pub fn enqueue(shared: &FileCaptureShared, capture: Box<FileCapture>) {
        shared.files_waiting.borrow_mut().push_back(capture); // :644
        // :645 capture_cv.notify_one() — re-evaluation synchronous
    }

    /// :650-:654 `enqueue(FileCapture* first, FileCapture* second)`
    /// — both pushed in one section, queue ORDER first->second kept.
    pub fn enqueue2(
        shared: &FileCaptureShared,
        first: Box<FileCapture>,
        second: Box<FileCapture>,
    ) {
        let mut q = shared.files_waiting.borrow_mut();
        q.push_back(first); // :652
        q.push_back(second); // :653
        // :654 capture_cv.notify_one()
    }

    /// :656-:659 `released_buffers()`: `file_mempool->released()`. C
    /// derefs a null pool (crash); the port answers 0 (pinned
    /// deviation — reachable only after a reset with captures gone).
    pub fn released_buffers(shared: &FileCaptureShared) -> u64 {
        let pool = shared.file_mempool.borrow();
        pool.as_ref().map_or(0, |p| p.released())
    }

    // TestAccess `reset()` (:631-:639) does NOT touch files_waiting
    // — `resettable()` (:628) REQUIRES it empty first; that
    // drain-before-reset order is the fixture dtor pin (:794-:796),
    // no extra code needed.

    /// :63 `running` read (the writer's :87 cv-wait predicate part,
    /// `!running or !files_waiting.empty()`): single-thread this is
    /// only observable as "after exit(), a scripter's late pop finds
    /// no live writer loop" — kept as the honest pin of the :87 read.
    pub fn is_running(shared: &FileCaptureShared) -> bool {
        shared.running.get()
    }

    // ---- the ladder: create / save / process ----

    /// file_capture.cc:236-:261 `inline create_file_buffer()`: no
    /// pool -> nullptr (:238-:239); `m_alloc` (:241);
    /// `file_buffers_in_use = get_buffers_in_use()` runs even when
    /// the alloc failed, BEFORE the null test (:243 — order
    /// literal); alloc failure bumps `file_memcap_failures_total++`
    /// (:247) and yields nullptr (:248); success bumps
    /// `file_buffers_allocated_total++`
    /// (:251), the in-slot header write `length = 0; next = nullptr`
    /// (:253-:254 — pool-side equivalent is `mark_block_in_use`, the
    /// [file_mempool] gate precedent clearing the FREE magic), and
    /// the `file_buffers_used_max` ratchet off `allocated()`
    /// (:256-:258). Returns the arena index (None == the C nullptr).
    fn create_file_buffer(&mut self) -> Option<usize> {
        if self.shared.file_mempool.borrow().is_none() {
            return None; // :238-:239
        }

        // :241 `FileCaptureBlock* fileBlock =
        // (FileCaptureBlock*)file_mempool->m_alloc();`
        let slot = {
            let mut pb = self.shared.file_mempool.borrow_mut();
            let pool = pb.as_mut().expect("pool present (checked :238)");
            pool.m_alloc()
        };

        // :243 `file_counts.file_buffers_in_use =
        // get_buffers_in_use();` — runs on BOTH arms (literal order:
        // before the nullptr test below)
        let in_use = Self::get_buffers_in_use(&self.shared);
        self.counts.borrow_mut().file_buffers_in_use = in_use as PegCount;

        let Some(slot) = slot else {
            // :245-:249
            let mut counts = self.counts.borrow_mut();
            counts.file_memcap_failures_total =
                counts.file_memcap_failures_total.wrapping_add(1); // :247
            return None; // :248
        };

        // :251
        {
            let mut counts = self.counts.borrow_mut();
            counts.file_buffers_allocated_total =
                counts.file_buffers_allocated_total.wrapping_add(1);
        }

        // :253-:254 `fileBlock->length = 0; fileBlock->next =
        // nullptr;` — the header write: pool magic cleared
        // (mark_block_in_use, module header)
        {
            let mut pb = self.shared.file_mempool.borrow_mut();
            let pool = pb.as_mut().expect("pool present (checked :238)");
            pool.mark_block_in_use(Some(slot));

            // :256 `uint64_t num_files_queued =
            // file_mempool->allocated();`
            let num_files_queued = pool.allocated();
            // :257-:258 ratchet
            let mut counts = self.counts.borrow_mut();
            if counts.file_buffers_used_max < num_files_queued {
                counts.file_buffers_used_max = num_files_queued;
            }
        }

        // the Rust-side block (module header): payload capacity =
        // capture_block_size (the slot's payload region)
        let cap = self.shared.capture_block_size.get().max(0) as usize;
        self.blocks.push(FileCaptureBlock {
            length: 0, // :253
            next: None, // :254
            slot,
            payload: vec![0u8; cap],
        });
        Some(self.blocks.len() - 1)
    }

    /// file_capture.cc:268-:344 `inline save_to_file_buffer(
    /// file_data, data_size, max_size)` — the payload-offset dance
    /// (`(uint8_t*)lastBlock + lastBlock->length + sizeof(*lastBlock)`
    /// :294/:335, `(uint8_t*)last + sizeof(*new_block)` :318/:325)
    /// transcribes to per-block `payload[length ..]` writes (the C
    /// block header is 16 bytes; the Rust payload vector starts where
    /// C's block + 16 starts — module header).
    fn save_to_file_buffer(
        &mut self,
        file_data: &[u8],
        data_size: i64,
        max_size: i64,
    ) -> u32 {
        if data_size <= 0 {
            return FILE_CAPTURE_SUCCESS; // :274-:275
        }

        // :277 `if ( data_size + (int64_t)capture_size > max_size)`
        if data_size.wrapping_add(self.capture_size as i64) > max_size {
            // :279-:281
            let mut counts = self.counts.borrow_mut();
            counts.file_size_max = counts.file_size_max.wrapping_add(1); // :279
            self.capture_state = FILE_CAPTURE_MAX; // :280
            return FILE_CAPTURE_MAX; // :281
        }

        // :271 `FileCaptureBlock* lastBlock = last;` — C null-derefs
        // below without a test; both callers create first
        // (:380-:390 / :430-:442) — pinned-absent.
        let last_block = self.last.expect(
            "lastBlock null at file_capture.cc:285 — C derefs null here; callers create the head block first (:380-:390/:430-:442); pinned-absent (see :285 cite)",
        );

        // :285 `/* Check whether current file block can hold file
        // data*/ available_bytes = capture_block_size -
        // lastBlock->length;`
        let block_size = self.shared.capture_block_size.get(); // capture_block_size static
        let available_bytes = block_size.wrapping_sub(self.blocks[last_block].length as i64);

        if data_size > available_bytes {
            // :287-:331 the split ladder ("We can support any file
            // capture block size", :300)
            let mut file_current: usize = 0; // :290 `file_current = file_data`
            let file_end: usize = data_size as usize; // :291 `file_end = file_data + data_size`

            // :293-:295 "can't hold all, use current block first"
            let avail = available_bytes.max(0) as usize;
            let len = self.blocks[last_block].length as usize;
            self.blocks[last_block].payload[len..len + avail]
                .copy_from_slice(&file_data[file_current..file_current + avail]); // :294-:295
            self.blocks[last_block].length = block_size as u32; // :297
            file_current += avail; // :298

            loop {
                // :303 `new_block = static_cast<FileCaptureBlock*>
                // (create_file_buffer());`
                let new_block = match self.create_file_buffer() {
                    Some(n) => n,
                    None => {
                        // :306-:310
                        self.capture_state = FILE_CAPTURE_MEMCAP; // :308
                        return FILE_CAPTURE_MEMCAP; // :309
                    }
                };

                // :312-:313 `last->next = new_block; last =
                // new_block;` (:313 last IS the new block — the C
                // global-to-last update)
                let last = self.last.expect("last set (:124 init / create sets it)");
                self.blocks[last].next = Some(new_block); // :312
                self.last = Some(new_block); // :313

                // :316 `if (file_current + capture_block_size <
                // file_end)`
                if (file_current as i64) + block_size < file_end as i64 {
                    // :318-:321 full-block arm
                    let bs = block_size as usize;
                    self.blocks[new_block].payload[..bs]
                        .copy_from_slice(&file_data[file_current..file_current + bs]);
                    self.blocks[new_block].length = block_size as u32; // :320
                    file_current += bs; // :321
                } else {
                    // :325-:329 tail arm
                    let n = file_end - file_current; // `file_end - file_current`
                    self.blocks[new_block].payload[..n]
                        .copy_from_slice(&file_data[file_current..file_end]);
                    self.blocks[new_block].length = n as u32; // :328
                    break; // :329
                }
            }
        } else {
            // :335-:338 fits-in-current arm
            let len = self.blocks[last_block].length as usize;
            let n = data_size as usize;
            self.blocks[last_block].payload[len..len + n]
                .copy_from_slice(&file_data[..n]); // :335-:336
            self.blocks[last_block].length = (len + n) as u32; // :338 `+= data_size`
        }

        // :341 `capture_size += data_size`
        self.capture_size = self.capture_size.wrapping_add(data_size as u64);

        FILE_CAPTURE_SUCCESS // :343
    }

    /// file_capture.cc:361-:396 `process_buffer(file_data,
    /// data_size, position)` — the FULL/END/SPLIT ladder:
    /// current_data/len recorded FIRST (:364-:365; owned copy,
    /// module header); SNORT_FILE_FULL bumps `file_within_packet`
    /// (:369-:371); SNORT_FILE_END nothing (:372-:373); default
    /// (START/MIDDLE — "the file is larger than one packet",
    /// :376-:378): create `head = last = create_file_buffer()` if
    /// head absent — MEMCAP return on null (:384-:387) — then
    /// `files_buffered_total++` (:389), then tail-call
    /// `save_to_file_buffer(file_data, data_size,
    /// capture_max_size)` (:392); everything else returns
    /// FILE_CAPTURE_SUCCESS (:395).
    pub fn process_buffer(&mut self, file_data: &[u8], data_size: i32, position: u32) -> u32 {
        // :364-:365 `current_data = file_data; current_data_len =
        // data_size;` (owned copy)
        self.current_data = file_data.to_vec();
        self.current_data_len = data_size as u32;

        match position {
            SNORT_FILE_FULL => {
                // :369-:371
                let mut counts = self.counts.borrow_mut();
                counts.file_within_packet = counts.file_within_packet.wrapping_add(1);
            }
            SNORT_FILE_END => {
                // :372-:373 `case SNORT_FILE_END: break;`
            }
            _ => {
                // :374-:392 default: SNORT_FILE_START/MIDDLE arm
                // ("For File position is either SNORT_FILE_START or
                // SNORT_FILE_MIDDLE", :376-:378)
                if self.head.is_none() {
                    // :380-:390 `head = last = create_file_buffer();
                    // if (!head) return FILE_CAPTURE_MEMCAP;` — C
                    // assigns head=last=null on the failure arm (the
                    // chained assignment), kept literal.
                    match self.create_file_buffer() {
                        Some(b) => {
                            self.head = Some(b); // :382
                            self.last = Some(b); // :382
                            let mut counts = self.counts.borrow_mut();
                            counts.files_buffered_total =
                                counts.files_buffered_total.wrapping_add(1); // :389
                        }
                        None => {
                            self.head = None; // :382 (chained null)
                            self.last = None; // :382
                            return FILE_CAPTURE_MEMCAP; // :386
                        }
                    }
                }

                // :392 `return (save_to_file_buffer(file_data,
                // data_size, capture_max_size));`
                let max_size = self.capture_max_size;
                return self.save_to_file_buffer(file_data, data_size as i64, max_size);
            }
        }

        FILE_CAPTURE_SUCCESS // :395
    }

    // ---- reserve / get / reset ----

    /// file_capture.cc:399-:458 `reserve_file(const FileInfo* file)`:
    /// non-SUCCESS capture_state -> `error_capture(capture_state)`
    /// (:403-:406); `fileSize = file->get_file_size()` (:413, "file
    /// size is updated at this point" :411); size MIN arm (:415-:419)
    /// and MAX arm (:421-:425) — the C `(unsigned)` truncation of the
    /// i64 config limits BEFORE the uint64 compare is kept literal;
    /// head absent -> create arm with
    /// `file_memcap_failures_reserve++` (:430-:442);
    /// `save_to_file_buffer(current_data, current_data_len,
    /// capture_max_size)` — the "Copy the last piece of file to file
    /// buffer" step (:444-:449, any nonzero answer ->
    /// `error_capture(capture_state)`); `files_captured_total++`
    /// (:451); `current_block = head` (:453);
    /// `file_info = new FileInfo(*file)` — the COPY ctor
    /// (file_lib.cc:326-:329 -> copy(other, clear_data=true) per
    /// file_lib.h:97 — capture detached, policy_id cleared, no
    /// user_file_data) — (:455); FILE_CAPTURE_SUCCESS (:457).
    pub fn reserve_file(&mut self, file: &FileInfo) -> u32 {
        // :403-:406
        if self.capture_state != FILE_CAPTURE_SUCCESS {
            let state = self.capture_state;
            let mut counts = self.counts.borrow_mut();
            return FileCapture::error_capture(state, &mut counts);
        }

        // :408 `FileCaptureBlock* fileBlock = head;`
        let mut file_block = self.head;

        // :413 `fileSize = file->get_file_size();`
        let file_size = file.get_file_size();

        // :415 `if ( fileSize < (unsigned)capture_min_size)` — C
        // truncates the i64 to unsigned int first (literal; never
        // bites at sane configs).
        if file_size < ((self.capture_min_size as u32) as u64) {
            let mut counts = self.counts.borrow_mut();
            counts.file_size_min = counts.file_size_min.wrapping_add(1); // :417
            return FileCapture::error_capture(FILE_CAPTURE_MIN, &mut counts); // :418
        }

        // :421 `if ( fileSize > (unsigned)capture_max_size)`
        if file_size > ((self.capture_max_size as u32) as u64) {
            let mut counts = self.counts.borrow_mut();
            counts.file_size_max = counts.file_size_max.wrapping_add(1); // :423
            return FileCapture::error_capture(FILE_CAPTURE_MAX, &mut counts); // :424
        }

        // :427-442 `if (!fileBlock) { ... }` — "This is the case for
        // small file" (:428)
        if file_block.is_none() {
            file_block = self.create_file_buffer(); // :432

            if file_block.is_none() {
                // :434-:438
                let mut counts = self.counts.borrow_mut();
                counts.file_memcap_failures_reserve =
                    counts.file_memcap_failures_reserve.wrapping_add(1); // :436
                return FileCapture::error_capture(FILE_CAPTURE_MEMCAP, &mut counts); // :437
            }

            {
                let mut counts = self.counts.borrow_mut();
                counts.files_buffered_total = counts.files_buffered_total.wrapping_add(1); // :440
            }
            self.head = file_block; // :441 `head = last = fileBlock`
            self.last = file_block; // :441
        }

        // :444-:449 `if (save_to_file_buffer(current_data,
        // current_data_len, capture_max_size))  return
        // error_capture(capture_state);` — current_data is
        // self-owned; clone (or take/put) so the &mut self call is
        // legal (the C alias-free raw read is structural here).
        let current = std::mem::take(&mut self.current_data);
        let cur_len = self.current_data_len as i64;
        let max_size = self.capture_max_size;
        let save_state = self.save_to_file_buffer(&current, cur_len, max_size);
        self.current_data = current; // restore (C keeps the pointer live)
        if save_state != FILE_CAPTURE_SUCCESS {
            let state = self.capture_state;
            let mut counts = self.counts.borrow_mut();
            return FileCapture::error_capture(state, &mut counts); // :448
        }

        {
            let mut counts = self.counts.borrow_mut();
            counts.files_captured_total = counts.files_captured_total.wrapping_add(1); // :451
        }

        self.current_block = self.head; // :453

        // :455 `file_info = new FileInfo(*file);` — copy-ctor
        // semantics = FileInfo::copy(other, clear_data = true)
        // (file_lib.cc:326-:329; file_lib.h:97 default arg)
        let mut owned = FileInfo::default();
        owned.copy(file, true);
        self.file_info = Some(owned);

        FILE_CAPTURE_SUCCESS // :457
    }

    /// file_capture.cc:471-:486 `get_file_data(uint8_t** buff, int*
    /// size)` — the repeated-read API ("this should be called
    /// repeatedly until nullptr", file_capture.h:79-:84): no current
    /// block -> `*size = 0; *buff = nullptr;` return nullptr
    /// (:474-:479); else `*buff = block + sizeof(FileCaptureBlock)`
    /// payload (:481 — C block header is 16 bytes, vectors CONST;
    /// the Rust payload slice is that region), `*size =
    /// current_block->length` (:482), advance `current_block =
    /// current_block->next` and RETURN the next block (:484-:485 —
    /// return value is the next block, only ever null-checked by
    /// callers, e.g. store_file :548/:558 and probe walk_capture).
    pub fn get_file_data<'s>(
        &'s mut self,
        buff: &mut Option<&'s [u8]>,
        size: &mut i32,
    ) -> Option<usize> {
        // :473 `assert(buff && size);` — Rust out-params are never
        // null; the assert is structurally satisfied.
        let Some(cur) = self.current_block else {
            // :474-:479
            *size = 0;
            *buff = None;
            return None;
        };

        // :482 `*size = current_block->length;` + :484-:485 advance
        // BEFORE handing out the payload borrow (Rust borrow order;
        // the C out-param writes interleave freely — same values
        // observed).
        *size = self.blocks[cur].length as i32;
        self.current_block = self.blocks[cur].next; // :484

        // :481 `*buff = (uint8_t*)current_block +
        // sizeof(*current_block);` — the payload region (module
        // header), length = :482's size.
        let len = self.blocks[cur].length as usize;
        *buff = Some(&self.blocks[cur].payload[..len]);

        self.current_block // :485 `return (current_block);`
    }

    /// file_capture.h:112 inline `get_file_reset()` — "installed
    /// file-capture state-reset API" (cppcheck note :111): `current_
    /// block = head` — rewinds the get_file_data walk (probe
    /// `B_reset_walk` re-walk vector).
    pub fn get_file_reset(&mut self) {
        self.current_block = self.head; // :112
    }

    /// file_capture.h:113 inline `set_data(file_data, size)` —
    /// `current_data = file_data; current_data_len = size` — feeds
    /// the reserve_file last-piece save (:445). Owned copy (module
    /// header).
    pub fn set_data(&mut self, file_data: &[u8], size: u32) {
        self.current_data = file_data.to_vec(); // :113
        self.current_data_len = size; // :113
    }

    /// file_capture.h:110 inline `get_file_capture_size()`
    pub fn get_file_capture_size(&self) -> i64 {
        self.capture_size as i64 // :110
    }

    /// file_capture.h:109 inline `get_max_file_capture_size()`
    pub fn get_max_file_capture_size(&self) -> i64 {
        self.capture_max_size // :109
    }

    /// file_capture.h:107 inline `get_file_info()`
    pub fn get_file_info(&self) -> Option<&FileInfo> {
        self.file_info.as_ref() // :107
    }

    // ---- disk store ----

    /// file_capture.cc:488-:526 `write_file_data(uint8_t* buf,
    /// size_t buf_len, FILE* fh)` — the capped-retry fwrite loop:
    /// "In the case of interrupt errors, the write is retried, but
    /// only for a finite number of times" (:490-:492). max_retries
    /// 3 (:497); `bytes_written += fwrite(...)` (:510) -> `File::
    /// write` byte loop (fwrite = one write syscall until short);
    /// `err = ferror(fh)` (:512) -> the failing call's raw errno
    /// (C stdio ferror is 0/1; a non-EINTR/EAGAIN code breaks at
    /// :513-:516 — the transcribed errno comparison keeps the C arm,
    /// deviation pinned: real short-write errno reaches the arm,
    /// C's never did). do/while (:506-:520) verbatim. Shortfall ->
    /// `ErrorMessage("File inspect: disk writing error - %s!\n",
    /// get_error(err))` (:522-:525); the pinned vectors never reach
    /// it (disk vector H writes fully clean), so it renders to
    /// stderr in the same shape, seam-free.
    fn write_file_data(fh: &mut std::fs::File, buf: &[u8], buf_len: usize) {
        let mut max_retries: i32 = 3; // :497
        let mut bytes_written: usize = 0; // :498
        let mut err: i32 = 0; // :499

        /* Nothing to write or nothing to write to */
        // :501-:503 `(buf == nullptr) || (fh == nullptr)` — the Rust
        // types carry the null-free proof for fh; a zero buf_len is
        // the C "nothing to write" reading and falls through the
        // loop as a no-op (bytes_written == buf_len at once).

        /* writing several times */
        loop {
            // :508 `size_t bytes_left = buf_len - bytes_written;`
            let bytes_left = buf_len.wrapping_sub(bytes_written);

            // :510 `bytes_written += fwrite(buf + bytes_written, 1,
            // bytes_left, fh);` — a single write maps the C short-
            // fwrite-with-error to a raw errno (deviation note above;
            // clean short writes keep err 0 and the retry
            // accounting runs exactly like C).
            match fh.write(&buf[bytes_written..bytes_written + bytes_left]) {
                Ok(n) => bytes_written += n,
                Err(e) => {
                    err = e.raw_os_error().unwrap_or(0);
                }
            }

            // :512-:516 `err = ferror(fh); if (err && (err != EINTR)
            // && (err != EAGAIN)) break;`
            if err != 0 && err != EINTR && err != EAGAIN {
                break; // :515
            }

            // :518 `max_retries--;`
            max_retries -= 1;
            // :520 `while ((max_retries > 0) && (bytes_written <
            // buf_len));`
            if !(max_retries > 0 && bytes_written < buf_len) {
                break;
            }
        }

        // :522-:525
        if bytes_written < buf_len {
            let msg = format!(
                "File inspect: disk writing error - {}!\n",
                crate::utils::util::get_error(err)
            );
            eprintln!("{msg}"); // ErrorMessage shape (see doc)
        }
    }

    /// file_capture.cc:529-:561 `store_file()`: no file_info ->
    /// return (:531-:532); `fopen(name, "wx")` (:536) ->
    /// create_new(true) (O_WRONLY|O_CREAT|O_EXCL); OPEN FAILURE ->
    /// silent return (:537-:540 — the nameless-FileInfo pin:
    /// `fopen("", "wx")` fails fast, NO disk write, NO ErrorMessage;
    /// vectors `B_store_nameless_noop=1` + PLAN §5 last bullet,
    /// gate-side `H_async` covers the success path); then the walk
    /// ":541-:558": repeated `get_file_data` (:548), null/zero read
    /// -> `fclose; return` (:550-:554), else `write_file_data`
    /// (:556), loop while the walk returns a block (:558); :560
    /// fclose (`File` drop, module header).
    pub fn store_file(&mut self) {
        if self.file_info.is_none() {
            return; // :531-:532
        }

        // :534 `const std::string& file_full_name = file_info->
        // get_file_name();`
        let file_full_name = self
            .file_info
            .as_ref()
            .expect("file_info present (checked :384 -> :531)")
            .get_file_name()
            .to_vec();

        // :536 `FILE* fh = fopen(file_full_name.c_str(), "wx");`
        use std::os::unix::ffi::OsStrExt;
        let mut fh = match std::fs::OpenOptions::new()
            .create_new(true) //  "wx" O_EXCL arm
            .write(true) // "w"
            .open(std::ffi::OsStr::from_bytes(&file_full_name))
        {
            Ok(f) => f,
            Err(_) => {
                // :537-:540 `if (!fh) return;` — silent
                return;
            }
        };

        // Check the file buffer (:541)
        loop {
            let mut buff: Option<&[u8]> = None; // :542 `uint8_t* buff = nullptr`
            let mut size: i32 = 0; // :543 `int size = 0`
            // :548 `file_mem = get_file_data(&buff, &size);`
            let file_mem = self.get_file_data(&mut buff, &mut size);

            // :549-554 `if (!buff || !size) { fclose(fh); return; }`
            let Some(b) = buff else {
                return; // fh drop == fclose (module header)
            };
            if size == 0 {
                return; // fh drop == fclose
            }

            // :556 `write_file_data(buff, size, fh);`
            FileCapture::write_file_data(&mut fh, b, size as usize);

            // :558 `while (file_mem);`
            if file_mem.is_none() {
                break;
            }
        }
        // :560 `fclose(fh);` — File closes on drop (module header)
    }

    /// file_capture.cc:564-:584 `store_file_async()`:
    /// "Queue files to be stored to disk" (:563). No file_info ->
    /// `std::string()` (:567-:568); `sha =
    /// file_info->get_file_sig_sha256()`, null -> `std::string()`
    /// (:570-:572); `file_name = file_info->sha_to_string(sha)`
    /// (:574, UPPERCASE hex, 64 chars, file_lib.cc);
    /// `get_instance_file(file_full_name, file_name.c_str())`
    /// (:576-:577) through the [InstanceFileApi] seam (default =
    /// harness witness, probe `H_async name_eq_sha=1`: the bare name
    /// reaches disk in CWD); `set_file_name(full, size)` (:578);
    /// lock + `files_waiting.push(this)` + `notify_one` (:580-:582)
    /// — Rust move transfers ownership to the queue; the C writer
    /// completes the transaction with `delete file` (:106, module
    /// header). Returns the full name (:583).
    pub fn store_file_async(mut self: Box<Self>) -> String {
        // :567-:568
        if self.file_info.is_none() {
            return String::new();
        }

        // :570-:572
        let sha = match self.file_info.as_ref().and_then(|fi| fi.get_file_sig_sha256()) {
            Some(s) => *s, // copy of the 32-byte digest ([u8; SHA256_HASH_SIZE])
            None => return String::new(),
        };

        // :574 `std::string file_name = file_info->sha_to_string(sha);`
        let file_name = self
            .file_info
            .as_ref()
            .expect("file_info present (:286 -> :567)")
            .sha_to_string(&sha);

        // :576-:577 `std::string file_full_name;
        // get_instance_file(file_full_name, file_name.c_str());`
        let file_full_name = self
            .shared
            .instance_file
            .borrow()
            .get_instance_file(&file_name);

        // :578 `file_info->set_file_name(file_full_name.c_str(),
        // file_full_name.size());` — size_t -> uint32_t param is the
        // C truncating call, literal cast.
        if let Some(fi) = self.file_info.as_mut() {
            fi.set_file_name(
                Some(file_full_name.as_bytes()),
                file_full_name.len() as u32,
            );
        }

        // :580 `std::lock_guard<std::mutex> lk(capture_mutex);`
        // :581-:582 `files_waiting.push(this);
        // capture_cv.notify_one();` — ownership move (module
        // header). Cloning the Rc first keeps the queue borrow off
        // `self`, which moves into the queue (the C push of `this`).
        let shared = Rc::clone(&self.shared);
        shared.files_waiting.borrow_mut().push_back(self);

        file_full_name // :583
    }
}

/// file_capture.cc:131-:164 `~FileCapture()`: walk the chain from
/// head (:133); `files_released_total++` when file_info reserved,
/// else `files_freed_total++` (:135-:138); per block (:140-:158):
/// capture the next first (:142), then the reserved vs transient
/// split — `m_release` failure -> `file_buffers_release_errors++`,
/// then `file_buffers_released_total++` (:143-:148) versus
/// `m_free` failure -> `file_buffers_free_errors++`, then
/// `file_buffers_freed_total++` (:150-:154) — each pass
/// recomputing `file_buffers_in_use = get_buffers_in_use()` from the
/// pool (:156); then `head = last = nullptr` (:160); `delete
/// file_info` only when set (:162-:163). C derefs a pool a reset
/// already deleted (:633-:634 leaves nullptr — a capture outliving
/// the reset is UB in C); the port answers FILE_MEM_FAIL into the
/// error arms (pinned deviation).
impl Drop for FileCapture {
    fn drop(&mut self) {
        let reserved = self.file_info.is_some();

        {
            // :135-:138
            let mut counts = self.counts.borrow_mut();
            if reserved {
                counts.files_released_total = counts.files_released_total.wrapping_add(1); // :136
            } else {
                counts.files_freed_total = counts.files_freed_total.wrapping_add(1); // :138
            }
        }

        let mut file_block = self.head; // :133 `file_block = head`
        while let Some(idx) = file_block {
            // :142 `FileCaptureBlock* next_block = file_block->
            // next;` — snapshot before the chain member is released
            let next_block = self.blocks[idx].next;

            if reserved {
                // :143-:148 (`file_info` arm)
                let rel = {
                    let mut pb = self.shared.file_mempool.borrow_mut();
                    match pb.as_mut() {
                        Some(p) => p.m_release(Some(self.blocks[idx].slot)), // :145
                        None => super::file_mempool::FILE_MEM_FAIL, // pinned deviation (doc)
                    }
                };
                if rel != FILE_MEM_SUCCESS {
                    // :146
                    let mut counts = self.counts.borrow_mut();
                    counts.file_buffers_release_errors =
                        counts.file_buffers_release_errors.wrapping_add(1);
                }
                {
                    let mut counts = self.counts.borrow_mut();
                    counts.file_buffers_released_total =
                        counts.file_buffers_released_total.wrapping_add(1); // :147
                }
            } else {
                // :150-:154 (transient arm)
                let fr = {
                    let mut pb = self.shared.file_mempool.borrow_mut();
                    match pb.as_mut() {
                        Some(p) => p.m_free(Some(self.blocks[idx].slot)), // :151
                        None => super::file_mempool::FILE_MEM_FAIL, // pinned deviation (doc)
                    }
                };
                if fr != FILE_MEM_SUCCESS {
                    // :152
                    let mut counts = self.counts.borrow_mut();
                    counts.file_buffers_free_errors =
                        counts.file_buffers_free_errors.wrapping_add(1);
                }
                {
                    let mut counts = self.counts.borrow_mut();
                    counts.file_buffers_freed_total =
                        counts.file_buffers_freed_total.wrapping_add(1); // :153
                }
            }

            // :156 `file_counts.file_buffers_in_use =
            // get_buffers_in_use();` — pool re-read every pass
            let in_use = Self::get_buffers_in_use(&self.shared);
            self.counts.borrow_mut().file_buffers_in_use = in_use as PegCount;

            file_block = next_block; // :157
        }

        self.head = None; // :160 `head = last = nullptr`
        self.last = None; // :160

        if self.file_info.is_some() {
            self.file_info = None; // :162-:163 `delete file_info`
        }
    }
}

/// Row 17s seam closure (fcap PLAN §8-3): the REAL FileCapture
/// answers the `FileCaptureApi` trait (file_lib.rs:116-:130) at its
/// real signatures; `process_buffer` overrides the file_lib witness
/// DEFAULT (:127-:129) with the real ladder — the seam's 17r
/// "harness witness implements the buffer-state ladder" comment
/// retires here.
impl FileCaptureApi for FileCapture {
    fn reserve_file(&mut self, file: &FileInfo) -> u32 {
        FileCapture::reserve_file(self, file)
    }
    fn get_file_capture_size(&self) -> i64 {
        FileCapture::get_file_capture_size(self)
    }
    fn get_max_file_capture_size(&self) -> i64 {
        FileCapture::get_max_file_capture_size(self)
    }
    fn set_data(&mut self, file_data: &[u8], size: u32) {
        FileCapture::set_data(self, file_data, size)
    }
    fn process_buffer(&mut self, file_data: &[u8], data_size: i32, position: u32) -> u32 {
        FileCapture::process_buffer(self, file_data, data_size, position)
    }
}

/// Row 17s seam closure (fcap PLAN §8-3): the real `new
/// FileCapture(config->capture_min_size, config->capture_max_size)`
/// (file_lib.cc:1174, process_file_capture) replaces the
/// `NoFileCaptureFactory` default (kept for witness opt-out
/// injection); C `new` never answers nullptr, so `.expect("new
/// FileCapture -> null ... pinned-absent")` at file_lib.rs:3005-:3008
/// is now satisfied by construction. The factory owns the in-object
/// C file-statics + counts (17r/17m discipline) and hands clones to
/// every capture (`init` reaches them through [shared]/[counts] —
/// the C statics were global for exactly the same reason).
pub struct RealFileCaptureFactory {
    shared: Rc<FileCaptureShared>,
    counts: Rc<RefCell<FileCounts>>,
}

impl RealFileCaptureFactory {
    /// adopt existing statics (the harness fixture pattern: N
    /// captures over one shared pool via one factory set)
    pub fn with_statics(
        shared: Rc<FileCaptureShared>,
        counts: Rc<RefCell<FileCounts>>,
    ) -> Self {
        RealFileCaptureFactory { shared, counts }
    }

    /// fresh statics (C :55-:63 initializers via
    /// [FileCaptureShared::new]) + zeroed counts. `FileService::init`
    /// time `FileCapture::init(memcap, block_size)` writes them from
    /// [FileCapture::shared]()/[FileCapture::counts]().
    pub fn new() -> Self {
        RealFileCaptureFactory {
            shared: Rc::new(FileCaptureShared::new()),
            counts: Rc::new(RefCell::new(FileCounts::default())),
        }
    }

    pub fn shared(&self) -> Rc<FileCaptureShared> {
        self.shared.clone()
    }
    pub fn counts(&self) -> Rc<RefCell<FileCounts>> {
        self.counts.clone()
    }
}

impl Default for RealFileCaptureFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl FileCaptureFactory for RealFileCaptureFactory {
    fn new_capture(&mut self, min: i64, max: i64) -> Option<Box<dyn FileCaptureApi>> {
        // ctor file_capture.cc:120-:129; min/max ride verbatim (:127-:128)
        Some(Box::new(FileCapture::new(
            min,
            max,
            self.shared.clone(),
            self.counts.clone(),
        )))
    }
}
