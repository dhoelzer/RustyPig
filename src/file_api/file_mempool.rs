//! Literal port of `file_api/file_mempool.{h,cc}` — the fixed-block
//! pool with O(1) alloc/free, double-free detection via an in-block
//! magic, and a one-writer / one-releaser split (free_list /
//! released_list circular buffers, `super::circular_buffer`).
//!
//! Ground truth: /opt/data/snort3-src (file_mempool.cc 303 +
//! file_mempool.h 84 lines) @ fe29cbe7403a. Gate = the TU's OWN
//! embedded UNIT_TEST block (file_mempool.cc:223-303, 3 `[file_mempool]`
//! TEST_CASEs / 27 assertions: :231 "m_free detects double free", :243
//! "m_free double free does not duplicate queue entries", :273
//! "m_release double free does not duplicate queue entries"), compiled
//! VERBATIM in `tools/fctx_harness` (gate binary tail: "All tests
//! passed (91 assertions in 18 test cases)").
//!
//! C shapes -> Rust shapes (deviations, recorded under the
//! KNOWN DEVIATIONS.md row for this pair):
//! * `datapool` (file_mempool.h:75 `void**`, calloc'd at .cc:78 as
//!   `num_objects * o_size` bytes) is a byte arena sliced into blocks
//!   (`.cc:98` `(char*)datapool + (i * obj_size)`) -> `Vec<u8>` arena;
//!   block identity in the API is NEVER a C pointer: slots are
//!   `Option<usize>` (None == nullptr, C:130), matching the
//!   `ElemType = Option<usize>` ring elements of circular_buffer.rs.
//! * the `MagicType FREE_MAGIC` lives in each block's first 8 bytes in
//!   C (.cc:105/:157/:167, and the test helper .cc:228 writes 0 through
//!   the block pointer); the Rust port keeps a PARALLEL per-slot magic
//!   table (`magic: Vec<MagicType>`) — the block-header reads/writes
//!   transcribe to table ops, so the C obj_size < 8 header-overlap
//!   quirk (never exercised: the gate sizes blocks at
//!   `sizeof(uint64_t)`) is structurally impossible here.
//! * `std::mutex pool_mutex` + `lock_guard` (.h:80, .cc:132/:174/:191)
//!   map to Rust's `&mut self` exclusivity; the C "same thread as
//!   m_alloc" rule for m_free (file_mempool.h:50) is enforced by the
//!   borrow checker instead — the single-threaded-port reading (the
//!   one-writer/one-reader thread safety is a C concurrency property
//!   the borrow checker already supplies; atomics in the ring and the
//!   mutex here are comment-transcribed, not ported, same discipline
//!   as file_cache.rs's commented cache_mutex sites).
//! * the .cc:149 `static int remove(CircularBuffer* cb, void* obj)` is
//!   METHODED as `remove(sel, slot)`: the magic test needs the pool's
//!   table, and `cb` becomes a list selector (cbuffer_free-null
//!   tolerance kept: a None list answers the write as CB_FAIL, where
//!   C would deref a nullptr ring — reachable only after a degenerate
//!   ctor, pinned deviation).

use super::circular_buffer::{CB_FAIL, CB_SUCCESS, CircularBuffer, ElemType};

/// file_mempool.h:35 (`// FIXIT-RC use bool`)
pub const FILE_MEM_SUCCESS: i32 = 0;
/// file_mempool.h:36
pub const FILE_MEM_FAIL: i32 = -1;

/// file_mempool.cc:46 `typedef uint64_t MagicType`
pub type MagicType = u64;

/// file_mempool.cc:45 — "This magic is used for double free
/// detection" (cc:43)
pub const FREE_MAGIC: MagicType = 0x2525_2525_2525_2525;

/// which ring `remove` (cc:149 `remove(CircularBuffer* cb, ...)`) is
/// handed: file_mempool.cc:176 `remove(free_list, obj)` / :194
/// `remove(released_list, obj)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListSel {
    FreeList,
    ReleaseList,
}

/// C `class FileMemPool` (file_mempool.h:38-81), members in C order
/// (.h:75-79) plus the block-magic table standing in for the in-block
/// header (module header); `pool_mutex` (.h:80) is the &mut-self rule.
pub struct FileMemPool {
    /// memory buffer (C `void** datapool`, never nullptr-dereffed
    /// here: Option None == freed/degenerate pool)
    datapool: Option<Vec<u8>>,
    total: u64,
    free_list: Option<CircularBuffer>,
    released_list: Option<CircularBuffer>,
    obj_size: usize,
    /// per-slot stand-in for the blocks' first 8 bytes (module
    /// header); parallel to the slot indices queued in the rings
    magic: Vec<MagicType>,
}

impl FileMemPool {
    /// file_mempool.cc:49-59 `free_pools()`: null-tolerant datapool
    /// free (:51-55) + `cbuffer_free(free_list); cbuffer_free(
    /// released_list);` (:57-58, both accept nullptr per
    /// circular_buffer.cc:74). Also the ~FileMemPool body (:114-117)
    /// via [Drop], and the ctor's two cbuffer_init-failure cleanup
    /// arms (:84/:91).
    fn free_pools(&mut self) {
        if self.datapool.is_some() {
            self.datapool = None; // cc:53-54 snort_free + datapool = nullptr
        }
        CircularBuffer::cbuffer_free(self.free_list.take()); // cc:57
        CircularBuffer::cbuffer_free(self.released_list.take()); // cc:58
    }

    /// file_mempool.cc:68-108 ctor: the `num_objects < 1 || o_size < 1`
    /// early-return leaves EVERY member at its .h:75-79 initializer
    /// (:72-73); datapool = calloc'd byte arena (:78); the two
    /// cbuffer_init arms free the pools and bail (:82-93); then each
    /// slot's block address (:98) is queued into free_list (:100), its
    /// magic planted FREE_MAGIC (:105) and `total` bumped (:106) — all
    /// `num_objects` writes must land (:101-104 arm kept literally,
    /// unreachable at exact capacity, same as C's).
    pub fn new(num_objects: u64, o_size: usize) -> Self {
        // .h:75-79 member initializers (datapool/free_list/
        // released_list nullptr, total/obj_size 0) == "everything
        // stays empty" for the early-return arms.
        let mut pool = FileMemPool {
            datapool: None,
            total: 0,
            free_list: None,
            released_list: None,
            obj_size: 0,
            magic: Vec::new(),
        };

        if (num_objects < 1) || (o_size < 1) {
            return pool; // cc:72-73
        }

        pool.obj_size = o_size; // cc:75

        // cc:78 `datapool = (void**)snort_calloc(num_objects, obj_size);`
        // — one byte arena, sliced into num_objects blocks of obj_size
        // (wrapping mul mirrors the C size_t product).
        pool.datapool = Some(vec![
            0u8;
            (num_objects.wrapping_mul(pool.obj_size as u64)) as usize
        ]);
        // module header: the block headers (calloc => 0, then .cc:105
        // sets FREE_MAGIC) live in the parallel table.
        pool.magic = vec![0; num_objects as usize];

        // cc:81 `free_list = cbuffer_init(num_objects);`
        pool.free_list = CircularBuffer::cbuffer_init(num_objects);
        if pool.free_list.is_none() {
            pool.free_pools(); // cc:84
            return pool; // cc:85
        }

        // cc:88 `released_list = cbuffer_init(num_objects);`
        pool.released_list = CircularBuffer::cbuffer_init(num_objects);
        if pool.released_list.is_none() {
            pool.free_pools(); // cc:91
            return pool; // cc:92
        }

        pool.total = 0; // cc:95
        for i in 0..num_objects {
            // cc:98 `void* data = ((char*)datapool) + (i * obj_size);`
            // -> the slot index itself (module header).
            let cbuffer_write = pool
                .free_list
                .as_mut()
                .map_or(CB_FAIL, |fl| fl.cbuffer_write(Some(i as usize)));
            if cbuffer_write != CB_SUCCESS {
                // cc:100 `if (cbuffer_write(free_list, data))` (also
                // the degenerate-list arm; the write never fails at
                // exact ring capacity, same as C).
                pool.free_pools(); // cc:102
                return pool; // cc:103
            }
            pool.magic[i as usize] = FREE_MAGIC; // cc:105
            pool.total = pool.total.wrapping_add(1); // cc:106
        }

        pool
    }

    /// file_mempool.cc:128-143 `m_alloc()`: pop from free_list; only
    /// if THAT read fails (C:134, b stays nullptr on failure — the C
    /// out-param write happens on the success path only,
    /// circular_buffer.cc:166) steal from released_list (C:136: free
    /// and release writers are different threads, so a freed-in full
    /// ring can only be topped up from the released side); both read
    /// failed -> nullptr (C:138). Returns the slot,
    /// `Option<usize>` == the C `void*` (module header).
    pub fn m_alloc(&mut self) -> Option<usize> {
        // std::lock_guard<std::mutex> lock(pool_mutex); (cc:132 —
        // &mut self exclusivity, module header)
        let mut b: ElemType = None; // cc:130 `void* b = nullptr;`

        let free_read_fails = self
            .free_list
            .as_mut()
            // cc:134 `if (cbuffer_read(free_list, &b))` — a None ring
            // (post-degenerate-ctor, where C'd deref nullptr) answers
            // the read as CB_FAIL (pinned deviation).
            .is_none_or(|cb| cb.cbuffer_read(&mut b) != CB_SUCCESS);

        if free_read_fails {
            let released_read_fails = self
                .released_list
                .as_mut()
                .is_none_or(|cb| cb.cbuffer_read(&mut b) != CB_SUCCESS); // cc:136
            if released_read_fails {
                return None; // cc:138
            }
        }

        b // cc:142
    }

    /// file_mempool.cc:149-170 `static int remove(CircularBuffer* cb,
    /// void* obj)` — the double-free gate, TRANSFERRED ORDER
    /// PRESERVED: nullptr obj -> FAIL (:151-152); magic ALREADY
    /// FREE_MAGIC -> FAIL (:157-160, whose C comment pins that the
    /// test runs BEFORE `cbuffer_write` : a post-write test would
    /// queue the block twice and a later m_alloc pair would hand the
    /// SAME block to two owners — the CHECK(first != second) arms of
    /// the :243/:273 TEST_CASEs pin this); else queue into the
    /// selected ring (:162-165 write full -> FAIL), THEN plant
    /// FREE_MAGIC (:167); FILE_MEM_SUCCESS (:169).
    fn remove(&mut self, sel: ListSel, obj: Option<usize>) -> i32 {
        let Some(obj) = obj else {
            return FILE_MEM_FAIL; // cc:151-152 `if (obj == nullptr)`
        };

        // cc:157 `if (*(MagicType*)obj == FREE_MAGIC)` -> table read.
        // out-of-pool slot: C derefs the stray pointer (UB); the port
        // answers FAIL (pinned deviation).
        let Some(&magic) = self.magic.get(obj) else {
            return FILE_MEM_FAIL;
        };
        if magic == FREE_MAGIC {
            return FILE_MEM_FAIL; // cc:157-160 (BEFORE enqueuing)
        }

        let cb = match sel {
            ListSel::FreeList => self.free_list.as_mut(), // cc:176
            ListSel::ReleaseList => self.released_list.as_mut(), // cc:194
        };
        let Some(cb) = cb else {
            // C hands a nullptr ring only after a degenerate ctor and
            // cbuffer_write would deref it (UB); the port answers the
            // cc:162-165 write as CB_FAIL -> FILE_MEM_FAIL (pinned
            // deviation).
            return FILE_MEM_FAIL;
        };

        if cb.cbuffer_write(Some(obj)) != CB_SUCCESS {
            return FILE_MEM_FAIL; // cc:162-165
        }

        self.magic[obj] = FREE_MAGIC; // cc:167 `*(MagicType*)obj = FREE_MAGIC`

        FILE_MEM_SUCCESS // cc:169
    }

    /// file_mempool.cc:172-180 `m_free(void* obj)`: lock (:174 —
    /// &mut self; this MUST pair with the m_alloc side per .h:50, the
    /// single-thread rule the borrow checker enforces, module header)
    /// then `remove(free_list, obj)` (:176), return verbatim (:179).
    pub fn m_free(&mut self, obj: Option<usize>) -> i32 {
        self.remove(ListSel::FreeList, obj)
    }

    /// file_mempool.cc:189-198 `m_release(void* obj)`: same as m_free
    /// but into released_list (:194) — the side another thread's
    /// m_alloc steals from (.h:53-55; see m_alloc, cc:134-139).
    pub fn m_release(&mut self, obj: Option<usize>) -> i32 {
        self.remove(ListSel::ReleaseList, obj)
    }

    /// file_mempool.cc:201-205 `allocated()`: `total - (released() +
    /// freed())`, C evaluation order kept (:203).
    pub fn allocated(&self) -> u64 {
        let total_freed = self.released().wrapping_add(self.freed()); // cc:203
        self.total.wrapping_sub(total_freed) // cc:204
    }

    /// file_mempool.cc:208-211 `freed()`: `cbuffer_used(free_list)` —
    /// blocks sitting in free_list awaiting the alloc-side steal. (C
    /// derefs the nullptr ring after a degenerate ctor; the port
    /// answers 0 — pinned deviation.)
    pub fn freed(&self) -> u64 {
        self.free_list
            .as_ref()
            .map_or(0, |cb| cb.cbuffer_used())
    }

    /// file_mempool.cc:214-217 `released()`: `cbuffer_used(
    /// released_list)` (same nullptr reading as [freed]).
    pub fn released(&self) -> u64 {
        self.released_list
            .as_ref()
            .map_or(0, |cb| cb.cbuffer_used())
    }

    /// file_mempool.h:68 inline `total_objects()`
    pub fn total_objects(&self) -> u64 {
        self.total
    }

    /// file_mempool.cc:223-229 unit-test helper `mark_block_in_use`
    /// ("In production, callers initialize block headers immediately
    /// after m_alloc()" — :226-227; the plant is `*(MagicType*)p = 0`
    /// at :228, i.e. slot magic -> in-use). Exposed so the parity test
    /// can replay the 3 gate TEST_CASEs verbatim.
    pub fn mark_block_in_use(&mut self, obj: Option<usize>) {
        if let Some(obj) = obj {
            self.magic[obj] = 0; // cc:228
        }
    }
}

impl Drop for FileMemPool {
    /// file_mempool.cc:114-117 `~FileMemPool() { free_pools(); }`
    fn drop(&mut self) {
        self.free_pools();
    }
}
