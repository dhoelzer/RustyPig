//! Literal port of `file_api/circular_buffer.{h,cc}` — the
//! one-slot-open ring that is thread-safe for exactly one writer and
//! one reader (`circular_buffer.h:25-27`). Ring index math transcribed
//! verbatim: `cbuffer_init` allocates `size + 1` slots for a `size`
//! request (cc:58, cc:61 — one slot is always kept open so full and
//! empty never alias), start/end are raw wrap counters compared
//! against `cb->size` (never `%`), and `cbuffer_used` folds the
//! end-<start wrap back in with `size + end - start`.
//!
//! Ground truth: /opt/data/snort3-src (circular_buffer.cc 173 +
//! circular_buffer.h 62 lines) @ fe29cbe7403a, compiled VERBATIM in
//! the fctx/filib/fflows harness links; ZERO upstream TEST_CASEs —
//! its behavioural ground truth is the three `[file_mempool]`
//! TEST_CASEs at file_mempool.cc:223-303, which drive this ring solely
//! through the pool's free_list/released_list (gate binary
//! `tools/fctx_harness/gate`: "All tests passed (91 assertions in 18
//! test cases)").
//!
//! C `ElemType` is `void*` (circular_buffer.h:35); this port NEVER
//! puts a C pointer in the API — the only consumer (FileMemPool, see
//! `super::file_mempool`) hands out block identity, and the Rust
//! element type is `Option<usize>` == slot index (None == nullptr).
//! `elems: Vec<ElemType>` stands in for the snort_calloc'd ElemType
//! array; entries outside the [start, end) window hold stale slots,
//! exactly as C's stale pointers do — they are never read.
//!
//! C `std::atomic<uint64_t>` start/end with relaxed/acquire/release
//! orders (cc:47-48) map to plain u64 fields under Rust's `&mut self`
//! exclusivity: one writer/one reader discipline is enforced by the
//! borrow checker instead of the atomics (structural deviation,
//! recorded in KNOWN DEVIATIONS.md next to the file_mempool row).

/// circular_buffer.h:31 (`// FIXIT-RC use bool`)
pub const CB_SUCCESS: i32 = 0;
/// circular_buffer.h:32
pub const CB_FAIL: i32 = -1;

/// C `typedef void* ElemType` (circular_buffer.h:35) -> slot index,
/// None == nullptr (module header).
pub type ElemType = Option<usize>;

/// `struct _CircularBuffer` (circular_buffer.cc:44-50), fields in C
/// order; `size` is the ALLOCATED slot count (request + 1, cc:58), so
/// usable capacity is `cbuffer_size()` == size - 1.
pub struct CircularBuffer {
    /// maximum number of elements (slots; +1 per one-slot-open)
    pub size: u64,
    /// index of oldest element, reader update only
    pub start: u64,
    /// index to write new element, writer update only
    pub end: u64,
    /// vector of elements
    pub elems: Vec<ElemType>,
}

impl CircularBuffer {
    /// circular_buffer.cc:54-70 `cbuffer_init(uint64_t size)`: calloc'd
    /// cb; `cb->size = size + 1` (cc:58 — the one slot kept open);
    /// start = end = 0 (cc:59-60, relaxed stores); elems calloc'd over
    /// `cb->size` slots (cc:61). The C `if (!cb->elems)` null-arm
    /// (cc:63-67) cannot fire on a Vec (allocation OOM aborts, never
    /// returns null) — the Option shape and the caller's failure arms
    /// are kept for structural parity.
    #[allow(clippy::unnecessary_wraps)] // C calloc-failure shape; see doc
    pub fn cbuffer_init(size: u64) -> Option<CircularBuffer> {
        let size = size.wrapping_add(1); // cc:58
        Some(CircularBuffer {
            size,
            start: 0, // cc:59
            end: 0,   // cc:60
            // cc:61 `snort_calloc(cb->size, sizeof(ElemType))`
            elems: vec![None; size as usize],
        })
    }

    /// circular_buffer.cc:72-81 `cbuffer_free`: frees elems (nulling
    /// the field, cc:77) then the struct itself, both null-tolerant.
    /// Rust: dropping the value (or `Option::take` in the caller's
    /// free_pools) runs the same teardown — the snort_free pair needs
    /// no explicit body.
    pub fn cbuffer_free(cb: Option<CircularBuffer>) {
        drop(cb);
    }

    /// circular_buffer.cc:83-91 `cbuffer_is_full`: the one-slot-open
    /// test — full when `end + 1` (wrapped against `size`, NOT `%`)
    /// equals start. Returns 1/0 like the C `int` (header FIXIT-RC).
    pub fn cbuffer_is_full(&self) -> i32 {
        let mut next = self.end.wrapping_add(1); // cc:85 (+1)
        if next == self.size {
            next = 0; // cc:87-88 wrap
        }
        i32::from(next == self.start) // cc:90
    }

    /// circular_buffer.cc:94-97 `cbuffer_is_empty`: end == start.
    pub fn cbuffer_is_empty(&self) -> i32 {
        i32::from(self.end == self.start) // cc:96
    }

    /// circular_buffer.cc:100-109 `cbuffer_used`: number of elements
    /// in use, folding the end<start wrap through `size + end -
    /// start` (cc:105-108) — all u64 wrapping.
    pub fn cbuffer_used(&self) -> u64 {
        if self.end < self.start {
            self.size.wrapping_add(self.end).wrapping_sub(self.start) // cc:106
        } else {
            self.end.wrapping_sub(self.start) // cc:108
        }
    }

    /// circular_buffer.cc:114-117 `cbuffer_size`: total number of
    /// elements == allocated slots - 1 (the permanently-open slot).
    pub fn cbuffer_size(&self) -> u64 {
        self.size.wrapping_sub(1) // cc:116
    }

    /// circular_buffer.cc:129-145 `cbuffer_write`: full -> CB_FAIL
    /// (cc:133-136); store at `end`, advance the local cursor and wrap
    /// against `size` (cc:138-140), publish end (cc:142); CB_SUCCESS.
    pub fn cbuffer_write(&mut self, elem: ElemType) -> i32 {
        let mut w = self.end; // cc:131

        if self.cbuffer_is_full() != CB_SUCCESS {
            return CB_FAIL; // cc:133-136 ("full, return error")
        }

        self.elems[w as usize] = elem; // cc:138 `cb->elems[w++]`
        w = w.wrapping_add(1);
        if w == self.size {
            w = 0; // cc:139-140
        }

        self.end = w; // cc:142 (release store -> &mut exclusivity)

        CB_SUCCESS // cc:144
    }

    /// circular_buffer.cc:157-173 `cbuffer_read`: empty -> CB_FAIL
    /// (cc:161-164, the out-param `elem` keeps its caller's value,
    /// exactly like C, which only writes `*elem` on the success
    /// path); take `elems[start]`, advance and wrap (cc:166-168),
    /// publish start (cc:170); CB_SUCCESS.
    pub fn cbuffer_read(&mut self, elem: &mut ElemType) -> i32 {
        let mut r = self.start; // cc:159

        if self.cbuffer_is_empty() != CB_SUCCESS {
            return CB_FAIL; // cc:161-164 ("Empty, return error")
        }

        *elem = self.elems[r as usize]; // cc:166 `*elem = cb->elems[r++]`
        r = r.wrapping_add(1);
        if r == self.size {
            r = 0; // cc:167-168
        }

        self.start = r; // cc:170 (release store -> &mut exclusivity)

        CB_SUCCESS // cc:172
    }
}
