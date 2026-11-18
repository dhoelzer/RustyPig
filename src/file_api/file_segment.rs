//! Literal port of file_api/file_segment.{h,cc} — segmented file data
//! reassembly (plan row 17r; the machinery behind
//! `FileContext::process` offset form, file_lib.cc:986).
//!
//! Ground truth: /opt/data/snort3-src @ fe29cbe7403a (file_segment.cc
//! 355 + .h 78 lines), compiled VERBATIM in the fctx harness link (the
//! donor list already carried it); ZERO upstream TEST_CASEs — the probe
//! O-block (tools/fctx_harness/vectors.txt) is the whole ground truth.
//! C `FileSegments::process_one` recurses into FileContext::process
//! (position form) — the mutual-call chain is threaded as explicit
//! `this: &Rc<RefCell<FileContext>>` + the free
//! `file_lib::process_pos` entry (skill rule for C mutual-call chains:
//! no self-referential structs; the Rc form also keeps the RefCell
//! discipline, see the file_lib.rs module header).
//!
//! Structural deviations (KNOWN DEVIATIONS.md, row 17r):
//! * C `FileSegment{next, prev}` doubly-linked list — always kept
//!   sorted by offset — -> `Vec<FileSegment>` in list order. Every
//!   pointer walk (head/tail fast paths, the closer-end `le` search,
//!   the overlap `left = left->next` ladder with insert_segment's
//!   `*left = (*left)->next` caller-slot re-aim) is transcribed as the
//!   same walk over indices, so insertion ORDER and every FILE_DEBUG
//!   print land exactly where C put them. `clear()` empties the Vec
//!   but the owning Option in FileContext stays Some — the C
//!   `file_segments` pointer likewise survives a clear (pinned by O5:
//!   "segments_queued" true after the false-arm clear, false only
//!   after remove_segments).
//! * C `std::string* data` holds raw bytes -> `Vec<u8>`.
//! * `FileSegment::offset` keeps the C uint32_t field type: the
//!   process/add args are uint64 and TRUNCATE at node creation,
//!   literally (`offset as u32`, never observed for >u32 values).
//! * C's implicit uint64 <-> int64 narrowing on the add/insert/
//!   process boundaries is the explicit `as` cast pair (2's
//!   complement; the pinning inputs keep every intermediate in range —
//!   wrapping_add mirrors the C modulo-2^64 wraps).

use std::cell::RefCell;
use std::rc::Rc;

use super::file_cache::{
    FilePolicyHandle, PacketView, TRACE_DEBUG_LEVEL, TRACE_ERROR_LEVEL, TRACE_INFO_LEVEL,
};
use super::file_lib::{
    FlowsRef, process_pos, FileContext, FileEnvLite, SNORT_FILE_END, SNORT_FILE_FULL,
    SNORT_FILE_MIDDLE, SNORT_FILE_POSITION_UNKNOWN, SNORT_FILE_START,
};
use crate::file_api::file_stats::FileCounts;

/// file_segment.h:38 `class FileSegment` — the C next/prev raw
/// pointers are carried by Vec order (module header); offset/data
/// fields verbatim.
#[derive(Clone, Debug)]
pub struct FileSegment {
    pub offset: u32,
    pub data: Vec<u8>, // C `std::string* data`
}

/// the C `FileSegment*` cursor in the add()/insert_segment walks:
/// `Option<usize>` == pointer-into-segs / nullptr.
type Left = Option<usize>;

/// file_segment.h:52 `class FileSegments` — head/tail == Vec front/back
/// (module header), current_offset and the segment list verbatim; the
/// C `context` back-pointer is the threaded `this` argument.
pub struct FileSegments {
    pub current_offset: u64,
    segs: Vec<FileSegment>,
}

impl Default for FileSegments {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSegments {
    /// file_segment.cc:40 ctor `FileSegments(FileContext* ctx)`:
    /// head = tail = nullptr, current_offset = 0.
    pub fn new() -> Self {
        FileSegments {
            current_offset: 0,
            segs: Vec::new(),
        }
    }

    /// file_segment.cc:48 ~FileSegments -> clear(); the clear() body
    /// walks the chain deleting every node, nulls head/tail and resets
    /// current_offset (O3c pins the offset reset: after clear, 18 != 0
    /// re-queues).
    pub fn clear(&mut self) {
        self.segs.clear();
        self.current_offset = 0;
    }

    /// file_segment.cc:62 `add(Packet*, const uint8_t* file_data,
    /// int64_t data_size, uint64_t offset)` — head fast path (the
    /// "Adding segment, offset : %u data_size : %" PRId64 line prints
    /// AFTER the node fields are set, BEFORE linking: the C arg list
    /// reads new_segment->offset, and the std::string ctor ran first —
    /// the Vec push below lands after the print exactly like the C
    /// head = tail = assignment follows it), tail fast path, the
    /// closer-end `le` search, the end-append front-trim, the
    /// head-insert end-trim, and the `left` overlap ladder.
    fn add(
        &mut self,
        p: &mut PacketView,
        file_data: &[u8],
        mut data_size: i64,
        offset: u64,
        env: &mut FileEnvLite,
    ) {
        if self.segs.is_empty() {
            let off32 = offset as u32; // C node field uint32_t
            env.trace.file_trace(
                TRACE_DEBUG_LEVEL,
                &format!("Adding segment, offset : {} data_size : {}\n", off32, data_size),
            );
            // C `new std::string((const char*)file_data, data_size)` —
            // data_size >= 0 here (the <= 0 arm was consumed upstream;
            // saturating keeps a malformed negative from panicking).
            self.segs.push(FileSegment {
                offset: off32,
                data: file_data[..(data_size.max(0) as usize)].to_vec(),
            });
            return;
        }

        let start = offset;
        // C `uint64_t end = offset + data_size;` (int64 into uint64 add)
        let end = offset.wrapping_add(data_size as u64);

        // C: `FileSegment* left = nullptr; FileSegment* previous =
        // nullptr; bool find_left = false;`
        let mut find_left = false;
        let mut left: Left = None;

        // tail->offset > start? (list sorted; segs.last() == tail)
        if (self.segs[self.segs.len() - 1].offset as u64) > start {
            find_left = true;
            if (self.segs[0].offset as u64) > start {
                // start before every segment: insert before head
                left = None;
            } else {
                // first segment with offset > start == the first split
                // point of a head->next walk; head_dist == 0 because
                // head->offset <= start, so the else arm (head walk) is
                // the one C always takes here (transcribed literally).
                let mut i = 0usize;
                while i < self.segs.len() && (self.segs[i].offset as u64) <= start {
                    i += 1;
                }
                left = Some(i); // Some(len) == tail, None == before head
                if i == self.segs.len() {
                    left = None;
                }
            }
        }
        // else arm: `find_left = false; previous = tail;` handled
        // directly in the append arm below.

        if !find_left {
            // C `left = previous;` (previous == tail; non-null since the
            // list is non-empty here)
            let li = self.segs.len() - 1;
            let mut offset = offset;
            let mut data_size = data_size;
            let mut fd = file_data;
            // C front-trim when the new range starts inside left's span
            if li < self.segs.len()
                && ((self.segs[li].offset as u64) + (self.segs[li].data.len() as u64)) > start
            {
                offset = (self.segs[li].offset as u64) + (self.segs[li].data.len() as u64);
                data_size = end.wrapping_sub(offset) as i64;
                fd = &fd[((offset - start) as usize)..];
            }
            self.insert_segment(p, fd, data_size, offset, find_left, Some(li), env);
        } else if left.is_none() {
            // C head-insert end-trim: `if (end > head->offset) data_size
            // = head->offset - offset;` (C `size_t - uint64` -> i64 bits)
            let mut data_size = data_size;
            if end > (self.segs[0].offset as u64) {
                data_size = ((self.segs[0].offset as u64).wrapping_sub(offset)) as i64;
            }
            self.insert_segment(p, file_data, data_size, offset, find_left, left, env);
        } else {
            // C: `while (left and (left->offset + left->data->size() <=
            // end)) { ...; insert_segment(p, cur_file_data, data_size,
            // offset, find_left, &left); left = left->next; }` — the
            // `&&` folds into `break if > end` (Rust while-let on the
            // Option cursor).
            let mut left = left;
            while let Some(li) = left {
                let li_end = (self.segs[li].offset as u64) + (self.segs[li].data.len() as u64);
                if li_end > end {
                    break;
                }
                // C iteration-local copies of the outer cursor triple:
                // `const uint8_t *cur_file_data = file_data;` and the
                // outer `offset`/`data_size` (the C code DOES mutate
                // the outer offset/data_size in the front-trim arm —
                // transcribed: they are the loop-carried values here).
                let mut offset = offset;
                if li_end > start {
                    offset = li_end;
                    data_size = end.wrapping_sub(offset) as i64;
                }
                let cur_from = (offset - start) as usize; // cur_file_data base
                let data_size = if li + 1 < self.segs.len()
                    && (self.segs[li + 1].offset as u64) < end
                {
                    // C right-overlap cap: `data_size =
                    // left->next->offset - offset;`
                    ((self.segs[li + 1].offset as u64).wrapping_sub(offset)) as i64
                } else {
                    data_size
                };
                // C insert_segment(..., &left): on a successful insert
                // the find_left arm also re-aims `*left =
                // (*left)->next` (the caller's cursor at the NEW node);
                // the data_size <= 0 return leaf leaves `*left`
                // untouched. Then the ladder advances `left =
                // left->next` from the (re-aimed) slot.
                let inserted = self.insert_segment(
                    p,
                    &file_data[cur_from..],
                    data_size,
                    offset,
                    find_left,
                    Some(li),
                    env,
                );
                // On a NON-find_left insert C never re-aims; but this
                // ladder always passes find_left == true (its arm ran
                // only after `find_left = true`), so the `*left =
                // (*left)->next` slot-aim inside insert_segment's
                // else arm fires on every successful insert: the
                // cursor moves to the NEW node (index li + 1 after
                // the splice). A data_size <= 0 leaf returns without
                // touching *left (cursor stays). Then the ladder's
                // own `left = left->next` advances one further.
                let aimed = if inserted { Some(li + 1) } else { Some(li) };
                left = aimed.and_then(|a| if a + 1 < self.segs.len() { Some(a + 1) } else { None });
            }
        }
    }

    // (the ladder advance above: C `left = left->next` walks one past
    // the insert; the two-statement form above mirrors the C
    // re-aim (`*left = (*left)->next`) plus the advance.)

    /// file_segment.cc:191 `insert_segment(Packet*, const uint8_t*,
    /// int64_t data_size, uint64_t offset, bool find_left, FileSegment**
    /// left)` — returns whether a node was inserted (the C `*left`
    /// re-aim is reachable on every non-early-return path).
    #[allow(clippy::too_many_arguments)] // C signature, 7 params + &mut self
    fn insert_segment(
        &mut self,
        _p: &mut PacketView, // C's `Packet* p` arg is live at the
        // FILE_DEBUG sites but unused there (no GET_CURRENT_PACKET arm
        // reaches it — the sink seam never consumes the view)
        file_data: &[u8],
        data_size: i64,
        offset: u64,
        find_left: bool,
        left: Left, // C FileSegment** slot (None == insert before head)
        env: &mut FileEnvLite,
    ) -> bool {
        // C: `// ignore overlap case  if (data_size <= 0) { FILE_DEBUG
        // ... TRACE_ERROR_LEVEL ... "Complete overlap while adding
        // segments  offset : %" PRIu64 " data_size : %" PRId64 "\n";
        // return; }` (two spaces after "segments"; p arg -> plain
        // FILE_DEBUG, no GET_CURRENT_PACKET)
        if data_size <= 0 {
            env.trace.file_trace(
                TRACE_ERROR_LEVEL,
                &format!(
                    "Complete overlap while adding segments  offset : {} data_size : {}\n",
                    offset, data_size
                ),
            );
            return false;
        }

        // C FILE_DEBUG DEBUG "Adding offset : %" PRIu64 " data_size : %"
        // PRId64 "\n" BEFORE linking (the new node is built first:
        // offset/data set by C at :199-201 ABOVE the DEBUG).
        env.trace.file_trace(
            TRACE_DEBUG_LEVEL,
            &format!("Adding offset : {} data_size : {}\n", offset, data_size),
        );
        let new_segment = FileSegment {
            offset: offset as u32, // C uint32_t field; uint64 arg truncates
            data: file_data[..(data_size.max(0) as usize)].to_vec(),
        };

        match left {
            // C `if (!*left)`: insert before head (`head->prev = new` /
            // `tail = new` when the list was empty)
            None => self.segs.insert(0, new_segment),
            // C `else if (!find_left)`: append after left (left == tail)
            Some(li) if !find_left => self.segs.insert(li + 1, new_segment),
            // C else arm: splice after left before left->next; re-aim
            // happens in the caller above.
            Some(li) => self.segs.insert(li + 1, new_segment),
        }
        true
    }

    /// file_segment.cc:241 `get_file_position(uint64_t data_size,
    /// uint64_t file_size)` (C reads `context->get_file_size()` at the
    /// call site; this stays exactly as C ordered it).
    fn get_file_position(&self, data_size: u64, file_size: u64) -> u32 {
        if self.current_offset == 0 {
            if file_size == data_size {
                return SNORT_FILE_FULL;
            } else {
                return SNORT_FILE_START;
            }
        }
        if file_size != 0 && file_size <= data_size + self.current_offset {
            return SNORT_FILE_END;
        }
        SNORT_FILE_MIDDLE
    }

    /// file_segment.cc:257 `process_one(Packet*, const uint8_t*, int
    /// data_size, FilePolicyBase*, FilePosition position = UNKNOWN)` —
    /// position resolves through get_file_position; the recursion edge
    /// `context->process(p, file_data, data_size, position, policy)` is
    /// the position-form overload = the file_lib free `process_pos`.
    #[allow(clippy::too_many_arguments)]
    fn process_one(
        &mut self,
        p: &mut PacketView,
        file_data: &[u8],
        data_size: i32,
        policy: Option<FilePolicyHandle>,
        position: u32,
        this: &Rc<RefCell<FileContext>>,
        ff: &mut FlowsRef<'_>,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> bool {
        let position = if position == SNORT_FILE_POSITION_UNKNOWN {
            self.get_file_position(data_size as u64, this.borrow().info.get_file_size())
        } else {
            position
        };
        process_pos(this, p, file_data, data_size, position, policy, ff, env, counts)
    }

    /// file_segment.cc:266 `process_all(Packet*, FilePolicyBase*)` —
    /// the on-current-offset drain; a false ret -> `clear(); break;`.
    #[allow(clippy::too_many_arguments)]
    fn process_all(
        &mut self,
        p: &mut PacketView,
        policy: Option<FilePolicyHandle>,
        this: &Rc<RefCell<FileContext>>,
        ff: &mut FlowsRef<'_>,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> bool {
        let mut ret = true; // C `int ret = 1;`
        while !self.segs.is_empty() && self.current_offset == (self.segs[0].offset as u64) {
            // C FILE_DEBUG INFO "processing the current offset %" PRIu64
            // "\n" (p arg — no GET_CURRENT_PACKET witness line beside it)
            env.trace.file_trace(
                TRACE_INFO_LEVEL,
                &format!("processing the current offset {}\n", self.current_offset),
            );

            // C hands the live node buffer to process_one through the
            // pointer, then deletes the node AFTER the call returns. The
            // port clones the bytes out (borrow shape; the node itself
            // stays in the list across the call exactly as C's did, the
            // erase below is the C delete point — no print or re-entry
            // observes the list mid-call: the pinned O-block drains one
            // segment per loop iteration).
            let data = self.segs[0].data.clone();
            let n = data.len() as i32; // C size_t -> int arg (pinned small)

            ret = self.process_one(p, &data, n, policy.clone(), SNORT_FILE_POSITION_UNKNOWN, this, &mut *ff, env, counts);

            if !ret {
                self.clear();
                break;
            }

            // C tail arm: `current_offset += segment->data->size();
            // head = segment->next; if (head) head->prev = nullptr; else
            // tail = nullptr; delete (current_segment); current_segment
            // = head;`
            self.current_offset += data.len() as u64;
            self.segs.remove(0);
        }
        ret
    }

    /// file_segment.cc:305 `process(Packet*, const uint8_t* file_data,
    /// uint64_t data_size, uint64_t offset, FilePolicyBase*,
    /// FilePosition position = SNORT_FILE_POSITION_UNKNOWN)`:
    /// * ret 1 (true): continue processing/log/block this file
    /// * ret 0 (false): ignore this file
    ///
    /// The false flush return clears the list AND answers 0 (:341-342 —
    /// pinned at O5: the LIST empties while the FileContext pointer
    /// survives; `process_all`'s internal false reaches the same clear
    /// through its own `clear(); break;`).
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        &mut self,
        p: &mut PacketView,
        file_data: &[u8],
        data_size: u64, // C uint64_t (the FileContext arg converts from int here)
        offset: u64,
        policy: Option<FilePolicyHandle>,
        position: u32,
        this: &Rc<RefCell<FileContext>>,
        ff: &mut FlowsRef<'_>,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> bool {
        let mut file_data = file_data;
        let mut data_size = data_size;
        let mut offset = offset;
        let mut ret = false; // C `int ret = 0;`

        // C: `if (offset < current_offset) { if (offset + data_size >
        // current_offset) { file_data += (current_offset - offset);
        // data_size = (offset + data_size) - current_offset; offset =
        // current_offset; } else { FILE_DEBUG DEBUG "not adding to file
        // segment queue offset %lu , current_offset %lu\n"; return 1; } }`
        if offset < self.current_offset {
            if offset.wrapping_add(data_size) > self.current_offset {
                let skip = (self.current_offset - offset) as usize;
                file_data = &file_data[skip..];
                data_size = offset.wrapping_add(data_size).wrapping_sub(self.current_offset);
                offset = self.current_offset;
            } else {
                env.trace.file_trace(
                    TRACE_DEBUG_LEVEL,
                    &format!(
                        "not adding to file segment queue offset {} , current_offset {}\n",
                        offset, self.current_offset
                    ),
                );
                return true;
            }
        }

        // C: `// Walk through the segments that can be flushed
        // if (current_offset == offset) { if (head and offset+data_size >
        // head->offset) { if (head->offset < offset) return 1; data_size
        // = head->offset - offset; } ret = process_one(p, file_data,
        // data_size, policy, position); current_offset += data_size; if
        // (!ret) { clear(); return 0; } ret = process_all(p, policy); }`
        if self.current_offset == offset {
            if !self.segs.is_empty()
                && offset.wrapping_add(data_size) > (self.segs[0].offset as u64)
            {
                if (self.segs[0].offset as u64) < offset {
                    return true;
                }
                data_size = (self.segs[0].offset as u64).wrapping_sub(offset);
            }

            // C `process_one(p, file_data, data_size, policy, position)`
            // — the uint64 into the int data_size parameter conversion
            // (process_all re-widens; pinned inputs keep it < i32::MAX).
            ret = self.process_one(
                p, file_data, data_size as i32, policy.clone(), position, this, &mut *ff, env, counts,
            );
            self.current_offset += data_size;
            if !ret {
                self.clear();
                return false;
            }

            ret = self.process_all(p, policy, this, &mut *ff, env, counts);
        }
        // C: `else if ((current_offset < context->get_file_size()) &&
        // (current_offset < offset)) { add(p, file_data, data_size,
        // offset); return 1; }` (the backlog arm; a segment-armed
        // FileSegments pointer is what segments_queued() reads)
        else if self.current_offset < this.borrow().info.get_file_size()
            && self.current_offset < offset
        {
            self.add(p, file_data, data_size as i64, offset, env);
            return true;
        }

        ret
    }
}
