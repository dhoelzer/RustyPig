// Port of snort3 helpers/ring2.h (Copyright (C) 2024-2026 Cisco).
//
// SPSC byte-ring of length-prefixed records; identical cursor protocol:
// Writer/Reader hold (cursor, guard, turn flag) snapshots and publish
// with a release store; LEN_TYPE = uint32_t. Rust uses UnsafeCell for the
// store and usize offsets instead of raw uint8_t*; the single-writer /
// single-reader safety contract is the same as C's (see KNOWN DEVIATIONS.md).

#![allow(dead_code)]

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub const LEN_SIZE: usize = 4; // sizeof(LEN_TYPE) = sizeof(uint32_t)

// Safety: payload bytes in the region exclusively owned by the current
// writer (write_ptr..cursor) or reader (read_ptr..cursor) are only touched
// by that one thread; publication/turn decisions go through the atomics.
pub struct Ring2 {
    store: UnsafeCell<Vec<u8>>,
    store_len: usize,
    write_ptr: AtomicUsize,
    read_ptr: AtomicUsize,
}

unsafe impl Send for Ring2 {}
unsafe impl Sync for Ring2 {}

impl Ring2 {
    pub fn new(buffer_size: usize) -> Self {
        Ring2 {
            store: UnsafeCell::new(vec![0u8; buffer_size]),
            store_len: buffer_size,
            write_ptr: AtomicUsize::new(0),
            read_ptr: AtomicUsize::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.store_len
    }

    pub fn empty(&self) -> bool {
        self.write_ptr.load(Ordering::Acquire) == self.read_ptr.load(Ordering::Acquire)
    }

    pub fn clear(&self) {
        self.write_ptr.store(0, Ordering::Relaxed);
        self.read_ptr.store(0, Ordering::Relaxed);
    }

    /// C writer(): no_wrapping when the reader sits ahead of the writer
    /// (gap to fill), guard = reader pos; else guard = store end.
    pub fn writer(&self) -> Writer<'_> {
        let w = self.write_ptr.load(Ordering::Acquire);
        let r = self.read_ptr.load(Ordering::Acquire);
        let no_wrapping = w < r;
        let guard = if no_wrapping { r } else { self.store_len };
        Writer {
            ptr: w,
            end: guard,
            store: self,
            no_turns: no_wrapping,
        }
    }

    pub fn reader(&self) -> Reader<'_> {
        let w = self.write_ptr.load(Ordering::Acquire);
        let r = self.read_ptr.load(Ordering::Acquire);
        let wrapping = r > w;
        let guard = if wrapping { self.store_len } else { w };
        Reader {
            ptr: r,
            end: guard,
            store: self,
            more_turns: wrapping,
        }
    }

    fn memcpy_out(&self, at: usize, data: &[u8]) {
        // Safety: single-writer region contract (mirrors C memcpy into the
        // un-published tail region).
        // raw-pointer access like the C memcpy: no references over the
        // shared store, so the writer/reader threads never alias.
        unsafe {
            let buf = self.store.get();
            let src = data.as_ptr();
            std::ptr::copy_nonoverlapping(src, (*buf).as_mut_ptr().add(at), data.len());
        }
    }

    fn read_u32(&self, at: usize) -> u32 {
        // Safety: single-reader region contract.
        unsafe {
            let buf = self.store.get();
            let p = (*buf).as_ptr().add(at);
            let mut b = [0u8; 4];
            std::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 4);
            u32::from_le_bytes(b)
        }
    }

    fn read_bytes(&self, at: usize, len: usize) -> Vec<u8> {
        // Safety: single-reader region contract. C hands the caller a
        // borrowed pointer valid until pop(); copying matches everything
        // the tests observe (memcmp of the record).
        unsafe {
            let buf = self.store.get();
            let p = (*buf).as_ptr().add(at);
            std::slice::from_raw_parts(p, len).to_vec()
        }
    }

    pub fn write_ptr(&self) -> usize {
        self.write_ptr.load(Ordering::Relaxed)
    }
    pub fn read_ptr(&self) -> usize {
        self.read_ptr.load(Ordering::Relaxed)
    }

    /// test helper matching the C test's std::this_thread::sleep_for(2ms)
    /// + relaxed loads busy_wait()
    pub fn busy_wait(&self) {
        Ring2::sleep(2);
        let _ = self.write_ptr();
        let _ = self.read_ptr();
        if self.empty() {
            let _ = self.write_ptr();
        }
    }

    pub fn sleep(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

pub struct Writer<'a> {
    ptr: usize,
    end: usize,
    store: &'a Ring2,
    no_turns: bool,
}

impl Writer<'_> {
    pub fn cursor(&self) -> usize {
        self.ptr
    }
    pub fn guard(&self) -> usize {
        self.end
    }
    pub fn no_turns(&self) -> bool {
        self.no_turns
    }
    pub fn is_native(&self) -> bool {
        true // single Ring2 owner in Rust (C pointer identity check)
    }

    /// C Ring2::Writer::write probe path for lengths only: C validates
    /// data_len (0 and oversized) BEFORE dereferencing the data pointer,
    /// so the "Oversized record" Catch case (usize::MAX/2-sized length over
    /// a 1-byte literal) is observable without a 4GB slice. Same result
    /// as C for every reachable length.
    pub fn write(&mut self, data: &[u8]) -> bool {
        let n = data.len();
        self.write_with_len(data, n)
    }

    /// C Ring2::Writer::write(nullptr-equivalent, huge_len) probe path.
    pub fn write_len_check(&mut self, data_len: usize) -> bool {
        self.write_with_len(&[], data_len)
    }

    fn write_with_len(&mut self, data: &[u8], data_len: usize) -> bool {
        if data_len == 0 {
            return false; // empty records are not allowed
        }
        if data_len > u32::MAX as usize {
            return false;
        }
        debug_assert!(data.len() == data_len || data.is_empty());

        let available = self.end - self.ptr;
        if available > LEN_SIZE && data_len < available - LEN_SIZE {
            // normal case
            self.store.memcpy_out(self.ptr, &(data_len as u32).to_le_bytes());
            self.store.memcpy_out(self.ptr + LEN_SIZE, data);
            self.ptr += LEN_SIZE + data_len;
            return true;
        } else if self.no_turns {
            return false; // overflow
        }

        // wrapping case
        let zero_record = available >= LEN_SIZE;
        let ptr_orig = self.ptr;
        let end_orig = self.end;

        self.no_turns = true;
        self.ptr = 0;
        self.end = self.store.read_ptr.load(Ordering::Acquire);

        let res = self.ptr != self.end && self.write_with_len(data, data_len);

        if res {
            if zero_record {
                self.store.memcpy_out(ptr_orig, &0u32.to_le_bytes());
            }
        } else {
            self.no_turns = false;
            self.ptr = ptr_orig;
            self.end = end_orig;
        }
        res
    }

    pub fn retry(&mut self) {
        *self = self.store.writer();
    }

    pub fn push(&self) {
        self.store.write_ptr.store(self.ptr, Ordering::Release);
    }
}

pub struct Reader<'a> {
    ptr: usize,
    end: usize,
    store: &'a Ring2,
    more_turns: bool,
}

impl Reader<'_> {
    pub fn cursor(&self) -> usize {
        self.ptr
    }
    pub fn guard(&self) -> usize {
        self.end
    }
    pub fn more_turns(&self) -> bool {
        self.more_turns
    }

    /// C Ring2::Reader::read(): returns the record bytes (C returns a
    /// borrowed pointer into the store; records in the tests hold no NULs
    /// but zero_pad records ARE part of the payload, so no string ops).
    pub fn read(&mut self) -> Option<Vec<u8>> {
        let mut data_len = 0usize;

        if self.ptr + LEN_SIZE <= self.end {
            data_len = self.store.read_u32(self.ptr) as usize;
        }

        if data_len != 0 && self.ptr + LEN_SIZE + data_len <= self.end {
            // normal case
            self.ptr += LEN_SIZE;
            let start = self.ptr;
            self.ptr += data_len;
            return Some(self.store.read_bytes(start, data_len));
        } else if self.more_turns {
            // wrapping case
            self.more_turns = false;
            self.ptr = 0;
            self.end = self.store.write_ptr.load(Ordering::Acquire);
            return self.read();
        }

        // underflow (C: assert(data_len == 0); return nullptr)
        debug_assert!(data_len == 0);
        None
    }

    pub fn retry(&mut self) {
        *self = self.store.reader();
    }

    pub fn pop(&self) {
        self.store.read_ptr.store(self.ptr, Ordering::Release);
    }
}
