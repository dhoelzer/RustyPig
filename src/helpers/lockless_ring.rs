// Port of snort3 helpers/lockless_ring.h (Copyright (C) 2014-2026 Cisco).
//
// Same SPSC/MPMC MPMC ring as C: head/tail are free-running u32 counters
// claimed with fetch_add (push/pop) or CAS (try_push/try_pop); each slot
// has a EMPTY/STORING/STORED/LOADING status state machine guarding the
// payload. Rust port keeps the identical algorithm; UnsafeCell + the same
// CAS protocol replaces std::atomic<SlotStatus> + raw data, and UnsafeCell
// reads/writes sit between the acquire CAS and the release store exactly
// as in C. USE_MOVE_TO_DEQUEUE is kept as a parameter for parity; both C
// branches move in Rust, so it is inert (see KNOWN DEVIATIONS.md).

#![allow(dead_code)]

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering::Relaxed};

pub fn round_up_to_power_of_2(n: u32) -> u32 {
    let mut n = n.wrapping_sub(1);
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n.wrapping_add(1)
}

pub const SLOT_EMPTY: u8 = 0;
pub const SLOT_STORING: u8 = 1;
pub const SLOT_STORED: u8 = 2;
pub const SLOT_LOADING: u8 = 3;

pub struct Slot<T> {
    pub status: AtomicU8,
    pub data: UnsafeCell<T>,
}

impl<T: Default> Slot<T> {
    fn new() -> Self {
        Slot {
            status: AtomicU8::new(SLOT_EMPTY),
            data: UnsafeCell::new(T::default()),
        }
    }
}

// Safety: concurrent access to a slot's data is only ever performed by
// the thread that won the status CAS (EMPTY->STORING for writers,
// STORED->LOADING for readers); the acquire on the winning CAS and the
// release on the status store order the payload accesses, mirroring the
// C implementation's memory protocol.
unsafe impl<T: Send> Send for Slot<T> {}
unsafe impl<T: Send> Sync for Slot<T> {}

pub struct LocklessRing<T: Default, const USE_MOVE_TO_DEQUEUE: bool = true> {
    buf_cap: u32,
    buffer: Vec<Slot<T>>,
    head_index: AtomicU32,
    tail_index: AtomicU32,
}

impl<T: Default, const MOVE: bool> LocklessRing<T, MOVE> {
    pub fn new(capacity: usize) -> Self {
        let buf_cap = round_up_to_power_of_2(capacity as u32);
        let buffer = (0..buf_cap).map(|_| Slot::new()).collect();
        LocklessRing {
            buf_cap,
            buffer,
            head_index: AtomicU32::new(0),
            tail_index: AtomicU32::new(0),
        }
    }

    fn do_push(&self, item: T, slot_idx: usize) {
        let slot = &self.buffer[slot_idx];
        loop {
            let acquire = std::sync::atomic::Ordering::Acquire;
            let expected = SLOT_EMPTY;
            if slot
                .status
                .compare_exchange_weak(expected, SLOT_STORING, acquire, Relaxed)
                .is_ok()
            {
                // Safety: only the CAS winner touches data between STORING
                // and STORED, exactly as C.
                unsafe { *slot.data.get() = item };
                slot.status.store(SLOT_STORED, std::sync::atomic::Ordering::Release);
                return;
            }
        }
    }

    fn do_pop(&self, slot_idx: usize) -> T {
        let slot = &self.buffer[slot_idx];
        loop {
            let acquire = std::sync::atomic::Ordering::Acquire;
            let expected = SLOT_STORED;
            if slot
                .status
                .compare_exchange_weak(expected, SLOT_LOADING, acquire, Relaxed)
                .is_ok()
            {
                // Safety: the acquire CAS above guarantees the writer's
                // data store is visible; we are the only LOADING holder.
                let item = unsafe { std::ptr::read(slot.data.get()) };
                slot.status.store(SLOT_EMPTY, std::sync::atomic::Ordering::Release);
                return item;
            }
        }
    }

    pub fn push(&self, item: T) {
        let current_head = self.head_index.fetch_add(1, Relaxed);
        self.do_push(item, (current_head & (self.buf_cap - 1)) as usize);
    }

    pub fn try_push(&self, item: T) -> bool {
        let mut current_head_index = self.head_index.load(Relaxed);
        loop {
            if (current_head_index.wrapping_sub(self.tail_index.load(Relaxed)) as i32)
                >= self.buf_cap as i32
            {
                return false; // Buffer is full
            }
            match self.head_index.compare_exchange_weak(
                current_head_index,
                current_head_index + 1,
                Relaxed,
                Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_head_index = actual,
            }
        }
        self.do_push(item, (current_head_index & (self.buf_cap - 1)) as usize);
        true
    }

    pub fn pop(&self) -> T {
        let current_tail = self.tail_index.fetch_add(1, Relaxed);
        self.do_pop((current_tail & (self.buf_cap - 1)) as usize)
    }

    pub fn try_pop(&self) -> Option<T> {
        let mut current_tail_index = self.tail_index.load(Relaxed);
        loop {
            if (self.head_index.load(Relaxed).wrapping_sub(current_tail_index) as i32) <= 0 {
                return None; // Buffer is empty
            }
            match self.tail_index.compare_exchange_weak(
                current_tail_index,
                current_tail_index + 1,
                Relaxed,
                Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_tail_index = actual,
            }
        }
        Some(self.do_pop((current_tail_index & (self.buf_cap - 1)) as usize))
    }

    /// approximate size (C wraps UINT32_MAX the same way)
    pub fn size(&self) -> u32 {
        let head_pos = self.head_index.load(Relaxed);
        let tail_pos = self.tail_index.load(Relaxed);
        if head_pos >= tail_pos {
            head_pos - tail_pos
        } else {
            // C quirk preserved verbatim: head_pos + (UINT32_MAX - tail_pos),
            // which is 1 less than the true wrapping difference
            head_pos.wrapping_add(u32::MAX - tail_pos)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// C get_buffer(): returns the slot array and the masked tail index;
    /// ring2 uses this for in-place batch draining.
    pub fn get_buffer(&self) -> (&[Slot<T>], u32) {
        let cur_tail = self.tail_index.load(Relaxed) & (self.buf_cap - 1);
        (&self.buffer, cur_tail)
    }

    pub fn reset(&self) {
        self.head_index.store(0, Relaxed);
        self.tail_index.store(0, Relaxed);
        for slot in &self.buffer {
            slot.status.store(SLOT_EMPTY, Relaxed);
        }
    }
}
