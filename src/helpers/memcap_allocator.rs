// Port of snort3 helpers/memcap_allocator.h (header-only class).
#![allow(dead_code)]

pub type PegCount = u64;

/// MemCapAllocator: fixed-size block accounting with an optional cap.
#[derive(Clone, Debug)]
pub struct MemCapAllocator {
    mem_capacity: u64,
    allocation_size: u64,
    mem_allocated: u64,
    allocation_requests: PegCount,
    free_requests: PegCount,
    no_memory_available: PegCount,
}

impl MemCapAllocator {
    pub fn new(capacity: u64, allocation_size: u64) -> MemCapAllocator {
        MemCapAllocator {
            mem_capacity: capacity,
            allocation_size,
            mem_allocated: 0,
            allocation_requests: 0,
            free_requests: 0,
            no_memory_available: 0,
        }
    }

    /// C allocate(): calloc on success; returns Option here (C nullptr).
    pub fn allocate(&mut self) -> bool {
        if self.is_space_available() {
            self.mem_allocated += self.allocation_size;
            self.allocation_requests += 1;
            true
        } else {
            self.no_memory_available += 1;
            false
        }
    }

    pub fn free_(&mut self) {
        // C free(mem): snort_free then unconditional decrement (even if the
        // pointer wasn't from this allocator — kept as unconditional).
        self.mem_allocated = self.mem_allocated.saturating_sub(self.allocation_size);
        self.free_requests += 1;
    }

    pub fn is_space_available(&self) -> bool {
        if self.mem_capacity == 0 {
            true
        } else {
            self.mem_allocated + self.allocation_size <= self.mem_capacity
        }
    }

    pub fn is_over_capacity(&self) -> bool {
        if self.mem_capacity == 0 {
            false
        } else {
            self.mem_allocated > self.mem_capacity
        }
    }

    pub fn set_mem_capacity(&mut self, capacity: u64) {
        self.mem_capacity = capacity;
    }
    pub fn get_mem_capacity(&self) -> u64 {
        self.mem_capacity
    }
    pub fn get_allocation_size(&self) -> u64 {
        self.allocation_size
    }
    pub fn get_mem_allocated(&self) -> u64 {
        self.mem_allocated
    }
    pub fn get_allocation_requests(&self) -> PegCount {
        self.allocation_requests
    }
    pub fn get_free_requests(&self) -> PegCount {
        self.free_requests
    }
    pub fn get_no_memory_available(&self) -> PegCount {
        self.no_memory_available
    }
}
