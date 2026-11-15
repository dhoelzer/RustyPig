// Port of snort3 hash/hash_defs.h: HASH_* constants (re-exported from
// hash_key_operations) and the HashNode layout.
#![allow(dead_code)]

/// C `class HashNode`. In C these are raw pointers into one allocation; the
/// Rust port uses arena indices (see XHash::nodes). `data` is an opaque
/// index into the owner's payload arena (C `void*`).
#[derive(Clone, Debug)]
pub struct XHashNode {
    /// lru or free node list links
    pub gnext: Option<usize>,
    pub gprev: Option<usize>,
    /// hash row node list links
    pub next: Option<usize>,
    pub prev: Option<usize>,
    pub key: Vec<u8>,
    pub data: usize,
    pub rindex: usize,
}

impl XHashNode {
    pub fn new() -> XHashNode {
        // C nodes arrive zeroed from snort_calloc.
        XHashNode {
            gnext: None,
            gprev: None,
            next: None,
            prev: None,
            key: Vec::new(),
            data: 0,
            rindex: 0,
        }
    }
}

impl Default for XHashNode {
    fn default() -> Self {
        XHashNode::new()
    }
}

/// sizeof(HashNode) on x86-64: 6 pointers + int rindex padded to 8-alignment.
/// Pinned because MemCapAllocator sizing (and therefore memcap-driven test
/// math) depends on it.
pub const SIZEOF_HASH_NODE: u64 = 56;
