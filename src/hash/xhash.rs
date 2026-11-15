// Port of snort3 hash/xhash.{h,cc}: generic key->data hash table with memcap
// accounting, free-list node recycling and ANR (automatic node recovery) via
// the LRU caches.
//
// C++ manages HashNode* raw pointers; this port uses an index arena
// (nodes: Vec<XHashNode>) with the same link/cursor update order. The C
// `void* data` becomes an opaque `usize` payload handle (user-managed, like
// the C++ tests' `unsigned* data`); see KNOWN DEVIATIONS.md.
#![allow(dead_code)]

use super::hash_defs::{XHashNode, SIZEOF_HASH_NODE};
use super::hash_key_operations::{
    hash_nearest_power_of_2, HashKeyOperations, HASH_INTABLE, HASH_NOMEM, HASH_NOT_FOUND,
    HASH_OK, HASH_PENDING,
};
use super::hash_lru_cache::HashLruCache;
use crate::helpers::memcap_allocator::MemCapAllocator;

// Bound the walk so a fully-pinned cache is not re-scanned end-to-end each
// insert (XHASH_MAX_RECOVERY_WALK).
const XHASH_MAX_RECOVERY_WALK: u32 = 64;

/// C++ `HashKeyOperations` virtual do_hash: the xhash family dispatches
/// through a subclass per key type (plain jenkins, flow mix, test stubs).
pub trait HashOps {
    fn do_hash(&self, key: &[u8]) -> u32;
}
impl HashOps for HashKeyOperations {
    fn do_hash(&self, key: &[u8]) -> u32 {
        HashKeyOperations::do_hash(self, key)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XHashStats {
    pub memcap_prunes: u64,
    pub memcap_deletes: u64,
    pub release_recycles: u64,
    pub release_deletes: u64,
}

pub struct XHash {
    pub nrows: u32,
    pub keysize: u32,
    pub num_nodes: u32,
    pub num_free_nodes: u32,
    pub recycle_nodes: bool,
    pub anr_enabled: bool,
    pub num_lru_caches: u8,

    // protected in C
    pub mem_allocator: MemCapAllocator,
    pub lru_caches: Vec<HashLruCache>,

    // private in C (exposed here for the arena model)
    pub(crate) nodes: Vec<XHashNode>,
    pub table: Vec<Option<usize>>,
    pub hashkey_ops: Box<dyn HashOps>,
    pub cursor: Option<usize>,
    pub fhead: Option<usize>,
    pub lfind: Option<usize>,
    pub datasize: u32,
    pub mem_cap: u64,
    pub max_nodes: u32,
    pub crow: u32,
    pub stats: XHashStats,

    // C virtual hooks (is_node_recovery_ok / free_user_data) become
    // overridable state carried by ported subclasses.
    pub pinned_keys: Vec<Vec<u8>>,

    // C initializes table only in the 4-arg ctor; the 3-arg one leaves it
    // null. Modeled with an explicit flag.
    pub initialized: bool,
}

impl XHash {
    /// C `XHash(int rows, int keysize, uint8_t num_lru_caches)` — no table.
    pub fn new_uninitialized(rows: i32, keysize: u32, num_lru_caches: u8) -> XHash {
        XHash::base(rows, keysize, 0, 0, num_lru_caches, false)
    }

    /// C `XHash(int rows, int keysize, int datasize, unsigned long memcap,
    /// uint8_t num_lru_caches)`.
    pub fn new(
        rows: i32,
        keysize: u32,
        datasize: u32,
        memcap: u64,
        num_lru_caches: u8,
    ) -> XHash {
        assert!(num_lru_caches > 0);
        let mut x = XHash::base(rows, keysize, datasize, memcap, num_lru_caches, true);
        x.initialize();
        x
    }

    fn base(
        rows: i32,
        keysize: u32,
        datasize: u32,
        memcap: u64,
        num_lru_caches: u8,
        init: bool,
    ) -> XHash {
        let mut nrows = if rows > 0 {
            hash_nearest_power_of_2(rows)
        } else {
            -rows
        };
        if nrows < 0 {
            nrows = 0; // rows == i32::MIN guard; C is UB there.
        }
        XHash {
            nrows: nrows as u32,
            keysize,
            num_nodes: 0,
            num_free_nodes: 0,
            recycle_nodes: true,
            anr_enabled: true,
            num_lru_caches,
            mem_allocator: MemCapAllocator::new(
                memcap,
                SIZEOF_HASH_NODE + keysize as u64 + datasize as u64,
            ),
            lru_caches: (0..num_lru_caches).map(|_| HashLruCache::new()).collect(),
            nodes: Vec::new(),
            table: if init {
                vec![None; nrows as usize]
            } else {
                Vec::new()
            },
            hashkey_ops: Box::new(HashKeyOperations::new(nrows, true)),
            cursor: None,
            fhead: None,
            lfind: None,
            datasize,
            mem_cap: memcap,
            max_nodes: 0,
            crow: 0,
            stats: XHashStats::default(),
            pinned_keys: Vec::new(),
            initialized: init,
        }
    }

    pub fn initialize(&mut self) {
        self.initialize_with_ops(Box::new(HashKeyOperations::new(self.nrows as i32, true)));
    }

    /// C initialize(HashKeyOperations*): also (re)allocates the table and
    /// lru caches exactly like C (lru_caches.resize + new per entry).
    pub fn initialize_with_ops(&mut self, ops: Box<dyn HashOps>) {
        self.hashkey_ops = ops;
        self.table = vec![None; self.nrows as usize];
        self.lru_caches = (0..self.num_lru_caches).map(|_| HashLruCache::new()).collect();
        self.initialized = true;
    }

    pub fn set_max_nodes(&mut self, max: u32) {
        self.max_nodes = max;
    }

    pub fn set_memcap(&mut self, memcap: u64) {
        self.mem_allocator.set_mem_capacity(memcap);
    }
    pub fn get_memcap(&self) -> u64 {
        self.mem_allocator.get_mem_capacity()
    }
    pub fn get_mem_used(&self) -> u64 {
        self.mem_allocator.get_mem_allocated()
    }
    pub fn get_num_nodes(&mut self) -> u32 {
        self.num_nodes
    }
    pub fn get_num_free_nodes(&mut self) -> u32 {
        self.num_free_nodes
    }
    pub fn get_stats(&self) -> XHashStats {
        self.stats
    }

    /// C `bool full() const { return !fhead; }` — quirk: "full" means the
    /// free list is empty, not the table.
    pub fn full(&self) -> bool {
        self.fhead.is_none()
    }

    /// Recovery gate: C `virtual is_node_recovery_ok()` returns true unless a
    /// ported subclass pins node keys (mirrors selective_pinned_xhash).
    fn is_node_recovery_ok(&self, hnode: usize) -> bool {
        !self.pinned_keys.iter().any(|k| *k == self.nodes[hnode].key)
    }

    fn free_user_data(&mut self, _hnode: usize) {
        // C virtual default: no-op. Payload is user-managed (arena), like
        // the C++ tests' manual `delete (unsigned*)node->data`.
    }

    pub fn insert(&mut self, key: &[u8], payload: usize) -> i32 {
        assert!(key.len() == self.keysize as usize);
        let mut index = 0usize;
        let found = self.find_node_row(key, &mut index, 0, true);
        if let Some(n) = found {
            self.cursor = Some(n);
            return HASH_INTABLE;
        }
        let hnode = self.allocate_node(key, payload, index);
        self.cursor = hnode;
        if hnode.is_some() {
            HASH_OK
        } else {
            HASH_NOMEM
        }
    }

    pub fn find_node(&mut self, key: &[u8]) -> Option<usize> {
        let mut rindex = 0usize;
        self.find_node_row(key, &mut rindex, 0, true)
    }

    fn find_node_row(
        &mut self,
        key: &[u8],
        rindex: &mut usize,
        typ: u8,
        touch: bool,
    ) -> Option<usize> {
        assert!((typ as u32) < self.num_lru_caches as u32);
        let hashkey = self.hashkey_ops.do_hash(key);
        *rindex = HashKeyOperations::get_row(hashkey, self.nrows) as usize;
        let mut hnode = self.table.get(*rindex).copied().flatten();
        while let Some(n) = hnode {
            if self.nodes[n].key == key {
                self.lfind = Some(n);
                if touch {
                    self.move_to_front(n, typ);
                }
                return Some(n);
            }
            hnode = self.nodes[n].next;
        }
        None
    }

    fn allocate_node(&mut self, key: &[u8], payload: usize, index: usize) -> Option<usize> {
        // use a free one if available...
        let mut hnode = self.get_free_node();

        // if no free nodes, try to allocate a new one...
        if hnode.is_none() && (self.max_nodes == 0 || self.num_nodes < self.max_nodes) {
            hnode = self.alloc_node_mem();
        }

        // if still no node then try to reuse one...
        if hnode.is_none() && self.anr_enabled {
            hnode = self.release_lru_node(0);
        }

        if let Some(n) = hnode {
            self.initialize_node(n, key, payload, index, 0);
            self.num_nodes += 1;
        }
        hnode
    }

    // ---- used by the ZHash subclass (C++ protected access) ----
    pub(crate) fn find_node_row_pub(&mut self, key: &[u8], rindex: &mut usize) -> Option<usize> {
        self.find_node_row(key, rindex, 0, true)
    }
    pub(crate) fn link_node_pub(&mut self, hnode: usize) {
        self.link_node(hnode)
    }
    pub(crate) fn unlink_node_pub(&mut self, hnode: usize) {
        self.unlink_node(hnode)
    }
    pub(crate) fn get_free_node_pub(&mut self) -> Option<usize> {
        self.get_free_node()
    }
    pub(crate) fn save_free_node_pub(&mut self, hnode: usize) {
        self.save_free_node(hnode)
    }
    pub(crate) fn free_node_mem_pub(&mut self, hnode: usize) {
        self.free_node_mem(hnode)
    }

    fn alloc_node_mem(&mut self) -> Option<usize> {
        if !self.mem_allocator.allocate() {
            return None;
        }
        self.nodes.push(XHashNode {
            key: vec![0u8; self.keysize as usize],
            data: 0,
            ..Default::default()
        });
        Some(self.nodes.len() - 1)
    }

    fn initialize_node(&mut self, hnode: usize, key: &[u8], payload: usize, index: usize, typ: u8) {
        assert!((typ as u32) < self.num_lru_caches as u32);
        self.nodes[hnode].key.clear();
        self.nodes[hnode].key.extend_from_slice(key);
        // C memcpy's the inline datasize blob when datasize > 0 and data !=
        // null; the port stores the payload handle in both cases (deviation).
        self.nodes[hnode].data = payload;
        self.nodes[hnode].rindex = index;
        self.link_node(hnode);
        self.lru_caches[typ as usize].insert(&mut self.nodes, hnode);
    }

    fn link_node(&mut self, hnode: usize) {
        let rindex = self.nodes[hnode].rindex;
        if let Some(head) = self.table[rindex] {
            self.nodes[hnode].prev = None;
            self.nodes[hnode].next = Some(head);
            self.nodes[head].prev = Some(hnode);
            self.table[rindex] = Some(hnode);
        } else {
            self.nodes[hnode].prev = None;
            self.nodes[hnode].next = None;
            self.table[rindex] = Some(hnode);
        }
    }

    fn unlink_node(&mut self, hnode: usize) {
        let rindex = self.nodes[hnode].rindex;
        let prev = self.nodes[hnode].prev;
        let next = self.nodes[hnode].next;
        if let Some(p) = prev {
            self.nodes[p].next = next;
            if let Some(x) = next {
                self.nodes[x].prev = prev;
            }
        } else if let Some(head) = self.table[rindex] {
            self.table[rindex] = self.nodes[head].next;
            if let Some(x) = self.table[rindex] {
                self.nodes[x].prev = None;
            }
        }
    }

    fn move_to_front(&mut self, node: usize, typ: u8) {
        let rindex = self.nodes[node].rindex;
        if self.table[rindex] != Some(node) {
            self.unlink_node(node);
            self.link_node(node);
        }
        self.lru_caches[typ as usize].touch(&mut self.nodes, node);
    }

    pub fn touch_last_found(&mut self, typ: u8) {
        assert!((typ as u32) < self.num_lru_caches as u32);
        if let Some(n) = self.lfind {
            self.move_to_front(n, typ);
        }
    }

    pub fn get_user_data(&mut self, key: &[u8], typ: u8, touch: bool) -> Option<usize> {
        assert!((typ as u32) < self.num_lru_caches as u32);
        let mut rindex = 0usize;
        let hnode = self.find_node_row(key, &mut rindex, typ, touch);
        hnode.map(|n| self.nodes[n].data)
    }

    /// payload of the node under the find_first/find_next cursor.
    pub fn get_user_data_cursor(&self) -> Option<usize> {
        self.cursor.map(|c| self.nodes[c].data)
    }

    pub fn find_first_node(&mut self) -> Option<usize> {
        for crow in 0..self.nrows {
            self.cursor = self.table[crow as usize];
            if self.cursor.is_some() {
                let n = self.cursor;
                self.update_cursor();
                return n;
            }
        }
        None
    }

    pub fn find_next_node(&mut self) -> Option<usize> {
        let n = self.cursor?;
        self.update_cursor();
        Some(n)
    }

    fn update_cursor(&mut self) {
        if let Some(c) = self.cursor {
            self.cursor = self.nodes[c].next;
            if self.cursor.is_some() {
                return;
            }
        } else {
            return;
        }
        self.crow += 1;
        while self.crow < self.nrows {
            self.cursor = self.table[self.crow as usize];
            if self.cursor.is_some() {
                return;
            }
            self.crow += 1;
        }
    }

    pub fn release(&mut self, typ: u8) {
        assert!((typ as u32) < self.num_lru_caches as u32);
        let node = self.lru_caches[typ as usize].get_current_node();
        assert!(node.is_some());
        self.release_node_handle(node.unwrap(), typ);
    }

    pub fn release_node_key(&mut self, key: &[u8], typ: u8) -> i32 {
        assert!((typ as u32) < self.num_lru_caches as u32);
        let hashkey = self.hashkey_ops.do_hash(key);
        let index = HashKeyOperations::get_row(hashkey, self.nrows) as usize;
        let mut hnode = self.table[index];
        while let Some(n) = hnode {
            if self.nodes[n].key == key {
                self.release_node_handle(n, typ);
                return HASH_OK;
            }
            hnode = self.nodes[n].next;
        }
        HASH_NOT_FOUND
    }

    pub fn release_node_handle(&mut self, hnode: usize, typ: u8) -> i32 {
        assert!((typ as u32) < self.num_lru_caches as u32);
        self.free_user_data(hnode);
        self.unlink_node(hnode);
        self.lru_caches[typ as usize].remove_node(&mut self.nodes, hnode);
        self.num_nodes -= 1;

        if self.recycle_nodes {
            self.save_free_node(hnode);
            self.stats.release_recycles += 1;
        } else {
            self.free_node_mem(hnode);
            self.stats.release_deletes += 1;
        }
        HASH_OK
    }

    fn free_node_mem(&mut self, _hnode: usize) {
        // C mem_allocator->free(node): decrement accounting and free.
        // The arena slot stays (recycled slots re-enter via free list only
        // when recycling; the Rust arena never reuses *slots*, only the
        // allocator accounting is decremented as in C).
        self.mem_allocator.free_();
    }

    fn save_free_node(&mut self, hnode: usize) {
        if let Some(fh) = self.fhead {
            self.nodes[hnode].gprev = None;
            self.nodes[hnode].gnext = Some(fh);
            self.nodes[fh].gprev = Some(hnode);
            self.fhead = Some(hnode);
        } else {
            self.nodes[hnode].gprev = None;
            self.nodes[hnode].gnext = None;
            self.fhead = Some(hnode);
        }
        self.num_free_nodes += 1;
    }

    fn get_free_node(&mut self) -> Option<usize> {
        let node = self.fhead;
        if let Some(fh) = self.fhead {
            self.fhead = self.nodes[fh].gnext;
            if let Some(nh) = self.fhead {
                self.nodes[nh].gprev = None;
            }
            self.num_free_nodes -= 1;
        }
        node
    }

    fn delete_free_node(&mut self) -> bool {
        let hnode = self.get_free_node();
        if let Some(n) = hnode {
            self.free_node_mem(n);
            true
        } else {
            false
        }
    }

    fn purge_free_list(&mut self) {
        let mut cur = self.fhead;
        while let Some(c) = cur {
            let next = self.nodes[c].gnext;
            self.free_node_mem(c);
            cur = next;
        }
        self.fhead = None;
        self.num_free_nodes = 0;
    }

    pub fn clear_hash(&mut self) {
        for i in 0..self.nrows as usize {
            let mut node = self.table[i];
            while let Some(xnode) = node {
                node = self.nodes[xnode].next;
                self.release_node_handle(xnode, 0);
            }
        }
        self.max_nodes = 0;
        self.num_nodes = 0;
        self.crow = 0;
        self.cursor = None;
    }

    pub fn get_mru_user_data(&self, typ: u8) -> Option<usize> {
        self.lru_caches[typ as usize].get_mru_user_data(&self.nodes)
    }
    pub fn get_lru_user_data(&self, typ: u8) -> Option<usize> {
        self.lru_caches[typ as usize].get_lru_user_data(&self.nodes)
    }
    pub fn get_walk_user_data(&mut self, typ: u8) -> Option<usize> {
        let walk_node = self.lru_caches[typ as usize].get_walk_node(&self.nodes);
        walk_node.map(|n| self.nodes[n].data)
    }
    pub fn get_next_walk_user_data(&mut self, typ: u8) -> Option<usize> {
        let walk_node = self.lru_caches[typ as usize].get_next_walk_node(&self.nodes);
        walk_node.map(|n| self.nodes[n].data)
    }

    /// C: returns the recycled node when a recovery-ok node is found within
    /// the bounded walk from the LRU tail.
    fn release_lru_node(&mut self, typ: u8) -> Option<usize> {
        let mut hnode = self.lru_caches[typ as usize].get_lru_node();
        let mut candidates = 0u32;
        while let Some(n) = hnode {
            if candidates >= XHASH_MAX_RECOVERY_WALK {
                break;
            }
            if self.is_node_recovery_ok(n) {
                self.lru_caches[typ as usize].remove_node(&mut self.nodes, n);
                self.free_user_data(n);
                self.unlink_node(n);
                self.num_nodes -= 1;
                self.stats.memcap_prunes += 1;
                return Some(n);
            }
            hnode = self.lru_caches[typ as usize].get_next_lru_node(&self.nodes);
            candidates += 1;
        }
        None
    }

    fn switch_node_lru_cache(&mut self, hnode: usize, old_type: u8, new_type: u8) {
        self.lru_caches[old_type as usize].remove_node(&mut self.nodes, hnode);
        self.lru_caches[new_type as usize].insert(&mut self.nodes, hnode);
    }

    pub fn switch_lru_cache(&mut self, key: &[u8], old_type: u8, new_type: u8) -> bool {
        assert!((old_type as u32) < self.num_lru_caches as u32);
        assert!((new_type as u32) < self.num_lru_caches as u32);
        let mut rindex = 0usize;
        let hnode = self.find_node_row(key, &mut rindex, old_type, true);
        if let Some(n) = hnode {
            self.switch_node_lru_cache(n, old_type, new_type);
            true
        } else {
            false
        }
    }

    pub fn delete_lru_node(&mut self, typ: u8) -> bool {
        assert!((typ as u32) < self.num_lru_caches as u32);
        let hnode = self.lru_caches[typ as usize].remove_lru_node(&mut self.nodes);
        if let Some(n) = hnode {
            self.unlink_node(n);
            self.free_user_data(n);
            self.free_node_mem(n);
            self.num_nodes -= 1;
            true
        } else {
            false
        }
    }

    fn delete_a_node(&mut self) -> bool {
        if self.delete_free_node() {
            return true;
        }
        self.delete_lru_node(0)
    }

    pub fn tune_memory_resources(&mut self, work_limit: u32, num_freed: &mut u32) -> i32 {
        let mut work = work_limit;
        while work > 0 && self.mem_allocator.is_over_capacity() {
            work -= 1;
            if !self.delete_a_node() {
                break;
            }
            self.stats.memcap_deletes += 1;
            *num_freed += 1;
        }
        if self.mem_allocator.is_over_capacity() {
            HASH_PENDING
        } else {
            HASH_OK
        }
    }
}
