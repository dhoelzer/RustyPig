// Port of snort3 hash/lru_cache_shared.{h,cc}: thread-safe shared LRU cache
// over shared_ptr payloads.
//
// Deviations (audited, see KNOWN DEVIATIONS.md):
// - Data = std::shared_ptr<Value> -> Arc<RefCell<Value>> (C mutates the
//   pointee through the shared_ptr in tests; RefCell mirrors that).
// - std::mutex + public lock()/unlock() dropped: Rust's borrow checker
//   provides the same exclusivity statically; single-threaded &mut self.
// - list+iterator model -> arena ids + order Vec (front == MRU), same as
//   the lru_cache_local port.
// - stats quirk preserved: bytes_in_use and items_in_use are NEVER updated
//   by this class (only derived caches do); they read 0 and the C++ suite
//   pins exactly that.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub type Data<V> = Rc<RefCell<V>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LcsInsertStatus {
    LcsItemPresent,
    LcsItemInserted,
    LcsItemReplaced,
}

/// Field ORDER IS LOAD-BEARING: C get_counts() reinterprets the struct as a
/// PegCount array in peg-name order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LruCacheSharedStats {
    pub adds: u64,
    pub alloc_prunes: u64,
    pub bytes_in_use: u64,
    pub items_in_use: u64,
    pub find_hits: u64,
    pub find_misses: u64,
    pub reload_prunes: u64,
    pub removes: u64,
    pub replaced: u64,
}

/// lru_cache_shared.cc peg table (name column only; COUNT_TYPE ends the C
/// array — Rust uses a fixed slice).
pub const LRU_CACHE_SHARED_PEG_NAMES: [&str; 9] = [
    "adds",
    "alloc_prunes",
    "bytes_in_use",
    "items_in_use",
    "find_hits",
    "find_misses",
    "reload_prunes",
    "removes",
    "replaced",
];

pub struct LruCacheShared<K: std::cmp::Eq + std::hash::Hash + Clone, V: Default> {
    max_size: usize,
    current_size: usize,
    arena: Vec<Option<(K, Data<V>)>>, // front of order == MRU
    order: Vec<usize>,
    map: HashMap<K, usize>,
    stats: LruCacheSharedStats,
}

impl<K: std::cmp::Eq + std::hash::Hash + Clone, V: Default> LruCacheShared<K, V> {
    pub fn new(initial_size: usize) -> LruCacheShared<K, V> {
        LruCacheShared {
            max_size: initial_size,
            current_size: 0,
            arena: Vec::new(),
            order: Vec::new(),
            map: HashMap::new(),
            stats: LruCacheSharedStats::default(),
        }
    }

    pub fn size(&self) -> usize {
        self.order.len()
    }

    /// C mem_size() = list.size() * (sizeof(shared_ptr)+sizeof(Value));
    /// layout-dependent sizes are not observable in Rust, so this reports
    /// the item count and the deviation is documented.
    pub fn mem_size(&self) -> usize {
        self.order.len()
    }

    pub fn get_max_size(&self) -> usize {
        self.max_size
    }

    fn touch(&mut self, id: usize) {
        let pos = self.order.iter().position(|&x| x == id).unwrap();
        if pos != 0 {
            self.order.remove(pos);
            self.order.insert(0, id);
        }
    }

    /// C prune(purgatory): pruned payloads go to the caller's purgatory so
    /// their destructors run outside the lock; Rc clone = same role. Note
    /// there is NO `list.size() > 1` guard here (unlike LruCacheLocal).
    fn prune(&mut self, purgatory: &mut Vec<Data<V>>) {
        while self.current_size > self.max_size && !self.order.is_empty() {
            let id = *self.order.last().unwrap();
            self.order.pop();
            let (k, data) = self.arena[id].take().unwrap();
            purgatory.push(data); // keeps the value alive, like C++
            self.map.remove(&k);
            self.current_size -= 1;
            self.stats.alloc_prunes += 1;
        }
    }

    fn insert_front(&mut self, key: K, data: Data<V>, purgatory: &mut Vec<Data<V>>) {
        self.arena.push(Some((key.clone(), data)));
        let id = self.arena.len() - 1;
        self.order.insert(0, id);
        self.map.insert(key, id);
        self.increase_size();
        self.prune(purgatory);
    }

    fn increase_size(&mut self) {
        self.current_size += 1;
    }
    fn decrease_size(&mut self) {
        self.current_size -= 1;
    }

    pub fn find(&mut self, key: &K) -> Option<Data<V>> {
        if let Some(&id) = self.map.get(key) {
            self.stats.find_hits += 1;
            self.touch(id);
            Some(self.arena[id].as_ref().unwrap().1.clone())
        } else {
            self.stats.find_misses += 1;
            None
        }
    }

    /// C operator[].
    pub fn index_create(&mut self, key: K) -> Data<V> {
        self.find_else_create(key, None)
    }

    pub fn find_else_create(&mut self, key: K, new_data: Option<&mut bool>) -> Data<V> {
        // C comment: the lock must be held when returning the pointer so
        // other threads can't free it; Arc keeps that property structurally.
        if let Some(&id) = self.map.get(&key) {
            if let Some(nd) = new_data {
                *nd = false;
            }
            self.stats.find_hits += 1;
            self.touch(id);
            self.arena[id].as_ref().unwrap().1.clone()
        } else {
            self.stats.find_misses += 1;
            self.stats.adds += 1;
            if let Some(nd) = new_data {
                *nd = true;
            }
            let data: Data<V> = Rc::new(RefCell::new(V::default())); // C Data(new Value)
            let mut purgatory = Vec::new();
            self.insert_front(key, data.clone(), &mut purgatory);
            data
        }
    }

    /// C bool find_else_insert(key, data, replace).
    pub fn find_else_insert(&mut self, key: K, data: Data<V>, replace: bool) -> bool {
        let mut status = None;
        self.find_else_insert_status(key, data, &mut status, replace);
        matches!(status.unwrap(), LcsInsertStatus::LcsItemPresent)
    }

    /// C overload with LcsInsertStatus*.
    pub fn find_else_insert_status(
        &mut self,
        key: K,
        data: Data<V>,
        status: &mut Option<LcsInsertStatus>,
        replace: bool,
    ) -> Data<V> {
        if let Some(&id) = self.map.get(&key) {
            self.stats.find_hits += 1;
            *status = Some(LcsInsertStatus::LcsItemPresent);
            if replace {
                let old = {
                    let slot = self.arena[id].as_mut().unwrap();
                    std::mem::replace(&mut slot.1, data.clone())
                };
                self.decrease_size();
                // purgatory: old value stays alive until here, as in C
                drop(old);
                self.increase_size();
                self.stats.replaced += 1;
                *status = Some(LcsInsertStatus::LcsItemReplaced);
            }
            self.touch(id);
            self.arena[id].as_ref().unwrap().1.clone()
        } else {
            self.stats.find_misses += 1;
            self.stats.adds += 1;
            *status = Some(LcsInsertStatus::LcsItemInserted);
            let mut purgatory = Vec::new();
            self.insert_front(key, data.clone(), &mut purgatory);
            data
        }
    }

    /// MRU first. C returns copies of the shared_ptr/vector of pairs.
    pub fn get_all_data(&self) -> Vec<(K, Data<V>)> {
        self.order
            .iter()
            .map(|&id| {
                let (k, d) = self.arena[id].as_ref().unwrap();
                (k.clone(), d.clone())
            })
            .collect()
    }

    pub fn set_max_size(&mut self, newsize: usize) -> bool {
        if newsize == 0 {
            return false; // not allowed
        }
        self.max_size = newsize;
        let mut purgatory = Vec::new(); // C: lives past the lock
        self.prune(&mut purgatory);
        true
    }

    pub fn remove_simple(&mut self, key: &K, new_size: Option<&mut usize>) -> bool {
        self.remove_impl(key, None, new_size)
    }

    pub fn remove_data(
        &mut self,
        key: &K,
        data_out: &mut Option<Data<V>>,
        new_size: Option<&mut usize>,
    ) -> bool {
        self.remove_impl(key, Some(data_out), new_size)
    }

    fn remove_impl(
        &mut self,
        key: &K,
        data_out: Option<&mut Option<Data<V>>>,
        new_size: Option<&mut usize>,
    ) -> bool {
        if let Some(id) = self.map.get(key).copied() {
            let data = self.arena[id].as_ref().unwrap().1.clone();
            if let Some(o) = data_out {
                *o = Some(data.clone());
            }

            self.decrease_size();
            let pos = self.order.iter().position(|&x| x == id).unwrap();
            self.order.remove(pos);
            self.arena[id] = None;
            self.map.remove(key);
            self.stats.removes += 1;
            if let Some(ns) = new_size {
                *ns = self.order.len();
            }
            true
        } else {
            if let Some(ns) = new_size {
                *ns = self.order.len();
            }
            false
        }
    }

    /// get_pegs / get_counts (C peg table + stats-array reinterpret).
    pub fn get_pegs() -> &'static [&'static str; 9] {
        &LRU_CACHE_SHARED_PEG_NAMES
    }
    pub fn get_counts(&self) -> [u64; 9] {
        [
            self.stats.adds,
            self.stats.alloc_prunes,
            self.stats.bytes_in_use,
            self.stats.items_in_use,
            self.stats.find_hits,
            self.stats.find_misses,
            self.stats.reload_prunes,
            self.stats.removes,
            self.stats.replaced,
        ]
    }
}
