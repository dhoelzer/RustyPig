// Port of snort3 hash/lru_cache_local.h: thread-unsafe memcap-enforced LRU
// cache (template LruCacheLocal<Key, Value, Hash>; the Hash parameter is
// irrelevant in Rust where the map is a HashMap).
//
// C++ keeps std::list<pair<K,V>> front=MRU / back=LRU plus a map to list
// iterators. The port keys an entry arena by stable id and keeps a Vec of
// ids front=MRU: splice-to-front and erase-from-middle keep ids stable so
// outstanding handles stay valid (C Value& references would dangle after
// splice — same hazard in C, avoided here by handle indirection; see KNOWN
// DEVIATIONS).
#![allow(dead_code)]

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LruCacheLocalStats {
    pub cache_adds: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_replaces: u64,
    pub cache_max: u64,
    pub cache_prunes: u64,
    pub cache_removes: u64,
}

pub struct LruCacheLocal<K: std::cmp::Eq + std::hash::Hash + Clone, V> {
    entry_size: u64, // C entry_size = 2*sizeof(Key)+sizeof(Value)+sizeof(iter)
    pub max_size: u64,
    current_size: u64,
    arena: Vec<Option<(K, V)>>,
    order: Vec<usize>, // front (index 0) == MRU, back == LRU
    map: HashMap<K, usize>,
    stats: LruCacheLocalStats, // C binds an external stats struct by ref
}

impl<K: std::cmp::Eq + std::hash::Hash + Clone, V: Default> LruCacheLocal<K, V> {
    /// C ctor: sz==0 means unlimited; 0 < sz < entry_size clamps to
    /// entry_size (with a WarningMessage in C; log skipped as a deviation).
    pub fn new(max_size: u64, entry_size: u64) -> LruCacheLocal<K, V> {
        let max_size = if max_size != 0 && max_size < entry_size {
            entry_size
        } else {
            max_size
        };
        LruCacheLocal {
            entry_size,
            max_size,
            current_size: 0,
            arena: Vec::new(),
            order: Vec::new(),
            map: HashMap::new(),
            stats: LruCacheLocalStats::default(),
        }
    }

    pub fn get_stats(&self) -> LruCacheLocalStats {
        self.stats
    }
    pub fn current_size(&self) -> u64 {
        self.current_size
    }

    /// C prune(): note the `list.size() > 1` guard — the last entry is never
    /// pruned even if it exceeds max_size (quirk preserved).
    fn prune(&mut self) {
        if self.max_size == 0 {
            return;
        }
        while self.current_size > self.max_size && self.order.len() > 1 {
            let id = *self.order.last().unwrap();
            self.order.pop();
            let (k, _) = self.arena[id].take().unwrap();
            self.map.remove(&k);
            self.current_size -= self.entry_size;
            self.stats.cache_prunes += 1;
        }
    }

    fn add_entry(&mut self, key: K, value: V) -> usize {
        self.stats.cache_adds += 1;
        self.arena.push(Some((key.clone(), value)));
        let id = self.arena.len() - 1;
        self.order.insert(0, id); // emplace_front
        self.map.insert(key, id);
        self.current_size += self.entry_size;
        self.prune();
        if self.stats.cache_max < self.current_size {
            self.stats.cache_max = self.current_size;
        }
        id
    }

    /// C splice-to-front for a found entry.
    fn touch(&mut self, id: usize) {
        let pos = self.order.iter().position(|&x| x == id).unwrap();
        if pos != 0 {
            self.order.remove(pos);
            self.order.insert(0, id);
        }
    }

    /// C count(): 1 if present, else 0.
    pub fn count(&self, key: &K) -> i32 {
        if self.map.contains_key(key) {
            1
        } else {
            0
        }
    }

    /// C find_else_create: returns a stable handle (C returns Value&).
    /// Use `entry(handle)` / `set_entry(handle, v)` to read/write.
    pub fn find_else_create(&mut self, key: K, is_new: &mut bool) -> usize {
        if let Some(&id) = self.map.get(&key) {
            *is_new = false;
            self.stats.cache_hits += 1;
            self.touch(id);
            id
        } else {
            self.stats.cache_misses += 1;
            *is_new = true;
            // C add_entry(key, Value()): value-initialized slot.
            self.add_entry(key, V::default())
        }
    }

    /// C add(): true if inserted, false if the key existed (value replaced
    /// only when `replace` is set).
    pub fn add(&mut self, key: K, value: V, replace: bool) -> bool {
        if let Some(&id) = self.map.get(&key) {
            self.stats.cache_hits += 1;
            self.touch(id);
            if replace {
                self.arena[id].as_mut().unwrap().1 = value;
                self.stats.cache_replaces += 1;
            }
            false
        } else {
            self.stats.cache_misses += 1;
            self.add_entry(key, value);
            true
        }
    }

    pub fn remove(&mut self, key: &K) -> bool {
        if let Some(id) = self.map.remove(key) {
            let pos = self.order.iter().position(|&x| x == id).unwrap();
            self.order.remove(pos);
            self.arena[id] = None;
            self.current_size -= self.entry_size;
            self.stats.cache_removes += 1;
            true
        } else {
            false
        }
    }

    /// C get_all_values: MRU first.
    pub fn get_all_values(&self) -> Vec<(K, V)>
    where
        V: Clone,
    {
        self.order
            .iter()
            .map(|&id| {
                let (k, v) = self.arena[id].as_ref().unwrap();
                (k.clone(), v.clone())
            })
            .collect()
    }

    pub fn entry(&self, id: usize) -> &V {
        &self.arena[id].as_ref().unwrap().1
    }
    pub fn set_entry(&mut self, id: usize, v: V) {
        self.arena[id].as_mut().unwrap().1 = v;
    }
}
