// Port of snort3 hash/lru_segmented_cache_shared.h: SegmentedLruCache —
// power-of-two segments of LruCacheShared keyed by an XOR-fold of the key
// bytes. C++ virtual get_segment_idx stands as an overridable hook via the
// segment_idx_fn closure.
#![allow(dead_code)]

use super::lru_cache_shared::{
    Data, LcsInsertStatus, LruCacheShared, LruCacheSharedStats,
};

pub const DEFAULT_SEGMENT_COUNT: usize = 4;

pub struct SegmentedLruCache<K, V>
where
    K: std::cmp::Eq + std::hash::Hash + Clone + Copy,
    V: Default,
{
    segment_count: usize,
    segments: Vec<LruCacheShared<K, V>>,
    counts: LruCacheSharedStats, // C aggregates into this on get_counts()
    segment_idx_fn: Box<dyn Fn(K) -> usize>,
}

impl<K, V> SegmentedLruCache<K, V>
where
    K: std::cmp::Eq + std::hash::Hash + Clone + Copy,
    V: Default,
{
    pub fn new(initial_size: usize, segment_count: usize) -> SegmentedLruCache<K, V> {
        assert!(segment_count > 0 && (segment_count & (segment_count - 1)) == 0);
        let segments = (0..segment_count)
            .map(|_| LruCacheShared::new(initial_size / segment_count))
            .collect();
        SegmentedLruCache {
            segment_count,
            segments,
            counts: LruCacheSharedStats::default(),
            segment_idx_fn: default_idx_fn::<K>(segment_count),
        }
    }

    pub fn new_default_segments(initial_size: usize) -> SegmentedLruCache<K, V> {
        SegmentedLruCache::new(initial_size, DEFAULT_SEGMENT_COUNT)
    }

    fn seg(&self, key: K) -> usize {
        (self.segment_idx_fn)(key)
    }

    pub fn find(&mut self, key: K) -> Option<Data<V>> {
        let idx = self.seg(key);
        self.segments[idx].find(&key)
    }

    pub fn index_create(&mut self, key: K) -> Data<V> {
        let idx = self.seg(key);
        self.segments[idx].index_create(key)
    }

    pub fn remove(&mut self, key: K, new_size: Option<&mut usize>) -> bool {
        let idx = self.seg(key);
        self.segments[idx].remove_simple(&key, new_size)
    }

    pub fn remove_data(
        &mut self,
        key: K,
        data_out: &mut Option<Data<V>>,
        new_size: Option<&mut usize>,
    ) -> bool {
        let idx = self.seg(key);
        self.segments[idx].remove_data(&key, data_out, new_size)
    }

    pub fn find_else_create(&mut self, key: K, new_data: Option<&mut bool>) -> Data<V> {
        let idx = self.seg(key);
        self.segments[idx].find_else_create(key, new_data)
    }

    pub fn find_else_insert(&mut self, key: K, data: Data<V>, replace: bool) -> bool {
        let idx = self.seg(key);
        self.segments[idx].find_else_insert(key, data, replace)
    }

    pub fn find_else_insert_status(
        &mut self,
        key: K,
        data: Data<V>,
        status: Option<&mut LcsInsertStatus>,
        replace: bool,
    ) -> Data<V> {
        let idx = self.seg(key);
        let mut st: Option<LcsInsertStatus> = None;
        let r = self
            .segments[idx]
            .find_else_insert_status(key, data, &mut st, replace);
        if let Some(s) = status {
            *s = st.unwrap();
        }
        r
    }

    pub fn set_max_size(&mut self, max_size: usize) -> bool {
        let mut success = true;
        let memcap_per_segment = max_size / self.segment_count;
        for segment in &mut self.segments {
            if !segment.set_max_size(memcap_per_segment) {
                success = false;
            }
        }
        success
    }

    pub fn get_all_data(&self) -> Vec<(K, Data<V>)> {
        let mut all_data = Vec::new();
        for cache in &self.segments {
            all_data.extend(cache.get_all_data());
        }
        all_data
    }

    pub fn mem_size(&self) -> usize {
        self.segments.iter().map(|c| c.mem_size()).sum()
    }

    /// get_counts(): aggregates per-segment counts into the owned totals
    /// (C writes into reinterpret_cast of the stats struct).
    pub fn get_counts(&mut self) -> [u64; 9] {
        let mut pcs = [0u64; 9];
        for cache in &self.segments {
            let c = cache.get_counts();
            for i in 0..9 {
                pcs[i] += c[i];
            }
        }
        self.counts = LruCacheSharedStats {
            adds: pcs[0],
            alloc_prunes: pcs[1],
            bytes_in_use: pcs[2],
            items_in_use: pcs[3],
            find_hits: pcs[4],
            find_misses: pcs[5],
            reload_prunes: pcs[6],
            removes: pcs[7],
            replaced: pcs[8],
        };
        pcs
    }

    pub fn size(&self) -> usize {
        self.segments.iter().map(|c| c.size()).sum()
    }

    pub fn get_max_size(&self) -> usize {
        self.segments.iter().map(|c| c.get_max_size()).sum()
    }

    pub fn get_segment_count(&self) -> usize {
        self.segment_count
    }
}

/// C virtual get_segment_idx: XOR the key bytes pairwise, mask by
/// (segment_count - 1). For u32 keys (LE) that is b0^b1^b2^b3.
fn default_idx_fn<K: Copy>(segment_count: usize) -> Box<dyn Fn(K) -> usize> {
    let size = std::mem::size_of::<K>();
    if segment_count == 1 {
        return Box::new(move |_: K| 0);
    }
    Box::new(move |key: K| {
        let bytes = unsafe_key_bytes(&key);
        let mut result: u8 = 0;
        for b in bytes.iter().take(size) {
            result ^= *b;
        }
        (result as usize) & (segment_count - 1)
    })
}

/// Read the raw key bytes the way C reinterprets `&val` as uint8_t*. The
/// slice aliases the caller's aligned Copy value read-only.
fn unsafe_key_bytes<K: Copy>(key: &K) -> &[u8] {
    unsafe { std::slice::from_raw_parts(key as *const K as *const u8, std::mem::size_of::<K>()) }
}
