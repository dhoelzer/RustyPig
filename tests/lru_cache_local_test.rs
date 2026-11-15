//! Port of snort3 hash/test/lru_cache_local_test.cc (CppUTest suite).
//! C entry_size pins: sizeof(std::list iterator)==8 on x86-64.

/// LruCacheLocal<int,int>: entry_size = 2*4 + 4 + 8 = 20.
const ENTRY_INT_INT: u64 = 2 * 4 + 4 + 8;
/// LruCacheLocal<uint64_t,float>: entry_size = 2*8 + 4 + 8 = 28.
const ENTRY_U64_F32: u64 = 2 * 8 + 4 + 8;

use snort3::hash::LruCacheLocal;

/// Port of lru_cache_local basic.
#[test]
fn basic() {
    // memcap = 40 bytes holds 2 entries
    let mut lru = LruCacheLocal::<i32, i32>::new(40, ENTRY_INT_INT);

    lru.add(1, 100, false);
    lru.add(2, 200, false);
    lru.add(3, 300, false);

    // entries are stored MRU-first; the LRU tail (key 1) was pruned
    let vec = lru.get_all_values();
    assert_eq!(vec.len(), 2);
    assert_eq!(vec[0], (3, 300));
    assert_eq!(vec[1], (2, 200));

    // non-existent entry: find_else_create() returns a new (defaulted) entry
    let mut is_new = false;
    let h = lru.find_else_create(4, &mut is_new);
    assert!(is_new);
    lru.set_entry(h, 400);

    // subsequent calls return the same entry (C returned Value&)
    let mut is_new = false;
    let h2 = lru.find_else_create(4, &mut is_new);
    assert_eq!(*lru.entry(h2), 400);
    assert!(!is_new);
    lru.set_entry(h2, 4000);

    let mut is_new = true;
    let h3 = lru.find_else_create(4, &mut is_new);
    assert_eq!(*lru.entry(h3), 4000);
    assert!(!is_new);
    assert_eq!(h, h2);
    assert_eq!(h2, h3);

    // cache changed: key 1 gone, key 2 pushed out by key 4 insert
    let vec = lru.get_all_values();
    assert_eq!(vec.len(), 2);
    assert_eq!(vec[0], (4, 4000));
    assert_eq!(vec[1], (3, 300));

    let st = lru.get_stats();
    // adds: 1,2,3 + key4 = 4; hits: 2 (key-4 find_else_create hits);
    // misses: 3 inserted-first (1,2,3) + 1 (key 4) = 4
    assert_eq!(st.cache_adds, 4);
    assert_eq!(st.cache_hits, 2);
    assert_eq!(st.cache_misses, 4);
    assert_eq!(st.cache_replaces, 0);
    assert_eq!(st.cache_prunes, 2); // pruned once each at adds of key3 and key4
    assert_eq!(st.cache_removes, 0);
}

/// Port of lru_cache_local max_size_less_than_entry_size: max_size below
/// entry_size is clamped so the cache holds exactly one entry.
#[test]
fn max_size_less_than_entry_size() {
    let mut lru = LruCacheLocal::<u64, f32>::new(10, ENTRY_U64_F32);

    let mut is_new = false;
    for i in 0..10u64 {
        let h = lru.find_else_create(i, &mut is_new);
        lru.set_entry(h, i as f32 * 1.5);
    }

    let vec = lru.get_all_values();
    assert_eq!(vec.len(), 1); // clamped to one entry
    assert_eq!(lru.count(&9), 1);
    assert_eq!(lru.count(&5), 0);
    // the one survivor is the most recent
    assert_eq!(vec[0].0, 9);
    assert_eq!(vec[0].1, 13.5);
}
