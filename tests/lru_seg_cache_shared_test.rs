//! Port of snort3 hash/test/lru_seg_cache_shared_test.cc (CppUTest, 11 cases).
use snort3::hash::lru_cache_shared::{Data, LcsInsertStatus};
use snort3::hash::lru_segmented_cache_shared::{SegmentedLruCache, DEFAULT_SEGMENT_COUNT};
use std::cell::RefCell;
use std::rc::Rc;

fn seg4<V: Default>(initial: usize) -> SegmentedLruCache<i32, V> {
    SegmentedLruCache::new(initial, DEFAULT_SEGMENT_COUNT)
}

fn s(v: &str) -> Data<String> {
    Rc::new(RefCell::new(v.to_string()))
}

/// constructor_test
#[test]
fn constructor_test() {
    let lru = seg4::<String>(8);
    // 8/4 segments == 2 each; summed max == 8
    assert_eq!(lru.get_max_size(), 8);
    assert_eq!(lru.size(), 0);
}

/// insert_test
#[test]
fn insert_test() {
    let mut lru = seg4::<String>(4); // 1 per segment

    let data = lru.index_create(0);
    assert_eq!(data.as_ptr(), lru.find(0).unwrap().as_ptr());
    *data.borrow_mut() = "zero".to_string();

    let data = lru.index_create(1);
    assert_eq!(data.as_ptr(), lru.find(1).unwrap().as_ptr());
    *data.borrow_mut() = "one".to_string();

    let data = lru.index_create(2);
    assert_eq!(data.as_ptr(), lru.find(2).unwrap().as_ptr());
    *data.borrow_mut() = "two".to_string();

    let data = lru.index_create(0);
    *data.borrow_mut() = "new_zero".to_string();

    assert!(lru.find(3).is_none());

    let data = lru.index_create(3);
    assert_eq!(data.as_ptr(), lru.find(3).unwrap().as_ptr());
    *data.borrow_mut() = "three".to_string();

    // 4 keys land in 4 distinct segments (0^0^0^0=0, 1, 2, 3 idx)
    let vec = lru.get_all_data();
    assert_eq!(vec.len(), 4);
}

/// mem_size_test
#[test]
fn mem_size_test() {
    let mut cache = seg4::<String>(5);
    let data = s("hello");
    cache.find_else_insert(1, data, false);
    assert_ne!(cache.mem_size(), 0);
}

/// get_counts_test
#[test]
fn get_counts_test() {
    let mut cache = seg4::<String>(5);
    // C checks the returned pointer is non-null; the Rust array always exists.
    let counts = cache.get_counts();
    assert_eq!(counts[0], 0);
}

/// size_test
#[test]
fn size_test() {
    let mut cache = seg4::<String>(5);
    let data = s("hello");
    cache.find_else_insert(1, data, false);
    assert_eq!(cache.size(), 1);
}

/// max_size
#[test]
fn max_size() {
    let mut lru = seg4::<String>(16);
    assert_eq!(lru.get_max_size(), 16);

    // 8/4 = 2 per segment
    assert!(lru.set_max_size(8));
    assert_eq!(lru.get_max_size(), 8);
}

/// remove_test — key 5 must share the segment of key 1 for the C test to
/// exercise "nonexistent key in the same segment" (5^0^0^0 = 5 & 3 == 1).
#[test]
fn remove_test() {
    let mut lru = seg4::<String>(4);

    for i in 0..4i32 {
        let data = s(&i.to_string());
        assert!(!lru.find_else_insert(i, data.clone(), false));
        assert!(lru.find_else_insert(i, data.clone(), false));
        assert!(lru.remove(i, None));
        assert!(lru.find(i).is_none());
    }
    assert_eq!(lru.size(), 0);

    let mut data_ptr: Option<Data<String>> = None;
    let data = s("one");
    lru.find_else_insert(1, data, false);
    assert_eq!(lru.size(), 1);

    // remove an entry that doesn't exist from the same segment
    let mut cache_size = 0usize;
    assert!(!lru.remove_data(5, &mut data_ptr, Some(&mut cache_size)));
    assert_eq!(cache_size, 1);

    // remove an entry that does exist
    assert!(lru.remove_data(1, &mut data_ptr, None));
    assert_eq!(*data_ptr.unwrap().borrow(), "one");
    assert_eq!(lru.size(), 0);
}

/// find_else_insert
#[test]
fn find_else_insert() {
    let data = s("12345");
    let mut lru = seg4::<String>(8);

    assert!(!lru.find_else_insert(1, data.clone(), false));
    assert_eq!(lru.size(), 1);

    assert!(lru.find_else_insert(1, data.clone(), false));
    assert_eq!(lru.size(), 1);
}

/// segments_8
#[test]
fn segments_8() {
    let mut lru = SegmentedLruCache::<i32, String>::new(1024, 8);
    let data = s("12345");

    assert!(!lru.find_else_insert(1, data.clone(), false));
    assert_eq!(lru.size(), 1);

    assert!(lru.find_else_insert(1, data.clone(), false));
    assert_eq!(lru.size(), 1);

    assert_eq!(lru.get_segment_count(), 8);
}

/// stats_test — per-segment pruning pins the summed array exactly as the
/// C++ TEST does (segments: 2/seg for size 8).
#[test]
fn stats_test() {
    let mut lru = seg4::<String>(8); // per-segment cap 2

    for i in 0..10i32 {
        lru.index_create(i);
    }

    lru.find(7);
    lru.find(8);
    lru.find(9);
    lru.find(10);
    lru.find(11);

    // raising per-segment cap to 4 prunes nothing
    assert!(lru.set_max_size(16));

    let mut cache_size = 0usize;
    lru.remove(7, Some(&mut cache_size));
    assert_eq!(cache_size, 1);

    cache_size = 0;
    lru.remove(8, Some(&mut cache_size));
    assert_eq!(cache_size, 1);

    cache_size = 0;
    lru.remove(11, Some(&mut cache_size)); // not in cache (pruned)
    assert_eq!(cache_size, 1);

    let stats = lru.get_counts();
    assert_eq!(stats[0], 10); // adds
    assert_eq!(stats[1], 2); // alloc prunes (seg0: keys 0,1 evicted by 8,9)
    assert_eq!(stats[2], 0); // bytes in use
    assert_eq!(stats[3], 0); // items in use
    assert_eq!(stats[4], 3); // find hits
    assert_eq!(stats[5], 12); // find misses
    assert_eq!(stats[6], 0); // reload prunes
    assert_eq!(stats[7], 2); // removes
    assert_eq!(stats[8], 0); // replaced
}

/// find_else_insert_replace
#[test]
fn find_else_insert_replace() {
    let mut lru = seg4::<String>(8);
    let data = s("hello");
    let mut status = LcsInsertStatus::LcsItemPresent;

    lru.find_else_insert_status(1, data.clone(), Some(&mut status), false);
    assert_eq!(status, LcsInsertStatus::LcsItemInserted);

    let new_data = s("world");
    let returned = lru.find_else_insert_status(1, new_data.clone(), Some(&mut status), true);
    // C checks "returnedData != nullptr"; Rc is always non-null in Rust.
    assert_eq!(status, LcsInsertStatus::LcsItemReplaced);
    assert_eq!(*returned.borrow(), "world");

    let returned = lru.find_else_insert_status(1, new_data.clone(), Some(&mut status), false);
    assert_eq!(status, LcsInsertStatus::LcsItemPresent);
    assert_eq!(*returned.borrow(), "world");
}
