//! Port of snort3 hash/test/lru_cache_shared_test.cc (CppUTest, 7 cases).
use snort3::hash::lru_cache_shared::*;
use std::cell::RefCell;
use std::rc::Rc;

fn s(v: &str) -> Data<String> {
    Rc::new(RefCell::new(v.to_string()))
}

/// constructor_test
#[test]
fn constructor_test() {
    let lru: LruCacheShared<i32, String> = LruCacheShared::new(5);
    assert_eq!(lru.get_max_size(), 5);
    assert_eq!(lru.size(), 0);
}

/// insert_test
#[test]
fn insert_test() {
    let mut lru: LruCacheShared<i32, String> = LruCacheShared::new(3);

    let data = lru.index_create(0);
    assert_eq!(data.as_ptr(), lru.find(&0).unwrap().as_ptr());
    *data.borrow_mut() = "zero".to_string();

    let data = lru.index_create(1);
    assert_eq!(data.as_ptr(), lru.find(&1).unwrap().as_ptr());
    *data.borrow_mut() = "one".to_string();

    let data = lru.index_create(2);
    assert_eq!(data.as_ptr(), lru.find(&2).unwrap().as_ptr());
    *data.borrow_mut() = "two".to_string();

    // Replace existing (touch to front)
    let data = lru.index_create(0);
    *data.borrow_mut() = "new_zero".to_string();

    // find fails for non-existent item
    assert!(lru.find(&3).is_none());

    // Replace least recently used when capacity exceeded (key 1 evicted)
    let data = lru.index_create(3);
    assert_eq!(data.as_ptr(), lru.find(&3).unwrap().as_ptr());
    *data.borrow_mut() = "three".to_string();

    let vec = lru.get_all_data();
    assert_eq!(vec.len(), 3);
    assert_eq!(*vec[0].1.borrow(), "three");
    assert_eq!(*vec[1].1.borrow(), "new_zero");
    assert_eq!(*vec[2].1.borrow(), "two");
}

/// max_size
#[test]
fn max_size() {
    let mut lru: LruCacheShared<i32, String> = LruCacheShared::new(5);

    let sz = lru.get_max_size();
    assert_eq!(sz, 5);

    for i in 0..sz as i32 {
        let d = lru.index_create(i);
        *d.borrow_mut() = i.to_string();
    }

    // can't set max size to 0
    assert!(!lru.set_max_size(0));
    assert_eq!(lru.get_max_size(), sz);

    // prunes the three oldest: 0, 1, 2
    assert!(lru.set_max_size(2));

    let vec = lru.get_all_data();
    assert_eq!(vec.len(), 2);
    assert_eq!(vec[0].0, 4);
    assert_eq!(*vec[0].1.borrow(), "4");
    assert_eq!(vec[1].0, 3);
    assert_eq!(*vec[1].1.borrow(), "3");
}

/// remove_test
#[test]
fn remove_test() {
    let mut cache_size = 0usize;
    let mut lru: LruCacheShared<i32, String> = LruCacheShared::new(5);

    for i in 0..5i32 {
        let d = lru.index_create(i);
        *d.borrow_mut() = i.to_string();
        assert!(lru.remove_simple(&i, None));
        assert!(lru.find(&i).is_none());
    }
    assert_eq!(lru.size(), 0);

    // remove API that returns the removed data
    let mut data_ptr: Option<Data<String>> = None;
    let d = lru.index_create(1);
    *d.borrow_mut() = "one".to_string();
    assert_eq!(lru.size(), 1);
    assert!(lru.remove_data(&1, &mut data_ptr, Some(&mut cache_size)));
    assert_eq!(cache_size, 0);
    assert_eq!(*data_ptr.take().unwrap().borrow(), "one");
    assert_eq!(lru.size(), 0);

    let d = lru.index_create(1);
    *d.borrow_mut() = "one".to_string();
    let d = lru.index_create(2);
    *d.borrow_mut() = "two".to_string();
    assert_eq!(lru.size(), 2);

    // removing a nonexistent item does not affect the cache
    cache_size = 0;
    assert!(!lru.remove_simple(&3, Some(&mut cache_size)));
    assert_eq!(cache_size, 2);
    cache_size = 0;
    assert!(!lru.remove_data(&4, &mut data_ptr, Some(&mut cache_size)));
    assert_eq!(cache_size, 2);
    assert_eq!(lru.size(), 2);

    let vec = lru.get_all_data();
    assert_eq!(vec.len(), 2);
    assert_eq!(vec[0].0, 2);
    assert_eq!(*vec[0].1.borrow(), "two");
    assert_eq!(vec[1].0, 1);
    assert_eq!(*vec[1].1.borrow(), "one");
}

/// find_else_insert
#[test]
fn find_else_insert() {
    let data = s("12345");
    let data2 = s("54321");
    let mut lru: LruCacheShared<i32, String> = LruCacheShared::new(2);

    assert!(!lru.find_else_insert(1, data.clone(), false));
    assert_eq!(lru.size(), 1);

    assert!(lru.find_else_insert(1, data.clone(), false));
    assert_eq!(lru.size(), 1);

    let mut status = None;
    let got = lru.find_else_insert_status(1, data.clone(), &mut status, false);
    assert_eq!(got.as_ptr(), data.as_ptr());
    assert_eq!(status, Some(LcsInsertStatus::LcsItemPresent));
    assert_eq!(lru.size(), 1);

    let got = lru.find_else_insert_status(2, data2.clone(), &mut status, false);
    assert_eq!(got.as_ptr(), data2.as_ptr());
    assert_eq!(status, Some(LcsInsertStatus::LcsItemInserted));
    assert_eq!(lru.size(), 2);

    let got = lru.find_else_insert_status(1, data2.clone(), &mut status, true);
    assert_eq!(status, Some(LcsInsertStatus::LcsItemReplaced));
    assert_eq!(got.as_ptr(), data2.as_ptr());
    assert_eq!(*lru.find(&1).unwrap().borrow(), "54321");
    assert_eq!(lru.size(), 2);
}

/// find_else_create
#[test]
fn find_else_create() {
    let mut lru: LruCacheShared<i32, i32> = LruCacheShared::new(3);
    let mut is_new = false;

    let entry = lru.find_else_create(4, Some(&mut is_new));
    assert!(is_new);
    *entry.borrow_mut() = 400;

    let entry = lru.find_else_create(4, Some(&mut is_new));
    assert_eq!(*entry.borrow(), 400);
    assert!(!is_new);
    assert_eq!(lru.size(), 1);
}

/// stats_test — pins the full stats array against the upstream checks.
#[test]
fn stats_test() {
    let mut cache_size = 0usize;
    let mut lru: LruCacheShared<i32, String> = LruCacheShared::new(5);

    for i in 0..10i32 {
        lru.index_create(i);
    }

    lru.find(&7); // hits
    lru.find(&8);
    lru.find(&9);

    lru.find(&10); // misses; in addition to the 10 operator[] misses
    lru.find(&11);

    assert!(lru.set_max_size(3)); // prunes 2 more; 5 prunes happened earlier

    assert!(!lru.remove_simple(&10, Some(&mut cache_size))); // miss
    assert_eq!(cache_size, 3);

    assert!(lru.remove_simple(&7, Some(&mut cache_size))); // hit
    assert_eq!(cache_size, 2);

    let stats = lru.get_counts();
    assert_eq!(stats[0], 10); // adds
    assert_eq!(stats[1], 7); // alloc prunes
    assert_eq!(stats[2], 0); // bytes in use (never updated — C quirk)
    assert_eq!(stats[3], 0); // items in use (never updated — C quirk)
    assert_eq!(stats[4], 3); // find hits
    assert_eq!(stats[5], 12); // find misses
    assert_eq!(stats[6], 0); // reload prunes
    assert_eq!(stats[7], 1); // removes

    // statistics names (peg table order)
    let pegs = LruCacheShared::<i32, String>::get_pegs();
    assert_eq!(pegs[0], "adds");
    assert_eq!(pegs[1], "alloc_prunes");
    assert_eq!(pegs[2], "bytes_in_use");
    assert_eq!(pegs[3], "items_in_use");
    assert_eq!(pegs[4], "find_hits");
    assert_eq!(pegs[5], "find_misses");
    assert_eq!(pegs[6], "reload_prunes");
    assert_eq!(pegs[7], "removes");
}
