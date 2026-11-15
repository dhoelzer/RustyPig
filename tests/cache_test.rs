//! Port of snort3 hash/test/{xhash_test.cc, hash_lru_cache_test.cc,
//! zhash_test.cc} (CppUTest suites) plus sanity pins for memcap_allocator
//! (no upstream suite; expectations derived from the header logic).

/// Payload null sentinel: C `data = nullptr` for datasize==0 inserts.
const NULL_PAYLOAD: usize = usize::MAX;

fn k4(i: i32) -> [u8; 4] {
    i.to_le_bytes()
}

// ---------------------------------------------------------------------------
// xhash_test.cc
// ---------------------------------------------------------------------------
mod xhash_tests {
    use super::k4;
    use super::NULL_PAYLOAD;
    use snort3::hash::{XHash, HASH_NOMEM, HASH_OK};

    /// Port of xhash create_xhash_test.
    #[test]
    fn create_xhash_test() {
        let mut t = XHash::new(4, 4, 0, 0, 1);
        // empty table: no MRU node
        assert!(t.get_mru_user_data(0).is_none());

        for i in 1..=4u32 {
            let ret = t.insert(&k4((10 * i) as i32), NULL_PAYLOAD);
            assert_eq!(ret, HASH_OK);
        }

        let xnode = t.find_node(&k4(10));
        assert!(xnode.is_some());
        let ret = t.release_node_handle(xnode.unwrap(), 0);
        assert_eq!(ret, HASH_OK);
    }

    /// Port of xhash free_anr_lru_delete_free_node_test: after release the
    /// node sits on the free list, so delete_lru_node finds nothing in the
    /// LRU cache (returns false) and the key is gone from the table anyway.
    #[test]
    fn free_anr_lru_delete_free_node_test() {
        let mut t = XHash::new(3, 4, 1, 1040, 1);
        let ret = t.insert(&k4(10), NULL_PAYLOAD);
        assert_eq!(ret, HASH_OK);

        let xnode = t.find_node(&k4(10));
        assert!(xnode.is_some());

        let ret = t.release_node_handle(xnode.unwrap(), 0);
        assert_eq!(ret, HASH_OK);

        // C CHECK(ret == HASH_OK): delete_lru_node returns false(0) — the
        // recycled node lives on the free list, not in the LRU cache.
        assert!(!t.delete_lru_node(0));

        let xhnode = t.find_node(&k4(10));
        assert!(xhnode.is_none());
    }

    /// Port of xhash free_anr_lru_delete_tail_node_test: with no free node,
    /// delete_lru_node removes the LRU tail and the key disappears.
    #[test]
    fn free_anr_lru_delete_tail_node_test() {
        let mut t = XHash::new(3, 4, 1, 1040, 1);
        let ret = t.insert(&k4(0), NULL_PAYLOAD);
        assert_eq!(ret, HASH_OK);

        assert!(t.delete_lru_node(0));

        let xhnode = t.find_node(&k4(0));
        assert!(xhnode.is_none());
    }

    /// Port of xhash release_lru_node_never_evicts_pinned: every node
    /// pinned -> ANR evicts nothing, insert fails with HASH_NOMEM.
    #[test]
    fn release_lru_node_never_evicts_pinned() {
        let mut t = XHash::new(4, 4, 0, 0, 1);
        t.set_max_nodes(4);
        for i in 1..=4u32 {
            t.pinned_keys.push(k4(i as i32).to_vec());
            assert_eq!(t.insert(&k4(i as i32), NULL_PAYLOAD), HASH_OK);
        }
        assert_eq!(t.num_nodes, 4);

        assert_eq!(t.insert(&k4(99), NULL_PAYLOAD), HASH_NOMEM);
        assert_eq!(t.num_nodes, 4);

        assert!(t.find_node(&k4(1)).is_some());
    }

    /// Port of xhash release_lru_node_reclaims_recoverable_behind_pinned:
    /// walk passes pinned 1,2 and reclaims node 3.
    #[test]
    fn release_lru_node_reclaims_recoverable_behind_pinned() {
        let mut t = XHash::new(8, 4, 0, 0, 1);
        t.set_max_nodes(4);
        for i in 1..=2u32 {
            t.pinned_keys.push(k4(i as i32).to_vec());
        }
        for i in 1..=4u32 {
            assert_eq!(t.insert(&k4(i as i32), NULL_PAYLOAD), HASH_OK);
        }
        assert_eq!(t.num_nodes, 4);

        assert_eq!(t.insert(&k4(5), NULL_PAYLOAD), HASH_OK);
        assert_eq!(t.num_nodes, 4);

        assert!(t.find_node(&k4(1)).is_some());
        assert!(t.find_node(&k4(2)).is_some());
        assert!(t.find_node(&k4(3)).is_none());
        assert!(t.find_node(&k4(5)).is_some());
    }

    /// Port of xhash release_lru_node_walk_is_bounded: only the MRU head is
    /// recoverable, but the bounded walk (64) never reaches it.
    #[test]
    fn release_lru_node_walk_is_bounded() {
        const CAP: u32 = 80;
        let mut t = XHash::new(128, 4, 0, 0, 1);
        t.set_max_nodes(CAP);
        for i in 1..CAP {
            t.pinned_keys.push(k4(i as i32).to_vec());
        }
        for i in 1..=CAP {
            assert_eq!(t.insert(&k4(i as i32), NULL_PAYLOAD), HASH_OK);
        }
        assert_eq!(t.num_nodes, CAP);

        assert_eq!(t.insert(&k4(999), NULL_PAYLOAD), HASH_NOMEM);
        assert_eq!(t.num_nodes, CAP);
    }
}

// ---------------------------------------------------------------------------
// hash_lru_cache_test.cc — arena stand-in for raw HashNode* nodes.
// ---------------------------------------------------------------------------
mod lru_cache_tests {
    use snort3::hash::{HashLruCache, XHashNode};

    struct Fixture {
        arena: Vec<XHashNode>,
        lru: HashLruCache,
    }
    impl Fixture {
        fn new() -> Fixture {
            Fixture {
                arena: Vec::new(),
                lru: HashLruCache::new(),
            }
        }
        fn add_node(&mut self, data: usize) -> usize {
            self.arena.push(XHashNode {
                data,
                ..Default::default()
            });
            self.arena.len() - 1
        }
        /// Port of the CppUTest teardown(): drain the LRU from the tail,
        /// asserting node_id sequence, MRU==5 while any data remains, and
        /// LRU == node_id+1 after each removal.
        fn teardown(&mut self) {
            let mut node_id: usize = 1;
            let mut node = self.lru.remove_lru_node(&mut self.arena);
            while let Some(n) = node {
                assert_eq!(self.arena[n].data, node_id);
                if let Some(d) = self.lru.get_mru_user_data(&self.arena) {
                    assert_eq!(d, 5);
                }
                if let Some(d) = self.lru.get_lru_user_data(&self.arena) {
                    assert_eq!(d, node_id + 1);
                }
                node_id += 1;
                node = self.lru.remove_lru_node(&mut self.arena);
            }
        }
    }

    /// Port of hash_lru_cache create_hash_lru_cache_test.
    #[test]
    fn create_hash_lru_cache_test() {
        let mut f = Fixture::new();
        assert!(f.lru.get_next_lru_node(&f.arena).is_none());
        assert!(f.lru.get_current_node().is_none());
        assert!(f.lru.get_mru_user_data(&f.arena).is_none());
        assert!(f.lru.get_lru_user_data(&f.arena).is_none());
        assert!(f.lru.remove_lru_node(&mut f.arena).is_none());
        f.teardown();
    }

    /// Port of hash_lru_cache hash_lru_cache_insert_test.
    #[test]
    fn hash_lru_cache_insert_test() {
        let mut f = Fixture::new();
        for i in 0..5usize {
            let node = f.add_node(i + 1);
            f.lru.insert(&mut f.arena, node);
            assert_eq!(f.lru.get_mru_user_data(&f.arena), Some(i + 1));
            assert_eq!(f.lru.get_lru_user_data(&f.arena), Some(1));
        }

        for i in 0..5usize {
            let node = f.lru.get_lru_node();
            assert!(node.is_some());
            assert_eq!(f.arena[node.unwrap()].data, i + 1);
            f.lru.touch(&mut f.arena, node.unwrap());
            assert_eq!(f.lru.get_mru_user_data(&f.arena), Some(i + 1));
            assert_eq!(f.lru.get_lru_user_data(&f.arena), Some(((i + 1) % 5) + 1));
        }

        let node = f.lru.get_lru_node();
        assert!(node.is_some());
        assert_eq!(f.arena[node.unwrap()].data, 1);
        f.teardown();
    }

    /// Port of hash_lru_cache hash_lru_cache_browse_test.
    #[test]
    fn hash_lru_cache_browse_test() {
        let mut f = Fixture::new();
        for i in 0..5usize {
            let node = f.add_node(i + 1);
            f.lru.insert(&mut f.arena, node);
        }

        for i in 0..5usize {
            let node = f.lru.get_lru_node();
            assert!(node.is_some());
            assert_eq!(f.arena[node.unwrap()].data, i + 1);
            f.lru.touch(&mut f.arena, node.unwrap());
        }

        let mut node = f.lru.get_lru_node();
        let mut i = 1usize;
        while let Some(n) = node {
            assert_eq!(f.arena[n].data, i);
            let cur = f.lru.get_current_node().unwrap();
            assert_eq!(f.arena[cur].data, i);
            node = f.lru.get_next_lru_node(&f.arena);
            i += 1;
        }
        f.teardown();
    }
}

// ---------------------------------------------------------------------------
// zhash_test.cc — payload handles index a test-local Vec<u32> standing for
// the snort_calloc'd `unsigned*` payloads.
// ---------------------------------------------------------------------------
mod zhash_tests {
    use snort3::hash::ZHash;

    const ZHASH_ROWS: i32 = 50;
    const ZHASH_KEY_SIZE: u32 = 100;
    const MAX_ZHASH_NODES: usize = 100;

    struct Fixture {
        zh: ZHash,
        payload: Vec<u32>,
        key_buf: [u8; 100],
    }
    impl Fixture {
        fn new() -> Fixture {
            // C ZHash(50, 100) + initialize(FlowHashKeyOps); the C++ suite
            // stubs FlowHashKeyOps::do_hash as the unfinalized accumulation.
            let zh = ZHash::with_ops(
                ZHASH_ROWS,
                ZHASH_KEY_SIZE,
                1,
                true,
                Some(ZHash::flow_test_ops(3193, 719, 133824503)),
            );
            Fixture {
                zh,
                payload: Vec::new(),
                key_buf: [0u8; 100],
            }
        }
        fn alloc_payload(&mut self, v: u32) -> usize {
            self.payload.push(v);
            self.payload.len() - 1
        }
    }

    /// Port of zhash create_zhash_test.
    #[test]
    fn create_zhash_test() {
        let mut f = Fixture::new();
        for _ in 0..MAX_ZHASH_NODES {
            let p = f.alloc_payload(0);
            f.zh.push(p);
        }

        assert_eq!(f.zh.get_num_nodes(), 0);
        assert_eq!(f.zh.get_num_free_nodes(), MAX_ZHASH_NODES as u32);

        for i in 0..MAX_ZHASH_NODES {
            let key = format!("foo{}", i + 1);
            f.key_buf = [0u8; 100];
            f.key_buf[..key.len()].copy_from_slice(key.as_bytes());
            let data = f.zh.get(&f.key_buf, 0);
            assert!(data.is_some());
            let h = data.unwrap();
            assert_eq!(f.payload[h], 0);
            f.payload[h] = (i + 1) as u32;
        }

        assert_eq!(f.zh.get_num_nodes(), MAX_ZHASH_NODES as u32);
        assert_eq!(f.zh.get_num_free_nodes(), 0);

        let mut nodes_walked = 0usize;
        let mut data = f.zh.lru_first(0);
        while let Some(h) = data {
            nodes_walked += 1;
            assert_eq!(f.payload[h], nodes_walked as u32);
            data = f.zh.lru_next(0);
        }
        assert_eq!(nodes_walked, MAX_ZHASH_NODES);

        let h = f.zh.lru_first(0).unwrap();
        assert_eq!(f.payload[h], 1);
        let h = f.zh.remove(0).unwrap();
        assert_eq!(f.payload[h], 1);
        let h = f.zh.lru_current(0).unwrap();
        assert_eq!(f.payload[h], 2);
        let h = f.zh.lru_first(0).unwrap();
        assert_eq!(f.payload[h], 2);

        for i in 1..MAX_ZHASH_NODES {
            let h = f.zh.remove(0).unwrap();
            assert_eq!(f.payload[h], (i + 1) as u32);
        }
    }

    /// Port of zhash zhash_pop_test.
    #[test]
    fn zhash_pop_test() {
        let mut f = Fixture::new();
        assert!(f.zh.pop().is_none());
        let data = f.alloc_payload(0);
        f.zh.push(data);
        let pop_data = f.zh.pop();
        assert_eq!(pop_data, Some(data));
        assert!(f.zh.pop().is_none());
    }

    /// Port of zhash zhash_get_test.
    #[test]
    fn zhash_get_test() {
        let mut f = Fixture::new();
        let data = f.alloc_payload(0);
        f.zh.push(data);
        f.key_buf[0] = b'a';
        let get_data = f.zh.get(&f.key_buf, 0);
        assert_eq!(get_data, Some(data));
        let get_data = f.zh.get(&f.key_buf, 0);
        assert_eq!(get_data, Some(data));
        f.key_buf[0] = b'b';
        let get_data = f.zh.get(&f.key_buf, 0);
        assert_eq!(get_data, None);
        let get_data = f.zh.lru_first(0);
        assert_eq!(get_data, Some(data));
        let get_data = f.zh.remove(0);
        assert_eq!(get_data, Some(data));
    }

    /// Port of zhash zhash_lru_test.
    #[test]
    fn zhash_lru_test() {
        let mut f = Fixture::new();
        let data1 = f.alloc_payload(0);
        f.zh.push(data1);
        f.key_buf[0] = b'1';
        let get_data = f.zh.get(&f.key_buf, 0);
        assert_eq!(get_data, Some(data1));
        let data2 = f.alloc_payload(0);
        f.zh.push(data2);
        f.key_buf[0] = b'2';
        let get_data = f.zh.get(&f.key_buf, 0);
        assert_eq!(get_data, Some(data2));

        let get_data = f.zh.lru_first(0);
        assert_eq!(get_data, Some(data1));

        f.zh.lru_touch(0);
        let get_data = f.zh.lru_first(0);
        assert_eq!(get_data, Some(data2));
        let get_data = f.zh.remove(0);
        assert_eq!(get_data, Some(data2));

        let get_data = f.zh.lru_first(0);
        assert_eq!(get_data, Some(data1));
        let get_data = f.zh.remove(0);
        assert_eq!(get_data, Some(data1));
    }
}

// ---------------------------------------------------------------------------
// memcap_allocator: no upstream CppUTest suite; pins derived directly from
// the header's inline logic (no capacity -> unlimited; bounded accounting).
// ---------------------------------------------------------------------------
mod memcap_tests {
    use snort3::helpers::memcap_allocator::MemCapAllocator;

    #[test]
    fn unlimited_capacity_never_refuses() {
        let mut a = MemCapAllocator::new(0, 100);
        for _ in 0..10 {
            assert!(a.allocate());
        }
        assert_eq!(a.get_mem_allocated(), 1000);
        assert!(!a.is_over_capacity());
        assert_eq!(a.get_allocation_requests(), 10);
        assert_eq!(a.get_no_memory_available(), 0);
    }

    #[test]
    fn bounded_capacity_refuses_and_counts() {
        let mut a = MemCapAllocator::new(10, 6);
        assert!(a.is_space_available());
        assert!(a.allocate()); // 6 <= 10
                               // 6 + 6 > 10 -> refused (C returns nullptr; no snort_calloc)
        assert!(!a.allocate());
        assert_eq!(a.get_mem_allocated(), 6);
        assert_eq!(a.get_no_memory_available(), 1);
        assert_eq!(a.get_allocation_requests(), 1);
        // C free() decrements even for foreign pointers (accounting quirk
        // preserved: unconditional mem_allocated -= allocation_size).
        a.free_();
        assert_eq!(a.get_mem_allocated(), 0);
        assert!(a.allocate());
        a.free_();
        // double-free is UB in C (unsigned wraparound); Rust saturates at 0
        // and the deviation is documented in KNOWN DEVIATIONS.md.
        a.free_();
        assert_eq!(a.get_mem_allocated(), 0);
        assert_eq!(a.get_free_requests(), 3);
    }

    #[test]
    fn over_capacity_only_when_accounting_exceeds_cap() {
        let mut a = MemCapAllocator::new(10, 6);
        assert!(!a.is_over_capacity());
        assert!(a.allocate());
        assert!(!a.is_over_capacity());
        // force overcap the way C can: set the cap below current usage
        a.set_mem_capacity(5);
        assert!(a.is_over_capacity());
        assert!(!a.is_space_available());
    }
}
