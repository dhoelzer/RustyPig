// Port of snort3 hash/zhash.{h,cc}: the "zero copy" hash used by the flow
// layer. Nodes carry user payloads (`void*`), are pre-allocated onto a free
// list (push/pop) and adopted into the table on first `get(key)`.
#![allow(dead_code)]

use super::xhash::{HashOps, XHash};

pub struct ZHash {
    inner: XHash,
}

impl ZHash {
    /// C `ZHash(int nrows, int key_len, uint8_t lru_count, bool recycle)`
    /// followed by `initialize(new FlowHashKeyOps(nrows))`. The plain
    /// constructor uses the standard jenkins ops (the flow-specific ops are
    /// supplied via `with_ops`, mirroring how the C++ tests stub
    /// FlowHashKeyOps::do_hash).
    pub fn new(rows: i32, key_len: u32, lru_count: u8, recycle: bool) -> ZHash {
        ZHash::with_ops(rows, key_len, lru_count, recycle, None)
    }

    pub fn with_ops(
        rows: i32,
        key_len: u32,
        lru_count: u8,
        recycle: bool,
        ops: Option<Box<dyn HashOps>>,
    ) -> ZHash {
        let mut zh = ZHash {
            inner: XHash::new_uninitialized(rows, key_len, lru_count),
        };
        match ops {
            Some(o) => zh.inner.initialize_with_ops(o),
            None => zh.inner.initialize(),
        }
        zh.inner.anr_enabled = false;
        zh.inner.recycle_nodes = recycle;
        zh
    }

    pub fn get(&mut self, key: &[u8], typ: u8) -> Option<usize> {
        assert!((typ as u32) < self.inner.num_lru_caches as u32);
        let mut index = 0usize;
        let node = self.inner.find_node_row_pub(key, &mut index);
        if let Some(n) = node {
            return Some(self.inner.nodes[n].data);
        }

        let node = self.inner.get_free_node_pub()?;

        self.inner.nodes[node].key.clear();
        self.inner.nodes[node].key.extend_from_slice(key);
        self.inner.nodes[node].rindex = index;
        self.inner.link_node_pub(node);
        self.inner.lru_caches[typ as usize].insert(&mut self.inner.nodes, node);
        self.inner.num_nodes += 1;
        Some(self.inner.nodes[node].data)
    }

    pub fn remove(&mut self, typ: u8) -> Option<usize> {
        assert!((typ as u32) < self.inner.num_lru_caches as u32);
        let node = self.inner.lru_caches[typ as usize].get_current_node();
        assert!(node.is_some());
        let Some(node) = node else {
            unreachable!()
        };
        let pv = self.inner.nodes[node].data;

        self.inner.unlink_node_pub(node);
        self.inner.lru_caches[typ as usize].remove_node(&mut self.inner.nodes, node);
        self.inner.num_nodes -= 1;
        self.inner.free_node_mem_pub(node);
        Some(pv)
    }

    /// C push(void* p): allocate a node, attach the payload, park it on the
    /// free list. `data` (payload handle) stands in for the returned
    /// inline key pointer, which carries no observable identity here.
    pub fn push(&mut self, p: usize) {
        assert!(self.inner.mem_allocator.allocate());
        self.inner.nodes.push(super::hash_defs::XHashNode {
            key: vec![0u8; self.inner.keysize as usize],
            data: p,
            ..Default::default()
        });
        let node = self.inner.nodes.len() - 1;
        self.inner.save_free_node_pub(node);
    }

    pub fn pop(&mut self) -> Option<usize> {
        let node = self.inner.get_free_node_pub()?;
        let pv = self.inner.nodes[node].data;
        self.inner.free_node_mem_pub(node);
        Some(pv)
    }

    pub fn get_node_count(&self, typ: u8) -> u64 {
        self.inner.lru_caches[typ as usize].get_node_count()
    }

    pub fn lru_first(&mut self, typ: u8) -> Option<usize> {
        let node = self.inner.lru_caches[typ as usize].get_lru_node();
        node.map(|n| self.inner.nodes[n].data)
    }
    pub fn lru_next(&mut self, typ: u8) -> Option<usize> {
        let node = self.inner.lru_caches[typ as usize].get_next_lru_node(&self.inner.nodes);
        node.map(|n| self.inner.nodes[n].data)
    }
    pub fn lru_current(&self, typ: u8) -> Option<usize> {
        let node = self.inner.lru_caches[typ as usize].get_current_node();
        node.map(|n| self.inner.nodes[n].data)
    }
    pub fn lru_touch(&mut self, typ: u8) {
        let node = self.inner.lru_caches[typ as usize].get_current_node();
        assert!(node.is_some());
        self.inner.lru_caches[typ as usize].touch(&mut self.inner.nodes, node.unwrap());
    }

    // pass-through accessors the C ZHash inherits from XHash
    pub fn get_num_nodes(&mut self) -> u32 {
        self.inner.get_num_nodes()
    }
    pub fn get_num_free_nodes(&mut self) -> u32 {
        self.inner.get_num_free_nodes()
    }
    pub fn get_mem_used(&self) -> u64 {
        self.inner.get_mem_used()
    }

    /// C FlowHashKeyOps::do_hash is defined in flow/flow_key.cc (bob-jenkins
    /// mix over the FlowKey words) but is *stubbed* in zhash_test.cc as the
    /// unfinalized seed/scale/hardener accumulation. This struct pins the
    /// test-stub variant, which is what the ported test vectors replay.
    pub fn flow_test_ops(seed: u32, scale: u32, hardener: u32) -> Box<dyn HashOps> {
        Box::new(FlowTestOps {
            seed,
            scale,
            hardener,
        })
    }
}

#[derive(Debug)]
struct FlowTestOps {
    seed: u32,
    scale: u32,
    hardener: u32,
}
impl HashOps for FlowTestOps {
    fn do_hash(&self, key: &[u8]) -> u32 {
        // zhash_test.cc stub, verbatim:
        //   unsigned hash = seed; while (len) { hash *= scale; hash += *k++; len--; }
        //   return hash ^ hardener;
        let mut hash = self.seed;
        for k in key.iter() {
            hash = hash.wrapping_mul(self.scale);
            hash = hash.wrapping_add(*k as u32);
        }
        hash ^ self.hardener
    }
}
