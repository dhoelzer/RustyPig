// Port of snort3 hash/hash_lru_cache.{h,cc}.
//
// C++ HashLruCache links raw HashNode*; this port uses arena indices into the
// XHash node arena (or any Vec<XHashNode> passed in), preserving the exact
// head/tail/cursor/walk_cursor update order of the original.
#![allow(dead_code)]

use super::hash_defs::XHashNode;

#[derive(Clone, Debug)]
pub struct HashLruCache {
    head: Option<usize>,
    tail: Option<usize>,
    cursor: Option<usize>,
    // walk_cursor is used to traverse from tail to head while dumping flows.
    walk_cursor: Option<usize>,
    node_count: u64,
}


impl HashLruCache {
    pub fn new() -> HashLruCache {
        HashLruCache {
            head: None,
            tail: None,
            cursor: None,
            walk_cursor: None,
            node_count: 0,
        }
    }

    pub fn insert(&mut self, arena: &mut [XHashNode], hnode: usize) {
        arena[hnode].gprev = None;
        arena[hnode].gnext = self.head;
        match self.head {
            Some(h) => arena[h].gprev = Some(hnode),
            None => self.tail = Some(hnode),
        }
        self.head = Some(hnode);
        self.node_count += 1;
    }

    pub fn touch(&mut self, arena: &mut [XHashNode], hnode: usize) {
        if self.cursor == Some(hnode) {
            self.cursor = arena[hnode].gprev;
        }
        if self.walk_cursor == Some(hnode) {
            self.walk_cursor = arena[hnode].gprev;
        }
        if self.head != Some(hnode) {
            self.remove_node(arena, hnode);
            self.insert(arena, hnode);
        }
    }

    pub fn remove_node(&mut self, arena: &mut [XHashNode], hnode: usize) {
        if self.cursor == Some(hnode) {
            self.cursor = arena[hnode].gprev;
        }
        if self.walk_cursor == Some(hnode) {
            self.walk_cursor = arena[hnode].gprev;
        }
        if self.head == Some(hnode) {
            self.head = arena[hnode].gnext;
            if let Some(h) = self.head {
                arena[h].gprev = None;
            }
        }
        if let Some(p) = arena[hnode].gprev {
            arena[p].gnext = arena[hnode].gnext;
        }
        if let Some(x) = arena[hnode].gnext {
            arena[x].gprev = arena[hnode].gprev;
        }
        if self.tail == Some(hnode) {
            self.tail = arena[hnode].gprev;
        }
        self.node_count -= 1;
    }

    pub fn get_lru_node(&mut self) -> Option<usize> {
        self.cursor = self.tail;
        self.cursor
    }

    pub fn get_next_lru_node(&mut self, arena: &[XHashNode]) -> Option<usize> {
        if let Some(c) = self.cursor {
            self.cursor = arena[c].gprev;
        }
        self.cursor
    }

    pub fn get_current_node(&self) -> Option<usize> {
        self.cursor
    }

    pub fn get_mru_user_data(&self, arena: &[XHashNode]) -> Option<usize> {
        self.head.map(|h| arena[h].data)
    }

    pub fn get_lru_user_data(&self, arena: &[XHashNode]) -> Option<usize> {
        self.tail.map(|t| arena[t].data)
    }

    pub fn remove_lru_node(&mut self, arena: &mut [XHashNode]) -> Option<usize> {
        let hnode = self.tail;
        if let Some(n) = hnode {
            self.remove_node(arena, n);
        }
        hnode
    }

    pub fn get_walk_node(&mut self, arena: &[XHashNode]) -> Option<usize> {
        if let Some(t) = self.tail {
            self.walk_cursor = arena[t].gprev;
        }
        self.tail
    }

    pub fn get_next_walk_node(&mut self, arena: &[XHashNode]) -> Option<usize> {
        let rnode = self.walk_cursor;
        if let Some(w) = self.walk_cursor {
            self.walk_cursor = arena[w].gprev;
        }
        rnode
    }

    pub fn get_node_count(&self) -> u64 {
        self.node_count
    }
}

impl Default for HashLruCache {
    fn default() -> Self {
        HashLruCache::new()
    }
}
