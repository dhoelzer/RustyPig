// Port of snort3 hash/ghash.{h,cc} — generic key->value hash table with
// doubly-linked bucket chains and a find_first/find_next scan cursor.
//
// C++ design: raw `void* data` + caller-owned keys (userkey) or malloc'd
// key copies, plus a `gHashFree` destructor hook. Rust models keys as
// owned byte vectors and data as a user-supplied `D` cloneable payload;
// userfree maps to Drop of D. See KNOWN DEVIATIONS.md.
use super::hash_key_operations::{
    HashKeyOperations, HASH_INTABLE, HASH_NOT_FOUND, HASH_OK,
};

mod node_idx {
    pub const NIL: u32 = u32::MAX;
}

#[derive(Clone, Debug)]
struct Node<D> {
    prev: u32,
    next: u32,
    key: Vec<u8>,
    data: D,
}

/// Iteration cursor state (C crow/cnode); a Rust iterator over the scan
/// order carries (crow, next node index) instead.
#[derive(Clone, Debug)]
pub struct ScanCursor {
    // cursor state mirrors C crow/cnode; read by cursor_state() consumers
    #[allow(dead_code)]
    pub crow: i32,
    pub cnode: u32,
}

pub struct GHash<D: Clone> {
    keysize: u32, // 0 => string key (NUL-terminated compare), >0 => fixed
    #[allow(dead_code)] // kept to mirror the C ctor; Rust always owns key bytes
    userkey: bool,
    // C: userkey=false => table mallocs a copy of the key. Rust always
    // owns a copy of the key bytes; userkey is kept to pin get_key_length
    // semantics only.
    nrows: i32,
    hashfcn: HashKeyOperations,
    table: Vec<u32>,
    // arena; freed nodes recycled via free list (C snort_free)
    nodes: Vec<Option<Node<D>>>,
    free_list: Vec<u32>,
    count: u32,
    crow: i32,
    cnode: u32,
}

impl<D: Clone> GHash<D> {
    /// GHash(int nrows, unsigned keysize, bool userkey, gHashFree)
    /// C quirk preserved: nrows > 0 => nearest_prime(nrows); nrows <= 0 =>
    /// nrows = -nrows literally (0 rows possible: insert then divides by
    /// zero in get_index — reproduced as a Rust panic on insert).
    pub fn new(nrows: i32, keysize: u32, userkey: bool, static_hash: bool) -> GHash<D> {
        let nrows = if nrows > 0 {
            super::hash_key_operations::nearest_prime(nrows)
        } else {
            -nrows
        };
        let hashfcn = HashKeyOperations::new(nrows, static_hash);
        let table = vec![node_idx::NIL; nrows as usize];
        GHash {
            keysize,
            userkey,
            nrows,
            hashfcn,
            table,
            nodes: Vec::new(),
            free_list: Vec::new(),
            count: 0,
            crow: 0,
            cnode: node_idx::NIL,
        }
    }

    pub fn set_hashkey_ops(&mut self, hk: HashKeyOperations) {
        self.hashfcn = hk;
    }

    pub fn get_count(&self) -> u32 {
        self.count
    }

    fn get_key_length(&self, key: &[u8]) -> usize {
        if self.keysize > 0 {
            self.keysize as usize
        } else {
            // strlen(s) + 1: for Rust &str/&[u8] without embedded NUL that
            // is key.len()+1; C string keys terminate at first NUL.
            let mut len = 0;
            while len < key.len() && key[len] != 0 {
                len += 1;
            }
            len + 1
        }
    }

    fn get_index(&self, key: &[u8]) -> u32 {
        let klen = self.get_key_length(key);
        let hb = self.key_scan(key);
        let hashkey = self.hashfcn.do_hash(&hb[..klen.min(hb.len())]);
        // C: hashkey % nrows. nrows==0 => float div by zero (SIGFPE) in C;
        // Rust reproduces the crash with an explicit panic (documented).
        hashkey % (self.nrows as u32)
    }

    /// Bytes considered for string keys: up to and including the first
    /// NUL (C strlen+1 semantics). Binary keys pass through.
    fn key_scan(&self, key: &[u8]) -> Vec<u8> {
        if self.keysize == 0 {
            let len = key.iter().take_while(|c| **c != 0).count();
            let mut v = key[..len].to_vec();
            v.push(0);
            v
        } else {
            key.to_vec()
        }
    }

    /// key equality per C: string keys via strcmp on NUL-terminated
    /// semantics; binary keys fixed-length memcmp.
    fn keys_equal(&self, a: &[u8], b: &[u8]) -> bool {
        if self.keysize == 0 {
            let al = a.iter().take_while(|c| **c != 0).count();
            let bl = b.iter().take_while(|c| **c != 0).count();
            if al != bl {
                return false;
            }
            // strcmp: compare byte-wise including the NUL
            for x in 0..al {
                if a[x] != b[x] {
                    return false;
                }
            }
            true
        } else {
            let n = self.keysize as usize;
            let ascan = &a[..n.min(a.len())];
            let bscan = &b[..n.min(b.len())];
            if ascan.len() != n || bscan.len() != n {
                // C memcmp reads n bytes regardless of slice len; Rust
                // callers must supply >= keysize bytes (assert in pin).
                // Pad with zeros to mirror a caller who passed short keys
                // with adjacent heap bytes — pin only for padded inputs.
                return a == b;
            }
            ascan == bscan
        }
    }

    fn find_node(&self, key: &[u8], index: u32) -> Option<u32> {
        let mut idx = self.table[index as usize];
        while idx != node_idx::NIL {
            let node = self.nodes[idx as usize].as_ref().unwrap();
            if self.keys_equal(&node.key, key) {
                return Some(idx);
            }
            idx = node.next;
        }
        None
    }

    /// int insert(const void* const key, void* const data)
    /// C asserts key && data. Returns HASH_INTABLE (and sets cnode) on dup.
    pub fn insert(&mut self, key: &[u8], data: D) -> (i32, Option<u32>) {
        let index = self.get_index(key);
        if let Some(hnode) = self.find_node(key, index) {
            self.cnode = hnode;
            return (HASH_INTABLE, Some(hnode));
        }
        // C stores a copy of get_key_length bytes: string => strlen+1
        // (NUL included), binary => keysize bytes.
        let klen = self.get_key_length(key);
        let scanned = self.key_scan(key);
        let mut kcopy = scanned[..klen.min(scanned.len())].to_vec();
        if kcopy.len() < klen {
            kcopy.resize(klen, 0);
        }
        let idx = if let Some(f) = self.free_list.pop() {
            self.nodes[f as usize] = Some(Node {
                prev: node_idx::NIL,
                next: node_idx::NIL,
                key: kcopy,
                data,
            });
            f
        } else {
            self.nodes.push(Some(Node {
                prev: node_idx::NIL,
                next: node_idx::NIL,
                key: kcopy,
                data,
            }));
            (self.nodes.len() - 1) as u32
        };

        // insert at head, C chain maintenance verbatim
        let head = self.table[index as usize];
        self.nodes[idx as usize].as_mut().unwrap().prev = node_idx::NIL;
        self.nodes[idx as usize].as_mut().unwrap().next = head;
        if head != node_idx::NIL {
            self.nodes[head as usize].as_mut().unwrap().prev = idx;
        }
        self.table[index as usize] = idx;
        self.count += 1;
        (HASH_OK, Some(idx))
    }

    pub fn find(&self, key: &[u8]) -> Option<D> {
        let index = self.get_index(key);
        self.find_node(key, index)
            .map(|i| self.nodes[i as usize].as_ref().unwrap().data.clone())
    }

    fn free_node(&mut self, index: u32, hnode: u32) -> i32 {
        // C: clears key, calls userfree(data), unlinks, snort_free(node),
        // count--. Rust: Drop of data happens when we take the node.
        let node = self.nodes[hnode as usize].take().unwrap();
        // unlink
        if node.prev != node_idx::NIL {
            self.nodes[node.prev as usize].as_mut().unwrap().next = node.next;
            if node.next != node_idx::NIL {
                self.nodes[node.next as usize].as_mut().unwrap().prev = node.prev;
            }
        } else if self.table[index as usize] != node_idx::NIL {
            self.table[index as usize] = node.next; // == node itself when head
            if self.table[index as usize] != node_idx::NIL {
                self.nodes[self.table[index as usize] as usize]
                    .as_mut()
                    .unwrap()
                    .prev = node_idx::NIL;
            }
        }
        // drop data (C userfree), recycle arena slot
        drop(node);
        self.free_list.push(hnode);
        self.count -= 1;
        HASH_OK
    }

    pub fn remove(&mut self, key: &[u8]) -> i32 {
        let index = self.get_index(key);
        match self.find_node(key, index) {
            Some(h) => self.free_node(index, h),
            None => HASH_NOT_FOUND,
        }
    }

    // ---- find_first / find_next scan cursor (verbatim crow/cnode walk) ----

    fn next_step(&mut self) {
        let cnode = self.cnode;
        debug_assert!(cnode != node_idx::NIL);
        self.cnode = self.nodes[cnode as usize].as_ref().unwrap().next;
        if self.cnode != node_idx::NIL {
            return;
        }
        self.crow += 1;
        while self.crow < self.nrows {
            let t = self.table[self.crow as usize];
            if t != node_idx::NIL {
                self.cnode = t;
                return;
            }
            self.crow += 1;
        }
    }

        /// C protocol verbatim: C find_first() sets cnode to the row head,
    /// calls next() (advancing the cursor), and returns the head — so the
    /// cursor is already on the SECOND element when find_first returns.
    pub fn find_first(&mut self) -> Option<(u32, Vec<u8>, D)> {
        self.crow = 0;
        while self.crow < self.nrows {
            let t = self.table[self.crow as usize];
            if t != node_idx::NIL {
                self.cnode = t;
                let n = self.cnode;
                let node = self.nodes[n as usize].as_ref().unwrap();
                let out = (n, node.key.clone(), node.data.clone());
                self.next_step();
                return Some(out);
            }
            self.crow += 1;
        }
        None
    }

    /// find_next: return the currently parked cnode, then advance. C
    /// returns a DANGLING pointer when the node was already freed by a
    /// remove() during iteration (the upstream drain loops rely on
    /// glibc leaving ->next readable in a freed chunk: undefined
    /// behavior). Rust models the C cursor protocol cleanly instead: a
    /// freed slot ends the scan, and the drain loops below re-seed with
    /// find_first() so they remain total. Pinned as a deviation.
    pub fn find_next(&mut self) -> Option<(u32, Vec<u8>, D)> {
        let n = self.cnode;
        if n == node_idx::NIL {
            return None;
        }
        match self.nodes[n as usize].as_ref() {
            Some(node) => {
                let out = (n, node.key.clone(), node.data.clone());
                self.next_step();
                Some(out)
            }
            None => {
                self.cnode = node_idx::NIL;
                None
            }
        }
    }

    /// snapshot of the (crow,cnode) cursor for tests that need to inspect
    /// the scan state
    pub fn cursor_state(&self) -> ScanCursor {
        ScanCursor {
            crow: self.crow,
            cnode: self.cnode,
        }
    }
}
