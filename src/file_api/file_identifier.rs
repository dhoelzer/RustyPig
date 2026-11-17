//! Literal port of `file_api/file_identifier.{h,cc}` (row 17n):
//! FileMeta + the magic-byte trie FileIdentifier.
//!
//! Ground truth: tools/fid_harness — `file_identifier.cc` compiled
//! VERBATIM; the TU's own embedded `[FileMagic]` suite is the gate
//! (6 cases / 6 assertions). 19-line transcript replayed byte-for-byte
//! in tests/fid_parity_test.rs (md5 febec99794d97d46ae9660890b13a8be).
//!
//! Production quirk pinned by upstream: `add_file_id` populates ONLY
//! `file_magic_rules[]`; nothing ever inserts into the trie, so every
//! production `find_file_type_id` is CONTINUE->UNKNOWN (the suite's
//! six tautologies). The traversal arm is still ported literally and
//! pinned by witness-grown tries through the public API.

use crate::hash::GHash;
use std::rc::Rc;

pub const MAX_BRANCH: usize = (u8::MAX as usize) + 1; // UINT8_MAX + 1
pub const SNORT_FILE_TYPE_UNKNOWN: u32 = u16::MAX as u32;
pub const SNORT_FILE_TYPE_CONTINUE: u32 = 0;
pub const FILE_ID_MAX: usize = 1024;

/// C ABI: sizeof(IdentifierNode) = type_id + state + offset + pad
/// (16) + 256 next[] pointers (2048) = 2064, pinned by the harness
/// transcript (`sznode=2064`, `A1 mem=2064`). The Rust node uses
/// Rc/Vec cells, but memory_usage() tracks the C byte accounting:
/// calloc_mem is always called with this constant for nodes, exactly
/// like C's calloc_mem(sizeof(*node)).
pub const C_IDENTIFIER_NODE_SIZE: usize = 2064;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum IdNodeState {
    New = 0,   // ID_NODE_NEW
    Used = 1,  // ID_NODE_USED
    Shared = 2, // ID_NODE_SHARED
}

#[derive(Clone, Debug, Default)]
pub struct FileMeta {
    // C default members; FileMeta(type_id,...) ctor is a caller-side
    // aggregate construction in the transcripts.
    pub rev: u32,
    pub id: u32,
    pub r#type: String,
    pub category: String,
    pub version: String,
    pub groups: Vec<String>,
}

impl FileMeta {
    pub fn clear(&mut self) {
        self.rev = 0;
        self.r#type.clear();
        self.id = 0;
        self.category.clear();
        self.version.clear();
        self.groups.clear();
    }
}

/// C stores IdentifierNodes in raw calloc'd blocks (node address
/// identity = trie structure). Rust keeps the same shape with
/// Rc<RefCell<...>> so context pointers survive across find calls.
pub struct CIdentifierNode {
    pub type_id: u32, // magic content to match
    pub state: IdNodeState,
    pub offset: u32, // offset from file start
    pub next: Vec<Option<FIdNode>>, // 256 identifier pointers
}

pub type FIdNode = Rc<std::cell::RefCell<CIdentifierNode>>;

pub type IdMemoryBlocks = Vec<usize>; // C list<void*>: block addresses

/// C ParseError seam (probe witness printed "PE <msg>").
pub trait FileIdErrorSink {
    fn parse_error(&mut self, msg: &str);
}

pub struct FileIdentifier {
    // ---- private in C ----
    identifier_root: Option<FIdNode>, // root of magic tries
    memory_used: u32,                 // track memory usage (calloc_mem)
    identifier_merge_hash: Option<GHash<MergeNodeKey>>,
    pub(crate) file_magic_rules: Vec<FileMeta>, // [FILE_ID_MAX + 1]
    id_memory_blocks: IdMemoryBlocks,
}

/// sizeof(MergeNode) slot of the merge hash: C GHash holds
/// `{IdentifierNode* shared; IdentifierNode* append;}` blobs keyed by
/// pointer identity. No ported production path ever inserts/queries;
/// the hash only exists (Ghash::new) like C's init_merge_hash, so the
/// key type carries the two node addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MergeNodeKey {
    shared_node: u64,
    append_node: u64,
}

// Ghash requires its key type param as a "data" blob in our port;
// check crate::hash::ghash expectations at use sites.

impl FileIdentifier {
    pub fn new() -> Self {
        FileIdentifier {
            identifier_root: None,
            memory_used: 0,
            identifier_merge_hash: None,
            file_magic_rules: vec![FileMeta::default(); FILE_ID_MAX + 1],
            id_memory_blocks: Vec::new(),
        }
    }

    fn init_merge_hash(&mut self) {
        // C: new GHash(1000, sizeof(MergeNode), false, nullptr)
        self.identifier_merge_hash = Some(GHash::new(1000, 16, false, true));
    }

    pub fn memory_usage(&self) -> u32 {
        self.memory_used
    }

    /// C tracks each block's size; the address bookkeeping (`block id
    /// = counter`) stands in for raw pointers (drop frees all, same
    /// as the dtor's snort_free loop).
    fn calloc_mem(&mut self, size: usize) -> usize {
        self.memory_used = self.memory_used.wrapping_add(size as u32); // C uint32 +=
        let id = self.id_memory_blocks.len();
        self.id_memory_blocks.push(id);
        id
    }

    fn new_node(&mut self) -> FIdNode {
        self.calloc_mem(C_IDENTIFIER_NODE_SIZE);
        Rc::new(std::cell::RefCell::new(CIdentifierNode {
            type_id: 0,
            state: IdNodeState::New,
            offset: 0,
            next: vec![None; MAX_BRANCH],
        }))
    }

    /// C static recursion toggles NEW->USED->SHARED->SHARED... on the
    /// whole subtree (state==SHARED early-outs). C keeps these two
    /// trie helpers with `cppcheck-suppress unusedFunction` (entry
    /// point retained for external/conditional/test use); mirror that:
    #[allow(dead_code)]
    pub(crate) fn set_node_state_shared(start: &Option<FIdNode>) {
        let Some(start) = start else {
            return;
        };
        {
            let s = start.borrow();
            if s.state == IdNodeState::Shared {
                return;
            }
        }
        {
            let mut m = start.borrow_mut();
            m.state = match m.state {
                IdNodeState::Used => IdNodeState::Shared,
                _ => IdNodeState::Used,
            };
        }
        let children: Vec<Option<FIdNode>> = {
            let m = start.borrow();
            m.next.clone()
        };
        for c in children {
            Self::set_node_state_shared(&c);
        }
    }

    /// "Clone a trie" — C copies offset/type_id + the next[] pointers
    /// (sharing subtrees), allocating one fresh node.
    #[allow(dead_code)]
    pub(crate) fn clone_node(&mut self, start: &Option<FIdNode>) -> Option<FIdNode> {
        let Some(start) = start else {
            return None;
        };
        // order matters: calloc first (memory_used), then fill
        let s = start.borrow();
        // node = calloc_mem(sizeof(*node)) happens before the copies;
        // Rust: allocate via same bookkeeping path
        drop(s);
        let node = self.new_node();
        {
            let s = start.borrow();
            let mut m = node.borrow_mut();
            m.offset = s.offset;
            m.type_id = s.type_id;
            for index in 0..MAX_BRANCH {
                if s.next[index].is_some() {
                    m.next[index] = s.next[index].clone();
                }
            }
        }
        Some(node)
    }

    pub fn add_file_id<S: FileIdErrorSink>(&mut self, rule: &FileMeta, sink: &mut S) {
        if self.identifier_root.is_none() {
            self.identifier_root = Some(self.new_node());
            self.init_merge_hash();
        }
        let rid = rule.id as usize;
        if rid <= FILE_ID_MAX && self.file_magic_rules[rid].id > 0 {
            sink.parse_error(&format!("file type: rule id {} found duplicate", rule.id));
            return;
        }
        if rid <= FILE_ID_MAX {
            self.file_magic_rules[rid] = rule.clone();
        }
    }

    /// The public find. `context` mirrors C's in/out `void**`.
    /// Returns (file_type_id, new context).
    pub fn find_file_type_id(
        &self,
        buf: &[u8],
        file_offset: u64,
        context: &mut Option<FIdNode>,
    ) -> u32 {
        let mut file_type_id = SNORT_FILE_TYPE_CONTINUE;
        // assert(context): the API contract; Rust models &mut Option.

        if buf.is_empty() {
            // C: !buf || len <= 0 (len==0 hits the len<=0 arm too)
            return SNORT_FILE_TYPE_CONTINUE;
        }

        let root = self.identifier_root.clone();
        if context.is_none() {
            *context = root; // (void*)identifier_root (may be null)
        }

        let mut current = context.take();
        let len = buf.len() as u64;
        let end = file_offset.wrapping_add(len);

        while let Some(cur) = current.clone() {
            if !(cur.borrow().offset as u64 >= file_offset) {
                break;
            }
            if cur.borrow().type_id != 0 {
                // found file id, save and continue
                file_type_id = cur.borrow().type_id;
            }
            if (cur.borrow().offset as u64) >= end {
                // save current state
                *context = Some(cur);
                if file_type_id != 0 {
                    return file_type_id;
                } else {
                    return SNORT_FILE_TYPE_CONTINUE;
                }
            }
            // move to the next level
            let idx = buf[(cur.borrow().offset as u64).wrapping_sub(file_offset) as usize];
            current = cur.borrow().next[idx as usize].clone();
        }

        // either end of magics or passed the current offset
        *context = None;

        if file_type_id == SNORT_FILE_TYPE_CONTINUE {
            file_type_id = SNORT_FILE_TYPE_UNKNOWN;
        }
        file_type_id
    }

    pub fn get_rule_from_id(&self, id: u32) -> Option<&FileMeta> {
        let i = id as usize;
        if i < FILE_ID_MAX && self.file_magic_rules[i].id > 0 {
            Some(&self.file_magic_rules[i])
        } else {
            None
        }
    }

    pub fn get_magic_rule_ids_from_type(
        &self,
        r#type: &str,
        version: &str,
        ids_set: &mut [u64; FILE_ID_MAX / 64],
    ) {
        for w in ids_set.iter_mut() {
            *w = 0; // C reset()
        }
        // C walks i < FILE_ID_MAX indexing file_magic_rules[i]; same
        // elements via iterator (id kept for the set below).
        for rule in self.file_magic_rules.iter().take(FILE_ID_MAX) {
            if r#type == rule.r#type {
                let quoted = format!("\"{version}\"");
                let tmp = if version.is_empty() {
                    String::new()
                } else {
                    quoted
                };
                if tmp.is_empty() || tmp == rule.version {
                    let id = rule.id as usize;
                    if id < FILE_ID_MAX {
                        ids_set[id / 64] |= 1u64 << (id % 64);
                    }
                }
            }
        }
    }
}

impl Default for FileIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Test-visible trie growth seam: the harness probe reached private
/// calloc_mem + identifier_root through the grafted-public header; the
/// Rust parity test uses this equivalent (access control only).
impl FileIdentifier {
    pub fn test_grow(&mut self) -> (FIdNode, [FIdNode; 2]) {
        let root = self.new_node();
        let n1 = self.new_node();
        let n2 = self.new_node();
        root.borrow_mut().offset = 0;
        root.borrow_mut().type_id = 0;
        n1.borrow_mut().offset = 1;
        n1.borrow_mut().type_id = 0;
        n2.borrow_mut().offset = 2;
        n2.borrow_mut().type_id = 42;
        root.borrow_mut().next[b'P' as usize] = Some(Rc::clone(&n1));
        n1.borrow_mut().next[b'D' as usize] = Some(Rc::clone(&n2));
        self.identifier_root = Some(root.clone());
        (root, [n1, n2])
    }
    pub fn root(&self) -> Option<FIdNode> {
        self.identifier_root.clone()
    }
}
