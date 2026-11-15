// Port of snort3 utils/sflsq.{h,cc}: SF_LIST doubly-linked list with
// pointer-to-pointer cursors. Quirks preserved verbatim:
//   * sflist_add_before(nullptr lnode) is a no-op; lnode == head delegates
//     to add_head;
//   * sflist_first sets the cursor to head THEN returns its data, and
//     sflist_next advances the cursor THEN returns its data (same protocol
//     as GHash find_first);
//   * count is an unsigned maintenance counter (int in the exported API).
#![allow(clippy::needless_option_as_deref)]

const NIL: usize = usize::MAX;

#[derive(Clone, Copy, Debug)]
struct Node<T> {
    next: usize,
    prev: usize,
    ndata: T,
    live: bool,
}

/// Stands for the C `SF_LNODE**` cursor: names a node in `list`, not the list.
#[derive(Clone, Copy, Debug, Default)]
pub struct ListCursor {
    node: usize,
    valid: bool,
}

/// C exposes the raw `SF_LNODE*` cursor; null it after exhaustion so
/// probes/tests can observe the same state.
pub fn cursor_is_null(v: &ListCursor) -> bool {
    !v.valid
}

pub struct SfList<T> {
    head: usize,
    tail: usize,
    count: u32,
    nodes: Vec<Node<T>>,
}

impl<T: Copy> Default for SfList<T> {
    fn default() -> Self {
        Self::new()
    }
}

// sflist_new + sflist_init
// T: Copy mirrors the C NODE_DATA = void* payload semantics.
impl<T: Copy> SfList<T> {
    pub fn new() -> Self {
        SfList {
            head: NIL,
            tail: NIL,
            count: 0,
            nodes: Vec::new(),
        }
    }

    pub fn init(&mut self) {
        self.count = 0;
        self.head = NIL;
        self.tail = NIL;
        self.nodes.clear();
    }

    pub fn count(&self) -> i32 {
        self.count as i32
    }

    fn push_node(&mut self, ndata: T) {
        self.nodes.push(Node {
            next: NIL,
            prev: NIL,
            ndata,
            live: true,
        });
    }

    // sflist_add_head
    pub fn add_head(&mut self, ndata: T) {
        if self.head == NIL {
            self.push_node(ndata);
            let n = self.nodes.len() - 1;
            self.head = n;
            self.tail = n;
        } else {
            self.push_node(ndata);
            let q = self.nodes.len() - 1;
            self.nodes[q].next = self.head;
            self.nodes[q].prev = NIL;
            self.nodes[self.head].prev = q;
            self.head = q;
        }
        self.count += 1;
    }

    // sflist_add_tail
    pub fn add_tail(&mut self, ndata: T) {
        if self.head == NIL {
            self.push_node(ndata);
            let n = self.nodes.len() - 1;
            self.head = n;
            self.tail = n;
        } else {
            self.push_node(ndata);
            let q = self.nodes.len() - 1;
            self.nodes[q].next = NIL;
            self.nodes[q].prev = self.tail;
            let t = self.tail;
            self.nodes[t].next = q;
            self.tail = q;
        }
        self.count += 1;
    }

    /// sflist_add_before: `lnode` is a cursor naming an existing node. A dead
    /// or stale handle models C UB-adjacent input; like C we only recognize
    /// the head-delegation and otherwise splice at the recorded links.
    pub fn add_before(&mut self, lnode: ListCursor, ndata: T) {
        if !lnode.valid || lnode.node == NIL {
            return;
        }
        if self.head == lnode.node {
            self.add_head(ndata);
            return;
        }
        let l = lnode.node;
        self.push_node(ndata);
        let q = self.nodes.len() - 1;
        self.nodes[q].next = l;
        self.nodes[q].prev = self.nodes[l].prev;
        let p = self.nodes[l].prev;
        self.nodes[p].next = q;
        self.nodes[l].prev = q;
        self.count += 1;
    }

    // sflist_remove_head
    pub fn remove_head(&mut self) -> Option<T> {
        if self.head == NIL {
            return None;
        }
        let q = self.head;
        let ndata = self.nodes[q].ndata;
        self.nodes[q].live = false;
        self.head = self.nodes[q].next;
        self.count -= 1;
        if self.head == NIL {
            self.tail = NIL;
        } else {
            let h = self.head;
            self.nodes[h].prev = NIL;
        }
        Some(ndata)
    }

    // sflist_remove_tail
    pub fn remove_tail(&mut self) -> Option<T> {
        if self.tail == NIL {
            return None;
        }
        let q = self.tail;
        let ndata = self.nodes[q].ndata;
        self.nodes[q].live = false;
        self.count -= 1;
        self.tail = self.nodes[q].prev;
        if self.tail == NIL {
            self.head = NIL;
        } else {
            let t = self.tail;
            self.nodes[t].next = NIL;
        }
        Some(ndata)
    }

    pub fn first(&self, v: &mut ListCursor) -> Option<&T> {
        v.node = self.head;
        v.valid = self.head != NIL;
        if self.head != NIL {
            Some(&self.nodes[self.head].ndata)
        } else {
            None
        }
    }

    pub fn next<'a>(&'a self, v: &mut ListCursor) -> Option<&'a T> {
        // C: `*v = (*v)->next; if (*v) return (*v)->ndata;` — the cursor IS
        // re-assigned (to null when past the tail), unlike a read-only walk.
        if v.valid && v.node != NIL {
            let n = self.nodes[v.node].next;
            v.node = n;
            if n == NIL {
                v.valid = false;
                return None;
            }
            return Some(&self.nodes[n].ndata);
        }
        None
    }



    /// sflist_free / sflist_free_all / sflist_static_free_all: dropping the
    /// SfList releases everything in Rust; free_all's callback runs per
    /// removed node so caller cleanup is observable.
    pub fn free_all<F: FnMut(T)>(mut self, mut nfree: F) {
        while self.count > 0 {
            if let Some(p) = self.remove_head() {
                nfree(p);
            }
        }
    }
}
