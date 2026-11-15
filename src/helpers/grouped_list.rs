// Port of snort3 src/helpers/grouped_list.h (GroupedList<T>).
//
// Original: Copyright (C) 2022-2026 Cisco and/or its affiliates.
//
// The C++ original is a doubly-linked container (list 1: prev/next threaded
// around a holder sentinel) whose elements additionally chain into disjoint
// groups (list 2: mate). Each element's `grp` is a pointer-to-pointer: either
// the caller's group variable, or the mate field of its group predecessor.
//
// This port reproduces the exact observable semantics (iteration order, group
// head updates on leave/erase, deletion splices) via an index arena:
//   - the arena is owned by the container; holder = element 0
//   - Group is a slot standing in for a `GroupedList*& group` variable
//   - GrpRef models `T** grp` without raw pointers
// Quirks preserved:
//   - appending pushes the new element to the FRONT of its group chain
//     (group = this), so group iteration is reverse insertion order
//   - leave_group() on an already-left element is a no-op (grp == null)
//   - erasing an element that is referenced by a dead mate is not possible
//     here; see KNOWN DEVIATIONS.md for the one unreachable-UB divergence.

#![allow(dead_code)]

use std::ops::{Index, IndexMut};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrpRef {
    /// the group handle slot (C++: &group — the caller's variable)
    Group(usize),
    /// the `mate` field of element i (C++: &mate of the predecessor element
    /// that points at this one)
    MateOf(usize),
}

#[derive(Clone, Debug)]
struct Node<T> {
    value: T,
    prev: usize, // container chain indices; 0 == holder
    next: usize,
    mate: Option<usize>, // group chain
    grp: Option<GrpRef>,
    holder: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElemRef(pub usize);

pub struct GroupedList<T> {
    nodes: Vec<Node<T>>, // node 0 is the holder, always present
    groups: Vec<Option<usize>>, // group slot -> head element (or None)
    group_alive: Vec<bool>,
}

impl<T: Default> GroupedList<T> {
    /// GroupedList(): holder with prev = next = this.
    pub fn new() -> Self {
        let mut g = GroupedList {
            nodes: Vec::with_capacity(8),
            groups: Vec::new(),
            group_alive: Vec::new(),
        };
        g.nodes.push(Node {
            value: T::default(),
            prev: 0,
            next: 0,
            mate: None,
            grp: None,
            holder: true,
        });
        g
    }

    /// A `GroupedList*& group` variable, initialized to nullptr.
    pub fn new_group(&mut self) -> Group {
        self.groups.push(None);
        self.group_alive.push(true);
        Group(self.groups.len() - 1)
    }

    /// GroupedList(cont, group, value) + init() + `group = this`.
    pub fn append(&mut self, group: Group, value: T) -> ElemRef {
        let slot = group.0;
        assert!(self.group_alive[slot], "dangling group reference");
        let head = self.groups[slot];

        let holder = 0usize;
        let prev = self.nodes[holder].prev;
        let next = holder;

        let idx = self.nodes.len();
        self.nodes.push(Node { value, prev, next, mate: head, grp: Some(GrpRef::Group(slot)), holder: false });

        // init(): prev->next = this; next->prev = this;
        self.nodes[prev].next = idx;
        self.nodes[next].prev = idx;
        // init(): if (mate) mate->grp = &mate;
        //   &mate == the mate field of THIS new element (prev head points
        //   into it only after some group surgery); in C++ `&mate` is the
        //   address of the new element's own mate member.
        if let Some(h) = head {
            self.nodes[h].grp = Some(GrpRef::MateOf(idx));
        }
        // group = this
        self.groups[slot] = Some(idx);
        ElemRef(idx)
    }

    /// operator*
    pub fn value(&self, el: ElemRef) -> &T {
        &self.nodes[el.0].value
    }
    pub fn value_mut(&mut self, el: ElemRef) -> &mut T {
        &mut self.nodes[el.0].value
    }

    /// get_next(): the next container element; None when wrapped to holder.
    pub fn get_next(&self, el: ElemRef) -> Option<ElemRef> {
        let n = self.nodes[el.0].next;
        if n == 0 {
            None
        } else {
            Some(ElemRef(n))
        }
    }

    /// void leave_group()
    pub fn leave_group(&mut self, el: ElemRef) {
        let e = el.0;
        assert!(!self.nodes[e].holder, "leave_group(): assert(!holder)");
        let grp = self.nodes[e].grp;
        if let Some(g) = grp {
            let cur = self.deref_grp(g);
            let newv = if cur == Some(e) { self.nodes[e].mate } else { None };
            self.assign_grp(g, newv);
        }
        let mate = self.nodes[e].mate;
        if let Some(m) = mate {
            let g2 = self.nodes[e].grp;
            self.nodes[m].grp = g2;
        }
        self.nodes[e].grp = None;
        self.nodes[e].mate = None;
    }

    /// static unsigned erase_group(GroupedList*& group)
    pub fn erase_group(&mut self, group: Group) -> usize {
        let slot = group.0;
        assert!(self.group_alive[slot], "dangling group reference");
        let mut it = self.groups[slot].take(); // group = nullptr
        let mut cnt = 0;
        while let Some(el) = it {
            let nxt = self.nodes[el].mate;
            cnt += 1;
            self.delete_element(ElemRef(el));
            it = nxt;
        }
        cnt
    }

    /// ~GroupedList() for elements: leave() then remove from list 1.
    /// Values are dropped; element indices of later calls must be re-taken.
    pub fn delete_element(&mut self, el: ElemRef) -> T {
        let e = el.0;
        assert!(!self.nodes[e].holder, "delete of holder");
        // leave(): splice out of list 1
        let (prev, next) = (self.nodes[e].prev, self.nodes[e].next);
        self.nodes[prev].next = next;
        self.nodes[next].prev = prev;
        // the element dies: fix any live group/mate backreferences before removing
        self.fix_dead_refs(e);
        // stable indices: swap the node out; mark with a tombstone
        self.nodes[e].mate = None;
        self.nodes[e].grp = None;
        std::mem::take(&mut self.nodes[e].value)
    }

    fn fix_dead_refs(&mut self, e: usize) {
        if let Some(g) = self.nodes[e].grp {
            // something still points at the deleted element through g: nuke it
            if self.deref_grp(g) == Some(e) {
                self.assign_grp(g, None);
            }
        }
    }

    /// ~GroupedList() for the holder: erase_all(); returns remaining values
    /// in container order.
    pub fn erase_all(&mut self) -> Vec<T> {
        let mut out = Vec::new();
        let mut it = self.nodes[0].next;
        while it != 0 {
            let el = it;
            it = self.nodes[el].next;
            out.push(self.delete_element(ElemRef(el)));
        }
        out
    }

    /// container iteration values (what check_container verifies)
    pub fn container_values(&self) -> Vec<&T> {
        let mut out = Vec::new();
        let mut it = self.nodes[0].next;
        while it != 0 {
            out.push(&self.nodes[it].value);
            it = self.nodes[it].next;
        }
        out
    }

    pub fn group_head(&self, group: Group) -> Option<ElemRef> {
        self.groups[group.0].map(ElemRef)
    }

    // ---- GrpRef pointer-to-pointer machinery ----
    fn deref_grp(&self, g: GrpRef) -> Option<usize> {
        match g {
            GrpRef::Group(s) => self.groups[s],
            GrpRef::MateOf(i) => self.nodes.get(i).and_then(|n| n.mate),
        }
    }

    fn assign_grp(&mut self, g: GrpRef, v: Option<usize>) {
        match g {
            GrpRef::Group(s) => self.groups[s] = v,
            GrpRef::MateOf(i) => {
                // writes through possibly dead refs in C++ are UB; here the
                // element is retained (swap_removed tombstones), so writes
                // always land, matching the live-object case.
                if let Some(n) = self.nodes.get_mut(i) {
                    n.mate = v;
                }
            }
        }
    }
}

impl<T: Default> Default for GroupedList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Default> Index<ElemRef> for GroupedList<T> {
    type Output = T;
    fn index(&self, el: ElemRef) -> &T {
        self.value(el)
    }
}
impl<T: Default> IndexMut<ElemRef> for GroupedList<T> {
    fn index_mut(&mut self, el: ElemRef) -> &mut T {
        self.value_mut(el)
    }
}
