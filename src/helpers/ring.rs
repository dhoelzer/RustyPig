// Port of snort3 src/helpers/ring_logic.h + ring.h (RingLogic / Ring<T>).
//
// Original: Copyright (C) 2014-2026 Cisco and/or its affiliates.
// Semantics preserved exactly: slots = size, usable = size - 1 (one slot lost to
// the full/empty distinction), rx starts 0, wx starts 1, next(ix) wraps.

#[derive(Clone, Debug)]
pub struct RingLogic {
    sz: usize,
    rx: usize,
    wx: usize,
}

impl RingLogic {
    pub fn new(size: usize) -> Self {
        RingLogic { sz: size, rx: 0, wx: 1 }
    }

    fn next(&self, ix: usize) -> usize {
        let ix = ix + 1;
        if ix < self.sz {
            ix
        } else {
            0
        }
    }

    /// return next available position or -1
    pub fn read(&self) -> i64 {
        let nx = self.next(self.rx);
        if nx == self.wx {
            -1
        } else {
            nx as i64
        }
    }

    pub fn write(&self) -> i64 {
        let nx = self.next(self.wx);
        if nx == self.rx {
            -1
        } else {
            self.wx as i64
        }
    }

    /// return true if index advanced
    pub fn push(&mut self) -> bool {
        let nx = self.next(self.wx);
        if nx == self.rx {
            return false;
        }
        self.wx = nx;
        true
    }

    pub fn pop(&mut self) -> bool {
        let nx = self.next(self.rx);
        if nx == self.wx {
            return false;
        }
        self.rx = nx;
        true
    }

    pub fn count(&self) -> i64 {
        let mut c = self.wx as i64 - self.rx as i64 - 1;
        if c < 0 {
            c += self.sz as i64;
        }
        c
    }

    pub fn full(&self) -> bool {
        self.count() == self.sz as i64
    }

    pub fn empty(&self) -> bool {
        self.count() == 0
    }
}

pub struct Ring<T> {
    logic: RingLogic,
    store: Vec<T>,
}

impl<T: Clone + Default> Ring<T> {
    pub fn new(size: usize) -> Self {
        Ring { logic: RingLogic::new(size), store: vec![T::default(); size] }
    }

    pub fn read(&self) -> Option<&T> {
        let ix = self.logic.read();
        if ix < 0 {
            None
        } else {
            Some(&self.store[ix as usize])
        }
    }

    pub fn write(&mut self) -> Option<&mut T> {
        let ix = self.logic.write();
        if ix < 0 {
            None
        } else {
            Some(&mut self.store[ix as usize])
        }
    }

    pub fn push(&mut self) -> bool {
        self.logic.push()
    }

    pub fn pop(&mut self) -> bool {
        self.logic.pop()
    }

    /// Mirrors `T get(T v)`: reads + pops, returning `v` when empty.
    pub fn get(&mut self, v: T) -> T {
        let ix = self.logic.read();
        if ix < 0 {
            return v;
        }
        let out = self.store[ix as usize].clone();
        self.logic.pop();
        out
    }

    /// Mirrors `bool put(const T& v)`: writes + pushes, false when full.
    pub fn put(&mut self, v: T) -> bool {
        let ix = self.logic.write();
        if ix < 0 {
            return false;
        }
        self.store[ix as usize] = v;
        self.logic.push();
        true
    }

    pub fn count(&self) -> i64 {
        self.logic.count()
    }

    pub fn full(&self) -> bool {
        self.logic.full()
    }

    pub fn empty(&self) -> bool {
        self.logic.empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from src/helpers/test/ring_test.cc (Catch): exercises put/get and count.
    // NOTE: with C++ RingLogic (rx=0, wx=1, full when next(wx)==rx), a size-N ring
    // holds at most N-2 items; full() (count()==sz) never fires in the original.
    #[test]
    fn ring_put_get() {
        let mut r: Ring<i32> = Ring::new(6); // 4 usable slots (sz - 2)
        assert!(r.empty());
        for i in 0..4 {
            assert!(r.put(i));
        }
        assert_eq!(r.count(), 4);
        assert!(!r.put(99)); // full
        for i in 0..4 {
            assert_eq!(r.get(-1), i);
        }
        assert!(r.empty());
        assert_eq!(r.get(-7), -7);
    }

    #[test]
    fn ring_logic_wrap_counts() {
        let mut l = RingLogic::new(4); // slots 0..3; usable 2
        assert!(l.empty());
        assert_eq!(l.write(), 1);
        assert!(l.push()); // wx -> 2
        assert_eq!(l.write(), 2);
        assert!(l.push()); // wx -> 3
        assert_eq!(l.count(), 2);
        assert!(!l.push()); // next(3) == rx: full
        assert!(l.pop()); // rx -> 1, frees a slot
        assert_eq!(l.count(), 1);
        assert!(l.push()); // now wraps wx -> 0
        assert_eq!(l.write(), -1); // full again: next(0) == rx(1)
        assert_eq!(l.read(), 2); // slot after rx
        assert!(l.pop()); // rx -> 2
        assert_eq!(l.count(), 1);
    }
}
