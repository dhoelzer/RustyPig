// Port of snort3 src/helpers/bitop.h (BitOp: simple dynamically sized bit vector).
//
// Original: Copyright (C) 2015-2026 Cisco and/or its affiliates.
// Ported to Rust preserving exact semantics:
//   - index(bit) = (bit + 7) >> 3, buffer length = index+1 bytes
//   - mask(bit) = 0x80 >> (bit & 7) (MSB-first within each byte)
//   - set() grows the buffer; is_set() returns false beyond it; clear() is a no-op beyond it.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitOp {
    bit_buf: Vec<u8>,
}

impl BitOp {
    /// Mirrors `BitOp(size_t bit) { bit_buf.resize(index(bit) + 1); }`
    pub fn new(bit: usize) -> Self {
        let mut bit_buf = vec![0u8; 0];
        bit_buf.resize(BitOp::index(bit) + 1, 0);
        BitOp { bit_buf }
    }

    fn size(&self) -> usize {
        self.bit_buf.len()
    }

    fn index(bit: usize) -> usize {
        (bit + 7) >> 3
    }

    fn mask(bit: usize) -> u8 {
        0x80u8 >> (bit & 7)
    }

    pub fn set(&mut self, bit: usize) {
        let i = BitOp::index(bit);
        if i >= self.size() {
            self.bit_buf.resize(i + 1, 0);
        }
        self.bit_buf[i] |= BitOp::mask(bit);
    }

    pub fn is_set(&self, bit: usize) -> bool {
        let i = BitOp::index(bit);
        if i >= self.size() {
            return false;
        }
        (self.bit_buf[i] & BitOp::mask(bit)) != 0
    }

    pub fn clear(&mut self, bit: usize) {
        let i = BitOp::index(bit);
        if i >= self.size() {
            return;
        }
        self.bit_buf[i] &= !BitOp::mask(bit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from src/helpers/test/bitop_test.cc
    fn num_set(bitop: &BitOp, max: usize) -> usize {
        (0..max).filter(|&i| bitop.is_set(i)).count()
    }

    fn is_clear(bitop: &BitOp, max: usize) -> bool {
        num_set(bitop, max) == 0
    }

    #[test]
    fn bitop_zero_initialized() {
        const MAX: usize = 16;
        let bitop = BitOp::new(MAX);
        assert!(is_clear(&bitop, MAX));
    }

    #[test]
    fn bitop_toggle() {
        const MAX: usize = 16;
        let mut bitop = BitOp::new(MAX);
        const BIT: usize = 7;

        bitop.set(BIT);
        assert!(bitop.is_set(BIT));
        assert_eq!(num_set(&bitop, MAX), 1);

        bitop.clear(BIT);
        assert!(!bitop.is_set(BIT));
        assert!(is_clear(&bitop, MAX));
    }

    #[test]
    fn bitop_over_size() {
        const MAX: usize = 16;
        let mut bitop = BitOp::new(MAX);
        let j = MAX / 2;
        let k = MAX + 2;

        bitop.set(j);
        assert!(bitop.is_set(j));

        assert!(!bitop.is_set(k));

        bitop.set(k);
        assert!(bitop.is_set(k));

        assert_eq!(num_set(&bitop, k + 2), 2);
        assert!(bitop.is_set(j));

        bitop.clear(k);
        assert!(!bitop.is_set(k));

        assert!(bitop.is_set(j));
        bitop.clear(j);

        assert!(is_clear(&bitop, k + 2));
    }
}
