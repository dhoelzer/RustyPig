// Port of snort3 utils/bits.h bitset typedefs (std::bitset<N> subset).
#![allow(dead_code)]

/// std::bitset<N> subset used by Value::get_bits and BitList options.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FixedBitSet<const N: usize> {
    bits: Vec<bool>,
}

impl<const N: usize> Default for FixedBitSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FixedBitSet<N> {
    pub fn new() -> Self {
        FixedBitSet {
            bits: vec![false; N],
        }
    }

    pub fn size(&self) -> usize {
        N
    }

    pub fn reset(&mut self) {
        for b in self.bits.iter_mut() {
            *b = false;
        }
    }

    pub fn set(&mut self, n: usize) {
        self.bits[n] = true;
    }

    pub fn test(&self, n: usize) -> bool {
        self.bits[n]
    }

    pub fn count(&self) -> usize {
        self.bits.iter().filter(|b| **b).count()
    }
}

// C typedefs: std::bitset<65536> PortBitSet; <4096> VlanBitSet; <256> ByteBitSet
pub type CPortBitSet = FixedBitSet<65536>;
pub type VlanBitSet = FixedBitSet<4096>;
pub type ByteBitSet = FixedBitSet<256>;
