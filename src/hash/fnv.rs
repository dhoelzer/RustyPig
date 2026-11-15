// Port of snort3 hash/fnv.h: FNV-1a 64-bit hash.
#![allow(dead_code)]

pub const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
pub const FNV_BASIS: u64 = 0xCBF2_9CE4_8422_2325;

/// FNV-1a hash (draft-eastlake-fnv).
pub fn fnv1a(buf: &[u8]) -> u64 {
    let mut result = FNV_BASIS;
    for b in buf {
        // C: `result = (result ^ byte) * FNV_PRIME;` — wraps mod 2^64.
        result ^= *b as u64;
        result = result.wrapping_mul(FNV_PRIME);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_known_vectors() {
        // Verbatim empty-string case: basis.
        assert_eq!(fnv1a(b""), 0xCBF29CE484222325);
        // Standard FNV-1a test vectors (64-bit): "a", "foobar". These are
        // not upstream snort pins but canonical draft-eastlake FNV-1a values
        // that a correct implementation must hit; a real-world pin for
        // snort's own usage sites arrives with the snort_ml port.
        assert_eq!(fnv1a(b"a"), 0xAF63DC4C8601EC8C);
        assert_eq!(fnv1a(b"foobar"), 0x85944171f73967e8);
    }
}
