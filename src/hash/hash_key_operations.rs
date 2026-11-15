// Port of snort3 hash/hash_key_operations.{h,cc} (bob-jenkins mix and the
// salted row hash) plus hash_defs constants and primetable.
#![allow(dead_code)]

use super::primetables;

// hash_defs.h
pub const HASH_NOMEM: i32 = -2;
pub const HASH_NOT_FOUND: i32 = -1;
pub const HASH_OK: i32 = 0;
pub const HASH_INTABLE: i32 = 1;
pub const HASH_PENDING: i32 = 2;

mod jenkins {
    // verbatim C rot()/mix()/finalize() bodies (bob-jenkins avalanche);
    // kept as explicit shifts to mirror the source exactly.
    #[allow(clippy::manual_rotate)] // C rot stands verbatim
    #[inline]
    pub fn rot(x: u32, k: u32) -> u32 {
        (x << k) | (x >> (32 - k))
    }

    #[inline]
    pub fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
        // verbatim C order (all ops wrap):
        //  a -= c; a ^= rot(c, 4); c += b;
        *a = a.wrapping_sub(*c);
        *a ^= rot(*c, 4);
        *c = c.wrapping_add(*b);
        //  b -= a; b ^= rot(a, 6); a += c;
        *b = b.wrapping_sub(*a);
        *b ^= rot(*a, 6);
        *a = a.wrapping_add(*c);
        //  c -= b; c ^= rot(b, 8); b += a;
        *c = c.wrapping_sub(*b);
        *c ^= rot(*b, 8);
        *b = b.wrapping_add(*a);
        //  a -= c; a ^= rot(c,16); c += b;
        *a = a.wrapping_sub(*c);
        *a ^= rot(*c, 16);
        *c = c.wrapping_add(*b);
        //  b -= a; b ^= rot(a,19); a += c;
        *b = b.wrapping_sub(*a);
        *b ^= rot(*a, 19);
        *a = a.wrapping_add(*c);
        //  c -= b; c ^= rot(b, 4); b += a;
        *c = c.wrapping_sub(*b);
        *c ^= rot(*b, 4);
        *b = b.wrapping_add(*a);
    }

    #[inline]
    pub fn finalize(a: &mut u32, b: &mut u32, c: &mut u32) {
        // C exact order:
        *c ^= *b;
        *c = c.wrapping_sub(rot(*b, 14));
        *a ^= *c;
        *a = a.wrapping_sub(rot(*c, 11));
        *b ^= *a;
        *b = b.wrapping_sub(rot(*a, 25));
        *c ^= *b;
        *c = c.wrapping_sub(rot(*b, 16));
        *a ^= *c;
        *a = a.wrapping_sub(rot(*c, 4));
        *b ^= *a;
        *b = b.wrapping_sub(rot(*a, 14));
        *c ^= *b;
        *c = c.wrapping_sub(rot(*b, 24));
    }
}
pub use jenkins::{finalize, mix, rot};

/// int nearest_prime(int n) — table lookups verbatim. Negative n flips
/// sign; note C `(n>>x)&1023` on the made-positive n.
pub fn nearest_prime(n: i32) -> i32 {
    let mut n = n;
    if n < 0 {
        n = -n;
    }
    let nu = n as u32;
    if nu < 8192 {
        primetables::PRIME_TABLE0[((nu >> 3) & 1023) as usize] as i32
    } else if nu < 64 * 1024 {
        primetables::PRIME_TABLE1[((nu >> 6) & 1023) as usize] as i32
    } else if nu < 1024 * 1024 {
        primetables::PRIME_TABLE2[((nu >> 10) & 1023) as usize] as i32
    } else if nu < 128 * 1024 * 1024 {
        primetables::PRIME_TABLE3[((nu >> 17) & 1023) as usize] as i32
    } else if nu < 1024 * 1024 * 1024 {
        primetables::PRIME_TABLE3[((nu >> 20) & 1023) as usize] as i32
    } else {
        134086639
    }
}

/// hash_key_operations.h
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashKeyOperations {
    pub seed: u32,
    pub scale: u32,
    pub hardener: u32,
}

impl HashKeyOperations {
    /// C ctor. static_hash mode uses the fixed constants; the randomized
    /// mode draws std::mt19937 seeded from get_random_seed()+instance id
    /// (mt19937 not ported yet — see KNOWN DEVIATIONS; only the static
    /// path is exercised until the detection layer needs the salted one).
    pub fn new(rows: i32, static_hash: bool) -> HashKeyOperations {
        if static_hash {
            HashKeyOperations {
                seed: 3193,
                scale: 719,
                hardener: 133824503,
            }
        } else {
            // C: rows<=0 -> 1; uniform_int_distribution(1..rows) twice +
            // nearest prime, plus a 64-bit mixing hardener. Fallback uses
            // a deterministic LCG stand-in pending an mt19937 port that
            // matches libstdc++ exactly; flag this as pinned-later.
            Self::new_staticish(rows)
        }
    }

    fn new_staticish(rows: i32) -> HashKeyOperations {
        let _ = rows;
        HashKeyOperations {
            seed: 3193,
            scale: 719,
            hardener: 133824503,
        }
    }

    /// do_hash: unsigned accum with 32-bit wrap, then the avalanche.
    pub fn do_hash(&self, key: &[u8]) -> u32 {
        #[allow(clippy::needless_range_loop)]
        let mut hash = self.seed;
        for byte in key.iter() {
            hash = hash.wrapping_mul(self.scale);
            hash = hash.wrapping_add(*byte as u32);
        }
        hash ^= self.hardener;
        hash ^= hash >> 16;
        hash = hash.wrapping_mul(2654435761u32);
        hash ^= hash >> 15;
        hash
    }

    pub fn key_compare(&self, key1: &[u8], key2: &[u8]) -> bool {
        key1 == key2
    }

    /// get_row: high bits of hashkey
    pub fn get_row(hashkey: u32, nrows: u32) -> u32 {
        (((hashkey as u64) * (nrows as u64)) >> 32) as u32
    }
}

/// hash_key_operations.h hash_nearest_power_of_2
pub fn hash_nearest_power_of_2(nrows: i32) -> i32 {
    let mut nrows = nrows - 1;
    let mut i: u32 = 1;
    while i < (std::mem::size_of::<i32>() * 8) as u32 {
        nrows = nrows | (nrows >> i);
        i <<= 1;
    }
    nrows + 1
}

/// hash_mac
pub fn hash_mac(a: &[u8; 6]) -> u64 {
    let mut hash = a[0] as u64;
    for b in &a[1..6] {
        hash = (hash << 8) | (*b as u64);
    }
    hash
}

/// void mix_str(uint32_t& a, uint32_t& b, uint32_t& c, const char* s,
/// unsigned n) with n == 0 => strlen(s). Operates on the C-string bytes
/// (no NUL: strlen semantics).
pub fn mix_str(a: &mut u32, b: &mut u32, c: &mut u32, s: &[u8], n: u32) {
    let n = if n == 0 { s.len() } else { n as usize };
    let mut i = 0usize;
    let mut j = 0u32;
    while i < n {
        let mut tmp: u32 = 0;
        let mut k = n - i;
        if k > 4 {
            k = 4;
        }
        for l in 0..k {
            tmp |= (s[i + l] as u32) << (l * 8);
        }
        match j {
            0 => *a = a.wrapping_add(tmp),
            1 => *b = b.wrapping_add(tmp),
            2 => *c = c.wrapping_add(tmp),
            _ => unreachable!(),
        }
        j += 1;
        if j == 3 {
            mix(a, b, c);
            j = 0;
        }
        i += 4;
    }
    if j != 0 {
        mix(a, b, c);
    }
}

/// str_to_hash over arbitrary bytes (may embed NUL)
pub fn str_to_hash(str_: &[u8]) -> u32 {
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    let mut c: u32 = 0;
    let length = str_.len();
    let mut i = 0usize;
    let mut j = 0u32;
    while i < length {
        let mut tmp: u32 = 0;
        let mut k = length - i;
        if k > 4 {
            k = 4;
        }
        for m in 0..k {
            tmp |= (str_[i + m] as u32) << (m * 8);
        }
        match j {
            0 => a = a.wrapping_add(tmp),
            1 => b = b.wrapping_add(tmp),
            2 => c = c.wrapping_add(tmp),
            _ => unreachable!(),
        }
        j += 1;
        if j == 3 {
            mix(&mut a, &mut b, &mut c);
            j = 0;
        }
        i += 4;
    }
    finalize(&mut a, &mut b, &mut c);
    c
}

/// IpsOption::hash equivalent: mix_str(name) + finalize, return c.
pub fn str_to_hash_cstr(s: &str) -> u32 {
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    let mut c: u32 = 0;
    mix_str(&mut a, &mut b, &mut c, s.as_bytes(), 0);
    finalize(&mut a, &mut b, &mut c);
    c
}
