//! Dependency-free SHA-256 (FIPS 180-4) standing in for OpenSSL's EVP
//! SHA-256 chain used by `FileContext::process_file_signature_sha256`
//! (file_lib.cc:1065). The crate has ZERO external dependencies and the
//! host has no openssl dev packages, so the EVP surface the C TU uses
//! is implemented directly:
//!
//! | C (file_lib.cc)                          | Rust here                       |
//! |------------------------------------------|---------------------------------|
//! | `EVP_MD_CTX_new()`                       | `Sha256Ctx::new()`              |
//! | `EVP_DigestInit_ex(ctx, EVP_sha256(), 0)` | `init()` (resets the state)    |
//! | `EVP_DigestUpdate(ctx, d, n)`            | `update(&d[..n])`               |
//! | `EVP_MD_CTX_copy_ex(tmp, ctx)` +         | `snap()` — the port copies the |
//! | `EVP_DigestFinal_ex(tmp, out, &len)`     | running state, finalizes the    |
//! |   (FLUSH arms :1093-1105 / :1117-1129)  | copy: same digest, live ctx     |
//! |                                        | untouched                       |
//! | `EVP_DigestFinal_ex(ctx, out, &len)`     | `finalize()` (END/FULL arms)    |
//! | `EVP_MD_CTX_free(ctx)`                   | drop                            |
//!
//! Known answers pinned by the fctx harness transcript (M1_FULL,
//! verified against real libcrypto EVP in the C probe):
//!     SHA-256("abc") =
//!       BA78 16BF 8F01 CFEA 4141 40DE 5DAE 2223 B003 61A3 9617 7A9C B410 FF61 F200 15AD
//!   (file_lib prints it as 2-byte uppercase pairs, file_lib.cc:1280).
//! The M2 block re-checks the incremental chain:
//!     SHA-256("START12345") = 67B65215... (M2_H1, the FLUSH split point)
//!     SHA-256("START12345MID123456MID456END1") = 57630153... (M2_HREF)

/// The 8 FIPS 180-4 initial hash values H0..H7.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

/// The 64 round constants K0..K63 (first 32 bits of the fractional
/// parts of the cube roots of the first 64 primes, FIPS 180-4).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// Incremental SHA-256 context (the `EVP_MD_CTX` the file_lib.cc
/// signature chain drives). `Clone` is `EVP_MD_CTX_copy_ex`.
#[derive(Clone)]
pub struct Sha256Ctx {
    h: [u32; 8],
    /// pending bytes (< 64)
    buf: [u8; 64],
    buflen: usize,
    /// total message length in bits
    len_bits: u64,
}

impl Default for Sha256Ctx {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Ctx {
    /// `EVP_MD_CTX_new()`: fresh, un-keyed context. `init()` still arms
    /// it (mirrors the C chain: new then DigestInit_ex).
    pub fn new() -> Self {
        Sha256Ctx { h: H0, buf: [0u8; 64], buflen: 0, len_bits: 0 }
    }

    /// `EVP_DigestInit_ex(ctx, EVP_sha256(), 0)`.
    pub fn init(&mut self) {
        self.h = H0;
        self.buflen = 0;
        self.len_bits = 0;
    }

    /// `EVP_DigestUpdate(ctx, d, n)`.
    pub fn update(&mut self, data: &[u8]) {
        self.len_bits = self.len_bits.wrapping_add((data.len() as u64) << 3);
        let mut data = data;
        if self.buflen > 0 {
            let take = (64 - self.buflen).min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            if self.buflen < 64 {
                return;
            }
            block(&mut self.h, &self.buf);
            data = &data[take..];
            self.buflen = 0;
        }
        let mut i = 0usize;
        while i + 64 <= data.len() {
            block(&mut self.h, &data[i..i + 64]);
            i += 64;
        }
        let rem = data.len() - i;
        if rem > 0 {
            self.buf[..rem].copy_from_slice(&data[i..]);
            self.buflen = rem;
        }
    }

    /// `EVP_MD_CTX_copy_ex(tmp, ctx)` + `EVP_DigestFinal_ex(tmp, ...)`:
    /// digest everything fed so far WITHOUT disturbing the live
    /// context (the FILE_SIG_FLUSH arms snapshot the running hash).
    pub fn snap(&self) -> [u8; 32] {
        let mut c = self.clone();
        c.finalize()
    }

    /// `EVP_DigestFinal_ex(ctx, out, &len)` for a fresh context per
    /// call site — take-and-finish; re-`init()` to reuse.
    pub fn finalize(&mut self) -> [u8; 32] {
        // padding: 0x80, zeros, big-endian 64-bit bit length
        let len_bits = self.len_bits;
        let mut pad = [0u8; 128];
        pad[0] = 0x80;
        let padlen = if self.buflen < 56 { 56 - self.buflen } else { 120 - self.buflen };
        self.update_no_count(&pad[..padlen]);
        self.update_no_count(&len_bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn update_no_count(&mut self, data: &[u8]) {
        // update() without the length accounting (finalize owns it)
        let mut data = data;
        if self.buflen > 0 {
            let take = (64 - self.buflen).min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            if self.buflen < 64 {
                return;
            }
            block(&mut self.h, &self.buf);
            data = &data[take..];
            self.buflen = 0;
        }
        let mut i = 0usize;
        while i + 64 <= data.len() {
            block(&mut self.h, &data[i..i + 64]);
            i += 64;
        }
        let rem = data.len() - i;
        if rem > 0 {
            self.buf[..rem].copy_from_slice(&data[i..]);
            self.buflen = rem;
        }
    }
}

/// One SHA-256 compression over a 64-byte block.
fn block(h: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8; 32]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(msg: &[u8]) -> [u8; 32] {
        let mut c = Sha256Ctx::new();
        c.init();
        c.update(msg);
        c.finalize()
    }

    #[test]
    fn abc_nist() {
        // FIPS 180-4 example + the fctx M1_FULL known answer (real
        // libcrypto pinned: vectors.txt M1 "BA78 16BF ... 15AD")
        assert_eq!(
            hex(&digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_nist() {
        assert_eq!(
            hex(&digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn million_a_streaming() {
        // FIPS 180-4 example 3: 1,000,000 x 'a'
        let mut c = Sha256Ctx::new();
        c.init();
        for _ in 0..1000 {
            c.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&c.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn snap_is_copy_ex() {
        // The FLUSH sandwich shape (file_lib.cc:1093-1105): digest the
        // prefix WITHOUT disturbing the live context. The harness M2
        // block pins the same incremental chain.
        let mut c = Sha256Ctx::new();
        c.init();
        c.update(b"START12345");
        let after_start = c.snap();
        assert_eq!(
            hex(&after_start),
            "67b6521515ec7503325fa0299f7fdbaf2cdde6df63b9c8951d7958cec9180f26"
        );
        c.update(b"MID123");
        let after_mid = c.snap();
        // live context still continues
        c.update(b"456MID456END1");
        assert_eq!(
            hex(&c.finalize()),
            "57630153077fcb6b0e7ad66c1477ccbcd09ddc9beb60c956ac1c08f208bd07fa"
        );
        // the END arm's full-stream reference call (M2_HREF) agrees
        assert_eq!(
            hex(&digest(b"START12345MID123456MID456END1")),
            "57630153077fcb6b0e7ad66c1477ccbcd09ddc9beb60c956ac1c08f208bd07fa"
        );
        // snap() consumed nothing
        assert_eq!(hex(&after_mid), hex(&digest(b"START12345MID123")));
    }

    #[test]
    fn unaligned_feeds_match_whole_message() {
        // byte-at-a-time vs one big update -> identical digest (the C
        // EVP chain is feed-granularity agnostic)
        let msg: Vec<u8> = (0..500u32).map(|i| (i * 31) as u8).collect();
        let one = digest(&msg);
        let mut c = Sha256Ctx::new();
        c.init();
        for b in &msg {
            c.update(&[*b]);
        }
        assert_eq!(c.finalize(), one);
    }
}
