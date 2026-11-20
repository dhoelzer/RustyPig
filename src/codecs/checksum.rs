//! Port of `src/codecs/ip/checksum.h` (284 L, all-inline header lib) —
//! row 18b.  Ground: snort3-src @ fe29cbe, md5 b43628f369e16b1d5c093ff447d3e954.
//!
//! The C original lives ENTIRELY in a header: checksum.h:68-:75 states the
//! reason (multiple DSOs consume the checksums; linker-flag fragility beat
//! putting the details in a TU). nm-Proven at tools/csum_harness build.sh
//! E3: the header compiled as its own TU emits ZERO text symbols (`T`/`W`)
//! — every definition below is a 1:1 Rust counterpart of a C `inline` (or,
//! for the C forward decl at checksum.h:59, the public `cksum_add` entry).
//!
//! Endianness posture (deviations row 18b / csum PLAN §1, §5 Q1): C
//! `detail::read_word` (:83-:88) is a native-endian memcpy of a `uint16_t`
//! — little-endian on the x86_64 ground host. The whole ones-complement
//! layer below is therefore written in LE word terms (`u16::from_le_bytes`),
//! which is value-identical on the pinned host and makes the ODD-TAIL arm
//! (:102-:103 — the final byte is summed RAW, not swapped) auditable: the
//! sum-over-whole-words is byte-swap symmetric (Zimmermann), the tail is
//! NOT, and vectors K_cksum16=0xbc43 / K_cksum15=0xbb44 pin that break.
//!
//! C namespace mapping: `checksum::{...}` -> this module; `checksum::detail::{...}`
//! -> `pub mod detail` below. The C overload set (icmp_cksum 2-arg vs 3-arg,
//! tcp/udp Pseudoheader-vs-Pseudoheader6 — :60-:66 decls, :208/:218,
//! :223/:235, :247/:259 bodies) cannot exist in Rust; overloads land as
//! distinct names (`tcp_cksum4`/`tcp_cksum6`, ...) — deviations row 18b.
//! `IpProtocol` rides the landed 17d home `framework::codec::ip_protocol`
//! (codec.rs:86-:113; the 17d "checksum.rs RIDES it" ruling, csum PLAN §6:
//! protocol_ids.h:54-:77 values re-measured there).

use crate::framework::codec::IpProtocol;

// ---- unions Pseudoheader / Pseudoheader6 (checksum.h:30-:42 / :44-:56) ----
// C models these as unions: a 12-/36-byte struct aliasing `uint16_t arr[6]`
// / `arr[18]`, with static_asserts (:41, :55) pinning both views at the
// same size. Rust does NOT model C++ unions (deviations row 18b, R5): the
// struct field view is the ported type and the `arr` word view is provided
// by explicit byte-pinning helpers (`arr_words()`), so the union-punning
// observable — the harness word dumps PH4 `arr=007f 0100 007f 0100 0600
// 1400 sizeof=12` and PH6 `sizeof=36 arr17=0x1400` — replays exactly.
// Field init semantics of `Pseudoheader6 ph6{}` (test :127) == Default
// (all zero bytes).

/// The C struct member of `union Pseudoheader` (checksum.h:32-:39), and —
/// via `arr_words()`/`as_bytes()` — the `uint16_t arr[6]` member (:40).
/// static_assert(sizeof(hdr) == sizeof(arr)) at :41 restated below.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pseudoheader {
    /// uint32_t sip (:34) — raw bits as stored (wire-order on the callers).
    pub sip: u32,
    /// uint32_t dip (:35)
    pub dip: u32,
    /// uint8_t zero (:36) — the padding byte before `protocol` on LE lays
    /// at arr[2] high byte (PH4 pin arr[2]=007f with zero=0 protocol=06).
    pub zero: u8,
    /// IpProtocol protocol (:37) — a u8 (protocol_ids.h:54).
    pub protocol: IpProtocol,
    /// uint16_t len (:38) — the C callers store NETWORK order here
    /// (`htons(20)` test :174); the harness/probe pins raw bits 0x1400.
    pub len: u16,
}

// checksum.h:41 static_assert(sizeof(hdr) == sizeof(arr),
// "IPv4 pseudoheader must be 12 bytes") — C struct is 4+4+1+1+2 = 12 with
// natural alignment; Rust field order identical, repr assert below.
const _: () = assert!(std::mem::size_of::<Pseudoheader>() == 12);

impl Pseudoheader {
    /// The union's `uint16_t arr[6]` view (:40) computed byte-wise exactly
    /// as the LE compiler lays the struct out (sip@0 dip@4 zero@8 proto@9
    /// len@10) — the PH4 vectors line is this word dump.
    pub fn arr_words(&self) -> [u16; 6] {
        let b = self.as_bytes();
        let mut w = [0u16; 6];
        for i in 0..6 {
            w[i] = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]);
        }
        w
    }

    /// Byte view of the 12-byte union storage (field offsets as in C:
    /// the C struct has no padding — 12 == sizeof pinned by :41).
    pub fn as_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.sip.to_le_bytes());
        b[4..8].copy_from_slice(&self.dip.to_le_bytes());
        b[8] = self.zero;
        b[9] = self.protocol;
        b[10..12].copy_from_slice(&self.len.to_le_bytes());
        b
    }
}

/// The C struct member of `union Pseudoheader6` (checksum.h:46-:53), plus
/// the `uint16_t arr[18]` view (:54) via `arr_words()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pseudoheader6 {
    /// uint32_t sip[4] (:48)
    pub sip: [u32; 4],
    /// uint32_t dip[4] (:49)
    pub dip: [u32; 4],
    /// uint8_t zero (:50)
    pub zero: u8,
    /// IpProtocol protocol (:51)
    pub protocol: IpProtocol,
    /// uint16_t len (:52) — network-order bits (PH6 pin arr[17]=0x1400).
    pub len: u16,
}

// checksum.h:55 static_assert(sizeof(hdr) == sizeof(arr),
// "IPv6 pseudoheader must be 36 bytes") — 16+16+1+1+2 = 36.
const _: () = assert!(std::mem::size_of::<Pseudoheader6>() == 36);

impl Pseudoheader6 {
    /// The union's `uint16_t arr[18]` view (:54), byte-wise LE.
    pub fn arr_words(&self) -> [u16; 18] {
        let b = self.as_bytes();
        let mut w = [0u16; 18];
        for i in 0..18 {
            w[i] = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]);
        }
        w
    }

    /// Byte view of the 36-byte union storage (sip@0 dip@16 zero@32
    /// protocol@33 len@34 — no C padding; :55 pins the total).
    pub fn as_bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        for i in 0..4 {
            b[4 * i..4 * i + 4].copy_from_slice(&self.sip[i].to_le_bytes());
            b[16 + 4 * i..16 + 4 * i + 4].copy_from_slice(&self.dip[i].to_le_bytes());
        }
        b[32] = self.zero;
        b[33] = self.protocol;
        b[34..36].copy_from_slice(&self.len.to_le_bytes());
        b
    }
}

// The C forward declarations (:59-:66) need no Rust form (single-pass); one
// of them is load-bearing for the nm witness story (deviations row 18b):
// the `static uint16_t cksum_add(...)` fwd decl at :59 leaves a TU-local
// `t _ZN8checksumL9cksum_addEPKvm` symbol at -O0 (csum build.sh:92 grep)
// even though the DEFINITION at :280-:281 is `inline`. Rust's public
// `cksum_add` below mirrors that definition verbatim.

// ============================================================================
// namespace detail (checksum.h:81-:206) — the "IT IS HIGHLY RECOMMENDED to
// use the above API. Rather than calling any of the following recommendations
// directly" layer (:77-:80).
// ============================================================================
pub mod detail {
    use super::{Pseudoheader, Pseudoheader6};

    /// `detail::read_word` (checksum.h:83-:88): memcpy of a uint16_t — on
    /// the pinned LE host this equals `u16::from_le_bytes`; memcpy ALSO
    /// means no alignment requirement (R5): any byte offset is legal, so
    /// the slice read must not assume an aligned u16 (no unsafe align trick).
    #[inline]
    pub fn read_word(data: &[u8]) -> u16 {
        u16::from_le_bytes([data[0], data[1]])
    }

    /// `detail::cksum_add(buf, len, cksum)` (checksum.h:90-:109) VERBATIM:
    /// while len > 1 { cksum += read_word(data); data += 2; len -= 2 } (:94-
    /// :99); odd tail `if (len & 0x01) cksum += *data;` (:102-:103, the RAW
    /// last byte — NOT swap-invariant, Q1); fold (:105-:106) then
    /// `(uint16_t)(~cksum)` (:108). uint32 accumulate with wrapping ops:
    /// max 48 words (36 ph + 20 hdr on the largest pseudoheader... worst
    /// 60 x 0xffff < 2^32 in practice, but the C arithmetic is mod-2^32 —
    /// `wrapping_add` is the literal transcription, never a debug panic).
    /// `(uint16_t)(~cksum)` == `!(...).0 as u16` truncation (:108 cast is
    /// load-bearing for the all-ones input: cksum_add(_,0) = ~0 = 0xffff,
    /// K_cksum0 pin, Q2).
    #[inline]
    pub fn cksum_add(buf: &[u8], len: usize, mut cksum: u32) -> u16 {
        // A Rust slice is (ptr, len) — pin the walk to the CALLER-declared
        // `len` (C `buf` + `len`), which may be SHORTER than the slice
        // (suite fixture: short_buf[16] walked with declared len=15,
        // vectors K_cksum15). Declared len > real buffer = C OOB walk =
        // Rust index panic posture (never exercised by the ground suite).
        let mut data: &[u8] = &buf[..len];

        while data.len() > 1 {
            cksum = cksum.wrapping_add(read_word(data) as u32); // :96
            data = &data[2..]; // :97/:98 `data += 2; len -= 2` — the Rust
            // slice pair (ptr,len) advances exactly like the C two locals.
        }

        // :102-:103 if ( len & 0x01 ) cksum += *data;  -- the odd tail:
        // the final BYTE summed raw (never word-swapped) — the Q1 arm that
        // breaks the ones-complement swap symmetry (0xbb44 at len=15 vs
        // the byte-swapped 16-byte walk).
        if data.len() & 0x01 != 0 {
            cksum = cksum.wrapping_add(data[0] as u32);
        }

        // :105-:106 the two-step fold, LITERAL (no masking shortcut — a
        // masked single fold would silently drop the second carry):
        cksum = (cksum >> 16) + (cksum & 0x0000ffff);
        cksum += cksum >> 16;
        // :108 return (uint16_t)(~cksum);  -- bitwise NOT on the uint32_t,
        // then the truncating cast, kept literal (Q2: the len=0 arm pins
        // (~0x00000000 as u16) == 0xffff exactly).
        (!cksum) as u16
    }

    /// `detail::add_ipv4_pseudoheader` (checksum.h:111-:122): six explicit
    /// `cksum += h[i]` adds over `ph4.arr` (:116-:121) — kept as six adds,
    /// not a fold over the array, so the line-for-line audit against C
    /// holds (the sum is order-equivalent anyway, but the literal shape is
    /// ported, per the row's literal-transcription rule).
    #[inline]
    pub fn add_ipv4_pseudoheader(ph4: Pseudoheader, cksum: &mut u32) {
        let h = ph4.arr_words();

        /* ipv4 pseudo header must have 12 bytes */
        *cksum = cksum.wrapping_add(h[0] as u32);
        *cksum = cksum.wrapping_add(h[1] as u32);
        *cksum = cksum.wrapping_add(h[2] as u32);
        *cksum = cksum.wrapping_add(h[3] as u32);
        *cksum = cksum.wrapping_add(h[4] as u32);
        *cksum = cksum.wrapping_add(h[5] as u32);
    }

    /// `detail::add_ipv6_pseudoheader` (checksum.h:124-:147): eighteen
    /// explicit adds (:129-:146), ported with the same literal count.
    #[inline]
    pub fn add_ipv6_pseudoheader(ph6: Pseudoheader6, cksum: &mut u32) {
        let h = ph6.arr_words();

        /* PseudoHeader must have 36 bytes */
        *cksum = cksum.wrapping_add(h[0] as u32);
        *cksum = cksum.wrapping_add(h[1] as u32);
        *cksum = cksum.wrapping_add(h[2] as u32);
        *cksum = cksum.wrapping_add(h[3] as u32);
        *cksum = cksum.wrapping_add(h[4] as u32);
        *cksum = cksum.wrapping_add(h[5] as u32);
        *cksum = cksum.wrapping_add(h[6] as u32);
        *cksum = cksum.wrapping_add(h[7] as u32);
        *cksum = cksum.wrapping_add(h[8] as u32);
        *cksum = cksum.wrapping_add(h[9] as u32);
        *cksum = cksum.wrapping_add(h[10] as u32);
        *cksum = cksum.wrapping_add(h[11] as u32);
        *cksum = cksum.wrapping_add(h[12] as u32);
        *cksum = cksum.wrapping_add(h[13] as u32);
        *cksum = cksum.wrapping_add(h[14] as u32);
        *cksum = cksum.wrapping_add(h[15] as u32);
        *cksum = cksum.wrapping_add(h[16] as u32);
        *cksum = cksum.wrapping_add(h[17] as u32);
    }

    // checksum.h:149-:151 constexpr std::size_t length floors.
    pub const TCP_MIN_HEADER_LEN: usize = 20;
    pub const UDP_MIN_HEADER_LEN: usize = 8;
    pub const IP_MIN_HEADER_LEN: usize = 20;

    /// `detail::add_tcp_header(d, len, cksum)` (checksum.h:153-:169).
    /// THE 2026 HARDENING REGRESSION (guard :157-:162 + suite header
    /// prose :20-:26): len < 20  =>  len = 0; return. THREE observable
    /// facts measured by the csum probe (Q3): len==0 (suite CHECK_EQUAL
    /// :67), cksum INPUT UNTOUCHED (probe cks=0x0000), and the pointer
    /// NOT advanced (probe ptr_moved=0 — beyond the C suite, pinned by
    /// vectors G_tcp). NEVER the pre-hardening `len -= N` size_t underflow
    /// -> ~2^64 cksum_add walk -> SIGSEGV. At len >= 20 the guard is inert
    /// (suite `checksum_valid_inputs` group): 10 read_word adds over the
    /// FIXED TCP_MIN_HEADER_LEN (not hlen), then d += 20, len -= 20
    /// (:165-:168).
    ///
    /// C signature is by-reference (const uint8_t*& d, size_t& len,
    /// uint32_t& cksum); Rust models the in/out triple as (slice view,
    /// len) -> (advanced view, reduced len, updated cksum) — deviations
    /// row 18b; the CALLERS (:230-:232 etc.) re-thread the outputs exactly
    /// like C's reference parameters do. Because a Rust slice carries its
    /// own length, `len` here is the C caller-declared length (which may
    /// EXCEED or EQUAL the slice, never exceed it in the Rust harness
    /// posture): the guard reads `len`, NOT the slice length — a caller
    /// could declare len=4 over a 16-byte buffer (exactly the suite
    /// fixture, short_buf[16] + len=4, checksum_test.cc:48 + :61), and the
    /// walk must respect the DECLARED len like C does.
    #[inline]
    pub fn add_tcp_header<'a>(d: &'a [u8], len: usize, cksum: &mut u32) -> (&'a [u8], usize) {
        // guard a short/corrupt buffer against len underflow and header over-read
        if len < TCP_MIN_HEADER_LEN {
            // :160-:161: len = 0; return;  -- d UNTOUCHED, cksum UNTOUCHED.
            return (d, 0);
        }

        /* TCP hdr must have 20 hdr bytes */
        for i in (0..TCP_MIN_HEADER_LEN).step_by(2) {
            // :166 `cksum += read_word(d + i)` — over the CALLER-declared
            // window (d[..len]), which the guard proved >= 20.
            *cksum = cksum.wrapping_add(read_word(&d[i..]) as u32);
        }
        (
            &d[TCP_MIN_HEADER_LEN..], // :167 d += 20
            len - TCP_MIN_HEADER_LEN, // :168 len -= 20
        )
    }

    /// `detail::add_udp_header` (checksum.h:171-:187). Identical guard
    /// posture (:175-:180, UDP floor 8). NOTE the C statement ORDER quirk
    /// vs its tcp/ip siblings: udp does `len -= ...` at :185 BEFORE
    /// `d += ...` at :186 (tcp :167/:168 and ip :203/:204 go d-then-len) —
    /// no observable difference (independent locals) but recorded so the
    /// line-for-line audit stays honest.
    #[inline]
    pub fn add_udp_header<'a>(d: &'a [u8], len: usize, cksum: &mut u32) -> (&'a [u8], usize) {
        // guard a short/corrupt buffer against len underflow and header over-read
        if len < UDP_MIN_HEADER_LEN {
            return (d, 0);
        }

        /* UDP must have 8 hdr bytes */
        for i in (0..UDP_MIN_HEADER_LEN).step_by(2) {
            *cksum = cksum.wrapping_add(read_word(&d[i..]) as u32);
        }
        (
            &d[UDP_MIN_HEADER_LEN..],
            len - UDP_MIN_HEADER_LEN,
        )
    }

    /// `detail::add_ip_header` (checksum.h:189-:205) — guard :193-:198,
    /// IP floor 20.
    #[inline]
    pub fn add_ip_header<'a>(d: &'a [u8], len: usize, cksum: &mut u32) -> (&'a [u8], usize) {
        // guard a short/corrupt buffer against len underflow and header over-read
        if len < IP_MIN_HEADER_LEN {
            return (d, 0);
        }

        /* IP must be >= 20 bytes */
        for i in (0..IP_MIN_HEADER_LEN).step_by(2) {
            *cksum = cksum.wrapping_add(read_word(&d[i..]) as u32);
        }
        (
            &d[IP_MIN_HEADER_LEN..],
            len - IP_MIN_HEADER_LEN,
        )
    }
}

// ============================================================================
// public API (checksum.h:208-:281) — the C overload set lands as distinct
// names: {icmp,tcp,udp}_{cksum}{4,6} by which Pseudoheader type the C
// overload resolved (deviations row 18b; call map in csum PLAN §3 pins
// WHO takes which arm once the codec rows land).
// ============================================================================

/// `icmp_cksum(buf, len, ph)` — 3-arg/IPv6 form (checksum.h:208-:216):
/// cksum=0, add_ipv6_pseudoheader, then detail::cksum_add(buf, len, cksum).
/// (No header-eating step: ICMP6 rides the pseudoheader only — contrast
/// tcp/udp below.)
#[inline]
pub fn icmp_cksum_v6(buf: &[u8], len: usize, ph: Pseudoheader6) -> u16 {
    let mut cksum = 0u32;

    detail::add_ipv6_pseudoheader(ph, &mut cksum);
    detail::cksum_add(buf, len, cksum)
}

/// `icmp_cksum(buf, len)` — 2-arg form (checksum.h:218-:221): plain
/// cksum_add over init 0. (The cd_icmp4 :588 / packet_manager :641 encode
/// path will call this row-20-adjacent arm.)
#[inline]
pub fn icmp_cksum(buf: &[u8], len: usize) -> u16 {
    detail::cksum_add(buf, len, 0)
}

/// `tcp_cksum(buf, len, const Pseudoheader&)` — IPv4 form (checksum.h:223-
/// :233): ph4 adds, then add_tcp_header EATS the fixed 20-byte header
/// (:231), then the residual (data) walks through detail::cksum_add (:232).
/// The guard interplay is what the suite pins: short len kills the header
/// walk AND zeroes the residual — P_tcp4_len4=0xf9ff == ~ph4_sum exactly.
#[inline]
pub fn tcp_cksum4(buf: &[u8], len: usize, ph: Pseudoheader) -> u16 {
    let mut cksum = 0u32;

    detail::add_ipv4_pseudoheader(ph, &mut cksum);
    let (data, len) = detail::add_tcp_header(buf, len, &mut cksum);
    detail::cksum_add(data, len, cksum)
}

/// `tcp_cksum(buf, len, const Pseudoheader6&)` — IPv6 overload (:235-:245):
/// add_ipv6_pseudoheader + the SAME add_tcp_header/cksum_add tail.
/// tcp_cksum(short_buf, 4, ph6{}) = 0xffff: empty ph6 + guard-zeroed len
/// => cksum stays 0 => ~0 fold => 0xffff (K/P_tcp6 pin).
#[inline]
pub fn tcp_cksum6(buf: &[u8], len: usize, ph: Pseudoheader6) -> u16 {
    let mut cksum = 0u32;

    detail::add_ipv6_pseudoheader(ph, &mut cksum);
    let (data, len) = detail::add_tcp_header(buf, len, &mut cksum);
    detail::cksum_add(data, len, cksum)
}

/// `udp_cksum(buf, len, const Pseudoheader&)` — IPv4 form (:247-:257),
/// UDP_MIN 8-byte header eat via add_udp_header.
#[inline]
pub fn udp_cksum4(buf: &[u8], len: usize, ph: Pseudoheader) -> u16 {
    let mut cksum = 0u32;

    detail::add_ipv4_pseudoheader(ph, &mut cksum);
    let (data, len) = detail::add_udp_header(buf, len, &mut cksum);
    detail::cksum_add(data, len, cksum)
}

/// `udp_cksum(buf, len, const Pseudoheader6&)` — IPv6 overload (:259-:269).
#[inline]
pub fn udp_cksum6(buf: &[u8], len: usize, ph: Pseudoheader6) -> u16 {
    let mut cksum = 0u32;

    detail::add_ipv6_pseudoheader(ph, &mut cksum);
    let (data, len) = detail::add_udp_header(buf, len, &mut cksum);
    detail::cksum_add(data, len, cksum)
}

/// `ip_cksum(buf, len)` (checksum.h:271-:278): NO pseudoheader; add_ip_header
/// eats the fixed 20 bytes, residual walks cksum_add. ip_cksum(short_buf, 4)
/// = 0xffff — guard zeroes len, 0 words, fold(~0) (P_ip_len4 pin).
#[inline]
pub fn ip_cksum(buf: &[u8], len: usize) -> u16 {
    let mut cksum = 0u32;

    let (data, len) = detail::add_ip_header(buf, len, &mut cksum);
    detail::cksum_add(data, len, cksum)
}

/// `cksum_add(buf, len)` — the public general-case entry (checksum.h:59
/// fwd decl + :280-:281 definition): `return detail::cksum_add(buf, len, 0);`
/// verbatim. The :59-vs-:280 pairing is the nm witness `t _ZN8checksumL9cksum_addEPKvm`
/// (csum build.sh:92) — no Rust equivalent needed, kept as a doc pin
/// (deviations row 18b, Q6).
#[inline]
pub fn cksum_add(buf: &[u8], len: usize) -> u16 {
    detail::cksum_add(buf, len, 0)
}
