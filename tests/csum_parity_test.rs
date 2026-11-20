//! Parity test for `src/codecs/checksum.rs` — row 18b (ip/checksum.h,
//! 284 L all-inline header lib; the 10th-straight ZERO-EDIT gate row).
//!
//! Ground truth #1: `tools/csum_harness/vectors.txt` (16 L, NEVER edited;
//! md5 e4baf7816440e18917d3249597f60b88 re-measured THIS session, two
//! clean `bash build.sh` rebuilds byte-ident; -O0 == -O2 identity is a
//! build.sh arm, vectors_O0/O2 cmp) — the known-answer/guard ladder
//! probe.cc runs against the ground header (E1-E5 receipts in build.sh;
//! PROBE-ONLY harness, no gate: the row adds ZERO .o to any donor link,
//! nm-proven, and the CppUTest suite is unbuildable on this host — the
//! build.sh E4 wall receipt re-proves the wall every build). The whole
//! transcript replays HERE line-for-line as ONE ordered session (the
//! flog/fsvc/fmod replay shape: whole-vector per-index assert_eq,
//! want.len()==16 — ordered, not set-membership).
//!
//! Ground truth #2: snort3-src `src/codecs/ip/test/checksum_test.cc`
//! (201 L, CppUTest dialect: 3 TEST_GROUPs / 10 TESTs / 10 CHECKs —
//! 6 CHECK_EQUAL :67/:78/:89/:100/:181/:192 + 4 CHECK(true) :122/:130/
//! :143/:149). No native C gate is buildable (CppUTest absent — E4);
//! the 16g/16h precedent applies: the 10 TESTs translate BELOW as 10
//! `up_gate_*` fns, statement-for-statement, each citing its C lines.
//! The 4 CHECK(true) arms pin "the call returned" — the C suite checks
//! ONLY that + `len`; the probe (vectors G_*/P_*) pins the full Q3
//! triple (len==0, cksum UNTOUCHED, pointer NOT advanced) and the exact
//! return values — value asserts therefore cite vectors.txt lines,
//! NEVER bare suite inference (unverifiable-fixture rule).
//!
//! Suite-fixture literals (checksum_test.cc:48-:50 short_buf, :166-:167
//! tcph, :187 iph, :170-:174 ph fills, :49/:52 order preserved verbatim)
//! are copied byte-for-byte — NOT re-derived.

use snort3::codecs::checksum as csum;
use snort3::codecs::checksum::detail;
use snort3::framework::codec::ip_protocol as ipp;

const VECTORS: &str = include_str!("../tools/csum_harness/vectors.txt");

/// `short_buf[16]` — checksum_test.cc:48-:50 (and probe.cc:6-7), verbatim.
const SHORT_BUF: [u8; 16] = [
    0x22, 0x11, 0x44, 0x33, 0x66, 0x55, 0x88, 0x77, 0xaa, 0x99, 0xcc, 0xbb, 0xee, 0xdd, 0x00,
    0xff,
];

// ==========================================================================
// 1. Whole-transcript replay — vectors.txt line-for-line, ordered session
//    (probe.cc statement order == vectors line order; each arm cites its
//    probe.cc line + the checksum.h body it exercises).
// ==========================================================================
#[test]
fn csum_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 16, "vectors.txt must hold the full 16-line ladder");
    let mut out: Vec<String> = Vec::new();

    // -- probe.cc:9 detail guard arms. Q3 triple per arm: len==0, cksum
    // input UNTOUCHED, pointer NOT advanced (the d!=short_buf printf fact —
    // BEYOND the C suite's CHECK_EQUAL(0u,len); the Rust return gives the
    // same view: the returned slice is the INPUT slice unchanged).
    {
        let mut cks = 0u32;
        let (d, len) = detail::add_tcp_header(&SHORT_BUF, 4, &mut cks); // checksum.h:153 guard :158-:162
        let ptr_moved = d.as_ptr() != SHORT_BUF.as_ptr();
        out.push(format!(
            "G_tcp len4->len={} cks=0x{:04x} ptr_moved={}",
            len,
            cks & 0xffff,
            ptr_moved as i32
        ));
    }
    {
        let mut cks = 0u32;
        let (_d, len) = detail::add_udp_header(&SHORT_BUF, 4, &mut cks); // :171 guard :176-:180
        out.push(format!("G_udp len4->len={} cks=0x{:04x}", len, cks & 0xffff));
    }
    {
        let mut cks = 0u32;
        let (_d, len) = detail::add_ip_header(&SHORT_BUF, 4, &mut cks); // :189 guard :194-:198
        out.push(format!("G_ip  len4->len={} cks=0x{:04x}", len, cks & 0xffff));
    }
    {
        let mut cks = 0u32;
        let (_d, len) = detail::add_tcp_header(&SHORT_BUF, 0, &mut cks); // len==0 arm (test :92 probe analog)
        out.push(format!("G_tcp len0->len={}", len));
    }

    // -- probe.cc:14-20 public short-len arms: guard zeroes len + skips
    // the header eats => the result is the PSEUDOHEADER-ONLY complement.
    let ph_tcp = csum::Pseudoheader {
        sip: 0,
        dip: 0,
        zero: 0,
        protocol: ipp::TCP, // 6 -> PH word 0x0600 via byte @9 (probe.cc:14)
        len: 0,
    };
    out.push(format!("P_tcp4_len4=0x{:04x}", csum::tcp_cksum4(&SHORT_BUF, 4, ph_tcp))); // :223
    let ph6 = csum::Pseudoheader6::default(); // `Pseudoheader6 ph6{}` zero-init (test :127, probe.cc:16)
    out.push(format!("P_tcp6_len4=0x{:04x}", csum::tcp_cksum6(&SHORT_BUF, 4, ph6))); // :235, ~0 over empty ph6
    let ph_udp = csum::Pseudoheader {
        sip: 0,
        dip: 0,
        zero: 0,
        protocol: ipp::UDP, // 17 (probe.cc:18)
        len: 0,
    };
    out.push(format!("P_udp4_len4=0x{:04x}", csum::udp_cksum4(&SHORT_BUF, 4, ph_udp))); // :247
    out.push(format!("P_ip_len4=0x{:04x}", csum::ip_cksum(&SHORT_BUF, 4))); // :271

    // -- probe.cc:22-28 valid-input verify pair (the suite's own
    // `checksum_valid_inputs` shape; words stored LE exactly as the C
    // uint16_t array is memcpy'd on the x86_64 ground host).
    {
        let mut tcph: Vec<u8> = [0x0050u16, 0xd431, 0x0000, 0x0001, 0x0000, 0x0000, 0x5002, 0x2000, 0x0000, 0x0000]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let ph = csum::Pseudoheader {
            sip: 0x0100007f,
            dip: 0x0100007f,
            zero: 0,
            protocol: ipp::TCP,
            len: 0x1400, // htons(20) as LE raw bits (probe.cc:23; Q1 ruling)
        };
        let s = csum::tcp_cksum4(&tcph, 20, ph);
        tcph[16..18].copy_from_slice(&s.to_le_bytes()); // tcph[8] = sum (:180)
        let reverify = (csum::tcp_cksum4(&tcph, 20, ph) == 0) as i32;
        out.push(format!("K_tcp4 sum=0x{:04x} reverify={}", s, reverify));
    }
    {
        let mut iph: Vec<u8> = [0x4500u16, 0x0028, 0x1c46, 0x4000, 0x4006, 0x0000, 0x007f, 0x0000, 0x0100, 0x0000]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let s = csum::ip_cksum(&iph, 20);
        iph[10..12].copy_from_slice(&s.to_le_bytes()); // iph[5] = sum (:191)
        let reverify = (csum::ip_cksum(&iph, 20) == 0) as i32;
        out.push(format!("K_ip4 sum=0x{:04x} reverify={}", s, reverify));
    }

    // -- probe.cc:30-33 bare cksum_add ladder over the fixture: 16-word /
    // ODD-TAIL(15, Q1 swap-break) / single-byte / empty arms. Declared len
    // SHORTER than the buffer = C (ptr,len) window semantics — the Rust
    // slice takes the same window via the len arg.
    out.push(format!("K_cksum16=0x{:04x}", csum::cksum_add(&SHORT_BUF, 16)));
    out.push(format!("K_cksum15=0x{:04x}", csum::cksum_add(&SHORT_BUF, 15)));
    out.push(format!("K_cksum1=0x{:04x}", csum::cksum_add(&SHORT_BUF, 1)));
    out.push(format!("K_cksum0=0x{:04x}", csum::cksum_add(&SHORT_BUF, 0)));

    // -- probe.cc:35-38 pseudoheader word dumps (union punning pins, Q5).
    let q = csum::Pseudoheader {
        sip: 0x0100007f, // 127.0.0.1 net-order bits (test :170 analog)
        dip: 0x0100007f,
        zero: 0,
        protocol: ipp::TCP,
        len: 0x1400,
    };
    let w = q.arr_words();
    out.push(format!(
        "PH4 arr={:04x} {:04x} {:04x} {:04x} {:04x} {:04x} sizeof={}",
        w[0], w[1], w[2], w[3], w[4], w[5],
        std::mem::size_of::<csum::Pseudoheader>()
    ));
    // probe.cc:37 `Pseudoheader6 r{};` zero-init + two field sets — the
    // explicit all-fields literal pins the same 36 zero bytes.
    let r = csum::Pseudoheader6 {
        sip: [0; 4],
        dip: [0; 4],
        zero: 0,
        protocol: ipp::TCP,
        len: 0x1400,
    };
    out.push(format!(
        "PH6 sizeof={} arr17=0x{:04x}",
        std::mem::size_of::<csum::Pseudoheader6>(),
        r.arr_words()[17]
    ));

    for (i, line) in out.iter().enumerate() {
        assert_eq!(line, want[i], "vectors line {} mismatch", i + 1);
    }
}

// ==========================================================================
// 2. The 10 CppUTest TESTs translated statement-for-statement.
//    TEST_GROUPs (checksum_test.cc:56/:107/:156) hold no fixture state
//    (`{ };` empty), so each SECTION-analog = a fresh #[test] (skill
//    rule 10: every TEST starts from clean state — SHORT_BUF is const,
//    every cksum starts at 0 like the C local declarations).
//    CHECK(true) arms: the C suite pins ONLY "the call returned" (its
//    whole point: pre-hardening the underflow meant NO return — the walk
//    SIGSEGV'd, suite header prose :20-:26). The exact return values are
//    pinned by the probe transcript, cited; not asserted blind here.
// ==========================================================================

// ---- TEST_GROUP(checksum_header_guards) — checksum_test.cc:56 ----

#[test]
/// TEST(checksum_header_guards, tcp_header_short_len_no_underflow) —
/// checksum_test.cc:58-:68. d=short_buf, len=4 (< TCP_MIN_HEADER_LEN 20,
/// checksum.h:149), cksum=0; add_tcp_header; CHECK_EQUAL(0u, len) (@:67).
fn up_gate_header_guards_tcp_short_len() {
    let mut cksum = 0u32; // :62
    let (_d, mut len) = (SHORT_BUF.as_slice(), 4usize); // :60-:61
    let (_d, l) = detail::add_tcp_header(_d, len, &mut cksum); // :64
    len = l;
    assert_eq!(0u32, len as u32); // CHECK_EQUAL(0u, len) :67
}

#[test]
/// TEST(checksum_header_guards, udp_header_short_len_no_underflow) —
/// checksum_test.cc:70-:79. len=4 < UDP_MIN_HEADER_LEN 8 (:150).
fn up_gate_header_guards_udp_short_len() {
    let mut cksum = 0u32; // :74
    let (_d, mut len) = (SHORT_BUF.as_slice(), 4usize); // :72-:73
    let (_d, l) = detail::add_udp_header(_d, len, &mut cksum); // :76
    len = l;
    assert_eq!(0u32, len as u32); // CHECK_EQUAL(0u, len) :78
}

#[test]
/// TEST(checksum_header_guards, ip_header_short_len_no_underflow) —
/// checksum_test.cc:81-:90. len=4 < IP_MIN_HEADER_LEN 20 (:151).
fn up_gate_header_guards_ip_short_len() {
    let mut cksum = 0u32; // :85
    let (_d, mut len) = (SHORT_BUF.as_slice(), 4usize); // :83-:84
    let (_d, l) = detail::add_ip_header(_d, len, &mut cksum); // :87
    len = l;
    assert_eq!(0u32, len as u32); // CHECK_EQUAL(0u, len) :89
}

#[test]
/// TEST(checksum_header_guards, tcp_header_zero_len_no_underflow) —
/// checksum_test.cc:92-:101. len=0 also takes the guard (0 < 20).
fn up_gate_header_guards_tcp_zero_len() {
    let mut cksum = 0u32; // :96
    let (_d, mut len) = (SHORT_BUF.as_slice(), 0usize); // :94-:95
    let (_d, l) = detail::add_tcp_header(_d, len, &mut cksum); // :98
    len = l;
    assert_eq!(0u32, len as u32); // CHECK_EQUAL(0u, len) :100
}

// ---- TEST_GROUP(checksum_public_api_guards) — checksum_test.cc:107 ----

#[test]
/// TEST(checksum_public_api_guards, tcp_cksum_ip4_short_len) —
/// checksum_test.cc:111-:123. ph: sip/dip/zero/len = 0, protocol TCP
/// (:113-:118) — the TcpCodec::update() updated_len==4 shape (comment
/// :109-:110). `(void)tcp_cksum(short_buf, 4, ph);` then CHECK(true)
/// (:121-:122): reaching the CHECK at all IS the regression proof
/// (pre-hardening: size_t underflow -> ~2^64 walk -> SIGSEGV, header
/// prose :20-:26). Return value pinned OUTSIDE the suite: vectors
/// line 5 `P_tcp4_len4=0xf9ff` (probe-measured).
fn up_gate_public_api_tcp_cksum_ip4_short() {
    let ph = csum::Pseudoheader {
        sip: 0,        // :114
        dip: 0,        // :115
        zero: 0,       // :116
        protocol: ipp::TCP, // :117 IpProtocol::TCP
        len: 0,        // :118
    };
    let _ = csum::tcp_cksum4(&SHORT_BUF, 4, ph); // :121
    // CHECK(true) :122 — the call returned.
}

#[test]
/// TEST(checksum_public_api_guards, tcp_cksum_ip6_short_len) —
/// checksum_test.cc:125-:131. `Pseudoheader6 ph6{}` = full zero-init
/// (:127; the Rust `default()` is the same 36 zero bytes — Q5 posture).
/// Return pinned by vectors line 6 `P_tcp6_len4=0xffff`.
fn up_gate_public_api_tcp_cksum_ip6_short() {
    let ph6 = csum::Pseudoheader6::default(); // :127
    let _ = csum::tcp_cksum6(&SHORT_BUF, 4, ph6); // :129
    // CHECK(true) :130.
}

#[test]
/// TEST(checksum_public_api_guards, udp_cksum_ip4_short_len) —
/// checksum_test.cc:133-:144. ph protocol UDP (:139). Return pinned by
/// vectors line 7 `P_udp4_len4=0xeeff`.
fn up_gate_public_api_udp_cksum_ip4_short() {
    let ph = csum::Pseudoheader {
        sip: 0,
        dip: 0,
        zero: 0,
        protocol: ipp::UDP, // :139 IpProtocol::UDP
        len: 0,             // :140
    };
    let _ = csum::udp_cksum4(&SHORT_BUF, 4, ph); // :142
    // CHECK(true) :143.
}

#[test]
/// TEST(checksum_public_api_guards, ip_cksum_short_len) —
/// checksum_test.cc:146-:150. Return pinned by vectors line 8
/// `P_ip_len4=0xffff`.
fn up_gate_public_api_ip_cksum_short() {
    let _ = csum::ip_cksum(&SHORT_BUF, 4); // :148
    // CHECK(true) :149.
}

// ---- TEST_GROUP(checksum_valid_inputs) — checksum_test.cc:156 ----

#[test]
/// TEST(checksum_valid_inputs, tcp_min_header_checksum_verifies) —
/// checksum_test.cc:163-:182. 10-word minimal TCP header (:166-:167)
/// stored as the C uint16_t array is memcpy'd (LE on the ground host);
/// ph sip/dip = 0x0100007f (127.0.0.1 net order, :170-:171), protocol
/// TCP (:173), `htons(20)` (:174) lands as raw bits 0x1400 (Q1 ruling —
/// never host-native 20). sum = tcp_cksum(tcph,20,ph) (:176), write
/// back tcph[8] (:180), CHECK_EQUAL(0, recompute) (:181). The sum
/// itself is suite-unobserved (the suite checks the verify property
/// ONLY); vectors line 9 pins `sum=0x9e7c reverify=1` probe-side.
fn up_gate_valid_inputs_tcp_min_header_verifies() {
    let mut tcph: Vec<u8> = [0x0050u16, 0xd431, 0x0000, 0x0001, 0x0000, 0x0000, 0x5002, 0x2000, 0x0000, 0x0000]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(); // :166-:167
    let ph = csum::Pseudoheader {
        sip: 0x0100007f,
        dip: 0x0100007f,
        zero: 0,
        protocol: ipp::TCP,
        len: 0x1400, // htons(20) LE :174
    };
    let sum = csum::tcp_cksum4(&tcph, 20, ph); // :176
    tcph[16..18].copy_from_slice(&sum.to_le_bytes()); // tcph[8] = sum :180
    assert_eq!(0, csum::tcp_cksum4(&tcph, 20, ph)); // CHECK_EQUAL(0, ...) :181
}

#[test]
/// TEST(checksum_valid_inputs, ip_min_header_checksum_verifies) —
/// checksum_test.cc:184-:193. 20-byte IPv4 header, checksum word 5
/// zeroed (:186-:187 comment + value 0x0000 at :188 word idx 5); sum =
/// ip_cksum(iph,20) (:190); iph[5] = sum (:191); CHECK_EQUAL(0,
/// recompute) (:192). vectors line 10 pins `sum=0x1d0c reverify=1`.
fn up_gate_valid_inputs_ip_min_header_verifies() {
    let mut iph: Vec<u8> = [0x4500u16, 0x0028, 0x1c46, 0x4000, 0x4006, 0x0000, 0x007f, 0x0000, 0x0100, 0x0000]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(); // :187-:188
    let sum = csum::ip_cksum(&iph, 20); // :190
    iph[10..12].copy_from_slice(&sum.to_le_bytes()); // iph[5] = sum :191
    assert_eq!(0, csum::ip_cksum(&iph, 20)); // CHECK_EQUAL(0, ...) :192
}

// ---- extra arms beyond both sources (the Q-ladder, probe-cited) ----

#[test]
/// Q2 fold/complement posture: the len=0 arm of the public cksum_add
/// (:280-:281 -> detail :90-:109) = `(uint16_t)(~0)` = 0xffff EXACTLY —
/// the (:108) cast truncation arm. vectors lines 11-14 ladder: 16 /
/// 15 (odd tail 0xdd RAW — Q1: the swap-invariance BREAK, 0xbb44 is NOT
/// a byte-swap of 0xbc43) / 1 (single raw byte 0x22 -> ~ = 0xffdd) / 0.
fn csum_cksum_add_ladder_q1_q2() {
    assert_eq!(csum::cksum_add(&SHORT_BUF, 16), 0xbc43); // vectors:11
    assert_eq!(csum::cksum_add(&SHORT_BUF, 15), 0xbb44); // vectors:12 Q1
    assert_eq!(csum::cksum_add(&SHORT_BUF, 1), 0xffdd); // vectors:13
    assert_eq!(csum::cksum_add(&SHORT_BUF, 0), 0xffff); // vectors:14 Q2
}

#[test]
/// Q5 size pins: the static_asserts checksum.h:41 (12) / :55 (36) restated
/// Rust-side as const _: () = assert!(...) in checksum.rs AND greppable
/// here — plus the union view word pins (PH4 six words, PH6 arr[17] =
/// the len word at u16 index 17 = 0x1400). vectors:15/:16.
fn csum_pseudoheader_sizes_and_views() {
    assert_eq!(std::mem::size_of::<csum::Pseudoheader>(), 12); // checksum.h:41 static_assert
    assert_eq!(std::mem::size_of::<csum::Pseudoheader6>(), 36); // checksum.h:55 static_assert
    let q = csum::Pseudoheader {
        sip: 0x0100007f,
        dip: 0x0100007f,
        zero: 0,
        protocol: ipp::TCP,
        len: 0x1400,
    };
    assert_eq!(
        q.arr_words(),
        [0x007f, 0x0100, 0x007f, 0x0100, 0x0600, 0x1400]
    ); // vectors:15 word pun
    let r = csum::Pseudoheader6 {
        sip: [0; 4],
        dip: [0; 4],
        zero: 0,
        protocol: ipp::TCP,
        len: 0x1400,
    };
    assert_eq!(r.arr_words()[17], 0x1400); // vectors:16
}

#[test]
/// Q3 guard posture, extended face (probe-only facts the C suite never
/// checked): on every guard bail the cksum ACCUMULATOR is untouched and
/// the cursor is not advanced — vectors:1-3 `cks=0x0000` x3 +
/// `ptr_moved=0`. The Rust port returns the input slice unchanged, so
/// the pointer fact asserts structurally.
fn csum_guard_arms_keeps_cksum_and_cursor() {
    let mut cks = 0xdead_beefu32; // armed NON-zero — the probe armed 0;
    // any untouched accumulator must still read dead_beef (posture test
    // BEYOND the transcript's 0x0000 face; the transcript face replays
    // in csum_transcript_replay lines 1-3).
    let (d, len) = detail::add_tcp_header(&SHORT_BUF, 4, &mut cks);
    assert_eq!(len, 0);
    assert_eq!(cks, 0xdead_beef);
    assert!(std::ptr::eq(d.as_ptr(), SHORT_BUF.as_ptr()));

    let (d, len) = detail::add_udp_header(&SHORT_BUF, 4, &mut cks);
    assert_eq!(len, 0);
    assert_eq!(cks, 0xdead_beef);
    assert!(std::ptr::eq(d.as_ptr(), SHORT_BUF.as_ptr()));

    let (d, len) = detail::add_ip_header(&SHORT_BUF, 4, &mut cks);
    assert_eq!(len, 0);
    assert_eq!(cks, 0xdead_beef);
    assert!(std::ptr::eq(d.as_ptr(), SHORT_BUF.as_ptr()));
}
