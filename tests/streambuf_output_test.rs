//! Output half of the streambuf_test.cc port (ostreambuf_infl + ostream).

// offset literals copied verbatim from C ((0 - len - len), (0 + 1), ...)
#![allow(clippy::identity_op)]
use snort3::helpers::streambuf::*;

// EXP_RES: take_data bookkeeping + expected data length and allocation.
// d1==act / d2==nullptr modelled as: taken bytes equal the pre-take data()
// snapshot; post-take data() empty and data_len()==0.
fn exp_res(b: &mut OStreamBufInfl, exp: &[u8], exp_len: i64, exp_mem_size: i64) {
    let d1_len = b.data_len();
    let d1 = b.data().to_vec();
    let (act, act_len) = b.take_data_len();
    let d2_len = b.data_len();
    let d2_empty = b.data().is_empty();

    let act = act.expect("take_data returned a buffer"); // d1 != null in tests using this
    assert_eq!(d1[..d1_len as usize], act[..d1_len as usize]); // d1 == act, d1_len == act_len
    assert!(d2_empty); // d2 == nullptr
    assert_eq!(d2_len, 0);

    assert_eq!(act_len, exp_mem_size);
    assert!(exp_len <= act_len);
    assert_eq!(&act[..exp_len as usize], &exp[..exp_len as usize]);
}

// ---- std::ostream emulation (libstdc++ 14 semantics) ----
struct OStream<'a> {
    b: &'a mut OStreamBufInfl,
    fail: bool,
    bad: bool,
}

impl<'a> OStream<'a> {
    fn new(b: &'a mut OStreamBufInfl) -> Self {
        OStream { b, fail: false, bad: false }
    }
    // ostream::write -> __ostream_insert -> sentry -> sputn;
    // __ostream_write: sputn != n => setstate(badbit)
    fn write(&mut self, src: &[u8], n: i64) {
        if self.bad || self.fail {
            return; // sentry blocks
        }
        let put = self.b.sputn(src, n);
        if put != n {
            self.bad = true;
        }
    }
    #[allow(dead_code)] // exercised only via EXP_OUT/CHECK semantics
    fn good(&self) -> bool {
        !self.fail && !self.bad
    }
    fn fail_(&self) -> bool {
        self.fail || self.bad // libstdc++: fail() true if failbit OR badbit
    }
    fn bad_(&self) -> bool {
        self.bad
    }
    fn clear(&mut self) {
        self.fail = false;
        self.bad = false;
    }
    fn tellp(&mut self) -> i64 {
        if self.fail || self.bad {
            return -1;
        }
        self.b.pubseekoff(0, SeekDir::Cur, MODE_OUT)
    }
}

fn exp_out(s: &mut OStream, exp: &[u8], exp_len: i64) {
    assert!(!s.fail_());
    assert!(!s.bad_());
    s.clear();
    assert_eq!(s.tellp(), exp_len);
    let act_len = s.b.data_len();
    let act = s.b.data().to_vec();
    assert_eq!(act_len, exp_len);
    assert_eq!(&act[..exp_len as usize], &exp[..exp_len as usize]);
}

fn eof_out(s: &mut OStream, exp: &[u8], exp_len: i64) {
    assert!(s.fail_());
    assert!(s.bad_());
    s.clear();
    assert_eq!(s.tellp(), exp_len);
    let act_len = s.b.data_len();
    let act = s.b.data().to_vec();
    assert_eq!(act_len, exp_len);
    assert_eq!(&act[..exp_len as usize], &exp[..exp_len as usize]);
}

// "output buffer - basic"
#[test]
fn output_buffer_basic() {
    // EXP_SIZE = 4096; const char exp[EXP_SIZE]="ABC" -> 4096 bytes, first 3
    // are ABC then zeros
    let exp = {
        let mut v = vec![0u8; 4096];
        v[..3].copy_from_slice(b"ABC");
        v
    };

    {
        // no input
        let _n: &[u8] = b""; // C `const char* n = ""`
        let l = 0i64;
        let mut b = OStreamBufInfl::new();
        // EXP_RES with d1 == act == nullptr: take_data returns None, act_len 0
        let d1_len = b.data_len();
        assert_eq!(d1_len, 0);
        assert!(b.data().is_empty());
        let (act, act_len) = b.take_data_len(); // act == nullptr
        assert!(b.data().is_empty());
        assert_eq!(b.data_len(), 0);
        assert!(act.is_none());
        assert_eq!(act_len, l);
        assert_eq!(act_len, 0); // exp_mem_size == 0 (pbase null, nothing grown)
    }
    {
        // put char
        let mut b = OStreamBufInfl::new();
        let c = b.sputc(b'A');
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(c, b'A' as i32);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 1);
        assert_eq!(off_e, 2048);
        exp_res(&mut b, &exp, 1, 2048);
    }
    {
        // put two chars
        let mut b = OStreamBufInfl::new();
        let c1 = b.sputc(b'A');
        let off_1 = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let c2 = b.sputc(b'B');
        let off_2 = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(c1, b'A' as i32);
        assert_eq!(c2, b'B' as i32);
        assert_eq!(off_e, 2048);
        assert_eq!(off_b, 0);
        assert_eq!(off_1, 1);
        assert_eq!(off_2, 2);
        // EXP_RES(b, exp, 2, 2048): preceded only by pubseekoff(0,end) above
        // which parked pptr at epptr, so allocation = 2048
        assert_eq!(b.data_len(), 2048);
        let (act, act_len) = b.take_data_len();
        let act = act.unwrap();
        assert_eq!(act_len, 2048);
        assert_eq!(&act[..2], &exp[..2]);
    }
    {
        // extend buffer
        let mut b = OStreamBufInfl::new();
        let c1 = b.sputc(b'A');
        let off_1 = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        let c2 = b.sputc(b'Z');
        let off_2 = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_z = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(c1, b'A' as i32);
        assert_eq!(c2, b'Z' as i32);
        assert_eq!(off_b, 0);
        assert_eq!(off_1, 1);
        assert_eq!(off_2, 2049);
        assert_eq!(off_e, 2048);
        assert_eq!(off_z, 6144);
    }
    {
        // put sequence of chars: len = sizeof(exp) = 4096
        let mut b = OStreamBufInfl::new();
        let len = 4096i64;
        let n = b.sputn(&exp, len);
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let _off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(n, len);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, len);
        exp_res(&mut b, &exp, len, 4096);
    }
    {
        // continue sequence: sputc A; sputn(exp, 4095); sputc Z
        let mut b = OStreamBufInfl::new();
        let len = 4095i64;
        let c1 = b.sputc(b'A');
        let n = b.sputn(&exp, len);
        let c2 = b.sputc(b'Z');
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(n, len);
        assert_eq!(c1, b'A' as i32);
        assert_eq!(c2, b'Z' as i32);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, len + 2);
        assert_eq!(off_e, 4096 + 2048);
    }
    {
        // get char sequence
        let exp_s = b"ABC";
        let exp_len = 3i64;
        let mut b = OStreamBufInfl::new();
        b.sputn(exp_s, exp_len);
        let off_c = b.pubseekoff(-exp_len, SeekDir::Cur, MODE_OUT);
        assert_eq!(off_c, 0);
        let mut act_seq = vec![0u8; 3];
        assert_eq!(b.sgetn(&mut act_seq, exp_len), exp_len);
        assert_eq!(&act_seq, exp_s);
        let new_off = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        assert_eq!(new_off, exp_len);
    }
    {
        // get char sequence from the end
        let exp_s = b"ABC";
        let exp_len = 3i64;
        let mut b = OStreamBufInfl::new();
        let mut buf = vec![0u8; 3];
        buf.copy_from_slice(exp_s);
        b.pubsetbuf(Some(buf), exp_len);
        let data_off = b.pubseekoff(exp_len, SeekDir::Beg, MODE_OUT);
        assert_eq!(data_off, exp_len);
        let mut act_seq = vec![0u8; 3];
        assert_eq!(b.sgetn(&mut act_seq, exp_len), 0);
        assert_eq!(&act_seq, b"\0\0\0");
        let new_off = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        assert_eq!(new_off, exp_len);
    }
    {
        // get char sequence more than available
        let exp_s = b"ABC";
        let exp_len = 3i64;
        let mut b = OStreamBufInfl::new();
        let mut buf = vec![0u8; 3];
        buf.copy_from_slice(exp_s);
        b.pubsetbuf(Some(buf), exp_len);
        let mut act_seq = vec![0u8; 4];
        assert_eq!(b.sgetn(&mut act_seq, exp_len + 1), exp_len);
        assert_eq!(&act_seq[..3], exp_s);
        let new_off = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        assert_eq!(new_off, exp_len);
    }
}

// "output buffer - buffer management"
#[test]
fn output_buffer_management() {
    let dat1: &[u8] = b"0123";
    let dat2: &[u8] = b"4567";
    let dat3: &[u8] = b"89";
    let dat4: &[u8] = b"-+";

    {
        // sync
        let mut b = OStreamBufInfl::new();
        let buf = vec![0u8; 4];
        b.pubsetbuf(Some(buf), 4);
        assert_eq!(b.pubsync(), -1);
    }
    {
        // changing buffer
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 128]), 128);
        b.sputn(dat1, 4);
        exp_res(&mut b, dat1, 4, 4);

        b.pubsetbuf(Some(vec![0u8; 256]), 256);
        b.sputn(dat2, 4);
        exp_res(&mut b, dat2, 4, 4);

        b.pubsetbuf(Some(vec![0u8; 32]), 32);
        b.sputn(dat3, 2);
        exp_res(&mut b, dat3, 2, 2);

        b.pubsetbuf(Some(vec![0u8; 64]), 64);
        b.sputn(dat4, 2);
        exp_res(&mut b, dat4, 2, 2);
    }
}

// "output buffer - positioning"
#[test]
fn output_buffer_positioning() {
    let exp: &[u8] = b"Early bird gets a corn.";
    let len = 23i64;
    let len1d3 = 23 * 1 / 3;
    let len2d3 = len - len1d3;

    {
        // no data
        let mut b = OStreamBufInfl::new();
        let pos_c = b.pubseekpos(len / 2, MODE_OUT);
        let pos_b = b.pubseekpos(0, MODE_OUT);
        let pos_e = b.pubseekpos(len, MODE_OUT);
        assert_eq!(pos_b, 0);
        assert_eq!(pos_c, 0);
        assert_eq!(pos_e, 0);
    }
    {
        // wrong buffer
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        let pos_c = b.pubseekpos(len / 2, MODE_IN);
        let pos_b = b.pubseekpos(0, MODE_IN);
        let pos_e = b.pubseekpos(len, MODE_IN);
        assert_eq!(pos_b, -1);
        assert_eq!(pos_c, -1);
        assert_eq!(pos_e, -1);
    }
    {
        // out of range
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        let pos = b.pubseekpos(0 - len, MODE_OUT);
        assert_eq!(pos, 0);
        exp_res(&mut b, exp, 0, 0);

        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        let pos = b.pubseekpos(len + len, MODE_OUT);
        assert_eq!(pos, len);
        exp_res(&mut b, exp, len, len);
    }
    {
        // on the edge
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        for (p, want) in [
            (0i64, 0i64),
            (0 - 1, 0),
            (0 + 1, 1),
            (len, len),
            (len - 1, len - 1),
            (len + 1, len),
        ] {
            let pos = b.pubseekpos(p, MODE_OUT);
            assert_eq!(pos, want);
        }
        let pos = b.pubseekpos(0, MODE_OUT);
        assert_eq!(pos, 0);
        exp_res(&mut b, exp, 0, 0);
    }
    {
        // in range
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        let pos = b.pubseekpos(len1d3, MODE_OUT);
        assert_eq!(pos, len1d3);
        let pos = b.pubseekpos(len2d3, MODE_OUT);
        assert_eq!(pos, len2d3);
    }
}

// "output buffer - offset"
#[test]
fn output_buffer_offset() {
    let exp: &[u8] = b"Early bird gets a corn.";
    let len = 23i64;
    let len1d3 = 23 * 1 / 3;
    let len2d3 = len - len1d3;

    {
        // no data
        let mut b = OStreamBufInfl::new();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 0);
        assert_eq!(off_e, 0);
    }
    {
        // wrong buffer
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        let off_a = b.pubseekoff(0, SeekDir::from_raw(0x5a5a), MODE_OUT);
        assert_eq!(off_b, -1);
        assert_eq!(off_c, -1);
        assert_eq!(off_e, -1);
        assert_eq!(off_a, -1);
    }
    {
        // begin
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        for (o, want) in [
            (0 - len - len, 0i64),
            (0 + len + len, len),
            (0 - 1, 0),
            (0 + 1, 1),
            (0 + len1d3, len1d3),
            (0 + len2d3, len2d3),
            (0 + len - 1, len - 1),
            (0 + len, len),
            (0, 0),
        ] {
            let off = b.pubseekoff(o, SeekDir::Beg, MODE_OUT);
            assert_eq!(off, want);
        }
        // EXP_RES(b, exp, 0, 0) at off 0
        res_data(&mut b, exp, 0);
        // re-fill buffer after take (C: take_data left pbase null; test then
        // sputns again which re-allocates via overflow)
        b.sputn(exp, len);
        res_data(&mut b, exp, len);
    }
    {
        // end
        let exp_alt: &[u8] = b"Early bird gets a corn!";
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        for (o, want) in [
            (0 - len - len, 0i64),
            (0 + len + len, len),
            (0, len),
            (0 - 1, len - 1),
            (0 + 1, len),
            (0 - len1d3, len2d3),
            (0 - len2d3, len1d3),
            (0 - len + 1, 1),
            (0 - len, 0),
        ] {
            let off = b.pubseekoff(o, SeekDir::End, MODE_OUT);
            assert_eq!(off, want);
        }
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        let off = b.pubseekoff(-1, SeekDir::End, MODE_OUT);
        assert_eq!(off, len - 1);
        b.sputn(b"!", 1);
        let off = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(off, len);
        res_data(&mut b, exp_alt, len);
    }
    {
        // current
        let exp_alt: &[u8] = b"Early birds get a worm.";
        let ovr_alt: &[u8] = b"s get a worm.";
        let off_alt = 13i64;
        let mut b = OStreamBufInfl::new();
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        for (pre, o, want) in [
            (len1d3, 0 - len - len, 0i64),
            (len1d3, 0 + len + len, len),
            (len1d3, 0, len1d3),
            (len1d3, 0 - 1, len1d3 - 1),
            (len1d3, 0 + 1, len1d3 + 1),
            (len1d3, 0 + len1d3, len1d3 + len1d3),
            (len1d3, 0 + len2d3, len),
            (len1d3, 0 + len, len),
        ] {
            b.pubseekoff(pre, SeekDir::Beg, MODE_OUT);
            let off = b.pubseekoff(o, SeekDir::Cur, MODE_OUT);
            assert_eq!(off, want);
        }
        b.pubsetbuf(Some(vec![0u8; 23]), 23);
        b.sputn(exp, len);
        b.pubseekoff(-off_alt, SeekDir::End, MODE_OUT);
        let off = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        assert_eq!(off, len - off_alt);
        b.sputn(ovr_alt, off_alt);
        let off = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(off, len);
        res_data(&mut b, exp_alt, len);
    }
}

fn res_data(b: &mut OStreamBufInfl, exp: &[u8], exp_len: i64) {
    // EXP_RES where exp_mem_size tracks pptr; pbase may be null (post-take),
    // in which case C take_data yields nullptr and act_len 0.
    let d1_len = b.data_len();
    let d1 = b.data().to_vec();
    let (act, act_len) = b.take_data_len();
    assert!(b.data().is_empty());
    assert_eq!(b.data_len(), 0);
    assert!(exp_len <= act_len);
    match act {
        Some(act) => {
            assert_eq!(&d1[..d1_len as usize], &act[..d1_len as usize]);
            assert_eq!(&act[..exp_len as usize], &exp[..exp_len as usize]);
        }
        None => {
            assert_eq!(act_len, 0);
            assert_eq!(exp_len, 0);
        }
    }
}

// "output stream - basic" + "reserved size" (EXP_OUT)
#[test]
fn output_stream_basic_and_reserved() {
    for reserved in [false, true] {
        {
            // no input
            let exp: &[u8] = b"";
            let mut b = OStreamBufInfl::new();
            if reserved {
                b.reserve(32);
            }
            let mut s = OStream::new(&mut b);            exp_out(&mut s, exp, 0);
        }
        {
            // 1 byte input
            let src: &[u8] = b"A";
            let mut b = OStreamBufInfl::new();
            if reserved {
                b.reserve(32);
            }
            let mut s = OStream::new(&mut b);            s.write(src, 1);
            exp_out(&mut s, src, 1);
        }
        {
            // 8 bytes input
            let src: &[u8] = b"12345678";
            let mut b = OStreamBufInfl::new();
            if reserved {
                b.reserve(32);
            }
            let mut s = OStream::new(&mut b);            s.write(src, 8);
            exp_out(&mut s, src, 8);
        }
        {
            // partial write (byte-by-byte)
            let src: &[u8] = b"12345678";
            let mut b = OStreamBufInfl::new();
            if reserved {
                b.reserve(32);
            }
            let mut s = OStream::new(&mut b);            for c in src.iter() {
                s.write(&[*c], 1);
            }
            exp_out(&mut s, src, 8);
        }
    }
}

// "output stream - large data" (EOF_OUT): deterministic random content
// self-consistent between write and compare (C rand() need not match).
#[test]
fn output_stream_large_data() {
    let len = 1 << 21i64;
    let plen = 1 << 12i64;
    // deterministic pseudo-random fill (upstream uses rand(); the suite only
    // compares what it wrote, so any content works)
    let mut chars: Vec<u8> = Vec::with_capacity(len as usize);
    let mut st: u32 = 1;
    for _ in 0..len {
        st = st.wrapping_mul(1103515245).wrapping_add(12345);
        chars.push((st >> 16) as u8);
    }

    for reserve in [0i64, 1 << 10, 1 << 18] {
        let mut b = OStreamBufInfl::new();
        if reserve > 0 {
            b.reserve(reserve);
        }
        let mut s = OStream::new(&mut b);        let mut i = 0i64;
        let mut off = 0i64;
        while i < len {
            let n = plen.min(len - i);
            s.write(&chars[off as usize..(off + n) as usize], n);
            i += n;
            off += n;
        }
        eof_out(&mut s, &chars, 1 << 20);
    }
}

fn _unused_exp_res(_b: &mut OStreamBufInfl) {}
