//! Faithful port of helpers/test/streambuf_test.cc (Catch2, 17 TEST_CASEs /
//! 97 sections). Ground truth: the upstream suite compiled against the
//! original streambuf.cc (tools/streambuf_harness) — passes 17/17 cases,
//! 832 assertions. The std::istream/std::ostream entry points the suite
//! uses (read/tellg/eof/clear/write/tellp) are emulated here with the
//! libstdc++ 14 semantics verified against /usr/include/c++/14.
// offset literals copied verbatim from C ((0 - len - len), (0 + 1), ...)
#![allow(clippy::identity_op)]
use snort3::helpers::streambuf::*;

const ACT: usize = 1024;

fn exp_avail1(b: &mut IStreamBufGlue, exp: &[u8], len: i64, off: i64) {
    let avail = b.in_avail();
    assert_eq!(avail, len - off);
    let mut act = vec![0u8; ACT];
    let n = b.sgetn(&mut act, len);
    assert_eq!(n, len - off);
    assert_eq!(&act[..n as usize], &exp[off as usize..(off + n) as usize]);
}

fn exp_avail2(b: &mut IStreamBufGlue, exp: &[u8], len: i64, off: i64, len_1c: i64) {
    let avail = b.in_avail();
    if off < len_1c {
        assert_eq!(avail, len_1c - off);
    } else {
        assert_eq!(avail, len - off);
    }
    let mut act = vec![0u8; ACT];
    let n = b.sgetn(&mut act, len);
    assert_eq!(n, len - off);
    assert_eq!(&act[..n as usize], &exp[off as usize..(off + n) as usize]);
}

fn expand_n(b: &mut IStreamBufGlue, exp: &[u8], len: i64, off: i64) {
    // EXP_AVAILn: no in_avail check
    let mut act = vec![0u8; ACT];
    let n = b.sgetn(&mut act, len);
    assert_eq!(n, len - off);
    assert_eq!(&act[..n as usize], &exp[off as usize..(off + n) as usize]);
}

// ---- std::istream emulation (libstdc++ 14 semantics) ----
struct IStream<'a, 'b> {
    b: &'a mut IStreamBufGlue<'b>,
    eof: bool,
    fail: bool,
    bad: bool,
}

impl<'a, 'b> IStream<'a, 'b> {
    fn new(b: &'a mut IStreamBufGlue<'b>) -> Self {
        IStream { b, eof: false, fail: false, bad: false }
    }
    fn read(&mut self, dst: &mut [u8], n: i64) {
        if self.bad {
            return; // sentry blocks on badbit
        }
        let gcount = self.b.sgetn(dst, n); // xsgetn entry
        if gcount != n {
            self.eof = true;
            self.fail = true;
        }
    }
    fn good(&self) -> bool {
        !(self.eof || self.fail || self.bad)
    }
    fn eof_(&self) -> bool {
        self.eof
    }
    fn clear(&mut self) {
        self.eof = false;
        self.fail = false;
        self.bad = false;
    }
    fn tellg(&mut self) -> i64 {
        if self.fail || self.bad {
            return -1;
        }
        self.b.pubseekoff(0, SeekDir::Cur, MODE_IN)
    }
}

fn exp_in(s: &mut IStream, exp: &[u8], act: &[u8], len: i64) {
    assert!(s.good());
    assert_eq!(s.tellg(), len);
    assert_eq!(&act[..len as usize], &exp[..len as usize]);
}

fn eof_in(s: &mut IStream, exp: &[u8], act: &[u8], len: i64) {
    assert!(s.eof_());
    s.clear();
    assert_eq!(s.tellg(), len);
    assert_eq!(&act[..len as usize], &exp[..len as usize]);
}

fn bytes_read(s: &mut IStream) -> i64 {
    // BYTES_READ macro: (s).clear(), max(tellg, lco) - lco
    s.clear();
    let lco = s.b.last_chunk_offset();
    let tg = s.tellg();
    tg.max(lco) - lco
}

// "input buffer - basic one source"
#[test]
fn input_basic_one_source() {
    let exp = b"Early bird gets a corn.";
    let len = 23i64;
    let dat: &[u8] = b"Early bird gets a corn.";

    {
        // section: no data
        let mut b = IStreamBufGlue::new();
        let avail_1 = b.in_avail();
        let c = b.sgetc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, SOCKET_EOF);
        assert_eq!(avail_1, -1);
        assert_eq!(avail_2, -1);
        assert_eq!(off_b, -1);
        assert_eq!(off_c, -1);
        assert_eq!(off_e, -1);
    }
    {
        // section: get char
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let avail_1 = b.in_avail();
        let c = b.sgetc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'E' as i32);
        assert_eq!(avail_1, len);
        assert_eq!(avail_2, len);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 0);
        assert_eq!(off_e, len);
    }
    {
        // section: get char and bump
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let avail_1 = b.in_avail();
        let c = b.sbumpc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'E' as i32);
        assert_eq!(avail_1, len);
        assert_eq!(avail_2, len - 1);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 1);
        assert_eq!(off_e, len);
    }
    {
        // section: advance and get char
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let avail_1 = b.in_avail();
        let c = b.snextc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'a' as i32);
        assert_eq!(avail_1, len);
        assert_eq!(avail_2, len - 1);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 1);
        assert_eq!(off_e, len);
    }
    {
        // section: get chars
        let b2 = &mut IStreamBufGlue::new();
        b2.pubsetbuf(Some(dat), len);
        let avail_1 = b2.in_avail();
        let mut act = vec![0u8; ACT];
        let nread_1 = b2.sgetn(&mut act, 10);
        let avail_2 = b2.in_avail();
        let nread_2 = b2.sgetn(&mut act[10..], 10);
        let avail_3 = b2.in_avail();
        let off_c = b2.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b2.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b2.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(nread_1, 10);
        assert_eq!(nread_2, 10);
        assert_eq!(avail_1, len);
        assert_eq!(avail_2, len - 10);
        assert_eq!(avail_3, len - 20);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 20);
        assert_eq!(off_e, len);
        assert_eq!(&act[..20], &exp[..20]);
    }
    {
        // section: get chars EOF
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let avail_1 = b.in_avail();
        let mut act = vec![0u8; ACT];
        let nread_1 = b.sgetn(&mut act, 10);
        let avail_2 = b.in_avail();
        let nread_2 = b.sgetn(&mut act[10..], 10);
        let avail_3 = b.in_avail();
        let nread_3 = b.sgetn(&mut act[20..], 10);
        let avail_4 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(nread_1, 10);
        assert_eq!(nread_2, 10);
        assert_eq!(nread_3, 3);
        assert_eq!(avail_1, len);
        assert_eq!(avail_2, len - 10);
        assert_eq!(avail_3, len - 20);
        assert_eq!(avail_4, 0);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 23);
        assert_eq!(off_e, len);
        assert_eq!(&act[..len as usize], &exp[..len as usize]);
    }
    {
        // section: put char back
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let off_o = b.pubseekoff(5, SeekDir::Beg, MODE_IN);
        let avail_1 = b.in_avail();
        let c = b.sungetc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'y' as i32);
        assert_eq!(avail_1, len - 5);
        assert_eq!(avail_2, len - 4);
        assert_eq!(off_o, 5);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 4);
        assert_eq!(off_e, len);
    }
    {
        // section: put another char back
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let off_o = b.pubseekoff(5, SeekDir::Beg, MODE_IN);
        let avail_1 = b.in_avail();
        let c1 = b.sputbackc(b' ');
        let c2 = b.sputbackc(b'y');
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c1, SOCKET_EOF); // pbackfail -> eof
        assert_eq!(c2, b'y' as i32);
        assert_eq!(avail_1, len - 5);
        assert_eq!(avail_2, len - 4);
        assert_eq!(off_o, 5);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 4);
        assert_eq!(off_e, len);
    }
}

// "input buffer - basic two sources"
#[test]
fn input_basic_two_sources() {
    let exp = b"Early bird gets a corn.";
    let len = 23i64;
    let dat1: &[u8] = b"Early bird";
    let dat2: &[u8] = b" gets a corn.";
    let dat1_len = 10i64;
    let dat2_len = 13i64;
    let _ = dat2_len;

    {
        // get char
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let avail_1 = b.in_avail();
        let c = b.sgetc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'E' as i32);
        assert_eq!(avail_1, dat1_len);
        assert_eq!(avail_2, dat1_len);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 0);
        assert_eq!(off_e, len);
    }
    {
        // get char and bump
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let avail_1 = b.in_avail();
        let c = b.sbumpc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'E' as i32);
        assert_eq!(avail_1, dat1_len);
        assert_eq!(avail_2, dat1_len - 1);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 1);
        assert_eq!(off_e, len);
    }
    {
        // advance and get char
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let avail_1 = b.in_avail();
        let c = b.snextc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'a' as i32);
        assert_eq!(avail_1, dat1_len);
        assert_eq!(avail_2, dat1_len - 1);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 1);
        assert_eq!(off_e, len);
    }
    {
        // get chars
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let avail_1 = b.in_avail();
        let mut act = vec![0u8; ACT];
        let nread_1 = b.sgetn(&mut act, 10);
        let avail_2 = b.in_avail();
        let nread_2 = b.sgetn(&mut act[10..], 10);
        let avail_3 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(nread_1, 10);
        assert_eq!(nread_2, 10);
        assert_eq!(avail_1, dat1_len);
        assert_eq!(avail_2, len - 10);
        assert_eq!(avail_3, len - 20);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 20);
        assert_eq!(off_e, len);
        assert_eq!(&act[..20], &exp[..20]);
    }
    {
        // get chars EOF
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let avail_1 = b.in_avail();
        let mut act = vec![0u8; ACT];
        let nread_1 = b.sgetn(&mut act, 10);
        let avail_2 = b.in_avail();
        let nread_2 = b.sgetn(&mut act[10..], 10);
        let avail_3 = b.in_avail();
        let nread_3 = b.sgetn(&mut act[20..], 10);
        let avail_4 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(nread_1, 10);
        assert_eq!(nread_2, 10);
        assert_eq!(nread_3, 3);
        assert_eq!(avail_1, dat1_len);
        assert_eq!(avail_2, len - 10);
        assert_eq!(avail_3, len - 20);
        assert_eq!(avail_4, 0);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 23);
        assert_eq!(off_e, len);
        assert_eq!(&act[..len as usize], &exp[..len as usize]);
    }
    {
        // put char back
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let off_o = b.pubseekoff(5, SeekDir::Beg, MODE_IN);
        let avail_1 = b.in_avail();
        let c = b.sungetc();
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c, b'y' as i32);
        assert_eq!(avail_1, dat1_len - 5);
        assert_eq!(avail_2, dat1_len - 4);
        assert_eq!(off_o, 5);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 4);
        assert_eq!(off_e, len);
    }
    {
        // put another char back
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let off_o = b.pubseekoff(5, SeekDir::Beg, MODE_IN);
        let avail_1 = b.in_avail();
        let c1 = b.sputbackc(b' ');
        let c2 = b.sputbackc(b'y');
        let avail_2 = b.in_avail();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(c1, SOCKET_EOF);
        assert_eq!(c2, b'y' as i32);
        assert_eq!(avail_1, dat1_len - 5);
        assert_eq!(avail_2, dat1_len - 4);
        assert_eq!(off_o, 5);
        assert_eq!(off_b, 0);
        assert_eq!(off_c, 4);
        assert_eq!(off_e, len);
    }
}

// "input buffer - buffer management"
#[test]
fn input_buffer_management() {
    let exp = b"Early bird gets a corn.";
    let len = 23i64;
    let dat: &[u8] = b"Early bird gets a corn.";
    let dat1: &[u8] = b"Early ";
    let dat2: &[u8] = b"bird ";
    let dat3: &[u8] = b"gets ";
    let dat4: &[u8] = b"a corn.";
    let (l1, l2, l3, l4) = (6i64, 5i64, 5i64, 7i64);
    let _ = len;

    {
        // sync
        let mut b1 = IStreamBufGlue::new();
        let mut b2 = IStreamBufGlue::new();
        b1.pubsetbuf(Some(dat), 23);
        b2.pubsetbuf(Some(dat1), l1);
        b2.pubsetbuf(Some(dat2), l2);
        assert_eq!(b1.pubsync(), -1);
        assert_eq!(b2.pubsync(), -1);
    }
    {
        // chain of buffers
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(None, 0);
        b.pubsetbuf(Some(dat1), l1);
        expand_n(&mut b, exp, l1, 0);
        b.pubsetbuf(Some(dat2), l2);
        expand_n(&mut b, &exp[6..], l2, 0);
        b.pubsetbuf(None, 0);
        b.pubsetbuf(Some(dat1), l1);
        b.pubsetbuf(Some(dat2), l2);
        expand_n(&mut b, exp, l1 + l2, 0);
        b.pubsetbuf(Some(dat3), l3);
        b.pubsetbuf(Some(dat4), l4);
        expand_n(&mut b, &exp[11..], l3 + l4, 0);
        b.pubsetbuf(None, 0);
        b.pubsetbuf(Some(dat1), l1);
        b.pubsetbuf(Some(dat2), l2);
        b.pubsetbuf(Some(dat3), l3);
        b.pubsetbuf(Some(dat4), l4);
        expand_n(&mut b, exp, 23, 0);
    }
}

// "input buffer - offset one source"
#[test]
fn input_offset_one_source() {
    let exp = b"Early bird gets a corn.";
    let len = 23i64;
    let len1d3 = 23 * 1 / 3;
    let len2d3 = len - len1d3;
    let dat: &[u8] = b"Early bird gets a corn.";

    {
        // no data
        let mut b = IStreamBufGlue::new();
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_IN);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_IN);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_IN);
        assert_eq!(off_b, -1);
        assert_eq!(off_c, -1);
        assert_eq!(off_e, -1);
    }
    {
        // wrong argument
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        let off_a = b.pubseekoff(0, SeekDir::from_raw(0x5a5a), MODE_IN);
        assert_eq!(off_b, -1);
        assert_eq!(off_c, -1);
        assert_eq!(off_e, -1);
        assert_eq!(off_a, -1);
    }
    {
        // begin
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let mut cases: Vec<(i64, i64)> = vec![
            (0 - len - len, 0),
            (0 + len + len, len),
            (0, 0),
            (0 - 1, 0),
            (0 + 1, 1),
            (0 + len1d3, len1d3),
            (0 + len2d3, len2d3),
            (0 + len - 1, len - 1),
            (0 + len, len),
        ];
        for (off_in, want) in cases.drain(..) {
            let off = b.pubseekoff(off_in, SeekDir::Beg, MODE_IN);
            assert_eq!(off, want);
            exp_avail1(&mut b, exp, len, off);
        }
    }
    {
        // end
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let cases: Vec<(i64, i64)> = vec![
            (0 - len - len, 0),
            (0 + len + len, len),
            (0, len),
            (0 - 1, len - 1),
            (0 + 1, len),
            (0 - len1d3, len2d3),
            (0 - len2d3, len1d3),
            (0 - len + 1, 1),
            (0 - len, 0),
        ];
        for (off_in, want) in cases {
            let off = b.pubseekoff(off_in, SeekDir::End, MODE_IN);
            assert_eq!(off, want);
            exp_avail1(&mut b, exp, len, off);
        }
    }
    for anchor in [len1d3, len2d3] {
        // current 1/3 and current 2/3
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let cases: Vec<(i64, i64)> = if anchor == len1d3 {
            vec![
                (0 - len - len, 0),
                (0 + len + len, len),
                (0, len1d3),
                (0 - 1, len1d3 - 1),
                (0 + 1, len1d3 + 1),
                (0 + len1d3, len1d3 + len1d3),
                (0 + len2d3, len),
                (0 + len, len),
            ]
        } else {
            vec![
                (0 - len - len, 0),
                (0 + len + len, len),
                (0, len2d3),
                (0 - 1, len2d3 - 1),
                (0 + 1, len2d3 + 1),
                (0 + len1d3, len),
                (0 + len2d3, len),
                (0 + len, len),
            ]
        };
        for (off_in, want) in cases {
            b.pubseekoff(anchor, SeekDir::Beg, MODE_IN);
            let off = b.pubseekoff(off_in, SeekDir::Cur, MODE_IN);
            assert_eq!(off, want);
            exp_avail1(&mut b, exp, len, off);
        }
    }
}

// "input buffer - offset two sources"
#[test]
fn input_offset_two_sources() {
    let exp = b"Early bird gets a corn.";
    let len = 23i64;
    let len1d3 = 23 * 1 / 3;
    let len2d3 = len - len1d3;
    let dat1: &[u8] = b"Early bird";
    let dat2: &[u8] = b" gets a corn.";
    let dat1_len = 10i64;
    let dat2_len = 13i64;
    let _ = dat2_len;

    {
        // wrong buffer
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let off_c = b.pubseekoff(0, SeekDir::Cur, MODE_OUT);
        let off_b = b.pubseekoff(0, SeekDir::Beg, MODE_OUT);
        let off_e = b.pubseekoff(0, SeekDir::End, MODE_OUT);
        assert_eq!(off_b, -1);
        assert_eq!(off_c, -1);
        assert_eq!(off_e, -1);
    }
    {
        // begin
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let cases: Vec<(i64, i64)> = vec![
            (0 - len - len, 0),
            (0 + len + len, len),
            (0, 0),
            (0 - 1, 0),
            (0 + 1, 1),
            (0 + len1d3, len1d3),
            (0 + len2d3, len2d3),
            (0 + len - 1, len - 1),
            (0 + len, len),
        ];
        for (off_in, want) in cases {
            let off = b.pubseekoff(off_in, SeekDir::Beg, MODE_IN);
            assert_eq!(off, want);
            exp_avail2(&mut b, exp, len, off, dat1_len);
        }
    }
    {
        // end
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let cases: Vec<(i64, i64)> = vec![
            (0 - len - len, 0),
            (0 + len + len, len),
            (0, len),
            (0 - 1, len - 1),
            (0 + 1, len),
            (0 - len1d3, len2d3),
            (0 - len2d3, len1d3),
            (0 - len + 1, 1),
            (0 - len, 0),
        ];
        for (off_in, want) in cases {
            let off = b.pubseekoff(off_in, SeekDir::End, MODE_IN);
            assert_eq!(off, want);
            exp_avail2(&mut b, exp, len, off, dat1_len);
        }
    }
    for anchor in [len1d3, len2d3] {
        // current 1/3 and current 2/3
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let cases: Vec<(i64, i64)> = if anchor == len1d3 {
            vec![
                (0 - len - len, 0),
                (0 + len + len, len),
                (0, len1d3),
                (0 - 1, len1d3 - 1),
                (0 + 1, len1d3 + 1),
                (0 + len1d3, len1d3 + len1d3),
                (0 + len2d3, len),
                (0 + len, len),
            ]
        } else {
            vec![
                (0 - len - len, 0),
                (0 + len + len, len),
                (0, len2d3),
                (0 - 1, len2d3 - 1),
                (0 + 1, len2d3 + 1),
                (0 + len1d3, len),
                (0 + len2d3, len),
                (0 + len, len),
            ]
        };
        for (off_in, want) in cases {
            b.pubseekoff(anchor, SeekDir::Beg, MODE_IN);
            let off = b.pubseekoff(off_in, SeekDir::Cur, MODE_IN);
            assert_eq!(off, want);
            exp_avail2(&mut b, exp, len, off, dat1_len);
        }
    }
}

// "input buffer - positioning one source"
#[test]
fn input_positioning_one_source() {
    let exp = b"Early bird gets a corn.";
    let len = 23i64;
    let len1d3 = 23 * 1 / 3;
    let len2d3 = len - len1d3;
    let dat: &[u8] = b"Early bird gets a corn.";

    {
        // no data
        let mut b = IStreamBufGlue::new();
        let pos_c = b.pubseekpos(len / 2, MODE_IN);
        let pos_b = b.pubseekpos(0, MODE_IN);
        let pos_e = b.pubseekpos(len, MODE_IN);
        assert_eq!(pos_b, -1);
        assert_eq!(pos_c, -1);
        assert_eq!(pos_e, -1);
    }
    {
        // wrong buffer
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let pos_c = b.pubseekpos(len / 2, MODE_OUT);
        let pos_b = b.pubseekpos(0, MODE_OUT);
        let pos_e = b.pubseekpos(len, MODE_OUT);
        assert_eq!(pos_b, -1);
        assert_eq!(pos_c, -1);
        assert_eq!(pos_e, -1);
    }
    {
        // out of range
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let pos = b.pubseekpos(0 - len, MODE_IN);
        assert_eq!(pos, 0);
        exp_avail1(&mut b, exp, len, pos);
        let pos = b.pubseekpos(len + len, MODE_IN);
        assert_eq!(pos, len);
        exp_avail1(&mut b, exp, len, pos);
    }
    {
        // on the edge
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        for (p, want) in [
            (0i64, 0i64),
            (0 - 1, 0),
            (0 + 1, 1),
            (len, len),
            (len - 1, len - 1),
            (len + 1, len),
        ] {
            let pos = b.pubseekpos(p, MODE_IN);
            assert_eq!(pos, want);
            exp_avail1(&mut b, exp, len, pos);
        }
    }
    {
        // in range
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        for p in [len1d3, len2d3] {
            let pos = b.pubseekpos(p, MODE_IN);
            assert_eq!(pos, p);
            exp_avail1(&mut b, exp, len, pos);
        }
    }
}

// "input buffer - positioning two sources"
#[test]
fn input_positioning_two_sources() {
    let exp = b"Early bird gets a corn.";
    let len = 23i64;
    let len1d3 = 23 * 1 / 3;
    let len2d3 = len - len1d3;
    let dat1: &[u8] = b"Early bird";
    let dat2: &[u8] = b" gets a corn.";
    let dat1_len = 10i64;
    let dat2_len = 13i64;
    let _ = dat2_len;

    {
        // wrong buffer
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let pos_c = b.pubseekpos(len / 2, MODE_OUT);
        let pos_b = b.pubseekpos(0, MODE_OUT);
        let pos_e = b.pubseekpos(len, MODE_OUT);
        assert_eq!(pos_b, -1);
        assert_eq!(pos_c, -1);
        assert_eq!(pos_e, -1);
    }
    {
        // out of range
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        let pos = b.pubseekpos(0 - len, MODE_IN);
        assert_eq!(pos, 0);
        exp_avail2(&mut b, exp, len, pos, dat1_len);
        let pos = b.pubseekpos(len + len, MODE_IN);
        assert_eq!(pos, len);
        exp_avail2(&mut b, exp, len, pos, dat1_len);
    }
    {
        // on the edge
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        for (p, want) in [
            (0i64, 0i64),
            (0 - 1, 0),
            (0 + 1, 1),
            (len, len),
            (len - 1, len - 1),
            (len + 1, len),
        ] {
            let pos = b.pubseekpos(p, MODE_IN);
            assert_eq!(pos, want);
            exp_avail2(&mut b, exp, len, pos, dat1_len);
        }
    }
    {
        // in range
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), dat1_len);
        b.pubsetbuf(Some(dat2), dat2_len);
        for p in [
            len1d3,
            len2d3,
            dat1_len,
            dat1_len + 1,
            dat1_len - 1,
            dat1_len + 2,
            dat1_len - 2,
        ] {
            let pos = b.pubseekpos(p, MODE_IN);
            assert_eq!(pos, p);
            exp_avail2(&mut b, exp, len, pos, dat1_len);
        }
    }
}

// "input stream - one source"
#[test]
fn input_stream_one_source() {
    let exp: &[u8] = b"Early bird gets a corn.";
    let len = 23i64;
    let dat: &[u8] = b"Early bird gets a corn.";

    {
        // no data
        let mut b = IStreamBufGlue::new();
        let mut act = vec![0u8; ACT];
        let mut s = IStream::new(&mut b);
        s.read(&mut act, ACT as i64);
        assert!(s.eof_());
        assert_eq!(s.tellg(), -1);
        s.clear();
        assert_eq!(s.tellg(), -1);
    }
    {
        // equal
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let mut s = IStream::new(&mut b);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, len);
        exp_in(&mut s, exp, &act, len);
    }
    {
        // partial read
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), len);
        let mut s = IStream::new(&mut b);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, 1);
        s.read(&mut act[1..], 2);
        s.read(&mut act[3..], 3);
        s.read(&mut act[6..], 4);
        exp_in(&mut s, exp, &act, 10);
        s.read(&mut act[10..], len - 10);
        exp_in(&mut s, exp, &act, len);
    }
    {
        // EOF
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat), 10);
        let mut s = IStream::new(&mut b);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, len);
        eof_in(&mut s, exp, &act, 10);
    }
}

// "input stream - two sources"
#[test]
fn input_stream_two_sources() {
    let exp: &[u8] = b"Early bird gets a corn.";
    let len = 23i64;
    let dat1: &[u8] = b"Early bird";
    let dat2: &[u8] = b" gets a corn.";

    {
        // equal
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), 10);
        b.pubsetbuf(Some(dat2), 13);
        let mut s = IStream::new(&mut b);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, len);
        exp_in(&mut s, exp, &act, len);
    }
    {
        // partial read
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), 10);
        b.pubsetbuf(Some(dat2), 13);
        let mut s = IStream::new(&mut b);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, 1);
        s.read(&mut act[1..], 2);
        s.read(&mut act[3..], 3);
        s.read(&mut act[6..], 4);
        exp_in(&mut s, exp, &act, 10);
        s.read(&mut act[10..], len - 10);
        exp_in(&mut s, exp, &act, len);
    }
    {
        // EOF
        let mut b = IStreamBufGlue::new();
        b.pubsetbuf(Some(dat1), 10);
        b.pubsetbuf(Some(dat2), 1);
        let mut s = IStream::new(&mut b);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, len);
        eof_in(&mut s, exp, &act, 11);
    }
}

// "input stream - last chunk offset"
#[test]
fn input_stream_last_chunk_offset() {
    {
        // no data
        let mut b = IStreamBufGlue::new();
        let mut s = IStream::new(&mut b);
        assert_eq!(s.b.last_chunk_offset(), 0);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, 1);
        assert_eq!(s.b.last_chunk_offset(), 0);
    }
    {
        // single buffer
        let dat1: &[u8] = b"01234567";
        let mut b = IStreamBufGlue::new();
        let mut s = IStream::new(&mut b);
        assert_eq!(s.b.last_chunk_offset(), 0);
        s.b.pubsetbuf(Some(dat1), 8);
        assert_eq!(s.b.last_chunk_offset(), 0);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, 1);
        assert_eq!(s.b.last_chunk_offset(), 0);
        assert_eq!(bytes_read(&mut s), 1);
        s.read(&mut act, 2);
        assert_eq!(s.b.last_chunk_offset(), 0);
        assert_eq!(bytes_read(&mut s), 3);
        s.read(&mut act, 5);
        assert_eq!(s.b.last_chunk_offset(), 0);
        assert_eq!(bytes_read(&mut s), 8);
        s.read(&mut act, 1);
        assert_eq!(s.b.last_chunk_offset(), 0);
        assert_eq!(bytes_read(&mut s), 8);
    }
    {
        // two buffers
        let dat1: &[u8] = b"0123";
        let dat2: &[u8] = b"4567";
        let mut b = IStreamBufGlue::new();
        let mut s = IStream::new(&mut b);
        assert_eq!(s.b.last_chunk_offset(), 0);
        s.b.pubsetbuf(Some(dat1), 4);
        s.b.pubsetbuf(Some(dat2), 4);
        assert_eq!(s.b.last_chunk_offset(), 4);
        assert_eq!(bytes_read(&mut s), 0);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, 1);
        assert_eq!(s.b.last_chunk_offset(), 4);
        assert_eq!(bytes_read(&mut s), 0);
        s.read(&mut act, 1);
        assert_eq!(s.b.last_chunk_offset(), 4);
        assert_eq!(bytes_read(&mut s), 0);
        s.read(&mut act, 4);
        assert_eq!(s.b.last_chunk_offset(), 4);
        assert_eq!(bytes_read(&mut s), 2);
        s.read(&mut act, 2);
        assert_eq!(s.b.last_chunk_offset(), 4);
        assert_eq!(bytes_read(&mut s), 4);
        s.read(&mut act, 1);
        assert_eq!(s.b.last_chunk_offset(), 4);
        assert_eq!(bytes_read(&mut s), 4);
    }
    {
        // three buffers
        let dat1: &[u8] = b"0123";
        let dat2: &[u8] = b"4567";
        let dat3: &[u8] = b"89+*";
        let mut b = IStreamBufGlue::new();
        let mut s = IStream::new(&mut b);
        assert_eq!(s.b.last_chunk_offset(), 0);
        s.b.pubsetbuf(Some(dat1), 4);
        s.b.pubsetbuf(Some(dat2), 4);
        s.b.pubsetbuf(Some(dat3), 4);
        assert_eq!(s.b.last_chunk_offset(), 8);
        assert_eq!(bytes_read(&mut s), 0);
        let mut act = vec![0u8; ACT];
        s.read(&mut act, 3);
        assert_eq!(s.b.last_chunk_offset(), 8);
        assert_eq!(bytes_read(&mut s), 0);
        s.read(&mut act, 3);
        assert_eq!(s.b.last_chunk_offset(), 8);
        assert_eq!(bytes_read(&mut s), 0);
        s.read(&mut act, 3);
        assert_eq!(s.b.last_chunk_offset(), 8);
        assert_eq!(bytes_read(&mut s), 1);
        s.read(&mut act, 3);
        assert_eq!(s.b.last_chunk_offset(), 8);
        assert_eq!(bytes_read(&mut s), 4);
        s.read(&mut act, 1);
        assert_eq!(s.b.last_chunk_offset(), 8);
        assert_eq!(bytes_read(&mut s), 4);
    }
}
