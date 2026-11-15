// Port of snort3 helpers/streambuf.{h,cc}
// (Author Dave Rigby, 2021-2026 Cisco).
//
// C++ std::streambuf base-class bookkeeping (eback/gptr/egptr,
// pbase/pptr/epptr) is modeled with i64 offsets into the chunk store /
// owned vector; the ported virtuals are line-for-line. The public
// libstdc++ entry points exercised by streambuf_test.cc (in_avail,
// sgetc, sbumpc, snextc, sungetc, sputbackc, sgetn, sputc, sputn,
// pubsetbuf, pubseekoff, pubseekpos, pubsync) are replicated here with
// libstdc++ 14 semantics (verified against /usr/include/c++/14/streambuf)
// so the Catch suite ports without an iostream layer for the buffer
// tests. KNOWN DEVIATIONS.md lists the audited differences.

pub const SOCKET_EOF: i32 = -1; // std::char_traits<char>::eof()

pub const SIZE_LIMIT: i64 = 1 << 20;

// ios_base::in / ios_base::out as bitmask (libstdc++: in=1, out=2)
pub const MODE_IN: u32 = 1;
pub const MODE_OUT: u32 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeekDir {
    Beg,
    Cur,
    End,
    /// anything else (C: static_cast<seekdir>(0x5a5a) etc.) -> -1
    Invalid,
}

impl SeekDir {
    /// libstdc++ seekdir enum values: cur=1, beg=2, end=3.
    pub fn from_raw(v: i32) -> SeekDir {
        match v {
            1 => SeekDir::Cur,
            2 => SeekDir::Beg,
            3 => SeekDir::End,
            _ => SeekDir::Invalid,
        }
    }
}

const fn max64(a: i64, b: i64) -> i64 {
    if a > b {
        a
    } else {
        b
    }
}
const fn min64(a: i64, b: i64) -> i64 {
    if a < b {
        a
    } else {
        b
    }
}

//--------------------------------------------------------------------------
// istreambuf_glue
//--------------------------------------------------------------------------

struct Chunk {
    len: i64,
    /// cumulative begin offset (C get<2> "b_off")
    b_off: i64,
}

pub struct IStreamBufGlue<'a> {
    // C chunks: vector<tuple<char*, streamsize, streamoff>>
    chunks: Vec<Chunk>,
    store: Vec<&'a [u8]>,
    cur_idx: usize,
    size: i64,

    // C streambuf get-area pointers as offsets into [0, total store len);
    // eback/gptr/egptr of std::streambuf default-init to null == 0 here.
    eback: i64,
    gptr: i64,
    egptr: i64,
}

impl<'a> Default for IStreamBufGlue<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IStreamBufGlue<'a> {
    pub fn new() -> Self {
        IStreamBufGlue {
            chunks: Vec::new(),
            store: Vec::new(),
            cur_idx: 0,
            size: 0,
            eback: 0,
            gptr: 0,
            egptr: 0,
        }
    }

    // ---- public of the C class ----
    pub fn last_chunk_offset(&self) -> i64 {
        if self.chunks.is_empty() {
            return 0;
        }
        self.chunks[self.chunks.len() - 1].b_off
    }

    // ---- protected virtuals of the C class ----
    pub fn pubsetbuf(&mut self, data: Option<&'a [u8]>, n: i64) {
        // C: n = max(0, n)
        let n = max64(0, n);

        if data.is_none() || n == 0 {
            self.chunks.clear();
            self.store.clear();
            self.cur_idx = 0;
            self.size = 0;
            return;
        }
        let data = data.unwrap();

        if self.size == 0 {
            // setg(s, s, s+n): the store index space starts fresh when a
            // chain has just been cleared, so store index == b_off holds.
            let base = self.store_total();
            self.eback = base;
            self.gptr = base;
            self.egptr = base + n;
        }

        self.store.push(data);
        self.chunks.push(Chunk {
            len: n,
            b_off: self.size,
        });
        self.size += n;
    }

    fn store_total(&self) -> i64 {
        self.store.iter().map(|s| s.len() as i64).sum()
    }

    pub fn pubseekoff(&mut self, off: i64, way: SeekDir, which: u32) -> i64 {
        if which & MODE_IN == 0 {
            return -1;
        }
        if self.chunks.is_empty() {
            return -1;
        }

        let c_chunk_off = self.chunks[self.cur_idx].b_off;
        let c_off = c_chunk_off + self.gptr - self.eback;

        let pos = match way {
            SeekDir::Beg => 0,
            SeekDir::Cur => c_off,
            SeekDir::End => self.size,
            SeekDir::Invalid => return -1,
        };

        let mut pos = pos + off;
        pos = max64(0, pos);
        pos = min64(pos, self.size);

        for i in 0..self.chunks.len() {
            let len = self.chunks[i].len;
            let b_off = self.chunks[i].b_off;
            let e_off = b_off + len;

            if b_off <= pos && (pos < e_off || (pos == e_off && self.last_chunk(i))) {
                // setg(ptr, ptr - b_off + pos, ptr + len): the get-area
                // offsets are absolute store positions; ptr here sits at
                // the chunk's b_off, so gptr = pos + (chunk base - b_off).
                let base = self.chunk_base(i);
                self.eback = base;
                self.gptr = base + (pos - b_off);
                self.egptr = base + len;
                self.cur_idx = i;
                break;
            }
        }

        pos
    }

    pub fn pubseekpos(&mut self, pos: i64, which: u32) -> i64 {
        if which & MODE_IN == 0 {
            return -1;
        }
        if self.chunks.is_empty() {
            return -1;
        }

        let mut pos = pos;
        pos = max64(0, pos);
        pos = min64(pos, self.size);

        for i in 0..self.chunks.len() {
            let len = self.chunks[i].len;
            let b_off = self.chunks[i].b_off;
            let e_off = b_off + len;

            if b_off <= pos && pos < e_off {
                let off = pos - b_off;
                let base = self.chunk_base(i);
                self.eback = base;
                self.gptr = base + off;
                self.egptr = base + len;
                self.cur_idx = i;
                break;
            }
        }

        pos
    }

    pub fn pubsync(&mut self) -> i32 {
        -1
    }

    pub fn showmanyc(&mut self) -> i64 {
        if self.chunks.is_empty() {
            return -1;
        }
        let chunk_off = self.chunks[self.cur_idx].b_off;
        let off = chunk_off + self.gptr - self.eback;
        self.size - off
    }

    pub fn xsgetn(&mut self, dst: &mut [u8], n: i64) -> i64 {
        // C assert(n >= 0)
        debug_assert!(n >= 0);

        if self.chunks.is_empty() {
            return -1;
        }

        let mut n = n;
        let mut out = 0usize;
        let mut r = 0i64;

        loop {
            let l = min64(self.egptr - self.gptr, n);
            // memcpy(s, gptr(), l)
            for k in 0..l {
                dst[out + k as usize] = self.at(self.gptr + k);
            }
            self.gptr += l; // gbump(l)

            out += l as usize;
            r += l;
            n -= l;

            if n <= 0 || self.last_chunk(self.cur_idx) {
                break;
            }

            self.cur_idx += 1;

            // setg(ptr, ptr, ptr+len)
            let len = self.chunks[self.cur_idx].len;
            let base = self.chunk_base(self.cur_idx);
            self.eback = base;
            self.gptr = base;
            self.egptr = base + len;
        }

        r
    }

    pub fn underflow(&mut self) -> i32 {
        if self.chunks.is_empty() {
            return SOCKET_EOF;
        }
        if self.last_chunk(self.cur_idx) {
            return SOCKET_EOF;
        }

        self.cur_idx += 1;
        let len = self.chunks[self.cur_idx].len;
        let base = self.chunk_base(self.cur_idx);
        self.eback = base;
        self.gptr = base;
        self.egptr = base + len;

        self.sgetc()
    }

    fn last_chunk(&self, idx: usize) -> bool {
        idx + 1 >= self.chunks.len()
    }

    // ---- libstdc++ public streambuf entry points used by the tests ----

    pub fn in_avail(&mut self) -> i64 {
        let ret = self.egptr - self.gptr;
        if ret != 0 {
            ret
        } else {
            self.showmanyc()
        }
    }

    pub fn sgetc(&mut self) -> i32 {
        if self.gptr < self.egptr {
            self.at(self.gptr) as i32
        } else {
            self.underflow()
        }
    }

    pub fn sbumpc(&mut self) -> i32 {
        if self.gptr < self.egptr {
            let c = self.at(self.gptr) as i32;
            self.gptr += 1;
            c
        } else {
            self.uflow()
        }
    }

    pub fn snextc(&mut self) -> i32 {
        if self.sbumpc() == SOCKET_EOF {
            SOCKET_EOF
        } else {
            self.sgetc()
        }
    }

    /// base-class uflow: underflow, then bump.
    pub fn uflow(&mut self) -> i32 {
        let ret = self.underflow();
        if ret != SOCKET_EOF {
            let c = self.at(self.gptr) as i32;
            self.gptr += 1;
            return c;
        }
        SOCKET_EOF
    }

    pub fn sungetc(&mut self) -> i32 {
        if self.eback < self.gptr {
            self.gptr -= 1; // gbump(-1)
            self.at(self.gptr) as i32
        } else {
            self.pbackfail(SOCKET_EOF)
        }
    }

    pub fn sputbackc(&mut self, c: u8) -> i32 {
        let testpos = self.eback < self.gptr;
        if !testpos || self.at(self.gptr - 1) != c {
            self.pbackfail(c as i32)
        } else {
            self.gptr -= 1;
            self.at(self.gptr) as i32
        }
    }

    /// base-class pbackfail: does nothing, returns eof.
    pub fn pbackfail(&mut self, _c: i32) -> i32 {
        SOCKET_EOF
    }

    pub fn sgetn(&mut self, dst: &mut [u8], n: i64) -> i64 {
        self.xsgetn(dst, n)
    }

    // ---- helpers ----

    /// cumulative store position of chunk i's data start.
    fn chunk_base(&self, i: usize) -> i64 {
        self.store[..i].iter().map(|s| s.len() as i64).sum()
    }

    /// byte at offset position in the concatenated store.
    fn at(&self, p: i64) -> u8 {
        let mut p = p as usize;
        for s in &self.store {
            if p < s.len() {
                return s[p];
            }
            p -= s.len();
        }
        unreachable!("get-area offset outside store");
    }
}

//--------------------------------------------------------------------------
// ostreambuf_infl
//--------------------------------------------------------------------------

/// C states[] table: each entry is (next, n) with self-referential chain;
/// Rust index simulates the pointer chain. states[i].s -> i+1 except the
/// last two both point at states[4] (index 4, saturating growth).
// states[i].s: states[0].s=states+1 ... states[4].s=states+4 (self)
const STATE_S: [usize; 5] = [1, 2, 3, 4, 4];
const STATE_N: [i64; 5] = [1 << 11, 1 << 12, 1 << 13, 1 << 14, 1 << 15];

pub struct OStreamBufInfl {
    // C states[] / gen: the generator cursor (index into STATE_* + cur n)
    gen_s: usize,
    gen_n: i64,

    // C put-area pointers as offsets into buf (pbase==0; an unowned C
    // external buffer is modeled by taking ownership in pubsetbuf, see
    // KNOWN DEVIATIONS.md)
    pbase: bool, // buffer allocated (pbase != nullptr)
    pptr: i64,
    epptr: i64,
    buf: Vec<u8>,
}

impl Default for OStreamBufInfl {
    fn default() -> Self {
        Self::new()
    }
}

impl OStreamBufInfl {
    pub fn new() -> Self {
        OStreamBufInfl {
            gen_s: STATE_S[0], // gen(states[0]): s = states+1
            gen_n: STATE_N[0],
            pbase: false,
            pptr: 0,
            epptr: 0,
            buf: Vec::new(),
        }
    }

    // ---- public of the C class ----

    pub fn reserve(&mut self, n: i64) {
        let size = self.epptr - self.pbase_i();
        if n > size {
            self.enlarge_len(n - size);
        }
    }

    /// C take_data(): releases the buffer; caller takes ownership.
    /// Returns None iff pbase == nullptr.
    pub fn take_data(&mut self) -> Option<Vec<u8>> {
        if !self.pbase {
            // C returns nullptr; nothing to take
            self.reset_gen();
            return None;
        }
        let d = std::mem::take(&mut self.buf);
        // setp(nullptr, nullptr)
        self.pbase = false;
        self.pptr = 0;
        self.epptr = 0;
        self.reset_gen();
        Some(d)
    }

    pub fn take_data_len(&mut self) -> (Option<Vec<u8>>, i64) {
        let n = self.pptr - self.pbase_i();
        let d = self.take_data();
        (d, n)
    }

    pub fn data(&self) -> &[u8] {
        if !self.pbase {
            return &[];
        }
        &self.buf
    }

    pub fn data_len(&self) -> i64 {
        if !self.pbase {
            return 0;
        }
        self.pptr - self.pbase_i()
    }

    // ---- protected virtuals of the C class ----

    /// C setbuf(s, n): takes ownership of an external buffer (Rust models
    /// the `new char[]` the tests always pass).
    pub fn pubsetbuf(&mut self, s: Option<Vec<u8>>, n: i64) {
        // C: n = min(n, size_limit); then setp(s, s + max(0, n))
        let n = min64(n, SIZE_LIMIT);

        // delete[] pbase()
        self.buf.clear();
        self.buf.shrink_to_fit();

        match s {
            Some(mut v) => {
                v.resize(n.max(0) as usize, 0);
                self.buf = v;
                self.pbase = true;
                self.pptr = 0;
                self.epptr = max64(0, n);
            }
            None => {
                // C setbuf(s=null, n): setp(nullptr, max(0,n) past null):
                // null base; epptr - pbase collapses to whatever, base stays
                // null -> treat as no buffer (C UB territory; tests never
                // exercise it, see KNOWN DEVIATIONS.md)
                self.pbase = false;
                self.pptr = 0;
                self.epptr = 0;
            }
        }
    }

    pub fn pubseekoff(&mut self, off: i64, way: SeekDir, which: u32) -> i64 {
        if which & MODE_OUT == 0 {
            return -1;
        }

        if off == 0 && way == SeekDir::Cur {
            return self.pptr - self.pbase_i();
        }

        let base = self.pbase_i();
        let size = self.epptr - base;

        let npos = match way {
            SeekDir::Beg => 0,
            SeekDir::Cur => self.pptr - base,
            SeekDir::End => self.epptr - base,
            SeekDir::Invalid => return -1,
        };

        let mut npos = npos + off;
        npos = max64(0, npos);
        npos = min64(npos, size);

        self.pptr = base + npos; // pbump(npos - cpos)
        npos
    }

    pub fn pubseekpos(&mut self, pos: i64, which: u32) -> i64 {
        if which & MODE_OUT == 0 {
            return -1;
        }

        let base = self.pbase_i();
        let size = self.epptr - base;

        let mut pos = pos;
        pos = max64(0, pos);
        pos = min64(pos, size);

        self.pptr = base + pos; // pbump(pos - cpos)
        pos
    }

    pub fn pubsync(&mut self) -> i32 {
        -1
    }

    pub fn xsputn(&mut self, s: &[u8], mut n: i64) -> i64 {
        // C assert(n >= 0); n = max(0, n)
        debug_assert!(n >= 0);
        n = max64(0, n);

        let c_avail = self.epptr - self.pptr;
        if n > c_avail {
            // C: gen.n > (n - c_avail) ? enlarge() : enlarge(n - c_avail)
            if self.gen_n > (n - c_avail) {
                self.enlarge();
            } else {
                self.enlarge_len(n - c_avail);
            }
        }

        let n_avail = self.epptr - self.pptr;
        n = min64(n, n_avail);

        // memcpy(pptr(), s, n)
        for k in 0..n {
            self.buf[(self.pptr + k) as usize] = s[k as usize];
        }
        self.pptr += n; // pbump(n)
        n
    }

    pub fn xsgetn(&mut self, dst: &mut [u8], mut n: i64) -> i64 {
        debug_assert!(n >= 0);

        if self.pptr != self.epptr {
            n = max64(0, n);
            let c_avail = self.epptr - self.pptr;
            n = min64(c_avail, n);

            // memcpy(s, pptr(), n): reads from the *unwritten* tail of
            // [pptr, epptr) — the C original's deliberate "get from the
            // output area" quirk (bytes past data_len are uninitialized
            // in C; here they are whatever the Vec holds, always 0 after
            // resize — see KNOWN DEVIATIONS.md)
            for k in 0..n {
                dst[k as usize] = self.buf[(self.pptr + k) as usize];
            }
            self.pptr += n; // pbump(n)
            return n;
        }
        0
    }

    pub fn overflow(&mut self, c: i32) -> i32 {
        if c == SOCKET_EOF {
            return SOCKET_EOF;
        }
        if !self.enlarge() {
            return SOCKET_EOF;
        }
        self.buf[self.pptr as usize] = c as u8; // *pptr() = c
        self.pptr += 1; // pbump(1)
        c
    }

    // ---- libstdc++ public streambuf entry points used by the tests ----

    pub fn sputc(&mut self, c: u8) -> i32 {
        if self.pptr < self.epptr {
            self.buf[self.pptr as usize] = c;
            self.pptr += 1;
            c as i32
        } else {
            self.overflow(c as i32)
        }
    }

    pub fn sputn(&mut self, s: &[u8], n: i64) -> i64 {
        self.xsputn(s, n)
    }

    pub fn sgetn(&mut self, dst: &mut [u8], n: i64) -> i64 {
        self.xsgetn(dst, n)
    }

    // ---- internals ----

    fn reset_gen(&mut self) {
        self.gen_s = STATE_S[0];
        self.gen_n = STATE_N[0];
    }

    fn pbase_i(&self) -> i64 {
        // pbase is always store index 0 or null; null collapses to 0
        0
    }

    /// C gen.get_next_size()
    fn get_next_size(&mut self) -> i64 {
        let r = self.gen_n;
        self.gen_n = STATE_N[self.gen_s];
        self.gen_s = STATE_S[self.gen_s];
        r
    }

    fn enlarge(&mut self) -> bool {
        let extra = self.get_next_size();
        self.enlarge_len(extra)
    }

    fn enlarge_len(&mut self, extra_len: i64) -> bool {
        // C assert(extra_len > 0)
        debug_assert!(extra_len > 0);

        let c_size = self.epptr - self.pbase_i();
        let mut n_size = c_size + extra_len;
        n_size = min64(n_size, SIZE_LIMIT);

        let n_off = self.pptr - self.pbase_i();

        // new char[n_size]; memcpy(n_pbase, c_pbase, c_size); delete[] old
        let mut n_buf = vec![0u8; n_size as usize];
        if self.pbase {
            n_buf[..c_size as usize].copy_from_slice(&self.buf[..c_size as usize]);
        }
        self.buf = n_buf;
        self.pbase = true;
        self.pptr = n_off; // setp + pbump(n_off)
        self.epptr = n_size;

        // C: return n_pbase != nullptr && n_epptr > n_pbase
        n_size > 0
    }
}
