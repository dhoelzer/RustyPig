//! Faithful Rust port of `utils/stats/response_buf.{h,cc}` (ground truth
//! @ fe29cbe7403a): a `std::streambuf` subclass that chunks stats output
//! into pieces that fit a control connection's `respond()` limit.
//!
//! Deviations & fidelity notes (see KNOWN DEVIATIONS.md):
//! - C holds a raw `ControlConn*` and calls the global `snort::LogMessage`
//!   when it is null. Rust models the two externals as traits:
//!   [`ControlConn`] (only reached with `("%s", chunk)` at the sole call
//!   site) and [`LogSink`] (stands in for the global). `send_chunk` picks
//!   between them exactly as C does.
//! - The C++ `std::ostream` half of the probe (sentry + `operator<<` +
//!   `write` + badbit) lives in libstdc++, not in this TU; `emulated
//!   _ostream_insert` reproduces `__ostream_insert`/`__ostream_write`
//!   (`bits/ostream_insert.h`) and `ostream::write` (`bits/ostream.tcc`)
//!   with the semantics verified against the installed headers: the
//!   sentry skips the operation once `bad` is set, and a short `sputn`
//!   sets badbit. `xsputn` is the verbatim `bits/streambuf.tcc` loop.
//!   The bad flag itself is the ostream's state, so it is tracked by the
//!   driver via `EmuOstream` rather than inside the buffered class.
//! - C++ protected virtual dispatch (streambuf calling `overflow`/`sync`
//!   through the vtable) is direct method calls; behavior identical.
//! - `flush()` copies the buffer to a local before calling `send_chunk`
//!   (Rust borrow split: the chunk is read while the sink mutates; C
//!   reads the same memory through the pointer, contents identical).
//! - The C destructor (`~StatsResponseBuf` -> `flush()`) is the explicit
//!   [`StatsResponseBuf::dtor`], mirrored at the C destruction point.
//! - `static_assert(RESPONSE_BUFFER_SIZE < STD_BUF)` is a Rust `assert!`
//!   in const context.
//!
//! No pinned-vector deviations: 1023-byte effective put capacity
//! (`setp(buffer, buffer + sizeof(buffer) - 1)`), failed flush keeps the
//! put area intact (destructor re-sends the same bytes), `send_chunk`
//! skips empty/first-byte-NUL chunks without touching the sinks, and C
//! `%s` semantics truncate at the first NUL.
use crate::log::messages::STD_BUF;

pub const RESPONSE_BUFFER_SIZE: usize = 1024;

// C static_assert(RESPONSE_BUFFER_SIZE < STD_BUF, "Stats response chunks
// must fit in ControlConn::respond()")
const _: () = assert!(RESPONSE_BUFFER_SIZE < STD_BUF);

/// `std::char_traits<char>::eof()` as `int_type` (i32, per the streambuf
/// conventions already pinned in `helpers::streambuf`).
pub const EOF_INT: i32 = -1;

/// Stands in for upstream `ControlConn` (a full port of which belongs to
/// the control/shell layer). The only method `response_buf.cc` reaches is
/// `respond(const char* format, ...)` at the `("%s", data)` call site, so
/// the chunk arrives as raw bytes; the witness is responsible for the C
/// `%s` NUL-truncation semantics, exactly as `vsnprintf` applied them.
pub trait ControlConn {
    fn respond(&mut self, chunk: &[u8]) -> bool;
}

/// Stands in for the global `snort::LogMessage("%s", data)`.
pub trait LogSink {
    fn log_message(&mut self, chunk: &[u8]);
}

/// C `snort::StatsResponseBuf : public std::streambuf`. Put-area pointers
/// are offsets into the fixed `buffer` (pbase is always 0).
pub struct StatsResponseBuf<'a> {
    ctrlcon: Option<&'a mut dyn ControlConn>,
    log: &'a mut dyn LogSink,

    // C buffer + put-area pointers: setp(buffer, buffer + sizeof -
    // 1) in the ctor.
    buffer: [u8; RESPONSE_BUFFER_SIZE],
    pptr: usize,
    epptr: usize,
}

impl<'a> StatsResponseBuf<'a> {
    pub fn new(
        ctrlcon: Option<&'a mut dyn ControlConn>,
        log: &'a mut dyn LogSink,
    ) -> Self {
        StatsResponseBuf {
            // C ctor body is just `: ctrlcon(conn)`; setp() below.
            ctrlcon,
            log,
            buffer: [0; RESPONSE_BUFFER_SIZE],
            pptr: 0,
            epptr: RESPONSE_BUFFER_SIZE - 1,
        }
    }

    /// C `~StatsResponseBuf() { flush(); }`
    pub fn dtor(&mut self) {
        self.flush();
    }

    /// C virtual `sync() { return flush(); }`
    pub fn sync(&mut self) -> i32 {
        self.flush()
    }

    /// C `flush()`.
    pub fn flush(&mut self) -> i32 {
        let pending = self.pptr; // pptr() - pbase()
        if pending > 0 {
            self.buffer[pending] = 0; // *pptr() = 0 (index <= epptr fits)
            // Borrow split (documented deviation): copy the C string
            // out before handing the sink a mutable borrow.
            let snapshot: [u8; RESPONSE_BUFFER_SIZE] = self.buffer;
            if !self.send_chunk(&snapshot[..=pending]) {
                return -1;
            }
            self.setp();
        }
        0
    }

    /// C virtual `overflow(int_type ch)`.
    pub fn overflow(&mut self, ch: i32) -> i32 {
        if ch == EOF_INT {
            // traits_type::not_eof(eof) == 0 on success
            return if self.sync() == 0 { 0 } else { EOF_INT };
        }

        if self.pptr == self.epptr && self.sync() != 0 {
            return EOF_INT;
        }

        self.buffer[self.pptr] = (ch & 0xff) as u8;
        self.pptr += 1; // pbump(1)
        ch
    }

    /// C `int flush()` is protected; C++-internal callers use
    /// `sync`. Rust keeps the direct call from C's own bodies.
    fn setp(&mut self) {
        // setp(buffer, buffer + sizeof(buffer) - 1)
        self.pptr = 0;
        self.epptr = RESPONSE_BUFFER_SIZE - 1;
    }

    /// C `bool send_chunk(const char* data) const`.
    fn send_chunk(&mut self, data: &[u8]) -> bool {
        if data.is_empty() || data[0] == 0 {
            // `if ( !data || !*data ) return true;` -- nothing sent,
            // neither respond nor LogMessage runs.
            return true;
        }

        if let Some(conn) = &mut self.ctrlcon {
            conn.respond(data)
        } else {
            self.log.log_message(data);
            true
        }
    }

    /// libstdc++ `basic_streambuf::xsputn` (`bits/streambuf.tcc`),
    /// transcribed verbatim; `sputn` is `pub fn sputn -> xsputn`.
    pub fn xsputn(&mut self, s: &[u8]) -> i64 {
        let n = s.len() as i64;
        let mut ret: i64 = 0;
        let mut si: usize = 0;
        while ret < n {
            let buf_len = self.epptr as i64 - self.pptr as i64;
            if buf_len != 0 {
                let remaining = n - ret;
                let len = std::cmp::min(buf_len, remaining) as usize;
                self.buffer[self.pptr..self.pptr + len]
                    .copy_from_slice(&s[si..si + len]);
                ret += len as i64;
                si += len;
                self.pptr += len; // __safe_pbump(len)
            }

            if ret < n {
                let c = self.overflow(s[si] as i32 & 0xff); // to_int_type
                if c != EOF_INT {
                    ret += 1;
                    si += 1;
                } else {
                    break;
                }
            }
        }
        ret
    }

    pub fn sputn(&mut self, s: &[u8]) -> i64 {
        self.xsputn(s)
    }
}

/// The probe-side `std::ostream` over a [`StatsResponseBuf`]. C++ splits
/// the stream state (good/bad) from the buffer; kept separate here for
/// the same reason. Emulates `operator<<(const char*)` / `operator<<
/// (std::string)` (sentry + `__ostream_write`) and `ostream::write`:
/// sentry skips the op once bad is set, and a short `sputn` sets badbit
/// (semantics verified against /usr/include/c++/14 `bits/
/// ostream_insert.h`, `bits/ostream.tcc`).
pub struct EmuOstream<'a, 'b> {
    pub bad: bool,
    sb: &'b mut StatsResponseBuf<'a>,
}

impl<'a, 'b> EmuOstream<'a, 'b> {
    pub fn new(sb: &'b mut StatsResponseBuf<'a>) -> Self {
        EmuOstream { bad: false, sb }
    }

    /// `out << text` where `text` is the byte slice already NUL-stripped
    /// (`operator<<(const char*)` measures with `traits::length`; the
    /// `std::string` overload passes `size()`).
    pub fn insert(&mut self, text: &[u8]) {
        // sentry: skip when the stream already failed
        if self.bad {
            return;
        }
        // width() is always 0 in the probe, so __ostream_insert reduces
        // to __ostream_write: sputn; short write -> badbit
        if self.sb.sputn(text) != text.len() as i64 {
            self.bad = true;
        }
    }

    /// `out.write(s, n)` (ostream.tcc: sentry; `sputn != n -> badbit`).
    pub fn write(&mut self, s: &[u8]) {
        if self.bad {
            return;
        }
        if self.sb.sputn(s) != s.len() as i64 {
            self.bad = true;
        }
    }
}
