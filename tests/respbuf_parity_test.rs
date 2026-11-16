//! Replay of `tools/stats_rb_harness/vectors.txt` (the ground-truth probe
//! over ORIGINAL utils/stats/response_buf.cc @ fe29cbe7403a) through
//! `snort3::utils::stats::response_buf`, plus direct translations of the
//! five upstream `TEST_CASE`s from
//! `src/utils/stats/test/response_buf_test.cc` (the C++ `gate` runs that
//! suite against real C++: 12 assertions / 5 cases green — both sides
//! green is the bar).
//!
//! The witness mirrors the probe's `emit_line`: RSP/LOG label,
//! `len=<strlen after %s>`, `ret` for RSP, then fwrite of the truncated
//! text -- so C's `%s` NUL-truncation is reproduced here.
use snort3::utils::stats::response_buf::{
    ControlConn, EmuOstream, EOF_INT, LogSink, StatsResponseBuf,
};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

fn nul_truncate(chunk: &[u8]) -> &[u8] {
    match chunk.iter().position(|&b| b == 0) {
        Some(i) => &chunk[..i],
        None => chunk,
    }
}

/// The probe's global witness state (C: file-static `respond_result`,
/// shared `responded`/`logged` accumulation -> here a line Vec).
struct Witness {
    out: Rc<RefCell<Vec<String>>>,
    respond_result: Rc<Cell<bool>>,
}

impl Witness {
    fn new() -> Witness {
        Witness { out: Rc::new(RefCell::new(Vec::new())), respond_result: Rc::new(Cell::new(true)) }
    }
}

struct WConn(Rc<RefCell<Vec<String>>>, Rc<Cell<bool>>);

impl ControlConn for WConn {
    fn respond(&mut self, chunk: &[u8]) -> bool {
        let text = String::from_utf8_lossy(nul_truncate(chunk)).into_owned();
        self.0.borrow_mut().push(format!("RSP len={} ret={} {text}", text.len(), if self.1.get() { 1 } else { 0 }));
        self.1.get()
    }
}

struct WLog(Rc<RefCell<Vec<String>>>);

impl LogSink for WLog {
    fn log_message(&mut self, chunk: &[u8]) {
        let text = String::from_utf8_lossy(nul_truncate(chunk)).into_owned();
        self.0.borrow_mut().push(format!("LOG len={} {text}", text.len()));
    }
}

fn line(out: &Rc<RefCell<Vec<String>>>, s: String) {
    out.borrow_mut().push(s);
}

/// Upstream suite translation. Each #[test] = one TEST_CASE, mirroring
/// `reset_output()`-fresh state. The CHECK statements run in TEST_CASE
/// scope, i.e. BEFORE the stack buffer's destructor.
mod upstream {
    use super::*;

    struct Fresh {
        out: Rc<RefCell<Vec<String>>>,
        conn: WConn,
        log: WLog,
    }

    fn fresh() -> Fresh {
        let w = Witness::new();
        Fresh {
            conn: WConn(w.out.clone(), w.respond_result.clone()),
            log: WLog(w.out.clone()),
            out: w.out,
        }
    }

    /// write_response(ctrlcon, text) helper from the suite.
    fn write_response(f: &mut Fresh, ctrlcon: bool, text: &[u8]) {
        let mut buf = if ctrlcon {
            StatsResponseBuf::new(Some(&mut f.conn), &mut f.log)
        } else {
            StatsResponseBuf::new(None, &mut f.log)
        };
        {
            let mut os = EmuOstream::new(&mut buf);
            os.insert(text);
        }
        buf.dtor(); // ~StatsResponseBuf at the end of the helper scope
    }

    fn responded(f: &Fresh) -> String {
        f.out
            .borrow()
            .iter()
            .filter(|l| l.starts_with("RSP"))
            .map(|l| l.splitn(4, ' ').nth(3).unwrap_or("").to_string())
            .collect()
    }

    fn logged(f: &Fresh) -> String {
        f.out
            .borrow()
            .iter()
            .filter(|l| l.starts_with("LOG"))
            .map(|l| l.splitn(3, ' ').nth(2).unwrap_or("").to_string())
            .collect()
    }

    #[test]
    fn logs_when_no_control_connection() {
        let mut f = fresh();
        write_response(&mut f, false, b"abc");
        // CHECK(responded.empty()); CHECK(logged == "abc")
        assert!(responded(&f).is_empty());
        assert_eq!(logged(&f), "abc");
    }

    #[test]
    fn responds_to_local_control_connections() {
        let mut f = fresh();
        write_response(&mut f, true, b"abc");
        // CHECK(responded == "abc"); CHECK(logged.empty())
        assert_eq!(responded(&f), "abc");
        assert!(logged(&f).is_empty());
    }

    #[test]
    fn responds_to_remote_control_connections_without_logging() {
        let mut f = fresh();
        // the upstream witness respond() ignores the local flag; the
        // remote case behaves identically through response_buf itself
        write_response(&mut f, true, b"abc");
        assert_eq!(responded(&f), "abc");
        assert!(logged(&f).is_empty());
    }

    #[test]
    fn handles_eof_overflow() {
        // separate locals so the out/log witness sinks can be inspected
        // while the buffer still holds them (C: globals, no borrow rules)
        let w = Witness::new();
        let (mut log, out) = (WLog(w.out.clone()), w.out.clone());
        {
            let mut buf = StatsResponseBuf::new(None, &mut log);
            // CHECK(overflow(eof) != eof); CHECK(responded.empty());
            // CHECK(logged.empty())  -- all BEFORE ~TestStatsResponseBuf
            let r = buf.overflow(EOF_INT);
            assert_ne!(r, EOF_INT);
            assert!(out.borrow().is_empty());
            buf.dtor();
        }
        assert!(out.borrow().is_empty());
    }

    fn rsp_texts(out: &RefCell<Vec<String>>) -> String {
        out.borrow()
            .iter()
            .filter_map(|l| l.strip_prefix("RSP len=1023 ret=0 "))
            .collect()
    }

    #[test]
    fn reports_full_buffer_flush_failure() {
        let w = Witness::new();
        let (mut conn, mut log, out) = (
            WConn(w.out.clone(), w.respond_result.clone()),
            WLog(w.out.clone()),
            w.out.clone(),
        );
        w.respond_result.set(false);
        {
            let mut buf = StatsResponseBuf::new(Some(&mut conn), &mut log);
            {
                let mut os = EmuOstream::new(&mut buf);
                os.insert(&vec![b'x'; 1024]);
                // CHECK(out.bad())
                assert!(os.bad);
            }
            // CHECK(responded == std::string(1023,'x'));
            // CHECK(logged.empty())
            assert_eq!(rsp_texts(&out), "x".repeat(1023));
            assert!(!out.borrow().iter().any(|l| l.starts_with("LOG")));
            // ~StatsResponseBuf runs after the CHECKs in C (stack unwind
            // at TEST_CASE end); its second 1023-x respond lands
            // post-assertions -- the replay vectors pin that pair (W7).
            buf.dtor();
            assert_eq!(rsp_texts(&out), "x".repeat(2046));
        }
    }
}

/// Whole-transcript replay of the 16-line locked vectors.
#[test]
fn respbuf_transcript_replay() {
    let w = Witness::new();
    struct Drv {
        out: Rc<RefCell<Vec<String>>>,
        respond_result: Rc<Cell<bool>>,
    }
    let d = Drv { out: w.out.clone(), respond_result: w.respond_result.clone() };
    let mut conn = WConn(d.out.clone(), d.respond_result.clone());
    let mut log = WLog(d.out.clone());
    let out = d.out.clone();

    // W1: no control connection -> chunk goes to LogMessage (dtor flush)
    {
        let mut buf = StatsResponseBuf::new(None, &mut log);
        let mut os = EmuOstream::new(&mut buf);
        os.insert(b"abc");
        buf.dtor();
    }

    // W2: local control connection -> respond path
    {
        let mut buf = StatsResponseBuf::new(Some(&mut conn), &mut log);
        let mut os = EmuOstream::new(&mut buf);
        os.insert(b"abc");
        buf.dtor();
    }

    // W3: direct overflow(eof) on EMPTY buffer: sync()/flush() has
    // nothing pending -> 0 -> not_eof(eof); zero witness lines.
    {
        let mut buf = StatsResponseBuf::new(None, &mut log);
        let r = buf.overflow(EOF_INT);
        line(&out, format!("W3 eof_on_empty ret!=eof={}", (r != EOF_INT) as i32));
        buf.dtor();
    }

    // W4: direct single-char overflow lands in pptr; dtor flush sends
    // exactly "Z".
    {
        let mut buf = StatsResponseBuf::new(None, &mut log);
        let r = buf.overflow(b'Z' as i32);
        line(&out, format!("W4 ov_ret==Z={}", (r == b'Z' as i32) as i32));
        buf.dtor();
    }

    // W5: overflow(eof) with PENDING data flushes it first.
    {
        let mut buf = StatsResponseBuf::new(None, &mut log);
        buf.overflow(b'Y' as i32);
        let r = buf.overflow(EOF_INT);
        line(&out, format!("W5 eof_with_pending ret!=eof={}", (r != EOF_INT) as i32));
        buf.dtor();
    }

    // W6: sync() on empty -> 0, nothing sent; dtor likewise.
    {
        let mut buf = StatsResponseBuf::new(None, &mut log);
        let r = buf.sync();
        line(&out, format!("W6 sync_empty ret={r}"));
        buf.dtor();
    }

    // W7: full-buffer flush FAILURE: streaming 1024 x's; badbit set;
    // failed flush keeps the put area -> dtor re-sends the same bytes.
    {
        d.respond_result.set(false);
        let mut buf = StatsResponseBuf::new(Some(&mut conn), &mut log);
        {
            let mut os = EmuOstream::new(&mut buf);
            os.insert(&vec![b'x'; 1024]);
            line(&out, format!("W7 out.bad={}", os.bad as i32));
        }
        buf.dtor();
    }
    d.respond_result.set(true);

    // W8: long stream succeeds: 1023-byte RSP chunks + short tail via
    // dtor flush.
    {
        let mut buf = StatsResponseBuf::new(Some(&mut conn), &mut log);
        let mut os = EmuOstream::new(&mut buf);
        os.insert(&vec![b'y'; 2050]);
        buf.dtor();
    }

    // W9: embedded NUL mid-chunk via write; "%s" prints "a" only.
    {
        let mut buf = StatsResponseBuf::new(None, &mut log);
        let mut os = EmuOstream::new(&mut buf);
        os.write(b"a\0b");
        buf.dtor();
    }

    // W10: chunk of only a NUL byte: send_chunk skips both sinks;
    // pending area still resets. Zero witness lines.
    {
        let mut buf = StatsResponseBuf::new(None, &mut log);
        let mut os = EmuOstream::new(&mut buf);
        os.write(b"\0");
        buf.dtor();
    }

    line(&out, "DONE".to_string());
    let _ = &w; // keep witnesses alive to end of scope like globals

    let vectors = include_str!("../tools/stats_rb_harness/vectors.txt");
    let want: Vec<&str> = vectors.lines().collect();
    let got = out.borrow();
    assert_eq!(got.len(), want.len(), "line count mismatch");
    for (i, (g, e)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, e, "line {}", i + 1);
    }
}
