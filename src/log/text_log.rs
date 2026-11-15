//! Port map of snort3 src/log/text_log.{h,cc} — buffered text logging with
//! size-capped files that rename+reopen ("roll") on overflow.
//!
//! C models the FILE* + a flexible char array sized by snort_alloc; the
//! Rust port models the buffer as a Vec and the handle as a std::fs File
//! (or an injected stdout sink — C's one special FILE*, never closed and
//! never rolled). vsnprintf/snprintf/fwrite semantics are reproduced
//! exactly via crate::utils::cfmt: the truncating write + NUL placement,
//! the "%.*s"-is-a-PRECISION quirk in TextLog_Write (not a width!), the
//! would-be return length vs bytes-actually-written split, and the
//! overflow branch that leaves pos = maxBuf - 1 with a NUL in the buffer.
//!
//! C's stubbed time() in tools/textlog_harness is stood for by threading a
//! clock callback: the replay drives the same fake clock the probe did, so
//! roll filenames and the suppression rule (last >= now) compare exactly.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::rc::Rc;

use crate::log::messages::LogEngine;
use crate::main::thread::{NamingConfig, ThreadState, get_instance_file, get_main_file, in_main_thread};
use crate::utils::cfmt::{Arg, cfmt};
use crate::utils::util::get_error;

// text_log.h
pub const K_BYTES: usize = 1024;
pub const M_BYTES: usize = K_BYTES * K_BYTES;
pub const G_BYTES: usize = K_BYTES * M_BYTES;

// text_log.cc: a reasonable minimum
pub const MIN_BUF: usize = 4 * K_BYTES;

// messages.h STD_BUF. roll_log_file's newname is char[STD_BUF+1] and
// SnortSnprintf is capped at sizeof(newname)-1 = STD_BUF bytes, which
// snprintf converts to STD_BUF-1 chars + NUL.
const STD_BUF: usize = 2048;

pub type Clock = Box<dyn FnMut() -> u64>;

/// The replay's capture for the C stdout handle. The C probe merged
/// stdout+stderr into one stream; the test drives markers and this sink
/// into the same Vec so ordering reproduces fwrite placement exactly.
pub type StdoutSink = Rc<RefCell<Vec<u8>>>;

#[derive(Debug)]
enum Handle {
    /// C `stdout`: written, never rolled, never closed.
    Stdout(StdoutSink),
    File(File),
}

pub struct TextLog {
    file: Handle,
    name: String,
    size: u64,
    max_file: usize,
    last: u64,
    pos: usize,
    max_buf: usize,
    buf: Vec<u8>,
    /// Stands for FatalError killing the process mid-roll (C never came
    /// back). Every later operation becomes a silent no-op.
    dead: bool,
}

impl TextLog {
    /// text_log.cc:111 TextLog_Avail: maxBuf - pos - 1 (C int; stays
    /// >= 0 because pos is capped at maxBuf - 1).
    pub fn avail(&self) -> i64 {
        self.max_buf as i64 - self.pos as i64 - 1
    }

    /// text_log.cc:116 TextLog_Reset.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.buf[0] = 0;
    }
}

/// text_log.cc:77 TextLog_Open: "stdout" (strcasecmp) beats the
/// filesystem; everything else goes through open_log_file("a").
fn text_log_open(
    name: &str,
    is_critical: bool,
    log: &mut LogEngine,
    sink: &StdoutSink,
) -> Option<Handle> {
    if name.eq_ignore_ascii_case("stdout") {
        // USE_STDLOG not set in this build: plain stdout.
        return Some(Handle::Stdout(sink.clone()));
    }
    open_log_file(name, is_critical, log)
}

/// text_log.cc:341 open_log_file: fopen(filename, "a"); on failure,
/// critical -> FatalError (FATAL line + "Fatal Error, Quitting.." and the
/// process is gone; the port records the fatal and hands back None),
/// non-critical -> ErrorMessage and None (Init then returns null).
fn open_log_file(filename: &str, is_critical: bool, log: &mut LogEngine) -> Option<Handle> {
    match OpenOptions::new().create(true).append(true).open(filename) {
        // C additionally setvbuf(file, NULL, _IOLBF, 0); std::fs::File has
        // no stdio buffering, and every byte reaches it through our own
        // TextLog buffer, so the write stream is identical.
        Ok(f) => Some(Handle::File(f)),
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(0);
            let args: [Arg<'_>; 2] = [
                Arg::S(Some(filename.into())),
                Arg::S(Some(get_error(errno).into())),
            ];
            if is_critical {
                log.fatal_error("can't open log file %s: %s\n", &args);
            } else {
                log.error_message("can't open log file %s: %s\n", &args);
            }
            None
        }
    }
}

/// text_log.cc:358 roll_log_file: rename(old, "<old>.<now>"), name built
/// by SnortSnprintf capped to STD_BUF-1 chars; rename failure logs
/// ErrorMessage (the errno return value is ignored by the only caller).
fn roll_log_file(oldname: &str, now: u64, log: &mut LogEngine) {
    let newname: String = cfmt(
        "%s.%lu",
        &[Arg::S(Some(oldname.into())), Arg::U(now)],
    )
    .chars()
    .take(STD_BUF - 1)
    .collect();
    if let Err(e) = std::fs::rename(oldname, &newname) {
        let errno = e.raw_os_error().unwrap_or(0);
        log.error_message(
            "can't rename(%s, %s) = %s\n",
            &[
                Arg::S(Some(oldname.into())),
                Arg::S(Some(newname.clone().into())),
                Arg::S(Some(get_error(errno).into())),
            ],
        );
    }
}

/// text_log.cc:100 TextLog_Size: fstat size, 0 on error. For stdout the
/// value is never observable (Roll bails out on stdout before touching
/// size), matching C where it also only feeds maxFile comparisons.
fn text_log_size(h: &Handle) -> u64 {
    match h {
        Handle::File(f) => f.metadata().map(|m| m.len()).unwrap_or(0),
        Handle::Stdout(_) => 0,
    }
}

/// text_log.cc:126 TextLog_Init. maxBuf < MIN_BUF is clamped up (vectors
/// B1/B5). Non-"stdout" names get the log_dir/run_prefix treatment from
/// the thread layer, main vs packet flavor by thread type.
#[allow(clippy::too_many_arguments)]
pub fn text_log_init(
    name: &str,
    max_buf: usize,
    max_file: usize,
    is_critical: bool,
    ts: &ThreadState,
    conf: &NamingConfig,
    log: &mut LogEngine,
    now: &mut Clock,
    sink: &StdoutSink,
) -> Option<TextLog> {
    let max_buf = if max_buf < MIN_BUF { MIN_BUF } else { max_buf };

    let resolved_name = if name.eq_ignore_ascii_case("stdout") {
        name.to_string()
    } else if in_main_thread(ts) {
        get_main_file(conf, name)
    } else {
        get_instance_file(conf, ts, name, log)
    };

    let file = text_log_open(&resolved_name, is_critical, log, sink)?;

    let size = text_log_size(&file);
    let last = now();

    // C allocates sizeof(TextLog)+maxBuf and uses buf[maxBuf] as the NUL
    // slot; one Vec with the extra slot models the whole flexible array.
    let buf = vec![0u8; max_buf + 1];

    Some(TextLog {
        file,
        name: resolved_name,
        size,
        max_file,
        last,
        pos: 0,
        max_buf,
        buf,
        dead: false,
    })
}

/// text_log.cc:169 TextLog_Term: flush, close (stdout never closed —
/// Handle::File drops do the fclose), free.
pub fn text_log_term(txt: Option<&mut TextLog>, now: &mut Clock, log: &mut LogEngine) {
    let Some(txt) = txt else { return };
    txt.flush(now, log);
}

/// text_log.cc:187 TextLog_Roll: close, rename, reopen; but never for
/// stdout ("don't roll over stdout — any sooner than the resolution of
/// the filename discriminator") and never while last >= time(). C calls
/// time() three times across roll (suppress check, name, last=); the
/// replay's stub clock is constant between bumps, so all three read the
/// same value, and the port still calls now() thrice.
fn text_log_roll(txt: &mut TextLog, now: &mut Clock, log: &mut LogEngine) {
    if matches!(txt.file, Handle::Stdout(_)) {
        return;
    }
    let t = now();
    if txt.last >= t {
        return;
    }
    // C: fclose first, then rename. Dropping the File models fclose.
    if let Handle::File(_) = &txt.file {
        txt.file = Handle::Stdout(Rc::new(RefCell::new(Vec::new()))); // placeholder drop
    }
    let t_name = now();
    roll_log_file(&txt.name.clone(), t_name, log);
    // C: TextLog_Open(txt->name) WITHOUT the is_critical argument ->
    // defaults true, so a reopen failure is FATAL and never returns
    // (vector H4: rename ENOENT message, then FATAL, child gone).
    match open_log_file(&txt.name.clone(), true, log) {
        Some(h) => txt.file = h,
        None => {
            txt.dead = true;
            return;
        }
    }
    let t2 = now();
    txt.last = t2;
    txt.size = 0;
}

impl TextLog {
    /// text_log.cc:206 TextLog_Flush. The roll test is strictly `>`:
    /// size == maxFile does not roll (vector E2). Roll happens BEFORE the
    /// fwrite; the rolled path receives the full buffer and size restarts
    /// from 0. Returns whether the fwrite succeeded (C ok==1).
    pub fn flush(&mut self, now: &mut Clock, log: &mut LogEngine) -> bool {
        if self.dead || self.pos == 0 {
            return false;
        }
        if self.max_file != 0
            && (self.size as i64 + self.pos as i64) > self.max_file as i64
        {
            text_log_roll(self, now, log);
            if self.dead {
                return false;
            }
        }
        let ok = match &mut self.file {
            Handle::Stdout(sink) => {
                sink.borrow_mut().extend_from_slice(&self.buf[..self.pos]);
                true
            }
            Handle::File(f) => f.write_all(&self.buf[..self.pos]).is_ok(),
        };
        if ok {
            self.size += self.pos as u64;
            self.reset();
        }
        ok
    }

    /// text_log.cc:231 TextLog_Putc: flush-if-full, append, NUL-terminate.
    /// Always true after a successful flush of 4096 (avail >= 1 again).
    pub fn putc(&mut self, c: u8, now: &mut Clock, log: &mut LogEngine) -> bool {
        if self.dead {
            return false;
        }
        if self.avail() < 1 {
            self.flush(now, log);
            if self.dead {
                return false;
            }
        }
        self.buf[self.pos] = c;
        self.pos += 1;
        self.buf[self.pos] = 0;
        true
    }

    /// text_log.cc:247 TextLog_Write. `%.*s` — the `*` is a PRECISION, it
    /// caps the string, it does NOT pad (C8 pins this: 5000-byte write
    /// into a 4096 buffer, and "%.*s" of "ab" with len 5 adds nothing).
    /// len < 0 clears the precision (glibc) so the full string goes (C8c).
    /// n is the would-be snprintf length; `n < avail and n < len` is the
    /// early return that makes Write("ab", 5) fail having written nothing
    /// (C8b).
    pub fn write(&mut self, s: &str, len: i64, now: &mut Clock, log: &mut LogEngine) -> bool {
        if self.dead {
            return false;
        }
        let str_bytes = s.as_bytes();
        let mut str_off = 0usize;
        let mut len = len;
        loop {
            let avail = self.avail();
            // snprintf(buf+pos, avail, "%.*s", len, str) would-be length:
            let slen = (str_bytes.len() - str_off) as i64;
            let n: i64 = if len >= 0 { slen.min(len) } else { slen };
            if n < avail && n < len {
                return false;
            }

            // actual bytes written:
            // 1) if avail is a limit, auto-appended '\0' should be truncated
            // 2) avail could be zero from the start, keep it as 0
            let l = n.min(if avail > 0 { avail - 1 } else { 0 }).max(0) as usize;
            self.buf[self.pos..self.pos + l].copy_from_slice(&str_bytes[str_off..str_off + l]);
            if avail > 0 {
                self.buf[self.pos + l] = 0;
            }
            self.pos += l;
            str_off += l;
            len -= l as i64;

            if n >= avail {
                self.flush(now, log);
            }
            if self.dead || len <= 0 {
                return !self.dead;
            }
        }
    }

    /// text_log.cc:276 TextLog_Print. Truncating vsnprintf semantics via
    /// cfmt: on overflow C flushes once and formats AGAIN into the
    /// emptied buffer; still-too-big leaves the truncated bytes + NUL
    /// committed up to pos = maxBuf - 1 (vectors C4-C7, c3.log/c4.log).
    pub fn print(
        &mut self,
        fmt: &str,
        args: &[Arg<'_>],
        now: &mut Clock,
        log: &mut LogEngine,
    ) -> bool {
        if self.dead {
            return false;
        }
        let mut avail = self.avail();
        let s = cfmt(fmt, args);
        let bytes = s.as_bytes();
        let len: i64 = bytes.len() as i64;

        vsnprintf_into(&mut self.buf, self.pos, avail, bytes);

        if len >= avail {
            self.flush(now, log);
            avail = self.avail();
            vsnprintf_into(&mut self.buf, self.pos, avail, bytes);
        }
        if len >= avail {
            self.pos = self.max_buf - 1;
            self.buf[self.pos] = 0;
            return false;
        } else if len < 0 {
            return false;
        }

        self.pos += len as usize;
        true
    }

    /// text_log.cc:315 TextLog_Quote: '"' + each " and \ doubled
    /// (strcspn runs through TextLog_Write/Putc, so buffer boundaries
    /// split mid-escape cleanly) + '"'.
    pub fn quote(&mut self, qs: &str, now: &mut Clock, log: &mut LogEngine) -> bool {
        if self.dead {
            return false;
        }
        self.putc(b'"', now, log);
        let qs = qs.as_bytes();
        let mut off = 0usize;
        loop {
            let len = qs.len() - off;
            let pre = qs[off..]
                .iter()
                .position(|&c| c == b'"' || c == b'\\')
                .unwrap_or(len);
            let seg = String::from_utf8_lossy(&qs[off..off + pre]).into_owned();
            self.write(&seg, pre as i64, now, log);
            off += pre;
            if pre < len {
                self.putc(b'\\', now, log);
                self.putc(qs[off], now, log);
                off += 1;
            }
            if self.dead || off >= qs.len() {
                break;
            }
        }
        self.putc(b'"', now, log);
        true
    }
}

/// glibc vsnprintf(dst+pos, size, "%s", ...) over an already-populated
/// buffer: when size > 0 copies min(n, size-1) bytes and NUL-terminates
/// at pos + min(n, size-1); when size == 0 writes nothing at all (the
/// buffer keeps its previous bytes, exactly like C).
fn vsnprintf_into(buf: &mut [u8], pos: usize, size: i64, bytes: &[u8]) {
    if size <= 0 {
        return;
    }
    let cap = (size as usize) - 1;
    let l = bytes.len().min(cap);
    buf[pos..pos + l].copy_from_slice(&bytes[..l]);
    buf[pos + l] = 0;
}
