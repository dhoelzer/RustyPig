// Port of snort3 log/messages.{h,cc} + log/log_errors.h.
//
// C file-globals (parse_errors/parse_warnings/reload_errors/
// reload_errors_description/already_fatal and log_safec_error's
// THREAD_LOCAL counter) live on LogEngine. The SnortConfig statics this
// file reads (warning_flags, logging_flags, output_flags,
// log_quiet_bypassed) live on LogEngine too: they are SnortConfig CLASS
// statics, so they persist even when get_conf() == nullptr. conf_present
// stands for get_conf() != nullptr and gates the two places that deref
// the object (ParseWarning's guard, WriteLogMessage's buffered check).
// FatalError _exit(EXIT_FAILURE) becomes Ok(Fatal::Quitting): the
// reentrant already_fatal guard (_exit(1), message NOT formatted) is
// Fatal::Reentrant, and log_safec_error's assert(false) is a panic the
// replay driver catches. All printf/fprintf/syslog formatting goes
// through crate::utils::cfmt — tools/log_harness pinned cfmt-relevant
// semantics (including the 2047-vs-2048 truncation asymmetry, glibc
// "(null)", and SYSLOG priorities 29/28/27) against glibc itself.
#![allow(dead_code)]

use crate::utils::cfmt::{cfmt, Arg};

pub const STD_BUF: usize = 2048;
pub const LOG_DIV: &str = "--------------------------------------------------";

/// C enum WarningGroup (declaration order).
pub type WarningGroup = u32;
pub const WARN_DAQ: WarningGroup = 0;
pub const WARN_CONF: WarningGroup = 1;
pub const WARN_CONF_STRICT: WarningGroup = 2;
pub const WARN_VARS: WarningGroup = 3;
pub const WARN_SYMBOLS: WarningGroup = 4;
pub const WARN_SCRIPTS: WarningGroup = 5;
pub const WARN_HOSTS: WarningGroup = 6;
pub const WARN_RULES: WarningGroup = 7;
pub const WARN_FLOWBITS: WarningGroup = 8;
pub const WARN_PLUGINS: WarningGroup = 9;
pub const WARN_MAX: WarningGroup = 10;

// SnortConfig flag bits this file touches.
pub const OUTPUT_FLAG_LOG_BUFFERED: u32 = 0x0000_2000;
pub const LOGGING_FLAG_QUIET: u32 = 0x0000_0002;
pub const LOGGING_FLAG_SYSLOG: u32 = 0x0000_0004;

// syslog(3) facility/priority (glibc: LOG_CONS=2, LOG_DAEMON=24,
// LOG_NOTICE=5, LOG_WARNING=4, LOG_ERR=3 — pinned empirically).
pub const LOG_CONS: u32 = 2;
pub const LOG_DAEMON: u32 = 24;
pub const LOG_NOTICE: u32 = 5;
pub const LOG_WARNING: u32 = 4;
pub const LOG_ERR: u32 = 3;
pub const PRIO_NOTICE: u32 = LOG_DAEMON | LOG_NOTICE; // 29
pub const PRIO_WARNING: u32 = LOG_DAEMON | LOG_WARNING; // 28
pub const PRIO_ERROR: u32 = LOG_CONS | LOG_DAEMON | LOG_ERR; // 27

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Stdout,
    Stderr,
    /// Syslog branch: the value is the syslog priority.
    Syslog(u32),
    /// LogMessage(FILE*, ...) to a real file handle (harness tmpfile).
    File(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEvent {
    pub phase: Phase,
    pub text: String,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fatal {
    /// FatalError executed the shutdown sequence; caller should exit(1).
    Quitting,
    /// Reentrant FatalError: C did fflush(NULL) + _exit(1) WITHOUT
    /// formatting the message (already_fatal was 1).
    Reentrant,
}

#[derive(Clone, Debug)]
pub struct LogEngine {
    /// Ordered transcript: exactly the bytes C wrote to stdout/stderr,
    /// the syslog stub, or a LogMessage(FILE*) target — in order, with
    /// embedded newlines preserved verbatim.
    pub out: Vec<LogEvent>,
    /// parser/parse_conf.cc file-static location stack top (C only
    /// exposes the top via get_parse_location).
    pub parse_loc: (Option<String>, u32),
    pub parse_errors: u32,
    pub parse_warnings: u32,
    pub reload_errors: u32,
    pub reload_errors_description: String,
    pub already_fatal: bool,
    pub safec_errors: u32,
    // SnortConfig statics this file reads; faithful mirror: in C these
    // are CLASS statics that persist even when get_conf() == nullptr.
    pub warning_flags: u32,
    pub logging_flags: u32,
    pub output_flags: u32,
    pub log_quiet_bypassed: bool,
    /// Stands for SnortConfig::get_conf() != nullptr. Only
    /// ParseWarning's guard and WriteLogMessage's use_log_buffered()
    /// deref the conf object; the flag statics above do not.
    pub conf_present: bool,
}

impl Default for LogEngine {
    fn default() -> Self {
        LogEngine {
            out: Vec::new(),
            parse_loc: (None, 0),
            parse_errors: 0,
            parse_warnings: 0,
            reload_errors: 0,
            reload_errors_description: String::new(),
            already_fatal: false,
            safec_errors: 0,
            warning_flags: 0,
            logging_flags: 0,
            output_flags: 0,
            log_quiet_bypassed: false,
            conf_present: true,
        }
    }
}

impl LogEngine {
    pub fn use_log_buffered(&self) -> bool {
        self.conf_present && self.output_flags & OUTPUT_FLAG_LOG_BUFFERED != 0
    }
    pub fn log_syslog(&self) -> bool {
        self.logging_flags & LOGGING_FLAG_SYSLOG != 0
    }
    pub fn log_quiet(&self) -> bool {
        // static THREAD_LOCAL bypass + static logging_flags: no conf deref
        !self.log_quiet_bypassed && self.logging_flags & LOGGING_FLAG_QUIET != 0
    }
    pub fn set_log_quiet(&mut self, enabled: bool) {
        if enabled {
            self.logging_flags |= LOGGING_FLAG_QUIET;
        } else {
            self.logging_flags &= !LOGGING_FLAG_QUIET;
        }
    }
}

impl LogEngine {
    fn emit(&mut self, phase: Phase, text: String) {
        self.out.push(LogEvent { phase, text });
    }

    /// Concatenated transcript = what the interleaved stdout+stderr+stub
    /// stream looked like (parity tests merge both streams anyway).
    pub fn transcript(&self) -> String {
        self.out.iter().map(|e| e.text.as_str()).collect::<String>()
    }

    // ------------------------------------------------------------------
    // log_errors.h (file-static counters)
    // ------------------------------------------------------------------

    pub fn reset_parse_errors(&mut self) {
        self.parse_errors = 0;
        self.reload_errors = 0;
    }

    /// C reads-then-zeroes (destructive getter — pinned by #warns2=0).
    pub fn get_parse_errors(&mut self) -> u32 {
        let tmp = self.parse_errors;
        self.parse_errors = 0;
        tmp
    }

    pub fn get_parse_warnings(&mut self) -> u32 {
        let tmp = self.parse_warnings;
        self.parse_warnings = 0;
        tmp
    }

    pub fn reset_reload_errors(&mut self) {
        self.reload_errors = 0;
        self.reload_errors_description.clear();
    }

    /// NOT destructive (unlike get_parse_*).
    pub fn get_reload_errors(&self) -> u32 {
        self.reload_errors
    }

    pub fn get_reload_errors_description(&self) -> &str {
        &self.reload_errors_description
    }

    pub fn set_parse_location(&mut self, file: Option<&str>, line: u32) {
        self.parse_loc = (file.map(|f| f.to_string()), line);
    }

    // ------------------------------------------------------------------
    // messages.h/.cc
    // ------------------------------------------------------------------

    pub fn parse_warning(&mut self, wg: WarningGroup, format: &str, args: &[Arg<'_>]) {
        // C: if ( get_conf() and !(warning_flags & (1 << wg)) ) return;
        if self.conf_present && self.warning_flags & (1 << wg) == 0 {
            return;
        }
        // vsnprintf(buf, STD_BUF, ...) -> at most STD_BUF-1 chars
        let buf: String = cfmt(format, args).chars().take(STD_BUF - 1).collect();
        self.log_message(Phase::Stderr, "WARNING", &buf);
        self.parse_warnings += 1;
    }

    pub fn parse_error(&mut self, format: &str, args: &[Arg<'_>]) {
        let buf: String = cfmt(format, args).chars().take(STD_BUF - 1).collect();
        self.log_message(Phase::Stderr, "ERROR", &buf);
        self.parse_errors += 1;
    }

    pub fn reload_error(&mut self, format: &str, args: &[Arg<'_>]) {
        // vsnprintf(buf, sizeof(buf)) with buf = char[STD_BUF+1]:
        // STD_BUF chars survive (one more than ParseError's) — P8 pins it.
        let buf: String = cfmt(format, args).chars().take(STD_BUF).collect();
        self.log_message(Phase::Stderr, "ERROR", &buf);
        if self.reload_errors_description.is_empty() {
            self.reload_errors_description = buf;
        } else {
            self.reload_errors_description.push(',');
            self.reload_errors_description.push_str(&buf);
        }
        self.reload_errors += 1;
    }

    /// ParseAbort: emits through FatalError() then unwinds. C's
    /// [[noreturn]] + longjmp-to-recovery-point is modeled by the
    /// caller's control flow; the returned Fatal::Quitting is what
    /// FatalError reached before C's setjmp target.
    pub fn parse_abort(&mut self, format: &str, args: &[Arg<'_>]) -> Fatal {
        let buf: String = cfmt(format, args).chars().take(STD_BUF - 1).collect();
        let (file_name, file_line) = (&self.parse_loc.0.clone(), self.parse_loc.1);
        if file_line != 0 {
            let f = file_name.clone().unwrap_or_default();
            let msg = cfmt("%s:%u %s\n", &[Arg::S(Some(f.into())), Arg::I(file_line as i64), Arg::S(Some(buf.into()))]);
            self.fatal_error(&msg, &[])
        } else {
            let msg = cfmt("%s\n", &[Arg::S(Some(buf.into()))]);
            self.fatal_error(&msg, &[])
        }
    }

    /// WriteLogMessage core for the (FILE*, prefer_fh) shape.
    fn write_log_message(
        &mut self,
        phase: Phase,
        prefer_fh: bool,
        format: &str,
        args: &[Arg<'_>],
    ) {
        // C: sc && sc->use_log_buffered() -> BatchedLogger (not ported;
        // the harness abort()s when this path is entered).
        if self.use_log_buffered() {
            panic!("BatchedLogger path not ported (OUTPUT_FLAG_LOG_BUFFERED)");
        }
        let text = cfmt(format, args);
        let syslog_route = !prefer_fh && self.log_syslog();
        if syslog_route {
            let trunc: String = text.chars().take(STD_BUF - 1).collect();
            self.emit(Phase::Syslog(PRIO_NOTICE), format!("SYSLOG({PRIO_NOTICE}) {trunc}\n"));
        } else {
            self.emit(phase, text);
        }
    }

    // helper: log_message (static in C); routes through
    // LogMessage(stderr, ...) so quiet does NOT gate it and the syslog
    // branch is live (P15b pins the NOTICE prio for these).
    fn log_message(&mut self, phase: Phase, msg_type: &str, msg: &str) {
        let (file_name, file_line) = (self.parse_loc.0.clone(), self.parse_loc.1);
        let text = if file_line != 0 {
            let f = file_name.clone().unwrap_or_default();
            cfmt(
                "%s: %s:%d %s\n",
                &[
                    Arg::S(Some(msg_type.into())),
                    Arg::S(Some(f.into())),
                    Arg::I(file_line as i64),
                    Arg::S(Some(msg.into())),
                ],
            )
        } else if file_name.is_some() {
            let f = file_name.unwrap();
            cfmt(
                "%s: %s: %s\n",
                &[
                    Arg::S(Some(msg_type.into())),
                    Arg::S(Some(f.into())),
                    Arg::S(Some(msg.into())),
                ],
            )
        } else {
            cfmt(
                "%s: %s\n",
                &[Arg::S(Some(msg_type.into())), Arg::S(Some(msg.into()))],
            )
        };
        // In C this routes through LogMessage(FILE* fh, ...) with fh=
        // stderr: quiet only suppresses stdout; prefer_fh=false for
        // stderr so the syslog branch is live.
        self.write_log_message(phase, false, "%s", &[Arg::S(Some(text.into()))]);
    }

    // ------------------------------------------------------------------
    // FatalError
    // ------------------------------------------------------------------

    /// Returns what the process should do; C never returns (exit(1)).
    pub fn fatal_error(&mut self, format: &str, args: &[Arg<'_>]) -> Fatal {
        // bail before formatting if reentering
        if self.already_fatal {
            // C: fflush(NULL); _exit(1) — nothing printed.
            return Fatal::Reentrant;
        }
        self.already_fatal = true;
        let buf: String = cfmt(format, args).chars().take(STD_BUF - 1).collect();
        if self.log_syslog() {
            let s = cfmt("FATAL ERROR: %s", &[Arg::S(Some(buf.clone().into()))]);
            self.emit(Phase::Syslog(PRIO_ERROR), format!("SYSLOG({PRIO_ERROR}) {s}\n"));
        } else {
            // two separate fprintf calls; the second is an exact constant
            self.emit(Phase::Stderr, cfmt("FATAL: %s", &[Arg::S(Some(buf.into()))]));
            self.emit(Phase::Stderr, "Fatal Error, Quitting..\n".to_string());
        }
        // in_main_thread() is true in the single-threaded core; worker
        // abort() path deferred with threads. cleanup_fatal_error() and
        // the exit are the embedding binary's (replay's) responsibility.
        Fatal::Quitting
    }

    /// log_safec_error: emits like ErrorMessage, then C assert(false) ->
    /// the port panics (driver catches and records sig=6).
    pub fn log_safec_error(&mut self, msg: &str, e: i32) -> ! {
        self.safec_errors += 1;
        if self.safec_errors < 1000 {
            self.error_message("SafeC error %i: %s\n", &[Arg::I(e as i64), Arg::S(Some(msg.into()))]);
        }
        panic!("log_safec_error: assertion failed");
    }

    // ------------------------------------------------------------------
    // LogMessage / WarningMessage / ErrorMessage
    // ------------------------------------------------------------------

    pub fn log_message_stdout(&mut self, format: &str, args: &[Arg<'_>]) {
        if self.log_quiet() {
            return;
        }
        self.write_log_message(Phase::Stdout, false, format, args);
    }

    /// LogMessage(FILE*, ...): quiet only gates stdout; prefer_fh=(fh !=
    /// stdout && fh != stderr).
    pub fn log_message_file(&mut self, fh: Phase, format: &str, args: &[Arg<'_>]) {
        if matches!(fh, Phase::Stdout) && self.log_quiet() {
            return;
        }
        let prefer_fh = !matches!(fh, Phase::Stdout | Phase::Stderr);
        self.write_log_message(fh, prefer_fh, format, args);
    }

    pub fn warning_message(&mut self, format: &str, args: &[Arg<'_>]) {
        let text = cfmt(format, args);
        if self.log_syslog() {
            let trunc: String = text.chars().take(STD_BUF - 1).collect();
            self.emit(Phase::Syslog(PRIO_WARNING), format!("SYSLOG({PRIO_WARNING}) {trunc}\n"));
        } else {
            self.emit(Phase::Stderr, text);
        }
    }

    pub fn error_message(&mut self, format: &str, args: &[Arg<'_>]) {
        let text = cfmt(format, args);
        if self.log_syslog() {
            let trunc: String = text.chars().take(STD_BUF - 1).collect();
            self.emit(Phase::Syslog(PRIO_ERROR), format!("SYSLOG({PRIO_ERROR}) {trunc}\n"));
        } else {
            self.emit(Phase::Stderr, text);
        }
    }
}
// ----------------------------------------------------------------------
// Dumper (header-inline class in messages.h)
// ----------------------------------------------------------------------

pub struct Dumper {
    max: u32,
    idx: u32,
}

impl Dumper {
    /// C constructor: logs "%s\n" when s is non-null.
    pub fn new(e: &mut LogEngine, s: Option<&str>, n: u32) -> Dumper {
        if let Some(s) = s {
            e.log_message_stdout( "%s\n", &[Arg::S(Some(s.into()))]);
        }
        Dumper { max: n, idx: 0 }
    }

    /// C destructor: if idx % max != 0, logs "\n".
    pub fn finish(self, e: &mut LogEngine) {
        if !self.idx.is_multiple_of(self.max) {
            e.log_message_stdout( "\n", &[]);
        }
    }

    pub fn dump_v(&mut self, e: &mut LogEngine, s: &str, v: u32) {
        self.idx += 1;
        let eol = if !self.idx.is_multiple_of(self.max) { "" } else { "\n" };
        e.log_message_stdout(
            "    %18.18s(v%u)%s",
            &[Arg::S(Some(s.into())), Arg::U(u64::from(v)), Arg::S(Some(eol.into()))],
        );
    }

    pub fn dump_t(&mut self, e: &mut LogEngine, s: &str, t: &str) {
        e.log_message_stdout(
            "%s::%s\n",
            &[Arg::S(Some(s.into())), Arg::S(Some(t.into()))],
        );
    }
}

// ----------------------------------------------------------------------
// ConfigLogger (all-static class; state is the engine transcript only)
// ----------------------------------------------------------------------

const INDENTION: usize = 25;
const MAX_LINE_LEN: usize = 75;

pub struct ConfigLogger;

impl ConfigLogger {
    fn ind(caption: &str, subopt: bool) -> usize {
        if subopt {
            INDENTION + caption.len() + 2
        } else {
            INDENTION
        }
    }

    pub fn log_option(e: &mut LogEngine, caption: &str) {
        e.log_message_stdout( "%*s:\n", &[Arg::I(INDENTION as i64), Arg::S(Some(caption.into()))]);
    }

    pub fn log_flag(e: &mut LogEngine, caption: &str, flag: bool, subopt: bool) -> bool {
        let fmt = if subopt { "%*s = %s\n" } else { "%*s: %s\n" };
        let ind = Self::ind(caption, subopt);
        e.log_message_stdout(
            fmt,
            &[
                Arg::I(ind as i64),
                Arg::S(Some(caption.into())),
                Arg::S(Some(if flag { "enabled" } else { "disabled" }.into())),
            ],
        );
        flag
    }

    fn log_limit_i(e: &mut LogEngine, caption: &str, val: i64, unlim: i64, disable: Option<i64>, subopt: bool) {
        let fmt = if subopt { "%*s = %lld%s\n" } else { "%*s: %lld%s\n" };
        let ind = Self::ind(caption, subopt);
        // C overloads check disable BEFORE unlim when a disable value
        // exists, so an equal-to-both value prints "(disabled)".
        let suffix = match disable {
            Some(d) if val == d => " (disabled)",
            _ if val == unlim => " (unlimited)",
            _ => "",
        };
        e.log_message_stdout(
            fmt,
            &[Arg::I(ind as i64), Arg::S(Some(caption.into())), Arg::I(val), Arg::S(Some(suffix.into()))],
        );
    }

    fn log_limit_u(e: &mut LogEngine, caption: &str, val: u64, unlim: u64, disable: Option<u64>, subopt: bool) {
        let fmt = if subopt { "%*s = %llu%s\n" } else { "%*s: %llu%s\n" };
        let ind = Self::ind(caption, subopt);
        let suffix = match disable {
            Some(d) if val == d => " (disabled)",
            _ if val == unlim => " (unlimited)",
            _ => "",
        };
        e.log_message_stdout(
            fmt,
            &[Arg::I(ind as i64), Arg::S(Some(caption.into())), Arg::U(val), Arg::S(Some(suffix.into()))],
        );
    }

    // C overloads collapsed: signed/unsigned int, long (+ll); the u64
    // shapes pass disable as None for the 3-arg overloads.
    pub fn log_limit_int(e: &mut LogEngine, caption: &str, val: i64, unlim: i64, subopt: bool) {
        Self::log_limit_i(e, caption, val, unlim, None, subopt);
    }
    pub fn log_limit_uint(e: &mut LogEngine, caption: &str, val: u64, unlim: u64, subopt: bool) {
        Self::log_limit_u(e, caption, val, unlim, None, subopt);
    }
    pub fn log_limit_int_dis(e: &mut LogEngine, caption: &str, val: i64, unlim: i64, disable: i64, subopt: bool) {
        Self::log_limit_i(e, caption, val, unlim, Some(disable), subopt);
    }
    pub fn log_limit_uint_dis(e: &mut LogEngine, caption: &str, val: u64, unlim: u64, disable: u64, subopt: bool) {
        Self::log_limit_u(e, caption, val, unlim, Some(disable), subopt);
    }

    pub fn log_value_desc(e: &mut LogEngine, caption: &str, n: i64, descr: &str, subopt: bool) {
        let fmt = if subopt { "%*s = %lld (%s)\n" } else { "%*s: %lld (%s)\n" };
        let ind = Self::ind(caption, subopt);
        e.log_message_stdout(
            fmt,
            &[Arg::I(ind as i64), Arg::S(Some(caption.into())), Arg::I(n), Arg::S(Some(descr.into()))],
        );
    }

    fn log_value_i(e: &mut LogEngine, caption: &str, n: i64, subopt: bool) {
        let fmt = if subopt { "%*s = %lld\n" } else { "%*s: %lld\n" };
        let ind = Self::ind(caption, subopt);
        e.log_message_stdout( fmt, &[Arg::I(ind as i64), Arg::S(Some(caption.into())), Arg::I(n)]);
    }

    fn log_value_u(e: &mut LogEngine, caption: &str, n: u64, subopt: bool) {
        let fmt = if subopt { "%*s = %llu\n" } else { "%*s: %llu\n" };
        let ind = Self::ind(caption, subopt);
        e.log_message_stdout( fmt, &[Arg::I(ind as i64), Arg::S(Some(caption.into())), Arg::U(n)]);
    }

    pub fn log_value_int(e: &mut LogEngine, caption: &str, n: i64, subopt: bool) {
        Self::log_value_i(e, caption, n, subopt);
    }
    pub fn log_value_uint(e: &mut LogEngine, caption: &str, n: u64, subopt: bool) {
        Self::log_value_u(e, caption, n, subopt);
    }

    pub fn log_value_double(e: &mut LogEngine, caption: &str, n: f64, subopt: bool) {
        let fmt = if subopt { "%*s = %lf\n" } else { "%*s: %lf\n" };
        let ind = Self::ind(caption, subopt);
        e.log_message_stdout( fmt, &[Arg::I(ind as i64), Arg::S(Some(caption.into())), Arg::F(n)]);
    }

    pub fn log_value_str(e: &mut LogEngine, caption: &str, str_: Option<&str>, subopt: bool) {
        // C: if ( !str or !str[0] ) return;
        if str_.is_none_or(|s| s.is_empty()) {
            return;
        }
        let fmt = if subopt { "%*s = %s\n" } else { "%*s: %s\n" };
        let ind = Self::ind(caption, subopt);
        e.log_message_stdout(
            fmt,
            &[Arg::I(ind as i64), Arg::S(Some(caption.into())), Arg::S(Some(str_.unwrap().into()))],
        );
    }

    /// log_list(caption, list, prefix=" ", subopt=false). Streams-style
    /// whitespace token split (ss >> val skips ALL whitespace runs).
    pub fn log_list(e: &mut LogEngine, caption: Option<&str>, list: &str, prefix: &str, subopt: bool) {
        if list.is_empty() {
            return;
        }
        let delim_symbol = if subopt { "=" } else { ":" };
        let ind = Self::ind(caption.unwrap_or(""), subopt);
        // C: (caption and caption[0]) ? delim_symbol : " "
        let delim = if caption.is_some_and(|c| !c.is_empty()) { delim_symbol } else { " " };
        // head_fmt = "%*s%s%.0s%s\n"  <- ind, caption, delim, prefix, res
        // tail_fmt = "%*.0s%.0s%s%s\n" <- ind, (empty caption!), prefix, res
        // Rust cfmt doesn't know %.0s; emulate by passing empty caption S.
        let mut fmt_head = true;
        let mut res = String::new();
        for val in list.split_whitespace() {
            if res.len() + val.len() > MAX_LINE_LEN {
                if fmt_head {
                    Self::list_head(e, ind, caption, delim, &res);
                } else {
                    Self::list_tail(e, ind, prefix, &res);
                }
                fmt_head = false;
                res.clear();
            }
            res.push(' ');
            res.push_str(val);
        }
        if fmt_head {
            Self::list_head(e, ind, caption, delim, &res);
        } else {
            Self::list_tail(e, ind, prefix, &res);
        }
    }

    fn list_head(e: &mut LogEngine, ind: usize, caption: Option<&str>, delim: &str, res: &str) {
        // C head_fmt "%*s%s%.0s%s\n" consumes prefix via %.0s (prints
        // nothing): head line = padded caption + delim + res only. A
        // null caption lands in cfmt %s -> glibc "(null)" (P19 pinned).
        e.log_message_stdout(
            "%*s%s%s\n",
            &[
                Arg::I(ind as i64),
                Arg::S(caption.map(|c| c.into())),
                Arg::S(Some(delim.into())),
                Arg::S(Some(res.into())),
            ],
        );
    }

    fn list_tail(e: &mut LogEngine, ind: usize, prefix: &str, res: &str) {
        // "%*.0s%.0s%s%s\n": empty string padded to ind, then the (also
        // .0s-suppressed) caption, then prefix, then res.
        e.log_message_stdout(
            "%*s%s%s\n",
            &[
                Arg::I(ind as i64),
                Arg::S(Some("".into())),
                Arg::S(Some(prefix.into())),
                Arg::S(Some(res.into())),
            ],
        );
    }

    /// log_list(list) (no caption): tab-continuation variant. NB the
    /// separator logic differs from the capped overload: res never
    /// starts with a space here.
    pub fn log_list_bare(e: &mut LogEngine, list: &str) {
        if list.is_empty() {
            return;
        }
        let mut res = String::new();
        for val in list.split_whitespace() {
            if res.len() + val.len() > MAX_LINE_LEN {
                e.log_message_stdout( "\t\t%s\n", &[Arg::S(Some(res.clone().into()))]);
                res.clear();
            }
            if !res.is_empty() {
                res.push(' ');
            }
            res.push_str(val);
        }
        e.log_message_stdout( "\t\t%s\n", &[Arg::S(Some(res.into()))]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eng() -> LogEngine {
        LogEngine::default()
    }

    #[test]
    fn warning_group_filter() {
        let mut e = eng();
        e.parse_warning(WARN_VARS, "suppressed %d", &[Arg::I(7)]);
        assert!(e.out.is_empty());
        assert_eq!(e.get_parse_warnings(), 0);

        e.warning_flags = 1 << WARN_VARS;
        e.parse_warning(WARN_RULES, "no", &[]);
        assert!(e.out.is_empty());
        e.parse_warning(WARN_VARS, "vars-shown %d", &[Arg::I(1)]);
        assert_eq!(e.out[0].text, "WARNING: vars-shown 1\n");
        // destructive
        assert_eq!(e.get_parse_warnings(), 1);
        assert_eq!(e.get_parse_warnings(), 0);
    }

    #[test]
    fn conf_null_passes_warning() {
        let mut e = eng();
        e.conf_present = false;
        e.parse_warning(WARN_VARS, "passthrough", &[]);
        assert_eq!(e.parse_warnings, 1);
    }

    #[test]
    fn location_branches() {
        let mut e = eng();
        e.set_parse_location(Some("foo.rules"), 42);
        e.parse_error("bad %s here", &[Arg::S(Some("thing".into()))]);
        assert_eq!(e.out[0].text, "ERROR: foo.rules:42 bad thing here\n");
        e.set_parse_location(Some("bar.rules"), 0);
        e.parse_error("err file noline", &[]);
        assert_eq!(e.out[1].text, "ERROR: bar.rules: err file noline\n");
        e.set_parse_location(None, 0);
        e.parse_error("err plain %u", &[Arg::U(12)]);
        assert_eq!(e.out[2].text, "ERROR: err plain 12\n");
    }

    #[test]
    fn reload_join_and_getters() {
        let mut e = eng();
        e.reload_error("first", &[]);
        e.reload_error("second %d", &[Arg::I(2)]);
        assert_eq!(e.get_reload_errors_description(), "first,second 2");
        assert_eq!(e.get_reload_errors(), 2);
        e.reset_reload_errors();
        assert!(e.get_reload_errors_description().is_empty());
        // reset_parse_errors also clears reload_errors
        e.reload_error("x", &[]);
        e.reset_parse_errors();
        assert_eq!(e.get_reload_errors(), 0);
    }

    #[test]
    fn truncation_asymmetry() {
        let mut e = eng();
        let big = "A".repeat(1500) + &"B".repeat(1500);
        e.parse_error("%s", &[Arg::S(Some(big.clone().into()))]);
        e.reload_error("%s", &[Arg::S(Some(big.into()))]);
        let pe = &e.out[0].text;
        let body = pe.trim_end_matches('\n');
        assert_eq!(body.chars().count(), 7 + 2047); // "ERROR: " prefix + 2047
        let d = e.get_reload_errors_description();
        assert_eq!(d.chars().count(), 2048);
        assert_eq!(d.as_bytes()[2047], b'B');
    }

    #[test]
    fn fatal_first_and_reentrant() {
        let mut e = eng();
        e.set_parse_location(None, 0);
        let f = e.parse_abort("plain abort %d\n", &[Arg::I(9)]);
        assert_eq!(f, Fatal::Quitting);
        let tr = e.transcript();
        assert!(tr.starts_with("FATAL: plain abort 9\n"), "{tr:?}");
        assert!(tr.contains("Fatal Error, Quitting..\n"));
        // reentry: nothing new is emitted
        let n = e.out.len();
        assert_eq!(e.fatal_error("inner\n", &[]), Fatal::Reentrant);
        assert_eq!(e.out.len(), n);
    }

    #[test]
    fn quiet_gates_stdout_only() {
        let mut e = eng();
        e.set_log_quiet(true);
        e.log_message_stdout("quiet-suppressed %d", &[Arg::I(1)]);
        assert!(e.out.is_empty());
        e.log_message_file(Phase::Stderr, "stderr-shown-despite-quiet\n", &[]);
        assert!(!e.out.is_empty());
        e.set_log_quiet(false);
        e.log_message_stdout("not-quiet %d", &[Arg::I(3)]);
        assert_eq!(e.out.last().unwrap().text, "not-quiet 3");
    }

    #[test]
    fn syslog_branch_priorities() {
        let mut e = eng();
        e.logging_flags |= LOGGING_FLAG_SYSLOG;
        e.log_message_stdout( "syslog-info %d", &[Arg::I(1)]);
        assert!(e.out[0].text.starts_with("SYSLOG(29) syslog-info 1"));
        e.warning_message("syslog-warn", &[]);
        assert!(e.out[1].text.starts_with("SYSLOG(28) syslog-warn"));
        e.error_message("syslog-err %s", &[Arg::S(Some("e".into()))]);
        assert!(e.out[2].text.starts_with("SYSLOG(27) syslog-err"));
    }
}
