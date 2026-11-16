// Port of the stats-label half of snort3 log/log_stats.cc — the exact
// pieces parse_rule_print drives: LogLabel/LogCount (+LogText/LogValue and
// LogSeparator). LogfRespond(s_ctrlcon, fh, ...) is the control.h macro:
// s_ctrlcon == nullptr in the harness (set_log_conn never called) so the
// abort branch never runs and every call lands in LogMessage(fh, ...).
// Ground truth: ORIGINAL log_stats.cc compiled in tools/rules_harness;
// vectors.txt STATS blocks pin the separator + "%25.25s: %llu" output and
// the count==0 print-skip verbatim.
#![allow(dead_code)]

use crate::log::messages::{LogEngine, Phase};
use crate::utils::cfmt::Arg;

pub const STATS_SEPARATOR: &str = "--------------------------------------------------";

/// static inline void LogSeparator(FILE* fh = stdout)
pub fn log_separator(e: &mut LogEngine, fh: Phase) {
    e.log_message_file(fh, "%s\n", &[Arg::S(Some(STATS_SEPARATOR.into()))]);
}

/// void LogText(const char* s, FILE* fh)
pub fn log_text(e: &mut LogEngine, s: &str, fh: Phase) {
    e.log_message_file(fh, "%s\n", &[Arg::S(Some(s.into()))]);
}

/// void LogLabel(const char* s, FILE* fh)
pub fn log_label(e: &mut LogEngine, s: &str, fh: Phase) {
    if s.as_bytes().first() == Some(&b' ') {
        e.log_message_file(fh, "%s\n", &[Arg::S(Some(s.into()))]);
    } else {
        log_separator(e, fh);
        e.log_message_file(fh, "%s\n", &[Arg::S(Some(s.into()))]);
    }
}

/// void LogValue(const char* s, const char* v, FILE* fh)
pub fn log_value(e: &mut LogEngine, s: &str, v: &str, fh: Phase) {
    e.log_message_file(
        fh,
        "%25.25s: %s\n",
        &[Arg::S(Some(s.into())), Arg::S(Some(v.into()))],
    );
}

/// void LogCount(const char* s, uint64_t c, FILE* fh): prints ONLY when
/// the count is nonzero (file-static-adjacent quirk pinned by the probe's
/// zero-count lines being absent).
pub fn log_count(e: &mut LogEngine, s: &str, c: u64, fh: Phase) {
    if c != 0 {
        e.log_message_file(fh, "%25.25s: %llu\n", &[Arg::S(Some(s.into())), Arg::U(c)]);
    }
}

/// stdout-default convenience matching the C default argument.
pub mod stdout_defaults {
    use super::*;
    pub fn log_label(e: &mut LogEngine, s: &str) {
        super::log_label(e, s, Phase::Stdout)
    }
    pub fn log_count(e: &mut LogEngine, s: &str, c: u64) {
        super::log_count(e, s, c, Phase::Stdout)
    }
    pub fn log_text(e: &mut LogEngine, s: &str) {
        super::log_text(e, s, Phase::Stdout)
    }
    pub fn log_value(e: &mut LogEngine, s: &str, v: &str) {
        super::log_value(e, s, v, Phase::Stdout)
    }
    pub fn log_separator(e: &mut LogEngine) {
        super::log_separator(e, Phase::Stdout)
    }
}
