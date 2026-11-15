// Port of the parse-diagnostic surface of snort3 log/messages.{h,cc} as the
// parser/vars layer uses it: ParseError / ParseWarning / ParseAbort.
//
// C logs through file-global functions with printf semantics, and ParseAbort
// additionally longjmps out of every frame. The port models them explicitly:
// messages land in an ordered log on the vars engine (chronological, matching
// C's immediate printf), and ParseAbort is a returned Err with the same text
// already recorded in the log — tools/vars_harness replay compares the log
// line-for-line against the C harness output ("PERR ", "WARN(3) ", "ABORT "
// prefixes; in-C trailing '\n' inside a format string is kept verbatim).
#![allow(dead_code)]

/// C enum WarningGroup values (log/messages.h declaration order, 0-based).
pub const WARN_DAQ: u32 = 0;
pub const WARN_CONF: u32 = 1;
pub const WARN_CONF_STRICT: u32 = 2;
pub const WARN_VARS: u32 = 3;
pub const WARN_SYMBOLS: u32 = 4;
pub const WARN_SCRIPTS: u32 = 5;
pub const WARN_HOSTS: u32 = 6;
pub const WARN_RULES: u32 = 7;
pub const WARN_FLOWBITS: u32 = 8;
pub const WARN_PLUGINS: u32 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseMsg {
    Error(String),
    Warning(u32, String),
    /// Recorded when a Parse Abort fires (the Err is also returned).
    Abort(String),
}

/// ParseAbort payload: the formatted message text, no "ABORT " prefix.
/// May contain embedded newlines exactly as the C printf produced them
/// (multi-line PortVar parse-error caret display).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseAbort(pub String);

impl ParseAbort {
    pub fn text(&self) -> &str {
        &self.0
    }
}
