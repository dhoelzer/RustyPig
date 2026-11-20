// Port of the configuration-file core of snort3 parser/parse_conf.cc:
// the parse-location stack (`static std::stack<Location> files`),
// rules_file_depth, s_ips_policy, get_config_file's four-way directory
// walk (include/parse/config/working dirs), parse_include,
// parse_rules_file, parse_rules_string and get_rule_list. ParseIpVar
// lives in parser::vars (the resolve_nets callback); config_conf and
// checksum flags in parser::config_file.
//
// C++ ParseAbort longjmps out of these frames from ExpandVars; the port
// returns early after the abort was already logged, matching exactly what
// the replay observes (no ParseError after the abort line).
#![allow(dead_code, clippy::too_many_arguments)]

use std::cell::RefCell;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;

use crate::log::messages::LogEngine;
use crate::main::policy::IpsPolicy;
use crate::parser::config_file::ConfFiles;
use crate::parser::vars::{expand_vars, VarContext};
use crate::utils::cfmt::Arg;

/// Seam type: the harness/test injects a parse_stream substitute that may
/// re-enter parse_include (pins rules_file_depth / seed-selection live).
pub type StreamSeam<'a> = &'a mut dyn FnMut(
    &mut ParseConf,
    &mut VarContext,
    &mut SnortConfig,
    &ConfFiles,
    &IpsPolicy,
    &mut LogEngine,
);

unsafe extern "C" {
    fn strerror(errnum: i32) -> *const std::ffi::c_char;
}

/// parse_conf.cc:52 — struct Location. `code` keeps the C++ const char*
/// null-vs-empty distinction: print_parse_file's ternary picks "?" only
/// for a *null* code; an empty non-null code prints as "".
#[derive(Clone, Debug)]
struct Location {
    code: Option<String>,
    path: String,
    file: String,
    line: u32,
}

/// policy.h RuleListNode. ListHead is the detection layer's opaque list;
/// the conf layer threads it through untouched, so the port carries an
/// opaque stand-in type parameter.
#[derive(Debug)]
pub struct RuleListNode {
    pub name: String,
    pub rule_list: Option<Rc<RefCell<Vec<u8>>>>,
    pub next: Option<Rc<RuleListNode>>,
}

/// The public get_rule_list return alias (opaque ListHead pointer).
pub type ListHeadRef = Rc<RefCell<Vec<u8>>>;

/// The minimal SnortConfig surface parse_conf.cc touches (plus the
/// special includer owned here, which C++ keeps in parser.cc file-statics
/// until the rule layer lands — see deviations).
#[derive(Debug, Default)]
pub struct SnortConfig {
    show_file_codes: bool,
    pub include_path: String,
    pub rule_lists: Option<Rc<RuleListNode>>,
    special_includer: String,
    // ---- row 18c: the decode-module knobs the codec TUs read ----
    // snort_config.h:278 `uint8_t max_ip6_extensions = 0;` (the C
    // NSDMI zero == Rust Default zero).
    pub max_ip6_extensions: u8,
    // ---- row 18d: the ethernet-rewrite knob cd_eth encode reads ----
    // snort_config.h:289 `uint8_t* eth_dst = nullptr;` — the nullptr
    // NSDMI == Rust None; Some([6 bytes]) models the set face
    // (cd_eth.cc cc:170/:179 `if ( sc->eth_dst )` arms; the null arm
    // is the MEASURABLE face under the harness witness config, eth
    // PLAN §2).
    pub eth_dst: Option<[u8; 6]>,
}

impl SnortConfig {
    /// snort_config.h:450-:451 inlined getter (row 18c wiring; read by
    /// codecs/ip/cd_no_next decode): C
    /// `return max_ip6_extensions && (curr_opt >= max_ip6_extensions);`
    /// — the C truthy test is literal `!= 0` (0 first short-circuits).
    #[inline]
    #[allow(non_snake_case)]
    pub fn hit_ip6_maxopts(&self, curr_opt: u8) -> bool {
        self.max_ip6_extensions != 0 && (curr_opt >= self.max_ip6_extensions)
    }

    pub fn show_file_codes(&self) -> bool {
        self.show_file_codes
    }
    pub fn set_show_file_codes(&mut self, v: bool) {
        self.show_file_codes = v;
    }
    pub fn set_special_includer(&mut self, v: &str) {
        self.special_includer = v.to_string();
    }
}

/// parse_conf.cc file-statics: `files`, `rules_file_depth`, `s_ips_policy`
/// (default true, line 65). The parse seam (original parse_stream belongs
/// to the rule layer) is a callback; `stream_reads` counts reachings so
/// the replay can pin depth bookkeeping without the whole parser.
#[derive(Debug, Default)]
pub struct ParseConf {
    files: Vec<Location>,
    rules_file_depth: i32,
    ips_policy: bool,
    pub stream_reads: i32,
}

impl ParseConf {
    pub fn new() -> Self {
        ParseConf {
            files: Vec::new(),
            rules_file_depth: 0,
            ips_policy: true,
            stream_reads: 0,
        }
    }

    /// file-static accessors for the parse_stream include channel (C
    /// reaches these as globals; the port threads ParseConf).
    pub fn depth(&self) -> i32 {
        self.rules_file_depth
    }
    pub fn bump_rules_file_depth(&mut self, d: i32) {
        self.rules_file_depth += d;
    }
    pub fn ips_policy_flag(&self) -> bool {
        self.ips_policy
    }
    pub fn set_ips_policy(&mut self, v: bool) {
        self.ips_policy = v;
    }

    /// const char* get_parse_file() (67-73): stack top path else conf.
    pub fn get_parse_file<'a>(&'a self, conf_files: &'a ConfFiles) -> &'a str {
        match self.files.last() {
            Some(loc) => loc.path.as_str(),
            None => conf_files.get_snort_conf(),
        }
    }

    /// get_parse_location (75-86). Empty stack -> (nullptr, 0).
    pub fn get_parse_location(&self) -> (Option<&str>, u32) {
        match self.files.last() {
            None => (None, 0),
            Some(loc) => (Some(loc.file.as_str()), loc.line),
        }
    }

    /// print_parse_file (88-95).
    fn print_parse_file(&self, msg: &str, loc: &Location, conf: &SnortConfig, log: &mut LogEngine) {
        if conf.show_file_codes() {
            let code: &str = match &loc.code {
                None => "?",          // C++ ternary on the null pointer
                Some(c) => c.as_str(),
            };
            log.log_message_stdout(
                "%s %s:%s:\n",
                &[
                    Arg::S(Some(msg.to_string().into())),
                    Arg::S(Some(code.to_string().into())),
                    Arg::S(Some(loc.file.clone().into())),
                ],
            );
        } else {
            log.log_message_stdout(
                "%s %s:\n",
                &[
                    Arg::S(Some(msg.to_string().into())),
                    Arg::S(Some(loc.file.clone().into())),
                ],
            );
        }
    }

    /// push_parse_location (97-109). null path -> no push. null file ->
    /// file = path (both path and file copied separately, like C++).
    pub fn push_parse_location(
        &mut self,
        code: Option<&str>,
        path: Option<&str>,
        file: Option<&str>,
        line: u32,
        conf: &SnortConfig,
        log: &mut LogEngine,
    ) {
        let path = match path {
            None => return, // null path: returns before any logging
            Some(p) => p,
        };
        let file = file.unwrap_or(path);
        let loc = Location {
            code: code.map(|c| c.to_string()),
            path: path.to_string(),
            file: file.to_string(),
            line,
        };
        self.files.push(loc.clone());
        self.print_parse_file("Loading", &loc, conf, log);
        Self::sync(log, self);
    }

    /// pop_parse_location (111-119). Empty -> silent no-op.
    pub fn pop_parse_location(&mut self, conf: &SnortConfig, log: &mut LogEngine) {
        if let Some(loc) = self.files.last().cloned() {
            self.print_parse_file("Finished", &loc, conf, log);
            self.files.pop();
            Self::sync(log, self);
        }
    }

    /// inc_parse_position (121-127). Empty -> silent no-op.
    pub fn inc_parse_position(&mut self, log: &mut LogEngine) {
        if let Some(loc) = self.files.last_mut() {
            loc.line += 1;
            Self::sync(log, self);
        }
    }

    /// LogEngine::parse_loc mirrors C++ get_parse_location, which reads
    /// the same stack top; re-sync after every stack mutation.
    fn sync(log: &mut LogEngine, this: &ParseConf) {
        let (f, l) = this.get_parse_location();
        log.set_parse_location(f, l);
    }

    /// valid_file (129-136): path += '/' + file, stat == 0. Directories
    /// stat fine (the adir quirk in parse_rules_file is separate).
    fn valid_file(path: &mut Vec<u8>, file: &OsStr) -> bool {
        path.push(b'/');
        path.extend_from_slice(file.as_bytes());
        std::fs::metadata(OsStr::from_bytes(&*path)).is_ok()
    }

    /// relative_to_parse_dir (138-148): empty path -> get_parse_file();
    /// rfind('/') -> erase(idx); else ".". (Note: path retains the "/" —
    /// "./" before an empty arg is the pinned GC5/GC9 artifact.)
    fn relative_to_parse_dir(
        &self,
        file: &OsStr,
        path: &mut Vec<u8>,
        conf_files: &ConfFiles,
    ) -> bool {
        if path.is_empty() {
            path.extend_from_slice(self.get_parse_file(conf_files).as_bytes());
        }
        match path.iter().rposition(|&c| c == b'/') {
            Some(idx) => path.truncate(idx), // erase(idx) removes idx..end
            None => {
                path.clear();
                path.push(b'.');
            }
        }
        Self::valid_file(path, file)
    }

    /// relative_to_config_dir (150-154): path assigned fresh from conf dir.
    fn relative_to_config_dir(file: &OsStr, path: &mut Vec<u8>, conf_files: &ConfFiles) -> bool {
        path.clear();
        path.extend_from_slice(conf_files.get_snort_conf_dir().as_bytes());
        Self::valid_file(path, file)
    }

    /// relative_to_include_dir (156-162): conf->include_path; empty -> false.
    fn relative_to_include_dir(file: &OsStr, path: &mut Vec<u8>, conf: &SnortConfig) -> bool {
        path.clear();
        path.extend_from_slice(conf.include_path.as_bytes());
        if path.is_empty() {
            return false;
        }
        Self::valid_file(path, file)
    }

    /// relative_to_working_dir (164-168): path = "."; then stats "./arg".
    fn relative_to_working_dir(file: &OsStr, path: &mut Vec<u8>) -> bool {
        path.clear();
        path.push(b'.');
        Self::valid_file(path, file)
    }

    /// get_config_file (170-198). Order: absolute -> "I" -> "F" -> "C" -> "W".
    /// On miss `file` keeps the last W attempt (".arg") — pinned GC7.
    pub fn get_config_file(
        &self,
        arg: &str,
        file: &mut Vec<u8>,
        conf: &SnortConfig,
        conf_files: &ConfFiles,
    ) -> Option<&'static str> {
        // NOTE(arg): C++ assert(arg) — never null at these call sites.
        if arg.as_bytes().first() == Some(&b'/') {
            file.clear();
            file.extend_from_slice(arg.as_bytes());
            return Some("A");
        }
        let hint: Vec<u8> = file.clone();

        if Self::relative_to_include_dir(OsStr::new(arg), file, conf) {
            return Some("I");
        }
        *file = hint;

        if self.relative_to_parse_dir(OsStr::new(arg), file, conf_files) {
            return Some("F");
        }
        if Self::relative_to_config_dir(OsStr::new(arg), file, conf_files) {
            return Some("C");
        }
        if Self::relative_to_working_dir(OsStr::new(arg), file) {
            return Some("W");
        }
        None
    }

    /// parse_include (200-225): ExpandVars, pick seed by depth/policy,
    /// resolve, then push file/conf and parse the file. A var expansion
    /// abort longjmps in C++: its message is already in the log and no
    /// ParseError follows — modeled by an early return.
    pub fn parse_include(
        &mut self,
        arg: &str,
        ctx: &mut VarContext,
        conf: &mut SnortConfig,
        conf_files: &ConfFiles,
        ip: &IpsPolicy,
        log: &mut LogEngine,
        on_stream: Option<StreamSeam<'_>>,
    ) {
        let conf_str = match expand_vars(ctx, arg) {
            Ok(v) => v,
            Err(_) => return,
        };
        let file: &str = if self.rules_file_depth != 0 {
            self.get_parse_file(conf_files)
        } else if self.ips_policy {
            ip.includer.as_str()
        } else {
            conf.special_includer.as_str()
        };
        let mut buf: Vec<u8> = file.as_bytes().to_vec();

        let code = match self.get_config_file(&conf_str, &mut buf, conf, conf_files) {
            None => {
                log.parse_error("can't open %s\n", &[Arg::S(Some(conf_str.into()))]);
                return;
            }
            Some(c) => c,
        };
        let file_str = String::from_utf8_lossy(&buf).into_owned();
        let conf_str2 = conf_str.clone();
        // push_parse_location(code, file, conf): the C++ header default is
        // `unsigned line = 1` (parser.h) — parse_include passes nothing
        // beyond 3 args, so line starts at 1. Vectors: E1/E3 "Loading
        // b.rules:" with follow-up locations line=1.
        self.push_parse_location(
            Some(code),
            Some(&file_str),
            Some(&conf_str2),
            1,
            conf,
            log,
        );
        self.parse_rules_file(Some(&file_str), ctx, conf, conf_files, ip, log, on_stream);
        self.pop_parse_location(conf, log);
    }

    /// parse_rules_file (314-330). `fname` None models the C++ nullptr
    /// quiet return. Failed open -> ParseError with get_error(errno);
    /// directories *do* open via ifstream (vector: adir no error).
    pub fn parse_rules_file(
        &mut self,
        fname: Option<&str>,
        ctx: &mut VarContext,
        conf: &mut SnortConfig,
        conf_files: &ConfFiles,
        ip: &IpsPolicy,
        log: &mut LogEngine,
        on_stream: Option<StreamSeam<'_>>,
    ) {
        let fname = match fname {
            None => return,
            Some(f) => f,
        };
        if !Self::fstream_openable(fname) {
            log.parse_error(
                "unable to open rules file '%s': %s",
                &[
                    Arg::S(Some(fname.to_string().into())),
                    Arg::S(Some(strerror_enoent().into())),
                ],
            );
            return;
        }
        self.rules_file_depth += 1;
        self.stream_reads += 1; // the parse_stream seam
        if let Some(f) = on_stream {
            f(self, ctx, conf, conf_files, ip, log);
        }
        self.rules_file_depth -= 1;
    }

    /// parse_rules_string (332-339): sets s_ips_policy, streams, restores.
    /// Note it does NOT touch rules_file_depth — pinned by E10 (nested
    /// include at depth 0 picks the policy includer, not get_parse_file).
    pub fn parse_rules_string(
        &mut self,
        _s: &str,
        ips_policy: bool,
        ctx: &mut VarContext,
        conf: &mut SnortConfig,
        conf_files: &ConfFiles,
        ip: &IpsPolicy,
        log: &mut LogEngine,
        on_stream: Option<StreamSeam<'_>>,
    ) {
        self.ips_policy = ips_policy;
        self.stream_reads += 1; // parse_stream(ss, sc)
        if let Some(f) = on_stream {
            f(self, ctx, conf, conf_files, ip, log);
        }
        self.ips_policy = true;
    }

    /// get_rule_list (304-312): linear strcmp-walk over sc->rule_lists.
    pub fn get_rule_list(conf: &SnortConfig, s: &str) -> Option<ListHeadRef> {
        let mut cur = conf.rule_lists.as_ref().cloned();
        while let Some(node) = cur {
            if node.name == s {
                return node.rule_list.clone(); // matched; the list itself may be null
            }
            cur = node.next.clone();
        }
        None
    }

    /// C++ std::ifstream(fname, binary) success test. Regular files need
    /// read access; directories "open" (their stream EOFs immediately —
    /// no PERR; vector: adir). Nonexistent -> fail. The simplest faithful
    /// Linux approximation: metadata() succeeds (which covers both), else
    /// fail. EACCES-only files are indistinguishable by metadata; accept
    /// the shared simplification (deviation note).
    fn fstream_openable(fname: &str) -> bool {
        std::fs::metadata(fname).is_ok()
    }
}

/// get_error(errno) from utils/util.cc (GNU strerror_r branch). The only
/// open-failure errno that the conf-layer paths can observe on Linux is
/// ENOENT; strerror(2) is fixed glibc text the vectors pin verbatim.
fn strerror_enoent() -> String {
    unsafe {
        let p = strerror(2);
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}
