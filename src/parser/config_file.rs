// Port of snort3 parser/config_file.{h,cc}.
//
// C file-statics lua_conf / snort_conf_dir are modeled as explicit state
// on ConfFiles (threaded like every other parsed table). The
// Analyzer::set_main_hook(DetectionEngine::inspect) side effect of
// config_conf belongs to the detection layer and is deferred (see
// KNOWN DEVIATIONS.md).
#![allow(dead_code)]

use crate::log::messages::LogEngine;
use crate::main::policy::{NetworkPolicy, CHECKSUM_FLAG__ALL, CHECKSUM_FLAG__ICMP, CHECKSUM_FLAG__IP, CHECKSUM_FLAG__TCP, CHECKSUM_FLAG__UDP};
use crate::utils::cfmt::Arg;

/// C std::string lua_conf + snort_conf_dir (config_file.cc:37-38).
#[derive(Clone, Debug, Default)]
pub struct ConfFiles {
    pub lua_conf: String,
    pub snort_conf_dir: String,
}

impl ConfFiles {
    pub fn get_snort_conf(&self) -> &str {
        // C returns the (never-null) std::string c_str(); an empty lua_conf
        // yields "" exactly as C would.
        &self.lua_conf
    }

    pub fn get_snort_conf_dir(&self) -> &str {
        &self.snort_conf_dir
    }

    /// void SetSnortConfDir(const char* file) (config_file.cc:174-192).
    /// A nullptr leaves the previous dir in place; no separator means "./".
    pub fn set_snort_conf_dir(&mut self, file: Option<&str>) {
        if let Some(file) = file {
            match file.rfind('/') {
                // strrchr(file, '/') then ++: keep the separator itself
                Some(i) => self.snort_conf_dir = file[..=i].to_string(),
                None => self.snort_conf_dir = "./".to_string(),
            }
        }
    }

    /// void config_conf(const char* val) (config_file.cc:167-172).
    /// The set_main_hook half is a no-op until detection lands.
    pub fn config_conf(&mut self, val: &str) {
        self.lua_conf = val.to_string();
        let owned = self.lua_conf.clone();
        self.set_snort_conf_dir(Some(owned.as_str()));
    }
}

/// static int GetChecksumFlags(const char* args) (config_file.cc:46-153).
/// Returns (flags, bad_token): on an unknown token C emits
/// ParseError("unknown command line checksum option: %s.", tok) and
/// returns the pre-loop ret_flags (always 0). The caller owns the
/// ParseError so printf/location semantics stay in one place.
///
/// C tokenizes with `std::stringstream >> tok` (isspace split, empty runs
/// skipped) == split_ascii_whitespace.
fn get_checksum_flags(args: Option<&str>) -> Result<u32, String> {
    let args = match args {
        // args == nullptr -> CHECKSUM_FLAG__ALL
        None => return Ok(CHECKSUM_FLAG__ALL),
        Some(a) => a,
    };

    let mut negative_flags: u32 = 0;
    let mut positive_flags: u32 = 0;
    let mut got_positive_flag = false;
    let mut got_negative_flag = false;

    for tok in args.split_ascii_whitespace() {
        match tok {
            "all" => {
                positive_flags = CHECKSUM_FLAG__ALL;
                negative_flags = 0;
                got_positive_flag = true;
            }
            "none" => {
                positive_flags = 0;
                negative_flags = CHECKSUM_FLAG__ALL;
                got_negative_flag = true;
            }
            "ip" => {
                positive_flags |= CHECKSUM_FLAG__IP;
                negative_flags &= !CHECKSUM_FLAG__IP;
                got_positive_flag = true;
            }
            "noip" => {
                positive_flags &= !CHECKSUM_FLAG__IP;
                negative_flags |= CHECKSUM_FLAG__IP;
                got_negative_flag = true;
            }
            "tcp" => {
                positive_flags |= CHECKSUM_FLAG__TCP;
                negative_flags &= !CHECKSUM_FLAG__TCP;
                got_positive_flag = true;
            }
            "notcp" => {
                positive_flags &= !CHECKSUM_FLAG__TCP;
                negative_flags |= CHECKSUM_FLAG__TCP;
                got_negative_flag = true;
            }
            "udp" => {
                positive_flags |= CHECKSUM_FLAG__UDP;
                negative_flags &= !CHECKSUM_FLAG__UDP;
                got_positive_flag = true;
            }
            "noudp" => {
                positive_flags &= !CHECKSUM_FLAG__UDP;
                negative_flags |= CHECKSUM_FLAG__UDP;
                got_negative_flag = true;
            }
            "icmp" => {
                positive_flags |= CHECKSUM_FLAG__ICMP;
                negative_flags &= !CHECKSUM_FLAG__ICMP;
                got_positive_flag = true;
            }
            "noicmp" => {
                positive_flags &= !CHECKSUM_FLAG__ICMP;
                negative_flags |= CHECKSUM_FLAG__ICMP;
                got_negative_flag = true;
            }
            other => {
                return Err(other.to_string());
            }
        }
    }

    // Invert the negative flags with all checksums
    negative_flags ^= CHECKSUM_FLAG__ALL;
    negative_flags &= CHECKSUM_FLAG__ALL;

    if got_positive_flag && got_negative_flag {
        Ok(positive_flags & negative_flags)
    } else if got_positive_flag {
        Ok(positive_flags)
    } else {
        // a negative flag assumes all checksums on; a zero-token input
        // (got_neither) lands here too with negative_flags == ALL after
        // the invert (pinned: args "  " -> f).
        Ok(negative_flags)
    }
}

/// void ConfigChecksumDrop(const char* args) (config_file.cc:155-159).
pub fn config_checksum_drop(args: Option<&str>, policy: &mut NetworkPolicy, log: &mut LogEngine) {
    match get_checksum_flags(args) {
        Ok(flags) => policy.checksum_drop = flags,
        Err(tok) => {
            log.parse_error(
                "unknown command line checksum option: %s.",
                &[Arg::S(Some(tok.into()))],
            );
            // C: return ret_flags (0) BEFORE any assignment -> field keeps
            // whatever the previous call set? No: C assigns the return to
            // policy->checksum_drop anyway (GetChecksumFlags returned 0).
            policy.checksum_drop = 0;
        }
    }
}

/// void ConfigChecksumMode(const char* args) (config_file.cc:161-165).
pub fn config_checksum_mode(args: Option<&str>, policy: &mut NetworkPolicy, log: &mut LogEngine) {
    match get_checksum_flags(args) {
        Ok(flags) => policy.checksum_eval = flags,
        Err(tok) => {
            log.parse_error(
                "unknown command line checksum option: %s.",
                &[Arg::S(Some(tok.into()))],
            );
            policy.checksum_eval = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main::policy::CHECKSUM_FLAG__DEF;

    #[test]
    fn get_checksum_flags_table() {
        // Pinned spot-checks from tools/conf_harness/vectors.txt
        assert_eq!(get_checksum_flags(None).unwrap(), 0xf);
        assert_eq!(get_checksum_flags(Some("")).unwrap(), 0xf);
        assert_eq!(get_checksum_flags(Some("none")).unwrap(), 0x0);
        assert_eq!(get_checksum_flags(Some("noip")).unwrap(), 0xe);
        assert_eq!(get_checksum_flags(Some("ip noip")).unwrap(), 0x0);
        assert_eq!(get_checksum_flags(Some("all none")).unwrap(), 0x0);
        assert_eq!(get_checksum_flags(Some("none all")).unwrap(), 0xf);
        assert_eq!(get_checksum_flags(Some("ip all notcp")).unwrap(), 0xd);
        assert_eq!(get_checksum_flags(Some("  ")).unwrap(), 0xf);
        assert_eq!(get_checksum_flags(Some("bogus")).unwrap_err(), "bogus");
    }

    #[test]
    fn conf_dir_extract() {
        let mut c = ConfFiles::default();
        c.config_conf("/etc/snort/snort.lua");
        assert_eq!(c.get_snort_conf(), "/etc/snort/snort.lua");
        assert_eq!(c.get_snort_conf_dir(), "/etc/snort/");
        c.config_conf("snort.lua");
        assert_eq!(c.get_snort_conf_dir(), "./");
        c.config_conf("a/");
        assert_eq!(c.get_snort_conf_dir(), "a/");
        // nullptr leaves the dir untouched but assigns "" to lua_conf? C
        // constructs std::string from nullptr (UB); port takes Option on
        // set_snort_conf_dir only (deviation; config_conf never gets null
        // in practice).
        c.set_snort_conf_dir(None);
        assert_eq!(c.get_snort_conf_dir(), "a/");
        assert_eq!(CHECKSUM_FLAG__DEF, 0x8000_0000);
    }
}
