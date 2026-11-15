//! Port map of snort3 src/main/thread.cc — the instance/main file naming
//! half (populate_instance_maps and the instance-mappings CSV ride with
//! the thread layer). C keeps inst/run/thread-type in file-scope
//! thread_locals; the port models them explicitly in `ThreadState`, and
//! the SnortConfig fields these functions read in `NamingConfig`.

use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;

use crate::log::messages::LogEngine;
use crate::utils::util::get_error;

unsafe extern "C" {
    fn umask(mode: u32) -> u32;
}

// thread.h: enum SThreadType
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SThreadType {
    Other,
    Packet,
    Main,
}

/// thread.cc file-statics (THREAD_LOCAL instance_id, run_num, thread_type)
/// plus the one ThreadConfig value the naming path reads (instance_max).
#[derive(Clone, Debug)]
pub struct ThreadState {
    thread_type: SThreadType,
    pub instance_id: u32,
    run_num: u16,
    instance_max: u32,
}

impl Default for ThreadState {
    fn default() -> Self {
        ThreadState {
            thread_type: SThreadType::Other,
            instance_id: 0,
            run_num: 0,
            instance_max: 1, // thread_config.cc:44
        }
    }
}

impl ThreadState {
    pub fn set_thread_type(&mut self, t: SThreadType) {
        self.thread_type = t;
    }
    pub fn get_thread_type(&self) -> SThreadType {
        self.thread_type
    }
    pub fn set_run_num(&mut self, n: u16) {
        self.run_num = n;
    }
    pub fn get_run_num(&self) -> u16 {
        self.run_num
    }
    // ThreadConfig::set_instance_max shape
    pub fn set_instance_max(&mut self, m: u32) {
        self.instance_max = m;
    }
}

pub fn in_main_thread(ts: &ThreadState) -> bool {
    ts.get_thread_type() == SThreadType::Main
}

pub fn is_packet_thread(ts: &ThreadState) -> bool {
    ts.get_thread_type() == SThreadType::Packet
}

/// thread.cc: get_relative_instance_number()
pub fn get_relative_instance_number(ts: &ThreadState, conf: &NamingConfig) -> u32 {
    ts.instance_id + u32::from(conf.id_offset)
}

/// The SnortConfig fields thread.cc reads.
#[derive(Clone, Debug, Default)]
pub struct NamingConfig {
    pub log_dir: String,
    pub run_prefix: String,
    pub id_offset: u16,
    pub id_subdir: bool,
    pub id_zero: bool,
}

/// thread.cc:129 get_instance_file. Format is
///     <logdir>/[<run_prefix>][<id#>][<X>]<name>
/// Reproduces: log_dir or "./" defaulted, trailing-'/' guard, run_prefix,
/// the id emitted only when instance_max > 1 || id_zero (id_offset alone
/// does NOT trigger it — vector A3), the char id[8] with snprintf that
/// silently truncates to 7 digits (vector A11, 8-digit id), id_subdir
/// creating the directory (mkdir 0770 with umask quashed; EEXIST
/// swallowed, anything else ParseError'd with strerror text — vector
/// A10) versus the '_' separator when anything was appended, and the
/// bare name otherwise (vector A1: "./a.log").
pub fn get_instance_file(
    conf: &NamingConfig,
    ts: &ThreadState,
    name: &str,
    log: &mut LogEngine,
) -> String {
    let mut sep = false;
    let mut file = if !conf.log_dir.is_empty() {
        conf.log_dir.clone()
    } else {
        "./".to_string()
    };

    if file.as_bytes().last() != Some(&b'/') {
        file.push('/');
    }

    if !conf.run_prefix.is_empty() {
        file.push_str(&conf.run_prefix);
        sep = true;
    }

    if ts.instance_max > 1 || conf.id_zero {
        // C: char id[8]; snprintf(id, sizeof(id), "%u", id_val) — keeps
        // at most 7 digits, truncating silently.
        let id_val = ts.instance_id + u32::from(conf.id_offset);
        let id = format!("{id_val}");
        let id = if id.len() > 7 { &id[..7] } else { &id[..] };
        file.push_str(id);
        sep = true;
    }

    if conf.id_subdir {
        file.push('/');

        // Explicitly set mode to avoid umask issues (fixes random 0750/0700)
        let old_mask = unsafe { umask(0) };
        let dir = DirBuilder::new().mode(0o770).create(&file);
        unsafe {
            umask(old_mask);
        }
        if let Err(e) = dir {
            let errno = e.raw_os_error().unwrap_or(0);
            // errno != EEXIST
            if errno != 17 {
                log.parse_error(
                    "Failed to create directory %s - %s",
                    &[
                        crate::utils::cfmt::Arg::S(Some(file.clone().into())),
                        crate::utils::cfmt::Arg::S(Some(get_error(errno).into())),
                    ],
                );
            }
        }
    } else if sep {
        file.push('_');
    }

    file.push_str(name);
    file
}

/// thread.cc:173 get_main_file: <logdir>/[<run_prefix>][main_]<name>.
/// "main_" is skipped exactly when id_zero is set (vector A4 lineage).
pub fn get_main_file(conf: &NamingConfig, name: &str) -> String {
    let mut file = if !conf.log_dir.is_empty() {
        conf.log_dir.clone()
    } else {
        "./".to_string()
    };

    if !file.ends_with('/') {
        file.push('/');
    }

    if !conf.run_prefix.is_empty() {
        file.push_str(&conf.run_prefix);
    }

    if !conf.id_zero {
        file.push_str("main_");
    }

    file.push_str(name);
    file
}
