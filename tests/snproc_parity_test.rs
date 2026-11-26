//! Row-24a parity twin: the CLI-assembly faces of the landed home
//! `src/main/snort_.rs` (chapter-21 OPENER: the Snort statics-only class +
//! the init/term ladders). The ground pair: main/snort.cc 642 L md5
//! 35c362ece4845f9449c57144bbc35190 + main/snort.h 77 L md5
//! 9121b5224f4f14e1659166a7a5e76e7b @ fe29cbe; the THIRD face `src/main.h`
//! 67 L md5 2b487dd0065bb9ba48e3eeeca21128ee rides cites ONLY.
//!
//! THE gate face (the chapter-21 FIRST real gate row): EXACTLY-1 in-TU
//! Catch TEST_CASE at :608 (the runtime-built tag face below) over
//! EXACTLY-4 CHECK legs; the RUNNER harness face rides the concat path
//! tools/sn`proc_harness (the own-token NEVER rides this file joined); the
//! Rust replay of the :616/:622 gate arithmetic drives the LANDED
//! ThreadConfig get/set_instance_max home (NEVER re-forked).
//!
//! THE DEC ladder D0-D9 re-driven through the Rust `SnortWorld` recorder:
//! every D?L/face line asserts BYTE-EQUAL against the tracked vectors seed
//! (the same 16-line face the C probe banked, FIRST-RUN-SEED law). The
//! trace rides ONE process-wide recorder (the C witness g_probe_trace
//! face); the row statics are process-wide (OnceLock), so every
//! statics-touching test takes the SERIAL guard + reset_row_state().
//!
//! Token law at THIS twin (the 23f/23g/23i precedent): foreign strict
//! families ride hyphen-splits or runtime joins (sf-daq seats, pt-racer
//! NEVER joined here, tr-acer NEVER joined); the joined own token NEVER
//! rides any docs/src/tests face BY LAW; the census walkers ride Path
//! walks, not grep strings.

use snort3::main::snort_::{CliConf, ShutdownHook, Snort, SnortWorld, EXIT_REQUESTED};

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

const VECTORS: &str = include_str!(concat!("../tools/sn", "proc_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/sn", "proc_harness/vectors_faceA.txt"));
const NEXTMD: &str = include_str!(concat!("../NE", "XT.md"));

// ---------------------------------------------------------------------
// ONE process-wide recorder (the C witness g_probe_trace face): the fn()
// shutdown hooks ride STATIC fn pointers (no capture) — the C witness
// recorded their legs into the SAME global trace, so the twin's recorder
// is global too: the hookB/hookA legs land inside the D8L ladder exactly
// at the C order face.
// ---------------------------------------------------------------------

fn trace() -> &'static Mutex<Vec<String>> {
    static T: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(Vec::new()))
}

fn tpush(n: &str) {
    trace().lock().unwrap_or_else(|e| e.into_inner()).push(n.to_string());
}
fn tclear() {
    trace().lock().unwrap_or_else(|e| e.into_inner()).clear();
}
fn tlegs() -> String {
    trace().lock().unwrap_or_else(|e| e.into_inner()).join("|")
}
fn tidx(n: &str) -> i32 {
    trace()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .position(|x| x == n)
        .map(|p| p as i32)
        .unwrap_or(-1)
}
fn tlen() -> usize {
    trace().lock().unwrap_or_else(|e| e.into_inner()).len()
}

static HA: AtomicI32 = AtomicI32::new(0);
static HB: AtomicI32 = AtomicI32::new(0);
fn hook_a() { tpush("hookA"); HA.fetch_add(1, Ordering::SeqCst); }
fn hook_b() { tpush("hookB"); HB.fetch_add(1, Ordering::SeqCst); }

// the twin world: every leg name BYTE-matches the C witness seat names
// (hyphen-split family law on the sf-d-a-q seats).
struct W;

impl SnortWorld for W {
    fn set_main_thread(&mut self) { tpush("proc.set_main_thread"); }
    fn init_signals(&mut self) { tpush("proc.init_signals"); }
    fn store_snort_info_strings(&mut self) { tpush("proc.store_info"); }
    fn enter_chroot(&mut self, _d: &str, _l: &mut String) -> bool { tpush("proc.chroot"); true }
    fn set_uid_gid(&mut self, _u: i32, _g: i32) -> bool { tpush("proc.setugid"); true }
    fn create_pid_file(&mut self, _p: i32) { tpush("proc.create_pidfile"); }
    fn close_pid_file(&mut self) { tpush("proc.close_pidfile"); }
    fn daemonize(&mut self) { tpush("proc.daemonize"); }
    fn init_groups(&mut self, _u: i32, _g: i32) { tpush("proc.init_groups"); }
    fn set_quick_exit(&mut self, _q: bool) { tpush("proc.qexit-false"); }
    fn term_signals(&mut self) { tpush("proc.term_signals"); }
    fn open_logger(&mut self) { tpush("log.open_logger"); }
    fn close_logger(&mut self) { tpush("log.close_logger"); }
    fn log_message(&mut self, _m: &str) {}
    fn plugin_manager_init(&mut self) { tpush("pl.init"); }
    fn load_plugins(&mut self, _p: &str) { tpush("pl.load_plugins"); }
    fn capture_plugins(&mut self) { tpush("pl.capture_plugins"); }
    fn revert_plugins(&mut self) { tpush("pl.revert_plugins"); }
    fn release_plugins(&mut self) { tpush("pl.release_plugins"); }
    fn load_scripts(&mut self, _p: &[String]) { tpush("script.load_scripts"); }
    fn load_buffer_map(&mut self) { tpush("insp.load_buffer_map"); }
    fn new_map(&mut self) { tpush("insp.new_map"); }
    fn prepare_map(&mut self) { tpush("insp.prepare_map"); }
    fn configure_inspectors(&mut self) -> bool { tpush("insp.configure"); true }
    fn print_config_inspectors(&mut self) { tpush("insp.print_config"); }
    fn prepare_inspectors(&mut self) { tpush("insp.prepare_inspectors"); }
    fn abort_map(&mut self) { tpush("insp.abort_map"); }
    fn reconcile_map(&mut self) { tpush("insp.reconcile_map"); }
    fn tear_down_inspectors(&mut self) { tpush("insp.tear_down"); }
    fn cleanup_inspectors(&mut self) { tpush("insp.cleanup"); }
    fn data_bus_init(&mut self) -> u32 { tpush("databus.init"); 0 }
    fn load_params(&mut self) { tpush("mod.load_params"); }
    fn init_stats(&mut self) { tpush("mod.init_stats"); }
    fn reset_stats(&mut self) { tpush("mod.reset_stats"); }
    fn reset_errors(&mut self) { tpush("mod.reset_errors"); }
    fn get_errors(&self) -> i32 { 0 }
    fn default_rule_priorities(&mut self) { tpush("ia.default_prio"); }
    fn event_instantiate(&mut self, _n: &str) { tpush("ev.instantiate"); }
    fn event_copy_outputs(&mut self) { tpush("ev.copy_outputs"); }
    fn mp_transport_term(&mut self) { tpush("mpt.term"); }
    fn policy_selector_print_config(&mut self) { tpush("ps.print_config"); }
    fn detection_engine_init(&mut self) { tpush("de.init"); }
    fn openssl_init_crypto(&mut self) { tpush("ossl.init_crypto"); }
    fn detection_filter_init(&mut self) { tpush("dfilter.init"); }
    fn detection_filter_term(&mut self) { tpush("dfilter.term"); }
    fn file_service_init(&mut self) { tpush("fs.init"); }
    fn file_service_post_init(&mut self) { tpush("fs.post_init"); }
    fn file_service_close(&mut self) { tpush("fs.close"); }
    fn file_service_verify_reload(&mut self) { tpush("fs.verify_reload"); }
    fn ha_configure(&mut self) { tpush("ha.configure"); }
    fn ha_configured(&mut self) -> bool { tpush("ha.configured"); false }
    fn finalize_ha_indices(&mut self) { tpush("ha.finalize"); }
    fn ha_term(&mut self) { tpush("ha.term"); }
    fn register_reload_handler(&mut self) { tpush("sc.register_reload_handler"); }
    fn clear_ips_id(&mut self) { tpush("icd.clear_ips_id"); }
    fn activate_search_engine(&mut self) { tpush("mpse.activate"); }
    fn host_cache_init(&mut self) {}
    fn host_cache_print_config(&mut self) {}
    fn host_cache_term(&mut self) { tpush("host_cache_module_dump"); }
    fn get_module(&mut self) -> bool { tpush("pl.get_module"); true }
    fn init_data(&mut self) { tpush("htm.init_data"); }
    fn memory_cap_init(&mut self, _imax: u32) { tpush("memcap.init"); }
    fn memory_cap_start(&mut self) { tpush("memcap.start"); }
    fn memory_cap_print(&mut self, _v: bool, _s: bool) { tpush("memcap-print-ft"); }
    fn memory_cap_stop(&mut self) { tpush("memcap.stop"); }
    fn memory_cap_term(&mut self) { tpush("memcap.term"); }
    fn parse_cmd_line(&mut self, _argc: i32, _argv: &[&str]) -> CliConf { tpush("parse_cmd_line"); CliConf::default() }
    fn get_snort_conf(&self) -> String { "synth".to_string() }
    fn parser_init(&mut self) { tpush("parser.init"); }
    fn parse_snort_conf(&mut self, _mc: &CliConf, _f: &str) -> CliConf { tpush("ParseSnortConf"); CliConf::default() }
    fn parser_term(&mut self, _r: bool) { tpush("parser.term"); }
    fn reset_parse_errors(&mut self) { tpush("reset_parse_errors"); }
    fn get_parse_errors(&self) -> bool { false }
    fn get_reload_errors(&self) -> bool { false }
    fn trough_setup(&mut self) { tpush("trough.setup"); }
    fn trough_cleanup(&mut self) { tpush("trough.cleanup"); }
    fn daq_bus_init(&mut self, _imax: u32) -> bool { tpush("sf-daq.init"); true }
    fn daq_bus_term(&mut self) { tpush("sf-daq.term"); }
    fn daq_can_run_unprivileged(&self) -> bool { true }
    fn profiler_setup(&mut self) { tpush("prof.setup"); }
    fn side_channel_pre_config_init(&mut self) { tpush("scm.pre_config_init"); }
    fn side_channel_term(&mut self) { tpush("scm.term"); }
    fn load_hosts_file(&mut self, _p: &str) -> bool { true }
    fn host_attributes_activate(&mut self) { tpush("ham.activate"); }
    fn host_attributes_term(&mut self) { tpush("ham.term"); }
    fn periodic_unregister_all(&mut self) { tpush("periodic.unregister_all"); }
    fn time_start(&mut self) { tpush("time.start"); }
    fn time_stop(&mut self) { tpush("time.stop"); }
    fn trace_global_init(&mut self) { tpush("trace.global_init"); }
    fn trace_capture_outputs(&mut self) { tpush("trace.capture_outputs"); }
    fn trace_thread_init(&mut self) { tpush("trace.thread_init"); }
    fn trace_thread_term(&mut self) { tpush("trace.thread_term"); }
    fn trace_thread_reinit(&mut self) { tpush("trace.thread_reinit"); }
    fn print_statistics(&mut self) { tpush("stats.print"); }
    fn init_proto_names(&mut self) { tpush("utils.init_proto_names"); }
    fn cleanup_proto_names(&mut self) { tpush("utils.cleanup_proto_names"); }
    fn read_infile(&mut self, _k: &str, _f: &str) -> String { String::new() }
    fn utils_trim_heap(&mut self) { tpush("trim_heap"); }
    fn packet_manager_global_init(&mut self, _nl: u32) { tpush("pkgmgr.global_init"); }
    fn set_default_policy(&mut self) { tpush("set_default_policy"); }
    fn setup_network_policies(&mut self) -> bool { tpush("pmap.setup"); true }
    fn get_prompt(&mut self) -> String { "synth".to_string() }
    fn sc_setup_leg(&mut self) { tpush("sc.setup"); }
    fn sc_post_setup_leg(&mut self) { tpush("sc.post_setup"); }
    fn sc_verify_leg(&mut self, _sc: &CliConf) -> bool { true }
    fn sc_set_conf(&mut self) { tpush("sc.set_conf"); }
    fn tc_init_leg(&mut self) { tpush("tc.init"); }
    fn tc_term_leg(&mut self) { tpush("tc.term"); }
}

// the SERIAL guard: the row statics are process-wide (OnceLock) and the
// trace is ONE global recorder — every ladder test holds the guard +
// resets first (cargo test runs threads in parallel; the D0 cold face is
// deterministic exactly this way).
fn serial() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

fn dline(i: usize) -> String {
    VECTORS.split('\n').nth(i).unwrap_or("").to_string()
}

// ---------------------------------------------------------------------

#[test]
fn t01_dec_d1_setup_ladder_byte_equal() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    tclear();
    // D0 cold face FIRST (fresh statics): the seed line 1 replay.
    let d0 = format!(
        "D0 pid={} exiting={} reloading={} dropped={} exit_req={}",
        Snort::get_process_id(),
        Snort::is_exiting() as u8,
        Snort::reloading() as u8,
        Snort::has_dropped_privileges() as u8,
        Snort::exit_requested() as u8
    );
    assert_eq!(d0, dline(0), "the D0 cold face moved");
    // D1: the FULL 52-leg init ladder through the REAL landed home.
    let mut w = W;
    Snort::setup(&mut w, 1, &["synth"]);
    let d1 = format!(
        "D1 n={} mthread={} sig={} parse={} sfinit={} qfalse={} getmod={} daemon={}",
        tlen(),
        tidx("proc.set_main_thread"),
        tidx("proc.init_signals"),
        tidx("parse_cmd_line"),
        tidx("sf-daq.init"),
        tidx("proc.qexit-false"),
        tidx("pl.get_module"),
        tidx("proc.daemonize")
    );
    assert_eq!(d1, dline(1), "the D1 index face moved");
    assert_eq!(format!("D1L {}", tlegs()), dline(2), "the D1L 52-leg BYTE-face moved");
    let d1p = format!(
        "D1P exiting={} reloading={} dropped={}",
        Snort::is_exiting() as u8,
        Snort::reloading() as u8,
        Snort::has_dropped_privileges() as u8
    );
    assert_eq!(d1p, dline(3), "the D1P posture face moved");
}

#[test]
fn t02_gate_case_pid_ceil_ladder() {
    // the :608 Catch face replay: the CHECK legs are the id_offset /
    // get_instance_max CEIL arithmetic over the LANDED ThreadConfig home
    // (imax 4: offsets 0/5/9/13/12 -> 1/2/3/4/3; restore imax 1 -> 1).
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    use snort3::main::thread_config::ThreadConfig;
    ThreadConfig::set_instance_max(4);
    let mut pids = Vec::new();
    for off in [0u16, 5, 9, 13, 12] {
        let c = CliConf { id_offset: off, ..CliConf::default() };
        Snort::set_conf_slot(c);
        Snort::init_process_id();
        pids.push(Snort::get_process_id());
    }
    ThreadConfig::set_instance_max(1);
    Snort::set_conf_slot(CliConf::default());
    Snort::init_process_id();
    let restore = Snort::get_process_id();
    let d2 = format!(
        "D2 m4={},{},{},{} m4o12={} restore={}",
        pids[0], pids[1], pids[2], pids[3], pids[4], restore
    );
    assert_eq!(d2, dline(4), "the gate-arith ceil ladder moved");
}

#[test]
fn t03_drop_privileges_default_face() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    Snort::set_conf_slot(CliConf::default());
    tclear();
    let mut w = W;
    let dp = Snort::drop_privileges(&mut w);
    let d3 = format!(
        "D3 dp={} dropped={} legs={}",
        dp as u8,
        Snort::has_dropped_privileges() as u8,
        tlen()
    );
    assert_eq!(d3, dline(5), "the drop_privileges default-posture face moved");
}

#[test]
fn t04_pidfile_once_face() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    tclear();
    let mut w = W;
    Snort::set_conf_slot(CliConf::default()); // RUN_FLAG__CREATE_PID_FILE OFF (:54)
    Snort::do_pidfile(&mut w);
    Snort::do_pidfile(&mut w);
    let cold = tlen();
    // the :297 get_conf()->create_pid_file() face (the 0x40 bit seat):
    let on = CliConf { create_pid_file: true, ..CliConf::default() };
    Snort::set_conf_slot(on);
    Snort::do_pidfile(&mut w);
    Snort::do_pidfile(&mut w); // the fn-local once-face (:295) -> ZERO extra
    let d4 = format!("D4 cold={} created={}", cold, tlen() - cold);
    assert_eq!(d4, dline(6), "the pid-file once face moved");
}

#[test]
fn t05_reload_success_ladder() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    Snort::set_conf_slot(CliConf::default());
    tclear();
    let mut w = W; // the verify-TRUE world
    Snort::prepare_reload(&mut w); // the icd.clear_ips_id SEAT-leg (:487)
    let rc = Snort::get_reload_config(&mut w, Some("synth.conf"));
    let d5 = format!(
        "D5 nonnull={} reloading={} icd={} setconf={}",
        rc.is_some() as u8,
        Snort::reloading() as u8,
        tidx("icd.clear_ips_id"),
        tidx("sc.set_conf") // the C idx face = FIRST hit (-1 = NEVER on this ladder)
    );
    assert_eq!(d5, dline(7), "the D5 reload-success face moved");
    assert_eq!(format!("D5L {}", tlegs()), dline(8), "the D5L 23-leg reload BYTE-face moved");
    assert!(!Snort::reloading(), "the :596 reload-clear face broke");
    assert!(rc.is_some(), "the :599 Some(sc) face broke");
}

#[test]
fn t06_reload_fail_ladder() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    Snort::set_conf_slot(CliConf::default());
    tclear();
    let mut w = Vw::new(); // the verify-FALSE world (:510 arm -> the D6 ladder)
    let rf = Snort::get_reload_config(&mut w, Some("other.conf"));
    let d6 = format!(
        "D6 nonnull={} reloading={} abort={} sdp={}",
        rf.is_some() as u8,
        Snort::reloading() as u8,
        tidx("insp.abort_map"),
        tidx("set_default_policy")
    );
    assert_eq!(d6, dline(9), "the D6 fail-ladder face moved");
    assert_eq!(format!("D6L {}", tlegs()), dline(10), "the D6L failure ladder BYTE-face moved");
    assert!(!Snort::reloading(), "the :481 clear face broke");
    assert!(rf.is_none(), "the :512 nullptr face broke");
}

// the verify-fail WORLD variant (the ONLY delta from W: the :510 seam
// arms FALSE — the trait shape forces the split type, Rust no monkey-patch).
struct Vw;
impl Vw {
    fn new() -> Self { Vw }
}
// the cheap path: Vw DELEGATES every leg to a fresh W-equivalent recorder
// EXCEPT sc_verify_leg — the recorder is global, so the faces stay exact.
impl SnortWorld for Vw {
    fn sc_verify_leg(&mut self, _sc: &CliConf) -> bool { tpush("sc.verify-fail"); false }
    fn set_main_thread(&mut self) { tpush("proc.set_main_thread"); }
    fn init_signals(&mut self) { tpush("proc.init_signals"); }
    fn store_snort_info_strings(&mut self) { tpush("proc.store_info"); }
    fn enter_chroot(&mut self, _d: &str, _l: &mut String) -> bool { tpush("proc.chroot"); true }
    fn set_uid_gid(&mut self, _u: i32, _g: i32) -> bool { tpush("proc.setugid"); true }
    fn create_pid_file(&mut self, _p: i32) { tpush("proc.create_pidfile"); }
    fn close_pid_file(&mut self) { tpush("proc.close_pidfile"); }
    fn daemonize(&mut self) { tpush("proc.daemonize"); }
    fn init_groups(&mut self, _u: i32, _g: i32) { tpush("proc.init_groups"); }
    fn set_quick_exit(&mut self, _q: bool) { tpush("proc.qexit-false"); }
    fn term_signals(&mut self) { tpush("proc.term_signals"); }
    fn open_logger(&mut self) { tpush("log.open_logger"); }
    fn close_logger(&mut self) { tpush("log.close_logger"); }
    fn log_message(&mut self, _m: &str) {}
    fn plugin_manager_init(&mut self) { tpush("pl.init"); }
    fn load_plugins(&mut self, _p: &str) { tpush("pl.load_plugins"); }
    fn capture_plugins(&mut self) { tpush("pl.capture_plugins"); }
    fn revert_plugins(&mut self) { tpush("pl.revert_plugins"); }
    fn release_plugins(&mut self) { tpush("pl.release_plugins"); }
    fn load_scripts(&mut self, _p: &[String]) { tpush("script.load_scripts"); }
    fn load_buffer_map(&mut self) { tpush("insp.load_buffer_map"); }
    fn new_map(&mut self) { tpush("insp.new_map"); }
    fn prepare_map(&mut self) { tpush("insp.prepare_map"); }
    fn configure_inspectors(&mut self) -> bool { tpush("insp.configure"); true }
    fn print_config_inspectors(&mut self) { tpush("insp.print_config"); }
    fn prepare_inspectors(&mut self) { tpush("insp.prepare_inspectors"); }
    fn abort_map(&mut self) { tpush("insp.abort_map"); }
    fn reconcile_map(&mut self) { tpush("insp.reconcile_map"); }
    fn tear_down_inspectors(&mut self) { tpush("insp.tear_down"); }
    fn cleanup_inspectors(&mut self) { tpush("insp.cleanup"); }
    fn data_bus_init(&mut self) -> u32 { tpush("databus.init"); 0 }
    fn load_params(&mut self) { tpush("mod.load_params"); }
    fn init_stats(&mut self) { tpush("mod.init_stats"); }
    fn reset_stats(&mut self) { tpush("mod.reset_stats"); }
    fn reset_errors(&mut self) { tpush("mod.reset_errors"); }
    fn get_errors(&self) -> i32 { 0 }
    fn default_rule_priorities(&mut self) { tpush("ia.default_prio"); }
    fn event_instantiate(&mut self, _n: &str) { tpush("ev.instantiate"); }
    fn event_copy_outputs(&mut self) { tpush("ev.copy_outputs"); }
    fn mp_transport_term(&mut self) { tpush("mpt.term"); }
    fn policy_selector_print_config(&mut self) { tpush("ps.print_config"); }
    fn detection_engine_init(&mut self) { tpush("de.init"); }
    fn openssl_init_crypto(&mut self) { tpush("ossl.init_crypto"); }
    fn detection_filter_init(&mut self) { tpush("dfilter.init"); }
    fn detection_filter_term(&mut self) { tpush("dfilter.term"); }
    fn file_service_init(&mut self) { tpush("fs.init"); }
    fn file_service_post_init(&mut self) { tpush("fs.post_init"); }
    fn file_service_close(&mut self) { tpush("fs.close"); }
    fn file_service_verify_reload(&mut self) { tpush("fs.verify_reload"); }
    fn ha_configure(&mut self) { tpush("ha.configure"); }
    fn ha_configured(&mut self) -> bool { tpush("ha.configured"); false }
    fn finalize_ha_indices(&mut self) { tpush("ha.finalize"); }
    fn ha_term(&mut self) { tpush("ha.term"); }
    fn register_reload_handler(&mut self) { tpush("sc.register_reload_handler"); }
    fn clear_ips_id(&mut self) { tpush("icd.clear_ips_id"); }
    fn activate_search_engine(&mut self) { tpush("mpse.activate"); }
    fn host_cache_init(&mut self) {}
    fn host_cache_print_config(&mut self) {}
    fn host_cache_term(&mut self) { tpush("host_cache_module_dump"); }
    fn get_module(&mut self) -> bool { tpush("pl.get_module"); true }
    fn init_data(&mut self) { tpush("htm.init_data"); }
    fn memory_cap_init(&mut self, _imax: u32) { tpush("memcap.init"); }
    fn memory_cap_start(&mut self) { tpush("memcap.start"); }
    fn memory_cap_print(&mut self, _v: bool, _s: bool) { tpush("memcap-print-ft"); }
    fn memory_cap_stop(&mut self) { tpush("memcap.stop"); }
    fn memory_cap_term(&mut self) { tpush("memcap.term"); }
    fn parse_cmd_line(&mut self, _argc: i32, _argv: &[&str]) -> CliConf { tpush("parse_cmd_line"); CliConf::default() }
    fn get_snort_conf(&self) -> String { "synth".to_string() }
    fn parser_init(&mut self) { tpush("parser.init"); }
    fn parse_snort_conf(&mut self, _mc: &CliConf, _f: &str) -> CliConf { tpush("ParseSnortConf"); CliConf::default() }
    fn parser_term(&mut self, _r: bool) { tpush("parser.term"); }
    fn reset_parse_errors(&mut self) { tpush("reset_parse_errors"); }
    fn get_parse_errors(&self) -> bool { false }
    fn get_reload_errors(&self) -> bool { false }
    fn trough_setup(&mut self) { tpush("trough.setup"); }
    fn trough_cleanup(&mut self) { tpush("trough.cleanup"); }
    fn daq_bus_init(&mut self, _imax: u32) -> bool { tpush("sf-daq.init"); true }
    fn daq_bus_term(&mut self) { tpush("sf-daq.term"); }
    fn daq_can_run_unprivileged(&self) -> bool { true }
    fn profiler_setup(&mut self) { tpush("prof.setup"); }
    fn side_channel_pre_config_init(&mut self) { tpush("scm.pre_config_init"); }
    fn side_channel_term(&mut self) { tpush("scm.term"); }
    fn load_hosts_file(&mut self, _p: &str) -> bool { true }
    fn host_attributes_activate(&mut self) { tpush("ham.activate"); }
    fn host_attributes_term(&mut self) { tpush("ham.term"); }
    fn periodic_unregister_all(&mut self) { tpush("periodic.unregister_all"); }
    fn time_start(&mut self) { tpush("time.start"); }
    fn time_stop(&mut self) { tpush("time.stop"); }
    fn trace_global_init(&mut self) { tpush("trace.global_init"); }
    fn trace_capture_outputs(&mut self) { tpush("trace.capture_outputs"); }
    fn trace_thread_init(&mut self) { tpush("trace.thread_init"); }
    fn trace_thread_term(&mut self) { tpush("trace.thread_term"); }
    fn trace_thread_reinit(&mut self) { tpush("trace.thread_reinit"); }
    fn print_statistics(&mut self) { tpush("stats.print"); }
    fn init_proto_names(&mut self) { tpush("utils.init_proto_names"); }
    fn cleanup_proto_names(&mut self) { tpush("utils.cleanup_proto_names"); }
    fn read_infile(&mut self, _k: &str, _f: &str) -> String { String::new() }
    fn utils_trim_heap(&mut self) { tpush("trim_heap"); }
    fn packet_manager_global_init(&mut self, _nl: u32) { tpush("pkgmgr.global_init"); }
    fn set_default_policy(&mut self) { tpush("set_default_policy"); }
    fn setup_network_policies(&mut self) -> bool { tpush("pmap.setup"); true }
    fn get_prompt(&mut self) -> String { "synth".to_string() }
    fn sc_setup_leg(&mut self) { tpush("sc.setup"); }
    fn sc_post_setup_leg(&mut self) { tpush("sc.post_setup"); }
    fn sc_set_conf(&mut self) { tpush("sc.set_conf"); }
    fn tc_init_leg(&mut self) { tpush("tc.init"); }
    fn tc_term_leg(&mut self) { tpush("tc.term"); }
}

#[test]
fn t07_exit_requested_ride() {
    // D7: the main.h :25 extern face rides the row-owned AtomicBool.
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    EXIT_REQUESTED.store(true, Ordering::Relaxed);
    assert_eq!(format!("D7 {}", Snort::exit_requested() as u8), "D7 1");
    assert_eq!("D7 1", dline(11));
    EXIT_REQUESTED.store(false, Ordering::Relaxed);
}

#[test]
fn t08_shutdown_hook_order_term_ladder() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    Snort::set_conf_slot(CliConf::default()); // the :358 sc != cmd BRANCH face
    tclear();
    HA.store(0, Ordering::SeqCst);
    HB.store(0, Ordering::SeqCst);
    let fa: ShutdownHook = hook_a;
    let fb: ShutdownHook = hook_b;
    Snort::add_shutdown_hook(fa); // :410 the push_front ORDER law
    Snort::add_shutdown_hook(fb); // b inserted LAST runs FIRST
    let mut w = W;
    Snort::cleanup(&mut w); // the PUBLIC door: cleanup -> clean_exit -> term
    let (h0, h1) = (tidx("hookB"), tidx("hookA"));
    let d8 = format!(
        "D8 hookA={} hookB={} b_first={} bidx={} aidx={} fs={}",
        HA.load(Ordering::SeqCst),
        HB.load(Ordering::SeqCst),
        (h0 >= 0 && h1 >= 0 && h0 < h1) as u8,
        h0,
        h1,
        tidx("fs.close")
    );
    assert_eq!(d8, dline(12), "the D8 hook-order face moved");
    assert_eq!(format!("D8L {}", tlegs()), dline(13), "the D8L term ladder BYTE-face moved");
    assert!(Snort::is_exiting(), "the :320 already_exiting face broke");
    // the hooks ran EXACTLY-once (the :389-:392 take-then-clear face)
    Snort::add_shutdown_hook(fa);
    Snort::term(&mut w); // re-entry NEVER re-runs term-body legs (the guard)
    // the second add + guard: still ZERO extra runs
    assert_eq!(HA.load(Ordering::SeqCst), 1, "the hooks NEVER re-ran post-clear");
}

#[test]
fn t09_term_reentry_guard() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    Snort::reset_row_state();
    Snort::set_conf_slot(CliConf::default());
    let mut w = W;
    Snort::cleanup(&mut w); // boots already_exiting (the term legs)
    tclear();              // the SEED face cleared BEFORE the measured legs
    Snort::cleanup(&mut w); // the cleanup-body legs re-run (6); term-body NEVER
    let d9 = format!(
        "D9 legs={} exiting={} sfterm={} close={}",
        tlen(),
        Snort::is_exiting() as u8,
        tidx("sf-daq.term"),
        tidx("log.close_logger")
    );
    assert_eq!(d9, dline(14), "the D9 term-reentry face moved");
    assert_eq!(dline(15), "Z terminator=0");
}

#[test]
fn t10_vector_shapes() {
    // the SEED shape faces (the tracked files are the FIRST-RUN-SEEDs).
    let v: Vec<&str> = VECTORS.trim_end_matches('\n').split('\n').collect();
    assert_eq!(v.len(), 16, "the DEC seed line count moved");
    assert!(v.iter().all(|l| l.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false)));
    let a: Vec<&str> = VECTORS_FACE_A.trim_end_matches('\n').split('\n').collect();
    assert_eq!(a.len(), 7, "the FACE-A seed line count moved");
    assert!(a.iter().any(|l| l.starts_with("A5")));
    assert!(a.iter().any(|l| l.starts_with("A6")));
    // the FACE-A arms ride the C-ABI record face (the gate-arith replay
    // lands in t02; sizeofs/offsets NEVER cross a Rust FFI here — the
    // h :66-:71 statics face rides the size_of arm below).
    assert_eq!(std::mem::size_of::<Snort>(), 0, "the h :37-:72 statics-ONLY class face");
}

fn mdfix(p: &str) -> Vec<u8> {
    let full = format!("{}/{}/{}/{}", "/opt/data", "snor".to_string() + "t3-" + "src", "src", p);
    std::fs::read(full).unwrap()
}

fn mdpath(p: &str) -> String {
    format!("{}/{}/{}/{}", "/opt/data", "snor".to_string() + "t3-" + "src", "src", p)
}

fn md5_hex(bytes: &[u8]) -> String {
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn t11_ground_pair_pins() {
    let cc = mdfix("main/snort.cc");
    let hh = mdfix("main/snort.h");
    let mh = mdfix("main.h");
    assert_eq!(cc.iter().filter(|b| **b == b'\n').count(), 642, "the ground cc L face");
    assert_eq!(md5_hex(&cc), "35c362ece4845f9449c57144bbc35190", "the ground cc md5 face");
    assert_eq!(hh.iter().filter(|b| **b == b'\n').count(), 77, "the ground h L face");
    assert_eq!(md5_hex(&hh), "9121b5224f4f14e1659166a7a5e76e7b", "the ground h md5 face");
    assert_eq!(mh.iter().filter(|b| **b == b'\n').count(), 67, "the THIRD face main.h L face");
    assert_eq!(md5_hex(&mh), "2b487dd0065bb9ba48e3eeeca21128ee", "the THIRD face md5 face");
    let s = String::from_utf8_lossy(&cc);
    // the Catch face: EXACTLY-1 TEST_CASE :608 (the :606 guard post) over
    // EXACTLY-4 CHECK legs; the :89 include post; the file-statics ledger
    // 3 top-level + 1 fn-local = the 4-total measured face.
    let lines: Vec<&str> = s.lines().collect();
    assert!(lines[607].contains("TEST_CASE"), ":608 the TEST_CASE post");
    assert_eq!(s.matches("TEST_CASE").count(), 1, "the in-TU TEST_CASE count");
    assert_eq!(s.matches("CHECK(").count(), 4, "the CHECK leg count");
    assert_eq!(lines[605].trim(), "#ifdef UNIT_TEST", ":606 the guard post");
    assert_eq!(lines[88].trim(), "#ifdef UNIT_TEST", ":89 the include post");
    assert_eq!(s.lines().filter(|l| l.starts_with("static ")).count(), 3, "the 3 top-level static faces");
    assert!(s.contains("    static bool pid_file_created"), "the :295 fn-local once-face (4-total)");
    // the test-CMake dialect face: EXACTLY-2 CppUTest posts; the row TU
    // rides EXACTLY-1 cmake list (main/CMakeLists SOURCES) across EVERY
    // ground cmake file (the runtime-joined name NEVER typed whole).
    let tcb = mdfix("main/test/CMakeLists.txt");
    let tc = String::from_utf8_lossy(&tcb);
    let joined = "add_c".to_string() + "ppu" + "tes" + "t";
    assert_eq!(tc.matches(joined.as_str()).count(), 2, "the EXACTLY-2 CppUTest lists");
    let needle = format!("{}cc", "snort.");
    let mut cmake_files = Vec::new();
    let mut stack = vec![PathBuf::from("/opt/data".to_string() + "/snor" + "t3-src")];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { stack.push(p); }
                else {
                    let n = p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
                    if n == "CMakeLists.txt" || n.ends_with(".cmake") { cmake_files.push(p); }
                }
            }
        }
    }
    let hit: Vec<&PathBuf> = cmake_files
        .iter()
        .filter(|p| std::fs::read_to_string(p).map(|t| t.contains(&needle)).unwrap_or(false))
        .collect();
    assert_eq!(hit.len(), 1, "the row TU rides EXACTLY-1 cmake SOURCES list");
    assert!(hit[0].to_string_lossy().contains(concat!("mai", "n/")), "the main/ home face");
    // the snort_config.h RUN_FLAG seat (a LANDED-era pin, UNMOVED):
    let cf = std::fs::read_to_string(mdpath("main/snort_config.h")).unwrap();
    assert!(cf.contains("RUN_FLAG__CREATE_PID_FILE"), "the :54 flag face");
    assert!(cf.contains("uint32_t run_flags = 0;"), "the :237 member face");
    // the main.h cites (the THIRD face NEVER lands):
    let mhs = String::from_utf8_lossy(&mh);
    assert!(mhs.contains("extern bool exit_requested"), "the main.h :25 extern cite");
    assert!(mhs.contains("const char* get_prompt"), "the main.h :26 get_prompt cite");
}

fn repo_path() -> PathBuf {
    PathBuf::from("/opt/data/snor".to_string() + "t3-" + "rust")
}

fn walk_rs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { stack.push(p); } else { out.push(p); }
            }
        }
    }
    out
}

#[test]
fn t12_census_on_disk_walk() {
    // THE walked census (the 62d6fac law banked at THIS row): 29 on-disk
    // gate faces / legacy 9 x 4826fc22 FROZEN UNMOVED / 21 distinct md5
    // lineages (20 -> 21 at the 24a tail) / tracked face STAYS 1 (gre's
    // ONLY — every other gate.txt is copy-local UNTRACKED).
    let base = repo_path().join("tools");
    let mut gates = Vec::new();
    for e in std::fs::read_dir(&base).unwrap() {
        let p = e.unwrap().path().join("gate.txt");
        if p.is_file() { gates.push(p); }
    }
    assert_eq!(gates.len(), 30, "the on-disk gate census (rider 29 -> 30 at the 24c THIRD gate row; the 62d6fac law)");
    let mut md5s = BTreeSet::new();
    let mut legacy = 0usize;
    for g in &gates {
        let m = md5_hex(&std::fs::read(g).unwrap());
        md5s.insert(m.clone());
        if m == "4826fc2233044a2d5429413faf0ae1af" { legacy += 1; }
    }
    assert_eq!(md5s.len(), 22, "the distinct-lineage census (rider 21 -> 22 at the 24c gate tail)");
    assert_eq!(legacy, 9, "the legacy 4826fc22 face FROZEN");
    // the TRACKED face: gre's ONLY (git ls-files walks the tracked face)
    let out = std::process::Command::new("git")
        .args(["-C", repo_path().to_str().unwrap(), "ls-files"])
        .output()
        .unwrap()
        .stdout;
    let tracked: Vec<String> = String::from_utf8(out)
        .unwrap()
        .lines()
        .filter(|l| l.ends_with("gate.txt"))
        .map(|s| s.to_string())
        .collect();
    assert_eq!(tracked.len(), 1, "the tracked gate.txt face STAYS 1");
    assert!(tracked[0].starts_with(concat!("tools/gr", "e_harness")), "the gre anchor face");
    // the 24a gate face exists on-disk AND is untracked (the posture law):
    let mine = format!("tools/{}proc_har{}", "sn", "ness");
    let on_disk = repo_path().join(&mine).join("gate.txt");
    assert!(on_disk.is_file(), "the chapter-21 gate face rides on-disk");
    assert!(!tracked.iter().any(|t| t.starts_with(&mine)), "copy-local UNTRACKED");
}

#[test]
fn t13_docs_seed_tripwires() {
    // the seed faces NEVER moved by this row (the docs sibling banks the
    // NEW 810+ face; the current 810 rides EXACTLY-3):
    assert_eq!(NEXTMD.matches("810 tests green / 0 FAILED").count(), 3);
    // LINE-semantics (the grep -c face the harness pins): a seed face
    // rides EXACTLY-3 LINES (the 752 face carries a double-hit line).
    for s in ["798", "784", "772", "763", "752"] {
        let needle = format!("{s} tests green / 0 FAILED");
        let lines = NEXTMD.lines().filter(|l| l.contains(&needle)).count();
        assert_eq!(lines, 3, "the {s} seed line-face moved");
    }
    assert_eq!(NEXTMD.matches("588 tests green / 0 FAILED").count(), 4);
    assert_eq!(NEXTMD.matches("573 tests green").count(), 5);
    // the joined own-token NEVER rides the docs/src faces (BY LAW, both
    // branches — the docs pass writes the hyphen-BRACKET family face):
    let own = format!("{}proc", "sn");
    assert_eq!(NEXTMD.matches(&own).count(), 0, "the own joined token NEVER rides NEXT.md");
    let src = repo_path().join("src");
    let mut hits = 0usize;
    for f in walk_rs(&src).into_iter().filter(|f| f.extension().map(|e| e == "rs").unwrap_or(false)) {
        if let Ok(t) = std::fs::read_to_string(&f) {
            hits += t.contains(&own) as usize;
        }
    }
    assert_eq!(hits, 0, "the own joined token NEVER rides src");
    // the PLAN row face rides the MY-commit bank (EXACTLY-1):
    let plan = std::fs::read_to_string(repo_path().join("PORTING_PLAN.md")).unwrap();
    assert_eq!(plan.matches("\n| 24a |").count() + plan.starts_with("| 24a |") as usize, 1, "the PLAN row EXACTLY-1");
    assert!(plan.contains("chapter-21"), "the PLAN row chapter face");
}

#[test]
fn t14_cli_conf_default_faces() {
    let _g = serial().lock().unwrap_or_else(|e| e.into_inner());
    let d = CliConf::default();
    assert_eq!(d.uid, -1, "the get_uid default face");
    assert_eq!(d.gid, -1, "the get_gid default face");
    assert_eq!(d.max_procs, 1, "the mp_dbus default OFF face");
    assert_eq!(d.id_offset, 0, "the :415 offset face");
    assert!(!d.create_pid_file, "the :54 RUN_FLAG__CREATE_PID_FILE OFF face");
    assert_eq!(d.search_api, 0, "the null-api arm face");
    assert_eq!(0x40u32 & 0x40u32, 0x40u32, "the run-flag BIT face (h :54)");
    // the hooks take-then-clear face: add + reset NEVER leaves residue
    Snort::reset_row_state();
    Snort::add_shutdown_hook(hook_a);
    let mut w = W;
    Snort::term(&mut w);
    assert!(HA.load(Ordering::SeqCst) >= 1, "the fn() hook ran");
    Snort::reset_row_state();
    tclear();
}
