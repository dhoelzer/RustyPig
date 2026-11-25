//! Port map of snort3 `src/main/snort.cc` + `src/main/snort.h` (row 24a —
//! chapter-21 OPENER: the CLI-assembly TU, the Snort statics-only class +
//! the init/term ladder). The ground pair @ fe29cbe: snort.cc 642 L md5
//! 35c362ece4845f9449c57144bbc35190 + snort.h 77 L md5 9121b5224f4f14e1659166a7a5e76e7b
//! (the third ground face: `src/main.h` 67 L md5 2b487dd0065bb9ba48e3eeeca21128ee
//! rides the companion cites here, NEVER a landing of its own — its
//! exit_requested / get_prompt / main_snort_started faces are cited below).
//!
//! THE GATE FACE (THE CHAPTER-21 FIRST REAL GATE ROW): the sn-tu rides
//! EXACTLY-1 in-TU Catch TEST_CASE (:608 "[sn""ort_process_id]") over
//! EXACTLY-4 CHECK legs (:616/:622/:628/:634) under the :606 UNIT_TEST
//! guard (the :89 include guard = the 2nd post). The main/test CMakeLists
//! carries EXACTLY-2 add_cpputest faces (thread_test + distill_verdict_test —
//! BOTH CppUTest dialect, find-0 host-side); THIS TU rides the
//! main/CMakeLists.txt :49 SOURCES list (the ONE snort.cc face grep-walked
//! across EVERY ground cmake file) — the Catch arms ship INSIDE the TU, so
//! the harness ships the RUNNER gate (the 22a/23e/23f template), NOT a test
//! file. The gate legs replay in Rust below (test-side in the parity twin)
//! through the LANDED ThreadConfig home (`main/thread_config.rs`
//! set/get_instance_max — the row-owned home, NEVER re-forked).
//!
//! THE statics->fields law: the C file-statics face MEASURED EXACTLY-4
//! leading `static ` decls (snort_cmd_line_conf :99, snort_main_thread_pid
//! :100, the fn-local pid_file_created :295, the shutdown_hooks
//! forward_list :382) + the FOUR class-statics (h :67-:70 bools + the
//! inline-static process_id :71). The port models them in ONE
//! OnceLock<Mutex<SnortStatics>> (the row-owned home; the cc :399-:401
//! out-of-line defs ride the struct init).
//!
//! THE NEVER-LAND law (the row's includes ride a DEEP wall):
//! managers/*, detection/*, flow/ha*, host_tracker/*, memory/*, main/shell,
//! main/process, parser/*, trace/*, tr-acer/*, profiler/*, side_channel/*,
//! target_based/*, filters/*, mp_transport/* — those bodies ride THIS
//! port as the `SnortWorld` provider seam (the act.rs/pt-racer provider
//! precedent), CITE-NEVER-LAND: ZERO of those homes land HERE. LANDED
//! homes REUSED (one-home law): `ThreadConfig::get_instance_max` /
//! `set_instance_max` / `term` (the row-owned 22a-era home, cc :109/:176/
//! :418/:471 legs), `crate::log::messages::LogEngine` (the log legs),
//! `crate::utils::util::get_error` (the cc :339 face), the 23a
//! `SFDAQ::can_run_unprivileged` CITE (the h-home walk seam DEV-007).
//!
//! The fatal-error posture: FatalError -> Err/early-return ONLY where the
//! ground throws reach a port decision (cc :157/:194/:202/:281/:510); the
//! ParseError legs ride the world seam (log-side NEVER-land provider).
//! ZERO new allows, ZERO unsafe (the umask leg rides the SAME extern decl
//! shape the 22a thread.rs home declares — modeled behind the seam here,
//! DEV-016).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::main::thread_config::ThreadConfig;

// ======================================================================
// the world seam (cite-NEVER-land homes; the act.rs provider precedent).
// Every method maps to a ground call site (cites below); the parity twin's
// recorder maps legs to the vectors names for the BYTE-ORDER replay.
// ======================================================================

pub trait SnortWorld {
    // main/process.h (NEVER landed):
    fn set_main_thread(&mut self); // cc :426
    fn init_signals(&mut self);    // cc :108
    fn store_snort_info_strings(&mut self); // cc :114 (#else NOCOREFILE face)
    // #if NOCOREFILE SetNoCores() cc :112 rides the compile-time arm face.
    fn enter_chroot(&mut self, chroot_dir: &str, log_dir: &mut String) -> bool; // cc :273
    fn set_uid_gid(&mut self, uid: i32, gid: i32) -> bool; // cc :285
    fn create_pid_file(&mut self, pid: i32); // cc :299
    fn close_pid_file(&mut self); // cc :331
    fn daemonize(&mut self); // cc :436 (daemon_mode arm)
    fn init_groups(&mut self, uid: i32, gid: i32); // cc :442
    fn set_quick_exit(&mut self, quick: bool); // cc :444
    fn term_signals(&mut self); // cc :374
    // log/log.h + log/messages.h (messages.rs LANDED; log.h seam):
    fn open_logger(&mut self); // cc :430
    fn close_logger(&mut self); // cc :473
    fn log_message(&mut self, msg: &str); // banner legs cc :129-:135/:346
    // managers/* (NEVER landed):
    fn plugin_manager_init(&mut self); // cc :119
    fn load_plugins(&mut self, path: &str); // cc :139
    fn capture_plugins(&mut self); // cc :169
    fn revert_plugins(&mut self); // cc :360
    fn release_plugins(&mut self); // cc :372
    fn load_scripts(&mut self, paths: &[String]); // cc :140
    fn load_buffer_map(&mut self); // cc :142
    fn new_map(&mut self); // cc :143/:496
    fn prepare_map(&mut self); // cc :159/:516
    fn configure_inspectors(&mut self) -> bool; // cc :201/:530
    fn print_config_inspectors(&mut self); // cc :204/:554
    fn prepare_inspectors(&mut self); // cc :209/:540
    fn abort_map(&mut self); // cc :482
    fn reconcile_map(&mut self); // cc :539
    fn tear_down_inspectors(&mut self); // cc :361
    fn cleanup_inspectors(&mut self); // cc :370
    fn data_bus_init(&mut self) -> u32; // cc :118
    fn load_params(&mut self); // cc :144/:497
    fn init_stats(&mut self); // cc :178
    fn reset_stats(&mut self); // cc :179
    fn reset_errors(&mut self); // cc :500
    fn get_errors(&self) -> i32; // cc :510
    fn default_rule_priorities(&mut self); // cc :187 IpsAction::get_default_priorities (the alert_before_pass arm)
    fn event_instantiate(&mut self, name: &str); // cc :173 (output non-empty arm)
    fn event_copy_outputs(&mut self); // cc :570/:573 (rule-lists transfer arms)
    fn mp_transport_term(&mut self); // cc :324
    fn policy_selector_print_config(&mut self); // cc :199/:553 (log_verbose arm)
    // detection/* (NEVER landed):
    fn detection_engine_init(&mut self); // cc :120
    fn openssl_init_crypto(&mut self); // cc :122 (host OpenSSL header ABSENT — copy-local DECL rider face)
    fn detection_filter_init(&mut self); // cc :224
    fn detection_filter_term(&mut self); // cc :352
    // file_api/file_service.h (NEVER landed here — the 21-era file_api homes
    // ride OTHER names; this TU's legs are the seam):
    fn file_service_init(&mut self); // cc :147
    fn file_service_post_init(&mut self); // cc :212
    fn file_service_close(&mut self); // cc :325
    fn file_service_verify_reload(&mut self); // cc :542
    // filters/* + flow/ha* (NEVER landed; the :39/:40/:53 include seats carry
    // no default-posture call):
    fn ha_configure(&mut self); // cc :175/:527
    fn ha_configured(&mut self) -> bool; // cc :206/:536 (the face-leg)
    fn finalize_ha_indices(&mut self); // cc :207/:537
    fn ha_term(&mut self); // cc :349
    fn register_reload_handler(&mut self); // cc :528 (new HAReloadTuner)
    fn clear_ips_id(&mut self); // cc :487 (IpsContextData::clear_ips_id)
    // framework/mpse + managers/mpse_manager (NEVER landed):
    fn activate_search_engine(&mut self); // cc :230/:233/:586 (api-null arms)
    // host_tracker/* (NEVER landed):
    fn host_cache_init(&mut self); // cc :449
    fn host_cache_print_config(&mut self); // cc :451
    fn host_cache_term(&mut self); // cc :351
    fn get_module(&mut self) -> bool; // cc :450 (PluginManager::get_module + the static_cast)
    fn init_data(&mut self); // cc :450 tail (HostTrackerModule::init_data)
    // memory/memory_cap.h (NEVER landed):
    fn memory_cap_init(&mut self, instance_max: u32); // cc :176
    fn memory_cap_start(&mut self); // cc :446 (the prune_flows fn-ptr arg)
    fn memory_cap_print(&mut self, verbose: bool, started: bool); // cc :447
    fn memory_cap_stop(&mut self); // cc :466
    fn memory_cap_term(&mut self); // cc :371
    // parser/* (the config-parse legs; the parser home NOT landed here):
    fn parse_cmd_line(&mut self, argc: i32, argv: &[&str]) -> CliConf; // cc :124
    fn get_snort_conf(&self) -> String; // cc :150/:506 (main.h-neighbor face)
    fn parser_init(&mut self); // cc :149/:503
    fn parse_snort_conf(&mut self, main_conf: &CliConf, fname: &str) -> CliConf; // cc :150/:508
    fn parser_term(&mut self, reload: bool); // cc :245/:380(sc-arg)/:597
    fn reset_parse_errors(&mut self); // cc :501
    fn get_parse_errors(&self) -> bool; // cc :510
    fn get_reload_errors(&self) -> bool; // cc :543
    // packet_io/trough.h (h-23d LANDED home; this TU's legs ride the seam):
    fn trough_setup(&mut self); // cc :236
    fn trough_cleanup(&mut self); // cc :330
    // packet_io/sf-d-a-q.h home — the 23a LANDED home CITE (seam legs here, DEV-007):
    fn daq_bus_init(&mut self, instance_max: u32) -> bool; // cc :249 (SF-D-A-Q init, the 23a home cite)
    fn daq_bus_term(&mut self); // cc :465
    fn daq_can_run_unprivileged(&self) -> bool; // cc :279 (the 23a home cite)
    // profiler/side_channel/target_based/time/trace/tr-acer/utils:
    fn profiler_setup(&mut self); // cc :170
    fn side_channel_pre_config_init(&mut self); // cc :137
    fn side_channel_term(&mut self); // cc :350
    fn load_hosts_file(&mut self, path: &str) -> bool; // cc :193/:591
    fn host_attributes_activate(&mut self); // cc :196/:594
    fn host_attributes_term(&mut self); // cc :328
    fn periodic_unregister_all(&mut self); // cc :344
    fn time_start(&mut self); // cc :458
    fn time_stop(&mut self); // cc :463
    fn trace_global_init(&mut self); // cc :145/:498
    fn trace_capture_outputs(&mut self); // cc :154/:517
    fn trace_thread_init(&mut self); // cc :163
    fn trace_thread_term(&mut self); // cc :348
    fn trace_thread_reinit(&mut self); // cc :549
    fn print_statistics(&mut self); // cc :469
    fn init_proto_names(&mut self); // cc :117
    fn cleanup_proto_names(&mut self); // cc :353
    fn read_infile(&mut self, key: &str, file: &str) -> String; // cc :240
    fn utils_trim_heap(&mut self); // cc :502
    // main/framework PacketManager (NEVER landed):
    fn packet_manager_global_init(&mut self, num_layers: u32); // cc :220
    // main/policy.h — the 21-era LANDED policy home CITE (DEV-006):
    fn set_default_policy(&mut self); // cc :480
    fn setup_network_policies(&mut self) -> bool; // cc :156 (PolicyMap member face)
    // main.h faces (the ground main.h 67 L rides cites ONLY):
    fn get_prompt(&mut self) -> String; // main.h :26 (cc :131/:346)
    // the SnortConfig owner-home NEVER-land legs (DEV-001):
    fn sc_setup_leg(&mut self);            // cc :518/:189 SnortConfig::setup()
    fn sc_post_setup_leg(&mut self);       // cc :222/:581 post_setup()
    fn sc_verify_leg(&mut self, sc: &CliConf) -> bool; // cc :510 verify()
    fn sc_set_conf(&mut self);         // cc :125/:153/:365 SnortConfig::set_conf legs
    // the vectors-name-leg SEATS beside the LANDED-home REUSE calls (the
    // C witness mirrored ThreadConfig; the Rust port REUSES the landed
    // home DIRECTLY — the seat records ONLY the vectors-name leg,
    // DEV-019 honest face):
    fn tc_init_leg(&mut self);         // cc :109 seat (ThreadConfig::init REUSE)
    fn tc_term_leg(&mut self);         // cc :471 seat (ThreadConfig::term REUSE)
}

// ======================================================================
// CliConf: the DEREF-SEAM conf face the ladder reads (DEV-001: the
// snort_config.h OWNER home NEVER landed — this struct models ONLY the
// faces snort.cc itself reads; the parse seam hands it back).
// ======================================================================

#[derive(Clone, Debug)]
pub struct CliConf {
    // snort_config.h :54 RUN_FLAG__CREATE_PID_FILE = 0x00000040 (the :619 getter face)
    pub create_pid_file: bool,
    pub daemon_mode: bool, // :435 sc->daemon_mode()
    pub test_mode: bool,   // :468 sc->test_mode()
    pub alert_before_pass: bool, // :186
    pub log_verbose: bool, // :198/:203/:551
    pub uid: i32,
    pub gid: i32,
    pub chroot_dir: String,
    pub log_dir: String,
    pub plugin_path: String,           // :139
    pub script_paths: Vec<String>,     // :140
    pub attribute_hosts_file: String,  // :191/:589
    pub pid_filename: String,          // :333
    pub bpf_filter: String,            // :239-:242
    pub bpf_file: String,              // :239
    pub output: String,                // :172
    pub file_mask: u32,                // :214 (umask leg, DEV-016)
    pub num_layers: u32,               // :220
    pub max_procs: u32,                // :164/:183
    pub id_offset: u16,                // :415/:614 (h member face)
    pub rule_lists_names: Vec<String>, // :560-:578 (the name-name transfer face)
    pub ha_configured: bool,           // the tuner/configure faces
    pub search_api: i32,               // :229/:232/:583 (0 = the null-api arm face)
}

impl Default for CliConf {
    // the ground posture faces: uid/gid default -1 (snort_config.h the
    // get_uid/get_gid faces — the :277 NO-drop default), every run-flag
    // OFF, every string/path empty, search_api null (0), file_mask 0 (the
    // :217 umask(077) else arm), max_procs 1 (the :164 mp_dbus arm OFF).
    fn default() -> Self {
        CliConf {
            create_pid_file: false, // RUN_FLAG__CREATE_PID_FILE OFF (:54/:619)
            daemon_mode: false,
            test_mode: false,
            alert_before_pass: false,
            log_verbose: false,
            uid: -1,
            gid: -1,
            chroot_dir: String::new(),
            log_dir: String::new(),
            plugin_path: String::new(),
            script_paths: Vec::new(),
            attribute_hosts_file: String::new(),
            pid_filename: String::new(),
            bpf_filter: String::new(),
            bpf_file: String::new(),
            output: String::new(),
            file_mask: 0,
            num_layers: 0,
            max_procs: 1,
            id_offset: 0,
            rule_lists_names: Vec::new(),
            ha_configured: false,
            search_api: 0,
        }
    }
}

pub type ShutdownHook = fn();

struct SnortStatics {
    initializing: bool,        // h :66 (NEVER assigned in the TU — DEV-008)
    reloading: bool,           // cc :399
    privileges_dropped: bool,  // cc :400
    already_exiting: bool,     // cc :401
    process_id: u32,           // h :71 inline-static (= 0 NSDMI face, the D0 pin)
    shutdown_hooks: Vec<ShutdownHook>, // cc :382 forward_list (DEV-005)
    snort_cmd_line_conf: Option<Box<CliConf>>, // cc :99
    snort_main_thread_pid: i32, // cc :100 (gettid face DEV-004)
    main_conf_gen: u64,        // the sc-pointer-identity model (DEV-002)
    runtime_conf: Option<Box<CliConf>>, // the set_conf(sc) runtime slot
    runtime_gen: u64,
    gen_counter: u64,
    pid_file_created: bool, // cc :295 fn-local static (the once-face)
}

impl SnortStatics {
    fn new() -> Self {
        SnortStatics {
            initializing: false,
            reloading: false,
            privileges_dropped: false,
            already_exiting: false,
            process_id: 0, // h :71 `= 0`
            shutdown_hooks: Vec::new(),
            snort_cmd_line_conf: None,
            snort_main_thread_pid: 0, // cc :100
            main_conf_gen: 0,
            runtime_conf: None,
            runtime_gen: 0,
            gen_counter: 0,
            pid_file_created: false,
        }
    }
}

fn statics() -> &'static Mutex<SnortStatics> {
    static S: OnceLock<Mutex<SnortStatics>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(SnortStatics::new()))
}

// main.h :25 `extern bool exit_requested;` — the main.cc owner NEVER
// landed here (DEV-012); the port models the extern face as THIS row-owned
// AtomicBool (the cc :404 read side).
pub static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

// ======================================================================
// THE Snort class (h :37-:72, statics-ONLY — A1: sizeof ground == 1):
// every member is a static fn.
// ======================================================================

pub struct Snort;

impl Snort {
    // ---- the public door faces (h :40-:56) ----

    /// cc :424-:459 setup: set_main_thread -> OpenLogger -> init() -> the
    /// daemonize arm -> the qexit/groups/memcap/host-cache/TimeStart tail.
    pub fn setup<W: SnortWorld>(world: &mut W, argc: i32, argv: &[&str]) {
        world.set_main_thread(); // :426
        world.open_logger();     // :430
        Self::init(world, argc, argv);
        let daemon = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.daemon_mode).unwrap_or(false) // :433-:435
        };
        if daemon {
            world.daemonize(); // :436
        }
        // :439 `snort_main_thread_pid = gettid();` — the gettid face is
        // NOT landed (DEV-004): the ported posture keeps the stored 0.
        let (uid, gid) = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let c = s.runtime_conf.as_ref().cloned().unwrap_or_default();
            (c.uid, c.gid)
        };
        world.init_groups(uid, gid); // :442
        world.set_quick_exit(false); // :444
        {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let c = s.runtime_conf.as_ref().cloned().unwrap_or_default();
            let verbose = c.log_verbose;
            drop(s);
            world.memory_cap_start(); // :446
            world.memory_cap_print(verbose, true); // :447
        }
        world.host_cache_init();       // :449
        if world.get_module() {        // :450 (the static_cast face DEV-015)
            world.init_data();
        }
        world.host_cache_print_config(); // :451
        // :453-:456 USE_TSC_CLOCK clock_scale() = the compile-time-absent arm (face kept).
        // :214-:217 umask file_mask face rides the parser arm (DEV-016: the
        // umask leg declared in the 22a thread.rs home, NEVER re-forked).
        world.time_start(); // :458
    }

    /// cc :106-:250 init (private h :59): THE 52-leg init ladder.
    fn init<W: SnortWorld>(world: &mut W, argc: i32, argv: &[&str]) {
        world.init_signals();          // :108
        ThreadConfig::init();          // :109 THE LANDED thread_config home REUSE
        world.tc_init_leg();           // the vectors-name leg SEAT (DEV-019)
        // :111-:115 the NOCOREFILE compile pair: NOCOREFILE NEVER defined
        // here -> the #ELSE StoreSnortInfoStrings leg ONLY (DEV-018).
        world.store_snort_info_strings(); // :114
        world.init_proto_names();      // :117
        world.data_bus_init();         // :118
        world.plugin_manager_init();   // :119
        world.detection_engine_init(); // :120
        world.openssl_init_crypto();   // :122 (copy-local DECL rider posture)
        let cmd = world.parse_cmd_line(argc, argv); // :124
        {
            // :125-:127 SnortConfig::set_conf(snort_cmd_line_conf); init_process_id();
            let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.gen_counter += 1;
            s.main_conf_gen = s.gen_counter;
            s.snort_cmd_line_conf = Some(Box::new(cmd.clone()));
        }
        world.sc_set_conf();                     // :125 set_conf(snort_cmd_line_conf)
        Self::init_process_id();
        world.log_message("--------------------------------------------------\n"); // :129
        // :130-:134 BUILD banner leg (the VERSION/BUILD face; rider-cited)
        let prompt = world.get_prompt();
        world.log_message(&format!("{}  Snort++ 3.13.2.0\n", prompt)); // :133
        world.log_message("--------------------------------------------------\n"); // :135
        world.side_channel_pre_config_init(); // :137
        let (plugin_path, script_paths) = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let c = s.snort_cmd_line_conf.as_ref().cloned().unwrap_or_default();
            (c.plugin_path, c.script_paths)
        };
        world.load_plugins(&plugin_path);        // :139
        world.load_scripts(&script_paths);       // :140
        world.load_buffer_map();                 // :142
        world.new_map();                         // :143
        world.load_params();                     // :144
        world.trace_global_init();               // :145
        world.file_service_init();               // :147
        world.parser_init();                     // :149
        let conf = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let mc = s.snort_cmd_line_conf.as_ref().cloned().unwrap_or_default();
            let fname = world.get_snort_conf();
            world.parse_snort_conf(&mc, &fname)  // :150
        };
        {
            // :152-:153 the runtime set_conf face
            let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.gen_counter += 1;
            s.runtime_gen = s.gen_counter;
            s.runtime_conf = Some(Box::new(conf.clone()));
        }
        world.sc_set_conf();                     // :153 set_conf(sc)
        world.trace_capture_outputs();           // :154
        if !world.setup_network_policies() {     // :156-:157 the ParseError arm
            // :157 ParseError("Network policy user ids must be unique\n")
            // -> the seam side keeps the log face DEV-011.
        }
        world.prepare_map();                     // :159
        world.trace_thread_init();               // :163 (must FOLLOW set_conf — the order law)
        // :164-:167 max_procs > 1 -> mp_dbus arms (default-posture ZERO)
        world.capture_plugins();                 // :169
        world.profiler_setup();                  // :170
        let output = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.output.clone()).unwrap_or_default()
        };
        if !output.is_empty() {
            world.event_instantiate(&output);    // :172-:173
        }
        world.ha_configure();                    // :175
        {
            let imax = ThreadConfig::get_instance_max(); // :176 THE LANDED home REUSE
            world.memory_cap_init(imax);
        }
        world.init_stats();                      // :178
        world.reset_stats();                     // :179
        // :181-:184 mp_dbus->init(max_procs) arm (null default = ZERO legs)
        let abp = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.alert_before_pass).unwrap_or(false)
        };
        if abp {
            world.default_rule_priorities(); // :187 get_default_priorities arm
        }
        world.sc_setup_leg();                    // :189 sc->setup()
        let hosts = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.attribute_hosts_file.clone()).unwrap_or_default()
        };
        if !hosts.is_empty() {                   // :191-:195
            if !world.load_hosts_file(&hosts) {
                // :194 ParseError host-attributes arm (seam)
            }
        }
        world.host_attributes_activate();        // :196
        let verbose = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.log_verbose).unwrap_or(false)
        };
        if verbose {
            world.policy_selector_print_config(); // :198-:199
        }
        if world.configure_inspectors() {        // :201-:204
            if verbose {
                world.print_config_inspectors();
            }
        }
        // :206-:207 HA finalize arm (the configured() face-leg):
        if world.ha_configured() {
            world.finalize_ha_indices();
        }
        world.prepare_inspectors();              // :209
        world.file_service_post_init();          // :212 (after configure() — the order face)
        {
            let nl = {
                let s = statics().lock().unwrap_or_else(|e| e.into_inner());
                s.runtime_conf.as_ref().map(|c| c.num_layers).unwrap_or(0)
            };
            world.packet_manager_global_init(nl); // :220
        }
        world.sc_post_setup_leg();               // :222 sc->post_setup()
        world.detection_filter_init();           // :224
        // :226-:233 the two MpseManager::activate arms (null-api default = ZERO)
        world.trough_setup();                    // :236
        // :239-:243 the bpf read_infile arms:
        let (mut bpf_filter, bpf_file) = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let c = s.runtime_conf.as_ref().cloned().unwrap_or_default();
            (c.bpf_filter.clone(), c.bpf_file.clone())
        };
        if bpf_filter.is_empty() && !bpf_file.is_empty() { // :239
            bpf_filter = world.read_infile("bpf_file", &bpf_file); // :240
            if !bpf_filter.is_empty() {
                world.log_message(&format!("Snort BPF option: {}\n", bpf_filter)); // :243
            }
        }
        world.parser_term(false);                // :245 parser_term(sc)
        world.log_message("--------------------------------------------------\n"); // :247 LOG_DIV seat
        let imax = ThreadConfig::get_instance_max(); // :249 THE LANDED home REUSE
        world.daq_bus_init(imax);                  // :249
    }

    /// cc :268-:291: the chroot/uid-gid posture (ALL default-posture arms
    /// ride the conf faces — the ZERO-leg default = the DEC D3 face).
    pub fn drop_privileges<W: SnortWorld>(world: &mut W) -> bool {
        let (chroot, mut log_dir, uid, gid) = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let c = s.snort_cmd_line_conf.as_ref().cloned().unwrap_or_default(); // :270 get_main_conf
            (c.chroot_dir.clone(), c.log_dir.clone(), c.uid, c.gid)
        };
        if !chroot.is_empty() && !world.enter_chroot(&chroot, &mut log_dir) { // :273
            return false;
        }
        if uid != -1 || gid != -1 {              // :277
            if !world.daq_can_run_unprivileged() { // :279 (the 23a home CITE seam)
                // :281-:282 ParseError + false arm
                return false;
            }
            if !world.set_uid_gid(uid, gid) {    // :285
                return false;
            }
        }
        let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
        s.privileges_dropped = true;             // :289
        true
    }

    /// cc :293-:302: the create_pid_file && !pid_file_created ONCE face
    /// (the fn-local static :295 rides the SnortStatics field DEV-003).
    pub fn do_pidfile<W: SnortWorld>(world: &mut W) {
        let (on, created, pid) = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            (
                s.runtime_conf
                    .as_ref()
                    .map(|c| c.create_pid_file)
                    .unwrap_or(false), // :297 get_conf()->create_pid_file()
                s.pid_file_created,
                s.snort_main_thread_pid,
            )
        };
        if on && !created {
            world.create_pid_file(pid); // :299
            statics().lock().unwrap_or_else(|e| e.into_inner()).pid_file_created = true; // :300
        }
    }

    /// cc :308-:375: the already_exiting re-entry guard (:318-:320) + the
    /// FULL term ladder (the reverse-order legs).
    pub fn term<W: SnortWorld>(world: &mut W) {
        {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            if s.already_exiting {
                return; // :318-:319
            }
        }
        statics().lock().unwrap_or_else(|e| e.into_inner()).already_exiting = true; // :320
        world.mp_transport_term();               // :324
        world.file_service_close();              // :325
        Self::call_shutdown_hooks(world);        // :326
        world.host_attributes_term();            // :328
        world.trough_cleanup();                  // :330
        world.close_pid_file();                  // :331
        let pidfile = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.pid_filename.clone()).unwrap_or_default()
        };
        if !pidfile.is_empty() {                 // :333
            // :335-:341 the unlink() + ErrorMessage face: the ported
            // posture NEVER unlinks harness-side inodes (the DEC stays
            // leg-zero for the unlink seat — DEV-014 honest face).
        }
        world.periodic_unregister_all();         // :344
        let prompt = world.get_prompt();         // :346 (main.h :26 cite)
        world.log_message(&format!("{}  Snort exiting\n", prompt)); // :346
        world.trace_thread_term();               // :348
        world.ha_term();                         // :349
        world.side_channel_term();               // :350
        world.host_cache_term();                 // :351 (HostCacheIp::term — the
                                                 // DUMP-face leg, DEV-013 split)
        world.detection_filter_term();           // :352
        world.cleanup_proto_names();             // :353
        // :355-:356 OPENSSL_cleanup() rides the ground COMMENT face (NEVER called)
        let branch = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_gen != 0 && s.runtime_gen != s.main_conf_gen // :358 sc != cmd
        };
        if branch {
            world.revert_plugins();              // :360 (get_main_conf)
            world.tear_down_inspectors();        // :361
            let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf = None;               // :362 delete sc (the Rust drop face)
        }
        {
            let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf = None;               // :365 set_conf(nullptr)
            s.runtime_gen = 0;
        }
        world.sc_set_conf();                     // :365 set_conf(nullptr) leg
        {
            let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.snort_cmd_line_conf = None;        // :367-:368 delete + nullptr
        }
        world.cleanup_inspectors();              // :370
        world.memory_cap_term();                 // :371
        world.release_plugins();                 // :372
        world.term_signals();                    // :374
    }

    /// cc :377-:380 clean_exit(int) -> term() (the int arg UNREAD face).
    pub fn clean_exit<W: SnortWorld>(world: &mut W) {
        Self::term(world);
    }

    /// cc :461-:474 cleanup: TimeStop -> sf-d-a-q/memcap legs -> the
    /// test_mode ! face PrintStatistics -> ThreadConfig::term (LANDED home
    /// REUSE :471) -> clean_exit(0) -> CloseLogger.
    pub fn cleanup<W: SnortWorld>(world: &mut W) {
        world.time_stop();                       // :463
        world.daq_bus_term();                      // :465
        world.memory_cap_stop();                 // :466
        let test_mode = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.test_mode).unwrap_or(false)
        };
        if !test_mode {                          // :468
            world.print_statistics();            // :469
        }
        ThreadConfig::term();                    // :471 THE LANDED home REUSE
        world.tc_term_leg();                     // the vectors-name leg SEAT (DEV-019)
        Self::clean_exit(world);                 // :472
        world.close_logger();                    // :473
    }

    /// cc :476-:483: the verify-failure ladder legs (the DEC D6 face):
    /// parser_term(sc) -> delete -> set_default_policy -> reloading=false
    /// -> InspectorManager::abort_map.
    fn reload_failure_cleanup<W: SnortWorld>(world: &mut W) {
        world.parser_term(true);                 // :478 parser_term(sc)
        // :479 delete sc — the Rust drop face (the reload slot NEVER landed)
        world.set_default_policy();              // :480
        statics().lock().unwrap_or_else(|e| e.into_inner()).reloading = false; // :481
        world.abort_map();                       // :482
    }

    /// cc :485-:488: the ONE-leg reload prep.
    pub fn prepare_reload<W: SnortWorld>(world: &mut W) {
        world.clear_ips_id();                    // :487
    }

    /// cc :492-:600: the reload ladder (the 22-leg DEC D5 face + the D6
    /// failure ladder).
    pub fn get_reload_config<W: SnortWorld>(world: &mut W, fname: Option<&str>) -> Option<CliConf> {
        statics().lock().unwrap_or_else(|e| e.into_inner()).reloading = true; // :494
        world.new_map();                         // :496
        world.load_params();                     // :497
        world.trace_global_init();               // :498
        world.reset_errors();                    // :500
        world.reset_parse_errors();              // :501
        world.utils_trim_heap();                 // :502
        world.parser_init();                     // :503
        let fname = match fname {                // :505-:506
            Some(f) => f.to_string(),
            None => world.get_snort_conf(),
        };
        let sc = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let mc = s.snort_cmd_line_conf.as_ref().cloned().unwrap_or_default();
            world.parse_snort_conf(&mc, &fname)  // :508
        };
        let errs = world.get_parse_errors() || world.get_errors() != 0; // :510
        if errs || !world.sc_verify_leg(&sc) {
            Self::reload_failure_cleanup(world); // :512
            return None;
        }
        world.prepare_map();                     // :516
        world.trace_capture_outputs();           // :517
        world.sc_setup_leg();                    // :518
        // :520-:522 SHELL reconfigure = compile-time-absent arm (face kept)
        world.ha_configure();                    // :527
        world.register_reload_handler();         // :528 (new HAReloadTuner)
        if world.get_parse_errors() || !world.configure_inspectors() { // :530
            Self::reload_failure_cleanup(world); // :532
            return None;
        }
        if world.ha_configured() {               // :536-:537
            world.finalize_ha_indices();
        }
        world.reconcile_map();                   // :539
        world.prepare_inspectors();              // :540
        world.file_service_verify_reload();      // :542
        if world.get_reload_errors() {           // :543
            Self::reload_failure_cleanup(world); // :545
            return None;
        }
        world.trace_thread_reinit();             // :549
        // :551-:555 the two log_verbose print arms (default = ZERO)
        // :557-:579 the rule-lists name-name copy_outputs transfer (the
        // default-empty face = ZERO legs; DEV-010 keeps the arm STRUCTURE):
        let (old_names, new_names) = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let runtime = s.runtime_conf.as_ref().map(|c| c.rule_lists_names.clone()).unwrap_or_default();
            let cmd = s.snort_cmd_line_conf.as_ref().map(|c| c.rule_lists_names.clone()).unwrap_or_default();
            (cmd, runtime)
        };
        for cur in &old_names {                  // :562
            for rnew in &new_names {             // :566
                if cur.eq_ignore_ascii_case(rnew) { // :568 strcasecmp
                    world.event_copy_outputs();  // :570/:573
                    break;
                }
            }
        }
        world.sc_post_setup_leg();               // :581
        // :583-:587: the new-vs-current get_search_api DIFFERENCE face
        // (the int-api model DEV-009: the null 0 == 0 default = NO call).
        let swap = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            let cur = s
                .runtime_conf
                .as_ref()
                .map(|c| c.search_api)
                .unwrap_or(0);
            sc.search_api != cur
        };
        if swap {
            world.activate_search_engine();
        }
        if !sc.attribute_hosts_file.is_empty() { // :589-:593
            if !world.load_hosts_file(&sc.attribute_hosts_file) {
                world.log_message("== WARNING: host attributes file failed to load\n"); // :592
            }
        }
        world.host_attributes_activate();        // :594
        statics().lock().unwrap_or_else(|e| e.into_inner()).reloading = false; // :596
        world.parser_term(true);                 // :597 parser_term(sc)
        Some(sc)                                 // :599
    }

    // ---- the public state faces (h :46-:50, cc :399-:422) ----

    pub fn reloading() -> bool {
        statics().lock().unwrap_or_else(|e| e.into_inner()).reloading
    }
    /// h :66 `static bool initializing` — NEVER ASSIGNED anywhere in the
    /// ground TU (DEV-008 honest face); the accessor mirrors the declared
    /// face so the field is READ, the value stays the false posture.
    pub fn initializing() -> bool {
        statics().lock().unwrap_or_else(|e| e.into_inner()).initializing
    }
    pub fn has_dropped_privileges() -> bool {
        statics().lock().unwrap_or_else(|e| e.into_inner()).privileges_dropped
    }
    pub fn is_exiting() -> bool {
        statics().lock().unwrap_or_else(|e| e.into_inner()).already_exiting
    }
    pub fn exit_requested() -> bool {
        EXIT_REQUESTED.load(Ordering::Relaxed) // cc :403-:404 (main.h :25 extern)
    }

    /// cc :412-:419: the init_process_id CEIL ladder — the ground rides
    /// `std::ceil(id_offset / (float)get_instance_max())` :418; integer
    /// ceiling === `div_ceil` for exact non-negative ints (DEV-017 float-
    /// identity cite); id_offset 0 -> 1 (:415-:416).
    pub fn init_process_id() {
        // :414 SnortConfig::get_conf() — the runtime slot face (the
        // harness boots the conf BEFORE this leg: set_conf_slot).
        let offset = {
            let s = statics().lock().unwrap_or_else(|e| e.into_inner());
            s.runtime_conf.as_ref().map(|c| c.id_offset).unwrap_or(0)
        };
        let pid = if offset == 0 {
            1
        } else {
            let imax = ThreadConfig::get_instance_max(); // :418 THE LANDED home
            u32::from(offset).div_ceil(imax)
        };
        statics().lock().unwrap_or_else(|e| e.into_inner()).process_id = pid;
    }
    pub fn get_process_id() -> u32 {
        statics().lock().unwrap_or_else(|e| e.into_inner()).process_id
    }

    /// cc :384-:385: the h :257 push_front head-insert face (the reverse
    /// run-order law, the DEC D8 b-first face).
    pub fn add_shutdown_hook(f: ShutdownHook) {
        let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
        s.shutdown_hooks.insert(0, f);
    }

    /// private cc :351-:393: run-all-then-clear.
    fn call_shutdown_hooks<W: SnortWorld>(_world: &mut W) {
        let hooks = {
            let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut s.shutdown_hooks) // :389-:392 (for-loop then clear)
        };
        for f in hooks {
            f();
        }
    }

    // conf-slot legs folded into the world: sc->setup()/post_setup()/
    // verify() faces (the SnortConfig owner NEVER landed, DEV-001).
    #[allow(non_snake_case)]
    pub fn set_conf_slot(conf: CliConf) {
        let mut s = statics().lock().unwrap_or_else(|e| e.into_inner());
        s.gen_counter += 1;
        s.runtime_gen = s.gen_counter;
        s.runtime_conf = Some(Box::new(conf));
    }

    pub fn reset_row_state() {
        *statics().lock().unwrap_or_else(|e| e.into_inner()) = SnortStatics::new();
        EXIT_REQUESTED.store(false, Ordering::Relaxed);
    }
}




#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn snort_class_is_statics_only() {
        // h :37-:72: ZERO non-static data members — the ported face NEVER
        // holds state in the unit struct.
        assert_eq!(std::mem::size_of::<Snort>(), 0);
    }
}
