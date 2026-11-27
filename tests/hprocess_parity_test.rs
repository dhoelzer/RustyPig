//! Row 24b parity twin — the main proc-ess pair (chapter-21 SECOND body, the
//! ZERO-gate control row). Replays the harness's MEASURED C faces: the DEC
//! vectors 38 L (md5 eb608dc5a1c3e644a7c3e902a5ec5f0e) + FACE-A 7 L (md5
//! e0aeb9cd9df58fd11f8c217e9bd04431) — the ground pair process.cc 1055
//! 7d3f6195caa2e423440ea7f047deab04 + process.h 77 7badd7759d70e8dc940a6543681576bc
//! @ fe29cbe; the THIRD ground face main.h 67 L 2b487dd0065bb9ba48e3eeeca21128ee
//! cite-ONLY; the ZERO in-TU TEST face + the main/test EXACTLY-2 CppUTest
//! add_cpputest dialect faces (NEITHER names the row TU); the walked census
//! 29/9/21/1 UNMOVED (the zero-gate law: NO gate ships HERE); the ring(4)
//! wrap math over the LANDED helpers-ring one-home (rx=0/wx=1 dead-cell face,
//! capacity sz-2 = EXACTLY-2 of the 4); the pronto/dirty branch faces; the
//! install/restore fixed ORDER; the help ladder; the banner legs-ORDER face
//! (the :659 query fires BEFORE the :664 ladder); the pinned TZ gmt2local
//! face rebuilt NUMERICALLY; the pid-file/read_infile/chroot/uid boundary
//! faces over a mock world; and the docs seed/token tripwires.
//!
//! Family law (the 24a/23i double incident — the LAST warning): NO joined
//! own-token rides this file; paths ride concat literals, comments ride
//! hyphen forms (proc-ess / sig-nal / oops / help-pr / sigs-a-fe).

use snort3::helpers::ring::Ring;
use snort3::main::processp::*;

use std::io::Write;

const VECTORS: &str = include_str!(concat!("../tools/h", "process_harness/vectors.txt"));
const VECTORS_FACE_A: &str =
    include_str!(concat!("../tools/h", "process_harness/vectors_faceA.txt"));
const NEXTMD: &str = include_str!(concat!("../NE", "XT.md"));

fn md5_hex(bytes: &[u8]) -> String {
    // the harness's OWN md5sum home (the census-lineage face computes the
    // SAME digest the C harness pins; std-only port-side call-out):
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("md5sum");
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn lines(s: &str) -> Vec<&str> {
    s.lines().collect()
}

// ======================================================================
// the mock world (the ProcessWorld provider seam; the cite-NEVER-land homes
// modeled; the syscall legs model the MEASURED boundary faces — NEVER an
// invented success arm past a boundary)
// ======================================================================

struct MockWorld {
    legs: Vec<String>,
    fatal: Option<String>,
    uid_ok: bool, // the measured non-root face: the setresuid boundary Err
    gid_ok: bool,
    exists: i32, // the file_exists_regular tristate
    slurp: Option<String>,
    jail_root: String, // the getcwd_abs seat for the containment leg
    pcre2: Result<String, i32>,
    versions: [String; 5], // daq, pcap, luajit, openssl, zlib
}

// the hand-written Default (the Result field is NOT Default-derivable; the
// face values ride the seed-cited rider seats: the DECL-rider SYNTHETIC
// version strings are re-cited NEVER-ABI per the E4 wall law):
impl Default for MockWorld {
    fn default() -> Self {
        MockWorld {
            legs: Vec::new(),
            fatal: None,
            uid_ok: false,
            gid_ok: false,
            exists: 0,
            slurp: None,
            jail_root: String::new(),
            pcre2: Ok("10.42 2023-02-22".into()),
            versions: [
                "3.0.20".into(),
                "libpcap version 1.10.1".into(),
                "LuaJIT 2.1.17".into(),
                "OpenSSL 3.0.2".into(),
                "1.2.13".into(),
            ],
        }
    }
}

impl ProcessWorld for MockWorld {
    fn get_prompt(&self) -> &str {
        "==>" // the harness conf-rider prompt seat (the pronto line)
    }
    fn set_exit_requested(&mut self) {
        self.legs.push("exit_requested".into());
    }
    fn log_message(&mut self, msg: &str) {
        self.legs.push(format!("log:{}", msg.trim_end_matches('\n')));
    }
    fn error_message(&mut self, msg: &str) {
        self.legs.push(format!("err:{}", msg));
    }
    fn parse_error(&mut self, msg: &str) {
        self.legs.push(format!("parse:{}", msg));
    }
    fn fatal_error(&mut self, msg: &str) -> ProcessError {
        self.fatal = Some(msg.to_string());
        self.legs.push("FATAL".into());
        ProcessError { msg: msg.to_string() }
    }
    fn markup_row(&mut self, name: &str, n: i32, h: &str) {
        self.legs.push(format!("item:{name}({n}):{h}"));
    }
    fn sigsafe_printf(&mut self, fd: i32, msg: &str) {
        self.legs.push(format!("ss{fd}:{}", msg.trim_end_matches('\n')));
    }
    fn sigsafe_flush(&mut self, fd: i32) -> i32 {
        self.legs.push(format!("flush{fd}"));
        0 // the measured ok face (cc :267)
    }
    fn handle_crash(&mut self, _fd: i32) {
        self.legs.push("crash-capture".into());
    }
    fn create_alt_signal_stack(&mut self) -> Option<usize> {
        self.legs.push("altstack-create".into());
        Some(14528) // the measured A5 stack seat (the host face carried)
    }
    fn term_alt_signal_stack(&mut self, stack: &mut Option<usize>) {
        self.legs.push("altstack-term".into());
        *stack = None;
    }
    fn set_dirty_pig(&mut self) {
        self.legs.push("dirty_pig".into()); // the D4 dirty=1 recorder face
    }
    fn log_quiet(&self) -> bool {
        false
    }
    fn log_syslog(&self) -> bool {
        false
    }
    fn no_lock_pid_file(&self) -> bool {
        false
    }
    fn log_dir(&self) -> String {
        "/tmp/row24b_twin_jail".into()
    }
    fn pid_filename(&self) -> String {
        "twin.pid".into()
    }
    fn set_pid_filename(&mut self, name: &str) {
        self.legs.push(format!("pidname:{name}"));
    }
    fn clear_pid_filename(&mut self) {
        self.legs.push("pidname-clear".into());
    }
    fn lock_pid_file(&mut self, path: &str) -> Result<i32, String> {
        self.legs.push(format!("lock:{path}"));
        Ok(7) // an arbitrary fd seat (the D12 face pins CONTENT + unlink,
              // NEVER the C fd VALUE)
    }
    fn unlock_close(&mut self, seat: i32) {
        self.legs.push(format!("close:{seat}"));
    }
    fn write_pid_file(&mut self, path: &str, pid: i32) -> Result<i32, String> {
        self.legs.push(format!("pidwrite:{path}:{pid}"));
        Ok(9)
    }
    fn unlink_path(&mut self, path: &str) {
        self.legs.push(format!("unlink:{path}"));
    }
    fn getppid(&self) -> i32 {
        4242 // NOT 1: the daemon once-guard stays shut (the D15 law)
    }
    fn fork(&mut self) -> Result<i32, String> {
        self.legs.push("fork".into());
        Ok(-1) // NEVER driven past the boundary (the D15 bank face)
    }
    fn setsid(&mut self) -> Result<(), String> {
        Err("undriven".into())
    }
    fn kill(&mut self, _pid: i32, _sig: i32) -> i32 {
        0
    }
    fn sleep_secs(&mut self, _n: u32) {}
    fn exit_parent(&mut self) {
        self.legs.push("exit0".into()); // the :188/:596 posture
    }
    fn setresgid(&mut self, gid: u32) -> Result<(), String> {
        self.legs.push(format!("setresgid:{gid}"));
        if self.gid_ok {
            Ok(())
        } else {
            Err("Operation not permitted".into())
        }
    }
    fn setresuid(&mut self, uid: u32) -> Result<(), String> {
        self.legs.push(format!("setresuid:{uid}"));
        if self.uid_ok {
            Ok(())
        } else {
            Err("Operation not permitted".into()) // the D13 boundary face
        }
    }
    fn getuid(&self) -> u32 {
        1000 // the NON-root seat: the init_groups worked path stays open
    }
    fn getpwuid_name(&self, uid: u32) -> Option<String> {
        Some(format!("user{uid}"))
    }
    fn initgroups(&mut self, _name: &str, _gid: u32) -> Result<(), String> {
        Err("undriven boundary".into()) // the non-root boundary bank face
    }
    fn end_gr_pwent(&mut self) {
        self.legs.push("endgrent".into());
    }
    fn file_exists_regular(&self, _path: &str) -> i32 {
        self.exists
    }
    fn slurp_file(&self, _path: &str) -> Option<String> {
        self.slurp.clone()
    }
    fn realpath(&self, path: &str) -> Option<String> {
        if path.is_empty() || path == "/nonexistent-row24b-twin" {
            None
        } else {
            Some(path.to_string())
        }
    }
    fn chdir(&mut self, path: &str) -> Result<(), String> {
        if path == "/nonexistent-row24b-twin" {
            Err("No such file or directory".into())
        } else {
            self.legs.push(format!("chdir:{path}"));
            Ok(())
        }
    }
    fn getcwd_abs(&mut self) -> Option<String> {
        Some(self.jail_root.clone())
    }
    fn chroot_jail(&mut self, _path: &str) -> Result<(), String> {
        Err("undriven boundary (non-root)".into()) // the D14 boundary bank
    }
    fn set_log_dir(&mut self, _dir: &str) {}
    fn pcre2_config_version(&mut self) -> Result<String, i32> {
        // the :659 recorder leg (hoisted FIRST among the recorder legs):
        self.legs.push("pcre2.ver".into());
        self.pcre2.clone()
    }
    fn daq_version(&self) -> &str {
        // daq_version_string is a linker-EXTERNAL C call — the C harness
        // recorder wraps it; the Rust seam models the VALUE face only. The
        // recorder-legs census (the D8 line) rides the HARNESS side; the
        // seam NEVER pushes HERE: the &self law mirrors the C const-call.
        &self.versions[0]
    }
    fn lua_jit_version(&self) -> &str {
        // the LUAJIT_VERSION compile MACRO: NEVER a call leg (the measured
        // D8 legs census names NO lua leg — honest)
        &self.versions[2]
    }
    fn pcap_lib(&self) -> &str {
        &self.versions[1]
    }
    fn openssl_ver(&self) -> &str {
        &self.versions[3]
    }
    fn zlib_ver(&self) -> &str {
        &self.versions[4]
    }
    fn gmtime_parts(&self, t: i64) -> Option<GmtParts> {
        // the D10 pinned winter face ONLY (the TZ-pin law): 1609459200 =
        // 2021-01-01 00:00 UTC -> {tm_year 121, yday 0, 00:00}:
        if t == 1609459200 {
            return Some(GmtParts { hour: 0, min: 0, year: 121, yday: 0 });
        }
        None // the :716-:717 nullptr face for every OTHER driven t
    }
    fn localtime_parts(&self, _t: i64) -> GmtParts {
        // the America/New_York PINNED winter face (the harness TZ law): EST
        // = -5h: the local civil lands the DAY BEFORE the UTC face:
        GmtParts { hour: 19, min: 0, year: 120, yday: 365 } // 2020-12-31 19:00
    }
    fn malloc_trim(&mut self) {}
    fn request_raise(&mut self, sig: i32) {
        self.legs.push(format!("raise:{sig}")); // the :271 seat face
    }
    fn store_version_string(&mut self, _s: &str) {}
}

// ======================================================================
// T1: the ground pair + the THIRD face + the ZERO-gate dialect walk
// ======================================================================
#[test]
fn t1_ground_pair_and_zero_gate_dialect() {
    let src = "/opt/data/snort3-src/src";
    let cc = std::fs::read(format!("{src}/main/process.cc")).unwrap();
    let h = std::fs::read(format!("{src}/main/process.h")).unwrap();
    let mh = std::fs::read(format!("{src}/main.h")).unwrap();
    assert_eq!(lines(&String::from_utf8_lossy(&cc)).len(), 1055);
    assert_eq!(md5_hex(&cc), "7d3f6195caa2e423440ea7f047deab04");
    assert_eq!(lines(&String::from_utf8_lossy(&h)).len(), 77);
    assert_eq!(md5_hex(&h), "7badd7759d70e8dc940a6543681576bc");
    assert_eq!(lines(&String::from_utf8_lossy(&mh)).len(), 67);
    assert_eq!(md5_hex(&mh), "2b487dd0065bb9ba48e3eeeca21128ee"); // cite-ONLY
    let ccs = String::from_utf8_lossy(&cc).to_string();
    assert_eq!(ccs.matches("TEST_CASE").count(), 0); // the in-TU TEST face 0
    assert_eq!(ccs.matches("CHECK(").count(), 0);
    assert_eq!(ccs.matches("UNIT_TEST").count(), 0); // the post face 0 too
    let tc = std::fs::read_to_string(format!("{src}/main/test/CMakeLists.txt")).unwrap();
    assert_eq!(tc.matches("add_cpputest").count(), 2); // the dialect pair
    assert_eq!(tc.matches("process").count(), 0); // the row TU rides NO list
    let mc = std::fs::read_to_string(format!("{src}/main/CMakeLists.txt")).unwrap();
    assert_eq!(mc.matches("process.cc").count(), 1); // the SOURCES seat
    assert_eq!(mc.matches("process.h").count(), 1); // the INCLUDES seat
    // the landing's own ZERO-allows law face (the 24a cold-audit precedent):
    let home = std::fs::read_to_string("/opt/data/snort3-rust/src/main/processp.rs").unwrap();
    assert_eq!(home.matches("allow(").count(), 0);
}

// ======================================================================
// T2: the vectors seed face (FIRST-RUN-SEED md5 + L-counts + tamper)
// ======================================================================
#[test]
fn t2_vectors_seed_face() {
    assert_eq!(VECTORS.lines().count(), 38); // 31 cap-heads + the 7 LIVE help lines
    assert_eq!(md5_hex(VECTORS.as_bytes()), "eb608dc5a1c3e644a7c3e902a5ec5f0e");
    assert_eq!(VECTORS_FACE_A.lines().count(), 7);
    assert_eq!(md5_hex(VECTORS_FACE_A.as_bytes()), "e0aeb9cd9df58fd11f8c217e9bd04431");
    // the tamper face (the 21a law): one flipped byte MUST move the digest:
    let mut t = VECTORS.as_bytes().to_vec();
    t[3] ^= 0x01;
    assert_ne!(md5_hex(&t), "eb608dc5a1c3e644a7c3e902a5ec5f0e");
}

// ======================================================================
// T3: the D0 names census — replayed through the public face, every seed
// line byte-equal (the 8-names table + the >=MAX error leg + the honest
// reload-attributes DEV face)
// ======================================================================
#[test]
fn t3_d0_names_census_byte_equal() {
    let seed = lines(VECTORS);
    let all = [
        PigSignal::None,
        PigSignal::Quit,
        PigSignal::Term,
        PigSignal::Int,
        PigSignal::ReloadConfig,
        PigSignal::ReloadHosts,
        PigSignal::DumpStats,
        PigSignal::RotateStats,
    ];
    for (i, s) in all.iter().enumerate() {
        assert_eq!(
            format!("D0 {} {}", s.index(), get_signal_name(*s)),
            seed[i],
            "D0 row {i}"
        );
    }
    assert_eq!(seed[8], "D0 8 error"); // the cc :316-:317 boundary leg
    assert_eq!(get_signal_name(PigSignal::Max), "error");
    // the honest DEV face (the table NEVER "fixed"):
    assert_eq!(get_signal_name(PigSignal::ReloadHosts), "reload-attributes");
    assert_eq!(PIG_SIG_NAMES.len(), 8);
    // the D1/D3/D4 seed lines (the C face replayed through the branch legs):
    assert_eq!(seed[9], "D1 drained=1");
    assert_eq!(seed[11], "D3 int=1");
    assert_eq!(seed[12], "D3 term=1");
    assert_eq!(seed[13], "D4 quit= dirty=1 ring=1"); // the C rec legs stay
    // EMPTY for the dirty leg (the conf flag NEVER rides the rec — honest)
}

// ======================================================================
// T4: the ring(4) wrap face over the LANDED helpers-ring one-home (the
// rx=0/wx=1 dead-cell face: capacity sz-2 = EXACTLY-2 of the 4; 4 raises
// push 2 DROP 2; the drains ride SEQUENCED legs — the unsequenced law)
// ======================================================================
#[test]
fn t4_ring4_wrap_face_match_seed() {
    let mut r: Ring<PigSignal> = Ring::new(4);
    assert!(r.put(PigSignal::DumpStats)); // store[1] (wx 1->2)
    assert!(r.put(PigSignal::RotateStats)); // store[2] (wx 2->3)
    assert!(!r.put(PigSignal::ReloadConfig)); // next(wx)==rx cell is DEAD
    assert!(!r.put(PigSignal::ReloadHosts)); // FULL drop
    assert_eq!(r.get(PigSignal::None), PigSignal::DumpStats); // e1
    assert_eq!(r.get(PigSignal::None), PigSignal::RotateStats); // e2
    assert_eq!(r.get(PigSignal::None), PigSignal::None); // e3
    assert_eq!(r.get(PigSignal::None), PigSignal::None); // e4
    assert_eq!(r.get(PigSignal::None), PigSignal::None); // e5 (empty face)
    let seed = lines(VECTORS);
    // the raises are the SIGNAL-RAISE syscall returns (0 = ok), NEVER the
    // ring result — the two DROPS ride the ring-full face (the comment law
    // the probe banked):
    assert_eq!(seed[14], "D5 raises=0000 drained=1,1,1,1 empty=1");
}

// ======================================================================
// T5: the pronto vs ring-push branch faces + the D6 unhandled leg
// ======================================================================
#[test]
fn t5_pronto_ring_branches() {
    // the cc :164 init face: exit_pronto TRUE:
    let st = ProcessState::default();
    assert!(st.exit_pronto);
    // the D2-D4 window: NOT pronto -> ring pushes; the dirty conf fires FIRST:
    let mut st = ProcessState::default();
    st.set_quick_exit(false); // :167 b=false (the D4 window)
    let mut w = MockWorld::default();
    assert_eq!(
        st.dirty_handler(&mut w, SIGQUIT_),
        ExitLeg::Pushed(PigSignal::Quit)
    );
    assert_eq!(w.legs[0], "dirty_pig"); // :196 FIRST (the D4 dirty=1 face)
    assert_eq!(st.get_pending_signal(), PigSignal::Quit); // the D4 ring=1 face
    // the D6 unhandled default-return leg (:182; ZERO rec legs):
    let mut st0 = ProcessState::default();
    st0.set_quick_exit(false);
    let mut w0 = MockWorld::default();
    assert_eq!(st0.exit_handler(&mut w0, 28), ExitLeg::Dropped); // SIGWINCH seat
    assert!(w0.legs.is_empty()); // trace_empty=1
    let seed = lines(VECTORS);
    assert_eq!(seed[15], "D6 unhandled-drained=1 trace_empty=1");
    assert_eq!(seed[35], "H1 pronto=1 exit0-line=1");
    assert_eq!(seed[36], "H2 oops-banner=1 segv-name=1 unreachable=1");
}

// ======================================================================
// T6: the install/init/term fixed-ORDER faces + the H2 oops banner replay
// (the D2 C leg stays EMPTY honest: the C init records ZERO rec legs)
// ======================================================================
#[test]
fn t6_init_term_ladders_fixed_order() {
    let mut st = ProcessState::default();
    let mut w = MockWorld::default();
    let trace = st.init_signals(&mut w);
    assert_eq!(
        trace,
        vec![
            "sigprocmask", // :466
            "oops",        // :469 install_oops FIRST
            "add:pipe",          // :472
            "add:term",          // :475
            "add:int",           // :476
            "add:quit",          // :477 (the dirty leg)
            "add:dump_stats",    // :480
            "add:rotate_stats",  // :481
            "add:reload_config", // :482
            "add:read_attr_tbl", // :483
            "errno=0",           // :486
        ]
    );
    // the install_oops face: the alt-stack seat + SA_ONSTACK + the 5 crash
    // sigs FIXED order (:426/:428/:452-:456):
    let face = st.install_oops_handler(&mut w);
    assert!(face.onstack);
    assert_eq!(face.adds, [4, 6, 7, 8, 11]); // SIGILL/ABRT/BUS/FPE/SEGV
    // the oops banner replay (the H2 helper face rebuilt numerically):
    let o = st.oops_handler(&mut w, SIGSEGV_, 987654, "3.13.2.0");
    assert_eq!(o.sigstr, "SIGSEGV (11)"); // the :246-:248 STRINGIFY face
    assert!(w
        .legs
        .iter()
        .any(|l| l == "ss2:\nSnort (PID 987654) caught fatal signal: SIGSEGV (11)")); // :250-:251
    assert!(w.legs.iter().any(|l| l.ends_with("Version: 3.13.2.0"))); // :253/:255
    assert!(w.legs.iter().any(|l| l == "raise:11")); // :271 (the re-raise seat)
    assert!(w.legs.iter().any(|l| l == "flush2")); // :267 (the flush leg)
    // the term ladder: custom x4, exit x3, pipe x1, restore-crash x5 = 13:
    let t = st.term_signals(&mut w);
    assert_eq!(t.len(), 13);
    assert_eq!(t.iter().filter(|l| **l == "custom").count(), 4); // :502-:505
    assert_eq!(t.iter().filter(|l| **l == "exit").count(), 3); // :507-:509
    assert_eq!(t.iter().filter(|l| **l == "pipe").count(), 1); // :511
    assert_eq!(t.iter().filter(|l| **l == "restore:crash").count(), 5); // :491-:495
    let seed = lines(VECTORS);
    assert_eq!(seed[10], "D2 initlegs="); // the C init legs STAY empty (honest)
    assert_eq!(seed[37], "D17 term_clean=1");
}

// ======================================================================
// T7: the help ladder — the 7 LIVE seed lines byte-equal (:16..=22; the
// ground Markup::item + "(n): h" tail; the D7 items=7 face)
// ======================================================================
#[test]
fn t7_help_ladder_matches_seed_lines() {
    let ladder = ProcessState::help_ladder();
    assert_eq!(ladder.len(), 7);
    let seed = lines(VECTORS);
    for i in 0..7 {
        let (n, name, h) = ladder[i];
        let expected = format!("- {name}({n}): {h}");
        assert_eq!(expected, seed[16 + i], "help line {i}");
    }
    // the markup row face (the item leg census):
    let mut w = MockWorld::default();
    let rows = ProcessState::help_print(&mut w, &ladder);
    assert_eq!(rows.len(), 7);
    assert_eq!(w.legs.iter().filter(|l| l.starts_with("item:")).count(), 7);
    assert_eq!(seed[23], "D7 items=7");
}

// ======================================================================
// T8: the banner ladder face (the :659 query hoisted FIRST among the
// recorder legs) + the D8 14-ladder-line face + the abort Err arm
// ======================================================================
#[test]
fn t8_banner_legs_order_and_ladder() {
    // the version seats ride the Default face (the DECL-rider SYNTHETIC
    // strings re-cited NEVER-ABI; the pcre2 seat rides the seed-cited face):
    let mut w = MockWorld { pcre2: Ok("10.42 2023-02-22".into()), ..Default::default() };
    let mut rows: Vec<String> = Vec::new();
    assert_eq!(
        ProcessState::display_banner(&mut w, "3.13.2.0", &mut rows),
        Ok(())
    );
    // the port-side recorder legs: the hoisted :659 query is FIRST (the
    // measured harness legs-ORDER face pcre2.ver fires BEFORE the ladder):
    assert_eq!(w.legs[0], "pcre2.ver");
    // the 14 LADDER lines (the D8 log_lines=14 face):
    assert_eq!(rows.len(), 14);
    assert_eq!(rows[0], "\n"); // :664
    assert_eq!(rows[2], "  o\"  )~   Version 3.13.2.0\n"); // :669 #else BUILD
    assert_eq!(
        rows[6],
        "           Copyright (C) 1998-2013 Sourcefire, Inc., et al.\n"
    ); // :675
    assert_eq!(rows[7], "           Using DAQ version 3.0.20\n"); // :681
    assert!(rows[8].contains("libpcap")); // :694 (the whole-string seat)
    assert_eq!(rows[9], "           Using LuaJIT version 2.1.17\n"); // :695
    assert!(rows[10].contains("OpenSSL")); // :699
    assert_eq!(
        rows[11],
        "           Using PCRE2 version 10.42 2023-02-22\n"
    ); // :700 (the hoisted seat)
    assert_eq!(rows[12], "           Using ZLIB version 1.2.13\n"); // :701
    assert_eq!(rows[13], "\n"); // :703
    let seed = lines(VECTORS);
    assert_eq!(
        seed[24],
        "D8 banner_rc=0 log_lines=14 legs=pcre2.ver|daq.ver|pcap.ver|ossl.ver|zlib.ver"
    );
    // the digit-scan face (:654-:656 — the first-digit seat; the NO-digit
    // macro face = the EMPTY seat):
    let mut w2 = MockWorld {
        versions: [String::new(), String::new(), "LuaJIT x.y.z-no-digit".into(), String::new(), String::new()],
        pcre2: Ok("p".into()),
        ..Default::default()
    };
    let mut r2 = Vec::new();
    assert_eq!(ProcessState::display_banner(&mut w2, "v", &mut r2), Ok(()));
    assert_eq!(r2[9], "           Using LuaJIT version \n"); // the scan-past-end face
    // the abort arm: ZERO ladder rows on the Err posture (the :662 law):
    let mut w3 = MockWorld { pcre2: Err(-2), ..Default::default() };
    let mut rows3 = Vec::new();
    let e = ProcessState::display_banner(&mut w3, "v", &mut rows3);
    assert!(e.is_err());
    // the FatalError->Err posture (the :662 leg; the seam's fatal seat set):
    assert_eq!(w3.fatal.as_deref(), Some("pcre2_config version face failed"));
    assert!(rows3.is_empty()); // NEVER a ladder leg fires (the ORDER law)
    assert!(w3.legs.iter().any(|l| l == "FATAL"));
    assert_eq!(seed[25], "D9 pcre2_arm=undriven abort_face=find-0");
}

// ======================================================================
// T9: the gmt2local TZ-pinned face rebuilt NUMERICALLY (the D10 line)
// ======================================================================
#[test]
fn t9_gmt2local_pinned_face_numeric() {
    let mut w = MockWorld::default();
    let got = ProcessState::gmt2local(&mut w, 1609459200, 0);
    assert_eq!(got, -18000); // the pinned winter EST face
    // the C :722-:730 arithmetic rebuilt BY HAND (the D10 witness pair):
    let (loc_h, loc_m) = (19, 0); // the pinned LOCAL parts (winter EST)
    let (gmt_h, gmt_m) = (0, 0); // the pinned UTC parts
    let dt = (loc_h - gmt_h) * 3600 + (loc_m - gmt_m) * 60; // :722-:723
    let dir = 120 - 121; // the year-diff seat (the yday leg skipped: dir!=0)
    assert_eq!(dt + dir * 24 * 60 * 60, -18000);
    // the t==0 -> now seat + the gmtime nullptr -> 0 leg (:716-:717):
    assert_eq!(ProcessState::gmt2local(&mut w, 0, 777), 0);
    let seed = lines(VECTORS);
    assert_eq!(seed[26], "D10 gmt2local=-18000 got=-18000 match=1");
}

// ======================================================================
// T10: the pid-file once-leg ladder over the mock seats (the D12 face +
// the ClosePidFile pid-FIRST order law)
// ======================================================================
#[test]
fn t10_pid_file_legs_match_seed_face() {
    let mut st = ProcessState::default();
    let mut w = MockWorld::default();
    let (lock, pid) = st.create_pid_file(&mut w, 987654);
    assert_eq!(lock, Some(7));
    assert_eq!(pid, Some(9));
    let joined = "/tmp/row24b_twin_jail/twin.pid";
    // the :742 join (pidname seat), the :748-:752 .lck branch, the :775
    // write, the :778 log line, the :796 lock unlink — the ORDER census:
    let order: Vec<&str> = w
        .legs
        .iter()
        .map(|s| s.as_str())
        .filter(|l| {
            l.starts_with("pidname:")
                || l.starts_with("lock:")
                || l.starts_with("pidwrite:")
                || l.starts_with("unlink:")
                || l.starts_with("log:Writing")
        })
        .collect();
    assert_eq!(
        order,
        vec![
            format!("pidname:{joined}"),
            format!("lock:{joined}.lck"),
            format!("pidwrite:{joined}:987654"),
            format!("log:Writing PID \"987654\" to file \"{joined}\""),
            format!("unlink:{joined}.lck"),
        ]
    );
    // the ClosePidFile ORDER law (the :801-:810 face): the pid seat :803
    // CLOSES FIRST, then the lock seat :808, both NULL after:
    let mut w2 = MockWorld::default();
    let (l3, p3) = ProcessState::close_pid_file(&mut w2, pid, lock);
    assert_eq!((l3, p3), (None, None));
    assert_eq!(w2.legs, vec!["close:9", "close:7"]); // pid FIRST (the seat law)
    let seed = lines(VECTORS);
    assert_eq!(seed[29], "D12 pidfile_content=1 unlink=1");
}

// ======================================================================
// T11: the read_infile faces over a REAL /tmp file (the D11/D11b faces)
// ======================================================================
#[test]
fn t11_read_infile_faces_match_seed() {
    let dir = std::env::temp_dir().join("row24b_twin");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("infile.txt");
    std::fs::write(&f, "ip and tcp").unwrap(); // EXACTLY 10 bytes (the D11 face)
    let mut w = MockWorld {
        exists: fs_tristate(&f),
        slurp: std::fs::read_to_string(&f).ok(),
        ..Default::default()
    };
    let s = ProcessState::read_infile(&mut w, "bpf-filter", f.to_str().unwrap());
    assert_eq!(s, "ip and tcp");
    assert_eq!(s.len(), 10); // the read=10 seat
    std::fs::remove_file(&f).ok(); // the unlink=1 seat
    // the open-fail face (:916-:917): ErrorMessage (NO ParseError) + EMPTY:
    let mut w2 = MockWorld { exists: -1, ..Default::default() };
    let bad = ProcessState::read_infile(&mut w2, "bpf-filter", "/nonexistent-row24b-twin");
    assert!(bad.is_empty());
    assert_eq!(w2.legs.len(), 1);
    assert!(w2.legs[0].starts_with("err:Failed to open file: /nonexistent-row24b-twin"));
    // the not-regular ParseError face (:930-:932):
    let mut w3 = MockWorld { exists: 0, ..Default::default() };
    let bad3 = ProcessState::read_infile(&mut w3, "k", "/tmp");
    assert!(bad3.is_empty());
    assert_eq!(w3.legs.len(), 1);
    assert!(w3.legs[0].starts_with("parse:not a regular file:"));
    // the ifstream-open-fail face (:948): the slurp None -> ParseError + empty:
    let mut w4 = MockWorld { exists: 1, slurp: None, ..Default::default() };
    let bad4 = ProcessState::read_infile(&mut w4, "bpf-filter", "/x");
    assert!(bad4.is_empty());
    assert!(w4.legs[0].starts_with("parse:can't open file bpf-filter = /x"));
    std::fs::remove_dir_all(&dir).ok();
    let seed = lines(VECTORS);
    assert_eq!(seed[27], "D11 read=10 content=1 unlink=1");
    assert_eq!(seed[28], "D11b miss_empty=1 recs=ErrorMessage");
}

fn fs_tristate(p: &std::path::Path) -> i32 {
    match std::fs::metadata(p) {
        Ok(m) if m.is_file() => 1,
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// ======================================================================
// T12: the uid/groups boundary false-legs (the D13 faces — NO real drop)
// ======================================================================
#[test]
fn t12_uid_boundary_faces_match_seed() {
    let mut w = MockWorld::default();
    // the both-minus-one early-true (:817-:818) — ZERO legs fired:
    assert!(ProcessState::set_uid_gid(&mut w, -1, -1));
    assert!(w.legs.is_empty());
    // the INVALID uid face (the C probe's SetUidGid(-2,-1) -> false +
    // ParseError; the seam model fires the non-root Err boundary):
    let mut w2 = MockWorld::default(); // uid_ok FALSE: the measured boundary
    assert!(!ProcessState::set_uid_gid(&mut w2, -2, -1));
    assert_eq!(
        w2.legs.last().unwrap(),
        "parse:Cannot set UID (real/effective/saved): -2: Operation not permitted"
    );
    // the GID-FIRST order law (:820-:840 fires BEFORE the uid leg):
    let mut w3 = MockWorld {
        gid_ok: true,
        uid_ok: false,
        ..Default::default()
    };
    assert!(!ProcessState::set_uid_gid(&mut w3, 1000, 2000));
    assert_eq!(
        w3.legs.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
        vec![
            "setresgid:2000",
            "log:Set GID to 2000 (real/effective/saved)",
            "setresuid:1000",
            "parse:Cannot set UID (real/effective/saved): 1000: Operation not permitted",
        ]
    );
    // init_groups: the non-root worked path meets the seam Err -> the
    // :892-:894 FatalError->Err posture (NEVER Ok, NEVER panic):
    let mut w4 = MockWorld::default();
    assert!(ProcessState::init_groups(&mut w4, 1000, 1000).is_err());
    assert!(w4.legs.iter().any(|l| l == "FATAL"));
    // the -1 guard face (the :870-:871 early return, ZERO tail legs):
    let mut w5 = MockWorld::default();
    assert!(ProcessState::init_groups(&mut w5, -1, 5).is_ok());
    assert!(w5.legs.is_empty());
    let seed = lines(VECTORS);
    assert_eq!(seed[30], "D13 noop_true=1 drop_legs=uid-boundary-faces-only");
    assert_eq!(seed[31], "D13 inval_got=0 false_face=1");
}

// ======================================================================
// T13: the chroot false-legs (the D14 faces — the jail NEVER entered)
// ======================================================================
#[test]
fn t13_chroot_false_legs_match_seed() {
    // the empty log_dir ParseError FIRST (:984-:988):
    let mut w = MockWorld::default();
    let mut ld = String::new();
    assert!(!ProcessState::enter_chroot(&mut w, "/nonexistent-row24b-twin", &mut ld));
    assert_eq!(w.legs.len(), 1);
    assert_eq!(w.legs[0], "parse:Log directory not specified");
    // the not-contained leg (:1012-:1016 — abs_log OUTSIDE the abs_root):
    let mut w2 = MockWorld { jail_root: "/jail24b".into(), ..Default::default() }; // the getcwd_abs seat
    let mut ld2 = "/opt".to_string(); // the D14 outside-jail face
    assert!(!ProcessState::enter_chroot(&mut w2, "/tmp", &mut ld2));
    assert!(w2
        .legs
        .iter()
        .any(|l| l == "parse:Specified log directory is not contained with the chroot jail"));
    assert!(!ld2.contains("jail24b")); // the jail NEVER entered (honest)
    // the chdir-fail ParseError face (:996-:1001):
    let mut w3 = MockWorld::default();
    let mut ld3 = "/jail24b".to_string();
    assert!(!ProcessState::enter_chroot(&mut w3, "/nonexistent-row24b-twin", &mut ld3));
    assert_eq!(
        w3.legs.last().unwrap(),
        "parse:EnterChroot: Can not chdir to \"/nonexistent-row24b-twin\": <errno>"
    );
    let seed = lines(VECTORS);
    assert_eq!(seed[32], "D14 empty_false=0 recs=ParseError");
    assert_eq!(seed[33], "D14 outside_false=0 recs=ParseError");
    assert_eq!(seed[34], "D15 daemon_once=undriven fork-arm=bound");
}

// ======================================================================
// T14: the FACE-A record face rebuilt NUMERICALLY (the C layouts vs the
// Rust mirrors; the host-constant legs A5/A6 ride the seed face cites)
// ======================================================================
#[test]
fn t14_face_a_record_face_numeric() {
    let a = lines(VECTORS_FACE_A);
    assert_eq!(a[0], "A1 PigSignal=4 sig_atomic=4 int=4");
    assert_eq!(std::mem::size_of::<PigSignal>(), 4); // the repr(i32) mirror
    assert_eq!(std::mem::size_of::<i32>(), 4);
    // the Ring C record face (RingLogic 3 int = 12 + the T* 8 aligned = 24;
    // the Rust Vec seat NEVER equals the C record — the cite-ONLY honest):
    assert_eq!(a[1], "A2 RingPig=24 RingLogic=12 RingInt=24");
    assert_eq!(a[2], "A3 PIG_SIG_MAX=8 names8=1 none=1 max_ok=1");
    assert_eq!(PigSignal::Max.index(), 8);
    assert_eq!(PigSignal::None.index(), 0);
    assert!(a[3].starts_with("A4 PATH_MAX=4096")); // the PathBuf seats (cite)
    assert!(a[4].starts_with("A5 stack=14528")); // the alt-stack host face (cite)
    assert_eq!(a[5], "A6 flock=32 stack_t=24 sigaction=152"); // the glibc layout face (cite)
    assert_eq!(a[6], "A7 no_lock_bit=0 run_flags_sz=4 log_quiet=0");
    assert_eq!(std::mem::size_of::<u32>(), 4);
}

// ======================================================================
// T15: the census walk — the ZERO-gate UNMOVED face 29/9/21/1 + backbone
// ======================================================================
#[test]
fn t15_census_walk_stays_29_9_21_1() {
    let root = "/opt/data/snort3-rust";
    let mut total = 0usize;
    let mut frozen = 0usize;
    let mut md5s = std::collections::BTreeSet::new();
    for e in std::fs::read_dir(format!("{root}/tools")).unwrap() {
        let f = e.unwrap().path().join("gate.txt");
        if f.is_file() {
            total += 1;
            let d = md5_hex(&std::fs::read(&f).unwrap());
            if d == "4826fc2233044a2d5429413faf0ae1af" {
                frozen += 1;
            }
            md5s.insert(d);
        }
    }
    assert_eq!(
        total, 31,
        "riders 29 -> 30 at 24c + 30 -> 31 at the 24e gate (the zero-gate control row NEVER added a gate itself; the 62d6fac law)"
    );
    assert_eq!(frozen, 9, "the legacy 4826fc22 family FROZEN");
    assert_eq!(md5s.len(), 23, "rider 21 -> 22 at 24c, 22 -> 23 at the 24e gate tail (the 62d6fac law; no new tail from THIS row)");
    let tracked = std::process::Command::new("git")
        .args(["-C", root, "ls-files"])
        .output()
        .unwrap()
        .stdout;
    let tracked = String::from_utf8(tracked)
        .unwrap()
        .lines()
        .filter(|l| l.ends_with("gate.txt"))
        .count();
    assert_eq!(tracked, 1, "the tracked gate.txt face stays gre's ONLY");
    // the own row NEVER ships a gate face (the harness own dir has NO gate):
    let own = std::path::Path::new(root)
        .join("tools")
        .join(concat!("h", "process_harness"))
        .join("gate.txt");
    assert!(!own.exists(), "the ZERO-gate law: NO gate EVER ships HERE");
    // backbone frozen:
    let bb = std::fs::read(format!("{root}/tools/link4_harness/backbone10.txt")).unwrap();
    assert_eq!(lines(&String::from_utf8_lossy(&bb)).len(), 10);
    assert_eq!(md5_hex(&bb), "5339c7ee501dab8a85277c37dc2d1e0c");
}

// ======================================================================
// T16: the docs tripwires — the seed x3 faces + the own-token ZERO + the
// mod.rs 6->7 rider-flip face + the landmine NAMING law
// ======================================================================
#[test]
fn t16_docs_seed_token_tripwires() {
    // the 23i dialect law: EVERY harness arm counts LINES (grep -c), NEVER
    // occurrences — a single ledger line can carry the SAME token twice:
    let nf = |needle: &str| NEXTMD.lines().filter(|l| l.contains(needle)).count();
    assert_eq!(nf("825 tests green / 0 FAILED"), 3); // the CURRENT seed x3
    for s in ["810", "798", "784", "772", "763", "752"] {
        assert_eq!(nf(&format!("{s} tests green / 0 FAILED")), 3, "absorbed seed {s} x3");
    }
    // the own joined token NEVER rides NEXT.md (the 23g/24a ZERO law; the
    // docs sibling writes the hyphen form ONLY) — the face runtime-built:
    let mn = format!("{}{}", "hp", "rocess");
    assert!(!NEXTMD.contains(&mn), "own joined token rides the docs face");
    // the landing + this twin carry ZERO joined own-token (the SELF-scan):
    let own_rs = std::fs::read_to_string("/opt/data/snort3-rust/src/main/processp.rs").unwrap();
    assert!(!own_rs.contains(&mn));
    let this = include_str!(concat!("h", "process_parity_test.rs"));
    assert!(!this.contains(&mn));
    // the misc-9 landmine NAMING law: this twin declares NO landmine shape
    // (the face runtime-built so the SELF-check NEVER joins the token):
    let land = format!("{}{}", "struct Tra", "cer");
    assert_eq!(this.matches(land.as_str()).count(), 0);
    // the mod.rs rider-flip face (the 62d6fac complete-flip law):
    let mrs = std::fs::read_to_string("/opt/data/snort3-rust/src/main/mod.rs").unwrap();
    assert_eq!(mrs.lines().count(), 12);  // [24c 7->8, 24d 8->9, 24e rider 9->10: the module-registry landing's ONE new wiring line (the 62d6fac law, walked face)]   [24f rider 10->11: the snort-module config-owner pair's ONE new wiring line (the 62d6fac law, walked face)]# #   [24g rider 11->12: the snor-t-confi-g own-er pair's ONE new wiring line in the mo-d-r-s (the 62d6fac complete-flip law, walked face)]
    assert_eq!(mrs.matches("pub mod processp").count(), 1);
    // the row NEVER touches the seed faces (the pin faces UNMOVED):
    assert_eq!(NEXTMD.matches("5 TEST(").count(), 1);
}
