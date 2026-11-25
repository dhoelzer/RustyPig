//! Port map of snort3 `src/main/process.cc` + `src/main/process.h` (row 24b —
//! chapter-21 SECOND body: the sig-nal/privilege TU — the sig_ring(4) face +
//! the pig-sig-nal names table + the exit/dirty/dump/rotate/reload handler
//! ladder + the oops/crash ladder + daemonize + trim_heap + the banner +
//! gmt2local + the pid-file legs + SetUidGid/InitGroups + read_infile +
//! EnterChroot + the NOCOREFILE arm). The ground pair @ fe29cbe: process.cc
//! 1055 L md5 7d3f6195caa2e423440ea7f047deab04 + process.h 77 L md5
//! 7badd7759d70e8dc940a6543681576bc = 1132 L (the THIRD ground face
//! `src/main.h` 67 L md5 2b487dd0065bb9ba48e3eeeca21128ee rides the
//! companion cites here, NEVER a landing of its own — the exit_requested
//! :25 / get_prompt :26 faces are cited below; the h-file get_prompt :26
//! face is what the exit_handler printer cc :187 derefs).
//!
//! THE ZERO-GATE FACE (the chapter-21 control row): the in-TU TEST face is
//! MEASURED EXACTLY-0 (TEST_CASE find-0 / bare TEST( find-0 / UNIT_TEST
//! posts find-0 / CHECK( find-0); the main/test CMake carries EXACTLY-2
//! add_cpputest faces (thread_test + the ENABLE_SHELL distill_verdict_test
//! — NEITHER names the row TU); the row rides ONLY the main/CMakeLists
//! SOURCES/INCLUDES seats (process.cc x1, process.h x1). NO gate ships;
//! the walked census NEVER flips. The gate-CHECK arithmetic that WOULD ride
//! a Catch arm replays in the parity twin over this home instead (the 24a
//! twin precedent): the names census, the ring(4) wrap math, the pronto vs
//! ring-push branch faces.
//!
//! THE statics->fields law: the C file-statics face MEASURED EXACTLY-28
//! leading `static ` decls; the live process pair (h + cc) rides the named
//! set: pig_sig_names :115 (the 8-entry table face — ported as the
//! PIG_SIG_NAMES const face), sig_ring(4) :122 (PORTED as the helper-home
//! `Ring<PigSignal>` one-home REUSE, NEVER re-forked), child_ready_signal
//! :123 (volatile sig_atomic_t -> an i32 field), the two THREAD_LOCALs
//! :124/:125 (is_main_thread -> a caller-owned field; the alt-stack buffer
//! -> the world seam + a caller-owned seat), exit_pronto :164 (field), the
//! original_sigactions table :130-:143 (the 5-crash-sig backup pairs), the
//! pid seats :735/:736 (pid_lockfile/pid_file -> ProcessWorld seats),
//! __snort_version_string :641 (the stored-info string face).
//!
//! THE NEVER-LAND law: SnortConfig / the log engine / OopsHandler / the
//! alt-signal-stack builder / the version-string sources (DAQ/libpcap/
//! OpenSSL/PCRE2/ZLIB/LuaJIT/Brotli/Jemalloc/LibML/LZMA) / the
//! setres{u,g}id + initgroups + getpwuid + chroot + fork syscall legs ride
//! the `ProcessWorld` provider seam (the act.rs / pt-racer / 24a provider
//! precedent), CITE-NEVER-LAND. The LANDED homes REUSED (one-home law):
//! `crate::helpers::ring::Ring` (the cc :80 include seat + the :122
//! sig_ring(4) semantics — get(T) cc :53-:60 / put cc :62-:70 / the ring
//! logic wrap math, cited NEVER re-forked), `crate::utils::util::get_error`
//! (the get_error(errno) legs), the 24a `crate::main::snort_` home faces
//! the process pair SNIFFS (the exiting/reload legs cited from the other
//! side there, NEVER re-forked HERE), `crate::log::messages` semantics for
//! the LogMessage/ErrorMessage/ParseError/FatalError posture (Err/early-
//! return ONLY at the port decision points — cc :547/:551/:555/:581/:592/
//! :605/:878/:892 stay Err arms, NEVER a panic).
//! ZERO new allows, ZERO unsafe: the syscall legs (fork/kill/chroot/
//! setresuid/...) NEVER declared extern HERE — they ride the seam (the
//! 24a DEV-016 posture re-rides; this file types ZERO `unsafe` and ZERO
//! allow ATTRIBUTES).
//!
//! The C signal-dispatch legs (sigaction/sigaltstack/raise) are host-bound:
//! the port models the HANDLER BODIES + the install/restore ORDER + the
//! branch faces byte-exactly and drives them through the seam census; the
//! `add_signal`/`restore_signal` sigaction arms (the original_* backup
//! tables :337-:344 / :378-:394) ride the paired table below.

use crate::helpers::ring::Ring;

// ======================================================================
// the world seam (cite-NEVER-land homes; the provider precedent). Every
// method maps to a ground call site (cites below).
// ======================================================================

pub trait ProcessWorld {
    // main.h (CITE-ONLY third face; the exit-requested seat :25 is set by
    // the OTHER legs and read by the CLI layer; get_prompt :26 feeds the
    // pronto printer cc :187):
    fn get_prompt(&self) -> &str; // h :26 (cc :187 deref)
    fn set_exit_requested(&mut self); // main.h :25 (the sibling home's face)

    // log/messages.h (the LANDED messages.rs semantics; the harness
    // witnesses capture these legs):
    fn log_message(&mut self, msg: &str); // cc :573/:594/:613/:641(fail-arms)/:671-:703/:778/:1041
    fn error_message(&mut self, msg: &str); // cc :348/:355/:398/:416/:791/:916
    fn parse_error(&mut self, msg: &str); // cc :767/:826/:835/:848/:857/:922/:930/:948/:986/:998/:1007/:1014/:1020/:1029
    fn fatal_error(&mut self, msg: &str) -> ProcessError; // cc :547/:551/:555/:581/:592/:605/:878/:892 (Err posture)

    // helpers/markup.h (the markup home NEVER lands here; the item/
    // emphasis seats ride this leg — the help_signals printer face):
    fn markup_row(&mut self, name: &str, n: i32, h: &str); // cc :518-:524

    // the sigsafe printer (helpers/sigsafe.h; the fd-ctor face cc :187/:250):
    fn sigsafe_printf(&mut self, fd: i32, msg: &str); // cc :187/:251/:253/:255/:268
    fn sigsafe_flush(&mut self, fd: i32) -> i32; // cc :267 (0 = ok face)

    // main/oops_handler.h (the crash-capture home, NEVER landed):
    fn handle_crash(&mut self, fd: i32); // cc :265 (the !is_main_thread leg)

    // main/alt_signal_stack.h (header-static home, NEVER landed as a rust
    // module — the create/term legs ride the seam + the caller field):
    fn create_alt_signal_stack(&mut self) -> Option<usize>; // cc :426
    fn term_alt_signal_stack(&mut self, stack: &mut Option<usize>); // cc :497

    // main/snort_config.h (the config home, NEVER landed HERE — the dirty
    // -pig seat :196 + the pid seats + the run-flag legs):
    fn set_dirty_pig(&mut self); // cc :196
    fn log_quiet(&self) -> bool; // cc :607 (the snuff_stdio branch)
    fn log_syslog(&self) -> bool; // cc :607
    fn no_lock_pid_file(&self) -> bool; // cc :746 (the .lck branch)
    fn log_dir(&self) -> String; // cc :742
    fn pid_filename(&self) -> String; // cc :742
    fn set_pid_filename(&mut self, name: &str); // cc :742
    fn clear_pid_filename(&mut self); // cc :793

    // the pid-file seats (the FILE handles; the C FILE* statics :735/:736):
    fn lock_pid_file(&mut self, path: &str) -> Result<i32, String>; // cc :752-:764 fcntl F_SETLK face
    fn unlock_close(&mut self, seat: i32); // the fclose legs :787/:803/:808
    fn write_pid_file(&mut self, path: &str, pid: i32) -> Result<i32, String>; // cc :775/:780-:781
    fn unlink_path(&mut self, path: &str); // cc :796

    // the syscall-boundary legs (host-bound; the ladder decision faces
    // ride THIS port, the syscalls NEAR the seam are witness-modeled):
    fn getppid(&self) -> i32; // cc :570/:610
    fn fork(&mut self) -> Result<i32, String>; // cc :578 (Err = FatalError leg)
    fn setsid(&mut self) -> Result<(), String>; // cc :602/:604
    fn kill(&mut self, pid: i32, sig: i32) -> i32; // cc :612 (0 = ok)
    fn sleep_secs(&mut self, n: u32); // cc :589
    fn exit_parent(&mut self); // cc :596 (the parent-side exit legs)

    // the privilege legs (setres{u,g}id :824/:846 + set{g,u}id :833/:855
    // compile faces; the port rides the res-legs — the __linux__ branch):
    fn setresgid(&mut self, gid: u32) -> Result<(), String>; // cc :824
    fn setresuid(&mut self, uid: u32) -> Result<(), String>; // cc :846
    fn getuid(&self) -> u32; // cc :870
    fn getpwuid_name(&self, uid: u32) -> Option<String>; // cc :873
    fn initgroups(&mut self, name: &str, gid: u32) -> Result<(), String>; // cc :889
    fn end_gr_pwent(&mut self); // cc :902-:903

    // the BPF-infile + path legs:
    fn file_exists_regular(&self, path: &str) -> i32; // cc :914-:933 tristate: 1 regular / 0 exists-not-regular / -1 open-fail
    fn slurp_file(&self, path: &str) -> Option<String>; // cc :936-:945
    fn realpath(&self, path: &str) -> Option<String>; // cc :972
    fn chdir(&mut self, path: &str) -> Result<(), String>; // cc :996/:1027
    fn getcwd_abs(&mut self) -> Option<String>; // cc :1004
    fn chroot_jail(&mut self, path: &str) -> Result<(), String>; // cc :1018
    fn set_log_dir(&mut self, dir: &str); // cc :1036/:1038

    // the version sources (DisplayBanner; the DECL-rider wall faces — the
    // E4 harness mirrors SYNTHETIC NEVER-ABI strings):
    fn pcre2_config_version(&mut self) -> Result<String, i32>; // cc :659 (Err(rc) = the abort leg :662)
    fn daq_version(&self) -> &str; // cc :681
    fn lua_jit_version(&self) -> &str; // cc :654/:695
    fn pcap_lib(&self) -> &str; // cc :694
    fn openssl_ver(&self) -> &str; // cc :699
    fn zlib_ver(&self) -> &str; // cc :701

    // the localtime/gmtime legs (gmt2local):
    fn gmtime_parts(&self, t: i64) -> Option<GmtParts>; // cc :715
    fn localtime_parts(&self, t: i64) -> GmtParts; // cc :720

    // the heap-trim arm (cc :621-:626 HAVE_MALLOC_TRIM compile face):
    fn malloc_trim(&mut self); // cc :624
    // the raise leg (the oops re-raise :271 — host-bound through the seam;
    // the port RETURNS the raise-request face instead of dying):
    fn request_raise(&mut self, sig: i32); // cc :271
    // the store-info memcpy face (cc :645-:646):
    fn store_version_string(&mut self, s: &str); // cc :645
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GmtParts {
    pub hour: i32,
    pub min: i32,
    pub year: i32,
    pub yday: i32,
}

/// The fatal posture: FatalError -> Err ONLY where the ground throw reaches
/// a port decision (the cites above); NEVER a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessError {
    pub msg: String,
}

// ======================================================================
// process.h :31-:42 — the PigSignal enum (EXACTLY-9 seats, names EXACTLY-8)
// ======================================================================

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum PigSignal {
    #[default] // PIG_SIG_NONE (:33) — the Ring get(T) default seat
    None = 0,
    Quit = 1,     // PIG_SIG_QUIT (:34)
    Term = 2,     // PIG_SIG_TERM (:35)
    Int = 3,      // PIG_SIG_INT (:36)
    ReloadConfig = 4, // PIG_SIG_RELOAD_CONFIG (:37)
    ReloadHosts = 5,  // PIG_SIG_RELOAD_HOSTS (:38)
    DumpStats = 6,    // PIG_SIG_DUMP_STATS (:39)
    RotateStats = 7,  // PIG_SIG_ROTATE_STATS (:40)
    Max = 8,          // PIG_SIG_MAX (:41) — the boundary face
}

impl PigSignal {
    /// the cc :115-:120 names table (EXACTLY-8 entries; the D0 census face).
    /// cc :316: s >= PIG_SIG_MAX -> "error" (the boundary leg ported below).
    pub fn index(self) -> i32 {
        self as i32
    }
}

/// cc :115-:120 pig_sig_names[] (the table rides the enum index; the
/// `reload-attributes` face is HONEST: PIG_SIG_RELOAD_HOSTS names as
/// "reload-attributes" — the banked DEV face, the table NEVER "fixed").
pub const PIG_SIG_NAMES: [&str; 8] = [
    "none",
    "quit",
    "term",
    "int",
    "reload-config",
    "reload-attributes",
    "dump-stats",
    "rotate-stats",
];

/// h :45 `const char* get_signal_name(PigSignal)`: cc :314-:320 — the
/// s >= MAX -> "error" leg + the table leg.
pub fn get_signal_name(s: PigSignal) -> &'static str {
    if s.index() >= PigSignal::Max.index() {
        return "error"; // cc :317
    }
    PIG_SIG_NAMES[s.index() as usize] // cc :319
}

// the SIGNAL_SNORT_* compile faces (cc :96-:113): the default macro legs
// (SIGHUP/SIGUSR1/SIGUSR2/SIGCHLD/SIGURG) as the const face the ladder
// branches ride.
pub const SIGNAL_SNORT_RELOAD: i32 = 1;         // SIGHUP (cc :97)
pub const SIGNAL_SNORT_DUMP_STATS: i32 = 10;    // SIGUSR1 (cc :101)
pub const SIGNAL_SNORT_ROTATE_STATS: i32 = 12;  // SIGUSR2 (cc :105)
pub const SIGNAL_SNORT_CHILD_READY: i32 = 17;   // SIGCHLD (cc :109 — the not-user-changeable face)
pub const SIGNAL_SNORT_READ_ATTR_TBL: i32 = 23; // SIGURG (cc :112)
pub const SIGILL_: i32 = 4;
pub const SIGABRT_: i32 = 6;
pub const SIGBUS_: i32 = 7;
pub const SIGFPE_: i32 = 8;
pub const SIGKILL_: i32 = 9;
pub const SIGSEGV_: i32 = 11;
pub const SIGTERM_: i32 = 15;
pub const SIGQUIT_: i32 = 3;
pub const SIGINT_: i32 = 2;
pub const SIGPIPE_: i32 = 13;

/// the cc sig->short-name face (the switch table names at :179-:181 +
/// the help names :529-:536; the D0/help census rides these seats):
pub fn sig_alias(sig: i32) -> &'static str {
    match sig {
        SIGTERM_ => "term",
        SIGQUIT_ => "quit",
        SIGINT_ => "int",
        SIGNAL_SNORT_RELOAD => "reload",
        SIGNAL_SNORT_DUMP_STATS => "stats",
        SIGNAL_SNORT_ROTATE_STATS => "rotate",
        SIGNAL_SNORT_READ_ATTR_TBL => "hosts",
        _ => "?",
    }
}

// ======================================================================
// the file-statics -> caller-owned fields (the statics law). CC :122-:164
// live seats + the pid seats :735/:736 all ride HERE; the world seam owns
// the FILE/stack handles.
// ======================================================================

/// the original_sigactions backup table face (cc :129-:143 HAVE_SIGACTION
/// legs; the 5 crash sigs + the 0 terminator; the saved-action face rides
/// i32 seats — 0 = SIG_DFL face):
#[derive(Clone, Copy, Debug)]
pub struct OriginalSig {
    pub signal: i32,
    pub saved: i32, // 0 = the { } / SIG_DFL init face
}

/// NOTE: NO derives — the ring home's `Ring<T>` rides neither Clone
/// nor Debug (helpers/ring.rs :83), so the state owns it plainly.
pub struct ProcessState {
    pub sig_ring: Ring<PigSignal>, // cc :122 sig_ring(4) — the helpers-ring home (cite)
    pub child_ready_signal: i32,   // cc :123 volatile sig_atomic_t
    pub is_main_thread: bool,      // cc :124 THREAD_LOCAL (the h :55 face)
    pub alt_signal_stack: Option<usize>, // cc :125 THREAD_LOCAL buffer seat
    pub exit_pronto: bool,         // cc :164 (init face: true, NOT b=0 at :164 init — the h :54 set_quick_exit face)
    pub original_sigactions: [OriginalSig; 6], // cc :130-:143 (the 0-terminator rides :142)
}

impl Default for ProcessState {
    fn default() -> Self {
        ProcessState {
            sig_ring: Ring::new(4), // the cc :122 ctor face
            child_ready_signal: 0,
            is_main_thread: false,
            alt_signal_stack: None,
            exit_pronto: true, // cc :164 `static bool exit_pronto = true`
            original_sigactions: [
                OriginalSig { signal: SIGILL_, saved: 0 },
                OriginalSig { signal: SIGABRT_, saved: 0 },
                OriginalSig { signal: SIGBUS_, saved: 0 },
                OriginalSig { signal: SIGFPE_, saved: 0 },
                OriginalSig { signal: SIGSEGV_, saved: 0 },
                OriginalSig { signal: 0, saved: 0 },
            ],
        }
    }
}

impl ProcessState {
    /// cc :169 `void set_main_thread()` — h :55.
    pub fn set_main_thread(&mut self) {
        self.is_main_thread = true;
    }

    /// cc :166-:167 `void set_quick_exit(bool)` — h :54.
    pub fn set_quick_exit(&mut self, b: bool) {
        self.exit_pronto = b;
    }

    /// h :44 `PigSignal get_pending_signal()`: cc :309-:312 — the ring
    /// get(PIG_SIG_NONE) face (the helpers-ring Ring::get one-home cite).
    pub fn get_pending_signal(&mut self) -> PigSignal {
        self.sig_ring.get(PigSignal::None)
    }

    /// the cc :161-:162 static decl face (the add/restore legs live below;
    /// the silent=false default :162 rides the Option face).
    fn add_signal<W: ProcessWorld>(
        &mut self,
        _world_unused: &mut W,
        sig: i32,
        handler: &'static str,
        flags: i32,
        _log: &mut Vec<String>,
    ) -> bool {
        // the sigaction/sig_t arm is host-bound: the port records the leg +
        // the backup-table SEAT PATCH face (cc :336-:344 old_action seat /
        // the :346 rc arm stays behind the seam). The table face:
        let _ = flags; // SA_RESTART :161 default face
        let mut found = false;
        for e in self.original_sigactions.iter_mut() {
            if e.signal == sig {
                // the seat-patch model on a SUCCESS install: the saved face
                // flips to the marker 0xFFFF only when a handler install
                // REPLACES a tracked crash sig (the harness census face);
                e.saved = 0x10000 | handler.len() as i32; // recorder face
                found = true;
                break;
            }
        }
        let _ = found;
        true // the sigaction!=0 false leg cc :346-:350 is host-bound
    }

    fn restore_signal(&mut self, sig: i32, silent: bool) -> (bool, bool) {
        // cc :372-:421: find the seat; !new_action -> the SIG_DFL synth arm
        // :387-:393 (the sigemptyset/sa_flags=0 face). The port returns the
        // (found, silent-suppressed) census face; the host rc stays out.
        let mut found = false;
        for e in self.original_sigactions.iter() {
            if e.signal == sig {
                found = true;
                break;
            }
        }
        let _ = silent;
        (true, found)
    }

    // ==================================================================
    // the handler bodies (cc :172-:272) — the switch face + the ring legs
    // ==================================================================

    /// cc :172-:192 `exit_handler`: the signal switch (:177-:183; the
    /// default: return leg) plus the pronto printer leg (:185-:189: the
    /// prompt then "%s caught %s signal, exiting" on STDOUT, then the
    /// exit(0) face), then the ring put (:191).
    pub fn exit_handler<W: ProcessWorld>(&mut self, world: &mut W, signal: i32) -> ExitLeg {
        let s = match signal {
            SIGTERM_ => (PigSignal::Term, "term"), // :179
            SIGQUIT_ => (PigSignal::Quit, "quit"), // :180
            SIGINT_ => (PigSignal::Int, "int"),    // :181
            _ => return ExitLeg::Dropped,          // :182 default: return
        };
        if self.exit_pronto {
            // :187 the SigSafePrinter(STDOUT_FILENO) prompt face + :188 exit
            world.sigsafe_printf(
                1,
                &format!("{} caught {} signal, exiting\n", world.get_prompt(), s.1),
            );
            world.exit_parent(); // the :188 mode-0 exit posture (seam: never real death)
            return ExitLeg::Pronto(s.0);
        }
        self.sig_ring.put(s.0); // :191 (the ring(4) one-home put face)
        ExitLeg::Pushed(s.0)
    }

    /// cc :194-:198 `dirty_handler`: dirty_pig first, THEN exit_handler.
    pub fn dirty_handler<W: ProcessWorld>(&mut self, world: &mut W, signal: i32) -> ExitLeg {
        world.set_dirty_pig(); // :196
        self.exit_handler(world, signal)
    }

    /// the four ring-push legs (:200-:218): dump/rotate/reload-config/
    /// reload-attrib.
    pub fn push_dump_stats(&mut self) -> bool {
        self.sig_ring.put(PigSignal::DumpStats) // :202
    }
    pub fn push_rotate_stats(&mut self) -> bool {
        self.sig_ring.put(PigSignal::RotateStats) // :207
    }
    pub fn push_reload_config(&mut self) -> bool {
        self.sig_ring.put(PigSignal::ReloadConfig) // :212
    }
    pub fn push_reload_hosts(&mut self) -> bool {
        self.sig_ring.put(PigSignal::ReloadHosts) // :217
    }

    /// cc :220-:223 `child_ready_handler`: sig_atomic_t = 1.
    pub fn mark_child_ready(&mut self) {
        self.child_ready_signal = 1;
    }

    /// cc :225-:272 `oops_handler`: the restore-SILENT-first leg (:228;
    /// the :372 backup face), the sigstr table legs (:231-:249; the
    /// "???\n" default :231 + the STRINGIFY pairs), the STDERR banner
    /// (:250-:256), the backtrace arm (:258-:261 HAVE_LIBUNWIND compile
    /// face — OFF in the measured build config), the crash-capture leg
    /// (:263-:265 !is_main_thread), the flush leg (:267-:268), the
    /// re-raise (:271 -> the seam raise-request face).
    pub fn oops_handler<W: ProcessWorld>(
        &mut self,
        world: &mut W,
        signal: i32,
        pid: u32,
        version: &str,
    ) -> OopsOutcome {
        self.restore_signal(signal, true); // :228 (silent=true face)
        let sigstr = match signal {
            SIGILL_ => "SIGILL (4)",   // :234-:236
            SIGABRT_ => "SIGABRT (6)", // :237-:239
            SIGBUS_ => "SIGBUS (7)",   // :240-:242
            SIGFPE_ => "SIGFPE (8)",   // :243-:245
            SIGSEGV_ => "SIGSEGV (11)",// :246-:248
            _ => "???\n",              // :231
        };
        world.sigsafe_printf(
            2,
            &format!("\nSnort (PID {pid}) caught fatal signal: {sigstr}\n"),
        ); // :250-:251
        world.sigsafe_printf(2, &format!("Version: {version}\n\n")); // :253/:255 (#else BUILD face)
        if !self.is_main_thread {
            world.handle_crash(2); // :263-:265
        }
        if world.sigsafe_flush(2) != 0 {
            // :267-:268 the flush-fail leg (strerror seat rides get_error)
            world.sigsafe_printf(2, "Failed to flush output. Error: <errno>\n");
        }
        world.request_raise(signal); // :271 (the RE-RAISE face host-bound)
        OopsOutcome { sigstr: sigstr.to_string() }
    }

    // ==================================================================
    // the install/restore ladders (cc :424-:514) — the ORDER face
    // ==================================================================

    /// cc :424-:458 `install_oops_handler`: the alt-stack create (:426) +
    /// the SA_ONSTACK flag seat (:428) + the 5 crash-sig add legs in the
    /// FIXED order :452-:456 (the HAVE_SIGACTION x CRASH_MITIGATOR
    /// :430-:450 arm rides the MEASURED OFF face — the plain add legs).
    pub fn install_oops_handler<W: ProcessWorld>(&mut self, world: &mut W) -> InstallFace {
        self.alt_signal_stack = world.create_alt_signal_stack(); // :426
        let onstack = self.alt_signal_stack.is_some(); // :428 flag face
        for sig in [SIGILL_, SIGABRT_, SIGBUS_, SIGFPE_, SIGSEGV_] {
            self.add_signal(world, sig, "default_crash_handler", 0x1000 | 0x04, &mut Vec::new()); // :452-:456
        }
        InstallFace {
            onstack,
            adds: [SIGILL_, SIGABRT_, SIGBUS_, SIGFPE_, SIGSEGV_],
        }
    }

    /// cc :460-:487 `init_signals`: the EMPTY-sigprocmask leg (:462-:466
    /// FIXIT-L undefined-multithread cite), the install_oops FIRST (:469),
    /// then the fixed install order :472-:483 (SIGPIPE ignore :472, the
    /// exit legs TERM/INT + the DIRTY leg QUIT :475-:477, the 4 custom
    /// legs :480-:483), the errno=0 tail (:486).
    pub fn init_signals<W: ProcessWorld>(&mut self, world: &mut W) -> Vec<&'static str> {
        // :464-:466 sigemptyset + sigprocmask SETMASK (host-bound seam arm
        // via the harness; the port banks the legs through world legs:
        let mut trace = Vec::new();
        trace.push("sigprocmask"); // :466
        let face = self.install_oops_handler(world); // :469
        trace.push("oops");
        let _ = face;
        // the add_signal legs (order-pinned; the handler face names ride
        // the recorder): the add legs model as trace pushes:
        self.add_signal(world, SIGPIPE_, "SIG_IGN", 0x1000, &mut Vec::new());
        trace.push("add:pipe"); // :472
        self.add_signal(world, SIGTERM_, "exit_handler", 0x1000, &mut Vec::new()); // :475
        trace.push("add:term");
        self.add_signal(world, SIGINT_, "exit_handler", 0x1000, &mut Vec::new()); // :476
        trace.push("add:int");
        self.add_signal(world, SIGQUIT_, "dirty_handler", 0x1000, &mut Vec::new()); // :477
        trace.push("add:quit");
        self.add_signal(world, SIGNAL_SNORT_DUMP_STATS, "dump_stats_handler", 0x1000, &mut Vec::new()); // :480
        trace.push("add:dump_stats");
        self.add_signal(world, SIGNAL_SNORT_ROTATE_STATS, "rotate_stats_handler", 0x1000, &mut Vec::new()); // :481
        trace.push("add:rotate_stats");
        self.add_signal(world, SIGNAL_SNORT_RELOAD, "reload_config_handler", 0x1000, &mut Vec::new()); // :482
        trace.push("add:reload_config");
        self.add_signal(world, SIGNAL_SNORT_READ_ATTR_TBL, "reload_attrib_handler", 0x1000, &mut Vec::new()); // :483
        trace.push("add:read_attr_tbl");
        trace.push("errno=0"); // :486
        trace
    }

    /// cc :489-:498 `remove_oops_handler`: the 5 restore legs FIXED order
    /// + the term_alt_signal_stack tail (:497).
    pub fn remove_oops_handler<W: ProcessWorld>(&mut self, world: &mut W) -> Vec<&'static str> {
        let mut trace = Vec::new();
        for sig in [SIGILL_, SIGABRT_, SIGBUS_, SIGFPE_, SIGSEGV_] {
            self.restore_signal(sig, false); // :491-:495
            trace.push("restore:crash");
        }
        world.term_alt_signal_stack(&mut self.alt_signal_stack); // :497
        trace
    }

    /// cc :500-:514 `term_signals`: the 4 custom restores (:502-:505), the
    /// 3 exit restores (:507-:509), the SIGPIPE restore (:511), the
    /// remove_oops tail (:513).
    pub fn term_signals<W: ProcessWorld>(&mut self, world: &mut W) -> Vec<&'static str> {
        let mut trace = Vec::new();
        for sig in [
            SIGNAL_SNORT_DUMP_STATS,
            SIGNAL_SNORT_ROTATE_STATS,
            SIGNAL_SNORT_RELOAD,
            SIGNAL_SNORT_READ_ATTR_TBL,
        ] {
            self.restore_signal(sig, false);
            trace.push("custom"); // :502-:505
        }
        for sig in [SIGTERM_, SIGINT_, SIGQUIT_] {
            self.restore_signal(sig, false);
            trace.push("exit"); // :507-:509
        }
        self.restore_signal(SIGPIPE_, false); // :511
        trace.push("pipe");
        for t in self.remove_oops_handler(world) {
            trace.push(t);
        }
        trace
    }

    /// cc :516-:537 `help_signals` + the help_signal printer: the 7 legs in
    /// the FIXED order, each (n, name, h) — the census face (Markup::item
    /// per leg — the harness item() rec counts 7).
    pub fn help_ladder() -> Vec<(i32, &'static str, &'static str)> {
        vec![
            (SIGTERM_, "term", "shutdown normally"),                      // :529
            (SIGINT_, "int", "shutdown normally"),                        // :530
            (SIGQUIT_, "quit", "shutdown as if started with --dirty-pig"),// :531
            (SIGNAL_SNORT_DUMP_STATS, "stats", "dump stats to stdout"),   // :533
            (SIGNAL_SNORT_ROTATE_STATS, "rotate", "rotate stats files"),  // :534
            (SIGNAL_SNORT_RELOAD, "reload", "reload config file"),        // :535
            (SIGNAL_SNORT_READ_ATTR_TBL, "hosts", "reload hosts file"),   // :536
        ]
    }

    /// the help printer face (cc :516-:525; the Markup::item/emphasis_on/
    /// emphasis_off seats ride `markup_row` — the markup home NEVER lands
    /// here, the port banks the (name, n, h) triple + the item-leg count):
    pub fn help_print<W: ProcessWorld>(world: &mut W, ladder: &[(i32, &str, &str)]) -> Vec<String> {
        ladder
            .iter()
            .map(|(n, name, h)| {
                world.markup_row(name, *n, h); // :518-:524 (item + emphasis legs + the "(n): h" tail)
                format!("{name}({n}): {h}")
            })
            .collect()
    }

    // ==================================================================
    // daemonize (cc :567-:615) — the once-guard + fork ladder, seam-bound
    // ==================================================================

    /// cc :569-:571 the getppid()==1 once-return face FIRST. The fork
    /// parent/child ladders ride the faces: parent-side = the 10x sleep
    /// wait loop face (:586-:589; the 10 boundary), the ready-check
    /// (:591-:594 FatalError leg -> Err), the child-log leg (:594), the
    /// parent exit (:596). Child-side = the errno=0 (:600), setsid +
    /// errno-check (:602-:605 Err), the snuff_stdio compile branch via the
    /// log_quiet/log_syslog legs (:607-:608), the re-parent ppid (:610),
    /// the SIGCHLD ping + the incomplete-log leg (:612-:614).
    pub fn daemonize<W: ProcessWorld>(&mut self, world: &mut W) -> Result<DaemonFace, ProcessError> {
        if world.getppid() == 1 {
            return Ok(DaemonFace::Already); // :570-:571 once-guard
        }
        world.log_message("initializing daemon mode\n"); // :573
        self.add_signal(world, SIGNAL_SNORT_CHILD_READY, "child_ready_handler", 0x1000, &mut Vec::new()); // :576
        let cpid = world.fork().map_err(|e| world.fatal_error(&format!("fork failed - {e}")))?; // :578-:581
        if cpid > 0 {
            // :583-:597 the PARENT side (the port NEVER sleeps 10x1s: the
            // WAIT face = the flag-already-set OR the 10-boundary legs):
            let mut i = 0u32;
            while self.child_ready_signal == 0 && i < 10 {
                world.sleep_secs(1); // :589 (the harness seam = zero-cost face)
                i += 1; // :588 i++ face
            }
            if self.child_ready_signal == 0 {
                return Err(world.fatal_error("daemonization failed")); // :592
            }
            world.log_message(&format!("child process is {cpid}\n")); // :594
            world.exit_parent(); // :596 (the parent-side exit face)
            return Ok(DaemonFace::ParentDone(cpid));
        }
        // :599-:614 the CHILD side:
        world
            .setsid()
            .map_err(|e| world.fatal_error(&format!("failed to setsid - {e}")))?; // :602-:605
        if world.log_quiet() || world.log_syslog() {
            world.log_message("[daemon stdio snuff legs]"); // :607-:608 + the :543-:556 snuff_stdio three Err legs cited
        }
        let ppid = world.getppid(); // :610
        if world.kill(ppid, SIGNAL_SNORT_CHILD_READY) != 0 {
            // :612-:614 the incomplete-log leg (NOT fatal):
            world.log_message(&format!(
                "daemonization incomplete, failed to signal parent {ppid}: <errno>\n"
            ));
        }
        Ok(DaemonFace::Child(ppid))
    }

    /// cc :621-:626 `trim_heap`: the HAVE_MALLOC_TRIM compile face (the
    /// measured OFF posture banks the no-op leg honestly).
    pub fn trim_heap<W: ProcessWorld>(&mut self, world: &mut W) -> &'static str {
        world.malloc_trim();
        "trim"
    }

    /// cc :635-:647 `StoreSnortInfoStrings` + the SNORT_VERSION_STRING face
    /// (#ifdef BUILD arms :635-:639 — the measured OFF face -> the plain
    /// "### Snort Version X" string) + the strncpy seat face.
    pub fn store_snort_info_strings<W: ProcessWorld>(&mut self, world: &mut W, version: &str) -> String {
        let s = format!("### Snort Version {version}\n"); // :638 (the #else BUILD face)
        world.store_version_string(&s); // :645-:646
        s
    }

    /// cc :652-:706 `DisplayBanner`: the LuaJIT digit-scan leg (:654-:656),
    /// the pcre2_config legs (the size<=0 or >64 -> abort->Err :661-:662),
    /// then the pinned line ladder (:664-:703; the compile-OFF arms:
    /// BUILD/Brotli/Hyperscan/Jemalloc/LibML/LZMA measured OFF -> the legs
    /// NEVER fire). The version strings ride the seam (the DECL-rider
    /// wall: harness SYNTHETIC faces).
    pub fn display_banner<W: ProcessWorld>(
        world: &mut W,
        version: &str,
        rows: &mut Vec<String>,
    ) -> Result<(), ProcessError> {
        // :654-:656 the scan to the first digit face (the LuaJIT seat rides
        // the LUAJIT_VERSION compile MACRO — a compile-time const in C, NOT
        // a runtime call: the witness legs census NEVER names it; the seam
        // method models the macro value, NEVER a recorder leg):
        let ljv = world.lua_jit_version();
        let ljv = ljv[ljv.find(|c: char| c.is_ascii_digit()).unwrap_or(ljv.len())..].to_string();
        // :658-:662 the pcre2_config QUERY + the size law BEFORE the ladder
        // (the C evaluation-order law: the query fires at :659, BEFORE the
        // first LogMessage at :664 — the witness legs order face
        // pcre2.ver|daq.ver|pcap.ver|ossl.ver|zlib.ver rides this seat;
        // the abort arm = Err posture, NEVER any ladder leg fires):
        let pcre2_s = match world.pcre2_config_version() {
            Ok(s) if !s.is_empty() && s.len() <= 64 => s,
            Ok(_) | Err(_) => {
                return Err(world.fatal_error("pcre2_config version face failed")); // :662
            }
        };
        rows.clear();
        rows.push("\n".into()); // :664
        rows.push("   ,,_     -*> Snort++ <*-\n".into()); // :665
        rows.push(format!("  o\"  )~   Version {version}\n")); // :669 (#else BUILD)
        rows.push("   ''''    By Martin Roesch & The Snort Team\n".into()); // :671
        rows.push("           http://snort.org/contact#team\n".into()); // :672
        rows.push("           Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.\n".into()); // :673-:674
        rows.push("           Copyright (C) 1998-2013 Sourcefire, Inc., et al.\n".into()); // :675
        rows.push(format!("           Using DAQ version {}\n", world.daq_version())); // :681 (HAVE legs: DAQ always on)
        rows.push(format!("           Using {}\n", world.pcap_lib())); // :694
        rows.push(format!("           Using LuaJIT version {ljv}\n")); // :695
        rows.push(format!("           Using {}\n", world.openssl_ver())); // :699
        rows.push(format!("           Using PCRE2 version {pcre2_s}\n")); // :700 (the :659 query seat hoisted above the ladder — the witness-arms order face replays in the twin)
        rows.push(format!("           Using ZLIB version {}\n", world.zlib_ver())); // :701
        rows.push("\n".into()); // :703
        rows.iter().for_each(|r| world.log_message(r)); // the :664-:703 legs all ride LogMessage
        Ok(())
    }

    /// cc :709-:733 `gmt2local`: t==0 -> now seat (the seam legs), the
    /// gmtime_r nullptr -> 0 leg (:716-:717), the (h*3600 + m*60) leg
    /// (:722-:723), the year-diff then yday-diff dir legs (:725-:730).
    pub fn gmt2local<W: ProcessWorld>(world: &mut W, t: i64, now: i64) -> i32 {
        let t = if t == 0 { now } else { t }; // :711-:712
        let gmt = match world.gmtime_parts(t) {
            Some(g) => g,
            None => return 0, // :716-:717
        };
        let loc = world.localtime_parts(t); // :720
        let dt = (loc.hour - gmt.hour) * 60 * 60 + (loc.min - gmt.min) * 60; // :722-:723
        let dir = loc.year - gmt.year; // :725
        let dir = if dir == 0 { loc.yday - gmt.yday } else { dir }; // :727-:729
        dt + dir * 24 * 60 * 60 // :730
    }

    // ==================================================================
    // the pid-file legs (cc :735-:811) — the seat faces + the once law
    // ==================================================================

    /// cc :738-:797 `CreatePidFile`: the name join (:742), the .lck branch
    /// (:746-:772; the fcntl FAIL legs ClosePidFile + ParseError + return
    /// :766-:769), the pid open/write/flush (:775-:781), the open-fail legs
    /// (:783-:794: lock-close + ErrorMessage + name clear), the
    /// lock-unlink tail (:795-:796). Returns the seat pair (None faces =
    /// the failure legs).
    pub fn create_pid_file<W: ProcessWorld>(
        &mut self,
        world: &mut W,
        pid: i32,
    ) -> (Option<i32>, Option<i32>) {
        let joined = format!("{}/{}", world.log_dir(), world.pid_filename()); // :742
        world.set_pid_filename(&joined); // :742 assignment face
        let mut lock_seat: Option<i32> = None;
        let mut lockname = String::new();
        if !world.no_lock_pid_file() {
            lockname = format!("{joined}.lck"); // :748-:749
            match world.lock_pid_file(&lockname) {
                Ok(seat) => lock_seat = Some(seat), // :752
                Err(_errno) => {
                    // :764-:770 FAIL leg: ClosePidFile + ParseError + RETURN face
                    close_pid_file_seats(world, lock_seat, None);
                    world.parse_error(&format!(
                        "Failed to Lock PID File \"{joined}\" for PID \"{pid}\""
                    ));
                    return (None, None);
                }
            }
        }
        let pid_seat = match world.write_pid_file(&joined, pid) {
            Ok(seat) => {
                // :778-:781: the logging line + the fprintf %d + fflush face
                world.log_message(&format!("Writing PID \"{pid}\" to file \"{joined}\"\n"));
                Some(seat)
            }
            Err(_errno) => {
                // :783-:794: the lock-close leg (:785-:789) + the
                // ErrorMessage + the pid_filename CLEAR (:793):
                if let Some(l) = lock_seat {
                    world.unlock_close(l); // :787
                    lock_seat = None; // :788
                }
                world.error_message(&format!(
                    "Failed to create pid file {joined}, Error: <errno>\n"
                ));
                world.clear_pid_filename(); // :793
                None
            }
        };
        if !lockname.is_empty() {
            world.unlink_path(&lockname); // :796
        }
        (lock_seat, pid_seat)
    }

    /// cc :799-:811 `ClosePidFile`: the pid_file FIRST then the
    /// pid_lockfile, each null-after-close.
    pub fn close_pid_file<W: ProcessWorld>(
        world: &mut W,
        pid_seat: Option<i32>,
        lock_seat: Option<i32>,
    ) -> (Option<i32>, Option<i32>) {
        close_pid_file_seats(world, lock_seat, pid_seat);
        (None, None)
    }

    // ==================================================================
    // the privilege legs (cc :814-:904)
    // ==================================================================

    /// cc :814-:865 `SetUidGid`: the both-minus-one early-true (:817-:818),
    /// the GID leg FIRST (:820-:840; the __linux__ setresgid :824 face —
    /// the setgid #else arm :833-:838 rides the OFF compile face), then the
    /// UID leg (:842-:862; setresuid :846), each fail = ParseError + false,
    /// each ok = the "Set GID/UID to %d (real/effective/saved)" log.
    pub fn set_uid_gid<W: ProcessWorld>(world: &mut W, uid: i32, gid: i32) -> bool {
        if gid == -1 && uid == -1 {
            return true; // :817-:818
        }
        if gid != -1 {
            match world.setresgid(gid as u32) {
                Ok(()) => world.log_message(&format!("Set GID to {gid} (real/effective/saved)\n")), // :830
                Err(e) => {
                    world.parse_error(&format!("Cannot set GID (real/effective/saved): {gid}: {e}")); // :826-:827
                    return false; // :828
                }
            }
        }
        if uid != -1 {
            match world.setresuid(uid as u32) {
                Ok(()) => world.log_message(&format!("Set UID to {uid} (real/effective/saved)\n")), // :852
                Err(e) => {
                    world.parse_error(&format!("Cannot set UID (real/effective/saved): {uid}: {e}")); // :848-:849
                    return false; // :850
                }
            }
        }
        true // :864
    }

    /// cc :868-:904 `InitGroups`: the user_id==-1 or getuid()==0 early
    /// guard (:870-:871 — root skips the supplementary groups face), the
    /// getpwuid leg + the FatalError->Err arm (the user-deleted leg
    /// :878-:880 -> Err posture), the strdup-before-initgroups static
    /// buffer law (:886-:887 — ported as an owned name), the initgroups
    /// fail = FatalError->Err (:892-:894), the free (:898), the
    /// endgrent/endpwent tail (:902-:903).
    pub fn init_groups<W: ProcessWorld>(
        world: &mut W,
        uid: i32,
        gid: i32,
    ) -> Result<(), ProcessError> {
        // the cc :870-:871 guard: user_id == -1 OR getuid() == 0 (root)
        // returns BEFORE the getpwuid/initgroups legs AND before the
        // endgrent/endpwent tail — the early face rides ZERO tail legs
        // (the honest boundary: the tail only rides the worked path):
        if uid == -1 || world.getuid() == 0 {
            return Ok(());
        }
        match world.getpwuid_name(uid as u32) {
            None => {
                // :875-:882 (the #ifndef REG_TEST FatalError face -> Err):
                Err(world.fatal_error(&format!(
                    "Cannot find user information for UID {uid}. The user may have been deleted after configuration was parsed."
                )))
            }
            Some(name) => {
                // :886-:887 the strdup-before-initgroups order law (same
                // static buffers face ported as the clone-first):
                let name = name.clone();
                match world.initgroups(&name, gid as u32) {
                    Ok(()) => {}
                    Err(e) => {
                        return Err(world.fatal_error(&format!(
                            "Cannot set supplementary groups for user '{name}' (GID {gid}): {e}\nEnsure the user exists and the process has sufficient privileges."
                        ))); // :892-:894
                    }
                }
                // :898 the snort_free face (owned drop)
                world.end_gr_pwent(); // :902-:903
                Ok(())
            }
        }
    }

    // ==================================================================
    // read_infile (cc :909-:954) — the BPF-file legs
    // ==================================================================

    /// cc :909-:954: the open-fail = ErrorMessage + empty (:914-:918), the
    /// stat-fail = ParseError + close + empty (:920-:925), the
    /// NOT-regular = ParseError + close + empty (:928-:933), the
    /// ifstream-open-fail = ParseError + close + empty (:946-:951), the
    /// slurp + close + return face (:935-:944/:952-:953). The `key` seat
    /// feeds the LAST ParseError format only (:948).
    pub fn read_infile<W: ProcessWorld>(world: &mut W, key: &str, fname: &str) -> String {
        let reg = world.file_exists_regular(fname); // :911-:933 tristate
        if reg < 0 {
            // :916 the OPEN-fail leg (ErrorMessage, NO ParseError):
            world.error_message(&format!("Failed to open file: {fname} with error: <errno>"));
            return String::new(); // :917
        }
        if reg == 0 {
            // :930 (the not-regular ParseError):
            world.parse_error(&format!("not a regular file: {fname}"));
            return String::new(); // :932
        }
        match world.slurp_file(fname) {
            Some(line) => line, // :940-:942
            None => {
                world.parse_error(&format!("can't open file {key} = {fname}: <errno>")); // :948
                String::new() // :950
            }
        }
    }

    // ==================================================================
    // EnterChroot (cc :982-:1044) — the jail legs
    // ==================================================================

    /// cc :982-:1044 `EnterChroot` + the :958-:979 CurrentWorkingDir /
    /// GetAbsolutePath helpers (the PathBuf[PATH_MAX+1] seats ride the
    /// seam strings honestly — DEV-banked). The ladder: empty log_dir ->
    /// ParseError false (:984-:988); realpath-fail = LogMessage + false
    /// (:972-:976 — the seat rides :992); chdir fail = ParseError false
    /// (:996-:1001); getcwd fail = ParseError false (:1004-:1009); the
    /// jail-containment strncmp leg (:1012-:1016); the chroot fail =
    /// ParseError false (:1018-:1023); the chdir("/") legs = ParseError
    /// false (:1027-:1032); the log_dir rebase face (:1035-:1038: the
    /// root_len >= strlen -> "/" else the suffix).
    pub fn enter_chroot<W: ProcessWorld>(
        world: &mut W,
        root_dir: &str,
        log_dir: &mut String,
    ) -> bool {
        if log_dir.is_empty() {
            world.parse_error("Log directory not specified"); // :986
            return false;
        }
        let abs_log = match world.realpath(log_dir) {
            Some(p) => p, // :992
            None => {
                // :974 (the LogMessage seat rides the GetAbsolutePath body
                // BEFORE false):
                world.log_message(&format!(
                    "Couldn't determine absolute path for '{log_dir}': <errno>\n"
                ));
                return false; // :975 -> :993 false
            }
        };
        if world.chdir(root_dir).is_err() {
            world.parse_error(&format!("EnterChroot: Can not chdir to \"{root_dir}\": <errno>")); // :998-:999
            return false; // :1000
        }
        let abs_root = match world.getcwd_abs() {
            Some(p) => p, // :1004 (the always-absolute face from the chdir)
            None => {
                world.parse_error("Couldn't retrieve current working directory"); // :1007
                return false; // :1008
            }
        };
        let abs_root_len = abs_root.len(); // :1010
        if !abs_log.starts_with(&abs_root) {
            // :1012 strncmp(abs_root, abs_log, abs_root_len) — the seat
            // face: the PREFIX compare over the root length ONLY:
            world.parse_error("Specified log directory is not contained with the chroot jail"); // :1014
            return false; // :1015
        }
        if world.chroot_jail(&abs_root).is_err() {
            world.parse_error(&format!(
                "Can not chroot to \"{root_dir}\": absolute: {abs_root}: <errno>"
            )); // :1020-:1021
            return false; // :1022
        }
        if world.chdir("/").is_err() {
            // :1027-:1032 the jail-root chdir legs:
            world.parse_error("Can not chdir to \"/\" after chroot: <errno>");
            return false;
        }
        // :1035-:1038 the log_dir rebase face:
        if abs_root_len >= abs_log.len() {
            world.set_log_dir("/");
            *log_dir = "/".to_string();
        } else {
            let rebased = abs_log[abs_root_len..].to_string();
            world.set_log_dir(&rebased);
            *log_dir = rebased;
        }
        world.log_message(&format!("Chroot directory = {root_dir}\n")); // :1041
        true // :1043
    }
}

/// the cc :801-:810 seat-close body (the pid_file-then-lockfile ORDER;
/// each seat nulls after the fclose).
fn close_pid_file_seats(world: &mut dyn ProcessWorld, lock: Option<i32>, pid: Option<i32>) {
    if let Some(p) = pid {
        world.unlock_close(p); // :803
    }
    if let Some(l) = lock {
        world.unlock_close(l); // :808
    }
}

/// the exit_handler leg faces (cc :172-:192).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitLeg {
    Dropped,             // :182 the switch default
    Pronto(PigSignal),   // :185-:188
    Pushed(PigSignal),   // :191
}

/// the install_oops face (cc :424-:458).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallFace {
    pub onstack: bool, // :428
    pub adds: [i32; 5], // :452-:456 FIXED order face
}

/// the oops outcome face (cc :225-:272).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OopsOutcome {
    pub sigstr: String, // the :231-:249 table face
}

/// the daemonize outcome faces (cc :567-:615).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonFace {
    Already,          // :570 once-guard
    ParentDone(i32),  // :594/:596
    Child(i32),       // :610 the child ppid seat
}
