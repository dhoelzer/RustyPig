//! Port of `src/main/reload_tracker.{h,cc}` (ground truth @ fe29cbe:
//! reload_tracker.cc 89 L md5 `bdd9e3d773904514e8672a261fb6fddc` +
//! reload_tracker.h 49 L md5 `598e08b485165bd2fdc514954b13652b`) — row 19a,
//! the 89-L half of the chapter-19 misc9 pick P1 (misc9 PLAN §3 landing map
//! names `src/main/reload_tracker.rs`).
//!
//! THE one fresh cp of the harness row: reload_tracker.cc's four includes
//! resolve 3-find-1 (control/control.h, log/messages.h, main/snort_types.h
//! find-1 INHERITED; reload_tracker.h find-0 fresh-cp — MEASURED; build.sh
//! cp census, mid-build 124 = 122 donor + cc + h; the E4 arms prove it:
//! dropping reload_tracker.h kills ONLY tracker while module SURVIVES — the
//! 1-cp law — and the control.h drop kills ONLY tracker, module SURVIVES:
//! the link6 log_text wall INVERTED face).
//!
//! The C statics (cc :33-:35 `bool reload_in_progress = false; std::string
//! current_command; ControlConn* ctrl = nullptr;`) are ReloadTracker CLASS
//! statics — process state. The port carries them on an explicit
//! [`ReloadTracker`] instance (the landed statics-on-struct posture:
//! LogEngine's C file-globals ride the struct, log/messages.rs:4-:8).
//!
//! `ControlConn` (ground control/control.h :37, forward-declared at
//! reload_tracker.h :26 OUTSIDE the namespace) has NO landed Rust type —
//! the control/shell layer belongs to a later row (the response_buf.rs
//! :52-:56 "a full port of which belongs to the control/shell layer"
//! ruling). This row's four entry points reach ONLY two of its faces,
//! landed as the cited input face [`ControlConnTracker`] (response_buf.rs
//! ControlConn/LogSink trait lineage, deviation row 19a):
//! * `get_current_command()` (control.h :60 `return pending_commands.
//!   front();`) — the harness probe NEVER carries a live ControlConn (every
//!   call site passes nullptr -> the `"signal"` ternary arms at cc :43/:47),
//!   so the queried command arrives as `Option<String>`; the provider-queued
//!   queue face of the real ControlConn NEVER gets invented here (the
//!   pkthdr_flags/queue_event provider precedent).
//! * `show_prompt()` (control.h :53, pulled at cc :63) — the harness witness
//!   (tools/misc9_harness/witness_misc9.cc 27 L md5 ada2b1e8…, the OWN-new
//!   +1 face; the LogMessage half of the recon +2 DIED by the carried
//!   stubs_18d seam — multiple-definition law, PLAN §9) SYNTHESIZES the body
//!   as counter+true, NEVER deref, because the ground body (control/
//!   control.cc show_prompt) drags the shell/pending_commands world
//!   (cited-never-compiled, the miscip R1 law). The Rust seam stays
//!   LEFT-OPEN the same way: the ported face counts ONLY the :63 PULL SITE
//!   (the witness counter twin `prompt_pulls`), the BODY is provider-queued,
//!   NEVER invented. The observable pins: `TRK end-prompt-true delta=1` vs
//!   `TRK end-prompt-false delta=0`.
//!
//! THE LogMessage seam (the carried seam, NEVER re-stubbed): the C reaches
//! the global `snort::LogMessage(const char* format, ...)` (log/messages.cc
//! :213-:222 — the log_quiet gate (:215) + WriteLogMessage -> vprintf
//! (:210/:196)). Rust routes through the landed [`LogEngine::log_message_stdout`]
//! (log/messages.rs:353-:358 — the SAME gate + cfmt core), so the format
//! strings + args land EXACTLY as the C call literals. The printed strings
//! are FIRST-CLASS vectors (the EV-line precedent, PLAN §9: the seed-pass
//! "print counters, cite text" design CORRECTED by disk): cc :41-:43/:48/:60
//! /:75/:88 literals pin the transcript BOTH ways (build.sh PYPIN greps all
//! five printed forms against vectors.txt); the harness seam's vprintf body
//! and trailing putchar('\n') yield the vectors' BLANK-LINE face after each
//! message (24 of the 41 DEC lines are message+blank pairs).
//!
//! THE -DNDEBUG arms (cc :54-:57 / :69-:72 / :82-:85): `#ifdef NDEBUG
//! UNUSED(ctrlcon); #else assert(ctrl == ctrlcon and reload_in_progress);
//! #endif` — under the PRODUCTION -DNDEBUG arm (the only arm the harness
//! graph builds, PLAN §9) the ctrlcon param is UNUSED and the assert ELIDES;
//! a debug build ADDS the `ctrl == ctrlcon and reload_in_progress`
//! contract. The port models the production arm unconditionally (cargo cfg
//! != the autotools -DNDEBUG flag, the 18d DEBUG_MSGS precedent) and keeps
//! the debug contract as debug_assert! — the ladder is assert-clean BOTH
//! ways (MEASURED: every end/failed/update pairs ctrlcon with the tracker's
//! own ctrl; the probe is null==null true; the vectors are arm-invariant,
//! and the harness re-builds non-NDEBUG too: the only delta is one
//! __assert_fail U per TU, nm 31/25 vs 32/26).

#![allow(dead_code)] // the tracker accessors serve the later control/shell rows

use crate::log::messages::LogEngine;
use crate::utils::cfmt::Arg;

/// control.h :37 class fwd face — the TWO faces reload_tracker.cc reaches,
/// landed as the queried input (provider-queued: the real ControlConn lands
/// with the control/shell row; NEVER invented here).
pub struct ControlConnTracker {
    /// the get_current_command() face at the moment of the call (None
    /// models the harness's nullptr ControlConn — the "signal" ternary arm
    /// every misc9 vector line rode).
    pub current_command: Option<String>,
}

impl ControlConnTracker {
    /// control.h :60 `get_current_command() const { return
    /// pending_commands.front(); }` (the queue front face; None == the
    /// null-conn ternary arm the probe always rides).
    pub fn get_current_command(&self) -> Option<&str> {
        self.current_command.as_deref()
    }
}

/// cc :43/:47 `get_current_command().substr(0, 50)` — std::string::substr
/// clamps to the length (no trap) with cap EXACTLY 50 (the build.sh PYPIN
/// re-reads the `substr(0, 50)` literal face EVERY build).
const COMMAND_CAP: usize = 50;

/// ReloadTracker — reload_tracker.h :31-:47 (`class SO_PUBLIC ReloadTracker
/// { ReloadTracker() = delete;                                  // h:33
///   static bool start(ControlConn* ctrlcon);                   // h:34
///   static void end(const ControlConn* ctrlcon, bool prompt=false); // h:35
///   static void failed(const ControlConn* ctrlcon, const char* reason); // h:36
///   static void update(const ControlConn* ctrlcon, const char* status); // h:37
/// private: static bool reload_in_progress; static std::string
/// current_command; static ControlConn* ctrl; }`). `ReloadTracker() =
/// delete` (h:33): the C class is NEVER instantiated — the Rust face holds
/// the three statics (the LogEngine posture) and the four statics become
/// &mut self methods; the prompt_pulls counter is the witness-side
/// observable (witness_misc9.cc g_prompt twin — NOT a C field, deviation
/// row 19a).
pub struct ReloadTracker {
    reload_in_progress: bool,   // h:44 field / cc:33 initializer `= false`
    current_command: String,    // h:45 / cc:34 default-constructed empty
    ctrl_present: bool,         // h:46 `static ControlConn* ctrl` — presence
                                // face only (cc:35 `= nullptr`; the debug
                                // arm's ptr-compare lands as the presence
                                // EQUALITY, true for the probe's both-null)
    prompt_pulls: u32,          // witness_misc9.cc misc9_prompt_calls twin
                                // (the cc:63 observable; NEVER a C field)
}

impl Default for ReloadTracker {
    /// cc :33-:35 the three static initializers.
    fn default() -> Self {
        ReloadTracker {
            reload_in_progress: false,      // cc:33
            current_command: String::new(), // cc:34
            ctrl_present: false,            // cc:35
            prompt_pulls: 0,                // harness witness face, not C
        }
    }
}

impl ReloadTracker {
    /// cc :37-:50 —
    /// ```text
    /// if (reload_in_progress)
    /// {
    ///     LogMessage("Reload in progress [%s], attempting command: [%s]\n",
    ///         current_command.c_str(),
    ///         ctrlcon ? ctrlcon->get_current_command().substr(0, 50).c_str() : "signal");
    ///     return false;                                    // :44
    /// }
    /// reload_in_progress = true;                           // :46
    /// current_command = (ctrlcon ? …substr(0, 50) : "signal"); // :47
    /// LogMessage("Reload started. [%s]\n", current_command.c_str()); // :48
    /// ctrl = ctrlcon;                                      // :49
    /// return true;                                         // :50
    /// ```
    /// THE in-progress LogMessage pairs the OLD current_command with the NEW
    /// attempt (:41-:43 DOUBLE-arg face — vectors:4 `Reload in progress
    /// [signal], attempting command: [signal]`); start1=true, start2-during
    /// =false (vectors:3/:6 `TRK start1 -> 1` / `start2-during -> 0`).
    pub fn start(&mut self, log: &mut LogEngine, ctrlcon: Option<&ControlConnTracker>) -> bool {
        if self.reload_in_progress {
            // cc:39 the gate; :41-:43 the message reads old cmd + attempt
            let attempt = Self::attempt_face(ctrlcon); // cc:43 ternary face
            // the CC CALL LITERAL lands verbatim (cfmt core via LogEngine):
            log.log_message_stdout(
                "Reload in progress [%s], attempting command: [%s]\n",
                &[
                    Arg::S(Some(self.current_command.as_str().into())),
                    Arg::S(Some(attempt.as_str().into())),
                ],
            );
            return false; // cc:44
        }
        self.reload_in_progress = true; // cc:46
        self.current_command = Self::attempt_face(ctrlcon); // cc:47 substr(0,50) + ternary
        log.log_message_stdout(
            "Reload started. [%s]\n", // cc:48 literal (vectors:1/:15/:21/:27 arms)
            &[Arg::S(Some(self.current_command.as_str().into()))],
        );
        self.ctrl_present = ctrlcon.is_some(); // cc:49 `ctrl = ctrlcon;`
        true // cc:50
    }

    /// the cc:43/:47 `ctrlcon ? ctrlcon->get_current_command().substr(0, 50)
    /// : "signal"` face — cap 50, clamped, the null-conn "signal" arm.
    fn attempt_face(ctrlcon: Option<&ControlConnTracker>) -> String {
        match ctrlcon {
            Some(c) => c
                .get_current_command()
                .map(|s| s.chars().take(COMMAND_CAP).collect::<String>())
                .unwrap_or_else(|| String::from("signal")),
            None => String::from("signal"),
        }
    }

    /// cc :53-:66 —
    /// ```text
    /// #ifdef NDEBUG
    ///     UNUSED(ctrlcon);                                  // :56
    /// #else
    ///     assert(ctrl == ctrlcon and reload_in_progress);   // :58
    /// #endif
    /// LogMessage("Reload ended. [%s]\n", current_command.c_str()); // :60
    /// current_command.clear();               // :61
    /// if (prompt)                            // :62
    ///     ctrl->show_prompt();               // :63
    /// ctrl = nullptr;                        // :64
    /// reload_in_progress = false;            // :65
    /// ```
    /// order pin (harness PYPIN `log:60-before-guard:62->prompt:63 | drop
    /// ctrl:64-before-flag:65`): the message lands BEFORE the prompt guard;
    /// ctrl drops BEFORE the flag. The :63 pull site is counted, NEVER
    /// given a body (show_prompt provider-queued — deviation row 19a); the
    /// vectors pin the delta face (prompt-true delta=1 / prompt-false
    /// delta=0). Debug arm contract kept as debug_assert (the measured
    /// harness face: the ladder is assert-clean BOTH ways).
    pub fn end(
        &mut self,
        log: &mut LogEngine,
        ctrlcon: Option<&ControlConnTracker>,
        prompt: bool,
    ) {
        debug_assert!(
            self.ctrl_present == ctrlcon.is_some() && self.reload_in_progress,
            "reload_tracker.cc:58 assert(ctrl == ctrlcon and reload_in_progress)"
        );
        // cc:54-:57 NDEBUG production arm: ctrlcon UNUSED (it rides the
        // debug_assert ONLY -- exactly the shipped face).
        log.log_message_stdout(
            "Reload ended. [%s]\n", // cc:60 literal (vectors:19/:25 arms)
            &[Arg::S(Some(self.current_command.as_str().into()))],
        );
        self.current_command.clear(); // cc:61
        if prompt {
            // cc:62-:63 ctrl->show_prompt() -- the harness OBSERVABLE is the
            // witness counter (misc9_prompt_calls); the Rust face counts the
            // PULL SITE only, the body stays provider-queued (the control/
            // shell row lands ControlConn::show_prompt; NEVER invented --
            // the ground body drags the shell/pending_commands world).
            self.prompt_pulls += 1;
        }
        self.ctrl_present = false; // cc:64 `ctrl = nullptr;`
        self.reload_in_progress = false; // cc:65
    }

    /// h:35 `static void end(const ControlConn* ctrlcon, bool prompt=false);`
    /// — the DEFAULT-ARG face (the vectors' `ReloadTracker::end(nullptr)`
    /// probe line -> prompt FALSE, `delta=0`).
    pub fn end_default(&mut self, log: &mut LogEngine, ctrlcon: Option<&ControlConnTracker>) {
        self.end(log, ctrlcon, false); // h:35 NSDMI `prompt=false`
    }

    /// cc :68-:79 — NDEBUG arm (:70-::72) then
    /// ```text
    /// LogMessage("Reload failed! %s [%s]\n", reason, current_command.c_str()); // :75
    /// current_command.clear();      // :76
    /// ctrl = nullptr;               // :77
    /// reload_in_progress = false;   // :78
    /// ```
    /// the reason rides the FIRST %s (vectors `Reload failed! why [signal]`
    /// :9 vs `Reload failed! x [signal]` :31 — the two fired arms differ
    /// ONLY in the printed reason half); start-after-failed == true
    /// (vectors:32 `TRK start-after-failed -> 1` — the failed drop
    /// re-arms :46).
    pub fn failed(
        &mut self,
        log: &mut LogEngine,
        ctrlcon: Option<&ControlConnTracker>,
        reason: &str,
    ) {
        debug_assert!(
            self.ctrl_present == ctrlcon.is_some() && self.reload_in_progress,
            "reload_tracker.cc:73 assert(ctrl == ctrlcon and reload_in_progress)"
        );
        // cc:69-:72 NDEBUG arm: ctrlcon UNUSED (debug_assert-only rider).
        log.log_message_stdout(
            "Reload failed! %s [%s]\n", // cc:75 literal
            &[
                Arg::S(Some(reason.into())),
                Arg::S(Some(self.current_command.as_str().into())),
            ],
        );
        self.current_command.clear(); // cc:76
        self.ctrl_present = false; // cc:77
        self.reload_in_progress = false; // cc:78
    }

    /// cc :81-:89 — NDEBUG arm (:82-:85) then
    /// `LogMessage("Reload update: %s [%s]\n", status, current_command.
    /// c_str());` (:88) — the ONLY entry that changes NO state (the
    /// current_command stays live across update(): vectors:7/:23 `Reload
    /// update: st [signal]` / `st2` ride between the [signal] arms).
    pub fn update(
        &mut self,
        log: &mut LogEngine,
        ctrlcon: Option<&ControlConnTracker>,
        status: &str,
    ) {
        debug_assert!(
            self.ctrl_present == ctrlcon.is_some() && self.reload_in_progress,
            "reload_tracker.cc:86 assert(ctrl == ctrlcon and reload_in_progress)"
        );
        // cc:82-:85 NDEBUG arm: ctrlcon UNUSED (debug_assert-only rider).
        log.log_message_stdout(
            "Reload update: %s [%s]\n", // cc:88 literal
            &[
                Arg::S(Some(status.into())),
                Arg::S(Some(self.current_command.as_str().into())),
            ],
        );
    }

    // ---- harness observation faces (probe_dec.cc delta arithmetic) ----

    /// the cc:63 observable twin (witness_misc9.cc g_prompt /
    /// misc9_prompt_calls): how many show_prompt PULLS ran.
    pub fn prompt_pulls(&self) -> u32 {
        self.prompt_pulls
    }
    /// h:34 gate face (cc:39 read site).
    pub fn reload_in_progress(&self) -> bool {
        self.reload_in_progress
    }
}
