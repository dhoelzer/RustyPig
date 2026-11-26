//! Row 24d parity twin — the anal-yzer loop PAIR (chapter-21 FOURTH body,
//! the SECOND ZERO-gate control row after 24b). Replays the harness's
//! MEASURED C faces: the DEC vectors 10 L (md5 925adf60c5091f979833e4354a53c382,
//! the line-4 banner-blank seat) + FACE-A 10 L (md5 dfaf5c54a1c2efd5e37e757d39270b52)
//! — the ground pair main/anal-yzer.cc 1164 L b917d1670f40ba5c59b4206e1080dbc5
//! and main/anal-yzer.h 177 L 8f51a8a75b5ae5ea02439245aa4cdc07 @ fe29cbe
//! (1,341 L ledger); the THIRD ground face main.h 67 L
//! 2b487dd0065bb9ba48e3eeeca21128ee cite-ONLY — the row exits through the
//! CLASS-MEMBER exit seat (h :150 / cc :1141), NEVER the global sibling
//! (:25, the process-pair's seat that landed with 24b); the ZERO in-TU
//! TEST faces + the main/test EXACTLY-2 CppUTest add_cpputest dialect faces
//! (NEITHER names the row TU as a TEST host) + the row riding
//! main/CMakeLists anal-yzer.cc x1 + anal-yzer.h x1 ONLY; the walked census
//! 30/9/22/1 UNMOVED at this row's era face (the zero-gate law: NO gate ships
//! HERE — t13 walks it; the 24e registry-gate rider moved the LIVE face to
//! 31/9/23/1, the 62d6fac law); the state-ladder
//! transitions + the set_state poke/watchdog face; the command-queue
//! bookkeeping trio (pending pop-increments-unfinished / completed
//! push+finish / the uncompleted erase-then-hold walk + the both-arms
//! kick_watchdog law / the reap size-BEFORE-pop do-while > 1 drain + the
//! dtor while-form); the RetryQueue timeval ctor face (200 ms default) +
//! the timeradd usec-carry + the head-of-line get law + the term drain;
//! the max_recv min-ladder (the zero-disables-the-cap faces); the
//! skip-first finalize law; the exit/pause zero-roll IF/ELSE chain; the
//! SOF/EOF/OTHER branch + rstat dispatch tables; the sticky verdict over
//! the LANDED 23a sf-daq one-home verdict constants; the init 21 / term
//! 22+9 ladders + the oops pre/post faces pinned against the C rec census
//! CONTIGUOUS-order; the RetryQueue zero-interval assert-face -> NONE; the
//! show_source banner face (the run_num != 1 newline leg + the EXACT
//! printf face); and the docs seed/token tripwires.
//!
//! Family law (banked faces): NO joined own-token rides this file; paths
//! ride concat literals (the `concat!("anz", "l_harness/...")` include
//! seats), comments ride the hyphen split (anal-yzer, sf-daq, sh-ell).

use snort3::main::analyzer::*;

use std::io::Write;

const VECTORS: &str = include_str!(concat!("../tools/anz", "l_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/anz", "l_harness/vectors_faceA.txt"));
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
// the mock world (the AnalyzerWorld provider seam; the cite-NEVER-land
// homes modeled by the SAME leg-recorder discipline the C witness keeps;
// no seam ever invents success past a measured boundary)
// ======================================================================

#[derive(Default)]
struct MockWorld {
    legs: Vec<String>,
    poke: u32,
    log: u32,
    err: u32,
    kick: u32,
    watchdog: bool,
    daq_present: bool,
    interrupted: u32,
    reloaded: u32,
    rotate: u32,
    local_present: Option<bool>,
    started: bool, // the armed daq_start face (false models the failure leg)
}

impl MockWorld {
    fn rec(&mut self, l: &str) {
        self.legs.push(l.to_string());
    }
}

impl AnalyzerWorld for MockWorld {
    fn exit_requested_global(&self) -> bool {
        false
    }
    fn log_message(&mut self, msg: &str) {
        self.log += 1;
        self.rec(&format!("log.msg|{}", msg.trim_end()));
    }
    fn error_message(&mut self, _msg: &str) {
        self.err += 1;
        self.rec("err.msg");
    }
    fn main_poke(&mut self, _id: u32) {
        self.poke += 1;
        self.rec("poke");
    }
    fn update_thread_status(&mut self, watchdog_active: bool, _id: u32) {
        self.watchdog = watchdog_active;
        self.rec(if watchdog_active {
            "tc.status-on"
        } else {
            "tc.status-off"
        });
    }
    fn daq_start(&mut self) -> bool {
        self.rec("inst.start");
        self.started
    }
    fn daq_interrupt(&mut self) {
        self.interrupted += 1;
        self.rec("inst.interrupt");
    }
    fn daq_get_batch_size(&self) -> u32 {
        64
    }
    fn daq_receive(&mut self, _max_recv: u32) -> u32 {
        DAQ_RSTAT_WOULD_BLOCK
    }
    fn daq_next_message(&mut self) -> Option<u64> {
        None
    }
    fn daq_finalize(&mut self, _msg: u64, _verdict: u32) -> i32 {
        self.rec("inst.fin");
        0
    }
    fn daq_reload(&mut self) {
        self.reloaded += 1;
        self.rec("inst.reload");
    }
    fn daq_get_input_spec(&self) -> String {
        "d-a".into()
    }
    fn daq_get_error(&self) -> String {
        String::new()
    }
    fn daq_present(&self) -> bool {
        self.daq_present
    }
    fn publish_daq_message(&mut self, key: u8) {
        self.rec(&format!("bus.pub-{}", key));
    }
    fn publish_to_all_network_policies(&mut self) {
        self.rec("bus.pub-idle");
    }
    fn publish_thread_rotate(&mut self) {
        self.rotate += 1;
        self.rec("bus.pub-rot");
    }
    fn sf_daq_set_local_instance_present(&mut self, present: bool) {
        self.local_present = Some(present);
        self.rec("sf.local");
    }
    fn oops_set_current(&mut self, _msg: Option<u64>) {
        self.rec("oops.set");
    }
    fn advance_packet_time(&mut self, _sec: i64, _usec: i64) {}
    fn process_retry_queue_here(&mut self) {}
    fn handle_uncompleted_commands_here(&mut self) {}
    fn kick_watchdog(&mut self, _id: u32) {
        self.kick += 1;
        self.rec("tc.kick");
    }
}

fn ctor_pair(w: &mut MockWorld) -> (AnalyzerCore, RetryQueue) {
    AnalyzerCore::new(7, Some("d-a"), 0, 200, w).expect("the 200 ms ctor face")
}

fn v(idx: usize) -> String {
    lines(VECTORS)[idx].to_string()
}

// ======================================================================
// T1: the DEC vectors face — the md5 + length pins (drift-REFUSE law)
// ======================================================================
#[test]
fn t1_vectors_md5_and_lengths() {
    assert_eq!(lines(VECTORS).len(), 10, "the DEC vectors 10-L face");
    assert_eq!(lines(VECTORS_FACE_A).len(), 10, "the FACE-A 10-L face");
    assert_eq!(
        md5_hex(VECTORS.as_bytes()),
        "925adf60c5091f979833e4354a53c382"
    );
    assert_eq!(
        md5_hex(VECTORS_FACE_A.as_bytes()),
        "dfaf5c54a1c2efd5e37e757d39270b52"
    );
    // the tamper face (the 21a law): one flipped word MUST move the digest
    let mut tampered = VECTORS.to_string();
    tampered = tampered.replace("fin=PASS", "fin=BLCK");
    assert_ne!(md5_hex(tampered.as_bytes()), md5_hex(VECTORS.as_bytes()));
}

// ======================================================================
// T2: the P0/D2/D4 ladder faces replayed through the landing ctor + the
// NEW-guard seat (the cc :812-:821 ctor tail set_state(NEW) face)
// ======================================================================
#[test]
fn t2_ctor_and_new_guard_replay() {
    let mut w = MockWorld::default();
    let (core, rq) = ctor_pair(&mut w);
    // the P0 face: the log.msg retry leg + the ctor-tail poke + watchdog-off
    // (the inst.ctor leg is the harness's OWN mirror seat, NEVER the port's)
    assert_eq!(
        w.legs.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("|"),
        "log.msg|Retry queue interval is: 200 ms|poke|tc.status-off",
        "the P0 ctor legs face (the cc :817 set_state(NEW) tail)"
    );
    assert!(v(0).starts_with("P0 ctor legs=inst.ctor|log.msg|poke|tc.status-off"));
    assert_eq!(core.get_state(), STATE_NEW);
    assert!(!core.exit_requested, "the h :150 member face at ctor");
    assert_eq!(rq.interval_ms(), 200, "the h :73 retry_timeout seat");
    // the D2 face: execute at NEW pushes ONLY (no interrupt leg, cc :998-:1007)
    let legs_before = w.legs.len();
    let mut core = core;
    core.execute(1, &mut w);
    assert_eq!(w.legs.len(), legs_before, "execute@NEW adds ZERO legs");
    assert_eq!(v(2), "D2 execute@NEW legs-empty=1");
    // the D4 face: the dtor reap legs ride the harness mirror (inst.dtor);
    // the port-owned dtor reap drain face rides T5.
    assert_eq!(v(9), "D4 dtor legs=inst.dtor");
    // the dtor reap of the ctor-clean queue = the empty drain face:
    let reaped = core.reap_dtor_drain();
    assert!(reaped.is_empty());
    // the P1 parsed face:
    assert_eq!(
        v(1),
        "P1 state0=NEW source=d-a idling=0",
        "the state_string + source + is_idling faces"
    );
    assert_eq!(core.get_source(), "d-a");
    assert!(!core.is_idling());
}

// ======================================================================
// T3: the state-ladder transitions + the set_state poke/watchdog face
// (cc :902-:909 the two-state OR VERBATIM)
// ======================================================================
#[test]
fn t3_state_ladder_watchdog_face() {
    let mut w = MockWorld::default();
    let (mut core, _rq) = ctor_pair(&mut w);
    // the start() success face -> STARTED (watchdog OFF at STARTED)
    w.started = true;
    w.daq_present = true;
    core.set_state(STATE_INITIALIZED, &mut w);
    core.start(&mut w);
    assert_eq!(core.get_state(), STATE_STARTED);
    assert!(!w.watchdog, "STARTED arms NO watchdog (the OR face)");
    core.set_state(STATE_RUNNING, &mut w);
    assert!(w.watchdog, "RUNNING arms the watchdog");
    // execute-at-RUNNING interrupts (the LAW face cc :1004-:1005)
    core.execute(2, &mut w);
    assert_eq!(w.interrupted, 1, "the >= STARTED && < STOPPED && present face");
    // the STOP face: STOPPING keeps the watchdog ON BEFORE the exit member
    core.stop(&mut w);
    assert_eq!(core.get_state(), STATE_STOPPING);
    assert!(w.watchdog, "STOPPING keeps the watchdog (the OR face)");
    assert!(core.exit_requested, "cc :1141 the MEMBER exit seat (NOT main.h :25)");
    // the FAILED face: start-failure arms exit + FAILED (cc :1115-:1116)
    let mut w2 = MockWorld::default();
    let (mut core2, _rq2) = ctor_pair(&mut w2);
    w2.started = false;
    core2.set_state(STATE_INITIALIZED, &mut w2);
    core2.start(&mut w2);
    assert_eq!(core2.get_state(), STATE_FAILED);
    assert!(core2.exit_requested);
    assert_eq!(w2.err, 1);
    // the pause/resume state-guard faces (the exact error-message seats)
    core2.pause(&mut w2);
    assert_eq!(w2.err, 2, "pause at FAILED -> the state-string error face");
    let s = state_string(STATE_STOPPED).unwrap();
    assert_eq!(s, "STOPPED");
    assert!(state_string(8).is_none(), "the NUM_STATES guard face");
}

// ======================================================================
// T4: the command-queue bookkeeping trio (cc :994-:1056 + :954-:968)
// ======================================================================
#[test]
fn t4_command_queue_trio() {
    let mut w = MockWorld::default();
    let (mut core, _rq) = ctor_pair(&mut w);

    // handle_command pop face: pop-increments-unfinished, empty -> NONE
    assert!(core.pop_pending_command().is_none());
    core.execute(11, &mut w);
    core.execute(12, &mut w);
    assert_eq!(core.pop_pending_command(), Some(11));
    assert_eq!(core.unfinished_commands, 1);

    // the OK arm: completed push + finish (-- unfinished)
    core.complete_command(11);
    assert_eq!(core.unfinished_commands, 0);
    assert_eq!(core.completed_count(), 1);

    // the FALSE arm parks in the uncompleted set; the walk: erase-then-hold,
    // BOTH arms kick the watchdog (cc :966 VERBATIM)
    assert_eq!(core.pop_pending_command(), Some(12), "the second pending seat");
    assert_eq!(core.unfinished_commands, 1);
    core.add_command_to_uncompleted_queue(12);
    let mut order = Vec::new();
    core.handle_uncompleted_commands(&mut w, &mut |c| {
        order.push(c);
        true // the second walk executes OK (the false-mock RETRY face)
    });
    assert_eq!(order, vec![12]);
    assert!(core.uncompleted.is_empty(), "the erase-then-hold face");
    assert_eq!(core.completed_count(), 2);
    assert!(w.kick >= 1, "the cc :966 both-arms kick face");

    // the NOT-OK arm advances without erase:
    core.add_command_to_uncompleted_queue(13);
    core.handle_uncompleted_commands(&mut w, &mut |_| false);
    assert_eq!(core.uncompleted.len(), 1, "the ++it advance face");

    // finish_command saturation guard (the assert(>0) port face):
    core.finish_command();
    assert_eq!(core.unfinished_commands, 0);

    // is_fully_paused: the THREE-way AND (pending-empty + unfinished==0 +
    // state==PAUSED)
    assert!(!core.is_fully_paused());
    core.set_state(STATE_PAUSED, &mut w);
    assert!(core.is_fully_paused());
}

// ======================================================================
// T5: the reap arithmetic (the size-BEFORE-pop do-while face + the dtor
// while-form) — the N=3/1/0 measured arithmetic
// ======================================================================
#[test]
fn t5_reap_do_while_arithmetic() {
    let mut w = MockWorld::default();
    let (mut core, _rq) = ctor_pair(&mut w);
    // N=3 -> full drain (3>1, 2>1 arms, the 1 tail pass)
    for c in [101, 102, 103] {
        core.completed_push_test(c);
    }
    assert_eq!(core.reap_commands_reaps(), vec![101, 102, 103]);
    // N=1 -> one reap, one pass
    core.completed_push_test(104);
    assert_eq!(core.reap_commands_reaps(), vec![104]);
    // N=0 -> zero reaps
    assert!(core.reap_commands_reaps().is_empty());
    // the dtor while-form drains the same face
    for c in [105, 106] {
        core.completed_push_test(c);
    }
    assert_eq!(core.reap_dtor_drain(), vec![105, 106]);
    // the refcount LAW face (cc :942-:948: put()->0 -> destroy leg):
    assert!(AnalyzerCore::reap_command_refcount_zero(0));
    assert!(!AnalyzerCore::reap_command_refcount_zero(1));
    let _ = &w;
}

// ======================================================================
// T6: the RetryQueue timeval ctor + timeradd carry + head-of-line + drain
// (cc :100-:152 the FILE-LOCAL class, landed INSIDE the module)
// ======================================================================
#[test]
fn t6_retry_queue_timeval_face() {
    let mut w = MockWorld::default();
    // the zero-interval assert-face -> NONE (the Fatal posture law)
    assert!(RetryQueue::new(0, &mut w).is_none());
    let mut rq = RetryQueue::new(200, &mut w).unwrap();
    assert_eq!(retry_interval_ms(200), (0, 200_000), "the cc :126 split");
    assert_eq!(retry_interval_ms(1500), (1, 500_000));
    // timeradd usec-carry (the C timeradd macro face):
    assert_eq!(timeradd((10, 900_000), (0, 200_000)), (11, 100_000));
    assert_eq!(timeradd((10, 500_000), (0, 200_000)), (10, 700_000));
    // put + head-of-line get law (cc :140 strict front-only):
    rq.put(7, (9, 900_000)); // next_try = 10.200000 (the carry face)
    rq.put(8, (11, 0));      // next_try = 11.200000
    assert_eq!(rq.get(Some((10, 200_000))), Some(7), "the front ready (=) face");
    assert_eq!(
        rq.get(Some((11, 199_999))), // the SECOND front NOT ready: 11.199 < 11.200
        None, "the head-of-line NOT-ready face (next_try = 11.200000)"
    );
    assert_eq!(rq.get(Some((11, 200_000))), Some(8));
    assert!(rq.empty());
    assert!(rq.dtor_empty_ok());
    // the term drain face (cc :1133-:1140 get() with NO clock until empty):
    rq.put(9, (0, 0));
    rq.put(10, (0, 0));
    assert_eq!(rq.drain_all(), vec![9, 10]);
}

// ======================================================================
// T7: the max_recv min-ladder (the zero-disables-the-cap faces, cc
// :1020-:1025) + the skip-first finalize law (cc :1036-:1047)
// ======================================================================
#[test]
fn t7_max_recv_ladder_and_skip_law() {
    let mut w = MockWorld::default();
    let (mut core, _rq) = ctor_pair(&mut w);
    assert_eq!(core.compute_max_recv(64), 64, "the batch-only face");
    core.exit_after_cnt = 5;
    assert_eq!(core.compute_max_recv(64), 5, "the exit-cap face");
    core.pause_after_cnt = 3;
    assert_eq!(core.compute_max_recv(64), 3, "the double-cap (min) face");
    core.exit_after_cnt = 0;
    assert_eq!(core.compute_max_recv(64), 3, "zero DISABLES the exit cap");
    core.pause_after_cnt = 9999;
    assert_eq!(
        core.compute_max_recv(64),
        64,
        "the < max_recv guard face (big cap NEVER caps)"
    );

    // the skip law: EVERY msg while skip_cnt>0 finalizes PASS + decrements,
    // BEFORE any processing arm (the cc :1041-:1040 skip-first ORDER):
    core.set_skip_cnt(2);
    let fin = core.take_skip_finalizes(&[1, 2, 3, 4]);
    assert_eq!(fin, vec![1, 2], "the skip x2 PASS finalize face (L1c skipped=2)");
    assert_eq!(core.skip_cnt, 0, "the skip seat fully drained");
    // skip=0 finalizes NOTHING through this face:
    assert!(core.take_skip_finalizes(&[5, 6]).is_empty());

    // the pause_after seat the resume(3) arms (L1: resume -> pause_after=3,
    // then recv 3 -> the pause-while-RUNNING LIVE face):
    core.set_pause_after_cnt(3);
    assert_eq!(core.pause_after_cnt, 3);
}

// ======================================================================
// T8: the exit/pause zero-roll IF/ELSE chain (cc apply_recv_counters — the
// ELSE arm NEVER decrements when the exit seat is nonzero)
// ======================================================================
#[test]
fn t8_zero_roll_if_else() {
    let mut w = MockWorld::default();
    let (mut core, _rq) = ctor_pair(&mut w);
    // exit_after 5 - 5 == 0 -> the stop() arm LIVE (poke + watchdog-on +
    // exit member):
    core.exit_after_cnt = 5;
    core.pause_after_cnt = 9;
    core.set_state(STATE_RUNNING, &mut w);
    core.apply_recv_counters(5, &mut w);
    assert_eq!(core.get_state(), STATE_STOPPING, "the stop arm fired");
    assert!(core.pause_after_cnt == 9, "the ELSE arm NEVER touched the pause seat");
    assert!(core.exit_requested);

    // exit_after 5 - 3 != 0 -> decrement, NO stop, pause seat UNtouched:
    let (mut core2, _rq2) = ctor_pair(&mut w);
    core2.exit_after_cnt = 5;
    core2.pause_after_cnt = 3;
    core2.set_state(STATE_RUNNING, &mut w);
    core2.apply_recv_counters(3, &mut w);
    assert_eq!(core2.exit_after_cnt, 2);
    assert_eq!(core2.pause_after_cnt, 3, "the short-circuit face (cc &&-chain)");
    assert_eq!(core2.get_state(), STATE_RUNNING);

    // pause roll: 3 - 3 == 0 -> pause() LIVE (L1 "log.msg|== [7] paused"):
    let (mut core3, _rq3) = ctor_pair(&mut w);
    core3.pause_after_cnt = 3;
    core3.set_state(STATE_RUNNING, &mut w);
    core3.apply_recv_counters(3, &mut w);
    assert_eq!(core3.get_state(), STATE_PAUSED);
    assert_eq!(core3.id, 7, "the pause LOG id seat rides the ctor face");

    // reload guard (cc the if(daq_instance) seat):
    w.daq_present = false;
    core3.reload_daq(&mut w);
    assert_eq!(w.reloaded, 0);
    w.daq_present = true;
    core3.reload_daq(&mut w);
    assert_eq!(w.reloaded, 1);
    // rotate arms publish (the STOP-command chain face):
    core3.rotate(&mut Some(&mut w));
    assert_eq!(w.rotate, 1);
}

// ======================================================================
// T9: the branch tables — SOF/EOF/OTHER + the rstat dispatch + the sticky
// verdict over the LANDED 23a sf-daq one-home constants
// ======================================================================
#[test]
fn t9_branch_tables_sticky() {
    assert_eq!(AnalyzerCore::sofeof_branch(DAQ_MSG_TYPE_EOF), "eof");
    assert_eq!(AnalyzerCore::sofeof_branch(DAQ_MSG_TYPE_SOF), "sof");
    assert_eq!(
        AnalyzerCore::sofeof_branch(DAQ_MSG_TYPE_PACKET),
        "packet",
        "the row NEVER counts the packet seat (the L1c packet face rides NO column)"
    );
    assert_eq!(AnalyzerCore::sofeof_branch(9), "other", "the user-range seat");
    // the rstat dispatch (cc :933-:941 the analyze() face; the L1 script
    // arms TIMEOUT idle + INTERRUPTED kick+commands LIVE):
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_TIMEOUT),
        RstatAction::Idle
    ));
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_INTERRUPTED),
        RstatAction::KickThenCommands
    ));
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_OK),
        RstatAction::Continue
    ));
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_WOULD_BLOCK),
        RstatAction::Continue
    ));
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_NOBUF),
        RstatAction::ErrNomsgs
    ));
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_ERROR),
        RstatAction::ErrInstance
    ));
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_EOF),
        RstatAction::Break
    ));
    assert!(matches!(
        AnalyzerCore::rstat_action(DAQ_RSTAT_INVALID),
        RstatAction::Break
    ));
    // the sticky verdict (the LANDING seam; the deny-seat name rides the
    // LANDED 23a home = DAQ_VERDICT_BLACKLIST, NEVER a re-named DENY):
    assert!(is_sticky_verdict(DAQ_VERDICT_WHITELIST));
    assert!(is_sticky_verdict(DAQ_VERDICT_BLACKLIST));
    assert!(is_sticky_verdict(DAQ_VERDICT_IGNORE));
    assert!(!is_sticky_verdict(DAQ_VERDICT_PASS));
    assert!(!is_sticky_verdict(DAQ_VERDICT_BLOCK));
    // the idle counter face (the cc :919 daq_stats.idle++ seat):
    assert_eq!(AnalyzerCore::idle_stats_reset_face(2), 3, "the L1c idle=2 face grew from the script legs");
    // the L1c counter line parsed face (the scripted deterministic seats):
    let l1c = lines(VECTORS)[7];
    assert!(l1c.starts_with("L1c idle=2 skipped=2 sof=1 eof=2 other=0"));
    assert!(l1c.contains("rq=0 rp=0 rdisc=0 analyzed=1"));
    // the row-scoped msg-type consts ride the REAL SDK face (daq_common.h
    // :82-:85 — the landed-home law, NEVER a graft):
    assert_eq!((DAQ_MSG_TYPE_PACKET, DAQ_MSG_TYPE_PAYLOAD, DAQ_MSG_TYPE_SOF, DAQ_MSG_TYPE_EOF), (1, 2, 3, 4));
}

// ======================================================================
// T10: the ladder consts pinned CONTIGUOUS against the C rec census (the
// DEC order ladder byte-face; the init 21 + term 22+9 + oops pre/post)
// ======================================================================
#[test]
fn t10_ladders_byte_order_against_c_census() {
    let l1 = v(5);
    let l1 = strip_prefix(&l1, "L1 legs=").unwrap();
    // the init_unprivileged 21-entry ladder rides CONTIGUOUS in the C census:
    assert!(
        l1.contains(&AnalyzerCore::INIT_LADDER.join("|")),
        "the cc :664-:702 init ladder CONTIGUOUS (LIVE face after the pol.net + arity re-measure)"
    );
    // the term 22 + tail 9 ride CONTIGUOUS-CONTIGUOUS (the :714-:770 ladder):
    let joined_term = AnalyzerCore::TERM_LADDER.join("|");
    let joined_tail = AnalyzerCore::TERM_TAIL.join("|");
    assert!(l1.contains(&format!("|{joined_term}|")));
    // the TAIL sits ADJACENT after et.term (LIVE C face). The pin below
    // proves BOTH adjacency AND the full ORDER in ONE pass:
    assert!(
        l1.contains(&format!("{joined_term}|{joined_tail}|poke|tc.status-off|oops.tterm")),
        "the term-ladder + tail adjacency face (the LIVE C census face)"
    );
    // the oops/thread-init pre-apply face (the 7-entry const, the sw.apply +
    // de.tinit seats INTERLEAVE, NEVER folded — the honest split faces):
    assert!(l1.contains(
        "oops.tinit|set_type|set_inst|set_run_num|sw.apply|de.tinit|tc.tid|get_inst|tc.policy|sf.local"
    ));
    // the ladder arities (the COLD census face): 21 / 22 / 9; the const
    // NEVER interleaves the retry-drain legs (they ride their OWN line):
    assert_eq!(AnalyzerCore::INIT_LADDER.len(), 21);
    assert_eq!(AnalyzerCore::TERM_LADDER.len(), 22);
    assert_eq!(AnalyzerCore::TERM_TAIL.len(), 9);
    assert_eq!(AnalyzerCore::MAX_CONTEXTS_BUILD, 255, "the non-REG_TEST compile face");
    // the L1b tail faces (the switcher/local/statics + the distill echo):
    assert_eq!(
        v(6),
        "L1b state=STOPPED switcher=1 local=1 fin=PASS",
        "the exit-state + the statics + the finalize PASS echo"
    );
}

fn strip_prefix<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    s.strip_prefix(p)
}

// ======================================================================
// T11: FACE-A rebuilt NUMERICALLY — the SDK record face + the config
// DEFAULTS + the AC-wall stringify/ref seats (the record-face-only law)
// ======================================================================
#[test]
fn t11_face_a_numeric_rebuild() {
    let fa = lines(VECTORS_FACE_A);
    assert_eq!(fa[0], "AF-a type=1/1 pkthdr=1 len=16 pktlen=120 ts=1700000000.000555");
    assert_eq!(fa[1], "AF-b data=dead ref=1");
    assert_eq!(fa[2], "AF-c types=1,3,4,9 hdr_len=0 meta=1");
    // the enum seats rebuilt from the LANDED consts (the same numeric face):
    let f_enum = format!(
        "AF-f enum={},{},{},{} {},{},{},{}",
        DAQ_MSG_TYPE_PACKET,
        DAQ_MSG_TYPE_PAYLOAD,
        DAQ_MSG_TYPE_SOF,
        DAQ_MSG_TYPE_EOF,
        DAQ_VERDICT_PASS,
        DAQ_VERDICT_IGNORE,
        DAQ_VERDICT_BLACKLIST,
        DAQ_VERDICT_WHITELIST
    );
    assert_eq!(fa[3], f_enum);
    // the SFDAQConfig DEFAULTS record (64 / 1518 — the copy-closure heads
    // face; the port-side mirror of the getter seam rides the world):
    assert_eq!(fa[4], "AF-g batch=64 mru=1518 timeout=1500");
    assert_eq!(fa[5], "AF-g2 set=7,99");
    // the AC-wall command-set stringify names (the NEVER-land facility, the
    // real AC-prefixed classes; NEVER a fabricated ReloadXxx shape):
    assert_eq!(fa[6], "AF-h ac=1 names=PAUSE|RESUME|ROTATE|RUN|START|STOP");
    // the inline ref-count law (get x2 -> 1,2; put -> 1; the reap put()->0):
    assert_eq!(fa[7], "AF-i ref=1,2,1");
    assert_eq!(fa[8], "AF-r idle=3 rx=120 analyzed=1");
    // the record-face-only law (NO private-access flag EVER ships; the
    // banner never recs -> empty legs):
    assert_eq!(fa[9], "AF-s legs-empty=1");
    // the port-side batch DEFAULT cross-check (the world seam arms 64):
    let w = MockWorld::default();
    assert_eq!(w.daq_get_batch_size(), 64);
}

// ======================================================================
// T12: the banner face (cc :890-:905) — stdin rename, the run_num newline
// leg, the EXACT printf face — rebuilt and cmp'd against the LIVE L1 line 5
// ======================================================================
#[test]
fn t12_show_source_banner_face() {
    let mut w = MockWorld::default();
    let (core, _rq) = ctor_pair(&mut w);
    // run_num == 1 -> NO leading newline:
    assert_eq!(
        core.show_source(1, 1518),
        "Reading network traffic from \"d-a\" with snaplen = 1518\n"
    );
    // run_num != 1 -> the newline leg (the probe arms run_num 2 — the LIVE
    // L1 pass prints the face, vectors line 5 rides the blank line seat):
    assert_eq!(
        core.show_source(2, 1518),
        "\nReading network traffic from \"d-a\" with snaplen = 1518\n"
    );
    // the stdin rename seat (cc :569-:570):
    let (mut core2, _rq2) = AnalyzerCore::new(1, Some("-"), 0, 200, &mut w).unwrap();
    core2.exit_after_cnt = 1;
    assert_eq!(
        core2.show_source(1, 1518),
        "Reading network traffic from \"stdin\" with snaplen = 1518\n"
    );
    // the LIVE vectors evidence: line 3 blank = the run_num-2 newline leg
    // landing on its OWN stdout line (the banner printed BEFORE the L1 echo):
    assert_eq!(lines(VECTORS)[3], "");
    // the LIVE banner line rides its OWN stdout line (index 4):
    assert_eq!(
        lines(VECTORS)[4],
        "Reading network traffic from \"d-a\" with snaplen = 1518"
    );
    assert!(VECTORS.contains("Reading network traffic from \"d-a\" with snaplen = 1518"));
    // the null-source ctor face (the cc :815 `s ? s : ""` seat):
    let (core3, _rq3) = AnalyzerCore::new(1, None, 0, 200, &mut w).unwrap();
    assert_eq!(core3.get_source(), "");
}

// ======================================================================
// T13: the census walk — the era face 30/9/22/1 rider-flipped to the LIVE
// 31/9/23/1 at the 24e registry gate (the 62d6fac law) + backbone
// (the 24b control-row walk; NO gate ships HERE — this row NEVER adds one)
// ======================================================================
#[test]
fn t13_census_walk_stays_30_9_22_1() {
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
    assert_eq!(total, 31, "the 24d ZERO-gate row NEVER added a gate (era face 30; rider 30 -> 31 at the 24e registry gate, the 62d6fac law)");
    assert_eq!(frozen, 9, "the legacy 4826fc22 family FROZEN");
    assert_eq!(md5s.len(), 23, "NO new lineage tail from THIS row (era face 22; rider 22 -> 23 at the 24e gate tail, the 62d6fac law)");
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
        .join(concat!("anz", "l_harness"))
        .join("gate.txt");
    assert!(!own.exists(), "the ZERO-gate law: NO gate EVER ships HERE");
    // backbone frozen:
    let bb = std::fs::read(format!("{root}/tools/link4_harness/backbone10.txt")).unwrap();
    assert_eq!(lines(&String::from_utf8_lossy(&bb)).len(), 10);
    assert_eq!(md5_hex(&bb), "5339c7ee501dab8a85277c37dc2d1e0c");
    // the harness tracked face = EXACTLY-7 (the ZERO-gate stageable face):
    let tracked_h = std::process::Command::new("git")
        .args(["-C", root, "ls-files", "--"])
        .arg(format!("tools/{}l_harness", "anz"))
        .output()
        .unwrap()
        .stdout;
    let n = String::from_utf8(tracked_h).unwrap().lines().count();
    // PRE-commit face 0 tolerated (files staged by the SAME commit); POST
    // face EXACTLY-7 asserted by the harness build.sh ls-files guard:
    assert!(n == 0 || n == 7, "tracked faces 0 (PRE) or 7 (POST): {n}");
}

// ======================================================================
// T14: the docs tripwires — the seed x3 faces + the own-token ZERO + the
// mod.rs 8->9 rider-flip face + the landmine NAMING law
// ======================================================================
#[test]
fn t14_docs_seed_token_tripwires() {
    // the 23i dialect law: EVERY harness arm counts LINES (grep -c), NEVER
    // occurrences — a single ledger line can carry the SAME token twice:
    let nf = |needle: &str| NEXTMD.lines().filter(|l| l.contains(needle)).count();
    assert_eq!(nf("855 tests green / 0 FAILED"), 3); // the CURRENT seed x3
    for s in ["841", "825", "810", "798", "784", "772", "763", "752"] {
        assert_eq!(nf(&format!("{s} tests green / 0 FAILED")), 3, "absorbed seed {s} x3");
    }
    // the own joined token NEVER rides NEXT.md (the 23g/24a ZERO law; the
    // docs sibling writes the hyphen form ONLY) — the face runtime-built:
    let mn = format!("{}{}", "anz", "l");
    assert!(!NEXTMD.contains(&mn), "own joined token rides the docs face");
    // the landing + this twin carry ZERO joined own-token (the SELF-scan):
    let own_rs = std::fs::read_to_string("/opt/data/snort3-rust/src/main/analyzer.rs").unwrap();
    assert!(!own_rs.contains(&mn));
    let this = include_str!(concat!("anz", "l_parity_test.rs"));
    assert!(!this.contains(&mn));
    // the PLAN/deviation docs NEVER carry the DONE echo either:
    let plan = std::fs::read_to_string("/opt/data/snort3-rust/PORTING_PLAN.md").unwrap();
    assert!(!plan.contains(&mn));
    // the misc-9 landmine NAMING law: this twin declares NO landmine shape
    // (the face runtime-built so the SELF-check NEVER joins the token):
    let land = format!("{}{}", "struct Tra", "cer");
    assert_eq!(this.matches(land.as_str()).count(), 0);
    // the mod.rs rider-flip face (the 62d6fac complete-flip law):
    let mrs = std::fs::read_to_string("/opt/data/snort3-rust/src/main/mod.rs").unwrap();
    assert_eq!(mrs.lines().count(), 10); // [24c rider 7->8 + 24d rider 8->9 + 24e rider 9->10: the module-registry landing's ONE new wiring line (the 62d6fac law, walked face)]
    assert_eq!(mrs.matches("pub mod analyzer").count(), 1);
    // the row NEVER touches the seed faces (the pin faces UNMOVED):
    assert_eq!(NEXTMD.matches("5 TEST(").count(), 1);
}

// ======================================================================
// T15: the E4 + ZERO-gate ground faces by WALK (the SAME measures the
// harness ships, re-asserted port-side: the pair totals the ledger)
// ======================================================================
#[test]
fn t15_ground_ledger_zero_gate_walk() {
    let g = "/opt/data/snort3-src/src/main";
    let cc = std::fs::read(format!("{g}/analyzer.cc")).unwrap();
    let h = std::fs::read(format!("{g}/analyzer.h")).unwrap();
    let cc = String::from_utf8_lossy(&cc).to_string();
    let hh = String::from_utf8_lossy(&h).to_string();
    assert_eq!(cc.lines().count(), 1164);
    assert_eq!(hh.lines().count(), 177);
    assert_eq!(1164 + 177, 1341, "the pair ledger");
    // the ZERO in-TU TEST faces (the second ZERO-gate control face):
    assert_eq!(cc.matches("TEST_CASE").count(), 0);
    assert_eq!(cc.matches("CHECK(").count(), 0);
    assert_eq!(cc.matches("UNIT_TEST").count(), 0);
    // the ONE friend post h :126 (the dialect host find-0 face):
    assert_eq!(hh.matches("UNIT_TEST_BUILD").count(), 1);
    assert!(hh.contains("friend class AnalyzerTestAccess"));
    // the file-statics census faces (the caller-owned-fields law):
    assert_eq!(
        cc.lines()
            .filter(|l| l.starts_with("static "))
            .count(),
        7,
        "the ^static census"
    );
    assert_eq!(cc.matches("THREAD_LOCAL").count(), 2);
    // the THIRD face cite-ONLY (the main.h seat NEVER lands THIS row):
    let mh = std::fs::read("/opt/data/snort3-src/src/main.h").unwrap();
    let mh = String::from_utf8_lossy(&mh).to_string();
    assert_eq!(mh.lines().count(), 67);
    assert!(mh.contains("extern bool exit_requested"));
    // the row exits through the MEMBER seat, the sibling stays processp's:
    assert_eq!(cc.matches("exit_requested = true").count(), 3, "cc :1097/:1114 (run() codec-fail) + :1128 — the THREE member seats, the sibling main.h :25 face NEVER rides the row TU");
    // the harness NEVER uses a private-access flag (the record-face law):
    let bs = std::fs::read_to_string(concat!(
        "/opt/data/snort3-rust/tools/anz",
        "l_harness/build.sh"
    ))
    .unwrap();
    assert_eq!(bs.matches("fno-access-control").count(), 0);
    assert_eq!(
        lines(&bs)
            .iter()
            .filter(|l| l.contains("4826fc22"))
            .count(),
        5,
        "the legacy-lineage pin face, LINE semantics (the 24b control pattern)"
    );
    assert!(bs.contains("eq 203"), "the closure-pin face");
    assert!(bs.contains("eq 137"), "the nm-census pin face");
}
