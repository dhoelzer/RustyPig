//! Parity test for the row-19a chapter-19 OPENER ports — src/framework/
//! module.rs (the Module base; ground module.cc 403 L md5
//! 9608434cb5d1820d6033a32632080499 + module.h 283 L md5
//! e1c35b873644dac5b00d0fc5e5c903ba) + src/main/reload_tracker.rs (the
//! reload prompt shim; ground cc 89 L md5 bdd9e3d773904514e8672a261fb6fddc
//! plus h 49 L md5 598e08b485165bd2fdc514954b13652b); the 492 SUM re-measured
//! every build by tools/misc9_harness/build.sh. THE DEBT-CLOSE face: this
//! row lands the Module base the 17z/18a rulings banked (file_module.rs:75
//! — "NO Rust Module base forked — the REAL framework/module.o closes it
//! harness-side"; the cite pair the row carries). THE donor-VERBATIM face:
//! harness copy/framework/module.cc == ground byte-ident (md5 equality
//! asserted by build.sh EVERY build — the FIRST row whose 403-L half needs
//! ZERO cps); the tracker half = the ONE fresh cp (E4 face: reload_tracker.h
//! drop kills ONLY the tracker, module SURVIVES).
//!
//! ZERO-gate row (22nd straight): gate-token grep 0 x2 EVERY build + the
//! pair rides NO test CMakeLists SOURCES (grep-0 face) -> NO up_gate_* set:
//! honest absence, census-cited (misc9 PLAN §0/§7). The chapter's REAL gate
//! material = the CppUTest suites (framework/test 3 + main/test 2),
//! dialect-blocked headers find-0 on this host, naming OTHER TUs — NEVER a
//! 26th tracked gate; the frozen 25/9/17/1 echo UNDISTURBED, gre's
//! gate.txt (6751d1a8) stays the ONE tracked gate.
//!
//! Ground truth #1: `tools/misc9_harness/vectors.txt` — the DEC face
//! (probe_dec.cc), 41 L md5 e6328da1f3188df9754b9e45d74897db NEVER
//! edited. WHOLE transcript replays HERE line-for-line as ONE ordered
//! session: 12 message lines through the CARRIED LogMessage seam + their
//! 12 BLANK-line faces (the stubs_18d vprintf body incl. its trailing
//! putchar('\n') — the EV-line printed-stub precedent; the witness
//! +1-vs-+2 correction face, PLAN §9) + the TRK counter/order lines + the
//! MS/SP stats-ladder lines + the order-cite lines. THE R6 EVAL-ORDER RULE
//! REPLAYS (every state call lands as a var BEFORE its print, NEVER
//! reordered). THE -DNDEBUG OBSERVABLE arm: `MS ggc hit=13 miss=0` — the
//! get_global_count wrong-name arm (module.cc :372 assert(false) ELIDES
//! under the production -DNDEBUG arm -> :373 `return 0;` is OBSERVABLE,
//! vectors-pinned; a debug build of the ground ABORTS and the line could
//! NEVER print). The port models the production arm unconditionally (18d
//! autotools-flag != cargo-cfg precedent); this whole replay runs
//! DEBUG-armed and stays assert-clean (the measured harness face: "the
//! tracker ladder is assert-clean BOTH ways").
//!
//! Ground truth #2: `tools/misc9_harness/vectors_faceA.txt` — FACE-A, the
//! FRAMEWORK-TU shape face (probe.cc), 11 L md5
//! dfe738fb8b4200368332ba73b81a4e96. THE spec correction (§8 flagged): the
//! link-era hidden-table -> LOAD -> ver=/size= FACE-A walk NEVER fits a
//! framework TU — line 1 IS the absence face itself (NOLOAD + BUILDING_SO/
//! snort_plugins grep-0 x4); NO `LOAD`-prefixed line, NO `ver=`, NO `size=`
//! EVER (line-anchored, tripwired here + build.sh x2). The real face: REC x3
//! ctor/shape census, the HIDDEN null_params walk (NULLWALK entries=0
//! sentinel_type=21 — the PT_MAX ordinal by the parameter.h enum walk),
//! Command::get_arg_list x2, the 13-arm DEFS default-virtual census
//! (usage=1 = CONTEXT), the VERB verified-trio pair (1/1/1 vs 1/0/1 — the
//! :384 list guard), the order-cite line.

use snort3::framework::counts::{CountType, PegCount, PegInfo};
use snort3::framework::module::{Command, Module, ModuleVirt, NULL_PARAMS, SIMPLE_PEGS};
use snort3::framework::parameter::{Parameter, Type as PtType};
use snort3::framework::value::Value;
use snort3::log::messages::LogEngine;
use snort3::main::reload_tracker::{ControlConnTracker, ReloadTracker};

const VECTORS: &str = include_str!("../tools/misc9_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/misc9_harness/vectors_faceA.txt");
const MODULE_RS: &str = include_str!("../src/framework/module.rs");
const TRACKER_RS: &str = include_str!("../src/main/reload_tracker.rs");
const WITNESS_CC: &str = include_str!("../tools/misc9_harness/witness_misc9.cc");

// ==========================================================================
// The probe-side fixtures — EXACTLY probe.cc / probe_dec.cc's tables.
// ==========================================================================

/// probe.cc:35-39 two_params — the probe table riding the SAME sentinel
/// shape as the ground null_params row (cc:34).
static TWO_PARAMS: [Parameter; 3] = [
    Parameter { name: Some("one"), ptype: PtType::PtInt, deflt: Some("1") },
    Parameter { name: Some("two"), ptype: PtType::PtString, deflt: None },
    Parameter { name: None, ptype: PtType::PtMax, deflt: None }, // the cc:34 sentinel shape
];

/// probe.cc:41 walk_entries — `while (p and p->name) { ++n; ++p; }`.
fn walk_entries(p: Option<&'static [Parameter]>) -> usize {
    p.map_or(0, |p| p.iter().take_while(|q| q.name.is_some()).count())
}

/// the all-default virtual holder (the FACE-A ProbeModule overrides NOTHING
/// — the DEFS census IS the trait-default survey, module.h :92-:222).
struct DefaultVirt;
impl ModuleVirt for DefaultVirt {
    fn get_counts(&mut self) -> Option<&mut [PegCount]> {
        None // h:154-:155 default nullptr face
    }
}

/// probe_dec.cc:46-:51 four_pegs — {SUM "s", NOW "n", MAX "m", END}.
static FOUR_PEGS: [PegInfo; 4] = [
    PegInfo { peg_type: CountType::Sum, name: "s", help: "sum peg" },
    PegInfo { peg_type: CountType::Now, name: "n", help: "now peg" },
    PegInfo { peg_type: CountType::Max, name: "m", help: "max peg" },
    PegInfo { peg_type: CountType::End, name: "", help: "" }, // `CountType::END, nullptr, nullptr`
];

/// pegs-carrier for the replay (the live counters ride the explicit &mut
/// slice param — the cc:169 get_counts() fetch site modelled through the
/// borrow, module.rs header deviation note).
struct PegsVirt;
impl ModuleVirt for PegsVirt {
    fn get_pegs(&self) -> Option<&'static [PegInfo]> {
        Some(&FOUR_PEGS)
    }
    fn get_counts(&mut self) -> Option<&mut [PegCount]> {
        None // the replay's live cells ride the slice param (the get_counts face)
    }
}

/// the store-holding carrier for the get_counts-GATE arms (cc:74-:77 /
/// :343 — the probe's StatsMod override, probe_dec.cc:36-:37).
struct StoreVirt {
    store: [PegCount; 4],
}
impl ModuleVirt for StoreVirt {
    fn get_pegs(&self) -> Option<&'static [PegInfo]> {
        Some(&FOUR_PEGS)
    }
    fn get_counts(&mut self) -> Option<&mut [PegCount]> {
        Some(self.store.as_mut()) // probe_dec.cc:37 const_cast face
    }
}

/// probe_dec.cc:52-:59 SimpleMod — the RESIDENT simple_pegs face (module.o's
/// own table cc :398-:401; the Rust twin SIMPLE_PEGS lands the home).
struct SimpleVirt;
impl ModuleVirt for SimpleVirt {
    fn get_pegs(&self) -> Option<&'static [PegInfo]> {
        Some(&SIMPLE_PEGS) // counts.h:55 extern face, DEFINED at module.cc :398
    }
    fn get_counts(&mut self) -> Option<&mut [PegCount]> {
        None
    }
}

/// Drain the CARRIED-seam LogMessage output into vector lines: each cfmt-
/// rendered text already ends in the format literal's trailing '\n' (the
/// message LINE); the harness seam's end-of-body putchar('\n') produces the
/// BLANK-LINE face right after (24 of the 41 DEC lines ride pairs).
fn drain(log: &LogEngine, mark: &mut usize, out: &mut Vec<String>) {
    for ev in &log.out[*mark..] {
        let body = ev.text.strip_suffix('\n').unwrap_or(&ev.text);
        out.push(body.to_string());
        if ev.text.ends_with('\n') {
            out.push(String::new()); // the seam trailing newline
        }
    }
    *mark = log.out.len();
}

// ==========================================================================
// 1. DEC-face whole-transcript replay — vectors.txt 41 lines, ORDERED,
//    ONE session (probe_dec.cc main() statement order, R6 var-first).
// ==========================================================================
#[test]
fn misc9_dec_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 41, "vectors.txt must hold the full 41-line DEC face");

    let mut out: Vec<String> = Vec::new();

    // ---------------- the reload_tracker ladder (cc sites sed-pinned) ----
    // LogMessage strings print through the CARRIED seam path (ground
    // literals cc :41-:43/:48/:60/:75/:88 — the same five forms build.sh
    // PYPIN greps); every probe call site passes a NULLPTR ControlConn (the
    // "signal" ternary arms; the live-conn + 50-cap face is unit 3).
    let mut log = LogEngine::default();
    let mut mark = 0usize;
    let mut trk = ReloadTracker::default(); // cc :33-:35 static inits

    let s1 = trk.start(&mut log, None); // :37; :47 null -> "signal"; :48 msg
    drain(&log, &mut mark, &mut out);
    out.push(format!("TRK start1 -> {}", i32::from(s1))); // vectors:3

    let s2 = trk.start(&mut log, None); // :39 gate -> :41 msg DOUBLE-arg arm
    drain(&log, &mut mark, &mut out);
    out.push(format!("TRK start2-during -> {}", i32::from(s2))); // vectors:6

    trk.update(&mut log, None, "st"); // :81/:88; NO state change
    drain(&log, &mut mark, &mut out);

    trk.failed(&mut log, None, "why"); // :68/:75; :76 clear, :77 ctrl drop, :78 flag
    drain(&log, &mut mark, &mut out);

    let _s3 = trk.start(&mut log, None); // :46-:49 re-arm after failed
    drain(&log, &mut mark, &mut out);

    let p_before1 = trk.prompt_pulls(); // probe misc9_prompt_calls() face
    trk.end(&mut log, None, true); // :60 msg; :62 TRUE -> :63 show_prompt #1
    drain(&log, &mut mark, &mut out);
    out.push(format!(
        "TRK end-prompt-true delta={}",
        trk.prompt_pulls() - p_before1
    )); // vectors:15

    trk.start(&mut log, None); // :46-:49
    drain(&log, &mut mark, &mut out);
    trk.update(&mut log, None, "st2"); // :88 msg
    drain(&log, &mut mark, &mut out);
    let p_before2 = trk.prompt_pulls();
    trk.end_default(&mut log, None); // h:35 prompt=false -> :62 FALSE -> NO :63
    drain(&log, &mut mark, &mut out);
    out.push(format!(
        "TRK end-prompt-false delta={}",
        trk.prompt_pulls() - p_before2
    )); // vectors:22

    trk.start(&mut log, None); // :46-:49
    drain(&log, &mut mark, &mut out);
    trk.failed(&mut log, None, "x"); // :75 msg (the reason half = the ONLY diff)
    drain(&log, &mut mark, &mut out);
    let s6 = trk.start(&mut log, None); // re-arms after failed -> true
    drain(&log, &mut mark, &mut out);
    out.push(format!("TRK start-after-failed -> {}", i32::from(s6))); // vectors:29
    out.push(String::from(
        "TRK order gate:39-before-log:41 | log:60-before-guard:62->prompt:63 | drop ctrl:64-before-flag:65",
    )); // vectors:30 (the harness PYPIN re-measures these index orders)

    // ---------------- the module stats ladder (probe_dec.cc:88-:113) ----
    let st = PegsVirt; // four_pegs face (the override-free carrier)
    let mut m = Module::new("modS", "stats"); // the cc :62-:63 2-arg ctor
    m.init_stats(&st, true); // :312 new_thread=TRUE -> :327 threads=1 (NO ThreadConfig pull)
    out.push(format!(
        "MS init-true num_counts={} rows={}",
        m.get_num_counts(), // h:159-:160
        m.counts.len()
    )); // walk :322-:324 stops BEFORE the END sentinel (3 / 1)

    // the live store rides the explicit slice param (the ported get_counts
    // face — module.rs header note; the C fetches it at cc:169):
    let mut store: [PegCount; 4] = [0; 4];
    store[0] = 7;
    let _r3 = m.verified_begin(&st, "f", 0); // :376-:380 (table_level++ first, R6 var)
    m.sum_stats(&st, store.as_mut(), false); // SUM :205-:209 add cc:206 THEN clear cc:208
    out.push(format!(
        "MS sum-false cell0={} p0={}",
        m.counts[0][0],
        store[0]
    )); // 7 / 0
    store[0] = 3;
    store[2] = 9;
    m.sum_stats(&st, store.as_mut(), true); // first-dump COPY :178-:182 THEN the add; p NEVER cleared (:207 guard)
    out.push(format!(
        "MS sum-true cell0={} dcell0={} p0={}",
        m.counts[0][0],
        m.dump_stats_counts[0][0],
        store[0]
    )); // 7 / 10 / 3 (dump = copy(7) + add(3))
    store[2] = 2;
    m.sum_stats(&st, store.as_mut(), true); // MAX: 2 > 9 FALSE keep (the :250 h-face arm)
    out.push(format!("MS max-arm dcell2={}", m.dump_stats_counts[0][2])); // 9
    m.main_accumulate_stats(&st); // cc:96-:107 aggregate dump rows -> results [13,0,9]
    out.push(format!(
        "MS ggc hit={} miss={}",
        m.get_global_count(&st, "s"), // :369-:370 name-hit -> results[0] = 13
        m.get_global_count(&st, "nope") // :372/:373 THE -DNDEBUG OBSERVABLE arm -> 0
    )); // 13 / 0
    store[1] = 5;
    m.reset_stats(&st, store.as_mut()); // :354-:355 rows zeroed; :357 p[i]=0 ONLY if type!=NOW -> p1 SURVIVES
    out.push(format!(
        "MS reset cell0={} dcell0={} p0={} p1={} p2={}",
        m.counts[0][0],
        m.dump_stats_counts[0][0],
        store[0],
        store[1],
        store[2]
    )); // 0/0/0/5/0
    m.init_stats_with_max(&st, false, 1); // :327 new_thread=FALSE -> ThreadConfig::get_instance_max (witness_conf 4dd91018: body returns 1) APPENDS one row 1->2 (cc:329-:334)
    out.push(format!(
        "MS init-false rows={} num_counts={}",
        m.counts.len(),
        m.get_num_counts()
    )); // 2 / 3

    // ---------------- the resident simple_pegs face (cc :398-:401) ----
    let mut sm = Module::new("simple", "simple module"); // module.cc :62-:63
    sm.init_stats(&SimpleVirt, true);
    out.push(format!(
        "SP num_counts={} rows={}",
        sm.get_num_counts(),
        sm.counts.len()
    )); // 1 / 1 — ONE real peg + the END-sentinel stop face
    let mut sstore: [PegCount; 2] = [0; 2];
    sstore[0] = 12;
    sm.sum_stats(&SimpleVirt, sstore.as_mut(), false); // SUM cc:206 -> counts[0][0]=12; cc:208 clears p
    out.push(format!(
        "SP sum cell0={} p0={}",
        sm.counts[0][0],
        sstore[0]
    )); // 12 / 0
    out.push(format!(
        "SP ggc-hit={}",
        // :369 hit arm reads dump_stats_results (the resized zero row), NOT
        // the 12 that landed in counts — the vectors' honest 0 face:
        sm.get_global_count(&SimpleVirt, "packets")
    ));
    out.push(String::from(
        "MS order add:cc206-before-clear:cc208 | accumulate:cc96-before-ggc:cc362",
    )); // vectors:41 (measured ground lines, R6 law)

    assert_eq!(out.len(), 41, "replay must produce exactly the 41-line face");
    for (i, w) in want.iter().enumerate() {
        assert_eq!(&out[i], w, "DEC vector line {}", i + 1);
    }
}

// ==========================================================================
// 2. FACE-A whole-transcript replay — vectors_faceA.txt 11 lines, ORDERED.
// ==========================================================================
#[test]
fn misc9_face_a_replay() {
    let want: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(want.len(), 11, "vectors_faceA.txt holds the 11-line framework-TU face");

    let mut out: Vec<String> = Vec::new();

    // line 1 IS the honest absence face — a framework TU loads NO hidden
    // codec table (NOLOAD; BUILDING_SO / snort_plugins grep-0 x4 asserted
    // by build.sh on the ground files + tripwired here): the §8 spec
    // correction says the link-era LOAD/ver=/size= walk NEVER fits here.
    out.push(String::from(
        "NOLOAD framework-TU BUILDING_SO-grep0-x4 snort_plugins-grep0-x4",
    ));

    // ProbeModule a/b/c (probe.cc:47-:49; b/c ride the 3-arg ctor, list
    // false/true at cc:65-:70):
    let a = Module::new("modA", "help A"); // 2-arg ctor h:225
    let mut b = Module::new_params("modB", "help B", Some(&TWO_PARAMS), false); // h:226
    let mut c = Module::new_params("modC", "help C", Some(&TWO_PARAMS), true); // the LIST face cc:65-:68

    // REC x3 (is_table h:117-:118 / is_list h:120-:121 / get_type h:123-:131):
    out.push(format!(
        "REC a is_table={} is_list={} type={}",
        i32::from(a.is_table()),
        i32::from(a.is_list()),
        a.get_type() as u32
    )); // 1/0/0 (PtTable arm h:128)
    out.push(format!(
        "REC b is_table={} is_list={} type={}",
        i32::from(b.is_table()),
        i32::from(b.is_list()),
        b.get_type() as u32
    )); // 1/0/0
    out.push(format!(
        "REC c is_table={} is_list={} type={}",
        i32::from(c.is_table()),
        i32::from(c.is_list()),
        c.get_type() as u32
    )); // 1/1/1 (PtList arm h:125-:126)

    // the HIDDEN null_params walk (cc:32 static -> init cc:59 -> get h:136):
    let ap = a.get_parameters().expect("init installs null_params (cc:59)");
    // the SAME static identity as the module-level NULL_PARAMS table:
    assert!(std::ptr::eq(ap, NULL_PARAMS.as_slice()));
    out.push(format!(
        "NULLWALK entries={} sentinel_type={}",
        walk_entries(a.get_parameters()), // 0 — row 0's name is null (cc:34)
        ap[0].ptype as u32                // 21 — PT_MAX (the parameter.h walk)
    ));

    // Command::get_arg_list over BOTH tables (cc:37-:50):
    let cmd_default = Command {
        name: Some("cmd"),
        func: None,
        params: a.get_parameters(),
        help: None,
        can_run_in_parallel: false, // h:72 NSDMI face
    };
    let cmd_two = Command {
        name: Some("cmd"),
        func: None,
        params: Some(&TWO_PARAMS),
        help: None,
        can_run_in_parallel: false,
    };
    out.push(format!("ARGS default {}", cmd_default.get_arg_list())); // "()" — the :42 gate face
    out.push(format!("ARGS two {}", cmd_two.get_arg_list())); // "(one, two)" — the :44-:45 joiner face

    // the default-virtual census (EVERY arm the module.h DEFAULT body — the
    // ProbeModule in probe.cc overrides NOTHING, probe.cc:27-:30):
    let dv = DefaultVirt;
    out.push(format!(
        "DEFS gid={} rules={} pegs={} cmds={} prof={} defaults={} bind={} agg={} statagg={} global={} prep={} matches={} usage={}",
        dv.get_gid(),                              // h:111-:112 -> 0
        i32::from(dv.get_rules().is_some()),       // h:142 nullptr
        i32::from(dv.get_pegs().is_some()),        // h:145 nullptr
        i32::from(dv.get_commands().is_some()),    // h:139 nullptr
        i32::from(dv.get_profile()),               // h:162 nullptr face
        i32::from(dv.get_defaults().is_some()),    // h:170 nullptr
        i32::from(dv.is_bindable()),               // h:221 false
        i32::from(dv.is_aggregator()),             // h:183 false
        i32::from(dv.stats_are_aggregated()),      // h:178 false
        i32::from(dv.global_stats()),              // h:173 false
        i32::from(dv.counts_need_prep()),          // h:148 false
        i32::from(dv.matches("p")),                // h:107 false (the lua out-param untouched)
        dv.get_usage()                             // h:218 CONTEXT = 1 (the 18d C_USAGE_* import)
    )); // the vectors' 0/0/0/0/0/0/0/0/0/0/0/0/1 census

    // the verified trio (cc :376-:394; R6 var-first: the table_level++
    // :378 mutation lands BEFORE verified_set's guard read :384 — NEVER
    // printf-argument order). Value v(true) = value.h:44 unambiguous arm;
    // Module::set default cc:387 NEVER reads it):
    let mut v_true = Value::from_bool(true);
    let rb = b.verified_begin(&dv, "f", 0); // :376-:380 table_level 0->1
    let rs = b.verified_set(&dv, "f", &mut v_true); // :382-:387 list FALSE -> guard passes
    let re = b.verified_end(&dv, "f", 0); // :390-:394 table_level 1->0
    out.push(format!(
        "VERB table begin={} set={} end={}",
        i32::from(rb),
        i32::from(rs),
        i32::from(re)
    )); // 1/1/1
    let cb = c.verified_begin(&dv, "f", 0); // table_level 0->1
    let cs = c.verified_set(&dv, "f", &mut v_true); // the LIST guard :384 (1 < 2) -> FALSE
    let ce = c.verified_end(&dv, "f", 0); // back to 0
    out.push(format!(
        "VERB list begin={} set={} end={}",
        i32::from(cb),
        i32::from(cs),
        i32::from(ce)
    )); // 1/0/1
    out.push(String::from(
        "order nullwalk:table:32->init:59->get:136 | set-list-guard:384-before-end:390",
    ));

    assert_eq!(out.len(), 11, "FACE-A replay must produce 11 lines");
    for (i, w) in want.iter().enumerate() {
        assert_eq!(&out[i], w, "FACE-A vector line {}", i + 1);
    }
}

// ==========================================================================
// 3. tracker behavior BEYOND the vectors (the arms the null-conn probe
//    never rode, all cc-cited): the LIVE-conn ternary FALSE arm + the
//    substr(0, 50) cap face + the update() no-state-change face + the five
//    ground literals verbatim + the NDEBUG assert-cite faces.
// ==========================================================================
#[test]
fn misc9_tracker_behavior_units() {
    let mut log = LogEngine::default();
    let mark0 = log.out.len();
    let mut trk = ReloadTracker::default();
    // the LIVE-conn face (`ctrlcon ? substr(0,50)`): a 60-char command caps
    // at 50 (cc:43/:47 — the 50-cap face build.sh PYPIN re-reads); the
    // probe NEVER rode it (every vector line = the null "signal" arm).
    let live = ControlConnTracker {
        current_command: Some("x".repeat(60)),
    };
    assert!(trk.start(&mut log, Some(&live))); // cc:47 the substr clamp -> 50
    assert_eq!(log.out.len(), mark0 + 1); // ONE message line
    assert!(log.out[mark0].text.contains(&"x".repeat(50))); // the cap face
    assert!(!log.out[mark0].text.contains(&"x".repeat(51))); // NEVER 51
    assert!(trk.reload_in_progress()); // the :39 gate face after start
    // start-during pairs the OLD cmd with the NEW attempt (cc:41-:43 DOUBLE):
    let live2 = ControlConnTracker { current_command: Some("second".into()) };
    assert!(!trk.start(&mut log, Some(&live2))); // :39 gate -> false
    let second_msg = log.out.last().expect("the in-progress line");
    assert!(second_msg
        .text
        .contains("Reload in progress [xxxxx") // old = the 50-x command
        && second_msg.text.contains("attempting command: [second]"));
    // failed(reason = the FIRST %s) + the ctrl-drop/flag order:
    trk.failed(&mut log, Some(&live), "boom"); // :75
    assert!(!trk.reload_in_progress()); // the :78 drop face
    // failed's :76-:78 drop pair RE-ENABLES start (the vectors:29 face):
    assert!(trk.start(&mut log, Some(&live)));
    // update() changes NOTHING (cc:81-:89 the ONLY entry with zero state):
    trk.update(&mut log, Some(&live), "mid");
    assert!(trk.reload_in_progress());
    trk.end_default(&mut log, Some(&live)); // h:35 default FALSE -> :63 NEVER fires
    assert_eq!(trk.prompt_pulls(), 0);
    trk.start(&mut log, Some(&live));
    trk.end(&mut log, Some(&live), true); // the :63 PULL fires once (body provider-queued)
    assert_eq!(trk.prompt_pulls(), 1);

    // the five ground LogMessage literals ride the port VERBATIM (the same
    // forms build.sh PYPIN against vectors.txt):
    for lit in [
        "Reload in progress [%s], attempting command: [%s]\\n",
        "Reload started. [%s]\\n",
        "Reload ended. [%s]\\n",
        "Reload failed! %s [%s]\\n",
        "Reload update: %s [%s]\\n",
    ] {
        assert!(TRACKER_RS.contains(lit), "ground literal {lit}");
    }
    // the 50-cap face cited + the ternary "signal" arm lands BOTH sites:
    assert!(TRACKER_RS.contains("COMMAND_CAP: usize = 50"));
    assert!(TRACKER_RS.matches("String::from(\"signal\")").count() >= 2);
    // the NDEBUG UNUSED faces ride the cite (cc :55-:57/:70-:72/:83-:85)
    // and the #else assert contracts land as debug_assert cites:
    assert!(TRACKER_RS.matches("UNUSED").count() >= 3);
    for line in ["reload_tracker.cc:58", "reload_tracker.cc:73", "reload_tracker.cc:86"] {
        assert!(TRACKER_RS.contains(line), "debug-arm cite {line}");
    }
    // the show_prompt PULL cite + the provider-queued ruling cited:
    assert!(TRACKER_RS.contains("cc :63") || TRACKER_RS.contains("cc:63"));
    assert!(TRACKER_RS.contains("provider-queued"));
    // the CARRIED seam routes through the landed LogEngine::log_message_
    // stdout (the log_quiet gate cc:215-:217 face) — NEVER a private
    // re-stub of the vprintf body (the multiple-definition law):
    assert!(TRACKER_RS.matches("log_message_stdout").count() >= 5);
}

// ==========================================================================
// 4. null_params / SIMPLE_PEGS table census (the hidden-static identity).
// ==========================================================================
#[test]
fn misc9_table_census() {
    // NULL_PARAMS — cc :32-:35: ONE row, name null, the PT_MAX sentinel:
    assert_eq!(NULL_PARAMS.len(), 1);
    assert_eq!(NULL_PARAMS[0].name, None); // cc:34 `{ nullptr,`
    assert_eq!(NULL_PARAMS[0].ptype, PtType::PtMax);
    assert_eq!(NULL_PARAMS[0].ptype as u32, 21); // the parameter.h enum-walk ordinal (harness PYPIN twin)
    assert_eq!(walk_entries(Some(&NULL_PARAMS)), 0); // the entries=0 face
    // the init install face (cc:59 — the same static, not a copy):
    let init_m = Module::new("x", "y");
    let gp = init_m.get_parameters().expect("init cc:59 installs null_params");
    assert!(std::ptr::eq(gp, NULL_PARAMS.as_slice()));
    // SIMPLE_PEGS — cc :398-:401 VERBATIM rows:
    assert_eq!(SIMPLE_PEGS.len(), 2);
    assert_eq!(SIMPLE_PEGS[0].peg_type, CountType::Sum);
    assert_eq!(SIMPLE_PEGS[0].name, "packets");
    assert_eq!(SIMPLE_PEGS[0].help, "total packets");
    assert_eq!(SIMPLE_PEGS[1].peg_type, CountType::End); // cc:401 `END, nullptr, nullptr`
    // the walk helper (probe.cc:41) + the sentinel stop:
    assert_eq!(walk_entries(Some(&TWO_PARAMS)), 2);
    assert_eq!(TWO_PARAMS[2].name, None);
    // the get_name fallback h:114-:115 name-null -> params->name face:
    let pmod = Module::new_params("modN", "h", Some(&TWO_PARAMS), false);
    assert_eq!(pmod.get_name(), Some("modN")); // name present arm
    // the name-less params->type arm (h:130) is NOT reachable through the
    // public ctor pair (name is &str, "" is NOT the C nullptr) — cite-only
    // honesty; ""-named module rides the h:117 name-ptr TRUE arm:
    let fallback = Module::new_params("", "h", Some(&NULL_PARAMS), false);
    assert_eq!(fallback.get_name(), Some("")); // C `name ?` tests the POINTER: "" != nullptr
    assert_eq!(fallback.get_type(), PtType::PtTable); // is_table TRUE face (h:128)
}

// ==========================================================================
// 5. Command::get_arg_list edge arms (cc:42/:44/:45 gates + h:72 NSDMI).
// ==========================================================================
#[test]
fn misc9_command_arg_list_units() {
    let null_cmd = Command { name: None, func: None, params: Some(&NULL_PARAMS), help: None, can_run_in_parallel: false };
    assert_eq!(null_cmd.get_arg_list(), "()"); // cc:42 gate stops AT row 0
    let bare = Command { name: None, func: None, params: None, help: None, can_run_in_parallel: false };
    assert_eq!(bare.get_arg_list(), "()"); // cc:40 `p = params` null face
    static ONE_PARAM: [Parameter; 2] = [
        Parameter { name: Some("~pos"), ptype: PtType::PtInt, deflt: None },
        Parameter { name: None, ptype: PtType::PtMax, deflt: None },
    ];
    let sc = Command { name: None, func: None, params: Some(&ONE_PARAM), help: None, can_run_in_parallel: false };
    assert_eq!(sc.get_arg_list(), "(~pos)"); // the joiner guard cc:44 (p != params)
    assert!(!sc.can_run_in_parallel); // h:72 NSDMI `= false` face
    // the LuaCFunction token posture (h:63; no fn pointers in the Rust
    // tree — 18a lineage, deviation row 19a):
    assert!(MODULE_RS.contains("pub struct LuaCFunctionToken;"));
    assert!(!MODULE_RS.contains("dyn Fn("));
    // get_name's params fallback face over a null name + first-row name:
    static NAMED: [Parameter; 2] = [
        Parameter { name: Some("fb"), ptype: PtType::PtString, deflt: None },
        Parameter { name: None, ptype: PtType::PtMax, deflt: None },
    ];
    let fb = Module::new_params("", "h", Some(&NAMED), false); // "" != nullptr in C -> keep; use the None-slot fallback via NULL_PARAMS-style instead:
    assert_eq!(fb.get_name(), Some("")); // C `name ? name : ...` with "" -> Some("") (the C nullptr test is on the POINTER, not emptiness)
    let _ = fb; // (the true fallback arm needs the Option None name — unexpressible through the public ctor pair; h:114 cited in module.rs, accessor face pinned through get_parameters above)
}

// ==========================================================================
// 6. the stats family BEYOND the vectors (the get_counts-GATE arms +
//    cc:72/:164-:310 heads + the global_stats direct-assigned pair + the
//    aggregate skip/keep faces + the helper pair), all cc-cited.
// ==========================================================================
#[test]
fn misc9_stats_family_units() {
    // --- clear_global_active_counters (cc:72-:94): NOW cells zero across
    // rows+results; SUM/MAX untouched. The cc:74-:77 null-counts gate needs
    // a StoreVirt (get_counts Some); cc:79-:81 assert(q) clean.
    let mut sv = StoreVirt { store: [0; 4] };
    let mut m = Module::new("cgac", "cgac");
    m.init_stats_with_max(&sv, false, 2); // rows 2, num_counts 3 (four_pegs walk)
    for row in &mut m.counts {
        row[0] = 7;
        row[1] = 5;
        row[2] = 9;
    }
    for row in &mut m.dump_stats_counts {
        row[0] = 11;
        row[1] = 13;
        row[2] = 17;
    }
    m.dump_stats_results = vec![19, 23, 29];
    m.clear_global_active_counters(&mut sv);
    for row in &m.counts {
        assert_eq!([row[0], row[1], row[2]], [7, 0, 9]); // SUM/MAX stay; NOW zeroed cc:86-:89
    }
    for row in &m.dump_stats_counts {
        assert_eq!([row[0], row[1], row[2]], [11, 0, 17]); // cc:88
    }
    assert_eq!(&m.dump_stats_results, &[19, 0, 29]); // cc:90 the NOW result cell
    // --- dump-results set/copy/clear (cc:272-:295 the three gates):
    m.set_dump_stats_results(&sv, &[100, 101, 102]); // size == num_counts ok (cc:283)
    assert_eq!(m.get_dump_stats_results(), &[100, 101, 102]); // cc:286-:289
    m.set_dump_stats_results(&sv, &[1, 2]); // cc:280 size-mismatch gate -> NO copy
    assert_eq!(m.get_dump_stats_results(), &[100, 101, 102]);
    m.clear_dump_stats_state(); // cc:291-:295 re-arm (num_counts > 0 guard)
    assert_eq!(m.dump_stats_initialized, vec![0, 0]);
    // first-dump copy RE-fires after the clear (the cc:178-:182 face again):
    let mut store: [PegCount; 4] = [4, 0, 0, 0];
    let _ = m.verified_begin(&sv, "f", 0);
    m.sum_stats(&sv, store.as_mut(), true); // copy counts[0] ([7,0,9]) THEN SUM add 4
    assert_eq!(m.dump_stats_counts[0][0], 7 + 4); // 11
    assert_eq!(m.dump_stats_initialized, vec![1, 0]); // only instance 0 re-armed
    // --- show_stats_and_clear (cc:303-:310; the renderer half cited-never-
    // land, the residue seam face) + show_interval_stats guard (cc:297-):
    assert!(m.show_stats_and_clear()); // num_counts 3 > 0
    assert_eq!(m.dump_stats_initialized, vec![0, 0]); // the cc:308 clear arm
    assert!(m.show_interval_stats_guard(&mut sv)); // the cc:299 guard face (counts+pegs live)
    // --- init_stats null-pegs gate (cc:316): a no-pegs carrier NO-OPs:
    let dv = DefaultVirt; // get_pegs default None
    let mut m0 = Module::new("np", "np");
    m0.init_stats(&dv, false);
    assert!(m0.counts.is_empty() && m0.num_counts == -1); // the :316 return face
    // the sum_stats head init (cc:166-:167 init_stats(false) on negative):
    let mut fresh = Module::new("fresh", "fresh");
    let mut fstore: [PegCount; 4] = [6, 0, 0, 0];
    fresh.sum_stats(&PegsVirt, fstore.as_mut(), false); // head walk -> nc 3 rows 1 -> SUM 6
    assert_eq!(fresh.counts[0][0], 6);
    assert_eq!(fstore[0], 0); // the cc:208 clear
    // --- global_stats direct-assigned arms (cc:184-:195):
    struct GlobVirt;
    impl ModuleVirt for GlobVirt {
        fn get_pegs(&self) -> Option<&'static [PegInfo]> {
            Some(&FOUR_PEGS)
        }
        fn global_stats(&self) -> bool {
            true // the cc:184 TRUE arm
        }
        fn get_counts(&mut self) -> Option<&mut [PegCount]> {
            None
        }
    }
    let mut g = Module::new("gs", "gs");
    g.init_stats(&GlobVirt, true);
    let mut gstore: [PegCount; 4] = [77, 0, 0, 0];
    g.sum_stats(&GlobVirt, gstore.as_mut(), false); // counts[0][i] = p[i] direct cc:193; NO clear on this path
    assert_eq!(g.counts[0][0], 77);
    assert_eq!(gstore[0], 77); // the honest no-clear contrast (NOT the per-peg switch)
    g.sum_stats(&GlobVirt, gstore.as_mut(), true); // first-dump copy THEN results = p direct cc:191
    assert_eq!(g.dump_stats_results[0], 77);
    // --- collect_dump_stats_counts (cc:226-:270; the cited-never-vectored
    // face fully ported):
    let mut c = Module::new("col", "col");
    c.init_stats(&PegsVirt, true); // nc 3 rows 1
    for row in &mut c.counts {
        row[0] = 10;
        row[1] = 20;
        row[2] = 30;
    }
    let mut live: [PegCount; 4] = [3, 4, 5, 0];
    let mut outv: Vec<PegCount> = Vec::new();
    c.collect_dump_stats_counts(&PegsVirt, live.as_mut(), &mut outv);
    // SUM cc:262 = 10+3; NOW shares the SUM/NOW arm = 20+4; MAX cc:266 =
    // max(5, 30) = 30:
    assert_eq!(outv, vec![13, 24, 30]);
    // the stale-instance face (cc:249-:251): assign stays, NO merge:
    struct IdVirt;
    impl ModuleVirt for IdVirt {
        fn get_pegs(&self) -> Option<&'static [PegInfo]> {
            Some(&FOUR_PEGS)
        }
        fn get_instance_id(&self) -> u32 {
            9 // the 17l thread-static face (instance 9 out of a 1-row table)
        }
        fn get_counts(&mut self) -> Option<&mut [PegCount]> {
            None
        }
    }
    let mut outv3: Vec<PegCount> = Vec::new();
    let mut live3: [PegCount; 4] = [1, 1, 1, 0];
    c.collect_dump_stats_counts(&IdVirt, live3.as_mut(), &mut outv3);
    assert_eq!(outv3, vec![0, 0, 0]); // cc:240 assigned, cc:251 returned
    // the !num_counts gate (cc:234-:237 clear face) on a fresh module:
    let mut fresh2 = Module::new("g4", "g4");
    let mut outv4: Vec<PegCount> = vec![7];
    let mut live4: [PegCount; 4] = [0; 4];
    // fresh2 num_counts -1 -> head init_stats fires (cc:228) so the gate
    // passes with FOUR_PEGS; force the gate via a NO-pegs carrier + empty p:
    fresh2.num_counts = 0; // the explicit cc:234 `num_counts <= 0` arm
    fresh2.collect_dump_stats_counts(&PegsVirt, live4.as_mut(), &mut outv4);
    assert!(outv4.is_empty()); // the cc:236 out.clear() face
    // --- the aggregate ptr overload skip/keep face (cc:132-:157):
    let rows: Vec<Vec<PegCount>> = vec![vec![1, 0, 0], vec![9, 9]];
    let short = rows.get(1); // len 2 != 3 -> the cc:139 continue face
    let ptrs: [Option<&Vec<PegCount>>; 4] = [Some(&rows[0]), None, short, Some(&rows[0])];
    let mut agg: Vec<PegCount> = Vec::new();
    Module::aggregate_dump_stats_counts_ptrs(&FOUR_PEGS, 3, &ptrs, &mut agg);
    assert_eq!(agg, vec![2, 0, 0]); // two full rows add; the short row + null skip
    let rows2: Vec<Vec<PegCount>> = vec![vec![0, 0, 9], vec![0, 0, 4]];
    let ptrs2: Vec<Option<&Vec<PegCount>>> = rows2.iter().map(Some).collect();
    let mut agg2: Vec<PegCount> = Vec::new();
    Module::aggregate_dump_stats_counts_ptrs(&FOUR_PEGS, 3, &ptrs2, &mut agg2);
    assert_eq!(agg2, vec![0, 0, 9]); // cc:155 4 > 9 FALSE keep face
    // the value-rows overload FORWARDS identically (cc:118-:123):
    let mut agg3: Vec<PegCount> = Vec::new();
    Module::aggregate_dump_stats_counts(&FOUR_PEGS, 3, &rows2, &mut agg3);
    assert_eq!(agg3, vec![0, 0, 9]);
    // the empty-table NO-OP head (cc:115 `!pegs`; the num_counts<=0 twin too):
    let mut agg4: Vec<PegCount> = Vec::new();
    Module::aggregate_dump_stats_counts(&[], 3, &rows2, &mut agg4);
    Module::aggregate_dump_stats_counts(&FOUR_PEGS, 0, &rows2, &mut agg4);
    assert!(agg4.is_empty());
    // --- the helper trio (h:236-:267 dump-vs-live pair + the two keeps):
    let mut h = Module::new("helpers", "h");
    h.init_stats(&PegsVirt, true); // nc 3 rows 1
    h.add_peg_count(0, 5, false, 0); // h:266
    h.set_max_peg_count(2, 3, false, 0); // h:256
    h.set_max_peg_count(2, 1, false, 0); // h:255 the 1 > 3 FALSE keep
    h.set_peg_count(1, 42, false, 0); // h:242
    assert_eq!(h.counts[0], vec![5, 42, 3]);
    h.add_peg_count(0, 5, true, 0); // h:264
    h.set_max_peg_count(2, 4, true, 0); // h:251
    h.set_peg_count(1, 99, true, 0); // h:240
    assert_eq!(h.dump_stats_counts[0], vec![5, 99, 4]);
    // reset_stats BOTH gates (cc:343 empty-p return / cc:348 null-pegs):
    let mut fresh3 = Module::new("rst", "rst");
    let mut nop: [PegCount; 0] = [];
    fresh3.reset_stats(&PegsVirt, nop.as_mut()); // the cc:343 arms, NO panic
    assert_eq!(fresh3.num_counts, -1);
    let mut nopv = DefaultVirt; // null pegs -> the cc:348 return
    let mut one: [PegCount; 1] = [5];
    fresh3.reset_stats(&nopv, one.as_mut()); // guard returns (num_counts<0 loop no-op anyway)
    assert_eq!(one[0], 5);
    // get_global_count: hit reads RESULTS (the SP 0-face twin, NOT counts):
    let mut t = Module::new("res", "res");
    t.init_stats(&SimpleVirt, true); // nc 1, results len 1 zero
    let mut s4: [PegCount; 2] = [12, 0];
    t.sum_stats(&SimpleVirt, s4.as_mut(), false); // counts[0][0] = 12, p cleared
    assert_eq!(t.counts[0][0], 12);
    assert_eq!(s4[0], 0);
    assert_eq!(t.get_global_count(&SimpleVirt, "packets"), 0); // results stay 0 — the vectors' SP face
    // set_dump_stats_results then hit reads the NEW value (the cc:283 copy):
    t.set_dump_stats_results(&SimpleVirt, &[13]);
    assert_eq!(t.get_global_count(&SimpleVirt, "packets"), 13);
    // the short-results clamp (panic-free):
    t.set_dump_stats_results(&SimpleVirt, &[]); // size gate cc:280 refuses (nc 1)
    assert_eq!(t.get_global_count(&SimpleVirt, "packets"), 13); // still the ok copy
    // miss arm = the -DNDEBUG OBSERVABLE 0 (vectors-pinned arm):
    assert_eq!(t.get_global_count(&SimpleVirt, "no-such-peg"), 0);
    // show_* guards on a NO-counts module (cc:299/:305 false arms):
    assert!(!fresh3.show_stats_and_clear());
    assert!(!fresh3.show_interval_stats_guard(&mut nopv));
}

// ==========================================================================
// 7. the verified-trio arm matrix (cc :376-:394) beyond FACE-A: nesting
//    depth (table_level) and the :384 boundary at table_level == 2.
// ==========================================================================
#[test]
fn misc9_verified_trio_units() {
    let dv = DefaultVirt;
    // LIST module (the cc:384 guard): level 1 -> FALSE, level 2 NOT < 2:
    let mut lcm = Module::new_params("listC", "h", Some(&TWO_PARAMS), true);
    let mut v = Value::from_bool(true);
    assert!(lcm.verified_begin(&dv, "outer", 0)); // table_level 0->1
    assert!(!lcm.verified_set(&dv, "x", &mut v)); // 1 < 2 -> FALSE (cc:384-:385)
    assert!(lcm.verified_begin(&dv, "inner", 1)); // the list-ITEM face: level 2
    assert!(lcm.verified_set(&dv, "y", &mut v)); // 2 NOT < 2 -> set (:387)
    assert!(lcm.verified_end(&dv, "inner", 1)); // level 1
    assert!(!lcm.verified_set(&dv, "z", &mut v)); // guard fires again
    assert!(lcm.verified_end(&dv, "outer", 0)); // back to 0
    // TABLE module: NO guard at ANY depth (list false, the FACE-A set=1):
    let mut tcm = Module::new("tab", "h");
    assert!(tcm.verified_begin(&dv, "t", 0));
    assert!(tcm.verified_set(&dv, "s", &mut v));
    assert!(tcm.verified_begin(&dv, "t2", 1)); // nested table (the level>=2 arm)
    assert!(tcm.verified_set(&dv, "s2", &mut v)); // guard never arms
    // the begin/end default TRUEs (h:92-:96) ride EVERY arm above.
}

// ==========================================================================
// 8. tripwires + module-identity census (the harness grep-0 faces re-driven
//    rs-side: the framework-TU NEVER grows a codec-table face; the
//    ordinal/identity census; the witness carried-seam face; the -DNDEBUG
//    arm cite faces; the NEVER-fabricated provider posture; the zero-gate
//    posture).
// ==========================================================================
#[test]
fn misc9_tripwires_and_census() {
    // ---- THE framework-TU absence faces (the FACE-A line-1 law): ----
    assert!(VECTORS_FACE_A.lines().next().unwrap().starts_with("NOLOAD"));
    // line-anchored: NO LOAD/ver=/size= line EVER lands (build.sh x2 twins):
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("LOAD")).count(), 0);
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("ver=")).count(), 0);
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("size=")).count(), 0);
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("GETIDS")).count(), 0);
    assert_eq!(VECTORS_FACE_A.lines().filter(|l| l.starts_with("GETDLT")).count(), 0);
    // the codec-table tokens live ONLY inside line 1 (the grep-0 RECORD
    // text), never as code faces, and NEVER across the DEC file:
    assert_eq!(VECTORS.matches("BUILDING_SO").count(), 0);
    assert_eq!(VECTORS.matches("snort_plugins").count(), 0);
    assert_eq!(
        VECTORS_FACE_A.lines().skip(1).filter(|l| l.contains("BUILDING_SO") || l.contains("snort_plugins")).count(),
        0
    );
    assert_eq!(VECTORS.matches("cd_").count(), 0); // NO codec name EVER
    assert_eq!(VECTORS.lines().filter(|l| l.starts_with("EV ")).count(), 0); // NO event queue in a framework row
    // the rs-side NEVER-land twin (the hidden-table CODE face):
    assert!(!MODULE_RS.contains("#[no_mangle]"));
    assert!(!TRACKER_RS.contains("#[no_mangle]"));
    assert!(!MODULE_RS.contains("extern \"C\"")); // NO dso-shim face in a framework TU
    assert!(!TRACKER_RS.contains("extern \"C\""));
    // ---- module-identity ordinal census (every vector print's ordinal): --
    assert_eq!(PtType::PtTable as u32, 0); // REC type=0
    assert_eq!(PtType::PtList as u32, 1); // REC type=1
    assert_eq!(PtType::PtMax as u32, 21); // NULLWALK sentinel_type=21
    assert_eq!(CountType::End as u32, 0);
    assert_eq!(CountType::Sum as u32, 1);
    assert_eq!(CountType::Now as u32, 2);
    assert_eq!(CountType::Max as u32, 3); // the counts.h walk (harness PYPIN twin)
    assert_eq!(DefaultVirt.get_usage(), 1); // DEFS usage=1 CONTEXT (the 18d resident import)
    // ---- the donor md5 + debt cites present in the rs docs: ----
    assert!(MODULE_RS.contains("9608434cb5d1820d6033a32632080499")); // module.cc (the harness copy==ground face)
    assert!(MODULE_RS.contains("e1c35b873644dac5b00d0fc5e5c903ba")); // module.h
    assert!(TRACKER_RS.contains("bdd9e3d773904514e8672a261fb6fddc")); // reload_tracker.cc
    assert!(TRACKER_RS.contains("598e08b485165bd2fdc514954b13652b")); // reload_tracker.h
    assert!(MODULE_RS.contains("file_module.rs:75")); // THE debt cite closed
    assert!(MODULE_RS.contains("NO Rust Module base forked"));
    // ---- the witness face (the +1 correction; LogMessage carried): the own
    //      witness defines show_prompt ONLY and misc9_prompt_calls; it NEVER
    //      carries a second LogMessage BODY (the multiple-definition law —
    //      stubs_18d owns that seam):
    assert!(WITNESS_CC.contains("ControlConn::show_prompt()"));
    assert!(WITNESS_CC.contains("misc9_prompt_calls()"));
    assert!(!WITNESS_CC.contains("void LogMessage"));
    assert!(!WITNESS_CC.contains("LogMessage(const char* format"));
    // ---- the -DNDEBUG arm faces (cited BOTH rs files + the vectors): ----
    assert!(MODULE_RS.contains("assert(false); // wrong name = programmer error")); // cc:372 verbatim cite
    assert!(MODULE_RS.contains("return 0;") ); // the cc:373 model (its cite beside it)
    assert_eq!(VECTORS.lines().filter(|l| l.starts_with("MS ggc")).count(), 1);
    assert!(VECTORS.contains("MS ggc hit=13 miss=0")); // THE OBSERVABLE arm
    // the four order-cite lines ride the vectors EXACTLY-1 each:
    for cite in [
        "TRK order gate:39-before-log:41",
        "add:cc206-before-clear:cc208",
        "accumulate:cc96-before-ggc:cc362",
        "set-list-guard:384-before-end:390",
    ] {
        assert_eq!(
            VECTORS.matches(cite).count() + VECTORS_FACE_A.matches(cite).count(),
            1,
            "order cite {cite}"
        );
    }
    // ---- ladder NEVEr re-walks the codec backbone (residents rule): ----
    assert!(!MODULE_RS.contains("use crate::codecs::codec_api"));
    assert!(MODULE_RS.contains("use crate::codecs::codec_module::{C_USAGE_CONTEXT, RuleMap};")); // imports ONLY
    assert!(!MODULE_RS.contains("pub struct RuleMap")); // NEVER re-forked (codec_module.rs:253 home)
    assert!(!MODULE_RS.contains("C_USAGE_GLOBAL: u32")); // NEVER re-authored (codec_module.rs:273 home)
    assert!(!MODULE_RS.contains("pub const GENERAL_DECODE_RULES"));
    // ---- gate posture (22nd straight): this row adds NO suite/gate: ----
    assert!(!MODULE_RS.contains("up_gate_"));
    assert!(!TRACKER_RS.contains("up_gate_"));
    // ---- the control.h non-participant face (E4: it kills ONLY the
    //      tracker; the module port NEVER reaches that header — the
    //      ControlConn MENTION in module.rs docs rides the response_buf
    //      trait lineage cite ONLY, NEVER an include face):
    assert!(!MODULE_RS.contains("control/control.h"));
    assert!(TRACKER_RS.contains("control.h"));
    // ---- NEVER-fabricated provider posture: show_prompt lands as the
    //      PULL-SITE count ONLY (counter + provider-queued cite):
    assert!(!TRACKER_RS.contains("fn show_prompt"));
    assert!(TRACKER_RS.contains("prompt_pulls"));
    assert!(TRACKER_RS.contains("witness_misc9"));
    // ---- the carried seam posture: the port NEVER re-stubs LogMessage's
    //      vprintf body (stubs_18d owns it; LogEngine owns the Rust twin) —
    //      the CITE text mentions vprintf, no CALL face ever lands:
    assert!(!TRACKER_RS.contains("vprintf("));
    assert!(TRACKER_RS.contains("log::messages::LogEngine"));
    // ---- P1 zero-cp honesty face (module half) vs the tracker 1-cp face:
    assert!(MODULE_RS.contains("ZERO cps"));
    assert!(TRACKER_RS.contains("ONE fresh cp") || TRACKER_RS.contains("one fresh cp"));
}
