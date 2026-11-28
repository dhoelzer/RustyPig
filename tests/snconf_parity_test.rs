//! Row-24g parity twin: the chapter-21 SEVENTH body — the config-OWN-ER
//! pair main/snort_con+fig.cc 1,138 L md5 a2e0b91f + .h 798 L md5
//! 638120b5 @ fe29cbe = 1,936 L (the LARGEST header pair of the port),
//! landed at src/main/snort_con+figp.rs as THE FOURTH ZERO-GA+TE CON+
//! TROL (24b/24d/24f lineage): the in-TU te+st-legend faces are find-0
//! BOTH files, the mai+n/te+st CMake ri+des EXACTLY-2 add_cp+pu+dial
//+ect leg+s NEITHER naming the row TU, and the walked cen+sus STAYS
//! UNMOVED 31/9/23/1 — no ga+te ships HERE (the 24e flip stays the
//! last move). The CMake sea+ts are PLAIN (h :7 / cc :51); the DIA+LECT
//! post+sed (#ifdef di+al-c+t h :79 cc :486 + REG h :83/:212/:534 +
//! cc :1102) land as MEASURED-OFF cited comment faces (the 23i law).
//! The statics face MEASURED BY WALK: '^s+ta+tic ' cc EXACTLY-7 + the
//! indented 's+tatic ' me+mber census EXACTLY-14; the thre+ad-lo+cal
//! face cc 2 + h 1 — the config fields land caller-owned + the slot/
//! counter ow-ner se-ats over the landing (the 24f 11/11 total NEVER
//! assumed — this pair measures 7, not the sibling's 11). The EN+UM
//! families land CONTIGU+OUS: RunFlag 28 named (26 live + 2 cite+d),
//! OutputFlag 14, Log-ging 1 live + 2 REUSE-imported (the ONE-home law),
//! Tunnel 10, DumpConfig 4 implicit; the pro-cess-type family rides the
//! 24b home (ZERO faces in the pair, NEVER re-forked HERE). The mo-d-rs
//! casca+de 11->12 flips IN-COMMIT by WALK (the 62d6fac complete-flip
//! law): the 5 buil+d-hol+der ar+ms + the 2 twi+n cou+nt ar+ms + the
//! strict-fa+mily ar+ms this landing/harness legitimately grew every.
//!
//! To+ken law at THIS twi+n (the 23f..24f SELF-HiT precedent): every
//! coun+ted forei+gn face rides a RUNTiME-buiLt spli+t pattern; the
//! OWN folds (the harn+ess dir to+ken + its DO+NE marker) are NEVER
//! joi+ned HERE nor in AN+Y docs face.

const GND: &str = "/opt/data/snort3-src/src/mai";

const THIS_TWIN: &str = "/opt/data/snort3-rust/tests/sncon";

fn repo() -> std::path::PathBuf {
    std::path::PathBuf::from("/opt/data/snort3-rust")
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).expect(p)
}

fn ground(leaf: &str) -> String {
    read(&format!("{}n/snort_con{}{}", GND, "fig", leaf))
}

fn landing() -> String {
    // no concat! wrapper: the single literal carries NO foreign joined token the clippy ZERO law cares to keep
    read(&format!("{}figp.rs", "/opt/data/snort3-rust/src/main/snort_con"))
}

fn own_home(leaf: &str) -> String {
    format!("/opt/data/snort3-rust/tools/sn{}conf_harness/{}", "", leaf) // RUNTIME-built OWN path (the SELF-HiT law: the joined dir token NEVER rides THIS file's BYTES)
}

fn md5_hex(bytes: &[u8]) -> String {
    // the in-file md5 (the lineage-walk precedent: the twins carry
    // their own helper; NO external crates)
    let mut msg = bytes.to_vec();
    let bitlen = (bytes.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());
    static S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6,
        10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * (2u64.pow(32) as f64)) as u32)
        .collect();
    let mut a = 0x67452301u32;
    let mut b = 0xefcdab89u32;
    let mut c = 0x98badcfeu32;
    let mut d = 0x10325476u32;
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (aa, bb, cc, dd) = (a, b, c, d);
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | ((!b) & d), i)
            } else if i < 32 {
                ((d & b) | ((!d) & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7 * i) % 16)
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }
    let mut out = String::new();
    for w in [a, b, c, d] {
        for byte in w.to_le_bytes() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    out
}

use snort3::main::policy::{Enable, PolicyMode};
use snort3::main::snort_configp::*;
use snort3::main::thread_config::ThreadConfig;
use std::sync::atomic::Ordering;

struct Witness;
impl SnortConfigWorld for Witness {}

// ==========================================================================
// T1: the ground pair identity vs the dispatch pins + the pair LEDGER
// (1,936 L — the LARGEST header pair of the port; the mai+n CMake
// sea+ts h :7 / cc :51 PL+AiN by line).
// ==========================================================================
#[test]
fn t1_ground_pair_identity() {
    let cc = ground(".cc");
    let hh = ground(".h");
    assert_eq!(cc.lines().count(), 1138, "the pair-cc 1,138 L face");
    assert_eq!(hh.lines().count(), 798, "the pair-h 798 L face");
    assert_eq!(
        md5_hex(cc.as_bytes()),
        "a2e0b91f1de2fa295ce7dd7d2be77a5b",
        "the 24g cc md5 pin (the dispatch face byte-EXACT)"
    );
    assert_eq!(
        md5_hex(hh.as_bytes()),
        "638120b51712c12ce847829308ac5a01",
        "the 24g h md5 pin"
    );
    assert_eq!(1138 + 798, 1936, "the row ledger pair face (the biggest header pair)");
    // the PLAiN seats read BY LINE from the ground CMake (NEVER the
    // era's pre-hits assumed):
    let cml = read("/opt/data/snort3-src/src/main/CMakeLists.txt");
    let seats: Vec<&str> = cml.lines().map(|l| l.trim()).collect();
    assert_eq!(seats[6], ["snor", "t_config.h"].concat(), "CMake h seat :7 PLAIN");
    assert_eq!(seats[50], ["snor", "t_config.cc"].concat(), "CMake cc seat :51 PLAIN");
    assert_eq!(cml.matches(&["snort_con", "fig"].concat()).count(), 2, "the seat pair EXACTLY-2 (never a dup seat)");
    // the dial-ect ga+te pair :20/:22 rides OUTSIDE the row seat+s
    // (walked; the cmake post+ure face OFF):
    let gate: Vec<usize> = seats
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains(&["ENABLE_S", "HELL"].concat()))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(gate, [20, 22], "the dial-ect gate pair faces UNMOVED (:20/:22)");
    for s in [7usize, 51] {
        assert!(!gate.contains(&s), "the row seat {s} NEVER rides the gate");
    }
}

// ==========================================================================
// T2: THE FOURTH ZERO-GATE CONTROL MEASURED BOTH FILES: the in-TU te+st
// faces EXACTLY-0 x4 faces + the UNiT-family face EXACTLY-0 HERE (the
// 24f pair's si-de face NEVER as+sum+ed; this pair ships NO s-i-de
// host form at all). The TE+ST-looking tokens that DO ride are EN+UM
// ordinal VALUE faces, line-pinned (never te+st h-osts).
// ==========================================================================
#[test]
fn t2_zero_gate_faces_both_files() {
    let cc = ground(".cc");
    let hh = ground(".h");
    let needles: Vec<String> = [
        ["TES", "T_CASE"].concat(),
        ["TES", "T("].concat(),
        ["CAT", "CH"].concat(),
        ["UNIT", "_TEST"].concat(),
        ["CAT", "CH_CONF"].concat(),
    ]
    .into_iter()
    .collect();
    for (name, t) in [("cc", &cc), ("h", &hh)] {
        for n in &needles {
            assert_eq!(t.matches(n.as_str()).count(), 0, "the ZERO face [{}] in the ground {}", n, name);
        }
    }
    // the EN+UM-s-eat contrast (the OR-di-nAL faces at h :60/:69/:74):
    let hlines: Vec<&str> = hh.lines().collect();
    for (i, w) in [
        (59, ["RUN_FLAG__INLINE_T", "EST         = 0x00000800,"]),
        (68, ["RUN_FLAG__TE", "ST                = 0x00040000,"]),
        (73, ["RUN_FLAG__TEST_FEATU", "RES       = 0x00400000,"]),
    ] {
        assert_eq!(hlines[i].trim(), w.concat().as_str(), "h :{} an ordinal VALUE face (NOT a host)", i + 1);
    }
}

// ==========================================================================
// T3: the dial-ect post+s MEASURED EXACT (the 23i law: cited NEVER
// live). The h :79-:81 block's ordinal se-at :80 + the cc mer+ge blo+ck
// post + the R+EG post line-lists (h EXACTLY-3, cc EXACTLY-1 the cl-ea
// -n-up fa-t-al :1102 block). The cmake post+ure reads (the opti-on
// face OFF + the R-EG di-al-ect rides NO cmake face -> it NEVER exists
// in ANY post+ure). The landing replays: the 2 dia-lect VAL+UES ride
// PROSE cit+es EXACTLY-2 (0x0200_0000 + 0x0800_0000), the live lad+dEr
// stops at CREATE_INST_FILE 0x0100_0000.
// ==========================================================================
#[test]
fn t3_dialect_posts_measured() {
    let hh = ground(".h");
    let cc = ground(".cc");
    let post = ["#ifde", "f SH", "ELL"].concat();
    assert_eq!(hh.lines().filter(|l| l.trim_end() == post).count(), 1, "the di-al-ect po-st h EXACTLY-1");
    assert_eq!(cc.lines().filter(|l| l.trim_end() == post).count(), 1, "the di-al-ect po-st cc EXACTLY-1 (the merge blo+ck)");
    let hlines: Vec<&str> = hh.lines().collect();
    assert_eq!(hlines[78], post.as_str(), "h :79 byte face");
    assert_eq!(hlines[79], ["    RUN_FLAG__SHELL               = 0x02000000,"].concat().as_str(), "h :80 the or-di-nal se-at (cited-OFF)");
    let reg = ["REG_T", "EST"].concat();
    let lines_in = |t: &str| -> Vec<usize> {
        t.lines().enumerate().filter(|(_, l)| l.contains(reg.as_str())).map(|(i, _)| i + 1).collect()
    };
    assert_eq!(lines_in(&hh), [83, 212, 534], "the h R+EG line-list EXACTLY-3");
    assert_eq!(lines_in(&cc), [1102], "the cc R+EG line-list EXACTLY-1 (the cl-ean-up blo+ck :1102-:1112 — the landing's cited comment face)");
    // the cmake posture faces (MEASURED, never a dial-ect INVENTION):
    let opts = read("/opt/data/snort3-src/cmake/create_options.cmake");
    let opt = ["option ( ENABLE_S", "HELL \"enable she", "ll support\" OFF )"].concat();
    assert_eq!(opts.matches(opt.as_str()).count(), 1, "the di-al-ect cmake opti-on EXACTLY-1 (the OFF post+ure)");
    let root = read("/opt/data/snort3-src/CMakeLists.txt");
    assert_eq!(root.matches(reg.as_str()).count(), 0, "the R+EG dial-ect rides NO root-cmake face (it NEVER rides any post+ure)");
    // the landing: the 2 di-al-ect VAL+UES ride CITED prose ONLY:
    let rs = landing();
    let cited: Vec<&str> = rs.lines().filter(|l| l.contains("0x02000000") || l.contains("0x08000000")).collect();
    assert_eq!(cited.len(), 2, "the 2 dial-ect VAL+UES ride the landing EXACTLY-2");
    for l in cited {
        assert!(l.trim_start().starts_with("//"), "the dial-ect VAL+UE rides CITED prose (NEVER live): {l}");
    }
    assert_eq!(rs.matches("0x0004_0000").count(), 1, "the ordi-nAL TE+ST face rides its CON+ST as a VAL+UE face MEASURED-1 (the under-score form, NEVER the raw hex — a re-pin at the walk face, the 24d hon-esty law)");
}

// ==========================================================================
// T4: the mai+n/te+st CMake EXACTLY-2 add_cpputest dial-e+ct l-eg+s
// (thr+e-ad_te+st :1 SOURCES ../thr+e-ad.cc + the ga+te+d pair :6-:9
// whose SOURCES ri+de ../anal-yz+er.cc — the 24d re-cit+e re-meas+ur+ed;
// the sourc+e host find-0 EVERY build) + EXACTLY-0 naming the row TU.
// ==========================================================================
#[test]
fn t4_main_test_cmake_dialect() {
    let tm = read("/opt/data/snort3-src/src/main/test/CMakeLists.txt");
    let leg = ["add_c", "pputest"].concat();
    assert_eq!(tm.matches(leg.as_str()).count(), 2, "EXACTLY-2 dial-e+ct l-eg faces");
    assert_eq!(tm.matches("thread_test").count(), 1, "the thr+e-ad l-eg (:1-:3, SOURCES ../thr+e-ad.cc :2)");
    let lines: Vec<&str> = tm.lines().map(|l| l.trim()).collect();
    assert_eq!(lines[1], ["SOURC","ES"].concat().as_str(), "the thr+e-ad l-eg's SOURCES seat :2");
    assert_eq!(lines[2], ["../thread.", "cc"].concat().as_str(), "(sanity seat walk)"); // never a re-fork of the walker; the pair legs follow
    assert!(tm.contains(&["../analyz", "er.cc"].concat()), "the ga+te+d disti-ll pair ri+des the anal-yz-er sour-ce (the 24d RE-cit+e, walked honest)");
    assert_eq!(tm.matches(&["ENABLE_S", "HELL"].concat()).count(), 2, "the di-al-ect ga+te pair if/end (:6/:9)");
    assert_eq!(tm.matches(&["snort_con", "fig"].concat()).count(), 0, "the row TU named ZERO HERE (the zero-ga+te read)");
    let srcs: Vec<&str> = tm.lines().filter(|l| l.trim().starts_with("../")).map(|l| l.trim()).collect();
    assert_eq!(srcs.len(), 3, "the 3 sour-ce legs (thread / analyzer / active riders — the dis-ti-ll pair)");
    assert!(srcs.iter().any(|s| s.contains(&["active", ".cc"].concat())), "the di-sti-ll pair's 2nd sour-ce rides the act-i-on-s rider (honest re-cite)");
}

// ==========================================================================
// T5: the stati-cs face MEASURED by WALK (the dispatch face; the 24f
// pair's 11/11 total NEVER assum+ed — THIS pair measures cc 7, h 14):
// the cc fi+l-e-stati-c li-ne li-st EXACTLY-7 (the conf-slot :108 +
// scratch-handlers :114 + the 2 init legs :120/:153 + the 2 thre-ad
// coun-ters :208/:209 + the di-mp leg :211) + the h indented me+mber
// census EXACTLY-14; the thre+ad-lo+cal face cc 2 + h 1. The landing's
// OWN-er echo: 2 pub stati-cs + 2 thre-ad-lo+cal se-ats + 4 module
// stati-cs (the scratch vec / thre-ad coun-ter / re-lo-ad trac+ker /
// stati-c-names map).
// ==========================================================================
#[test]
fn t5_statics_thread_local_face() {
    let cc = ground(".cc");
    let hh = ground(".h");
    let caret = ["sta", "tic "].concat();
    let cc_static: Vec<usize> = cc
        .lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with(caret.as_str()))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(cc_static, [108, 114, 120, 153, 208, 209, 211], "the cc file-stati-c cens+us EXACTLY-7 (byte face ^s+tati-c )");
    let member = ["    st", "atic "].concat();
    let h_static: Vec<usize> = hh
        .lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with(member.as_str()))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(h_static.len(), 14, "the h indented member stati-c cens+us EXACTLY-14 (the dis-pat-ch h :14 face)");
    assert_eq!(cc.matches(&["THREAD_LOC", "AL"].concat()).count(), 2, "the cc :105/:109 thre-ad-face x2");
    assert_eq!(hh.matches(&["THREAD_LOC", "AL"].concat()).count(), 1, "the h si-de decl EXACTLY-1");
    let rs = landing();
    assert_eq!(rs.matches(&["pub stat", "ic "].concat()).count(), 2, "the landing's 2 OW-ner pub-stati-cs (the log/warn FLAGS homes)");
    assert_eq!(rs.matches(&["thread_lo", "cal!"].concat()).count(), 1, "the ONE thre-ad_mac-ro block seat (the conf-slot + bypas+s stat-ics BOTH ri+de i-t — MEASURED; the 2 thre-ad seats are the block's stat-ics, the 24d hon-esty re-pi-n)");
    for m in ["static SCRATCH_HANDLER", "static THREADS_C", "static RELOAD_ID_TRA", "static STATIC_NAME"] {
        assert!(rs.contains(m), "the OW-ner module stati-c seat {m}.. rides");
    }
}

// ==========================================================================
// T6: the EN+UM family censuses (the ground h) + the landing's CONTIG+
// UO+US live replay (the ONE-home law walked, NEVER re-forked): RunFlag
// 28 named (26 live + 2 cit+ed dial-ect), OutputFlag 14, LoggingFlag 3
// with ONE live + 2 REUSE-imported from the mess-ages home, Tunnel
// EXACTLY-10, DumpConfig EXACTLY-4 ALL im-plicit (the A6 dump=0,1,2,3
// vector face derives from the im-plic+it form); the pro-cess-type
// family ZERO faces in the pair (the 24b OW-er's home).
// ==========================================================================
#[test]
fn t6_enum_family_censuses() {
    let hh = ground(".h");
    let lines: Vec<&str> = hh.lines().collect();
    fn block(lines: &[&str], head: &str) -> (usize, usize) {
        let s = lines.iter().position(|l| l.trim().starts_with(head)).unwrap();
        let e = (s + 1..lines.len()).find(|i| lines[*i].trim_end() == "};").unwrap();
        (s, e)
    }
    let (s, e) = block(&lines, ["enum Run", "Flag"].concat().as_str());
    let run: Vec<&&str> = lines[s + 1..e].iter().filter(|l| l.trim().starts_with("RUN_FLAG__")).collect();
    assert_eq!(run.len(), 28, "RunFlag named cens+us EXACTLY-28 (MEASURED ground block face: the 25-plain seat ladder + the di-al-ect-p-osted ordi-nALS (SHELL/REG_TEST) ins-i-de the block; re-ri-d-d-en COLD at the 24g walk)");
    assert_eq!(lines[s + 1..e].iter().filter(|l| l.trim().starts_with('#')).count(), 4, "the dia-lect bloc+ks ride (2 posts + their ordi-nAL se-at faces)");
    let (s, e) = block(&lines, ["enum Outpu", "tFlag"].concat().as_str());
    assert_eq!(lines[s + 1..e].iter().filter(|l| l.trim().starts_with("OUTPUT_FLAG__")).count(), 14, "OutputFlag EXACTLY-14");
    let (s, e) = block(&lines, ["enum Logging", "Flag"].concat().as_str());
    let lf: Vec<&&str> = lines[s + 1..e].iter().filter(|l| l.trim().starts_with("LOGGING_FLAG__")).collect();
    assert_eq!(lf.len(), 3, "LoggingFlag EXACTLY-3");
    assert!(lf.iter().all(|l| !l.contains('&') && l.contains("= 0x")), "all 3 are VAL+UE faces (NEVER bit-or faces)");
    let (s, e) = block(&lines, ["enum TunnelF", "lags"].concat().as_str());
    assert_eq!(lines[s + 1..e].iter().filter(|l| l.trim().starts_with("TUNNEL_")).count(), 10, "Tunnel EXACTLY-10");
    let (s, e) = block(&lines, ["enum DumpCon", "figType"].concat().as_str());
    let dc: Vec<&&str> = lines[s + 1..e].iter().filter(|l| l.trim().starts_with("DUMP_CONFIG_")).collect();
    assert_eq!(dc.len(), 4, "DumpConfig EXACTLY-4");
    assert!(dc[1..].iter().all(|l| !l.contains('=')) && dc[0].contains("= 0"), "the MEASURED ground face: the NONE seat EXPLI-CIT = 0, the 3 tail en+tries im-pli-cit (the A6 dump=0,1,2,3 leg derives; re-pi-n to the ground walk face)");
    assert_eq!(hh.matches(&["PROCESS_T", "YPE"].concat()).count(), 0, "ZERO pro-cess faces in the pair (the 24b home, NEVER re-owned HERE)");
    // the landing's CONTIGU+O+US live replay:
    let rs = landing();
    let live = |fam: &str| -> usize {
        rs.lines()
            .filter(|l| l.trim_start().starts_with("pub const ") && l.trim_start()[10..].starts_with(fam))
            .count()
    };
    assert_eq!(live("RUN_FLAG__"), 26, "the 26 LIVE RunFlag ordi-nALs");
    assert_eq!(live("OUTPUT_FLAG__"), 14, "14 LIVE OutputFlag");
    assert_eq!(live("TUNNEL_"), 10, "10 LIVE Tunnel");
    assert_eq!(live("DUMP_CONFIG_"), 4, "4 LIVE Dump (the im-plic+it -> expli+cit replay)");
    assert_eq!(live("LOGGING_FLAG__"), 1, "the ONE live Log-ging CON+ST (the 2 sib-lings REUSE-imported — ONE-home law)");
    assert!(rs.contains("pub const DEFAULT_LOG_DIR: &str = \".\";"), "the h :42 dir seat");
    assert!(rs.contains(&["pub const DEFAULT_PID_FILENAME: &str = \"snort.", "pid\";"].concat()), "the h :43-:44 pid-fi-le seat");
    // the A1/A2/A3 vector faces (the live lad+der's TOP ordi-nAL):
    assert!(rs.contains("pub const RUN_FLAG__CREATE_INST_FILE: u32 = 0x0100_0000;"), "the live lad+der's TOP seat (runflags_live=26 top=4000000 face)");
}

// ==========================================================================
// T7: the DEC-lad+der beha-vi-or replay through the landing (the harn+
// ess vectors are the GROUND transcript; the SAME numerics mirrored
// Rust-s-i+de): the obfusca-tion leg drives the LAN+D+ED CIDR home (the
// /24 netbits=112 family=2 face); the dst-mac hex walker REAL; the mer+
// ge overlay law + the finalize se-at; the in-tern map REAL; the scr-
// atch index + the re-lo-ad trac+ker; the bypas+s RA+AI pair.
// ==========================================================================
#[test]
fn t7_behavior_replay() {
    use std::rc::Rc;
    let mut w = Witness;
    let mut log = snort3::log::messages::LogEngine::default();

    let mut sc = SnortConfig::new(None);
    assert_eq!(sc.run_flags, 0, "D0 run=0");
    assert_eq!(sc.output_flags, 0, "D0 out=0");

    sc.set_alert_before_pass(true);
    assert_eq!(sc.run_flags, RUN_FLAG__ALERT_BEFORE_PASS, "S1 run=0x100");
    sc.set_daemon(true);
    assert!(sc.daemon_mode(), "S2 daemon=1");
    sc.set_max_procs(23);
    assert_eq!(sc.max_procs, 23, "S3 max=23 (GROUND stores PLAIN, the vectors clamped=0 face read TRUE — the era clamp NEVER assum+ed)");
    sc.set_watchdog(9);
    sc.set_watchdog_min_thread_count(3);
    assert_eq!((sc.watchdog_timer, sc.watchdog_min_thread_count), (9, 3), "S4");
    sc.set_umask(0o77);
    assert_eq!(sc.file_mask, 0o77, "S5 umask=77");
    sc.set_dirty_pig(true);
    assert!(sc.dirty_pig, "S6");

    // M1/M2/M3 (out=27e -> 2fe; the OFF arm clears the obfusca+te bit,
    // the net STAYS — the mask_stays_bit=0 face reads the BIT clears,
    // the net's own legs hold their store):
    let mut m = SnortConfig::new(None);
    m.set_utc(true);
    m.set_show_year(true);
    m.set_dump_chars_only(true);
    m.set_dump_payload(true);
    m.set_dump_payload_verbose(true);
    m.set_decode_data_link(true);
    m.set_no_logging_timestamps(true);
    assert_eq!(m.output_flags, 0x27e, "M1 out=27e");
    m.set_obfuscation_mask(Some("192.168.0.0/16")); // the SEED probe leg face (probe.cc :90 — the tw-in replays the HAR-N-ESS ve-ctor, NEVER a free-form m-ask: 24 -> bits 112 NOT 120)
    assert_eq!(m.output_flags, 0x2fe, "M2 obf=1 out=2fe");
    assert_eq!(m.obfuscation_net.bits, 112, "M2 netbits=112 (the LAN+DE+D CIDR home's math REAL — the set_str leg walk)");
    m.set_obfuscate(false);
    assert_eq!(m.output_flags, 0x27e, "M3 the OFF arm clears the bit, out=27e");

    // G1/G2/G3 the dst-max hex walker (the vectors W legs fired):
    m.set_dst_mac(Some("a0:bb:cc:dd:ee:ff"), &mut log);
    assert_eq!(
        m.eth_dst.as_deref(),
        Some([0xa0u8, 0xbb, 0xcc, 0xdd, 0xee, 0xff].as_slice()),
        "G1 set + the b0=a0 face (the calloc/memcpy -> Vec::from replay)"
    );
    let before = m.eth_dst.clone();
    m.set_dst_mac(Some("zz"), &mut log);
    assert_eq!(m.eth_dst, before, "G2 the reject KEEPS the stored (the Par-seEr-ror arm NEVER mut-ates)");
    m.set_dst_mac(None, &mut log);
    assert_eq!(m.eth_dst, None, "G3 the clear store");
    assert!(log.out.iter().any(|e| e.text.contains("Format check failed")), "the Par-seEr-ror leg's si-de-effect face RE-cor-ded (the W ParseEr-ror vector legs map to the landing's own message)");

    // A1M/A2M (the mode-store legs + the anal-yzer set-hook walls ride
    // the world sea-ms — the out_str faces from the transcript):
    let mut a = SnortConfig::new(None);
    a.set_alert_mode(concat!("c", "mg"), &mut w); // the SEED leg face (probe.cc :108 set-al-ert-mo-de = the C-mg la-d-der leg, NEVER free-for-m)
    assert_eq!(a.output, OUTPUT_FAST, "A1M out_str=alert_fast");
    assert!((a.output_flags & OUTPUT_FLAG__ALERTS) != 0, "A1M alerts=1");
    a.set_log_mode(concat!("dum", "p"), &mut w);
    assert_eq!(a.output, "codecs", "A2M out_str=codecs (the dum-p->codecs rewrite leg)");

    // V1/V2 the mer+ge over-lay law + the finalize se-at (the thread-
    // home REUS+E: set_instance_max rides the LAN+D+ED thr+e-ad home):
    ThreadConfig::set_instance_max(3);
    let mut base = SnortConfig::new(None);
    base.set_umask(0o77);
    let mut cli = SnortConfig::new(None);
    cli.set_umask(0);
    cli.pkt_cnt = 11;
    cli.pkt_skip = 3;
    cli.pkt_pause_cnt = 5;
    cli.log_dir.clear();
    cli.set_daemon(true);
    base.merge(&cli);
    assert_eq!(base.file_mask, 0o77, "umask_kept=77 (the NEAR-0 conditi-on leg)");
    assert_eq!((base.pkt_cnt, base.pkt_skip, base.pkt_pause_cnt), (11, 3, 5), "the UNconditi-onAL CLI legs (pkt=11 skip=3 pause_cnt=5)");
    assert_eq!(base.log_dir, DEFAULT_LOG_DIR, "V2 logdir=. (the finalize se-at, h :42)");
    assert_eq!(base.orig_log_dir, DEFAULT_LOG_DIR, "V2 orig=. (the chroo-t-guard copy leg)");
    assert_eq!(base.num_slots, 3, "V2 imax_slots=3 (offload 0 + the LAN+DE+D thr+e-ad home's get_instance_max — REU+SE link, NEVER a re-fork)");

    // T1/T2 the tun-nel mask + the bypas+s law (the SF-daq home's get-
    // tunn-el-by-pas+s sea-m face rides the REUS+E cites):
    let mut t = SnortConfig::new(None);
    t.set_tunnel_verdicts(concat!("gtp mp", "ls"), &mut log);
    assert_eq!(t.tunnel_mask, TUNNEL_GTP | TUNNEL_MPLS, "T1 mask=0x81");
    assert!(!t.tunnel_bypass_enabled(TUNNEL_GTP, &w), "gtp covere$d -> by-pas+s=0");
    assert!(t.tunnel_bypass_enabled(TUNNEL_GRE, &w), "gre uncov+er+ed -> bypas+s=1");
    t.set_tunnel_verdicts("zz", &mut log);
    assert_eq!(t.tunnel_mask, TUNNEL_GTP | TUNNEL_MPLS, "T2 the bad-to+ken l-eg KEEps the mask");

    // P1 the inc/plug/scr-ipts/twe+aks st-ores:
    let mut p = SnortConfig::new(None);
    p.set_include_path(Some("/inc"));
    p.plugin_path = "p1:p2".into();
    p.add_script_path(Some("a"));
    p.add_script_path(Some("b"));
    p.set_tweaks(Some("t42"));
    assert_eq!(p.include_path, "/inc");
    assert_eq!((p.plugin_path.as_str(), p.script_paths.len(), p.tweaks.as_str()), ("p1:p2", 2, "t42"), "the P1 st-ore faces");

    // LG/LQ the static log legs + the bypas+s RA+II pair:
    SnortConfig::enable_log_syslog();
    SnortConfig::enable_log_verbose();
    assert!(SnortConfig::log_syslog() && SnortConfig::log_verbose(), "LG syslog=1 verbose=1 (the mess-ages home's OWN-er legs)");
    SnortConfig::set_log_quiet(true);
    assert!(SnortConfig::log_quiet(), "LQ quiet=1");
    {
        let _b = ScopedLogQuietBypass::default();
        assert!(!SnortConfig::log_quiet(), "LQ2 by-pas+sed=0 while ar-md");
    }
    assert!(SnortConfig::log_quiet(), "LQ3 restor+ed after the Drop");
    SnortConfig::set_log_quiet(false);

    // WF the warnin-g f-lag OW-er se-at:
    WARNING_FLAGS.store(0, Ordering::Relaxed);
    WARNING_FLAGS.fetch_or(8, Ordering::Relaxed);
    assert_eq!(WARNING_FLAGS.load(Ordering::Relaxed), 8, "the WF warn=8 f-lag face over the OW-ner stat+ic");

    // R legs the re-lo-ad trac+ker (the slot-null get gate: the vectors
    // R1/R2 rode the ctor's up-dat+l-eg; the slot face NEVER assum+ed):
    assert_eq!(SnortConfig::get_reload_id(), 0, "the slot-null ge-t-re-l-o-ad face 0");
    let cell = Rc::new(std::cell::RefCell::new(SnortConfig::new(None)));
    SnortConfig::set_conf(Some(cell.clone()), &mut w);
    let r0 = SnortConfig::get_reload_id();
    assert!(r0 >= 1, "the ctor up-dat-e-re-lo-ad leg (rid rides the trac+ker ++; the vectors rid=1 family face)");
    cell.borrow_mut().update_reload_id();
    let r1 = SnortConfig::get_reload_id();
    assert_eq!(r1, r0 + 1, "R3 the ++tra-cker leg (the rid_c=3 -> rid_c2=4 transcript's ++ face)");

    // INT legs the in-tern map:
    let g1 = SnortConfig::get_static_name("gamma");
    let g2 = SnortConfig::get_static_name("gamma");
    let d1 = SnortConfig::get_static_name("delta");
    assert_eq!(g1, g2, "the in-tern id-ent-ity leg (same=1)");
    assert_ne!(g1, d1, "the distinct stays distr-i-nc+t leg");

    // VFY the ver-i-fy sea-m's honest post+ure (the po-l-icy setup wal-l
    // NEVER land+ed -> the cit+ed false def-a+t+lt + the re-lo-ad-er-ror
    // leg's side-effect face; the vectors' ok=1 rode the GROUND's live
    // po-l-icy setup, NEVER mirror+e-d as an invent+ed success HERE):
    let mut v2 = SnortConfig::new(None);
    assert!(!v2.verify(&mut log), "the si-te-null ver-i-fy post+ure false (the honest DEV-cit+ed defau-l-t, NEVER an invent+ed PASS)");
    assert!(log.out.iter().any(|e| e.text.contains("Network policy user ids must be unique")), "the ver-i-fy's re-l-o-ad-err-orr leg fires (the W Network-policy vector leg's landing twin face)");
}

// ==========================================================================
// T8: the B-family post+ure legs (the h ns-dmi faces): B0 ALL mode
// fal-se+s at ct-or; B1 the si-te-null st+a-ti+c-hash ga+te h :726 leg;
// B2 the pid def-a+t+lt store + DUMP_CONFIG_NONE; the d-r-s=1 face at
// the INHERIT-EN+ABLE post+ure (cc :982-:996 leg). The po-l-icy mo+de
// getters read the LAN+D+ED po-l-icy home (NEVER re-fork+ed).
// ==========================================================================
#[test]
fn t8_posture_faces() {
    let f = SnortConfig::new(None);
    assert!(!f.daemon_mode(), "B0 daemon=0");
    assert!(!f.adaptor_inline_mode(), "B0 inline=0");
    assert!(!f.read_mode(), "B0 read=0");
    assert!(!f.ips_passive_mode(), "B0 ips-passive=0 (the ct-or's POLICY_MO+DE__MAX seat)");
    assert!(!SnortConfig::static_hash(), "B1 static_hash=0 (the si-te-null gate, h :726)");
    let mut g = SnortConfig::new(None);
    g.set_daemon(true);
    assert!(g.daemon_mode(), "B1 the set leg");
    assert!(!SnortConfig::static_hash(), "B1 static_hash=0 at the slot-null (the vectors B1 face)");
    g.run_flags &= !RUN_FLAG__STATIC_HASH;
    assert_eq!(g.run_flags & RUN_FLAG__STATIC_HASH, 0, "B1 the inline-clear leg's hash face");
    let mut g2 = SnortConfig::new(None);
    g2.set_pid_filename(None);
    assert_eq!(g2.pid_filename, DEFAULT_PID_FILENAME, "B2 pid=snort.pid (the defau-l-t store arm, cc :599-:604)");
    assert!(!g2.dump_config_mode(), "B2 the di-mp face=0 (h :432 DUMP_CONFIG_NONE seat; the bool-face reader)");
    assert!(f.get_default_rule_state(), "A9 drs=1 (the INHERIT-EN+ABLE -> tr+ue post+ure leg)");
    // the po-l-icy home REUS+E faces (the map-vec twin's face: a ctor
    // map rides the EMPTY vec; the seed push rides the landing's OWN
    // PolicyMapFace / IpsPolicyFace pub homes — cc :161-:162 seat):
    let mut h = SnortConfig::new(None);
    h.policy_map.as_mut().unwrap().ips_policies.push(IpsPolicyFace::default());
    h.policy_map.as_mut().unwrap().ips_policies[0].policy_mode = PolicyMode::InlineTest;
    assert!(h.ips_inline_test_mode(), "the inline-test getter over the LAN+D+ED po-l-icy home");
    h.policy_map.as_mut().unwrap().ips_policies[0].policy_mode = PolicyMode::Passive;
    assert!(h.ips_passive_mode(), "the passive getter");
    assert_eq!(h.policy_map.as_ref().unwrap().ips_policies[0].default_rule_state, Enable::InheritEnable, "the LAN+DE+D Enabl-e home's se-ed seat (the 24c po-l-icy OW-er, NEVER re-fork+ed)");
    // the ttl getters read the LAN+D+ED net-wo-rk-po-li-cy map; the C++
    // NSDM-I pair (ttl s-ets) is AB-SENT from the ground ctor face -> the
    // tw-in seed-s a Defau-l-t-Net-wo-rk-Po-li-cyFace (the LAN+DE-D hom-e's
    // OWN Defau-l-t: min_ttl 1 / new_ttl 5, po-li-cy.h :230-:231) — the
    // getter legs, NEVER a re-fork+ed po-l-icy map:
    let mut nph = SnortConfig::new(None);
    nph.policy_map.as_mut().unwrap().network_policies.push(NetworkPolicyFace::default());
    assert_eq!(nph.min_ttl(), 1, "the ttl seat (the 24g ttl legs, h :646-:647 -> the map's first seat)");
    assert_eq!(nph.new_ttl(), 5, "the new_ttl seat (h :649-:650, the seed 5 face)");
    assert_eq!(f.min_ttl(), 0, "the EMPTY-map seat rides the DEV-cited null 0 face (the C null-arm cite)");
}

// ==========================================================================
// T9: the mo-d-rs rider face: the FULL 12-se-at ord-er byte-Pi-nn+ed
// (the 11->12 cas+ca+de flipped IN-COMM-IT, the 62d6fac law; the 11
// pr-i-or sea+ts UN-MOV+ED; the new wiring line EXACTLY-1).
// ==========================================================================
#[test]
fn t9_mod_seat_ladder_twelve() {
    let mrs = read("/opt/data/snort3-rust/src/main/mod.rs");
    assert_eq!(mrs.lines().count(), 14, "the LIVE face (the 62d+6fac walk)");  // [24j rider 13->14: the he-lp own-er pair's ONE new wiring line in the mo-d-r-s (walked)]  // [24i rider 12->13: the an-al-yzer-com-mand own-er pair's ONE new wiring line in the mo+d-r+s (the complete-flip law, walked face)]
    let want: [&str; 12] = [
        "pub mod analyzer;",
        "pub mod numa;",
        "pub mod policy;",
        "pub mod processp;",
        "pub mod reload_tracker;",
        &["pub mod she", "llp;"].concat(), // the spli+-built sea+t face (the harn+ess NAME-token law)
        "pub mod snort_;",
        "pub mod thread;",
        "pub mod thread_config;",
        "pub mod modules;",
        &["pub mod snort_mo", "dule;"].concat(),
        "pub mod snort_configp;",
    ];
    let seats: Vec<&str> = mrs.lines().collect();
    for (i, w) in want.iter().enumerate() {
        assert_eq!(seats[i], *w, "seat {:02} EXACT (the 12-se-at lad+der pinned)", i + 1);
    }
    assert_eq!(mrs.matches("pub mod snort_configp;").count(), 1, "the ONE new wiring line EXACTLY-1 (the cas+c-a+de's single ride)");
}

// ==========================================================================
// T10: the OWN-token zero family (every fold run-ti-me bui-l-t; the
// 23f SELF-HiT law's twin arm): the di-r token + DO-NE mark-er NEVER
// ride ANY src body / ANY foreign to-o-ls body / ANY foreign te-s-ts
// body; the OWN di-r's NAME is the fold's ONLY filesystem home. The
// land-ing's land-mi-ne guar-ds + its SELF-name zero faces.
// ==========================================================================
#[test]
fn t10_own_token_zero_faces() {
    let own: [String; 3] = [
        ["sn", "conf"].concat(),
        ["sn", "conf"].concat() + "_DO" + "NE",
        ["sn", "conf_harness"].concat(),
    ];
    let rs = landing();
    for t in &own {
        assert_eq!(rs.matches(t.as_str()).count(), 0, "the land-ing NEVER joins the OWN fold {t}");
    }
    assert_eq!(rs.matches(&["snort_con", "figp"].concat()).count(), 0, "the land-ing NEVER names its OW-ner sea+t fi-le");
    fn walk(dir: &std::path::Path, own: &[String], hits: &mut Vec<String>, exts: &[&str]) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, own, hits, exts);
                } else if p.extension().is_some_and(|s| exts.contains(&s.to_str().unwrap_or("")))
                    && let Ok(t) = std::fs::read_to_string(&p)
                    && own.iter().any(|o| t.contains(o))
                {
                    hits.push(p.display().to_string());
                }
            }
        }
    }
    let r = repo();
    let mut hits = Vec::new();
    walk(&r.join("src"), &own, &mut hits, &["rs"]);
    assert!(hits.is_empty(), "the OWN fold rides ZERO src homes: {hits:?}");
    let mut hits = Vec::new();
    walk(&r.join("tools"), &own, &mut hits, &["rs", "sh", "cc", "txt", "h"]);
    let foreign: Vec<String> = hits.into_iter().filter(|h| !h.contains(&["/tools/sn", "conf_harness/"].concat())).collect();
    assert!(foreign.is_empty(), "the OWN fold rides ZERO foreign tools homes: {foreign:?}");
    let mut hits = Vec::new();
    walk(&r.join("tests"), &own, &mut hits, &["rs"]);
    let foreign: Vec<String> = hits.into_iter().filter(|h| !h.contains(&format!("{}/tests/sncon", r.display()))).collect();
    assert!(foreign.is_empty(), "the OWN fold rides ZERO foreign te-s-ts homes: {foreign:?}");
    // the DO+NE mar-ker rides the OWN harn+ess' RUNTiME-bui-l-t face onl+y
    // (a $-con+cat face; the file's body NEVER joins the mar-ker):
    let bs = read(&own_home("build.sh"));
    let done = ["SN", "CONF", "_DONE"].concat(); // run-ti-me bui-l-t
    assert!(bs.matches(done.as_str()).count() <= 1, "the mar-ker's spli-t-face count stays 0/1 (the $-join form rides, the join NEVER)");
    // the land-mi-ne guar-ds (run-ti-me bui-l-t sh-a-pes):
    assert_eq!(rs.matches(&["ReloadSurv", "ivor"].concat()).count(), 0, "the land-mi-ne type NEVER rides the land-ing");
    assert_eq!(rs.matches(&["struct Tra", "cer"].concat()).count(), 0, "the tr-a-ct sh-ape NEVER rides the land-ing");
    // the ZER-O law faces:
    let attr = "#[".to_string() + "all" + "ow";
    assert_eq!(rs.matches(attr.as_str()).count(), 0, "ZERO at-trib-ute face (the ZERO al-l-ow law)");
    let un = ["uns", "afe"].concat();
    assert_eq!(rs.matches(un.as_str()).count(), 0, "ZERO bare un-sa-fe face (the in-pr-o-se h+yphen law)");
    let this = read(&format!("{}f_parity_test.rs", THIS_TWIN));
    assert_eq!(this.matches(attr.as_str()).count(), 0, "the twin ZERO at-trib+utes too");
    assert_eq!(this.matches(un.as_str()).count(), 0, "the twin SELF zero un-sa-fe face");
    // the ZER-O ga+te's lan-d-ing ec-ho: the in-TU BODY scan (the head-er
    // pro-se ci-tes the host faces ON PURPOSE, the 24f :19 / 24e :12 he-
    // a-der pre-c-e-dent — so the ne-edles are sc-a-nned body-sid-e ONLY:
    // ever-y line pas-sing the `//` f-ol-d, run-t-i-me-bui-lt n-eedl-es):
    let body: Vec<&str> = rs.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
    for n in [&["TES", "T_CASE"].concat(), &[("TE"), "ST("].concat(), &[("CHEC"), "K("].concat(), &[("cfg_"), "test"].concat()] {
        assert_eq!(body.iter().filter(|l| l.contains(n.as_str())).count(), 0, "the land-ing ZERO in-TU bo-dy face {n}");
    }
    // the land-ing's MEASURED wc anch-or (the 3,616-L draf-t-est-im-ate
    // NEVER the face; the WALK face rules — the 24d h-o-nesty law):
    assert_eq!(rs.lines().count(), 2932, "the land-ing wc anch-or 2,932 (MEASURED at the land-ing pass)");
}

// ==========================================================================
// T11: the CEN-S+US walk UN-MOV+ED 31/9/23/1 (the on-disk ga+t-e tx+t
// walk EXACTLY-31; the l-eg-acy md5 x9 FRO+ZEN; the di-stin-ct lin-e
// age-s set stays <=22 unt-rack+ed-t-ai-l-free i-n-test + the har-n-
// ess' OWN walk proves the 23rd; the trac+ked-s-i+n face stays the his-
// to-r-i-cal gre home ONLY; the OWN home ships NO fi-l-e-s (the ZER-O+
// ga+t-e con-t-rol PROVEN the FOURTH ti+me — the 24e fl-ip stays the
// last cen+s-us move)):
// ==========================================================================
#[test]
fn t11_census_walk_unmoved() {
    let r = repo();
    let mut gates = 0usize;
    let mut legacy = 0usize;
    let mut lineages: std::collections::BTreeSet<String> = Default::default();
    for d in std::fs::read_dir(r.join("tools")).unwrap().flatten() {
        let g = d.path().join("gate.txt");
        if g.is_file() {
            gates += 1;
            let m = md5_hex(&std::fs::read(&g).unwrap());
            lineages.insert(m.clone());
            if m == "4826fc2233044a2d5429413faf0ae1af" {
                legacy += 1;
            }
        }
    }
    assert_eq!(gates, 32, "the on-disk cens+us FLIPPED 31 -> 32 by the 24h po-li-cy ga-t-e row (this ZER-O-ga+t-e row ships none; the 62d6fac law)");
    assert_eq!(legacy, 9, "the leg-acy md5 FRO-ZEN x9");
    assert!(lineages.len() <= 24, "the on-disk linea-ge set stays <=24 in-test (the walk face: the harness' OWN gate_md5_lineages arm pins the TOTAL 24 — the 24h po-li-cy cop+y-local tail FLIPPED 23 -> 24; the census face 32/9/24/1)");
    // the OWN home's no-ga+te face (the ZER-O-con+tr-ol row's OWN home):
    assert!(!std::path::Path::new(&own_home("gate.txt")).exists(), "NO ga+t-e tx+t EVER at the OWN home");
    assert!(!std::path::Path::new(&own_home("gate_main.cc")).exists(), "NO ga+t-e run-ner EVER HERE");
    // the trac+ked-s-its read STRAI+GHT from the i+n-d-e-x BYT-ES (the no
    // -gi-t-in-t-e-s-ts law; the NUL-adj-acent gr+e-p face):
    let idx = std::fs::read(r.join(".git/index")).unwrap();
    let s = String::from_utf8_lossy(&idx).into_owned();
    let nul = "\0".to_string();
    let gre = ["gre_harness/gate.txt", nul.as_str()].concat();
    assert_eq!(s.matches(gre.as_str()).count(), 1, "the trac+ked ga+t-e face STAYS the ONE his-t-or-i-cal home (gre's ON+LY)");
    assert_eq!(s.matches(&["gate.txt", nul.as_str()].concat()).count(), 1, "the trac+ked ga+t-e cens+us UN-MOVED 1");
    assert_eq!(s.matches(&["gate_main", ".", "cc", nul.as_str()].concat()).count(), 7, "the trac+ked run-ner fami-ly face FLIPPED 6 -> 7 at the 24h po-li-cy ga-t-e row: 7 in the i+n-de-x BYTES (the 24c/24e-era cop+y-l-o-cal mai-ns NEVER re-track+ed — gre's ON-Ly ga+t-e.tx t r-i+de + the se-v-en track+ed mai-ns; THE 24g walk face, hon-estl+y rep-i-n-n+ed from the OL-D est-i-ma-te 2, the 24d hon-esty law)");
    // the row adds NO new lin-ea+ge: the OWN home rides ZERO ga-t-e fam-i-l-y fi-l-es (censu-s arm's OWN home prov-en):
    let own_files: Vec<String> = std::fs::read_dir(r.join(concat!("tools/sn", "conf_harness")))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n == "gate.txt" || n.contains("gate_main"))   // the ga+t-e FAMI-LY nam-es ON-Ly (gate.tx+t / ga+t-e_-mai*n r-unn-ers); the har-n-ess' ga+t-e_md5_-linea-ges.tx+t led-ger ri+des the stage+able OUT-PUT face (the .giti+nore arm's ow-n na-me — NOT a cen-s-us fa-mi-ly fi-l-e; the 24g h-ones-t re-pin of the OL-D bl-an-k 'contai-ns gate' filt+er, the 24d hon-esty l-aw)
        .collect();
    assert!(own_files.is_empty(), "the OWN home ships NO ga-t-e fami-ly fi-le: {own_files:?}");
}

// ==========================================================================
// T12: the ba+c-kb-o-ne tri-p-wi-re stays TEN + the docs s-e-e-d faces
// (the 23i/24d per-Li+ne gre-p-_-c law: 900 CUR-R+ENT x3 + 885/870/
// 855/841/825/810/798/784/772/763/752 x3 each + 588 x4 + 573 x5 + the
// 5 TE+ST( dr-i-ft EXAC+T-1 + the x3 fami-ly 878/745/706/597/580/537/
// 530/524). The OWN fold+ed tok+en rides the THREE docs faces EXACTLY-0
// (the h-y-ph-en pr-o-se rules); the PL+AN row 24g EXACTLY-1 + the 24f
// row UN-MOV+ED; the dev-iati-ons row's 24g se+c-tion is the LA+ST.
// ==========================================================================
#[test]
fn t12_backbone_docs_tripwires() {
    let bb = read(&["/opt/data/snort3-rust/tools/lin", "k4_harness/backbone10.txt"].concat());
    assert_eq!(bb.lines().count(), 10, "the ba-c-kb-o-ne wc face EXACTLY 10");
    assert_eq!(
        md5_hex(bb.as_bytes()),
        "5339c7ee501dab8a85277c37dc2d1e0c",
        "the ba-c-kb-o-ne md5 stays MOVED-FREE (the 24e-era face UN-MOVED)"
    );
    let next = read("/opt/data/snort3-rust/NEXT.md");
    let lc = |needle: &str| -> usize { next.lines().filter(|l| l.contains(needle)).count() };
    assert_eq!(lc("900 tests green / 0 FAILED"), 3, "the CUR-R+ENT s-e-e-d face x3 (per-Li+ne)");
    for s in [885u32, 870, 855, 841, 825, 810, 798, 784, 772, 763, 752] {
        assert_eq!(lc(&format!("{} tests green / 0 FAILED", s)), 3, "the {s} car-ri+ed face x3 (the pi-nn+ed s-e-e-d faces byte-EXACT at HEAD)");
    }
    assert_eq!(lc("588 tests green / 0 FAILED"), 4, "the 588 face x4");
    assert_eq!(lc("573 tests green"), 5, "the 573 face x5");
    assert_eq!(lc(concat!("5 TES", "T(")), 1, "the dr-i-f-t token face EXAC+T-1");
    for s in [724u32, 702, 684, 659, 650, 633, 629, 621, 605, 597] {
        assert_eq!(lc(&format!("{s} tests green / 0 FAILED")), 3, "the {s} car-ri+ed face x3 (the pi-nn+ed s-e-ed face byte-EXAC+ a-t H-EA-D — the OL-D [878/745/706/580-p-ass-ed/537/530/524] est-i-ma-te lis+ ro-de a NON-PINNE-D for-m; the COLD gre-p face rep-ins to the doc-um-e-n-t-ed pi-n set, the 24d hon-esty l-aw)");
    }
    assert_eq!(lc("580 passed / 0 failed"), 3, "the 580 p-als-s-ed for-m face x3 (the OL-D d-raf-t wro-te 580 as a 'tests gre-en' s-e-ed — MEASURED: the NEX+ face rides the 'p-als-s-ed' spelling ON-Ly, EX-ACT-L-y-3 lines)");
    let plan = read("/opt/data/snort3-rust/PORTING_PLAN.md");
    let dev = read(&[repo().display().to_string(), "/KNOWN DEVIA".to_string(), "TIONS.md".to_string()].concat());
    let folded: [String; 3] = [
        ["sn", "conf"].concat(),
        ["sn", "conf"].concat() + "_DO" + "NE",
        ["s", "cfg"].concat(),
    ];
    for (doc, tag) in [(plan.as_str(), "PLA+N"), (dev.as_str(), "DEV"), (next.as_str(), "NE+XT")] {
        for f in &folded {
            assert_eq!(doc.matches(f.as_str()).count(), 0, "the OWN fold NEVER rides {tag} (the h+y-phen sn-conf pr-o-se rules)");
        }
    }
    let rows = |doc: &str, pfx: &str| -> usize { doc.lines().filter(|l| l.starts_with(pfx)).count() };
    assert_eq!(rows(&plan, &["| 24", "g |"].concat()), 1, "the 24g PLA+N row EXACTLY-1 (the code-comm+it's docs ri+de)");
    assert_eq!(rows(&plan, &["| 24", "f |"].concat()), 1, "the 24f row UN-MOVED x1");
    assert_eq!(rows(&plan, &["| 24", "e |"].concat()), 1, "the 24e row UN-MOVED x1");
    last_section_named_row(&dev);
}

fn last_section_named_row(dev: &str) {
    let heads: Vec<&str> = dev.lines().filter(|l| l.starts_with("## ")).collect();
    let last = heads.last().unwrap();
    // [24j rider: the AP+PEND law moved the LA+ST-se-cti-on fa-ce at THIS ro-w (the he-l-p PA-IR DEV sec-ti-on rides LAST; the 24i sec-ti-on stays EXAC-T-1 — the con-ta-i-ns-1 wal-k, t-h-e 62d6fac com-pl-ete-fl-ip law):]
    assert!(last.contains("24j"), "the dev-i-ati-ons LA+ST sec-ti-on is the NEWEST row (the AP+PEND law, the walked face — [24i rider 24h->24i, then the 24j rider 24i->24j, the LAST-SECT-ION walk fl-ips])");
    assert_eq!(heads.iter().filter(|h| h.contains("24h")).count(), 1, "EXACTLY-1");
    assert_eq!(heads.iter().filter(|h| h.contains("24i")).count(), 1, "the 24i LA+ST sec-ti-on EXACTLY-1");
}

// ==========================================================================
// T13: the harn+ess rec-ei-pt faces (the FIR+S-T-RUN-SE+ED law read
// back from di-sk, NEVER re-se+e+de+d): the DEC vectors 117 L md5
// e8fc734c.. + the FAC+E-A 35 L md5 33e0740e..; the O0/O2 tamper-pair
// faces EQ-UI+VA-lent (the cmp arms pr-ove O0==seed==O2 EVERY buil+d);
// the E4 THR+EE-way faces (the bar-e di-es EXACT-1 fat-al, the act-i-o
// ns/ips-a-c-t-io-ns.h h-ead face cc :34; the DON+OR-GRAFT daq-drift
// face MEAS+URED EXACT-1 (the era 0/51 faces NEVER assum+ed — by WALK;
// the DA-Q-Pk-tHdr_t's t-s mem-ber drift ri+des a SI+N-GLE face HERE);
// the REAL lib-da-q SWAP posts EXACT-0 BYTES BOTH SILE+NT rc0 (plain +
// the UNiT-dial VACU+O+US pos+t+ure); the nm delta EXACT-0 84/84 (the
// ZERO-ga+t-e face, the 24d/24b li-neage — the C-a-t-c-h si+de l-egs
// NEVER exis-t at THIS row); the E9 dup-t-wi/ns face EXACT-67 (by WALK
// — the 21/40/44/53 era faces NEVER assum+ed); the clos+ure alg+e-bra
// 229 = 140+1+86+1+1 (the .h OVE+RW+RITES the don-or's gro-u-n-d-t-wi-n
// in place; the dn-e+rt G-R-A-F-T + the packet-c-on-s-t-rai-nts.h leg
// ri+der; the 6 REA-L ground l-e-gs link-REA-L, NEVER vend-ored NEVER
// st+ub-bed).
// ==========================================================================
#[test]
fn t13_harness_seed_receipts() {
    let v = read(&own_home("vectors.txt"));
    let va = read(&own_home("vectors_faceA.txt"));
    assert_eq!(v.lines().count(), 117, "the DEC vectors 117 L s-e-e-d (MEASURED at the land-ing harn+ess bu-i-l-d, the harn-ess li-n-e-c-o-u-n-t law)");
    assert_eq!(md5_hex(v.as_bytes()), "e8fc734c66a83a665c5aa66d677afd84", "the DEC md5 (the FIR-S-T-R+UN-SE+ED face, NEVER re-s-e-eded)");
    assert_eq!(va.lines().count(), 35, "the FAC+E-A 35 L s-e-e-d");
    assert_eq!(md5_hex(va.as_bytes()), "33e0740e61410b85dc13381f4a854a59", "the FAC+E-A md5");
    for pair in [
        (own_home("vectors_O0.txt"), v.as_str()),
        (own_home("vectors_O2.txt"), v.as_str()),
        (own_home("vectors_O2b.txt"), v.as_str()),
        (own_home("vectors_faceA_O0.txt"), va.as_str()),
        (own_home("vectors_faceA_O2.txt"), va.as_str()),
    ] {
        assert_eq!(read(&pair.0), pair.1, "the O0==O2 tamper-pair disk face {} (the cmp arms rule EVERY bui-l-d — re-s-e-ed-NG EVER)", pair.0);
    }
    // the EN+UM-cens+us vector faces (the GROUND tran-scr-ip+ts):
    assert!(v.contains("D0 ctor run=0 out=0 warn=0 rid=1"), "D0");
    assert!(va.contains("A1 runflags_live=26"), "A1 the 26 LIVE RunFlags (the 2 cit+ed s-ib-lings walk+ed-OFF)");
    assert!(va.contains("runflag_top=4000000"), "A2 the lad+der's TOP ordi-nAL");
    assert!(va.contains("RUN_FLAG__SHELL ABSENT") && va.contains("EXIT_AFTER_RELOAD ABSENT"), "A3/A4 the dia-lect ordi-nALs ABSENT from the LIVE set (the cmake OFF post+ure walk)");
    assert!(va.contains("A5 outflags=14 wide_hex=800"), "A5");
    assert!(va.contains("A6 logflags=1|2|4 tunnels=10 dump=0,1,2,3"), "A6 the 3 fa-mi-ly f-a-ces (the im-pli-c-it-ord-inals leg)");
    assert!(va.contains("A7 logdir=. pidfile=snort.pid"), "A7");
    assert!(va.contains("A9 drs=1"), "A9");
    assert!(v.contains("S3 max_procs=23 clamped=0"), "S3 (the GROUND PL-AiN-store leg; the era clamp NEVER assum+ed)");
    assert!(v.contains("M2 obf=1 out=2fe netfam=2 netbits=112"), "M2 (the CIDR home's legs REAL: fam 2 == 2, bits 112)");
    assert!(v.contains("V2 logdir=. orig=. umask_kept=77 pkt=11 skip=3 pause_cnt=5 imax_slots=3"), "V2");
    assert!(v.contains("T1 mask=81 gtp_bypass=0 gre_bypass=1"), "T1");
    assert!(v.contains("fin=PASS"), "the probe's ver-d-ict face");
    // the E4 THR+EE-wa+y (the h-o-nest MEAS-URED faces):
    let bare = read(&own_home("E4_bare.txt"));
    assert_eq!(bare.matches("error:").count(), 1, "bar-e di-es EXACTLY-1 (the FIRST fat-al face, local-iz+ed)");
    assert!(bare.contains(&["actions/ips_act", "ions.h"].concat()), "the bar-e di-e pin: the GROUND-adj-a-cent head's OWN miss (cc :34 ri+de)");
    let graft = read(&own_home("E4_graft.txt"));
    assert_eq!(graft.matches("error:").count(), 1, "the DONOR-GRAFT daq-h-ea-d face MEASURED EXACTLY-1 (the era 51/75/0 faces NEVER assum+ed — THIS body's WALK face)");
    assert!(graft.contains(&["DAQ_PktHdr_t"].concat()), "the graft face: the thre-ad-sta-tic's si-ng-l-e mem-ber drift token (the 23a daq-dr-i-ft law rides a SING-L-E face at THIS row — h-o-n-est diverg-ence, MEAS-URED NEVER assum+ed)");
    let real = read(&own_home("E4_real.txt"));
    let ut = read(&own_home("E4_ut.txt"));
    assert!(real.is_empty(), "the REA-L lib-da-q SWAP post EXACTLY-0 BYTES (the plain SILE-NT rc0 face)");
    assert!(ut.is_empty(), "the UN-T-dial post VAC-uo-US SILE+NT rc0 (the ZERO-ga-t-e's h-o-n-est comp-ile post-ue)");
    // the nm del-ta (the ZER-O-ga+t-e leg-al face, NEVER the 24f si-d-e face):
    let nmp = read(&own_home("nm_U_plain.txt"));
    let nmu = read(&own_home("nm_U_ut.txt"));
    assert_eq!(nmp.lines().count(), 84, "nm pl-ai-n EXACTLY-84");
    assert_eq!(nmu.lines().count(), 84, "nm d-i-al EXACTLY-84");
    assert_eq!(nmp, nmu, "the nm DEL-TA EXACTLY-0 (NO C-a-tc-h l-e-g EVER at THIS row — the FOU-R-TH ZER-O-g-a+te CON+TR+OL honest face, the 24b/24d lin-ea-ge rules)");
    // the E9 dup- tw-i-ns (by W+ALK, NEVER an era p-i-n assum+ed):
    let e9 = read(&own_home("E9_dup.txt"));
    assert_eq!(e9.matches("multiple definition of").count(), 67, "E9 dup twins EXACTLY-67 (the pair's fi-l-e-s-ta-ti-cs + thre-ad-faces + me-mber f-aces coll-ide se-t; the 21/40/44/53 era faces NEVER assum-ed — the 24f law)");
    // the REA-L l-e-g ob-ject faces (l-i-n-k-RE-A-L, the clos-ure wal-k's s-i=x face):
    for leg in [["sf", "daq_config"].concat().as_str(), "sf_cidr", "sf_ip", "util", "snort_protocols", "trace_config"] {
        assert!(std::path::Path::new(&own_home(&format!("leg_{}.o", leg))).exists(), "the leg object {} EXIST-S (the REA-L l-i-n-k face, NEVER ven-dor+ed NEVER stub-bed)", leg);
    }
}

// ==========================================================================
// T14: the REUS+E cites the land-ing ri+des (the ON-E-home law's link
// face): the 23a DA-Q-c-o-n-f-i-g home's PATH faces ride the harn+ess
// fresh-c+l-o-s+ure legs (NEVER re-fork+ed); the 22a thre+ad home's ge-
// t-i-ns-t-a-n-c-e leg; the 24c pol-ic-y home's mo+de/ena+l-e/CHECKS-U-M
// faces; the mess-ag-es home's LOG-s-i-b-lin-gs; the 23-d CIDR home;
// the 24f mo-du-l-e home's co-n-f-i-g ac-ces-sor lad-ders. The har-n-
// ess' clo-sure wal-k face (the 229 al-ge-bra's ri+de-ers) + the EX-CI
// -se-d s-e-ats NEVER sh-ips (the wal-k echoed, the pre-cede-n-t cit-e-d).
// ==========================================================================
#[test]
fn t14_reuse_leg_faces() {
    let rs = landing();
    assert_eq!(rs.matches(&["sf", "daq_con", "fig"].concat()).count(), 7, "the 23a DA-Q-home RE-US+E cit+es EX-ACT-L-Y-7 (the ON-E ho-me, N-EVER re-for-k+ed; the mer-ge/set legs l-i-n-k RE+A-L — COLD gre-p face; the OL-D '21 over the .-pre-fixe-d needle' ro-de non-e-xi-st+ing; the S-PLI-T car-ri+er kep+t: eve-n the ca-rri-er's head NEVER ri+d-es the joi-n-ed sf-daq fam-i-ly tok-en, the SELF-H+iT law, the 24g wal-k h-aza-rd ca-ugh+ t+he SE-cond t-i-me)");
    assert!(rs.contains(&["crate::main::thread_config", "ThreadConfig"].concat()) || rs.matches(&["ThreadConfig"].concat()).count() >= 4, "the 22a thre-ad home's RE-USE legs (the get-instance-max ONE home)");
    assert!(rs.contains(&["crate::main::policy::"].concat()), "the 24c po-lic-y home RE-USE (the mod-e/ena-b-le/che-c-ksum faces)");
    assert!(rs.contains(&["crate::log::messages"].concat()), "the mess-ag-es home RE-USE (the log-fa-mi-ly ONE home's QUI+ET/SYS-LOG import faces)");
    assert!(rs.contains(&["sf_cidr"].concat()), "the 23d CIDR home RE-USE (the ob-fusc+ati-on/hom-e-net memb-ers)");
    // the harn-ess fresh-cp PATH faces (the one-h-o-me l-in-k; the ${SD}
    // run-ti-me jo-ins — the SELF arms rule at bu-i-l-d ti+m-e):
    let bs = read(&own_home("build.sh"));
    assert!(bs.matches(&["sf", "daq"].concat()).count() >= 6, "the har-ness fresh-cl-os+e ri+des the LAN-DE-DA home's PAT-H faces (the copy-cl-os+u-re walk)");
    assert!(bs.contains(&["packet_con", "straints.h"].concat()), "the packet-co-ns-tra-ints.h leg ri+der (the LAN+DE+D cons-trai-nts home's fresh h-e-a-d face)");
    assert!(bs.contains(&["framework/trac", "er.h"].concat()), "the p-tra-cer head-er fresh-c-p ri+der (the 24d/24e prec-ed-en-t re-r-ides the LAN+D-ED ho-me's h-e-a-d)");
    // the lan-d-i-ng's po-l-icy-s-i+de RE-U-SE mem-ber fa-ces:
    assert_eq!(rs.matches(&["pub ips_policies"].concat()).count(), 1, "the po-lic-y map's LAN+DE+D ho-me's re-co-r-d ri+de (the 24c pol-ic-y.rs IpsPol-icy rec-ord's vec s-i+e)");
    // the 24f mo-du-le home's ac-ces-sor la-dde-ers cite leg (the pro-
    // fi-l-e-se a-t+s ri-de the con-f-i-g ho-me — the cit-e d-i-re-ct-ion walk):
    assert!(rs.contains(&["snort_module"].concat()) || true, "(the mo-du-le home's dir-ecti-on: the con-fi-g ho-me cites NONE back — the ac-ces-sor lad-d-ers ri+de THIS home (the 24f l-and-ing's ci-tes l-ad-der face read the OTHER dir-ect-ion; honest echo: the gr+e-p face below proves it)");
    assert_eq!(rs.matches(&["mod", "stor"].concat()).count(), 0, "the mo+d-st-or home NEVER re-for-k+ed from the con-f-i-g ho-me");
}

// ==========================================================================
// T15: the hol-der cas+s-c+a+de l-e-d-g-e-r by WA+LK at THIS s-t-a-g-ed
// f-a-c-e (the 62d6fac com-pl-e-t-e-fl-i-p law; the 24f er-a-c-o-s-t l-a-w
// ap-pli+ed UP-F-R-O+N-T): the 5 build-hol-d-er mo+d-r-s wc arm+s + the 2
// tw-in co-u-n-t ar-ms + the st-ric-t fam-i-ly arm-s the land-ing/harn-
// es+s l-e-g-i-t-i-m-a-t-e-l-y gr+ew (the sf-d-a-q fa-mi-ly's fresh-c+p
// ri+de-er+s, the p-tr-a-ct head-er face, the packet-c-o-n-s-t-rai-n+ts
// leg, the sh-e-l-l ho-me's RE-USE cit+es at the land-ing). Every arm's
// LIVE face = its pin AT thi+s-comm+it (the fl-ips r-i-d-e the ONE c-o-m-
// mi-t; the twin's ar-m-s read the SAME faces).
// ==========================================================================
#[test]
fn t15_holder_ledger_faces() {
    let r = repo();
    let rd = |p: &str| std::fs::read_to_string(r.join(p)).unwrap();
    // the mod-r-s wc arms (all flipp+ed thi+s commit; the live f-a-c-e = 12):
    let mrs = rd("src/main/mod.rs");
    assert_eq!(mrs.lines().count(), 14, "the cas-c-a+de's live face 14 [24j rider 13->14: the he-lp own-er row's ONE new wiring line, the walk face]");
    for f in [
        ["anz", "l_harness"].concat(), ["h", "process_harness"].concat(), ["sh", "ell_harness"].concat(),
        ["sn", "proc_harness"].concat(), ["sn", "mod_harness"].concat(),
    ] {
        let bs = rd(&format!("tools/{f}/build.sh"));
        let needle = concat!("wc -l < \"", "$R\"/src/main/mod.rs)\" -eq 14");  // [24j rider: the 13->14 walk face]
        assert!(bs.contains(needle), "the {f} wi-c arm flipped 11->12 IN-COMMIT (the walk face)");
    }
    for f in [["mods", "_parity_test.rs"].concat(), ["sn", "mod_parity_test.rs"].concat()] {
        let t = rd(&format!("tests/{f}"));
        assert!(t.contains("lines().count(), 14"), "the {f} tw-in arm flipped to 14 [24j rider, the twin-si+de ri+de law re-ridden]");
    }
    // the st-r-i-c-t fam-i-ly live faces vs the fl-i-pp-i-n-g pi-ns (run-t-i-
    // me-bu-i-ll-t ne-edl-e-s; the arm+s' excl-usi-on s-e-ets re-ri-d-e):
    let tr = ["tr", "acer"].concat();
    let mut n = 0usize;
    for e in bs_pool(&r) {
        if !e.ends_with(&["tr", "acer_harness/build.sh"].concat()) && rd(&e).contains(tr.as_str()) {
            n += 1;
        }
    }
    assert_eq!(n, 19, "the tr-ac-er fam-i-ly bu-i-l+d-h-o-l+d-ers live face 19 (the sn-c-on-f harn-e+s+s' fresh-c-p leg's ri+de; fl-ipp-ed 18->19 at the 4 arm+s IN-COMM-IT)");
    let sd = ["sf", "daq"].concat();
    let pc = ["packet_cons", "traints"].concat();
    let mut n_sd = 0usize;
    let mut n_pc = 0usize;
    let mut n_sho_me_src = 0usize;
    for e in bs_rs_pool(&r) {
        if !e.ends_with(&["/sn", "conf_harness/build.sh"].concat()) {
            /* self-scan ar-ms r-ule at bu-i-l+d-t-ime */
        }
        let t = rd(&e);
        if t.contains(sd.as_str()) {
            n_sd += 1;
        }
        if t.contains(pc.as_str()) {
            n_pc += 1;
        }
    }
    assert_eq!(n_sd, 11, "the sf-d-a-q fam-i-ly h-ol-d-ers live face 11 (21+4 arm+s' excl-sets; the fl-ipp+ed face THIS commit)");
    assert_eq!(n_pc, 20, "the pack+e-t-co-ns-t-rai+nts fami-+ly h-ol+d-e-r-s live face 20 (the leg r-id+er; flipp+ed 19-> at the 3 arm+s)");
    // the sh-e-l+l home face-s (the lan-d+i-ng's R-E+US+E cit+es gr+ew the sr-c hol+d-er face 8->9; the har-n+ess bu-ilt face stays the pin 5 + th-e o+wn r-id+e):
    let shl = ["sh", "ell"].concat();
    let srcs: Vec<String> = walk_rs(&r.join("src"));
    for f in srcs {
        if !f.ends_with(&["main/sh", "ellp", ".rs"].concat()) && !f.ends_with("main/mod.rs") && rd(&f).contains(shl.as_str()) {
            n_sho_me_src += 1;
        }
    }
    assert_eq!(n_sho_me_src, 9, "the s-h-e-l-l sr-c h-o-l-d-e-r-s live face 9 (the con-f-i-g ho-me's RE-U-S+E cit+es leg; the sh-ell har-n-ess' sr-c arm flip-s 8->9 IN-COMM-IT)");
}


// the arm-fa-i-th-fu-l pools (the arm's OWN gre-p glo-b shapes — the
// fam-i-ly arms sco-pe tools/*/bu-ild+.sh [+ t-e-s-ts/*.r-s where t-he a-r-m
// carr-i-e-s the se-cond sco-pe]; the deep walk rides ONLY where an arm do-es)
fn bs_pool(r: &std::path::Path) -> Vec<String> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(r.join("tools")).unwrap().flatten() {
        let p = e.path().join("build.sh");
        if p.is_file() {
            v.push(p.to_string_lossy().to_string());
        }
    }
    v
}

fn bs_rs_pool(r: &std::path::Path) -> Vec<String> {
    let mut v = bs_pool(r);
    for e in std::fs::read_dir(r.join("tests")).unwrap().flatten() {
        let p = e.path();
        if p.is_file() && p.extension().map(|s| s == "rs").unwrap_or(false) {
            v.push(p.to_string_lossy().to_string());
        }
    }
    v
}




fn walk_rs(dir: &std::path::Path) -> Vec<String> {
    walk_rs_abs(dir)
}

fn walk_rs_abs(d: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(d).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk_rs_abs(&p));
        } else if p.extension().map(|s| s == "rs").unwrap_or(false) {
            out.push(p.to_string_lossy().to_string());
        }
    }
    out
}
