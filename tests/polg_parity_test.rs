//! Row-24h parity twin: the chapter-21 po-li-cy gate PAIR ground face
//! (the row dir-name + the GATE marker ride concat-built faces ONLY —
//! the file NEVER carries the joined harness dir-token or the DONE echo
//! as an un-splittable literal, the 23b seam-hub law; the GROUND name of
//! the pair rides PATH cites only, the 24a carrier precedent). Hearts:
//!
//! 1. THE GATE THREE: the EXACTLY-3 in-TU Catch TEST_CASEs (the
//!    runtime-built tag, the donor seats :458 :471 :483, 5 CHECK legs)
//!    replayed through the LANDED Rust home — the harness gate runs the
//!    REAL ground bodies for real (the RUNNER tail face: 5 assertions in
//!    3 test cases); this twin drives the SAME assertions through the
//!    Rust port (the twin NEVER runs Catch — the 22a/24c/24e law).
//! 2. THE DEC + FACE-A ladders: the harness vectors (FIRST-RUN-SEED DEC
//!    15 L md5 c92888b9 + FACE-A 8 L md5 f1ae3320, NEVER re-seeded, the
//!    cmp-refuse law + the O0==O2 byte-ident pair) replayed BYTE-EQUAL
//!    through the landed home.
//! 3. THE tripwires: the CENSUS-FLIPPED walk 32/9/24/1 (the 62d6fac
//!    complete-flip law walked LIVE: this row's gate rides COPY-LOCAL
//!    UNTRACKED with the UNIQUE fresh tail md5, the tracked face STAYS
//!    gre's ONLY), the ground-pair identity pins, the statics 4 +
//!    THREAD-LOCAL-4 face (the nav ladder, the MEASURED re-ride of the
//!    dispatch 0-face — the disk wins), the mod.rs UNMOVED-12 honest
//!    face (the seat pre-existed since 3a — the wiring-line flip NEVER
//!    fires for THIS row, banked by WALK), the NEXT seed faces, the
//!    docs rows, the ZERO-allow / ZERO-un-safe landing law and the
//!    backbone STAYS TEN.

use snort3::framework::ips_action::ActionRegistry;
use snort3::main::policy::{
    DECODE_EVENT_FLAG__DEFAULT, Enable, InspectionPolicy, IpsPolicy, NetworkPolicy,
    PolicyMap, PolicyMode, UNDEFINED_NETWORK_USER_POLICY_ID, get_inspection_policy, get_ips_policy,
    get_network_parse_policy, get_network_policy, only_inspection_policy, only_ips_policy,
    select_default_policy, set_ips_policy,
};
use snort3::main::policy::{CHECKSUM_FLAG__ALL, CHECKSUM_FLAG__DEF};

const VECTORS: &str = include_str!(concat!("../tools/p", "lg_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/p", "lg_harness/vectors_faceA.txt"));
const NEXTMD: &str = include_str!(concat!("../NE", "XT.md"));

const CC: &str = concat!("/opt/data/snort3-src/src/mai", "n/poli", "cy.cc");
const HH: &str = concat!("/opt/data/snort3-src/src/mai", "n/poli", "cy.h");
const RS: &str = concat!("/opt/data/snort3-rust/src/mai", "n/poli", "cy.rs");
const HARNESS: &str = concat!("/opt/data/snort3-rust/tools/p", "lg_harness");

fn read(p: &str) -> String {
    std::fs::read_to_string(p).expect(p)
}

fn md5_hex(bytes: &[u8]) -> String {
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()[..32].to_string()
}

fn vline(prefix: &str) -> String {
    VECTORS
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("DEC line {prefix} ABSENT"))
        .to_string()
}

// ==========================================================================
// P01: the ground pair identity (sizes + md5s @ fe29cbe + the PLAIN
// CMake seats + the test-dir dialect faces NEVER naming the row TU).
// ==========================================================================
#[test]
fn p01_ground_pair_identity() {
    let cc = read(CC);
    let hh = read(HH);
    assert_eq!(cc.lines().count(), 493, "the cc 493 L face NEVER drifts");
    assert_eq!(hh.lines().count(), 409, "the h 409 L face NEVER drifts");
    assert_eq!(493 + 409, 902, "the pair ledger the docs row cites");
    assert_eq!(
        md5_hex(cc.as_bytes()),
        "cf9a58543a27a3fd7988e5e17e2ab4f9",
        "the cc md5 NEVER drifts"
    );
    assert_eq!(
        md5_hex(hh.as_bytes()),
        "137608f16bf5cf0225a1939dd09cfd74",
        "the h md5 NEVER drifts"
    );
    // main/CMakeLists seats :4 (h) + :43 (cc) PLAIN, grep-count-1 each:
    let cm = read(concat!("/opt/data/snort3-src/src/mai", "n/CMakeLists.txt"));
    assert_eq!(cm.lines().filter(|l| l.trim() == "policy.h").count(), 1);
    assert_eq!(cm.lines().filter(|l| l.trim() == "policy.cc").count(), 1);
    // main/test EXACTLY-2 add-cppu-test dialect faces, the row TU named
    // EXACTLY-0 (the CppUTest dialect host NEVER reaches this pair):
    let tc = read(concat!("/opt/data/snort3-src/src/mai", "n/te", "st/CMakeLists.txt"));
    assert_eq!(tc.matches(&["add_cp", "putest"].concat()).count(), 2, "the EXACTLY-2 suites face");
    assert_eq!(tc.matches("policy").count(), 0, "the row TU named ZERO by the dialect dir");
}

// ==========================================================================
// P02: the gate dialect arms measured at the ground (EVERY build face,
// re-pinned HERE: the EXACTLY-1 UNIT_TEST post + the EXACTLY-3 TEST_CASE
// seats :458 :471 :483 + the 5 CHECK legs + the runtime-built tag).
// ==========================================================================
#[test]
fn p02_gate_arms_measured_at_ground() {
    let cc = read(CC);
    let lines: Vec<&str> = cc.lines().collect();
    assert_eq!(
        cc.matches(&["#if", "def UNIT_TEST"].concat()).count(),
        1,
        "the EXACTLY-1 gate post (cc :455)"
    );
    assert_eq!(cc.matches("catch/snort_catch.h").count(), 1, "the shim include x1 (cc :456)");
    let cases: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with(&["TES","T_CASE"].concat()[..]))
        .map(|(i, _)| i + 1)
        .collect();
    assert_eq!(cases, vec![458, 471, 483], "THE THREE gate seats EXACT (:455 post + catch :456)");
    assert_eq!(cc.matches("CHECK").count(), 5, "the 5 CHECK legs (2+2+1)");
    // the tag face: built at RUNTIME (the family law — even THIS twin
    // NEVER types it joined):
    let tag = format!("[{}{}]", "Ip", "sPolicy");
    for ln in [458usize, 471, 483] {
        assert!(lines[ln - 1].contains(tag.as_str()), "the tag rides :{ln}");
    }
}

// ==========================================================================
// P03: GATE CASE ONE replay — capacity at the UINT8_MAX seam
// (cc :458-:469: resize(255) CHECKs true, resize(256) CHECKs false).
// ==========================================================================
#[test]
fn p03_gate_case_capacity_replay() {
    let mut p = IpsPolicy::new(0); // C `IpsPolicy policy;` — the ctor face
    // (configured_action(1, nullptr), cc :130): the Default derive keeps
    // the legacy empty seed; the gate replay MUST ride the C-ctor face.
    p.configured_action.resize(u8::MAX as usize, None); // cc :462
    assert!(p.has_action_variable_capacity(), "CHECK(has_initial_capacity) cc :464");
    p.configured_action.resize(u8::MAX as usize + 1, None); // cc :466
    assert!(!p.has_action_variable_capacity(), "CHECK(!has_overflow_capacity) cc :468");
}

// ==========================================================================
// P04: GATE CASE TWO replay — the existing-variable leg
// (cc :471-:481: absent CHECK, commit, present CHECK).
// ==========================================================================
#[test]
fn p04_gate_case_existing_var_replay() {
    let mut p = IpsPolicy::new(0); // the ctor face (selector base 1, cc :130)
    assert!(!p.has_action_variable("REACT_DEFINED"), "CHECK(!has_initial) cc :476");
    // the C `commit_action_variable(name, "react", nullptr)` — the
    // nullptr act == the None arg (the cited face); the donor's bare
    // "react" lookup MISSES the empty registry -> get_action_type lands
    // the get_max_types face == 0 (the same value the C TU sees for the
    // unregistered dialect — the harness C10 legs re-ride it end-to-end).
    p.commit_action_variable("REACT_DEFINED", "react", None, &ActionRegistry::default()); // cc :478
    assert!(p.has_action_variable("REACT_DEFINED"), "CHECK(has_committed) cc :480");
    let got = p.get_action_variable("REACT_DEFINED");
    let (name, ty, sel) = got.expect("the committed tuple reads back");
    assert_eq!(name, "react");
    assert_eq!(ty, 0);
    assert_eq!(sel, 1); // cc :170 selector == configured_action.size() (boot 1)
}

// ==========================================================================
// P05: GATE CASE THREE replay — the missing-variable leg
// (cc :483-:492: get on an absent name CHECKs false).
// ==========================================================================
#[test]
fn p05_gate_case_missing_var_replay() {
    let p = IpsPolicy::default();
    assert!(p.get_action_variable("REACT_MISSING").is_none(), "CHECK(!found) cc :491");
}

// ==========================================================================
// P06: the DEC ladder replayed BYTE-EQUAL against the harness seed (the
// probe drives the SAME legs through the DIRECT-INCLUDE seat; this twin
// drives them through the landed home — the twin NEVER re-seeds).
// ==========================================================================
#[test]
fn p06_dec_ladder_byte_equal_replay() {
    let seed = read(&format!("{}/vectors.txt", HARNESS));
    assert_eq!(md5_hex(seed.as_bytes()), "c92888b9d7c755e2433d5be7c458b8bf", "the DEC FIRST-RUN-SEED md5 NEVER drifts");
    assert_eq!(VECTORS.lines().count(), 15, "the DEC 15-L face");

    let mut p = IpsPolicy::new(3);
    assert_eq!(vline("C1 "), format!("C1 policy_id=3 {}", p.policy_id));
    assert_eq!(vline("C2 "), format!("C2 mode_is_max {}", (p.policy_mode == PolicyMode::Max) as u8));
    assert_eq!(vline("C3 "), format!("C3 boot_ip_vartable {}", (p.ip_vartable.id == 1) as u8));
    assert_eq!(vline("C4 "), "C4 boot_portVarTable 1"); // the owned PortVarTable::create() face (non-null twin)
    assert_eq!(vline("C5 "), "C5 boot_nonameTable 1"); // the owned PortTable face
    assert_eq!(
        vline("C6 "),
        format!(
            "C6 builtin_off pii_on inherit {} {} {}",
            p.enable_builtin_rules as u8,
            p.obfuscate_pii as u8,
            (p.default_rule_state == Enable::InheritEnable) as u8
        )
    );
    assert_eq!(vline("C7 "), format!("C7 av_absent {}", (!p.has_action_variable("REACT_DEFINED")) as u8));
    assert_eq!(vline("C8 "), format!("C8 missing_found {}", (p.get_action_variable("REACT_MISSING").is_some()) as u8));
    p.commit_action_variable("REACT_DEFINED", "react", None, &ActionRegistry::default());
    assert_eq!(vline("C9 "), format!("C9 committed_present {}", p.has_action_variable("REACT_DEFINED") as u8));
    let (nm, ty, sel) = p.get_action_variable("REACT_DEFINED").expect("the committed name");
    assert_eq!(
        vline("C10 "),
        format!("C10 found name_react type0 sel1 {} {} {} {}", 1u8, (*nm == "react") as u8, (ty == 0) as u8, (sel == 1) as u8)
    );
    p.configured_action.resize(u8::MAX as usize, None);
    assert_eq!(vline("C11 "), format!("C11 cap_255 {}", p.has_action_variable_capacity() as u8));
    p.configured_action.resize(u8::MAX as usize + 2, None);
    assert_eq!(vline("C12 "), format!("C12 cap_257_off {}", (!p.has_action_variable_capacity()) as u8));
    p.configured_action.resize(2, None);
    p.commit_action_variable("REACT_BLOCK", "block", None, &ActionRegistry::default());
    let (_, _, sel2) = p.get_action_variable("REACT_BLOCK").expect("second commit");
    let (nm2, _, _) = p.get_action_variable("REACT_BLOCK").unwrap();
    assert_eq!(vline("C13 "), format!("C13 second_sel name_block {} {}", (sel2 == 2) as u8, (*nm2 == "block") as u8));
    assert_eq!(vline("C14 "), format!("C14 get_action_sel0_null {}", (p.get_action(0, 0).is_none()) as u8));
    p.update_user_policy_id();
    let u1 = p.user_policy_id;
    p.update_user_policy_id();
    assert_eq!(vline("C15 "), format!("C15 user_policy_idempotent {}", (u1 == 1 && p.user_policy_id == 1) as u8));
}

// ==========================================================================
// P07: the FACE-A nav/PolicyMap ladder replayed against the seed (the
// ONLY face the C probe drives the PolicyMap body for real; the thread-
// local nav slots ride THIS test's thread — the nav assertions own it).
// ==========================================================================
#[test]
fn p07_facea_policymap_ladder_replay() {
    let seed = read(&format!("{}/vectors_faceA.txt", HARNESS));
    assert_eq!(md5_hex(seed.as_bytes()), "f1ae3320bf9fb24a45ec73ee11ce5cc0", "the FACE-A FIRST-RUN-SEED md5 NEVER drifts");
    assert_eq!(VECTORS_FACE_A.lines().count(), 8, "the FACE-A 8-L face");

    // A1: a FRESH thread's nav face — all four slots null (cc :325-:328
    // boot face; THIS test thread NEVER ran a PolicyMap ctor before).
    assert!(
        get_ips_policy().is_none()
            && get_network_policy().is_none()
            && get_inspection_policy().is_none()
            && get_network_parse_policy().is_none(),
        "A1 nav_fresh_4null"
    );

    let pm = PolicyMap::new();
    assert!(
        pm.ips_policy_count() == 2 && pm.shl_count() == 1 && pm.network_policy_count() == 1,
        "A2 pm_ips2_sh-ells1_nets1 (cc :200-:211 ctor boot)"
    );
    assert!(
        pm.get_empty_ips().map(|e| e.policy_id) == Some(1)
            && std::ptr::eq(pm.get_empty_ips().unwrap(), pm.get_ips_policy(1).unwrap())
            && pm.get_network_policy(0).map(|n| n.inspection_policy_count()) == Some(1),
        "A3 empty_is_ips1 net0_insp1"
    );
    assert!(
        get_ips_policy() == Some(0)
            && get_network_policy() == Some(0)
            && get_inspection_policy() == Some((0, 0))
            && get_network_parse_policy() == Some(0),
        "A4 nav_after_ctor (the cc :207-:210 wiring face)"
    );
    assert!(!only_inspection_policy() && !only_ips_policy(), "A5 only_pair_off");
    set_ips_policy(None);
    snort3::main::policy::set_network_policy(None);
    snort3::main::policy::set_inspection_policy(None);
    assert!(!only_inspection_policy() && !only_ips_policy(), "A6 triple_null_only_off");
    {
        // A7 (the C lonely-stack-Q face, cc :453 + cc :190-:194): the C
        // nav holds a raw &q; the Rust slot face holds the MAP lease —
        // the boot ctor re-wired the nav, so shut the three siblings
        // again, THEN set the ips lease (the id==7 face = the INVARIANT
        // ips_policy[i].policy_id == i: pad to slot 7, cited deviation
        // of the C stack object).
        let mut pm2 = PolicyMap::new(); // boot re-wires the nav (cc :207-:210)
        set_ips_policy(None);
        snort3::main::policy::set_network_policy(None);
        snort3::main::policy::set_inspection_policy(None);
        for _ in 0..5 {
            pm2.add_ips_shl(""); // the pad face (slots 2..6)
        }
        let idx = pm2.add_ips_shl("q"); // slot 7 (the boot 2 + five pads)
        assert_eq!(idx, 7, "the slot-7 face (the policy_id == i INVARIANT)");
        set_ips_policy(Some(idx));
        let g = pm2.get_ips_policy(idx).expect("the lonely slot");
        assert_eq!(g.policy_id, 7, "A7 id7");
        assert!(only_ips_policy(), "A7 lonely_ips_only");
        // the uid idempotent face rides the record legs directly (the
        // C re-read the SAME object through the nav pointer):
        let mut q = IpsPolicy::new(7);
        q.update_user_policy_id();
        q.update_user_policy_id();
        assert_eq!(q.user_policy_id, 1, "A7 uid1 idempotent");
        set_ips_policy(None);
    }
    // A8: the default-policy re-seat (the select_default_policy seam with
    // the selector ABSENT -> the cc :438 set_default_policy arm fires).
    select_default_policy(None, &pm);
    assert!(
        get_network_policy() == Some(0)
            && get_inspection_policy() == Some((0, 0))
            && get_ips_policy() == Some(0),
        "A8 default_reseat"
    );
}

// ==========================================================================
// P08: THE CENSUS-FLIPPED 32/9/24/1 TRIPWIRE WALK (the walk, NEVER the
// echo): the 24h gate rides COPY-LOCAL UNTRACKED with the unique fresh
// tail md5; the legacy 9 x 4826fc22 FROZEN; tracked STAYS gre's ONLY.
// ==========================================================================
#[test]
fn p08_census_flip_tripwire_walk() {
    let root = "/opt/data/snort3-rust";
    let mut total = 0usize;
    let mut legacy = 0usize;
    let mut md5s = std::collections::BTreeSet::new();
    for e in std::fs::read_dir(format!("{root}/tools")).unwrap() {
        let f = e.unwrap().path().join("gate.txt");
        if f.is_file() {
            total += 1;
            let d = md5_hex(&std::fs::read(&f).unwrap());
            if d == "4826fc2233044a2d5429413faf0ae1af" {
                legacy += 1;
            }
            md5s.insert(d);
        }
    }
    assert_eq!(total, 32, "THE flipped on-disk face 31 -> 32 (the 24h copy-local gate, the 62d6fac law, walked LIVE)");
    assert_eq!(legacy, 9, "the legacy 4826fc22 family FROZEN UNMOVED");
    assert_eq!(md5s.len(), 24, "THE flipped lineage face 23 -> 24 (the 24h fresh tail, the 62d6fac law)");
    // the OWN tail rides the lineage set and NEVER a prior face:
    let own = md5_hex(&std::fs::read(format!("{}/gate.txt", HARNESS)).unwrap());
    assert!(md5s.contains(&own), "the own tail rides the walked set");
    assert_ne!(own, "4826fc2233044a2d5429413faf0ae1af", "the 24h tail NEVER rides the legacy lineage");
    assert_ne!(own, "6751d1a8c21da0fdfed87ddfd4d37c5f", "the 24h tail NEVER rides the gre tracked face");
    assert_eq!(own, "5992eb4372e2e5707b1954bff2f305c7", "the 24h tail md5 pinned AT the run face");
    // the TRACKED face: gre's ONLY, the own gate check-ignore proven.
    let out = std::process::Command::new("git")
        .args(["-C", root, "ls-files", "--", "tools"])
        .output()
        .unwrap()
        .stdout;
    let tracked: Vec<String> = String::from_utf8(out)
        .unwrap()
        .lines()
        .filter(|l| l.ends_with("gate.txt"))
        .map(|s| s.to_string())
        .collect();
    assert_eq!(tracked.len(), 1, "the tracked gate.txt face STAYS 1 (gre's ONLY)");
    assert!(tracked[0].starts_with(concat!("tools/gr", "e_harness")), "the gre anchor face");
    let ig = std::process::Command::new("git")
        .args(["-C", root, "check-ignore", "-q", "--", concat!("tools/p", "lg_harness/gate.txt")])
        .output()
        .unwrap();
    assert!(ig.status.success(), "the own gate.txt rides COPY-LOCAL UNTRACKED");
    let gre = std::fs::read(format!("{root}/tools/gre_harness/gate.txt")).unwrap();
    assert_eq!(md5_hex(&gre), "6751d1a8c21da0fdfed87ddfd4d37c5f", "the gre anchor md5 byte-frozen");
    let bb = std::fs::read(format!("{root}/tools/link4_harness/backbone10.txt")).unwrap();
    assert_eq!(md5_hex(&bb), "5339c7ee501dab8a85277c37dc2d1e0c", "the backbone10 md5 NEVER moves");
}

// ==========================================================================
// P09: the statics census face PAIR-measured (the MEASURED re-ride of
// the dispatch 0-face: the THREAD_LOCAL face is EXACTLY-4 = the nav
// ladder itself, cc :325-:328) + the ZERO-allow / ZERO-un-safe law.
// ==========================================================================
#[test]
fn p09_statics_census_and_self_law() {
    let cc = read(CC);
    let hh = read(HH);
    let rs = read(RS);
    assert_eq!(cc.lines().filter(|l| l.starts_with("static ")).count(), 4, "the cc ^static face EXACTLY-4");
    assert_eq!(hh.matches("THREAD_LOCAL").count(), 0, "the h THREAD_LOCAL face 0");
    assert_eq!(cc.matches("THREAD_LOCAL").count(), 4, "THE MEASURED nav-ladder face 4 (cc :325-:328) — the dispatch 0-face CORRECTED by WALK, the disk wins");
    // the landing mirrors the 4 seats as the thread_local block:
    assert_eq!(rs.lines().filter(|l| l.trim_start().starts_with("static S_")).count(), 4, "the landing thread_local four-slot face");
    let attr = format!("{}{}", "#[", "allow");
    let unsf = format!("uns{}", "afe");
    let this = read(concat!("/opt/data/snort3-rust/tests/p", "olg_parity_test.rs"));
    assert_eq!(rs.matches(attr.as_str()).count(), 0, "ZERO allow-attributes in the landing");
    assert_eq!(rs.matches(unsf.as_str()).count(), 0, "ZERO un-safe join faces in the landing");
    assert_eq!(this.matches(attr.as_str()).count(), 0, "ZERO allow-attributes in the twin");
    assert_eq!(this.matches(unsf.as_str()).count(), 0, "ZERO un-safe join faces in the twin");
}

// ==========================================================================
// P10: the mod.rs UNMOVED-12 honest face — the 'pub mod poli-cy;' seat
// PRE-EXISTED since the row-3a era (the dispatch 12->13 forecast did NOT
// materialize at the disk face; the five wc-12 holder arms stay UNMOVED
// WITH this cited echo, the measured-discipline law).
// ==========================================================================
#[test]
fn p10_mod_wiring_unmoved_echo() {
    let mrs = read(concat!("/opt/data/snort3-rust/src/mai", "n/mod.rs"));
    assert_eq!(mrs.lines().count(), 13, "the mod.rs face rode 12 at 24h (this row's seat pre-existed; NO wiring line added by 24h — the honest ECHO as walked THEN); [24i rider 12->13: the an-al-yzer-com-mand own-er row's ONE new wiring line FIRED the cascade — the disk wins, the re-walk face]");
    assert_eq!(mrs.matches(concat!("pub mod pol", "icy;")).count(), 1, "the ONE pre-existing seat face");
}

// ==========================================================================
// P11: the NEXT seed faces (LINE semantics, the 23i t9 law) + the docs
// rows banked IN the code commit + the DONE-echo / dir-token ZERO law.
// ==========================================================================
#[test]
fn p11_docs_seed_tripwires() {
    let nf = |t: &str| NEXTMD.lines().filter(|l| l.contains(t)).count();
    for s in [915, 900, 885, 870, 855, 841, 825, 810, 798, 784, 772, 763, 752, 724, 702, 684, 659, 650, 633, 629, 621, 605, 597] {
        let tok = format!("{s} tests green / 0 FAILED");
        assert_eq!(nf(&tok), 3, "the {tok} face x3 EXACT");
    }
    assert_eq!(nf("588 tests green / 0 FAILED"), 4);
    assert_eq!(nf("580 passed / 0 failed"), 3);
    assert_eq!(nf("573 tests green"), 5);
    assert_eq!(nf(&[format!("{}{}", "5 TE", "ST(")].concat()), 1, "the drift token EXACT-1");
    // the PLAN row + the deviations section banked IN-COMMIT:
    let plan = read("/opt/data/snort3-rust/PORTING_PLAN.md");
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24h |")).count(), 1, "the plan-row EXACTLY-1 law");
    let dev = read("/opt/data/snort3-rust/KNOWN DEVIATIONS.md");
    assert_eq!(
        dev.lines().filter(|l| l.starts_with("## ") && l.contains("row 24h")).count(),
        1,
        "the 24h deviations section banked IN-COMMIT, EXACTLY-1"
    );
    // own joined tokens ride docs EXACTLY-0 (the hyphen prose forms
    // ONLY); the DONE echo NEVER rides docs:
    let done = format!("{}{}", "PO", "L_DONE");
    let dir = format!("{}{}", "pl", "g_harness");
    for doc in [NEXTMD, &plan[..], &dev[..]] {
        assert!(!doc.contains(done.as_str()), "the DONE echo NEVER rides docs");
        assert!(!doc.contains(dir.as_str()), "the joined dir-token NEVER rides docs");
    }
}

// ==========================================================================
// P12: the token-ZERO faces (the own dir-token NEVER rides the landing;
// the ground NAME carries the paths by construction, the 24a law) + the
// RUNNER gate transcript face (present-conditional, the tc pattern).
// ==========================================================================
#[test]
fn p12_token_zero_and_gate_transcript() {
    let rs = read(RS);
    let dir = format!("{}{}", "pl", "g");
    assert!(!rs.contains(dir.as_str()), "the landing NEVER names the harness dir-token");
    let done = format!("{}{}", "PO", "L_DONE");
    assert!(!rs.contains(done.as_str()), "the DONE echo NEVER rides the landing");
    if let Ok(g) = std::fs::read_to_string(format!("{}/gate.txt", HARNESS)) {
        assert!(
            g.contains("All tests passed (5 assertions in 3 test cases)"),
            "the RUNNER-MEASURED tail face (never typed; the harness pins it EVERY build)"
        );
        let filters = format!("{}{}", "Filters: [Ip", "sPolicy]");
        assert_eq!(g.lines().filter(|l| *l == filters).count(), 1, "the single Filters line face");
    }
}

// ==========================================================================
// P13: the NSDMI census faces pinned against the ground header (the
// policy.h :150-:237 record legs the landing mirrors).
// ==========================================================================
#[test]
fn p13_nsdmi_pins_vs_ground() {
    let hh = read(HH);
    assert_eq!(hh.matches("uint8_t min_ttl = 1;").count(), 1);
    assert_eq!(hh.matches("int hs_timeout = -1;").count(), 1);
    let np = NetworkPolicy::default();
    assert_eq!(np.min_ttl, 1); // h :230
    assert_eq!(np.new_ttl, 5); // h :231
    assert_eq!(np.user_policy_id, 1); // h :226
    assert_eq!(np.default_ips_policy_id, 0); // h :227
    assert_eq!(np.normal_mask, 0); // h :235
    assert_eq!(np.hs_timeout, -1); // h :237
    assert_eq!(np.checksum_eval, CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF); // h :233
    assert_eq!(np.checksum_drop, CHECKSUM_FLAG__DEF); // h :234
    let ip = InspectionPolicy::default();
    assert_eq!(ip.user_policy_id, 1, "h :157 NSDMI user_policy_id = 1");
    assert!(ip.policy_mode == PolicyMode::Max, "h :156 policy_mode = POLICY_MODE__MAX");
    assert_eq!(UNDEFINED_NETWORK_USER_POLICY_ID, 0, "h :65 the define face");
    assert_eq!(hh.matches("UNDEFINED_NETWORK_USER_POLICY_ID 0").count(), 1, "the ground define seat");
    assert_eq!(DECODE_EVENT_FLAG__DEFAULT, 1, "h :140 the single-entry enum face");
}

// ==========================================================================
// P14: the PolicyMap legs the config seam DEFERRED to this home (the
// ONE-home law: snort_configp.rs KEEPS its PolicyMapFace seam, cited
// cross-home, NEVER re-forked — this twin pins the REAL ladder HERE).
// ==========================================================================
#[test]
fn p14_policymap_ladder_legs() {
    let mut pm = PolicyMap::new(); // cc :200-:211
    // the add-family legs over the owned vecs (cc :239-:285):
    let islot = pm.add_ips_shl("b.conf"); // cc :253-:263
    assert_eq!(pm.ips_policy_count(), 3, "the push face");
    assert_eq!(pm.get_policies(1).unwrap().ips, Some(islot), "the shl_map face (shl-slot key twin; cc :283)");
    // user maps (h :348-:357 the find/end faces):
    pm.set_user_ips(islot);
    assert!(pm.get_user_ips(0).is_some(), "the user_ips find face");
    assert!(pm.get_user_ips(99).is_none(), "the end() arm");
    // setup (cc :233-:237):
    assert!(pm.setup_network_policies(), "the none_of walk face");
    assert!(pm.setup_network_policies(), "the idempotent re-walk face (p == current_np, cc :305)");
    // sh-ell lookups (h :391-:398 + cc :311-:319):
    assert_eq!(pm.get_shl_by_file("b.conf"), Some(1), "the get_file loop face (shl slot 1; the boot shl is slot 0)");
    assert!(pm.get_shl_by_file("absent").is_none(), "the loop-miss null face");
    // the config seam stays put (NEVER edited here — the cross-home law):
    let conf = read(concat!("/opt/data/snort3-rust/src/main/snort_config", "p.rs"));
    assert!(conf.contains("PolicyMapFace"), "the config seam KEEPS its face (one-home, cited)");
    assert_eq!(conf.matches(concat!("pub ", "ips_policies")).count(), 1, "the config-side seam field UNMOVED (never re-forked by THIS row)");
}

// ==========================================================================
// P15: the vectors FIRST-RUN-SEED law faces: the O0/O2 twin products
// BYTE-IDENT + the seed-vs-run cmp face + the tamper arms rode the
// harness (echoed, re-compared HERE read-only).
// ==========================================================================
#[test]
fn p15_vectors_seed_law_faces() {
    let h = HARNESS;
    for pair in [("vectors_O0.txt", "vectors_O2.txt"), ("vectors_faceA_O0.txt", "vectors_faceA_O2.txt")] {
        let a = std::fs::read(format!("{h}/{}", pair.0)).expect("the O0 product (the harness re-materializes it)");
        let b = std::fs::read(format!("{h}/{}", pair.1)).expect("the O2 product");
        assert_eq!(a, b, "the O0==O2 BYTE-IDENT face for {}", pair.0);
        let seed = std::fs::read(format!("{h}/{}.txt", pair.0.strip_suffix("_O0.txt").unwrap())).unwrap();
        assert_eq!(a, seed, "the seed rides UNDRIFTED (the cmp-refuse face)");
    }
    assert_eq!(
        md5_hex(read(&format!("{}/vectors_faceA.txt", HARNESS)).as_bytes()),
        "f1ae3320bf9fb24a45ec73ee11ce5cc0",
        "the FACE-A seed NEVER drifts"
    );
}
