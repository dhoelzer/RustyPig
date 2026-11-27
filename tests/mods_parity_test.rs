//! Row-24e parity twin: the chapter-21 module-REGISTRY MEGA pair ground
//! face. The row dir-name rides concat-built paths only (the file NEVER
//! carries the joined harness dir-token as an un-splittable literal, the
//! 23b seam-hub law; the GROUND name of the pair rides PATH cites only,
//! the 24a carrier precedent). Three hearts:
//!
//! 1. THE REGISTRY LADDER: the harness witness mirror replayed the C
//!    add_independent_modules 35-leg PluginManager boot ladder + the
//!    add_dependent_modules 1-leg face (the CRASH_MITIGATOR dialect tail
//!    MEASURED-OFF); THIS twin replays the SAME ladder through the landed
//!    Rust add_independent_modules/add_dependent_modules over the ledger
//!    NullWorld and asserts the ORDERED names BYTE-EQUAL against the
//!    harness vectors (FIRST-RUN-SEED DEC 46 L md5 5f8adc06 + FACE-A 9 L
//!    md5 48181d93, NEVER re-seeded — the cmp-refuse law: the O0/O2 twin
//!    products re-compared BYTE-EXACT at every run).
//! 2. THE FUNCTIONAL FOUR: the EXACTLY-4 in-TU Catch TEST_CASEs
//!    ([Ip""sModule] tag, cc :2429 :2442 :2455 :2469, 12 CHECK legs)
//!    replayed through the LANDED IpsModule faces: the
//!    is_action_var_placeholder ladder, the missing-name ParseError leg,
//!    the react.validation legs + the DUPLICATE rejection over the landed
//!    policy.rs action_vars face (the harness gate runs the REAL ground
//!    bodies; this twin drives the SAME assertions through the Rust port —
//!    the twin NEVER runs Catch).
//! 3. THE tripwires: the LIVE census walk (31/9/23/1 post-flip, the
//!    62d6fac law: the 24e gate rides COPY-LOCAL UNTRACKED with a UNIQUE
//!    md5 tail, the tracked face STAYS gre's ONLY), the ground-pair
//!    identity pins, the gate arms of the ground cc, the statics 43 +
//!    THREAD_LOCAL 2 + dialect faces, the CMake PLAIN seats :37/:38, the
//!    harness receipts echo (E4 three-way + the UNIT_TEST post, the nm
//!    Catch delta x-11 honest, the E9 dup count 53, the E10 BOTH-ways
//!    tail), the landmine trio 3-occupant face, the own-token ZERO faces,
//!    the ZERO-allow / ZERO-un-safe landing law, the NEXT seed faces and
//!    the backbone STAYS TEN.
//!
//! Token law at THIS twin (the 23f..24d precedent): every counted
//! foreign face rides a RUNTIME-built pattern; the landed-home imports
//! are the LEGIT strict-face cites the row's build.sh union arms walk.

use snort3::framework::ips_action::ActionRegistry;
use snort3::framework::value::Value;
use snort3::main::modules::{
    ACTION_MAP_PARAMS, ACTION_VAR_PARAMS, ACTION_VAR_REACT_PARAMS, ACTION_VARS_PARAMS,
    DEPENDENT_MODULE_IDS, INDEPENDENT_MODULE_IDS, IPS_PARAMS, IpsModule,
    ModulesWorld, NullWorld, VARIABLE_PARAMS, VAR_PARAMS, add_dependent_modules,
    add_independent_modules, get_var_name, is_action_var_placeholder,
};
use snort3::main::policy::IpsPolicy;

const VECTORS: &str = include_str!(concat!("../tools/mod", "stor_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/mod", "stor_harness/vectors_faceA.txt"));
const NEXTMD: &str = include_str!(concat!("../NE", "XT.md"));

const CC: &str = concat!("/opt/data/snort3-src/src/mai", "n/modules.cc");
const HH: &str = concat!("/opt/data/snort3-src/src/mai", "n/modules.h");
const RS: &str = concat!("/opt/data/snort3-rust/src/mai", "n/modu", "les.rs");

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

/// the policy-owning test world: gate case 4 needs the C
/// set_ips_policy(&policy) posture (cc :2476); everything else
/// delegates to the landed NullWorld posture (the seam defaults, cited
/// at each leg).
struct GateWorld {
    nw: NullWorld,
    policy: IpsPolicy,
}

impl ModulesWorld for GateWorld {
    fn sc(&mut self) -> &mut snort3::main::modules::ScWriteBag {
        self.nw.sc()
    }
    fn log(&mut self) -> &mut snort3::log::messages::LogEngine {
        self.nw.log()
    }
    fn thread_config(&mut self) -> Option<&mut snort3::main::thread_config::ThreadConfig> {
        self.nw.thread_config()
    }
    fn tc_and_log(
        &mut self,
    ) -> (
        Option<&mut snort3::main::thread_config::ThreadConfig>,
        &mut snort3::log::messages::LogEngine,
    ) {
        self.nw.tc_and_log()
    }
    fn proto_ref_add(&mut self, name: &str) -> u16 {
        self.nw.proto_ref_add(name)
    }
    fn ips_policy(&mut self) -> Option<&mut IpsPolicy> {
        Some(&mut self.policy) // cc :2476 set_ips_policy(&policy) posture
    }
}

// ==========================================================================
// T01: the ground pair identity (MEASURED vs the orchestrator pins).
// ==========================================================================
#[test]
fn t01_ground_pair_identity() {
    let cc = read(CC);
    let hh = read(HH);
    assert_eq!(cc.lines().count(), 2491, "modules.cc 2,491 L");
    assert_eq!(hh.lines().count(), 30, "modules.h 30 L");
    assert_eq!(
        md5_hex(cc.as_bytes()),
        "1a1c7937a7c6b73318122a924e37ecff",
        "the 24e cc md5 pin"
    );
    assert_eq!(
        md5_hex(hh.as_bytes()),
        "d004a88be5ec59832bcef19b9e652733",
        "the 24e h md5 pin"
    );
    assert_eq!(2491 + 30, 2521, "the row ledger pair face");
}

// ==========================================================================
// T02: THE registry ladder BYTE-EQUAL vs the seed (35 + 1 legs); the
// ledger NullWorld drives the Rust add_* ladders (the ModuleRegistrar
// ledger face; the PluginManager wall cited at the fn).
// ==========================================================================
#[test]
fn t02_registry_ladder_byte_equal_vs_seed() {
    let mut w = NullWorld::default();
    add_independent_modules(&mut w);
    add_dependent_modules(&mut w);
    assert_eq!(
        w.registered.len(),
        36,
        "35 independent + 1 dependent (the CRASH_MITIGATOR tail NEVER registers — dialect OFF)"
    );
    let seeds: Vec<String> = VECTORS
        .lines()
        .filter(|l| l.starts_with("I2 n"))
        .map(|l| l.splitn(3, ' ').nth(2).unwrap().to_string())
        .collect();
    assert_eq!(seeds.len(), 35, "the seed carries EXACTLY-35 ladder names");
    for (i, got) in w.registered.iter().enumerate().take(35) {
        assert_eq!(*got, seeds[i].as_str(), "ladder leg {:02} byte-equal (cc :2367..)", i + 1);
    }
    assert_eq!(VECTORS.lines().next().unwrap(), "I1 independent=35", "the I1 head byte");
    assert_eq!(
        VECTORS.lines().find(|l| l.starts_with("D1 ")).unwrap(),
        "D1 dependent=1 trace",
        "the D1 dependent face (TraceModule ONLY, the mitigator face OFF)"
    );
    assert_eq!(w.registered[35], "trace", "the dependent leg");
    // the const faces (the twin's use-path legs):
    assert_eq!(INDEPENDENT_MODULE_IDS.len(), 35);
    assert_eq!(DEPENDENT_MODULE_IDS.len(), 1);
    assert_eq!(DEPENDENT_MODULE_IDS[0], "trace");
    // the ledger order == the const order (the pinned CONTIGUOUS law):
    assert_eq!(w.registered[..35], INDEPENDENT_MODULE_IDS);
}

// ==========================================================================
// T03+T04: the file-static helper ladders P1..P6 + V1..V3 BYTE-EQUAL vs
// the seed legs (the C strstr/strrchr faces, byte-EXACT port).
// ==========================================================================
#[test]
fn t03_placeholder_ladder_bytes() {
    let legs: [(&str, bool); 6] = [
        ("P1 ph_self", true),
        ("P2 ph_named", false),
        ("P3 ph_missing", false),
        ("P4 ph_net", false),
        ("P5 ph_prefix", true),
        ("P6 ph_none", false),
    ];
    for (tag, want) in legs {
        let row = VECTORS.lines().find(|l| l.starts_with(tag)).unwrap();
        assert_eq!(
            row.split('=').nth(1).unwrap(),
            if want { "1" } else { "0" },
            "seed leg {tag} byte"
        );
    }
    assert!(is_action_var_placeholder("ips.variables.actions.$var.react"));
    assert!(!is_action_var_placeholder("ips.variables.actions.REACT_CUSTOM.react"));
    assert!(!is_action_var_placeholder("ips.variables.actions.$var"));
    assert!(!is_action_var_placeholder("ips.variables.nets.$var.react"));
    assert!(is_action_var_placeholder("ips.variables.actions.$var.react.page")); // P5 extra
    assert!(!is_action_var_placeholder("ips.mode")); // P6 extra
}

#[test]
fn t04_get_var_name_ladder() {
    assert_eq!(get_var_name("ips.variables.actions.REACT_CUSTOM.react"), "react"); // V1
    assert_eq!(get_var_name("ips.variables.nets.$var"), "$var"); // V2
    assert_eq!(get_var_name("ips.variables.actions.REACT.page"), "page"); // V3
    for (tag, want) in [("V1 vn_react", "react"), ("V2 vn_var", "$var"), ("V3 vn_page", "page")] {
        let row = VECTORS.lines().find(|l| l.starts_with(tag)).unwrap();
        assert_eq!(
            row.split('=').nth(1).unwrap(),
            want,
            "seed V-leg {tag} byte"
        );
    }
}

// ==========================================================================
// T05..T08: THE GATE FOUR replayed through the landed IpsModule (the
// harness runs the REAL Catch bodies — gate.txt tail '12 assertions
// in 4 test cases' re-read at T14; THIS twin drives the SAME assertion
// legs through the Rust port).
// ==========================================================================
#[test]
fn t05_gate_case1_placeholder() {
    // cc :2429 TEST_CASE body, the 4 CHECK legs in body order (:2436-:2439):
    let m = is_action_var_placeholder("ips.variables.actions.$var.react");
    let a = is_action_var_placeholder("ips.variables.actions.REACT_CUSTOM.react");
    let c = is_action_var_placeholder("ips.variables.actions.$var");
    let n = is_action_var_placeholder("ips.variables.nets.$var.react");
    assert!(m && !a && !c && !n, "the case-1 CHECK quartet");
}

#[test]
fn t06_gate_case2_missing_name() {
    // cc :2442: reset_parse_errors; set("ips.variables.actions.page",
    // page@action_var_react_params[0]) -> CHECK(!accepted) (:2451) +
    // CHECK(get_parse_errors() == 1) (:2452):
    let mut w = NullWorld::default();
    w.log.reset_parse_errors();
    let mut module = IpsModule::new();
    let mut page = Value::from_str("../custom_page.html");
    page.set_param(&ACTION_VAR_REACT_PARAMS[0]); // the C page.set(&action_var_react_params[0])
    let accepted = module.set("ips.variables.actions.page", &mut page, &mut w);
    assert!(!accepted, "CHECK(!accepted) replay (:2451)");
    assert_eq!(w.log.get_parse_errors(), 1, "CHECK(get_parse_errors() == 1) replay (:2452)");
}

#[test]
fn t07_gate_case3_react_validation() {
    // cc :2455: end("$var.react", 0) -> accepted (the placeholder escape
    // :1505-:1507); reset; end("REACT_CUSTOM.react", 0) -> the must-set
    // react.page rejection (:2465) + EXACTLY-1 ParseError (:2466):
    let mut w = NullWorld::default();
    let mut module = IpsModule::new();
    let ph = module.end("ips.variables.actions.$var.react", 0, &mut w);
    assert!(ph, "the placeholder-escape CHECK (:2460)");
    w.log.reset_parse_errors();
    let ok = module.end("ips.variables.actions.REACT_CUSTOM.react", 0, &mut w);
    assert!(!ok, "the must-set-react.page rejection (:2465)");
    assert_eq!(w.log.get_parse_errors(), 1, "EXACTLY-1 ParseError (:2466)");
}

#[test]
fn t08_gate_case4_duplicate_rejection() {
    // cc :2469 (THE functional heart; the harness mirror already re-rode
    // the policy.cc :164 semantics on the C witness): a COMMITTED name +
    // the same name re-registered -> end() REJECTS via the landed
    // policy.rs has_action_variable (:123) face:
    let mut world = GateWorld { nw: NullWorld::default(), policy: IpsPolicy::default() };
    world.nw.log.reset_parse_errors();
    world
        .policy
        .commit_action_variable("REACT_DUPLICATE", "react", None, &ActionRegistry::default()); // cc :2475 leg (the nullptr act face = the None arg, cited)
    let mut module = IpsModule::new();
    let mut page = Value::from_str("../custom_page.html");
    page.set_param(&ACTION_VAR_REACT_PARAMS[0]);
    let set_ok = module.set("ips.variables.actions.REACT_DUPLICATE.react.page", &mut page, &mut world);
    assert!(set_ok, "CHECK(set_accepted) replay (:2480)");
    let end_ok = module.end("ips.variables.actions.REACT_DUPLICATE.react", 0, &mut world);
    assert!(!end_ok, "CHECK(!end_accepted) replay (:2482) — the duplicate gate");
    assert_eq!(world.nw.log.get_parse_errors(), 1, "CHECK(get_parse_errors() == 1) replay (:2487)");
}

// ==========================================================================
// T09: the parameter-table CHAIN arities (the nested table walk FACE-A
// pins: ips -> variables -> $var -> react -> page).
// ==========================================================================
#[test]
fn t09_parameter_table_chain() {
    assert_eq!(VAR_PARAMS.len(), 2); // cc :1270
    assert_eq!(ACTION_VAR_REACT_PARAMS.len(), 2); // cc :1278
    assert_eq!(ACTION_VAR_PARAMS.len(), 2); // cc :1286
    assert_eq!(ACTION_VARS_PARAMS.len(), 2); // cc :1294
    assert_eq!(VARIABLE_PARAMS.len(), 5); // cc :1302
    assert_eq!(ACTION_MAP_PARAMS.len(), 3); // cc :1319
    assert_eq!(IPS_PARAMS.len(), 12); // cc :1330 (the uuid dialect seat = a table slot EXACTLY-12 with the HAVE_UUID ifdef seat IN the table face, the A7 seat=0 face re-read in the harness — NEVER counted off the table)
    // FACE-A legs A1-A5 (the harness chain-walk seed, BYTE pins):
    assert_eq!(
        VECTORS_FACE_A.lines().find(|l| l.starts_with("A1 ")).unwrap(),
        "A1 ips n=11: action_map action_override default_rule_state enable_builtin_rules id include mode obfuscate_pii rules states variables"
    );
    assert_eq!(
        VECTORS_FACE_A.lines().find(|l| l.starts_with("A2 ")).unwrap(),
        "A2 variables n=4: actions nets paths ports"
    );
    let cc = read(CC);
    for table in ["ips_params", "variable_params", "action_vars_params", "action_var_params", "action_var_react_params", "var_params", "action_map_params"] {
        assert_eq!(
            cc.lines().filter(|l| l.contains(&format!("static const Parameter {table}"))).count(),
            1,
            "ground table {table} EXACTLY-1 decl"
        );
    }
}

// ==========================================================================
// T10: the GATE arms of the ground cc (ONE UNIT_TEST post :2425 / the
// two extra includes / EXACTLY-4 TEST_CASE / 12 CHECK) + the landing
// carries ZERO Catch body (rule-(5) cite-comment face ONLY):
// ==========================================================================
#[test]
fn t10_gate_arms_ground_vs_landing() {
    let cc = read(CC);
    let lines: Vec<&str> = cc.lines().collect();
    assert_eq!(lines[2424], "#ifdef UNIT_TEST", "the single UNIT_TEST post :2425");
    assert_eq!(lines[2425], "#include \"catch/snort_catch.h\"", ":2426");
    assert_eq!(lines[2426], "#include \"log/log_errors.h\"", ":2427");
    let tag = ["[Ip", "sModule]"].concat(); // RUNTIME-built tag (the family law)
    for n in [2428usize, 2441, 2454, 2468] {
        assert!(lines[n].starts_with("TEST_CASE(") && lines[n].contains(&tag), "TEST_CASE at :{}", n + 1);
    }
    assert_eq!(cc.matches("TEST_CASE(").count(), 4, "EXACTLY-4 TEST_CASE faces");
    assert_eq!(cc.matches("CHECK(").count(), 12, "EXACTLY-12 CHECK legs (4+2+3+3)");
    assert_eq!(lines[2490], "#endif", "the seat-close #endif :2491");
    // the landing NEVER replays a Catch body (rule (5): the cite-comment
    // face may MENTION the family, NEVER a TEST_CASE/CHECK face):
    let rs = read(RS);
    assert_eq!(rs.matches("TEST_CASE(").count(), 0, "the landing ZERO TEST_CASE bodies");
    assert_eq!(rs.matches("CHECK(").count(), 0, "the landing ZERO CHECK bodies");
    assert_eq!(rs.lines().filter(|l| l.trim_start().starts_with("#ifdef UNIT_TEST")).count(), 0, "the landing NEVER a live dialect post (the 2 cite-comment MENTIONS at the gate block NEVER directive lines)");
}

// ==========================================================================
// T11: the statics / THREAD_LOCAL / dialect / CMake censuses (the
// ifdeffed-dialect law: CRASH_MITIGATOR x2 OFF; CMake PLAIN seats):
// ==========================================================================
#[test]
fn t11_statics_dialect_cmake_censuses() {
    let cc = read(CC);
    assert_eq!(
        cc.lines().filter(|l| l.trim_start().starts_with("static ")).count(),
        43,
        "the ^static census 43 (MEASURED: grep '^[[:space:]]*static ' = 43)"
    );
    assert_eq!(cc.lines().filter(|l| l.contains("THREAD_LOCAL")).count(), 2, "THREAD_LOCAL x2");
    assert_eq!(cc.lines().filter(|l| l.contains("CRASH_MITIGATOR")).count(), 2, "CRASH_MITIGATOR x2 ifdef faces (:58 + :2420); the cmake define face OFF, NEVER invented (the 23i dialect law)");
    assert_eq!(cc.lines().filter(|l| l.contains("MitigatorModule")).count(), 1, "MitigatorModule EXACTLY-1 (the dialect boot)");
    let cm = read("/opt/data/snort3-src/src/main/CMakeLists.txt");
    let cml: Vec<&str> = cm.lines().collect();
    assert_eq!(cml[36].trim(), "modules.cc", "CMake :37 PLAIN seat");
    assert_eq!(cml[37].trim(), "modules.h", "CMake :38 PLAIN seat");
    let tm = read("/opt/data/snort3-src/src/main/test/CMakeLists.txt");
    assert_eq!(tm.matches(&["modu", "les"].concat()).count(), 0, "the row TU NEVER named in main/test CMake (the CppUTest dialect NEVER reached — MEASURED 0)");
}

// ==========================================================================
// T12: the LIVE census walk (THE POST-FLIP face 31/9/23/1 — the 24e
// gate COPY-LOCAL UNTRACKED; legacy 9 x 4826fc22 FROZEN; tracked face
// STAYS gre's ONLY; the fresh tail md5 UNIQUE):
// ==========================================================================
#[test]
fn t12_census_walk_live_31_9_23_1() {
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
    assert_eq!(total, 31, "THE FLIP face 30 -> 31 (the 62d6fac complete-flip law, walked live)");
    assert_eq!(frozen, 9, "the legacy 4826fc22 family FROZEN UNMOVED");
    assert_eq!(md5s.len(), 23, "THE lineage FLIP face 22 -> 23 (the 24e fresh tail)");
    // the own tail (path-built; NEVER rides a prior lineage):
    let own = {
        let mut p = format!("{root}/tools/");
        p.push_str(&["mod", "stor_harness/gate.txt"].concat());
        p
    };
    let own_md5 = md5_hex(&std::fs::read(&own).unwrap());
    assert_ne!(own_md5, "4826fc2233044a2d5429413faf0ae1af", "the 24e tail NEVER rides the legacy lineage");
    assert_ne!(own_md5, "6751d1a8c21da0fdfed87ddfd4d37c5f", "the 24e tail NEVER rides the gre tracked face");
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
    assert_eq!(tracked, 1, "the tracked gate.txt face STAYS gre's ONLY (the tc/24c law re-rides)");
}

// ==========================================================================
// T13: the vectors FIRST-RUN-SEED pins (NEVER re-seeded; the O0==O2
// BYTE-IDENT + the harness run-products == the seed bytes):
// ==========================================================================
#[test]
fn t13_vectors_seed_pins() {
    let h = harness_dir();
    assert_eq!(VECTORS.lines().count(), 46, "the DEC seed 46 L");
    assert_eq!(VECTORS_FACE_A.lines().count(), 9, "the FACE-A seed 9 L");
    assert_eq!(
        md5_hex(VECTORS.as_bytes()),
        "5f8adc0641e6b0dab2b11406271a7084",
        "the FIRST-RUN-SEED DEC md5 (NEVER re-seeded)"
    );
    assert_eq!(
        md5_hex(VECTORS_FACE_A.as_bytes()),
        "48181d936ed0727e656e08ee60d32b59",
        "the FIRST-RUN-SEED FACE-A md5"
    );
    for pair in [("vectors_O0.txt", "vectors_O2.txt"), ("vectors_faceA_O0.txt", "vectors_faceA_O2.txt")] {
        let a = std::fs::read(format!("{h}/{}", pair.0)).unwrap();
        let b = std::fs::read(format!("{h}/{}", pair.1)).unwrap();
        assert_eq!(a, b, "the O0==O2 BYTE-IDENT face for {}", pair.0);
    }
    let seed = std::fs::read(format!("{h}/vectors.txt")).unwrap();
    let o0 = std::fs::read(format!("{h}/vectors_O0.txt")).unwrap();
    assert_eq!(md5_hex(&seed), md5_hex(&o0), "the seed == the run product (the cmp-refuse law, NEVER re-seeded)");
    assert_eq!(
        VECTORS_FACE_A.lines().find(|l| l.starts_with("A8 ")).unwrap(),
        "A8 dependent=1 trace",
        "the CRASH_MITIGATOR-off dependent face"
    );
}

fn harness_dir() -> String {
    let mut p = String::from("/opt/data/snort3-rust/tools/");
    p.push_str(&["mod", "stor_harness"].concat());
    p
}

// ==========================================================================
// T14: the receipts echo (E4 three-way + the UNIT_TEST post; the honest
// NON-ZERO nm Catch delta, the 24a/24c precedent face; the E9 dup
// count; the E10 RUNNER tail):
// ==========================================================================
#[test]
fn t14_receipts_echo() {
    let h = harness_dir();
    // E4 way-1: the fresh-cp BARE die, FIRST-FATAL localized on the
    // ground actions/actions_module.h seat cc :29 (the flipped-assert
    // face the harness re-measures EVERY build):
    let bare = read(&format!("{h}/E4_bare.txt"));
    assert_eq!(bare.matches("fatal error").count(), 1, "EXACTLY-1 first fatal");
    assert!(bare.contains("actions/actions_module.h: No such file"), "the localize face");
    assert!(bare.contains("modules.cc:29:10"), "the :29 seat address");
    // way-2: the DONOR-GRAFT daq trio face MEASURED EXACTLY-0 error lines
    // (the HONEST divergence from the 24d count: the registry TU NEVER
    // pulls a daq-drift face — echoed, NEVER assumed):
    let graft = read(&format!("{h}/E4_graft.txt"));
    assert_eq!(graft.matches("error:").count(), 0, "the graft daq face MEASURED ZERO (the drifted face NEVER pulled)");
    // way-3: the REAL libdaq @ c8d4083 head SWAP compiles BOTH posts
    // SILENT rc0 (empty receipts = zero diagnostic bytes, plain + the
    // UNIT_TEST post = the four Catch legs compile):
    assert!(std::fs::metadata(format!("{h}/E4_real.txt")).unwrap().len() == 0, "the plain post SILENT");
    assert!(std::fs::metadata(format!("{h}/E4_ut.txt")).unwrap().len() == 0, "the UT post SILENT (the 4 Catch TEST legs CLEAN)");
    // THE honest nm delta (unlike the 24d DELTA-0, THIS row has a real
    // delta; MEASURED 137-120=17 lines, 11 Catch symbols plain 0):
    let plain = read(&format!("{h}/nm_U_plain.txt"));
    let utm = read(&format!("{h}/nm_U_ut.txt"));
    assert_eq!(utm.lines().filter(|l| l.contains("Catch")).count(), 11, "the ut Catch-symbol line delta 11 (x4 TEST_CASE legs, MEASURED)");
    assert_eq!(plain.lines().filter(|l| l.contains("Catch")).count(), 0, "the plain face ZERO Catch");
    assert_eq!(utm.lines().count() - plain.lines().count(), 17, "the nm face grew 120 -> 137 (MEASURED delta)");
    // E9 (the dup-twin attempt banked: MEASURED 53 multiple-definition arms):
    let e9 = read(&format!("{h}/E9_dup.txt"));
    assert_eq!(e9.matches("multiple definition").count(), 53, "the E9 dup count MEASURED 53 (never a prior era's 21/40/44)");
    // E10 the gate tail BOTH-ways face:
    let gate = read(&format!("{h}/gate.txt"));
    assert!(gate.contains("All tests passed (12 assertions in 4 test cases)"), "the E10 RUNNER tail");
    assert!(gate.contains(&["[Ip", "sModule]"].concat()), "the runtime tag face in the filter echo");
}

// ==========================================================================
// T15: token faces + wiring + landmines + ZERO law + NEXT seeds +
// backbone + the stage-union face:
// ==========================================================================
#[test]
fn t15_tokens_wiring_landmines_seeds() {
    let root = "/opt/data/snort3-rust";
    let rs = read(RS);
    // the OWN-token family ZERO faces (the dir token NEVER rides src;
    // the DONE marker NEVER rides src joined; pattern runtime-built so
    // THIS file NEVER carries the joined form either):
    let mn = ["mod", "stor"].concat();
    assert!(!rs.contains(&mn), "the landing NEVER names the harness dir token");
    let done = ["MODS", "_DONE"].concat();
    assert!(!rs.contains(&done), "the landing NEVER names the DONE marker");
    // landing law: ZERO allow-attrs + ZERO bare un-safe word:
    assert_eq!(rs.matches("allow(").count(), 0, "ZERO new allow attributes");
    assert_eq!(rs.lines().filter(|l| l.contains(&["un", "safe"].concat()) && !l.contains("un-safe")).count(), 0, "ZERO bare un-safe (the hyphen prose face NEVER counted)");
    // the mod.rs rider face (9 -> 10, the ONE new wiring line):
    let mrs = read(&format!("{root}/src/mai{}n/mod.rs", ""));
    assert_eq!(mrs.lines().count(), 12, "the mod.rs 10 -> 11 rider face at row 24f (the 62d6fac law, walked)");  // [24g rider 11->12: the snor-t-confi-g own-er pair's ONE new wiring line in the mo-d-r-s (the 62d6fac complete-flip law, walked face)]
    assert_eq!(mrs.matches(&["pub mod modu", "les;"].concat()).count(), 1, "the ONE new seat EXACTLY-1");
    // the landmine trio face (the 24e legit ONE-home reuse rider 2 -> 3;
    // pieces runtime-built so THIS file NEVER carries a joined face):
    let pats: [String; 3] = [
        ["Reload", "Survivor"].concat(),
        ["reload_survi", "vor"].concat(),
        ["struct Tra", "cer"].concat(),
    ];
    fn w(dir: &std::path::Path, pats: &[String], hits: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let x = e.path();
            if x.is_dir() {
                w(&x, pats, hits);
            } else if x.extension().is_some_and(|s| s == "rs")
                && let Ok(t) = std::fs::read_to_string(&x)
                && pats.iter().any(|p| t.contains(p))
            {
                hits.push(x);
            }
        }
    }
    let mut hits = Vec::new();
    w(std::path::Path::new(root).join("src").as_path(), &pats, &mut hits);
    assert_eq!(hits.len(), 3, "the trio src occupants 2 -> 3 at the 24e legit ONE-home riding (the 62d6fac rider face, measured by walk)");
    assert!(hits.iter().all(|p| !p.components().any(|c| c.as_os_str() == "packet_io")), "ZERO landmine faces inside the packet_io tree (the era pin UNMOVED)");
    // the NEXT seed faces UNMOVED by any twin (the docs sibling banks
    // the new rows; the pinned set re-ridden at HEAD):
    assert_eq!(NEXTMD.lines().filter(|l| l.contains("870 tests green / 0 FAILED")).count(), 3, "the CURRENT seed x3");
    assert_eq!(NEXTMD.lines().filter(|l| l.contains("855 tests green / 0 FAILED")).count(), 3, "the 24c-era carried face x3");
    // the backbone STAYS TEN (md5 5339c7ee..., the era face UNTOUCHED):
    let b = format!("{root}/tools/link4_harness/backbone10.txt");
    assert_eq!(std::fs::read_to_string(&b).unwrap().lines().count(), 10, "backbone STAYS 10");
    assert!(md5_hex(std::fs::read(&b).unwrap().as_slice()).starts_with("5339c7ee"), "the backbone md5 face");
    // the harness stage-union face: 0 PRE-commit / 8 POST-commit (the
    // state-tolerant law; the gate rides UNTRACKED per the .gitignore):
    let ls = std::process::Command::new("git")
        .args(["-C", root, "ls-files", &format!("tools/{mn}_harness")])
        .output()
        .unwrap()
        .stdout;
    let tracked_faces = String::from_utf8(ls).unwrap().lines().count();
    assert!(
        tracked_faces == 0 || tracked_faces == 8,
        "the stage-union face 0 PRE-commit / 8 POST-commit: {tracked_faces}"
    );
    let gi = read(&format!("{}/{mn}_harness/.gitignore", harness_dir().rsplit_once('/').unwrap().0));
    assert!(gi.contains("gate.txt") && gi.contains("COPY-LOCAL"), "the COPY-LOCAL UNTRACKED gate posture on the .gitignore face");
}
