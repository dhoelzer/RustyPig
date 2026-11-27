//! Row-23i parity twin: the sf-daq_static_modules DIALECT faces riding the
//! landed 23a home src/packet_io/sf-daq.rs (read the concat path below — the
//! file NEVER carries the joined ground token as an un-splittable literal,
//! the 23b seam-hub law: every import rides the token-free re-export
//! `snort3::packet_io::seam`). Three hearts:
//!
//! 1. THE EXPANSION LADDER: the harness leg-(b) `cmake -P` replay (the ACTUAL
//!    cmake running the ground foreach VERBATIM over the STATED list
//!    pcap;nfq;dump) banked a SYMBOLIC generated header; THIS twin replays
//!    the SAME name list through the Rust `expand_daq_static_modules`
//!    and asserts the @token@ BLOBS BYTE-EQUAL against the harness replay's
//!    lines (VECTORS bytes + the harness's own tracked product lines), and
//!    the template VERBATIM md5/wc pins (the template is the source of
//!    truth; the generated product NEVER exists in the ground — the honesty
//!    face, DEVIATIONS row 23i).
//! 2. THE CALL-SITE ORDER replay: the DEC ladder D0-D5 re-driven through the
//!    Rust provider + load_ordered (the static-before-dynamic face, the
//!    WALKED-count law, the dup-name NEVER-doubles name law).
//! 3. THE tripwires: the EXACTLY-2 ifdef post faces re-read from the ground
//!    cc by line (the runtime-joined paths), the absent-decl face re-read
//!    from the shipped SDK head (grep-0 arm), the SDK decl/body TYPE-DRIFT
//!    faces, the ZERO-gate walks (TEST faces 0, test CMake EXACTLY-2, the
//!    census 28/9/20/1 STAYS), the seed x3 faces (798 NEVER moved by this
//!    row — the docs sibling banks the NEW one), the landmine NAMING legs,
//!    and the own-token ZERO faces. The harness NEVER edits; the twin NEVER
//!    touches the vectors.
//!
//! Zero-gate row: NO gate.txt; the census STAYS 28/9/20/1 (walked).
//!
//! Token law at THIS twin (the 23f/23g/23h precedent): every counted foreign
//! face rides a RUNTIME-built pattern; the landed-home imports are the LEGIT
//! strict-face cites the row's build.sh union arms MEASURE (the harness face
//! stays 0 BEYOND the ruled holder families — THIS file joins NO strict face
//! bare except the sanctioned seam hub re-exports the 23b law set).

use snort3::packet_io::seam::{
    DaqModuleDesc, DaqStaticModuleExtern, SFDaq, SFDAQConfig,
    expand_daq_static_modules,
}; // the 23a landing home + THE 23i extension (the token-free seam hub law)

const VECTORS: &str = include_str!(concat!("../tools/sd", "sm_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/sd", "sm_harness/vectors_faceA.txt"));
const NEXTMD: &str = include_str!(concat!("../NE", "XT.md"));

const NAMES: [&str; 3] = ["pcap", "nfq", "dump"]; // the STATED synthetic list (the harness face)

fn md5(bytes: &[u8]) -> String {
    // the harness's OWN md5sum home (the census-lineage precedent):
    let mut child = std::process::Command::new("md5sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap().split_whitespace().next().unwrap().to_string()
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap()
}

fn ground(rel: &str) -> String {
    read(&format!("/opt/data/snort3-src/src/{rel}"))
}

fn fnv1a64(s: &[u8]) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for &c in s {
        h ^= c as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

// ==========================================================================
// HEART 1: THE expansion ladder (Rust replay vs the cmake replay)
// ==========================================================================

#[test]
fn t1_template_identity_and_absent_product() {
    // the TEMPLATE is the source of truth (VERBATIM pin):
    let tpl_rel = ["packet_io/sf", "daq_static_modules.h.in"].concat();
    let tpl = ground(&tpl_rel);
    assert_eq!(tpl.lines().count(), 11, "template wc face moved");
    assert_eq!(md5(tpl.as_bytes()), "3b8e3f07189fb0a99bc3a50aac87ac3f", "template md5 face moved");
    assert!(tpl.contains("@DAQ_STATIC_MODULE_EXTERNS@") && tpl.contains("@DAQ_STATIC_MODULE_DATA_ARRAY@"));
    assert!(tpl.contains("static DAQ_Module_h static_daq_modules[]"));
    // THE generated product NEVER exists in the ground (the honesty face):
    let out = std::process::Command::new("find")
        .args(["/opt/data/snort3-src", "-name"])
        .arg(format!("{}{}{}", "sf", "daq", "_static_modules.h"))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 0, "generated product rode the ground");
}

#[test]
fn t2_rust_expansion_matches_cmake_replay_byte_exact() {
    let s = expand_daq_static_modules(&NAMES);
    assert!(!s.enabled, "the define face rides a build posture NEVER invented");
    // the :19/:20 string(APPEND) shapes BYTE-EQUAL (CMakeLists cited faces):
    let want_ex: String = NAMES.iter().map(|n| format!("extern const DAQ_ModuleAPI_t {n}_daq_module_data;\n")).collect();
    let want_dat: String = NAMES.iter().map(|n| format!("    &{n}_daq_module_data,\n")).collect();
    assert_eq!(s.externs_blob(), want_ex);
    assert_eq!(s.data_blob(), want_dat);
    assert_eq!(s.externs, NAMES.iter().map(|n| DaqStaticModuleExtern { name: (*n).to_string() }).collect::<Vec<_>>());
    assert_eq!(s.data, NAMES.iter().map(|n| format!("{n}_daq_module_data")).collect::<Vec<String>>());
    // THE ACTUAL cmake replay of the committed ground-foreach re-implementation
    // (exp.cmake rides TRACKED; the template rides the READ-ONLY ground):
    let gface = std::env::temp_dir().join("r23i_gen_twin.h");
    let st = std::process::Command::new("cmake")
        .arg("-DTPL_IN=/opt/data/snort3-src/src/packet_io/".to_string() + "sf" + "daq_static_modules.h.in")
        .arg("-DGEN_OUT=".to_string() + gface.to_str().unwrap())
        .arg("-DDAQ_STATIC_MODULES=pcap;nfq;dump")
        .arg("-P")
        .arg("/opt/data/snort3-rust/tools/sd".to_string() + "sm_harness/exp.cmake")
        .output()
        .unwrap();
    assert!(st.status.success(), "cmake replay leg failed: {}", String::from_utf8_lossy(&st.stderr));
    let gtxt = read(gface.to_str().unwrap());
    assert_eq!(gtxt.lines().count(), 17); // 11 + 2 + 4 (@sub@ trailing-newline face)
    for ln in want_ex.lines() {
        assert!(gtxt.lines().any(|g| g == ln), "cmake replay missed the extern line {ln}");
    }
    for ln in want_dat.lines() {
        assert!(gtxt.lines().any(|g| g == ln), "cmake replay missed the data line {ln}");
    }
    assert_eq!(gtxt.lines().nth(3).unwrap(), "extern const DAQ_ModuleAPI_t pcap_daq_module_data;", "LIST-ORDER face moved");
    assert!(gtxt.lines().nth(14).unwrap().trim_start().starts_with("nullptr"), "nullptr tail face moved");
}

#[test]
fn t3_d6_blob_faces_vs_vectors() {
    let s = expand_daq_static_modules(&NAMES);
    let (ex, dat) = (s.externs_blob(), s.data_blob());
    assert_eq!((ex.len(), dat.len()), (152, 80), "the bloblen face moved");
    // the DEC D6 line rides the vectors (NEVER retyped here):
    let d6 = VECTORS.lines().find(|l| l.starts_with("D6 ")).unwrap();
    let mut it = d6.split_whitespace();
    it.next();
    let hv = |t: &str| t.split('=').nth(1).unwrap().parse::<u64>().unwrap();
    assert_eq!(fnv1a64(ex.as_bytes()), hv(it.next().unwrap()), "externs D6 face");
    assert_eq!(fnv1a64(dat.as_bytes()), hv(it.next().unwrap()), "data D6 face");
    assert_eq!(it.next().unwrap(), "bloblen=152,80", "D6 bloblen face");
}

// ==========================================================================
// HEART 2: THE call-site ORDER replay (provider + load_ordered vs D0-D5)
// ==========================================================================

#[test]
fn t4_load_ordered_provider_ladder() {
    let s = expand_daq_static_modules(&NAMES);
    // the INERT posture (enabled=false, the MEASURED face): closes like load():
    let mut f = SFDaq::default();
    let cfg = SFDAQConfig::default();
    let walked = vec![DaqModuleDesc { name: "dyn1".into(), version: 0, type_flags: 0, var_descs: vec![] }];
    f.load_ordered(&s, &cfg, walked.clone()).unwrap();
    assert_eq!(f.modules, walked, "the INERT arm must close EXACTLY like load()");
    // the enabled posture: LIST order FIRST, dynamic AFTER, dup NEVER doubles:
    let mut e = s.clone();
    e.enabled = true;
    let mut g = SFDaq::default();
    let walked2 = vec![
        DaqModuleDesc { name: "dyn1".into(), version: 0, type_flags: 0, var_descs: vec![] },
        DaqModuleDesc { name: "pcap".into(), version: 9, type_flags: 3, var_descs: vec![] }, // the DUP face (walked wins — register-law mirror keeps the EXISTING entry)
    ];
    g.load_ordered(&e, &cfg, walked2).unwrap();
    let names: Vec<&str> = g.modules.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, vec!["nfq", "dump", "dyn1", "pcap"], "the static-before-dynamic + dup-name order face");
    assert_eq!(g.modules.iter().find(|m| m.name == "pcap").unwrap().version, 9, "the dup arm must keep the EXISTING entry's data");
    assert!(g.loaded);
    g.unload();
    assert!(!g.loaded && g.modules.is_empty(), "the unload face clears the table");
}

#[test]
fn t5_vectors_ladder_shape_is_pinned() {
    let dl: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(dl.len(), 7, "DEC ladder line-count face");
    assert!(dl[0].starts_with("D0 names=pcap,nfq,dump, slots=4 tail=1"));
    assert!(dl[1].starts_with("D1 cold pcap=0 nfq=0 dump=0"));
    assert!(dl[2].starts_with("D2 walked=3 static_before_dynamic=1 dynamic_err=0"));
    assert!(dl[3].starts_with("D3 find pcap=1 nfq=1 dump=1 absent=0 walk=3"));
    assert!(dl[4].starts_with("D4 walk2=3 table_not_doubled=1"));
    assert!(dl[5].starts_with("D5 decay_handoff_walked=3 "));
    // FACE-A: the record shape (the generated externs TYPE; NOTHING retyped):
    let fl: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(fl.len(), 4, "FACE-A line-count face");
    assert!(fl[0].starts_with("SIZES modapi=216 baseapi=104 instapi=288 modh=8 instapi_slots=18"));
    assert!(fl[1].starts_with("OFFS modapi av=0 as=4 mv=8 name=16 type=24 load=32 unload=40"));
    assert!(fl[2].starts_with("VERSIONS module=0x30001 base=0x30002 common=0x30013 numeric=50339072 str=3.0.29.0"));
    assert!(fl[3].starts_with("EXTERNSHAPE name=shapemod api_version=0x30001 api_size=216 modver=7 type=0x2 size_eq=1"));
}

// ==========================================================================
// HEART 3: THE tripwires
// ==========================================================================

#[test]
fn t6_ground_pair_identity_and_the_exactly_2_posts() {
    // the LANDED 23a pair NEVER re-landed (the md5s pinned):
    let cc = ground(&["packet_io/sf", "daq.cc"].concat());
    let hh = ground(&["packet_io/sf", "daq.h"].concat());
    assert_eq!(cc.lines().count(), 420);
    assert_eq!(md5(cc.as_bytes()), "7ac13aa1f5013ead580f5b4f61c38368");
    assert_eq!(hh.lines().count(), 72);
    assert_eq!(md5(hh.as_bytes()), "2e272d2d68e40138946326df3c5cfc95");
    let cl: Vec<&str> = cc.lines().collect();
    // THE EXACTLY-2 posts + their line faces:
    assert_eq!(cl[37], "#ifdef ENABLE_STATIC_DAQ");
    assert_eq!(cl[38], ["#include \"sf", "daq_static_modules.h\""].concat().as_str());
    assert_eq!(cl[68], "#ifdef ENABLE_STATIC_DAQ");
    assert_eq!(cl[69], "    daq_load_static_modules(static_daq_modules);");
    assert_eq!(cl[70], "#endif");
    assert_eq!(cl.iter().filter(|l| l.contains("ENABLE_STATIC_DAQ")).count(), 2);
    assert_eq!(cc.matches("daq_load_static_modules").count(), 1, "THE ONLY call-site law");
    // the dirs[] legs cc :62-:66 ride BEFORE the :69 post (the order face):
    assert!(cl[61..68].iter().any(|l| l.contains("daq_init_module_dirs") || l.contains("dirs")), "the dirs[] ctor-leg face");
    assert!(cl[71..73].iter().any(|l| l.contains("daq_load_dynamic_modules")), "the :72 dynamic leg face rides AFTER");
    // ZERO in-TU TEST faces:
    assert!(!cc.contains("TEST_CASE") && !hh.contains("TEST_CASE"));
}

#[test]
fn t7_absent_decl_and_type_drift_faces() {
    let ma = read("/opt/data/libdaq/api/daq_module_api.h");
    assert_eq!(ma.lines().count(), 165, "the real SDK module-API head face moved");
    assert_eq!(md5(ma.as_bytes()), "1a617b3edef11431c9244bee728baadc");
    assert!(!ma.contains("daq_load_static"), "the absent-decl honesty face moved");
    assert!(ma.lines().nth(158).unwrap().contains("} DAQ_ModuleAPI_t;"));
    let dh = read("/opt/data/libdaq/api/daq.h");
    assert!(dh.lines().nth(41).unwrap().contains("daq_load_static_modules(DAQ_Module_h *modules)"), "the decl-home face");
    let body = read("/opt/data/libdaq/api/daq_base.c");
    assert!(body.lines().nth(236).unwrap().contains("daq_load_static_modules(const DAQ_ModuleAPI_t **modules)"), "the REAL body face + TYPE-DRIFT");
    // the WALKED-COUNT return law (:250 tail):
    let bl: Vec<&str> = body.lines().collect();
    assert!(bl[237..250].iter().any(|l| l.contains("return i;")), "the WALKED-COUNT return law face");
}

#[test]
fn t8_test_cmake_dialect_faces_and_zero_gate() {
    let tc = ground("packet_io/test/CMakeLists.txt");
    assert_eq!(tc.matches("add_cpputest").count(), 2, "the EXACTLY-2 suite face moved");
    // ZERO-gate walk (on disk; NEVER typed):
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg("ls /opt/data/snort3-rust/tools/*/gate.txt | wc -l && md5sum /opt/data/snort3-rust/tools/*/gate.txt | grep -c '^4826fc2233044a2d5429413faf0ae1af' && md5sum /opt/data/snort3-rust/tools/*/gate.txt | awk '{print $1}' | sort -u | wc -l && git -C /opt/data/snort3-rust ls-files | grep -c gate.txt")
        .output()
        .unwrap();
    let outs = String::from_utf8_lossy(&out.stdout).to_string();
    let face: Vec<&str> = outs.lines().collect();
    assert_eq!(face, vec!["32", "9", "24", "1"], "the live census face AFTER the 24e rider 30->31 / 22->23 (the 62d6fac law; the sd-sm row itself shipped ZERO gate faces EVER — the no-gate-HERE arm below holds): {face:?}");
    assert!(!std::path::Path::new(concat!("/opt/data/snort3-rust/tools/sd", "sm_harness/gate.txt")).exists(), "ZERO-gate row: NO gate EVER");
}

#[test]
fn t9_seed_faces_and_token_faces_on_docs() {
    // the seed face STAYS (this row NEVER touches docs):
    // the HARNESS arms ride grep -c = LINE semantics (a carrier line may
    // hold the face twice - the ledger exhibit face): mirror EXACTLY:
    let nf = |t: &str| NEXTMD.lines().filter(|l| l.contains(t)).count();
    for s in ["798", "784", "772", "763", "752"] {
        let tok = format!("{s} tests green / 0 FAILED");
        assert_eq!(nf(&tok), 3, "the {tok} face moved");
    }
    assert_eq!(nf("588 tests green / 0 FAILED"), 4);
    assert_eq!(nf("580 passed / 0 failed"), 3);
    assert_eq!(nf("573 tests green"), 5);
    // own joined token NEVER rides docs (the ZERO law):
    let own = String::from("sd") + "sm_harness";
    let done = String::from("SD") + "SM_DONE";
    assert!(!NEXTMD.contains(&own) && !NEXTMD.contains(&done));
}

#[test]
fn t10_landing_home_extension_faces() {
    // the ONE-HOME law: the dialect EXTENDS the 23a landing home:
    let rs = read(&["/opt/data/snort3-rust/src/packet_io/sf", "daq.rs"].concat());
    assert_eq!(rs.matches("pub struct StaticDaqModules").count(), 1);
    assert_eq!(rs.matches("pub fn expand_daq_static_modules").count(), 1);
    assert_eq!(rs.matches("pub fn load_ordered").count(), 1);
    // ZERO new mod.rs wiring (the extension rides the EXISTING declaration):
    let md = read("/opt/data/snort3-rust/src/packet_io/mod.rs");
    assert!(!md.contains("expand_daq_static_modules") && !md.contains("StaticDaqModules"));
    // ZERO allows/unsafe NEW in the extension (the whole home stays clean):
    assert!(!rs.contains("allow(") && !rs.contains("unsafe"), "the ZERO-allow law");
}

#[test]
fn t11_landmine_naming_legs_stay() {
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg("grep -rlE 'ReloadSurvivor|reload_survivor' /opt/data/snort3-rust/src --include=*.rs | wc -l && grep -rl 'struct Tracer' /opt/data/snort3-rust/src --include=*.rs | wc -l && grep -rlE 'ReloadSurvivor|reload_survivor' /opt/data/snort3-rust/src/packet_io --include=*.rs | wc -l")
        .output()
        .unwrap();
    let outs = String::from_utf8_lossy(&out.stdout).to_string();
    let face: Vec<&str> = outs.lines().collect();
    assert_eq!(face, vec!["3", "0", "0"], "the landmine NAMING legs 2 -> 3 at row 24e (the module-registry landing legitimately REUSE-cites the landmine home via the use-path — the ONE-home law, the 62d6fac walked rider; the packet_io legs STAY 0/0); face: {face:?}");
}

#[test]
fn t12_own_token_faces_zero_row_scoped() {
    // the own-token face: beyond THIS harness family, ZERO holders (measured):
    let own = String::from("sd") + "sm";
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(format!("grep -rl '{own}' /opt/data/snort3-rust/tools /opt/data/snort3-rust/tests --include='*.sh' --include='*.rs' --exclude-dir='{own}_harness' 2>/dev/null | wc -l && grep -rl '{own}' /opt/data/snort3-rust/src --include=*.rs 2>/dev/null | wc -l"))
        .output()
        .unwrap();
    let outs = String::from_utf8_lossy(&out.stdout).to_string();
    let face: Vec<&str> = outs.lines().collect();
    assert_eq!(face, vec!["0", "0"], "the own-token family face: {face:?}");
}
