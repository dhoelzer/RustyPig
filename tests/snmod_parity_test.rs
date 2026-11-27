//! Row-24f parity twin: the chapter-21 SIXTH body, the CLI MEGA pair,
//! THE THIRD ZERO-GATE CONTROL row (after 24d / 24b): the in-TU test
//! faces ride EXACTLY-0 in BOTH ground files (no Catch TEST_CASE, no
//! legacy CppUTest TEST(, no CATCH macro — MEASURED side-by-side like
//! the 24e t10 face walk; THIS row ships ZERO in-TU tests and NO gate
//! harness), the main/test CMake carries EXACTLY-2 add_cpputest legs of
//! the OTHER dialect (thread_test + the ENABLE_SHELL distill_verdict
//! seat — host CppUTest ABSENT) and the row TU rides NO test list. The
//! walked census STAYS UNMOVED 31 / 9 / 23 / 1 (the zero-gate row ships
//! NO new tail — the complete-flip law re-ridden as a NOFLIP face).
//! Three hearts:
//!
//! 1. THE ground pair identity: main pair-cc 1,338 L md5 34ac6432 +
//!    pair-h 93 L md5 088a264a @ fe29cbe — pair LEDGER 1431.
//! 2. THE dialect / s_params censuses: the ^static census 11 + the
//!    THREAD_LOCAL pair 1+1; '#ifdef SHELL' cc 9 + h 1; UNIT_TEST 3;
//!    REG_TEST 4; the EXACTLY-1 catch include; the EXACTLY-3
//!    UNIT_TEST||BENCHMARK Test post face; the s_params bounds face
//!    EXACTLY-143 named rows + EXACTLY-1 PT_MAX sentinel (the SHELL-ON
//!    source face: 143 = 134 live + 9 SHELL-dialect rows; THE LANDING
//!    keeps the SAME law: [Parameter; 135] = 134 named + 1 sentinel,
//!    the 9 dialect rows ride cite-comments ONLY; 143 - 9 = 134).
//! 3. THE tripwires: the LIVE census walk UNMOVED (COPY-LOCAL UNTRACKED
//!    .gitignore face arm + the tracked face STAYS gre's ONLY — read
//!    through the index BYTES, NO git process: the no-git-in-tests law
//!    replacing the 24e dir-walk arm); the backbone STAYS TEN; the
//!    mod.rs 10 -> 11 rider face with the full 11-seat order pinned;
//!    the docs seed faces UNMOVED (885 x3 / 588 x4 / 573 x5 per-LINE +
//!    the drift token EXACT-1); the OWN joined + hyphen token ZERO
//!    faces (patterns runtime-built so THIS file NEVER self-hits, the
//!    landmine law); the ZERO allow-attr law + the ZERO un-safe LIVE-code
//!    law (the landing's ONE un-safe face rides doc prose ONLY — the
//!    truth pinned, NOT an invented 0); the cite-reach law (the
//!    registry callsite cite EXACTLY-1).
//!
//! Token law at THIS twin (the 23f..24e precedent): every counted
//! foreign face rides a RUNTIME-built pattern.

const CC: &str = concat!("/opt/data/snort3-src/src/mai", "n/snort_", "module.cc");
const HH: &str = concat!("/opt/data/snort3-src/src/mai", "n/snort_", "module.h");

const THIS_TWIN: &str = concat!(
    "/opt/data/snort3-rust/tests/",
    "sn",
    "mod_parity_test",
    ".rs"
);

fn repo() -> std::path::PathBuf {
    std::path::PathBuf::from("/opt/data/snort3-rust")
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).expect(p)
}

fn md5_hex(bytes: &[u8]) -> String {
    // the in-file md5 (the lineage-walk precedent: the twins carry their
    // own helper; NO external crates)
    let mut msg = bytes.to_vec();
    let bitlen = (msg.len() as u64) * 8;
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
    let mut k = [0u32; 64];
    for (i, kk) in k.iter_mut().enumerate() {
        let si = (i as f64 + 1.0).sin().abs();
        *kk = (si * (2u64.pow(32) as f64)) as u32;
    }
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

/// the doc-face predicate (the landing's prose-vs-live split face).
fn is_prose(l: &str) -> bool {
    let t = l.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*')
}

// ==========================================================================
// T1: the ground pair identity (MEASURED vs the orchestrator pins) + the
// pair LEDGER face.
// ==========================================================================
#[test]
fn t1_ground_pair_identity() {
    let cc = read(CC);
    let hh = read(HH);
    assert_eq!(cc.lines().count(), 1338, "the pair-cc 1,338 L face");
    assert_eq!(hh.lines().count(), 93, "the pair-h 93 L face");
    assert_eq!(
        md5_hex(cc.as_bytes()),
        "34ac6432449d694c0eb3683ccb01a200",
        "the 24f cc md5 pin"
    );
    assert_eq!(
        md5_hex(hh.as_bytes()),
        "088a264aad42c171bea37253a2fc2705",
        "the 24f h md5 pin"
    );
    assert_eq!(1338 + 93, 1431, "the row ledger pair face");
}

// ==========================================================================
// T2: THE ZERO-GATE face (THE control law at THIS row, the 24d/24b
// precedent): the in-TU test faces EXACTLY-0 in BOTH ground files
// (TEST_CASE / TEST( / CATCH counted side-by-side on the ground TEXT,
// the 24e t10 pattern); the EXACTLY-1 unit_test dialect post = the
// catch include seat :51-:52 (byte arms).
// ==========================================================================
#[test]
fn t2_zero_gate_faces_both_files() {
    let cc = read(CC);
    let hh = read(HH);
    for (name, t) in [("cc", &cc), ("h", &hh)] {
        for pat in ["TEST_CASE", "TEST(", "CATCH"] {
            assert_eq!(t.matches(pat).count(), 0, "the ZERO {pat} face in the ground {name}");
        }
    }
    let lines: Vec<&str> = cc.lines().collect();
    let post = &["defined(UNIT_TEST) || defined(BENCHMARK_", "Test)"].concat().replace("Test", "TEST");
    assert_eq!(lines[50], format!("#if {post}"), ":51 the dialect post face");
    assert_eq!(
        lines[51],
        ["#include \"catch/unit_te", "st.h\""].concat(),
        ":52 the catch include (the row ships the INCLUDE face ONLY)"
    );
}

// ==========================================================================
// T3: the main CMakeLists PLAIN seats (:52 h / :53 cc) — NEVER
// dialect-gated at the seat face.
// ==========================================================================
#[test]
fn t3_main_cmake_plain_seats() {
    let cm = read("/opt/data/snort3-src/src/main/CMakeLists.txt");
    let cml: Vec<&str> = cm.lines().collect();
    let h_seat = ["snort_mod", "ule.h"].concat();
    let cc_seat = ["snort_mod", "ule.cc"].concat();
    assert_eq!(cml[51].trim(), h_seat.as_str(), "CMake :52 PLAIN seat");
    assert_eq!(cml[52].trim(), cc_seat.as_str(), "CMake :53 PLAIN seat");
    assert_eq!(
        cm.lines().filter(|l| l.trim() == h_seat.as_str()).count(),
        1,
        "the h seat EXACTLY-1"
    );
    assert_eq!(
        cm.lines().filter(|l| l.trim() == cc_seat.as_str()).count(),
        1,
        "the cc seat EXACTLY-1"
    );
}

// ==========================================================================
// T4: the main/test CMakeLists dialect face: EXACTLY-2 add_cpputest legs
// (thread_test + the ENABLE_SHELL distill_verdict seat — the thread/
// distill dialect, host CppUTest ABSENT) + EXACTLY-0 naming of the row
// TU (the row rides NO test list, the CppUTest dialect NEVER reached,
// MEASURED 0 like the 24e law).
// ==========================================================================
#[test]
fn t4_main_test_cmake_dialect() {
    let tm = read("/opt/data/snort3-src/src/main/test/CMakeLists.txt");
    assert_eq!(
        tm.matches(&["add_cppu", "test"].concat()).count(),
        2,
        "EXACTLY-2 add_cpputest faces (the thread_test + distill_verdict dialect)"
    );
    assert_eq!(tm.matches("thread_test").count(), 1, "the thread_test leg");
    assert_eq!(tm.matches("distill_verdict_test").count(), 1, "the distill_verdict leg");
    assert_eq!(tm.matches(&["ENABLE_", "SHELL"].concat()).count(), 2, "the SHELL dialect gate pair (if + endif)");
    assert_eq!(
        tm.matches(&["snort_mod", "ule"].concat()).count(),
        0,
        "the row TU NEVER named in main/test CMake (MEASURED 0)"
    );
}

// ==========================================================================
// T5: the statics census (^static EXACTLY-11, wholly on the cc side) +
// the THREAD_LOCAL pair face (cc 1 + h 1).
// ==========================================================================
#[test]
fn t5_statics_thread_local_census() {
    let cc = read(CC);
    let hh = read(HH);
    let cc_static = cc.lines().filter(|l| l.starts_with("static ")).count();
    let h_static = hh.lines().filter(|l| l.starts_with("static ")).count();
    assert_eq!(cc_static + h_static, 11, "the ^static pair census EXACTLY-11");
    assert_eq!(cc_static, 11, "the ^static census rides the cc side wholly");
    assert_eq!(h_static, 0, "the h side rides NO ^static seat");
    assert_eq!(cc.lines().filter(|l| l.contains("THREAD_LOCAL")).count(), 1, "THREAD_LOCAL cc 1");
    assert_eq!(hh.lines().filter(|l| l.contains("THREAD_LOCAL")).count(), 1, "THREAD_LOCAL h 1");
    assert_eq!(
        hh.lines().nth(37).unwrap(),
        "extern THREAD_LOCAL const snort::Trace* snort_trace;",
        "the h :38 extern seat byte face"
    );
}

// ==========================================================================
// T6: the dialect censuses (string counts on the ground text): '#ifdef
// SHELL' cc EXACTLY-9 + h EXACTLY-1; UNIT_TEST cc EXACTLY-3; REG_TEST
// cc EXACTLY-4; the catch include EXACTLY-1; the
// UNIT_TEST||BENCHMARK_TEST post face EXACTLY-3 (:51 + :637 + :1234).
// ==========================================================================
#[test]
fn t6_dialect_censuses() {
    let cc = read(CC);
    let hh = read(HH);
    assert_eq!(cc.matches("#ifdef SHELL").count(), 9, "'#ifdef SHELL' cc EXACTLY-9 (the SHELL-ON source face)");
    assert_eq!(hh.matches("#ifdef SHELL").count(), 1, "'#ifdef SHELL' h EXACTLY-1 (the :53 seat)");
    assert_eq!(cc.matches("UNIT_TEST").count(), 3, "the UNIT_TEST census EXACTLY-3 (posts ONLY, NEVER the include's lower face)");
    assert_eq!(cc.matches("REG_TEST").count(), 4, "the REG_TEST census EXACTLY-4 (2 ifdef + 2 defined arms)");
    assert_eq!(cc.matches(&["catch/unit_te", "st.h"].concat()).count(), 1, "the catch include EXACTLY-1");
    assert_eq!(
        cc.matches(&["defined(UNIT_TEST) || defined(BENCHMARK_T", "EST)"].concat()).count(),
        3,
        "the UNIT_TEST||BENCHMARK_TEST post face EXACTLY-3 (:51 + :637 + :1234)"
    );
}

// ==========================================================================
// T7: the s_params bounds face: between the table bounds (:232 decl /
// :684 close) EXACTLY-143 named rows ('    { "') + EXACTLY-1 PT_MAX
// sentinel — the SHELL-ON source face (143 = 134 live + 9 SHELL-dialect
// rows riding the ground table under the #ifdef SHELL seats).
// ==========================================================================
#[test]
fn t7_s_params_ground_rows() {
    let cc = read(CC);
    let lines: Vec<&str> = cc.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with(&["static const Parameter s_para", "ms[] ="].concat()))
        .unwrap();
    assert_eq!(start + 1, 232, "the s_params decl seat :232");
    let end = (start + 1..lines.len()).find(|i| lines[*i].trim_end() == "};").unwrap();
    assert_eq!(end + 1, 684, "the table close seat :684");
    let seg = &lines[start + 1..end];
    let named = seg.iter().filter(|l| l.starts_with("    { \"")).count();
    let sentinel = seg
        .iter()
        .filter(|l| l.starts_with("    { nullptr, Parameter::PT_MAX"))
        .count();
    assert_eq!(named, 143, "EXACTLY-143 named rows in the SHELL-ON ground table");
    assert_eq!(sentinel, 1, "EXACTLY-1 PT_MAX sentinel (the :683 seat)");
    assert_eq!(named + sentinel, 144, "the table row face 143 names + 1 tail");
    assert_eq!(
        lines[682].trim_start(),
        "{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }",
        "the :683 sentinel byte face (NO trailing comma)"
    );
}

// ==========================================================================
// T8: the cite-reach law: the registry callsite cites the ground ctor
// EXACTLY-1 (the :3605 seat) and the ground ctor BYTE face rides :702.
// ==========================================================================
#[test]
fn t8_modules_cite_drift() {
    let mr = read(&["/opt/data/snort3-rust/src/mai", "n/modules.rs"].concat());
    let cite = &["new Snort", "Module (main/snort_mod", "ule.cc :702)"].concat();
    assert_eq!(mr.matches(cite.as_str()).count(), 1, "the cite-reach face EXACTLY-1 in the registry home");
    let seat = mr.lines().nth(3604).unwrap();
    assert!(seat.contains(cite.as_str()), "the :3605 seat carries the cite");
    assert!(seat.contains("INDEPENDENT_MODULE_IDS[0]"), "the registry boot leg byte face");
    let cc = read(CC);
    assert_eq!(
        cc.lines().nth(701).unwrap(),
        ["SnortModule::SnortModule() : Module(", "s_name, s_help, s_params)"].concat(),
        "the ground ctor byte face :702"
    );
}

// ==========================================================================
// T9: the landing exists + the LIVE-table shape face (pinning WHAT THE
// LANDING ACTUALLY CARRIES — the landing child left 134 named + 1
// sentinel in the live region): [Parameter; 135] rides the decl + the
// doc cite (EXACTLY-2 faces); the 9 SHELL-dialect ground rows ride
// cite-comments ONLY (the 143 - 9 = 134 law, echoed ONE face).
// ==========================================================================
#[test]
fn t9_landing_identity_and_table_shape() {
    let rs = read(&["/opt/data/snort3-rust/src/mai", "n/snort_mod", "ule.rs"].concat());
    assert_eq!(rs.lines().count(), 1764, "the landing 1,764 L anchor (re-pinned: the header cite-drift fix at commit, the 24d honesty bank)");
    let anno = &["[Parameter; 13", "5]"].concat();
    assert_eq!(rs.matches(anno.as_str()).count(), 2, "the annotation face rides the doc cite + the decl (EXACTLY-2)");
    let lines: Vec<&str> = rs.lines().collect();
    let s = lines.iter().position(|l| l.starts_with("pub static S_PARAMS")).unwrap();
    assert_eq!(
        lines[s],
        &["pub static S_PARAMS: [Parameter; 135] = [", ""].concat(),
        "the live-table decl byte face"
    );
    let e = (s + 1..lines.len())
        .find(|i| lines[*i].trim_end() == "];")
        .unwrap();
    let seg = &lines[s + 1..e];
    let named = seg.iter().filter(|l| l.contains(&["Parameter { name: Som", "e("].concat())).count();
    let sentinel = seg
        .iter()
        .filter(|l| l.contains(&["Parameter { name: ", "None,"].concat()))
        .count();
    assert_eq!(
        named, 134,
        "the LIVE table carries EXACTLY-134 named rows (the ground 143 minus the 9 dialect rows; the truth face, the landing NEVER ships a dialect live seat)"
    );
    assert_eq!(sentinel, 1, "the live table carries EXACTLY-1 sentinel");
    assert_eq!(named + sentinel, 135, "the shape law 134 + 1 == the [Parameter; 135] annotation");
    assert_eq!(
        rs.lines().filter(|l| l.contains(&["rows = ", "9"].concat())).count(),
        1,
        "the dialect-9 cite-comment face EXACTLY-1 (the 143 - 9 = 134 law echoed)"
    );
    assert_eq!(rs.matches(&["pub struct Snort", "Module {"].concat()).count(), 1, "the ONE landing struct face");
    assert_eq!(
        rs.lines().filter(|l| l.starts_with("pub static")).count(),
        7,
        "the landing pub-static census 7 (S_PARAMS + SNORT_TRACE_OPTIONS + the five profile tokens)"
    );
}

// ==========================================================================
// T10: the ZERO law (landing + twin self-census; the split-needle
// idiom the existing twins use so the scan NEVER joins the face it
// counts): ZERO allow-attr faces BOTH homes; ZERO un-safe faces in LIVE
// landing code (the landing's ONE un-safe face rides doc prose ONLY —
// pinned as the truth, the 24e t15 self-census re-ridden on a truth
// face); ZERO live Catch/test bodies in the landing (the rule-(5)
// cite-comment MENTIONS pinned honestly).
// ==========================================================================
#[test]
fn t10_zero_law_self_census() {
    let this = read(THIS_TWIN);
    let landing = read(&["/opt/data/snort3-rust/src/mai", "n/snort_mod", "ule.rs"].concat());
    let attr = &["#[", "allow"].concat();
    let unsf = &["uns", "afe"].concat();
    assert_eq!(landing.matches(attr.as_str()).count(), 0, "ZERO allow attrs in the landing");
    assert_eq!(this.matches(attr.as_str()).count(), 0, "ZERO allow attrs in the twin (the needle runtime-built)");
    assert_eq!(
        landing.lines().filter(|l| l.contains(unsf.as_str()) && !is_prose(l)).count(),
        0,
        "ZERO un-safe faces in LIVE landing code"
    );
    assert_eq!(
        landing.lines().filter(|l| l.contains(unsf.as_str())).count(),
        1,
        "the landing's ONE un-safe face rides DOC PROSE ONLY (the truth face)"
    );
    assert_eq!(this.matches(unsf.as_str()).count(), 0, "ZERO un-safe joined faces in the twin (the SELF-scan pattern law)");
    assert_eq!(landing.matches(&["TEST_CA", "SE("].concat()).count(), 0, "the landing ZERO TEST_CASE bodies (the ONE prose MENTION has no live paren)");
    assert_eq!(landing.matches("CHECK(").count(), 0, "the landing ZERO CHECK bodies");
    assert_eq!(landing.matches("#[cfg(test").count(), 0, "the landing ZERO cfg-test regions");
    assert_eq!(
        landing.lines().filter(|l| l.contains("TEST(") && !is_prose(l)).count(),
        0,
        "the landing ZERO live TEST( faces (the ONE prose MENTION face honestly pinned)"
    );
}

// ==========================================================================
// T11: the mod.rs rider face (the 10 -> 11 flip): line-count 11, the
// ONE new seat EXACTLY-1, the FULL 11-seat order pinned byte-exact (the
// prior seats UNMOVED).
// ==========================================================================
#[test]
fn t11_mod_rider_eleven_seats() {
    let mrs = read(&["/opt/data/snort3-rust/src/mai", "n/mod.rs"].concat());
    assert_eq!(mrs.lines().count(), 11, "the mod.rs 10 -> 11 rider face (the complete-flip law)");
    let seats: Vec<&str> = mrs.lines().collect();
    let want: [&str; 11] = [
        "pub mod analyzer;",
        "pub mod numa;",
        "pub mod policy;",
        "pub mod processp;",
        "pub mod reload_tracker;",
        &["pub mod she", "llp;"].concat(), // the split-built seat face (the foreign-harness NAME-token law: this twin NEVER joins the sh-ell family)
        "pub mod snort_;",
        "pub mod thread;",
        "pub mod thread_config;",
        "pub mod modules;",
        &["pub mod snort_mod", "ule;"].concat(),
    ];
    for (i, w) in want.iter().enumerate() {
        assert_eq!(seats[i], *w, "seat {:02} EXACT (the full pinned 11-seat set)", i + 1);
    }
    assert_eq!(mrs.matches(&["pub mod snort_mod", "ule;"].concat()).count(), 1, "the ONE new wiring line EXACTLY-1");
}

// ==========================================================================
// T12: the OWN joined-token ZERO faces (the landmine law; every needle
// runtime-built so THIS file NEVER self-hits): the two-letter-fold
// token / the row-fold token / the h-abbrev token / the name-fold token
// ride ZERO in the landing, across the WHOLE src tree, in EVERY tools/
// dir-name, in THIS twin and in the index BYTES (the row ships NO
// harness home).
// ==========================================================================
#[test]
fn t12_own_joined_token_zero_faces() {
    let landing = read(&["/opt/data/snort3-rust/src/mai", "n/snort_mod", "ule.rs"].concat());
    let own: [String; 4] = [
        ["sn", "mod"].concat(),
        ["snort", "mod"].concat(),
        ["snm", "_h"].concat(),
        ["sn", "module"].concat(),
    ];
    for t in &own {
        assert_eq!(landing.matches(t.as_str()).count(), 0, "the landing NEVER names the own fold {t}");
    }
    fn walk(dir: &std::path::Path, pats: &[String], hits: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let x = e.path();
            if x.is_dir() {
                walk(&x, pats, hits);
            } else if x.extension().is_some_and(|s| s == "rs")
                && let Ok(t) = std::fs::read_to_string(&x)
                && pats.iter().any(|p| t.contains(p))
            {
                hits.push(x);
            }
        }
    }
    fn walk_text(dir: &std::path::Path, pats: &[String], hits: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let x = e.path();
            if x.is_dir() {
                walk_text(&x, pats, hits);
            } else if let Ok(t) = std::fs::read_to_string(&x)
                && pats.iter().any(|p| t.contains(p))
            {
                hits.push(x);
            }
        }
    }
    let mut hits = Vec::new();
    walk(repo().join("src").as_path(), &own, &mut hits);
    assert_eq!(hits.len(), 0, "the own-fold family rides ZERO src homes");
    // the OWN harness home (the 24d/24e dir-name precedent: the dir name
    // is the token's ONLY legit filesystem home; the anz-l law: NO arm
    // EVER count-pins MY files — the own-token rides file CONTENTS
    // EXACTLY-0; the swept set EXCLUDES the own dir + the own twin):
    for e in std::fs::read_dir(repo().join("tools")).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if own.iter().any(|p| name.contains(p.as_str())) {
            assert_eq!(name, ["sn", "mod_harness"].concat(), "the tools/ dir-name face is the OWN harness home ONLY");
        }
    }
    let mut foreign_hits = Vec::new();
    if let Ok(rd) = std::fs::read_dir(repo().join("tools")) {
        for e in rd.flatten() {
            let d = e.path();
            if d.is_dir() && own.iter().any(|p| d.file_name().unwrap().to_string_lossy().contains(p.as_str())) {
                continue; // the OWN harness home excluded (the anz-l exclusion law)
            }
            walk_text(&d, &own, &mut foreign_hits);
        }
    }
    assert_eq!(foreign_hits.len(), 0, "the own fold rides ZERO foreign tools/ file bodies");
    let mut test_hits = Vec::new();
    walk_text(&repo().join("tests"), &own, &mut test_hits);
    test_hits.retain(|p| {
        // the OWN twin carries the concat-split patterns ONLY (never the
        // join): a body hit here means a JOINED own token rode a twin
        p != std::path::Path::new(THIS_TWIN)
    });
    assert_eq!(test_hits.len(), 0, "the own fold rides ZERO foreign tests/ file bodies");
    let twin = read(THIS_TWIN);
    for t in &own {
        assert_eq!(twin.matches(t.as_str()).count(), 0, "the twin NEVER joins the own fold (the pattern law)");
    }
}

// ==========================================================================
// T13: the LIVE census walk UNMOVED (the zero-gate control row ships NO
// new gate: 31 files / legacy 4826fc22 x9 FROZEN / 23 lineages — the
// 30->31 / 22->23 riders STAY at their flip rows) + the COPY-LOCAL
// UNTRACKED .gitignore face arm + the tracked face STAYS gre's ONLY,
// read through the index BYTES (NO git process at THIS twin).
// ==========================================================================
#[test]
fn t13_census_walk_unmoved_31_9_23_1() {
    let root = repo();
    let mut total = 0usize;
    let mut frozen = 0usize;
    let mut md5s = std::collections::BTreeSet::new();
    for e in std::fs::read_dir(root.join("tools")).unwrap() {
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
    assert_eq!(total, 31, "the gate census STAYS UNMOVED 31 (the zero-gate row ships NO tail)");
    assert_eq!(frozen, 9, "the legacy 4826fc22 family FROZEN UNMOVED");
    assert_eq!(md5s.len(), 23, "the lineage census STAYS 23 (NO new tail at THIS row)");
    // the tracked face WITHOUT a git process: the index stores each
    // tracked path NUL-terminated after its stat block:
    let idx_bytes = std::fs::read(root.join(".git/index")).unwrap();
    let idx = String::from_utf8_lossy(&idx_bytes).into_owned();
    assert!(idx.starts_with("DIRC"), "the index signature face");
    assert_eq!(idx.matches(&["gate.txt", "\0"].concat()).count(), 1, "the tracked EXACTLY-1 gate face");
    assert_eq!(
        idx.matches(&["gre", "_harness/gate.txt", "\0"].concat()).count(),
        1,
        "the tracked face STAYS gre's ONLY (the tc/24c law re-rides)"
    );
    let own_dir = ["tools/sn", "mod_harness/"].concat();
    let own_faces = idx.matches(own_dir.as_str()).count();
    // the 7-face tracked set rides the index ONLY once THE ROW's commit
    // lands (the 24e pre-stage twin law: dev-time the arm reads ZERO;
    // the committed cold face reads EXACTLY-7):
    assert!(own_faces == 0 || own_faces == 7,
        "the OWN harness home tracks EXACTLY-7 faces at POST (the anz-l 7-trackable law) — dev-time face UNTRACKED");
    if own_faces == 7 {
        for f in ["build.sh", "probe.cc", "probe_faceA.cc", "witness_row.cc", "vectors.txt", "vectors_faceA.txt", ".gitignore"] {
            assert!(idx.contains((own_dir.clone() + f).as_str()), "the trackable face {f} rides the index");
        }
    }
    assert!(!idx.contains((own_dir + "gate").as_str()), "NO gate EVER ships at the OWN home (the zero-gate walk face read from the index)");
    // the COPY-LOCAL UNTRACKED .gitignore face arm (the 24e arm re-
    // read; the harness-dir token runtime-built):
    let gi = read(&format!(
        "{}/tools/{}stor_harness/.gitignore",
        root.display(),
        "mod"
    ));
    assert!(gi.contains("gate.txt") && gi.contains("COPY-LOCAL"), "the COPY-LOCAL UNTRACKED gate posture on the .gitignore face");
}

// ==========================================================================
// T14: the backbone STAYS TEN (wc 10 + the md5 tripwire, the 24e arm
// re-ridden; the row NEVER touches the backbone).
// ==========================================================================
#[test]
fn t14_backbone_stays_ten() {
    let b = format!("{}/tools/{}k4_harness/backbone10.txt", repo().display(), "lin");
    assert_eq!(std::fs::read_to_string(&b).unwrap().lines().count(), 10, "backbone STAYS 10");
    assert_eq!(
        md5_hex(std::fs::read(&b).unwrap().as_slice()),
        ["5339c7ee501dab8a85277c37", "dc2d1e0c"].concat(),
        "the backbone md5 tripwire (the full face)"
    );
}

// ==========================================================================
// T15: the docs seed faces UNMOVED (per-LINE semantics, the 24c t13
// linecount law; 885 x3 / 588 x4 / 573 x5 + the drift token EXACT-1) +
// the OWN joined AND hyphen-form token ZERO faces on NEXT / PLAN /
// DEVIATIONS (ALL needles runtime-built, the landmine law) + the
// plan-row faces (the 24a..24e seats stay EXACTLY-1 each; the 24f plan
// row rides the docs sibling — THIS twin NEVER moves a doc).
// ==========================================================================
#[test]
fn t15_docs_seed_tripwires() {
    let root = repo();
    let next = std::fs::read_to_string(root.join("NEXT.md")).unwrap();
    let linecount = |needle: &str| -> usize {
        next.lines().filter(|l| l.contains(needle)).count()
    };
    assert_eq!(linecount("885 tests green / 0 FAILED"), 3, "the CURRENT seed face x3 (per-LINE)");
    assert_eq!(linecount("588 tests green / 0 FAILED"), 4, "the carried 588 face x4 (per-LINE)");
    assert_eq!(linecount(&["573 tests g", "reen"].concat()), 5, "the carried 573 face x5 (per-LINE)");
    assert_eq!(linecount(&["5 TES", "T("].concat()), 1, "the drift token face EXACT-1");
    let plan = std::fs::read_to_string(root.join("PORTING_PLAN.md")).unwrap();
    let dev = std::fs::read_to_string(root.join(["KNOWN DEVIATIO", "NS.md"].concat())).unwrap();
    let docs: [&str; 3] = [&next, &plan, &dev];
    // the joined own family rides docs EXACTLY-0 BY LAW; the hyphen
    // prose forms (sn-mod / snort-module) are the sanctioned DOCS face
    // (the 23f/24a docs-prose law) — the section header + the plan row
    // carry them, NEVER the joins:
    let needles: [String; 4] = [
        ["sn", "mod"].concat(),
        ["snort", "mod"].concat(),
        ["snm", "_h"].concat(),
        ["sn", "module"].concat(),
    ];
    for d in docs {
        for n in &needles {
            assert_eq!(d.matches(n.as_str()).count(), 0, "the own folded form NEVER rides the docs (the needle is runtime-built)");
        }
    }
    for r in ["a", "b", "c", "d", "e"] {
        assert_eq!(
            plan.lines().filter(|l| l.starts_with(&format!("| 24{r} |"))).count(),
            1,
            "the plan-row 24{r} EXACTLY-1 law UNMOVED"
        );
    }
    assert_eq!(
        plan.lines().filter(|l| l.starts_with(&["| 24", "f |"].concat())).count(),
        1,
        "the 24f plan-row EXACTLY-1 law (banked IN the code commit, the 24c-24e pattern)"
    );
    assert_eq!(
        dev.lines().filter(|l| l.starts_with("## ") && l.contains("row 24e")).count(),
        1,
        "the 24e deviations seat UNMOVED"
    );
}
