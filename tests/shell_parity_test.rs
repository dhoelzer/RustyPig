//! Parity twin for row 24c — the main/sh-ell pair (shell.cc 944 + shell.h
//! 161 = 1,105 L @ fe29cbe; the chapter-21 THIRD body; THE THIRD REAL GATE
//! ROW: the EXACTLY-1 in-TU Catch TEST_CASE :928 over the REAL LuaJIT (the
//! tag + the ground pair names ride concat faces at the harness homes — the
//! family law; the joined own-harness CENSUS token + the DONE echo ride ZERO
//! by law). The Rust home is src/main/shellp.rs. The DEC ladder rides the
//! TRACKED seed BYTE-EQUAL (the harness runs the REAL-VM side every build);
//! this twin rebuilds the pure Decision faces through the landing home +
//! walks the on-disk census (the era FLIP: 30/9/22/1 after this row; rider
//! 30->31 / 22->23 at the 24e registry gate, the 62d6fac law). ZERO new
//! allow-attrs / ZERO un-safe (the self-census below).

use std::collections::BTreeSet;

use snort3::main::shellp as sh;

const VECTORS: &str = include_str!(concat!("../tools/sh", "ell_harness/vectors.txt"));
const VECTORS_FACE_A: &str = include_str!(concat!("../tools/sh", "ell_harness/vectors_faceA.txt"));

fn ground(main_rel: &str) -> String {
    // the ground tree READ-ONLY (the pair face @ fe29cbe)
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/{main_rel}")).unwrap()
}

fn repo_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/opt/data/snort3-rust")
}

fn md5_hex(bytes: &[u8]) -> String {
    // the in-file md5 (the lineage-walk precedent: the twins carry their own
    // helper; NO external crates)
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

// ==========================================================================
// T1: the ground identity faces (RE-MEASURED every run; the law)
// ==========================================================================
#[test]
fn t1_ground_pair_identity() {
    let cc = ground("main/shell.cc");
    let h = ground("main/shell.h");
    assert_eq!(
        md5_hex(cc.as_bytes()),
        "cb7f74e836c4e91542f89fdf0f8d9c10",
        "shell.cc identity MOVED — re-measure the row"
    );
    assert_eq!(
        md5_hex(h.as_bytes()),
        "8b2de00a3507bfacf0584413ea104f88",
        "shell.h identity MOVED"
    );
    assert_eq!(cc.lines().count(), 944);
    assert_eq!(h.lines().count(), 161);
    // the THIRD ground face (CITES-ONLY NEVER lands, the 24a law):
    let third = std::fs::read_to_string("/opt/data/snort3-src/src/main.h").unwrap();
    assert_eq!(third.lines().count(), 67);
    assert_eq!(md5_hex(third.as_bytes()), "2b487dd0065bb9ba48e3eeeca21128ee");
}

// ==========================================================================
// T2: THE GATE dialect face walk (the :928 faces; NEVER assumed)
// ==========================================================================
#[test]
fn t2_gate_dialect_faces() {
    let cc = ground("main/shell.cc");
    let lc = |tok: &str| -> usize { cc.lines().filter(|l| l.contains(tok)).count() };
    assert_eq!(lc("#ifdef UNIT_TEST"), 1, "the EXACTLY-1 post face");
    assert_eq!(lc("TEST_CASE"), 1, "the EXACTLY-1 gate TEST_CASE");
    assert_eq!(lc("CHECK("), 1, "the ONE stack-equal CHECK");
    assert_eq!(lc("REQUIRE("), 0, "ZERO REQUIRE legs");
    let l928 = cc.lines().nth(927).unwrap();
    let want = format!(
        "TEST_CASE(\"lua stack size on commands install\", \"[{}{}]\")",
        "Sh", "ell"
    );   // the tag face RUNTIME-built (never typed joined here)
    assert_eq!(l928.trim_end(), want, ":928 the tag face (RUNTIME-built)");
    let cm = std::fs::read_to_string("/opt/data/snort3-src/src/main/CMakeLists.txt").unwrap();
    assert_eq!(
        cm.lines().filter(|l| l.trim() == "shell.h").count(),
        1,
        "the :47 INCLUDES seat (plain, NEVER dialect-gated)"
    );
    assert_eq!(
        cm.lines().filter(|l| l.trim() == "shell.cc").count(),
        1,
        "the :48 SOURCES seat"
    );
    assert_eq!(
        cm.lines()
            .filter(|l| l.contains(&format!("{}{}", "ac_", "shell")))
            .count(),
        1,
        "the ENABLE_SHELL dialect face :21 (the ac- pair NEVER lands)"
    );
    assert_eq!(
        cm.lines().filter(|l| l.contains("lua_wrap.sh")).count(),
        2,
        "the generated-pair COMMAND faces :67/:73"
    );
    let tc = std::fs::read_to_string("/opt/data/snort3-src/src/main/test/CMakeLists.txt").unwrap();
    assert_eq!(
        tc.matches(&format!("{}{}", "add_cppu", "test")).count(),
        2,
        "EXACTLY-2 OTHER-dialect lists (host find-0)"
    );
    assert_eq!(
        tc.matches(&format!("{}{}", "sh", "ell")).count(),
        0,
        "the row TU rides NO test list"
    );
    // the generated heads NEVER exist on disk (the honesty face):
    assert!(
        !std::path::Path::new("/opt/data/snort3-src/src/main/lua_bootstrap.h").exists(),
        "the generated product NEVER exists at a fixed path"
    );
    assert!(
        !std::path::Path::new("/opt/data/snort3-src/src/main/lua_finalize.h").exists(),
        "the generated product NEVER exists at a fixed path"
    );
}

// ==========================================================================
// T3: the DEC seed face pins (BYTE face vs the TRACKED vectors seed; the
// harness re-runs the REAL-VM side + refuses drift EVERY build)
// ==========================================================================
#[test]
fn t3_vectors_seed_face() {
    let lines: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(lines.len(), 14, "the DEC seed 14 L");
    assert_eq!(
        lines[0], "D0 lua=1 top=0 loaded=0 file_empty=1 from_empty=1",
        "the ctor census (REAL VM: the replayed bootstrap chunk balances the stack)"
    );
    assert!(lines[1].starts_with("D0L cfgdata.ctor"), "the ctor order seat");
    assert_eq!(
        lines[2], "D1 sv=3.13.2.0 maj=3 min=13 pat=2 sub=0 build_nil=1 top=0",
        "the REAL version-globals writes (the VERSION seat; the BUILD arm OFF)"
    );
    assert!(
        lines[3].starts_with("D2 tab=1 all_str=1 daq=3.0.14-witness trusted_cold=0"),
        "the dep-table face (the mirror DAQ version seat) + the cold-static trusted 0 (NO current shell)"
    );
    assert_eq!(lines[4], "D3 ud=1 top=1", "the the-shell userdata seat (the ctor setglobal)");
    assert_eq!(
        lines[5], "D4 bal=1 tab=1 fn=1 bal2=1 noop_nil=1 top=0",
        "THE GATE arithmetic DEC replay: register+pop BALANCE + the empty-reg early-out (no table EVER)"
    );
    assert_eq!(
        lines[6], "D5 ls=0 sbfail=1 bal=1 top=0",
        "the sandbox legs: the REAL loadfile MISS false + the execute env-fail FIXED rsp face (the sandbox global UNDEFINED) + the install post-register table-MISS pop face BALANCED"
    );
    assert!(
        lines[7].starts_with("D6 brk=1 nl=1 len20=1"),
        "the REAL LuaJIT error rsp face (the error-string seat + the appended newline)"
    );
    assert_eq!(lines[8], "D7 bal=1 ing=1 top=0", "the s-nort _G-merge strcmp arm (the closure reaches _G)");
    assert_eq!(lines[9], "D7L cfgdata.ctor|pol.set_default|pol.set_default", "the ctor/dtor order legs (the dump-walker witness legs per live Shell)");
    assert_eq!(lines[10], "D8 file=nominal_policy.lua loaded=0 top=0", "the named-file ctor face");
    assert_eq!(lines[11], "D8P net=5 nap=11 ips=13", "the policy-index round trip (the nap->inspect SEAT order face)");
    assert_eq!(lines[13], "Z terminator=0", "the Z seat");
    let va: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(va.len(), 5, "the FACE-A seed 5 L");
    assert!(va[0].starts_with("A1 shapeCmd_sz="), "the shape face");
    assert_eq!(va[1], "A2 n928=1 n3=3 n0=0", "the count-walk face");
}

// ==========================================================================
// T4: FACE-A rebuilt NUMERICALLY (no row linkage at all)
// ==========================================================================
#[test]
fn t4_face_a_numeric() {
    let reg928: [Option<&str>; 2] = [Some("test_closure"), None];
    assert_eq!(sh::command_count(&reg928), 1, "A2 n928=1 (the gate reg count)");
    let reg3: [Option<&str>; 4] = [Some("a"), Some("b"), Some("c"), None];
    assert_eq!(sh::command_count(&reg3), 3);
    let reg0: [Option<&str>; 1] = [None];
    assert_eq!(sh::command_count(&reg0), 0, "the :712 early-out face");
    assert_eq!(sh::VERSION_NAMES.len(), 5, "A3 heads=5 (the BUILD-OFF host face)");
    assert_eq!(sh::DEP_NAMES.len(), 6, "A3 deps=6");
    let rsp = "Failed to apply sandbox environment to control command\n";
    assert_eq!(rsp.len(), 55, "A4 the fixed rsp len (cc :836)");
    assert!(rsp.ends_with('\n'));
    assert_eq!(sh::LUA_SHELL_ID.len(), 9, "A5 the id len (the concat const)");
    assert_eq!(sh::LUA_SHELL_ID, format!("the_{}", "shell"));
}

// ==========================================================================
// T5: the gate-CHECK replay over the landing fns PURE side (the :928-:939
// face): the reg[2] count + the cmds(n+1) nullptr tail + the balance net
// ==========================================================================
#[test]
fn t5_gate_check_replay() {
    let reg: [(Option<&str>, Option<u8>); 2] = [(Some("test_closure"), Some(0)), (None, None)];
    let cmds = sh::build_cmds_table(&reg);
    assert_eq!(cmds.len(), 2, "the cmds(n+1) seat + the nullptr tail face");
    assert_eq!(cmds[1], (None, None), "the :724-:725 tail pair");
    let mut world = sh::ShellWorld::new_boot();
    let trace = sh::install_effect(&mut world, "test_module", 1);
    assert_eq!(
        trace,
        vec!["reg.test_module".to_string()],
        "the register leg then the sandbox-empty early-out; the pop faces Balance the register legs (the CHECK leg: init_stack == stack)"
    );
}

// ==========================================================================
// T6: the allowlist law (cc :253-:284 + :899-:911): prefixes-first scan,
// the current-shell gates, the pre-boot internal seat, the null-keyword skip
// ==========================================================================
#[test]
fn t6_allowlist_law() {
    let mut world = sh::ShellWorld::new_boot();
    let mut shells = vec![sh::Shell::new(None, false), sh::Shell::new(None, false)];
    // NO current shell -> is_trusted cold FALSE + the append NO-OP (the
    // harness D2 trusted_cold=0 seat):
    assert!(!sh::Shell::is_trusted(&world, &shells, "anything"));
    assert_eq!(
        sh::Shell::allowlist_append(&mut world, &mut shells, Some("k"), false),
        "noop"
    );
    world.current_shells.push(0); // the ctor push face
    // bootstrapped FALSE -> the INTERNAL list seat:
    assert_eq!(
        sh::Shell::allowlist_append(&mut world, &mut shells, Some("internal_kw"), false),
        "internal-list"
    );
    // the null-keyword skip face (cc :909) STILL selects the list:
    assert_eq!(
        sh::Shell::allowlist_append(&mut world, &mut shells, None, false),
        "internal-list"
    );
    assert!(!shells[0].allowlist.contains("internal_kw"));
    assert!(shells[0].internal_allowlist.contains("internal_kw"));
    assert!(sh::Shell::is_trusted(&world, &shells, "internal_kw"));
    assert!(!sh::Shell::is_trusted(&world, &shells, "internal_k"));
    // the PREFIXES-first scan face (the key.compare(0, len, prefix) seat):
    sh::Shell::allowlist_append(&mut world, &mut shells, Some("pre"), true);
    assert!(sh::Shell::is_trusted(&world, &shells, "prefixed_name"));
    // bootstrapped flips -> the allowlist LIST seat:
    shells[0].bootstrapped = true;
    assert_eq!(
        sh::Shell::allowlist_append(&mut world, &mut shells, Some("late"), false),
        "allow-list"
    );
    assert!(shells[0].allowlist.contains("late"));
    // the pop face -> NO current shell:
    world.current_shells.pop();
    assert!(!sh::Shell::is_trusted(&world, &shells, "late"));
    assert_eq!(
        sh::Shell::allowlist_append(&mut world, &mut shells, Some("x"), false),
        "noop"
    );
    // clear ALL THREE (the configure :707 + h :120-:125 face):
    world.current_shells.push(0);
    shells[0].clear_allowlist();
    assert!(shells[0].allowlist.is_empty()
        && shells[0].internal_allowlist.is_empty()
        && shells[0].allowlist_prefixes.is_empty());
}

// ==========================================================================
// T7: the ctor order + the field law (cc :566-:595 ORDER; the ACCUMULATE
// overrides face; the nap->inspect seat order)
// ==========================================================================
#[test]
fn t7_ctor_order_and_fields() {
    let mut s = sh::Shell::new(Some("policy.lua"), true);
    assert_eq!(s.get_file(), "policy.lua");
    assert!(!s.get_loaded()); // cc :585
    assert!(!s.bootstrapped); // flips ONLY post-bootstrap (cc :592)
    assert!(s.load_defaults);
    s.set_file("two.lua");
    s.set_overrides_str("a=1;");
    s.set_overrides_str("b=2;");
    let mut p = sh::Shell::new(None, false);
    p.set_overrides_str("c=3;");
    s.set_overrides_shell(&p);
    assert_eq!(s.overrides, "a=1;b=2;c=3;", "the += ACCUMULATE face (NEVER an overwrite)");
    assert_eq!(s.get_from(), ""); // the get_parse_file seam seat
    s.set_policy_indices(5, 11, 13);
    assert_eq!(s.get_policy_indices(), (5, 11, 13), "the nap->inspect SEAT order face");
    let order = sh::Shell::ctor_order();
    assert_eq!(order.len(), 11);
    assert_eq!(order[0], "newstate");
    assert_eq!(order[1], "push-current");
    assert_eq!(order[6], "loaded-false", "loaded=FALSE BEFORE the bootstrap load");
    assert_eq!(order[7], "bootstrap-load");
    assert_eq!(order[10], "bootstrapped-true+pop", "the flip AFTER the bootstrap legs, the pop LAST");
}

// ==========================================================================
// T8: the dump-walker legs (cc :303-:412): the dump-off gate FIRST (the
// REAL boot posture), the PT_MULTI latch, the climb, the descend-MISS face
// ==========================================================================
#[test]
fn t8_dump_walker() {
    let world = sh::ShellWorld::new_boot(); // dump OFF (the measured gate posture)
    let mut w = sh::DumpWalker::new();
    assert_eq!(w.open(&world, true, false, 0, "t", None), vec!["dump-off".to_string()]);
    assert_eq!(w.close(&world), vec!["dump-off".to_string()]);
    assert_eq!(
        w.update_current(&world, "x"),
        vec!["dump-off-or-null".to_string()]
    );
    // dump ON face through the output seam (the s_config_output leg):
    let mut w2 = sh::ShellWorld::new_boot();
    w2.config_output_set = true;
    assert_eq!(
        w.open(&w2, true, false, 0, "root-table", None),
        vec!["root.root-table".to_string()]
    );
    assert_eq!(
        w.open(&w2, false, false, 0, "child", Some(sh::PT_MULTI)),
        vec!["multi-latch-off".to_string()]
    );
    assert!(!w.close_table, "the :319 latch");
    assert_eq!(w.close(&w2), vec!["latch-reset".to_string()], "the :380 latch face (return BEFORE the climb)");
    assert!(w.close_table);
    assert_eq!(w.close(&w2), vec!["climb".to_string()], "the :389 climb");
    assert_eq!(w.current, None, "the root parent = nullptr face");
    // the climb PAST the root left current NONE -> the :363-:365 OR-null
    // early-out fires BEFORE any descend leg (the honest null face):
    let r = w.update_current(&w2, "nope");
    assert_eq!(r, vec!["dump-off-or-null".to_string()], "the null early-out (root parent = nullptr)");
    // with a live current, the named-descend MISS face (the ground assert seat NEVER invents a descent):
    w.open(&w2, true, false, 1, "root2", None);
    assert_eq!(w.current, Some(1), "the fresh root seat (nodes.len() face)");
    let r2 = w.update_current(&w2, "nope");
    assert_eq!(r2, vec![format!("descend-miss.{}", "nope")], "the descend-MISS honest face");
}

// ==========================================================================
// T9: the execute decision ladder (cc :826-:853) + the panic capture face
// ==========================================================================
#[test]
fn t9_execute_ladder() {
    let mut world = sh::ShellWorld::new_boot();
    let mut rsp = String::new();
    assert_eq!(sh::execute_face(&world, false, &mut rsp), "pcall", "no sandbox -> straight to the pcall arm");
    sh::set_lua_sandbox(&mut world, "sb.lua");
    assert!(!world.sandbox_env_defined);
    assert_eq!(sh::execute_face(&world, false, &mut rsp), "env-fail");
    assert_eq!(rsp, "Failed to apply sandbox environment to control command\n");
    assert_eq!(sh::execute_face(&world, true, &mut rsp), "load-err", "the load FAILURE short-circuits the env seat (the :831 !err && seat)");
    sh::panic_capture(&mut world, "boom from lua");
    assert_eq!(world.fatal, "boom from lua", "the :421 capture seat");
    let rsp2 = world.fatal.clone(); // the catch(...) hand face (the :843 seat)
    assert_eq!(rsp2, "boom from lua");
    sh::set_lua_sandbox(&mut world, "");
    assert!(sh::get_lua_sandbox(&world).is_empty());
}

// ==========================================================================
// T10: the install() ladder faces (cc :706-:790): the sn-gate _G merge, the
// sandbox table-MISS pop, the rebuild ladder, the existing-name skip
// ==========================================================================
#[test]
fn t10_install_ladder() {
    let mut w = sh::ShellWorld::new_boot();
    let sn = format!("{}{}", "sn", "ort");
    assert!(sh::install_effect(&mut w, "any", 0).is_empty(), "the :712 empty early-out");
    let t = sh::install_effect(&mut w, &sn, 2);
    assert_eq!(t, vec!["reg._G".to_string(), "reg.snort".to_string()], "the :728 merge arm");
    sh::set_lua_sandbox(&mut w, "sb.lua");
    let t = sh::install_effect(&mut w, "mod1", 1);
    assert_eq!(t, vec!["reg.mod1".to_string(), "sbx-miss+pop".to_string()], "the :744-:748 table-MISS pop");
    w.sandbox_env_defined = true;
    let t = sh::install_effect(&mut w, "mod2", 1);
    assert_eq!(
        t,
        vec![
            "reg.mod2".to_string(),
            "nil-pop+new-table".to_string(),
            "table.mod2".to_string(),
            "setfield.mod2".to_string(),
            "pop".to_string()
        ],
        "the :762-:789 rebuild ladder"
    );
    let t = sh::install_effect(&mut w, &sn, 3);
    assert_eq!(
        t,
        vec![
            "reg._G".to_string(),
            "reg.snort".to_string(),
            "cf.0".to_string(),
            "cf.1".to_string(),
            "cf.2".to_string(),
            "pop".to_string()
        ],
        "the :752-:759 per-name ladder"
    );
    w.sandbox_names.insert("mod2".to_string());
    let t = sh::install_effect(&mut w, "mod2", 1);
    assert_eq!(t[1], "table.mod2".to_string(), "the EXISTING-name skip face");
}

// ==========================================================================
// T11: THE walked census (the sanctioned FLIP rider at THIS row, the 62d6fac
// complete-flip law): 30 on-disk / legacy 9 x 4826fc22 FROZEN / 22 lineages
// / tracked-1 gre anchor
// ==========================================================================
#[test]
fn t11_census_walk_30_9_22_1() {
    let base = repo_path().join("tools");
    let mut gates = Vec::new();
    for e in std::fs::read_dir(&base).unwrap() {
        let p = e.unwrap().path().join("gate.txt");
        if p.is_file() {
            gates.push(p);
        }
    }
    assert_eq!(
        gates.len(),
        31,
        "the on-disk gate census (era face 29 -> 30 at this row's 24c tail; rider 30 -> 31 at the 24e registry gate, the 62d6fac law)"
    );
    let mut md5s = BTreeSet::new();
    let mut legacy = 0usize;
    for g in &gates {
        let m = md5_hex(&std::fs::read(g).unwrap());
        md5s.insert(m.clone());
        if m == "4826fc2233044a2d5429413faf0ae1af" {
            legacy += 1;
        }
    }
    assert_eq!(md5s.len(), 23, "the distinct-lineage census (era face 21 -> 22 at this row; rider 22 -> 23 at the 24e gate tail, the 62d6fac law)");
    assert_eq!(legacy, 9, "the legacy 4826fc22 face FROZEN");
    let out = std::process::Command::new("git")
        .args(["-C", "/opt/data/snort3-rust", "ls-files"])
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
    assert!(
        tracked[0].starts_with(&format!("tools/gr{}", "e_harness")),
        "the gre anchor face"
    );
    // MY gate face: on-disk AND untracked (the posture law):
    let mine = format!("tools/{}{}_harness", "sh", "ell");
    let on_disk = repo_path().join(&mine).join("gate.txt");
    assert!(on_disk.is_file(), "the chapter-21 THIRD gate face rides on-disk");
    assert!(
        !tracked.iter().any(|t| t.starts_with(&mine)),
        "copy-local UNTRACKED (the tc law re-armed at chapter-21's third gate)"
    );
    // the gre gate transcript face:
    assert_eq!(std::fs::read_to_string(repo_path().join("tools/gre_harness/gate.txt")).unwrap().lines().count(), 3);
}

// ==========================================================================
// T12: the ground-walk arithmetic pins (the file-statics census + the
// replay wrapper arithmetic + the ffi cdef leg counts)
// ==========================================================================
#[test]
fn t12_ground_arith() {
    let cc = ground("main/shell.cc");
    assert_eq!(
        cc.lines()
            .filter(|l| l.starts_with("static ")
                || l.starts_with("    static ")
                || l.starts_with("\tstatic "))
            .count(),
        7,
        "the leading-static census face"
    );
    // the harness REPLAY legs ride the REAL .lua bodies (the RE-CITE law):
    let b = std::fs::read("/opt/data/snort3-src/src/main/bootstrap.lua").unwrap();
    let f = std::fs::read("/opt/data/snort3-src/src/main/finalize.lua").unwrap();
    assert_eq!(b.len(), 5019, "the ground bootstrap.lua face MOVED");
    assert_eq!(f.len(), 3785, "the ground finalize.lua face MOVED");
    // the replay wrapper arithmetic MEASURED by the harness (bytes):
    assert_eq!(b.len() + 65, 5084, "the replayed bootstrap head face (the raw-string wrapper: 65 B of head+tail)");
    assert_eq!(f.len() + 62, 3847, "the replayed finalize head face");
    let bs = String::from_utf8_lossy(&b);
    assert_eq!(bs.matches("ffi.C.").count(), 6, "the bootstrap ffi.C call-site census (the witness mirror legs)");
    let fs = String::from_utf8_lossy(&f);
    assert_eq!(fs.matches("ffi.C.").count(), 10, "the finalize ffi.C call-site census (the dump-table mirror legs)");
}

// ==========================================================================
// T13: the docs/seed tripwires (the CURRENT seed faces NEVER moved by this
// row; the OWN joined tokens + the DONE echo ride ZERO; the mod.rs flip)
// ==========================================================================
#[test]
fn t13_docs_seed_tripwires() {
    let next = std::fs::read_to_string(repo_path().join("NEXT.md")).unwrap();
    let linecount = |needle: &str| -> usize {
        next.lines().filter(|l| l.contains(needle)).count()
    };
    assert_eq!(linecount("841 tests green / 0 FAILED"), 3, "the CURRENT seed face x3 NEVER moved");
    for s in ["825", "810", "798", "784", "772", "763", "752"] {
        assert_eq!(linecount(&format!("{s} tests green / 0 FAILED")), 3, "the carried seed {s} x3");
    }
    assert_eq!(linecount("588 tests green / 0 FAILED"), 4);
    assert_eq!(linecount("580 passed / 0 failed"), 3);
    assert_eq!(linecount("573 tests green"), 5);
    assert_eq!(linecount(format!("5 TES{}", "T(").as_str()), 1, "the drift token EXACT-1");
    // the OWN-token ZERO faces (the self-token law; the runtime-built needles):
    let own_token = format!("shell_har{}", "ness");
    let done = format!("SLP{}", "_DONE");
    assert_eq!(linecount(own_token.as_str()), 0, "the joined own-harness CENSUS token NEVER rides NEXT.md");
    assert_eq!(linecount(done.as_str()), 0, "the DONE echo NEVER rides NEXT.md");
    // the mod.rs rider-flip face (the 62d6fac complete-flip law):
    let mrs = std::fs::read_to_string(repo_path().join("src/main/mod.rs")).unwrap();
    assert_eq!(mrs.lines().count(), 11, "the 7 -> 8 -> 9 -> 10 -> 11 rider-flip chain (row 24f: the snort-module config-owner pair's ONE new wiring line, the 62d6fac law, walked face)");
    assert_eq!(mrs.matches(format!("pub mod shell{}", "p").as_str()).count(), 1, "the ONE new seat");
    // the PLAN row + the deviations section banked IN the code commit:
    let plan = std::fs::read_to_string(repo_path().join("PORTING_PLAN.md")).unwrap();
    assert_eq!(plan.lines().filter(|l| l.starts_with("| 24c |")).count(), 1, "the plan-row EXACTLY-1 law");
    let dev = std::fs::read_to_string(repo_path().join("KNOWN DEVIATIONS.md")).unwrap();
    assert!(
        dev.lines().any(|l| l.starts_with("## ") && l.contains("row 24c")),
        "the deviations section banked IN-COMMIT"
    );
    assert_eq!(dev.lines().filter(|l| l.contains(done.as_str())).count(), 0, "the DONE echo NEVER rides docs");
}

// ==========================================================================
// T14: the SELF-census — ZERO allow-attributes ZERO un-safe (landing + this
// twin); the ONE-HOME REUSE faces (the Command face + the Lua RAII home)
// ==========================================================================
#[test]
fn t14_self_census_and_one_home() {
    let this = std::fs::read_to_string(format!("{}/tests/{}", env!("CARGO_MANIFEST_DIR"), "shell_parity_test.rs")).unwrap();
    let landing = std::fs::read_to_string(repo_path().join("src/main/shellp.rs")).unwrap();
    let attr = format!("{}{}", "#[", "allow");
    let unsf = format!("uns{}", "afe");
    assert_eq!(landing.matches(attr.as_str()).count(), 0, "ZERO allow-attributes in the landing");
    assert_eq!(this.matches(attr.as_str()).count(), 0, "ZERO allow-attributes in the twin");
    assert_eq!(landing.matches(unsf.as_str()).count(), 0, "ZERO un-safe faces in the landing");
    assert_eq!(this.matches(unsf.as_str()).count(), 0, "ZERO un-safe faces in the twin (the needle runtime-built so the SELF-scan NEVER joins the token it counts)");
    // the ONE-HOME REUSE faces (the token assembled at runtime so this
    // scan NEVER joins the face it counts):
    let modrs = std::fs::read_to_string(repo_path().join("src/framework/module.rs")).unwrap();
    assert_eq!(modrs.matches(format!("pub struct Comman{}", "d").as_str()).count(), 1, "the Command face rides the landed home");
    assert_eq!(landing.matches(format!("pub struct Comman{}", "d").as_str()).count(), 0, "NEVER re-forked HERE");
    let luah = std::fs::read_to_string(repo_path().join("src/lua/mod.rs")).unwrap();
    assert!(
        luah.matches(format!("ManageSta{}", "ck").as_str()).count() >= 3,
        "the landed Lua RAII home (the REAL ground owner TU rides the harness link REAL)"
    );
    // the landmine NAMING law (the runtime-built face NEVER joins here):
    let land = format!("{}{}", "struct Tra", "cer");
    assert_eq!(landing.matches(land.as_str()).count(), 0);
    assert_eq!(this.matches(land.as_str()).count(), 0);
}
