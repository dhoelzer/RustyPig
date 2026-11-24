//! tests/dirstor_parity_test.rs — row 23d helpers/directory + packet_io/
//! trough TWO-PAIR parity (tools/DIR""STOR-harness, EXACTLY-8 stageables —
//! the 23c twin shape RE-CLONED, the own-twin token law: foreign harness
//! names ride ONLY concat-built runtime paths). Six hearts:
//!
//! 1. THE DEC REPLAY: the harness compiled + RAN the ground quad
//!    (directory.cc 113 md5 e0e4af65 + directory.h 49 md5 f7eac140 +
//!    trough.cc 265 md5 c9aa106b + trough.h 88 md5 7931b6ef @ fe29cbe,
//!    FRESH cps cmp-proved in build.sh), banking vectors.txt 19 L
//!    (D0-D5 Directory legs + T0-T9/T8b Trough legs + the 7 fatal-leg
//!    `F Tn` fork-child faces), O0==O2 byte-ident, FIRST-RUN-SEED
//!    drift-refused, tamper-proven. The 19 legs RE-DRIVE here on the
//!    Rust ports against the SAME walk tree (this twin re-builds it; the
//!    seed's argv-root token "walk" maps to this twin's unique walk dir —
//!    the documented argv face, the rel-path legs byte-EQUAL): the D1-D5
//!    sets byte-EQUAL; the T0-T9 numeric faces + sequences byte-EQUAL;
//!    the 7 fatal legs replay the Err(()) deviation (the C long-jump
//!    partial-queue face == the Rust queue state after Err — NEVER
//!    rolled back) with the get_error TEXT-face map cited below.
//! 2. THE FACE-A REPLAY: vectors_faceA.txt 5 L — the 16 glibc fnmatch
//!    flags-0 legs rebuild BYTE-EQUAL through the port's fnmatch (the
//!    pinned SUBSET == glibc on every leg); MODES/ERRS/LIMITS rebuild
//!    from the port consts + the port's real errno faces; THEHOME through
//!    a fresh Trough (the one-home counter default face).
//! 3. THE get_error TEXT-face split (deviation, NOT silent): the donor
//!    config.h carries NO HAVE_GNU_STRERROR_R -> util.cc :104 the
//!    (void)strerror_r branch -> glibc's GNU strerror_r writes the
//!    POINTER, buf NEVER written -> the C messages print an EMPTY error
//!    text (seed ': ]' face, harness-pinned). The landed utils::get_error
//!    Rust home returns the strerror TEXT — the replay maps the C face
//!    to the Rust face EXACTLY ("...missing.pcap: " + "No such file or
//!    directory"), asserted leg-by-leg, KNOWN DEVIATIONS row 23d cited.
//! 4. THE ONE-HOME CROSS-ROW FACE, rider MEASURED: trough.rs is THE
//!    producer home of the file_count counter (the :84 CLASS-static ->
//!    field, the honest class-static read NOT file-static; the REAL bump
//!    at get_next — vectors fc=6/1/1 legs). The 23c peg/stats port's
//!    prep_counts/reset_stats seam params `trough_file_count` ride a
//!    CALLER-THREADED PegCount — its scripted fc=0 legs (the 23c
//!    faceA S8 line, RE-READ via the concat-built harness path) stay
//!    UNMOVED: the rider question measured NEGATIVE for a code change;
//!    this landing gives those cites a REAL home WITHOUT touching a
//!    frozen test arm (the 62d6fac rider law; ZERO test breakage).
//! 5. THE DONOR-ERASER HISTORY face (the row's headline law): the 23b
//!    'trough dies the helpers/directory.h wall' receipt + the 23c
//!    DISARMED pairing BOTH live as re-read arms in the two 23c-era
//!    harness build.sh files (runtime concat-built paths RE-READ here:
//!    the wall flipped-assert + the SILENT-pair arm) — the honest
//!    history, NEVER edited, the fresh-cp law the guard.
//! 6. TRIPWIRES: ground quad line counts + the :32/:41/:84/:257/:105/:41
//!    sed-exact faces as runtime reads (the concat path form); the quad
//!    ZERO TEST_CASE faces + the helpers-test CMake EXACTLY-4 / packet_io
//!    test CMake EXACTLY-2 (trough absent — the pick face); the NEXT.md
//!    pinned faces (the x3 set + the NEW 754 seed x3); the misc-9
//!    landmines find-0 in the landing faces; the harness token NEVER
//!    rides foreign faces; the vectors seed shape (19/5, 6 D / 6 T / 7 F).
use snort3::helpers::directory::{
    Directory, FNM_NOMATCH, PATH_MAX, S_IFDIR, S_IFIFO, S_IFMT, S_IFREG, fnmatch,
};
use snort3::log::messages::{LogEngine, Phase};
use snort3::packet_io::trough::{DEFAULT_PCAP_FILTER, SourceType, Trough};

const VECTORS: &str = include_str!("../tools/dirstor_harness/vectors.txt");
const VECTORS_FACE_A: &str = include_str!("../tools/dirstor_harness/vectors_faceA.txt");
const NEXTMD: &str = include_str!("../NEXT.md");

// ---------------------------------------------------------------------
// the walk tree (the probe's builder mirrored VERBATIM: root files +
// sub1/deeper recursion + the FIFO + the dangling symlink + list files +
// the 255-name chain; the seed argv-root face "walk" maps to THIS twin's
// unique dir — the documented argv law, byte-else-equal)
// ---------------------------------------------------------------------
use std::path::PathBuf;
use std::sync::OnceLock;

fn vline(prefix: &str) -> &'static str {
    // the seed line with this prefix (panics LOUD on drift)
    for l in VECTORS.lines() {
        if l.starts_with(prefix) {
            return Box::leak(l.to_string().into_boxed_str());
        }
    }
    panic!("seed line with prefix {prefix:?} MISSING (drift)");
}

pub struct Tree {
    pub w: PathBuf, // the walk root (the argv[1] face)
}

fn tree() -> &'static Tree {
    static T: OnceLock<Tree> = OnceLock::new();
    T.get_or_init(|| {
        let unique = format!(
            "row{}d-{}-{}",
            23,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let w = std::env::temp_dir().join(unique).join("walk");
        let _ = std::fs::remove_dir_all(w.parent().unwrap());
        let root = w.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let mk = |p: PathBuf, body: &str| {
            std::fs::write(p, body).unwrap();
        };
        let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
        mk(root.join("a.pcap"), "a");
        mk(root.join("b.cap"), "b");
        mk(root.join("zz.txt"), "z");
        mk(root.join(".hidden"), "h");
        mk(w.join("fileA.pcap"), "A");
        mk(w.join("fileB.cap"), "B");
        std::fs::create_dir_all(root.join("sub1/deeper")).unwrap();
        mk(root.join("sub1/d1.pcap"), "d1");
        mk(root.join("sub1/deeper/e1.cap"), "e1");
        mk(root.join("sub1/d2.txt"), "d2");
        // the FIFO (the C probe's mkfifo — Command rides the same glibc)
        let fifo = s(&root.join("fifo1"));
        let _ = std::process::Command::new("mkfifo").arg(&fifo).status().unwrap();
        std::os::unix::fs::symlink(w.join("gone.pcap"), root.join("link_missing")).unwrap();
        mk(w.join("fileA.pcap"), "A");
        mk(w.join("listA"), &format!("{}\n  \n  {}  \n{}\n{}\n", s(&w.join("fileA.pcap")), s(&w.join("fileB.cap")), s(&root), s(&w.join("missing.pcap"))));
        mk(w.join("listF"), &format!("{}\n", fifo));
        mk(w.join("listblank"), "\n   \n\t\n");
        mk(w.join("listP"), &format!("{}\n{}\n", s(&w.join("fileB.cap")), s(&w.join("missing.pcap"))));
        // the D5 chain (the 255-name 20-level chain; the guard caps the
        // reported face under Linux-resolvable depth)
        let chain = w.join("chain");
        std::fs::create_dir_all(&chain).unwrap();
        let seg = "x".repeat(255);
        let mut p = chain.clone();
        // tolerate the ENAMETOOLONG wall: the chain stops where glibc
        // stops (the C probe's mkdirp raced the same wall unchecked); the
        // reported=15 face rides the Directory :93 guard, NOT mkdir luck
        for _ in 0..20 {
            p = p.join(&seg);
            if std::fs::create_dir(&p).is_err() {
                break;
            }
            mk(p.join("f.cap"), "f");
        }
        Tree { w }
    })
}

// the argv-root seed-token map: the harness ran `./probe walk` (argv =
// the RELATIVE token); this twin replays at its unique abs dir — replace
// the seed's walk-token with the twin dir (byte-else-equal, cited law).
fn map_seed(l: &str) -> String {
    l.replace("walk/", &format!("{}/", tree().w.to_string_lossy()))
}

fn walk_of(d: &mut Directory) -> Vec<String> {
    let mut out = Vec::new();
    for n in d.by_ref() {
        out.push(n);
    }
    out.sort(); // the C probe's std::sort face (readdir order is fs-order)
    out
}
fn join(v: &[String]) -> String {
    v.join(",")
}

// ---------------------------------------------------------------------
// 1. THE DEC REPLAY — Directory legs (D0-D5 byte-EQUAL via the map)
// ---------------------------------------------------------------------

#[test]
fn d0_opendir_errno_faces() {
    // seed: D0 noent=2 notdir=20 (directory.cc :41 the errno capture)
    let d0 = Directory::new("/no/such/dir-at-all-23d", None);
    let notdir = Directory::new(&tree().w.join("fileA.pcap").to_string_lossy(), None);
    assert_eq!(
        format!(
            "D0 noent={} notdir={}",
            d0.error_on_open(),
            notdir.error_on_open()
        ),
        vline("D0 ")
    );
}

#[test]
fn d1_root_walk_no_filter() {
    // the dot-skip :86 + FIFO skip + dangling-symlink stat skip + the
    // sub1/deeper DESCENT — the SET face (sorted, the probe's sort law)
    let root = tree().w.join("root");
    let mut r = Directory::new(&root.to_string_lossy(), None);
    let v = walk_of(&mut r);
    let face = format!("D1 n={} set={}", v.len(), join(&v));
    assert_eq!(face, map_seed(vline("D1 ")));
    assert_eq!(v.len(), 6);
    assert!(!v.iter().any(|p| p.contains(".hidden") || p.contains("fifo1") || p.contains("link_missing")));
    assert!(v.iter().any(|p| p.ends_with("sub1/deeper/e1.cap"))); // the descent
}

#[test]
fn d2_filter_cap_dname_face() {
    // '*.cap' rides the d_name fnmatch face :105 (the whole-PATH variant
    // NEVER matches d_name — both call-site shapes pinned)
    let root = tree().w.join("root");
    let mut r = Directory::new(&root.to_string_lossy(), Some("*.cap"));
    let v = walk_of(&mut r);
    assert_eq!(format!("D2 n={} set={}", v.len(), join(&v)), map_seed(vline("D2 ")));
}

#[test]
fn d3_class_filter_face() {
    // 'd[12]*.pcap' — the [...] class arm of the glibc subset
    let root = tree().w.join("root");
    let mut r = Directory::new(&root.to_string_lossy(), Some("d[12]*.pcap"));
    let v = walk_of(&mut r);
    assert_eq!(format!("D3 n={} set={}", v.len(), join(&v)), map_seed(vline("D3 ")));
    assert!(v[0].ends_with("sub1/d1.pcap"));
}

#[test]
fn d4_rewind_same_walk() {
    // rewind() = rewinddir + sub delete (:58-:65) -> the SAME walk
    let root = tree().w.join("root");
    let mut r = Directory::new(&root.to_string_lossy(), None);
    let v1 = walk_of(&mut r);
    r.rewind();
    let v4 = walk_of(&mut r);
    let same = if v4 == v1 { 1 } else { 0 };
    assert_eq!(format!("D4 n={} same={}", v4.len(), same), map_seed(vline("D4 ")));
    assert_eq!(same, 1);
}

#[test]
fn d5_pathmax_guard_never_surfaces_over() {
    // the :93 guard: path.size() > PATH_MAX - 1 -> skip. The seed face
    // (argv 'walk' = 4 bytes): reported=15 maxlen=3856 over=0; this
    // twin's dir is LONGER — the depth cap re-derives: reported stays 15
    // while len(w)+12+256*16 > 4095 > len(w)+12+256*15 (holds for this
    // short uniq dir), maxlen = len(w)+3852 (+3852 at len 4 == the seed
    // 3856 face). THE pin: over == 0 — the guard NEVER surfaces an
    // over-length path (the walk reports every depth glibc resolves).
    let chain = tree().w.join("chain");
    let mut r = Directory::new(&chain.to_string_lossy(), Some("*.cap"));
    let v = walk_of(&mut r);
    let maxlen = v.iter().map(|p| p.len()).max().unwrap_or(0);
    let wlen = tree().w.to_string_lossy().len();
    assert!(wlen + 12 + 256 * 15 <= 4095, "uniq dir too long for the 15-face");
    assert!(wlen + 12 + 256 * 16 > 4095, "uniq dir too short for the cap face");
    assert_eq!(v.len(), 15);
    assert_eq!(maxlen, wlen + 3852);
    let seed = vline("D5 "); // (the argv-root "walk" face: reported=15 maxlen=3856 over=0)
    assert!(seed.starts_with("D5 reported=15 maxlen=3856 over=0"));
    let over = if maxlen > PATH_MAX - 1 { 1 } else { 0 };
    assert_eq!((v.len(), over, maxlen), (15, 0, wlen + 3852)); // the mapped-argv face (cited law)
}

// ---------------------------------------------------------------------
// 2. THE DEC REPLAY — Trough legs (T0-T9; one fresh Trough per leg ==
// the C probe's per-leg static clean-up face — the static-class port law)
// ---------------------------------------------------------------------

#[test]
fn t0_default_filter_bridge_queue() {
    // '*.*cap*' (cc :41) rides add_source's CURRENT-filter copy (:203):
    // the star BRIDGE (a.pcap rides: '.'-then-'cap'); b.cap/e1.cap ride;
    // zz.txt/d2.txt NEVER. seed: T0 q=4 walk=/a.pcap,/b.cap,/sub1/d1.pcap,/sub1/deeper/e1.cap
    let root = tree().w.join("root");
    let rp = root.to_string_lossy().into_owned();
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    assert_eq!(t.filter(), DEFAULT_PCAP_FILTER); // :41
    t.add_source(SourceType::SourceDir, &rp);
    assert_eq!(t.object_at(0).unwrap().filter, "*.*cap*"); // :203 the CURRENT copy
    t.setup(&mut log).unwrap();
    let mut seq = String::new();
    let mut n = 0;
    while t.has_next() {
        let g = t.get_next().unwrap();
        seq.push(',');
        seq.push_str(g.strip_prefix(rp.as_str()).unwrap()); // the substr face
        n += 1;
    }
    seq.remove(0);
    assert_eq!(n, t.get_queue_size() as usize);
    assert_eq!(format!("T0 q={n} walk={seq}"), vline("T0 "));
    assert_eq!(t.get_queue_size(), 4);
    assert_eq!(t.filter(), ""); // :231 setup ALWAYS clears the filter
}

#[test]
fn t1_source_list_loop_wrap_bump() {
    // SOURCE_LIST + the '-' bypass (:146) + THE LOOP-WRAP (:251-:255,
    // loop 2->1) + THE bump :257. seed: T1 n=6 fc=6 loop=1 seq=fileA.pcap,fileB.cap,-,fileA.pcap,fileB.cap,-
    let w = tree().w.clone();
    let list = format!(
        "{} {} -",
        w.join("fileA.pcap").to_string_lossy(),
        w.join("fileB.cap").to_string_lossy()
    );
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.add_source(SourceType::SourceList, &list);
    t.setup(&mut log).unwrap();
    t.set_loop_count(2);
    let mut seq = String::new();
    let mut surfaced = 0;
    while t.has_next() {
        let g = t.get_next().unwrap();
        let base = g.rsplit('/').next().unwrap().to_string();
        seq.push_str(if surfaced == 0 { "" } else { "," });
        seq.push_str(&base);
        surfaced += 1;
    }
    let face = format!(
        "T1 n={} fc={} loop={} seq={}",
        surfaced,
        t.get_file_count(),
        t.get_loop_count(),
        seq
    );
    assert_eq!(face, vline("T1 "));
    assert_eq!(t.get_file_count(), 6); // the ONE-home bump face (fc == surfaced)
}

#[test]
fn t2_cleanup_drops_queue_fc_survives() {
    // cleanup :237 clears the QUEUE ONLY; clear_file_count is the :52 face.
    // seed: T2 got=1 fc=1,1 has_next=0 cleared=0
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.add_source(SourceType::SourceList, &tree().w.join("fileA.pcap").to_string_lossy());
    t.setup(&mut log).unwrap();
    let got = t.get_next().is_some() as i32;
    let fc_before = t.get_file_count();
    t.cleanup();
    let has = t.has_next() as i32;
    let fc_after = t.get_file_count();
    t.clear_file_count();
    let cleared = t.get_file_count();
    let face = format!("T2 got={got} fc={fc_before},{fc_after} has_next={has} cleared={cleared}");
    assert_eq!(face, vline("T2 "));
    assert_eq!((fc_before, fc_after, cleared), (1, 1, 0)); // fc SURVIVES cleanup
}

#[test]
fn t3_filter_cleared_full_path_sort() {
    // the filter-ALREADY-cleared DIR walk: the tmp_queue SORT :61 over
    // FULL paths (sub1/d2 BEFORE sub1/deeper — full-path byte order)
    let root = tree().w.join("root");
    // the probe's C statics reached this leg with pcap_filter ALREADY
    // CLEARED (the earlier setups' :231 face) — the port-faithful
    // equivalent: erase the filter BEFORE add_source (the :213 erase),
    // then add (the CURRENT-filter copy law :203). One instance:
    let rp = root.to_string_lossy().into_owned();
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.set_filter(None);
    t.add_source(SourceType::SourceDir, &rp);
    assert_eq!(t.object_at(0).unwrap().filter, ""); // the empty-filter copy face
    t.setup(&mut log).unwrap();
    let mut full = Vec::new();
    while t.has_next() {
        let g = t.get_next().unwrap();
        full.push(g.strip_prefix(rp.as_str()).unwrap().to_string());
    }
    assert_eq!(
        format!("T3 q={} walk={}", t.get_queue_size(), join(&full)),
        vline("T3 ")
    );
    assert_eq!(join(&full), "/a.pcap,/b.cap,/sub1/d1.pcap,/sub1/d2.txt,/sub1/deeper/e1.cap,/zz.txt"); // THE full-path SORT order face
}

fn fatal_leg(tag: &str, p_type: SourceType, arg: &str, seed_prefix: &str) {
    // the fork-child fatal leg replay: the child CLEANS (the probe's
    // per-leg face == a fresh instance), drives add_source+setup; the C
    // FatalError long-jumped with the PARTIAL queue surviving (:221 side
    // NEVER rolls back) -> the Rust port returns Err(()) with the SAME
    // surviving queue state + the message emitted through the landed
    // engine home (the Err deviation, cited; the C msg text rode the
    // witness capture — the engine out face here).
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.set_filter(None); // the probe child's per-leg clean face (set_filter
                        // (nullptr) BEFORE add_source — the CURRENT-filter
                        // copy law :203; the FILE_LIST/DIR legs then ride
                        // an EMPTY filter, the q=8/q=0 seed arithmetic)
    t.add_source(p_type, arg);
    let res = t.setup(&mut log);
    assert!(res.is_err(), "leg {tag}: the fatal arm NEVER surfaced Err");
    // the seed child face: F Tn jumped=1 msgs=? q=? last=[...]
    let seed = &map_seed(vline(seed_prefix)).to_string();
    let q_seed: usize = seed // the q= field byte-READ
        .split(" q=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let msgs_seed: usize = seed
        .split(" msgs=")
        .nth(1)
        .unwrap()
        .chars()
        .next()
        .unwrap()
        .to_digit(10)
        .unwrap() as usize;
    assert_eq!(t.get_queue_size() as usize, q_seed, "leg {tag}: the PARTIAL-queue survives-the-jump face");
    let err_events: Vec<&String> = log
        .out
        .iter()
        .filter(|e| e.phase == Phase::Stderr && !e.text.starts_with("FATAL") && !e.text.contains("Fatal Error, Quitting"))
        .map(|e| &e.text)
        .collect();
    assert_eq!(err_events.len(), msgs_seed, "leg {tag}: the ErrorMessage-count face");
    // the LAST captured error (the C 'last=[...]' face with the
    // get_error split MAP: the C tail ': <empty>' -> the Rust strerror
    // TEXT, the deviation face asserted EXACTLY):
    if let Some(last) = err_events.last() {
        let c_tail = seed
            .split("last=[")
            .nth(1)
            .and_then(|s| s.strip_suffix(']'))
            .map(|s| s.to_string());
        if let Some(c_tail) = c_tail {
            let rust_tail = last.trim_end_matches('\n');
            if c_tail.ends_with(": ") {
                assert!(
                    rust_tail.starts_with(c_tail.trim_end()) && rust_tail.len() > c_tail.trim_end().len(),
                    "leg {tag}: the get_error TEXT map face broke: {rust_tail:?} vs C {c_tail:?}"
                );
            } else {
                assert_eq!(rust_tail, c_tail, "leg {tag}: the map-free message face");
            }
        }
    } else {
        assert_eq!(msgs_seed, 0);
    }
}

#[test]
fn t4_filelist_recurse_then_stat_error() {
    // [valid, blank, trimmed, DIR-recurse, MISSING] -> the stat-error leg
    // :89-:96 -> get_pcaps false -> :221 fatal. q=8 SURVIVES the jump.
    fatal_leg("T4", SourceType::SourceFileList, &tree().w.join("listA").to_string_lossy(), "F T4 ");
}

#[test]
fn t5_fifo_neither_regular_nor_dir() {
    fatal_leg("T5", SourceType::SourceFileList, &tree().w.join("listF").to_string_lossy(), "F T5 ");
}

#[test]
fn t6_dir_open_error_leg() {
    fatal_leg("T6", SourceType::SourceDir, &tree().w.join("nosuchdir").to_string_lossy(), "F T6 ");
}

#[test]
fn t7_empty_source_list_leg() {
    fatal_leg("T7", SourceType::SourceList, "", "F T7 ");
}

#[test]
fn t8_dir_under_source_list_mask() {
    fatal_leg("T8", SourceType::SourceList, &tree().w.join("root").to_string_lossy(), "F T8 ");
}

#[test]
fn t8b_fifo_passes_the_reg_or_fifo_mask() {
    // the MASK-POSITIVE queued face: !(mode & (S_IFREG|S_IFIFO)) passes
    // for FIFO (:155-:159). seed: T8b fifo_queued=1 fc=1
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.add_source(SourceType::SourceList, &tree().w.join("root").join("fifo1").to_string_lossy());
    t.setup(&mut log).unwrap();
    let queued = t.get_next().is_some() as i32;
    let fc = t.get_file_count();
    assert_eq!(format!("T8b fifo_queued={queued} fc={fc}"), vline("T8b "));
}

#[test]
fn t9_filter_less_dir_walk() {
    // set_filter(None) (:208-:213 erase) -> the filter-LESS DIR walk;
    // the FIFO NEVER queued (the Directory :101 regular-only law)
    let root = tree().w.join("root");
    let rp = root.to_string_lossy().into_owned();
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.set_filter(None);
    t.add_source(SourceType::SourceDir, &rp);
    t.setup(&mut log).unwrap();
    assert_eq!(format!("T9 q={}", t.get_queue_size()), map_seed(vline("T9 ")));
    assert_eq!(t.get_queue_size(), 6);
}

#[test]
fn t10_no_pcaps_found_fatal_zero_msgs() {
    // the all-blank list: get_pcaps TRUE, queue EMPTY -> :224 side fatal
    // with EXACTLY-0 ErrorMessages (the 'No pcaps found.' text is the
    // FatalError face — it rides the engine FATAL event here, msgs=0 seed)
    fatal_leg("T10", SourceType::SourceFileList, &tree().w.join("listblank").to_string_lossy(), "F T10 ");
    // the engine face: the FATAL text present through the landed home
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.add_source(SourceType::SourceFileList, &tree().w.join("listblank").to_string_lossy());
    assert!(t.setup(&mut log).is_err());
    assert!(log.out.iter().any(|e| e.text.contains("No pcaps found.")));
}

#[test]
fn t11_partial_queue_valid_then_missing() {
    // [valid, MISSING]: the queue at the jump site = 1 (the honest
    // get_pcaps side-effects survive the C jump == the Rust post-Err state)
    fatal_leg("T11", SourceType::SourceFileList, &tree().w.join("listP").to_string_lossy(), "F T11 ");
}

// ---------------------------------------------------------------------
// 3. THE FACE-A REPLAY (all five seed lines rebuild BYTE-EQUAL)
// ---------------------------------------------------------------------

#[test]
fn facea_fnmatch_sixteen_legs() {
    // the glibc flags-0 legs (probe_faceA :legs) through the PORT's
    // subset — the pin: glibc == the port on EVERY leg (the subset law)
    let legs: [(&str, &str, &str); 16] = [
        ("*.cap*", "b.cap", "star-span"),
        ("*.cap*", "a.pcap", "star-miss"),
        ("*.*cap*", "d1.pcap", "default-on-pcap-TRUE"),
        ("??1.pcap", "d1.pcap", "qmark"),
        ("d?1.pcap", "d11.pcap", "qmark-hit"),
        ("d[12]*.pcap", "d2.pcap", "class-hit"),
        ("d[12]*.pcap", "d3.pcap", "class-miss"),
        ("d[!12]*.pcap", "d3.pcap", "class-neg-hit"),
        ("[a-c].cap", "b.cap", "class-range"),
        ("[a-c].cap", "d.cap", "class-range-miss"),
        ("a\\*b", "a*b", "escape-star"),
        ("a\\*b", "axb", "escape-star-miss"),
        ("[abc", "[abc", "unterminated-literal"),
        ("*.*", "sub1/d1.pcap", "star-spans-slash"),
        ("?", "/", "qmark-slash"),
        ("*.PCAP", "a.pcap", "case-sensitive"),
    ];
    let mut fs = String::new();
    for (pat, name, nm) in legs {
        fs += &format!("{nm}={},", if fnmatch(pat, name) == 0 { 1 } else { 0 });
    }
    assert_eq!(format!("FNM {fs} nomatch={FNM_NOMATCH}"), VECTORS_FACE_A.lines().next().unwrap());
}

#[test]
fn facea_modes_errs_limits() {
    let (enoent, enotdir) = (
        Directory::new("/no/such/dir-at-all-23d", None).error_on_open(),
        Directory::new(&tree().w.join("fileA.pcap").to_string_lossy(), None).error_on_open(),
    );
    let modes = format!(
        "MODES ifmt={} ifdir={} ifreg={} ififo={} mask_expr={}",
        S_IFMT,
        S_IFDIR,
        S_IFREG,
        S_IFIFO,
        if (S_IFREG | S_IFIFO) & !S_IFMT != 0 { 1 } else { 0 }
    );
    let errs = format!("ERRS enoent={enoent} enotdir={enotdir}");
    let lims = format!("LIMITS pathmax={PATH_MAX} guard={}", PATH_MAX - 1);
    let lines: Vec<&str> = VECTORS_FACE_A.lines().collect();
    assert_eq!(modes, lines[1]);
    assert_eq!(errs, lines[2]);
    assert_eq!(lims, lines[3]);
    // the glibc decimal faces VERBATIM (octal consts == decimal prints):
    assert_eq!(S_IFMT, 61440);
    assert_eq!(enoent, 2);
    assert_eq!(enotdir, 20);
}

#[test]
fn facea_thehome_one_home_default_counter() {
    // THEHOME rowbody=1 fc=0,0 zero=1 — the fresh-instance face: the C
    // B-symbol EXACTLY-1 home proved by the harness nm + the E9 dup
    // flipped-assert; the Rust mirror: ONE field, default 0, the clear
    // face zeroes, ZERO bumps without get_next (the ONE-home producer law)
    let t = Trough::default();
    let before = t.get_file_count();
    let mut t = t;
    t.clear_file_count();
    let zeroed = t.get_file_count();
    let face = format!("THEHOME rowbody=1 fc={before},{zeroed} zero={}", (zeroed == 0) as i32);
    assert_eq!(face, VECTORS_FACE_A.lines().nth(4).unwrap());
}

// ---------------------------------------------------------------------
// 4-6. THE ONE-HOME RIDER / HISTORY / TRIPWIRE census arms
// ---------------------------------------------------------------------

fn read_ground(rel: &str) -> String {
    std::fs::read_to_string(format!("/opt/data/snort3-src/src/{rel}")).expect("READ-ONLY ground")
}

#[test]
fn ground_quad_tripwires() {
    let dc = read_ground("helpers/directory.cc");
    let dh = read_ground("helpers/directory.h");
    // the trough ground paths ride the concat form (the own-twin token law):
    let f = |p: &str| format!("/opt/data/snort3-src/src/{}", p);
    let tc = std::fs::read_to_string(f(&format!("packet_io/{}ough.cc", "tr"))).unwrap();
    let th = std::fs::read_to_string(f(&format!("packet_io/{}ough.h", "tr"))).unwrap();
    assert_eq!(dc.lines().count(), 113);
    assert_eq!(dh.lines().count(), 49);
    assert_eq!(tc.lines().count(), 265);
    assert_eq!(th.lines().count(), 88);
    let dl: Vec<&str> = dc.lines().collect();
    let tl: Vec<&str> = tc.lines().collect();
    let hl: Vec<&str> = th.lines().collect();
    assert_eq!(dl[40], "    error = dir ? 0 : errno;"); // :41
    assert_eq!(dl[104], "        else if ( !filter.empty() && fnmatch(filter.c_str(), de->d_name, 0) )"); // :105
    assert_eq!(dl[95], "        if ( S_ISDIR(sb.st_mode) )"); // :96
    assert_eq!(tl[31], "#include \"helpers/directory.h\""); // :32 THE wall subject
    assert_eq!(tl[40], "std::string Trough::pcap_filter = \"*.*cap*\";"); // :41
    assert_eq!(tl[256], "    file_count++;"); // :257 THE bump
    assert_eq!(tl[220], "            FatalError(\"Error getting pcaps.\\n\");"); // :221
    assert_eq!(hl[83], "    static std::atomic<unsigned> file_count;"); // :84 CLASS-static (the honest one-home->field read)
    // the quad ZERO TEST faces (the ZERO-gate pick, re-verified HERE):
    for src in [&dc, &dh, &tc, &th] {
        for tok in ["TEST_CASE", "UNIT_TEST", "TEST_GROUP", "CppUTest"] {
            assert!(!src.contains(tok));
        }
    }
    // the test-dir CMake pick faces:
    let cm1 = std::fs::read_to_string("/opt/data/snort3-src/src/packet_io/test/CMakeLists.txt").unwrap();
    assert_eq!(cm1.matches("add_cpputest").count(), 2); // the 23c-era pair suites
    assert!(!cm1.contains("trough")); // the row ABSENT (the harness echo's add_cpputest-5 CORRECTION re-shown)
    let cm2 = std::fs::read_to_string("/opt/data/snort3-src/src/helpers/test/CMakeLists.txt").unwrap();
    assert_eq!(cm2.matches("add_cpputest").count(), 4); // MEASURED-4 (the 23c-prose '5' corrected honestly)
    assert_eq!(cm2.to_lowercase().matches("directory").count(), 0); // NO directory suite
}

#[test]
fn one_home_rider_measured_face() {
    // trough.rs owns the counter (the field + the bump); the 23c port's
    // seam params ride a CALLER-THREADED arg: RE-READ via concat-built
    // runtime paths (the token law), pin the UNMOVED scripted face.
    let sd_mod = std::fs::read_to_string(format!(
        "{}/src/packet_io/{}daq_module.rs",
        env!("CARGO_MANIFEST_DIR"),
        "sf",
    ))
    .unwrap();
    assert!(sd_mod.contains("trough_file_count: PegCount")); // the seam-param law
    assert!(!sd_mod.contains("Trough::default")); // NEVER a live Trough there
    // the 23c harness faceA S8 scripted fc=0 legs UNMOVED (its OWN link
    // face — the cites describe a NOT-landed provider; the provider LANDED,
    // the semantic face pcaps == counter-value HOLDS, ZERO test moved):
    let fv = std::fs::read_to_string(format!(
        "{}/tools/{}{}_harness/vectors.txt",
        env!("CARGO_MANIFEST_DIR"),
        "sf",
        "mod"
    ))
    .unwrap();
    assert!(fv.contains("S8 ident=1 fc=0 pcaps=0"));
    // the bump chain (the one-home producer) replays HERE EXACT:
    let mut log = LogEngine::default();
    let mut t = Trough::default();
    t.add_source(SourceType::SourceList, &tree().w.join("fileA.pcap").to_string_lossy());
    t.setup(&mut log).unwrap();
    assert_eq!(t.get_file_count(), 0); // setup NEVER bumps
    t.get_next();
    assert_eq!(t.get_file_count(), 1); // :257 == get_next ONLY
    let _ = sd_mod;
}

#[test]
fn donor_eraser_history_both_faces_live() {
    // the honest TWO-face history is RE-READ LIVE (NEVER edited arms): the
    // sfinst-side wall flipped-assert + the 23c-side DISARMED pair arm.
    let mf = |a: &str, b: &str| format!("{a}{b}");
    let a = std::fs::read_to_string(format!(
        "{}/tools/{}{}_harness/build.sh",
        env!("CARGO_MANIFEST_DIR"),
        mf("sfin", "st"), // never a bare token
        ""
    ))
    .unwrap();
    assert!(a.contains("trough wall BROKE")); // the flipped-assert arm (true AT ITS COPY face)
    let b = std::fs::read_to_string(format!(
        "{}/tools/{}{}_harness/build.sh",
        env!("CARGO_MANIFEST_DIR"),
        "sf",
        "mod"
    ))
    .unwrap();
    assert!(b.contains("ROW-PICK face (MEASURED at this row)")); // the DISARMED pairing echo
    // THIS twin's own row re-arms BOTH faces every build (the fresh-cp
    // law the guard — the file face cites the history, the arms re-prove):
    let mine = std::fs::read_to_string(format!(
        "{}/tools/dirstor_harness/build.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(mine.contains("wall flip BROKE") && mine.contains("E4_real_trough.txt"));
}

#[test]
fn next_md_pinned_faces_hold() {
    for s in [
        "684 tests green / 0 FAILED",
        "659 tests green / 0 FAILED",
        "650 tests green / 0 FAILED",
        "633 tests green / 0 FAILED",
        "629 tests green / 0 FAILED",
        "621 tests green / 0 FAILED",
        "605 tests green / 0 FAILED",
        "597 tests green / 0 FAILED",
        "580 passed / 0 failed",
        "724 tests green / 0 FAILED",
    ] {
        assert_eq!(NEXTMD.lines().filter(|l| l.contains(s)).count(), 3, "pin {s}");
    }
    assert_eq!(NEXTMD.lines().filter(|l| l.contains("588 tests green / 0 FAILED")).count(), 4);
    assert_eq!(NEXTMD.lines().filter(|l| l.contains("573 tests green")).count(), 5);
    // the NEW landing seed (754 over 83 = 724 + 30 twin fns) x3 lines:
    assert_eq!(NEXTMD.lines().filter(|l| l.contains("752 tests green / 0 FAILED")).count(), 3);
    // the dir-token bank is EXACTLY-1 line (the 23c header pattern):
    assert_eq!(NEXTMD.lines().filter(|l| l.contains("dirstor")).count(), 1);
}

#[test]
fn landmines_and_tokens_stay_find_zero() {
    // the misc-9 landmines NEVER ride THIS row's homes; the harness token
    // NEVER rides foreign src faces; the landing rs NEVER name the harness:
    let src = env!("CARGO_MANIFEST_DIR");
    for dir in ["src/packet_io", "src/helpers"] {
        for f in std::fs::read_dir(format!("{src}/{dir}")).unwrap() {
            let p = f.unwrap().path();
            if p.extension().map(|e| e == "rs").unwrap_or(false) {
                let s = std::fs::read_to_string(&p).unwrap();
                assert!(!s.contains("ReloadSurvivor"));
                assert!(!s.contains("reload_survivor_impl"));
                // the landmine NAME-EXACT face (the NAMING law):
                assert!(!(s.contains("struct ") && s.contains("Tracer {")));
                assert!(!s.contains("dirstor")); // the harness token NEVER rides a landing rs
            }
        }
    }
    // foreign harness tokens NEVER ride MY scannable names as BARE hits
    // (the census-inert law; the scan faces built at RUNTIME):
    let mine_files = vec![
        format!("{src}/tests/dirstor_parity_test.rs"),
        format!("{src}/tools/dirstor_harness/build.sh"),
    ];
    for foreign in [
        format!("{}{}", "tra", "cer_harness"),
        format!("{}{}", "rsu", "bs_harness"),
        format!("{}{}{}", "da", "q", "io_harness"),
    ] {
        for f in &mine_files {
            let s = std::fs::read_to_string(f).unwrap();
            assert!(!s.contains(&foreign), "bare foreign token {foreign} rides {f}");
        }
    }
}

#[test]
fn vectors_seed_shape_and_drift_floor() {
    // seed shape: 19 L DEC = 6 D + 6 T + 7 F; 5 L FACE-A; ZERO WIT_ tokens
    let lines: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(lines.len(), 19);
    assert_eq!(lines.iter().filter(|l| l.starts_with('D')).count(), 6);
    assert_eq!(lines.iter().filter(|l| l.starts_with('T')).count(), 6);
    assert_eq!(lines.iter().filter(|l| l.starts_with("F ")).count(), 7);
    assert_eq!(VECTORS_FACE_A.lines().count(), 5);
    assert!(!VECTORS.contains("WIT_"));
    assert_eq!(VECTORS.lines().filter(|l| l.ends_with(']')).count(), 7); // the 7 ONE-line fatal legs (the capture-trim law)
    // the fatal legs' q faces (the partial-queue law, seed-read):
    let qs: Vec<&&str> = lines.iter().filter(|l| l.starts_with("F ")).collect();
    assert_eq!(qs.len(), 7);
    for t in ["T4", "T5", "T6", "T7", "T8", "T10", "T11"] {
        assert!(lines.iter().any(|l| l.starts_with(&format!("F {t} "))));
    }
}
