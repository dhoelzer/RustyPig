// Whole-transcript replay of tools/fid_harness/vectors.txt (C probe
// compiles file_identifier.cc VERBATIM) against the Rust port, plus
// faithful translations of the 6 upstream [FileMagic] TEST_CASEs.
use snort3::file_api::file_identifier::*;

const PE_EXPECT: &str = "PE file type: rule id 1 found duplicate";

struct Sink {
    msgs: Vec<String>,
}
impl FileIdErrorSink for Sink {
    fn parse_error(&mut self, msg: &str) {
        self.msgs.push(format!("PE {}", msg));
    }
}

impl Sink {
    fn new() -> Self {
        Sink { msgs: Vec::new() }
    }
}

const BITS_WORDS: usize = FILE_ID_MAX / 64;

fn bitset_count(ids: &[u64; BITS_WORDS]) -> u32 {
    ids.iter().map(|w| w.count_ones()).sum::<u32>()
}
fn bitset_test(ids: &[u64; BITS_WORDS], i: usize) -> bool {
    ids[i / 64] & (1u64 << (i % 64)) != 0
}

struct Rep {
    got: Vec<String>,
}

impl Rep {
    fn push(&mut self, s: impl Into<String>) {
        self.got.push(s.into());
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn fid_transcript_replay() {
    let mut rep = Rep { got: Vec::new() };
    let mut sink = Sink::new();

    // ---- FileMeta::clear ----
    let mut r = FileMeta {
        rev: 7,
        id: 3,
        r#type: "pdf".into(),
        category: "docs".into(),
        version: "\"1.7\"".into(),
        groups: vec!["g1".into(), "g2".into()],
    };
    r.clear();
    rep.push(format!(
        "CLEAR {} {} [{}] [{}] [{}] ng={}",
        r.rev,
        r.id,
        r.r#type,
        r.category,
        r.version,
        r.groups.len()
    ));

    // ---- empty-trie production path ----
    let mut fi = FileIdentifier::new();
    rep.push(format!("P0 mem={}", fi.memory_usage()));

    let a = FileMeta {
        r#type: "pdf".into(),
        id: 1,
        ..Default::default()
    };
    fi.add_file_id(&a, &mut sink);
    rep.push(format!("A1 mem={}", fi.memory_usage()));

    let mut ctx: Option<FIdNode> = None;
    let r1 = fi.find_file_type_id(b"PDF", 0, &mut ctx);
    rep.push(format!(
        "P1 empty find={} ctxnull={}",
        r1,
        ctx.is_none() as u8
    ));
    let r2 = fi.find_file_type_id(b"", 0, &mut ctx);
    rep.push(format!(
        "P2 empty find2={} ctxnull={}",
        r2,
        ctx.is_none() as u8
    ));

    // ---- duplicate id -> ParseError; first rule kept ----
    let dupt = FileMeta {
        r#type: "exe".into(),
        id: 1,
        ..Default::default()
    };
    fi.add_file_id(&dupt, &mut sink);
    assert_eq!(sink.msgs.as_slice(), [PE_EXPECT]);
    for m in sink.msgs.drain(..) {
        rep.push(m);
    }
    let got = fi.get_rule_from_id(1);
    rep.push(format!(
        "DUP kept=[{}] id={}",
        got.map_or("-".into(), |g| g.r#type.clone()),
        got.map_or(0, |g| g.id)
    ));

    // ---- get_rule_from_id edges ----
    let b = FileMeta {
        r#type: "exe".into(),
        id: 2,
        ..Default::default()
    };
    fi.add_file_id(&b, &mut sink);
    let g2 = fi.get_rule_from_id(2);
    let g0 = fi.get_rule_from_id(0);
    let gbig = fi.get_rule_from_id((FILE_ID_MAX + 1) as u32);
    rep.push(format!(
        "GET id2=[{}] id0={} id1025={}",
        g2.map_or("-".into(), |g| g.r#type.clone()),
        (g0.is_none()) as u8,
        (gbig.is_none()) as u8
    ));

    // ---- id 0 quirk ----
    let z = FileMeta {
        r#type: "zero".into(),
        id: 0,
        ..Default::default()
    };
    fi.add_file_id(&z, &mut sink);
    assert!(sink.msgs.is_empty());
    let gz = fi.get_rule_from_id(0);
    rep.push(format!("ZERO keptnull={}", gz.is_none() as u8));

    // ---- get_magic_rule_ids_from_type ----
    let c = FileMeta {
        r#type: "".into(),
        id: 3,
        ..Default::default()
    };
    fi.add_file_id(&c, &mut sink);
    let mut ids = [0u64; BITS_WORDS];
    fi.get_magic_rule_ids_from_type("exe", "", &mut ids);
    rep.push(format!(
        "MEXE count={} id1={} id2={} id3={}",
        bitset_count(&ids),
        bitset_test(&ids, 1) as u8,
        bitset_test(&ids, 2) as u8,
        bitset_test(&ids, 3) as u8
    ));
    fi.get_magic_rule_ids_from_type("exe", "1.7", &mut ids);
    rep.push(format!("MEXE17 count={}", bitset_count(&ids)));
    let d = FileMeta {
        r#type: "exe".into(),
        id: 4,
        version: "\"1.7\"".into(),
        ..Default::default()
    };
    fi.add_file_id(&d, &mut sink);
    fi.get_magic_rule_ids_from_type("exe", "1.7", &mut ids);
    rep.push(format!(
        "MEXE17B count={} id2={} id4={}",
        bitset_count(&ids),
        bitset_test(&ids, 2) as u8,
        bitset_test(&ids, 4) as u8
    ));
    fi.get_magic_rule_ids_from_type("", "", &mut ids);
    rep.push(format!(
        "MEMPTY count={} id3={}",
        bitset_count(&ids),
        bitset_test(&ids, 3) as u8
    ));

    // ---- witness-grown trie: root(0)->'P' n1(1)->'D' n2(2 type 42) ----
    let (_root, ns) = fi.test_grow();
    let (n1, n2) = (ns[0].clone(), ns[1].clone());
    rep.push(format!(
        "GROWN mem={} sznode={}",
        fi.memory_usage(),
        C_IDENTIFIER_NODE_SIZE
    ));

    let mut ctx: Option<FIdNode> = None;
    let t1 = fi.find_file_type_id(b"PDFEXE", 0, &mut ctx);
    rep.push(format!(
        "T1 full={} ctxnull={}",
        t1,
        ctx.is_none() as u8
    ));

    let mut ctx: Option<FIdNode> = None;
    let t2 = fi.find_file_type_id(b"PD", 0, &mut ctx);
    rep.push(format!(
        "T2 atnode={} ctxoff={}",
        t2,
        ctx.as_ref().map_or(-1, |c| c.borrow().offset as i64)
    ));

    let mut ctx: Option<FIdNode> = Some(n1.clone());
    let t3 = fi.find_file_type_id(b"FEXE", 1, &mut ctx);
    rep.push(format!(
        "T3 resume={} ctxoff={}",
        t3,
        ctx.as_ref().map_or(-1, |c| c.borrow().offset as i64)
    ));

    let mut ctx: Option<FIdNode> = None;
    let t4 = fi.find_file_type_id(b"PQ", 0, &mut ctx);
    rep.push(format!(
        "T4 nomatch={} ctxnull={}",
        t4,
        ctx.is_none() as u8
    ));

    let mut ctx: Option<FIdNode> = None;
    let t5 = fi.find_file_type_id(b"PDF", 5, &mut ctx);
    rep.push(format!(
        "T5 skipped={} ctxnull={}",
        t5,
        ctx.is_none() as u8
    ));
    let _ = n2;

    rep.push("DONE".to_string());

    let want_bytes = include_bytes!("../tools/fid_harness/vectors.txt");
    let want = String::from_utf8(want_bytes.to_vec()).expect("vectors utf8");
    let want_lines: Vec<String> = want
        .trim_end_matches('\n')
        .split('\n')
        .map(|s| s.to_string())
        .collect();
    assert_eq!(want_lines, rep.got, "transcript replay mismatch");
}

// ---- upstream [FileMagic] TEST_CASE translations ----
// (all six tautologies: add_file_id never inserts into the trie, so
// find always returns SNORT_FILE_TYPE_UNKNOWN on production objects)

fn meta(t: &str, id: u32) -> FileMeta {
    FileMeta {
        r#type: t.into(),
        id,
        ..Default::default()
    }
}

fn find_unknown(rc: &mut FileIdentifier, data: &[u8]) -> u32 {
    let mut ctx: Option<FIdNode> = None;
    rc.find_file_type_id(data, 0, &mut ctx)
}

#[test]
fn up_file_id_memory() {
    let rc = FileIdentifier::new();
    assert_eq!(rc.memory_usage(), 0);
}

#[test]
fn up_file_id_rule_pdf() {
    let rule = meta("pdf", 1);
    let mut rc = FileIdentifier::new();
    rc.add_file_id(&rule, &mut Sink::new());
    assert_eq!(find_unknown(&mut rc, b"PDF"), SNORT_FILE_TYPE_UNKNOWN);
}

#[test]
fn up_file_id_rule_unknown() {
    let rule = meta("pdf", 1);
    let mut rc = FileIdentifier::new();
    rc.add_file_id(&rule, &mut Sink::new());
    assert_eq!(find_unknown(&mut rc, b"DDF"), SNORT_FILE_TYPE_UNKNOWN);
}

#[test]
fn up_file_id_rule_exe() {
    let mut sink = Sink::new();
    let mut rule = meta("exe", 1);
    let mut rc = FileIdentifier::new();
    rc.add_file_id(&rule, &mut sink);
    rule.clear();
    rule.r#type = "exe".into();
    rule.id = 3;
    rc.add_file_id(&rule, &mut sink);
    assert_eq!(find_unknown(&mut rc, b"PDFooo"), SNORT_FILE_TYPE_UNKNOWN);
}

#[test]
fn up_file_id_rule_pdfexe() {
    let mut sink = Sink::new();
    let mut rule = meta("exe", 1);
    let mut rc = FileIdentifier::new();
    rc.add_file_id(&rule, &mut sink);
    rule.clear();
    rule.r#type = "exe".into();
    rule.id = 3;
    rc.add_file_id(&rule, &mut sink);
    // Match the last one
    assert_eq!(find_unknown(&mut rc, b"PDFEXE"), SNORT_FILE_TYPE_UNKNOWN);
}

#[test]
fn up_file_id_rule_first() {
    let mut sink = Sink::new();
    let mut rule = meta("exe", 1);
    let mut rc = FileIdentifier::new();
    rc.add_file_id(&rule, &mut sink);
    rule.clear();
    rule.r#type = "exe".into();
    rule.id = 3;
    rc.add_file_id(&rule, &mut sink);
    assert_eq!(find_unknown(&mut rc, b"PDF"), SNORT_FILE_TYPE_UNKNOWN);
}
