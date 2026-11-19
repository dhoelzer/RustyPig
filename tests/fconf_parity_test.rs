//! Parity test for `src/file_api/file_config.rs` — row 17u.
//!
//! Ground truth: `tools/fconf_harness/vectors.txt` (20 L, md5
//! 65968e1cc11e9489b89762b6c6f3765e, NEVER edited) — the C transcript
//! of file_config.{h,cc} driven by probe.cc (264 L). The C TU has
//! ZERO TEST_CASEs and ZERO `#ifdef UNIT_TEST` fragments (fconf PLAN
//! §2/§4): every oracle is a labeled probe vector arm (D/N/T/F/G/M/S,
//! PLAN §7), replayed here through the Rust port.
//!
//! One layer only (task gate): `fconf_transcript_replay` runs probe.cc
//! main() (:59-:263) as ONE ordered session — every printf line (all
//! 20, the armed-seam "FileInspect ctor" witness included) pushed at
//! the exact C print position and byte-compared line-for-line against
//! vectors.txt (donor fcshare/fctx/fcap replay shape: want.len() ==
//! 20, per-index assert_eq with the vectors line cite).
//!
//! Drive-shape mapping (probe.cc header): the C session armed the
//! process-wide inspector through stubs — `fcache_set_file_inspector
//! (1)` (probe :65) built the witness FileInspect whose ctor (stubs.cc
//! :425-:430) prints the line-1 witness and wires `config =
//! &g_stub_file_config`; `fconf_set_file_inspector_null(on)`
//! (stubs.cc :371-:376) toggles the inspector pointer with a saved
//! restore (R4 teardown). The port has no process-wide static: the
//! seam is `FileEnvLite::file_config` (file_lib.rs:1115) and `Session`
//! below mirrors the donor arm_inspector/set_inspector_null latch the
//! fctx (fctx_parity_test.rs:770-:776) and fflows (:419-:425) hubs
//! already use: one-shot arm + saved-slot null toggle, silent re-arm.
//!
//! R6 (free-vs-member file_type_name collision): the free arms (F5/F6)
//! resolve through the env seam (`file_api::file_config::file_type_name`,
//! cc:80-:87 with the "NA" null arm cc:85-:86); the member arms (T1-T4)
//! run on stack `FileConfigLite`s and never touch the seam (PLAN §9).

use std::cell::RefCell;
use std::rc::Rc;

use snort3::file_api::file_config::{
    file_type_name, get_file_config, get_magic_rule_ids_from_type,
    set_rule_id_from_type, DEFAULT_FILE_BLOCK_TIMEOUT, DEFAULT_FILE_CAPTURE_BLOCK_SIZE,
    DEFAULT_FILE_CAPTURE_MAX_SIZE, DEFAULT_FILE_CAPTURE_MEM, DEFAULT_FILE_CAPTURE_MIN_SIZE,
    DEFAULT_FILE_LOOKUP_TIMEOUT, DEFAULT_FILE_SIGNATURE_DEPTH, DEFAULT_FILE_SHOW_DATA_DEPTH,
    DEFAULT_FILE_TYPE_DEPTH, DEFAULT_MAX_FILES_CACHED, DEFAULT_MAX_FILES_PER_FLOW, FILE_ID_HELP,
    FILE_ID_NAME,
};
use snort3::file_api::file_identifier::{
    FileIdErrorSink, FileMeta, FILE_ID_MAX, SNORT_FILE_TYPE_CONTINUE, SNORT_FILE_TYPE_UNKNOWN,
};
use snort3::file_api::file_lib::{FileConfigLite, FileEnvLite};

const VECTORS: &str = include_str!("../tools/fconf_harness/vectors.txt");

/// probe :68 — `sizeof(FileConfig)` (the embedded-FileIdentifier blob)
/// has NO ported consumer (file_config.rs LEFT-OPEN note: "a Rust
/// layout pin would re-derive the fid row's internals"): this field is
/// a probe-computed pin compared by DIRECT string parse of the vector
/// line, NEVER by `size_of` on any Rust type (fcshare SIZEOF_*
/// precedent: the port does not fake C layouts).
const PROBE_SIZEOF_FILE_CONFIG: usize = 131360;
/// probe :68 — `sizeof(FileMeta)`: same no-consumer posture as above
/// (probe-computed pin, direct string parse against the vector).
const PROBE_SIZEOF_FILE_META: usize = 128;

/// C global `ParseError` stand-in (file_config.rs:133-:143 keeps its
/// null sink private; the test arms the pub `FileIdErrorSink` trait
/// with the same silent body — no pinned vector routes a duplicate
/// through these arms, so silence is the honest observation).
struct SilentParseError;
impl FileIdErrorSink for SilentParseError {
    fn parse_error(&mut self, _msg: &str) {}
}

/// bitset<FILE_ID_MAX> helpers over the ported word form
/// (`&mut [u64; FILE_ID_MAX / 64]`, file_api.h:118-:119 via the fid
/// row): count == bs.count(), test == bs.test(i) (probe M3/M4).
fn bs_count(bs: &[u64]) -> u32 {
    bs.iter().map(|w| w.count_ones()).sum()
}
fn bs_test(bs: &[u64], id: usize) -> bool {
    (bs[id / 64] >> (id % 64)) & 1 == 1
}

/// The one ordered C session (probe main :59-:263): env seam + the
/// harness FileConfig (stubs `g_stub_file_config`), the output
/// transcript, and the fconf_set_file_inspector_null saved-pointer
/// toggle (stubs.cc :371-:376, R4 teardown).
struct Session {
    env: FileEnvLite,
    harness_conf: Rc<RefCell<FileConfigLite>>,
    saved: Option<Rc<RefCell<FileConfigLite>>>,
    armed: bool,
    out: Vec<String>,
}

impl Session {
    fn new() -> Self {
        Session {
            env: FileEnvLite::default(),
            harness_conf: Rc::new(RefCell::new(FileConfigLite::default())),
            saved: None,
            armed: false,
            out: Vec::with_capacity(20),
        }
    }

    fn push(&mut self, s: String) {
        self.out.push(s);
    }

    /// `fcache_set_file_inspector(1)` (probe :65): one-shot latch; the
    /// witness FileInspect ctor (stubs.cc :425-:430) PRINTS line 1 and
    /// wires config = &g_stub_file_config — the port arms
    /// `env.file_config` with the harness conf at the same instant
    /// (fctx hub arm_inspector :770-:776 donor shape).
    fn arm_inspector(&mut self) {
        if !self.armed {
            self.push("FileInspect ctor".to_string());
            self.env.file_config = Some(self.harness_conf.clone());
            self.armed = true;
        }
    }

    /// `fconf_set_file_inspector_null(on)` (stubs.cc :371-:376): save
    /// /restore, no print either way (R4: re-arm before the next arm
    /// reads the table).
    fn set_inspector_null(&mut self, on: bool) {
        if on {
            self.saved = self.env.file_config.take();
        } else {
            self.env.file_config = self.saved.take();
        }
    }
}

/// probe :67-:69 CONF line. file_id_max rides the ported FILE_ID_MAX
/// const (file_identifier.rs:21 = 1024); the two sizeof fields are
/// probe-computed pins (see PROBE_SIZEOF_* notes — the vector line is
/// additionally parsed verbatim in the replay body).
fn const_line() -> String {
    format!(
        "CONF sizeof_FileConfig={PROBE_SIZEOF_FILE_CONFIG} sizeof_FileMeta={PROBE_SIZEOF_FILE_META} file_id_max={FILE_ID_MAX}"
    )
}

/// probe :72-:87 (D_defaults): every ctor field of a FRESH FileConfig;
/// the hand-written `FileConfigLite::default()` (file_lib.rs:851-:873,
/// the R1 derive-Default trap guard) must answer the §7b table: the 10
/// non-zero in-class initializers + 7 zero arms.
fn arm_d_defaults() -> String {
    let fc = FileConfigLite::default();
    // §7b pins (the 10 non-zero initializers, file_config.h:30-:40 —
    // asserted against the canonical consts in file_config.rs, the
    // numbers the D_defaults line prints):
    assert_eq!(fc.file_type_depth, DEFAULT_FILE_TYPE_DEPTH); // 1460
    assert_eq!(fc.file_signature_depth, DEFAULT_FILE_SIGNATURE_DEPTH); // 10485760
    assert_eq!(fc.file_block_timeout, DEFAULT_FILE_BLOCK_TIMEOUT); // 86400
    assert_eq!(fc.file_lookup_timeout, DEFAULT_FILE_LOOKUP_TIMEOUT); // 2
    assert_eq!(fc.capture_memcap, DEFAULT_FILE_CAPTURE_MEM); // 100 RAW MiB (R2)
    assert_eq!(fc.capture_max_size, DEFAULT_FILE_CAPTURE_MAX_SIZE); // 1048576
    assert_eq!(fc.capture_min_size, DEFAULT_FILE_CAPTURE_MIN_SIZE); // 0
    assert_eq!(fc.capture_block_size, DEFAULT_FILE_CAPTURE_BLOCK_SIZE); // 32768
    assert_eq!(fc.max_files_cached, DEFAULT_MAX_FILES_CACHED); // 65536 (int64)
    assert_eq!(fc.max_files_per_flow, DEFAULT_MAX_FILES_PER_FLOW); // 128 (u64, R2)
    assert_eq!(fc.show_data_depth, DEFAULT_FILE_SHOW_DATA_DEPTH); // 100
    // the 7 zero arms:
    assert!(!fc.block_timeout_lookup && fc.file_depth == 0 && !fc.trace_type
        && !fc.trace_signature && !fc.trace_stream && fc.snort_protocol_id == 0);
    format!(
        "D_defaults ftd={} sig_depth={} blk_to={} lookup={} btl={} cap_mem={} cap_max={} cap_min={} cap_blk={} fdepth={} max_cached={} max_per_flow={} show_depth={} tt={} ts={} tstream={} spid={}",
        fc.file_type_depth,
        fc.file_signature_depth,
        fc.file_block_timeout,
        fc.file_lookup_timeout,
        u8::from(fc.block_timeout_lookup),
        fc.capture_memcap,
        fc.capture_max_size,
        fc.capture_min_size,
        fc.capture_block_size,
        fc.file_depth,
        fc.max_files_cached,
        fc.max_files_per_flow,
        fc.show_data_depth,
        u8::from(fc.trace_type),
        u8::from(fc.trace_signature),
        u8::from(fc.trace_stream),
        fc.snort_protocol_id,
    )
}

/// probe :89-:107 (D_forwarders): the member forwarders on a STACK
/// FileConfig (never the seam). process_file_rule fills
/// file_magic_rules[] ONLY (the fid-harness fact: production never
/// inserts into the trie), so find_file_type_id on the same conf walks
/// an empty trie -> UNKNOWN (65535), *context stays null.
fn arm_d_forwarders() -> String {
    let mut fc2 = FileConfigLite::default();
    let m7 = FileMeta {
        rev: 0,
        id: 7,
        r#type: "exe".to_string(),
        category: "cat".to_string(),
        version: "v1".to_string(),
        groups: vec!["g1".to_string()],
    };
    let mut sink = SilentParseError;
    fc2.process_file_rule(&m7, &mut sink); // cc:48-:51
    let r7 = fc2.get_rule_from_id(7); // cc:53-:56
    let t7: String = r7.map(|m| m.r#type.clone()).unwrap_or_default();
    let rid7: u32 = r7.map(|m| m.id).unwrap_or(0);
    let r13 = fc2.get_rule_from_id(13); // never armed
    let mut ctx: Option<_> = None;
    let f = fc2.find_file_type_id(b"MZx", 0, &mut ctx); // cc:41-:45
    format!(
        "D_forwarders rule_hit={} rule_id={} rule_type={} rule13null={} find_empty_trie={} ctx_null={}",
        u8::from(r7.is_some()),
        rid7,
        t7,
        u8::from(r13.is_none()),
        f,
        u8::from(ctx.is_none()),
    )
}

/// probe :109-:114 (N_names): FILE_ID_NAME / FILE_ID_HELP literals
/// (h:42-:43).
fn arm_n_names() -> String {
    let neq = FILE_ID_NAME == "file_inspect";
    let heq = FILE_ID_HELP == "configure file inspection";
    format!(
        "N_names name={FILE_ID_NAME} name_eq={} help_eq={}",
        u8::from(neq),
        u8::from(heq),
    )
}

/// probe :116-:129 (T1-T4): the MEMBER file_type_name, 4 arms
/// (cc:63-:77), on a stack conf — the seam is never consulted (R6).
fn arm_t1_t4() -> [String; 4] {
    let mut fc3 = FileConfigLite::default();
    let m7 = FileMeta {
        rev: 0,
        id: 7,
        r#type: "exe".to_string(),
        category: "cat".to_string(),
        version: "v1".to_string(),
        groups: vec!["g1".to_string()],
    };
    let mut sink = SilentParseError;
    fc3.process_file_rule(&m7, &mut sink);
    let t1 = fc3.file_type_name(SNORT_FILE_TYPE_UNKNOWN); // 65535 (cc:66-:67)
    let t2 = fc3.file_type_name(SNORT_FILE_TYPE_CONTINUE); // 0     (cc:69-:70)
    let t3 = fc3.file_type_name(7); // table hit (cc:72-:75)
    let t4 = fc3.file_type_name(999); // miss -> "" (cc:77)
    [
        format!("T1_unknown id={SNORT_FILE_TYPE_UNKNOWN} s={t1}"),
        format!("T2_continue id={SNORT_FILE_TYPE_CONTINUE} s={t2}"),
        format!("T3_hit id=7 s={t3}"),
        format!("T4_miss id=999 s_empty={}", u8::from(t4.is_empty())),
    ]
}

/// probe :131-:146 (F5): the free-function seam (cc:80-:87) on the
/// ARMED inspector -> get_file_config() -> the harness conf; the id-7
/// entry is armed THROUGH THE SEAM table (hc->process_file_rule), the
/// F5 answer feeds M3's "exe"/"v1" row.
fn arm_f5(s: &mut Session) -> String {
    let hc = get_file_config(&s.env); // armed seam state (cc:89-:100)
    let seam_nonnull = hc.clone().is_some();
    if let Some(conf) = hc {
        let m7 = FileMeta {
            rev: 0,
            id: 7,
            r#type: "exe".to_string(),
            category: "cat".to_string(),
            version: "v1".to_string(),
            groups: vec!["g1".to_string()],
        };
        let mut sink = SilentParseError;
        conf.borrow_mut().process_file_rule(&m7, &mut sink);
    }
    let f5 = file_type_name(&s.env, 7); // cc:82-:84 member path
    format!(
        "F5_free_resolved seam_nonnull={} name=exe eq={}",
        u8::from(seam_nonnull),
        u8::from(f5 == "exe"),
    )
}

/// probe :148-:163 (F6 + G3): ONE null-inspector scope. free name ->
/// "NA" (cc:85-:86); get_file_config BOTH C call shapes -> null
/// (cc:98-:99). Deviation cite (file_config.rs:117-:131): the Rust
/// seam has no `sc` parameter — `get_file_config(&sc)` and
/// `get_file_config()` collapse to ONE seam lookup answering `None`
/// for both arms, which is exactly what G3 pins. Then the R4 teardown
/// re-arm, witnessed.
fn arm_f6_g3(s: &mut Session) -> [String; 2] {
    s.set_inspector_null(true);
    let f6 = file_type_name(&s.env, 7); // "NA" arm (cc:86)
    let g3a = get_file_config(&s.env); // no-arg arm (cc:91-:92)
    let g3b = get_file_config(&s.env); // explicit-sc arm (cc:94) — same seam
    let null_a = g3a.is_none();
    let null_b = g3b.is_none();
    s.set_inspector_null(false); // R4 teardown: re-arm
    [
        format!(
            "F6_free_null s=NA eq_na={}",
            u8::from(f6 == "NA"),
        ),
        format!(
            "G3_null_arm conf_null_noarg={} conf_null_sc={} rearmed={}",
            u8::from(null_a),
            u8::from(null_b),
            u8::from(get_file_config(&s.env).is_some()),
        ),
    ]
}

/// probe :165-:174 (G1 + G2): get_file_config with the seam ARMED —
/// both C call shapes resolve to the harness conf (cc:94 cast /
/// get_conf() default). Deviation cite as above: one seam answers both
/// shapes; the two arms stay two separate lines at the pinned
/// positions. is_harness_conf == Rc::ptr_eq with `get_harness_file_
/// config()` (stubs.cc :439).
fn arm_g1_g2(s: &mut Session) -> [String; 2] {
    let c1 = get_file_config(&s.env).expect("G1 armed seam");
    let c2 = get_file_config(&s.env).expect("G2 armed seam");
    let same1 = Rc::ptr_eq(&c1, &s.harness_conf);
    let same2 = Rc::ptr_eq(&c2, &s.harness_conf);
    [
        format!(
            "G1_explicit_sc nonnull=1 is_harness_conf={}",
            u8::from(same1),
        ),
        format!(
            "G2_null_sc_default nonnull=1 is_harness_conf={}",
            u8::from(same2),
        ),
    ]
}

/// probe :176-:226 (M1-M4): the snort-namespace API shims
/// (cc:104-:127) against the ONE seam table.
fn arm_m1(s: &mut Session) -> String {
    set_rule_id_from_type(
        &s.env,
        12,
        "pdf".to_string(),
        "cat".to_string(),
        "v".to_string(),
        vec!["g".to_string()],
    );
    let hc = get_file_config(&s.env).expect("armed seam");
    let hc_ref = hc.borrow();
    let r12 = hc_ref.get_rule_from_id(12);
    let n12 = file_type_name(&s.env, 12); // free path through the seam
    let ng = r12.map(|m| m.groups.len()).unwrap_or(0);
    let g0 = r12
        .filter(|_| ng > 0)
        .map(|m| m.groups[0].clone())
        .unwrap_or_default();
    format!(
        "M1_set_rule rule12_hit={} name12=pdf name_eq={} groups={ng} g0={g0}",
        u8::from(r12.is_some()),
        u8::from(n12 == "pdf"),
    )
}

/// M2 (probe :192-:199): the null-conf arm is a SILENT NO-OP (cc:122
/// guard) — WITNESS-FREE in C (no line between the toggles); the
/// table stays empty at id 13 after the re-arm.
fn arm_m2(s: &mut Session) -> String {
    s.set_inspector_null(true);
    set_rule_id_from_type(
        &s.env,
        13,
        "zip".to_string(),
        "cat".to_string(),
        "v".to_string(),
        Vec::new(),
    );
    s.set_inspector_null(false);
    let hc = get_file_config(&s.env).expect("rearmed");
    let hc_ref = hc.borrow();
    let r13 = hc_ref.get_rule_from_id(13);
    format!(
        "M2_set_rule_null silent_noop={} rule13null={}",
        u8::from(r13.is_none()),
        u8::from(r13.is_none()),
    )
}

/// M3 (probe :201-:212): the F5-armed seam table (id 7 "exe" version
/// "v1"). version "" -> tmp empty -> match-ANY; version "v1" -> tmp
/// "\"v1\"" != stored unquoted "v1" -> miss (version-quoting pinned by
/// the fid harness MEXE17 arm).
fn arm_m3(s: &mut Session) -> String {
    let mut bs = [0u64; FILE_ID_MAX / 64];
    get_magic_rule_ids_from_type(&s.env, "exe", "", &mut bs);
    let c_a = bs_count(&bs);
    let b7_a = bs_test(&bs, 7);
    get_magic_rule_ids_from_type(&s.env, "exe", "v1", &mut bs);
    let c_q = bs_count(&bs);
    format!(
        "M3_magic_ids any_ver_count={c_a} id7={} quoted_miss_count={c_q}",
        u8::from(b7_a),
    )
}

/// M4 (probe :214-:225): the null-conf arm -> ids_set.reset()
/// (cc:112) on observable sentinel bits (bitset<1024>, file_api.h:119
/// — bits 0/7/1023).
fn arm_m4(s: &mut Session) -> String {
    let mut bs2 = [0u64; FILE_ID_MAX / 64];
    bs2[0] |= 1u64 << 0;
    bs2[0] |= 1u64 << 7;
    bs2[FILE_ID_MAX / 64 - 1] |= 1u64 << (1023 % 64);
    let pre = bs_count(&bs2);
    let (p0, p7, p1023) = (
        u8::from(bs_test(&bs2, 0)),
        u8::from(bs_test(&bs2, 7)),
        u8::from(bs_test(&bs2, 1023)),
    );
    s.set_inspector_null(true);
    get_magic_rule_ids_from_type(&s.env, "exe", "1.7", &mut bs2); // cc:112 reset
    s.set_inspector_null(false);
    let post = bs_count(&bs2);
    let q0 = u8::from(bs_test(&bs2, 0));
    let q7 = u8::from(bs_test(&bs2, 7));
    let q1023 = u8::from(bs_test(&bs2, 1023));
    format!(
        "M4_magic_reset pre_count={pre} pre={p0}{p7}{p1023} post_count={post} post={q0}{q7}{q1023} rearmed={}",
        u8::from(get_file_config(&s.env).is_some()),
    )
}

/// probe :228-:260 (S1): the 15 file_module.cc:200-:242 load_config
/// setter targets on a FRESH conf — every value differs from
/// D_defaults; `file_depth` + `snort_protocol_id` are NEVER set by
/// load_config (PLAN §6) and stay 0.
fn arm_s1() -> String {
    // struct-update form of the 15 sequential setters (clippy-clean;
    // observationally identical: fresh Default conf + each load_config
    // target, file_depth/spid never assigned -> stay the Default 0s).
    let fc = FileConfigLite {
        file_type_depth: 2000,
        file_signature_depth: 20_971_520,
        file_block_timeout: 172_800,
        file_lookup_timeout: 4,
        block_timeout_lookup: true,
        capture_memcap: 250,
        capture_max_size: 2_097_152,
        capture_min_size: 4_096,
        capture_block_size: 65_536,
        max_files_cached: 131_072,
        max_files_per_flow: 256,
        show_data_depth: 200,
        trace_type: true,
        trace_signature: true,
        trace_stream: true,
        ..FileConfigLite::default()
    };
    let mutated = fc.file_type_depth == 2000
        && fc.file_signature_depth == 20_971_520
        && fc.file_block_timeout == 172_800
        && fc.file_lookup_timeout == 4
        && fc.block_timeout_lookup
        && fc.capture_memcap == 250
        && fc.capture_max_size == 2_097_152
        && fc.capture_min_size == 4_096
        && fc.capture_block_size == 65_536
        && fc.max_files_cached == 131_072
        && fc.max_files_per_flow == 256
        && fc.show_data_depth == 200
        && fc.trace_type
        && fc.trace_signature
        && fc.trace_stream;
    format!(
        "S1_load_config_setters ftd={} sig={} blk={} lut={} btl={} cm={} cms={} cmin={} cbs={} mfc={} mpf={} sdd={} tt={} tsig={} tst={} all_mutated={} fdepth_untouched={} spid_untouched={}",
        fc.file_type_depth,
        fc.file_signature_depth,
        fc.file_block_timeout,
        fc.file_lookup_timeout,
        u8::from(fc.block_timeout_lookup),
        fc.capture_memcap,
        fc.capture_max_size,
        fc.capture_min_size,
        fc.capture_block_size,
        fc.max_files_cached,
        fc.max_files_per_flow,
        fc.show_data_depth,
        u8::from(fc.trace_type),
        u8::from(fc.trace_signature),
        u8::from(fc.trace_stream),
        u8::from(mutated),
        u8::from(fc.file_depth == 0),
        u8::from(fc.snort_protocol_id == 0),
    )
}

// -------------------------------------------------------------------
// The whole-transcript loop (row 17u): probe.cc main() (:59-:263) as
// ONE ordered session — every printf line pushed at its exact C
// print position (line 1 = the armed-seam "FileInspect ctor" witness,
// stubs.cc :427) and compared against vectors.txt at every index
// (donor fcap/fctx/fcshare replay shape: want.len() == 20, per-index
// assert_eq with the vectors line cite).
// -------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn fconf_transcript_replay() {
    let mut s = Session::new();

    // probe :65 — fcache_set_file_inspector(1): the witness FileInspect
    // ctor prints vectors line 1 and wires the harness conf.
    s.arm_inspector();

    // CONF (:67-:69) — the two probe-computed sizeof pins are ALSO
    // verified by direct string parse of the vector line (no ported
    // consumer, file_config.rs LEFT-OPEN note; NEVER size_of):
    let want: Vec<&str> = VECTORS.trim_end_matches('\n').lines().collect();
    assert_eq!(want.len(), 20, "vectors.txt must hold exactly 20 lines");
    {
        let mut fields = want[1].split_whitespace();
        assert_eq!(
            fields.next(),
            Some("CONF"),
            "vectors.txt line 2 label (probe-computed pin cite)"
        );
        assert_eq!(
            fields.next(),
            Some(format!("sizeof_FileConfig={PROBE_SIZEOF_FILE_CONFIG}").as_str()),
            "vectors.txt line 2 sizeof_FileConfig (probe-computed pin, no ported consumer)"
        );
        assert_eq!(
            fields.next(),
            Some(format!("sizeof_FileMeta={PROBE_SIZEOF_FILE_META}").as_str()),
            "vectors.txt line 2 sizeof_FileMeta (probe-computed pin, no ported consumer)"
        );
        assert_eq!(
            fields.next(),
            Some(format!("file_id_max={FILE_ID_MAX}").as_str()),
            "vectors.txt line 2 file_id_max == ported FILE_ID_MAX (file_identifier.rs:21)"
        );
    }
    s.push(const_line());

    // D_defaults (:72-:87)
    let line = arm_d_defaults();
    assert_eq!(line, want[2], "vectors.txt line 3 (D_defaults §7b pins)");
    s.push(line);

    // D_forwarders (:89-:107)
    s.push(arm_d_forwarders());

    // N_names (:109-:114)
    s.push(arm_n_names());

    // T1-T4 (:116-:129)
    for line in arm_t1_t4() {
        s.push(line);
    }

    // F5 (:131-:146)
    let line = arm_f5(&mut s);
    assert_eq!(line, want[9], "vectors.txt line 10 (F5 free-resolved)");
    s.push(line);

    // F6 + G3 (:148-:163)
    for line in arm_f6_g3(&mut s) {
        s.push(line);
    }

    // G1 + G2 (:165-:174)
    for line in arm_g1_g2(&mut s) {
        s.push(line);
    }

    // M1-M4 (:176-:226) — one seam table, arms sequenced exactly as
    // probe main() runs them (M2/M4 toggle null and re-arm inside).
    let line = arm_m1(&mut s);
    assert_eq!(line, want[14], "vectors.txt line 15 (M1_set_rule)");
    s.push(line);
    let line = arm_m2(&mut s);
    assert_eq!(line, want[15], "vectors.txt line 16 (M2_set_rule_null)");
    s.push(line);
    let line = arm_m3(&mut s);
    assert_eq!(line, want[16], "vectors.txt line 17 (M3_magic_ids)");
    s.push(line);
    let line = arm_m4(&mut s);
    assert_eq!(line, want[17], "vectors.txt line 18 (M4_magic_reset)");
    s.push(line);

    // S1 (:228-:260)
    let line = arm_s1();
    assert_eq!(line, want[18], "vectors.txt line 19 (S1_load_config_setters)");
    s.push(line);

    s.push("FCONF_PROBE_DONE".to_string()); // :262

    // ---- the line-for-line compare (donor fcap/fcshare :1042-:1055) ----
    if std::env::var("FCONF_DUMP").is_ok() {
        let _ = std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../cache/scratch/fconf_got.txt"),
            s.out.join("\n") + "\n",
        );
    }
    assert_eq!(s.out.len(), want.len(), "replay emitted {} lines", s.out.len());
    for (i, (g, w)) in s.out.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors.txt line {}", i + 1);
    }
}
