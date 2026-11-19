//! Parity test for `src/file_api/file_policy.rs` — row 17x.
//!
//! Ground truth: `tools/fpolicy_harness/vectors.txt` (27 L, md5
//! b989a8d5cddaf0a2289f5528121ddf35, NEVER edited) — the C transcript
//! of file_policy.{h,cc} driven by probe.cc (V1..V10 + V-ref arms; the
//! TU has ZERO TEST_CASEs and ZERO `#ifdef UNIT_TEST` fragments —
//! fpolicy PLAN §2: probe vectors are the only oracles), replayed here
//! as ONE ordered session (finspect/fconf replay shape: per-index
//! assert_eq against the vectors line, want.len() == 27).
//!
//! The REAL ported ladder runs end to end here: `FilePolicy::new` +
//! the flag pairs (V2), `add_file_id` (V3/V5/V8/V9: sha table + the
//! cc:103-:104 UNCONDITIONAL type_enabled quirk + the conditional
//! signature/capture arms riding the real file_service.cc:199-:204
//! enable-capture CASCADE through FileServiceLite::enable_file_capture,
//! file_lib.rs:1005-:1008), `load()` (V4: the OR-arm quirk + the
//! capture-only DEF/SVC drift pin `def t=0 s=0 c=1 svc t=0 s=1 c=1`),
//! `match_file_rule` (V5: sha'd skip, first-match, wildcard,
//! default_rule fallback), the `match_file_signature` delay ladder
//! (V6: cc:157-:160 PER-CALL decrement, PENDING x2 -> LOG,
//! `left=0` FIXACC readback), `policy_check` (V7: the trio write +
//! the cc:176 single-policy set_policy_id(0) quirk), `type_lookup`
//! (V8: the cc:182-:183 FileInfo re-arm pin), the `signature_lookup`
//! capture ladder (V9: reserve-FAIL arm, the reserve-SUCCESS +
//! trait-default `store_file_async -> ""` empty-name arm — cc:199-:202
//! size=0, hand-off + `config_file_capture(false)` re-arm readbacks,
//! and the FILE_SIG_DEPTH_FAIL -> LOG arm cc:210-:212), and the REAL
//! ref protocol (V-ref: add_ref 1->2, delete 2->1, final drain 1->0 —
//! the R1 heap-only posture, ~FilePolicyBase assert(!ref_count),
//! file_api.cc:31-:32).
//!
//! V1 layout pin: `base=16 rule=48 policy=152` are the PROBE-PINNED
//! literals from vectors.txt:1 / probe.cc:71-:73, carried as the
//! `C_SIZEOF_*` consts (file_policy.rs:52-:54) — NEVER a Rust
//! `size_of` on a ported type (file_cache_share.rs:69 rule; base=16
//! was already frozen as the 17v fapi `fpolbase=16` pin,
//! fapi_parity_test.rs:79). `refs=1` is the LIVE handle read
//! (FilePolicyHandle::new_boxed ctor posture, file_api.cc:28-:29).
//!
//! Witness posture (R5 KEEP): the donor StubFilePolicy (stubs.cc:
//! 360-:370) is KEPT — V10 drives the Rust PolicyStub twin (the
//! fflows/fctx twins' shape) over the SAME FilePolicyHandle seam, and
//! the vectors' FOUR V10 POLICY lines decompose exactly: lines 21-22
//! are the stub's OWN internal prints (stubs.cc:364 "POLICY
//! type_lookup -> %d" / :366 "POLICY signature_lookup -> %d", byte-
//! VERBATIM) reached through `with_policy_mut`, lines 23-24 are the
//! probe's own printf mirrors. The real-body POLICY lines (V6/V8/V9)
//! carry NO internal print — file_policy.cc prints nothing — only the
//! probe printf mirrors ride (stubs.cc formats, %d -> decimal).
//!
//! V1 composition deviation (pinned here): the C `fp =
//! static_cast<FilePolicy*>(pol)` alias splits in Rust into the owned
//! body `fp` (member calls, C non-virtual setters/getters) and the
//! `pol` handle fronting the same ctor posture (the seam + ref
//! ladder); NO vector line observes the alias — V10's `same=0` is the
//! stub-vs-real identity pin (R5: different objects) and V_ref reads
//! only the counters, both answered by the handle.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use snort3::file_api::file_api::{
    FILE_CAPTURE_SUCCESS, FILE_SIG_DEPTH_FAIL, FILE_VERDICT_BLOCK,
    FILE_VERDICT_LOG, FILE_VERDICT_PENDING, FILE_VERDICT_REJECT, FILE_VERDICT_STOP,
    FilePolicyApi,
    FilePolicyHandle,
};
use snort3::file_api::file_cache::{CacheFlow, PacketView};
use snort3::file_api::file_lib::{FileCaptureApi, FileContext, FileEnvLite, FileInfo};
use snort3::file_api::file_policy::{
    C_SIZEOF_FILE_POLICY, C_SIZEOF_FILE_POLICY_BASE, C_SIZEOF_FILE_RULE, FilePolicy,
    FileRule,
};

const VECTORS: &str = include_str!("../tools/fpolicy_harness/vectors.txt");

/// probe.cc:52 HEX32 — raw 32 bytes 01..20 as the hex the REAL
/// cc:92-:97 stoi loop decodes (PLAN R7: vectors never arm junk hex).
const HEX32: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

type Out = Rc<RefCell<Vec<String>>>;

fn push(out: &Out, line: impl Into<String>) {
    out.borrow_mut().push(line.into());
}

/// `fcache_set_file_service(int on)` witness body VERBATIM
/// (fpolicy stubs.cc:735-:743): sets the TYPE static; the off arm
/// clears signature AND capture. All probe arms call it with 0.
fn wit_set_file_service(env: &mut FileEnvLite, on: bool) {
    env.svc.set_file_type_enabled(on); // stubs.cc:737
    if !on {
        // stubs.cc:738-:742
        env.svc.set_file_signature_enabled(false);
        env.svc.set_file_capture_enabled(false);
    }
}

/// probe.cc:58-:64 arm_sha — the REAL file_lib FileInfo::sha256 write
/// (digest bytes 01..20 == the cc:99 table key of HEX32).
fn digest_01_20() -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = (i + 1) as u8; // probe.cc:62 `(uint8_t)(i + 1)`
    }
    d
}

fn arm_sha(info: &mut FileInfo) {
    info.sha256 = Some(digest_01_20()); // file_lib.h:129 member (FIXACC)
    info.is_sha256_set = true; // file_lib.cc:570-:572 posture
}

/// V9b witness capture (the C arm pairs `new FileCapture(10, 1000)`
/// over an inited mempool, probe.cc:284-:285): reserve_file answers
/// the FILE_CAPTURE_SUCCESS arm (fb.file_size 100 in [10, 1000]).
/// `store_file_async` is deliberately NOT overridden — the trait
/// DEFAULT `-> ""` (file_lib.rs:105-:107, added row 17x) is exactly
/// the cc:197 -> cc:199 EMPTY-name arm the C REAL body reaches there
/// (the copy's sha256 is null, file_lib.cc:570-:572, so the name is
/// ""). Sizes mirror the C args; the 100 landing at extracted_size
/// (file_lib.rs:663) is overwritten by the cc:201 set_extracted_size(0).
struct WitCap;
impl FileCaptureApi for WitCap {
    fn reserve_file(&mut self, _file: &FileInfo) -> u32 {
        FILE_CAPTURE_SUCCESS // file_capture.cc:422-:443 success arm
    }
    fn get_file_capture_size(&self) -> i64 {
        100 // C min/max (10, 1000) in-range readout (invisible: cc:201 wins)
    }
    fn get_max_file_capture_size(&self) -> i64 {
        1000
    }
    fn set_data(&mut self, _file_data: &[u8], _size: u32) {}
}

/// The donor StubFilePolicy twin (stubs.cc:360-:370; fflows_parity_
/// test.rs:144-:170 / fctx shape KEPT per R5): probe-armed verdicts
/// ride Cells (fcache_set_policy_verdicts, stubs.cc:380-:387), and
/// the reached virtuals print the stub formats BYTE-VERBATIM
/// (stubs.cc:364/:366).
struct PolicyStub {
    out: Out,
    tv: Rc<Cell<u32>>,
    sv: Rc<Cell<u32>>,
}
impl FilePolicyApi for PolicyStub {
    fn type_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        let v = self.tv.get();
        push(&self.out, format!("POLICY type_lookup -> {v}")); // stubs.cc:364
        v
    }
    fn signature_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 {
        let v = self.sv.get();
        push(&self.out, format!("POLICY signature_lookup -> {v}")); // stubs.cc:366
        v
    }
    // stubs.cc:362 policy_check / :368 log_file_action kept as the
    // trait arms: UNREACHED in this probe (V10 only calls the lookup
    // pair); policy_check rides the trait default (the C base no-op —
    // the stub's print is un-pinabsent here), log_file_action is the
    // required item, empty twin.
    fn log_file_action(&mut self, _flow: &CacheFlow, _file: &mut FileContext, _action: u32) {}
}

/// The whole probe main() as one ordered session (probe.cc:66-:336).
#[test]
#[allow(clippy::too_many_lines)]
fn fpolicy_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 27, "vectors.txt must stay the 27-line oracle");
    let out: Out = Rc::new(RefCell::new(Vec::new()));
    let mut env = FileEnvLite::default();
    let mut pkt = PacketView::default(); // the dead `nullptr` Packet arg
    let flow = CacheFlow::default(); // the dead `nullptr` Flow arg

    // ---- V1 (probe.cc:67-:74): the layout pin + the heap ctor ref
    // posture. `C new FilePolicy` -> FilePolicyHandle::new_boxed
    // (ref_count = 1, file_api.cc:28-:29). Sizes are the probe-pinned
    // literals (vectors:1 / file_policy.rs:52-:54), NEVER size_of. ----
    let mut pol = FilePolicyHandle::new_boxed(Box::new(FilePolicy::new()));
    let mut fp = FilePolicy::new(); // cc:44 default member init (h:88-:91)
    push(
        &out,
        format!(
            "V1_size base={} rule={} policy={} refs={}",
            C_SIZEOF_FILE_POLICY_BASE, // 16 (the 17v fapi fpolbase twin)
            C_SIZEOF_FILE_RULE,        // 48 — this vectors line is its home
            C_SIZEOF_FILE_POLICY,      // 152 — ditto
            pol.ref_count(),           // pol->ref_count == 1 (ctor SETS 1)
        ),
    ); // line 1

    // ---- V2 (probe.cc:79-:96): FileRule ctor/clear readback + the
    // flag pairs. Pin: getters are MEMBER-only — the svc trio stays
    // 0 THROUGH the setters while the members read 1/1/0. ----
    wit_set_file_service(&mut env, false); // fcache_set_file_service(0)
    let r = FileRule::new(); // cc:44-:47 -> clear cc:34-:42
    push(
        &out,
        format!(
            "V2_rule tid={} shaempty={} verdict={} t={} s={} c={}",
            r.when.type_id, // :36 -> 0
            u8::from(r.when.sha256.is_empty()), // :37 -> 1
            r.r#use.verdict,                    // :41 UNKNOWN -> 0
            u8::from(r.r#use.type_enabled),     // :40 -> 0
            u8::from(r.r#use.signature_enabled), // :39 -> 0
            u8::from(r.r#use.capture_enabled), // :38 -> 0
        ),
    ); // line 2
    fp.set_file_type(true); // cc:49-:52
    fp.set_file_signature(true); // cc:54-:57
    fp.set_file_capture(false); // cc:59-:62
    push(
        &out,
        format!(
            "V2_getters t={} s={} c={} svc t={} s={} c={}",
            u8::from(fp.get_file_type()), // cc:64-:67 member-only
            u8::from(fp.get_file_signature()), // cc:70-:73
            u8::from(fp.get_file_capture()), // cc:76-:79
            u8::from(env.svc.is_file_type_id_enabled()), // trio stays 0
            u8::from(env.svc.is_file_signature_enabled()),
            u8::from(env.svc.is_file_capture_enabled()),
        ),
    ); // line 3

    // ---- V3 (probe.cc:101-:120): add_file_id — sha decode into the
    // TABLE (cc:85-:100) + the UNCONDITIONAL enable_file_type + the
    // type_enabled QUIRK (cc:103-:104) + the conditional signature
    // arm (cc:106-:107); capture use-flag OFF -> no cascade arm. ----
    wit_set_file_service(&mut env, false);
    {
        let mut p3 = FilePolicy::new();
        let mut r3 = FileRule::new();
        r3.when.sha256 = HEX32.to_string();
        r3.r#use.verdict = FILE_VERDICT_LOG;
        r3.r#use.signature_enabled = true;
        p3.add_file_id(&r3, &mut env.svc); // cc:81
        push(
            &out,
            format!(
                "V3_add rules={} shas={} type_enabled={} svc t={} s={} c={}",
                p3.file_rules.len(), // FIXACC h:85 -> 1
                p3.file_shas.len(),  // FIXACC h:86 -> 1 (hex->32 raw bytes)
                u8::from(p3.get_file_type()), // cc:104 QUIRK -> 1
                u8::from(env.svc.is_file_type_id_enabled()), // cc:103 -> 1
                u8::from(env.svc.is_file_signature_enabled()), // cc:107 -> 1
                u8::from(env.svc.is_file_capture_enabled()), // cc:109 OFF -> 0
            ),
        ); // line 4
        drop(p3); // delete_file_policy drain (R1; defaulted dtor prints NOTHING — nm-measured, R3)
    }

    // ---- V4 (probe.cc:125-:150): load(). a) capture-only: the
    // cc:115 OR-arm stays FALSE -> the type static is NOT lit; the
    // REAL enable_file_capture CASCADE (file_service.cc:199-:204,
    // fpolicy stubs.cc:602, Rust twin file_lib.rs:1005-:1008) lights
    // the signature STATIC anyway -> member s=0 vs svc s=1 DRIFT PIN.
    // b) signature-only: the OR-arm fires -> type lit both sides. ----
    wit_set_file_service(&mut env, false);
    {
        let mut p4 = FilePolicy::new();
        p4.set_file_capture(true);
        p4.load(&mut env.svc); // cc:113
        push(
            &out,
            format!(
                "V4_load_cap def t={} s={} c={} svc t={} s={} c={}",
                u8::from(p4.default_rule.r#use.type_enabled), // cc:127 -> 0
                u8::from(p4.default_rule.r#use.signature_enabled), // cc:128 -> 0
                u8::from(p4.default_rule.r#use.capture_enabled), // cc:129 -> 1
                u8::from(env.svc.is_file_type_id_enabled()), // -> 0
                u8::from(env.svc.is_file_signature_enabled()), // CASCADE -> 1
                u8::from(env.svc.is_file_capture_enabled()), // -> 1
            ),
        ); // line 5
        let mut p5 = FilePolicy::new();
        p5.set_file_signature(true);
        p5.load(&mut env.svc);
        push(
            &out,
            format!(
                "V4_load_sig def t={} s={} c={}",
                u8::from(p5.default_rule.r#use.type_enabled), // cc:117 OR-arm -> 1
                u8::from(p5.default_rule.r#use.signature_enabled), // -> 1
                u8::from(p5.default_rule.r#use.capture_enabled), // -> 0
            ),
        ); // line 6
        drop(p4);
        drop(p5); // delete_file_policy drains (R1)
    }

    // ---- V5 (probe.cc:155-:190): match_file_rule — sha'd rule
    // SKIPPED (cc:136-:137), type match returns FIRST (cc:139-:140),
    // wildcard type_id==0 catches, else default_rule (cc:144). C
    // address reads ride Rust ptr identity (file_policy.rs:381-:386
    // same_default posture). ----
    {
        let mut p6 = FilePolicy::new();
        let mut r0 = FileRule::new(); // type 7 -> STOP
        r0.when.type_id = 7;
        r0.r#use.verdict = FILE_VERDICT_STOP;
        let mut r1 = FileRule::new(); // sha'd -> skipped
        r1.when.sha256 = "ab".to_string();
        r1.when.type_id = 7;
        r1.r#use.verdict = FILE_VERDICT_BLOCK;
        let mut r2 = FileRule::new(); // wildcard -> REJECT
        r2.r#use.verdict = FILE_VERDICT_REJECT;
        p6.add_file_id(&r0, &mut env.svc);
        p6.add_file_id(&r1, &mut env.svc);
        p6.add_file_id(&r2, &mut env.svc);
        let mut f7 = FileInfo::default(); // f7.set_file_type(7)
        f7.set_file_type(7);
        let mut f9 = FileInfo::default();
        f9.set_file_type(9);
        let m7 = p6.match_file_rule(&f7); // cc:132
        let m9 = p6.match_file_rule(&f9);
        push(
            &out,
            format!(
                "V5_match typed={} wildcard={} first_rule={} def={}",
                m7.r#use.verdict, // 2 STOP
                m9.r#use.verdict, // 4 REJECT (wildcard)
                u8::from(std::ptr::eq(m7, &p6.file_rules[0])), // C &m7 == &file_rules[0]
                u8::from(std::ptr::eq(m9, &p6.default_rule)), // -> 0 (r2 wins)
            ),
        ); // line 7
        let mut p7 = FilePolicy::new(); // all-sha'd -> default_rule arm
        let mut r3 = FileRule::new();
        r3.when.sha256 = "ab".to_string();
        r3.r#use.verdict = FILE_VERDICT_BLOCK;
        p7.add_file_id(&r3, &mut env.svc);
        let md = p7.match_file_rule(&f7);
        assert!(p7.same_default(md)); // &md == &default_rule (C address)
        push(
            &out,
            format!(
                "V5_def v={} is_default={}",
                md.r#use.verdict, // default UNKNOWN -> 0
                u8::from(p7.same_default(md)), // -> 1
            ),
        ); // line 8
        drop(p6);
        drop(p7); // deletes (R1 drain posture)
    }

    // ---- V6 (probe.cc:195-:221): signature_lookup through the seam
    // with rule capture OFF (straight to the cc:215 match) + the
    // verdict_delay PENDING ladder: set 2 -> PENDING, PENDING (per-
    // CALL decrement cc:157-:160) -> table LOG; the FIXACC `left=0`
    // read lands BEFORE the xored-key MISS -> UNKNOWN (cc:167). ----
    wit_set_file_service(&mut env, false);
    {
        let mut p8 = FilePolicy::new();
        let mut r8 = FileRule::new();
        r8.when.sha256 = HEX32.to_string();
        r8.r#use.verdict = FILE_VERDICT_LOG;
        p8.add_file_id(&r8, &mut env.svc);
        p8.set_verdict_delay(2); // h:80 inline write
        let f0 = FileContext::ctor(None, &env); // FileInfo fn: sha null
        let v0 = FilePolicyApi::signature_lookup(&mut p8, &mut pkt, &mut f0.borrow_mut());
        push(&out, format!("POLICY signature_lookup -> {v0}")); // probe.cc:207 -> 0
        let fh = FileContext::ctor(None, &env);
        arm_sha(&mut fh.borrow_mut().info); // fh: key HIT cc:152
        let v1 = FilePolicyApi::signature_lookup(&mut p8, &mut pkt, &mut fh.borrow_mut());
        push(&out, format!("POLICY signature_lookup -> {v1}")); // :212 PENDING 5
        let v2 = FilePolicyApi::signature_lookup(&mut p8, &mut pkt, &mut fh.borrow_mut());
        push(&out, format!("POLICY signature_lookup -> {v2}")); // :213 PENDING 5
        let v3 = FilePolicyApi::signature_lookup(&mut p8, &mut pkt, &mut fh.borrow_mut());
        push(&out, format!("POLICY signature_lookup -> {v3}")); // :214 LOG 1
        let left = p8.verdict_delay; // FIXACC h:91 read BEFORE the miss
        let fm = FileContext::ctor(None, &env);
        {
            let mut info = fm.borrow_mut();
            arm_sha(&mut info.info);
            info.info.sha256.as_mut().unwrap()[0] ^= 0xFF; // fm.sha256[0] ^= 0xFF
        }
        let v4 = FilePolicyApi::signature_lookup(&mut p8, &mut pkt, &mut fm.borrow_mut());
        push(
            &out,
            format!("V6_delay left={} miss={}", left, v4), // :219 -> 0 / 0
        ); // line 13
        drop(p8); // delete (R1)
    }

    // ---- V7 (probe.cc:226-:234): policy_check — the trio write from
    // the POLICY members (cc:173-:175: t=1 s=0 c=1) + the single
    // policy set_policy_id(0) QUIRK (cc:176 -> pid=0). Void body:
    // NO POLICY print rides. ----
    {
        let mut p9 = FilePolicy::new();
        p9.set_file_type(true);
        p9.set_file_capture(true);
        let f = FileContext::ctor(None, &env); // FileInfo f
        FilePolicyApi::policy_check(&mut p9, &flow, &mut f.borrow_mut()); // cc:170
        push(
            &out,
            format!(
                "V7_pcheck f t={} s={} c={} pid={}",
                u8::from(f.borrow().info.file_type_enabled), // 1
                u8::from(f.borrow().info.file_signature_enabled), // 0
                u8::from(f.borrow().info.file_capture_enabled), // 1
                f.borrow().info.get_policy_id(), // cc:176 quirk -> 0
            ),
        ); // line 14
        drop(p9); // delete (R1)
    }

    // ---- V8 (probe.cc:239-:253): type_lookup through the base seam
    // — match (type 7 STOP) + the cc:182-:183 FileInfo RE-ARM from
    // the matched rule (s=1 c=1) + the rule verdict through the
    // byte-VERBATIM stub format printf (probe.cc:249). ----
    {
        let mut pa = FilePolicy::new();
        let mut ra = FileRule::new();
        ra.when.type_id = 7;
        ra.r#use.verdict = FILE_VERDICT_STOP;
        ra.r#use.signature_enabled = true;
        ra.r#use.capture_enabled = true;
        pa.add_file_id(&ra, &mut env.svc);
        let f = FileContext::ctor(None, &env);
        f.borrow_mut().info.set_file_type(7);
        let v = FilePolicyApi::type_lookup(&mut pa, &mut pkt, &mut f.borrow_mut()); // cc:179
        push(&out, format!("POLICY type_lookup -> {v}")); // probe.cc:249 STOP 2
        push(
            &out,
            format!(
                "V8_rearm f s={} c={}",
                u8::from(f.borrow().info.is_file_signature_enabled()), // cc:182 -> 1
                u8::from(f.borrow().info.is_file_capture_enabled()), // cc:183 -> 1
            ),
        ); // line 16
        drop(pa); // delete (R1)
    }

    // ---- V9 (probe.cc:271-:295): the signature_lookup CAPTURE
    // ladder (rule capture ON — add_file_id cc:109 arms it with the
    // service CASCADE). a) no file_capture member: FileInfo::
    // reserve_file FAILS (file_lib.rs:656-:658 error_capture arm) ->
    // the cc:207-:208 delete-null arm -> sig_state clean -> cc:215
    // match miss -> UNKNOWN. b) WitCap reserve SUCCESS -> cc:197
    // store_file_async (trait DEFAULT "", = the C real empty-name
    // arm) -> cc:199-:202 size 0; reserve_file handed the capture off
    // (cc:529 posture: slot None) and re-armed config_file_capture
    // (false) -> all four readouts 0. c) sig_state DEPTH_FAIL ->
    // cc:210-:212 LOG BEFORE the match. ----
    wit_set_file_service(&mut env, false);
    {
        let mut pb = FilePolicy::new();
        let mut rb = FileRule::new();
        rb.r#use.capture_enabled = true;
        rb.r#use.verdict = FILE_VERDICT_BLOCK;
        pb.add_file_id(&rb, &mut env.svc); // cc:109 arms capture
        let fa = FileContext::ctor(None, &env); // a) reserve FAILS
        let va = FilePolicyApi::signature_lookup(&mut pb, &mut pkt, &mut fa.borrow_mut());
        push(&out, format!("POLICY signature_lookup -> {va}")); // probe.cc:281 -> 0
        let fb = FileContext::ctor(None, &env); // b) capture armed
        {
            let mut info = fb.borrow_mut();
            info.info.set_file_size(100); // fb.file_size = 100 (in [10, 1000])
            info.info.file_capture = Some(Box::new(WitCap)); // new FileCapture(10, 1000)
        }
        let vb = FilePolicyApi::signature_lookup(&mut pb, &mut pkt, &mut fb.borrow_mut());
        push(&out, format!("POLICY signature_lookup -> {vb}")); // :287 -> 0 (empty name, no sha)
        push(
            &out,
            format!(
                "V9b_extract size={} cutoff={} handed_off={} fcapcfg={}",
                fb.borrow().info.get_extracted_size(), // cc:201 -> 0
                u8::from(fb.borrow().info.get_extracted_cutoff()), // :205 NOT taken -> 0
                u8::from(fb.borrow().info.file_capture.is_some()), // hand-off -> 0
                u8::from(fb.borrow().info.is_file_capture_enabled()), // file_lib.cc:529 -> 0
            ),
        ); // line 19
        let fc2 = FileContext::ctor(None, &env); // c) depth fail
        fc2.borrow_mut().info.file_state.sig_state = FILE_SIG_DEPTH_FAIL; // h:86
        let vc = FilePolicyApi::signature_lookup(&mut pb, &mut pkt, &mut fc2.borrow_mut());
        push(&out, format!("POLICY signature_lookup -> {vc}")); // :293 LOG 1
        drop(pb); // delete (R1)
    }

    // ---- V10 (probe.cc:301-:313): the KEPT donor StubFilePolicy
    // (R5) over the SAME FilePolicyHandle seam. fcache_set_policy_
    // verdicts(BLOCK=3, PENDING=5) arms the Cells (stubs.cc:380-:
    // :387). Lines 21/22 are the stub's OWN prints through the seam
    // call (stubs.cc:366/:364); lines 23/24 the probe printf mirrors
    // (probe.cc:309/:310); identity: stub != the V1 real handle
    // (same_store, file_api.rs:320-:321) and the stub's own ref_count
    // is still its ctor 1 (fcache_stub_policy_refs, stubs.cc:747-:748). ----
    {
        let tv = Rc::new(Cell::new(FILE_VERDICT_BLOCK)); // (type_v, sig_v)
        let sv = Rc::new(Cell::new(FILE_VERDICT_PENDING));
        let mut stub = FilePolicyHandle::new_boxed(Box::new(PolicyStub {
            out: out.clone(),
            tv: tv.clone(),
            sv: sv.clone(),
        }));
        let f = FileContext::ctor(None, &env); // FileInfo f
        let a: u32 = stub.with_policy_mut(|p: &mut dyn FilePolicyApi| {
            p.signature_lookup(&mut pkt, &mut f.borrow_mut()) // stub prints -> 5
        });
        let b: u32 = stub.with_policy_mut(|p: &mut dyn FilePolicyApi| {
            p.type_lookup(&mut pkt, &mut f.borrow_mut()) // stub prints -> 3
        });
        push(&out, format!("POLICY signature_lookup -> {a}")); // probe.cc:309 mirror
        push(&out, format!("POLICY type_lookup -> {b}")); // probe.cc:310 mirror
        push(
            &out,
            format!(
                "V10_identity same={} refs={}",
                u8::from(stub.same_store(&pol)), // sp == rp? NO -> 0 (R5)
                stub.ref_count(), // fcache_stub_policy_refs -> 1
            ),
        ); // line 25
        // fcache_release_stub_policy (stubs.cc:377-:379, probe LAST):
        // the drain 1->0 posture (stubs.cc:374-:375 heap rule).
        stub.delete_file_policy();
        assert_eq!(stub.ref_count(), 0, "stub drain 1->0 (R1)");
        drop(stub);
    }

    // ---- V-ref (probe.cc:319-:327): the REAL ref protocol
    // (file_api.cc:28-:43) on the V1 handle: add_ref 1->2, the first
    // delete_file_policy 2->1 (no fire), the FINAL drain 1->0 fires
    // the real delete — ~FilePolicyBase's LIVE assert(!ref_count)
    // (file_api.cc:31) holds on the heap-only drained posture. ----
    pol.add_ref(); // file_api.h:165-:166
    let r_after = pol.ref_count();
    pol.delete_file_policy(); // 2 -> 1
    let r_mid = pol.ref_count();
    pol.delete_file_policy(); // 1 -> 0 -> the real delete moment
    assert_eq!(pol.ref_count(), 0, "final drain reaches 0 (cc:39-:41)");
    push(
        &out,
        format!(
            "V_ref add={} mid={} drained=1",
            u8::from(r_after == 2), // probe.cc:326 equality prints
            u8::from(r_mid == 1),
        ),
    ); // line 26
    drop(pol); // ref 0: Rc + Box release == the C delete (silent dtor)

    push(&out, "FPOLICY_PROBE_DONE"); // line 27 (probe.cc:334)

    let got = out.borrow();
    assert_eq!(got.len(), want.len(), "transcript line count");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors.txt line {}: Rust replay vs C probe", i + 1);
    }
}
