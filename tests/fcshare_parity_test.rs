//! Parity test for `src/file_api/file_cache_share.rs` — row 17t.
//!
//! Ground truth: `tools/fcshare_harness/vectors.txt` (25 L, md5
//! 03d43c143440bd2a101d56818fd20be4, NEVER edited) — C transcripts of
//! file_cache_share.cc:30-:75 + the pub_sub/file_events.h:82-:127 codec
//! walk driven by probe.cc (415 L). The C TU has ZERO TEST_CASEs
//! (fcshare PLAN §2): every oracle is a probe vector arm, replayed
//! here through the Rust port.
//!
//! Two layers ride the SAME arm helpers (fcap/fctx donor split): the
//! 13 label-slice tests pin one vector label each (witness asserts),
//! and `fcshare_transcript_replay` runs probe.cc main() (:87-:415) as
//! ONE ordered session — every printf line (all 25, IMGR witnesses
//! included) pushed at the exact C print position and byte-compared
//! line-for-line against vectors.txt.
//!
//! Drive-shape mapping (probe.cc header): C installed the cache
//! through the process-wide `FileService::file_cache` static
//! (file_service.h:109). The port has no such static: `handle` takes
//! `Option<&mut FileCache>` (the cc:38 null-guard == the `None` arm,
//! H1), and the 17t default `FileCacheShareSink` (file_cache.rs:1200+
//! swap) queues the cc:44 wire frames into `FileCache::mp_wire` that
//! `drain` decodes back through cc:63 + handle — producer -> wire ->
//! subscriber without an MP bus (the unported transport half stays
//! the seam). Where the probe drove `fcs.handle(ev, nullptr)`
//! directly, the test drives handle directly (the C subscription
//! shape); the sink middle is pinned in v_sink_default_is_file_cache_share.
//!
//! FIXACC note: the probe armed `ev.hashkey.sgroup` / mutated
//! `ev.file_ctx` through the FIXACC-published members
//! (probe.cc:149/:286, PLAN §7); `FileMpEvent`'s fields are pub for
//! the same seam (file_lib.rs:205 precedent).

use std::cell::RefCell;
use std::rc::Rc;

use snort3::file_api::file_cache::{
    CacheFlow, DriverPacketClock, FileCache, FileCacheClearReport, FileConfigView,
    FilePolicyApi, FileHashKey, InspectorApi, InspectorManagerApi, PacketView,
};
use snort3::file_api::file_cache_share::{
    FILE_MP_EVENT_FIXED_LEN, FileCacheShare, FileCacheShareSink, FileMpEvent,
    SIZEOF_FILE_MP_EVENT, deserialize_file_event, serialize_file_event,
};
use snort3::file_api::file_cache::FILE_HASH_KEY_BYTES;
use snort3::file_api::file_lib::{
    FileContext, FileInfo, FILE_VERDICT_BLOCK, FILE_VERDICT_LOG, FILE_VERDICT_REJECT,
    FILE_VERDICT_UNKNOWN, SHA256_HASH_SIZE, TimeVal,
};
use snort3::file_api::file_stats::FileCounts;

const VECTORS: &str = include_str!("../tools/fcshare_harness/vectors.txt");

const G_SHA: [u8; SHA256_HASH_SIZE] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20,
];

// probe.cc printf lines whose fields are pure manual-contract
// witnesses (no port state to compute): the literals, cited.
const S_D_OWNERSHIP_LINE: &str = "S_D_ownership buf_freed=1 event_freed=1 leak_delta=0 \
    (caller frees cc:54 buffer + cc:68 event)";
const X2_OWNERSHIP_LINE: &str = "X2_ownership event_freed=1 leak_delta=0";

fn mkkey(file_id: u64) -> FileHashKey {
    // probe mkkey(): FileHashKey{} then file_id (probe.cc:55-:60)
    FileHashKey { file_id, ..FileHashKey::default() }
}

fn cache_add(
    cache: &mut FileCache,
    k: &FileHashKey,
    timeout: i64,
    counts: &mut FileCounts,
) -> Rc<RefCell<FileContext>> {
    // probe cache_add(): the PUBLIC add() with cache_sync = true
    // (probe.cc:62-:68 — same form store_shared_verdict uses at cc:512)
    let mut cf = false;
    let mut ce = 0i64;
    cache
        .add(k, timeout, &mut cf, &mut ce, true, counts)
        .expect("node present")
}

/// pkt_now(1000000, 0): fixed packet clock, clamps forward only
/// (probe.cc:90); FileCache::new default is 16 max like the probe's.
fn mk_cache() -> FileCache {
    let mut c = FileCache::new(16);
    c.clock = Box::new(DriverPacketClock { now: TimeVal { tv_sec: 1000000, tv_usec: 0 } });
    c
}

/// vectors.txt lookup by label prefix (the 13 label-slice arms).
fn vector_line(label: &str) -> &'static str {
    VECTORS
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("vectors.txt label {label:?} missing"))
}

// -------------------------------------------------------------------
// C-session IMGR witnesses (fcshare_transcript_replay only).
// The C session linked stubs.cc InspectorManager::acquire_file_inspector
// (:358-:366): EVERY `new FileContext` (file_lib.cc:563 via
// FileCache::add -> add:219 == add:212 FileContext ctor) printed
// "IMGR acquire -> null" — the six witnesses at vectors:11/:15/:16/
// :18/:19/:21. The port's default NullInspectorManager prints nothing;
// the replay arms a pushing manager on the pub `FileCache::imgr` seam
// (file_cache.rs:1159) so each push lands at the exact C instant —
// the ~FileContext release half (file_lib.cc:583 `if (inspector)`)
// never fires: the stub returned null for every node, and vectors.txt
// holds no release line (deviation cite: Rc drop == the C delete).
// -------------------------------------------------------------------
struct ImgrTranscriptWitness {
    out: Rc<RefCell<Vec<String>>>,
}
impl InspectorManagerApi for ImgrTranscriptWitness {
    fn acquire_file_inspector(&mut self) -> Option<Rc<dyn InspectorApi>> {
        self.out.borrow_mut().push("IMGR acquire -> null".to_string());
        None
    }
    fn release(&mut self, _ins: &Rc<dyn InspectorApi>) {
        // silent: guarded by `if (inspector)` in the C dtor — no node
        // of this session ever held one (the stub always returned null).
    }
}

fn mk_cache_witnessed(out: &Rc<RefCell<Vec<String>>>) -> FileCache {
    let mut c = mk_cache();
    c.imgr = Rc::new(RefCell::new(Box::new(ImgrTranscriptWitness { out: out.clone() })));
    c
}

/// push a probe printf line into the replay transcript at its exact
/// C print position (None for the standalone label-slice tests).
fn push_line(out: Option<&Rc<RefCell<Vec<String>>>>, line: &str) {
    if let Some(out) = out {
        out.borrow_mut().push(line.to_string());
    }
}

// -------------------------------------------------------------------
// Arm helpers — one probe arm each. They RUN the arm and RETURN both
// the witness values (asserted by the label-slice tests) and the
// exact line probe.cc prints at that point (the replay pushes them).
// -------------------------------------------------------------------

/// probe :93-:94 — sizeofs printed, never mental (file_capture
/// SIZEOF_FILE_CAPTURE precedent: the port NEVER calls size_of; the
/// pinned literals ride the consts).
fn const_line() -> String {
    format!(
        "CONST sizeof_FileHashKey={FILE_HASH_KEY_BYTES} fixed_len={FILE_MP_EVENT_FIXED_LEN} sizeof_FileMPEvent={SIZEOF_FILE_MP_EVENT}"
    )
}

/// vectors.txt:1 — CONST sizeof_FileHashKey=56 fixed_len=64
/// sizeof_FileMPEvent=392 (probe CONST line, pinned literals; the
/// port NEVER calls size_of — file_capture.rs SIZEOF_FILE_CAPTURE
/// precedent).
#[test]
fn v_const_wire_layout() {
    let line = VECTORS.lines().find(|l| l.starts_with("CONST ")).unwrap();
    assert_eq!(line, const_line());
}

/// probe :98-:104 (S1). Deviation: the C out-params (`char*& buffer`
/// null, `uint16_t* len` 0xBEEF sentinel) are modelled by the Rust
/// Option return (file_cache_share.rs:417): the None return IS
/// ret=0, the caller's buffer stays null and its sentinel survives
/// because the tuple never exists — buf_null_after=1, len_untouched=1.
fn arm_s1() -> (bool, String) {
    let r = serialize_file_event(None);
    let ok = r.is_some();
    let line = format!("S1_null ret={} buf_null_after=1 len_untouched=1", u8::from(ok));
    (ok, line)
}

/// vectors.txt:2 — S1_null ret=0 buf_null_after=1 len_untouched=1
/// (cc:46-:47: null event -> false; out-params untouched).
#[test]
fn v_s1_null_event() {
    let (ok, line) = arm_s1();
    assert!(!ok, "S1_null ret=0");
    assert_eq!(line, vector_line("S1_null "));
}

/// probe :106-:132 (S2). Both ctor arms converge on len==0
/// (file_events.h:49-:50): the default ctor (file_events.h:55-:59)
/// and the oversized cap (probe name 65420 'X': tail > 65535-64 ->
/// len=0; the FIXACC member write is the PLAN-7-sanctioned seam).
fn arm_s2() -> ((bool, u16), (bool, u16), String) {
    let mut ev_zero = FileMpEvent::default();
    let rz = serialize_file_event(Some(&mut ev_zero)).is_some(); // :115
    let dl_zero = ev_zero.get_data_len(); // :116
    let big = FileInfo {
        file_name: vec![b'X'; 65420], // FIXACC member write (probe :122)
        file_name_set: true,
        ..FileInfo::default()
    };
    let kb = mkkey(501);
    let mut ev_big = FileMpEvent::new(&kb, 3600, &big); // ctor caps len=0 (:125)
    let dl_big = ev_big.get_data_len(); // :126
    let ro = serialize_file_event(Some(&mut ev_big)).is_some(); // :128
    let line = format!(
        "S2_zerolen ret_default={} data_len_default={} ret_oversized={} data_len_oversized={}",
        u8::from(rz),
        dl_zero,
        u8::from(ro),
        dl_big
    );
    ((rz, dl_zero), (ro, dl_big), line)
}

/// vectors.txt:3 — S2_zerolen ret_default=0 data_len_default=0
/// ret_oversized=0 data_len_oversized=0.
#[test]
fn v_s2_zero_len_convergence() {
    let ((rz, dl_zero), (ro, dl_big), line) = arm_s2();
    assert_eq!(dl_zero, 0, "data_len_default=0");
    assert!(!rz, "ret_default=0");
    assert_eq!(dl_big, 0, "data_len_oversized=0");
    assert!(!ro, "ret_oversized=0");
    assert_eq!(line, vector_line("S2_zerolen "));
}

/// Build the S3 event exactly as probe :138-:149 (verdict BLOCK,
/// name/url/id/size set, sha set, timeout 3000001234) and serialize.
/// data_len == the probe's `dl3 = ev3.get_data_len()` read AFTER the
/// serialize call (:151-:153).
fn s3_event_and_wire() -> (Vec<u8>, u16, i64, u16) {
    let k3 = mkkey(503);
    let mut fi3 = FileInfo {
        verdict: FILE_VERDICT_BLOCK,
        ..FileInfo::default()
    };
    fi3.set_file_name(Some(b"s3_shared.exe"), 13); // exact strlen: no clamp
    fi3.set_url(Some(b"/share/s3"), 9);
    fi3.set_file_id(503);
    fi3.set_file_size(2048);
    fi3.sha256 = Some(G_SHA);
    let mut ev3 = FileMpEvent::new(&k3, 3000001234, &fi3);
    ev3.hashkey.sgroup = 7; // FIXACC arm (probe :149)
    ev3.hashkey.dgroup = 9;
    let (wire, len) = serialize_file_event(Some(&mut ev3)).expect("S3 ret=1");
    (wire, len, ev3.get_timeout(), ev3.get_data_len())
}

struct S3Witness {
    ok: bool,
    len_out: u16,
    data_len: u16,
    timeout: i64,
    hdr_len: usize,
    hdr_eq: bool,
    tail_eq: bool,
    hex: String,
    wire: Vec<u8>, // == probe `static char* g_wire` (:84-:85) for the D arms
    line: String,
}

/// probe :134-:187 (S3): populated event serializes; the buffer ==
/// the manual LE header walk (cc:59 order == file_events.h:108-:125,
/// probe :157-:168) and the REAL FileInfo::serialize tail over a deep
/// copy (probe :170-:176), byte for byte.
fn arm_s3() -> S3Witness {
    let (wire, len, timeout, data_len) = s3_event_and_wire();
    let ok = true; // s3_event_and_wire expects the Some arm (probe :151 r3=1)

    // hdr_eq: the expected header is the probe's manual LE walk
    // (probe :157-:168) == the same file_events.h:108-:125 order.
    let mut hdr: Vec<u8> = Vec::new();
    hdr.extend_from_slice(&3000001234i64.to_le_bytes()); // timeout
    hdr.extend_from_slice(&[0u8; 16]); // sip.ip8
    hdr.extend_from_slice(&0i16.to_le_bytes()); // sip.family
    hdr.extend_from_slice(&7i16.to_le_bytes()); // sgroup
    hdr.extend_from_slice(&[0u8; 16]); // dip.ip8
    hdr.extend_from_slice(&0i16.to_le_bytes()); // dip.family
    hdr.extend_from_slice(&9i16.to_le_bytes()); // dgroup
    hdr.extend_from_slice(&503u64.to_le_bytes()); // file_id
    hdr.extend_from_slice(&0u16.to_le_bytes()); // asid
    hdr.extend_from_slice(&[0u8; 6]); // padding
    let hdr_eq = hdr.len() == FILE_MP_EVENT_FIXED_LEN && wire[..64] == hdr[..];

    // tail_eq=1: the REAL FileInfo::serialize over a deep copy drives
    // the expected tail (probe :170-:176 expect_tail construction
    // through the real file_lib.o).
    let k3 = mkkey(503);
    let mut fi3 = FileInfo {
        verdict: FILE_VERDICT_BLOCK,
        ..FileInfo::default()
    };
    fi3.set_file_name(Some(b"s3_shared.exe"), 13);
    fi3.set_url(Some(b"/share/s3"), 9);
    fi3.set_file_id(503);
    fi3.set_file_size(2048);
    fi3.sha256 = Some(G_SHA);
    let mut ref_copy = FileMpEvent::new(&k3, 3000001234, &fi3);
    ref_copy.hashkey.sgroup = 7;
    ref_copy.hashkey.dgroup = 9;
    let mut expect_tail = vec![0u8; 4096];
    ref_copy.file_ctx.serialize(&mut expect_tail, 174 - 64);
    let tail_eq = wire[64..] == expect_tail[..174 - 64];

    // hdr_bytes witness (uppercase %02X runs, first 24 bytes)
    let hex: String = wire[..24].iter().map(|b| format!("{b:02X}")).collect();
    let line = format!(
        "S3_ok ret={} len_out={} data_len={} hdr_eq={} tail_eq={} tail_off={} hdr_bytes={}",
        u8::from(ok),
        len,
        data_len,
        u8::from(hdr_eq),
        u8::from(tail_eq),
        FILE_MP_EVENT_FIXED_LEN, // fixed_len_of(k3) == the pinned const
        hex
    );
    S3Witness {
        ok,
        len_out: len,
        data_len,
        timeout,
        hdr_len: hdr.len(),
        hdr_eq,
        tail_eq,
        hex,
        wire,
        line,
    }
}

/// vectors.txt:4 — S3_ok ret=1 len_out=174 data_len=174 hdr_eq=1
/// tail_eq=1 tail_off=64 hdr_bytes=D262D0B20000000000000000000000000000000000000000
#[test]
fn v_s3_success_and_header() {
    let w = arm_s3();
    // ret/len/data_len/tail_off witnesses
    assert!(w.ok, "S3 ret=1");
    assert_eq!(w.len_out, 174, "len_out=174");
    assert_eq!(w.data_len, 174, "data_len=174");
    assert_eq!(w.timeout, 3000001234);
    assert_eq!(w.hdr_len, FILE_MP_EVENT_FIXED_LEN, "tail_off=64");
    assert!(w.hdr_eq, "hdr_eq=1");
    assert!(w.tail_eq, "tail_eq=1");
    assert_eq!(w.hex, vector_line("S3_ok ").split("hdr_bytes=").nth(1).unwrap().trim());
    assert_eq!(w.line, vector_line("S3_ok "));
    // (drop(wire) == the probe's delete[] g_wire at :235 — R7 caller
    // frees the cc:54 buffer.)
    drop(w.wire);
}

/// probe :196-:201 (D1). Deviation: the empty slice models the C null
/// buffer (probe :199); the None return == ret=0 and the caller's
/// out-event sentinel stays null because no out-param exists.
fn arm_d1() -> (bool, String) {
    let r = deserialize_file_event(&[], 64).is_some();
    (r, format!("D1_nullbuf ret={} event_untouched=1", u8::from(r)))
}

/// vectors.txt:5 — D1_nullbuf ret=0 event_untouched=1 (cc:65: the
/// `!buffer` arm; the Rust empty slice models the C null pointer and
/// the None return leaves the caller's out-event sentinel untouched).
#[test]
fn v_d1_null_buffer() {
    let (ret, line) = arm_d1();
    assert!(!ret, "D1 ret=0");
    assert_eq!(line, vector_line("D1_nullbuf "));
}

/// vectors.txt:6 — D2_zerolen ret=0 event_untouched=1 (cc:65 second
/// arm: valid buffer, len 0).
#[test]
fn v_d2_zero_len() {
    let (wire, len, _, _) = s3_event_and_wire();
    let (ret, line) = arm_d2(&wire);
    assert!(!ret, "D2 ret=0");
    assert_eq!(line, vector_line("D2_zerolen "));
    // R5 documented NOT vectored (probe :192-:194): 0<len<64 against
    // a SHORT buffer is an OOB read in C -> a Rust panic; UB is never
    // oracle material (this arm only pins the panic posture).
    let r = std::panic::catch_unwind(|| deserialize_file_event(&wire[..10], 10));
    assert!(r.is_err(), "R5: truncated wire = the C OOB read UB -> Rust panic, unpinned");
    assert_eq!(len, 174);
}

/// probe :202-:207 (D2): valid buffer, len 0 -> false (cc:65 second
/// arm: valid buffer, len 0).
fn arm_d2(wire: &[u8]) -> (bool, String) {
    let r = deserialize_file_event(wire, 0).is_some();
    (r, format!("D2_zerolen ret={} event_untouched=1", u8::from(r)))
}

/// probe :208-:239 (D3/D4): S3's live g_wire round-trips every field
/// (the file_events.h:82-:104 walk) and get_data_len records the RAW
/// wire len (file_events.h:103, risk R8 pin — never a recomputed
/// fixed+file_size). `ev` drops at fn exit == the probe's `delete ev3`
/// at :237; S_D_ownership (vectors:9, probe :238-:239) is the
/// caller-frees-both-halves contract line (R7).
fn arm_d3_d4(wire: &[u8], len: u16) -> D34Witness {
    let ev = deserialize_file_event(wire, len);
    let nonnull = ev.is_some();
    let ret_ok = nonnull;
    let (timeout_eq, key_eq, verdict_eq, name_eq, url_eq, sha_eq, size_eq, data_len) =
        match &ev {
            Some(ev) => {
                let mut k3 = mkkey(503);
                k3.sgroup = 7;
                k3.dgroup = 9;
                let fc = ev.get_file_ctx();
                (
                    ev.get_timeout() == 3000001234,
                    ev.get_hashkey() == &k3,
                    fc.verdict == FILE_VERDICT_BLOCK,
                    fc.get_file_name() == b"s3_shared.exe",
                    fc.get_url() == b"/share/s3",
                    fc.sha256 == Some(G_SHA),
                    fc.get_file_size() == 2048,
                    ev.get_data_len(),
                )
            }
            None => (false, false, false, false, false, false, false, 0),
        };
    let len_rec_eq = data_len == len;
    let d3_line = format!(
        "D3_roundtrip ret={} nonnull={} timeout_eq={} key_eq={} verdict_eq={} name_eq={} url_eq={} sha_eq={} file_size_eq={}",
        u8::from(ret_ok),
        u8::from(nonnull),
        u8::from(timeout_eq),
        u8::from(key_eq),
        u8::from(verdict_eq),
        u8::from(name_eq),
        u8::from(url_eq),
        u8::from(sha_eq),
        u8::from(size_eq)
    );
    // D4 (probe :233-:234): wire_len == recorded data_len (R8).
    let d4_line = format!(
        "D4_lenrec wire_len={} data_len={} len_rec_eq={}",
        len,
        data_len,
        u8::from(len_rec_eq)
    );
    D34Witness {
        d3_line,
        d4_line,
        timeout_eq,
        key_eq,
        verdict_eq,
        name_eq,
        url_eq,
        sha_eq,
        size_eq,
        len_rec_eq,
        wire_len: len,
        data_len,
    }
}

struct D34Witness {
    d3_line: String,
    d4_line: String,
    timeout_eq: bool,
    key_eq: bool,
    verdict_eq: bool,
    name_eq: bool,
    url_eq: bool,
    sha_eq: bool,
    size_eq: bool,
    len_rec_eq: bool,
    wire_len: u16,
    data_len: u16,
}

/// vectors.txt:7-:9 — D3_roundtrip (field-by-field round trip) +
/// D4_lenrec + S_D_ownership (the caller owns BOTH heap halves; Rust
/// moves/drops == the probe's delete[] + delete, leak_delta 0).
#[test]
fn v_d3_d4_roundtrip_and_ownership() {
    let (wire, len, _, _) = s3_event_and_wire();
    let d = arm_d3_d4(&wire, len);
    assert!(d.timeout_eq, "timeout_eq=1");
    assert!(d.key_eq, "key_eq=1");
    assert!(d.verdict_eq, "verdict_eq=1");
    assert!(d.name_eq, "name_eq=1");
    assert!(d.url_eq, "url_eq=1");
    assert!(d.sha_eq, "sha_eq=1");
    assert!(d.size_eq, "file_size_eq=1");
    assert_eq!(d.d3_line, vector_line("D3_roundtrip "));
    // D4 (vectors.txt:8): wire_len == recorded data_len (R8: never a
    // recomputed fixed+file_size).
    assert!(d.len_rec_eq, "len_rec_eq=1");
    assert_eq!(d.wire_len, d.data_len);
    assert_eq!(d.d4_line, vector_line("D4_lenrec "));
    // S_D_ownership (vectors.txt:9): buf + event freed by the caller;
    // Rust scope-exit drops == delete[] g_wire + delete ev3.
    drop(wire);
    assert_eq!(S_D_OWNERSHIP_LINE, vector_line("S_D_ownership "));
}

/// probe :245-:258 (H1): FileService::file_cache == nullptr (default
/// zero-init, file_service.h:109) -> the cc:38 `if (file_cache)` guard
/// returns; nothing crashes, nothing stored. handled=1/cache_null=1
/// are C literals at :257; guard_hit == the null-cache witness
/// (get_file_cache() ? 0 : 1) — ported as "no entry was stored".
fn arm_h1() -> (bool, String) {
    let fcs = FileCacheShare::new();
    let mut counts = FileCounts::default();
    let k1 = mkkey(601);
    let mut fi1 = FileInfo {
        verdict: FILE_VERDICT_BLOCK,
        ..FileInfo::default()
    };
    fi1.set_file_name(Some(b"h1.bin"), 6);
    let ev1 = FileMpEvent::new(&k1, 3600, &fi1);
    fcs.handle(&ev1, None, &mut counts); // None == the null static
    let guard_hit = counts.file_cache_total_entries == 0;
    (
        guard_hit,
        format!("H1_nocache handled=1 cache_null=1 guard_hit={}", u8::from(guard_hit)),
    )
}

/// vectors.txt:10 — H1_nocache: the null-static guard returns.
#[test]
fn v_h1_null_cache_guard() {
    let (guard_hit, line) = arm_h1();
    assert!(guard_hit, "guard_hit=1: nothing stored");
    assert_eq!(line, vector_line("H1_nocache "));
}

/// Witnesses of the H2/H3/H4/H_xattr chain (probe :260-:352) driven
/// against ONE cache — the four label-slice tests and the replay
/// share this walker. `out` Some(...) == replay mode: each line is
/// pushed at its exact C printf position.
struct HChain {
    lines: [String; 4],
    // H2 (probe :266-:293)
    node_hit: bool,
    v2: u32,
    n2_len: usize,
    n2: Vec<u8>,
    ent_h2: i64,
    copy_not_alias: bool, // 1 - probe alias (:290/:293)
    // H3 (:295-:309)
    h3_verdict: u32,
    h3_name: Vec<u8>,
    h3_kept: bool,
    // H4 (:310-:324)
    h4_verdict: u32,
    h4_name: Vec<u8>,
    h4_size: u64,
    h4_copy_fired: bool,
    // H_xattr (:326-:350)
    ent_first: i64,
    ent_after: i64,
    x_verdict: u32,
    x_name: Vec<u8>,
    x_recovered: bool,
}

/// vectors.txt:12-:17 — H2_copy_then_store / H3_blocked / H4_blocked2
/// / H_xattr against ONE real FileCache, events driven through
/// FileCacheShare::handle exactly like the C subscriber (the probe's
/// drive shape).
fn run_h_chain(
    cache: &mut FileCache,
    counts: &mut FileCounts,
    out: Option<&Rc<RefCell<Vec<String>>>>,
) -> HChain {
    let fcs = FileCacheShare::new();

    // H2 (probe :268-:293; vectors:12 H2_copy_then_store node_hit=1
    // verdict=3 name_len=6 name=h2.bin entries=1 copy_not_alias=1):
    // the cc:35 value copy + the deep FileInfo copy ctor
    // (file_lib.cc:326) keep the node independent of the event.
    let k2 = mkkey(702);
    let mut fi2 = FileInfo {
        verdict: FILE_VERDICT_BLOCK,
        ..FileInfo::default()
    };
    fi2.set_file_name(Some(b"h2.bin"), 6);
    fi2.set_file_id(702);
    fi2.sha256 = Some(G_SHA);
    let mut ev2 = FileMpEvent::new(&k2, 3600, &fi2);
    fcs.handle(&ev2, Some(cache), counts);
    let node = cache_add(cache, &k2, 3600, counts);
    let node_hit = true; // cache_add expects the Some arm (probe :279 node ? 1 : 0)
    let v2 = node.borrow().info.verdict;
    // snapshot into owned bytes BEFORE any later printf (probe :281-:284)
    let n2 = node.borrow().info.get_file_name().to_vec();
    let n2_len = n2.len();
    let ent_h2 = cache.get_num_entries();
    // mutate the EVENT AFTER the call (probe :286-:287) -> the node
    // must not move (copy_not_alias=1).
    ev2.file_ctx.verdict = FILE_VERDICT_UNKNOWN;
    ev2.file_ctx.set_file_name(Some(b"MUT.exe"), 7);
    let node2 = cache_add(cache, &k2, 3600, counts);
    let copy_not_alias = node2.borrow().info.verdict == FILE_VERDICT_BLOCK
        && node2.borrow().info.get_file_name() == b"h2.bin";
    let h2_line = format!(
        "H2_copy_then_store node_hit={} verdict={} name_len={} name={} entries={} copy_not_alias={}",
        u8::from(node_hit),
        v2,
        n2_len,
        String::from_utf8_lossy(&n2),
        ent_h2,
        u8::from(copy_not_alias)
    );
    push_line(out, &h2_line);

    // H3 (vectors:13): cached terminal BLOCK, incoming UNKNOWN ->
    // verdict-publish gate drops (file_cache.cc:519-:524 through the
    // cc:40 callee): verdict=3 name=h2.bin node_unchanged=1.
    let mut fi3 = FileInfo {
        verdict: FILE_VERDICT_UNKNOWN,
        ..FileInfo::default()
    };
    fi3.set_file_name(Some(b"h3.bin"), 6);
    let ev3 = FileMpEvent::new(&k2, 3600, &fi3);
    fcs.handle(&ev3, Some(cache), counts);
    let n3 = cache_add(cache, &k2, 3600, counts);
    let h3_verdict = n3.borrow().info.verdict;
    let h3_name = n3.borrow().info.get_file_name().to_vec();
    // probe :306 kept = v == BLOCK && nm == "h2.bin"
    let h3_kept = h3_verdict == FILE_VERDICT_BLOCK && h3_name == *b"h2.bin";
    let h3_line = format!(
        "H3_blocked verdict={} name={} node_unchanged={}",
        h3_verdict,
        String::from_utf8_lossy(&h3_name),
        u8::from(h3_kept)
    );
    push_line(out, &h3_line);

    // H4 (vectors:14): BLOCK -> BLOCK NOT gated (incoming terminal);
    // *((FileInfo*)node) = src fires (file_cache.cc:526-:527):
    // name=h4.bin file_size=77 copy_fired=1.
    let mut fi4 = FileInfo {
        verdict: FILE_VERDICT_BLOCK,
        ..FileInfo::default()
    };
    fi4.set_file_name(Some(b"h4.bin"), 6);
    fi4.set_file_size(77);
    let ev4 = FileMpEvent::new(&k2, 3600, &fi4);
    fcs.handle(&ev4, Some(cache), counts);
    let n4 = cache_add(cache, &k2, 3600, counts);
    let h4_verdict = n4.borrow().info.verdict;
    let h4_name = n4.borrow().info.get_file_name().to_vec();
    let h4_size = n4.borrow().info.get_file_size();
    let h4_copy_fired = h4_name == *b"h4.bin"; // probe :323 copy_fired
    let h4_line = format!(
        "H4_blocked2 verdict={} name={} file_size={} copy_fired={}",
        h4_verdict,
        String::from_utf8_lossy(&h4_name),
        h4_size,
        u8::from(h4_copy_fired)
    );
    push_line(out, &h4_line);

    // H_xattr (probe :326-:349; vectors:17): timeout 1s -> clock jump
    // +10s -> re-handle SAME wire key: the expired node is recovered
    // (is_node_recovery_ok, file_cache.cc:68-:86) and the fresh
    // event's data lands. R1: handle forwards the wire key verbatim.
    let kx = mkkey(900);
    let mut fix_ = FileInfo {
        verdict: FILE_VERDICT_LOG,
        ..FileInfo::default()
    };
    fix_.set_file_name(Some(b"orig.bin"), 8);
    let evx = FileMpEvent::new(&kx, 1, &fix_); // expire = now+1s
    fcs.handle(&evx, Some(cache), counts);
    let ent_first = cache.get_num_entries();
    cache.clock = Box::new(DriverPacketClock { now: TimeVal { tv_sec: 1000010, tv_usec: 0 } }); // pkt_now(1000010,0)
    let mut fir = FileInfo {
        verdict: FILE_VERDICT_LOG,
        ..FileInfo::default()
    };
    fir.set_file_name(Some(b"recover.bin"), 11);
    let evr = FileMpEvent::new(&kx, 3600, &fir); // SAME wire key
    fcs.handle(&evr, Some(cache), counts);
    let nx = cache_add(cache, &kx, 3600, counts);
    let x_verdict = nx.borrow().info.verdict;
    let x_name = nx.borrow().info.get_file_name().to_vec();
    let x_recovered = x_name == *b"recover.bin"; // probe :349
    let ent_after = cache.get_num_entries(); // read AFTER nx (probe :345)
    let xattr_line = format!(
        "H_xattr entries_after_first={} entries_after={} verdict={} name={} recovered={}",
        ent_first,
        ent_after,
        x_verdict,
        String::from_utf8_lossy(&x_name),
        u8::from(x_recovered)
    );
    push_line(out, &xattr_line);

    HChain {
        lines: [h2_line, h3_line, h4_line, xattr_line],
        node_hit,
        v2,
        n2_len,
        n2,
        ent_h2,
        copy_not_alias,
        h3_verdict,
        h3_name,
        h3_kept,
        h4_verdict,
        h4_name,
        h4_size,
        h4_copy_fired,
        ent_first,
        ent_after,
        x_verdict,
        x_name,
        x_recovered,
    }
}

#[test]
fn v_h2_h3_h4_hxattr_store_chain() {
    let mut cache = mk_cache();
    let mut counts = FileCounts::default();
    let c = run_h_chain(&mut cache, &mut counts, None);

    // H2 witnesses (vectors:12)
    assert!(c.node_hit, "node_hit=1");
    assert_eq!(c.v2, FILE_VERDICT_BLOCK, "verdict=3");
    assert_eq!(c.n2_len, 6, "name_len=6");
    assert_eq!(&c.n2[..], &b"h2.bin"[..], "name=h2.bin");
    assert_eq!(c.ent_h2, 1, "entries=1");
    assert!(c.copy_not_alias, "copy_not_alias=1");

    // H3 witnesses (vectors:13)
    assert_eq!(c.h3_verdict, FILE_VERDICT_BLOCK, "H3 verdict=3");
    assert_eq!(&c.h3_name[..], &b"h2.bin"[..], "node_unchanged=1");
    assert!(c.h3_kept);

    // H4 witnesses (vectors:14)
    assert_eq!(c.h4_verdict, FILE_VERDICT_BLOCK, "H4 verdict=3");
    assert_eq!(&c.h4_name[..], &b"h4.bin"[..], "copy_fired=1");
    assert_eq!(c.h4_size, 77, "file_size=77");
    assert!(c.h4_copy_fired);

    // H_xattr (vectors:17) — absolute entry counts come straight off
    // the vector line; R1 re-handle of the expired key recovered.
    let v = vector_line("H_xattr ");
    let want_first: i64 = v
        .split("entries_after_first=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let want_after: i64 = v
        .split("entries_after=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(c.ent_first, want_first, "entries_after_first match");
    assert_eq!(c.ent_after, want_after, "entries_after match");
    assert_eq!(c.x_verdict, FILE_VERDICT_LOG, "verdict=1");
    assert_eq!(&c.x_name[..], &b"recover.bin"[..], "recovered=1");
    assert!(c.x_recovered);

    // exact printf lines
    assert_eq!(c.lines[0], vector_line("H2_copy_then_store "));
    assert_eq!(c.lines[1], vector_line("H3_blocked "));
    assert_eq!(c.lines[2], vector_line("H4_blocked2 "));
    assert_eq!(c.lines[3], v);
}

/// probe :356-:380 (X1): handle -> clear() -> handle the SAME live
/// event again: the event's by-value FileInfo (file_events.h:132)
/// cannot dangle through the clear walk (R3 safe half) -> fresh node.
struct X1Witness {
    freed: u64,
    remaining: u64,
    ent_mid: i64, // entries_after_clear
    ent_after: i64,
    verdict: u32,
    name: Vec<u8>,
    fresh: bool, // probe :378 v == BLOCK
    line: String,
}

fn run_x1(
    cache: &mut FileCache,
    counts: &mut FileCounts,
    out: Option<&Rc<RefCell<Vec<String>>>>,
) -> X1Witness {
    let kx = mkkey(950);
    let mut fi = FileInfo {
        verdict: FILE_VERDICT_BLOCK,
        ..FileInfo::default()
    };
    fi.set_file_name(Some(b"x1.bin"), 6);
    let ev = FileMpEvent::new(&kx, 3600, &fi); // stack event survives (probe :364)
    {
        let h = FileCacheShare::new();
        h.handle(&ev, Some(cache), counts); // :365 { FileCacheShare h; h.handle }
    }
    let rep: FileCacheClearReport = cache.clear(); // file_cache.h:88 (:366)
    let ent_mid = cache.get_num_entries(); // :367
    {
        let h = FileCacheShare::new();
        h.handle(&ev, Some(cache), counts); // same key again (:368)
    }
    let n = cache_add(cache, &kx, 3600, counts); // :369-:370
    let verdict = n.borrow().info.verdict;
    let name = n.borrow().info.get_file_name().to_vec();
    let fresh = verdict == FILE_VERDICT_BLOCK;
    let ent_after = cache.get_num_entries(); // read in the printf args (:377)
    let line = format!(
        "X1_handle_after_clear freed={} remaining={} entries_after_clear={} entries_after={} verdict={} name={} fresh_node={}",
        rep.freed,
        rep.remaining,
        ent_mid,
        ent_after,
        verdict,
        String::from_utf8_lossy(&name),
        u8::from(fresh)
    );
    push_line(out, &line);
    X1Witness {
        freed: rep.freed,
        remaining: rep.remaining,
        ent_mid,
        ent_after,
        verdict,
        name,
        fresh,
        line,
    }
}

/// vectors.txt:20 — X1_handle_after_clear: handle the same live event
/// after clear() lands a fresh node (R3 safe half).
#[test]
fn v_x1_handle_after_clear() {
    let mut cache = mk_cache();
    let mut counts = FileCounts::default();
    let w = run_x1(&mut cache, &mut counts, None);
    assert_eq!(w.freed, 1, "freed=1");
    assert_eq!(w.remaining, 0, "remaining=0");
    assert_eq!(w.ent_mid, 0, "entries_after_clear=0");
    assert_eq!(w.ent_after, 1, "entries_after=1");
    assert_eq!(w.verdict, FILE_VERDICT_BLOCK, "fresh_node=1 verdict=3");
    assert_eq!(&w.name[..], &b"x1.bin"[..], "name=x1.bin");
    assert!(w.fresh);
    assert_eq!(w.line, vector_line("X1_handle_after_clear "));
}

/// probe :382-:410 (X2): event allocated BEFORE the cache; the cache
/// dtor (Rust drop walk, file_cache.rs:985-:1002 == C
/// ~ExpectedFileCache delete_hash_table) runs while the event holder
/// stays alive: the event's deep copy is intact afterwards
/// (event_owns_copy=1), and dropping the event frees its own copy
/// (X2_ownership leak_delta=0 — Rust drops by construction, no Rc
/// cycle: store_shared_verdict never retains the src wrapper).
struct X2Witness {
    ent: i64,
    verdict: u32,
    name: Vec<u8>,
    file_size: u64,
    owns_copy: bool, // probe :407 nm == "x2_hold.bin"
    enter_line: String,
    dtor_line: String,
}

fn run_x2(out: Option<&Rc<RefCell<Vec<String>>>>) -> X2Witness {
    let k2 = mkkey(960);
    let mut fi = FileInfo {
        verdict: FILE_VERDICT_REJECT,
        ..FileInfo::default()
    };
    fi.set_file_name(Some(b"x2_hold.bin"), 11);
    fi.set_file_size(5);
    let evy = FileMpEvent::new(&k2, 3600, &fi); // BEFORE cache (probe :392)
    let ent;
    {
        let mut cache = match out {
            Some(o) => mk_cache_witnessed(o),
            None => mk_cache(),
        };
        let mut counts = FileCounts::default();
        {
            let h = FileCacheShare::new();
            h.handle(&evy, Some(&mut cache), &mut counts); // :396
        }
        ent = cache.get_num_entries(); // :397
        // :398 FileService::file_cache = nullptr (silent)
    } // ~FileCache walks + frees every node's FileContext (:400)
    let enter_line = format!("X2_enter entries={ent}"); // printed INSIDE the scope (:399)
    push_line(out, &enter_line);

    let fc = evy.get_file_ctx(); // alive AFTER the dtor walk (:401)
    let verdict = fc.verdict;
    let name = fc.get_file_name().to_vec();
    let file_size = fc.get_file_size();
    let owns_copy = name == *b"x2_hold.bin";
    let dtor_line = format!(
        "X2_dtor_with_live_event event_verdict={} event_name={} event_file_size={} event_owns_copy={}",
        verdict,
        String::from_utf8_lossy(&name),
        file_size,
        u8::from(owns_copy)
    );
    push_line(out, &dtor_line);
    drop(evy); // delete evY (:408)
    push_line(out, X2_OWNERSHIP_LINE); // :409
    X2Witness {
        ent,
        verdict,
        name,
        file_size,
        owns_copy,
        enter_line,
        dtor_line,
    }
}

/// vectors.txt:22-:24 — X2: the cache dtor walk never touches the
/// event's own deep copy; the event drop frees only itself.
#[test]
fn v_x2_dtor_with_live_event() {
    let w = run_x2(None);
    assert_eq!(w.ent, 1, "X2_enter entries=1");
    assert_eq!(w.verdict, FILE_VERDICT_REJECT, "event_verdict=4");
    assert_eq!(&w.name[..], &b"x2_hold.bin"[..], "event_name=x2_hold.bin");
    assert_eq!(w.file_size, 5, "event_file_size=5");
    assert!(w.owns_copy, "event_owns_copy=1");
    assert_eq!(w.enter_line, vector_line("X2_enter "));
    assert_eq!(w.dtor_line, vector_line("X2_dtor_with_live_event "));
    assert_eq!(X2_OWNERSHIP_LINE, vector_line("X2_ownership"));
}

// -------------------------------------------------------------------
// The whole-transcript loop (row 17t): probe.cc main() (:87-:415) as
// ONE ordered session — every printf line pushed at its exact C
// position (the six IMGR witnesses included; vectors:11/15/16/18/19/
// 21) and compared against vectors.txt at every index (donor
// fcap_transcript_replay / fctx_transcript_replay shape: assert
// want.len() == 25, per-index assert_eq with the vectors line cite).
// -------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn fcshare_transcript_replay() {
    let out: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::with_capacity(25)));
    let push = |s: String| out.borrow_mut().push(s);

    // probe prelude (:89-:90): setvbuf line-buffered + pkt_now(1000000,
    // 0) — the port arms that clock per-cache (mk_cache, 16 max).
    push(const_line()); // :93

    // S1 (:98-:104)
    let (ok, line) = arm_s1();
    assert!(!ok, "S1 ret=0 witness");
    push(line);

    // S2 (:106-:132)
    let ((rz, dz), (ro, db), line) = arm_s2();
    assert!(!rz && dz == 0 && !ro && db == 0, "S2 zero-len convergence");
    push(line);

    // S3 (:134-:187) — the wire buffer == probe `static g_wire` (:84-
    // :85), kept ALIVE for the D arms (R7), freed there (:235).
    let s3 = arm_s3();
    assert!(s3.ok && s3.hdr_eq && s3.tail_eq, "S3 hdr/tail witnesses");
    push(s3.line);

    // D1 (:196-:201)
    let (d1, line) = arm_d1();
    assert!(!d1, "D1 ret=0 witness");
    push(line);

    // D2 (:202-:207): g_wire in hand, len 0
    let (wire, wlen) = (s3.wire.clone(), s3.len_out);
    let (d2, line) = arm_d2(&wire);
    assert!(!d2, "D2 ret=0 witness");
    push(line);

    // R5 pinned-but-NOT-vectored UB arm (probe :192-:194): ANY
    // 0<len<64 against a SHORT buffer is an OOB read in C — the probe
    // prints NOTHING for it, so the C session gains no line here.
    // The Rust port panics instead; catch_unwind holds that posture,
    // the session continues, and no line is invented.
    let ub = std::panic::catch_unwind(|| deserialize_file_event(&wire[..10], 10));
    assert!(ub.is_err(), "R5 UB == Rust panic, no transcript line");

    // D3 + D4 (:208-:234) then the frees (:235 delete[] g_wire,
    // :237 delete ev3 — ev dropped inside arm_d3_d4; Rust
    // scope-exit order deviates harmlessly: ownership is the witness)
    let d34 = arm_d3_d4(&wire, wlen);
    assert!(d34.timeout_eq && d34.key_eq && d34.verdict_eq && d34.name_eq
        && d34.url_eq && d34.sha_eq && d34.size_eq && d34.len_rec_eq,
        "D3/D4 witness flags all 1");
    push(d34.d3_line);
    push(d34.d4_line);
    drop(wire);
    push(S_D_OWNERSHIP_LINE.to_string()); // :238-:239

    // H1 (:243-:258)
    let (gh, line) = arm_h1();
    assert!(gh, "guard_hit=1 witness");
    push(line);

    // H2..H_xattr (:260-:352) against ONE cache — the six IMGR
    // witnesses fire through the armed stub seam (1 here at the H2
    // node insert, 2 more before H_xattr at the kx node inserts).
    {
        let mut cache = mk_cache_witnessed(&out);
        let mut counts = FileCounts::default();
        let c = run_h_chain(&mut cache, &mut counts, Some(&out));
        assert!(c.copy_not_alias && c.h3_kept && c.h4_copy_fired && c.x_recovered);
        // :351 static reset + :352 ~FileCache delete_hash_table walk:
        // every node is inspector-less -> silent release half.
    }

    // X1 (:356-:380) — both node inserts acquire (:18/:19 witnesses)
    {
        let mut cache = mk_cache_witnessed(&out);
        let mut counts = FileCounts::default();
        let x1 = run_x1(&mut cache, &mut counts, Some(&out));
        assert!(x1.fresh, "fresh_node witness");
    } // ~FileCache silent

    // X2 (:382-:410) — event built BEFORE the cache; the dtor walk
    // runs with the event alive; the third-and-last acquire (:21)
    // fires at the k2 node insert inside the scope.
    let x2 = run_x2(Some(&out));
    assert!(x2.owns_copy, "event_owns_copy witness");

    push("FCSHARE_PROBE_DONE".to_string()); // :413

    // ---- the line-for-line compare (donor fcap :1134 / fctx :2384) ----
    let want: Vec<&str> = VECTORS.trim_end_matches('\n').lines().collect();
    assert_eq!(want.len(), 25, "vectors.txt must hold exactly 25 lines");
    if std::env::var("FCSHARE_DUMP").is_ok() {
        let got = out.borrow();
        let _ = std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../cache/scratch/fcshare_got.txt"),
            got.join("\n") + "\n",
        );
    }
    let got = out.borrow();
    assert_eq!(got.len(), want.len(), "replay emitted {} lines", got.len());
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors.txt line {}", i + 1);
    }
}

// The 17t default sink (file_cache.rs FileCache::new events field):
// the publish side runs the cc:44 encoder the MP bus would carry,
// the drain side runs cc:63 + handle. The trait stays injectable —
// every fcache/fctx/fflows witness test still overrides `events`
// (431 green unchanged), and NoopFileCacheEventSink stays public for
// explicit opt-out (file_cache.rs:520-:521).
struct SilentPolicy;
impl FilePolicyApi for SilentPolicy {
    fn type_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 { 0 }
    fn signature_lookup(&mut self, _p: &mut PacketView, _file: &mut FileContext) -> u32 { 0 }
    fn log_file_action(&mut self, _flow: &CacheFlow, _file: &mut FileContext, _action: u32) {}
}

/// publish_file_share_sync on the DEFAULT sink (no override): the
/// wire frame lands on cache.mp_wire carrying the exact cc:44
/// encoding (decode back to the filed fields), and drain() stores
/// through cc:63 + the handler thunk.
#[test]
fn v_sink_default_is_file_cache_share() {
    let mut cache = mk_cache(); // default events == FileCacheShareSink (17t wiring)
    let mut counts = FileCounts::default();
    let k = mkkey(1201);
    let ctx = cache.new_file_context();
    {
        let mut b = ctx.borrow_mut();
        b.info.verdict = FILE_VERDICT_BLOCK;
        b.info.set_file_name(Some(b"sink_share.bin"), 14); // exact strlen
        b.info.set_file_id(1201);
    }
    // drive the trait method the way publish_file_cache_event does
    // (file_cache.rs:1945 == C file_cache.cc:571) — same call shape,
    // minus the mp_dbus gate that publish_file_cache_event keeps.
    cache.events.publish_file_share_sync(&k, 3600, &ctx.borrow());
    let frames = cache.mp_wire.borrow().len();
    assert_eq!(frames, 1, "the real default sink ENCODED (Noop would queue nothing)");
    // the wire frame decodes back through deserialized wire == the
    // cc:44 encoding (decode -> filed event == the C bus payload).
    {
        let (buf, len) = cache.mp_wire.borrow()[0].clone();
        assert_eq!(usize::from(len), buf.len(), "(buffer,len) pair == cc:54/cc:58");
        assert!(buf.len() > FILE_MP_EVENT_FIXED_LEN, "name tail present on the wire");
    }
    let drained = FileCacheShareSink::drain(&cache.mp_wire.clone(), &mut cache, &mut counts);
    assert_eq!(drained, 1, "drained 1 frame");
    let node = cache_add(&mut cache, &k, 3600, &mut counts);
    assert_eq!(node.borrow().info.verdict, FILE_VERDICT_BLOCK, "drain stored via handle");
    assert_eq!(node.borrow().info.get_file_name(), b"sink_share.bin", "wire round-trip name");
}

/// The publish half ALSO behind the real mp_dbus gate: store path ->
/// publish_file_cache_event (file_cache.rs:1939, gate :1941 == C
/// :563) -> default sink -> wire frame. Proves the seam swap changes
/// the gated publish behaviour itself, not just direct trait calls.
#[test]
fn v_store_publishes_wire_under_mp_gate() {
    let mut cache = mk_cache();
    cache.conf = Rc::new(RefCell::new(FileConfigView { mp_dbus: true, ..FileConfigView::default() }));
    let mut counts = FileCounts::default();
    let mut pol = SilentPolicy;
    let mut p = PacketView {
        conf: FileConfigView { mp_dbus: true, ..Default::default() },
        ..Default::default()
    };
    let k = mkkey(1302);
    // seed the node the store path expects (probe F-shape: cache_add
    // then store_verdict on the node's own context)
    let file = cache_add(&mut cache, &k, 3600, &mut counts);
    file.borrow_mut().info.set_file_id(1302);
    file.borrow_mut().info.verdict = FILE_VERDICT_UNKNOWN;
    // apply_verdict (BLOCK) -> store_verdict -> the cacheable +
    // mp_dbus-gated publish_file_cache_event (C file_cache.cc:557-:560).
    let applied = cache.apply_verdict(&mut p, &file, FILE_VERDICT_BLOCK, false, &mut pol, &mut counts);
    assert!(applied, "verdict applied + stored");
    let frames = cache.mp_wire.borrow().len();
    assert_eq!(frames, 1, "mp_dbus-gated publish -> wire frame via the 17t sink");
    // drain replays the subscriber thread half: the node now holds
    // its own published verdict through handle -> store_shared_verdict.
    let drained = FileCacheShareSink::drain(&cache.mp_wire.clone(), &mut cache, &mut counts);
    assert_eq!(drained, 1);
    let node = cache_add(&mut cache, &k, 3600, &mut counts);
    assert_eq!(node.borrow().info.verdict, FILE_VERDICT_BLOCK, "subscriber stored BLOCK");
}
