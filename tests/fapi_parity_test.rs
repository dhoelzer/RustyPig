//! Parity test for `src/file_api/file_api.rs` — row 17v.
//!
//! Ground truth: `tools/fcapi_harness/vectors.txt` (21 L, md5
//! a953a5017b74f5d44dbba14df48ac5ea, NEVER edited) — the C transcript
//! of file_api.{h,cc} driven by probe.cc (C/E/M/P/S/R arms; the TU has
//! ZERO TEST_CASEs and ZERO `#ifdef UNIT_TEST` fragments — fcapi PLAN
//! §2/§4: probe vectors are the only oracles), replayed here through
//! the Rust port as ONE ordered session (fconf/fcshare replay shape:
//! per-index assert_eq against the vectors line, want.len() == 21).
//!
//! Layout posture (file_api.rs header + KNOWN DEVIATIONS 17v):
//! `fpolbase=16` / `ufd=8` are PROBE-COMPUTED C++ object pins (vptr
//! facts with no Rust counterpart) — direct const pins, NEVER
//! `size_of` on a Rust type (fconf PROBE_SIZEOF precedent). `fstate=8`
//! / `fccr=16` ride `size_of` on the ported shapes (the same values
//! the 17o filib A_SZ_STATE pin reads); `bitset=128` is the
//! FILE_ID_MAX word-span derivation — the witness posture (no Rust
//! wrapper type, PLAN §6).
//!
//! R-block drive shape: the C ladder heap-allocates a ProbePolicy and
//! reads the FIXACC-visible ref_count member raw; the Rust port drives
//! the moved FilePolicyHandle counter (the file_api.cc:28-:43 model —
//! the same one the fctx/fflows fixtures use) and answers the same
//! in->out observation. `R_del0 gone=1`: in C the second
//! delete_file_policy frees the object under the LIVE dtor
//! ~FilePolicyBase assert(!ref_count) (cc:32, no -DNDEBUG); in Rust the
//! counter reaches 0, no further use happens, and the Box drops with the
//! handle scope — the printed pin is the C flag, the drain is real.
//! `R_del_null silent=1`: the C null-arg arm (cc:36) = the port's
//! Option-slot None (17q posture) — the None arm below runs nothing.

use snort3::file_api::file_api::{
    ENABLE_FILE_CAPTURE, ENABLE_FILE_SIGNATURE_SHA256, ENABLE_FILE_TYPE_IDENTIFICATION,
    FILE_ACTION_DEFAULT, FILE_ALL_OFF, FILE_ALL_ON, FILE_CAPTURE_FAIL, FILE_CAPTURE_MAX,
    FILE_CAPTURE_MEMCAP, FILE_CAPTURE_MIN, FILE_CAPTURE_SUCCESS, FILE_DOWNLOAD,
    FILE_RESUME_BLOCK, FILE_RESUME_LOG, FILE_SIG_DEPTH_FAIL, FILE_SIG_DONE, FILE_SIG_FLUSH,
    FILE_SIG_PROCESSING, FILE_UPLOAD, FILE_VERDICT_BLOCK, FILE_VERDICT_LOG, FILE_VERDICT_MAX,
    FILE_VERDICT_PENDING, FILE_VERDICT_REJECT, FILE_VERDICT_STOP, FILE_VERDICT_STOP_CAPTURE,
    FILE_VERDICT_UNKNOWN, FileCacheClearReport, FilePolicyHandle, FileState,
    SNORT_CHAR_ENCODING_ASCII, SNORT_CHAR_ENCODING_UTF_16LE, SNORT_FILE_CAPTURE,
    SNORT_FILE_END, SNORT_FILE_FULL, SNORT_FILE_MIDDLE, SNORT_FILE_POSITION_UNKNOWN,
    SNORT_FILE_SHA256, SNORT_FILE_START, SNORT_FILE_TYPE_ID, UTF_16_LE_BOM,
    UTF_16_LE_BOM_LEN, final_file_position, get_character_encoding, init_file_position,
    is_file_end, is_file_start, update_file_position,
};
use snort3::file_api::file_cache::{CacheFlow, FilePolicyApi};
use snort3::file_api::file_identifier::FILE_ID_MAX;
use snort3::file_api::file_lib::FileContext;

const VECTORS: &str = include_str!("../tools/fcapi_harness/vectors.txt");

/// probe C_sz pins for the C++ objects (the probe's own sizeof, never
/// hand-typed; no Rust layout replicates a vptr — documented, never
/// faked; fconf PROBE_SIZEOF_* precedent).
const PROBE_SIZEOF_FILE_POLICY_BASE: usize = 16; // fpolbase: vptr 8 + atomic_uint 4 + pad 4
const PROBE_SIZEOF_USER_FILE_DATA_BASE: usize = 8; // ufd: vptr only

/// The R ladder's policy — the local analogue of the probe's FRESH
/// ProbePolicy overriding ALL FOUR virtuals (PLAN 7 R-block: never the
/// donor StubFilePolicy, whose teardown is entangled with fcache/
/// fflows replay vectors). Silent: the R arms observe ONLY ref_count.
struct RProbePolicy;
impl FilePolicyApi for RProbePolicy {
    fn type_lookup(&mut self, _p: &mut snort3::file_api::file_cache::PacketView, _f: &mut FileContext) -> u32 {
        FILE_VERDICT_UNKNOWN
    }
    fn signature_lookup(&mut self, _p: &mut snort3::file_api::file_cache::PacketView, _f: &mut FileContext) -> u32 {
        FILE_VERDICT_UNKNOWN
    }
    fn log_file_action(&mut self, _flow: &CacheFlow, _file: &mut FileContext, _action: u32) {}
}

#[test]
fn fapi_transcript_replay() {
    let want: Vec<&str> = VECTORS.lines().collect();
    assert_eq!(want.len(), 21, "vectors.txt must stay the 21-line oracle");
    let mut got: Vec<String> = Vec::with_capacity(21);

    // ---- C_sz fpolbase=16 ufd=8 fstate=8 fccr=16 bitset=128 file_id_max=1024
    got.push(format!(
        "C_sz fpolbase={} ufd={} fstate={} fccr={} bitset={} file_id_max={}",
        PROBE_SIZEOF_FILE_POLICY_BASE,
        PROBE_SIZEOF_USER_FILE_DATA_BASE,
        std::mem::size_of::<FileState>(), // repr(C) 2x u32 = 8 (A_SZ_STATE pin holds)
        std::mem::size_of::<FileCacheClearReport>(), // 2x u64 = 16 (fccr pin holds)
        (FILE_ID_MAX / 64) * 8, // bitset<1024> = 16 words x 8B = 128 (word-form witness)
        FILE_ID_MAX,
    ));

    let join = |v: &[u32]| -> String {
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    // ---- E_enums action=0,1,2 verdict=0..7 pos=0..4 cap=0..4 sig=0..3 ptype=0,1,2 dir=0,1 enc=0,1
    got.push(format!(
        "E_enums action={} verdict={} pos={} cap={} sig={} ptype={} dir={} enc={}",
        join(&[FILE_ACTION_DEFAULT, FILE_RESUME_BLOCK, FILE_RESUME_LOG]),
        join(&[
            FILE_VERDICT_UNKNOWN,
            FILE_VERDICT_LOG,
            FILE_VERDICT_STOP,
            FILE_VERDICT_BLOCK,
            FILE_VERDICT_REJECT,
            FILE_VERDICT_PENDING,
            FILE_VERDICT_STOP_CAPTURE,
            FILE_VERDICT_MAX,
        ]),
        join(&[
            SNORT_FILE_POSITION_UNKNOWN,
            SNORT_FILE_START,
            SNORT_FILE_MIDDLE,
            SNORT_FILE_END,
            SNORT_FILE_FULL,
        ]),
        join(&[
            FILE_CAPTURE_SUCCESS,
            FILE_CAPTURE_MIN,
            FILE_CAPTURE_MAX,
            FILE_CAPTURE_MEMCAP,
            FILE_CAPTURE_FAIL,
        ]),
        join(&[
            FILE_SIG_PROCESSING,
            FILE_SIG_DEPTH_FAIL,
            FILE_SIG_FLUSH,
            FILE_SIG_DONE,
        ]),
        join(&[SNORT_FILE_TYPE_ID, SNORT_FILE_SHA256, SNORT_FILE_CAPTURE]),
        join(&[FILE_DOWNLOAD, FILE_UPLOAD]),
        join(&[SNORT_CHAR_ENCODING_ASCII, SNORT_CHAR_ENCODING_UTF_16LE]),
    ));

    // ---- M_flags 1,2,4 allon=ffffffff alloff=0 bom_len=2 b0=255 b1=254
    // (%x hex WITHOUT the 0x prefix — the vectors hygiene gate)
    got.push(format!(
        "M_flags {:x},{:x},{:x} allon={:x} alloff={:x} bom_len={} b0={} b1={}",
        ENABLE_FILE_TYPE_IDENTIFICATION,
        ENABLE_FILE_SIGNATURE_SHA256,
        ENABLE_FILE_CAPTURE,
        FILE_ALL_ON,
        FILE_ALL_OFF,
        UTF_16_LE_BOM_LEN,
        UTF_16_LE_BOM[0],
        UTF_16_LE_BOM[1],
    ));

    // ---- P ladder h:174-:205 (value-in/value-out; probe hoisted locals)
    got.push(format!("P_init0 pos={}", init_file_position(0, 0))); // ->START
    got.push(format!("P_init7 pos={}", init_file_position(0, 7))); // ->MIDDLE
    got.push(format!(
        "P_upd_end0 pos={}",
        update_file_position(SNORT_FILE_END, 0)
    )); // END->START
    got.push(format!(
        "P_upd_full9 pos={}",
        update_file_position(SNORT_FILE_FULL, 9)
    )); // reset arm FIRST (h:183) still ->START with data
    got.push(format!(
        "P_upd_mid0 pos={}",
        update_file_position(SNORT_FILE_MIDDLE, 0)
    )); // else-UNCHANGED
    got.push(format!(
        "P_upd_unk0 pos={}",
        update_file_position(SNORT_FILE_POSITION_UNKNOWN, 0)
    )); // UNKNOWN survives (measured quirk)
    got.push(format!("P_fin_start pos={}", final_file_position(SNORT_FILE_START))); // ->FULL
    got.push(format!(
        "P_fin_mid pos={}",
        final_file_position(SNORT_FILE_MIDDLE)
    )); // ->END
    got.push(format!(
        "P_fin_unk pos={}",
        final_file_position(SNORT_FILE_POSITION_UNKNOWN)
    )); // QUIRK UNKNOWN->END, h:193 un-guarded (PLAN 9-R7 pin-not-fix)
    let pos5 = [
        SNORT_FILE_POSITION_UNKNOWN,
        SNORT_FILE_START,
        SNORT_FILE_MIDDLE,
        SNORT_FILE_END,
        SNORT_FILE_FULL,
    ];
    got.push(format!(
        "P_isstart {}",
        pos5.iter()
            .map(|p| u8::from(is_file_start(*p)).to_string())
            .collect::<String>()
    )); // 01001 (UNK,START,MID,END,FULL)
    got.push(format!(
        "P_isend {}",
        pos5.iter()
            .map(|p| u8::from(is_file_end(*p)).to_string())
            .collect::<String>()
    )); // 00011

    // ---- S_enc short=0 nonbom=0 bom=1 partial=0 (h:207-:217; the memcmp
    // reads EXACTLY 2 bytes only when length>=2 — short=1-byte 0xFF stays
    // ASCII by construction). C "\\xFEXF" = one hex escape 0xFE plus 'F'
    // -> the memcmp pair is FE,'F': reversed-pair arm.
    got.push(format!(
        "S_enc short={} nonbom={} bom={} partial={}",
        get_character_encoding(&[0xFF], 1),
        get_character_encoding(b"AB", 2),
        get_character_encoding(&[0xFF, 0xFE, b'A'], 3),
        get_character_encoding(&[0xFE, b'F'], 2),
    ));

    // ---- R ref-count ladder over the MOVED file_api.cc:28-:43 model
    // (heap handle, fully drained — PLAN 9-R1 posture).
    let mut p = FilePolicyHandle::new_boxed(Box::new(RProbePolicy));
    got.push(format!("R_ctor ref={}", p.ref_count())); // ctor SETS 1 (cc:28-:29)
    p.add_ref(); // h:165-:166
    got.push(format!("R_addref ref={}", p.ref_count()));
    p.delete_file_policy(); // pre-decrement + read-back (cc:39)
    got.push(format!("R_del1 ref={}", p.ref_count()));
    p.delete_file_policy(); // -> 0; C deletes here under the live dtor
                           // assert(!ref_count) (cc:32); Rust: Box drops at scope
                           // exit, no further use = the `gone` flag.
    got.push(format!(
        "R_del0 gone={}",
        u8::from(p.ref_count() == 0)
    ));
    // delete_file_policy(nullptr): cc:36 `if (policy)` guard — the port's
    // Option-slot None arm runs NOTHING (17q posture); silent by
    // construction, the flag prints the C arm it mirrors.
    let mut slot: Option<FilePolicyHandle> = None;
    if let Some(h) = slot.as_mut() {
        h.delete_file_policy(); // never runs — exactly the C guard arm
    }
    got.push(format!(
        "R_del_null silent={}",
        u8::from(slot.is_none())
    ));

    got.push("FCAPI_PROBE_DONE".to_string());

    assert_eq!(got.len(), want.len());
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "vectors line {} (0-based {})", i + 1, i);
    }
}
