//! Row 17v: `src/file_api/file_api.{h,cc}` — the vocabulary umbrella of the
//! whole file_api subsystem (227 + 43 lines at fe29cbe; ZERO TEST_CASEs,
//! ZERO `#ifdef UNIT_TEST` fragments — the 21-line `tools/fcapi_harness/
//! vectors.txt` oracle, md5 `a953a5017b74f5d44dbba14df48ac5ea`, is the only
//! ground truth: C/E/M/P/S/R arms, PLAN 7).
//!
//! CORRECTION the row PLAN pins against the queue label: this TU is NOT a
//! factory. `file_api.cc` contains ONLY the three `FilePolicyBase`
//! ref-protocol bodies (cc:28-:29 ctor, cc:31-:32 dtor, cc:34-:43
//! `delete_file_policy`) — "No static, no global, no factory" (fcapi PLAN
//! 3). The header is shared vocabulary: 5 dead feature macros (h:37-:41),
//! 8 enums (h:43-:108), the BOM macros (h:50-:51), FileState (h:110-:114),
//! `FILE_ID_MAX`/`FileTypeBitSet` (h:118-:119), FileCacheClearReport
//! (h:121-:125), UserFileDataBase (h:132-:142), FilePolicyBase
//! (h:144-:172), and 6 inline helpers (h:174-:217).
//!
//! CANONICAL HOME (the 17u const-home recipe — items that already rode
//! interim homes MOVE here and the old sites become `pub use` re-exports so
//! every existing binding stays green; 26 parity suites glob these modules):
//!   * 8 enum const-blocks — were file_lib.rs:41-:104 (FileVerdict,
//!     FilePosition, FileCaptureState, FileSigState, FileDirection,
//!     FileCharEncoding + UTF_16_LE_BOM_LEN) and file_cache.rs:308-:310
//!     (FileAction). Wire values pinned by the E_enums vector.
//!   * FileState struct — was file_lib.rs:90-:96 (A_SZ_STATE=8; `fstate=8`).
//!   * get_character_encoding — was file_lib.rs:99-:104 (live at
//!     file_lib.rs:1269/:1693).
//!   * FileCacheClearReport — was file_cache.rs:116-:121 (`fccr=16`).
//!   * FilePolicyApi trait + FilePolicyHandle — were file_cache.rs:545-:626
//!     (the row's actual BODY: the file_api.cc:28-:43 ref protocol that
//!     17q already modeled there; consolidation moved the model VERBATIM,
//!     no design churn — fcapi PLAN 8 item 2).
//!
//! LEAVE-IN-PLACE (explicit rulings, do NOT consolidate):
//!   * `FILE_ID_MAX` stays at file_identifier.rs:21 with its mirror at
//!     file_stats.rs:22 (the fid row's turf; file_config.rs LEFT-OPEN list
//!     rules "not touched by this row" — same ruling 17u). Vector pin
//!     `file_id_max=1024`.
//!   * `FileTypeBitSet` (h:119 `typedef std::bitset<FILE_ID_MAX>`, probed
//!     `bitset=128` = 1024/8*8 — NOT 16): NO new Rust bitset type. The word
//!     form `&mut [u64; FILE_ID_MAX / 64]` (file_identifier.rs:282,
//!     file_config.rs:172) stands; a Rust `[bool; N]`-style wrapper could
//!     never match the 128B pin anyway.
//!   * The four h:219-:224 `SO_PUBLIC` declarations: bodies live in OTHER
//!     TUs and are ALREADY ported — see the decl-map section below. Do NOT
//!     re-port (fcapi PLAN 9-R8: a duplicate Rust fork would split ladders
//!     three transcripts pin).
//!
//! C-ABI size posture (probe C_sz line): `FilePolicyBase=16` (vptr 8 +
//! std::atomic_uint 4 + tail pad 4) and `UserFileDataBase=8` (vptr only)
//! are C++-object facts (a Rust trait object carries a fat-ptr pair, not a
//! C vptr) — pinned in vectors.txt and documented in KNOWN DEVIATIONS
//! rather than asserted via `size_of` (no ported Rust struct replicates
//! those layouts). `size_of::<FileState>() == 8` and
//! `size_of::<FileCacheClearReport>() == 16` DO hold on the ported
//! `#[repr(C)]`/plain-field shapes and are asserted by the parity-style
//! checks where those structs are read.

#![allow(dead_code)] // dead vocabulary (R5) rides here pinned on the wire only

// ==================================================================
// Feature-word macros — file_api.h:37-:41. MEASURED fact (PLAN 9-R5):
// these five defines have ZERO consumers anywhere in the C src tree —
// dead vocabulary in this snapshot. Ported as wire-pinned consts
// (M_flags vector `1,2,4 allon=ffffffff alloff=0`) and DELIBERATELY
// NOT connected to the FileService enable statics (file_service.cc,
// an unported row — conflating the dead masks with the live enable
// path would be a semantic invention the vectors cannot catch).
// ==================================================================

/// file_api.h:37 `#define ENABLE_FILE_TYPE_IDENTIFICATION 0x1` (dead — grep-0 consumers)
pub const ENABLE_FILE_TYPE_IDENTIFICATION: u32 = 0x1;
/// file_api.h:38 `#define ENABLE_FILE_SIGNATURE_SHA256 0x2` (dead)
pub const ENABLE_FILE_SIGNATURE_SHA256: u32 = 0x2;
/// file_api.h:39 `#define ENABLE_FILE_CAPTURE 0x4` (dead)
pub const ENABLE_FILE_CAPTURE: u32 = 0x4;
/// file_api.h:40 `#define FILE_ALL_ON 0xFFFFFFFF` (dead)
pub const FILE_ALL_ON: u32 = 0xFFFF_FFFF;
/// file_api.h:41 `#define FILE_ALL_OFF 0x00000000` (dead)
pub const FILE_ALL_OFF: u32 = 0x0000_0000;

// ==================================================================
// BOM macros — file_api.h:50-:51. `UTF_16_LE_BOM "\xFF\xFE"` +
// `UTF_16_LE_BOM_LEN 2` (M_flags vector `bom_len=2 b0=255 b1=254`).
// The byte pair used to be inlined at file_lib.rs:101; the LEN const
// moves here from file_lib.rs:32 (re-export keeps that binding green).
// ==================================================================

/// file_api.h:50 `#define UTF_16_LE_BOM "\xFF\xFE"` (decimal pair pin b0=255 b1=254)
pub const UTF_16_LE_BOM: [u8; 2] = [0xFF, 0xFE];
/// file_api.h:51 `#define UTF_16_LE_BOM_LEN 2`
pub const UTF_16_LE_BOM_LEN: usize = 2;

// ==================================================================
// The eight enums (C wire values = the E_enums vector; all 4-byte
// ints upstream — pin "SZ_VERDICT=4 SZ_DIR=4 SZ_CAPST=4 SZ_SIGST=4"
// from the filib A_SZ transcript; u32 through the move, never
// isize/i32, fcapi PLAN 9-R6). NOTE the header declares these OUTSIDE
// namespace snort (the namespace opens h:116, after FileState).
// ==================================================================

/// file_api.h:43-:48 `enum FileAction` (interim home file_cache.rs:308-:310).
pub const FILE_ACTION_DEFAULT: u32 = 0; // h:45
pub const FILE_RESUME_BLOCK: u32 = 1; // h:46
pub const FILE_RESUME_LOG: u32 = 2; // h:47

/// file_api.h:53-:63 `enum FileVerdict` (interim home file_lib.rs:41-:48;
/// filib A_ENUMS pins vU..vM=0..7).
pub const FILE_VERDICT_UNKNOWN: u32 = 0; // h:55
pub const FILE_VERDICT_LOG: u32 = 1; // h:56
pub const FILE_VERDICT_STOP: u32 = 2; // h:57
pub const FILE_VERDICT_BLOCK: u32 = 3; // h:58
pub const FILE_VERDICT_REJECT: u32 = 4; // h:59
pub const FILE_VERDICT_PENDING: u32 = 5; // h:60
pub const FILE_VERDICT_STOP_CAPTURE: u32 = 6; // h:61
pub const FILE_VERDICT_MAX: u32 = 7; // h:62

/// file_api.h:65-:72 `enum FilePosition` (interim home file_lib.rs:63-:67;
/// E_pos `0,1,2,3,4`).
pub const SNORT_FILE_POSITION_UNKNOWN: u32 = 0; // h:67
pub const SNORT_FILE_START: u32 = 1; // h:68
pub const SNORT_FILE_MIDDLE: u32 = 2; // h:69
pub const SNORT_FILE_END: u32 = 3; // h:70
pub const SNORT_FILE_FULL: u32 = 4; // h:71

/// file_api.h:74-:81 `enum FileCaptureState` (interim home file_lib.rs:70-:74).
pub const FILE_CAPTURE_SUCCESS: u32 = 0; // h:76
pub const FILE_CAPTURE_MIN: u32 = 1; // h:77 "smaller than file capture min"
pub const FILE_CAPTURE_MAX: u32 = 2; // h:78 "larger than file capture max"
pub const FILE_CAPTURE_MEMCAP: u32 = 3; // h:79 "memcap reached, no more file buffer"
pub const FILE_CAPTURE_FAIL: u32 = 4; // h:80 "Other file capture failures"

/// file_api.h:83-:89 `enum FileSigState` (interim home file_lib.rs:77-:80).
pub const FILE_SIG_PROCESSING: u32 = 0; // h:85
pub const FILE_SIG_DEPTH_FAIL: u32 = 1; // h:86 "larger than file signature depth"
pub const FILE_SIG_FLUSH: u32 = 2; // h:87
pub const FILE_SIG_DONE: u32 = 3; // h:88

/// file_api.h:91-:96 `enum FileProcessType`. MEASURED (PLAN 3/9-R5): the
/// enum is declared and NEVER used as a parameter type anywhere in src
/// (file_flows.cc:503 picks FileDirection) — dead vocabulary; consts join
/// as wire pins only (E_ptype `0,1,2`), no behavior vectors exist.
pub const SNORT_FILE_TYPE_ID: u32 = 0; // h:93
pub const SNORT_FILE_SHA256: u32 = 1; // h:94
pub const SNORT_FILE_CAPTURE: u32 = 2; // h:95

/// file_api.h:98-:102 `enum FileDirection` (interim home file_lib.rs:83-:84;
/// LIVE side: file_lib.h:137 member default, file_flows.cc:503,
/// file_cache.cc:1097).
pub const FILE_DOWNLOAD: u32 = 0; // h:100
pub const FILE_UPLOAD: u32 = 1; // h:101

/// file_api.h:104-:108 `enum FileCharEncoding` (interim home file_lib.rs:87-:88;
/// LIVE: [`get_character_encoding`] return + file_lib.cc:87/:662).
pub const SNORT_CHAR_ENCODING_ASCII: u32 = 0; // h:106
pub const SNORT_CHAR_ENCODING_UTF_16LE: u32 = 1; // h:107

// ==================================================================
// namespace snort opens h:116.
//   * h:118 `#define FILE_ID_MAX 1024` — LEAVES at file_identifier.rs:21
//     (+ the file_stats.rs:22 mirror): fid row turf, 17u ruling carried
//     (vector pin `file_id_max=1024`).
//   * h:119 `typedef std::bitset<FILE_ID_MAX> FileTypeBitSet` —
//     sizeof=128 probed (`bitset=128`); NO Rust wrapper type (witness
//     posture, PLAN 6) — the word form `&mut [u64; FILE_ID_MAX / 64]`
//     used by the get/process-rule forwarders stands.
// ==================================================================

/// file_api.h:121-:125 `struct FileCacheClearReport` (interim home
/// file_cache.rs:116-:121). The two in-class `= 0` initializers stand
/// (hand-defaulted fields; derive(Default) here is equivalent but was
/// already hand-exact at the old site — moved VERBATIM). LIVE:
/// FileCache::clear() return (file_cache.cc:457), file_service.h:61.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileCacheClearReport {
    pub freed: u64, // h:123 `uint64_t freed = 0;`
    pub remaining: u64, // h:124 `uint64_t remaining = 0;`
}

/// file_service.h:47-:54 `enum class FileCacheClearStatus : uint8_t` —
/// row 17y landing (the 5-arm ladder's home; the V1_enum vector pins
/// the wire values r=0 m=1 u=2 n=3 b=4, sizeof=1 per V1_sizes `st=1`).
/// LIVE: FileService::get_file_cache_clear_status() (file_service.cc:86)
/// + the FileCacheClearResult default field (h:60, UNAVAILABLE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FileCacheClearStatus {
    Ready = 0, // h:50 READY
    Multiprocess = 1, // h:50 MULTIPROCESS
    Unavailable = 2, // h:51 UNAVAILABLE (the h:60 default)
    NotInitialized = 3, // h:52 NOT_INITIALIZED
    PacketThreadsBusy = 4, // h:53 PACKET_THREADS_BUSY
}

impl Default for FileCacheClearStatus {
    /// h:60 `FileCacheClearStatus status = UNAVAILABLE;`
    fn default() -> Self {
        FileCacheClearStatus::Unavailable
    }
}

/// file_service.h:56-:62 `struct FileCacheClearResult` — row 17y.
/// sizeof=24 pinned by the fsvc V1_sizes line `rs=24` (report 16 +
/// u8 status + 7 pad); `def=2` pins the default status rendering AS
/// the UNAVAILABLE enum ordinal. LIVE: FileService::clear_file_cache()
/// (file_service.cc:107) return.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileCacheClearResult {
    pub status: FileCacheClearStatus, // h:60 (UNAVAILABLE default)
    pub report: FileCacheClearReport, // h:61
}

/// file_api.h:110-:114 `struct FileState` (interim home file_lib.rs:90-:96;
/// A_SZ_STATE=8 = vector `fstate=8`). LIVE: file_lib.h:146 default
/// `{ FILE_CAPTURE_SUCCESS, FILE_SIG_PROCESSING }`, consumed
/// file_policy.cc:210 (unported row).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FileState {
    pub capture_state: u32, // h:112 FileCaptureState
    pub sig_state: u32, // h:113 FileSigState
}

// ==================================================================
// class UserFileDataBase — file_api.h:132-:142.
//   * h:135 defaulting ctor / h:136 virtual dtor — live side only ever
//     `new UserFileDataBase` + delete (file_cache.cc:1176; set/get at
//     file_lib.cc:541/:554; dup check file_cache.cc:426).
//   * h:137 copy ctor, h:138 copy-assign, h:141 private `void copy(
//     const UserFileDataBase&)` are DECLARED ONLY and measured fact
//     (PLAN 3 / 9-R4): **zero definitions anywhere in the C tree**
//     (`grep -rn 'UserFileDataBase::' src` -> 0 hits at fe29cbe,
//     re-verified this session). Any C TU that copies one is a LINK
//     ERROR; porting Rust equivalents would fabricate behavior that the
//     linker itself forbids. LEFT-OPEN posture with the trait shape kept
//     exactly as 17o landed it (moved from file_lib.rs:107-:111; the
//     file_lib.rs re-export keeps `tests/fcache_parity_test.rs:50` and
//     friends green).
//   * `sizeof(UserFileDataBase)=8` (vptr only) is the C line `ufd=8` —
//     not reproducible in Rust (no vptr), documented not asserted.
// ==================================================================

/// C `UserFileDataBase` (file_api.h:132-:142) — opaque here; the copy()/
/// clear_data path only ever deletes it (E0 `ufd=0`). The copy ctor /
/// copy-assign / copy() trio stays UNPORTED: no bodies exist in the C
/// tree (grep-0 — see KNOWN DEVIATIONS row 17v; fabricating them = the
/// dead-body trap).
pub trait UserFileDataBase {
    fn as_any(&self) -> &dyn std::any::Any;
}

// ==================================================================
// class SO_PUBLIC FilePolicyBase — file_api.h:144-:172, bodies
// file_api.cc:28-:43 (the ONLY contents of the .cc, PLAN 3).
// ==================================================================

use super::file_cache::CacheFlow;
use super::file_lib::FileContext;

/// `FilePolicyBase` virtuals (file_api.h:151-:163; concrete impl:
/// file_policy.cc row — unported). Moved VERBATIM from file_cache.rs:
/// 545-:556 (interim home since 17q).
pub trait FilePolicyApi {
    /// file_api.h:152-:153 `virtual void policy_check(Flow*, FileInfo*) { }`
    /// — reached from FileContext::check_policy (file_lib.cc:763, 17q;
    /// C base no-op, the harness stub prints "POLICY policy_check").
    /// Default = the C base-class empty body.
    fn policy_check(&mut self, _flow: &CacheFlow, _file: &mut FileContext) {}
    /// file_api.h:155-:157 `virtual FileVerdict type_lookup(Packet*, FileInfo*)
    /// { return FILE_VERDICT_UNKNOWN; }` — inline default.
    fn type_lookup(&mut self, p: &mut PacketView, file: &mut FileContext) -> u32;
    /// file_api.h:159-:161 `virtual FileVerdict signature_lookup(...)` —
    /// inline default (C default body = FILE_VERDICT_UNKNOWN; kept
    /// REQUIRED so every impl states the answer, 17q posture carried).
    fn signature_lookup(&mut self, p: &mut PacketView, file: &mut FileContext) -> u32;
    /// file_api.h:163 `virtual void log_file_action(Flow*, FileInfo*, FileAction) { }`
    fn log_file_action(&mut self, flow: &CacheFlow, file: &mut FileContext, action: u32);
}

/// `FilePolicyBase*` (file_api.h:144-:172) ownership handle — the row's
/// actual BODY, the file_api.cc:28-:43 ref protocol that 17q modeled and
/// 17v moves HERE from file_cache.rs:558-:626 (design NOT "improved" in
/// transit — fcapi PLAN 8 item 2). The C ref protocol is a raw atomic
/// ref_count with `add_ref()` (h:165-:166) and the static
/// `delete_file_policy` (h:168 -> file_api.cc:34: `if (policy) {
/// assert(policy->ref_count); unsigned ref = --policy->ref_count; if
/// (!ref) delete policy; }`). The port wraps `Rc<FilePolicyBox>`...
/// simpler: an Rc-based clone-count model is WRONG for the pinned witness
/// reads (refs=1->2, policy_refs=2->1 read the C atomic member directly),
/// so the handle carries an explicit counter over a Box, mirroring the C
/// member; the clone-discipline at the C sites (set_file_policy pair,
/// NetworkPolicy-owned base) is the driver's. `ref_count()` answers the
/// probe read.
///
/// Deviation posture carried with the move (PLAN 9-R2 — do not drop it):
/// `std::atomic_uint` (h:171) is seq_cst; the Rust port uses a plain u32
/// (17p/17q precedent: "mutex/atomics not reproduced") — single-threaded
/// probe, observationally identical. Rust posture for
/// `delete_file_policy(null)`: Option None at callers (17q doc: "the C
/// null-argument arm = the port's Option-slot None"; vector
/// `R_del_null silent=1` pins the C arm). Rust posture for the two LIVE
/// C asserts (cc:32 `assert(!ref_count)` in the dtor, cc:38
/// `assert(policy->ref_count)` the underflow guard): debug_assert here;
/// the harness link has NO -DNDEBUG so the C arm ABORTS (the R ladder
/// never dares probe cc:38 — pinned-panic posture, KNOWN DEVIATIONS 17v).
#[derive(Clone)]
pub struct FilePolicyHandle {
    inner: std::rc::Rc<std::cell::RefCell<PolicyStore>>,
}

struct PolicyStore {
    policy: Box<dyn FilePolicyApi>,
    /// std::atomic_uint ref_count (file_api.h:171)
    ref_count: u32,
}

impl FilePolicyHandle {
    /// C `new FilePolicy` sites yield ref_count == 1
    /// (file_api.cc:28-:29 `FilePolicyBase() { ref_count = 1; }` — the
    /// ctor SETS 1, it does not default-init then increment; fresh
    /// object held once, like a `new`). Vector `R_ctor ref=1`.
    pub fn new_boxed(policy: Box<dyn FilePolicyApi>) -> FilePolicyHandle {
        FilePolicyHandle {
            inner: std::rc::Rc::new(std::cell::RefCell::new(PolicyStore {
                policy,
                ref_count: 1,
            })),
        }
    }
    /// `void add_ref() { ++ref_count; }` (file_api.h:165-:166). Vector
    /// `R_addref ref=2`.
    pub fn add_ref(&mut self) {
        self.inner.borrow_mut().ref_count += 1;
    }
    /// `static void delete_file_policy(FilePolicyBase* policy)`
    /// (file_api.cc:34-:43) on the handle's own object: decrement; at 0
    /// the Box drops (C `delete policy`; ~FilePolicyBase asserts
    /// !ref_count — already 0). The C null-argument arm = the port's
    /// Option-slot None (callers pass through Option). Vectors
    /// `R_del1 ref=1` (pre-decrement read-back cc:39) / `R_del0 gone=1`
    /// (cc:40-:41 delete).
    pub fn delete_file_policy(&mut self) {
        let mut st = self.inner.borrow_mut();
        debug_assert!(st.ref_count > 0); // assert(policy->ref_count) cc:38
        st.ref_count -= 1; // unsigned ref = --policy->ref_count  cc:39
    }
    pub fn ref_count(&self) -> u32 {
        self.inner.borrow().ref_count
    }
    /// C pointer-identity compare `policy == stub_file_policy()` /
    /// `static_pol == pol` (file_flows probe B_CREATE / get_file_policy
    /// static): two handles front the same object iff they share the
    /// store (the C raw pointers compare by address).
    pub fn same_store(&self, other: &FilePolicyHandle) -> bool {
        std::rc::Rc::ptr_eq(&self.inner, &other.inner)
    }
    /// Borrow the object (null-ness = C `if (!fp)` arms).
    pub fn is_null(&self) -> bool {
        false // the handle type only ever fronts a real object
    }
    /// Run a closure with `&mut dyn FilePolicyApi` — the C raw-pointer
    /// call shape (file_policy->signature_lookup(...) etc.).
    pub fn with_policy_mut<R, F: FnOnce(&mut dyn FilePolicyApi) -> R>(&mut self, f: F) -> R {
        let mut st = self.inner.borrow_mut();
        f(st.policy.as_mut())
    }
    /// Read the object immutably.
    pub fn with_policy<R, F: FnOnce(&dyn FilePolicyApi) -> R>(&self, f: F) -> R {
        let st = self.inner.borrow();
        f(st.policy.as_ref())
    }
}

/// `PacketView` re-export so the moved trait's signatures resolve at this
/// home while the struct itself stays file_cache.rs turf (the 17p-pinned
/// by-value view; NOT moved — consolidation touches vocabulary, not the
/// pinned packet view).
use super::file_cache::PacketView;

// ==================================================================
// The six inline helpers — file_api.h:174-:217. The ONLY unported live
// code this row found (PLAN 6: initFilePosition/updateFilePosition/
// finalFilePosition/isFileStart/isFileEnd ABSENT grep-0; upstream
// consumers ftpdata_splitter.cc:131/:132, ftp_data.cc:190/:196/:257/:258,
// imap.cc:521, smtp.cc:1093, pop.cc:471, file_mime_process.cc x10 —
// never gated upstream, so the P/S vectors ARE their truth).
//
// C's `FilePosition*` in/out pointer is a calling convention (C lacks
// return tuples); the Rust form is value-in/value-out and the vectors
// pin BOTH in and out states (PLAN 7 P block).
// ==================================================================

/// file_api.h:174-:179 `initFilePosition(FilePosition* position, uint64_t
/// processed_size)`: `*position = SNORT_FILE_START; if (processed_size)
/// *position = SNORT_FILE_MIDDLE;`. Vectors `P_init0 pos=1` /
/// `P_init7 pos=2`.
pub fn init_file_position(_position: u32, processed_size: u64) -> u32 {
    // C overwrites the out-param WITHOUT reading it (h:176 unconditional
    // first store) — hence the underscore binding; the E-in form exists
    // so call sites transcribe positionally.
    let mut position = SNORT_FILE_START; // h:176
    if processed_size != 0 {
        position = SNORT_FILE_MIDDLE; // h:178
    }
    position
}

/// file_api.h:181-:187 `updateFilePosition(FilePosition* position,
/// uint64_t processed_size)`: the (END|FULL)->START reset arm PRECEDES
/// the MIDDLE arm (h:183, so `P_upd_full9 pos=1` even with data); the
/// else-UNCHANGED arm keeps UNKNOWN alive (`P_upd_unk0 pos=0` — measured
/// quirk pin vs [`final_file_position`] below).
pub fn update_file_position(position: u32, processed_size: u64) -> u32 {
    if position == SNORT_FILE_END || position == SNORT_FILE_FULL {
        SNORT_FILE_START // h:184 (arm checked FIRST — h:183)
    } else if processed_size != 0 {
        SNORT_FILE_MIDDLE // h:186
    } else {
        position // else UNCHANGED (UNKNOWN stays UNKNOWN — upd_unk0=0)
    }
}

/// file_api.h:189-:195 `finalFilePosition(FilePosition* position)`:
/// START -> FULL; else if != FULL -> END. QUIRK (h:193 has NO UNKNOWN
/// guard — measured `P_fin_unk pos=3`, UNKNOWN -> END): pin-not-fix
/// (PLAN 9-R7 — the future mime row's INIT->...->FINAL ladder depends
/// on this exact promotion).
pub fn final_file_position(position: u32) -> u32 {
    if position == SNORT_FILE_START {
        SNORT_FILE_FULL // h:192
    } else if position != SNORT_FILE_FULL {
        SNORT_FILE_END // h:194 — the un-guarded else-if (UNKNOWN lands here)
    } else {
        position // FULL stays FULL
    }
}

/// file_api.h:197-:200 `isFileStart(FilePosition position)`:
/// `(position == SNORT_FILE_START) || (position == SNORT_FILE_FULL)` —
/// measured truth table `P_isstart 01001` over (UNK,START,MID,END,FULL).
pub fn is_file_start(position: u32) -> bool {
    position == SNORT_FILE_START || position == SNORT_FILE_FULL
}

/// file_api.h:202-:205 `isFileEnd(FilePosition position)`:
/// `(position == SNORT_FILE_END) || (position == SNORT_FILE_FULL)` —
/// measured `P_isend 00011`.
pub fn is_file_end(position: u32) -> bool {
    position == SNORT_FILE_END || position == SNORT_FILE_FULL
}

/// file_api.h:207-:217 `get_character_encoding(const char* file_name,
/// size_t length)` — moved VERBATIM from file_lib.rs:99-:104 (the
/// `&[u8]` borrow form stands). Default ASCII; only when `length >=
/// UTF_16_LE_BOM_LEN` does the memcmp read EXACTLY 2 bytes — no OOB on
/// len-1 input, pin by construction. Measured arms (vector
/// `S_enc short=0 nonbom=0 bom=1 partial=0`): len<2 with 0xFF -> ASCII;
/// 2 non-BOM bytes -> ASCII; BOM+tail -> UTF_16LE; reversed pair ->
/// ASCII. LIVE consumers file_lib.cc:87 (get_UTF8_fname cluster) and
/// file_lib.cc:662 — ported homes keep calling through the re-export.
pub fn get_character_encoding(file_name: &[u8], length: usize) -> u32 {
    let mut encoding = SNORT_CHAR_ENCODING_ASCII;
    if length >= UTF_16_LE_BOM_LEN && file_name[..UTF_16_LE_BOM_LEN] == UTF_16_LE_BOM {
        encoding = SNORT_CHAR_ENCODING_UTF_16LE;
    }
    encoding
}

// ==================================================================
// The four outbound SO_PUBLIC declarations — file_api.h:219-:224.
// This TU DECLARES them; the bodies live in OTHER TUs (link fact,
// PLAN 9-R8: "the umbrella TU owns these symbols" is WRONG at link
// time) and every one is ALREADY ported. Re-export/re-map decls below
// so `file_api::` names resolve to the ported bodies WITHOUT a second
// implementation (the fflows/fconf transcripts pin their ladders).
// ==================================================================

/// h:219 `SO_PUBLIC uint64_t get_file_processed_size(Flow* flow);` — body
/// **file_service.cc:256** (NOT this TU); ported home
/// `file_flows::get_file_processed_size` (file_flows.rs, 17q). Body kept
/// there — re-exported name only.
pub use super::file_flows::get_file_processed_size;
/// h:220 `SO_PUBLIC FilePosition get_file_position(Packet* pkt);` — body
/// **file_flows.cc:61** per the fcapi PLAN 3 measurement (the file_api.cc
/// half of the PLAN row-note's "re-declares the two snort:: shims" wording
/// is NEXT.md's stale line map; the .cc has ONE include and three
/// functions, so the decls ride the header only); ported home
/// `file_flows::get_file_position` (F_POSITION ladder, 17q).
pub use super::file_flows::get_file_position;
/// h:221-:222 `SO_PUBLIC void set_rule_id_from_type(SnortConfig*, uint64_t
/// id, std::string type, std::string file_category, std::string
/// file_version, std::vector<std::string> file_groups);` — body
/// **file_config.cc:115-:127**; ported home `file_config::
/// set_rule_id_from_type` (row 17u).
pub use super::file_config::set_rule_id_from_type;
/// h:223-:224 `SO_PUBLIC void get_magic_rule_ids_from_type(const
/// std::string& type, const std::string& version, FileTypeBitSet& ids_set,
/// SnortConfig*);` — body **file_config.cc:104-:113**; ported home
/// `file_config::get_magic_rule_ids_from_type` (row 17u; the M4
/// null-conf `ids_set.reset()` sentinel already pinned there).
pub use super::file_config::get_magic_rule_ids_from_type;
