//! Literal port of file_api/file_lib.{h,cc} — the FileInfo half.
//!
//! Ground truth: /opt/data/snort3-src @ fe29cbe7403a, harness
//! `tools/filib_harness` (transcript `vectors.txt`, gate = the TU's own
//! 19 [file_info] Catch cases). NEXT.md row 17o scope: FileInfo fields,
//! serializer, size accounting, cap/trim quirk table. FileContext stays
//! a seam (its paths entangle cache/service/flows/capture monoliths —
//! pinned by the harness transcript for later plan rows).
//!
//! C `std::string` members hold arbitrary bytes (names carry 0xFF
//! payloads and raw UTF-16LE per the transcript), so every string field
//! is a `Vec<u8>` here — a Rust `String` could not represent them.
//!
//! Upstream UB equivalence: the deserialize header memcpy and the
//! serialize string memcpy are unguarded in C; the Rust port indexes
//! slices equivalently, so the same truncated-buffer cases panic
//! (release = panic, never silent OOB) — documented in KNOWN DEVIATIONS.

use super::file_stats::FileCounts;

// ------------------------------------------------------------------
// file_lib.h / file_api.h vocabulary (A_ENUMS/A_SZ_* transcript-pinned)
// ------------------------------------------------------------------

/// file_lib.h:32
pub const SNORT_FILE_TYPE_UNKNOWN: u32 = u16::MAX as u32;
/// file_lib.h:33
pub const SNORT_FILE_TYPE_CONTINUE: u32 = 0;
/// hash/hashes.h (transcript-pinned digest width)
pub const SHA256_HASH_SIZE: usize = 32;
// Row 17v consolidation: the file_api.h vocabulary (the 6 enum const
// blocks below the caps, FileState, get_character_encoding,
// UserFileDataBase, UTF_16_LE_BOM_LEN) moved to its canonical home
// (super::file_api — the umbrella TU, row 17v); these pub re-exports keep
// every 17o/17q/17r binding green (tests/filib_parity_test.rs +
// fcache/fctx/fflows glob-import this module; grep-verified before the
// move — the 17u const-home recipe VERBATIM).
pub use super::file_api::{
    FILE_CAPTURE_FAIL, FILE_CAPTURE_MAX, FILE_CAPTURE_MEMCAP, FILE_CAPTURE_MIN,
    FILE_CAPTURE_SUCCESS, FILE_DOWNLOAD, FILE_SIG_DEPTH_FAIL, FILE_SIG_DONE,
    FILE_SIG_FLUSH, FILE_SIG_PROCESSING, FILE_UPLOAD, FILE_VERDICT_BLOCK,
    FILE_VERDICT_LOG, FILE_VERDICT_MAX, FILE_VERDICT_PENDING, FILE_VERDICT_REJECT,
    FILE_VERDICT_STOP, FILE_VERDICT_STOP_CAPTURE, FILE_VERDICT_UNKNOWN, FileState,
    SNORT_CHAR_ENCODING_ASCII, SNORT_CHAR_ENCODING_UTF_16LE, SNORT_FILE_END,
    SNORT_FILE_FULL, SNORT_FILE_MIDDLE, SNORT_FILE_POSITION_UNKNOWN, SNORT_FILE_START,
    UTF_16_LE_BOM_LEN, UserFileDataBase, get_character_encoding,
};

/// file_lib.cc:76-78 (hardening caps; PATH_MAX = 4096 on Linux — B3 pins
/// NAMELEN=4096).
pub const FILE_URL_CAP: u32 = 4095;
pub const FILE_NAME_CAP: u32 = 4096;
pub const FILE_HOST_CAP: u32 = 256;

// FileVerdict / FilePosition / FileCaptureState / FileSigState /
// FileDirection / FileCharEncoding const blocks: MOVED to file_api.rs
// (row 17v) and re-exported above — wire values pinned there by the
// fcapi E_enums vector; the old numerals (4-byte-int posture, A_SZ
// "SZ_VERDICT=4 SZ_DIR=4 SZ_CAPST=4 SZ_SIGST=4") ride unchanged.

/// file_lib.h:38 — 8 entries INCLUDING index 7 (FILE_VERDICT_MAX -> "INVALID").
pub const VERDICT_NAME: [&str; 8] = [
    "Unknown",
    "Log",
    "Stop",
    "Block",
    "Reset",
    "Pending",
    "Stop Capture",
    "INVALID",
];

// FileState struct + get_character_encoding: MOVED to file_api.rs
// (row 17v; A_SZ_STATE=8 pin), re-exported above.

// UserFileDataBase trait: MOVED to file_api.rs (row 17v) — the
// dead-copy-ctor doc (grep-0 bodies at fe29cbe) travels WITH it;
// re-exported above.

/// Seam for `FileCapture` (file_api/file_capture.cc — plan row 17p+).
/// The two members FileInfo::reserve_file/get_max_file_capture_size/
/// set_capture_file_data touch, at their real signatures.
pub trait FileCaptureApi {
    /// `FileCapture::reserve_file(const FileInfo*)`
    fn reserve_file(&mut self, file: &FileInfo) -> u32;
    fn get_file_capture_size(&self) -> i64;
    fn get_max_file_capture_size(&self) -> i64;
    fn set_data(&mut self, file_data: &[u8], size: u32);
    /// `FileCapture::process_buffer(const uint8_t*, int, FilePosition)`
    /// (file_capture.h:73; the process_file_capture ladder, row 17r —
    /// port-side seam substitution per PLAN §3: file_capture.cc stays
    /// its own row, the harness witness implements the buffer-state
    /// ladder incl. the file_counts stats bumps its REAL body drives).
    fn process_buffer(&mut self, _file_data: &[u8], _data_size: i32, _position: u32) -> u32 {
        FILE_CAPTURE_SUCCESS
    }
    /// Row 17x: `std::string FileCapture::store_file_async()`
    /// (file_capture.h:90 -> file_capture.cc:564-:584) — reached ONLY
    /// by FilePolicy::signature_lookup's capture leg
    /// (file_policy.cc:197, row 17x). The REAL FileCapture overrides
    /// with the inherent body (file_capture.rs:1195, Box-consuming
    /// queue push); the default "" answers the cc:199 extracted_name
    /// EMPTY arm (V9b pins size=0 cutoff=0), which is exactly the
    /// witness-capture posture (no CWD store from a stub).
    fn store_file_async(self: Box<Self>) -> String {
        String::new()
    }
}

/// Row 17r: `new FileCapture(config->capture_min_size,
/// config->capture_max_size)` (file_lib.cc:1174) rides this factory
/// seam on FileEnvLite (the capture ENGINE body stays its own row —
/// port-side seam substitution, PLAN §3).
pub trait FileCaptureFactory {
    fn new_capture(&mut self, min: i64, max: i64) -> Option<Box<dyn FileCaptureApi>>;
    /// Row 17y: the static-half pair the FileService lifecycle reaches —
    /// `FileCapture::init(conf->capture_memcap, conf->capture_block_size)`
    /// (post_init cc:138) and `FileCapture::exit()` (close cc:180). The
    /// REAL factory (RealFileCaptureFactory, owns the landed statics)
    /// drives the landed bodies (file_capture.rs:303 init / :439 exit,
    /// the 17s single-thread posture: flag + drained queue, no OS
    /// thread ever exists); the default no-ops keep every witness
    /// factory (fcache/fctx/fflows/finspect twins — the 17r posture,
    /// stubs.cc :641-:645 "NEVER call init" arms) byte-UNCHANGED.
    fn init_capture(&mut self, _memcap: i64, _block_size: i64) {}
    fn exit_capture(&mut self) {}
}

pub struct NoFileCaptureFactory;
impl FileCaptureFactory for NoFileCaptureFactory {
    fn new_capture(&mut self, _min: i64, _max: i64) -> Option<Box<dyn FileCaptureApi>> {
        None // C `new` never answers null; the caller expects (pinned-absent)
    }
}

/// Row 17r: `fp_eval_service_group(p, conf->snort_protocol_id)`
/// (file_lib.cc:1044; detection/fingerprint engine reach — donor
/// witness TU stubs.cc prints the "FP_EVAL spid=%u have_pkt=%d n=%u"
/// pair and, when armed, SWAPS the run-continuation of this context:
/// "FP_EVAL set_type=%u" / "FP_EVAL swap -> alt"). The seam receives
/// the live context handle so an armed witness can drive the file_type
/// write the detection engine performs through service rules.
pub trait FpEvalApi {
    fn fp_eval_service_group(
        &mut self,
        p: &PacketView,
        snort_protocol_id: i32,
        ctx: &Rc<RefCell<FileContext>>,
    );
}

pub struct NoFpEval;
impl FpEvalApi for NoFpEval {
    fn fp_eval_service_group(
        &mut self,
        _p: &PacketView,
        _snort_protocol_id: i32,
        _ctx: &Rc<RefCell<FileContext>>,
    ) {
    }
}

/// file_capture.cc:72 `FileCapture::error_capture`
pub fn error_capture(state: u32, counts: &mut FileCounts) -> u32 {
    counts.file_reserve_failures += 1;
    state
}

/// file_lib.cc:80
fn file_clamp_len(len: u32, cap: u32) -> u32 {
    if len > cap {
        cap
    } else {
        len
    }
}

/// time/clock_defs.h `struct timeval` (SZ_TIMEVAL=16; long/long on Linux)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

// ------------------------------------------------------------------
// FileInfo (file_lib.h:50) — fields verbatim, defaults verbatim
// ------------------------------------------------------------------

// No derive(Clone): user_file_data/file_capture hold trait objects; the
// upstream copy-assignment discipline is the explicit `copy`/`assign`
// pair below (file_lib.cc:134/331), which is what the gate pins.
pub struct FileInfo {
    // protected (pub here so the FileContext seam + tests can reach them)
    pub file_name: Vec<u8>,
    pub file_name_set: bool,
    pub url: Vec<u8>,
    pub url_set: bool,
    pub host_name: Vec<u8>,
    pub host_set: bool,
    pub file_size: u64,
    pub direction: u32, // FileDirection
    pub file_type_id: u32, // C uint32_t; set_file_type widens the arg
    pub sha256: Option<[u8; SHA256_HASH_SIZE]>,
    pub is_sha256_set: bool,
    pub file_id: u64,
    pub file_capture: Option<Box<dyn FileCaptureApi>>,
    pub file_type_enabled: bool,
    pub file_signature_enabled: bool,
    pub file_capture_enabled: bool,
    pub file_state: FileState,
    pub policy_id: u32,
    pub user_file_data: Option<Box<dyn UserFileDataBase>>,
    pub re_eval: bool,
    pub is_partial: bool,
    pub extracted_cutoff: bool,
    pub extracted_size: u64,
    pub extracted_file_name: Vec<u8>,

    // public fields
    pub verdict: u32, // FileVerdict
    pub processing_complete: bool,
    pub pending_expire_time: TimeVal,
}

impl Default for FileInfo {
    fn default() -> Self {
        FileInfo {
            file_name: Vec::new(),
            file_name_set: false,
            url: Vec::new(),
            url_set: false,
            host_name: Vec::new(),
            host_set: false,
            file_size: 0,
            direction: FILE_DOWNLOAD,
            file_type_id: SNORT_FILE_TYPE_CONTINUE,
            sha256: None,
            is_sha256_set: false,
            file_id: 0,
            file_capture: None,
            file_type_enabled: false,
            file_signature_enabled: false,
            file_capture_enabled: false,
            // FileState file_state = { FILE_CAPTURE_SUCCESS, FILE_SIG_PROCESSING };
            file_state: FileState {
                capture_state: FILE_CAPTURE_SUCCESS,
                sig_state: FILE_SIG_PROCESSING,
            },
            policy_id: 0,
            user_file_data: None,
            re_eval: false,
            is_partial: false,
            extracted_cutoff: false,
            extracted_size: 0,
            extracted_file_name: Vec::new(),
            verdict: FILE_VERDICT_UNKNOWN,
            processing_complete: false,
            pending_expire_time: TimeVal::default(),
        }
    }
}

// ~FileInfo (file_lib.cc:118): frees user_file_data then sha256. Rust
// Drop is automatic; the explicit hooks below mirror it for the seam.

impl FileInfo {
    /// file_lib.cc:175
    pub fn get_serialized_size(&self) -> usize {
        let mut size = 1 // sizeof(is_sha256_set) (bool == 1 byte, B0 pins)
            + 4 // verdict
            + 8 // file_size
            + 4 // direction
            + 8 // file_id
            + 4 // file_type_id
            + 4 // file_state.capture_state
            + 4 // file_state.sig_state
            + 4 // policy_id
            + 7; // file_name_set url_set host_set type sig capture partial (bools)

        if self.sha256.is_some() {
            size += SHA256_HASH_SIZE;
        }
        if self.file_name_set {
            size += 4 + self.file_name.len();
        }
        if self.url_set {
            size += 4 + self.url.len();
        }
        if self.host_set {
            size += 4 + self.host_name.len();
        }
        size
    }

    /// C byte writers (little-endian x86 memcpy, pinned by the B2 hex).
    fn write_bool(buf: &mut [u8], off: &mut usize, val: bool) {
        buf[*off] = u8::from(val);
        *off += 1;
    }
    fn write_u32(buf: &mut [u8], off: &mut usize, val: u32) {
        buf[*off..*off + 4].copy_from_slice(&val.to_le_bytes());
        *off += 4;
    }
    fn write_u64(buf: &mut [u8], off: &mut usize, val: u64) {
        buf[*off..*off + 8].copy_from_slice(&val.to_le_bytes());
        *off += 8;
    }
    fn write_string(buf: &mut [u8], off: &mut usize, buffer_len: usize, str: &[u8], is_set: bool) {
        Self::write_bool(buf, off, is_set);
        if is_set && *off < buffer_len {
            let len = str.len() as u32;
            Self::write_u32(buf, off, len);
            buf[*off..*off + len as usize].copy_from_slice(str);
            *off += len as usize;
        }
    }

    /// file_lib.cc:197 — NOTE takes &mut self (upstream mutates
    /// is_sha256_set when a digest is present).
    pub fn serialize(&mut self, buffer: &mut [u8], buffer_len: usize) {
        let mut offset = 0usize;

        if self.sha256.is_some() {
            self.is_sha256_set = true;
        }

        Self::write_bool(buffer, &mut offset, self.is_sha256_set);

        if self.is_sha256_set && offset < buffer_len && let Some(sha) = self.sha256 {
            buffer[offset..offset + SHA256_HASH_SIZE].copy_from_slice(&sha);
            offset += SHA256_HASH_SIZE;
        }

        Self::write_u32(buffer, &mut offset, self.verdict);
        Self::write_u64(buffer, &mut offset, self.file_size);
        Self::write_u32(buffer, &mut offset, self.direction);
        Self::write_u64(buffer, &mut offset, self.file_id);
        Self::write_u32(buffer, &mut offset, self.file_type_id);
        Self::write_u32(buffer, &mut offset, self.file_state.capture_state);
        Self::write_u32(buffer, &mut offset, self.file_state.sig_state);
        Self::write_u32(buffer, &mut offset, self.policy_id);
        Self::write_string(buffer, &mut offset, buffer_len, &self.file_name, self.file_name_set);
        Self::write_string(buffer, &mut offset, buffer_len, &self.url, self.url_set);
        Self::write_string(buffer, &mut offset, buffer_len, &self.host_name, self.host_set);
        Self::write_bool(buffer, &mut offset, self.file_type_enabled);
        Self::write_bool(buffer, &mut offset, self.file_signature_enabled);
        Self::write_bool(buffer, &mut offset, self.file_capture_enabled);
        Self::write_bool(buffer, &mut offset, self.is_partial);
    }

    /// file_lib.cc:254 — peer-supplied (MP sync) hardening: clamp the
    /// copied length to cap but always CONSUME the full on-wire length;
    /// any length/size overrun sets offset = buffer_len so every later
    /// read fails (the is_set byte is already consumed — B4 pins
    /// URL_SET=1 with an empty url). Transcribed via a cursor struct so
    /// the C cascade `offset = buffer_len` behaves identically (every
    /// later read then sees `offset >= buffer_len` and fails).
    pub fn deserialize(&mut self, buffer: &[u8], buffer_len: usize) {
        struct Cur<'a> {
            buf: &'a [u8],
            len: usize,
            offset: usize,
        }
        impl<'a> Cur<'a> {
            fn read_bool(&mut self) -> bool {
                if self.offset + 1 > self.len {
                    self.offset = self.len;
                    return false;
                }
                // C memcpy of sizeof(bool): any byte pattern; non-zero reads true
                let v = self.buf[self.offset] != 0;
                self.offset += 1;
                v
            }
            fn read_u32(&mut self) -> u32 {
                // C memcpy with NO bounds check (pinned UB: short payload
                // panics in Rust instead of reading OOB)
                let v = u32::from_le_bytes(self.buf[self.offset..self.offset + 4].try_into().unwrap());
                self.offset += 4;
                v
            }
            fn read_u64(&mut self) -> u64 {
                let v = u64::from_le_bytes(self.buf[self.offset..self.offset + 8].try_into().unwrap());
                self.offset += 8;
                v
            }
            fn read_string(&mut self, str: &mut Vec<u8>, is_set: &mut bool, cap: u32) {
                *is_set = self.read_bool();
                if !*is_set {
                    return;
                }
                if self.offset + 4 > self.len {
                    self.offset = self.len;
                    return;
                }
                let len = self.read_u32();
                if len > (self.len - self.offset) as u32 {
                    self.offset = self.len;
                    return;
                }
                str.clear();
                str.extend_from_slice(&self.buf[self.offset..self.offset + file_clamp_len(len, cap) as usize]);
                self.offset += len as usize;
            }
        }

        let mut cur = Cur { buf: buffer, len: buffer_len, offset: 0 };

        // C memcpy with NO bounds check here (pinned UB: short header panics)
        self.is_sha256_set = cur.buf[cur.offset] != 0;
        cur.offset += 1;

        if self.is_sha256_set && cur.offset < buffer_len {
            // C: `if (!sha256) sha256 = new uint8_t[..]` then memcpy —
            // an existing digest is overwritten in place.
            let mut sha = [0u8; SHA256_HASH_SIZE];
            sha.copy_from_slice(&buffer[cur.offset..cur.offset + SHA256_HASH_SIZE]);
            self.sha256 = Some(sha);
            cur.offset += SHA256_HASH_SIZE;
        }
        self.verdict = cur.read_u32();
        self.file_size = cur.read_u64();
        self.direction = cur.read_u32();
        self.file_id = cur.read_u64();
        self.file_type_id = cur.read_u32();
        self.file_state.capture_state = cur.read_u32();
        self.file_state.sig_state = cur.read_u32();
        self.policy_id = cur.read_u32();
        cur.read_string(&mut self.file_name, &mut self.file_name_set, FILE_NAME_CAP);
        cur.read_string(&mut self.url, &mut self.url_set, FILE_URL_CAP);
        cur.read_string(&mut self.host_name, &mut self.host_set, FILE_HOST_CAP);
        self.file_type_enabled = cur.read_bool();
        self.file_signature_enabled = cur.read_bool();
        self.file_capture_enabled = cur.read_bool();
        self.is_partial = cur.read_bool();
    }

    /// file_lib.cc:331 FileInfo::operator= (copy with clear_data = true)
    pub fn assign(&mut self, other: &FileInfo) {
        if std::ptr::eq(self, other) {
            return;
        }
        self.copy(other, true);
    }

    /// file_lib.cc:134 — literal field discipline: sha256 only copied
    /// when src has one (dst keeps its own otherwise); clear_data=true
    /// detaches capture, zeroes policy_id, and drops user_file_data
    /// (which is NOT copied from src either way); re_eval/is_sha256_set/
    /// is_partial-adjacent fields and extracted_name are NOT touched.
    pub fn copy(&mut self, other: &FileInfo, clear_data: bool) {
        if std::ptr::eq(self, other) {
            return;
        }

        if let Some(sha) = other.sha256 {
            self.sha256 = Some(sha);
        }

        self.file_size = other.file_size;
        self.direction = other.direction;
        self.file_type_id = other.file_type_id;
        self.file_id = other.file_id;
        self.file_name = other.file_name.clone();
        self.file_name_set = other.file_name_set;
        self.url = other.url.clone();
        self.url_set = other.url_set;
        self.host_name = other.host_name.clone();
        self.host_set = other.host_set;
        self.verdict = other.verdict;
        self.file_type_enabled = other.file_type_enabled;
        self.is_partial = other.is_partial;
        self.file_signature_enabled = other.file_signature_enabled;
        self.file_capture_enabled = other.file_capture_enabled;
        self.file_state = other.file_state;
        self.pending_expire_time = other.pending_expire_time;
        self.extracted_cutoff = other.extracted_cutoff;
        self.extracted_size = other.extracted_size;
        if clear_data {
            // only one copy of file capture
            self.file_capture = None;
            self.policy_id = 0;
            self.user_file_data = None;
        }
    }

    // ---- file properties (file_lib.cc:343+) ----

    /// set_file_name: NULL/zero assign skipped BUT the set flag is
    /// always raised (C3 pins SET=1 EMPTY=1 from a null name).
    pub fn set_file_name(&mut self, name: Option<&[u8]>, name_size: u32) {
        if let Some(n) = name
            && name_size != 0
        {
            self.file_name = n[..file_clamp_len(name_size, FILE_NAME_CAP) as usize].to_vec();
        }
        self.file_name_set = true;
    }

    /// set_weak_file_name: assigns but never sets the flag (C4/C5).
    pub fn set_weak_file_name(&mut self, name: Option<&[u8]>, name_size: u32) {
        if let Some(n) = name
            && name_size != 0
        {
            self.file_name = n[..file_clamp_len(name_size, FILE_NAME_CAP) as usize].to_vec();
        }
    }

    pub fn unset_file_name(&mut self) {
        self.file_name_set = false;
    }

    /// reset_sha (file_lib.cc:362): sig_state resets to PROCESSING ONLY
    /// when a digest existed.
    pub fn reset_sha(&mut self) {
        if self.sha256.take().is_some() {
            self.file_state.sig_state = FILE_SIG_PROCESSING;
        }
    }

    pub fn set_url(&mut self, url_name: Option<&[u8]>, url_size: u32) {
        if let Some(u) = url_name
            && url_size != 0
        {
            self.url = u[..file_clamp_len(url_size, FILE_URL_CAP) as usize].to_vec();
        }
        self.url_set = true;
    }

    pub fn set_weak_url(&mut self, url_name: Option<&[u8]>, url_size: u32) {
        if let Some(u) = url_name
            && url_size != 0
        {
            self.url = u[..file_clamp_len(url_size, FILE_URL_CAP) as usize].to_vec();
        }
    }

    /// set_host: FIRST-SET-WINS — a second set_host is a full no-op
    /// (C6 keeps "first.com").
    pub fn set_host(&mut self, new_host_name: Option<&[u8]>, host_size: u32) {
        if self.host_set {
            return;
        }
        if let Some(h) = new_host_name
            && host_size != 0
        {
            self.host_name = h[..file_clamp_len(host_size, FILE_HOST_CAP) as usize].to_vec();
            self.host_set = true;
        }
    }

    pub fn get_file_size(&self) -> u64 {
        self.file_size
    }
    pub fn set_file_size(&mut self, size: u64) {
        self.file_size = size;
    }

    /// set_file_type(uint64_t id) into the uint32_t field (C14: 60000 keeps;
    /// wide values would truncate — literal C cast).
    pub fn set_file_type(&mut self, id: u64) {
        self.file_type_id = id as u32;
    }
    pub fn get_file_type(&self) -> u32 {
        self.file_type_id
    }

    pub fn set_file_id(&mut self, id: u64) {
        self.file_id = id;
    }
    pub fn get_file_id(&self) -> u64 {
        self.file_id
    }

    pub fn set_file_direction(&mut self, dir: u32) {
        self.direction = dir;
    }
    pub fn get_file_direction(&self) -> u32 {
        self.direction
    }

    pub fn get_file_sig_sha256(&self) -> Option<&[u8; SHA256_HASH_SIZE]> {
        self.sha256.as_ref()
    }

    /// file_lib.cc:458 — table lookup, UPPERCASE hex, exactly
    /// SHA256_HASH_SIZE bytes of the digest (reads 32 short-of-bounds in
    /// C; Rust panics equivalently via the slice indexing below).
    pub fn sha_to_string(&self, digest: &[u8]) -> String {
        const CONV: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = String::with_capacity(SHA256_HASH_SIZE * 2);
        for &b in &digest[..SHA256_HASH_SIZE] {
            out.push(CONV[(b >> 4) as usize] as char);
            out.push(CONV[(b & 0x0F) as usize] as char);
        }
        out
    }

    pub fn config_file_type(&mut self, enabled: bool) {
        self.file_type_enabled = enabled;
    }
    pub fn is_file_type_enabled(&self) -> bool {
        self.file_type_enabled
    }
    pub fn config_file_signature(&mut self, enabled: bool) {
        self.file_signature_enabled = enabled;
    }
    pub fn is_file_signature_enabled(&self) -> bool {
        self.file_signature_enabled
    }
    pub fn config_file_capture(&mut self, enabled: bool) {
        self.file_capture_enabled = enabled;
    }
    pub fn is_file_capture_enabled(&self) -> bool {
        self.file_capture_enabled
    }

    pub fn set_policy_id(&mut self, id: u32) {
        self.policy_id = id;
    }
    pub fn get_policy_id(&self) -> u32 {
        self.policy_id
    }

    pub fn set_file_data(&mut self, fd: Option<Box<dyn UserFileDataBase>>) {
        self.user_file_data = fd;
    }
    pub fn get_file_data(&self) -> bool {
        self.user_file_data.is_some()
    }

    pub fn set_partial_flag(&mut self, partial: bool) {
        self.is_partial = partial;
    }
    pub fn is_partial_download(&self) -> bool {
        self.is_partial
    }

    pub fn set_re_eval(&mut self) {
        self.re_eval = true;
    }
    pub fn has_to_re_eval(&self) -> bool {
        self.re_eval
    }
    pub fn unset_re_eval(&mut self) {
        self.re_eval = false;
    }

    /// FileInfo::reset (file_lib.cc:777): verdict + processing + SHA only;
    /// name/url/host/size/policy/extracted all SURVIVE (gate "reset" + C13).
    pub fn reset(&mut self) {
        self.verdict = FILE_VERDICT_UNKNOWN;
        self.processing_complete = false;
        self.reset_sha();
        self.pending_expire_time.tv_sec = 0;
        self.pending_expire_time.tv_usec = 0;
    }

    /// file_lib.cc:518. `dest` out-param mirrors C's `FileCapture*&`;
    /// the no-capture arm runs error_capture(FILE_CAPTURE_FAIL) which
    /// bumps file_counts.file_reserve_failures (F4/G6B pin ST=4 RES_FAIL=1).
    pub fn reserve_file(
        &mut self,
        dest: &mut Option<Box<dyn FileCaptureApi>>,
        counts: &mut FileCounts,
    ) -> u32 {
        let Some(mut cap) = self.file_capture.take() else {
            *dest = None;
            return error_capture(FILE_CAPTURE_FAIL, counts);
        };
        let state = cap.reserve_file(self);
        if state == FILE_CAPTURE_SUCCESS {
            self.extracted_size = cap.get_file_capture_size() as u64;
        }
        self.config_file_capture(false);
        *dest = Some(cap);
        state
    }

    /// file_lib.cc:536
    pub fn get_max_file_capture_size(&self) -> i64 {
        match &self.file_capture {
            Some(cap) => cap.get_max_file_capture_size(),
            None => 0,
        }
    }

    /// file_lib.cc:547 (unusedFunction-suppressed entry point)
    pub fn set_capture_file_data(&mut self, file_data: &[u8], size: u32) {
        if let Some(cap) = &mut self.file_capture {
            cap.set_data(file_data, size);
        }
    }

    // C inline getters/setters (file_lib.h:104-111), verbatim casts:
    pub fn get_extracted_size(&self) -> i64 {
        self.extracted_size as i64
    }
    pub fn get_extracted_cutoff(&self) -> bool {
        self.extracted_cutoff
    }
    pub fn get_extracted_name(&self) -> &[u8] {
        &self.extracted_file_name
    }
    pub fn set_extracted_name(&mut self, name: &[u8]) {
        self.extracted_file_name = name.to_vec();
    }
    pub fn set_extracted_size(&mut self, size: i64) {
        self.extracted_size = size as u64;
    }
    pub fn set_extracted_cutoff(&mut self, cutoff: bool) {
        self.extracted_cutoff = cutoff;
    }

    pub fn get_file_state(&self) -> FileState {
        self.file_state
    }

    // The three set_* accessors mirroring C's const std::string& return.
    pub fn get_file_name(&self) -> &[u8] {
        &self.file_name
    }
    pub fn is_file_name_set(&self) -> bool {
        self.file_name_set
    }
    pub fn get_url(&self) -> &[u8] {
        &self.url
    }
    pub fn is_url_set(&self) -> bool {
        self.url_set
    }
    pub fn get_host_name(&self) -> &[u8] {
        &self.host_name
    }
    pub fn is_host_set(&self) -> bool {
        self.host_set
    }
}

// ==================================================================
// FileContext — moved from file_cache.rs (the 17p seam struct: same
// members, same defaults; the 17p comment there pointed its full body
// at this row) and deepened against file_lib.cc:559-1362 (row 17q):
// ctor/dtor arms, finalize_file_type, get_mime_type, set_source,
// log_file_event (REAL body — the FileCacheEventSink forwarder seam
// 17p left open is retired here), set_signature_state, check_policy,
// remove_segments, reset (hides FileInfo::reset — the C++ shadow the
// upstream cppcheck note flags), update_file_size, stop_file_capture,
// print_file_sha256/print_file_name/print (string form; the
// config->trace_type tail is dead in every pinned transcript:
// trace_type=false pinned).
//
// PORTED, row 17r (no panics left in this TU): process (both
// overloads), finish_signature_lookup, file_signature_lookup,
// find_file_type_from_ips, process_file_type,
// process_file_signature_sha256, process_file_capture,
// print_file_data — the heavy FileContext half (file_lib.cc:825-1362
// + the signature-lookup pair) on top of the file_segment.rs
// machinery and the zero-dep helpers::sha256 EVP substitute.
//
// Support vocabulary this row grows: FileConfigLite (file_config.h
// fields + file_type_name/get_rule_from_id), FileServiceLite (the
// FileService statics the two halves read), PublishApi (the two
// DataBus::publish witness shapes log_file_event drives),
// NetworkPolicySeam (the NetworkPolicy::get_base_file_policy factory
// reach), FileEnvLite (the C file-scope globals + witness bundle),
// HrClock (the SnortClock seam the donor fake clock arms).
// ==================================================================

use super::file_cache::{
    CacheFlow, FileConfigView, FilePolicyApi, FilePolicyHandle, ImgrRc, InspectorApi,
    PacketTracerApi, PacketView, PROTO_BIT__PDU, PKT_ALLOW_MULTIPLE_DETECT, TRACE_DEBUG_LEVEL,
    TRACE_INFO_LEVEL,
};
// Row 17r (the heavy half): find_file_type_from_ips reaches the C
// statics FileFlows::get_file_flows / get_file_policy and the
// CurrentContextSlot swap/restore pair — the module cycle
// (file_flows already imports this module) is the C mutual-call shape
// the port threads explicitly (skill rule: no self-referential
// structs).
use super::file_flows::{CurrentContextSlot, FileFlows};
use super::file_identifier::{
    FIdNode, FileIdErrorSink, FileIdentifier, FileMeta, FILE_ID_MAX,
};
use super::file_segment::FileSegments;
use crate::helpers::event_gen::DetectionEventSink;
use crate::helpers::sha256::Sha256Ctx;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// file_config.h:30-:40 macro table — row 17u moved the canonical
/// numerals to file_config.rs (the three-way dup's one home, PLAN 8
/// item 1); these pub re-exports keep every existing binding green
/// (tests/fctx_parity_test.rs:59-:61 imports the old names through
/// this module; grep-verified before the move). Use-site cites of
/// file_config.h stay valid.
pub use super::file_config::{
    DEFAULT_FILE_CAPTURE_BLOCK_SIZE, DEFAULT_FILE_CAPTURE_MAX_SIZE, DEFAULT_FILE_CAPTURE_MIN_SIZE,
    DEFAULT_FILE_CAPTURE_MEM, DEFAULT_FILE_SHOW_DATA_DEPTH, DEFAULT_FILE_SIGNATURE_DEPTH,
    DEFAULT_FILE_TYPE_DEPTH, DEFAULT_MAX_FILES_PER_FLOW,
};

/// file_config.h:35 `class FileConfig` — every field at the exact C
/// declared name/type/order, plus the two methods this half reads.
/// Defaults mirror the C in-class initializers (hand-written Default:
/// derive would zero the non-zero depths — skill rule). No Clone/Debug:
/// the private FileIdentifier member is neither (fid row); the struct
/// rides Rc<RefCell<..> throughout, matching the C pointer usage.
pub struct FileConfigLite {
    // file_config.h:47-56 in declared order:
    pub file_type_depth: i64,
    pub file_signature_depth: i64,
    pub file_block_timeout: i64,
    pub file_lookup_timeout: i64,
    pub block_timeout_lookup: bool,
    pub capture_memcap: i64,
    pub capture_max_size: i64,
    pub capture_min_size: i64,
    pub capture_block_size: i64,
    /// file_config.h:64 (the FileService::get_max_file_depth source)
    pub file_depth: i64,
    /// file_config.h:65
    pub max_files_cached: i64,
    /// file_config.h:66 (file_flows.cc:325 over-limit gate)
    pub max_files_per_flow: u64,
    // file_config.h:70-74:
    pub show_data_depth: i64,
    pub trace_type: bool,
    pub trace_signature: bool,
    pub trace_stream: bool,
    /// file_config.h:72 `SnortProtocolId snort_protocol_id =
    /// UNKNOWN_PROTOCOL_ID;` (the find_file_type_from_ips +
    /// fp_eval_service_group arg; row 17r)
    pub snort_protocol_id: i32,
    /// the private `FileIdentifier fileIdentifier` member
    pub file_identifier: FileIdentifier,
}

impl Default for FileConfigLite {
    fn default() -> Self {
        FileConfigLite {
            file_type_depth: DEFAULT_FILE_TYPE_DEPTH,
            file_signature_depth: DEFAULT_FILE_SIGNATURE_DEPTH,
            file_block_timeout: super::file_config::DEFAULT_FILE_BLOCK_TIMEOUT,
            file_lookup_timeout: super::file_config::DEFAULT_FILE_LOOKUP_TIMEOUT,
            block_timeout_lookup: false,
            capture_memcap: DEFAULT_FILE_CAPTURE_MEM,
            capture_max_size: DEFAULT_FILE_CAPTURE_MAX_SIZE,
            capture_min_size: DEFAULT_FILE_CAPTURE_MIN_SIZE,
            capture_block_size: DEFAULT_FILE_CAPTURE_BLOCK_SIZE,
            file_depth: 0,
            max_files_cached: super::file_config::DEFAULT_MAX_FILES_CACHED,
            max_files_per_flow: DEFAULT_MAX_FILES_PER_FLOW,
            show_data_depth: DEFAULT_FILE_SHOW_DATA_DEPTH,
            trace_type: false,
            trace_signature: false,
            trace_stream: false,
            snort_protocol_id: 0, // UNKNOWN_PROTOCOL_ID (snort_types.h)
            file_identifier: FileIdentifier::new(),
        }
    }
}

impl FileConfigLite {
    /// file_config.cc:41-:45 `FileConfig::find_file_type_id` ->
    /// fileIdentifier.find_file_type_id (the D_forwarders arm:
    /// `find_empty_trie=65535 ctx_null=1` — the production path never
    /// inserts into the trie, only add_file_id fills
    /// file_magic_rules[], fid-harness fact). The C in/out `void**
    /// context` rides the fid row's `&mut Option<FIdNode>` (the
    /// pinned surface; the raw shape stays there — wire the raw
    /// `void**` shim only when a vector demands it).
    pub fn find_file_type_id(
        &self,
        buf: &[u8],
        file_offset: u64,
        context: &mut Option<FIdNode>,
    ) -> u32 {
        self.file_identifier.find_file_type_id(buf, file_offset, context)
    }

    /// file_config.cc:48-:51 `FileConfig::process_file_rule(const
    /// FileMeta&)` -> fileIdentifier.add_file_id (the M1 arm's arm-the
    /// seam-table path; `S` is the C global ParseError stand-in — see
    /// file_config.rs's NullParseError note).
    pub fn process_file_rule<S: FileIdErrorSink>(&mut self, rule: &FileMeta, sink: &mut S) {
        // C const this= is a language artifact; the C add_file_id
        // itself mutates file_magic_rules, so the forward is &mut
        // (crate-wide interior-mutability deviation, same shape as
        // FileIdentifier::add_file_id).
        self.file_identifier.add_file_id(rule, sink);
    }

    /// file_config.cc:53-:56 `FileConfig::get_rule_from_id` ->
    /// fileIdentifier.get_rule_from_id.
    pub fn get_rule_from_id(&self, id: u32) -> Option<&FileMeta> {
        self.file_identifier.get_rule_from_id(id)
    }

    /// file_config.cc:58-:62 `FileConfig::get_magic_rule_ids_from_
    /// type` -> fileIdentifier (the M3 version-quoting arm lives in
    /// the file_identifier row).
    pub fn get_magic_rule_ids_from_type(
        &self,
        r#type: &str,
        version: &str,
        ids_set: &mut [u64; FILE_ID_MAX / 64],
    ) {
        self.file_identifier
            .get_magic_rule_ids_from_type(r#type, version, ids_set);
    }

    /// file_config.cc:63 `FileConfig::file_type_name(uint32_t)`
    pub fn file_type_name(&self, id: u32) -> String {
        if SNORT_FILE_TYPE_UNKNOWN == id {
            "Unknown file type, done".to_string()
        } else if SNORT_FILE_TYPE_CONTINUE == id {
            "Undecided file type, continue...".to_string()
        } else if let Some(info) = self.get_rule_from_id(id) {
            info.r#type.clone()
        } else {
            String::new()
        }
    }
}

/// 17p bridge: PacketView::conf keeps the 2-field `FileConfigView`
/// snapshot ("the per-packet conf lives on PacketView::conf — FileCache
/// reads block_timeout_lookup/mp_dbus off the clone", :259-266); this
/// copies the shared field out of the full config.
pub fn file_config_view_of(cfg: &FileConfigLite) -> FileConfigView {
    FileConfigView {
        block_timeout_lookup: cfg.block_timeout_lookup,
        trace_type: cfg.trace_type,
        trace_signature: cfg.trace_signature,
        trace_stream: cfg.trace_stream,
        show_data_depth: cfg.show_data_depth,
        file_signature_depth: cfg.file_signature_depth,
        ..FileConfigView::default()
    }
}

/// `FileService` statics both halves read (file_service.cc:
/// atomics -> Cell/plain fields, single-threaded port, the 17p mutex
/// deviation):
///   * `bool is_file_service_enabled()` (:206 — true iff a type
///     signature or file signature service is enabled — the landed
///     REAL 2-OR (row 17y retired the harness's 3-OR witness; the
///     capture flag is NOT in the pair, cc:208, V2b drift pin)
///   * `static FileCache* get_file_cache()` (file_service.h:98 inline)
///   * `int64_t get_max_file_depth(FileConfig* fc = nullptr)` (:214) —
///     row 17y landed the REAL body as the `FileServiceLite::
///     get_max_file_depth` associated fn below; the FileEnvLite
///     passthrough stays for the frozen H/J arms (R4, PLAN 4)
///   * `uint64_t get_file_processed_size(Flow*)` (:256 — body at the
///     free fn in file_flows.rs (17q); the FileService C linkage is
///     namespace-scope, no member ever existed — cite only, row 17y).
#[derive(Clone, Default)]
pub struct FileServiceLite {
    // cc:48 `std::atomic<bool> FileService::file_type_id_enabled(false)`:
    // Cell carries the relaxed store/load pair (cc:70/:191/:216/:234,
    // single-threaded posture). Row 17y Cells (were plain bools) so the
    // REAL reset(cc:66-:74) clears through &self while reading the env
    // seams — the C++ all-static class maps to associated fns over the
    // driver bundle, interior mutability does the rest.
    file_type_id_enabled: Cell<bool>,
    file_signature_enabled: Cell<bool>, // cc:49
    // Row 17w: the third enable static (file_service.h `static bool
    // file_capture_enabled` + `is_file_type_id_enabled`/
    // `is_file_signature_enabled`/`is_file_capture_enabled` inline
    // getters) -- the file_config_show gates cc:92/:95/:101 read all
    // three; the coarse pair above stays as fconf/fflows drive it.
    file_capture_enabled: Cell<bool>, // cc:50
    // cc:53 `FileCache* FileService::file_cache = nullptr` — the RefCell
    // lets post_init's lazy `new FileCache` (cc:128-:134) and close's
    // `delete` + null (cc:173-:177) run through &self (static-class port).
    file_cache: RefCell<Option<Rc<RefCell<super::file_cache::FileCache>>>>,
    // Row 17y: cc:57-:59 the file-scope reload-comparison shadows
    // ("FIXIT-L make these params reloadable", cc:56). NOT part of the
    // C++ class — file statics here owned on the svc object (the ONE
    // FileServiceLite per env == the ONE process); observable ONLY
    // through the verify_reload mismatch arms (V4 vs V6).
    shadow_max_files_cached: Cell<i64>, // cc:57 `static int64_t max_files_cached = 0`
    shadow_capture_memcap: Cell<i64>, // cc:58
    shadow_capture_block_size: Cell<i64>, // cc:59
    // Row 17y: the PAUSE PREDICATE seam (PLAN §3 + R6). The real
    // main_packet_threads_fully_paused (src/main.cc:325-:340) walks the
    // pigs[]/Analyzer monolith — NEVER pulled; the port models it as the
    // armable Cell (harness twin stubs.cc NEW17y `g_svc_paused`, default
    // FALSE = packet threads running; the donor witness arms 1).
    // pause_calls mirrors the witness knob fsvc_pause_calls: the
    // freeze=0 pin (V3_ladder) is the || / short-circuit call-count
    // proof. h:94 const contract: the STATUS check never touches the
    // cache (V3_unchanged).
    pub packet_threads_fully_paused: Cell<bool>,
    pub pause_calls: Cell<u32>,
}

impl FileServiceLite {
    pub fn set_file_service_enabled(&mut self, type_on: bool, sig_on: bool) {
        self.file_type_id_enabled.set(type_on);
        self.file_signature_enabled.set(sig_on);
    }
    /// file_service.cc:206-:209 — the EXACT 2-OR:
    /// `return (file_type_id_enabled.load() or file_signature_enabled);`
    /// Row 17y: the harness donor witness (stubs.cc:604) computed a 3-OR
    /// INCLUDING capture; the real body never does. The capture-only arm
    /// (t=0 s=0 c=1 — reachable only via the FIXACC public-static poke,
    /// the enable_file_capture cascade hides it from the API) answers
    /// FALSE: the fsvc V2b_drift line `c=1 svc=0` pins that (PLAN R3).
    pub fn is_file_service_enabled(&self) -> bool {
        self.file_type_id_enabled.get() || self.file_signature_enabled.get()
    }
    // Row 17w: per-flag arms/readers (the fcache_set_file_service +
    // direct-static arms of the finspect stubs ride these; the C
    // std::atomic<bool> -> Cell<bool> relaxed store/load, single-threaded
    // posture; the FIXACC direct static pokes of the fsvc probe — the
    // V2b capture arm — map to these setter arms).
    pub fn set_file_type_enabled(&mut self, on: bool) {
        self.file_type_id_enabled.set(on);
    }
    pub fn set_file_signature_enabled(&mut self, on: bool) {
        self.file_signature_enabled.set(on);
    }
    pub fn set_file_capture_enabled(&mut self, on: bool) {
        self.file_capture_enabled.set(on);
    }
    // ---- Row 17x: the REAL `enable_*` trio bodies (file_service.cc:
    // 189-:204) — the FilePolicy add_file_id/load arms (cc:103/:107/
    // :110/:118/:122/:125) call THESE, not the set_* arms above. ----
    // Distinction pinned (row 17x, KNOWN DEVIATIONS): the set_file_*
    // _enabled arms above are the finspect/fctx HARNESS witness arms
    // (stubs.cc:596-:598 donor version, NO cascade — the frozen
    // finspect show-ladder arm C pins capture-on with signature still
    // disabled, finspect vectors lines 68-:82), and stay
    // byte-VERBATIM for the frozen replays. `enable_file_*` below are
    // the Real FileService bodies; the fsvc harness retired the witness
    // cascade replica entirely (the REAL body links now — the V2_enable
    // `casc=1` line pins the cascade against the real TU).
    // `void enable_file_type()` — file_service.cc:189-:192 (the
    // std::atomic store -> Cell relaxed store, 17p mutex deviation).
    pub fn enable_file_type(&self) {
        self.file_type_id_enabled.set(true); // :191
    }
    /// `void enable_file_signature()` — file_service.cc:194-:197.
    pub fn enable_file_signature(&self) {
        self.file_signature_enabled.set(true); // :196
    }
    /// `void enable_file_capture()` — file_service.cc:199-:204: sets
    /// capture AND cascades `enable_file_signature()` (:203). Pinned
    /// by the fpolicy vectors V4_load_cap `svc t=0 s=1 c=1` (the
    /// SERVICE-level cascade lights signature while the policy
    /// MEMBER stays 0) and V3_add (`svc t=1 s=1 c=0` — capture use
    /// flag off, no cascade); row 17y's fsvc V2_enable `casc=1` rides
    /// the REAL body.
    pub fn enable_file_capture(&self) {
        self.file_capture_enabled.set(true); // :202
        self.enable_file_signature(); // :203 the cascade
    }
    pub fn is_file_type_id_enabled(&self) -> bool {
        self.file_type_id_enabled.get()
    }
    pub fn is_file_signature_enabled(&self) -> bool {
        self.file_signature_enabled.get()
    }
    pub fn is_file_capture_enabled(&self) -> bool {
        self.file_capture_enabled.get()
    }
    /// file_service.h:98 inline (`return file_cache;`)
    pub fn get_file_cache(&self) -> Option<Rc<RefCell<super::file_cache::FileCache>>> {
        self.file_cache.borrow().clone()
    }
    /// harness arm (`fcache_set_file_cache(c)` — stubs.cc:639; against
    /// the REAL static from 17y it writes the real `file_cache` field).
    pub fn set_file_cache(&mut self, c: Option<Rc<RefCell<super::file_cache::FileCache>>>) {
        *self.file_cache.borrow_mut() = c;
    }

    // ==================================================================
    // Row 17y: the REAL lifecycle bodies (the row TU linked into the
    // C harness; these were witness stubs through 17x). The C++ class
    // is ALL-static: the methods ride as associated fns over the
    // driver-owned FileEnvLite (the seam bundle), and the static state
    // lives in this object's Cells/RefCell (interior mutability — no
    // &mut threading needed, matching the C "call from anywhere"
    // shape). `decode_conf` (h:99, cc:54) STAYS harness-only: no
    // DecodeConfig exists in the Rust tree (mime/service-inspector
    // owner rows) — KNOWN DEVIATIONS row 17y.
    // ==================================================================

    /// file_service.cc:61-:64 `init()` — `FileFlows::init();` ONLY
    /// (file_flows.h:62-:63 inline -> the FlowData::create_flow_data_id
    /// counter; the Rust landed arm file_flows.rs:327 carries it
    /// through env.file_flow_data_id). V14 pin: `ffd=1`.
    pub fn init(env: &mut FileEnvLite) {
        super::file_flows::FileFlows::init(env);
    }

    /// file_service.cc:66-:74 `reset()`:
    /// `if ( InspectorManager::get_inspector("file_inspect",
    ///  Module::GLOBAL) ) return;` then clear the THREE enable statics.
    /// Upstream facts pinned: `Module::GLOBAL` is usage 0
    /// (framework/module.h:216, before the harness prints `usage=0`);
    /// `file_processing_initiated` (cc:51) is NEVER touched here — nor
    /// anywhere else (grep-0 readers upstream; the dead static is not
    /// ported, KNOWN DEVIATIONS row 17y). The get_inspector gate is the
    /// NEW17y witness arm (`get_inspector` on InspectorManagerApi,
    /// default None == no inspector armed) — V9 arms it both ways
    /// (gate closed -> statics CLEAR; gate open -> statics SURVIVE).
    /// All-static C++ class: associated fn over the env bundle (the
    /// svc Cells clear through their interior mutability).
    pub fn reset(env: &FileEnvLite) {
        // if ( InspectorManager::get_inspector(...) ) return;
        if env
            .imgr
            .borrow_mut()
            .get_inspector("file_inspect", 0 /* Module::GLOBAL */)
            .is_some()
        {
            return;
        }
        // :70-:72 the three clears (file_processing_initiated absent —
        // the upstream body never resets it either)
        env.svc.file_type_id_enabled.set(false);
        env.svc.file_signature_enabled.set(false);
        env.svc.file_capture_enabled.set(false);
    }

    /// file_service.cc:118-:144 `post_init()`. ORDER PINNED (the fsvc
    /// V5 arms): `reset()` then `MimeSession::init()` BEFORE ANY conf
    /// check — the null-conf arm still rode the mime init (cc:120-:121
    /// precede cc:123-:126; the C post_init NEVER touches
    /// MimeSession::exit — close does). Mime is an OUT-OF-CLOSURE seam
    /// (the env.mime MimeApi trait; the mime row stays queued,
    /// NEXT.md:126-:131 — the real MimeSession::init news a SearchTool
    /// over mpse, the exact drag NEXT.md scoped out). The lazy-cache
    /// arm is REAL over the landed FileCache (cc:128-:134); the
    /// capture arm rides the landed FileCapture::init through the
    /// factory seam (cc:138, the 17s single-thread seam); the proto
    /// arm (cc:142-:143) is REAL over `sc->proto_ref->find("file_id")`
    /// — the Rust SnortConfig seam carries no proto_ref slot, the REAL
    /// ProtocolReference rides env.proto_ref (17y real-cp parity, the
    /// Rust twin snort_protocols.rs:141; harness seed add("file_id")=6,
    /// V1 `spid=6`).
    pub fn post_init(env: &mut FileEnvLite) {
        // reset();
        Self::reset(env);
        // MimeSession::init();  (BEFORE the conf check — pinned order)
        env.mime.borrow_mut().init();

        // FileConfig* const conf = get_file_config();
        let conf = env.get_file_config();
        let Some(conf) = conf else {
            return; // cc:125-:126
        };

        // if (!file_cache) { file_cache = new FileCache(
        //     conf->max_files_cached); ... }
        if env.svc.file_cache.borrow().is_none() {
            let (max_files_cached, block_timeout, lookup_timeout) = {
                let c = conf.borrow();
                (
                    c.max_files_cached,
                    c.file_block_timeout,
                    c.file_lookup_timeout,
                )
            };
            let mut cache = super::file_cache::FileCache::new(max_files_cached); // :130
            // the C new FileContext INSIDE the cache's ctor-time use of
            // the GLOBAL InspectorManager: the Rust cache takes its
            // manager from the env seam (the 17p creator-learns-the-
            // manager deviation; file_cache.rs:1110 `pub imgr`) — the
            // fsvc V10 add -> acquire pin rides this wiring.
            cache.imgr = env.imgr.clone();
            cache.set_block_timeout(block_timeout); // :132
            cache.set_lookup_timeout(lookup_timeout); // :133
            *env.svc.file_cache.borrow_mut() = Some(Rc::new(RefCell::new(cache)));
            env.svc.shadow_max_files_cached.set(max_files_cached); // :131
        }

        // if (file_capture_enabled) { FileCapture::init(
        //     conf->capture_memcap, conf->capture_block_size); ... }
        if env.svc.file_capture_enabled.get() {
            let (memcap, block) = {
                let c = conf.borrow();
                (c.capture_memcap, c.capture_block_size)
            };
            // the landed capture statics (file_capture.rs:303 init)
            // behind the factory seam (REAL factory drives the landed
            // block-size/mempool/alive-flag body; a witness factory
            // default no-ops — the seam deviation, 17s ruling).
            env.capture_factory.init_capture(memcap, block);
            env.svc.shadow_capture_memcap.set(memcap); // :140
            env.svc.shadow_capture_block_size.set(block); // :141
        }

        // const SnortConfig* sc = SnortConfig::get_conf();
        // conf->snort_protocol_id = sc->proto_ref->find("file_id");
        let spid = env
            .proto_ref
            .borrow()
            .find(crate::target_based::snort_protocols::FILE_ID_PROTO_NAME); // :143
        conf.borrow_mut().snort_protocol_id = spid as i32;
    }

    /// file_service.cc:146-:169 `verify_reload(sc)`. reset runs FIRST
    /// (V4c: the conf-null arm still ran the gate + the clears). The
    /// three ReloadError arms (cc:155/:160/:162) ride the driver-owned
    /// log seam (ErrorLogApi::reload_error; the C witness prints
    /// "WITNESS ReloadError ..." through the resident stubs.cc:123).
    /// SHADOW SEMANTICS PINNED (V4 vs V6): the compare NEVER assigns —
    /// only post_init copies the shadows — so a FIRST pass over drifted
    /// shadows fires the lines, and the SECOND pass after a post_init
    /// lands ZERO lines (copy-vs-compare pin: cc:154 NEVER assigns).
    /// The capture pair is compared ONLY under `file_capture_enabled`
    /// (cc:157) and the two captures are INDEPENDENT ifs (cc:159/:161 —
    /// V4 arms memcap AND block drift; one drift answers one line).
    /// `sc`: snort.cc:542 always passes non-null and cc:167 derefs the
    /// RAW sc — the port reads env.proto_ref directly (the Rust seam
    /// has no null-config slot; the conf-null arm is pinned via
    /// env.file_config = None, V4c; cc:149 returns BEFORE any sc deref).
    pub fn verify_reload(env: &mut FileEnvLite, errlog: &mut dyn super::file_cache::ErrorLogApi) {
        // reset();
        Self::reset(env);
        // FileConfig* const conf = get_file_config(sc);
        let conf = env.get_file_config();
        let Some(conf) = conf else {
            return; // cc:149-:152
        };

        // cc:154-:156
        if env.svc.shadow_max_files_cached.get() != conf.borrow().max_files_cached {
            errlog.reload_error("Changing file_inspect.max_files_cached requires a restart.\n");
        }

        // cc:157-:163 (the file_capture_enabled guard, TWO independent
        // compares — NEVER nest: the V4 memcap + block x2-line pin)
        if env.svc.file_capture_enabled.get() {
            if env.svc.shadow_capture_memcap.get() != conf.borrow().capture_memcap {
                errlog.reload_error("Changing file_inspect.capture_memcap requires a restart.\n");
            }
            if env.svc.shadow_capture_block_size.get() != conf.borrow().capture_block_size {
                errlog.reload_error(
                    "Changing file_inspect.capture_block_size requires a restart.\n",
                );
            }
        }

        // cc:165-:168 the UNKNOWN_PROTOCOL_ID re-arm
        if conf.borrow().snort_protocol_id
            == crate::target_based::snort_protocols::UNKNOWN_PROTOCOL_ID as i32
        {
            let spid = env
                .proto_ref
                .borrow()
                .find(crate::target_based::snort_protocols::FILE_ID_PROTO_NAME); // :167
            conf.borrow_mut().snort_protocol_id = spid as i32;
        }
    }

    /// file_service.cc:171-:181 `close()`: the ONLY-owner delete + null
    /// (cc:173-:177 — the cache Rc drops here if no driver alias is
    /// live, the R2 new/delete pair with post_init), MimeSession::exit
    /// (cc:179 — the env.mime trait seam; the C witness body prints
    /// once) and FileCapture::exit (cc:180 — the landed drain-and-flag
    /// body through the seam, joining the writer the V5 init spawned).
    /// Idempotent after: the cc:173 guard + the landed exit guards.
    pub fn close(env: &mut FileEnvLite) {
        // cc:173-:177: `if (file_cache) { delete file_cache;
        // file_cache = nullptr; }`
        if env.svc.file_cache.borrow().is_some() {
            *env.svc.file_cache.borrow_mut() = None;
        }

        // MimeSession::exit();
        env.mime.borrow_mut().exit();

        // FileCapture::exit();  (REAL factory arms the landed drain;
        // a witness factory default no-ops — the 17s seam posture)
        env.capture_factory.exit_capture();
    }

    /// cc:183 `void thread_init() { file_stats_init(); }` (brace-on-line
    /// quirk) — the landed file_stats.rs:180 calloc model.
    pub fn thread_init(env: &mut FileEnvLite) {
        super::file_stats::file_stats_init(env.stats.get_mut());
    }
    /// cc:185 `void thread_term() { file_stats_term(); }` — the landed
    /// file_stats.rs:185 free model (None replaces the C dangling
    /// pointer, the documented 17p deviation).
    pub fn thread_term(env: &mut FileEnvLite) {
        super::file_stats::file_stats_term(env.stats.get_mut());
    }

    /// cc:211-:225 `get_max_file_depth(FileConfig* fc)` — the REAL
    /// ladder, row 17y: `fc ? fc : get_file_config()`; null -> -1;
    /// `file_depth > 0 ? file_depth : -1`. The V8 pins: default arg
    /// answers the CONFIG 1460 (never the armed fcache g_max_file_depth
    /// shadow — R4 drift: that Cell stays inert here), null conf -> -1,
    /// the fc-ARG arm WINS (fc.file_depth -5 -> -1 even with a live
    /// config). The FileEnvLite passthrough (17q) stays UNTOUCHED for
    /// the frozen fflows H/J vectors (PLAN 4 verdict).
    pub fn get_max_file_depth(
        env: &FileEnvLite,
        fc: Option<&Rc<RefCell<FileConfigLite>>>,
    ) -> i64 {
        // const FileConfig* file_config = fc ? fc : get_file_config();
        let fc = fc.cloned().or_else(|| env.get_file_config());
        let Some(fc) = fc else {
            return -1; // :217-:219
        };
        let depth = fc.borrow().file_depth;
        if depth > 0 {
            return depth; // :221-:223
        }
        -1 // :224
    }

    /// cc:227-:252 `set_max_file_depth(sc)` — the REAL ladder (the
    /// canonical body the fsvc V8_set ladder drives; the file_inspect.rs
    /// instrumented twin that feeds the frozen finspect `SMD conf=`
    /// lines stays, the 17x dual-view ruling extends to this pair).
    /// `get_file_config(sc)` == env.get_file_config() with the sc-hopped
    /// overload collapsed (the C body ignores sc past the get_file_config
    /// hop; plan §1 — arms: conf null -> return; type-on copies
    /// file_type_depth (cc:234-:237); sig-on AND file_signature_depth >
    /// file_depth RAISES (cc:239-:243); `file_depth > 0` -> ++ "extra
    /// byte for deciding whether file data will be over limit"
    /// (cc:245-:249); bare return (cc:251). V8 pins 1460->1461,
    /// 7->20->21, both-off -5 stays.)
    pub fn set_max_file_depth(env: &FileEnvLite) {
        let conf = env.get_file_config();
        let Some(conf) = conf else {
            return; // cc:229-:232
        };
        let mut c = conf.borrow_mut();
        if env.svc.file_type_id_enabled.get() {
            c.file_depth = c.file_type_depth; // :236
        }
        if env.svc.file_signature_enabled.get() && c.file_signature_depth > c.file_depth {
            c.file_depth = c.file_signature_depth; // :242
        }
        if c.file_depth > 0 {
            c.file_depth += 1; // :247 the extra byte
        }
        // cc:251 bare `return;`
    }

    /// cc:76-:84 `collect_cache_usage(builder, group)` — null-cache
    /// early return (:78-:79), the `entries > 0` gate (:82), and the
    /// snapshot.h:125-:136 inline `builder.counter(group, "File cache
    /// entries", (uint64_t)entries)` (:83) through the landed
    /// snapshot::Builder::counter. V10 pins: null cache -> counters=0
    /// (no line); populated -> one counter named "File cache entries"
    /// carrying Value::U64(entries); a second call appends (counters=2).
    /// Row 17y signature deviation: the C takes `stats::Builder&`
    /// because counter is a member-syntax STATIC (snapshot.h:125 — it
    /// NEVER reads the builder instance; measured zero stats symbols
    /// in the row residue, §0.4). The Rust snapshot Builder carries a
    /// mutable borrow of the snapshot, so threading an inert receiver
    /// next to the borrowed Group would double-borrow; the landed
    /// `Builder::counter` associated fn stands in exactly (same body —
    /// sjson_parity_test.rs already calls it as a static).
    pub fn collect_cache_usage(
        env: &FileEnvLite,
        group: &mut crate::utils::stats::snapshot::Group,
    ) {
        // if (!file_cache) return;
        let Some(cache) = env.svc.get_file_cache() else {
            return;
        };
        // const auto entries = file_cache->get_num_entries();
        let entries = cache.borrow_mut().get_num_entries();
        // if (entries > 0) builder.counter(group, "File cache entries",
        //     static_cast<uint64_t>(entries));
        if entries > 0 {
            crate::utils::stats::snapshot::Builder::counter(
                group,
                "File cache entries",
                crate::utils::stats::snapshot::Value::U64(entries as u64),
            );
        }
    }

    /// h:93-:95 + cc:86-:105 `get_file_cache_clear_status()` — the
    /// 5-arm ladder (enum values pinned by the V1_enum line:
    /// UNAVAILABLE=2, MULTIPROCESS=1, NOT_INITIALIZED=3,
    /// PACKET_THREADS_BUSY=4, READY=0):
    ///
    ///   1. `!sc` -> UNAVAILABLE (cc:89-:91; harness fsvc_set_conf_null
    ///      arm models the null SnortConfig — ported as the
    ///      `conf_present` arg, the SnortConfig seam has no null slot)
    ///   2. `sc->max_procs != 1 or sc->mp_dbus` -> MULTIPROCESS
    ///      (cc:93-/:94; max_procs rides the driver arg, mp_dbus the
    ///      landed env.mp_dbus Cell)
    ///   3. `!file_cache` -> NOT_INITIALIZED (cc:96-:97)
    ///   4. `!main_packet_threads_fully_paused()` -> PACKET_THREADS_BUSY
    ///      (cc:99-:101 via the pause-predicate Cell; pause_calls counts
    ///      the witnesses — the 1/2/3rd arms SHORT-CIRCUIT before it,
    ///      the V3 freeze=0 pin)
    ///   5. READY (cc:104)
    ///
    /// h:94 doc-contract: this reads state only — the cache is NEVER
    /// touched (the V3_unchanged pin).
    pub fn get_file_cache_clear_status(env: &FileEnvLite, conf_present: bool, max_procs: u32) -> super::file_api::FileCacheClearStatus {
        // cc:88-:91
        if !conf_present {
            return super::file_api::FileCacheClearStatus::Unavailable;
        }
        // cc:93-:94 `sc->max_procs != 1 or sc->mp_dbus`
        if max_procs != 1 || env.mp_dbus.get() {
            return super::file_api::FileCacheClearStatus::Multiprocess;
        }
        // cc:96-:97
        if env.svc.file_cache.borrow().is_none() {
            return super::file_api::FileCacheClearStatus::NotInitialized;
        }
        // cc:99-:101 the pause witness: call-count + armed value
        env.svc.pause_calls.set(env.svc.pause_calls.get() + 1);
        if !env.svc.packet_threads_fully_paused.get() {
            return super::file_api::FileCacheClearStatus::PacketThreadsBusy;
        }
        // cc:104
        super::file_api::FileCacheClearStatus::Ready
    }

    /// h:96 + cc:107-:116 `clear_file_cache()`: the status check; ONLY
    /// READY reaches `file_cache->clear()` (cc:112-:113) — the landed
    /// FileCache::clear walk (file_cache.rs:1729) fills the report
    /// (freed/remaining). The non-READY arms return the default result
    /// untouched (the cc:111 no-fire pin: V3_busyarm `st=4 freed=0
    /// kept=2`, then the re-paused READY pass clears the SAME entries).
    pub fn clear_file_cache(env: &FileEnvLite, conf_present: bool, max_procs: u32) -> super::file_api::FileCacheClearResult {
        // C: `FileCacheClearResult result;` (h:60 default = UNAVAILABLE
        // status + zeroed report) then `result.status = ...` — clippy's
        // field_reassign_with_default shape carries the SAME semantics
        // (status lands from get_file_cache_clear_status, the report
        // stays the h:60/h:123/h:124 zero-default).
        let mut result = super::file_api::FileCacheClearResult {
            status: Self::get_file_cache_clear_status(env, conf_present, max_procs),
            ..Default::default()
        };

        // if ( result.status == FileCacheClearStatus::READY )
        //     result.report = file_cache->clear();
        if result.status == super::file_api::FileCacheClearStatus::Ready {
            // h:95 contract-safe here: READY answered with the cache
            // non-null (cc:113 deref is guarded by the same ladder).
            let cache = env.svc.get_file_cache().expect("READY implies non-null file_cache (cc:96 runs before cc:104)");
            result.report = cache.borrow_mut().clear();
        }
        result
    }
    // The free API `snort::get_file_processed_size` (cc:254-:270) keeps
    // its 17q home in file_flows.rs (namespace-scope C linkage, never a
    // FileService member); row 17y retired the harness's verbatim-copy
    // witness — the row .o owns the symbol, Rust side UNCHANGED.
}

/// `SnortClock` seam (17q scope: FileContext's
/// start_time/duration/`duration-%f` lines only — the donor fake
/// clock (`filib_enable_fake_clock` / `fcache_set_fake_now`, DOUBLE
/// seconds into a static g_now; stubs.cc) is what C arms, so the seam
/// carries SECONDS as f64 and every pinned line
/// ("duration-0.000000", "CLK tv=...") lands byte-identical. C keeps
/// ns ticks (clock_defs: TO_USECS = ticks/1000, duration = usecs /
/// 1e6); the f64-seconds unit choice is a documented deviation — no
/// absolute tick ever appears in a transcript, only deltas and the
/// %f render (row 17j rule). No wall-clock tick value is ever
/// printed.
pub trait HrClock {
    fn now(&self) -> f64;
}

/// real-clock default for unpinned paths (monotonic seconds; the
/// epoch base is unobservable, row 17j precedent).
pub struct SystemHrClock;
impl HrClock for SystemHrClock {
    fn now(&self) -> f64 {
        static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        let base = *BASE.get_or_init(std::time::Instant::now);
        std::time::Instant::now().duration_since(base).as_secs_f64()
    }
}

/// `framework/data_bus.h DataBus::publish` witness pair (data_bus.cc
/// drags the pub/sub monolith — donor witness TU stubs.cc prints
/// "PUBBYTES pub=%u evt=%u len=%u data=<hex>" and "PUB pub=%u
/// evt=%u len=%u"):
///   * `publish(intrinsic_pub_id, IntrinsicEventIds::FILE_VERDICT,
///     (const uint8_t*)"LOG"|"BLOCK"|"RESET", len, flow)`
///     (file_lib.cc:624/629/633; `const unsigned intrinsic_pub_id = 1`
///     pub_sub/intrinsic_event_ids.h:73; IntrinsicEventIds::FILE_VERDICT
///     is the 23rd enumerator — header-pinned, fcache transcript
///     "pub=1 evt=23")
///   * `publish(get_file_adv_pub_id(), FileEventIds::FILE_COMPLETE,
///     file_event, flow)` (file_lib.cc:658;
///     pub_sub/file_events_ids.h:44 FILE_COMPLETE = 0; the
///     `DataEvent&` publish witness prints no payload bytes: the fcache
///     line `PUB pub=7 evt=0 len=0`).
pub trait PublishApi {
    fn publish_verdict(&mut self, pid: u32, eid: u32, data: &[u8]);
    fn publish_file_complete(&mut self, pid: u32, eid: u32);
}

pub struct NoPublish;
impl PublishApi for NoPublish {
    fn publish_verdict(&mut self, _pid: u32, _eid: u32, _data: &[u8]) {}
    fn publish_file_complete(&mut self, _pid: u32, _eid: u32) {}
}

pub const INTRINSIC_PUB_ID: u32 = 1;
pub const INTRINSIC_EVENT_ID_FILE_VERDICT: u32 = 23;
pub const FILE_EVENT_ID_FILE_COMPLETE: u32 = 0;

/// Row 17y: `mime/file_mime_process.h MimeSession::{init,exit}` — the
/// OUT-OF-CLOSURE pair FileService reaches at cc:121 (post_init, BEFORE
/// the conf check) and cc:179 (close). The REAL bodies stay queued (the
/// mime row; NEXT.md:126-:131 — MimeSession::init (file_mime_process.cc:
/// 948) news a SearchTool over mpse, the exact drag the fsvc PLAN §2.2
/// scoped out; the harness proves it with the print-pair witnesses).
/// Seam = the driver pin (same pattern as PublishApi): the fsvc replay
/// arms print "WITNESS MimeSession::init|exit" at the exact C positions;
/// the silent default never spawns drag.
pub trait MimeApi {
    fn init(&mut self);
    fn exit(&mut self);
}

pub struct NoMimeSession;
impl MimeApi for NoMimeSession {
    fn init(&mut self) {}
    fn exit(&mut self) {}
}

/// `main/policy.h` NetworkPolicy seam for the factory reach
/// `FileFlows::set_file_policy(get_network_policy()->
///  get_base_file_policy())` (file_flows.cc:150; policy.h:91
/// get_network_policy / :196 get_base_file_policy). The donor witness
/// pair prints "WITNESS get_network_policy" + "POLICY base_file_policy
/// -> stub"; the shared handle rides FilePolicyHandle (file_cache.rs)
/// so the C add_ref / delete_file_policy ref protocol observes the
/// same object.
pub trait NetworkPolicySeam {
    fn get_base_file_policy(&mut self) -> Option<FilePolicyHandle>;
}

/// `DetectionEngine::queue_event` no-op default (the donor witness
/// prints "DE queue_event gid=%u sid=%u" when reached).
pub struct NoopDetectionEvents;
impl DetectionEventSink for NoopDetectionEvents {
    fn queue_event(&mut self, _gid: u32, _sid: u32) {}
}

/// The C file-scope globals + seam bundle both halves reach (the 17p
/// "driver-owned seams" convention): witness pairs (file_trace +
/// GET_CURRENT_PACKET), PacketTracer, DataBus publish,
/// DetectionEngine queue_event, ThreadConfig::get_instance_max +
/// get_instance_id (via ThreadApi + the FileFlows arm below), the
/// interposed SnortClock, the InspectorManager static, and the
/// process-wide counters/ids whose C homes are file statics:
/// `max_file_id` THREAD_LOCAL (file_flows.cc:57), `file_flow_data_id`
/// (+ the FlowData::create_flow_data_id ++ counter, stubs witness
/// :575-577), `file_adv_pub_id` (file_inspect.cc:46, PINNED through the
/// REAL arm of configure() by the finspect row 17w -- setter retired --
/// and read back through file_inspect::get_file_adv_pub_id), the
/// `SnortConfig::mp_dbus` harness shim (fcache_set_mp_dbus, armed for
/// the configure() cc:76-:83 arm), the get_file_config()
/// resolution and the FileService statics.
pub struct FileEnvLite {
    pub trace: Box<dyn super::file_cache::TraceSink>,
    pub curpkt: Box<dyn super::file_cache::CurrentPacketApi>,
    pub packet_tracer: Box<dyn PacketTracerApi>,
    pub publish: Box<dyn PublishApi>,
    pub de: Box<dyn DetectionEventSink>,
    pub clock: Box<dyn HrClock>,
    pub thread: Box<dyn super::file_cache::ThreadApi>,
    pub imgr: ImgrRc,
    /// file_inspect.cc:46 `static std::atomic<unsigned> file_adv_pub_id`
    pub adv_pub_id: Cell<u32>,
    /// file_flows.cc:57 `static THREAD_LOCAL uint32_t max_file_id = 0;`
    pub max_file_id: Cell<u32>,
    /// file_flows.cc:56 / file_flows.h `static unsigned file_flow_data_id`
    pub file_flow_data_id: Cell<u32>,
    /// `FlowData::flow_data_id` (the create_flow_data_id counter arm,
    /// stubs.cc:577 `return ++flow_data_id;`)
    pub flow_data_id: Cell<u32>,
    /// Row 17w: `SnortConfig::mp_dbus` (snort_config.h:391) — the
    /// harness shim armed by fcache_set_mp_dbus (finspect stubs.cc;
    /// fcapi build.sh:131 `bool mp_dbus = false;`). configure()'s
    /// cc:76-:83 subscription arm gates on this; the 17p
    /// FileCache::conf.mp_dbus stays the cache-side view of the SAME
    /// C static (two views in force, same ruling as the config
    /// duality — fcapi PLAN R9).
    pub mp_dbus: Cell<bool>,
    /// main/thread.h `get_instance_id()` witness (stubs.cc:170 hardwired
    /// 0 in the DONOR; the fflows stubs make it armable —
    /// fcache_set_instance_id)
    pub get_instance_id: Cell<u32>,
    /// the fflows/fcache harness FileService WITNESS static `g_max_file_depth`
    /// (stubs.cc `static long long g_max_file_depth = 0;`, armed by
    /// fcache_set_max_file_depth) — the value `get_max_file_depth` answers
    /// through, pinned by the H/J vectors (0, 10, -5 arms). Row 17y note:
    /// against the REAL FileService::get_max_file_depth (the landed
    /// FileServiceLite assoc fn) this Cell is INERT (the R4 drift pin,
    /// fsvc V8_get arms -7/-9 vs the config 1460) — it stays ONLY for the
    /// frozen fflows/fcache passthrough replays through FileEnvLite::
    /// get_max_file_depth below.
    pub max_file_depth: Cell<i64>,
    /// Row 17y: the MimeSession seam (file_service.cc:121 cc:init /
    /// cc:179 close:exit). Silent default; the fsvc replay arms print
    /// the witness pair at the pinned C positions.
    pub mime: Rc<RefCell<Box<dyn MimeApi>>>,
    /// Row 17y: the `SnortConfig::proto_ref` slot the FileService proto
    /// arms read (cc:143/:167 `proto_ref->find("file_id")`) — the REAL
    /// ProtocolReference (the 17y real-cp parity; snort_protocols.rs is
    /// fully ported, find at :141). Harness seed: ctor seeds
    /// unknown/ip/icmp/tcp/udp/file (0..5) + add("file_id") -> 6 (the
    /// fsvc V1 spid pin).
    pub proto_ref: Rc<RefCell<crate::target_based::snort_protocols::ProtocolReference>>,
    pub svc: FileServiceLite,
    /// flow.h `char* service` for the pinned flow (set_source,
    /// file_lib.cc:608 — see the deviation note there). Empty == null.
    pub flow_service: std::cell::RefCell<Vec<u8>>,
    /// get_file_config() resolution (file_config.cc:89; null while no
    /// file inspector is armed)
    pub file_config: Option<Rc<RefCell<FileConfigLite>>>,
    pub network_policy: Option<Rc<RefCell<dyn NetworkPolicySeam>>>,
    /// Row 17r: `fp_eval_service_group` (file_lib.cc:1044) — witness
    /// seam (real fingerprint engine unportable, PLAN §3 WITNESS).
    pub fpe: Box<dyn FpEvalApi>,
    /// Row 17r: `new FileCapture(min, max)` factory seam
    /// (process_file_capture, file_lib.cc:1174; capture engine body
    /// stays its own row).
    pub capture_factory: Box<dyn FileCaptureFactory>,
    /// Row 17r: the C THREAD_LOCAL `FileStats* file_stats` global
    /// (file_stats.cc) the heavy-half ladders bump
    /// (files_processed / signatures_processed / data_processed).
    /// Driver-owned (17m FileStatsEnv discipline); the probe runs
    /// file_stats_init() at startup so the deref is never null in the
    /// pinned runs (the heavy-half expects document that).
    pub stats: std::cell::RefCell<super::file_stats::FileStatsEnv>,
}

impl Default for FileEnvLite {
    /// everything silent / un-armed until wired (donor defaults);
    /// `get_instance_id` models the donor's hardwired 0.
    fn default() -> Self {
        FileEnvLite {
            trace: Box::new(super::file_cache::NoTrace),
            curpkt: Box::new(super::file_cache::NoCurrentPacket),
            packet_tracer: Box::new(super::file_cache::NoPacketTracer),
            publish: Box::new(NoPublish),
            de: Box::new(NoopDetectionEvents),
            clock: Box::new(SystemHrClock),
            thread: Box::new(super::file_cache::DefaultThread),
            imgr: Rc::new(RefCell::new(Box::new(
                super::file_cache::NullInspectorManager,
            ))),
            adv_pub_id: Cell::new(0),
            max_file_id: Cell::new(0),
            file_flow_data_id: Cell::new(0),
            flow_data_id: Cell::new(0),
            mp_dbus: Cell::new(false),
            get_instance_id: Cell::new(0),
            max_file_depth: Cell::new(0),
            mime: Rc::new(RefCell::new(Box::new(NoMimeSession))),
            // the real ProtocolReference ctor (the probe's `new
            // ProtocolReference` — unknown/ip/icmp/tcp/udp/file pre-
            // seeded, find("file_id") misses until the probe/driver
            // add()s it: the harness seeds 6)
            proto_ref: Rc::new(RefCell::new(
                crate::target_based::snort_protocols::ProtocolReference::new(),
            )),
            svc: FileServiceLite::default(),
            flow_service: std::cell::RefCell::new(Vec::new()),
            file_config: None,
            network_policy: None,
            fpe: Box::new(NoFpEval),
            // Row 17s seam closure: the REAL FileCapture engine
            // (file_capture.rs over the live file_mempool.rs +
            // circular_buffer.rs) is now the default `new
            // FileCapture(min, max)` at file_lib.cc:1174 — C `new`
            // never answers null, so process_file_capture's
            // pinned-absent expect at :3005-:3008 holds by
            // construction. NoFileCaptureFactory (file_lib.rs:140-
            // :145) stays for witness opt-out injection (the 17r
            // HubCapture fixtures re-arm their own).
            capture_factory: Box::new(super::file_capture::RealFileCaptureFactory::new()),
            stats: std::cell::RefCell::new(super::file_stats::FileStatsEnv::default()),
        }
    }
}

impl FileEnvLite {
    /// `GET_CURRENT_PACKET` (file_module.h:41 -> DetectionEngine::
    /// get_current_packet): the macro ARGUMENT is evaluated at every
    /// FILE_DEBUG site reached, level gate or not — the port calls the
    /// seam before every GET_CURRENT_PACKET-based FILE_DEBUG exactly
    /// like FileCache::curbkt.
    pub fn curbkt(&mut self) {
        self.curpkt.get_current_packet();
    }

    /// file_config.cc:89 `get_file_config(const SnortConfig* sc =
    /// nullptr)` (harness: the single resolved FileConfig; null arm ->
    /// nullptr, file_config.cc's `fi ? fi->config : nullptr`).
    pub fn get_file_config(&self) -> Option<Rc<RefCell<FileConfigLite>>> {
        self.file_config.clone()
    }

    /// `FileService::get_max_file_depth(FileConfig* fc = nullptr)` as
    /// the 17q link actually resolves it: file_service.cc is NOT in the
    /// fflows/fcache harness closure — FileService is a witness TU and
    /// the body every file_flows/file_lib call site reaches is the
    /// passthrough `return g_max_file_depth;` (stubs.cc's file-scope
    /// static, armed by fcache_set_max_file_depth). The vectors pin
    /// that passthrough verbatim: H_SETNAME1's completion arm needs
    /// depth 0 (`processed(0) == depth(0)`), and J_DEPTH_NEG runs
    /// with -5 passed through (`file_depth < 0` early return). The
    /// REAL file_service.cc:214 body (config-resolved,
    /// `file_depth > 0 ? file_depth : -1`) is row 17r's — deviation,
    /// restated in the plan row until FileService links as a real TU.
    pub fn get_max_file_depth(&self, _fc: Option<&FileConfigLite>) -> i64 {
        self.max_file_depth.get()
    }
}

/// file_flows.h:35 `static const uint32_t FILE_ID_GID = 150;` +
/// file_flows.h:37-42 `enum FileSid`. The `FileEventGen` alias lives
/// in file_flows.rs over helpers::event_gen::EventGen.
pub const FILE_ID_GID: u32 = 150;
pub const EVENT__NONE: i32 = -1;
pub const EVENT_FILE_DROPPED_OVER_LIMIT: i32 = 1;
pub const EVENT__MAX_VALUE: i32 = 2;

/// C-locale `isprint` over a (signed) char: (char)0x80..0xff is
/// negative -> not printable (the 17h json-escape pinned the same
/// rule; 0x7f not printable, 0x20 printable).
fn c_isprint(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// C-locale `isspace` over a (signed) char (the print_file_data
/// hexdump gate, file_lib.cc:1237; same table as parse_ports' private
/// copy of the rule).
fn c_isspace(b: u8) -> bool {
    matches!(b, 0x09..=0x0D | 0x20)
}

/// The printable-sanitizer FileEvent::get_filename (pub_sub/
/// file_events.cc:54) and FileContext::print_file_name (file_lib.cc:
/// 1301) run over the get_UTF8_fname result. Both render unprintables
/// as UPPER-case 2-hex escapes separated by spaces between '|'
/// delimiters (`snprintf "%02X"` / `std::uppercase << setfill('0') <<
/// setw(2) << hex` — the 17o G-block "|FE FF" shape).
fn escape_unprintable(name: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0usize;
    while pos < name.len() {
        if c_isprint(name[pos]) {
            out.push(name[pos]);
            pos += 1;
        } else {
            out.push(b'|');
            let mut add_space = false;
            while pos < name.len() && !c_isprint(name[pos]) {
                if add_space {
                    out.push(b' ');
                } else {
                    add_space = true;
                }
                out.extend_from_slice(format!("{:02X}", name[pos]).as_bytes());
                pos += 1;
            }
            out.push(b'|');
        }
    }
}

/// `FileContext::get_UTF8_fname` (file_lib.cc:85). Non-UTF-16LE names
/// return None (C leaves outbuf == nullptr; every caller then keeps
/// the raw bytes). UTF-16LE names go through the iconv arm the harness
/// builds (config.h HAVE_ICONV=1): the port converts
/// UTF-16LE -> UTF-8 hermetically (BMP + surrogate pairs) instead of
/// linking iconv — documented deviation, identical output for every
/// pinned transcript input (the 17o fffe-prefixed UTF-16 name bytes,
/// BMP-only). C's `size_t* converted_len` out-param == the returned
/// Vec length. Row 17z visibility note: `fn` -> `pub(crate) fn` (the
/// file_log::LogHandler::log_file_name arm, cc:102, is the second
/// TU-scope caller — body UNTOUCHED, deviation row 17z).
pub(crate) fn get_utf8_fname(file_name: &[u8]) -> Option<Vec<u8>> {
    if get_character_encoding(file_name, file_name.len()) != SNORT_CHAR_ENCODING_UTF_16LE {
        return None;
    }
    // iconv("UTF-8", "UTF-16LE", inbuf+BOM, outbuf, len-BOM,
    //       (len-BOM)*2): decode everything after the 2-byte BOM.
    let mut out = Vec::new();
    let mut i = UTF_16_LE_BOM_LEN;
    while i + 1 < file_name.len() {
        let hi = u16::from_le_bytes([file_name[i], file_name[i + 1]]);
        i += 2;
        let cp = if (0xD800..0xDC00).contains(&hi)
            && i + 1 < file_name.len()
            && (0xDC00..0xE000).contains(&u16::from_le_bytes([file_name[i], file_name[i + 1]]))
        {
            let lo = u16::from_le_bytes([file_name[i], file_name[i + 1]]);
            i += 2;
            0x1_0000 + ((hi as u32 - 0xD800) << 10) + (lo as u32 - 0xDC00)
        } else {
            hi as u32
        };
        let c = char::from_u32(cp).unwrap_or('\u{FFFD}');
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    Some(out)
}

pub struct FileContext {
    /// C++ base class `FileInfo` (file_lib.h:50), already ported.
    pub info: FileInfo,

    // file_lib.h private members (defaults verbatim):
    pub(crate) processed_bytes: u64,
    /// C `void* file_type_context`: the file-type identification
    /// context (the FileDetector side of the find_file_type_from_ips
    /// ladder is a later row; C only ever nulls it here
    /// — finalize_file_type + the dtor never free it). 17q shape
    /// kept (Option<()> == "null unless the type-context row lands").
    pub(crate) file_type_context: Option<()>,
    /// C `EVP_MD_CTX* file_signature_context` (file_lib.h:231): the
    /// incremental SHA-256 context the process_file_signature_sha256
    /// ladder drives (file_lib.cc:1065). Zero-dep substitute:
    /// helpers::sha256::Sha256Ctx; `EVP_MD_CTX_new` ==
    /// `Some(Sha256Ctx::new())`, `EVP_MD_CTX_free` == drop (the Drop
    /// arm below), `EVP_MD_CTX_copy_ex` + `EVP_DigestFinal_ex` on the
    /// copy == `snap()`. NULL-vs-empty kept literal: `None` models the
    /// C null pointer (the MIDDLE/END early-return arms, M3 pin),
    /// `Some` the allocated ctx.
    pub(crate) file_signature_context: Option<Sha256Ctx>,
    /// C `FileSegments* file_segments` — row 17r: the real segment
    /// machinery (file_segment.rs). Deviation: the C FileSegments
    /// back-holds `context` (self-referential raw pair); the port
    /// keeps it as Rc<RefCell<FileSegments>> owned here, clones the
    /// handle out of the context borrow, and threads
    /// `this: &Rc<RefCell<FileContext>>` into the segment walk (no
    /// self-referential borrow; process_pos re-borrows cleanly).
    /// `segments_queued()` / the Drop `delete` / `remove_segments`
    /// all read the Option.
    pub(crate) file_segments: Option<Rc<RefCell<FileSegments>>>,
    pub(crate) cacheable: bool, // = true
    pub(crate) cache_dup: bool, // = false
    pub(crate) limit_excluded: bool, // = false
    pub(crate) in_use: i32, // = 0
    /// C `hr_time start_time = TIME_POINT_ZERO;` on the f64-seconds
    /// HrClock seam (unit deviation documented at the trait; the C
    /// header's TIME_POINT_ZERO is never observable — the ctor always
    /// overwrites with now()).
    pub(crate) start_time: f64,
    /// C `double duration = 0.0;` (fractional seconds)
    pub(crate) duration: f64,
    pub(crate) source: Vec<u8>,
    pub(crate) timedout: bool,
    pub(crate) force_adv_log: bool,
    /// C `FileConfig* config` / `FileInspect* inspector` raw
    /// non-owning pointers; the port shares Rc seams with identical
    /// null-gating. The Rc type is file_cache's `FileConfigView` (the
    /// 17p InspectorApi::config seam — pinned by the fcache test's
    /// StubInspector); the fields this half reads through it
    /// (`trace_type`, `file_type_name`) exist on the view. The
    /// full-table side of the same C object rides
    /// `FileEnvLite::file_config` (FileConfigLite) — deviation: two
    /// Rust views model the one C FileConfig pointer, wired from a
    /// single driver-owned source.
    pub(crate) config: Option<Rc<RefCell<FileConfigView>>>,
    pub(crate) inspector: Option<Rc<dyn InspectorApi>>,
    /// The InspectorManager that handed out `inspector` (C reaches the
    /// static in ~FileContext; the port keeps the Rc so the release
    /// witness fires at the exact C delete point — 17p harness-pinned).
    pub(crate) imgr: Option<ImgrRc>,

    /// C's `check_policy(Flow*, FileDirection, ...)` direction
    /// argument, staged per call by FileFlows (the witness
    /// `policy_check(flow, this)` takes `&mut dyn` + `&mut self`;
    /// parking the dir in the struct keeps the two statements' order
    /// and the single write exactly as C).
    pub(crate) pending_dir: u32,
    /// Row 17r: C owns every FileContext through ONE owner slot
    /// (FileFlows ppc/current-alias, FileCache node->file, or a raw
    /// caller pointer) and `delete` runs ~FileContext (file_lib.cc:574
    /// -> the IMGR release witness) AT THE OWNER'S DELETE SITE
    /// regardless of stray alias pointers elsewhere. The Rc port
    /// aliases the same object in driver hands, so a plain last-drop
    /// would move the witness to whenever the aliases happen to die.
    /// The guard makes the dtor body idempotent: owners run
    /// `owner_delete()` at the C delete point; the (C-illegal-by-
    /// construction, port-legal) later Rc last-drops stay silent.
    pub(crate) dtor_ran: std::cell::Cell<bool>,
}

impl Drop for FileContext {
    /// file_lib.cc:574 ~FileContext — idempotent (see dtor_ran): the
    /// last Rc drop runs the body only if no owner delete-site ran it.
    fn drop(&mut self) {
        if !self.dtor_ran.replace(true) {
            self.run_dtor();
        }
    }
}

impl FileContext {
    /// file_lib.cc:574-586 every arm, in C order:
    /// `if (file_signature_context) EVP_MD_CTX_free((EVP_MD_CTX*)..);`
    /// `if (file_capture) stop_file_capture();`
    /// `delete file_segments;`
    /// `if (inspector) InspectorManager::release(inspector);`
    fn run_dtor(&mut self) {
        // if (file_signature_context) EVP_MD_CTX_free(..): the Sha256Ctx
        // slot drops with the struct (row 17r; the C guard arm keeps
        // its observable meaning — the dtor order below).
        if self.info.file_capture.is_some() {
            self.stop_file_capture(); // guard, then unlocked body
        }
        self.file_segments = None; // delete file_segments (null in 17q)
        if let (Some(imgr), Some(ins)) = (&self.imgr, &self.inspector) {
            imgr.borrow_mut().release(ins);
        }
    }

    /// The C `delete <owner slot>` moment for a FileContext: run
    /// ~FileContext NOW at the owner's release site (file_lib.cc:574;
    /// the harness IMGR-release witness lines pin the moment), mark
    /// the guard so the Rc aliases the driver keeps alive never
    /// re-emit the body late.
    pub fn owner_delete(ctx: &Rc<RefCell<FileContext>>) {
        let mut b = ctx.borrow_mut();
        if !b.dtor_ran.replace(true) {
            b.run_dtor();
        }
    }
}

impl FileContext {
    /// 17p-compatible defaults (file_cache.rs `new_file_context`
    /// drives the ctor arms itself; base() = the C default member
    /// init block, start_time stays 0.0 until the C ctor line sets
    /// now()).
    pub(crate) fn base(imgr: Option<ImgrRc>) -> FileContext {
        FileContext {
            info: FileInfo::default(),
            processed_bytes: 0,
            file_type_context: None,
            file_signature_context: None,
            file_segments: None,
            cacheable: true,
            cache_dup: false,
            limit_excluded: false,
            in_use: 0,
            start_time: 0.0,
            duration: 0.0,
            source: Vec::new(),
            timedout: false,
            force_adv_log: false,
            config: None,
            inspector: None,
            imgr,
            pending_dir: FILE_DOWNLOAD,
            dtor_ran: std::cell::Cell::new(false),
        }
    }

    /// `FileContext()` ctor (file_lib.cc:559) — the REAL shape used
    /// by FileFlows::get_file_context / find_main_file_context
    /// (`new FileContext`): `start_time(SnortClock::now())`;
    /// `inspector = static_cast<FileInspect*>(InspectorManager::
    ///  acquire_file_inspector());
    ///  if (inspector and SnortConfig::get_conf())
    ///      config = inspector->config; else config = nullptr;`
    pub fn ctor(imgr: Option<ImgrRc>, env: &FileEnvLite) -> Rc<RefCell<FileContext>> {
        let mut fc = FileContext::base(imgr);
        fc.start_time = env.clock.now();
        if let Some(imgr) = &fc.imgr {
            let ins = imgr.borrow_mut().acquire_file_inspector();
            if let Some(ins) = ins {
                let cfg = ins.config();
                fc.inspector = Some(ins);
                fc.config = Some(cfg);
            }
        }
        Rc::new(RefCell::new(fc))
    }

    // file_lib.h:194-225 inline accessors, literally:
    pub fn set_not_cacheable(&mut self) {
        self.cacheable = false;
    }
    pub fn is_cacheable(&self) -> bool {
        self.cacheable
    }
    pub fn pin(&mut self) {
        self.in_use += 1;
    }
    pub fn unpin(&mut self) {
        if self.in_use > 0 {
            self.in_use -= 1;
        }
    }
    pub fn is_in_use(&self) -> bool {
        self.in_use > 0
    }
    pub fn set_cache_dup(&mut self) {
        self.cache_dup = true;
    }
    pub fn is_cache_dup(&self) -> bool {
        self.cache_dup
    }
    pub fn set_limit_excluded(&mut self) {
        self.limit_excluded = true;
    }
    pub fn is_limit_excluded(&self) -> bool {
        self.limit_excluded
    }
    pub fn get_timedout(&self) -> bool {
        self.timedout
    }
    pub fn set_timedout(&mut self) {
        self.timedout = true;
    }
    /// file_lib.h:212 `segments_queued() const`
    pub fn segments_queued(&self) -> bool {
        self.file_segments.is_some()
    }
    /// file_lib.h:214-215 set_config/get_config (FileConfig*):
    /// get_config answers "is set" through the Rc option (the 17p
    /// shape — C returned the pointer; every consumer tested truth).
    pub fn get_config(&self) -> bool {
        self.config.is_some()
    }
    pub fn set_config(&mut self, fc: Option<Rc<RefCell<FileConfigView>>>) {
        self.config = fc;
    }
    /// file_lib.h:218-219 set_inspector/get_inspector (FileInspect*)
    pub fn set_inspector(&mut self, ins: Option<Rc<dyn InspectorApi>>) {
        self.inspector = ins;
    }
    pub(crate) fn get_inspector(&self) -> bool {
        self.inspector.is_some()
    }
    /// file_lib.h:189 `get_processed_bytes() const`
    pub fn get_processed_bytes(&self) -> u64 {
        self.processed_bytes
    }
    /// file_lib.h:230-231 get_duration/set_duration (fractional seconds)
    pub fn get_duration(&self) -> f64 {
        self.duration
    }
    pub fn set_duration(&mut self, d: f64) {
        self.duration = d;
    }
    /// file_lib.h:235 `get_source() const` (const std::string&)
    pub fn get_source(&self) -> &[u8] {
        &self.source
    }

    /// file_lib.cc:1189/1195 `stop_file_capture()` + the unlocked
    /// body: ud-lock (Rust exclusivity deviation), delete +
    /// config_file_capture(false). 17p carried the seam; the capture
    /// engine body stays its own row.
    pub(crate) fn stop_file_capture(&mut self) {
        if self.info.file_capture.is_some() {
            self.info.file_capture = None; // FileCapture* capture = ...; delete
        }
        self.info.config_file_capture(false);
    }

    /// file_lib.cc:589 inline `finalize_file_type` (stop file type
    /// identification): C writes the raw `UINT16_MAX` into the uint32
    /// field (only 2 octets touched — upper bytes survive; kept
    /// literal, NOT the SNORT_FILE_TYPE_UNKNOWN const).
    #[allow(dead_code)] // row 17r bodies call it (file_lib.cc:1043-...)
    pub(crate) fn finalize_file_type(&mut self) {
        if SNORT_FILE_TYPE_CONTINUE == self.info.file_type_id {
            self.info.file_type_id = u16::MAX as u32;
        }
        self.file_type_context = None;
    }

    /// file_lib.cc:596 `get_mime_type` — the free-global
    /// `get_file_config()` resolution (no-arg arm: get_conf() -> the
    /// file inspector's config).
    pub fn get_mime_type(&self, env: &FileEnvLite) -> String {
        match env.get_file_config() {
            Some(conf) => {
                if SNORT_FILE_TYPE_UNKNOWN != self.info.file_type_id
                    && SNORT_FILE_TYPE_CONTINUE != self.info.file_type_id
                {
                    match conf.borrow().get_rule_from_id(self.info.file_type_id) {
                        Some(info) => info.r#type.clone(),
                        None => String::new(), // info != nullptr ? ... : ""
                    }
                } else {
                    String::new()
                }
            }
            None => String::new(), // conf null -> return ""
        }
    }

    /// file_lib.cc:608 `set_source(Flow* flow)`:
    /// `source = (flow && flow->service ? std::string(flow->service)
    ///     : std::string());` — flow is always the live handle in the
    /// port (never null). Deviation: `flow->service` (flow.h char*)
    /// doesn't ride the Copy CacheFlow key view (its committed 17p
    /// field set), so the harness-armed service name sits on
    /// `FileEnvLite::flow_service` (static storage in C; the empty
    /// Cell == the null pointer — every pinned line renders `source-`
    /// empty, which is what the donor g_flow carries).
    pub fn set_source(&mut self, flow: &CacheFlow, env: &FileEnvLite) {
        let _ = flow; // C reads only flow->service through the handle
        self.source = env.flow_service.borrow().clone();
    }

    /// file_lib.cc:613 `FileContext::log_file_event(Flow*,
    /// FilePolicyBase*)` — the REAL body (the forwarder seam 17p
    /// pinned at file_cache.rs:645 retires). C order: the outer gate
    /// `is_file_name_set() or !flow->two_way_traffic()`; the verdict
    /// switch publishes "LOG"/"BLOCK"/"RESET" verdict strings on the
    /// intrinsic bus (any other verdict sets log_needed=false); the
    /// policy->log_file_action(FILE_ACTION_DEFAULT) arm rides [ud-lock
    /// +] `policy and log_needed and user_file_data and !force_adv_log`
    /// (user_file_data is null on every pinned path — arm transcribed
    /// literally); when `processing_complete or force_adv_log or
    /// log_needed`: now = SnortClock::now(), duration = (now -
    /// start_time) in seconds; FileEvent(*this) { ud-lock:
    /// set_source(flow); snapshot(); } (snapshot = the four lazy
    /// materializations, no output); DataBus::publish(
    /// get_file_adv_pub_id(), FILE_COMPLETE, file_event, flow); then
    /// the GET_CURRENT_PACKET advance-log FILE_DEBUG whose args are the
    /// FileEvent getters (pub_sub/file_events.cc); start_time rewound
    /// to now. Tail: `config->trace_type and !force_adv_log` ->
    /// print(std::cout) (dead: trace_type=false pinned; C derefs config
    /// unguarded — port null-gates).
    pub fn log_file_event(
        &mut self,
        flow: &CacheFlow,
        policy: Option<&mut dyn FilePolicyApi>,
        env: &mut FileEnvLite,
    ) {
        // log file event either when filename is set or if it is a asymmetric flow
        if self.info.is_file_name_set() || !flow.two_way_traffic {
            let mut log_needed = true;

            match self.info.verdict {
                FILE_VERDICT_LOG => {
                    // Log file event through data bus
                    env.publish.publish_verdict(
                        INTRINSIC_PUB_ID,
                        INTRINSIC_EVENT_ID_FILE_VERDICT,
                        b"LOG",
                    );
                }
                FILE_VERDICT_BLOCK => {
                    // can't block session inside a session
                    env.publish.publish_verdict(
                        INTRINSIC_PUB_ID,
                        INTRINSIC_EVENT_ID_FILE_VERDICT,
                        b"BLOCK",
                    );
                }
                FILE_VERDICT_REJECT => {
                    env.publish.publish_verdict(
                        INTRINSIC_PUB_ID,
                        INTRINSIC_EVENT_ID_FILE_VERDICT,
                        b"RESET",
                    );
                }
                _ => {
                    log_needed = false;
                }
            }

            // user_file_data_mutex.lock();
            if let Some(pol) = policy
                && log_needed
                && self.info.user_file_data.is_some()
                && !self.force_adv_log
            {
                pol.log_file_action(flow, self, super::file_cache::FILE_ACTION_DEFAULT);
            }
            // user_file_data_mutex.unlock();

            if self.info.processing_complete || self.force_adv_log || log_needed {
                // hr_time now = SnortClock::now();
                // duration = (TO_USECS(now - start_time)) / 1000000.0;
                let now = env.clock.now();
                self.duration = now - self.start_time;

                // FileEvent file_event(*this);
                // { std::lock_guard udlock(user_file_data_mutex);
                //   set_source(flow); file_event.snapshot(); }
                self.set_source(flow, env);
                // snapshot() = get_filename()/get_sha256()/get_source()/
                // get_extracted_name() — lazy materialization, no output;
                // the advance-log render answers those getters below.

                // DataBus::publish(get_file_adv_pub_id(),
                //     FileEventIds::FILE_COMPLETE, file_event, flow);
                // row 17w seam swap: the REAL getter (file_inspect.cc:
                // :87-:88 over the cc:46 static, whose slot is
                // env.adv_pub_id) now stands between here and the
                // publish; the C TU is the getter's only consumer.
                env.publish.publish_file_complete(
                    super::file_inspect::get_file_adv_pub_id(env),
                    FILE_EVENT_ID_FILE_COMPLETE,
                );

                // std::string filename = file_event.get_filename();
                // size_t fname_len = filename.length();
                // FileCharEncoding encoding =
                //     get_character_encoding(filename.c_str(), fname_len);
                let filename = FileContext::file_event_filename(&self.info);
                let encoding = get_character_encoding(&filename, filename.len());

                // FileEvent field getters (pub_sub/file_events.cc 36
                // -140) answered off the context:
                let mime = self.get_mime_type(env);
                let sha_txt = match self.info.get_file_sig_sha256() {
                    Some(d) => self.info.sha_to_string(d),
                    None => String::new(),
                };
                // (get_sha256 lazily renders via sha_to_string — the
                // 17o UPPERCASE table; empty std::string when no digest)
                let extracted_name = self.info.get_extracted_name().to_vec();
                let seen_bytes = if self.processed_bytes > 0 {
                    self.processed_bytes
                } else {
                    self.info.file_size // "In that case, file_size holds the final processed count"
                };

                // FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID,
                // TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
                // "File advance log: fuid-%" PRIu64 ", source-%s,
                //  mime type-%s, file name-%s, duration-%f, is orig-%d,
                //  seen bytes-%" PRIu64 ", total bytes-%" PRIu64 ",
                //  timedout-%d, sha256-%s, extracted name-%s,
                //  extracted cutoff-%d, extracted size-%" PRIu64 "\n",
                //  file_event.get_fuid(), get_source(), get_mime_type(),
                //  (encoding==UTF16 ? "" : filename), get_duration(),
                //  get_is_orig(), get_seen_bytes(), get_total_bytes(),
                //  get_timedout(), get_sha256(),
                //  (encoding==UTF16 ? "" : get_extracted_name()),
                //  get_extracted_cutoff(), get_extracted_size())
                // C's %f: fixed lowercase, 6 fraction digits
                // (0.000000 pinned); {:.6} matches.
                env.curbkt();
                env.trace.file_trace(
                    TRACE_DEBUG_LEVEL,
                    &format!(
                        "File advance log: fuid-{}, source-{}, mime type-{}, file name-{}, duration-{:.6}, is orig-{}, seen bytes-{}, total bytes-{}, timedout-{}, sha256-{}, extracted name-{}, extracted cutoff-{}, extracted size-{}\n",
                        self.info.get_file_id(), // get_fuid
                        String::from_utf8_lossy(self.get_source()),
                        mime,
                        if encoding == SNORT_CHAR_ENCODING_UTF_16LE {
                            String::new()
                        } else {
                            String::from_utf8_lossy(&filename).into_owned()
                        },
                        self.duration,
                        u8::from(self.info.get_file_direction() == FILE_UPLOAD), // get_is_orig
                        seen_bytes,
                        self.info.file_size, // get_total_bytes
                        u8::from(self.timedout), // get_timedout %d
                        sha_txt,
                        if encoding == SNORT_CHAR_ENCODING_UTF_16LE {
                            String::new()
                        } else {
                            String::from_utf8_lossy(&extracted_name).into_owned()
                        },
                        u8::from(self.info.get_extracted_cutoff()), // %d
                        self.info.get_extracted_size(),
                    ),
                );
                self.start_time = env.clock.now();
            }

            // if ( config->trace_type and !force_adv_log )
            // { udlock; print(std::cout); }
            if !self.force_adv_log
                && let Some(cfgrc) = self.config.clone()
                && cfgrc.borrow().trace_type
            {
                // std::cout: the harness transcript never carries it
                // (trace_type=false pinned, I-block comment: "the
                // full ... config->trace_type print bypass"); the
                // faithful stream is built and unpinned.
                let _ = self.print(env);
            }
        }
    }

    /// The 17p forwarder preserved for FileCache's three pinned call
    /// sites (apply_verdict / store / resume paths): the fcache test's
    /// FileCacheEventSink wiring (EvtSink) is what reproduces the
    /// committed 17p transcript (PUBBYTES/PUB/advance-log lines), so
    /// the cache half keeps driving the seam. C has ONE method; the
    /// split (sink-forwarder vs real env body) is a row-17q deviation
    /// restated in the plan notes: FileFlows (the 17q subject) reaches
    /// the real body below, FileCache's sites stay seam-pinned.
    pub(crate) fn log_file_event_sink(
        &self,
        flow: &CacheFlow,
        policy: &mut dyn FilePolicyApi,
        events: &mut dyn super::file_cache::FileCacheEventSink,
    ) {
        events.file_log_event(self, flow, policy);
    }

    /// pub_sub/file_events.cc:54 FileEvent::get_filename (the lazy
    /// snapshot materialization made direct): empty name -> ""; else
    /// the get_UTF8_fname-or-raw-byte stream through the printable
    /// sanitizer.
    pub(crate) fn file_event_filename(info: &FileInfo) -> Vec<u8> {
        let mut filename = Vec::new();
        let fname_len = info.file_name.len();
        if fname_len != 0 {
            let outbuf = get_utf8_fname(&info.file_name);
            let fname: &[u8] = match &outbuf {
                Some(u) => u, // (outbuf != nullptr) ? outbuf : ...
                None => &info.file_name,
            };
            escape_unprintable(fname, &mut filename);
        }
        filename
    }

    /// file_lib.cc:1301 `print_file_name(std::ostream&)` as a string
    /// (populate_trace_data feeds the ostringstream; the
    /// "File name: " prefix + the trailing endl ride the
    /// PacketTracer::is_daq_activated() gate exactly as C). 17r: pub
    /// (FIXACC parity — the C probe reaches the private member
    /// directly, file_lib.h joined the harness private->public list).
    pub fn print_file_name_str(&self, env: &FileEnvLite) -> String {
        let mut out = String::new();
        if self.info.file_name.is_empty() {
            return out; // size_t fname_len == 0 -> return (no prefix)
        }
        let outbuf = get_utf8_fname(&self.info.file_name);
        let fname: &[u8] = match &outbuf {
            Some(u) => u,
            None => &self.info.file_name,
        };
        if !env.packet_tracer.is_daq_activated() {
            out.push_str("File name: ");
        }
        let mut esc = Vec::new();
        escape_unprintable(fname, &mut esc);
        out.push_str(&String::from_utf8_lossy(&esc));
        if !env.packet_tracer.is_daq_activated() {
            out.push('\n'); // log << std::endl
        }
        out
    }

    /// file_lib.cc:1331 `print_file_sha256(std::ostream&)` — null
    /// digest early return; else "SHA256: " + 2-byte hex pairs
    /// (uppercase, space-separated) + endl, fmtflags save/restore.
    #[allow(dead_code)] // FileContext::print tail (file_lib.cc:1080; 17r)
    /// file_lib.cc:1330 `print_file_sha256(std::ostream&)` as a
    /// string (uppercase, 4-hex groups). 17r: pub (FIXACC parity —
    /// the C probe reaches the private member directly).
    pub fn print_file_sha256_str(&self) -> String {
        let mut out = String::new();
        let hash = match self.info.get_file_sig_sha256() {
            Some(h) => h,
            None => return out,
        };
        out.push_str("SHA256: ");
        for i in (0..SHA256_HASH_SIZE).step_by(2) {
            out.push_str(&format!("{:02X}{:02X}", hash[i], hash[i + 1]));
            if i < SHA256_HASH_SIZE - 2 {
                out.push(' ');
            }
        }
        out.push('\n');
        out
    }

    /// file_lib.cc:1348 `print(std::ostream&)` (reached only through
    /// the dead config->trace_type tail). 17r: pub (FIXACC parity —
    /// the C probe calls the private member directly).
    pub fn print(&self, env: &FileEnvLite) -> String {
        let mut out = self.print_file_name_str(env);
        if !self.info.url.is_empty() {
            out.push_str("File URI: ");
            out.push_str(&String::from_utf8_lossy(&self.info.url));
            out.push('\n');
        }
        if !self.info.host_name.is_empty() {
            out.push_str("Host name: ");
            out.push_str(&String::from_utf8_lossy(&self.info.host_name));
            out.push('\n');
        }
        out.push_str(&format!(
            "File type: {}({})\n",
            self.config
                .as_ref()
                .map(|c| c.borrow().file_type_name(self.info.file_type_id))
                .unwrap_or_default(),
            self.info.file_type_id
        ));
        out.push_str(&format!("File size: {}\n", self.info.file_size));
        out.push_str(&format!("Processed size: {}\n", self.processed_bytes));
        out
    }

    /// 17r test seam (FIXACC private->public parity: probe.cc arms
    /// `ctx->processed_bytes = 3` directly for the K9 depth ladder,
    /// file_lib.h:230 joined the harness's private->public list).
    pub fn fl_test_processed_bytes_set(&mut self, n: u64) {
        self.processed_bytes = n;
    }

    /// file_lib.cc:744 `set_signature_state(bool gen_sig)` — frees a
    /// digest WITHOUT clearing is_sha256_set (serialize gates on the
    /// pointer; the stale flag stays invisible — kept literal);
    /// gen_sig clears + latches FLUSH, else PROCESSING.
    pub fn set_signature_state(&mut self, gen_sig: bool) {
        if gen_sig {
            if self.info.sha256.is_some() {
                self.info.sha256 = None; // snort_free(sha256); sha256 = nullptr
            }
            self.info.file_state.sig_state = FILE_SIG_FLUSH;
        } else {
            self.info.file_state.sig_state = FILE_SIG_PROCESSING;
        }
    }

    /// file_lib.cc:760 `check_policy(Flow*, FileDirection,
    /// FilePolicyBase*)`:
    /// `file_counts.files_total++; set_file_direction(dir);
    ///  policy->policy_check(flow, this);` — `file_counts` is the C
    /// THREAD_LOCAL global (driver-owned `&mut FileCounts`, rows
    /// 17m/17o/17p convention); `dir` rides pending_dir (C's third
    /// real argument — the witness `policy_check(&mut FileContext)`
    /// reborrow makes the plain parameter impossible inside the same
    /// statement; the two C statements land in order, single write).
    pub fn check_policy(&mut self, flow: &CacheFlow, policy: &mut dyn FilePolicyApi, counts: &mut FileCounts) {
        counts.files_total += 1;
        let dir = self.pending_dir;
        self.info.set_file_direction(dir);
        policy.policy_check(flow, self);
    }

    /// file_lib.cc:801 `remove_segments` — full body: null early
    /// return; else `delete file_segments;` (the machinery itself is
    /// the circular-buffer/file-segment row; the pinned paths all take
    /// the null-guard arm).
    pub fn remove_segments(&mut self) {
        if self.file_segments.is_none() {
            return;
        }
        self.file_segments = None; // FileSegments* s = file_segments; delete s
    }

    /// file_lib.cc:810 `FileContext::reset` — the derived reset that
    /// HIDES FileInfo::reset (the C++ shadow the upstream cppcheck
    /// note flags): verdict/counters like the base, then
    /// remove_segments + start_time rearm + force_adv_log clear (and
    /// NOT base re_eval / pending_expire — those belong to the
    /// FileInfo reset ported at the FileInfo half).
    pub fn reset(&mut self, env: &FileEnvLite) {
        self.info.verdict = FILE_VERDICT_UNKNOWN;
        self.info.processing_complete = false;
        self.info.reset_sha();
        self.remove_segments();
        self.start_time = env.clock.now();
        self.force_adv_log = false;
    }

    /// file_lib.cc:1207 `update_file_size(int data_size, FilePosition)`
    /// — full body incl. the GET_CURRENT_PACKET FILE_DEBUG (macro arg
    /// always evaluated: curbkt first). C adds the int to the u64 in
    /// 2's-complement wrap; kept as the wrapping add on the u64.
    pub fn update_file_size(
        &mut self,
        data_size: i32,
        position: u32,
        env: &mut FileEnvLite,
    ) {
        self.processed_bytes =
            (self.processed_bytes as i64).wrapping_add(data_size as i64) as u64;

        env.curbkt();
        env.trace.file_trace(
            TRACE_DEBUG_LEVEL,
            &format!(
                "Updating file size of file_id {} at position {} with processed_bytes {}\n",
                self.info.file_id, position, self.processed_bytes
            ),
        );
        if position == SNORT_FILE_END || position == SNORT_FILE_FULL {
            self.info.file_size = self.processed_bytes;
            self.processed_bytes = 0;
            self.info.processing_complete = true;
        } else if position == SNORT_FILE_MIDDLE
            && self.info.get_file_sig_sha256().is_some()
        {
            self.info.file_size = self.processed_bytes;
        }
    }

    // ---------------- 17r heavy-half members (row 17r landed) ----------------
    //
    // The signature-lookup pair were C members running on the raw
    // `this`; the port keeps them as associated functions threading
    // `this: &Rc<RefCell<FileContext>>` so apply_verdict /
    // log_file_event keep their 17p/17q Rc shapes. The C `policy`
    // raw pointer is reused at several sites per ladder; the Rust
    // rides one FilePolicyHandle alias per ladder (Rc alias of the
    // same PolicyStore — aliasing, not ref_count: the C raw pointer
    // arg never touches ref_count either; the 17q FilePolicyHandle
    // note). Each C `policy->X(...)` site opens the object through
    // with_policy_mut (the C-pointer call shape); the null pointer ==
    // (None, panic or guard) per C site: C derefs at the lookup and
    // apply_verdict sites, log_file_event has base-class-default null
    // arms.

    /// file_lib.cc:701 finish_signature_lookup.
    pub fn finish_signature_lookup(
        this: &Rc<RefCell<FileContext>>,
        p: &mut PacketView,
        final_lookup: bool,
        policy: Option<FilePolicyHandle>,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) {
        // Flow* flow = p->flow;
        let flow = p.flow;

        // if (get_file_sig_sha256())
        if this.borrow().info.get_file_sig_sha256().is_some() {
            // verdict = policy->signature_lookup(p, this);
            // (C derefs the possibly-null policy pointer; pinned-absent
            // at this site — every armed ladder passes the stub.)
            let verdict = match policy.as_ref() {
                Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                    let mut cb = this.borrow_mut();
                    pol.signature_lookup(p, &mut cb)
                })},
                None => panic!("C deref of null `FilePolicyBase*` at file_lib.cc:706 signature_lookup — pinned-absent"),
            };
            // C keeps the verdict member live across the rest; the port
            // writes it at the same point.
            this.borrow_mut().info.verdict = verdict;

            // FILE_DEBUG(..., TRACE_DEBUG_LEVEL, p, "finish signature
            // lookup verdict %d\n", verdict)  (p arg: no
            // GET_CURRENT_PACKET — no curbkt seam)
            env.trace.file_trace(
                TRACE_DEBUG_LEVEL,
                &format!("finish signature lookup verdict {verdict}\n"),
            );

            if verdict != FILE_VERDICT_UNKNOWN || final_lookup {
                // FileCache* file_cache = FileService::get_file_cache();
                // if (file_cache) file_cache->apply_verdict(p, this,
                // verdict, false, policy);
                match (env.svc.get_file_cache(), policy.clone()) {
                    // C calls apply_verdict as a STATEMENT here (the bool return
                    //  value is dropped at the C call site — `let _` keeps that
                    //  non-observable shape explicit).
                    (Some(cache), Some(mut h)) => {
                        let _ = h.with_policy_mut(|pol| {
                            cache.borrow_mut().apply_verdict(p, this, verdict, false, pol, counts)
                        });
                    }
                    (Some(_), None) => panic!("C deref of null `FilePolicyBase*` at file_lib.cc:714 apply_verdict — pinned-absent"),
                    (None, _) => {} // C `if (file_cache)` guard
                }

                // if (PacketTracer::is_active() and (verdict == BLOCK or
                //     verdict == REJECT))
                //   PacketTracer::log("File: signature lookup verdict %s\n", ...)
                if env.packet_tracer.is_active()
                    && (verdict == FILE_VERDICT_BLOCK || verdict == FILE_VERDICT_REJECT)
                {
                    env.packet_tracer.log(&format!(
                        "File: signature lookup verdict {}\n",
                        if verdict == FILE_VERDICT_BLOCK {
                            "block"
                        } else {
                            "reject"
                        }
                    ));
                }

                // log_file_event(flow, policy);
                // (handle-alias open at the C policy-> site; the C
                //  null pointer reaches log_file_event's null-check
                //  arms — file_lib.cc:615 `if (!policy) return;` —
                //  modeled by the None arm)
                match policy.as_ref() {
                    Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                        this.borrow_mut().log_file_event(&flow, Some(pol), env)
                    })},
                    None => this.borrow_mut().log_file_event(&flow, None, env),
                }

                // config_file_signature(false);
                this.borrow_mut().info.config_file_signature(false);

                // file_stats->signatures_processed[get_file_type()]
                //     [get_file_direction()]++;
                {
                    let cb = this.borrow();
                    let ft = cb.info.get_file_type() as usize;
                    let fd = cb.info.get_file_direction() as usize;
                    drop(cb);
                    file_stats_bump_signatures(env, ft, fd);
                }
            } else {
                // cppcheck-suppress knownConditionTrueFalse ;
                // completion and verdict depend on file processing
                // if ( processing_complete and (verdict == FILE_VERDICT_UNKNOWN ))
                // { force_adv_log sandwich + log_file_event }
                if this.borrow().info.processing_complete && verdict == FILE_VERDICT_UNKNOWN {
                    this.borrow_mut().force_adv_log = true;
                    // (handle-alias open at the C policy-> site; the C
                    //  null pointer reaches log_file_event's null-check
                    //  arms — file_lib.cc:615 `if (!policy) return;` —
                    //  modeled by the None arm)
                    match policy.as_ref() {
                        Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                            this.borrow_mut().log_file_event(&flow, Some(pol), env)
                        })},
                        None => this.borrow_mut().log_file_event(&flow, None, env),
                    }
                    this.borrow_mut().force_adv_log = false;
                }
                // { std::lock_guard<std::recursive_mutex> lock(
                //       user_file_data_mutex);
                //   snort_free(sha256); sha256 = nullptr; }
                // (ud-lock = Rust exclusivity, 17p deviation; the
                // snort_free-vs-new[] mixed-allocator pair on the C
                // sha256 slot is structurally excluded in Rust,
                // PLAN section 5-M — one Option covers both.)
                this.borrow_mut().info.sha256 = None;
            }
        }
    }

    /// file_lib.cc:686 file_signature_lookup — public for the FileCache
    /// / FileService rows (the fflows J-block never reaches through
    /// here: the cached-verdict arm returns earlier). Deviation: the C
    /// `FileFlows::get_file_policy(flow)` static resolves through the
    /// driver-owned flow handle (FlowsRef, PLAN section 6.2 — the Flow
    /// monolith does not ride the port; the slot IS the flow's
    /// FileFlows handle).
    pub fn file_signature_lookup(
        this: &Rc<RefCell<FileContext>>,
        p: &mut PacketView,
        flows: FlowsRef<'_>,
    ) -> u32 {
        // Flow* flow = p->flow;
        // if (get_file_sig_sha256())
        if this.borrow().info.get_file_sig_sha256().is_some() {
            // FilePolicyBase* policy = FileFlows::get_file_policy(flow);
            // (file_flows.rs get_file_policy_static: fd && fd->file_policy)
            if let Some(mut handle) = flows.file_policy_handle() {
                // if (policy) return policy->signature_lookup(p, this);
                // (the handle type only ever fronts a real object —
                // FilePolicyHandle::is_null false)
                return handle.with_policy_mut(|pol| {
                    let mut cb = this.borrow_mut();
                    pol.signature_lookup(p, &mut cb)
                });
            }
        }

        // return FILE_VERDICT_UNKNOWN;
        FILE_VERDICT_UNKNOWN
    }

    /// file_lib.cc:1057 process_file_type — "file type already found
    /// and no magics to continue": only the CONTINUE type re-enters
    /// the detection walk.
    #[allow(clippy::too_many_arguments)] // C method arg set + threaded this
    pub fn process_file_type(
        this: &Rc<RefCell<FileContext>>,
        p: &mut PacketView,
        file_data: &[u8],
        data_size: i32,
        position: u32,
        flows: &mut FlowsRef<'_>,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) {
        if SNORT_FILE_TYPE_CONTINUE == this.borrow().info.file_type_id {
            find_file_type_from_ips(this, p, file_data, data_size, position, flows, env, counts);
        }
    }

    /// file_lib.cc:1065 process_file_signature_sha256 — the
    /// incremental OpenSSL EVP chain rides the zero-dep
    /// helpers::sha256::Sha256Ctx (new/init/update verbatim;
    /// copy_ex + DigestFinal on the copy == snap(), live-ctx
    /// DigestFinal == finalize; M-block pins match the C digests).
    /// The C `snort_alloc` (START/MIDDLE FLUSH) vs `new uint8_t[]`
    /// (END/FULL) pair on sha256 is observably one Option write
    /// (no C read tells the allocators apart; the END/FULL
    /// overwrite-vs-`if (!sha256)` difference re-materializes only
    /// as the same Some([u8; 32])).
    /// 17r: pub (FIXACC parity — the C probe calls the private member
    /// directly; file_lib.h:177 joined the harness private->public
    /// list).
    pub fn process_file_signature_sha256(
        &mut self,
        file_data: &[u8],
        data_size: i32,
        position: u32,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) {
        // std::lock_guard<std::recursive_mutex> lock(user_file_data_mutex);
        // (17p single-thread deviation: Rust exclusivity models the lock)

        // if ((int64_t)processed_bytes + data_size > config->file_signature_depth)
        let depth = self
            .config
            .as_ref()
            .expect("config member null at file_lib.cc:1070 (C derefs; a signature-enabled ladder has the FileInspect armed => config armed — pinned-absent)")
            .borrow()
            .file_signature_depth;
        // (the view field mirrors the FileConfigLite member; both
        // views answer the one C FileConfig — deviation at the
        // config slot)
        if (self.processed_bytes as i64) + (data_size as i64) > depth {
            // FILE_DEBUG(..., GET_CURRENT_PACKET,
            // "process_file_signature_sha256:FILE_SIG_DEPTH_FAIL\n")
            env.curbkt();
            env.trace.file_trace(
                TRACE_INFO_LEVEL,
                "process_file_signature_sha256:FILE_SIG_DEPTH_FAIL\n",
            );
            self.info.file_state.sig_state = FILE_SIG_DEPTH_FAIL;
            counts.file_sig_depth_exceeded += 1;
            return;
        }

        // FILE_DEBUG(..., GET_CURRENT_PACKET, "processing file signature
        // position: %d sig state %d \n", position, file_state.sig_state)
        // (the trailing space before \n is verbatim C)
        env.curbkt();
        env.trace.file_trace(
            TRACE_DEBUG_LEVEL,
            &format!(
                "processing file signature position: {position} sig state {} \n",
                self.info.file_state.sig_state
            ),
        );

        // if (!sha256) sha256 = snort_alloc / = new uint8_t[32]; +
        // EVP_DigestFinal into it — one Option write per position,
        // below. Negative data_size: C hands the int to
        // EVP_DigestUpdate's size_t (huge value, C UB territory; the
        // pinned vectors keep it >= 0 — saturate, literal otherwise).
        let n = (data_size.max(0) as usize).min(file_data.len());
        match position {
            SNORT_FILE_START => {
                // if (!file_signature_context) file_signature_context =
                //     EVP_MD_CTX_new();
                let ctx = self
                    .file_signature_context
                    .get_or_insert_with(Sha256Ctx::new);
                // EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
                ctx.init();
                // EVP_DigestUpdate(ctx, file_data, data_size);
                ctx.update(&file_data[..n]);
                // FILE_DEBUG(..., GET_CURRENT_PACKET, "position is
                // start of file\n")
                env.curbkt();
                env.trace.file_trace(TRACE_DEBUG_LEVEL, "position is start of file\n");
                if self.info.file_state.sig_state == FILE_SIG_FLUSH {
                    // EVP_MD_CTX* tmp = EVP_MD_CTX_new();
                    // EVP_MD_CTX_copy_ex(tmp, ctx) + DigestFinal_ex(tmp,
                    // sha256) + EVP_MD_CTX_free(tmp)  ==  snap()
                    let digest = self
                        .file_signature_context
                        .as_ref()
                        .expect("ctx vanished between arms (impossible)")
                        .snap();
                    self.info.sha256 = Some(digest);
                }
            }

            SNORT_FILE_MIDDLE => {
                // if (!file_signature_context) return;   (M3 pin:
                // None == the C null EVP_MD_CTX* early return)
                let ctx = match self.file_signature_context.as_mut() {
                    Some(ctx) => ctx,
                    None => return,
                };
                ctx.update(&file_data[..n]);
                env.curbkt();
                env.trace.file_trace(TRACE_DEBUG_LEVEL, "position is middle of the file\n");
                if self.info.file_state.sig_state == FILE_SIG_FLUSH {
                    let digest = self
                        .file_signature_context
                        .as_ref()
                        .expect("ctx vanished between arms (impossible)")
                        .snap();
                    self.info.sha256 = Some(digest);
                }
            }

            SNORT_FILE_END => {
                // if (!file_signature_context) return;
                let ctx = match self.file_signature_context.as_mut() {
                    Some(ctx) => ctx,
                    None => return,
                };
                ctx.update(&file_data[..n]);
                // sha256 = new uint8_t[SHA256_HASH_SIZE];
                // EVP_DigestFinal_ex(ctx, sha256, &out_len);
                self.info.sha256 = Some(ctx.finalize());
                self.info.file_state.sig_state = FILE_SIG_DONE;
                env.curbkt();
                env.trace.file_trace(TRACE_DEBUG_LEVEL, "position is end of the file\n");
            }

            SNORT_FILE_FULL => {
                // if (!file_signature_context) file_signature_context =
                //     EVP_MD_CTX_new();
                let ctx = self
                    .file_signature_context
                    .get_or_insert_with(Sha256Ctx::new);
                ctx.init();
                ctx.update(&file_data[..n]);
                self.info.sha256 = Some(ctx.finalize());
                self.info.file_state.sig_state = FILE_SIG_DONE;
                env.curbkt();
                env.trace.file_trace(TRACE_DEBUG_LEVEL, "position is full file\n");
            }

            // default: break;  (SNORT_FILE_POSITION_UNKNOWN: nothing)
            _ => {}
        }
    }

    /// file_lib.cc:1226 print_file_data(FILE*, const uint8_t*, int
    /// len, int max_depth) — the hexdump writer, ported to a String
    /// (the K1/K2 harness seams route it to stdout verbatim; the C
    /// fprintf sites are transcribed byte-for-byte, incl. the "Show
    /// length: %d " trailing-space header, the pos==8 double gap, the
    /// pos==17 row break and the tail-pad "   "/"    " arms). C-locale
    /// isprint/isspace over (char) sign.
    pub fn print_file_data(data: &[u8], len: i32, max_depth: i64) -> String {
        // if (max_depth < len) len = max_depth;
        let mut len = len as i64;
        if max_depth < len {
            len = max_depth;
        }
        let len = len.max(0) as usize;

        let mut out = String::new();
        out.push_str(&format!("Show length: {len} \n"));

        // C `char str[18]` + cursor; the NUL terminator lands when the
        // row prints (str[pos] = 0 at pos==17 / at the tail).
        let mut strbuf: Vec<u8> = Vec::new();
        let mut pos = 0usize;
        for b in data.iter().copied().take(len) {
            // char c = (char)data[i];
            // isprint(c) and (c == ' ' or !isspace(c)) ? c : '.'
            let printable = c_isprint(b) && (b == b' ' || !c_isspace(b));
            strbuf.push(if printable { b } else { b'.' });
            pos += 1;
            out.push_str(&format!("{b:02X} "));

            if pos == 17 {
                out.push_str(&format!("  {}\n", String::from_utf8_lossy(&strbuf)));
                // C `pos = 0`: the str cursor rewinds and every later
                // write overwrites from index 0 — the row's content is
                // dead.  The port's Vec is cleared here to model the
                // C str[pos]=0-then-overwrite semantics exactly.
                strbuf.clear();
                pos = 0;
            } else if pos == 8 {
                strbuf.push(b' ');
                pos += 1;
                out.push(' ');
            }
        }
        if pos != 0 {
            // C: `str[pos] = 0; for (; pos < 17; pos++) { if (pos ==
            // 8) { pos++; fprintf(fp, "%s", "    "); } else fprintf(
            // fp, "%s", "   "); }` — the body's pos++ at pos==8
            // SKIPS one iteration on top of the loop's pos++ (a
            // frozen-range form would emit a stray group); the str
            // NUL already sits at the vec boundary and nothing reads
            // pos after the walk, so the cursor rides `pad`
            // literally.
            let mut pad = pos;
            while pad < 17 {
                if pad == 8 {
                    pad += 1;
                    out.push_str("    ");
                } else {
                    out.push_str("   ");
                }
                pad += 1;
            }
            out.push_str(&format!("  {}\n", String::from_utf8_lossy(&strbuf)));
        }
        out
    }
}

// ==================================================================
// Row 17r free-function half — the heavy FileContext ladders.
//
// The C members run raw-pointer style on `this`; the port threads
// `this: &Rc<RefCell<FileContext>>` and re-borrows per C
// statement-group so (a) the cache/apply/log calls keep their Rc
// shapes, (b) an armed fp_eval witness can write file_type through the
// handle WITHOUT a ReentrantRuntime panic, and (c) the statement
// ORDER lands exactly where C put it (the borrow blocks are invisible;
// they cannot reorder or duplicate a C line — each line appears
// exactly once across blocks).
// ==================================================================

/// The flow handle the heavy half threads (file_lib <-> file_flows
/// mutual-call chain; skill rule for C mutual-call chains: explicit
/// handle refs, no self-referential structs). The C statics resolve
/// FileFlows out of the Flow's flow data (file_flows.cc:133
/// get_file_flows(flow, to_create=false) — the flow's own fd); in the
/// port that identity is reached two ways:
/// * Handle: the driver-owned Rc<RefCell> (the fctx probe shape);
/// * Direct: the in-call `&mut self` FileFlows when file_process_multi
///   / file_process entered the heavy half — C flow-data identity IS
///   this object, no static re-resolution needed (and the heavy half
///   never takes the create arm: :1030 passes to_create=false).
///
/// The null arm (get_file_flows answers nullptr — flow carries no fd,
/// to_create=false) only exists in the Handle form.
pub enum FlowsRef<'a> {
    Handle(&'a Rc<RefCell<FileFlows>>),
    Direct(&'a mut FileFlows),
}

impl<'a> FlowsRef<'a> {
    /// `files->get_current_file_context()` (a C const-ish read; takes
    /// the get_file_context arm when current_file_id rides).
    pub fn get_current_file_context(
        &mut self,
        env: &mut FileEnvLite,
        counts: &mut FileCounts,
    ) -> Option<Rc<RefCell<FileContext>>> {
        match self {
            FlowsRef::Handle(h) => h.borrow_mut().get_current_file_context(env, counts),
            FlowsRef::Direct(ff) => ff.get_current_file_context(env, counts),
        }
    }
    /// `files->swap_current_file_context_no_delete(this)`
    pub fn swap_current_file_context_no_delete(
        &mut self,
        new_ctx: &Rc<RefCell<FileContext>>,
    ) -> CurrentContextSlot {
        match self {
            FlowsRef::Handle(h) => h.borrow_mut().swap_current_file_context_no_delete(new_ctx),
            FlowsRef::Direct(ff) => ff.swap_current_file_context_no_delete(new_ctx),
        }
    }
    /// `files->restore_current_file_context_no_delete(saved)`
    pub fn restore_current_file_context_no_delete(&mut self, saved: &CurrentContextSlot) {
        match self {
            FlowsRef::Handle(h) => h.borrow_mut().restore_current_file_context_no_delete(saved),
            FlowsRef::Direct(ff) => ff.restore_current_file_context_no_delete(saved),
        }
    }
    /// `FileFlows::get_file_policy(flow)` — the C static: fd &&
    /// fd->file_policy; None arm == no flows (null fd).
    pub fn file_policy_handle(self) -> Option<FilePolicyHandle> {
        match self {
            FlowsRef::Handle(h) => FileFlows::get_file_policy_static(Some(h)),
            FlowsRef::Direct(ff) => ff.file_policy.clone(),
        }
    }
}

/// file_lib.cc:905/:932/:736 `file_stats->...` — the C THREAD_LOCAL
/// `FileStats* file_stats` global (file_stats.cc), driver-owned
/// through FileEnvLite::stats (17m discipline; the probe runs
/// file_stats_init() at startup so the C deref is never null in the
/// pinned runs — the expect documents that). The C arrays are indexed
/// by the FULL u16 file_type value (MAX_FILE_TYPES rows); a pinned
/// out-of-range type at the :736 site (UNKNOWN reaches the
/// signatures_processed arm only via ladder arms that already excluded
/// it) is C UB the port can never panic on — min-clamped with this
/// note, and pinned vectors never observe the clamp firing.
fn file_stats_bump_files(env: &FileEnvLite, ft: usize, dir: usize) {
    let mut b = env.stats.borrow_mut();
    let fs = b
        .file_stats
        .as_mut()
        .expect("file_stats null at file_lib.cc:905 (file_stats_init not run; pinned-absent)");
    let ft = ft.min(fs.files_processed.len() - 1);
    fs.files_processed[ft][dir] += 1;
}

fn file_stats_bump_signatures(env: &FileEnvLite, ft: usize, dir: usize) {
    let mut b = env.stats.borrow_mut();
    let fs = b
        .file_stats
        .as_mut()
        .expect("file_stats null at file_lib.cc:736 (file_stats_init not run; pinned-absent)");
    let ft = ft.min(fs.signatures_processed.len() - 1);
    fs.signatures_processed[ft][dir] += 1;
}

fn file_stats_add_data(env: &FileEnvLite, ft: usize, dir: usize, size: i32) {
    let mut b = env.stats.borrow_mut();
    let fs = b
        .file_stats
        .as_mut()
        .expect("file_stats null at file_lib.cc:932 (file_stats_init not run; pinned-absent)");
    let ft = ft.min(fs.data_processed.len() - 1);
    // C `+= data_size` (int widened into PegCount; 2's-complement wrap)
    fs.data_processed[ft][dir] =
        (fs.data_processed[ft][dir] as i64).wrapping_add(size as i64) as u64;
}

/// file_lib.cc:1004 find_file_type_from_ips(Packet* pkt, const
/// uint8_t* file_data, int data_size, FilePosition position).
/// The IpsContext writes land on PacketView (deviation at the
/// PacketView field note); the swap/restore pair drives the REAL
/// FileFlows slot machinery (the 17q swap_ladder witness, live now —
/// vectors L2/L3/L4/L5).
#[allow(clippy::too_many_arguments)]
pub fn find_file_type_from_ips(
    this: &Rc<RefCell<FileContext>>,
    p: &mut PacketView,
    file_data: &[u8],
    data_size: i32,
    position: u32,
    flows: &mut FlowsRef<'_>,
    env: &mut FileEnvLite,
    counts: &mut FileCounts,
) {
    // bool depth_exhausted = false;
    let mut depth_exhausted = false;
    let mut data_size = data_size;
    let processed = this.borrow().processed_bytes;
    // if ((int64_t)processed_bytes + data_size >= config->file_type_depth)
    // (C member config deref; the port reads the same FileConfig
    // through the env-resolved FileConfigLite — two-view deviation at
    // FileContext::config)
    let conf = env
        .get_file_config()
        .expect("get_file_config() null at file_lib.cc:1012 (C conf/config derefs at :1012/:1024/:1045; pinned-absent)");
    if (processed as i64) + (data_size as i64) >= conf.borrow().file_type_depth {
        // data_size = config->file_type_depth - processed_bytes;
        data_size = (conf.borrow().file_type_depth - processed as i64) as i32;
        // if (data_size < 0) return;
        if data_size < 0 {
            return;
        }
        depth_exhausted = true;
    }
    // const FileConfig* const conf = get_file_config();
    // (hoisted above: the same object, single resolution — the C pair
    // `config`/`conf` is one pointer)

    // Packet *p = DetectionEngine::set_next_packet(pkt);
    // (C drives the RETURNED packet from here on; single-view port —
    // the seam arms the current-packet latch, `p` continues. Deviation
    // record: the witness returns the same logical PDU packet in every
    // pinned run.)
    env.curpkt.set_next_packet(p);

    // DetectionEngine de;  (ctor: no witness — dead)
    // p->flow = pkt->flow;  (same view here — no-op)

    // p->context->file_data = { file_data, (unsigned int)data_size };
    p.file_data = Some(file_data[..(data_size.max(0) as usize)].to_vec());
    // p->context->file_pos = processed_bytes;
    p.file_pos = processed;
    // p->context->file_type_process = true;
    p.file_type_process = true;
    // p->context->set_snort_protocol_id(conf->snort_protocol_id);
    p.snort_protocol_id = conf.borrow().snort_protocol_id;
    // p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
    p.packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
    // p->proto_bits |= PROTO_BIT__PDU;
    p.proto_bits |= PROTO_BIT__PDU;

    // The regular set_current_file_context() cannot be used here: it
    // engages deferred-delete (would free a context still owned via
    // partially_processed_contexts) and clears current_file_id (would
    // break the matched restore).
    // FileFlows* files = FileFlows::get_file_flows(pkt->flow, false);
    // (to_create=false returns the flow's fd as-is — the FlowsRef
    // deviation note at the enum: it IS the threaded handle; the null
    // arm == flows None in the Handle form, never the Direct form)
    let mut saved = CurrentContextSlot::default();
    let mut did_swap = false;
    // const FileContext* context = files->get_current_file_context();
    let context = flows.get_current_file_context(env, counts);
    // if (!context or context != this)
    let differs = match &context {
        Some(c) => !Rc::ptr_eq(c, this),
        None => true,
    };
    if differs {
        // saved = files->swap_current_file_context_no_delete(this);
        saved = flows.swap_current_file_context_no_delete(this);
        did_swap = true;
    }

    // fp_eval_service_group(p, conf->snort_protocol_id);
    let spid = conf.borrow().snort_protocol_id;
    env.fpe.fp_eval_service_group(p, spid, this);

    /* Check whether file transfer is done or type depth is reached */
    // if ((position == SNORT_FILE_END) || (position == SNORT_FILE_FULL)
    //     || depth_exhausted) finalize_file_type();
    if position == SNORT_FILE_END || position == SNORT_FILE_FULL || depth_exhausted {
        this.borrow_mut().finalize_file_type();
    }

    // if (did_swap)
    if did_swap {
        // Re-entrant fp_eval_service_group may have replaced
        // current_context; don't overwrite whatever it installed with a
        // possibly-stale saved.ctx.
        // if (files->get_current_file_context() == this)
        let cur = flows.get_current_file_context(env, counts);
        let same = cur.is_some() && Rc::ptr_eq(cur.as_ref().unwrap(), this);
        if same {
            // files->restore_current_file_context_no_delete(saved);
            flows.restore_current_file_context_no_delete(&saved);
        }
    }
}

/// file_lib.cc:986 process(Packet* p, const uint8_t* file_data,
/// int data_size, uint64_t offset, FilePolicyBase* policy,
/// FilePosition position) — the offset form: lazy `new
/// FileSegments(this)`, then the segment queue ladder.
/// Deviation (row 17r): the C `FileSegments*` back-holds `context`
/// and calls into it (process_one -> context->process position form);
/// the port keeps the segment Box in the context as
/// Rc<RefCell<FileSegments>>, clones the handle OUT of the context
/// borrow, then drives the segment with its own borrow while
/// process_pos re-borrows the context — same call graph, no
/// self-referential borrow and no C reentrancy-through-a-live-pointer
/// hazard. The C `delete file_segments` reaching mid-iterate (reset
/// via an apply_verdict arm — C UB) leaves the port's Rc segment
/// alive to the end of the ladder instead of dangling.
#[allow(clippy::too_many_arguments)]
pub fn process(
    this: &Rc<RefCell<FileContext>>,
    p: &mut PacketView,
    file_data: &[u8],
    data_size: i32,
    offset: u64,
    policy: Option<FilePolicyHandle>,
    position: u32,
    flows: &mut FlowsRef<'_>,
    env: &mut FileEnvLite,
    counts: &mut FileCounts,
) -> bool {
    // if (!file_segments) file_segments = new FileSegments(this);
    if this.borrow().file_segments.is_none() {
        this.borrow_mut().file_segments = Some(Rc::new(RefCell::new(FileSegments::new())));
    }
    // return file_segments->process(p, file_data, data_size, offset,
    //     policy, position);
    let seg = this
        .borrow()
        .file_segments
        .clone()
        .expect("just installed above (impossible)");
    seg.borrow_mut().process(
        p,
        file_data,
        data_size as u64, // C int -> uint64_t arg conversion, literal
        offset,
        policy,
        position,
        this,
        flows,
        env,
        counts,
    )
}

/// file_lib.cc:825 process(Packet* p, const uint8_t* file_data,
/// int data_size, FilePosition position, FilePolicyBase* policy) —
/// the position form, THE main processing ladder ("Main File type
/// processing function").
///
/// Return: true = continue processing/log/block this file;
///         false = ignore this file.
#[allow(clippy::too_many_arguments)]
pub fn process_pos(
    this: &Rc<RefCell<FileContext>>,
    p: &mut PacketView,
    file_data: &[u8],
    data_size: i32,
    position: u32,
    policy: Option<FilePolicyHandle>,
    flows: &mut FlowsRef<'_>,
    env: &mut FileEnvLite,
    counts: &mut FileCounts,
) -> bool {
    // Profile profile(file_perf_stats); — dead in the pinned runs
    // (TimeProfilerStats::enabled=false witness; no Profile line
    // exists in ANY vector, so Rust keeps no file_perf_stats stat).
    // Flow* flow = p->flow;
    let flow = p.flow;

    // if ( data_size < 0 ) return true;
    if data_size < 0 {
        return true;
    }

    // if ( config->trace_stream ) FileContext::print_file_data(stdout,
    //     file_data, data_size, config->show_data_depth);
    // (C derefs config unguarded — port null-gates, 17q print-tail
    // precedent; the raw-stdout writes go through TraceSink::raw_line
    // exactly once per fprintf site reached.)
    let cfg_stream = this
        .borrow()
        .config
        .as_ref()
        .map(|c| (c.borrow().trace_stream, c.borrow().show_data_depth));
    if let Some((true, show_depth)) = cfg_stream {
        let dump = FileContext::print_file_data(file_data, data_size, show_depth);
        for line in dump.split_inclusive('\n') {
            env.trace.raw_line(line);
        }
    }

    // file_counts.file_data_total += data_size;
    counts.file_data_total =
        (counts.file_data_total as i64).wrapping_add(data_size as i64) as u64;

    // if ((!is_file_type_enabled()) and (!is_file_signature_enabled()))
    if !this.borrow().info.is_file_type_enabled() && !this.borrow().info.is_file_signature_enabled()
    {
        this.borrow_mut().update_file_size(data_size, position, env);
        this.borrow_mut().info.processing_complete = true;
        // FILE_DEBUG(..., TRACE_DEBUG_LEVEL, p, "File: Type and Sig
        // not enabled\n")  (p arg: no GET_CURRENT_PACKET)
        env.trace
            .file_trace(TRACE_DEBUG_LEVEL, "File: Type and Sig not enabled\n");
        if env.packet_tracer.is_active() {
            env.packet_tracer.log("File: Type and Sig not enabled\n");
        }
        return false;
    }

    // if (cacheable and (FileService::get_file_cache()->cached_verdict_lookup(
    //         p, this, policy, file_data, data_size) != FILE_VERDICT_UNKNOWN))
    // { ... } else if (cacheable) file_counts.file_cache_misses++;
    // (PARITY FIX 17r: C's first condition is the COMPOUND
    // `cacheable && (lookup != UNKNOWN)` — when cacheable and the lookup
    // answers UNKNOWN, C falls through to `else if (cacheable)` and DOES
    // increment file_cache_misses (file_lib.cc:859-863; the K5-K9/O-block
    // cacheable ladders with an un-cached file_id take that arm). The
    // pre-fix Rust `if cacheable { ... if v != UNKNOWN {...} } else if
    // cacheable {...}` put the misses++ arm on the wrong `if`: with
    // cacheable true the else is unreachable, so file_cache_misses never
    // incremented anywhere. The C short-circuit keeps the lookup behind
    // cacheable; the hit arm rides `hit`, not an early return.)
    let hit = if this.borrow().cacheable {
        // C derefs the cache pointer (null cache is UB — pinned-absent:
        // every armed ladder keeps fcache_set_file_cache).
        let cache = env.svc.get_file_cache().expect(
            "FileService::get_file_cache() null at file_lib.cc:853 (C deref, pinned-absent)",
        );
        let mut h = policy.clone().expect(
            "null policy at file_lib.cc:853 cached_verdict_lookup (C deref, pinned-absent)",
        );
        let v = h.with_policy_mut(|pol| {
            cache
                .borrow_mut()
                .cached_verdict_lookup(p, this, pol, file_data, data_size as u32, counts)
        });
        v != FILE_VERDICT_UNKNOWN
    } else {
        false
    };
    if hit {
        // file_counts.file_cache_hits++;
        counts.file_cache_hits += 1;
        // FILE_DEBUG(..., TRACE_INFO_LEVEL, p, "file process
        // completed in file context process\n")
        env.trace.file_trace(
            TRACE_INFO_LEVEL,
            "file process completed in file context process\n",
        );
        this.borrow_mut().info.processing_complete = true;
        return true;
    }
    // else if (cacheable) file_counts.file_cache_misses++;
    else if this.borrow().cacheable {
        counts.file_cache_misses += 1;
    }

    /*file type id*/
    // if (is_file_type_enabled())
    if this.borrow().info.is_file_type_enabled() {
        // process_file_type(p, file_data, data_size, position);
        FileContext::process_file_type(this, p, file_data, data_size, position, flows, env, counts);

        /*Don't care unknown file type*/
        // if (get_file_type() == SNORT_FILE_TYPE_UNKNOWN)
        if this.borrow().info.get_file_type() == SNORT_FILE_TYPE_UNKNOWN {
            this.borrow_mut().info.config_file_type(false);
            this.borrow_mut().info.config_file_signature(false);
            this.borrow_mut().update_file_size(data_size, position, env);
            this.borrow_mut().info.processing_complete = true;
            this.borrow_mut().stop_file_capture();
            // FILE_DEBUG(..., TRACE_INFO_LEVEL, p, "File: Type unknown\n")
            env.trace.file_trace(TRACE_INFO_LEVEL, "File: Type unknown\n");
            if env.packet_tracer.is_active() {
                env.packet_tracer.log("File: Type unknown\n");
            }
            return false;
        }

        // if (get_file_type() != SNORT_FILE_TYPE_CONTINUE)
        if this.borrow().info.get_file_type() != SNORT_FILE_TYPE_CONTINUE {
            // FILE_DEBUG(..., TRACE_INFO_LEVEL, p, "File: Type-%s
            // found\n", file_type_name(get_file_type()).c_str()) — the
            // file_type_name FREE global (file_config.cc:80), NOT the
            // member (the 17q print tail used the member via config):
            // conf ? conf->file_type_name(id) : "NA". The harness
            // FreeIdentifier table resolves the pinned ids to "" — the
            // K-block "Type- found" pins keep the empty name.
            let ft = this.borrow().info.get_file_type();
            let tname = match env.get_file_config() {
                Some(c) => c.borrow().file_type_name(ft),
                None => "NA".to_string(),
            };
            env.trace
                .file_trace(TRACE_INFO_LEVEL, &format!("File: Type-{tname} found\n"));
            if env.packet_tracer.is_active() {
                env.packet_tracer.log(&format!("File: Type-{tname} found\n"));
            }
            this.borrow_mut().info.config_file_type(false);

            // if (!(is_file_signature_enabled())) { DEBUG pair }
            if !this.borrow().info.is_file_signature_enabled() {
                env.trace
                    .file_trace(TRACE_INFO_LEVEL, "File: signature config is disabled\n");
                if env.packet_tracer.is_active() {
                    env.packet_tracer.log("File: signature config is disabled\n");
                }
            }

            // file_stats->files_processed[get_file_type()][get_file_direction()]++;
            {
                let cb = this.borrow();
                let ft = cb.info.get_file_type() as usize;
                let fd = cb.info.get_file_direction() as usize;
                drop(cb);
                file_stats_bump_files(env, ft, fd);
            }
            // //Check file type based on file policy
            // FileVerdict v = policy->type_lookup(p, this);
            let v = match policy.as_ref() {
                Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                    let mut cb = this.borrow_mut();
                    pol.type_lookup(p, &mut cb)
                })},
                None => panic!("C deref of null `FilePolicyBase*` at file_lib.cc:903 type_lookup — pinned-absent"),
            };
            // if ( v != FILE_VERDICT_UNKNOWN )
            if v != FILE_VERDICT_UNKNOWN {
                // if (v == FILE_VERDICT_STOP) config_file_signature(false);
                if v == FILE_VERDICT_STOP {
                    this.borrow_mut().info.config_file_signature(false);
                }
                // FileCache* file_cache = FileService::get_file_cache();
                // if (file_cache) file_cache->apply_verdict(p, this, v,
                //     false, policy);
                match (env.svc.get_file_cache(), policy.clone()) {
                    // C calls apply_verdict as a STATEMENT here (the bool return
                    //  value is dropped at the C call site — `let _` keeps that
                    //  non-observable shape explicit).
                    (Some(cache), Some(mut h)) => {
                        let _ = h.with_policy_mut(|pol| {
                            cache.borrow_mut().apply_verdict(p, this, v, false, pol, counts)
                        });
                    }
                    (Some(_), None) => panic!("C deref of null `FilePolicyBase*` at file_lib.cc:912 apply_verdict — pinned-absent"),
                    (None, _) => {} // C `if (file_cache)` guard
                }

                // if (PacketTracer::is_active() and (v == BLOCK or
                //     v == REJECT)) FILE_DEBUG + PT log pair
                if env.packet_tracer.is_active()
                    && (v == FILE_VERDICT_BLOCK || v == FILE_VERDICT_REJECT)
                {
                    let kind = if v == FILE_VERDICT_BLOCK { "block" } else { "reject" };
                    env.trace
                        .file_trace(TRACE_INFO_LEVEL, &format!("File: file type verdict {kind}\n"));
                    env.packet_tracer.log(&format!("File: file type verdict {kind}\n"));
                }
            }

            // log_file_event(flow, policy);
            // (handle-alias open at the C policy-> site; the C
            //  null pointer reaches log_file_event's null-check
            //  arms — file_lib.cc:615 `if (!policy) return;` —
            //  modeled by the None arm)
            match policy.as_ref() {
                Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                    this.borrow_mut().log_file_event(&flow, Some(pol), env)
                })},
                None => this.borrow_mut().log_file_event(&flow, None, env),
            }
        }
    }

    /* file signature calculation */
    // if (is_file_signature_enabled())
    if this.borrow().info.is_file_signature_enabled() {
        // FILE_DEBUG(..., TRACE_DEBUG_LEVEL, p, "file signature is enabled\n")
        env.trace
            .file_trace(TRACE_DEBUG_LEVEL, "file signature is enabled\n");

        // if (!sha256) process_file_signature_sha256(file_data,
        //     data_size, position);
        if this.borrow().info.get_file_sig_sha256().is_none() {
            this.borrow_mut()
                .process_file_signature_sha256(file_data, data_size, position, env, counts);
        }

        // file_stats->data_processed[get_file_type()][get_file_direction()]
        //     += data_size;
        {
            let cb = this.borrow();
            let ft = cb.info.get_file_type() as usize;
            let fd = cb.info.get_file_direction() as usize;
            drop(cb);
            file_stats_add_data(env, ft, fd, data_size);
        }

        // update_file_size(data_size, position);
        this.borrow_mut().update_file_size(data_size, position, env);

        // if ( config->trace_signature ) print_file_sha256(std::cout);
        // (std::cout, NOT file_trace: the raw_line seam — the M/K8 pins
        // carry the "SHA256: ..." line unprefixed. C derefs config;
        // null-gated, 17q print-tail precedent.)
        let trace_sig = this
            .borrow()
            .config
            .as_ref()
            .is_some_and(|c| c.borrow().trace_signature);
        if trace_sig {
            let s = this.borrow().print_file_sha256_str();
            env.trace.raw_line(&s);
        }

        /*Fails to capture, when out of memory or size limit, need lookup*/
        // if (is_file_capture_enabled()) process_file_capture(file_data,
        //     data_size, position);
        if this.borrow().info.is_file_capture_enabled() {
            process_file_capture(this, file_data, data_size, position, env);
        }

        // finish_signature_lookup(p, ( file_state.sig_state !=
        //     FILE_SIG_FLUSH ), policy);
        let final_lookup = this.borrow().info.file_state.sig_state != FILE_SIG_FLUSH;
        FileContext::finish_signature_lookup(this, p, final_lookup, policy.clone(), env, counts);

        // if (file_state.sig_state == FILE_SIG_DEPTH_FAIL)
        if this.borrow().info.file_state.sig_state == FILE_SIG_DEPTH_FAIL {
            // verdict = policy->signature_lookup(p, this);
            let v = match policy.as_ref() {
                Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                    let mut cb = this.borrow_mut();
                    let v = pol.signature_lookup(p, &mut cb);
                    cb.info.verdict = v;
                    v
                })},
                None => panic!("C deref of null `FilePolicyBase*` at file_lib.cc:955 signature_lookup — pinned-absent"),
            };
            // if ( verdict != FILE_VERDICT_UNKNOWN )
            if v != FILE_VERDICT_UNKNOWN {
                // FileCache* file_cache = FileService::get_file_cache();
                // if (file_cache) file_cache->apply_verdict(p, this,
                //     verdict, false, policy);
                match (env.svc.get_file_cache(), policy.clone()) {
                    // C calls apply_verdict as a STATEMENT here (the bool return
                    //  value is dropped at the C call site — `let _` keeps that
                    //  non-observable shape explicit).
                    (Some(cache), Some(mut h)) => {
                        let _ = h.with_policy_mut(|pol| {
                            cache.borrow_mut().apply_verdict(p, this, v, false, pol, counts)
                        });
                    }
                    (Some(_), None) => panic!("C deref of null `FilePolicyBase*` at file_lib.cc:960 apply_verdict — pinned-absent"),
                    (None, _) => {} // C `if (file_cache)` guard
                }
                // log_file_event(flow, policy);
                // (handle-alias open at the C policy-> site; the C
                //  null pointer reaches log_file_event's null-check
                //  arms — file_lib.cc:615 `if (!policy) return;` —
                //  modeled by the None arm)
                match policy.as_ref() {
                    Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                        this.borrow_mut().log_file_event(&flow, Some(pol), env)
                    })},
                    None => this.borrow_mut().log_file_event(&flow, None, env),
                }
            } else {
                // FILE_DEBUG(..., TRACE_INFO_LEVEL, p, "File: Sig depth
                // exceeded\n") + PT log pair
                env.trace
                    .file_trace(TRACE_INFO_LEVEL, "File: Sig depth exceeded\n");
                if env.packet_tracer.is_active() {
                    env.packet_tracer.log("File: Sig depth exceeded\n");
                }

                // force_adv_log = true; log_file_event(flow, policy);
                // force_adv_log = false; return false;
                this.borrow_mut().force_adv_log = true;
                // (handle-alias open at the C policy-> site; the C
                //  null pointer reaches log_file_event's null-check
                //  arms — file_lib.cc:615 `if (!policy) return;` —
                //  modeled by the None arm)
                match policy.as_ref() {
                    Some(h0) => { let mut h = h0.clone(); h.with_policy_mut(|pol| {
                        this.borrow_mut().log_file_event(&flow, Some(pol), env)
                    })},
                    None => this.borrow_mut().log_file_event(&flow, None, env),
                }
                this.borrow_mut().force_adv_log = false;
                return false;
            }
        }
    }
    // else update_file_size(data_size, position);
    else {
        this.borrow_mut().update_file_size(data_size, position, env);
    }

    // return true;
    true
}

/// file_lib.cc:1169 process_file_capture(const uint8_t*, int
/// data_size, FilePosition) -> FileCaptureState. Port-side seam
/// substitution (PLAN section 3): `new FileCapture(config->
/// capture_min_size, config->capture_max_size)` rides
/// FileEnvLite::capture_factory; the capture ENGINE body
/// (file_capture.cc: circular buffer + mempool + the file_counts
/// within-packet/buffered/memcap/buffers-allocated bumps its
/// process_buffer drives) stays its own row — the seam answer carries
/// N-block pins inside the witness impl, not through the port.
pub fn process_file_capture(
    this: &Rc<RefCell<FileContext>>,
    file_data: &[u8],
    data_size: i32,
    position: u32,
    env: &mut FileEnvLite,
) -> u32 {
    // std::lock_guard<std::recursive_mutex> lock(user_file_data_mutex);
    // (17p single-thread deviation: Rust exclusivity models the lock)

    // if (!file_capture) file_capture = new FileCapture(min, max);
    if this.borrow().info.file_capture.is_none() {
        let conf = env.get_file_config().expect(
            "get_file_config() null at file_lib.cc:1174 (C config deref; a capture-enabled ladder has the inspector armed — pinned-absent)",
        );
        let (min, max) = {
            let cb = conf.borrow();
            (cb.capture_min_size, cb.capture_max_size)
        };
        let cap = env
            .capture_factory
            .new_capture(min, max)
            .expect("new FileCapture -> null (C new never returns null; pinned-absent)");
        this.borrow_mut().info.file_capture = Some(cap);
    }

    // file_state.capture_state = file_capture->process_buffer(
    //     file_data, data_size, position);
    let state = {
        let mut cb = this.borrow_mut();
        let cap = cb
            .info
            .file_capture
            .as_mut()
            .expect("file_capture slot vanished mid-call (impossible; pinned-absent)");
        cap.process_buffer(file_data, data_size, position)
    };
    this.borrow_mut().info.file_state.capture_state = state;

    // if (file_state.capture_state != FILE_CAPTURE_SUCCESS)
    //     stop_file_capture_unlocked();
    if state != FILE_CAPTURE_SUCCESS {
        // (ud-lock already held in C — the unlocked arm; Rust same body)
        let mut cb = this.borrow_mut();
        if cb.info.file_capture.is_some() {
            cb.info.file_capture = None; // FileCapture* capture = ...; delete capture
        }
        cb.info.config_file_capture(false);
    }

    // return file_state.capture_state;
    state
}
