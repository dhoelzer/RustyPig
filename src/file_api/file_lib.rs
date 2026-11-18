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
/// file_api.h:45
pub const UTF_16_LE_BOM_LEN: usize = 2;

/// file_lib.cc:76-78 (hardening caps; PATH_MAX = 4096 on Linux — B3 pins
/// NAMELEN=4096).
pub const FILE_URL_CAP: u32 = 4095;
pub const FILE_NAME_CAP: u32 = 4096;
pub const FILE_HOST_CAP: u32 = 256;

// FileVerdict (file_api.h:56): C serializes it as a 4-byte int (A_SZ_VERDICT=4).
pub const FILE_VERDICT_UNKNOWN: u32 = 0;
pub const FILE_VERDICT_LOG: u32 = 1;
pub const FILE_VERDICT_STOP: u32 = 2;
pub const FILE_VERDICT_BLOCK: u32 = 3;
pub const FILE_VERDICT_REJECT: u32 = 4;
pub const FILE_VERDICT_PENDING: u32 = 5;
pub const FILE_VERDICT_STOP_CAPTURE: u32 = 6;
pub const FILE_VERDICT_MAX: u32 = 7;

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

// FilePosition (file_api.h:66)
pub const SNORT_FILE_POSITION_UNKNOWN: u32 = 0;
pub const SNORT_FILE_START: u32 = 1;
pub const SNORT_FILE_MIDDLE: u32 = 2;
pub const SNORT_FILE_END: u32 = 3;
pub const SNORT_FILE_FULL: u32 = 4;

// FileCaptureState (file_api.h:74)
pub const FILE_CAPTURE_SUCCESS: u32 = 0;
pub const FILE_CAPTURE_MIN: u32 = 1;
pub const FILE_CAPTURE_MAX: u32 = 2;
pub const FILE_CAPTURE_MEMCAP: u32 = 3;
pub const FILE_CAPTURE_FAIL: u32 = 4;

// FileSigState (file_api.h:82)
pub const FILE_SIG_PROCESSING: u32 = 0;
pub const FILE_SIG_DEPTH_FAIL: u32 = 1;
pub const FILE_SIG_FLUSH: u32 = 2;
pub const FILE_SIG_DONE: u32 = 3;

// FileDirection (file_api.h:99)
pub const FILE_DOWNLOAD: u32 = 0;
pub const FILE_UPLOAD: u32 = 1;

// FileCharEncoding (file_api.h:104)
pub const SNORT_CHAR_ENCODING_ASCII: u32 = 0;
pub const SNORT_CHAR_ENCODING_UTF_16LE: u32 = 1;

/// file_api.h:60 `struct FileState` (A_SZ_STATE=8)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FileState {
    pub capture_state: u32,
    pub sig_state: u32,
}

/// file_api.h:207 inline
pub fn get_character_encoding(file_name: &[u8], length: usize) -> u32 {
    let mut encoding = SNORT_CHAR_ENCODING_ASCII;
    if length >= UTF_16_LE_BOM_LEN && file_name[..UTF_16_LE_BOM_LEN] == [0xFF, 0xFE] {
        encoding = SNORT_CHAR_ENCODING_UTF_16LE;
    }
    encoding
}

/// C `UserFileDataBase` (file_api.h) — opaque here; the copy()/clear_data
/// path only ever deletes it (E0 `ufd=0`).
pub trait UserFileDataBase {
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Seam for `FileCapture` (file_api/file_capture.cc — plan row 17p+).
/// The two members FileInfo::reserve_file/get_max_file_capture_size/
/// set_capture_file_data touch, at their real signatures.
pub trait FileCaptureApi {
    /// `FileCapture::reserve_file(const FileInfo*)`
    fn reserve_file(&mut self, file: &FileInfo) -> u32;
    fn get_file_capture_size(&self) -> i64;
    fn get_max_file_capture_size(&self) -> i64;
    fn set_data(&mut self, file_data: &[u8], size: u32);
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
// STILL seam/panic (heavy half, row 17r; the fflows probe cuts every
// path before a call site — file_flows.cc:473/:486/:531): process
// (both overloads), finish_signature_lookup, file_signature_lookup,
// find_file_type_from_ips, process_file_type,
// process_file_signature_sha256, process_file_capture,
// print_file_data.
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
    PacketTracerApi, PacketView, TRACE_DEBUG_LEVEL,
};
use super::file_identifier::{FileIdentifier, FileMeta};
use crate::helpers::event_gen::DetectionEventSink;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// file_config.h:40 `#define DEFAULT_MAX_FILES_PER_FLOW 128`
pub const DEFAULT_MAX_FILES_PER_FLOW: u64 = 128;
/// file_config.h:26-38 (the DEFAULT_* this half's defaults pin; the
/// block_timeout / lookup / max_cached trio already lives on
/// file_cache.rs as the FileCache constants of the same name).
pub const DEFAULT_FILE_TYPE_DEPTH: i64 = 1460;
pub const DEFAULT_FILE_SIGNATURE_DEPTH: i64 = 10_485_760; // 10 MiB
pub const DEFAULT_FILE_SHOW_DATA_DEPTH: i64 = 100;
pub const DEFAULT_FILE_CAPTURE_MEM: i64 = 100; // 100 MiB
pub const DEFAULT_FILE_CAPTURE_MAX_SIZE: i64 = 1_048_576; // 1 MiB
pub const DEFAULT_FILE_CAPTURE_MIN_SIZE: i64 = 0;
pub const DEFAULT_FILE_CAPTURE_BLOCK_SIZE: i64 = 32_768;

/// file_config.h:35 `class FileConfig` — every field at the exact C
/// declared name/type/order, plus the two methods this half reads.
/// Defaults mirror the C in-class initializers (hand-written Default:
/// derive would zero the non-zero depths — skill rule). No Clone/Debug:
/// the private FileIdentifier member is neither (fid row); the struct
/// rides Rc<RefCell<..> throughout, matching the C pointer usage).
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
    /// the private `FileIdentifier fileIdentifier` member
    pub file_identifier: FileIdentifier,
}

impl Default for FileConfigLite {
    fn default() -> Self {
        FileConfigLite {
            file_type_depth: DEFAULT_FILE_TYPE_DEPTH,
            file_signature_depth: DEFAULT_FILE_SIGNATURE_DEPTH,
            file_block_timeout: super::file_cache::DEFAULT_FILE_BLOCK_TIMEOUT,
            file_lookup_timeout: super::file_cache::DEFAULT_FILE_LOOKUP_TIMEOUT,
            block_timeout_lookup: false,
            capture_memcap: DEFAULT_FILE_CAPTURE_MEM,
            capture_max_size: DEFAULT_FILE_CAPTURE_MAX_SIZE,
            capture_min_size: DEFAULT_FILE_CAPTURE_MIN_SIZE,
            capture_block_size: DEFAULT_FILE_CAPTURE_BLOCK_SIZE,
            file_depth: 0,
            max_files_cached: super::file_cache::DEFAULT_MAX_FILES_CACHED,
            max_files_per_flow: DEFAULT_MAX_FILES_PER_FLOW,
            show_data_depth: DEFAULT_FILE_SHOW_DATA_DEPTH,
            trace_type: false,
            trace_signature: false,
            trace_stream: false,
            file_identifier: FileIdentifier::new(),
        }
    }
}

impl FileConfigLite {
    /// file_config.cc:48 `FileConfig::get_rule_from_id` ->
    /// fileIdentifier.get_rule_from_id.
    pub fn get_rule_from_id(&self, id: u32) -> Option<&FileMeta> {
        self.file_identifier.get_rule_from_id(id)
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
        ..FileConfigView::default()
    }
}

/// `FileService` statics both halves read (file_service.cc:
/// atomics -> Cell/plain fields, single-threaded port, the 17p mutex
/// deviation):
///   * `bool is_file_service_enabled()` (:206 — true iff a type
///     signature or file signature service is enabled)
///   * `static FileCache* get_file_cache()` (file_service.h:98 inline)
///   * `int64_t get_max_file_depth(FileConfig* fc = nullptr)` (:214)
///   * `uint64_t get_file_processed_size(Flow*)` (:256 — body copied
///     literally at the FileServiceLite method below).
#[derive(Clone, Default)]
pub struct FileServiceLite {
    file_type_id_enabled: bool,
    file_signature_enabled: bool,
    file_cache: Option<Rc<RefCell<super::file_cache::FileCache>>>,
}

impl FileServiceLite {
    pub fn set_file_service_enabled(&mut self, type_on: bool, sig_on: bool) {
        self.file_type_id_enabled = type_on;
        self.file_signature_enabled = sig_on;
    }
    /// file_service.cc:206
    pub fn is_file_service_enabled(&self) -> bool {
        self.file_type_id_enabled || self.file_signature_enabled
    }
    /// file_service.h:98 inline (`return file_cache;`)
    pub fn get_file_cache(&self) -> Option<Rc<RefCell<super::file_cache::FileCache>>> {
        self.file_cache.clone()
    }
    /// harness arm (`fcache_set_file_cache(c)`)
    pub fn set_file_cache(&mut self, c: Option<Rc<RefCell<super::file_cache::FileCache>>>) {
        self.file_cache = c;
    }
    // The remaining FileService statics both halves call —
    // get_max_file_depth (file_service.cc:214) and
    // snort::get_file_processed_size (:256) — are ported on
    // FileEnvLite and as the free function in file_flows.rs (their C
    // linkage is namespace-scope; the bodies are verbatim there).
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
/// :575-577), `file_adv_pub_id` (file_inspect.cc:46,
/// fcache_set_adv_pub_id(7) pinned), the get_file_config()
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
    /// main/thread.h `get_instance_id()` witness (stubs.cc:170 hardwired
    /// 0 in the DONOR; the fflows stubs make it armable —
    /// fcache_set_instance_id)
    pub get_instance_id: Cell<u32>,
    /// the fflows/fcache harness FileService WITNESS static `g_max_file_depth`
    /// (stubs.cc `static long long g_max_file_depth = 0;`, armed by
    /// fcache_set_max_file_depth) — the value `get_max_file_depth` answers
    /// through, pinned by the H/J vectors (0, 10, -5 arms).
    pub max_file_depth: Cell<i64>,
    pub svc: FileServiceLite,
    /// flow.h `char* service` for the pinned flow (set_source,
    /// file_lib.cc:608 — see the deviation note there). Empty == null.
    pub flow_service: std::cell::RefCell<Vec<u8>>,
    /// get_file_config() resolution (file_config.cc:89; null while no
    /// file inspector is armed)
    pub file_config: Option<Rc<RefCell<FileConfigLite>>>,
    pub network_policy: Option<Rc<RefCell<dyn NetworkPolicySeam>>>,
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
            get_instance_id: Cell::new(0),
            max_file_depth: Cell::new(0),
            svc: FileServiceLite::default(),
            flow_service: std::cell::RefCell::new(Vec::new()),
            file_config: None,
            network_policy: None,
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
/// Vec length.
fn get_utf8_fname(file_name: &[u8]) -> Option<Vec<u8>> {
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
    /// C `void* file_type_context` / `void* file_signature_context`:
    /// the 17q scope never grows them (finalize_file_type only nulls;
    /// ~FileContext only frees when set — the EVP chain is 17r).
    pub(crate) file_type_context: Option<()>,
    pub(crate) file_signature_context: Option<()>,
    /// C `FileSegments* file_segments` — the segment machinery is a
    /// later row; null through every pinned 17q/17p path (the dtor
    /// `delete`, the dtor and remove_segments null-guard arms are
    /// transcribed literally).
    pub(crate) file_segments: Option<()>,
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
}

impl Drop for FileContext {
    /// file_lib.cc:574 ~FileContext — every arm, in C order:
    /// `if (file_signature_context) EVP_MD_CTX_free((EVP_MD_CTX*)..);`
    /// `if (file_capture) stop_file_capture();`
    /// `delete file_segments;`
    /// `if (inspector) InspectorManager::release(inspector);`
    fn drop(&mut self) {
        if self.file_signature_context.is_some() {
            self.file_signature_context = None; // EVP_MD_CTX_free (17r)
        }
        if self.info.file_capture.is_some() {
            self.stop_file_capture(); // guard, then unlocked body
        }
        self.file_segments = None; // delete file_segments (null in 17q)
        if let (Some(imgr), Some(ins)) = (&self.imgr, &self.inspector) {
            imgr.borrow_mut().release(ins);
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
                env.publish
                    .publish_file_complete(env.adv_pub_id.get(), FILE_EVENT_ID_FILE_COMPLETE);

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
    /// PacketTracer::is_daq_activated() gate exactly as C).
    pub(crate) fn print_file_name_str(&self, env: &FileEnvLite) -> String {
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
    pub(crate) fn print_file_sha256_str(&self) -> String {
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
    /// the dead config->trace_type tail).
    pub(crate) fn print(&self, env: &FileEnvLite) -> String {
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

    // ---------------- 17r seam bodies (pinned panic) ----------------
    // The fflows probe cuts every path before it reaches anything
    // here (file_flows.cc:473/:486/:531: the J sections stop at early
    // returns or the cached-verdict arm). The same methods are
    // declared so the FileFlows transcription stays literal around
    // the seams; each panics when reached (deviation: pinned UB
    // pattern, row 17o precedent).

    /// file_lib.cc:986 `process(Packet*, const uint8_t*, int, uint64_t
    /// offset, FilePolicyBase*, FilePosition)` — heavy body (Profile +
    /// trace_stream + find_file_type_from_ips + segment queueing +
    /// process_file_capture + finish_signature_lookup + the
    /// cached-verdict chain): row 17r.
    pub fn process(
        &mut self,
        _p: &mut PacketView,
        _file_data: &[u8],
        _data_size: i32,
        _offset: u64,
        _policy: Option<&mut dyn FilePolicyApi>,
        _position: u32,
    ) -> bool {
        unimplemented!("FileContext::process offset form — heavy half, row 17r")
    }

    /// file_lib.cc:825 `process(Packet*, const uint8_t*, int,
    /// FilePosition, FilePolicyBase*)` (the SNORT_FILE_FULL form the
    /// re-eval arm and the single file_process drive): row 17r.
    pub fn process_pos(
        &mut self,
        _p: &mut PacketView,
        _file_data: &[u8],
        _data_size: i32,
        _position: u32,
        _policy: Option<&mut dyn FilePolicyApi>,
    ) -> bool {
        unimplemented!("FileContext::process position form — heavy half, row 17r")
    }
}
