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
