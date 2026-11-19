//! Literal port of `file_api/file_policy.{h,cc}` (row 17x) — the
//! FilePolicy TU: the FileRule table + the enable-flag getter/setter
//! pairs + the type/signature lookup ladder, riding the EXISTING 17v
//! `FilePolicyApi` / `FilePolicyHandle` seam
//! (src/file_api/file_api.rs:229/:273 — no forked handle type, per
//! NEXT.md:132-:133 / fpolicy PLAN §3.1 "the real file_policy.rs
//! implements FilePolicy on them").
//!
//! Donor oracle: `tools/fpolicy_harness` (finspect donor; the row TU
//! compiles byte-VERBATIM, 0 grafts — 0 TEST_CASE / 0 UNIT_TEST
//! measured, PLAN §2). vectors.txt line 1 is the layout pin:
//! `V1_size base=16 rule=48 policy=152 refs=1` (C sizeof via
//! probe.cc:71-:73). C sizes are probe-pinned literals here, NEVER
//! Rust `size_of` (file_cache_share.rs:69 rule): the C++ layout has
//! the std::string ABI (FileVerdictWhen 40, FileRule 48, FilePolicy
//! 152 including the FilePolicyBase 16 vptr+ref_count tail —
//! cross-checked byte-ident at fe29cbe this pass); the Rust shapes
//! differ BY DESIGN and no frozen vector reads a Rust size. The one
//! real overlap, `FileVerdictUse` = 8, is asserted for real below.
//!
//! Naming deviation (pinned row-17x, KNOWN DEVIATIONS): Rust
//! `TypeIdSet` is C `struct FileVerdictWhen` (h:33-:37 — the which-
//! file-types selector) and Rust `FileUse` is C `struct
//! FileVerdictUse` (h:39-:45); the `FileRule` name matches C (h:47).
//!
//! C file has ZERO file-scope data (nm-measured, PLAN pre-note): no
//! static g_file_policy. Ownership in production is the NetworkPolicy
//! member (main/policy.h:215 `FilePolicy* file_policy = nullptr`, new
//! at policy.cc:44, `delete_file_policy` at policy.cc:51, accessor
//! pair policy.h:196/:197 -> policy.cc:61-:64). The Rust twin of that
//! wiring is [`NetworkPolicy`] below (models policy.cc without
//! porting main/policy.cc).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::file_api::{FilePolicyApi, FilePolicyHandle};
use super::file_api::{FILE_CAPTURE_SUCCESS, FILE_SIG_DEPTH_FAIL};
use super::file_api::{
    FILE_VERDICT_LOG, FILE_VERDICT_PENDING, FILE_VERDICT_UNKNOWN,
};
use super::file_cache::{CacheFlow, PacketView};
use super::file_lib::{FileCaptureApi, FileContext, FileInfo, FileServiceLite};
use super::file_stats::FileCounts;

/// C sizes pinned from the fpolicy probe (vectors.txt:1 `V1_size
/// base=16 rule=48 policy=152 refs=1` + probe.cc:71-:73), literals,
/// never size_of (file_cache_share.rs:69 precedent). `when=40` is the
/// static_assert cross-check added this row (uint32 + pad + 32-byte
/// std::string); `use=8` matches the Rust layout and IS asserted.
pub const C_SIZEOF_FILE_POLICY_BASE: usize = 16; // vectors.txt V1_size `base=16`
pub const C_SIZEOF_FILE_RULE: usize = 48; // vectors.txt V1_size `rule=48`
pub const C_SIZEOF_FILE_POLICY: usize = 152; // vectors.txt V1_size `policy=152`

#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<FileUse>() == 8); // C use=8; real overlap, asserted

// ==================================================================
// struct FileVerdictWhen — file_policy.h:33-:37. Rust name TypeIdSet
// (row-17x deviation, module header).
// ==================================================================

/// `uint32_t type_id = 0` (h:35) + `std::string sha256` (h:36).
/// type_id 0 is the wildcard arm (match_file_rule cc:139-:140); the
/// sha256 slot holds the rule's HEX text as configured (raw bytes are
/// the `file_shas` KEY, not this field — add_file_id cc:85-:100).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeIdSet {
    pub type_id: u32, // h:35
    pub sha256: String, // h:36 (hex as configured)
}

// ==================================================================
// struct FileVerdictUse — file_policy.h:39-:45. Rust name FileUse.
//   * `FileVerdict verdict = FILE_VERDICT_UNKNOWN` (h:41; the const
///    block lives in file_api.rs:108-:115)
//   * `bool type_enabled` (h:42) / `signature_enabled` (h:43) /
//     `capture_enabled` (h:44) — per-rule flags (DEFAULT all-false,
//     h:42-:44 initializers + cc:38-:41 clear). The getters cc:64-:79
//     are MEMBER-only: they do NOT read FileService
//     (fpolicy PLAN §1 "pin per cc"; V2_getters `svc t=0 s=0 c=0`).
// ==================================================================

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileUse {
    pub verdict: u32, // h:41 FileVerdict (FILE_VERDICT_UNKNOWN default)
    pub type_enabled: bool, // h:42
    pub signature_enabled: bool, // h:43
    pub capture_enabled: bool, // h:44
}

// ==================================================================
// class FileRule — file_policy.h:47-:55; bodies cc:34-:47.
// ==================================================================

/// C `class FileRule { FileVerdictWhen when; FileVerdictUse use; ... }`
/// — the field is named `use` in C (h:51), hence the raw ident
/// `r#use` (the file_config.rs `r#type` field precedent).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileRule {
    pub when: TypeIdSet, // h:50
    pub r#use: FileUse, // h:51
}

impl FileRule {
    /// `FileRule()` cc:44-:47 — the ctor calls `FileRule::clear()`
    /// (cc:46); every member default already states those values, so
    /// new() == Default here (C has no other ctor — h:53).
    pub fn new() -> Self {
        Self::default()
    }

    /// `void FileRule::clear()` cc:34-:42 — zeroes when.type_id (:36),
    /// the sha256 STRING (clear, cc:37), the three use flags (cc:38-
    /// :40) and the verdict (:41 FILE_VERDICT_UNKNOWN).
    pub fn clear(&mut self) {
        self.when.type_id = 0; // cc:36
        self.when.sha256.clear(); // cc:37 std::string::clear
        self.r#use.capture_enabled = false; // cc:38
        self.r#use.signature_enabled = false; // cc:39
        self.r#use.type_enabled = false; // cc:40
        self.r#use.verdict = FILE_VERDICT_UNKNOWN; // cc:41
    }
}

// ==================================================================
// class FilePolicy : public snort::FilePolicyBase — h:57-:92; all 10
// cc bodies below. The base's 4-virtual protocol (file_api.h:151-
// :163) rides the 17v FilePolicyApi trait (file_api.rs:229); the
// ref-count handle (file_api.cc:28-:43) rides FilePolicyHandle
// (file_api.rs:273) — this struct NEVER clones itself into a second
// handle except THROUGH the ref protocol.
//   * `FilePolicy() = default` h:61 / `~FilePolicy() override =
//     default` h:62 — defaulted BOTH SIDES: no T lines in the row .o
//     (nm-measured, PLAN §2 pre-note + R3); Rust = the derived
//     defaults below (dtor arm = the delete_file_policy drain at the
//     handle, same posture as StubFilePolicy's heap rule, stubs.cc:
//     374-:379 / ~FilePolicyBase assert(!ref_count), file_api.cc:
//     31-:32 via fcapi PLAN:156).
//   * NOT overridden: log_file_action (h:64-:70 override list only
//     covers policy_check/type_lookup/signature_lookup; fpolicy PLAN
//     §1 — the body stays the file_api.cc base arm).
// ==================================================================

/// C members h:85-:91, all `pub` here: the C header has exactly one
/// `private:` (h:82) and the harness FIXACC step (fpolicy build.sh
/// :261 tuple entry "/file_api/file_policy.h") flips it public — the
/// probe reads `file_rules`/`file_shas`/`verdict_delay`/`default_rule`
/// (V3_add `rules=1 shas=1`, V5_match `def=0`, V6_delay `left=0`);
/// Rust states the same visibility with the cite.
pub struct FilePolicy {
    /// `std::vector<FileRule> file_rules` (h:85)
    pub file_rules: Vec<FileRule>,
    /// `std::map<std::string, FileVerdict> file_shas` (h:86) —
    /// std::map is ORDERED: BTreeMap keeps find() semantics exact
    /// (fpolicy PLAN §3.1 row). Key is the RAW 32-byte sha bytes
    /// (cc:99 / cc:152), not the hex text.
    pub file_shas: BTreeMap<Vec<u8>, u32>,
    /// `FileRule default_rule` (h:87)
    pub default_rule: FileRule,
    /// `bool type_enabled = false` (h:88)
    pub type_enabled: bool,
    /// `bool signature_enabled = false` (h:89)
    pub signature_enabled: bool,
    /// `bool capture_enabled = false` (h:90)
    pub capture_enabled: bool,
    /// `int64_t verdict_delay = 0` (h:91) + `set_verdict_delay`
    /// (h:80 INLINE, plain write — pinned by V6 `left=0` after the
    /// cc:157-:160 decrement ladder).
    pub verdict_delay: i64,
    /// Deviation (row 17x, pinned in KNOWN DEVIATIONS): the C
    /// signature_lookup capture leg reaches the thread-static
    /// `file_counts` (file_lib.cc/file_capture.cc, 17m FileCounts
    /// discipline) THROUGH FileInfo::reserve_file's counts arg
    /// (file_lib.rs:652-:655). C FilePolicy carries NO such member
    /// (h:85-:91 complete); Rust injects the driver-owned counts Rc,
    /// same convention as RealFileCaptureFactory::counts
    /// (file_capture.rs:1381).
    pub counts: Rc<RefCell<FileCounts>>,
}

impl Default for FilePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl FilePolicy {
    /// `FilePolicy() = default` (h:61) + the h:88-:91 default
    /// initializers verbatim (all flags false, delay 0, table empty).
    pub fn new() -> Self {
        FilePolicy {
            file_rules: Vec::new(), // h:85
            file_shas: BTreeMap::new(), // h:86
            default_rule: FileRule::default(), // h:87 (FileRule ctor cc:44)
            type_enabled: false, // h:88
            signature_enabled: false, // h:89
            capture_enabled: false, // h:90
            verdict_delay: 0, // h:91
            counts: Rc::new(RefCell::new(FileCounts::default())),
        }
    }

    /// adopt existing driver counts (harness fixture pattern; the C
    /// thread-static file_counts is global FOR exactly this reason)
    pub fn with_counts(mut self, counts: Rc<RefCell<FileCounts>>) -> Self {
        self.counts = counts;
        self
    }

    /// `set_verdict_delay(int64_t delay)` h:80 (inline member write).
    pub fn set_verdict_delay(&mut self, delay: i64) {
        self.verdict_delay = delay; // h:80
    }

    // ---- the enable-flag setter/getter pairs, cc:49-:79 ----

    /// `void set_file_type(bool enabled)` cc:49-:52 — plain member
    /// writer (h:88).
    pub fn set_file_type(&mut self, enabled: bool) {
        self.type_enabled = enabled; // cc:51
    }

    /// `void set_file_signature(bool enabled)` cc:54-:57 (h:89).
    pub fn set_file_signature(&mut self, enabled: bool) {
        self.signature_enabled = enabled; // cc:56
    }

    /// `void set_file_capture(bool enabled)` cc:59-:62 (h:90).
    pub fn set_file_capture(&mut self, enabled: bool) {
        self.capture_enabled = enabled; // cc:61
    }

    /// `bool get_file_type() const` cc:64-:67 — member-only (see the
    /// FileUse block: NO FileService read; V2_getters pins `svc
    /// t=0 s=0 c=0` while these return 1/1/0).
    pub fn get_file_type(&self) -> bool {
        self.type_enabled // cc:66
    }

    /// `bool get_file_signature() const` cc:70-:73 — the
    /// cppcheck-suppress unusedFunction comment rides VERBATIM at
    /// cc:69 (a no-op in Rust; retained as the doc cite).
    pub fn get_file_signature(&self) -> bool {
        self.signature_enabled // cc:72
    }

    /// `bool get_file_capture() const` cc:76-:79 — same
    /// unusedFunction-suppress posture (cc:75 comment line).
    pub fn get_file_capture(&self) -> bool {
        self.capture_enabled // cc:78
    }

    // ---- the config-time table loaders, cc:81-:130 ----

    /// `void add_file_id(FileRule& rule)` cc:81-:111 — the sha TABLE
    /// + the ENABLE side-effects on the FileService static trio:
    ///   * `file_rules.emplace_back(rule)` cc:83 (COPY into the
    ///     vector — the by-ref arg is never mutated; Rust clones at
    ///     the same point);
    ///   * cc:85-:100 hex->bytes: per 2-char window
    ///     `std::stoi(hex.substr(offset,2),nullptr,16)` (cc:94) ->
    ///     `bytes.push_back((unsigned char))` (cc:95), key stored as
    ///     the raw 32 (or any even-ish) byte string (cc:99 NOTE: ANY
    ///     non-empty sha is tabled, not just 64-hex — production
    ///     config validation guarantees digest hex upstream);
    ///   * QUIRK cc:103-:104: `FileService::enable_file_type();
    ///     type_enabled = true;` UNCONDITIONAL on EVERY rule ("Enable
    ///     file type for all other features" comment cc:102) — pinned
    ///     by V3_add `type_enabled=1 svc t=1`;
    ///   * signature/capture arming CONDITIONAL on the RULE's use
    ///     flags only (cc:106-:107 / cc:109-:110) — the capture arm
    ///     CASCADES `enable_file_signature()` inside the C real body
    ///     (file_service.cc:199-:204 "Enable file capture, also
    ///     enable file signature"; ride that cascade through
    ///     FileServiceLite::enable_file_capture, file_lib.rs row 17x).
    ///
    /// Hex-decode error posture (PLAN R7): a malformed nibble in C
    /// throws via std::stoi (the `__throw_invalid_argument`/
    /// `out_of_range` residue is LIVE in file_policy.o, nm-measured);
    /// the port PANICS identically — vectors NEVER arm junk hex (same
    /// posture as the frozen FileIdentifier arms). An odd-length tail
    /// submits a 1-char window, matching C substr's short read.
    pub fn add_file_id(&mut self, rule: &FileRule, svc: &mut FileServiceLite) {
        self.file_rules.push(rule.clone()); // cc:83

        if !rule.when.sha256.is_empty() {
            // cc:87-:100: std::string hex = rule.when.sha256; loop
            // offset += 2
            let hex = &rule.when.sha256;
            let mut bytes: Vec<u8> = Vec::new();
            let mut offset = 0usize;
            while offset < hex.len() {
                // cc:94 hex.substr(offset, 2) — short read on an odd
                // tail; the radix panic == the C stoi throw (R7).
                let chunk = &hex[offset..std::cmp::min(offset + 2, hex.len())];
                let buffer = u8::from_str_radix(chunk, 16).unwrap_or_else(|_| {
                    panic!(
                        "add_file_id cc:94 std::stoi throw on malformed sha hex \
                         (production config validation forbids this arm — pinned-absent)"
                    )
                });
                bytes.push(buffer); // cc:95 push_back((unsigned char)buffer)
                offset += 2; // cc:96
            }
            self.file_shas.insert(bytes, rule.r#use.verdict); // cc:99 map-key
        }

        // Enable file type for all other features  (cc:102 comment)
        svc.enable_file_type(); // cc:103 UNCONDITIONAL
        self.type_enabled = true; // cc:104 UNCONDITIONAL (quirk pin)

        if rule.r#use.signature_enabled {
            svc.enable_file_signature(); // cc:106-:107
        }

        if rule.r#use.capture_enabled {
            svc.enable_file_capture(); // cc:109-:110 (cascades signature
            // per file_service.cc:199-:204 — V3/V4 svc pins)
        }
    }

    /// `void load()` cc:113-:130 — the OR-arm quirk: `if (type_enabled
    /// or signature_enabled)` arms BOTH the member and the service
    /// (:115-:119, so signature-enabled alone implies type-enabled —
    /// V4_load_sig `def t=1 s=1 c=0`); then the plain signature
    /// (:121-:122) and capture arms (:124-:125, capture AGAIN rides
    /// the file_service.cc:199-:204 cascade — V4_load_cap pins
    /// `svc t=0 s=1 c=1`: the cascade lights file_signature_enabled at
    /// the SERVICE level while the policy's own `signature_enabled`
    /// MEMBER stays 0 and the type OR-arm stays dark). Finally the
    /// three flags stamp `default_rule.use` (:127-:129 — the default
    /// rule carries the policy posture, NOT the reverse).
    pub fn load(&mut self, svc: &mut FileServiceLite) {
        if self.type_enabled || self.signature_enabled {
            self.type_enabled = true; // cc:117
            svc.enable_file_type(); // cc:118
        }

        if self.signature_enabled {
            svc.enable_file_signature(); // cc:121-:122
        }

        if self.capture_enabled {
            svc.enable_file_capture(); // cc:124-:125 (cascade pin above)
        }

        self.default_rule.r#use.type_enabled = self.type_enabled; // cc:127
        self.default_rule.r#use.signature_enabled = self.signature_enabled; // cc:128
        self.default_rule.r#use.capture_enabled = self.capture_enabled; // cc:129
    }

    // ---- the match pair, cc:132-:168 (C `private:` h:82-:84; pub
    // per the FIXACC-visibility ruling at the struct block) ----

    /// `FileRule& match_file_rule(Flow*, const FileInfo*)` cc:132-:145
    /// — the C dead `Flow*` arg drops (Rust omission, documented; C
    /// never touches it — cc:132 unnamed). FIRST rule whose sha256 is
    /// EMPTY (sha-keyed rules do NOT answer the type lane — cc:136-
    /// :137 `continue`) AND (`when.type_id == 0` wildcard, cc:139, OR
    /// `== file->get_file_type()`, cc:140) wins; else `default_rule`
    /// (cc:144 — V5_match `wildcard=4 first_rule=1 def=0` pins the
    /// whole arm set). Rust returns a borrow (C `FileRule&` — V5_def
    /// `is_default=1` pins the fallback identity via the C address
    /// compare; Rust answers through `same_default` below).
    pub fn match_file_rule(&self, file: &FileInfo) -> &FileRule {
        for rule in self.file_rules.iter() {
            if !rule.when.sha256.is_empty() {
                continue; // cc:136-:137
            }
            // No file type specified in rule or file type is matched
            // (cc:138 comment verbatim intent)
            if rule.when.type_id == 0 || rule.when.type_id == file.get_file_type() {
                return rule; // cc:139-:141
            }
        }
        &self.default_rule // cc:144
    }

    /// V5_def's C compare `&rule == &p.file_policy.default_rule`: the
    /// pointer-identity arm rides Rust index identity instead (borrow
    /// addresses are not a thing here) — `same_default` answers it.
    pub fn same_default(&self, rule: &FileRule) -> bool {
        std::ptr::eq(rule, &self.default_rule)
    }

    /// `FileVerdict match_file_signature(Flow*, const FileInfo*)`
    /// cc:147-:168 — sha TABLE lane only:
    ///   * `file->get_file_sig_sha256()` guard (:150-:151 — null ==
    ///     Rust Option::None, the port's shape for C's ptr check);
    ///   * key = the FIRST SHA256_HASH_SIZE BYTES of the digest
    ///     (`std::string sha((const char*)ptr, SHA256_HASH_SIZE)`
    ///     :152 — the digest slot is exactly 32 (file_lib.rs:561
    ///     `Option<&[u8; SHA256_HASH_SIZE]>`), so the slice is exact,
    ///     no truncation ever observable);
    ///   * HIT + `verdict_delay > 0` -> `verdict_delay--; return
    ///     FILE_VERDICT_PENDING` (:157-:160 — the counter decrements
    ///     PER CALL; the probe pins the PENDINGx2 -> verdict ladder,
    ///     vectors lines 8-11 `-> 5 / -> 5 / -> 1` with `V6_delay
    ///     left=0`);
    ///   * HIT with counter drained -> the table verdict (:163);
    ///   * MISS -> FILE_VERDICT_UNKNOWN (:167).
    pub fn match_file_signature(&mut self, file: &FileInfo) -> u32 {
        if let Some(digest) = file.get_file_sig_sha256() {
            // cc:152 std::string(ptr, SHA256_HASH_SIZE) -> the raw
            // byte key (same key construction as cc:99).
            let sha = digest.to_vec();

            if let Some(hit) = self.file_shas.get(&sha) {
                let verdict = *hit; // cc:154-:155 find != end
                if self.verdict_delay > 0 {
                    self.verdict_delay -= 1; // cc:159 verdict_delay--
                    return FILE_VERDICT_PENDING; // cc:160
                }
                return verdict; // cc:163 (search->second)
            }
        }

        FILE_VERDICT_UNKNOWN // cc:167
    }

    // ---- the FilePolicyApi overrides (the 17v seam) ----

    /// `void policy_check(Flow*, FileInfo*)` cc:170-:177 — the C body
    /// carries only a TODO ("enable based on file policy rules on
    /// flow", cc:172): the trio write is the WHOLE config surface —
    /// `config_file_type(type_enabled)` / `config_file_signature
    /// (signature_enabled)` / `config_file_capture(capture_enabled)`
    /// (:173-:175, the POLICY members onto the FileInfo — NOT the
    /// matched rule; V7_pcheck `f t=1 s=0 c=1 pid=0`) — plus the
    /// single-policy quirk `set_policy_id(0)` (:176, always 0).
    pub fn policy_check_body(&mut self, file: &mut FileContext) {
        // TODO: enable based on file policy rules on flow  (cc:172)
        file.info.config_file_type(self.type_enabled); // cc:173
        file.info.config_file_signature(self.signature_enabled); // cc:174
        file.info.config_file_capture(self.capture_enabled); // cc:175
        file.info.set_policy_id(0); // cc:176 single-policy quirk
    }

    /// `FileVerdict type_lookup(Packet*, FileInfo*)` cc:179-:185 —
    /// after the file TYPE is known (h:66 comment): copy-match the
    /// rule (cc:181 `FileRule rule = match_file_rule(...)` — the C
    /// local copy is non-observable; the port borrows and reads the
    /// three fields directly, same arm order), RE-ARMS the FileInfo
    /// signature/capture switches from the matched rule (:182-:183 —
    /// the V8_rearm `f s=1 c=1` pin), returns `rule.use.verdict`
    /// (:184 — V7/V8 `type_lookup -> 2` / `-> 3`).
    pub fn type_lookup_body(&self, file: &mut FileContext) -> u32 {
        let rule = self.match_file_rule(&file.info); // cc:181
        file.info.config_file_signature(rule.r#use.signature_enabled); // cc:182
        file.info.config_file_capture(rule.r#use.capture_enabled); // cc:183
        rule.r#use.verdict // cc:184
    }

    /// `FileVerdict signature_lookup(Packet*, FileInfo*)` cc:187-:216
    /// — after the signature is COMPLETE (h:69 comment):
    ///   * `const FileRule& rule = match_file_rule(...)` (:189 — C
    ///     const-REF here, no copy, unlike type_lookup :181);
    ///   * capture leg ONLY if `rule.use.capture_enabled` (:191) —
    ///     the 3-arm capture ladder:
    ///     - `file->reserve_file(captured) == FILE_CAPTURE_SUCCESS`
    ///       (:195) -> `extracted_name = captured->store_file_async()`
    ///       (:197, rides the REAL FileCapture body, file_capture.cc:
    ///       564-:584, through the FileCaptureApi default-method seam
    ///       added this row; witness captures keep the empty-default
    ///       = the cc:199 name-empty arm) -> `set_extracted_name`
    ///       (:198) -> the EMPTY-name arm stores size 0 + deletes the
    ///       capture (:199-:203, Rust Box drop = C `delete captured`;
    ///       V9b `size=0 cutoff=0 handed_off=0`); else
    ///       `set_extracted_cutoff(false)` hands off the async store
    ///       (:204-:205);
    ///     - the RESERVE-FAIL arm deletes the (possibly set) captures
    ///       pointer (:207-:208 — Rust None drop is the exact
    ///       no-op-identical twin, FileInfo::reserve_file zeroes dest
    ///       on the fail arm, file_lib.rs:657-:659);
    ///   * then `state.sig_state == FILE_SIG_DEPTH_FAIL ->
    ///     FILE_VERDICT_LOG` unconditionally over the table (:210-
    ///     :212 — the vectors' `signature_lookup -> 1` arms after the
    ///     two PENDINGs pin this LOG ladder BEFORE the match);
    ///   * fall-through `return match_file_signature(...)` (:215).
    pub fn signature_lookup_body(&mut self, file: &mut FileContext) -> u32 {
        let capture_enabled = self.match_file_rule(&file.info).r#use.capture_enabled; // cc:189-:190

        if capture_enabled {
            // FileCapture* captured = nullptr;  (cc:193)
            let mut captured: Option<Box<dyn FileCaptureApi>> = None;

            // if (file->reserve_file(captured) == FILE_CAPTURE_SUCCESS)
            // (cc:195; the counts arg = the driver-owned counts Rc,
            // deviation doc at the struct block)
            if file
                .info
                .reserve_file(&mut captured, &mut self.counts.borrow_mut())
                == FILE_CAPTURE_SUCCESS
            {
                let extracted_name = captured
                    .take()
                    .map(|cap| cap.store_file_async()) // cc:197
                    .unwrap_or_default(); // pin
                file.info.set_extracted_name(extracted_name.as_bytes()); // cc:198
                if extracted_name.is_empty() {
                    // :199-:203 empty-name arm: size 0 (+ the C
                    // `delete captured` = the Box drop already done by
                    // the move into store_file_async / take above)
                    file.info.set_extracted_size(0); // :201
                } else {
                    file.info.set_extracted_cutoff(false); // :205
                }
            }
            // else delete captured; (:207-:208) — FileInfo::reserve_-
            // file hands the capture back in dest on the WITH-capture
            // file arm too (file_lib.rs:666 stores *dest before the state
            // check), so dropping the Option at scope end here is the
            // exact C `delete captured` for BOTH arms (the no-
            // capture fail arm already left it None, :657-:659).

            // FileState state = file->get_file_state();  (:210)
            let state = file.info.get_file_state();
            if state.sig_state == FILE_SIG_DEPTH_FAIL {
                return FILE_VERDICT_LOG; // :211-:212
            }
        }

        self.match_file_signature(&file.info) // cc:215
    }
}

/// The real FilePolicy over the 17v FilePolicyApi seam (file_api.rs:
/// 229 — the trait the handle fronts, NEXT.md:132-:133 "implements
/// FilePolicy on them"; file_api.rs:273/:288 new_boxed is the ONLY
/// way in; identity arms ride same_store file_api.rs:320-:321). C
/// `Packet*`/`Flow*` args stay dead (cc:170/:179/:187 unnamed params).
impl FilePolicyApi for FilePolicy {
    /// file_api.h:152-:153 protocol slot -> the cc:170-:177 body.
    fn policy_check(&mut self, _flow: &CacheFlow, file: &mut FileContext) {
        self.policy_check_body(file);
    }

    /// file_api.h:155-:157 slot -> the cc:179-:185 body.
    fn type_lookup(&mut self, _p: &mut PacketView, file: &mut FileContext) -> u32 {
        self.type_lookup_body(file)
    }

    /// file_api.h:159-:161 slot -> the cc:187-:216 body.
    fn signature_lookup(&mut self, _p: &mut PacketView, file: &mut FileContext) -> u32 {
        self.signature_lookup_body(file)
    }

    /// NOT overridden by FilePolicy (h:64-:70 override list; fpolicy
    /// PLAN §1 proof-via-StubFilePolicy): the C arm is the
    /// FilePolicyBase empty body (file_api.h:163 inline `{ }`) — the
    /// Rust equivalent is this empty impl.
    fn log_file_action(&mut self, _flow: &CacheFlow, _file: &mut FileContext, _action: u32) {}
}

// ==================================================================
// `NetworkPolicy` ownership twin — main/policy.h:215 member +
// policy.cc:41-:68. Models the C `new FilePolicy` (policy.cc:44, the
// ctor-ref ref_count == 1 arm via FilePolicyHandle::new_boxed,
// file_api.cc:28-:29) and `delete_file_policy(file_policy)`
// (policy.cc:51 -> the handle drain, file_api.cc:34-:43) WITHOUT
// porting main/policy.cc (monolith, row 18+). Implements the EXIST-
// ING seam (file_lib.rs:1089-:1098 NetworkPolicySeam::
// get_base_file_policy -> Option<FilePolicyHandle>; the
// FileEnvLite::network_policy slot file_lib.rs:1165 keeps its pub
// type — swapping the finspect witness (stubs.cc:696-:697
// `POLICY base_file_policy -> stub`, KEPT VERBATIM for the frozen
// fctx/fflows replays) for THIS real arm is a driver-side
// assignment: env.network_policy = Some(Rc::new(RefCell::new(
// NetworkPolicy::new_file_policy(policy))))). Pub names UNCHANGED
// at both ends (file_flows.rs:289/:1447 the handle member +
// get_file_policy_static read the same seam output — grep-verified
// row 17x).
//   * NOT ported here: NetworkPolicy::add_file_policy_rule
//     (policy.h:198 -> policy.cc:66-:68 forwards into add_file_id) —
//     its ONLY consumers are the FilePolicyModule config ladder
//     (main/modules.cc:2298/:2350, WITNESS/out-of-scope row, fpolicy
//     PLAN §3.2); Rust harness arms go straight onto FilePolicy's
//     own add_file_id.
// ==================================================================

pub struct NetworkPolicy {
    /// `FilePolicyBase* get_base_file_policy() const` answers this
    /// (policy.h:196 -> policy.cc:61-:62 `return file_policy;`).
    file_policy: Option<FilePolicyHandle>,
}

impl NetworkPolicy {
    /// policy.cc:41-:44 `file_policy = new FilePolicy;` — C fresh
    /// ref_count == 1 (file_api.cc:28-:29), the handle's own ctor
    /// posture (file_api.rs:284-:295 doc).
    pub fn new_file_policy(policy: FilePolicy) -> Self {
        NetworkPolicy {
            file_policy: Some(FilePolicyHandle::new_boxed(Box::new(policy))),
        }
    }

    /// policy.cc:49-:51 `~NetworkPolicy` ->
    /// `FilePolicyBase::delete_file_policy(file_policy)`: the drain
    /// must walk refs to 0 before the Box drops (the ~FilePolicyBase
    /// assert(!ref_count) posture, file_api.cc:31-:32 — same heap-
    /// only rule the StubFilePolicy twins pin, stubs.cc:374-:379).
    /// Handles cloned to consumers (the FileFlows pair, file_flows.cc:
    /// 150) must release FIRST.
    pub fn release_base_file_policy(&mut self) {
        if let Some(mut h) = self.file_policy.take() {
            h.delete_file_policy(); // the NetworkPolicy's own ref
        }
    }

    /// policy.h:196 -> policy.cc:61-:62 (const accessor returning the
    /// same object — the clone is the handle-copy, the ADD_REF
    /// discipline at C consumers is the driver's, file_api.rs:254-
    /// :259 doc carried).
    pub fn get_base_file_policy(&self) -> Option<FilePolicyHandle> {
        self.file_policy.clone()
    }
}

/// The seam arm (file_lib.rs:1097-:1098) — the "witness -> real"
/// swap this row is allowed to make: the SAME trait, the SAME slot
/// type, no pub-name churn anywhere in file_lib/file_flows.
impl super::file_lib::NetworkPolicySeam for NetworkPolicy {
    /// `get_network_policy()->get_base_file_policy()` (file_flows.cc:
    /// 150, reached by get_file_flows' B_CREATE arm, file_flows.rs:
    /// 1469-:1498) — the C pair "WITNESS get_network_policy / POLICY
    /// base_file_policy -> stub" retires in THIS arm: the real
    /// FilePolicy handle answers, identity-provable downstream
    /// through same_store (file_api.rs:320-:321, the 17q
    /// static_pol==pol pin family).
    fn get_base_file_policy(&mut self) -> Option<FilePolicyHandle> {
        // C `return file_policy;` (policy.cc:62) — the handle clone
        // (consumer add_ref discipline).
        self.file_policy.clone()
    }
}
