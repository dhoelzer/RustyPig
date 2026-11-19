//! Literal port of `file_api/file_cache_share.{h,cc}` — the MP-share
//! glue row (17t): the `FileCacheShare` DataHandler thunk + the
//! `serialize_file_event` / `deserialize_file_event` codec pair that
//! MPDataBus binds for `FileMPEvents::FILE_SHARE_SYNC`.
//!
//! Ground truth: /opt/data/snort3-src @ fe29cbe7 (file_cache_share.h
//! 40 L, file_cache_share.cc 75 L, `pub_sub/file_events.h` FileMPEvent
//! :37-:134). The TU has ZERO TEST_CASEs / zero `#ifdef UNIT_TEST`
//! fragments (fcshare PLAN §2/§4): every oracle rides
//! `tools/fcshare_harness/probe.cc` (415 L) + `vectors.txt`
//! (25 L, md5 03d43c143440bd2a101d56818fd20be4, NEVER edited). Parity
//! test = `tests/fcshare_parity_test.rs`.
//!
//! C shapes -> Rust shapes (deviations, mirrored in KNOWN DEVIATIONS.md):
//! * **Unchecked downcasts elided by typing** (risk R6):
//!   `static_cast<FileMPEvent&>(de)` (cc:32) and
//!   `static_cast<FileMPEvent*>(event)` (cc:49) are UB for any other
//!   DataEvent; the Rust signatures take `&FileMpEvent` directly, so
//!   the downcast is a compile-time fact — no runtime check is added
//!   (transcription fidelity: the C TU checks nothing).
//! * **Dead null-checks on `new` NOT transcribed** (risk R4, cc:55-:56
//!   and cc:69-:70): `new char[]`/`new FileMPEvent` never return null
//!   in C++17; they allocate `Vec`/move a value in Rust, so the
//!   `return false` arms are unreachable code in C and absent here.
//! * **Heap-ownership contract** (risk R7, `S_D_ownership` vector
//!   vectors.txt:9): cc:54 `new char[event_buffer_len]` and cc:68
//!   `new FileMPEvent` are NEVER freed in the C TU — the CALLER frees
//!   both (`delete[]` / `delete` at probe arms). In Rust the returned
//!   `Vec<u8>` / `FileMpEvent` MOVE to the caller, which drops them;
//!   the "no TU-side free" contract is preserved structurally (the
//!   port allocates nothing it retains).
//! * **No minimum-length guard preserved** (risk R5, cc:65-:66 rejects
//!   ONLY null buffer / len==0): the fixed header memcpy walk
//!   (file_events.h:85-:100) reads timeout+key unconditionally, so any
//!   `0 < len < 64` wire is an OOB READ in C. The Rust port indexes
//!   slices equivalently — the same truncated wire panics (release =
//!   panic, never silent OOB); it is NOT "improved" (file_lib.rs
//!   deserialize precedent, rows 17o/17q).
//! * **`FileService::get_file_cache()` static** (cc:37,
//!   file_service.h:98/109) is not a ported singleton: `handle` threads
//!   the cache as `Option<&mut FileCache>`, the `if (file_cache)`
//!   null-guard (cc:38, vector `H1_nocache`) maps to the `Option`.
//! * **The unnamed `Flow*` argument (cc:30) is dropped** — never
//!   referenced in the body (C's unused parameter).
//! * **Wire constants are probe-pinned literals, never `size_of`**:
//!   vectors.txt:1 `CONST sizeof_FileHashKey=56 fixed_len=64
//!   sizeof_FileMPEvent=392` (sizeof_FileMPEvent is the C++ object
//!   width incl. vtable — layout trivia, pinned here because the probe
//!   prints it; nothing in the codec reads it). C computes
//!   `fixed_len` via sizeof sums (file_events.h:43-:46); the Rust
//!   constant is the pinned sum.
//! * **`hashkey.padding[3]`** (file_cache.h:48 PADDING_GUARD): the
//!   C codec memcpys 6 wire bytes into it (file_events.h:99 / :125);
//!   the Rust `FileHashKey` (file_cache.rs:129) keeps padding as
//!   implicit zeros (`make_key` starts at `{}` — file_cache.cc:500), so
//!   the wire padding bytes are read-as-zero and re-emitted zero. The
//!   pinned `D3 key_eq=1` (wire padding all-zero) holds; a wire with
//!   non-zero padding would alias to zeros (deviation, unpinned by any
//!   vector).

use std::cell::RefCell;
use std::rc::Rc;

use super::file_cache::{FileCache, FileCacheEventSink, FileHashKey};
use super::file_lib::{FileContext, FileInfo};
use super::file_stats::FileCounts;

// ------------------------------------------------------------------
// Wire constants — vectors.txt:1 CONST line, NEVER size_of (probe
// `sizeof probe_key` / `fixed_len_of()` / `sizeof(FileMPEvent)`).
// ------------------------------------------------------------------

/// probe CONST `fixed_len=64`: the FileMPEvent ctor sum
/// `sizeof(timeout)+sizeof(sip)+sizeof(sgroup)+sizeof(dip)+
/// sizeof(dgroup)+sizeof(file_id)+sizeof(asid)+sizeof(padding)`
/// (file_events.h:43-:46) = 8+18+2+18+2+8+2+6 with SfIp=18
/// (file_cache.rs:78) and FileHashKey=56 (file_cache.h:40-:49,
/// PADDING_GUARD — no implicit padding).
pub const FILE_MP_EVENT_FIXED_LEN: usize = 64;

/// probe CONST `sizeof_FileMPEvent=392` (C++ object width incl. the
/// DataEvent vtable + by-value FileInfo). Pinned witness only — no
/// Rust site depends on it (the event is a plain value here).
pub const SIZEOF_FILE_MP_EVENT: usize = 392;

/// `FILE_ID_NAME` (file_config.h:42 `#define FILE_ID_NAME
/// "file_inspect"`) — the `DataHandler(FILE_ID_NAME)` ctor binding
/// (file_cache_share.h:32). The DataHandler base itself (data_bus.cc)
/// is an unported row; the name is kept as the handler's field so the
/// binding stays visible.
pub const FILE_ID_NAME: &str = "file_inspect";

// ------------------------------------------------------------------
// FileMPEvent (pub_sub/file_events.h:37-:134, derived directly from
// snort::DataEvent — no Rust DataEvent analog exists in ported code,
// so this is a LOCAL new struct; PLAN §8-1).
// ------------------------------------------------------------------

/// `class FileMPEvent : public snort::DataEvent` (file_events.h:37).
/// Members verbatim (file_events.h:129-:134): `int64_t timeout;
/// FileHashKey hashkey; FileInfo file_ctx; uint16_t len;` — `file_ctx`
/// is a BY-VALUE FileInfo (risk R3: the event owns a deep copy, so no
/// wire event can dangle through `FileCache::clear()` or the cache
/// dtor walk — vectors X1/X2).
// No derive(Debug): FileInfo is deliberately not Debug (Box<dyn>
// members, file_lib.rs:201-:204 posture) — the event rides it.
pub struct FileMpEvent {
    // int64_t timeout (file_events.h:129). C members are private;
    // pub here on the file_info.rs precedent (file_lib.rs:205
    // "protected (pub here so the ... seam + tests can reach
    // them)") — the C probe reached them through the FIXACC-published
    // header (probe.cc:149/:286, PLAN §7).
    pub timeout: i64,
    // FileHashKey hashkey (file_events.h:130; Rust mirror
    // file_cache.rs:129 — Copy)
    pub hashkey: FileHashKey,
    // FileInfo file_ctx, BY VALUE (file_events.h:132)
    pub file_ctx: FileInfo,
    // uint16_t len (file_events.h:134)
    pub len: u16,
}

impl Default for FileMpEvent {
    /// `FileMPEvent() : hashkey() { timeout = 0; len = 0; }`
    /// (file_events.h:55-:59); FileInfo rides its default member init
    /// (`FileInfo() = default`, file_lib.h:54).
    fn default() -> Self {
        FileMpEvent {
            timeout: 0,
            hashkey: FileHashKey::default(), // hashkey() zeroes
            file_ctx: FileInfo::default(),
            len: 0,
        }
    }
}

impl FileMpEvent {
    /// `FileMPEvent(const FileHashKey& key, int64_t tm, FileInfo&
    /// file)` (file_events.h:41-:53). `file_ctx(file)`
    /// COPY-CONSTRUCTS (file_lib.cc:326: `copy(other)` with the
    /// default `clear_data = true`, file_lib.h:97) — the deep-copy
    /// half of vectors H2 (`copy_not_alias=1`). The ctor cap math
    /// (file_events.h:49-:50) zeroes `len` when the serialized file
    /// tail no longer fits a u16 frame; the subtraction is the C
    /// size_t wrap (`max_len - fixed_len`, uint16_max minus the sum)
    /// kept as `wrapping_sub` verbatim.
    pub fn new(key: &FileHashKey, tm: i64, file: &FileInfo) -> Self {
        let mut file_ctx = FileInfo::default();
        file_ctx.copy(file, true); // file_lib.cc:326-:328 (copy(other) default clear_data=true)

        // const size_t fixed_len = sizeof(timeout) + ... (file_events.h:43-:46)
        // == the probe-pinned 64 (vectors.txt:1).
        let fixed_len = FILE_MP_EVENT_FIXED_LEN;
        // const size_t file_size = file_ctx.get_serialized_size();
        let file_size = file_ctx.get_serialized_size();
        // const size_t max_len = std::numeric_limits<uint16_t>::max();
        let max_len = u16::MAX as usize;

        // if (file_size > max_len - fixed_len) len = 0;
        // else len = static_cast<uint16_t>(fixed_len + file_size);
        let len = if file_size > max_len.wrapping_sub(fixed_len) {
            0
        } else {
            (fixed_len + file_size) as u16 // static_cast, fits by the guard
        };

        FileMpEvent {
            timeout: tm,
            hashkey: *key, // hashkey(key) — POD copy, file_events.h:41
            file_ctx,
            len,
        }
    }

    /// `int64_t get_timeout()` (file_events.h:61-:64)
    pub fn get_timeout(&self) -> i64 {
        self.timeout
    }

    /// `const FileInfo& get_file_ctx() const` (file_events.h:66-:70) —
    /// C comment verbatim: "Returned references are event-owned and
    /// must not outlive this FileMPEvent."
    pub fn get_file_ctx(&self) -> &FileInfo {
        &self.file_ctx
    }

    /// `const FileHashKey& get_hashkey() const` (file_events.h:72-:75)
    pub fn get_hashkey(&self) -> &FileHashKey {
        &self.hashkey
    }

    /// `uint16_t get_data_len()` (file_events.h:77-:80)
    pub fn get_data_len(&self) -> u16 {
        self.len
    }

    /// field-by-field little-endian copies of the six FileHashKey
    /// members INTO the wire at [8..64] — the exact memcpy order of
    /// the serialize walk (file_events.h:110-:123); byte layout is
    /// the one pinned for `FileHashKey::to_bytes` (file_cache.rs:141-
    /// :157: sip.ip8@0, sip.family@16, sgroup@18, dip@20, dgroup@38,
    /// file_id@40, asid@48, padding@50..56 implicit zeros — risk R6-
    /// padding deviation in the module header). C memcpy's each
    /// member; the fixed u16 offsets mirror that (no struct-as-slab
    /// transmute).
    fn key_serialize_into(&self, buffer: &mut [u8]) {
        let k = &self.hashkey;
        buffer[8..24].copy_from_slice(&k.sip.ip8); // sip.ip8 (16 B)
        buffer[24..26].copy_from_slice(&k.sip.family.to_le_bytes()); // sip.family (int16)
        buffer[26..28].copy_from_slice(&k.sgroup.to_le_bytes()); // sgroup
        buffer[28..44].copy_from_slice(&k.dip.ip8); // dip.ip8
        buffer[44..46].copy_from_slice(&k.dip.family.to_le_bytes()); // dip.family
        buffer[46..48].copy_from_slice(&k.dgroup.to_le_bytes()); // dgroup
        buffer[48..56].copy_from_slice(&k.file_id.to_le_bytes()); // file_id
        buffer[56..58].copy_from_slice(&k.asid.to_le_bytes()); // asid
        // memcpy(&hashkey.padding ...) (file_events.h:124-:125): 6
        // zero bytes already in the vec (padding deviation, module
        // header) — no write needed.
    }

    /// mirror of the deserialize memcpy walk (file_events.h:85-:100)
    /// for the timeout+key header: every C `memcpy(&member, buffer +
    /// offset, sizeof(member))` becomes a LE read at the pinned
    /// offset. SHORT WIRE: the C walk is unguarded (risk R5) — the
    /// Rust slices panic on any wire shorter than the header, the
    /// same UB-equivalence posture file_lib.rs pins for the FileInfo
    /// header walk (NOT a validation guard; transcription fidelity).
    fn key_deserialize_from(&mut self, buffer: &[u8]) {
        self.timeout = i64::from_le_bytes(buffer[0..8].try_into().unwrap()); // memcpy(&timeout, buffer, 8)
        let k = &mut self.hashkey;
        k.sip.ip8.copy_from_slice(&buffer[8..24]);
        k.sip.family = i16::from_le_bytes(buffer[24..26].try_into().unwrap());
        k.sgroup = i16::from_le_bytes(buffer[26..28].try_into().unwrap());
        k.dip.ip8.copy_from_slice(&buffer[28..44]);
        k.dip.family = i16::from_le_bytes(buffer[44..46].try_into().unwrap());
        k.dgroup = i16::from_le_bytes(buffer[46..48].try_into().unwrap());
        k.file_id = u64::from_le_bytes(buffer[48..56].try_into().unwrap());
        k.asid = u16::from_le_bytes(buffer[56..58].try_into().unwrap());
        // padding: 6 wire bytes memcpy'd in C (file_events.h:99);
        // kept zero in the Rust mirror (module-header deviation).
    }

    /// `void serialize(char* buffer, uint16_t data_len)`
    /// (file_events.h:106-:127) — fixed header walk then the
    /// `file_ctx.serialize` tail guarded by `offset < data_len`. The
    /// u16 offset arithmetic is kept as C `uint16_t offset` with
    /// wrapping adds; the tail REUSES the ported `FileInfo::serialize`
    /// (file_lib.rs:332, file_lib.cc:197 body).
    pub fn serialize(&mut self, buffer: &mut [u8], data_len: u16) {
        let mut offset: u16 = 0;
        // memcpy(buffer, &timeout, sizeof(timeout)); offset += 8;
        buffer[usize::from(offset)..usize::from(offset) + 8]
            .copy_from_slice(&self.timeout.to_le_bytes());
        offset = offset.wrapping_add(8);
        // sip/sgroup/dip/dgroup/file_id/asid/padding memcpys,
        // file_events.h:110-:125 — walk order == the key helper's
        // writes.
        self.key_serialize_into(buffer);
        // offset += sizeof(sip) 18 + sgroup 2 + dip 18 + dgroup 2 +
        // file_id 8 + asid 2 + padding 6 == 56 (file_events.h:
        // 110-:125); 8 + 56 == the pinned fixed_len 64.
        offset = offset.wrapping_add(56);
        // if (offset < data_len) file_ctx.serialize(buffer + offset,
        //     data_len - offset);
        if offset < data_len {
            let off = usize::from(offset);
            let tail_len = data_len.wrapping_sub(offset);
            self.file_ctx.serialize(&mut buffer[off..], usize::from(tail_len));
        }
    }

    /// `void deserialize(const char* buffer, uint16_t data_len)`
    /// (file_events.h:82-:104) — mirror of serialize; the
    /// `file_ctx.deserialize` tail REUSES the ported walk
    /// (file_lib.rs:370, file_lib.cc:254 body incl. the peer-wire
    /// hardening). Risk R8 / D4 vector: `len = data_len` records the
    /// RAW wire len (file_events.h:103), never a recomputed
    /// fixed+file_size.
    pub fn deserialize(&mut self, buffer: &[u8], data_len: u16) {
        let mut offset: u16 = 0;
        // header memcpys (file_events.h:85-:99), short wire panics
        // == the C OOB read UB equivalent (module header); the
        // timeout + six-member walk consumes 8 + 56 == 64 (the
        // field-wise reads happen in key_deserialize_from).
        self.key_deserialize_from(buffer);
        offset = offset.wrapping_add(64);
        // if (offset < data_len) file_ctx.deserialize(buffer + offset,
        //     data_len - offset);
        if offset < data_len {
            let off = usize::from(offset);
            let tail_len = data_len.wrapping_sub(offset);
            self.file_ctx.deserialize(&buffer[off..], usize::from(tail_len));
        }
        // len = data_len; (file_events.h:103 — D4 pin)
        self.len = data_len;
    }
}

// ------------------------------------------------------------------
// FileCacheShare (file_cache_share.h:29-:34, file_cache_share.cc:
// :30-:42) — the subscriber half.
// ------------------------------------------------------------------

/// `class FileCacheShare : public snort::DataHandler`
/// (file_cache_share.h:29-:34): no members; the ctor binds the
/// DataHandler name `FILE_ID_NAME == "file_inspect"`
/// (file_cache_share.h:32, file_config.h:42). Non-copyable-by-design
/// singleton: C `new FileCacheShare()` once (file_inspect.cc:82) and
/// never deletes it (perpetual subscriber). The DataHandler base is an
/// unported pub/sub row — the name binding is kept verbatim as a field.
pub struct FileCacheShare {
    /// `DataHandler(FILE_ID_NAME)` (file_cache_share.h:32)
    pub name: &'static str,
}

impl Default for FileCacheShare {
    fn default() -> Self {
        FileCacheShare::new()
    }
}

impl FileCacheShare {
    /// `FileCacheShare() : DataHandler(FILE_ID_NAME) {}`
    /// (file_cache_share.h:32)
    pub fn new() -> Self {
        FileCacheShare { name: FILE_ID_NAME }
    }

    /// `void handle(DataEvent& de, Flow*)` (file_cache_share.cc:30-:42).
    /// * cc:32 `static_cast<FileMPEvent&>(de)` — UNCHECKED downcast,
    ///   no RTTI (risk R6); the Rust parameter is already a
    ///   `&FileMpEvent`, so nothing checks (fidelity: C checks
    ///   nothing). The unnamed `Flow*` (cc:30) is unused and dropped.
    /// * cc:33-:35: THREE value extractions —
    ///   `int64_t timeout = fe.get_timeout(); FileHashKey key =
    ///   fe.get_hashkey(); FileInfo file = fe.get_file_ctx();` — `key`
    ///   copies the POD (cc:34) and `file` DEEP-COPIES the
    ///   event-owned FileInfo (cc:35, `FileInfo(const FileInfo&)` =
    ///   `copy(other)` + default clear_data=true, file_lib.cc:326):
    ///   that copy is what makes the later store survive event/cache
    ///   races (risk R3, vectors `H2 copy_not_alias=1`).
    /// * cc:37-:41: `FileService::get_file_cache()` (inline, file_service.h:98
    ///   over the file_service.h:109 static) is NULL-GUARDED (cc:38)
    ///   then `file_cache->store_shared_verdict(key, timeout, file)`
    ///   — the REAL port landed in 17q (file_cache.rs:1838-:1889) and
    ///   is called here unmodified. The `Option<&mut FileCache>`
    ///   parameter models the C static: `None` == null cache, the
    ///   `H1_nocache` guard arm.
    ///
    /// Deviation (PLAN §8-4): C hands `store_shared_verdict` a
    /// `FileInfo&`; the Rust port's signature (file_cache.rs:1841-:1847)
    /// takes `&Rc<RefCell<FileContext>>`, so the copied FileInfo
    /// arrives in a FRESH wrapper ctx — never ptr-equal to any cache
    /// node, exactly like the C situation where `src` aliases only
    /// itself (the port's `Rc::ptr_eq` self-alias no-op guard,
    /// file_cache.rs:1858-:1863, stays a no-op for event-sourced src).
    pub fn handle(
        &self,
        de: &FileMpEvent,
        file_cache: Option<&mut FileCache>,
        file_counts: &mut FileCounts,
    ) {
        // int64_t timeout = fe.get_timeout();  (cc:33)
        let timeout = de.get_timeout();
        // FileHashKey key = fe.get_hashkey();  (cc:34 — VALUE copy:
        // handle forwards the WIRE key verbatim, never rebuilds it —
        // risk R1 pin, H_xattr vector)
        let key = *de.get_hashkey();
        // FileInfo file = fe.get_file_ctx();   (cc:35 — deep copy,
        // clear_data=true per the copy ctor's default arg,
        // file_lib.h:97 / file_lib.cc:326-:328)
        let mut local = FileInfo::default();
        local.copy(de.get_file_ctx(), true);

        // FileCache* file_cache = FileService::get_file_cache();
        // if (file_cache)
        //     file_cache->store_shared_verdict(key, timeout, file);
        if let Some(file_cache) = file_cache {
            let mut src_ctx = FileContext::base(None);
            src_ctx.info = local; // the cc:35 copy drives the store
            let src = Rc::new(RefCell::new(src_ctx));
            file_cache.store_shared_verdict(&key, timeout, &src, file_counts);
        }
    }
}

// ------------------------------------------------------------------
/// `bool serialize_file_event(DataEvent* event, char*& buffer,
/// uint16_t* len)` (file_cache_share.cc:44-:61) — the
/// `MPSerializeFunc` binding (file_inspect.cc:78, mp_data_bus.h:89).
///
/// * cc:46-:47 `if (!event) return false;` — the NULL-EVENT arm
///   (`S1_null` vector): Rust models the C `DataEvent*` as
///   `Option<&mut FileMpEvent>`; `None` returns `None` and NOTHING
///   is allocated, the exact "buffer/len out-params untouched"
///   witness (`buf_null_after=1 len_untouched=1`).
/// * cc:49 the unchecked downcast (R6) — typed away (module header);
///   the probe only ever feeds real FileMPEvents (PLAN §7).
/// * cc:50-:52 `event_buffer_len = file_event->get_data_len();
///   if (event_buffer_len == 0) return false;` — the len==0 gate,
///   reached BOTH by the default-ctor event and by the oversized-
///   FILE cap (`S2_zerolen` vector: ctor cap, file_events.h:49-:50).
/// * cc:54 `buffer = new char[event_buffer_len];` — the ALLOCATION +
///   the cc:55-:56 `if (!buffer)` arm (dead in C++17, risk R4, NOT
///   transcribed). The fresh `Vec` IS the `new char[]`.
/// * cc:58-:60 `*len = event_buffer_len; file_event->serialize(
///   buffer, *len); return true;` — the wire length returned equals
///   `get_data_len()` (S3 `len_out=174 data_len=174`), the tail is
///   the file_events.h:106-:127 walk.
///
/// OWNERSHIP CONTRACT (risk R7, vectors `S_D_ownership`
/// `caller frees cc:54 buffer`): the C `char*&` out-buffer is
/// NEVER freed by this TU — the caller frees (`delete[] g_wire`,
/// probe :235). The Rust return MOVES the `Vec<u8>` to the caller,
/// which drops it — the leak-to-caller contract is the documented,
/// pinned invariant.
pub fn serialize_file_event(event: Option<&mut FileMpEvent>) -> Option<(Vec<u8>, u16)> {
    // if (!event) return false;  (cc:46-:47)
    let event = event?;
    // uint16_t event_buffer_len = file_event->get_data_len();
    let event_buffer_len = event.get_data_len();
    // if (event_buffer_len == 0) return false;  (cc:51-:52)
    if event_buffer_len == 0 {
        return None;
    }
    // buffer = new char[event_buffer_len];  (cc:54; cc:55-:56 dead, R4)
    let mut buffer: Vec<u8> = vec![0u8; usize::from(event_buffer_len)];
    // *len = event_buffer_len;               (cc:58)
    let len = event_buffer_len;
    // file_event->serialize(buffer, *len);   (cc:59)
    event.serialize(&mut buffer, len);
    // return true;                           (cc:60)
    Some((buffer, len))
}

// ------------------------------------------------------------------
/// `bool deserialize_file_event(const char* buffer, uint16_t len,
/// DataEvent*& event)` (file_cache_share.cc:63-:75) — the
/// `MPDeserializeFunc` binding (file_inspect.cc:79, mp_data_bus.h:90).
///
/// * cc:65-:66 `if (!buffer || len == 0) return false;` — BOTH arms
///   pinned: `D1_nullbuf` (null buffer, non-zero len; Rust
///   `buffer.is_empty()` models `!buffer`) and `D2_zerolen` (valid
///   buffer, len 0). The OUT-event stays untouched in both (C
///   `event_untouched=1`; Rust simply returns `None`).
/// * R5 PRESERVED, NOT FIXED: there is NO minimum-length check — the
///   only rejects are null/len==0, and the header walk then reads a
///   full 64-byte frame. A wire with `0 < len < 64` is UB in C (OOB
///   read); the Rust slices panic instead (file_lib.rs precedent).
///   Not validated further (transcription fidelity, D-vectors note).
/// * cc:68-:70 `new FileMPEvent()` + the dead `!file_event` arm
///   (R4, NOT transcribed): the default-ctor event (len=0 first).
/// * cc:72-:73 `file_event->deserialize(buffer, len); event =
///   file_event;` — the out-param RECEIVES OWNERSHIP (probe `delete
///   ev3`, :237; leak_delta 0 at :238). `FileMpEvent` returns by
///   value; the caller drops it.
pub fn deserialize_file_event(buffer: &[u8], len: u16) -> Option<FileMpEvent> {
    // if (!buffer || len == 0) return false;  (cc:65-:66)
    if buffer.is_empty() || len == 0 {
        return None;
    }
    // FileMPEvent* file_event = new FileMPEvent();  (cc:68; cc:69-:70
    // dead, R4)
    let mut file_event = FileMpEvent::default();
    // file_event->deserialize(buffer, len);  (cc:72)
    file_event.deserialize(buffer, len);
    // event = file_event; return true;       (cc:73-:74 — ownership
    // moves to the caller, R7)
    Some(file_event)
}

// ------------------------------------------------------------------
// Seam closure (row 17t): the real FileCacheShare-backed default for
// the `FileCacheEventSink` seam (file_cache.rs:503-:521; wiring site
// file_cache.rs:1171/:1200).
//
// C producer -> wire -> C subscriber chain, file_inspect.cc:76-:83:
// register_event_helpers(file_mp_pub_key, FILE_SHARE_SYNC,
// serialize_file_event, deserialize_file_event) + subscribe(..., new
// FileCacheShare()). MPDataBus publishes the FileMPEvent built at
// file_cache.cc:563-:571 (Rust twin publish_file_cache_event,
// file_cache.rs:1934-:1959); the bus SERIALIZES on the publisher
// side, DESERIALIZES on the subscriber (target-thread) side, and
// feeds FileCacheShare::handle. THIS PORT HAS NO MP BUS (the
// mp_dbus gate, file_cache.rs:1936 == C :563, stays the seam) — the
// sink runs the encode half at publish and queues the wire buffer;
// `drain` runs the decode half + handle (the target-thread moment).
// 17s `RealFileCaptureFactory` pattern: the shared wire queue is the
// Rc the driver clones before wiring the sink in, so the transport
// stays injectable while the default is the real machinery.
// ------------------------------------------------------------------

/// The FileCacheShare-backed sink: publishes through the cc:44
/// encoder and stores through the cc:63 decoder +
/// `FileCacheShare::handle` at drain time. The wire queue element is
/// `(buffer, len)` exactly as the C out-params pair it (cc:54/:58).
/// Alias for the clippy type-complexity threshold — the queue IS the
/// C out-param pair `(char* buffer, uint16_t len)` (cc:54/:58), kept
/// explicit; the alias names it, no restructure.
pub type WireQueue = Rc<RefCell<Vec<(Vec<u8>, u16)>>>;

pub struct FileCacheShareSink {
    /// the bound handler (DataHandler(FILE_ID_NAME), h:32)
    pub handler: FileCacheShare,
    wire: WireQueue,
}

/// a fresh queue (the unported MPDataBus hand-off stand-in)
pub fn new_wire_queue() -> WireQueue {
    Rc::new(RefCell::new(Vec::new()))
}

impl Default for FileCacheShareSink {
    fn default() -> Self {
        FileCacheShareSink::new()
    }
}

impl FileCacheShareSink {
    pub fn new() -> Self {
        FileCacheShareSink {
            handler: FileCacheShare::new(),
            wire: new_wire_queue(),
        }
    }

    /// attach to a shared queue (the `FileCache::new` default wiring:
    /// the cache owns the hand-off queue as `mp_wire`, the sink holds
    /// the clone — C's process-wide MPDataBus between publish and the
    /// subscriber thread's deserialize+handle).
    pub fn with_queue(wire: WireQueue) -> Self {
        FileCacheShareSink { handler: FileCacheShare::new(), wire }
    }

    /// Transport handle clone for the driver (17s factory precedent):
    /// the queue survives the `Box<dyn>` move so drain-side replay
    /// stays reachable; a default-wired cache simply never drains —
    /// the MP bus that would deliver is the unported transport half.
    pub fn wire_handle(&self) -> WireQueue {
        self.wire.clone()
    }

    /// Subscriber-side replay: `deserialize_file_event` (cc:63) each
    /// queued wire frame, then `FileCacheShare::handle` (cc:30)
    /// against the real cache. Returns the frame count drained (the
    /// `H*` vectors drive their events this way). Static because the
    /// driver holds only the cloned wire handle after the sink moves
    /// into `Box<dyn>`; the handler is stateless in C (cc:30-:42
    /// touches no DataHandler member).
    pub fn drain(
        wire: &WireQueue,
        file_cache: &mut FileCache,
        file_counts: &mut FileCounts,
    ) -> usize {
        let handler = FileCacheShare::new();
        let frames = std::mem::take(&mut *wire.borrow_mut());
        let mut n = 0;
        for (buffer, len) in frames {
            // cc:65-:66 guards inside deserialize_file_event; an
            // undecodable frame is dropped exactly where C would not
            // invoke the subscriber at all.
            if let Some(ev) = deserialize_file_event(&buffer, len) {
                handler.handle(&ev, Some(file_cache), file_counts);
                n += 1;
            }
        }
        n
    }
}

impl FileCacheEventSink for FileCacheShareSink {
    /// The publish-side half of the seam: mirrors
    /// `std::make_shared<FileMPEvent>(hashkey, timeout, *file)` +
    /// `MPDataBus::publish(...FILE_SHARE_SYNC...)` queued at
    /// file_cache.rs:1942-:1947 (C file_cache.cc:565-:571) — the
    /// FileMPEvent ctor copy (file_events.h:41), the cc:44 encode
    /// (skip on the len==0 cap arm: nothing reaches the bus), and
    /// the bus queue. `file_log_event` keeps the trait default: the
    /// FILE_VERDICT/FILE_COMPLETE publishes belong to the
    /// log_file_event body + PublishApi seam (file_lib.rs:757+,
    /// 17r), not to this TU.
    fn publish_file_share_sync(&mut self, key: &FileHashKey, timeout: i64, file: &FileContext) {
        let mut ev = FileMpEvent::new(key, timeout, &file.info);
        if let Some((buffer, len)) = serialize_file_event(Some(&mut ev)) {
            self.wire.borrow_mut().push((buffer, len));
        }
    }
}
