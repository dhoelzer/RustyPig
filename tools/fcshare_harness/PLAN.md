# fcshare_harness PLAN — row 17t: file_api/file_cache_share.{h,cc} (the MP-share glue row, probe-vectors-only)

RECON-measured against `/opt/data/snort3-src` @ fe29cbe7 (ground truth,
read-only) from snort3-rust @ d0109b8 (rows 1–17s landed; 431 tests; real
ports file_cache/flows/lib/segment/mempool/circular_buffer/capture.rs).
Every number below was measured this recon (wc/grep/sed plus a live
`g++ -fsyntax-only` + compile + `nm -u` of the real TU against the donor
copy tree — see §3), not estimated.
Harness donor = `tools/fcap_harness/` (row 17s; its build.sh already cp's
`file_cache.cc`/`file_lib.cc`/`file_events.{h,cc}`/`mp_data_bus.h` VERBATIM
and links `file_cache.o`/`file_lib.o` into both the gate and the probe —
the entire symbol closure this TU needs is already in that link).

## 1. Scope definition + size (measured)

- `src/file_api/file_cache_share.h` = **40 lines**; `src/file_api/file_cache_share.cc` =
  **75 lines** (wc/read this recon). The entire file is the compilable
  region (`#ifdef HAVE_CONFIG_H` :20–:22 only; no `#ifdef UNIT_TEST`
  anywhere — grep 0 hits).
- Row scope = the 3 public entry points of the TU:
  1. `FileCacheShare` class (h:29–:34) — a `snort::DataHandler` subclass
     (decl `framework/data_bus.h:78` src, `copy/framework/data_bus.h:78`
     donor) with ctor `DataHandler(FILE_ID_NAME)` (h:32;
     `FILE_ID_NAME` = `"file_inspect"`, file_config.h:42) and one virtual
     `handle(DataEvent&, Flow*)` (h:33 → cc:30–:42).
  2. `serialize_file_event(DataEvent*, char*&, uint16_t*)` (h:36 →
     cc:44–:61) — matches `MPSerializeFunc` typedef (src
     framework/mp_data_bus.h:89).
  3. `deserialize_file_event(const char*, uint16_t, DataEvent*&)` (h:37 →
     cc:63–:75) — matches `MPDeserializeFunc` typedef (src
     framework/mp_data_bus.h:90).
- Supporting cast target `FileMPEvent` lives in `pub_sub/file_events.h`
  (already donor-copied, build.sh:37) — its inline `serialize`
  (file_events.h:106–:127) / `deserialize` (file_events.h:82–:104) codec
  walk is ground truth for vectors but NOT a new TU.
- NOT in scope: `FileCache::store_shared_verdict` (file_cache.cc:508–:528)
  — already ported 17q (file_cache.rs:1838–:1889); the FileInspect
  subscription wiring (file_inspect.cc:76–:83) — not a ported row; the
  producer side `publish_file_cache_event` (file_cache.cc:561–:575) —
  already ported behind the `FileCacheEventSink` seam (file_cache.rs:1934–:1959,
  §6). 17t is a **thin glue row**: codec pair + handler thunk + sink swap.

## 2. TEST_CASE inventory (measured)

**ZERO TEST_CASEs, ZERO RUNNER assertions, ZERO `#ifdef UNIT_TEST`
fragments** in the TU (`grep -c TEST_CASE` = 0; grep UNIT_TEST = 0 hits,
both files). This row is **probe-vectors-only ground truth**: the gate
link contributes no upstream catch tests for 17t; every behavioral oracle
comes from a new `file_cache_share_probe.cc` + vectors.txt arms (plan §7).
Gate assertion count therefore stays 543-donor (22 cases / 114 assertions,
fcap gate.txt) — the 17t delta there is 0 cases; witness deltas ride in
new `FCS_*` vector lines only.

## 3. Include closure of file_cache_share.cc vs the fcap donor (VERIFIED this recon)

Includes = `config.h` (cc:21), `file_cache_share.h` (cc:24 → pulls
`framework/mp_data_bus.h` h:24 + `pub_sub/file_events.h` h:25),
`file_service.h` (cc:25), `log/messages.h` (cc:26).

Donor status of every header (fcap build.sh):
| include | fcap donor status |
|---|---|
| config.h | shim written by build.sh:68 — already-verbatim |
| framework/mp_data_bus.h (via h:24) | REAL header `cp`'d verbatim (build.sh:46); **include is explicitly NOT excised** (build.sh:242–:245 note) because file_cache.cc:563–:571 uses MPDataBus — witness `get_id`/`publish` BODIES already in stubs.cc:298/:300 |
| pub_sub/file_events.h + file_events.cc (via h:25 → file_cache.h, file_events.h:29) | REAL header + TU cp'd (build.sh:37); `file_events.o` in objs loop (build.sh:365) |
| file_service.h (cc:25) | REAL header cp'd (build.sh:36: `file_api/…file_service.h`); `FileService::get_file_cache()` is inline (file_service.h:98) over static `file_cache` (file_service.h:109) — B symbol already defined in **stubs.o** |
| log/messages.h (cc:26) | REAL header cp'd (build.sh:59); `ErrorMessage` body witness stubs.cc:115 — already in link |
| framework/data_bus.h (via h:24 → mp_data_bus/data bus closure) | REAL header cp'd (build.sh:46) — hosts `DataHandler` (:78) |

**Live verification (run this recon)** — TU copied verbatim to a scratch
dir and compiled with ONLY the donor tree headers
(`g++ -std=c++17 -O0 -w -I<scratch> -I<fcap copy> -I<copy>/file_api -I$NODE_INC`):
- `-fsyntax-only` → **PASS** (one include-path note: because the TU lives
  in `src/file_api/`, relative includes `file_cache_share.h`/`file_service.h`
  need the `-I$C/file_api` addition or the file placed in `copy/file_api/` —
  the donor already does the latter for every other file_api TU).
- `-c` to object → **PASS**.
- `nm -u file_cache_share.o` = 30 undefined symbols; **application-symbol
  residue = 7**, every one already DEFINED in the existing fcap link:

| undefined app symbol (demangled kernel) | provider .o (all already in the fcap link) |
|---|---|
| `FileCache::store_shared_verdict(FileHashKey const&, long, FileInfo&)` | copy/file_api/**file_cache.o** @ +0x1aa4 (real TU, gate objs build.sh:521 + probe objs build.sh:537) |
| `FileInfo::serialize(char*, unsigned short)` | copy/file_api/**file_lib.o** @ +0x80c (body file_lib.cc:197) |
| `FileInfo::deserialize(char const*, unsigned short)` | copy/file_api/**file_lib.o** @ +0xcfa (body file_lib.cc:254) |
| `FileInfo` copy ctor | **file_lib.o** @ +0x1008 |
| `FileInfo` dtor | **file_lib.o** @ +0x278 |
| `FileInfo` vtable `_ZTVN5snort8FileInfoE` | **file_lib.o** (V) |
| `FileService::file_cache` static | **stubs.o** (B @ +0x98) |

Remaining 23 undefined are libstdc++/libc (`operator new[]/delete`,
`basic_string` internals, RTTI type-info, memcpy/strlen, unwind) — all
already satisfied by the donor link line. **Closure diff vs the donor =
ZERO new TUs, ZERO new stubs**; the ONLY build.sh delta is adding
`file_cache_share.h file_cache_share.cc` to the cp list (build.sh:36), the
`-fsyntax-only` loop (build.sh:365–:367), and `file_cache_share.o` to the
gate objs (build.sh:521) + probe objs (build.sh:537) arrays.

## 4. `#ifdef UNIT_TEST` fragment table

**Empty.** No fragments in either file (grep 0). No keep/excise decisions;
no FIXLIBUT-style rfind+brace-guard surgery needed for the target TU —
unusual and worth pinning: the donor's UNIT_TEST excision recipes
(build.sh per-file python seds) simply never fire on this file.

## 5. Surface map + internals (all cited)

5.1 `FileCacheShare` (h:29–:34, cc:30–:42):
- Non-copyable-by-design singleton: the ctor only sets the DataHandler
  name `"file_inspect"` (h:32, file_config.h:42). No members. No dtor —
  the instance is `new`-allocated once (file_inspect.cc:82) and never
  deleted (perpetual subscriber; leaks by design at exit).
- `handle(DataEvent& de, Flow*)` (cc:30–:42):
  - `static_cast<FileMPEvent&>(de)` (cc:32) — **unchecked downcast, no
    RTTI**; passing a non-FileMPEvent is UB (risk R6).
  - copies out `int64_t timeout = fe.get_timeout()` (cc:33;
    file_events.h:61–:64), `FileHashKey key = fe.get_hashkey()` (cc:34;
    file_events.h:72–:75 returns const-ref, cc:34 **copies**), and
    `FileInfo file = fe.get_file_ctx()` (cc:35; **copy-constructs** from
    the event-owned const-ref — file_events.h:66–:70 documents
    "Returned references are event-owned and must not outlive this
    FileMPEvent"; the local copy is what makes the later store safe).
  - `FileService::get_file_cache()` (cc:37, inline getter
    file_service.h:98) → **null-guarded** (cc:38) →
    `file_cache->store_shared_verdict(key, timeout, file)` (cc:40).
- `store_shared_verdict` internals (file_cache.cc:508–:528, the hash
  machinery this row only *drives*, hashed in XHash):
  - `ExpectedFileCache : XHash` (file_cache.cc:56–:66) — no new hash math
    here; Rust `XHash` port exists (src/hash/xhash.rs, real, landed) and
    `FileHashKey` = 7-field PADDING_GUARD struct (file_cache.h:40–:49:
    sip/sgroup/dip/dgroup/file_id/asid/padding) — Rust mirror
    file_cache.rs:129.
  - `add(key, timeout, cache_full, cache_expire, true)` (cc:512 — cache
    sync flag) then `find_add(key, timeout)` under `cache_mutex` (cc:514–
    :515); null node → return (cc:516–:517).
  - Verdict-priority gate: `verdict_publish_blocked(node->verdict,
    src.verdict) || (cached_condemned && !incoming_condemned)` → drop
    (cc:519–:524; body: cached terminal && incoming {UNKNOWN,PENDING} →
    blocked). Then `*((FileInfo*)node) = src` under the node's recursive
    user-data mutex (cc:526–:527). Rust twin: file_cache.rs:1838–:1889
    incl. the `Rc::ptr_eq` self-alias no-op guard (file_cache.rs:1858–
    :1863) which C lacks structurally.

5.2 `serialize_file_event` (cc:44–:61), branch-exact:
- `!event` → false (cc:46–:47); buffer out-param untouched.
- `event_buffer_len = file_event->get_data_len()` (cc:50;
  file_events.h:77–:80) == 0 → false (cc:51–:52). len==0 arises from the
  oversized-file cap in `FileMPEvent` ctor (file_events.h:43–:52:
  `fixed_len` = timeout + the six FileHashKey members; `len = 0` iff
  serialized file size > `uint16_max - fixed_len`).
- `buffer = new char[len]` (cc:54); `if (!buffer) return false` (cc:55–
  :56) is **dead code in C++17** (`new[]` throws, never returns null —
  risk R4).
- `*len = len` (cc:58); `file_event->serialize(buffer, *len)` (cc:59 →
  file_events.h:106–:127 memcpy walk: timeout, sip, sgroup, dip, dgroup,
  file_id, asid, padding, then `file_ctx.serialize` tail iff
  `offset < data_len`). **Allocates; TU never deletes** — caller frees
  (probe must `delete[]`, §7).

5.3 `deserialize_file_event` (cc:63–:75), branch-exact:
- `!buffer || len == 0` → false (cc:65–:66). Note: **no minimum-length
  check** — a 1-byte buffer still enters the fixed memcpy header walk
  (file_events.h:85–:100 reads timeout+key fields unconditionally) → OOB
  read risk R5.
- `new FileMPEvent()` (cc:68; null-check cc:69–:70 dead-code like R4);
  `file_event->deserialize(buffer, len)` (cc:72 → file_events.h:82–:104,
  mirror of serialize, `file_ctx.deserialize` tail iff offset<len, then
  `len = data_len` :103).
- `event = file_event` (cc:73) — **heap-allocated out-param; ownership
  transfers to caller; no delete in this TU** (probe must delete, else
  the leak shows in valgrind/leak gate — §7).

5.4 `FileMPEvent` payload (file_events.h:37–:134): members
timeout/hashkey/file_ctx/len (h:129–:134); ctor-from-parts (h:41–:53) and
default ctor zeroing (h:55–:59). `file_ctx` is a **by-value FileInfo**
(h:132) — the event owns a copy, which is why cache-clear races can't
dangle through the wire (risk R3 discussion).

## 6. Consumer map (ground truth) + Rust seam sites (exact lines)

C-side consumers (grep -rn 'FileCacheShare|file_cache_share|serialize_file_event|deserialize_file_event' this recon — all hits):
| site | role |
|---|---|
| file_inspect.cc:37 | `#include "file_cache_share.h"` — ONLY class consumer |
| file_inspect.cc:76–:83 | `if (sc->mp_dbus)` gate: binds both free funcs as function pointers (:78–:79), `MPDataBus::register_event_helpers(file_mp_pub_key, FileMPEvents::FILE_SHARE_SYNC, …)` (:81), `MPDataBus::subscribe(…, new FileCacheShare())` (:82). `FILE_SHARE_SYNC` id = the second enum value (file_events_ids.h:34–:38) on PubKey `file_mp_pub_key` (file_events_ids.h:49) |
| file_cache.cc:561–:575 (via :563 mp_dbus gate) | producer: publishes `std::make_shared<FileMPEvent>(hashkey, timeout, *file)` — the event this TU's `handle` receives |
| inspector_manager.cc:1905–:1909 | comment "this check required for FileCacheShare events from non-packet threads" + `if (!curr_iv) return nullptr;` — the threading context of `handle` (risk R2) |
| src/file_api/CMakeLists.txt:18–:19 | build registration |

Rust-side current seams/witnesses (grep this recon; **no
`file_cache_share.rs` exists** — mod.rs :1–:9 has 9 file_api modules, none
shares):
| Rust site | role vs the C TU |
|---|---|
| src/file_api/file_cache.rs:503–:518 | `FileCacheEventSink` trait: `publish_file_share_sync(&mut self, &FileHashKey, i64, &FileContext)` (:504–:510) — the **publish side** seam standing in for MPDataBus::publish + (by transport) the serialize/handle pair |
| src/file_api/file_cache.rs:520–:521 | `NoopFileCacheEventSink` (default: does nothing) |
| src/file_api/file_cache.rs:1200 | `events: Box::new(NoopFileCacheEventSink)` wiring site |
| src/file_api/file_cache.rs:1934–:1959 | `publish_file_cache_event` (file_cache.cc:561 twin; mp_dbus gate :1936 = C :563; comment block :1940–:1944 marks the elided FileMPEvent/make_shared/publish sequence) — the seam the 17t PORT swaps |
| src/file_api/file_cache.rs:1838–:1889 | `store_shared_verdict` — **the entire cc:40 callee already ported** (17q); 17t's handle thunk calls it |
| src/file_api/file_cache.rs:1660–:1670 | `verdict_publish_blocked` twin (file_cache.cc static) |
| src/file_api/file_cache.rs:129 | `FileHashKey` mirror (file_cache.h:40–:49) |
| src/file_api/file_lib.rs:451 | `FileInfo::assign` — twin of cc-via-`store_shared_verdict` `*((FileInfo*)node) = src` |
| src/hash/xhash.rs (+ ghash/hash_key_operations/primetables) | the hash layer store_shared_verdict runs on — already real; 17t adds no hash code |
| grep serialize_file_event/deserialize_file_event in Rust | **ZERO hits** — the codec pair is the genuinely new surface |

## 7. Gate plan + PROBE VECTOR PLAN (labeled arms; 0-TEST_CASE TU → probe-only ground truth)

Harness child recipe: extend the fcap donor per §3 delta (cp entry, syntax
loop entry, 2 objs entries), add `copy/file_api/file_cache_share_probe.cc`
(pattern = donor `file_cache_probe.cc`, `-DUNIT_TEST -fsyntax-only` gate
build.sh:496, compiled into probe link build.sh:537), and append FCS arms
to vectors.txt (format precedent: donor vectors.txt line style
`LABEL k=v k=v …`). FIXACC precedent (build.sh:235–:241) applies to
FileMPEvent/file_service if probe needs private statics: **the probe
writes `FileService::file_cache` directly** (stubs.o B symbol,
file_service.h:109) — no new stub needed because
`store_shared_verdict`/`FileInfo` methods link to the REAL .o files (§3).

Probe must construct only real `FileMPEvent`s (never a raw DataEvent into
`handle` — UB by the cc:32 downcast, risk R6). Arms:

**S — serialize_file_event (3 arms):**
- `S1_null =` `serialize_file_event(nullptr, buf, &len)` → 0/false; buf
  still null, len unchanged (cc:46–:47). Witness: `buf_null_after=1
  len_untouched=<sentinel>`.
- `S2_zerolen =` default-constructed `FileMPEvent` (len==0,
  file_events.h:55–:59) → 0/false, buf untouched (cc:51–:52). PLUS
  oversized-file sub-arm: file_ctx whose `get_serialized_size()` forces
  the ctor cap `len = 0` (file_events.h:49–:50) → same false — one line,
  both branches of len==0 convergence.
- `S3_ok =` populated 4-tuple event → 1/true; `len_out = fixed+file_size
  == get_data_len()`; buffer bytes == expected manual layout
  (timeout(8)|sip|sgroup|dip|dgroup|file_id(8)|asid|pad(6)|file tail —
  field order file_events.h:108–:127); probe `delete[]` after (cc:54
  allocation, no TU-side free). Witness `roundtrip_hdr=1 len_eq=1
  tail_off_eq=1`.

**D — deserialize_file_event (3 arms):**
- `D1_nullbuf =` (`nullptr`, nonzero len) → false (cc:65–:66), out-event
  stays untouched sentinel.
- `D2_zerolen =` (valid buf, len 0) → false (cc:65–:66).
- `D3_roundtrip =` S3's buffer → true; non-null `event`; `get_timeout()`,
  all six hashkey fields (file_cache.h:40–:49), and file_ctx verdict/name
  equal originals (file_events.h:82–:104 walk); then probe handles the
  new'd event's ownership (delete it — cc:68 heap out-param, leak oracle
  = FCS leak-delta 0). Sub-arm `D4_lenrec`: post-call
  `event->get_data_len() == len` (file_events.h:103 records input len).

**H — FileCacheShare::handle (4 arms):**
- `H1_nocache =` `FileService::file_cache == nullptr` (default; stubs.o
  zero-init) → handle(event, nullptr-flow) returns, no crash (cc:38 null
  guard). Witness `cached_after=null`.
- `H2_copy_then_store =` FileCache constructed & installed; event carries
  file_ctx verdict BLOCK with distinct sha/name → after handle: cache
  node via `find` has verdict BLOCK and file_data copied; and mutating
  `event`'s file_ctx **after** the call does NOT alter the cache node
  (proves the value copies at cc:35 and the FileInfo deep-copy ctor,
  file_lib.o +0x1008).
- `H3_blocked =` pre-seed cache node terminal verdict BLOCK, incoming event
  verdict UNKNOWN → node unchanged (verdict-publish gate cc driven via
  public handle; body file_cache.cc:519–:524).
- `H4_blocked2 =` pre-seed node BLOCK, incoming also BLOCK (condemned→
  condemned not gated; verdict_publish_blocked false because incoming
  terminal) → `*((FileInfo*)node)=src` fires (file_cache.cc:526–:527).
- Sub-arm `H_xattr`: `H2` with `timeout` past expiry — second `handle`
  same key must create/recover entry (XHash node-recovery,
  file_cache.cc:68–:86 `is_node_recovery_ok`) — pins the hash identity
  half of risk R1.
- Clear/dtor interaction arms (FileCache Drop-walk precedent
  file_cache.cc:63–:66 `~ExpectedFileCache → delete_hash_table`; Rust
  Drop file_cache.rs:985–:1002): `X1_handle_after_clear` = call
  store-path handle, `FileCache::clear()` (file_cache.h:88), then handle
  same key again → fresh node, no UAF; `X2_dtor_with_live_event` = let
  FileCache dtor run while the FileMPEvent holder is still alive → no
  access violation (event owns a by-value FileInfo, file_events.h:132);
  witness leak delta 0 at probe exit for the event (catch teardown order
  = declaration order: allocate event X1 before the cache like the
  donor's F-lifecycle vectors).

**W — witness inventory delta for the probe link:** no new stubs (§3);
new probe-visible counters all readable: `file_cache->get_num_entries()`
(file_cache.h:68), node verdict via FIXACC-exposed find, `get_num_entries`
before/after each H/X arm, and `sizeof(FileHashKey)` STATIC_ASSERT-style
CONST line (cf. donor `CONST sizeof_FileCapture=72` vector line).

## 8. PORT scoping — transcription plan + seam swap sites (no code here)

New `src/file_api/file_cache_share.rs` (~small; mirrors 40+75-line TU):
1. `FileMpEvent` struct — fields timeout:i64, hashkey:FileHashKey
   (file_cache.rs:129), file_ctx owned copy, len:u16; ctor cap arithmetic
   transcribed from file_events.h:41–:59; `serialize`/`deserialize` byte
   walk transcribed 1:1 from file_events.h:82–:127 (fixed header order +
   `file_ctx` tail guarded by `offset < data_len`).
2. `serialize_file_event(&FileMpEvent) -> Option<(Vec<u8>, u16)>` —
   branches cc:46/:51 kept; the dead `!buffer` branch (cc:55–:56) **not
   transcribed** with deviation note (Rust Vec alloc can't return null).
3. `deserialize_file_event(&[u8], u16) -> Option<FileMpEvent>` — cc:65
   guard kept exactly (null→empty-slice, len==0 kept); the missing
   minimum-length guard is preserved as-is with risk note (R5) — do NOT
   "improve" the C logic (transcription fidelity).
4. `FileCacheShare` handler thunk: plain `fn handle(&mut self…)`-style
   receive over a decoded event + `&mut FileCache` — body = 3 field reads
   (cc:33–:35; the cc:35 copy is load-bearing, R3) +
   `file_cache.store_shared_verdict(&key, timeout, &src_rc, counts)`
   (file_cache.rs:1838 — already real; the `if (file_cache)` null-check
   (cc:38) maps to `Option<&mut FileCache>`). No `Rc<RefCell>` re-entry:
   the event-sourced src must arrive as a *separate* `Rc<RefCell<FileContext>>`
   so the existing ptr_eq guard (file_cache.rs:1858–:1863) behaves as C
   aliasing (risk R3).

Seam swap sites:
- `file_cache.rs:520–:521` `NoopFileCacheEventSink` → real sink
  implementation whose `publish_file_share_sync` (:504–:510 default body)
  encodes via `serialize_file_event` (the transport half stays a seam —
  there is no MP bus in the port; the vector gate already pins mp_dbus
  off, file_cache.rs:1936).
- Wiring site `file_cache.rs:1200` (`events: Box::new(…)`) is the one-line
  constructor swap site.
- `src/file_api/mod.rs` :1–:9 — add the module entry (alphabetically
  after file_capture, matching donor CMakeLists ordering C:18–:19).
- Nothing to swap in `store_shared_verdict` / xhash.rs — they already
  match ground truth.

Suggested Rust test mapping (probe label → Rust test, no Rust written in
this row): S1–S3/D1–D4 → codec unit tests at the new module; H1–H4/X1
already 17q-covered at the `store_shared_verdict` level — add the thin
handle-thunk duplicates (null-cache + copy-not-alias) only (mirror the
donor's minimal glue coverage posture).

## 9. Risks flagged for HARNESS/PORT children

- **R1 file_id vs flow-key identity**: the `FileHashKey` this TU forwards
  is built only on the PRODUCER side (`make_key`, file_cache.cc:500–:501/
  :1937–:1938 Rust). handle trusts the wire key verbatim (cc:34) — a
  wrong/mismatched key silently CREATES an entry via `add(...,true)`
  (file_cache.cc:512). Vectors H2/H_xattr must pin key-equality, and the
  PORT must not rebuild keys inside handle (that would fork identity).
- **R2 threading**: `handle` can run on non-packet threads — the only
  guard is `InspectorManager::acquire_file_inspector` nulling out on
  `!curr_iv` (inspector_manager.cc:1905–:1909). No THREAD_LOCAL appears
  in this TU (grep verified 0 hits in both files); `FileService::file_cache`
  is a process-wide static (file_service.h:109). Thread-safety rides
  entirely in `FileCache::cache_mutex` (file_cache.cc:514) + the node's
  recursive user-data mutex (file_cache.cc:526). Harness stays
  single-threaded (donor precedent); PORT seam note: the Rust `FileCache`
  is `&mut`-borrowed, so a real MP receive path would need an external
  serialization point — out of scope, flag only.
- **R3 entry lifetimes across cache clears**: the event owns a BY-VALUE
  `FileInfo` (file_events.h:132) and cc:35 copies again — so no wire event
  can dangle through `FileCache::clear()` (file_cache.h:85–:88, Rust
  file_cache.rs:1756) or the dtor walk (`~ExpectedFileCache`
  file_cache.cc:63–:66; Rust Drop file_cache.rs:985–:1002). The danger is
  inverted on the WRITE side: `*((FileInfo*)node) = src`
  (file_cache.cc:527) mutates a node another thread may be pinning —
  pinned by the recursive mutex in C; the Rust port relies on
  `Rc<RefCell>` single-thread aliasing (no concurrent writer exists yet).
  X1/X2 vectors pin the safe half.
- **R4 dead null-checks on `new`** (cc:55–:56, cc:69–:70): never taken in
  C++17. Harness: no vector can reach them without `-fno-exceptions`
  tricks — document as unreachable arms, do not fake them. PORT: use
  Vec/Box and note the deviation in the module doc comment.
- **R5 deserialize has no minimum-length guard** (cc:65–:66 only rejects
  len==0; the fixed header memcpy walk at file_events.h:85–:100 reads the
  full timeout+key header unconditionally → any 0<len<fixed header read
  is OOB). Harness must NOT vector a truncated buffer (UB, not oracle
  material); the comment in the probe records the known upstream gap.
- **R6 unchecked downcasts** `DataEvent→FileMPEvent` (cc:32, cc:49): the
  harness feeds only true FileMPEvents; a raw `DataEvent` is UB, not a
  negative test.
- **R7 heap-ownership oracles**: `serialize_file_event` allocates
  `new char[]` (cc:54) and `deserialize_file_event` allocates `new
  FileMPEvent` (cc:68), both caller-owned, never freed in the TU. Probe
  must free both and assert leak delta 0 (catch `TEST_CASE`-free
  lifecycle: manual delete at arm end), or the leak check misattributes
  glue-row noise.
- **R8 len semantics coupling**: `get_data_len` doubles as (a) the
  serialize false-gate (cc:51) and (b) the recorded input len on
  deserialize (file_events.h:103) — D4 vector pins that deserialize's
  `len` out-value equals the raw wire len, not a recomputed
  fixed+file_size (a PORT "validation" here would diverge).

## 10. Session ritual (mirror fcap PLAN §10)

1. `bash /opt/data/snort3-rust/tools/fcap_harness/build.sh` untouched first:
   gate "All tests passed (114 assertions in 22 test cases)" must stay
   byte-ident at 17t baseline (this row adds 0 assertions — §2).
2. Copy §3 delta into a NEW `tools/fcshare_harness/build.sh` (full donor
   cp/sed/objs blocks; do NOT mutate the fcap donor).
3. Verify with the donor's own gates: `-fsyntax-only` loop incl.
   file_cache_share (done by this recon — PASS), then objs-loop + probe
   link + `nm -u` residue diff vs fcap nm_residue.txt (expect only the
   file_cache_share.o's own 7 already-satisfied app symbols; §3).
4. `nm -u file_cache_share.o` (fresh, this recon — the check the parent
   asked re-verified): 30 U entries, 7 app, all defined in
   file_cache.o/file_lib.o/stubs.o provider attribution table §3. No
   undefined app-symbol residue that the donor link cannot close.
5. Run probe, append FCS_* lines to vectors.txt (S/D/H/X blocks, §7);
   commit nothing (row is PLAN-only until the harness child lands).
