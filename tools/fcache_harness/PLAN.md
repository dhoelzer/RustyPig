# fcache_harness PLAN — row 17p: file_api/file_cache.{h,cc}

Phase: RECON (this file is the only artifact). Donor: `tools/filib_harness`
(row 17o). Upstream ground truth: `/opt/data/snort3-src` @ `fe29cbe`
(READ-ONLY). Every claim below was measured against the real files.

## 1. Target measurements

| file | lines | note |
|---|---|---|
| `src/file_api/file_cache.cc` | 1287 | includes at :20-50; UNIT_TEST block :1140-1287 |
| `src/file_api/file_cache.h` | 115 | FileHashKey PADDING_GUARD :39-50; class FileCache :52-113 |

Header structure (file_cache.h):
- `FileHashKey` POD key :40-49 — `snort::SfIp sip/dip`, `int16_t sgroup/dgroup`,
  `uint64_t file_id` (:46), `uint16_t asid` (:47), `uint16_t padding[3]` (:48).
- `ExpectedFileCache` forward-declared :37; member `ExpectedFileCache*
  fileHash = nullptr;` :108 (a POINTER — see §4 for xhash verdict).
- `FileCache` public API :54-88 (add/get_file/cached_verdict_lookup/apply_verdict/
  dup_cache_context/take_pending_file_data/resume_pending_verdict/
  cached_context_not_cacheable/store_shared_verdict/dump_cache/dump_cache_entry/
  clear); privates :90-105; atomics `block_timeout` :109, `lookup_timeout` :110;
  `max_files` :111; `std::mutex cache_mutex` :112.
- Header includes: `sfip/sf_ip.h` :29, `utils/cpp_macros.h` :30,
  `file_api.h` :32, `file_config.h` :33 (no mp_data_bus include).
- `FileCacheClearReport { uint64_t freed; uint64_t remaining; }` lives in
  `file_api/file_api.h:121-125`.

file_cache.cc key landmarks:
- `class ExpectedFileCache : public XHash` :56-92 — overrides
  `is_node_recovery_ok` :68-84 (packet_gettimeofday :78 + timercmp :80) and
  `free_user_data` :86-91 (`delete node->file` :90).
- ctor :118-123 (`new ExpectedFileCache(max_files, sizeof(FileHashKey),
  sizeof(FileNode))` :121 + `set_max_nodes` :122).
- `clear()` :457-481 — manual `find_first_node`/`find_next_node`/`release_node`
  walk (:467-477) chosen deliberately over `XHash::clear_hash()` per comment
  :466 (clear_hash would reset capacity).
- anon-ns `CacheNodePin` RAII :94-107 (`file->unpin()` under cache_mutex :101-102).
- `time_elapsed_ms` :110-116 (uses `timersub_ms` from `time/packet_time.h:31`).
- dump path snapshot/format split :906-1002, `walk_locked` :1004-1029,
  `dump_cache` :1031-1071, `dump_cache_entry` :1073-1134 (LogRespond macro is
  `control/control.h:99-101`, null-conn arm falls to `snort::LogMessage`).

## 2. TEST_CASE inventory (UNIT_TEST block file_cache.cc:1140-1287)

Catch include inside block: `#include "catch/snort_catch.h"` :1142. Helpers
`ut_make_key` :1144-1149 and `ut_add` :1151-1156 (add with timeout 60,
cache_sync=true). **7 TEST_CASEs, 42 assertions (MEASURED by the built gate
run; the original RECON tally of 36 was an undercount).**

| # | TEST_CASE (line) | [file_cache] semantics pinned |
|---|---|---|
| 1 | "file cache clear: all entries are freed" (:1158) | 4 entries (UNKNOWN/PENDING/LOG/+UserFileDataBase via `set_file_data` :1176); `clear()` → freed==4, remaining==0, get_num_entries()==0. Pins ownership: every FileContext (incl. user data) freed via XHash `free_user_data` (file_cache.cc:90). |
| 2 | "file cache clear: entry with capture is freed" (:1184) | `set_config(&config)` :1192 + `process_file_capture(nullptr,0,SNORT_FILE_FULL)==FILE_CAPTURE_SUCCESS` :1193 (real file_capture closure); freed==1. Pins capture-buffer ownership inside the cached FileContext. |
| 3 | "file cache clear: entry with queued segments is freed" (:1201) | `set_file_size(16)`; out-of-order `process(nullptr,&data,1,8,nullptr)` :1210; `segments_queued()` :1211 (file_lib.h:207, member `file_segments` file_lib.h:233); freed==1. Pins segment-queue owned by the entry (`FileNode.file`, file_cache.h:59), freed by `~FileContext`. |
| 4 | "file cache clear: configured capacity is preserved" (:1219) | max_files=4; add 4, clear (freed==4 :1231), re-add ids 100..103 all succeed, get_num_entries()==4. Pins that `clear()` does NOT call `XHash::clear_hash()` (comment :466) — `set_max_nodes` capacity survives. |
| 5 | "file cache clear: empty cache stays empty" (:1242) | clear on empty: freed==0, remaining==0. Pin of the null/empty-walk arm :463-480. |
| 6 | "file cache clear: re-add creates a fresh entry" (:1251) | id 42 BLOCK → clear → re-add same key → verdict==UNKNOWN :1263, entries==1. Pins fresh `new FileContext` (file_cache.cc:219) not recycled node data despite XHash node recycling. |
| 7 | "file cache clear: owned copy remains valid" (:1267) | source with name/url/BLOCK; `copy.copy(*source,false)` :1277; after clear, copy keeps name/url/verdict, `get_file_data()==nullptr`. Pins real `FileInfo::copy` (file_lib.h:97, body in file_api.cc) deep-copy vs entry deletion. |

Gate expectation: **7 cases / 42 assertions** (measured; vs filib's 19/334).

## 3. Include closure & per-TU classify vs the filib donor

file_cache.cc includes (verbatim lines): `config.h` :21, `file_cache.h` :24,
`cassert/cinttypes/cstring/limits/vector` :26-31, `control/control.h` :33,
`flow/flow_key.h` :34, `hash/hash_defs.h` :35, `hash/hashes.h` :36,
`hash/xhash.h` :37, `log/messages.h` :38, `managers/inspector_manager.h` :39,
`main/snort_config.h` :40, `main/thread_config.h` :41, `packet_io/active.h` :42,
`packet_io/packet_tracer.h` :43, `pub_sub/file_events.h` :44,
`time/packet_time.h` :45, `file_flows.h` :47, `file_inspect.h` :48,
`file_module.h` :49, `file_stats.h` :50, `catch/snort_catch.h` :1142 (UNIT_TEST).

Diff vs donor: **every include except `hash/xhash.h`, `packet_io/active.h`
and `main/thread_config.h` is already handled in filib** (header copied real,
shimmed, or grafted). `flow/flow_key.h` is safe real (its closure:
`daq_common.h` witness at donor build.sh:118-129, `framework/decode_data.h`,
`hash/hash_key_operations.h` — all already in the donor link).
NEW in this harness: real `hash/xhash.{h,cc}` + `hash/hash_lru_cache.{h,cc}`
closure (proven compiled+linked in `tools/rules_harness/build.sh:58,996`;
`helpers/memcap_allocator.h` is header-only — no .cc exists), real
`time/packet_time.cc` (84 lines, includes only `packet_time.h` +
`time/timersub.h`; `s_recent_packet` is a static THREAD_LOCAL in that TU,
armed via `packet_time_update` at packet_time.cc:69-77), `packet_io/active.h`
(real header; its include chain `protocols/packet_manager.h` → packet.h
works on the donor's flowz-patched packet.h), and `main/thread_config.h`
(needs an hwloc excision — no hwloc headers on host: `/usr/include/hwloc.h`
absent; only `ThreadConfig::get_instance_max()` is used, file_cache.cc:144).

### Classify table (verbatim / witness / graft)

(a) VERBATIM upstream .cc in the link — 19 TUs:

| TU | donor source |
|---|---|
| file_cache.cc (both modes) | target (new; was witness in donor stubs.cc:345-417) |
| file_lib.cc, file_api.cc, file_config.cc, file_identifier.cc, file_stats.cc, file_capture.cc, file_mempool.cc, circular_buffer.cc, file_segment.cc | filib build.sh:33 + objs loop :298 (proven) |
| pub_sub/file_events.cc, helpers/utf.cc | filib build.sh:34,36 |
| hash/hashes.cc, hash/ghash.cc, hash/hash_key_operations.cc, hash/primetable.cc | filib build.sh:35 |
| hash/xhash.cc, hash/hash_lru_cache.cc | NEW here; proven verbatim at tools/rules_harness/build.sh:58,996 |
| time/packet_time.cc | NEW here (see clock section; replaces reliance on donor stubs.cc:99 only if no packet_now ref) |

Real headers lifted verbatim from donor copy list (build.sh:33-60):
`file_cache.h/file_flows.h/file_inspect.h/file_module.h/file_stats.h/file_api.h/
file_config.h/file_capture.h/file_segment.h/file_service.h (witness-only)/
control/control.h, log/{messages,log_errors,log_stats}.h,
managers/inspector_manager.h, hash/*_defs/hashes/ghash/hash_key_operations/
primetable headers, framework/{counts,base_api,inspector,mp_transport,
data_bus,…}.h, main/{snort_types,thread}.h, sfip/*, protocols/* (packet.h
grafted, see below), time/{packet_time.h,clock_defs.h,stopwatch.h},
packet_io/{active.h,active_action.h,packet_tracer.h,packet_constraints.h},
memory/heap_interface.h`, plus `helpers/memcap_allocator.h` (new — xhash.h:30)
and `hash/hash_lru_cache.h` (new).

(b) WITNESS symbol groups — 15 (bodies live in new `stubs.cc`, each prints
WITNESS/ FILEDBG / tagged lines so hits are explicit):

| seam (declared in real header) | donor anchor | fcache use site |
|---|---|---|
| SnortConfig statics/get_conf (header is shim, see grafts) | donor stubs.cc:40-63 | file_cache.cc:563 (`mp_dbus`) |
| log/messages.h ParseError/LogMessage/ErrorMessage/ReloadError/FatalError | donor stubs.cc:101-128 | :148; LogRespond null-conn macro arm (control.h:100) |
| main/thread.h witnesses + THREAD_LOCAL `file_trace` | donor stubs.cc:130-155 | FILE_DEBUG sites via file_trace |
| PacketTracer::is_active/log (TracerMute too) | donor stubs.cc:157-188 | :230-231,:635-637,:649-651,:678-680,:698-700,:715-718,:723-730,:750-752,:785-787 |
| DataBus::publish bodies (header real) | donor stubs.cc:190-224 | file_events publish chain |
| InspectorManager::acquire_file_inspector/get_file_inspector/release | donor stubs.cc:266-292 | :319, :353 |
| Inspector + FileInspect witness bodies | donor stubs.cc:294-342 | FileInspect seam for :319/:353 |
| get_file_config (real body lives in file_inspect.cc monolith) | donor stubs.cc:266-272 seam | :669 |
| FileFlows::get_file_flows/add_pending_file (+context mgmt set carried if needed) | donor stubs.cc:562-585 (`add_pending_file` body :577-580) | :737-741 |
| FileService statics (incl. `FileService::file_cache`) + method witnesses | donor stubs.cc:419-455 | link-time (statics), not called by file_cache.cc |
| Active::set_delayed_action / set_drop_reason | NEW body; header real incl. packet_io/active_action.h | :640-641,:654-655,:734,:749,:757 |
| ThreadConfig::get_instance_max | NEW (header graft below) | :144 |
| MPDataBus::get_id / publish (mini decl+body pair) | NEW (include excised, see grafts) | :570-571 |
| ControlConn::respond (needed by inlined LogRespond macro at link time) | NEW (real body is control monolith) | :1052-1070,:1109-1132 (dump sites; gate path passes null → LogMessage) |
| DetectionEngine::set_next_packet/get_current_packet/queue_event | donor stubs.cc:596-622 (`GET_CURRENT_PACKET` = DetectionEngine::get_current_packet per file_module.h:42) | :241,:257,:573,:586,:595 context |

(c) GRAFTS — 10 (header surgery, each justified):

1. `flowz/flow_fwd.h` (donor build.sh:136-157) **extended**: `make_key`
   (file_cache.cc:363-372) needs `Flow::client_ip/server_ip`
   (real flow/flow.h:523-524), `client_group/server_group` (flow.h:583-584),
   `const FlowKey* key` (flow.h:503) with REAL `FlowKey::addressSpaceId`
   (flow/flow_key.h:56 — flow_key.h itself compiles real). Note truncation
   semantics: `hashKey.asid` is `uint16_t` (file_cache.h:47) assigned from
   `uint32_t addressSpaceId` (:371) — must be pinned, not "fixed".
2. `protocols/packet.h` sed `flow/flow.h`→`flowz/flow_fwd.h` — donor build.sh:157.
3. `file_flows.h` sed include → `flowz/flow_fwd.h` + `flowz/flow_data.h` — donor build.sh:159-162.
4. `main/snort_config.h` EOFCFG shim (extracted from rules_harness build.sh, donor build.sh:92-115) — already carries `mp_dbus=false` member (:111) for :563.
5. `main/thread_config.h` graft: excise `#include <hwloc.h>` (thread_config.h:22; header absent on host) and the HAVE_NUMA arm; keep decls, witness get_instance_max.
6. `daq_common.h` witness header — donor build.sh:118-129 (flow_key.h:28).
7. `trace/trace.h` + `trace/trace_api.h` witnesses (FILE_DEBUG → trace_logf chain, prints FILEDBG-tagged format strings under `file_trace`) — donor build.sh:219-286; file_module.h maps FILE_DEBUG verbatim (:42 GET_CURRENT_PACKET too).
8. `detection/detection_engine.h` witness header — donor build.sh:180-217.
9. `catch/snort_catch.h` shim + vendored `catch/catch.hpp` — donor build.sh:61-65 (gate mode).
10. pub_sub mp_data_bus excision: `sed -i '/#include "framework\/mp_data_bus.h"/d'` on `pub_sub/file_events.h` + `file_events_ids.h` — donor build.sh:164-178 — plus the NEW MPDataBus mini witness decl. (Donor also `private:`→`public:` grafts `file_cache.h/file_service.h/file_flows.h` at build.sh:69-77; carried for the probe's dump/walk seams, then RETIRE the FileCache witness bodies per NEXT.md:83-85 — file_cache.cc is now real, so the donor's `FileCache::*` witness block stubs.cc:345-417 must NOT link here; it would collide with the real TU.)
NOT needed here: policy.h graft (file_cache.cc pulls no policy).

## 4. xhash-member verdict (NEXT.md:77 check)

**file_cache.h does NOT embed a by-value HashTable.** The only hash member is
line **file_cache.h:108**: `ExpectedFileCache* fileHash = nullptr;` (forward
decl :37). The XHash base is embedded by inheritance one TU over: **file_cache.cc:56**
`class ExpectedFileCache : public XHash` (ctor :59-61 → `XHash(rows,key_len,
datasize,0)`; dtor :63-66 `delete_hash_table()`). So the xhash closure
(hash/xhash.{h,cc}, hash/hash_lru_cache.{h,cc}, helpers/memcap_allocator.h
header-only, utils/util.h dead-branch seeds) must be REAL in this harness —
it is already compiled verbatim in `tools/rules_harness/build.sh:58,996` and
is already ported in Rust: `src/hash/xhash.rs`, `src/hash/hash_lru_cache.rs`,
`src/hash/hash_defs.rs`, `src/hash/hash_key_operations.rs` (KNOWN DEVIATIONS.md
§"hash cache layer (memcap_allocator, hash_lru_cache, xhash, zhash)" line ~282).

## 5. Danger spots (exact cites in file_cache.cc)

1. **Pending-expire clock** — `packet_gettimeofday(&now)` in the PENDING arm
   :663; timeout test `timercmp(&file_ctx->pending_expire_time, &now, <)`
   :665-666; `block_timeout_lookup` arm :673-684; `set_timedout()` +
   `file_counts.file_lookup_timeouts++` :686-687; `time_elapsed_ms` calls
   :696,:700,:725,:730 (helper :110-116 → `timersub_ms` packet_time.h:31);
   arm sets `pending_expire_time = now + cur_lookup_timeout` :707-710. Also
   cache-expiry clocks: `find_add` :179-194, `find` :282-296, `add` :209-212,
   and XHash ANR hook `is_node_recovery_ok` :77-81. Clock pinning: compile
   **real time/packet_time.cc** and arm the THREAD_LOCAL `s_recent_packet`
   ONLY via `packet_time_update()` (packet_time.cc:70; it only moves time
   forward via `timercmp(<)` — deterministic); the donor's interposed
   `clock_gettime` fake clock (stubs.cc:77-98, `filib_set_fake_now`) is
   orthogonal (SnortClock) and is kept for anything SnortClock-derived but
   file_cache itself is packet-time-driven. THREAD_LOCAL `file_counts`
   (file_stats.h:85) defined by real file_stats.cc:45 — arm `file_stats_init()`
   before any count bump or rc 139 (NEXT.md:57).
2. **FileInfo*/FileContext ref counting across add()/delete** — `add` creates
   `new FileContext` :219 and on insert failure `delete new_node.file` :244;
   `release_node` without ownership for expired/in-use nodes :174,:184,:286;
   `find_and_pin` pins :348 and `CacheNodePin` unpins under cache_mutex
   :99-103; expiry skips release while `is_in_use()` :183,:285 (file_lib.h:197-201,
   `in_use` :239) and :74 (ANR); `free_user_data` unconditionally
   `delete node->file` :90 — clear() frees even a pinned entry (dangling-by-
   design under the paused-threads precondition, file_cache.h:85-87);
   `cached_verdict_lookup` :820 nests CacheNodePin then re-takes cache_mutex
   :840 (recursive lock discipline). Slice-assigns `*((FileInfo*)node) = *src`
   :438,:527 + `set_file_data` transfer/null ownership dance :426-430,:445-454,
   :490-495 — the ref/ownership seams the vectors must pin.
3. **Segment-queue ownership in entries** — the queue hangs off the entry's
   FileContext (file_cache.h:59 node->file; file_lib.h:207/:233), freed only
   through `release_node`→`free_user_data`→`~FileContext` (file_cache.cc:90);
   `clear()` :467-477 walks `find_first_node`/`find_next_node` and takes the
   NEXT node before releasing the current one (:472 comment) — iterator-
   invalidation shape must be preserved; gate case 3 (:1201-1217) and case 4
   (:1219-1240) pin the free-with-segments and capacity-non-reset behavior.
4. **file_id == 0 gate in cached_verdict_lookup** — early return UNKNOWN with
   TRACE_ERROR FILE_DEBUG at file_cache.cc:808-813; same gate in store_verdict
   :584-589 and resume_pending_verdict :859-864. The donor FileCache witness
   mirrors it at stubs.cc:373-377 ("CACHE lookup no-id -> 0") — with the real
   TU linking, that WITNESS line disappears from transcripts; only the
   `FILEDBG … File id not found, returning` trace line survives (armed via
   `filib_set_file_trace`, donor stubs.cc:149-155).

## 6. Two-mode build (planned, not yet built)

- **Gate**: `g++ -DUNIT_TEST -c copy/file_api/file_cache.cc` (block :1140-1287
  live; `catch/snort_catch.h`→vendored catch.hpp graft) + `catch_main.cc`
  (donor build.sh:316-325 recipe) over the SAME link closure as the probe.
  Expect: `7 test cases / 36 assertions` (measured assertion tally §2).
- **Probe**: file_cache.cc with the UNIT_TEST block INERT (compiled without
  -DUNIT_TEST — donor jsnorm shape, build.sh:295-305) + probe.cc driving:
  add/find/clear capacity churn, pin/unpin lifetimes across release, PENDING
  expiry ladder via `packet_time_update` steps, cached_verdict_lookup with
  file_id 0 vs n, store/dup/take_pending file_data ownership transfers,
  dump_cache/dump_cache_entry with null ControlConn (LogMessage witness) —
  every WITNESS seam prints, FILEDBG lines pin the format strings.
- Build mechanics: `GXX="g++ -std=c++17 -O0 -w -I$C -I$NODE_INC"`;
  link `$LIBCRYPTO -lpthread` (hash chains, donor recipe); objs loop extended
  from donor build.sh:298 with `xhash hash_lru_cache packet_time`.
- Retire rule (NEXT.md:83-85): do NOT carry donor stubs.cc:345-417
  (`FileCache::*` witnesses) into fcache stubs — the real TU defines those
  symbols; carry the FileService statics block (stubs.cc:429 `file_cache`
  pointer) minus the retired witness methods only if probe needs them.
  filib's committed vectors.txt (md5 77ffd8e4…) is NOT touched.

## 7. Top risks

1. Two clocks: packet_time (THREAD_LOCAL s_recent_packet in real
   packet_time.cc) vs interposed clock_gettime fake clock — unarched
   s_recent_packet = {0,0} makes time_elapsed_ms degenerate to 0 (:112-113);
   probes must arm via   packet_time_update and never call it with a backstep
   (it clamps, packet_time.cc:69-77).
2. XHash node recycling vs "re-add creates a fresh entry" (:1251) — depends
   on free_user_data (:90) + fresh `new FileContext` (:219); Rust Rc/RefCell
   port will need an explicit deviation entry.
3. clear() force-frees pinned entries (free_user_data unconditional :90) —
   dangling-pointer semantics are UPSTREAM behavior; Rust port must model
   the pause-precondition, document in KNOWN DEVIATIONS.
4. flowz/flow_fwd.h extension touches every shared header (packet.h chain);
   any drift from the donor copy forks filib-pinned packet semantics.
5. `uint32_t addressSpaceId` → `uint16_t asid` truncation in make_key (:371,
   file_cache.h:47) — pin, don't "fix".
6. THREAD_LOCAL `file_counts` must be armed (file_stats.cc:45) or file bump
   sites :233/237/243/248/250/687 crash (rc 139, NEXT.md:57).
7. Retired-donor collision: if any donor FileCache witness body sneaks into
   link, duplicate-symbol or, worse, silent witness shadowing on 17o paths.
8. `*((FileInfo*)node) = *src` shallow copy + file_data handoff (:438,
   :426-430, :445-454) is the double-free hazard for the Rust port; vectors
   must cover both same-node (`same` :413) and cross-file (sha compare :419)
   arms.
