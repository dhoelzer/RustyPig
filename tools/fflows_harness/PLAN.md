# fflows_harness PLAN — row 17q: file_api/file_flows.{h,cc} + the light FileContext half

Phase: RECON (this file is the only artifact). Donor: `tools/fcache_harness`
(row 17p — the proven file_api closure donor). Upstream ground truth:
`/opt/data/snort3-src` @ `fe29cbe` (READ-ONLY). Every claim below was
measured against the real files this session; two claims are pinned by an
empirical compile + `nm` in a scratch copy tree (`/opt/data/cache/scratch/ff2`).

## 1. Target measurements

| file | lines | note |
|---|---|---|
| `src/file_api/file_flows.cc` | 775 | includes :26-48; `#ifdef UNIT_TEST` catch include :50-52; UNIT_TEST block **:587-775**; `file_flow_data_id` static :56; `static THREAD_LOCAL uint32_t max_file_id` :57 |
| `src/file_api/file_flows.h` | 154 | `FILE_ID_GID = 150` :35; `FileSid` enum :37-42 (`EVENT__NONE=-1`, `EVENT_FILE_DROPPED_OVER_LIMIT=1`); `FileEventGen = EventGen<EVENT__MAX_VALUE, EVENT__NONE, FILE_ID_GID>` :44; `friend struct FFTestAccessor` :130-132 under `#ifdef UNIT_TEST` |

Method map (file_flows.cc, grep-measured): `get_file_position` (anon-ns) :61,
`populate_trace_data` :79, `handle_retransmit` :100, `get_file_flows` :139,
`get_file_policy(Flow*)` :157, `set_current_file_context` :167,
`swap_..._no_delete` :180, `restore_..._no_delete` :189,
`get_current_file_context` :195, `get_new_file_instance` :205,
`~FileFlows` :211, `find_main_file_context` :242,
`get_partially_processed_context` :270, `get_file_context` :278,
`retire_victim` :349, `remove_processed_file_context` :367,
`file_process` (multi) :388, `file_process` (single) :499,
`set_file_name` :542, `add_pending_file` :578.

## 2. TEST_CASE inventory (UNIT_TEST block :587-775)

Block ships its OWN scaffolding — NO private->public graft needed for the gate:
- `class FF_TEST_CONTEXT : public FileContext { set_file_id(id); }` :592-597
- `struct FFTestAccessor` :598-605 (reaches `partially_processed_contexts`,
  `current_context`, `current_file_id`, `deferred_delete_context`,
  `main_context` via the friend hook file_flows.h:130-132)

8 TEST_CASEs / grep-tally **22** CHECK invocations (runner will re-measure —
17p lesson: grep undercounts/overcounts, the runner is truth):
1. `retire defers delete, dtor drains it` :608 `[file_flows][lifecycle]`
2. `retire then set drops deferred via retire_victim` :622 `[lifecycle]`
3. `CSCwt96192 regression: retire non-current then set other` :645 `[lifecycle]`
4. `ISS-1 regression: caller deref after remove is safe` :672 `[lifecycle]`
5. `nested retire drains prior via retire_victim` :686 `[lifecycle]`
6. `dtor drains main + partially_processed_contexts + deferred (original crash shape)` :707 `[lifecycle]`
7. `swap/restore preserves both current_context and current_file_id` :727 `[file_flows][swap]`
8. `swap/restore does not engage deferred-delete` :755 `[swap]`

Gate requirements measured: `new FF_TEST_CONTEXT(id)` runs the REAL
`FileContext` ctor (file_lib.cc:559 — `SnortClock::now()` + the
InspectorManager::acquire witness, both already in the donor link);
`delete ff` runs REAL `~FileFlows` (:211) -> `retire_victim` (:349) ->
`delete` -> REAL `~FileContext` (file_lib.cc:574, null-gated
EVP_MD_CTX_free / stop_file_capture / delete file_segments / release).
All real, all already linked by the donor. Gate printfs (IMGR/POLICY/DE
witness lines) land in gate.txt like fcache's did.

## 3. Include closure verdict — MEASURED, not asserted

Probe performed: donor `copy/` tree + pristine `file_flows.cc` added;
`g++ -std=c++17 -fsyntax-only` run plain AND `-DUNIT_TEST`. Both compile
CLEAN after exactly ONE graft delta:

- **Graft delta (only one):** the `flowz/flow_fwd.h` witness `Flow` gains
  `FlowData* get_flow_data(unsigned)` / `set_flow_data(FlowData*)`
  (real flow.h:195/:200) — needed by file_flows.cc:141/:149/:159. Recommend a
  deterministic single-slot arm (store fd; get returns it iff id == id param)
  so `get_file_flows` and the `get_file_processed_size` witness chain work
  against real flow (deviation-documented witness FlowData store).

Everything else was ALREADY handled by the donor (NEXT.md's closure claim
CONFIRMED): `catch/snort_catch.h` vendored (build.sh:90-96);
`helpers/event_gen.h` copied (build.sh:39) and needs only
`DetectionEngine::queue_event` (witness stubs.cc:606 — prints
`DE queue_event gid=%u sid=%u`; FileEventGen pins gid=150, sid=1, and the
bitset suppression :48 means the EventGen fires ONCE per instance — pin that);
`main/thread.h get_instance_id` witness stubs.cc:170; `file_trace`
THREAD_LOCAL defined stubs.cc:177 + `fcache_set_file_trace`;
`file_counts` real via file_stats.cc + `file_stats_init()` (probe.cc:136 rc-139
rule); `detection_engine.h` witness (:220) has `get_current_packet` +
`set_next_packet` + `queue_event` and `GET_CURRENT_PACKET` expands via
file_module.h:42 in the copy tree; `FILE_DEBUG` gate witness trace_api.h
(:292); PolicyMap graft + `main/policy.h` copied; FIXACC private->public
pass on file_service.h/file_cache.h/file_flows.h (build.sh:202) — keep it
(probe touches seams; friend decl stays harmless once privates vanish).

`#include <thread>` (file_flows.cc:48) — links fine (fcache_gate already
links -lpthread).

### Link-symbol verdict (nm -u on the real file_flows.o, app-level)
Supplied REAL by existing TUs: all FileContext/FileInfo/FilePolicyBase/
FileConfig/file_type_name (file_lib.o + file_config.o), FileCache::{get_file,
dup_cache_context, cached_verdict_lookup, cached_context_not_cacheable,
resume_pending_verdict} (file_cache.o), FlowData ctor/dtor (stubs witnesses
:575-583 — KEEP; the inline FileFlows ctor file_flows.h:57 uses it).
Supplied by existing witnesses: FileService::{get_file_cache,
is_file_service_enabled, get_max_file_depth} (stubs :413-439), DetectionEngine,
PacketTracer::{is_active,is_daq_activated,log,daq_log} (:197-212).

NEW witnesses required (measured undefined in the donor link — file_service.cc
is NOT linked; these must be added, ~10 lines each):
1. `snort::get_network_policy()` + `NetworkPolicy::get_base_file_policy() const`
   (policy.h:91/:196; call site file_flows.cc:150) -> hand back the heap
   `StubFilePolicy` singleton (stubs.cc:296-313) — mind the ref-count
   protocol at set_file_policy (file_flows.h:120-126: delete old, add_ref new;
   stubs.cc:310 static-object assert comment applies).
2. `snort::get_file_processed_size(Flow*)` (file_api.h:219; REAL body
   file_service.cc:256-268 = get_file_flows -> get_current_file_context ->
   get_processed_bytes) — witness body copied literally; works once the
   single-slot FlowData graft arms the Flow.
3. `PacketTracer::get_time()` (used via populate_trace_data format arg
   file_flows.cc:87) + `restart_timer()` (:427/:520) — witness pinned to the
   packet clock or a constant.
4. CHANGE donor hardwire `is_daq_activated() -> false` (stubs.cc:198) to an
   armed flag, else `populate_trace_data` never runs and its
   `daq_log("file+%" PRId64 "+Matched policy id %u...")` format ladder
   (file_flows.cc:82-95) — a main pin target — never fires.
5. CHANGE donor `get_instance_id() -> 0` (stubs.cc:170) to an armable
   witness (file-static) to pin `(id<<32)|max_file_id++` at
   file_flows.cc:205-209 (THREAD_LOCAL max_file_id :57 stays real).

## 4. Witness-retire list (NEW link only — fcache's committed vectors UNTOUCHED)

Retire the whole donor FileFlows witness block, fcache_harness
`stubs.cc:442-573` (17o->17p retirement precedent):
`file_flow_data_id` def :448, `get_file_flows` :450, `get_file_policy` :459,
`handle_retransmit` :464, `get_current_file_context` :465,
`set_current_file_context` :476, `swap/restore` :482/:491,
`get_file_context` :497, `get_partially_processed_context` :516,
`remove_processed_file_context` :521, `get_new_file_instance` :531,
`~FileFlows` :532, `set_file_name` :544, `file_process` x2 :546/:548,
`init_file_context` :551, `find_main_file_context` :553, `retire_victim` :555,
`add_pending_file` :568. The real TU defines them all. Note
`init_file_context` (file_flows.h:133) is a DEAD declaration upstream —
grep shows no definition anywhere in snort3-src; retiring its stub links fine.
KEEP: FlowData witnesses :575-583, StubFilePolicy :296-316 (real
FilePolicyBase ref-count protocol exercised via set_file_policy/dtor),
FileService witnesses (file_service.cc stays a witness TU — its proper row is
backlog), clock interpose, file_trace/file_counts arming, IMGR witnesses.

## 5. Gate recipe (two-mode, donor shape)

- copy the whole fcache build.sh; add `file_flows.cc` to the copy set; apply
  the one flow_fwd graft delta (get/set_flow_data single-slot).
- probe link: `probe.o stubs.o file_flows.o file_cache.o file_lib.o
  ${objs[@]}` (file_cache.cpp.o stays REAL — retire rule).
- gate: `catch_main.cc` + `g++ -DUNIT_TEST -c copy/file_api/file_flows.cc`
  -> `gate` link same closure. Expect `8 test cases` and a MEASURED assertion
  count (grep says 22; do not hardcode — pin from the runner per 17p).
- vectors.txt+gate.txt md5 stable across >=2 clean rebuilds; `.gitignore`
  block mirroring fcache; `git check-ignore` BEFORE staging; grep-guard
  (count 0) before plan-row insert.
- probe must call `file_stats_init()` (rc 139) and arm fake clock +
  `fcache_set_file_cache` (get_file_context asserts at file_flows.cc:294 —
  unarm'd FileService::file_cache = crash, never a miss).

## 6. Danger spots / pin targets (exact cites, file_flows.cc)

- Retire/deferred-delete ALIASING matrix IS the semantics:
  `set_current_file_context` skips victim when victim==ctx (:167-178);
  `retire_victim` nulls current AND deferred slots only (:349-362, NOT ppc);
  `remove_processed_file_context` erase->park sequence (:367-386) with the
  cache_dup_count decrement (:371-372, gated on is_limit_excluded —
  set only via dup_cache path :308-310); `~FileFlows` ownership walk
  aliases-null-first + ppc move-out (:211-239).
- `get_current_file_context` file-id ladder: `current_file_id != 0` routes
  through get_file_context(...,to_create=false) (:195-202).
- `get_new_file_instance` = `(get_instance_id()<<32) | max_file_id++`
  (:205-209) — instance arm must be nonzero at least once.
- `get_file_position` ladder (FULL/START/END via PKT_PDU_TAIL/MIDDLE via
  get_file_processed_size) :61-76.
- over-limit event arm: `new_context_count == fc->max_files_per_flow` ->
  `file_counts.files_over_flow_limit_not_processed++` +
  `events.create_event(EVENT_FILE_DROPPED_OVER_LIMIT)` (:325-330; default
  cap 128 file_config.h:40/66 — shrink via get_harness_file_config stubs.cc:404
  to reach the arm in ~3 adds); EventGen bitset suppresses the 2nd fire
  (:48 event_gen.h) — pin once-only.
- `handle_retransmit` (:100-138): null-file_policy return, cache vs
  no-cache arms (`FileService::get_file_cache()` null -> policy->
  signature_lookup + log_file_event), pending_resolution reset (:127/:135).
- `populate_trace_data` via armed daq flags the on/off triads
  (:88-91) + VerdictName[file_lib.h:38] + file_type_name — needs witness
  PacketTracer::get_time.
- printf hygiene: hoist mutating calls into locals (fid/codec lesson).

## 7. FileContext member half — scope (file_lib.cc:559-1362, 25 definitions measured)

Already REAL in the donor link (physically available; 17p's Rust seam in
`src/file_api/file_cache.rs:541-660` carries the cache-reachable subset:
`FileContext` struct :541, Drop :561, stop_file_capture :635, log_file_event
FORWARDER seam :645 explicitly left "body row 17q"). file_lib.h members list
:150-252.

LIGHT half (no detection/EVP/print closure — 17q Rust scope): ctor :559 /
dtor :574 (seam edges 17p pins), finalize_file_type :589, get_mime_type :596,
set_source :608, log_file_event :613-683 (the FileCacheEventSink seam),
set_signature_state :744, check_policy :760-765 (file_counts.files_total++ +
virtual policy_check -> StubFilePolicy witness prints), remove_segments :801,
FileContext::reset :810-823, update_file_size :1207, stop_file_capture x2
:1189/:1195 (already partly in Rust seam).

HEAVY half (drags detection fp_eval / live EVP / print/iconv — 17r scope):
process(position) :825-985 (Profile + trace_stream + cached_verdict_lookup +
type/sig ladder + file_stats->files_processed), process(offset) :986-992
(lazy `new FileSegments` — REAL TU already linked fcache),
find_file_type_from_ips :1004-1055 + process_file_type :1057 (the
swap/restore NO-DELETE contract at :1041-1047/:1056-1062 — THIS is who
consumes FileFlows swap/restore; witness fp_eval_service_group exists
stubs.cc:627), file_signature_lookup :686 + finish_signature_lookup :701-743,
process_file_signature_sha256 :1065-1167 (live EVP ladder via libcrypto.so.3
+ node headers — proven recipe 17o/17p), process_file_capture :1169-1187
(FileCapture witness TU — file_capture.cc not linked), get_UTF8_fname :85-112
(iconv arm; helpers/utf.cc REAL incl. convert_character_encoding :355),
print_file_data :1224, print_file_sha256 :1280, print_file_name :1301,
print :1346.

## 8. Measured 17q/17r split recommendation

The natural cut is the three `context->process(...)` call sites at
file_flows.cc:473, :486, :531 — everything above them is FileFlows + light
FileContext; everything below drags the FileSegments/detection/EVP/print
ladder.

- **17q (this row):** `file_flows.{h,cc}` VERBATIM (C++ 929 lines) + the
  LIGHT FileContext half (25 defs of which ~12 light, ~150 C++ LOC) +
  NEW `src/file_api/file_flows.rs` (est. 600-900 Rust lines: retire/defer
  aliasing matrix, the swap/restore pair as plain struct moves — the Rust
  port can own this with Box/Rc cleanly) + light FileContext methods onto
  the file_cache.rs:541 struct (check_policy, reset, set_signature_state,
  set_source, get_mime_type, update_file_size, log_file_event BODY through
  the already-installed FileCacheEventSink seam) + the flow_fwd single-slot
  graft + the 5 new/changed witnesses (:3 list). Probe blocks A-E: A
  lifecycle matrix beyond the gate (main/ppc/current/deferred slots crossed,
  get_file_context ppc-hit vs cache-hit vs create, dup_cache_context +
  limit_excluded cache_dup_count decrement); B get_new_file_instance
  bit-ladder; C get_file_position + get_current_file_context id-ladder;
  D over-limit event (shrunk cap: counter + single queue_event(150,1) +
  EventGen suppression); E set_file_name/file_process early-return arms
  (service-disabled :505, position-unknown :512, depth :401) +
  handle_retransmit arms WITHOUT crossing into context->process.
- **17r:** HEAVY half — process x2 + FileSegments segment-queue ladder (the
  real file_segment/circular_buffer/file_mempool TUs are linked today;
  their 3 `[file_mempool]` gate cases at file_mempool.cc:231-303 ride free),
  find_file_type_from_ips/process_file_type (fp_eval witness + the
  swap-restore contract from the FileContext side), the EVP sha256 ladder,
  process_file_capture, file_sig lookup pair, get_UTF8_fname, print x4.
  Estimated comparable size (~700 C++ LOC incl. FileSegments :241-261
  interplay). FileService-proper / file_capture / file_log stay backlog.

Rationale (measured): the 17q probe can reach EVERY light member through
real FileFlows bodies without any process-ladder pin, and the gate block
itself needs zero heavy members (FF_TEST_CONTEXT only touches ctor +
set_file_id). Splitting at the process boundary keeps each row's witness
surface honest: 17q retires 19 FileFlows witnesses; 17r retires none in a
NEW harness (it reuses this one with process-ladder probes) — or lands the
mempool/circular_buffer gate as its free rider.

## 9. Session-ritual reminders for the build phase

md5 stability x2 clean rebuilds; `cargo test` >= 397 zero FAILED + clippy 0;
parity test `tests/fflows_parity_test.rs` (include_str! donor pattern
tests/fcache_parity_test.rs); plan-row grep-guard then insert; deviations
append; NEXT.md refresh; wiki trio.
