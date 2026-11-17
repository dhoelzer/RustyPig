# NEXT.md — resume point (2026-11-17)

## Ground rules (unchanged)
- Ground truth: `/opt/data/snort3-src` @ `fe29cbe7403a`. Port repo:
  `/opt/data/snort3-rust`, branch `master`, remote
  `github.com/dhoelzer/RustyPig`.
- Method per milestone: C++ harness under `tools/<name>_harness/`
  compiling the ORIGINAL sources (VERBATIM where reachable) emitting
  a deterministic labeled `vectors.txt`; Rust port as literal
  transcription; whole-transcript replay test in `tests/`; build a
  Catch gate whenever upstream ships embedded `UNIT_TEST`/
  `CATCH_TEST_BUILD` blocks or a `test/` suite — compile it verbatim.
  The harness transcript is truth; never fabricate behavior.
- Gates at EVERY commit: `cargo test` all green (currently **389
  passed / 0 failed**), `cargo clippy --all-targets` **0 warnings**.
  Commit + push at every milestone. Push recipe:
  `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`
  (token = LAST `GITHUB_TOKEN` line in `/opt/data/.env`; NEVER echo it).
- Determinism first: fixed seeds/ids/order; never lock a
  nondeterministic transcript. Probe printf arg evaluation order
  bites — hoist mutating calls before printf (see codec H-block,
  fid T2/T3 fixes).
- New harness `.gitignore` block mirrors siblings
  (`copy/`, `probe`, `gate`, `gate.txt`, `catch_main.cc`, `*.o`,
  `*.log`, `probe_dbg`/`probe_asan` if any) — verify with
  `git check-ignore` BEFORE staging.
- Header grafts (private→public, shim includes like
  `framework/detection_engine_wit.h`, `data_bus_wit.h`, the
  rules_harness `snort_config.h` EOFCFG shim + `policy.h` graft +
  `packet_io/active_action.h` + `control.h`, `flowz/flow_fwd.h`):
  document every graft in `KNOWN DEVIATIONS.md`. The rules_harness
  `build.sh` is the proven-recipe donor; `catch/snort_catch.h` ->
  plain-catch shim (codec/jsnorm/fid recipe).

## State
- HEAD = origin/master = row-17o docs commit (milestone `dd8efc2`:
  `file_api/file_lib` FileInfo port + `tools/filib_harness`). Working
  tree clean. Wiki HEAD `911b3e8` at
  https://github.com/dhoelzer/RustyPig/wiki — update it at every
  milestone (clone `/tmp/RustyPig.wiki`; edit via kernel Python —
  `patch` can't write outside `/opt/data`; `git -C DIR subcmd`).
- `PORTING_PLAN.md` rows 1–17o DONE; `KNOWN DEVIATIONS.md` current.
- LuaJIT 2.1 built at `/opt/data/tools/luajit-src` (chunk row 17k).
- OpenSSL unblocked WITHOUT a dev package (apt is locked, no root):
  compile with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node`
  and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly —
  smoke-tested, real SHA256("abc") verified (used for real in 17o).
- `tools/filib_harness` is now the DONOR for everything file_api's
  FileContext half touches: its stubs.cc witnesses (FileCache,
  FileService, FileFlows, FileInspect ctor, InspectorManager,
  DetectionEngine, PacketTracer, trace, DataBus publish, fake clock),
  the `flowz/flow_fwd.h` graft, the profiler TU pair, and the
  verbatim capture-closure link list (file_capture/file_mempool/
  circular_buffer compile near-verbatim there already).
  vectors.txt md5 77ffd8e458ef15de68f9c53d24a1a1c8 (273 lines, stable
  x2 clean rebuilds); gate 19 cases / 334 assertions.

## Next milestone — row 17p: `file_api/file_cache.{h,cc}`
Measured: `file_cache.cc` 1287 lines + `file_cache.h` 115; SEVEN
embedded TEST_CASEs in an `#ifdef UNIT_TEST` block from line 1140
("[file_cache]" — clear/ownership/capacity/re-add semantics).
- Gate: `-DUNIT_TEST` verbatim compile (plain-catch shim) — the
  seventh sibling gate recipe, unchanged.
- Includes (file_cache.cc:21-50): control/control.h, flow/flow_key.h,
  hash/{hash_defs,hashes,xhash}.h (ported / cheap), log/messages.h,
  managers/inspector_manager.h, main/snort_config.h,
  main/thread_config.h, packet_io/{active,packet_tracer}.h,
  pub_sub/file_events.h, time/packet_time.h, file_{flows,inspect,
  module,stats}.h — every one is ALREADY a proven witness/graft in
  `tools/filib_harness/build.sh` + `stubs.cc`; lift that closure.
  Real xhash/GHash closure from fid_h donor if the cache uses
  HashTable directly (check file_cache.h member).
- Watch: THREAD_LOCAL `cache` instance handling, pending-expire clock
  (reuse the filib fake clock), FileInfo* ref counts (add_entry/
  delete_entry pinning), segment-queue ownership in entries, and the
  `file_id == 0` cached_verdict_lookup gate the filib witness already
  mirrors.
- Rust: `src/file_api/file_cache.rs` — literal entry/eviction/verdict
  transcription; retire the filib FileCache witness only AFTER this
  row lands (its vectors pin current witness behavior in the G-blocks;
  if ported semantics fork from the witness, fix THIS row's harness
  forward, do not silently rewrite 17o's transcript).

## Alternative quick win if file_cache bloats
`main/thread_config.cc` (920 lines, 14 TEST_CASEs, tiny include
closure: analyzer_command.h shim + messages + snort_config shim +
real time/periodic (ported) + util; body needs hwloc at link —
witness hwloc_topology_*/bitmap_* or check HAVE_NUMA-gated paths;
`NumaWrapper`/`HwlocWrapper` live in main/numa which is ported).

## Backlog (plan rows)
- 17q+: FileContext proper (file_lib.cc second half) — the G-blocks
  in filib vectors.txt already pin its paths; port after cache +
  capture + service + flows rows land.
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified: NO
  upstream TEST_CASEs anywhere in `codecs/` tree; transcripts are the
  only ground truth there.
- 19: detection option engines (~30k+ subset), 20: packet_io/DAQ
  (AF_PACKET via libc), 21: `snort -q -c` end-to-end parity.

## Session ritual
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors md5 stable x2.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` +
   clippy 0 -> add `.gitignore` block -> commit+push -> insert plan
   row N+1 + deviations (ONE grep-guard per append; the numa
   double-append incident cost a force-push) -> wiki (status row +
   deviations + stats refresh) -> push wiki.
