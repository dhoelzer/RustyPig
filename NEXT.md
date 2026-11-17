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
- Gates at EVERY commit: `cargo test` all green (currently **384
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
  `packet_io/active_action.h` + `control.h`): document every graft in
  `KNOWN DEVIATIONS.md`. The rules_harness `build.sh` is the
  proven-recipe donor; `catch/snort_catch.h` -> plain-catch shim
  (codec/jsnorm/fid recipe).

## State
- HEAD = origin/master = `8e09fdd` (docs for row 17n; milestone
  `ee6999e`). Working tree clean. Wiki HEAD `911b3e8` at
  https://github.com/dhoelzer/RustyPig/wiki — update it at every
  milestone (clone `/tmp/RustyPig.wiki`; edit via kernel Python —
  `patch` can't write outside `/opt/data`; `git -C DIR subcmd`).
- `PORTING_PLAN.md` rows 1–17n DONE; `KNOWN DEVIATIONS.md` current.
- LuaJIT 2.1 built at `/opt/data/tools/luajit-src` (chunk row 17k).
- OpenSSL unblocked WITHOUT a dev package (apt is locked, no root):
  compile with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node`
  and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly —
  smoke-tested, real SHA256("abc") verified.

## Next milestone — row 17o: `file_api/file_lib.{h,cc}` (FileInfo)
Measured: `file_lib.cc` 1624 lines, 19 TEST_CASEs, ALL in an embedded
`UNIT_TEST` block (serialize/deserialize, set_url/set_file_name/
set_host cap oversized strings, deserialize peer-input hardening,
get_serialized_size) — the tests exercise FileInfo near-standalone.
- Gate: `-DUNIT_TEST` compile of the TU (jsnorm/fid recipe).
- Includes to tame (see file_lib.cc:27-67): openssl -> node-header
  recipe above (link libcrypto.so.3; or witness EVP/SHA only if the
  tested paths avoid it); `detection/fp_detect.h`,
  `framework/data_bus.h`, `managers/inspector_manager.h`,
  `packet_io/packet_tracer.h`, `profiler/profiler.h`,
  `pub_sub/*`, `time/packet_time.h`, file_{cache,config,flows,
  inspect,module,segment,service,stats}.h — most are declaration
  seams (witness/graft patterns from fstats build.sh, which already
  compiles file_api's header closure). `hash/hashes.h` + `helpers/
  utf.h` real (already ported in Rust: sha/md5, utf8).
- Rust: `src/file_api/file_lib.rs` — FileInfo fields, serializer,
  size accounting, cap/trim quirk table; `file_lib.h` FileInfo
  statics (file_type_name etc.) stay as seams where C's live in
  file_config.cc.

## Alternative quick win if file_lib bloats
`main/thread_config.cc` (920 lines, 14+2 embedded test markers, tiny
include closure: analyzer_command.h shim + messages + snort_config
shim + real time/periodic (ported) + util; body needs hwloc at link —
witness hwloc_topology_*/bitmap_* or check HAVE_NUMA-gated paths;
`NumaWrapper`/`HwlocWrapper` live in main/numa which is ported).

## Backlog (plan rows)
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
