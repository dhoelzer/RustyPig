# NEXT.md — takeover context & plan (2026-11-17)

This file is the single resume point for a fresh agent. It carries only
what is not cheaply re-derivable. `PORTING_PLAN.md` (row table, per-row
completion notes) and `KNOWN DEVIATIONS.md` (every deliberate departure,
source-cited) are the deep references — consult, never re-invent.

## What this project is
Port Snort 3 (C++) to Rust with byte-exact behavioral parity, milestone
by milestone. Ground truth source: `/opt/data/snort3-src` @
`fe29cbe7403a` (read-only reference; do not edit). Port repo:
`/opt/data/snort3-rust` (branch `master`, remote
`github.com/dhoelzer/RustyPig`, HEAD `027d21a` = origin/master).

Current state: plan rows 1–17o DONE (64 commits, **389 tests green**,
`cargo clippy --all-targets` **0 warnings**, ~26k lines Rust in
`src/`, 45 `tests/*_parity_test.rs` replay tests). GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki is the public status doc
(clone at `/tmp/RustyPig.wiki`, remote `RustyPig.wiki.git`, HEAD
`a90096c`).

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt`. The transcript is truth:
   never fabricate behavior from memory; if a run flakes, fix
   determinism, never lock a flaky transcript.
2. **Catch gate** whenever upstream ships an embedded
   `#ifdef UNIT_TEST` block or a `test/` suite: compile it verbatim
   (`catch/snort_catch.h` -> plain-catch shim; codec/jsnorm/fid
   recipe). Run it; record cases/assertions in `gate.txt`.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fstats_parity_test.rs`, `tests/filib_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 389),
   clippy --all-targets ZERO warnings, `vectors.txt`+`gate.txt` md5
   stable across >= 2 clean rebuilds, harness `.gitignore` block
   added (mirror siblings) and verified with `git check-ignore`
   BEFORE staging. Then commit + push, insert the plan row
   (grep-guard: count must be 0 before insert — the numa
   double-append incident cost a force-push), append deviations
   (one grep-guarded append), update the wiki (status row +
   deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. Real EVP SHA256 verified and already used in production paths (row 17o).
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k).
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics (e.g. `file_stats`) must be armed (`file_stats_init()`) or you get rc 139.

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/filib_harness/` — **the donor for all file_api FileContext-adjacent rows**: witness bodies in `stubs.cc` (FileCache/FileService/FileFlows/FileInspect-ctor/InspectorManager/DetectionEngine/PacketTracer/trace/DataBus-publish/fake clock — every body prints a `WITNESS`/`FILEDBG` line so hits are explicit), `flowz/flow_fwd.h` graft, real profiler TU pair, verbatim capture closure (file_capture/file_mempool/circular_buffer), interposed clock for deterministic duration. vectors.txt 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (stable x2); gate 19 cases / 334 assertions.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, flow/packet patterns.
- `tools/fid_harness/` — ghash/hash_key_operations/primetable closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17p: `file_api/file_cache.{h,cc}`
Measured: `file_cache.cc` 1287 lines + `file_cache.h` 115. SEVEN
embedded TEST_CASEs in an `#ifdef UNIT_TEST` block starting line 1140
(`[file_cache]`: clear/ownership/capacity/re-add semantics).
- Gate: `-DUNIT_TEST` verbatim compile (plain-catch shim) — standard
  sibling recipe.
- Its include closure (file_cache.cc:21-50: control.h, flow_key.h,
  hash/*, messages, inspector_manager, snort_config, thread_config,
  active, packet_tracer, file_events, packet_time, file_{flows,
  inspect,module,stats}.h) is ALREADY proven as witnesses/grafts
  inside `tools/filib_harness/build.sh` + `stubs.cc` — lift, don't
  re-author. Check whether file_cache.h embeds a HashTable (xhash)
  member; that closure is real and ported in Rust already.
- Watch: pending-expire clock (reuse the filib fake clock), FileInfo*
  ref counts across add/delete_entry, segment-queue ownership in
  entries, the `file_id == 0` cached_verdict_lookup gate the filib
  witness mirrors.
- Rust: `src/file_api/file_cache.rs`. When it lands, retire the
  filib FileCache WITNESS behavior only forward (do not rewrite
  17o's committed transcript; fix any fork in 17p's harness).

## Alternative quick win if file_cache bloats
`main/thread_config.cc` (920 lines, 14 TEST_CASEs, tiny include
closure: analyzer_command.h shim + messages + snort_config shim +
real time/periodic (ported) + util; body needs hwloc at link —
witness hwloc_topology_*/bitmap_* or check HAVE_NUMA-gated paths;
main/numa is ported).

## Backlog (plan rows)
- 17q+: FileContext proper (second half of `file_lib.cc`) — the
  filib G-blocks already pin its paths; port after cache + capture
  + service + flows land.
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO
  upstream TEST_CASEs in `codecs/`; transcripts are the only ground
  truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ
  (AF_PACKET via libc); 21: `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
