# NEXT.md — takeover context & plan (2026-11-17, post-17p)

This file is the single resume point for a fresh agent. It carries only
what is not cheaply re-derivable. `PORTING_PLAN.md` (row table, per-row
completion notes) and `KNOWN DEVIATIONS.md` (every deliberate departure,
source-cited) are the deep references — consult, never re-invent.

## What this project is
Port Snort 3 (C++) to Rust with byte-exact behavioral parity, milestone
by milestone. Ground truth source: `/opt/data/snort3-src` @
`fe29cbe7403a` (read-only reference; do not edit — it carries a local
`M src/managers/action_manager.h` plus an untracked `src/key` from a
prior probe; NEVER `git add` anything under snort3-src). Port repo:
`/opt/data/snort3-rust` (branch `master`, remote
`github.com/dhoelzer/RustyPig`).

Current state (measured this session): plan rows 1–17p DONE (69 commits
after the 17p docs commit, **397 tests green / 0 FAILED**,
`cargo clippy --all-targets` **0 warnings**, 28,596 lines Rust in
`src/`, 21 `tests/*_parity_test.rs` whole-transcript replay tests among
46 test files). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `a90096c` = row 17o — **the 17p wiki refresh
is still owed**: status row + deviations section + stats line
"69 commits / 397 tests").

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt`. The transcript is truth:
   never fabricate behavior from memory; if a run flakes, fix
   determinism, never lock a flaky transcript.
2. **Catch gate** whenever upstream ships an embedded
   `#ifdef UNIT_TEST` block or a `test/` suite: compile it verbatim
   (`catch/snort_catch.h` -> plain-catch shim; codec/jsnorm/fid/fcache
   recipe). Run it; record cases/assertions in `gate.txt`. NEVER gate
   on grep-estimated assertion counts — pin case names/counts from
   grep, measure assertions from the runner (17p: grep said 36, the
   runner said 42).
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/filib_parity_test.rs`, `tests/fcache_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 397; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings, `vectors.txt`+`gate.txt` md5 stable
   across >= 2 clean rebuilds, harness `.gitignore` block added
   (mirror siblings) and verified with `git check-ignore` BEFORE
   staging. Then commit + push, insert the plan row (grep-guard:
   count must be 0 before insert — the numa double-append incident
   cost a force-push), append deviations (one grep-guarded append),
   update the wiki (status row + deviations section + stats line),
   push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. Real EVP SHA256 verified, used in production paths (17o) and the 17p gate/probe (sha_to_string UPPERCASE vectors).
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k).
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/fcache_harness/` — **the NEW donor for every file_api row that needs the full hash/clock closure**: everything filib had, PLUS real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc` in the link, the extended `flowz/flow_fwd.h` graft (Flow `client_ip/server_ip/client_group/server_group`, `key->addressSpaceId`; uint32->uint16 asid truncation pinned), the `main/thread_config.h` hwloc excision (witness `get_instance_max`), and the `IpsContext` witness carrying the `conf` member file_cache.cc:669 reads. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (identical across 5 from-scratch rebuilds this session); gate 7 cases / 42 assertions, gate.txt md5 `6b3c041e65bce7ad12a585d54f287eff`. Its `PLAN.md` is the RECON->HARNESS contract example — keep writing one per harness.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads; 17p's expiry ladder is pure packet time). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17q: `file_api/file_flows.{h,cc}` + the FileContext member half
Measured: `file_flows.cc` 775 lines + `file_flows.h` 154. EIGHT embedded
TEST_CASEs at `:587-775` (`[file_flows][lifecycle]`: retire defers
delete + dtor drains it / retire then set drops deferred via
retire_victim / CSCwt96192 regression (retire non-current then set
other) / ISS-1 regression (caller deref after remove safe) / nested
retire drains prior / dtor drains main + partially_processed_contexts +
deferred (original crash shape) / swap-restore round-trips the
(current_context, current_file_id) pair / swap does NOT engage
deferred-delete). The block ships its OWN `FFTestAccessor` friend
struct (reaches privates `partially_processed_contexts`,
`current_context`, `current_file_id`, `deferred_delete_context`,
`main_context`) and `FF_TEST_CONTEXT : public FileContext` — so NO
private->public header graft is needed; copy the block verbatim and
link a real-enough FileContext (ctor/dtor/set_file_id).

- Closure verdict (measured against the fcache links): EVERY include of
  file_flows.cc is already handled in `tools/fcache_harness` (real
  file_cache.cc + file_lib.cc + file_stats TUs;
  detection/inspector_manager/packet_tracer/trace/snort_config
  witnesses; `helpers/event_gen.h` already copied at build.sh:39 — its
  detection_engine queue_event witness carries on). Harness = fcache
  with file_flows.cc swapped into the -DUNIT_TEST slot + a new probe.
- The UNPORTED FileContext member half — 27 method refs between
  `file_lib.cc:596-1362` (get_UTF8_fname :85, get_mime_type,
  set_source, log_file_event :613 (the `FileCacheEventSink` seam 17p
  left open), finish_signature_lookup, set_signature_state,
  check_policy, remove_segments, FileContext::reset, process x2
  (:825/:986), find_file_type_from_ips, process_file_type,
  process_file_signature_sha256 (EVP via the node-headers recipe),
  stop_file_capture(_unlocked), update_file_size, print_file_data,
  print_file_sha256, print_file_name, print) — port THOSE rows' half
  this row. `file_segments` is the REAL file_segment/circular_buffer/
  file_mempool closure ALREADY linked verbatim in fcache. Ctor
  (file_lib.cc:559, `start_time(SnortClock::now())` +
  InspectorManager::acquire_file_inspector gate) and dtor (:574,
  EVP_MD_CTX_free + stop_file_capture + `delete file_segments` +
  InspectorManager::release) are the seam edges 17p's file_cache.rs
  already pins.
- Probe pin targets: the retire/deferred-delete ALIASING matrix (victim
  vs current vs ppc slots — the ISS-1/CSCwt96192 regressions ARE the
  semantics), `get_new_file_instance` =
  `(get_instance_id() << 32) | max_file_id++` (file_flows.cc:205-209;
  witness get_instance_id, file-static THREAD_LOCAL max_file_id),
  `get_file_position` packet-flag ladder (FULL/START/END/MIDDLE via
  is_full_pdu/is_pdu_start/PKT_PDU_TAIL/get_file_processed_size),
  `events.create_event(EVENT_FILE_DROPPED_OVER_LIMIT)` —
  EventGen<EVENT__MAX_VALUE=3, EVENT__NONE=-1, FILE_ID_GID=150> +
  FileSid enum — behind the queue_event witness, `populate_trace_data`
  PacketTracer::daq_log format, retire_victim nulling EVERY alias slot.
- Rust: deepen `src/file_api/file_lib.rs` (FileContext), new
  `src/file_api/file_flows.rs`. Retire the FileFlows witness block in
  the NEW harness link only (fcache's committed transcript untouched);
  the FileCache witness retirement precedent (17p) is the pattern.

## Alternative quick win if file_flows bloats
`file_api/file_mempool.{h,cc}` (303+84 lines) + `circular_buffer.{h,cc}`
(173+62): 3 TEST_CASEs at file_mempool.cc:223-303 `[file_mempool]`
(m_free / m_free-queue / m_release double-free detection; the block
plants `*(MagicType*)p = 0` headers to mirror production init) —
circular_buffer has ZERO unit tests, probe-only. BOTH already linked
verbatim (headers + .cc) inside the fcache copy tree, so the harness
closes with one small build.sh. `main/thread_config.cc` (920 lines, 14
TEST_CASEs, hwloc witness ladder; main/numa ported) is the bigger alt.

## Backlog (plan rows)
- 17r+: FileService proper (file_service.cc 270, ZERO TEST_CASEs —
  probe-only ground truth; drags `main.h`, mime/file_mime_process,
  search_engines/search_tool), file_capture.cc full async writer-thread
  (913; 4 TEST_CASEs at :620-913 incl. "Flush waits for the
  asynchronous writer" — the std::thread/file_storer dance must be made
  deterministic or witness-threaded), file_config.cc (128),
  file_module.cc (379), file_cache_share.cc (75), file_log.cc (329),
  file_inspect.cc (175).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO
  upstream TEST_CASEs in `codecs/`; transcripts are the only ground
  truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ
  (AF_PACKET via libc); 21: `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
