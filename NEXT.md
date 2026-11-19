# NEXT.md — takeover context & plan (2026-11-18, post-17r)

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

Current state (measured at the 17r docs pass): plan rows 1–17r DONE (74
commits counting the 17r docs commit, **415 tests green / 0 FAILED**
across 49 suites, `cargo clippy --all-targets` **0 warnings** on a
forced relint — all `src`/`tests` touched, 34,042 lines Rust in 114
`src/*.rs` files, 23 `tests/*_parity_test.rs` whole-transcript replay
tests among 48 test files, 276 tracked files, 30 `tools/*_harness`
dirs). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `2ab5a72` = row 17q — **the 17r wiki refresh
is OWED NOW** (17r code landed at c9b1688): status row + deviations
section + stats line "276 tracked files / ~34,000 src lines / 74
commits / 415 tests").

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
   runner said 42). When gate and probe link the same TU, use the
   **duplicate-symbol rule**: every UT-compiled TU's plain `.o` is
   EXCLUDED from the gate link (17r: 3 UT TUs in one binary —
   `[file_flows]` carry, `[file_cache]` carry, `[file_mempool]` NEW =
   18 cases / 91 assertions). When a TU has BOTH early `#ifdef
   UNIT_TEST` fragments AND a trailing suite block, excise the LAST
   block only, via `rfind` + brace-balance guard, on BOTH builds (17r
   file_lib recipe, build.sh heredoc `FIXLIBUT`).
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fctx_parity_test.rs` (the freshest: 2471 lines, whole
   610-line replay + 3 `up_gate_mempool_*` translations),
   `tests/fflows_parity_test.rs`, `tests/fcache_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 415; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings, `vectors.txt`+`gate.txt` md5 stable
   across >= 2 clean rebuilds, harness `.gitignore` block added
   (mirror siblings) and verified with `git check-ignore` BEFORE
   staging. Then commit + push, insert the plan row (grep-guard:
   count must be 0 before insert — the numa double-append incident
   cost a force-push), append deviations (one grep-guarded append),
   refresh NEXT.md, commit+push docs, update the wiki (status row +
   deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s (file_capture) does NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k).
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/fctx_harness/` — **the NEW donor for any row reaching FileContext + capture/mempool/segment closure**: everything fflows had, PLUS the probe-mode file_lib.cc with ONLY the :1363 UNIT_TEST block excised, the 3-UT-TU gate link (18 cases / 91 assertions), `FileCaptureTestAccess`-shaped witnesses already resident, and the A/K/L/M/N/O probe blocks over the heavy ladder. vectors.txt 610 lines md5 `839b5566be0a2191876e0f34b4ed56e4` (re-verified byte-identical from a from-scratch rebuild at 17r docs time); gate.txt md5 `42349372258e49db1a8f4f60e7a27ed6`. `tools/fctx_harness/PLAN.md` is the RECON→HARNESS→PORT contract example (its §3 ZERO-new-witness measurement held exactly: the fflows donor link already resolved every heavy-half symbol).
- `tools/fflows_harness/` — per-flow FileFlows + FlowData graft donor: the flowz/flow_fwd.h Flow `get_flow_data`/`set_flow_data` single-slot graft (flow.h:195/200), FIXACC access-only file_api.h extension, NetworkPolicy/policy witnesses. vectors.txt 146 lines md5 `bd8c00af7a7047ef5b745a34c2a0df55` (committed, DO NOT touch); gate 8/22 md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc`, the `flowz/flow_fwd.h` Flow key graft (uint32->uint16 asid truncation pinned), `main/thread_config.h` hwloc excision, IpsContext `conf` witness. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (committed, DO NOT touch — vanished witness lines in NEWER transcripts are the retirement signal); gate 7/42, gate.txt md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE, never leaks into fctx.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17s: file_api/file_capture.{h,cc} (the async capture row)
Measured this pass against `/opt/data/snort3-src` (file_capture.cc 913 +
.h 150):

| seam | line | notes |
|---|---|---|
| embedded UNIT_TEST block | :620–913 | **4 [file_capture] TEST_CASEs** measured at :808 (no-segfault w/ unconfigured mempool) / :815 (Flush no pending) / :820 ("Flush waits for the asynchronous writer to release its capture") / :864 ("Flush keeps waiting between queued asynchronous captures") — 17s's REAL gate, first capture-side TU with its own suite |
| test scaffolding in that block | :620–:807 | `FileCaptureTestAccess` (resettable/reset/enqueue/released_buffers) + the `AsyncWriterGate` hook ladder (`writer_wait`, `writer_idle`, `flush_entered`, `pause_first_idle_transition`, `release_writer`, …, static `async_writer_gate` at :754 area) + `wait_in_writer_test_hook` — determinism contract = the gate's own hooks; harness threads are WITNESS-threaded, never raced |
| early UNIT_TEST fragments | :45/:65/:100/:112/:197/:203 | probe excision must rfind-guard the LAST block only (same FIXLIBUT recipe as file_lib :37/:54 fragments) |
| file-static state | :55–:60 | `file_mempool` (real FileMemPool — Rust port LIVE since 17r), `capture_block_size`, `capture_mutex`, `capture_cv`, `std::thread* file_storer` (:171 `new std::thread(writer_thread)`, :186–:190 join/delete), `files_waiting` queue, `file_storing`, `running` |
| init / init_mempool | :233 | `new FileMemPool(max_files, block_size)` — the Rust `file_mempool.rs` (315L, gated 27 assertions inside the fctx link) plugs straight in |
| capture/write path | m_alloc :241, m_release :145, m_free :151 | CircularBuffer rider (`circular_buffer.rs` 161L live) |
| flush dance | :620+ suite bodies | `std::set<std::thread::id> flush_callers`, two concurrent `std::thread` flush callers (:838/:843) — the deterministic witness-thread design problem is 17s's core |
| Rust seam to close | file_lib.rs `FileCaptureApi` trait + `new_capture` factory | `process_file_capture` (file_lib.cc:1169–1187) N-block vectors ALREADY pin the state ladder through the seam (17r); the real TU lands `Box<dyn FileCaptureApi>` impl over the live mempool/circular_buffer modules — no heavy-half unlock needed |

Gate plan: fctx donor already compiles `file_capture.cc` VERBATIM in the
probe link — 17s adds the `-DUNIT_TEST` variant to the fctx-or-fresh
gate binary (duplicate-symbol rule: exclude its plain .o, expected
file_capture UT assertions pinned from the RUNNER, carry the 17r trio:
flows 8/22 + mempool 3/27 + cache 7/42). Fresh `tools/fcap_harness/`
from the fctx donor.

## Alternative quick-win rows (measured TEST_CASE inventories, this pass)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| file_service.{h,cc} | 270+112 | 0 | drags `main.h` (`main_packet_threads_fully_paused()` :101), mime/file_mime_process, search_engines/search_tool |
| file_config.{h,cc} | 128+80 | 0 | probe-only; InspectorManager/SnortConfig include closure |
| file_module.{h,cc} | 379+86 | 0 | |
| file_cache_share.{h,cc} | 75+40 | 0 | |
| file_log.cc | 329 (no .h) | 0 | |
| file_inspect.{h,cc} | 175+42 | 0 | |
| file_segment / file_mempool / circular_buffer | — | DONE 17r | landed early with the fctx gate |

## Backlog (plan rows)
- 17s: **DONE (this session, uncommitted)** — file_capture proper (async
  writer row): `src/file_api/file_capture.rs` (+ `pub mod`), real
  `RealFileCaptureFactory` default seam closure in file_lib.rs,
  `tests/fcapture_parity_test.rs` 11 tests (426 total green), fcap harness
  vectors md5 0208a69116861a506f0c46a7dc36b2ac re-verified. Wiki trio for
  17r OWED as ever; 17s docs (status row + wiki stats line) ride the
  parent's doc commit.
- 17t+: file_service, file_config, file_module, file_cache_share,
  file_log, file_inspect (see table).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO
  upstream TEST_CASEs in `codecs/`; transcripts are the only ground
  truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ
  (AF_PACKET via libc); 21: `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
