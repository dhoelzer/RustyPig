# NEXT.md — takeover context & plan (2026-11-19, post-17s)

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

Current state (measured at the 17s docs pass): plan rows 1–17s DONE (76
commits counting the 17s docs commit, **431 tests green / 0 FAILED**,
`cargo clippy --all-targets` **0 warnings**, 35,473 lines Rust across
115 `src/*.rs` files, 24 `tests/*_parity_test.rs` whole-transcript
replay tests among 49 test files, 283 tracked files, 31 `tools/*_harness`
dirs). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `ecb800f` = row 17r trio LANDED: status row +
deviations section + stats line). **The 17s wiki trio is OWED NOW**
(status row + deviations section + stats line "283 tracked files /
~35,500 src lines / 76 commits / 431 tests"); the 17r trio is no longer
debt — `git -C /tmp/RustyPig.wiki log` shows it at ecb800f.

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
5. **Gates at EVERY commit**: `cargo test` all green (>= 431; never
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
- `tools/fcap_harness/` — **the NEW donor for the remaining file_api rows (smallest donor, ZERO new witnesses ever)**: fresh from the fctx donor for 17s; the probe link already resolves FileCapture real + FileService statics armable (stubs.cc:440-445) + FileMPEvent real (copy/pub_sub/file_events.h). vectors.txt 27 lines md5 `0208a69116861a506f0c46a7dc36b2ac` (committed, NEVER edit); unified gate `[file_capture]` 4 + `[file_flows]` 8/22 + `[file_cache]` 7/42 = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af`. Its build.sh cp-list (:36) + compile-list (:365) ALREADY compile `file_api.cc` and `file_config.cc` VERBATIM (their .o link in the probe) — header-only `file_service.h`/`file_policy.h` also copied.
- `tools/fctx_harness/` — donor for any row reaching FileContext + capture/mempool/segment closure: everything fflows had, PLUS the probe-mode file_lib.cc with ONLY the :1363 UNIT_TEST block excised, the 3-UT-TU gate link (18 cases / 91 assertions), `FileCaptureTestAccess`-shaped witnesses already resident, and the A/K/L/M/N/O probe blocks over the heavy ladder. vectors.txt 610 lines md5 `839b5566be0a2191876e0f34b4ed56e4` (re-verified byte-identical from a from-scratch rebuild at 17r docs time); gate.txt md5 `42349372258e49db1a8f4f60e7a27ed6`. `tools/fctx_harness/PLAN.md` is the RECON→HARNESS→PORT contract example (its §3 ZERO-new-witness measurement held exactly: the fflows donor link already resolved every heavy-half symbol; 17s repeated the trick — fcap measured ZERO new witnesses too).
- `tools/fflows_harness/` — per-flow FileFlows + FlowData graft donor: the flowz/flow_fwd.h Flow `get_flow_data`/`set_flow_data` single-slot graft (flow.h:195/200), FIXACC access-only file_api.h extension, NetworkPolicy/policy witnesses. vectors.txt 146 lines md5 `bd8c00af7a7047ef5b745a34c2a0df55` (committed, DO NOT touch); gate 8/22 md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc`, the `flowz/flow_fwd.h` Flow key graft (uint32->uint16 asid truncation pinned), `main/thread_config.h` hwloc excision, IpsContext `conf` witness. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (committed, DO NOT touch — vanished witness lines in NEWER transcripts are the retirement signal); gate 7/42, gate.txt md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE, never leaks into fctx.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17t: file_api/file_cache_share.{h,cc} (the cross-thread shared-verdict shim)

Freshly measured this pass against `/opt/data/snort3-src/src/file_api`
(wc -l; `grep -c TEST_CASE` — ALL EIGHT remaining file_api TUs measure
ZERO TEST_CASEs, so 17t is probe-vectors-only):

| candidate | .h+.cc lines | TEST_CASEs | donor-covered? | blockers |
|---|---|---|---|---|
| **file_cache_share** (17t PICK) | 40+75 = 115 | **0** | YES — cp'd? no, but PROVEN: dropped the TU into the **fcap donor copy closure unchanged and `g++ -fsyntax-only` PASSED with ZERO grafts** (needs only file_service.h + log/messages.h, both resident); `FileCacheShare::handle` calls `FileService::get_file_cache()` (statics armable in fcap stubs.cc:440-:445) + `store_shared_verdict` (Rust LIVE file_cache.rs:1838); `FileMPEvent` REAL in copy/pub_sub/file_events.h | none — smallest + fully tractable |
| file_config | 80+128 = 208 | 0 | YES — `file_config.cc` ALREADY compiled VERBATIM in fcap/fctx build.sh compile-lists (:365) | port-only; InspectorManager/SnortConfig witnesses resident |
| file_api shim (FilePolicyBase + friends) | 227+43 = 270 | 0 | YES — `file_api.cc` also compiled VERBATIM at :365; ref protocol already ported inline at 17q (file_cache.rs FilePolicyHandle, cites file_api.cc:28-41) | mostly a consolidation row; small real delta |
| file_inspect | 42+175 = 217 | 0 | partial — header cp'd; file_inspect.cc NOT compiled yet | include closure: file_cache_share + file_module + file_service headers (17t lands the first) |
| file_policy | 94+216 = 310 | 0 | partial — header cp'd, .cc not compiled | drags file_capture.h (REAL now, 17s) + file_lib + hashes (all resident) — tractable after 17t |
| file_service | 112+270 = 382 | 0 | partial (.h cp'd) | drags main.h (`main_packet_threads_fully_paused()`), mime/file_mime_process, search_engines/search_tool — NEW closure work |
| file_log (no .h) | 329 | 0 | NO | drags log/text_log.h + framework/module (log engine layer, new) |
| file_module | 86+379 = 465 | 0 | NO (.h cp'd, .cc not) | drags main/snort.h + managers/module_manager + lua/lua.h (Lua LIVE 17k but snort.h is heavy) |

17t plan (`file_cache_share.{h,cc}`, 75+40 lines): fresh `tools/fcshare_harness`
**from the fcap donor** (smallest donor; the closure is already proven to
take this TU with zero grafts — verified at docs time by dropping the TU
into `tools/fcap_harness/copy` and syntax-only compiling it). No Catch
gate (0 TEST_CASEs): vectors are the ground truth. Probe blocks to pin:
(1) `FileCacheShare::handle` -> `FileService::get_file_cache()` null-skip
arm vs armed-cache arm (arm the SAME FileCache the fcache fixtures build;
store_shared_verdict arms already pinned at 17p I-block — replay through
the handler wrapper to pin the arg plumbing: key/timeout/file passthrough);
(2) `serialize_file_event` full ladder (null event -> false; len==0 ->
false; happy path = `new char[get_data_len()]` + FileMPEvent::serialize —
byte-dump the buffer: FileMPEvent.h ctor/get_data_len, FileInfo::serialize
wire already pinned at 17o B-block); (3) `deserialize_file_event` ladder
(null/len 0 -> false; round-trip back via file_lib.rs FileInfo::deserialize
— pin the `buffer + offset, data_len - offset` cursor at
pub_sub/file_events.h:102). Rust lands `src/file_api/file_cache_share.rs` +
a FileMPEvent port (pub_sub/file_events.h:37-:120 is header-only:
timeout/hashkey/file_ctx + serialize/deserialize pair — it rides the
17o FileInfo wire). Expected witness delta: ZERO new (FileService statics
armable + get_file_cache already resolved; probe's FileCache is the real
TU). The serialize/deserialize pair is the MP-transport face the 17p
FILE_SHARE_SYNC publish witness only stubbed — 17t makes the wire real.

Queue after 17t (measured, same table): file_config (208) -> file_api
shim consolidation (270) -> file_inspect (217) -> file_policy (310) ->
file_service (382, new closure) -> file_log (329) -> file_module (465).
Alt bigger-win: main/thread_config.cc 920L with **14** [ThreadConfig]
TEST_CASEs :615-:903 (hwloc witness ladder, 17l precedent) if a gated
row is wanted.

## Alternative quick-win rows (re-measured this pass; 0 TEST_CASEs across ALL remaining file_api TUs)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| file_service.{h,cc} | 270+112 | 0 | drags `main.h` (`main_packet_threads_fully_paused()` :101), mime/file_mime_process, search_engines/search_tool |
| file_config.{h,cc} | 128+80 | 0 | probe-only; TU already VERBATIM-compiled inside fcap/fctx harnesses |
| file_module.{h,cc} | 379+86 | 0 | drags main/snort.h, module_manager, lua |
| file_cache_share.{h,cc} | 75+40 | 0 | 17t PICK; donor-proven, zero blockers |
| file_log.cc | 329 (no .h) | 0 | drags log/text_log.h (log engine layer) |
| file_inspect.{h,cc} | 175+42 | 0 | needs file_cache_share (17t) in closure |
| file_policy.{h,cc} | 216+94 | 0 | CaptureFilePolicy rides file_capture.h (REAL now, 17s) + file_lib + hashes (measured includes) |
| file_segment / file_mempool / circular_buffer / file_capture | — | DONE 17r/17s | fcap harness is the freshest donor |

## Backlog (plan rows)
- 17s: **DONE (committed at dc94885)** — file_capture proper (async
  writer row): `src/file_api/file_capture.rs` 1421L,
  `RealFileCaptureFactory` seam closed at file_lib.rs:1125,
  `tests/fcapture_parity_test.rs` 1357L / 16 tests, **431 total green**,
  fcap harness vectors md5 0208a69116861a506f0c46a7dc36b2ac tracked.
  Wiki trio for 17s OWED (wiki ecb800f has 17r trio; 17s status row +
  deviations + stats line still to push).
- 17t+: file_cache_share, file_config, file_api shim, file_inspect,
  file_policy, file_service, file_log, file_module (table above).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO
  upstream TEST_CASEs in `codecs/`; transcripts are the only ground
  truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ
  (AF_PACKET via libc); 21: `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
