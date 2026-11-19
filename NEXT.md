# NEXT.md — takeover context & plan (2026-11-19, post-17t)

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

Current state (measured at the 17t docs pass): plan rows 1–17t DONE (78
commits counting the 17t docs commit, **445 tests green / 0 FAILED**,
`cargo clippy --all-targets` **0 warnings**, 36,086 lines Rust across
116 `src/*.rs` files, 25 `tests/*_parity_test.rs` whole-transcript
replay tests among 50 test files, 290 tracked files, 32 `tools/*_harness`
dirs). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `64ae736` = row 17s trio LANDED: status row +
deviations section + stats line, incl. the stats-line duplicate repair).
**The 17t wiki trio is OWED NOW**
(status row + deviations section + stats line "290 tracked files /
~36,100 src lines / 78 commits / 445 tests"); the 17s trio is no longer
debt — `git -C /tmp/RustyPig.wiki log` shows it at 64ae736.

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
5. **Gates at EVERY commit**: `cargo test` all green (>= 445; never
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
- `tools/fcshare_harness/` — **the NEW donor for the remaining file_api rows (smallest donor, ZERO new witnesses ever, 17t)**: fresh from the fcap donor; cp-list adds ONLY `file_cache_share.{h,cc}`. vectors.txt 25 lines md5 `03d43c143440bd2a101d56818fd20be4` (committed, NEVER edit); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)". Its cp-list (:35) + compile-list (:365) ALREADY carry the full file_api closure (incl. file_cache_share now) — see per-candidate table below.
- `tools/fcap_harness/` — the 17s donor (superseded by fcshare): fresh from the fctx donor for 17s; the probe link already resolves FileCapture real + FileService statics armable (stubs.cc:440-445) + FileMPEvent real (copy/pub_sub/file_events.h). vectors.txt 27 lines md5 `0208a69116861a506f0c46a7dc36b2ac` (committed, NEVER edit); unified gate `[file_capture]` 4 + `[file_flows]` 8/22 + `[file_cache]` 7/42 = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af`. Its build.sh cp-list (:36) + compile-list (:365) ALREADY compile `file_api.cc` and `file_config.cc` VERBATIM (their .o link in the probe) — header-only `file_service.h`/`file_policy.h` also copied.
- `tools/fctx_harness/` — donor for any row reaching FileContext + capture/mempool/segment closure: everything fflows had, PLUS the probe-mode file_lib.cc with ONLY the :1363 UNIT_TEST block excised, the 3-UT-TU gate link (18 cases / 91 assertions), `FileCaptureTestAccess`-shaped witnesses already resident, and the A/K/L/M/N/O probe blocks over the heavy ladder. vectors.txt 610 lines md5 `839b5566be0a2191876e0f34b4ed56e4` (re-verified byte-identical from a from-scratch rebuild at 17r docs time); gate.txt md5 `42349372258e49db1a8f4f60e7a27ed6`. `tools/fctx_harness/PLAN.md` is the RECON→HARNESS→PORT contract example (its §3 ZERO-new-witness measurement held exactly: the fflows donor link already resolved every heavy-half symbol; 17s repeated the trick — fcap measured ZERO new witnesses too).
- `tools/fflows_harness/` — per-flow FileFlows + FlowData graft donor: the flowz/flow_fwd.h Flow `get_flow_data`/`set_flow_data` single-slot graft (flow.h:195/200), FIXACC access-only file_api.h extension, NetworkPolicy/policy witnesses. vectors.txt 146 lines md5 `bd8c00af7a7047ef5b745a34c2a0df55` (committed, DO NOT touch); gate 8/22 md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc`, the `flowz/flow_fwd.h` Flow key graft (uint32->uint16 asid truncation pinned), `main/thread_config.h` hwloc excision, IpsContext `conf` witness. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (committed, DO NOT touch — vanished witness lines in NEWER transcripts are the retirement signal); gate 7/42, gate.txt md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE, never leaks into fctx.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17u: file_api/file_config.{h,cc} (the config facade + rule-id plumbing)

Freshly measured this pass against `/opt/data/snort3-src/src/file_api`
(wc -l head/tail of .h+.cc; `grep -c TEST_CASE` per TU — ALL SEVEN
remaining file_api TUs measure ZERO TEST_CASEs, so 17u is
probe-vectors-only; cp/compile column = presence in
`tools/fcshare_harness/build.sh` cp-list :35 and compile-list :365,
same in fcap/fctx for the shared closure — file_cache_share now cp'd +
compiled VERBATIM in the fcsh donor):

| candidate | .h+.cc lines | TEST_CASEs | in fcshare donor? | blockers |
|---|---|---|---|---|
| **file_config** (17u PICK) | 80+128 = 208 | **0** | cp'd AND compiled VERBATIM (cp-list :35, compile-list :365 — its .o already links in every file_api probe) | port-only; include closure ALL resident (snort_config.h shim, detection_engine witness, file_identifier REAL 17n, inspector_manager witness, parse_utils, file_flows REAL 17q, file_inspect HEADER-only — file_config.cc only names the header, `get_file_config` casts `InspectorManager::get_file_inspector` which is a witness) |
| file_api shim (FilePolicyBase + friends) | 227+43 = 270 | 0 | cp'd AND compiled VERBATIM (:35/:365) | consolidation row; ref protocol already ported inline at 17q (file_cache.rs FilePolicyHandle, cites file_api.cc:28-41) |
| file_inspect | 42+175 = 217 | 0 | cp'd (.h)/.cc NOT compiled | include closure NOW fully resident: file_cache REAL 17p + file_cache_share REAL 17t + file_config (17u lands it) + file_module.h + file_service.h + pub_sub ids; gate-side needs InspectorManager::get_file_inspector armable |
| file_policy | 94+216 = 310 | 0 | NOT cp'd | drags file_capture.h (REAL 17s) + file_lib (REAL) + hashes (resident) — tractable |
| file_service | 112+270 = 382 | 0 | .h only | drags main.h (`main_packet_threads_fully_paused()`), mime/file_mime_process, search_engines/search_tool — NEW closure work |
| file_log (no .h) | 329 | 0 | NOT cp'd | drags log/text_log.h + framework/module (log engine layer, new) |
| file_module | 86+379 = 465 | 0 | .h only | drags main/snort.h + managers/module_manager + lua/lua.h (Lua LIVE 17k but snort.h is heavy) |

17u plan (`file_config.{h,cc}`, 80+128 — smallest fully tractable): no
Catch gate (0 TEST_CASEs); probe vectors are the ground truth. The TU is
ALREADY VERBATIM-compiled-and-linked in every file_api harness since
17q — the delta is the Rust port + a probe block on top of the fcshare
donor:
(1) `FileConfig` DEFAULT ladder pins from the header macros
(file_config.h:29-40): file_type_depth 1460 / file_signature_depth
10485760 / show_data_depth 100 / block_timeout 86400 / lookup_timeout 2
/ capture memcap 100 MiB / max_size 1048576 / min_size 0 / block_size
32768 / max_files_cached 65536 / max_files_per_flow 128 / file_depth 0 /
trace flags false / snort_protocol_id UNKNOWN (int64 vs uint64 widths
literal);
(2) `file_type_name` arms: UNKNOWN id -> "Unknown file type, done",
CONTINUE -> "Undecided file type, continue...", id-with-rule -> rule
type, id-without-rule -> ""; the FREE function `file_type_name` null-conf
-> "NA" (file_config.cc:71-78 -- the Rust port already exposes
file_identifier 17n, wire the facade);
(3) `get_file_config(sc)` null-sc -> `SnortConfig::get_conf()` + the
InspectorManager cast arm: get_file_inspector null -> nullptr (witness
armable both ways); `get_magic_rule_ids_from_type` null-conf ->
`ids_set.reset()` arm (file_config.cc:103-110);
(4) `set_rule_id_from_type` the FileMeta ctor plumbing (:112-127) ->
drives the REAL file_identifier add_file_id (17n, incl. the dup ->
ParseError quirk);
(5) thin forwarders find_file_type_id / process_file_rule /
get_rule_from_id / get_magic_rule_ids_from_type -> the REAL
FileIdentifier member (already ported) — pin that they are pure
delegation (no extra logic).
Rust lands `src/file_api/file_config.rs` (the FileConfig struct with the
full default ladder) and RETIRES the interim FileConfigView/
FileConfigLite two-view shim in file_cache.rs to the extent the real
shape replaces their read sites (keep what fcache/fflows fixtures
compile against; the two-view deviation was row 17p's — check
file_cache.rs:~2000 before deleting anything). Expected witness delta:
ZERO new (InspectorManager + SnortConfig witnesses resident).

## Alternative quick-win rows (re-measured at the 17t docs pass; 0 TEST_CASEs across ALL remaining file_api TUs)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| file_service.{h,cc} | 270+112 | 0 | drags `main.h` (`main_packet_threads_fully_paused()` :101), mime/file_mime_process, search_engines/search_tool |
| file_config.{h,cc} | 128+80 | 0 | 17u PICK; TU already VERBATIM-compiled-and-linked inside fcshare/fcap/fctx harnesses |
| file_module.{h,cc} | 379+86 | 0 | drags main/snort.h, module_manager, lua |
| file_cache_share.{h,cc} | 75+40 | 0 | DONE 17t |
| file_log.cc | 329 (no .h) | 0 | drags log/text_log.h (log engine layer) |
| file_inspect.{h,cc} | 175+42 | 0 | closure NOW complete (17t landed file_cache_share) — next after file_config |
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
- 17t: **DONE (code at 3285cd0)** — file_cache_share:
  `src/file_api/file_cache_share.rs` 588L + FileMpEvent port
  (file_events.h:37-:134), `FileCacheShareSink` closes the
  FileCache default events sink (file_cache.rs:1200),
  `tests/fcshare_parity_test.rs` 1139L (25/25 replay + 13 arms),
  tools/fcshare_harness vectors 25 lines md5
  03d43c143440bd2a101d56818fd20be4 tracked, gate stays 114/22,
  **445 total green**. Wiki trio for 17t OWED (wiki 64ae736 has the
  17s trio; 17t status row + deviations + stats line still to push).
- 17u+: file_config, file_api shim, file_inspect, file_policy,
  file_service, file_log, file_module (table above).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO
  upstream TEST_CASEs in `codecs/`; transcripts are the only ground
  truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ
  (AF_PACKET via libc); 21: `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
