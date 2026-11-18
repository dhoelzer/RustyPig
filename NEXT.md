# NEXT.md — takeover context & plan (2026-11-18, post-17q)

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

Current state (measured this session): plan rows 1–17q DONE (71 commits
after the 17q docs commit, **406 tests green / 0 FAILED** across 48
suites, `cargo clippy --all-targets` **0 warnings** on a forced relint,
31,405 lines Rust in `src/`, 22 `tests/*_parity_test.rs`
whole-transcript replay tests among 47 test files). GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki is the public status doc
(clone at `/tmp/RustyPig.wiki`, remote `RustyPig.wiki.git`, HEAD
`a90096c` = row 17o — **the 17p AND 17q wiki refreshes are still
owed**: status rows + deviations sections + stats line
"71 commits / 406 tests").

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
   `tests/filib_parity_test.rs`, `tests/fcache_parity_test.rs`,
   `tests/fflows_parity_test.rs` (the freshest: 146/146-line replay +
   8 `up_gate_*` translations of the embedded Catch cases).
5. **Gates at EVERY commit**: `cargo test` all green (>= 406; never
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
- **OpenSSL without dev packages** (apt locked, no root): compile with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. Real EVP SHA256 verified, used in production paths (17o) and the 17p gate/probe (sha_to_string UPPERCASE vectors). 17r NEEDS it again: `process_file_signature_sha256` (file_lib.cc:1065) + `print_file_sha256` (:1280) + the EVP_MD_CTX dtor chain.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k).
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/fflows_harness/` — **the NEW donor for any row reaching the per-flow FileFlows + FileContext + cache closure**: everything fcache had, PLUS the real `file_flows.cc` TU (gate mode = its own 8 [file_flows][lifecycle] cases / 22 assertions; probe mode = UNIT_TEST-excised), the flowz/flow_fwd.h Flow `get_flow_data`/`set_flow_data` single-slot graft (flow.h:195/200 — the ONLY graft delta over fcache), FIXACC access-only extension to file_api.h, and witnesses NetworkPolicy/get_base_file_policy, `snort::get_file_processed_size` (real file_service.cc:256), PacketTracer get_time/restart_timer + armable is_daq_activated/get_instance_id/get_max_file_depth, DE queue_event, FileService get_max_file_depth passthrough. vectors.txt 146 lines md5 `bd8c00af7a7047ef5b745a34c2a0df55` (stable x3 clean rebuilds, committed); gate.txt md5 `e14626fc6f112a9786c7098e6b4df40c`. `tools/fflows_harness/PLAN.md` is the RECON contract example (incl. its §7/§8 FileContext half scope + the measured 17q/17r split). The donor fcache FileFlows witness block is RETIRED in this link (retire rule).
- `tools/fcache_harness/` — file_api hash/clock closure donor: real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc`, the `flowz/flow_fwd.h` Flow key graft (uint32->uint16 asid truncation pinned), `main/thread_config.h` hwloc excision, IpsContext `conf` witness. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (committed, DO NOT touch — vanished witness lines in NEWER transcripts are the retirement signal); gate 7 cases / 42 assertions, gate.txt md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17r: the HEAVY FileContext half (file_lib.cc:825–1362)
Measured this session against `/opt/data/snort3-src` (file_lib.cc 1624
+ file_lib.h 252; ~538 lines of heavy-half bodies in that span):

| seam | line | notes |
|---|---|---|
| `process` (offset form) | :825 | FILEDBG print arm at :836 |
| `process` (position form) | :986 | calls find_file_type_from_ips + sha256 + capture chain |
| `find_file_type_from_ips` | :1004 | **CONSUMES the FileFlows swap/restore NOW REAL in Rust** — C swap at :1040 (`swap_current_file_context_no_delete`), conditional restore at :1053 |
| `process_file_type` | :1057 | CONTINUE -> find_file_type_from_ips arm |
| `process_file_signature_sha256` | :1065 | depth-fail arm + EVP via **node-headers openssl recipe**; recursive_mutex over user_file_data (17p deviation pattern applies) |
| `process_file_capture` | :1169 | rides the REAL FileCapture/circular_buffer/file_mempool closure already linked verbatim in the fflows donor (17o G13 pins the buffer lifecycle) |
| `stop_file_capture` / `_unlocked` | :1189/:1195 | dtor path already ported 17q pins the call order |
| `update_file_size` | :1207 | position ladder |
| print ladder | :1226/:1280/:1301/:1346 | print_file_data / print_file_sha256 / print_file_name (**get_UTF8_fname :85** UTF-16LE iconv cluster — 17q already ported the fn; the print callers are 17r) / print |
| unlock side | file_flows.cc:473/:486/:531 | the pinned-panic `context->process(...)` call sites in file_flows.rs go live SAME commit — semantics never split across rows (deviations rule) |

Harness = the fflows donor (it carries everything). 17r's own embedded
TEST_CASE count in that span: **ZERO** (file_lib.cc's only UNIT_TEST
block is the [file_info] suite, gated in 17o) — ground truth = probe
vectors + the 17o G-blocks. Pair it with a FREE Catch gate from the
same tree: `[file_mempool]` 3 TEST_CASEs at file_mempool.cc:231/:243/
:273 (block :223-303; file_mempool.cc 303 + .h 84) — both the block's
`*(MagicType*)p = 0` plant and m_release double-free arms run against
the mempool ALREADY linked verbatim in the fflows copy tree.
circular_buffer.{h,cc} (173+62) has ZERO unit tests, probe-only, and is
linked there too.

## Alternative quick-win rows (measured TEST_CASE inventories, file_api)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| file_mempool.{h,cc} | 303+84 | **3** at :231/:243/:273 `[file_mempool]` | free Catch gate, already linked in fflows donor — likely 17r's gate partner |
| circular_buffer.{h,cc} | 173+62 | 0 | probe-only; rides file_segment |
| file_segment.{h,cc} | 355+78 | 0 | probe-only; feeds FileSegments/file_segments member |
| file_capture.{h,cc} | 913+150 | **4** at :808/:815/:820/:864 `[file_capture]` | incl. "Flush waits for the asynchronous writer" — std::thread/file_storer dance must be witness-threaded deterministically |
| file_service.{h,cc} | 270+112 | 0 | drags `main.h`, mime/file_mime_process, search_engines/search_tool |
| file_config.{h,cc} | 128+80 | 0 | probe-only |
| file_module.{h,cc} | 379+86 | 0 | |
| file_cache_share.{h,cc} | 75+40 | 0 | |
| file_log.cc | 329 (no .h) | 0 | |
| file_inspect.{h,cc} | 175+42 | 0 | |
| main/thread_config.cc | 920 | **14** | bigger alt; hwloc witness ladder, main/numa ported |

## Backlog (plan rows)
- 17r: heavy FileContext half (above) + free [file_mempool] gate.
- 17s+: file_segment/circular_buffer proper, file_service proper,
  file_capture async-writer row, file_config, file_module,
  file_cache_share, file_log, file_inspect (see table).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO
  upstream TEST_CASEs in `codecs/`; transcripts are the only ground
  truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ
  (AF_PACKET via libc); 21: `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
