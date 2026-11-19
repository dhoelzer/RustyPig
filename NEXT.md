# NEXT.md — takeover context & plan (2026-11-19, post-17v)

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

Current state (measured at the 17v docs pass): plan rows 1–17v DONE (82
commits counting the 17v docs commit, **447 tests green / 0 FAILED**,
`cargo clippy --all-targets` **0 warnings**, 36,760 lines Rust across
118 `src/*.rs` files, 27 `tests/*_parity_test.rs` whole-transcript
replay tests among 52 test files, 304 tracked files, 34 `tools/*_harness`
dirs). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `7662621` = row 17u trio LANDED: status row +
deviations section + stats line; verified read-only at this docs pass —
`git -C /tmp/RustyPig.wiki log --oneline -5` prints
`7662621 row 17u: status + deviations + stats` atop `c16d2dc row 17t`,
and `grep -rn '17v' /tmp/RustyPig.wiki` is EMPTY — the wiki is NEVER
touched by code or plan rows). **The 17v wiki trio is OWED** and is owed
at the NEXT WIKI phase, not by this docs pass (status row + deviations
section + stats line "304 tracked files / ~36,800 src lines / 82
commits / 447 tests"); the 17u trio is no longer debt — landed at
7662621.

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
5. **Gates at EVERY commit**: `cargo test` all green (>= 447; never
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
- `tools/fcapi_harness/` — **the NEW donor for the remaining file_api rows (smallest donor, 17v)**: fresh from the fconf donor; **ZERO cp delta** for the row TU — file_api.{h,cc} sit in the donor cp-list (:54) and the generic compile loop (:386); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af` (byte-ident to the fconf/fcshare donor — the row added ZERO TEST_CASEs; build.sh self-checks :574-:576 grep-pin the TU's TEST_CASE/UNIT_TEST = 0). vectors.txt 21 lines md5 `a953a5017b74f5d44dbba14df48ac5ea` (committed, NEVER edit); probe arms C_sz/E_enums/M_flags/P_/S_enc/R_ (see PLAN §5); stubs.cc = fconf donor VERBATIM (incl. the fconf_set_file_inspector_null toggle :371). Its cp-list (:54) + compile loop (:386) + explicit block (:409-:414) ALREADY carry the full file_api closure incl. file_api itself — see per-candidate table below. NB the harness dir is `fcapi_harness` (the 17u NEXT.md said `fapi_harness` — pinned name, do not "fix" the code).
- `tools/fconf_harness/` — the 17u donor (superseded by fcapi; kept for lineage): fresh from the fcshare donor; **ZERO cp delta** — file_config.{h,cc} (and everything the queue needs, see table) already sat in the donor cp-list (:38) and compile-list (:370). vectors.txt 20 lines md5 `65968e1cc11e9489b89762b6c6f3765e` (committed, NEVER edit); probe probe.cc D/N/T/F/G/M/S arms; stubs.cc = fcshare donor + ONE toggle (`fconf_set_file_inspector_null`).
- `tools/fcshare_harness/` — the 17t donor (superseded by fconf): fresh from the fcap donor; cp-list adds ONLY `file_cache_share.{h,cc}`. vectors.txt 25 lines md5 `03d43c143440bd2a101d56818fd20be4` (committed, NEVER edit); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)". Its cp-list (:35) + compile-list (:367) ALREADY carry the full file_api closure (incl. file_cache_share now).
- `tools/fcap_harness/` — the 17s donor (superseded by fcshare): fresh from the fctx donor for 17s; the probe link already resolves FileCapture real + FileService statics armable (stubs.cc:440-445) + FileMPEvent real (copy/pub_sub/file_events.h). vectors.txt 27 lines md5 `0208a69116861a506f0c46a7dc36b2ac` (committed, NEVER edit); unified gate `[file_capture]` 4 + `[file_flows]` 8/22 + `[file_cache]` 7/42 = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af`. Its build.sh cp-list (:36) + compile-list (:365) ALREADY compile `file_api.cc` and `file_config.cc` VERBATIM (their .o link in the probe) — header-only `file_service.h`/`file_policy.h` also copied.
- `tools/fctx_harness/` — donor for any row reaching FileContext + capture/mempool/segment closure: everything fflows had, PLUS the probe-mode file_lib.cc with ONLY the :1363 UNIT_TEST block excised, the 3-UT-TU gate link (18 cases / 91 assertions), `FileCaptureTestAccess`-shaped witnesses already resident, and the A/K/L/M/N/O probe blocks over the heavy ladder. vectors.txt 610 lines md5 `839b5566be0a2191876e0f34b4ed56e4` (re-verified byte-identical from a from-scratch rebuild at 17r docs time); gate.txt md5 `42349372258e49db1a8f4f60e7a27ed6`. `tools/fctx_harness/PLAN.md` is the RECON→HARNESS→PORT contract example (its §3 ZERO-new-witness measurement held exactly: the fflows donor link already resolved every heavy-half symbol; 17s repeated the trick — fcap measured ZERO new witnesses too).
- `tools/fflows_harness/` — per-flow FileFlows + FlowData graft donor: the flowz/flow_fwd.h Flow `get_flow_data`/`set_flow_data` single-slot graft (flow.h:195/200), FIXACC access-only file_api.h extension, NetworkPolicy/policy witnesses. vectors.txt 146 lines md5 `bd8c00af7a7047ef5b745a34c2a0df55` (committed, DO NOT touch); gate 8/22 md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc`, the `flowz/flow_fwd.h` Flow key graft (uint32->uint16 asid truncation pinned), `main/thread_config.h` hwloc excision, IpsContext `conf` witness. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (committed, DO NOT touch — vanished witness lines in NEWER transcripts are the retirement signal); gate 7/42, gate.txt md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE, never leaks into fctx.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17w: file_inspect.{h,cc} (the inspector TU: configure() arms the REAL FileCache + the ConfigLogger show ladder + the sin_file_flow API record)

Freshly measured this pass against `/opt/data/snort3-src/src/file_api`
(`wc -l`; `grep -c 'TEST_CASE\|ifdef UNIT_TEST'` per TU — ALL FIVE
remaining queue TUs measure ZERO, so 17w stays probe-vectors-only;
donor cp/compile column = presence in `tools/fcapi_harness/build.sh`
cp-list :54, the generic compile loop :386, and the explicit compile
block :409-:414 — checked by `grep` this pass):

| candidate | .h+.cc lines | TEST_CASEs | in fcapi donor? | blockers |
|---|---|---|---|---|
| **file_inspect** (17w PICK) | 42+175 = 217 | **0** | .h cp'd (:54; also FIXACC :252 + stubs.cc:13); **.cc ZERO presence** (cp delta = file_inspect.cc ONLY) | include closure FULLY RESIDENT (file_cache.cc compiled :412, file_cache_share/file_config/file_flows in the :386 loop, file_service.h + file_module.h + pub_sub/file_events_ids.h cp'd :54/:55, framework/inspector.h cp'd :64). NEW witness bodies (grep-0 in stubs.cc, measured): `DataBus::get_id` (file_inspect.cc:74; only MPDataBus::get_id :298 present), `MPDataBus::register_event_helpers` + `MPDataBus::subscribe` (:81/:82), `ConfigLogger::log_flag/log_value` (declared copy/log/messages.h:63/:70, no bodies), `FileIdModule::load_config` (called by the REAL ctor :50; module body is file_module.cc turf — witness arms the FileConfig* dst). WITNESSES THAT RETIRE on the real link: FileInspect body block stubs.cc:425-436 + `get_file_adv_pub_id` :309 (REAL definition file_inspect.cc:87-:88 over the static atomic :46); `fcache_set_file_inspector` toggle :352-355 must re-arm (real ctor calls load_config, never nullptr-mod). |
| file_policy | 94+216 = 310 | 0 | NOT cp'd (ZERO `file_policy` hits in build.sh) | includes measured: file_api.h (REAL now 17v) + file_capture.h (REAL 17s) + file_lib.h (REAL) + file_service.h (cp'd) + hash/hashes.h (REAL :386) — cp delta = file_policy.{h,cc} only; FileService::enable_* statics already REAL in stubs (:451-:465); signature_lookup :187-:216 rides FileInfo reserve_file/store_file_async (the 17s RealFileCaptureFactory closure) — tractable, queue next after 17w |
| file_service | .h 112 cp'd, .cc 270 NOT compiled | 0 | .h only (cp :54) | drags `main.h` (`main_packet_threads_fully_paused()` file_service.cc:101 — grep-0 cp'd, new witness), mime/file_mime_process.h + search_engines/search_tool.h (includes :37/:38, grep-0 cp'd) + utils/stats builder call :76 (snapshot.h cp'd :63 but Builder/Group/GaugeDef layer is stats turf) |
| file_log (no .h) | 329 | 0 | NOT cp'd | drags log/text_log.h (grep-0 cp'd — TextLog engine layer, new) + Module/PegInfo bodies (framework/module.h cp'd :64, body NOT) ; data_bus/packet_time/file_config/file_flows/file_lib all REAL |
| file_module | .h 86 cp'd, .cc 379 NOT compiled | 0 | .h only (:54) | drags main/snort.h + managers/module_manager.h + parser/parser.h (all grep-0 cp'd) + lua/lua.h (LuaJIT LIVE at /opt/data/tools/luajit-src since 17k but lua.{h,cc} not in this donor); consumes FILE_ID_NAME/FILE_ID_HELP consts 17u landed; ALSO the home of FileIdModule::load_config — the 17w witness body lives on this row's real TU |

17w plan (`file_inspect.{h,cc}`, 42+175 — smallest fully tractable, cp
delta ONE file): new `tools/finspect_harness` from the **fcapi** donor
(smallest; witness delta measured above = 4 NEW witness bodies + 2
donor witness retirements — nm-verify per the fcapi PLAN recipe);
vectors = configure() null-config early return + the REAL FileCache
timeout/cap arm ladder (set_block_timeout/set_lookup_timeout/
set_max_files from the FileConfig fields — file_cache.rs setters
ported 17p), `FileService::set_max_file_depth` (stub :469, instrument
it), the get_file_adv_pub_id static round-trip (DataBus::get_id
witness id -> static -> getter :87), the mp_dbus=true arm
(register_event_helpers + subscribe(new FileCacheShare()) witness
prints), file_config_show over all 13 ConfigLogger keys + the three
FileService enable flags, the sin_file_flow InspectApi record consts
(PT_INSPECTOR/API_OPTIONS/FILE_ID_NAME+HELP 17u consts/IT_PASSIVE/
PROTO_BIT__NONE/"file" + the file_init->REAL FileFlows::init and
file_ctor wiring — probe reads the BaseApi fields through the
`sin_file_flow` global). Rust lands `src/file_api/file_inspect.rs`:
FileInspect over the ported FileConfigLite/FileCache pieces, the
ConfigLogger trait seam (witness-style), the pub-id static, the API
record as consts; watch the 17u LEFT-OPENs (file_config.rs:225-:250:
file_inspect.h:36 `FileConfig* config` IS the named closure target —
the FileEnvLite::file_config seam slot can land here, but only if no
17p/17r pinned vector re-arms).

## Alternative quick-win rows (re-measured at the 17v docs pass; ZERO TEST_CASEs + ZERO `#ifdef UNIT_TEST` across ALL remaining file_api TUs)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| file_service.{h,cc} | 382 (112+270) | 0 | drags `main.h` (`main_packet_threads_fully_paused()` :101), mime/file_mime_process, search_engines/search_tool |
| file_module.{h,cc} | 465 (379+86) | 0 | drags main/snort.h, module_manager, lua; home of FileIdModule::load_config (the 17w witness body) |
| file_log.cc | 329 (no .h) | 0 | drags log/text_log.h (log engine layer) |
| **file_inspect.{h,cc}** | 217 (42+175) | 0 | **17w PICK**; closure complete, cp delta = the .cc only; ConfigLogger/DataBus::get_id/MPDataBus pair/FileIdModule::load_config witnesses land (measured grep-0 in fcapi stubs) |
| file_policy.{h,cc} | 310 (216+94) | 0 | includes measured file_api.h+file_capture.h+file_lib.h+file_service.h+hashes — ALL already real/cp'd in the fcapi donor; queue next after file_inspect |
| file_config.{h,cc} | 208 (80+128) | 0 | DONE 17u |
| file_api.{h,cc} | 270 (227+43) | 0 | DONE 17v (fcapi harness is the freshest donor) |
| file_cache_share.{h,cc} | 115 (40+75) | 0 | DONE 17t |
| file_segment / file_mempool / circular_buffer / file_capture | — | DONE 17r/17s | fcapi harness supersedes all as donor |

## Backlog (plan rows)
- 17s: **DONE (dc94885)** — file_capture proper; wiki trio LANDED (746ae26 + 64ae736 repair).
- 17t: **DONE (3285cd0)** — file_cache_share; wiki trio LANDED (c16d2dc).
- 17u: **DONE (f20da19)** — file_config: src/file_api/file_config.rs 250L (canonical const home +
  free funcs + the two snort:: shim null-arms), tools/fconf_harness vectors 20 lines md5
  65968e1cc11e9489b89762b6c6f3765e tracked, gate stays 114/22 (gate md5 unchanged
  4826fc2233044a2d5429413faf0ae1af), tests/fconf_parity_test.rs 611L 20/20 replay,
  **446 total green**, clippy 0. **Wiki trio for 17u OWED** (owed at the next WIKI phase:
  status row + deviations section + stats line; wiki HEAD c16d2dc carries through 17t).
- 17v: **DONE (254b690)** — file_api umbrella: src/file_api/file_api.rs 467L (canonical vocabulary
  home + FilePolicyBase ref-protocol + pub-use re-points file_lib/file_cache), tools/fcapi_harness
  vectors 21 lines md5 a953a5017b74f5d44dbba14df48ac5ea tracked, gate stays 114/22 (gate md5 unchanged
  4826fc2233044a2d5429413faf0ae1af), tests/fapi_parity_test.rs 243L 21/21 replay,
  **447 total green**, clippy 0. **Wiki trio for 17v OWED** (owed at the next WIKI phase:
  status row + deviations section + stats line; wiki HEAD 7662621 carries through 17u).
- 17w+: file_inspect (PICK), file_policy, file_service, file_log, file_module
  (table above).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO upstream TEST_CASEs in
  codecs/; transcripts are the only ground truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ (AF_PACKET via libc);
  21: snort -q -c end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
