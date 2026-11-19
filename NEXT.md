# NEXT.md — takeover context & plan (2026-11-19, post-17x)

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

Current state (measured at this 17x docs pass): plan rows 1–17x DONE (86
commits counting this 17x docs commit, **449 tests green / 0 FAILED**,
`cargo clippy --all-targets` **0 warnings**, 38,068 lines Rust across
120 `src/*.rs` files, 29 `tests/*_parity_test.rs` whole-transcript
replay tests among 54 test files, 318 tracked files, 36 `tools/*_harness`
dirs). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `576f8f2` = row 17w trio LANDED: status row +
deviations section + stats line; verified read-only at this docs pass —
`git -C /tmp/RustyPig.wiki log --oneline -3` prints
`576f8f2 row 17w: status + deviations + stats` atop `29e05a3 row 17v`,
and `grep -rn '17x' /tmp/RustyPig.wiki --include='*.md'` is EMPTY — the
wiki is NEVER touched by code or plan rows). **The 17x wiki trio is
OWED** and is owed at the NEXT WIKI phase, not by this docs pass
(status row + deviations section + stats line "318 tracked files /
~38,100 src lines / 86 commits / 449 tests"); the 17w trio is no
longer debt — landed at 576f8f2.

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
5. **Gates at EVERY commit**: `cargo test` all green (>= 449; never
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
- `tools/fpolicy_harness/` — **the NEW donor for the remaining file_api rows (17x)**: fresh from the finspect donor; **cp delta EXACTLY TWO FILES** (`file_policy.{h,cc}` appended to the cp braces :87 + the objs loop :426; FIXACC :291 gains `file_api/file_policy.h` — n=1 private at h:82, access-only, build.sh :285-:290 explains); stubs.cc 877L = finspect lineage VERBATIM + the ONE 17x witness edit (enable_file_capture upgraded to the REAL cascade, :598-:602; NEW witness bodies ZERO, retirements ZERO — the R5 landmine assert pins stubs.o carries zero T FilePolicy::/FileRule:: defs, build.sh :632-:633 pin the row .o's own T defs + vtable); vectors.txt 27 lines md5 `b989a8d5cddaf0a2289f5528121ddf35` (committed, NEVER edit); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af` byte-ident (sixth straight zero-regression row; build.sh :683-:685 hard-assert the row TU's TEST_CASE/UNIT_TEST = 0). Its cp-list (:87) + compile loop (:426) ALREADY carry the full file_api closure incl. file_policy — see per-candidate table below. NB the cp-list still carries NO `file_service.cc` / `file_log.cc` / `file_module.cc` (only their .h where noted) — that is where 17y's cp delta starts.
- `tools/finspect_harness/` — the 17w donor (superseded by fpolicy; kept for lineage): fresh from the fcapi donor; **cp delta EXACTLY ONE file** (`file_inspect.cc` appended to the cp braces :63 + the generic compile loop :396; the FIXACC access-graft list :261 stays as-is — file_inspect.h does NOT join it, build.sh :9 explains why); stubs.cc 873L = fconf-lineage + 4 NEW witness bodies (DataBus::get_id, the MPDataBus reg_helpers/subscribe pair, the ConfigLogger log_flag/log_value pair, the FileIdModule::load_config steal witness) + 2 retirement comments (:347 get_file_adv_pub_id, :507 FileInspect body block — the dup-symbol rule R5); vectors.txt 103 lines md5 `3cbd009e9bb4228ee427ed3fadc64fb4` (committed, NEVER edit).
- `tools/fcapi_harness/` — **the 17v donor (superseded by finspect)**: fresh from the fconf donor; **ZERO cp delta** for the row TU — file_api.{h,cc} sit in the donor cp-list (:54) and the generic compile loop (:386); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af` (byte-ident to the fconf/fcshare donor — the row added ZERO TEST_CASEs; build.sh self-checks :574-:576 grep-pin the TU's TEST_CASE/UNIT_TEST = 0). vectors.txt 21 lines md5 `a953a5017b74f5d44dbba14df48ac5ea` (committed, NEVER edit); probe arms C_sz/E_enums/M_flags/P_/S_enc/R_ (see PLAN §5); stubs.cc = fconf donor VERBATIM (incl. the fconf_set_file_inspector_null toggle :371). Its cp-list (:54) + compile loop (:386) + explicit block (:409-:414) ALREADY carry the full file_api closure incl. file_api itself — see per-candidate table below. NB the harness dir is `fcapi_harness` (the 17u NEXT.md said `fapi_harness` — pinned name, do not "fix" the code).
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

## Next milestone — row 17y: file_service.{h,cc} (the FileService statics TU: the enable-flag trio + max_file_depth ladder + the cache-clear posture + the init/close lifecycle over the REAL file_api closure)

Freshly measured this pass against `/opt/data/snort3-src/src/file_api`
(`wc -l`; combined `grep -c 'TEST_CASE\|ifdef UNIT_TEST'` per TU — ALL
THREE remaining queue TUs measure ZERO, so 17y stays probe-vectors-only;
donor cp/compile column = presence in `tools/fpolicy_harness/build.sh`
cp braces :87, FIXACC list :291, and the objs loop :426 — re-checked by
`grep` this pass):

| candidate | .h+.cc lines | TEST_CASEs | in fpolicy donor? | blockers |
|---|---|---|---|---|
| **file_service** (17y PICK) | 112+270 = 382 | **0** (.h grep 0 + .cc grep 0, measured this pass) | `.h` cp'd (:87) + FIXACC (:291); `.cc` NOT cp'd / NOT in the objs loop (:426 grep-0 — 17y cp delta = file_service.cc appended to the braces + the loop) | drag risks BELOW; the FULL FileService witness block (stubs.cc:575-:637: the four statics :584-:589, lifecycle :590-:595, enable trio :596-:602, get/set_max_file_depth :605-:633 incl. the instrumented REAL-shape walk, collect_cache_usage :634, clear-status pair :635-:636, reset :637) gets REPLACED by the real TU under the dup-symbol rule (all retire together) |
| file_log (no .h) | 329 | **0** (measured) | NOT cp'd (grep-0 in build.sh) | drags log/text_log.h (cc:27, grep-0 cp'd — TextLog engine layer, new witness; Rust-side twin src/log/text_log.rs 422L already LANDED) + Module/PegInfo bodies (framework/module.h cp'd :97, body NOT); data_bus/packet_time/file_config/file_flows/file_lib all REAL or already witnessed |
| file_module | 86+379 = 465 | **0** (measured) | .h only (:87); .cc NOT cp'd/compiled | drags main/snort.h (:38) + managers/module_manager.h (:40) + parser/parser.h (:48, only parse_utils.h cp'd :108) + lua/lua.h (:37 — LuaJIT LIVE at /opt/data/tools/luajit-src since 17k but lua.{h,cc} not in this donor); consumes the 17u FILE_ID_NAME/FILE_ID_HELP consts; ALSO the **home of FileIdModule::load_config (file_module.cc:263, body verified this pass: `dst = fc; fc = nullptr;`)** — the 17w witness body (donor stubs.cc:418-:430, incl. the empty FileIdModule ctor shim :412) gets REPLACED by the real TU here |

Drag-risk cite verdicts for 17y (each verified by grep read THIS pass —
one-line verdicts):

1. **main pause**: `main_packet_threads_fully_paused()` called at
   file_service.cc:101 (get_file_cache_clear_status; decl src/main.h:56,
   def src/main.cc:325) — donor cp's NO main.h (only snort_types.h/
   thread.h/thread_config.h :103) and stubs.cc grep-0 => NEW witness
   (armable bool; verdict: cheap).
2. **mime**: include cc:37; REAL calls `MimeSession::init()` cc:121 and
   `MimeSession::exit()` cc:179 (MimeSession class file_mime_process.h:66,
   static pair :78-:79) => NEW witness pair stub-init/stub-exit
   (verdict: cheap; the mime row itself stays queued — do NOT cp the
   mime TU).
3. **search_tool**: include cc:38 ONLY — grep shows ZERO symbol use in
   file_service.cc bodies => compile-only header cp, no witness
   (verdict: free).
4. **stats::Builder/Group**: `collect_cache_usage(stats::Builder&,
   stats::Group&)` at cc:76, body calls `builder.counter(group, "File
   cache entries", ...)` => the harness needs snapshot.cc witness bodies
   OR grafts, but the RUST side is DONE: src/utils/stats/snapshot.rs
   Group :108 / Builder :142 / Builder::counter :193 already landed —
   the Rust collect_cache_usage ports clean (verdict: harness-side only).
5. **inspector_manager**: include cc:36; `InspectorManager::get_inspector
   ("file_inspect", Module::GLOBAL)` called at cc:68 (reset) — real
   header cp'd (build.sh :102) but get_inspector has NO witness body
   (donor stubs only carry acquire/get_file_inspector/release :445-:464)
   => NEW witness returning the armed inspector/null (verdict: cheap).
   (log/log_stats.h cc:32 cp'd :110 + utils/stats/snapshot.h cc:39
   cp'd :96 — headers already resident.)

17y plan (`file_service.{h,cc}`, 112+270; witnesses mostly resident as
REPLACE-ME bodies): new `tools/fsvc_harness` from the **fpolicy** donor
(smallest current donor; cp delta ONE file: file_service.cc to braces
:87 + loop :426); retire the whole donor FileService witness block under
the dup-symbol rule, arm the real statics instead; ~4 NEW witnesses per
the verdict list (pause bool, MimeSession pair, get_inspector); the set_
max_file_depth instrumented walk (file_service.cc:227-:251) becomes the
REAL body — the donor printed SMD arms already mirror it, expect ZERO
vector drift there; keep fcache_set_file_cache/fpolicy toggles working
(real file_cache static now defined by the real TU); gate must stay
byte-ident 4826fc2233044a2d5429413faf0ae1af = SEVENTH straight
zero-regression row. Rust lands src/file_api/file_service.rs: move/
extend the FileServiceLite statics (file_lib.rs trio already grew the
capture_enabled arm + the real enable_* bodies at 17x) into the proper
TU, clear_file_cache posture (NOT_INITIALIZED / PACKET_THREADS_BUSY /
READY arms), collect_cache_usage over the landed stats Builder/Group.

## Alternative quick-win rows (re-measured at this 17x docs pass; ZERO TEST_CASEs + ZERO `#ifdef UNIT_TEST` across ALL remaining file_api TUs)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| **file_service.{h,cc}** | 382 (112+270) | 0 | **17y PICK**; drag cites verdicted above: pause witness cc:101 cheap, MimeSession::init/exit cc:121/:179 pair, search_tool.h cc:38 header-only FREE, stats::Builder cc:76 harness-side only (Rust twin landed), get_inspector cc:68 cheap |
| file_module.{h,cc} | 465 (379+86) | 0 | drags main/snort.h + module_manager + parser/parser.h + lua; home of FileIdModule::load_config (file_module.cc:263 — the 17w witness body, retire target) |
| file_log.cc | 329 (no .h) | 0 | drags log/text_log.h cc:27 (log engine layer; Rust twin src/log/text_log.rs 422L LANDED) + Module/PegInfo bodies |
| **file_policy.{h,cc}** | 310 (216+94) | 0 | DONE 17x (fpolicy harness = freshest donor; gate 6th straight byte-ident) |
| **file_inspect.{h,cc}** | 217 (42+175) | 0 | DONE 17w |
| file_config.{h,cc} | 208 (80+128) | 0 | DONE 17u |
| file_api.{h,cc} | 270 (227+43) | 0 | DONE 17v |
| file_cache_share.{h,cc} | 115 (40+75) | 0 | DONE 17t |
| file_segment / file_mempool / circular_buffer / file_capture | — | DONE 17r/17s | fpolicy harness supersedes all as donor |

## Backlog (plan rows)
- 17s: **DONE (dc94885)** — file_capture proper; wiki trio LANDED (746ae26 + 64ae736 repair).
- 17t: **DONE (3285cd0)** — file_cache_share; wiki trio LANDED (c16d2dc).
- 17u: **DONE (f20da19)** — file_config: src/file_api/file_config.rs 250L (canonical const home +
  free funcs + the two snort:: shim null-arms), tools/fconf_harness vectors 20 lines md5
  65968e1cc11e9489b89762b6c6f3765e tracked, gate stays 114/22 (gate md5 unchanged
  4826fc2233044a2d5429413faf0ae1af), tests/fconf_parity_test.rs 611L 20/20 replay,
  **446 total green**, clippy 0. **Wiki trio for 17u LANDED (7662621)**.
- 17v: **DONE (254b690)** — file_api umbrella: src/file_api/file_api.rs 467L (canonical vocabulary
  home + FilePolicyBase ref-protocol + pub-use re-points file_lib/file_cache), tools/fcapi_harness
  vectors 21 lines md5 a953a5017b74f5d44dbba14df48ac5ea tracked, gate stays 114/22 (gate md5 unchanged
  4826fc2233044a2d5429413faf0ae1af), tests/fapi_parity_test.rs 243L 21/21 replay,
  **447 total green**, clippy 0. **Wiki trio for 17v LANDED (29e05a3)**.
- 17w: **DONE (5bebf3b)** — file_inspect: src/file_api/file_inspect.rs 536L (steal ctor closes the 17u
  h:36 LEFT-OPEN; real pub-id getter + file_lib.cc:658 publish-seam swap; configure ladder w/ REAL
  FileCache/FileCacheShare/FileFlows; ConfigLogger collapsed onto real 17j; 2 witness blocks retired via
  dup-symbol rule; SMD show trio; SIN record), tools/finspect_harness vectors 103L md5
  3cbd009e9bb4228ee427ed3fadc64fb4 tracked, gate UNCHANGED (md5 4826fc2233044a2d5429413faf0ae1af,
  fifth straight), tests/finspect_parity_test.rs 497L 103/103 replay, **448 total green**, clippy 0.
  **Wiki trio for 17w LANDED (576f8f2)** — no longer debt; the 17x trio is what the wiki owes now.
- 17x: **DONE (693b61c)** — file_policy: src/file_api/file_policy.rs 637L (real FilePolicy over the
  17v FilePolicyApi/FilePolicyHandle seam; add_file_id unconditional-enable quirk + std::stoi panic arms;
  NetworkPolicy seam swap witness->REAL; store_file_async joined FileCaptureApi; enable_file_capture
  cascade pin), tools/fpolicy_harness vectors 27L md5 b989a8d5cddaf0a2289f5528121ddf35 tracked, gate
  UNCHANGED (md5 4826fc2233044a2d5429413faf0ae1af, sixth straight), tests/fpolicy_parity_test.rs 550L
  27/27 replay, **449 total green**, clippy 0. **Wiki trio for 17x OWED** (owed at the next WIKI phase:
  status row + deviations section + stats line; wiki HEAD 576f8f2 carries through 17w).
- 17y+: file_service (PICK), file_log, file_module (table above).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO upstream TEST_CASEs in
  codecs/; transcripts are the only ground truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ (AF_PACKET via libc);
  21: snort -q -c end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
