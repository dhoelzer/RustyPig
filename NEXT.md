# NEXT.md — takeover context & plan (2026-11-19, post-17u)

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

Current state (measured at the 17u docs pass): plan rows 1–17u DONE (80
commits counting the 17u docs commit, **446 tests green / 0 FAILED**,
`cargo clippy --all-targets` **0 warnings**, 36,386 lines Rust across
117 `src/*.rs` files, 26 `tests/*_parity_test.rs` whole-transcript
replay tests among 51 test files, 297 tracked files, 33 `tools/*_harness`
dirs). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki is the
public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `c16d2dc` = row 17t trio LANDED: status row +
deviations section + stats line; verified read-only at this docs pass —
`git -C /tmp/RustyPig.wiki log` — the wiki is NEVER touched by code or
plan rows). **The 17u wiki trio is OWED** and is owed at the NEXT WIKI
phase, not by this docs pass (status row + deviations section + stats
line "297 tracked files / ~36,400 src lines / 80 commits / 446 tests");
the 17t trio is no longer debt — landed at c16d2dc.

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
5. **Gates at EVERY commit**: `cargo test` all green (>= 446; never
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
- `tools/fconf_harness/` — **the NEW donor for the remaining file_api rows (smallest donor, ZERO new witnesses ever, 17u)**: fresh from the fcshare donor; **ZERO cp delta** — file_config.{h,cc} (and everything the queue needs, see table) already sit in the donor cp-list (:38) and compile-list (:370). gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af` (byte-ident to the fcshare donor — the row added ZERO TEST_CASEs). vectors.txt 20 lines md5 `65968e1cc11e9489b89762b6c6f3765e` (committed, NEVER edit); probe probe.cc D/N/T/F/G/M/S arms; stubs.cc = fcshare donor + ONE toggle (`fconf_set_file_inspector_null`, probe-settable InspectorManager null, pointer swap only).
- `tools/fcshare_harness/` — the 17t donor (superseded by fconf): fresh from the fcap donor; cp-list adds ONLY `file_cache_share.{h,cc}`. vectors.txt 25 lines md5 `03d43c143440bd2a101d56818fd20be4` (committed, NEVER edit); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)". Its cp-list (:35) + compile-list (:365) ALREADY carry the full file_api closure (incl. file_cache_share now) — see per-candidate table below.
- `tools/fcap_harness/` — the 17s donor (superseded by fcshare): fresh from the fctx donor for 17s; the probe link already resolves FileCapture real + FileService statics armable (stubs.cc:440-445) + FileMPEvent real (copy/pub_sub/file_events.h). vectors.txt 27 lines md5 `0208a69116861a506f0c46a7dc36b2ac` (committed, NEVER edit); unified gate `[file_capture]` 4 + `[file_flows]` 8/22 + `[file_cache]` 7/42 = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af`. Its build.sh cp-list (:36) + compile-list (:365) ALREADY compile `file_api.cc` and `file_config.cc` VERBATIM (their .o link in the probe) — header-only `file_service.h`/`file_policy.h` also copied.
- `tools/fctx_harness/` — donor for any row reaching FileContext + capture/mempool/segment closure: everything fflows had, PLUS the probe-mode file_lib.cc with ONLY the :1363 UNIT_TEST block excised, the 3-UT-TU gate link (18 cases / 91 assertions), `FileCaptureTestAccess`-shaped witnesses already resident, and the A/K/L/M/N/O probe blocks over the heavy ladder. vectors.txt 610 lines md5 `839b5566be0a2191876e0f34b4ed56e4` (re-verified byte-identical from a from-scratch rebuild at 17r docs time); gate.txt md5 `42349372258e49db1a8f4f60e7a27ed6`. `tools/fctx_harness/PLAN.md` is the RECON→HARNESS→PORT contract example (its §3 ZERO-new-witness measurement held exactly: the fflows donor link already resolved every heavy-half symbol; 17s repeated the trick — fcap measured ZERO new witnesses too).
- `tools/fflows_harness/` — per-flow FileFlows + FlowData graft donor: the flowz/flow_fwd.h Flow `get_flow_data`/`set_flow_data` single-slot graft (flow.h:195/200), FIXACC access-only file_api.h extension, NetworkPolicy/policy witnesses. vectors.txt 146 lines md5 `bd8c00af7a7047ef5b745a34c2a0df55` (committed, DO NOT touch); gate 8/22 md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc`, the `flowz/flow_fwd.h` Flow key graft (uint32->uint16 asid truncation pinned), `main/thread_config.h` hwloc excision, IpsContext `conf` witness. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (committed, DO NOT touch — vanished witness lines in NEWER transcripts are the retirement signal); gate 7/42, gate.txt md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE, never leaks into fctx.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 17v: file_api.{h,cc} (the consolidation row: shared vocabulary + FilePolicyBase canonical home)

Freshly measured this pass against `/opt/data/snort3-src/src/file_api`
(`wc -l`; `grep -c 'TEST_CASE|ifdef UNIT_TEST'` per TU — ALL SIX
remaining queue TUs plus file_api itself measure ZERO, so 17v stays
probe-vectors-only; donor cp/compile column = presence in
`tools/fconf_harness/build.sh` cp-list :38 and compile-list :370 —
checked by `grep`, identical lists in fcshare :35/:367 (fcshare compile-list sits at :367)):

| candidate | .h+.cc lines | TEST_CASEs | in fconf donor? | blockers |
|---|---|---|---|---|
| **file_api** (17v PICK) | 227+43 = 270 | **0** | cp'd AND compiled VERBATIM (:38/:370 — the .o already links in every file_api probe since 17q) | consolidation, ZERO new closure: FilePolicyBase trio (file_api.cc:28-:41, ref-count `new` protocol) + enums (FileVerdict/FilePosition/FileAction/FileCaptureState/FileSigState/FileProcessType/FileDirection/FileCharEncoding, h:41-:113) + FILE_ID_MAX/FileTypeBitSet (h:118-:119) + FileCacheClearReport h:121-:125 + UserFileDataBase h:132-:141 + the three inline FilePosition helpers h:174-:197 + get_character_encoding h:214-:223; cc ALSO re-declares the two snort:: shims 17u just ported (h:224-:227). Most pieces ALREADY ride interim homes (FileVerdict et al. in file_lib.rs / file_cache.rs: FilePolicyHandle + policy verbs file_cache.rs:549-:600 cites file_api.cc:34 / FILE_ID_MAX+bitset word form file_identifier.rs:21) — 17v = consolidation + canonical home + the unported parts only (position helpers, FileProcessType, UserFileDataBase). get_file_processed_size/get_file_position DECLARATIONS (h:224-:225) live in file_service.cc:256 + file_flows.cc:61 — ported homes, not this TU. |
| file_inspect | 42+175 = 217 | 0 | cp'd (.h only, :38); .cc NOT compiled | queue after 17v: include closure NOW fully resident (file_cache 17p + file_cache_share 17t + file_config 17u + file_module.h + file_service.h + pub_sub ids); gate side needs `InspectorManager::get_file_inspector` armable (already the fconf stubs toggle) + Inspector base (framework/inspector.h already cp'd) |
| file_policy | 94+216 = 310 | 0 | NOT cp'd (ZERO presence in fconf or fcshare cp-list) | drags file_capture.h (REAL 17s) + file_lib (REAL) + hashes (resident) — cp delta = file_policy.{h,cc} only; tractable |
| file_service | .h 112 cp'd, .cc 270 NOT compiled | 0 | .h only (:38/:35) | drags `main.h` (`main_packet_threads_fully_paused()` file_service.cc:101), mime/file_mime_process, search_engines/search_tool — NEW closure work |
| file_log (no .h) | 329 | 0 | NOT cp'd | drags log/text_log.h + framework/module (log engine layer, new) |
| file_module | .h 86 cp'd, .cc 379 NOT compiled | 0 | .h only (:38/:35) | drags main/snort.h + managers/module_manager + lua/lua.h (Lua LIVE 17k but snort.h is heavy); consumes FILE_ID_NAME/FILE_ID_HELP consts 17u landed |

17v plan (`file_api.{h,cc}`, 227+43 — smallest fully tractable, ZERO
cp delta): new `tools/fapi_harness` from the **fconf** donor (smallest;
ZERO new witnesses — the probe link already resolves everything this TU
touches, nm-verify per the fconf PLAN 3/7/8 recipe); vectors =
FilePolicyBase ref-ladder (ctor ref=1 file_api.cc:28,
delete_file_policy decrement/delete :34-:41 incl. null-policy guard
:36, dtor `assert(!ref_count)` :31 posture), the three inline position
helpers over the START/MIDDLE/END/FULL ladder (h:174-:197, the ftp/
dce consumers in upstream cite them — probe directly), get_character_
encoding BOM arms (h:214-:223, UTF_16_LE_BOM "\xFF\xFE" h:50), enum
wire values (FileVerdict 0-7 h:49-:58 etc. — pins vs the interim
homes), UserFileDataBase copy semantics h:132-:141. Rust lands
`src/file_api/file_api.rs` as the canonical vocabulary home and
re-points the interim homes to it with `pub use` (the 17u const-home
recipe — leave every existing binding green). Watch the two-view
LEFT-OPENs from 17u (file_config.rs:225-:250) before re-pointing
anything pinned by 17p/17r vectors.

## Alternative quick-win rows (re-measured at the 17u docs pass; ZERO TEST_CASEs + ZERO `#ifdef UNIT_TEST` across ALL remaining file_api TUs)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| file_service.{h,cc} | 382 (112+270) | 0 | drags `main.h` (`main_packet_threads_fully_paused()` :101), mime/file_mime_process, search_engines/search_tool |
| file_module.{h,cc} | 465 (379+86) | 0 | drags main/snort.h, module_manager, lua |
| file_log.cc | 329 (no .h) | 0 | drags log/text_log.h (log engine layer) |
| file_inspect.{h,cc} | 217 (42+175) | 0 | closure complete since 17u (get_file_inspector toggle live in fconf stubs) — next after file_api |
| file_policy.{h,cc} | 310 (216+94) | 0 | CaptureFilePolicy rides file_capture.h (REAL 17s) + file_lib + hashes (measured includes) |
| **file_api.{h,cc}** | 270 (227+43) | 0 | **17v PICK**; TU already VERBATIM-compiled-and-linked inside fconf/fcshare/fcap harnesses |
| file_config.{h,cc} | 208 (80+128) | 0 | DONE 17u (fconf harness is the freshest donor) |
| file_cache_share.{h,cc} | 115 (40+75) | 0 | DONE 17t |
| file_segment / file_mempool / circular_buffer / file_capture | — | DONE 17r/17s | fconf harness supersedes all as donor |

## Backlog (plan rows)
- 17s: **DONE (dc94885)** — file_capture proper; wiki trio LANDED (746ae26 + 64ae736 repair).
- 17t: **DONE (3285cd0)** — file_cache_share; wiki trio LANDED (c16d2dc).
- 17u: **DONE (f20da19)** — file_config: src/file_api/file_config.rs 250L (canonical const home +
  free funcs + the two snort:: shim null-arms), tools/fconf_harness vectors 20 lines md5
  65968e1cc11e9489b89762b6c6f3765e tracked, gate stays 114/22 (gate md5 unchanged
  4826fc2233044a2d5429413faf0ae1af), tests/fconf_parity_test.rs 611L 20/20 replay,
  **446 total green**, clippy 0. **Wiki trio for 17u OWED** (owed at the next WIKI phase:
  status row + deviations section + stats line; wiki HEAD c16d2dc carries through 17t).
- 17v+: file_api shim (PICK), file_inspect, file_policy, file_service, file_log, file_module
  (table above).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO upstream TEST_CASEs in
  codecs/; transcripts are the only ground truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ (AF_PACKET via libc);
  21: snort -q -c end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
