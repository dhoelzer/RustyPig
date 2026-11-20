# NEXT.md — takeover context & plan (2026-11-20, post-17z)

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

Current state (measured at this 17z docs pass): plan rows 1–17z DONE (89
commits counting the 17z code commit ef9bf83 — this docs commit lands as
the 90th, **459 tests green / 0 FAILED** (full `cargo test --all-targets`
re-run AT THIS docs pass: summed `test result` lines = 459 passed / 0
failed), `cargo clippy --all-targets` **0 warnings**, 39,743 lines Rust
across 121 `src/*.rs` files, 31 `tests/*_parity_test.rs` whole-transcript
replay tests among 56 test files, 331 tracked files, 38
`tools/*_harness` dirs). GitHub wiki https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `b71494a` = row 17y trio LANDED: status row +
deviations section + stats line; verified read-only at this docs pass —
`git -C /tmp/RustyPig.wiki log --oneline -3` prints
`b71494a row 17y: status + deviations + stats (88 commits / 324 files /
38,617 src lines / 450 tests)` atop `8d74e32 row 17x`, and `grep -rnE
'17z' /tmp/RustyPig.wiki --include='*.md'` is EMPTY — the wiki is NEVER
touched by code or plan rows). **The 17z wiki trio is OWED** and is owed
at the NEXT WIKI phase, not by this docs pass (status row + deviations
section + stats line "331 tracked files / ~39,700 src lines / 89+
commits / 459 tests"); the 17y trio is no longer debt — landed at
b71494a.

Deviations verdict for row 17z (KNOWN DEVIATIONS.md section landed WITH
the code commit ef9bf83, 105 lines; audited by re-grounding claims THIS
pass): **adequate — leave as-is, no follow-up edits.** Spot-verification:
the ONLY landed-file edit outside mod.rs is the `get_utf8_fname`
visibility widening (`fn` -> `pub(crate) fn`, file_lib.rs:1792, body
BYTE-untouched — matches the ef9bf83 diff hunk);
`InspectApiRecord.service` is `&'static str` (file_inspect.rs:498) so
the cc:312 nullptr slot's empty-string collapse is structurally forced,
not invention; the landed `Parameter` struct (parameter.rs:36-:42) has
no `help` slot — the cc:233/:237 help strings pinned only in the
FL_PARAMS doc comment matches the code; VERDICT_NAME reuse (file_lib.rs
-:62, 8 rows incl. index-7 INVALID) greps real. The base-class-skipping
(Inspector/Module plumbing closed harness-side by the REAL module.o) +
THREE-cells (Rc stats / Option<TextLog> / clock injection) +
registration-only bus + free-signature drops (DataEvent&/Flow*) cluster
matches the vectors' observable semantics (V7 alias lines, V3_sub
stashed-only, V4c partial-line arms). No deviation in the section lacks
an anchor cite verified this pass.

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
   file_lib recipe, build.sh heredoc `FIXLIBUT`). The 17y row added
   the INVERSION lesson: when a donor carries a WITNESS BLOCK for the
   row TU, landing the real TU retires the whole block (23 hard
   collisions, fsvc build.sh :706-:707/:778/:827 nm pins) — the
   retire-evidence echo is the guard, not a silent link failure.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fsvc_parity_test.rs` (the freshest: 890 lines, whole
   64-line replay + drift/retirement narrative pins),
   `tests/fpolicy_parity_test.rs`, `tests/fctx_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 450; never
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
- `tools/flog_harness/` — **the NEW donor for the remaining file_api rows (18a+)**: fresh from the fsvc donor; **cp deltas** = `file_log.cc` appended to the file_api braces :153 (+ `text_log.{h,cc}` + `log.h` appended to the log braces :185 — `text_log.cc:45` includes `log.h`; `messages.cc` STAYS OUT, R6 resident-trio guard) + REAL cp `framework/module.cc` :192 (+ compile-only header cps `utils/stats.h`, `main/stats_output_format.h` — the header-only `module.cc:28 -> stats.h:31` chain, zero link contribution); THREE dirs join the objs loop (`file_log`, `text_log` = the NEW `d=log` case, `module`); the ONE flowz graft delta since 17q (witness Flow + uint16 `client_port`/`server_port`, real flow.h:586-:587) + the ONE shim delta (`main/snort_config.h` + `#include "framework/inspector.h"`, real snort_config.h:35 — the `class FileLog : public Inspector` chain); stubs.cc 938L = fsvc lineage + the NEW17z block, **ZERO retirements** (W1 plain `DataBus::subscribe` :908 + W2 `show_stats` pair :924/:931 = exactly the two app residues of the two link-added .o's, scratch residue_final.txt); build.sh self-checks :853-:854 pin file_log.cc TEST_CASE/UNIT_TEST = 0 and :857 the same for the newly-added module.cc; vectors.txt 50 lines md5 `b260ec6ae0be7ebbf4e0e60338b8cee3` (committed, NEVER edit); gate UNCHANGED = gate.txt md5 `4826fc2233044a2d5429413faf0ae1af` byte-ident (EIGHTH straight). Its cp braces (:153) + objs loop now carry the FULL file_api closure EXCEPT `file_module.cc` (the `.h` is already cp'd in the same braces — the only file_api TU still absent; see the 18a scoping below).
- `tools/fsvc_harness/` — the 17y donor (**superseded by flog; kept for lineage**): fresh from the fpolicy donor; **cp delta TWO entries** (`file_service.cc` appended to the cp braces :96 + the objs loop :464, AND `target_based/snort_protocols.cc` appended to the same loop — real-cp parity for `ProtocolReference::find`, snort_protocols.cc:92, residue zero app-NEW after it); FIXACC python block at :311 (file_service.h was already in the donor graft list); stubs.cc 879L = fpolicy lineage + the 17y RETIREMENT comment :591 (whole donor FileService witness block gone — the landmine inversion, 23 hard collisions) + the get_file_processed_size retire :726 + 4 NEW witness bodies (pause int :611, MimeSession::init/exit :626, InspectorManager::get_inspector :631; include `mime/file_mime_process.h` :29); build.sh self-checks :773-:775 pin the row TU TEST_CASE/UNIT_TEST = 0, :706-:707 pin the row .o's own T defs, :827 echoes nm retire evidence; vectors.txt 64 lines md5 `54864705dd654a18585960a13a853baf` (committed, NEVER edit); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af` byte-ident (SEVENTH straight zero-regression row). Its cp braces (:96) + objs loop (:464) ALREADY carry the FULL file_api closure incl. file_service.cc + file_module.h + the real snort_protocols.cc — see the 18a scoping below (file_log.cc landed 17z; file_module.cc is the only file_api TU still absent).
- `tools/fpolicy_harness/` — the 17x donor (superseded by fsvc; kept for lineage): fresh from the finspect donor; **cp delta EXACTLY TWO FILES** (`file_policy.{h,cc}` appended to the cp braces :87 + the objs loop :426; FIXACC :291 gains `file_api/file_policy.h` — n=1 private at h:82, access-only); stubs.cc 877L with the ONE 17x witness edit (enable_file_capture real cascade :598-:602); vectors.txt 27 lines md5 `b989a8d5cddaf0a2289f5528121ddf35` (committed, NEVER edit); gate md5 `4826fc2233044a2d5429413faf0ae1af` (sixth straight).
- `tools/finspect_harness/` — the 17w donor (kept for lineage): cp delta ONE file (`file_inspect.cc`, braces :63 + loop :396); stubs.cc 873L = fconf-lineage + 4 NEW witness bodies (DataBus::get_id, the MPDataBus reg_helpers/subscribe pair, the ConfigLogger log_flag/log_value pair, the FileIdModule::load_config steal witness) + 2 retirement comments (:347 get_file_adv_pub_id, :507 FileInspect body block); vectors.txt 103 lines md5 `3cbd009e9bb4228ee427ed3fadc64fb4` (committed, NEVER edit).
- `tools/fcapi_harness/` — the 17v donor (kept for lineage): ZERO cp delta for the row TU — file_api.{h,cc} sat in the donor (cp :54, loop :386); gate md5 `4826fc2233044a2d5429413faf0ae1af`; vectors.txt 21 lines md5 `a953a5017b74f5d44dbba14df48ac5ea` (committed, NEVER edit); probe arms C_sz/E_enums/M_flags/P_/S_enc/R_. NB the harness dir is `fcapi_harness` (the 17u NEXT.md said `fapi_harness` — pinned name, do not "fix" the code).
- `tools/fconf_harness/` — the 17u donor (kept for lineage): ZERO cp delta; vectors.txt 20 lines md5 `65968e1cc11e9489b89762b6c6f3765e` (committed, NEVER edit); stubs.cc = fcshare donor + ONE toggle (`fconf_set_file_inspector_null`).
- `tools/fcshare_harness/` — the 17t donor (kept for lineage): cp-list adds ONLY `file_cache_share.{h,cc}`; vectors.txt 25 lines md5 `03d43c143440bd2a101d56818fd20be4` (committed, NEVER edit); gate UNCHANGED.
- `tools/fcap_harness/` — the 17s donor (kept for lineage): vectors.txt 27 lines md5 `0208a69116861a506f0c46a7dc36b2ac` (committed, NEVER edit); gate md5 `4826fc2233044a2d5429413faf0ae1af` (the 114/22 chain STARTS here).
- `tools/fctx_harness/` — donor for any row reaching FileContext + capture/mempool/segment closure: the probe-mode file_lib.cc with ONLY the :1363 UNIT_TEST block excised, the 3-UT-TU gate link (18 cases / 91 assertions), FileCaptureTestAccess-shaped witnesses. vectors.txt 610 lines md5 `839b5566be0a2191876e0f34b4ed56e4`; gate.txt md5 `42349372258e49db1a8f4f60e7a27ed6`. `tools/fctx_harness/PLAN.md` is the RECON→HARNESS→PORT contract example.
- `tools/fflows_harness/` — per-flow FileFlows + FlowData graft donor: the flowz/flow_fwd.h Flow `get_flow_data`/`set_flow_data` single-slot graft (flow.h:195/200), FIXACC access-only file_api.h extension. vectors.txt 146 lines md5 `bd8c00af7a7047ef5b745a34c2a0df55` (committed, DO NOT touch); gate 8/22 md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: real `hash/xhash.cc` + `hash/hash_lru_cache.cc` + `time/packet_time.cc`, the Flow key graft (uint32->uint16 asid truncation pinned), hwloc excision, IpsContext `conf` witness. vectors.txt 278 lines md5 `b69db31078f6bf6be88eba7615378748` (committed, DO NOT touch); gate 7/42 md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure, witness bodies, interposed SnortClock fake clock (`filib_enable_fake_clock`/`filib_set_fake_now` governs SnortClock; packet_time is a SEPARATE packet clock — enumerate BOTH clocks a subsystem reads). vectors 273 lines md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (committed, DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE, never leaks out.
- `tools/textlog_harness/` — row 16r: compiles the ORIGINAL `log/text_log.cc` + `main/thread.cc` (build.sh :16 cp + :138 compile) with a deterministic `time()` interposition (:120) — THE recipe precedent for 17z's text_log drag (cp `log/{text_log.h,text_log.cc,log.h,messages.h,messages.cc,log_errors.h}` + the clock shim).
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/fstats_harness/` — file_api header closure, stats snapshot witnesses.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe.

## Next milestone — row 18a: file_module.{h,cc} (the file_inspect Module TU, FileIdModule: the parameter ladder + the load_config STEAL close; probe-vectors-only)

Freshly measured this pass (ground greps in `/opt/data/snort3-src` READ-
ONLY; donor copy-tree greps in `tools/flog_harness/copy/` — flog is the
freshest donor; the fsvc-era scoping for this TU is superseded):

- **Size/gate facts (re-measured):** `wc -l` = 86 + 379 = **465**;
  `grep -c 'TEST_CASE'` file_module.cc = **0**; `grep -c 'ifdef
  UNIT_TEST'` = **0** on BOTH .cc and .h (measured at this pass) ->
  probe-vectors-only, gate must stay byte-ident
  `4826fc2233044a2d5429413faf0ae1af` = **NINTH straight**
  zero-regression row; `file_module.h` is ALREADY cp'd in the flog donor
  cp braces (build.sh :153) — `file_module.cc` is the ONLY file_api TU
  still absent from the cp braces + objs loop (same brace pattern, so
  the .cc delta is one append + one objs entry).
- **THE load_config CLOSE (with cites): 17w's REPLACE-ME witness dies
  THIS row.** The REAL `FileIdModule::load_config(FileConfig*&)` body
  is file_module.**cc:263-:266** (`dst = fc; fc = nullptr;` — re-read
  this pass; decl file_module.h:61, plain member fn, NOT virtual).
  Landing the real TU RETIRES the flog-donor 17w witness trio under the
  dup-symbol rule (17y landmine-inversion precedent — retire-evidence
  nm echo, not a silent link): `tools/flog_harness/stubs.cc` **:419**
  (the `extern "C" void _ZN12FileIdModuleC1Ev()` empty ctor shim — the
  real FileIdModule ctor at file_module.cc turf defines it),
  **:423-:424** (`g_wit_mod_storage`/`g_wit_mod` pinned raw storage),
  **:425-:441** (witness #7 `FileIdModule::load_config` replicating the
  steal over the heap-only slot + `finspect_arm_mod_fc` :432) and the
  **:439-:447** `fcache_set_file_inspector` ctor-wiring comment (the
  toggle that arms the witness FileIdModule for the finspect/flog
  replays — it must keep working after the trio retires, exactly the
  17y extern-C-arm VERBATIM rule). The flog vectors.txt stays
  byte-frozen; the trio retire is harness-side ONLY.
- **Drags RE-VERIFIED in the copy tree (`tools/flog_harness/copy/`),
  this pass** (include cites from ground file_module.cc:35-:48):
  `control/control.h` :35 **PRESENT** (copy/control/control.h — the
  LogRespond macro, control.h:99); `log/messages.h` :36 PRESENT
  (resident); `main/snort_config.h`, file_api/file_{cache,service,
  stats}.h :44-:46 PRESENT-REAL; `packet_io/active.h` :41 +
  `trace/trace.h` :42 PRESENT (both joined the 17z cp). ABSENT, as the
  17y pass said, re-verified: **`lua/lua.h` :37 — NO copy/lua dir at
  all** (LuaJIT 2.1 LIVE at /opt/data/tools/luajit-src since 17k, but
  lua.{h,cc} has never entered a file_api donor; the two lua_State*
  command bodies at cc:281-:352 are the only real consumers — decide
  cp-vs-witness by file_module.o residue FIRST, flog PLAN 2 style);
  **`main/snort.h` :38 — copy/main carries ONLY
  policy.h/snort_config.h/snort_types.h/stats_output_format.h/thread.h/
  thread_config.h** (NEVER cp main.cc — the 17y R6 monolith rule);
  **`managers/module_manager.h` :40 — copy/managers carries ONLY
  inspector_manager.h** (one body needed: `ModuleManager::get_includer`
  at cc:258 inside `end()`); **`parser/parser.h` :48 — copy/parser
  carries ONLY parse_utils.h** (one body needed:
  `parser_append_rules_special` at cc:259). Consumption of the 17u
  consts: FILE_ID_NAME/FILE_ID_HELP land file_config.rs:91-:92 this
  row (their own note says the file_module row consumes them);
  `grep -rn 'FileIdModule' src/` = comment-only hits (file_inspect.rs
  :302-:303 steal-ctor doc, :477 vtable-hole note — the REAL Rust steal
  already rides the 17w FileConfigLite h:36 slot).

Queue-row-18 scale note (re-grepped THIS pass; do NOT restate it in the
18a PLAN.md): the codecs tree measures **11,914** lines over 48
.c+.h files and the old "verified NO upstream TEST_CASEs in codecs/"
note is **STALE** — exactly **1** TEST_CASE exists (cd_gre.cc:352
[cd_gre], inside `#ifdef UNIT_TEST` :351, whole file 366 L). The
DETECTION tree (queue row 19, ~30k+ subset claim) measures **14,533**
.h+.cc lines with **~47** embedded TEST_CASEs (fp_utils.cc 21,
detection_options.cc 6, ips_context.cc 5, extract.cc 5,
ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2, sfrim.cc 1,
ips_context_data.cc 1) — transcripts remain the primary ground truth,
but row 19 has real Catch material to carry like 17f/17r did.

## Alternative quick-win rows (re-measured at this 17z docs pass; ZERO TEST_CASEs + ZERO `#ifdef UNIT_TEST` across ALL remaining file_api TUs)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| **file_log.cc** | 329 (NO .h) | 0 | **DONE 17z** (ef9bf83; tools/flog_harness = NEW donor, vectors 50L md5 b260ec6ae0be7ebbf4e0e60338b8cee3, gate 8th straight byte-ident; zero-retirement row) |
| **file_module.{h,cc}** | 465 (86+379) | **0** (re-measured this pass, .cc and .h) | **18a PICK**; drags re-verified in the FLOG copy tree (lua/lua.h + main/snort.h + managers/module_manager.h + parser/parser.h grep-0 PRESENT; everything else resident); **closes the 17w load_config witness trio (flog stubs.cc:419/:423/:433, real body file_module.cc:263-:266) — scoping above** |
| **file_service.{h,cc}** | 382 (112+270) | 0 | **DONE 17y** (fsvc harness = freshest donor; gate 7th straight byte-ident; vectors md5 54864705dd654a18585960a13a853baf) |
| **file_policy.{h,cc}** | 310 (216+94) | 0 | DONE 17x |
| **file_inspect.{h,cc}** | 217 (42+175) | 0 | DONE 17w |
| file_config.{h,cc} | 208 (80+128) | 0 | DONE 17u |
| file_api.{h,cc} | 270 (227+43) | 0 | DONE 17v |
| file_cache_share.{h,cc} | 115 (40+75) | 0 | DONE 17t |
| file_segment / file_mempool / circular_buffer / file_capture | — | DONE 17r/17s | fsvc harness supersedes all as donor |

## Backlog (plan rows)
- 17u: **DONE (f20da19)** — file_config; wiki trio LANDED (7662621).
- 17v: **DONE (254b690)** — file_api umbrella; wiki trio LANDED (29e05a3).
- 17w: **DONE (5bebf3b)** — file_inspect; wiki trio LANDED (576f8f2).
- 17x: **DONE (693b61c)** — file_policy; wiki trio LANDED (8d74e32).
- 17y: **DONE (3093f5e)** — file_service: FileServiceLite real statics+ladder arms in file_lib.rs (+556L; shadows/Cells per deviations row 17y — NO new src/file_api/file_service.rs, the FileServiceLite home stays file_lib.rs), real snort_protocols cp (ProtocolReference::find parity), MimeApi trait seam + FileEnvLite.proto_ref, FileCaptureFactory init_capture/exit_capture defaulted arm, decode_conf STAYS SEAM (no DecodeConfig in src/, grep-0), file_processing_initiated NOT ported (dead upstream); tools/fsvc_harness vectors 64L md5 54864705dd654a18585960a13a853baf tracked, gate UNCHANGED (md5 4826fc2233044a2d5429413faf0ae1af, SEVENTH straight), the donor FileService witness block FULLY retired (23-symbol landmine inversion, build.sh :706/:778/:827 pins) + get_file_processed_size witness retired (Rust keeps its 17q home in file_flows.rs), tests/fsvc_parity_test.rs 890L 64/64 replay, **450 total green**, clippy 0. **Wiki trio for 17y LANDED (b71494a)** — wiki HEAD now covers through 17y.
- 17z: **DONE (ef9bf83, code)** — file_log.cc 329L single TU, NO .h (existence pin): src/file_api/file_log.rs 1114L FRESH over the landed text_log.rs (row 16r; ZERO Rust-side edits there) + log/messages.rs; sin_file[] doc-seam readback, FL_PARAMS/FL_PEGS/FL_API const records (17w InspectApiRecord shape; service slot -> "" empty, deviations 17z), sanitizer log_file_name (first-run-byte %02X no-space quirk), one Rc cell = the V7 get_counts alias, DataBusSeam subscribe(snort, 23, file_log) registration-only; the ONLY landed-file edit = file_lib.rs get_utf8_fname fn -> pub(crate) fn (body byte-untouched); tools/flog_harness ZERO retirements + NEW witnesses DataBus::subscribe + show_stats pair; vectors 50L md5 b260ec6ae0be7ebbf4e0e60338b8cee3 tracked, gate UNCHANGED (md5 4826fc2233044a2d5429413faf0ae1af, EIGHTH straight), tests/flog_parity_test.rs 746L 50/50 one-ordered-session replay + 8 lib unit tests (459 total green), clippy 0. **Wiki trio for 17z OWED** (owed at the next WIKI phase: status row + deviations section + stats line; wiki HEAD b71494a carries through 17y — `grep -rnE '17z' /tmp/RustyPig.wiki --include='*.md'` EMPTY verified this pass).
- 18a: file_module (PICK, scoping above). Row 18 (codecs) scale re-measured above: 11,914 L / 48 files, 1 [cd_gre] TEST_CASE at cd_gre.cc:352 (stale no-TEST_CASEs note corrected).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO upstream TEST_CASEs in
  codecs/; transcripts are the only ground truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ (AF_PACKET via libc);
  21: snort -q -c end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
