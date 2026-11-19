# NEXT.md — takeover context & plan (2026-11-19, post-17y)

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

Current state (measured at this 17y docs pass): plan rows 1–17y DONE (87
commits counting the 17y code commit 3093f5e — this docs commit lands as
the 88th, **450 tests green / 0 FAILED**, `cargo clippy --all-targets`
**0 warnings**, 38,617 lines Rust across 120 `src/*.rs` files, 30
`tests/*_parity_test.rs` whole-transcript replay tests among 55 test
files, 324 tracked files, 37 `tools/*_harness` dirs). GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki is the public status doc
(clone at `/tmp/RustyPig.wiki`, remote `RustyPig.wiki.git`, HEAD
`8d74e32` = row 17x trio LANDED: status row + deviations section +
stats line; verified read-only at this docs pass —
`git -C /tmp/RustyPig.wiki log --oneline -3` prints
`8d74e32 row 17x: status + deviations + stats` atop `576f8f2 row 17w`,
and `grep -rnE '17y|17z' /tmp/RustyPig.wiki --include='*.md'` is EMPTY —
the wiki is NEVER touched by code or plan rows). **The 17y wiki trio is
OWED** and is owed at the NEXT WIKI phase, not by this docs pass
(status row + deviations section + stats line "324 tracked files /
~38,600 src lines / 87+ commits / 450 tests"); the 17x trio is no
longer debt — landed at 8d74e32.

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
- `tools/fsvc_harness/` — **the NEW donor for the remaining file_api rows (17z+)**: fresh from the fpolicy donor; **cp delta TWO entries** (`file_service.cc` appended to the cp braces :96 + the objs loop :464, AND `target_based/snort_protocols.cc` appended to the same loop — real-cp parity for `ProtocolReference::find`, snort_protocols.cc:92, residue zero app-NEW after it); FIXACC python block at :311 (file_service.h was already in the donor graft list); stubs.cc 879L = fpolicy lineage + the 17y RETIREMENT comment :591 (whole donor FileService witness block gone — the landmine inversion, 23 hard collisions) + the get_file_processed_size retire :726 + 4 NEW witness bodies (pause int :611, MimeSession::init/exit :626, InspectorManager::get_inspector :631; include `mime/file_mime_process.h` :29); build.sh self-checks :773-:775 pin the row TU TEST_CASE/UNIT_TEST = 0, :706-:707 pin the row .o's own T defs, :827 echoes nm retire evidence; vectors.txt 64 lines md5 `54864705dd654a18585960a13a853baf` (committed, NEVER edit); gate UNCHANGED = "All tests passed (114 assertions in 22 test cases)", gate.txt md5 `4826fc2233044a2d5429413faf0ae1af` byte-ident (SEVENTH straight zero-regression row). Its cp braces (:96) + objs loop (:464) ALREADY carry the FULL file_api closure incl. file_service.cc + file_module.h + the real snort_protocols.cc — see the per-candidate table below: 17z's file_log.cc and the queued file_module.cc are the only file_api TUs still absent.
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

## Next milestone — row 17z: file_log.cc (the file-log Inspector: FILE_VERDICT LogHandler -> TextLog lines into file.log + the FileLogModule/InspectApi record; probe-vectors-only)

Freshly measured this pass (ground `wc -l` + greps in
`/opt/data/snort3-src`; donor presence re-grepped in
`tools/fsvc_harness/build.sh` — cp braces :96, objs loop :464, FIXACC
:311; witness greps in `tools/fsvc_harness/stubs.cc`):

**EXISTENCE FIRST: file_log has NO .h.** `find src -name 'file_log*'`
returns ONLY `src/file_api/file_log.cc` (git ls-files agrees; the donor
cp braces :96 carry NO file_log entry either way); `wc -l src/file_api/
file_log.cc` = **329**. It is a single-TU module (s_name "file_log"
:38, f_name "file.log" :39). Wiki coverage check: `grep -rn
'file_log\|FileLog' /tmp/RustyPig.wiki` = **0** — unmentioned upstream
too (wiki greps are only row statuses; nothing pre-scopes this row).

| candidate | lines | TEST_CASEs / UNIT_TEST | in fsvc donor? | blockers |
|---|---|---|---|---|
| **file_log** (17z PICK) | 329 (NO .h — existence verified above) | **0 / 0** (`grep -c TEST_CASE` 0 + `grep -c UNIT_TEST` 0, measured this pass) | **NOT cp'd at all** — `grep -n 'file_log' tools/fsvc_harness/build.sh` = 0 hits (cp braces :96, objs loop :464) | drags `log/text_log.h` (include **cc:27**; copy/log carries ONLY log_errors.h/log_stats.h/messages.h — text_log.{h,cc} grep-0 cp'd) + `framework/module.h` (cp'd :106 but the Module/PegInfo BODIES not; stubs.cc `grep Peg` = 0 hits) + plain `DataBus::subscribe` (DataHandler registration at cc:212 — stubs.cc has DataBus::publish :268 + get_id :306 + MPDataBus::subscribe :345 but grep-0 plain DataBus::subscribe); data_bus.h/packet_time/file_config/file_flows/file_lib/intrinsic_event_ids all REAL or cp'd already |
| file_module (queued) | 86+379 = 465 | **0 / 0** (measured `grep -c 'TEST_CASE\|ifdef UNIT_TEST'` both files) | `.h` cp'd (:96); `.cc` NOT cp'd / NOT in objs loop | drags main/snort.h (cc:38 — copy/main has NO snort.h: only policy.h/snort_config.h/snort_types.h/thread.h/thread_config.h) + managers/module_manager.h (cc:40 — copy/managers has ONLY inspector_manager.h) + parser/parser.h (cc:48 — ONLY parse_utils.h cp'd :123) + lua/lua.h (cc:37 — NO copy/lua dir at all; LuaJIT LIVE at /opt/data/tools/luajit-src since 17k but lua.{h,cc} never in any file_api donor); **17w-WITNESS-CLOSE home: `FileIdModule::load_config` body at file_module.cc:263-:266 (`dst = fc; fc = nullptr;`, re-read this pass) — landing the real TU RETIRES the fsvc witness trio (stubs.cc:419 empty extern-C ctor shim `_ZN12FileIdModuleC1Ev`, :423-:424 pinned raw storage, :433 witness load_config + the :443-:445 ctor wiring comment) under the dup-symbol rule — closes the 17w REPLACE-ME witness**; consumes the 17u FILE_ID_NAME/FILE_ID_HELP consts |

file_log witness/landmark map (grep-measured in `src/file_api/file_log.cc`
this pass — the probe must pin these): `static const char* s_name =
"file_log"` :38 / `f_name = "file.log"` :39; `struct FileLogConfig` :42;
`struct FileLogStats` :48 with `PegCount total_events` :50;
`THREAD_LOCAL FileLogStats fl_stats` :53; `static const PegInfo
fl_pegs[]` :55 (peg table — Module::get_pegs :247-:248 + get_counts
reinterpret-cast :250-:251); `THREAD_LOCAL TextLog* tlog` :65;
`dl_tinit` :67 / `dl_tterm` :72 (the TextLog open/roll/flush lifecycle);
`class LogHandler : public DataHandler` :81 with `handle(DataEvent&,
Flow*) override` :87/:140 + static `log_file_name(TextLog*,
FileContext*)` :91 — `sys_time` :144 vs `pkt_time` :154 (BOTH clocks:
util `get_time` vs packet_time — the filib two-clock lesson applies);
`class FileLog : public Inspector` :202 subscribing
`DataBus::subscribe(intrinsic_pub_key, IntrinsicEventIds::FILE_VERDICT,
new LogHandler(config))` :212; `FileLog::show` :220; `Parameter
fl_params[]` :230; `class FileLogModule : public Module` :241 +
`mod_ctor` :277 / `mod_dtor` :280 / `fl_ctor` :283 / `fl_dtor` :289 +
`static const InspectApi fl_api` :294 (the sin record — 17w's
InspectApi-as-DATA precedent applies).

Rust-side seam audit (measured this pass): `grep -rn 'FileLog' src/`
= **ZERO hits** — no Rust seam, stub, or placeholder exists anywhere;
17z lands the port FRESH. The TextLog twin IS landed: row 16r landed
`src/log/text_log.rs` **422L** (`wc -l` verified; PLAN row 16r =
log/text_log.{h,cc} + main/thread.cc naming, DONE, with
`tests/textlog_parity_test.rs` landed) — TextLog grep hits are ONLY
src/log/text_log.rs (+ mod.rs + src/parser/parse_stream.rs using it).
The Rust FileLog therefore ports over the LANDED text_log.rs + the
landed log/messages.rs; the FILE_VERDICT publication side (FileCache
apply_verdict -> MPDataBus/DataBus publish) is already REAL from 17p/
17y — 17z is the SUBSCRIBE + format + peg-count half.

17z plan (file_log.cc, 329, probe-vectors-only): new `tools/flog_harness`
from the **fsvc** donor (freshest/smallest; cp delta: `file_log.cc` to
braces :96 + objs loop :464, and `log/text_log.{h,cc}` + `log/log.h`
cp'd per the textlog_harness recipe :16/:138 OR witness-only if the
probe formats through witness TextLog_* bodies — measure the file_log.o
residue FIRST, fsvc PLAN §0.4 style); expected NEW witnesses: plain
`DataBus::subscribe` (armable handler capture, mirroring the MPDataBus
witness at stubs.cc:345), the PegInfo/peg-count plumbing (stubs Peg
grep-0), possibly the TextLog bodies vs the real-text_log.cc compile
(textlog clock shim precedent — decide by residue nm). ZERO retirements
expected (stub grep-0 FileLog/TextLog). Gate must stay byte-ident
`4826fc2233044a2d5429413faf0ae1af` = **EIGHTH straight zero-regression
row**. Rust lands src/file_api/file_log.rs fresh over src/log/
text_log.rs + a DataHandler-shaped seam; the FILE_VERDICT event source
is the landed FileCache publish path.

## Alternative quick-win rows (re-measured at this 17y docs pass; ZERO TEST_CASEs + ZERO `#ifdef UNIT_TEST` across ALL remaining file_api TUs)
| target | lines | TEST_CASEs (measured) | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder needed (17l numa precedent); bigger alt |
| **file_log.cc** | 329 (NO .h — `find src -name 'file_log*'` = the .cc ONLY) | 0 | **17z PICK**; NEW witnesses: DataBus::subscribe (stubs grep-0), PegInfo bodies (stubs `grep Peg` 0); text_log.h drag cc:27 (Rust twin src/log/text_log.rs 422L LANDED row 16r; harness recipe = tools/textlog_harness) |
| file_module.{h,cc} | 465 (86+379) | 0 | QUEUED after 17z; drags main/snort.h + module_manager + parser/parser.h + lua (all grep-0 absent from the fsvc donor); **closes the 17w load_config witness trio (stubs.cc:419/:423/:433) when the real TU lands — body file_module.cc:263-:266** |
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
- 17y: **DONE (3093f5e)** — file_service: FileServiceLite real statics+ladder arms in file_lib.rs (+556L; shadows/Cells per deviations row 17y — NO new src/file_api/file_service.rs, the FileServiceLite home stays file_lib.rs), real snort_protocols cp (ProtocolReference::find parity), MimeApi trait seam + FileEnvLite.proto_ref, FileCaptureFactory init_capture/exit_capture defaulted arm, decode_conf STAYS SEAM (no DecodeConfig in src/, grep-0), file_processing_initiated NOT ported (dead upstream); tools/fsvc_harness vectors 64L md5 54864705dd654a18585960a13a853baf tracked, gate UNCHANGED (md5 4826fc2233044a2d5429413faf0ae1af, SEVENTH straight), the donor FileService witness block FULLY retired (23-symbol landmine inversion, build.sh :706/:778/:827 pins) + get_file_processed_size witness retired (Rust keeps its 17q home in file_flows.rs), tests/fsvc_parity_test.rs 890L 64/64 replay, **450 total green**, clippy 0. **Wiki trio for 17y OWED** (owed at the next WIKI phase: status row + deviations section + stats line; wiki HEAD 8d74e32 carries through 17x).
- 17z+: file_log (PICK), file_module (table above).
- 18: codecs IP/TCP/UDP normalization (~15k lines) — verified NO upstream TEST_CASEs in
  codecs/; transcripts are the only ground truth there.
- 19: detection option engines (~30k+ subset); 20: packet_io/DAQ (AF_PACKET via libc);
  21: snort -q -c end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
