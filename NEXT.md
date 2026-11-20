# NEXT.md — takeover context & plan (2026-11-20, post-18a: file_api chapter CLOSED)

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

Current state (measured at this 18a docs pass): plan rows 1–18a DONE —
**the file_api chapter is CLOSED** (see the chapter-complete section
below). 91 commits counting the 18a code commit 74bcc23 — **this docs
commit lands as the 92nd**. **473 tests green / 0 FAILED** (full
`cargo test --all-targets` re-run AT THIS docs pass: summed
`test result` lines = 473 passed / 0 failed, 58 `test result` lines),
`cargo clippy --all-targets` **0 warnings**, 40,572 lines Rust across
122 `src/*.rs` files, 32 `tests/*_parity_test.rs` whole-transcript
replay tests among 57 test files, 338 tracked files, 39
`tools/*_harness` dirs. GitHub wiki https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `f91be60` = row 17z trio LANDED: status row +
deviations section + stats line; verified read-only at this docs pass —
`git -C /tmp/RustyPig.wiki log -1` prints `f91be60 row 17z: status +
deviations + stats (90 commits / 331 files / 39,743 src lines / 459
tests)` atop `b71494a row 17y`, and the 17z trio greps PRESENT
(`Porting-status.md:90` status row, `Deviations-from-Snort-3.md:892`
deviations section — the 17z trio is NO LONGER debt; the wiki is NEVER
touched by code or plan rows). **The 18a wiki trio is OWED** and is
owed at the NEXT WIKI phase, not by this docs pass (`grep -rn 18a
/tmp/RustyPig.wiki --include='*.md'` = 0 hits verified this pass). The
owed trio = status row (file_module 465 L, 816L Rust, gate 9th straight
byte-ident, fmod harness first third-party link, 473 tests) + the
row-18a deviations section (copy from KNOWN DEVIATIONS.md :2120-:2236)
+ stats line ("91+ commits / 338 tracked files / ~40,600 src lines /
473 tests").

## file_api chapter — SUBSYSTEM COMPLETE (row 18a closed it)
Ground `src/file_api/` holds exactly **17 .cc TUs** (ls this pass:
circular_buffer, file_api, file_cache, file_cache_share, file_capture,
file_config, file_flows, file_identifier, file_inspect, file_lib,
file_log, file_mempool, file_module, file_policy, file_segment,
file_service, file_stats) and **all 17 are LANDED** — rows 17m–18a,
end-to-end with ZERO Rust regressions down the whole chain. The
witness artifacts the subsystem carried are all closed: the
load_config STEAL is REAL at file_module.cc:263-:266 (`dst = fc; fc =
nullptr;`), `file_trace` THREAD_LOCAL has its definition home (h:44 /
cc:52), the FileService statics are REAL (17y landmine inversion).
Nothing in src/file_api/ waits on another file_api TU. If a LATER row
(18+, mime, detection) discovers a file_api seam gap, it patches as
usual — but do NOT re-scope file_api rows.

Deviations verdict for row 18a (KNOWN DEVIATIONS.md section landed WITH
the code commit 74bcc23, 117 lines at :2120-:2236; audited by
re-grounding claims THIS pass): **adequate — leave as-is, no follow-up
edits.** Spot-verification (every anchor below was opened THIS pass):
`C_USAGE_GLOBAL=0` from the unscoped `enum Usage { GLOBAL, CONTEXT,
INSPECT, DETECT }` at ground module.h:216 — matches the V1 `usage=0`
pin; `LuaCFunction = int(*)(lua_State*)` real at module.h:63 (so "NO
Rust value" is structurally true — there is no lua_State in the Rust
tree); `RuleMap { unsigned sid; const char* msg; }` real at
module.h:77-:81 (pair-tuple + msg-slot "" ruling sound); file_stats.h:71
carries the verbatim "internal only; not in file_pegs[]" comment behind
the 31-slot get_counts view; the landed Parameter (parameter.rs:36-:40)
has NO help/range slot — the FMOD_PARAMS doc-comment-only pin repeats
the 17z FL_PARAMS ruling verbatim; FILE_ID_NAME/HELP at
file_config.rs:91-:95 carry their own "file_module row consumes it"
note, HONORED this row; FILE_ID_GID=150 file_lib.rs:1733; the landed
REAL dump_cache/dump_cache_entry (file_cache.rs:2589/:2647) answer the
Lua pair per the cc:1031/:1073 cites; `ControlConn::query_from_lua`
const-nullptr under non-SHELL verified at control/control.cc:41-:48
(ground dir is control/, not main/ — the deviations cite "control.cc:
:41-:48" resolves there); the cc:148-:152 `if (fc)` ownership-skip is
real; the "NA" free file_type_name arm real at file_config.cc:82-:86,
the NaNames fixture note matches file_config.rs:110; `file_perf_stats`
def home real at file_lib.cc:71; get_includer body real at
module_manager.cc:893 / decl module_manager.h:52 (fmod PLAN:27's
"module_manager.cc:52" is cite drift toward the DECL — frozen harness
PLAN, cosmetic, no doc edit warranted; the deviations section is
correct). One label worth pinning: the deviations header says the Lua
pair spans cc:281-:351 with the Command table at cc:369-:376 — grep
this pass shows the table block runs cc:369-:377 (+terminator;
get_commands cc:378): a 1-line span-label drift inside a frozen
section, within meaning. No deviation lacks an anchor verified this
pass.

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt`. The transcript is truth:
   never fabricate behavior from memory; if a run flakes, fix
   determinism, never lock a flaky transcript.
2. **Catch gate** whenever upstream ships an embedded
   `#ifdef UNIT_TEST` block or a `test/` suite: compile it verbatim
   (`catch/snort_catch.h` -> plain-catch shim; codec/jsnorm/fid/fcache
   recipe — the fmod build.sh :249/:270 carries the vendored
   catch.hpp pull + shim heredoc). Run it; record cases/assertions in
   `gate.txt`. NEVER gate on grep-estimated assertion counts — pin
   case names/counts from grep, measure assertions from the runner
   (17p: grep said 36, the runner said 42). When gate and probe link
   the same TU, use the **duplicate-symbol rule**: every UT-compiled
   TU's plain `.o` is EXCLUDED from the gate link (17r: 3 UT TUs in
   one binary). When a TU has BOTH early `#ifdef UNIT_TEST` fragments
   AND a trailing suite block, excise the LAST block only, via
   `rfind` + brace-balance guard, on BOTH builds (17r file_lib
   recipe, build.sh heredoc `FIXLIBUT`). The 17y row added the
   INVERSION lesson: when a donor carries a WITNESS BLOCK for the row
   TU, landing the real TU retires the block (23 hard collisions,
   fsvc build.sh :706-:707/:778/:827 nm pins) — the retire-evidence
   echo is the guard, not a silent link failure. The 18a row adds the
   PER-LINK corollary: retirement applies to the CURRENT donor's
   stubs ONLY — the four frozen donors keep their blocks + their
   vectors/gate/tests byte-frozen, and a census test pins both faces
   (fmod `trio_retirement_census`). Also 18a: the real row .o may BE
   the witness turf (T defs x18, B `file_trace`) — run the
   residue/landmine census BEFORE writing any witness bodies.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fmod_parity_test.rs` (the freshest: 1009 lines, whole
   61-line replay + the retirement census), then
   `tests/flog_parity_test.rs`, `tests/fsvc_parity_test.rs`,
   `tests/fctx_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 473; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings, `vectors.txt` md5 stable across >= 2
   clean rebuilds (gate.txt md5 likewise — it is regenerable, hence
   .gitignore'd: md5-pinned in docs per row, NOT tracked), harness
   `.gitignore` block added (mirror siblings) and verified with
   `git check-ignore` BEFORE staging (the fmod block is
   .gitignore:271-:289, 19 lines, landed via the orchestrator inside
   74bcc23 — re-verified by check-ignore at THIS docs pass:
   probe/copy//gate all ignored). Then commit + push, insert the plan
   row (grep-guard: count must be 0 before insert — the numa
   double-append incident cost a force-push), append deviations (one
   grep-guarded append), refresh NEXT.md, commit+push docs, update
   the wiki (status row + deviations section + stats line), push wiki.

## The 18a close-out facts (fresh-measured at this docs pass)
- `tools/fmod_harness/vectors.txt` 61 lines md5
  **f0fdbab06fe1681af1c654531b917c55** (tracked, NEVER edited); the
  tail pair = `IMGR release` at vectors:60/:61 (the V6 exit-time
  `static FileCache v6_cache` dtor position the replay models
  explicitly — the 17z flog sweep-tail precedent).
- **Gate md5 `4826fc2233044a2d5429413faf0ae1af` UNCHANGED byte-ident =
  NINTH straight zero-regression row** (the chain = cap(17s, start),
  fcshare, fconf, fcapi, finspect, fpolicy, fsvc, flog, fmod — nine
  harnesses, gate.txt byte-ident across all; fctx's gate is a
  DIFFERENT md5 (`42349372...`, its own 18/91 link) and never joined
  this chain).
- `tests/fmod_parity_test.rs` **1009 L**, 14 `#[test]` fns incl
  `fmod_transcript_replay` (61/61 line-for-line) +
  `trio_retirement_census` (retire-face + four-donor keep-face +
  PRINTS-FROZEN zero-steals grep).
- **Real-first lifecycle probe** (probe.cc:7-28 header): FIRST-TIME
  REAL-surface arming — REAL heap `new FileIdModule`, REAL 17-arm
  `set()` ladder (lazy `new FileConfig` on the FIRST param,
  cc:196-:197), REAL steal through the REAL FileInspect ctor
  (file_inspect.cc:126 mod_ctor resolves for the first time — the 17w
  "symbol merely EXISTS" raw-storage posture is DEAD), REAL
  `luaL_newstate` state driving the Command-pair function pointers.
- **Real LuaJIT archive**: the static `/opt/data/tools/luajit-src/src/
  libluajit.a` is pulled **BY PATH**, NOT `-lluajit` — `-lluajit`
  resolves the `.so` first and the gate probe then dies at load (no
  rpath; build.sh :181-:183, scratch-proven build 3); `-lm -ldl` tail
  for the mmap allocator; nm assert build.sh:961 pins the two `T
  luaL_optinteger`/`T luaL_optlstring` defs; `luaL_optint` (cc:295) /
  `luaL_optstring` (cc:320) are the macros that resolve to them.
  FIRST third-party link in the lineage.
- The trio retirement = exactly 3 collisions (ctor shim flog
  stubs.cc:419 + raw storage :423-:424 + load_config witness
  :431-:438 — byte-ident across finspect/fpolicy/fsvc/flog = the dup
  proof, md5 9165739e… block, 31 L) + the `file_trace` STANDOVER at
  stubs.cc:196 (a 4th symbol, outside the trio block). Retired in
  fmod stubs ONLY (nm pins: `T FileIdModule::` x18 on the row .o, `B
  file_trace` single, `T load_config` single); `fcache_set_file_
  inspector` rewired to REAL `new FileIdModule` (fmod stubs.cc:485,
  real ctor resolves) with the extern-C arm surviving verbatim.
- .gitignore: the 19-line fmod block at :271-:289 was landed BY THE
  ORCHESTRATOR inside code commit 74bcc23 (same pattern as flog's 18
  lines at ef9bf83). check-ignore verified this docs pass; do NOT
  re-add the block.
- Suite math at this docs pass: **473 = 459 + 14** fmod parity tests
  (full re-run, 0 FAILED); clippy quiet (`--all-targets`, 0 warnings);
  wiki HEAD `f91be60` covers 17z only -> **18a trio owed**.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s (file_capture) does NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH, `-lm -ldl`, no rpath trap — see the 18a close-out facts).
- **CppUTest is NOT installed on this host** (measured at this docs pass: no `/usr/include/CppUTest`, `ldconfig -p | grep cpputest` empty, no vendored copy under tools/ anywhere). Upstream **CppUTest** suites (the 4 codecs/test/ suites, the 16g/16h lru suites — those were translated Rust-side) can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp + the snort_catch.h shim) runs natively.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction). Since 18a `file_trace` has its REAL def on BOTH sides (Rust token Cell armed via the transcribed cc:154 set_trace; harness side the row .o defines it, fcache_set_file_trace rides it, fmod stubs.cc:205).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/fmod_harness/` — **THE donor for row 18+ (its cp braces + objs loop now carry the FULL file_api closure — all 17 TUs — plus text_log/module/snort_protocols; codecs ip/* consumers lean on the resident file_stats/file_cache/file_lib .o's)**: fresh from the flog donor; first third-party link (`libluajit.a` BY PATH + `-lm -ldl`, nm pin :961); the §0.1 header-cp chain (`copy/lua/lua.h`, `copy/main/snort.h`, `copy/managers/module_manager.h` + `main/analyzer_command.h` DIOCTL graft, `copy/parser/parser.h` + 6 detection/ports/mpse_batch header cps — ALL header-only, zero link contribution) + 2 witness grafts (TraceOption in trace.h, DIOCTL in daq_common.h); 4 NEW witness bodies (query_from_lua const-nullptr / parser_append_rules_special / ModuleManager::get_includer / DecodeConfig::set_decompress_buffer_size — the set() arm LEAVES fc untouched, its target is the decode_conf static, the 17y STAYS-SEAM ruling); stubs.cc 984L = flog lineage + NEW18a block + the retirement comments (:196-:209 file_trace, :417-:433 trio); build.sh :1164L with the self-check mirrors (row-TU TEST_CASE/UNIT_TEST 0; `nm -C` T-def pins `T FileIdModule::`=18; the RETIRE-asserts). vectors.txt 61L md5 `f0fdbab06fe1681af1c654531b917c55` (committed, NEVER edit); gate md5 `4826fc2233044a2d5429413faf0ae1af` byte-ident (NINTH straight).
- `tools/flog_harness/` — the 17z donor (**superseded by fmod; kept for lineage**): the ZERO-retirement row; cp deltas file_log.cc + text_log.{h,cc} + log.h + REAL framework/module.cc + compile-only stats.h/stats_output_format.h; W1 DataBus::subscribe :908 + W2 show_stats pair :924/:931; the 17w FileIdModule trio + file_trace standover STAY FROZEN at :419/:423-:424/:425-:441 + :196; vectors 50L md5 `b260ec6ae0be7ebbf4e0e60338b8cee3`; gate 8th straight.
- `tools/fsvc_harness/` — the 17y donor (kept for lineage): the landmine inversion (23 collisions, whole FileService witness block retired), real snort_protocols cp (ProtocolReference::find parity); vectors 64L md5 `54864705dd654a18585960a13a853baf`.
- `tools/fpolicy_harness/` — the 17x donor (kept): cp delta TWO files; vectors 27L md5 `b989a8d5cddaf0a2289f5528121ddf35`.
- `tools/finspect_harness/` — the 17w donor (kept): 4 NEW witness bodies (the load_config steal witness among them — STILL live and frozen here); vectors 103L md5 `3cbd009e9bb4228ee427ed3fadc64fb4`.
- `tools/fcapi_harness/` — the 17v donor (kept): ZERO cp delta; vectors 21L md5 `a953a5017b74f5d44dbba14df48ac5ea`. NB dir name `fcapi_harness` (the 17u NEXT.md said `fapi_harness` — pinned name, do not "fix" the code).
- `tools/fconf_harness/` — the 17u donor (kept): vectors 20L md5 `65968e1cc11e9489b89762b6c6f3765e`.
- `tools/fcshare_harness/` — the 17t donor (kept): vectors 25L md5 `03d43c143440bd2a101d56818fd20be4`.
- `tools/fcap_harness/` — the 17s donor (kept): vectors 27L md5 `0208a69116861a506f0c46a7dc36b2ac`; gate md5 `4826fc2233044a2d5429413faf0ae1af` — the 114/22 chain STARTS here.
- `tools/fctx_harness/` — FileContext + capture/mempool/segment closure donor: the probe-mode file_lib.cc with ONLY the :1363 UNIT_TEST block excised, the 3-UT-TU gate link (18 cases / 91 assertions). vectors 610L md5 `839b5566be0a2191876e0f34b4ed56e4`; gate md5 `42349372258e49db1a8f4f60e7a27ed6`. `PLAN.md` = the RECON→HARNESS→PORT contract example.
- `tools/fflows_harness/` — flowz graft donor: vectors 146L md5 `bd8c00af7a7047ef5b745a34c2a0df55` (DO NOT touch); gate md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: vectors 278L md5 `b69db31078f6bf6be88eba7615378748` (DO NOT touch); gate md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure + interposed SnortClock fake clock (enumerate BOTH clocks a subsystem reads). vectors 273L md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE, never leaks out.
- `tools/fstats_harness/` — carries the ONLY file_api test/ suite: upstream `file_api/test/file_stats_test.cc` compiled via the catch shim (:25/:122) + header closure + stats witnesses (17m).
- `tools/textlog_harness/` — row 16r: original text_log.cc + time() interposition precedent.
- `tools/rules_harness/` — SnortConfig EOFCFG shim, policy.h graft, xhash verbatim proven; hosts `copy/catch/catch.hpp` — the vendored Catch every shimmed gate pulls.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe. **`tools/codec_harness` is row 17d's harness (framework/codec base) — row 18 MUST re-read it: 17d deferred "Codec's virtual decode/encode/update/format vtable + the CodecApi plugin struct + plugin loading" to the plugin-loading row and RawData DROPPED daq_msg "row 20" — the codecs rows are exactly where those deferrals surface.**

## Next milestone — row 18: codecs (the queue row; 18a closed the file_api chapter)

### Row-18 scale table (ALL numbers re-measured at THIS 18a docs pass,
### ground `/opt/data/snort3-src/src/codecs` @ fe29cbe READ-ONLY; the
### old "~15k" plan claim is OVERSTATED — measured **11,914 total lines
### over 48 .cc+.h files; 11,289 over the 44 NON-test files**)

| unit (ground cite) | lines (wc -l this pass) | gate material (grep-counted this pass) |
|---|---|---|
| `codec_api.{h,cc}` | 26 + 121 = 147 | none |
| `codec_module.{h,cc}` | 269 + 71 = 340 | none |
| root/: `cd_raw.cc` + `cd_eth.cc` | 105 + 262 = 367 | none |
| ip/ (14 cd_*.cc + checksum.h; **39 of 40 cd_*.cc have NO same-named .h** — the NO_HEADER sweep this pass; the cd_*.cc ARE the TUs, file_log precedent) | 6,570 | cd_gre embedded Catch :352 + the checksum suite |
| link/ (10 cd_*.cc) | 2,043 | none |
| misc/ (9 cd_*.cc) | 1,822 | 3 CppUTest test/ suites |
| `ip/checksum.h` — pure-INLINE header lib: `detail::add_tcp_header` :153 / `add_udp_header` :171 / `add_ip_header` :189; public `tcp_cksum` :60/:61 (Pseudoheader + Pseudoheader6 overloads, bodies :223/:235), `ip_cksum` :66; **7 consumers** (grep: cd_pgm/cd_gre/cd_icmp4/cd_udp/cd_ipv4/cd_icmp6/cd_tcp) | 284 | its own suite (next row) |
| `ip/test/checksum_test.cc` | 201 | **CppUTest: 10 TESTs / 3 TEST_GROUPs (first group `checksum_header_guards` :56) / 10 CHECKs** — the 2026 size_t underflow-hardening regression suite (file header :17-:31: old unconditional `len -= N` underflowed size_t -> cksum_add scanned ~2^64 bytes -> OOB -> SIGSEGV; guard zeroes len = safe no-op; fixture `short_buf[16]`) |
| `misc/test/teredo_codec_test.cc` | 121 | **CppUTest 2 TESTs / 1 group** (:90/:103 rejects payload ending after auth/origin indicator); **#include "../cd_teredo.cc"** self-include unit + its own stub witnesses (:36-:50 show_stats pair etc) |
| `misc/test/gtp_codec_test.cc` | 140 | **CppUTest 2 TESTs / 8 CHECKs** gtpv1+v0 header-fills-packet_no_inner_read; includes **"../cd_gtp.cc"** |
| `misc/test/geneve_codec_test.cc` | 163 | **CppUTest 3 TESTs / 19 CHECKs** decode + geneve_lyr opts; includes **"../cd_geneve.cc"** |
| `ip/cd_gre.cc` | 366 | **the ONLY embedded Catch TEST_CASE in all of codecs/: :352 `[cd_gre]`** inside `#ifdef UNIT_TEST` :351 (header shim include block :34) — `raw_len > GRE_HEADER_LEN` -> encode false (1 CHECK) |

Big-TU pins (wc -l): cd_tcp.cc **839**, cd_ipv4.cc **790**,
cd_ipv6.cc **733**, cd_udp.cc **660**, cd_icmp4.cc **645**, cd_icmp6.cc
**518**, cd_mpls.cc **390**, cd_gre.cc 366, cd_icmp4_ip.cc 345,
cd_gtp.cc 291, cd_geneve.cc 282. The old "verified NO upstream
TEST_CASEs in codecs/" claim stays TRUE for Catch (exactly 1:
cd_gre.cc:352) but is **STALE as a gate-availability claim**: the 4
CppUTest suites (10+2+2+3 = **17 upstream TESTs**, ~40 CHECKs) exist
at fe29cbe — recounted via `grep -cE '^TEST\('` this pass. CppUTest is
NOT runnable here (see environment facts) -> those suites translate
Rust-side ONLY (the 16g/16h CppUTest porting precedent), NEVER
pretend a native CppUTest gate. Codecs-adjacent struct drags measured:
protocols/{eth.h 74, ip.h 131, tcp.h 211, udp.h 68} = 484 L, all
struct-only (consumed via cd_eth.cc:31-:32, cd_ipv4.cc:36-:39 chains)
— NOT in the fmod copy tree; fresh header cps.

### Proposed smallest-first subrow scoping (PROPOSAL — the 18 PLAN.md owns final scoping; scratch nm residue census FIRST, PLAN-0 discipline)
- **18b = `ip/checksum.h` (284, ALL inline) + Rust-side translation of
  its 10-TEST/3-GROUP suite.** Smallest closed unit in the tree; adds
  **ZERO .o** to any donor link (inline-only) -> the 114/22 gate chain
  CANNOT be disturbed -> **gate byte-ident `4826fc22...` = TENTH
  straight** trivially. Rust home `src/codecs/checksum.rs` (new
  `src/codecs/` dir; mod.rs keeps the C-alpha order). Pins to drive:
  short_buf[16] fixture values byte-for-byte, the guard arms (declared
  len < fixed header -> safe no-op, len==0, NEVER the ~2^64 walk),
  valid-input invariance, Pseudoheader/Pseudoheader6 words, the 7-
  consumer call map for the later ip rows. The 2026 hardening is
  itself a quirk pin (pre-hardening underflow = documented C history
  the suite guards — pin the guarded behavior, not the old UB).
- **18c = codec vocabulary + no-op codecs**: `codec_api.{h,cc}` 147 +
  `cd_default.cc` 83 + `cd_bad_proto.cc` 98 + `cd_no_next.cc` 116 +
  root `cd_raw.cc` 105 (~550 L; all TUs <=121 L, zero suites ->
  probe-vectors-only; FIRST slab of the 17d-deferred CodecApi plugin
  surface — the Codec base + CodecData ALREADY landed at 17d, ride it,
  do not re-port).
- **18d = root layer**: `cd_eth.cc` 262 + `codec_module.{h,cc}` 340 +
  link `cd_arp.cc` 128 (~730 L).
- **18e = the IPv6 extension chain**: cd_hop_opts 143 + cd_dst_opts
  134 + cd_routing 163 + cd_mobility 143 + cd_igmp 138 (~720 L) — every
  one rides the LANDED 17d CheckIPV6HopOptions / CheckIPv6ExtensionOrder
  + RFC order tables (the 17d H/O blocks are the pre-pinned ground
  truth: the fall-through H3/H4, TRUNCATED-then-continue H6, the
  DSTOPTS ROUTING_SEEN AND next==ORDER_MAX exception O4/O11).
- Thereafter: tunnels WITH self-include suite units — teredo 161+121 /
  gtp 291+140 / geneve 282+163 (gate pattern = the TEST file
  #includes the row .cc itself, the 17f/17g stats precedent — but
  these are CppUTest: Rust-side translation, deviation-noted, C gate
  untouched); then **cd_gre 366 = the row that changes the gate (see
  rule below)**; then the ICMP pair (645+518), then udp 660 / ipv4 790
  / ipv6 733 / tcp 839 (the heaviest single-TU rows, checksum.h fully
  resident by then), then the link tail (mpls/vlan/pppoe/erspan/
  ciscometadata/fabricpath/trans_bridge/ppp_encap, 2,043 total), then
  the misc tail (llc 198 / vxlan 133 / user 167 / icmp4_ip 345 /
  icmp6_ip 162).
- Standing drags the first codecs probe must resolve BEFORE planning
  cp deltas (scratch nm census): `framework/codec.cc` (the 17d base —
  NOT in the fmod copy tree; decide witness-vs-REAL-cp by residue),
  the protocols/*.h struct cps (all header-only), the RawData/
  DecodeData/packet shapes (17d deviation: RawData drops daq_msg,
  "row 20" — pin the seam posture once, cite it), and
  `codecs/codec_module` registration (Module base = the 17z module.o
  closure rides the donor already).

### The gate rule for row 18 (explicit)
Gate md5 `4826fc2233044a2d5429413faf0ae1af` stays **byte-ident every
subrow from 18b until the cd_gre subrow** (10th straight at 18b, 11th
at 18c, ...). At the **cd_gre row the gate MUST change, exactly once**:
compile the embedded UNIT_TEST block (:351-:366, the `[cd_gre]` case)
via the fmod build.sh catch recipe (:249 catch.hpp pull, :270 shim
heredoc, catch_main link) and apply the duplicate-symbol rule — the
gate link carries the UT-compiled cd_gre TU ONLY, the plain probe
`.o` excluded; on the PROBE build excise the trailing UNIT_TEST block
(rfind recipe). Expected new gate line: **"All tests passed (115
assertions in 23 test cases)"** — MEASURE it from the runner, NEVER
type it from this forecast (the 17p lesson: grep estimates lie). That
run's gate.txt becomes the NEW chain anchor md5; every later subrow
byte-matches the NEW md5. CppUTest suites NEVER touch the C gate (no
CppUTest on host). NEVER edit a frozen donor's gate/vectors to
"fix" a count.

## Alternative quick-win rows (verdicts re-affirmed at this pass)
| target | lines | gate material | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` Catch cases at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder (17l numa precedent); THE fallback if row 18 stalls |
| file_log.cc (17z) | 329 | 0 | DONE — flog donor |
| file_module.{h,cc} (18a) | 465 (86+379) | 0 | DONE — fmod donor = NEW lineage head; **file_api subsystem CLOSED** |

## Backlog (plan rows)
- 17y: DONE (3093f5e) — wiki trio LANDED (b71494a).
- 17z: DONE (ef9bf83) — file_log single-TU row; **wiki trio LANDED (f91be60)** — 17z debt CLEARED (verified present this pass: Porting-status.md:90 + Deviations-from-Snort-3.md:892).
- 18a: **DONE (74bcc23)** — file_module: `src/file_api/file_module.rs` 816L FRESH (FMOD_PARAMS 17 params cc:55-:109 / FMOD_PEGS 30 cc:111-:144 / FMOD_RULES with the {0,nullptr} msg-slot "" ruling + V1 msg0_null=0 derived from live text / load_config steal == Option::take with ZERO file_inspect.rs edits — the frozen 17w seam keeps its shape / file_trace token Cell + cc:154 set_trace / the Lua pair as free fns over already-queried args, unwrap_or(100) sentinel + -1->u32::MAX fold + the cc:337-:347 in-place isxdigit+toupper normalize VERBATIM, CommandRecord presence bools, query_from_lua stays a driver-side pre-read cn=None); `tools/fmod_harness` = NEW lineage donor (libluajit.a BY PATH first third-party link; §0.1 header-cp chain; 4 witness bodies; trio+standover retirement WITH nm census; fcache_set_file_inspector -> REAL ctor); vectors 61L md5 f0fdbab06fe1681af1c654531b917c55 tracked, gate UNCHANGED md5 4826fc22... NINTH straight (2 clean rebuilds byte-ident), `tests/fmod_parity_test.rs` 1009L 61/61 replay + census (473 total green), clippy 0, .gitignore fmod block via orchestrator. **Wiki trio for 18a OWED** (next WIKI phase; wiki HEAD f91be60 stops at 17z).
- 18: codecs — ~15k claim corrected to 11,914 measured; scale table + 18b.. scoping above; row starts with the 18b PLAN.md.
- 19: detection option engines (~30k+ subset claim stands but the tree measures **14,533** .h+.cc with **~47** embedded Catch TEST_CASEs — fp_utils.cc 21, detection_options.cc 6, ips_context.cc 5, extract.cc 5, ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2, sfrim.cc 1, ips_context_data.cc 1 — real Catch material to carry like 17f/17r; re-grep at that row's scoping pass); 20: packet_io / DAQ (AF_PACKET via libc; the 17d RawData/daq_msg deferral closes HERE); 21: main CLI + `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
