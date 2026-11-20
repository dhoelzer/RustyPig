# NEXT.md — takeover context & plan (2026-11-20, post-18b: codecs chapter OPENED, checksum primitive layer resident)

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

Current state (measured at this 18b verify-mode docs pass): plan rows
1–18b DONE. 93 commits counting the 18b code commit 7e1744c — **this
docs commit lands as the 94th**. **487 tests green / 0 FAILED** (full
`cargo test --all-targets` re-run AT THIS docs pass: summed
`test result` lines = 487 passed / 0 failed, `grep -c '^test result: ok'`
= 59 lines; 487 = 473 + 14 csum parity tests, math below), `cargo
clippy --all-targets` **0 warnings** (forced relint THIS pass: touched
every .rs, `Checking snort3` ran, 0 warnings), 41,019 lines Rust across
124 `src/*.rs` files, 33 `tests/*_parity_test.rs` whole-transcript
replay tests among 58 test files, 345 tracked files (`git ls-files | wc
-l`), 40 `tools/*_harness` dirs. GitHub wiki https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `9792858` = row 18a trio LANDED: verified
read-only at this docs pass — `git -C /tmp/RustyPig.wiki log -1` prints
`9792858 row 18a: status + deviations + stats (92 commits / 338 files /
40,572 src lines / 473 tests; file_api SUBSYSTEM COMPLETE 17/17, gate
9th straight byte-ident 4826fc22...)` atop `f91be60 row 17z`, and the
18a trio greps PRESENT (`Porting-status.md:91` status row,
`Deviations-from-Snort-3.md:960` deviations section — the 18a trio is NO
LONGER debt; the wiki is NEVER touched by code or plan rows). **The 18b
wiki trio is OWED** and is owed at the NEXT WIKI phase, not by this docs
pass (`grep -rn 18b /tmp/RustyPig.wiki --include='*.md'` = **0 hits**
verified this pass). The owed trio = status row (checksum.h 284 L
all-inline landed 436 L Rust at src/codecs/checksum.rs, probe-only csum
harness, gate untouched 10th straight, suite Rust-side 10 TEST/3 GROUP,
487 tests) + the row-18b deviations section (copy from KNOWN
DEVIATIONS.md :2236-:2320) + stats line ("94 commits / 345 tracked files
/ ~41,000 src lines / 487 tests").

## 18b close-out — VERIFY MODE (plan row + deviations already landed WITH code commit 7e1744c; this pass greps-verify rather than append)
Unlike prior rows, 18b's plan row and deviations section shipped inside
the CODE commit, so this docs pass is a verification pass. Everything
below was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18b' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:81) — insert guard satisfied, NO append needed, row
  text stands as committed.
- **Deviations section**: `grep -c '^## codecs/ip/checksum.h (row 18b'
  KNOWN DEVIATIONS.md` = **1** at :2236, running to EOF at :2320 = 85
  lines / 12 bullets. **Verdict: adequate — leave, no follow-up edits.**
  Anchor re-grounding (every file opened THIS pass in ground
  snort-src @ fe29cbe7403a): `checksum.h` = 284 L + md5
  `b43628f369e16b1d5c093ff447d3e954` (matches the build.sh :37 pin);
  guard arms REAL at h:157-:162 (`if ( len < TCP_MIN_HEADER_LEN ) { len
  = 0; return; }` ladder shape — :175-:180/:193-:198 the udp/ip twins);
  `read_word` memcpy body REAL at h:83-:88; the fold two-step REAL at
  h:105-:106; the odd-tail raw-add REAL at h:102-:103; the `static`
  fwd-decl REAL at h:59; the two `static_assert` size pins REAL at
  h:41/:55; the decl block h:60-:66 = 7 decls (tcp x2, udp x2, icmp x2,
  ip) which is the Rust 6-name mapping's census (`icmp_cksum`/`_v6` +
  `tcp_cksum4/6` + `udp_cksum4/6` + `ip_cksum` + `cksum_add` — 8 `pub
  fn` measured in checksum.rs); suite TEST_GROUP anchors REAL at
  checksum_test.cc:56/:107/:156; the FOUR `CHECK(true)` arms REAL at
  :122/:130/:143/:149; 6 `CHECK_EQUAL` at :67/:78/:89/:100/:181/:192 =
  10 assertions total; `grep -c '^TEST('` = 10; the packet_manager.cc
  correction cites REAL (include :30, icmp_cksum call :641,
  `Pseudoheader6 ps6;` :697, icmp_cksum(buf, ip_len, ps6) :705); ground
  consumer census re-run `git grep -c 'checksum::'` = **8 files / 39
  lines** — matches the CORRECTED plan-row census (the old 7-consumer
  NEXT.md claim, corrected in csum PLAN §0 to EIGHT, stands).
- **Vectors stability**: `tools/csum_harness/vectors.txt` 16 L md5
  `e4baf7816440e18917d3249597f60b88` — build.sh re-run **x2 clean**
  THIS pass, both rc 0, md5 stable; the committed `vectors_O0.txt` and
  `vectors_O2.txt` carry the SAME md5 (the -O0==-O2 byte-ident arm,
  build.sh :116 cmp proven live), and the E4 CppUTest wall receipt
  re-printed in both fresh runs (`cpputest_fatal.txt:1` =
  `checksum_test.cc:36:10: fatal error: CppUTest/CommandLineTestRunner.h:
  No such file or directory`).
- **Gate chain LIVE**: fmod lineage head rebuilt THIS pass
  (`FMOD_HARNESS_OK`, rc 0): vectors `f0fdbab06fe1681af1c654531b917c55`
  (61 L) + gate `4826fc2233044a2d5429413faf0ae1af` **byte-ident = 10TH
  STRAIGHT confirmed by measurement, not assertion**. md5 census over
  all tracked gate.txt THIS pass: exactly **9 files** carry
  `4826fc22...` (fcap, fcshare, fconf, fcapi, finspect, fpolicy, fsvc,
  flog, fmod) — the csum build.sh :154 self-check asserts the same
  count. 18b shipped NO gate.txt (probe-only row, census stays 9).
- **Test math**: 487 = 473 + 14 csum parity tests — `tests/csum_parity_test.rs`
  414 L, 14 `#[test]`: `csum_transcript_replay` (16/16 ordered) + 10
  `up_gate_*` CppUTest translations + 3 Q-ladder extras; 15th `#[test]`
  candidate? no — 14 counted both in source (`grep -c '#\[test\]'` = 14)
  and runner. Suite result at THIS pass: 14/14 ok.
- **commit census**: 93 at HEAD 7e1744c (`git rev-list --count HEAD`);
  .gitignore csum block at :291-:300+ re-verified by `git check-ignore`
  THIS pass (probe/copied/*.o all ignored, vectors stays tracked) — do
  NOT re-add.

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
   echo is the guard, not a silent link failure. The 18a row added the
   PER-LINK corollary: retirement applies to the CURRENT donor's
   stubs ONLY — the frozen donors keep their blocks + their
   vectors/gate/tests byte-frozen, and a census test pins both faces
   (fmod `trio_retirement_census`). The 18b row adds the PROBE-ONLY
   corollary: when the row contributes ZERO .o to every donor link
   (all-inline header lib, nm-proven: header-as-TU = ZERO text
   symbols, consumer TU = 11 weak `W` COMDATs + the h:59 `t` fwd-decl
   residue) and its suite dialect (CppUTest) cannot build on the host,
   the honest artifact is a probe-only harness — NO gate at all, with
   the zero-link claim nm-proved in build.sh and the 9-holder chain
   re-censused EVERY build (:154). A fake Catch gate over a CppUTest
   suite = the 17p anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fmod_parity_test.rs` (1009 lines, whole 61-line replay +
   the retirement census), freshest-smallest `tests/csum_parity_test.rs`
   (414 L, 16-line replay + 10 up_gate translations + 3 extras — the
   pattern for probe-only rows), then `tests/flog_parity_test.rs`,
   `tests/fsvc_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 487; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings (force relint by touching all .rs),
   `vectors.txt` md5 stable across >= 2 clean rebuilds (gate.txt md5
   likewise — regenerable, hence .gitignore'd: md5-pinned in docs per
   row, NOT tracked), harness `.gitignore` block added (mirror
   siblings) and verified with `git check-ignore` BEFORE staging (the
   csum block is .gitignore:291-:300+, landed inside code commit
   7e1744c). Then commit + push, insert the plan row (grep-guard:
   count must be 0 before insert — the numa double-append incident
   cost a force-push), append deviations (one grep-guarded append) —
   the 18b variant: BOTH may ship inside the code commit, then the
   docs pass VERIFY-greps them (count == 1 each) instead of inserting,
   and still re-measures every load-bearing claim. Refresh NEXT.md
   (FRESH rewrite), commit+push docs, update the wiki (status row +
   deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s (file_capture) and 18b (checksum) do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH — `-lluajit` hits the .so and the gate probe dies at load, no rpath; `-lm -ldl` tail; nm pin fmod build.sh:961).
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum build since 18b: `g++ -fsyntax-only` on checksum_test.cc dies at its :36 include, receipt `tools/csum_harness/cpputest_fatal.txt:1`). Upstream **CppUTest** suites (the 4 codecs/test/ suites, the 16g/16h lru suites — those were translated Rust-side) can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp + the snort_catch.h shim) runs natively.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction). Since 18a `file_trace` has its REAL def on BOTH sides (Rust token Cell armed via the transcribed cc:154 set_trace; harness side the row .o defines it, fcache_set_file_trace rides it, fmod stubs.cc:205).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/fmod_harness/` — **THE donor for row 18c+ (its cp braces + objs loop carry the FULL file_api closure — all 17 TUs — plus text_log/module/snort_protocols)**: first third-party link (`libluajit.a` BY PATH + `-lm -ldl`, nm pin :961); the §0.1 header-cp chain (`copy/lua/lua.h`, `copy/main/snort.h`, `copy/managers/module_manager.h` + `main/analyzer_command.h` DIOCTL graft, `copy/parser/parser.h` + 6 detection/ports/mpse_batch header cps — ALL header-only, zero link contribution) + 2 witness grafts (TraceOption in trace.h, DIOCTL in daq_common.h); 4 NEW witness bodies; stubs.cc 984L; build.sh 1164L with the self-check mirrors. vectors.txt 61L md5 `f0fdbab06fe1681af1c654531b917c55` (committed, NEVER edit); gate md5 `4826fc2233044a2d5429413faf0ae1af` byte-ident (rebuilt THIS docs pass, 10th straight). Its copy tree ALREADY holds: `framework/codec.h`, `config.h`, `main/snort_config.h`, `main/snort_types.h`, `daq_common.h` (graft), `protocols/protocol_ids.h` — and does NOT hold `codecs/codec_module.h`, `managers/plugin_manager.h`, `managers/plugin.h`, or any `daq_dlt.h` (find = 0 hits tree-wide; the 18c cp census below).
- `tools/csum_harness/` — row 18b, **the probe-only pattern for ZERO-.o rows**: no gate/copy/gate.txt shipped; build.sh self-checks = ground-header md5 pin (:37), E4 CppUTest wall receipt every build (:67-:70), dialect proof 10 `TEST(` / 0 `TEST_CASE` (:72-:73), nm ZERO-text-symbols proof for the header-as-TU (:79-:80), consumer `t` fwd-decl residue witness (:92), zero donor-closure checksum defs (:101), O0==O2 byte-identity (:116), 9-holder gate census (:154). vectors 16L md5 `e4baf7816440e18917d3249597f60b88`. PLAN.md carries the full recon incl. the corrected 8-file/39-line consumer census and the scratch nm backbone (`donor_defs.txt` 5,858 donor-closure symbols, scratch copy at `/opt/data/cache/scratch/row18b/donor_defs.txt` = 5,898).
- `tools/flog_harness/` — the 17z donor (**superseded by fmod; kept for lineage**); vectors 50L md5 `b260ec6ae0be7ebbf4e0e60338b8cee3`.
- `tools/fsvc_harness/` — the 17y donor: the landmine inversion (23 collisions); vectors 64L md5 `54864705dd654a18585960a13a853baf`.
- `tools/fpolicy_harness/` — the 17x donor: vectors 27L md5 `b989a8d5cddaf0a2289f5528121ddf35`.
- `tools/finspect_harness/` — the 17w donor: vectors 103L md5 `3cbd009e9bb4228ee427ed3fadc64fb4`.
- `tools/fcapi_harness/` — the 17v donor: vectors 21L md5 `a953a5017b74f5d44dbba14df48ac5ea`. NB dir name `fcapi_harness` (pinned, do not "fix").
- `tools/fconf_harness/` — the 17u donor: vectors 20L md5 `65968e1cc11e9489b89762b6c6f3765e`.
- `tools/fcshare_harness/` — the 17t donor: vectors 25L md5 `03d43c143440bd2a101d56818fd20be4`.
- `tools/fcap_harness/` — the 17s donor: vectors 27L md5 `0208a69116861a506f0c46a7dc36b2ac`; gate md5 `4826fc22...` — the 114/22 chain STARTS here.
- `tools/fctx_harness/` — FileContext + capture/mempool/segment closure donor: vectors 610L md5 `839b5566be0a2191876e0f34b4ed56e4`; gate md5 `42349372258e49db1a8f4f60e7a27ed6` (its OWN 18/91 link, never joined the 4826fc22 chain). `PLAN.md` = the RECON→HARNESS→PORT contract example.
- `tools/fflows_harness/` — flowz graft donor: vectors 146L md5 `bd8c00af7a7047ef5b745a34c2a0df55` (DO NOT touch); gate md5 `e14626fc6f112a9786c7098e6b4df40c`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: vectors 278L md5 `b69db31078f6bf6be88eba7615378748` (DO NOT touch); gate md5 `6b3c041e65bce7ad12a585d54f287eff`.
- `tools/filib_harness/` — file_api header closure + interposed SnortClock fake clock. vectors 273L md5 `77ffd8e458ef15de68f9c53d24a1a1c8` (DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE.
- `tools/fstats_harness/` — carries the ONLY file_api test/ suite (upstream `file_api/test/file_stats_test.cc` via the catch shim).
- `tools/textlog_harness/` — row 16r: time() interposition precedent.
- `tools/rules_harness/` — SnortConfig EOFCFG shim; hosts `copy/catch/catch.hpp` — the vendored Catch every shimmed gate pulls.
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe. **`tools/codec_harness` is row 17d's harness (framework/codec base) — 18c/18d MUST re-read it: 17d deferred "Codec's virtual decode/encode/update/format vtable + the CodecApi plugin struct + plugin loading" to the plugin-loading row and RawData DROPPED daq_msg "row 20" — 18c is exactly where those deferrals surface first.**

## Next milestone — row 18c: codecs vocabulary + the no-op codecs (18b closed the primitive layer; this scoping FRESH-measured at the 18b docs pass)

### 18c scale table — the "549 L" NEXT.md claim **VERIFIED** (every `wc -l` re-run THIS pass, ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY)

| unit (measured path THIS pass — note: NOT all in root/) | lines (`wc -l` this pass) | gate material (grep this pass) |
|---|---|---|
| `codec_api.{h,cc}` (codecs/ root) | 26 + 121 = **147** | 0 TEST_CASE / 0 UNIT_TEST / 0 `TEST(` (per-file grep this pass, all zeros) |
| `cd_default.cc` (**misc/** — path correction: not root/) | **83** | 0/0/0 |
| `cd_bad_proto.cc` (**ip/**) | **98** | 0/0/0 |
| `cd_no_next.cc` (**ip/**) | **116** | 0/0/0 |
| `root/cd_raw.cc` | **105** | 0/0/0 |
| **TOTAL** | **549** (26+121+83+98+116+105, summed this pass) | **NONE — probe-vectors-only row (18b/17v/17u precedent)** |

Path correction pinned: an earlier NEXT.md draft wrote "root `cd_default.cc`" — ground find THIS pass: `misc/cd_default.cc`, `ip/cd_bad_proto.cc`, `ip/cd_no_next.cc`, `root/cd_raw.cc` (all four `wc` rows above are at THOSE paths). codec_api.h body measured: it is the `load_codecs()` decl ONLY (h:24) — the real content is codec_api.cc.

### 18c shape facts (measured THIS pass — the deferral surface the row must settle)
- **codec_api.cc is the plugin-loading seam**: `grep -c '^extern const BaseApi\*'` = **39 extern table decls** + the `#ifdef STATIC_CODECS` ladder; body drives `managers/plugin_manager.h` (`PluginManager` — NOT yet ported on the Rust side in scope; plugin_manager.h includes `framework/base_api.h` (RESIDENT in fmod copy tree) + `managers/plugin.h` (NOT in copy tree — fresh header cp)). The 17d deferral "CodecApi plugin struct + plugin loading" lands HERE: Rust home rides the landed `src/framework/codec.rs` (`CodecData` :183, `ip_protocol::ip_protocol` :86 — the checksum.rs 17d-ride rule, cite src/codecs/checksum.rs header).
- **The three no-op Codec TUs** (cd_default / cd_bad_proto / cd_no_next) each: `class X : public Codec` + `static Codec* ctor` + `CodecApi` record + `const BaseApi* cd_x[]` (cd_default.cc:20-:83 shape read THIS pass — same InspectApiRecord-as-DATA pattern as 17z/18a rows).
- **cd_raw.cc drags `<daq_dlt.h>` — the ONLY such include in codecs/ and NOT present anywhere**: ground snort3-src find = 0, fmod copy tree find = 0, scratch/host find = 0 (three finds run THIS pass). The fmod **`copy/daq_common.h` graft precedent** (hand-authored DAQ stand-in with the NEW18a TraceOption/DIOCTL grafts) applies: 18c PLAN §0 must author/extend the daq header graft, cite the real DAQ include chain at row 20 (17d RawData-drops-daq_msg deviation, NEXT.md backlog line).
- **include closure vs the fmod copy tree (per-TU `grep '^#include'` THIS pass)**: ALL five TUs include `"config.h"` (resident `copy/config.h`) + `"framework/codec.h"` (resident `copy/framework/codec.h` — 18a §0.1 header cp, 402-L ground twin); `codec_api.cc` adds `codec_api.h` (fresh 26-L cp, zero includes of its own) + `managers/plugin_manager.h` (fresh cp, drags `managers/plugin.h` fresh header cp); `cd_bad_proto.cc`/`cd_no_next.cc` add `codecs/codec_module.h` (fresh header-ONLY cp — codec_module.cc 379 L is **18d turf**, do not link it at 18c); `cd_no_next.cc` adds `main/snort_config.h` (RESIDENT — 18a shim chain); `cd_raw.cc` adds `<daq_dlt.h>` (GRAFT needed, above).
- **The REAL-codec-base residue question (PLAN-0 of the 18c PLAN.md, scratch nm census FIRST)**: all five TUs inherit the Codec vtable; fmod's copy tree cp's `framework/codec.h` but NOT `framework/codec.cc` (231 L, measured wc THIS pass; the 17d base TU). fmod stubs.cc carries ZERO codec witness defs (`grep -c codec` = 0 THIS pass) and the csum donor-closure census (`donor_defs.txt`, 5,858 lines) has ZERO Codec-surface symbols — so the 18c probe faces a real residue census: decide REAL cp of framework/codec.cc vs witness bodies BY nm, the 17y/18a landmine discipline (run residue BEFORE writing witnesses).
- Rust side: `src/codecs/` exists (18b opened it; `mod.rs` header line 3 already reserves "row 18c+ will grow this list"). **The flat-vs-dir convention call lands AT 18c** (csum PLAN §7 deferred it; checksum.rs sits FLAT at `src/codecs/checksum.rs` — if 18c adds 5 more TUs, decide: stay flat with name-prefixes vs C-dir submodules `src/codecs/{root,ip,misc}`; C-alpha order kept — `codecs` at lib.rs:12 sorts before `file_api` :13).
- Gate material remains 0 across the whole 18c slab -> **probe-vectors-only, NO new gate.txt**; the 9-holder `4826fc22...` census (= exactly 9 tracked gate.txt THIS pass) must re-measure 9 at the 18c build too (frozen donor rule) -> **11th straight byte-ident**.
- Vectors arms to drive (arm plan, values NEVER pre-typed — 17p lesson): the no-op decode ladders (CodecData next_proto/encap writes, the `PROTO_NOT_SET` / `ip_protocol::` pins codec.rs:219/:264 already landed), cd_bad_proto's next-node->DROP arm, cd_no_next's drop-both arm + the snort_config-gated arm, cd_raw's DLT ladder (daq_dlt graft values pinned as GRAFT facts, row-20 cite), load_codecs()'s table-walk ordering + the STATIC_CODECS ifdef posture.

## Thereafter — remaining row-18 order (from the 18a scale table, totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — both wc sweeps re-run)
- **18d = root layer**: `cd_eth.cc` 262 + `codec_module.{h,cc}` 340 + `link/cd_arp.cc` 128 (~730 L).
- **18e = the IPv6 extension chain**: cd_hop_opts 143 + cd_dst_opts 134 + cd_routing 163 + cd_mobility 143 + cd_igmp 138 (~720 L) — every one rides the LANDED 17d CheckIPV6HopOptions / CheckIPv6ExtensionOrder + RFC order tables. (Footnote carried from csum PLAN §0: 18e 721 < 18d 730 by 9 L — strict size order would swap; keep NEXT order, 18d registers the codec vocabulary 18e+ consume.)
- Then tunnels WITH self-include suite units — teredo 161+121 / gtp 291+140 / geneve 282+163 (self-include gate pattern = the 17f/17g precedent — but these 3 suites are **CppUTest**: Rust-side translation, deviation-noted, C gate untouched; suite counts re-confirmed at f91be60-era counts: 2+2+3 TESTs); and `ip/checksum.h`'s 201-L suite is ALREADY translated (18b done, 10 TEST/3 GROUP — grep pins re-run THIS pass: `^TEST(` = 10, TEST_GROUP :56/:107/:156).
- Then **cd_gre 366 = the row that changes the gate (rule below)**; then the ICMP pair (645+518), then udp 660 / ipv4 790 / ipv6 733 / tcp 839 (checksum.h fully resident since 18b — these rows `git grep`-hit the 39-line checksum:: census, 8 files incl. packet_manager.cc :641/:697/:705), then the link tail (mpls/vlan/pppoe/erspan/ciscometadata/fabricpath/trans_bridge/ppp_encap, 2,043 total), then the misc tail (llc 198 / vxlan 133 / user 167 / icmp4_ip 345 / icmp6_ip 162).

### The gate rule for the rest of row 18 (status at 18b close-out: **10 straight**, re-measured live THIS pass)
Gate md5 `4826fc2233044a2d5429413faf0ae1af` has stayed **byte-ident every subrow through 18b** (chain holders measured THIS pass = 9 files: fcap, fcshare, fconf, fcapi, finspect, fpolicy, fsvc, flog, fmod; 18b added NO gate = zero-EDIT row, census 9 asserted in its build.sh :154 + re-counted by md5 census THIS docs pass = 9). Stays byte-ident 18c.. until the **cd_gre subrow** (11th straight at 18c, ...). At the **cd_gre row the gate MUST change, exactly once**: compile the embedded UNIT_TEST block (:351-:366, the `[cd_gre]` case at :352) via the fmod build.sh catch recipe (:249 catch.hpp pull, :270 shim heredoc, catch_main link) and apply the duplicate-symbol rule — the gate link carries the UT-compiled cd_gre TU ONLY, the plain probe `.o` excluded; on the PROBE build excise the trailing UNIT_TEST block (rfind recipe). Expected new gate line: **"All tests passed (115 assertions in 23 test cases)"** — MEASURE it from the runner, NEVER type it from this forecast (the 17p lesson). That run's gate.txt becomes the NEW chain anchor md5; every later subrow byte-matches the NEW md5. CppUTest suites NEVER touch the C gate (no CppUTest on host — E4 receipt re-proven every csum build). NEVER edit a frozen donor's gate/vectors to "fix" a count.

## Alternative quick-win rows (verdicts re-affirmed at this pass)
| target | lines | gate material | notes |
|---|---|---|---|
| main/thread_config.cc | 920 | **14** `[ThreadConfig]` Catch cases at :615–:903 | cpuset parse/affinity/NUMA failure ladders; hwloc witness ladder (17l numa precedent); THE fallback if row 18 stalls |
| codecs/ip/checksum.h (18b) | 284 | CppUTest suite (host-unbuildable) — DONE, Rust-side | csum probe-only donor |
| file_api (17m–18a) | — | — | DONE — **subsystem CLOSED**, fmod donor = lineage head |

## Backlog (plan rows)
- 17z: DONE (ef9bf83) — wiki trio LANDED (f91be60).
- 18a: DONE (74bcc23) — wiki trio LANDED (9792858 — wiki HEAD verified this pass; Porting-status.md:91 + Deviations-from-Snort-3.md:960 greps present).
- 18b: **DONE (7e1744c)** — codecs chapter OPENED: `src/codecs/checksum.rs` 436L FRESH (src/codecs/ NEW dir; 15 inline fns = 7 detail + 8 public + 2 Pseudoheader types w/ const size_of pins 12/36 + `arr_words()`/`as_bytes()` union-view ruling — deviations :2236-:2320, adequate-leave, verified this pass); `tools/csum_harness` = first PROBE-ONLY harness (zero gate by nm-proof, E4 wall receipt every build; 19 self-check arms in build.sh); vectors 16L md5 e4baf78... stable x2 clean rebuilds THIS pass + O0==O2 arm; gate chain 10th straight CONFIRMED live (fmod rebuild f0fdbab/4826fc22 byte-ident this docs pass; census 9 holders); `tests/csum_parity_test.rs` 414L 14 tests (16/16 replay + 10 up_gate + 3 Q extras); suite re-run 487/0 THIS pass (59 result lines); clippy forced relint 0 THIS pass; .gitignore block :291-:300+ check-ignore re-verified this pass. **Wiki trio for 18b OWED** (next WIKI phase; wiki HEAD 9792858 stops at 18a, 18b grep = 0 hits verified).
- 18: codecs — 18b DONE; 18c scoping ABOVE (549 L claim VERIFIED with per-file wc table THIS pass); row continues 18d/18e/... per order above.
- 19: detection option engines (~30k+ subset claim stands but the tree measures **14,533** .h+.cc with **~47** embedded Catch TEST_CASEs — fp_utils.cc 21, detection_options.cc 6, ips_context.cc 5, extract.cc 5, ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2, sfrim.cc 1, ips_context_data.cc 1 — real Catch material to carry like 17f/17r; re-grep at that row's scoping pass); 20: packet_io / DAQ (AF_PACKET via libc; the 17d RawData/daq_msg deferral + the 18c daq_dlt.h graft both close HERE); 21: main CLI + `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/<harness> && bash build.sh` -> vectors+gate md5 stable x2 clean rebuilds.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard; 18b variant: verify-grep if shipped with the code commit) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
