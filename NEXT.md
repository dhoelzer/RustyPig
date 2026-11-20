# NEXT.md — takeover context & plan (2026-11-20, post-18d: codecs root/link layer + the DECODE_* vocabulary header + ARP landed; donor = eth_harness)

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

Current state (measured at this 18d verify-mode docs pass): plan rows
1–18d DONE. 97 commits counting the 18d code commit 5c8e31e — **this
docs commit lands as the 98th**. **511 tests green / 0 FAILED** (full
`cargo test --all-targets` re-run AT THIS docs pass: summed
`test result` lines = 511 passed / 0 failed, `grep -c '^test result'`
= 61 lines (60 at 18c + 1 from `tests/eth_parity_test.rs`); 511 = 498
+ 13 eth (`grep -c '#\[test\]' tests/eth_parity_test.rs` = 13 re-measured
THIS pass; the three new src/codecs TUs carry ZERO in-crate `#[test]` —
grep 0/0/0 measured), `cargo clippy --all-targets` **0 warnings**
(forced relint THIS pass: touched every .rs, `Checking snort3` ran,
`grep -c '^warning'` = 0), 42,828 lines Rust across 132 `src/*.rs`
files (`find src -name '*.rs' -exec wc -l {} +` THIS pass), 35
`tests/*_parity_test.rs` whole-transcript replay tests among 60 tracked
test files, 365 tracked files (`git ls-files | wc -l`), 42
`tools/*_harness` dirs. GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `72d39cd` = **row 18c wiki trio LANDED**:
verified read-only at this docs pass — `git -C /tmp/RustyPig.wiki log -1`
prints `72d39cd row 18c: status + deviations + stats (96 commits / 356
files / 41,782 src lines / 498 tests; SECOND probe-only codecs row,
zero-gate census 0 on all 6 files, gate 11th straight byte-ident
4826fc2233044a2d5429413faf0ae1af, plan cite PORTING_PLAN.md:82 in code
commit 9ed8a8f)` atop `aa22a11 row 18b`, and the 18c trio greps PRESENT
(`Porting-status.md:93` status row + `:97` chapter note +
`Deviations-from-Snort-3.md:1163` deviations header — the 18c trio is
NO LONGER debt; the wiki is NEVER touched by code or plan rows). **The
18d wiki trio is OWED** and is owed at the NEXT WIKI phase, not by this
docs pass (`grep -rn 'row 18d' --include='*.md' /tmp/RustyPig.wiki` =
**0 hits** verified this pass; even a bare-`18d` grep = 0 hits,
measured THIS pass). The owed trio = status row (root/cd_eth.cc +
codec_module.{h,cc} + link/cd_arp.cc, 730 L ground -> 964 L Rust across
3 flat src/codecs/*.rs (+41 framework/codec.rs wiring +7 parse_conf.rs),
probe-only eth harness, gate untouched 12th straight, suite ZERO
upstream, 511 tests) + the row-18d deviations section (copy from KNOWN
DEVIATIONS.md :2420-:2577) + stats line ("97 commits / 365 tracked
files / ~42,800 src lines / 511 tests").

## 18d close-out — VERIFY MODE (plan row + deviations shipped WITH code commit 5c8e31e; this pass greps-verify rather than append)
Like 18b/18c, 18d's plan row and deviations section shipped inside the
CODE commit, so this docs pass is a verification pass. Everything below
was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18d |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:83) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what 5c8e31e shipped (`git show
  --stat 5c8e31e`: 15 files, +2,590 — harness 5 files + docs row +
  deviations + 3 Rust TUs + mod.rs/codec.rs/parse_conf.rs wiring +
  tests/eth_parity_test.rs 608 L in one commit).
- **Deviations section**: `grep -c '^## codecs ethernet/arp/module (row 18d'
  KNOWN DEVIATIONS.md` = **1** at :2420, running to EOF at :2577 = 158
  lines / 16 bullets (`grep '^- \*\*'` count THIS pass). **Verdict:
  adequate — leave, no follow-up edits.** Anchor re-grounding (every
  file opened THIS pass in ground snort3-src @ fe29cbe7403a): cd_eth
  `SnortConfig::get_conf()` REAL at cd_eth.cc:164 (tree's first
  consumer); `TextLog_Print` literals `  len:0x%04X` / `  type:0x%04X`
  REAL at cd_eth.cc:133/:135 (sed-verified); the cc:161-:162 ternary
  (`ho->ether_type = enc.ethertype_set() ? htons(...) : hi->ether_type`)
  REAL; codec_module.cc help define cc:30-:31 + one-row `s_params`
  PT_MAX cc:37 + `#ifndef DEBUG_MSGS / return nullptr` cc:47-:48 +
  the `general_decode_rules` 8 rows + `{ 0, nullptr }` terminator
  cc:55-:67 ALL REAL via sed THIS pass; codec_module.h `GID_DECODE =
  116` h:38, `DECODE_ARP_TRUNCATED = 109` h:73 (literal pin),
  `DECODE_ICMP4_TYPE_OTHER = 418` h:171 + `DECODE_ETH_HDR_TRUNC` h:177
  (walk pin +6), `is_list = false` default h:246 — ALL REAL; cd_arp.cc
  `const BaseApi* cd_arp[] =` REAL at cd_arp.cc:122; real LogEthAddrs
  body at log/log_text.cc:112 (stays OUT of the link); snort_config.h
  :289 `uint8_t* eth_dst = nullptr` NSDMI REAL; codec_api.cc:34
  `extern const BaseApi* cd_hopopts[]` + :82 `load_plugins(cd_hopopts)`
  REAL (the dormant STATIC_CODECS face the landmine note leans on);
  eth build.sh :606 census echo + :60-:62 lua-seam asserts REAL;
  witness_stubs.cc stub bodies :7-:10 + table defs :11-:14 REAL;
  vectors.txt:25-:28 the four `LOAD cd_*_stub` lines REAL; eth
  vectors.txt:2 HELP `(DLT 1) (DLT 51)`, :3 `EV 116 424`, :7/:8 `DLT
  51` then `DLT 1`, :12 `EV 116 109`, :15 `MOD rules=8 gid=116
  help=general decoder rules trace=null` ALL re-read REAL;
  `find src/codecs/link src/codecs/root -iname '*test*'` EMPTY re-run
  (the zero-suite census foundation).
- **Numbers drift note (recorded honestly; the row was NOT edited)**:
  the plan row's nm-census triple `cd_eth 26 / cd_arp 21 /
  codec_module 14` matches the on-disk receipt `wc -l` EXACTLY
  (nm_U_cd_eth 26, nm_U_cd_arp 21, nm_U_codec_module 14 THIS pass), but
  its `module 5 / text_log 13` figures do not match ANY live face of
  this pass (receipts now 32/30 lines; the build.sh :603 echo counts
  are 4/8). Fresh live echo THIS rebuild: `cd_eth(snort::)=14 arp=11
  codec_module=10 module=4 text_log=8`. The census METHOD (per-TU
  receipts, re-run every build) is sound; the module/text_log headline
  figures in the shipped row drifted. Next docs pass may restate —
  do NOT rewrite the shipped row (no force-push rule stands).
- **Vectors stability**: `tools/eth_harness/vectors.txt` 15 L md5
  `1bd98dbb57dd2f536104995bd76d9bad` — eth build.sh re-run FRESH THIS
  docs pass (rc 0, `ETH_HARNESS_OK vectors=15`): md5 stable,
  `vectors_O0.txt` byte-ident to the pin, `O0==O2 vectors identity:
  BYTE-IDENT` self-check re-armed, `util-dup collision proven: E6-YES`
  re-printed, residue echo `cd_eth=14 arp=11 codec_module=10 module=4
  text_log=8 (ZERO cd_*[] tables)`, all-decimal hygiene (`grep -c '0x'`
  = 0 re-run). Receipt `/opt/data/cache/scratch/eth_rebuild_18ddocs.log`.
- **Gate chain LIVE — TWELFTH STRAIGHT, MEASURED not asserted**: fmod
  rebuilt FRESH THIS pass (rc 0, `FMOD_HARNESS_OK vectors=61`): vectors
  `f0fdbab06fe1681af1c654531b917c55` + gate `4826fc2233044a2d5429413faf0ae1af`,
  gate.txt last non-empty line VERBATIM `All tests passed (114
  assertions in 22 test cases)` (receipt `/opt/data/cache/scratch/fmod_rebuild_18ddocs.log`).
  md5 census over all tracked gate.txt THIS pass: exactly **9 files**
  carry `4826fc22...` (fcap, fcapi, fconf, fcshare, finspect, flog,
  fmod, fpolicy, fsvc) out of **24**; the eth build echoed the same
  `gate census holders: 9/24` live (build.sh :606), and :597-:600
  assert 9 == holders, 24 == total, and `test ! -e gate.txt/gate` —
  18d shipped NO gate artifacts (probe-only row). vocab donor vectors
  md5 `5da70e82416b6f769af8177d859331e7` re-pinned by FILE md5 THIS
  pass (29 L; not rebuilt — the ritual rebuild pair is now eth + fmod,
  see Session ritual).
- **Test math**: 511 = 498 + 13 — `tests/eth_parity_test.rs` 608 L,
  13 `#[test]` (`eth_transcript_replay` 15/15 ordered +
  `codec_sid_walk_vs_header` + rules-table + module-record face +
  trace-slot + DLT-ladder composition + fpath/log/encode/format/update
  + arp-PIDS + the record census — 10 fixture fns grep-listed THIS
  pass); the 3 landed src TUs (`cd_eth.rs` 364 L, `codec_module.rs`
  459 L, `cd_arp.rs` 141 L — wc re-run THIS pass) carry ZERO in-crate
  tests. Suite result at THIS pass: all green, 0 FAILED (61 result
  lines).
- **commit census + gitignore**: 97 at HEAD 5c8e31e (`git rev-list
  --count HEAD`); .gitignore eth block at :325-:334 re-verified by
  `git check-ignore` THIS pass (copy/ :326, probe :328, nm_U_* :334,
  vectors_O0.txt :332 all ignored; `vectors.txt` + `build.sh` +
  `stubs_18d.cc` NOT ignored, rc 1 — stageables exactly 5,
  `git ls-files tools/eth_harness` = PLAN.md build.sh probe.cc
  stubs_18d.cc vectors.txt) — do NOT re-add.

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt`. The transcript is truth:
   never fabricate behavior from memory; if a run flakes, fix
   determinism, never lock a flaky transcript. vectors.txt is a tracked
   INPUT the build re-verifies but NEVER fabricates (18d: when a
   verification pass deleted it, build.sh correctly refused; restored
   VERBATIM from its own vectors_O0.txt receipt).
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
   recipe) — cd_gre.cc (366 L) is EXACTLY that shape early (:34-:35)
   + trailing (:351-:366), the cd_gre row will run this recipe.
   The 17y row added the INVERSION lesson: when a donor carries a
   WITNESS BLOCK for the row TU, landing the real TU retires the block
   (23 hard collisions, fsvc build.sh :706-:707/:778/:827 nm pins) —
   the retire-evidence echo is the guard, not a silent link failure.
   The 18a row added the PER-LINK corollary: retirement applies to the
   CURRENT donor's stubs ONLY — the frozen donors keep their blocks +
   their vectors/gate/tests byte-frozen, and a census test pins both
   faces (fmod `trio_retirement_census`). The 18b row added the
   PROBE-ONLY corollary: when the row contributes ZERO .o to every
   donor link and its suite dialect cannot build on host, the honest
   artifact is a probe-only harness — NO gate at all, with the zero-
   contribution claim nm-proved in build.sh and the 9-holder chain
   re-censused EVERY build. 18c/18d exercised it twice more (18d:
   per-file grep 0/0/0 on all four row files + `test ! -e gate.txt`
   asserts, `ETH_HARNESS_OK vectors=15`). The 18d row added the
   INVERTED-DUP face of the dup rule: the NEW real cp (utils/util.o)
   retires an OLD frozen donor (codec_harness/stubs.cc — link arm 10
   MUST FAIL with `multiple definition .* snort_str`, receipt
   E6_dup_collision.txt re-printed every build, build.sh :479-:486),
   then the harness' OWN tracked stubs_18d.cc carries the
   `RETIRED at 18d:` marker (:30) — the frozen donor stays byte-frozen
   in its own dir. A fake Catch gate over a suite-zero row = the
   17p anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fmod_parity_test.rs` (1009 lines, whole 61-line replay + the
   retirement census), freshest-smallest `tests/eth_parity_test.rs`
   (608 L, 15-line ordered transcript replay via the probe statement
   order + R6 var-first mirror + 12 per-file arms — the pattern for
   zero-suite rows), then `tests/vocab_parity_test.rs` (442 L),
   `tests/csum_parity_test.rs` (414 L, probe-only rows WITH a suite),
   `tests/flog_parity_test.rs`, `tests/fsvc_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 511; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings (force relint by touching all .rs),
   `vectors.txt` md5 stable across >= 2 clean rebuilds (gate.txt md5
   likewise — regenerable, hence .gitignore'd: md5-pinned in docs per
   row, NOT tracked), harness `.gitignore` block added (mirror
   siblings) and verified with `git check-ignore` BEFORE staging (the
   eth block is .gitignore:325-:334, landed inside code commit
   5c8e31e). Then commit + push, insert the plan row (grep-guard:
   count must be 0 before insert — the numa double-append incident
   cost a force-push), append deviations (one grep-guarded append) —
   the 18b/18c/18d variant: BOTH ship inside the code commit, then the
   docs pass VERIFY-greps them (count == 1 each) instead of inserting,
   and still re-measures every load-bearing claim. Refresh NEXT.md
   (FRESH rewrite), commit+push docs, update the wiki (status row +
   deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s/18b/18c/18d do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH — `-lluajit` hits the .so and the gate probe dies at load, no rpath; `-lm -ldl` tail; nm pin fmod build.sh:961). 18d row TUs carry ZERO lua refs (grep -ci lua 0/0/0/0 asserted at eth build.sh :60-:62 every build).
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum + vocab + eth build: `cpputest_fatal.txt` wall receipt at checksum_test.cc:36 include; eth E4_walls_* receipts re-printed at the 18d build). Upstream **CppUTest** suites (the 4 codecs/misc/test + ip/test suites, the 16g/16h lru suites — translated Rust-side) can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp + the snort_catch.h shim) runs natively.
- **daq_dlt.h graft IS now a committed fact** (existed nowhere in ground — 18c find): `tools/vocab_harness/copy/daq_dlt.h` + the eth copy carry `DLT_RAW 12` (libpcap master pcap/dlt.h:112-:114) extended at 18d with `DLT_EN10MB 1` (master :68) + `DLT_PPP_ETHER 51` (master :243) — the 18c android-mirror URL 404s as of this pass, cite CORRECTED in the graft header. Later rows cp/extend THAT graft; row 20 cites the real DAQ include chain.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 var-first arms + 18d eth replay mirrored Rust-side).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction). Since 18a `file_trace` has its REAL def on BOTH sides (Rust token Cell armed via the transcribed cc:154 set_trace; harness side the row .o defines it, fcache_set_file_trace rides it, fmod stubs.cc:205).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/eth_harness/` — **THE donor for row 18e+ (lineage head)**: the 18d probe-only row/link pattern — exactly 5 tracked files (build.sh 608L, probe.cc 41L, PLAN.md 83L 9 sections, stubs_18d.cc 35L with the :30 `RETIRED at 18d` marker, vectors.txt 15L tracked), `copy/` tree = the vocab donor VERBATIM + the 4 row cps + the 26-file measured delta (per the plan row's census: vocab-donor + row cps; top level now also holds `flowz/`, `trace/`, `log/`, `detection/`, `control/` + `util.o`/`text_log.o`/`module.o` real cps), the EXTENDED `daq_dlt.h` graft, EOFLOW/EOFTRH/EOFDAQ heredoc carries, packet.h flow.h->flowz/flow_fwd.h SURGERY + thread_config.h hwloc excision carries. Self-checks re-run THIS pass: O0==O2 identity, per-TU nm receipts `nm_U_*.txt`, ZERO-cd_*[]-table assert, E6 inverted-dup collision assert (:479-:486), 9/24 gate census echo (:597-:606), lua-seam assert (:60-:62). vectors md5 `1bd98dbb57dd2f536104995bd76d9bad` (committed, NEVER edit); NO gate.txt (probe-only). Its copy tree holds EVERY header the 18e five TUs `#include` (closure grep THIS pass — see 18e scoping) = zero fresh cps needed.
- `tools/vocab_harness/` — the 18c donor (superseded at 18d; kept for lineage): 9 committed files (build.sh 325L, probe.cc 90L, witness_stubs.cc 14L — **the 4 cd_*[] stub tables at :11-:14 with bodies :7-:10, frozen by vectors:25-:28**, witness_conf.cc, PLAN.md 69L, vectors.txt 29L tracked, cp_audit_ok.txt); the `daq_dlt.h` GRAFT originated here; `test ! -e "$H"/witness_stubs.cc` at eth build.sh :380 proves the eth link carries NO stub tables. vectors md5 `5da70e82416b6f769af8177d859331e7` (committed, NEVER edit).
- `tools/fmod_harness/` — the 18a donor & **gate-lineage source** (rebuilt fresh at every docs pass for the byte-ident echo — done THIS pass, 12th straight): cp braces + objs loop carry the FULL file_api closure; first third-party link (`libluajit.a` BY PATH + `-lm -ldl`, nm pin :961); §0.1 header-cp chain + 2 witness grafts (TraceOption in trace.h, DIOCTL in daq_common.h); stubs.cc 984L; build.sh 1164L; vectors.txt 61L md5 `f0fdbab06fe1681af1c654531b917c55`; gate md5 `4826fc2233044a2d5429413faf0ae1af`.
- `tools/csum_harness/` — row 18b, **the probe-only pattern for ZERO-.o rows**: no gate shipped; build.sh self-checks = ground-header md5 pin (:37), E4 CppUTest wall receipt (:67-:70), dialect proof (:72-:73), nm ZERO-text-symbols proof (:79-:80), O0==O2 (:116), 9-holder census (:154). vectors 16L md5 `e4baf7816440e18917d3249597f60b88`. PLAN.md carries the 8-file/39-line checksum:: consumer census + donor_defs.txt nm backbone.
- `tools/flog_harness/` — the 17z donor (superseded; kept for lineage); vectors 50L md5 `b260ec6ae0be7ebbf4e0e60338b8cee3`.
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
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe. **`tools/codec_harness` is row 17d's harness (framework/codec base; its stubs.cc md5 `be9bdd0b437d1f6c56c841e8155d9e70` is the FROZEN donor the 18d E6-YES arm re-collides against every build) — 18e MUST re-read it: the RawData/daq_msg deferral closed partially at 18c (codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.**

## Next milestone — row 18e: the IPv6 extension chain (18d closed root/link + the vocabulary header; this scoping FRESH-measured at the 18d docs pass)

### 18e scale table — every `wc -l` re-run THIS pass, ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY

| unit (measured path THIS pass) | lines (`wc -l` this pass) | gate material (per-file grep THIS pass) |
|---|---|---|
| `ip/cd_hop_opts.cc` | **143** | 0 TEST_CASE / 0 TEST_GROUP / 0 `TEST(` / 0 UNIT_TEST |
| `ip/cd_dst_opts.cc` | **134** | 0/0/0/0 |
| `ip/cd_routing.cc` | **163** | 0/0/0/0 |
| `ip/cd_mobility.cc` | **143** | 0/0/0/0 |
| `ip/cd_igmp.cc` | **138** | 0/0/0/0 |
| **TOTAL** | **721** (143+134+163+143+138, summed this pass) | **NONE — probe-vectors-only row, fourth time (18b/18c/18d precedent)** |

- **Include closure is ZERO-FRESH at the eth donor** (per-TU
  `grep '^#include'` THIS pass): all five TUs include ONLY
  `config.h` + `codecs/codec_module.h` + `framework/codec.h` +
  `main/snort_config.h` (cd_igmp the same four, snort_config last but
  present) — ALL four headers RESIDENT in `tools/eth_harness/copy/`
  this pass (ls-verified). ip/ carries NO codec headers of its own
  (only `checksum.h`, resident since 18b). 18e lifts the eth donor
  VERBATIM + 5 row cps; per-TU nm_U_*.txt residue census BEFORE
  witnesses (18d discipline).
- **Donor = eth_harness** (lineage head, Deviations-verified untouched
  frozen donors); re-run the 9/24 gate census + fmod fresh rebuild ->
  **13th straight byte-ident**, MEASURED.
- **Every 18e unit rides the LANDED 17d CheckIPV6HopOptions face**:
  `src/framework/codec.rs:521 check_ipv6_hop_options` + `:594
  check_ipv6_extension_order` + `:636/:650` the two order tables
  (grep THIS pass) — RFC order tables already in Rust codec.rs from
  the 17d base; 18e ports the five codecs that CALL them.

### THE cd_hopopts dup-landmine — retirement MECHANISM spelled (carry-forward from 18d; analyzed THIS docs pass with fresh cites)
- **The frozen face**: `tools/vocab_harness/witness_stubs.cc:11-:14`
  defines the four stub tables `cd_ipv4[]/cd_ipv6[]/cd_tcp[]/
  cd_hopopts[]` (bodies :7-:10); the stub names are FROZEN by
  `vocab vectors.txt:25-:28` (`LOAD cd_ipv4_stub`..`LOAD
  cd_hopopts_stub`, re-read THIS pass) and consumed Rust-side by
  `src/codecs/codec_api.rs:82-:85` (the dormant-tripwire records;
  deviations :2351-:2357 R3: "a later row renaming a stub forks the
  vectors"; :2526-:2534: 18d verified NO retirement — the vocab stub
  set carries NO cd_arp/cd_eth).
- **The collision face (why it is a landmine at 18e)**: the REAL
  `const BaseApi* cd_hopopts[]` lands at `ip/cd_hop_opts.cc:137`
  (sed-verified THIS pass — `//SO_PUBLIC ... //#else` context right
  above). If an 18e link carries BOTH the vocab witness_stubs.cc and
  the real cd_hop_opts.o, the two `cd_hopopts[]` defs MUST fail with
  multiple-definition — EXACTLY the E6 face 18d rehearsed INVERTED:
  eth build.sh :479-:486 compiles the frozen `tools/codec_harness/
  stubs.cc`, asserts the co-link FAILS with `multiple definition of
  .*snort_str` (receipt `E6_dup_collision.txt`, `E6-YES` echo every
  build), then links the harness' OWN `stubs_18d.cc` whose :30
  `RETIRED at 18d:` marker is the retire-evidence echo. The 18a
  PER-LINK corollary applies: 18e retires ONLY its own link's copy of
  the stub (its cp of witness_stubs.cc, line :14), while the FROZEN
  vocab donor keeps its stub + frozen vectors byte-frozen.
- **The clean face (CHOSEN posture for 18e)**: the eth donor link
  carries ZERO cd_*[] stub tables — eth build.sh :380
  `test ! -e "$H"/witness_stubs.cc` proves it (re-read THIS pass).
  Lifting the eth donor means the real `cd_hopopts[]` simply links
  FRESH, no collision, no retirement ceremony needed. The landmine
  then bites only in two disciplined places: (i) if 18e ALSO pulls
  `codec_api.cc` into its link, the dormant `extern cd_hopopts[]` at
  codec_api.cc:34 (with :82 `load_plugins(cd_hopopts)`, sed-verified
  THIS pass) FREE-resolves to the real table — that is a face FLIP of
  the probe: the transcript would print the real LOAD, forking the
  frozen vocab vectors if vocab transcript were replayed here — do
  NOT pull codec_api.cc into the 18e probe; keep the dormant pinned;
  (ii) Rust-side: adding the real `cd_hopopts[]` record must NOT
  rename/fork the four `stub("cd_*_stub")` consts at
  codec_api.rs:82-:85 — census-test both faces like fmod
  `trio_retirement_census`. The four heavyweights cd_ipv4/ipv6/tcp
  (stub-colliding, codec_api.cc externs at :31-:33 region) + the
  three UNstubbed 18e names cd_dstopts (codec_api.cc:44/:89),
  cd_igmp (:58/:103), cd_mobility (:60/:105), cd_routing (:67/:112)
  (all grep-verified THIS pass) complete the later-row checklist:
  the stub trio retires at the three heavyweight rows, the four
  18e-only names never collide because no stub exists for them.
- **Vectors arms for 18e** (arm plan, values NEVER pre-typed — 17p
  lesson): the five codecs' HELP arms, each table's API line (size
  112/ver 1900547 carry), the RFC order-table interactions through
  CheckIPV6HopOptions/CheckIPv6ExtensionOrder (the landed codec.rs
  face), DECODE_*/6.x event sids via the landed full CodecSid enum
  (18d landed all 170 discriminants — 18e NEVER re-walks), the
  option-walk loop arms (TLVs), IGMP's odd-ball group decode arms.
  Gate material 0 across the slab -> **NO new gate.txt**; the 9/24
  census echo + fmod fresh rebuild land the 13th straight.

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — both wc sweeps re-run THIS docs pass)
- Then tunnels WITH self-include suite units (path pin THIS pass: all
  THREE live in `misc/`, NOT ip/; ground `ls misc/` shows **ZERO .h
  files** — the old `+121/+140/+163` figures are the CppUTest SUITE
  files, not headers): teredo `misc/cd_teredo.cc` 161 +
  `misc/test/teredo_codec_test.cc` 121 / gtp `misc/cd_gtp.cc` 291 +
  `gtp_codec_test.cc` 140 / geneve `misc/cd_geneve.cc` 282 +
  `geneve_codec_test.cc` 163 — all wc re-run THIS pass; the three
  suites are **CppUTest** (grep 3/3/4 hits THIS pass): Rust-side
  translation, deviation-noted, C gate untouched (E4 receipt).
  `ip/checksum.h`'s 201-L suite is ALREADY translated (18b, 10 TEST/
  3 GROUP).
- Then **cd_gre 366 = the row that changes the gate (rule below)** —
  `ip/cd_gre.cc` wc re-run THIS pass = 366 ✓; then the ICMP pair
  (`ip/cd_icmp4.cc` 645 + `ip/cd_icmp6.cc` 518 wc THIS pass), then
  udp **`ip/cd_udp.cc`** 660 (path pin THIS pass — ip/, NOT misc/ as
  an old draft said) / ipv4 790 / ipv6 733 / tcp 839 (all wc re-run
  THIS pass; checksum.rs fully resident since 18b; the 4 stub tables
  get REAL retirement treatment at three of these rows, per-link,
  via the E6 inverted mechanics), then the link tail (wc THIS pass:
  mpls 390 / vlan 236 / pppoe 243 / erspan2 145 / erspan3 147 /
  ciscometadata 235 / fabricpath 187 / trans_bridge 158 / ppp_encap
  174), then the misc tail (wc THIS pass: llc 198 / vxlan 133 /
  user 167 / icmp4_ip 345 / icmp6_ip 162).
- The 18c STATIC_CODECS extern census (39 tables, cc-order) + the
  dormant STATIC_CODEC_EXTERN_NAMES tripwire give the later rows
  their completeness checklist: by the end of row 18 every extern
  must either link real or stay pinned dormant.

### The gate rule for the rest of row 18 (status at 18d close-out: **12 straight**, RE-MEASURED live THIS pass — fmod rebuilt fresh + md5 census, not asserted)
Gate md5 `4826fc2233044a2d5429413faf0ae1af` (tail line reads `All tests passed (114 assertions in 22 test cases)`, re-printed from the fresh fmod gate.txt THIS pass) has stayed **byte-ident every subrow through 18d** (chain holders md5-censused THIS pass = exactly 9 files: fcap, fcapi, fconf, fcshare, finspect, flog, fmod, fpolicy, fsvc, out of 24 tracked gate.txt; 18b/18c/18d added NO gate = zero-gate rows, eth build.sh echoed `gate census holders: 9/24` live at its rebuild). Stays byte-ident 18e.. until the **cd_gre subrow** (13th straight at 18e, ...). At the **cd_gre row the gate MUST change, exactly once**: ip/cd_gre.cc has BOTH shapes — an EARLY `#ifdef UNIT_TEST` include fragment at :34-:35 (`#include "catch/snort_catch.h"` — sed re-verified THIS pass) AND the trailing suite block at **:351-:366** (`TEST_CASE ("Validate error check for raw_len greater than GRE_HEADER_LEN", "[cd_gre]")` at :352, :366 `#endif` — sed re-verified THIS pass) — so the 17r rfind/balance-guard excision recipe runs on the PROBE build (LAST block only) while the gate build compiles the block verbatim via the fmod build.sh catch recipe (:249 catch.hpp pull, :270 shim heredoc, catch_main link), and the **duplicate-symbol rule** applies — the gate link carries the UT-compiled cd_gre TU ONLY, the plain probe `.o` excluded. Expected new gate line: **"All tests passed (115 assertions in 23 test cases)"** (= 114/22 + the `[cd_gre]` case at :352 with its 1 CHECK — arithmetic from the measured 114/22 tail, but MEASURE the runner's line, NEVER type it from this forecast — the 17p lesson). That run's gate.txt becomes the NEW chain anchor md5; every later subrow byte-matches the NEW md5. CppUTest suites NEVER touch the C gate (no CppUTest on host — E4 receipt re-proven every csum AND vocab AND eth build). NEVER edit a frozen donor's gate/vectors to "fix" a count.

### 18e alternatives — honest comparison (measured THIS pass)
| option | size | gate material | verdict |
|---|---|---|---|
| **(a) NEXT order as scheduled: 18e = IPv6 extension chain (hopopts 143 + dstopts 134 + routing 163 + mobility 143 + igmp 138)** | 721 L, zero Catch material (0/0/0/0 per-file grep THIS pass) | still 0 = 13th straight | **CHOSEN**: include closure measured ZERO-fresh at the eth donor (four resident headers); the codec.rs:521/:594/:636/:650 call-targets LANDED since 17d; the cd_hopopts landmine resolves CLEANLY at the eth donor (zero stub tables in the link, eth build.sh :380) while the E6 inverse-dup mechanics + per-link retirement are already rehearsed if codec_api is ever pulled; the four 18e-only table names never collide (no stub exists). |
| (b) jump to cd_gre 366 to land the ONE gate-change early | 366 L | **1** Catch case (the 115/23 flip) | REJECT: breaks the size/dependency order — cd_gre decodes UNDER the ip-ext chain it would now precede, the 17r rfind excision + dup-symbol gate recipe is the riskiest C-side move and wants the probe-only rows banked first, and the existing NEXT footnote already rules keep-order. The rule above stays pinned to the cd_gre row. |
| (c) detour to `src/main/thread_config.cc` quick-win | 920 L wc re-verified THIS pass | **14** `[ThreadConfig]` Catch TEST_CASEs (grep re-counted THIS pass) | The ONLY nearby row with fresh Catch gate material — first chance to extend the gated chain off the 114/22 anchor before cd_gre; needs hwloc witness ladder (17l numa precedent; note the eth tree already carries the thread_config.h hwloc EXCISION face) + breaks codec-row continuity and the donor chain. Keep strictly as the fallback if row 18 stalls (18a/18c ruling re-affirmed). |

## Backlog (plan rows)
- 17z: DONE (ef9bf83) — wiki trio LANDED (f91be60).
- 18a: DONE (74bcc23) — wiki trio LANDED (9792858).
- 18b: DONE (7e1744c) — wiki trio LANDED (aa22a11).
- 18c: DONE (9ed8a8f) — wiki trio LANDED (72d39cd — wiki HEAD verified THIS docs pass: `row 18c` greps PRESENT at Porting-status.md:93/:97 + Deviations-from-Snort-3.md:1163; the lone bare-`18c`-era deferral note at Deviations :1160 is the 18b-era flat-vs-dir note; wiki stats 96 commits / 356 files / 41,782 src lines / 498 tests).
- 18d: **DONE (5c8e31e)** — codecs root/link landed: `root/cd_eth.cc` + `codec_module.{h,cc}` + `link/cd_arp.cc` (730 L ground -> 964 L Rust across src/codecs/{cd_eth 364L, codec_module 459L, cd_arp 141L}.rs FLAT, +41 framework/codec.rs ETH wiring +7 parse_conf.rs eth_dst); `tools/eth_harness` NOW LINEAGE HEAD (exactly 5 tracked files, copy tree = vocab donor + row cps + 26-file delta, EXTENDED daq_dlt graft, E6 inverted-dup arm, ZERO cd_*[] tables asserted); vectors 15L md5 `1bd98dbb...` stable (FRESH rebuild THIS docs pass, O0==O2 arm, E6-YES); gate chain **12th straight CONFIRMED live THIS pass** (fmod fresh rebuild byte-ident + 9/24 md5 census); `tests/eth_parity_test.rs` 608L 13 tests (15/15 ordered replay + 12 per-file arms); suite re-run **511/0** THIS pass (61 result lines); clippy forced relint 0 THIS pass; .gitignore eth block :325-:334 check-ignore re-verified THIS pass (stageables exactly 5); plan row + deviations VERIFY-GREPED this pass (count 1 each: PORTING_PLAN.md:83 / KNOWN DEVIATIONS.md:2420-:2577, 158L/16 bullets, verdict ADEQUATE-LEAVE with every anchor re-grounded + the module/text_log census-drift note — see 18d close-out). **Wiki trio for 18d OWED** (next WIKI phase; wiki HEAD 72d39cd stops at 18c; `row 18d` grep = 0 hits verified THIS pass, bare `18d` also 0).
- 18: codecs — 18b/18c/18d DONE; 18e scoping ABOVE (721 L claim VERIFIED with per-file wc table THIS pass; landmine mechanism spelled); row continues per order above.
- 19: detection option engines (~30k+ subset claim stands but the tree measures **14,533** .h+.cc with **~47** embedded Catch TEST_CASEs — fp_utils.cc 21, detection_options.cc 6, ips_context.cc 5, extract.cc 5, ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2, sfrim.cc 1, ips_context_data.cc 1 — real Catch material to carry like 17f/17r; re-grep at that row's scoping pass); 20: packet_io / DAQ (AF_PACKET via libc; the 17d RawData/daq_msg deferral + the daq_dlt.h graft (now TWO consumers: vocab 18c + cd_eth 18d) both close HERE); 21: main CLI + `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/eth_harness && bash build.sh` -> vectors md5 stable x2 clean rebuilds (NO gate — probe-only; E6-YES echo); rebuild `tools/fmod_harness` too for the gate-chain byte-ident echo (vocab md5 file-pin spot-check optional).
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard; 18b/18c/18d variant: verify-grep if shipped with the code commit) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
