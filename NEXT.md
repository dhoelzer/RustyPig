# NEXT.md — takeover context & plan (2026-11-20, post-18e: codecs IPv6 extension chain landed; donor = ext_harness)

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

Current state (measured at this 18e verify-mode docs pass): plan rows
1–18e DONE. 99 commits counting the 18e code commit c30a30e — **this
docs commit lands as the 100th**. **521 tests green / 0 FAILED** (full
`cargo test --all-targets` re-run AT THIS docs pass: summed
`test result` lines = 521 passed / 0 failed, `grep -c '^test result'`
= 62 lines (61 at 18d + 1 from `tests/ext_parity_test.rs`); 521 = 511
+ 10 ext (`grep -c '#\[test\]' tests/ext_parity_test.rs` = 10
re-measured THIS pass; the five new src/codecs TUs carry ZERO in-crate
`#[test]` — 993 Rust L across the five, wc re-run THIS pass),
`cargo clippy --all-targets` **0 warnings** (forced relint THIS pass:
touched every .rs, `Finished` line present, `grep -c '^warning'` = 0),
43,831 lines Rust across 137 `src/*.rs` files (`find src -name '*.rs'
-exec wc -l {} +` THIS pass), 36 `tests/*_parity_test.rs` whole-
transcript replay tests among 61 tracked test files, 378 tracked files
(`git ls-files | wc -l`), 43 `tools/*_harness` dirs. GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `63a6170` = **row 18d wiki trio LANDED**:
verified read-only at this docs pass — `git -C /tmp/RustyPig.wiki log
-1` prints `63a6170 row 18d: status + deviations + stats (98 commits /
365 files / 42,828 src lines / 511 tests ...)` atop `72d39cd row 18c`,
and the 18d trio greps PRESENT (`Porting-status.md:94` status row +
`:99` chapter note + `Deviations-from-Snort-3.md:1261` deviations
header — the 18d trio is NO LONGER debt; the wiki is NEVER touched by
code or plan rows). **The 18e wiki trio is OWED** and is owed at the
NEXT WIKI phase, not by this docs pass (`grep -rn 'row 18e'
--include='*.md' /tmp/RustyPig.wiki` = **0 hits** verified this pass;
a bare-`18e` grep = 2 hits and BOTH are carry-forward mentions, NOT the
trio: `Deviations-from-Snort-3.md:1372` the 18d-section landmine note
"18e cd_hopopts landmine carries forward UNCHANGED" +
`Porting-status.md:93` the 18c status row mentioning the later row —
measured THIS pass). The owed trio = status row (ip/cd_hop_opts.cc +
cd_dst_opts.cc + cd_routing.cc + cd_mobility.cc + cd_igmp.cc, 721 L
ground -> 993 L Rust across 5 flat src/codecs/*.rs, mod.rs wiring
only; probe-only ext harness w/ DUAL faces 27L DEC + 9L FACE-A, gate
untouched 13th straight census 9/24, suite ZERO upstream, 521 tests) +
the row-18e deviations section (copy from KNOWN DEVIATIONS.md
:2579-:2730) + stats line ("99 commits / 378 tracked files / ~43,800
src lines / 521 tests").

## 18e close-out — VERIFY MODE (plan row + deviations shipped WITH code commit c30a30e; this pass greps-verify + re-ground rather than append)
Like 18b/18c/18d, 18e's plan row and deviations section shipped inside
the CODE commit, so this docs pass is a verification pass. Everything
below was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18e |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:84) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what c30a30e shipped (`git show
  --stat c30a30e`: 17 files, +2,287 — harness 7 tracked files + docs
  row + deviations + 5 Rust TUs + mod.rs wiring +
  tests/ext_parity_test.rs 593 L in one commit).
- **Deviations section**: `grep -c '^## codecs ipv6 extension codecs
  (row 18e' KNOWN DEVIATIONS.md` = **1** at :2579, running to EOF at
  :2730 = 152 lines / 13 bullets (`grep '^- \*\*'` count THIS pass).
  **Verdict: adequate-READ — leave, no follow-up edits.** Anchor
  re-grounding (files opened THIS pass in ground snort3-src @
  fe29cbe7403a): the five row files `wc -l` 143/134/163/143/138 = 721
  EXACT re-run; cd_hopopts always-static oddity REAL at
  ip/cd_hop_opts.cc:134-:138 (`//#ifdef BUILDING_SO` / `//SO_PUBLIC` /
  `//#else` / `const BaseApi* cd_hopopts[] =` / `//#endif`) with the
  cc:130-:132 "static to ensure the symbols CheckIPV6HopOptions and
  CheckIPv6ExtensionOrder" comment REAL and the cc:17 header-author
  "cd_hopopts.cc" drift kept; codec_api.cc:34 `extern const BaseApi*
  cd_hopopts[]` + :82 `load_plugins(cd_hopopts)` + :44/:89 cd_dstopts
  pair REAL (sed THIS pass); snort_config.h:278
  `max_ip6_extensions = 0` NSDMI + :451 the hit-lambda REAL (the 456
  dead-at-default cite); vectors.txt:22-:23 `EV 116 475` + `MOB
  badpayl -> 1 next=60` re-read REAL; stubs_18e.cc:14 the `RETIRED at
  18e: cd_hopopts stub (real table ip/cd_hop_opts.cc:137 lands this
  row)` marker REAL (grep THIS pass); codec_api.rs:82 +
  :102/:116/:118/:125 the CD_DSTOPTS/CD_IGMP/CD_MOBILITY/CD_ROUTING
  ladder names re-read REAL (cd_hopopts ABSENT from the 34-ladder,
  rides the always-loaded five); Rust five TUs wc 202+174+206+177+234
  = 993 EXACT re-run.
- **ip/test census re-measured (the zero-suite foundation for the
  five)**: `wc -l ip/test/checksum_test.cc` = **201** + `ip/test/
  CMakeLists.txt` = 1 = 202 (the 18b face, re-run THIS pass);
  combined grep `TEST_CASE|TEST_GROUP|^TEST(|UNIT_TEST` = 0/0/0/0/0 on
  ALL FIVE row files re-run THIS pass — matches ext build.sh PLAN §0
  seeds and the deviations cite.
- **Vectors stability — BOTH faces re-md5'd THIS pass**:
  `tools/ext_harness/vectors.txt` 27 L md5 re-summed EXACT against
  the pinned value `da21842980d042d5871edeaaf502049e`; `vectors_faceA.txt` 9 L
  md5 `0fa79b534d2a598b2befb047c95c3579` — both stable across the
  FRESH ext rebuild THIS pass (`EXT_HARNESS_OK vectors=27 faceA=9`,
  `O0==O2: FACE-A BYTE-IDENT, DEC BYTE-IDENT`, `vectors_faceII.txt`
  receipt md5 `cdaa92dfb8bdb35ce1ffaa41c1ae3fc4` asserted equal by
  build.sh :309 at the rebuild, 3 stubs survive the flip + `LOAD
  cd_hopopts_stub` count 0 + `LOAD ipv6_hop_opts` FORK-MEASURED — the
  face-II receipt is NEVER a tracked pin). probe.cc 21 L md5
  `af4c83fcd6845898c29784249bcb7edf` + probe_dec.cc 48 L md5
  `35d7f771c450657c0df6ffc313dc76e2` re-summed THIS pass, zero drift.
  Receipt `/opt/data/cache/scratch/ext_rebuild_18edocs.log`.
- **Landmine receipts LIVE at the docs-pass ext rebuild**: E6 co-link
  real cd_hop_opts.o + frozen vocab witness_stubs.o FAILED with
  `multiple definition of ... cd_hopopts` as required every build
  (receipt `E6_hopopts_dup_collision.txt`), own stubs_18e.cc = frozen
  vocab MINUS :14 PLUS marker, diff-0 proven; 3-face stub census echo
  `frozen=4 retired=3 real=5`; per-TU nm residue `hopopts=11
  dstopts=11 routing=10 mobility=10 igmp=21` — matches the shipped
  plan row's `11/11/10/10/21` triple EXACTLY (zero drift this pass —
  unlike the 18d module/text_log drift, 18e's census figures all
  match live faces); frozen vocab donor untouched (witness_stubs.cc
  md5 `9fad7e9d7a278fbc2ee82c233f86e774` asserted byte-ident by ext
  build.sh :342 at the rebuild). Copy tree 101 files (find THIS pass;
  c30a30e message's "81 files" counted tracked+delta against the
  86-file eth tree — live `find tools/ext_harness/copy -type f` =
  101; recorded honestly, row NOT rewritten, no force-push rule).
- **Gate chain LIVE — THIRTEENTH STRAIGHT, MEASURED not asserted**:
  fmod rebuilt FRESH THIS pass (rc 0, `FMOD_HARNESS_OK vectors=61`):
  vectors `f0fdbab06fe1681af1c654531b917c55` + gate
  `4826fc2233044a2d5429413faf0ae1af`, gate.txt last non-empty line
  VERBATIM `All tests passed (114 assertions in 22 test cases)`
  (receipt `/opt/data/cache/scratch/fmod_rebuild_18edocs.log`).
  eth donor rebuilt FRESH THIS pass too (rc 0, `ETH_HARNESS_OK
  vectors=15`, O0==O2 BYTE-IDENT, `E6-YES` util-dup echo, residue
  `cd_eth=14 arp=11 codec_module=10 module=4 text_log=8`, vectors
  `1bd98dbb57dd2f536104995bd76d9bad` stable — receipt
  `/opt/data/cache/scratch/eth_rebuild_18edocs.log`). md5 census over
  all 24 `tools/*/gate.txt` THIS pass: exactly **9 files** carry
  `4826fc22...` (fcap, fcapi, fconf, fcshare, finspect, flog, fmod,
  fpolicy, fsvc); ext build.sh :319-:323 asserts 9 == holders, 24 ==
  total, and zero gate artifacts in the ext dir — 18e shipped NO gate
  (probe-only row, fourth time). vocab donor vectors md5
  `5da70e82416b6f769af8177d859331e7` re-pinned by FILE md5 THIS pass
  (29 L; its ritual rebuild slot moved to the ext harness' vocab-
  donor-side E6 asserts at build.sh :342/:176 — witness_stubs.cc
  byte-ident + recompiled).
- **Test math**: 521 = 511 + 10 — `tests/ext_parity_test.rs` 593 L,
  10 `#[test]` (27/27 ORDERED DEC replay + 9/9 ORDERED FACE-A replay
  + the cited arms incl `ext_static_names_tripwire` +
  `ext_record_census` — both function names grep-counted = 1 each
  THIS pass); the 5 landed src TUs (`cd_hop_opts.rs` 202 L,
  `cd_dst_opts.rs` 174 L, `cd_routing.rs` 206 L, `cd_mobility.rs`
  177 L, `cd_igmp.rs` 234 L — wc re-run THIS pass) carry ZERO
  in-crate tests. Suite result at THIS pass: all green, 0 FAILED, 0
  panicked (62 result lines).
- **commit census + gitignore**: 99 at HEAD c30a30e (`git rev-list
  --count HEAD`); .gitignore ext block at :343-:370 re-verified by
  `git check-ignore` THIS pass (copy/ :344, probe :347, probe_dec
  :349, vectors_faceII.txt :365, probe_lc.cc :352 all ignored;
  `vectors.txt` + `vectors_faceA.txt` + `build.sh` + `PLAN.md` +
  `probe.cc` + `probe_dec.cc` + `stubs_18e.cc` NOT ignored, rc 1 —
  stageables exactly 7, `git ls-files tools/ext_harness` = PLAN.md
  build.sh probe.cc probe_dec.cc stubs_18e.cc vectors.txt
  vectors_faceA.txt) — do NOT re-add.

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
   re-censused EVERY build. 18c/18d/18e exercised it three more times
   (18e: per-file grep 0 x5 + `test ! -e gate.txt` + zero-gate
   asserts, `EXT_HARNESS_OK vectors=27 faceA=9`). The 18d row added
   the INVERTED-DUP face of the dup rule: the NEW real cp
   (utils/util.o) retires an OLD frozen donor (codec_harness/stubs.cc
   — link arm 10 MUST FAIL with `multiple definition .* snort_str`,
   receipt E6_dup_collision.txt re-printed every build, build.sh
   :479-:486), then the harness' OWN tracked stubs_18d.cc carries the
   `RETIRED at 18d:` marker (:30) — the frozen donor stays byte-frozen
   in its own dir. The 18e row added the **FACE-RULE face**: a probe
   that must NEVER fork a frozen transcript keeps the flipping TU
   OUT of every tracked link (FACE-A/DEC link lists carry ZERO
   codec_api object), and rehearses the flip as a BUILD RECEIPT only
   (vectors_faceII.txt, build.sh :307-:312 asserts the FORK live) —
   receipts are .gitignore'd, never tracked, never replayed Rust-side.
   A fake Catch gate over a suite-zero row = the 17p anti-pattern.
3. **Rust port** in `src/...`: literal transcription. Deviations are
   allowed only when structurally forced (trait objects, Vec<u8> for
   byte-carrying std::string, Rc<RefCell> arenas...) and every one
   gets a section in `KNOWN DEVIATIONS.md`.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-line assert), donor pattern:
   `tests/fmod_parity_test.rs` (1009 lines, whole 61-line replay + the
   retirement census), freshest-smallest `tests/ext_parity_test.rs`
   (593 L, DUAL-face ordered replay — 27-line DEC + 9-line FACE-A,
   probe statement order + R6 var-first mirror — the pattern for
   multi-face zero-suite rows), then `tests/eth_parity_test.rs`
   (608 L), `tests/vocab_parity_test.rs` (442 L),
   `tests/csum_parity_test.rs` (414 L, probe-only rows WITH a suite),
   `tests/flog_parity_test.rs`, `tests/fsvc_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 521; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings (force relint by touching all .rs),
   `vectors.txt` md5 stable across >= 2 clean rebuilds (gate.txt md5
   likewise — regenerable, hence .gitignore'd: md5-pinned in docs per
   row, NOT tracked), harness `.gitignore` block added (mirror
   siblings) and verified with `git check-ignore` BEFORE staging (the
   ext block is .gitignore:343-:370, landed inside code commit
   c30a30e). Then commit + push, insert the plan row (grep-guard:
   count must be 0 before insert — the numa double-append incident
   cost a force-push), append deviations (one grep-guarded append) —
   the 18b/18c/18d/18e variant: BOTH ship inside the code commit, then
   the docs pass VERIFY-greps them (count == 1 each) instead of
   inserting, and still re-measures every load-bearing claim. Refresh
   NEXT.md (FRESH rewrite), commit+push docs, update the wiki (status
   row + deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s/18b/18c/18d/18e do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH — `-lluajit` hits the .so and the gate probe dies at load, no rpath; `-lm -ldl` tail; nm pin fmod build.sh:961). 18d/18e row TUs carry ZERO lua refs (grep -ci lua asserted every build at eth build.sh :60-:62 / ext build.sh).
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum + vocab + eth + ext build: `cpputest_fatal.txt` wall receipt at checksum_test.cc:36 include; ext build.sh re-printed the E4_walls_* receipts at the docs-pass rebuild). Upstream **CppUTest** suites (the 4 codecs/misc/test + ip/test suites — the 18f trio's three wall at misc/test/{teredo,gtp,geneve}_codec_test.cc:31-:32 / :25-:26, the 16g/16h lru suites — translated Rust-side) can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp + the snort_catch.h shim) runs natively.
- **daq_dlt.h graft IS now a committed fact** (existed nowhere in ground — 18c find): `tools/vocab_harness/copy/daq_dlt.h` + the eth copy carry `DLT_RAW 12` (libpcap master pcap/dlt.h:112-:114) extended at 18d with `DLT_EN10MB 1` (master :68) + `DLT_PPP_ETHER 51` (master :243) — the 18c android-mirror URL 404s as of this pass, cite CORRECTED in the graft header. Later rows cp/extend THAT graft; row 20 cites the real DAQ include chain.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 var-first arms + 18d/18e replay mirrored Rust-side — 18e probe_dec.cc R6 face re-mirrored, `probe statement order` asserted in the Rust 27-line replay).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction). Since 18a `file_trace` has its REAL def on BOTH sides (Rust token Cell armed via the transcribed cc:154 set_trace; harness side the row .o defines it, fcache_set_file_trace rides it, fmod stubs.cc:205).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/ext_harness/` — **THE donor for row 18f+ (lineage head)**: the 18e probe-only DUAL-face pattern — exactly 7 tracked files (build.sh 330L, probe.cc 21L md5 `af4c83fc…`, probe_dec.cc 48L md5 `35d7f771…`, PLAN.md 58L, stubs_18e.cc 14L with the :14 `RETIRED at 18e` marker, vectors.txt 27L md5 `da218429…` tracked, vectors_faceA.txt 9L md5 `0fa79b53…` tracked), `copy/` tree = the eth donor VERBATIM + EXACTLY 5 row cps (find = 101 files THIS pass), ZERO fresh cps/grafts needed for the 18e five (include closure fully resident — the 18f FRESH scoping below shows the tunnels DO need fresh cps: `protocols/teredo.h` + `packet_io/active.h` MISS the tree THIS pass). Self-checks re-run THIS pass at the docs rebuild (rc 0, `EXT_HARNESS_OK vectors=27 faceA=9`): both-face md5 pins, O0==O2 per face, E6 cd_hopopts co-link MUST-fail + diff-0 + 3-face nm census (`frozen=4 retired=3 real=5`), FACE-II flip asserts (:307-:312), per-TU nm receipts (`hopopts=11 dstopts=11 routing=10 mobility=10 igmp=21`), gate census 9/24 + zero-gate asserts, cd_gre anchors re-measured NOT touched (:50-:53 sed asserts: :34 `#ifdef UNIT_TEST`, :35 snort_catch include, :352 one TEST_CASE, 366 L), vocab witness_stubs.cc md5 assert (:342), rule that FACE-A/DEC links carry ZERO codec_api object. NO gate.txt (probe-only).
- `tools/eth_harness/` — the 18d donor (superseded at 18e as lineage head; kept, rebuilt fresh every docs pass for the E6-YES + residue echo — done THIS pass): exactly 5 tracked files (build.sh 608L, probe.cc 41L, PLAN.md 83L 9 sections, stubs_18d.cc 35L with the :30 `RETIRED at 18d` marker, vectors.txt 15L tracked), copy tree = 86 files (find THIS pass), the EXTENDED `daq_dlt.h` graft, EOFLOW/EOFTRH/EOFDAQ heredoc carries, packet.h flow.h->flowz/flow_fwd.h SURGERY + thread_config.h hwloc excision carries, `test ! -e "$H"/witness_stubs.cc` (:380), 9/24 census echo (:597-:606), lua-seam assert (:60-:62). vectors md5 `1bd98dbb57dd2f536104995bd76d9bad` (committed, NEVER edit); NO gate.txt.
- `tools/vocab_harness/` — the 18c donor (superseded; kept for lineage): 9 committed files (build.sh 325L, probe.cc 90L, witness_stubs.cc 14L md5 `9fad7e9d7a278fbc2ee82c233f86e774` — **the 4 cd_*[] stub tables at :11-:14 with bodies :7-:10, frozen by vectors:25-:28**, witness_conf.cc, PLAN.md 69L, vectors.txt 29L tracked, cp_audit_ok.txt); the `daq_dlt.h` GRAFT originated here. vectors md5 `5da70e82416b6f769af8177d859331e7` (committed, NEVER edit).
- `tools/fmod_harness/` — the 18a donor & **gate-lineage source** (rebuilt fresh at every docs pass for the byte-ident echo — done THIS pass, 13th straight): cp braces + objs loop carry the FULL file_api closure; first third-party link (`libluajit.a` BY PATH + `-lm -ldl`, nm pin :961); §0.1 header-cp chain + 2 witness grafts (TraceOption in trace.h, DIOCTL in daq_common.h); stubs.cc 984L; build.sh 1164L; vectors.txt 61L md5 `f0fdbab06fe1681af1c654531b917c55`; gate md5 `4826fc2233044a2d5429413faf0ae1af`.
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
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe. **`tools/codec_harness` is row 17d's harness (framework/codec base; its stubs.cc md5 `be9bdd0b437d1f6c56c841e8155d9e70` is the FROZEN donor the E6-YES arms re-collide against every build) — 18f MUST re-read it: the RawData/daq_msg deferral closed partially at 18c (codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.**

## Next milestone — row 18f: the tunnel trio (18e closed the IPv6 extension chain; this scoping FRESH-measured at the 18e docs pass)

### 18f scale table — every `wc -l` re-run THIS pass, ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY

| unit (measured path THIS pass) | lines (`wc -l` this pass) | gate material (per-file grep THIS pass) |
|---|---|---|
| `misc/cd_teredo.cc` | **161** | 0 TEST_CASE / 0 TEST_GROUP / 0 `TEST(` / 0 UNIT_TEST |
| `misc/cd_gtp.cc` | **291** | 0/0/0/0 |
| `misc/cd_geneve.cc` | **282** | 0/0/0/0 |
| `misc/test/teredo_codec_test.cc` | **121** | CppUTest wall (NOT host-runnable) |
| `misc/test/gtp_codec_test.cc` | **140** | CppUTest wall (NOT host-runnable) |
| `misc/test/geneve_codec_test.cc` | **163** | CppUTest wall (NOT host-runnable) |
| **TOTAL row TUs** | **734** (161+291+282, summed this pass) + 424 L suite side (121+140+163 = 424) | **ZERO Catch material in the TUs -> probe-vectors-only, fifth time (18b/18c/18d/18e precedent)** |

### ALL-claim re-verification w/ find+wc cites (the "tunnels ALL live in misc/" claim, re-run THIS pass)
- `ls misc/` = `CMakeLists.txt cd_default.cc cd_geneve.cc cd_gtp.cc
  cd_icmp4_ip.cc cd_icmp6_ip.cc cd_llc.cc cd_teredo.cc cd_user.cc
  cd_vxlan.cc dev_notes.txt test/` — and
  `find /opt/data/snort3-src/src/codecs/misc -name '*.h' | wc -l` =
  **0**: the misc/ slab carries ZERO .h files. The old `+121/+140/+163`
  tunnel figures were NEVER headers — they are the `misc/test/` SUITE
  files, re-wc'd THIS pass at exactly 121/140/163; the TUs are 161/291/282.
- `find misc -name '*.cc'` = the 9 TUs + `find misc -name '*test*'` =
  the 3 named suites above — no stray tunnel file hides in ip/ or
  link/: `cd_udp` = `ip/cd_udp.cc` 660 (path pin holds), `cd_gre` =
  `ip/cd_gre.cc` 366 (path pin holds, see gate rule below).
- codec_api.cc STATIC_CODECS extern census **re-counted THIS pass** =
  39 (`grep -c 'extern const BaseApi\*' codecs/codec_api.cc`), and the
  tunnel six are IN it with cites: cd_geneve :51/:96, cd_gtp :53/:98,
  cd_llc :59/:104, cd_teredo :68/:113, cd_user :71/:116, cd_vxlan
  :73/:118 (extern/load_plugins pairs grep-verified THIS pass) — the
  three 18f names are UNstubbed (no witness stub exists), so the
  cd_hopopts-style landmine NEVER fires for them; same discipline as
  the four 18e-only names.
- misc/ tail wc re-run THIS pass: llc 198 / vxlan 133 / user 167 /
  icmp4_ip 345 / icmp6_ip 162 (+ cd_default.cc 83, LANDED at 18c —
  do not count in tail totals). Row-18 tree totals re-run THIS pass:
  codecs/ = **11,914 L / 48 files**, non-test **11,289 L / 44 files**
  (find+wc sweeps identical to the 18d figures — zero drift).

### CppUTest wall census — runner-re-confirmed LIVE at the docs-pass ext rebuild (the E4 face)
- The three suite files are CppUTest, not Catch: each
  `#include <CppUTest/CommandLineTestRunner.h>` +
  `<CppUTest/TestHarness.h>` (teredo/gtp :31/:32, geneve :25/:26 — sed
  THIS pass); geneve additionally the ONLY one with
  `#include <CppUTestExt/MockSupport.h>` :27 (MockSupport grep = 1 hit
  in the trio; the mock machinery must NOT be faked — translate the
  arm's OBSERVABLE assertions only, deviation-note the mock calls).
- TEST_GROUP names (grep THIS pass): `teredo_codec_tests` /
  `gtp_codec_tests` / `geneve_codec_tests`; TEST( counts 2/2/3 (the
  old 3/3/4 NEXT figure is SUPERSEDED — that grep counted TEST_GROUP+
  TEST( lines together; per-construct counts pinned THIS pass); raw
  CHECK-family counts 1/8/18 (teredo CHECK_TRUE 1, gtp 8, geneve 18).
- CppUTest remains NOT installed on this host — re-proven by the FRESH
  ext build.sh docs-pass rebuild (rc 0) which re-prints the E4_walls_*
  receipts (`scratch/ext_rebuild_18edocs.log`): any suite compiled
  against the host hits the include wall at the CppUTest header line,
  exactly the checksum_test.cc:36 precedent. So 18f's suites are
  **Rust-side translation only** (like the 18b 10-TEST/3-GROUP
  checksum translation and the 16g/16h lru suites), deviation-noted;
  the C gate stays UNTOUCHED = **14th straight**, the 9/24 census echo
  + fmod fresh rebuild carry the proof (NEVER a fake Catch gate — the
  17p anti-pattern).
- **The geneve double-wall finding (NEW this pass, sed-verified)**:
  ALL THREE suites `#include "../cd_<tunnel>.cc"` directly —
  geneve :20, teredo :29, gtp :29 — so the SUITE TU is the codec TU
  (self-include shape): even if CppUTest existed, the suite compile
  drags the codec TU + its includes TWICE into one binary; the
  thread_config include at all three `:27`/`:23` (teredo/gtp :27,
  geneve :23) drags the hwloc face (17l numa precedent + the eth
  tree's thread_config.h hwloc EXCISION carry) plus `config.h`;
  geneve additionally pulls `utils/endian.h` :22. None of this can
  run natively — it just bounds the blast radius if a later host-
  availability miracle ever tempts a native gate.

### Fresh cps the 18f row needs at the ext donor (measured THIS pass — the tunnels are NOT zero-fresh like 18e)
- Include closure per-TU (`grep '^#include'` THIS pass): teredo =
  config.h + framework/codec.h + main/snort_config.h +
  **protocols/teredo.h** + cstring; gtp = config.h +
  codecs/codec_module.h + framework/codec.h + main/snort_config.h;
  geneve = config.h + codecs/codec_module.h + framework/codec.h +
  log/text_log.h + main/snort_config.h + **packet_io/active.h** +
  **protocols/geneve.h**.
- Residency census against `tools/ext_harness/copy/` THIS pass (ls
  loop): codec_module.h/codec.h/config.h/snort_config.h/log/text_log.h/
  log.h/protocols/ip.h/managers/plugin_manager.h = RESIDENT (geneve's
  ground-copy `protocols/geneve.h` md5 `10cfe860...` byte-ident to
  ground in the tree); **MISS = `protocols/teredo.h` (44 L ground,
  wc THIS pass) and `packet_io/active.h` (240 L ground)** — plus the
  geneve `utils/endian.h` family: geneve.h RESIDENT covers geneve's
  own defs; endian.h is header-only ground-resident elsewhere in
  the tree's utils chain (re-verify at row). So 18f = ext donor
  VERBATIM + 3 row cps + fresh cps: teredo needs `protocols/teredo.h`
  ONLY (44 L, trivial); geneve needs the `packet_io/active.h` drag —
  240 L header whose Active body (managers/active_manager + the
  packet_io subsystem) does NOT exist in Rust src either (no
  src/packet_io; row 20 territory; grep THIS pass). cd_geneve.cc
  itself references the `Active` symbol ZERO times (`grep -c 'Active'
  cd_geneve.cc` = 0 — the include is inherited weight, likely trim-
  able like the 17x header trims; DO NOT trim ground C in the probe,
  graft/witness instead); its decode logs via the LANDED log/text_log
  face (resident since 18d). Honest call: land 18f as ONE row if the
  active.h witness stays header-only (the E4-style include + zero-
  symbol posture), else teredo+gtp first and geneve as subrow —
  decide at the row's ext-PLAN §0 with the SAME zero-symbol nm proof
  discipline, and NEVER pre-type vectors values (17p lesson).
- Call targets ride LANDED faces only: BaseCodecModule/RuleMap/
  RuleMap rule_count (18d), CodecSid full 170-discriminant enum (18d,
  NEVER re-walk), check_ipv6_* tables (17d/18e); geneve/teredo need
  NO new subsystem beyond what the fresh cps + the landed log face
  cover — that is the 18d eth pattern.

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — both find+wc sweeps re-run THIS docs pass)
- Then **cd_gre 366 = the row that changes the gate (rule below; 18f
  is the 14th holder of the byte-ident chain and stays ZERO-EDIT
  because every cd_gre.cc anchor was re-MEASURED live, never pre-dug;
  the gate-change-at-cd_gre arithmetic is intentionally NOT written
  down here at all)** —
  `ip/cd_gre.cc` wc re-run THIS pass = 366 ✓, early + trailing
  anchors re-verified THIS pass by BOTH this docs grep AND the live
  ext build.sh self-asserts (:50-:53 — sed `:34 == #ifdef UNIT_TEST`,
  `:35 == #include "catch/snort_catch.h"`, :352 exactly one
  `TEST_CASE (`, wc 366): if 18f takes two subrows, cd_gre = the 14th
  gate-change row either way; **NEVER type the new gate line, MEASURE
  the runner**, and this docs pass intentionally leaves even the
  old 115/23 forecast un-repeated in this file (17p lesson hard-
  enforcer: the arithmetic hint lived in NEXT.md since 18c; the cd_gre
  runner's line is the ONLY anchor. THIS pass deliberately deleted
  the old arithmetic forecast that lived in NEXT.md since 18c — the
  cd_gre build.sh/runner receipts are the sole source of the new tail
  line, and any number copied forward invites the 17p failure mode).
  The dup-symbol rule + 17r rfind/balance-guard excision recipe stand
  exactly as the ext build.sh :50-:53 asserts pin it. NOT to be
  confused with the cd_gre gate change: `ip/cd_gre.cc` is NOT a
  tunnels row and 18f changes NO gate.
- Then the ICMP pair (`ip/cd_icmp4.cc` **645** + `ip/cd_icmp6.cc`
  **518** wc THIS pass), then udp **`ip/cd_udp.cc` 660** (path pin
  re-verified — ip/, NOT misc/) / ipv4 **790** / ipv6 **733** / tcp
  **839** (all wc re-run THIS pass; checksum.rs fully resident since
  18b; the 4 stub tables cd_ipv4/cd_ipv6/cd_tcp + the retired
  cd_hopopts face get REAL retirement treatment at three of these
  rows, per-link, via the E6 inverted mechanics + ext 3-face census
  discipline), then the link tail (wc THIS pass: mpls 390 / vlan 236
  / pppoe 243 / erspan2 145 / erspan3 147 / ciscometadata 235 /
  fabricpath 187 / trans_bridge 158 / ppp_encap 174), then the misc
  tail (wc THIS pass: llc 198 / vxlan 133 / user 167 / icmp4_ip 345 /
  icmp6_ip 162).
- The 18c STATIC_CODECS extern census (**39** tables re-counted THIS
  pass, cc-order) + the dormant STATIC_CODEC_EXTERN_NAMES tripwire
  give the later rows their completeness checklist: by the end of row
  18 every extern must either link real or stay pinned dormant.

### 18f alternatives — honest comparison (measured THIS pass)
| option | size | gate material | verdict |
|---|---|---|---|
| **(a) NEXT order as scheduled: 18f = tunnel trio (teredo 161 + gtp 291 + geneve 282)** | 734 L | 0 Catch in TUs (per-file 0/0/0/0 grep THIS pass); 3 CppUTest suites 424 L Rust-side translated | **CHOSEN**: rides the ext donor at 734 L; 2 of 3 TUs (teredo/gtp) need ONE fresh cp / zero fresh cps; the CppUTest-wall posture is fully rehearsed (E4 receipts live at every rebuild since 18b); the three names are UNstubbed externs — zero landmine risk, ext 3-face census carries over as the discipline. |
| (b) jump to cd_gre 366 to land the ONE gate-change early | 366 L | 1 Catch case (magnitude +1 case) | REJECT AGAIN: same ruling as 18d's (b) — breaks size/dependency order (gre decodes under the chain tunnels feed), the 17r excision + dup-symbol gate recipe is the riskiest C move and must bank the zero-gate rows first. Rule stays pinned to the cd_gre row. |
| (c) detour to `src/main/thread_config.cc` quick-win | 920 L wc re-verified THIS pass (unchanged) | 14 `[ThreadConfig]` Catch TEST_CASEs (grep re-count THIS pass) | Still the ONLY nearby fresh-Catch-gate option; needs the hwloc witness ladder (17l precedent; the eth tree already carries the thread_config.h hwloc EXCISION face — the 18f suites' thread_config :27/:23 drag re-confirms that carry pays rent) + breaks codec-row continuity and the donor chain. Keep strictly as the fallback if row 18 stalls (18a/18c/18d ruling re-affirmed THIS pass). |

### The gate rule for the rest of row 18 (status at 18e close-out: **13 straight**, RE-MEASURED live THIS pass — fmod + eth + ext all rebuilt fresh, 9/24 md5 census re-run, not asserted)
Gate md5 `4826fc2233044a2d5429413faf0ae1af` (gate.txt last non-empty line re-read VERBATIM THIS pass: `All tests passed (114 assertions in 22 test cases)`) has stayed **byte-ident every subrow through 18e** (chain holders md5-censused THIS pass = exactly 9 of 24: fcap, fcapi, fconf, fcshare, finspect, flog, fmod, fpolicy, fsvc; 18b/18c/18d/18e added NO gate = four zero-gate rows, eth build.sh echoed `gate census holders: 9/24` live AND ext build.sh :319-:320 asserted 9==holders/24==total at the docs-pass rebuild). Stays byte-ident 18f.. until the **cd_gre subrow** where it MUST change, exactly once: the ext build.sh :50-:53 anchors (THIS pass live), the 17r rfind excision recipe for the PROBE build (LAST block only), the fmod catch-recipe gate build (:249/:270), and the **duplicate-symbol rule** (gate link carries the UT-compiled cd_gre TU ONLY, plain probe .o excluded). The runner's line — NOT any number typed in any docs — becomes the NEW chain anchor. NEVER edit a frozen donor's gate/vectors to "fix" a count.

## Backlog (plan rows)
- 17z: DONE (ef9bf83) — wiki trio LANDED (f91be60).
- 18a: DONE (74bcc23) — wiki trio LANDED (9792858).
- 18b: DONE (7e1744c) — wiki trio LANDED (aa22a11).
- 18c: DONE (9ed8a8f) — wiki trio LANDED (72d39cd).
- 18d: DONE (5c8e31e) — wiki trio LANDED (63a6170, wiki HEAD verified THIS docs pass: `row 18d` greps PRESENT at Porting-status.md:94/:99 + Deviations-from-Snort-3.md:1261; wiki stats 98 commits / 365 files / 42,828 src lines / 511 tests).
- 18e: **DONE (c30a30e)** — codecs IPv6 extension chain landed: `ip/cd_hop_opts.cc` + `cd_dst_opts.cc` + `cd_routing.cc` + `cd_mobility.cc` + `cd_igmp.cc` (721 L ground -> 993 L Rust across src/codecs/{cd_hop_opts 202L, cd_dst_opts 174L, cd_routing 206L, cd_mobility 177L, cd_igmp 234L}.rs FLAT, mod.rs wiring ONLY outside); `tools/ext_harness` NOW LINEAGE HEAD (exactly 7 tracked files, DUAL-face vectors 27L `da218429...` + 9L FACE-A `0fa79b53...` both stable at the docs-pass rebuild rc 0, O0==O2 both faces; cd_hopopts dup landmine retired INVERTED with E6 MUST-fail + diff-0 + 3-face census frozen=4/retired=3/real=5 + FACE-II flip receipt (receipt NEVER a pin); per-TU nm residue 11/11/10/10/21 matches the plan row EXACTLY); gate chain **13th straight CONFIRMED live THIS pass** (fmod + eth + ext rebuilt fresh THIS pass + 9/24 md5 census re-run); `tests/ext_parity_test.rs` 593L 10 tests (27/27 + 9/9 ordered replays + cited arms); suite re-run **521/0** THIS pass (62 result lines, 0 FAILED/panicked); clippy forced relint 0 THIS pass; .gitignore ext block :343-:370 check-ignore re-verified THIS pass (stageables exactly 7); plan row + deviations VERIFY-GREPED this pass (count 1 each: PORTING_PLAN.md:84 / KNOWN DEVIATIONS.md:2579-:2730, 152L/13 bullets, verdict ADEQUATE-READ-LEAVE with every anchor re-grounded — see 18e close-out; ONE honest drift recorded: the commit message's copy-tree "81 files" vs live find = 101, file-count drift only, no behavioral claim moved — row NOT rewritten). **Wiki trio for 18e OWED** (next WIKI phase; wiki HEAD 63a6170 stops at 18d; `grep 'row 18e'` = 0 hits verified THIS pass; the 2 bare-`18e` greps are carry-forward mentions at Deviations :1372 + Porting-status :93, NOT the trio).
- 18: codecs — 18b/18c/18d/18e DONE; 18f scoping ABOVE (734 L claim VERIFIED with per-file wc table THIS pass; misc/-ALL claim re-verified with find cites: 0 .h in misc/, suites 121+140+163 = 424 L side; geneve double-wall + self-include suite shape pinned; fresh-cp census: protocols/teredo.h + packet_io/active.h MISS the donor, geneve.h resident byte-ident); row continues per order above.
- 19: detection option engines (~30k+ subset claim stands but the tree measures **14,533** .h+.cc with **~47** embedded Catch TEST_CASEs — fp_utils.cc 21, detection_options.cc 6, ips_context.cc 5, extract.cc 5, ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2, sfrim.cc 1, ips_context_data.cc 1 — real Catch material to carry like 17f/17r; re-grep at that row's scoping pass); 20: packet_io / DAQ (AF_PACKET via libc; the 17d RawData/daq_msg deferral + the daq_dlt.h graft (now TWO consumers: vocab 18c + cd_eth 18d) both close HERE — the 18f geneve `packet_io/active.h` fresh-cp demand is the FIRST live rent on this closure, keep the posture documented above); 21: main CLI + `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/ext_harness && bash build.sh` -> BOTH vectors md5s stable x2 clean rebuilds (NO gate — probe-only; E6 dup MUST-fail echo + 3-face census + O0==O2 both faces); rebuild `tools/eth_harness` (donor-2 lineage) AND `tools/fmod_harness` too for the gate-chain byte-ident echo (vocab md5 file-pin spot-check now rides ext build.sh :342's live assert).
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard; 18b-18e variant: verify-grep if shipped with the code commit) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
