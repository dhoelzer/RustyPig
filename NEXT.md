# NEXT.md — takeover context & plan (2026-11-20, post-18f: codecs misc tunnel trio landed; donor = tun_harness)

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

Current state (measured at this 18f verify-mode docs pass): plan rows
1–18f DONE. **101 commits at HEAD 3ece5c6** (`git rev-list --count
HEAD` THIS pass — note: the 18f commit message's own "100 commits at
HEAD" line miscounts by one; the live count is 101, drift recorded
honestly, message NOT rewritten, no force-push rule — **this docs
commit lands as the 102nd**). **530 tests green / 0 FAILED** (full
`cargo test --all-targets` re-run AT THIS docs pass: summed
`test result` lines = 530 passed / 0 failed, `grep -c '^test result'`
= 63 lines (62 at 18e + 1 from `tests/tun_parity_test.rs`); 530 = 521
+ 9 tun (`grep -c '#\[test\]' tests/tun_parity_test.rs` = 9
re-measured THIS pass; the three new src/codecs TUs carry ZERO
in-crate `#[test]` — per-file grep 0/0/0 re-run THIS pass; 1399 Rust L
across the three, wc re-run THIS pass), `cargo clippy --all-targets`
**0 warnings** (forced relint THIS pass: touched every .rs, `Finished`
line present, `grep -c '^warning'` = 0), 45,233 lines Rust across 140
`src/*.rs` files (`find src -name '*.rs' -exec wc -l {} +` THIS pass),
37 `tests/*_parity_test.rs` whole-transcript replay tests among 62
tracked test files, 389 tracked files (`git ls-files | wc -l`), 44
`tools/*_harness` dirs. GitHub wiki
https://github.com/dhoelzer/RustyPig/wiki
is the public status doc (clone at `/tmp/RustyPig.wiki`, remote
`RustyPig.wiki.git`, HEAD `1cacca1` = **row 18e wiki trio LANDED**:
verified read-only at this docs pass — `git -C /tmp/RustyPig.wiki log
-1` prints `1cacca1 row 18e: status + deviations + stats (100 commits /
378 files / 43,831 src lines / 521 tests ...)` atop `63a6170 row 18d`,
and the 18e trio greps PRESENT (`Porting-status.md:95` status row +
`:101` chapter note + `Deviations-from-Snort-3.md:1420` deviations
header — the 18e trio is NO LONGER debt; the wiki is NEVER touched by
code or plan rows; this docs pass touched the wiki ZERO times). **The
18f wiki trio is OWED** and is owed at the NEXT WIKI phase, not by
this docs pass (`grep -rn 'row 18f' --include='*.md' /tmp/RustyPig.wiki` =
**0 hits** verified THIS pass — the wiki stops at 18e). The owed trio
= status row (misc/cd_teredo.cc + cd_gtp.cc + cd_geneve.cc, 734 L
ground -> 1399 L Rust across 3 flat src/codecs/*.rs, mod.rs wiring
only; probe-only tun harness w/ DUAL faces 40L DEC + 7L FACE-A, gate
untouched 14th straight census 9/24, suite ZERO upstream translated
Rust-side, 530 tests) + the row-18f deviations section (copy from
KNOWN DEVIATIONS.md :2732-:2899) + stats line ("102 commits / 390
tracked files / ~45,200 src lines / 530 tests" — LIVE values at the
docs commit, re-measure at the wiki pass before typing).

## 18f close-out — VERIFY MODE (plan row + deviations shipped WITH code commit 3ece5c6; this pass greps-verify + re-ground rather than append)
Like 18b/18c/18d/18e, 18f's plan row and deviations section shipped
inside the CODE commit, so this docs pass is a verification pass.
Everything below was re-measured/re-opened THIS pass:

- **Plan row**: `grep -c '^| 18f |' PORTING_PLAN.md` = **1** (at
  PORTING_PLAN.md:85) — insert guard satisfied, NO append needed; row
  text stands as committed and matches what 3ece5c6 shipped (`git show
  --stat 3ece5c6`: 15 files, +3,053 — harness 7 tracked files + docs
  row + deviations + 3 Rust TUs + mod.rs wiring +
  tests/tun_parity_test.rs 860 L in one commit).
- **Deviations section**: `grep -c '^## codecs misc tunnel trio
  (row 18f' KNOWN DEVIATIONS.md` = **1** at :2732, running to EOF at
  :2899 = 168 lines / **12** bullets (`grep '^- \*\*'` count THIS
  pass). **ONE honest drift recorded**: the 3ece5c6 commit-message
  copy says "11 bullets" — the live section measures **12** (a bullet
  count drift only, same face as 18e's "81 files" vs 101; row/section
  NOT rewritten, no force-push). **Verdict: adequate-READ — leave, no
  follow-up edits.** Anchor re-grounding (files opened THIS pass in
  ground snort3-src @ fe29cbe7403a): the three row files `wc -l`
  161/291/282 = 734 EXACT re-run; the three suites `wc -l` 121/140/163
  EXACT re-run; combined gate grep `TEST_CASE\|TEST_GROUP\|^TEST(\|\
  UNIT_TEST` = **0 on all three row TUs** re-run THIS pass; per-TU
  ground gate material for contrast = ONLY cd_gre in ip/ (3 hits =
  :34/:351 block + :352 case) — see 18g scoping below.
- **Suite-side census re-grounded THIS pass** (misc/test, the
  CppUTest trio): wall includes `CppUTest/CommandLineTestRunner.h` +
  `TestHarness.h` at teredo :31/:32, gtp :31/:32, geneve :25/:26
  (sed THIS pass — geneve additionally `CppUTestExt/MockSupport.h`
  :27, the lone mock rider); self-includes `../cd_<tunnel>.cc` at
  teredo :29 / gtp :29 / geneve :20 (sed THIS pass — the suite TU IS
  the codec TU); `TEST_GROUP` exactly one per suite (teredo :86, gtp
  :87, geneve :103); `^TEST(` counts 2/2/3 grep THIS pass; raw
  CHECK-line counts 3/8/19 grep THIS pass (matches the shipped plan
  row's 3/8/19; the older 18e-pass 1/8/18 was a CHECK_TRUE-only
  dialect count — both recorded, per-construct face stands).
- **Vectors stability — BOTH tun faces re-md5'd THIS pass**:
  `tools/tun_harness/vectors.txt` 40 L md5 re-summed EXACT against
  the pinned `2a7924796f8f0cfdca5e665dee28f519`; `vectors_faceA.txt`
  7 L md5 `81602890210d8d83068397c2cece1241` — both stable across the
  FRESH tun rebuild THIS pass (`TUN_HARNESS_OK vectors=40 faceA=7`,
  `O0==O2: FACE-A BYTE-IDENT, DEC BYTE-IDENT`). tun probe.cc 21 L md5
  `5b8355189caa2d8b1a12913f94c3838d` + probe_dec.cc 105 L md5
  `99a8257cd470c33be8a4135eb45e547a` + witness_18f.cc 21 L md5
  `ea1f79f3f05f8a91dc9524a963692b39` re-summed THIS pass, zero drift.
  Frozen upstream-face re-md5 at this pass (all byte-exact, zero
  drift): ext `vectors.txt` `da218429...` + `vectors_faceA.txt`
  `0fa79b53...` + probe.cc `af4c83fc...` + probe_dec.cc `35d7f771...`;
  donor fingerprints vocab witness_stubs.cc `9fad7e9d...` (the 4
  cd_*[] stub tables :11-:14 still intact — cd_gre/cd_udp/cd_icmp4/
  cd_icmp6 counts **0/0** in vocab witness_stubs.cc + codec_harness
  stubs.cc re-grepped THIS pass: NO landmine for the 18g queue) /
  codec stubs.cc `be9bdd0b...` / eth stubs_18d.cc `f4afd35f...`
  (tun build.sh :223 pins `f4afd35f06bc45ce5aa0ec12110ed8ae`) / tun
  witness_conf.cc `4dd91018...` (heredoc-regenerated, byte-ident at
  the rebuild). Receipts `/opt/data/cache/scratch/row18f/
  {tun,fmod,vocab,eth,ext}_rebuild_18fdocs.log`.
- **Copy-tree face — one honest count note**: build.sh asserts the
  SOURCES face 84 pre-fresh-cp / 86 post (81 ext donor + 3 row cps +
  2 fresh hdr cps, pinned md5s `b7adb3d8...` teredo.h 44 L +
  `ce608579...` active.h 240 L; geneve.h RESIDENT byte-ident
  `10cfe860...`); live `find tools/tun_harness/copy -type f` THIS
  pass = **96** (= 86 sources + 10 `copy/*.o` build artifacts the
  in-tree objs loop produces — artifact-count face, NOT a source-face
  drift; sources face verified 86 via `! -name '*.o'` count THIS
  pass). Row NOT rewritten. E4 flipped-asserts re-ran live (pre-cp
  cd_teredo MUST fail protocols/teredo.h + cd_geneve MUST fail
  packet_io/active.h + cd_gtp MUST pass empty + post-cp rc 0 x3 +
  CppUTest suites MUST die at CommandLineTestRunner.h x3).
- **Gate chain LIVE — FOURTEENTH STRAIGHT, MEASURED not asserted**:
  fmod rebuilt FRESH THIS pass (rc 0, `FMOD_HARNESS_OK vectors=61`):
  vectors `f0fdbab06fe1681af1c654531b917c55` + gate
  `4826fc2233044a2d5429413faf0ae1af`, gate.txt last non-empty line
  VERBATIM `All tests passed (114 assertions in 22 test cases)`
  (receipt above). tun harness ships ZERO gate artifacts (build.sh
  gate-census echo `holders: 9/24 (tun harness gate.txt count 0)`).
  vocab donor rebuilt FRESH (rc 0, `VOCAB_HARNESS_OK vectors=29`,
  vectors `5da70e82...` stable); eth donor rebuilt FRESH (rc 0,
  `ETH_HARNESS_OK vectors=15`, residue 14/11/10/4/8, E6-YES echo,
  vectors `1bd98dbb...` stable); ext donor rebuilt FRESH (rc 0,
  `EXT_HARNESS_OK vectors=27 faceA=9`, 3-face stub census
  frozen=4/retired=3/real=5 + FACE-II flip FORK-MEASURED, cd_gre
  anchors re-measured at :50-:53 NOT touched). md5 census over all 24
  `tools/*/gate.txt` THIS pass: exactly **9 files** carry
  `4826fc22...` (fcap, fcapi, fconf, fcshare, finspect, flog, fmod,
  fpolicy, fsvc) — 18f shipped NO gate (probe-only row, fifth time),
  so 14 straight holds MEASURED.
- **nm row census re-echoed live at the rebuild**: per-TU U-counts
  teredo=10 gtp=24 geneve=42, each EXACTLY 1 `tunnel_bypass` U-line;
  codec_event 0/1/1 + Module::Module 0/1/1 (teredo's honest null face,
  pinned by FACE-A:7 + DEC:40) — matches the shipped plan row EXACTLY,
  zero drift.
- **Test math**: 530 = 521 + 9 — `tests/tun_parity_test.rs` 860 L,
  9 `#[test]` (40/40 ORDERED DEC replay + 7/7 ORDERED FACE-A replay +
  the 8 `up_tun_*` CppUTest translations incl the 8th
  get_geneve_opt_data suite-helper arm — all cited in the deviations
  section); the 3 landed src TUs (`cd_teredo.rs` 277 L, `cd_gtp.rs`
  496 L, `cd_geneve.rs` 626 L — wc re-run THIS pass) carry ZERO
  in-crate tests (grep 0/0/0 THIS pass). Suite result at THIS pass:
  all green, 0 FAILED, 0 panicked (63 result lines, FAILED/panicked
  grep = 0).
- **commit census + gitignore**: 101 at HEAD 3ece5c6 (`git rev-list
  --count HEAD`; see the commit-message mis-count drift above);
  .gitignore tun block at :372-:391 re-verified by `git check-ignore`
  THIS pass (copy/ :373, o2/ :374, probe binaries :375-:380, *.o,
  witness_conf.cc :380, vectors_O0/O2 faces :381-:384, nm_U_*/E4*/
  E4b* receipts, gate artifacts :389-:390, *.log :391 all ignored
  rc 0; `vectors.txt` + `vectors_faceA.txt` + `build.sh` + `PLAN.md`
  + `probe.cc` + `probe_dec.cc` + `witness_18f.cc` NOT ignored, rc 1
  — stageables exactly 7, `git ls-files tools/tun_harness` = PLAN.md
  build.sh probe.cc probe_dec.cc vectors.txt vectors_faceA.txt
  witness_18f.cc) — do NOT re-add. (ext block stays :343-:370.)

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
   catch.hpp pull + shim heredoc; the FRESH full shape of that recipe
   stands re-citable at `tools/fctx_harness/build.sh` :60-:63 —
   `cp .../rules_harness/copy/catch/catch.hpp` + `cat > snort_catch.h`
   heredoc + `catch_main.cc` TU at :403-:407 — which is what the 18g
   cd_gre gate will clone). Run it; record cases/assertions in
   `gate.txt`. NEVER gate on grep-estimated assertion counts — pin
   case names/counts from grep, measure assertions from the runner
   (17p: grep said 36, the runner said 42). When gate and probe link
   the same TU, use the **duplicate-symbol rule**: every UT-compiled
   TU's plain `.o` is EXCLUDED from the gate link (17r: 3 UT TUs in
   one binary). When a TU has BOTH early `#ifdef UNIT_TEST` fragments
   AND a trailing suite block, excise the LAST block only, via
   `rfind` + brace-balance guard, on BOTH builds (17r file_lib
   recipe) — cd_gre.cc (366 L) is EXACTLY that shape early (:34-:35,
   the include-only fragment) + trailing (:351-:366, the suite block),
   the cd_gre row will run this recipe. The 17y row added the
   INVERSION lesson: when a donor carries a WITNESS BLOCK for the row
   TU, landing the real TU retires the block (23 hard collisions,
   fsvc build.sh :706-:707/:778/:827 nm pins) — the retire-evidence
   echo is the guard, not a silent link failure. The 18a row added the
   PER-LINK corollary: retirement applies to the CURRENT donor's
   stubs ONLY — the frozen donors keep their blocks + their
   vectors/gate/tests byte-frozen, and a census test pins both faces
   (fmod `trio_retirement_census`). The 18b row added the
   PROBE-ONLY corollary: when the row contributes ZERO .o to every
   donor link and its suite dialect cannot build on host, the honest
   artifact is a probe-only harness — NO gate at all, with the zero-
   contribution claim nm-proved in build.sh and the 9-holder chain
   re-censused EVERY build. 18c/18d/18e/18f exercised it four more
   times (18f: per-file grep 0 x3 + E4 flipped-asserts + zero-gate
   asserts, `TUN_HARNESS_OK vectors=40 faceA=7`). The 18d row added
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
   retirement census), freshest-smallest `tests/tun_parity_test.rs`
   (860 L, DUAL-face ordered replay 40L DEC + 7L FACE-A PLUS the 8
   `up_tun_*` CppUTest-suite translations with byte-for-byte fixture
   literals — the pattern for multi-face zero-suite rows whose C
   suites are wall-dead), then `tests/eth_parity_test.rs` (608 L),
   `tests/vocab_parity_test.rs` (442 L),
   `tests/csum_parity_test.rs` (414 L, probe-only rows WITH a suite),
   `tests/flog_parity_test.rs`, `tests/fsvc_parity_test.rs`.
5. **Gates at EVERY commit**: `cargo test` all green (>= 530; never
   trust a summed total from a run containing FAILED), clippy
   --all-targets ZERO warnings (force relint by touching all .rs),
   `vectors.txt` md5 stable across >= 2 clean rebuilds (gate.txt md5
   likewise — regenerable, hence .gitignore'd: md5-pinned in docs per
   row, NOT tracked), harness `.gitignore` block added (mirror
   siblings) and verified with `git check-ignore` BEFORE staging (the
   tun block is .gitignore:372-:391, landed inside code commit
   3ece5c6). Then commit + push, insert the plan row (grep-guard:
   count must be 0 before insert — the numa double-append incident
   cost a force-push), append deviations (one grep-guarded append) —
   the 18b-18f variant: BOTH ship inside the code commit, then the
   docs pass VERIFY-greps them (count == 1 each) instead of
   inserting, and still re-measures every load-bearing claim. Refresh
   NEXT.md (FRESH rewrite), commit+push docs, update the wiki (status
   row + deviations section + stats line), push wiki.

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The 17r probe/gate links ran REAL EVP (the M-block hashes are libcrypto ground truth); the Rust side stands on the dependency-free `src/helpers/sha256.rs` whose known answers were cross-checked against it. 17s/18b-18f do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k). fmod 18a proves the LINK recipe (static BY PATH — `-lluajit` hits the .so and the gate probe dies at load, no rpath; `-lm -ldl` tail; nm pin fmod build.sh:961). 18d-18g-queue row TUs carry ZERO lua refs (grep -ci lua asserted every build).
- **CppUTest is NOT installed on this host** (RE-PROVEN every csum + vocab + eth + ext + tun build: the tun build.sh E4_cpputest_fatal.txt receipt face `CppUTest/CommandLineTestRunner.h: No such file` x3 flipped-assert EVERY build, plus the checksum_test.cc:36 precedent). Upstream **CppUTest** suites (misc/test/{teredo,gtp,geneve}_codec_test.cc — landed-and-translated at 18f as `up_tun_*` — plus the STILL-LIVE 16g/16h lru ones — translated Rust-side) can ONLY be translated Rust-side, NEVER run natively. Only the vendored Catch (rules_harness copy/catch/catch.hpp + the snort_catch.h shim) runs natively — which is exactly why cd_gre (18g) gets a REAL native Catch gate.
- **daq_dlt.h graft IS now a committed fact** (existed nowhere in ground — 18c find): `tools/vocab_harness/copy/daq_dlt.h` + the eth copy carry `DLT_RAW 12` (libpcap master pcap/dlt.h:112-:114) extended at 18d with `DLT_EN10MB 1` (master :68) + `DLT_PPP_ETHER 51` (master :243) — the 18c android-mirror URL 404s as of this pass, cite CORRECTED in the graft header. Later rows cp/extend THAT graft; row 20 cites the real DAQ include chain.
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds/serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` tools are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) must be edited via python scripts kept in `/opt/data/cache/scratch/` and run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there); put probe/debug programs there, never the system temp dir.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; 18c R6 var-first arms + 18d/18e/18f replay mirrored Rust-side — tun build.sh greps-pin `bool [a-z]…=.*->decode` >= 10 + `printf.*->decode` == 0 on probe_dec.cc, Rust side stores every bool before field reads).
- No gdb. Diagnose segfaults via stdout tail + source inspection; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY (it clamps backwards calls — never backstep by construction). Since 18a `file_trace` has its REAL def on BOTH sides (Rust token Cell armed via the transcribed cc:154 set_trace; harness side the row .o defines it, fcache_set_file_trace rides it, fmod stubs.cc:205).

## Donor harnesses (copy their build.sh recipes wholesale)
- `tools/tun_harness/` — **THE donor for row 18g+ (lineage head)**: the 18f probe-only DUAL-face pattern — exactly 7 tracked files (build.sh 343L, probe.cc 21L md5 `5b835518…`, probe_dec.cc 105L md5 `99a8257c…`, PLAN.md 63L, witness_18f.cc 21L md5 `ea1f79f3…` — the EXACTLY-ONE new SnortConfig::tunnel_bypass_enabled witness, ground-shaped body over the observable tun_mask, SFDAQ arm pinned false, vectors.txt 40L md5 `2a792479…` tracked, vectors_faceA.txt 7L md5 `81602890…` tracked), `copy/` tree = the ext donor VERBATIM + 3 row cps + 2 FRESH header cps (teredo.h 44L `b7adb3d8…` + active.h 240L `ce608579…`; geneve.h RESIDENT `10cfe860…`) = 86 sources (96 files incl 10 .o artifacts — artifact face, see close-out note), witness_conf.cc heredoc-regenerated byte-ident `4dd91018…`: ZERO new witness beyond witness_18f. Self-checks re-run THIS pass at the docs rebuild (rc 0, `TUN_HARNESS_OK vectors=40 faceA=7`): both-face md5 pins, O0==O2 per face, E4 walls flipped-assert x2 faces + CppUTest-dead x3, per-TU nm U-census 10/24/42 + tunnel_bypass U-line == 1 per TU + codec_event 0/1/1 + Module::Module 0/1/1 arms, landmine-zero asserts (three names UNstubbed in vocab + codec donors; NO codec_api object in probe links), 5-fingerprint frozen census (9fad7e9d/5da70e82/be9bdd0b/f4afd35f/4dd91018), cd_gre anchors re-MEASURED not pre-dug (:72-:75 — sed :34/:35/:352 + wc 366; NOTE for 18g: the tun anchors already pin :352 `TEST_CASE (` == 1, the :364 CHECK line + :351/:366 block shape re-measured at THIS docs pass, see scoping), gate census 9/24 + tun gate* count 0. NO gate.txt (probe-only).
- `tools/ext_harness/` — the 18e donor (superseded at 18f as lineage head; kept, rebuilt fresh every docs pass for the frozen-face echo — done THIS pass): exactly 7 tracked files, DUAL faces 27L `da218429…` + 9L `0fa79b53…`, cd_gre anchor asserts :50-:53 live, FACE-II flip receipts NEVER pins. NO gate.txt.
- `tools/eth_harness/` — the 18d donor (superseded; kept for lineage): exactly 5 tracked files (build.sh 608L, probe.cc 41L, PLAN.md 83L, stubs_18d.cc 35L with the :30 `RETIRED at 18d` marker md5 `f4afd35f…` — carried by every later row, vectors.txt 15L tracked), the EXTENDED `daq_dlt.h` graft, EOFLOW/EOFTRH/EOFDAQ heredoc carries, thread_config.h hwloc excision carry, 9/24 census echo (:597-:606), lua-seam assert (:60-:62). vectors md5 `1bd98dbb…` (committed, NEVER edit); NO gate.txt.
- `tools/vocab_harness/` — the 18c donor (superseded; kept for lineage): 9 committed files (build.sh 325L, probe.cc 90L, witness_stubs.cc 14L md5 `9fad7e9d…` — **the 4 cd_*[] stub tables (cd_ipv4/cd_ipv6/cd_tcp/cd_hopopts) at :11-:14, frozen by vectors:25-:28; cd_gre/cd_udp/cd_icmp4/cd_icmp6 stub counts 0 — re-grepped THIS pass**, witness_conf.cc, PLAN.md 69L, vectors.txt 29L tracked md5 `5da70e82…`, cp_audit_ok.txt); the `daq_dlt.h` GRAFT originated here.
- `tools/fmod_harness/` — the 18a donor & **gate-lineage source** (rebuilt fresh at every docs pass for the byte-ident echo — done THIS pass, 14th straight holder-intact): cp braces + objs loop carry the FULL file_api closure; first third-party link (`libluajit.a` BY PATH + `-lm -ldl`, nm pin :961); §0.1 header-cp chain + 2 witness grafts; stubs.cc 984L; build.sh 1164L; vectors.txt 61L md5 `f0fdbab06fe1681af1c654531b917c55`; gate md5 `4826fc2233044a2d5429413faf0ae1af`; **the catch-recipe clone target for 18g: build.sh :249 (catch.hpp pull from rules_harness) + :270 (snort_catch.h heredoc)** — full working shape also at fctx build.sh :60-:63 + :403-:407 (catch_main.cc TU + gate link line).
- `tools/csum_harness/` — row 18b, **the probe-only pattern for ZERO-.o rows**: no gate shipped; build.sh self-checks = ground-header md5 pin (:37), E4 CppUTest wall receipt (:67-:70), dialect proof (:72-:73), nm ZERO-text-symbols proof (:79-:80), O0==O2 (:116), 9-holder census (:154). vectors 16L md5 `e4baf7816440e18917d3249597f60b88`. NOTE for 18g: `ip/checksum.h` 284 L is an INLINE lib — its host tree has NO compiled checksum.o consumer; cd_gre's `#include "checksum.h"` (cc:32, same-dir) needs a fresh cp of that header, the 18b face is Rust-side only.
- `tools/flog_harness/` — the 17z donor: vectors 50L md5 `b260ec6a…`.
- `tools/fsvc_harness/` — the 17y donor: the landmine inversion (23 collisions); vectors 64L md5 `54864705…`.
- `tools/fpolicy_harness/` — the 17x donor: vectors 27L md5 `b989a8d5…`.
- `tools/finspect_harness/` — the 17w donor: vectors 103L md5 `3cbd009e…`.
- `tools/fcapi_harness/` — the 17v donor: vectors 21L md5 `a953a501…`. NB dir name `fcapi_harness` (pinned, do not "fix").
- `tools/fconf_harness/` — the 17u donor: vectors 20L md5 `65968e1c…`.
- `tools/fcshare_harness/` — the 17t donor: vectors 25L md5 `03d43c14…`.
- `tools/fcap_harness/` — the 17s donor: vectors 27L md5 `0208a691…`; gate md5 `4826fc22...` — the 114/22 chain STARTS here.
- `tools/fctx_harness/` — FileContext + capture/mempool/segment closure donor: vectors 610L md5 `839b5566…`; gate md5 `42349372…` (its OWN 18/91 link, never joined the 4826fc22 chain). `PLAN.md` = the RECON→HARNESS→PORT contract example; **:60-:63/:403-:407 = the CATCH SHIM + catch_main RECIPE the 18g gate clones** (and :413 shows the gate link line shape with the UT-compiled file_lib .o face — the 17r dup-symbol precedent lives in this tree).
- `tools/fflows_harness/` — flowz graft donor: vectors 146L md5 `bd8c00af…` (DO NOT touch); gate md5 `e14626fc…`.
- `tools/fcache_harness/` — file_api hash/clock closure donor: vectors 278L md5 `b69db310…` (DO NOT touch); gate md5 `6b3c041e…`.
- `tools/filib_harness/` — file_api header closure + interposed SnortClock fake clock. vectors 273L md5 `77ffd8e4…` (DO NOT touch); gate 19/334 — 17o's [file_info] suite stays HERE.
- `tools/fstats_harness/` — carries the ONLY file_api test/ suite (upstream `file_api/test/file_stats_test.cc` via the catch shim).
- `tools/textlog_harness/` — row 16r: time() interposition precedent.
- `tools/rules_harness/` — SnortConfig EOFCFG shim; hosts `copy/catch/catch.hpp` — the vendored Catch every shimmed gate pulls (18g source of the pull).
- `tools/fid_harness/` — ghash closure, private->public header graft, dead-branch witness pattern.
- `tools/codec_harness/`, `tools/jsnorm_harness` — plain-catch shim recipe. **`tools/codec_harness` is row 17d's harness (framework/codec base; its stubs.cc md5 `be9bdd0b437d1f6c56c841e8155d9e70` is the FROZEN donor the E6-YES arms re-collide against every build; grep cd_gre/udp/icmp counts 0 — no landmine) — the RawData/daq_msg deferral closed partially at 18c (codec.rs:9/:171 + deviations :2341-:2344); the FULL plugin-loading deferral (PluginManager::load_plugins REAL body, plugin_manager.cc 1015 L) still defers to row 20.**

## Next milestone — row 18g: cd_gre, THE gate-change row (18f closed the tunnel trio; this scoping FRESH-measured at the 18f docs pass)

### cd_gre measured face (all anchors re-run THIS pass, ground `/opt/data/snort3-src/src/codecs` @ fe29cbe7403a READ-ONLY)
- `ip/cd_gre.cc` `wc -l` = **366** ✓ (also live-asserted by ext build.sh
  :50-:53 and tun build.sh :72-:75 at this pass's rebuilds).
- DUAL `#ifdef UNIT_TEST` face (grep THIS pass): **:34 = `#ifdef
  UNIT_TEST`** + **:35 = `#include "catch/snort_catch.h"`** + `#endif`
  :36 (the EARLY include-only fragment — leave it armed on the gate
  build); **:351 = second `#ifdef UNIT_TEST`** opening the TRAILING
  suite block; **:352 = the ONE `TEST_CASE ("Validate error check for
  raw_len greater than GRE_HEADER_LEN", "[cd_gre]")`**; **:364 = the
  block's single `CHECK (false == grecodec.encode(...))`** (CHECK-line
  grep count over the whole file = 1, ALL of it inside the block);
  **:366 = `#endif`** closing at EOF. 1 TEST_CASE / 1
  TEST_CASE-tag / 1 CHECK — that grep face is NAME/shape pinning
  ONLY: **the assertion count that enters docs/gate history is the
  RUNNER's line, NEVER this grep arithmetic (17p lesson)**; this
  docs pass deliberately types NO predicted "N assertions in M cases"
  tail for 18g (the old 115/23-style forecast face died here again —
  queue udp/icmp/auth rows below likewise carry NO arithmetic
  forecasts).
- Table face: :337-:341 real `#ifdef BUILDING_SO` / `SO_PUBLIC const
  BaseApi* snort_plugins[]` / `#else const BaseApi* cd_gre[] =` —
  the REAL cd_gre[] table at **:340** (unlike cd_hopopts at 18e whose
  face was commented-out; gre's ifdef-live arms mean a probe link at
  default build picks the `cd_gre[]` branch, never `snort_plugins[]`
  by name — nm face to be pinned at the row).
- Landmine: **ZERO** — cd_gre stub count **0** in vocab
  witness_stubs.cc AND codec_harness stubs.cc (grep re-run THIS
  pass, gre/udp/icmp4/icmp6 all 0/0); no witness block anywhere
  freezes the name; no FACE-II rehearsal needed (18e codified rule).
- STATIC_CODECS externs (codec_api.cc, census 39 re-confirmed THIS
  pass): **cd_gre :52** (the extern census hit list for the 18g
  region: cd_esp :47, cd_frag :50, cd_gre :52, cd_icmp4 :54,
  cd_icmp4_ip :55, cd_icmp6 :56, cd_icmp6_ip :57, cd_pgm :63,
  cd_udp :70); the Rust ladder name "cd_gre" is ALREADY resident in
  STATIC_CODEC_EXTERN_NAMES (codec_api.rs:110 — grep THIS pass, keep
  untouched, same face as the tunnel three at :109/:111/:126).
- Include closure per-TU (grep THIS pass, cc:22-:35): config.h +
  codecs/codec_module.h + framework/codec.h + log/messages.h +
  log/text_log.h + main/snort_config.h + **protocols/gre.h (50 L
  ground)** + **checksum.h (same-dir = ip/checksum.h, 284 L)** —
  residency vs `tools/tun_harness/copy/`: codec_module.h /
  messages.h / text_log.h / snort_config.h / framework/codec.h =
  RESIDENT (find THIS pass); **MISS = `protocols/gre.h` (0 hits),
  `ip/checksum.h` (0 hits anywhere in copy — the csum row was Rust-
  inline only, header NEVER cp'd into any donor tree) and its rider
  `utils/endian.h` (76 L ground; copy/utils carries bits.h/
  cpp_macros.h/stats.h/util.*/util_net.h — NO endian.h — find THIS
  pass)**. So 18g = tun donor + 1 row cp + ~3 fresh header cps
  (gre.h + checksum.h + endian.h; re-census the full transitive face
  at the row's PLAN §0, NEVER pre-type).
- Bypass provider: gre decodes THROUGH the same left-open seam 18f
  codified (TUNNEL_GRE = 0x40 at snort_config.h:125 — the TunnelFlags
  block :119-:128 re-sed THIS pass: GTP :119 0x01, TEREDO :120 0x02,
  GRE :125 0x40, VXLAN :127 0x100, GENEVE :128 0x200); the 18f
  hook-param + witness replay face carries over unchanged.

### THE GATE CHANGE — what happens exactly once at 18g (rules pinned, measured not typed)
- cd_gre is THE sanctioned row where the 4826fc22 chain **changes
  exactly once** — 18a-18f never touched it; 18f was the 14th straight
  MEASURED (see close-out). At 18g: (1) build the REAL Catch gate for
  cd_gre.cc — clone the fmod :249/:270 + fctx :60-:63/:403-:407
  recipe (catch.hpp from rules_harness + snort_catch.h shim +
  catch_main TU); (2) **rfind + brace-balance excision ONLY of the
  LAST block (:351-:366) on the probe build**; the EARLY fragment
  (:34-:36) is include-only and MUST stay armed for the gate build's
  verbatim compile (17r file_lib recipe — the "excise the last block
  only" rule exists precisely for this shape); (3) **duplicate-symbol
  rule**: the UT-compiled cd_gre .o goes in the GATE link; the plain
  probe-side cd_gre .o is EXCLUDED (nm face: gate binary carries the
  UNIT_TEST macro-expanded case body, probe binary carries the plain
  TU; each link's cd_gre symbol census pinned in build.sh,
  runner-measured); (4) the runner's tail line becomes the NEW chain
  anchor — the post-change holder census is RUNNER-MEASURED at that
  row (does the gre gate carry the new md5 at 10 holders? the answer
  comes from the md5 census loop AT the row; typed numbers here are
  BANNED); (5) the 9 legacy holders (fcap/fcapi/fconf/fcshare/
  finspect/flog/fmod/fpolicy/fsvc) stay **byte-frozen at 4826fc22** —
  NEVER edit any frozen donor's gate/vectors to "rejoin" a new chain;
  the census just starts counting two md5 lineages honestly from that
  row on. NEVER pre-verify any new count in docs — measure at the row.

### 18g alternatives — honest comparison (measured THIS pass)
| option | size | gate material | verdict |
|---|---|---|---|
| **(a) NEXT order as scheduled: 18g = ip/cd_gre.cc** | 366 L | **1 Catch TEST_CASE (:352, tag [cd_gre], CHECKs inside :353-:365 all live-measured at the row)** — the FIRST real codec-row Catch gate | **CHOSEN**: it was always the sanctioned break point (pinned at 18c, re-pinned 18d/18e/18f); tunnels feed GRE's decoded under-chain, recipe risk banked behind 5 zero-gate rows now; fresh-cp delta small (gre.h + checksum.h + endian.h, measured MISS face above); tunnel_bypass seam already homed by witness_18f. |
| (b) swap queue: udp 660 / icmp4 645 / icmp6 518 first | 660/645/518 wc THIS pass | 0/0/0 (combined grep THIS pass; all three ZERO-suite honest rows) | REJECT: postpones the riskiest C move past EIGHT more rows and drags daq.h + protocol headers (udp.h/icmp4.h/icmp6.h + `#include <daq.h>` in all three, grep THIS pass) while the gate-change rule stays unbanked; gre is 366 L and READY. |
| (c) detour to `src/main/thread_config.cc` quick-win | 920 L wc re-verified THIS pass (unchanged) | 14 `[ThreadConfig]` Catch TEST_CASEs (grep re-count THIS pass) | Still the ONLY nearby fresh-Catch-gate option OUTSIDE codecs; needs the hwloc witness ladder (17l precedent; eth tree's thread_config.h hwloc EXCISION carry) + breaks codec-row continuity and the donor chain. Keep strictly as the fallback if row 18 stalls (18a/18c/18d/18f ruling re-affirmed THIS pass). |

## Thereafter — remaining row-18 order (totals RE-VERIFIED THIS pass: codecs/ tree = **11,914 L / 48 files**, non-test **11,289 L / 44 files** — both find+wc sweeps re-run THIS docs pass, zero drift)
- Then the ICMP pair (`ip/cd_icmp4.cc` **645** + `ip/cd_icmp6.cc`
  **518** wc THIS pass; combined gate grep THIS pass 0/0 — honest
  zero-suite rows) with the udp heavyweight (`ip/cd_udp.cc` **660** —
  path pin re-verified, ip/ NOT misc/: `protocols/udp.h` +
  `protocols/teredo.h` RESIDENT at the tun tree, `#include <daq.h>`
  = row-20 pressure, grep THIS pass), then ipv4 **790** / ipv6
  **733** / tcp **839**; the 3 surviving stub tables cd_ipv4/cd_ipv6/
  cd_tcp (witness_stubs.cc :11-:13, re-read THIS pass) get REAL
  retirement treatment at those three rows, per-link, via the E6
  inverted mechanics + tun 3-face census discipline. Also ip/ still
  ships the small four `cd_esp.cc 227 / cd_pgm.cc 211 / cd_frag.cc
  190 / cd_auth.cc 172` (wc THIS pass, combined gate grep
  0/0/0/0): extern cites cd_esp :47 / cd_frag :50 / cd_pgm :63
  (grep THIS pass) but **cd_auth has NO codec_api extern at all** —
  where they sit in the tail order is each row's PLAN-0 call, no
  pre-ordering or arithmetic forecasts typed here.
- Then the link tail (wc THIS pass: mpls 390 / vlan 236 / pppoe 243 /
  erspan2 145 / erspan3 147 / ciscometadata 235 / fabricpath 187 /
  trans_bridge 158 / ppp_encap 174), then the misc tail (wc THIS
  pass: llc 198 / vxlan 133 / user 167 / icmp4_ip 345 / icmp6_ip
  162).
- The 18c STATIC_CODECS extern census (**39** tables re-counted THIS
  pass, cc-order) + the dormant STATIC_CODEC_EXTERN_NAMES tripwire
  give the later rows their completeness checklist: by the end of row
  18 every extern must either link real or stay pinned dormant.
  (ip-region extern hit-list w/ cites re-echoed in the 18g scoping
  above.)

## Backlog (plan rows)
- 17z: DONE (ef9bf83) — wiki trio LANDED (f91be60).
- 18a: DONE (74bcc23) — wiki trio LANDED (9792858).
- 18b: DONE (7e1744c) — wiki trio LANDED (aa22a11).
- 18c: DONE (9ed8a8f) — wiki trio LANDED (72d39cd).
- 18d: DONE (5c8e31e) — wiki trio LANDED (63a6170).
- 18e: DONE (c30a30e) — wiki trio LANDED (**1cacca1**, wiki HEAD
  verified THIS docs pass: `row 18e` greps PRESENT at
  Porting-status.md:95/:101 + Deviations-from-Snort-3.md:1420; wiki
  stats 100 commits / 378 files / 43,831 src lines / 521 tests — the
  EARLIER NEXT editions' "18e trio OWED, wiki stops at 18d/63a6170"
  line is SUPERSEDED by this measurement: the trio LANDED as
  measured, wiki-debt corrected to **18f only**).
- 18f: **DONE (3ece5c6)** — codecs misc tunnel trio landed:
  `misc/cd_teredo.cc` + `cd_gtp.cc` + `cd_geneve.cc` (734 L ground ->
  1399 L Rust across src/codecs/{cd_teredo 277L, cd_gtp 496L,
  cd_geneve 626L}.rs FLAT, mod.rs wiring ONLY outside; framework/
  codec.rs + parse_conf.rs + codec_api.rs BYTE-UNTOUCHED — ladder
  names already resident codec_api.rs:109/:111/:126); `tools/
  tun_harness` NOW LINEAGE HEAD (exactly 7 tracked files, DUAL-face
  vectors 40L `2a792479...` + 7L FACE-A `81602890...` both stable at
  the docs-pass rebuild rc 0, O0==O2 both faces; EXACTLY-ONE new
  witness tunnel_bypass_enabled, landmine ZERO re-grepped; E4 walls
  flipped-assert + CppUTest dead x3; nm U-census 10/24/42 +
  codec_event 0/1/1 vs Module::Module 0/1/1 asymmetry; 2 fresh hdr
  cps teredo.h/active.h, geneve.h resident); gate chain **14th
  straight CONFIRMED live THIS pass** (fmod + vocab + eth + ext + tun
  rebuilt fresh THIS pass + 9/24 md5 census re-run); `tests/
  tun_parity_test.rs` 860L 9 tests (40/40 + 7/7 ordered replays + 8
  up_tun_* CppUTest translations, fixture literals byte-for-byte);
  suite re-run **530/0** THIS pass (63 result lines, 0 FAILED/panicked);
  clippy forced relint 0 THIS pass; .gitignore tun block :372-:391
  check-ignore re-verified THIS pass (stageables exactly 7); plan row
  + deviations VERIFY-GREPED this pass (count 1 each:
  PORTING_PLAN.md:85 / KNOWN DEVIATIONS.md:2732-:2899, 168L/**12**
  bullets, verdict ADEQUATE-READ-LEAVE with every anchor re-grounded
  — see 18f close-out; TWO honest drifts recorded, rows NOT
  rewritten: the 3ece5c6 message's "11 bullets" vs live 12, and its
  "100 commits" vs live 101 — count drifts only, no behavioral claim
  moved). **Wiki trio for 18f OWED** (next WIKI phase; wiki HEAD
  1cacca1 stops at 18e; `grep -rn 'row 18f' /tmp/RustyPig.wiki` = 0
  hits verified THIS pass).
- 18: codecs — 18b/18c/18d/18e/18f DONE; 18g = cd_gre gate-change
  scoping ABOVE (366 L + :34/:35/:351/:352/:364/:366 anchors w/ live
  build.sh asserts, table :340, landmine 0/0, fresh-cp MISS face
  gre.h/checksum.h/endian.h measured); row continues per order above.
- 19: detection option engines (~30k+ subset claim stands but the tree measures **14,533** .h+.cc with **~47** embedded Catch TEST_CASEs — fp_utils.cc 21, detection_options.cc 6, ips_context.cc 5, extract.cc 5, ips_context_chain.cc 3, context_switcher.cc 3, rules.cc 2, sfrim.cc 1, ips_context_data.cc 1 — real Catch material to carry like 17f/17r; re-grep at that row's scoping pass); 20: packet_io / DAQ (AF_PACKET via libc; the 17d RawData/daq_msg deferral + the daq_dlt.h graft (now TWO consumers: vocab 18c + cd_eth 18d) both close HERE — the 18f geneve `packet_io/active.h` fresh-cp was the FIRST live rent paid, the udp/icmp `#include <daq.h>` trio is the next; keep the posture documented above); 21: main CLI + `snort -q -c` end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
2. `cd tools/tun_harness && bash build.sh` -> BOTH vectors md5s stable x2 clean rebuilds (NO gate — probe-only; E4 flipped-asserts + nm U-census arms); rebuild `tools/fmod_harness` for the gate-chain byte-ident echo AND the 18g catch-recipe cite check (:249/:270), plus `tools/vocab_harness` + `tools/eth_harness` + `tools/ext_harness` for the 5-fingerprint + frozen-face echoes (all rc 0 with the *_HARNESS_OK tails).
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test` (zero FAILED) + clippy 0 -> `.gitignore` block + `git check-ignore` -> commit+push -> plan row (grep-guard) -> deviations append (grep-guard; 18b-18f variant: verify-grep if shipped with the code commit) -> refresh THIS file -> commit+push docs -> wiki (status row + deviations + stats line) -> push wiki.
