# NEXT.md — takeover context & plan (2026-11-23, post-21b: The chapter-19 P3 SURVIVOR-FLOW-DATA PIN PROVIDER LANDED AT 3e9f2d7 — framework/survivor_flow_data.cc 88 L SOLO 4b1eedaf + THE 21a DECL-ONLY CITE COMPLETION row + witness own-9 face (tterm PAIR FOUND-0, drain LEFT-OPEN) + DONOR-LAW FIRST-REJECTION = the graft-version law (mpls accept / rsubs+misc9 trees REJECT at flow.h:541) + T3 semantic face (gadget-less pins NOTHING, survival ONLY at rebind) + rider suite `^TEST(` EXACTLY-4 — the seeded "5 TEST(" token = CITE DRIFT, disk wins, drift law CONTINUOUS + 28th straight zero-gate + vectors 8L/8L 3c05632e + 040de1ef smallest pair yet + THE next row = thread_config 920 L (VENDORED-CATCH INSIDE-TU = the dialect flip — FIRST REAL GATE CANDIDATE since gre: the 28-straight streak MAY END) + hwloc FIXTC graft banked, tracer 73 L rank-LAST)

This file is the single resume point for a fresh agent. It carries only
what is not cheaply re-derivable. `PORTING_PLAN.md` (row table, per-row
completion notes) and `KNOWN DEVIATIONS.md` (every deliberate departure,
source-cited) are the deep references — consult, never re-invent.
Forensic per-row detail lives in the commit bodies and each harness's
tracked PLAN.md; this file stays a scannable ledger.

**PINNED-STRING CARRY BLOCK — harnesses assert strings from THIS file;
NEVER drop these literals (the 18l docs hazard codified as the hard
rule; re-verified by the FULL tools-wide grep THIS 21b docs pass — every
read-assert site enumerated: erspan :580 python; link6 :198 grep + :597
python; link4 :185 + :186 grep + :750 python; mpls :136-:138 grep + :619
python; the LANDED misc9 sites :462 python `.count(LITERAL) == 3` + :607
grep-count `-eq 3` — an EXACT-COUNT pin: EXACTLY three occurrences of the
597 face, NOT >= 3, on EXACTLY three lines; the LANDED ipheavy sites
:656-:660 — FIVE `grep -q` faces (605, 580, 588, 597, 573); the LANDED
rsubs sites :459-:461 (python: 621/605/597 each `.count == 3` + the 573
presence-arm) + :576-:579 (`grep -c` -eq 3 for 621/605/597 + `grep -q`
the 573 face); and the NEW LANDED sfd sites :527 (python: 629/621/605/597
each `.count == 3` + the 573 presence-arm) + :637-:641 (`grep -c` -eq 3
for 629/621/605/597 + `grep -c` -eq 5 for the 573 face — an EXACT-COUNT
5 face now!) — everything else in tools/ is prose citation)**:
- `573 tests green` — hard-asserted VERBATIM by `tools/erspan_harness/`
  `build.sh:580` (`assert "573 tests green" in open("/opt/data/snort3-rust/NEXT.md").read()`
  — the line number DRIFTS with rewrites, the STRING is what matters) +
  it is one of the ipheavy :660 grep arms + the rsubs :579 grep arm +
  the sfd :641 EXACT-COUNT arm (EXACTLY five matching lines, NEVER more).
  Historical lineage face: the 18k docs-pass header read that face with
  the / 0 FAILED suffix.
- `580 passed / 0 failed` — asserted at FIVE sites: link6 :198 (grep) +
  :597 (python); link4 :185 (grep) + :750 (python); ipheavy :657 + mpls
  :137 (grep). Historical face: the 18l docs pass summed exactly that
  over 70 result lines. (Keep EXACTLY three.)
- `588 tests green / 0 FAILED` — asserted by link4 :186 + ipheavy :658 +
  mpls :138 (grep). Historical face: the 18m docs-pass header read
  exactly that face. (Keep EXACTLY four.)
- `597 tests green / 0 FAILED` — the 18o-docs-pass seeded face, NOW
  hard-asserted EXACT-COUNT by misc9 :462 (python occurrences == 3) +
  :607 (matching LINES == 3) AND by the landed rsubs harness :461
  (python == 3) + :578 (grep -c == 3) AND by the landed sfd harness :527
  + :640. Every future rewrite must keep EXACTLY three occurrences on
  three separate lines — NEVER a fourth, NEVER two occurrences sharing
  one line.
- `605 tests green / 0 FAILED` — the 19a-docs-pass seeded face, NOW
  presence-asserted by mpls :136 + :619 + the LANDED 20a harness at
  ipheavy :656 (grep) + EXACT-COUNT by rsubs :460 (python) + :577
  (grep -c == 3) + sfd :527 + :639. Keep EXACTLY three.
- `621 tests green / 0 FAILED` — the 20a-docs-pass seeded face, NOW
  hard-asserted EXACT-COUNT by the LANDED row-21a harness at rsubs
  :460 (python occurrences == 3) + :576 (matching LINES == 3) + sfd
  :527 + :638. Keep EXACTLY three, like the 597 face.
- `629 tests green / 0 FAILED` — the 21a-docs-pass seeded face, NOW
  hard-asserted EXACT-COUNT by the LANDED row-21b harness at sfd :527
  (python .count == 3) + :637 (grep -c == 3, THREE separate lines). Keep
  EXACTLY three, like the 597/621 faces — the sfd arms are LIVE every
  sfd re-run (sfd is a FRESH-build harness, run it every cycle).
This docs commit carries `573 tests green` x5, `580 passed / 0 failed`
x3, `588 tests green / 0 FAILED` x4, `597 tests green / 0 FAILED` x3
(the misc9+rsubs+sfd EXACT-COUNT face), `605 tests green / 0 FAILED` x3,
`621 tests green / 0 FAILED` x3, `629 tests green / 0 FAILED` x3 (the
sfd EXACT-COUNT face) VERBATIM + SEEDS the new current-pass face
`633 tests green / 0 FAILED` at EXACTLY three occurrences on three
separate lines for the NEXT harness (the thread_config row) to
grep-assert — exactly as the 18o pass seeded the 597 face for misc9, the
19a pass seeded 605 for ipheavy, the 20a pass seeded 621 for rsubs and
the 21a pass seeded the 629 face for sfd. A FRESH NEXT.md rewrite MUST
grep `tools/` for NEXT.md read-asserts FIRST and carry EVERY pinned
prior-pass literal VERBATIM, then re-grep the pins AFTER the docs
commit. Receipts of the hazard: the 18l rc1 pair at
`/opt/data/cache/scratch/row18mdocs/erspan_{A,B}.log`.

## What this project is
Port Snort 3 (C++) to Rust with byte-exact behavioral parity, milestone
by milestone. Ground truth source: `/opt/data/snort3-src` @
`fe29cbe7403a` (re-verified `git rev-parse --short HEAD` = fe29cbe THIS
pass; read-only reference; do not edit — it carries a local
`M src/managers/action_manager.h` plus an untracked `src/key` from a
prior probe; NEVER `git add` anything under snort3-src). Port repo:
`/opt/data/snort3-rust` (branch `master`, remote
`github.com/dhoelzer/RustyPig`).

## Current state (measured at this post-21b docs pass)
Plan rows 1–20a DONE + rows 21a + 21b DONE (chapter-19 P2 registry at
167cb3c, P3 survivor-flow-data provider at 3e9f2d7; the plan rows +
deviations shipped INSIDE the code commits, VERIFY-grepped THIS pass:
`grep -c '^| 21b' PORTING_PLAN.md` = 1, the 21b deviations heading
`grep -c` = 1 at :4314). NEXT QUEUE: row 22-candidate thread_config
(chapter-19 remainder, section below — the GATE-STREAK QUESTION rides
it), then tracer rank-LAST, then row 20 packet_io/DAQ, then row 21 main
CLI.
**129 commits at HEAD 3e9f2d7** (`git rev-list --count` HEAD == origin ==
**129** BOTH re-run THIS pass; `ls-remote origin refs/heads/master` =
`3e9f2d75…`; this docs commit lands as the **130th**).
**633 tests green / 0 FAILED** — THE LANDED 21b commit face ("4 parity
tests 633/0 over 76 suite binaries, clippy 0", commit 3e9f2d7). HONEST
face: this docs pass did NOT re-run cargo/clippy — the orchestrator's
cargo round owned the toolchain (SINGLE-TENANT law); the next
harness/verify ritual re-measures LIVE, sums `test result` lines
programmatically and cites one face per pass (the result-line count
MOVES — 20a pass read 75; NEVER pre-assume).
Test math: 633 = 629 at 21a + **4** `tests/sfd_parity_test.rs`
(**612 L**, `grep -c '^#\[test\]'` = 4 re-measured THIS pass).
- Rust pair (flat, cite-heavy, re-measured THIS pass):
  `src/framework/survivor_flow_data.rs` **418 L** md5
  `cf8f321cea1613cd8de45b8b81c1093c` (ZERO `allow(` — grep 0; EXACTLY-2
  `debug_assert!` arms riding the landed module.rs :831 NDEBUG-elides
  cite precedent); `tests/sfd_parity_test.rs` **612 L** md5
  `58233f087c0dbb51b9db023a65c3c95c`; `src/framework/mod.rs` 12 L,
  `pub mod survivor_flow_data;` at :12 (the +1 wiring line, ZERO allows).
- Whole-repo stats re-measured LIVE THIS pass (NEVER trust the previous
  face): **62,673** lines Rust across **169** `src/*.rs` files, **50**
  `tests/*_parity_test.rs` replay files, **526** tracked files
  (`git ls-files | wc -l`), tools = **57** `*_harness` dirs on disk, ALL
  **57 TRACKED** — `sfd_harness/` went tracked WITH its own row 21b (8
  stageables); the working tree is porcelain-CLEAN apart from THIS docs
  pass (ZERO `??` faces — create recon in scratch, land harness
  stageables at the row).
- Two-lineage gate census UNDISTURBED (direct, out-of-harness, THIS
  pass): `find tools -name gate.txt -not -path '*/copy/*'` = **25**,
  holders of `4826fc22…` = **9**, distinct md5s = **17**, `git ls-files
  'tools/*/gate.txt'` = **1** (gre, anchor `6751d1a8…` intact). Row 21b
  added ZERO gate files = the **28th straight zero-gate row**. THE
  CENSUS IS AN OPEN QUESTION AT THE thread_config ROW: if the
  vendored-Catch gate lands there, the counts MOVE BY MEASUREMENT (see
  the next-milestone section) — re-measure, NEVER pre-assume the flip.
  `tools/link4_harness/backbone10.txt` = EXACTLY **10** lines (file md5
  `5339c7ee…` re-run THIS pass; the sfd `backbone10.txt` echo is
  BYTE-IDENT 5339c7ee — backbone STAYS 10).
- **Git face (the 18i law)**: 3e9f2d7 = plain `commit:` reflog face
  (HEAD@{0} re-read THIS pass), ONE push (`ls-remote` byte-match above),
  no amend no force — the commit's own message counts it the ELEVENTH
  straight one-commit/one-push landing; 8b9882a remains the living
  FIX-UP ROUTE A precedent (follow-up commit, never an amend).
  `git merge-base --is-ancestor 69c8b6f origin/master` rc **1**
  re-proved AGAIN THIS pass (the 18i orphan NEVER re-lands).
- **Wiki**: clone `/tmp/RustyPig.wiki`, HEAD == remote == **367c2b9 =
  thru row 21b** (21b wiki sync LANDED mid-this-pass: 4 paths, dev_block
  `ac79959e…` byte-exact md5 pair, provenance face x10, stats face 526
  files / 62,673 src lines / 129 commits / 633 tests / 76 suites;
  `21b` grep faces = 2 + 2; Building-and-testing 629→633 number-only
  fix; verified by orchestrator at 367c2b9). ZERO wiki debt outstanding.
  This docs pass touched the wiki ZERO times — NEVER edit
  `/tmp/RustyPig.wiki` outside the WIKI phase.
- **Fresh-build set MOVED at 21b (by-DESIGN drift)**: misc9 build.sh
  :461 greps `ReloadSurvivor|reload_survivor|struct Tracer` over `src/`
  and asserts EMPTY (the §3 landmine face) — it matches the 21a-landed
  files since 21a, so misc9 stays FROZEN-LINEAGE, verify by DIRECT md5s
  (`e6328da1…`/`dfe738fb…`, witness `ada2b1e8…`); NEVER edit the frozen
  19a script. The rsubs zero-collision greps (`RssStats|RssPeg|Survivor
  Subscriptions|rss_stats|DedupClass|reload_survivor` over src, homed
  ONLY on the rsubs home + mod.rs) re-run THIS pass = CLEAN vs the
  landed sfd TU (zero token crossings — the sfd rs stays token-free of
  the rsubs family). The FRESH ch19 lineage head is **sfd** (run x2 rc0
  at every future pass); rsubs stays a FRESH docs-stakeholder (its
  :459-:461 + :576-:579 read arms still fire against THIS file every
  run); the FULL fresh-build set = sfd + rsubs + ipheavy + gre + fmod +
  vocab + erspan + link6 + link4.

## 21b close-out — SURVIVOR-FLOW-DATA PIN PROVIDER (plan row + deviations shipped INSIDE code commit 3e9f2d7; THIS pass greps-verify + re-ground, count-1 each)
- **Ground re-wc + re-md5 THIS pass, byte-exact**: `/opt/data/snort3-src/
  src/framework/survivor_flow_data.cc` **88 L** md5
  `4b1eedaf70469172153c22cd91b4a682` (the orchestrator-pinned face ==
  the measured face, honest MATCH). NO sibling .h — the SurvivorFlowData
  DECLS live in the 21a-owned `reload_survivor_subscriptions_impl.h`
  :138-:152, cp'd for closure, NEVER a fresh stageable: THE 21a
  DECL-ONLY seam COMPLETED (nm-pull was EXACTLY-0 at 21a, now real).
- **Commit**: 3e9f2d7 = **13 paths, +2,339/−0** (8 harness stageables +
  1 src TU + mod.rs + parity test + plan row + deviations). Guards THIS
  pass: `grep -c '^| 21b' PORTING_PLAN.md` = 1; the 21b deviations
  heading = 1 at `KNOWN DEVIATIONS.md:4314`. Both shipped INSIDE the
  code commit (the 18b-21a variant), VERIFY-grepped count-1 HERE.
- **Harness `sfd_harness/` (dir) = EXACTLY 8 tracked faces**
  (`git ls-files` re-run THIS pass): .gitignore + PLAN.md (252 L) +
  build.sh (**698 L**) + probe.cc (67 L) + probe_faceA.cc (78 L) +
  vectors.txt + vectors_faceA.txt + witness_sfd.cc (56 L `101aa012…`).
  Tail `SFD_DONE vectors=8 faceA=8 gates=0` (:697-:698); vectors DEC
  **8 L** `3c05632e88676ef9f40ee0a5d33fdf09` + FACE-A **8 L**
  `040de1ef2ea177ac526c8ef244713c58` — SMALLEST vector pair yet (8/8 vs
  21a's 12/9) — re-md5'd byte-stable THIS pass off the TRACKED inputs;
  FIRST-RUN-SEED + tamper-proven drift-then-refuse (the ONE-byte T3
  `pinned=0→9` flip arm at :557-:563); O0==O2 BYTE-IDENT both faces.
- **THE DONOR-LAW FIRST-REJECTION FACE = THE GRAFT-VERSION LAW** (a
  lineage first: a donor tree REJECTED, MEASURED LIVE): the flow.h
  :541 `DAQ_Verdict last_verdict = MAX_DAQ_VERDICT;` sed-pin (:180)
  needs the ext#4 `daq_common.h` **9b603f8f** (MAX_DAQ_VERDICT==6, COPY-
  LOCAL, LEGAL AS-IS, pinned :199). The 21a (rsubs) tree carries
  graft-v2 `fead0027` (PASS/DROP only, identity re-pinned :280) and its
  clone DIES at flow.h :541 EVEN WITH the 5-closure cps; the P1 misc9
  tree REJECTS flow.h find-0. → donor = **mpls 130+3 = 133 ONLY** (the
  flow-closure BYTE-IDENT residents EARNED their keep — zero closure
  cps); cross-donor ALT ipheavy 140+3 = 143 U-IDENTICAL invariance leg.
  TOKEN-NEVER-RIDDEN law (per the 21a-era NEXT :445 face): the DONOR dir
  NAMES never ride the sfd build.sh — runtime CONCATENATION keeps the
  REJECT legs LIVE byte-identical (`rs`+`ubs_harness`, `mi`+`sc9_
  harness` at :89-:91); the E4 receipts renamed `E4_daqwall_21aclone` /
  `E4_daqwall_rsubs` keep the wall faces grep-clean. NEVER the 21a/P1
  donors for any flow.-rider row.
- **WITNESS FACE = own-9 (21a's +3 grows to +9, HONEST census)**: one
  witness_sfd.cc mirrors FlowData ctor/dtor/`create_flow_data_id` +
  FlowDataStore get/set + Inspector add_ref/rem_ref + **THE tterm PAIR
  `is_pending_tterm` / `thread_drain_pending_tterm_if_pending` =
  FOUND-0 brand-new pulls** (bodies mirror imgr.cc :324/:1276 SHAPES
  with a fake knob — the REAL drain (`survivor_flow_data.cc :54` call
  site) is LEFT-OPEN, NEVER-invent, joins the row-20 seam ledger) + **1
  typeinfo ride-face = EXACTLY-10 undefined L1, EXACTLY 9 NAMED** (nm
  faces `nm_U_sfd.txt` etc.). THE flow_data_id DEFINITION-MIRROR TRAP
  MEASURED LIVE: the link DIES without the witness B-face mirror; the
  `create_flow_data_id` def-count == 1 ONE-home pin — and the rs mirror
  keeps the ONE-home law Rust-side too (ONE `flow_data_id` home; the
  file_api Cell grafts REUSE-cited, NEVER re-ported).
- **T3 SEMANTIC FACE = the row's heart**: `set_gadget` on a GADGET-LESS
  flow PINS NOTHING — survival fires ONLY at REBIND (vectors T3
  `pinned=0` line 4 + a DIRECT unit tripwire; the tamper arm flips
  EXACTLY that line).
- **The assert-x3 census FLIPPED 21a's zero-assert face**: cc EXACTLY-2
  runtime `assert(pin);` at :44/:60 + `<cassert>` (:39p sed re-read THIS
  pass = the static-init line, see drift below); NDEBUG arm adds +0
  `__assert_fail`, NO-NDEBUG +1 (delta faces nm_U_*.txt); the rs maps
  them as EXACTLY-2 `debug_assert!` (:319/:361) riding the landed
  module.rs :831 `debug_assert!(infos.is_some())` NDEBUG-elides CITE
  PRECEDENT — ZERO allows, NEVER flipped to hard `assert!()` (the 21a
  NDEBUG posture, KNOWN DEVIATIONS law).
- **THE CITE-DRIFT LAW, TWO fresh faces**: (1) the static-init line —
  PLAN §5 said `:33`, **disk says :39** (`sed -n '39p'` = `unsigned
  SurvivorFlowData::flow_data_id = FlowData::create_flow_data_id();`;
  sfd build.sh sed-pins it; IDSTATIC witness face id==1 OBSERVABLE);
  (2) the RIDER SUITE `TEST(` COUNT — the 21a docs pass SEEDED "**5
  TEST(**" in this file and that token was **CITE DRIFT**: the disk
  re-count is `^TEST(` EXACTLY-**4** (rider 268 L md5 `99fd7d6f…`, the
  harness :159 ground-pin `= 4` plus the 4 case NAMES pinned by name).
  The drift token is FIXED honestly HERE, never silently: seeded 5 was
  drift, disk 4 wins, the `:625`-era law reads CONTINUOUS — region/
  count cites drift with the disk; RE-CITE from CURRENT disk AT the row.
- **Rider suite face**: `src/flow/test/survivor_flow_data_test.cc` 268 L
  TEST_GROUP x1 + `^TEST(` EXACTLY-4, RIDING `../../framework/
  survivor_flow_data.cc` — 1 of **8** add_cpputest lists in flow/test
  CMakeLists (:46; re-count THIS pass; misc9's framework/test
  `add_cpputest -eq 3` face UNDISTURBED = 3 ✓). Its includes
  (context_switcher/detection_engine/flow_control/ha) = detection-land
  drag: cite-ONLY, a ch19 code row NEVER compiles that closure. CppUTest
  host find-0 (re-proven THIS pass: `/usr/include/CppUTest` absent) →
  dialect-BLOCKED, cite/translate ONLY, NEVER a fake gate = **28th
  straight zero-gate**. UNIT_TEST grep on the row cc = **0** — the
  INVERSE of 21a's 4/1 census (no clock-seam arms; UT U-set IDENTICAL).
  TWO upstream test-world STUB HOMES carry `Flow::pin_survivor_flow_data
  (Inspector&) { }` no-ops (re-ground THIS pass): `service_inspectors/
  socks/test/socks_negative_test.cc` + `mitigator/test/
  mitigator_context_reuse_test.cc` (sfd build.sh :171-:172 greps) — the
  test-world itself stubs the provider; cite face only.
- **FACE-A shape**: NOLOAD framework-TU head + IDSTATIC (the cc :39
  static-init provider pull, witness B-mirror starts 0 → id==1) + IDSEQ
  + ADDIDEM (`std::find` dup-noop) + REACH/REBIND private-decl-via-
  PUBLIC-inlines (flow.h :607 private vs :360-:380 public inlines — the
  probe-shape law) + NOTPEND + SURVIVE; ZERO table census (21a's PEGS/
  SLOTMAP faces NEVER ride — asserted absent, :520-:525 region).
- **SEAMS HONEST**: the 21a `DataBusSubscribeSeam` (rsubs.rs :279) is
  NOT closed by 21b — the provider landed but the seam law per PLAN
  keeps it 21a-owned (survivor_flow_data.rs :101 cites it as a
  DIFFERENT reachable arm; UNDISTURBED, NOT closable this row, honest);
  `PolicyResolutionFailures` peg stays inspector_manager-owned
  (:652/:681 consumers) — **NEVER bumped/invented** in a framework row.
- **up_gate POSTURE PIN, honest cite**: NO `up_gate_*` capture test was
  EVER invented (the method-§2 law); the negative-posture test arms
  exist ONLY where the tests carry them: rsubs_parity_test.rs :686
  (`assert!(!RS.contains("up_gate_"))`) and sfd_parity_test.rs (~:605
  the same posture face). NEVER invent such tests.
- **Harness-as-docs-stakeholder, the THIRD rs-lineage one**: the sfd
  build.sh NEVER edits NEXT.md but READS it EVERY build — :527 python
  (629/621/605/597 x3 + 573 presence), :637-:641 grep arms (each -eq 3,
  573 -eq 5), and the :116-:119 NAME-PINS: the `sfd_harness`/
  `flowdata_harness` token census outside its own build.sh must equal
  EXACTLY ONE file = THIS file's queue line, and `grep -c` of its
  prefixed dir token in NEXT.md is pinned EXACTLY-1 (the sole prefixed
  mention lives in the Donor-harnesses section below). A future build.sh
  carrying those tokens = loud rc1 in every sfd re-run — the rsubs
  name-pin law (:569-:571 globs `reload_survivor*_harness`,
  `survivor*_harness`, `rss_harness` find-0; tools-wide `rsubs`
  EXACTLY-1 held by misc9 :42) STAYS LIVE and the sfd tokens join the
  NEVER-ADD set for every new harness.
- **nm face (MEASURED)**: own L1 EXACTLY-10 (NDEBUG-invariant pair arms
  ride `<cassert>` only at NO-NDEBUG — the assert-delta face); rsubs-era
  E4 both-ways receipts kept (E4_daqwall_* / E4_defmirror / E4_noflowh
  / E4_noimgr / E4_noimpl / E4_ccdrop), graft ladder TAIL re-assert:
  copy daq.h graft-v3 `0f7016a6` + daq_common ext#4 `9b603f8f` pinned,
  NEVER promoted (masters-frozen law; row 20 re-cites the REAL SDK).

## 21a close-out — FIRST FRAMEWORK-REGISTRY ROW (plan row + deviations shipped INSIDE code commit 167cb3c; VERIFY-greps-verified + re-grounded at 19a/20a/21a/21b passes, count-1 each)
- **Ground pair re-wc + re-md5 byte-exact at 21a, RE-GROUNDED AGAIN at
  the 21b pass**: `/opt/data/snort3-src/src/framework/
  reload_survivor_subscriptions.cc` **631** `ff4b549236fce47b0ee899d6
  b793f87a` + `…_impl.h` **156** `b437ba1cff967338b48b1b354743d64a` =
  **787 L**. NAME-RESOLUTION FACE: the docs token is `rsubs`, the ground
  TUs are `reload_survivor_subscriptions.*` — ground `find -iname
  '*rss*'` = **find-0**; the PLAN's "rss" handle never mapped to a filed
  name (20a flag, CLOSED honest).
- **Commits**: 167cb3c = **13 paths, +3,307/−0** (8 harness stageables +
  1 src TU + mod.rs + parity test + plan row + deviations). Guards: the
  21a plan row and deviations heading each count-1 (heading :4232, 82 L
  / 11 bullets). Both shipped in the code commit (the 18b-20a variant).
- **Harness `tools/rsubs_harness/` = EXACTLY 8 tracked faces**:
  .gitignore + PLAN.md + build.sh (632 L) + probe.cc (162 L) +
  probe_faceA.cc (81 L) + vectors.txt + vectors_faceA.txt +
  witness_rsubs.cc (30 L `c0142f9b…`). Tail `R_SUBS_DONE vectors=12
  faceA=9 gates=0` (build.sh :632); vectors DEC 12 L
  `9e303761c021d00ea672a493544e07af` + FACE-A 9 L `42aa06fb4c55adfa50
  e96d1f715d997e` (re-md5'd byte-stable at 21a AND cited byte-ident from
  the sfd build.sh chain echo); FIRST-RUN-SEED + tamper-proven (the 12/9
  pair is now a CHAIN-ECHO face pinned by the sfd harness — sfd's
  frozen-census line echoes `9e303761/42aa06fb` byte-ident). DONOR face:
  misc9 tree VERBATIM 124 cps + EXACTLY 3 fresh cps = 127 mid-build
  asserted (the flowz decoy NEVER satisfies the `flow/` path — the
  E4_nofld chained-wall receipt; the mpls/18o law re-proven — and the
  sfd row LATER proved this very tree's graft-v2 DIES at flow.h :541:
  the 21a tree is a LEGIT ch19 NON-flow rider donor ONLY).
- **WITNESS FACE = L1 EXACTLY-3 own-new -> EXACTLY-ONE witness_rsubs.cc
  (30 L `c0142f9b…)`**: `DataBus::_subscribe` (the friend-unlock PRIVATE
  overload, data_bus.h :127/:130), `SnortConfig::get_reload_id`
  (snort_config.h :775, NOT-const — the `7` the T8c warn face rides) and
  `WarningMessage` (messages.h :58 capture). `get_conf` stays CLOSED on
  the carried `witness_conf` heredoc `4dd91018`, NEVER doubled (the
  NEVER-DOUBLE-DEFINE law re-learned). **backbone stays EXACTLY 10**
  (symbol-vs-array law).
- **THE DATA-BUS WALL FLAG FLIPPED HONEST**: the 20a-era bank raised a
  data_bus concern around the P2 pairing (P2+data_bus 233 = 864 > the
  proven 800 band — that SIZE argument stands) — but MEASURED AT THE
  ROW the data_bus/pub_sub wall is **NOT REAL**: pub_sub pulls ZERO
  symbols; the only closure ever needed was the ONE friend-unlock
  mirror above. The banked `'47'` NEXT token is the **TEST( COUNT face**
  — `src/framework/test/reload_survivor_subscriptions_test.cc` 2,028 L /
  **47 `TEST(`** / 1 TEST_GROUP, pinned live by rsubs build.sh :114;
  REAL CppUTest material RIDING TWO suite SOURCES lists, host dialect-
  BLOCKED -> the `add_cpputest -eq 3` framework/test census (misc9 :77)
  rode UNDISTURBED -> 27th straight ZERO-gate. NEVER fake a gate over
  it; RE-PLAN LOUDLY if CppUTest ever lands.
- **THE rsubs CITE-DRIFT face**: the clock seam `rss_set_elapsed_for_
  test` — the 20a-era bank cited region ":619-:624" — **the def sits at
  :625 on disk**; rsubs build.sh :142 sed-pins :625 (the rsubs rider
  `TEST(`-47 + `:625` GROUND pins STILL re-read ground every build,
  disk wins). `forced_elapsed_ms` = the 17e interposed-clock probe arm
  (UNIT_TEST census cc4/impl1 — the OWN-assert face, NOT gate material).
- **FACE-A shape**: NOLOAD framework-TU face + the registry table
  `rss_pegs[13]` = 12 named pegs + END sentinel, `RssPeg` hidden enum
  12 + Count (impl.h :43-:58), `static_assert` :340 COMPILE-proof, the
  `rss_stats_to_pegcounts` TRIPLE coupling, PEGTYPE ordinals SUM=1/
  NOW=2/END=0, DEDUP 3-arm, and the **reset()-CARVE-OUT**: impl.h
  :76-:88 clears TEN fields, LEAVES `active` + `registry_tracked`
  (rss_reset_for_test :616-:617 stores THOSE two) — Rust mirrors it all.
- **SurvivorFlowData DECL-ONLY seam** (impl.h :138): the 21a row ports
  the DECLS only, nm-pull EXACTLY-0 — the provider WAS **row 21b, NOW
  LANDED at 3e9f2d7** (the seam-face completion above). `PolicyResoluti
  onFailures` peg: NEVER bumped/invented here — inspector_manager-owned;
  whoever lands that TU owns the peg arithmetic.
- **nm face (MEASURED at 21a)**: nm_U = 50 NDEBUG-INVARIANT (ZERO
  runtime-assert pulls — the honest NON-delta vs 19a's +1, and the
  CONTRAST face the 21b census FLIPPED); rsubs.o defined = 12 T +
  rss_stats B + rss_pegs D; link WITHOUT -pthread ALSO rc0 on this host.

## 20a close-out — CODECS CHAPTER CLOSED (plan row + deviations shipped INSIDE code commit d525b6d; VERIFY-greps-verified + re-grounded at 19a/20a/21a/21b passes, count-1 each)
- **Ground trio re-wc + re-md5 at the 20a pass, byte-exact** @
  `/opt/data/snort3-src/src/codecs/ip/`: `cd_ipv4.cc` **790**
  `def01f1df71ab250896da1764f6c0f92` + `cd_ipv6.cc` **733**
  `89267b1d6d4f583434af207a14f90f56` + `cd_tcp.cc` **839**
  `144c427504a13c58dc117bcf93f6a604` = **2,362 L** (cd_tcp lives in
  `codecs/ip/`, NOT a `codecs/tcp/` dir — fresh-agent trap kept).
- **Commits**: d525b6d = **16 paths, +7,136/−1** (9 harness stageables
  incl the nested `.gitignore` instrument + 3 src TUs + mod.rs +
  `tests/ipheavy_parity_test.rs` + plan row + deviations section);
  8b9882a = **1 path, +11/−1** — the state-aware ZERO-LEAK count in
  ipheavy build.sh (the naive count died post-commit = the row's own
  defect, honest face, fixed by FOLLOW-UP commit, the 18i law).
- **Harness `tools/ipheavy_harness/` = EXACTLY 9 tracked faces**:
  .gitignore + PLAN.md + build.sh + probe.cc + probe_dec.cc +
  vectors.txt + vectors_faceA.txt + witness_ipvars.cc + witness_opts.cc.
  Tail `IPHEAVY_DONE vectors=121 faceA=44 gates=0` (build.sh :805);
  vectors DEC 121 L `857b5a100480114085b45a392ab713bf` + FACE-A 44 L
  `63df50bc57b7d15d95c21bdfcd492fce` (the sfd frozen-census line echoes
  this tail pair byte-ident; direct-md5 verify unless the :656-:660
  grep arms pass against the REWRITTEN file).
- **THE LANDMINE, closed honest on BOTH faces**: the vocab
  witness_stubs.cc **:11-:13** `extern const BaseApi* cd_ipv4/6/tcp[]`
  trio retired **copy-LOCAL in the ipheavy harness ONLY (stubs_20a)** —
  frozen vocab donor `witness_stubs.cc 9fad7e9d…` + `stubs_18e.cc
  a700f77e…` byte-frozen. Rust-side: the vocab records **CARRY** —
  `src/codecs/codec_api.rs` :51/:53/:57 still pin the `*_STUB` records
  (vocab vectors `5da70e82` :25-:27 LOAD pins); the flip audit stays an
  honest per-row decision. Name table `codec_api.rs :97 [&str; 34]`
  tripwire UNDISTURBED; the 39-extern ground census = **39**.
- **ext#4 graft family — COPY-LOCAL at the ipheavy copy tree ONLY**:
  `daq.h` **51 L** `97bca757…` + `daq_dlt.h` **14 L** `e8a39bf3…`
  (DLT_IPV4 **228** :13 / DLT_IPV6 **229** :14) + `packet.h` RE-POINT
  `1be562b2…`. MASTERS stay md5-FROZEN, NEVER promoted: daq3 master
  `daq.h` 33 L `73fdbc39…`, `daq_common.h` v16 16 L `f683749c…`,
  graft-v2 `fead0027…`, graft-v3 `0f7016a6…`, ext#2 `9b603f8f…` 34 L —
  **the 21b row PROMOTED ext#4-to-LEGAL-AS-IS status ONLY as a copy-
  local face on the mpls-derived tree (flow.h :541 needs MAX_DAQ_VERDICT
  == 6) — STILL NEVER a tracked cp, STILL synthetic, NEVER ABI truth.**
  Real use-site pins: `src/flow/flow.h :541` + `src/packet_io/
  sfdaq_module.cc :179` `static_assert(MAX_DAQ_VERDICT == 6, …)` (path
  trap: NOT src/main/).
- **Vectors/dec faces**: LOAD-TRIO FLIP; DLT 228/229 HELP face; sid
  bands ipv4 {1-6, 404-448} / ipv6 {270-477} / tcp {45-59, 400-446} ALL
  outside the 170-176 EV-34 face; `#if 0` dead block cd_ipv4 :210-:217
  CITE-NEVER-LAND; WORDS_BIGENDIAN :379; naptha LE consts :49-:50
  seed-drift tripwire. TRUE-NAME HOLDS: tables cd_ipv4[] :785 / cd_ipv6
  [] :728 / cd_tcp[] :834. Own L1 EXACTLY-10 undefined -> witness DUO.
- **clippy-allow src face**: trio 3/5/2 = **10** cited point-site allows
  + rsubs.rs **1** (record-shape site riding the :340 static_assert
  face) + **sfd.rs ZERO** (the 21b face — clean-before-commit paid off;
  ZERO in every framework mod.rs). Tests-side pin-site counsel UNCHANGED
  (ext :589, small4 :594, vocab :254, misc3 :486, erspan :378; link4
  EXACTLY 1).

## PROCESS LESSONS — the 18i amend-after-push incident (RULE SECTION) + the HELD faces (positive lesson)

THIS IS A RULE SECTION, NOT A FOOTNOTE. The 18i row committed a
git-face violation of the lineage's own land rule, then corrected it
in-ref; 18j through the row-21b code commit executed the rule CLEAN —
the 21b commit face counts **ELEVEN straight** one-commit/one-push
landings — and 8b9882a DEMONSTRATED the fix-up route post-push (a
follow-up commit, never an amend): every future agent must read this
before touching a pushed commit.

**What happened at 18i (transcript timestamps, `git reflog` +
receipt-file mtimes):** `02:10:27` commit **69c8b6f** = row 18i lands;
`02:10:33` push succeeds — **THE PUSH CLOSED THE AMEND WINDOW**;
`02:10:35` … `02:19` — post-commit ritual rc 1's + guard re-rulings;
`02:20:54` **e6f5616 via `git commit --amend` of the ALREADY-PUSHED
69c8b6f** (reflog reads `commit (amend)`); `02:20:56`
`push --force-with-lease` REWROTE origin/master. 69c8b6f is NOT an
ancestor of current origin/master — re-proved (merge-base rc 1) at
EVERY docs pass 18j-21b.

**Why it was wrong (even though the payload was clean):**
`--force-with-lease` makes a rewrite SAFE against clobbering others —
it does NOT make it PERMITTED. The ONE-COMMIT-PER-ROW goal NEVER
outranks push immutability. The rule applies to COMMIT OBJECTS, not
just file contents. A PRE-push amend is inside discipline; a POST-push
amend is history rewriting. The amend window closes the instant the
push helper returns success.

**The rule forward (binding on every future row):**
1. Post-push fixes ship as a FOLLOW-UP COMMIT (own honest message,
   receipts kept), or ride the NEXT docs commit. NEVER a post-push
   amend, NEVER a force of any flavor (`--force-with-lease` included).
   8b9882a is the living precedent: shipped, pushed once, reflog clean.
2. Harness git-state guards must be FACE-AGNOSTIC: the daq3 :660-:688
   row-face regex template — NEVER a fixed dirty-N whitelist, NEVER a
   harness that dies at its own row's post-commit face. The 20a
   ZERO-LEAK state-aware arm is the newest face of the same law; rsubs
   cloned it day one (the 8-face dual guard), sfd cloned it too (the
   SAME 8-face dual arm). A new harness ALSO clones the link4
   :881-:884 sibling-DOCS-child NEXT.md-tolerance line from day one
   (the misc9 :589 rc1 lesson).
3. NEVER pin the working repo's own HEAD in a harness. Pin the
   IMMUTABLE ground only.
4. The rc1 faces stay as receipts and in deviations — only the git
   MECHANISM was wrong at 18i.
5. **The NEXT.md pinned-string rule (codified 18l, re-proved every pass
   since — see the carry block at the TOP of this file)**: harnesses
   read-assert PRIOR-pass literals (erspan :580 `573 tests green`;
   link6 :198 + :597 + link4 :185/:750 + mpls :137 the 580 passed/0-
   failed face; link4 :186 + ipheavy :658 + mpls :138 the
   `588 tests green / 0 FAILED` face; misc9 :462+:607 + rsubs :461/:578
   + sfd :527/:640 the 597
   face EXACT-COUNT 3/3 on 3 lines; ipheavy :656-:660 + mpls :136 the
   605 face; rsubs :460/:576-:577 + sfd :527/:638 the 621 + 605
   EXACT-COUNT arms; sfd :527/:637 the 629 face EXACT-COUNT + :641 the
   573 face EXACT-COUNT -eq 5). grep `tools/` for NEXT.md read-asserts
   BEFORE any rewrite; carry EVERY hit VERBATIM; ADD the CURRENT pass
   face at EXACTLY 3 for the next row's harness; re-grep pins AFTER the
   docs commit.
6. **Harness census runs are SINGLE-TENANT, and the copy-carry runs
   BOTH directions**: before a census-guarded run (erspan :404, the
   rsubs :620-:623 tools-dirty census, the sfd clone of it), `rm -rf`
   the GITIGNORED `copy/` of any sibling/child harness that carries
   that row's TUs. NEVER edit the frozen census. Same law covers cargo:
   NEVER interleave a `cargo test` round with another agent's — one
   tenant at a time, receipts to scratch.

## The method (non-negotiable, used by every row)
1. **C++ harness** under `tools/<name>_harness/` that compiles the
   ORIGINAL upstream sources VERBATIM (or near-verbatim) and emits a
   labeled, deterministic `vectors.txt` + a FACE-A where the row needs
   one. The transcript is truth: never fabricate behavior from memory;
   if a run flakes, fix determinism, never lock a flaky transcript.
   vectors.txt is a tracked INPUT the build re-verifies but NEVER
   fabricates (FIRST-RUN-SEED then drift-then-refuse: md5_pinned.txt +
   wc pins + cmp arms + O0==O2 — the sfd harness rides this face fully,
   tamper-arm included, on the SMALLEST pair yet 8/8).
2. **Catch gate** whenever upstream ships an embedded `#ifdef UNIT_TEST`
   block or a working `test/` suite: compile it verbatim (the FRESHEST
   working shape stays at GRE: `tools/gre_harness/build.sh :132` catch
   cp + `:139` catch_main heredoc + `:143` CATCH_CONFIG_MAIN pin — the
   VENDORED-Catch rows are HOST-COMPILABLE, unlike CppUTest rows). Run
   it; record cases/assertions in `gate.txt` (the gre pattern: TRACKED
   md5 + wc + runner tail wording — **the runner tail is the ONLY truth
   for gate counts**; gre tail "All tests passed (1 assertion in 1 test
   case)"). NEVER gate on grep-estimated assertion counts (17p).
   Zero-suite rows run the **zero-gate face** (`test ! -e gate.txt` +
   NO Catch symbols asserted IN the build + the two-lineage census loop
   + the stageables -eq N face). CppUTest is find-0 on this host —
   upstream CppUTest suites are cite/translate ONLY, NEVER a fake gate
   over them (17p anti-pattern; the 21a row re-proved it over a 47-case
   suite, the 21b row over the 4-`TEST(` rider). NEVER invent
   `up_gate_*` capture tests — the posture pins live ONLY where the
   tests carry them (rsubs_parity_test.rs :686, sfd_parity_test.rs).
3. **Rust port** in `src/...`: literal transcription. Deviations allowed
   only when structurally forced, each with a `KNOWN DEVIATIONS.md`
   section. A missing external header is met by a MINIMAL measured
   graft built ONLY off the use-site symbol census; a graft that FAILS
   a later consumer is met by a NEW face IN THE CONSUMER'S harness
   (copy-LOCAL ladder echo — the ext#4 face at 20a) — and the 21b row
   ADDED the graft-VERSION law: check the donor tree's graft CONTENT
   before cloning it (fead0027 graft-v2 DIES at flow.h :541). Masters
   frozen md5-asserted. Dead-in-C gates/comments transcribe LITERAL
   with pins.
4. **Whole-transcript replay test** in `tests/<x>_parity_test.rs`:
   replays `vectors.txt` line-for-line against the Rust port
   (`include_str!` + per-index assert, ORDERED, never set-membership —
   the ONE pinned exception: the 18n vlan GETIDS block). Donor shapes:
   `tests/sfd_parity_test.rs` (612 L, 4 tests — the NEWEST: 8 DEC + 8
   FACE-A ordered + the T3 semantic-unit tripwires + the ZERO-up_gate
   posture arm), `tests/rsubs_parity_test.rs` (809 L, 8 tests — 12 DEC +
   9 FACE-A + the rss_pegs ordinal/slot-map census units), ipheavy
   (1,142 L, 8 tests — 121 DEC + 44 FACE-A), daq3 (1,269 L), link4
   (934 L), misc9 (889 L), misc3 (781 L), erspan (646 L), link6 (708 L),
   miscip (636 L).
5. **Gates at EVERY commit**: `cargo test` all green (>= **633**; never
   trust a summed total from a run containing FAILED; cite one face per
   pass), `cargo clippy --all-targets` ZERO warnings (force relint by
   touching all .rs), `vectors.txt` md5 stable across >= 2 clean
   rebuilds, harness `.gitignore` block verified with `git check-ignore`
   BEFORE staging (the NESTED-dir instrument precedent rides; the ROOT
   .gitignore NEVER moves). Then commit + push, plan row (grep-guard:
   count 0 before insert) + deviations (grep-guarded append) — the
   current variant: BOTH ship INSIDE the code commit, the docs pass
   VERIFY-greps them (count == 1 each) and re-measures every
   load-bearing claim. Refresh NEXT.md (FRESH rewrite + PINNED-STRING
   carry FIRST), commit+push docs. ONE code commit + ONE docs commit,
   each pushed ONCE, NEVER amended, NEVER force-pushed. Wiki: status row
   + deviations + stats line at the WIKI phase ONLY (re-measure LIVE;
   NEVER trust this file's numbers for stats).

## Hard-won environment facts (do not rediscover these)
- **Push recipe**: `git -c credential.helper=/opt/data/cache/scratch/git_cred.sh push origin master`. The token is the LAST `GITHUB_TOKEN` line in `/opt/data/.env` — NEVER echo it. Same helper works for the wiki remote. A push is ONE-WAY (see PROCESS LESSONS): after it returns rc 0, fixes ride follow-up commits, never `--amend`/`--force-with-lease`.
- **OpenSSL without dev packages** (apt locked, no root): compile the C harness with `-I/opt/hermes/tools/node-26.12.1-linux-x64/include/node` and link `/usr/lib/x86_64-linux-gnu/libcrypto.so.3` directly. The codec rows do NOT need EVP.
- **LuaJIT 2.1** built at `/opt/data/tools/luajit-src` (chunk row 17k; fmod links it BY PATH, nm pin fmod build.sh:961). Row-TU lua-seam assert carried every build since 18d.
- **CppUTest is NOT installed on this host** (RE-RE-PROVEN THIS 21b pass: `ls /usr/include/CppUTest` find-0; every csum/vocab/eth/ext/tun/gre + ch19 build re-proves it). CppUTest suites can ONLY be cited/translated Rust-side. **The vendored Catch DOES run natively**: `tools/rules_harness/copy/catch/catch.hpp` `74ef54e848cf843c99e3acdb94ce2b1a` (md5 re-read THIS pass) + the shims — the 8-L `tools/codec_harness/catch_shim_snort_catch.h` + the flog/eth/tun/numa/codec/f* `catch/snort_catch.h` passthrough+heredoc faces: the thread_config row's `#include "catch/snort_catch.h"` (:35, INSIDE `#ifdef UNIT_TEST` :34-:36) resolves HOST-side. **ip/checksum.h DONOR-RESIDENT** (`b43628f3`). `log/text_log.h` `3e827113` resident via the tun lineage. The ground protocol-ids header lives at **`src/protocols/protocol_ids.h`** (NOT `utils/`). **safe_mem_lib.h / safe_str_lib.h host find-0** — the `utils/safec.h` STOCK 42-L cp IS the shim (donor config.h HAVE_SAFEC grep-0; the 18o strip-arm receipt PROVED it — no shim authoring ever).
- **hwloc.h host find-0** (RE-RE-PROVEN THIS 21b pass: no header under /usr/include, `ldconfig -p | grep -c hwloc` = 0) — the ground `main/thread_config.{h,cc}` carry hwloc faces (cc **133** tokens / h **2** re-measured THIS pass); the FLOG :364-:377 **FIXTC hwloc-excision graft** (excise `#include <hwloc.h>` + the HAVE_NUMA arm, keep decls, witness get_instance_max) is the banked, twice-consumed route (17z origin; eth + misc9 PLAN cite it). The thread_config row NEEDS it; NEVER pretend the header exists.
- **`#include <daq.h>` is a landed-ONCE graft family (NEVER confuse the faces)**: (1) MASTER `daq.h` 33 L `73fdbc39…` — daq3 home, the ONLY tracked cp; NEVER re-authored. (2) `daq_common.h` v16 16 L `f683749c…` — fmod home, sed-pinned by misc3 :155-:156. (3) graft-v2 `daq_common.h` `fead0027…` — misc3 `EOFGRAFT` heredoc regen (link6/link4/rsubs inherit), DAQ_Verdict carries ONLY 2 values — **the 21b GRAFT-VERSION LAW: this face DIES at flow.h :541 (MAX_DAQ_VERDICT) for ANY flow.-rider row**. (4) graft-v3 `daq.h` 39 L `0f7016a6…` — link4 ladder arm, copy-local ONLY (the sfd copy tree rides it, pinned). (5) ext#2/ext#4 `9b603f8f…` 34 L MAX_DAQ_VERDICT=6 — NEVER landed tracked, but **the 21b row proved it the LEGAL face for flow.h riders (copy-local, pinned in sfd :199)**. (6) ext#4 trio at 20a: daq.h 51 L `9b603f8f`-pair home ipheavy `97bca757` + daq_dlt.h 14 L `e8a39bf3` (DLT_IPV4 228 / DLT_IPV6 229) + packet.h RE-POINT `1be562b2`. ALL synthetic faces: row 20 RE-CITES the REAL SDK; synthetic value NEVER ABI truth. Real use-site pins: `src/flow/flow.h :541` (`sed -n '541p'` sed-pinned by sfd :180) + `src/packet_io/sfdaq_module.cc :179` static_assert (path trap: NOT src/main/).
- Host cgroup caps at **2 CPUs** (`nproc` lies: says 16). Keep builds serial; >4 parallel workers degrade. Toolchain: rustc/cargo 1.100.0.
- Tool constraints: `write_file`/`read_file` are jailed to `/opt/data` — wiki files (`/tmp/RustyPig.wiki`) edited only via python scripts kept in `/opt/data/cache/scratch/` run through the terminal, with `git -C /tmp/RustyPig.wiki ...`. Scratch dir is `/opt/data/cache/scratch` (TMPDIR points there). Harness builds take MINUTES at 2 CPUs — write sequences to a scratch .sh and background them; single-tenant; `rm -rf` child `copy/` before census-guarded runs. The FULL `cargo test`+clippy pass runs ~several minutes — run it in the background and read the receipt, ONE TENANT at a time.
- Probe printf hygiene: hoist mutating calls into locals before any printf (C++ arg evaluation order bit codec H-block + fid T2/T3; R6 var-first census at EVERY compound decode site).
- No gdb. Diagnose segfaults via stdout tail + source inference; THREAD_LOCAL statics must be armed or you get rc 139: `file_stats` via `file_stats_init()`, `packet_time`'s `s_recent_packet` via `packet_time_update()` ONLY. Since 18a `file_trace` has its REAL def on BOTH sides.
- Frozen-donor build.sh rc-1 face BY DESIGN (the 18g drift codified): tun/eth/ext/miscip-era scripts die at their point-in-time gate-count ls-asserts since gre added the 25th gate — NEVER edit frozen scripts; verify their face by DIRECT vectors md5 re-sums. The misc9 :461 landmine-drift face STAYS (since 21a). The FRESH-build set = **sfd + rsubs + ipheavy + gre + fmod + vocab + erspan + link6 + link4** (erasable copy/ trees); everything else frozen-lineage / direct-md5 ONLY.
- **The rsubs + sfd NEXT.md + census arms are LIVE LAW for every later row** (NEITHER edits NEXT, BOTH read it EVERY build): rsubs `621/605/597` x3 + 573 presence (:459-:461, :576-:579) + the name-pin census (:569-:571) pins `tools/reload_survivor*_harness`, `tools/survivor*_harness`, `tools/rss_harness` find-0 EVERY rsubs build + tools-wide `rsubs`-in-build.sh EXACTLY-1 (misc9 :42 holds the slot, :573-:576); sfd `629/621/605/597` x3 + `573` x5-EXACT (:527, :637-:641) + the sfd name-pins (:116-:119): the `sfd_harness`/`flowdata_harness` token outside its own build.sh = EXACTLY-ONE FILE (this file's queue face) and the prefixed-token line-count in NEXT.md EXACTLY-1 + the rider GROUND pins `^TEST( -eq 4` :159 + flow.h `:541` sed-pin :180 + graft md5s :199/:280 re-read the GROUND every build (disk wins). A future harness dir MUST dodge ALL of: the rsubs globs, `*sfd*`/`*flowdata*`, and NEVER add `rsubs`/`sfd_harness`/`flowdata_harness` tokens to any build.sh. The ground rsubs `TEST(`-47 :114 + `:625` :142 ground pins likewise stay.

## Donor harnesses (condensed — forensic per-row detail lives in the commit bodies + each tracked PLAN.md)
- `sfd_harness/` (dir) — **THE NEW LINEAGE HEAD (row 21b)**: 8 tracked stageables (misc9/rsubs 8-face shape); the NEXT.md read arms :527 python + :637-:641 grep (573 -eq 5 = the FIRST exact-5 pin of that face — a docs stakeholder NOW); the state-aware ZERO-LEAK 8-face count; name-pins :116-:119 (the sole prefixed dir-token line in NEXT.md is pinned -eq 1; the token census -eq 1 file); the donor-law REJECT legs runtime-concatenated (:89-:91, E4_daqwall_* receipts) + graft-tail md5 pins :199 9b603f8f / :280 fead0027; the rider ground pins :159 (-eq 4, "NEVER 5") + the 4 named `TEST(`s + flow/test 8-total + framework/test 3-UNDISTURBED :164; FIRST-RUN-SEED + tamper arm (vectors 3c05632e 8L / FACE-A 040de1ef 8L — smallest pair yet); tail `SFD_DONE vectors=8 faceA=8 gates=0` :697-:698; backbone10 echo 5339c7ee byte-ident; the frozen-census chain echo of rsubs 12/9 + older pairs :697.
- `tools/rsubs_harness/` (row 21a, the first-framework-registry head, NOW the SECOND ch19 harness): 8 tracked stageables; the FIVE NEXT.md read arms :459-:461 python + :576-:579 grep (a docs stakeholder — a rewrite must pass these BEFORE the commit); the state-aware ZERO-LEAK 8-face count; name-pin census :569-:571 + tools-wide rsubs-mention EXACTLY-1 :573-:576; the ground `TEST(` 47 + `:625` sed pins :114/:142; vectors 9e303761 12L / 42aa06fb 9L; donor misc9 124 + 3 EXACT cps = 127 (flowz-decoy path-trap E4 proven; graft-v2 wall proven BY THE 21b REJECT face); E4 both-ways (api_options chained wall / impl.h drop); tail `R_SUBS_DONE vectors=12 faceA=9 gates=0` :632.
- `tools/ipheavy_harness/` (row 20a, the codecs closer): 9 tracked stageables; the FIVE NEXT.md grep arms :656-:660 (the pinned-string template every fresh clone copies); the state-aware ZERO-LEAK 9-face count (8b9882a); stubs_20a copy-LOCAL trio retirement; ext#4 heredoc family; backbone wc-10 assert; tail `IPHEAVY_DONE vectors=121 faceA=44 gates=0` :805.
- `tools/misc9_harness/` (row 19a; NOW frozen-lineage — the :461 landmine-drift face since 21a): 8 stageables incl the nested .gitignore (31 L) — the instrument precedent; EXACT-COUNT pins :462/:607 (STILL LIVE against NEXT.md even at direct-md5 verify — keep them satisfiable); the `add_cpputest -eq 3` framework/test suite-count face :77 (ch19 rows reuse it); the :42 dialect-census token = THE tolerated tools-wide 'rsubs' mention; tail `MISC9_FRAMEWORK_OK vectors=41 faceA=11 gates=0`; vectors `e6328da1…`/FACE-A `dfe738fb…`; witness_misc9 27 L `ada2b1e8…`; the 18g-style drift face = verify by DIRECT md5s ONLY.
- `tools/mpls_harness/` (row 18o, tracked: 8 stageables): the LINK chapter closer (6/6, the 1465-L sum pin); **THE 21b donor tree — 130+3=133 cps**; its PLAN.md carries the flowz/flow_data decoy-path law + the safec stock-shim decision; the NEXT.md read arms :136-:138 grep + :619 python (605/580/588 presence faces).
- `tools/link4_harness/` (18n): graft-v3 ladder arm :902 (master RE-RIDE + 2 DECL rows); NEXT.md arms :185/:186 + :750; the 1465 link-tail sum pin :64; `backbone10.txt` = 10 L `5339c7ee…` (per-build wc-10 assert home); witness_18f CARRIED asserts; tail `LINK4_VLAN_OK vectors=28 faceA=24 gates=0`; the :881-:884 NEXT.md-tolerance line — clone day one in every new harness.
- `tools/link6_harness/` (18m): :198/:597 read-asserts; E4-both-ways wall receipts; tail `LINK6_PPP_OK vectors=20 faceA=20 gates=0`; vectors `e59f7a8a…`/`d2fc5591…`.
- `tools/erspan_harness/` (18l): **the :580 pinned-string stakeholder + the :404 tools-wide drift census — re-read BOTH before ANY docs rewrite or sibling landing**; tail `MISC_L_ERSPAN_OK vectors=18 faceA=19 gates=0`; vectors `7d7d3500…`/`3ec325d7…`.
- `tools/gre_harness/` — **THE gate-shape donor THE thread_config ROW CLONES (the ONLY row with real Catch material to date; tail 1 assertion/1 test case)**: gate.txt 3 L `6751d1a8` the ONLY tracked gate; catch shape :132 (vendored catch.hpp cp, md5 pin `74ef54e8…` :131) / :139-:143 (catch_main heredoc + CATCH_CONFIG_MAIN -eq 1) ; E9 dup flip :232-:234 (ONE-face link rule: catch_main.o + the -DUNIT_TEST .o, plain .o EXCLUDED — flipped-assert EVERY build); :298 exactly-ONE-U nm census; tail `GRE_HARNESS_OK vectors=26 faceA=5 gate_lines=3`; gate `4826fc22` lineage anchor rides fmod.
- Frozen-lineage donors (direct-md5 ONLY, NEVER chase to rc 0): misc3 (`e75f7385`/`fe1189c6`, graft-v2 heredoc :220-:244 — the fead0027 GENERATOR; row-face guard template :660-:688), miscip (`43b259ac`/`e4c47bac`; tcp.h 211 L `a7ac7b82` BANKED — CONSUMED at 20a), daq3 (`fd1855e1`/`2fb9dc45`; THE daq.h + daq_common v16 MASTER homes; the 7-face law), small4 (`462f0ff6`/`4755d48c`; 6-stageable head-shape), tun (vectors `2a792479`/`81602890`; witness_18f.cc `ea1f79f3` = the `tunnel_bypass_enabled` witness def :16 — carried by gre/misc3/link4/mpls/rsubs/sfd), ext (`da218429`/`0fa79b53`; stubs_18e.cc `a700f77e…`), eth (`1bd98dbb`, stubs_18d.cc `f4afd35f` retirement-marker precedent — stubs_18d also rides the sfd link), **vocab (witness_stubs.cc `9fad7e9d…` — its :11-:13 defs are the frozen face; its vectors LOAD-pin the `*_stub` names = the reason the Rust vocab records CARRY after 20a; daq_dlt.h graft home)**, fmod (gate `4826fc22`, vectors `f0fdbab`, daq_common v16 home), csum (`e4baf781` probe-only origin), the f* row-17 harnesses per PLAN rows (flog = the FIXTC hwloc-excavation home), `tools/codec_harness/` (17d; stubs.cc `be9bdd0b` frozen donor; the FULL plugin-loading deferral — plugin_manager.cc 1015 L — STILL defers to row 20).

## Next milestone — chapter-19 remainder: main/thread_config (the P-next row; THE DIALECT FLIP = THE FIRST REAL-GATE CANDIDATE SINCE gre)
- **Ground re-measured THIS pass, byte-exact**: `/opt/data/snort3-src/
  src/main/thread_config.cc` **920 L** md5
  `ca123f895a028e53328b3b0451af8073` (orchestrator-pinned face ==
  measured, MATCH) + `src/main/thread_config.h` **95 L** md5
  `86a4d24805a6413ecebbbe72e4f10e5b`. **DICTATE AGAINST THE BANK**: the
  orchestrator context token said the .h is **86 L** — DISK SAYS **95**
  (wc re-run 2x THIS pass) — a fresh CITE-DRIFT face OPEN BEFORE the row
  even starts: the md5 PIN MATCHES, the LINE COUNT drifts; re-cite from
  disk at the row, NEVER re-type a banked count. Path `src/main/` ONLY —
  `src/daqs/` NEVER existed (19a-era trap face kept).
- **Harness-name law (MEASURED THIS pass)**: `find tools -maxdepth 1
  -iname '*thread*' -o -iname 'tc_*'` = find-0 and the tokens
  `tc_harness`/`thrconf`/`threadconfig` = 0 hits in tools build.sh
  files + NEXT.md (the `ThreadConfig` token rides 231 BINARY
  receipts/objects — irrelevant to name censuses). **Pin the name
  `tc_harness`** per PLAN-0 re-verify at the row; it MUST dodge the
  rsubs globs (`survivor*_harness`, `rss_harness`,
  `reload_survivor*_harness`) AND the sfd :118-:119 token census (the tc
  build.sh carries `sfd_harness`/`flowdata_harness` NEVER).
- **THE DIALECT FLIP, FLAGGED HONEST — THIS ROW MAY END THE
  28-STRAIGHT ZERO-GATE STREAK**: `thread_config.cc` carries **14
  `TEST_CASE`** faces (re-counted THIS pass; first :615
  `[ThreadConfig]`) INSIDE the TU under `#ifdef UNIT_TEST` with the
  vendored `catch/snort_catch.h` include at :35 — UNLIKE the
  CppUTest-BLOCKED rider rows (sfd's 4-`TEST(` suite, main/test's
  CppUTest suites) the vendored-Catch material is **HOST-COMPILABLE**
  (the gre precedent re-proved catch runs natively). If the gate lands:
  clone the GRE gate shape EXACTLY (catch cp :132 + md5 pin 74ef54e8,
  catch_main heredoc :139 + CATCH_CONFIG_MAIN -eq 1 :143, the snort_
  catch.h shim heredoc precedent = codec_harness 8-L `catch_shim_
  snort_catch.h` + the flog/eth/tun passthrough faces, the E9 ONE-FACE
  link rule :232-:234 — catch_main.o + the -DUNIT_TEST TU .o, plain .o
  EXCLUDED); **the RUNNER TAIL is the SOLE truth for the gate count**
  (gre: "All tests passed (1 assertion in 1 test case)" -> gate.txt 3 L;
  NEVER gate on grep-estimated 14-case arithmetic (17p law)). Census
  re-pin question: a 26th gate file would move 25/9/17/1 BY MEASUREMENT
  (the 9 holders of `4826fc22` stay FROZEN — the two-lineage law: the
  18g legacy lineage is frozen at 9 holders, the gre anchor `6751d1a8`
  is the tracked-1 law); decide the tc gate.txt TRACKED-vs-untracked
  face per gre at the row, re-measure the WHOLE census, NEVER pre-
  assume. If instead the build DIES (hwloc residue, closure walls), the
  zero-gate face rides (29th straight) — BOTH outcomes honest, the
  harness MEASURES, the transcript decides.
- **The hwloc wall + the FIXTC graft**: hwloc host find-0 RE-RE-PROVEN
  THIS pass; cc **133** / h **2** hwloc tokens measured; the FLOG
  :364-:377 FIXTC excision graft is banked, twice-consumed — CONSUME IT
  at the row (graft #3), NEVER pretend the header exists.
- **The CMakeLists census face**: `src/main/test/CMakeLists.txt` carries
  EXACTLY **-2-** add_cpputest faces (re-counted THIS pass):
  thread_test.cc **442 L / 36 `^TEST(`** (rides `src/main/thread.cc`
  190 L — NOT thread_config.cc) + distill_verdict_test.cc **381 L / 14
  `^TEST(`** (the 19a-era 'thread 36'/'distill 14' dialect tokens now
  ground-pinned). thread_config.cc itself rides ONLY the OBJECT-library
  sources list (main/CMakeLists :57/:58) — upstream NEVER built a suite
  over its Catch block, so the gate route = compile the ROW TU with
  -DUNIT_TEST (the gre shape proves the one-face link works).
- **Scale flag**: 920-L TU + hwloc excision + Catch gate question =
  HEAVIER than 21b; fallback position per the 18a-18h rulings re-
  affirmed if the orchestrator re-ranks.
- **P-alt tracer rank-LAST UNCHANGED + RE-MEASURED**:
  `src/framework/tracer.cc` **73 L** md5 `9ee6b2ee…` + `tracer.h`
  **125 L** md5 `98d53205…` (byte-exact THIS pass). The daq wall flag:
  direct `daq` grep on tracer.{cc,h} = 0 — the wall is REAL via the
  packet face: tracer.cc :52/:54-:55 read `p->pkth->address_space_id` /
  `p->pkth->tenant_id`, fields the SYNTHETIC graft masters (ext#4 trio
  incl.) NEVER carry -> the DAQ-graft-EXTENSION wall UNCHANGED until
  row 20 lands the REAL SDK; a ch19 row NEVER re-opens graft churn. The
  `src/tracer/` logger family (file/stdout/syslog trace loggers +
  trace_loader) is a SEPARATE future census, not the ch19 tracer row.
- CppUTest dialect flag STAYS RAISED across chapter 19 (the misc9 §0
  census cite: data_bus 5 / rsubs 47 — BOTH landed-face measured /
  flow 8-suite / main 36 + 14). ALL dialect-BLOCKED, NEVER fake a gate
  over one — the thread_config Catch face is NOT a CppUTest row: the
  dialect flip means its gate question is LEGITIMATE (gre precedent).
  Pairing P2+data_bus = HISTORIC; the size-band arithmetic (233 = 864 >
  800) stands as history. A ch19 agent NEVER co-mines codec rows;
  single-tenancy extends to scratch recon dirs.

## Row 20 (DAQ / packet_io) — the re-cite law + the left-open seam ledger (closes at the row)
- EVERY daq graft face is SYNTHETIC evidence: the ext#4 pdd/NAPT family
  + DLT_IPV4 228 / DLT_IPV6 229 landed copy-LOCAL at 20a; the 21b row
  proved the graft-VERSION law (fead0027 DIES at flow.h :541; 9b603f8f
  carries MAX_DAQ_VERDICT==6) — row 20 RE-CITES the REAL daq3 SDK for
  pdd/NAPT/DLT/verdict families at THAT row; NEVER treat a graft face
  as ABI truth. The tracer row's tenant_id/address_space_id face joins
  this list (21a recon, re-grounded at tracer.cc :52/:54-:55).
- Left-open seam ledger (each audit-cited since the landing rows):
  prune/stats provider; `Stream::get_held_pkt_seq`; the IpOptionIterator
  x4 face; the `daq_msg_get_pkthdr` PROVIDER (witnesses TOGGLE the
  0x40 IGNORE_VLAN flag, the real provider NEVER landed); SFDAQ module
  (the synth-SFDAQ witnesses stop at 20a); `Flow::get_mpls_layer_per_dir`
  (18o cited-never-called); the bypass-provider face (witness_18f is a
  synthesized carrier); `show_prompt` PULL-SITE (misc9 :425 EXACTLY-1
  cite); the FULL codec plugin-loading deferral (plugin_manager.cc
  1015 L, open since 17d); the PolicyResolutionFailures peg face
  (inspector_manager-owned, 21a/21b cited-never-bumped); the **tterm
  REAL drain `thread_drain_pending_tterm_if_pending`** (21b: the call
  site lands at survivor_flow_data.cc :54, the provider body FOUND-0,
  witness mirrors the imgr :324/:1276 SHAPE with a fake knob — drain
  NEVER-invented).
- Then row 21: main CLI + `snort -q -c` end-to-end PCAP parity — the
  project's integration proof.

## Rules forward from 21b
- **Git-face rules (the 18i law, HELD ELEVEN straight clean landings
  18j→21b, the follow-up COMMIT route proven by 8b9882a)**: ONE commit +
  ONE push per row; post-push fixups = follow-up commit; face-agnostic
  harness guards; NO own-HEAD pins. The 69c8b6f orphan must stay
  merge-base rc **1** against origin/master — re-proved THIS pass.
- The two-lineage census (**25 / 9 x `4826fc22` / 17 distinct /
  tracked-1 — RE-MEASURED DIRECT AGAIN THIS pass**, gre anchor
  `6751d1a8…` intact; row 21b landed the **28th** straight zero-gate
  row) is the LIVE face; NEVER re-pin the arithmetic without measuring
  THAT pass (17p) — and the thread_config gate question means the
  arithmetic MAY legitimately MOVE at that row: measure, cite, never
  pre-assume either way. The BACKBONE-10 array moves ONLY when a row
  ADDS backbone symbols — witness DUOS/TRIOS/9-tuples ride symbol faces,
  not array entries; the sfd backbone10.txt echo (5339c7ee byte-ident)
  is the newest face of that law.
- **SINGLE-TENANT is the top-cycle law**: one cargo/census round at a
  time; a docs pass NEVER runs cargo while an orchestrator/row round is
  in flight (THIS pass: the 633/0 + clippy-0 face rides the 21b commit
  receipts, re-measured at the next harness phase); harness census runs
  clear sibling `copy/` trees first, BOTH directions (sfd + rsubs each
  own a live tools-dirty census every build — keep tools/ porcelain-
  clean apart from the in-flight row's stageables).
- New harness build.sh MUST clone, day one: the link4 NEXT.md-tolerance
  line, the FRESH harness read-asserts the FULL pinned set (sfd :527 +
  :637-:641 is the NEWEST template — include the NEW seeded face at
  EXACT-COUNT 3 + carry every older x3 face + the 573 x5/-eq-5 law), the
  state-aware stageables face-guard (8-face dual arm), the name-pin
  census (tc: dodge the rsubs globs + the sfd token census — the sfd
  :118-:119 arms stay find-0-clean of foreign build.sh tokens), the
  `rm -rf`-copy-first census discipline, and the nested `.gitignore`
  instrument for new dirs (root NEVER moves).
- clippy-allow practice: CLEAN own warnings BEFORE the code commit;
  cited allows ONLY at genuine record/ABI point sites — the live src
  face: trio 3/5/2 = 10 cited (20a) + rsubs.rs EXACTLY 1 (21a) +
  survivor_flow_data.rs ZERO (21b), ZERO in any framework mod.rs —
  tests-side pin-site counsel unchanged.
- NEXT.md rewrites: pin floors THIS face = `573 tests green` x5
  (EXACT, lines), `580 passed / 0 failed` x3, `588 tests green / 0 FAILED` x4,
  `597 tests green / 0 FAILED` EXACTLY x3 on EXACTLY 3 lines,
  `605 tests green / 0 FAILED` x3, `621 tests green / 0 FAILED`
  EXACTLY x3, `629 tests green / 0 FAILED` EXACTLY x3 (the sfd arms are
  LIVE every sfd re-run), seeded `633 tests green / 0 FAILED` EXACTLY
  x3 — re-grep BEFORE writing (tools/ read-assert sites above) and AFTER
  the docs commit. KEEP `grep -c` of the sfd prefixed dir token in this
  file at EXACTLY 1 line (sfd :119). CITE-DRIFT law — THREE landed faces
  now: the rsubs `:625` face, the cc `:39` static-init face (PLAN said
  :33), and the seeded "5 TEST(" rider count that DISK corrected to 4 —
  the law reads CONTINUOUS because the drift token gets FIXED openly,
  never silently; the thread_config.h `86-vs-95` bank token is the NEXT
  live instance: DISK WINS, at the row.

## Backlog (plan rows)
- Wiki: **landed through 21b at 367c2b9** (HEAD == remote == ls-remote,
  clean worktree, orchestrator-verified: `21b` greps 2+2 faces, dev block
  `ac79959e…` md5 pair byte-exact, provenance x10, stats face 526 files /
  62,673 src lines / 129 commits / 633 tests / 76 suites) — ZERO wiki
  debt; NEVER edit `/tmp/RustyPig.wiki` outside the wiki phase.
- 21b: **DONE (3e9f2d7 13 paths +2,339/−0; plain reflog, ONE push, no
  amend no force; the 11th straight one-commit/one-push face per the
  commit's own count)** — the whole face is in the 21b close-out above +
  the commit body.
- 21a: **DONE (167cb3c 13 paths +3,307/−0; the 10th straight face)** —
  the face is in the 21a close-out above + the commit body.
- 20a: **DONE (d525b6d 16 paths +7,136/−1 + follow-up 8b9882a)** — the
  face is in the 20a close-out above + the commit bodies.
- 18 (codecs): **CHAPTER CLOSED** — umbrella DONE at
  `PORTING_PLAN.md:87`; residual = per-row CppUTest test-side material
  ONLY (dialect-BLOCKED, cite/translate), NEVER re-open the code side
  without orchestrator ruling.
- 19: opener 19a DONE; P2 rsubs DONE (21a); P3 survivor_flow_data DONE
  (21b, 3e9f2d7); **thread_config = the next milestone (face above,
  with the gate-streak question)**; then tracer rank-LAST; then the
  detection-option engines (~30k+, the gre gate shape banked).
- 20: packet_io/DAQ TODO — re-cite law + seam ledger above (the tterm
  drain joins the ledger at 21b). 21: main CLI + end-to-end PCAP parity.

## Session ritual (verbatim order)
1. `git -C /opt/data/snort3-rust status --short; git log --oneline -3`
   (status CLEAN apart from the in-flight row; NEVER amend/force
   anything — the 69c8b6f orphan must stay merge-base rc 1 against
   origin/master — re-proved at every docs pass 18j-21b).
2. Verify-mode receipts (ONE tenant at a time): full `cargo test` (sum
   `test result` lines programmatically; expect the **633** landed face
   re-measured LIVE, 0 FAILED; the result-line count MOVES, re-measure)
   + `cargo clippy --all-targets` grep-0. Harness receipts at a docs
   pass: run the REWRITTEN-NEXT-armed harnesses LAST->FIRST as needed,
   each ONLY AFTER the rewritten NEXT.md passes its read arms — `cd
   tools/sfd_harness && bash build.sh` (its :637-:641 x3/x5 arms +
   :116-:119 name-pins must pass the NEW file; state-aware 8-face
   dual guard: pre-commit 8-untracked / post-commit 8-tracked, both
   rc0); `cd tools/rsubs_harness && bash build.sh` (its :459-:461 +
   :576-:579 arms + the `TEST(`-47 + `:625` GROUND pins); `cd
   tools/ipheavy_harness && bash build.sh` ONLY AFTER its :656-:660
   arms pass; gre FRESH (gate `6751d1a8`, `GRE_HARNESS_OK vectors=26
   faceA=5 gate_lines=3`), fmod (`4826fc22`), vocab (`VOCAB_HARNESS_OK
   vectors=29`), erspan (the pinned-string stakeholder :580 + :404
   census; clear the child copies FIRST incl sfd + ipheavy + rsubs
   copy/ for the :404 face), link6 (`LINK6_PPP_OK vectors=20 faceA=20
   gates=0`) and `rm -rf tools/link4_harness/copy tools/link6_harness/
   copy` FIRST (plus the sfd + rsubs `copy/` trees before any tools-
   dirty census) then
   link4 x2 (`LINK4_VLAN_OK vectors=28 faceA=24 gates=0`, copy-find
   RE-DERIVES, backbone wc-10). Verify misc9 by DIRECT md5s ONLY now
   (vectors `e6328da1…`/`dfe738fb…`, witness `ada2b1e8…` — the :461
   landmine-drift face, NEVER chase to rc 0, NEVER edit it), same for
   the frozen lineage (mpls/ipheavy/link4/link6/erspan/misc3/miscip/
   daq3/small4/gre/tun/ext/eth/csum/fmod/vocab vector + witness + graft-
   master faces as listed above; backbone `5339c7ee`; witness census
   `9fad7e9d`/`be9bdd0b`/`f4afd35f`/`ea1f79f3`/`ef50cd2f`/`c5b498ff`;
   graft masters `73fdbc39`/`f683749c` + regen `0f7016a6`/`fead0027`;
   rsubs vectors `9e303761…`/`42aa06fb…`, witness `c0142f9b…`; sfd
   vectors `3c05632e…`/`040de1ef…`, witness_sfd `101aa012…`). NEVER
   edit frozen scripts; FRESH-build set = sfd + rsubs + ipheavy + gre +
   fmod + vocab + erspan + link6 + link4. Harness sequences go in a
   scratch .sh, single-tenant.
3. Port -> `cargo test --test <x>_parity_test` -> full `cargo test`
   (zero FAILED; >= **633**) + clippy 0 -> harness `.gitignore` +
   `git check-ignore` -> stage ONLY the row's paths -> commit+push
   (**ONE push, then done — fixes ride FOLLOW-UP commits**; verify
   `git ls-remote` matches HEAD BEFORE any further commit) -> plan row
   + deviations (grep-guards; ship inside the code commit, verify-grep
   at the docs pass) -> refresh THIS file (**carry the PINNED STRINGS
   FIRST — grep tools/ for NEXT.md read-asserts BEFORE writing; carry
   every floor VERBATIM — misc9 + rsubs + sfd EXACT-COUNT arms, the 573
   face at EXACTLY 5 lines — + seed the current-pass face at EXACTLY 3
   for the next harness; re-grep pins AFTER the commit**) -> commit+push
   docs -> wiki (**ZERO debt at 367c2b9 thru 21b** — if a row lands, the
   wiki pass re-measures HEAD + ALL stats LIVE; push ONCE).
